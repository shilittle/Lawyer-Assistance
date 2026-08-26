//! Authenticated recovery for one narrowly defined interrupted legacy bootstrap.
//!
//! Some development-era profiles contain an exact v0.3.1 user schema whose
//! business tables are all empty, while the entire Privacy root was never
//! created.  A later standalone-MCP acceptance run can additionally leave the
//! four fixed v0.4 Approved-MCP credentials behind without any corresponding
//! target files.  That shape is neither a genuine fresh profile nor an exact
//! v0.3.1 migration source, so ordinary startup must continue to reject it.
//!
//! This module repairs only that exact shape.  It preserves the old user image,
//! archives the four credentials under DPAPI CurrentUser, reconstructs an
//! explicitly labelled empty Privacy-v1 database from the frozen v0.3.1 DDL,
//! and deletes the four orphan credentials with the existing compare-and-delete
//! prefix protocol.  The resulting profile must pass the unchanged exact
//! v0.3.1 observer before the pending authority is retired.  The next process
//! then reuses the existing crash-safe receipt 0..9 migration unchanged.

use crate::{
    approved_mcp::{
        advance_v031_recovery_approved_mcp_credential_delete_prefix,
        authenticate_v031_recovery_approved_mcp_credentials_read_only,
        capture_v031_recovery_approved_mcp_credentials_read_only,
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only,
        V031ApprovedMcpCredentialSnapshot,
    },
    v031_startup::{
        observe_exact_v031_source_profile_read_only, ExactV031SourceProfileObservation,
    },
    v031_upgrade_r2::{
        self, CredentialAbsenceQuery, CredentialPresenceProbe, DirectorySync, PlatformDirectorySync,
    },
};
use privacy::{
    protect_local, sha256_hex, unprotect_local,
    vnext::{canonical_json_v1, strict_json_v1_from_slice},
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const RECOVERY_DIRECTORY: &str = "legacy-empty-bootstrap-recovery-v1";
const USER_BACKUP_BASENAME: &str = "original-empty-user-v10.sqlite";
const USER_BACKUP_STAGING_BASENAME: &str = "original-empty-user-v10.sqlite.staging";
const CREDENTIAL_ARCHIVE_BASENAME: &str = "orphan-approved-credentials.dpapi";
const CREDENTIAL_ARCHIVE_STAGING_BASENAME: &str = "orphan-approved-credentials.dpapi.staging";
const COMPLETED_REPORT_BASENAME: &str = "completed.report.dpapi";
const COMPLETED_REPORT_STAGING_BASENAME: &str = "completed.report.dpapi.staging";
const PRIVACY_BACKUP_BASENAME: &str = "reconstructed-empty-privacy-v1.sqlite";
const PRIVACY_BACKUP_STAGING_BASENAME: &str = "reconstructed-empty-privacy-v1.sqlite.staging";
const PRIVACY_INCOMING_BASENAME: &str = "legacy-empty-bootstrap-privacy-v1.incoming";
const PRIVACY_DIRECTORY_NAME: &str = "privacy";
const PRIVACY_DATABASE_BASENAME: &str = "privacy-workflow.sqlite";
const PENDING_MARKER_BASENAME: &str = "legacy-empty-bootstrap-pending.dpapi";
const PENDING_MARKER_STAGING_BASENAME: &str = "legacy-empty-bootstrap-pending.dpapi.staging";
const MARKER_SCHEMA: &str = "lawyer-assistance-empty-legacy-bootstrap-pending-v1";
const REPORT_SCHEMA: &str = "lawyer-assistance-empty-legacy-bootstrap-completed-v1";
const SOURCE_PROFILE: &str = "exact-empty-user-v10-missing-privacy";
const RECOVERY_REASON: &str = "missing_source_reconstructed_empty";
const RESULT_PROFILE: &str = "exact-v031-source-reconstructed-empty-privacy-v1";
const FORMAT_VERSION: u64 = 1;
const EXPECTED_USER_TABLES: u64 = 27;
const EXPECTED_USER_METADATA_ROWS: u64 = 2;
const EXPECTED_USER_TOTAL_ROWS: u64 = 2;
const MAX_PROTECTED_EVIDENCE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmptyLegacyBootstrapOutcome {
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmptyLegacyBootstrapError {
    InvalidState,
    EvidenceIo,
    CredentialState,
}

impl fmt::Display for EmptyLegacyBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidState => "the interrupted empty legacy profile is not exact",
            Self::EvidenceIo => "the interrupted legacy recovery evidence could not be persisted",
            Self::CredentialState => {
                "the interrupted legacy Approved-MCP credential state is not exact"
            }
        })
    }
}

impl std::error::Error for EmptyLegacyBootstrapError {}

#[derive(Debug)]
struct InitialCandidate {
    user: database::UserMigrationSourceProof,
    credentials: V031ApprovedMcpCredentialSnapshot,
    cleanup_pending_staging: bool,
}

enum EmptyLegacyBootstrapGateState {
    Initial(InitialCandidate),
    Pending {
        marker: EmptyLegacyBootstrapMarkerV1,
        protected_sha256: String,
        staging: bool,
    },
}

pub(crate) struct EmptyLegacyBootstrapGate {
    app_local_data_dir: PathBuf,
    state: EmptyLegacyBootstrapGateState,
}

impl fmt::Debug for EmptyLegacyBootstrapGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmptyLegacyBootstrapGate")
            .field("app_local_data_dir", &"<fixed-app-root>")
            .field(
                "state",
                &match self.state {
                    EmptyLegacyBootstrapGateState::Initial(_) => "initial",
                    EmptyLegacyBootstrapGateState::Pending { staging: true, .. } => {
                        "pending-staging"
                    }
                    EmptyLegacyBootstrapGateState::Pending { staging: false, .. } => {
                        "pending-final"
                    }
                },
            )
            .finish()
    }
}

pub(crate) enum EmptyLegacyBootstrapObservation {
    Absent,
    Authenticated(EmptyLegacyBootstrapGate),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmptyLegacyBootstrapMarkerV1 {
    schema: String,
    format_version: u64,
    source_profile: String,
    creator_app_version: String,
    created_at_unix: u64,
    user_schema_manifest_sha256: String,
    user_logical_manifest_sha256: String,
    user_business_manifest_sha256: String,
    user_business_row_manifest_sha256: String,
    user_database_sha256: String,
    user_database_bytes: u64,
    user_table_count: u64,
    user_total_rows: u64,
    user_backup_basename: String,
    user_backup_sha256: String,
    user_backup_bytes: u64,
    credential_archive_basename: String,
    credential_archive_sha256: String,
    credential_archive_bytes: u64,
    recovery_reason: String,
    privacy_backup_basename: String,
    privacy_database_sha256: String,
    privacy_database_bytes: u64,
    privacy_logical_manifest_sha256: String,
    privacy_business_manifest_sha256: String,
    privacy_business_primary_key_manifest_sha256: String,
    privacy_business_row_manifest_sha256: String,
    privacy_logical_rows: u64,
    privacy_business_rows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmptyLegacyBootstrapCompletedV1 {
    schema: String,
    format_version: u64,
    source_profile: String,
    result_profile: String,
    creator_app_version: String,
    completed_at_unix: u64,
    pending_marker_protected_sha256: String,
    user_database_sha256: String,
    user_database_bytes: u64,
    credential_archive_sha256: String,
    recovery_reason: String,
    privacy_database_sha256: String,
    privacy_database_bytes: u64,
}

struct FilesystemOnlyCredentialAbsence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconstructedPrivacyLayout {
    Absent,
    Incoming,
    IncomingResidue,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactPresence {
    Absent,
    Staging,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecoveryInventory {
    user: ArtifactPresence,
    credentials: ArtifactPresence,
    privacy: ArtifactPresence,
    report: ArtifactPresence,
}

impl CredentialPresenceProbe for FilesystemOnlyCredentialAbsence {
    type Error = EmptyLegacyBootstrapError;

    fn credential_exists_read_only(
        &self,
        query: CredentialAbsenceQuery,
    ) -> Result<bool, Self::Error> {
        if query.target != query.role.target()
            || query.account != v031_upgrade_r2::APPROVED_MCP_CREDENTIAL_ACCOUNT
        {
            return Err(EmptyLegacyBootstrapError::InvalidState);
        }
        Ok(false)
    }
}

/// Manager-free, strictly read-only observer used by the aggregate production
/// startup pass.  The returned capability owns every secret or proof needed by
/// the later action; observing alone never creates a directory or credential.
pub(crate) fn observe_interrupted_empty_legacy_profile_read_only(
    app_local_data_dir: &Path,
) -> Result<EmptyLegacyBootstrapObservation, EmptyLegacyBootstrapError> {
    validate_recovery_namespace_siblings(app_local_data_dir)?;
    let pending = app_local_data_dir.join(PENDING_MARKER_BASENAME);
    let pending_staging = app_local_data_dir.join(PENDING_MARKER_STAGING_BASENAME);
    let pending_present = ordinary_file_presence(&pending)?;
    let staging_present = ordinary_file_presence(&pending_staging)?;

    if pending_present && staging_present {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }

    if pending_present {
        let (marker, protected_sha256) = read_pending_marker(&pending)?;
        authenticate_pending_state_read_only(app_local_data_dir, &marker, &protected_sha256)?;
        return Ok(EmptyLegacyBootstrapObservation::Authenticated(
            EmptyLegacyBootstrapGate {
                app_local_data_dir: app_local_data_dir.to_path_buf(),
                state: EmptyLegacyBootstrapGateState::Pending {
                    marker,
                    protected_sha256,
                    staging: false,
                },
            },
        ));
    }

    if staging_present {
        match read_pending_marker(&pending_staging).and_then(|(marker, protected_sha256)| {
            authenticate_pre_mutation_assets(app_local_data_dir, &marker)?;
            Ok((marker, protected_sha256))
        }) {
            Ok((marker, protected_sha256)) => {
                return Ok(EmptyLegacyBootstrapObservation::Authenticated(
                    EmptyLegacyBootstrapGate {
                        app_local_data_dir: app_local_data_dir.to_path_buf(),
                        state: EmptyLegacyBootstrapGateState::Pending {
                            marker,
                            protected_sha256,
                            staging: true,
                        },
                    },
                ));
            }
            Err(_) => {
                let Some(mut candidate) = observe_initial_candidate_read_only(app_local_data_dir)?
                else {
                    return Err(EmptyLegacyBootstrapError::InvalidState);
                };
                candidate.cleanup_pending_staging = true;
                return Ok(EmptyLegacyBootstrapObservation::Authenticated(
                    EmptyLegacyBootstrapGate {
                        app_local_data_dir: app_local_data_dir.to_path_buf(),
                        state: EmptyLegacyBootstrapGateState::Initial(candidate),
                    },
                ));
            }
        }
    }

    let Some(candidate) = observe_initial_candidate_read_only(app_local_data_dir)? else {
        return Ok(EmptyLegacyBootstrapObservation::Absent);
    };
    Ok(EmptyLegacyBootstrapObservation::Authenticated(
        EmptyLegacyBootstrapGate {
            app_local_data_dir: app_local_data_dir.to_path_buf(),
            state: EmptyLegacyBootstrapGateState::Initial(candidate),
        },
    ))
}

pub(crate) fn repair_observed_interrupted_empty_legacy_profile(
    app_local_data_dir: &Path,
    gate: EmptyLegacyBootstrapGate,
) -> Result<EmptyLegacyBootstrapOutcome, EmptyLegacyBootstrapError> {
    if gate.app_local_data_dir != app_local_data_dir {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    match gate.state {
        EmptyLegacyBootstrapGateState::Initial(candidate) => {
            let marker = prepare_initial_authority(app_local_data_dir, &candidate)?;
            let pending = app_local_data_dir.join(PENDING_MARKER_BASENAME);
            let (installed, protected_sha256) = read_pending_marker(&pending)?;
            if installed != marker {
                return Err(EmptyLegacyBootstrapError::InvalidState);
            }
            resume_repair(app_local_data_dir, &installed, &protected_sha256)
        }
        EmptyLegacyBootstrapGateState::Pending {
            marker,
            protected_sha256,
            staging: false,
        } => resume_repair(app_local_data_dir, &marker, &protected_sha256),
        EmptyLegacyBootstrapGateState::Pending {
            marker,
            protected_sha256,
            staging: true,
        } => {
            let pending = app_local_data_dir.join(PENDING_MARKER_BASENAME);
            let pending_staging = app_local_data_dir.join(PENDING_MARKER_STAGING_BASENAME);
            authenticate_pre_mutation_assets(app_local_data_dir, &marker)?;
            v031_upgrade_r2::rename_new_no_replace_write_through(&pending_staging, &pending)
                .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
            sync_directory(app_local_data_dir)?;
            let (installed, installed_sha256) = read_pending_marker(&pending)?;
            if installed != marker
                || installed_sha256 != protected_sha256
                || ordinary_file_presence(&pending_staging)?
            {
                return Err(EmptyLegacyBootstrapError::InvalidState);
            }
            resume_repair(app_local_data_dir, &installed, &installed_sha256)
        }
    }
}

fn observe_initial_candidate_read_only(
    app_local_data_dir: &Path,
) -> Result<Option<InitialCandidate>, EmptyLegacyBootstrapError> {
    if !app_local_data_dir.is_absolute() {
        return Ok(None);
    }
    let user_path = database::user_database_path(app_local_data_dir);
    if !ordinary_file_presence(&user_path)? {
        return Ok(None);
    }
    let (user, ()) =
        match database::with_validated_user_database_migration_source_read_only(&user_path, |_| ())
        {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
    if !is_exact_empty_v031_user_proof(&user) {
        return Ok(None);
    }
    if path_presence_requires_absence(&app_local_data_dir.join("privacy"))? {
        return Ok(None);
    }
    if v031_upgrade_r2::verify_exact_target_absence(
        app_local_data_dir,
        &FilesystemOnlyCredentialAbsence,
    )
    .is_err()
    {
        return Ok(None);
    }
    let credentials = match capture_v031_recovery_approved_mcp_credentials_read_only() {
        Ok(credentials) => credentials,
        Err(_) => return Ok(None),
    };
    Ok(Some(InitialCandidate {
        user,
        credentials,
        cleanup_pending_staging: false,
    }))
}

fn is_exact_empty_v031_user_proof(proof: &database::UserMigrationSourceProof) -> bool {
    proof.schema == database::ValidatedUserSourceSchema::V031V10
        && proof.wal.is_none()
        && proof.shm.is_none()
        && proof.journal.is_none()
        && proof.tables.len() as u64 == EXPECTED_USER_TABLES
        && proof.total_rows == EXPECTED_USER_TOTAL_ROWS
        && proof.tables.iter().all(|table| {
            if table.table == "user_database_metadata" {
                table.rows == EXPECTED_USER_METADATA_ROWS
                    && table.business_manifest_sha256.is_none()
                    && table.business_primary_key_manifest_sha256.is_none()
                    && table.business_row_manifest_sha256.is_none()
            } else {
                table.rows == 0
                    && table.business_manifest_sha256.is_some()
                    && table.business_primary_key_manifest_sha256.is_some()
                    && table.business_row_manifest_sha256.is_some()
            }
        })
}

fn prepare_initial_authority(
    app_local_data_dir: &Path,
    candidate: &InitialCandidate,
) -> Result<EmptyLegacyBootstrapMarkerV1, EmptyLegacyBootstrapError> {
    validate_local_directory_chain(app_local_data_dir)?;
    let pending = app_local_data_dir.join(PENDING_MARKER_BASENAME);
    let pending_staging = app_local_data_dir.join(PENDING_MARKER_STAGING_BASENAME);
    if ordinary_file_presence(&pending)? {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    if candidate.cleanup_pending_staging {
        remove_fixed_staging_file(&pending_staging, app_local_data_dir)?;
    } else if ordinary_file_presence(&pending_staging)? {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }

    let recovery = recovery_directory(app_local_data_dir)?;
    ensure_recovery_directory(&recovery)?;
    validate_pre_marker_recovery_inventory(&recovery)?;
    let backup = install_user_backup(app_local_data_dir, &recovery, &candidate.user)?;
    let archive = install_credential_archive(&recovery, &candidate.credentials)?;
    let privacy = install_reconstructed_privacy_backup(&recovery)?;
    require_pre_mutation_assets_inventory(&recovery)?;

    let current = observe_initial_candidate_read_only(app_local_data_dir)?
        .ok_or(EmptyLegacyBootstrapError::InvalidState)?;
    if !same_user_source(&candidate.user, &current.user) {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    authenticate_v031_recovery_approved_mcp_credentials_read_only(&candidate.credentials)
        .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;

    let marker = EmptyLegacyBootstrapMarkerV1 {
        schema: MARKER_SCHEMA.to_owned(),
        format_version: FORMAT_VERSION,
        source_profile: SOURCE_PROFILE.to_owned(),
        creator_app_version: env!("CARGO_PKG_VERSION").to_owned(),
        created_at_unix: unix_now()?,
        user_schema_manifest_sha256: candidate.user.schema_manifest_sha256.clone(),
        user_logical_manifest_sha256: candidate.user.logical_database_manifest_sha256.clone(),
        user_business_manifest_sha256: candidate.user.business_manifest_sha256.clone(),
        user_business_row_manifest_sha256: candidate.user.business_row_manifest_sha256.clone(),
        user_database_sha256: candidate.user.database_file.sha256.clone(),
        user_database_bytes: candidate.user.database_file.length,
        user_table_count: candidate.user.tables.len() as u64,
        user_total_rows: candidate.user.total_rows,
        user_backup_basename: USER_BACKUP_BASENAME.to_owned(),
        user_backup_sha256: backup.0,
        user_backup_bytes: backup.1,
        credential_archive_basename: CREDENTIAL_ARCHIVE_BASENAME.to_owned(),
        credential_archive_sha256: archive.0,
        credential_archive_bytes: archive.1,
        recovery_reason: RECOVERY_REASON.to_owned(),
        privacy_backup_basename: PRIVACY_BACKUP_BASENAME.to_owned(),
        privacy_database_sha256: privacy.database_file.sha256.clone(),
        privacy_database_bytes: privacy.database_file.length,
        privacy_logical_manifest_sha256: privacy.logical_manifest.sha256.clone(),
        privacy_business_manifest_sha256: privacy.business_manifest.sha256.clone(),
        privacy_business_primary_key_manifest_sha256: privacy
            .business_manifest
            .primary_key_sha256
            .clone(),
        privacy_business_row_manifest_sha256: privacy.business_manifest.row_sha256.clone(),
        privacy_logical_rows: privacy.logical_manifest.total_row_count,
        privacy_business_rows: privacy.business_manifest.total_row_count,
    };
    validate_marker_static(&marker)?;
    install_pending_marker(app_local_data_dir, &marker)?;
    Ok(marker)
}

fn resume_repair(
    app_local_data_dir: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
    pending_protected_sha256: &str,
) -> Result<EmptyLegacyBootstrapOutcome, EmptyLegacyBootstrapError> {
    validate_marker_static(marker)?;
    authenticate_pending_state_read_only(app_local_data_dir, marker, pending_protected_sha256)?;
    let recovery = recovery_directory(app_local_data_dir)?;
    validate_pending_recovery_inventory(&recovery)?;
    let credentials = authenticate_recovery_assets(&recovery, marker)?;
    authenticate_user_copy_against_marker(
        &database::user_database_path(app_local_data_dir),
        marker,
    )?;
    let mut prefix =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(&credentials)
            .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;
    let privacy_layout =
        observe_reconstructed_privacy_layout_read_only(app_local_data_dir, marker)?;
    if privacy_layout != ReconstructedPrivacyLayout::Active && prefix.prefix_len() != 0 {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    install_or_authenticate_reconstructed_privacy(
        app_local_data_dir,
        &recovery,
        marker,
        prefix.prefix_len() == 0,
    )?;
    while prefix.prefix_len() < 4 {
        prefix = advance_v031_recovery_approved_mcp_credential_delete_prefix(&credentials, &prefix)
            .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;
    }

    match observe_exact_v031_source_profile_read_only(app_local_data_dir)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
    {
        ExactV031SourceProfileObservation::Exact(_) => {}
        ExactV031SourceProfileObservation::NotSource => {
            return Err(EmptyLegacyBootstrapError::InvalidState)
        }
    }

    install_or_authenticate_completed_report(&recovery, marker, pending_protected_sha256)?;
    let pending = app_local_data_dir.join(PENDING_MARKER_BASENAME);
    fs::remove_file(&pending).map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
    sync_directory(app_local_data_dir)?;
    if ordinary_file_presence(&pending)? {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    match observe_exact_v031_source_profile_read_only(app_local_data_dir)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
    {
        ExactV031SourceProfileObservation::Exact(_) => {}
        ExactV031SourceProfileObservation::NotSource => {
            return Err(EmptyLegacyBootstrapError::InvalidState)
        }
    }
    Ok(EmptyLegacyBootstrapOutcome::Completed)
}

fn install_user_backup(
    app_local_data_dir: &Path,
    recovery: &Path,
    expected: &database::UserMigrationSourceProof,
) -> Result<(String, u64), EmptyLegacyBootstrapError> {
    let final_path = recovery.join(USER_BACKUP_BASENAME);
    let staging_path = recovery.join(USER_BACKUP_STAGING_BASENAME);
    if ordinary_file_presence(&final_path)? {
        return authenticate_user_copy(&final_path, expected);
    }
    let staging_ready = if ordinary_file_presence(&staging_path)? {
        match authenticate_user_copy(&staging_path, expected) {
            Ok(_) => true,
            Err(_) => {
                remove_fixed_staging_file(&staging_path, recovery)?;
                false
            }
        }
    } else {
        false
    };
    if !staging_ready {
        let source = database::user_database_path(app_local_data_dir);
        let bytes =
            v031_upgrade_r2::read_bounded_file(&source, database::MAX_V031_USER_SQLITE_IMAGE_BYTES)
                .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
        if sha256_hex(&bytes) != expected.database_file.sha256
            || u64::try_from(bytes.len()).ok() != Some(expected.database_file.length)
        {
            return Err(EmptyLegacyBootstrapError::InvalidState);
        }
        v031_upgrade_r2::write_create_new_sync(
            &staging_path,
            &bytes,
            database::MAX_V031_USER_SQLITE_IMAGE_BYTES,
        )
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
        sync_directory(recovery)?;
        authenticate_user_copy(&staging_path, expected)?;
    }
    v031_upgrade_r2::rename_new_no_replace_write_through(&staging_path, &final_path)
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
    sync_directory(recovery)?;
    authenticate_user_copy(&final_path, expected)
}

fn authenticate_user_copy(
    path: &Path,
    expected: &database::UserMigrationSourceProof,
) -> Result<(String, u64), EmptyLegacyBootstrapError> {
    let (actual, ()) =
        database::with_validated_user_database_migration_source_read_only(path, |_| ())
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    if !is_exact_empty_v031_user_proof(&actual)
        || !same_user_source(expected, &actual)
        || actual.database_file.sha256 != expected.database_file.sha256
        || actual.database_file.length != expected.database_file.length
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok((actual.database_file.sha256, actual.database_file.length))
}

fn install_reconstructed_privacy_backup(
    recovery: &Path,
) -> Result<privacy::ValidatedPrivacyV1Source, EmptyLegacyBootstrapError> {
    let final_path = recovery.join(PRIVACY_BACKUP_BASENAME);
    let staging_path = recovery.join(PRIVACY_BACKUP_STAGING_BASENAME);
    if ordinary_file_presence(&final_path)? {
        return authenticate_empty_privacy_v1_file(&final_path);
    }
    let staging_ready = if ordinary_file_presence(&staging_path)? {
        match authenticate_empty_privacy_v1_file(&staging_path) {
            Ok(_) => true,
            Err(_) => {
                remove_fixed_staging_file(&staging_path, recovery)?;
                false
            }
        }
    } else {
        false
    };
    if !staging_ready {
        let bytes = reconstructed_empty_privacy_v1_image()?;
        let image = privacy::validate_privacy_v1_sqlite_image_read_only(&bytes)
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
        validate_empty_privacy_v1_proof(&image)?;
        v031_upgrade_r2::write_create_new_sync(
            &staging_path,
            &bytes,
            privacy::MAX_PRIVACY_V1_SQLITE_IMAGE_BYTES,
        )
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
        sync_directory(recovery)?;
        let installed = authenticate_empty_privacy_v1_file(&staging_path)?;
        if installed.database_file.sha256 != image.database_file.sha256
            || installed.database_file.length != image.database_file.length
        {
            return Err(EmptyLegacyBootstrapError::InvalidState);
        }
    }
    v031_upgrade_r2::rename_new_no_replace_write_through(&staging_path, &final_path)
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
    sync_directory(recovery)?;
    authenticate_empty_privacy_v1_file(&final_path)
}

fn reconstructed_empty_privacy_v1_image() -> Result<Vec<u8>, EmptyLegacyBootstrapError> {
    let connection =
        Connection::open_in_memory().map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    connection
        .execute_batch(privacy::PRIVACY_V1_SCHEMA_MANIFEST_DDL)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    connection
        .execute(
            "INSERT INTO privacy_schema_metadata(key,value,updated_at)
             VALUES('schema_version','1','2026-07-19 15:41:29')",
            [],
        )
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    let image = connection
        .serialize(rusqlite::MAIN_DB)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
        .to_vec();
    let proof = privacy::validate_privacy_v1_sqlite_image_read_only(&image)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    validate_empty_privacy_v1_proof(&proof)?;
    Ok(image)
}

fn authenticate_empty_privacy_v1_file(
    path: &Path,
) -> Result<privacy::ValidatedPrivacyV1Source, EmptyLegacyBootstrapError> {
    let proof = privacy::validate_privacy_v1_migration_source_read_only(path)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    validate_empty_privacy_v1_proof(&proof)?;
    Ok(proof)
}

fn validate_empty_privacy_v1_proof(
    proof: &privacy::ValidatedPrivacyV1Source,
) -> Result<(), EmptyLegacyBootstrapError> {
    if proof.schema_version != privacy::PRIVACY_V1_SCHEMA_VERSION
        || proof.schema_object_count != privacy::PRIVACY_V1_SCHEMA_OBJECT_COUNT
        || proof.protected_review_payload_count != 0
        || proof.wal.is_some()
        || proof.shm.is_some()
        || proof.journal.is_some()
        || proof.logical_manifest.total_row_count != 1
        || proof.business_manifest.total_row_count != 0
        || proof
            .logical_manifest
            .tables
            .iter()
            .find(|table| table.table_name == "privacy_schema_metadata")
            .map(|table| table.row_count)
            != Some(1)
        || proof
            .logical_manifest
            .tables
            .iter()
            .filter(|table| table.table_name != "privacy_schema_metadata")
            .any(|table| table.row_count != 0)
        || proof
            .business_manifest
            .tables
            .iter()
            .any(|table| table.row_count != 0)
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(())
}

fn marker_matches_privacy(
    marker: &EmptyLegacyBootstrapMarkerV1,
    proof: &privacy::ValidatedPrivacyV1Source,
) -> bool {
    validate_empty_privacy_v1_proof(proof).is_ok()
        && marker.privacy_database_sha256 == proof.database_file.sha256
        && marker.privacy_database_bytes == proof.database_file.length
        && marker.privacy_logical_manifest_sha256 == proof.logical_manifest.sha256
        && marker.privacy_business_manifest_sha256 == proof.business_manifest.sha256
        && marker.privacy_business_primary_key_manifest_sha256
            == proof.business_manifest.primary_key_sha256
        && marker.privacy_business_row_manifest_sha256 == proof.business_manifest.row_sha256
        && marker.privacy_logical_rows == proof.logical_manifest.total_row_count
        && marker.privacy_business_rows == proof.business_manifest.total_row_count
}

fn observe_reconstructed_privacy_layout_read_only(
    app_local_data_dir: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
) -> Result<ReconstructedPrivacyLayout, EmptyLegacyBootstrapError> {
    let privacy_root = app_local_data_dir.join(PRIVACY_DIRECTORY_NAME);
    let metadata = match fs::symlink_metadata(&privacy_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ReconstructedPrivacyLayout::Absent)
        }
        Err(_) => return Err(EmptyLegacyBootstrapError::InvalidState),
        Ok(metadata) => metadata,
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    validate_local_directory_chain(&privacy_root)?;
    let entries = fs::read_dir(&privacy_root)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
        .map(|entry| {
            entry
                .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
                .file_name()
                .into_string()
                .map_err(|_| EmptyLegacyBootstrapError::InvalidState)
        })
        .collect::<Result<Vec<_>, _>>()?;
    match entries.as_slice() {
        [] => Ok(ReconstructedPrivacyLayout::Absent),
        [name] if name == PRIVACY_INCOMING_BASENAME => {
            let incoming = privacy_root.join(PRIVACY_INCOMING_BASENAME);
            match authenticate_empty_privacy_v1_file(&incoming) {
                Ok(proof) if marker_matches_privacy(marker, &proof) => {
                    Ok(ReconstructedPrivacyLayout::Incoming)
                }
                Ok(_) => Err(EmptyLegacyBootstrapError::InvalidState),
                Err(_) => {
                    v031_upgrade_r2::verify_plain_single_link_file(&incoming)
                        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
                    Ok(ReconstructedPrivacyLayout::IncomingResidue)
                }
            }
        }
        [name] if name == PRIVACY_DATABASE_BASENAME => {
            let proof =
                authenticate_empty_privacy_v1_file(&privacy_root.join(PRIVACY_DATABASE_BASENAME))?;
            if marker_matches_privacy(marker, &proof) {
                Ok(ReconstructedPrivacyLayout::Active)
            } else {
                Err(EmptyLegacyBootstrapError::InvalidState)
            }
        }
        _ => Err(EmptyLegacyBootstrapError::InvalidState),
    }
}

fn install_or_authenticate_reconstructed_privacy(
    app_local_data_dir: &Path,
    recovery: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
    allow_incoming_residue_cleanup: bool,
) -> Result<(), EmptyLegacyBootstrapError> {
    let privacy_root = app_local_data_dir.join(PRIVACY_DIRECTORY_NAME);
    validate_local_directory_chain(app_local_data_dir)?;
    if !crate::privacy_manager::is_normal_local_absolute(&privacy_root)
        || !crate::privacy_manager::local_path_chain_is_ordinary(&privacy_root)
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    match fs::create_dir(&privacy_root) {
        Ok(()) => sync_directory(app_local_data_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(EmptyLegacyBootstrapError::EvidenceIo),
    }
    validate_local_directory_chain(&privacy_root)?;
    let active = privacy_root.join(PRIVACY_DATABASE_BASENAME);
    let incoming = privacy_root.join(PRIVACY_INCOMING_BASENAME);
    let active_present = ordinary_file_presence(&active)?;
    let mut incoming_present = ordinary_file_presence(&incoming)?;
    if !active_present && incoming_present {
        match authenticate_empty_privacy_v1_file(&incoming) {
            Ok(proof) if marker_matches_privacy(marker, &proof) => {}
            Ok(_) => return Err(EmptyLegacyBootstrapError::InvalidState),
            Err(_) if allow_incoming_residue_cleanup => {
                remove_fixed_staging_file(&incoming, &privacy_root)?;
                incoming_present = false;
            }
            Err(_) => return Err(EmptyLegacyBootstrapError::InvalidState),
        }
    }
    match (active_present, incoming_present) {
        (true, false) => {
            let proof = authenticate_empty_privacy_v1_file(&active)?;
            if !marker_matches_privacy(marker, &proof) {
                return Err(EmptyLegacyBootstrapError::InvalidState);
            }
        }
        (false, true) => {
            let proof = authenticate_empty_privacy_v1_file(&incoming)?;
            if !marker_matches_privacy(marker, &proof) {
                return Err(EmptyLegacyBootstrapError::InvalidState);
            }
            v031_upgrade_r2::rename_new_no_replace_write_through(&incoming, &active)
                .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
            sync_directory(&privacy_root)?;
        }
        (false, false) => {
            let bytes = v031_upgrade_r2::read_bounded_file(
                &recovery.join(PRIVACY_BACKUP_BASENAME),
                privacy::MAX_PRIVACY_V1_SQLITE_IMAGE_BYTES,
            )
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
            if sha256_hex(&bytes) != marker.privacy_database_sha256
                || u64::try_from(bytes.len()).ok() != Some(marker.privacy_database_bytes)
            {
                return Err(EmptyLegacyBootstrapError::InvalidState);
            }
            v031_upgrade_r2::write_create_new_sync(
                &incoming,
                &bytes,
                privacy::MAX_PRIVACY_V1_SQLITE_IMAGE_BYTES,
            )
            .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
            sync_directory(&privacy_root)?;
            let proof = authenticate_empty_privacy_v1_file(&incoming)?;
            if !marker_matches_privacy(marker, &proof) {
                return Err(EmptyLegacyBootstrapError::InvalidState);
            }
            v031_upgrade_r2::rename_new_no_replace_write_through(&incoming, &active)
                .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
            sync_directory(&privacy_root)?;
        }
        (true, true) => return Err(EmptyLegacyBootstrapError::InvalidState),
    }
    let proof = authenticate_empty_privacy_v1_file(&active)?;
    if !marker_matches_privacy(marker, &proof) || ordinary_file_presence(&incoming)? {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(())
}

fn install_credential_archive(
    recovery: &Path,
    expected: &V031ApprovedMcpCredentialSnapshot,
) -> Result<(String, u64), EmptyLegacyBootstrapError> {
    let final_path = recovery.join(CREDENTIAL_ARCHIVE_BASENAME);
    let staging_path = recovery.join(CREDENTIAL_ARCHIVE_STAGING_BASENAME);
    if ordinary_file_presence(&final_path)? {
        let (snapshot, hash, bytes) = open_credential_archive(&final_path)?;
        authenticate_v031_recovery_approved_mcp_credentials_read_only(&snapshot)
            .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;
        return Ok((hash, bytes));
    }
    let staging_ready = if ordinary_file_presence(&staging_path)? {
        match open_credential_archive(&staging_path).and_then(|(snapshot, _, _)| {
            authenticate_v031_recovery_approved_mcp_credentials_read_only(&snapshot)
                .map_err(|_| EmptyLegacyBootstrapError::CredentialState)
        }) {
            Ok(()) => true,
            Err(_) => {
                remove_fixed_staging_file(&staging_path, recovery)?;
                false
            }
        }
    } else {
        false
    };
    if !staging_ready {
        authenticate_v031_recovery_approved_mcp_credentials_read_only(expected)
            .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;
        let plaintext = expected
            .to_canonical_archive_plaintext()
            .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;
        let protected = protect_local(plaintext.as_bytes())
            .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;
        v031_upgrade_r2::write_create_new_sync(
            &staging_path,
            &protected,
            MAX_PROTECTED_EVIDENCE_BYTES,
        )
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
        sync_directory(recovery)?;
        let (snapshot, _, _) = open_credential_archive(&staging_path)?;
        authenticate_v031_recovery_approved_mcp_credentials_read_only(&snapshot)
            .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;
    }
    v031_upgrade_r2::rename_new_no_replace_write_through(&staging_path, &final_path)
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
    sync_directory(recovery)?;
    let (_, hash, bytes) = open_credential_archive(&final_path)?;
    Ok((hash, bytes))
}

fn open_credential_archive(
    path: &Path,
) -> Result<(V031ApprovedMcpCredentialSnapshot, String, u64), EmptyLegacyBootstrapError> {
    let protected = v031_upgrade_r2::read_bounded_file(path, MAX_PROTECTED_EVIDENCE_BYTES)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    let hash = sha256_hex(&protected);
    let bytes =
        u64::try_from(protected.len()).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    let plaintext = Zeroizing::new(
        unprotect_local(&protected).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?,
    );
    let snapshot =
        V031ApprovedMcpCredentialSnapshot::from_canonical_archive_plaintext(plaintext.as_slice())
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    Ok((snapshot, hash, bytes))
}

fn install_pending_marker(
    app_local_data_dir: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
) -> Result<(), EmptyLegacyBootstrapError> {
    let final_path = app_local_data_dir.join(PENDING_MARKER_BASENAME);
    let staging_path = app_local_data_dir.join(PENDING_MARKER_STAGING_BASENAME);
    if ordinary_file_presence(&final_path)? || ordinary_file_presence(&staging_path)? {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    let plaintext =
        canonical_json_v1(marker).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    let protected =
        protect_local(&plaintext).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    v031_upgrade_r2::write_create_new_sync(&staging_path, &protected, MAX_PROTECTED_EVIDENCE_BYTES)
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
    sync_directory(app_local_data_dir)?;
    let (readback, _) = read_pending_marker(&staging_path)?;
    if &readback != marker {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    v031_upgrade_r2::rename_new_no_replace_write_through(&staging_path, &final_path)
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
    sync_directory(app_local_data_dir)?;
    Ok(())
}

fn read_pending_marker(
    path: &Path,
) -> Result<(EmptyLegacyBootstrapMarkerV1, String), EmptyLegacyBootstrapError> {
    let protected = v031_upgrade_r2::read_bounded_file(path, MAX_PROTECTED_EVIDENCE_BYTES)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    let plaintext = Zeroizing::new(
        unprotect_local(&protected).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?,
    );
    let marker: EmptyLegacyBootstrapMarkerV1 = strict_json_v1_from_slice(plaintext.as_slice())
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    if canonical_json_v1(&marker).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
        != plaintext.as_slice()
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    validate_marker_static(&marker)?;
    Ok((marker, sha256_hex(&protected)))
}

fn validate_marker_static(
    marker: &EmptyLegacyBootstrapMarkerV1,
) -> Result<(), EmptyLegacyBootstrapError> {
    if marker.schema != MARKER_SCHEMA
        || marker.format_version != FORMAT_VERSION
        || marker.source_profile != SOURCE_PROFILE
        || marker.creator_app_version != env!("CARGO_PKG_VERSION")
        || marker.created_at_unix == 0
        || marker.user_table_count != EXPECTED_USER_TABLES
        || marker.user_total_rows != EXPECTED_USER_TOTAL_ROWS
        || marker.user_database_bytes == 0
        || marker.user_backup_bytes != marker.user_database_bytes
        || marker.credential_archive_bytes == 0
        || marker.user_backup_basename != USER_BACKUP_BASENAME
        || marker.credential_archive_basename != CREDENTIAL_ARCHIVE_BASENAME
        || marker.recovery_reason != RECOVERY_REASON
        || marker.privacy_backup_basename != PRIVACY_BACKUP_BASENAME
        || marker.privacy_database_bytes == 0
        || marker.privacy_logical_rows != 1
        || marker.privacy_business_rows != 0
        || [
            &marker.user_schema_manifest_sha256,
            &marker.user_logical_manifest_sha256,
            &marker.user_business_manifest_sha256,
            &marker.user_business_row_manifest_sha256,
            &marker.user_database_sha256,
            &marker.user_backup_sha256,
            &marker.credential_archive_sha256,
            &marker.privacy_database_sha256,
            &marker.privacy_logical_manifest_sha256,
            &marker.privacy_business_manifest_sha256,
            &marker.privacy_business_primary_key_manifest_sha256,
            &marker.privacy_business_row_manifest_sha256,
        ]
        .into_iter()
        .any(|value| !valid_hash(value))
        || marker.user_backup_sha256 != marker.user_database_sha256
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(())
}

fn authenticate_pre_mutation_assets(
    app_local_data_dir: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
) -> Result<(), EmptyLegacyBootstrapError> {
    validate_marker_static(marker)?;
    let candidate = observe_initial_candidate_read_only(app_local_data_dir)?
        .ok_or(EmptyLegacyBootstrapError::InvalidState)?;
    if !marker_matches_user(marker, &candidate.user) {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    let recovery = recovery_directory(app_local_data_dir)?;
    require_pre_mutation_assets_inventory(&recovery)?;
    authenticate_recovery_assets(&recovery, marker)?;
    Ok(())
}

fn authenticate_pending_state_read_only(
    app_local_data_dir: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
    pending_protected_sha256: &str,
) -> Result<(), EmptyLegacyBootstrapError> {
    validate_marker_static(marker)?;
    validate_recovery_namespace_siblings(app_local_data_dir)?;
    validate_local_directory_chain(app_local_data_dir)?;
    if v031_upgrade_r2::verify_exact_target_absence(
        app_local_data_dir,
        &FilesystemOnlyCredentialAbsence,
    )
    .is_err()
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    authenticate_user_copy_against_marker(
        &database::user_database_path(app_local_data_dir),
        marker,
    )?;
    let recovery = recovery_directory(app_local_data_dir)?;
    let inventory = validate_pending_recovery_inventory(&recovery)?;
    let credentials = authenticate_recovery_assets(&recovery, marker)?;
    let prefix =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(&credentials)
            .map_err(|_| EmptyLegacyBootstrapError::CredentialState)?;
    let privacy = observe_reconstructed_privacy_layout_read_only(app_local_data_dir, marker)?;
    if privacy != ReconstructedPrivacyLayout::Active && prefix.prefix_len() != 0 {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    let terminal_repair_state = privacy == ReconstructedPrivacyLayout::Active
        && prefix.prefix_len() == v031_upgrade_r2::ApprovedMcpCredentialRole::ALL.len();
    if !terminal_repair_state && inventory.report != ArtifactPresence::Absent {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    if terminal_repair_state {
        match inventory.report {
            ArtifactPresence::Absent => {}
            ArtifactPresence::Final => {
                let report = read_completed_report(&recovery.join(COMPLETED_REPORT_BASENAME))?;
                validate_completed_report(&report, marker, pending_protected_sha256)?;
            }
            ArtifactPresence::Staging => {
                if let Ok(report) =
                    read_completed_report(&recovery.join(COMPLETED_REPORT_STAGING_BASENAME))
                {
                    validate_completed_report(&report, marker, pending_protected_sha256)?;
                }
            }
        }
    }
    Ok(())
}

fn authenticate_recovery_assets(
    recovery: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
) -> Result<V031ApprovedMcpCredentialSnapshot, EmptyLegacyBootstrapError> {
    validate_recovery_directory(recovery)?;
    let (backup_hash, backup_bytes) =
        authenticate_user_copy_against_marker(&recovery.join(USER_BACKUP_BASENAME), marker)?;
    if backup_hash != marker.user_backup_sha256 || backup_bytes != marker.user_backup_bytes {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    let (credentials, archive_hash, archive_bytes) =
        open_credential_archive(&recovery.join(CREDENTIAL_ARCHIVE_BASENAME))?;
    if archive_hash != marker.credential_archive_sha256
        || archive_bytes != marker.credential_archive_bytes
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    let privacy = authenticate_empty_privacy_v1_file(&recovery.join(PRIVACY_BACKUP_BASENAME))?;
    if !marker_matches_privacy(marker, &privacy) {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(credentials)
}

fn authenticate_user_copy_against_marker(
    path: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
) -> Result<(String, u64), EmptyLegacyBootstrapError> {
    let (proof, ()) =
        database::with_validated_user_database_migration_source_read_only(path, |_| ())
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    if !is_exact_empty_v031_user_proof(&proof) || !marker_matches_user(marker, &proof) {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok((proof.database_file.sha256, proof.database_file.length))
}

fn install_or_authenticate_completed_report(
    recovery: &Path,
    marker: &EmptyLegacyBootstrapMarkerV1,
    pending_protected_sha256: &str,
) -> Result<(), EmptyLegacyBootstrapError> {
    let final_path = recovery.join(COMPLETED_REPORT_BASENAME);
    let staging_path = recovery.join(COMPLETED_REPORT_STAGING_BASENAME);
    if ordinary_file_presence(&final_path)? {
        if ordinary_file_presence(&staging_path)? {
            return Err(EmptyLegacyBootstrapError::InvalidState);
        }
        let report = read_completed_report(&final_path)?;
        return validate_completed_report(&report, marker, pending_protected_sha256);
    }
    let staging_ready = if ordinary_file_presence(&staging_path)? {
        match read_completed_report(&staging_path) {
            Ok(report) => {
                validate_completed_report(&report, marker, pending_protected_sha256)?;
                true
            }
            Err(_) => {
                remove_fixed_staging_file(&staging_path, recovery)?;
                false
            }
        }
    } else {
        false
    };
    if !staging_ready {
        let report = EmptyLegacyBootstrapCompletedV1 {
            schema: REPORT_SCHEMA.to_owned(),
            format_version: FORMAT_VERSION,
            source_profile: SOURCE_PROFILE.to_owned(),
            result_profile: RESULT_PROFILE.to_owned(),
            creator_app_version: env!("CARGO_PKG_VERSION").to_owned(),
            completed_at_unix: unix_now()?,
            pending_marker_protected_sha256: pending_protected_sha256.to_owned(),
            user_database_sha256: marker.user_database_sha256.clone(),
            user_database_bytes: marker.user_database_bytes,
            credential_archive_sha256: marker.credential_archive_sha256.clone(),
            recovery_reason: RECOVERY_REASON.to_owned(),
            privacy_database_sha256: marker.privacy_database_sha256.clone(),
            privacy_database_bytes: marker.privacy_database_bytes,
        };
        validate_completed_report(&report, marker, pending_protected_sha256)?;
        let plaintext =
            canonical_json_v1(&report).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
        let protected =
            protect_local(&plaintext).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
        v031_upgrade_r2::write_create_new_sync(
            &staging_path,
            &protected,
            MAX_PROTECTED_EVIDENCE_BYTES,
        )
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
        sync_directory(recovery)?;
        let readback = read_completed_report(&staging_path)?;
        validate_completed_report(&readback, marker, pending_protected_sha256)?;
    }
    v031_upgrade_r2::rename_new_no_replace_write_through(&staging_path, &final_path)
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
    sync_directory(recovery)?;
    let readback = read_completed_report(&final_path)?;
    validate_completed_report(&readback, marker, pending_protected_sha256)?;
    validate_pending_recovery_inventory(recovery)?;
    Ok(())
}

fn read_completed_report(
    path: &Path,
) -> Result<EmptyLegacyBootstrapCompletedV1, EmptyLegacyBootstrapError> {
    let protected = v031_upgrade_r2::read_bounded_file(path, MAX_PROTECTED_EVIDENCE_BYTES)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    let plaintext = Zeroizing::new(
        unprotect_local(&protected).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?,
    );
    let report: EmptyLegacyBootstrapCompletedV1 =
        strict_json_v1_from_slice(plaintext.as_slice())
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    if canonical_json_v1(&report).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
        != plaintext.as_slice()
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(report)
}

fn validate_completed_report(
    report: &EmptyLegacyBootstrapCompletedV1,
    marker: &EmptyLegacyBootstrapMarkerV1,
    pending_protected_sha256: &str,
) -> Result<(), EmptyLegacyBootstrapError> {
    if report.schema != REPORT_SCHEMA
        || report.format_version != FORMAT_VERSION
        || report.source_profile != SOURCE_PROFILE
        || report.result_profile != RESULT_PROFILE
        || report.creator_app_version != env!("CARGO_PKG_VERSION")
        || report.completed_at_unix == 0
        || !valid_hash(&report.pending_marker_protected_sha256)
        || report.pending_marker_protected_sha256 != pending_protected_sha256
        || report.user_database_sha256 != marker.user_database_sha256
        || report.user_database_bytes != marker.user_database_bytes
        || report.credential_archive_sha256 != marker.credential_archive_sha256
        || report.recovery_reason != RECOVERY_REASON
        || report.privacy_database_sha256 != marker.privacy_database_sha256
        || report.privacy_database_bytes != marker.privacy_database_bytes
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(())
}

fn marker_matches_user(
    marker: &EmptyLegacyBootstrapMarkerV1,
    proof: &database::UserMigrationSourceProof,
) -> bool {
    is_exact_empty_v031_user_proof(proof)
        && marker.user_schema_manifest_sha256 == proof.schema_manifest_sha256
        && marker.user_logical_manifest_sha256 == proof.logical_database_manifest_sha256
        && marker.user_business_manifest_sha256 == proof.business_manifest_sha256
        && marker.user_business_row_manifest_sha256 == proof.business_row_manifest_sha256
        && marker.user_database_sha256 == proof.database_file.sha256
        && marker.user_database_bytes == proof.database_file.length
        && marker.user_table_count == proof.tables.len() as u64
        && marker.user_total_rows == proof.total_rows
}

fn same_user_source(
    left: &database::UserMigrationSourceProof,
    right: &database::UserMigrationSourceProof,
) -> bool {
    left.schema == right.schema
        && left.schema_manifest_sha256 == right.schema_manifest_sha256
        && left.logical_database_manifest_sha256 == right.logical_database_manifest_sha256
        && left.business_manifest_sha256 == right.business_manifest_sha256
        && left.business_primary_key_manifest_sha256 == right.business_primary_key_manifest_sha256
        && left.business_row_manifest_sha256 == right.business_row_manifest_sha256
        && left.database_file.sha256 == right.database_file.sha256
        && left.database_file.length == right.database_file.length
        && left.tables == right.tables
        && left.total_rows == right.total_rows
        && left.wal.is_none()
        && right.wal.is_none()
        && left.shm.is_none()
        && right.shm.is_none()
        && left.journal.is_none()
        && right.journal.is_none()
}

fn validate_recovery_namespace_siblings(
    app_local_data_dir: &Path,
) -> Result<(), EmptyLegacyBootstrapError> {
    let metadata = match fs::symlink_metadata(app_local_data_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(EmptyLegacyBootstrapError::InvalidState),
        Ok(metadata) => metadata,
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    validate_local_directory_chain(app_local_data_dir)?;
    for entry in
        fs::read_dir(app_local_data_dir).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
    {
        let name = entry
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?
            .file_name()
            .into_string()
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
        let lowercase = name.to_ascii_lowercase();
        let recovery_like = lowercase.starts_with("legacy-empty-bootstrap-recovery-v1");
        let pending_like = lowercase.starts_with("legacy-empty-bootstrap-pending.dpapi");
        if (recovery_like && name != RECOVERY_DIRECTORY)
            || (pending_like
                && name != PENDING_MARKER_BASENAME
                && name != PENDING_MARKER_STAGING_BASENAME)
        {
            return Err(EmptyLegacyBootstrapError::InvalidState);
        }
    }
    Ok(())
}

fn observe_recovery_inventory(
    recovery: &Path,
) -> Result<RecoveryInventory, EmptyLegacyBootstrapError> {
    validate_recovery_directory(recovery)?;
    let mut names = Vec::new();
    for entry in fs::read_dir(recovery).map_err(|_| EmptyLegacyBootstrapError::InvalidState)? {
        let entry = entry.map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
        if !matches!(
            name.as_str(),
            USER_BACKUP_BASENAME
                | USER_BACKUP_STAGING_BASENAME
                | CREDENTIAL_ARCHIVE_BASENAME
                | CREDENTIAL_ARCHIVE_STAGING_BASENAME
                | PRIVACY_BACKUP_BASENAME
                | PRIVACY_BACKUP_STAGING_BASENAME
                | COMPLETED_REPORT_BASENAME
                | COMPLETED_REPORT_STAGING_BASENAME
        ) {
            return Err(EmptyLegacyBootstrapError::InvalidState);
        }
        v031_upgrade_r2::verify_plain_single_link_file(&entry.path())
            .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
        names.push(name);
    }
    names.sort();
    names.dedup();
    Ok(RecoveryInventory {
        user: artifact_presence(&names, USER_BACKUP_BASENAME, USER_BACKUP_STAGING_BASENAME)?,
        credentials: artifact_presence(
            &names,
            CREDENTIAL_ARCHIVE_BASENAME,
            CREDENTIAL_ARCHIVE_STAGING_BASENAME,
        )?,
        privacy: artifact_presence(
            &names,
            PRIVACY_BACKUP_BASENAME,
            PRIVACY_BACKUP_STAGING_BASENAME,
        )?,
        report: artifact_presence(
            &names,
            COMPLETED_REPORT_BASENAME,
            COMPLETED_REPORT_STAGING_BASENAME,
        )?,
    })
}

fn artifact_presence(
    names: &[String],
    final_name: &str,
    staging_name: &str,
) -> Result<ArtifactPresence, EmptyLegacyBootstrapError> {
    match (
        names.iter().any(|name| name == final_name),
        names.iter().any(|name| name == staging_name),
    ) {
        (false, false) => Ok(ArtifactPresence::Absent),
        (false, true) => Ok(ArtifactPresence::Staging),
        (true, false) => Ok(ArtifactPresence::Final),
        (true, true) => Err(EmptyLegacyBootstrapError::InvalidState),
    }
}

fn validate_pre_marker_recovery_inventory(
    recovery: &Path,
) -> Result<(), EmptyLegacyBootstrapError> {
    let inventory = observe_recovery_inventory(recovery)?;
    let valid_prefix = matches!(
        (inventory.user, inventory.credentials, inventory.privacy),
        (
            ArtifactPresence::Absent,
            ArtifactPresence::Absent,
            ArtifactPresence::Absent
        ) | (
            ArtifactPresence::Staging,
            ArtifactPresence::Absent,
            ArtifactPresence::Absent
        ) | (
            ArtifactPresence::Final,
            ArtifactPresence::Absent,
            ArtifactPresence::Absent
        ) | (
            ArtifactPresence::Final,
            ArtifactPresence::Staging,
            ArtifactPresence::Absent
        ) | (
            ArtifactPresence::Final,
            ArtifactPresence::Final,
            ArtifactPresence::Absent
        ) | (
            ArtifactPresence::Final,
            ArtifactPresence::Final,
            ArtifactPresence::Staging
        ) | (
            ArtifactPresence::Final,
            ArtifactPresence::Final,
            ArtifactPresence::Final
        )
    );
    if !valid_prefix || inventory.report != ArtifactPresence::Absent {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(())
}

fn require_pre_mutation_assets_inventory(recovery: &Path) -> Result<(), EmptyLegacyBootstrapError> {
    let inventory = observe_recovery_inventory(recovery)?;
    if inventory
        != (RecoveryInventory {
            user: ArtifactPresence::Final,
            credentials: ArtifactPresence::Final,
            privacy: ArtifactPresence::Final,
            report: ArtifactPresence::Absent,
        })
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(())
}

fn validate_pending_recovery_inventory(
    recovery: &Path,
) -> Result<RecoveryInventory, EmptyLegacyBootstrapError> {
    let inventory = observe_recovery_inventory(recovery)?;
    if inventory.user != ArtifactPresence::Final
        || inventory.credentials != ArtifactPresence::Final
        || inventory.privacy != ArtifactPresence::Final
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(inventory)
}

fn remove_fixed_staging_file(
    path: &Path,
    expected_parent: &Path,
) -> Result<(), EmptyLegacyBootstrapError> {
    if path.parent() != Some(expected_parent) {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    v031_upgrade_r2::verify_plain_single_link_file(path)
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    fs::remove_file(path).map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)?;
    sync_directory(expected_parent)?;
    if ordinary_file_presence(path)? {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(())
}

fn recovery_directory(app_local_data_dir: &Path) -> Result<PathBuf, EmptyLegacyBootstrapError> {
    if !app_local_data_dir.is_absolute() {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(app_local_data_dir.join(RECOVERY_DIRECTORY))
}

fn ensure_recovery_directory(path: &Path) -> Result<(), EmptyLegacyBootstrapError> {
    if !crate::privacy_manager::is_normal_local_absolute(path)
        || !crate::privacy_manager::local_path_chain_is_ordinary(path)
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    match fs::create_dir(path) {
        Ok(()) => {
            let parent = path
                .parent()
                .ok_or(EmptyLegacyBootstrapError::InvalidState)?;
            sync_directory(parent)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(EmptyLegacyBootstrapError::EvidenceIo),
    }
    validate_recovery_directory(path)
}

fn validate_recovery_directory(path: &Path) -> Result<(), EmptyLegacyBootstrapError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    validate_local_directory_chain(path)?;
    Ok(())
}

fn validate_local_directory_chain(path: &Path) -> Result<(), EmptyLegacyBootstrapError> {
    if !crate::privacy_manager::is_normal_local_absolute(path)
        || !crate::privacy_manager::local_path_chain_is_ordinary(path)
    {
        return Err(EmptyLegacyBootstrapError::InvalidState);
    }
    Ok(())
}

fn ordinary_file_presence(path: &Path) -> Result<bool, EmptyLegacyBootstrapError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            v031_upgrade_r2::verify_plain_single_link_file(path)
                .map_err(|_| EmptyLegacyBootstrapError::InvalidState)?;
            Ok(true)
        }
        Ok(_) => Err(EmptyLegacyBootstrapError::InvalidState),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(EmptyLegacyBootstrapError::InvalidState),
    }
}

fn path_presence_requires_absence(path: &Path) -> Result<bool, EmptyLegacyBootstrapError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(EmptyLegacyBootstrapError::InvalidState),
    }
}

fn sync_directory(path: &Path) -> Result<(), EmptyLegacyBootstrapError> {
    PlatformDirectorySync
        .sync_directory(path)
        .map_err(|_| EmptyLegacyBootstrapError::EvidenceIo)
}

fn unix_now() -> Result<u64, EmptyLegacyBootstrapError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| EmptyLegacyBootstrapError::InvalidState)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct FrozenV031UserSchemaObject {
        object_type: String,
        sql: String,
    }

    fn create_exact_empty_v031_user(root: &Path) {
        let user_database_path = database::user_database_path(root);
        let connection = rusqlite::Connection::open(&user_database_path).unwrap();
        let objects =
            include_str!("../../../../crates/database/schema/v031-user-sqlite-master.jsonl")
                .lines()
                .map(|line| serde_json::from_str::<FrozenV031UserSchemaObject>(line).unwrap())
                .collect::<Vec<_>>();
        for object_type in ["table", "index", "trigger", "view"] {
            for object in objects
                .iter()
                .filter(|object| object.object_type == object_type)
            {
                connection.execute_batch(&object.sql).unwrap();
            }
        }
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_SCHEMA_VERSION.to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('canonical_schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_CANONICAL_SCHEMA_MARKER],
            )
            .unwrap();
    }

    fn hash(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn empty_user_proof() -> database::UserMigrationSourceProof {
        let mut tables = (0..26)
            .map(|index| database::UserMigrationTableProof {
                table: format!("business_{index:02}"),
                rows: 0,
                logical_manifest_sha256: hash(&format!("logical-{index}")),
                business_manifest_sha256: Some(hash(&format!("business-{index}"))),
                business_primary_key_manifest_sha256: Some(hash(&format!("pk-{index}"))),
                business_row_manifest_sha256: Some(hash(&format!("rows-{index}"))),
            })
            .collect::<Vec<_>>();
        tables.push(database::UserMigrationTableProof {
            table: "user_database_metadata".to_owned(),
            rows: 2,
            logical_manifest_sha256: hash("metadata"),
            business_manifest_sha256: None,
            business_primary_key_manifest_sha256: None,
            business_row_manifest_sha256: None,
        });
        tables.sort_by(|left, right| left.table.cmp(&right.table));
        database::UserMigrationSourceProof {
            schema: database::ValidatedUserSourceSchema::V031V10,
            database_file: database::UserMigrationSourceFileProof {
                identity_sha256: hash("identity"),
                length: 4096,
                modified_unix_nanos: Some(1),
                sha256: hash("database"),
            },
            wal: None,
            shm: None,
            journal: None,
            schema_manifest_sha256: hash("schema"),
            logical_database_manifest_sha256: hash("logical"),
            business_manifest_sha256: hash("business"),
            business_primary_key_manifest_sha256: hash("pk"),
            business_row_manifest_sha256: hash("rows"),
            tables,
            total_rows: 2,
            data_version: 1,
        }
    }

    #[test]
    fn exact_empty_user_gate_rejects_every_data_or_sidecar_shape() {
        let exact = empty_user_proof();
        assert!(is_exact_empty_v031_user_proof(&exact));

        let mut business_row = exact.clone();
        business_row.tables[0].rows = 1;
        business_row.total_rows = 3;
        assert!(!is_exact_empty_v031_user_proof(&business_row));

        let mut metadata_row = exact.clone();
        let metadata = metadata_row
            .tables
            .iter_mut()
            .find(|table| table.table == "user_database_metadata")
            .unwrap();
        metadata.rows = 3;
        metadata_row.total_rows = 3;
        assert!(!is_exact_empty_v031_user_proof(&metadata_row));

        let mut current = exact.clone();
        current.schema = database::ValidatedUserSourceSchema::CurrentV11;
        assert!(!is_exact_empty_v031_user_proof(&current));

        let mut wal = exact.clone();
        wal.wal = Some(database::UserMigrationSourceFileProof {
            identity_sha256: hash("wal-identity"),
            length: 1,
            modified_unix_nanos: Some(1),
            sha256: hash("wal"),
        });
        assert!(!is_exact_empty_v031_user_proof(&wal));
    }

    #[test]
    fn pending_marker_contract_binds_exact_backup_archive_and_reconstructed_privacy() {
        let proof = empty_user_proof();
        let marker = EmptyLegacyBootstrapMarkerV1 {
            schema: MARKER_SCHEMA.to_owned(),
            format_version: FORMAT_VERSION,
            source_profile: SOURCE_PROFILE.to_owned(),
            creator_app_version: env!("CARGO_PKG_VERSION").to_owned(),
            created_at_unix: 1,
            user_schema_manifest_sha256: proof.schema_manifest_sha256.clone(),
            user_logical_manifest_sha256: proof.logical_database_manifest_sha256.clone(),
            user_business_manifest_sha256: proof.business_manifest_sha256.clone(),
            user_business_row_manifest_sha256: proof.business_row_manifest_sha256.clone(),
            user_database_sha256: proof.database_file.sha256.clone(),
            user_database_bytes: proof.database_file.length,
            user_table_count: proof.tables.len() as u64,
            user_total_rows: proof.total_rows,
            user_backup_basename: USER_BACKUP_BASENAME.to_owned(),
            user_backup_sha256: proof.database_file.sha256.clone(),
            user_backup_bytes: proof.database_file.length,
            credential_archive_basename: CREDENTIAL_ARCHIVE_BASENAME.to_owned(),
            credential_archive_sha256: hash("archive"),
            credential_archive_bytes: 128,
            recovery_reason: RECOVERY_REASON.to_owned(),
            privacy_backup_basename: PRIVACY_BACKUP_BASENAME.to_owned(),
            privacy_database_sha256: hash("privacy-database"),
            privacy_database_bytes: 77_824,
            privacy_logical_manifest_sha256: hash("privacy-logical"),
            privacy_business_manifest_sha256: hash("privacy-business"),
            privacy_business_primary_key_manifest_sha256: hash("privacy-pk"),
            privacy_business_row_manifest_sha256: hash("privacy-rows"),
            privacy_logical_rows: 1,
            privacy_business_rows: 0,
        };
        validate_marker_static(&marker).unwrap();
        assert!(marker_matches_user(&marker, &proof));
        let canonical = canonical_json_v1(&marker).unwrap();
        let decoded: EmptyLegacyBootstrapMarkerV1 = strict_json_v1_from_slice(&canonical).unwrap();
        assert_eq!(decoded, marker);

        let mut wrong_backup = marker.clone();
        wrong_backup.user_backup_sha256 = hash("different");
        assert_eq!(
            validate_marker_static(&wrong_backup),
            Err(EmptyLegacyBootstrapError::InvalidState)
        );
    }

    #[test]
    fn reconstructed_privacy_v1_is_exact_empty_and_deterministic() {
        let first = reconstructed_empty_privacy_v1_image().unwrap();
        let second = reconstructed_empty_privacy_v1_image().unwrap();
        assert_eq!(sha256_hex(&first), sha256_hex(&second));
        let proof = privacy::validate_privacy_v1_sqlite_image_read_only(&first).unwrap();
        validate_empty_privacy_v1_proof(&proof).unwrap();
        assert_eq!(proof.logical_manifest.total_row_count, 1);
        assert_eq!(proof.business_manifest.total_row_count, 0);
        assert_eq!(proof.protected_review_payload_count, 0);
    }

    #[test]
    fn recovery_inventory_accepts_only_the_frozen_phase_prefixes() {
        let directory = tempfile::tempdir().unwrap();
        let recovery = directory.path();
        validate_pre_marker_recovery_inventory(recovery).unwrap();

        fs::write(recovery.join(USER_BACKUP_STAGING_BASENAME), b"partial").unwrap();
        validate_pre_marker_recovery_inventory(recovery).unwrap();
        fs::remove_file(recovery.join(USER_BACKUP_STAGING_BASENAME)).unwrap();
        fs::write(recovery.join(USER_BACKUP_BASENAME), b"user").unwrap();
        fs::write(recovery.join(CREDENTIAL_ARCHIVE_BASENAME), b"credentials").unwrap();
        fs::write(recovery.join(PRIVACY_BACKUP_BASENAME), b"privacy").unwrap();
        require_pre_mutation_assets_inventory(recovery).unwrap();
        validate_pending_recovery_inventory(recovery).unwrap();

        fs::write(recovery.join(COMPLETED_REPORT_STAGING_BASENAME), b"partial").unwrap();
        validate_pending_recovery_inventory(recovery).unwrap();
        assert_eq!(
            require_pre_mutation_assets_inventory(recovery),
            Err(EmptyLegacyBootstrapError::InvalidState)
        );
    }

    #[test]
    fn recovery_inventory_rejects_unknown_reverse_and_dual_artifacts() {
        let unknown = tempfile::tempdir().unwrap();
        fs::write(unknown.path().join("unexpected"), b"x").unwrap();
        assert_eq!(
            validate_pre_marker_recovery_inventory(unknown.path()),
            Err(EmptyLegacyBootstrapError::InvalidState)
        );

        let reverse = tempfile::tempdir().unwrap();
        fs::write(reverse.path().join(CREDENTIAL_ARCHIVE_BASENAME), b"x").unwrap();
        assert_eq!(
            validate_pre_marker_recovery_inventory(reverse.path()),
            Err(EmptyLegacyBootstrapError::InvalidState)
        );

        let dual = tempfile::tempdir().unwrap();
        fs::write(dual.path().join(USER_BACKUP_BASENAME), b"x").unwrap();
        fs::write(dual.path().join(USER_BACKUP_STAGING_BASENAME), b"x").unwrap();
        assert_eq!(
            validate_pre_marker_recovery_inventory(dual.path()),
            Err(EmptyLegacyBootstrapError::InvalidState)
        );
    }

    #[test]
    fn fixed_partial_staging_cleanup_is_narrow_and_single_link_only() {
        let directory = tempfile::tempdir().unwrap();
        let staging = directory.path().join(USER_BACKUP_STAGING_BASENAME);
        fs::write(&staging, b"partial").unwrap();
        remove_fixed_staging_file(&staging, directory.path()).unwrap();
        assert!(!staging.exists());

        let original = directory.path().join("original");
        fs::write(&original, b"shared").unwrap();
        fs::hard_link(&original, &staging).unwrap();
        assert_eq!(
            remove_fixed_staging_file(&staging, directory.path()),
            Err(EmptyLegacyBootstrapError::InvalidState)
        );
        assert!(original.exists());
        assert!(staging.exists());
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_empty_legacy_bootstrap_repairs_to_exact_v031_without_touching_non_target_credential(
    ) {
        use crate::v031_upgrade_r2::ApprovedMcpCredentialRole;

        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        create_exact_empty_v031_user(root);
        let original_user = fs::read(database::user_database_path(root)).unwrap();

        let mut credentials =
            crate::approved_mcp::V031CrossProcessCredentialHarness::create_parent(
                root.to_path_buf(),
            )
            .unwrap();
        credentials.seed_v031_target_credentials_for_test().unwrap();
        let seeded_probe = credentials.credential_probe();
        for role in ApprovedMcpCredentialRole::ALL {
            assert!(seeded_probe
                .credential_exists_read_only(CredentialAbsenceQuery {
                    role,
                    target: role.target(),
                    account: v031_upgrade_r2::APPROVED_MCP_CREDENTIAL_ACCOUNT,
                })
                .unwrap());
        }
        assert!(!root.join(PRIVACY_DIRECTORY_NAME).exists());
        let signer_before = Zeroizing::new(
            credentials
                .load_or_create_privacy_receipt_signer_key()
                .unwrap(),
        );
        let override_guard = credentials
            .install_recovery_credential_override_for_test()
            .unwrap();

        let mut observed = crate::v031_startup::observe_production_startup_read_only(root).unwrap();
        assert_eq!(
            observed.summary().profile,
            crate::v031_startup::InstalledProfile::EmptyLegacyBootstrap
        );
        assert_eq!(
            crate::v031_startup::classify_startup(observed.summary()),
            Ok(crate::v031_startup::StartupRoute::RepairEmptyLegacyBootstrapAndRestart)
        );
        let gate = observed.take_empty_legacy_bootstrap_gate().unwrap();
        assert_eq!(
            repair_observed_interrupted_empty_legacy_profile(root, gate),
            Ok(EmptyLegacyBootstrapOutcome::Completed)
        );

        let probe = credentials.credential_probe();
        for role in ApprovedMcpCredentialRole::ALL {
            assert!(!probe
                .credential_exists_read_only(CredentialAbsenceQuery {
                    role,
                    target: role.target(),
                    account: v031_upgrade_r2::APPROVED_MCP_CREDENTIAL_ACCOUNT,
                })
                .unwrap());
        }
        let signer_after = Zeroizing::new(
            credentials
                .load_privacy_receipt_signer_key_read_only()
                .unwrap(),
        );
        assert!(signer_before.as_ref() == signer_after.as_ref());
        assert!(
            original_user.as_slice()
                == fs::read(database::user_database_path(root))
                    .unwrap()
                    .as_slice()
        );
        assert!(
            original_user.as_slice()
                == fs::read(recovery_directory(root).unwrap().join(USER_BACKUP_BASENAME))
                    .unwrap()
                    .as_slice()
        );

        let privacy_path = root
            .join(PRIVACY_DIRECTORY_NAME)
            .join(PRIVACY_DATABASE_BASENAME);
        let privacy =
            privacy::validate_privacy_v1_migration_source_read_only(&privacy_path).unwrap();
        validate_empty_privacy_v1_proof(&privacy).unwrap();
        assert!(!root.join(PENDING_MARKER_BASENAME).exists());
        assert!(!root
            .join(PRIVACY_DIRECTORY_NAME)
            .join(PRIVACY_INCOMING_BASENAME)
            .exists());
        assert!(recovery_directory(root)
            .unwrap()
            .join(COMPLETED_REPORT_BASENAME)
            .is_file());

        let observed = crate::v031_startup::observe_production_startup_read_only(root).unwrap();
        assert_eq!(
            observed.summary().profile,
            crate::v031_startup::InstalledProfile::ExactV031Source
        );
        assert_eq!(
            crate::v031_startup::classify_startup(observed.summary()),
            Ok(
                crate::v031_startup::StartupRoute::AdvanceUpgradeThroughReceiptEight {
                    next_ordinal: 0
                }
            )
        );

        drop(override_guard);
        credentials.cleanup().unwrap();
    }
}
