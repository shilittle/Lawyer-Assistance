use crate::{commands::case::IpcError, state::AppState};
#[cfg(test)]
use rusqlite::{backup::Backup, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use std::fs::OpenOptions;
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use tauri::State;
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    },
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub app_version: String,
    pub build_unix: u64,
    pub user_schema_version: i64,
    pub legal_database_version: String,
    pub legal_data_scope: String,
    pub source_manifest_hash: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiagnosticRequest {
    pub destination_path: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileOperationResponse {
    pub completed: bool,
    pub cancelled: bool,
    pub path: Option<String>,
    pub restart_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingRestoreMarker {
    format_version: u8,
    incoming_sha256: String,
}

const PENDING_RESTORE_FORMAT_VERSION: u8 = 1;
const MAX_PENDING_RESTORE_MARKER_BYTES: u64 = 4 * 1024;
#[cfg(test)]
const MAX_DATABASE_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingDatabaseRestorePhase {
    /// Marker, active v11, and authenticated incoming v11 are present. No
    /// rollback has been created yet.
    Prepared,
    /// The previous active database reached the rollback slot, while the
    /// authenticated incoming database has not reached the active slot.
    ActiveMovedToRollback,
    /// The marker-bound replacement is active. The previous database may
    /// still occupy the rollback slot until cleanup commits.
    InstalledPendingCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingRestoreFileProof {
    identity_sha256: String,
    length: u64,
    modified_unix_nanos: Option<u128>,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingRestoreDatabaseProof {
    file: PendingRestoreFileProof,
    schema_manifest_sha256: String,
    logical_database_manifest_sha256: String,
    business_manifest_sha256: String,
    case_assistant_pending_output_rows: u64,
}

/// Path-free, non-forgeable capability returned only after the complete
/// legacy-user restore namespace has been authenticated read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingDatabaseRestoreGate {
    phase: PendingDatabaseRestorePhase,
    marker: PendingRestoreMarker,
    marker_file: PendingRestoreFileProof,
    incoming: Option<PendingRestoreDatabaseProof>,
    active: Option<PendingRestoreDatabaseProof>,
    rollback: Option<PendingRestoreDatabaseProof>,
}

impl PendingDatabaseRestoreGate {
    #[cfg(test)]
    pub(crate) const fn phase(&self) -> PendingDatabaseRestorePhase {
        self.phase
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Keep the observed restore proof inline as one non-forgeable capability.
#[allow(clippy::large_enum_variant)]
pub(crate) enum PendingDatabaseRestoreObservation {
    Absent,
    Authenticated(PendingDatabaseRestoreGate),
}

#[tauri::command]
pub fn get_version_info(state: State<'_, AppState>) -> Result<VersionInfo, IpcError> {
    let legal = database::open_legal_core_read_only(state.legal_core_path())?;
    let metadata = |key: &str| -> String {
        legal
            .query_row(
                "SELECT value FROM database_metadata WHERE key=?1",
                [key],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "unknown".into())
    };
    Ok(VersionInfo {
        app_version: env!("CARGO_PKG_VERSION").into(),
        build_unix: env!("LAWYER_ASSISTANCE_BUILD_UNIX")
            .parse()
            .unwrap_or_default(),
        user_schema_version: database::USER_SCHEMA_VERSION,
        legal_database_version: metadata("dataset_version"),
        legal_data_scope: metadata("data_scope"),
        source_manifest_hash: metadata("source_manifest_sha256"),
    })
}
#[cfg(test)]
fn require_protected_database_backup() -> Result<(), IpcError> {
    Err(IpcError::new(
        "privacy_required",
        "Plaintext user database backup is disabled until encrypted local-only backup is available.",
    ))
}
#[tauri::command]
pub fn export_diagnostic_report(
    state: State<'_, AppState>,
    request: DiagnosticRequest,
) -> Result<FileOperationResponse, IpcError> {
    let Some(destination_path) = request
        .destination_path
        .filter(|path| !path.trim().is_empty())
    else {
        return Ok(cancelled());
    };
    let crash_events = crate::crash_log::read(state.crash_log_path()).map_err(io_error)?;
    let report = format!(
        "Lawyer Assistance {}\nbuild unix {}\nuser schema {}\nos {} {}\n\ncrash events (payload-free)\n{}",
        env!("CARGO_PKG_VERSION"),
        env!("LAWYER_ASSISTANCE_BUILD_UNIX"),
        database::USER_SCHEMA_VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH,
        sanitize_diagnostic_text(&crash_events)
    );
    let destination = Path::new(&destination_path);
    let restore = restore_paths(state.user_database_path())?;
    let protected = protected_application_paths(
        state.user_database_path(),
        state.legal_core_path(),
        state.crash_log_path(),
        &restore,
    );
    write_diagnostic_report(destination, &report, &protected)?;
    Ok(FileOperationResponse {
        completed: true,
        cancelled: false,
        path: Some(destination_path),
        restart_required: false,
    })
}

fn write_diagnostic_report(
    destination: &Path,
    report: &str,
    protected_paths: &[&Path],
) -> Result<(), IpcError> {
    if protected_paths
        .iter()
        .any(|protected| paths_refer_to_same_file(protected, destination))
    {
        return Err(IpcError::new(
            "validation",
            "diagnostic destination must not replace application state or a legal resource",
        ));
    }
    if destination.is_dir() {
        return Err(IpcError::new(
            "validation",
            "diagnostic destination must name a file",
        ));
    }
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    let incoming = unique_sibling(destination, "diagnostic-incoming")?;
    let previous = unique_sibling(destination, "diagnostic-previous")?;
    let mut file = File::create(&incoming).map_err(io_error)?;
    if let Err(error) = file
        .write_all(report.as_bytes())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&incoming);
        return Err(io_error(error));
    }
    drop(file);
    if let Err(error) = crate::atomic_file::install(
        &incoming,
        destination,
        destination.exists().then_some(previous.as_path()),
    ) {
        let _ = fs::remove_file(&incoming);
        return Err(io_error(error));
    }
    if previous.exists() {
        fs::remove_file(previous).map_err(io_error)?;
    }
    Ok(())
}
fn cancelled() -> FileOperationResponse {
    FileOperationResponse {
        completed: false,
        cancelled: true,
        path: None,
        restart_required: false,
    }
}

#[cfg(test)]
fn backup_database(
    source: &Path,
    destination: &Path,
    protected_paths: &[&Path],
) -> Result<(), IpcError> {
    if protected_paths
        .iter()
        .any(|protected| paths_refer_to_same_file(protected, destination))
    {
        return Err(IpcError::new(
            "validation",
            "backup destination must not replace application state or a legal resource",
        ));
    }
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(io_error)?
    }
    let incoming = unique_sibling(destination, "backup-incoming")?;
    let previous = unique_sibling(destination, "backup-previous")?;
    let source = database::open_user_database(source)?;
    let mut destination_connection = Connection::open(&incoming).map_err(IpcError::from)?;
    if let Err(error) = Backup::new(&source, &mut destination_connection)
        .and_then(|backup| backup.run_to_completion(64, std::time::Duration::from_millis(1), None))
    {
        drop(destination_connection);
        let _ = fs::remove_file(incoming);
        return Err(error.into());
    }
    drop(destination_connection);
    database::validate_and_migrate_user_database(&incoming).map_err(|error| {
        let _ = fs::remove_file(&incoming);
        IpcError::from(error)
    })?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&incoming)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    let destination_existed = destination.exists();
    if let Err(error) = crate::atomic_file::install(
        &incoming,
        destination,
        destination_existed.then_some(previous.as_path()),
    ) {
        let _ = fs::remove_file(incoming);
        return Err(io_error(error));
    }
    if previous.exists() {
        let _ = fs::remove_file(previous);
    }
    Ok(())
}

#[cfg(test)]
fn stage_database_restore(source: &Path, destination: &Path) -> Result<(), IpcError> {
    if !source.is_file() {
        return Err(IpcError::new("validation", "backup file does not exist"));
    }
    if paths_refer_to_same_file(source, destination) {
        return Err(IpcError::new(
            "validation",
            "restore source must differ from the active database",
        ));
    }
    let size = source.metadata().map_err(io_error)?.len();
    if size == 0 || size > MAX_DATABASE_FILE_BYTES {
        return Err(IpcError::new(
            "validation",
            "backup database size is outside the supported range",
        ));
    }
    let paths = restore_paths(destination)?;
    if paths.marker.exists() {
        return Err(IpcError::new(
            "restore_pending",
            "a validated restore is already pending application restart",
        ));
    }
    if paths.incoming.exists() {
        fs::remove_file(&paths.incoming).map_err(io_error)?;
    }
    let copy_path = unique_sibling(destination, "restore-copy")?;
    if let Err(error) = fs::copy(source, &copy_path) {
        let _ = fs::remove_file(&copy_path);
        return Err(io_error(error));
    }
    if let Err(error) = database::validate_and_migrate_user_database(&copy_path) {
        let _ = fs::remove_file(&copy_path);
        return Err(error.into());
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&copy_path)
        .and_then(|file| file.sync_all())
        .map_err(io_error)?;
    let incoming_sha256 = file_sha256(&copy_path)?;
    if let Err(error) = crate::atomic_file::install(&copy_path, &paths.incoming, None) {
        let _ = fs::remove_file(copy_path);
        return Err(io_error(error));
    }
    let marker = PendingRestoreMarker {
        format_version: PENDING_RESTORE_FORMAT_VERSION,
        incoming_sha256,
    };
    if let Err(error) = write_pending_marker(&paths.marker, &marker) {
        let _ = fs::remove_file(&paths.incoming);
        return Err(error);
    }
    Ok(())
}

/// Authenticates the complete legacy-user restore namespace without creating,
/// repairing, deleting, renaming, or opening a writable SQLite connection.
///
/// An absent marker is accepted only when both mutation slots and every
/// restore-namespaced sibling are also absent. A present marker must be the
/// exact canonical JSON produced by the staging protocol and must describe one
/// of the three frozen crash states below. Every database image is exact v11,
/// sidecar-free, ordinary, single-link, stable, and lineage-safe before a gate
/// can escape this module.
pub(crate) fn observe_pending_database_restore_read_only(
    app_local_data_dir: &Path,
) -> Result<PendingDatabaseRestoreObservation, IpcError> {
    let destination = database::user_database_path(app_local_data_dir);
    let paths = restore_paths(&destination)?;
    reject_unknown_restore_namespace_entries(&destination, &paths)?;

    let marker_present = restore_slot_present(&paths.marker)?;
    let incoming_present = restore_slot_present(&paths.incoming)?;
    let active_present = restore_slot_present(&destination)?;
    let rollback_present = restore_slot_present(&paths.rollback)?;

    if !marker_present {
        if incoming_present || rollback_present {
            return Err(restore_pending_error(
                "an unmarked legacy-user restore mutation slot is present",
            ));
        }
        return Ok(PendingDatabaseRestoreObservation::Absent);
    }

    let (marker, marker_file) = read_canonical_pending_restore_marker(&paths.marker)?;
    let phase = match (incoming_present, active_present, rollback_present) {
        (true, true, false) => PendingDatabaseRestorePhase::Prepared,
        (true, false, true) => PendingDatabaseRestorePhase::ActiveMovedToRollback,
        (false, true, _) => PendingDatabaseRestorePhase::InstalledPendingCleanup,
        _ => {
            return Err(restore_pending_error(
                "the legacy-user restore slots do not match a complete crash state",
            ))
        }
    };

    let incoming = incoming_present
        .then(|| observe_current_restore_database(&paths.incoming, "incoming"))
        .transpose()?;
    let active = active_present
        .then(|| observe_current_restore_database(&destination, "active"))
        .transpose()?;
    let rollback = rollback_present
        .then(|| observe_current_restore_database(&paths.rollback, "rollback"))
        .transpose()?;

    let installed = match phase {
        PendingDatabaseRestorePhase::Prepared
        | PendingDatabaseRestorePhase::ActiveMovedToRollback => incoming.as_ref(),
        PendingDatabaseRestorePhase::InstalledPendingCleanup => active.as_ref(),
    }
    .ok_or_else(|| restore_pending_error("the marker-bound restore image is absent"))?;
    if installed.file.sha256 != marker.incoming_sha256 {
        return Err(restore_pending_error(
            "the marker-bound restore image digest does not match canonical evidence",
        ));
    }

    if legacy_restore_database_proofs_have_unified_lineage(&incoming, &active, &rollback) {
        return Err(IpcError::new(
            "application_restore_requires_five_components",
            "A legacy user-database restore cannot replace or install case-assistant pending-output lineage. Restore an authenticated five-component backup instead.",
        ));
    }

    // This probe is deliberately part of observation. It cannot create a
    // manager or mutate storage, and it prevents a single-database restore
    // from severing already-unified Privacy/Vault/application lineage.
    super::application_backup::ensure_standalone_restore_is_lineage_safe(app_local_data_dir)
        .map_err(|error| IpcError::new(error.error_type, error.message))?;

    Ok(PendingDatabaseRestoreObservation::Authenticated(
        PendingDatabaseRestoreGate {
            phase,
            marker,
            marker_file,
            incoming,
            active,
            rollback,
        },
    ))
}

fn legacy_restore_database_proofs_have_unified_lineage(
    incoming: &Option<PendingRestoreDatabaseProof>,
    active: &Option<PendingRestoreDatabaseProof>,
    rollback: &Option<PendingRestoreDatabaseProof>,
) -> bool {
    [incoming, active, rollback]
        .into_iter()
        .flatten()
        .any(|proof| proof.case_assistant_pending_output_rows != 0)
}

/// Applies only the exact path-free capability returned by the read-only
/// observer. The whole namespace is re-observed and compared byte-for-byte at
/// the proof layer immediately before the first filesystem mutation.
pub(crate) fn apply_observed_pending_database_restore(
    app_local_data_dir: &Path,
    gate: &PendingDatabaseRestoreGate,
) -> Result<(), IpcError> {
    match observe_pending_database_restore_read_only(app_local_data_dir)? {
        PendingDatabaseRestoreObservation::Authenticated(observed) if &observed == gate => {}
        PendingDatabaseRestoreObservation::Absent
        | PendingDatabaseRestoreObservation::Authenticated(_) => {
            return Err(restore_pending_error(
                "legacy-user restore evidence changed after process-start observation",
            ))
        }
    }

    let destination = database::user_database_path(app_local_data_dir);
    let paths = restore_paths(&destination)?;
    let expected_active = match gate.phase {
        PendingDatabaseRestorePhase::Prepared => {
            crate::atomic_file::install(
                &paths.incoming,
                &destination,
                Some(paths.rollback.as_path()),
            )
            .map_err(io_error)?;
            gate.incoming.as_ref()
        }
        PendingDatabaseRestorePhase::ActiveMovedToRollback => {
            crate::atomic_file::install(&paths.incoming, &destination, None).map_err(io_error)?;
            gate.incoming.as_ref()
        }
        PendingDatabaseRestorePhase::InstalledPendingCleanup => gate.active.as_ref(),
    }
    .ok_or_else(|| restore_pending_error("the authenticated replacement proof is absent"))?;

    let active = observe_current_restore_database(&destination, "installed active")?;
    if &active != expected_active || active.file.sha256 != gate.marker.incoming_sha256 {
        return Err(restore_pending_error(
            "the installed restore image does not match its authenticated gate",
        ));
    }

    let expected_rollback = match gate.phase {
        PendingDatabaseRestorePhase::Prepared => gate.active.as_ref(),
        PendingDatabaseRestorePhase::ActiveMovedToRollback
        | PendingDatabaseRestorePhase::InstalledPendingCleanup => gate.rollback.as_ref(),
    };
    if let Some(expected) = expected_rollback {
        let rollback = observe_current_restore_database(&paths.rollback, "rollback cleanup")?;
        if &rollback != expected {
            return Err(restore_pending_error(
                "the restore rollback slot changed before authenticated cleanup",
            ));
        }
    }
    let (marker, marker_file) = read_canonical_pending_restore_marker(&paths.marker)?;
    if marker != gate.marker || marker_file != gate.marker_file {
        return Err(restore_pending_error(
            "the pending restore marker changed before authenticated cleanup",
        ));
    }

    // Rollback is removed before the marker. A crash after this deletion is
    // the final authenticated crash state and is resumed without another swap.
    if gate.rollback.is_some() || gate.phase == PendingDatabaseRestorePhase::Prepared {
        fs::remove_file(&paths.rollback).map_err(io_error)?;
    }
    fs::remove_file(&paths.marker).map_err(io_error)?;
    Ok(())
}

fn restore_pending_error(message: impl Into<String>) -> IpcError {
    IpcError::new("restore_pending", message)
}

fn restore_slot_present(path: &Path) -> Result<bool, IpcError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(io_error(error)),
    }
}

fn reject_unknown_restore_namespace_entries(
    destination: &Path,
    paths: &RestorePaths,
) -> Result<(), IpcError> {
    let parent = destination
        .parent()
        .ok_or_else(|| IpcError::new("validation", "database path has no parent directory"))?;
    let database_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| IpcError::new("validation", "database path has an invalid filename"))?;
    let ordinary_prefix = format!("{database_name}.restore-");
    let temporary_prefix = format!(".{database_name}.restore-");
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(error)),
    };
    for entry in entries {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        if path == paths.incoming || path == paths.marker || path == paths.rollback {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let normalized_name = name.to_ascii_lowercase();
        if normalized_name.starts_with(&ordinary_prefix)
            || normalized_name.starts_with(&temporary_prefix)
        {
            return Err(restore_pending_error(
                "an unknown legacy-user restore sibling is present",
            ));
        }
    }
    Ok(())
}

fn read_canonical_pending_restore_marker(
    marker_path: &Path,
) -> Result<(PendingRestoreMarker, PendingRestoreFileProof), IpcError> {
    let before = observe_fixed_restore_file(marker_path, "pending restore marker")?;
    if before.length == 0 || before.length > MAX_PENDING_RESTORE_MARKER_BYTES {
        return Err(restore_pending_error(
            "the pending restore marker length is invalid",
        ));
    }
    let mut file = File::open(marker_path).map_err(io_error)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_PENDING_RESTORE_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    drop(file);
    let after = observe_fixed_restore_file(marker_path, "pending restore marker")?;
    if before != after
        || u64::try_from(bytes.len()).ok() != Some(before.length)
        || sha256_bytes(&bytes) != before.sha256
    {
        return Err(restore_pending_error(
            "the pending restore marker changed during read-only observation",
        ));
    }
    let marker: PendingRestoreMarker = serde_json::from_slice(&bytes)
        .map_err(|_| restore_pending_error("the pending restore marker is invalid"))?;
    if marker.format_version != PENDING_RESTORE_FORMAT_VERSION
        || !is_lowercase_sha256(&marker.incoming_sha256)
    {
        return Err(restore_pending_error(
            "the pending restore marker version or digest is invalid",
        ));
    }
    let canonical = serde_json::to_vec(&marker)
        .map_err(|_| restore_pending_error("the pending restore marker cannot be canonicalized"))?;
    if canonical != bytes {
        return Err(restore_pending_error(
            "the pending restore marker is not canonical and complete",
        ));
    }
    Ok((marker, before))
}

fn observe_current_restore_database(
    path: &Path,
    role: &str,
) -> Result<PendingRestoreDatabaseProof, IpcError> {
    let (proof, ()) =
        database::with_validated_user_database_migration_source_read_only(path, |_| ()).map_err(
            |_| {
                restore_pending_error(format!(
                    "the {role} legacy-user restore database is not an exact stable source"
                ))
            },
        )?;
    if proof.schema != database::ValidatedUserSourceSchema::CurrentV11
        || proof.wal.is_some()
        || proof.shm.is_some()
        || proof.journal.is_some()
    {
        return Err(restore_pending_error(format!(
            "the {role} legacy-user restore database is not sidecar-free exact current schema"
        )));
    }
    let case_assistant_pending_output_rows = proof
        .tables
        .iter()
        .find(|table| table.table == "case_assistant_pending_outputs")
        .map(|table| table.rows)
        .ok_or_else(|| {
            restore_pending_error(format!(
                "the {role} legacy-user restore database lacks current lineage evidence"
            ))
        })?;
    Ok(PendingRestoreDatabaseProof {
        file: PendingRestoreFileProof {
            identity_sha256: proof.database_file.identity_sha256,
            length: proof.database_file.length,
            modified_unix_nanos: proof.database_file.modified_unix_nanos,
            sha256: proof.database_file.sha256,
        },
        schema_manifest_sha256: proof.schema_manifest_sha256,
        logical_database_manifest_sha256: proof.logical_database_manifest_sha256,
        business_manifest_sha256: proof.business_manifest_sha256,
        case_assistant_pending_output_rows,
    })
}

fn observe_fixed_restore_file(
    path: &Path,
    role: &str,
) -> Result<PendingRestoreFileProof, IpcError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(restore_pending_error(format!(
            "the {role} is not an ordinary fixed file"
        )));
    }
    let information = windows_file_information(path).map_err(io_error)?;
    if information.nNumberOfLinks != 1
        || information.dwFileAttributes
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return Err(restore_pending_error(format!(
            "the {role} is linked or reparse-backed"
        )));
    }
    let mut identity = Sha256::new();
    identity.update(b"lawyer-assistance-legacy-user-restore-file-identity-v1\0");
    identity.update(information.dwVolumeSerialNumber.to_be_bytes());
    identity.update(information.nFileIndexHigh.to_be_bytes());
    identity.update(information.nFileIndexLow.to_be_bytes());
    let modified_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    Ok(PendingRestoreFileProof {
        identity_sha256: format!("{:x}", identity.finalize()),
        length: metadata.len(),
        modified_unix_nanos,
        sha256: file_sha256(path)?,
    })
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

struct RestorePaths {
    incoming: PathBuf,
    marker: PathBuf,
    rollback: PathBuf,
}

fn protected_application_paths<'a>(
    user_database: &'a Path,
    legal_core: &'a Path,
    crash_log: &'a Path,
    restore: &'a RestorePaths,
) -> [&'a Path; 6] {
    [
        user_database,
        legal_core,
        crash_log,
        &restore.incoming,
        &restore.marker,
        &restore.rollback,
    ]
}

fn restore_paths(destination: &Path) -> Result<RestorePaths, IpcError> {
    let parent = destination
        .parent()
        .ok_or_else(|| IpcError::new("validation", "database path has no parent directory"))?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| IpcError::new("validation", "database path has an invalid filename"))?;
    Ok(RestorePaths {
        incoming: parent.join(format!("{name}.restore-incoming")),
        marker: parent.join(format!("{name}.restore-pending.json")),
        rollback: parent.join(format!("{name}.restore-rollback")),
    })
}

fn unique_sibling(path: &Path, role: &str) -> Result<PathBuf, IpcError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| IpcError::new("validation", "path has an invalid filename"))?;
    Ok(parent.join(format!(".{name}.{role}-{}", uuid::Uuid::new_v4())))
}

#[cfg(test)]
fn write_pending_marker(marker_path: &Path, marker: &PendingRestoreMarker) -> Result<(), IpcError> {
    let incoming = unique_sibling(marker_path, "marker-incoming")?;
    let bytes = serde_json::to_vec(marker)?;
    let mut file = File::create(&incoming).map_err(io_error)?;
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    drop(file);
    crate::atomic_file::install(&incoming, marker_path, None).map_err(io_error)
}

fn file_sha256(path: &Path) -> Result<String, IpcError> {
    let mut file = File::open(path).map_err(io_error)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(crate) fn paths_refer_to_same_file(first: &Path, second: &Path) -> bool {
    if first == second {
        return true;
    }
    if let (Ok(first), Ok(second)) = (windows_file_identity(first), windows_file_identity(second)) {
        return first == second;
    }
    match (fs::canonicalize(first), fs::canonicalize(second)) {
        (Ok(first), Ok(second)) => first == second,
        _ => first == second,
    }
}

fn windows_file_identity(path: &Path) -> std::io::Result<(u32, u64)> {
    let information = windows_file_information(path)?;
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, file_index))
}

fn windows_file_information(path: &Path) -> std::io::Result<BY_HANDLE_FILE_INFORMATION> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let succeeded = unsafe { GetFileInformationByHandle(handle, &mut information) };
    unsafe {
        CloseHandle(handle);
    }
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(information)
}
fn io_error(error: std::io::Error) -> IpcError {
    IpcError::new("io", error.to_string())
}

pub fn sanitize_diagnostic_text(input: &str) -> String {
    let redacted = providers::redact_sensitive(input);
    redacted
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.contains("request body")
                && !lower.contains("response body")
                && !lower.contains("case material")
                && !lower.contains("案件原文")
        })
        .take(200)
        .map(|line| {
            let clipped = line.chars().take(500).collect::<String>();
            format!("{clipped}\n")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[derive(Debug, PartialEq, Eq)]
    struct RestoreTreeEntrySnapshot {
        name: Vec<u16>,
        is_file: bool,
        is_directory: bool,
        is_symlink: bool,
        length: u64,
        modified: Option<std::time::SystemTime>,
        bytes: Option<Vec<u8>>,
    }

    fn restore_tree_snapshot(root: &Path) -> Vec<RestoreTreeEntrySnapshot> {
        let mut entries = fs::read_dir(root)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let metadata = fs::symlink_metadata(entry.path()).unwrap();
                RestoreTreeEntrySnapshot {
                    name: entry.file_name().encode_wide().collect(),
                    is_file: metadata.is_file(),
                    is_directory: metadata.is_dir(),
                    is_symlink: metadata.file_type().is_symlink(),
                    length: metadata.len(),
                    modified: metadata.modified().ok(),
                    bytes: metadata.is_file().then(|| fs::read(entry.path()).unwrap()),
                }
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        entries
    }

    fn observe_without_mutation(
        app_root: &Path,
    ) -> Result<PendingDatabaseRestoreObservation, IpcError> {
        let before = restore_tree_snapshot(app_root);
        let result = observe_pending_database_restore_read_only(app_root);
        assert_eq!(restore_tree_snapshot(app_root), before);
        result
    }

    fn stage_current_restore(
        app_root: &Path,
    ) -> (PathBuf, RestorePaths, PendingDatabaseRestoreGate) {
        let active = database::ensure_user_database(app_root).unwrap();
        let backup = app_root.join("legacy-user-backup.sqlite");
        backup_database(&active, &backup, &[&active]).unwrap();
        stage_database_restore(&backup, &active).unwrap();
        let paths = restore_paths(&active).unwrap();
        let PendingDatabaseRestoreObservation::Authenticated(gate) =
            observe_without_mutation(app_root).unwrap()
        else {
            panic!("staged restore must authenticate");
        };
        (active, paths, gate)
    }

    fn observe_and_apply_pending_database_restore(app_root: &Path) -> Result<(), IpcError> {
        match observe_pending_database_restore_read_only(app_root)? {
            PendingDatabaseRestoreObservation::Absent => Ok(()),
            PendingDatabaseRestoreObservation::Authenticated(gate) => {
                apply_observed_pending_database_restore(app_root, &gate)
            }
        }
    }

    #[test]
    fn plaintext_user_database_backup_is_disabled() {
        let error = require_protected_database_backup().unwrap_err();
        assert_eq!(error.error_type, "privacy_required");
        assert!(error
            .message
            .contains("Plaintext user database backup is disabled"));
        assert!(!error.message.contains("sqlite"));
    }
    use super::*;
    #[test]
    fn diagnostics_remove_secrets_bodies_and_case_text() {
        let raw =
            "Authorization: Bearer sk-secret\nrequest body: {private}\n案件原文：隐私\nsafe event";
        let clean = sanitize_diagnostic_text(raw);
        assert!(!clean.contains("sk-secret"));
        assert!(!clean.contains("private"));
        assert!(!clean.contains("隐私"));
        assert!(clean.contains("safe event"));
    }
    #[test]
    fn cancel_is_explicit_and_side_effect_free() {
        let result = cancelled();
        assert!(result.cancelled);
        assert!(!result.completed);
    }

    #[test]
    fn diagnostic_export_cannot_overwrite_or_hardlink_to_protected_state() {
        let directory = tempfile::tempdir().unwrap();
        let active = directory.path().join("user.sqlite");
        fs::write(&active, b"database-bytes").unwrap();

        let direct_error = write_diagnostic_report(&active, "report", &[&active]).unwrap_err();
        assert_eq!(direct_error.error_type, "validation");
        assert_eq!(fs::read(&active).unwrap(), b"database-bytes");

        let hardlink = directory.path().join("diagnostic.txt");
        fs::hard_link(&active, &hardlink).unwrap();
        let hardlink_error = write_diagnostic_report(&hardlink, "report", &[&active]).unwrap_err();
        assert_eq!(hardlink_error.error_type, "validation");
        assert_eq!(fs::read(&active).unwrap(), b"database-bytes");
    }

    #[test]
    fn diagnostic_export_atomically_replaces_an_ordinary_report() {
        let directory = tempfile::tempdir().unwrap();
        let protected = directory.path().join("user.sqlite");
        fs::write(&protected, b"database").unwrap();
        let report = directory.path().join("diagnostic.txt");
        fs::write(&report, b"old report").unwrap();

        write_diagnostic_report(&report, "new report", &[&protected]).unwrap();

        assert_eq!(fs::read_to_string(report).unwrap(), "new report");
        assert_eq!(fs::read(protected).unwrap(), b"database");
    }

    #[test]
    fn diagnostic_export_protects_every_application_state_path() {
        let directory = tempfile::tempdir().unwrap();
        let active = directory.path().join("user.sqlite");
        let legal = directory.path().join("legal_core.sqlite");
        let crash = directory.path().join("crash-events.log");
        let restore = restore_paths(&active).unwrap();
        let protected = protected_application_paths(&active, &legal, &crash, &restore);

        for (index, path) in protected.iter().enumerate() {
            let original = format!("protected-{index}").into_bytes();
            fs::write(path, &original).unwrap();
            let error = write_diagnostic_report(path, "report", &protected).unwrap_err();
            assert_eq!(error.error_type, "validation");
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }

    #[test]
    fn backup_cannot_replace_legal_crash_or_pending_restore_files() {
        let directory = tempfile::tempdir().unwrap();
        let active = database::ensure_user_database(directory.path()).unwrap();
        let legal = directory.path().join("legal_core.sqlite");
        let crash = directory.path().join("crash-events.log");
        fs::write(&legal, b"formal-law-bytes").unwrap();
        fs::write(&crash, b"crash-log-bytes").unwrap();
        let restore = restore_paths(&active).unwrap();
        fs::write(&restore.marker, b"restore-marker").unwrap();
        let protected = [
            active.as_path(),
            legal.as_path(),
            crash.as_path(),
            restore.incoming.as_path(),
            restore.marker.as_path(),
            restore.rollback.as_path(),
        ];

        for destination in [&legal, &crash, &restore.marker] {
            let before = fs::read(destination).unwrap();
            let error = backup_database(&active, destination, &protected).unwrap_err();
            assert_eq!(error.error_type, "validation");
            assert_eq!(fs::read(destination).unwrap(), before);
        }
    }

    #[test]
    fn backup_and_restore_roundtrip_v9_assistant_workspace() {
        let directory = tempfile::tempdir().expect("temp directory");
        let active = database::ensure_user_database(directory.path()).expect("user database");
        {
            let connection = database::open_user_database(&active).expect("active opens");
            database::upsert_case_project(
                &connection,
                &database::CaseProjectRow {
                    project_id: "project-backup".into(),
                    title: "备份时标题".into(),
                    case_type: "civil".into(),
                    status: "active".into(),
                    opened_on: None,
                    summary: String::new(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )
            .expect("project inserts");
            database::create_conversation(
                &connection,
                "conversation-backup",
                Some("project-backup"),
                "备份中的助理会话",
            )
            .expect("conversation inserts");
            database::create_message(
                &connection,
                &database::NewMessageRow {
                    message_id: "message-backup-user".into(),
                    conversation_id: "conversation-backup".into(),
                    role: "user".into(),
                    kind: "text".into(),
                    text_summary: "请梳理材料".into(),
                    artifact_id: None,
                    run_id: None,
                },
            )
            .expect("user message inserts");
            database::insert_attachment(
                &connection,
                &database::NewAttachmentRow {
                    attachment_id: "attachment:backup".into(),
                    project_id: Some("project-backup".into()),
                    original_name: "backup.txt".into(),
                    extension: "txt".into(),
                    detected_mime: "text/plain".into(),
                    sha256: "b".repeat(64),
                    size_bytes: 6,
                    content_blob: b"backup".to_vec(),
                    extraction_status: "succeeded".into(),
                    extracted_text: Some("backup".into()),
                    segments_json: "[]".into(),
                    error_code: None,
                },
            )
            .expect("attachment inserts");
            database::attach_to_message(&connection, "message-backup-user", "attachment:backup", 0)
                .expect("attachment links");
            database::add_conversation_source(
                &connection,
                "conversation-backup",
                "legal-source-backup",
            )
            .expect("source links");
            database::create_agent_run(
                &connection,
                &database::NewAgentRunRow {
                    run_id: "run-backup".into(),
                    conversation_id: "conversation-backup".into(),
                    user_message_id: "message-backup-user".into(),
                    provider_id: None,
                    provider_snapshot_json: "{}".into(),
                    intent: "case_analysis".into(),
                    status: "queued".into(),
                    budget_json: r#"{"maxToolCalls":8}"#.into(),
                },
            )
            .expect("run inserts");
            database::create_tool_call(
                &connection,
                &database::NewToolCallRow {
                    tool_call_id: "tool-backup".into(),
                    run_id: "run-backup".into(),
                    ordinal: 0,
                    capability_name: "case.read".into(),
                    status: "queued".into(),
                    access_mode: "read".into(),
                    requires_confirmation: false,
                    input_audit_json: r#"{"projectId":"project-backup"}"#.into(),
                    output_audit_json: "{}".into(),
                    source_audit_json: "[]".into(),
                },
            )
            .expect("tool call inserts");
            database::create_artifact(
                &connection,
                &database::NewArtifactRow {
                    artifact_id: "artifact-backup".into(),
                    conversation_id: Some("conversation-backup".into()),
                    project_id: Some("project-backup".into()),
                    kind: "research".into(),
                    title: "备份研究产物".into(),
                    status: "draft".into(),
                },
                &database::NewArtifactVersionRow {
                    version_id: "artifact-backup-v1".into(),
                    artifact_id: "artifact-backup".into(),
                    content_json: r#"{"schemaVersion":1}"#.into(),
                    rendered_text: "备份研究产物正文".into(),
                    source_refs_json: r#"["attachment:backup"]"#.into(),
                    citation_report_json: "{}".into(),
                    provider_snapshot_json: "{}".into(),
                },
            )
            .expect("artifact inserts");
            database::create_case_change_proposal(
                &connection,
                &database::NewCaseChangeProposalRow {
                    proposal_id: "proposal-backup".into(),
                    conversation_id: "conversation-backup".into(),
                    project_id: "project-backup".into(),
                    run_id: Some("run-backup".into()),
                    base_case_digest: "c".repeat(64),
                    changes_json: r#"{"facts":[]}"#.into(),
                    source_refs_json: r#"["attachment:backup"]"#.into(),
                },
            )
            .expect("proposal inserts");
        }
        let backup = directory.path().join("backup.sqlite");
        backup_database(&active, &backup, &[&active]).expect("backup succeeds");
        {
            let connection = database::open_user_database(&active).expect("active reopens");
            let mut project = database::list_case_projects(&connection)
                .expect("projects list")
                .remove(0);
            project.title = "修改后标题".into();
            database::upsert_case_project(&connection, &project).expect("project changes");
            database::archive_conversation(&connection, "conversation-backup")
                .expect("conversation archives");
            database::compare_and_set_case_change_proposal_status(
                &connection,
                "proposal-backup",
                "project-backup",
                &"c".repeat(64),
                "rejected",
            )
            .expect("proposal rejects before restore");
        }
        stage_database_restore(&backup, &active).expect("restore stages");
        {
            let connection = database::open_user_database(&active).expect("old database remains");
            assert_eq!(
                database::list_case_projects(&connection).unwrap()[0].title,
                "修改后标题",
                "online restore never swaps the active database"
            );
        }
        observe_and_apply_pending_database_restore(directory.path())
            .expect("startup applies restore");
        let connection = database::open_user_database(&active).expect("restored opens");
        assert_eq!(
            database::list_case_projects(&connection).unwrap()[0].title,
            "备份时标题"
        );
        assert_eq!(
            database::get_conversation(&connection, "conversation-backup")
                .unwrap()
                .unwrap()
                .status,
            "open"
        );
        assert_eq!(
            database::list_messages(&connection, "conversation-backup")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database::list_message_attachments(&connection, "message-backup-user")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database::list_conversation_sources(&connection, "conversation-backup").unwrap()[0]
                .source_id,
            "legal-source-backup"
        );
        assert!(database::get_agent_run(&connection, "run-backup")
            .unwrap()
            .is_some());
        assert!(database::get_tool_call(&connection, "tool-backup")
            .unwrap()
            .is_some());
        assert!(database::get_attachment(&connection, "attachment:backup")
            .unwrap()
            .is_some());
        assert_eq!(
            database::list_artifact_versions(&connection, "artifact-backup")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database::get_case_change_proposal(&connection, "proposal-backup")
                .unwrap()
                .unwrap()
                .status,
            "pending"
        );
        database::validate_user_database_read_only(&active)
            .expect("restored v9 assistant workspace remains canonical");
    }

    #[test]
    fn invalid_restore_leaves_active_database_unchanged() {
        let directory = tempfile::tempdir().expect("temp directory");
        let active = database::ensure_user_database(directory.path()).expect("user database");
        let before = fs::read(&active).expect("active bytes");
        let invalid = directory.path().join("invalid.sqlite");
        fs::write(&invalid, b"not sqlite").expect("invalid candidate");
        assert!(stage_database_restore(&invalid, &active).is_err());
        assert_eq!(fs::read(active).expect("active remains"), before);
        let paths = restore_paths(&database::user_database_path(directory.path())).unwrap();
        assert!(!paths.marker.exists());
        assert!(!paths.incoming.exists());
    }

    #[test]
    fn fabricated_current_schema_is_rejected_before_a_restore_is_marked_pending() {
        let directory = tempfile::tempdir().unwrap();
        let active = database::ensure_user_database(directory.path()).unwrap();
        let candidate = directory.path().join("fabricated.sqlite");
        let connection = Connection::open(&candidate).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE user_database_metadata (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
                 );
                 INSERT INTO user_database_metadata VALUES
                    ('schema_version', '8', CURRENT_TIMESTAMP),
                    ('canonical_schema_version', 'v8-fact-issue-links-20260716', CURRENT_TIMESTAMP);",
            )
            .unwrap();
        drop(connection);

        assert!(stage_database_restore(&candidate, &active).is_err());
        let paths = restore_paths(&active).unwrap();
        assert!(!paths.marker.exists());
        assert!(!paths.incoming.exists());
    }

    #[test]
    fn startup_finishes_a_restore_interrupted_after_the_atomic_swap() {
        let directory = tempfile::tempdir().unwrap();
        let active = database::ensure_user_database(directory.path()).unwrap();
        let backup = directory.path().join("backup.sqlite");
        backup_database(&active, &backup, &[&active]).unwrap();
        stage_database_restore(&backup, &active).unwrap();
        let paths = restore_paths(&active).unwrap();
        crate::atomic_file::install(&paths.incoming, &active, Some(&paths.rollback)).unwrap();
        assert!(paths.marker.exists());
        assert!(paths.rollback.exists());

        observe_and_apply_pending_database_restore(directory.path()).unwrap();

        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
        database::validate_and_migrate_user_database(&active).unwrap();
    }

    #[test]
    fn legacy_restore_observer_authenticates_every_frozen_crash_state_without_writes() {
        for phase in [
            PendingDatabaseRestorePhase::Prepared,
            PendingDatabaseRestorePhase::ActiveMovedToRollback,
            PendingDatabaseRestorePhase::InstalledPendingCleanup,
        ] {
            let directory = tempfile::tempdir().unwrap();
            let (active, paths, _) = stage_current_restore(directory.path());
            match phase {
                PendingDatabaseRestorePhase::Prepared => {}
                PendingDatabaseRestorePhase::ActiveMovedToRollback => {
                    fs::rename(&active, &paths.rollback).unwrap();
                }
                PendingDatabaseRestorePhase::InstalledPendingCleanup => {
                    crate::atomic_file::install(&paths.incoming, &active, Some(&paths.rollback))
                        .unwrap();
                }
            }

            let PendingDatabaseRestoreObservation::Authenticated(gate) =
                observe_without_mutation(directory.path()).unwrap()
            else {
                panic!("crash state must authenticate");
            };
            assert_eq!(gate.phase(), phase);
            apply_observed_pending_database_restore(directory.path(), &gate).unwrap();
            assert!(!paths.marker.exists());
            assert!(!paths.incoming.exists());
            assert!(!paths.rollback.exists());
            database::validate_user_database_read_only(&active).unwrap();
        }

        let directory = tempfile::tempdir().unwrap();
        let (active, paths, _) = stage_current_restore(directory.path());
        crate::atomic_file::install(&paths.incoming, &active, Some(&paths.rollback)).unwrap();
        fs::remove_file(&paths.rollback).unwrap();
        let PendingDatabaseRestoreObservation::Authenticated(gate) =
            observe_without_mutation(directory.path()).unwrap()
        else {
            panic!("post-rollback-cleanup crash state must authenticate");
        };
        assert_eq!(
            gate.phase(),
            PendingDatabaseRestorePhase::InstalledPendingCleanup
        );
        apply_observed_pending_database_restore(directory.path(), &gate).unwrap();
        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
        database::validate_user_database_read_only(&active).unwrap();
    }

    #[test]
    fn legacy_restore_observer_rejects_noncanonical_and_tampered_markers_without_writes() {
        let directory = tempfile::tempdir().unwrap();
        let (_, paths, _) = stage_current_restore(directory.path());
        let mut bytes = fs::read(&paths.marker).unwrap();
        bytes.push(b'\n');
        fs::write(&paths.marker, bytes).unwrap();
        let error = observe_without_mutation(directory.path())
            .expect_err("noncanonical marker must fail closed");
        assert_eq!(error.error_type, "restore_pending");

        let directory = tempfile::tempdir().unwrap();
        let (_, paths, _) = stage_current_restore(directory.path());
        let mut marker: PendingRestoreMarker =
            serde_json::from_slice(&fs::read(&paths.marker).unwrap()).unwrap();
        marker.incoming_sha256 = "A".repeat(64);
        fs::write(&paths.marker, serde_json::to_vec(&marker).unwrap()).unwrap();
        let error = observe_without_mutation(directory.path())
            .expect_err("non-lowercase digest must fail closed");
        assert_eq!(error.error_type, "restore_pending");
    }

    #[test]
    fn legacy_restore_apply_reobserves_marker_and_incoming_proofs_before_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let (active, paths, gate) = stage_current_restore(directory.path());
        let alternate_root = tempfile::tempdir().unwrap();
        let alternate = database::ensure_user_database(alternate_root.path()).unwrap();
        {
            let connection = database::open_user_database(&alternate).unwrap();
            database::upsert_case_project(
                &connection,
                &database::CaseProjectRow {
                    project_id: "gate-drift-project".to_owned(),
                    title: "Gate drift".to_owned(),
                    case_type: "civil".to_owned(),
                    status: "active".to_owned(),
                    opened_on: None,
                    summary: String::new(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )
            .unwrap();
        }
        fs::copy(&alternate, &paths.incoming).unwrap();
        let mut marker: PendingRestoreMarker =
            serde_json::from_slice(&fs::read(&paths.marker).unwrap()).unwrap();
        marker.incoming_sha256 = file_sha256(&paths.incoming).unwrap();
        fs::write(&paths.marker, serde_json::to_vec(&marker).unwrap()).unwrap();

        let before_apply = restore_tree_snapshot(directory.path());
        let error = apply_observed_pending_database_restore(directory.path(), &gate)
            .expect_err("a stale opaque gate must not authorize mutation");
        assert_eq!(error.error_type, "restore_pending");
        assert_eq!(restore_tree_snapshot(directory.path()), before_apply);
        assert!(active.exists());
        assert!(paths.incoming.exists());
        assert!(!paths.rollback.exists());
    }

    #[test]
    fn legacy_restore_observer_rejects_unmarked_and_mixed_residue_without_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let (_, paths, _) = stage_current_restore(directory.path());
        fs::remove_file(&paths.marker).unwrap();
        let error = observe_without_mutation(directory.path())
            .expect_err("unmarked incoming residue must fail closed");
        assert_eq!(error.error_type, "restore_pending");
        assert!(paths.incoming.exists());

        let directory = tempfile::tempdir().unwrap();
        let (active, paths, _) = stage_current_restore(directory.path());
        fs::copy(&active, &paths.rollback).unwrap();
        let error = observe_without_mutation(directory.path())
            .expect_err("active + incoming + rollback is not an atomic crash state");
        assert_eq!(error.error_type, "restore_pending");
        assert!(paths.marker.exists());
        assert!(paths.incoming.exists());
        assert!(paths.rollback.exists());

        let directory = tempfile::tempdir().unwrap();
        let (active, paths, _) = stage_current_restore(directory.path());
        fs::remove_file(&active).unwrap();
        fs::remove_file(&paths.incoming).unwrap();
        let error = observe_without_mutation(directory.path())
            .expect_err("marker-only partial state must fail closed");
        assert_eq!(error.error_type, "restore_pending");
        assert!(paths.marker.exists());
    }

    #[test]
    fn legacy_restore_observer_rejects_unknown_restore_siblings_without_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let (_, _, _) = stage_current_restore(directory.path());
        let unknown = directory.path().join("user.sqlite.restore-surprise");
        fs::write(&unknown, b"unknown").unwrap();
        let error = observe_without_mutation(directory.path())
            .expect_err("unknown restore namespace sibling must fail closed");
        assert_eq!(error.error_type, "restore_pending");
        assert_eq!(fs::read(unknown).unwrap(), b"unknown");
    }

    #[test]
    fn legacy_restore_observer_rejects_hardlinked_marker_and_incoming_slots() {
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let (_, paths, _) = stage_current_restore(directory.path());
        let marker_alias = outside.path().join("marker-alias");
        fs::hard_link(&paths.marker, &marker_alias).unwrap();
        let error = observe_without_mutation(directory.path())
            .expect_err("a hardlinked marker must fail closed");
        assert_eq!(error.error_type, "restore_pending");
        assert_eq!(
            fs::read(&marker_alias).unwrap(),
            fs::read(&paths.marker).unwrap()
        );

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let (_, paths, _) = stage_current_restore(directory.path());
        let incoming_alias = outside.path().join("incoming-alias");
        fs::hard_link(&paths.incoming, &incoming_alias).unwrap();
        let error = observe_without_mutation(directory.path())
            .expect_err("a hardlinked incoming database must fail closed");
        assert_eq!(error.error_type, "restore_pending");
        assert_eq!(
            fs::read(&incoming_alias).unwrap(),
            fs::read(&paths.incoming).unwrap()
        );
    }

    #[test]
    fn every_legacy_restore_database_slot_participates_in_unified_lineage_policy() {
        let directory = tempfile::tempdir().unwrap();
        let (_, _, gate) = stage_current_restore(directory.path());
        let clean = gate.active.clone().unwrap();
        for slot in 0..3 {
            let mut incoming = None;
            let mut active = None;
            let mut rollback = None;
            let mut unified = clean.clone();
            unified.case_assistant_pending_output_rows = 1;
            match slot {
                0 => incoming = Some(unified),
                1 => active = Some(unified),
                2 => rollback = Some(unified),
                _ => unreachable!(),
            }
            assert!(legacy_restore_database_proofs_have_unified_lineage(
                &incoming, &active, &rollback
            ));
        }
        assert!(!legacy_restore_database_proofs_have_unified_lineage(
            &None,
            &Some(clean),
            &None,
        ));
    }

    #[test]
    fn legacy_pending_user_restore_refuses_unified_lineage_before_swap() {
        let directory = tempfile::tempdir().unwrap();
        let active = database::ensure_user_database(directory.path()).unwrap();
        let backup = directory.path().join("backup.sqlite");
        backup_database(&active, &backup, &[&active]).unwrap();
        {
            let connection = database::open_user_database(&active).unwrap();
            database::upsert_case_project(
                &connection,
                &database::CaseProjectRow {
                    project_id: "current-project".to_owned(),
                    title: "Current project must survive".to_owned(),
                    case_type: "civil".to_owned(),
                    status: "active".to_owned(),
                    opened_on: None,
                    summary: String::new(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )
            .unwrap();
        }
        stage_database_restore(&backup, &active).unwrap();
        let privacy_directory = directory.path().join("privacy");
        fs::create_dir_all(&privacy_directory).unwrap();
        let privacy_database = privacy_directory.join("privacy-workflow.sqlite");
        Connection::open(&privacy_database)
            .unwrap()
            .execute_batch(
                "CREATE TABLE case_material_selections(selection_id TEXT PRIMARY KEY);
                 INSERT INTO case_material_selections VALUES('selection-current');",
            )
            .unwrap();
        let paths = restore_paths(&active).unwrap();

        let error = observe_without_mutation(directory.path())
            .expect_err("single-database restore must fail closed for unified lineage");
        assert_eq!(
            error.error_type,
            "application_restore_requires_five_components"
        );
        let connection = database::open_user_database(&active).unwrap();
        assert_eq!(
            database::list_case_projects(&connection).unwrap()[0].project_id,
            "current-project"
        );
        assert!(paths.marker.exists());
        assert!(paths.incoming.exists());
        assert!(!paths.rollback.exists());
    }
}
