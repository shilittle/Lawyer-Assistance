use crate::{commands::case::IpcError, state::AppState};
use rusqlite::{backup::Backup, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
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
pub struct BackupRequest {
    pub destination_path: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreRequest {
    pub source_path: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingRestoreMarker {
    format_version: u8,
    incoming_sha256: String,
}

const PENDING_RESTORE_FORMAT_VERSION: u8 = 1;
const MAX_DATABASE_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

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
#[tauri::command]
pub fn backup_user_database(
    state: State<'_, AppState>,
    request: BackupRequest,
) -> Result<FileOperationResponse, IpcError> {
    let Some(path) = request.destination_path.filter(|p| !p.trim().is_empty()) else {
        return Ok(cancelled());
    };
    let restore = restore_paths(state.user_database_path())?;
    let protected = protected_application_paths(
        state.user_database_path(),
        state.legal_core_path(),
        state.crash_log_path(),
        &restore,
    );
    backup_database(state.user_database_path(), Path::new(&path), &protected)?;
    Ok(FileOperationResponse {
        completed: true,
        cancelled: false,
        path: Some(path),
        restart_required: false,
    })
}
#[tauri::command]
pub fn restore_user_database(
    state: State<'_, AppState>,
    request: RestoreRequest,
) -> Result<FileOperationResponse, IpcError> {
    let Some(path) = request.source_path.filter(|p| !p.trim().is_empty()) else {
        return Ok(cancelled());
    };
    stage_database_restore(Path::new(&path), state.user_database_path())?;
    Ok(FileOperationResponse {
        completed: true,
        cancelled: false,
        path: Some(path),
        restart_required: true,
    })
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

/// Applies a fully validated restore before any application database
/// connection is created. The marker/backup protocol is restart-safe across
/// every individual filesystem step.
pub fn apply_pending_database_restore(app_local_data_dir: &Path) -> Result<(), IpcError> {
    let destination = database::user_database_path(app_local_data_dir);
    let paths = restore_paths(&destination)?;

    if !paths.marker.exists() {
        if paths.incoming.exists() {
            fs::remove_file(&paths.incoming).map_err(io_error)?;
        }
        recover_or_remove_stale_rollback(&destination, &paths.rollback)?;
        return Ok(());
    }

    let marker: PendingRestoreMarker =
        serde_json::from_slice(&fs::read(&paths.marker).map_err(io_error)?)
            .map_err(|_| IpcError::new("restore_pending", "pending restore marker is invalid"))?;
    if marker.format_version != PENDING_RESTORE_FORMAT_VERSION || marker.incoming_sha256.len() != 64
    {
        return Err(IpcError::new(
            "restore_pending",
            "pending restore marker version or digest is invalid",
        ));
    }

    if paths.incoming.exists() {
        if file_sha256(&paths.incoming)? != marker.incoming_sha256 {
            return Err(IpcError::new(
                "restore_pending",
                "pending restore copy digest does not match its marker",
            ));
        }
        database::validate_user_database_read_only(&paths.incoming)?;
        recover_or_remove_stale_rollback(&destination, &paths.rollback)?;
        crate::atomic_file::install(
            &paths.incoming,
            &destination,
            destination.exists().then_some(paths.rollback.as_path()),
        )
        .map_err(io_error)?;
    } else if !destination.exists() || file_sha256(&destination)? != marker.incoming_sha256 {
        rollback_pending_restore(&destination, &paths)?;
        return Err(IpcError::new(
            "restore_pending",
            "interrupted restore did not leave the validated replacement in place",
        ));
    }

    if let Err(error) = database::validate_user_database_read_only(&destination) {
        rollback_pending_restore(&destination, &paths)?;
        return Err(IpcError::new(
            "restore_pending",
            format!("restored database failed final validation: {error}"),
        ));
    }
    fs::remove_file(&paths.marker).map_err(io_error)?;
    if paths.rollback.exists() {
        let _ = fs::remove_file(&paths.rollback);
    }
    Ok(())
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

fn paths_refer_to_same_file(first: &Path, second: &Path) -> bool {
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
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((information.dwVolumeSerialNumber, file_index))
}

fn recover_or_remove_stale_rollback(destination: &Path, rollback: &Path) -> Result<(), IpcError> {
    if !rollback.exists() {
        return Ok(());
    }
    if destination.exists() && database::validate_user_database_read_only(destination).is_ok() {
        fs::remove_file(rollback).map_err(io_error)?;
    } else if !destination.exists() {
        fs::rename(rollback, destination).map_err(io_error)?;
    } else {
        restore_previous_database(destination, rollback)?;
    }
    Ok(())
}

fn rollback_pending_restore(destination: &Path, paths: &RestorePaths) -> Result<(), IpcError> {
    if paths.rollback.exists() {
        restore_previous_database(destination, &paths.rollback)?;
    }
    let _ = fs::remove_file(&paths.incoming);
    let _ = fs::remove_file(&paths.marker);
    Ok(())
}

fn restore_previous_database(destination: &Path, rollback: &Path) -> Result<(), IpcError> {
    if destination.exists() {
        let failed = unique_sibling(destination, "restore-failed")?;
        crate::atomic_file::install(rollback, destination, Some(&failed)).map_err(io_error)?;
        let _ = fs::remove_file(failed);
    } else {
        fs::rename(rollback, destination).map_err(io_error)?;
    }
    database::validate_user_database_read_only(destination)?;
    Ok(())
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
    fn backup_and_restore_roundtrip_user_projects() {
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
        apply_pending_database_restore(directory.path()).expect("startup applies restore");
        let connection = database::open_user_database(&active).expect("restored opens");
        assert_eq!(
            database::list_case_projects(&connection).unwrap()[0].title,
            "备份时标题"
        );
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

        apply_pending_database_restore(directory.path()).unwrap();

        assert!(!paths.marker.exists());
        assert!(!paths.rollback.exists());
        database::validate_and_migrate_user_database(&active).unwrap();
    }
}
