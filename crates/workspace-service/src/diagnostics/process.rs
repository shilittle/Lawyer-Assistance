//! Minimal, local-only process evidence for the daemon and its isolated workers.
//!
//! This module deliberately has no store, workspace, provider, document or URL
//! dependency.  Its JSONL schema contains only fixed event names, safe identifiers
//! and process facts, so it can remain useful when the normal service is failing.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};

const PROCESS_DIAGNOSTICS_DIRECTORY_ENV: &str = "LAWYER_ASSISTANCE_PROCESS_DIAGNOSTICS_DIR";
const PROCESS_DIAGNOSTICS_LAUNCH_ENV: &str = "LAWYER_ASSISTANCE_PROCESS_LAUNCH_ID";
const PROCESS_DIAGNOSTICS_PARENT_LAUNCH_ENV: &str = "LAWYER_ASSISTANCE_PROCESS_PARENT_LAUNCH_ID";
const PROCESS_DIAGNOSTICS_REVISION_ENV: &str = "LAWYER_ASSISTANCE_PROCESS_REVISION";
const MAX_PROCESS_LOG_BYTES: u64 = 256 * 1024;
const MAX_PROCESS_LOG_FILES: u8 = 3;
const MAX_PROCESS_LAUNCH_LOG_FILES: usize = 32;
const MAX_PANIC_EMERGENCY_BYTES: u64 = 64 * 1024;
const MAX_PANIC_EMERGENCY_LOG_FILES: usize = 16;
const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_TAG_BYTES: usize = 64;
const MAX_RAW_STACK_FRAMES: usize = 24;

tokio::task_local! {
    static CURRENT_OPERATION_ID: String;
}

static CURRENT_PROCESS_DIAGNOSTICS: OnceLock<RwLock<Option<ProcessDiagnostics>>> = OnceLock::new();
static ACTIVE_LAUNCH_IDS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// The only roles emitted by the local process log.  The same executable can
/// appear as both daemon and document worker, so role is an explicit field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRole {
    Daemon,
    DocumentWorker,
    Diagnostics,
    #[cfg(feature = "document-worker-fault-injection")]
    DiagnosticFault,
}

/// Why a parent intentionally began stopping a child.  This is recorded before
/// `start_kill`, so the later exit code cannot be mistaken for the original
/// failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationIntent {
    Cancelled,
    Timeout,
    ParentCleanup,
    JobCleanup,
    Shutdown,
}

/// Distinguishes a naturally observed exit from an exit observed only after the
/// parent began cleanup.  Neither variant attributes the exit to Pdfium or OOM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitSource {
    Natural,
    AfterCleanup,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessIdentity {
    pub build_revision: String,
    pub exe_module_name: Option<String>,
    pub exe_sha256: Option<String>,
    pub exe_hash_status: &'static str,
    /// CodeView GUID+age read from the exact executable's debug directory.
    /// It is absent in stripped ordinary release builds and is never replaced
    /// with a PDB from another executable.
    pub pdb_identity: Option<String>,
    pub pdb_identity_status: &'static str,
    pub launch_id: String,
    pub parent_launch_id: Option<String>,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub role: ProcessRole,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProcessDiagnosticsStatus {
    pub ready: bool,
    pub status: &'static str,
    pub last_error_code: Option<String>,
    pub current_phase: String,
    pub dropped_events: u64,
    pub identity: ProcessIdentity,
}

/// A child-safe environment bundle.  It has no workspace or material value;
/// the child uses it only to append process facts into its parent's diagnostic
/// directory and to retain launch correlation.
#[derive(Clone, Debug)]
pub struct ProcessChildEnvironment {
    directory: PathBuf,
    launch_id: String,
    parent_launch_id: String,
    revision: String,
}

impl ProcessChildEnvironment {
    pub fn launch_id(&self) -> &str {
        &self.launch_id
    }

    pub fn apply_to_tokio_command(&self, command: &mut tokio::process::Command) {
        command
            .env(PROCESS_DIAGNOSTICS_DIRECTORY_ENV, &self.directory)
            .env(PROCESS_DIAGNOSTICS_LAUNCH_ENV, &self.launch_id)
            .env(
                PROCESS_DIAGNOSTICS_PARENT_LAUNCH_ENV,
                &self.parent_launch_id,
            )
            .env(PROCESS_DIAGNOSTICS_REVISION_ENV, &self.revision);
    }
}

#[derive(Clone)]
pub struct ProcessDiagnostics {
    inner: Arc<ProcessDiagnosticsInner>,
}

struct ProcessDiagnosticsInner {
    directory: Option<PathBuf>,
    active_lease: Mutex<Option<ActiveLaunchLease>>,
    panic_slot: Option<PathBuf>,
    panic_reserved_bytes: AtomicU64,
    launch_log_name: String,
    identity: ProcessIdentity,
    state: Mutex<ProcessDiagnosticsState>,
    /// This lock protects only the small local JSONL rotation/write sequence.
    /// Panic recording always uses `try_lock`, and never takes a workspace lock.
    write_guard: Mutex<()>,
    limits: ProcessLogLimits,
}

#[derive(Clone, Copy)]
struct ProcessLogLimits {
    max_bytes: u64,
    max_files: u8,
}

struct ProcessDiagnosticsState {
    ready: bool,
    last_error_code: Option<String>,
    current_phase: String,
    dropped_events: u64,
}

#[derive(Serialize)]
struct ActiveLaunchMarker {
    launch_id: String,
    pid: u32,
    created_unix_ms: u64,
}

struct ActiveLaunchLease {
    marker_path: PathBuf,
    _marker_file: std::fs::File,
}

#[derive(Serialize)]
struct ProcessDiagnosticEvent<'a> {
    schema_version: u8,
    timestamp_unix_ms: u64,
    event: &'static str,
    build_revision: &'a str,
    exe_sha256: Option<&'a str>,
    exe_hash_status: &'static str,
    exe_module_name: Option<&'a str>,
    pdb_identity: Option<&'a str>,
    pdb_identity_status: &'static str,
    launch_id: &'a str,
    parent_launch_id: Option<&'a str>,
    pid: u32,
    parent_pid: Option<u32>,
    role: ProcessRole,
    phase: Option<&'a str>,
    operation_id: Option<&'a str>,
    result: Option<&'a str>,
    error_code: Option<&'a str>,
    child_pid: Option<u32>,
    child_launch_id: Option<&'a str>,
    termination_intent: Option<TerminationIntent>,
    native_exit_code: Option<u32>,
    exit_code_hex: Option<String>,
    exit_source: Option<ExitSource>,
    child_reaped: Option<bool>,
    stderr_discarded_bytes: Option<u64>,
    stderr_read_errors: Option<u64>,
    memory: Option<MemorySnapshot>,
    memory_scope: Option<&'static str>,
    panic: Option<PanicLocation>,
}

#[derive(Clone, Copy, Serialize)]
struct MemorySnapshot {
    working_set_bytes: u64,
    private_commit_bytes: u64,
}

#[derive(Serialize)]
struct PanicLocation {
    source_module: String,
    line: u32,
    column: u32,
    raw_stack: Vec<RawStackFrame>,
}

#[derive(Serialize)]
struct RawStackFrame {
    address_hex: String,
    module_name: Option<String>,
    module_binding: Option<&'static str>,
    module_base_hex: Option<String>,
    module_offset_hex: Option<String>,
}

impl ProcessDiagnostics {
    /// Initializes daemon-local logging at `<workspace>/diagnostics/process`.
    /// Initialization failure is retained in status and never changes service
    /// behavior into a false success.
    pub fn initialize(root: &Path, role: ProcessRole, build_revision: &str) -> Self {
        let directory = root.join("diagnostics").join("process");
        let ready = prepare_directory(&directory).is_ok();
        Self::new(
            ready.then_some(directory),
            role,
            build_revision,
            None,
            ProcessLogLimits {
                max_bytes: MAX_PROCESS_LOG_BYTES,
                max_files: MAX_PROCESS_LOG_FILES,
            },
            !ready,
        )
    }

    /// Uses only the parent-supplied, absolute diagnostics directory.  A
    /// manually invoked hidden worker with no valid parent environment stays
    /// observable through stderr but cannot write an arbitrary path.
    pub fn from_child_environment(role: ProcessRole, fallback_revision: &str) -> Self {
        let directory = std::env::var_os(PROCESS_DIAGNOSTICS_DIRECTORY_ENV)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            // The daemon created this directory before spawning the child.  A
            // manually invoked hidden command must not create a diagnostic
            // tree chosen from an untrusted environment variable.
            .filter(|path| path.is_dir() && crate::filesystem::ordinary_chain(path).is_ok());
        let launch_id = std::env::var(PROCESS_DIAGNOSTICS_LAUNCH_ENV)
            .ok()
            .filter(|value| safe_operation_id(value))
            .unwrap_or_else(|| new_launch_id(role));
        let parent_launch_id = std::env::var(PROCESS_DIAGNOSTICS_PARENT_LAUNCH_ENV)
            .ok()
            .filter(|value| safe_operation_id(value));
        let revision = std::env::var(PROCESS_DIAGNOSTICS_REVISION_ENV)
            .ok()
            .filter(|value| safe_tag(value))
            .unwrap_or_else(|| safe_value_or_unknown(fallback_revision));
        let failed = directory.is_none();
        Self::new_with_identity(
            directory,
            role,
            revision,
            launch_id,
            parent_launch_id,
            ProcessLogLimits {
                max_bytes: MAX_PROCESS_LOG_BYTES,
                max_files: MAX_PROCESS_LOG_FILES,
            },
            failed,
        )
    }

    pub fn disabled(role: ProcessRole, build_revision: &str) -> Self {
        Self::new(
            None,
            role,
            build_revision,
            None,
            ProcessLogLimits {
                max_bytes: MAX_PROCESS_LOG_BYTES,
                max_files: MAX_PROCESS_LOG_FILES,
            },
            true,
        )
    }

    fn new(
        directory: Option<PathBuf>,
        role: ProcessRole,
        build_revision: &str,
        parent_launch_id: Option<String>,
        limits: ProcessLogLimits,
        failed: bool,
    ) -> Self {
        Self::new_with_identity(
            directory,
            role,
            safe_value_or_unknown(build_revision),
            new_launch_id(role),
            parent_launch_id,
            limits,
            failed,
        )
    }

    fn new_with_identity(
        directory: Option<PathBuf>,
        role: ProcessRole,
        build_revision: String,
        launch_id: String,
        parent_launch_id: Option<String>,
        limits: ProcessLogLimits,
        failed: bool,
    ) -> Self {
        let executable = std::env::current_exe().ok();
        let exe_sha256 = executable.as_deref().and_then(executable_sha256);
        let exe_module_name = executable
            .as_deref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .map(safe_source_module);
        let pdb_identity = executable.as_deref().and_then(pdb_identity_from_executable);
        let identity = ProcessIdentity {
            build_revision,
            exe_module_name,
            exe_hash_status: if exe_sha256.is_some() {
                "available"
            } else {
                "unavailable"
            },
            exe_sha256,
            pdb_identity_status: if pdb_identity.is_some() {
                "available"
            } else {
                "unavailable"
            },
            pdb_identity,
            launch_id,
            parent_launch_id,
            pid: std::process::id(),
            parent_pid: current_parent_pid(),
            role,
        };
        // A marker is created before the first record.  Global pruning only
        // deletes a launch after its validated marker says that PID has exited;
        // a full budget of live ledgers therefore degrades a new writer instead
        // of silently splitting a live process history.
        let requested_directory = directory;
        let launch_lease = requested_directory
            .as_deref()
            .and_then(|directory| create_launch_lease(directory, &identity).ok());
        let marker_failed = requested_directory.is_some() && launch_lease.is_none();
        let panic_slot = launch_lease.as_ref().map(|lease| lease.panic_slot.clone());
        if launch_lease.is_some() {
            register_active_launch(&identity.launch_id);
        }
        let directory = if marker_failed {
            None
        } else {
            requested_directory
        };
        let this = Self {
            inner: Arc::new(ProcessDiagnosticsInner {
                directory,
                active_lease: Mutex::new(launch_lease.map(|lease| ActiveLaunchLease {
                    marker_path: lease.marker_path,
                    _marker_file: lease.marker_file,
                })),
                panic_slot,
                panic_reserved_bytes: AtomicU64::new(0),
                launch_log_name: format!("process-{}.jsonl", identity.launch_id),
                identity,
                state: Mutex::new(ProcessDiagnosticsState {
                    ready: !(failed || marker_failed),
                    last_error_code: (failed || marker_failed)
                        .then(|| "diagnostic_write_failed".to_owned()),
                    current_phase: "starting".to_owned(),
                    dropped_events: 0,
                }),
                write_guard: Mutex::new(()),
                limits,
            }),
        };
        this.record_started();
        this
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.inner.identity.clone()
    }

    pub fn status(&self) -> ProcessDiagnosticsStatus {
        let state = self.inner.state.lock().ok();
        let (ready, last_error_code, current_phase, dropped_events) = match state {
            Some(state) => (
                state.ready,
                state.last_error_code.clone(),
                state.current_phase.clone(),
                state.dropped_events,
            ),
            None => (
                false,
                Some("diagnostic_state_unavailable".to_owned()),
                "unknown".to_owned(),
                0,
            ),
        };
        ProcessDiagnosticsStatus {
            ready,
            status: if ready { "ready" } else { "degraded" },
            last_error_code,
            current_phase,
            dropped_events,
            identity: self.identity(),
        }
    }

    pub fn child_environment(&self) -> Option<ProcessChildEnvironment> {
        self.inner
            .directory
            .as_ref()
            .map(|directory| ProcessChildEnvironment {
                directory: directory.clone(),
                launch_id: new_launch_id(ProcessRole::DocumentWorker),
                parent_launch_id: self.inner.identity.launch_id.clone(),
                revision: self.inner.identity.build_revision.clone(),
            })
    }

    pub fn record_started(&self) {
        self.record(
            "started",
            Some("starting"),
            None,
            None,
            None,
            EventDetails::default(),
        );
    }

    pub fn record_phase(&self, phase: &str) {
        let phase = safe_tag(phase).then_some(phase);
        if let Some(phase) = phase {
            if let Ok(mut state) = self.inner.state.lock() {
                state.current_phase = phase.to_owned();
            }
            self.record(
                "phase",
                Some(phase),
                None,
                None,
                None,
                EventDetails::default(),
            );
        }
    }

    pub fn record_operation_started(&self, operation_id: &str, phase: &str) {
        self.record(
            "operation_started",
            safe_tag(phase).then_some(phase),
            safe_operation_id(operation_id).then_some(operation_id),
            None,
            None,
            EventDetails::default(),
        );
    }

    pub fn record_operation_finished(&self, operation_id: &str, phase: &str) {
        self.record(
            "operation_finished",
            safe_tag(phase).then_some(phase),
            safe_operation_id(operation_id).then_some(operation_id),
            Some("completed"),
            None,
            EventDetails::default(),
        );
    }

    pub fn record_operation_failed(&self, operation_id: &str, phase: &str, error_code: &str) {
        self.record(
            "operation_failed",
            safe_tag(phase).then_some(phase),
            safe_operation_id(operation_id).then_some(operation_id),
            Some("failed"),
            safe_tag(error_code).then_some(error_code),
            EventDetails::default(),
        );
    }

    pub fn record_start_failure(&self, error_code: &str) {
        self.record(
            "startup_failed",
            Some("startup_failed"),
            current_operation_id().as_deref(),
            Some("failed"),
            safe_tag(error_code).then_some(error_code),
            EventDetails::default(),
        );
        self.retire_active_marker();
    }

    pub fn record_unexpected_stop(&self, error_code: &str) {
        self.record(
            "unexpected_stop",
            Some("stopped"),
            current_operation_id().as_deref(),
            Some("failed"),
            safe_tag(error_code).then_some(error_code),
            EventDetails::default(),
        );
        self.retire_active_marker();
    }

    pub fn record_normal_stop(&self) {
        self.record(
            "normal_stop",
            Some("stopped"),
            current_operation_id().as_deref(),
            Some("completed"),
            None,
            EventDetails::default(),
        );
        self.retire_active_marker();
    }

    pub fn record_child_started(
        &self,
        pid: u32,
        operation_id: &str,
        phase: &str,
        child_launch_id: &str,
    ) {
        self.record(
            "child_started",
            safe_tag(phase).then_some(phase),
            safe_operation_id(operation_id).then_some(operation_id),
            None,
            None,
            EventDetails {
                child_pid: Some(pid),
                child_launch_id: safe_operation_id(child_launch_id)
                    .then(|| child_launch_id.to_owned()),
                ..EventDetails::default()
            },
        );
    }

    pub fn record_termination_intent(
        &self,
        pid: u32,
        operation_id: &str,
        phase: &str,
        intent: TerminationIntent,
    ) {
        self.record(
            "termination_intent",
            safe_tag(phase).then_some(phase),
            safe_operation_id(operation_id).then_some(operation_id),
            None,
            None,
            EventDetails {
                child_pid: Some(pid),
                termination_intent: Some(intent),
                ..EventDetails::default()
            },
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_child_exit(
        &self,
        pid: u32,
        operation_id: &str,
        phase: &str,
        status: Option<&ExitStatus>,
        source: ExitSource,
        stderr_discarded_bytes: u64,
        stderr_read_errors: u64,
        reaped: bool,
    ) {
        let native_exit_code = status.and_then(exit_code_u32);
        self.record(
            "child_exit",
            safe_tag(phase).then_some(phase),
            safe_operation_id(operation_id).then_some(operation_id),
            Some(if status.is_some_and(ExitStatus::success) {
                "completed"
            } else {
                "failed"
            }),
            None,
            EventDetails {
                child_pid: Some(pid),
                native_exit_code,
                exit_source: Some(source),
                child_reaped: Some(reaped),
                stderr_discarded_bytes: Some(stderr_discarded_bytes),
                stderr_read_errors: Some(stderr_read_errors),
                ..EventDetails::default()
            },
        );
    }

    /// Persists only a source basename, line/column and raw addresses.  The
    /// panic payload is intentionally not accepted by this API.
    pub fn record_panic_location(&self, source_module: &str, line: u32, column: u32) {
        // Keep the entire panic-side path inside this boundary: even platform
        // stack capture or a diagnostic allocation failure must not replace
        // the original application panic.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let location = PanicLocation {
                source_module: safe_source_module(source_module),
                line,
                column,
                raw_stack: capture_raw_stack(self.inner.identity.exe_module_name.as_deref()),
            };
            self.record_nonblocking(
                "panic",
                Some("panicked"),
                current_operation_id().as_deref(),
                Some("failed"),
                Some("task_panicked"),
                EventDetails {
                    panic: Some(location),
                    ..EventDetails::default()
                },
            );
        }));
    }

    fn record(
        &self,
        event: &'static str,
        phase: Option<&str>,
        operation_id: Option<&str>,
        result: Option<&'static str>,
        error_code: Option<&str>,
        details: EventDetails,
    ) {
        self.record_impl(
            event,
            phase,
            operation_id,
            result,
            error_code,
            details,
            false,
        );
    }

    fn record_nonblocking(
        &self,
        event: &'static str,
        phase: Option<&str>,
        operation_id: Option<&str>,
        result: Option<&'static str>,
        error_code: Option<&str>,
        details: EventDetails,
    ) {
        // A panic hook must not panic or wait for a file/diagnostic lock.  The
        // tiny catch boundary also protects the original panic from diagnostic
        // serialization or filesystem failures.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.record_impl(
                event,
                phase,
                operation_id,
                result,
                error_code,
                details,
                true,
            );
        }));
    }

    #[allow(clippy::too_many_arguments)]
    fn record_impl(
        &self,
        event: &'static str,
        phase: Option<&str>,
        operation_id: Option<&str>,
        result: Option<&'static str>,
        error_code: Option<&str>,
        details: EventDetails,
        nonblocking: bool,
    ) {
        let memory = memory_snapshot();
        let event = ProcessDiagnosticEvent {
            schema_version: 1,
            timestamp_unix_ms: unix_millis(),
            event,
            build_revision: &self.inner.identity.build_revision,
            exe_sha256: self.inner.identity.exe_sha256.as_deref(),
            exe_hash_status: self.inner.identity.exe_hash_status,
            exe_module_name: self.inner.identity.exe_module_name.as_deref(),
            pdb_identity: self.inner.identity.pdb_identity.as_deref(),
            pdb_identity_status: self.inner.identity.pdb_identity_status,
            launch_id: &self.inner.identity.launch_id,
            parent_launch_id: self.inner.identity.parent_launch_id.as_deref(),
            pid: self.inner.identity.pid,
            parent_pid: self.inner.identity.parent_pid,
            role: self.inner.identity.role,
            phase,
            operation_id,
            result,
            error_code,
            child_pid: details.child_pid,
            child_launch_id: details.child_launch_id.as_deref(),
            termination_intent: details.termination_intent,
            native_exit_code: details.native_exit_code,
            exit_code_hex: details.native_exit_code.map(|code| format!("0x{code:08X}")),
            exit_source: details.exit_source,
            child_reaped: details.child_reaped,
            stderr_discarded_bytes: details.stderr_discarded_bytes,
            stderr_read_errors: details.stderr_read_errors,
            memory_scope: memory.as_ref().map(|_| "self_process"),
            memory,
            panic: details.panic,
        };
        // A panic never enters the normal JSONL path: after the process-local
        // try-lock succeeds, that path could still wait on the cross-process
        // directory budget lock. Its pre-reserved emergency slot is the sole
        // panic writer and does no directory scan, rotation or lease lookup.
        let written = if nonblocking && event.event == "panic" {
            self.write_panic_emergency(&event)
        } else {
            self.write_event(&event, nonblocking)
        };
        self.note_write_result(written, nonblocking);
    }

    fn write_event(&self, event: &ProcessDiagnosticEvent<'_>, nonblocking: bool) -> bool {
        let Ok(mut line) = serde_json::to_vec(event) else {
            return false;
        };
        line.push(b'\n');
        let Some(directory) = self.inner.directory.as_deref() else {
            return false;
        };
        let guard = if nonblocking {
            match self.inner.write_guard.try_lock() {
                Ok(guard) => guard,
                Err(_) => return false,
            }
        } else {
            match self.inner.write_guard.lock() {
                Ok(guard) => guard,
                Err(_) => return false,
            }
        };
        let result = write_rotated_jsonl(
            directory,
            &self.inner.launch_log_name,
            &line,
            self.inner.limits,
        );
        drop(guard);
        result.is_ok()
    }

    /// A panic must remain observable even if another normal diagnostic record
    /// currently owns the rotation lock.  The emergency file belongs solely to
    /// this random launch id, has its own hard size limit, and never contains a
    /// panic payload or source path.
    fn write_panic_emergency(&self, event: &ProcessDiagnosticEvent<'_>) -> bool {
        let Some(path) = self.inner.panic_slot.as_deref() else {
            return false;
        };
        let Ok(mut line) = serde_json::to_vec(event) else {
            return false;
        };
        line.push(b'\n');
        if !self.reserve_panic_bytes(line.len() as u64) {
            return false;
        }
        let written = OpenOptions::new()
            .append(true)
            .open(path)
            .and_then(|mut file| {
                file.write_all(&line)?;
                file.sync_data()
            })
            .is_ok();
        // The panic path never scans or prunes other launches: checking live
        // PIDs or metadata here could wait while the original process is
        // already unwinding. Normal initialization/writes reclaim stale files.
        written
    }

    fn reserve_panic_bytes(&self, incoming: u64) -> bool {
        let mut current = self.inner.panic_reserved_bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(incoming) else {
                return false;
            };
            if next > MAX_PANIC_EMERGENCY_BYTES {
                return false;
            }
            match self.inner.panic_reserved_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn note_write_result(&self, written: bool, nonblocking: bool) {
        let update = |state: &mut ProcessDiagnosticsState| {
            if written {
                state.ready = true;
                state.last_error_code = None;
            } else {
                state.ready = false;
                state.last_error_code = Some("diagnostic_write_failed".to_owned());
                state.dropped_events = state.dropped_events.saturating_add(1);
            }
        };
        if nonblocking {
            if let Ok(mut state) = self.inner.state.try_lock() {
                update(&mut state);
            }
        } else if let Ok(mut state) = self.inner.state.lock() {
            update(&mut state);
        }
    }

    fn retire_active_marker(&self) {
        let lease = self
            .inner
            .active_lease
            .lock()
            .ok()
            .and_then(|mut lease| lease.take());
        if let Some(lease) = lease {
            let marker = lease.marker_path.clone();
            drop(lease);
            if crate::filesystem::ordinary_chain(&marker).is_ok() {
                let _ = fs::remove_file(marker);
            }
            unregister_active_launch(&self.inner.identity.launch_id);
            if let Some(panic_slot) = self.inner.panic_slot.as_deref() {
                if panic_slot.metadata().map(|metadata| metadata.len()).ok() == Some(0)
                    && crate::filesystem::ordinary_chain(panic_slot).is_ok()
                {
                    let _ = fs::remove_file(panic_slot);
                }
            }
        }
    }
}

#[derive(Default)]
struct EventDetails {
    child_pid: Option<u32>,
    child_launch_id: Option<String>,
    termination_intent: Option<TerminationIntent>,
    native_exit_code: Option<u32>,
    exit_source: Option<ExitSource>,
    child_reaped: Option<bool>,
    stderr_discarded_bytes: Option<u64>,
    stderr_read_errors: Option<u64>,
    panic: Option<PanicLocation>,
}

/// Installs the process recorder read by the global panic hook.  Replacing a
/// prior recorder is intentional for tests and short-lived hidden workers.
pub fn install_process_diagnostics(diagnostics: ProcessDiagnostics) {
    if let Ok(mut slot) = CURRENT_PROCESS_DIAGNOSTICS
        .get_or_init(|| RwLock::new(None))
        .write()
    {
        *slot = Some(diagnostics);
    }
}

pub fn current_process_diagnostics() -> Option<ProcessDiagnostics> {
    CURRENT_PROCESS_DIAGNOSTICS
        .get()
        .and_then(|slot| slot.try_read().ok().and_then(|value| value.clone()))
}

/// Runs a future with an operation identifier visible only to this Tokio task.
/// It does not use a process-global mutable "current operation", so concurrent
/// A/B requests cannot overwrite one another's diagnostics.
pub async fn with_operation_id<T>(
    operation_id: String,
    future: impl std::future::Future<Output = T>,
) -> T {
    CURRENT_OPERATION_ID.scope(operation_id, future).await
}

pub fn current_operation_id() -> Option<String> {
    CURRENT_OPERATION_ID.try_with(Clone::clone).ok()
}

pub fn new_operation_id(prefix: &str) -> String {
    let prefix = if safe_tag(prefix) {
        prefix
    } else {
        "operation"
    };
    format!("{prefix}_{}", uuid::Uuid::new_v4().simple())
}

fn new_launch_id(role: ProcessRole) -> String {
    let role = match role {
        ProcessRole::Daemon => "daemon",
        ProcessRole::DocumentWorker => "document_worker",
        ProcessRole::Diagnostics => "diagnostics",
        #[cfg(feature = "document-worker-fault-injection")]
        ProcessRole::DiagnosticFault => "diagnostic_fault",
    };
    new_operation_id(&format!("launch_{role}"))
}

fn safe_value_or_unknown(value: &str) -> String {
    if safe_tag(value) {
        value.to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn safe_tag(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TAG_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn safe_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_OPERATION_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn safe_source_module(value: &str) -> String {
    let file = value.rsplit(['/', '\\']).next().unwrap_or("unknown");
    if safe_tag(file) {
        file.to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn executable_sha256(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = std::io::Read::read(&mut file, &mut buffer).ok()?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

/// Extracts only the RSDS CodeView GUID and age from the executable's PE debug
/// directory.  The embedded PDB path is deliberately ignored, so no local
/// filesystem path reaches diagnostics.  This lets a diagnostic-build frame be
/// checked against its matching PDB without pretending that a PDB from a prior
/// executable is exact.
fn pdb_identity_from_executable(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let pe_offset = read_u32(&bytes, 0x3c)? as usize;
    if bytes.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
        return None;
    }
    let file_header = pe_offset.checked_add(4)?;
    let section_count = read_u16(&bytes, file_header + 2)? as usize;
    let optional_size = read_u16(&bytes, file_header + 16)? as usize;
    let optional = file_header.checked_add(20)?;
    let magic = read_u16(&bytes, optional)?;
    let data_directory = match magic {
        0x20b => optional.checked_add(112)?,
        0x10b => optional.checked_add(96)?,
        _ => return None,
    };
    // Debug directory is IMAGE_DIRECTORY_ENTRY_DEBUG (index 6).
    let debug_rva = read_u32(&bytes, data_directory.checked_add(6 * 8)?)?;
    let debug_size = read_u32(&bytes, data_directory.checked_add(6 * 8 + 4)?)? as usize;
    if debug_rva == 0 || debug_size < 28 {
        return None;
    }
    let sections = optional.checked_add(optional_size)?;
    let debug_offset = rva_to_file_offset(&bytes, sections, section_count, debug_rva)?;
    let entries = debug_size / 28;
    for index in 0..entries {
        let entry = debug_offset.checked_add(index.checked_mul(28)?)?;
        // IMAGE_DEBUG_TYPE_CODEVIEW = 2; PointerToRawData is more direct than
        // the RVA and remains valid for the file we hash above.
        if read_u32(&bytes, entry + 12)? != 2 {
            continue;
        }
        let size = read_u32(&bytes, entry + 16)? as usize;
        let data_offset = read_u32(&bytes, entry + 24)? as usize;
        let data = bytes.get(data_offset..data_offset.checked_add(size)?)?;
        if data.len() < 24 || &data[..4] != b"RSDS" {
            continue;
        }
        let guid = data[4..20]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let age = u32::from_le_bytes(data[20..24].try_into().ok()?);
        return Some(format!("rsds-{guid}-{age}"));
    }
    None
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn rva_to_file_offset(
    bytes: &[u8],
    sections_offset: usize,
    section_count: usize,
    rva: u32,
) -> Option<usize> {
    for index in 0..section_count {
        let section = sections_offset.checked_add(index.checked_mul(40)?)?;
        let virtual_size = read_u32(bytes, section + 8)?;
        let virtual_address = read_u32(bytes, section + 12)?;
        let raw_size = read_u32(bytes, section + 16)?;
        let raw_offset = read_u32(bytes, section + 20)?;
        let span = virtual_size.max(raw_size);
        let end = virtual_address.checked_add(span)?;
        if rva >= virtual_address && rva < end {
            return usize::try_from(raw_offset.checked_add(rva - virtual_address)?).ok();
        }
    }
    // Debug information can reside in the headers, before the first section.
    usize::try_from(rva)
        .ok()
        .filter(|offset| *offset < bytes.len())
}

fn prepare_directory(directory: &Path) -> std::io::Result<()> {
    if !directory.is_absolute() {
        return Err(std::io::Error::other(
            "diagnostic directory is not absolute",
        ));
    }
    fs::create_dir_all(directory)?;
    crate::filesystem::ordinary_chain(directory)
        .map_err(|_| std::io::Error::other("diagnostic directory rejected"))
}

struct CreatedLaunchLease {
    marker_path: PathBuf,
    marker_file: std::fs::File,
    panic_slot: PathBuf,
}

fn create_launch_lease(
    directory: &Path,
    identity: &ProcessIdentity,
) -> std::io::Result<CreatedLaunchLease> {
    with_directory_budget_lock(directory, || {
        if !prune_stale_all(directory)?
            || !prune_logs(
                directory,
                MAX_PANIC_EMERGENCY_LOG_FILES.saturating_sub(1),
                is_panic_log_name,
            )?
        {
            return Err(std::io::Error::other("diagnostic panic budget exhausted"));
        }
        create_active_marker(directory, identity)
    })
}

fn create_active_marker(
    directory: &Path,
    identity: &ProcessIdentity,
) -> std::io::Result<CreatedLaunchLease> {
    crate::filesystem::ordinary_chain(directory)
        .map_err(|_| std::io::Error::other("diagnostic directory rejected"))?;
    let path = directory.join(format!("active-{}.json", identity.launch_id));
    let panic_slot = directory.join(format!("panic-{}.jsonl", identity.launch_id));
    let marker = ActiveLaunchMarker {
        launch_id: identity.launch_id.clone(),
        pid: identity.pid,
        created_unix_ms: unix_millis(),
    };
    let bytes = serde_json::to_vec(&marker)
        .map_err(|_| std::io::Error::other("diagnostic marker serialization failed"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_data()?;
    file.lock()?;
    if let Err(error) = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&panic_slot)
        .and_then(|file| file.sync_data())
    {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    crate::filesystem::ordinary_chain(&path)
        .map_err(|_| std::io::Error::other("diagnostic marker rejected"))?;
    Ok(CreatedLaunchLease {
        marker_path: path,
        marker_file: file,
        panic_slot,
    })
}

fn with_directory_budget_lock<T>(
    directory: &Path,
    action: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let path = directory.join("process-budget.lock");
    if path.exists() {
        crate::filesystem::ordinary_chain(&path)
            .map_err(|_| std::io::Error::other("diagnostic budget lock rejected"))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    file.lock()?;
    action()
}

fn write_rotated_jsonl(
    directory: &Path,
    launch_log_name: &str,
    line: &[u8],
    limits: ProcessLogLimits,
) -> std::io::Result<()> {
    with_directory_budget_lock(directory, || {
        write_rotated_jsonl_locked(directory, launch_log_name, line, limits)
    })
}

fn write_rotated_jsonl_locked(
    directory: &Path,
    launch_log_name: &str,
    line: &[u8],
    limits: ProcessLogLimits,
) -> std::io::Result<()> {
    crate::filesystem::ordinary_chain(directory)
        .map_err(|_| std::io::Error::other("diagnostic directory rejected"))?;
    // Every daemon/worker gets its own random launch file.  Parent and worker
    // processes therefore never rename or truncate one another's active log.
    let active = directory.join(launch_log_name);
    if active.exists() {
        crate::filesystem::ordinary_chain(&active)
            .map_err(|_| std::io::Error::other("diagnostic log rejected"))?;
    }
    let size = active
        .metadata()
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let rotates = size.saturating_add(line.len() as u64) > limits.max_bytes;
    let creates_new_launch_file = !active.exists()
        || (rotates && !rotated_log_path(&active, limits.max_files.saturating_sub(1)).exists());
    // Reclaim only verified-dead launches before adding a new ledger segment.
    // If every retained record is still live, reject this write rather than
    // unlinking an active history.
    if !prune_stale_all(directory)?
        || (creates_new_launch_file
            && !prune_logs(
                directory,
                MAX_PROCESS_LAUNCH_LOG_FILES.saturating_sub(1),
                is_launch_log_name,
            )?)
    {
        return Err(std::io::Error::other("diagnostic log budget exhausted"));
    }
    if rotates {
        rotate_logs(&active, limits.max_files)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(&active)?;
    file.write_all(line)?;
    // This log is deliberately low-volume.  Durability is worth the small
    // synchronous write cost because it records process state after a crash.
    file.sync_data()?;
    Ok(())
}

fn rotate_logs(active: &Path, max_files: u8) -> std::io::Result<()> {
    if max_files < 2 {
        return Ok(());
    }
    let oldest = rotated_log_path(active, max_files - 1);
    if oldest.exists() {
        crate::filesystem::ordinary_chain(&oldest)
            .map_err(|_| std::io::Error::other("diagnostic log rejected"))?;
        fs::remove_file(&oldest)?;
    }
    for index in (1..max_files).rev() {
        let source = rotated_log_path(active, index - 1);
        if !source.exists() {
            continue;
        }
        crate::filesystem::ordinary_chain(&source)
            .map_err(|_| std::io::Error::other("diagnostic log rejected"))?;
        let destination = rotated_log_path(active, index);
        if destination.exists() {
            crate::filesystem::ordinary_chain(&destination)
                .map_err(|_| std::io::Error::other("diagnostic log rejected"))?;
        }
        fs::rename(source, destination)?;
    }
    Ok(())
}

fn rotated_log_path(active: &Path, index: u8) -> PathBuf {
    if index == 0 {
        return active.to_path_buf();
    }
    let stem = active
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("process-invalid");
    active.with_file_name(format!("{stem}.{index}.jsonl"))
}

fn prune_logs(
    directory: &Path,
    limit: usize,
    name_matches: fn(&str) -> bool,
) -> std::io::Result<bool> {
    let mut logs = fs::read_dir(directory)?
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            if !name_matches(name) || !entry.file_type().ok()?.is_file() {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok();
            Some((entry.path(), modified))
        })
        .collect::<Vec<_>>();
    logs.sort_by_key(|(_, modified)| *modified);
    let mut retained = logs.len();
    for (path, _) in logs {
        if retained <= limit {
            break;
        }
        if log_is_active(&path) {
            continue;
        }
        if crate::filesystem::ordinary_chain(&path).is_ok() && fs::remove_file(path).is_ok() {
            retained = retained.saturating_sub(1);
        }
    }
    Ok(retained <= limit)
}

fn prune_stale_all(directory: &Path) -> std::io::Result<bool> {
    Ok(
        prune_logs(directory, MAX_PROCESS_LAUNCH_LOG_FILES, is_launch_log_name)?
            && prune_logs(directory, MAX_PANIC_EMERGENCY_LOG_FILES, is_panic_log_name)?,
    )
}

fn is_launch_log_name(name: &str) -> bool {
    name.starts_with("process-launch_")
        && name.ends_with(".jsonl")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn is_panic_log_name(name: &str) -> bool {
    name.starts_with("panic-launch_")
        && name.ends_with(".jsonl")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn log_is_active(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    let Some(launch_id) = launch_id_from_log_name(name) else {
        return true;
    };
    if active_launch_is_registered(launch_id) {
        return true;
    }
    let Some(directory) = path.parent() else {
        return true;
    };
    let marker = directory.join(format!("active-{launch_id}.json"));
    if !marker.exists() {
        return false;
    }
    if crate::filesystem::ordinary_chain(&marker).is_err() {
        return true;
    }
    let Ok(lease_probe) = OpenOptions::new().read(true).write(true).open(&marker) else {
        return true;
    };
    // A process owns this advisory lock for the full launch.  Crash/exit
    // releases it atomically, unlike PID checks which are vulnerable to reuse.
    if lease_probe.try_lock().is_err() {
        return true;
    }
    drop(lease_probe);
    let _ = fs::remove_file(marker);
    false
}

fn launch_id_from_log_name(name: &str) -> Option<&str> {
    let stem = if let Some(stem) = name.strip_prefix("process-") {
        stem.strip_suffix(".jsonl")?
    } else {
        name.strip_prefix("panic-")?.strip_suffix(".jsonl")?
    };
    let launch_id = stem.split('.').next()?;
    safe_operation_id(launch_id).then_some(launch_id)
}

fn register_active_launch(launch_id: &str) {
    if let Ok(mut active) = ACTIVE_LAUNCH_IDS
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
    {
        active.insert(launch_id.to_owned());
    }
}

fn unregister_active_launch(launch_id: &str) {
    if let Some(active) = ACTIVE_LAUNCH_IDS.get() {
        if let Ok(mut active) = active.lock() {
            active.remove(launch_id);
        }
    }
}

fn active_launch_is_registered(launch_id: &str) -> bool {
    ACTIVE_LAUNCH_IDS
        .get()
        .and_then(|active| active.lock().ok().map(|active| active.contains(launch_id)))
        .unwrap_or(false)
}

fn exit_code_u32(status: &ExitStatus) -> Option<u32> {
    status.code().map(|code| code as u32)
}

#[cfg(windows)]
fn current_parent_pid() -> Option<u32> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
    };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return None;
    }
    let current = std::process::id();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut found = None;
    let mut has_entry = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while has_entry {
        if entry.th32ProcessID == current {
            found = Some(entry.th32ParentProcessID);
            break;
        }
        has_entry = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe {
        CloseHandle(snapshot);
    }
    found
}

#[cfg(not(windows))]
fn current_parent_pid() -> Option<u32> {
    None
}

#[cfg(windows)]
fn memory_snapshot() -> Option<MemorySnapshot> {
    use windows_sys::Win32::System::{
        ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
        },
        Threading::GetCurrentProcess,
    };
    let mut counters = PROCESS_MEMORY_COUNTERS_EX {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    let ok = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
            counters.cb,
        )
    } != 0;
    ok.then_some(MemorySnapshot {
        working_set_bytes: counters.WorkingSetSize as u64,
        private_commit_bytes: counters.PrivateUsage as u64,
    })
}

#[cfg(not(windows))]
fn memory_snapshot() -> Option<MemorySnapshot> {
    None
}

#[cfg(windows)]
fn capture_raw_stack(main_module_name: Option<&str>) -> Vec<RawStackFrame> {
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::HMODULE,
        System::{
            Diagnostics::Debug::RtlCaptureStackBackTrace,
            LibraryLoader::{
                GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            },
        },
    };
    let mut addresses = [std::ptr::null_mut::<c_void>(); MAX_RAW_STACK_FRAMES];
    let captured = unsafe {
        RtlCaptureStackBackTrace(
            1,
            MAX_RAW_STACK_FRAMES as u32,
            addresses.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    } as usize;
    addresses[..captured]
        .iter()
        .map(|address| {
            let raw = *address as usize;
            let mut module: HMODULE = std::ptr::null_mut();
            let found = unsafe {
                GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                        | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    *address as *const u16,
                    &mut module,
                )
            } != 0;
            let base = found.then_some(module as usize);
            let module_name = found.then(|| loaded_module_basename(module)).flatten();
            RawStackFrame {
                address_hex: format!("0x{raw:016X}"),
                // Only the main executable carries the exact CodeView identity
                // persisted with this launch. DLL frames retain a basename/RVA
                // for later collection, but are explicitly unbound until a
                // matching resource manifest supplies their version/hash.
                module_binding: match module_name.as_deref().zip(main_module_name) {
                    Some((actual, main)) if actual.eq_ignore_ascii_case(main) => {
                        Some("main_executable")
                    }
                    Some(_) => Some("unbound_module"),
                    None => Some("unresolved_module"),
                },
                module_name,
                module_base_hex: base.map(|value| format!("0x{value:016X}")),
                module_offset_hex: base
                    .and_then(|value| raw.checked_sub(value))
                    .map(|value| format!("0x{value:X}")),
            }
        })
        .collect()
}

#[cfg(windows)]
fn loaded_module_basename(module: windows_sys::Win32::Foundation::HMODULE) -> Option<String> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;
    let mut buffer = [0u16; 32_768];
    let length =
        unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    Some(safe_source_module(
        &std::ffi::OsString::from_wide(&buffer[..length]).to_string_lossy(),
    ))
}

#[cfg(not(windows))]
fn capture_raw_stack(_main_module_name: Option<&str>) -> Vec<RawStackFrame> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{mpsc, Arc, Barrier},
        thread,
        time::Duration,
    };

    struct RegisteredLaunches(Vec<String>);

    impl RegisteredLaunches {
        fn release(&mut self) {
            for launch_id in self.0.drain(..) {
                unregister_active_launch(&launch_id);
            }
        }
    }

    impl Drop for RegisteredLaunches {
        fn drop(&mut self) {
            self.release();
        }
    }

    fn test_diagnostics(directory: &Path, limits: ProcessLogLimits) -> ProcessDiagnostics {
        ProcessDiagnostics::new(
            Some(directory.to_path_buf()),
            ProcessRole::Daemon,
            "test_revision",
            None,
            limits,
            false,
        )
    }

    fn diagnostic_logs(directory: &Path) -> Vec<PathBuf> {
        fs::read_dir(directory)
            .expect("list diagnostics")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| is_launch_log_name(name) || is_panic_log_name(name))
            })
            .collect()
    }

    fn panic_logs(directory: &Path) -> Vec<PathBuf> {
        diagnostic_logs(directory)
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(is_panic_log_name)
            })
            .collect()
    }

    #[test]
    fn whitelist_jsonl_keeps_identity_but_rejects_payload_like_values() {
        let temporary = tempfile::tempdir().expect("temporary diagnostics directory");
        let diagnostics = test_diagnostics(
            temporary.path(),
            ProcessLogLimits {
                max_bytes: 4096,
                max_files: 3,
            },
        );
        diagnostics.record_operation_started("run_123", "pdf_render");
        diagnostics.record_operation_failed(
            "not a safe identifier / sensitive source",
            "pdf_render",
            "provider_failed?https://private.example",
        );
        diagnostics.record_panic_location("C:\\private\\source.rs", 77, 3);
        // Panic records use a distinct nonblocking emergency ledger. Verify
        // both ledgers, without assuming either event stays in one segment.
        let log = diagnostic_logs(temporary.path())
            .into_iter()
            .map(|path| fs::read_to_string(path).expect("process record exists"))
            .collect::<Vec<_>>()
            .join("");
        assert!(log.contains("\"launch_id\""));
        assert!(log.contains("\"exe_hash_status\""));
        assert!(log.contains("\"operation_id\":\"run_123\""));
        assert!(log.contains("\"source_module\":\"source.rs\""));
        assert!(!log.contains("private.example"));
        assert!(!log.contains("not a safe identifier"));
        assert!(!log.contains("C:\\\\private"));
    }

    #[test]
    fn write_failure_is_visible_and_never_reported_as_ready() {
        let temporary = tempfile::tempdir().expect("temporary diagnostics directory");
        let file = temporary.path().join("not_a_directory");
        fs::write(&file, b"fixture").expect("write fixture");
        let diagnostics = ProcessDiagnostics::initialize(&file, ProcessRole::Daemon, "revision");
        let status = diagnostics.status();
        assert!(!status.ready);
        assert_eq!(
            status.last_error_code.as_deref(),
            Some("diagnostic_write_failed")
        );
    }

    #[test]
    fn bounded_rotation_retains_only_the_configured_file_count() {
        let temporary = tempfile::tempdir().expect("temporary diagnostics directory");
        let diagnostics = test_diagnostics(
            temporary.path(),
            ProcessLogLimits {
                max_bytes: 800,
                max_files: 3,
            },
        );
        for index in 0..12 {
            diagnostics.record_operation_started(&format!("run_{index}"), "pdf_render");
        }
        let logs = diagnostic_logs(temporary.path())
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(is_launch_log_name)
            })
            .collect::<Vec<_>>();
        assert!(logs
            .iter()
            .any(|path| !path.to_string_lossy().contains(".1.jsonl")
                && !path.to_string_lossy().contains(".2.jsonl")));
        assert!(logs
            .iter()
            .any(|path| path.to_string_lossy().contains(".1.jsonl")));
        assert!(logs
            .iter()
            .any(|path| path.to_string_lossy().contains(".2.jsonl")));
        assert!(!logs
            .iter()
            .any(|path| path.to_string_lossy().contains(".3.jsonl")));
    }

    #[test]
    fn live_launch_lease_is_not_pruned_until_released() {
        let temporary = tempfile::tempdir().expect("temporary diagnostics directory");
        let limits = ProcessLogLimits {
            max_bytes: 4096,
            max_files: 3,
        };
        let old = test_diagnostics(temporary.path(), limits);
        let old_id = old.identity().launch_id;
        let old_log = temporary.path().join(format!("process-{old_id}.jsonl"));
        let old_marker = temporary.path().join(format!("active-{old_id}.json"));
        assert!(
            old_log.exists(),
            "the old launch writes its starting ledger"
        );
        assert!(old_marker.exists(), "the old launch owns a lease marker");
        assert!(old
            .inner
            .active_lease
            .lock()
            .expect("inspect old lease")
            .is_some());

        // Fill the aggregate normal-ledger allowance. The 31 synthetic ledgers
        // model other still-running processes; the old entry is a real held
        // marker lease. Their in-process registrations avoid relying on PID
        // liveness during this single-process unit test.
        let mut active_ids = Vec::new();
        for _ in 0..MAX_PROCESS_LAUNCH_LOG_FILES.saturating_sub(1) {
            let launch_id = new_launch_id(ProcessRole::Daemon);
            fs::write(
                temporary.path().join(format!("process-{launch_id}.jsonl")),
                b"{\"event\":\"fixture\"}\n",
            )
            .expect("write live ledger fixture");
            register_active_launch(&launch_id);
            active_ids.push(launch_id);
        }
        let mut active_ids = RegisteredLaunches(active_ids);

        let blocked = test_diagnostics(temporary.path(), limits);
        let blocked_status = blocked.status();
        assert!(!blocked_status.ready, "all live ledgers exhaust the budget");
        assert_eq!(
            blocked_status.last_error_code.as_deref(),
            Some("diagnostic_write_failed")
        );
        assert!(old_marker.exists(), "a live lease marker was not deleted");
        assert!(old_log.exists(), "a live launch ledger was not deleted");

        // This is the same release path reached after a terminal record. Once
        // the marker lease is gone, the next writer may reclaim that old entry.
        old.retire_active_marker();
        assert!(!old_marker.exists(), "released lease marker is removed");
        let recycled = test_diagnostics(temporary.path(), limits);
        assert!(recycled.status().ready, "a dead ledger can be reclaimed");
        assert!(
            !old_log.exists(),
            "the released oldest launch is reclaimed under aggregate pressure"
        );
        recycled.record_normal_stop();
        blocked.retire_active_marker();
        active_ids.release();
    }

    #[test]
    fn panic_slots_are_bounded_per_launch_and_across_live_launches() {
        let temporary = tempfile::tempdir().expect("temporary diagnostics directory");
        let limits = ProcessLogLimits {
            max_bytes: 4096,
            max_files: 3,
        };
        let diagnostics = (0..MAX_PANIC_EMERGENCY_LOG_FILES)
            .map(|_| test_diagnostics(temporary.path(), limits))
            .collect::<Vec<_>>();
        assert!(diagnostics.iter().all(|entry| entry.status().ready));

        // Use concurrent writers so every pre-reserved emergency file is used.
        // One writer continues through its strict per-file byte budget, while
        // peers establish independent concurrent panic records.
        let barrier = Arc::new(Barrier::new(diagnostics.len()));
        let writers = diagnostics
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, diagnostics)| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    if index == 0 {
                        let mut dropped = diagnostics.status().dropped_events;
                        for line in 1..=128 {
                            diagnostics.record_panic_location("panic_budget.rs", line, 1);
                            let next = diagnostics.status().dropped_events;
                            if next > dropped {
                                return true;
                            }
                            dropped = next;
                        }
                        false
                    } else {
                        diagnostics.record_panic_location("panic_peer.rs", index as u32, 1);
                        false
                    }
                })
            })
            .collect::<Vec<_>>();
        let saturated = writers
            .into_iter()
            .enumerate()
            .map(|(index, writer)| (index, writer.join().expect("panic writer returned")))
            .collect::<Vec<_>>();
        assert!(
            saturated[0].1,
            "the per-launch panic budget eventually rejects another record"
        );

        let logs = panic_logs(temporary.path());
        assert_eq!(logs.len(), MAX_PANIC_EMERGENCY_LOG_FILES);
        assert!(logs.iter().all(|path| {
            let length = fs::metadata(path).expect("panic log metadata").len();
            length > 0 && length <= MAX_PANIC_EMERGENCY_BYTES
        }));

        // All 16 slots are still leased. A seventeenth launch has no emergency
        // file, reports degraded status, and records its failed panic attempt
        // as dropped instead of pretending it was persisted.
        let blocked = test_diagnostics(temporary.path(), limits);
        let before = blocked.status().dropped_events;
        assert!(!blocked.status().ready);
        blocked.record_panic_location("overflow.rs", 1, 1);
        let after = blocked.status();
        assert!(!after.ready);
        assert!(after.dropped_events > before);
        assert_eq!(
            panic_logs(temporary.path()).len(),
            MAX_PANIC_EMERGENCY_LOG_FILES
        );

        for diagnostics in diagnostics {
            diagnostics.record_normal_stop();
        }
    }

    #[test]
    fn panic_recording_never_waits_for_a_busy_diagnostic_writer() {
        let temporary = tempfile::tempdir().expect("temporary diagnostics directory");
        let diagnostics = test_diagnostics(
            temporary.path(),
            ProcessLogLimits {
                max_bytes: 4096,
                max_files: 3,
            },
        );
        let guard = diagnostics
            .inner
            .write_guard
            .lock()
            .expect("hold only diagnostics writer lock");
        let budget = OpenOptions::new()
            .read(true)
            .write(true)
            .open(temporary.path().join("process-budget.lock"))
            .expect("open directory budget lock");
        budget.lock().expect("hold directory budget lock");
        let (sent, received) = mpsc::channel();
        let child = diagnostics.clone();
        thread::spawn(move || {
            child.record_panic_location("controlled.rs", 11, 2);
            sent.send(()).expect("panic recorder returned");
        });
        received
            .recv_timeout(Duration::from_millis(250))
            .expect("panic recorder must not wait for either diagnostic lock");
        drop(guard);
        drop(budget);
        let emergency = fs::read_dir(temporary.path())
            .expect("list panic records")
            .flatten()
            .map(|entry| entry.path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("panic-launch_"))
            })
            .expect("busy normal writer still leaves an emergency panic record");
        let log = fs::read_to_string(emergency).expect("read emergency panic record");
        assert!(log.contains("\"event\":\"panic\""));
        assert!(log.contains("\"source_module\":\"controlled.rs\""));
    }
}
