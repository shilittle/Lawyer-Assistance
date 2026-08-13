use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use tauri::{plugin::TauriPlugin, AppHandle, Manager, Runtime};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, SetLastError, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE,
        WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
};

const MAIN_WINDOW_LABEL: &str = "main";
const STARTUP_GUARD_TIMEOUT_MS: u32 = 120_000;
const MIGRATION_GUARD_TIMEOUT_MS: u32 = 120_000;

pub(crate) type PendingRevealFlag = Arc<AtomicBool>;
pub(crate) type UiReadyFlag = Arc<AtomicBool>;

/// Owns one session-local mutex used by the startup or lifetime fail-closed guard.
#[must_use]
#[derive(Debug)]
pub(crate) struct NamedMutexGuard {
    handle: HANDLE,
}

impl Drop for NamedMutexGuard {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.handle);
            CloseHandle(self.handle);
        }
    }
}

pub(crate) fn new_pending_reveal_flag() -> PendingRevealFlag {
    Arc::new(AtomicBool::new(false))
}

pub(crate) fn new_ui_ready_flag() -> UiReadyFlag {
    Arc::new(AtomicBool::new(false))
}

pub(crate) fn acquire_startup_guard(identifier: &str) -> io::Result<NamedMutexGuard> {
    acquire_named_startup_guard(
        &format!("Local\\{identifier}-single-instance-startup"),
        STARTUP_GUARD_TIMEOUT_MS,
    )
}

/// Serializes every migration and restore transition independently of the
/// single-instance startup/lifetime guards. Keeping this namespace distinct is
/// intentional: the startup guard is released once Tauri has finished
/// building, whereas this guard is held only for the classified state
/// transition and must be released before the normal event loop starts.
pub(crate) fn acquire_migration_guard(identifier: &str) -> io::Result<NamedMutexGuard> {
    acquire_named_startup_guard(
        &format!("Local\\{identifier}-migration-and-restore"),
        MIGRATION_GUARD_TIMEOUT_MS,
    )
}

pub(crate) fn try_acquire_lifetime_guard(identifier: &str) -> io::Result<Option<NamedMutexGuard>> {
    try_acquire_named_lifetime_guard(&format!("Local\\{identifier}-single-instance-lifetime"))
}

fn acquire_named_startup_guard(name: &str, timeout_ms: u32) -> io::Result<NamedMutexGuard> {
    let (handle, already_exists) = create_owned_named_mutex(name)?;
    if already_exists {
        let wait_result = unsafe { WaitForSingleObject(handle, timeout_ms) };
        match wait_result {
            WAIT_OBJECT_0 | WAIT_ABANDONED => {}
            WAIT_TIMEOUT => {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for the single-instance startup guard",
                ));
            }
            WAIT_FAILED => {
                let error = io::Error::last_os_error();
                unsafe {
                    CloseHandle(handle);
                }
                return Err(error);
            }
            unexpected => {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(io::Error::other(format!(
                    "unexpected single-instance wait result: {unexpected}"
                )));
            }
        }
    }

    Ok(NamedMutexGuard { handle })
}

fn try_acquire_named_lifetime_guard(name: &str) -> io::Result<Option<NamedMutexGuard>> {
    let (handle, already_exists) = create_owned_named_mutex(name)?;
    if already_exists {
        unsafe {
            CloseHandle(handle);
        }
        Ok(None)
    } else {
        Ok(Some(NamedMutexGuard { handle }))
    }
}

fn create_owned_named_mutex(name: &str) -> io::Result<(HANDLE, bool)> {
    if name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "single-instance mutex name contains NUL",
        ));
    }

    let wide_name = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    unsafe {
        SetLastError(ERROR_SUCCESS);
    }
    let handle = unsafe { CreateMutexW(std::ptr::null(), true.into(), wide_name.as_ptr()) };
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }

    Ok((handle, unsafe { GetLastError() } == ERROR_ALREADY_EXISTS))
}

pub(crate) fn plugin<R: Runtime>(
    pending_reveal: PendingRevealFlag,
    ui_ready: UiReadyFlag,
) -> TauriPlugin<R> {
    // The secondary process's argv and cwd are intentionally matched with `_`:
    // they are immediately discarded and are never logged, emitted, or persisted.
    tauri_plugin_single_instance::init(move |app, _, _| {
        request_main_window_reveal(app, &pending_reveal, &ui_ready);
    })
}

fn request_main_window_reveal<R: Runtime>(
    app: &AppHandle<R>,
    pending: &AtomicBool,
    ui_ready: &AtomicBool,
) {
    request_reveal(pending, ui_ready, || reveal_main_window(app));
}

fn request_reveal(pending: &AtomicBool, ui_ready: &AtomicBool, reveal: impl FnOnce() -> bool) {
    // Store first, then try the window. This order closes the race with app setup:
    // either this call reveals the window or setup observes and flushes the flag.
    pending.store(true, Ordering::Release);
    if ui_ready.load(Ordering::Acquire) && reveal() {
        pending.store(false, Ordering::Release);
    }
}

pub(crate) fn mark_ui_ready_and_reveal_main_window<R: Runtime>(
    app: &AppHandle<R>,
    pending: &AtomicBool,
    ui_ready: &AtomicBool,
) {
    ui_ready.store(true, Ordering::Release);
    pending.store(true, Ordering::Release);
    flush_pending_reveal(pending, || reveal_main_window(app));
}

fn flush_pending_reveal(pending: &AtomicBool, reveal: impl FnOnce() -> bool) {
    if pending.swap(false, Ordering::AcqRel) && !reveal() {
        pending.store(true, Ordering::Release);
    }
}

fn reveal_main_window<R: Runtime>(app: &AppHandle<R>) -> bool {
    let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        return false;
    };

    // Attempt every operation independently so one platform-specific failure does
    // not prevent the remaining best-effort restore/focus actions.
    let _ = window.show();
    let _ = window.unminimize();
    let _ = window.set_focus();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const CHILD_MUTEX_NAME_ENV: &str = "LAWYER_ASSISTANCE_TEST_STARTUP_MUTEX_NAME";
    const CHILD_MUTEX_MODE_ENV: &str = "LAWYER_ASSISTANCE_TEST_STARTUP_MUTEX_MODE";

    #[test]
    fn startup_guard_fails_closed_across_processes_and_recovers_after_release() {
        let name = format!(
            "Local\\lawyer-assistance-test-startup-{}",
            uuid::Uuid::new_v4()
        );
        let first = acquire_named_startup_guard(&name, 1_000).expect("first guard");
        run_startup_guard_child(&name, "blocked");

        drop(first);
        run_startup_guard_child(&name, "available");
    }

    #[test]
    fn migration_guard_blocks_across_processes_and_recovers_after_release() {
        let identifier = format!("lawyer-assistance-test-migration-{}", uuid::Uuid::new_v4());
        let name = format!("Local\\{identifier}-migration-and-restore");
        let first = acquire_migration_guard(&identifier).expect("first migration guard");
        run_startup_guard_child(&name, "blocked");

        drop(first);
        run_startup_guard_child(&name, "available");
    }

    #[test]
    fn lifetime_guard_assigns_exactly_one_primary_across_processes() {
        let name = format!(
            "Local\\lawyer-assistance-test-lifetime-{}",
            uuid::Uuid::new_v4()
        );
        let first = try_acquire_named_lifetime_guard(&name)
            .expect("first lifetime guard")
            .expect("first process is primary");
        run_startup_guard_child(&name, "lifetime-secondary");

        drop(first);
        run_startup_guard_child(&name, "lifetime-primary");
    }

    fn run_startup_guard_child(name: &str, mode: &str) {
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "single_instance::tests::startup_guard_child_process",
                "--nocapture",
            ])
            .env(CHILD_MUTEX_NAME_ENV, name)
            .env(CHILD_MUTEX_MODE_ENV, mode)
            .output()
            .expect("run startup guard child process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "child process failed; stdout={stdout}; stderr={stderr}"
        );
        assert!(
            stdout.contains("single_instance::tests::startup_guard_child_process"),
            "child helper did not run; stdout={stdout}; stderr={stderr}"
        );
    }

    #[test]
    fn startup_guard_child_process() {
        let Ok(name) = std::env::var(CHILD_MUTEX_NAME_ENV) else {
            return;
        };
        let mode = std::env::var(CHILD_MUTEX_MODE_ENV).expect("child mutex mode");

        match mode.as_str() {
            "blocked" => assert_eq!(
                acquire_named_startup_guard(&name, 25)
                    .expect_err("parent guard must prevent child acquisition")
                    .kind(),
                io::ErrorKind::TimedOut
            ),
            "available" => drop(
                acquire_named_startup_guard(&name, 1_000)
                    .expect("child acquires guard after parent release"),
            ),
            "lifetime-secondary" => assert!(
                try_acquire_named_lifetime_guard(&name)
                    .expect("child lifetime role")
                    .is_none(),
                "child must remain secondary while parent owns lifetime guard"
            ),
            "lifetime-primary" => drop(
                try_acquire_named_lifetime_guard(&name)
                    .expect("child lifetime role")
                    .expect("child becomes primary after parent release"),
            ),
            unexpected => panic!("unexpected child mutex mode: {unexpected}"),
        }
    }

    #[test]
    fn early_reveal_request_is_flushed_after_reveal_target_exists() {
        let pending = new_pending_reveal_flag();
        let ui_ready = new_ui_ready_flag();
        let reveal_attempts = AtomicBool::new(false);

        request_reveal(&pending, &ui_ready, || {
            reveal_attempts.store(true, Ordering::Release);
            true
        });
        assert!(pending.load(Ordering::Acquire));
        assert!(!reveal_attempts.load(Ordering::Acquire));

        ui_ready.store(true, Ordering::Release);
        flush_pending_reveal(&pending, || {
            reveal_attempts.store(true, Ordering::Release);
            true
        });

        assert!(!pending.load(Ordering::Acquire));
        assert!(reveal_attempts.load(Ordering::Acquire));
    }

    #[test]
    fn failed_pending_reveal_remains_pending_for_a_later_flush() {
        let pending = new_pending_reveal_flag();
        pending.store(true, Ordering::Release);

        flush_pending_reveal(&pending, || false);

        assert!(pending.load(Ordering::Acquire));
    }

    #[test]
    fn invalid_mutex_name_is_rejected_without_calling_windows() {
        let error = acquire_named_startup_guard("bad\0name", 0).expect_err("invalid name");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
