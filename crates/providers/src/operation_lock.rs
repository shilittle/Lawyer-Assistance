#[cfg(windows)]
mod platform {
    use crate::{ProviderError, ProviderErrorKind};
    use std::{io, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
    };

    const PROVIDER_STORE_MUTEX_NAME: &str = "Local\\LawyerAssistance.ProviderStore.v1";
    const PROVIDER_STORE_LOCK_TIMEOUT_MS: u32 = 5_000;

    /// Serializes the SQLite/Credential Manager lifecycle across app processes.
    ///
    /// Provider profile rows and Windows credentials live in different stores, so
    /// every command that observes or mutates both must hold this named OS mutex.
    /// Windows releases an abandoned mutex when a process exits unexpectedly.
    #[derive(Debug)]
    pub struct ProviderStoreLock {
        handle: windows_sys::Win32::Foundation::HANDLE,
    }

    impl ProviderStoreLock {
        pub fn acquire() -> Result<Self, ProviderError> {
            Self::acquire_named(PROVIDER_STORE_MUTEX_NAME, PROVIDER_STORE_LOCK_TIMEOUT_MS)
        }

        fn acquire_named(name: &str, timeout_ms: u32) -> Result<Self, ProviderError> {
            let wide_name = name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            // SAFETY: the mutex name is a live, NUL-terminated UTF-16 buffer and
            // the returned handle is owned by ProviderStoreLock until Drop.
            let handle = unsafe { CreateMutexW(ptr::null(), 0, wide_name.as_ptr()) };
            if handle.is_null() {
                return Err(lock_error("create", io::Error::last_os_error()));
            }

            // SAFETY: handle is a valid mutex handle returned by CreateMutexW.
            let wait_result = unsafe { WaitForSingleObject(handle, timeout_ms) };
            match wait_result {
                WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self { handle }),
                WAIT_TIMEOUT => {
                    // SAFETY: handle is valid and is not owned after a timeout.
                    unsafe { CloseHandle(handle) };
                    Err(ProviderError::new(
                        ProviderErrorKind::Credential,
                        "provider credential store is busy; retry the operation",
                    ))
                }
                _ => {
                    let error = io::Error::last_os_error();
                    // SAFETY: handle is valid and is not owned after a failed wait.
                    unsafe { CloseHandle(handle) };
                    Err(lock_error("wait for", error))
                }
            }
        }
    }

    impl Drop for ProviderStoreLock {
        fn drop(&mut self) {
            // SAFETY: successful acquisition makes the current thread the mutex
            // owner, and this guard is dropped on that same synchronous command
            // thread. The handle is closed exactly once here.
            unsafe {
                ReleaseMutex(self.handle);
                CloseHandle(self.handle);
            }
        }
    }

    fn lock_error(action: &str, error: io::Error) -> ProviderError {
        ProviderError::new(
            ProviderErrorKind::Credential,
            format!("failed to {action} provider credential store lock: {error}"),
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{sync::mpsc, thread, time::Duration};

        fn test_mutex_name(test_name: &str) -> String {
            format!(
                "Local\\LawyerAssistance.ProviderStore.test.{}.{}",
                std::process::id(),
                test_name
            )
        }

        #[test]
        fn named_lock_serializes_concurrent_threads() {
            let name = test_mutex_name("serialize");
            let first =
                ProviderStoreLock::acquire_named(&name, 1_000).expect("first lock acquires");
            let (started_tx, started_rx) = mpsc::channel();
            let (acquired_tx, acquired_rx) = mpsc::channel();
            let contender_name = name.clone();

            let contender = thread::spawn(move || {
                started_tx.send(()).expect("start signal sends");
                let _second = ProviderStoreLock::acquire_named(&contender_name, 2_000)
                    .expect("second lock eventually acquires");
                acquired_tx.send(()).expect("acquired signal sends");
            });

            started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("contender starts");
            assert!(acquired_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err());
            drop(first);
            acquired_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("contender acquires after release");
            contender.join().expect("contender exits");
        }

        #[test]
        fn named_lock_reports_bounded_busy_error() {
            let name = test_mutex_name("timeout");
            let _first =
                ProviderStoreLock::acquire_named(&name, 1_000).expect("first lock acquires");
            let contender_name = name.clone();
            let error = thread::spawn(move || {
                ProviderStoreLock::acquire_named(&contender_name, 25)
                    .expect_err("contender times out")
            })
            .join()
            .expect("contender exits");

            assert_eq!(error.kind, ProviderErrorKind::Credential);
            assert!(error.message.contains("busy"));
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use crate::{ProviderError, ProviderErrorKind};

    /// Provider profiles are paired with Windows Credential Manager secrets.
    ///
    /// The desktop credential lifecycle is intentionally unavailable on other
    /// platforms. Returning an error here prevents callers from silently running
    /// a multi-store operation without the Windows cross-process mutex.
    #[derive(Debug)]
    pub struct ProviderStoreLock {
        _private: (),
    }

    impl ProviderStoreLock {
        pub fn acquire() -> Result<Self, ProviderError> {
            Err(ProviderError::new(
                ProviderErrorKind::Credential,
                "provider credential store lock is only available on Windows",
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn non_windows_lock_fails_closed() {
            let error =
                ProviderStoreLock::acquire().expect_err("non-Windows credential lock is rejected");

            assert_eq!(error.kind, ProviderErrorKind::Credential);
            assert!(error.message.contains("only available on Windows"));
        }
    }
}

pub use platform::ProviderStoreLock;
