use crate::types::ProcessingError;
use std::process::{Child, Command};

pub(crate) struct ProcessTreeGuard {
    #[cfg(windows)]
    inner: windows::Job,
}

impl ProcessTreeGuard {
    /// Create the production MinerU worker Job. The managed worker must run
    /// Python and MinerU in-process; Windows rejects every descendant process.
    pub(crate) fn new_single_process() -> Result<Self, ProcessingError> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: windows::Job::new(1)?,
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {})
        }
    }

    /// Configure process creation so no uncontained child code runs before the
    /// process is assigned to the Job Object and the trust state is rechecked.
    pub(crate) fn configure_command(command: &mut Command) {
        #[cfg(windows)]
        windows::configure_command(command);
        #[cfg(not(windows))]
        let _ = command;
    }

    pub(crate) fn assign(&mut self, child: &Child) -> Result<(), ProcessingError> {
        #[cfg(windows)]
        {
            self.inner.assign(child)
        }
        #[cfg(not(windows))]
        {
            let _ = child;
            Ok(())
        }
    }

    pub(crate) fn resume(&mut self, child: &Child) -> Result<(), ProcessingError> {
        #[cfg(windows)]
        {
            self.inner.resume(child)
        }
        #[cfg(not(windows))]
        {
            let _ = child;
            Ok(())
        }
    }

    pub(crate) fn terminate(&mut self) -> Result<(), ProcessingError> {
        #[cfg(windows)]
        {
            self.inner.terminate()
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

#[cfg(windows)]
mod windows {
    #![allow(unsafe_code)]

    use crate::types::ProcessingError;
    use std::{
        mem::size_of,
        os::windows::{io::AsRawHandle, process::CommandExt},
        process::{Child, Command},
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
            Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED},
        },
    };

    #[link(name = "ntdll")]
    extern "system" {
        fn NtResumeProcess(process_handle: HANDLE) -> i32;
    }

    pub(super) fn configure_command(command: &mut Command) {
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
    }

    pub(super) struct Job {
        handle: HANDLE,
        assigned: bool,
    }

    impl Job {
        pub(super) fn new(active_process_limit: u32) -> Result<Self, ProcessingError> {
            if active_process_limit != 1 {
                return Err(ProcessingError::OcrProcessContainmentUnavailable);
            }
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(ProcessingError::OcrProcessContainmentUnavailable);
            }
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = active_process_limit;
            let configured = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&limits).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if configured == 0 {
                unsafe {
                    CloseHandle(handle);
                }
                return Err(ProcessingError::OcrProcessContainmentUnavailable);
            }
            Ok(Self {
                handle,
                assigned: false,
            })
        }

        pub(super) fn assign(&mut self, child: &Child) -> Result<(), ProcessingError> {
            let process = child.as_raw_handle() as HANDLE;
            if process.is_null() || unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
                return Err(ProcessingError::OcrProcessContainmentUnavailable);
            }
            self.assigned = true;
            Ok(())
        }

        pub(super) fn resume(&mut self, child: &Child) -> Result<(), ProcessingError> {
            if !self.assigned {
                return Err(ProcessingError::OcrProcessContainmentUnavailable);
            }
            let process = child.as_raw_handle() as HANDLE;
            if process.is_null() || unsafe { NtResumeProcess(process) } != 0 {
                return Err(ProcessingError::OcrProcessContainmentUnavailable);
            }
            Ok(())
        }

        pub(super) fn terminate(&mut self) -> Result<(), ProcessingError> {
            if self.assigned && unsafe { TerminateJobObject(self.handle, 1) } == 0 {
                return Err(ProcessingError::OcrProcessContainmentUnavailable);
            }
            self.assigned = false;
            Ok(())
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            if self.assigned {
                unsafe {
                    TerminateJobObject(self.handle, 1);
                }
            }
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}
