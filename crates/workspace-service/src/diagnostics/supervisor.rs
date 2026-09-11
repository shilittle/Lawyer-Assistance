use crate::{now, Error};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    future::Future,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_HEARTBEAT_AGE: Duration = Duration::from_secs(10);
const MAX_RETAINED_OPERATIONS: usize = 128;
const REPEATED_FAILURE_LOG_INTERVAL: Duration = Duration::from_secs(60);
const MAX_DIAGNOSTIC_LOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DIAGNOSTIC_LOG_FILES: u8 = 3;

/// Tracks the liveness of work which outlives an HTTP request.  It intentionally
/// holds identifiers and stable error classifications only; document content,
/// provider requests, credentials and filesystem paths are never diagnostic data.
pub(crate) struct Supervisor {
    root: PathBuf,
    state: Mutex<SupervisorState>,
}

#[derive(Default)]
struct SupervisorState {
    operations: HashMap<OperationKey, OperationState>,
    diagnostic_error: Option<String>,
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct OperationKey {
    kind: &'static str,
    id: String,
}

struct OperationState {
    phase: &'static str,
    started_at: u64,
    started: Instant,
    heartbeat: Instant,
    terminal: TerminalState,
    error_code: Option<String>,
    last_failure_log: Option<Instant>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TerminalState {
    Active,
    Completed,
    Failed,
}

#[derive(Serialize)]
pub(crate) struct SupervisorHealth {
    pub(crate) material_worker: WorkerHealth,
    pub(crate) diagnostics: DiagnosticsHealth,
    active_ai_runs: usize,
    failed_ai_runs: usize,
}

#[derive(Serialize)]
pub(crate) struct WorkerHealth {
    pub(crate) ready: bool,
    status: &'static str,
    last_error_code: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct DiagnosticsHealth {
    pub(crate) ready: bool,
    status: &'static str,
    last_error_code: Option<String>,
}

#[derive(Serialize)]
struct DiagnosticEvent<'a> {
    timestamp: u64,
    component: &'static str,
    operation_id: &'a str,
    phase: &'static str,
    event: &'static str,
    error_code: Option<&'a str>,
    retryable: Option<bool>,
    error_category: Option<&'static str>,
    error_detail: Option<&'a str>,
    elapsed_ms: Option<u64>,
}

impl Supervisor {
    pub(crate) fn new(root: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            root,
            state: Mutex::new(SupervisorState::default()),
        })
    }

    pub(crate) fn start(&self, kind: &'static str, id: &str, phase: &'static str) {
        let key = OperationKey {
            kind,
            id: id.to_owned(),
        };
        let state = OperationState {
            phase,
            started_at: now(),
            started: Instant::now(),
            heartbeat: Instant::now(),
            terminal: TerminalState::Active,
            error_code: None,
            last_failure_log: None,
        };
        if let Ok(mut all) = self.state.lock() {
            all.operations.insert(key, state);
            trim_completed(&mut all.operations);
        }
        self.write_event(kind, id, phase, "started", None);
    }

    pub(crate) fn heartbeat(&self, kind: &'static str, id: &str, phase: &'static str) {
        let key = OperationKey {
            kind,
            id: id.to_owned(),
        };
        if let Ok(mut all) = self.state.lock() {
            if let Some(operation) = all.operations.get_mut(&key) {
                operation.phase = phase;
                operation.heartbeat = Instant::now();
                if operation.terminal == TerminalState::Failed {
                    operation.terminal = TerminalState::Active;
                    operation.error_code = None;
                }
            }
        }
    }

    /// Records a handled operation error without declaring the long-lived worker
    /// unavailable.  A material can fail validation while the worker remains able
    /// to accept the next material.
    pub(crate) fn operation_failed(
        &self,
        kind: &'static str,
        id: &str,
        phase: &'static str,
        error: &Error,
    ) {
        self.write_event(kind, id, phase, "operation_failed", Some(error));
    }

    /// Records that the supervisor itself can no longer establish that an
    /// operation is able to work, for example a queue read failure or task panic.
    pub(crate) fn failed(&self, kind: &'static str, id: &str, phase: &'static str, error: &Error) {
        let key = OperationKey {
            kind,
            id: id.to_owned(),
        };
        let write_event = if let Ok(mut all) = self.state.lock() {
            let operation = all.operations.entry(key).or_insert_with(|| OperationState {
                phase,
                started_at: now(),
                started: Instant::now(),
                heartbeat: Instant::now(),
                terminal: TerminalState::Active,
                error_code: None,
                last_failure_log: None,
            });
            let now_instant = Instant::now();
            let same_failure = operation.terminal == TerminalState::Failed
                && operation.phase == phase
                && operation.error_code.as_deref() == Some(error.code.as_str());
            let rate_limited = same_failure
                && operation.last_failure_log.is_some_and(|last| {
                    now_instant.duration_since(last) < REPEATED_FAILURE_LOG_INTERVAL
                });
            operation.phase = phase;
            operation.heartbeat = now_instant;
            operation.terminal = TerminalState::Failed;
            operation.error_code = Some(error.code.clone());
            if !rate_limited {
                operation.last_failure_log = Some(now_instant);
            }
            trim_completed(&mut all.operations);
            !rate_limited
        } else {
            false
        };
        if write_event {
            self.write_event(kind, id, phase, "failed", Some(error));
        }
    }

    pub(crate) fn completed(&self, kind: &'static str, id: &str, phase: &'static str) {
        let key = OperationKey {
            kind,
            id: id.to_owned(),
        };
        let completed = if let Ok(mut all) = self.state.lock() {
            if let Some(operation) = all.operations.get_mut(&key) {
                if operation.terminal == TerminalState::Failed {
                    return;
                }
                operation.phase = phase;
                operation.heartbeat = Instant::now();
                operation.terminal = TerminalState::Completed;
                operation.error_code = None;
            }
            trim_completed(&mut all.operations);
            true
        } else {
            false
        };
        if completed {
            self.write_event(kind, id, phase, "completed", None);
        }
    }

    /// Runs a task under a small join supervisor.  The outer handle keeps the
    /// normal caller-owned cancellation semantics; the guard aborts the inner
    /// task if that outer handle is aborted, avoiding a detached worker.
    pub(crate) fn spawn<F, H>(
        self: &Arc<Self>,
        kind: &'static str,
        id: String,
        future: F,
        on_failure: H,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
        H: FnOnce(&Error) -> crate::Result<()> + Send + 'static,
    {
        self.start(kind, &id, "started");
        let supervisor = Arc::clone(self);
        tokio::spawn(async move {
            // Keep the operation identity task-local for the work itself and
            // its panic hook.  A process-wide mutable value would let a
            // concurrent A/B run incorrectly claim another run's worker.
            let task = tokio::spawn(super::process::with_operation_id(id.clone(), future));
            let guard = AbortChildOnDrop(task.abort_handle());
            let result = task.await;
            match result {
                Ok(()) => supervisor.completed(kind, &id, "completed"),
                Err(join_error) if join_error.is_panic() => {
                    let error = Error::new("task_panicked");
                    supervisor.failed(kind, &id, "panicked", &error);
                    if let Err(persist_error) = on_failure(&error) {
                        supervisor.operation_failed(kind, &id, "panic_persist", &persist_error);
                    }
                }
                Err(_) => {
                    let error = Error::new("task_cancelled");
                    supervisor.failed(kind, &id, "cancelled", &error);
                    if let Err(persist_error) = on_failure(&error) {
                        supervisor.operation_failed(kind, &id, "cancel_persist", &persist_error);
                    }
                }
            }
            // Dropping this after `await` is harmless for a completed child and
            // aborts it only if the outer supervisor itself is cancelled early.
            drop(guard);
        })
    }

    pub(crate) fn health(&self) -> SupervisorHealth {
        let now_instant = Instant::now();
        let Ok(all) = self.state.lock() else {
            return SupervisorHealth {
                material_worker: WorkerHealth {
                    ready: false,
                    status: "unavailable",
                    last_error_code: Some("supervisor_unavailable".to_owned()),
                },
                diagnostics: DiagnosticsHealth {
                    ready: false,
                    status: "unavailable",
                    last_error_code: Some("supervisor_unavailable".to_owned()),
                },
                active_ai_runs: 0,
                failed_ai_runs: 0,
            };
        };
        let worker = all.operations.get(&OperationKey {
            kind: "material_worker",
            id: "worker".to_owned(),
        });
        let material_worker = match worker {
            None => WorkerHealth {
                ready: false,
                status: "not_started",
                last_error_code: None,
            },
            Some(operation) if operation.terminal == TerminalState::Failed => WorkerHealth {
                ready: false,
                status: "failed",
                last_error_code: operation.error_code.clone(),
            },
            Some(operation) if operation.terminal == TerminalState::Completed => WorkerHealth {
                ready: false,
                status: "stopped",
                last_error_code: None,
            },
            Some(operation)
                if now_instant.duration_since(operation.heartbeat) > MAX_HEARTBEAT_AGE =>
            {
                WorkerHealth {
                    ready: false,
                    status: "stale",
                    last_error_code: None,
                }
            }
            Some(_) => WorkerHealth {
                ready: true,
                status: "running",
                last_error_code: None,
            },
        };
        let active_ai_runs = all
            .operations
            .iter()
            .filter(|(key, value)| key.kind == "ai_run" && value.terminal == TerminalState::Active)
            .count();
        let failed_ai_runs = all
            .operations
            .iter()
            .filter(|(key, value)| key.kind == "ai_run" && value.terminal == TerminalState::Failed)
            .count();
        let diagnostics = match &all.diagnostic_error {
            Some(code) => DiagnosticsHealth {
                ready: false,
                status: "failed",
                last_error_code: Some(code.clone()),
            },
            None => DiagnosticsHealth {
                ready: true,
                status: "ready",
                last_error_code: None,
            },
        };
        SupervisorHealth {
            material_worker,
            diagnostics,
            active_ai_runs,
            failed_ai_runs,
        }
    }

    fn write_event(
        &self,
        component: &'static str,
        operation_id: &str,
        phase: &'static str,
        event: &'static str,
        error: Option<&Error>,
    ) {
        let event = DiagnosticEvent {
            timestamp: now(),
            component,
            operation_id,
            phase,
            event,
            error_code: error.map(|value| value.code.as_str()),
            retryable: error.map(|value| value.retryable),
            error_category: error.and_then(Error::diagnostic_category),
            error_detail: error.and_then(Error::diagnostic_detail),
            elapsed_ms: self.operation_elapsed_ms(component, operation_id),
        };
        let Ok(mut line) = serde_json::to_vec(&event) else {
            return;
        };
        line.push(b'\n');
        let directory = self.root.join("diagnostics");
        if std::fs::create_dir_all(&directory).is_err()
            || crate::filesystem::ordinary_chain(&directory).is_err()
        {
            self.diagnostic_write_failed();
            return;
        }
        let path = directory.join("supervisor.jsonl");
        if path.exists() && crate::filesystem::ordinary_chain(&path).is_err() {
            self.diagnostic_write_failed();
            return;
        }
        if self
            .rotate_log_if_needed(&directory, &path, line.len() as u64)
            .is_err()
        {
            self.diagnostic_write_failed();
            return;
        }
        let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
            self.diagnostic_write_failed();
            return;
        };
        if file.write_all(&line).is_err() {
            self.diagnostic_write_failed();
            return;
        }
        self.diagnostic_write_succeeded();
    }

    fn rotate_log_if_needed(
        &self,
        directory: &std::path::Path,
        active: &std::path::Path,
        incoming: u64,
    ) -> std::io::Result<()> {
        let current = active
            .metadata()
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if current.saturating_add(incoming) <= MAX_DIAGNOSTIC_LOG_BYTES {
            return Ok(());
        }
        let oldest = directory.join(format!("supervisor.{}.jsonl", MAX_DIAGNOSTIC_LOG_FILES - 1));
        if oldest.exists() {
            crate::filesystem::ordinary_chain(&oldest)
                .map_err(|_| std::io::Error::other("diagnostic path rejected"))?;
            std::fs::remove_file(&oldest)?;
        }
        for index in (1..MAX_DIAGNOSTIC_LOG_FILES).rev() {
            let source = if index == 1 {
                active.to_path_buf()
            } else {
                directory.join(format!("supervisor.{}.jsonl", index - 1))
            };
            if !source.exists() {
                continue;
            }
            crate::filesystem::ordinary_chain(&source)
                .map_err(|_| std::io::Error::other("diagnostic path rejected"))?;
            let destination = directory.join(format!("supervisor.{}.jsonl", index));
            if destination.exists() {
                crate::filesystem::ordinary_chain(&destination)
                    .map_err(|_| std::io::Error::other("diagnostic path rejected"))?;
            }
            std::fs::rename(source, destination)?;
        }
        Ok(())
    }

    fn diagnostic_write_failed(&self) {
        if let Ok(mut all) = self.state.lock() {
            all.diagnostic_error = Some("diagnostic_write_failed".to_owned());
        }
    }

    fn diagnostic_write_succeeded(&self) {
        if let Ok(mut all) = self.state.lock() {
            all.diagnostic_error = None;
        }
    }

    fn operation_elapsed_ms(&self, kind: &'static str, id: &str) -> Option<u64> {
        let all = self.state.lock().ok()?;
        all.operations
            .get(&OperationKey {
                kind,
                id: id.to_owned(),
            })
            .map(|operation| Instant::now().duration_since(operation.started).as_millis() as u64)
    }
}

struct AbortChildOnDrop(tokio::task::AbortHandle);

impl Drop for AbortChildOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn trim_completed(operations: &mut HashMap<OperationKey, OperationState>) {
    if operations.len() <= MAX_RETAINED_OPERATIONS {
        return;
    }
    let mut completed = operations
        .iter()
        .filter(|(_, value)| value.terminal == TerminalState::Completed)
        .map(|(key, value)| (key.clone(), value.started_at))
        .collect::<Vec<_>>();
    completed.sort_by_key(|(_, started_at)| *started_at);
    for (key, _) in completed {
        if operations.len() <= MAX_RETAINED_OPERATIONS {
            break;
        }
        operations.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn supervised_panic_is_visible_without_logging_sensitive_payloads() {
        let directory = tempfile::tempdir().expect("temporary diagnostics directory");
        let supervisor = Supervisor::new(directory.path().to_path_buf());
        let handle = supervisor.spawn(
            "ai_run",
            "run_test".to_owned(),
            async { panic!("must not become a diagnostic record: sensitive original 13800138000") },
            |_| Ok(()),
        );
        handle.await.expect("supervisor itself does not panic");

        let health = supervisor.health();
        assert_eq!(health.failed_ai_runs, 1);
        let log = std::fs::read_to_string(directory.path().join("diagnostics/supervisor.jsonl"))
            .expect("controlled diagnostic log exists");
        assert!(log.contains("task_panicked"));
        assert!(log.contains("elapsed_ms"));
        assert!(!log.contains("sensitive original"));
        assert!(!log.contains("13800138000"));
    }

    #[test]
    fn diagnostic_write_failure_is_visible_to_health() {
        let directory = tempfile::tempdir().expect("temporary diagnostics directory");
        let file = directory.path().join("not_a_directory");
        std::fs::write(&file, b"not a directory").expect("test root file writes");
        let supervisor = Supervisor::new(file);
        supervisor.start("material_worker", "worker", "started");
        let health = supervisor.health();
        assert!(!health.diagnostics.ready);
        assert_eq!(
            health.diagnostics.last_error_code.as_deref(),
            Some("diagnostic_write_failed")
        );
    }
}
