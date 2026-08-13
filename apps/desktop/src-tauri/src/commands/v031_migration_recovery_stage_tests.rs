#![cfg(windows)]

//! Public R3 staging/quiescence state-machine tests.
//!
//! The production Tauri handler and this fake both use
//! `sequence_v031_recovery_stage`; the fake deliberately has no `AppHandle`.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Success,
    BeginAlreadyOwned,
    DrainFailure,
    FinalizeFormalAbsent,
    FinalizeFormalPresent,
    CleanupFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    PrepareCompleted,
    BeginAccepted,
    BeginRejected,
    AdmissionClosed,
    RestartAlreadyOwned,
    DrainStarted,
    DrainCompleted,
    DrainFailed,
    FinalizeStarted,
    ThreeBarriersAcquired,
    FinalReproofPassed,
    FinalReproofFailed,
    FormalInstalled,
    GuardsRetained,
    FinalizeReportedFailure,
    CleanupStarted,
    CleanupVerified,
    CleanupFailed,
    RestartRequested,
}

struct FakeStageRuntime {
    scenario: Scenario,
    events: Vec<Event>,
    admission_closed: bool,
    admission_close_count: usize,
    drain_completed: bool,
    formal_installed: bool,
    restart_count: usize,
}

impl FakeStageRuntime {
    fn new(scenario: Scenario) -> Self {
        Self {
            scenario,
            events: Vec::new(),
            admission_closed: false,
            admission_close_count: 0,
            drain_completed: false,
            formal_installed: false,
            restart_count: 0,
        }
    }

    fn close_admission_fail_closed(&mut self) {
        assert!(!self.admission_closed, "admission is closed exactly once");
        self.admission_closed = true;
        self.admission_close_count += 1;
        self.events.push(Event::AdmissionClosed);
    }

    fn error(error_type: &'static str) -> IpcError {
        recovery_error(error_type, "synthetic R3 public stage failure")
    }

    fn assert_fail_closed(&self) {
        assert!(self.admission_closed, "R3 admission remains closed");
        assert_eq!(self.admission_close_count, 1);
    }
}

impl V031RecoveryStageRuntime for FakeStageRuntime {
    fn prepare_reserve_exit_and_close_admission(
        &mut self,
    ) -> StageFuture<'_, StagePreparationOutcome> {
        Box::pin(async move {
            self.events.push(Event::PrepareCompleted);
            if self.scenario == Scenario::BeginAlreadyOwned {
                self.events.push(Event::BeginRejected);
                self.close_admission_fail_closed();
                self.events.push(Event::CleanupStarted);
                self.events.push(Event::CleanupVerified);
                self.events.push(Event::RestartAlreadyOwned);
                return StagePreparationOutcome::Failed {
                    error: Self::error("application_exiting"),
                    exit_ownership: Some(StageExitOwnership::RestartAlreadyOwned),
                };
            }

            self.events.push(Event::BeginAccepted);
            self.close_admission_fail_closed();
            StagePreparationOutcome::PreparedAndExitOwned
        })
    }

    fn drain_mcp_and_standalone(&mut self) -> StageFuture<'_, Result<(), IpcError>> {
        Box::pin(async move {
            assert!(
                self.admission_closed,
                "combined MCP/standalone drain starts only after admission closes"
            );
            self.events.push(Event::DrainStarted);
            if matches!(
                self.scenario,
                Scenario::DrainFailure | Scenario::CleanupFailure
            ) {
                self.events.push(Event::DrainFailed);
                return Err(Self::error("v031_migration_recovery_drain_failed"));
            }
            self.drain_completed = true;
            self.events.push(Event::DrainCompleted);
            Ok(())
        })
    }

    fn cleanup_unauthorized_residue(&mut self) -> StageFuture<'_, Result<(), IpcError>> {
        Box::pin(async move {
            assert!(self.admission_closed, "cleanup cannot reopen admission");
            assert!(
                !self.formal_installed,
                "formal authority is never deleted by unauthorized-residue cleanup"
            );
            self.events.push(Event::CleanupStarted);
            if self.scenario == Scenario::CleanupFailure {
                self.events.push(Event::CleanupFailed);
                Err(Self::error("v031_migration_recovery_cleanup_failed"))
            } else {
                self.events.push(Event::CleanupVerified);
                Ok(())
            }
        })
    }

    fn finalize_after_quiescence(&mut self) -> StageFuture<'_, StageFinalizeOutcome> {
        Box::pin(async move {
            assert!(self.admission_closed, "finalize cannot reopen admission");
            assert!(
                self.drain_completed,
                "formal authority is considered only after the combined drain"
            );
            self.events.push(Event::FinalizeStarted);
            self.events.push(Event::ThreeBarriersAcquired);
            match self.scenario {
                Scenario::Success => {
                    self.events.push(Event::FinalReproofPassed);
                    self.formal_installed = true;
                    self.events.push(Event::FormalInstalled);
                    self.events.push(Event::GuardsRetained);
                    StageFinalizeOutcome::FormalInstalled
                }
                Scenario::FinalizeFormalAbsent => {
                    self.events.push(Event::FinalReproofFailed);
                    self.events.push(Event::CleanupStarted);
                    self.events.push(Event::CleanupVerified);
                    StageFinalizeOutcome::FailedFormalAbsent {
                        error: Self::error("v031_migration_recovery_finalize_failed"),
                        cleanup_error: None,
                    }
                }
                Scenario::FinalizeFormalPresent => {
                    self.events.push(Event::FinalReproofPassed);
                    self.formal_installed = true;
                    self.events.push(Event::FormalInstalled);
                    self.events.push(Event::GuardsRetained);
                    self.events.push(Event::FinalizeReportedFailure);
                    StageFinalizeOutcome::FailedFormalPresent {
                        error: Self::error("v031_migration_recovery_finalize_failed"),
                    }
                }
                Scenario::BeginAlreadyOwned | Scenario::DrainFailure | Scenario::CleanupFailure => {
                    panic!("failed pre-finalize scenario reached finalization")
                }
            }
        })
    }

    fn restart_owned_exit_once(&mut self) -> StageFuture<'_, ()> {
        Box::pin(async move {
            assert!(self.admission_closed, "restart cannot reopen admission");
            assert_eq!(self.restart_count, 0, "owned exit restarts exactly once");
            self.restart_count += 1;
            self.events.push(Event::RestartRequested);
        })
    }
}

async fn run(scenario: Scenario) -> (FakeStageRuntime, Result<(), IpcError>) {
    let mut runtime = FakeStageRuntime::new(scenario);
    let result = sequence_v031_recovery_stage(&mut runtime).await;
    (runtime, result)
}

fn assert_error(result: Result<(), IpcError>, expected: &str) {
    assert_eq!(result.expect_err("scenario must fail").error_type, expected);
}

fn assert_formal_follows_drain(events: &[Event]) {
    let drain = events
        .iter()
        .position(|event| *event == Event::DrainCompleted)
        .expect("formal scenarios complete the combined drain");
    let formal = events
        .iter()
        .position(|event| *event == Event::FormalInstalled)
        .expect("formal marker event is present");
    assert!(formal > drain, "formal marker follows the completed drain");
}

#[tokio::test]
async fn r3_public_stage_success_orders_quiescence_before_formal_and_restarts_once() {
    let (runtime, result) = run(Scenario::Success).await;
    result.expect("formal staging succeeds");
    assert_eq!(
        runtime.events,
        vec![
            Event::PrepareCompleted,
            Event::BeginAccepted,
            Event::AdmissionClosed,
            Event::DrainStarted,
            Event::DrainCompleted,
            Event::FinalizeStarted,
            Event::ThreeBarriersAcquired,
            Event::FinalReproofPassed,
            Event::FormalInstalled,
            Event::GuardsRetained,
            Event::RestartRequested,
        ]
    );
    runtime.assert_fail_closed();
    assert_formal_follows_drain(&runtime.events);
    assert!(runtime.formal_installed);
    assert_eq!(runtime.restart_count, 1);
}

#[tokio::test]
async fn r3_public_stage_begin_failure_cleans_residue_and_observes_restart_already_owned() {
    let (runtime, result) = run(Scenario::BeginAlreadyOwned).await;
    assert_error(result, "application_exiting");
    assert_eq!(
        runtime.events,
        vec![
            Event::PrepareCompleted,
            Event::BeginRejected,
            Event::AdmissionClosed,
            Event::CleanupStarted,
            Event::CleanupVerified,
            Event::RestartAlreadyOwned,
        ]
    );
    runtime.assert_fail_closed();
    assert!(!runtime.formal_installed);
    assert_eq!(
        runtime.restart_count, 0,
        "the existing exit owner is not duplicated"
    );
}

#[tokio::test]
async fn r3_public_stage_drain_failure_cleans_residue_and_restarts_once() {
    let (runtime, result) = run(Scenario::DrainFailure).await;
    assert_error(result, "v031_migration_recovery_drain_failed");
    assert_eq!(
        runtime.events,
        vec![
            Event::PrepareCompleted,
            Event::BeginAccepted,
            Event::AdmissionClosed,
            Event::DrainStarted,
            Event::DrainFailed,
            Event::CleanupStarted,
            Event::CleanupVerified,
            Event::RestartRequested,
        ]
    );
    runtime.assert_fail_closed();
    assert!(!runtime.formal_installed);
    assert_eq!(runtime.restart_count, 1);
}

#[tokio::test]
async fn r3_public_stage_finalize_formal_absent_cleans_residue_and_restarts_once() {
    let (runtime, result) = run(Scenario::FinalizeFormalAbsent).await;
    assert_error(result, "v031_migration_recovery_finalize_failed");
    assert_eq!(
        runtime.events,
        vec![
            Event::PrepareCompleted,
            Event::BeginAccepted,
            Event::AdmissionClosed,
            Event::DrainStarted,
            Event::DrainCompleted,
            Event::FinalizeStarted,
            Event::ThreeBarriersAcquired,
            Event::FinalReproofFailed,
            Event::CleanupStarted,
            Event::CleanupVerified,
            Event::RestartRequested,
        ]
    );
    runtime.assert_fail_closed();
    assert!(!runtime.formal_installed);
    assert_eq!(runtime.restart_count, 1);
}

#[tokio::test]
async fn r3_public_stage_finalize_formal_present_retains_guards_and_restarts_once() {
    let (runtime, result) = run(Scenario::FinalizeFormalPresent).await;
    assert_error(result, "v031_migration_recovery_finalize_failed");
    assert_eq!(
        runtime.events,
        vec![
            Event::PrepareCompleted,
            Event::BeginAccepted,
            Event::AdmissionClosed,
            Event::DrainStarted,
            Event::DrainCompleted,
            Event::FinalizeStarted,
            Event::ThreeBarriersAcquired,
            Event::FinalReproofPassed,
            Event::FormalInstalled,
            Event::GuardsRetained,
            Event::FinalizeReportedFailure,
            Event::RestartRequested,
        ]
    );
    runtime.assert_fail_closed();
    assert_formal_follows_drain(&runtime.events);
    assert!(runtime.formal_installed);
    assert!(!runtime.events.contains(&Event::CleanupStarted));
    assert_eq!(runtime.restart_count, 1);
}

#[tokio::test]
async fn r3_public_stage_cleanup_failure_is_dominant_fail_closed_and_restarts_once() {
    let (runtime, result) = run(Scenario::CleanupFailure).await;
    assert_error(result, "v031_migration_recovery_cleanup_failed");
    assert_eq!(
        runtime.events,
        vec![
            Event::PrepareCompleted,
            Event::BeginAccepted,
            Event::AdmissionClosed,
            Event::DrainStarted,
            Event::DrainFailed,
            Event::CleanupStarted,
            Event::CleanupFailed,
            Event::RestartRequested,
        ]
    );
    runtime.assert_fail_closed();
    assert!(!runtime.formal_installed);
    assert_eq!(runtime.restart_count, 1);
}
