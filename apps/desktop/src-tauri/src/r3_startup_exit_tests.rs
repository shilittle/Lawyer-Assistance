use super::*;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    process::Command,
};

const CHILD_MODE_ENV: &str = "LAWYER_ASSISTANCE_R3_STARTUP_EXIT_CHILD";
const CHILD_TRACE_ENV: &str = "LAWYER_ASSISTANCE_R3_STARTUP_EXIT_TRACE";
const CHILD_TEST_PATH: &str =
    "r3_startup_exit_tests::r3_shared_startup_exit_boundary_child_process";

fn append_trace(path: &std::path::Path, event: &str) -> io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{event}")?;
    file.sync_all()
}

struct RecoveryOnlyChildActions {
    trace_path: std::path::PathBuf,
    migration_guard: Option<single_instance::NamedMutexGuard>,
    exit_drain: ExitDrainCoordinator,
}

impl RecoveryOnlyChildActions {
    fn new(trace_path: std::path::PathBuf) -> io::Result<Self> {
        let identifier = format!(
            "com.shilittle.lawyer-assistance.r3-startup-exit-{}",
            std::process::id()
        );
        Ok(Self {
            trace_path,
            migration_guard: Some(single_instance::acquire_migration_guard(&identifier)?),
            exit_drain: ExitDrainCoordinator::default(),
        })
    }

    fn record(&self, event: &str) -> io::Result<()> {
        append_trace(&self.trace_path, event)
    }

    fn forbidden(&self, event: &str) -> io::Error {
        self.record(event)
            .expect("R3 child records a forbidden startup action");
        io::Error::other(format!("recovery-only startup invoked {event}"))
    }
}

impl ExplicitRecoveryExitBoundary for RecoveryOnlyChildActions {
    type Error = io::Error;

    fn apply_authenticated_recovery(&mut self) -> Result<String, Self::Error> {
        self.record("apply:authenticated-recovery")?;
        Ok("0.3.1".to_owned())
    }

    fn release_recovery_migration_guard(&mut self) -> Result<(), Self::Error> {
        let guard = self
            .migration_guard
            .take()
            .ok_or_else(|| io::Error::other("R3 migration guard was released more than once"))?;
        drop(guard);
        self.record("release:migration-guard")
    }

    fn mark_recovery_exit_finalizing(&mut self) {
        self.exit_drain.mark_finalizing();
        self.record("exit-drain:finalizing")
            .expect("R3 child persists the Finalizing event");
    }

    fn exit_recovery_process(&mut self, exit_code: i32) {
        if self.migration_guard.is_some() {
            self.record("invalid:exit-before-guard-release")
                .expect("R3 child persists the invalid guard order");
            std::process::exit(91);
        }
        if !self.exit_drain.is_finalizing() {
            self.record("invalid:exit-before-finalizing")
                .expect("R3 child persists the invalid finalization order");
            std::process::exit(92);
        }
        self.record(&format!("exit:{exit_code}"))
            .expect("R3 child persists the exact exit action");
        std::process::exit(exit_code);
    }
}

impl v031_startup::StartupActions for RecoveryOnlyChildActions {
    type Error = io::Error;

    fn observe_read_only(&mut self) -> Result<v031_startup::StartupObservation, Self::Error> {
        self.record("observe:r3-authenticated")?;
        Ok(v031_startup::StartupObservation {
            restores: v031_startup::RestoreObservation {
                explicit_recovery: v031_startup::AuthenticatedPresence::Authenticated,
                full_application: v031_startup::AuthenticatedPresence::Absent,
                legacy_user_database: v031_startup::AuthenticatedPresence::Absent,
                standalone_privacy: v031_startup::AuthenticatedPresence::Absent,
            },
            upgrade: v031_startup::UpgradeObservation {
                terminal_lineage_count: 0,
                active: None,
            },
            // Without the authenticated R3 presence this exact source would
            // enter the ordinary v0.3.1 upgrade route.  Its suppression proves
            // the production precedence rather than merely testing an empty
            // fallback profile.
            profile: v031_startup::InstalledProfile::ExactV031Source,
            unknown_marker_or_sibling: false,
        })
    }

    fn apply_explicit_recovery_and_exit(&mut self) -> Result<(), Self::Error> {
        apply_authenticated_recovery_and_exit(self)
    }

    fn apply_current_restore(
        &mut self,
        _kind: v031_startup::CurrentRestoreKind,
    ) -> Result<(), Self::Error> {
        Err(self.forbidden("ordinary-restore"))
    }

    fn repair_empty_legacy_bootstrap(&mut self) -> Result<(), Self::Error> {
        Err(self.forbidden("empty-legacy-bootstrap"))
    }

    fn advance_upgrade_through_receipt_eight(
        &mut self,
        _next_ordinal: u8,
    ) -> Result<(), Self::Error> {
        Err(self.forbidden("ordinary-migration"))
    }

    fn run_step_eight_and_install_receipt_nine(&mut self) -> Result<(), Self::Error> {
        Err(self.forbidden("ordinary-migration-step-eight"))
    }

    fn request_controlled_restart(&mut self) -> Result<(), Self::Error> {
        Err(self.forbidden("restart"))
    }

    fn initialize_ordinary_application(&mut self, _fresh: bool) -> Result<(), Self::Error> {
        for event in [
            "ordinary-manager",
            "ordinary-maintenance",
            "ordinary-ui",
            "ordinary-window",
            "ordinary-background",
        ] {
            self.record(event)?;
        }
        Err(io::Error::other(
            "recovery-only startup initialized the ordinary application",
        ))
    }
}

#[test]
fn r3_shared_startup_exit_boundary_child_process() {
    if std::env::var_os(CHILD_MODE_ENV).is_none() {
        return;
    }
    let trace_path = std::path::PathBuf::from(
        std::env::var_os(CHILD_TRACE_ENV).expect("R3 child receives its fixed trace path"),
    );
    let mut actions =
        RecoveryOnlyChildActions::new(trace_path).expect("R3 child acquires its migration guard");
    let returned = v031_startup::execute_startup(&mut actions);
    panic!("recovery-only startup returned instead of exiting: {returned:?}");
}

#[test]
fn r3_shared_startup_exit_boundary_exits_zero_without_ordinary_initialization() {
    let directory = tempfile::tempdir().expect("R3 startup child trace directory");
    let trace_path = directory.path().join("startup-exit.trace");
    let output = Command::new(std::env::current_exe().expect("current Rust test executable"))
        .arg("--exact")
        .arg(CHILD_TEST_PATH)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_MODE_ENV, "1")
        .env(CHILD_TRACE_ENV, &trace_path)
        .output()
        .expect("R3 recovery-only startup child launches");

    assert!(
        output.status.success(),
        "R3 recovery-only startup child did not exit successfully\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.status.code(), Some(0));

    let trace = std::fs::read_to_string(&trace_path).expect("R3 child persisted its event trace");
    let events = trace.lines().collect::<Vec<_>>();
    assert_eq!(
        events,
        [
            "observe:r3-authenticated",
            "apply:authenticated-recovery",
            "release:migration-guard",
            "exit-drain:finalizing",
            "exit:0",
        ]
    );
    assert_eq!(
        events.iter().filter(|event| **event == "exit:0").count(),
        1,
        "the recovery route emits exactly one successful exit"
    );
    for forbidden in [
        "ordinary-restore",
        "ordinary-migration",
        "ordinary-migration-step-eight",
        "restart",
        "ordinary-manager",
        "ordinary-maintenance",
        "ordinary-ui",
        "ordinary-window",
        "ordinary-background",
    ] {
        assert_eq!(
            events.iter().filter(|event| **event == forbidden).count(),
            0,
            "recovery-only startup must not invoke {forbidden}"
        );
    }
}
