use super::*;
use crate::privacy_workflow::{
    test_workspace_instance_id, LifecycleStatusRequest, SetRetentionPolicyRequest,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};
use tempfile::TempDir;

const USER_CANARY_KEY: &str = "privacy_vnext_paired_backup_canary";
const BACKED_UP_USER_CANARY: &str = "SYNTHETIC_USER_DB_BEFORE_BACKUP_4F9C";
const MUTATED_USER_CANARY: &str = "SYNTHETIC_USER_DB_AFTER_BACKUP_A71D";
const R3_SAFETY_WRITER_LOCK_ENV: &str = "LAWYER_ASSISTANCE_R3_SAFETY_WRITER_LOCK";
const R3_SAFETY_WRITER_READY_ENV: &str = "LAWYER_ASSISTANCE_R3_SAFETY_WRITER_READY";
const R3_SAFETY_WRITER_COMMIT_ENV: &str = "LAWYER_ASSISTANCE_R3_SAFETY_WRITER_COMMIT";
fn policy(days: u64) -> SetRetentionPolicyRequest {
    SetRetentionPolicyRequest {
        review_retention_seconds: days * 86_400,
        mapping_retention_seconds: days * 86_400,
        receipt_grace_seconds: 3_600,
        backup_retention_seconds: 7 * 86_400,
    }
}

fn fixture() -> (
    TempDir,
    privacy::vnext::WorkspaceInstanceId,
    AppState,
    PrivacyWorkflowManager,
) {
    let directory = tempfile::tempdir().expect("application data directory");
    let user_database =
        database::ensure_user_database(directory.path()).expect("canonical user database");
    let state = AppState::new(directory.path().join("legal.sqlite"), user_database);
    let workspace = test_workspace_instance_id();
    let workflow = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace.clone())
        .expect("privacy workflow");
    (directory, workspace, state, workflow)
}

fn fixture_v3() -> (
    TempDir,
    privacy::vnext::WorkspaceInstanceId,
    AppState,
    PrivacyWorkflowManager,
    crate::approved_mcp::ApplicationBackupTestHarness,
) {
    let directory = tempfile::tempdir().expect("application data directory");
    let user_database =
        database::ensure_user_database(directory.path()).expect("canonical user database");
    let state = AppState::new(directory.path().join("legal.sqlite"), user_database);
    let approved =
        crate::approved_mcp::ApplicationBackupTestHarness::new(directory.path().to_path_buf());
    let workspace = approved
        .workspace
        .workspace_instance_id()
        .expect("approved workspace identity");
    let workflow = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace.clone())
        .expect("privacy workflow");
    (directory, workspace, state, workflow, approved)
}

#[test]
fn r3_safety_readback_recomputes_and_enforces_component_identity() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let (bytes, metadata, _, identity, _) = build_application_backup_internal(
        directory.path(),
        &state,
        &workflow,
        Some(&approved.workspace),
        false,
        || {},
        || {},
    )
    .expect("build authenticated five-component V3 fixture");
    let identity = identity.expect("five-component identity");
    let path = directory.path().join("r3-safety-reproof.lavbackup");
    write_new_file(&path, &bytes).expect("write fixed Safety fixture");
    let mut proof = V031RecoverySafetyBackupProof {
        backup_id: metadata.backup_id.clone(),
        privacy_backup_id: metadata.privacy_backup_id.clone(),
        workspace_instance_id: metadata.workspace_instance_id.as_str().to_owned(),
        app_version: metadata.app_version.clone(),
        user_schema_version: metadata.user_schema_version,
        created_at_unix: metadata.created_at_unix,
        expires_at_unix: metadata.expires_at_unix,
        bundle_sha256: metadata.bundle_sha256.clone(),
        bundle_bytes: bytes.len() as u64,
        component_identity_sha256: migration_component_fingerprint(&identity.current),
        stage_slot_inventory_sha256: "11".repeat(32),
    };
    verify_v031_recovery_safety_backup_read_only(&path, &proof)
        .expect("bundle-derived component identity matches build identity");

    proof.component_identity_sha256 = "22".repeat(32);
    assert_eq!(
        verify_v031_recovery_safety_backup_read_only(&path, &proof)
            .expect_err("a valid-shaped but mismatched component identity must fail")
            .error_type,
        "migration_backup_component_mismatch"
    );
}

/// Exact child-process endpoint for the production Approved operation lock.
/// A normal test run has no environment binding and returns without touching
/// the filesystem.
#[test]
fn r3_safety_writer_child_process() {
    let Some(lock_path) = std::env::var_os(R3_SAFETY_WRITER_LOCK_ENV) else {
        return;
    };
    let ready_path = std::env::var_os(R3_SAFETY_WRITER_READY_ENV)
        .map(std::path::PathBuf::from)
        .expect("R3 safety writer ready path");
    let commit_path = std::env::var_os(R3_SAFETY_WRITER_COMMIT_ENV)
        .map(std::path::PathBuf::from)
        .expect("R3 safety writer commit path");
    std::fs::write(&ready_path, b"attempting-production-operation-lock")
        .expect("announce cross-process writer attempt");

    use std::os::windows::fs::OpenOptionsExt;
    let started = std::time::Instant::now();
    let _operation = loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&lock_path)
        {
            Ok(file) => break file,
            Err(_) if started.elapsed() < Duration::from_secs(10) => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("cross-process writer could not acquire production lock: {error}"),
        }
    };
    std::fs::write(&commit_path, b"writer-committed-after-safety-reproof")
        .expect("commit cross-process writer sentinel");
}

#[test]
fn r3_safety_holds_cross_process_approved_writer_until_slots_after_reproof() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let case_id = format!("case_{}", "e".repeat(32));
    let generation = approved
        .publish_generation(&case_id, 'e')
        .expect("approved Safety generation");
    approved
        .create_work_product(&generation, b"[PERSON_001] Safety barrier work product")
        .expect("Safety work product");
    approved
        .epochs()
        .expect("all four Safety credentials are present");

    let coordination = tempfile::tempdir().expect("R3 Safety writer coordination directory");
    let ready_path = coordination.path().join("writer-ready");
    let commit_path = directory
        .path()
        .join("privacy/approved-mcp/approved-generations")
        .join("r3-safety-cross-process-writer-sentinel");
    let operation_lock = directory
        .path()
        .join("privacy/approved-mcp/approved-generations")
        .join(".approved-workspace-operation.lock");
    assert!(operation_lock.is_file());

    let mut child = None;
    let ready_for_attempt = ready_path.clone();
    let commit_for_attempt = commit_path.clone();
    let commit_at_reproof = commit_path.clone();
    let slots_after_reproved = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let slots_after_reproved_in_hook = Arc::clone(&slots_after_reproved);
    let build = build_application_backup_internal(
        directory.path(),
        &state,
        &workflow,
        Some(&approved.workspace),
        true,
        || {
            child = Some(
                std::process::Command::new(
                    std::env::current_exe().expect("current desktop test executable"),
                )
                .arg("--exact")
                .arg("commands::application_backup::tests::r3_safety_writer_child_process")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env(R3_SAFETY_WRITER_LOCK_ENV, &operation_lock)
                .env(R3_SAFETY_WRITER_READY_ENV, &ready_for_attempt)
                .env(R3_SAFETY_WRITER_COMMIT_ENV, &commit_for_attempt)
                .spawn()
                .expect("spawn cross-process Approved writer"),
            );
            for _ in 0..300 {
                if ready_for_attempt.is_file() {
                    break;
                }
                assert!(
                    child
                        .as_mut()
                        .expect("writer child")
                        .try_wait()
                        .expect("poll writer child")
                        .is_none(),
                    "writer child exited before attempting the production lock"
                );
                thread::sleep(Duration::from_millis(10));
            }
            assert!(
                ready_for_attempt.is_file(),
                "writer attempt was not observed"
            );
            thread::sleep(Duration::from_millis(150));
            assert!(
                !commit_for_attempt.exists(),
                "cross-process writer committed while the Safety barrier was held"
            );
        },
        || {
            assert!(
                !commit_at_reproof.exists(),
                "cross-process writer committed before slots-after reproof"
            );
            slots_after_reproved_in_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        },
    );

    let status = child
        .as_mut()
        .expect("writer child was spawned")
        .wait()
        .expect("wait for cross-process Approved writer");
    assert!(status.success());
    assert!(
        slots_after_reproved.load(std::sync::atomic::Ordering::SeqCst),
        "production Safety path never reached slots-after reproof"
    );
    assert!(commit_path.is_file(), "writer did not resume after release");
    let (_, _, _, identity, slots) = build.expect("production R3 Safety build succeeds");
    assert!(identity.is_some());
    assert!(slots.is_some());
}

#[test]
fn application_restore_uses_legacy_96_mib_and_current_v6_256_mib_privacy_limits() {
    assert_eq!(
        privacy_database_backup_maximum(5).expect("v5 migration restore limit"),
        privacy::lifecycle::MAX_PRE_MIGRATION_BACKUP_DATABASE_BYTES
    );
    assert_eq!(
        privacy_database_backup_maximum(PRIVACY_STORE_SCHEMA_VERSION)
            .expect("current v6 restore limit"),
        privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES
    );
    assert_eq!(
        privacy_database_backup_maximum(PRIVACY_STORE_SCHEMA_VERSION + 1)
            .expect_err("future schema is rejected")
            .error_type,
        "application_restore_invalid"
    );

    let page_size = 4_096_u64;
    let legacy_pages = u64::try_from(privacy::lifecycle::MAX_PRE_MIGRATION_BACKUP_DATABASE_BYTES)
        .expect("legacy maximum")
        / page_size;
    let current_pages = u64::try_from(privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES)
        .expect("current maximum")
        / page_size;
    validate_privacy_database_page_values(5, legacy_pages, page_size)
        .expect("v5 source at 96 MiB remains valid");
    assert_eq!(
        validate_privacy_database_page_values(5, legacy_pages + 1, page_size)
            .expect_err("v5 source above 96 MiB is blocked before migration")
            .error_type,
        "migration_backup_privacy_source_too_large"
    );
    validate_privacy_database_page_values(
        PRIVACY_STORE_SCHEMA_VERSION,
        legacy_pages + 1,
        page_size,
    )
    .expect("v6 source above the old ceiling remains valid");
    assert_eq!(
        validate_privacy_database_page_values(
            PRIVACY_STORE_SCHEMA_VERSION,
            current_pages + 1,
            page_size,
        )
        .expect_err("v6 source above 256 MiB is blocked")
        .error_type,
        "migration_backup_privacy_source_too_large"
    );
}

#[test]
fn pre_migration_backup_gate_creates_one_fixed_five_component_backup_and_reuses_it() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("semantic migration source fingerprint");
    let first = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect("create fixed pre-migration backup");
    let expected_path = directory
        .path()
        .join(MIGRATION_BACKUP_DIRECTORY_NAME)
        .join(format!(
            "case-material-unification-v1-{source_fingerprint}.lavbackup"
        ));
    assert!(first.created);
    assert_eq!(first.path, expected_path);
    assert_eq!(first.metadata.chunk_count, 5);
    assert!(first.metadata.approved_workspace_bundle_sha256.is_some());
    assert!(first.metadata.work_products_bundle_sha256.is_some());
    assert!(first.path.is_file());
    assert!(migration_backup_identity_path(&first.path)
        .expect("identity path")
        .is_file());

    let second = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect("strictly validate and reuse fixed pre-migration backup");
    assert!(!second.created);
    assert_eq!(second.path, first.path);
    assert_eq!(second.metadata, first.metadata);

    let connection =
        Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE)).expect("privacy DB");
    let active_backups: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM privacy_backup_registry WHERE state='active'",
            [],
            |row| row.get(0),
        )
        .expect("active backup count");
    assert_eq!(active_backups, 1);
}

#[test]
fn pre_migration_backup_gate_never_reuses_a_snapshot_for_changed_source_rows() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let first_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("initial semantic source fingerprint");
    let first = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &first_fingerprint,
    )
    .expect("create first source-bound backup");

    database::upsert_case_project(
        &database::open_user_database(state.user_database_path()).expect("open user database"),
        &database::CaseProjectRow {
            project_id: "case-backup-source-change".to_owned(),
            title: "Changed migration source".to_owned(),
            case_type: "civil".to_owned(),
            status: "active".to_owned(),
            opened_on: None,
            summary: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        },
    )
    .expect("change project source rows");
    let second_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("changed semantic source fingerprint");
    assert_ne!(second_fingerprint, first_fingerprint);

    let second = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &second_fingerprint,
    )
    .expect("create a new backup for changed source rows");

    assert!(first.created);
    assert!(second.created);
    assert_ne!(second.path, first.path);
    assert!(first.path.is_file());
    assert!(second.path.is_file());
}

fn assert_component_drift_creates_new_preserved_backup(
    first: &MigrationApplicationBackup,
    second: &MigrationApplicationBackup,
) {
    assert!(first.created);
    assert!(second.created);
    assert_ne!(first.path, second.path);
    for path in [&first.path, &second.path] {
        assert!(path.is_file());
        assert!(migration_backup_identity_path(path)
            .expect("component identity path")
            .is_file());
    }
}

#[test]
fn pre_migration_backup_rebuilds_without_replacement_for_user_database_component_drift() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source = workflow
        .case_material_migration_source_fingerprint()
        .expect("source fingerprint");
    let first = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("first backup");
    set_user_canary(
        state.user_database_path(),
        "NON_SOURCE_USER_COMPONENT_DRIFT",
    );
    assert_eq!(
        workflow
            .case_material_migration_source_fingerprint()
            .expect("unchanged semantic source"),
        source
    );
    let second = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("new identity-bound backup");
    assert_component_drift_creates_new_preserved_backup(&first, &second);
}

#[test]
fn pre_migration_backup_rebuilds_without_replacement_for_privacy_component_drift() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source = workflow
        .case_material_migration_source_fingerprint()
        .expect("source fingerprint");
    let first = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("first backup");
    workflow
        .set_retention_policy(policy(2))
        .expect("non-migration Privacy change");
    let second = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("new identity-bound backup");
    assert_component_drift_creates_new_preserved_backup(&first, &second);
}

#[test]
fn pre_migration_backup_rebuilds_without_replacement_for_vault_component_drift() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    let source = workflow
        .case_material_migration_source_fingerprint()
        .expect("source fingerprint");
    let first = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("first backup");
    let vault = VaultStore::initialize(
        directory.path().join(VAULT_DIRECTORY_NAME),
        workspace.clone(),
    )
    .expect("open Vault");
    vault
        .create_source_object(
            &privacy::vnext::CaseId::parse(format!("case_{}", "d".repeat(32)))
                .expect("Privacy CaseId"),
            privacy::vault_store::VaultPrivateMetadataInputV1 {
                original_file_name: "vault-drift.txt".to_owned(),
                original_source_path: None,
                original_media_type: "text/plain".to_owned(),
                imported_at_unix: 1_750_000_100,
            },
            b"isolated Vault component drift",
            1_750_000_100,
        )
        .expect("committed Vault object");
    drop(vault);
    let second = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("new identity-bound backup");
    assert_component_drift_creates_new_preserved_backup(&first, &second);
}

#[test]
fn pre_migration_backup_rebuilds_without_replacement_for_approved_component_drift() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source = workflow
        .case_material_migration_source_fingerprint()
        .expect("source fingerprint");
    let first = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("first backup");
    approved
        .publish_generation(&format!("case_{}", "e".repeat(32)), 'e')
        .expect("approved generation drift");
    let second = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("new identity-bound backup");
    assert_component_drift_creates_new_preserved_backup(&first, &second);
}

#[test]
fn pre_migration_backup_rebuilds_without_replacement_for_work_product_component_drift() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let case_id = format!("case_{}", "f".repeat(32));
    let published = approved
        .publish_generation(&case_id, 'f')
        .expect("baseline approved generation");
    let source = workflow
        .case_material_migration_source_fingerprint()
        .expect("source fingerprint");
    let first = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("first backup");
    approved
        .create_work_product(&published, b"[PERSON_001] isolated work-product drift")
        .expect("work-product drift");
    let second = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("new identity-bound backup");
    assert_component_drift_creates_new_preserved_backup(&first, &second);
}

#[test]
fn migration_reuse_authenticates_expired_and_cross_version_rollback_points_without_weakening_normal_open(
) {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    let source = workflow
        .case_material_migration_source_fingerprint()
        .expect("source fingerprint");
    let first = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("first backup");
    let bytes = fs::read(&first.path).expect("backup bytes");
    assert_eq!(
        open_application_backup(
            &bytes,
            &ApplicationBackupOpenContext {
                expected_workspace_instance_id: &workspace,
                expected_app_version: env!("CARGO_PKG_VERSION"),
                expected_user_schema_version: database::USER_SCHEMA_VERSION,
                now_unix: first.metadata.expires_at_unix,
            },
        ),
        Err(privacy::ApplicationBackupError::Expired)
    );
    assert_eq!(
        open_application_backup(
            &bytes,
            &ApplicationBackupOpenContext {
                expected_workspace_instance_id: &workspace,
                expected_app_version: "999.0.0-migration-recovery-test",
                expected_user_schema_version: database::USER_SCHEMA_VERSION,
                now_unix: first.metadata.created_at_unix,
            },
        ),
        Err(privacy::ApplicationBackupError::EnvironmentMismatch)
    );
    let reused = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source,
    )
    .expect("migration-only protected identity authenticates the rollback point");
    assert!(!reused.created);
    assert_eq!(reused.path, first.path);
    let identity_path = migration_backup_identity_path(&first.path).expect("identity path");
    let staged = stage_migration_application_restore_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &first.path,
        &identity_path,
        &bytes,
    )
    .expect("the supported restore command stages the authenticated migration rollback point");
    assert_eq!(staged.bundle_sha256, first.metadata.bundle_sha256);
    drop(workflow);
    drop(state);
    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("the normal pending-restore transaction applies all five migration components");
    assert_no_restore_residue(&application_restore_paths(directory.path()));
}

#[test]
fn pre_migration_backup_gate_fails_closed_for_tamper_and_hardlinks() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("semantic migration source fingerprint");
    let backup = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect("create fixed pre-migration backup");
    let alias = directory.path().join("migration-backup-hardlink-alias");
    fs::hard_link(&backup.path, &alias).expect("create backup hardlink");
    let hardlink_error = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect_err("hardlinked fixed backup must fail closed");
    assert_eq!(hardlink_error.error_type, "migration_backup_unsafe_path");
    fs::remove_file(alias).expect("remove backup hardlink alias");

    let mut bytes = fs::read(&backup.path).expect("read fixed backup");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    fs::write(&backup.path, bytes).expect("tamper fixed backup");
    let tamper_error = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect_err("tampered fixed backup must fail closed");
    assert_eq!(tamper_error.error_type, "migration_backup_tampered");
}

#[test]
fn pre_migration_backup_gate_fails_closed_for_identity_sidecar_tamper() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("semantic migration source fingerprint");
    let backup = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect("create fixed pre-migration backup");
    let identity_path = migration_backup_identity_path(&backup.path).expect("identity path");
    let mut bytes = fs::read(&identity_path).expect("identity bytes");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    fs::write(&identity_path, bytes).expect("tamper identity");
    let error = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect_err("tampered DPAPI identity must fail closed");
    assert_eq!(error.error_type, "migration_backup_identity_tampered");
    assert!(backup.path.is_file());
}

#[test]
fn pre_migration_backup_gate_rejects_path_like_ids_before_creating_a_marker() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("semantic migration source fingerprint");
    let error = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        "../case-material-unification-v1",
        &source_fingerprint,
    )
    .expect_err("path-like migration id must be rejected");
    assert_eq!(error.error_type, "migration_backup_invalid_id");
    assert!(!directory
        .path()
        .join(MIGRATION_BACKUP_DIRECTORY_NAME)
        .exists());

    let fingerprint_error = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        "../not-a-hash",
    )
    .expect_err("path-like source fingerprint must be rejected");
    assert_eq!(
        fingerprint_error.error_type,
        "migration_backup_invalid_source_fingerprint"
    );
    assert!(!directory
        .path()
        .join(MIGRATION_BACKUP_DIRECTORY_NAME)
        .exists());

    let reparse_target = directory.path().join("synthetic-migration-backup-target");
    fs::create_dir(&reparse_target).expect("create reparse target");
    if std::os::windows::fs::symlink_dir(
        &reparse_target,
        directory.path().join(MIGRATION_BACKUP_DIRECTORY_NAME),
    )
    .is_err()
    {
        // Windows runners without Developer Mode cannot create a test reparse point.
        // Production still rejects it through FILE_ATTRIBUTE_REPARSE_POINT.
        return;
    }
    let reparse_error = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect_err("reparse migration backup directory must fail closed");
    assert_eq!(reparse_error.error_type, "migration_backup_unsafe_path");
}

#[test]
fn pre_migration_backup_build_failure_leaves_no_success_or_staging_file() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("semantic migration source fingerprint");
    fs::remove_file(state.user_database_path()).expect("remove synthetic user database");
    ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect_err("backup build without the fixed user database must fail");
    let backup_directory = directory.path().join(MIGRATION_BACKUP_DIRECTORY_NAME);
    assert!(!backup_directory
        .join(format!(
            "case-material-unification-v1-{source_fingerprint}.lavbackup"
        ))
        .exists());
    if backup_directory.exists() {
        assert!(fs::read_dir(&backup_directory)
            .expect("read backup directory")
            .next()
            .is_none());
    }
}

#[test]
fn pre_migration_backup_install_failure_preserves_and_recovers_the_authenticated_pair() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("semantic migration source fingerprint");
    let error = ensure_pre_migration_application_backup_with_install_hook(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
        |_, _| {
            Err(ipc_error(
                "synthetic_migration_backup_install_failure",
                "Synthetic migration backup install failure.",
            ))
        },
    )
    .expect_err("synthetic install failure must propagate");
    assert_eq!(error.error_type, "migration_backup_install_incomplete");
    let backup_directory = directory.path().join(MIGRATION_BACKUP_DIRECTORY_NAME);
    assert!(!backup_directory
        .join(format!(
            "case-material-unification-v1-{source_fingerprint}.lavbackup"
        ))
        .exists());
    let identity_path = backup_directory.join(format!(
        "case-material-unification-v1-{source_fingerprint}.lavbackup.identity.dpapi"
    ));
    assert!(identity_path.is_file());
    assert!(fs::read_dir(&backup_directory)
        .expect("read backup directory")
        .any(|entry| entry
            .expect("staging entry")
            .file_name()
            .to_string_lossy()
            .ends_with(".staged.lavbackup")));

    let connection =
        Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE)).expect("privacy DB");
    let (active, revoked): (i64, i64) = connection
        .query_row(
            "SELECT
               SUM(CASE WHEN state='active' THEN 1 ELSE 0 END),
               SUM(CASE WHEN state='revoked' THEN 1 ELSE 0 END)
             FROM privacy_backup_registry",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("privacy backup states");
    assert_eq!(active, 1);
    assert_eq!(revoked, 0);
    drop(connection);

    let recovered = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect("next startup recovers the exact staged bundle named by the protected identity");
    assert!(!recovered.created);
    assert!(recovered.path.is_file());
    assert!(identity_path.is_file());
}

#[test]
fn pre_migration_backup_cleans_authenticated_precommit_staging_and_revokes_its_registry_row() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("semantic migration source fingerprint");
    let (bytes, metadata, _, built, _) = build_application_backup_internal(
        directory.path(),
        &state,
        &workflow,
        Some(&approved.workspace),
        false,
        || {},
        || {},
    )
    .expect("build interrupted pair");
    let built = built.expect("five-component identity");
    let file_name =
        migration_backup_file_name(CASE_MATERIAL_UNIFICATION_MIGRATION_ID, &source_fingerprint)
            .expect("fixed file name");
    let identity = migration_backup_identity(
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
        &file_name,
        &workflow,
        &metadata,
        &built,
    )
    .expect("protected identity");
    let backup_directory =
        ensure_migration_backup_directory(directory.path()).expect("backup directory");
    let staged_backup = backup_directory.join(format!(
        ".{}-{}-{}.staged.lavbackup",
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        source_fingerprint,
        Uuid::new_v4().simple()
    ));
    let staged_identity = backup_directory.join(format!(
        ".{}-{}-{}.staged.identity.dpapi",
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        source_fingerprint,
        Uuid::new_v4().simple()
    ));
    stage_migration_backup_pair(
        &staged_backup,
        &staged_identity,
        &bytes,
        &identity,
        &workflow,
        &metadata,
    )
    .expect("durable precommit staging");

    let completed = ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
    )
    .expect("restart cleans the orphan and builds one committed pair");
    assert!(completed.created);
    assert!(!staged_backup.exists());
    assert!(!staged_identity.exists());
    let connection =
        Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE)).expect("privacy DB");
    let (active, revoked): (i64, i64) = connection
        .query_row(
            "SELECT
               SUM(CASE WHEN state='active' THEN 1 ELSE 0 END),
               SUM(CASE WHEN state='revoked' THEN 1 ELSE 0 END)
             FROM privacy_backup_registry",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("privacy backup states");
    assert_eq!(active, 1);
    assert_eq!(revoked, 1);
}

#[test]
fn source_change_after_durable_install_preserves_the_old_source_rollback_pair_and_registry() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    let source_fingerprint = workflow
        .case_material_migration_source_fingerprint()
        .expect("semantic migration source fingerprint");
    let user_database = state.user_database_path().to_path_buf();
    let error = ensure_pre_migration_application_backup_with_install_hook(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
        &source_fingerprint,
        |staging, destination| {
            atomic_install_new_migration_backup(staging, destination)?;
            database::upsert_case_project(
                &database::open_user_database(&user_database).map_err(|_| {
                    ipc_error("synthetic_source_change_failed", "open synthetic user DB")
                })?,
                &database::CaseProjectRow {
                    project_id: "case-post-install-source-change".to_owned(),
                    title: "Post-install source change".to_owned(),
                    case_type: "civil".to_owned(),
                    status: "active".to_owned(),
                    opened_on: None,
                    summary: String::new(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )
            .map_err(|_| {
                ipc_error(
                    "synthetic_source_change_failed",
                    "mutate synthetic migration source",
                )
            })
        },
    )
    .expect_err("source drift blocks migration after durable install");
    assert_eq!(error.error_type, "migration_backup_source_changed");
    let old_path = directory
        .path()
        .join(MIGRATION_BACKUP_DIRECTORY_NAME)
        .join(format!(
            "case-material-unification-v1-{source_fingerprint}.lavbackup"
        ));
    assert!(old_path.is_file());
    assert!(migration_backup_identity_path(&old_path)
        .expect("old identity")
        .is_file());
    let connection =
        Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE)).expect("privacy DB");
    let active: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM privacy_backup_registry WHERE state='active'",
            [],
            |row| row.get(0),
        )
        .expect("active rollback registry");
    assert_eq!(active, 1);
}

fn tree_sha256(root: &Path) -> String {
    fn collect(root: &Path, current: &Path, output: &mut Vec<(String, Vec<u8>)>) {
        let mut entries = fs::read_dir(current)
            .expect("read tree")
            .map(|entry| entry.expect("tree entry").path())
            .collect::<Vec<_>>();
        entries.sort();
        for path in entries {
            let metadata = fs::symlink_metadata(&path).expect("tree metadata");
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                collect(root, &path, output);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("relative path")
                    .to_string_lossy()
                    .replace('\\', "/");
                output.push((relative, fs::read(path).expect("tree file")));
            }
        }
    }
    let mut files = Vec::new();
    collect(root, root, &mut files);
    let mut bytes = Vec::new();
    for (relative, value) in files {
        bytes.extend_from_slice(relative.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&value);
    }
    privacy::sha256_hex(&bytes)
}

fn approved_lineage_manifests(workspace: &ApprovedMcpWorkspace) -> (String, String) {
    let snapshot = workspace
        .snapshot_for_application_backup()
        .expect("snapshot approved/work-product lineage");
    (
        snapshot.approved_workspace_manifest_sha256,
        snapshot.work_products_manifest_sha256,
    )
}

fn assert_no_restore_residue(paths: &ApplicationRestorePaths) {
    for path in [
        &paths.marker,
        &paths.user_incoming,
        &paths.user_rollback,
        &paths.privacy_incoming,
        &paths.privacy_rollback,
        &paths.vault_incoming,
        &paths.vault_rollback,
        &paths.approved_incoming,
        &paths.approved_rollback,
        &paths.work_products_incoming,
        &paths.work_products_rollback,
    ] {
        assert!(!path.exists(), "restore transaction residue: {path:?}");
    }
}

fn replace_privacy_store_with_exact_v4(
    path: &Path,
    workspace: &privacy::vnext::WorkspaceInstanceId,
) {
    for candidate in [
        path.to_path_buf(),
        sqlite_sidecar_path(path, "-journal"),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
    ] {
        if candidate.exists() {
            fs::remove_file(&candidate).expect("remove current Privacy fixture");
        }
    }
    let mut connection = Connection::open(path).expect("create exact v4 Privacy fixture");
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE privacy_schema_metadata(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             INSERT INTO privacy_schema_metadata(key,value)
             VALUES('schema_version','4');
             CREATE TABLE privacy_materials(
                material_id TEXT PRIMARY KEY,
                project_id TEXT,
                attachment_id TEXT,
                source_sha256 TEXT NOT NULL,
                source_name_sha256 TEXT NOT NULL,
                media_type TEXT NOT NULL,
                page_count INTEGER,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
             );
             CREATE TABLE privacy_redactions(
                redaction_id TEXT PRIMARY KEY,
                material_id TEXT NOT NULL,
                extraction_sha256 TEXT NOT NULL,
                redacted_content_sha256 TEXT NOT NULL,
                approved_payload_sha256 TEXT,
                policy_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                detector_version TEXT NOT NULL,
                unresolved_high_risk_count INTEGER NOT NULL,
                review_state TEXT NOT NULL,
                protected_review_blob BLOB NOT NULL,
                protection_scheme TEXT NOT NULL,
                reviewed_by_sha256 TEXT,
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                FOREIGN KEY(material_id) REFERENCES privacy_materials(material_id)
             );",
        )
        .expect("exact v4 backing schema");
    PrivacyLifecycle::initialize(&mut connection, workspace.clone(), 1_750_000_000)
        .expect("v4 lifecycle state");
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("flush v4 fixture");
}

#[test]
fn five_component_restore_recovers_exact_v4_privacy_and_v1_vault_then_upgrades_after_backup() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    let privacy_database = directory.path().join(PRIVACY_DATABASE_RELATIVE);
    let vault_root = directory.path().join(VAULT_DIRECTORY_NAME);
    let vault_database = vault_root.join("vault-state.sqlite");
    drop(workflow);
    replace_privacy_store_with_exact_v4(&privacy_database, &workspace);
    let connection = Connection::open(&vault_database).expect("open Vault database");
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             DROP TRIGGER IF EXISTS trg_vault_cleanup_purged_no_update;
             DROP TRIGGER IF EXISTS trg_vault_cleanup_no_delete;
             DROP INDEX IF EXISTS idx_vault_retention_expiry;
             DROP TABLE IF EXISTS vault_cleanup_candidates;
             DROP TABLE IF EXISTS vault_cleanup_journal;
             DROP TABLE IF EXISTS vault_object_retention;
             DROP TABLE IF EXISTS vault_lifecycle_meta;
             UPDATE vault_meta SET schema_version=1 WHERE singleton=1;
             COMMIT;
             PRAGMA wal_checkpoint(TRUNCATE);",
        )
        .expect("downgrade synthetic Vault to exact v1");
    drop(connection);

    let workflow =
        PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
            directory.path().to_path_buf(),
            workspace.clone(),
            Arc::new(approved.workspace.clone()),
        )
        .expect("open exact legacy components without upgrading");
    assert!(workflow.privacy_store_schema_upgrade_required());
    assert!(workflow.vault_startup_write_required());
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build five-component backup containing v4 Privacy and v1 Vault");

    workflow
        .upgrade_privacy_store_schema_after_backup()
        .expect("upgrade active components only after the synthetic backup");
    assert_eq!(
        PrivacyStore::preflight_schema(
            &Connection::open(&privacy_database).expect("open upgraded active Privacy")
        )
        .expect("intermediate active Privacy schema"),
        PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 }
    );
    let active_projection_source_fingerprint = workflow
        .approved_projection_migration_source_fingerprint()
        .expect("active approved-projection source fingerprint");
    ensure_pre_migration_application_backup(
        directory.path(),
        &state,
        &workflow,
        &approved.workspace,
        APPROVED_CASE_PROJECTION_MIGRATION_ID,
        &active_projection_source_fingerprint,
    )
    .expect("install the distinct active approved-projection backup");
    workflow
        .run_approved_projection_migration_after_backup_for_source(
            &active_projection_source_fingerprint,
        )
        .expect("complete the active approved-projection migration");

    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage five components with authenticated legacy Privacy and Vault");
    let paths = application_restore_paths(directory.path());
    drop(workflow);
    drop(state);

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let result = apply_pending_application_restore_with_hook(
            directory.path(),
            &workspace,
            Some(&approved.workspace),
            |point| {
                if point == ApplicationRestoreCommitPoint::PrivacyInstalled {
                    panic!("synthetic process stop after legacy Privacy install");
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            panic!("apply returned before the PrivacyInstalled crash hook: {error:?}");
        }
    }));
    assert!(crashed.is_err());
    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("restart completes the authenticated legacy five-component restore");

    let (_restored, restored_upgrade_required) =
        VaultStore::open_for_application_startup(&paths.vault_active, workspace.clone())
            .expect("read restored v1 Vault");
    assert!(restored_upgrade_required);
    assert_eq!(
        PrivacyStore::preflight_schema(
            &Connection::open(&paths.privacy_active).expect("read restored v4 Privacy")
        )
        .expect("restored Privacy schema"),
        PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 4 }
    );
    assert_no_restore_residue(&paths);

    let restarted_state = AppState::new(
        directory.path().join("legal.sqlite"),
        database::user_database_path(directory.path()),
    );
    let restarted =
        PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
            directory.path().to_path_buf(),
            workspace.clone(),
            Arc::new(approved.workspace.clone()),
        )
        .expect("read-only startup opens restored legacy components");
    assert!(restarted.privacy_store_schema_upgrade_required());
    assert!(restarted.vault_startup_write_required());
    assert_eq!(
        PrivacyStore::preflight_schema(
            &Connection::open(&paths.privacy_active).expect("pre-backup legacy Privacy")
        )
        .expect("pre-backup schema remains legacy"),
        PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 4 }
    );
    assert!(restarted
        .case_material_migration_required()
        .expect("legacy restore requires startup migration"));
    restarted
        .prepare_startup_storage_after_preflight()
        .expect("prepare backed-up legacy sources");
    let source_fingerprint = restarted
        .case_material_migration_source_fingerprint()
        .expect("restored migration source fingerprint");
    for migration_id in [
        PROJECT_PRIVACY_CASE_BINDING_MIGRATION_ID,
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID,
    ] {
        ensure_pre_migration_application_backup(
            directory.path(),
            &restarted_state,
            &restarted,
            &approved.workspace,
            migration_id,
            &source_fingerprint,
        )
        .expect("install a source-bound five-component backup before startup upgrade");
        assert_eq!(
            PrivacyStore::preflight_schema(
                &Connection::open(&paths.privacy_active).expect("backed-up legacy Privacy")
            )
            .expect("backup does not evolve Privacy schema"),
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 4 }
        );
    }
    restarted
        .upgrade_privacy_store_schema_after_backup()
        .expect("post-backup startup upgrades restored Privacy and Vault");
    assert_eq!(
        PrivacyStore::preflight_schema(
            &Connection::open(&paths.privacy_active).expect("post-backup Privacy")
        )
        .expect("post-backup unified Privacy"),
        PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 }
    );
    restarted
        .run_case_material_migration_after_backup_for_source(&source_fingerprint)
        .expect("complete the restored unified case-material migration");
    let projection_source_fingerprint = restarted
        .approved_projection_migration_source_fingerprint()
        .expect("approved-only projection source fingerprint");
    ensure_pre_migration_application_backup(
        directory.path(),
        &restarted_state,
        &restarted,
        &approved.workspace,
        APPROVED_CASE_PROJECTION_MIGRATION_ID,
        &projection_source_fingerprint,
    )
    .expect("install the distinct source-bound approved-projection backup");
    restarted
        .run_approved_projection_migration_after_backup_for_source(&projection_source_fingerprint)
        .expect("complete the approved-only projection migration");
    assert_eq!(
        PrivacyStore::preflight_schema(
            &Connection::open(&paths.privacy_active).expect("post-projection Privacy")
        )
        .expect("post-projection current Privacy"),
        PrivacyStoreSchemaStatus::Current
    );
    assert!(!restarted.privacy_store_schema_upgrade_required());
    let (_vault, vault_upgrade_required) =
        VaultStore::open_for_application_startup(&paths.vault_active, workspace)
            .expect("post-backup Vault");
    assert!(!vault_upgrade_required);
}

#[test]
fn five_component_v3_restores_approved_generations_encrypted_work_products_and_revokes_epochs() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    let case_id = format!("case_{}", "a".repeat(32));
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let backed_up_policy = workflow
        .set_retention_policy(policy(1))
        .expect("backed-up privacy state");
    let first = approved
        .publish_generation(&case_id, '1')
        .expect("first approved generation");
    let first_work_product_id = approved
        .create_work_product(
            &first,
            b"[PERSON_001] approved analysis version one V3_WORK_PRODUCT_CANARY",
        )
        .expect("first encrypted work product");
    let work_product_generation = directory
        .path()
        .join("privacy/approved-mcp/work-products/work-products")
        .join(&case_id)
        .join(&first_work_product_id)
        .join("v00000000000000000001");
    assert!(work_product_generation
        .join("content.envelope.json")
        .is_file());
    assert!(!work_product_generation.join("content.bin").exists());

    let (bundle, metadata, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build five-component backup");
    assert!(metadata.approved_workspace_bundle_sha256.is_some());
    assert!(metadata.work_products_bundle_sha256.is_some());
    assert_eq!(metadata.chunk_count, 5);
    for canary in [
        BACKED_UP_USER_CANARY.as_bytes(),
        b"V3_WORK_PRODUCT_CANARY".as_slice(),
    ] {
        assert!(!bundle.windows(canary.len()).any(|window| window == canary));
    }
    assert_eq!(approved.work_product_count(&case_id).unwrap(), 1);

    set_user_canary(state.user_database_path(), MUTATED_USER_CANARY);
    workflow
        .set_retention_policy(policy(2))
        .expect("mutated privacy state");
    let second = approved
        .publish_generation(&case_id, '2')
        .expect("second approved generation");
    approved
        .create_work_product(&second, b"[PERSON_002] approved analysis version two")
        .expect("second encrypted work product");
    assert_eq!(approved.workspace.list(Some(&case_id)).unwrap().len(), 2);
    assert_eq!(
        approved.committed_work_product_row_count(&case_id).unwrap(),
        2
    );
    assert!(approved.work_product_count(&case_id).is_err());

    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage five components");
    let paths = application_restore_paths(directory.path());
    let protected_marker = fs::read(&paths.marker).expect("protected V3 marker");
    assert!(!protected_marker
        .windows(metadata.backup_id.len())
        .any(|window| window == metadata.backup_id.as_bytes()));
    let epochs_before = approved.epochs().expect("pre-restore epochs");
    drop(workflow);
    drop(state);

    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("commit five-component restore");
    let epochs_after = approved.epochs().expect("post-restore epochs");
    assert_ne!(epochs_after.0, epochs_before.0);
    assert_ne!(epochs_after.1, epochs_before.1);
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        BACKED_UP_USER_CANARY
    );
    let restarted = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace)
        .expect("reopen restored privacy state");
    assert_eq!(
        status(&restarted).retention_policy.revision,
        backed_up_policy.revision
    );
    assert_eq!(approved.workspace.list(Some(&case_id)).unwrap().len(), 1);
    assert_eq!(approved.work_product_count(&case_id).unwrap(), 1);
    assert_no_restore_residue(&paths);
}

#[test]
fn v3_marker_precommit_failure_cleans_all_components_and_unmarked_crash_fails_closed() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    let case_id = format!("case_{}", "b".repeat(32));
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let generation = approved
        .publish_generation(&case_id, '3')
        .expect("approved generation");
    approved
        .create_work_product(&generation, b"[PERSON_003] approved work product")
        .expect("encrypted work product");
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build V3 backup");
    let paths = application_restore_paths(directory.path());
    let epochs_before = approved.epochs().expect("pre-stage epochs");
    let lineage_before = approved_lineage_manifests(&approved.workspace);
    for failure_point in [
        ApplicationRestoreStagePoint::VaultStaging,
        ApplicationRestoreStagePoint::ApprovedAndWorkProductsStaging,
        ApplicationRestoreStagePoint::BeforeProtectedMarker,
    ] {
        let injected = stage_application_restore_bytes_with_hook(
            directory.path(),
            state.user_database_path(),
            &workflow,
            Some(&approved.workspace),
            &bundle,
            |point| {
                if point == failure_point {
                    Err(ipc_error(
                        "synthetic_precommit_stage_failure",
                        "synthetic precommit stage failure",
                    ))
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("every pre-marker stage error must fail without business-state mutation");
        assert_eq!(
            injected.error_type, "synthetic_precommit_stage_failure",
            "failure point: {failure_point:?}"
        );
        assert_no_restore_residue(&paths);
        assert_eq!(
            approved_lineage_manifests(&approved.workspace),
            lineage_before
        );
        assert_eq!(approved.epochs().unwrap(), epochs_before);
        assert_eq!(approved.workspace.list(Some(&case_id)).unwrap().len(), 1);
        assert_eq!(
            approved.committed_work_product_row_count(&case_id).unwrap(),
            1
        );
    }

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let _ = stage_application_restore_bytes_with_hook(
            directory.path(),
            state.user_database_path(),
            &workflow,
            Some(&approved.workspace),
            &bundle,
            |point| {
                if point == ApplicationRestoreStagePoint::BeforeProtectedMarker {
                    panic!("synthetic process stop before protected marker");
                }
                Ok(())
            },
        );
    }));
    assert!(crashed.is_err());
    assert!(!paths.marker.exists());
    for path in [
        &paths.user_incoming,
        &paths.privacy_incoming,
        &paths.vault_incoming,
        &paths.approved_incoming,
        &paths.work_products_incoming,
    ] {
        assert!(path.exists(), "expected crash residue: {path:?}");
    }
    let unmarked = restore_observer_filesystem_snapshot(directory.path());
    let error = apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect_err("startup must not guess that unmarked incoming components are disposable");
    assert_eq!(error.error_type, "application_restore_conflict");
    assert_eq!(
        restore_observer_filesystem_snapshot(directory.path()),
        unmarked,
        "unmarked crash observation cleaned or rewrote unauthenticated residue"
    );
    cleanup_pair_incoming(&paths).expect("explicitly clean the synthetic pre-marker stage crash");
    assert_no_restore_residue(&paths);
    assert_eq!(
        approved_lineage_manifests(&approved.workspace),
        lineage_before
    );
    assert_eq!(approved.epochs().unwrap(), epochs_before);

    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("next slot preflight succeeds after complete cleanup");
    drop(workflow);
    drop(state);
    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("commit retry");
    assert_no_restore_residue(&paths);
}

#[test]
fn v3_failure_after_five_swaps_rolls_back_every_component_without_revoking_epochs() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    let case_id = format!("case_{}", "c".repeat(32));
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let first = approved
        .publish_generation(&case_id, '4')
        .expect("backed generation");
    approved
        .create_work_product(&first, b"[PERSON_004] backed work product")
        .expect("backed work product");
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build V3 backup");

    set_user_canary(state.user_database_path(), MUTATED_USER_CANARY);
    let post_backup_policy = workflow
        .set_retention_policy(policy(3))
        .expect("post-backup privacy state");
    let second = approved
        .publish_generation(&case_id, '5')
        .expect("post-backup generation");
    approved
        .create_work_product(&second, b"[PERSON_005] post-backup work product")
        .expect("post-backup work product");
    let paths = application_restore_paths(directory.path());
    let approved_before = tree_sha256(&paths.approved_active);
    let work_products_before = tree_sha256(&paths.work_products_active);
    let epochs_before = approved.epochs().expect("epochs before failure");
    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage V3");
    drop(workflow);
    drop(state);
    let error = apply_pending_application_restore_with_hook(
        directory.path(),
        &workspace,
        Some(&approved.workspace),
        |point| {
            if point == ApplicationRestoreCommitPoint::WorkProductsInstalled {
                Err(ipc_error(
                    "synthetic_after_five_swaps",
                    "synthetic failure after five swaps",
                ))
            } else {
                Ok(())
            }
        },
    )
    .expect_err("fifth-swap fault must roll back the transaction");
    assert_eq!(error.error_type, "synthetic_after_five_swaps");
    assert_eq!(approved.epochs().unwrap(), epochs_before);
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        MUTATED_USER_CANARY
    );
    let restarted = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace)
        .expect("reopen original privacy state");
    assert_eq!(
        status(&restarted).retention_policy.revision,
        post_backup_policy.revision
    );
    assert_eq!(tree_sha256(&paths.approved_active), approved_before);
    assert_eq!(
        tree_sha256(&paths.work_products_active),
        work_products_before
    );
    assert_eq!(approved.workspace.list(Some(&case_id)).unwrap().len(), 2);
    assert_eq!(
        approved.committed_work_product_row_count(&case_id).unwrap(),
        2
    );
    assert_no_restore_residue(&paths);
}

#[test]
fn v3_crash_after_four_components_finishes_exact_fifth_component_on_restart() {
    let (directory, _workspace, state, workflow, approved) = fixture_v3();
    let case_id = format!("case_{}", "d".repeat(32));
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let generation = approved
        .publish_generation(&case_id, '6')
        .expect("backed generation");
    approved
        .create_work_product(&generation, b"[PERSON_006] backed work product")
        .expect("backed work product");
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build V3 backup");
    set_user_canary(state.user_database_path(), MUTATED_USER_CANARY);
    workflow
        .set_retention_policy(policy(4))
        .expect("mutate privacy state");
    let second = approved
        .publish_generation(&case_id, '7')
        .expect("second generation");
    approved
        .create_work_product(&second, b"[PERSON_007] second work product")
        .expect("second work product");
    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage V3");
    let paths = application_restore_paths(directory.path());
    let PendingApplicationRestoreObservation::Authenticated(prepared) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe prepared V3 gate")
    else {
        panic!("prepared V3 marker must be present");
    };
    assert_eq!(prepared.phase(), PendingApplicationRestorePhase::Prepared);
    drop(workflow);
    drop(state);

    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reached_in_hook = Arc::clone(&reached);
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let result = apply_observed_pending_application_restore_with_hook(
            directory.path(),
            &prepared,
            Some(&approved.workspace),
            |point| {
                if point == ApplicationRestoreCommitPoint::ApprovedWorkspaceInstalled {
                    reached_in_hook.store(true, std::sync::atomic::Ordering::SeqCst);
                    panic!("synthetic process stop after four installed components");
                }
                Ok(())
            },
        );
        if let Err(error) = result {
            panic!("apply failed before the four-component crash point: {error:?}");
        }
    }));
    assert!(crashed.is_err(), "the four-component hook must stop apply");
    assert!(reached.load(std::sync::atomic::Ordering::SeqCst));
    assert!(paths.work_products_incoming.exists());
    assert!(!paths.work_products_rollback.exists());

    let PendingApplicationRestoreObservation::Authenticated(resume_gate) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe the four-component crash phase")
    else {
        panic!("the V3 marker must remain after the synthetic process stop");
    };
    assert_eq!(
        resume_gate.phase(),
        PendingApplicationRestorePhase::ApprovedWorkspaceInstalled
    );
    apply_observed_pending_application_restore_with_hook(
        directory.path(),
        &resume_gate,
        Some(&approved.workspace),
        |_| Ok(()),
    )
    .expect("restart completes the exact fifth component");
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        BACKED_UP_USER_CANARY
    );
    assert_eq!(approved.workspace.list(Some(&case_id)).unwrap().len(), 1);
    assert_eq!(approved.work_product_count(&case_id).unwrap(), 1);
    assert_no_restore_residue(&paths);
}

#[test]
fn v3_tampered_or_missing_case_store_dependency_fails_closed_and_preserves_active_state() {
    for remove_work_products in [false, true] {
        let (directory, workspace, state, workflow, approved) = fixture_v3();
        let case_id = format!(
            "case_{}",
            (if remove_work_products { "e" } else { "f" }).repeat(32)
        );
        set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
        let first = approved
            .publish_generation(&case_id, '8')
            .expect("backed generation");
        approved
            .create_work_product(&first, b"[PERSON_008] backed work product")
            .expect("backed work product");
        let (bundle, _, _) =
            build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
                .expect("build V3 backup");
        set_user_canary(state.user_database_path(), MUTATED_USER_CANARY);
        let second = approved
            .publish_generation(&case_id, '9')
            .expect("post-backup generation");
        approved
            .create_work_product(&second, b"[PERSON_009] post-backup work product")
            .expect("post-backup work product");
        stage_application_restore_bytes_with_approved(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &approved.workspace,
            &bundle,
        )
        .expect("stage V3");
        let paths = application_restore_paths(directory.path());
        if remove_work_products {
            remove_restore_directory(&paths.work_products_incoming)
                .expect("remove required incoming work products");
        } else {
            let database = paths.approved_incoming.join("workspace-state.sqlite");
            let mut bytes = fs::read(&database).expect("approved database");
            let offset = bytes.len() / 2;
            bytes[offset] ^= 0x40;
            fs::write(database, bytes).expect("tamper approved database");
        }
        drop(workflow);
        drop(state);
        let tampered = restore_observer_filesystem_snapshot(directory.path());
        apply_pending_application_restore_with_approved(
            directory.path(),
            &workspace,
            &approved.workspace,
        )
        .expect_err("tampered or missing case store must fail closed");
        assert_eq!(
            restore_observer_filesystem_snapshot(directory.path()),
            tampered,
            "tampered or missing V3 dependency was cleaned before explicit recovery"
        );
        assert_eq!(
            user_canary(&database::user_database_path(directory.path())),
            MUTATED_USER_CANARY
        );
        assert_eq!(approved.workspace.list(Some(&case_id)).unwrap().len(), 2);
        assert_eq!(
            approved.committed_work_product_row_count(&case_id).unwrap(),
            2
        );
        cleanup_pair_incoming(&paths).expect("explicitly clean the rejected V3 test fixture");
        assert_no_restore_residue(&paths);
    }
}

fn set_user_canary(path: &Path, value: &str) {
    let connection =
        database::open_existing_user_database(path).expect("open existing user database");

    connection
        .execute(
            "INSERT INTO user_database_metadata (key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
            (USER_CANARY_KEY, value),
        )
        .expect("write synthetic user database canary");
}

fn case_work_test_provider_snapshot_json() -> String {
    serde_json::to_string(&serde_json::json!({
        "kind": "deep_seek",
        "modelId": "test-model",
        "baseUrl": "https://api.example.invalid/v1",
        "capabilities": {
            "chat": true,
            "streaming": true,
            "customModelId": true,
            "customBaseUrl": true,
            "reasoning": true,
        },
        "options": {
            "thinking": false,
            "enableThinking": null,
            "thinkingBudget": null,
            "reasoningEffort": null,
            "endpointId": null,
            "workspaceId": null,
            "allowPrivateNetwork": false,
        },
    }))
    .expect("serialize no-credential provider snapshot")
}

fn install_case_assistant_pending_output(path: &Path, suffix: &str) {
    let connection = database::open_user_database(path).expect("open user database");
    let project_id = format!("case-pending-{suffix}");
    let conversation_id = format!("case-pending-conversation-{suffix}");
    let user_message_id = format!("case-pending-user-{suffix}");
    let assistant_message_id = format!("case-pending-assistant-{suffix}");
    let run_id = format!("case-pending-run-{suffix}");
    let tool_call_id = format!("case-pending-tool-{suffix}");
    let generation_id = format!("generation-{suffix}");
    let source_snapshots_json = serde_json::to_string(&serde_json::json!([{
        "approvedPayloadSha256": "c".repeat(64),
        "extractionSha256": "d".repeat(64),
        "generationId": generation_id,
        "generationNumber": 1,
        "generationRowVersion": 1,
        "materialId": format!("material-{suffix}"),
        "ordinal": 0,
        "redactedContentSha256": "e".repeat(64),
        "riskRevision": 1,
        "riskRevisionHash": "f".repeat(64),
        "selectionId": format!("selection-{suffix}"),
        "selectionRowVersion": 1
    }]))
    .expect("serialize pending source lineage");
    let source_snapshots_sha256 = sha256_hex(source_snapshots_json.as_bytes());
    let output_payload_json = serde_json::to_string(&serde_json::json!({
        "content": {},
        "outputKind": "case_document",
        "schemaVersion": 1
    }))
    .expect("serialize pending output");
    let output_sha256 = sha256_hex(output_payload_json.as_bytes());
    let provider_snapshot_json = case_work_test_provider_snapshot_json();
    let provider_snapshot = serde_json::from_str::<serde_json::Value>(&provider_snapshot_json)
        .expect("parse provider snapshot");
    database::upsert_case_project(
        &connection,
        &database::CaseProjectRow {
            project_id: project_id.clone(),
            title: "Pending lineage project".to_owned(),
            case_type: "civil".to_owned(),
            status: "active".to_owned(),
            opened_on: None,
            summary: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        },
    )
    .expect("create pending lineage project");
    database::create_case_work_conversation(
        &connection,
        &conversation_id,
        &project_id,
        "Pending lineage conversation",
    )
    .expect("create pending lineage conversation");
    database::create_message(
        &connection,
        &database::NewMessageRow {
            message_id: user_message_id.clone(),
            conversation_id: conversation_id.clone(),
            role: "user".to_owned(),
            kind: "text".to_owned(),
            text_summary: "Question".to_owned(),
            artifact_id: None,
            run_id: None,
        },
    )
    .expect("create pending lineage user message");
    database::create_agent_run(
        &connection,
        &database::NewAgentRunRow {
            run_id: run_id.clone(),
            conversation_id: conversation_id.clone(),
            user_message_id,
            provider_id: None,
            provider_snapshot_json: provider_snapshot_json.clone(),
            intent: "interactive_case_work".to_owned(),
            status: "queued".to_owned(),
            budget_json: "{}".to_owned(),
        },
    )
    .expect("create pending lineage run");
    database::create_tool_call(
        &connection,
        &database::NewToolCallRow {
            tool_call_id: tool_call_id.clone(),
            run_id: run_id.clone(),
            ordinal: 0,
            capability_name: "assistant.case_work".to_owned(),
            status: "running".to_owned(),
            access_mode: "write".to_owned(),
            requires_confirmation: false,
            input_audit_json: serde_json::to_string(&serde_json::json!({
                "requestId": run_id,
                "runId": run_id,
                "capability": "assistant.case_work",
                "classification": "case_redacted_approved",
                "inputIds": {
                    "projectId": project_id,
                    "conversationId": conversation_id,
                    "redactionGenerationIds": [generation_id],
                },
                "inputHashes": {
                    "promptSha256": "1".repeat(64),
                    "historySha256": "2".repeat(64),
                    "minimalContextSha256": "3".repeat(64),
                    "generationSetSha256": "4".repeat(64),
                    "workspaceDigest": "b".repeat(64),
                },
                "inputCounts": {
                    "promptBytes": 1,
                    "historyMessages": 0,
                    "historyBytes": 0,
                    "generationCount": 1,
                    "knownBodyBytes": 1,
                },
                "providerSnapshot": provider_snapshot,
                "confirmation": {
                    "writebackRequired": true,
                    "received": false,
                },
                "status": "running",
            }))
            .expect("serialize pending input audit"),
            output_audit_json: "{}".to_owned(),
            source_audit_json: "{}".to_owned(),
        },
    )
    .expect("create pending lineage tool audit");
    database::create_message(
        &connection,
        &database::NewMessageRow {
            message_id: assistant_message_id.clone(),
            conversation_id: conversation_id.clone(),
            role: "assistant".to_owned(),
            kind: "text".to_owned(),
            text_summary: "Pending output".to_owned(),
            artifact_id: None,
            run_id: Some(run_id.clone()),
        },
    )
    .expect("create pending lineage assistant message");
    assert!(matches!(
        database::compare_and_set_tool_call_status(
            &connection,
            &tool_call_id,
            "running",
            "succeeded",
            &serde_json::to_string(&serde_json::json!({
                "outputIds": {"pendingOutputKind": "case_document"},
                "outputHashes": {
                    "providerOutputSha256": "5".repeat(64),
                    "typedOutputSha256": output_sha256,
                    "approvedEnvelopeSha256": "6".repeat(64),
                    "proposalSourceRefsSha256": sha256_hex(b"[]"),
                },
                "outputCounts": {
                    "approvedEnvelopeBytes": 1,
                    "bytes": 1,
                    "items": 1,
                },
                "status": "succeeded",
                "confirmation": {
                    "writebackRequired": true,
                    "received": false,
                },
            }))
            .expect("serialize pending output audit"),
            &serde_json::to_string(&serde_json::json!({
                "classification": "case_redacted_approved",
                "sourceRefs": [generation_id],
                "inputHashes": {
                    "projectBindingSha256": "a".repeat(64),
                    "sourceSnapshotsSha256": source_snapshots_sha256,
                    "aggregateSourceSha256": "7".repeat(64),
                    "aggregateExtractionSha256": "8".repeat(64),
                    "aggregateRedactedContentSha256": "9".repeat(64),
                },
                "providerSnapshot": provider_snapshot,
                "confirmation": {
                    "writebackRequired": true,
                    "received": false,
                },
            }))
            .expect("serialize pending source audit"),
            None,
        )
        .expect("complete pending lineage tool audit"),
        database::ToolCallStatusUpdateResult::Updated(_)
    ));
    assert!(matches!(
        database::compare_and_set_agent_run_status(
            &connection,
            &run_id,
            "queued",
            "succeeded",
            Some(&assistant_message_id),
            None,
        )
        .expect("complete pending lineage run"),
        database::AgentRunStatusUpdateResult::Updated(_)
    ));
    database::create_case_assistant_pending_output(
        &connection,
        &database::NewCaseAssistantPendingOutputRow {
            pending_output_id: format!("case-pending-output-{suffix}"),
            project_id,
            conversation_id,
            run_id,
            assistant_message_id,
            project_binding_sha256: "a".repeat(64),
            source_snapshots_sha256,
            source_snapshots_json,
            expected_proposal_source_refs_json: "[]".to_owned(),
            expected_proposal_source_refs_sha256: sha256_hex(b"[]"),
            output_kind: "case_document".to_owned(),
            output_sha256,
            output_payload_json,
            output_preview: "Pending output".to_owned(),
            output_version: 1,
            workspace_base_digest: "b".repeat(64),
        },
    )
    .expect("create independent pending-output lineage");
}

fn user_write_is_busy(path: &Path, value: &str) -> bool {
    let connection =
        database::open_existing_user_database(path).expect("open existing user database");
    connection
        .busy_timeout(Duration::ZERO)
        .expect("disable waiting for the lock probe");
    match connection.execute(
        "INSERT INTO user_database_metadata (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        (USER_CANARY_KEY, value),
    ) {
        Ok(_) => false,
        Err(rusqlite::Error::SqliteFailure(failure, _))
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            true
        }
        Err(error) => panic!("unexpected user-database write result: {error}"),
    }
}

fn user_canary(path: &Path) -> String {
    let connection =
        database::open_user_database_read_only(path).expect("open user database read only");
    connection
        .query_row(
            "SELECT value FROM user_database_metadata WHERE key = ?1",
            [USER_CANARY_KEY],
            |row| row.get(0),
        )
        .expect("read synthetic user database canary")
}

fn user_source_identity(path: &Path) -> (Vec<u8>, i64, String) {
    let bytes = fs::read(path).expect("read exact user database bytes");
    let connection =
        database::open_user_database_read_only(path).expect("open user source read-only");
    let schema_version = connection
        .query_row(
            "SELECT value FROM user_database_metadata WHERE key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("user schema version")
        .parse::<i64>()
        .expect("numeric user schema version");
    let manifest = logical_database_manifest(&connection, &BTreeSet::new())
        .expect("logical user database manifest");
    (bytes, schema_version, manifest)
}

fn status(workflow: &PrivacyWorkflowManager) -> crate::privacy_workflow::LifecycleStatusView {
    workflow
        .lifecycle_status(LifecycleStatusRequest { redaction_id: None })
        .expect("lifecycle status")
}

#[test]
fn coherent_user_snapshot_is_query_only_and_preserves_source_bytes_schema_and_manifest() {
    let (directory, _, state, workflow) = fixture();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let before = user_source_identity(state.user_database_path());
    let _privacy_guard = workflow.begin_application_backup_pair();
    let (connection, mut source_file) =
        open_coherent_user_snapshot(directory.path(), state.user_database_path())
            .expect("open pinned read-only user snapshot");
    assert_eq!(
        connection
            .query_row("PRAGMA query_only", [], |row| row.get::<_, i64>(0))
            .expect("query-only state"),
        1
    );
    let update_error = connection
        .execute(
            "UPDATE user_database_metadata SET value='forbidden'
             WHERE key=?1",
            [USER_CANARY_KEY],
        )
        .expect_err("the migration source snapshot must not have UPDATE authority");
    assert!(matches!(
        update_error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ReadOnly
    ));
    let snapshot = snapshot_user_database(
        directory.path(),
        state.user_database_path(),
        &mut source_file,
    )
    .expect("read exact pinned source bytes");
    assert_eq!(snapshot.as_slice(), before.0.as_slice());
    rollback_user_snapshot(&connection).expect("close read-only source snapshot");
    drop(connection);
    drop(source_file);
    drop(_privacy_guard);

    let after = user_source_identity(state.user_database_path());
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert_eq!(after.2, before.2);
    database::validate_user_database_read_only(state.user_database_path())
        .expect("source schema remains canonical");
}

#[test]
fn paired_backup_restores_both_databases_after_interruption_without_plaintext() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let backed_up_policy = workflow
        .set_retention_policy(policy(1))
        .expect("set backed-up privacy state");

    let (bundle, metadata, _) =
        build_application_backup(directory.path(), &state, &workflow).expect("build paired backup");
    assert!(!bundle
        .windows(BACKED_UP_USER_CANARY.len())
        .any(|window| window == BACKED_UP_USER_CANARY.as_bytes()));
    assert!(!bundle.starts_with(b"SQLite format 3"));

    set_user_canary(state.user_database_path(), MUTATED_USER_CANARY);
    workflow
        .set_retention_policy(policy(2))
        .expect("mutate privacy state after backup");
    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage authenticated pair");
    let paths = application_restore_paths(directory.path());
    let protected_marker = fs::read(&paths.marker).expect("protected pair marker");
    assert!(!protected_marker
        .windows(metadata.backup_id.len())
        .any(|window| window == metadata.backup_id.as_bytes()));

    // Model a process stop after the user component swap and before the
    // privacy component swap. Startup must finish the exact authenticated pair.
    fs::rename(&paths.user_active, &paths.user_rollback).expect("save current user database");
    fs::rename(&paths.user_incoming, &paths.user_active).expect("install backed-up user database");
    drop(workflow);
    drop(state);

    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("startup completes interrupted paired restore");
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        BACKED_UP_USER_CANARY
    );
    let restarted =
        PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace).expect("restart");
    assert_eq!(
        status(&restarted).retention_policy.revision,
        backed_up_policy.revision
    );
    for path in [
        paths.marker,
        paths.user_incoming,
        paths.user_rollback,
        paths.privacy_incoming,
        paths.privacy_rollback,
        paths.vault_incoming,
        paths.vault_rollback,
    ] {
        assert!(!path.exists(), "restore transaction residue: {path:?}");
    }
}

#[test]
fn identical_three_component_restore_consumes_every_staged_component() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
        .expect("build identical-state backup");

    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage identical three-component backup");
    let paths = application_restore_paths(directory.path());
    drop(workflow);
    drop(state);

    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("identical restore is committed and cleaned");
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        BACKED_UP_USER_CANARY
    );
    for path in [
        paths.marker,
        paths.user_incoming,
        paths.user_rollback,
        paths.privacy_incoming,
        paths.privacy_rollback,
        paths.vault_incoming,
        paths.vault_rollback,
    ] {
        assert!(!path.exists(), "identical restore residue: {path:?}");
    }
    PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace)
        .expect("all restored components reopen after identical restore");
}

#[test]
fn three_component_restore_refuses_unified_or_approved_workspace_lineage_without_staging() {
    {
        let (directory, _, state, workflow, approved) = fixture_v3();
        set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
        let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
            .expect("build legacy three-component backup");
        let connection = Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE))
            .expect("open unified Privacy store");
        connection
            .execute(
                "INSERT INTO privacy_materials(
                     material_id,source_kind,extraction_status,migration_status,state
                 ) VALUES(
                     'mat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     'legacy_reference','legacy_reference','legacy_reference','blocked'
                 )",
                [],
            )
            .expect("install unified material state");
        drop(connection);

        let error = stage_application_restore_bytes_with_approved(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &approved.workspace,
            &bundle,
        )
        .expect_err("legacy restore must not fork unified material lineage");
        assert_eq!(
            error.error_type,
            "application_restore_requires_five_components"
        );
        assert_eq!(
            user_canary(state.user_database_path()),
            BACKED_UP_USER_CANARY
        );
        let material_count: i64 =
            Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE))
                .expect("reopen unified Privacy store")
                .query_row("SELECT COUNT(*) FROM privacy_materials", [], |row| {
                    row.get(0)
                })
                .expect("unified material count");
        assert_eq!(material_count, 1);
        assert_no_restore_residue(&application_restore_paths(directory.path()));
    }

    {
        let (directory, _, state, workflow, approved) = fixture_v3();
        set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
        let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
            .expect("build legacy three-component backup");
        let case_id = format!("case_{}", "9".repeat(32));
        let generation = approved
            .publish_generation(&case_id, '9')
            .expect("install current approved-generation lineage");
        approved
            .create_work_product(&generation, b"[PERSON_009] current protected work product")
            .expect("install current work-product lineage");
        let paths = application_restore_paths(directory.path());
        let epochs_before = approved.epochs().expect("current credential epochs");
        let lineage_before = approved_lineage_manifests(&approved.workspace);

        let error = stage_application_restore_bytes_with_approved(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &approved.workspace,
            &bundle,
        )
        .expect_err("legacy restore must not fork approved/work-product lineage");
        assert_eq!(
            error.error_type,
            "application_restore_requires_five_components"
        );
        assert_eq!(
            approved_lineage_manifests(&approved.workspace),
            lineage_before
        );
        assert_eq!(approved.epochs().unwrap(), epochs_before);
        assert_eq!(approved.workspace.list(Some(&case_id)).unwrap().len(), 1);
        assert_eq!(
            approved.committed_work_product_row_count(&case_id).unwrap(),
            1
        );
        assert_no_restore_residue(&paths);
    }
}

#[test]
fn three_component_restore_refuses_project_deletion_journal_lineage_without_staging() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
        .expect("build legacy three-component backup");
    let scope_json = concat!(
        "{\"schemaVersion\":\"project-deletion-journal-v1\",",
        "\"projectId\":\"case-retired-lineage\",",
        "\"privacyCaseId\":null,",
        "\"materialIds\":[],\"generationIds\":[]}"
    );
    let scope_sha256 = sha256_hex(scope_json.as_bytes());
    let connection = Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE))
        .expect("open unified Privacy store");
    connection
        .execute(
            "INSERT INTO project_deletion_journal(
                 deletion_id,project_id,privacy_case_id,scope_json,scope_sha256,state,
                 created_at_unix,privacy_revoked_at_unix,user_deleted_at_unix,completed_at_unix
             ) VALUES(
                 'pdel_retired_lineage','case-retired-lineage',NULL,?1,?2,'completed',
                 1700000000,1700000000,1700000000,1700000000
             )",
            rusqlite::params![scope_json, scope_sha256],
        )
        .expect("install completed project-deletion lineage");
    drop(connection);

    let error = stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect_err("legacy restore must not fork project-deletion lineage");
    assert_eq!(
        error.error_type,
        "application_restore_requires_five_components"
    );
    assert_eq!(
        user_canary(state.user_database_path()),
        BACKED_UP_USER_CANARY
    );
    let deletion_count: i64 = Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE))
        .expect("reopen unified Privacy store")
        .query_row("SELECT COUNT(*) FROM project_deletion_journal", [], |row| {
            row.get(0)
        })
        .expect("project deletion lineage count");
    assert_eq!(deletion_count, 1);
    assert_no_restore_residue(&application_restore_paths(directory.path()));
}

#[test]
fn three_component_restore_refuses_case_assistant_pending_output_lineage() {
    let (directory, _, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
        .expect("build legacy three-component backup");
    install_case_assistant_pending_output(state.user_database_path(), "before-stage");

    let error = stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect_err("legacy restore must not discard pending-output lineage");
    assert_eq!(
        error.error_type,
        "application_restore_requires_five_components"
    );
    let connection =
        database::open_user_database(state.user_database_path()).expect("reopen user database");
    assert_eq!(
        database::list_case_assistant_pending_outputs(
            &connection,
            "case-pending-before-stage",
            "case-pending-conversation-before-stage",
            10,
        )
        .expect("list preserved pending outputs")
        .len(),
        1
    );
    assert_no_restore_residue(&application_restore_paths(directory.path()));
}

#[test]
fn pending_three_component_restore_rechecks_case_assistant_pending_output_lineage() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
        .expect("build legacy three-component backup");
    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage while pending-output lineage is empty");
    let paths = application_restore_paths(directory.path());
    install_case_assistant_pending_output(state.user_database_path(), "before-install");
    drop(workflow);
    drop(state);

    let error = apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect_err("startup must recheck pending-output lineage before the first swap");
    assert_eq!(
        error.error_type,
        "application_restore_requires_five_components"
    );
    let connection = database::open_user_database(database::user_database_path(directory.path()))
        .expect("reopen current user database");
    assert_eq!(
        database::list_case_assistant_pending_outputs(
            &connection,
            "case-pending-before-install",
            "case-pending-conversation-before-install",
            10,
        )
        .expect("list preserved pending outputs")
        .len(),
        1
    );
    assert!(paths.marker.exists());
    assert!(paths.user_incoming.exists());
    assert!(!paths.user_rollback.exists());
    cleanup_pair_incoming(&paths).expect("clean refused synthetic restore transaction");
    assert_no_restore_residue(&paths);
}

#[test]
fn pending_three_component_restore_rechecks_lineage_before_any_component_swap() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
        .expect("build legacy three-component backup");
    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage while the current lineage is empty");
    let paths = application_restore_paths(directory.path());
    assert!(paths.marker.exists());

    set_user_canary(state.user_database_path(), MUTATED_USER_CANARY);
    Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE))
        .expect("open current Privacy store")
        .execute(
            "INSERT INTO privacy_materials(
                 material_id,source_kind,extraction_status,migration_status,state
             ) VALUES(
                 'mat_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                 'legacy_reference','legacy_reference','legacy_reference','blocked'
             )",
            [],
        )
        .expect("create unified state after staging");
    drop(workflow);
    drop(state);

    let error = apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect_err("startup must recheck current lineage before the first swap");
    assert_eq!(
        error.error_type,
        "application_restore_requires_five_components"
    );
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        MUTATED_USER_CANARY
    );
    let material_count: i64 = Connection::open(directory.path().join(PRIVACY_DATABASE_RELATIVE))
        .expect("reopen current Privacy store")
        .query_row("SELECT COUNT(*) FROM privacy_materials", [], |row| {
            row.get(0)
        })
        .expect("current unified material count");
    assert_eq!(material_count, 1);
    assert!(paths.marker.exists());
    assert!(paths.user_incoming.exists());
    assert!(!paths.user_rollback.exists());
    assert!(!paths.privacy_rollback.exists());
    assert!(!paths.vault_rollback.exists());
    cleanup_pair_incoming(&paths).expect("clean refused synthetic restore transaction");
    assert_no_restore_residue(&paths);
}

#[test]
fn coherent_backup_holds_both_database_write_boundaries_until_both_snapshots_finish() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let backed_up_policy = workflow
        .set_retention_policy(policy(1))
        .expect("set backed-up privacy state");

    let backup_directory = directory.path().to_path_buf();
    let backup_state = state.clone();
    let backup_workflow = workflow.clone();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let backup_thread = thread::spawn(move || {
        build_application_backup_with_lock_hook(
            &backup_directory,
            &backup_state,
            &backup_workflow,
            || {
                locked_tx.send(()).expect("signal both locks");
                release_rx.recv().expect("release both locks");
            },
        )
    });
    locked_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("backup acquired both database boundaries");

    let user_path = state.user_database_path().to_path_buf();
    let (user_blocked_tx, user_blocked_rx) = mpsc::channel();
    let (user_retry_tx, user_retry_rx) = mpsc::channel();
    let (user_done_tx, user_done_rx) = mpsc::channel();
    let user_writer = thread::spawn(move || {
        assert!(user_write_is_busy(&user_path, MUTATED_USER_CANARY));
        user_blocked_tx
            .send(())
            .expect("signal blocked user writer");
        user_retry_rx
            .recv()
            .expect("retry user writer after backup");
        set_user_canary(&user_path, MUTATED_USER_CANARY);
        user_done_tx.send(()).expect("signal user writer");
    });
    let privacy_writer_workflow = workflow.clone();
    let (privacy_done_tx, privacy_done_rx) = mpsc::channel();
    let privacy_writer = thread::spawn(move || {
        privacy_writer_workflow
            .set_retention_policy(policy(2))
            .expect("mutate privacy policy");
        privacy_done_tx.send(()).expect("signal privacy writer");
    });

    user_blocked_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("user write is rejected while the coherent boundary is held");
    assert!(user_done_rx
        .recv_timeout(Duration::from_millis(200))
        .is_err());
    assert!(privacy_done_rx
        .recv_timeout(Duration::from_millis(200))
        .is_err());
    release_tx.send(()).expect("release coherent backup");
    let (bundle, _, _) = backup_thread
        .join()
        .expect("backup thread joins")
        .expect("coherent backup succeeds");
    user_retry_tx
        .send(())
        .expect("retry user writer after coherent backup");
    user_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("user writer completes only after coherent backup");
    user_writer.join().expect("user writer joins");
    privacy_writer.join().expect("privacy writer joins");
    assert_eq!(user_canary(state.user_database_path()), MUTATED_USER_CANARY);
    assert_eq!(status(&workflow).retention_policy.revision, 3);

    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage coherent pair");
    drop(workflow);
    drop(state);
    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("restore coherent pair");
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        BACKED_UP_USER_CANARY
    );
    let restarted = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace)
        .expect("restart after coherent restore");
    assert_eq!(
        status(&restarted).retention_policy.revision,
        backed_up_policy.revision
    );
}

#[test]
fn application_backup_snapshot_cleanup_is_exact_and_rejects_hardlinks() {
    let directory = tempfile::tempdir().expect("application data directory");
    assert!(is_application_backup_snapshot_name(
        ".application-backup-user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sqlite"
    ));
    assert!(is_application_backup_snapshot_name(
        ".application-backup-user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sqlite-wal"
    ));
    assert!(!is_application_backup_snapshot_name(
        ".application-backup-user-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.sqlite"
    ));
    assert!(!is_application_backup_snapshot_name(
        ".application-backup-user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sqlite.exe"
    ));

    let exact = directory
        .path()
        .join(".application-backup-user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.sqlite");
    let unknown = directory.path().join("unrelated.sqlite");
    fs::write(&exact, b"synthetic sensitive residual").expect("write exact residual");
    fs::write(&unknown, b"synthetic unrelated file").expect("write unrelated file");
    cleanup_stale_application_backup_snapshots(directory.path()).expect("clean exact residual");
    assert!(!exact.exists());
    assert!(unknown.exists());

    let hardlinked = directory
        .path()
        .join(".application-backup-user-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.sqlite");
    let alias = directory.path().join("synthetic-hardlink");
    fs::write(&hardlinked, b"synthetic hardlinked residual").expect("write residual");
    fs::hard_link(&hardlinked, &alias).expect("create hardlink");
    assert_eq!(
        cleanup_stale_application_backup_snapshots(directory.path())
            .expect_err("hardlinked residual must fail closed")
            .error_type,
        "application_backup_unsafe_temporary"
    );
    fs::remove_file(alias).expect("remove hardlink alias");
    fs::remove_file(hardlinked).expect("remove hardlinked residual");
    fs::remove_file(unknown).expect("remove unrelated file");
}
#[test]
fn paired_restore_rejects_legacy_collision_and_preserves_privacy_tamper_residue() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let (bundle, _, _) =
        build_application_backup(directory.path(), &state, &workflow).expect("build paired backup");

    set_user_canary(state.user_database_path(), MUTATED_USER_CANARY);
    let post_backup_policy = workflow
        .set_retention_policy(policy(3))
        .expect("mutate privacy state after backup");
    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage authenticated pair");
    let paths = application_restore_paths(directory.path());
    fs::write(&paths.legacy_user_marker, b"synthetic legacy collision")
        .expect("legacy marker fixture");
    let collided = restore_observer_filesystem_snapshot(directory.path());
    let collision = apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect_err("two restore protocols must not race");
    assert_eq!(collision.error_type, "application_restore_conflict");
    assert_eq!(
        restore_observer_filesystem_snapshot(directory.path()),
        collided,
        "mixed-protocol rejection changed restore state"
    );
    assert_eq!(user_canary(state.user_database_path()), MUTATED_USER_CANARY);
    fs::remove_file(&paths.legacy_user_marker).expect("remove collision fixture");

    let mut privacy_component = fs::read(&paths.privacy_incoming).expect("privacy incoming");
    let offset = privacy_component.len() / 2;
    privacy_component[offset] ^= 0x5a;
    fs::write(&paths.privacy_incoming, privacy_component).expect("tamper privacy incoming");
    drop(workflow);
    drop(state);
    let tampered = restore_observer_filesystem_snapshot(directory.path());
    let tamper = apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect_err("tampered privacy component must reject the whole pair");
    assert!(matches!(
        tamper.error_type.as_str(),
        "application_restore_tampered"
            | "application_restore_invalid"
            | "application_backup_component_mismatch"
    ));
    assert_eq!(
        restore_observer_filesystem_snapshot(directory.path()),
        tampered,
        "tampered V2 component was cleaned before explicit recovery"
    );
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        MUTATED_USER_CANARY
    );
    let restarted =
        PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace).expect("restart");
    assert_eq!(
        status(&restarted).retention_policy.revision,
        post_backup_policy.revision
    );
    cleanup_pair_incoming(&paths).expect("explicitly clean rejected V2 privacy fixture");
    assert_no_restore_residue(&paths);
}

#[test]
fn three_component_restore_preserves_every_slot_when_vault_is_tampered() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    set_user_canary(state.user_database_path(), BACKED_UP_USER_CANARY);
    let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
        .expect("build complete backup");

    set_user_canary(state.user_database_path(), MUTATED_USER_CANARY);
    let post_backup_policy = workflow
        .set_retention_policy(policy(4))
        .expect("mutate privacy state after backup");
    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage all three components");
    let paths = application_restore_paths(directory.path());
    let database_path = paths.vault_incoming.join("vault-state.sqlite");
    let mut vault_database = fs::read(&database_path).expect("staged Vault database");
    let offset = vault_database.len() / 2;
    vault_database[offset] ^= 0x40;
    fs::write(&database_path, vault_database).expect("tamper staged encrypted Vault state");

    drop(workflow);
    drop(state);
    let tampered = restore_observer_filesystem_snapshot(directory.path());
    let error = apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect_err("tampered Vault must fail closed before the complete restore starts");
    assert!(matches!(
        error.error_type.as_str(),
        "vault_store_database_failed"
            | "vault_store_content_corrupt"
            | "vault_backup_tampered"
            | "application_restore_tampered"
            | "application_restore_invalid"
    ));
    assert_eq!(
        restore_observer_filesystem_snapshot(directory.path()),
        tampered,
        "tampered V2 Vault was cleaned before explicit recovery"
    );
    assert_eq!(
        user_canary(&database::user_database_path(directory.path())),
        MUTATED_USER_CANARY
    );
    let restarted = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace)
        .expect("restart original stores");
    assert_eq!(
        status(&restarted).retention_policy.revision,
        post_backup_policy.revision
    );
    cleanup_pair_incoming(&paths).expect("explicitly clean rejected V2 Vault fixture");
    assert_no_restore_residue(&paths);
}
#[test]
fn paired_restore_cleanup_failure_dominates_original_and_rejects_hardlinks() {
    let directory = tempfile::tempdir().expect("application data directory");
    fs::create_dir_all(directory.path().join("privacy")).expect("privacy directory");
    let paths = application_restore_paths(directory.path());
    let alias = directory.path().join("synthetic-user-incoming-hardlink");

    fs::write(&paths.user_incoming, b"synthetic sensitive user restore")
        .expect("write user incoming");
    fs::hard_link(&paths.user_incoming, &alias).expect("create user incoming hardlink");
    fs::write(
        &paths.privacy_incoming,
        b"synthetic sensitive privacy restore",
    )
    .expect("write privacy incoming");
    fs::write(&paths.marker, b"synthetic protected marker").expect("write marker");

    let error = finish_pair_restore_stage(
        &paths,
        Err(ipc_error(
            "synthetic_original_restore_failure",
            "synthetic original failure",
        )),
    )
    .expect_err("unsafe cleanup must dominate the original stage error");

    assert_eq!(error.error_type, "application_restore_unsafe_cleanup");
    assert!(paths.user_incoming.exists());
    assert!(alias.exists());
    assert!(!paths.privacy_incoming.exists());
    assert!(!paths.marker.exists());

    fs::remove_file(alias).expect("remove hardlink alias");
    fs::remove_file(paths.user_incoming).expect("remove hardlinked incoming");
}

#[test]
fn vault_restore_cleanup_rejects_hardlinked_files_and_preserves_the_tree() {
    let directory = tempfile::tempdir().expect("application data directory");
    let paths = application_restore_paths(directory.path());
    fs::create_dir_all(paths.vault_incoming.join("keys")).expect("Vault incoming tree");
    let encrypted = paths
        .vault_incoming
        .join("keys")
        .join("case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.key.json");
    let alias = directory.path().join("synthetic-vault-hardlink");
    fs::write(&encrypted, b"SYNTHETIC_DPAPI_WRAPPED_KEY_BYTES").expect("write encrypted fixture");
    fs::hard_link(&encrypted, &alias).expect("create Vault hardlink");

    let error = finish_pair_restore_stage(
        &paths,
        Err(ipc_error(
            "synthetic_original_restore_failure",
            "synthetic original failure",
        )),
    )
    .expect_err("unsafe Vault cleanup must dominate the original error");
    assert_eq!(error.error_type, "application_restore_unsafe_cleanup");
    assert!(paths.vault_incoming.exists());
    assert!(encrypted.exists());
    assert!(alias.exists());

    fs::remove_file(alias).expect("remove hardlink alias");
    remove_vault_restore_directory(&paths.vault_incoming).expect("cleanup validated Vault tree");
}
#[test]
fn unmarked_pair_restore_does_not_ignore_rollback_residue() {
    let directory = tempfile::tempdir().expect("application data directory");
    let paths = application_restore_paths(directory.path());
    fs::write(&paths.user_rollback, b"synthetic sensitive rollback")
        .expect("write rollback residue");

    let error = cleanup_unmarked_pair_incoming(&paths)
        .expect_err("unmarked rollback residue must fail closed");

    assert_eq!(error.error_type, "application_restore_conflict");
    assert!(paths.user_rollback.exists());
    fs::remove_file(paths.user_rollback).expect("remove rollback residue");
}

#[test]
fn v3_slot_preflight_and_unmarked_cleanup_cover_both_case_store_directories() {
    let directory = tempfile::tempdir().expect("application data directory");
    fs::create_dir_all(directory.path().join("privacy/approved-mcp")).expect("approved MCP parent");
    let paths = application_restore_paths(directory.path());
    for path in [&paths.approved_incoming, &paths.work_products_incoming] {
        fs::create_dir(path).expect("incoming directory residue");
        assert_eq!(
            ensure_pair_restore_slot_empty(&paths)
                .expect_err("incoming case-store residue occupies the slot")
                .error_type,
            "application_restore_conflict"
        );
        cleanup_unmarked_pair_incoming(&paths).expect("clean unmarked incoming directory");
        assert!(!path.exists());
    }
    for path in [&paths.approved_rollback, &paths.work_products_rollback] {
        fs::create_dir(path).expect("rollback directory residue");
        assert_eq!(
            ensure_pair_restore_slot_empty(&paths)
                .expect_err("rollback case-store residue occupies the slot")
                .error_type,
            "application_restore_conflict"
        );
        assert_eq!(
            cleanup_unmarked_pair_incoming(&paths)
                .expect_err("unmarked rollback residue must never be discarded")
                .error_type,
            "application_restore_conflict"
        );
        remove_restore_directory(path).expect("remove synthetic rollback directory");
    }
}

#[test]
fn strict_original_presence_classifies_every_v2_v3_swap_and_cleanup_phase() {
    let kinds = [
        RestoreComponentKind::User,
        RestoreComponentKind::Privacy,
        RestoreComponentKind::Vault,
        RestoreComponentKind::ApprovedWorkspace,
        RestoreComponentKind::WorkProducts,
    ];
    for component_count in [3_usize, 5_usize] {
        for mask in 0_usize..(1_usize << component_count) {
            let presence = (0..component_count)
                .map(|index| mask & (1 << index) != 0)
                .collect::<Vec<_>>();
            let prepared = presence
                .iter()
                .map(|present| {
                    if *present {
                        RestoreSlotProgress::PreparedWithOriginal
                    } else {
                        RestoreSlotProgress::PreparedFromAbsent
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                classify_restore_progress_sequence(
                    &prepared,
                    &kinds[..component_count],
                    Some(&presence),
                )
                .expect("strict prepared phase"),
                PendingApplicationRestorePhase::Prepared,
                "component_count={component_count}, mask={mask:#07b}"
            );

            for current in 0..component_count {
                let installed = |index: usize| {
                    if presence[index] {
                        RestoreSlotProgress::InstalledWithRollback
                    } else {
                        RestoreSlotProgress::InstalledFromAbsent
                    }
                };
                if presence[current] {
                    let mut moved = prepared.clone();
                    for (index, state) in moved.iter_mut().enumerate().take(current) {
                        *state = installed(index);
                    }
                    moved[current] = RestoreSlotProgress::MovedToRollback;
                    assert_eq!(
                        classify_restore_progress_sequence(
                            &moved,
                            &kinds[..component_count],
                            Some(&presence),
                        )
                        .expect("strict moved phase"),
                        moved_restore_phase(kinds[current]).expect("known component"),
                        "moved component_count={component_count}, mask={mask:#07b}, current={current}"
                    );
                }

                let mut after_install = prepared.clone();
                for (index, state) in after_install.iter_mut().enumerate().take(current + 1) {
                    *state = installed(index);
                }
                let observed = classify_restore_progress_sequence(
                    &after_install,
                    &kinds[..component_count],
                    Some(&presence),
                )
                .expect("strict installed phase");
                let expected = if current + 1 < component_count {
                    installed_restore_phase(kinds[current]).expect("non-terminal component")
                } else {
                    let first_rollback = presence
                        .iter()
                        .position(|present| *present)
                        .unwrap_or(component_count);
                    PendingApplicationRestorePhase::InstalledPendingCleanup {
                        removed_rollback_prefix: first_rollback as u8,
                    }
                };
                assert_eq!(
                    observed, expected,
                    "installed component_count={component_count}, mask={mask:#07b}, current={current}"
                );
            }

            for cleanup_boundary in 0..=component_count {
                let states = presence
                    .iter()
                    .enumerate()
                    .map(|(index, present)| {
                        if !*present {
                            RestoreSlotProgress::InstalledFromAbsent
                        } else if index < cleanup_boundary {
                            RestoreSlotProgress::Cleaned
                        } else {
                            RestoreSlotProgress::InstalledWithRollback
                        }
                    })
                    .collect::<Vec<_>>();
                let expected_prefix = presence
                    .iter()
                    .enumerate()
                    .find_map(|(index, present)| {
                        (index >= cleanup_boundary && *present).then_some(index)
                    })
                    .unwrap_or(component_count);
                assert_eq!(
                    classify_restore_progress_sequence(
                        &states,
                        &kinds[..component_count],
                        Some(&presence),
                    )
                    .expect("strict cleanup phase"),
                    PendingApplicationRestorePhase::InstalledPendingCleanup {
                        removed_rollback_prefix: expected_prefix as u8,
                    },
                    "cleanup component_count={component_count}, mask={mask:#07b}, boundary={cleanup_boundary}"
                );
            }
        }
    }

    let interspersed_presence = [true, false, true, true, false];
    let out_of_order = [
        RestoreSlotProgress::InstalledWithRollback,
        RestoreSlotProgress::InstalledFromAbsent,
        RestoreSlotProgress::Cleaned,
        RestoreSlotProgress::InstalledWithRollback,
        RestoreSlotProgress::InstalledFromAbsent,
    ];
    assert_eq!(
        classify_restore_progress_sequence(&out_of_order, &kinds, Some(&interspersed_presence))
            .expect_err("a cleaned rollback after a surviving rollback is not a prefix")
            .error_type,
        "application_restore_conflict"
    );
}

fn rewrite_pending_marker_as_pre_presence_fixture(marker_path: &Path) -> PendingApplicationRestore {
    let protected = fs::read(marker_path).expect("read current protected marker");
    let plaintext = unprotect_local(&protected).expect("unprotect current marker");
    let mut value: serde_json::Value =
        privacy::vnext::strict_json_v1_from_slice(&plaintext).expect("strict current marker JSON");
    let object = value.as_object_mut().expect("marker object");
    for field in [
        "originalUserPresent",
        "originalPrivacyPresent",
        "originalVaultPresent",
        "originalApprovedWorkspacePresent",
        "originalWorkProductsPresent",
    ] {
        object.remove(field);
    }
    let legacy_plaintext =
        privacy::vnext::canonical_json_v1(&value).expect("canonical old marker fixture");
    let parsed: PendingApplicationRestore =
        privacy::vnext::strict_json_v1_from_slice(&legacy_plaintext)
            .expect("parse old marker fixture");
    assert_eq!(
        privacy::vnext::canonical_json_v1(&parsed).expect("re-encode old marker fixture"),
        legacy_plaintext,
        "an already-durable old marker must retain byte-exact canonical plaintext"
    );
    assert!(
        marker_original_presence(&parsed)
            .expect("old marker presence mode")
            .is_none(),
        "old markers must not acquire a forged strict presence proof"
    );
    let protected = protect_local(&legacy_plaintext).expect("protect old marker fixture");
    fs::write(marker_path, protected).expect("install old marker fixture");
    parsed
}

#[test]
fn durable_pre_presence_v2_and_v3_marker_bytes_round_trip_and_resume() {
    {
        let (directory, workspace, state, workflow, approved) = fixture_v3();
        let (bundle, _, _) =
            build_application_backup(directory.path(), &state, &workflow).expect("build V2");
        stage_application_restore_bytes(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &bundle,
        )
        .expect("stage V2");
        let paths = application_restore_paths(directory.path());
        assert!(matches!(
            rewrite_pending_marker_as_pre_presence_fixture(&paths.marker),
            PendingApplicationRestore::V2(_)
        ));
        let PendingApplicationRestoreObservation::Authenticated(gate) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("observe durable old V2 marker")
        else {
            panic!("old V2 marker must be present");
        };
        assert_eq!(gate.phase(), PendingApplicationRestorePhase::Prepared);
        drop(workflow);
        drop(state);
        apply_pending_application_restore_with_approved(
            directory.path(),
            &workspace,
            &approved.workspace,
        )
        .expect("resume durable old V2 marker");
        assert_no_restore_residue(&paths);
    }

    {
        let (directory, workspace, state, workflow, approved) = fixture_v3();
        let (bundle, _, _) =
            build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
                .expect("build V3");
        stage_application_restore_bytes_with_approved(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &approved.workspace,
            &bundle,
        )
        .expect("stage V3");
        let paths = application_restore_paths(directory.path());
        assert!(matches!(
            rewrite_pending_marker_as_pre_presence_fixture(&paths.marker),
            PendingApplicationRestore::V3(_)
        ));
        let PendingApplicationRestoreObservation::Authenticated(gate) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("observe durable old V3 marker")
        else {
            panic!("old V3 marker must be present");
        };
        assert_eq!(gate.phase(), PendingApplicationRestorePhase::Prepared);
        drop(workflow);
        drop(state);
        apply_pending_application_restore_with_approved(
            directory.path(),
            &workspace,
            &approved.workspace,
        )
        .expect("resume durable old V3 marker");
        assert_no_restore_residue(&paths);
    }
}

#[test]
fn v3_observer_gate_apply_resumes_after_every_swap_and_cleanup_commit_point() {
    let crash_matrix = [
        (
            ApplicationRestoreCommitPoint::UserMovedToRollback,
            PendingApplicationRestorePhase::UserMovedToRollback,
        ),
        (
            ApplicationRestoreCommitPoint::UserInstalled,
            PendingApplicationRestorePhase::UserInstalled,
        ),
        (
            ApplicationRestoreCommitPoint::PrivacyMovedToRollback,
            PendingApplicationRestorePhase::PrivacyMovedToRollback,
        ),
        (
            ApplicationRestoreCommitPoint::PrivacyInstalled,
            PendingApplicationRestorePhase::PrivacyInstalled,
        ),
        (
            ApplicationRestoreCommitPoint::VaultMovedToRollback,
            PendingApplicationRestorePhase::VaultMovedToRollback,
        ),
        (
            ApplicationRestoreCommitPoint::VaultInstalled,
            PendingApplicationRestorePhase::VaultInstalled,
        ),
        (
            ApplicationRestoreCommitPoint::ApprovedWorkspaceMovedToRollback,
            PendingApplicationRestorePhase::ApprovedWorkspaceMovedToRollback,
        ),
        (
            ApplicationRestoreCommitPoint::ApprovedWorkspaceInstalled,
            PendingApplicationRestorePhase::ApprovedWorkspaceInstalled,
        ),
        (
            ApplicationRestoreCommitPoint::WorkProductsMovedToRollback,
            PendingApplicationRestorePhase::WorkProductsMovedToRollback,
        ),
        (
            ApplicationRestoreCommitPoint::WorkProductsInstalled,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 0,
            },
        ),
        (
            ApplicationRestoreCommitPoint::CredentialsInvalidated,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 0,
            },
        ),
        (
            ApplicationRestoreCommitPoint::UserRollbackCleaned,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 1,
            },
        ),
        (
            ApplicationRestoreCommitPoint::PrivacyRollbackCleaned,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 2,
            },
        ),
        (
            ApplicationRestoreCommitPoint::VaultRollbackCleaned,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 3,
            },
        ),
        (
            ApplicationRestoreCommitPoint::ApprovedWorkspaceRollbackCleaned,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 4,
            },
        ),
        (
            ApplicationRestoreCommitPoint::WorkProductsRollbackCleaned,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 5,
            },
        ),
    ];

    for (crash_point, expected_phase) in crash_matrix {
        let (directory, _workspace, state, workflow, approved) = fixture_v3();
        let (bundle, _, _) =
            build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
                .expect("build exact V3 crash fixture");
        stage_application_restore_bytes_with_approved(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &approved.workspace,
            &bundle,
        )
        .expect("stage exact V3 crash fixture");
        let paths = application_restore_paths(directory.path());
        let PendingApplicationRestoreObservation::Authenticated(prepared) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("observe prepared V3 gate")
        else {
            panic!("prepared V3 marker must be present");
        };
        assert_eq!(prepared.phase(), PendingApplicationRestorePhase::Prepared);
        drop(workflow);
        drop(state);

        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reached_in_hook = Arc::clone(&reached);
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let result = apply_observed_pending_application_restore_with_hook(
                directory.path(),
                &prepared,
                Some(&approved.workspace),
                |point| {
                    if point == crash_point {
                        reached_in_hook.store(true, std::sync::atomic::Ordering::SeqCst);
                        panic!("synthetic process stop at {point:?}");
                    }
                    Ok(())
                },
            );
            if let Err(error) = result {
                panic!("apply failed before {crash_point:?}: {error:?}");
            }
        }));
        assert!(crashed.is_err(), "hook did not stop at {crash_point:?}");
        assert!(
            reached.load(std::sync::atomic::Ordering::SeqCst),
            "apply returned before {crash_point:?}"
        );

        let PendingApplicationRestoreObservation::Authenticated(resume_gate) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("observe exact V3 crash phase")
        else {
            panic!("crashed V3 marker must remain present");
        };
        assert_eq!(
            resume_gate.phase(),
            expected_phase,
            "crash point {crash_point:?}"
        );
        apply_observed_pending_application_restore_with_hook(
            directory.path(),
            &resume_gate,
            Some(&approved.workspace),
            |_| Ok(()),
        )
        .unwrap_or_else(|error| panic!("resume after {crash_point:?}: {error:?}"));
        assert_no_restore_residue(&paths);
    }
}

#[test]
fn v3_credentials_invalidated_crash_replays_monotonic_revocation_before_cleanup() {
    let (directory, _workspace, state, workflow, approved) = fixture_v3();
    let epochs_before = approved
        .epochs()
        .expect("materialize pre-restore credential epochs");
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build credential replay V3 fixture");
    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage credential replay V3 fixture");
    let paths = application_restore_paths(directory.path());
    let PendingApplicationRestoreObservation::Authenticated(prepared) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe prepared credential replay gate")
    else {
        panic!("credential replay marker must be present");
    };
    drop(workflow);
    drop(state);

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let _ = apply_observed_pending_application_restore_with_hook(
            directory.path(),
            &prepared,
            Some(&approved.workspace),
            |point| {
                if point == ApplicationRestoreCommitPoint::CredentialsInvalidated {
                    panic!("synthetic stop after credential invalidation");
                }
                Ok(())
            },
        );
    }));
    assert!(crashed.is_err(), "credential invalidation hook must stop");
    let epochs_after_crash = approved
        .epochs()
        .expect("read epochs after first credential invalidation");
    assert_ne!(epochs_after_crash.0, epochs_before.0);
    assert_ne!(epochs_after_crash.1, epochs_before.1);

    let PendingApplicationRestoreObservation::Authenticated(resume_gate) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe credential replay crash phase")
    else {
        panic!("credential replay marker must remain after the crash");
    };
    assert_eq!(
        resume_gate.phase(),
        PendingApplicationRestorePhase::InstalledPendingCleanup {
            removed_rollback_prefix: 0,
        },
        "an invalidation hook has no durable cleanup proof"
    );
    assert!(!observed_present_original_cleanup_exists(&resume_gate)
        .expect("classify credential replay cleanup evidence"));

    apply_observed_pending_application_restore_with_hook(
        directory.path(),
        &resume_gate,
        Some(&approved.workspace),
        |_| Ok(()),
    )
    .expect("resume and replay credential invalidation");
    let epochs_after_resume = approved
        .epochs()
        .expect("read epochs after replayed credential invalidation");
    assert_ne!(
        epochs_after_resume.0, epochs_after_crash.0,
        "the ticket credential issued before the crash must remain invalid"
    );
    assert_ne!(
        epochs_after_resume.1, epochs_after_crash.1,
        "the qualification epoch issued before the crash must remain invalid"
    );
    assert_no_restore_residue(&paths);
}

#[test]
fn v3_present_original_cleanup_proof_suppresses_duplicate_credential_invalidation() {
    let (directory, _workspace, state, workflow, approved) = fixture_v3();
    let epochs_before = approved
        .epochs()
        .expect("materialize pre-restore credential epochs");
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build credential skip V3 fixture");
    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage credential skip V3 fixture");
    let paths = application_restore_paths(directory.path());
    let marker = read_pair_marker(&paths.marker).expect("read credential skip marker");
    assert_eq!(
        marker_original_presence(&marker).expect("strict original presence"),
        Some(vec![true, true, true, true, true])
    );
    let PendingApplicationRestoreObservation::Authenticated(prepared) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe prepared credential skip gate")
    else {
        panic!("credential skip marker must be present");
    };
    drop(workflow);
    drop(state);

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let _ = apply_observed_pending_application_restore_with_hook(
            directory.path(),
            &prepared,
            Some(&approved.workspace),
            |point| {
                if point == ApplicationRestoreCommitPoint::UserRollbackCleaned {
                    panic!("synthetic stop after first present rollback cleanup");
                }
                Ok(())
            },
        );
    }));
    assert!(crashed.is_err(), "first cleanup hook must stop");
    let epochs_after_cleanup = approved
        .epochs()
        .expect("read epochs after the first cleanup");
    assert_ne!(epochs_after_cleanup.0, epochs_before.0);
    assert_ne!(epochs_after_cleanup.1, epochs_before.1);

    let PendingApplicationRestoreObservation::Authenticated(resume_gate) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe credential skip crash phase")
    else {
        panic!("credential skip marker must remain after the crash");
    };
    assert_eq!(
        resume_gate.phase(),
        PendingApplicationRestorePhase::InstalledPendingCleanup {
            removed_rollback_prefix: 1,
        }
    );
    assert!(observed_present_original_cleanup_exists(&resume_gate)
        .expect("authenticate present-original cleanup evidence"));

    apply_observed_pending_application_restore_with_hook(
        directory.path(),
        &resume_gate,
        Some(&approved.workspace),
        |_| Ok(()),
    )
    .expect("resume without duplicate credential invalidation");
    assert_eq!(
        approved
            .epochs()
            .expect("read epochs after credential skip resume"),
        epochs_after_cleanup,
        "a cleaned present rollback is durable proof that invalidation already ran"
    );
    assert_no_restore_residue(&paths);
}

#[test]
fn v2_observer_gate_apply_resumes_after_every_swap_and_cleanup_commit_point() {
    let crash_matrix = [
        (
            ApplicationRestoreCommitPoint::UserMovedToRollback,
            PendingApplicationRestorePhase::UserMovedToRollback,
        ),
        (
            ApplicationRestoreCommitPoint::UserInstalled,
            PendingApplicationRestorePhase::UserInstalled,
        ),
        (
            ApplicationRestoreCommitPoint::PrivacyMovedToRollback,
            PendingApplicationRestorePhase::PrivacyMovedToRollback,
        ),
        (
            ApplicationRestoreCommitPoint::PrivacyInstalled,
            PendingApplicationRestorePhase::PrivacyInstalled,
        ),
        (
            ApplicationRestoreCommitPoint::VaultMovedToRollback,
            PendingApplicationRestorePhase::VaultMovedToRollback,
        ),
        (
            ApplicationRestoreCommitPoint::VaultInstalled,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 0,
            },
        ),
        (
            ApplicationRestoreCommitPoint::UserRollbackCleaned,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 1,
            },
        ),
        (
            ApplicationRestoreCommitPoint::PrivacyRollbackCleaned,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 2,
            },
        ),
        (
            ApplicationRestoreCommitPoint::VaultRollbackCleaned,
            PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: 3,
            },
        ),
    ];

    for (crash_point, expected_phase) in crash_matrix {
        let (directory, _workspace, state, workflow, approved) = fixture_v3();
        let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
            .expect("build exact V2 crash fixture");
        stage_application_restore_bytes(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &bundle,
        )
        .expect("stage exact V2 crash fixture");
        let paths = application_restore_paths(directory.path());
        let PendingApplicationRestoreObservation::Authenticated(prepared) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("observe prepared V2 gate")
        else {
            panic!("prepared V2 marker must be present");
        };
        assert_eq!(prepared.phase(), PendingApplicationRestorePhase::Prepared);
        drop(workflow);
        drop(state);

        let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reached_in_hook = Arc::clone(&reached);
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let result = apply_observed_pending_application_restore_with_hook(
                directory.path(),
                &prepared,
                Some(&approved.workspace),
                |point| {
                    if point == crash_point {
                        reached_in_hook.store(true, std::sync::atomic::Ordering::SeqCst);
                        panic!("synthetic V2 process stop at {point:?}");
                    }
                    Ok(())
                },
            );
            if let Err(error) = result {
                panic!("V2 apply failed before {crash_point:?}: {error:?}");
            }
        }));
        assert!(crashed.is_err(), "V2 hook did not stop at {crash_point:?}");
        assert!(
            reached.load(std::sync::atomic::Ordering::SeqCst),
            "V2 apply returned before {crash_point:?}"
        );

        let PendingApplicationRestoreObservation::Authenticated(resume_gate) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("observe exact V2 crash phase")
        else {
            panic!("crashed V2 marker must remain present");
        };
        assert_eq!(
            resume_gate.phase(),
            expected_phase,
            "V2 crash point {crash_point:?}"
        );
        apply_observed_pending_application_restore_with_hook(
            directory.path(),
            &resume_gate,
            Some(&approved.workspace),
            |_| Ok(()),
        )
        .unwrap_or_else(|error| panic!("resume V2 after {crash_point:?}: {error:?}"));
        assert_no_restore_residue(&paths);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RestoreObserverFilesystemEntry {
    relative: String,
    directory: bool,
    bytes: u64,
    created: u64,
    modified: u64,
    attributes: u32,
    sha256: Option<String>,
}

fn restore_observer_filesystem_snapshot(root: &Path) -> Vec<RestoreObserverFilesystemEntry> {
    fn visit(root: &Path, current: &Path, output: &mut Vec<RestoreObserverFilesystemEntry>) {
        let mut entries = fs::read_dir(current)
            .expect("snapshot directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("snapshot entries");
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("snapshot metadata");
            let relative = path
                .strip_prefix(root)
                .expect("snapshot relative path")
                .to_string_lossy()
                .replace('\\', "/");
            let directory = metadata.is_dir();
            output.push(RestoreObserverFilesystemEntry {
                relative,
                directory,
                bytes: metadata.len(),
                created: metadata.creation_time(),
                modified: metadata.last_write_time(),
                attributes: metadata.file_attributes(),
                sha256: metadata
                    .is_file()
                    .then(|| privacy::sha256_hex(&fs::read(&path).expect("snapshot file"))),
            });
            if directory {
                visit(root, &path, output);
            }
        }
    }

    let mut output = Vec::new();
    visit(root, root, &mut output);
    output
}

fn create_restore_test_directory_reparse(target: &Path, link: &Path) -> std::io::Result<()> {
    use std::{
        io,
        os::windows::process::CommandExt,
        process::{Command, Stdio},
    };
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    match std::os::windows::fs::symlink_dir(target, link) {
        Ok(()) => Ok(()),
        Err(symlink_error) => {
            let normalized_link = link.components().collect::<PathBuf>();
            let normalized_target = target.components().collect::<PathBuf>();
            let status = Command::new("cmd.exe")
                .args(["/d", "/c", "mklink", "/J"])
                .arg(normalized_link)
                .arg(normalized_target)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status()?;
            if status.success() {
                Ok(())
            } else {
                Err(io::Error::new(
                    symlink_error.kind(),
                    "failed to create a restore-test directory symlink or junction",
                ))
            }
        }
    }
}

#[test]
fn v3_observer_is_recursive_zero_write_and_never_calls_load_or_create() {
    let (directory, _workspace, state, workflow, approved) = fixture_v3();
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build observer V3 fixture");
    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage observer V3 fixture");
    drop(workflow);
    drop(state);
    approved.panic_if_load_or_create_is_called();
    let before = restore_observer_filesystem_snapshot(directory.path());

    for _ in 0..2 {
        let PendingApplicationRestoreObservation::Authenticated(gate) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("repeat exact read-only V3 observation")
        else {
            panic!("staged V3 marker must be observed");
        };
        assert_eq!(gate.phase(), PendingApplicationRestorePhase::Prepared);
    }

    assert_eq!(
        restore_observer_filesystem_snapshot(directory.path()),
        before,
        "observer changed recursive entries, bytes, timestamps, or attributes"
    );
}

#[test]
fn observed_gate_rejects_incoming_tamper_before_first_write() {
    let (directory, _workspace, state, workflow, approved) = fixture_v3();
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build gate tamper fixture");
    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage gate tamper fixture");
    let paths = application_restore_paths(directory.path());
    drop(workflow);
    drop(state);
    let PendingApplicationRestoreObservation::Authenticated(gate) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("capture gate before tamper")
    else {
        panic!("tamper fixture marker must be observed");
    };
    let mut user = fs::read(&paths.user_incoming).expect("incoming user bytes");
    user[0] ^= 0x80;
    fs::write(&paths.user_incoming, user).expect("tamper after gate");
    let tampered = restore_observer_filesystem_snapshot(directory.path());

    let error = apply_observed_pending_application_restore_with_hook(
        directory.path(),
        &gate,
        Some(&approved.workspace),
        |_| Ok(()),
    )
    .expect_err("gate-after-tamper must reject before the first rename or cleanup");
    assert!(matches!(
        error.error_type.as_str(),
        "application_restore_observation_changed"
            | "application_restore_tampered"
            | "application_restore_invalid"
    ));
    assert_eq!(
        restore_observer_filesystem_snapshot(directory.path()),
        tampered,
        "failed gate revalidation wrote or cleaned restore state"
    );
}

#[test]
fn v2_cross_workspace_identity_fails_closed_without_writes() {
    let (directory, _workspace, state, workflow, approved) = fixture_v3();
    let (other_directory, _, _, _, other_approved) = fixture_v3();
    let _other_workspace = other_approved
        .workspace
        .workspace_instance_id()
        .expect("create distinct existing workspace identity");
    let (bundle, _, _) =
        build_application_backup(directory.path(), &state, &workflow).expect("build V2 fixture");
    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage V2 cross-workspace fixture");
    drop(workflow);
    drop(state);
    let before = restore_observer_filesystem_snapshot(directory.path());

    let error = observe_pending_application_restore_read_only_with_approved(
        directory.path(),
        Some(&other_approved.workspace),
    )
    .expect_err("a different existing Approved identity must not authenticate V2");
    assert_eq!(error.error_type, "approved_workspace_unavailable");
    assert_eq!(
        restore_observer_filesystem_snapshot(directory.path()),
        before
    );
    drop(other_directory);
    drop(approved);
}

#[test]
fn v2_original_absent_user_and_vault_are_lazily_installed_and_cleaned() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    let (bundle, _, _) = build_application_backup(directory.path(), &state, &workflow)
        .expect("build V2 absent-original fixture");
    let paths = application_restore_paths(directory.path());
    remove_database_restore_files(&paths.user_active).expect("remove original user component");
    remove_vault_restore_directory(&paths.vault_active).expect("remove original Vault component");
    assert!(!paths.user_active.exists());
    assert!(!paths.vault_active.exists());

    stage_application_restore_bytes(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &bundle,
    )
    .expect("stage V2 with authenticated absent originals");
    let marker = read_pair_marker(&paths.marker).expect("read V2 absent-original marker");
    assert_eq!(
        marker_original_presence(&marker).expect("V2 presence proof"),
        Some(vec![false, true, false])
    );
    let PendingApplicationRestoreObservation::Authenticated(gate) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe V2 absent-original gate")
    else {
        panic!("V2 absent-original marker must be present");
    };
    assert_eq!(gate.phase(), PendingApplicationRestorePhase::Prepared);
    drop(workflow);
    drop(state);

    apply_observed_pending_application_restore_with_hook(
        directory.path(),
        &gate,
        Some(&approved.workspace),
        |_| Ok(()),
    )
    .expect("apply V2 absent-original restore");
    database::validate_user_database_read_only(&paths.user_active)
        .expect("lazily installed user component is canonical");
    let restarted = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace)
        .expect("reopen V2 absent-original Privacy component");
    assert!(paths.vault_active.is_dir());
    drop(restarted);
    assert_no_restore_residue(&paths);
}

#[test]
fn v3_original_absent_four_component_interleaving_is_lazily_installed_and_cleaned() {
    let (directory, workspace, state, workflow, approved) = fixture_v3();
    let epochs_before = approved
        .epochs()
        .expect("materialize credentials before the absent-original gate");
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build V3 absent-original fixture");
    let paths = application_restore_paths(directory.path());
    remove_database_restore_files(&paths.user_active).expect("remove original user component");
    remove_vault_restore_directory(&paths.vault_active).expect("remove original Vault component");
    if paths.approved_active.exists() {
        remove_restore_directory(&paths.approved_active)
            .expect("remove original Approved component");
    }
    if paths.work_products_active.exists() {
        remove_restore_directory(&paths.work_products_active)
            .expect("remove original work-products component");
    }
    assert!(!paths.user_active.exists());
    assert!(!paths.vault_active.exists());
    assert!(!paths.approved_active.exists());
    assert!(!paths.work_products_active.exists());

    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage V3 with interleaved authenticated absent originals");
    let marker = read_pair_marker(&paths.marker).expect("read V3 absent-original marker");
    assert_eq!(
        marker_original_presence(&marker).expect("V3 presence proof"),
        Some(vec![false, true, false, false, false])
    );
    let PendingApplicationRestoreObservation::Authenticated(gate) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe V3 absent-original gate")
    else {
        panic!("V3 absent-original marker must be present");
    };
    assert_eq!(gate.phase(), PendingApplicationRestorePhase::Prepared);
    drop(workflow);
    drop(state);

    let reached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reached_in_hook = Arc::clone(&reached);
    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let _ = apply_observed_pending_application_restore_with_hook(
            directory.path(),
            &gate,
            Some(&approved.workspace),
            |point| {
                if point == ApplicationRestoreCommitPoint::WorkProductsInstalled {
                    reached_in_hook.store(true, std::sync::atomic::Ordering::SeqCst);
                    panic!("synthetic stop after absent-original V3 swaps");
                }
                Ok(())
            },
        );
    }));
    assert!(crashed.is_err());
    assert!(reached.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        approved.epochs().expect("epochs before absent resume"),
        epochs_before,
        "the post-swap hook stops before credential invalidation"
    );
    let PendingApplicationRestoreObservation::Authenticated(resume_gate) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("observe absent-original post-swap phase")
    else {
        panic!("absent-original V3 marker must remain after the swap crash");
    };
    assert_eq!(
        resume_gate.phase(),
        PendingApplicationRestorePhase::InstalledPendingCleanup {
            removed_rollback_prefix: 1,
        },
        "a leading absent slot is a numeric prefix, not invalidation evidence"
    );
    apply_observed_pending_application_restore_with_hook(
        directory.path(),
        &resume_gate,
        Some(&approved.workspace),
        |_| Ok(()),
    )
    .expect("resume V3 absent-original restore");
    let epochs_after = approved.epochs().expect("epochs after absent resume");
    assert_ne!(epochs_after.0, epochs_before.0);
    assert_ne!(epochs_after.1, epochs_before.1);
    database::validate_user_database_read_only(&paths.user_active)
        .expect("lazily installed V3 user component is canonical");
    let restarted = PrivacyWorkflowManager::new(directory.path().to_path_buf(), workspace)
        .expect("reopen V3 absent-original Privacy component");
    assert!(paths.vault_active.is_dir());
    assert!(paths.approved_active.is_dir());
    assert!(paths.work_products_active.is_dir());
    drop(restarted);
    assert_no_restore_residue(&paths);
}

#[test]
fn observed_gate_rejects_recursive_file_and_directory_tamper_before_first_write() {
    for tamper_directory in [false, true] {
        let (directory, _workspace, state, workflow, approved) = fixture_v3();
        let case_id = format!(
            "case_{}",
            (if tamper_directory { "7" } else { "6" }).repeat(32)
        );
        let generation = approved
            .publish_generation(&case_id, if tamper_directory { 'b' } else { 'a' })
            .expect("publish recursive-proof generation");
        let work_product_id = approved
            .create_work_product(&generation, b"[PERSON_001] recursive restore proof fixture")
            .expect("create recursive-proof work product");
        let (bundle, _, _) =
            build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
                .expect("build recursive-proof V3 fixture");
        stage_application_restore_bytes_with_approved(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &approved.workspace,
            &bundle,
        )
        .expect("stage recursive-proof V3 fixture");
        let paths = application_restore_paths(directory.path());
        let PendingApplicationRestoreObservation::Authenticated(gate) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("capture gate before recursive tamper")
        else {
            panic!("recursive tamper fixture marker must be observed");
        };
        drop(workflow);
        drop(state);

        if tamper_directory {
            let unexpected = paths
                .work_products_incoming
                .join("work-products")
                .join("unexpected-recursive-directory");
            fs::create_dir(&unexpected).expect("insert unexpected recursive directory");
        } else {
            let envelope = paths
                .work_products_incoming
                .join("work-products")
                .join(&case_id)
                .join(&work_product_id)
                .join("v00000000000000000001")
                .join("content.envelope.json");
            let mut bytes = fs::read(&envelope).expect("read nested encrypted envelope");
            let offset = bytes.len() / 2;
            bytes[offset] ^= 0x20;
            fs::write(&envelope, bytes).expect("tamper nested encrypted envelope");
        }
        let tampered = restore_observer_filesystem_snapshot(directory.path());
        let error = apply_observed_pending_application_restore_with_hook(
            directory.path(),
            &gate,
            Some(&approved.workspace),
            |_| Ok(()),
        )
        .expect_err("recursive tree drift must fail before the first rename or cleanup");
        assert!(matches!(
            error.error_type.as_str(),
            "application_restore_observation_changed"
                | "application_restore_invalid"
                | "approved_workspace_unavailable"
        ));
        assert_eq!(
            restore_observer_filesystem_snapshot(directory.path()),
            tampered,
            "recursive file/directory rejection changed the filesystem"
        );
    }
}

#[test]
fn observed_gate_rejects_credential_digest_drift_before_first_write() {
    let (directory, _workspace, state, workflow, approved) = fixture_v3();
    approved
        .epochs()
        .expect("materialize both non-manifest credential slots");
    let (bundle, _, _) =
        build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
            .expect("build credential-drift V3 fixture");
    stage_application_restore_bytes_with_approved(
        directory.path(),
        state.user_database_path(),
        &workflow,
        &approved.workspace,
        &bundle,
    )
    .expect("stage credential-drift V3 fixture");
    let PendingApplicationRestoreObservation::Authenticated(gate) =
        observe_pending_application_restore_read_only_with_approved(
            directory.path(),
            Some(&approved.workspace),
        )
        .expect("capture gate before credential drift")
    else {
        panic!("credential-drift fixture marker must be observed");
    };
    drop(workflow);
    drop(state);
    approved
        .drift_application_restore_ticket_credential()
        .expect("rotate one observed non-manifest credential");
    let drifted = restore_observer_filesystem_snapshot(directory.path());

    let error = apply_observed_pending_application_restore_with_hook(
        directory.path(),
        &gate,
        Some(&approved.workspace),
        |_| Ok(()),
    )
    .expect_err("credential proof drift must fail before the first rename or cleanup");
    assert_eq!(error.error_type, "application_restore_observation_changed");
    assert_eq!(
        restore_observer_filesystem_snapshot(directory.path()),
        drifted,
        "credential digest rejection changed the restore filesystem"
    );
}

#[test]
fn observed_gate_rejects_unknown_unmarked_mixed_hardlink_and_reparse_state_without_writes() {
    #[derive(Debug, Clone, Copy)]
    enum Attack {
        UnknownSibling,
        UnmarkedResidue,
        MixedProtocol,
        Hardlink,
        ReparsePoint,
    }

    for attack in [
        Attack::UnknownSibling,
        Attack::UnmarkedResidue,
        Attack::MixedProtocol,
        Attack::Hardlink,
        Attack::ReparsePoint,
    ] {
        let (directory, _workspace, state, workflow, approved) = fixture_v3();
        let (bundle, _, _) =
            build_application_backup_v3(directory.path(), &state, &workflow, &approved.workspace)
                .expect("build namespace-drift V3 fixture");
        stage_application_restore_bytes_with_approved(
            directory.path(),
            state.user_database_path(),
            &workflow,
            &approved.workspace,
            &bundle,
        )
        .expect("stage namespace-drift V3 fixture");
        let paths = application_restore_paths(directory.path());
        let PendingApplicationRestoreObservation::Authenticated(gate) =
            observe_pending_application_restore_read_only_with_approved(
                directory.path(),
                Some(&approved.workspace),
            )
            .expect("capture gate before namespace drift")
        else {
            panic!("namespace-drift fixture marker must be observed");
        };
        drop(workflow);
        drop(state);

        let mut reparse_link = None;
        match attack {
            Attack::UnknownSibling => {
                fs::write(
                    directory
                        .path()
                        .join("user.sqlite.application-restore-staging-unknown"),
                    b"unknown restore sibling",
                )
                .expect("create unknown restore sibling");
            }
            Attack::UnmarkedResidue => {
                fs::remove_file(&paths.marker).expect("remove protected marker after gate");
            }
            Attack::MixedProtocol => {
                fs::write(&paths.legacy_user_marker, b"mixed legacy restore marker")
                    .expect("create mixed-protocol marker");
            }
            Attack::Hardlink => {
                fs::hard_link(
                    &paths.user_incoming,
                    directory.path().join("synthetic-restore-hardlink-alias"),
                )
                .expect("create incoming user hardlink after gate");
            }
            Attack::ReparsePoint => {
                let target = directory.path().join("synthetic-restore-reparse-target");
                fs::create_dir(&target).expect("create reparse target");
                fs::write(target.join("sentinel"), b"reparse target sentinel")
                    .expect("write reparse target sentinel");
                let link = paths.vault_incoming.join("synthetic-reparse-entry");
                create_restore_test_directory_reparse(&target, &link)
                    .expect("create restore reparse point after gate");
                reparse_link = Some(link);
            }
        }
        let attacked = restore_observer_filesystem_snapshot(directory.path());
        let error = apply_observed_pending_application_restore_with_hook(
            directory.path(),
            &gate,
            Some(&approved.workspace),
            |_| Ok(()),
        )
        .expect_err("namespace drift must fail before the first write");
        let expected_code = match attack {
            Attack::UnknownSibling => "application_restore_unknown_state",
            Attack::UnmarkedResidue | Attack::MixedProtocol => "application_restore_conflict",
            Attack::Hardlink | Attack::ReparsePoint => "application_restore_invalid",
        };
        assert_eq!(error.error_type, expected_code, "attack {attack:?}");
        assert_eq!(
            restore_observer_filesystem_snapshot(directory.path()),
            attacked,
            "attack rejection changed the filesystem: {attack:?}"
        );
        if let Some(link) = reparse_link {
            fs::remove_dir(link).expect("remove test junction without traversing its target");
        }
    }
}
