use super::*;
use crate::privacy_workflow::{
    test_workspace_instance_id, LifecycleStatusRequest, SetRetentionPolicyRequest,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::mpsc,
    thread,
    time::Duration,
};
use tempfile::TempDir;

const USER_CANARY_KEY: &str = "privacy_vnext_paired_backup_canary";
const BACKED_UP_USER_CANARY: &str = "SYNTHETIC_USER_DB_BEFORE_BACKUP_4F9C";
const MUTATED_USER_CANARY: &str = "SYNTHETIC_USER_DB_AFTER_BACKUP_A71D";

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
    assert_eq!(epochs_after.0, epochs_before.0.wrapping_add(1));
    assert_eq!(epochs_after.1, epochs_before.1.wrapping_add(1));
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
fn v3_marker_precommit_failure_cleans_all_components_and_unmarked_crash_recovers() {
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
    let injected = stage_application_restore_bytes_with_hook(
        directory.path(),
        state.user_database_path(),
        &workflow,
        Some(&approved.workspace),
        &bundle,
        |_| {
            Err(ipc_error(
                "synthetic_before_marker_failure",
                "synthetic before marker failure",
            ))
        },
    )
    .expect_err("marker-precommit error must fail stage");
    assert_eq!(injected.error_type, "synthetic_before_marker_failure");
    let paths = application_restore_paths(directory.path());
    assert_no_restore_residue(&paths);

    let crashed = catch_unwind(AssertUnwindSafe(|| {
        let _ = stage_application_restore_bytes_with_hook(
            directory.path(),
            state.user_database_path(),
            &workflow,
            Some(&approved.workspace),
            &bundle,
            |_| panic!("synthetic process stop before protected marker"),
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
    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("startup removes every unmarked incoming component");
    assert_no_restore_residue(&paths);

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
    let (directory, workspace, state, workflow, approved) = fixture_v3();
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
    let marker = read_pair_marker(&paths.marker).expect("V3 marker");
    let PendingApplicationRestore::V3(marker) = marker else {
        panic!("expected V3 marker");
    };
    advance_component(
        &paths.user_active,
        &paths.user_incoming,
        &paths.user_rollback,
        &marker.user_database_sha256,
        |path| validate_user_component(path, &marker.user_database_sha256),
    )
    .expect("install user before crash");
    advance_component(
        &paths.privacy_active,
        &paths.privacy_incoming,
        &paths.privacy_rollback,
        &marker.privacy_database_sha256,
        |path| {
            validate_privacy_component(
                path,
                &workspace,
                marker.privacy_key_epoch,
                &marker.privacy_database_sha256,
            )
        },
    )
    .expect("install privacy before crash");
    advance_vault_component(
        &paths.vault_active,
        &paths.vault_incoming,
        &paths.vault_rollback,
        &workspace,
        &marker.vault_manifest_sha256,
        &marker.vault_archive_sha256,
    )
    .expect("install Vault before crash");
    advance_restore_directory(
        &paths.approved_active,
        &paths.approved_incoming,
        &paths.approved_rollback,
    )
    .expect("install approved workspace before crash");
    assert!(paths.work_products_incoming.exists());
    assert!(!paths.work_products_rollback.exists());
    drop(workflow);
    drop(state);

    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("restart completes fifth component");
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
        apply_pending_application_restore_with_approved(
            directory.path(),
            &workspace,
            &approved.workspace,
        )
        .expect_err("tampered or missing case store must fail closed");
        assert_eq!(
            user_canary(&database::user_database_path(directory.path())),
            MUTATED_USER_CANARY
        );
        assert_eq!(approved.workspace.list(Some(&case_id)).unwrap().len(), 2);
        assert_eq!(
            approved.committed_work_product_row_count(&case_id).unwrap(),
            2
        );
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

fn status(workflow: &PrivacyWorkflowManager) -> crate::privacy_workflow::LifecycleStatusView {
    workflow
        .lifecycle_status(LifecycleStatusRequest { redaction_id: None })
        .expect("lifecycle status")
}

#[test]
fn paired_backup_restores_both_databases_after_interruption_without_plaintext() {
    let (directory, workspace, state, workflow) = fixture();
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

    apply_pending_application_restore(directory.path(), &workspace)
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
    let (directory, workspace, state, workflow) = fixture();
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

    apply_pending_application_restore(directory.path(), &workspace)
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
fn coherent_backup_holds_both_database_write_boundaries_until_both_snapshots_finish() {
    let (directory, workspace, state, workflow) = fixture();
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
    apply_pending_application_restore(directory.path(), &workspace).expect("restore coherent pair");
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
fn paired_restore_rejects_legacy_collision_and_rolls_back_on_privacy_tamper() {
    let (directory, workspace, state, workflow) = fixture();
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
    let collision = apply_pending_application_restore(directory.path(), &workspace)
        .expect_err("two restore protocols must not race");
    assert_eq!(collision.error_type, "application_restore_conflict");
    assert_eq!(user_canary(state.user_database_path()), MUTATED_USER_CANARY);
    fs::remove_file(&paths.legacy_user_marker).expect("remove collision fixture");

    let mut privacy_component = fs::read(&paths.privacy_incoming).expect("privacy incoming");
    let offset = privacy_component.len() / 2;
    privacy_component[offset] ^= 0x5a;
    fs::write(&paths.privacy_incoming, privacy_component).expect("tamper privacy incoming");
    drop(workflow);
    drop(state);
    let tamper = apply_pending_application_restore(directory.path(), &workspace)
        .expect_err("tampered privacy component must reject the whole pair");
    assert!(matches!(
        tamper.error_type.as_str(),
        "application_restore_tampered"
            | "application_restore_invalid"
            | "application_backup_component_mismatch"
    ));
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
    assert!(!paths.marker.exists());
    assert!(!paths.user_incoming.exists());
    assert!(!paths.user_rollback.exists());
    assert!(!paths.privacy_incoming.exists());
    assert!(!paths.privacy_rollback.exists());
    assert!(!paths.vault_incoming.exists());
    assert!(!paths.vault_rollback.exists());
}

#[test]
fn three_component_restore_rolls_back_both_databases_when_vault_is_tampered() {
    let (directory, workspace, state, workflow) = fixture();
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
    let error = apply_pending_application_restore(directory.path(), &workspace)
        .expect_err("tampered Vault must reject and roll back the complete restore");
    assert!(matches!(
        error.error_type.as_str(),
        "vault_store_database_failed"
            | "vault_store_content_corrupt"
            | "vault_backup_tampered"
            | "application_restore_tampered"
            | "application_restore_invalid"
    ));
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
    assert!(!paths.marker.exists());
    assert!(!paths.user_incoming.exists());
    assert!(!paths.user_rollback.exists());
    assert!(!paths.privacy_incoming.exists());
    assert!(!paths.privacy_rollback.exists());
    assert!(!paths.vault_incoming.exists());
    assert!(!paths.vault_rollback.exists());
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
