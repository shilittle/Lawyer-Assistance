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
    let (bytes, metadata, _, built) = build_application_backup_internal(
        directory.path(),
        &state,
        &workflow,
        Some(&approved.workspace),
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
        .expect("upgraded active Privacy schema"),
        PrivacyStoreSchemaStatus::Current
    );

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
        let _ = apply_pending_application_restore_with_hook(
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
        .expect("post-backup current Privacy"),
        PrivacyStoreSchemaStatus::Current
    );
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
    apply_pending_application_restore_with_approved(
        directory.path(),
        &workspace,
        &approved.workspace,
    )
    .expect("startup removes every unmarked incoming component");
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
                marker
                    .privacy_store_schema_version
                    .unwrap_or(PRIVACY_STORE_SCHEMA_VERSION),
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
fn pending_three_component_restore_rechecks_lineage_before_any_component_swap() {
    let (directory, workspace, state, workflow) = fixture();
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

    let error = apply_pending_application_restore(directory.path(), &workspace)
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
