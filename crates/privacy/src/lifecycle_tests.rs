#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::{
        DestinationKind, DestinationScope, PrivacyStore, ReceiptSigner, RedactionReceiptClaims,
        RegisterPrivacyMaterial, ReviewState, SaveReviewDraft, PRIVACY_STORE_SCHEMA_VERSION,
        REDACTION_VERSION,
    };
    use std::fs;

    const NOW: u64 = 10_000;
    const MAP_ID: &str = "map_11111111111111111111111111111111";
    const CLEANUP_ID: &str = "cln_22222222222222222222222222222222";
    const BACKUP_ID: &str = "bkp_33333333333333333333333333333333";
    const OUTPUT_ID: &str = "out_44444444444444444444444444444444";

    fn workspace() -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse("ws_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("workspace")
    }

    fn other_workspace() -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse("ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").expect("workspace")
    }

    fn mapping() -> SensitiveMappingPayloadV1 {
        SensitiveMappingPayloadV1::new(vec![
            SensitiveMappingEntryV1 {
                alias: "[PERSON_1]".to_owned(),
                sensitive_value: "SYNTHETIC_PRIVATE_NAME_CANARY".to_owned(),
            },
            SensitiveMappingEntryV1 {
                alias: "[PHONE_1]".to_owned(),
                sensitive_value: "13800000000".to_owned(),
            },
        ])
        .expect("mapping")
    }

    fn setup_review() -> (Connection, PrivacyLifecycle) {
        let mut connection = Connection::open_in_memory().expect("database");
        connection
            .execute_batch("PRAGMA foreign_keys=ON;")
            .expect("foreign keys");
        PrivacyStore::initialize(&connection).expect("privacy schema");
        PrivacyStore::register_material(
            &connection,
            &RegisterPrivacyMaterial {
                material_id: "material-1",
                project_id: Some("project-1"),
                attachment_id: Some("attachment-1"),
                source_sha256: &sha256_hex(b"synthetic source"),
                source_name_sha256: &sha256_hex(b"synthetic.pdf"),
                media_type: "application/pdf",
                page_count: Some(1),
            },
        )
        .expect("material");
        PrivacyStore::save_review_draft(
            &connection,
            &SaveReviewDraft {
                redaction_id: "redaction-1",
                material_id: "material-1",
                extraction_sha256: &sha256_hex(b"synthetic extraction"),
                redacted_content_sha256: &sha256_hex(b"synthetic redacted"),
                policy_id: "cn-legal-default",
                policy_version: 1,
                detector_version: REDACTION_VERSION,
                unresolved_high_risk_count: 0,
                review_payload_plaintext: b"synthetic protected review",
            },
        )
        .expect("review");
        let lifecycle =
            PrivacyLifecycle::initialize(&mut connection, workspace(), NOW).expect("lifecycle");
        (connection, lifecycle)
    }

    fn approve_and_receipt(connection: &mut Connection) -> String {
        let approved = b"synthetic approved source";
        PrivacyStore::approve_review(
            connection,
            "redaction-1",
            &sha256_hex(b"synthetic redacted"),
            &sha256_hex(approved),
            &sha256_hex(approved),
            &sha256_hex(b"synthetic reviewer"),
            approved,
        )
        .expect("approve");
        let signer = ReceiptSigner::new([7_u8; 32]).expect("signer");
        let receipt = signer
            .issue(RedactionReceiptClaims {
                receipt_id: String::new(),
                source_sha256: vec![sha256_hex(b"synthetic source")],
                extraction_sha256: sha256_hex(b"synthetic extraction"),
                redacted_content_sha256: sha256_hex(approved),
                approved_payload_sha256: sha256_hex(approved),
                policy_id: "cn-legal-default".to_owned(),
                policy_version: 1,
                detector_version: REDACTION_VERSION.to_owned(),
                destination: DestinationScope {
                    kind: DestinationKind::ExternalProvider,
                    identifier: "provider-synthetic".to_owned(),
                },
                purpose: "assistant_chat".to_owned(),
                unresolved_high_risk_count: 0,
                review_state: ReviewState::Approved,
                issued_at_unix: NOW,
                expires_at_unix: Some(NOW + 2_000),
                key_version: 1,
            })
            .expect("receipt");
        let token = signer.encode_token(&receipt).expect("token");
        PrivacyStore::persist_receipt(
            connection,
            "redaction-1",
            &signer,
            &receipt,
            &token,
            approved,
            NOW + 1,
        )
        .expect("persist receipt");
        receipt.claims.receipt_id
    }

    #[test]
    fn privacy_store_v1_migrates_through_lifecycle_risk_and_consumption_schema_v4_and_rejects_future_schema() {
        let connection = Connection::open_in_memory().expect("database");
        connection
            .execute_batch(
                "CREATE TABLE privacy_schema_metadata(
                   key TEXT PRIMARY KEY,value TEXT NOT NULL,
                   updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 INSERT INTO privacy_schema_metadata(key,value) VALUES('schema_version','1');",
            )
            .expect("v1 metadata");
        PrivacyStore::initialize(&connection).expect("migrate");
        let version: String = connection
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("version");
        assert_eq!(version, PRIVACY_STORE_SCHEMA_VERSION.to_string());
        let lifecycle_table: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
                 WHERE type='table' AND name='privacy_sensitive_mappings')",
                [],
                |row| row.get(0),
            )
            .expect("table");
        assert!(lifecycle_table);
        let risk_schema: (bool, bool) = connection
            .query_row(
                "SELECT
                    EXISTS(SELECT 1 FROM sqlite_master
                      WHERE type='table' AND name='privacy_risk_review_revisions'),
                    EXISTS(SELECT 1 FROM sqlite_master
                      WHERE type='trigger' AND name='trg_privacy_risk_review_no_update')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("risk revision schema");
        assert_eq!(risk_schema, (true, true));
        connection
            .execute(
                "UPDATE privacy_schema_metadata SET value='999' WHERE key='schema_version'",
                [],
            )
            .expect("future version");
        assert_eq!(
            PrivacyStore::initialize(&connection),
            Err(PrivacyStoreError::UnsupportedSchema)
        );

        let future = Connection::open_in_memory().expect("future database");
        future
            .execute_batch(
                "CREATE TABLE privacy_schema_metadata(
                   key TEXT PRIMARY KEY,value TEXT NOT NULL,
                   updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 INSERT INTO privacy_schema_metadata(key,value) VALUES('schema_version','999');",
            )
            .expect("future metadata");
        assert_eq!(
            PrivacyStore::initialize(&future),
            Err(PrivacyStoreError::UnsupportedSchema)
        );
        let lifecycle_table: bool = future
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
                 WHERE type='table' AND name='privacy_sensitive_mappings')",
                [],
                |row| row.get(0),
            )
            .expect("future table check");
        assert!(!lifecycle_table);
    }

    #[cfg(windows)]
    #[test]
    fn encrypted_mapping_round_trip_access_expiry_rotation_and_revocation() {
        let (mut connection, lifecycle) = setup_review();
        let summary = lifecycle
            .save_mapping_revision(&mut connection, MAP_ID, "redaction-1", 1, &mapping(), NOW + 1)
            .expect("save mapping");
        assert_eq!(summary.key_version, 1);
        let stored: Vec<u8> = connection
            .query_row(
                "SELECT ciphertext FROM privacy_sensitive_mappings WHERE mapping_id=?1",
                [MAP_ID],
                |row| row.get(0),
            )
            .expect("ciphertext");
        assert!(!stored
            .windows(b"SYNTHETIC_PRIVATE_NAME_CANARY".len())
            .any(|window| window == b"SYNTHETIC_PRIVATE_NAME_CANARY"));
        assert!(!format!("{:?}", mapping()).contains("SYNTHETIC_PRIVATE_NAME_CANARY"));
        let denied = MappingAccessContextV1 {
            access_id: "mapping-access-denied",
            redaction_id: "redaction-1",
            purpose: "local_mapping_review",
            now_unix: NOW + 2,
            private_mapping_access_authorized: false,
        };
        assert_eq!(
            lifecycle.load_mapping_revision(&mut connection, MAP_ID, &denied),
            Err(LifecycleError::MappingAccessDenied)
        );
        let allowed = MappingAccessContextV1 {
            access_id: "mapping-access-allowed",
            private_mapping_access_authorized: true,
            ..denied
        };
        let loaded = lifecycle
            .load_mapping_revision(&mut connection, MAP_ID, &allowed)
            .expect("load mapping");
        assert_eq!(loaded, mapping());
        assert_eq!(
            lifecycle.load_mapping_revision(
                &mut connection,
                MAP_ID,
                &MappingAccessContextV1 {
                    access_id: "mapping-access-wrong-redaction",
                    redaction_id: "redaction-other",
                    ..allowed
                },
            ),
            Err(LifecycleError::MappingAccessDenied)
        );
        let next = lifecycle
            .rotate_mapping_key(&mut connection, NOW + 3)
            .expect("rotate");
        assert_eq!(next, 2);
        lifecycle
            .revoke_mapping_key(&connection, 1, NOW + 4)
            .expect("revoke old key");
        assert_eq!(
            lifecycle.load_mapping_revision(
                &mut connection,
                MAP_ID,
                &MappingAccessContextV1 {
                    access_id: "mapping-access-revoked-key",
                    ..allowed
                },
            ),
            Err(LifecycleError::MappingRevoked)
        );
        let protected_hash: String = connection
            .query_row(
                "SELECT protected_key_sha256 FROM privacy_mapping_keys WHERE key_version=1",
                [],
                |row| row.get(0),
            )
            .expect("key hash");
        lifecycle
            .destroy_mapping_key(&connection, 1, &protected_hash, NOW + 5)
            .expect("destroy key");
        let state: (String, Option<Vec<u8>>) = connection
            .query_row(
                "SELECT state,protected_key FROM privacy_mapping_keys WHERE key_version=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("destroyed state");
        assert_eq!(state, ("destroyed".to_owned(), None));
        assert_eq!(
            lifecycle
                .verify_mapping_access_audit(&connection)
                .expect("verify mapping audit"),
            4
        );
        assert!(connection
            .execute(
                "UPDATE privacy_mapping_access_audit SET allowed=1 WHERE access_id=?1",
                ["mapping-access-denied"],
            )
            .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn mapping_tamper_wrong_key_and_expiry_fail_closed() {
        let (mut connection, lifecycle) = setup_review();
        let summary = lifecycle
            .save_mapping_revision(&mut connection, MAP_ID, "redaction-1", 1, &mapping(), NOW + 1)
            .expect("mapping");
        let context = MappingAccessContextV1 {
            access_id: "tamper-access",
            redaction_id: "redaction-1",
            purpose: "local_mapping_review",
            now_unix: NOW + 2,
            private_mapping_access_authorized: true,
        };
        connection
            .execute(
                "UPDATE privacy_sensitive_mappings SET ciphertext=zeroblob(length(ciphertext))
                 WHERE mapping_id=?1",
                [MAP_ID],
            )
            .expect("tamper ciphertext");
        assert_eq!(
            lifecycle.load_mapping_revision(&mut connection, MAP_ID, &context),
            Err(LifecycleError::Crypto)
        );

        let (mut hash_connection, hash_lifecycle) = setup_review();
        hash_lifecycle
            .save_mapping_revision(
                &mut hash_connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
            .expect("mapping for plaintext hash tamper");
        hash_connection
            .execute(
                "UPDATE privacy_sensitive_mappings SET mapping_revision_sha256=?2
                 WHERE mapping_id=?1",
                params![MAP_ID, sha256_hex(b"wrong mapping plaintext")],
            )
            .expect("tamper mapping plaintext hash");
        assert_eq!(
            hash_lifecycle.load_mapping_revision(
                &mut hash_connection,
                MAP_ID,
                &MappingAccessContextV1 {
                    access_id: "mapping-hash-tamper-access",
                    ..context
                },
            ),
            Err(LifecycleError::Crypto)
        );

        let (mut wrong_connection, wrong_lifecycle) = setup_review();
        wrong_lifecycle
            .save_mapping_revision(
                &mut wrong_connection,
                "map_55555555555555555555555555555555",
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
            .expect("other mapping");
        let wrong_wrapped: (Vec<u8>, String) = wrong_connection
            .query_row(
                "SELECT protected_key,protected_key_sha256 FROM privacy_mapping_keys
                 WHERE key_version=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("wrong key");
        let (mut connection, lifecycle) = setup_review();
        lifecycle
            .save_mapping_revision(&mut connection, MAP_ID, "redaction-1", 1, &mapping(), NOW + 1)
            .expect("mapping");
        connection
            .execute(
                "UPDATE privacy_mapping_keys SET protected_key=?1,protected_key_sha256=?2
                 WHERE key_version=1",
                params![wrong_wrapped.0, wrong_wrapped.1],
            )
            .expect("replace with valid wrong key");
        assert_eq!(
            lifecycle.load_mapping_revision(
                &mut connection,
                MAP_ID,
                &MappingAccessContextV1 {
                    access_id: "wrong-key-access",
                    ..context
                },
            ),
            Err(LifecycleError::Crypto)
        );

        let (mut connection, lifecycle) = setup_review();
        lifecycle
            .save_mapping_revision(&mut connection, MAP_ID, "redaction-1", 1, &mapping(), NOW + 1)
            .expect("mapping");
        assert_eq!(
            lifecycle.load_mapping_revision(
                &mut connection,
                MAP_ID,
                &MappingAccessContextV1 {
                    access_id: "expired-access",
                    now_unix: summary.expires_at_unix,
                    ..context
                },
            ),
            Err(LifecycleError::MappingExpired)
        );
    }

    #[cfg(windows)]
    #[test]
    fn protected_approved_output_is_exactly_bound_listed_revoked_and_retained() {
        let (mut connection, lifecycle) = setup_review();
        let receipt_id = approve_and_receipt(&mut connection);
        let content = b"SYNTHETIC_APPROVED_PROVIDER_RESULT";
        let summary = lifecycle
            .save_approved_output(
                &connection,
                &SaveApprovedOutputV1 {
                    output_id: OUTPUT_ID,
                    redaction_id: "redaction-1",
                    approval_generation_id: &receipt_id,
                    receipt_id: &receipt_id,
                    provider: "provider-synthetic",
                    model: "synthetic-model-v1",
                    purpose: "assistant_chat",
                    approved_payload_sha256: &sha256_hex(b"synthetic approved source"),
                    content,
                    expected_content_sha256: &sha256_hex(content),
                    created_at_unix: NOW + 2,
                    expires_at_unix: NOW + 500,
                },
            )
            .expect("save output");
        assert_eq!(summary.content_sha256, sha256_hex(content));
        let protected: Vec<u8> = connection
            .query_row(
                "SELECT protected_content FROM privacy_approved_outputs WHERE output_id=?1",
                [OUTPUT_ID],
                |row| row.get(0),
            )
            .expect("protected output");
        assert!(!protected.windows(content.len()).any(|window| window == content));
        let context = ApprovedOutputAccessContextV1 {
            redaction_id: "redaction-1",
            approval_generation_id: &receipt_id,
            receipt_id: &receipt_id,
            provider: "provider-synthetic",
            model: "synthetic-model-v1",
            purpose: "assistant_chat",
            approved_payload_sha256: &sha256_hex(b"synthetic approved source"),
            now_unix: NOW + 3,
            approved_output_access_authorized: true,
        };
        let loaded = lifecycle
            .load_approved_output(&connection, OUTPUT_ID, &context)
            .expect("load output");
        assert_eq!(loaded.content, content);
        assert!(!format!("{loaded:?}").contains("SYNTHETIC_APPROVED_PROVIDER_RESULT"));
        assert_eq!(lifecycle.list_approved_outputs(&connection, "redaction-1").expect("list").len(), 1);
        assert_eq!(
            lifecycle.load_approved_output(
                &connection,
                OUTPUT_ID,
                &ApprovedOutputAccessContextV1 {
                    model: "wrong-model",
                    ..context.clone()
                },
            ),
            Err(LifecycleError::MappingAccessDenied)
        );
        lifecycle
            .revoke_approved_output(&connection, OUTPUT_ID, NOW + 4)
            .expect("revoke output");
        assert_eq!(
            lifecycle.load_approved_output(&connection, OUTPUT_ID, &context),
            Err(LifecycleError::MappingRevoked)
        );
    }

    #[cfg(windows)]
    #[test]
    fn retention_prepare_recovery_legal_hold_and_tamper_journal_are_verified() {
        let (mut connection, lifecycle) = setup_review();
        let current = lifecycle.retention_policy(&connection).expect("policy");
        lifecycle
            .set_retention_policy(
                &mut connection,
                &RetentionPolicyV1 {
                    policy_id: "short-synthetic-retention".to_owned(),
                    review_retention_seconds: 10,
                    mapping_retention_seconds: 10,
                    receipt_grace_seconds: 0,
                    backup_retention_seconds: 20,
                    revision: current.revision + 1,
                    updated_at_unix: NOW + 1,
                },
            )
            .expect("short policy");
        lifecycle
            .save_mapping_revision(&mut connection, MAP_ID, "redaction-1", 1, &mapping(), NOW + 2)
            .expect("mapping");
        PrivacyStore::save_review_draft(
            &connection,
            &SaveReviewDraft {
                redaction_id: "redaction-2",
                material_id: "material-1",
                extraction_sha256: &sha256_hex(b"synthetic extraction sibling"),
                redacted_content_sha256: &sha256_hex(b"synthetic redacted sibling"),
                policy_id: "cn-legal-default",
                policy_version: 1,
                detector_version: REDACTION_VERSION,
                unresolved_high_risk_count: 0,
                review_payload_plaintext: b"synthetic protected sibling review",
            },
        )
        .expect("sibling review");
        lifecycle
            .bind_redaction_retention(&connection, "redaction-2", NOW + 2)
            .expect("retain sibling");
        lifecycle
            .set_legal_hold(&connection, "redaction-2", true, NOW + 3)
            .expect("hold sibling");
        lifecycle
            .set_legal_hold(&connection, "redaction-1", true, NOW + 3)
            .expect("legal hold");
        assert_eq!(
            lifecycle
                .prepare_retention_sweep(&mut connection, CLEANUP_ID, NOW + 20)
                .expect("prepare held"),
            0
        );
        let reports = lifecycle
            .recover_prepared_sweeps(&mut connection, NOW + 21)
            .expect("recover held");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].removed, 0);
        assert_eq!(reports[0].erasure_disclosure, LOGICAL_ERASURE_DISCLOSURE);
        lifecycle
            .set_legal_hold(&connection, "redaction-1", false, NOW + 22)
            .expect("release hold");
        let second = "cln_66666666666666666666666666666666";
        lifecycle
            .prepare_retention_sweep(&mut connection, second, NOW + 23)
            .expect("prepare cleanup");
        lifecycle
            .set_legal_hold(&connection, "redaction-1", true, NOW + 24)
            .expect("late legal hold");
        assert_eq!(
            lifecycle
                .revalidate_prepared_retention_sweep_for_external_invalidation(
                    &mut connection,
                    second,
                    NOW + 25,
                )
                .expect("late hold produces a safe terminal decision"),
            None
        );
        let (late_hold_state, late_hold_error): (String, Option<String>) = connection
            .query_row(
                "SELECT state,error_code FROM privacy_cleanup_journal WHERE cleanup_id=?1",
                [second],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("late-hold cleanup state");
        assert_eq!(late_hold_state, "failed");
        assert_eq!(
            late_hold_error.as_deref(),
            Some(RETENTION_PRECONDITION_CHANGED_ERROR_CODE)
        );
        assert!(connection
            .query_row(
                "SELECT 1 FROM privacy_redactions WHERE redaction_id='redaction-1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .expect("late-held redaction state")
            .is_some());
        lifecycle
            .set_legal_hold(&connection, "redaction-1", false, NOW + 26)
            .expect("release late hold");
        let third = "cln_77777777777777777777777777777777";
        lifecycle
            .prepare_retention_sweep(&mut connection, third, NOW + 27)
            .expect("prepare final cleanup");
        let report = lifecycle
            .commit_retention_sweep(&mut connection, third, NOW + 28)
            .expect("commit cleanup");
        assert!(report.removed >= 2);
        assert_eq!(lifecycle.verify_cleanup_journal(&connection).expect("journal"), 3);
        let sibling_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_redactions
                 WHERE redaction_id='redaction-2' AND material_id='material-1'",
                [],
                |row| row.get(0),
            )
            .expect("retained sibling");
        assert_eq!(sibling_count, 1);
        assert_eq!(
            lifecycle.load_mapping_revision(
                &mut connection,
                MAP_ID,
                &MappingAccessContextV1 {
                    access_id: "after-cleanup",
                    redaction_id: "redaction-1",
                    purpose: "local_mapping_review",
                    now_unix: NOW + 25,
                    private_mapping_access_authorized: true,
                },
            ),
            Err(LifecycleError::MappingNotAvailable)
        );
        assert!(connection
            .execute(
                "UPDATE privacy_cleanup_journal SET removed_count=999 WHERE cleanup_id=?1",
                [second],
            )
            .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn late_legal_hold_cancels_a_mapping_only_prepared_sweep_before_external_invalidation() {
        let (mut connection, lifecycle) = setup_review();
        let current = lifecycle.retention_policy(&connection).expect("policy");
        lifecycle
            .set_retention_policy(
                &mut connection,
                &RetentionPolicyV1 {
                    policy_id: "mapping-first-synthetic-retention".to_owned(),
                    review_retention_seconds: 100,
                    mapping_retention_seconds: 10,
                    receipt_grace_seconds: 0,
                    backup_retention_seconds: 200,
                    revision: current.revision + 1,
                    updated_at_unix: NOW + 1,
                },
            )
            .expect("mapping-first policy");
        lifecycle
            .save_mapping_revision(&mut connection, MAP_ID, "redaction-1", 1, &mapping(), NOW + 2)
            .expect("mapping");
        assert_eq!(
            lifecycle
                .prepare_retention_sweep(&mut connection, CLEANUP_ID, NOW + 20)
                .expect("prepare mapping-only cleanup"),
            1
        );
        lifecycle
            .set_legal_hold(&connection, "redaction-1", true, NOW + 21)
            .expect("late legal hold");
        assert_eq!(
            lifecycle
                .revalidate_prepared_retention_sweep_for_external_invalidation(
                    &mut connection,
                    CLEANUP_ID,
                    NOW + 22,
                )
                .expect("mapping-only late hold produces a safe terminal decision"),
            None
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT state FROM privacy_cleanup_journal WHERE cleanup_id=?1",
                    [CLEANUP_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("cleanup state"),
            "failed"
        );
        assert!(connection
            .query_row(
                "SELECT 1 FROM privacy_sensitive_mappings WHERE mapping_id=?1",
                [MAP_ID],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .expect("held mapping state")
            .is_some());
    }

    #[cfg(windows)]
    #[test]
    fn encrypted_backup_round_trip_tamper_wrong_environment_expiry_revoke_and_hardlink() {
        let (mut connection, lifecycle) = setup_review();
        lifecycle
            .save_mapping_revision(&mut connection, MAP_ID, "redaction-1", 1, &mapping(), NOW + 1)
            .expect("mapping");
        let directory = tempfile::tempdir().expect("backup directory");
        let store = EncryptedPrivacyBackupStore::initialize(directory.path()).expect("backup store");
        let exported = store
            .export_database(
                &mut connection,
                &lifecycle,
                &BackupExportRequestV1 {
                    backup_id: BACKUP_ID,
                    created_at_unix: NOW + 2,
                    expires_at_unix: Some(NOW + 100),
                },
            )
            .expect("export");
        let backup_path = store.backup_path(BACKUP_ID).expect("path");
        let envelope_bytes = fs::read(&backup_path).expect("envelope");
        assert!(!envelope_bytes
            .windows(b"SYNTHETIC_PRIVATE_NAME_CANARY".len())
            .any(|window| window == b"SYNTHETIC_PRIVATE_NAME_CANARY"));
        let context = BackupVerificationContextV1 {
            expected_workspace_instance_id: lifecycle.workspace_instance_id(),
            expected_key_epoch: lifecycle.current_key_epoch(&connection).expect("epoch"),
            now_unix: NOW + 3,
        };
        assert_eq!(store.verify_backup(&connection, BACKUP_ID, &context).expect("verify"), exported);
        assert_eq!(
            store
                .verify_detached_backup(BACKUP_ID, &context)
                .expect("detached verify"),
            exported
        );
        let mut detached_restore =
            Connection::open_in_memory().expect("detached restore database");
        store
            .restore_detached_into_empty_database(&mut detached_restore, BACKUP_ID, &context)
            .expect("detached restore");
        PrivacyLifecycle::open(&detached_restore, workspace()).expect("open detached restore");
        let mut restored = Connection::open_in_memory().expect("restored database");
        store
            .restore_into_empty_database(&connection, &mut restored, BACKUP_ID, &context)
            .expect("restore");
        let restored_lifecycle = PrivacyLifecycle::open(&restored, workspace()).expect("open restored");
        let loaded = restored_lifecycle
            .load_mapping_revision(
                &mut restored,
                MAP_ID,
                &MappingAccessContextV1 {
                    access_id: "restored-access",
                    redaction_id: "redaction-1",
                    purpose: "local_mapping_review",
                    now_unix: NOW + 4,
                    private_mapping_access_authorized: true,
                },
            )
            .expect("restored mapping");
        assert_eq!(loaded, mapping());
        assert_eq!(
            store.verify_backup(
                &connection,
                BACKUP_ID,
                &BackupVerificationContextV1 {
                    expected_workspace_instance_id: &other_workspace(),
                    ..context
                },
            ),
            Err(LifecycleError::EnvironmentMismatch)
        );
        assert_eq!(
            store.verify_backup(
                &connection,
                BACKUP_ID,
                &BackupVerificationContextV1 {
                    now_unix: NOW + 100,
                    ..context
                },
            ),
            Err(LifecycleError::BackupExpired)
        );

        let hardlink = directory.path().join("backup-hardlink.lavbackup");
        fs::hard_link(&backup_path, &hardlink).expect("hardlink");
        assert_eq!(
            store.verify_backup(&connection, BACKUP_ID, &context),
            Err(LifecycleError::UnsafeFilesystem)
        );
        fs::remove_file(&hardlink).expect("remove hardlink");

        let mut tampered = envelope_bytes.clone();
        let middle = tampered.len() / 2;
        tampered[middle] ^= 0x01;
        fs::write(&backup_path, &tampered).expect("tamper");
        assert_eq!(
            store.verify_backup(&connection, BACKUP_ID, &context),
            Err(LifecycleError::BackupTampered)
        );
        fs::write(&backup_path, &envelope_bytes).expect("restore envelope");

        let state_path = store.backup_state_path(BACKUP_ID).expect("state path");
        let state_bytes = fs::read(&state_path).expect("protected state");
        let state_hardlink = directory.path().join("state-hardlink.dpapi");
        fs::hard_link(&state_path, &state_hardlink).expect("state hardlink");
        assert_eq!(
            store.verify_detached_backup(BACKUP_ID, &context),
            Err(LifecycleError::UnsafeFilesystem)
        );
        fs::remove_file(&state_hardlink).expect("remove state hardlink");
        let mut tampered_state = state_bytes.clone();
        let state_middle = tampered_state.len() / 2;
        tampered_state[state_middle] ^= 0x80;
        fs::write(&state_path, tampered_state).expect("tamper protected state");
        assert_eq!(
            store.verify_detached_backup(BACKUP_ID, &context),
            Err(LifecycleError::ProtectedBlob)
        );
        fs::write(&state_path, state_bytes).expect("restore protected state");
        store
            .revoke_backup(&connection, BACKUP_ID, NOW + 5)
            .expect("revoke backup");
        connection
            .execute(
                "UPDATE privacy_backup_registry SET state='active',revoked_at_unix=NULL
                 WHERE backup_id=?1",
                [BACKUP_ID],
            )
            .expect("simulate crash before registry revoke");
        store
            .revoke_backup(&connection, BACKUP_ID, NOW + 6)
            .expect("finish revocation after retry");
        store
            .revoke_backup(&connection, BACKUP_ID, NOW + 7)
            .expect("idempotent revoke");
        assert_eq!(
            store.verify_backup(&connection, BACKUP_ID, &context),
            Err(LifecycleError::BackupRevoked)
        );
        assert_eq!(
            store.verify_detached_backup(BACKUP_ID, &context),
            Err(LifecycleError::BackupRevoked)
        );
        assert_eq!(
            store.verify_backup(&connection, "bkp_../../escape", &context),
            Err(LifecycleError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    fn portable_backup_bundle_import_restores_and_rejects_tamper_environment_and_duplicate() {
        let (mut connection, lifecycle) = setup_review();
        lifecycle
            .save_mapping_revision(&mut connection, MAP_ID, "redaction-1", 1, &mapping(), NOW + 1)
            .expect("mapping");
        let source_directory = tempfile::tempdir().expect("source backup directory");
        let source_store =
            EncryptedPrivacyBackupStore::initialize(source_directory.path()).expect("source store");
        source_store
            .export_database(
                &mut connection,
                &lifecycle,
                &BackupExportRequestV1 {
                    backup_id: BACKUP_ID,
                    created_at_unix: NOW + 2,
                    expires_at_unix: Some(NOW + 100),
                },
            )
            .expect("encrypted backup");
        let context = BackupVerificationContextV1 {
            expected_workspace_instance_id: lifecycle.workspace_instance_id(),
            expected_key_epoch: lifecycle.current_key_epoch(&connection).expect("epoch"),
            now_unix: NOW + 3,
        };
        let bundle = source_store
            .export_portable_bundle(BACKUP_ID, &context)
            .expect("portable bundle");
        assert!(!bundle
            .windows(b"SYNTHETIC_PRIVATE_NAME_CANARY".len())
            .any(|window| window == b"SYNTHETIC_PRIVATE_NAME_CANARY"));

        let destination_directory = tempfile::tempdir().expect("destination directory");
        let destination_store = EncryptedPrivacyBackupStore::initialize(destination_directory.path())
            .expect("destination store");
        destination_store
            .import_portable_bundle(&bundle, &context)
            .expect("import");
        assert!(destination_store
            .import_portable_bundle(&bundle, &context)
            .is_err());
        let mut restored = Connection::open_in_memory().expect("restore target");
        destination_store
            .restore_detached_into_empty_database(&mut restored, BACKUP_ID, &context)
            .expect("restore imported backup");
        let restored_lifecycle =
            PrivacyLifecycle::open(&restored, workspace()).expect("restored lifecycle");
        assert_eq!(
            restored_lifecycle
                .load_mapping_revision(
                    &mut restored,
                    MAP_ID,
                    &MappingAccessContextV1 {
                        access_id: "portable-restore-access",
                        redaction_id: "redaction-1",
                        purpose: "local_mapping_review",
                        now_unix: NOW + 4,
                        private_mapping_access_authorized: true,
                    },
                )
                .expect("mapping restored"),
            mapping()
        );

        let wrong_directory = tempfile::tempdir().expect("wrong environment directory");
        let wrong_store =
            EncryptedPrivacyBackupStore::initialize(wrong_directory.path()).expect("wrong store");
        assert_eq!(
            wrong_store.import_portable_bundle(
                &bundle,
                &BackupVerificationContextV1 {
                    expected_workspace_instance_id: &other_workspace(),
                    ..context
                },
            ),
            Err(LifecycleError::EnvironmentMismatch)
        );
        let mut tampered = bundle;
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        assert!(wrong_store.import_portable_bundle(&tampered, &context).is_err());
    }

    #[test]
    fn backup_staging_filename_matcher_accepts_only_exact_private_formats() {
        let id = "bkp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        for name in [
            format!("{id}-1111111111111111-sqlite"),
            format!("{id}-1111111111111111-restore.sqlite"),
            format!("{id}-verify-1111111111111111.sqlite"),
            format!("{id}-write-1111111111111111.tmp"),
            format!("{id}-1111111111111111-sqlite-wal"),
            format!("{id}-1111111111111111-restore.sqlite-shm"),
        ] {
            assert!(is_exact_backup_staging_name(&name), "{name}");
        }
        for name in [
            "unrelated.sqlite",
            "bkp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1111111111111111.sqlite",
            "bkp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-1111111111111111-sqlite",
            "bkp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-111111111111111-sqlite",
            "bkp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-write-1111111111111111.exe",
            "bkp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-verify-1111111111111111.sqlite.exe",
        ] {
            assert!(!is_exact_backup_staging_name(name), "{name}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn backup_store_startup_cleans_exact_residuals_and_rejects_unknown_or_hardlinked_files() {
        let directory = tempfile::tempdir().expect("backup directory");
        EncryptedPrivacyBackupStore::initialize(directory.path()).expect("initialize store");
        let staging = directory.path().join(".staging");
        let exact = staging.join(
            "bkp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1111111111111111-restore.sqlite",
        );
        fs::write(&exact, b"synthetic residual").expect("write exact residual");
        EncryptedPrivacyBackupStore::open(directory.path()).expect("clean exact residual");
        assert!(!exact.exists());

        let unknown = staging.join("unknown.sqlite");
        fs::write(&unknown, b"synthetic unknown").expect("write unknown residual");
        assert!(matches!(
            EncryptedPrivacyBackupStore::open(directory.path()),
            Err(LifecycleError::UnsafeFilesystem)
        ));
        fs::remove_file(&unknown).expect("remove unknown residual");

        let hardlinked = staging.join(
            "bkp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-2222222222222222-sqlite",
        );
        let alias = directory.path().join("synthetic-hardlink");
        fs::write(&hardlinked, b"synthetic hardlinked residual").expect("write residual");
        fs::hard_link(&hardlinked, &alias).expect("create hardlink");
        assert!(matches!(
            EncryptedPrivacyBackupStore::open(directory.path()),
            Err(LifecycleError::UnsafeFilesystem)
        ));
        fs::remove_file(alias).expect("remove hardlink");
        fs::remove_file(hardlinked).expect("remove residual");
    }

    #[cfg(windows)]
    #[test]
    fn backup_valid_wrong_key_and_dpapi_wrapper_tamper_fail_closed() {
        let (mut connection, lifecycle) = setup_review();
        let directory = tempfile::tempdir().expect("backup directory");
        let store = EncryptedPrivacyBackupStore::initialize(directory.path()).expect("backup store");
        store
            .export_database(
                &mut connection,
                &lifecycle,
                &BackupExportRequestV1 {
                    backup_id: BACKUP_ID,
                    created_at_unix: NOW + 2,
                    expires_at_unix: Some(NOW + 100),
                },
            )
            .expect("export");
        let path = store.backup_path(BACKUP_ID).expect("path");
        let original = fs::read(&path).expect("envelope");
        let mut envelope: BackupEnvelopeV1 =
            strict_json_v1_from_slice(&original).expect("parse envelope");
        let wrong_key = SecretKey32::generate().expect("wrong key");
        let wrong_wrapped = wrap_case_key(&wrong_key).expect("wrap wrong key");
        envelope.wrapped_data_key_base64 = BASE64_STANDARD.encode(&wrong_wrapped);
        envelope.wrapped_data_key_sha256 = sha256_hex(&wrong_wrapped);
        let wrong_bytes = canonical_json_v1(&envelope).expect("wrong envelope");
        fs::write(&path, &wrong_bytes).expect("write wrong envelope");
        connection
            .execute(
                "UPDATE privacy_backup_registry SET envelope_sha256=?2 WHERE backup_id=?1",
                params![BACKUP_ID, sha256_hex(&wrong_bytes)],
            )
            .expect("update registry hash");
        let context = BackupVerificationContextV1 {
            expected_workspace_instance_id: lifecycle.workspace_instance_id(),
            expected_key_epoch: lifecycle.current_key_epoch(&connection).expect("epoch"),
            now_unix: NOW + 3,
        };
        assert!(matches!(
            store.verify_backup(&connection, BACKUP_ID, &context),
            Err(LifecycleError::Crypto | LifecycleError::ProtectedBlob)
        ));

        envelope.wrapped_data_key_base64 = BASE64_STANDARD.encode([0_u8; 128]);
        envelope.wrapped_data_key_sha256 = sha256_hex(&[0_u8; 128]);
        let corrupt_wrapper = canonical_json_v1(&envelope).expect("corrupt envelope");
        fs::write(&path, &corrupt_wrapper).expect("write corrupt wrapper");
        connection
            .execute(
                "UPDATE privacy_backup_registry SET envelope_sha256=?2 WHERE backup_id=?1",
                params![BACKUP_ID, sha256_hex(&corrupt_wrapper)],
            )
            .expect("update corrupt registry hash");
        assert!(matches!(
            store.verify_backup(&connection, BACKUP_ID, &context),
            Err(LifecycleError::ProtectedBlob | LifecycleError::Crypto)
        ));
    }
}
