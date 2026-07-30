#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::{
        DestinationKind, DestinationScope, PrivacyStore, ReceiptSigner, RedactionReceiptClaims,
        RegisterPrivacyMaterial, ReviewState, SaveReviewDraft, LOCAL_PROTECTION_SCHEME,
        PRIVACY_STORE_SCHEMA_VERSION, REDACTION_VERSION,
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

    fn set_privacy_store_schema_version(connection: &Connection, version: i64) {
        let changed = connection
            .execute(
                "UPDATE privacy_schema_metadata SET value=?1 WHERE key='schema_version'",
                [version.to_string()],
            )
            .expect("set synthetic privacy schema version");
        assert_eq!(changed, 1);
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
    fn fresh_privacy_store_initializes_lifecycle_risk_and_consumption_schema_and_rejects_future_schema(
    ) {
        let connection = Connection::open_in_memory().expect("database");
        PrivacyStore::initialize(&connection).expect("initialize fresh store");
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
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
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
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
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
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
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
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
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
        assert!(!protected
            .windows(content.len())
            .any(|window| window == content));
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
        assert_eq!(
            lifecycle
                .list_approved_outputs(&connection, "redaction-1")
                .expect("list")
                .len(),
            1
        );
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
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 2,
            )
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
        assert_eq!(
            lifecycle
                .verify_cleanup_journal(&connection)
                .expect("journal"),
            3
        );
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
    fn final_generation_cleanup_retains_only_audited_non_sensitive_material_identity() {
        let (mut connection, lifecycle) = setup_review();
        let display_name = b"synthetic-private-filename.pdf";
        let protected_display_name = protect_local(display_name).expect("protected display name");
        connection
            .execute(
                "UPDATE privacy_materials
                 SET protected_display_name=?2,display_name_sha256=?3,
                     display_name_protection_scheme=?4,source_kind='local_review',
                     row_version=row_version+1
                 WHERE material_id=?1",
                params![
                    "material-1",
                    protected_display_name,
                    sha256_hex(display_name),
                    LOCAL_PROTECTION_SCHEME,
                ],
            )
            .expect("seed protected display name");
        connection
            .execute(
                "INSERT INTO case_material_migration_ledger(
                    migration_id,source_store,source_table,source_key,source_fingerprint,
                    target_material_id,target_redaction_id,assigned_generation_number,
                    result_state,error_code,started_at,completed_at
                 ) VALUES(
                    'case-material-unification-v1','privacy-workflow.sqlite',
                    'privacy_redactions','redaction-1',?1,
                    'material-1','redaction-1',1,'migrated',NULL,
                    CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
                 )",
                [sha256_hex(b"synthetic migration source")],
            )
            .expect("migration ledger");
        let current = lifecycle.retention_policy(&connection).expect("policy");
        lifecycle
            .set_retention_policy(
                &mut connection,
                &RetentionPolicyV1 {
                    policy_id: "short-final-generation-retention".to_owned(),
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
            .bind_redaction_retention(&connection, "redaction-1", NOW + 2)
            .expect("retention binding");
        let cleanup_id = "cln_88888888888888888888888888888888";
        lifecycle
            .run_retention_sweep(&mut connection, cleanup_id, NOW + 20)
            .expect("final-generation cleanup");

        let tombstone = connection
            .query_row(
                "SELECT project_id,source_sha256,source_kind,state,deleted_at IS NOT NULL,
                        protected_display_name,display_name_sha256,
                        display_name_protection_scheme
                 FROM privacy_materials WHERE material_id='material-1'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, Option<Vec<u8>>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .expect("retained tombstone");
        assert_eq!(tombstone.0.as_deref(), Some("project-1"));
        assert_eq!(
            tombstone.1.as_deref(),
            Some(sha256_hex(b"synthetic source").as_str())
        );
        assert_eq!(tombstone.2, "local_review");
        assert_eq!(tombstone.3, "revoked");
        assert!(tombstone.4);
        assert_eq!((tombstone.5, tombstone.6, tombstone.7), (None, None, None));
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM case_material_migration_ledger",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("ledger count"),
            1
        );
        assert!(lifecycle
            .redaction_cleanup_is_authorized(&connection, "redaction-1", "material-1", 1,)
            .expect("exact erasure evidence"));
        assert!(lifecycle
            .material_cleanup_is_authorized(&connection, "material-1")
            .expect("material erasure evidence"));
        assert!(connection
            .execute(
                "UPDATE privacy_cleanup_candidates
                 SET expected_sha256=?2
                 WHERE cleanup_id=?1 AND target_kind='redaction'",
                params![cleanup_id, sha256_hex(b"tampered candidate")],
            )
            .is_err());
        assert!(connection
            .execute(
                "DELETE FROM privacy_cleanup_candidates WHERE cleanup_id=?1",
                [cleanup_id],
            )
            .is_err());
        assert!(connection
            .execute(
                "INSERT OR REPLACE INTO privacy_cleanup_journal(
                    cleanup_id,state,policy_revision,started_at_unix,completed_at_unix,
                    candidate_count,removed_count,keys_destroyed,error_code,
                    previous_event_hash,event_hash,erasure_disclosure
                 ) SELECT cleanup_id,state,policy_revision,started_at_unix,completed_at_unix,
                          candidate_count,removed_count,keys_destroyed,error_code,
                          previous_event_hash,event_hash,erasure_disclosure
                   FROM privacy_cleanup_journal WHERE cleanup_id=?1",
                [cleanup_id],
            )
            .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn final_cleanup_does_not_retain_an_unjournaled_revoked_material() {
        let (mut connection, lifecycle) = setup_review();
        connection
            .execute(
                "UPDATE privacy_materials
                 SET state='revoked',deleted_at=CURRENT_TIMESTAMP,row_version=row_version+1
                 WHERE material_id='material-1'",
                [],
            )
            .expect("seed non-project-deletion revocation");
        let current = lifecycle.retention_policy(&connection).expect("policy");
        lifecycle
            .set_retention_policy(
                &mut connection,
                &RetentionPolicyV1 {
                    policy_id: "unjournaled-revocation-retention".to_owned(),
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
            .bind_redaction_retention(&connection, "redaction-1", NOW + 2)
            .expect("retention binding");
        lifecycle
            .run_retention_sweep(
                &mut connection,
                "cln_89898989898989898989898989898989",
                NOW + 20,
            )
            .expect("cleanup unjournaled revocation");

        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_materials WHERE material_id='material-1'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("material count"),
            0
        );
        assert!(!lifecycle
            .material_cleanup_is_authorized(&connection, "material-1")
            .expect("no retained tombstone authorization"));
        assert!(lifecycle
            .redaction_cleanup_is_authorized(&connection, "redaction-1", "material-1", 1,)
            .expect("exact redaction erasure remains authorized"));
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_hash_chain_follows_finalization_order_not_prepared_row_order() {
        let (mut connection, lifecycle) = setup_review();
        let first = "cln_99999999999999999999999999999999";
        let second = "cln_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(
            lifecycle
                .prepare_retention_sweep(&mut connection, first, NOW + 1)
                .expect("prepare first"),
            0
        );
        assert_eq!(
            lifecycle
                .prepare_retention_sweep(&mut connection, second, NOW + 2)
                .expect("prepare second"),
            0
        );
        lifecycle
            .commit_retention_sweep(&mut connection, second, NOW + 3)
            .expect("commit later row first");
        lifecycle
            .commit_retention_sweep(&mut connection, first, NOW + 4)
            .expect("commit earlier row second");
        assert_eq!(
            lifecycle
                .verify_cleanup_journal(&connection)
                .expect("finalization-ordered chain"),
            2
        );
    }

    #[cfg(windows)]
    #[test]
    fn legacy_cleanup_journal_verifies_but_cannot_authorize_missing_migration_target() {
        let (connection, lifecycle) = setup_review();
        let cleanup_id = "cln_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let expected_sha256 = sha256_hex(b"legacy cleanup candidate");
        connection
            .execute(
                "INSERT INTO privacy_cleanup_journal(
                    cleanup_id,state,policy_revision,started_at_unix,completed_at_unix,
                    candidate_count,removed_count,keys_destroyed,error_code,
                    previous_event_hash,event_hash,erasure_disclosure
                 ) VALUES(?1,'prepared',1,?2,NULL,1,0,0,NULL,'','',?3)",
                params![
                    cleanup_id,
                    i64::try_from(NOW).expect("small time"),
                    LOGICAL_ERASURE_DISCLOSURE
                ],
            )
            .expect("legacy prepared journal");
        connection
            .execute(
                "INSERT INTO privacy_cleanup_candidates(
                    cleanup_id,target_kind,target_id,expected_sha256,state
                 ) VALUES(?1,'redaction','redaction-1',?2,'pending')",
                params![cleanup_id, expected_sha256],
            )
            .expect("legacy candidate");
        connection
            .execute(
                "UPDATE privacy_cleanup_candidates SET state='removed'
                 WHERE cleanup_id=?1 AND target_kind='redaction'
                   AND target_id='redaction-1'",
                [cleanup_id],
            )
            .expect("legacy removed candidate");
        let legacy_row = CleanupJournalRow {
            cleanup_id: cleanup_id.to_owned(),
            state: "committed".to_owned(),
            policy_revision: 1,
            started_at_unix: i64::try_from(NOW).expect("small time"),
            completed_at_unix: Some(i64::try_from(NOW + 1).expect("small time")),
            candidate_count: 1,
            removed_count: 1,
            keys_destroyed: 0,
            error_code: None,
            previous_event_hash: String::new(),
            event_hash: String::new(),
            erasure_disclosure: LOGICAL_ERASURE_DISCLOSURE.to_owned(),
        };
        let event_hash = cleanup_event_hash(&legacy_row).expect("legacy event hash");
        connection
            .execute(
                "UPDATE privacy_cleanup_journal
                 SET state='committed',completed_at_unix=?2,removed_count=1,
                     previous_event_hash='',event_hash=?3
                 WHERE cleanup_id=?1 AND state='prepared'",
                params![
                    cleanup_id,
                    i64::try_from(NOW + 1).expect("small time"),
                    event_hash
                ],
            )
            .expect("finalize legacy journal");
        assert_eq!(
            lifecycle
                .verify_cleanup_journal(&connection)
                .expect("legacy chain remains readable"),
            1
        );
        assert!(!lifecycle
            .redaction_cleanup_is_authorized(&connection, "redaction-1", "material-1", 1,)
            .expect("legacy evidence is not v2 authorization"));
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
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 2,
            )
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
    fn pre_migration_backup_records_and_authenticates_actual_v4_while_normal_export_rejects_it() {
        let (mut connection, lifecycle) = setup_review();
        lifecycle
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
            .expect("complete lifecycle state");
        set_privacy_store_schema_version(&connection, 4);
        let directory = tempfile::tempdir().expect("backup directory");
        let store =
            EncryptedPrivacyBackupStore::initialize(directory.path()).expect("backup store");
        let normal_backup_id = "bkp_44444444444444444444444444444444";
        let request = BackupExportRequestV1 {
            backup_id: normal_backup_id,
            created_at_unix: NOW + 2,
            expires_at_unix: Some(NOW + 100),
        };
        assert_eq!(
            store.export_database(&mut connection, &lifecycle, &request),
            Err(LifecycleError::UnsupportedSchema)
        );
        assert!(!store
            .backup_path(normal_backup_id)
            .expect("normal backup path")
            .exists());

        let request = BackupExportRequestV1 {
            backup_id: BACKUP_ID,
            ..request
        };
        let exported = store
            .export_pre_migration_database(
                &mut connection,
                &lifecycle,
                &request,
                &PreMigrationBackupExportContextV1 {
                    expected_privacy_store_schema_version: 4,
                },
            )
            .expect("export complete v4 pre-migration backup");
        assert_eq!(exported.privacy_store_schema_version, 4);
        let envelope_bytes =
            fs::read(store.backup_path(BACKUP_ID).expect("backup path")).expect("envelope");
        let envelope: BackupEnvelopeV1 =
            strict_json_v1_from_slice(&envelope_bytes).expect("strict envelope");
        assert_eq!(envelope.privacy_store_schema_version, 4);

        let key_epoch = lifecycle
            .current_key_epoch(&connection)
            .expect("current key epoch");
        let pre_migration_context = PreMigrationBackupVerificationContextV1 {
            expected_workspace_instance_id: lifecycle.workspace_instance_id(),
            expected_key_epoch: key_epoch,
            expected_privacy_store_schema_version: 4,
            now_unix: NOW + 3,
        };
        assert_eq!(
            store
                .verify_pre_migration_backup(&connection, BACKUP_ID, &pre_migration_context)
                .expect("verify registered v4 backup"),
            exported
        );
        assert_eq!(
            store
                .verify_detached_pre_migration_backup(BACKUP_ID, &pre_migration_context)
                .expect("verify detached v4 backup"),
            exported
        );
        let portable = store
            .export_pre_migration_portable_bundle(BACKUP_ID, &pre_migration_context)
            .expect("export v4 portable bundle");
        assert!(!portable.is_empty());

        let normal_context = BackupVerificationContextV1 {
            expected_workspace_instance_id: lifecycle.workspace_instance_id(),
            expected_key_epoch: key_epoch,
            now_unix: NOW + 3,
        };
        assert_eq!(
            store.verify_backup(&connection, BACKUP_ID, &normal_context),
            Err(LifecycleError::EnvironmentMismatch)
        );
        assert_eq!(
            store.export_portable_bundle(BACKUP_ID, &normal_context),
            Err(LifecycleError::EnvironmentMismatch)
        );
        let restore_directory = tempfile::tempdir().expect("coordinated restore directory");
        let restore_store = EncryptedPrivacyBackupStore::initialize(restore_directory.path())
            .expect("coordinated restore store");
        assert_eq!(
            restore_store.import_portable_bundle(&portable, &normal_context),
            Err(LifecycleError::EnvironmentMismatch)
        );
        let imported = restore_store
            .import_portable_bundle_for_coordinated_pre_migration_restore(
                &portable,
                &normal_context,
            )
            .expect("coordinated application restore authenticates exact v4");
        assert_eq!(imported.privacy_store_schema_version, 4);
        assert_eq!(
            restore_store
                .import_portable_bundle_for_coordinated_pre_migration_restore(
                    &portable,
                    &normal_context,
                )
                .expect("coordinated restore import is exact-idempotent"),
            imported
        );
        let mut restored = Connection::open_in_memory().expect("legacy restore target");
        let restored_backup = restore_store
            .restore_detached_for_coordinated_pre_migration_restore(
                &mut restored,
                BACKUP_ID,
                imported.privacy_store_schema_version,
                &normal_context,
            )
            .expect("restore exact v4 without schema evolution");
        assert_eq!(restored_backup, imported);
        assert_eq!(
            read_privacy_store_schema_version(&restored).expect("restored schema marker"),
            4
        );
        assert_eq!(
            PrivacyStore::preflight_schema(&restored).expect("restored legacy preflight"),
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 4 }
        );
        let mut wrong_schema_target =
            Connection::open_in_memory().expect("wrong-schema restore target");
        assert_eq!(
            restore_store.restore_detached_for_coordinated_pre_migration_restore(
                &mut wrong_schema_target,
                BACKUP_ID,
                3,
                &normal_context,
            ),
            Err(LifecycleError::EnvironmentMismatch)
        );
        let mut future_schema_target =
            Connection::open_in_memory().expect("future-schema restore target");
        assert_eq!(
            restore_store.restore_detached_for_coordinated_pre_migration_restore(
                &mut future_schema_target,
                BACKUP_ID,
                PRIVACY_STORE_SCHEMA_VERSION + 1,
                &normal_context,
            ),
            Err(LifecycleError::UnsupportedSchema)
        );
        assert_eq!(
            store.verify_pre_migration_backup(
                &connection,
                BACKUP_ID,
                &PreMigrationBackupVerificationContextV1 {
                    expected_privacy_store_schema_version: 3,
                    ..pre_migration_context
                },
            ),
            Err(LifecycleError::EnvironmentMismatch)
        );
        assert_eq!(
            store.verify_pre_migration_backup(
                &connection,
                BACKUP_ID,
                &PreMigrationBackupVerificationContextV1 {
                    expected_workspace_instance_id: &other_workspace(),
                    ..pre_migration_context
                },
            ),
            Err(LifecycleError::EnvironmentMismatch)
        );
        assert_eq!(
            store.verify_pre_migration_backup(
                &connection,
                BACKUP_ID,
                &PreMigrationBackupVerificationContextV1 {
                    expected_key_epoch: key_epoch + 1,
                    ..pre_migration_context
                },
            ),
            Err(LifecycleError::EnvironmentMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn pre_migration_backup_rejects_invalid_empty_future_mismatched_and_damaged_sources() {
        let invalid_versions = [0, PRIVACY_STORE_SCHEMA_VERSION, 6];
        for invalid_version in invalid_versions {
            let (mut connection, lifecycle) = setup_review();
            set_privacy_store_schema_version(&connection, 4);
            let directory = tempfile::tempdir().expect("backup directory");
            let store =
                EncryptedPrivacyBackupStore::initialize(directory.path()).expect("backup store");
            assert_eq!(
                store.export_pre_migration_database(
                    &mut connection,
                    &lifecycle,
                    &BackupExportRequestV1 {
                        backup_id: BACKUP_ID,
                        created_at_unix: NOW + 2,
                        expires_at_unix: Some(NOW + 100),
                    },
                    &PreMigrationBackupExportContextV1 {
                        expected_privacy_store_schema_version: invalid_version,
                    },
                ),
                Err(LifecycleError::InvalidInput),
                "invalid expected version {invalid_version}"
            );
            assert!(!store
                .backup_path(BACKUP_ID)
                .expect("invalid-context backup path")
                .exists());
        }

        let (mut empty, empty_lifecycle) = setup_review();
        set_privacy_store_schema_version(&empty, 4);
        empty
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DROP TABLE privacy_redactions;
                 DROP TABLE privacy_materials;
                 PRAGMA foreign_keys=ON;",
            )
            .expect("remove required privacy backing tables");
        let empty_directory = tempfile::tempdir().expect("empty backup directory");
        let empty_store = EncryptedPrivacyBackupStore::initialize(empty_directory.path())
            .expect("empty backup store");
        assert_eq!(
            empty_store.export_pre_migration_database(
                &mut empty,
                &empty_lifecycle,
                &BackupExportRequestV1 {
                    backup_id: BACKUP_ID,
                    created_at_unix: NOW + 2,
                    expires_at_unix: Some(NOW + 100),
                },
                &PreMigrationBackupExportContextV1 {
                    expected_privacy_store_schema_version: 4,
                },
            ),
            Err(LifecycleError::UnsupportedSchema)
        );

        let (mut future, future_lifecycle) = setup_review();
        set_privacy_store_schema_version(&future, 6);
        let future_directory = tempfile::tempdir().expect("future backup directory");
        let future_store = EncryptedPrivacyBackupStore::initialize(future_directory.path())
            .expect("future backup store");
        assert_eq!(
            future_store.export_pre_migration_database(
                &mut future,
                &future_lifecycle,
                &BackupExportRequestV1 {
                    backup_id: BACKUP_ID,
                    created_at_unix: NOW + 2,
                    expires_at_unix: Some(NOW + 100),
                },
                &PreMigrationBackupExportContextV1 {
                    expected_privacy_store_schema_version: 4,
                },
            ),
            Err(LifecycleError::UnsupportedSchema)
        );

        let (mut mismatched, mismatched_lifecycle) = setup_review();
        set_privacy_store_schema_version(&mismatched, 3);
        let mismatched_directory = tempfile::tempdir().expect("mismatched backup directory");
        let mismatched_store = EncryptedPrivacyBackupStore::initialize(mismatched_directory.path())
            .expect("mismatched backup store");
        assert_eq!(
            mismatched_store.export_pre_migration_database(
                &mut mismatched,
                &mismatched_lifecycle,
                &BackupExportRequestV1 {
                    backup_id: BACKUP_ID,
                    created_at_unix: NOW + 2,
                    expires_at_unix: Some(NOW + 100),
                },
                &PreMigrationBackupExportContextV1 {
                    expected_privacy_store_schema_version: 4,
                },
            ),
            Err(LifecycleError::EnvironmentMismatch)
        );

        let (mut damaged, damaged_lifecycle) = setup_review();
        damaged
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
                 DELETE FROM privacy_materials WHERE material_id='material-1';
                 PRAGMA foreign_keys=ON;",
            )
            .expect("create synthetic foreign-key damage");
        set_privacy_store_schema_version(&damaged, 4);
        let damaged_directory = tempfile::tempdir().expect("damaged backup directory");
        let damaged_store = EncryptedPrivacyBackupStore::initialize(damaged_directory.path())
            .expect("damaged backup store");
        assert_eq!(
            damaged_store.export_pre_migration_database(
                &mut damaged,
                &damaged_lifecycle,
                &BackupExportRequestV1 {
                    backup_id: BACKUP_ID,
                    created_at_unix: NOW + 2,
                    expires_at_unix: Some(NOW + 100),
                },
                &PreMigrationBackupExportContextV1 {
                    expected_privacy_store_schema_version: 4,
                },
            ),
            Err(LifecycleError::BackupTampered)
        );
        assert!(!damaged_store
            .backup_path(BACKUP_ID)
            .expect("damaged backup path")
            .exists());
        let registered: i64 = damaged
            .query_row(
                "SELECT COUNT(*) FROM privacy_backup_registry WHERE backup_id=?1",
                [BACKUP_ID],
                |row| row.get(0),
            )
            .expect("damaged backup registry");
        assert_eq!(registered, 0);
    }

    #[cfg(windows)]
    #[test]
    fn current_v5_backup_remains_normal_and_never_falls_back_to_pre_migration() {
        let (mut connection, lifecycle) = setup_review();
        let directory = tempfile::tempdir().expect("backup directory");
        let store =
            EncryptedPrivacyBackupStore::initialize(directory.path()).expect("backup store");
        let request = BackupExportRequestV1 {
            backup_id: BACKUP_ID,
            created_at_unix: NOW + 2,
            expires_at_unix: Some(NOW + 100),
        };
        let exported = store
            .export_database(&mut connection, &lifecycle, &request)
            .expect("normal current-schema export");
        assert_eq!(
            exported.privacy_store_schema_version,
            PRIVACY_STORE_SCHEMA_VERSION
        );
        let normal_context = BackupVerificationContextV1 {
            expected_workspace_instance_id: lifecycle.workspace_instance_id(),
            expected_key_epoch: lifecycle
                .current_key_epoch(&connection)
                .expect("current key epoch"),
            now_unix: NOW + 3,
        };
        assert_eq!(
            store
                .verify_detached_backup(BACKUP_ID, &normal_context)
                .expect("normal detached verification"),
            exported
        );
        assert_eq!(
            store.verify_detached_pre_migration_backup(
                BACKUP_ID,
                &PreMigrationBackupVerificationContextV1 {
                    expected_workspace_instance_id: lifecycle.workspace_instance_id(),
                    expected_key_epoch: normal_context.expected_key_epoch,
                    expected_privacy_store_schema_version: 4,
                    now_unix: NOW + 3,
                },
            ),
            Err(LifecycleError::EnvironmentMismatch)
        );

        let second_id = "bkp_55555555555555555555555555555555";
        assert_eq!(
            store.export_pre_migration_database(
                &mut connection,
                &lifecycle,
                &BackupExportRequestV1 {
                    backup_id: second_id,
                    ..request
                },
                &PreMigrationBackupExportContextV1 {
                    expected_privacy_store_schema_version: PRIVACY_STORE_SCHEMA_VERSION,
                },
            ),
            Err(LifecycleError::InvalidInput)
        );
        assert!(!store
            .backup_path(second_id)
            .expect("pre-migration current-schema path")
            .exists());
    }

    #[cfg(windows)]
    #[test]
    fn encrypted_backup_round_trip_tamper_wrong_environment_expiry_revoke_and_hardlink() {
        let (mut connection, lifecycle) = setup_review();
        lifecycle
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
            .expect("mapping");
        let directory = tempfile::tempdir().expect("backup directory");
        let store =
            EncryptedPrivacyBackupStore::initialize(directory.path()).expect("backup store");
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
        assert_eq!(
            store
                .verify_backup(&connection, BACKUP_ID, &context)
                .expect("verify"),
            exported
        );
        assert_eq!(
            store
                .verify_detached_backup(BACKUP_ID, &context)
                .expect("detached verify"),
            exported
        );
        let mut detached_restore = Connection::open_in_memory().expect("detached restore database");
        store
            .restore_detached_into_empty_database(&mut detached_restore, BACKUP_ID, &context)
            .expect("detached restore");
        PrivacyLifecycle::open(&detached_restore, workspace()).expect("open detached restore");
        let mut restored = Connection::open_in_memory().expect("restored database");
        store
            .restore_into_empty_database(&connection, &mut restored, BACKUP_ID, &context)
            .expect("restore");
        let restored_lifecycle =
            PrivacyLifecycle::open(&restored, workspace()).expect("open restored");
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
            .save_mapping_revision(
                &mut connection,
                MAP_ID,
                "redaction-1",
                1,
                &mapping(),
                NOW + 1,
            )
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
        let destination_store =
            EncryptedPrivacyBackupStore::initialize(destination_directory.path())
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
        assert!(wrong_store
            .import_portable_bundle(&tampered, &context)
            .is_err());
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
        let exact =
            staging.join("bkp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-1111111111111111-restore.sqlite");
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

        let hardlinked =
            staging.join("bkp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-2222222222222222-sqlite");
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
        let store =
            EncryptedPrivacyBackupStore::initialize(directory.path()).expect("backup store");
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
