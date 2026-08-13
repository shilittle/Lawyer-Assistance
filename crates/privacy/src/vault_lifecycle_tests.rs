#[cfg(test)]
mod vault_lifecycle_tests {
    use super::*;

    fn workspace() -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse("ws_cccccccccccccccccccccccccccccccc").expect("workspace")
    }

    fn case_id() -> CaseId {
        CaseId::parse("case_dddddddddddddddddddddddddddddddd").expect("case")
    }

    fn metadata(imported_at_unix: u64) -> VaultPrivateMetadataInputV1 {
        VaultPrivateMetadataInputV1 {
            original_file_name: "synthetic.pdf".to_owned(),
            original_source_path: Some("C:\\synthetic\\fixture.pdf".to_owned()),
            original_media_type: "application/pdf".to_owned(),
            imported_at_unix,
        }
    }

    #[cfg(windows)]
    #[test]
    fn expired_ocr_object_cleanup_honors_legal_hold_and_preserves_source_key() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().join("vault");
        let store = VaultStore::initialize(&root, workspace()).expect("store");
        let case = case_id();
        let source = store
            .create_source_object(&case, metadata(100), b"SYNTHETIC_SOURCE", 100)
            .expect("source");
        let ocr = store
            .create_object(
                &case,
                VaultObjectKind::LocalOcrArtifact,
                metadata(101),
                b"SYNTHETIC_OCR_INTERMEDIATE",
                101,
            )
            .expect("ocr");
        store
            .set_object_retention(&VaultRetentionBindingV1 {
                case_id: case.clone(),
                object_id: ocr.object_id.clone(),
                version: ocr.version,
                expires_at_unix: 120,
                legal_hold: true,
                policy_revision: 1,
                bound_at_unix: 110,
            })
            .expect("retention");
        let held = "cln_77777777777777777777777777777777";
        assert_eq!(
            store
                .prepare_expired_object_cleanup(held, 130)
                .expect("held"),
            0
        );
        let report = store
            .commit_expired_object_cleanup(held, 131)
            .expect("empty cleanup");
        assert_eq!(report.logically_removed_count, 0);
        store
            .set_object_legal_hold(&case, &ocr.object_id, ocr.version, false, 132)
            .expect("release hold");
        let cleanup = "cln_88888888888888888888888888888888";
        store
            .prepare_expired_object_cleanup(cleanup, 140)
            .expect("prepare cleanup");
        store
            .set_object_legal_hold(&case, &ocr.object_id, ocr.version, true, 141)
            .expect("late hold");
        assert_eq!(
            store.commit_expired_object_cleanup(cleanup, 142),
            Err(VaultStoreError::ContentCorrupt)
        );
        assert_eq!(
            store
                .read_object(&case, &ocr.object_id, ocr.version)
                .expect("held OCR retained")
                .content,
            b"SYNTHETIC_OCR_INTERMEDIATE"
        );
        store
            .set_object_legal_hold(&case, &ocr.object_id, ocr.version, false, 143)
            .expect("release late hold");
        let report = store
            .commit_expired_object_cleanup(cleanup, 144)
            .expect("cleanup");
        assert_eq!(report.candidate_count, 1);
        assert_eq!(report.logically_removed_count, 1);
        assert_eq!(report.key_records_destroyed, 0);
        assert_eq!(report.quarantine_paths_pending, 0);
        assert_eq!(report.erasure_disclosure, VAULT_LOGICAL_ERASURE_DISCLOSURE);
        assert_eq!(
            store.read_object(&case, &ocr.object_id, ocr.version),
            Err(VaultStoreError::ObjectNotAvailable)
        );
        assert_eq!(
            store
                .read_object(&case, &source.object_id, source.version)
                .expect("source retained")
                .content,
            b"SYNTHETIC_SOURCE"
        );
        assert!(store.case_key_path(&case).is_file());
        assert_eq!(store.verify_vault_cleanup_journal().expect("journal"), 2);
    }

    #[cfg(windows)]
    #[test]
    fn staged_crash_recovery_completes_cleanup_and_destroys_orphan_case_key() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().join("vault");
        let store = VaultStore::initialize(&root, workspace()).expect("store");
        let case = case_id();
        let object = store
            .create_object(
                &case,
                VaultObjectKind::ReviewDraft,
                metadata(200),
                b"SYNTHETIC_REVIEW_DRAFT",
                200,
            )
            .expect("object");
        store
            .set_object_retention(&VaultRetentionBindingV1 {
                case_id: case.clone(),
                object_id: object.object_id.clone(),
                version: object.version,
                expires_at_unix: 220,
                legal_hold: false,
                policy_revision: 1,
                bound_at_unix: 210,
            })
            .expect("retention");
        let cleanup = "cln_99999999999999999999999999999999";
        store
            .prepare_expired_object_cleanup(cleanup, 230)
            .expect("prepare");
        let db = open_database(&store.root).expect("database");
        let candidates = load_vault_cleanup_candidates(&db, cleanup).expect("candidates");
        assert_eq!(candidates.len(), 1);
        store
            .stage_cleanup_candidate(cleanup, &candidates[0])
            .expect("simulate crash after rename");
        drop(db);
        assert!(!store
            .object_directory(&case, &object.object_id, object.version)
            .exists());
        let reports = store.recover_object_cleanups(240).expect("recover");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].state, "purged");
        assert_eq!(reports[0].key_records_destroyed, 1);
        assert!(!store.case_key_path(&case).exists());
        assert_eq!(
            store.read_object(&case, &object.object_id, object.version),
            Err(VaultStoreError::ObjectNotAvailable)
        );
        assert_eq!(store.verify_vault_cleanup_journal().expect("journal"), 1);
    }

    struct FailVaultCleanupAt(VaultCleanupFailurePoint);

    impl VaultCleanupFailureInjector for FailVaultCleanupAt {
        fn inject(&self, point: VaultCleanupFailurePoint) -> Result<(), VaultStoreError> {
            if point == self.0 {
                Err(VaultStoreError::IoFailed)
            } else {
                Ok(())
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn physical_purge_crash_preserves_durable_key_count_and_later_same_case_writes() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().join("vault");
        let store = VaultStore::initialize(&root, workspace()).expect("store");
        let case = case_id();
        let object = store
            .create_object(
                &case,
                VaultObjectKind::ReviewDraft,
                metadata(250),
                b"SYNTHETIC_DURABLE_KEY_COUNT",
                250,
            )
            .expect("object");
        store
            .set_object_retention(&VaultRetentionBindingV1 {
                case_id: case.clone(),
                object_id: object.object_id.clone(),
                version: object.version,
                expires_at_unix: 270,
                legal_hold: false,
                policy_revision: 1,
                bound_at_unix: 260,
            })
            .expect("retention");
        let cleanup = "cln_44444444444444444444444444444444";
        assert_eq!(
            store.run_or_resume_expired_object_cleanup_with_failure_injector(
                cleanup,
                280,
                &FailVaultCleanupAt(
                    VaultCleanupFailurePoint::AfterPhysicalPurgeBeforeJournalCommit,
                ),
            ),
            Err(VaultStoreError::IoFailed)
        );

        let db = open_database(&store.root).expect("committed cleanup database");
        let committed: (String, i64, String) = db
            .query_row(
                "SELECT state,key_records_destroyed,event_hash
                 FROM vault_cleanup_journal WHERE cleanup_id=?1",
                [cleanup],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("committed cleanup row");
        assert_eq!(committed, ("committed".to_owned(), 1, String::new()));
        assert!(!store.case_key_path(&case).exists());
        assert!(!vault_cleanup_quarantine_path(
            &store.root,
            cleanup,
            &object.object_id,
            object.version,
        )
        .expect("quarantine path")
        .exists());
        drop(db);

        assert_eq!(
            store.create_object(
                &case,
                VaultObjectKind::ReviewDraft,
                metadata(281),
                b"MUST_NOT_REKEY_UNFINISHED_QUARANTINED_OBJECT",
                281,
            ),
            Err(VaultStoreError::CaseKeyUnavailable),
            "an unfinished committed cleanup still owns quarantined ciphertext and must not be re-keyed",
        );

        let reports = store.recover_object_cleanups(280).expect("recovery");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].state, "purged");
        assert_eq!(reports[0].key_records_destroyed, 1);
        assert_eq!(reports[0].event_hash.len(), 64);
        let stable = store
            .run_or_resume_expired_object_cleanup(cleanup, 280)
            .expect("purged cleanup reloads");
        assert_eq!(stable, reports[0]);

        let replacement = store
            .create_object(
                &case,
                VaultObjectKind::ReviewDraft,
                metadata(290),
                b"SYNTHETIC_REPLACEMENT_IN_SAME_CASE",
                290,
            )
            .expect("same-case replacement creates a new key");
        assert!(store.case_key_path(&case).is_file());
        assert_eq!(
            store
                .read_object(&case, &replacement.object_id, replacement.version)
                .expect("replacement decrypts")
                .content,
            b"SYNTHETIC_REPLACEMENT_IN_SAME_CASE"
        );
        assert_eq!(store.verify_vault_cleanup_journal().expect("journal"), 1);
        assert_eq!(
            store
                .run_or_resume_expired_object_cleanup(cleanup, 280)
                .expect("historical cleanup remains stable after same-case write"),
            stable
        );
    }

    #[cfg(windows)]
    #[test]
    fn lineage_cleanup_run_or_resume_covers_missing_prepared_committed_and_purged() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().join("vault");
        let store = VaultStore::initialize(&root, workspace()).expect("store");

        let missing_id = "cln_11111111111111111111111111111111";
        let missing = store
            .run_or_resume_expired_object_cleanup(missing_id, 400)
            .expect("missing cleanup runs exactly once");
        assert_eq!(missing.state, "purged");
        assert_eq!(missing.started_at_unix, 400);
        assert_eq!(missing.completed_at_unix, 400);
        assert_eq!(
            store
                .run_or_resume_expired_object_cleanup(missing_id, 400)
                .expect("purged cleanup verifies as a stable no-op"),
            missing
        );
        assert_eq!(
            store.run_or_resume_expired_object_cleanup(missing_id, 401),
            Err(VaultStoreError::ContentCorrupt),
            "the same cleanup identity cannot be rebound to another cutoff"
        );

        let prepared_id = "cln_22222222222222222222222222222222";
        store
            .prepare_expired_object_cleanup(prepared_id, 500)
            .expect("prepare crash window");
        let prepared = store
            .run_or_resume_expired_object_cleanup(prepared_id, 500)
            .expect("prepared cleanup resumes");
        assert_eq!(prepared.state, "purged");
        assert_eq!(prepared.started_at_unix, 500);
        assert_eq!(prepared.completed_at_unix, 500);

        let committed_id = "cln_33333333333333333333333333333333";
        store
            .prepare_expired_object_cleanup(committed_id, 600)
            .expect("prepare committed crash window");
        let connection = open_database(&store.root).expect("open committed crash fixture");
        assert_eq!(
            connection
                .execute(
                    "UPDATE vault_cleanup_journal
                     SET state='committed',completed_at_unix=600
                     WHERE cleanup_id=?1 AND state='prepared'",
                    [committed_id],
                )
                .expect("commit journal crash fixture"),
            1
        );
        drop(connection);
        let committed = store
            .run_or_resume_expired_object_cleanup(committed_id, 600)
            .expect("committed cleanup resumes final purge");
        assert_eq!(committed.state, "purged");
        assert_eq!(committed.started_at_unix, 600);
        assert_eq!(committed.completed_at_unix, 600);
        assert_eq!(
            store
                .run_or_resume_expired_object_cleanup(committed_id, 600)
                .expect("resumed purged cleanup remains stable"),
            committed
        );

        let status = store
            .inspect_cleanup_status_read_only()
            .expect("final cleanup status");
        assert_eq!(status.prepared_count, 0);
        assert_eq!(status.committed_count, 0);
        assert_eq!(status.purged_count, 3);
        assert_eq!(store.verify_vault_cleanup_journal().expect("journal"), 3);
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_rejects_envelope_tamper_and_hardlink_without_marking_removed() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().join("vault");
        let store = VaultStore::initialize(&root, workspace()).expect("store");
        let case = case_id();
        let object = store
            .create_object(
                &case,
                VaultObjectKind::LocalOcrArtifact,
                metadata(300),
                b"SYNTHETIC_OCR_TAMPER",
                300,
            )
            .expect("object");
        store
            .set_object_retention(&VaultRetentionBindingV1 {
                case_id: case.clone(),
                object_id: object.object_id.clone(),
                version: object.version,
                expires_at_unix: 320,
                legal_hold: false,
                policy_revision: 1,
                bound_at_unix: 310,
            })
            .expect("retention");
        let cleanup = "cln_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        store
            .prepare_expired_object_cleanup(cleanup, 330)
            .expect("prepare");
        let envelope_path = store
            .object_directory(&case, &object.object_id, object.version)
            .join("envelope.json");
        let original = fs::read(&envelope_path).expect("envelope");
        let mut tampered = original.clone();
        tampered[0] ^= 1;
        fs::write(&envelope_path, &tampered).expect("tamper");
        assert_eq!(
            store.commit_expired_object_cleanup(cleanup, 331),
            Err(VaultStoreError::EnvelopeInvalid)
        );
        let state: String = open_database(&store.root)
            .expect("database")
            .query_row(
                "SELECT state FROM vault_cleanup_journal WHERE cleanup_id=?1",
                [cleanup],
                |row| row.get(0),
            )
            .expect("state");
        assert_eq!(state, "prepared");
        fs::write(&envelope_path, &original).expect("restore");
        let hardlink = directory.path().join("envelope-hardlink.json");
        fs::hard_link(&envelope_path, &hardlink).expect("hardlink");
        assert_eq!(
            store.commit_expired_object_cleanup(cleanup, 332),
            Err(VaultStoreError::UnsafeFilesystem)
        );
        fs::remove_file(hardlink).expect("remove hardlink");
        let chunk_path = store
            .object_directory(&case, &object.object_id, object.version)
            .join(chunk_file_name(0));
        let chunk_hardlink = directory.path().join("chunk-hardlink.bin");
        fs::hard_link(&chunk_path, &chunk_hardlink).expect("chunk hardlink");
        assert_eq!(
            store.commit_expired_object_cleanup(cleanup, 333),
            Err(VaultStoreError::UnsafeFilesystem)
        );
        fs::remove_file(chunk_hardlink).expect("remove chunk hardlink");
        store
            .commit_expired_object_cleanup(cleanup, 334)
            .expect("cleanup after repair");
    }

    #[cfg(windows)]
    #[test]
    fn vault_v1_migrates_to_v2_but_future_schema_is_not_mutated() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().join("vault");
        let legacy_probe = VaultStore::initialize(&root, workspace()).expect("initial store");
        let database = root.join("vault-state.sqlite");
        let db = Connection::open(&database).expect("database");
        db.execute_batch(
            "DROP TABLE vault_cleanup_candidates;
             DROP TABLE vault_cleanup_journal;
             DROP TABLE vault_object_retention;
             DROP TABLE vault_lifecycle_meta;
             UPDATE vault_meta SET schema_version=1 WHERE singleton=1;",
        )
        .expect("make v1 fixture");
        drop(db);
        let before_probe = fs::read(&database).expect("v1 database before probe");
        let before_probe_modified = fs::metadata(&database)
            .expect("v1 database metadata before probe")
            .modified()
            .expect("v1 database mtime before probe");
        assert_eq!(
            legacy_probe
                .inspect_cleanup_status_read_only()
                .expect("authenticated v1 read-only probe"),
            VaultCleanupPendingStatusV1 {
                prepared_count: 0,
                committed_count: 0,
                purged_count: 0,
            }
        );
        assert_eq!(
            fs::read(&database).expect("v1 database after probe"),
            before_probe
        );
        assert_eq!(
            fs::metadata(&database)
                .expect("v1 database metadata after probe")
                .modified()
                .expect("v1 database mtime after probe"),
            before_probe_modified
        );
        let partial = Connection::open(&database).expect("partial lifecycle fixture");
        partial
            .execute_batch(
                "CREATE TABLE vault_lifecycle_meta(
                   singleton INTEGER PRIMARY KEY,
                   schema_version INTEGER NOT NULL
                 );",
            )
            .expect("create partial lifecycle state");
        drop(partial);
        assert_eq!(
            legacy_probe.inspect_cleanup_status_read_only(),
            Err(VaultStoreError::ContentCorrupt)
        );
        Connection::open(&database)
            .expect("remove partial lifecycle fixture")
            .execute("DROP TABLE vault_lifecycle_meta", [])
            .expect("drop partial lifecycle state");
        VaultStore::initialize(&root, workspace()).expect("migrate v1");
        let db = Connection::open(&database).expect("migrated database");
        let version: u32 = db
            .query_row(
                "SELECT schema_version FROM vault_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("version");
        assert_eq!(version, VAULT_STORE_SCHEMA_VERSION);
        db.execute_batch(
            "DROP TABLE vault_cleanup_candidates;
             DROP TABLE vault_cleanup_journal;
             DROP TABLE vault_object_retention;
             DROP TABLE vault_lifecycle_meta;
             UPDATE vault_meta SET schema_version=999 WHERE singleton=1;",
        )
        .expect("make future fixture");
        drop(db);
        assert!(matches!(
            VaultStore::initialize(&root, workspace()),
            Err(VaultStoreError::DatabaseFailed)
        ));
        let db = Connection::open(&database).expect("future database");
        let lifecycle_table: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
                 WHERE type='table' AND name='vault_lifecycle_meta')",
                [],
                |row| row.get(0),
            )
            .expect("future lifecycle table");
        assert!(!lifecycle_table);
    }

    #[test]
    fn cleanup_identifier_rejects_traversal() {
        assert_eq!(
            valid_vault_cleanup_id("cln_../../escape"),
            Err(VaultStoreError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    fn pending_cleanup_probe_is_strictly_read_only_for_prepared_and_committed_states() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().join("vault");
        let store = VaultStore::initialize(&root, workspace()).expect("store");
        store
            .prepare_expired_object_cleanup("cln_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 100)
            .expect("prepare empty cleanup");
        store
            .prepare_encrypted_backup_snapshot()
            .expect("checkpoint prepared state before proof");
        let database = root.join("vault-state.sqlite");
        let prepared_bytes = fs::read(&database).expect("prepared database bytes");
        let prepared_modified = fs::metadata(&database)
            .expect("prepared database metadata")
            .modified()
            .expect("prepared database mtime");

        let prepared = store
            .inspect_cleanup_status_read_only()
            .expect("read prepared status");
        assert_eq!(prepared.prepared_count, 1);
        assert_eq!(prepared.committed_count, 0);
        assert!(prepared.has_unfinished_cleanup());
        assert_eq!(
            fs::read(&database).expect("database after prepared probe"),
            prepared_bytes
        );
        assert_eq!(
            fs::metadata(&database)
                .expect("metadata after prepared probe")
                .modified()
                .expect("mtime after prepared probe"),
            prepared_modified
        );

        let connection = open_database(&store.root).expect("write committed fixture state");
        connection
            .execute(
                "UPDATE vault_cleanup_journal
                 SET state='committed',completed_at_unix=101
                 WHERE cleanup_id='cln_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                   AND state='prepared'",
                [],
            )
            .expect("mark fixture committed");
        drop(connection);
        store
            .prepare_encrypted_backup_snapshot()
            .expect("checkpoint committed state before proof");
        let committed_bytes = fs::read(&database).expect("committed database bytes");
        let committed_modified = fs::metadata(&database)
            .expect("committed database metadata")
            .modified()
            .expect("committed database mtime");

        let committed = store
            .inspect_cleanup_status_read_only()
            .expect("read committed status");
        assert_eq!(committed.prepared_count, 0);
        assert_eq!(committed.committed_count, 1);
        assert!(committed.has_unfinished_cleanup());
        assert_eq!(
            fs::read(&database).expect("database after committed probe"),
            committed_bytes
        );
        assert_eq!(
            fs::metadata(&database)
                .expect("metadata after committed probe")
                .modified()
                .expect("mtime after committed probe"),
            committed_modified
        );
    }
}
