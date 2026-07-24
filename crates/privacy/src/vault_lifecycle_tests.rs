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
        assert_eq!(store.prepare_expired_object_cleanup(held, 130).expect("held"), 0);
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
        VaultStore::initialize(&root, workspace()).expect("initial store");
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
        VaultStore::initialize(&root, workspace()).expect("migrate v1");
        let db = Connection::open(&database).expect("migrated database");
        let version: u32 = db
            .query_row("SELECT schema_version FROM vault_meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
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
}
