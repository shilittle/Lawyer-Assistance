// Included from vault_store.rs. This code has access to the fixed vault root and never accepts a
// caller-provided filesystem path.

pub const VAULT_LIFECYCLE_SCHEMA_VERSION: u32 = 1;
pub const VAULT_LOGICAL_ERASURE_DISCLOSURE: &str =
    "vault_logical_cleanup_only_not_forensic_media_wipe";
const VAULT_LIFECYCLE_TABLES: [&str; 4] = [
    "vault_lifecycle_meta",
    "vault_object_retention",
    "vault_cleanup_journal",
    "vault_cleanup_candidates",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRetentionBindingV1 {
    pub case_id: CaseId,
    pub object_id: ObjectId,
    pub version: u64,
    pub expires_at_unix: u64,
    pub legal_hold: bool,
    pub policy_revision: u64,
    pub bound_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCleanupReportV1 {
    pub cleanup_id: String,
    pub state: String,
    pub candidate_count: u64,
    pub logically_removed_count: u64,
    pub key_records_destroyed: u64,
    pub quarantine_paths_pending: u64,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
    pub event_hash: String,
    pub erasure_disclosure: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultCleanupPendingStatusV1 {
    pub prepared_count: u64,
    pub committed_count: u64,
    pub purged_count: u64,
}

/// Durable writer boundaries used by the application upgrade coordinator to
/// prove that an interrupted cleanup resumes through the same production
/// implementation.  The public surface is intentionally minimal: production
/// callers use [`NoopVaultCleanupFailureInjector`].
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultCleanupFailurePoint {
    AfterPreparedTransactionCommit,
    AfterCommittedTransactionCommit,
    AfterPhysicalPurgeBeforeJournalCommit,
}

#[doc(hidden)]
pub trait VaultCleanupFailureInjector: Send + Sync {
    fn inject(&self, point: VaultCleanupFailurePoint) -> Result<(), VaultStoreError>;
}

#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopVaultCleanupFailureInjector;

impl VaultCleanupFailureInjector for NoopVaultCleanupFailureInjector {
    fn inject(&self, _point: VaultCleanupFailurePoint) -> Result<(), VaultStoreError> {
        Ok(())
    }
}

impl VaultCleanupPendingStatusV1 {
    pub fn has_unfinished_cleanup(self) -> bool {
        self.prepared_count != 0 || self.committed_count != 0
    }
}

#[derive(Debug, Clone)]
struct VaultCleanupCandidateV1 {
    case_id: CaseId,
    object_id: ObjectId,
    version: u64,
    envelope_sha256: String,
    state: String,
}

impl VaultStore {
    pub fn set_object_retention(
        &self,
        binding: &VaultRetentionBindingV1,
    ) -> Result<(), VaultStoreError> {
        if binding.version == 0
            || binding.expires_at_unix == 0
            || binding.policy_revision == 0
            || binding.bound_at_unix == 0
            || binding.expires_at_unix <= binding.bound_at_unix
        {
            return Err(VaultStoreError::InvalidInput);
        }
        let db = open_database(&self.root)?;
        initialize_vault_lifecycle_schema(&db)?;
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM object_journal
                   WHERE case_id=?1 AND object_id=?2 AND version=?3 AND state='committed'
                 )",
                params![
                    binding.case_id.as_str(),
                    binding.object_id.as_str(),
                    sql_i64(binding.version)?
                ],
                |row| row.get(0),
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if !exists {
            return Err(VaultStoreError::ObjectNotAvailable);
        }
        let changed = db
            .execute(
                "INSERT INTO vault_object_retention(
                   case_id,object_id,version,expires_at_unix,legal_hold,policy_revision,bound_at_unix
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(object_id,version) DO UPDATE SET
                   expires_at_unix=excluded.expires_at_unix,
                   legal_hold=excluded.legal_hold,
                   policy_revision=excluded.policy_revision,
                   bound_at_unix=excluded.bound_at_unix
                 WHERE vault_object_retention.case_id=excluded.case_id",
                params![
                    binding.case_id.as_str(),
                    binding.object_id.as_str(),
                    sql_i64(binding.version)?,
                    sql_i64(binding.expires_at_unix)?,
                    binding.legal_hold,
                    sql_i64(binding.policy_revision)?,
                    sql_i64(binding.bound_at_unix)?
                ],
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(VaultStoreError::ContentCorrupt)
        }
    }

    pub fn set_object_legal_hold(
        &self,
        case_id: &CaseId,
        object_id: &ObjectId,
        version: u64,
        enabled: bool,
        changed_at_unix: u64,
    ) -> Result<(), VaultStoreError> {
        if version == 0 || changed_at_unix == 0 {
            return Err(VaultStoreError::InvalidInput);
        }
        let db = open_database(&self.root)?;
        initialize_vault_lifecycle_schema(&db)?;
        let changed = db
            .execute(
                "UPDATE vault_object_retention SET legal_hold=?4,hold_changed_at_unix=?5
                 WHERE case_id=?1 AND object_id=?2 AND version=?3",
                params![
                    case_id.as_str(),
                    object_id.as_str(),
                    sql_i64(version)?,
                    enabled,
                    sql_i64(changed_at_unix)?
                ],
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(VaultStoreError::ObjectNotAvailable)
        }
    }

    pub fn prepare_expired_object_cleanup(
        &self,
        cleanup_id: &str,
        now_unix: u64,
    ) -> Result<u64, VaultStoreError> {
        valid_vault_cleanup_id(cleanup_id)?;
        if now_unix == 0 {
            return Err(VaultStoreError::InvalidInput);
        }
        let mut db = open_database(&self.root)?;
        initialize_vault_lifecycle_schema(&db)?;
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        transaction
            .execute(
                "INSERT INTO vault_cleanup_journal(
                   cleanup_id,state,started_at_unix,candidate_count,removed_count,
                   key_records_destroyed,previous_event_hash,event_hash,erasure_disclosure
                 ) VALUES(?1,'prepared',?2,0,0,0,'','',?3)",
                params![
                    cleanup_id,
                    sql_i64(now_unix)?,
                    VAULT_LOGICAL_ERASURE_DISCLOSURE
                ],
            )
            .map_err(|_| VaultStoreError::AlreadyExists)?;
        let candidates = {
            let mut statement = transaction
                .prepare(
                    "SELECT j.case_id,j.object_id,j.version,j.envelope_sha256
                     FROM object_journal j
                     JOIN vault_object_retention r
                       ON r.object_id=j.object_id AND r.version=j.version AND r.case_id=j.case_id
                     WHERE j.state='committed' AND r.legal_hold=0 AND r.expires_at_unix<=?1
                     ORDER BY j.case_id,j.object_id,j.version",
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            let rows = statement
                .query_map([sql_i64(now_unix)?], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| VaultStoreError::DatabaseFailed)?
        };
        for (case_id, object_id, version, envelope_sha256) in &candidates {
            let envelope_sha256 = envelope_sha256
                .as_deref()
                .ok_or(VaultStoreError::EnvelopeInvalid)?;
            if envelope_sha256.len() != 64 {
                return Err(VaultStoreError::EnvelopeInvalid);
            }
            transaction
                .execute(
                    "INSERT INTO vault_cleanup_candidates(
                       cleanup_id,case_id,object_id,version,envelope_sha256,state
                     ) VALUES(?1,?2,?3,?4,?5,'pending')",
                    params![cleanup_id, case_id, object_id, version, envelope_sha256],
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
        }
        transaction
            .execute(
                "UPDATE vault_cleanup_journal SET candidate_count=?2
                 WHERE cleanup_id=?1 AND state='prepared'",
                params![
                    cleanup_id,
                    i64::try_from(candidates.len()).map_err(|_| VaultStoreError::InvalidInput)?
                ],
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        transaction
            .commit()
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        u64::try_from(candidates.len()).map_err(|_| VaultStoreError::InvalidInput)
    }

    pub fn commit_expired_object_cleanup(
        &self,
        cleanup_id: &str,
        completed_at_unix: u64,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        self.commit_expired_object_cleanup_with_failure_injector(
            cleanup_id,
            completed_at_unix,
            &NoopVaultCleanupFailureInjector,
        )
    }

    fn commit_expired_object_cleanup_with_failure_injector(
        &self,
        cleanup_id: &str,
        completed_at_unix: u64,
        failure_injector: &dyn VaultCleanupFailureInjector,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        valid_vault_cleanup_id(cleanup_id)?;
        if completed_at_unix == 0 {
            return Err(VaultStoreError::InvalidInput);
        }
        let mut db = open_database(&self.root)?;
        initialize_vault_lifecycle_schema(&db)?;
        let (state, started_at, candidate_count): (String, i64, i64) = db
            .query_row(
                "SELECT state,started_at_unix,candidate_count FROM vault_cleanup_journal
                 WHERE cleanup_id=?1",
                [cleanup_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| VaultStoreError::DatabaseFailed)?
            .ok_or(VaultStoreError::ObjectNotAvailable)?;
        if !matches!(state.as_str(), "prepared" | "committed")
            || u64::try_from(started_at)
                .ok()
                .is_none_or(|started| started > completed_at_unix)
        {
            return Err(VaultStoreError::InvalidInput);
        }
        let candidates = load_vault_cleanup_candidates(&db, cleanup_id)?;
        if i64::try_from(candidates.len()).ok() != Some(candidate_count) {
            return Err(VaultStoreError::ContentCorrupt);
        }
        if state == "prepared" {
            if candidates
                .iter()
                .any(|candidate| candidate.state != "pending")
            {
                return Err(VaultStoreError::ContentCorrupt);
            }
            // Acquire the write lock before the final legal-hold/expiry check. This prevents a
            // concurrent hold update from racing the filesystem quarantine transition.
            let transaction = db
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            let key_destruction_cases =
                cleanup_key_destruction_cases_before_commit(&transaction, cleanup_id, &candidates)?;
            for case_id in &key_destruction_cases {
                let key_path = self.case_key_path(case_id);
                if !key_path.exists() {
                    return Err(VaultStoreError::CaseKeyUnavailable);
                }
                validate_controlled_path(&self.root, &key_path, true)?;
            }
            for candidate in &candidates {
                validate_vault_cleanup_candidate_current(
                    &transaction,
                    candidate,
                    completed_at_unix,
                )?;
                self.stage_cleanup_candidate(cleanup_id, candidate)?;
            }
            for candidate in &candidates {
                let changed = transaction
                    .execute(
                        "UPDATE object_journal SET state='quarantined'
                         WHERE case_id=?1 AND object_id=?2 AND version=?3
                           AND state='committed' AND envelope_sha256=?4",
                        params![
                            candidate.case_id.as_str(),
                            candidate.object_id.as_str(),
                            sql_i64(candidate.version)?,
                            candidate.envelope_sha256
                        ],
                    )
                    .map_err(|_| VaultStoreError::DatabaseFailed)?;
                if changed != 1 {
                    return Err(VaultStoreError::ContentCorrupt);
                }
                let changed = transaction
                    .execute(
                        "UPDATE vault_cleanup_candidates SET state='quarantined'
                         WHERE cleanup_id=?1 AND object_id=?2 AND version=?3 AND state='pending'",
                        params![
                            cleanup_id,
                            candidate.object_id.as_str(),
                            sql_i64(candidate.version)?
                        ],
                    )
                    .map_err(|_| VaultStoreError::DatabaseFailed)?;
                if changed != 1 {
                    return Err(VaultStoreError::ContentCorrupt);
                }
                transaction
                    .execute(
                        "DELETE FROM nonce_reservations WHERE object_id=?1 AND version=?2",
                        params![candidate.object_id.as_str(), sql_i64(candidate.version)?],
                    )
                    .map_err(|_| VaultStoreError::DatabaseFailed)?;
                transaction
                    .execute(
                        "DELETE FROM vault_object_retention WHERE object_id=?1 AND version=?2",
                        params![candidate.object_id.as_str(), sql_i64(candidate.version)?],
                    )
                    .map_err(|_| VaultStoreError::DatabaseFailed)?;
            }
            let changed = transaction
                .execute(
                    "UPDATE vault_cleanup_journal SET state='committed',removed_count=?2,
                       completed_at_unix=?3,key_records_destroyed=?4
                     WHERE cleanup_id=?1 AND state='prepared'",
                    params![
                        cleanup_id,
                        candidate_count,
                        sql_i64(completed_at_unix)?,
                        i64::try_from(key_destruction_cases.len())
                            .map_err(|_| VaultStoreError::InvalidInput)?
                    ],
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            if changed != 1 {
                return Err(VaultStoreError::ContentCorrupt);
            }
            transaction
                .commit()
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            failure_injector.inject(VaultCleanupFailurePoint::AfterCommittedTransactionCommit)?;
        } else if candidates
            .iter()
            .any(|candidate| candidate.state != "quarantined")
        {
            return Err(VaultStoreError::ContentCorrupt);
        }
        self.finalize_committed_vault_cleanup(cleanup_id, completed_at_unix, failure_injector)
    }

    pub fn run_expired_object_cleanup(
        &self,
        cleanup_id: &str,
        now_unix: u64,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        self.run_expired_object_cleanup_with_failure_injector(
            cleanup_id,
            now_unix,
            &NoopVaultCleanupFailureInjector,
        )
    }

    fn run_expired_object_cleanup_with_failure_injector(
        &self,
        cleanup_id: &str,
        now_unix: u64,
        failure_injector: &dyn VaultCleanupFailureInjector,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        self.prepare_expired_object_cleanup(cleanup_id, now_unix)?;
        failure_injector.inject(VaultCleanupFailurePoint::AfterPreparedTransactionCommit)?;
        self.commit_expired_object_cleanup_with_failure_injector(
            cleanup_id,
            now_unix,
            failure_injector,
        )
    }

    /// Runs the lineage-bound cleanup exactly once, or resumes/verifies the
    /// same durable journal after a crash. A reused identifier with a different
    /// cutoff is a conflict rather than a request to create another cleanup.
    pub fn run_or_resume_expired_object_cleanup(
        &self,
        cleanup_id: &str,
        now_unix: u64,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        self.run_or_resume_expired_object_cleanup_with_failure_injector(
            cleanup_id,
            now_unix,
            &NoopVaultCleanupFailureInjector,
        )
    }

    #[doc(hidden)]
    pub fn run_or_resume_expired_object_cleanup_with_failure_injector(
        &self,
        cleanup_id: &str,
        now_unix: u64,
        failure_injector: &dyn VaultCleanupFailureInjector,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        valid_vault_cleanup_id(cleanup_id)?;
        if now_unix == 0 {
            return Err(VaultStoreError::InvalidInput);
        }
        let db = open_database(&self.root)?;
        initialize_vault_lifecycle_schema(&db)?;
        let existing = db
            .query_row(
                "SELECT state,started_at_unix,completed_at_unix,candidate_count,
                        removed_count,key_records_destroyed,event_hash,erasure_disclosure
                 FROM vault_cleanup_journal WHERE cleanup_id=?1",
                [cleanup_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        drop(db);
        let Some((
            state,
            started_at,
            completed_at,
            candidate_count,
            removed_count,
            key_records_destroyed,
            event_hash,
            erasure_disclosure,
        )) = existing
        else {
            return self.run_expired_object_cleanup_with_failure_injector(
                cleanup_id,
                now_unix,
                failure_injector,
            );
        };
        if u64::try_from(started_at).ok() != Some(now_unix) {
            return Err(VaultStoreError::ContentCorrupt);
        }
        match state.as_str() {
            "prepared" | "committed" => self.commit_expired_object_cleanup_with_failure_injector(
                cleanup_id,
                now_unix,
                failure_injector,
            ),
            "purged" => {
                if completed_at.and_then(|value| u64::try_from(value).ok()) != Some(now_unix)
                    || candidate_count < 0
                    || removed_count < 0
                    || key_records_destroyed < 0
                    || removed_count != candidate_count
                    || event_hash.len() != 64
                    || erasure_disclosure != VAULT_LOGICAL_ERASURE_DISCLOSURE
                {
                    return Err(VaultStoreError::ContentCorrupt);
                }
                self.verify_vault_cleanup_journal()?;
                Ok(VaultCleanupReportV1 {
                    cleanup_id: cleanup_id.to_owned(),
                    state,
                    candidate_count: u64::try_from(candidate_count)
                        .map_err(|_| VaultStoreError::ContentCorrupt)?,
                    logically_removed_count: u64::try_from(removed_count)
                        .map_err(|_| VaultStoreError::ContentCorrupt)?,
                    key_records_destroyed: u64::try_from(key_records_destroyed)
                        .map_err(|_| VaultStoreError::ContentCorrupt)?,
                    quarantine_paths_pending: 0,
                    started_at_unix: now_unix,
                    completed_at_unix: now_unix,
                    event_hash,
                    erasure_disclosure: VAULT_LOGICAL_ERASURE_DISCLOSURE,
                })
            }
            _ => Err(VaultStoreError::ContentCorrupt),
        }
    }

    pub fn recover_object_cleanups(
        &self,
        recovered_at_unix: u64,
    ) -> Result<Vec<VaultCleanupReportV1>, VaultStoreError> {
        if recovered_at_unix == 0 {
            return Err(VaultStoreError::InvalidInput);
        }
        let db = open_database(&self.root)?;
        initialize_vault_lifecycle_schema(&db)?;
        let cleanup_ids = {
            let mut statement = db
                .prepare(
                    "SELECT cleanup_id FROM vault_cleanup_journal
                     WHERE state IN('prepared','committed') ORDER BY cleanup_id",
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| VaultStoreError::DatabaseFailed)?
        };
        let mut reports = Vec::with_capacity(cleanup_ids.len());
        for cleanup_id in cleanup_ids {
            reports.push(self.commit_expired_object_cleanup(&cleanup_id, recovered_at_unix)?);
        }
        Ok(reports)
    }

    pub fn verify_vault_cleanup_journal(&self) -> Result<u64, VaultStoreError> {
        let db = open_database(&self.root)?;
        initialize_vault_lifecycle_schema(&db)?;
        Self::verify_vault_cleanup_journal_connection(&db)
    }

    /// Inspects cleanup state without initializing schema, checkpointing WAL, recovering a
    /// cleanup, or opening the Vault database for writes. Migration preflight uses this boundary
    /// to fail closed while a prepared or committed cleanup is still pending.
    pub fn inspect_cleanup_status_read_only(
        &self,
    ) -> Result<VaultCleanupPendingStatusV1, VaultStoreError> {
        with_database_read_only_snapshot(&self.root, |db| {
            validate_database_integrity(db)?;
            let (store_version, workspace): (u32, String) = db
                .query_row(
                    "SELECT schema_version,workspace_instance_id
                 FROM vault_meta WHERE singleton=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            if workspace != self.workspace_instance_id.as_str() {
                return Err(VaultStoreError::ContentCorrupt);
            }
            let lifecycle_table_count = vault_lifecycle_table_count(db)?;
            if store_version == 1 {
                if lifecycle_table_count != 0 {
                    return Err(VaultStoreError::ContentCorrupt);
                }
                return Ok(VaultCleanupPendingStatusV1 {
                    prepared_count: 0,
                    committed_count: 0,
                    purged_count: 0,
                });
            }
            if store_version != VAULT_STORE_SCHEMA_VERSION
                || lifecycle_table_count
                    != u8::try_from(VAULT_LIFECYCLE_TABLES.len()).unwrap_or(u8::MAX)
            {
                return Err(VaultStoreError::ContentCorrupt);
            }
            let lifecycle_version: u32 = db
                .query_row(
                    "SELECT schema_version FROM vault_lifecycle_meta WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            if lifecycle_version != VAULT_LIFECYCLE_SCHEMA_VERSION {
                return Err(VaultStoreError::ContentCorrupt);
            }
            let mut prepared_count = 0_u64;
            let mut committed_count = 0_u64;
            let mut purged_count = 0_u64;
            let mut statement = db
                .prepare(
                    "SELECT cleanup_id,state,started_at_unix,completed_at_unix,candidate_count,
                        removed_count,key_records_destroyed,previous_event_hash,event_hash,
                        erasure_disclosure
                 FROM vault_cleanup_journal ORDER BY rowid",
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                })
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            for row in rows {
                let row = row.map_err(|_| VaultStoreError::DatabaseFailed)?;
                valid_vault_cleanup_id(&row.0)?;
                let candidate_counts: (i64, i64, i64, i64) = db
                    .query_row(
                        "SELECT COUNT(*),
                            COALESCE(SUM(state='pending'),0),
                            COALESCE(SUM(state='quarantined'),0),
                            COALESCE(SUM(state='purged'),0)
                     FROM vault_cleanup_candidates WHERE cleanup_id=?1",
                        [&row.0],
                        |candidate| {
                            Ok((
                                candidate.get(0)?,
                                candidate.get(1)?,
                                candidate.get(2)?,
                                candidate.get(3)?,
                            ))
                        },
                    )
                    .map_err(|_| VaultStoreError::DatabaseFailed)?;
                let cleanup_candidates = load_vault_cleanup_candidates(db, &row.0)?;
                let distinct_candidate_cases =
                    i64::try_from(cleanup_candidate_cases(&cleanup_candidates).len())
                        .map_err(|_| VaultStoreError::ContentCorrupt)?;
                let committed_expected_key_destructions = if row.1 == "committed" {
                    Some(
                        i64::try_from(
                            cleanup_key_destruction_cases_after_commit(db, &cleanup_candidates)?
                                .len(),
                        )
                        .map_err(|_| VaultStoreError::ContentCorrupt)?,
                    )
                } else {
                    None
                };
                if row.2 <= 0
                    || row.4 < 0
                    || row.5 < 0
                    || row.6 < 0
                    || candidate_counts.0 != row.4
                    || row.9 != VAULT_LOGICAL_ERASURE_DISCLOSURE
                {
                    return Err(VaultStoreError::ContentCorrupt);
                }
                match row.1.as_str() {
                    "prepared"
                        if row.3.is_none()
                            && row.5 == 0
                            && row.6 == 0
                            && row.7.is_empty()
                            && row.8.is_empty()
                            && candidate_counts.1 == row.4
                            && candidate_counts.2 == 0
                            && candidate_counts.3 == 0 =>
                    {
                        prepared_count = prepared_count.saturating_add(1);
                    }
                    "committed"
                        if row.3.is_some_and(|completed| completed >= row.2)
                            && row.5 == row.4
                            && committed_expected_key_destructions == Some(row.6)
                            && row.7.is_empty()
                            && row.8.is_empty()
                            && candidate_counts.1 == 0
                            && candidate_counts.2 == row.4
                            && candidate_counts.3 == 0 =>
                    {
                        committed_count = committed_count.saturating_add(1);
                    }
                    "purged"
                        if row.3.is_some_and(|completed| completed >= row.2)
                            && row.5 == row.4
                            && row.6 <= distinct_candidate_cases
                            && candidate_counts.1 == 0
                            && candidate_counts.2 == 0
                            && candidate_counts.3 == row.4 =>
                    {
                        purged_count = purged_count.saturating_add(1);
                    }
                    _ => return Err(VaultStoreError::ContentCorrupt),
                }
            }
            drop(statement);
            if Self::verify_vault_cleanup_journal_connection(db)? != purged_count {
                return Err(VaultStoreError::ContentCorrupt);
            }
            Ok(VaultCleanupPendingStatusV1 {
                prepared_count,
                committed_count,
                purged_count,
            })
        })
    }

    fn verify_vault_cleanup_journal_connection(db: &Connection) -> Result<u64, VaultStoreError> {
        let mut statement = db
            .prepare(
                "SELECT cleanup_id,started_at_unix,completed_at_unix,candidate_count,
                        removed_count,key_records_destroyed,previous_event_hash,event_hash,
                        erasure_disclosure
                 FROM vault_cleanup_journal WHERE state='purged' ORDER BY rowid",
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                ))
            })
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        let mut previous = String::new();
        let mut count = 0_u64;
        for row in rows {
            let row = row.map_err(|_| VaultStoreError::DatabaseFailed)?;
            let (candidate_count, purged_candidates, distinct_cases): (i64, i64, i64) = db
                .query_row(
                    "SELECT COUNT(*),COALESCE(SUM(state='purged'),0),
                            COUNT(DISTINCT case_id)
                     FROM vault_cleanup_candidates WHERE cleanup_id=?1",
                    [&row.0],
                    |candidate| Ok((candidate.get(0)?, candidate.get(1)?, candidate.get(2)?)),
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            let expected = vault_cleanup_event_hash(
                &row.0, row.1, row.2, row.3, row.4, row.5, &row.6, &row.8,
            )?;
            if row.3 < 0
                || row.4 != row.3
                || row.5 < 0
                || row.5 > distinct_cases
                || candidate_count != row.3
                || purged_candidates != row.3
                || row.6 != previous
                || row.7 != expected
                || row.8 != VAULT_LOGICAL_ERASURE_DISCLOSURE
            {
                return Err(VaultStoreError::ContentCorrupt);
            }
            previous = row.7;
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    fn stage_cleanup_candidate(
        &self,
        cleanup_id: &str,
        candidate: &VaultCleanupCandidateV1,
    ) -> Result<(), VaultStoreError> {
        if candidate.state != "pending" {
            return Err(VaultStoreError::ContentCorrupt);
        }
        let source =
            self.object_directory(&candidate.case_id, &candidate.object_id, candidate.version);
        let quarantine = vault_cleanup_quarantine_path(
            &self.root,
            cleanup_id,
            &candidate.object_id,
            candidate.version,
        )?;
        if source.exists() && !quarantine.exists() {
            validate_controlled_path(&self.root, &source, false)?;
            let envelope_path = source.join("envelope.json");
            validate_controlled_path(&self.root, &envelope_path, true)?;
            let envelope_bytes = read_bounded(&envelope_path, MAX_VAULT_ENVELOPE_BYTES)?;
            if sha256_hex(&envelope_bytes) != candidate.envelope_sha256 {
                return Err(VaultStoreError::EnvelopeInvalid);
            }
            let envelope: VaultObjectEnvelopeV1 = strict_json_v1_from_slice(&envelope_bytes)
                .map_err(|_| VaultStoreError::EnvelopeInvalid)?;
            envelope.validate()?;
            if envelope.workspace_instance_id != self.workspace_instance_id
                || envelope.case_id != candidate.case_id
                || envelope.object_id != candidate.object_id
                || envelope.version != candidate.version
            {
                return Err(VaultStoreError::EnvelopeInvalid);
            }
            validate_cleanup_object_tree(&self.root, &source, &envelope)?;
            validate_new_controlled_path(&self.root, &quarantine)?;
            fs::rename(&source, &quarantine).map_err(|_| VaultStoreError::IoFailed)?;
        } else if !source.exists() && quarantine.exists() {
            validate_controlled_path(&self.root, &quarantine, false)?;
        } else {
            return Err(VaultStoreError::ContentCorrupt);
        }
        Ok(())
    }

    fn finalize_committed_vault_cleanup(
        &self,
        cleanup_id: &str,
        completed_at_unix: u64,
        failure_injector: &dyn VaultCleanupFailureInjector,
    ) -> Result<VaultCleanupReportV1, VaultStoreError> {
        let mut db = open_database(&self.root)?;
        let candidates = load_vault_cleanup_candidates(&db, cleanup_id)?;
        let expected_keys_destroyed: i64 = db
            .query_row(
                "SELECT key_records_destroyed FROM vault_cleanup_journal
                 WHERE cleanup_id=?1 AND state='committed'",
                [cleanup_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| VaultStoreError::DatabaseFailed)?
            .ok_or(VaultStoreError::ObjectNotAvailable)?;
        let key_destruction_cases = cleanup_key_destruction_cases_after_commit(&db, &candidates)?;
        if i64::try_from(key_destruction_cases.len()).ok() != Some(expected_keys_destroyed) {
            return Err(VaultStoreError::ContentCorrupt);
        }
        for case_id in key_destruction_cases {
            let key_path = self.case_key_path(&case_id);
            if key_path.exists() {
                validate_controlled_path(&self.root, &key_path, true)?;
                fs::remove_file(&key_path).map_err(|_| VaultStoreError::IoFailed)?;
            }
        }
        for candidate in &candidates {
            let quarantine = vault_cleanup_quarantine_path(
                &self.root,
                cleanup_id,
                &candidate.object_id,
                candidate.version,
            )?;
            if quarantine.exists() {
                validate_controlled_path(&self.root, &quarantine, false)?;
                fs::remove_dir_all(&quarantine).map_err(|_| VaultStoreError::IoFailed)?;
            }
        }
        failure_injector.inject(VaultCleanupFailurePoint::AfterPhysicalPurgeBeforeJournalCommit)?;
        let transaction = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        transaction
            .execute(
                "UPDATE vault_cleanup_candidates SET state='purged'
                 WHERE cleanup_id=?1 AND state='quarantined'",
                [cleanup_id],
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        let (started_at, candidate_count, removed_count, durable_expected_keys_destroyed): (
            i64,
            i64,
            i64,
            i64,
        ) = transaction
            .query_row(
                "SELECT started_at_unix,candidate_count,removed_count,key_records_destroyed
                 FROM vault_cleanup_journal WHERE cleanup_id=?1 AND state='committed'",
                [cleanup_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|_| VaultStoreError::DatabaseFailed)?
            .ok_or(VaultStoreError::ObjectNotAvailable)?;
        if durable_expected_keys_destroyed != expected_keys_destroyed {
            return Err(VaultStoreError::ContentCorrupt);
        }
        let previous = transaction
            .query_row(
                "SELECT event_hash FROM vault_cleanup_journal
                 WHERE state='purged' ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| VaultStoreError::DatabaseFailed)?
            .unwrap_or_default();
        let event_hash = vault_cleanup_event_hash(
            cleanup_id,
            started_at,
            sql_i64(completed_at_unix)?,
            candidate_count,
            removed_count,
            expected_keys_destroyed,
            &previous,
            VAULT_LOGICAL_ERASURE_DISCLOSURE,
        )?;
        transaction
            .execute(
                "UPDATE vault_cleanup_journal SET state='purged',completed_at_unix=?2,
                   key_records_destroyed=?3,previous_event_hash=?4,event_hash=?5
                 WHERE cleanup_id=?1 AND state='committed'",
                params![
                    cleanup_id,
                    sql_i64(completed_at_unix)?,
                    expected_keys_destroyed,
                    previous,
                    event_hash
                ],
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        transaction
            .commit()
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        Ok(VaultCleanupReportV1 {
            cleanup_id: cleanup_id.to_owned(),
            state: "purged".to_owned(),
            candidate_count: u64::try_from(candidate_count)
                .map_err(|_| VaultStoreError::ContentCorrupt)?,
            logically_removed_count: u64::try_from(removed_count)
                .map_err(|_| VaultStoreError::ContentCorrupt)?,
            key_records_destroyed: u64::try_from(expected_keys_destroyed)
                .map_err(|_| VaultStoreError::ContentCorrupt)?,
            quarantine_paths_pending: 0,
            started_at_unix: u64::try_from(started_at)
                .map_err(|_| VaultStoreError::ContentCorrupt)?,
            completed_at_unix,
            event_hash,
            erasure_disclosure: VAULT_LOGICAL_ERASURE_DISCLOSURE,
        })
    }
}

fn vault_lifecycle_table_count(db: &Connection) -> Result<u8, VaultStoreError> {
    let mut count = 0_u8;
    for table in VAULT_LIFECYCLE_TABLES {
        let exists: bool = db
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM sqlite_schema
                   WHERE type='table' AND name=?1
                 )",
                [table],
                |row| row.get(0),
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        count = count.saturating_add(u8::from(exists));
    }
    Ok(count)
}

fn initialize_vault_lifecycle_schema(db: &Connection) -> Result<(), VaultStoreError> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS vault_lifecycle_meta(
           singleton INTEGER PRIMARY KEY CHECK(singleton=1),
           schema_version INTEGER NOT NULL CHECK(schema_version>0)
         ) STRICT;
         INSERT INTO vault_lifecycle_meta(singleton,schema_version)
           VALUES(1,1) ON CONFLICT(singleton) DO NOTHING;
         CREATE TABLE IF NOT EXISTS vault_object_retention(
           case_id TEXT NOT NULL,
           object_id TEXT NOT NULL,
           version INTEGER NOT NULL CHECK(version>0),
           expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix>0),
           legal_hold INTEGER NOT NULL CHECK(legal_hold IN(0,1)),
           policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
           bound_at_unix INTEGER NOT NULL CHECK(bound_at_unix>0),
           hold_changed_at_unix INTEGER,
           PRIMARY KEY(object_id,version),
           FOREIGN KEY(object_id,version) REFERENCES object_journal(object_id,version)
         ) STRICT;
         CREATE INDEX IF NOT EXISTS idx_vault_retention_expiry
           ON vault_object_retention(expires_at_unix,legal_hold);
         CREATE TABLE IF NOT EXISTS vault_cleanup_journal(
           cleanup_id TEXT PRIMARY KEY,
           state TEXT NOT NULL CHECK(state IN('prepared','committed','purged')),
           started_at_unix INTEGER NOT NULL CHECK(started_at_unix>0),
           completed_at_unix INTEGER,
           candidate_count INTEGER NOT NULL CHECK(candidate_count>=0),
           removed_count INTEGER NOT NULL CHECK(removed_count>=0),
           key_records_destroyed INTEGER NOT NULL CHECK(key_records_destroyed>=0),
           previous_event_hash TEXT NOT NULL CHECK(length(previous_event_hash) IN(0,64)),
           event_hash TEXT NOT NULL CHECK(length(event_hash) IN(0,64)),
           erasure_disclosure TEXT NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS vault_cleanup_candidates(
           cleanup_id TEXT NOT NULL,
           case_id TEXT NOT NULL,
           object_id TEXT NOT NULL,
           version INTEGER NOT NULL CHECK(version>0),
           envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256)=64),
           state TEXT NOT NULL CHECK(state IN('pending','quarantined','purged')),
           PRIMARY KEY(cleanup_id,object_id,version),
           FOREIGN KEY(cleanup_id) REFERENCES vault_cleanup_journal(cleanup_id)
         ) STRICT;
         CREATE TRIGGER IF NOT EXISTS trg_vault_cleanup_no_delete
           BEFORE DELETE ON vault_cleanup_journal BEGIN
             SELECT RAISE(ABORT,'vault cleanup journal is append only');
           END;
         CREATE TRIGGER IF NOT EXISTS trg_vault_cleanup_purged_no_update
           BEFORE UPDATE ON vault_cleanup_journal WHEN OLD.state='purged' BEGIN
             SELECT RAISE(ABORT,'purged vault cleanup journal is immutable');
           END;",
    )
    .map_err(|_| VaultStoreError::DatabaseFailed)?;
    let version: u32 = db
        .query_row(
            "SELECT schema_version FROM vault_lifecycle_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    if version != VAULT_LIFECYCLE_SCHEMA_VERSION {
        return Err(VaultStoreError::DatabaseFailed);
    }
    Ok(())
}

fn cleanup_candidate_cases(candidates: &[VaultCleanupCandidateV1]) -> BTreeSet<CaseId> {
    candidates
        .iter()
        .map(|candidate| candidate.case_id.clone())
        .collect()
}

/// Computes the cases whose final committed object is part of this cleanup.
/// This runs under the same IMMEDIATE transaction that validates and commits
/// the candidates, before any object is moved to quarantine.  A case key must
/// exist at this boundary; only after the durable expected count is committed
/// may recovery treat an absent key as evidence of an interrupted finalizer.
fn cleanup_key_destruction_cases_before_commit(
    db: &Connection,
    cleanup_id: &str,
    candidates: &[VaultCleanupCandidateV1],
) -> Result<BTreeSet<CaseId>, VaultStoreError> {
    let mut cases = BTreeSet::new();
    for case_id in cleanup_candidate_cases(candidates) {
        let remaining_after_cleanup: i64 = db
            .query_row(
                "SELECT COUNT(*)
                 FROM object_journal AS journal
                 WHERE journal.case_id=?1 AND journal.state='committed'
                   AND NOT EXISTS(
                     SELECT 1 FROM vault_cleanup_candidates AS candidate
                     WHERE candidate.cleanup_id=?2
                       AND candidate.case_id=journal.case_id
                       AND candidate.object_id=journal.object_id
                       AND candidate.version=journal.version
                       AND candidate.state='pending'
                   )",
                params![case_id.as_str(), cleanup_id],
                |row| row.get(0),
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if remaining_after_cleanup == 0 {
            cases.insert(case_id);
        }
    }
    Ok(cases)
}

/// Recomputes the still-exclusive cleanup cases while the journal is in its
/// unfinished committed state.  Ordinary business writes are barred at this
/// startup boundary, so this must match the expected count durably bound by
/// the commit transaction.  Purged history deliberately does not use this
/// computation because later ordinary writes may create a new object/key in
/// the same case.
fn cleanup_key_destruction_cases_after_commit(
    db: &Connection,
    candidates: &[VaultCleanupCandidateV1],
) -> Result<BTreeSet<CaseId>, VaultStoreError> {
    let mut cases = BTreeSet::new();
    for case_id in cleanup_candidate_cases(candidates) {
        let committed: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM object_journal
                 WHERE case_id=?1 AND state='committed'",
                [case_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if committed == 0 {
            cases.insert(case_id);
        }
    }
    Ok(cases)
}

fn validate_vault_cleanup_candidate_current(
    db: &Connection,
    candidate: &VaultCleanupCandidateV1,
    completed_at_unix: u64,
) -> Result<(), VaultStoreError> {
    let valid: bool = db
        .query_row(
            "SELECT EXISTS(
               SELECT 1 FROM object_journal j
               JOIN vault_object_retention r
                 ON r.case_id=j.case_id AND r.object_id=j.object_id AND r.version=j.version
               WHERE j.case_id=?1 AND j.object_id=?2 AND j.version=?3
                 AND j.state='committed' AND j.envelope_sha256=?4
                 AND r.legal_hold=0 AND r.expires_at_unix<=?5
             )",
            params![
                candidate.case_id.as_str(),
                candidate.object_id.as_str(),
                sql_i64(candidate.version)?,
                candidate.envelope_sha256,
                sql_i64(completed_at_unix)?
            ],
            |row| row.get(0),
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    if valid {
        Ok(())
    } else {
        Err(VaultStoreError::ContentCorrupt)
    }
}

fn validate_cleanup_object_tree(
    root: &ValidatedVaultRoot,
    directory: &Path,
    envelope: &VaultObjectEnvelopeV1,
) -> Result<(), VaultStoreError> {
    let mut expected = BTreeSet::from([
        "envelope.json".to_owned(),
        "commit.json".to_owned(),
        "private-metadata.bin".to_owned(),
    ]);
    for chunk in &envelope.chunks {
        expected.insert(chunk_file_name(chunk.chunk_index));
    }
    let entries = fs::read_dir(directory).map_err(|_| VaultStoreError::IoFailed)?;
    for entry in entries {
        let entry = entry.map_err(|_| VaultStoreError::IoFailed)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or(VaultStoreError::UnsafeFilesystem)?
            .to_owned();
        if !expected.remove(&name) {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        validate_controlled_path(root, &entry.path(), true)?;
    }
    if expected.is_empty() {
        Ok(())
    } else {
        Err(VaultStoreError::ContentCorrupt)
    }
}

fn load_vault_cleanup_candidates(
    db: &Connection,
    cleanup_id: &str,
) -> Result<Vec<VaultCleanupCandidateV1>, VaultStoreError> {
    let mut statement = db
        .prepare(
            "SELECT case_id,object_id,version,envelope_sha256,state
             FROM vault_cleanup_candidates WHERE cleanup_id=?1
             ORDER BY case_id,object_id,version",
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    let rows = statement
        .query_map([cleanup_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    let mut candidates = Vec::new();
    for row in rows {
        let row = row.map_err(|_| VaultStoreError::DatabaseFailed)?;
        candidates.push(VaultCleanupCandidateV1 {
            case_id: CaseId::parse(row.0).map_err(|_| VaultStoreError::ContentCorrupt)?,
            object_id: ObjectId::parse(row.1).map_err(|_| VaultStoreError::ContentCorrupt)?,
            version: u64::try_from(row.2).map_err(|_| VaultStoreError::ContentCorrupt)?,
            envelope_sha256: row.3,
            state: row.4,
        });
    }
    Ok(candidates)
}

fn vault_cleanup_quarantine_path(
    root: &ValidatedVaultRoot,
    cleanup_id: &str,
    object_id: &ObjectId,
    version: u64,
) -> Result<PathBuf, VaultStoreError> {
    valid_vault_cleanup_id(cleanup_id)?;
    if version == 0 {
        return Err(VaultStoreError::InvalidInput);
    }
    Ok(root.quarantine.join(format!(
        "{cleanup_id}-{}-v{version:020}",
        object_id.as_str()
    )))
}

fn valid_vault_cleanup_id(value: &str) -> Result<(), VaultStoreError> {
    let Some(suffix) = value.strip_prefix("cln_") else {
        return Err(VaultStoreError::InvalidInput);
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultStoreError::InvalidInput);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn vault_cleanup_event_hash(
    cleanup_id: &str,
    started_at_unix: i64,
    completed_at_unix: i64,
    candidate_count: i64,
    removed_count: i64,
    keys_destroyed: i64,
    previous_event_hash: &str,
    disclosure: &str,
) -> Result<String, VaultStoreError> {
    let bytes = canonical_json_v1(&serde_json::json!({
        "cleanupId": cleanup_id,
        "startedAtUnix": started_at_unix,
        "completedAtUnix": completed_at_unix,
        "candidateCount": candidate_count,
        "removedCount": removed_count,
        "keyRecordsDestroyed": keys_destroyed,
        "previousEventHash": previous_event_hash,
        "erasureDisclosure": disclosure,
    }))
    .map_err(|_| VaultStoreError::ContentCorrupt)?;
    Ok(sha256_hex(&bytes))
}
