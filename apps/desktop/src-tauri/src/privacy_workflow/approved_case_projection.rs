use super::{
    canonical_redacted_bytes, reject_normalized_canaries, validate_loaded_review, ApprovedPayload,
    CanonicalRedactedPage, PrivacyWorkflowError, PrivacyWorkflowManager, StoredReviewPayload,
    APPROVED_PAYLOAD_SCHEMA_VERSION,
};
use privacy::{
    scan_residual, ApprovedProjectionBackfill, PrivacyCaseId, PrivacyStore,
    PrivacyStoreSchemaStatus, ProjectId, ProjectPrivacyCaseBindingStore,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::sync::atomic::Ordering;

const PROJECTED_DATABASE_HEADROOM_BYTES: u64 = 1024 * 1024;
const READY_PROJECTION_ROW_HEADROOM_PAGES: u64 = 3;
const BLOCKED_PROJECTION_ROW_HEADROOM_PAGES: u64 = 2;

struct PreparedProjection {
    redaction_id: String,
    source_fingerprint: String,
    canonical_payload: Vec<u8>,
    risk_head: String,
    protected_size: u64,
}

enum ProjectionMigrationCandidate {
    Ready(PreparedProjection),
    Blocked {
        redaction_id: String,
        source_fingerprint: String,
        error_code: &'static str,
    },
}

impl PrivacyWorkflowManager {
    pub(crate) fn approved_projection_migration_required(
        &self,
    ) -> Result<bool, PrivacyWorkflowError> {
        Ok(matches!(
            self.preflight_privacy_store_schema_read_only()?,
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 }
        ))
    }

    /// Computes a migration-specific fingerprint from a query-only Privacy
    /// snapshot. It is stable across projection backfill, blocking decisions and
    /// migration-ledger writes, but changes if any v5 source, risk, binding or
    /// Vault provenance changes.
    pub(crate) fn approved_projection_migration_source_fingerprint(
        &self,
    ) -> Result<String, PrivacyWorkflowError> {
        let connection = self.open_projection_migration_read_snapshot()?;
        connection
            .execute_batch("BEGIN DEFERRED")
            .map_err(|_| projection_migration_error("approved_projection_snapshot_failed"))?;
        let result = PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
            .map_err(PrivacyWorkflowError::store);
        let rollback = connection
            .execute_batch("ROLLBACK")
            .map_err(|_| projection_migration_error("approved_projection_snapshot_failed"));
        rollback?;
        result
    }

    /// Performs the v5->v6 approved-only projection backfill after the caller
    /// has established the source-bound five-component backup.
    pub(crate) fn run_approved_projection_migration_after_backup_for_source(
        &self,
        expected_source_fingerprint: &str,
    ) -> Result<(), PrivacyWorkflowError> {
        if !is_lower_hash(expected_source_fingerprint) {
            return Err(projection_migration_error(
                "approved_projection_source_fingerprint_invalid",
            ));
        }
        let _guard = self.gate();
        let mut connection = self.open_raw_connection()?;
        match PrivacyStore::preflight_schema(&connection).map_err(PrivacyWorkflowError::store)? {
            PrivacyStoreSchemaStatus::Current => {
                let current =
                    PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
                        .map_err(PrivacyWorkflowError::store)?;
                if current != expected_source_fingerprint {
                    return Err(projection_migration_error(
                        "approved_projection_source_changed",
                    ));
                }
                self.shared
                    .schema_upgrade_required
                    .store(false, Ordering::Release);
                return Ok(());
            }
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 } => {}
            PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
                return Err(projection_migration_error(
                    "approved_projection_v5_required",
                ))
            }
        }
        verify_projection_source_fingerprint(&connection, expected_source_fingerprint)?;
        let candidates = self.prepare_projection_candidates(&connection)?;
        verify_projected_database_capacity(&connection, &candidates)?;
        verify_projection_source_fingerprint(&connection, expected_source_fingerprint)?;

        PrivacyStore::prepare_approved_projection_schema_after_backup(&connection)
            .map_err(PrivacyWorkflowError::store)?;
        for candidate in candidates {
            match candidate {
                ProjectionMigrationCandidate::Ready(candidate) => {
                    PrivacyStore::backfill_approved_projection_after_backup(
                        &mut connection,
                        &ApprovedProjectionBackfill {
                            redaction_id: &candidate.redaction_id,
                            source_fingerprint: &candidate.source_fingerprint,
                            approved_payload_plaintext: &candidate.canonical_payload,
                            approved_risk_revision_hash: &candidate.risk_head,
                        },
                    )
                    .map_err(PrivacyWorkflowError::store)?;
                }
                ProjectionMigrationCandidate::Blocked {
                    redaction_id,
                    source_fingerprint,
                    error_code,
                } => {
                    PrivacyStore::block_approved_projection_after_backup(
                        &mut connection,
                        &redaction_id,
                        &source_fingerprint,
                        error_code,
                    )
                    .map_err(PrivacyWorkflowError::store)?;
                }
            }
        }
        verify_projection_source_fingerprint(&connection, expected_source_fingerprint)?;
        PrivacyStore::finalize_approved_projection_schema_after_backup(&connection)
            .map_err(PrivacyWorkflowError::store)?;
        self.shared
            .schema_upgrade_required
            .store(false, Ordering::Release);
        Ok(())
    }

    fn prepare_projection_candidates(
        &self,
        connection: &Connection,
    ) -> Result<Vec<ProjectionMigrationCandidate>, PrivacyWorkflowError> {
        let redaction_ids = active_approved_projection_candidate_ids(connection)?;
        let mut candidates = Vec::with_capacity(redaction_ids.len());
        for redaction_id in redaction_ids {
            let source_fingerprint = PrivacyStore::approved_projection_migration_row_fingerprint(
                connection,
                &redaction_id,
            )
            .map_err(PrivacyWorkflowError::store)?;
            match self.prepare_projection_candidate(connection, &redaction_id) {
                Ok(mut candidate) => {
                    candidate.source_fingerprint = source_fingerprint;
                    candidates.push(ProjectionMigrationCandidate::Ready(candidate));
                }
                Err(error_code) => candidates.push(ProjectionMigrationCandidate::Blocked {
                    redaction_id,
                    source_fingerprint,
                    error_code,
                }),
            }
        }
        Ok(candidates)
    }

    fn prepare_projection_candidate(
        &self,
        connection: &Connection,
        redaction_id: &str,
    ) -> Result<PreparedProjection, &'static str> {
        let loaded = PrivacyStore::load_review_draft(connection, redaction_id)
            .map_err(|_| "approved_projection_full_blob_invalid")?;
        let stored: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| "approved_projection_full_blob_invalid")?;
        validate_loaded_review(&loaded, &stored)
            .map_err(|_| "approved_projection_review_identity_mismatch")?;
        self.verify_stored_vault_source(connection, &stored)
            .map_err(|_| "approved_projection_vault_mismatch")?;
        let project_id = connection
            .query_row(
                "SELECT project_id
                 FROM privacy_materials
                 WHERE material_id=?1 AND migration_status='ready'
                   AND deleted_at IS NULL",
                [&stored.material_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| "approved_projection_project_binding_invalid")?
            .flatten()
            .ok_or("approved_projection_project_binding_invalid")?;
        let project_id = ProjectId::parse(project_id)
            .map_err(|_| "approved_projection_project_binding_invalid")?;
        let privacy_case_id = stored
            .case_id
            .as_ref()
            .ok_or("approved_projection_project_binding_invalid")
            .and_then(|case_id| {
                PrivacyCaseId::parse(case_id.clone())
                    .map_err(|_| "approved_projection_project_binding_invalid")
            })?;
        ProjectPrivacyCaseBindingStore::validate_pair(connection, &project_id, &privacy_case_id)
            .map_err(|_| "approved_projection_project_binding_invalid")?;

        let pages = stored
            .pages
            .iter()
            .map(|page| CanonicalRedactedPage {
                page_number: page.page_number,
                text: page.suggested_redacted_text.clone(),
            })
            .collect::<Vec<_>>();
        if pages.is_empty()
            || pages.len() != stored.page_count as usize
            || pages
                .windows(2)
                .any(|pair| pair[0].page_number >= pair[1].page_number)
        {
            return Err("approved_projection_page_mismatch");
        }
        let redacted_content =
            canonical_redacted_bytes(&pages).map_err(|_| "approved_projection_payload_invalid")?;
        if privacy::sha256_hex(&redacted_content) != stored.suggested_redacted_content_sha256 {
            return Err("approved_projection_redacted_hash_mismatch");
        }
        reject_normalized_canaries(&pages, &stored.forbidden_canaries)
            .map_err(|_| "approved_projection_canary_detected")?;
        let canonical_payload = serde_json::to_vec(&ApprovedPayload {
            schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
            source_sha256: &stored.source_sha256,
            extraction_sha256: &stored.extraction_sha256,
            media_type: &stored.media_type,
            pages: &pages,
        })
        .map_err(|_| "approved_projection_payload_invalid")?;
        let residual = scan_residual(&canonical_payload)
            .map_err(|_| "approved_projection_residual_scan_failed")?;
        if !residual.passed {
            return Err("approved_projection_residual_detected");
        }
        let indexed_hash = connection
            .query_row(
                "SELECT approved_payload_sha256
                 FROM privacy_redactions
                 WHERE redaction_id=?1 AND review_state='approved'
                   AND generation_status='ready'
                   AND revocation_state='active'
                   AND revoked_at IS NULL
                   AND unresolved_high_risk_count=0",
                [redaction_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| "approved_projection_index_invalid")?
            .flatten()
            .ok_or("approved_projection_index_invalid")?;
        if privacy::sha256_hex(&canonical_payload) != indexed_hash {
            return Err("approved_projection_payload_hash_mismatch");
        }
        let (risk_revision, risk_head) =
            PrivacyStore::verify_complete_risk_review_chain(connection, redaction_id)
                .map_err(|_| "approved_projection_risk_chain_invalid")?;
        let indexed_revision = connection
            .query_row(
                "SELECT risk_revision FROM privacy_redactions WHERE redaction_id=?1",
                [redaction_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| "approved_projection_risk_chain_invalid")
            .and_then(|value| {
                u64::try_from(value).map_err(|_| "approved_projection_risk_chain_invalid")
            })?;
        if indexed_revision != risk_revision {
            return Err("approved_projection_risk_chain_invalid");
        }
        let protected_size = privacy::protect_local(&canonical_payload)
            .map_err(|_| "approved_projection_protection_failed")?
            .len() as u64;
        Ok(PreparedProjection {
            redaction_id: redaction_id.to_owned(),
            source_fingerprint: String::new(),
            canonical_payload,
            risk_head,
            protected_size,
        })
    }

    fn open_projection_migration_read_snapshot(&self) -> Result<Connection, PrivacyWorkflowError> {
        let connection = Connection::open_with_flags(
            &self.shared.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| projection_migration_error("approved_projection_snapshot_failed"))?;
        connection
            .execute_batch(
                "PRAGMA query_only=ON;
                 PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;",
            )
            .map_err(|_| projection_migration_error("approved_projection_snapshot_failed"))?;
        Ok(connection)
    }
}

fn active_approved_projection_candidate_ids(
    connection: &Connection,
) -> Result<Vec<String>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT redaction_id
             FROM privacy_redactions
             WHERE review_state='approved'
               AND generation_status='ready'
               AND revocation_state='active'
               AND revoked_at IS NULL
             ORDER BY material_id ASC,generation_number ASC,redaction_id ASC",
        )
        .map_err(|_| projection_migration_error("approved_projection_source_invalid"))?;
    let redaction_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| projection_migration_error("approved_projection_source_invalid"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| projection_migration_error("approved_projection_source_invalid"))?;
    Ok(redaction_ids)
}

fn verify_projection_source_fingerprint(
    connection: &Connection,
    expected: &str,
) -> Result<(), PrivacyWorkflowError> {
    let current = PrivacyStore::approved_projection_migration_source_fingerprint(connection)
        .map_err(PrivacyWorkflowError::store)?;
    if current != expected {
        return Err(projection_migration_error(
            "approved_projection_source_changed",
        ));
    }
    Ok(())
}

fn verify_projected_database_capacity(
    connection: &Connection,
    candidates: &[ProjectionMigrationCandidate],
) -> Result<(), PrivacyWorkflowError> {
    let page_count = connection
        .pragma_query_value(None, "page_count", |row| row.get::<_, i64>(0))
        .map_err(|_| projection_migration_error("approved_projection_capacity_unknown"))
        .and_then(|value| {
            u64::try_from(value)
                .map_err(|_| projection_migration_error("approved_projection_capacity_unknown"))
        })?;
    let page_size = connection
        .pragma_query_value(None, "page_size", |row| row.get::<_, i64>(0))
        .map_err(|_| projection_migration_error("approved_projection_capacity_unknown"))
        .and_then(|value| {
            u64::try_from(value)
                .map_err(|_| projection_migration_error("approved_projection_capacity_unknown"))
        })?;
    let current_bytes = page_count
        .checked_mul(page_size)
        .ok_or_else(|| projection_migration_error("approved_projection_capacity_exceeded"))?;
    let projection_bytes = candidates.iter().try_fold(0_u64, |total, candidate| {
        let next = match candidate {
            ProjectionMigrationCandidate::Ready(candidate) => {
                let row_headroom = page_size
                    .checked_mul(READY_PROJECTION_ROW_HEADROOM_PAGES)
                    .ok_or_else(|| {
                        projection_migration_error("approved_projection_capacity_exceeded")
                    })?;
                candidate
                    .protected_size
                    .checked_add(row_headroom)
                    .ok_or_else(|| {
                        projection_migration_error("approved_projection_capacity_exceeded")
                    })?
            }
            ProjectionMigrationCandidate::Blocked { .. } => page_size
                .checked_mul(BLOCKED_PROJECTION_ROW_HEADROOM_PAGES)
                .ok_or_else(|| {
                    projection_migration_error("approved_projection_capacity_exceeded")
                })?,
        };
        total
            .checked_add(next)
            .ok_or_else(|| projection_migration_error("approved_projection_capacity_exceeded"))
    })?;
    let estimated = current_bytes
        .checked_add(projection_bytes)
        .and_then(|value| value.checked_add(PROJECTED_DATABASE_HEADROOM_BYTES))
        .ok_or_else(|| projection_migration_error("approved_projection_capacity_exceeded"))?;
    let maximum = u64::try_from(privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES)
        .map_err(|_| projection_migration_error("approved_projection_capacity_exceeded"))?;
    if estimated > maximum {
        return Err(projection_migration_error(
            "approved_projection_capacity_exceeded",
        ));
    }
    Ok(())
}

fn is_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn projection_migration_error(code: &'static str) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        code,
        "The approved-only case projection migration failed closed.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_query_selects_only_active_ready_approved_generations() {
        let connection = Connection::open_in_memory().expect("memory database");
        connection
            .execute_batch(
                "CREATE TABLE privacy_redactions(
                    redaction_id TEXT PRIMARY KEY,
                    material_id TEXT NOT NULL,
                    generation_number INTEGER NOT NULL,
                    generation_status TEXT NOT NULL,
                    review_state TEXT NOT NULL,
                    revocation_state TEXT NOT NULL,
                    revoked_at TEXT
                 );
                 INSERT INTO privacy_redactions VALUES
                    ('active-approved','material-a',1,'ready','approved','active',NULL),
                    ('revoked-approved','material-b',1,'ready','approved','revoked',
                     '2026-07-30 00:00:00'),
                    ('legacy-revoked-approved','material-c',1,'ready','approved',
                     'revoked_legacy_time_unknown',NULL),
                    ('review-state-revoked','material-d',1,'ready','revoked','active',NULL),
                    ('stale','material-e',1,'ready','stale','active',NULL),
                    ('pending','material-f',1,'ready','review_required','active',NULL),
                    ('blocked','material-g',1,'blocked','approved','active',NULL),
                    ('inconsistent-active','material-h',1,'ready','approved','active',
                     '2026-07-30 00:00:00');",
            )
            .expect("candidate rows");

        assert_eq!(
            active_approved_projection_candidate_ids(&connection).expect("candidate query"),
            vec!["active-approved".to_owned()]
        );
    }

    #[test]
    fn capacity_gate_accepts_ready_ciphertext_and_blocked_ledger_headroom() {
        let connection = Connection::open_in_memory().expect("memory database");
        connection
            .execute_batch("CREATE TABLE capacity_test(value TEXT);")
            .expect("capacity schema");
        let candidates = vec![
            ProjectionMigrationCandidate::Ready(PreparedProjection {
                redaction_id: "redaction-1".to_owned(),
                source_fingerprint: "a".repeat(64),
                canonical_payload: vec![1],
                risk_head: "b".repeat(64),
                protected_size: 4096,
            }),
            ProjectionMigrationCandidate::Blocked {
                redaction_id: "redaction-2".to_owned(),
                source_fingerprint: "c".repeat(64),
                error_code: "approved_projection_test_blocked",
            },
        ];
        verify_projected_database_capacity(&connection, &candidates)
            .expect("small migration capacity");
    }

    #[test]
    fn capacity_gate_rejects_projected_database_over_raw_limit() {
        let connection = Connection::open_in_memory().expect("memory database");
        connection
            .execute_batch("CREATE TABLE capacity_test(value TEXT);")
            .expect("capacity schema");
        let candidates = vec![ProjectionMigrationCandidate::Ready(PreparedProjection {
            redaction_id: "redaction-too-large".to_owned(),
            source_fingerprint: "a".repeat(64),
            canonical_payload: vec![1],
            risk_head: "b".repeat(64),
            protected_size: u64::try_from(privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES)
                .expect("raw database maximum fits u64"),
        })];
        assert_eq!(
            verify_projected_database_capacity(&connection, &candidates)
                .expect_err("oversized projected database")
                .code(),
            "approved_projection_capacity_exceeded"
        );
    }
}
