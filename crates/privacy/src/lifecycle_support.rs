// Included from lifecycle.rs so these helpers remain private to the lifecycle module.

fn insert_retention_policy(
    transaction: &Transaction<'_>,
    policy: &RetentionPolicyV1,
) -> Result<(), LifecycleError> {
    transaction
        .execute(
            "INSERT INTO privacy_retention_policy(
               singleton,policy_id,review_retention_seconds,mapping_retention_seconds,
               receipt_grace_seconds,backup_retention_seconds,revision,updated_at_unix
             ) VALUES(1,?1,?2,?3,?4,?5,?6,?7)",
            params![
                policy.policy_id,
                sql_i64(policy.review_retention_seconds)?,
                sql_i64(policy.mapping_retention_seconds)?,
                sql_i64(policy.receipt_grace_seconds)?,
                sql_i64(policy.backup_retention_seconds)?,
                sql_i64(policy.revision)?,
                sql_i64(policy.updated_at_unix)?
            ],
        )
        .map_err(|_| LifecycleError::Database)?;
    Ok(())
}

fn load_retention_policy(connection: &Connection) -> Result<RetentionPolicyV1, LifecycleError> {
    let row: (String, i64, i64, i64, i64, i64, i64) = connection
        .query_row(
            "SELECT policy_id,review_retention_seconds,mapping_retention_seconds,
                    receipt_grace_seconds,backup_retention_seconds,revision,updated_at_unix
             FROM privacy_retention_policy WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )
        .map_err(|_| LifecycleError::Database)?;
    let policy = RetentionPolicyV1 {
        policy_id: row.0,
        review_retention_seconds: sql_u64(row.1)?,
        mapping_retention_seconds: sql_u64(row.2)?,
        receipt_grace_seconds: sql_u64(row.3)?,
        backup_retention_seconds: sql_u64(row.4)?,
        revision: sql_u64(row.5)?,
        updated_at_unix: sql_u64(row.6)?,
    };
    policy.validate()?;
    Ok(policy)
}

fn ensure_workspace(
    connection: &Connection,
    expected: &WorkspaceInstanceId,
) -> Result<(), LifecycleError> {
    let row: Option<(i64, String)> = connection
        .query_row(
            "SELECT schema_version,workspace_instance_id FROM privacy_lifecycle_meta
             WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| LifecycleError::Database)?;
    if row
        != Some((
            PRIVACY_LIFECYCLE_SCHEMA_VERSION,
            expected.as_str().to_owned(),
        ))
    {
        return Err(LifecycleError::EnvironmentMismatch);
    }
    Ok(())
}

fn ensure_redaction_exists(
    connection: &Connection,
    redaction_id: &str,
) -> Result<(), LifecycleError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM privacy_redactions WHERE redaction_id=?1)",
            [redaction_id],
            |row| row.get(0),
        )
        .map_err(|_| LifecycleError::Database)?;
    if exists {
        Ok(())
    } else {
        Err(LifecycleError::MappingNotAvailable)
    }
}

fn load_active_mapping_key(connection: &Connection) -> Result<(u64, SecretKey32), LifecycleError> {
    let active: i64 = connection
        .query_row(
            "SELECT active_mapping_key_version FROM privacy_lifecycle_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| LifecycleError::EnvironmentMismatch)?;
    let version = sql_u64(active)?;
    Ok((version, load_mapping_key(connection, version)?))
}

fn load_mapping_key(
    connection: &Connection,
    key_version: u64,
) -> Result<SecretKey32, LifecycleError> {
    let row: Option<(Option<Vec<u8>>, String, String)> = connection
        .query_row(
            "SELECT protected_key,protected_key_sha256,state FROM privacy_mapping_keys
             WHERE key_version=?1",
            [sql_i64(key_version)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| LifecycleError::Database)?;
    let Some((Some(protected_key), protected_sha256, state)) = row else {
        return Err(LifecycleError::MappingRevoked);
    };
    if !matches!(state.as_str(), "active" | "retired") {
        return Err(LifecycleError::MappingRevoked);
    }
    if sha256_hex(&protected_key) != protected_sha256 {
        return Err(LifecycleError::Crypto);
    }
    unwrap_case_key(&protected_key).map_err(map_crypto_error)
}

fn mapping_aad(
    workspace: &WorkspaceInstanceId,
    mapping_id: &str,
    redaction_id: &str,
    revision: u64,
    key_version: u64,
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<Vec<u8>, LifecycleError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct MappingAad<'a> {
        aad_version: &'static str,
        workspace_instance_id: &'a WorkspaceInstanceId,
        mapping_id: &'a str,
        redaction_id: &'a str,
        revision: u64,
        key_version: u64,
        created_at_unix: u64,
        expires_at_unix: u64,
    }
    canonical_json_v1(&MappingAad {
        aad_version: MAPPING_AAD_VERSION,
        workspace_instance_id: workspace,
        mapping_id,
        redaction_id,
        revision,
        key_version,
        created_at_unix,
        expires_at_unix,
    })
    .map_err(|_| LifecycleError::InvalidInput)
}

fn append_mapping_access_audit(
    connection: &mut Connection,
    context: &MappingAccessContextV1<'_>,
    mapping_id: &str,
    allowed: bool,
    reason_code: &str,
) -> Result<(), LifecycleError> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| LifecycleError::Database)?;
    let previous = transaction
        .query_row(
            "SELECT event_hash FROM privacy_mapping_access_audit ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| LifecycleError::Database)?
        .unwrap_or_default();
    let purpose_sha256 = sha256_hex(context.purpose.as_bytes());
    let event_hash = sha256_hex(
        format!(
            "mapping-access-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            context.access_id,
            mapping_id,
            context.redaction_id,
            purpose_sha256,
            context.now_unix,
            allowed,
            reason_code,
            previous
        )
        .as_bytes(),
    );
    transaction
        .execute(
            "INSERT INTO privacy_mapping_access_audit(
               access_id,mapping_id,redaction_id,purpose_sha256,occurred_at_unix,
               allowed,reason_code,previous_event_hash,event_hash
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                context.access_id,
                mapping_id,
                context.redaction_id,
                purpose_sha256,
                sql_i64(context.now_unix)?,
                allowed,
                reason_code,
                previous,
                event_hash
            ],
        )
        .map_err(|_| LifecycleError::Conflict)?;
    transaction.commit().map_err(|_| LifecycleError::Database)
}

fn insert_cleanup_candidate(
    transaction: &Transaction<'_>,
    cleanup_id: &str,
    target_kind: &str,
    target_id: &str,
    expected_sha256: &str,
) -> Result<(), LifecycleError> {
    transaction
        .execute(
            "INSERT INTO privacy_cleanup_candidates(
               cleanup_id,target_kind,target_id,expected_sha256,state
             ) VALUES(?1,?2,?3,?4,'pending')",
            params![cleanup_id, target_kind, target_id, expected_sha256],
        )
        .map_err(|_| LifecycleError::Database)?;
    Ok(())
}

#[derive(Debug)]
struct CleanupCandidate {
    target_kind: String,
    target_id: String,
    expected_sha256: String,
}

fn cleanup_evidence_manifest(
    connection: &Connection,
    cleanup_id: &str,
) -> Result<String, LifecycleError> {
    let candidates = {
        let mut statement = connection
            .prepare(
                "SELECT target_kind,target_id,expected_sha256,state
                 FROM privacy_cleanup_candidates
                 WHERE cleanup_id=?1
                 ORDER BY target_kind,target_id",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([cleanup_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| LifecycleError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LifecycleError::Database)?;
        rows
    };
    let redaction_evidence = {
        let mut statement = connection
            .prepare(
                "SELECT redaction_id,material_id,generation_number,expected_sha256,
                        material_provenance_sha256,material_tombstoned
                 FROM privacy_cleanup_redaction_evidence
                 WHERE cleanup_id=?1
                 ORDER BY redaction_id",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([cleanup_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })
            .map_err(|_| LifecycleError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LifecycleError::Database)?;
        rows
    };
    let canonical = canonical_json_v1(&serde_json::json!({
        "candidates": candidates,
        "redactionEvidence": redaction_evidence,
    }))
    .map_err(|_| LifecycleError::CleanupIntegrity)?;
    Ok(sha256_hex(&canonical))
}

fn cleanup_event_hash_with_evidence(
    row: &CleanupJournalRow,
    evidence_manifest_sha256: &str,
) -> Result<String, LifecycleError> {
    if evidence_manifest_sha256.len() != 64 {
        return Err(LifecycleError::CleanupIntegrity);
    }
    let legacy_event_hash = cleanup_event_hash(row)?;
    Ok(sha256_hex(
        format!("privacy-cleanup-event-v2\0{legacy_event_hash}\0{evidence_manifest_sha256}")
            .as_bytes(),
    ))
}

fn cleanup_chain_tail(connection: &Connection) -> Result<String, LifecycleError> {
    let tails = {
        let mut statement = connection
            .prepare(
                "SELECT journal.event_hash
                 FROM privacy_cleanup_journal AS journal
                 WHERE journal.state IN('committed','failed')
                   AND NOT EXISTS(
                     SELECT 1 FROM privacy_cleanup_journal AS child
                     WHERE child.state IN('committed','failed')
                       AND child.previous_event_hash=journal.event_hash
                   )
                 ORDER BY journal.rowid",
            )
            .map_err(|_| LifecycleError::Database)?;
        let values = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|_| LifecycleError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LifecycleError::Database)?;
        values
    };
    match tails.as_slice() {
        [] => Ok(String::new()),
        [tail] if tail.len() == 64 => Ok(tail.clone()),
        _ => Err(LifecycleError::CleanupIntegrity),
    }
}

fn retention_material_provenance_sha256(
    connection: &Connection,
    material_id: &str,
) -> Result<String, LifecycleError> {
    let material = connection
        .query_row(
            "SELECT project_id,legacy_case_id,attachment_id,source_sha256,
                    source_name_sha256,media_type,page_count,source_kind,
                    extraction_status,migration_status,created_at
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .map_err(|_| LifecycleError::CleanupIntegrity)?;
    let vault_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='table' AND name='privacy_vault_material_refs'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| LifecycleError::Database)?;
    let vault = if vault_table_exists {
        connection
            .query_row(
                "SELECT case_id,object_id,object_version,source_sha256,
                        envelope_sha256,content_bytes
                 FROM privacy_vault_material_refs WHERE material_id=?1",
                [material_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?
    } else {
        None
    };
    let canonical = canonical_json_v1(&serde_json::json!({
        "materialId": material_id,
        "projectId": material.0,
        "legacyCaseId": material.1,
        "attachmentId": material.2,
        "sourceSha256": material.3,
        "sourceNameSha256": material.4,
        "mediaType": material.5,
        "pageCount": material.6,
        "sourceKind": material.7,
        "extractionStatus": material.8,
        "migrationStatus": material.9,
        "createdAt": material.10,
        "vaultIdentity": vault,
    }))
    .map_err(|_| LifecycleError::CleanupIntegrity)?;
    Ok(sha256_hex(&canonical))
}

fn preflight_cleanup_invalidation(
    connection: &mut Connection,
    cleanup_id: &str,
    now_unix: u64,
) -> Result<BTreeSet<String>, LifecycleError> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|_| LifecycleError::Database)?;
    let (state, started_at, candidate_count): (String, i64, i64) = transaction
        .query_row(
            "SELECT state,started_at_unix,candidate_count FROM privacy_cleanup_journal
             WHERE cleanup_id=?1",
            [cleanup_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| LifecycleError::Database)?
        .ok_or(LifecycleError::CleanupNotPrepared)?;
    if state != "prepared" || sql_u64(started_at)? > now_unix {
        return Err(LifecycleError::CleanupNotPrepared);
    }
    let candidates = {
        let mut statement = transaction
            .prepare(
                "SELECT target_kind,target_id,expected_sha256
                 FROM privacy_cleanup_candidates WHERE cleanup_id=?1 AND state='pending'
                 ORDER BY CASE target_kind WHEN 'redaction' THEN 0 WHEN 'mapping' THEN 1 WHEN 'approved_output' THEN 2 ELSE 3 END,
                          target_id",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([cleanup_id], |row| {
                Ok(CleanupCandidate {
                    target_kind: row.get(0)?,
                    target_id: row.get(1)?,
                    expected_sha256: row.get(2)?,
                })
            })
            .map_err(|_| LifecycleError::Database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| LifecycleError::Database)?
    };
    if i64::try_from(candidates.len()).ok() != Some(candidate_count) {
        return Err(LifecycleError::CleanupIntegrity);
    }
    for candidate in &candidates {
        validate_cleanup_candidate(&transaction, candidate, now_unix)?;
    }
    let bindings = candidates
        .iter()
        .filter(|candidate| candidate.target_kind == "redaction")
        .map(|candidate| candidate.target_id.clone())
        .collect();
    transaction.commit().map_err(|_| LifecycleError::Database)?;
    Ok(bindings)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RetentionProjectDeletionScopeV1 {
    schema_version: String,
    project_id: String,
    privacy_case_id: Option<String>,
    material_ids: Vec<String>,
    generation_ids: Vec<String>,
}

fn completed_project_deletion_contains_material(
    connection: &Connection,
    material_id: &str,
) -> Result<bool, LifecycleError> {
    let journal_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='table' AND name='project_deletion_journal'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| LifecycleError::Database)?;
    if !journal_exists {
        return Ok(false);
    }
    let row: Option<(String, Option<String>, String, String, String)> = connection
        .query_row(
            "SELECT journal.project_id,journal.privacy_case_id,
                    journal.scope_json,journal.scope_sha256,journal.state
             FROM privacy_materials AS material
             JOIN project_deletion_journal AS journal
               ON journal.project_id=material.project_id
             WHERE material.material_id=?1
               AND material.state='revoked'
               AND material.deleted_at IS NOT NULL",
            [material_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| LifecycleError::Database)?;
    let Some((project_id, privacy_case_id, scope_json, scope_sha256, state)) = row else {
        return Ok(false);
    };
    if state != "completed" {
        return Err(LifecycleError::CleanupIntegrity);
    }
    let scope: RetentionProjectDeletionScopeV1 =
        serde_json::from_str(&scope_json).map_err(|_| LifecycleError::CleanupIntegrity)?;
    let identifiers_valid = scope
        .material_ids
        .iter()
        .chain(scope.generation_ids.iter())
        .all(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value.trim() == value
                && !value.chars().any(char::is_control)
        });
    let strictly_sorted = |values: &[String]| {
        values
            .windows(2)
            .all(|pair| pair[0].as_str() < pair[1].as_str())
    };
    let canonical = serde_json::to_vec(&scope).map_err(|_| LifecycleError::CleanupIntegrity)?;
    if scope.schema_version != "project-deletion-journal-v1"
        || scope.project_id != project_id
        || scope.privacy_case_id != privacy_case_id
        || !identifiers_valid
        || !strictly_sorted(&scope.material_ids)
        || !strictly_sorted(&scope.generation_ids)
        || sha256_hex(&canonical) != scope_sha256
    {
        return Err(LifecycleError::CleanupIntegrity);
    }
    Ok(scope
        .material_ids
        .binary_search_by(|value| value.as_str().cmp(material_id))
        .is_ok())
}

fn commit_cleanup_transaction(
    connection: &mut Connection,
    cleanup_id: &str,
    completed_at_unix: u64,
) -> Result<CleanupReportV1, LifecycleError> {
    let transaction = connection
        .transaction()
        .map_err(|_| LifecycleError::Database)?;
    let (state, started_at, candidate_count): (String, i64, i64) = transaction
        .query_row(
            "SELECT state,started_at_unix,candidate_count FROM privacy_cleanup_journal
             WHERE cleanup_id=?1",
            [cleanup_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| LifecycleError::Database)?
        .ok_or(LifecycleError::CleanupNotPrepared)?;
    if state != "prepared" || sql_u64(started_at)? > completed_at_unix {
        return Err(LifecycleError::CleanupNotPrepared);
    }
    let candidates = {
        let mut statement = transaction
            .prepare(
                "SELECT target_kind,target_id,expected_sha256
                 FROM privacy_cleanup_candidates WHERE cleanup_id=?1 AND state='pending'
                 ORDER BY CASE target_kind WHEN 'redaction' THEN 0 WHEN 'mapping' THEN 1 WHEN 'approved_output' THEN 2 ELSE 3 END,
                          target_id",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([cleanup_id], |row| {
                Ok(CleanupCandidate {
                    target_kind: row.get(0)?,
                    target_id: row.get(1)?,
                    expected_sha256: row.get(2)?,
                })
            })
            .map_err(|_| LifecycleError::Database)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| LifecycleError::Database)?
    };
    if i64::try_from(candidates.len()).ok() != Some(candidate_count) {
        return Err(LifecycleError::CleanupIntegrity);
    }
    for candidate in &candidates {
        validate_cleanup_candidate(&transaction, candidate, completed_at_unix)?;
    }
    let migration_ledger_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='table' AND name='case_material_migration_ledger'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| LifecycleError::Database)?;
    let vault_ref_table_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='table' AND name='privacy_vault_material_refs'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| LifecycleError::Database)?;
    let mut removed = 0_u64;
    for candidate in &candidates {
        match candidate.target_kind.as_str() {
            "redaction" => {
                let (material_id, generation_number): (String, i64) = transaction
                    .query_row(
                        "SELECT material_id,generation_number
                         FROM privacy_redactions WHERE redaction_id=?1",
                        [candidate.target_id.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|_| LifecycleError::CleanupIntegrity)?;
                let material_provenance_sha256 =
                    retention_material_provenance_sha256(&transaction, &material_id)?;
                let final_material_generation: bool = !transaction
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM privacy_redactions
                            WHERE material_id=?1 AND redaction_id<>?2
                         )",
                        params![material_id, candidate.target_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| LifecycleError::Database)?;
                let retain_migrated_identity =
                    if final_material_generation && migration_ledger_exists {
                        transaction
                            .query_row(
                                "SELECT EXISTS(
                                    SELECT 1 FROM case_material_migration_ledger
                                    WHERE target_material_id=?1
                                 )",
                                [&material_id],
                                |row| row.get::<_, bool>(0),
                            )
                            .map_err(|_| LifecycleError::Database)?
                    } else {
                        false
                    };
                let retain_project_deletion_identity = if final_material_generation {
                    completed_project_deletion_contains_material(&transaction, &material_id)?
                } else {
                    false
                };
                let material_tombstoned =
                    retain_migrated_identity || retain_project_deletion_identity;
                transaction
                    .execute(
                        "INSERT INTO privacy_cleanup_redaction_evidence(
                            cleanup_id,redaction_id,material_id,generation_number,
                            expected_sha256,material_provenance_sha256,material_tombstoned
                         ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                        params![
                            cleanup_id,
                            candidate.target_id,
                            material_id,
                            generation_number,
                            candidate.expected_sha256,
                            material_provenance_sha256,
                            material_tombstoned,
                        ],
                    )
                    .map_err(|_| LifecycleError::Database)?;
                transaction
                    .execute(
                        "UPDATE privacy_receipts SET revoked_at_unix=COALESCE(revoked_at_unix,?1)
                         WHERE redaction_id=?2",
                        params![sql_i64(completed_at_unix)?, candidate.target_id],
                    )
                    .map_err(|_| LifecycleError::Database)?;
                let changed = transaction
                    .execute(
                        "DELETE FROM privacy_redactions WHERE redaction_id=?1",
                        [candidate.target_id.as_str()],
                    )
                    .map_err(|_| LifecycleError::Database)?;
                if changed != 1 {
                    return Err(LifecycleError::CleanupIntegrity);
                }
                // A material can own multiple redaction generations. Never cascade-delete a
                // retained or legally held sibling merely because one generation expired. Once
                // the final generation is erased, keep only an explicit non-sensitive tombstone
                // when an append-only migration ledger or completed project deletion still needs
                // this material identity as durable provenance.
                let remaining_generations: bool = transaction
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM privacy_redactions WHERE material_id=?1
                         )",
                        [&material_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| LifecycleError::Database)?;
                if !remaining_generations {
                    if retain_migrated_identity || retain_project_deletion_identity {
                        if vault_ref_table_exists {
                            transaction
                                .execute(
                                    "UPDATE privacy_vault_material_refs
                                     SET import_state='revoked',
                                         failure_code='retention_expired',
                                         updated_at=CURRENT_TIMESTAMP
                                     WHERE material_id=?1",
                                    [&material_id],
                                )
                                .map_err(|_| LifecycleError::Database)?;
                        }
                        let changed = transaction
                            .execute(
                                "UPDATE privacy_materials
                                 SET protected_display_name=NULL,
                                     display_name_sha256=NULL,
                                     display_name_protection_scheme=NULL,
                                     state='revoked',
                                     deleted_at=COALESCE(deleted_at,CURRENT_TIMESTAMP),
                                     updated_at=CURRENT_TIMESTAMP,
                                     row_version=row_version+1
                                 WHERE material_id=?1",
                                [&material_id],
                            )
                            .map_err(|_| LifecycleError::Database)?;
                        if changed != 1 {
                            return Err(LifecycleError::CleanupIntegrity);
                        }
                    } else {
                        transaction
                            .execute(
                                "DELETE FROM privacy_materials WHERE material_id=?1",
                                [&material_id],
                            )
                            .map_err(|_| LifecycleError::Database)?;
                    }
                }
            }
            "mapping" => {
                transaction
                    .execute(
                        "DELETE FROM privacy_sensitive_mappings WHERE mapping_id=?1",
                        [candidate.target_id.as_str()],
                    )
                    .map_err(|_| LifecycleError::Database)?;
            }
            "approved_output" => {
                transaction
                    .execute(
                        "DELETE FROM privacy_approved_outputs WHERE output_id=?1",
                        [candidate.target_id.as_str()],
                    )
                    .map_err(|_| LifecycleError::Database)?;
            }
            "receipt" => {
                transaction
                    .execute(
                        "DELETE FROM privacy_receipts WHERE receipt_id=?1",
                        [candidate.target_id.as_str()],
                    )
                    .map_err(|_| LifecycleError::Database)?;
            }
            _ => return Err(LifecycleError::CleanupIntegrity),
        }
        let changed = transaction
            .execute(
                "UPDATE privacy_cleanup_candidates SET state='removed'
                 WHERE cleanup_id=?1 AND target_kind=?2 AND target_id=?3 AND state='pending'",
                params![cleanup_id, candidate.target_kind, candidate.target_id],
            )
            .map_err(|_| LifecycleError::Database)?;
        if changed != 1 {
            return Err(LifecycleError::CleanupIntegrity);
        }
        removed = removed.saturating_add(1);
    }
    let keys_destroyed = transaction
        .execute(
            "UPDATE privacy_mapping_keys SET
               protected_key=NULL,state='destroyed',destroyed_at_unix=?1
             WHERE state IN('retired','revoked') AND protected_key IS NOT NULL
               AND NOT EXISTS(
                 SELECT 1 FROM privacy_sensitive_mappings s
                 WHERE s.key_version=privacy_mapping_keys.key_version
               )",
            [sql_i64(completed_at_unix)?],
        )
        .map_err(|_| LifecycleError::Database)?;
    let previous = cleanup_chain_tail(&transaction)?;
    let row = CleanupJournalRow {
        cleanup_id: cleanup_id.to_owned(),
        state: "committed".to_owned(),
        policy_revision: transaction
            .query_row(
                "SELECT policy_revision FROM privacy_cleanup_journal WHERE cleanup_id=?1",
                [cleanup_id],
                |row| row.get(0),
            )
            .map_err(|_| LifecycleError::Database)?,
        started_at_unix: started_at,
        completed_at_unix: Some(sql_i64(completed_at_unix)?),
        candidate_count,
        removed_count: i64::try_from(removed).map_err(|_| LifecycleError::InvalidInput)?,
        keys_destroyed: i64::try_from(keys_destroyed).map_err(|_| LifecycleError::InvalidInput)?,
        error_code: None,
        previous_event_hash: previous,
        event_hash: String::new(),
        erasure_disclosure: LOGICAL_ERASURE_DISCLOSURE.to_owned(),
    };
    let evidence_manifest_sha256 = cleanup_evidence_manifest(&transaction, cleanup_id)?;
    let event_hash = cleanup_event_hash_with_evidence(&row, &evidence_manifest_sha256)?;
    transaction
        .execute(
            "UPDATE privacy_cleanup_journal SET
               state='committed',completed_at_unix=?2,removed_count=?3,keys_destroyed=?4,
               previous_event_hash=?5,event_hash=?6
             WHERE cleanup_id=?1 AND state='prepared'",
            params![
                cleanup_id,
                sql_i64(completed_at_unix)?,
                sql_i64(removed)?,
                i64::try_from(keys_destroyed).map_err(|_| LifecycleError::InvalidInput)?,
                row.previous_event_hash,
                event_hash
            ],
        )
        .map_err(|_| LifecycleError::Database)?;
    transaction.commit().map_err(|_| LifecycleError::Database)?;
    Ok(CleanupReportV1 {
        cleanup_id: cleanup_id.to_owned(),
        state: "committed".to_owned(),
        candidates: sql_u64(candidate_count)?,
        removed,
        keys_destroyed: u64::try_from(keys_destroyed).map_err(|_| LifecycleError::InvalidInput)?,
        started_at_unix: sql_u64(started_at)?,
        completed_at_unix,
        event_hash,
        erasure_disclosure: LOGICAL_ERASURE_DISCLOSURE,
    })
}

fn validate_cleanup_candidate(
    transaction: &Connection,
    candidate: &CleanupCandidate,
    completed_at_unix: u64,
) -> Result<(), LifecycleError> {
    let completed_at = sql_i64(completed_at_unix)?;
    let actual = match candidate.target_kind.as_str() {
        "redaction" => transaction
            .query_row(
                "SELECT m.source_sha256,r.extraction_sha256
                 FROM privacy_redactions r
                 JOIN privacy_materials m ON m.material_id=r.material_id
                 JOIN privacy_retention_bindings b ON b.redaction_id=r.redaction_id
                 WHERE r.redaction_id=?1 AND b.legal_hold=0 AND b.expires_at_unix<=?2",
                params![candidate.target_id.as_str(), completed_at],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?
            .map(|(source, extraction)| {
                sha256_hex(
                    format!(
                        "redaction\0{}\0{}\0{}",
                        candidate.target_id, source, extraction
                    )
                    .as_bytes(),
                )
            }),
        "mapping" => transaction
            .query_row(
                "SELECT s.ciphertext_sha256 FROM privacy_sensitive_mappings s
                 LEFT JOIN privacy_retention_bindings b ON b.redaction_id=s.redaction_id
                 WHERE s.mapping_id=?1 AND s.expires_at_unix<=?2
                   AND COALESCE(b.legal_hold,0)=0",
                params![candidate.target_id.as_str(), completed_at],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?,
        "approved_output" => transaction
            .query_row(
                "SELECT o.protected_content FROM privacy_approved_outputs o
                 LEFT JOIN privacy_retention_bindings b ON b.redaction_id=o.redaction_id
                 WHERE o.output_id=?1 AND o.expires_at_unix<=?2
                   AND COALESCE(b.legal_hold,0)=0",
                params![candidate.target_id.as_str(), completed_at],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?
            .map(|bytes| sha256_hex(&bytes)),
        "receipt" => transaction
            .query_row(
                "SELECT p.signed_token FROM privacy_receipts p
                 LEFT JOIN privacy_retention_bindings b ON b.redaction_id=p.redaction_id
                 WHERE p.receipt_id=?1 AND p.expires_at_unix<=?2
                   AND COALESCE(b.legal_hold,0)=0",
                params![candidate.target_id.as_str(), completed_at],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?
            .map(|bytes| sha256_hex(&bytes)),
        _ => return Err(LifecycleError::CleanupIntegrity),
    };
    let actual = actual.ok_or(LifecycleError::CleanupIntegrity)?;
    if actual != candidate.expected_sha256 {
        return Err(LifecycleError::CleanupIntegrity);
    }
    Ok(())
}

fn mark_cleanup_failed(
    connection: &Connection,
    cleanup_id: &str,
    completed_at_unix: u64,
    error_code: &str,
) -> Result<(), LifecycleError> {
    let row: Option<(i64, i64, i64)> = connection
        .query_row(
            "SELECT policy_revision,started_at_unix,candidate_count
             FROM privacy_cleanup_journal WHERE cleanup_id=?1 AND state='prepared'",
            [cleanup_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| LifecycleError::Database)?;
    let Some((policy_revision, started_at_unix, candidate_count)) = row else {
        return Ok(());
    };
    let previous = cleanup_chain_tail(connection)?;
    let row = CleanupJournalRow {
        cleanup_id: cleanup_id.to_owned(),
        state: "failed".to_owned(),
        policy_revision,
        started_at_unix,
        completed_at_unix: Some(sql_i64(completed_at_unix)?),
        candidate_count,
        removed_count: 0,
        keys_destroyed: 0,
        error_code: Some(error_code.to_owned()),
        previous_event_hash: previous,
        event_hash: String::new(),
        erasure_disclosure: LOGICAL_ERASURE_DISCLOSURE.to_owned(),
    };
    let evidence_manifest_sha256 = cleanup_evidence_manifest(connection, cleanup_id)?;
    let event_hash = cleanup_event_hash_with_evidence(&row, &evidence_manifest_sha256)?;
    connection
        .execute(
            "UPDATE privacy_cleanup_journal SET
               state='failed',completed_at_unix=?2,error_code=?3,
               previous_event_hash=?4,event_hash=?5
             WHERE cleanup_id=?1 AND state='prepared'",
            params![
                cleanup_id,
                sql_i64(completed_at_unix)?,
                error_code,
                row.previous_event_hash,
                event_hash
            ],
        )
        .map_err(|_| LifecycleError::Database)?;
    Ok(())
}

#[derive(Debug)]
struct CleanupJournalRow {
    cleanup_id: String,
    state: String,
    policy_revision: i64,
    started_at_unix: i64,
    completed_at_unix: Option<i64>,
    candidate_count: i64,
    removed_count: i64,
    keys_destroyed: i64,
    error_code: Option<String>,
    previous_event_hash: String,
    event_hash: String,
    erasure_disclosure: String,
}

fn cleanup_event_hash(row: &CleanupJournalRow) -> Result<String, LifecycleError> {
    let bytes = canonical_json_v1(&serde_json::json!({
        "cleanupId": row.cleanup_id,
        "state": row.state,
        "policyRevision": row.policy_revision,
        "startedAtUnix": row.started_at_unix,
        "completedAtUnix": row.completed_at_unix,
        "candidateCount": row.candidate_count,
        "removedCount": row.removed_count,
        "keysDestroyed": row.keys_destroyed,
        "errorCode": row.error_code,
        "previousEventHash": row.previous_event_hash,
        "erasureDisclosure": row.erasure_disclosure,
    }))
    .map_err(|_| LifecycleError::CleanupIntegrity)?;
    Ok(sha256_hex(&bytes))
}

#[allow(clippy::too_many_arguments)]
fn backup_aad(
    backup_id: &str,
    workspace: &WorkspaceInstanceId,
    privacy_store_schema_version: i64,
    key_epoch: u64,
    created_at_unix: u64,
    expires_at_unix: u64,
    database_bytes: u64,
    database_sha256: &str,
    wrapped_data_key_sha256: &str,
) -> Result<Vec<u8>, LifecycleError> {
    canonical_json_v1(&BackupAadV1 {
        aad_version: BACKUP_AAD_VERSION,
        schema_version: ENCRYPTED_BACKUP_SCHEMA_VERSION,
        crypto_suite: BACKUP_CRYPTO_SUITE,
        backup_id,
        workspace_instance_id: workspace,
        privacy_store_schema_version,
        lifecycle_schema_version: PRIVACY_LIFECYCLE_SCHEMA_VERSION,
        key_epoch,
        created_at_unix,
        expires_at_unix,
        database_bytes,
        database_sha256,
        wrapped_data_key_sha256,
    })
    .map_err(|_| LifecycleError::BackupInvalid)
}

fn validate_backup_envelope(
    envelope: &BackupEnvelopeV1,
    backup_id: &str,
    context: &BackupVerificationExpectation<'_>,
    registry: &(String, i64, i64, i64, String),
) -> Result<(), LifecycleError> {
    let maximum_database_bytes =
        max_backup_database_bytes_for_schema(envelope.privacy_store_schema_version)
            .ok_or(LifecycleError::BackupInvalid)?;
    if envelope.schema_version != ENCRYPTED_BACKUP_SCHEMA_VERSION
        || envelope.crypto_suite != BACKUP_CRYPTO_SUITE
        || envelope.backup_id != backup_id
        || envelope.workspace_instance_id != *context.expected_workspace_instance_id
        || envelope.privacy_store_schema_version != context.expected_privacy_store_schema_version
        || envelope.lifecycle_schema_version != PRIVACY_LIFECYCLE_SCHEMA_VERSION
        || envelope.key_epoch != context.expected_key_epoch
        || envelope.key_epoch != sql_u64(registry.3)?
        || envelope.created_at_unix != sql_u64(registry.1)?
        || envelope.expires_at_unix != sql_u64(registry.2)?
        || envelope.created_at_unix == 0
        || envelope.created_at_unix >= envelope.expires_at_unix
        || envelope.database_bytes == 0
        || envelope.database_bytes
            > u64::try_from(maximum_database_bytes).map_err(|_| LifecycleError::BackupInvalid)?
    {
        return Err(LifecycleError::EnvironmentMismatch);
    }
    for hash in [
        envelope.database_sha256.as_str(),
        envelope.wrapped_data_key_sha256.as_str(),
        envelope.ciphertext_sha256.as_str(),
    ] {
        valid_hash(hash).map_err(|_| LifecycleError::BackupInvalid)?;
    }
    Ok(())
}

fn snapshot_database(source: &Connection, destination_path: &Path) -> Result<(), LifecycleError> {
    if destination_path.exists() {
        return Err(LifecycleError::UnsafeFilesystem);
    }
    let mut destination = Connection::open(destination_path).map_err(|_| LifecycleError::Io)?;
    {
        let backup = Backup::new(source, &mut destination).map_err(|_| LifecycleError::Database)?;
        backup
            .run_to_completion(64, Duration::from_millis(1), None)
            .map_err(|_| LifecycleError::Database)?;
    }
    destination
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|_| LifecycleError::Database)?;
    destination.close().map_err(|_| LifecycleError::Io)
}

fn verify_sqlite_snapshot_bytes(
    bytes: &[u8],
    workspace: &WorkspaceInstanceId,
    key_epoch: u64,
    expected_privacy_store_schema_version: i64,
    root: &FixedLocalStorageRoot,
    backup_id: &str,
) -> Result<(), LifecycleError> {
    let maximum_database_bytes =
        max_backup_database_bytes_for_schema(expected_privacy_store_schema_version)
            .ok_or(LifecycleError::BackupInvalid)?;
    if bytes.len() < 100
        || bytes.len() > maximum_database_bytes
        || !bytes.starts_with(b"SQLite format 3\0")
    {
        return Err(LifecycleError::BackupInvalid);
    }
    let mut random = [0_u8; 8];
    crate::vault_crypto::fill_random(&mut random).map_err(map_crypto_error)?;
    let path = root
        .canonical_root()
        .join(".staging")
        .join(format!("{backup_id}-verify-{}.sqlite", hex_lower(&random)));
    write_new_safe_file(&path, bytes)?;
    let verification = (|| {
        let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| LifecycleError::BackupInvalid)?;
        validate_sqlite_connection(
            &connection,
            workspace,
            key_epoch,
            expected_privacy_store_schema_version,
        )
    })();
    finish_sensitive_temporary(&path, root.canonical_root(), verification)
}

fn validate_sqlite_connection(
    connection: &Connection,
    workspace: &WorkspaceInstanceId,
    key_epoch: u64,
    expected_privacy_store_schema_version: i64,
) -> Result<(), LifecycleError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| LifecycleError::BackupInvalid)?;
    if integrity != "ok" {
        return Err(LifecycleError::BackupTampered);
    }
    let foreign_key_violations: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| LifecycleError::BackupInvalid)?;
    if foreign_key_violations != 0 {
        return Err(LifecycleError::BackupTampered);
    }
    if read_privacy_store_schema_version(connection)? != expected_privacy_store_schema_version {
        return Err(LifecycleError::UnsupportedSchema);
    }
    let meta: Option<(i64, String, i64)> = connection
        .query_row(
            "SELECT schema_version,workspace_instance_id,key_epoch
             FROM privacy_lifecycle_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| LifecycleError::BackupInvalid)?;
    if meta
        != Some((
            PRIVACY_LIFECYCLE_SCHEMA_VERSION,
            workspace.as_str().to_owned(),
            sql_i64(key_epoch)?,
        ))
    {
        return Err(LifecycleError::EnvironmentMismatch);
    }
    let lifecycle = PrivacyLifecycle {
        workspace_instance_id: workspace.clone(),
    };
    let _ = load_active_mapping_key(connection)?;
    lifecycle
        .verify_cleanup_journal(connection)
        .map_err(|_| LifecycleError::BackupTampered)?;
    lifecycle
        .verify_mapping_access_audit(connection)
        .map_err(|_| LifecycleError::BackupTampered)?;
    Ok(())
}

fn read_privacy_store_schema_version(connection: &Connection) -> Result<i64, LifecycleError> {
    let raw: Option<String> = connection
        .query_row(
            "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| LifecycleError::UnsupportedSchema)?;
    let raw = raw.ok_or(LifecycleError::UnsupportedSchema)?;
    let version = raw
        .parse::<i64>()
        .map_err(|_| LifecycleError::UnsupportedSchema)?;
    if version.to_string() != raw {
        return Err(LifecycleError::UnsupportedSchema);
    }
    let preflight_version =
        match PrivacyStore::preflight_schema(connection).map_err(map_store_error)? {
            PrivacyStoreSchemaStatus::Empty => return Err(LifecycleError::UnsupportedSchema),
            PrivacyStoreSchemaStatus::Current => PRIVACY_STORE_SCHEMA_VERSION,
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version } => found_version,
        };
    if version != preflight_version {
        return Err(LifecycleError::UnsupportedSchema);
    }
    Ok(preflight_version)
}

fn ensure_empty_database(connection: &Connection) -> Result<(), LifecycleError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' AND type IN('table','view','trigger','index')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| LifecycleError::Database)?;
    if count == 0 {
        Ok(())
    } else {
        Err(LifecycleError::Conflict)
    }
}

fn write_atomic_new_file(
    canonical_root: &Path,
    root: &FixedLocalStorageRoot,
    final_path: &Path,
    bytes: &[u8],
    backup_id: &str,
) -> Result<(), LifecycleError> {
    if final_path.exists() || !final_path.starts_with(canonical_root) {
        return Err(LifecycleError::Conflict);
    }
    root.validate_existing_directory(Path::new("backups"))
        .map_err(map_vault_error)?;
    let mut random = [0_u8; 8];
    crate::vault_crypto::fill_random(&mut random).map_err(map_crypto_error)?;
    let temporary = canonical_root
        .join(".staging")
        .join(format!("{backup_id}-write-{}.tmp", hex_lower(&random)));
    write_new_safe_file(&temporary, bytes)?;
    if fs::rename(&temporary, final_path).is_err() {
        return finish_sensitive_temporary(&temporary, canonical_root, Err(LifecycleError::Io));
    }
    validate_open_file_identity(final_path)?;
    Ok(())
}

fn write_new_safe_file(path: &Path, bytes: &[u8]) -> Result<(), LifecycleError> {
    let parent = path.parent().ok_or(LifecycleError::UnsafeFilesystem)?;
    if !parent.is_dir()
        || fs::symlink_metadata(parent)
            .map_err(|_| LifecycleError::Io)?
            .file_type()
            .is_symlink()
    {
        return Err(LifecycleError::UnsafeFilesystem);
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| LifecycleError::Io)?;
    file.write_all(bytes).map_err(|_| LifecycleError::Io)?;
    file.sync_all().map_err(|_| LifecycleError::Io)?;
    drop(file);
    validate_open_file_identity(path)
}

fn read_safe_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, LifecycleError> {
    let file = open_validated_file(path)?;
    let length = usize::try_from(file.metadata().map_err(|_| LifecycleError::Io)?.len())
        .map_err(|_| LifecycleError::InvalidInput)?;
    if length == 0 || length > max_bytes {
        return Err(LifecycleError::BackupInvalid);
    }
    let mut bytes = Vec::with_capacity(length);
    (&file)
        .take(u64::try_from(max_bytes.saturating_add(1)).map_err(|_| LifecycleError::InvalidInput)?)
        .read_to_end(&mut bytes)
        .map_err(|_| LifecycleError::Io)?;
    if bytes.len() != length || bytes.len() > max_bytes {
        return Err(LifecycleError::BackupTampered);
    }
    validate_file_handle_identity(&file)?;
    Ok(bytes)
}

fn remove_safe_temporary(path: &Path, canonical_root: &Path) -> Result<(), LifecycleError> {
    if !path.starts_with(canonical_root.join(".staging")) {
        return Err(LifecycleError::UnsafeFilesystem);
    }
    validate_open_file_identity(path)?;
    fs::remove_file(path).map_err(|_| LifecycleError::Io)
}

fn finish_sensitive_temporary<T>(
    path: &Path,
    canonical_root: &Path,
    result: Result<T, LifecycleError>,
) -> Result<T, LifecycleError> {
    match remove_sensitive_sqlite_temporary(path, canonical_root) {
        Ok(()) => result,
        Err(error) => {
            drop(result);
            Err(error)
        }
    }
}

fn remove_sensitive_sqlite_temporary(
    path: &Path,
    canonical_root: &Path,
) -> Result<(), LifecycleError> {
    let mut candidates = Vec::with_capacity(4);
    candidates.push(path.to_path_buf());
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        candidates.push(PathBuf::from(sidecar));
    }
    for candidate in candidates {
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(LifecycleError::UnsafeFilesystem);
                }
                remove_safe_temporary(&candidate, canonical_root)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(LifecycleError::Io),
        }
    }
    Ok(())
}

fn cleanup_stale_backup_staging(root: &FixedLocalStorageRoot) -> Result<(), LifecycleError> {
    let staging = root
        .validate_existing_directory(Path::new(".staging"))
        .map_err(map_vault_error)?;
    for entry in fs::read_dir(&staging).map_err(|_| LifecycleError::Io)? {
        let entry = entry.map_err(|_| LifecycleError::Io)?;
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| LifecycleError::UnsafeFilesystem)?;
        if !is_exact_backup_staging_name(&file_name) {
            return Err(LifecycleError::UnsafeFilesystem);
        }
        let path = entry.path();
        if path.parent() != Some(staging.as_path()) {
            return Err(LifecycleError::UnsafeFilesystem);
        }
        validate_open_file_identity(&path)?;
        fs::remove_file(path).map_err(|_| LifecycleError::Io)?;
    }
    Ok(())
}

fn is_exact_backup_staging_name(file_name: &str) -> bool {
    if !file_name.is_ascii() {
        return false;
    }
    let base = ["-journal", "-wal", "-shm"]
        .into_iter()
        .find_map(|suffix| file_name.strip_suffix(suffix))
        .unwrap_or(file_name);
    let Some(after_prefix) = base.strip_prefix("bkp_") else {
        return false;
    };
    if after_prefix.len() < 32 {
        return false;
    }
    let (backup_hex, tail) = after_prefix.split_at(32);
    if !is_lower_hex_exact(backup_hex, 32) {
        return false;
    }
    if let Some(value) = tail.strip_prefix('-') {
        if has_random_suffix(value, "-sqlite") || has_random_suffix(value, "-restore.sqlite") {
            return true;
        }
    }
    if let Some(value) = tail.strip_prefix("-verify-") {
        if has_random_suffix(value, ".sqlite") {
            return true;
        }
    }
    if let Some(value) = tail.strip_prefix("-write-") {
        if has_random_suffix(value, ".tmp") {
            return true;
        }
    }
    false
}

fn has_random_suffix(value: &str, suffix: &str) -> bool {
    value.len() == 16 + suffix.len()
        && is_lower_hex_exact(&value[..16], 16)
        && &value[16..] == suffix
}

fn is_lower_hex_exact(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn open_validated_file(path: &Path) -> Result<File, LifecycleError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| LifecycleError::BackupNotAvailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LifecycleError::UnsafeFilesystem);
    }
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| LifecycleError::Io)?
    };
    #[cfg(not(windows))]
    let file = File::open(path).map_err(|_| LifecycleError::Io)?;
    validate_file_handle_identity(&file)?;
    Ok(file)
}

fn validate_open_file_identity(path: &Path) -> Result<(), LifecycleError> {
    let file = open_validated_file(path)?;
    validate_file_handle_identity(&file)
}

#[cfg(windows)]
fn validate_file_handle_identity(file: &File) -> Result<(), LifecycleError> {
    use std::{mem::zeroed, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let success = unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            &mut information,
        )
    };
    if success == 0
        || information.nNumberOfLinks != 1
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(LifecycleError::UnsafeFilesystem);
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_file_handle_identity(_file: &File) -> Result<(), LifecycleError> {
    Err(LifecycleError::PlatformUnavailable)
}

fn decode_bounded_base64(value: &str, max_bytes: usize) -> Result<Vec<u8>, LifecycleError> {
    if value.is_empty() || value.len() > max_bytes.saturating_mul(2) {
        return Err(LifecycleError::BackupInvalid);
    }
    let bytes = BASE64_STANDARD
        .decode(value.as_bytes())
        .map_err(|_| LifecycleError::BackupInvalid)?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(LifecycleError::BackupInvalid);
    }
    Ok(bytes)
}

fn valid_identifier(value: &str) -> Result<(), LifecycleError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
        || value.contains("..")
    {
        Err(LifecycleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn valid_opaque_id(value: &str, prefix: &str) -> Result<(), LifecycleError> {
    let Some(suffix) = value.strip_prefix(prefix) else {
        return Err(LifecycleError::InvalidInput);
    };
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LifecycleError::InvalidInput);
    }
    Ok(())
}

fn valid_hash(value: &str) -> Result<(), LifecycleError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(LifecycleError::InvalidInput)
    }
}

fn valid_private_string(value: &str, max_bytes: usize) -> Result<(), LifecycleError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        Err(LifecycleError::InvalidInput)
    } else {
        Ok(())
    }
}

fn sql_i64(value: u64) -> Result<i64, LifecycleError> {
    i64::try_from(value).map_err(|_| LifecycleError::InvalidInput)
}

fn sql_u64(value: i64) -> Result<u64, LifecycleError> {
    u64::try_from(value).map_err(|_| LifecycleError::InvalidInput)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn map_store_error(error: PrivacyStoreError) -> LifecycleError {
    match error {
        PrivacyStoreError::UnsupportedSchema => LifecycleError::UnsupportedSchema,
        PrivacyStoreError::InvalidInput => LifecycleError::InvalidInput,
        PrivacyStoreError::Conflict => LifecycleError::Conflict,
        PrivacyStoreError::ProtectedBlob => LifecycleError::ProtectedBlob,
        _ => LifecycleError::Database,
    }
}

fn map_crypto_error(error: crate::vault_crypto::VaultCryptoError) -> LifecycleError {
    match error {
        crate::vault_crypto::VaultCryptoError::PlatformUnavailable => {
            LifecycleError::PlatformUnavailable
        }
        crate::vault_crypto::VaultCryptoError::KeyWrapFailed
        | crate::vault_crypto::VaultCryptoError::KeyUnwrapFailed => LifecycleError::ProtectedBlob,
        _ => LifecycleError::Crypto,
    }
}

fn map_vault_error(error: VaultStoreError) -> LifecycleError {
    match error {
        VaultStoreError::PlatformUnavailable => LifecycleError::PlatformUnavailable,
        VaultStoreError::InvalidRoot | VaultStoreError::UnsafeFilesystem => {
            LifecycleError::UnsafeFilesystem
        }
        VaultStoreError::AlreadyExists => LifecycleError::Conflict,
        VaultStoreError::InvalidInput => LifecycleError::InvalidInput,
        _ => LifecycleError::Io,
    }
}

fn zeroize_string(value: &mut str) {
    unsafe {
        value.as_bytes_mut().fill(0);
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

struct ZeroizingBytes(Vec<u8>);

impl ZeroizingBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl std::ops::Deref for ZeroizingBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

include!("lifecycle_approved_outputs.rs");
include!("lifecycle_backup_state.rs");
include!("lifecycle_tests.rs");
