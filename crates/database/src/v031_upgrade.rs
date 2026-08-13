use std::collections::BTreeMap;

use rusqlite::params;
use serde_json::Value;

use super::{
    existing_user_schema_version, get_operation_audit_by_idempotency_key_hash,
    migration_source::{
        current_user_manifest_proof_for_upgrade, v031_user_manifest_proof_for_upgrade,
        CanonicalUserManifestProof,
    },
    run_user_migrations_with_hooks, sha256_hex, user_schema_migration_error,
    validate_canonical_user_database, DatabaseInitError, OperationAuditRow,
    UserMigrationSourceFileProof, UserMigrationSourceProof, UserMigrationTableProof,
    ValidatedUserSourceSchema, USER_SCHEMA_VERSION, V031_USER_SCHEMA_MANIFEST_SHA256,
    V031_USER_SCHEMA_VERSION,
};

pub const V031_TO_V040_USER_MIGRATION_ID: &str = "v0.3.1-to-v0.4.0-user-schema-v1";
pub const V031_TO_V040_USER_AUDIT_OPERATION: &str = "v031_to_v040_upgrade";

const V031_UPGRADE_AUDIT_ID_DOMAIN: &[u8] =
    b"lawyer-assistance\0v031-to-v040-upgrade\0user-audit-id-v1\0";
const EXPECTED_V031_APPLICATION_TABLE_COUNT: usize = 27;
const EXPECTED_V031_PRIVACY_APPLICATION_TABLE_COUNT: u64 = 5;
const EXPECTED_ORIGINAL_ROLLBACK_SLOT_COUNT: u64 = 5;

/// Cross-component evidence that is already authenticated by the desktop
/// upgrade state machine before it opens the final user migration gate.
///
/// Every string is a hash or the anonymous lineage identifier. Paths,
/// credentials, private case identifiers, and business values are not
/// representable by this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V031UserUpgradeAuditEvidence {
    pub lineage_id: String,
    pub source_profile_proof_sha256: String,
    pub source_privacy_logical_manifest_sha256: String,
    pub source_privacy_business_manifest_sha256: String,
    pub original_rollback_identity_sha256: String,
    pub target_privacy_pre_audit_logical_manifest_sha256: String,
    pub target_privacy_pre_audit_business_manifest_sha256: String,
    pub previous_receipt_sha256: String,
    pub source_privacy_table_count: u64,
    pub source_privacy_total_rows: u64,
    pub target_privacy_table_count: u64,
    pub target_privacy_total_rows: u64,
    pub original_rollback_slot_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V031UserPreAuditManifest {
    pub schema_manifest_sha256: String,
    pub logical_manifest_sha256: String,
    pub business_manifest_sha256: String,
    pub business_primary_key_manifest_sha256: String,
    pub business_row_manifest_sha256: String,
    pub table_count: u64,
    pub total_rows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V031UserUpgradeResult {
    pub target_pre_audit_manifest: V031UserPreAuditManifest,
    pub audit: OperationAuditRow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V031UserUpgradeFailurePoint {
    AfterCanonicalMigration,
    AfterAuditInsert,
}

/// Performs the only writable v0.3.1 user migration admitted by the upgrade
/// protocol.
///
/// The caller must supply the exact proof returned by the read-only v0.3.1
/// source validator. The proof is re-bound to the still-unmodified database in
/// the same IMMEDIATE transaction before the first schema write. Canonical v11
/// validation, the pre-audit logical manifests, and the succeeded audit insert
/// then complete in that transaction; any error rolls all of them back.
pub fn migrate_exact_v031_user_to_v11_with_upgrade_audit(
    connection: &mut rusqlite::Connection,
    source_proof: &UserMigrationSourceProof,
    evidence: &V031UserUpgradeAuditEvidence,
) -> Result<V031UserUpgradeResult, DatabaseInitError> {
    migrate_exact_v031_user_to_v11_with_upgrade_audit_inner(
        connection,
        source_proof,
        evidence,
        None,
    )
}

/// Verifies the immutable audit after a committed v11 migration without
/// inserting or updating anything. Startup resume uses this idempotent path
/// when the user transaction committed before the next DPAPI receipt.
///
/// The original pre-audit manifest is recomputed while excluding exactly the
/// one matching upgrade audit row. All other historical and later audit rows
/// remain in the canonical manifest.
pub fn verify_exact_v031_user_v11_upgrade_audit(
    connection: &rusqlite::Connection,
    source_proof: &UserMigrationSourceProof,
    evidence: &V031UserUpgradeAuditEvidence,
) -> Result<V031UserUpgradeResult, DatabaseInitError> {
    validate_source_proof_contract(source_proof)?;
    validate_audit_evidence(evidence)?;

    let transaction = connection.unchecked_transaction()?;
    if existing_user_schema_version(&transaction)? != Some(USER_SCHEMA_VERSION) {
        return Err(upgrade_error(
            "idempotent v0.3.1 upgrade audit verification requires exact user schema 11",
        ));
    }
    validate_canonical_user_database(&transaction)?;
    let audit = load_upgrade_audit(&transaction, &evidence.lineage_id)?.ok_or_else(|| {
        upgrade_error("committed v0.3.1 upgrade is missing its unique user audit")
    })?;
    let target_manifest =
        current_user_manifest_proof_for_upgrade(&transaction, Some(&evidence.lineage_id))?;
    let details_json = canonical_upgrade_details(source_proof, evidence, &target_manifest)?;
    validate_exact_upgrade_audit(&audit, evidence, &details_json)?;
    validate_canonical_user_database(&transaction)?;
    transaction.commit()?;

    Ok(V031UserUpgradeResult {
        target_pre_audit_manifest: target_manifest.into(),
        audit,
    })
}

fn migrate_exact_v031_user_to_v11_with_upgrade_audit_inner(
    connection: &mut rusqlite::Connection,
    source_proof: &UserMigrationSourceProof,
    evidence: &V031UserUpgradeAuditEvidence,
    failure_point: Option<V031UserUpgradeFailurePoint>,
) -> Result<V031UserUpgradeResult, DatabaseInitError> {
    validate_source_proof_contract(source_proof)?;
    validate_audit_evidence(evidence)?;
    let audit_id = upgrade_audit_id(&evidence.lineage_id);

    run_user_migrations_with_hooks(
        connection,
        |transaction| {
            if existing_user_schema_version(transaction)? != Some(V031_USER_SCHEMA_VERSION) {
                return Err(upgrade_error(
                    "v0.3.1 upgrade writer accepts only exact user schema 10",
                ));
            }
            let current_source = v031_user_manifest_proof_for_upgrade(transaction)?;
            bind_source_proof(source_proof, &current_source)?;
            let conflicting_audit_count: i64 = transaction.query_row(
                "SELECT COUNT(*)
                 FROM operation_audit
                 WHERE audit_id = ?1
                    OR (
                        origin = 'desktop'
                        AND operation = ?2
                        AND idempotency_key_hash = ?3
                    )",
                params![
                    audit_id,
                    V031_TO_V040_USER_AUDIT_OPERATION,
                    evidence.lineage_id
                ],
                |row| row.get(0),
            )?;
            if conflicting_audit_count != 0 {
                return Err(upgrade_error(
                    "exact v0.3.1 source already contains a conflicting upgrade audit",
                ));
            }
            Ok(())
        },
        |transaction| {
            validate_canonical_user_database(transaction)?;
            if failure_point == Some(V031UserUpgradeFailurePoint::AfterCanonicalMigration) {
                return Err(upgrade_error(
                    "injected failure after canonical user migration",
                ));
            }

            let target_manifest = current_user_manifest_proof_for_upgrade(transaction, None)?;
            let details_json = canonical_upgrade_details(source_proof, evidence, &target_manifest)?;
            transaction.execute(
                "INSERT INTO operation_audit (
                     audit_id, origin, operation, project_id, request_hash,
                     idempotency_key_hash, status, details_json,
                     created_at, finished_at
                 ) VALUES (
                     ?1, 'desktop', ?2, NULL, ?3, ?4, 'succeeded', ?5,
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
                 )",
                params![
                    audit_id,
                    V031_TO_V040_USER_AUDIT_OPERATION,
                    evidence.source_profile_proof_sha256,
                    evidence.lineage_id,
                    details_json,
                ],
            )?;

            if failure_point == Some(V031UserUpgradeFailurePoint::AfterAuditInsert) {
                return Err(upgrade_error(
                    "injected failure after v0.3.1 user upgrade audit insert",
                ));
            }

            let audit =
                load_upgrade_audit(transaction, &evidence.lineage_id)?.ok_or_else(|| {
                    upgrade_error("inserted v0.3.1 upgrade audit could not be reloaded")
                })?;
            validate_exact_upgrade_audit(&audit, evidence, &details_json)?;

            // Only read validation follows the audit insert. A validation
            // failure drops this transaction and therefore removes both the
            // schema migration and the audit row.
            validate_canonical_user_database(transaction)?;
            Ok(V031UserUpgradeResult {
                target_pre_audit_manifest: target_manifest.into(),
                audit,
            })
        },
    )
}

fn validate_source_proof_contract(
    proof: &UserMigrationSourceProof,
) -> Result<(), DatabaseInitError> {
    if proof.schema != ValidatedUserSourceSchema::V031V10
        || proof.schema_manifest_sha256 != V031_USER_SCHEMA_MANIFEST_SHA256
        || proof.tables.len() != EXPECTED_V031_APPLICATION_TABLE_COUNT
        || proof.data_version < 0
    {
        return Err(upgrade_error(
            "v0.3.1 user upgrade requires the frozen exact source proof",
        ));
    }
    for hash in [
        &proof.schema_manifest_sha256,
        &proof.logical_database_manifest_sha256,
        &proof.business_manifest_sha256,
        &proof.business_primary_key_manifest_sha256,
        &proof.business_row_manifest_sha256,
    ] {
        require_hash(hash, "source user proof hash")?;
    }
    validate_file_proof(&proof.database_file, true)?;
    for sidecar in [&proof.wal, &proof.shm, &proof.journal]
        .into_iter()
        .flatten()
    {
        validate_file_proof(sidecar, false)?;
    }

    let mut total_rows = 0u64;
    let mut previous_table: Option<&str> = None;
    for table in &proof.tables {
        if table.table.is_empty()
            || table.table.len() > 128
            || table
                .table
                .bytes()
                .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
            || previous_table.is_some_and(|previous| previous.as_bytes() >= table.table.as_bytes())
        {
            return Err(upgrade_error(
                "v0.3.1 user source table proof ordering is invalid",
            ));
        }
        previous_table = Some(&table.table);
        validate_table_proof(table)?;
        total_rows = total_rows
            .checked_add(table.rows)
            .ok_or_else(|| upgrade_error("v0.3.1 user source row count overflow"))?;
    }
    if total_rows != proof.total_rows || total_rows > i64::MAX as u64 {
        return Err(upgrade_error(
            "v0.3.1 user source row counts do not match the proof",
        ));
    }
    Ok(())
}

fn validate_file_proof(
    proof: &UserMigrationSourceFileProof,
    require_nonempty: bool,
) -> Result<(), DatabaseInitError> {
    require_hash(&proof.identity_sha256, "source file identity hash")?;
    require_hash(&proof.sha256, "source file hash")?;
    if (require_nonempty && proof.length == 0) || proof.length > i64::MAX as u64 {
        return Err(upgrade_error("source file proof length is invalid"));
    }
    Ok(())
}

fn validate_table_proof(table: &UserMigrationTableProof) -> Result<(), DatabaseInitError> {
    require_hash(
        &table.logical_manifest_sha256,
        "source table logical manifest hash",
    )?;
    let is_metadata = table.table == "user_database_metadata";
    for (label, hash) in [
        (
            "source table business manifest hash",
            &table.business_manifest_sha256,
        ),
        (
            "source table primary-key manifest hash",
            &table.business_primary_key_manifest_sha256,
        ),
        (
            "source table business-row manifest hash",
            &table.business_row_manifest_sha256,
        ),
    ] {
        match (is_metadata, hash) {
            (true, None) => {}
            (false, Some(hash)) => require_hash(hash, label)?,
            _ => {
                return Err(upgrade_error(
                    "source table business proof exclusion is invalid",
                ));
            }
        }
    }
    if table.rows > i64::MAX as u64 {
        return Err(upgrade_error("source table row count is too large"));
    }
    Ok(())
}

fn validate_audit_evidence(
    evidence: &V031UserUpgradeAuditEvidence,
) -> Result<(), DatabaseInitError> {
    require_hash(&evidence.lineage_id, "upgrade lineage")?;
    for (label, hash) in [
        (
            "source profile proof hash",
            &evidence.source_profile_proof_sha256,
        ),
        (
            "source privacy logical manifest hash",
            &evidence.source_privacy_logical_manifest_sha256,
        ),
        (
            "source privacy business manifest hash",
            &evidence.source_privacy_business_manifest_sha256,
        ),
        (
            "original rollback identity hash",
            &evidence.original_rollback_identity_sha256,
        ),
        (
            "target privacy pre-audit logical manifest hash",
            &evidence.target_privacy_pre_audit_logical_manifest_sha256,
        ),
        (
            "target privacy pre-audit business manifest hash",
            &evidence.target_privacy_pre_audit_business_manifest_sha256,
        ),
        ("previous receipt hash", &evidence.previous_receipt_sha256),
    ] {
        require_hash(hash, label)?;
    }
    if evidence.source_privacy_table_count != EXPECTED_V031_PRIVACY_APPLICATION_TABLE_COUNT
        || evidence.target_privacy_table_count == 0
        || evidence.original_rollback_slot_count != EXPECTED_ORIGINAL_ROLLBACK_SLOT_COUNT
    {
        return Err(upgrade_error(
            "v0.3.1 upgrade audit component counts are invalid",
        ));
    }
    let counts = [
        evidence.source_privacy_table_count,
        evidence.source_privacy_total_rows,
        evidence.target_privacy_table_count,
        evidence.target_privacy_total_rows,
        evidence.original_rollback_slot_count,
    ];
    let mut total = 0u64;
    for count in counts {
        if count > i64::MAX as u64 {
            return Err(upgrade_error(
                "v0.3.1 upgrade audit count exceeds the signed SQLite boundary",
            ));
        }
        total = total
            .checked_add(count)
            .ok_or_else(|| upgrade_error("v0.3.1 upgrade audit count overflow"))?;
    }
    if total > i64::MAX as u64 {
        return Err(upgrade_error(
            "v0.3.1 upgrade audit count sum exceeds the signed SQLite boundary",
        ));
    }
    Ok(())
}

fn bind_source_proof(
    expected: &UserMigrationSourceProof,
    current: &CanonicalUserManifestProof,
) -> Result<(), DatabaseInitError> {
    if expected.schema_manifest_sha256 != current.schema_manifest_sha256
        || expected.logical_database_manifest_sha256 != current.logical_database_manifest_sha256
        || expected.business_manifest_sha256 != current.business_manifest_sha256
        || expected.business_primary_key_manifest_sha256
            != current.business_primary_key_manifest_sha256
        || expected.business_row_manifest_sha256 != current.business_row_manifest_sha256
        || expected.tables != current.tables
        || expected.total_rows != current.total_rows
    {
        return Err(upgrade_error(
            "user schema 10 no longer matches the caller-verified v0.3.1 source proof",
        ));
    }
    Ok(())
}

fn canonical_upgrade_details(
    source_proof: &UserMigrationSourceProof,
    evidence: &V031UserUpgradeAuditEvidence,
    target_manifest: &CanonicalUserManifestProof,
) -> Result<String, DatabaseInitError> {
    let source_user_table_count = u64::try_from(source_proof.tables.len())
        .map_err(|_| upgrade_error("source user table count is too large"))?;
    let target_user_table_count = u64::try_from(target_manifest.tables.len())
        .map_err(|_| upgrade_error("target user table count is too large"))?;
    let mut counts = BTreeMap::<&str, Value>::new();
    let mut count_sum = 0u64;
    for (key, value) in [
        (
            "originalRollbackSlots",
            evidence.original_rollback_slot_count,
        ),
        ("sourcePrivacyRows", evidence.source_privacy_total_rows),
        ("sourcePrivacyTables", evidence.source_privacy_table_count),
        ("sourceUserRows", source_proof.total_rows),
        ("sourceUserTables", source_user_table_count),
        ("targetPrivacyRows", evidence.target_privacy_total_rows),
        ("targetPrivacyTables", evidence.target_privacy_table_count),
        ("targetUserRows", target_manifest.total_rows),
        ("targetUserTables", target_user_table_count),
    ] {
        if value > i64::MAX as u64 {
            return Err(upgrade_error("upgrade audit detail count is too large"));
        }
        count_sum = count_sum
            .checked_add(value)
            .ok_or_else(|| upgrade_error("upgrade audit detail count sum overflow"))?;
        counts.insert(key, Value::from(value));
    }
    if count_sum > i64::MAX as u64 {
        return Err(upgrade_error(
            "upgrade audit detail count sum exceeds the signed SQLite boundary",
        ));
    }

    let mut details = BTreeMap::<&str, Value>::new();
    details.insert(
        "counts",
        serde_json::to_value(counts)
            .map_err(|_| upgrade_error("upgrade audit counts could not be canonically encoded"))?,
    );
    details.insert("lineageId", Value::from(evidence.lineage_id.clone()));
    details.insert("migrationId", Value::from(V031_TO_V040_USER_MIGRATION_ID));
    details.insert(
        "originalRollbackIdentitySha256",
        Value::from(evidence.original_rollback_identity_sha256.clone()),
    );
    details.insert(
        "previousReceiptSha256",
        Value::from(evidence.previous_receipt_sha256.clone()),
    );
    details.insert(
        "sourcePrivacyBusinessSha256",
        Value::from(evidence.source_privacy_business_manifest_sha256.clone()),
    );
    details.insert(
        "sourcePrivacyLogicalSha256",
        Value::from(evidence.source_privacy_logical_manifest_sha256.clone()),
    );
    details.insert(
        "sourceProfileProofSha256",
        Value::from(evidence.source_profile_proof_sha256.clone()),
    );
    details.insert(
        "sourceUserBusinessSha256",
        Value::from(source_proof.business_manifest_sha256.clone()),
    );
    details.insert(
        "sourceUserLogicalSha256",
        Value::from(source_proof.logical_database_manifest_sha256.clone()),
    );
    details.insert(
        "targetPrivacyBusinessSha256",
        Value::from(
            evidence
                .target_privacy_pre_audit_business_manifest_sha256
                .clone(),
        ),
    );
    details.insert(
        "targetPrivacyLogicalSha256",
        Value::from(
            evidence
                .target_privacy_pre_audit_logical_manifest_sha256
                .clone(),
        ),
    );
    details.insert(
        "targetUserBusinessSha256",
        Value::from(target_manifest.business_manifest_sha256.clone()),
    );
    details.insert(
        "targetUserLogicalSha256",
        Value::from(target_manifest.logical_database_manifest_sha256.clone()),
    );
    serde_json::to_string(&details)
        .map_err(|_| upgrade_error("upgrade audit details could not be canonically encoded"))
}

fn load_upgrade_audit(
    connection: &rusqlite::Connection,
    lineage_id: &str,
) -> Result<Option<OperationAuditRow>, DatabaseInitError> {
    get_operation_audit_by_idempotency_key_hash(
        connection,
        "desktop",
        V031_TO_V040_USER_AUDIT_OPERATION,
        lineage_id,
    )
    .map_err(Into::into)
}

fn validate_exact_upgrade_audit(
    audit: &OperationAuditRow,
    evidence: &V031UserUpgradeAuditEvidence,
    details_json: &str,
) -> Result<(), DatabaseInitError> {
    if audit.audit_id != upgrade_audit_id(&evidence.lineage_id)
        || audit.origin != "desktop"
        || audit.operation != V031_TO_V040_USER_AUDIT_OPERATION
        || audit.project_id.is_some()
        || audit.request_hash != evidence.source_profile_proof_sha256
        || audit.idempotency_key_hash.as_deref() != Some(evidence.lineage_id.as_str())
        || audit.status != "succeeded"
        || audit.details_json != details_json
        || audit.finished_at.is_none()
        || audit.created_at != audit.finished_at.as_deref().unwrap_or_default()
    {
        return Err(upgrade_error(
            "v0.3.1 user upgrade audit conflicts with the authenticated lineage evidence",
        ));
    }
    Ok(())
}

fn upgrade_audit_id(lineage_id: &str) -> String {
    let mut preimage = Vec::with_capacity(V031_UPGRADE_AUDIT_ID_DOMAIN.len() + lineage_id.len());
    preimage.extend_from_slice(V031_UPGRADE_AUDIT_ID_DOMAIN);
    preimage.extend_from_slice(lineage_id.as_bytes());
    sha256_hex(&preimage)
}

fn require_hash(value: &str, label: &str) -> Result<(), DatabaseInitError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(upgrade_error(&format!("{label} is not canonical SHA-256")));
    }
    Ok(())
}

fn upgrade_error(message: &str) -> DatabaseInitError {
    user_schema_migration_error(message.to_owned()).into()
}

impl From<CanonicalUserManifestProof> for V031UserPreAuditManifest {
    fn from(proof: CanonicalUserManifestProof) -> Self {
        Self {
            schema_manifest_sha256: proof.schema_manifest_sha256,
            logical_manifest_sha256: proof.logical_database_manifest_sha256,
            business_manifest_sha256: proof.business_manifest_sha256,
            business_primary_key_manifest_sha256: proof.business_primary_key_manifest_sha256,
            business_row_manifest_sha256: proof.business_row_manifest_sha256,
            table_count: u64::try_from(proof.tables.len())
                .expect("validated SQLite table count fits u64"),
            total_rows: proof.total_rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        configure_user_database_connection,
        migration_source::{
            create_exact_v031_user_database_for_upgrade_test,
            v031_user_source_proof_for_upgrade_test,
        },
    };
    use rusqlite::types::Value as SqliteValue;

    fn exact_v031_connection() -> rusqlite::Connection {
        let connection = rusqlite::Connection::open_in_memory().expect("fixture opens");
        configure_user_database_connection(&connection).expect("fixture configures");
        create_exact_v031_user_database_for_upgrade_test(&connection)
            .expect("exact v0.3.1 schema creates");
        seed_every_v031_business_table(&connection);
        connection
    }

    fn seed_every_v031_business_table(connection: &rusqlite::Connection) {
        connection
            .execute_batch(
                r#"
                BEGIN IMMEDIATE;
                PRAGMA defer_foreign_keys=ON;
                INSERT INTO provider_profiles(
                    id,kind,display_name,model_id,base_url,credential_account_id,
                    capabilities_json,options_json,created_at,updated_at
                ) VALUES(
                    'provider-1','openai','Provider','model-1','https://example.invalid',
                    'account-1','{}','{}','2026-07-19 10:00:00','2026-07-19 10:00:01'
                );
                INSERT INTO projects(
                    project_id,title,case_type,status,opened_on,summary,created_at,updated_at
                ) VALUES(
                    'project-1','Project title','civil','active','2026-07-01',
                    'Project summary','2026-07-19 10:01:00','2026-07-19 10:01:01'
                );
                INSERT INTO case_files(
                    file_id,project_id,title,file_type,storage_reference,summary,created_at
                ) VALUES(
                    'file-1','project-1','Case file','text','store-ref','File summary',
                    '2026-07-19 10:02:00'
                );
                INSERT INTO pending_extraction_reviews(
                    review_id,project_id,provider_id,provider_snapshot_json,
                    source_file_ids_json,source_materials_digest,extraction_json,revision,
                    created_at,expires_at
                ) VALUES(
                    'review-1','project-1','provider-1','{}','["file-1"]','',
                    '{"parties":[]}',2,'2026-07-19 10:03:00','2099-01-01 00:00:00'
                );
                INSERT INTO case_extraction_confirmations(
                    review_id,project_id,provider_id,provider_snapshot_json,
                    source_file_ids_json,confirmed_at
                ) VALUES(
                    'confirmed-review-1','project-1','provider-1','{}','["file-1"]',
                    '2026-07-19 10:04:00'
                );
                INSERT INTO case_parties(
                    party_id,project_id,name,normalized_name,role,contact,notes
                ) VALUES(
                    'party-1','project-1','Party','party','plaintiff','contact','notes'
                );
                INSERT INTO case_facts(
                    fact_id,project_id,occurred_on,title,description,source,confirmation_status
                ) VALUES(
                    'fact-1','project-1','2026-01-02','Fact','Fact detail','manual','confirmed'
                );
                INSERT INTO evidence_items(
                    evidence_id,project_id,evidence_number,title,source,formed_on,summary,
                    storage_reference,confirmation_status
                ) VALUES(
                    'evidence-1','project-1','E-1','Evidence','manual','2026-01-03',
                    'Evidence summary','evidence-ref','confirmed'
                );
                INSERT INTO evidence_links(link_id,project_id,fact_id,evidence_id)
                VALUES('evidence-link-1','project-1','fact-1','evidence-1');
                INSERT INTO legal_issues(
                    issue_id,project_id,title,description,claim,status,confirmation_status
                ) VALUES(
                    'issue-1','project-1','Issue','Issue detail','Claim','open','confirmed'
                );
                INSERT INTO fact_issue_links(link_id,project_id,fact_id,issue_id)
                VALUES('fact-issue-link-1','project-1','fact-1','issue-1');
                INSERT INTO case_uncertainties(
                    uncertainty_id,project_id,description,related_entity_type,
                    related_entity_id,source_file_ids_json,status,resolution,
                    confirmation_status,created_at,updated_at
                ) VALUES(
                    'uncertainty-1','project-1','Uncertain point','fact','fact-1',
                    '["file-1"]','open','','confirmed',
                    '2026-07-19 10:05:00','2026-07-19 10:05:01'
                );
                INSERT INTO legal_basis(
                    basis_id,project_id,issue_id,source_id,status,invalid_reason,case_date,
                    article_id,document_id,version_id,document_title,version_label,
                    article_number,article_title,canonical_label,effective_from,effective_to,
                    version_status,excerpt,note,created_at
                ) VALUES(
                    'basis-1','project-1','issue-1','source-1','valid',NULL,'2026-01-04',
                    'article-1','document-1','version-1','Document','2026','1','Article',
                    'Document Article 1','2026-01-01',NULL,'effective','Excerpt','Note',
                    '2026-07-19 10:06:00'
                );
                INSERT INTO conversations(
                    conversation_id,project_id,title,status,created_at,updated_at
                ) VALUES(
                    'conversation-1','project-1','Conversation','open',
                    '2026-07-19 10:07:00','2026-07-19 10:07:01'
                );
                INSERT INTO artifacts(
                    artifact_id,conversation_id,project_id,kind,title,status,current_version,
                    created_at,updated_at
                ) VALUES(
                    'artifact-1','conversation-1','project-1','research','Artifact','final',1,
                    '2026-07-19 10:08:00','2026-07-19 10:08:01'
                );
                INSERT INTO artifact_versions(
                    version_id,artifact_id,version_number,content_json,rendered_text,
                    source_refs_json,citation_report_json,provider_snapshot_json,created_at
                ) VALUES(
                    'artifact-version-1','artifact-1',1,'{"body":"kept"}','Rendered',
                    '["source-1"]','{}','{}','2026-07-19 10:09:00'
                );
                INSERT INTO attachments(
                    attachment_id,project_id,original_name,extension,detected_mime,sha256,
                    size_bytes,content_blob,extraction_status,extracted_text,segments_json,
                    error_code,created_at
                ) VALUES(
                    'attachment-1','project-1','source.txt','txt','text/plain',
                    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    3,X'010203','succeeded','Extracted','[]',NULL,'2026-07-19 10:10:00'
                );
                INSERT INTO messages(
                    message_id,conversation_id,role,kind,text_summary,artifact_id,run_id,created_at
                ) VALUES(
                    'message-user-1','conversation-1','user','text','Question',NULL,NULL,
                    '2026-07-19 10:11:00'
                );
                INSERT INTO messages(
                    message_id,conversation_id,role,kind,text_summary,artifact_id,run_id,created_at
                ) VALUES(
                    'message-assistant-1','conversation-1','assistant','artifact_ref','Answer',
                    'artifact-1',NULL,'2026-07-19 10:12:00'
                );
                INSERT INTO message_attachments(message_id,attachment_id,ordinal)
                VALUES('message-user-1','attachment-1',0);
                INSERT INTO conversation_sources(conversation_id,source_id,created_at)
                VALUES('conversation-1','source-1','2026-07-19 10:13:00');
                INSERT INTO agent_runs(
                    run_id,conversation_id,user_message_id,assistant_message_id,provider_id,
                    provider_snapshot_json,intent,status,budget_json,error_type,
                    created_at,finished_at
                ) VALUES(
                    'run-1','conversation-1','message-user-1','message-assistant-1','provider-1',
                    '{}','ordinary_assistant','succeeded','{}',NULL,
                    '2026-07-19 10:14:00','2026-07-19 10:14:01'
                );
                UPDATE messages SET run_id='run-1'
                WHERE message_id='message-assistant-1';
                INSERT INTO tool_calls(
                    tool_call_id,run_id,ordinal,capability_name,status,access_mode,
                    requires_confirmation,input_audit_json,output_audit_json,
                    source_audit_json,error_type,started_at,finished_at
                ) VALUES(
                    'tool-call-1','run-1',0,'legal.search','succeeded','read',0,
                    '{}','{}','[]',NULL,'2026-07-19 10:15:00','2026-07-19 10:15:01'
                );
                INSERT INTO case_change_proposals(
                    proposal_id,conversation_id,project_id,run_id,base_case_digest,status,
                    changes_json,source_refs_json,created_at,decided_at,applied_at
                ) VALUES(
                    'proposal-1','conversation-1','project-1','run-1',
                    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'applied','{"changes":[]}','["source-1"]',
                    '2026-07-19 10:16:00','2026-07-19 10:16:01','2026-07-19 10:16:02'
                );
                INSERT INTO operation_audit(
                    audit_id,origin,operation,project_id,request_hash,idempotency_key_hash,
                    status,details_json,created_at,finished_at
                ) VALUES(
                    'historical-audit','desktop','historical_operation','project-1',
                    'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                    NULL,'succeeded','{}','2026-07-19 10:17:00','2026-07-19 10:17:01'
                );
                INSERT INTO legal_answer_records(
                    record_id,project_id,conversation_id,provider_id,provider_snapshot_json,
                    question,answer_text,case_date,query_json,source_ids_json,
                    verified_citations_json,invalid_citations_json,
                    unsupported_legal_conclusion,created_at
                ) VALUES(
                    'answer-1','project-1','conversation-1','provider-1','{}','Question',
                    'Answer','2026-01-01','{}','["source-1"]','[]','[]',0,
                    '2026-07-19 10:18:00'
                );
                INSERT INTO document_generation_records(
                    record_id,project_id,template_id,template_version,source_ids_json,
                    citation_ids_json,export_path,exported_at
                ) VALUES(
                    'document-generation-1','project-1','template-1','1','["source-1"]',
                    '[]','export.docx','2026-07-19 10:19:00'
                );
                COMMIT;
                "#,
            )
            .expect("all exact v0.3.1 business rows seed");
    }

    fn audit_evidence(lineage_byte: char) -> V031UserUpgradeAuditEvidence {
        V031UserUpgradeAuditEvidence {
            lineage_id: lineage_byte.to_string().repeat(64),
            source_profile_proof_sha256: "2".repeat(64),
            source_privacy_logical_manifest_sha256: "3".repeat(64),
            source_privacy_business_manifest_sha256: "4".repeat(64),
            original_rollback_identity_sha256: "5".repeat(64),
            target_privacy_pre_audit_logical_manifest_sha256: "6".repeat(64),
            target_privacy_pre_audit_business_manifest_sha256: "7".repeat(64),
            previous_receipt_sha256: "8".repeat(64),
            source_privacy_table_count: 5,
            source_privacy_total_rows: 17,
            target_privacy_table_count: 41,
            target_privacy_total_rows: 29,
            original_rollback_slot_count: 5,
        }
    }

    fn business_snapshot(
        connection: &rusqlite::Connection,
        tables: &[UserMigrationTableProof],
    ) -> BTreeMap<String, Vec<Vec<SqliteValue>>> {
        let mut snapshot = BTreeMap::new();
        for table in tables.iter().filter(|table| {
            !matches!(
                table.table.as_str(),
                "user_database_metadata" | "operation_audit"
            )
        }) {
            let mut columns = connection
                .prepare(&format!("PRAGMA table_info(\"{}\")", table.table))
                .expect("table info prepares");
            let columns = columns
                .query_map([], |row| row.get::<_, String>(1))
                .expect("table info queries")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("table info collects");
            let columns = columns
                .into_iter()
                .filter(|column| !(table.table == "conversations" && column == "scope"))
                .collect::<Vec<_>>();
            let projection = columns
                .iter()
                .map(|column| format!("\"{column}\""))
                .collect::<Vec<_>>()
                .join(",");
            let mut statement = connection
                .prepare(&format!("SELECT {projection} FROM \"{}\"", table.table))
                .expect("business snapshot prepares");
            let rows = statement
                .query_map([], |row| {
                    (0..columns.len())
                        .map(|index| row.get::<_, SqliteValue>(index))
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .expect("business snapshot queries")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("business snapshot collects");
            snapshot.insert(table.table.clone(), rows);
        }
        snapshot
    }

    #[test]
    fn exact_v031_upgrade_preserves_all_business_and_session_rows_and_appends_audit_last() {
        let mut connection = exact_v031_connection();
        let source_proof =
            v031_user_source_proof_for_upgrade_test(&connection).expect("source proof computes");
        let before = business_snapshot(&connection, &source_proof.tables);
        assert_eq!(before.len(), 25, "all v0.3.1 business tables are covered");
        assert!(before.values().all(|rows| !rows.is_empty()));
        let evidence = audit_evidence('1');

        let result = migrate_exact_v031_user_to_v11_with_upgrade_audit(
            &mut connection,
            &source_proof,
            &evidence,
        )
        .expect("exact user upgrade commits");

        validate_canonical_user_database(&connection).expect("v11 remains exact");
        assert_eq!(business_snapshot(&connection, &source_proof.tables), before);
        assert_eq!(
            connection
                .query_row(
                    "SELECT scope FROM conversations WHERE conversation_id='conversation-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("migrated conversation reads"),
            "assistant",
            "v0.3.1 conversation scope is authoritative ordinary assistant scope"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT hex(content_blob) FROM attachments
                     WHERE attachment_id='attachment-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("attachment reads"),
            "010203"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT run_id FROM messages WHERE message_id='message-assistant-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("message lineage reads"),
            "run-1"
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM operation_audit", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("audit count reads"),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT audit_id FROM operation_audit ORDER BY rowid DESC LIMIT 1",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("last audit reads"),
            result.audit.audit_id
        );
        assert_eq!(result.audit.status, "succeeded");
        assert_eq!(result.audit.project_id, None);
        assert_eq!(
            result.audit.idempotency_key_hash.as_deref(),
            Some(evidence.lineage_id.as_str())
        );
        let details: Value = serde_json::from_str(&result.audit.details_json)
            .expect("canonical audit details parse");
        assert_eq!(
            serde_json::to_string(&details).expect("details re-encode"),
            result.audit.details_json
        );
        for forbidden in [
            "path",
            "filename",
            "credential",
            "token",
            "ticket",
            "privacyCaseId",
            "Project title",
            "Question",
            "Answer",
        ] {
            assert!(
                !result.audit.details_json.contains(forbidden),
                "audit details must not contain {forbidden}"
            );
        }
        assert_eq!(
            result.target_pre_audit_manifest.total_rows + 1,
            current_user_manifest_proof_for_upgrade(&connection, None)
                .expect("post-audit manifest computes")
                .total_rows,
            "the returned manifest is computed immediately before the one new audit row"
        );
    }

    #[test]
    fn committed_upgrade_audit_verification_is_idempotent_and_conflicts_fail_closed() {
        let mut connection = exact_v031_connection();
        connection
            .execute(
                "INSERT INTO operation_audit(
                     audit_id,origin,operation,project_id,request_hash,
                     idempotency_key_hash,status,details_json,created_at,finished_at
                 ) VALUES(
                     'same-operation-without-lineage','desktop',?1,NULL,?2,NULL,
                     'succeeded','{}','2026-07-19 10:20:00','2026-07-19 10:20:00'
                 )",
                params![V031_TO_V040_USER_AUDIT_OPERATION, "e".repeat(64)],
            )
            .expect("unrelated audit with a NULL idempotency key seeds");
        let source_proof =
            v031_user_source_proof_for_upgrade_test(&connection).expect("source proof computes");
        let evidence = audit_evidence('a');
        let committed = migrate_exact_v031_user_to_v11_with_upgrade_audit(
            &mut connection,
            &source_proof,
            &evidence,
        )
        .expect("upgrade commits");
        migrate_exact_v031_user_to_v11_with_upgrade_audit(
            &mut connection,
            &source_proof,
            &evidence,
        )
        .expect_err("the writable API never treats current v11 as a migration source");

        let first = verify_exact_v031_user_v11_upgrade_audit(&connection, &source_proof, &evidence)
            .expect("first resume verifies");
        let second =
            verify_exact_v031_user_v11_upgrade_audit(&connection, &source_proof, &evidence)
                .expect("second resume is the same no-op");
        assert_eq!(first, committed);
        assert_eq!(second, committed);
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM operation_audit
                     WHERE origin='desktop'
                       AND operation='v031_to_v040_upgrade'
                       AND idempotency_key_hash=?1",
                    [evidence.lineage_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("unique audit count reads"),
            1
        );

        connection
            .execute(
                "UPDATE operation_audit SET request_hash=?2
                 WHERE audit_id=?1",
                params![committed.audit.audit_id, "f".repeat(64)],
            )
            .expect("tamper fixture changes the audit");
        verify_exact_v031_user_v11_upgrade_audit(&connection, &source_proof, &evidence)
            .expect_err("conflicting persisted audit fails closed");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM operation_audit
                     WHERE operation='v031_to_v040_upgrade'
                       AND idempotency_key_hash=?1",
                    [evidence.lineage_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("audit count reads"),
            1,
            "verification never inserts a replacement audit"
        );
    }

    #[test]
    fn failures_before_and_after_audit_insert_roll_schema_and_audit_back_together() {
        for failure_point in [
            V031UserUpgradeFailurePoint::AfterCanonicalMigration,
            V031UserUpgradeFailurePoint::AfterAuditInsert,
        ] {
            let mut connection = exact_v031_connection();
            let source_proof = v031_user_source_proof_for_upgrade_test(&connection)
                .expect("source proof computes");
            let before = business_snapshot(&connection, &source_proof.tables);
            let evidence = audit_evidence(match failure_point {
                V031UserUpgradeFailurePoint::AfterCanonicalMigration => 'b',
                V031UserUpgradeFailurePoint::AfterAuditInsert => 'c',
            });

            migrate_exact_v031_user_to_v11_with_upgrade_audit_inner(
                &mut connection,
                &source_proof,
                &evidence,
                Some(failure_point),
            )
            .expect_err("injected transaction failure propagates");

            assert_eq!(
                existing_user_schema_version(&connection).expect("schema version reads"),
                Some(V031_USER_SCHEMA_VERSION)
            );
            v031_user_manifest_proof_for_upgrade(&connection)
                .expect("rolled-back database is still exact v0.3.1");
            assert_eq!(business_snapshot(&connection, &source_proof.tables), before);
            assert_eq!(
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM operation_audit
                         WHERE operation='v031_to_v040_upgrade'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .expect("rolled-back audit count reads"),
                0,
                "the succeeded audit cannot outlive a rolled-back schema migration"
            );
        }
    }

    #[test]
    fn mismatched_source_proof_is_rejected_before_any_schema_write() {
        let mut connection = exact_v031_connection();
        let mut source_proof =
            v031_user_source_proof_for_upgrade_test(&connection).expect("source proof computes");
        source_proof.logical_database_manifest_sha256 = "d".repeat(64);
        let evidence = audit_evidence('d');

        migrate_exact_v031_user_to_v11_with_upgrade_audit(
            &mut connection,
            &source_proof,
            &evidence,
        )
        .expect_err("semantic source proof mismatch fails closed");
        assert_eq!(
            existing_user_schema_version(&connection).expect("schema version reads"),
            Some(V031_USER_SCHEMA_VERSION)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM operation_audit
                     WHERE operation='v031_to_v040_upgrade'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("audit count reads"),
            0
        );
    }

    #[test]
    fn preexisting_same_lineage_audit_in_exact_v10_is_a_conflict_not_a_replay() {
        let mut connection = exact_v031_connection();
        let evidence = audit_evidence('e');
        connection
            .execute(
                "INSERT INTO operation_audit(
                     audit_id,origin,operation,project_id,request_hash,
                     idempotency_key_hash,status,details_json,created_at,finished_at
                 ) VALUES(?1,'desktop',?2,NULL,?3,?4,'succeeded','{}',?5,?5)",
                params![
                    upgrade_audit_id(&evidence.lineage_id),
                    V031_TO_V040_USER_AUDIT_OPERATION,
                    evidence.source_profile_proof_sha256,
                    evidence.lineage_id,
                    "2026-07-19 10:21:00",
                ],
            )
            .expect("conflicting v10 audit fixture inserts");
        let source_proof =
            v031_user_source_proof_for_upgrade_test(&connection).expect("source proof computes");

        migrate_exact_v031_user_to_v11_with_upgrade_audit(
            &mut connection,
            &source_proof,
            &evidence,
        )
        .expect_err("a v10 audit cannot masquerade as a committed v11 replay");
        assert_eq!(
            existing_user_schema_version(&connection).expect("schema version reads"),
            Some(V031_USER_SCHEMA_VERSION)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM operation_audit
                     WHERE operation='v031_to_v040_upgrade'
                       AND idempotency_key_hash=?1",
                    [evidence.lineage_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("conflicting audit count reads"),
            1,
            "the writer neither replaces nor duplicates the conflicting source row"
        );
    }
}
