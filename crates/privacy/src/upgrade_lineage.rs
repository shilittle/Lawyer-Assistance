use crate::store::{PrivacyStoreError, PRIVACY_STORE_SCHEMA_VERSION};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub const APPLICATION_UPGRADE_LINEAGE_TABLE_NAME: &str = "application_upgrade_lineage";
pub const V031_TO_V040_MIGRATION_ID: &str = "v0.3.1-to-v0.4.0-user-schema-v1";
pub const APPLICATION_UPGRADE_RESULT_OK: &str = "ok";
pub const MAX_APPLICATION_UPGRADE_CREATED_AT_UNIX: i64 = 253_402_300_799;

/// Frozen exclusions for a Privacy schema-6 business manifest. The logical
/// manifest still includes both tables; only the business manifest excludes
/// metadata and the self-referential application-upgrade ledger.
pub const PRIVACY_V6_BUSINESS_MANIFEST_EXCLUDED_TABLES: [&str; 2] = [
    APPLICATION_UPGRADE_LINEAGE_TABLE_NAME,
    "privacy_schema_metadata",
];

const LINEAGE_INDEX_NAME: &str = "idx_application_upgrade_lineage_id";
const NO_UPDATE_TRIGGER_NAME: &str = "trg_application_upgrade_lineage_no_update";
const NO_DELETE_TRIGGER_NAME: &str = "trg_application_upgrade_lineage_no_delete";
const NO_REPLACE_TRIGGER_NAME: &str = "trg_application_upgrade_lineage_no_replace";

const APPLICATION_UPGRADE_LINEAGE_TABLE_SQL: &str = "
    CREATE TABLE IF NOT EXISTS application_upgrade_lineage (
        lineage_id TEXT NOT NULL CHECK(
            length(lineage_id) = 64
            AND lineage_id NOT GLOB '*[^0-9a-f]*'
        ),
        migration_id TEXT NOT NULL CHECK(
            migration_id = 'v0.3.1-to-v0.4.0-user-schema-v1'
        ),
        source_profile_proof_sha256 TEXT NOT NULL CHECK(
            length(source_profile_proof_sha256) = 64
            AND source_profile_proof_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        source_user_logical_manifest_sha256 TEXT NOT NULL CHECK(
            length(source_user_logical_manifest_sha256) = 64
            AND source_user_logical_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        source_privacy_logical_manifest_sha256 TEXT NOT NULL CHECK(
            length(source_privacy_logical_manifest_sha256) = 64
            AND source_privacy_logical_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        original_rollback_identity_sha256 TEXT NOT NULL CHECK(
            length(original_rollback_identity_sha256) = 64
            AND original_rollback_identity_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        target_user_pre_audit_logical_manifest_sha256 TEXT NOT NULL CHECK(
            length(target_user_pre_audit_logical_manifest_sha256) = 64
            AND target_user_pre_audit_logical_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        target_user_pre_audit_business_manifest_sha256 TEXT NOT NULL CHECK(
            length(target_user_pre_audit_business_manifest_sha256) = 64
            AND target_user_pre_audit_business_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        target_privacy_pre_audit_logical_manifest_sha256 TEXT NOT NULL CHECK(
            length(target_privacy_pre_audit_logical_manifest_sha256) = 64
            AND target_privacy_pre_audit_logical_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        target_privacy_pre_audit_business_manifest_sha256 TEXT NOT NULL CHECK(
            length(target_privacy_pre_audit_business_manifest_sha256) = 64
            AND target_privacy_pre_audit_business_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        previous_receipt_sha256 TEXT NOT NULL CHECK(
            length(previous_receipt_sha256) = 64
            AND previous_receipt_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        result_code TEXT NOT NULL CHECK(result_code = 'ok'),
        created_at_unix INTEGER NOT NULL CHECK(
            created_at_unix BETWEEN 1 AND 253402300799
        )
    ) STRICT;
";

const APPLICATION_UPGRADE_LINEAGE_INDEX_SQL: &str = "
    CREATE UNIQUE INDEX IF NOT EXISTS idx_application_upgrade_lineage_id
        ON application_upgrade_lineage(lineage_id);
";

const APPLICATION_UPGRADE_LINEAGE_TRIGGER_SQL: &[(&str, &str)] = &[
    (
        NO_UPDATE_TRIGGER_NAME,
        "CREATE TRIGGER IF NOT EXISTS trg_application_upgrade_lineage_no_update
         BEFORE UPDATE ON application_upgrade_lineage
         BEGIN
             SELECT RAISE(ABORT, 'application upgrade lineage is append only');
         END;",
    ),
    (
        NO_DELETE_TRIGGER_NAME,
        "CREATE TRIGGER IF NOT EXISTS trg_application_upgrade_lineage_no_delete
         BEFORE DELETE ON application_upgrade_lineage
         BEGIN
             SELECT RAISE(ABORT, 'application upgrade lineage is append only');
         END;",
    ),
    (
        NO_REPLACE_TRIGGER_NAME,
        "CREATE TRIGGER IF NOT EXISTS trg_application_upgrade_lineage_no_replace
         BEFORE INSERT ON application_upgrade_lineage
         WHEN EXISTS(
             SELECT 1 FROM application_upgrade_lineage AS existing
             WHERE existing.lineage_id=NEW.lineage_id
         )
         BEGIN
             SELECT RAISE(ABORT, 'application upgrade lineage is append only');
         END;",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationUpgradeLineageRecord {
    pub lineage_id: String,
    pub migration_id: String,
    pub source_profile_proof_sha256: String,
    pub source_user_logical_manifest_sha256: String,
    pub source_privacy_logical_manifest_sha256: String,
    pub original_rollback_identity_sha256: String,
    pub target_user_pre_audit_logical_manifest_sha256: String,
    pub target_user_pre_audit_business_manifest_sha256: String,
    pub target_privacy_pre_audit_logical_manifest_sha256: String,
    pub target_privacy_pre_audit_business_manifest_sha256: String,
    pub previous_receipt_sha256: String,
    pub result_code: String,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationUpgradeLineageAppendOutcome {
    Inserted,
    AlreadyPresent,
}

pub fn append_application_upgrade_lineage(
    connection: &Connection,
    record: &ApplicationUpgradeLineageRecord,
) -> Result<ApplicationUpgradeLineageAppendOutcome, PrivacyStoreError> {
    validate_record(record)?;
    if connection.is_autocommit() {
        let transaction =
            rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
                .map_err(|_| PrivacyStoreError::Database)?;
        let outcome = append_application_upgrade_lineage_in_transaction(&transaction, record)?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)?;
        Ok(outcome)
    } else {
        append_application_upgrade_lineage_in_transaction(connection, record)
    }
}

pub fn load_application_upgrade_lineage(
    connection: &Connection,
    lineage_id: &str,
) -> Result<Option<ApplicationUpgradeLineageRecord>, PrivacyStoreError> {
    validate_lower_hex_64(lineage_id)?;
    validate_application_upgrade_lineage_schema(connection)?;
    load_application_upgrade_lineage_row(connection, lineage_id)
}

pub(crate) fn install_application_upgrade_lineage_schema(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    connection
        .execute_batch(APPLICATION_UPGRADE_LINEAGE_TABLE_SQL)
        .map_err(|_| PrivacyStoreError::Database)?;
    connection
        .execute_batch(APPLICATION_UPGRADE_LINEAGE_INDEX_SQL)
        .map_err(|_| PrivacyStoreError::Database)?;
    for (_, sql) in APPLICATION_UPGRADE_LINEAGE_TRIGGER_SQL {
        connection
            .execute_batch(sql)
            .map_err(|_| PrivacyStoreError::Database)?;
    }
    Ok(())
}

pub(crate) fn ensure_application_upgrade_lineage_absent(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    let count = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE name IN (?1,?2,?3,?4,?5)",
            params![
                APPLICATION_UPGRADE_LINEAGE_TABLE_NAME,
                LINEAGE_INDEX_NAME,
                NO_UPDATE_TRIGGER_NAME,
                NO_DELETE_TRIGGER_NAME,
                NO_REPLACE_TRIGGER_NAME,
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| PrivacyStoreError::Database)?;
    if count == 0 {
        Ok(())
    } else {
        Err(PrivacyStoreError::UnsupportedSchema)
    }
}

pub(crate) fn validate_application_upgrade_lineage_schema(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    let version = connection
        .query_row(
            "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)?;
    let expected_version = PRIVACY_STORE_SCHEMA_VERSION.to_string();
    if version.as_deref() != Some(expected_version.as_str()) {
        return Err(PrivacyStoreError::UnsupportedSchema);
    }

    for (kind, name, canonical_sql) in [
        (
            "table",
            APPLICATION_UPGRADE_LINEAGE_TABLE_NAME,
            APPLICATION_UPGRADE_LINEAGE_TABLE_SQL,
        ),
        (
            "index",
            LINEAGE_INDEX_NAME,
            APPLICATION_UPGRADE_LINEAGE_INDEX_SQL,
        ),
    ] {
        validate_schema_object(connection, kind, name, canonical_sql)?;
    }
    for (name, sql) in APPLICATION_UPGRADE_LINEAGE_TRIGGER_SQL {
        validate_schema_object(connection, "trigger", name, sql)?;
    }

    let object_count = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE tbl_name=?1
               AND type IN ('table','index','trigger')
               AND name NOT LIKE 'sqlite_%'",
            [APPLICATION_UPGRADE_LINEAGE_TABLE_NAME],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| PrivacyStoreError::Database)?;
    if object_count != 5 {
        return Err(PrivacyStoreError::UnsupportedSchema);
    }
    validate_all_application_upgrade_lineage_rows(connection)?;
    Ok(())
}

fn append_application_upgrade_lineage_in_transaction(
    connection: &Connection,
    record: &ApplicationUpgradeLineageRecord,
) -> Result<ApplicationUpgradeLineageAppendOutcome, PrivacyStoreError> {
    validate_application_upgrade_lineage_schema(connection)?;
    if let Some(existing) = load_application_upgrade_lineage_row(connection, &record.lineage_id)? {
        return if existing == *record {
            Ok(ApplicationUpgradeLineageAppendOutcome::AlreadyPresent)
        } else {
            Err(PrivacyStoreError::Conflict)
        };
    }

    let changed = connection
        .execute(
            "INSERT INTO application_upgrade_lineage(
                lineage_id,migration_id,source_profile_proof_sha256,
                source_user_logical_manifest_sha256,
                source_privacy_logical_manifest_sha256,
                original_rollback_identity_sha256,
                target_user_pre_audit_logical_manifest_sha256,
                target_user_pre_audit_business_manifest_sha256,
                target_privacy_pre_audit_logical_manifest_sha256,
                target_privacy_pre_audit_business_manifest_sha256,
                previous_receipt_sha256,result_code,created_at_unix
             ) VALUES(
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13
             )",
            params![
                record.lineage_id,
                record.migration_id,
                record.source_profile_proof_sha256,
                record.source_user_logical_manifest_sha256,
                record.source_privacy_logical_manifest_sha256,
                record.original_rollback_identity_sha256,
                record.target_user_pre_audit_logical_manifest_sha256,
                record.target_user_pre_audit_business_manifest_sha256,
                record.target_privacy_pre_audit_logical_manifest_sha256,
                record.target_privacy_pre_audit_business_manifest_sha256,
                record.previous_receipt_sha256,
                record.result_code,
                record.created_at_unix,
            ],
        )
        .map_err(map_insert_error)?;
    if changed != 1 {
        return Err(PrivacyStoreError::Conflict);
    }
    let installed = load_application_upgrade_lineage_row(connection, &record.lineage_id)?
        .ok_or(PrivacyStoreError::Conflict)?;
    if installed != *record {
        return Err(PrivacyStoreError::Conflict);
    }
    Ok(ApplicationUpgradeLineageAppendOutcome::Inserted)
}

fn load_application_upgrade_lineage_row(
    connection: &Connection,
    lineage_id: &str,
) -> Result<Option<ApplicationUpgradeLineageRecord>, PrivacyStoreError> {
    connection
        .query_row(
            "SELECT lineage_id,migration_id,source_profile_proof_sha256,
                    source_user_logical_manifest_sha256,
                    source_privacy_logical_manifest_sha256,
                    original_rollback_identity_sha256,
                    target_user_pre_audit_logical_manifest_sha256,
                    target_user_pre_audit_business_manifest_sha256,
                    target_privacy_pre_audit_logical_manifest_sha256,
                    target_privacy_pre_audit_business_manifest_sha256,
                    previous_receipt_sha256,result_code,created_at_unix
             FROM application_upgrade_lineage WHERE lineage_id=?1",
            [lineage_id],
            |row| {
                Ok(ApplicationUpgradeLineageRecord {
                    lineage_id: row.get(0)?,
                    migration_id: row.get(1)?,
                    source_profile_proof_sha256: row.get(2)?,
                    source_user_logical_manifest_sha256: row.get(3)?,
                    source_privacy_logical_manifest_sha256: row.get(4)?,
                    original_rollback_identity_sha256: row.get(5)?,
                    target_user_pre_audit_logical_manifest_sha256: row.get(6)?,
                    target_user_pre_audit_business_manifest_sha256: row.get(7)?,
                    target_privacy_pre_audit_logical_manifest_sha256: row.get(8)?,
                    target_privacy_pre_audit_business_manifest_sha256: row.get(9)?,
                    previous_receipt_sha256: row.get(10)?,
                    result_code: row.get(11)?,
                    created_at_unix: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)
}

fn validate_all_application_upgrade_lineage_rows(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    let mut statement = connection
        .prepare(
            "SELECT lineage_id,migration_id,source_profile_proof_sha256,
                    source_user_logical_manifest_sha256,
                    source_privacy_logical_manifest_sha256,
                    original_rollback_identity_sha256,
                    target_user_pre_audit_logical_manifest_sha256,
                    target_user_pre_audit_business_manifest_sha256,
                    target_privacy_pre_audit_logical_manifest_sha256,
                    target_privacy_pre_audit_business_manifest_sha256,
                    previous_receipt_sha256,result_code,created_at_unix
             FROM application_upgrade_lineage ORDER BY lineage_id",
        )
        .map_err(|_| PrivacyStoreError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok(ApplicationUpgradeLineageRecord {
                lineage_id: row.get(0)?,
                migration_id: row.get(1)?,
                source_profile_proof_sha256: row.get(2)?,
                source_user_logical_manifest_sha256: row.get(3)?,
                source_privacy_logical_manifest_sha256: row.get(4)?,
                original_rollback_identity_sha256: row.get(5)?,
                target_user_pre_audit_logical_manifest_sha256: row.get(6)?,
                target_user_pre_audit_business_manifest_sha256: row.get(7)?,
                target_privacy_pre_audit_logical_manifest_sha256: row.get(8)?,
                target_privacy_pre_audit_business_manifest_sha256: row.get(9)?,
                previous_receipt_sha256: row.get(10)?,
                result_code: row.get(11)?,
                created_at_unix: row.get(12)?,
            })
        })
        .map_err(|_| PrivacyStoreError::Database)?;
    for row in rows {
        let record = row.map_err(|_| PrivacyStoreError::Database)?;
        validate_record(&record).map_err(|_| PrivacyStoreError::Conflict)?;
    }
    Ok(())
}

fn validate_record(record: &ApplicationUpgradeLineageRecord) -> Result<(), PrivacyStoreError> {
    if record.migration_id != V031_TO_V040_MIGRATION_ID
        || record.result_code != APPLICATION_UPGRADE_RESULT_OK
        || !(1..=MAX_APPLICATION_UPGRADE_CREATED_AT_UNIX).contains(&record.created_at_unix)
    {
        return Err(PrivacyStoreError::InvalidInput);
    }
    for value in [
        record.lineage_id.as_str(),
        record.source_profile_proof_sha256.as_str(),
        record.source_user_logical_manifest_sha256.as_str(),
        record.source_privacy_logical_manifest_sha256.as_str(),
        record.original_rollback_identity_sha256.as_str(),
        record
            .target_user_pre_audit_logical_manifest_sha256
            .as_str(),
        record
            .target_user_pre_audit_business_manifest_sha256
            .as_str(),
        record
            .target_privacy_pre_audit_logical_manifest_sha256
            .as_str(),
        record
            .target_privacy_pre_audit_business_manifest_sha256
            .as_str(),
        record.previous_receipt_sha256.as_str(),
    ] {
        validate_lower_hex_64(value)?;
    }
    Ok(())
}

fn validate_lower_hex_64(value: &str) -> Result<(), PrivacyStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(PrivacyStoreError::InvalidInput)
    }
}

fn validate_schema_object(
    connection: &Connection,
    kind: &str,
    name: &str,
    canonical_sql: &str,
) -> Result<(), PrivacyStoreError> {
    let stored_sql = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type=?1 AND name=?2 AND tbl_name=?3",
            params![kind, name, APPLICATION_UPGRADE_LINEAGE_TABLE_NAME],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)?
        .ok_or(PrivacyStoreError::UnsupportedSchema)?;
    if normalize_schema_sql(&stored_sql) == normalize_schema_sql(canonical_sql) {
        Ok(())
    } else {
        Err(PrivacyStoreError::UnsupportedSchema)
    }
}

fn normalize_schema_sql(sql: &str) -> String {
    let normalized = sql
        .trim()
        .trim_end_matches(';')
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    for (with_if_not_exists, canonical) in [
        ("create table if not exists ", "create table "),
        ("create unique index if not exists ", "create unique index "),
        ("create trigger if not exists ", "create trigger "),
    ] {
        if let Some(suffix) = normalized.strip_prefix(with_if_not_exists) {
            return format!("{canonical}{suffix}");
        }
    }
    normalized
}

fn map_insert_error(error: rusqlite::Error) -> PrivacyStoreError {
    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
        PrivacyStoreError::Conflict
    } else {
        PrivacyStoreError::Database
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::PrivacyStore;

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn record() -> ApplicationUpgradeLineageRecord {
        ApplicationUpgradeLineageRecord {
            lineage_id: digest(0xaa),
            migration_id: V031_TO_V040_MIGRATION_ID.to_owned(),
            source_profile_proof_sha256: digest(1),
            source_user_logical_manifest_sha256: digest(2),
            source_privacy_logical_manifest_sha256: digest(3),
            original_rollback_identity_sha256: digest(4),
            target_user_pre_audit_logical_manifest_sha256: digest(5),
            target_user_pre_audit_business_manifest_sha256: digest(6),
            target_privacy_pre_audit_logical_manifest_sha256: digest(7),
            target_privacy_pre_audit_business_manifest_sha256: digest(8),
            previous_receipt_sha256: digest(9),
            result_code: APPLICATION_UPGRADE_RESULT_OK.to_owned(),
            created_at_unix: 1_785_433_600,
        }
    }

    fn setup() -> Connection {
        let connection = Connection::open_in_memory().expect("database");
        PrivacyStore::initialize(&connection).expect("schema");
        connection
    }

    #[test]
    fn canonical_v6_lineage_schema_and_business_exclusions_are_frozen() {
        let connection = setup();
        validate_application_upgrade_lineage_schema(&connection).expect("lineage schema");
        assert_eq!(
            PRIVACY_V6_BUSINESS_MANIFEST_EXCLUDED_TABLES,
            ["application_upgrade_lineage", "privacy_schema_metadata"]
        );
    }

    #[test]
    fn append_is_exactly_idempotent_and_conflicts_never_overwrite() {
        let connection = setup();
        let expected = record();
        assert_eq!(
            append_application_upgrade_lineage(&connection, &expected).expect("append"),
            ApplicationUpgradeLineageAppendOutcome::Inserted
        );
        assert_eq!(
            append_application_upgrade_lineage(&connection, &expected).expect("idempotent append"),
            ApplicationUpgradeLineageAppendOutcome::AlreadyPresent
        );
        assert_eq!(
            load_application_upgrade_lineage(&connection, &expected.lineage_id)
                .expect("load lineage"),
            Some(expected.clone())
        );

        let mut conflicting = expected.clone();
        conflicting.target_privacy_pre_audit_business_manifest_sha256 = digest(10);
        assert_eq!(
            append_application_upgrade_lineage(&connection, &conflicting),
            Err(PrivacyStoreError::Conflict)
        );
        assert_eq!(
            load_application_upgrade_lineage(&connection, &expected.lineage_id)
                .expect("load retained lineage"),
            Some(expected)
        );
    }

    #[test]
    fn api_rejects_noncanonical_hashes_fixed_fields_and_times() {
        let connection = setup();
        for mutate in [
            |record: &mut ApplicationUpgradeLineageRecord| record.lineage_id.make_ascii_uppercase(),
            |record: &mut ApplicationUpgradeLineageRecord| {
                record.source_profile_proof_sha256.pop();
            },
            |record: &mut ApplicationUpgradeLineageRecord| {
                record.migration_id = "other-migration".to_owned();
            },
            |record: &mut ApplicationUpgradeLineageRecord| {
                record.result_code = "failed".to_owned();
            },
            |record: &mut ApplicationUpgradeLineageRecord| record.created_at_unix = 0,
            |record: &mut ApplicationUpgradeLineageRecord| {
                record.created_at_unix = MAX_APPLICATION_UPGRADE_CREATED_AT_UNIX + 1;
            },
        ] {
            let mut invalid = record();
            mutate(&mut invalid);
            assert_eq!(
                append_application_upgrade_lineage(&connection, &invalid),
                Err(PrivacyStoreError::InvalidInput)
            );
        }
    }

    #[test]
    fn schema_guards_reject_update_delete_replace_and_mutating_upsert() {
        let connection = setup();
        let expected = record();
        append_application_upgrade_lineage(&connection, &expected).expect("append lineage");

        assert!(connection
            .execute(
                "UPDATE application_upgrade_lineage
                 SET created_at_unix=created_at_unix+1 WHERE lineage_id=?1",
                [&expected.lineage_id],
            )
            .is_err());
        assert!(connection
            .execute(
                "DELETE FROM application_upgrade_lineage WHERE lineage_id=?1",
                [&expected.lineage_id],
            )
            .is_err());
        assert!(connection
            .execute(
                "INSERT OR REPLACE INTO application_upgrade_lineage
                 SELECT * FROM application_upgrade_lineage WHERE lineage_id=?1",
                [&expected.lineage_id],
            )
            .is_err());
        assert!(connection
            .execute(
                "INSERT INTO application_upgrade_lineage
                 SELECT * FROM application_upgrade_lineage WHERE lineage_id=?1
                 ON CONFLICT(lineage_id) DO UPDATE
                 SET created_at_unix=excluded.created_at_unix",
                [&expected.lineage_id],
            )
            .is_err());
        assert_eq!(
            load_application_upgrade_lineage(&connection, &expected.lineage_id)
                .expect("retained lineage"),
            Some(expected)
        );
    }

    #[test]
    fn current_v6_rejects_missing_table_missing_trigger_and_weak_trigger() {
        let missing_table = setup();
        missing_table
            .execute_batch("DROP TABLE application_upgrade_lineage;")
            .expect("drop lineage table");
        assert_eq!(
            PrivacyStore::initialize(&missing_table),
            Err(PrivacyStoreError::UnsupportedSchema)
        );

        let missing_trigger = setup();
        missing_trigger
            .execute_batch("DROP TRIGGER trg_application_upgrade_lineage_no_delete;")
            .expect("drop lineage trigger");
        assert_eq!(
            PrivacyStore::initialize(&missing_trigger),
            Err(PrivacyStoreError::UnsupportedSchema)
        );

        let weak_trigger = setup();
        weak_trigger
            .execute_batch(
                "DROP TRIGGER trg_application_upgrade_lineage_no_update;
                 CREATE TRIGGER trg_application_upgrade_lineage_no_update
                 BEFORE UPDATE ON application_upgrade_lineage
                 WHEN 0 BEGIN SELECT 1; END;",
            )
            .expect("install weak lineage trigger");
        assert_eq!(
            PrivacyStore::initialize(&weak_trigger),
            Err(PrivacyStoreError::UnsupportedSchema)
        );
    }
}
