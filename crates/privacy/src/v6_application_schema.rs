//! Canonical application-owned objects that complete Privacy schema 6.
//!
//! These objects are part of schema 6, not optional post-upgrade additions.
//! Keeping their DDL in the Privacy crate lets fresh initialization, the
//! v5-to-v6 projection finalizer, and exact read-only manifest fixtures share
//! one byte-for-byte schema source without introducing a desktop dependency.

use crate::store::PrivacyStoreError;
use rusqlite::{Connection, OptionalExtension};

pub const CASE_MATERIAL_ASSIGNMENT_SCHEMA_VERSION: &str = "1";
pub const CASE_MATERIAL_ASSIGNMENT_SCHEMA_KEY: &str = "case_material_assignment_schema_version";

pub const ASSIGNMENT_AUDIT_NO_UPDATE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER IF NOT EXISTS trg_case_material_assignment_audit_no_update
    BEFORE UPDATE ON case_material_assignment_audit
    BEGIN
        SELECT RAISE(ABORT, 'case material assignment audit is append only');
    END
"#;

pub const ASSIGNMENT_AUDIT_NO_DELETE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER IF NOT EXISTS trg_case_material_assignment_audit_no_delete
    BEFORE DELETE ON case_material_assignment_audit
    BEGIN
        SELECT RAISE(ABORT, 'case material assignment audit is append only');
    END
"#;

pub const ASSIGNMENT_AUDIT_NO_REPLACE_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER IF NOT EXISTS trg_case_material_assignment_audit_no_replace
    BEFORE INSERT ON case_material_assignment_audit
    WHEN EXISTS (
        SELECT 1
        FROM case_material_assignment_audit AS existing
        WHERE existing.assignment_id=NEW.assignment_id
           OR existing.material_id=NEW.material_id
           OR existing.event_hash=NEW.event_hash
    )
    BEGIN
        SELECT RAISE(ABORT, 'case material assignment audit is append only');
    END
"#;

pub const ASSIGNMENT_AUDIT_SCOPE_MATCH_TRIGGER_SQL: &str = r#"
    CREATE TRIGGER IF NOT EXISTS trg_case_material_assignment_audit_scope_match
    BEFORE INSERT ON case_material_assignment_audit
    WHEN NOT EXISTS (
        SELECT 1
        FROM privacy_materials AS material
        JOIN project_privacy_case_bindings AS binding
          ON binding.project_id=NEW.project_id
         AND binding.privacy_case_id=NEW.privacy_case_id
        WHERE material.material_id=NEW.material_id
          AND material.project_id=NEW.project_id
          AND material.migration_status='ready'
          AND material.row_version=NEW.assigned_material_row_version
    )
    BEGIN
        SELECT RAISE(ABORT, 'case material assignment audit scope mismatch');
    END
"#;

const CASE_MATERIAL_ASSIGNMENT_SCHEMA_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS case_material_assignment_audit (
        assignment_id TEXT PRIMARY KEY NOT NULL CHECK(
            length(assignment_id) BETWEEN 1 AND 128
            AND assignment_id = trim(assignment_id)
        ),
        material_id TEXT UNIQUE NOT NULL CHECK(
            length(material_id) BETWEEN 1 AND 128
            AND material_id = trim(material_id)
        ),
        project_id TEXT NOT NULL CHECK(
            length(CAST(project_id AS BLOB)) BETWEEN 1 AND 256
            AND substr(project_id, 1, 5) = 'case-'
            AND project_id = trim(project_id)
        ),
        privacy_case_id TEXT NOT NULL CHECK(
            length(privacy_case_id) = 37
            AND substr(privacy_case_id, 1, 5) = 'case_'
            AND substr(privacy_case_id, 6) NOT GLOB '*[^0-9a-f]*'
        ),
        assignment_mode TEXT NOT NULL CHECK(
            assignment_mode IN ('initialize_null_case', 'preserve_historical_case')
        ),
        binding_action TEXT NOT NULL CHECK(
            binding_action IN ('created', 'reused')
        ),
        actor_sha256 TEXT NOT NULL CHECK(
            length(actor_sha256) = 64
            AND actor_sha256 NOT GLOB '*[^0-9a-f]*'
        ),
        expected_material_row_version INTEGER NOT NULL CHECK(
            expected_material_row_version >= 0
        ),
        assigned_material_row_version INTEGER NOT NULL CHECK(
            assigned_material_row_version = expected_material_row_version + 1
        ),
        previous_migration_status TEXT NOT NULL CHECK(
            previous_migration_status = 'unassigned'
        ),
        previous_state TEXT NOT NULL CHECK(length(previous_state) > 0),
        previous_event_hash TEXT NOT NULL CHECK(
            previous_event_hash = ''
            OR (
                length(previous_event_hash) = 64
                AND previous_event_hash NOT GLOB '*[^0-9a-f]*'
            )
        ),
        event_hash TEXT UNIQUE NOT NULL CHECK(
            length(event_hash) = 64
            AND event_hash NOT GLOB '*[^0-9a-f]*'
        ),
        result TEXT NOT NULL CHECK(result = 'assigned'),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK(length(created_at) > 0)
    );
"#;

const CASE_MATERIAL_ASSIGNMENT_METADATA_SQL: &str = r#"
    INSERT OR IGNORE INTO privacy_schema_metadata(key,value)
    VALUES('case_material_assignment_schema_version','1');
"#;

const VAULT_LINK_SCHEMA_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS privacy_vault_material_refs (
        material_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        object_id TEXT NOT NULL,
        object_version INTEGER NOT NULL CHECK(object_version > 0),
        source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
        envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64),
        content_bytes INTEGER NOT NULL CHECK(content_bytes > 0),
        retention_expires_at_unix INTEGER NOT NULL,
        retention_policy_revision INTEGER NOT NULL CHECK(retention_policy_revision > 0),
        bound_at_unix INTEGER NOT NULL,
        import_state TEXT NOT NULL CHECK(import_state IN (
            'vault_committed','review_ready','processing_failed','revoked'
        )),
        failure_code TEXT CHECK(failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 128),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(object_id, object_version),
        FOREIGN KEY(material_id) REFERENCES privacy_materials(material_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_privacy_vault_case
        ON privacy_vault_material_refs(case_id, material_id);
"#;

const CASE_DICTIONARY_SCHEMA_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS privacy_case_dictionary_heads (
        case_id TEXT PRIMARY KEY,
        revision INTEGER NOT NULL CHECK(revision > 0),
        revision_hash TEXT NOT NULL CHECK(length(revision_hash) = 64),
        state_object_id TEXT NOT NULL,
        state_object_version INTEGER NOT NULL CHECK(state_object_version > 0),
        state_content_sha256 TEXT NOT NULL CHECK(length(state_content_sha256) = 64),
        state_envelope_sha256 TEXT NOT NULL CHECK(length(state_envelope_sha256) = 64),
        state_content_bytes INTEGER NOT NULL CHECK(state_content_bytes > 0),
        updated_at_unix INTEGER NOT NULL CHECK(updated_at_unix > 0)
    );
    CREATE TABLE IF NOT EXISTS privacy_finding_secret_evidence (
        redaction_id TEXT PRIMARY KEY,
        case_id TEXT NOT NULL,
        evidence_hash TEXT NOT NULL CHECK(length(evidence_hash) = 64),
        object_id TEXT NOT NULL,
        object_version INTEGER NOT NULL CHECK(object_version > 0),
        content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
        envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256) = 64),
        content_bytes INTEGER NOT NULL CHECK(content_bytes > 0),
        created_at_unix INTEGER NOT NULL CHECK(created_at_unix > 0)
    );
    CREATE INDEX IF NOT EXISTS idx_privacy_finding_secret_case
        ON privacy_finding_secret_evidence(case_id,redaction_id);
"#;

const PROJECT_DELETION_SCHEMA_DDL: &str = r#"
    CREATE TABLE IF NOT EXISTS project_deletion_journal(
        deletion_id TEXT PRIMARY KEY NOT NULL CHECK(
            length(deletion_id) BETWEEN 1 AND 128
        ),
        project_id TEXT UNIQUE NOT NULL CHECK(
            length(CAST(project_id AS BLOB)) BETWEEN 1 AND 256
            AND substr(project_id,1,5)='case-'
            AND project_id=trim(project_id)
        ),
        privacy_case_id TEXT CHECK(
            privacy_case_id IS NULL OR (
                length(privacy_case_id)=37
                AND substr(privacy_case_id,1,5)='case_'
                AND substr(privacy_case_id,6) NOT GLOB '*[^0-9a-f]*'
            )
        ),
        scope_json TEXT NOT NULL CHECK(
            length(scope_json) BETWEEN 2 AND 1048576
        ),
        scope_sha256 TEXT NOT NULL CHECK(length(scope_sha256)=64),
        state TEXT NOT NULL CHECK(state IN(
            'prepared','privacy_revoked','user_deleted','completed'
        )),
        created_at_unix INTEGER NOT NULL CHECK(created_at_unix>0),
        privacy_revoked_at_unix INTEGER,
        user_deleted_at_unix INTEGER,
        completed_at_unix INTEGER,
        CHECK(
            (state='prepared'
             AND privacy_revoked_at_unix IS NULL
             AND user_deleted_at_unix IS NULL
             AND completed_at_unix IS NULL)
            OR
            (state='privacy_revoked'
             AND privacy_revoked_at_unix IS NOT NULL
             AND user_deleted_at_unix IS NULL
             AND completed_at_unix IS NULL)
            OR
            (state='user_deleted'
             AND privacy_revoked_at_unix IS NOT NULL
             AND user_deleted_at_unix IS NOT NULL
             AND completed_at_unix IS NULL)
            OR
            (state='completed'
             AND privacy_revoked_at_unix IS NOT NULL
             AND user_deleted_at_unix IS NOT NULL
             AND completed_at_unix IS NOT NULL)
        )
    );
    CREATE INDEX IF NOT EXISTS idx_project_deletion_journal_state
        ON project_deletion_journal(state,created_at_unix);
    CREATE TRIGGER IF NOT EXISTS trg_project_deletion_journal_no_delete
    BEFORE DELETE ON project_deletion_journal
    BEGIN
        SELECT RAISE(ABORT,'project deletion journal is append preserving');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_project_deletion_journal_no_replace
    BEFORE INSERT ON project_deletion_journal
    WHEN EXISTS(
        SELECT 1 FROM project_deletion_journal AS existing
        WHERE existing.deletion_id=NEW.deletion_id
           OR existing.project_id=NEW.project_id
    )
    BEGIN
        SELECT RAISE(ABORT,'project deletion journal is append preserving');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_project_deletion_journal_one_way
    BEFORE UPDATE ON project_deletion_journal
    WHEN NEW.deletion_id IS NOT OLD.deletion_id
      OR NEW.project_id IS NOT OLD.project_id
      OR NEW.privacy_case_id IS NOT OLD.privacy_case_id
      OR NEW.scope_json IS NOT OLD.scope_json
      OR NEW.scope_sha256 IS NOT OLD.scope_sha256
      OR NEW.created_at_unix IS NOT OLD.created_at_unix
      OR NOT(
           (OLD.state='prepared'
            AND NEW.state='privacy_revoked'
            AND OLD.privacy_revoked_at_unix IS NULL
            AND NEW.privacy_revoked_at_unix IS NOT NULL
            AND NEW.user_deleted_at_unix IS NULL
            AND NEW.completed_at_unix IS NULL)
        OR (OLD.state='privacy_revoked'
            AND NEW.state='user_deleted'
            AND NEW.privacy_revoked_at_unix=OLD.privacy_revoked_at_unix
            AND NEW.user_deleted_at_unix IS NOT NULL
            AND NEW.completed_at_unix IS NULL)
        OR (OLD.state='user_deleted'
            AND NEW.state='completed'
            AND NEW.privacy_revoked_at_unix=OLD.privacy_revoked_at_unix
            AND NEW.user_deleted_at_unix=OLD.user_deleted_at_unix
            AND NEW.completed_at_unix IS NOT NULL)
      )
    BEGIN
        SELECT RAISE(ABORT,'project deletion journal transition is invalid');
    END;
"#;

fn execute_schema(connection: &Connection, ddl: &str) -> Result<(), PrivacyStoreError> {
    connection
        .execute_batch(ddl)
        .map_err(|_| PrivacyStoreError::Database)
}

pub fn initialize_case_material_assignment_schema(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    execute_schema(connection, CASE_MATERIAL_ASSIGNMENT_SCHEMA_DDL)?;
    for trigger_sql in [
        ASSIGNMENT_AUDIT_NO_UPDATE_TRIGGER_SQL,
        ASSIGNMENT_AUDIT_NO_DELETE_TRIGGER_SQL,
        ASSIGNMENT_AUDIT_NO_REPLACE_TRIGGER_SQL,
        ASSIGNMENT_AUDIT_SCOPE_MATCH_TRIGGER_SQL,
    ] {
        execute_schema(connection, trigger_sql)?;
    }
    execute_schema(connection, CASE_MATERIAL_ASSIGNMENT_METADATA_SQL)?;
    let version = connection
        .query_row(
            "SELECT value FROM privacy_schema_metadata WHERE key=?1",
            [CASE_MATERIAL_ASSIGNMENT_SCHEMA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)?;
    if version.as_deref() != Some(CASE_MATERIAL_ASSIGNMENT_SCHEMA_VERSION) {
        return Err(PrivacyStoreError::UnsupportedSchema);
    }
    Ok(())
}

pub fn initialize_privacy_vault_link_schema(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    execute_schema(connection, VAULT_LINK_SCHEMA_DDL)
}

pub fn initialize_case_dictionary_schema(connection: &Connection) -> Result<(), PrivacyStoreError> {
    execute_schema(connection, CASE_DICTIONARY_SCHEMA_DDL)
}

pub fn initialize_project_deletion_schema(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    execute_schema(connection, PROJECT_DELETION_SCHEMA_DDL)
}

/// Installs every application-owned object that completes canonical Privacy
/// schema 6. Callers must first install the core store and project/case binding
/// schema so all referenced tables and columns already exist.
pub fn initialize_privacy_v6_application_extensions(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    initialize_case_material_assignment_schema(connection)?;
    initialize_privacy_vault_link_schema(connection)?;
    initialize_case_dictionary_schema(connection)?;
    initialize_project_deletion_schema(connection)
}
