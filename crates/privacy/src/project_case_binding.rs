//! Persistent, audited one-to-one bindings between application projects and
//! strict Privacy/Vault case identities.
//!
//! A [`ProjectId`] and a [`PrivacyCaseId`] are deliberately different
//! identities. This module is the only supported way to associate them: it
//! stores an immutable one-to-one binding in the Privacy SQLite database and
//! creates the matching append-only creation audit atomically. Ordinary
//! lifecycle APIs own a `BEGIN IMMEDIATE` transaction; migration coordinators
//! may instead include the same operation in a caller-owned transaction.

use crate::vnext::CaseId;
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use std::{fmt, time::Duration};
use uuid::Uuid;

pub const PROJECT_PRIVACY_CASE_BINDING_SCHEMA_VERSION: i64 = 1;

const BINDING_VERSION: i64 = 1;
const MAX_PROJECT_ID_BYTES: usize = 256;
const MAX_CONTEXT_ID_BYTES: usize = 128;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const AUDIT_TABLE: &str = "project_privacy_case_binding_audit";
const BINDING_TABLE: &str = "project_privacy_case_bindings";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectPrivacyCaseBindingError {
    InvalidProjectId,
    InvalidPrivacyCaseId,
    ProjectPrivacyCaseUnbound,
    ProjectPrivacyCaseConflict,
    AmbiguousLegacyBinding,
    InvalidLifecycleContext,
    ProjectPrivacyCaseStoreFailed,
}

impl ProjectPrivacyCaseBindingError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidProjectId => "invalid_project_id",
            Self::InvalidPrivacyCaseId => "invalid_privacy_case_id",
            Self::ProjectPrivacyCaseUnbound => "project_privacy_case_unbound",
            Self::ProjectPrivacyCaseConflict => "project_privacy_case_conflict",
            Self::AmbiguousLegacyBinding => "ambiguous_legacy_binding",
            Self::InvalidLifecycleContext => "invalid_project_privacy_case_lifecycle_context",
            Self::ProjectPrivacyCaseStoreFailed => "project_privacy_case_store_failed",
        }
    }
}

impl fmt::Display for ProjectPrivacyCaseBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProjectPrivacyCaseBindingError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ProjectId(String);

impl ProjectId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ProjectPrivacyCaseBindingError> {
        let value = value.into();
        if !valid_project_id(&value) {
            return Err(ProjectPrivacyCaseBindingError::InvalidProjectId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ProjectId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl AsRef<str> for ProjectId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ProjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PrivacyCaseId(CaseId);

impl PrivacyCaseId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ProjectPrivacyCaseBindingError> {
        CaseId::parse(value)
            .map(Self)
            .map_err(|_| ProjectPrivacyCaseBindingError::InvalidPrivacyCaseId)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn as_case_id(&self) -> &CaseId {
        &self.0
    }

    pub fn into_case_id(self) -> CaseId {
        self.0
    }
}

impl<'de> Deserialize<'de> for PrivacyCaseId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

impl From<CaseId> for PrivacyCaseId {
    fn from(value: CaseId) -> Self {
        Self(value)
    }
}

impl From<PrivacyCaseId> for CaseId {
    fn from(value: PrivacyCaseId) -> Self {
        value.0
    }
}

impl AsRef<str> for PrivacyCaseId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for PrivacyCaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingCreationSource {
    LifecycleInitialization,
    LegacyMigration,
}

impl BindingCreationSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LifecycleInitialization => "lifecycle_initialization",
            Self::LegacyMigration => "legacy_migration",
        }
    }

    fn parse_stored(value: &str) -> Option<Self> {
        match value {
            "lifecycle_initialization" => Some(Self::LifecycleInitialization),
            "legacy_migration" => Some(Self::LegacyMigration),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingLifecycleContext {
    creation_source: BindingCreationSource,
    creation_audit_id: String,
    migration_id: Option<String>,
}

impl BindingLifecycleContext {
    pub fn new(
        creation_source: BindingCreationSource,
        creation_audit_id: impl Into<String>,
        migration_id: Option<String>,
    ) -> Result<Self, ProjectPrivacyCaseBindingError> {
        let creation_audit_id = creation_audit_id.into();
        if !valid_context_id(&creation_audit_id)
            || migration_id
                .as_deref()
                .is_some_and(|value| !valid_context_id(value))
        {
            return Err(ProjectPrivacyCaseBindingError::InvalidLifecycleContext);
        }
        Ok(Self {
            creation_source,
            creation_audit_id,
            migration_id,
        })
    }

    pub const fn creation_source(&self) -> BindingCreationSource {
        self.creation_source
    }

    pub fn creation_audit_id(&self) -> &str {
        &self.creation_audit_id
    }

    pub fn migration_id(&self) -> Option<&str> {
        self.migration_id.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredBinding {
    project_id: String,
    privacy_case_id: String,
    binding_version: i64,
    creation_source: String,
    creation_audit_id: String,
    migration_id: Option<String>,
    created_at: String,
    updated_at: String,
}

pub struct ProjectPrivacyCaseBindingStore;

impl ProjectPrivacyCaseBindingStore {
    pub fn initialize(connection: &mut Connection) -> Result<(), ProjectPrivacyCaseBindingError> {
        configure_write_connection(connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_failed)?;
        Self::initialize_in_transaction(&transaction)?;
        transaction.commit().map_err(store_failed)
    }

    /// Installs and verifies the binding schema inside a caller-owned write
    /// transaction. Coordinated migrations use this only after reauthenticating
    /// their exact pre-binding state under the same `BEGIN IMMEDIATE` lock.
    pub fn initialize_in_transaction(
        transaction: &Transaction<'_>,
    ) -> Result<(), ProjectPrivacyCaseBindingError> {
        transaction
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS project_privacy_case_binding_audit (
                    creation_audit_id TEXT PRIMARY KEY NOT NULL CHECK(
                        length(creation_audit_id) BETWEEN 1 AND 128
                        AND creation_audit_id = trim(creation_audit_id)
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
                    binding_version INTEGER NOT NULL CHECK(binding_version > 0),
                    creation_source TEXT NOT NULL CHECK(
                        creation_source IN ('lifecycle_initialization', 'legacy_migration')
                    ),
                    migration_id TEXT CHECK(
                        migration_id IS NULL OR (
                            length(migration_id) BETWEEN 1 AND 128
                            AND migration_id = trim(migration_id)
                        )
                    ),
                    result TEXT NOT NULL CHECK(result = 'created'),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK(length(created_at) > 0)
                );

                CREATE TRIGGER IF NOT EXISTS trg_project_privacy_case_audit_no_update
                BEFORE UPDATE ON project_privacy_case_binding_audit
                BEGIN
                    SELECT RAISE(ABORT, 'project/privacy case binding audit is append only');
                END;

                CREATE TRIGGER IF NOT EXISTS trg_project_privacy_case_audit_no_delete
                BEFORE DELETE ON project_privacy_case_binding_audit
                BEGIN
                    SELECT RAISE(ABORT, 'project/privacy case binding audit is append only');
                END;

                CREATE TRIGGER IF NOT EXISTS trg_project_privacy_case_audit_no_replace
                BEFORE INSERT ON project_privacy_case_binding_audit
                WHEN EXISTS (
                    SELECT 1
                    FROM project_privacy_case_binding_audit AS existing
                    WHERE existing.creation_audit_id = NEW.creation_audit_id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'project/privacy case binding audit is append only');
                END;

                CREATE TABLE IF NOT EXISTS project_privacy_case_bindings (
                    project_id TEXT PRIMARY KEY NOT NULL CHECK(
                        length(CAST(project_id AS BLOB)) BETWEEN 1 AND 256
                        AND substr(project_id, 1, 5) = 'case-'
                        AND project_id = trim(project_id)
                    ),
                    privacy_case_id TEXT UNIQUE NOT NULL CHECK(
                        length(privacy_case_id) = 37
                        AND substr(privacy_case_id, 1, 5) = 'case_'
                        AND substr(privacy_case_id, 6) NOT GLOB '*[^0-9a-f]*'
                    ),
                    binding_version INTEGER NOT NULL CHECK(binding_version > 0),
                    creation_source TEXT NOT NULL CHECK(
                        creation_source IN ('lifecycle_initialization', 'legacy_migration')
                    ),
                    creation_audit_id TEXT UNIQUE NOT NULL CHECK(
                        length(creation_audit_id) BETWEEN 1 AND 128
                        AND creation_audit_id = trim(creation_audit_id)
                    ),
                    migration_id TEXT CHECK(
                        migration_id IS NULL OR (
                            length(migration_id) BETWEEN 1 AND 128
                            AND migration_id = trim(migration_id)
                        )
                    ),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK(length(created_at) > 0),
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP CHECK(length(updated_at) > 0),
                    FOREIGN KEY(creation_audit_id)
                        REFERENCES project_privacy_case_binding_audit(creation_audit_id)
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_project_privacy_case_reverse
                    ON project_privacy_case_bindings(privacy_case_id);

                CREATE TRIGGER IF NOT EXISTS trg_project_privacy_case_binding_no_replace
                BEFORE INSERT ON project_privacy_case_bindings
                WHEN EXISTS (
                    SELECT 1
                    FROM project_privacy_case_bindings AS existing
                    WHERE existing.project_id = NEW.project_id
                       OR existing.privacy_case_id = NEW.privacy_case_id
                       OR existing.creation_audit_id = NEW.creation_audit_id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'project/privacy case binding is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS trg_project_privacy_case_binding_audit_match
                BEFORE INSERT ON project_privacy_case_bindings
                WHEN NOT EXISTS (
                    SELECT 1
                    FROM project_privacy_case_binding_audit AS audit
                    WHERE audit.creation_audit_id = NEW.creation_audit_id
                      AND audit.project_id = NEW.project_id
                      AND audit.privacy_case_id = NEW.privacy_case_id
                      AND audit.binding_version = NEW.binding_version
                      AND audit.creation_source = NEW.creation_source
                      AND audit.migration_id IS NEW.migration_id
                      AND audit.result = 'created'
                )
                BEGIN
                    SELECT RAISE(ABORT, 'project/privacy case binding audit mismatch');
                END;

                CREATE TRIGGER IF NOT EXISTS trg_project_privacy_case_binding_no_update
                BEFORE UPDATE ON project_privacy_case_bindings
                BEGIN
                    SELECT RAISE(ABORT, 'project/privacy case binding is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS trg_project_privacy_case_binding_no_delete
                BEFORE DELETE ON project_privacy_case_bindings
                BEGIN
                    SELECT RAISE(ABORT, 'project/privacy case binding is immutable');
                END;
                ",
            )
            .map_err(store_failed)?;
        validate_schema_objects(transaction)?;
        validate_schema_contract(transaction)?;
        validate_all_bindings(transaction)?;
        Ok(())
    }

    pub fn resolve(
        connection: &Connection,
        project_id: &ProjectId,
    ) -> Result<Option<PrivacyCaseId>, ProjectPrivacyCaseBindingError> {
        load_binding_by_project(connection, project_id)?
            .map(|stored| validate_stored_binding(connection, stored).map(|(_, privacy)| privacy))
            .transpose()
    }

    pub fn resolve_or_create(
        connection: &mut Connection,
        project_id: &ProjectId,
        lifecycle_context: &BindingLifecycleContext,
    ) -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError> {
        Self::resolve_or_create_with_generator(connection, project_id, lifecycle_context, || {
            PrivacyCaseId::parse(format!("case_{}", Uuid::new_v4().simple()))
                .map_err(|_| ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)
        })
    }

    /// Resolves or creates a binding inside a caller-owned transaction.
    ///
    /// The caller is responsible for committing or rolling back `transaction`.
    /// This is intended for migration batches that must commit the binding,
    /// its creation audit, and a separate migration ledger atomically.
    pub fn resolve_or_create_in_transaction(
        transaction: &Transaction<'_>,
        project_id: &ProjectId,
        lifecycle_context: &BindingLifecycleContext,
    ) -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError> {
        configure_write_connection(transaction)?;
        Self::resolve_or_create_with_generator_in_connection(
            transaction,
            project_id,
            lifecycle_context,
            || {
                PrivacyCaseId::parse(format!("case_{}", Uuid::new_v4().simple()))
                    .map_err(|_| ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)
            },
        )
    }

    /// Creates the exact identity pair recovered by a trusted legacy migration.
    ///
    /// This never derives either identity and never replaces an existing pair. A
    /// retry succeeds only when the persisted pair is byte-for-byte identical.
    pub fn bind_existing_for_migration(
        connection: &mut Connection,
        project_id: &ProjectId,
        privacy_case_id: &PrivacyCaseId,
        lifecycle_context: &BindingLifecycleContext,
    ) -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError> {
        if lifecycle_context.creation_source() != BindingCreationSource::LegacyMigration {
            return Err(ProjectPrivacyCaseBindingError::InvalidLifecycleContext);
        }
        configure_write_connection(connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_failed)?;
        let resolved = Self::bind_existing_for_migration_in_connection(
            &transaction,
            project_id,
            privacy_case_id,
            lifecycle_context,
        )?;
        transaction.commit().map_err(store_failed)?;
        Ok(resolved)
    }

    /// Creates an exact legacy identity pair inside a caller-owned transaction.
    ///
    /// No transaction is started or committed here. The binding and its
    /// append-only creation audit therefore remain part of the caller's larger
    /// migration batch.
    pub fn bind_existing_for_migration_in_transaction(
        transaction: &Transaction<'_>,
        project_id: &ProjectId,
        privacy_case_id: &PrivacyCaseId,
        lifecycle_context: &BindingLifecycleContext,
    ) -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError> {
        if lifecycle_context.creation_source() != BindingCreationSource::LegacyMigration {
            return Err(ProjectPrivacyCaseBindingError::InvalidLifecycleContext);
        }
        configure_write_connection(transaction)?;
        Self::bind_existing_for_migration_in_connection(
            transaction,
            project_id,
            privacy_case_id,
            lifecycle_context,
        )
    }

    pub fn reverse_resolve(
        connection: &Connection,
        privacy_case_id: &PrivacyCaseId,
    ) -> Result<Option<ProjectId>, ProjectPrivacyCaseBindingError> {
        load_binding_by_privacy_case(connection, privacy_case_id)?
            .map(|stored| validate_stored_binding(connection, stored).map(|(project, _)| project))
            .transpose()
    }

    pub fn validate_pair(
        connection: &Connection,
        project_id: &ProjectId,
        privacy_case_id: &PrivacyCaseId,
    ) -> Result<(), ProjectPrivacyCaseBindingError> {
        if let Some(bound) = Self::resolve(connection, project_id)? {
            return if bound == *privacy_case_id {
                Ok(())
            } else {
                Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict)
            };
        }

        if Self::reverse_resolve(connection, privacy_case_id)?.is_some() {
            return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict);
        }

        Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseUnbound)
    }

    fn resolve_or_create_with_generator<F>(
        connection: &mut Connection,
        project_id: &ProjectId,
        lifecycle_context: &BindingLifecycleContext,
        generate: F,
    ) -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError>
    where
        F: FnOnce() -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError>,
    {
        configure_write_connection(connection)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_failed)?;

        let privacy_case_id = Self::resolve_or_create_with_generator_in_connection(
            &transaction,
            project_id,
            lifecycle_context,
            generate,
        )?;
        transaction.commit().map_err(store_failed)?;
        Ok(privacy_case_id)
    }

    fn resolve_or_create_with_generator_in_connection<F>(
        connection: &Connection,
        project_id: &ProjectId,
        lifecycle_context: &BindingLifecycleContext,
        generate: F,
    ) -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError>
    where
        F: FnOnce() -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError>,
    {
        if let Some(stored) = load_binding_by_project(connection, project_id)? {
            let (_, privacy_case_id) = validate_stored_binding(connection, stored)?;
            return Ok(privacy_case_id);
        }

        let audit_id_in_use: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM project_privacy_case_binding_audit
                    WHERE creation_audit_id=?1
                )",
                [lifecycle_context.creation_audit_id()],
                |row| row.get(0),
            )
            .map_err(store_failed)?;
        if audit_id_in_use {
            return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict);
        }

        let privacy_case_id = generate()?;
        if load_binding_by_privacy_case(connection, &privacy_case_id)?.is_some() {
            return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict);
        }

        connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,migration_id,result
                 ) VALUES (?1,?2,?3,?4,?5,?6,'created')",
                params![
                    lifecycle_context.creation_audit_id(),
                    project_id.as_str(),
                    privacy_case_id.as_str(),
                    BINDING_VERSION,
                    lifecycle_context.creation_source().as_str(),
                    lifecycle_context.migration_id(),
                ],
            )
            .map_err(store_failed)?;

        connection
            .execute(
                "INSERT INTO project_privacy_case_bindings(
                    project_id,privacy_case_id,binding_version,creation_source,
                    creation_audit_id,migration_id
                 ) VALUES (?1,?2,?3,?4,?5,?6)",
                params![
                    project_id.as_str(),
                    privacy_case_id.as_str(),
                    BINDING_VERSION,
                    lifecycle_context.creation_source().as_str(),
                    lifecycle_context.creation_audit_id(),
                    lifecycle_context.migration_id(),
                ],
            )
            .map_err(store_failed)?;

        Self::validate_pair(connection, project_id, &privacy_case_id)
            .map_err(|_| ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)?;
        Ok(privacy_case_id)
    }

    fn bind_existing_for_migration_in_connection(
        connection: &Connection,
        project_id: &ProjectId,
        privacy_case_id: &PrivacyCaseId,
        lifecycle_context: &BindingLifecycleContext,
    ) -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError> {
        let expected = privacy_case_id.clone();
        let resolved = Self::resolve_or_create_with_generator_in_connection(
            connection,
            project_id,
            lifecycle_context,
            || Ok(expected.clone()),
        )?;
        if resolved != expected {
            return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict);
        }
        Ok(resolved)
    }
}

fn valid_project_id(value: &str) -> bool {
    value.starts_with("case-")
        && value.len() <= MAX_PROJECT_ID_BYTES
        && value.trim() == value
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        && !value
            .chars()
            .any(|character| matches!(character, '\u{2028}' | '\u{2029}'))
}

fn valid_context_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONTEXT_ID_BYTES
        && value.trim() == value
        && !value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        && !value
            .chars()
            .any(|character| matches!(character, '\u{2028}' | '\u{2029}'))
}

fn configure_write_connection(
    connection: &Connection,
) -> Result<(), ProjectPrivacyCaseBindingError> {
    connection
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .map_err(store_failed)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(store_failed)?;
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .map_err(store_failed)?;
    let foreign_keys_enabled: bool = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(store_failed)?;
    let recursive_triggers_enabled: bool = connection
        .pragma_query_value(None, "recursive_triggers", |row| row.get(0))
        .map_err(store_failed)?;
    if !foreign_keys_enabled || !recursive_triggers_enabled {
        return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed);
    }
    Ok(())
}

fn load_binding_by_project(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<StoredBinding>, ProjectPrivacyCaseBindingError> {
    let mut statement = connection
        .prepare(
            "SELECT project_id,privacy_case_id,binding_version,creation_source,
                    creation_audit_id,migration_id,created_at,updated_at
             FROM project_privacy_case_bindings
             WHERE project_id=?1
             LIMIT 2",
        )
        .map_err(store_failed)?;
    let mut rows = statement
        .query([project_id.as_str()])
        .map_err(store_failed)?;
    let Some(row) = rows.next().map_err(store_failed)? else {
        return Ok(None);
    };
    let stored = StoredBinding {
        project_id: row.get(0).map_err(store_failed)?,
        privacy_case_id: row.get(1).map_err(store_failed)?,
        binding_version: row.get(2).map_err(store_failed)?,
        creation_source: row.get(3).map_err(store_failed)?,
        creation_audit_id: row.get(4).map_err(store_failed)?,
        migration_id: row.get(5).map_err(store_failed)?,
        created_at: row.get(6).map_err(store_failed)?,
        updated_at: row.get(7).map_err(store_failed)?,
    };
    if rows.next().map_err(store_failed)?.is_some() {
        return Err(ProjectPrivacyCaseBindingError::AmbiguousLegacyBinding);
    }
    Ok(Some(stored))
}

fn load_binding_by_privacy_case(
    connection: &Connection,
    privacy_case_id: &PrivacyCaseId,
) -> Result<Option<StoredBinding>, ProjectPrivacyCaseBindingError> {
    let project_ids = {
        let mut statement = connection
            .prepare(
                "SELECT project_id
                 FROM project_privacy_case_bindings
                 WHERE privacy_case_id=?1
                 LIMIT 2",
            )
            .map_err(store_failed)?;
        let mut rows = statement
            .query([privacy_case_id.as_str()])
            .map_err(store_failed)?;
        let mut project_ids = Vec::new();
        while let Some(row) = rows.next().map_err(store_failed)? {
            project_ids.push(row.get::<_, String>(0).map_err(store_failed)?);
        }
        project_ids
    };
    if project_ids.len() > 1 {
        return Err(ProjectPrivacyCaseBindingError::AmbiguousLegacyBinding);
    }
    let Some(project_id) = project_ids.into_iter().next() else {
        return Ok(None);
    };
    let project_id = ProjectId::parse(project_id)
        .map_err(|_| ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)?;
    let stored = load_binding_by_project(connection, &project_id)?
        .ok_or(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)?;
    if stored.privacy_case_id != privacy_case_id.as_str() {
        return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed);
    }
    Ok(Some(stored))
}

fn validate_stored_binding(
    connection: &Connection,
    stored: StoredBinding,
) -> Result<(ProjectId, PrivacyCaseId), ProjectPrivacyCaseBindingError> {
    let project_id = ProjectId::parse(stored.project_id.clone())
        .map_err(|_| ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)?;
    let privacy_case_id = PrivacyCaseId::parse(stored.privacy_case_id.clone())
        .map_err(|_| ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)?;
    let creation_source = BindingCreationSource::parse_stored(&stored.creation_source)
        .ok_or(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)?;
    if stored.binding_version != BINDING_VERSION
        || !valid_context_id(&stored.creation_audit_id)
        || stored
            .migration_id
            .as_deref()
            .is_some_and(|value| !valid_context_id(value))
        || stored.created_at.is_empty()
        || stored.updated_at.is_empty()
    {
        return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed);
    }

    let matching_audit_count: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM project_privacy_case_binding_audit
             WHERE creation_audit_id=?1
               AND project_id=?2
               AND privacy_case_id=?3
               AND binding_version=?4
               AND creation_source=?5
               AND migration_id IS ?6
               AND result='created'
               AND length(created_at)>0",
            params![
                stored.creation_audit_id,
                project_id.as_str(),
                privacy_case_id.as_str(),
                stored.binding_version,
                creation_source.as_str(),
                stored.migration_id,
            ],
            |row| row.get(0),
        )
        .map_err(store_failed)?;
    if matching_audit_count != 1 {
        return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed);
    }
    Ok((project_id, privacy_case_id))
}

fn validate_schema_objects(connection: &Connection) -> Result<(), ProjectPrivacyCaseBindingError> {
    for (kind, name) in [
        ("table", AUDIT_TABLE),
        ("table", BINDING_TABLE),
        ("index", "idx_project_privacy_case_reverse"),
        ("trigger", "trg_project_privacy_case_audit_no_update"),
        ("trigger", "trg_project_privacy_case_audit_no_delete"),
        ("trigger", "trg_project_privacy_case_audit_no_replace"),
        ("trigger", "trg_project_privacy_case_binding_no_replace"),
        ("trigger", "trg_project_privacy_case_binding_audit_match"),
        ("trigger", "trg_project_privacy_case_binding_no_update"),
        ("trigger", "trg_project_privacy_case_binding_no_delete"),
    ] {
        let exists: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2
                )",
                params![kind, name],
                |row| row.get(0),
            )
            .map_err(store_failed)?;
        if !exists {
            return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed);
        }
    }
    Ok(())
}

fn validate_schema_contract(connection: &Connection) -> Result<(), ProjectPrivacyCaseBindingError> {
    const SAVEPOINT: &str = "project_privacy_case_schema_probe";
    connection
        .execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))
        .map_err(store_failed)?;

    let validation: Result<(), ProjectPrivacyCaseBindingError> = (|| {
        let first_token = Uuid::new_v4().simple().to_string();
        let second_token = Uuid::new_v4().simple().to_string();
        let third_token = Uuid::new_v4().simple().to_string();
        let first_project = format!("case-schema-probe-{first_token}");
        let second_project = format!("case-schema-probe-{second_token}");
        let third_project = format!("case-schema-probe-{third_token}");
        let first_privacy = format!("case_{first_token}");
        let second_privacy = format!("case_{second_token}");
        let third_privacy = format!("case_{third_token}");
        let first_audit = format!("schema-probe-a-{first_token}");
        let second_audit = format!("schema-probe-b-{second_token}");
        let third_audit = format!("schema-probe-c-{third_token}");

        connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES (?1,?2,?3,1,'lifecycle_initialization','created')",
                params![first_audit, first_project, first_privacy],
            )
            .map_err(store_failed)?;
        connection
            .execute(
                "INSERT INTO project_privacy_case_bindings(
                    project_id,privacy_case_id,binding_version,creation_source,
                    creation_audit_id,migration_id
                 ) VALUES (?1,?2,1,'lifecycle_initialization',?3,NULL)",
                params![first_project, first_privacy, first_audit],
            )
            .map_err(store_failed)?;

        let must_reject = |result: rusqlite::Result<usize>| {
            if result.is_ok() {
                Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)
            } else {
                Ok(())
            }
        };
        must_reject(connection.execute(
            "INSERT INTO project_privacy_case_binding_audit(
                creation_audit_id,project_id,privacy_case_id,binding_version,
                creation_source,result
             ) VALUES ('schema-probe-invalid','case-invalid',
                       'case_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,
                       'lifecycle_initialization','created')",
            [],
        ))?;
        must_reject(connection.execute(
            "UPDATE project_privacy_case_bindings
             SET privacy_case_id=?1 WHERE project_id=?2",
            params![second_privacy, first_project],
        ))?;
        must_reject(connection.execute(
            "DELETE FROM project_privacy_case_bindings WHERE project_id=?1",
            [&first_project],
        ))?;
        must_reject(connection.execute(
            "INSERT OR REPLACE INTO project_privacy_case_bindings(
                project_id,privacy_case_id,binding_version,creation_source,
                creation_audit_id,migration_id
             ) VALUES (?1,?2,1,'lifecycle_initialization',?3,NULL)",
            params![first_project, first_privacy, first_audit],
        ))?;
        must_reject(connection.execute(
            "UPDATE project_privacy_case_binding_audit
             SET project_id=?1 WHERE creation_audit_id=?2",
            params![second_project, first_audit],
        ))?;
        must_reject(connection.execute(
            "DELETE FROM project_privacy_case_binding_audit WHERE creation_audit_id=?1",
            [&first_audit],
        ))?;
        must_reject(connection.execute(
            "INSERT OR REPLACE INTO project_privacy_case_binding_audit(
                creation_audit_id,project_id,privacy_case_id,binding_version,
                creation_source,result
             ) VALUES (?1,?2,?3,1,'lifecycle_initialization','created')",
            params![first_audit, second_project, second_privacy],
        ))?;

        connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES (?1,?2,?3,1,'lifecycle_initialization','created')",
                params![second_audit, second_project, first_privacy],
            )
            .map_err(store_failed)?;
        must_reject(connection.execute(
            "INSERT INTO project_privacy_case_bindings(
                project_id,privacy_case_id,binding_version,creation_source,
                creation_audit_id,migration_id
             ) VALUES (?1,?2,1,'lifecycle_initialization',?3,NULL)",
            params![second_project, first_privacy, second_audit],
        ))?;

        connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES (?1,?2,?3,1,'lifecycle_initialization','created')",
                params![third_audit, third_project, second_privacy],
            )
            .map_err(store_failed)?;
        must_reject(connection.execute(
            "INSERT INTO project_privacy_case_bindings(
                project_id,privacy_case_id,binding_version,creation_source,
                creation_audit_id,migration_id
             ) VALUES (?1,?2,1,'lifecycle_initialization',?3,NULL)",
            params![third_project, third_privacy, third_audit],
        ))?;
        Ok(())
    })();

    let cleanup = connection
        .execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"))
        .map_err(store_failed);
    match (validation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        _ => Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed),
    }
}

fn validate_all_bindings(connection: &Connection) -> Result<(), ProjectPrivacyCaseBindingError> {
    let project_ids = {
        let mut statement = connection
            .prepare(
                "SELECT project_id
                 FROM project_privacy_case_bindings
                 ORDER BY project_id",
            )
            .map_err(store_failed)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(store_failed)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(store_failed)?
    };
    for project_id in project_ids {
        let project_id = ProjectId::parse(project_id)
            .map_err(|_| ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)?;
        let stored = load_binding_by_project(connection, &project_id)?
            .ok_or(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)?;
        validate_stored_binding(connection, stored)?;
    }
    let unmatched_creation_audits: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM project_privacy_case_binding_audit AS audit
             WHERE audit.result='created'
               AND NOT EXISTS(
                   SELECT 1
                   FROM project_privacy_case_bindings AS binding
                   WHERE binding.creation_audit_id=audit.creation_audit_id
                     AND binding.project_id=audit.project_id
                     AND binding.privacy_case_id=audit.privacy_case_id
                     AND binding.binding_version=audit.binding_version
                     AND binding.creation_source=audit.creation_source
                     AND binding.migration_id IS audit.migration_id
               )",
            [],
            |row| row.get(0),
        )
        .map_err(store_failed)?;
    if unmatched_creation_audits != 0 {
        return Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed);
    }
    Ok(())
}

fn store_failed<T>(_error: T) -> ProjectPrivacyCaseBindingError {
    ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::{Arc, Barrier},
        thread,
    };
    use tempfile::TempDir;

    fn project(value: &str) -> ProjectId {
        ProjectId::parse(value).expect("valid project id")
    }

    fn privacy(value: char) -> PrivacyCaseId {
        PrivacyCaseId::parse(format!("case_{}", value.to_string().repeat(32)))
            .expect("valid privacy case id")
    }

    fn context(audit_id: &str) -> BindingLifecycleContext {
        BindingLifecycleContext::new(
            BindingCreationSource::LifecycleInitialization,
            audit_id,
            None,
        )
        .expect("valid lifecycle context")
    }

    fn migration_context(audit_id: &str) -> BindingLifecycleContext {
        BindingLifecycleContext::new(
            BindingCreationSource::LegacyMigration,
            audit_id,
            Some("project-privacy-case-binding-v1".to_owned()),
        )
        .expect("valid migration context")
    }

    fn initialized_memory() -> Connection {
        let mut connection = Connection::open_in_memory().expect("open in-memory database");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .expect("initialize binding schema");
        connection
    }

    fn initialized_file() -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("privacy-workflow.sqlite");
        let mut connection = Connection::open(&path).expect("open binding database");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .expect("initialize binding schema");
        drop(connection);
        (directory, path)
    }

    fn resolve_or_create_fixed(
        connection: &mut Connection,
        project_id: &ProjectId,
        lifecycle_context: &BindingLifecycleContext,
        privacy_case_id: PrivacyCaseId,
    ) -> Result<PrivacyCaseId, ProjectPrivacyCaseBindingError> {
        ProjectPrivacyCaseBindingStore::resolve_or_create_with_generator(
            connection,
            project_id,
            lifecycle_context,
            || Ok(privacy_case_id),
        )
    }

    #[test]
    fn strong_ids_enforce_separate_identity_contracts() {
        assert_eq!(
            ProjectId::parse(""),
            Err(ProjectPrivacyCaseBindingError::InvalidProjectId)
        );
        assert_eq!(
            ProjectId::parse(" case-one"),
            Err(ProjectPrivacyCaseBindingError::InvalidProjectId)
        );
        assert_eq!(
            ProjectId::parse("case one"),
            Err(ProjectPrivacyCaseBindingError::InvalidProjectId)
        );
        assert_eq!(
            ProjectId::parse("x".repeat(MAX_PROJECT_ID_BYTES + 1)),
            Err(ProjectPrivacyCaseBindingError::InvalidProjectId)
        );
        assert_eq!(
            ProjectId::parse("project-existing"),
            Err(ProjectPrivacyCaseBindingError::InvalidProjectId)
        );
        assert!(ProjectId::parse("case-existing-中文").is_ok());

        assert!(PrivacyCaseId::parse("case_0123456789abcdef0123456789abcdef").is_ok());
        assert_eq!(
            PrivacyCaseId::parse("case-0123456789abcdef0123456789abcdef"),
            Err(ProjectPrivacyCaseBindingError::InvalidPrivacyCaseId)
        );
        assert_eq!(
            PrivacyCaseId::parse("case_ABCDEF00000000000000000000000000"),
            Err(ProjectPrivacyCaseBindingError::InvalidPrivacyCaseId)
        );
    }

    #[test]
    fn lifecycle_context_is_bounded_and_explicit() {
        assert_eq!(
            BindingLifecycleContext::new(BindingCreationSource::LifecycleInitialization, "", None,),
            Err(ProjectPrivacyCaseBindingError::InvalidLifecycleContext)
        );
        assert_eq!(
            BindingLifecycleContext::new(
                BindingCreationSource::LegacyMigration,
                "audit-valid",
                Some("migration id".to_owned()),
            ),
            Err(ProjectPrivacyCaseBindingError::InvalidLifecycleContext)
        );
        assert!(BindingLifecycleContext::new(
            BindingCreationSource::LegacyMigration,
            "audit-migration",
            Some("case-material-unification-v1".to_owned()),
        )
        .is_ok());
    }

    #[test]
    fn resolve_create_reverse_and_validate_are_idempotent() {
        let mut connection = initialized_memory();
        let project_id = project("case-existing-one");
        let first_context = context("audit-create-one");
        let second_context = context("audit-create-one-retry");

        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("resolve unbound project"),
            None
        );
        let candidate = privacy('1');
        assert_eq!(
            ProjectPrivacyCaseBindingStore::validate_pair(&connection, &project_id, &candidate,),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseUnbound)
        );

        let created = resolve_or_create_fixed(
            &mut connection,
            &project_id,
            &first_context,
            candidate.clone(),
        )
        .expect("create binding");
        let retried =
            resolve_or_create_fixed(&mut connection, &project_id, &second_context, privacy('2'))
                .expect("resolve existing binding");
        assert_eq!(created, candidate);
        assert_eq!(retried, created);
        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("resolve binding"),
            Some(created.clone())
        );
        assert_eq!(
            ProjectPrivacyCaseBindingStore::reverse_resolve(&connection, &created)
                .expect("reverse resolve binding"),
            Some(project_id.clone())
        );
        ProjectPrivacyCaseBindingStore::validate_pair(&connection, &project_id, &created)
            .expect("pair validates");

        let binding_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM project_privacy_case_bindings",
                [],
                |row| row.get(0),
            )
            .expect("count bindings");
        let audit_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM project_privacy_case_binding_audit",
                [],
                |row| row.get(0),
            )
            .expect("count audits");
        assert_eq!(binding_count, 1);
        assert_eq!(audit_count, 1);

        let audit: (String, String, i64, String, String, Option<String>) = connection
            .query_row(
                "SELECT project_id,privacy_case_id,binding_version,creation_source,
                        result,migration_id
                 FROM project_privacy_case_binding_audit
                 WHERE creation_audit_id='audit-create-one'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .expect("read creation audit");
        assert_eq!(
            audit,
            (
                project_id.as_str().to_owned(),
                created.as_str().to_owned(),
                BINDING_VERSION,
                "lifecycle_initialization".to_owned(),
                "created".to_owned(),
                None,
            )
        );
    }

    #[test]
    fn migration_binding_preserves_exact_privacy_identity_and_rejects_replacement() {
        let mut connection = initialized_memory();
        let project_id = project("case-migrated");
        let first = privacy('4');
        let migration_context = migration_context("audit-migrated");

        assert_eq!(
            ProjectPrivacyCaseBindingStore::bind_existing_for_migration(
                &mut connection,
                &project_id,
                &first,
                &migration_context,
            )
            .expect("bind recovered identity"),
            first
        );
        assert_eq!(
            ProjectPrivacyCaseBindingStore::bind_existing_for_migration(
                &mut connection,
                &project_id,
                &privacy('5'),
                &BindingLifecycleContext::new(
                    BindingCreationSource::LegacyMigration,
                    "audit-migrated-conflict",
                    Some("project-privacy-case-binding-v1".to_owned()),
                )
                .expect("second migration context"),
            ),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict)
        );
        assert_eq!(
            ProjectPrivacyCaseBindingStore::bind_existing_for_migration(
                &mut connection,
                &project("case-wrong-source"),
                &privacy('6'),
                &context("audit-not-migration"),
            ),
            Err(ProjectPrivacyCaseBindingError::InvalidLifecycleContext)
        );
    }

    #[test]
    fn caller_owned_transaction_commits_binding_audit_and_ledger_together() {
        let mut connection = initialized_memory();
        connection
            .execute_batch(
                "CREATE TABLE test_migration_ledger (
                    target_id TEXT PRIMARY KEY NOT NULL
                 );",
            )
            .expect("create migration ledger fixture");
        let project_id = project("case-caller-transaction-commit");
        let privacy_case_id = privacy('b');

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin caller-owned transaction");
        assert_eq!(
            ProjectPrivacyCaseBindingStore::bind_existing_for_migration_in_transaction(
                &transaction,
                &project_id,
                &privacy_case_id,
                &migration_context("audit-caller-transaction-commit"),
            )
            .expect("bind exact identity in caller transaction"),
            privacy_case_id
        );
        transaction
            .execute(
                "INSERT INTO test_migration_ledger(target_id) VALUES (?1)",
                [project_id.as_str()],
            )
            .expect("write caller migration ledger");
        transaction.commit().expect("commit caller transaction");

        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("resolve committed binding"),
            Some(privacy_case_id)
        );
        let committed: (i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM project_privacy_case_binding_audit),
                    (SELECT COUNT(*) FROM test_migration_ledger)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("count atomically committed rows");
        assert_eq!(committed, (1, 1));
    }

    #[test]
    fn caller_owned_transaction_rolls_back_random_binding_audit_and_ledger_together() {
        let mut connection = initialized_memory();
        connection
            .execute_batch(
                "CREATE TABLE test_migration_ledger (
                    target_id TEXT PRIMARY KEY NOT NULL
                 );",
            )
            .expect("create migration ledger fixture");
        let project_id = project("case-caller-transaction-rollback");

        let generated = {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .expect("begin caller-owned transaction");
            let generated = ProjectPrivacyCaseBindingStore::resolve_or_create_in_transaction(
                &transaction,
                &project_id,
                &migration_context("audit-caller-transaction-rollback"),
            )
            .expect("create random identity in caller transaction");
            transaction
                .execute(
                    "INSERT INTO test_migration_ledger(target_id) VALUES (?1)",
                    [project_id.as_str()],
                )
                .expect("write caller migration ledger");
            assert_eq!(
                ProjectPrivacyCaseBindingStore::resolve(&transaction, &project_id)
                    .expect("resolve uncommitted binding"),
                Some(generated.clone())
            );
            transaction
                .rollback()
                .expect("roll back caller transaction");
            generated
        };

        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("resolve after rollback"),
            None
        );
        assert_eq!(
            ProjectPrivacyCaseBindingStore::reverse_resolve(&connection, &generated)
                .expect("reverse resolve after rollback"),
            None
        );
        let rolled_back: (i64, i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM project_privacy_case_bindings),
                    (SELECT COUNT(*) FROM project_privacy_case_binding_audit),
                    (SELECT COUNT(*) FROM test_migration_ledger)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("count atomically rolled-back rows");
        assert_eq!(rolled_back, (0, 0, 0));
    }

    #[test]
    fn caller_owned_exact_binding_preserves_conflict_and_idempotency_semantics() {
        let mut connection = initialized_memory();
        let project_id = project("case-caller-transaction-idempotent");
        let privacy_case_id = privacy('c');
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin first caller transaction");
        ProjectPrivacyCaseBindingStore::bind_existing_for_migration_in_transaction(
            &transaction,
            &project_id,
            &privacy_case_id,
            &migration_context("audit-caller-transaction-first"),
        )
        .expect("create exact binding");
        transaction.commit().expect("commit exact binding");

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin retry caller transaction");
        assert_eq!(
            ProjectPrivacyCaseBindingStore::bind_existing_for_migration_in_transaction(
                &transaction,
                &project_id,
                &privacy_case_id,
                &migration_context("audit-caller-transaction-retry"),
            )
            .expect("retry exact binding"),
            privacy_case_id
        );
        assert_eq!(
            ProjectPrivacyCaseBindingStore::bind_existing_for_migration_in_transaction(
                &transaction,
                &project_id,
                &privacy('d'),
                &migration_context("audit-caller-transaction-conflict"),
            ),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict)
        );
        transaction.commit().expect("commit idempotent retry");

        let counts: (i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM project_privacy_case_bindings),
                    (SELECT COUNT(*) FROM project_privacy_case_binding_audit)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("count binding and audit rows");
        assert_eq!(counts, (1, 1));
    }

    #[test]
    fn either_side_conflict_fails_closed() {
        let mut connection = initialized_memory();
        let first_project = project("case-conflict-one");
        let second_project = project("case-conflict-two");
        let shared_privacy = privacy('3');
        resolve_or_create_fixed(
            &mut connection,
            &first_project,
            &context("audit-conflict-one"),
            shared_privacy.clone(),
        )
        .expect("create first binding");

        assert_eq!(
            resolve_or_create_fixed(
                &mut connection,
                &second_project,
                &context("audit-conflict-two"),
                shared_privacy.clone(),
            ),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict)
        );
        assert_eq!(
            ProjectPrivacyCaseBindingStore::validate_pair(
                &connection,
                &first_project,
                &privacy('4'),
            ),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict)
        );
        assert_eq!(
            ProjectPrivacyCaseBindingStore::validate_pair(
                &connection,
                &second_project,
                &shared_privacy,
            ),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict)
        );
    }

    #[test]
    fn creation_audit_ids_cannot_be_reused_for_another_binding() {
        let mut connection = initialized_memory();
        let reused_context = context("audit-reused");
        resolve_or_create_fixed(
            &mut connection,
            &project("case-audit-owner"),
            &reused_context,
            privacy('5'),
        )
        .expect("create audit owner");
        assert_eq!(
            resolve_or_create_fixed(
                &mut connection,
                &project("case-audit-other"),
                &reused_context,
                privacy('6'),
            ),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict)
        );
    }

    #[test]
    fn database_constraints_and_triggers_are_fail_closed() {
        let mut connection = initialized_memory();
        let project_id = project("case-immutable");
        let privacy_case_id = resolve_or_create_fixed(
            &mut connection,
            &project_id,
            &context("audit-immutable"),
            privacy('7'),
        )
        .expect("create immutable binding");

        for sql in [
            "UPDATE project_privacy_case_bindings
             SET project_id='case-rewritten' WHERE project_id='case-immutable'",
            "UPDATE project_privacy_case_bindings
             SET privacy_case_id='case_88888888888888888888888888888888'
             WHERE project_id='case-immutable'",
            "DELETE FROM project_privacy_case_bindings WHERE project_id='case-immutable'",
            "UPDATE project_privacy_case_binding_audit
             SET result='created' WHERE creation_audit_id='audit-immutable'",
            "DELETE FROM project_privacy_case_binding_audit
             WHERE creation_audit_id='audit-immutable'",
        ] {
            assert!(
                connection.execute_batch(sql).is_err(),
                "mutation succeeded: {sql}"
            );
        }

        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("binding remains readable"),
            Some(privacy_case_id)
        );

        assert!(connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES ('audit-invalid-case','case-invalid',
                           'case_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,
                           'lifecycle_initialization','created')",
                [],
            )
            .is_err());
    }

    #[test]
    fn raw_sql_replace_cannot_rebind_either_identity_or_rewrite_the_audit() {
        let mut connection = initialized_memory();
        let project_id = project("case-replace-guard");
        let privacy_case_id = privacy('1');
        resolve_or_create_fixed(
            &mut connection,
            &project_id,
            &context("audit-replace-original"),
            privacy_case_id.clone(),
        )
        .expect("create original binding");

        let recursive_triggers: bool = connection
            .pragma_query_value(None, "recursive_triggers", |row| row.get(0))
            .expect("read recursive trigger configuration");
        assert!(recursive_triggers);

        let replacement_privacy_case_id = privacy('2');
        connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES (?1,?2,?3,1,'lifecycle_initialization','created')",
                params![
                    "audit-replace-project",
                    project_id.as_str(),
                    replacement_privacy_case_id.as_str(),
                ],
            )
            .expect("append replacement-attempt audit evidence");
        assert!(connection
            .execute(
                "INSERT OR REPLACE INTO project_privacy_case_bindings(
                    project_id,privacy_case_id,binding_version,creation_source,
                    creation_audit_id,migration_id
                 ) VALUES (?1,?2,1,'lifecycle_initialization',?3,NULL)",
                params![
                    project_id.as_str(),
                    replacement_privacy_case_id.as_str(),
                    "audit-replace-project",
                ],
            )
            .is_err());

        let replacement_project_id = project("case-replace-reverse");
        connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES (?1,?2,?3,1,'lifecycle_initialization','created')",
                params![
                    "audit-replace-reverse",
                    replacement_project_id.as_str(),
                    privacy_case_id.as_str(),
                ],
            )
            .expect("append reverse-replacement-attempt audit evidence");
        assert!(connection
            .execute(
                "INSERT OR REPLACE INTO project_privacy_case_bindings(
                    project_id,privacy_case_id,binding_version,creation_source,
                    creation_audit_id,migration_id
                 ) VALUES (?1,?2,1,'lifecycle_initialization',?3,NULL)",
                params![
                    replacement_project_id.as_str(),
                    privacy_case_id.as_str(),
                    "audit-replace-reverse",
                ],
            )
            .is_err());

        assert!(connection
            .execute(
                "INSERT OR REPLACE INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES ('audit-replace-original','case-rewritten',
                           'case_33333333333333333333333333333333',1,
                           'lifecycle_initialization','created')",
                [],
            )
            .is_err());

        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("resolve original binding"),
            Some(privacy_case_id.clone())
        );
        assert_eq!(
            ProjectPrivacyCaseBindingStore::reverse_resolve(&connection, &privacy_case_id)
                .expect("reverse resolve original binding"),
            Some(project_id.clone())
        );
        let original_audit: (String, String) = connection
            .query_row(
                "SELECT project_id,privacy_case_id
                 FROM project_privacy_case_binding_audit
                 WHERE creation_audit_id='audit-replace-original'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read immutable original audit");
        assert_eq!(
            original_audit,
            (
                project_id.as_str().to_owned(),
                privacy_case_id.as_str().to_owned(),
            )
        );
    }

    #[test]
    fn reopened_connections_reenable_recursive_guards_and_reject_upsert_rebinding() {
        let (_directory, path) = initialized_file();
        let project_id = project("case-upsert-guard");
        let privacy_case_id = privacy('4');
        {
            let mut connection = Connection::open(&path).expect("open first connection");
            resolve_or_create_fixed(
                &mut connection,
                &project_id,
                &context("audit-upsert-original"),
                privacy_case_id.clone(),
            )
            .expect("create original binding");
        }

        let mut connection = Connection::open(&path).expect("reopen binding database");
        connection
            .pragma_update(None, "recursive_triggers", "OFF")
            .expect("simulate connection default");
        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .expect("reinitialize connection guards");
        let recursive_triggers: bool = connection
            .pragma_query_value(None, "recursive_triggers", |row| row.get(0))
            .expect("read recursive trigger configuration");
        assert!(recursive_triggers);

        let replacement_privacy_case_id = privacy('5');
        connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES (?1,?2,?3,1,'lifecycle_initialization','created')",
                params![
                    "audit-upsert-replacement",
                    project_id.as_str(),
                    replacement_privacy_case_id.as_str(),
                ],
            )
            .expect("append upsert-attempt audit evidence");
        assert!(connection
            .execute(
                "INSERT INTO project_privacy_case_bindings(
                    project_id,privacy_case_id,binding_version,creation_source,
                    creation_audit_id,migration_id
                 ) VALUES (?1,?2,1,'lifecycle_initialization',?3,NULL)
                 ON CONFLICT(project_id) DO UPDATE SET
                    privacy_case_id=excluded.privacy_case_id,
                    creation_audit_id=excluded.creation_audit_id",
                params![
                    project_id.as_str(),
                    replacement_privacy_case_id.as_str(),
                    "audit-upsert-replacement",
                ],
            )
            .is_err());
        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("resolve immutable binding"),
            Some(privacy_case_id)
        );
    }

    #[test]
    fn audit_and_binding_insert_roll_back_together() {
        let mut connection = initialized_memory();
        connection
            .execute_batch(
                "CREATE TRIGGER test_reject_binding
                 BEFORE INSERT ON project_privacy_case_bindings
                 BEGIN
                     SELECT RAISE(ABORT, 'injected binding failure');
                 END;",
            )
            .expect("install injected failure");

        assert_eq!(
            resolve_or_create_fixed(
                &mut connection,
                &project("case-rollback"),
                &context("audit-rollback"),
                privacy('9'),
            ),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)
        );
        let audit_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM project_privacy_case_binding_audit",
                [],
                |row| row.get(0),
            )
            .expect("count rolled-back audits");
        let binding_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM project_privacy_case_bindings",
                [],
                |row| row.get(0),
            )
            .expect("count rolled-back bindings");
        assert_eq!(audit_count, 0);
        assert_eq!(binding_count, 0);
    }

    #[test]
    fn concurrent_resolve_or_create_returns_one_persisted_identity() {
        let (_directory, path) = initialized_file();
        let barrier = Arc::new(Barrier::new(2));
        let handles = (0..2)
            .map(|ordinal| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let mut connection =
                        Connection::open(path).expect("open concurrent connection");
                    let project_id = project("case-concurrent");
                    let lifecycle_context = context(&format!("audit-concurrent-{ordinal}"));
                    barrier.wait();
                    ProjectPrivacyCaseBindingStore::resolve_or_create(
                        &mut connection,
                        &project_id,
                        &lifecycle_context,
                    )
                    .expect("concurrent resolve or create")
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("binding worker exits"))
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], results[1]);

        let connection = Connection::open(path).expect("reopen binding database");
        let binding_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM project_privacy_case_bindings",
                [],
                |row| row.get(0),
            )
            .expect("count concurrent bindings");
        let audit_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM project_privacy_case_binding_audit",
                [],
                |row| row.get(0),
            )
            .expect("count concurrent audits");
        assert_eq!(binding_count, 1);
        assert_eq!(audit_count, 1);
    }

    #[test]
    fn initialization_is_idempotent_and_preserves_bindings() {
        let mut connection = initialized_memory();
        let project_id = project("case-schema-rerun");
        let created = resolve_or_create_fixed(
            &mut connection,
            &project_id,
            &context("audit-schema-rerun"),
            privacy('a'),
        )
        .expect("create before schema rerun");

        ProjectPrivacyCaseBindingStore::initialize(&mut connection)
            .expect("schema initialization reruns");
        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_id)
                .expect("binding survives schema rerun"),
            Some(created)
        );
    }

    #[test]
    fn initialization_rejects_preexisting_weak_tables_even_when_names_match() {
        let mut connection = Connection::open_in_memory().expect("open weak schema database");
        connection
            .execute_batch(
                "CREATE TABLE project_privacy_case_binding_audit (
                    creation_audit_id TEXT,
                    project_id TEXT,
                    privacy_case_id TEXT,
                    binding_version INTEGER,
                    creation_source TEXT,
                    migration_id TEXT,
                    result TEXT,
                    created_at TEXT
                 );
                 CREATE TABLE project_privacy_case_bindings (
                    project_id TEXT,
                    privacy_case_id TEXT,
                    binding_version INTEGER,
                    creation_source TEXT,
                    creation_audit_id TEXT,
                    migration_id TEXT,
                    created_at TEXT,
                    updated_at TEXT
                 );",
            )
            .expect("install weak same-name tables");

        assert_eq!(
            ProjectPrivacyCaseBindingStore::initialize(&mut connection),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)
        );
    }

    #[test]
    fn initialization_rejects_a_same_name_noop_guard_trigger() {
        let mut connection = initialized_memory();
        connection
            .execute_batch(
                "DROP TRIGGER trg_project_privacy_case_binding_no_update;
                 CREATE TRIGGER trg_project_privacy_case_binding_no_update
                 BEFORE UPDATE ON project_privacy_case_bindings
                 BEGIN
                    SELECT 1;
                 END;",
            )
            .expect("replace guard with no-op trigger");

        assert_eq!(
            ProjectPrivacyCaseBindingStore::initialize(&mut connection),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)
        );
    }

    #[test]
    fn initialization_rejects_an_orphaned_created_audit() {
        let mut connection = initialized_memory();
        connection
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                    creation_audit_id,project_id,privacy_case_id,binding_version,
                    creation_source,result
                 ) VALUES (
                    'audit-orphaned-created',
                    'case-orphaned-created',
                    'case_abcdefabcdefabcdefabcdefabcdefab',
                    1,
                    'lifecycle_initialization',
                    'created'
                 )",
                [],
            )
            .expect("append orphaned audit fixture");

        assert_eq!(
            ProjectPrivacyCaseBindingStore::initialize(&mut connection),
            Err(ProjectPrivacyCaseBindingError::ProjectPrivacyCaseStoreFailed)
        );
    }
}
