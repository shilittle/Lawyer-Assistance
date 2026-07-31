use super::{PrivacyWorkflowError, PrivacyWorkflowManager};
use privacy::{sha256_hex, PrivacyCaseId, ProjectId, ProjectPrivacyCaseBindingStore};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

const PROJECT_DELETION_REASON: &str = "case_project_deleted";
const PROJECT_DELETION_SCHEMA_VERSION: &str = "project-deletion-journal-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalState {
    Prepared,
    PrivacyRevoked,
    UserDeleted,
    Completed,
}

impl JournalState {
    fn parse(value: &str) -> Result<Self, PrivacyWorkflowError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "privacy_revoked" => Ok(Self::PrivacyRevoked),
            "user_deleted" => Ok(Self::UserDeleted),
            "completed" => Ok(Self::Completed),
            _ => Err(project_deletion_journal_error()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProjectDeletionScope {
    schema_version: String,
    project_id: String,
    privacy_case_id: Option<String>,
    material_ids: Vec<String>,
    generation_ids: Vec<String>,
}

impl ProjectDeletionScope {
    fn new(
        project_id: &ProjectId,
        privacy_case_id: Option<&PrivacyCaseId>,
        material_ids: BTreeSet<String>,
        generation_ids: BTreeSet<String>,
    ) -> Self {
        Self {
            schema_version: PROJECT_DELETION_SCHEMA_VERSION.to_owned(),
            project_id: project_id.as_str().to_owned(),
            privacy_case_id: privacy_case_id.map(|case_id| case_id.as_str().to_owned()),
            material_ids: material_ids.into_iter().collect(),
            generation_ids: generation_ids.into_iter().collect(),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, PrivacyWorkflowError> {
        serde_json::to_vec(self).map_err(|_| project_deletion_journal_error())
    }

    fn fingerprint(&self) -> Result<String, PrivacyWorkflowError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    fn validate(&self) -> Result<(), PrivacyWorkflowError> {
        if self.schema_version != PROJECT_DELETION_SCHEMA_VERSION
            || ProjectId::parse(self.project_id.clone()).is_err()
            || self
                .privacy_case_id
                .as_ref()
                .is_some_and(|value| PrivacyCaseId::parse(value.clone()).is_err())
            || !strictly_sorted_unique(&self.material_ids)
            || !strictly_sorted_unique(&self.generation_ids)
            || self
                .material_ids
                .iter()
                .chain(self.generation_ids.iter())
                .any(|value| !valid_scope_identifier(value))
        {
            return Err(project_deletion_journal_error());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ProjectDeletionJournal {
    deletion_id: String,
    project_id: ProjectId,
    scope: ProjectDeletionScope,
    scope_sha256: String,
    state: JournalState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProjectDeletionCheckpoint {
    JournalPrepared,
    ExternalInvalidated,
    PrivacyRevoked,
    UserDeleted,
}

pub(super) fn initialize_schema(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    connection
        .execute_batch(
            "
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
            ",
        )
        .map_err(|_| project_deletion_journal_error())?;
    validate_schema_contract(connection)
}

pub(super) fn ensure_project_accepts_privacy_writes(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<(), PrivacyWorkflowError> {
    initialize_schema(connection)?;
    let state = connection
        .query_row(
            "SELECT state FROM project_deletion_journal WHERE project_id=?1",
            [project_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| project_deletion_journal_error())?;
    match state.as_deref() {
        None => Ok(()),
        Some("completed") => Err(project_id_retired_error()),
        Some("prepared" | "privacy_revoked" | "user_deleted") => Err(PrivacyWorkflowError::new(
            "case_project_deletion_pending",
            "The case project is being deleted and cannot accept new Privacy material.",
        )),
        Some(_) => Err(project_deletion_journal_error()),
    }
}

impl PrivacyWorkflowManager {
    pub(crate) fn delete_case_project_lifecycle(
        &self,
        user_connection: &mut Connection,
        requested_project_id: &str,
    ) -> Result<bool, PrivacyWorkflowError> {
        self.delete_case_project_with_checkpoint_hook(user_connection, requested_project_id, |_| {
            Ok(())
        })
    }

    fn delete_case_project_with_checkpoint_hook<F>(
        &self,
        user_connection: &mut Connection,
        requested_project_id: &str,
        mut checkpoint: F,
    ) -> Result<bool, PrivacyWorkflowError>
    where
        F: FnMut(ProjectDeletionCheckpoint) -> Result<(), PrivacyWorkflowError>,
    {
        let project_id = ProjectId::parse(requested_project_id.to_owned())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        let _gate = self.gate();
        database::validate_open_user_database(user_connection)
            .map_err(|_| project_source_error())?;
        let user_transaction = user_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| project_source_error())?;
        let mut privacy_connection = self.open_connection()?;
        initialize_schema(&privacy_connection)?;

        let project_exists = user_project_exists(&user_transaction, &project_id)?;
        let existing_journal = load_journal_for_project(&privacy_connection, &project_id)?;
        if !project_exists {
            return self.finish_absent_project_deletion(
                user_transaction,
                &mut privacy_connection,
                existing_journal,
                &mut checkpoint,
            );
        }
        if existing_journal
            .as_ref()
            .is_some_and(|journal| journal.state == JournalState::Completed)
        {
            return Err(project_id_retired_error());
        }
        if existing_journal
            .as_ref()
            .is_some_and(|journal| journal.state == JournalState::UserDeleted)
        {
            return Err(PrivacyWorkflowError::new(
                "case_project_deletion_invariant_failed",
                "A journaled user deletion cannot coexist with a live case project.",
            ));
        }

        let current_scope = load_and_validate_scope(&privacy_connection, &project_id)?;
        ensure_no_legal_hold(&privacy_connection, &current_scope)?;
        let deletion_id = existing_journal
            .as_ref()
            .map(|journal| journal.deletion_id.clone())
            .unwrap_or_else(new_project_deletion_id);
        preflight_user_project_delete(&user_transaction, &project_id, &deletion_id)?;
        let journal = match existing_journal {
            Some(journal) => {
                ensure_scope_matches(&journal, &current_scope)?;
                journal
            }
            None => {
                let journal = insert_prepared_journal(
                    &mut privacy_connection,
                    deletion_id,
                    current_scope,
                    self.current_unix()?,
                )?;
                checkpoint(ProjectDeletionCheckpoint::JournalPrepared)?;
                journal
            }
        };

        if journal.state == JournalState::Prepared {
            self.invalidate_project_external_scope(&journal.scope)?;
            checkpoint(ProjectDeletionCheckpoint::ExternalInvalidated)?;
            commit_privacy_revocation(&mut privacy_connection, &journal, self.current_unix()?)?;
            checkpoint(ProjectDeletionCheckpoint::PrivacyRevoked)?;
        } else {
            verify_privacy_revoked(&privacy_connection, &journal.scope)?;
            self.invalidate_project_external_scope(&journal.scope)?;
        }

        if journal.state == JournalState::UserDeleted {
            return Err(project_deletion_journal_error());
        }
        let deleted = database::delete_case_project(
            &user_transaction,
            project_id.as_str(),
            &journal.deletion_id,
        )
        .map_err(|_| project_source_error())?;
        if !deleted {
            return Err(project_source_changed_error());
        }
        user_transaction
            .commit()
            .map_err(|_| project_source_error())?;
        checkpoint(ProjectDeletionCheckpoint::UserDeleted)?;
        complete_journal_after_user_delete(
            &mut privacy_connection,
            &journal.deletion_id,
            self.current_unix()?,
        )?;
        Ok(true)
    }

    fn finish_absent_project_deletion<F>(
        &self,
        user_transaction: Transaction<'_>,
        privacy_connection: &mut Connection,
        journal: Option<ProjectDeletionJournal>,
        checkpoint: &mut F,
    ) -> Result<bool, PrivacyWorkflowError>
    where
        F: FnMut(ProjectDeletionCheckpoint) -> Result<(), PrivacyWorkflowError>,
    {
        let Some(journal) = journal else {
            user_transaction
                .commit()
                .map_err(|_| project_source_error())?;
            return Ok(false);
        };
        match journal.state {
            JournalState::Prepared => Err(PrivacyWorkflowError::new(
                "case_project_deletion_invariant_failed",
                "The case project is absent before its Privacy lifecycle was revoked.",
            )),
            JournalState::PrivacyRevoked | JournalState::UserDeleted => {
                verify_privacy_revoked(privacy_connection, &journal.scope)?;
                self.invalidate_project_external_scope(&journal.scope)?;
                retire_absent_project_id(
                    &user_transaction,
                    &journal.project_id,
                    &journal.deletion_id,
                )?;
                user_transaction
                    .commit()
                    .map_err(|_| project_source_error())?;
                checkpoint(ProjectDeletionCheckpoint::UserDeleted)?;
                complete_journal_after_user_delete(
                    privacy_connection,
                    &journal.deletion_id,
                    self.current_unix()?,
                )?;
                Ok(true)
            }
            JournalState::Completed => {
                retire_absent_project_id(
                    &user_transaction,
                    &journal.project_id,
                    &journal.deletion_id,
                )?;
                user_transaction
                    .commit()
                    .map_err(|_| project_source_error())?;
                Ok(false)
            }
        }
    }

    fn invalidate_project_external_scope(
        &self,
        scope: &ProjectDeletionScope,
    ) -> Result<(), PrivacyWorkflowError> {
        if scope.privacy_case_id.is_none() && scope.generation_ids.is_empty() {
            return Ok(());
        }
        let invalidator = self
            .shared
            .approved_publication_invalidator
            .as_ref()
            .ok_or_else(external_lifecycle_unavailable_error)?;
        let generation_ids = scope
            .generation_ids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if !generation_ids.is_empty() {
            invalidator
                .invalidate_lifecycle_bindings(&generation_ids, PROJECT_DELETION_REASON)
                .map_err(external_lifecycle_error)?;
        }
        if let Some(case_id) = scope.privacy_case_id.as_ref() {
            let case_id =
                privacy::vnext::CaseId::parse(case_id.clone()).map_err(|_| scope_error())?;
            invalidator
                .invalidate_case(&case_id, PROJECT_DELETION_REASON)
                .map_err(external_lifecycle_error)?;
        }
        Ok(())
    }

    pub(crate) fn upsert_case_project_lifecycle(
        &self,
        user_connection: &mut Connection,
        project: &database::CaseProjectRow,
    ) -> Result<(), PrivacyWorkflowError> {
        let project_id = ProjectId::parse(project.project_id.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        let _gate = self.gate();
        database::validate_open_user_database(user_connection)
            .map_err(|_| project_source_error())?;
        let user_transaction = user_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| project_source_error())?;
        if database::case_project_id_is_retired(&user_transaction, project_id.as_str())
            .map_err(|_| project_source_error())?
        {
            return Err(project_id_retired_error());
        }
        let privacy_connection = self.open_connection()?;
        initialize_schema(&privacy_connection)?;
        let exists = user_project_exists(&user_transaction, &project_id)?;
        let has_deletion_history =
            load_journal_for_project(&privacy_connection, &project_id)?.is_some();
        let has_binding = ProjectPrivacyCaseBindingStore::resolve(&privacy_connection, &project_id)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .is_some();
        let has_material_history = privacy_connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM privacy_materials WHERE project_id=?1
                 )",
                [project_id.as_str()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| project_deletion_journal_error())?;
        if (!exists && (has_deletion_history || has_binding || has_material_history))
            || (exists && has_deletion_history)
        {
            return Err(project_id_retired_error());
        }
        database::upsert_case_project(&user_transaction, project)
            .map_err(|_| project_source_error())?;
        user_transaction
            .commit()
            .map_err(|_| project_source_error())
    }

    pub(super) fn recover_pending_project_deletions_unlocked(
        &self,
        privacy_connection: &mut Connection,
    ) -> Result<(), PrivacyWorkflowError> {
        initialize_schema(privacy_connection)?;
        let project_ids = pending_project_ids(privacy_connection)?;
        for project_id in project_ids {
            let mut user_connection = database::open_user_database(&self.shared.user_database_path)
                .map_err(|_| project_source_error())?;
            self.resume_pending_project_deletion_unlocked(
                &mut user_connection,
                privacy_connection,
                &project_id,
            )?;
        }
        Ok(())
    }

    fn resume_pending_project_deletion_unlocked(
        &self,
        user_connection: &mut Connection,
        privacy_connection: &mut Connection,
        project_id: &ProjectId,
    ) -> Result<(), PrivacyWorkflowError> {
        database::validate_open_user_database(user_connection)
            .map_err(|_| project_source_error())?;
        let user_transaction = user_connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| project_source_error())?;
        let journal = load_journal_for_project(privacy_connection, project_id)?
            .ok_or_else(project_deletion_journal_error)?;
        let project_exists = user_project_exists(&user_transaction, project_id)?;

        if journal.state == JournalState::Completed {
            if project_exists {
                return Err(project_id_retired_error());
            }
            retire_absent_project_id(&user_transaction, &journal.project_id, &journal.deletion_id)?;
            user_transaction
                .commit()
                .map_err(|_| project_source_error())?;
            return Ok(());
        }
        if journal.state == JournalState::UserDeleted && project_exists {
            return Err(PrivacyWorkflowError::new(
                "case_project_deletion_invariant_failed",
                "A journaled user deletion cannot coexist with a live case project.",
            ));
        }
        if journal.state == JournalState::Prepared && !project_exists {
            return Err(PrivacyWorkflowError::new(
                "case_project_deletion_invariant_failed",
                "The case project is absent before its Privacy lifecycle was revoked.",
            ));
        }
        if project_exists {
            let current_scope = load_and_validate_scope(privacy_connection, project_id)?;
            ensure_scope_matches(&journal, &current_scope)?;
            ensure_no_legal_hold(privacy_connection, &current_scope)?;
            preflight_user_project_delete(&user_transaction, project_id, &journal.deletion_id)?;
        }

        if journal.state == JournalState::Prepared {
            self.invalidate_project_external_scope(&journal.scope)?;
            commit_privacy_revocation(privacy_connection, &journal, self.current_unix()?)?;
        } else {
            verify_privacy_revoked(privacy_connection, &journal.scope)?;
            self.invalidate_project_external_scope(&journal.scope)?;
        }

        if project_exists {
            let deleted = database::delete_case_project(
                &user_transaction,
                project_id.as_str(),
                &journal.deletion_id,
            )
            .map_err(|_| project_source_error())?;
            if !deleted {
                return Err(project_source_changed_error());
            }
        } else {
            retire_absent_project_id(&user_transaction, &journal.project_id, &journal.deletion_id)?;
        }
        user_transaction
            .commit()
            .map_err(|_| project_source_error())?;
        complete_journal_after_user_delete(
            privacy_connection,
            &journal.deletion_id,
            self.current_unix()?,
        )
    }
}

fn validate_schema_contract(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    const REQUIRED_OBJECTS: [(&str, &str); 5] = [
        ("table", "project_deletion_journal"),
        ("index", "idx_project_deletion_journal_state"),
        ("trigger", "trg_project_deletion_journal_no_delete"),
        ("trigger", "trg_project_deletion_journal_no_replace"),
        ("trigger", "trg_project_deletion_journal_one_way"),
    ];
    for (object_type, name) in REQUIRED_OBJECTS {
        let present = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2
                 )",
                params![object_type, name],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| project_deletion_journal_error())?;
        if !present {
            return Err(project_deletion_journal_error());
        }
    }

    let expected_columns = [
        "deletion_id",
        "project_id",
        "privacy_case_id",
        "scope_json",
        "scope_sha256",
        "state",
        "created_at_unix",
        "privacy_revoked_at_unix",
        "user_deleted_at_unix",
        "completed_at_unix",
    ];
    let mut statement = connection
        .prepare("PRAGMA table_info(project_deletion_journal)")
        .map_err(|_| project_deletion_journal_error())?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| project_deletion_journal_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| project_deletion_journal_error())?;
    if columns != expected_columns {
        return Err(project_deletion_journal_error());
    }

    let no_replace_sql = connection
        .query_row(
            "SELECT lower(sql) FROM sqlite_master
             WHERE type='trigger'
               AND name='trg_project_deletion_journal_no_replace'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| project_deletion_journal_error())?;
    if !no_replace_sql.contains("before insert on project_deletion_journal")
        || !no_replace_sql.contains("existing.deletion_id=new.deletion_id")
        || !no_replace_sql.contains("existing.project_id=new.project_id")
        || !no_replace_sql.contains("raise(abort")
    {
        return Err(project_deletion_journal_error());
    }
    let no_delete_sql = connection
        .query_row(
            "SELECT lower(sql) FROM sqlite_master
             WHERE type='trigger'
               AND name='trg_project_deletion_journal_no_delete'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| project_deletion_journal_error())?;
    if !no_delete_sql.contains("before delete on project_deletion_journal")
        || !no_delete_sql.contains("raise(abort")
    {
        return Err(project_deletion_journal_error());
    }
    let one_way_sql = connection
        .query_row(
            "SELECT lower(sql) FROM sqlite_master
             WHERE type='trigger'
               AND name='trg_project_deletion_journal_one_way'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| project_deletion_journal_error())?;
    for required in [
        "before update on project_deletion_journal",
        "old.state='prepared'",
        "new.state='privacy_revoked'",
        "old.state='privacy_revoked'",
        "new.state='user_deleted'",
        "old.state='user_deleted'",
        "new.state='completed'",
        "raise(abort",
    ] {
        if !one_way_sql.contains(required) {
            return Err(project_deletion_journal_error());
        }
    }
    let malformed_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM project_deletion_journal
             WHERE length(scope_sha256)<>64
                OR state NOT IN('prepared','privacy_revoked','user_deleted','completed')
                OR created_at_unix<=0",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| project_deletion_journal_error())?;
    if malformed_rows != 0 {
        return Err(project_deletion_journal_error());
    }
    validate_trigger_behavior(connection)
}

fn validate_trigger_behavior(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    const SAVEPOINT: &str = "project_deletion_journal_schema_probe";
    connection
        .execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))
        .map_err(|_| project_deletion_journal_error())?;

    let validation: Result<(), PrivacyWorkflowError> = (|| {
        let token = Uuid::new_v4().simple().to_string();
        let deletion_id = format!("pdel_schema_probe_{token}");
        let alternate_deletion_id = format!("pdel_schema_probe_alt_{token}");
        let project_id = format!("case-schema-probe-{token}");
        let alternate_project_id = format!("case-schema-probe-alt-{token}");
        let scope_sha256 = "0".repeat(64);

        let require_one = |result: rusqlite::Result<usize>| match result {
            Ok(1) => Ok(()),
            _ => Err(project_deletion_journal_error()),
        };
        let must_reject = |result: rusqlite::Result<usize>| {
            if result.is_err() {
                Ok(())
            } else {
                Err(project_deletion_journal_error())
            }
        };

        require_one(connection.execute(
            "INSERT INTO project_deletion_journal(
                deletion_id,project_id,privacy_case_id,scope_json,scope_sha256,state,
                created_at_unix,privacy_revoked_at_unix,user_deleted_at_unix,
                completed_at_unix
             ) VALUES (?1,?2,NULL,'{}',?3,'prepared',1,NULL,NULL,NULL)",
            params![deletion_id, project_id, scope_sha256],
        ))?;

        must_reject(connection.execute(
            "INSERT OR REPLACE INTO project_deletion_journal(
                deletion_id,project_id,privacy_case_id,scope_json,scope_sha256,state,
                created_at_unix,privacy_revoked_at_unix,user_deleted_at_unix,
                completed_at_unix
             ) VALUES (?1,?2,NULL,'{}',?3,'prepared',1,NULL,NULL,NULL)",
            params![deletion_id, alternate_project_id, scope_sha256],
        ))?;
        must_reject(connection.execute(
            "INSERT OR REPLACE INTO project_deletion_journal(
                deletion_id,project_id,privacy_case_id,scope_json,scope_sha256,state,
                created_at_unix,privacy_revoked_at_unix,user_deleted_at_unix,
                completed_at_unix
             ) VALUES (?1,?2,NULL,'{}',?3,'prepared',1,NULL,NULL,NULL)",
            params![alternate_deletion_id, project_id, scope_sha256],
        ))?;
        must_reject(connection.execute(
            "DELETE FROM project_deletion_journal WHERE deletion_id=?1",
            [&deletion_id],
        ))?;
        must_reject(connection.execute(
            "UPDATE project_deletion_journal
             SET scope_sha256=?1 WHERE deletion_id=?2",
            params!["a".repeat(64), deletion_id],
        ))?;
        must_reject(connection.execute(
            "UPDATE project_deletion_journal
             SET state='completed',
                 privacy_revoked_at_unix=2,
                 user_deleted_at_unix=3,
                 completed_at_unix=4
             WHERE deletion_id=?1",
            [&deletion_id],
        ))?;

        require_one(connection.execute(
            "UPDATE project_deletion_journal
             SET state='privacy_revoked',privacy_revoked_at_unix=2
             WHERE deletion_id=?1",
            [&deletion_id],
        ))?;
        require_one(connection.execute(
            "UPDATE project_deletion_journal
             SET state='user_deleted',user_deleted_at_unix=3
             WHERE deletion_id=?1",
            [&deletion_id],
        ))?;
        require_one(connection.execute(
            "UPDATE project_deletion_journal
             SET state='completed',completed_at_unix=4
             WHERE deletion_id=?1",
            [&deletion_id],
        ))?;
        must_reject(connection.execute(
            "UPDATE project_deletion_journal
             SET state='user_deleted',completed_at_unix=NULL
             WHERE deletion_id=?1",
            [&deletion_id],
        ))?;
        Ok(())
    })();

    let cleanup = connection
        .execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"))
        .map_err(|_| project_deletion_journal_error());
    match (validation, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        _ => Err(project_deletion_journal_error()),
    }
}

fn user_project_exists(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
) -> Result<bool, PrivacyWorkflowError> {
    transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE project_id=?1)",
            [project_id.as_str()],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| project_source_error())
}

fn preflight_user_project_delete(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    privacy_deletion_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    match database::preflight_delete_case_project(
        transaction,
        project_id.as_str(),
        privacy_deletion_id,
    )
    .map_err(|_| project_source_error())?
    {
        true => Ok(()),
        false => Err(project_source_changed_error()),
    }
}

fn retire_absent_project_id(
    transaction: &Transaction<'_>,
    project_id: &ProjectId,
    privacy_deletion_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    if database::retire_absent_case_project_id_after_privacy_revocation(
        transaction,
        project_id.as_str(),
        privacy_deletion_id,
    )
    .map_err(|_| project_source_error())?
    {
        Ok(())
    } else {
        Err(project_source_changed_error())
    }
}

fn load_and_validate_scope(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<ProjectDeletionScope, PrivacyWorkflowError> {
    let privacy_case_id = ProjectPrivacyCaseBindingStore::resolve(connection, project_id)
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    let material_ids = collect_ids(
        connection,
        "SELECT material_id FROM privacy_materials
         WHERE project_id=?1 ORDER BY material_id",
        project_id.as_str(),
    )?;
    let generation_ids = collect_ids(
        connection,
        "SELECT generation.redaction_id
         FROM privacy_redactions AS generation
         JOIN privacy_materials AS material
           ON material.material_id=generation.material_id
         WHERE material.project_id=?1
         ORDER BY generation.redaction_id",
        project_id.as_str(),
    )?;
    let scope = ProjectDeletionScope::new(
        project_id,
        privacy_case_id.as_ref(),
        material_ids,
        generation_ids,
    );
    scope.validate()?;
    if privacy_case_id.is_none()
        && (!scope.material_ids.is_empty() || !scope.generation_ids.is_empty())
    {
        return Err(scope_error());
    }

    let mut vault_statement = connection
        .prepare(
            "SELECT vault.case_id
             FROM privacy_vault_material_refs AS vault
             JOIN privacy_materials AS material
               ON material.material_id=vault.material_id
             WHERE material.project_id=?1
             ORDER BY vault.material_id",
        )
        .map_err(|_| scope_error())?;
    let rows = vault_statement
        .query_map([project_id.as_str()], |row| row.get::<_, String>(0))
        .map_err(|_| scope_error())?;
    let vault_case_ids = rows
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| scope_error())?;
    if vault_case_ids.iter().any(|value| {
        PrivacyCaseId::parse(value.clone()).is_err()
            || privacy_case_id
                .as_ref()
                .is_none_or(|expected| expected.as_str() != value)
    }) {
        return Err(scope_error());
    }
    if privacy_case_id.is_none() && !vault_case_ids.is_empty() {
        return Err(scope_error());
    }

    let (generation_count, retention_count, invalid_policy_count) = connection
        .query_row(
            "SELECT COUNT(generation.redaction_id),
                    COUNT(retention.redaction_id),
                    COALESCE(SUM(
                      CASE WHEN retention.policy_revision IS NULL
                                  OR retention.policy_revision<=0
                           THEN 1 ELSE 0 END
                    ),0)
             FROM privacy_redactions AS generation
             JOIN privacy_materials AS material
               ON material.material_id=generation.material_id
             LEFT JOIN privacy_retention_bindings AS retention
               ON retention.redaction_id=generation.redaction_id
             WHERE material.project_id=?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .map_err(|_| retention_error())?;
    if usize::try_from(generation_count).ok() != Some(scope.generation_ids.len())
        || retention_count != generation_count
        || invalid_policy_count != 0
    {
        return Err(retention_error());
    }
    Ok(scope)
}

fn ensure_no_legal_hold(
    connection: &Connection,
    scope: &ProjectDeletionScope,
) -> Result<(), PrivacyWorkflowError> {
    let legal_hold_count = connection
        .query_row(
            "SELECT COUNT(*)
             FROM privacy_retention_bindings AS retention
             JOIN privacy_redactions AS generation
               ON generation.redaction_id=retention.redaction_id
             JOIN privacy_materials AS material
               ON material.material_id=generation.material_id
             WHERE material.project_id=?1 AND retention.legal_hold=1",
            [scope.project_id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| retention_error())?;
    if legal_hold_count != 0 {
        return Err(PrivacyWorkflowError::new(
            "legal_hold_active",
            "The case project contains material under legal hold and cannot be deleted.",
        ));
    }
    Ok(())
}

fn insert_prepared_journal(
    connection: &mut Connection,
    deletion_id: String,
    scope: ProjectDeletionScope,
    created_at_unix: u64,
) -> Result<ProjectDeletionJournal, PrivacyWorkflowError> {
    if created_at_unix == 0 || !valid_project_deletion_id(&deletion_id) {
        return Err(project_deletion_journal_error());
    }
    let scope_json = String::from_utf8(scope.canonical_bytes()?)
        .map_err(|_| project_deletion_journal_error())?;
    let scope_sha256 = scope.fingerprint()?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| project_deletion_journal_error())?;
    transaction
        .execute(
            "INSERT INTO project_deletion_journal(
                deletion_id,project_id,privacy_case_id,scope_json,scope_sha256,state,
                created_at_unix
             ) VALUES(?1,?2,?3,?4,?5,'prepared',?6)",
            params![
                deletion_id,
                scope.project_id,
                scope.privacy_case_id,
                scope_json,
                scope_sha256,
                sql_i64(created_at_unix)?,
            ],
        )
        .map_err(|_| project_deletion_journal_error())?;
    transaction
        .commit()
        .map_err(|_| project_deletion_journal_error())?;
    Ok(ProjectDeletionJournal {
        deletion_id,
        project_id: ProjectId::parse(scope.project_id.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?,
        scope,
        scope_sha256,
        state: JournalState::Prepared,
    })
}

fn new_project_deletion_id() -> String {
    format!("pdel_{}", Uuid::new_v4().simple())
}

fn valid_project_deletion_id(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("pdel_")
        && value[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value[5..]
            .bytes()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_lowercase())
}

fn load_journal_for_project(
    connection: &Connection,
    project_id: &ProjectId,
) -> Result<Option<ProjectDeletionJournal>, PrivacyWorkflowError> {
    let row = connection
        .query_row(
            "SELECT deletion_id,project_id,privacy_case_id,scope_json,scope_sha256,state
             FROM project_deletion_journal WHERE project_id=?1",
            [project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| project_deletion_journal_error())?;
    row.map(|row| {
        let stored_project_id =
            ProjectId::parse(row.1).map_err(PrivacyWorkflowError::project_case_binding)?;
        if &stored_project_id != project_id || !valid_project_deletion_id(&row.0) {
            return Err(project_deletion_journal_error());
        }
        let scope: ProjectDeletionScope =
            serde_json::from_str(&row.3).map_err(|_| project_deletion_journal_error())?;
        scope.validate()?;
        if scope.project_id != project_id.as_str()
            || scope.privacy_case_id != row.2
            || scope.fingerprint()? != row.4
        {
            return Err(project_deletion_journal_error());
        }
        Ok(ProjectDeletionJournal {
            deletion_id: row.0,
            project_id: stored_project_id,
            scope,
            scope_sha256: row.4,
            state: JournalState::parse(&row.5)?,
        })
    })
    .transpose()
}

fn ensure_scope_matches(
    journal: &ProjectDeletionJournal,
    current: &ProjectDeletionScope,
) -> Result<(), PrivacyWorkflowError> {
    if journal.project_id.as_str() != current.project_id
        || journal.scope != *current
        || journal.scope_sha256 != current.fingerprint()?
    {
        return Err(project_source_changed_error());
    }
    Ok(())
}

fn commit_privacy_revocation(
    connection: &mut Connection,
    journal: &ProjectDeletionJournal,
    revoked_at_unix: u64,
) -> Result<(), PrivacyWorkflowError> {
    if journal.state != JournalState::Prepared || revoked_at_unix == 0 {
        return Err(project_deletion_journal_error());
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| project_deletion_journal_error())?;
    transaction
        .execute(
            "UPDATE case_material_selections
             SET invalidated_at=CURRENT_TIMESTAMP,
                 invalidation_reason='project_deleted',
                 row_version=row_version+1
             WHERE project_id=?1
               AND deselected_at IS NULL
               AND invalidated_at IS NULL",
            [journal.project_id.as_str()],
        )
        .map_err(|_| project_deletion_journal_error())?;
    transaction
        .execute(
            "UPDATE privacy_receipts
             SET revoked_at_unix=COALESCE(revoked_at_unix,?2)
             WHERE redaction_id IN(
               SELECT generation.redaction_id
               FROM privacy_redactions AS generation
               JOIN privacy_materials AS material
                 ON material.material_id=generation.material_id
               WHERE material.project_id=?1
             )",
            params![journal.project_id.as_str(), sql_i64(revoked_at_unix)?],
        )
        .map_err(|_| project_deletion_journal_error())?;
    transaction
        .execute(
            "UPDATE privacy_approved_outputs
             SET revoked_at_unix=COALESCE(revoked_at_unix,?2)
             WHERE redaction_id IN(
               SELECT generation.redaction_id
               FROM privacy_redactions AS generation
               JOIN privacy_materials AS material
                 ON material.material_id=generation.material_id
               WHERE material.project_id=?1
             )",
            params![journal.project_id.as_str(), sql_i64(revoked_at_unix)?],
        )
        .map_err(|_| project_deletion_journal_error())?;
    transaction
        .execute(
            "UPDATE privacy_redactions
             SET revocation_state='revoked',
                 revoked_at=CURRENT_TIMESTAMP,
                 row_version=row_version+1
             WHERE material_id IN(
               SELECT material_id FROM privacy_materials WHERE project_id=?1
             )
               AND revocation_state='active'
               AND revoked_at IS NULL",
            [journal.project_id.as_str()],
        )
        .map_err(|_| project_deletion_journal_error())?;
    transaction
        .execute(
            "UPDATE privacy_materials
             SET state='revoked',
                 deleted_at=CURRENT_TIMESTAMP,
                 updated_at=CURRENT_TIMESTAMP,
                 row_version=row_version+1
             WHERE project_id=?1 AND deleted_at IS NULL",
            [journal.project_id.as_str()],
        )
        .map_err(|_| project_deletion_journal_error())?;
    transaction
        .execute(
            "UPDATE privacy_vault_material_refs
             SET import_state='revoked',
                 failure_code='project_deleted',
                 updated_at=CURRENT_TIMESTAMP
             WHERE material_id IN(
               SELECT material_id FROM privacy_materials WHERE project_id=?1
             )
               AND import_state<>'revoked'",
            [journal.project_id.as_str()],
        )
        .map_err(|_| project_deletion_journal_error())?;
    verify_privacy_revoked(&transaction, &journal.scope)?;
    let changed = transaction
        .execute(
            "UPDATE project_deletion_journal
             SET state='privacy_revoked',privacy_revoked_at_unix=?2
             WHERE deletion_id=?1 AND state='prepared'",
            params![journal.deletion_id, sql_i64(revoked_at_unix)?,],
        )
        .map_err(|_| project_deletion_journal_error())?;
    if changed != 1 {
        return Err(project_deletion_journal_error());
    }
    transaction
        .commit()
        .map_err(|_| project_deletion_journal_error())
}

fn verify_privacy_revoked(
    connection: &Connection,
    scope: &ProjectDeletionScope,
) -> Result<(), PrivacyWorkflowError> {
    let counts = connection
        .query_row(
            "SELECT
               (SELECT COUNT(*) FROM privacy_materials
                WHERE project_id=?1
                  AND (deleted_at IS NULL OR state<>'revoked')),
               (SELECT COUNT(*)
                FROM privacy_redactions AS generation
                JOIN privacy_materials AS material
                  ON material.material_id=generation.material_id
                WHERE material.project_id=?1
                  AND (
                       generation.revocation_state='active'
                       OR (generation.revocation_state='revoked'
                           AND generation.revoked_at IS NULL)
                       OR (generation.revocation_state='revoked_legacy_time_unknown'
                           AND generation.revoked_at IS NOT NULL)
                  )),
               (SELECT COUNT(*)
                FROM privacy_receipts AS receipt
                JOIN privacy_redactions AS generation
                  ON generation.redaction_id=receipt.redaction_id
                JOIN privacy_materials AS material
                  ON material.material_id=generation.material_id
                WHERE material.project_id=?1
                  AND receipt.revoked_at_unix IS NULL),
               (SELECT COUNT(*) FROM case_material_selections
                WHERE project_id=?1
                  AND deselected_at IS NULL
                  AND invalidated_at IS NULL),
               (SELECT COUNT(*)
                FROM privacy_approved_outputs AS output
                JOIN privacy_redactions AS generation
                  ON generation.redaction_id=output.redaction_id
                JOIN privacy_materials AS material
                  ON material.material_id=generation.material_id
                WHERE material.project_id=?1
                  AND output.revoked_at_unix IS NULL),
               (SELECT COUNT(*)
                FROM privacy_vault_material_refs AS vault
                JOIN privacy_materials AS material
                  ON material.material_id=vault.material_id
                WHERE material.project_id=?1
                  AND vault.import_state<>'revoked')",
            [scope.project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .map_err(|_| project_deletion_journal_error())?;
    if counts != (0, 0, 0, 0, 0, 0) {
        return Err(PrivacyWorkflowError::new(
            "case_project_privacy_revocation_incomplete",
            "The case project remains linked to a live Privacy capability.",
        ));
    }
    let current_materials = collect_ids(
        connection,
        "SELECT material_id FROM privacy_materials
         WHERE project_id=?1 ORDER BY material_id",
        &scope.project_id,
    )?;
    let current_generations = collect_ids(
        connection,
        "SELECT generation.redaction_id
         FROM privacy_redactions AS generation
         JOIN privacy_materials AS material
           ON material.material_id=generation.material_id
         WHERE material.project_id=?1
         ORDER BY generation.redaction_id",
        &scope.project_id,
    )?;
    if current_materials != scope.material_ids.iter().cloned().collect()
        || current_generations != scope.generation_ids.iter().cloned().collect()
    {
        return Err(project_source_changed_error());
    }
    Ok(())
}

fn complete_journal_after_user_delete(
    connection: &mut Connection,
    deletion_id: &str,
    completed_at_unix: u64,
) -> Result<(), PrivacyWorkflowError> {
    if completed_at_unix == 0 {
        return Err(project_deletion_journal_error());
    }
    let timestamp = sql_i64(completed_at_unix)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| project_deletion_journal_error())?;
    let state = transaction
        .query_row(
            "SELECT state FROM project_deletion_journal WHERE deletion_id=?1",
            [deletion_id],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| project_deletion_journal_error())?;
    match JournalState::parse(&state)? {
        JournalState::PrivacyRevoked => {
            let changed = transaction
                .execute(
                    "UPDATE project_deletion_journal
                     SET state='user_deleted',user_deleted_at_unix=?2
                     WHERE deletion_id=?1 AND state='privacy_revoked'",
                    params![deletion_id, timestamp],
                )
                .map_err(|_| project_deletion_journal_error())?;
            if changed != 1 {
                return Err(project_deletion_journal_error());
            }
        }
        JournalState::UserDeleted => {}
        JournalState::Completed => {
            transaction
                .commit()
                .map_err(|_| project_deletion_journal_error())?;
            return Ok(());
        }
        JournalState::Prepared => return Err(project_deletion_journal_error()),
    }
    let changed = transaction
        .execute(
            "UPDATE project_deletion_journal
             SET state='completed',completed_at_unix=?2
             WHERE deletion_id=?1 AND state='user_deleted'",
            params![deletion_id, timestamp],
        )
        .map_err(|_| project_deletion_journal_error())?;
    if changed != 1 {
        return Err(project_deletion_journal_error());
    }
    transaction
        .commit()
        .map_err(|_| project_deletion_journal_error())
}

fn pending_project_ids(connection: &Connection) -> Result<Vec<ProjectId>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT project_id FROM project_deletion_journal
             WHERE state<>'completed' ORDER BY created_at_unix,deletion_id",
        )
        .map_err(|_| project_deletion_journal_error())?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| project_deletion_journal_error())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| project_deletion_journal_error())?
        .into_iter()
        .map(|value| ProjectId::parse(value).map_err(PrivacyWorkflowError::project_case_binding))
        .collect()
}

fn collect_ids(
    connection: &Connection,
    query: &str,
    project_id: &str,
) -> Result<BTreeSet<String>, PrivacyWorkflowError> {
    let mut statement = connection.prepare(query).map_err(|_| scope_error())?;
    let rows = statement
        .query_map([project_id], |row| row.get::<_, String>(0))
        .map_err(|_| scope_error())?;
    rows.collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| scope_error())
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_str() < pair[1].as_str())
}

fn valid_scope_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn sql_i64(value: u64) -> Result<i64, PrivacyWorkflowError> {
    i64::try_from(value).map_err(|_| project_deletion_journal_error())
}

fn project_deletion_journal_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_project_deletion_journal_invalid",
        "The durable case-project deletion journal is unavailable or inconsistent.",
    )
}

fn project_source_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_material_source_unavailable",
        "The canonical case database could not be locked for lifecycle deletion.",
    )
}

fn project_source_changed_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_project_deletion_scope_changed",
        "The case project material scope changed after deletion was prepared.",
    )
}

fn scope_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_project_privacy_scope_invalid",
        "The case project Privacy/Vault scope is incomplete or inconsistent.",
    )
}

fn retention_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "retention_binding_unavailable",
        "Every case-project generation must have a valid retention binding before deletion.",
    )
}

fn external_lifecycle_unavailable_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "approved_publication_invalidation_unavailable",
        "Approved publications and derived work products cannot be verified for revocation.",
    )
}

fn external_lifecycle_error(_code: &'static str) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "approved_publication_invalidation_failed",
        "Approved publications or derived work products could not be revoked.",
    )
}

fn project_id_retired_error() -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        "case_project_id_retired",
        "This case project identifier is permanently retired by Privacy lifecycle history.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_workflow::ApprovedPublicationInvalidator;
    use privacy::vnext::{CaseId, MaterialId};
    use privacy::{
        ApproveReviewWithRiskRevision, ApprovedCasePageV1, ApprovedCasePayloadV1, PrivacyStore,
        SaveRiskReviewRevision, APPROVED_CASE_PAYLOAD_SCHEMA_VERSION,
    };
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    const PROJECT_ID: &str = "case-project-delete-test";
    const PRIVACY_CASE_ID: &str = "case_11111111111111111111111111111111";
    const MATERIAL_ID: &str = "mat_22222222222222222222222222222222";
    const REDACTION_ID: &str = "red_33333333333333333333333333333333";
    const LEGACY_REDACTION_ID: &str = "red_77777777777777777777777777777777";
    const RECEIPT_ID: &str = "rcpt_44444444444444444444444444444444";
    const OUTPUT_ID: &str = "out_55555555555555555555555555555555";

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureRedactedContent<'a> {
        schema_version: u16,
        pages: &'a [ApprovedCasePageV1],
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum InvalidationCall {
        Case(String),
        Lifecycle(BTreeSet<String>),
    }

    #[derive(Default)]
    struct RecordingInvalidator {
        calls: Mutex<Vec<InvalidationCall>>,
        fail_lifecycle_once: Mutex<bool>,
    }

    impl RecordingInvalidator {
        fn fail_next_lifecycle(&self) {
            *self.fail_lifecycle_once.lock().expect("failure lock") = true;
        }

        fn calls(&self) -> Vec<InvalidationCall> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl ApprovedPublicationInvalidator for RecordingInvalidator {
        fn invalidate_case(
            &self,
            case_id: &CaseId,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(InvalidationCall::Case(case_id.as_str().to_owned()));
            Ok(1)
        }

        fn invalidate_material(
            &self,
            _case_id: &CaseId,
            _material_id: &MaterialId,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_all(&self, _reason_code: &'static str) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_lifecycle_bindings(
            &self,
            lifecycle_binding_ids: &BTreeSet<String>,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            self.calls
                .lock()
                .expect("calls lock")
                .push(InvalidationCall::Lifecycle(lifecycle_binding_ids.clone()));
            let mut fail = self.fail_lifecycle_once.lock().expect("failure lock");
            if *fail {
                *fail = false;
                Err("synthetic_lifecycle_invalidation_failure")
            } else {
                Ok(u64::try_from(lifecycle_binding_ids.len()).expect("small fixture"))
            }
        }
    }

    struct Fixture {
        _directory: TempDir,
        manager: PrivacyWorkflowManager,
        invalidator: Arc<RecordingInvalidator>,
        user_database_path: std::path::PathBuf,
        privacy_database_path: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("fixture directory");
            let user_database_path =
                database::ensure_user_database(directory.path()).expect("user database");
            let invalidator = Arc::new(RecordingInvalidator::default());
            let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
                directory.path().to_path_buf(),
                super::super::test_workspace_instance_id(),
                invalidator.clone(),
            )
            .expect("privacy manager");
            let privacy_database_path = directory
                .path()
                .join(super::super::PRIVACY_DIRECTORY_NAME)
                .join(super::super::PRIVACY_DATABASE_NAME);
            let fixture = Self {
                _directory: directory,
                manager,
                invalidator,
                user_database_path,
                privacy_database_path,
            };
            fixture.seed();
            fixture
        }

        fn seed(&self) {
            let user =
                database::open_user_database(&self.user_database_path).expect("open user database");
            database::upsert_case_project(
                &user,
                &database::CaseProjectRow {
                    project_id: PROJECT_ID.to_owned(),
                    title: "Deletion lifecycle fixture".to_owned(),
                    case_type: "civil".to_owned(),
                    status: "active".to_owned(),
                    opened_on: None,
                    summary: String::new(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )
            .expect("insert project");
            drop(user);

            let mut privacy =
                Connection::open(&self.privacy_database_path).expect("open privacy database");
            privacy.execute_batch("PRAGMA foreign_keys=ON").expect("fk");
            let project_id = ProjectId::parse(PROJECT_ID).expect("project id");
            let privacy_case_id = PrivacyCaseId::parse(PRIVACY_CASE_ID).expect("privacy case id");
            let binding_context = privacy::BindingLifecycleContext::new(
                privacy::BindingCreationSource::LegacyMigration,
                "audit-project-delete-fixture",
                Some("project-delete-test-v1".to_owned()),
            )
            .expect("binding context");
            ProjectPrivacyCaseBindingStore::bind_existing_for_migration(
                &mut privacy,
                &project_id,
                &privacy_case_id,
                &binding_context,
            )
            .expect("binding");
            privacy
                .execute_batch(
                    "
                    INSERT INTO privacy_materials(
                        material_id,project_id,attachment_id,source_sha256,source_name_sha256,
                        media_type,page_count,source_kind,extraction_status,migration_status,state
                    ) VALUES(
                        'mat_22222222222222222222222222222222',
                        'case-project-delete-test',NULL,
                        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                        'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                        'text/plain',1,'vault','ready','ready','approved'
                    );
                    INSERT INTO privacy_vault_material_refs(
                        material_id,case_id,object_id,object_version,source_sha256,envelope_sha256,
                        content_bytes,retention_expires_at_unix,retention_policy_revision,
                        bound_at_unix,import_state
                    ) VALUES(
                        'mat_22222222222222222222222222222222',
                        'case_11111111111111111111111111111111',
                        'obj_22222222222222222222222222222222',1,
                        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                        32,4102444800,1,1700000000,'review_ready'
                    );
                    ",
                )
                .expect("seed project material fixture");

            let pages = vec![ApprovedCasePageV1 {
                page_number: 1,
                text: "project deletion fixture approved text".to_owned(),
            }];
            let approved_payload = ApprovedCasePayloadV1 {
                schema_version: APPROVED_CASE_PAYLOAD_SCHEMA_VERSION,
                source_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                extraction_sha256:
                    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned(),
                media_type: "text/plain".to_owned(),
                pages,
            };
            let approved_payload_plaintext = approved_payload
                .canonical_bytes()
                .expect("canonical approved projection fixture");
            let approved_payload_sha256 = sha256_hex(&approved_payload_plaintext);
            let redacted_content_sha256 = sha256_hex(
                &serde_json::to_vec(&FixtureRedactedContent {
                    schema_version: APPROVED_CASE_PAYLOAD_SCHEMA_VERSION,
                    pages: &approved_payload.pages,
                })
                .expect("canonical redacted-content fixture"),
            );
            privacy
                .execute(
                    "INSERT INTO privacy_redactions(
                        redaction_id,material_id,generation_number,extraction_sha256,
                        redacted_content_sha256,policy_id,policy_version,detector_version,
                        unresolved_high_risk_count,review_state,protected_review_blob,
                        protection_scheme
                     ) VALUES(?1,?2,1,?3,?4,'policy',1,'detector',0,
                              'review_required',X'01020304',
                              'windows_dpapi_current_user_v1')",
                    params![
                        REDACTION_ID,
                        MATERIAL_ID,
                        approved_payload.extraction_sha256,
                        redacted_content_sha256,
                    ],
                )
                .expect("seed review-required generation");
            let risk_sha256 = sha256_hex(b"project deletion fixture risk");
            let hard_gate_sha256 = sha256_hex(b"project deletion fixture hard gate");
            let reviewer_sha256 = sha256_hex(b"project deletion fixture reviewer");
            let reason_codes = Vec::new();
            PrivacyStore::approve_review_with_risk_revision(
                &mut privacy,
                &ApproveReviewWithRiskRevision {
                    redaction_id: REDACTION_ID,
                    expected_redacted_sha256: &redacted_content_sha256,
                    approved_redacted_content_sha256: &redacted_content_sha256,
                    approved_payload_sha256: &approved_payload_sha256,
                    reviewed_by_sha256: &reviewer_sha256,
                    approved_review_payload_plaintext: b"project deletion fixture full review",
                    approved_payload_plaintext: &approved_payload_plaintext,
                    risk_revision: SaveRiskReviewRevision {
                        redaction_id: REDACTION_ID,
                        expected_previous_revision: 0,
                        risk_sha256: &risk_sha256,
                        hard_gate_sha256: &hard_gate_sha256,
                        action_code: "full_review_approved",
                        reason_codes: &reason_codes,
                        state_plaintext: b"project deletion fixture risk state",
                    },
                },
            )
            .expect("atomically approve safe projection fixture");
            privacy
                .execute_batch(
                    "
                    INSERT INTO privacy_retention_bindings(
                        redaction_id,expires_at_unix,legal_hold,bound_at_unix,policy_revision
                    ) VALUES(
                        'red_33333333333333333333333333333333',4102444800,0,1700000000,1
                    );
                    ",
                )
                .expect("seed retention binding fixture");
            privacy
                .execute(
                    "INSERT INTO privacy_receipts(
                        receipt_id,redaction_id,signed_token,destination_kind,
                        destination_identifier_sha256,purpose,payload_sha256,policy_id,
                        policy_version,issued_at_unix,expires_at_unix
                     ) VALUES(
                        ?1,?2,'signed-fixture','external_mcp_host',
                        '1212121212121212121212121212121212121212121212121212121212121212',
                        'approved-material-read',?3,'policy',1,1700000000,4102444800
                     )",
                    params![RECEIPT_ID, REDACTION_ID, approved_payload_sha256],
                )
                .expect("seed receipt fixture");
            privacy
                .execute(
                    "INSERT INTO case_material_selections(
                        selection_id,project_id,material_id,redaction_id,purpose,
                        selected_by_user,selected_at,selected_generation_number,
                        selected_approved_payload_sha256,selected_risk_revision
                     ) VALUES(
                        'sel_66666666666666666666666666666666',?1,?2,?3,
                        'interactive_case_work',1,CURRENT_TIMESTAMP,1,?4,1
                     )",
                    params![
                        PROJECT_ID,
                        MATERIAL_ID,
                        REDACTION_ID,
                        approved_payload_sha256
                    ],
                )
                .expect("seed exact case-work selection fixture");
            privacy
                .execute(
                    "INSERT INTO privacy_approved_outputs(
                        output_id,redaction_id,approval_generation_id,receipt_id,
                        provider_sha256,model_sha256,purpose_sha256,
                        approved_payload_sha256,content_sha256,content_bytes,
                        protected_content,protection_scheme,created_at_unix,expires_at_unix
                     ) VALUES(
                        ?1,?2,?3,?3,
                        '1313131313131313131313131313131313131313131313131313131313131313',
                        '1414141414141414141414141414141414141414141414141414141414141414',
                        '1515151515151515151515151515151515151515151515151515151515151515',
                        ?4,
                        '1616161616161616161616161616161616161616161616161616161616161616',
                        4,X'01020304','windows_dpapi_current_user_v1',
                        1700000000,4102444800
                     )",
                    params![OUTPUT_ID, REDACTION_ID, RECEIPT_ID, approved_payload_sha256],
                )
                .expect("seed approved output fixture");
        }

        fn user_connection(&self) -> Connection {
            database::open_user_database(&self.user_database_path).expect("open user database")
        }

        fn privacy_connection(&self) -> Connection {
            Connection::open(&self.privacy_database_path).expect("open privacy database")
        }

        fn project_exists(&self) -> bool {
            self.user_connection()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM projects WHERE project_id=?1)",
                    [PROJECT_ID],
                    |row| row.get(0),
                )
                .expect("project existence")
        }
    }

    const CASE_WORK_CONVERSATION_ID: &str = "case-work-delete-conversation";
    const CASE_WORK_RUN_ID: &str = "case-work-delete-run";
    const CASE_WORK_USER_MESSAGE_ID: &str = "case-work-delete-user-message";
    const CASE_WORK_ASSISTANT_MESSAGE_ID: &str = "case-work-delete-assistant-message";
    const CASE_WORK_TOOL_CALL_ID: &str = "case-work-delete-tool-call";
    const CASE_WORK_PENDING_OUTPUT_ID: &str = "case-work-delete-pending-output";
    const CASE_WORK_PROPOSAL_ID: &str = "case-work-delete-proposal";
    const CASE_WORK_ARTIFACT_ID: &str = "case-work-delete-artifact";
    const ASSISTANT_CONVERSATION_ID: &str = "assistant-delete-preserved";
    const ASSISTANT_MESSAGE_ID: &str = "assistant-delete-preserved-message";

    #[derive(Clone, Copy)]
    enum CaseWorkDeletionVariant {
        Empty,
        Pending,
        ConfirmedProposal,
        ConfirmedArtifact,
    }

    fn case_work_source_snapshots_json() -> String {
        serde_json::to_string(&serde_json::json!([{
            "approvedPayloadSha256": "1".repeat(64),
            "extractionSha256": "2".repeat(64),
            "generationId": "generation-one",
            "generationNumber": 1,
            "generationRowVersion": 1,
            "materialId": MATERIAL_ID,
            "ordinal": 0,
            "redactedContentSha256": "3".repeat(64),
            "riskRevision": 1,
            "riskRevisionHash": "4".repeat(64),
            "selectionId": "selection-one",
            "selectionRowVersion": 1
        }]))
        .expect("case-work source snapshots serialize")
    }

    fn case_work_output_payload_json(output_kind: &str) -> String {
        let content = if output_kind == "case_analysis" {
            serde_json::json!({"changes": []})
        } else {
            serde_json::json!({"body": "case-work deletion fixture"})
        };
        serde_json::to_string(&serde_json::json!({
            "content": content,
            "outputKind": output_kind,
            "schemaVersion": 1
        }))
        .expect("case-work output serializes")
    }

    fn case_work_provider_snapshot_json() -> String {
        serde_json::to_string(&serde_json::json!({
            "kind": "deep_seek",
            "modelId": "test-model",
            "baseUrl": "https://api.example.invalid/v1",
            "capabilities": {
                "chat": true,
                "streaming": true,
                "customModelId": true,
                "customBaseUrl": true,
                "reasoning": true,
            },
            "options": {
                "thinking": false,
                "enableThinking": null,
                "thinkingBudget": null,
                "reasoningEffort": null,
                "endpointId": null,
                "workspaceId": null,
                "allowPrivateNetwork": false,
            },
        }))
        .expect("case-work provider snapshot serializes")
    }

    fn seed_case_work_deletion_variant(fixture: &Fixture, variant: CaseWorkDeletionVariant) {
        let mut user = fixture.user_connection();
        database::create_conversation(
            &user,
            ASSISTANT_CONVERSATION_ID,
            Some(PROJECT_ID),
            "Preserved assistant history",
        )
        .expect("assistant conversation creates");
        database::create_message(
            &user,
            &database::NewMessageRow {
                message_id: ASSISTANT_MESSAGE_ID.to_owned(),
                conversation_id: ASSISTANT_CONVERSATION_ID.to_owned(),
                role: "user".to_owned(),
                kind: "text".to_owned(),
                text_summary: "preserve ordinary assistant history".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("assistant message creates");
        database::create_case_work_conversation(
            &user,
            CASE_WORK_CONVERSATION_ID,
            PROJECT_ID,
            "Case-work deletion fixture",
        )
        .expect("case-work conversation creates");
        if matches!(variant, CaseWorkDeletionVariant::Empty) {
            return;
        }
        let workspace_base_digest = database::case_workspace_digest(&user, PROJECT_ID)
            .expect("workspace digest computes")
            .expect("project exists");
        let output_kind = if matches!(variant, CaseWorkDeletionVariant::ConfirmedProposal) {
            "case_analysis"
        } else {
            "case_document"
        };
        let snapshots = case_work_source_snapshots_json();
        let source_snapshots_sha256 = sha256_hex(snapshots.as_bytes());
        let output_payload = case_work_output_payload_json(output_kind);
        let output_sha256 = sha256_hex(output_payload.as_bytes());
        let provider_snapshot_json = case_work_provider_snapshot_json();
        let provider_snapshot = serde_json::from_str::<serde_json::Value>(&provider_snapshot_json)
            .expect("case-work provider snapshot parses");
        let generation_ids = vec!["generation-one"];
        let input_audit_json = serde_json::to_string(&serde_json::json!({
            "requestId": CASE_WORK_RUN_ID,
            "runId": CASE_WORK_RUN_ID,
            "capability": "assistant.case_work",
            "classification": "case_redacted_approved",
            "inputIds": {
                "projectId": PROJECT_ID,
                "conversationId": CASE_WORK_CONVERSATION_ID,
                "redactionGenerationIds": generation_ids,
            },
            "inputHashes": {
                "promptSha256": "1".repeat(64),
                "historySha256": "2".repeat(64),
                "minimalContextSha256": "3".repeat(64),
                "generationSetSha256": "4".repeat(64),
                "workspaceDigest": workspace_base_digest,
            },
            "inputCounts": {
                "promptBytes": 1,
                "historyMessages": 0,
                "historyBytes": 0,
                "generationCount": 1,
                "knownBodyBytes": 1,
            },
            "providerSnapshot": provider_snapshot,
            "confirmation": {
                "writebackRequired": true,
                "received": false,
            },
            "status": "running",
        }))
        .expect("case-work input audit serializes");
        let output_audit_json = serde_json::to_string(&serde_json::json!({
            "outputIds": {"pendingOutputKind": output_kind},
            "outputHashes": {
                "providerOutputSha256": "5".repeat(64),
                "typedOutputSha256": output_sha256,
                "approvedEnvelopeSha256": "6".repeat(64),
                "proposalSourceRefsSha256": sha256_hex(b"[]"),
            },
            "outputCounts": {
                "approvedEnvelopeBytes": 1,
                "bytes": 1,
                "items": 1,
            },
            "status": "succeeded",
            "confirmation": {
                "writebackRequired": true,
                "received": false,
            },
        }))
        .expect("case-work output audit serializes");
        let source_audit_json = serde_json::to_string(&serde_json::json!({
            "classification": "case_redacted_approved",
            "sourceRefs": generation_ids,
            "inputHashes": {
                "projectBindingSha256": "a".repeat(64),
                "sourceSnapshotsSha256": source_snapshots_sha256,
                "aggregateSourceSha256": "7".repeat(64),
                "aggregateExtractionSha256": "8".repeat(64),
                "aggregateRedactedContentSha256": "9".repeat(64),
            },
            "providerSnapshot": provider_snapshot,
            "confirmation": {
                "writebackRequired": true,
                "received": false,
            },
        }))
        .expect("case-work source audit serializes");

        database::create_message(
            &user,
            &database::NewMessageRow {
                message_id: CASE_WORK_USER_MESSAGE_ID.to_owned(),
                conversation_id: CASE_WORK_CONVERSATION_ID.to_owned(),
                role: "user".to_owned(),
                kind: "text".to_owned(),
                text_summary: "case-work question".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("case-work user message creates");
        database::create_agent_run(
            &user,
            &database::NewAgentRunRow {
                run_id: CASE_WORK_RUN_ID.to_owned(),
                conversation_id: CASE_WORK_CONVERSATION_ID.to_owned(),
                user_message_id: CASE_WORK_USER_MESSAGE_ID.to_owned(),
                provider_id: None,
                provider_snapshot_json: provider_snapshot_json.clone(),
                intent: "interactive_case_work".to_owned(),
                status: "running".to_owned(),
                budget_json: "{}".to_owned(),
            },
        )
        .expect("case-work run creates");
        database::create_tool_call(
            &user,
            &database::NewToolCallRow {
                tool_call_id: CASE_WORK_TOOL_CALL_ID.to_owned(),
                run_id: CASE_WORK_RUN_ID.to_owned(),
                ordinal: 0,
                capability_name: "assistant.case_work".to_owned(),
                status: "running".to_owned(),
                access_mode: "write".to_owned(),
                requires_confirmation: false,
                input_audit_json,
                output_audit_json: "{}".to_owned(),
                source_audit_json: "{}".to_owned(),
            },
        )
        .expect("case-work tool audit creates");
        database::create_message(
            &user,
            &database::NewMessageRow {
                message_id: CASE_WORK_ASSISTANT_MESSAGE_ID.to_owned(),
                conversation_id: CASE_WORK_CONVERSATION_ID.to_owned(),
                role: "assistant".to_owned(),
                kind: "text".to_owned(),
                text_summary: "case-work response".to_owned(),
                artifact_id: None,
                run_id: Some(CASE_WORK_RUN_ID.to_owned()),
            },
        )
        .expect("case-work assistant message creates");
        assert!(matches!(
            database::compare_and_set_tool_call_status(
                &user,
                CASE_WORK_TOOL_CALL_ID,
                "running",
                "succeeded",
                &output_audit_json,
                &source_audit_json,
                None,
            )
            .expect("case-work tool audit succeeds"),
            database::ToolCallStatusUpdateResult::Updated(_)
        ));
        assert!(matches!(
            database::compare_and_set_agent_run_status(
                &user,
                CASE_WORK_RUN_ID,
                "running",
                "succeeded",
                Some(CASE_WORK_ASSISTANT_MESSAGE_ID),
                None,
            )
            .expect("case-work run succeeds"),
            database::AgentRunStatusUpdateResult::Updated(_)
        ));
        let pending = database::NewCaseAssistantPendingOutputRow {
            pending_output_id: CASE_WORK_PENDING_OUTPUT_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            conversation_id: CASE_WORK_CONVERSATION_ID.to_owned(),
            run_id: CASE_WORK_RUN_ID.to_owned(),
            assistant_message_id: CASE_WORK_ASSISTANT_MESSAGE_ID.to_owned(),
            project_binding_sha256: "a".repeat(64),
            source_snapshots_sha256,
            source_snapshots_json: snapshots,
            expected_proposal_source_refs_json: "[]".to_owned(),
            expected_proposal_source_refs_sha256: sha256_hex(b"[]"),
            output_kind: output_kind.to_owned(),
            output_sha256,
            output_payload_json: output_payload,
            output_preview: "case-work response".to_owned(),
            output_version: 1,
            workspace_base_digest: workspace_base_digest.clone(),
        };
        database::create_case_assistant_pending_output(&user, &pending)
            .expect("case-work pending output creates");

        match variant {
            CaseWorkDeletionVariant::Empty | CaseWorkDeletionVariant::Pending => {}
            CaseWorkDeletionVariant::ConfirmedProposal => {
                let transaction = user
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .expect("proposal confirmation transaction begins");
                database::create_case_change_proposal(
                    &transaction,
                    &database::NewCaseChangeProposalRow {
                        proposal_id: CASE_WORK_PROPOSAL_ID.to_owned(),
                        conversation_id: CASE_WORK_CONVERSATION_ID.to_owned(),
                        project_id: PROJECT_ID.to_owned(),
                        run_id: Some(CASE_WORK_RUN_ID.to_owned()),
                        base_case_digest: workspace_base_digest.clone(),
                        changes_json: r#"{"changes":[]}"#.to_owned(),
                        source_refs_json: "[]".to_owned(),
                    },
                )
                .expect("case-work proposal creates");
                assert!(matches!(
                    database::compare_and_set_case_change_proposal_status(
                        &transaction,
                        CASE_WORK_PROPOSAL_ID,
                        PROJECT_ID,
                        &workspace_base_digest,
                        "applied",
                    )
                    .expect("case-work proposal applies"),
                    database::CaseChangeProposalStatusUpdateResult::Updated(_)
                ));
                let target = database::CaseAssistantConfirmationTarget::Proposal(
                    CASE_WORK_PROPOSAL_ID.to_owned(),
                );
                assert!(matches!(
                    database::compare_and_set_case_assistant_pending_output_confirmed(
                        &transaction,
                        &database::ConfirmCaseAssistantPendingOutput {
                            pending_output_id: CASE_WORK_PENDING_OUTPUT_ID,
                            project_id: PROJECT_ID,
                            expected_output_version: 1,
                            expected_output_sha256: &pending.output_sha256,
                            expected_workspace_base_digest: &workspace_base_digest,
                            expected_proposal_source_refs_json: &pending
                                .expected_proposal_source_refs_json,
                            expected_proposal_source_refs_sha256: &pending
                                .expected_proposal_source_refs_sha256,
                            confirmation_request_sha256: &"b".repeat(64),
                            target: &target,
                        },
                    )
                    .expect("proposal confirmation succeeds"),
                    database::CaseAssistantPendingOutputConfirmResult::Confirmed(_)
                ));
                transaction.commit().expect("proposal confirmation commits");
            }
            CaseWorkDeletionVariant::ConfirmedArtifact => {
                let transaction = user
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .expect("artifact confirmation transaction begins");
                database::create_artifact(
                    &transaction,
                    &database::NewArtifactRow {
                        artifact_id: CASE_WORK_ARTIFACT_ID.to_owned(),
                        conversation_id: Some(CASE_WORK_CONVERSATION_ID.to_owned()),
                        project_id: None,
                        kind: "document".to_owned(),
                        title: "Confirmed case-work artifact".to_owned(),
                        status: "draft".to_owned(),
                    },
                    &database::NewArtifactVersionRow {
                        version_id: format!("{CASE_WORK_ARTIFACT_ID}-v1"),
                        artifact_id: CASE_WORK_ARTIFACT_ID.to_owned(),
                        content_json: r#"{"body":"case-work deletion fixture"}"#.to_owned(),
                        rendered_text: pending.output_preview.clone(),
                        source_refs_json: "[]".to_owned(),
                        citation_report_json: "{}".to_owned(),
                        provider_snapshot_json: provider_snapshot_json.clone(),
                    },
                )
                .expect("case-work artifact creates");
                assert!(database::bind_artifact_to_case(
                    &transaction,
                    CASE_WORK_ARTIFACT_ID,
                    PROJECT_ID,
                )
                .expect("case-work artifact binds"));
                let target = database::CaseAssistantConfirmationTarget::Artifact(
                    CASE_WORK_ARTIFACT_ID.to_owned(),
                );
                assert!(matches!(
                    database::compare_and_set_case_assistant_pending_output_confirmed(
                        &transaction,
                        &database::ConfirmCaseAssistantPendingOutput {
                            pending_output_id: CASE_WORK_PENDING_OUTPUT_ID,
                            project_id: PROJECT_ID,
                            expected_output_version: 1,
                            expected_output_sha256: &pending.output_sha256,
                            expected_workspace_base_digest: &workspace_base_digest,
                            expected_proposal_source_refs_json: &pending
                                .expected_proposal_source_refs_json,
                            expected_proposal_source_refs_sha256: &pending
                                .expected_proposal_source_refs_sha256,
                            confirmation_request_sha256: &"c".repeat(64),
                            target: &target,
                        },
                    )
                    .expect("artifact confirmation succeeds"),
                    database::CaseAssistantPendingOutputConfirmResult::Confirmed(_)
                ));
                transaction.commit().expect("artifact confirmation commits");
            }
        }
    }

    fn assert_case_work_variant_deletes_without_split(variant: CaseWorkDeletionVariant) {
        let fixture = Fixture::new();
        seed_case_work_deletion_variant(&fixture, variant);
        let mut user = fixture.user_connection();
        assert!(fixture
            .manager
            .delete_case_project_lifecycle(&mut user, PROJECT_ID)
            .expect("case-work project lifecycle deletes"));
        drop(user);

        let privacy = fixture.privacy_connection();
        let (deletion_id, journal_state, material_state, generation_state) = privacy
            .query_row(
                "SELECT
                     (SELECT deletion_id FROM project_deletion_journal WHERE project_id=?1),
                     (SELECT state FROM project_deletion_journal WHERE project_id=?1),
                     (SELECT state FROM privacy_materials WHERE material_id=?2),
                     (SELECT revocation_state FROM privacy_redactions WHERE redaction_id=?3)",
                params![PROJECT_ID, MATERIAL_ID, REDACTION_ID],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .expect("Privacy deletion state reads");
        assert_eq!(journal_state, "completed");
        assert_eq!(material_state, "revoked");
        assert_eq!(generation_state, "revoked");
        drop(privacy);

        let user = fixture.user_connection();
        assert_eq!(
            user.query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id=?1",
                [PROJECT_ID],
                |row| row.get::<_, i64>(0),
            )
            .expect("project count reads"),
            0
        );
        assert_eq!(
            user.query_row(
                "SELECT retirement_reason,privacy_deletion_id
                 FROM retired_case_project_ids WHERE project_id=?1",
                [PROJECT_ID],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .expect("retirement tombstone reads"),
            ("case_project_deleted".to_owned(), deletion_id)
        );
        for (table, column, id) in [
            (
                "conversations",
                "conversation_id",
                CASE_WORK_CONVERSATION_ID,
            ),
            ("agent_runs", "run_id", CASE_WORK_RUN_ID),
            ("messages", "conversation_id", CASE_WORK_CONVERSATION_ID),
            ("tool_calls", "run_id", CASE_WORK_RUN_ID),
            (
                "case_change_proposals",
                "proposal_id",
                CASE_WORK_PROPOSAL_ID,
            ),
            ("artifacts", "artifact_id", CASE_WORK_ARTIFACT_ID),
        ] {
            assert_eq!(
                user.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1"),
                    [id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("live case-work lineage count reads"),
                0,
                "{table} live lineage must be physically removed"
            );
        }
        assert_eq!(
            user.query_row(
                "SELECT project_id FROM conversations WHERE conversation_id=?1",
                [ASSISTANT_CONVERSATION_ID],
                |row| row.get::<_, Option<String>>(0),
            )
            .expect("ordinary assistant history remains"),
            None
        );
        assert_eq!(
            user.query_row(
                "SELECT COUNT(*) FROM messages WHERE message_id=?1",
                [ASSISTANT_MESSAGE_ID],
                |row| row.get::<_, i64>(0),
            )
            .expect("ordinary assistant message count reads"),
            1
        );

        if matches!(variant, CaseWorkDeletionVariant::Empty) {
            assert_eq!(
                user.query_row(
                    "SELECT COUNT(*) FROM case_assistant_pending_outputs",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("empty pending audit count reads"),
                0
            );
        } else {
            let audit = database::get_case_assistant_pending_output(
                &user,
                CASE_WORK_PENDING_OUTPUT_ID,
                PROJECT_ID,
            )
            .expect("retired pending audit reads")
            .expect("retired pending audit remains");
            match variant {
                CaseWorkDeletionVariant::Pending => {
                    assert_eq!(audit.status, "pending");
                    assert_eq!(audit.row_version, 1);
                }
                CaseWorkDeletionVariant::ConfirmedProposal => {
                    assert_eq!(audit.status, "confirmed");
                    assert_eq!(
                        audit.confirmed_proposal_id.as_deref(),
                        Some(CASE_WORK_PROPOSAL_ID)
                    );
                }
                CaseWorkDeletionVariant::ConfirmedArtifact => {
                    assert_eq!(audit.status, "confirmed");
                    assert_eq!(
                        audit.confirmed_artifact_id.as_deref(),
                        Some(CASE_WORK_ARTIFACT_ID)
                    );
                }
                CaseWorkDeletionVariant::Empty => unreachable!(),
            }
        }
        database::validate_open_user_database(&user)
            .expect("deleted case-work variant remains canonical");
    }

    #[test]
    fn project_delete_handles_empty_case_work_without_cross_database_split() {
        assert_case_work_variant_deletes_without_split(CaseWorkDeletionVariant::Empty);
    }

    #[test]
    fn project_delete_handles_pending_output_without_cross_database_split() {
        assert_case_work_variant_deletes_without_split(CaseWorkDeletionVariant::Pending);
    }

    #[test]
    fn project_delete_handles_confirmed_proposal_without_cross_database_split() {
        assert_case_work_variant_deletes_without_split(CaseWorkDeletionVariant::ConfirmedProposal);
    }

    #[test]
    fn project_delete_handles_confirmed_artifact_without_cross_database_split() {
        assert_case_work_variant_deletes_without_split(CaseWorkDeletionVariant::ConfirmedArtifact);
    }

    #[test]
    fn project_delete_revokes_every_live_capability_before_user_project() {
        let fixture = Fixture::new();
        let mut user = fixture.user_connection();
        assert!(fixture
            .manager
            .delete_case_project_lifecycle(&mut user, PROJECT_ID)
            .expect("delete project"));
        assert!(!fixture.project_exists());

        let privacy = fixture.privacy_connection();
        let state = privacy
            .query_row(
                "SELECT
                   (SELECT state FROM project_deletion_journal WHERE project_id=?1),
                   (SELECT state FROM privacy_materials WHERE material_id=?2),
                   (SELECT deleted_at IS NOT NULL FROM privacy_materials WHERE material_id=?2),
                   (SELECT revocation_state FROM privacy_redactions WHERE redaction_id=?3),
                   (SELECT revoked_at_unix IS NOT NULL FROM privacy_receipts WHERE receipt_id=?4),
                   (SELECT invalidated_at IS NOT NULL FROM case_material_selections
                    WHERE project_id=?1),
                   (SELECT revoked_at_unix IS NOT NULL FROM privacy_approved_outputs
                    WHERE output_id=?5),
                   (SELECT import_state FROM privacy_vault_material_refs WHERE material_id=?2)",
                params![PROJECT_ID, MATERIAL_ID, REDACTION_ID, RECEIPT_ID, OUTPUT_ID],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, bool>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, bool>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .expect("revocation state");
        assert_eq!(
            state,
            (
                "completed".to_owned(),
                "revoked".to_owned(),
                true,
                "revoked".to_owned(),
                true,
                true,
                true,
                "revoked".to_owned(),
            )
        );
        assert!(fixture
            .invalidator
            .calls()
            .contains(&InvalidationCall::Case(PRIVACY_CASE_ID.to_owned())));
        assert!(fixture
            .invalidator
            .calls()
            .contains(&InvalidationCall::Lifecycle(BTreeSet::from([
                REDACTION_ID.to_owned()
            ]))));
    }

    #[test]
    fn project_delete_with_any_legal_hold_has_zero_business_state_change() {
        let fixture = Fixture::new();
        let privacy = fixture.privacy_connection();
        privacy
            .execute(
                "UPDATE privacy_retention_bindings SET legal_hold=1
                 WHERE redaction_id=?1",
                [REDACTION_ID],
            )
            .expect("enable legal hold");
        let before: (i64, String, String, Option<i64>, Option<String>, i64) = privacy
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM project_deletion_journal),
                   (SELECT state FROM privacy_materials WHERE material_id=?1),
                   (SELECT revocation_state FROM privacy_redactions WHERE redaction_id=?2),
                   (SELECT revoked_at_unix FROM privacy_receipts WHERE receipt_id=?3),
                   (SELECT invalidated_at FROM case_material_selections WHERE project_id=?4),
                   (SELECT COUNT(*) FROM privacy_approved_outputs
                    WHERE output_id=?5 AND revoked_at_unix IS NULL)",
                params![MATERIAL_ID, REDACTION_ID, RECEIPT_ID, PROJECT_ID, OUTPUT_ID],
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
            .expect("before state");
        drop(privacy);

        let error = fixture
            .manager
            .delete_case_project_lifecycle(&mut fixture.user_connection(), PROJECT_ID)
            .expect_err("legal hold blocks whole project deletion");
        assert_eq!(error.code(), "legal_hold_active");
        assert!(fixture.project_exists());
        assert!(fixture.invalidator.calls().is_empty());

        let after = fixture
            .privacy_connection()
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM project_deletion_journal),
                   (SELECT state FROM privacy_materials WHERE material_id=?1),
                   (SELECT revocation_state FROM privacy_redactions WHERE redaction_id=?2),
                   (SELECT revoked_at_unix FROM privacy_receipts WHERE receipt_id=?3),
                   (SELECT invalidated_at FROM case_material_selections WHERE project_id=?4),
                   (SELECT COUNT(*) FROM privacy_approved_outputs
                    WHERE output_id=?5 AND revoked_at_unix IS NULL)",
                params![MATERIAL_ID, REDACTION_ID, RECEIPT_ID, PROJECT_ID, OUTPUT_ID],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .expect("after state");
        assert_eq!(after, before);
    }

    #[test]
    fn failed_external_invalidation_keeps_project_and_restart_recovers_journal() {
        let fixture = Fixture::new();
        fixture.invalidator.fail_next_lifecycle();
        let error = fixture
            .manager
            .delete_case_project_lifecycle(&mut fixture.user_connection(), PROJECT_ID)
            .expect_err("synthetic external failure");
        assert_eq!(error.code(), "approved_publication_invalidation_failed");
        assert!(fixture.project_exists());
        let privacy = fixture.privacy_connection();
        assert_eq!(
            privacy
                .query_row(
                    "SELECT state FROM project_deletion_journal WHERE project_id=?1",
                    [PROJECT_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("prepared journal"),
            "prepared"
        );
        assert_eq!(
            privacy
                .query_row(
                    "SELECT revocation_state FROM privacy_redactions WHERE redaction_id=?1",
                    [REDACTION_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("generation state"),
            "active"
        );
        let pending_error = ensure_project_accepts_privacy_writes(
            &privacy,
            &ProjectId::parse(PROJECT_ID).expect("project id"),
        )
        .expect_err("prepared deletion blocks new Privacy material");
        assert_eq!(pending_error.code(), "case_project_deletion_pending");
        drop(privacy);

        let restarted = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            fixture._directory.path().to_path_buf(),
            super::super::test_workspace_instance_id(),
            fixture.invalidator.clone(),
        )
        .expect("startup resumes project deletion");
        drop(restarted);
        assert!(!fixture.project_exists());
        assert_eq!(
            fixture
                .privacy_connection()
                .query_row(
                    "SELECT state FROM project_deletion_journal WHERE project_id=?1",
                    [PROJECT_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("completed journal"),
            "completed"
        );
    }

    #[test]
    fn crash_after_privacy_commit_never_deletes_user_before_revocation_and_recovers() {
        let fixture = Fixture::new();
        let error = fixture
            .manager
            .delete_case_project_with_checkpoint_hook(
                &mut fixture.user_connection(),
                PROJECT_ID,
                |checkpoint| {
                    if checkpoint == ProjectDeletionCheckpoint::PrivacyRevoked {
                        Err(PrivacyWorkflowError::new(
                            "synthetic_crash",
                            "synthetic crash after Privacy commit",
                        ))
                    } else {
                        Ok(())
                    }
                },
            )
            .expect_err("synthetic crash");
        assert_eq!(error.code(), "synthetic_crash");
        assert!(fixture.project_exists());
        let privacy = fixture.privacy_connection();
        assert_eq!(
            privacy
                .query_row(
                    "SELECT state FROM project_deletion_journal WHERE project_id=?1",
                    [PROJECT_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("privacy-revoked journal"),
            "privacy_revoked"
        );
        assert_eq!(
            privacy
                .query_row(
                    "SELECT revocation_state FROM privacy_redactions WHERE redaction_id=?1",
                    [REDACTION_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("generation state"),
            "revoked"
        );
        drop(privacy);

        PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            fixture._directory.path().to_path_buf(),
            super::super::test_workspace_instance_id(),
            fixture.invalidator.clone(),
        )
        .expect("restart finishes user deletion");
        assert!(!fixture.project_exists());
    }

    #[test]
    fn every_persisted_project_deletion_checkpoint_recovers_idempotently_on_restart() {
        for crash_checkpoint in [
            ProjectDeletionCheckpoint::JournalPrepared,
            ProjectDeletionCheckpoint::ExternalInvalidated,
            ProjectDeletionCheckpoint::PrivacyRevoked,
            ProjectDeletionCheckpoint::UserDeleted,
        ] {
            let fixture = Fixture::new();
            let error = fixture
                .manager
                .delete_case_project_with_checkpoint_hook(
                    &mut fixture.user_connection(),
                    PROJECT_ID,
                    |checkpoint| {
                        if checkpoint == crash_checkpoint {
                            Err(PrivacyWorkflowError::new(
                                "synthetic_crash",
                                "synthetic persisted-checkpoint crash",
                            ))
                        } else {
                            Ok(())
                        }
                    },
                )
                .expect_err("synthetic crash checkpoint");
            assert_eq!(error.code(), "synthetic_crash");

            let privacy = fixture.privacy_connection();
            let journal_state = privacy
                .query_row(
                    "SELECT state FROM project_deletion_journal WHERE project_id=?1",
                    [PROJECT_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("journal state at crash");
            let generation_state = privacy
                .query_row(
                    "SELECT revocation_state FROM privacy_redactions WHERE redaction_id=?1",
                    [REDACTION_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("generation state at crash");
            match crash_checkpoint {
                ProjectDeletionCheckpoint::JournalPrepared
                | ProjectDeletionCheckpoint::ExternalInvalidated => {
                    assert_eq!(journal_state, "prepared");
                    assert_eq!(generation_state, "active");
                    assert!(fixture.project_exists());
                }
                ProjectDeletionCheckpoint::PrivacyRevoked => {
                    assert_eq!(journal_state, "privacy_revoked");
                    assert_eq!(generation_state, "revoked");
                    assert!(fixture.project_exists());
                }
                ProjectDeletionCheckpoint::UserDeleted => {
                    assert_eq!(journal_state, "privacy_revoked");
                    assert_eq!(generation_state, "revoked");
                    assert!(!fixture.project_exists());
                }
            }
            drop(privacy);

            PrivacyWorkflowManager::new_with_approved_publication_invalidator(
                fixture._directory.path().to_path_buf(),
                super::super::test_workspace_instance_id(),
                fixture.invalidator.clone(),
            )
            .expect("startup recovers persisted deletion checkpoint");
            assert!(!fixture.project_exists());
            assert_eq!(
                fixture
                    .privacy_connection()
                    .query_row(
                        "SELECT state FROM project_deletion_journal WHERE project_id=?1",
                        [PROJECT_ID],
                        |row| row.get::<_, String>(0),
                    )
                    .expect("completed journal after restart"),
                "completed"
            );
        }
    }

    #[test]
    fn legacy_unknown_time_revocation_is_already_unavailable_and_does_not_block_delete() {
        let fixture = Fixture::new();
        let privacy = fixture.privacy_connection();
        privacy
            .execute_batch(
                "
                INSERT INTO privacy_redactions(
                    redaction_id,material_id,generation_number,generation_status,
                    extraction_sha256,redacted_content_sha256,approved_payload_sha256,
                    policy_id,policy_version,detector_version,unresolved_high_risk_count,
                    review_state,risk_revision,protected_review_blob,protection_scheme,
                    revocation_state,revoked_at
                ) VALUES(
                    'red_77777777777777777777777777777777',
                    'mat_22222222222222222222222222222222',2,'legacy_id',
                    '1717171717171717171717171717171717171717171717171717171717171717',
                    '1818181818181818181818181818181818181818181818181818181818181818',
                    NULL,'legacy-policy',1,'legacy-detector',0,'revoked',0,X'01020304',
                    'windows_dpapi_current_user_v1','revoked_legacy_time_unknown',NULL
                );
                INSERT INTO privacy_retention_bindings(
                    redaction_id,expires_at_unix,legal_hold,bound_at_unix,policy_revision
                ) VALUES(
                    'red_77777777777777777777777777777777',4102444800,0,1700000000,1
                );
                ",
            )
            .expect("insert legacy revoked generation");
        drop(privacy);

        fixture
            .manager
            .delete_case_project_lifecycle(&mut fixture.user_connection(), PROJECT_ID)
            .expect("legacy unavailable generation permits project lifecycle deletion");
        assert!(!fixture.project_exists());
        let privacy = fixture.privacy_connection();
        assert_eq!(
            privacy
                .query_row(
                    "SELECT revocation_state,revoked_at
                     FROM privacy_redactions WHERE redaction_id=?1",
                    [LEGACY_REDACTION_ID],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .expect("legacy revocation state"),
            ("revoked_legacy_time_unknown".to_owned(), None)
        );
    }

    #[test]
    fn privacy_history_without_immutable_binding_blocks_project_delete() {
        let directory = tempfile::tempdir().expect("fixture directory");
        let user_database_path =
            database::ensure_user_database(directory.path()).expect("user database");
        let invalidator = Arc::new(RecordingInvalidator::default());
        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            directory.path().to_path_buf(),
            super::super::test_workspace_instance_id(),
            invalidator,
        )
        .expect("privacy manager");
        let mut user =
            database::open_user_database(&user_database_path).expect("open user database");
        database::upsert_case_project(
            &user,
            &database::CaseProjectRow {
                project_id: "case-unbound-history".to_owned(),
                title: "Unbound history".to_owned(),
                case_type: "civil".to_owned(),
                status: "active".to_owned(),
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .expect("insert project");
        let privacy_database = directory
            .path()
            .join(super::super::PRIVACY_DIRECTORY_NAME)
            .join(super::super::PRIVACY_DATABASE_NAME);
        let privacy = Connection::open(&privacy_database).expect("privacy database");
        privacy
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,legacy_case_id,attachment_id,
                    protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,
                    media_type,page_count,source_kind,extraction_status,migration_status,state
                 ) VALUES(
                    'mat_88888888888888888888888888888888',
                    'case-unbound-history',NULL,NULL,NULL,NULL,NULL,
                    '1919191919191919191919191919191919191919191919191919191919191919',
                    NULL,'text/plain',1,'user_attachment','ready','ready','registered'
                 )",
                [],
            )
            .expect("insert unbound Privacy history");
        drop(privacy);

        let error = manager
            .delete_case_project_lifecycle(&mut user, "case-unbound-history")
            .expect_err("Privacy history without binding is fail closed");
        assert_eq!(error.code(), "case_project_privacy_scope_invalid");
        assert!(
            database::get_case_workspace_rows(&user, "case-unbound-history")
                .expect("project lookup")
                .is_some()
        );
        assert_eq!(
            Connection::open(&privacy_database)
                .expect("privacy database")
                .query_row("SELECT COUNT(*) FROM project_deletion_journal", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("journal count"),
            0
        );
    }

    #[test]
    fn deleted_project_identifier_is_retired_but_existing_project_updates_normally() {
        let fixture = Fixture::new();
        let mut updated = database::CaseProjectRow {
            project_id: PROJECT_ID.to_owned(),
            title: "Updated existing project".to_owned(),
            case_type: "civil".to_owned(),
            status: "active".to_owned(),
            opened_on: None,
            summary: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        fixture
            .manager
            .upsert_case_project_lifecycle(&mut fixture.user_connection(), &updated)
            .expect("existing project update remains valid");
        assert_eq!(
            fixture
                .user_connection()
                .query_row(
                    "SELECT title FROM projects WHERE project_id=?1",
                    [PROJECT_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("updated project"),
            "Updated existing project"
        );

        fixture
            .manager
            .delete_case_project_lifecycle(&mut fixture.user_connection(), PROJECT_ID)
            .expect("delete project");
        updated.title = "Forbidden resurrection".to_owned();
        let error = fixture
            .manager
            .upsert_case_project_lifecycle(&mut fixture.user_connection(), &updated)
            .expect_err("retired project id must not be resurrected");
        assert_eq!(error.code(), "case_project_id_retired");
        assert!(!fixture.project_exists());
        assert_eq!(
            fixture
                .privacy_connection()
                .query_row(
                    "SELECT state FROM project_deletion_journal WHERE project_id=?1",
                    [PROJECT_ID],
                    |row| row.get::<_, String>(0),
                )
                .expect("immutable deletion journal"),
            "completed"
        );

        let privacy = fixture.privacy_connection();
        let deletion_id = privacy
            .query_row(
                "SELECT deletion_id FROM project_deletion_journal WHERE project_id=?1",
                [PROJECT_ID],
                |row| row.get::<_, String>(0),
            )
            .expect("deletion id");
        let replace_project = privacy
            .execute(
                "INSERT OR REPLACE INTO project_deletion_journal(
                    deletion_id,project_id,privacy_case_id,scope_json,scope_sha256,state,
                    created_at_unix,privacy_revoked_at_unix,user_deleted_at_unix,
                    completed_at_unix
                 )
                 SELECT
                    'pdel_replacement',project_id,privacy_case_id,scope_json,scope_sha256,state,
                    created_at_unix,privacy_revoked_at_unix,user_deleted_at_unix,
                    completed_at_unix
                 FROM project_deletion_journal WHERE project_id=?1",
                [PROJECT_ID],
            )
            .expect_err("raw REPLACE cannot replace an occupied project id");
        assert!(replace_project
            .to_string()
            .contains("project deletion journal is append preserving"));
        let replace_deletion_id = privacy
            .execute(
                "INSERT OR REPLACE INTO project_deletion_journal(
                    deletion_id,project_id,privacy_case_id,scope_json,scope_sha256,state,
                    created_at_unix,privacy_revoked_at_unix,user_deleted_at_unix,
                    completed_at_unix
                 )
                 SELECT
                    deletion_id,'case-retired-alias',NULL,scope_json,scope_sha256,state,
                    created_at_unix,privacy_revoked_at_unix,user_deleted_at_unix,
                    completed_at_unix
                 FROM project_deletion_journal WHERE deletion_id=?1",
                [deletion_id],
            )
            .expect_err("raw REPLACE cannot replace an occupied deletion id");
        assert!(replace_deletion_id
            .to_string()
            .contains("project deletion journal is append preserving"));
        let update_completed = privacy
            .execute(
                "UPDATE project_deletion_journal
                 SET scope_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                 WHERE project_id=?1",
                [PROJECT_ID],
            )
            .expect_err("completed journal cannot be mutated");
        assert!(update_completed
            .to_string()
            .contains("project deletion journal transition is invalid"));
        let delete_completed = privacy
            .execute(
                "DELETE FROM project_deletion_journal WHERE project_id=?1",
                [PROJECT_ID],
            )
            .expect_err("completed journal cannot be deleted");
        assert!(delete_completed
            .to_string()
            .contains("project deletion journal is append preserving"));
        assert_eq!(
            privacy
                .query_row("SELECT COUNT(*) FROM project_deletion_journal", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("journal row count"),
            1
        );
    }

    #[test]
    fn initialization_rejects_same_name_noop_journal_guards() {
        let weak_triggers = [
            (
                "trg_project_deletion_journal_no_delete",
                "CREATE TRIGGER trg_project_deletion_journal_no_delete
                 BEFORE DELETE ON project_deletion_journal
                 WHEN 0
                 BEGIN
                     SELECT RAISE(ABORT,'project deletion journal is append preserving');
                 END;",
            ),
            (
                "trg_project_deletion_journal_no_replace",
                "CREATE TRIGGER trg_project_deletion_journal_no_replace
                 BEFORE INSERT ON project_deletion_journal
                 WHEN 0 AND EXISTS(
                     SELECT 1 FROM project_deletion_journal AS existing
                     WHERE existing.deletion_id=NEW.deletion_id
                        OR existing.project_id=NEW.project_id
                 )
                 BEGIN
                     SELECT RAISE(ABORT,'project deletion journal is append preserving');
                 END;",
            ),
            (
                "trg_project_deletion_journal_one_way",
                "CREATE TRIGGER trg_project_deletion_journal_one_way
                 BEFORE UPDATE ON project_deletion_journal
                 WHEN 0 AND (
                     OLD.state='prepared'
                     OR NEW.state='privacy_revoked'
                     OR OLD.state='privacy_revoked'
                     OR NEW.state='user_deleted'
                     OR OLD.state='user_deleted'
                     OR NEW.state='completed'
                 )
                 BEGIN
                     SELECT RAISE(ABORT,'project deletion journal transition is invalid');
                 END;",
            ),
        ];

        for (trigger_name, weak_sql) in weak_triggers {
            let connection = Connection::open_in_memory().expect("open weak journal database");
            initialize_schema(&connection).expect("initialize strong journal schema");
            connection
                .execute_batch(&format!("DROP TRIGGER {trigger_name}; {weak_sql}"))
                .expect("install same-name no-op journal guard");

            let error = initialize_schema(&connection)
                .expect_err("behavior probe must reject same-name no-op journal guard");
            assert_eq!(error.code(), "case_project_deletion_journal_invalid");
        }
    }
}
