use crate::{Error, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rusqlite::{types::Value as SqlValue, Connection, OpenFlags, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    path::Path,
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroizing;

#[cfg(test)]
use std::cell::Cell;

const CHUNK: usize = 4 * 1024 * 1024;
const MAX_OBJECT: usize = 64 * 1024 * 1024;
const SCHEMA_V1: &str = "web-workspace-v1";
const SCHEMA_V2: &str = "web-workspace-v2";
const SCHEMA_V3: &str = "web-workspace-v3";

#[cfg(test)]
thread_local! {
    static PLAINTEXT_DECRYPTIONS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
fn reset_plaintext_decryptions() {
    PLAINTEXT_DECRYPTIONS.with(|count| count.set(0));
}

#[cfg(test)]
fn plaintext_decryptions() -> usize {
    PLAINTEXT_DECRYPTIONS.with(Cell::get)
}

/// The cleartext index deliberately contains only scheduling and relationship
/// fields. Titles, filenames, prompts, source digests and all content stay in
/// the separately protected object or summary blobs.
#[derive(Clone)]
struct ObjectIndex {
    status: Option<String>,
    subkind: Option<String>,
    created_at: u64,
    updated_at: u64,
    group_id: Option<String>,
    task_id: Option<String>,
    conversation_id: Option<String>,
    parent_id: Option<String>,
    material_id: Option<String>,
    result_id: Option<String>,
    revision: Option<u64>,
}

pub(crate) struct StoredRow {
    kind: String,
    id: String,
    body: Vec<u8>,
    index: ObjectIndex,
    summary: Option<Vec<u8>>,
    relations: Vec<(String, String)>,
}

pub(crate) struct SummaryPage {
    pub(crate) items: Vec<Value>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) total: u64,
    pub(crate) corrupt_count: u64,
}

pub(crate) struct Store {
    connection: Mutex<Connection>,
    _lock: File,
}

impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        for legacy in ["user.sqlite", "privacy-workflow.sqlite", "privacy.sqlite"] {
            if root.join(legacy).exists() {
                return Err(Error::new("legacy_workspace_rejected"));
            }
        }
        crate::filesystem::ordinary_chain(root)?;
        let lock_path = root.join("workspace.lock");
        if lock_path.exists() {
            crate::filesystem::ordinary_chain(&lock_path)?;
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.try_lock()
            .map_err(|_| Error::new("workspace_in_use"))?;
        let db = root.join("workspace.sqlite");
        if db.exists() {
            crate::filesystem::ordinary_chain(&db)?;
        }
        let mut connection = Connection::open(db)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; CREATE TABLE IF NOT EXISTS web_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS objects(kind TEXT NOT NULL,id TEXT NOT NULL,body BLOB NOT NULL,PRIMARY KEY(kind,id)); INSERT OR IGNORE INTO web_metadata VALUES('schema','web-workspace-v1');")?;
        let mut schema: String = connection.query_row(
            "SELECT value FROM web_metadata WHERE key='schema'",
            [],
            |r| r.get(0),
        )?;
        if ![SCHEMA_V1, SCHEMA_V2, SCHEMA_V3].contains(&schema.as_str()) {
            return Err(Error::new("unsupported_workspace_schema"));
        }
        let migrated_from_v1 = schema == SCHEMA_V1;
        if migrated_from_v1 {
            let count: i64 =
                connection.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
            if count > 0 {
                create_v1_backup(&connection, root)?;
            }
            connection.execute_batch("BEGIN IMMEDIATE; UPDATE web_metadata SET value='web-workspace-v2' WHERE key='schema'; COMMIT;")?;
            schema = SCHEMA_V2.into();
        }
        if schema == SCHEMA_V2 {
            let count: i64 =
                connection.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
            // A v1 backup taken immediately above already preserves the same
            // logical rows. Existing v2 workspaces always receive their own
            // verified pre-index backup before mutation.
            if count > 0 && !migrated_from_v1 {
                create_v2_backup(&connection, root)?;
            }
            migrate_v2_to_v3(&mut connection)?;
        } else {
            create_v3_tables(&connection)?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
            _lock: lock,
        })
    }
    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| Error::new("storage_unavailable"))
    }
    pub fn get<T: DeserializeOwned>(&self, kind: &str, id: &str) -> Result<T> {
        let bytes = self.raw(kind, id)?;
        match serde_json::from_slice(&bytes) {
            Ok(value) => Ok(value),
            Err(_) => {
                self.quarantine(kind, id, "object_json_invalid")?;
                Err(Error::new("storage_object_corrupt"))
            }
        }
    }
    pub fn maybe<T: DeserializeOwned>(&self, kind: &str, id: &str) -> Result<Option<T>> {
        match self.get(kind, id) {
            Ok(x) => Ok(Some(x)),
            Err(e) if e.code == "not_found" => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub fn list<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        let records = {
            let connection = self.connection()?;
            let mut statement = connection.prepare(
                "SELECT o.id,o.body FROM objects o LEFT JOIN corrupt_objects c ON c.kind=o.kind AND c.id=o.id WHERE o.kind=?1 AND c.id IS NULL ORDER BY o.id",
            )?;
            let rows = statement.query_map([kind], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            let mut records = Vec::new();
            for row in rows {
                records.push(row?);
            }
            records
        };
        let mut output = Vec::new();
        for (id, body) in records {
            let value = match open(kind, &id, &body)
                .and_then(|bytes| serde_json::from_slice::<T>(&bytes).map_err(Into::into))
            {
                Ok(value) => value,
                Err(error) => {
                    self.quarantine(kind, &id, &error.code)?;
                    continue;
                }
            };
            output.push(value);
        }
        Ok(output)
    }
    pub fn raw(&self, kind: &str, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        if self.is_quarantined(kind, id)? {
            return Err(Error::new("storage_object_corrupt"));
        }
        let body: Option<Vec<u8>> = {
            let connection = self.connection()?;
            connection
                .query_row(
                    "SELECT body FROM objects WHERE kind=?1 AND id=?2",
                    [kind, id],
                    |r| r.get(0),
                )
                .optional()?
        };
        match open(kind, id, &body.ok_or_else(|| Error::new("not_found"))?) {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                self.quarantine(kind, id, &error.code)?;
                Err(Error::new("storage_object_corrupt"))
            }
        }
    }
    pub fn save<T: Serialize>(&self, kind: &str, id: &str, value: &T) -> Result<()> {
        self.put_many(vec![Self::encoded(kind, id, value)?])
    }

    #[cfg(test)]
    pub(crate) fn fail_object_writes_for_kind_for_tests(&self, kind: &str) -> Result<()> {
        // This is deliberately test-only. It provides a deterministic SQLite
        // failure after earlier rows in `put_many` have been staged, proving
        // callers rely on the transaction rather than on write ordering.
        if kind.is_empty()
            || !kind
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(Error::new("invalid_request"));
        }
        let connection = self.connection()?;
        connection.execute_batch(&format!(
            "CREATE TRIGGER fail_object_write_insert BEFORE INSERT ON objects \
             WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(ABORT,'forced object write'); END; \
             CREATE TRIGGER fail_object_write_update BEFORE UPDATE ON objects \
             WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(ABORT,'forced object write'); END;"
        ))?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn clear_object_write_failure_for_tests(&self) -> Result<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            "DROP TRIGGER IF EXISTS fail_object_write_insert; \
             DROP TRIGGER IF EXISTS fail_object_write_update;",
        )?;
        Ok(())
    }

    pub fn encoded_raw(kind: &str, id: &str, value: &[u8]) -> Result<StoredRow> {
        Ok(StoredRow {
            kind: kind.into(),
            id: id.into(),
            body: seal(kind, id, value)?,
            index: ObjectIndex {
                status: None,
                subkind: None,
                created_at: crate::now(),
                updated_at: crate::now(),
                group_id: None,
                task_id: None,
                conversation_id: None,
                parent_id: None,
                material_id: None,
                result_id: None,
                revision: None,
            },
            summary: None,
            relations: Vec::new(),
        })
    }
    pub fn encoded<T: Serialize>(kind: &str, id: &str, value: &T) -> Result<StoredRow> {
        let data = Zeroizing::new(serde_json::to_vec(value)?);
        let value = serde_json::from_slice::<Value>(&data)?;
        let index = index_for_value(kind, &value);
        let summary = summary_for_value(kind, id, &value, &index);
        Ok(StoredRow {
            kind: kind.into(),
            id: id.into(),
            body: seal(kind, id, &data)?,
            index,
            summary: Some(seal(
                &summary_kind(kind),
                id,
                &serde_json::to_vec(&summary)?,
            )?),
            relations: relations_for_value(kind, &value),
        })
    }
    pub fn put_many(&self, rows: Vec<StoredRow>) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        for row in rows {
            write_row(&tx, row)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn delete(&self, kind: &str, id: &str) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        tx.execute("DELETE FROM objects WHERE kind=?1 AND id=?2", [kind, id])?;
        tx.execute(
            "DELETE FROM object_summaries WHERE kind=?1 AND id=?2",
            [kind, id],
        )?;
        tx.execute(
            "DELETE FROM object_index WHERE kind=?1 AND id=?2",
            [kind, id],
        )?;
        tx.execute(
            "DELETE FROM object_relations WHERE kind=?1 AND id=?2",
            [kind, id],
        )?;
        tx.execute(
            "DELETE FROM corrupt_objects WHERE kind=?1 AND id=?2",
            [kind, id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Returns protected display summaries without opening the corresponding
    /// full objects. Cursors encode only the indexed sort key and a random id.
    pub fn summary_page(
        &self,
        kind: &str,
        subkind: Option<&str>,
        group_id: Option<&str>,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<SummaryPage> {
        if !(1..=100).contains(&limit) {
            return Err(Error::new("invalid_pagination"));
        }
        let cursor = cursor.map(decode_cursor).transpose()?;
        let (selected, total, corrupt_count, missing_summary) = {
            let connection = self.connection()?;
            let (filter_sql, filter_values) = index_filter_sql(kind, subkind, group_id);
            let total: i64 = connection.query_row(
                &format!("SELECT COUNT(*) FROM object_index i WHERE {filter_sql}"),
                rusqlite::params_from_iter(filter_values.iter()),
                |row| row.get(0),
            )?;
            // A summary row is mandatory for a listable object. Do not allow
            // the JOIN below to hide a partially written or manually damaged
            // row from a page as though it had never existed.
            let missing_summary: Option<String> = connection
                .query_row(
                    &format!("SELECT i.id FROM object_index i LEFT JOIN object_summaries s ON s.kind=i.kind AND s.id=i.id WHERE {filter_sql} AND s.id IS NULL LIMIT 1"),
                    rusqlite::params_from_iter(filter_values.iter()),
                    |row| row.get(0),
                )
                .optional()?;
            let corrupt_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM corrupt_objects WHERE kind=?1",
                [kind],
                |row| row.get(0),
            )?;
            let mut values = filter_values;
            let mut cursor_sql = String::new();
            if let Some((updated_at, id)) = &cursor {
                cursor_sql = " AND (i.updated_at < ? OR (i.updated_at = ? AND i.id < ?))".into();
                values.push(SqlValue::Integer(*updated_at as i64));
                values.push(SqlValue::Integer(*updated_at as i64));
                values.push(SqlValue::Text(id.clone()));
            }
            values.push(SqlValue::Integer((limit + 1) as i64));
            let sql = format!(
                "SELECT i.id,i.updated_at,s.body FROM object_index i JOIN object_summaries s ON s.kind=i.kind AND s.id=i.id WHERE {filter_sql}{cursor_sql} ORDER BY i.updated_at DESC,i.id DESC LIMIT ?"
            );
            let mut statement = connection.prepare(&sql)?;
            let rows = statement.query_map(rusqlite::params_from_iter(values.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            let mut selected = Vec::new();
            for row in rows {
                selected.push(row?);
            }
            (
                selected,
                total as u64,
                corrupt_count as u64,
                missing_summary,
            )
        };
        if let Some(id) = missing_summary {
            self.quarantine(kind, &id, "summary_missing")?;
            return Err(Error::new("storage_object_corrupt"));
        }
        let has_more = selected.len() > limit;
        let mut items = Vec::new();
        let mut last = None;
        for (id, updated_at, body) in selected.into_iter().take(limit) {
            match open(&summary_kind(kind), &id, &body)
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(Into::into))
            {
                Ok(value) => {
                    last = Some((updated_at, id));
                    items.push(value);
                }
                Err(error) => {
                    self.quarantine(kind, &id, &error.code)?;
                    return Err(Error::new("storage_object_corrupt"));
                }
            }
        }
        Ok(SummaryPage {
            items,
            next_cursor: has_more
                .then(|| last.map(|(updated_at, id)| encode_cursor(updated_at, &id)))
                .flatten(),
            total,
            corrupt_count,
        })
    }

    /// Lists conflict candidates for one logical writing document using only
    /// the cleartext index.  Candidate bodies (and their protected summaries)
    /// stay unopened until the caller explicitly selects a candidate.
    pub fn draft_conflicts_page(
        &self,
        base_id: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<SummaryPage> {
        if !valid_writing_draft_base(base_id) {
            return Err(Error::new("invalid_ai_request"));
        }
        if !(1..=100).contains(&limit) {
            return Err(Error::new("invalid_pagination"));
        }

        let prefix = format!("{base_id}-c-");
        let upper = format!("{base_id}-c.");
        let candidate_len = prefix
            .len()
            .checked_add(32)
            .ok_or_else(|| Error::new("invalid_pagination"))?;
        let suffix_start = prefix
            .len()
            .checked_add(1)
            .ok_or_else(|| Error::new("invalid_pagination"))?;
        let cursor = cursor.map(decode_cursor).transpose()?;
        if let Some((updated_at, id)) = &cursor {
            // A cursor from another document must never be usable to walk a
            // different candidate namespace.  Keeping this check independent
            // from the database query also avoids turning an arbitrary cursor
            // into an index probe.
            if !valid_draft_conflict_id(&prefix, id) || i64::try_from(*updated_at).is_err() {
                return Err(Error::new("invalid_pagination"));
            }
        }

        let (selected, total, corrupt_count) = {
            let connection = self.connection()?;
            let total: i64 = connection.query_row(
                "SELECT COUNT(*) FROM object_index
                 WHERE kind='ai_draft' AND id>=?1 AND id<?2
                   AND length(id)=?3
                   AND substr(id,?4) NOT GLOB '*[^0-9a-f]*'",
                rusqlite::params![&prefix, &upper, candidate_len as i64, suffix_start as i64],
                |row| row.get(0),
            )?;
            let corrupt_count: i64 = connection.query_row(
                "SELECT COUNT(*) FROM corrupt_objects
                 WHERE kind='ai_draft' AND id>=?1 AND id<?2
                   AND length(id)=?3
                   AND substr(id,?4) NOT GLOB '*[^0-9a-f]*'",
                rusqlite::params![&prefix, &upper, candidate_len as i64, suffix_start as i64],
                |row| row.get(0),
            )?;

            let mut values = vec![
                SqlValue::Text(prefix.clone()),
                SqlValue::Text(upper.clone()),
                SqlValue::Integer(candidate_len as i64),
                SqlValue::Integer(suffix_start as i64),
            ];
            let mut cursor_sql = String::new();
            if let Some((updated_at, id)) = &cursor {
                cursor_sql = " AND (i.updated_at < ? OR (i.updated_at = ? AND i.id < ?))".into();
                let updated_at =
                    i64::try_from(*updated_at).map_err(|_| Error::new("invalid_pagination"))?;
                values.push(SqlValue::Integer(updated_at));
                values.push(SqlValue::Integer(updated_at));
                values.push(SqlValue::Text(id.clone()));
            }
            values.push(SqlValue::Integer((limit + 1) as i64));
            let sql = format!(
                "SELECT i.id,i.revision,i.updated_at FROM object_index i
                 WHERE i.kind='ai_draft' AND i.id>=? AND i.id<?
                   AND length(i.id)=? AND substr(i.id,?) NOT GLOB '*[^0-9a-f]*'
                   {cursor_sql}
                 ORDER BY i.updated_at DESC,i.id DESC LIMIT ?"
            );
            let mut statement = connection.prepare(&sql)?;
            let rows = statement.query_map(rusqlite::params_from_iter(values.iter()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
            let mut selected = Vec::new();
            for row in rows {
                selected.push(row?);
            }
            (
                selected,
                u64::try_from(total).map_err(|_| Error::new("storage_metadata_invalid"))?,
                u64::try_from(corrupt_count).map_err(|_| Error::new("storage_metadata_invalid"))?,
            )
        };

        let has_more = selected.len() > limit;
        let mut items = Vec::new();
        let mut last = None;
        for (id, revision, updated_at) in selected.into_iter().take(limit) {
            let updated_at =
                u64::try_from(updated_at).map_err(|_| Error::new("storage_metadata_invalid"))?;
            let revision = revision
                .map(|revision| {
                    u64::try_from(revision).map_err(|_| Error::new("storage_metadata_invalid"))
                })
                .transpose()?;
            last = Some((updated_at, id.clone()));
            items.push(json!({
                "id": id,
                "revision": revision,
                "updated_at": updated_at,
            }));
        }
        Ok(SummaryPage {
            items,
            next_cursor: has_more
                .then(|| last.map(|(updated_at, id)| encode_cursor(updated_at, &id)))
                .flatten(),
            total,
            corrupt_count,
        })
    }

    pub fn summary(&self, kind: &str, id: &str) -> Result<Value> {
        if self.is_quarantined(kind, id)? {
            return Err(Error::new("storage_object_corrupt"));
        }
        // A missing object is a normal result for optional records such as an
        // AI progress stage. An existing object without its independently
        // encrypted summary is corruption and must be quarantined instead.
        let row: Option<Option<Vec<u8>>> = {
            let connection = self.connection()?;
            connection
                .query_row(
                    "SELECT s.body FROM objects o LEFT JOIN object_summaries s ON s.kind=o.kind AND s.id=o.id WHERE o.kind=?1 AND o.id=?2",
                    [kind, id],
                    |row| row.get(0),
                )
                .optional()?
        };
        let Some(body) = row else {
            return Err(Error::new("not_found"));
        };
        let Some(body) = body else {
            self.quarantine(kind, id, "summary_missing")?;
            return Err(Error::new("storage_object_corrupt"));
        };
        match open(&summary_kind(kind), id, &body)
            .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        {
            Ok(value) => Ok(value),
            Err(error) => {
                self.quarantine(kind, id, &error.code)?;
                Err(Error::new("storage_object_corrupt"))
            }
        }
    }

    pub fn maybe_summary(&self, kind: &str, id: &str) -> Result<Option<Value>> {
        match self.summary(kind, id) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.code == "not_found" => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn corrupt_count(&self, kind: Option<&str>) -> Result<u64> {
        let connection = self.connection()?;
        match kind {
            Some(kind) => Ok(connection.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM corrupt_objects WHERE kind=?1",
                [kind],
                |row| row.get::<_, i64>(0),
            )? as u64),
            None => Ok(connection.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM corrupt_objects",
                [],
                |row| row.get::<_, i64>(0),
            )? as u64),
        }
    }

    pub fn any_indexed_relation_with_status(
        &self,
        kind: &str,
        relation_kind: &str,
        relation_id: &str,
        statuses: &[&str],
    ) -> Result<bool> {
        if statuses.is_empty() {
            return Ok(false);
        }
        let placeholders = std::iter::repeat_n("?", statuses.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut values = vec![
            SqlValue::Text(kind.into()),
            SqlValue::Text(relation_kind.into()),
            SqlValue::Text(relation_id.into()),
        ];
        values.extend(
            statuses
                .iter()
                .map(|status| SqlValue::Text((*status).into())),
        );
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                &format!("SELECT 1 FROM object_index i JOIN object_relations r ON r.kind=i.kind AND r.id=i.id WHERE i.kind=? AND r.relation_kind=? AND r.relation_id=? AND i.status IN ({placeholders}) LIMIT 1"),
                rusqlite::params_from_iter(values.iter()),
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn related_ids_with_status(
        &self,
        kind: &str,
        relations: &[(String, String)],
        statuses: &[&str],
    ) -> Result<Vec<String>> {
        if relations.is_empty() || statuses.is_empty() {
            return Ok(Vec::new());
        }
        let relation_terms =
            std::iter::repeat_n("(r.relation_kind=? AND r.relation_id=?)", relations.len())
                .collect::<Vec<_>>()
                .join(" OR ");
        let status_terms = std::iter::repeat_n("?", statuses.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut values = vec![SqlValue::Text(kind.into())];
        for (relation_kind, relation_id) in relations {
            values.push(SqlValue::Text(relation_kind.clone()));
            values.push(SqlValue::Text(relation_id.clone()));
        }
        values.extend(
            statuses
                .iter()
                .map(|status| SqlValue::Text((*status).into())),
        );
        let connection = self.connection()?;
        let mut statement = connection.prepare(&format!(
            "SELECT DISTINCT i.id FROM object_index i JOIN object_relations r ON r.kind=i.kind AND r.id=i.id WHERE i.kind=? AND ({relation_terms}) AND i.status IN ({status_terms})"
        ))?;
        let rows =
            statement.query_map(rusqlite::params_from_iter(values.iter()), |row| row.get(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        Ok(ids)
    }

    pub fn indexed_ids_with_status(&self, kind: &str, statuses: &[&str]) -> Result<Vec<String>> {
        if statuses.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = std::iter::repeat_n("?", statuses.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut values = vec![SqlValue::Text(kind.into())];
        values.extend(
            statuses
                .iter()
                .map(|status| SqlValue::Text((*status).into())),
        );
        let connection = self.connection()?;
        let mut statement = connection.prepare(&format!(
            "SELECT id FROM object_index WHERE kind=? AND status IN ({placeholders}) ORDER BY updated_at ASC,id ASC"
        ))?;
        let rows =
            statement.query_map(rusqlite::params_from_iter(values.iter()), |row| row.get(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        Ok(ids)
    }

    /// The empty-path reads only the material queue index. It also detects
    /// unindexed or quarantined material rows so corruption cannot masquerade
    /// as an idle worker.
    pub fn next_queued_material(&self) -> Result<Option<(String, String)>> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let missing: Option<String> = tx
            .query_row(
                "SELECT o.id FROM objects o LEFT JOIN object_index i ON i.kind=o.kind AND i.id=o.id WHERE o.kind='material' AND i.id IS NULL LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(id) = missing {
            quarantine_tx(&tx, "material", &id, "index_missing")?;
            tx.commit()?;
            return Err(Error::new("storage_object_corrupt"));
        }
        let corrupt: Option<String> = tx
            .query_row(
                "SELECT id FROM corrupt_objects WHERE kind='material' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if corrupt.is_some() {
            tx.commit()?;
            return Err(Error::new("storage_object_corrupt"));
        }
        let next = tx
            .query_row(
                "SELECT id,group_id FROM object_index WHERE kind='material' AND status='queued' ORDER BY updated_at ASC,id ASC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        tx.commit()?;
        Ok(next)
    }

    /// Claims exactly the indexed queued material and writes its protected
    /// object, summary and cleartext index transition in one transaction.
    pub fn claim_queued_material(
        &self,
        id: &str,
        dictionary_revision: u64,
    ) -> Result<Option<crate::Material>> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        let body: Option<Vec<u8>> = tx
            .query_row(
                "SELECT o.body FROM objects o JOIN object_index i ON i.kind=o.kind AND i.id=o.id WHERE o.kind='material' AND o.id=?1 AND i.status='queued'",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(body) = body else {
            tx.commit()?;
            return Ok(None);
        };
        let mut material = match open("material", id, &body)
            .and_then(|bytes| serde_json::from_slice::<crate::Material>(&bytes).map_err(Into::into))
        {
            Ok(material) if material.status == "queued" => material,
            Ok(_) => {
                quarantine_tx(&tx, "material", id, "index_body_mismatch")?;
                tx.commit()?;
                return Err(Error::new("storage_object_corrupt"));
            }
            Err(error) => {
                quarantine_tx(&tx, "material", id, &error.code)?;
                tx.commit()?;
                return Err(Error::new("storage_object_corrupt"));
            }
        };
        material.status = "running".into();
        material.dictionary_revision = dictionary_revision;
        write_row(&tx, Self::encoded("material", id, &material)?)?;
        tx.commit()?;
        Ok(Some(material))
    }

    fn is_quarantined(&self, kind: &str, id: &str) -> Result<bool> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT 1 FROM corrupt_objects WHERE kind=?1 AND id=?2",
                [kind, id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn quarantine(&self, kind: &str, id: &str, code: &str) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        quarantine_tx(&tx, kind, id, code)?;
        tx.commit()?;
        Ok(())
    }
}

fn summary_kind(kind: &str) -> String {
    format!("summary/{kind}")
}

fn field_string(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn field_u64(value: &Value, field: &str) -> Option<u64> {
    value.get(field).and_then(Value::as_u64)
}

fn valid_writing_draft_base(base_id: &str) -> bool {
    if base_id == "writing-current" {
        return true;
    }
    let Some(document_id) = base_id.strip_prefix("writing-") else {
        return false;
    };
    !document_id.is_empty()
        && base_id.len() <= 44
        && document_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn valid_draft_conflict_id(prefix: &str, id: &str) -> bool {
    id.len() == prefix.len() + 32
        && id.starts_with(prefix)
        && id[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn index_for_value(_kind: &str, value: &Value) -> ObjectIndex {
    let request = value.get("request").unwrap_or(&Value::Null);
    ObjectIndex {
        status: field_string(value, "status"),
        subkind: field_string(value, "kind"),
        created_at: field_u64(value, "created_at").unwrap_or_else(crate::now),
        updated_at: field_u64(value, "updated_at").unwrap_or_else(crate::now),
        group_id: field_string(value, "group_id"),
        task_id: field_string(value, "task_id"),
        conversation_id: field_string(value, "conversation_id")
            .or_else(|| field_string(request, "conversation_id")),
        parent_id: field_string(value, "parent_id").or_else(|| field_string(request, "parent_id")),
        material_id: field_string(value, "material_id"),
        result_id: field_string(value, "result_id"),
        revision: field_u64(value, "revision").or_else(|| field_u64(value, "dictionary_revision")),
    }
}

fn relation_pairs(value: &Value, relation_kind: &str, field: &str) -> Vec<(String, String)> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| match value {
            Value::String(id) if !id.is_empty() => Some((relation_kind.into(), id.clone())),
            Value::Object(_) => field_string(value, "id").map(|id| {
                let source = field_string(value, "source").unwrap_or_default();
                let relation_kind = if source.is_empty() {
                    relation_kind.into()
                } else {
                    format!("{relation_kind}_{source}")
                };
                (relation_kind, id)
            }),
            _ => None,
        })
        .collect()
}

fn relations_for_value(kind: &str, value: &Value) -> Vec<(String, String)> {
    let mut relations = BTreeSet::new();
    for (relation_kind, field) in [
        ("group", "group_id"),
        ("task", "task_id"),
        ("conversation", "conversation_id"),
        ("parent", "parent_id"),
        ("material", "material_id"),
        ("result", "result_id"),
    ] {
        if let Some(id) = field_string(value, field) {
            relations.insert((relation_kind.into(), id));
        }
    }
    for relation in relation_pairs(value, "material", "material_ids") {
        relations.insert(relation);
    }
    for relation in relation_pairs(value, "material", "materials") {
        relations.insert(relation);
    }
    for relation in relation_pairs(value, "attachment", "attachment_ids") {
        relations.insert(relation);
    }
    if kind == "ai_run" {
        let request = value.get("request").unwrap_or(&Value::Null);
        for (relation_kind, field) in [("conversation", "conversation_id"), ("parent", "parent_id")]
        {
            if let Some(id) = field_string(request, field) {
                relations.insert((relation_kind.into(), id));
            }
        }
        for relation in relation_pairs(request, "material", "materials") {
            relations.insert(relation);
        }
        for relation in relation_pairs(request, "attachment", "attachment_ids") {
            relations.insert(relation);
        }
    }
    relations.into_iter().collect()
}

fn summary_for_value(kind: &str, id: &str, value: &Value, index: &ObjectIndex) -> Value {
    match kind {
        "material" => json!({
            "id":id,"name":value["name"],"group_id":index.group_id,"task_id":index.task_id,
            "status":index.status,"result_id":index.result_id,"reason_code":value["reason_code"],
            "revision":index.revision,"source_sha256":value["source_sha256"],
            "source_byte_len":value["source_byte_len"],"source_format":value["source_format"],
            "has_analysis":value["analysis"].is_object(),
        }),
        "ai_run" => json!({
            "id":id,"kind":index.subkind,"status":index.status,"stage":value["stage"],
            "title":value["title"],"error_code":value["error_code"],"created_at":index.created_at,
            "updated_at":index.updated_at,"provider_id":value["provider_id"],"model":value["model"],
            "conversation_id":index.conversation_id,"parent_id":index.parent_id,
            "context_revision":value["request"]["context_revision"],"revision":index.revision,
            "document_id": if value["kind"].as_str() == Some("writing") {
                value["document_id"]
                    .as_str()
                    .filter(|document_id| !document_id.is_empty())
                    .map(|document_id| Value::String(document_id.to_owned()))
                    .unwrap_or_else(|| Value::String(id.to_owned()))
            } else {
                Value::Null
            },
        }),
        "ai_conversation" | "conversation" => json!({
            "id":id,"title":value["title"],"updated_at":index.updated_at,
            "context_revision":value["context_revision"],"context_known":value["context_known"],
            "materials":value["materials"],"attachment_ids":value["attachment_ids"],
            "context_ranges":value["context_ranges"],
        }),
        "ai_attachment" => json!({
            "id":id,"sha256":value["sha256"],"source_byte_len":value["source_byte_len"],
            "format":value["format"],"created_at":index.created_at
        }),
        "result" => json!({
            "id":id,"material_id":index.material_id,"revision":index.revision,
            "output_sha256":value["output_sha256"],"text_byte_len":value["text_byte_len"],
            "revoked":value["revoked"],
        }),
        "group" => {
            json!({"id":id,"name":value["name"],"dictionary_revision":value["dictionary_revision"]})
        }
        "task" => {
            json!({"id":id,"group_id":index.group_id,"created_at":index.created_at,"material_ids":value["material_ids"]})
        }
        "ai_stage" => json!({
            "material_id":value["material_id"],"revision":index.revision,
            "source_sha256":value["source_sha256"],"stage":value["stage"],
            "updated_at":index.updated_at,"error_code":value["error_code"],
        }),
        _ => json!({
            "id":id,"status":index.status,"created_at":index.created_at,
            "updated_at":index.updated_at,"revision":index.revision,
        }),
    }
}

fn write_row(tx: &Transaction<'_>, row: StoredRow) -> Result<()> {
    let created_at =
        i64::try_from(row.index.created_at).map_err(|_| Error::new("storage_metadata_invalid"))?;
    let updated_at =
        i64::try_from(row.index.updated_at).map_err(|_| Error::new("storage_metadata_invalid"))?;
    let revision = row
        .index
        .revision
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::new("storage_metadata_invalid"))?;
    tx.execute(
        "INSERT INTO objects(kind,id,body) VALUES(?1,?2,?3) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body",
        rusqlite::params![row.kind, row.id, row.body],
    )?;
    tx.execute(
        "INSERT INTO object_index(kind,id,status,subkind,created_at,updated_at,group_id,task_id,conversation_id,parent_id,material_id,result_id,revision) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) ON CONFLICT(kind,id) DO UPDATE SET status=excluded.status,subkind=excluded.subkind,created_at=excluded.created_at,updated_at=excluded.updated_at,group_id=excluded.group_id,task_id=excluded.task_id,conversation_id=excluded.conversation_id,parent_id=excluded.parent_id,material_id=excluded.material_id,result_id=excluded.result_id,revision=excluded.revision",
        rusqlite::params![row.kind,row.id,row.index.status,row.index.subkind,created_at,updated_at,row.index.group_id,row.index.task_id,row.index.conversation_id,row.index.parent_id,row.index.material_id,row.index.result_id,revision],
    )?;
    tx.execute(
        "DELETE FROM object_relations WHERE kind=?1 AND id=?2",
        rusqlite::params![row.kind, row.id],
    )?;
    for (relation_kind, relation_id) in row.relations {
        tx.execute(
            "INSERT INTO object_relations(kind,id,relation_kind,relation_id) VALUES(?1,?2,?3,?4)",
            rusqlite::params![row.kind, row.id, relation_kind, relation_id],
        )?;
    }
    match row.summary {
        Some(summary) => {
            tx.execute("INSERT INTO object_summaries(kind,id,body) VALUES(?1,?2,?3) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body", rusqlite::params![row.kind,row.id,summary])?;
        }
        None => {
            tx.execute(
                "DELETE FROM object_summaries WHERE kind=?1 AND id=?2",
                rusqlite::params![row.kind, row.id],
            )?;
        }
    }
    tx.execute(
        "DELETE FROM corrupt_objects WHERE kind=?1 AND id=?2",
        rusqlite::params![row.kind, row.id],
    )?;
    Ok(())
}

fn quarantine_tx(tx: &Transaction<'_>, kind: &str, id: &str, code: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO corrupt_objects(kind,id,code,detected_at) VALUES(?1,?2,?3,?4) ON CONFLICT(kind,id) DO UPDATE SET code=excluded.code,detected_at=excluded.detected_at",
        rusqlite::params![kind,id,code,i64::try_from(crate::now()).map_err(|_| Error::new("storage_metadata_invalid"))?],
    )?;
    tx.execute(
        "DELETE FROM object_summaries WHERE kind=?1 AND id=?2",
        [kind, id],
    )?;
    tx.execute(
        "DELETE FROM object_index WHERE kind=?1 AND id=?2",
        [kind, id],
    )?;
    tx.execute(
        "DELETE FROM object_relations WHERE kind=?1 AND id=?2",
        [kind, id],
    )?;
    Ok(())
}

fn index_filter_sql(
    kind: &str,
    subkind: Option<&str>,
    group_id: Option<&str>,
) -> (String, Vec<SqlValue>) {
    let mut filter = "i.kind=?".to_owned();
    let mut values = vec![SqlValue::Text(kind.into())];
    if let Some(subkind) = subkind {
        filter.push_str(" AND i.subkind=?");
        values.push(SqlValue::Text(subkind.into()));
    }
    if let Some(group_id) = group_id {
        filter.push_str(" AND i.group_id=?");
        values.push(SqlValue::Text(group_id.into()));
    }
    (filter, values)
}

fn encode_cursor(updated_at: u64, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("{updated_at}:{id}"))
}

fn decode_cursor(cursor: &str) -> Result<(u64, String)> {
    let decoded = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| Error::new("invalid_pagination"))?;
    let decoded = String::from_utf8(decoded).map_err(|_| Error::new("invalid_pagination"))?;
    let (updated_at, id) = decoded
        .split_once(':')
        .ok_or_else(|| Error::new("invalid_pagination"))?;
    if id.is_empty() || id.len() > 200 {
        return Err(Error::new("invalid_pagination"));
    }
    Ok((
        updated_at
            .parse::<u64>()
            .map_err(|_| Error::new("invalid_pagination"))?,
        id.into(),
    ))
}

/// Hash the logical rows rather than SQLite pages, which may legitimately
/// differ after a backup/checkpoint while still representing the same v1 data.
fn snapshot_fingerprint(connection: &Connection) -> Result<String> {
    fn add(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }

    let mut hasher = Sha256::new();
    let mut metadata = connection.prepare("SELECT key,value FROM web_metadata ORDER BY key")?;
    let rows = metadata.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (key, value) = row?;
        add(&mut hasher, key.as_bytes());
        add(&mut hasher, value.as_bytes());
    }
    let mut objects = connection.prepare("SELECT kind,id,body FROM objects ORDER BY kind,id")?;
    let rows = objects.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for row in rows {
        let (kind, id, body) = row?;
        add(&mut hasher, kind.as_bytes());
        add(&mut hasher, id.as_bytes());
        add(&mut hasher, &body);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn existing_backup_matches(backup: &Path, expected: &str) -> Result<bool> {
    crate::filesystem::ordinary_chain(backup)?;
    let connection = match Connection::open_with_flags(backup, OpenFlags::SQLITE_OPEN_READ_ONLY) {
        Ok(connection) => connection,
        Err(_) => return Ok(false),
    };
    let integrity: String = match connection.query_row("PRAGMA integrity_check", [], |r| r.get(0)) {
        Ok(integrity) => integrity,
        Err(_) => return Ok(false),
    };
    if integrity != "ok" {
        return Ok(false);
    }
    Ok(snapshot_fingerprint(&connection).is_ok_and(|actual| actual == expected))
}

fn unique_v1_backup_path(root: &Path) -> std::path::PathBuf {
    loop {
        let path = root.join(format!(
            "workspace.pre-ai-v1.{}.sqlite",
            uuid::Uuid::new_v4().simple()
        ));
        if !path.exists() {
            return path;
        }
    }
}

fn create_v1_backup(connection: &Connection, root: &Path) -> Result<()> {
    let expected = snapshot_fingerprint(connection)?;
    let primary = root.join("workspace.pre-ai-v1.sqlite");
    if primary.exists() && existing_backup_matches(&primary, &expected)? {
        return Ok(());
    }
    // Preserve a damaged or stale backup for forensic recovery. Its replacement
    // receives a fresh unique name and must prove both integrity and identity.
    let backup = if primary.exists() {
        unique_v1_backup_path(root)
    } else {
        primary
    };
    let mut destination = Connection::open(&backup)?;
    rusqlite::backup::Backup::new(connection, &mut destination)?.run_to_completion(
        128,
        std::time::Duration::from_millis(10),
        None,
    )?;
    drop(destination);
    if !existing_backup_matches(&backup, &expected)? {
        return Err(Error::new("workspace_backup_failed"));
    }
    Ok(())
}

fn create_v3_tables(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS object_index(
            kind TEXT NOT NULL,id TEXT NOT NULL,status TEXT,subkind TEXT,
            created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,
            group_id TEXT,task_id TEXT,conversation_id TEXT,parent_id TEXT,
            material_id TEXT,result_id TEXT,revision INTEGER,
            PRIMARY KEY(kind,id));
          CREATE INDEX IF NOT EXISTS object_index_kind_updated ON object_index(kind,updated_at DESC,id DESC);
          CREATE INDEX IF NOT EXISTS object_index_queue ON object_index(kind,status,updated_at,id);
          CREATE INDEX IF NOT EXISTS object_index_group ON object_index(kind,group_id,updated_at DESC,id DESC);
          CREATE TABLE IF NOT EXISTS object_summaries(kind TEXT NOT NULL,id TEXT NOT NULL,body BLOB NOT NULL,PRIMARY KEY(kind,id));
          CREATE TABLE IF NOT EXISTS object_relations(kind TEXT NOT NULL,id TEXT NOT NULL,relation_kind TEXT NOT NULL,relation_id TEXT NOT NULL,PRIMARY KEY(kind,id,relation_kind,relation_id));
          CREATE INDEX IF NOT EXISTS object_relations_lookup ON object_relations(relation_kind,relation_id,kind,id);
          CREATE TABLE IF NOT EXISTS corrupt_objects(kind TEXT NOT NULL,id TEXT NOT NULL,code TEXT NOT NULL,detected_at INTEGER NOT NULL,PRIMARY KEY(kind,id));",
    )?;
    Ok(())
}

fn migrate_v2_to_v3(connection: &mut Connection) -> Result<()> {
    let tx = connection.transaction()?;
    create_v3_tables(&tx)?;
    let records = {
        let mut statement = tx.prepare("SELECT kind,id,body FROM objects ORDER BY kind,id")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        records
    };
    for (kind, id, body) in records {
        let row = match open(&kind, &id, &body) {
            Ok(_bytes) if is_raw_kind(&kind) => Some(StoredRow {
                kind: kind.clone(),
                id: id.clone(),
                body,
                index: ObjectIndex {
                    status: None,
                    subkind: None,
                    created_at: crate::now(),
                    updated_at: crate::now(),
                    group_id: None,
                    task_id: None,
                    conversation_id: None,
                    parent_id: None,
                    material_id: None,
                    result_id: None,
                    revision: None,
                },
                summary: None,
                relations: Vec::new(),
            }),
            Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => {
                    let index = index_for_value(&kind, &value);
                    let summary = summary_for_value(&kind, &id, &value, &index);
                    Some(StoredRow {
                        kind: kind.clone(),
                        id: id.clone(),
                        body,
                        index,
                        summary: Some(seal(
                            &summary_kind(&kind),
                            &id,
                            &serde_json::to_vec(&summary)?,
                        )?),
                        relations: relations_for_value(&kind, &value),
                    })
                }
                Err(_) => None,
            },
            Err(_) => None,
        };
        if let Some(row) = row {
            write_row(&tx, row)?;
        } else {
            // Keep the original encrypted body for forensic recovery but
            // remove it from all executable/listable indexes.
            quarantine_tx(&tx, &kind, &id, "migration_object_invalid")?;
        }
    }
    tx.execute(
        "UPDATE web_metadata SET value=?1 WHERE key='schema'",
        [SCHEMA_V3],
    )?;
    tx.commit()?;
    Ok(())
}

fn is_raw_kind(kind: &str) -> bool {
    matches!(kind, "source" | "ai_attachment_source")
}

fn unique_v2_backup_path(root: &Path) -> std::path::PathBuf {
    loop {
        let path = root.join(format!(
            "workspace.pre-index-v2.{}.sqlite",
            uuid::Uuid::new_v4().simple()
        ));
        if !path.exists() {
            return path;
        }
    }
}

fn create_v2_backup(connection: &Connection, root: &Path) -> Result<()> {
    let expected = snapshot_fingerprint(connection)?;
    let primary = root.join("workspace.pre-index-v2.sqlite");
    if primary.exists() && existing_backup_matches(&primary, &expected)? {
        return Ok(());
    }
    let backup = if primary.exists() {
        unique_v2_backup_path(root)
    } else {
        primary
    };
    let mut destination = Connection::open(&backup)?;
    rusqlite::backup::Backup::new(connection, &mut destination)?.run_to_completion(
        128,
        std::time::Duration::from_millis(10),
        None,
    )?;
    drop(destination);
    if !existing_backup_matches(&backup, &expected)? {
        return Err(Error::new("workspace_backup_failed"));
    }
    Ok(())
}

fn seal(kind: &str, id: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_OBJECT {
        return Err(Error::new("object_too_large"));
    }
    let count = bytes.len().max(1).div_ceil(CHUNK);
    let mut output = b"LAWEB1".to_vec();
    output.extend_from_slice(&(count as u32).to_le_bytes());
    for i in 0..count {
        let mut chunk = Zeroizing::new(format!("{kind}/{id}/{i}/{count}\0").into_bytes());
        chunk.extend_from_slice(
            &bytes[(i * CHUNK).min(bytes.len())..((i + 1) * CHUNK).min(bytes.len())],
        );
        let protected =
            privacy::protect_local(&chunk).map_err(|_| Error::new("local_encryption_failed"))?;
        output.extend_from_slice(&(protected.len() as u32).to_le_bytes());
        output.extend_from_slice(&protected);
    }
    Ok(output)
}
fn open(kind: &str, id: &str, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(test)]
    PLAINTEXT_DECRYPTIONS.with(|count| count.set(count.get().saturating_add(1)));
    let invalid = || Error::new("encrypted_object_invalid");
    if bytes.len() < 10 || &bytes[..6] != b"LAWEB1" {
        return Err(invalid());
    }
    let number = u32::from_le_bytes(bytes[6..10].try_into().map_err(|_| invalid())?) as usize;
    if number == 0 || number > MAX_OBJECT.div_ceil(CHUNK) {
        return Err(invalid());
    }
    let mut at = 10;
    let mut plain = Zeroizing::new(Vec::new());
    for i in 0..number {
        let size = u32::from_le_bytes(
            bytes
                .get(at..at + 4)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ) as usize;
        at += 4;
        let slice = bytes
            .get(at..at.checked_add(size).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        at += size;
        let chunk = Zeroizing::new(privacy::unprotect_local(slice).map_err(|_| invalid())?);
        let prefix = format!("{kind}/{id}/{i}/{number}\0");
        if !chunk.starts_with(prefix.as_bytes()) {
            return Err(invalid());
        }
        plain.extend_from_slice(&chunk[prefix.len()..]);
        if plain.len() > MAX_OBJECT {
            return Err(invalid());
        }
    }
    if at != bytes.len() {
        return Err(invalid());
    }
    Ok(plain)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn queued_material(id: &str, status: &str) -> crate::Material {
        crate::Material {
            id: id.into(),
            name: "confidential-source.txt".into(),
            group_id: "grp_index".into(),
            task_id: "task_index".into(),
            status: status.into(),
            reason_code: None,
            revision: 1,
            source_sha256: "sensitive-source-hash".into(),
            source_byte_len: 0,
            source_format: "unknown".into(),
            encoding: Some("utf-8".into()),
            original_text: "sensitive original body".into(),
            analysis: None,
            result_id: None,
            dismissed: Vec::new(),
            dictionary_revision: 1,
        }
    }

    fn force_v2(root: &Path) {
        let connection = Connection::open(root.join("workspace.sqlite")).unwrap();
        connection
            .execute_batch(
                "DROP TABLE IF EXISTS object_relations;
                 DROP TABLE IF EXISTS object_summaries;
                 DROP TABLE IF EXISTS object_index;
                 DROP TABLE IF EXISTS corrupt_objects;
                 UPDATE web_metadata SET value='web-workspace-v2' WHERE key='schema';",
            )
            .unwrap();
    }

    #[test]
    fn encrypted_rows_are_bound_and_workspace_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.save("test", "one", &"敏感原文 13800138000").unwrap();
        assert_eq!(
            store.get::<String>("test", "one").unwrap(),
            "敏感原文 13800138000"
        );
        assert!(Store::open(dir.path()).is_err());
        let encoded = seal("test", "one", b"secret").unwrap();
        assert!(open("test", "two", &encoded).is_err());
        assert!(!encoded.windows(6).any(|x| x == b"secret"));
    }

    #[test]
    fn v2_index_migration_creates_verified_backup_and_protected_summary() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .save(
                "material",
                "mat_migrate",
                &queued_material("mat_migrate", "queued"),
            )
            .unwrap();
        drop(store);
        force_v2(directory.path());

        let migrated = Store::open(directory.path()).unwrap();
        assert_eq!(migrated.corrupt_count(None).unwrap(), 0);
        assert_eq!(
            migrated.summary("material", "mat_migrate").unwrap()["name"],
            "confidential-source.txt"
        );
        assert!(directory
            .path()
            .join("workspace.pre-index-v2.sqlite")
            .is_file());
        let database = Connection::open(directory.path().join("workspace.sqlite")).unwrap();
        let schema: String = database
            .query_row(
                "SELECT value FROM web_metadata WHERE key='schema'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema, SCHEMA_V3);
        let body: Vec<u8> = database
            .query_row(
                "SELECT body FROM object_summaries WHERE kind='material' AND id='mat_migrate'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!body
            .windows("confidential-source.txt".len())
            .any(|window| window == b"confidential-source.txt"));
        let metadata_sql: String = database
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='object_index'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!metadata_sql.contains("name"));
        assert!(!metadata_sql.contains("sha256"));
    }

    #[test]
    fn v2_verified_backup_restores_into_independent_workspace_and_remigrates() {
        let source_directory = tempfile::tempdir().unwrap();
        let source = Store::open(source_directory.path()).unwrap();
        source
            .save(
                "material",
                "mat_backup_restore",
                &queued_material("mat_backup_restore", "queued"),
            )
            .unwrap();
        drop(source);
        force_v2(source_directory.path());

        // Opening this v2 copy first creates and verifies the pre-index
        // backup, then migrates the active source workspace to v3.
        let migrated = Store::open(source_directory.path()).unwrap();
        assert_eq!(
            migrated.summary("material", "mat_backup_restore").unwrap()["status"],
            "queued"
        );
        let backup = source_directory
            .path()
            .join("workspace.pre-index-v2.sqlite");
        assert!(backup.is_file());

        // A recovery is an independent workspace, not a second connection to
        // the active source.  The local test encryption context is unchanged,
        // so opening the copied backup proves the original object can still be
        // decrypted and rebuilt into fresh protected summaries.
        let recovery_directory = tempfile::tempdir().unwrap();
        std::fs::copy(&backup, recovery_directory.path().join("workspace.sqlite")).unwrap();
        let recovered = Store::open(recovery_directory.path()).unwrap();
        let material: crate::Material = recovered.get("material", "mat_backup_restore").unwrap();
        assert_eq!(material.status, "queued");
        assert_eq!(material.original_text, "sensitive original body");
        assert_eq!(
            recovered.summary("material", "mat_backup_restore").unwrap()["name"],
            "confidential-source.txt"
        );
        assert!(recovery_directory
            .path()
            .join("workspace.pre-index-v2.sqlite")
            .is_file());

        let database =
            Connection::open(recovery_directory.path().join("workspace.sqlite")).unwrap();
        let schema: String = database
            .query_row(
                "SELECT value FROM web_metadata WHERE key='schema'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema, SCHEMA_V3);
        let summary: Vec<u8> = database
            .query_row(
                "SELECT body FROM object_summaries WHERE kind='material' AND id='mat_backup_restore'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!summary
            .windows("confidential-source.txt".len())
            .any(|window| { window == b"confidential-source.txt" }));
    }

    #[test]
    fn v2_migration_failure_rolls_back_before_recovery_without_touching_backup() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .save(
                "material",
                "mat_rollback_migration",
                &queued_material("mat_rollback_migration", "queued"),
            )
            .unwrap();
        drop(store);
        force_v2(directory.path());
        let database = Connection::open(directory.path().join("workspace.sqlite")).unwrap();
        database
            .execute_batch(
                "CREATE TRIGGER fail_v3_schema BEFORE UPDATE ON web_metadata
                 WHEN NEW.value='web-workspace-v3'
                 BEGIN SELECT RAISE(ABORT,'forced migration failure'); END;",
            )
            .unwrap();
        drop(database);

        assert!(Store::open(directory.path()).is_err());
        let database = Connection::open(directory.path().join("workspace.sqlite")).unwrap();
        let schema: String = database
            .query_row(
                "SELECT value FROM web_metadata WHERE key='schema'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema, SCHEMA_V2);
        let indexed: i64 = database
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='object_index'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexed, 0, "failed migration leaves no partial index");
        assert!(directory
            .path()
            .join("workspace.pre-index-v2.sqlite")
            .exists());
        database
            .execute_batch("DROP TRIGGER fail_v3_schema;")
            .unwrap();
        drop(database);

        let recovered = Store::open(directory.path()).unwrap();
        assert_eq!(
            recovered
                .summary_page("material", None, None, None, 10)
                .unwrap()
                .items[0]["id"],
            "mat_rollback_migration"
        );
    }

    #[test]
    fn v2_migration_quarantines_bad_object_without_hiding_valid_records() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .save(
                "material",
                "mat_good",
                &queued_material("mat_good", "queued"),
            )
            .unwrap();
        drop(store);
        force_v2(directory.path());
        let database = Connection::open(directory.path().join("workspace.sqlite")).unwrap();
        database
            .execute(
                "INSERT INTO objects(kind,id,body) VALUES('material','mat_bad',?1)",
                rusqlite::params![vec![0_u8]],
            )
            .unwrap();
        drop(database);

        let migrated = Store::open(directory.path()).unwrap();
        assert_eq!(migrated.corrupt_count(Some("material")).unwrap(), 1);
        assert_eq!(
            migrated.raw("material", "mat_bad").unwrap_err().code,
            "storage_object_corrupt"
        );
        let page = migrated
            .summary_page("material", None, None, None, 10)
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0]["id"], "mat_good");
        assert_eq!(page.corrupt_count, 1);
    }

    #[test]
    fn page_decrypts_only_current_protected_summary_and_cursor_is_stable() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        for id in ["run_a", "run_b", "run_c"] {
            store
                .save(
                    "ai_run",
                    id,
                    &json!({
                        "id":id,"kind":"writing","status":"completed","stage":"done",
                        "title":format!("title-{id}"),"content":"SENSITIVE FULL RUN BODY",
                        "created_at":1,"updated_at":1,"revision":1,
                        "request":{"parent_id":null,"conversation_id":null,"materials":[],"attachment_ids":[]},
                    }),
                )
                .unwrap();
        }
        reset_plaintext_decryptions();
        let first = store
            .summary_page("ai_run", Some("writing"), None, None, 1)
            .unwrap();
        assert_eq!(plaintext_decryptions(), 1);
        assert_eq!(first.items.len(), 1);
        assert!(first.items[0].get("content").is_none());
        let second = store
            .summary_page(
                "ai_run",
                Some("writing"),
                None,
                first.next_cursor.as_deref(),
                1,
            )
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_ne!(first.items[0]["id"], second.items[0]["id"]);
        assert_eq!(first.total, 3);
    }

    #[test]
    fn draft_conflict_page_is_scoped_index_only_and_paginated() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let base = "writing-run_alpha";
        let other_base = "writing-runXalpha";
        let candidate =
            |base: &str, digit: char| format!("{base}-c-{}", digit.to_string().repeat(32));
        let first_id = candidate(base, 'a');
        let second_id = candidate(base, 'b');
        let third_id = candidate(base, 'c');
        for (id, revision, updated_at, content) in [
            (&first_id, 1_u64, 10_u64, "short body".to_owned()),
            (&second_id, 2_u64, 10_u64, "second body".to_owned()),
            (&third_id, 3_u64, 11_u64, "third body".to_owned()),
        ] {
            store
                .save(
                    "ai_draft",
                    id,
                    &json!({
                        "revision":revision,"updated_at":updated_at,"content":content,
                    }),
                )
                .unwrap();
        }
        // A large protected body must not be opened just to build this page.
        let large_id = candidate(other_base, 'd');
        store
            .save(
                "ai_draft",
                &large_id,
                &json!({
                    "revision": 4,
                    "updated_at": 12,
                    "content": "x".repeat(4 * 1024 * 1024),
                }),
            )
            .unwrap();
        // Rows in the index range with a malformed suffix are not candidates.
        let malformed_short = format!("{base}-c-{}", "e".repeat(31));
        let malformed_upper = format!("{base}-c-{}", "F".repeat(32));
        for id in [&malformed_short, &malformed_upper] {
            store
                .save(
                    "ai_draft",
                    id,
                    &json!({"revision":99,"updated_at":99,"content":"ignore"}),
                )
                .unwrap();
        }
        {
            let connection = store.connection().unwrap();
            connection
                .execute(
                    "INSERT INTO corrupt_objects(kind,id,code,detected_at) VALUES(?1,?2,?3,?4)",
                    rusqlite::params!["ai_draft", &third_id, "test_corrupt", crate::now() as i64],
                )
                .unwrap();
            // This malformed and other-document entry must not inflate the
            // scoped corruption count.
            connection
                .execute(
                    "INSERT INTO corrupt_objects(kind,id,code,detected_at) VALUES(?1,?2,?3,?4)",
                    rusqlite::params![
                        "ai_draft",
                        &malformed_short,
                        "test_corrupt",
                        crate::now() as i64
                    ],
                )
                .unwrap();
        }

        reset_plaintext_decryptions();
        let first = store.draft_conflicts_page(base, None, 2).unwrap();
        assert_eq!(plaintext_decryptions(), 0);
        assert_eq!(first.total, 3);
        assert_eq!(first.corrupt_count, 1);
        assert_eq!(first.items.len(), 2);
        assert_eq!(first.items[0]["id"], third_id);
        assert_eq!(first.items[0]["revision"], 3);
        assert_eq!(first.items[0]["updated_at"], 11);
        assert_eq!(first.items[1]["id"], second_id);
        assert!(first.items[0].get("content").is_none());
        assert_eq!(first.items[0].as_object().unwrap().len(), 3);

        let second = store
            .draft_conflicts_page(base, first.next_cursor.as_deref(), 2)
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0]["id"], first_id);
        assert!(second.next_cursor.is_none());

        let foreign_cursor = encode_cursor(12, &large_id);
        assert_eq!(
            store
                .draft_conflicts_page(base, Some(&foreign_cursor), 2)
                .err()
                .expect("foreign cursor must be rejected")
                .code,
            "invalid_pagination"
        );
        assert_eq!(
            store
                .draft_conflicts_page(base, Some("not-a-cursor"), 2)
                .err()
                .expect("malformed cursor must be rejected")
                .code,
            "invalid_pagination"
        );
        assert_eq!(
            store
                .draft_conflicts_page("writing-", None, 2)
                .err()
                .expect("invalid base must be rejected")
                .code,
            "invalid_ai_request"
        );
        assert_eq!(
            store
                .draft_conflicts_page(base, None, 0)
                .err()
                .expect("invalid page size must be rejected")
                .code,
            "invalid_pagination"
        );
    }

    #[test]
    fn ai_run_summary_binds_writing_document_identity_and_hides_it_for_other_runs() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let base = json!({
            "kind":"writing","status":"completed","stage":"done","title":"draft",
            "request":{"context_revision":1},"revision":1,
        });
        store.save("ai_run", "legacy-run", &base).unwrap();
        assert_eq!(
            store.summary("ai_run", "legacy-run").unwrap()["document_id"],
            "legacy-run"
        );

        let mut current = base;
        current["document_id"] = json!("document-stable");
        store.save("ai_run", "new-run", &current).unwrap();
        assert_eq!(
            store.summary("ai_run", "new-run").unwrap()["document_id"],
            "document-stable"
        );

        let other = json!({
            "kind":"search","status":"completed","stage":"done","title":"search",
            "document_id":"must-not-be-exposed","request":{"context_revision":1},"revision":1,
        });
        store.save("ai_run", "search-run", &other).unwrap();
        assert!(store.summary("ai_run", "search-run").unwrap()["document_id"].is_null());
    }

    #[test]
    fn empty_queue_does_not_decrypt_and_claim_updates_body_summary_and_index_together() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        reset_plaintext_decryptions();
        assert!(store.next_queued_material().unwrap().is_none());
        assert_eq!(plaintext_decryptions(), 0);

        store
            .save(
                "material",
                "mat_claim",
                &queued_material("mat_claim", "queued"),
            )
            .unwrap();
        reset_plaintext_decryptions();
        assert_eq!(
            store.next_queued_material().unwrap(),
            Some(("mat_claim".into(), "grp_index".into()))
        );
        assert_eq!(plaintext_decryptions(), 0);
        let claimed = store
            .claim_queued_material("mat_claim", 9)
            .unwrap()
            .unwrap();
        assert_eq!(plaintext_decryptions(), 1);
        assert_eq!(claimed.status, "running");
        assert_eq!(claimed.dictionary_revision, 9);
        assert!(store.next_queued_material().unwrap().is_none());
        assert_eq!(
            store.summary("material", "mat_claim").unwrap()["status"],
            "running"
        );
    }

    #[test]
    fn decoded_json_failure_is_quarantined_instead_of_leaking_as_empty_data() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        store
            .put_many(vec![Store::encoded_raw(
                "json_test",
                "bad_json",
                b"not JSON",
            )
            .unwrap()])
            .unwrap();
        assert_eq!(
            store
                .get::<Value>("json_test", "bad_json")
                .unwrap_err()
                .code,
            "storage_object_corrupt"
        );
        assert_eq!(store.corrupt_count(Some("json_test")).unwrap(), 1);
    }

    #[test]
    fn missing_optional_summary_is_not_quarantined_as_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        assert_eq!(
            store
                .maybe_summary("ai_stage", "mat_without_stage")
                .unwrap(),
            None
        );
        assert_eq!(store.corrupt_count(Some("ai_stage")).unwrap(), 0);

        store
            .save(
                "material",
                "mat_summary",
                &queued_material("mat_summary", "queued"),
            )
            .unwrap();
        {
            let connection = store.connection().unwrap();
            connection
                .execute(
                    "DELETE FROM object_summaries WHERE kind='material' AND id='mat_summary'",
                    [],
                )
                .unwrap();
        }
        let error = match store.summary_page("material", None, None, None, 10) {
            Ok(_) => panic!("missing summary must not be omitted from a page"),
            Err(error) => error,
        };
        assert_eq!(error.code, "storage_object_corrupt");
        assert_eq!(store.corrupt_count(Some("material")).unwrap(), 1);
    }

    #[test]
    fn failed_summary_write_rolls_back_object_and_index_as_one_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        {
            let connection = store.connection().unwrap();
            connection
                .execute_batch(
                    "CREATE TRIGGER fail_material_summary BEFORE INSERT ON object_summaries
                     WHEN NEW.kind='material' BEGIN SELECT RAISE(ABORT,'forced'); END;",
                )
                .unwrap();
        }
        assert!(store
            .save(
                "material",
                "mat_rollback",
                &queued_material("mat_rollback", "queued")
            )
            .is_err());
        let connection = store.connection().unwrap();
        for table in ["objects", "object_index", "object_summaries"] {
            let count: i64 = connection
                .query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {table} WHERE kind='material' AND id='mat_rollback'"
                    ),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{table} rolls back");
        }
    }
}
