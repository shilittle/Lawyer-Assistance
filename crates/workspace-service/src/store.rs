use crate::{Error, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    sync::{Mutex, MutexGuard},
};
use zeroize::Zeroizing;

const CHUNK: usize = 4 * 1024 * 1024;
const MAX_OBJECT: usize = 64 * 1024 * 1024;

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
        let connection = Connection::open(db)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; CREATE TABLE IF NOT EXISTS web_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS objects(kind TEXT NOT NULL,id TEXT NOT NULL,body BLOB NOT NULL,PRIMARY KEY(kind,id)); INSERT OR IGNORE INTO web_metadata VALUES('schema','web-workspace-v1');")?;
        let schema: String = connection.query_row(
            "SELECT value FROM web_metadata WHERE key='schema'",
            [],
            |r| r.get(0),
        )?;
        if schema != "web-workspace-v1" && schema != "web-workspace-v2" {
            return Err(Error::new("unsupported_workspace_schema"));
        }
        if schema == "web-workspace-v1" {
            let count: i64 =
                connection.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
            if count > 0 {
                create_v1_backup(&connection, root)?;
            }
            connection.execute_batch("BEGIN IMMEDIATE; UPDATE web_metadata SET value='web-workspace-v2' WHERE key='schema'; COMMIT;")?;
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
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub fn maybe<T: DeserializeOwned>(&self, kind: &str, id: &str) -> Result<Option<T>> {
        match self.get(kind, id) {
            Ok(x) => Ok(Some(x)),
            Err(e) if e.code == "not_found" => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub fn list<T: DeserializeOwned>(&self, kind: &str) -> Result<Vec<T>> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT id,body FROM objects WHERE kind=?1 ORDER BY id")?;
        let records = statement.query_map([kind], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut output = Vec::new();
        for row in records {
            let (id, body) = row?;
            output.push(serde_json::from_slice(&open(kind, &id, &body)?)?);
        }
        Ok(output)
    }
    pub fn raw(&self, kind: &str, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let body: Option<Vec<u8>> = self
            .connection()?
            .query_row(
                "SELECT body FROM objects WHERE kind=?1 AND id=?2",
                [kind, id],
                |r| r.get(0),
            )
            .optional()?;
        open(kind, id, &body.ok_or_else(|| Error::new("not_found"))?)
    }
    pub fn save<T: Serialize>(&self, kind: &str, id: &str, value: &T) -> Result<()> {
        let data = Zeroizing::new(serde_json::to_vec(value)?);
        self.put_many(vec![(
            kind.to_owned(),
            id.to_owned(),
            seal(kind, id, &data)?,
        )])
    }
    pub fn encoded_raw(kind: &str, id: &str, value: &[u8]) -> Result<(String, String, Vec<u8>)> {
        Ok((kind.into(), id.into(), seal(kind, id, value)?))
    }
    pub fn encoded<T: Serialize>(
        kind: &str,
        id: &str,
        value: &T,
    ) -> Result<(String, String, Vec<u8>)> {
        let data = Zeroizing::new(serde_json::to_vec(value)?);
        Ok((kind.into(), id.into(), seal(kind, id, &data)?))
    }
    pub fn put_many(&self, rows: Vec<(String, String, Vec<u8>)>) -> Result<()> {
        let mut connection = self.connection()?;
        let tx = connection.transaction()?;
        for (kind, id, body) in rows {
            tx.execute("INSERT INTO objects(kind,id,body) VALUES(?1,?2,?3) ON CONFLICT(kind,id) DO UPDATE SET body=excluded.body",rusqlite::params![kind,id,body])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn delete(&self, kind: &str, id: &str) -> Result<()> {
        self.connection()?
            .execute("DELETE FROM objects WHERE kind=?1 AND id=?2", [kind, id])?;
        Ok(())
    }
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
}
