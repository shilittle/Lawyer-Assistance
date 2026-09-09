use crate::{filesystem::PathIdentityGuard, LegalServices, ServiceError, SERVICE_SCHEMA_VERSION};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};

const LEGAL_ARCHIVE_SCHEMA_VERSION: &str = "4";
const LEGAL_RUNTIME_SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseStatus {
    pub available: bool,
    pub schema_version: Option<String>,
    pub runtime_schema_version: Option<String>,
    pub dataset_name: Option<String>,
    pub dataset_version: Option<String>,
    pub distribution_profile: Option<String>,
    pub error: Option<ServiceError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemStatusResponse {
    pub schema_version: u16,
    pub status: String,
    pub legal_database: DatabaseStatus,
    pub user_database: DatabaseStatus,
    pub file_policy: FilePolicyStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilePolicyStatus {
    pub allowed_file_root_count: usize,
    pub output_root_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct LegalDatabaseIdentity {
    pub schema_version: String,
    pub runtime_schema_version: Option<String>,
    pub dataset_name: Option<String>,
    pub dataset_version: Option<String>,
    pub distribution_profile: Option<String>,
}

impl LegalDatabaseIdentity {
    pub(crate) fn public_version(&self) -> String {
        self.dataset_version
            .clone()
            .unwrap_or_else(|| format!("schema-{}", self.schema_version))
    }
}

impl LegalServices {
    pub fn system_status(&self) -> Result<SystemStatusResponse, ServiceError> {
        let legal = match open_validated_legal_database(self.legal_core_path()) {
            Ok((_, identity)) => DatabaseStatus {
                available: true,
                schema_version: Some(identity.schema_version),
                runtime_schema_version: identity.runtime_schema_version,
                dataset_name: identity.dataset_name,
                dataset_version: identity.dataset_version,
                distribution_profile: identity.distribution_profile,
                error: None,
            },
            Err(error) => DatabaseStatus {
                available: false,
                schema_version: None,
                runtime_schema_version: None,
                dataset_name: None,
                dataset_version: None,
                distribution_profile: None,
                error: Some(error),
            },
        };
        let user = if self.is_public_law_only() {
            // Public-law MCP deliberately has no private workspace.  Preserve
            // the wire DTO while making the absence explicit without probing
            // a path or making legal readiness degraded.
            DatabaseStatus {
                available: false,
                schema_version: None,
                runtime_schema_version: None,
                dataset_name: None,
                dataset_version: None,
                distribution_profile: None,
                error: None,
            }
        } else {
            match open_validated_user_database_read_only(self.user_database_path()) {
                Ok(connection) => {
                    let version = connection
                        .query_row(
                            "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                            [],
                            |row| row.get::<_, String>(0),
                        )
                        .ok();
                    DatabaseStatus {
                        available: true,
                        schema_version: version,
                        runtime_schema_version: None,
                        dataset_name: None,
                        dataset_version: None,
                        distribution_profile: None,
                        error: None,
                    }
                }
                Err(error) => DatabaseStatus {
                    available: false,
                    schema_version: None,
                    runtime_schema_version: None,
                    dataset_name: None,
                    dataset_version: None,
                    distribution_profile: None,
                    error: Some(error),
                },
            }
        };
        Ok(SystemStatusResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            status: if legal.available && (self.is_public_law_only() || user.available) {
                "ready"
            } else {
                "degraded"
            }
            .to_owned(),
            legal_database: legal,
            user_database: user,
            file_policy: FilePolicyStatus {
                allowed_file_root_count: self.config().allowed_file_roots.len(),
                output_root_available: self.output_root().is_dir(),
            },
        })
    }
}

pub(crate) fn open_validated_user_database_read_only(
    path: &Path,
) -> Result<rusqlite::Connection, ServiceError> {
    require_regular_database_file(path, "user_database_missing")?;
    let guard = PathIdentityGuard::regular_file(path, true)?;
    let connection = database::open_user_database_read_only(path)?;
    guard.verify()?;
    database::validate_open_user_database(&connection)?;
    guard.verify()?;
    Ok(connection)
}

pub(crate) fn open_validated_user_database_write(
    path: &Path,
) -> Result<rusqlite::Connection, ServiceError> {
    require_regular_database_file(path, "user_database_missing")?;
    let guard = PathIdentityGuard::regular_file(path, true)?;
    let connection = database::open_existing_user_database(path)?;
    guard.verify()?;
    database::validate_open_user_database(&connection)?;
    guard.verify()?;
    Ok(connection)
}

pub(crate) fn open_validated_legal_database(
    path: &Path,
) -> Result<(rusqlite::Connection, LegalDatabaseIdentity), ServiceError> {
    require_regular_database_file(path, "legal_database_missing")?;
    let guard = PathIdentityGuard::regular_file(path, true)?;
    let connection = database::open_legal_core_read_only(path)?;
    guard.verify()?;
    let identity = inspect_legal_database(&connection)?;
    guard.verify()?;
    Ok((connection, identity))
}

fn require_regular_database_file(
    path: &Path,
    missing_code: &'static str,
) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ServiceError::new(
            missing_code,
            "configured database file is missing or inaccessible",
            false,
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ServiceError::new(
            "database_path_rejected",
            "configured database path must name a regular non-symlink file",
            false,
        ));
    }
    Ok(())
}

fn inspect_legal_database(
    connection: &rusqlite::Connection,
) -> Result<LegalDatabaseIdentity, ServiceError> {
    let metadata_table: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'database_metadata')",
        [],
        |row| row.get(0),
    )?;
    if !metadata_table {
        return Err(ServiceError::new(
            "legal_database_incompatible",
            "legal database metadata table is missing",
            false,
        ));
    }
    let mut statement = connection.prepare("SELECT key, value FROM database_metadata")?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    let schema_version = entries.get("schema_version").cloned().ok_or_else(|| {
        ServiceError::new(
            "legal_database_incompatible",
            "legal database schema version is missing",
            false,
        )
    })?;
    if schema_version != LEGAL_ARCHIVE_SCHEMA_VERSION {
        return Err(ServiceError::new(
            "legal_database_incompatible",
            "legal database schema version is not supported",
            false,
        )
        .with_details(serde_json::json!({
            "found": schema_version,
            "supported": LEGAL_ARCHIVE_SCHEMA_VERSION,
        })));
    }
    let runtime_schema_version = entries.get("runtime_schema_version").cloned();
    if runtime_schema_version
        .as_deref()
        .is_some_and(|version| version != LEGAL_RUNTIME_SCHEMA_VERSION)
    {
        return Err(ServiceError::new(
            "legal_database_incompatible",
            "legal runtime database schema version is not supported",
            false,
        )
        .with_details(serde_json::json!({
            "found": runtime_schema_version,
            "supported": LEGAL_RUNTIME_SCHEMA_VERSION,
        })));
    }
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if runtime_schema_version.is_some() && user_version != 1 {
        return Err(ServiceError::new(
            "legal_database_incompatible",
            "legal runtime database PRAGMA user_version is inconsistent",
            false,
        ));
    }

    for table in [
        "issuing_authorities",
        "law_documents",
        "law_versions",
        "law_aliases",
        "citation_metadata",
        "law_relations",
        "legal_topics",
        "article_topics",
        "law_articles_fts",
    ] {
        require_legal_database_object(connection, table, "table")?;
    }
    if runtime_schema_version.is_some() {
        require_legal_database_object(connection, "law_articles", "view")?;
        require_legal_database_object(connection, "law_article_rows", "table")?;
        require_legal_database_object(connection, "law_article_contents", "table")?;
    } else {
        require_legal_database_object(connection, "law_articles", "table")?;
    }

    Ok(LegalDatabaseIdentity {
        schema_version,
        runtime_schema_version,
        dataset_name: entries.get("dataset_name").cloned(),
        dataset_version: entries.get("dataset_version").cloned(),
        distribution_profile: entries.get("distribution_profile").cloned(),
    })
}

fn require_legal_database_object(
    connection: &rusqlite::Connection,
    name: &str,
    expected_type: &str,
) -> Result<(), ServiceError> {
    let actual_type = connection
        .query_row(
            "SELECT type FROM sqlite_master WHERE name = ?1",
            [name],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if actual_type.as_deref() == Some(expected_type) {
        return Ok(());
    }
    Err(ServiceError::new(
        "legal_database_incompatible",
        "legal database is missing a required relation or its type is invalid",
        false,
    )
    .with_details(serde_json::json!({
        "relation": name,
        "expectedType": expected_type,
        "foundType": actual_type,
    })))
}

#[cfg(test)]
mod tests {
    use crate::LegalServices;

    #[test]
    fn public_status_does_not_require_or_open_a_user_database() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let legal_path = temporary.path().join("missing-legal-core.sqlite");
        let services = LegalServices::new_public(legal_path).expect("public service initializes");
        let status = services.system_status().expect("status response");
        assert!(!status.legal_database.available);
        assert!(!status.user_database.available);
        assert!(status.user_database.error.is_none());
    }
}
