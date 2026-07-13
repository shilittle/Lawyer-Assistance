use domain::law::SearchLawsRequest;
use rusqlite::OptionalExtension;
use std::{env, path::PathBuf};

const FORMAL_DATABASE_ENV: &str = "LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE";
const EXPECTED_DATASET_VERSION: &str = "2026.07.11-stage1c.1";

fn formal_connection() -> rusqlite::Connection {
    let path = env::var_os(FORMAL_DATABASE_ENV)
        .map(PathBuf::from)
        .expect("set LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE to the audited Stage 1C database");
    let connection = database::open_legal_core_read_only(path).expect("formal database opens");
    let dataset_version: String = connection
        .query_row(
            "SELECT value FROM database_metadata WHERE key = 'dataset_version'",
            [],
            |row| row.get(0),
        )
        .expect("formal database has a dataset version");
    assert_eq!(dataset_version, EXPECTED_DATASET_VERSION);
    connection
}

#[test]
#[ignore = "requires the audited multi-gigabyte Stage 1C legal database"]
fn formal_law_search_excludes_future_and_expired_versions_from_current_version() {
    let connection = formal_connection();
    let today: String = connection
        .query_row("SELECT date('now', 'localtime')", [], |row| row.get(0))
        .expect("SQLite returns the local date");

    let future_probe: Option<(String, String, String)> = connection
        .query_row(
            "
            SELECT documents.id, documents.title, versions.id
            FROM law_versions versions
            JOIN law_documents documents ON documents.id = versions.document_id
            WHERE versions.status = 'not_yet_effective'
              AND versions.effective_from > date('now', 'localtime')
              AND (
                SELECT COUNT(*) FROM law_documents same_title
                WHERE same_title.title = documents.title
              ) = 1
            ORDER BY versions.effective_from, versions.id
            LIMIT 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .expect("future-version probe is queryable");
    let (future_document_id, future_title, future_version_id) =
        future_probe.expect("formal snapshot contains a declared future version");
    let future_search = retrieval::search_laws(
        &connection,
        SearchLawsRequest {
            query: future_title,
            limit: Some(50),
        },
    )
    .expect("formal law search succeeds");
    let future_document = future_search
        .results
        .iter()
        .find(|result| result.document_id == future_document_id)
        .expect("future-version document appears in title search");
    assert_ne!(
        future_document.current_version_id.as_deref(),
        Some(future_version_id.as_str())
    );
    assert!(
        future_document
            .current_effective_from
            .as_deref()
            .map(|effective_from| effective_from <= today.as_str())
            .unwrap_or(true),
        "law search exposed a future effective date as current"
    );

    let expired_probe: (String, String) = connection
        .query_row(
            "
            SELECT documents.id, documents.title
            FROM law_documents documents
            WHERE EXISTS (
                SELECT 1 FROM law_versions versions
                WHERE versions.document_id = documents.id
            )
              AND NOT EXISTS (
                SELECT 1 FROM law_versions versions
                WHERE versions.document_id = documents.id
                  AND versions.effective_from <= date('now', 'localtime')
                  AND (
                    versions.effective_to IS NULL
                    OR versions.effective_to >= date('now', 'localtime')
                  )
                  AND versions.status <> 'not_yet_effective'
              )
              AND (
                SELECT COUNT(*) FROM law_documents same_title
                WHERE same_title.title = documents.title
              ) = 1
            ORDER BY documents.id
            LIMIT 1
            ",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("formal snapshot contains a fully expired document");
    let expired_search = retrieval::search_laws(
        &connection,
        SearchLawsRequest {
            query: expired_probe.1,
            limit: Some(50),
        },
    )
    .expect("expired law title search succeeds");
    let expired_document = expired_search
        .results
        .iter()
        .find(|result| result.document_id == expired_probe.0)
        .expect("expired document appears in title search");
    assert!(expired_document.current_version_id.is_none());
}
