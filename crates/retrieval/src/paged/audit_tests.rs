//! Adversarial lifecycle checks for the paged-search cache.
//!
//! This module deliberately exercises the private flight and cancellation guards
//! with a real on-disk SQLite corpus. Production includes it only during tests.

use super::*;
use rusqlite::{functions::FunctionFlags, Connection, ErrorCode};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{atomic::Ordering, mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

fn cacheable_fixture(path: &Path, article_id: &str, article_content: &str) -> Connection {
    let connection = Connection::open(path).expect("fixture database opens");
    connection
        .execute_batch(
            "
            CREATE TABLE issuing_authorities(id TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE law_documents(id TEXT PRIMARY KEY, title TEXT NOT NULL, document_type TEXT NOT NULL, authority_id TEXT NOT NULL, jurisdiction TEXT NOT NULL, effectiveness_level TEXT NOT NULL, status TEXT NOT NULL, promulgated_on TEXT, summary TEXT NOT NULL);
            CREATE TABLE law_versions(id TEXT PRIMARY KEY, document_id TEXT NOT NULL, version_label TEXT NOT NULL, status TEXT NOT NULL, effective_from TEXT NOT NULL, effective_to TEXT, published_on TEXT, source_reference TEXT NOT NULL);
            CREATE TABLE law_articles(id TEXT PRIMARY KEY, document_id TEXT NOT NULL, version_id TEXT NOT NULL, article_number TEXT NOT NULL, article_order INTEGER NOT NULL, title TEXT, content TEXT NOT NULL);
            CREATE TABLE law_aliases(id TEXT PRIMARY KEY, document_id TEXT NOT NULL, alias TEXT NOT NULL, normalized_alias TEXT NOT NULL);
            CREATE TABLE citation_metadata(article_id TEXT PRIMARY KEY, citation_id TEXT NOT NULL, canonical_label TEXT NOT NULL);
            CREATE TABLE database_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO issuing_authorities VALUES ('npc','全国人大');
            INSERT INTO law_documents VALUES ('test-law','缓存隔离测试法','law','npc','CN','national_law','in_force','2023-12-29','缓存隔离测试');
            INSERT INTO law_versions VALUES ('test-law-v1','test-law','现行版','in_force','2024-01-01',NULL,'2023-12-29','audit-fixture');
            INSERT INTO law_aliases VALUES ('test-law-alias','test-law','缓存隔离测试法','缓存隔离测试法');
            INSERT INTO database_metadata VALUES
              ('schema_version', '4'),
              ('runtime_schema_version', '1'),
              ('dataset_version', 'identical-metadata'),
              ('source_manifest_sha256', 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
            ",
        )
        .expect("fixture schema initializes");
    connection
        .execute(
            "INSERT INTO law_articles VALUES (?1, 'test-law', 'test-law-v1', '第一条', 1, NULL, ?2)",
            (article_id, article_content),
        )
        .expect("fixture article initializes");
    connection
}

fn cache_request() -> PagedSearchRequest {
    PagedSearchRequest {
        query: "隔离检索词".to_owned(),
        match_mode: SearchMatchMode::All,
        version_scope: VersionScope::Current,
        view: SearchView::Flat,
        document_id: None,
        case_date: None,
        limit: 20,
        offset: 0,
        document_type: None,
        effectiveness_level: None,
        jurisdiction: None,
        status: None,
        version_status: None,
        sort: SearchSort::Relevance,
    }
}

fn cache_key(connection: &Connection, request: &PagedSearchRequest) -> SearchCacheKey {
    SearchCacheKey::new(
        search_cache_identity(connection, None, request)
            .expect("cache identity reads")
            .expect("on-disk fixture is cacheable"),
        request,
    )
}

fn registered_handle_count(cancellation: &SearchCancellation) -> usize {
    cancellation
        .inner
        .handles
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len()
}

fn wait_for_waiter_subscription(flight: &SearchFlight) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while flight.subscribers.load(Ordering::Acquire) < 2 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    assert!(
        flight.subscribers.load(Ordering::Acquire) >= 2,
        "waiter did not attach to the owner flight before its release"
    );
}

enum OwnerExit {
    Error,
    Cancel,
    Panic,
}

/// A direct guard-level barrier is required here: the production owner may
/// return an SQLite error, be cancelled after a subscriber arrives, or unwind
/// before publishing. In all three cases the existing waiter must be woken,
/// reclaim the flight, execute the real SQLite page search, and finish.
fn assert_waiter_retries_after_owner_exit(exit: OwnerExit) {
    let directory = tempfile::tempdir().expect("temporary corpus directory");
    let path = directory.path().join("legal_core.sqlite");
    let owner_connection = cacheable_fixture(&path, "owner-retry-a1", "隔离检索词：等待者可完成。");
    let request = cache_request();
    let key = cache_key(&owner_connection, &request);
    let owner = SearchCancellation::new();
    let flight = match search_cache_probe(&key, &owner).expect("owner is admitted") {
        CacheProbe::Owner(flight, _) => flight,
        CacheProbe::Hit(_, _) => panic!("new fixture key must not be cached"),
    };

    let waiter_path: PathBuf = path.clone();
    let waiter_request = request.clone();
    let (result_tx, result_rx) = mpsc::channel();
    let waiter = thread::spawn(move || {
        let connection = Connection::open(waiter_path).expect("waiter database opens");
        result_tx
            .send(search_page_cancellable(
                &connection,
                None,
                waiter_request,
                &SearchCancellation::new(),
            ))
            .expect("waiter reports");
    });
    wait_for_waiter_subscription(&flight);

    match exit {
        OwnerExit::Error => {
            let guard = SearchFlightGuard::new(Some(key.clone()), &owner, Some(flight.clone()));
            let failure: Result<(), RetrievalError> = Err(RetrievalError::InvalidRequest(
                "forced owner failure".to_owned(),
            ));
            assert!(matches!(failure, Err(RetrievalError::InvalidRequest(_))));
            drop(guard);
        }
        OwnerExit::Cancel => {
            let guard = SearchFlightGuard::new(Some(key.clone()), &owner, Some(flight.clone()));
            owner.cancel();
            drop(guard);
        }
        OwnerExit::Panic => {
            let unwind = catch_unwind(AssertUnwindSafe(|| {
                let _guard =
                    SearchFlightGuard::new(Some(key.clone()), &owner, Some(flight.clone()));
                panic!("forced owner unwind after cache admission");
            }));
            assert!(unwind.is_err(), "owner unwind must be observed by the test");
        }
    }

    let response = result_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("surviving waiter must be woken and complete")
        .expect("surviving waiter search succeeds");
    assert_eq!(response.total, 1);
    assert_eq!(response.articles[0].article_id, "owner-retry-a1");
    waiter.join().expect("waiter thread joins");

    let (cache, _) = search_cache();
    assert!(
        !cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .in_flight
            .contains_key(&key),
        "retry owner must remove its flight after completion"
    );
}

#[test]
fn waiter_retries_after_owner_error_and_completes() {
    assert_waiter_retries_after_owner_exit(OwnerExit::Error);
}

#[test]
fn waiter_retries_after_owner_cancellation_and_completes() {
    assert_waiter_retries_after_owner_exit(OwnerExit::Cancel);
}

#[test]
fn waiter_retries_after_owner_panic_and_completes() {
    assert_waiter_retries_after_owner_exit(OwnerExit::Panic);
}

fn registered_operation_that_errors(
    cancellation: &SearchCancellation,
    first: &Connection,
    second: &Connection,
) -> Result<(), RetrievalError> {
    let _first_registration = cancellation.register_connection(first)?;
    let _second_registration = cancellation.register_connection(second)?;
    Err(RetrievalError::InvalidRequest(
        "forced post-registration error".to_owned(),
    ))
}

#[test]
fn multiple_interrupt_handles_are_cleared_after_error() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let first = Connection::open(directory.path().join("first.sqlite")).expect("first opens");
    let second = Connection::open(directory.path().join("second.sqlite")).expect("second opens");
    let cancellation = SearchCancellation::new();

    let error = registered_operation_that_errors(&cancellation, &first, &second).unwrap_err();
    assert!(matches!(error, RetrievalError::InvalidRequest(_)));
    assert_eq!(
        registered_handle_count(&cancellation),
        0,
        "the RAII guard must clear every registered connection after an error"
    );

    cancellation.cancel();
    assert_eq!(
        first
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        second
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn multiple_interrupt_handles_are_cleared_after_panic() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let first = Connection::open(directory.path().join("first.sqlite")).expect("first opens");
    let second = Connection::open(directory.path().join("second.sqlite")).expect("second opens");
    let cancellation = SearchCancellation::new();

    let unwind = catch_unwind(AssertUnwindSafe(|| {
        let _first_registration = cancellation
            .register_connection(&first)
            .expect("first handle registers");
        let _second_registration = cancellation
            .register_connection(&second)
            .expect("second handle registers");
        panic!("forced post-registration unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(
        registered_handle_count(&cancellation),
        0,
        "the RAII guard must clear every registered connection after unwind"
    );

    cancellation.cancel();
    assert_eq!(
        first
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        second
            .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn active_recursive_sql_is_interrupted_and_its_registration_is_released() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("interruptible.sqlite");
    let cancellation = SearchCancellation::new();
    let worker_cancellation = cancellation.clone();
    let (registered_tx, registered_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Arc::new(Mutex::new(release_rx));

    let worker = thread::spawn(move || {
        let connection = Connection::open(path).expect("worker database opens");
        let _registration = worker_cancellation
            .register_connection(&connection)
            .expect("worker handle registers");
        registered_tx.send(()).expect("worker reports registration");

        let release_rx = Arc::clone(&release_rx);
        connection
            .create_scalar_function(
                "audit_wait_until_cancel",
                0,
                FunctionFlags::SQLITE_UTF8,
                move |_| {
                    started_tx.send(()).expect("query reached scalar barrier");
                    release_rx
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .recv_timeout(Duration::from_secs(2))
                        .expect("test releases scalar barrier");
                    Ok(1_i64)
                },
            )
            .expect("scalar barrier registers");

        connection.query_row(
            "\
WITH RECURSIVE counter(value) AS (
    SELECT audit_wait_until_cancel()
    UNION ALL
    SELECT value + 1 FROM counter WHERE value < 1000000000
)
SELECT sum(value) FROM counter",
            [],
            |row| row.get::<_, i64>(0),
        )
    });

    registered_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("worker registers before cancellation");
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("recursive SQL starts before cancellation");
    cancellation.cancel();
    release_tx
        .send(())
        .expect("release reaches SQL scalar barrier");

    let error = worker
        .join()
        .expect("worker joins")
        .expect_err("active recursive SQL must be interrupted");
    assert!(matches!(
        error,
        rusqlite::Error::SqliteFailure(ref failure, _)
            if failure.code == ErrorCode::OperationInterrupted
    ));
    assert_eq!(
        registered_handle_count(&cancellation),
        0,
        "the interrupted operation must release its own registration"
    );
}

#[test]
fn matching_metadata_on_distinct_database_files_never_share_cached_pages() {
    let directory = tempfile::tempdir().expect("temporary corpus directory");
    let first_path = directory.path().join("first.sqlite");
    let second_path = directory.path().join("second.sqlite");
    let first = cacheable_fixture(
        &first_path,
        "first-db-a1",
        "隔离检索词：第一份数据库的独有正文。",
    );
    let second = cacheable_fixture(
        &second_path,
        "second-db-a1",
        "隔离检索词：第二份数据库的独有正文。",
    );
    let request = cache_request();

    let first_response = search_page(&first, None, request.clone()).expect("first search succeeds");
    assert!(!first_response.metrics.cache_hit);
    assert_eq!(first_response.articles[0].article_id, "first-db-a1");

    let second_response = search_page(&second, None, request).expect("second search succeeds");
    assert!(
        !second_response.metrics.cache_hit,
        "the second physical corpus must not consume the first corpus cache page"
    );
    assert_eq!(second_response.total, 1);
    assert_eq!(second_response.articles[0].article_id, "second-db-a1");
    assert!(
        second_response.articles[0].snippet.contains("第二份数据库"),
        "the returned page must contain the second corpus content, not a cached first-corpus row"
    );
}

#[test]
fn count_cache_reuses_logical_search_across_view_and_page_boundary() {
    let directory = tempfile::tempdir().expect("temporary corpus directory");
    let path = directory.path().join("legal_core.sqlite");
    let connection = cacheable_fixture(&path, "count-cache-a1", "隔离检索词：计数缓存复用。");
    let first_request = cache_request();

    let first = search_page(&connection, None, first_request).expect("flat first page succeeds");
    assert!(!first.metrics.count_cache_hit);
    assert_eq!(first.total, 1);

    let mut grouped_second_page = cache_request();
    grouped_second_page.view = SearchView::Grouped;
    grouped_second_page.limit = 1;
    grouped_second_page.offset = 1;
    let grouped =
        search_page(&connection, None, grouped_second_page).expect("grouped second page succeeds");

    assert!(
        grouped.metrics.count_cache_hit,
        "count cache key must omit view, limit, and offset for the same logical search"
    );
    assert_eq!(grouped.total, first.total);
    assert_eq!(grouped.total_laws, first.total_laws);
    assert_eq!(grouped.total_articles, first.total_articles);
}
