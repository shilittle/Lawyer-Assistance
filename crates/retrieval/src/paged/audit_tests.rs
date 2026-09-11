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

#[test]
fn page_cache_hit_does_not_reuse_owner_index_work_or_fallback_reason() {
    let directory = tempfile::tempdir().expect("temporary corpus directory");
    let path = directory.path().join("legal_core.sqlite");
    let connection = cacheable_fixture(&path, "metrics-cache-a1", "隔离检索词：指标缓存测试。");
    let request = cache_request();

    let first = search_page(&connection, None, request.clone()).expect("first metrics search");
    assert!(!first.metrics.cache_hit);
    assert!(first.metrics.index_fallback);
    assert_eq!(
        first.metrics.index_fallback_reason.as_deref(),
        Some(FALLBACK_REASON_INDEX_UNAVAILABLE)
    );

    let cached = search_page(&connection, None, request).expect("cached metrics search");
    assert!(cached.metrics.cache_hit);
    assert_eq!(cached.metrics.candidate_count, 0);
    assert!(!cached.metrics.index_fallback);
    assert_eq!(cached.metrics.index_fallback_reason, None);
    assert_eq!(cached.metrics.index_ms, 0);
    assert_eq!(cached.metrics.count_ms, 0);
    assert_eq!(cached.metrics.page_ms, 0);
}

#[test]
fn page_cache_hit_does_not_reuse_owner_count_cache_hit() {
    let directory = tempfile::tempdir().expect("temporary corpus directory");
    let path = directory.path().join("legal_core.sqlite");
    let connection = cacheable_fixture(
        &path,
        "metrics-count-cache-a1",
        "隔离检索词：计数缓存命中状态。",
    );

    let mut second_page_request = cache_request();
    second_page_request.query = "计数缓存命中状态".to_owned();
    second_page_request.limit = 1;
    second_page_request.offset = 1;
    let second_page = search_page(&connection, None, second_page_request)
        .expect("second page seeds the logical count cache");
    assert!(!second_page.metrics.cache_hit);
    assert!(!second_page.metrics.count_cache_hit);

    let mut first_page_request = cache_request();
    first_page_request.query = "计数缓存命中状态".to_owned();
    first_page_request.limit = 1;
    let owner = search_page(&connection, None, first_page_request.clone())
        .expect("first page uses the count cache and owns its page flight");
    assert!(!owner.metrics.cache_hit);
    assert!(owner.metrics.count_cache_hit);

    let cached = search_page(&connection, None, first_page_request)
        .expect("repeated first page is served from the page cache");
    assert!(cached.metrics.cache_hit);
    assert!(
        !cached.metrics.count_cache_hit,
        "page-cache hits did not read the count cache during this request"
    );
}

fn r05_ranking_fixture() -> Connection {
    let connection = Connection::open_in_memory().expect("ranking fixture opens");
    connection
        .execute_batch(
            "
            CREATE TABLE issuing_authorities(id TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE law_documents(id TEXT PRIMARY KEY, title TEXT NOT NULL, document_type TEXT NOT NULL, authority_id TEXT NOT NULL, jurisdiction TEXT NOT NULL, effectiveness_level TEXT NOT NULL, status TEXT NOT NULL, promulgated_on TEXT, summary TEXT NOT NULL);
            CREATE TABLE law_versions(id TEXT PRIMARY KEY, document_id TEXT NOT NULL, version_label TEXT NOT NULL, status TEXT NOT NULL, effective_from TEXT NOT NULL, effective_to TEXT, published_on TEXT, source_reference TEXT NOT NULL);
            CREATE TABLE law_articles(id TEXT PRIMARY KEY, document_id TEXT NOT NULL, version_id TEXT NOT NULL, article_number TEXT NOT NULL, article_order INTEGER NOT NULL, title TEXT, content TEXT NOT NULL);
            CREATE TABLE law_aliases(id TEXT PRIMARY KEY, document_id TEXT NOT NULL, alias TEXT NOT NULL, normalized_alias TEXT NOT NULL);
            CREATE TABLE citation_metadata(article_id TEXT PRIMARY KEY, citation_id TEXT NOT NULL, canonical_label TEXT NOT NULL);
            INSERT INTO issuing_authorities VALUES ('npc','全国人大');
            INSERT INTO law_documents VALUES ('civil-code','中华人民共和国民法典','law','npc','CN','national_law','in_force','2020-05-28','民事法律规范');
            INSERT INTO law_documents VALUES ('labor-contract','劳动合同法','law','npc','CN','national_law','in_force','2007-06-29','劳动合同法律规范');
            INSERT INTO law_versions VALUES ('civil-code-v1','civil-code','现行版','in_force','2020-05-28',NULL,'2020-05-28','r05-fixture');
            INSERT INTO law_versions VALUES ('labor-contract-v1','labor-contract','现行版','in_force','2007-06-29',NULL,'2007-06-29','r05-fixture');
            INSERT INTO law_articles VALUES ('civil-code-a1','civil-code','civil-code-v1','第一条',1,NULL,'劳动合同均等正文。');
            INSERT INTO law_articles VALUES ('labor-contract-a1','labor-contract','labor-contract-v1','第一条',1,NULL,'劳动合同均等正文。');
            ",
        )
        .expect("ranking fixture schema initializes");
    connection
}

fn r05_ranking_request() -> PagedSearchRequest {
    PagedSearchRequest {
        query: "劳动合同".to_owned(),
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

#[test]
fn r05_generic_relevance_prefers_matching_law_over_civil_code_boost() {
    let connection = r05_ranking_fixture();
    let response =
        search_page(&connection, None, r05_ranking_request()).expect("ranking search succeeds");
    assert_eq!(response.total, 2);
    assert_eq!(response.articles.len(), 2);
    assert_eq!(response.articles[0].document_id, "labor-contract");

    let civil = response
        .articles
        .iter()
        .find(|article| article.document_id == "civil-code")
        .expect("Civil Code article is present");
    let labor = response
        .articles
        .iter()
        .find(|article| article.document_id == "labor-contract")
        .expect("Labor Contract Law article is present");
    assert!(
        labor.score > civil.score,
        "title-matching Labor Contract Law should beat equal-body Civil Code: labor={} civil={}",
        labor.score,
        civil.score
    );
}

fn r06_index_with_common_terms() -> SearchIndex {
    let connection = Connection::open_in_memory().expect("candidate index opens");
    connection
        .execute_batch(
            "
            CREATE TABLE article_bigrams(
                bigram TEXT NOT NULL,
                article_rowid INTEGER NOT NULL,
                PRIMARY KEY(bigram, article_rowid)
            ) WITHOUT ROWID;
            ",
        )
        .expect("candidate index schema initializes");
    for article_rowid in 1_i64..=901 {
        connection
            .execute(
                "INSERT INTO article_bigrams(bigram, article_rowid) VALUES (?1, ?2)",
                ("合同", article_rowid),
            )
            .expect("合同 posting inserts");
    }
    connection
        .execute(
            "INSERT INTO article_bigrams(bigram, article_rowid) VALUES (?1, ?2)",
            ("解除", 1_i64),
        )
        .expect("shared 解除 posting inserts");
    for article_rowid in 902_i64..=1801 {
        connection
            .execute(
                "INSERT INTO article_bigrams(bigram, article_rowid) VALUES (?1, ?2)",
                ("解除", article_rowid),
            )
            .expect("解除 posting inserts");
    }
    SearchIndex {
        connection,
        source_manifest_sha256: None,
        source_article_count: None,
    }
}

#[test]
fn r06_all_common_terms_apply_budget_after_joint_intersection() {
    let index = r06_index_with_common_terms();
    let terms = vec!["合同".to_owned(), "解除".to_owned()];
    let rows = index
        .article_rowids_for_terms(&terms, SearchMatchMode::All)
        .expect("candidate probe succeeds");
    assert_eq!(rows, Some(vec![1]));
}

fn r06_index_with_small_any_terms() -> SearchIndex {
    let connection = Connection::open_in_memory().expect("ANY candidate index opens");
    connection
        .execute_batch(
            "
            CREATE TABLE article_bigrams(
                bigram TEXT NOT NULL,
                article_rowid INTEGER NOT NULL,
                PRIMARY KEY(bigram, article_rowid)
            ) WITHOUT ROWID;
            INSERT INTO article_bigrams VALUES ('合同', 1);
            INSERT INTO article_bigrams VALUES ('合同', 2);
            INSERT INTO article_bigrams VALUES ('解除', 2);
            INSERT INTO article_bigrams VALUES ('解除', 3);
            ",
        )
        .expect("ANY candidate index schema initializes");
    SearchIndex {
        connection,
        source_manifest_sha256: None,
        source_article_count: None,
    }
}

#[test]
fn r06_any_unions_complete_per_term_candidate_sets() {
    let index = r06_index_with_small_any_terms();
    let terms = vec!["合同".to_owned(), "解除".to_owned()];
    let rows = index
        .article_rowids_for_terms(&terms, SearchMatchMode::Any)
        .expect("ANY candidate probe succeeds");
    assert_eq!(rows, Some(vec![1, 2, 3]));
}

#[test]
fn r06_any_common_term_reports_candidate_limit_without_truncation() {
    let index = r06_index_with_common_terms();
    let terms = vec!["合同".to_owned(), "解除".to_owned()];
    let probe = index
        .article_rowids_for_terms_with_reason(&terms, SearchMatchMode::Any, None)
        .expect("ANY candidate probe completes");
    assert_eq!(probe.rowids, None);
    assert_eq!(probe.fallback_reason, Some(FALLBACK_REASON_CANDIDATE_LIMIT));
}

#[test]
fn r06_any_union_over_limit_falls_back_after_union_without_truncation() {
    let connection = Connection::open_in_memory().expect("ANY union index opens");
    connection
        .execute_batch(
            "
            CREATE TABLE article_bigrams(
                bigram TEXT NOT NULL,
                article_rowid INTEGER NOT NULL,
                PRIMARY KEY(bigram, article_rowid)
            ) WITHOUT ROWID;
            ",
        )
        .expect("ANY union index schema initializes");
    for article_rowid in 1_i64..=600 {
        connection
            .execute(
                "INSERT INTO article_bigrams(bigram, article_rowid) VALUES (?1, ?2)",
                ("合同", article_rowid),
            )
            .expect("ANY first posting inserts");
    }
    for article_rowid in 602_i64..=1201 {
        connection
            .execute(
                "INSERT INTO article_bigrams(bigram, article_rowid) VALUES (?1, ?2)",
                ("解除", article_rowid),
            )
            .expect("ANY second posting inserts");
    }
    let index = SearchIndex {
        connection,
        source_manifest_sha256: None,
        source_article_count: None,
    };
    let probe = index
        .article_rowids_for_terms_with_reason(
            &["合同".to_owned(), "解除".to_owned()],
            SearchMatchMode::Any,
            None,
        )
        .expect("ANY union probe completes");
    assert_eq!(probe.rowids, None);
    assert_eq!(probe.fallback_reason, Some(FALLBACK_REASON_CANDIDATE_LIMIT));
}

fn r06_index_with_large_intersection() -> SearchIndex {
    let connection = Connection::open_in_memory().expect("large intersection index opens");
    connection
        .execute_batch(
            "
            CREATE TABLE article_bigrams(
                bigram TEXT NOT NULL,
                article_rowid INTEGER NOT NULL,
                PRIMARY KEY(bigram, article_rowid)
            ) WITHOUT ROWID;
            ",
        )
        .expect("large intersection index schema initializes");
    for article_rowid in 1_i64..=901 {
        connection
            .execute(
                "INSERT INTO article_bigrams(bigram, article_rowid) VALUES (?1, ?2)",
                ("合同", article_rowid),
            )
            .expect("large 合同 posting inserts");
        connection
            .execute(
                "INSERT INTO article_bigrams(bigram, article_rowid) VALUES (?1, ?2)",
                ("解除", article_rowid),
            )
            .expect("large 解除 posting inserts");
    }
    SearchIndex {
        connection,
        source_manifest_sha256: None,
        source_article_count: None,
    }
}

#[test]
fn r06_all_large_final_intersection_falls_back_after_901_row_probe() {
    let index = r06_index_with_large_intersection();
    let terms = vec!["合同".to_owned(), "解除".to_owned()];
    let probe = index
        .article_rowids_for_terms_with_reason(&terms, SearchMatchMode::All, None)
        .expect("ALL candidate probe completes");
    assert_eq!(probe.rowids, None);
    assert_eq!(probe.fallback_reason, Some(FALLBACK_REASON_CANDIDATE_LIMIT));
}

#[test]
fn r06_index_parameter_limit_falls_back_without_truncating_required_bigrams() {
    let connection = Connection::open_in_memory().expect("parameter-limit index opens");
    connection
        .execute_batch(
            "
            CREATE TABLE article_bigrams(
                bigram TEXT NOT NULL,
                article_rowid INTEGER NOT NULL,
                PRIMARY KEY(bigram, article_rowid)
            ) WITHOUT ROWID;
            ",
        )
        .expect("parameter-limit index schema initializes");
    let term: String = (0..=MAX_INDEX_QUERY_PARAMETERS + 1)
        .map(|offset| char::from_u32(0x4e00 + offset as u32).expect("CJK fixture character"))
        .collect();
    let probe = (SearchIndex {
        connection,
        source_manifest_sha256: None,
        source_article_count: None,
    })
    .article_rowids_for_terms_with_reason(&[term], SearchMatchMode::All, None)
    .expect("parameter-limit probe completes");
    assert_eq!(probe.rowids, None);
    assert_eq!(probe.fallback_reason, Some(FALLBACK_REASON_PARAMETER_LIMIT));
}

#[test]
fn r06_source_parameter_budget_falls_back_without_changing_results() {
    let directory = tempfile::tempdir().expect("source-parameter fixture directory");
    let path = directory.path().join("legal_core.sqlite");
    let terms = [
        "合同", "解除", "租赁", "债务", "损害", "赔偿", "诉讼", "申请", "仲裁", "劳动", "工资",
        "公司", "股权", "财产", "责任", "义务",
    ];
    let source_content = format!("{}：源查询参数预算测试。", terms.join(" "));
    let connection = cacheable_fixture(&path, "source-parameter-a1", &source_content);
    connection
        .execute_batch(&format!(
            "
            INSERT INTO law_documents VALUES ('second-test-law','第二份缓存隔离测试法','law','npc','CN','national_law','in_force','2023-12-29','第二份源参数预算');
            INSERT INTO law_versions VALUES ('second-test-law-v1','second-test-law','现行版','in_force','2024-01-01',NULL,'2023-12-29','audit-fixture');
            INSERT INTO law_aliases VALUES ('second-test-law-alias','second-test-law','第二份缓存隔离测试法','第二份缓存隔离测试法');
            INSERT INTO law_articles VALUES ('source-parameter-a2','second-test-law','second-test-law-v1','第一条',1,NULL,'{source_content}');
            "
        ))
        .expect("source-parameter second law initializes");
    let mut request = cache_request();
    request.query = terms.join(" ");
    request.limit = 1;

    let mut index_connection = Connection::open_in_memory().expect("source-parameter index opens");
    index_connection
        .execute_batch(
            "
            CREATE TABLE article_bigrams(
                bigram TEXT NOT NULL,
                article_rowid INTEGER NOT NULL,
                PRIMARY KEY(bigram, article_rowid)
            ) WITHOUT ROWID;
            ",
        )
        .expect("source-parameter index schema initializes");
    {
        let transaction = index_connection
            .transaction()
            .expect("source-parameter index transaction starts");
        for article_rowid in 1_i64..=900 {
            for term in terms {
                transaction
                    .execute(
                        "INSERT INTO article_bigrams(bigram, article_rowid) VALUES (?1, ?2)",
                        (term, article_rowid),
                    )
                    .expect("source-parameter posting inserts");
            }
        }
        transaction
            .commit()
            .expect("source-parameter index transaction commits");
    }
    let index = SearchIndex {
        connection: index_connection,
        source_manifest_sha256: None,
        source_article_count: None,
    };
    for offset in 0..=1 {
        let mut page_request = request.clone();
        page_request.offset = offset;
        let without_index = search_page(&connection, None, page_request.clone())
            .expect("complete flat source query stays valid without an index");
        let with_index = search_page(&connection, Some(&index), page_request)
            .expect("flat index candidate bind overflow falls back to source SQL");

        assert_eq!(with_index.total, without_index.total);
        assert_eq!(
            with_index
                .articles
                .iter()
                .map(|article| article.article_id.as_str())
                .collect::<Vec<_>>(),
            without_index
                .articles
                .iter()
                .map(|article| article.article_id.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            with_index.metrics.index_fallback_reason.as_deref(),
            Some(FALLBACK_REASON_PARAMETER_LIMIT)
        );
        assert_eq!(with_index.metrics.candidate_count, 0);
    }

    for offset in 0..=1 {
        let mut grouped_request = request.clone();
        grouped_request.view = SearchView::Grouped;
        grouped_request.offset = offset;
        let grouped_without_index = search_page(&connection, None, grouped_request.clone())
            .expect("complete grouped source query stays valid without an index");
        let grouped_with_index = search_page(&connection, Some(&index), grouped_request)
            .expect("grouped index candidate bind overflow falls back to source SQL");
        assert_eq!(grouped_with_index.total, grouped_without_index.total);
        assert_eq!(
            grouped_with_index.total_laws,
            grouped_without_index.total_laws
        );
        assert_eq!(
            grouped_with_index
                .laws
                .iter()
                .map(|group| group.law.document_id.as_str())
                .collect::<Vec<_>>(),
            grouped_without_index
                .laws
                .iter()
                .map(|group| group.law.document_id.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            grouped_with_index.metrics.index_fallback_reason.as_deref(),
            Some(FALLBACK_REASON_PARAMETER_LIMIT)
        );
    }
}

#[test]
fn r06_cancelled_index_probe_is_error_instead_of_fallback() {
    let connection = Connection::open_in_memory().expect("cancelled index opens");
    connection
        .execute_batch(
            "
            CREATE TABLE source_bigrams(
                bigram TEXT NOT NULL,
                article_rowid INTEGER NOT NULL
            );
            INSERT INTO source_bigrams VALUES ('合同', 1);
            CREATE VIEW article_bigrams AS
              SELECT bigram, article_rowid
              FROM source_bigrams
              WHERE audit_wait_until_cancel() = 1;
            ",
        )
        .expect("cancelled index schema initializes");
    let cancellation = SearchCancellation::new();
    let worker_cancellation = cancellation.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Arc::new(Mutex::new(release_rx));
    connection
        .create_scalar_function("audit_wait_until_cancel", 0, FunctionFlags::SQLITE_UTF8, {
            let release_rx = Arc::clone(&release_rx);
            move |_| {
                started_tx.send(()).expect("index probe reaches barrier");
                release_rx
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv_timeout(Duration::from_secs(2))
                    .expect("test releases index probe barrier");
                Ok(1_i64)
            }
        })
        .expect("index cancellation scalar registers");
    let worker = thread::spawn(move || {
        let index = SearchIndex {
            connection,
            source_manifest_sha256: None,
            source_article_count: None,
        };
        let _registration = worker_cancellation
            .register_connection(&index.connection)
            .expect("index cancellation handle registers");
        index.article_rowids_for_terms_with_reason(
            &["合同".to_owned()],
            SearchMatchMode::All,
            Some(&worker_cancellation),
        )
    });
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("index probe starts before cancellation");
    cancellation.cancel();
    release_tx.send(()).expect("index probe barrier releases");
    let result = worker.join().expect("cancelled index worker joins");
    assert!(
        matches!(result, Err(RetrievalError::Cancelled)),
        "SQLite interruption must remain an error, not an index fallback: {result:?}"
    );
}
