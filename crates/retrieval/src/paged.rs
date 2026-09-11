//! Complete, paged legal search.
//!
//! The original retrieval functions are deliberately kept as the v1/MCP
//! compatibility surface.  This module is the Web/service surface for a
//! search that has an exact count and applies pagination after the complete
//! match set has been ranked.  A generated two-character index can narrow
//! Chinese substring probes, but every candidate is checked again against the
//! authoritative text in `legal_core.sqlite`.

use super::*;
use rusqlite::{
    functions::FunctionFlags, params_from_iter, types::Value, Connection, InterruptHandle,
    OpenFlags, OptionalExtension,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};

pub const DEFAULT_PAGE_LIMIT: u32 = 20;
pub const MAX_PAGE_LIMIT: u32 = 100;
pub const MAX_PAGE_OFFSET: u32 = 1_000_000;
pub const SEARCH_INDEX_FILE_NAME: &str = "legal_search_index.sqlite";
// SQLite builds in the wild still commonly use the 999-variable limit.  An
// index hit set larger than this is deliberately sent through the complete
// literal SQL path instead of expanding an unbounded IN list.  This is a
// performance fallback, never a result cap.
const MAX_INDEX_BOUND_CANDIDATES: usize = 900;
// Keep the derived-index probe below the smallest variable limit supported by
// the SQLite builds we ship.  This is separate from the candidate-row bound:
// too many distinct required bigrams must take the complete source-SQL path,
// never truncate the query to fit the IN list.
const MAX_INDEX_QUERY_PARAMETERS: usize = 900;
// The source query must remain valid on SQLite builds using the historical
// 999-variable limit.  Index candidates consume this same budget alongside
// score, filter, match, and pagination parameters, so a safe probe can still
// require a complete source-SQL fallback.
const MAX_SQLITE_PARAMETERS: usize = 999;
const FALLBACK_REASON_INDEX_UNAVAILABLE: &str = "index_unavailable";
const FALLBACK_REASON_UNSUPPORTED_TERM: &str = "unsupported_term";
const FALLBACK_REASON_CANDIDATE_LIMIT: &str = "candidate_limit";
const FALLBACK_REASON_PARAMETER_LIMIT: &str = "parameter_limit";
// Only bounded page payloads and exact count results are cached. Larger
// searches continue to use the exact paged SQL path; they are never
// truncated just to make them cacheable.
/// The cache retains rendered *pages*, never complete result sets.  The
/// values below are deliberately byte budgets rather than result-count
/// budgets: legal article bodies and snippets have highly variable sizes.
const MAX_SEARCH_CACHE_BYTES: usize = 128 * 1024 * 1024;
const MAX_SEARCH_CACHE_ENTRY_BYTES: usize = 16 * 1024 * 1024;
// Internal only: callers are rejected for control characters before a plan is
// compiled.  It marks a law-name/article selector so SQL uses equality on the
// article-number column rather than a substring probe (第二条 != 第二条之一).
const EXACT_ARTICLE_PREFIX: &str = "\u{001f}";

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum SearchMatchMode {
    /// Each ordinary term must match somewhere in the same candidate row.
    #[default]
    All,
    /// At least one ordinary term must match.
    Any,
    /// The supplied normalized text must occur as one contiguous literal.
    Phrase,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum VersionScope {
    /// Only an explicitly in-force version applicable today is visible.
    #[default]
    Current,
    /// Only a version applicable at `case_date` is visible.
    AsOf,
    /// Historical versions are intentionally included.  This is never the
    /// implicit fallback for an incomplete current-version record.
    All,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SearchView {
    Grouped,
    Flat,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SearchSort {
    Relevance,
    Effectiveness,
    EffectiveDate,
    PublishedDate,
    Title,
}

#[derive(Clone, Debug)]
pub struct PagedSearchRequest {
    pub query: String,
    pub match_mode: SearchMatchMode,
    pub version_scope: VersionScope,
    pub view: SearchView,
    pub document_id: Option<String>,
    pub case_date: Option<String>,
    pub limit: u32,
    pub offset: u32,
    pub document_type: Option<String>,
    pub effectiveness_level: Option<String>,
    pub jurisdiction: Option<String>,
    /// Document lifecycle status.  Version lifecycle status has its own
    /// filter so callers cannot accidentally treat a current document as a
    /// current historical article.
    pub status: Option<String>,
    pub version_status: Option<String>,
    pub sort: SearchSort,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchAppliedQuery {
    pub normalized_query: String,
    pub match_mode: SearchMatchMode,
    pub version_scope: VersionScope,
    pub as_of: Option<String>,
    pub resolved_document_id: Option<String>,
    pub exact_article_number: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LawNameAmbiguity {
    pub query: String,
    pub candidates: Vec<(String, String)>,
}

#[derive(Clone, Debug)]
pub struct LawSearchGroup {
    pub law: LawSearchResult,
    pub matched_article_count: u64,
    pub top_articles: Vec<ArticleSearchResult>,
}

#[derive(Clone, Debug)]
pub struct PagedSearchResponse {
    pub view: SearchView,
    pub laws: Vec<LawSearchGroup>,
    pub articles: Vec<ArticleSearchResult>,
    pub total: u64,
    /// Exact number of matching documents across the complete result set.
    pub total_laws: u64,
    /// Exact number of matching article rows across the complete result set.
    pub total_articles: u64,
    pub limit: u32,
    pub offset: u32,
    pub warnings: Vec<String>,
    pub applied_query: SearchAppliedQuery,
    pub ambiguities: Vec<LawNameAmbiguity>,
    /// Bounded observability for the local benchmark/health surface.  It
    /// contains no corpus text or filesystem path.
    pub metrics: SearchMetrics,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SearchMetrics {
    pub candidate_count: u64,
    pub index_fallback: bool,
    pub index_fallback_reason: Option<String>,
    pub cache_hit: bool,
    pub count_cache_hit: bool,
    pub cache_retained_bytes: u64,
    pub lock_wait_ms: u64,
    /// Milliseconds spent compiling the normalized query plan.
    pub plan_ms: u64,
    /// Milliseconds spent probing the optional derived index.
    pub index_ms: u64,
    /// Milliseconds spent obtaining the exact total counts.
    pub count_ms: u64,
    /// Milliseconds spent rendering the requested page.
    pub page_ms: u64,
    /// End-to-end retrieval time, including planning and cache coordination.
    pub total_ms: u64,
}

#[derive(Clone, Debug)]
pub struct VersionArticlesRequest {
    pub version_id: String,
    pub limit: u32,
    pub offset: u32,
}

#[derive(Clone, Debug)]
pub struct VersionArticlesResponse {
    pub version_id: String,
    pub document_id: String,
    pub articles: Vec<LawArticleDetail>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
}

/// A caller-owned cancellation token for a read-only SQLite search.
///
/// The token registers the connection before query preparation.  Cancelling
/// it then calls SQLite's interrupt handle, rather than merely abandoning the
/// async task that is waiting for a blocking query.  Page-cache flights attach
/// callers here and only interrupt their shared SQLite token when the final
/// subscriber leaves.
#[derive(Clone, Default)]
pub struct SearchCancellation {
    inner: Arc<SearchCancellationInner>,
}

#[derive(Default)]
struct SearchCancellationInner {
    cancelled: AtomicBool,
    next_registration: AtomicU64,
    handles: Mutex<Vec<(u64, InterruptHandle)>>,
    flights: Mutex<Vec<std::sync::Weak<SearchFlight>>>,
}

impl SearchCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        let handles = self
            .inner
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, handle) in handles.iter() {
            handle.interrupt();
        }
        let flights = std::mem::take(
            &mut *self
                .inner
                .flights
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for flight in flights.into_iter().filter_map(|flight| flight.upgrade()) {
            flight.release();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    /// Register one SQLite connection for this operation.  Its guard removes
    /// only this registration on drop, so a caller sharing a cancellation
    /// token cannot clear an unrelated concurrent query's interrupt handle.
    pub fn register_connection(
        &self,
        connection: &Connection,
    ) -> Result<CancellationRegistration, RetrievalError> {
        if self.is_cancelled() {
            return Err(RetrievalError::Cancelled);
        }
        let registration = self.inner.next_registration.fetch_add(1, Ordering::Relaxed);
        let mut handles = self
            .inner
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        handles.push((registration, connection.get_interrupt_handle()));
        if self.is_cancelled() {
            for (_, handle) in handles.iter() {
                handle.interrupt();
            }
            handles.retain(|(existing, _)| *existing != registration);
            return Err(RetrievalError::Cancelled);
        }
        Ok(CancellationRegistration {
            cancellation: self.clone(),
            registration,
        })
    }

    fn unregister(&self, registration: u64) {
        let mut handles = self
            .inner
            .handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(position) = handles
            .iter()
            .position(|(existing, _)| *existing == registration)
        {
            handles.remove(position);
        }
    }

    fn attach_flight(&self, flight: &Arc<SearchFlight>) -> Result<(), RetrievalError> {
        if self.is_cancelled() {
            return Err(RetrievalError::Cancelled);
        }
        flight.subscribers.fetch_add(1, Ordering::AcqRel);
        self.inner
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(flight));
        if self.is_cancelled() {
            self.detach_flight(flight);
            return Err(RetrievalError::Cancelled);
        }
        Ok(())
    }

    fn detach_flight(&self, flight: &Arc<SearchFlight>) {
        let mut flights = self
            .inner
            .flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(position) = flights.iter().position(|candidate| {
            candidate
                .upgrade()
                .is_some_and(|candidate| Arc::ptr_eq(&candidate, flight))
        }) {
            flights.remove(position);
            flight.release();
        }
    }
}

/// RAII registration returned by [`SearchCancellation::register_connection`].
/// It deliberately owns no SQLite connection and is safe to move into a
/// blocking task together with its cancellation token.
pub struct CancellationRegistration {
    cancellation: SearchCancellation,
    registration: u64,
}

impl Drop for CancellationRegistration {
    fn drop(&mut self) {
        self.cancellation.unregister(self.registration);
    }
}

struct SearchFlight {
    cancellation: SearchCancellation,
    subscribers: std::sync::atomic::AtomicUsize,
}

impl SearchFlight {
    fn new() -> Self {
        Self {
            cancellation: SearchCancellation::new(),
            subscribers: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn release(&self) {
        if self.subscribers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.cancellation.cancel();
        }
    }
}

/// A read-only derived index.  The index contains only `(bigram,rowid)`
/// pairs; the formal database remains the source of truth for all fields and
/// text.  A stale or malformed index is ignored and the caller falls back to
/// the complete SQL predicate.
pub struct SearchIndex {
    connection: Connection,
    source_manifest_sha256: Option<String>,
    source_article_count: Option<i64>,
}

impl std::fmt::Debug for SearchIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SearchIndex(..)")
    }
}

impl SearchIndex {
    pub fn open_if_current(
        path: impl AsRef<Path>,
        source_manifest_sha256: Option<&str>,
    ) -> Result<Option<Self>, RetrievalError> {
        let path = path.as_ref();
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(None),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Ok(None);
        }
        let connection = match Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) {
            Ok(connection) => connection,
            Err(_) => return Ok(None),
        };
        if connection.pragma_update(None, "query_only", "ON").is_err()
            || connection
                .pragma_update(None, "trusted_schema", "OFF")
                .is_err()
        {
            return Ok(None);
        }
        let schema_version = match connection
            .query_row(
                "SELECT value FROM search_index_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
        {
            Ok(schema_version) => schema_version,
            Err(_) => return Ok(None),
        };
        let schema_ok = schema_version.as_deref() == Some("1");
        if !schema_ok {
            return Ok(None);
        }
        let index_source = match connection
            .query_row(
                "SELECT value FROM search_index_metadata WHERE key = 'source_manifest_sha256'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
        {
            Ok(index_source) => index_source,
            Err(_) => return Ok(None),
        };
        if source_manifest_sha256.is_some() && index_source.as_deref() != source_manifest_sha256 {
            return Ok(None);
        }
        let table_ok: bool = match connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'article_bigrams')",
            [],
            |row| row.get(0),
        ) {
            Ok(table_ok) => table_ok,
            Err(_) => return Ok(None),
        };
        if !table_ok {
            return Ok(None);
        }
        let source_article_count = connection
            .query_row(
                "SELECT value FROM search_index_metadata WHERE key = 'source_article_count'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .and_then(|value| value.parse::<i64>().ok());
        Ok(Some(Self {
            connection,
            source_manifest_sha256: index_source,
            source_article_count,
        }))
    }

    fn cache_identity(&self) -> String {
        format!(
            "index:v1:{}:{}",
            self.source_manifest_sha256.as_deref().unwrap_or("unknown"),
            self.source_article_count.unwrap_or(-1)
        )
    }

    fn register_cancellation(
        &self,
        cancellation: &SearchCancellation,
    ) -> Result<CancellationRegistration, RetrievalError> {
        cancellation.register_connection(&self.connection)
    }

    /// Return a bounded candidate set.  `All` and `Phrase` intersect the
    /// *complete* set of required bigrams in one SQLite query; `Any` unions
    /// per-term intersections.  Literal SQL predicates still verify every
    /// selected source row.
    ///
    /// The bound is only a probe: once the index proves that the final
    /// candidate set has more than `MAX_INDEX_BOUND_CANDIDATES` rows, the
    /// caller receives `None` and the authoritative query scans all source
    /// rows.  It therefore cannot truncate a legal result set.  Keeping the
    /// probe bounded avoids reading millions of rowids merely to decide to
    /// fall back for common terms.
    #[cfg(test)]
    fn article_rowids_for_terms(
        &self,
        terms: &[String],
        match_mode: SearchMatchMode,
    ) -> Result<Option<Vec<i64>>, RetrievalError> {
        Ok(self
            .article_rowids_for_terms_with_reason(terms, match_mode, None)?
            .rowids)
    }

    fn article_rowids_for_terms_with_reason(
        &self,
        terms: &[String],
        match_mode: SearchMatchMode,
        cancellation: Option<&SearchCancellation>,
    ) -> Result<IndexCandidateProbe, RetrievalError> {
        ensure_index_probe_not_cancelled(cancellation)?;
        let mut term_bigrams = Vec::new();
        for term in terms {
            let chars = term.chars().collect::<Vec<_>>();
            if chars.len() < 2 || !chars.iter().copied().all(is_cjk_ideograph) {
                return Ok(IndexCandidateProbe::fallback(
                    FALLBACK_REASON_UNSUPPORTED_TERM,
                ));
            }
            let mut bigrams = HashSet::new();
            for pair in chars.windows(2) {
                bigrams.insert(pair.iter().collect::<String>());
            }
            let mut bigrams = bigrams.into_iter().collect::<Vec<_>>();
            bigrams.sort_unstable();
            term_bigrams.push(bigrams);
        }
        if term_bigrams.is_empty() {
            return Ok(IndexCandidateProbe::default());
        }

        match match_mode {
            SearchMatchMode::All | SearchMatchMode::Phrase => {
                // A row must contain every unique bigram from every term.
                // Doing this as one GROUP BY is essential: probing each term
                // separately would reject a small intersection merely because
                // one individual posting list is common (>900 rows).
                let mut required_bigrams = HashSet::new();
                for bigrams in term_bigrams {
                    required_bigrams.extend(bigrams);
                }
                let mut required_bigrams = required_bigrams.into_iter().collect::<Vec<_>>();
                required_bigrams.sort_unstable();
                self.article_rowids_for_bigrams_with_reason(&required_bigrams, cancellation)
            }
            SearchMatchMode::Any => {
                let mut rows = HashSet::new();
                for bigrams in term_bigrams {
                    let probe =
                        self.article_rowids_for_bigrams_with_reason(&bigrams, cancellation)?;
                    let Some(term_rows) = probe.rowids else {
                        // A bounded posting list cannot prove a complete
                        // union.  Fall back to literal source SQL; never
                        // union an arbitrary first 901 rows.
                        return Ok(probe);
                    };
                    rows.extend(term_rows);
                    // The union is itself the candidate set for ANY.  Keep
                    // the same bounded probe contract after each term; a
                    // union of individually small postings can still exceed
                    // the safe rowid bind budget.
                    if rows.len() > MAX_INDEX_BOUND_CANDIDATES {
                        return Ok(IndexCandidateProbe::fallback(
                            FALLBACK_REASON_CANDIDATE_LIMIT,
                        ));
                    }
                }
                ensure_index_probe_not_cancelled(cancellation)?;
                let mut rows = rows.into_iter().collect::<Vec<_>>();
                rows.sort_unstable();
                Ok(IndexCandidateProbe::candidates(rows))
            }
        }
    }

    fn article_rowids_for_bigrams_with_reason(
        &self,
        bigrams: &[String],
        cancellation: Option<&SearchCancellation>,
    ) -> Result<IndexCandidateProbe, RetrievalError> {
        ensure_index_probe_not_cancelled(cancellation)?;
        if bigrams.is_empty() {
            return Ok(IndexCandidateProbe::candidates(Vec::new()));
        }
        if bigrams.len() > MAX_INDEX_QUERY_PARAMETERS {
            return Ok(IndexCandidateProbe::fallback(
                FALLBACK_REASON_PARAMETER_LIMIT,
            ));
        }
        let placeholders = (0..bigrams.len())
            .map(|index| format!("?{}", index + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let values = bigrams.iter().cloned().map(Value::Text).collect::<Vec<_>>();
        let mut statement = self
            .connection
            .prepare(&format!(
                "SELECT article_rowid FROM article_bigrams WHERE bigram IN ({placeholders}) GROUP BY article_rowid HAVING COUNT(DISTINCT bigram) = {} LIMIT {}",
                bigrams.len(), MAX_INDEX_BOUND_CANDIDATES + 1
            ))
            .map_err(|error| index_probe_sqlite_error(error, cancellation))?;
        let mapped = statement
            .query_map(params_from_iter(values.iter()), |row| row.get::<_, i64>(0))
            .map_err(|error| index_probe_sqlite_error(error, cancellation))?;
        let rows = mapped
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|error| index_probe_sqlite_error(error, cancellation))?;
        ensure_index_probe_not_cancelled(cancellation)?;
        if rows.len() > MAX_INDEX_BOUND_CANDIDATES {
            Ok(IndexCandidateProbe::fallback(
                FALLBACK_REASON_CANDIDATE_LIMIT,
            ))
        } else {
            let mut rows = rows;
            rows.sort_unstable();
            Ok(IndexCandidateProbe::candidates(rows))
        }
    }
}

#[derive(Debug, Default)]
struct IndexCandidateProbe {
    rowids: Option<Vec<i64>>,
    fallback_reason: Option<&'static str>,
}

impl IndexCandidateProbe {
    fn candidates(rowids: Vec<i64>) -> Self {
        Self {
            rowids: Some(rowids),
            fallback_reason: None,
        }
    }

    fn fallback(reason: &'static str) -> Self {
        Self {
            rowids: None,
            fallback_reason: Some(reason),
        }
    }
}

fn ensure_index_probe_not_cancelled(
    cancellation: Option<&SearchCancellation>,
) -> Result<(), RetrievalError> {
    if cancellation.is_some_and(SearchCancellation::is_cancelled) {
        Err(RetrievalError::Cancelled)
    } else {
        Ok(())
    }
}

fn index_probe_sqlite_error(
    error: rusqlite::Error,
    cancellation: Option<&SearchCancellation>,
) -> RetrievalError {
    if cancellation.is_some_and(SearchCancellation::is_cancelled) {
        RetrievalError::Cancelled
    } else {
        RetrievalError::Sqlite(error)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SearchCacheKey {
    identity: String,
    query: String,
    match_mode: SearchMatchMode,
    version_scope: VersionScope,
    view: SearchView,
    document_id: Option<String>,
    case_date: Option<String>,
    document_type: Option<String>,
    effectiveness_level: Option<String>,
    jurisdiction: Option<String>,
    status: Option<String>,
    version_status: Option<String>,
    sort: SearchSort,
    limit: u32,
    offset: u32,
}

impl SearchCacheKey {
    fn new(identity: String, request: &PagedSearchRequest) -> Self {
        Self {
            identity,
            query: canonical_query(&request.query),
            match_mode: request.match_mode,
            version_scope: request.version_scope,
            view: request.view,
            document_id: request.document_id.clone(),
            case_date: request.case_date.clone(),
            document_type: request.document_type.clone(),
            effectiveness_level: request.effectiveness_level.clone(),
            jurisdiction: request.jurisdiction.clone(),
            status: request.status.clone(),
            version_status: request.version_status.clone(),
            sort: request.sort,
            limit: request.limit,
            offset: request.offset,
        }
    }
}

/// The page cache key deliberately includes view and pagination.  Exact
/// counts do not: the same logical search must not rescan every matching row
/// merely because a caller asks for page two or switches projection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CountCacheKey(SearchCacheKey);

impl CountCacheKey {
    fn from_page_key(key: &SearchCacheKey) -> Self {
        let mut key = key.clone();
        key.view = SearchView::Flat;
        key.sort = SearchSort::Relevance;
        key.limit = 0;
        key.offset = 0;
        Self(key)
    }
}

struct SearchCacheState {
    bytes: usize,
    entries: VecDeque<(SearchCacheKey, Arc<PagedSearchResponse>, usize)>,
    count_entries: VecDeque<(CountCacheKey, (u64, u64), usize)>,
    in_flight: HashMap<SearchCacheKey, Arc<SearchFlight>>,
}

static SEARCH_CACHE: OnceLock<(Mutex<SearchCacheState>, Condvar)> = OnceLock::new();

fn search_cache() -> &'static (Mutex<SearchCacheState>, Condvar) {
    SEARCH_CACHE.get_or_init(|| {
        (
            Mutex::new(SearchCacheState {
                bytes: 0,
                entries: VecDeque::new(),
                count_entries: VecDeque::new(),
                in_flight: HashMap::new(),
            }),
            Condvar::new(),
        )
    })
}

fn search_cache_retained_bytes() -> u64 {
    let (mutex, _) = search_cache();
    u64::try_from(
        mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bytes,
    )
    .unwrap_or(u64::MAX)
}

fn search_cache_get_locked(
    cache: &mut SearchCacheState,
    key: &SearchCacheKey,
) -> Option<PagedSearchResponse> {
    let position = cache
        .entries
        .iter()
        .position(|(entry_key, _, _)| entry_key == key)?;
    let (entry_key, result, bytes) = cache.entries.remove(position)?;
    let cloned = (*result).clone();
    cache.entries.push_front((entry_key, result, bytes));
    Some(cloned)
}

fn count_cache_get_locked(cache: &mut SearchCacheState, key: &CountCacheKey) -> Option<(u64, u64)> {
    let position = cache
        .count_entries
        .iter()
        .position(|(entry_key, _, _)| entry_key == key)?;
    let (entry_key, counts, bytes) = cache.count_entries.remove(position)?;
    cache.count_entries.push_front((entry_key, counts, bytes));
    Some(counts)
}

fn count_cache_store(key: CountCacheKey, counts: (u64, u64)) {
    let estimated = estimate_cache_key_bytes(&key.0)
        .saturating_add(std::mem::size_of::<CountCacheKey>())
        .saturating_add(std::mem::size_of::<(u64, u64)>())
        .saturating_add(std::mem::size_of::<(CountCacheKey, (u64, u64), usize)>());
    if estimated > MAX_SEARCH_CACHE_ENTRY_BYTES {
        return;
    }
    let (mutex, _) = search_cache();
    let mut cache = mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(position) = cache
        .count_entries
        .iter()
        .position(|(entry_key, _, _)| entry_key == &key)
    {
        if let Some((_, _, bytes)) = cache.count_entries.remove(position) {
            cache.bytes = cache.bytes.saturating_sub(bytes);
        }
    }
    cache.bytes = cache.bytes.saturating_add(estimated);
    cache.count_entries.push_front((key, counts, estimated));
    evict_cache_to_budget(&mut cache);
}

fn evict_cache_to_budget(cache: &mut SearchCacheState) {
    while cache.bytes > MAX_SEARCH_CACHE_BYTES {
        if let Some((_, _, bytes)) = cache.entries.pop_back() {
            cache.bytes = cache.bytes.saturating_sub(bytes);
        } else if let Some((_, _, bytes)) = cache.count_entries.pop_back() {
            cache.bytes = cache.bytes.saturating_sub(bytes);
        } else {
            break;
        }
    }
}

enum CacheProbe {
    Hit(Box<PagedSearchResponse>, u64),
    Owner(Arc<SearchFlight>, u64),
}

/// The first caller owns the exact SQLite calculation.  Same-key callers
/// sleep until it has published a page or a failure and then check again.
fn search_cache_probe(
    key: &SearchCacheKey,
    cancellation: &SearchCancellation,
) -> Result<CacheProbe, RetrievalError> {
    let wait_started = Instant::now();
    let (mutex, ready) = search_cache();
    let mut cache = mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    'probe: loop {
        if let Some(page) = search_cache_get_locked(&mut cache, key) {
            return Ok(CacheProbe::Hit(
                Box::new(page),
                elapsed_millis(wait_started),
            ));
        }
        if let Some(flight) = cache.in_flight.get(key).cloned() {
            cancellation.attach_flight(&flight)?;
            // The request's own cancellation wakes this bounded wait.  The
            // search itself only sees the shared flight token, so one client
            // leaving cannot abort remaining subscribers.
            loop {
                if cancellation.is_cancelled() {
                    cancellation.detach_flight(&flight);
                    return Err(RetrievalError::Cancelled);
                }
                if let Some(page) = search_cache_get_locked(&mut cache, key) {
                    cancellation.detach_flight(&flight);
                    return Ok(CacheProbe::Hit(
                        Box::new(page),
                        elapsed_millis(wait_started),
                    ));
                }
                // Failed owners remove the flight and notify every waiter.
                // Detach the stale subscription before one waiter becomes
                // the retry owner; otherwise a cancelled worker could leave
                // this Condvar permanently asleep.
                if !cache.in_flight.contains_key(key) {
                    cancellation.detach_flight(&flight);
                    continue 'probe;
                }
                let (next, _) = ready
                    .wait_timeout(cache, Duration::from_millis(25))
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                cache = next;
            }
        }
        let flight = Arc::new(SearchFlight::new());
        cancellation.attach_flight(&flight)?;
        cache.in_flight.insert(key.clone(), flight.clone());
        return Ok(CacheProbe::Owner(flight, elapsed_millis(wait_started)));
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn finish_cache_flight(key: &SearchCacheKey, result: Option<PagedSearchResponse>) {
    let (mutex, ready) = search_cache();
    let mut cache = mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cache.in_flight.remove(key);
    let Some(result) = result else {
        ready.notify_all();
        return;
    };
    let estimated = estimate_response_bytes(&result)
        .saturating_add(estimate_cache_key_bytes(key))
        .saturating_add(std::mem::size_of::<Arc<PagedSearchResponse>>())
        .saturating_add(std::mem::size_of::<(
            SearchCacheKey,
            Arc<PagedSearchResponse>,
            usize,
        )>());
    if estimated > MAX_SEARCH_CACHE_ENTRY_BYTES {
        ready.notify_all();
        return;
    }
    if let Some(position) = cache
        .entries
        .iter()
        .position(|(entry_key, _, _)| entry_key == key)
    {
        if let Some((_, _, bytes)) = cache.entries.remove(position) {
            cache.bytes = cache.bytes.saturating_sub(bytes);
        }
    }
    cache.bytes = cache.bytes.saturating_add(estimated);
    cache
        .entries
        .push_front((key.clone(), Arc::new(result), estimated));
    evict_cache_to_budget(&mut cache);
    ready.notify_all();
}

/// Guarantees that a failed or unwinding owner cannot leave waiters asleep in
/// the in-flight map.  Success supplies a page; every other exit wakes
/// waiters to retry or become the next owner.
struct SearchFlightGuard<'a> {
    key: Option<SearchCacheKey>,
    caller: &'a SearchCancellation,
    flight: Option<Arc<SearchFlight>>,
    finished: bool,
}

impl<'a> SearchFlightGuard<'a> {
    fn new(
        key: Option<SearchCacheKey>,
        caller: &'a SearchCancellation,
        flight: Option<Arc<SearchFlight>>,
    ) -> Self {
        Self {
            key,
            caller,
            flight,
            finished: false,
        }
    }

    fn finish(&mut self, result: Option<PagedSearchResponse>) {
        if let Some(key) = self.key.as_ref() {
            finish_cache_flight(key, result);
        }
        if let Some(flight) = self.flight.as_ref() {
            self.caller.detach_flight(flight);
        }
        self.finished = true;
    }
}

impl Drop for SearchFlightGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(None);
        }
    }
}

fn search_cache_identity(
    connection: &Connection,
    index: Option<&SearchIndex>,
    request: &PagedSearchRequest,
) -> Result<Option<String>, RetrievalError> {
    let has_metadata: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'database_metadata')",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);
    if !has_metadata {
        return Ok(None);
    }
    let metadata = connection
        .prepare("SELECT key, value FROM database_metadata WHERE key IN ('schema_version', 'runtime_schema_version', 'dataset_version', 'source_manifest_sha256') ORDER BY key")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let values = metadata.into_iter().collect::<HashMap<_, _>>();
    let source_manifest = values
        .get("source_manifest_sha256")
        .filter(|value| !value.is_empty());
    if source_manifest.is_none() {
        return Ok(None);
    }
    let Some(file_identity) = main_database_file_identity(connection)? else {
        // An in-memory or anonymous connection has no stable corpus identity.
        // Never allow it to share a process-global page cache with another
        // test/database connection that happens to declare matching metadata.
        return Ok(None);
    };
    let database_identity = [
        values
            .get("schema_version")
            .map(String::as_str)
            .unwrap_or(""),
        values
            .get("runtime_schema_version")
            .map(String::as_str)
            .unwrap_or(""),
        values
            .get("dataset_version")
            .map(String::as_str)
            .unwrap_or(""),
        source_manifest.map(String::as_str).unwrap_or(""),
    ]
    .join(":");
    // The effective visibility boundary belongs in the cache identity.  A
    // current search must not cross midnight; an as-of search is already
    // pinned by its supplied calendar date; `all` has no time boundary.
    let as_of = match request.version_scope {
        VersionScope::Current => {
            connection.query_row("SELECT date('now', 'localtime')", [], |row| row.get(0))?
        }
        VersionScope::AsOf => request.case_date.clone().unwrap_or_default(),
        VersionScope::All => "all".to_owned(),
    };
    let index_identity = index
        .map(SearchIndex::cache_identity)
        .unwrap_or_else(|| "index:none".to_owned());
    Ok(Some(format!(
        "db:{database_identity}|file:{file_identity}|as_of:{as_of}|{index_identity}"
    )))
}

fn main_database_file_identity(connection: &Connection) -> Result<Option<String>, RetrievalError> {
    let file = connection
        .prepare("PRAGMA database_list")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
        })?
        .find_map(|row| match row {
            Ok((name, path)) if name == "main" => Some(Ok(path)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .transpose()?;
    let Some(file) = file.filter(|path| !path.is_empty()) else {
        return Ok(None);
    };
    let canonical = match fs::canonicalize(&file) {
        Ok(path) => path,
        Err(_) => return Ok(None),
    };
    let metadata = match fs::metadata(&canonical) {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => return Ok(None),
    };
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0_u128, |duration| duration.as_nanos());
    Ok(Some(format!(
        "{}:{}:{modified}",
        canonical.to_string_lossy(),
        metadata.len()
    )))
}

pub fn search_page(
    connection: &Connection,
    index: Option<&SearchIndex>,
    request: PagedSearchRequest,
) -> Result<PagedSearchResponse, RetrievalError> {
    search_page_cancellable(connection, index, request, &SearchCancellation::new())
}

pub fn search_page_cancellable(
    connection: &Connection,
    index: Option<&SearchIndex>,
    request: PagedSearchRequest,
    cancellation: &SearchCancellation,
) -> Result<PagedSearchResponse, RetrievalError> {
    search_page_inner(connection, index, request, cancellation)
}

fn search_page_inner(
    connection: &Connection,
    index: Option<&SearchIndex>,
    request: PagedSearchRequest,
    cancellation: &SearchCancellation,
) -> Result<PagedSearchResponse, RetrievalError> {
    let total_started = Instant::now();
    if cancellation.is_cancelled() {
        return Err(RetrievalError::Cancelled);
    }
    validate_page(&request)?;
    // Planning and cache-identity reads may themselves query SQLite. Keep the
    // caller token installed until it has either left at a cache hit or been
    // attached to a shared flight; it must not leak into that flight's work.
    let caller_registration = cancellation.register_connection(connection)?;
    let plan_started = Instant::now();
    install_unicode_fold(connection)?;
    let plan = compile_query_plan(connection, &request)?;
    let plan_ms = elapsed_millis(plan_started);
    if !plan.ambiguities.is_empty() {
        return Ok(PagedSearchResponse {
            view: request.view,
            laws: Vec::new(),
            articles: Vec::new(),
            total: 0,
            total_laws: 0,
            total_articles: 0,
            limit: request.limit,
            offset: request.offset,
            warnings: vec!["ambiguous_law_name".to_owned()],
            applied_query: plan.applied,
            ambiguities: plan.ambiguities,
            metrics: SearchMetrics {
                plan_ms,
                total_ms: elapsed_millis(total_started),
                ..SearchMetrics::default()
            },
        });
    }

    // A cache key is only available for a source that declares an immutable
    // dataset identity.  Cache pages after SQL pagination; broad result sets
    // are therefore never materialized merely to make page two faster.
    let cache_key = search_cache_identity(connection, index, &plan.request)?
        .map(|identity| SearchCacheKey::new(identity, &plan.request));
    let mut cache_wait_ms = 0;
    let mut owned_flight = None;
    if let Some(key) = cache_key.as_ref() {
        match search_cache_probe(key, cancellation)? {
            CacheProbe::Hit(cached, wait_ms) => {
                let mut cached = *cached;
                cached.applied_query = plan.applied;
                cached.ambiguities = plan.ambiguities;
                cached.metrics.cache_hit = true;
                // A cache hit did not perform the owner's index/count/page
                // work.  Do not attribute those measurements or candidate
                // rows to this request.
                cached.metrics.candidate_count = 0;
                cached.metrics.index_fallback = false;
                cached.metrics.index_fallback_reason = None;
                cached.metrics.count_cache_hit = false;
                cached.metrics.plan_ms = plan_ms;
                cached.metrics.index_ms = 0;
                cached.metrics.count_ms = 0;
                cached.metrics.page_ms = 0;
                cached.metrics.total_ms = elapsed_millis(total_started);
                cached.metrics.lock_wait_ms = wait_ms;
                cached.metrics.cache_retained_bytes = search_cache_retained_bytes();
                return Ok(cached);
            }
            CacheProbe::Owner(flight, wait_ms) => {
                owned_flight = Some(flight);
                cache_wait_ms = wait_ms;
            }
        }
    }

    drop(caller_registration);
    let shared_cancellation = owned_flight
        .as_ref()
        .map(|flight| flight.cancellation.clone());
    let active_cancellation = shared_cancellation.as_ref().unwrap_or(cancellation);
    let mut flight_guard = SearchFlightGuard::new(cache_key.clone(), cancellation, owned_flight);
    let _source_registration = active_cancellation.register_connection(connection)?;
    let mut index_ms = 0;
    let mut count_ms = 0;
    let page_ms;
    let (result, candidate_count, index_fallback, index_fallback_reason, count_cache_hit) =
        if let Some(exact) = plan.exact.as_ref() {
            let page_started = Instant::now();
            let result = search_exact_page(connection, &plan.request, exact);
            page_ms = elapsed_millis(page_started);
            (result, 0, false, None, false)
        } else {
            let index_started = Instant::now();
            let candidates = indexed_candidates(index, &plan.request, active_cancellation)?;
            index_ms = elapsed_millis(index_started);
            let candidate_count = candidates.candidate_count;
            let index_fallback = candidates.index_fallback;
            let index_fallback_reason = candidates.index_fallback_reason.clone();
            let count_started = Instant::now();
            let (counts, count_cache_hit) = cached_article_match_counts(
                connection,
                cache_key.as_ref(),
                candidates.rowids.as_deref(),
                &plan.request,
            )?;
            count_ms = elapsed_millis(count_started);
            let page_started = Instant::now();
            let result = match plan.request.view {
                SearchView::Grouped => search_grouped_with_candidates(
                    connection,
                    &plan.request,
                    candidates.rowids.as_deref(),
                    Some(counts),
                ),
                SearchView::Flat => search_flat_with_candidates_page(
                    connection,
                    &plan.request,
                    candidates.rowids.as_deref(),
                    Some(counts),
                ),
            };
            page_ms = elapsed_millis(page_started);
            (
                result,
                candidate_count,
                index_fallback,
                index_fallback_reason,
                count_cache_hit,
            )
        };

    let mut result = result?;
    result.metrics = SearchMetrics {
        candidate_count,
        index_fallback,
        index_fallback_reason,
        cache_hit: false,
        count_cache_hit,
        cache_retained_bytes: 0,
        lock_wait_ms: cache_wait_ms,
        plan_ms,
        index_ms,
        count_ms,
        page_ms,
        total_ms: elapsed_millis(total_started),
    };
    flight_guard.finish(Some(result.clone()));
    result.metrics.cache_retained_bytes = search_cache_retained_bytes();
    result.metrics.total_ms = elapsed_millis(total_started);
    result.applied_query = plan.applied;
    result.ambiguities = plan.ambiguities;
    Ok(result)
}

#[derive(Clone, Debug)]
struct QueryPlan {
    request: PagedSearchRequest,
    applied: SearchAppliedQuery,
    ambiguities: Vec<LawNameAmbiguity>,
    exact: Option<ExactArticlePlan>,
}

#[derive(Clone, Debug)]
struct ExactArticlePlan {
    document_id: String,
    article_number: String,
    arabic_article_number: String,
}

/// Produce the one normalized plan used by flat results, grouped results,
/// index probing and the cache key.  A law-name/article query is deliberately
/// either resolved to one document or returned as an ambiguity: it never
/// broadens into an unrelated full-text search.
fn compile_query_plan(
    connection: &Connection,
    request: &PagedSearchRequest,
) -> Result<QueryPlan, RetrievalError> {
    validate_version_scope(request)?;
    let mut normalized = request.clone();
    normalized.query = canonical_query(&request.query);
    let mut applied = applied_query_for(&normalized, None, None);
    let mut ambiguities = Vec::new();
    let mut exact = None;

    if let Some((law_name, article_number, arabic_article_number)) =
        split_law_article_query(&normalized.query)
    {
        let law_name = normalize_law_name(&law_name);
        if !law_name.is_empty() {
            let mut statement = connection.prepare(
                "SELECT DISTINCT documents.id, documents.title
                 FROM law_documents documents
                 LEFT JOIN law_aliases aliases ON aliases.document_id = documents.id
                 WHERE documents.title = ?1 OR aliases.alias = ?1 OR aliases.normalized_alias = ?1
                 ORDER BY documents.id ASC",
            )?;
            let candidates = statement
                .query_map([&law_name], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            match candidates.as_slice() {
                [(document_id, _)] => apply_exact_article_plan(
                    &mut normalized,
                    &mut applied,
                    &mut exact,
                    document_id,
                    &article_number,
                    &arabic_article_number,
                )?,
                [] => {
                    // The request contains a syntactically exact selector,
                    // but its law name is absent.  Return no results rather
                    // than silently widening the scope.
                    if normalized.document_id.is_some() {
                        return Err(RetrievalError::InvalidRequest(
                            "document_id is not a candidate for the law name".to_owned(),
                        ));
                    }
                    ambiguities.push(LawNameAmbiguity {
                        query: law_name,
                        candidates: Vec::new(),
                    });
                }
                _ if normalized.document_id.is_some() => {
                    let filtered = normalized
                        .document_id
                        .as_deref()
                        .expect("guard ensures document_id is present");
                    let Some((document_id, _)) = candidates
                        .iter()
                        .find(|(document_id, _)| document_id == filtered)
                    else {
                        return Err(RetrievalError::InvalidRequest(
                            "document_id is not a candidate for the law name".to_owned(),
                        ));
                    };
                    apply_exact_article_plan(
                        &mut normalized,
                        &mut applied,
                        &mut exact,
                        document_id,
                        &article_number,
                        &arabic_article_number,
                    )?;
                }
                _ => ambiguities.push(LawNameAmbiguity {
                    query: law_name,
                    candidates,
                }),
            }
        }
    }
    Ok(QueryPlan {
        request: normalized,
        applied,
        ambiguities,
        exact,
    })
}

fn apply_exact_article_plan(
    normalized: &mut PagedSearchRequest,
    applied: &mut SearchAppliedQuery,
    exact: &mut Option<ExactArticlePlan>,
    document_id: &str,
    article_number: &str,
    arabic_article_number: &str,
) -> Result<(), RetrievalError> {
    if let Some(filtered) = normalized.document_id.as_deref() {
        if filtered != document_id {
            return Err(RetrievalError::InvalidRequest(
                "document_id conflicts with the resolved law name".to_owned(),
            ));
        }
    }
    normalized.document_id = Some(document_id.to_owned());
    // Search the stored canonical Chinese spelling.  The comparison below is
    // literal and document-scoped, so `第一条` cannot accidentally include
    // `第十条`.
    normalized.query = article_number.to_owned();
    normalized.match_mode = SearchMatchMode::Phrase;
    *applied = applied_query_for(
        normalized,
        Some(document_id.to_owned()),
        Some(article_number.to_owned()),
    );
    *exact = Some(ExactArticlePlan {
        document_id: document_id.to_owned(),
        arabic_article_number: arabic_article_number.to_owned(),
        article_number: article_number.to_owned(),
    });
    Ok(())
}

fn search_exact_page(
    connection: &Connection,
    request: &PagedSearchRequest,
    exact: &ExactArticlePlan,
) -> Result<PagedSearchResponse, RetrievalError> {
    // The resolved document id is carried by the request, but keep this
    // assertion at the sole exact-query gateway so a future caller cannot
    // accidentally turn the law-name/article intersection into a broad scan.
    if request.document_id.as_deref() != Some(exact.document_id.as_str()) {
        return Err(RetrievalError::InvalidRequest(
            "exact article plan lost its document constraint".to_owned(),
        ));
    }
    let mut exact_request = request.clone();
    exact_request.query = format!("{EXACT_ARTICLE_PREFIX}{}", exact.article_number);
    let response = match exact_request.view {
        SearchView::Grouped => {
            search_grouped_with_candidates(connection, &exact_request, None, None)
        }
        SearchView::Flat => {
            search_flat_with_candidates_page(connection, &exact_request, None, None)
        }
    }?;
    if response.total > 0 || exact.arabic_article_number == exact.article_number {
        return Ok(response);
    }
    exact_request.query = format!("{EXACT_ARTICLE_PREFIX}{}", exact.arabic_article_number);
    match exact_request.view {
        SearchView::Grouped => {
            search_grouped_with_candidates(connection, &exact_request, None, None)
        }
        SearchView::Flat => {
            search_flat_with_candidates_page(connection, &exact_request, None, None)
        }
    }
}

fn validate_version_scope(request: &PagedSearchRequest) -> Result<(), RetrievalError> {
    match (request.version_scope, request.case_date.as_deref()) {
        (VersionScope::AsOf, None) => Err(RetrievalError::InvalidRequest(
            "as_of version scope requires case_date".to_owned(),
        )),
        (VersionScope::Current | VersionScope::All, Some(_)) => {
            Err(RetrievalError::InvalidRequest(
                "case_date is only valid with as_of version scope".to_owned(),
            ))
        }
        _ => Ok(()),
    }
}

fn applied_query_for(
    request: &PagedSearchRequest,
    resolved_document_id: Option<String>,
    exact_article_number: Option<String>,
) -> SearchAppliedQuery {
    SearchAppliedQuery {
        normalized_query: canonical_query(&request.query),
        match_mode: request.match_mode,
        version_scope: request.version_scope,
        as_of: request.case_date.clone(),
        resolved_document_id,
        exact_article_number,
    }
}

fn canonical_query(input: &str) -> String {
    let mut normalized = String::with_capacity(input.len());
    let mut whitespace = false;
    for character in input.trim().chars() {
        let character = match character {
            '\u{3000}' => ' ',
            '\u{ff01}'..='\u{ff5e}' => {
                char::from_u32(character as u32 - 0xfee0).unwrap_or(character)
            }
            _ => character,
        };
        if character.is_whitespace() {
            whitespace = true;
        } else {
            if whitespace && !normalized.is_empty() {
                normalized.push(' ');
            }
            whitespace = false;
            normalized.push(character);
        }
    }
    normalized
}

fn install_unicode_fold(connection: &Connection) -> Result<(), RetrievalError> {
    connection.create_scalar_function(
        "law_search_fold",
        1,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let value = context.get::<String>(0)?;
            Ok(unicode_fold(&value))
        },
    )?;
    Ok(())
}

fn unicode_fold(value: &str) -> String {
    value
        .nfkd()
        .filter(|character| !is_combining_mark(*character))
        .flat_map(char::to_lowercase)
        .collect()
}

fn requires_unicode_fold(request: &PagedSearchRequest) -> bool {
    query_terms(request).iter().any(|term| {
        term.chars().any(|character| {
            character.is_alphabetic()
                && !matches!(character as u32, 0x3400..=0x4dbf | 0x4e00..=0x9fff | 0xf900..=0xfaff)
        })
    })
}

fn normalize_law_name(value: &str) -> String {
    value
        .trim()
        .trim_matches(|character| matches!(character, '《' | '》' | '"' | '\''))
        .trim()
        .to_owned()
}

fn split_law_article_query(query: &str) -> Option<(String, String, String)> {
    let marker = query.find('第')?;
    let law_name = query[..marker]
        .trim()
        .trim_end_matches([' ', '，', ',', '：', ':'])
        .to_owned();
    let suffix = &query[marker..];
    let end = suffix.find('条')?;
    let raw_number = &suffix['第'.len_utf8()..end];
    if raw_number.is_empty() {
        return None;
    }
    let base = parse_article_ordinal(raw_number)?;
    let tail = suffix[end + '条'.len_utf8()..].trim();
    let (canonical_suffix, arabic_suffix) = if tail.is_empty() {
        (String::new(), String::new())
    } else {
        let addition = parse_article_ordinal(tail.strip_prefix('之')?)?;
        (
            format!("之{}", chinese_number(addition)),
            format!("之{addition}"),
        )
    };
    Some((
        law_name,
        format!("第{}条{canonical_suffix}", chinese_number(base)),
        format!("第{base}条{arabic_suffix}"),
    ))
}

fn parse_article_ordinal(raw: &str) -> Option<u32> {
    if raw.chars().all(|character| character.is_ascii_digit()) {
        return raw.parse().ok().filter(|number: &u32| *number > 0);
    }
    let mut total = 0_u32;
    let mut section = 0_u32;
    let mut pending = 0_u32;
    for character in raw.chars() {
        match character {
            '零' => pending = 0,
            '一' => pending = 1,
            '二' | '两' => pending = 2,
            '三' => pending = 3,
            '四' => pending = 4,
            '五' => pending = 5,
            '六' => pending = 6,
            '七' => pending = 7,
            '八' => pending = 8,
            '九' => pending = 9,
            '十' => {
                if pending == 0 {
                    pending = 1;
                }
                section = section.checked_add(pending.checked_mul(10)?)?;
                pending = 0;
            }
            '百' => {
                if pending == 0 {
                    pending = 1;
                }
                section = section.checked_add(pending.checked_mul(100)?)?;
                pending = 0;
            }
            '千' => {
                if pending == 0 {
                    pending = 1;
                }
                section = section.checked_add(pending.checked_mul(1000)?)?;
                pending = 0;
            }
            '万' => {
                total = total.checked_add(section.checked_add(pending)?.checked_mul(10_000)?)?;
                section = 0;
                pending = 0;
            }
            _ => return None,
        }
    }
    let number = total
        .checked_add(section)?
        .checked_add(pending)
        .filter(|number| *number > 0)?;
    // A permissive accumulator would accept malformed forms such as “十十”
    // as twenty.  Exact article selection must never redirect such input to
    // a different provision, so only the canonical Chinese spelling is
    // accepted here (Arabic digits are handled above).
    (chinese_number(number) == raw).then_some(number)
}

fn chinese_number(value: u32) -> String {
    const DIGITS: [&str; 10] = ["零", "一", "二", "三", "四", "五", "六", "七", "八", "九"];
    if value < 10 {
        return DIGITS[value as usize].to_owned();
    }
    if value < 20 {
        return if value == 10 {
            "十".to_owned()
        } else {
            format!("十{}", DIGITS[(value % 10) as usize])
        };
    }
    let mut output = String::new();
    let mut emitted = false;
    for (divisor, unit) in [(10_000, "万"), (1_000, "千"), (100, "百"), (10, "十")] {
        let digit = (value / divisor) % 10;
        if digit > 0 {
            output.push_str(DIGITS[digit as usize]);
            output.push_str(unit);
            emitted = true;
        } else if emitted && value % divisor >= divisor / 10 && !output.ends_with('零') {
            output.push('零');
        }
    }
    let ones = value % 10;
    if ones > 0 {
        output.push_str(DIGITS[ones as usize]);
    }
    output
}

fn estimate_response_bytes(response: &PagedSearchResponse) -> usize {
    let mut bytes = std::mem::size_of::<PagedSearchResponse>()
        .saturating_add(
            response
                .laws
                .capacity()
                .saturating_mul(std::mem::size_of::<LawSearchGroup>()),
        )
        .saturating_add(
            response
                .articles
                .capacity()
                .saturating_mul(std::mem::size_of::<ArticleSearchResult>()),
        )
        .saturating_add(
            response
                .warnings
                .capacity()
                .saturating_mul(std::mem::size_of::<String>()),
        )
        .saturating_add(
            response
                .ambiguities
                .capacity()
                .saturating_mul(std::mem::size_of::<LawNameAmbiguity>()),
        );
    for group in &response.laws {
        bytes = bytes
            .saturating_add(estimate_law_bytes(&group.law))
            .saturating_add(
                group
                    .top_articles
                    .capacity()
                    .saturating_mul(std::mem::size_of::<ArticleSearchResult>()),
            );
        for article in &group.top_articles {
            bytes = bytes.saturating_add(estimate_article_bytes(article));
        }
    }
    for article in &response.articles {
        bytes = bytes.saturating_add(estimate_article_bytes(article));
    }
    for warning in &response.warnings {
        bytes = bytes.saturating_add(warning.capacity());
    }
    bytes = bytes.saturating_add(estimate_applied_query_bytes(&response.applied_query));
    for ambiguity in &response.ambiguities {
        bytes = bytes
            .saturating_add(ambiguity.query.capacity())
            .saturating_add(
                ambiguity
                    .candidates
                    .capacity()
                    .saturating_mul(std::mem::size_of::<(String, String)>()),
            );
        for (id, title) in &ambiguity.candidates {
            bytes = bytes
                .saturating_add(id.capacity())
                .saturating_add(title.capacity());
        }
    }
    bytes
}

fn estimate_law_bytes(law: &LawSearchResult) -> usize {
    std::mem::size_of::<LawSearchResult>()
        .saturating_add(law.document_id.capacity())
        .saturating_add(law.title.capacity())
        .saturating_add(law.document_type.capacity())
        .saturating_add(law.authority_name.capacity())
        .saturating_add(law.effectiveness_level.capacity())
        .saturating_add(law.status.capacity())
        .saturating_add(law.current_version_id.as_ref().map_or(0, String::capacity))
        .saturating_add(
            law.current_effective_from
                .as_ref()
                .map_or(0, String::capacity),
        )
        .saturating_add(
            law.current_effective_to
                .as_ref()
                .map_or(0, String::capacity),
        )
        .saturating_add(law.matched_alias.as_ref().map_or(0, String::capacity))
        .saturating_add(law.summary.capacity())
}

fn estimate_article_bytes(article: &ArticleSearchResult) -> usize {
    std::mem::size_of::<ArticleSearchResult>()
        .saturating_add(article.article_id.capacity())
        .saturating_add(article.document_id.capacity())
        .saturating_add(article.version_id.capacity())
        .saturating_add(article.document_title.capacity())
        .saturating_add(article.article_number.capacity())
        .saturating_add(article.article_title.as_ref().map_or(0, String::capacity))
        .saturating_add(article.snippet.capacity())
        .saturating_add(article.citation_id.capacity())
        .saturating_add(article.effective_from.capacity())
        .saturating_add(article.effective_to.as_ref().map_or(0, String::capacity))
        .saturating_add(article.version_status.capacity())
}

fn estimate_applied_query_bytes(query: &SearchAppliedQuery) -> usize {
    std::mem::size_of::<SearchAppliedQuery>()
        .saturating_add(query.normalized_query.capacity())
        .saturating_add(query.as_of.as_ref().map_or(0, String::capacity))
        .saturating_add(
            query
                .resolved_document_id
                .as_ref()
                .map_or(0, String::capacity),
        )
        .saturating_add(
            query
                .exact_article_number
                .as_ref()
                .map_or(0, String::capacity),
        )
}

fn estimate_cache_key_bytes(key: &SearchCacheKey) -> usize {
    std::mem::size_of::<SearchCacheKey>()
        .saturating_add(key.identity.capacity())
        .saturating_add(key.query.capacity())
        .saturating_add(key.document_id.as_ref().map_or(0, String::capacity))
        .saturating_add(key.case_date.as_ref().map_or(0, String::capacity))
        .saturating_add(key.document_type.as_ref().map_or(0, String::capacity))
        .saturating_add(key.effectiveness_level.as_ref().map_or(0, String::capacity))
        .saturating_add(key.jurisdiction.as_ref().map_or(0, String::capacity))
        .saturating_add(key.status.as_ref().map_or(0, String::capacity))
        .saturating_add(key.version_status.as_ref().map_or(0, String::capacity))
}

pub fn version_articles(
    connection: &Connection,
    request: VersionArticlesRequest,
) -> Result<VersionArticlesResponse, RetrievalError> {
    if request.version_id.trim().is_empty() {
        return Err(RetrievalError::InvalidRequest(
            "version_id must not be empty".to_owned(),
        ));
    }
    validate_page_values(request.limit, request.offset)?;
    let (document_id, total): (String, i64) = connection
        .query_row(
            "SELECT document_id, (SELECT COUNT(*) FROM law_articles WHERE version_id = versions.id) FROM law_versions versions WHERE id = ?1",
            [&request.version_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or_else(|| RetrievalError::InvalidRequest("version_id was not found".to_owned()))?;
    let mut statement = connection.prepare(
        "SELECT articles.id, articles.document_id, articles.version_id,
                documents.title, versions.version_label, articles.article_number,
                articles.title, articles.content, citation_metadata.citation_id,
                citation_metadata.canonical_label, versions.effective_from,
                versions.effective_to, versions.status, articles.article_order
         FROM law_articles articles
         JOIN law_documents documents ON documents.id = articles.document_id
         JOIN law_versions versions ON versions.id = articles.version_id
         LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
         WHERE articles.version_id = ?1
         ORDER BY articles.article_order ASC, articles.id ASC
         LIMIT ?2 OFFSET ?3",
    )?;
    let rows = statement
        .query_map(
            rusqlite::params![request.version_id, request.limit, request.offset],
            |row| {
                let article_id: String = row.get(0)?;
                let document_id: String = row.get(1)?;
                let version_id: String = row.get(2)?;
                let article_order: i64 = row.get(13)?;
                let citation_id = row.get::<_, Option<String>>(8)?.unwrap_or_else(|| {
                    generate_article_citation_id(
                        &document_id,
                        &version_id,
                        &article_order.to_string(),
                    )
                });
                Ok(LawArticleDetail {
                    article_id,
                    document_id,
                    version_id,
                    document_title: row.get(3)?,
                    version_label: row.get(4)?,
                    article_number: row.get(5)?,
                    article_title: row.get(6)?,
                    content: row.get(7)?,
                    canonical_label: row
                        .get::<_, Option<String>>(9)?
                        .unwrap_or(citation_id.clone()),
                    citation_id,
                    effective_from: row.get(10)?,
                    effective_to: row.get(11)?,
                    version_status: row.get(12)?,
                    topics: Vec::new(),
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VersionArticlesResponse {
        version_id: request.version_id,
        document_id,
        articles: rows,
        total: u64::try_from(total).unwrap_or(u64::MAX),
        limit: request.limit,
        offset: request.offset,
    })
}

/// Check whether an already-addressed version is in the same visibility set
/// used by paged search.  Detail and historical-body services use this before
/// returning an article selected from an earlier search result.
pub fn version_is_visible(
    connection: &Connection,
    version_id: &str,
    version_scope: VersionScope,
    case_date: Option<&str>,
    version_status: Option<&str>,
) -> Result<bool, RetrievalError> {
    let request = PagedSearchRequest {
        query: String::new(),
        match_mode: SearchMatchMode::All,
        version_scope,
        view: SearchView::Flat,
        document_id: None,
        case_date: case_date.map(str::to_owned),
        limit: 1,
        offset: 0,
        document_type: None,
        effectiveness_level: None,
        jurisdiction: None,
        status: None,
        version_status: version_status.map(str::to_owned),
        sort: SearchSort::Relevance,
    };
    validate_version_scope(&request)?;
    let mut builder = SqlBuilder::new();
    let version = builder.bind_text(version_id);
    let predicate = version_visibility_predicate(&mut builder, &request, "versions");
    let sql = format!("SELECT EXISTS(SELECT 1 FROM law_versions versions WHERE versions.id = {version} AND {predicate})");
    Ok(
        connection.query_row(&sql, params_from_iter(builder.values.iter()), |row| {
            row.get(0)
        })?,
    )
}

fn search_grouped_with_candidates(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
    counts: Option<(u64, u64)>,
) -> Result<PagedSearchResponse, RetrievalError> {
    // Both projections derive their totals from the same filtered article
    // rows.  In particular, an index candidate restriction must not be lost
    // when the grouped document EXISTS predicate is compiled.
    let (total_articles, total_laws) = match counts {
        Some(counts) => counts,
        None => count_article_matches(connection, candidate_rowids, request)?,
    };

    let mut page_builder = SqlBuilder::new();
    let page_cte = document_cte(&mut page_builder, request, candidate_rowids);
    let order = document_order(request.sort);
    let page_sql = format!(
        "{page_cte} SELECT document_id, title, document_type, authority_name,
                effectiveness_level, status, current_version_id, current_effective_from,
                current_effective_to, lexical_score, matched_alias, summary
         FROM document_matches ORDER BY {order}, document_id ASC LIMIT ? OFFSET ?"
    );
    page_builder.bind_value(Value::Integer(i64::from(request.limit)));
    page_builder.bind_value(Value::Integer(i64::from(request.offset)));
    let rows = connection
        .prepare(&page_sql)?
        .query_map(params_from_iter(page_builder.values.iter()), |row| {
            Ok(LawSearchResult {
                document_id: row.get(0)?,
                title: row.get(1)?,
                document_type: row.get(2)?,
                authority_name: row.get(3)?,
                effectiveness_level: row.get(4)?,
                status: row.get(5)?,
                current_version_id: row.get(6)?,
                current_effective_from: row.get(7)?,
                current_effective_to: row.get(8)?,
                score: row.get(9)?,
                matched_alias: row.get(10)?,
                summary: row.get(11)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    // One bounded query provides the count and three previews for the laws
    // already selected for this page.  It never materializes the complete
    // cross-corpus result just to render a grouped page.
    let mut previews = grouped_page_previews(connection, request, candidate_rowids, &rows)?;
    let groups = rows
        .into_iter()
        .map(|law| {
            let (matched_article_count, top_articles) =
                previews.remove(&law.document_id).unwrap_or((0, Vec::new()));
            LawSearchGroup {
                law,
                matched_article_count,
                top_articles,
            }
        })
        .collect::<Vec<_>>();
    let mut warnings = Vec::new();
    if total_laws == 0 {
        warnings.push("no_local_results_found".to_owned());
    }
    Ok(PagedSearchResponse {
        view: SearchView::Grouped,
        laws: groups,
        articles: Vec::new(),
        total: total_laws,
        total_laws,
        total_articles,
        limit: request.limit,
        offset: request.offset,
        warnings,
        applied_query: applied_query_for(request, None, None),
        ambiguities: Vec::new(),
        metrics: SearchMetrics::default(),
    })
}

fn grouped_page_previews(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
    laws: &[LawSearchResult],
) -> Result<HashMap<String, (u64, Vec<ArticleSearchResult>)>, RetrievalError> {
    if laws.is_empty() {
        return Ok(HashMap::new());
    }
    let mut builder = SqlBuilder::new();
    let article_source = article_source_table(&mut builder);
    let article_score = article_score_expression(&mut builder, request);
    let document_score = document_score_expression(&mut builder, request);
    let (filters, _) = article_filters(&mut builder, request);
    let predicate = article_match_predicate(&mut builder, request);
    let candidate_filter = candidate_predicate(&mut builder, candidate_rowids);
    let document_ids = laws
        .iter()
        .map(|law| builder.bind_text(&law.document_id))
        .collect::<Vec<_>>()
        .join(", ");
    let order = grouped_preview_order(request.sort);
    let sql = format!(
        "WITH scored AS (
           SELECT articles.id AS article_id, articles.document_id, articles.version_id,
                  documents.title AS document_title, articles.article_number,
                  articles.title AS article_title, articles.content,
                  citation_metadata.citation_id, versions.effective_from,
                  versions.effective_to, versions.status AS version_status,
                  articles.article_order, documents.effectiveness_level, versions.published_on,
                  ({article_score}) + ({document_score}) AS total_score
           FROM {article_source} articles
           JOIN law_documents documents ON documents.id = articles.document_id
           JOIN law_versions versions ON versions.id = articles.version_id
           LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
           WHERE {filters} AND ({predicate}) {candidate_filter}
             AND documents.id IN ({document_ids})
         ), ranked AS (
           SELECT scored.*,
                  COUNT(*) OVER (PARTITION BY document_id) AS matched_count,
                  ROW_NUMBER() OVER (PARTITION BY document_id ORDER BY {order}) AS preview_rank
           FROM scored
         )
         SELECT article_id, document_id, version_id, document_title, article_number,
                article_title, content, citation_id, effective_from, effective_to,
                version_status, article_order, effectiveness_level, total_score,
                matched_count
         FROM ranked
         WHERE preview_rank <= 3
         ORDER BY document_id ASC, preview_rank ASC"
    );
    let terms = query_terms(request);
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(builder.values.iter()), |row| {
        let article = article_from_paged_row(row, &terms)?;
        let matched_count: i64 = row.get(14)?;
        Ok((article, u64::try_from(matched_count).unwrap_or(u64::MAX)))
    })?;
    let mut grouped = HashMap::with_capacity(laws.len());
    for row in rows {
        let (article, matched_count) = row?;
        let entry = grouped
            .entry(article.document_id.clone())
            .or_insert_with(|| (matched_count, Vec::with_capacity(3)));
        entry.0 = matched_count;
        entry.1.push(article);
    }
    Ok(grouped)
}

fn grouped_preview_order(sort: SearchSort) -> &'static str {
    match sort {
        SearchSort::Relevance => {
            "total_score DESC, CASE WHEN version_status = 'in_force' THEN 0 ELSE 1 END, CASE effectiveness_level WHEN 'constitution' THEN 0 WHEN 'national_law' THEN 1 WHEN 'administrative_regulation' THEN 2 WHEN 'supervision_regulation' THEN 2 WHEN 'judicial_interpretation' THEN 3 WHEN 'department_rule' THEN 4 WHEN 'autonomous_regulation' THEN 5 WHEN 'special_zone_regulation' THEN 5 WHEN 'local_regulation' THEN 6 WHEN 'local_government_rule' THEN 7 ELSE 8 END, document_title ASC, article_order ASC, article_id ASC"
        }
        SearchSort::Effectiveness => {
            "CASE effectiveness_level WHEN 'constitution' THEN 0 WHEN 'national_law' THEN 1 WHEN 'administrative_regulation' THEN 2 WHEN 'supervision_regulation' THEN 2 WHEN 'judicial_interpretation' THEN 3 WHEN 'department_rule' THEN 4 WHEN 'autonomous_regulation' THEN 5 WHEN 'special_zone_regulation' THEN 5 WHEN 'local_regulation' THEN 6 WHEN 'local_government_rule' THEN 7 ELSE 8 END, total_score DESC, document_title ASC, article_order ASC, article_id ASC"
        }
        SearchSort::EffectiveDate => {
            "COALESCE(effective_from, '0001-01-01') DESC, total_score DESC, document_title ASC, article_order ASC, article_id ASC"
        }
        SearchSort::PublishedDate => {
            "COALESCE(published_on, '0001-01-01') DESC, total_score DESC, document_title ASC, article_order ASC, article_id ASC"
        }
        SearchSort::Title => {
            "document_title ASC, article_order ASC, total_score DESC, article_id ASC"
        }
    }
}

fn search_flat_with_candidates_page(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
    counts: Option<(u64, u64)>,
) -> Result<PagedSearchResponse, RetrievalError> {
    let (total_articles, total_laws) = match counts {
        Some(counts) => counts,
        None => count_article_matches(connection, candidate_rowids, request)?,
    };

    let mut result = search_flat_with_candidates(connection, request, candidate_rowids)?;
    result.total = total_articles;
    result.total_laws = total_laws;
    result.total_articles = total_articles;
    if total_articles == 0 {
        result.warnings.push("no_local_results_found".to_owned());
    }
    Ok(result)
}

fn search_flat_with_candidates(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
) -> Result<PagedSearchResponse, RetrievalError> {
    let mut page_builder = SqlBuilder::new();
    let sql = article_page_sql(
        &mut page_builder,
        request,
        candidate_rowids,
        Some((request.limit, request.offset)),
    );
    page_builder.bind_value(Value::Integer(i64::from(request.limit)));
    page_builder.bind_value(Value::Integer(i64::from(request.offset)));
    let terms = query_terms(request);
    let articles = connection
        .prepare(&sql)?
        .query_map(params_from_iter(page_builder.values.iter()), |row| {
            article_from_paged_row(row, &terms)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PagedSearchResponse {
        view: SearchView::Flat,
        laws: Vec::new(),
        articles,
        total: 0,
        total_laws: 0,
        total_articles: 0,
        limit: request.limit,
        offset: request.offset,
        warnings: Vec::new(),
        applied_query: applied_query_for(request, None, None),
        ambiguities: Vec::new(),
        metrics: SearchMetrics::default(),
    })
}

fn count_article_matches(
    connection: &Connection,
    candidate_rowids: Option<&[i64]>,
    request: &PagedSearchRequest,
) -> Result<(u64, u64), RetrievalError> {
    let mut builder = SqlBuilder::new();
    let article_source = article_source_table(&mut builder);
    let (filters, _) = article_filters(&mut builder, request);
    let predicate = article_match_predicate(&mut builder, request);
    let candidate_filter = candidate_predicate(&mut builder, candidate_rowids);
    let sql = format!(
        "SELECT COUNT(*), COUNT(DISTINCT articles.document_id)
         FROM {article_source} articles
         JOIN law_documents documents ON documents.id = articles.document_id
         JOIN law_versions versions ON versions.id = articles.version_id
         WHERE {filters} AND ({predicate}) {candidate_filter}"
    );
    let (total_articles, total_laws): (i64, i64) =
        connection.query_row(&sql, params_from_iter(builder.values.iter()), |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    Ok((
        u64::try_from(total_articles).unwrap_or(u64::MAX),
        u64::try_from(total_laws).unwrap_or(u64::MAX),
    ))
}

fn cached_article_match_counts(
    connection: &Connection,
    page_key: Option<&SearchCacheKey>,
    candidate_rowids: Option<&[i64]>,
    request: &PagedSearchRequest,
) -> Result<((u64, u64), bool), RetrievalError> {
    let count_key = page_key.map(CountCacheKey::from_page_key);
    if let Some(key) = count_key.as_ref() {
        let (mutex, _) = search_cache();
        let mut cache = mutex
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(counts) = count_cache_get_locked(&mut cache, key) {
            return Ok((counts, true));
        }
    }
    let counts = count_article_matches(connection, candidate_rowids, request)?;
    if let Some(key) = count_key {
        count_cache_store(key, counts);
    }
    Ok((counts, false))
}

struct IndexedCandidates {
    rowids: Option<Vec<i64>>,
    candidate_count: u64,
    index_fallback: bool,
    index_fallback_reason: Option<String>,
    // Keep the index connection registered through the authoritative source
    // query; cancellation must interrupt both SQLite connections.
    _registration: Option<CancellationRegistration>,
}

fn indexed_candidates(
    index: Option<&SearchIndex>,
    request: &PagedSearchRequest,
    cancellation: &SearchCancellation,
) -> Result<IndexedCandidates, RetrievalError> {
    // The derived bigram index is literal.  Unicode folding (for example,
    // `cafe` matching `Café`) has to scan the folded authoritative source,
    // otherwise index/no-index results could diverge.
    if requires_unicode_fold(request) {
        return Ok(IndexedCandidates {
            rowids: None,
            candidate_count: 0,
            index_fallback: true,
            index_fallback_reason: Some(FALLBACK_REASON_UNSUPPORTED_TERM.to_owned()),
            _registration: None,
        });
    }
    let Some(index) = index else {
        let has_terms = !query_terms(request).is_empty();
        return Ok(IndexedCandidates {
            rowids: None,
            candidate_count: 0,
            // This is intentionally observable: an ordinary textual query
            // against a missing/stale derived index performs the complete
            // authoritative SQLite scan.  Exact law/article selectors take
            // their equality path before this function and remain false.
            index_fallback: has_terms,
            index_fallback_reason: has_terms
                .then_some(FALLBACK_REASON_INDEX_UNAVAILABLE.to_owned()),
            _registration: None,
        });
    };
    let registration = index.register_cancellation(cancellation)?;
    let terms = query_terms(request);
    let probe = index.article_rowids_for_terms_with_reason(
        &terms,
        request.match_mode,
        Some(cancellation),
    )?;
    ensure_index_probe_not_cancelled(Some(cancellation))?;
    let source_parameter_fallback = probe
        .rowids
        .as_ref()
        .is_some_and(|candidates| !candidate_rows_fit_source_queries(request, candidates.len()));
    let rowids = if source_parameter_fallback {
        None
    } else {
        probe.rowids
    };
    let index_fallback_reason = if source_parameter_fallback {
        Some(FALLBACK_REASON_PARAMETER_LIMIT.to_owned())
    } else {
        probe.fallback_reason.map(str::to_owned)
    };
    let candidate_count = rowids.as_ref().map_or(0, |candidates| {
        u64::try_from(candidates.len()).unwrap_or(u64::MAX)
    });
    Ok(IndexedCandidates {
        index_fallback: rowids.is_none() && index_fallback_reason.is_some(),
        index_fallback_reason,
        rowids,
        candidate_count,
        _registration: Some(registration),
    })
}

fn candidate_rows_fit_source_queries(request: &PagedSearchRequest, candidate_count: usize) -> bool {
    let mut count_builder = SqlBuilder::new();
    let _article_source = article_source_table(&mut count_builder);
    let _filters = article_filters(&mut count_builder, request);
    let _predicate = article_match_predicate(&mut count_builder, request);
    let count_parameters = count_builder.values.len();
    if !fits_sqlite_parameter_limit(count_parameters, candidate_count) {
        return false;
    }

    let mut flat_builder = SqlBuilder::new();
    let _flat_sql = article_page_sql(
        &mut flat_builder,
        request,
        None,
        Some((request.limit, request.offset)),
    );
    let flat_parameters = flat_builder.values.len() + 2;
    if !fits_sqlite_parameter_limit(flat_parameters, candidate_count) {
        return false;
    }

    let mut grouped_builder = SqlBuilder::new();
    let _grouped_cte = document_cte(&mut grouped_builder, request, None);
    let grouped_parameters = grouped_builder.values.len() + 2;
    if !fits_sqlite_parameter_limit(grouped_parameters, candidate_count) {
        return false;
    }

    // A grouped response executes a second query for up to `limit` law
    // previews. Reserve that worst case before admitting index rowids;
    // otherwise a page that fits the CTE can still exceed SQLite's variable
    // limit while rendering previews. Applying this bound to both views keeps
    // the candidate decision stable when the same query changes presentation.
    let mut preview_builder = SqlBuilder::new();
    let _article_source = article_source_table(&mut preview_builder);
    let _article_score = article_score_expression(&mut preview_builder, request);
    let _document_score = document_score_expression(&mut preview_builder, request);
    let _filters = article_filters(&mut preview_builder, request);
    let _predicate = article_match_predicate(&mut preview_builder, request);
    let _candidate_filter = candidate_predicate(&mut preview_builder, None);
    for _ in 0..request.limit as usize {
        preview_builder.bind_text("");
    }
    let preview_parameters = preview_builder.values.len();
    fits_sqlite_parameter_limit(preview_parameters, candidate_count)
}

fn fits_sqlite_parameter_limit(base_parameters: usize, candidate_count: usize) -> bool {
    base_parameters
        .checked_add(candidate_count)
        .is_some_and(|total| total <= MAX_SQLITE_PARAMETERS)
}

fn article_page_sql(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
    candidates: Option<&[i64]>,
    page: Option<(u32, u32)>,
) -> String {
    let article_source = article_source_table(builder);
    // Positional bind parameters must be added in the same order as their
    // first appearance in the SQL text (SELECT expressions precede WHERE).
    let article_score = article_score_expression(builder, request);
    let document_score = document_score_expression(builder, request);
    let (filters, _) = article_filters(builder, request);
    let predicate = article_match_predicate(builder, request);
    let candidate_filter = candidate_predicate(builder, candidates);
    let order = article_order(request.sort);
    let pagination = if page.is_some() {
        " LIMIT ? OFFSET ?"
    } else {
        ""
    };
    format!(
        "SELECT articles.id, articles.document_id, articles.version_id,
                documents.title, articles.article_number, articles.title, articles.content,
                citation_metadata.citation_id, versions.effective_from, versions.effective_to,
                versions.status, articles.article_order, documents.effectiveness_level,
                ({article_score}) + ({document_score}) AS total_score
         FROM {article_source} articles
         JOIN law_documents documents ON documents.id = articles.document_id
         JOIN law_versions versions ON versions.id = articles.version_id
         LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
         WHERE {filters} AND ({predicate}) {candidate_filter}
         ORDER BY {order}, articles.id ASC{pagination}"
    )
}

fn article_from_paged_row(
    row: &rusqlite::Row<'_>,
    terms: &[String],
) -> rusqlite::Result<ArticleSearchResult> {
    let document_id: String = row.get(1)?;
    let version_id: String = row.get(2)?;
    let article_number: String = row.get(4)?;
    let article_title: Option<String> = row.get(5)?;
    let content: String = row.get(6)?;
    let article_order: i64 = row.get(11)?;
    let citation_id = row.get::<_, Option<String>>(7)?.unwrap_or_else(|| {
        generate_article_citation_id(&document_id, &version_id, &article_order.to_string())
    });
    let total_score: f64 = row.get(13)?;
    Ok(ArticleSearchResult {
        article_id: row.get(0)?,
        document_id,
        version_id,
        document_title: row.get(3)?,
        article_number,
        article_title,
        snippet: snippet_for_terms(terms, &content),
        citation_id,
        effective_from: row.get(8)?,
        effective_to: row.get(9)?,
        version_status: row.get(10)?,
        score: total_score,
    })
}

fn document_cte(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
    candidates: Option<&[i64]>,
) -> String {
    // The CTE precedes SELECT expressions in SQL, so bind its version
    // parameters first.  This keeps placeholder ordering exact for as-of
    // searches.
    let selected_versions = selected_versions_cte(builder, request);
    // Materialize only document ids from the same article predicate that
    // backs flat pages and exact counts. This admits the index candidate set
    // directly and avoids a metadata-correlated EXISTS scan per document.
    let article_source = article_source_table(builder);
    let (article_filters, _) = article_filters(builder, request);
    let article_match = article_match_predicate(builder, request);
    let candidate_filter = candidate_predicate(builder, candidates);
    let matched_articles = format!(
        "matched_article_documents AS (
           SELECT DISTINCT articles.document_id
           FROM {article_source} articles
           JOIN law_documents documents ON documents.id = articles.document_id
           JOIN law_versions versions ON versions.id = articles.version_id
           WHERE {article_filters} AND ({article_match}) {candidate_filter}
         )"
    );
    // SELECT expressions are written before WHERE, so bind their parameters
    // before the document-level filters.
    let score = document_score_expression(builder, request);
    let alias_like = builder.bind_like(request.query.trim());
    let (filters, _) = document_filters(builder, request);
    format!(
        "{selected_versions}, {matched_articles}, document_matches AS (
          SELECT documents.id AS document_id, documents.title, documents.document_type,
                 authorities.name AS authority_name, documents.effectiveness_level,
                 documents.status, selected_versions.id AS current_version_id,
                 selected_versions.effective_from AS current_effective_from,
                 selected_versions.effective_to AS current_effective_to,
                 {score} AS lexical_score,
                 MAX(CASE WHEN aliases.alias LIKE {alias_like} ESCAPE '\\' THEN aliases.alias ELSE NULL END) AS matched_alias,
                 documents.summary
          FROM matched_article_documents matched_documents
          JOIN law_documents documents ON documents.id = matched_documents.document_id
          JOIN issuing_authorities authorities ON authorities.id = documents.authority_id
          LEFT JOIN law_aliases aliases ON aliases.document_id = documents.id
          LEFT JOIN selected_versions ON selected_versions.document_id = documents.id
          WHERE {filters}
          GROUP BY documents.id
        )"
    )
}

fn selected_versions_cte(builder: &mut SqlBuilder, request: &PagedSearchRequest) -> String {
    let visibility = version_visibility_predicate(builder, request, "versions");
    format!(
        "WITH ranked_selected_versions AS (
           SELECT versions.*, ROW_NUMBER() OVER (
             PARTITION BY versions.document_id
             ORDER BY COALESCE(versions.effective_from, '0001-01-01') DESC, versions.id DESC
           ) AS selected_rank
           FROM law_versions versions WHERE {visibility}
         ), selected_versions AS (
           SELECT * FROM ranked_selected_versions WHERE selected_rank = 1
         )"
    )
}

fn version_visibility_predicate(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
    alias: &str,
) -> String {
    let mut clauses = Vec::new();
    match request.version_scope {
        VersionScope::Current => {
            clauses.push(known_iso_date_predicate(&format!("{alias}.effective_from")));
            clauses.push(format!("{alias}.effective_from <= date('now','localtime')"));
            clauses.push(format!(
                "({alias}.effective_to IS NULL OR ({} AND {alias}.effective_to >= date('now','localtime')))",
                known_iso_date_predicate(&format!("{alias}.effective_to")),
            ));
            clauses.push(format!("{alias}.status = 'in_force'"));
        }
        VersionScope::AsOf => {
            let date =
                builder.bind_text(request.case_date.as_deref().expect("validated as_of date"));
            clauses.push(known_iso_date_predicate(&format!("{alias}.effective_from")));
            clauses.push(format!("{alias}.effective_from <= {date}"));
            clauses.push(format!(
                "({alias}.effective_to IS NULL OR ({} AND {alias}.effective_to >= {date}))",
                known_iso_date_predicate(&format!("{alias}.effective_to")),
            ));
            clauses.push(format!(
                "NOT ({alias}.status = 'repealed' AND {alias}.effective_to IS NULL)"
            ));
            clauses.push(format!("{alias}.status <> 'not_yet_effective'"));
        }
        VersionScope::All => {}
    }
    if let Some(status) = request.version_status.as_deref() {
        clauses.push(format!("{alias}.status = {}", builder.bind_text(status)));
    }
    if clauses.is_empty() {
        "1 = 1".to_owned()
    } else {
        clauses.join(" AND ")
    }
}

fn known_iso_date_predicate(column: &str) -> String {
    // SQLite's lexical date comparisons accept an empty string and some
    // malformed calendar dates.  `date(julianday(...))` round-trips only a
    // real YYYY-MM-DD calendar date, so unknown/invalid metadata cannot be
    // inferred as currently effective.
    format!(
        "({column} IS NOT NULL AND length({column}) = 10 AND {column} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' AND date(julianday({column})) = {column})"
    )
}

fn document_filters(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
) -> (String, Vec<String>) {
    let mut clauses = Vec::new();
    let mut columns = Vec::new();
    if let Some(value) = request.document_id.as_deref() {
        clauses.push(format!("documents.id = {}", builder.bind_text(value)));
    }
    if let Some(value) = request.document_type.as_deref() {
        clauses.push(format!(
            "documents.document_type = {}",
            builder.bind_text(value)
        ));
    }
    if let Some(value) = request.effectiveness_level.as_deref() {
        clauses.push(format!(
            "documents.effectiveness_level = {}",
            builder.bind_text(value)
        ));
    }
    if let Some(value) = request.jurisdiction.as_deref() {
        clauses.push(format!(
            "documents.jurisdiction = {}",
            builder.bind_text(value)
        ));
    }
    if let Some(value) = request.status.as_deref() {
        clauses.push(format!("documents.status = {}", builder.bind_text(value)));
    }
    if request.version_scope != VersionScope::All {
        let visibility = version_visibility_predicate(builder, request, "date_versions");
        clauses.push(format!(
            "EXISTS (SELECT 1 FROM law_versions date_versions WHERE date_versions.document_id = documents.id AND {visibility})"
        ));
    }
    if clauses.is_empty() {
        clauses.push("1 = 1".to_owned());
    }
    columns.extend(clauses.iter().cloned());
    (clauses.join(" AND "), columns)
}

fn article_filters(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
) -> (String, Vec<String>) {
    let mut clauses = Vec::new();
    if let Some(value) = request.document_id.as_deref() {
        clauses.push(format!("documents.id = {}", builder.bind_text(value)));
    }
    if let Some(value) = request.document_type.as_deref() {
        clauses.push(format!(
            "documents.document_type = {}",
            builder.bind_text(value)
        ));
    }
    if let Some(value) = request.effectiveness_level.as_deref() {
        clauses.push(format!(
            "documents.effectiveness_level = {}",
            builder.bind_text(value)
        ));
    }
    if let Some(value) = request.jurisdiction.as_deref() {
        clauses.push(format!(
            "documents.jurisdiction = {}",
            builder.bind_text(value)
        ));
    }
    if let Some(value) = request.status.as_deref() {
        clauses.push(format!("documents.status = {}", builder.bind_text(value)));
    }
    clauses.push(version_visibility_predicate(builder, request, "versions"));
    clauses.push(selected_version_predicate(builder, request, "versions"));
    if clauses.is_empty() {
        clauses.push("1 = 1".to_owned());
    }
    (clauses.join(" AND "), clauses)
}

fn article_match_predicate(builder: &mut SqlBuilder, request: &PagedSearchRequest) -> String {
    article_match_predicate_for_aliases(builder, request, "articles", "documents")
}

fn selected_version_predicate(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
    alias: &str,
) -> String {
    if request.version_scope == VersionScope::All {
        return "1 = 1".to_owned();
    }
    let newer_visibility = version_visibility_predicate(builder, request, "newer_versions");
    format!(
        "NOT EXISTS (
           SELECT 1 FROM law_versions newer_versions
           WHERE newer_versions.document_id = {alias}.document_id
             AND {newer_visibility}
             AND (
               newer_versions.effective_from > {alias}.effective_from
               OR (newer_versions.effective_from = {alias}.effective_from AND newer_versions.id > {alias}.id)
             )
         )"
    )
}

fn article_match_predicate_for_aliases(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
    article_alias: &str,
    document_alias: &str,
) -> String {
    if let Some(article_number) = exact_article_term(request) {
        return format!(
            "{article_alias}.article_number = {}",
            builder.bind_text(article_number)
        );
    }
    let terms = query_terms(request);
    if terms.is_empty() {
        return "1 = 1".to_owned();
    }
    let fold = requires_unicode_fold(request);
    let joiner = match request.match_mode {
        SearchMatchMode::All => " AND ",
        SearchMatchMode::Any | SearchMatchMode::Phrase => " OR ",
    };
    terms
        .iter()
        .map(|term| {
            let folded_term;
            let match_term = if fold {
                folded_term = unicode_fold(term);
                &folded_term
            } else {
                term.as_str()
            };
            let like = builder.bind_like(match_term);
            let document_title = folded_column(&format!("{document_alias}.title"), fold);
            let alias = folded_column("matched_aliases.alias", fold);
            let normalized_alias = folded_column("matched_aliases.normalized_alias", fold);
            let article_number = folded_column(&format!("{article_alias}.article_number"), fold);
            let article_title = folded_column(&format!("COALESCE({article_alias}.title, '')"), fold);
            let article_content = folded_column(&format!("{article_alias}.content"), fold);
            format!(
                "({document_title} LIKE {like} ESCAPE '\\' OR EXISTS (SELECT 1 FROM law_aliases matched_aliases WHERE matched_aliases.document_id = {document_alias}.id AND ({alias} LIKE {like} ESCAPE '\\' OR {normalized_alias} LIKE {like} ESCAPE '\\')) OR {article_number} LIKE {like} ESCAPE '\\' OR {article_title} LIKE {like} ESCAPE '\\' OR {article_content} LIKE {like} ESCAPE '\\')"
            )
        })
        .collect::<Vec<_>>()
        .join(joiner)
}

fn folded_column(column: &str, fold: bool) -> String {
    if fold {
        format!("law_search_fold({column})")
    } else {
        column.to_owned()
    }
}

fn document_score_expression(builder: &mut SqlBuilder, request: &PagedSearchRequest) -> String {
    let terms = query_terms(request);
    if terms.is_empty() {
        return "0.0".to_owned();
    }
    let mut scores = Vec::new();
    for term in terms {
        let exact = builder.bind_text(&term);
        let prefix = builder.bind_prefix(&term);
        let like = builder.bind_like(&term);
        let topic = builder.bind_like(&format!("{}法", term));
        scores.push(format!(
            "CASE WHEN documents.title = {exact} THEN 1000000.0
                  WHEN EXISTS (SELECT 1 FROM law_aliases exact_aliases WHERE exact_aliases.document_id = documents.id AND (exact_aliases.alias = {exact} OR exact_aliases.normalized_alias = {exact})) THEN 950000.0
                  WHEN documents.title LIKE {prefix} ESCAPE '\\' THEN 850000.0
                  WHEN EXISTS (SELECT 1 FROM law_aliases prefix_aliases WHERE prefix_aliases.document_id = documents.id AND (prefix_aliases.alias LIKE {prefix} ESCAPE '\\' OR prefix_aliases.normalized_alias LIKE {prefix} ESCAPE '\\')) THEN 820000.0
                  WHEN documents.title LIKE {like} ESCAPE '\\' THEN 700000.0
                  WHEN EXISTS (SELECT 1 FROM law_aliases partial_aliases WHERE partial_aliases.document_id = documents.id AND (partial_aliases.alias LIKE {like} ESCAPE '\\' OR partial_aliases.normalized_alias LIKE {like} ESCAPE '\\')) THEN 650000.0
                  WHEN documents.summary LIKE {like} ESCAPE '\\' THEN 450000.0 ELSE 0.0 END
             + CASE WHEN documents.title LIKE {topic} ESCAPE '\\'
                         OR EXISTS (SELECT 1 FROM law_aliases topic_aliases WHERE topic_aliases.document_id = documents.id AND (topic_aliases.alias LIKE {topic} ESCAPE '\\' OR topic_aliases.normalized_alias LIKE {topic} ESCAPE '\\'))
                    THEN 220000.0 ELSE 0.0 END"
        ));
    }
    format!("({})", scores.join(" + "))
}

fn article_score_expression(builder: &mut SqlBuilder, request: &PagedSearchRequest) -> String {
    let terms = query_terms(request);
    if terms.is_empty() {
        return "0.0".to_owned();
    }
    let mut scores = Vec::new();
    for term in terms {
        let like = builder.bind_like(&term);
        let exact = builder.bind_text(&term);
        scores.push(format!(
            "CASE WHEN articles.content LIKE {like} ESCAPE '\\' THEN 100000.0 ELSE 0.0 END
             + CASE WHEN COALESCE(articles.title, '') LIKE {like} ESCAPE '\\' THEN 300000.0 ELSE 0.0 END
             + CASE WHEN articles.article_number = {exact} THEN 250000.0 ELSE 0.0 END"
        ));
    }
    format!("({})", scores.join(" + "))
}

fn document_order(sort: SearchSort) -> &'static str {
    match sort {
        SearchSort::Relevance => {
            "lexical_score DESC, CASE WHEN status = 'in_force' THEN 0 ELSE 1 END, CASE effectiveness_level WHEN 'constitution' THEN 0 WHEN 'national_law' THEN 1 WHEN 'administrative_regulation' THEN 2 WHEN 'supervision_regulation' THEN 2 WHEN 'judicial_interpretation' THEN 3 WHEN 'department_rule' THEN 4 WHEN 'autonomous_regulation' THEN 5 WHEN 'special_zone_regulation' THEN 5 WHEN 'local_regulation' THEN 6 WHEN 'local_government_rule' THEN 7 ELSE 8 END, title ASC"
        }
        SearchSort::Effectiveness => {
            "CASE effectiveness_level WHEN 'constitution' THEN 0 WHEN 'national_law' THEN 1 WHEN 'administrative_regulation' THEN 2 WHEN 'supervision_regulation' THEN 2 WHEN 'judicial_interpretation' THEN 3 WHEN 'department_rule' THEN 4 WHEN 'autonomous_regulation' THEN 5 WHEN 'special_zone_regulation' THEN 5 WHEN 'local_regulation' THEN 6 WHEN 'local_government_rule' THEN 7 ELSE 8 END, lexical_score DESC, CASE WHEN status = 'in_force' THEN 0 ELSE 1 END, title ASC"
        }
        SearchSort::EffectiveDate => {
            "COALESCE(current_effective_from, '0001-01-01') DESC, lexical_score DESC, title ASC"
        }
        SearchSort::PublishedDate => {
            "COALESCE((SELECT MAX(published_on) FROM law_versions published_versions WHERE published_versions.document_id = document_matches.document_id), '0001-01-01') DESC, lexical_score DESC, title ASC"
        }
        SearchSort::Title => {
            "title ASC, lexical_score DESC, CASE WHEN status = 'in_force' THEN 0 ELSE 1 END"
        }
    }
}

fn article_order(sort: SearchSort) -> &'static str {
    match sort {
        SearchSort::Relevance => {
            "total_score DESC, CASE WHEN versions.status = 'in_force' THEN 0 ELSE 1 END, CASE documents.effectiveness_level WHEN 'constitution' THEN 0 WHEN 'national_law' THEN 1 WHEN 'administrative_regulation' THEN 2 WHEN 'supervision_regulation' THEN 2 WHEN 'judicial_interpretation' THEN 3 WHEN 'department_rule' THEN 4 WHEN 'autonomous_regulation' THEN 5 WHEN 'special_zone_regulation' THEN 5 WHEN 'local_regulation' THEN 6 WHEN 'local_government_rule' THEN 7 ELSE 8 END, documents.title ASC, articles.article_order ASC"
        }
        SearchSort::Effectiveness => {
            "CASE documents.effectiveness_level WHEN 'constitution' THEN 0 WHEN 'national_law' THEN 1 WHEN 'administrative_regulation' THEN 2 WHEN 'supervision_regulation' THEN 2 WHEN 'judicial_interpretation' THEN 3 WHEN 'department_rule' THEN 4 WHEN 'autonomous_regulation' THEN 5 WHEN 'special_zone_regulation' THEN 5 WHEN 'local_regulation' THEN 6 WHEN 'local_government_rule' THEN 7 ELSE 8 END, total_score DESC, documents.title ASC, articles.article_order ASC"
        }
        SearchSort::EffectiveDate => {
            "COALESCE(versions.effective_from, '0001-01-01') DESC, total_score DESC, documents.title ASC, articles.article_order ASC"
        }
        SearchSort::PublishedDate => {
            "COALESCE(versions.published_on, '0001-01-01') DESC, total_score DESC, documents.title ASC, articles.article_order ASC"
        }
        SearchSort::Title => "documents.title ASC, articles.article_order ASC, total_score DESC",
    }
}

fn candidate_predicate(builder: &mut SqlBuilder, candidates: Option<&[i64]>) -> String {
    candidate_predicate_for_aliases(builder, candidates, "articles")
}

fn candidate_predicate_for_aliases(
    builder: &mut SqlBuilder,
    candidates: Option<&[i64]>,
    article_alias: &str,
) -> String {
    let Some(candidates) = candidates else {
        return String::new();
    };
    if candidates.is_empty() {
        return "AND 0 = 1".to_owned();
    }
    let placeholders = candidates
        .iter()
        .map(|candidate| builder.bind_value(Value::Integer(*candidate)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("AND {article_alias}.rowid IN ({placeholders})")
}

fn article_source_table(_builder: &mut SqlBuilder) -> &'static str {
    // `law_articles` is a compatibility view in runtime-slim databases and a
    // table in archival fixtures.  Both expose a stable rowid and the same
    // columns, so one query works for both layouts.
    "law_articles"
}

fn query_terms(request: &PagedSearchRequest) -> Vec<String> {
    let query = exact_article_term(request).unwrap_or(&request.query);
    if request.match_mode == SearchMatchMode::Phrase {
        let phrase = canonical_query(query);
        return (!phrase.is_empty() && !phrase.chars().any(char::is_control))
            .then_some(phrase)
            .into_iter()
            .collect();
    }
    let mut terms = Vec::new();
    for term in query.split_whitespace().take(MAX_SEARCH_TERMS) {
        let term = term.trim();
        if term.is_empty() || term.chars().any(char::is_control) {
            continue;
        }
        terms.push(term.to_owned());
    }
    if terms.is_empty() && !query.trim().is_empty() {
        terms.push(query.trim().to_owned());
    }
    terms
}

fn exact_article_term(request: &PagedSearchRequest) -> Option<&str> {
    request.query.strip_prefix(EXACT_ARTICLE_PREFIX)
}

fn validate_page(request: &PagedSearchRequest) -> Result<(), RetrievalError> {
    validate_page_values(request.limit, request.offset)
}

fn validate_page_values(limit: u32, offset: u32) -> Result<(), RetrievalError> {
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        return Err(RetrievalError::InvalidRequest(format!(
            "limit must be between 1 and {MAX_PAGE_LIMIT}"
        )));
    }
    if offset > MAX_PAGE_OFFSET {
        return Err(RetrievalError::InvalidRequest(format!(
            "offset must not exceed {MAX_PAGE_OFFSET}"
        )));
    }
    Ok(())
}

struct SqlBuilder {
    values: Vec<Value>,
}

impl SqlBuilder {
    fn new() -> Self {
        Self { values: Vec::new() }
    }

    fn bind_value(&mut self, value: Value) -> String {
        self.values.push(value);
        format!("?{}", self.values.len())
    }

    fn bind_text(&mut self, value: &str) -> String {
        self.bind_value(Value::Text(value.to_owned()))
    }

    fn bind_like(&mut self, value: &str) -> String {
        self.bind_text(&like_pattern(value))
    }

    fn bind_prefix(&mut self, value: &str) -> String {
        self.bind_text(&format!("{}%", escape_like(value)))
    }
}

#[cfg(test)]
#[path = "paged/audit_tests.rs"]
mod audit_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fixture() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
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
                INSERT INTO law_documents VALUES ('national','中华人民共和国公司法','law','npc','CN','national_law','in_force','2023-12-29','公司组织法律规范');
                INSERT INTO law_documents VALUES ('local','某地公司登记办法','local_regulation','npc','CN','local_regulation','in_force','2023-12-29','地方登记');
                INSERT INTO law_versions VALUES ('national-v1','national','现行版','in_force','2024-07-01',NULL,'2023-12-29','fixture');
                INSERT INTO law_versions VALUES ('local-v1','local','现行版','in_force','2024-01-01',NULL,'2024-01-01','fixture');
                INSERT INTO law_articles VALUES ('national-a1','national','national-v1','第一条',1,NULL,'公司是企业法人。');
                INSERT INTO law_articles VALUES ('national-a2','national','national-v1','第二条',2,NULL,'合同与公司治理。');
                INSERT INTO law_articles VALUES ('local-a1','local','local-v1','第一条',1,NULL,'公司登记由地方机关负责。');
                INSERT INTO law_aliases VALUES ('alias','national','公司法','公司法');
                INSERT INTO law_aliases VALUES ('alias2','local','地方公司登记','地方公司登记');
                ",
            )
            .unwrap();
        connection
    }

    fn ambiguous_law_fixture() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
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
                INSERT INTO law_documents VALUES ('audit-law','审查法','law','npc','CN','national_law','in_force','2024-01-01','审查合成法');
                INSERT INTO law_documents VALUES ('other-law','其他法','law','npc','CN','national_law','in_force','2024-01-01','其他合成法');
                INSERT INTO law_versions VALUES ('audit-now-1','audit-law','现行版','in_force','2024-01-01',NULL,'2024-01-01','ambiguity-fixture');
                INSERT INTO law_versions VALUES ('other-now-1','other-law','现行版','in_force','2024-01-01',NULL,'2024-01-01','ambiguity-fixture');
                INSERT INTO law_articles VALUES ('audit-a1','audit-law','audit-now-1','第一条',1,NULL,'审查法第一条正文。');
                INSERT INTO law_articles VALUES ('other-a1','other-law','other-now-1','第一条',1,NULL,'其他法第一条正文。');
                INSERT INTO law_aliases VALUES ('audit-alias','audit-law','歧义合成法','歧义合成法');
                INSERT INTO law_aliases VALUES ('other-alias','other-law','歧义合成法','歧义合成法');
                ",
            )
            .unwrap();
        connection
    }

    fn request(view: SearchView) -> PagedSearchRequest {
        PagedSearchRequest {
            query: "公司".to_owned(),
            match_mode: SearchMatchMode::All,
            version_scope: VersionScope::Current,
            view,
            document_id: None,
            case_date: None,
            limit: 1,
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
    fn grouped_search_counts_and_pages_without_truncating_documents() {
        let connection = fixture();
        let first = search_page(&connection, None, request(SearchView::Grouped)).unwrap();
        assert_eq!(first.total, 2);
        assert_eq!(first.total_laws, 2);
        assert_eq!(first.total_articles, 3);
        assert_eq!(first.laws.len(), 1);
        assert_eq!(first.laws[0].law.document_id, "national");
        let mut second_request = request(SearchView::Grouped);
        second_request.offset = 1;
        let second = search_page(&connection, None, second_request).unwrap();
        assert_eq!(second.laws[0].law.document_id, "local");
    }

    #[test]
    fn flat_search_returns_exact_total_and_filter() {
        let connection = fixture();
        let mut request = request(SearchView::Flat);
        request.effectiveness_level = Some("national_law".to_owned());
        let response = search_page(&connection, None, request).unwrap();
        assert_eq!(response.total, 2);
        assert_eq!(response.total_laws, 1);
        assert_eq!(response.total_articles, 2);
        assert_eq!(response.articles.len(), 1);
        assert_eq!(response.articles[0].document_id, "national");
    }

    #[test]
    fn published_date_sort_reads_version_publication_date() {
        let connection = fixture();
        let mut request = request(SearchView::Grouped);
        request.sort = SearchSort::PublishedDate;
        let response = search_page(&connection, None, request).unwrap();
        assert_eq!(response.laws[0].law.document_id, "local");
    }

    #[test]
    fn alias_match_returns_the_law_articles_in_both_views() {
        let connection = fixture();
        let request = PagedSearchRequest {
            query: "地方公司登记".to_owned(),
            match_mode: SearchMatchMode::All,
            version_scope: VersionScope::Current,
            view: SearchView::Grouped,
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
        };
        let grouped = search_page(&connection, None, request.clone()).unwrap();
        assert_eq!(grouped.total, 1);
        assert_eq!(grouped.total_laws, 1);
        assert_eq!(grouped.total_articles, 1);
        assert_eq!(grouped.laws[0].top_articles.len(), 1);

        let flat = search_page(
            &connection,
            None,
            PagedSearchRequest {
                view: SearchView::Flat,
                ..request
            },
        )
        .unwrap();
        assert_eq!(flat.total, 1);
        assert_eq!(flat.total_laws, 1);
        assert_eq!(flat.total_articles, 1);
    }

    #[test]
    fn malformed_optional_index_falls_back_instead_of_failing_search() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legal_search_index.sqlite");
        std::fs::write(&path, b"not a sqlite database").unwrap();
        assert!(SearchIndex::open_if_current(&path, None).unwrap().is_none());
    }

    #[test]
    fn version_articles_have_complete_content_and_pagination() {
        let connection = fixture();
        let response = version_articles(
            &connection,
            VersionArticlesRequest {
                version_id: "national-v1".to_owned(),
                limit: 1,
                offset: 1,
            },
        )
        .unwrap();
        assert_eq!(response.total, 2);
        assert_eq!(response.articles[0].content, "合同与公司治理。");
    }

    #[test]
    fn versioned_cache_projects_complete_flat_matches_across_pages() {
        let connection = fixture();
        connection
            .execute_batch(
                "
                CREATE TABLE database_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO database_metadata VALUES
                  ('schema_version', '4'),
                  ('runtime_schema_version', '1'),
                  ('dataset_version', 'cache-fixture'),
                  ('source_manifest_sha256', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
                ",
            )
            .unwrap();
        let mut first_request = request(SearchView::Flat);
        first_request.limit = 1;
        first_request.offset = 0;
        let first = search_page(&connection, None, first_request.clone()).unwrap();
        let mut second_request = first_request.clone();
        second_request.offset = 1;
        let second = search_page(&connection, None, second_request).unwrap();
        assert_eq!(first.total, 3);
        assert_eq!(first.total_laws, 2);
        assert_eq!(first.total_articles, 3);
        assert_eq!(first.articles.len(), 1);
        assert_eq!(second.articles.len(), 1);
        assert_ne!(first.articles[0].article_id, second.articles[0].article_id);

        // A repeated page is served from the same complete result set and
        // retains the stable order used by the initial request.
        let repeated = search_page(&connection, None, first_request).unwrap();
        assert_eq!(repeated.articles, first.articles);

        let mut grouped_request = request(SearchView::Grouped);
        grouped_request.limit = 1;
        grouped_request.offset = 0;
        let grouped_first = search_page(&connection, None, grouped_request.clone()).unwrap();
        assert_eq!(grouped_first.total, 2);
        assert_eq!(grouped_first.total_articles, 3);
        assert_eq!(grouped_first.laws[0].matched_article_count, 2);
        let mut grouped_second_request = grouped_request;
        grouped_second_request.offset = 1;
        let grouped_second = search_page(&connection, None, grouped_second_request).unwrap();
        assert_eq!(grouped_second.laws[0].law.document_id, "local");
        assert_eq!(grouped_second.laws[0].matched_article_count, 1);
    }

    #[test]
    fn cache_identity_change_discards_a_previous_complete_result() {
        let connection = fixture();
        connection
            .execute_batch(
                "
                CREATE TABLE database_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO database_metadata VALUES
                  ('schema_version', '4'),
                  ('runtime_schema_version', '1'),
                  ('dataset_version', 'cache-invalidation-a'),
                  ('source_manifest_sha256', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
                ",
            )
            .unwrap();
        let mut request = request(SearchView::Flat);
        request.query = "地方公司登记".to_owned();
        request.limit = 10;
        let initial = search_page(&connection, None, request.clone()).unwrap();
        assert_eq!(initial.total, 1);

        connection
            .execute_batch(
                "
                UPDATE law_aliases SET alias = '地方登记', normalized_alias = '地方登记' WHERE id = 'alias2';
                UPDATE database_metadata SET value = 'cache-invalidation-b' WHERE key = 'dataset_version';
                UPDATE database_metadata SET value = 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' WHERE key = 'source_manifest_sha256';
                ",
            )
            .unwrap();
        let changed = search_page(&connection, None, request).unwrap();
        assert_eq!(changed.total, 0);
        assert!(changed.articles.is_empty());
    }

    #[test]
    fn all_any_phrase_and_exact_article_use_one_flat_plan() {
        let connection = fixture();
        let mut all = request(SearchView::Flat);
        all.query = "合同 公司".to_owned();
        all.limit = 20;
        let all_response = search_page(&connection, None, all.clone()).unwrap();
        assert_eq!(all_response.total, 1);
        assert_eq!(all_response.articles[0].article_id, "national-a2");

        let mut any = all.clone();
        any.match_mode = SearchMatchMode::Any;
        let any_response = search_page(&connection, None, any).unwrap();
        assert_eq!(any_response.total, 3);

        let mut phrase = all;
        phrase.query = "合同与公司".to_owned();
        phrase.match_mode = SearchMatchMode::Phrase;
        let phrase_response = search_page(&connection, None, phrase).unwrap();
        assert_eq!(phrase_response.total, 1);

        connection
            .execute(
                "INSERT INTO law_articles VALUES ('national-a2-sub','national','national-v1','第二条之一',3,NULL,'派生条文。')",
                [],
            )
            .unwrap();

        let mut exact = request(SearchView::Flat);
        exact.query = "《中华人民共和国公司法》第２条".to_owned();
        exact.limit = 20;
        let exact_response = search_page(&connection, None, exact).unwrap();
        assert_eq!(exact_response.total, 1);
        assert_eq!(exact_response.articles[0].article_id, "national-a2");
        assert_eq!(
            exact_response.applied_query.exact_article_number.as_deref(),
            Some("第二条")
        );

        connection
            .execute(
                "INSERT INTO law_articles VALUES ('national-a120-sub','national','national-v1','第一百二十条之一',1201,NULL,'增设条款。')",
                [],
            )
            .unwrap();
        let mut addition = request(SearchView::Flat);
        addition.query = "公司法第120条之一".to_owned();
        addition.limit = 20;
        let addition_response = search_page(&connection, None, addition).unwrap();
        assert_eq!(addition_response.total, 1);
        assert_eq!(
            addition_response.articles[0].article_id,
            "national-a120-sub"
        );
        assert_eq!(
            addition_response
                .applied_query
                .exact_article_number
                .as_deref(),
            Some("第一百二十条之一")
        );

        let mut malformed = request(SearchView::Flat);
        malformed.query = "公司法第十十条".to_owned();
        malformed.limit = 20;
        assert_eq!(search_page(&connection, None, malformed).unwrap().total, 0);
    }

    #[test]
    fn version_scope_rejects_mixed_date_and_hides_unknown_current_versions() {
        let connection = fixture();
        let mut invalid = request(SearchView::Flat);
        invalid.case_date = Some("2024-08-01".to_owned());
        assert!(matches!(
            search_page(&connection, None, invalid),
            Err(RetrievalError::InvalidRequest(_))
        ));

        let mut as_of = request(SearchView::Flat);
        as_of.version_scope = VersionScope::AsOf;
        as_of.case_date = Some("2024-08-01".to_owned());
        assert_eq!(search_page(&connection, None, as_of).unwrap().total, 3);

        connection
            .execute(
                "UPDATE law_versions SET status = 'not_yet_effective' WHERE id = 'national-v1'",
                [],
            )
            .unwrap();
        assert_eq!(
            search_page(&connection, None, request(SearchView::Flat))
                .unwrap()
                .total,
            1
        );

        connection
            .execute(
                "UPDATE law_versions SET status = 'in_force', effective_from = '' WHERE id = 'national-v1'",
                [],
            )
            .unwrap();
        assert_eq!(
            search_page(&connection, None, request(SearchView::Flat))
                .unwrap()
                .total,
            1
        );
    }

    #[test]
    fn cancellation_before_admission_never_starts_search() {
        let connection = fixture();
        let cancellation = SearchCancellation::new();
        cancellation.cancel();
        assert!(matches!(
            search_page_cancellable(&connection, None, request(SearchView::Flat), &cancellation),
            Err(RetrievalError::Cancelled)
        ));
    }

    #[test]
    fn explicit_document_id_resolves_only_a_matching_ambiguous_law_candidate() {
        let connection = ambiguous_law_fixture();
        let mut request = request(SearchView::Flat);
        request.query = "歧义合成法第一条".to_owned();
        request.limit = 20;

        let ambiguous = search_page(&connection, None, request.clone()).unwrap();
        assert_eq!(ambiguous.total, 0);
        assert!(ambiguous.articles.is_empty());
        assert_eq!(ambiguous.ambiguities.len(), 1);
        assert_eq!(ambiguous.ambiguities[0].candidates.len(), 2);

        request.document_id = Some("audit-law".to_owned());
        let selected = search_page(&connection, None, request.clone()).unwrap();
        assert_eq!(selected.total, 1);
        assert_eq!(selected.articles[0].article_id, "audit-a1");
        assert_eq!(
            selected.applied_query.resolved_document_id.as_deref(),
            Some("audit-law")
        );
        assert_eq!(
            selected.applied_query.exact_article_number.as_deref(),
            Some("第一条")
        );

        request.document_id = Some("unrelated-law".to_owned());
        assert!(matches!(
            search_page(&connection, None, request),
            Err(RetrievalError::InvalidRequest(message))
                if message.contains("not a candidate")
        ));
    }

    #[test]
    fn article_ordinal_normalizes_chinese_arabic_and_fullwidth_forms() {
        assert_eq!(chinese_number(465), "四百六十五");
        assert_eq!(chinese_number(577), "五百七十七");
        assert_eq!(
            split_law_article_query(&canonical_query("民法典第４６５条")),
            Some((
                "民法典".to_owned(),
                "第四百六十五条".to_owned(),
                "第465条".to_owned(),
            ))
        );
        assert_eq!(
            split_law_article_query("民法典第五百七十七条"),
            Some((
                "民法典".to_owned(),
                "第五百七十七条".to_owned(),
                "第577条".to_owned(),
            ))
        );
        assert_eq!(
            split_law_article_query("民法典第120条之一"),
            Some((
                "民法典".to_owned(),
                "第一百二十条之一".to_owned(),
                "第120条之1".to_owned(),
            ))
        );
        assert!(parse_article_ordinal("十十").is_none());
    }

    #[test]
    fn latin_queries_keep_unicode_case_and_diacritic_folded_semantics() {
        let connection = fixture();
        connection
            .execute(
                "INSERT INTO law_articles VALUES ('national-cafe','national','national-v1','第三条',3,NULL,'Café agreement duties.')",
                [],
            )
            .unwrap();
        let mut all = request(SearchView::Flat);
        all.query = "cafe".to_owned();
        all.limit = 20;
        let all = search_page(&connection, None, all).unwrap();
        assert_eq!(all.total_articles, 1);
        assert_eq!(all.articles[0].article_id, "national-cafe");

        let mut phrase = request(SearchView::Flat);
        phrase.query = "CAFE agreement".to_owned();
        phrase.match_mode = SearchMatchMode::Phrase;
        phrase.limit = 20;
        let phrase = search_page(&connection, None, phrase).unwrap();
        assert_eq!(phrase.total_articles, 1);
        assert_eq!(phrase.articles[0].article_id, "national-cafe");
    }

    #[test]
    fn grouped_and_flat_share_the_candidate_constrained_article_set() {
        let connection = fixture();
        let selected_rowid: i64 = connection
            .query_row(
                "SELECT rowid FROM law_articles WHERE id = 'national-a2'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let candidates = [selected_rowid];
        let mut grouped_request = request(SearchView::Grouped);
        grouped_request.limit = 20;
        let grouped =
            search_grouped_with_candidates(&connection, &grouped_request, Some(&candidates), None)
                .unwrap();
        let flat = search_flat_with_candidates_page(
            &connection,
            &PagedSearchRequest {
                view: SearchView::Flat,
                ..grouped_request
            },
            Some(&candidates),
            None,
        )
        .unwrap();
        assert_eq!((grouped.total_laws, grouped.total_articles), (1, 1));
        assert_eq!((flat.total_laws, flat.total_articles), (1, 1));
        assert_eq!(grouped.laws[0].law.document_id, "national");
        assert_eq!(grouped.laws[0].matched_article_count, 1);

        let mut summary_only = request(SearchView::Flat);
        summary_only.query = "组织法律规范".to_owned();
        summary_only.limit = 20;
        let flat_summary = search_page(&connection, None, summary_only.clone()).unwrap();
        let grouped_summary = search_page(
            &connection,
            None,
            PagedSearchRequest {
                view: SearchView::Grouped,
                ..summary_only
            },
        )
        .unwrap();
        assert_eq!(
            (flat_summary.total_articles, grouped_summary.total_articles),
            (0, 0)
        );
        assert_eq!(
            (flat_summary.total_laws, grouped_summary.total_laws),
            (0, 0)
        );
    }

    #[test]
    fn current_and_as_of_select_one_latest_eligible_version_per_document() {
        let connection = fixture();
        connection
            .execute_batch(
                "
                INSERT INTO law_versions VALUES ('national-v2','national','修订版','in_force','2025-01-01',NULL,'2024-12-01','fixture');
                INSERT INTO law_articles VALUES ('national-v2-a1','national','national-v2','第一条',1,NULL,'修订版本条文。');
                "
            )
            .unwrap();
        let mut current = request(SearchView::Flat);
        current.document_id = Some("national".to_owned());
        current.limit = 20;
        let current = search_page(&connection, None, current).unwrap();
        assert_eq!(current.total_articles, 1);
        assert_eq!(current.articles[0].version_id, "national-v2");

        let mut as_of = request(SearchView::Flat);
        as_of.version_scope = VersionScope::AsOf;
        as_of.case_date = Some("2024-08-01".to_owned());
        as_of.document_id = Some("national".to_owned());
        as_of.limit = 20;
        let as_of = search_page(&connection, None, as_of).unwrap();
        assert_eq!(as_of.total_articles, 2);
        assert!(as_of
            .articles
            .iter()
            .all(|article| article.version_id == "national-v1"));

        let mut all = request(SearchView::Flat);
        all.version_scope = VersionScope::All;
        all.document_id = Some("national".to_owned());
        all.limit = 20;
        let all = search_page(&connection, None, all).unwrap();
        assert_eq!(all.total_articles, 3);
        assert!(all
            .articles
            .iter()
            .any(|article| article.version_id == "national-v1"));
        assert!(all
            .articles
            .iter()
            .any(|article| article.version_id == "national-v2"));
    }
}
