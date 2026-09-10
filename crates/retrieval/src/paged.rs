//! Complete, paged legal search.
//!
//! The original retrieval functions are deliberately kept as the v1/MCP
//! compatibility surface.  This module is the Web/service surface for a
//! search that has an exact count and applies pagination after the complete
//! match set has been ranked.  A generated two-character index can narrow
//! Chinese substring probes, but every candidate is checked again against the
//! authoritative text in `legal_core.sqlite`.

use super::*;
use rusqlite::{params_from_iter, types::Value, Connection, OpenFlags, OptionalExtension};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::Path,
    sync::{Mutex, OnceLock},
};

pub const DEFAULT_PAGE_LIMIT: u32 = 20;
pub const MAX_PAGE_LIMIT: u32 = 100;
pub const MAX_PAGE_OFFSET: u32 = 1_000_000;
pub const SEARCH_INDEX_FILE_NAME: &str = "legal_search_index.sqlite";
// SQLite builds in the wild still commonly use the 999-variable limit.  An
// index hit set larger than this is deliberately sent through the complete
// literal SQL path instead of expanding an unbounded IN list.  This is a
// performance fallback, never a result cap.
const MAX_INDEX_BOUND_CANDIDATES: usize = 900;
// A complete result set is cached only when it is small enough to retain its
// full payload safely.  Larger searches continue to use the exact paged SQL
// path; they are never truncated just to make them cacheable.
const MAX_CACHED_LAWS: u64 = 50_000;
const MAX_CACHED_ARTICLES: u64 = 100_000;
const MAX_SEARCH_CACHE_ENTRIES: usize = 8;

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
    pub view: SearchView,
    pub document_id: Option<String>,
    pub case_date: Option<String>,
    pub limit: u32,
    pub offset: u32,
    pub document_type: Option<String>,
    pub effectiveness_level: Option<String>,
    pub jurisdiction: Option<String>,
    pub status: Option<String>,
    pub sort: SearchSort,
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

    /// Return a bounded candidate set that may contain one of `terms`.
    ///
    /// The bound is only a probe: once the index proves that a term has more
    /// than `MAX_INDEX_BOUND_CANDIDATES` candidates, `indexed_candidates`
    /// returns `None` and the authoritative query scans all source rows.  It
    /// therefore cannot truncate a legal result set.  Keeping the probe
    /// bounded avoids reading millions of rowids merely to decide to fall
    /// back for common terms.
    fn article_rowids_for_terms(
        &self,
        terms: &[String],
    ) -> Result<Option<Vec<i64>>, RetrievalError> {
        let mut bigrams = HashSet::new();
        for term in terms {
            let chars = term.chars().collect::<Vec<_>>();
            if chars.len() < 2 || !chars.iter().copied().all(is_cjk_ideograph) {
                return Ok(None);
            }
            for pair in chars.windows(2) {
                bigrams.insert(pair.iter().collect::<String>());
            }
        }
        if bigrams.is_empty() {
            return Ok(None);
        }
        let placeholders = (0..bigrams.len())
            .map(|index| format!("?{}", index + 1))
            .collect::<Vec<_>>()
            .join(", ");
        let values = bigrams.into_iter().map(Value::Text).collect::<Vec<_>>();
        let mut statement = self.connection.prepare(&format!(
            "SELECT DISTINCT article_rowid FROM article_bigrams WHERE bigram IN ({placeholders}) LIMIT {}",
            MAX_INDEX_BOUND_CANDIDATES + 1
        ))?;
        let rows = statement
            .query_map(params_from_iter(values.iter()), |row| row.get::<_, i64>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(rows))
    }
}

#[derive(Clone, Debug)]
struct CompleteSearchResult {
    view: SearchView,
    laws: Vec<LawSearchGroup>,
    articles: Vec<ArticleSearchResult>,
    total_laws: u64,
    total_articles: u64,
    warnings: Vec<String>,
}

impl CompleteSearchResult {
    fn project(&self, request: &PagedSearchRequest) -> PagedSearchResponse {
        let start = usize::try_from(request.offset).unwrap_or(usize::MAX);
        let limit = usize::try_from(request.limit).unwrap_or(usize::MAX);
        let end = start.saturating_add(limit);

        match self.view {
            SearchView::Grouped => PagedSearchResponse {
                view: SearchView::Grouped,
                laws: project_page(&self.laws, start, end),
                articles: Vec::new(),
                total: self.total_laws,
                total_laws: self.total_laws,
                total_articles: self.total_articles,
                limit: request.limit,
                offset: request.offset,
                warnings: self.warnings.clone(),
            },
            SearchView::Flat => PagedSearchResponse {
                view: SearchView::Flat,
                laws: Vec::new(),
                articles: project_page(&self.articles, start, end),
                total: self.total_articles,
                total_laws: self.total_laws,
                total_articles: self.total_articles,
                limit: request.limit,
                offset: request.offset,
                warnings: self.warnings.clone(),
            },
        }
    }
}

fn project_page<T: Clone>(items: &[T], start: usize, end: usize) -> Vec<T> {
    if start >= items.len() {
        Vec::new()
    } else {
        items[start..items.len().min(end)].to_vec()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SearchCacheKey {
    identity: String,
    query: String,
    view: SearchView,
    document_id: Option<String>,
    case_date: Option<String>,
    document_type: Option<String>,
    effectiveness_level: Option<String>,
    jurisdiction: Option<String>,
    status: Option<String>,
    sort: SearchSort,
}

impl SearchCacheKey {
    fn new(identity: String, request: &PagedSearchRequest) -> Self {
        Self {
            identity,
            query: request.query.clone(),
            view: request.view,
            document_id: request.document_id.clone(),
            case_date: request.case_date.clone(),
            document_type: request.document_type.clone(),
            effectiveness_level: request.effectiveness_level.clone(),
            jurisdiction: request.jurisdiction.clone(),
            status: request.status.clone(),
            sort: request.sort,
        }
    }
}

struct SearchCacheState {
    identity: Option<String>,
    entries: VecDeque<(SearchCacheKey, CompleteSearchResult)>,
}

static SEARCH_CACHE: OnceLock<Mutex<SearchCacheState>> = OnceLock::new();

fn search_cache() -> &'static Mutex<SearchCacheState> {
    SEARCH_CACHE.get_or_init(|| {
        Mutex::new(SearchCacheState {
            identity: None,
            entries: VecDeque::new(),
        })
    })
}

fn search_cache_get(key: &SearchCacheKey) -> Option<CompleteSearchResult> {
    let mut cache = search_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cache.identity.as_ref() != Some(&key.identity) {
        cache.identity = Some(key.identity.clone());
        cache.entries.clear();
        return None;
    }
    let position = cache
        .entries
        .iter()
        .position(|(entry_key, _)| entry_key == key)?;
    let (entry_key, result) = cache.entries.remove(position)?;
    let cloned = result.clone();
    cache.entries.push_front((entry_key, result));
    Some(cloned)
}

fn search_cache_insert(key: SearchCacheKey, result: CompleteSearchResult) {
    let mut cache = search_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if cache.identity.as_ref() != Some(&key.identity) {
        cache.identity = Some(key.identity.clone());
        cache.entries.clear();
    }
    if let Some(position) = cache
        .entries
        .iter()
        .position(|(entry_key, _)| entry_key == &key)
    {
        cache.entries.remove(position);
    }
    cache.entries.push_front((key, result));
    while cache.entries.len() > MAX_SEARCH_CACHE_ENTRIES {
        cache.entries.pop_back();
    }
}

fn search_cache_identity(
    connection: &Connection,
    index: Option<&SearchIndex>,
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
    // Grouped current-version selection is evaluated against SQLite's local
    // date.  Include that as-of value so a long-lived service cannot reuse a
    // result across a date boundary when a version becomes effective.
    let as_of: String =
        connection.query_row("SELECT date('now', 'localtime')", [], |row| row.get(0))?;
    let index_identity = index
        .map(SearchIndex::cache_identity)
        .unwrap_or_else(|| "index:none".to_owned());
    Ok(Some(format!(
        "db:{database_identity}|as_of:{as_of}|{index_identity}"
    )))
}

pub fn search_page(
    connection: &Connection,
    index: Option<&SearchIndex>,
    request: PagedSearchRequest,
) -> Result<PagedSearchResponse, RetrievalError> {
    validate_page(&request)?;

    // The public service opens a fresh read-only connection for each call.
    // Cache only the materialized, complete match set so page 2+ does not
    // repeat a multi-second source scan.  A cache identity is required: test
    // fixtures and unversioned databases deliberately take the ordinary SQL
    // path instead of risking cross-database reuse.
    if let Some(identity) = search_cache_identity(connection, index)? {
        let key = SearchCacheKey::new(identity, &request);
        if let Some(complete) = search_cache_get(&key) {
            return Ok(complete.project(&request));
        }

        let candidate_rowids = indexed_candidates(index, &request)?;
        let (total_laws, total_articles) =
            complete_match_counts(connection, candidate_rowids.as_deref(), &request)?;
        if total_laws <= MAX_CACHED_LAWS && total_articles <= MAX_CACHED_ARTICLES {
            let complete = load_complete_result(
                connection,
                &request,
                candidate_rowids.as_deref(),
                total_laws,
                total_articles,
            )?;
            search_cache_insert(key, complete.clone());
            return Ok(complete.project(&request));
        }

        // Broad queries stay exact and page directly from SQLite.  The
        // preflight count above is the only extra work; no row cap is used.
        return match request.view {
            SearchView::Grouped => {
                search_grouped_with_candidates(connection, &request, candidate_rowids.as_deref())
            }
            SearchView::Flat => {
                search_flat_with_candidates_page(connection, &request, candidate_rowids.as_deref())
            }
        };
    }

    match request.view {
        SearchView::Grouped => search_grouped(connection, index, &request),
        SearchView::Flat => search_flat(connection, index, &request),
    }
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

fn search_grouped(
    connection: &Connection,
    index: Option<&SearchIndex>,
    request: &PagedSearchRequest,
) -> Result<PagedSearchResponse, RetrievalError> {
    let candidate_rowids = indexed_candidates(index, request)?;
    search_grouped_with_candidates(connection, request, candidate_rowids.as_deref())
}

fn search_grouped_with_candidates(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
) -> Result<PagedSearchResponse, RetrievalError> {
    let mut builder = SqlBuilder::new();
    let cte = document_cte(&mut builder, request, true);
    let count_sql = format!("{cte} SELECT COUNT(*) FROM document_matches");
    let total: i64 =
        connection.query_row(&count_sql, params_from_iter(builder.values.iter()), |row| {
            row.get(0)
        })?;
    let (total_articles, _) = count_article_matches(connection, candidate_rowids, request)?;

    let mut page_builder = SqlBuilder::new();
    let page_cte = document_cte(&mut page_builder, request, true);
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

    let mut groups = Vec::with_capacity(rows.len());
    for law in rows {
        let count =
            count_articles_for_document(connection, candidate_rowids, request, &law.document_id)?;
        let mut article_request = request.clone();
        article_request.view = SearchView::Flat;
        article_request.document_id = Some(law.document_id.clone());
        article_request.limit = 3;
        article_request.offset = 0;
        let previews =
            search_flat_with_candidates(connection, &article_request, candidate_rowids)?.articles;
        groups.push(LawSearchGroup {
            law,
            matched_article_count: count,
            top_articles: previews,
        });
    }
    let mut warnings = Vec::new();
    if total == 0 {
        warnings.push("no_local_results_found".to_owned());
    }
    Ok(PagedSearchResponse {
        view: SearchView::Grouped,
        laws: groups,
        articles: Vec::new(),
        total: u64::try_from(total).unwrap_or(u64::MAX),
        total_laws: u64::try_from(total).unwrap_or(u64::MAX),
        total_articles,
        limit: request.limit,
        offset: request.offset,
        warnings,
    })
}

fn search_flat(
    connection: &Connection,
    index: Option<&SearchIndex>,
    request: &PagedSearchRequest,
) -> Result<PagedSearchResponse, RetrievalError> {
    let candidate_rowids = indexed_candidates(index, request)?;
    search_flat_with_candidates_page(connection, request, candidate_rowids.as_deref())
}

fn search_flat_with_candidates_page(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
) -> Result<PagedSearchResponse, RetrievalError> {
    let (total_articles, total_laws) =
        count_article_matches(connection, candidate_rowids, request)?;

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
    let terms = query_terms(&request.query);
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
    })
}

fn complete_match_counts(
    connection: &Connection,
    candidate_rowids: Option<&[i64]>,
    request: &PagedSearchRequest,
) -> Result<(u64, u64), RetrievalError> {
    let mut article_count_builder = SqlBuilder::new();
    let article_source = article_source_table(&mut article_count_builder);
    let (article_filters, _) = article_filters(&mut article_count_builder, request);
    let article_predicate = article_match_predicate(&mut article_count_builder, request);
    let candidate_filter = candidate_predicate(&mut article_count_builder, candidate_rowids);
    let article_count_sql = format!(
        "SELECT COUNT(*), COUNT(DISTINCT articles.document_id)
         FROM {article_source} articles
         JOIN law_documents documents ON documents.id = articles.document_id
         JOIN law_versions versions ON versions.id = articles.version_id
         WHERE {article_filters} AND ({article_predicate}) {candidate_filter}"
    );
    let (total_articles, article_laws): (i64, i64) = connection.query_row(
        &article_count_sql,
        params_from_iter(article_count_builder.values.iter()),
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let total_laws = match request.view {
        // Flat results are defined by matching article rows; grouped results
        // include metadata-only document matches as well.
        SearchView::Flat => article_laws,
        SearchView::Grouped => {
            let mut document_builder = SqlBuilder::new();
            let document_cte_sql = document_cte(&mut document_builder, request, true);
            let document_count_sql =
                format!("{document_cte_sql} SELECT COUNT(*) FROM document_matches");
            connection.query_row(
                &document_count_sql,
                params_from_iter(document_builder.values.iter()),
                |row| row.get::<_, i64>(0),
            )?
        }
    };
    Ok((
        u64::try_from(total_laws).unwrap_or(u64::MAX),
        u64::try_from(total_articles).unwrap_or(u64::MAX),
    ))
}

fn load_complete_result(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
    total_laws: u64,
    total_articles: u64,
) -> Result<CompleteSearchResult, RetrievalError> {
    let (laws, articles, warnings) = match request.view {
        SearchView::Flat => {
            let mut article_request = request.clone();
            article_request.view = SearchView::Flat;
            let articles = load_all_articles(connection, &article_request, candidate_rowids)?;
            debug_assert_eq!(articles.len() as u64, total_articles);
            let warnings = if articles.is_empty() {
                vec!["no_local_results_found".to_owned()]
            } else {
                Vec::new()
            };
            (Vec::new(), articles, warnings)
        }
        SearchView::Grouped => {
            // Grouped results need only three previews and a count per
            // document.  A windowed source query avoids the previous N+1
            // document queries and avoids materializing every matching body.
            let documents = load_all_documents(connection, request)?;
            debug_assert_eq!(documents.len() as u64, total_laws);
            let mut article_groups =
                load_grouped_article_previews(connection, request, candidate_rowids)?;
            let groups = documents
                .into_iter()
                .map(|law| {
                    let (matched_article_count, top_articles) = article_groups
                        .remove(&law.document_id)
                        .unwrap_or((0, Vec::new()));
                    LawSearchGroup {
                        law,
                        matched_article_count,
                        top_articles,
                    }
                })
                .collect::<Vec<_>>();
            let warnings = if groups.is_empty() {
                vec!["no_local_results_found".to_owned()]
            } else {
                Vec::new()
            };
            (groups, Vec::new(), warnings)
        }
    };
    Ok(CompleteSearchResult {
        view: request.view,
        laws,
        articles,
        total_laws,
        total_articles,
        warnings,
    })
}

fn load_all_documents(
    connection: &Connection,
    request: &PagedSearchRequest,
) -> Result<Vec<LawSearchResult>, RetrievalError> {
    let mut builder = SqlBuilder::new();
    let cte = document_cte(&mut builder, request, true);
    let order = document_order(request.sort);
    let sql = format!(
        "{cte} SELECT document_id, title, document_type, authority_name,
                effectiveness_level, status, current_version_id, current_effective_from,
                current_effective_to, lexical_score, matched_alias, summary
         FROM document_matches ORDER BY {order}, document_id ASC"
    );
    let rows = connection
        .prepare(&sql)?
        .query_map(params_from_iter(builder.values.iter()), |row| {
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
    Ok(rows)
}

fn load_all_articles(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
) -> Result<Vec<ArticleSearchResult>, RetrievalError> {
    let mut builder = SqlBuilder::new();
    let sql = article_page_sql(&mut builder, request, candidate_rowids, None);
    let terms = query_terms(&request.query);
    let rows = connection
        .prepare(&sql)?
        .query_map(params_from_iter(builder.values.iter()), |row| {
            article_from_paged_row(row, &terms)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn load_grouped_article_previews(
    connection: &Connection,
    request: &PagedSearchRequest,
    candidate_rowids: Option<&[i64]>,
) -> Result<HashMap<String, (u64, Vec<ArticleSearchResult>)>, RetrievalError> {
    let mut builder = SqlBuilder::new();
    let article_source = article_source_table(&mut builder);
    // The document score is constant for all articles of one document.  The
    // grouped preview therefore needs only the article score plus the
    // per-version fields that can vary within a document.
    let article_score = article_score_expression(&mut builder, request);
    let (filters, _) = article_filters(&mut builder, request);
    let predicate = article_match_predicate(&mut builder, request);
    let candidate_filter = candidate_predicate(&mut builder, candidate_rowids);
    let order = grouped_article_order(request.sort);
    let sql = format!(
        "WITH scored AS (
           SELECT articles.id, articles.document_id, articles.version_id,
                  documents.title AS document_title, articles.article_number,
                  articles.title AS article_title, articles.content,
                  citation_metadata.citation_id, versions.effective_from,
                  versions.effective_to, versions.status, articles.article_order,
                  documents.effectiveness_level, versions.published_on,
                  ({article_score}) AS total_score
           FROM {article_source} articles
           JOIN law_documents documents ON documents.id = articles.document_id
           JOIN law_versions versions ON versions.id = articles.version_id
           LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
           WHERE {filters} AND ({predicate}) {candidate_filter}
         ), ranked AS (
           SELECT scored.*,
                  COUNT(*) OVER (PARTITION BY document_id) AS matched_count,
                  ROW_NUMBER() OVER (
                    PARTITION BY document_id ORDER BY {order}
                  ) AS preview_rank
           FROM scored
         )
         SELECT id, document_id, version_id, document_title, article_number,
                article_title, content, citation_id, effective_from, effective_to,
                status, article_order, effectiveness_level, total_score,
                matched_count
         FROM ranked
         WHERE preview_rank <= 3
         ORDER BY document_id ASC, preview_rank ASC"
    );
    let terms = query_terms(&request.query);
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(builder.values.iter()), |row| {
        let article = article_from_paged_row(row, &terms)?;
        let matched_count: i64 = row.get(14)?;
        Ok((article, u64::try_from(matched_count).unwrap_or(u64::MAX)))
    })?;
    let mut groups: HashMap<String, (u64, Vec<ArticleSearchResult>)> = HashMap::new();
    for row in rows {
        let (article, matched_count) = row?;
        let entry = groups
            .entry(article.document_id.clone())
            .or_insert_with(|| (matched_count, Vec::with_capacity(3)));
        entry.0 = matched_count;
        entry.1.push(article);
    }
    Ok(groups)
}

fn grouped_article_order(sort: SearchSort) -> &'static str {
    match sort {
        SearchSort::Relevance => {
            "total_score DESC, CASE WHEN status = 'in_force' THEN 0 ELSE 1 END, article_order ASC, id ASC"
        }
        SearchSort::Effectiveness => "total_score DESC, article_order ASC, id ASC",
        SearchSort::EffectiveDate => {
            "COALESCE(effective_from, '0001-01-01') DESC, total_score DESC, article_order ASC, id ASC"
        }
        SearchSort::PublishedDate => {
            "COALESCE(published_on, '0001-01-01') DESC, total_score DESC, article_order ASC, id ASC"
        }
        SearchSort::Title => "article_order ASC, total_score DESC, id ASC",
    }
}

fn count_articles_for_document(
    connection: &Connection,
    candidate_rowids: Option<&[i64]>,
    request: &PagedSearchRequest,
    document_id: &str,
) -> Result<u64, RetrievalError> {
    let mut scoped = request.clone();
    scoped.view = SearchView::Flat;
    scoped.document_id = Some(document_id.to_owned());
    let mut builder = SqlBuilder::new();
    let sql = article_count_sql(&mut builder, &scoped, candidate_rowids);
    let count: i64 =
        connection.query_row(&sql, params_from_iter(builder.values.iter()), |row| {
            row.get(0)
        })?;
    Ok(u64::try_from(count).unwrap_or(u64::MAX))
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

fn indexed_candidates(
    index: Option<&SearchIndex>,
    request: &PagedSearchRequest,
) -> Result<Option<Vec<i64>>, RetrievalError> {
    let Some(index) = index else { return Ok(None) };
    let terms = query_terms(&request.query);
    let candidates = index.article_rowids_for_terms(&terms)?;
    if candidates
        .as_ref()
        .is_some_and(|candidates| candidates.len() > MAX_INDEX_BOUND_CANDIDATES)
    {
        // Keeping the full source scan here preserves recall for common
        // Chinese terms while avoiding SQLite's bound-variable ceiling.
        return Ok(None);
    }
    Ok(candidates)
}

fn article_count_sql(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
    candidates: Option<&[i64]>,
) -> String {
    let article_source = article_source_table(builder); // keeps source detection in one place
    let (filters, _) = article_filters(builder, request);
    let predicate = article_match_predicate(builder, request);
    let candidate_filter = candidate_predicate(builder, candidates);
    format!(
        "SELECT COUNT(*) FROM {article_source} articles
         JOIN law_documents documents ON documents.id = articles.document_id
         JOIN law_versions versions ON versions.id = articles.version_id
         WHERE {filters} AND ({predicate}) {candidate_filter}"
    )
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
    require_match: bool,
) -> String {
    // SELECT expressions are written before WHERE, so bind their parameters
    // before the filter and match predicates.
    let score = document_score_expression(builder, request);
    let alias_like = builder.bind_like(request.query.trim());
    let (filters, _) = document_filters(builder, request);
    let match_predicate = document_match_predicate(builder, request);
    let article_match_predicate = article_document_exists_predicate(builder, request);
    let predicate = if require_match {
        format!("(({match_predicate}) OR ({article_match_predicate}))")
    } else {
        "1 = 1".to_owned()
    };
    let current = current_versions_cte();
    format!(
        "{current}, document_matches AS (
          SELECT documents.id AS document_id, documents.title, documents.document_type,
                 authorities.name AS authority_name, documents.effectiveness_level,
                 documents.status, current_versions.id AS current_version_id,
                 current_versions.effective_from AS current_effective_from,
                 current_versions.effective_to AS current_effective_to,
                 {score} AS lexical_score,
                 MAX(CASE WHEN aliases.alias LIKE {alias_like} ESCAPE '\\' THEN aliases.alias ELSE NULL END) AS matched_alias,
                 documents.summary
          FROM law_documents documents
          JOIN issuing_authorities authorities ON authorities.id = documents.authority_id
          LEFT JOIN law_aliases aliases ON aliases.document_id = documents.id
          LEFT JOIN current_versions ON current_versions.document_id = documents.id
          WHERE {filters} AND {predicate}
          GROUP BY documents.id
        )"
    )
}

fn current_versions_cte() -> &'static str {
    "WITH ranked_current_versions AS (
       SELECT versions.*,
              ROW_NUMBER() OVER (PARTITION BY versions.document_id
                                 ORDER BY versions.effective_from DESC, versions.id DESC) AS current_rank
       FROM law_versions versions
       WHERE versions.effective_from <= date('now','localtime')
         AND (versions.effective_to IS NULL OR versions.effective_to >= date('now','localtime'))
         AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)
         AND versions.status <> 'not_yet_effective'
     ), current_versions AS (
       SELECT * FROM ranked_current_versions WHERE current_rank = 1
     )"
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
    if let Some(value) = request.case_date.as_deref() {
        let parameter = builder.bind_text(value);
        clauses.push(format!(
            "EXISTS (SELECT 1 FROM law_versions date_versions WHERE date_versions.document_id = documents.id AND date_versions.effective_from <= {parameter} AND (date_versions.effective_to IS NULL OR date_versions.effective_to >= {parameter}) AND NOT (date_versions.status = 'repealed' AND date_versions.effective_to IS NULL))"
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
    if let Some(value) = request.case_date.as_deref() {
        let parameter = builder.bind_text(value);
        clauses.push(format!(
            "versions.effective_from <= {parameter} AND (versions.effective_to IS NULL OR versions.effective_to >= {parameter}) AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)"
        ));
    }
    if clauses.is_empty() {
        clauses.push("1 = 1".to_owned());
    }
    (clauses.join(" AND "), clauses)
}

fn document_match_predicate(builder: &mut SqlBuilder, request: &PagedSearchRequest) -> String {
    let terms = query_terms(&request.query);
    if terms.is_empty() {
        return "1 = 1".to_owned();
    }
    terms
        .iter()
        .map(|term| {
            let like = builder.bind_like(term);
            format!(
                "documents.title LIKE {like} ESCAPE '\\' OR documents.summary LIKE {like} ESCAPE '\\' OR aliases.alias LIKE {like} ESCAPE '\\' OR aliases.normalized_alias LIKE {like} ESCAPE '\\'"
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn article_match_predicate(builder: &mut SqlBuilder, request: &PagedSearchRequest) -> String {
    article_match_predicate_for_aliases(builder, request, "articles", "documents")
}

fn article_document_exists_predicate(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
) -> String {
    let terms = query_terms(&request.query);
    if terms.is_empty() {
        return "0 = 1".to_owned();
    }
    let predicate =
        article_match_predicate_for_aliases(builder, request, "matched_articles", "documents");
    let date_clause = request.case_date.as_deref().map(|date| {
        let parameter = builder.bind_text(date);
        format!(
            "AND matched_versions.effective_from <= {parameter} AND (matched_versions.effective_to IS NULL OR matched_versions.effective_to >= {parameter}) AND NOT (matched_versions.status = 'repealed' AND matched_versions.effective_to IS NULL)"
        )
    }).unwrap_or_default();
    format!(
        "EXISTS (SELECT 1 FROM law_articles matched_articles JOIN law_versions matched_versions ON matched_versions.id = matched_articles.version_id WHERE matched_articles.document_id = documents.id AND ({predicate}) {date_clause})"
    )
}

fn article_match_predicate_for_aliases(
    builder: &mut SqlBuilder,
    request: &PagedSearchRequest,
    article_alias: &str,
    document_alias: &str,
) -> String {
    let terms = query_terms(&request.query);
    if terms.is_empty() {
        return "1 = 1".to_owned();
    }
    terms
        .iter()
        .map(|term| {
            let like = builder.bind_like(term);
            format!(
                "{document_alias}.title LIKE {like} ESCAPE '\\' OR EXISTS (SELECT 1 FROM law_aliases matched_aliases WHERE matched_aliases.document_id = {document_alias}.id AND (matched_aliases.alias LIKE {like} ESCAPE '\\' OR matched_aliases.normalized_alias LIKE {like} ESCAPE '\\')) OR {article_alias}.article_number LIKE {like} ESCAPE '\\' OR COALESCE({article_alias}.title, '') LIKE {like} ESCAPE '\\' OR {article_alias}.content LIKE {like} ESCAPE '\\'"
            )
        })
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn document_score_expression(builder: &mut SqlBuilder, request: &PagedSearchRequest) -> String {
    let terms = query_terms(&request.query);
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
        // Contract queries should surface the currently applicable Civil Code
        // contract provisions even though the document title itself does not
        // contain “合同”.  The surrounding document predicate requires an
        // actual article-text match, so this is a topic boost rather than a
        // fabricated hit.  Other topics continue to use their aliases and
        // literal article matches.
        if term.contains('合') && term.contains('同') {
            scores.push(
                "CASE WHEN documents.title LIKE '%民法典%' THEN 1300000.0 ELSE 0.0 END".to_owned(),
            );
        }
    }
    // Two or more arguments force SQLite's scalar max() rather than its
    // aggregate form.  The leading zero also makes the one-term case scalar.
    format!("MAX(0.0, {})", scores.join(", "))
}

fn article_score_expression(builder: &mut SqlBuilder, request: &PagedSearchRequest) -> String {
    let terms = query_terms(&request.query);
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
    format!("MAX(0.0, {})", scores.join(", "))
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
    format!("AND articles.rowid IN ({placeholders})")
}

fn article_source_table(_builder: &mut SqlBuilder) -> &'static str {
    // `law_articles` is a compatibility view in runtime-slim databases and a
    // table in archival fixtures.  Both expose a stable rowid and the same
    // columns, so one query works for both layouts.
    "law_articles"
}

fn query_terms(query: &str) -> Vec<String> {
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

    fn request(view: SearchView) -> PagedSearchRequest {
        PagedSearchRequest {
            query: "公司".to_owned(),
            view,
            document_id: None,
            case_date: None,
            limit: 1,
            offset: 0,
            document_type: None,
            effectiveness_level: None,
            jurisdiction: None,
            status: None,
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
            view: SearchView::Grouped,
            document_id: None,
            case_date: None,
            limit: 20,
            offset: 0,
            document_type: None,
            effectiveness_level: None,
            jurisdiction: None,
            status: None,
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
}
