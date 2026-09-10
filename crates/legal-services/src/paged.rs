//! Versioned Web legal-search contracts.
//!
//! These DTOs are additive.  The original `LegalSearchRequest` remains the
//! frozen MCP/v1 operation; Web callers that need exact counts, filters, two
//! result views, or version bodies use the methods in this module.

use crate::{
    open_validated_legal_database_cancellable, require_schema_version, validate_identifier,
    validate_text, LegalServices, ServiceError, SERVICE_SCHEMA_VERSION,
};
use domain::law::{ArticleSearchResult, LawArticleDetail, LawSearchResult};
use retrieval::{
    LawNameAmbiguity, LawSearchGroup, PagedSearchRequest, SearchAppliedQuery, SearchCancellation,
    SearchIndex, SearchMatchMode, SearchMetrics, SearchSort, SearchView, VersionArticlesRequest,
    VersionScope,
};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

const MAX_FILTER_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalSearchView {
    #[default]
    Grouped,
    Flat,
}

impl From<LegalSearchView> for SearchView {
    fn from(value: LegalSearchView) -> Self {
        match value {
            LegalSearchView::Grouped => SearchView::Grouped,
            LegalSearchView::Flat => SearchView::Flat,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalSearchSort {
    #[default]
    Relevance,
    Effectiveness,
    EffectiveDate,
    PublishedDate,
    Title,
}

impl From<LegalSearchSort> for SearchSort {
    fn from(value: LegalSearchSort) -> Self {
        match value {
            LegalSearchSort::Relevance => SearchSort::Relevance,
            LegalSearchSort::Effectiveness => SearchSort::Effectiveness,
            LegalSearchSort::EffectiveDate => SearchSort::EffectiveDate,
            LegalSearchSort::PublishedDate => SearchSort::PublishedDate,
            LegalSearchSort::Title => SearchSort::Title,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalSearchMatchMode {
    #[default]
    All,
    Any,
    Phrase,
}

impl From<LegalSearchMatchMode> for SearchMatchMode {
    fn from(value: LegalSearchMatchMode) -> Self {
        match value {
            LegalSearchMatchMode::All => SearchMatchMode::All,
            LegalSearchMatchMode::Any => SearchMatchMode::Any,
            LegalSearchMatchMode::Phrase => SearchMatchMode::Phrase,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalVersionScope {
    #[default]
    Current,
    AsOf,
    All,
}

impl From<LegalVersionScope> for VersionScope {
    fn from(value: LegalVersionScope) -> Self {
        match value {
            LegalVersionScope::Current => VersionScope::Current,
            LegalVersionScope::AsOf => VersionScope::AsOf,
            LegalVersionScope::All => VersionScope::All,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalPagedSearchRequest {
    pub schema_version: u16,
    pub query: String,
    #[serde(default)]
    pub match_mode: LegalSearchMatchMode,
    /// None retains historic `caseDate` behavior: a supplied date means
    /// `as_of`, an absent date means `current`.  An explicit scope is checked
    /// strictly so new callers cannot accidentally mix the two semantics.
    #[serde(default)]
    pub version_scope: Option<LegalVersionScope>,
    #[serde(default)]
    pub view: LegalSearchView,
    pub document_id: Option<String>,
    pub case_date: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub document_type: Option<String>,
    pub effectiveness_level: Option<String>,
    pub jurisdiction: Option<String>,
    pub status: Option<String>,
    pub version_status: Option<String>,
    #[serde(default)]
    pub sort: LegalSearchSort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAppliedQuery {
    pub normalized_query: String,
    pub match_mode: LegalSearchMatchMode,
    pub version_scope: LegalVersionScope,
    pub as_of: Option<String>,
    pub resolved_document_id: Option<String>,
    pub exact_article_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalLawNameAmbiguity {
    pub query: String,
    pub candidates: Vec<LegalLawNameCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalLawNameCandidate {
    pub document_id: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalSearchMetrics {
    pub candidate_count: u64,
    pub index_fallback: bool,
    pub cache_hit: bool,
    pub count_cache_hit: bool,
    pub cache_retained_bytes: u64,
    pub lock_wait_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalSearchGroup {
    pub law: LawSearchResult,
    pub matched_article_count: u64,
    pub top_articles: Vec<ArticleSearchResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalPagedSearchResponse {
    pub schema_version: u16,
    pub query: String,
    pub view: LegalSearchView,
    pub laws: Vec<LegalSearchGroup>,
    pub articles: Vec<ArticleSearchResult>,
    pub total: u64,
    pub total_laws: u64,
    pub total_articles: u64,
    pub limit: u32,
    pub offset: u32,
    pub database_version: String,
    pub warnings: Vec<String>,
    pub applied_query: LegalAppliedQuery,
    pub ambiguities: Vec<LegalLawNameAmbiguity>,
    pub metrics: LegalSearchMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalVersionArticlesRequest {
    pub schema_version: u16,
    pub version_id: String,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// Additive historical-body request bound to the same current/as-of/all
/// rules as search.  The original version-id paging request is intentionally
/// preserved for MCP compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalVersionArticlesScopedRequest {
    pub schema_version: u16,
    pub version_id: String,
    #[serde(default)]
    pub version_scope: Option<LegalVersionScope>,
    pub case_date: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalVersionArticlesResponse {
    pub schema_version: u16,
    pub version_id: String,
    pub document_id: String,
    pub articles: Vec<LawArticleDetail>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
    pub database_version: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalSearchFacetsResponse {
    pub schema_version: u16,
    pub document_types: Vec<String>,
    pub effectiveness_levels: Vec<String>,
    pub jurisdictions: Vec<String>,
    pub statuses: Vec<String>,
    pub version_statuses: Vec<String>,
    pub database_version: String,
}

impl LegalServices {
    /// Complete, exact-count search for Web/AI callers.  The optional
    /// generated index is only an accelerator; a missing/stale index falls
    /// through to the complete literal SQL scan in `retrieval`.
    pub fn legal_search_page(
        &self,
        request: LegalPagedSearchRequest,
    ) -> Result<LegalPagedSearchResponse, ServiceError> {
        self.legal_search_page_cancellable(request, &SearchCancellation::new())
    }

    /// Same public result contract as `legal_search_page`, with an interrupt
    /// token for admission controllers that have shared subscribers.
    pub fn legal_search_page_cancellable(
        &self,
        request: LegalPagedSearchRequest,
        cancellation: &SearchCancellation,
    ) -> Result<LegalPagedSearchResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_text("query", &request.query, 16 * 1024, false)?;
        if let Some(document_id) = request.document_id.as_deref() {
            validate_identifier("documentId", document_id)?;
        }
        if let Some(case_date) = request.case_date.as_deref() {
            if !domain::date::is_iso_calendar_date(case_date) {
                return Err(ServiceError::invalid(
                    "caseDate",
                    "caseDate must be a valid YYYY-MM-DD calendar date",
                ));
            }
        }
        validate_filter("documentType", request.document_type.as_deref())?;
        validate_filter("effectivenessLevel", request.effectiveness_level.as_deref())?;
        validate_filter("jurisdiction", request.jurisdiction.as_deref())?;
        validate_filter("status", request.status.as_deref())?;
        validate_filter("versionStatus", request.version_status.as_deref())?;
        let version_scope =
            resolve_version_scope(request.version_scope, request.case_date.as_deref())?;
        let limit = request.limit.unwrap_or(retrieval::DEFAULT_PAGE_LIMIT);
        let offset = request.offset.unwrap_or(0);
        if !(1..=retrieval::MAX_PAGE_LIMIT).contains(&limit) {
            return Err(ServiceError::invalid(
                "limit",
                "limit must be between 1 and 100",
            ));
        }
        if offset > retrieval::MAX_PAGE_OFFSET {
            return Err(ServiceError::invalid(
                "offset",
                "offset must not exceed 1000000",
            ));
        }

        // The caller token protects service-side validation and index metadata
        // reads only. It must be dropped before retrieval admits a cache
        // flight, where a shared token owns the actual SQLite work.
        let (connection, identity, preflight_registration) =
            open_validated_legal_database_cancellable(self.legal_core_path(), cancellation)?;
        let source_manifest_sha256 = connection
            .query_row(
                "SELECT value FROM database_metadata WHERE key = 'source_manifest_sha256'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let index_path = self
            .legal_core_path()
            .parent()
            .map(|parent| parent.join(retrieval::SEARCH_INDEX_FILE_NAME));
        let index = index_path.as_deref().and_then(|path| {
            SearchIndex::open_if_current(path, source_manifest_sha256.as_deref())
                .ok()
                .flatten()
        });
        drop(preflight_registration);
        let result = retrieval::search_page_cancellable(
            &connection,
            index.as_ref(),
            PagedSearchRequest {
                query: request.query.clone(),
                match_mode: request.match_mode.into(),
                version_scope,
                view: request.view.into(),
                document_id: request.document_id,
                case_date: request.case_date,
                limit,
                offset,
                document_type: request.document_type,
                effectiveness_level: request.effectiveness_level,
                jurisdiction: request.jurisdiction,
                status: request.status,
                version_status: request.version_status,
                sort: request.sort.into(),
            },
            cancellation,
        )?;
        Ok(LegalPagedSearchResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            query: request.query,
            view: request.view,
            laws: result.laws.into_iter().map(into_legal_group).collect(),
            articles: result.articles,
            total: result.total,
            total_laws: result.total_laws,
            total_articles: result.total_articles,
            limit: result.limit,
            offset: result.offset,
            database_version: identity.public_version(),
            warnings: result.warnings,
            applied_query: into_legal_applied_query(result.applied_query),
            ambiguities: result
                .ambiguities
                .into_iter()
                .map(into_legal_ambiguity)
                .collect(),
            metrics: into_legal_metrics(result.metrics),
        })
    }

    /// Read the authoritative body of one historical version in pages.  The
    /// old version-list operation remains metadata-only for compatibility.
    pub fn legal_version_articles(
        &self,
        request: LegalVersionArticlesRequest,
    ) -> Result<LegalVersionArticlesResponse, ServiceError> {
        self.legal_version_articles_cancellable(request, &SearchCancellation::new())
    }

    pub fn legal_version_articles_cancellable(
        &self,
        request: LegalVersionArticlesRequest,
        cancellation: &SearchCancellation,
    ) -> Result<LegalVersionArticlesResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("versionId", &request.version_id)?;
        let limit = request.limit.unwrap_or(retrieval::DEFAULT_PAGE_LIMIT);
        let offset = request.offset.unwrap_or(0);
        if !(1..=retrieval::MAX_PAGE_LIMIT).contains(&limit) {
            return Err(ServiceError::invalid(
                "limit",
                "limit must be between 1 and 100",
            ));
        }
        if offset > retrieval::MAX_PAGE_OFFSET {
            return Err(ServiceError::invalid(
                "offset",
                "offset must not exceed 1000000",
            ));
        }
        let (connection, identity, _registration) =
            open_validated_legal_database_cancellable(self.legal_core_path(), cancellation)?;
        let result = retrieval::version_articles(
            &connection,
            VersionArticlesRequest {
                version_id: request.version_id.clone(),
                limit,
                offset,
            },
        )?;
        Ok(LegalVersionArticlesResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            version_id: result.version_id,
            document_id: result.document_id,
            articles: result.articles,
            total: result.total,
            limit: result.limit,
            offset: result.offset,
            database_version: identity.public_version(),
            warnings: Vec::new(),
        })
    }

    pub fn legal_version_articles_scoped(
        &self,
        request: LegalVersionArticlesScopedRequest,
    ) -> Result<LegalVersionArticlesResponse, ServiceError> {
        self.legal_version_articles_scoped_cancellable(request, &SearchCancellation::new())
    }

    pub fn legal_version_articles_scoped_cancellable(
        &self,
        request: LegalVersionArticlesScopedRequest,
        cancellation: &SearchCancellation,
    ) -> Result<LegalVersionArticlesResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("versionId", &request.version_id)?;
        if let Some(case_date) = request.case_date.as_deref() {
            if !domain::date::is_iso_calendar_date(case_date) {
                return Err(ServiceError::invalid(
                    "caseDate",
                    "caseDate must be a valid YYYY-MM-DD calendar date",
                ));
            }
        }
        let scope = resolve_version_scope(request.version_scope, request.case_date.as_deref())?;
        let limit = request.limit.unwrap_or(retrieval::DEFAULT_PAGE_LIMIT);
        let offset = request.offset.unwrap_or(0);
        if !(1..=retrieval::MAX_PAGE_LIMIT).contains(&limit) {
            return Err(ServiceError::invalid(
                "limit",
                "limit must be between 1 and 100",
            ));
        }
        if offset > retrieval::MAX_PAGE_OFFSET {
            return Err(ServiceError::invalid(
                "offset",
                "offset must not exceed 1000000",
            ));
        }
        let (connection, identity, _registration) =
            open_validated_legal_database_cancellable(self.legal_core_path(), cancellation)?;
        if !retrieval::version_is_visible(
            &connection,
            &request.version_id,
            scope,
            request.case_date.as_deref(),
            None,
        )? {
            return Err(ServiceError::not_found("law_version"));
        }
        let result = retrieval::version_articles(
            &connection,
            VersionArticlesRequest {
                version_id: request.version_id,
                limit,
                offset,
            },
        )?;
        Ok(LegalVersionArticlesResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            version_id: result.version_id,
            document_id: result.document_id,
            articles: result.articles,
            total: result.total,
            limit: result.limit,
            offset: result.offset,
            database_version: identity.public_version(),
            warnings: Vec::new(),
        })
    }

    /// Return the actual categorical values in the configured corpus so a
    /// client never has to guess filter spellings.
    pub fn legal_search_facets(&self) -> Result<LegalSearchFacetsResponse, ServiceError> {
        self.legal_search_facets_cancellable(&SearchCancellation::new())
    }

    pub fn legal_search_facets_cancellable(
        &self,
        cancellation: &SearchCancellation,
    ) -> Result<LegalSearchFacetsResponse, ServiceError> {
        let (connection, identity, _registration) =
            open_validated_legal_database_cancellable(self.legal_core_path(), cancellation)?;
        let document_types = distinct_values(&connection, "document_type")?;
        let effectiveness_levels = distinct_values(&connection, "effectiveness_level")?;
        let jurisdictions = distinct_values(&connection, "jurisdiction")?;
        let statuses = distinct_values(&connection, "status")?;
        let version_statuses = distinct_version_statuses(&connection)?;
        Ok(LegalSearchFacetsResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            document_types,
            effectiveness_levels,
            jurisdictions,
            statuses,
            version_statuses,
            database_version: identity.public_version(),
        })
    }
}

pub(crate) fn resolve_version_scope(
    explicit: Option<LegalVersionScope>,
    case_date: Option<&str>,
) -> Result<VersionScope, ServiceError> {
    match (explicit, case_date) {
        (Some(LegalVersionScope::Current | LegalVersionScope::All), Some(_)) => Err(
            ServiceError::invalid("caseDate", "caseDate is only valid with versionScope as_of"),
        ),
        (Some(LegalVersionScope::AsOf), None) => Err(ServiceError::invalid(
            "caseDate",
            "versionScope as_of requires caseDate",
        )),
        (Some(scope), _) => Ok(scope.into()),
        (None, Some(_)) => Ok(VersionScope::AsOf),
        (None, None) => Ok(VersionScope::Current),
    }
}

fn into_legal_applied_query(value: SearchAppliedQuery) -> LegalAppliedQuery {
    LegalAppliedQuery {
        normalized_query: value.normalized_query,
        match_mode: match value.match_mode {
            SearchMatchMode::All => LegalSearchMatchMode::All,
            SearchMatchMode::Any => LegalSearchMatchMode::Any,
            SearchMatchMode::Phrase => LegalSearchMatchMode::Phrase,
        },
        version_scope: match value.version_scope {
            VersionScope::Current => LegalVersionScope::Current,
            VersionScope::AsOf => LegalVersionScope::AsOf,
            VersionScope::All => LegalVersionScope::All,
        },
        as_of: value.as_of,
        resolved_document_id: value.resolved_document_id,
        exact_article_number: value.exact_article_number,
    }
}

fn into_legal_ambiguity(value: LawNameAmbiguity) -> LegalLawNameAmbiguity {
    LegalLawNameAmbiguity {
        query: value.query,
        candidates: value
            .candidates
            .into_iter()
            .map(|(document_id, title)| LegalLawNameCandidate { document_id, title })
            .collect(),
    }
}

fn into_legal_metrics(value: SearchMetrics) -> LegalSearchMetrics {
    LegalSearchMetrics {
        candidate_count: value.candidate_count,
        index_fallback: value.index_fallback,
        cache_hit: value.cache_hit,
        count_cache_hit: value.count_cache_hit,
        cache_retained_bytes: value.cache_retained_bytes,
        lock_wait_ms: value.lock_wait_ms,
    }
}

fn into_legal_group(group: LawSearchGroup) -> LegalSearchGroup {
    LegalSearchGroup {
        law: group.law,
        matched_article_count: group.matched_article_count,
        top_articles: group.top_articles,
    }
}

fn validate_filter(field: &'static str, value: Option<&str>) -> Result<(), ServiceError> {
    let Some(value) = value else { return Ok(()) };
    if value.is_empty()
        || value.len() > MAX_FILTER_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character == '%' || character == '_')
    {
        return Err(ServiceError::invalid(
            field,
            "filter must be a bounded literal value",
        ));
    }
    Ok(())
}

fn distinct_values(
    connection: &rusqlite::Connection,
    column: &'static str,
) -> Result<Vec<String>, ServiceError> {
    // `column` is a closed set of call-site constants, never request input.
    let sql = format!(
        "SELECT DISTINCT {column} FROM law_documents WHERE {column} <> '' ORDER BY {column}"
    );
    Ok(connection
        .prepare(&sql)?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

fn distinct_version_statuses(
    connection: &rusqlite::Connection,
) -> Result<Vec<String>, ServiceError> {
    let values = connection
        .prepare(
            "SELECT DISTINCT status FROM law_versions
             WHERE status IS NOT NULL AND status <> '' ORDER BY status ASC",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paged_request_uses_the_stable_camel_case_wire_contract() {
        let request: LegalPagedSearchRequest = serde_json::from_value(serde_json::json!({
            "schemaVersion": 1,
            "query": "合同",
            "sort": "published_date",
            "view": "flat",
            "documentType": "law",
            "caseDate": "2024-01-01"
        }))
        .expect("paged request deserializes");
        assert_eq!(request.schema_version, 1);
        assert_eq!(request.view, LegalSearchView::Flat);
        assert_eq!(request.sort, LegalSearchSort::PublishedDate);
        assert_eq!(request.document_type.as_deref(), Some("law"));
        assert_eq!(request.case_date.as_deref(), Some("2024-01-01"));

        let encoded = serde_json::to_value(LegalPagedSearchResponse {
            schema_version: 1,
            query: "合同".to_owned(),
            view: LegalSearchView::Flat,
            laws: Vec::new(),
            articles: Vec::new(),
            total_laws: 2,
            total_articles: 3,
            total: 3,
            limit: 20,
            offset: 0,
            database_version: "fixture".to_owned(),
            warnings: Vec::new(),
            applied_query: LegalAppliedQuery {
                normalized_query: "合同".to_owned(),
                match_mode: LegalSearchMatchMode::All,
                version_scope: LegalVersionScope::Current,
                as_of: None,
                resolved_document_id: None,
                exact_article_number: None,
            },
            ambiguities: Vec::new(),
            metrics: LegalSearchMetrics {
                candidate_count: 0,
                index_fallback: false,
                cache_hit: false,
                count_cache_hit: false,
                cache_retained_bytes: 0,
                lock_wait_ms: 0,
            },
        })
        .expect("response fields serialize");
        assert_eq!(encoded["totalLaws"], 2);
        assert_eq!(encoded["totalArticles"], 3);
    }

    #[test]
    fn omitted_scope_keeps_legacy_case_date_as_of_semantics() {
        assert_eq!(
            resolve_version_scope(None, Some("2024-01-01")).unwrap(),
            VersionScope::AsOf
        );
        assert_eq!(
            resolve_version_scope(None, None).unwrap(),
            VersionScope::Current
        );
        assert!(
            resolve_version_scope(Some(LegalVersionScope::Current), Some("2024-01-01")).is_err()
        );
        assert!(resolve_version_scope(Some(LegalVersionScope::AsOf), None).is_err());
    }

    #[test]
    fn cancelled_version_body_and_facets_never_open_the_corpus() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let services = LegalServices::new_public(temporary.path().join("not-opened.sqlite"))
            .expect("public service initializes");
        let cancellation = SearchCancellation::new();
        cancellation.cancel();

        let body = services.legal_version_articles_scoped_cancellable(
            LegalVersionArticlesScopedRequest {
                schema_version: 1,
                version_id: "version-1".into(),
                version_scope: None,
                case_date: None,
                limit: None,
                offset: None,
            },
            &cancellation,
        );
        assert!(matches!(
            body,
            Err(ServiceError { ref code, .. }) if code == "request_cancelled"
        ));
        let facets = services.legal_search_facets_cancellable(&cancellation);
        assert!(matches!(
            facets,
            Err(ServiceError { ref code, .. }) if code == "request_cancelled"
        ));
    }
}
