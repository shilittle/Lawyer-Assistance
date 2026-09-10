use crate::{
    open_validated_legal_database, open_validated_legal_database_cancellable,
    require_schema_version, validate_identifier, validate_text, LegalServices, SearchCancellation,
    ServiceError, SERVICE_SCHEMA_VERSION,
};
use domain::{
    law::{
        ArticleSearchResult, LawArticleDetail, LawRelationInfo, LawSearchResult, LawVersionInfo,
        RelationDirection,
    },
    qa::{CitationValidationReport, LegalSource},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_SEARCH_QUERY_BYTES: usize = 16 * 1024;
const MAX_ANSWER_BYTES: usize = 256 * 1024;
const MAX_ALLOWED_SOURCES: usize = 128;
const MAX_SEARCH_LIMIT: u32 = 50;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalSearchRequest {
    pub schema_version: u16,
    pub query: String,
    pub document_id: Option<String>,
    pub case_date: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalSearchResponse {
    pub schema_version: u16,
    pub laws: Vec<LawSearchResult>,
    pub articles: Vec<ArticleSearchResult>,
    pub database_version: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalGetArticleRequest {
    pub schema_version: u16,
    pub article_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalGetArticleResponse {
    pub schema_version: u16,
    pub article: LawArticleDetail,
    pub database_version: String,
    pub warnings: Vec<String>,
}

/// Additive scoped detail request.  The frozen MCP `legal_get_article`
/// remains ID-only; Web/AI callers can prove that a selected historical row
/// is visible under their applied version scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalGetArticleScopedRequest {
    pub schema_version: u16,
    pub article_id: String,
    #[serde(default)]
    pub version_scope: Option<crate::LegalVersionScope>,
    pub case_date: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalGetVersionsRequest {
    pub schema_version: u16,
    pub document_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalGetVersionsResponse {
    pub schema_version: u16,
    pub versions: Vec<LawVersionInfo>,
    pub database_version: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalGetRelationsRequest {
    pub schema_version: u16,
    pub document_id: String,
    pub direction: Option<RelationDirection>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalGetRelationsResponse {
    pub schema_version: u16,
    pub relations: Vec<LawRelationInfo>,
    pub database_version: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CitationValidateRequest {
    pub schema_version: u16,
    pub answer: String,
    pub allowed_source_ids: Vec<String>,
    pub case_date: Option<String>,
    pub include_expired: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CitationValidateResponse {
    pub schema_version: u16,
    pub report: CitationValidationReport,
    pub database_version: String,
    pub warnings: Vec<String>,
}

impl LegalServices {
    pub fn legal_search(
        &self,
        request: LegalSearchRequest,
    ) -> Result<LegalSearchResponse, ServiceError> {
        self.legal_search_cancellable(request, &SearchCancellation::new())
    }

    /// Frozen MCP/v1 response fields, implemented through the paged QueryPlan
    /// so old callers get the same all-term and date/version semantics as the
    /// Web and AI surfaces.
    pub fn legal_search_cancellable(
        &self,
        request: LegalSearchRequest,
        cancellation: &SearchCancellation,
    ) -> Result<LegalSearchResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_text("query", &request.query, MAX_SEARCH_QUERY_BYTES, false)?;
        if let Some(document_id) = request.document_id.as_deref() {
            validate_identifier("documentId", document_id)?;
        }
        let limit = request.limit.unwrap_or(20);
        if !(1..=MAX_SEARCH_LIMIT).contains(&limit) {
            return Err(ServiceError::invalid(
                "limit",
                "limit must be between 1 and 50",
            ));
        }
        let grouped = self.legal_search_page_cancellable(
            crate::LegalPagedSearchRequest {
                schema_version: request.schema_version,
                query: request.query.clone(),
                match_mode: crate::LegalSearchMatchMode::All,
                version_scope: None,
                view: crate::LegalSearchView::Grouped,
                document_id: request.document_id.clone(),
                case_date: request.case_date.clone(),
                limit: Some(limit),
                offset: Some(0),
                document_type: None,
                effectiveness_level: None,
                jurisdiction: None,
                status: None,
                version_status: None,
                sort: crate::LegalSearchSort::Relevance,
            },
            cancellation,
        )?;
        let flat = self.legal_search_page_cancellable(
            crate::LegalPagedSearchRequest {
                schema_version: request.schema_version,
                query: request.query,
                match_mode: crate::LegalSearchMatchMode::All,
                version_scope: None,
                view: crate::LegalSearchView::Flat,
                document_id: request.document_id,
                case_date: request.case_date,
                limit: Some(limit),
                offset: Some(0),
                document_type: None,
                effectiveness_level: None,
                jurisdiction: None,
                status: None,
                version_status: None,
                sort: crate::LegalSearchSort::Relevance,
            },
            cancellation,
        )?;
        let laws: Vec<LawSearchResult> = grouped.laws.into_iter().map(|group| group.law).collect();
        let articles = flat.articles;
        let mut warnings = Vec::new();
        if laws.is_empty() && articles.is_empty() {
            warnings.push("no_local_results_found".to_owned());
        }
        Ok(LegalSearchResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            laws,
            articles,
            database_version: flat.database_version,
            warnings,
        })
    }

    pub fn legal_get_article(
        &self,
        request: LegalGetArticleRequest,
    ) -> Result<LegalGetArticleResponse, ServiceError> {
        self.legal_get_article_cancellable(request, &SearchCancellation::new())
    }

    pub fn legal_get_article_cancellable(
        &self,
        request: LegalGetArticleRequest,
        cancellation: &SearchCancellation,
    ) -> Result<LegalGetArticleResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("articleId", &request.article_id)?;
        let (connection, identity, _registration) =
            open_validated_legal_database_cancellable(self.legal_core_path(), cancellation)?;
        let article = retrieval::get_article(
            &connection,
            domain::law::GetArticleRequest {
                article_id: request.article_id,
            },
        )?
        .article
        .ok_or_else(|| ServiceError::not_found("law_article"))?;
        Ok(LegalGetArticleResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            article,
            database_version: identity.public_version(),
            warnings: Vec::new(),
        })
    }

    pub fn legal_get_article_scoped(
        &self,
        request: LegalGetArticleScopedRequest,
    ) -> Result<LegalGetArticleResponse, ServiceError> {
        self.legal_get_article_scoped_cancellable(request, &SearchCancellation::new())
    }

    pub fn legal_get_article_scoped_cancellable(
        &self,
        request: LegalGetArticleScopedRequest,
        cancellation: &SearchCancellation,
    ) -> Result<LegalGetArticleResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("articleId", &request.article_id)?;
        if let Some(case_date) = request.case_date.as_deref() {
            if !domain::date::is_iso_calendar_date(case_date) {
                return Err(ServiceError::invalid(
                    "caseDate",
                    "caseDate must be a valid YYYY-MM-DD calendar date",
                ));
            }
        }
        let scope = crate::paged::resolve_version_scope(
            request.version_scope,
            request.case_date.as_deref(),
        )?;
        let (connection, identity, _registration) =
            open_validated_legal_database_cancellable(self.legal_core_path(), cancellation)?;
        let article = retrieval::get_article(
            &connection,
            domain::law::GetArticleRequest {
                article_id: request.article_id,
            },
        )?
        .article
        .ok_or_else(|| ServiceError::not_found("law_article"))?;
        if !retrieval::version_is_visible(
            &connection,
            &article.version_id,
            scope,
            request.case_date.as_deref(),
            None,
        )? {
            return Err(ServiceError::not_found("law_article"));
        }
        Ok(LegalGetArticleResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            article,
            database_version: identity.public_version(),
            warnings: Vec::new(),
        })
    }

    pub fn legal_get_versions(
        &self,
        request: LegalGetVersionsRequest,
    ) -> Result<LegalGetVersionsResponse, ServiceError> {
        self.legal_get_versions_cancellable(request, &SearchCancellation::new())
    }

    pub fn legal_get_versions_cancellable(
        &self,
        request: LegalGetVersionsRequest,
        cancellation: &SearchCancellation,
    ) -> Result<LegalGetVersionsResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("documentId", &request.document_id)?;
        let (connection, identity, _registration) =
            open_validated_legal_database_cancellable(self.legal_core_path(), cancellation)?;
        let versions = retrieval::get_law_versions(
            &connection,
            domain::law::GetLawVersionsRequest {
                document_id: request.document_id,
            },
        )?
        .versions;
        Ok(LegalGetVersionsResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            versions,
            database_version: identity.public_version(),
            warnings: Vec::new(),
        })
    }

    pub fn legal_get_relations(
        &self,
        request: LegalGetRelationsRequest,
    ) -> Result<LegalGetRelationsResponse, ServiceError> {
        self.legal_get_relations_cancellable(request, &SearchCancellation::new())
    }

    pub fn legal_get_relations_cancellable(
        &self,
        request: LegalGetRelationsRequest,
        cancellation: &SearchCancellation,
    ) -> Result<LegalGetRelationsResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("documentId", &request.document_id)?;
        let (connection, identity, _registration) =
            open_validated_legal_database_cancellable(self.legal_core_path(), cancellation)?;
        let relations = retrieval::get_law_relations(
            &connection,
            domain::law::GetLawRelationsRequest {
                document_id: request.document_id,
                direction: request.direction,
            },
        )?
        .relations;
        Ok(LegalGetRelationsResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            relations,
            database_version: identity.public_version(),
            warnings: Vec::new(),
        })
    }

    pub fn citation_validate(
        &self,
        request: CitationValidateRequest,
    ) -> Result<CitationValidateResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_text("answer", &request.answer, MAX_ANSWER_BYTES, true)?;
        if request.allowed_source_ids.len() > MAX_ALLOWED_SOURCES {
            return Err(ServiceError::invalid(
                "allowedSourceIds",
                "too many allowed citation sources",
            ));
        }
        let (connection, identity) = open_validated_legal_database(self.legal_core_path())?;
        let mut seen = BTreeSet::new();
        let mut sources: Vec<LegalSource> = Vec::new();
        let mut warnings = Vec::new();
        for source_id in request.allowed_source_ids {
            validate_identifier("allowedSourceIds", &source_id)?;
            if !seen.insert(source_id.clone()) {
                continue;
            }
            match citations::source_by_citation_id(&connection, &source_id)? {
                Some(source) => sources.push(source),
                None => warnings.push(format!("allowed_source_not_found:{source_id}")),
            }
        }
        let report = citations::validate_answer_citations(
            &connection,
            &request.answer,
            &sources,
            request.case_date.as_deref(),
            request.include_expired,
        )?;
        if !report.semantic_support_verified {
            warnings.push("semantic_support_not_verified".to_owned());
        }
        Ok(CitationValidateResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            report,
            database_version: identity.public_version(),
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cancelled_service() -> (tempfile::TempDir, LegalServices, SearchCancellation) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let services = LegalServices::new_public(temporary.path().join("not-opened.sqlite"))
            .expect("public service initializes");
        let cancellation = SearchCancellation::new();
        cancellation.cancel();
        (temporary, services, cancellation)
    }

    fn assert_cancelled<T>(result: Result<T, ServiceError>) {
        assert!(matches!(
            result,
            Err(ServiceError { ref code, .. }) if code == "request_cancelled"
        ));
    }

    #[test]
    fn cancelled_detail_and_metadata_reads_never_open_the_corpus() {
        let (_temporary, services, cancellation) = cancelled_service();
        assert_cancelled(services.legal_get_article_cancellable(
            LegalGetArticleRequest {
                schema_version: 1,
                article_id: "article-1".into(),
            },
            &cancellation,
        ));
        assert_cancelled(services.legal_get_article_scoped_cancellable(
            LegalGetArticleScopedRequest {
                schema_version: 1,
                article_id: "article-1".into(),
                version_scope: None,
                case_date: None,
            },
            &cancellation,
        ));
        assert_cancelled(services.legal_get_versions_cancellable(
            LegalGetVersionsRequest {
                schema_version: 1,
                document_id: "document-1".into(),
            },
            &cancellation,
        ));
        assert_cancelled(services.legal_get_relations_cancellable(
            LegalGetRelationsRequest {
                schema_version: 1,
                document_id: "document-1".into(),
                direction: None,
            },
            &cancellation,
        ));
    }
}
