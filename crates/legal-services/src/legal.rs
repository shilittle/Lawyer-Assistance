use crate::{
    open_validated_legal_database, require_schema_version, validate_identifier, validate_text,
    LegalServices, ServiceError, SERVICE_SCHEMA_VERSION,
};
use domain::{
    law::{
        ArticleSearchResult, LawArticleDetail, LawRelationInfo, LawSearchResult, LawVersionInfo,
        RelationDirection, SearchArticlesRequest, SearchLawsRequest,
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
        let (connection, identity) = open_validated_legal_database(self.legal_core_path())?;
        let laws = retrieval::search_laws(
            &connection,
            SearchLawsRequest {
                query: request.query.clone(),
                limit: Some(limit),
            },
        )?
        .results;
        let articles = retrieval::search_articles(
            &connection,
            SearchArticlesRequest {
                query: request.query,
                document_id: request.document_id,
                case_date: request.case_date,
                limit: Some(limit),
            },
        )?
        .results;
        let mut warnings = Vec::new();
        if laws.is_empty() && articles.is_empty() {
            warnings.push("no_local_results_found".to_owned());
        }
        Ok(LegalSearchResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            laws,
            articles,
            database_version: identity.public_version(),
            warnings,
        })
    }

    pub fn legal_get_article(
        &self,
        request: LegalGetArticleRequest,
    ) -> Result<LegalGetArticleResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("articleId", &request.article_id)?;
        let (connection, identity) = open_validated_legal_database(self.legal_core_path())?;
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

    pub fn legal_get_versions(
        &self,
        request: LegalGetVersionsRequest,
    ) -> Result<LegalGetVersionsResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("documentId", &request.document_id)?;
        let (connection, identity) = open_validated_legal_database(self.legal_core_path())?;
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
        require_schema_version(request.schema_version)?;
        validate_identifier("documentId", &request.document_id)?;
        let (connection, identity) = open_validated_legal_database(self.legal_core_path())?;
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
