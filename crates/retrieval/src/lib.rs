use std::{
    error::Error,
    fmt::{self, Display},
};

use domain::law::{
    generate_article_citation_id, ArticleSearchResult, GetArticleRequest, GetArticleResponse,
    GetLawRelationsRequest, GetLawRelationsResponse, GetLawVersionsRequest, GetLawVersionsResponse,
    LawArticleDetail, LawRelationInfo, LawSearchResult, LawVersionInfo, RelationDirection,
    SearchArticlesRequest, SearchArticlesResponse, SearchLawsRequest, SearchLawsResponse,
};
use rusqlite::{named_params, OptionalExtension};

const DEFAULT_SEARCH_LIMIT: u32 = 20;
const MAX_SEARCH_LIMIT: u32 = 50;

#[derive(Debug)]
pub enum RetrievalError {
    InvalidRequest(String),
    Sqlite(rusqlite::Error),
}

impl Display for RetrievalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid retrieval request: {message}")
            }
            Self::Sqlite(error) => write!(formatter, "sqlite retrieval error: {error}"),
        }
    }
}

impl Error for RetrievalError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRequest(_) => None,
            Self::Sqlite(error) => Some(error),
        }
    }
}

impl From<rusqlite::Error> for RetrievalError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub fn search_laws(
    connection: &rusqlite::Connection,
    request: SearchLawsRequest,
) -> Result<SearchLawsResponse, RetrievalError> {
    let query = request.query.trim();
    let is_empty = query.is_empty();
    let like_query = like_pattern(query);
    let limit = bounded_limit(request.limit);

    let mut statement = connection.prepare(
        "
        WITH ranked_current_versions AS (
            SELECT
                versions.*,
                ROW_NUMBER() OVER (
                    PARTITION BY versions.document_id
                    ORDER BY versions.effective_from DESC, versions.id DESC
                ) AS current_rank
            FROM law_versions versions
            WHERE versions.effective_from <= date('now', 'localtime')
              AND (
                versions.effective_to IS NULL
                OR versions.effective_to >= date('now', 'localtime')
              )
              AND versions.status <> 'not_yet_effective'
        ),
        current_versions AS (
            SELECT *
            FROM ranked_current_versions
            WHERE current_rank = 1
        )
        SELECT
            documents.id,
            documents.title,
            documents.document_type,
            authorities.name,
            documents.effectiveness_level,
            documents.status,
            current_versions.id,
            current_versions.effective_from,
            current_versions.effective_to,
            MAX(CASE
                WHEN :is_empty = 1 THEN 10.0
                WHEN documents.title = :query THEN 100.0
                WHEN aliases.alias = :query THEN 92.0
                WHEN documents.title LIKE :prefix_query ESCAPE '\\' THEN 84.0
                WHEN aliases.alias LIKE :prefix_query ESCAPE '\\' THEN 78.0
                WHEN documents.title LIKE :like_query ESCAPE '\\' THEN 64.0
                WHEN aliases.alias LIKE :like_query ESCAPE '\\' THEN 58.0
                WHEN documents.summary LIKE :like_query ESCAPE '\\' THEN 32.0
                ELSE 1.0
            END) AS score,
            MAX(CASE
                WHEN aliases.alias LIKE :like_query ESCAPE '\\' THEN aliases.alias
                ELSE NULL
            END) AS matched_alias,
            documents.summary
        FROM law_documents documents
        JOIN issuing_authorities authorities ON authorities.id = documents.authority_id
        LEFT JOIN law_aliases aliases ON aliases.document_id = documents.id
        LEFT JOIN current_versions ON current_versions.document_id = documents.id
        WHERE
            :is_empty = 1
            OR documents.title LIKE :like_query ESCAPE '\\'
            OR documents.summary LIKE :like_query ESCAPE '\\'
            OR aliases.alias LIKE :like_query ESCAPE '\\'
            OR aliases.normalized_alias LIKE :like_query ESCAPE '\\'
        GROUP BY documents.id
        ORDER BY
            score DESC,
            CASE documents.status WHEN 'in_force' THEN 0 ELSE 1 END,
            documents.title ASC
        LIMIT :limit
        ",
    )?;

    let prefix_query = format!("{}%", escape_like(query));
    let results = statement
        .query_map(
            named_params! {
                ":query": query,
                ":is_empty": if is_empty { 1_i64 } else { 0_i64 },
                ":like_query": like_query,
                ":prefix_query": prefix_query,
                ":limit": limit,
            },
            |row| {
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
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(SearchLawsResponse { results })
}

pub fn search_articles(
    connection: &rusqlite::Connection,
    request: SearchArticlesRequest,
) -> Result<SearchArticlesResponse, RetrievalError> {
    if let Some(case_date) = request.case_date.as_deref() {
        if !domain::date::is_iso_calendar_date(case_date) {
            return Err(RetrievalError::InvalidRequest(
                "case_date must be a valid YYYY-MM-DD calendar date".to_owned(),
            ));
        }
    }

    let query = request.query.trim();
    let limit = bounded_limit(request.limit);

    if !query.is_empty() {
        match search_articles_fts(connection, &request, query, limit) {
            Ok(results) if !results.is_empty() => return Ok(SearchArticlesResponse { results }),
            Ok(_) => {}
            Err(RetrievalError::Sqlite(_)) => {}
            Err(error @ RetrievalError::InvalidRequest(_)) => return Err(error),
        }
    }

    let results = search_articles_like(connection, &request, query, limit)?;

    Ok(SearchArticlesResponse { results })
}

pub fn get_article(
    connection: &rusqlite::Connection,
    request: GetArticleRequest,
) -> Result<GetArticleResponse, RetrievalError> {
    let article = connection
        .query_row(
            "
            SELECT
                articles.id,
                articles.document_id,
                articles.version_id,
                documents.title,
                versions.version_label,
                articles.article_number,
                articles.title,
                articles.content,
                citation_metadata.citation_id,
                citation_metadata.canonical_label,
                versions.effective_from,
                versions.effective_to,
                versions.status,
                articles.article_order
            FROM law_articles articles
            JOIN law_documents documents ON documents.id = articles.document_id
            JOIN law_versions versions ON versions.id = articles.version_id
            LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
            WHERE articles.id = ?1
            ",
            [request.article_id],
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
                        .unwrap_or_else(|| citation_id.clone()),
                    citation_id,
                    effective_from: row.get(10)?,
                    effective_to: row.get(11)?,
                    version_status: row.get(12)?,
                    topics: Vec::new(),
                })
            },
        )
        .optional()?;

    let article = match article {
        Some(mut article) => {
            article.topics = article_topics(connection, &article.article_id)?;
            Some(article)
        }
        None => None,
    };

    Ok(GetArticleResponse { article })
}

pub fn get_law_versions(
    connection: &rusqlite::Connection,
    request: GetLawVersionsRequest,
) -> Result<GetLawVersionsResponse, RetrievalError> {
    let mut statement = connection.prepare(
        "
        SELECT
            versions.id,
            versions.document_id,
            versions.version_label,
            versions.status,
            versions.effective_from,
            versions.effective_to,
            versions.published_on,
            versions.source_reference,
            (
                SELECT COUNT(*)
                FROM law_articles articles
                WHERE articles.version_id = versions.id
            ) AS article_count
        FROM law_versions versions
        WHERE versions.document_id = ?1
        ORDER BY versions.effective_from DESC
        ",
    )?;

    let versions = statement
        .query_map([request.document_id], |row| {
            let article_count: i64 = row.get(8)?;

            Ok(LawVersionInfo {
                version_id: row.get(0)?,
                document_id: row.get(1)?,
                version_label: row.get(2)?,
                status: row.get(3)?,
                effective_from: row.get(4)?,
                effective_to: row.get(5)?,
                published_on: row.get(6)?,
                source_reference: row.get(7)?,
                article_count: u32::try_from(article_count).unwrap_or(u32::MAX),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(GetLawVersionsResponse { versions })
}

pub fn get_law_relations(
    connection: &rusqlite::Connection,
    request: GetLawRelationsRequest,
) -> Result<GetLawRelationsResponse, RetrievalError> {
    let direction = match request.direction.unwrap_or(RelationDirection::Both) {
        RelationDirection::Both => "both",
        RelationDirection::Outgoing => "outgoing",
        RelationDirection::Incoming => "incoming",
    };

    let mut statement = connection.prepare(
        "
        SELECT
            relations.id,
            relations.from_document_id,
            from_documents.title,
            relations.to_document_id,
            to_documents.title,
            relations.relation_type,
            relations.description,
            relations.source_reference
        FROM law_relations relations
        JOIN law_documents from_documents ON from_documents.id = relations.from_document_id
        JOIN law_documents to_documents ON to_documents.id = relations.to_document_id
        WHERE
            (:direction = 'both'
                AND (relations.from_document_id = :document_id
                     OR relations.to_document_id = :document_id))
            OR (:direction = 'outgoing'
                AND relations.from_document_id = :document_id)
            OR (:direction = 'incoming'
                AND relations.to_document_id = :document_id)
        ORDER BY relations.relation_type ASC, to_documents.title ASC
        ",
    )?;

    let relations = statement
        .query_map(
            named_params! {
                ":direction": direction,
                ":document_id": request.document_id,
            },
            |row| {
                Ok(LawRelationInfo {
                    relation_id: row.get(0)?,
                    from_document_id: row.get(1)?,
                    from_title: row.get(2)?,
                    to_document_id: row.get(3)?,
                    to_title: row.get(4)?,
                    relation_type: row.get(5)?,
                    description: row.get(6)?,
                    source_reference: row.get(7)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(GetLawRelationsResponse { relations })
}

fn search_articles_fts(
    connection: &rusqlite::Connection,
    request: &SearchArticlesRequest,
    query: &str,
    limit: i64,
) -> Result<Vec<ArticleSearchResult>, RetrievalError> {
    let fts_query = quote_fts_query(query);
    let mut statement = connection.prepare(
        "
        SELECT
            articles.id,
            articles.document_id,
            articles.version_id,
            documents.title,
            articles.article_number,
            articles.title,
            articles.content,
            citation_metadata.citation_id,
            versions.effective_from,
            versions.effective_to,
            versions.status,
            bm25(law_articles_fts) AS rank,
            articles.article_order
        FROM law_articles_fts
        JOIN law_articles articles ON articles.rowid = law_articles_fts.rowid
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
        WHERE law_articles_fts MATCH :fts_query
          AND (:document_id IS NULL OR articles.document_id = :document_id)
          AND (
            :case_date IS NULL
            OR (
              versions.effective_from <= :case_date
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
            )
          )
        ORDER BY rank ASC, documents.title ASC, articles.article_order ASC
        LIMIT :limit
        ",
    )?;

    let rows = statement.query_map(
        named_params! {
            ":fts_query": fts_query,
            ":document_id": request.document_id.as_deref(),
            ":case_date": request.case_date.as_deref(),
            ":limit": limit,
        },
        |row| {
            let document_id: String = row.get(1)?;
            let version_id: String = row.get(2)?;
            let content: String = row.get(6)?;
            let article_order: i64 = row.get(12)?;
            let citation_id = row.get::<_, Option<String>>(7)?.unwrap_or_else(|| {
                generate_article_citation_id(&document_id, &version_id, &article_order.to_string())
            });
            let rank: f64 = row.get(11)?;

            Ok(ArticleSearchResult {
                article_id: row.get(0)?,
                document_id,
                version_id,
                document_title: row.get(3)?,
                article_number: row.get(4)?,
                article_title: row.get(5)?,
                snippet: snippet_for(query, &content),
                citation_id,
                effective_from: row.get(8)?,
                effective_to: row.get(9)?,
                version_status: row.get(10)?,
                score: -rank,
            })
        },
    )?;
    let results = rows.collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

fn search_articles_like(
    connection: &rusqlite::Connection,
    request: &SearchArticlesRequest,
    query: &str,
    limit: i64,
) -> Result<Vec<ArticleSearchResult>, RetrievalError> {
    let is_empty = query.is_empty();
    let like_query = like_pattern(query);

    let mut statement = connection.prepare(
        "
        SELECT
            articles.id,
            articles.document_id,
            articles.version_id,
            documents.title,
            articles.article_number,
            articles.title,
            articles.content,
            citation_metadata.citation_id,
            versions.effective_from,
            versions.effective_to,
            versions.status,
            CASE
                WHEN :is_empty = 1 THEN 10.0
                WHEN documents.title LIKE :like_query ESCAPE '\\' THEN 72.0
                WHEN articles.article_number LIKE :like_query ESCAPE '\\' THEN 68.0
                WHEN articles.title LIKE :like_query ESCAPE '\\' THEN 64.0
                WHEN articles.content LIKE :like_query ESCAPE '\\' THEN 52.0
                ELSE 1.0
            END AS score,
            articles.article_order
        FROM law_articles articles
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
        WHERE
          (
            :is_empty = 1
            OR documents.title LIKE :like_query ESCAPE '\\'
            OR articles.article_number LIKE :like_query ESCAPE '\\'
            OR articles.title LIKE :like_query ESCAPE '\\'
            OR articles.content LIKE :like_query ESCAPE '\\'
          )
          AND (:document_id IS NULL OR articles.document_id = :document_id)
          AND (
            :case_date IS NULL
            OR (
              versions.effective_from <= :case_date
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
            )
          )
        ORDER BY score DESC, documents.title ASC, articles.article_order ASC
        LIMIT :limit
        ",
    )?;

    let rows = statement.query_map(
        named_params! {
            ":is_empty": if is_empty { 1_i64 } else { 0_i64 },
            ":like_query": like_query,
            ":document_id": request.document_id.as_deref(),
            ":case_date": request.case_date.as_deref(),
            ":limit": limit,
        },
        |row| {
            let document_id: String = row.get(1)?;
            let version_id: String = row.get(2)?;
            let content: String = row.get(6)?;
            let article_order: i64 = row.get(12)?;
            let citation_id = row.get::<_, Option<String>>(7)?.unwrap_or_else(|| {
                generate_article_citation_id(&document_id, &version_id, &article_order.to_string())
            });

            Ok(ArticleSearchResult {
                article_id: row.get(0)?,
                document_id,
                version_id,
                document_title: row.get(3)?,
                article_number: row.get(4)?,
                article_title: row.get(5)?,
                snippet: snippet_for(query, &content),
                citation_id,
                effective_from: row.get(8)?,
                effective_to: row.get(9)?,
                version_status: row.get(10)?,
                score: row.get(11)?,
            })
        },
    )?;
    let results = rows.collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

fn article_topics(
    connection: &rusqlite::Connection,
    article_id: &str,
) -> Result<Vec<String>, RetrievalError> {
    let mut statement = connection.prepare(
        "
        SELECT topics.name
        FROM article_topics article_topics
        JOIN legal_topics topics ON topics.id = article_topics.topic_id
        WHERE article_topics.article_id = ?1
        ORDER BY topics.name ASC
        ",
    )?;

    let topics = statement
        .query_map([article_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(topics)
}

fn bounded_limit(limit: Option<u32>) -> i64 {
    i64::from(
        limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .clamp(1, MAX_SEARCH_LIMIT),
    )
}

fn like_pattern(query: &str) -> String {
    if query.trim().is_empty() {
        "%".to_owned()
    } else {
        format!("%{}%", escape_like(query.trim()))
    }
}

fn escape_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn quote_fts_query(query: &str) -> String {
    format!("\"{}\"", query.replace('"', "\"\""))
}

fn snippet_for(query: &str, content: &str) -> String {
    if query.is_empty() {
        return truncate_chars(content, 96);
    }

    let Some(byte_index) = content.find(query) else {
        return truncate_chars(content, 96);
    };

    let start = content[..byte_index]
        .char_indices()
        .rev()
        .nth(16)
        .map(|(index, _)| index)
        .unwrap_or(0);
    let end = content[byte_index..]
        .char_indices()
        .nth(query.chars().count() + 32)
        .map(|(index, _)| byte_index + index)
        .unwrap_or(content.len());
    let prefix = if start > 0 { "..." } else { "" };
    let suffix = if end < content.len() { "..." } else { "" };

    format!("{prefix}{}{suffix}", &content[start..end])
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut output = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        output.push_str("...");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETRIEVAL_FIXTURE_SQL: &str =
        include_str!("../../../data/fixtures/legal_core_retrieval_fixture.sql");

    fn fixture_connection() -> rusqlite::Connection {
        let connection = rusqlite::Connection::open_in_memory().expect("memory database opens");
        database::initialize_legal_core_database(&connection).expect("fixture schema loads");
        connection
            .execute_batch(RETRIEVAL_FIXTURE_SQL)
            .expect("retrieval fixture loads");
        connection
    }

    #[test]
    fn searches_laws_by_alias() {
        let connection = fixture_connection();
        let response = search_laws(
            &connection,
            SearchLawsRequest {
                query: "民法典".to_owned(),
                limit: Some(10),
            },
        )
        .expect("law search succeeds");

        assert_eq!(response.results[0].document_id, "cn-civil-code");
        assert_eq!(
            response.results[0].current_version_id.as_deref(),
            Some("cn-civil-code-20210101")
        );
    }

    #[test]
    fn law_search_does_not_present_a_future_version_as_current() {
        let connection = fixture_connection();
        connection
            .execute(
                "
                INSERT INTO law_versions (
                    id, document_id, version_label, status, effective_from, effective_to,
                    published_on, source_reference
                ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)
                ",
                rusqlite::params![
                    "cn-civil-code-29990101",
                    "cn-civil-code",
                    "未来版本",
                    "not_yet_effective",
                    "2999-01-01",
                    "2998-12-01",
                    "future-version-test"
                ],
            )
            .expect("future fixture version inserts");

        let response = search_laws(
            &connection,
            SearchLawsRequest {
                query: "民法典".to_owned(),
                limit: Some(10),
            },
        )
        .expect("law search succeeds");
        let civil_code = response
            .results
            .iter()
            .find(|result| result.document_id == "cn-civil-code")
            .expect("civil code is returned");

        assert_eq!(
            civil_code.current_version_id.as_deref(),
            Some("cn-civil-code-20210101")
        );
    }

    #[test]
    fn searches_articles_and_filters_effective_version_by_case_date() {
        let connection = fixture_connection();
        let old_case = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "违约责任".to_owned(),
                document_id: None,
                case_date: Some("2020-06-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("old case search succeeds");
        let new_case = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "违约责任".to_owned(),
                document_id: None,
                case_date: Some("2024-06-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("new case search succeeds");

        assert!(old_case
            .results
            .iter()
            .any(|result| result.version_id == "cn-contract-law-19991001"));
        assert!(new_case
            .results
            .iter()
            .any(|result| result.version_id == "cn-civil-code-20210101"));
        assert!(!new_case
            .results
            .iter()
            .any(|result| result.version_id == "cn-contract-law-19991001"));
    }

    #[test]
    fn rejects_invalid_case_date_before_article_search() {
        let connection = fixture_connection();
        let error = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "违约责任".to_owned(),
                document_id: None,
                case_date: Some("2024-02-30".to_owned()),
                limit: Some(10),
            },
        )
        .expect_err("invalid calendar date is rejected");

        assert!(matches!(error, RetrievalError::InvalidRequest(_)));
        assert!(error.to_string().contains("valid YYYY-MM-DD"));
    }

    #[test]
    fn get_article_returns_detail_topics_and_citation() {
        let connection = fixture_connection();
        let response = get_article(
            &connection,
            GetArticleRequest {
                article_id: "cn-labor-contract-law-20130701-82".to_owned(),
            },
        )
        .expect("article lookup succeeds");
        let article = response.article.expect("article exists");

        assert_eq!(article.document_title, "中华人民共和国劳动合同法");
        assert_eq!(article.article_number, "第八十二条");
        assert_eq!(
            article.citation_id,
            "law:cn-labor-contract-law:cn-labor-contract-law-20130701:art:82"
        );
        assert!(article.topics.contains(&"劳动关系".to_owned()));
    }

    #[test]
    fn lists_versions_for_document() {
        let connection = fixture_connection();
        let response = get_law_versions(
            &connection,
            GetLawVersionsRequest {
                document_id: "cn-civil-code".to_owned(),
            },
        )
        .expect("version lookup succeeds");

        assert_eq!(response.versions.len(), 1);
        assert_eq!(response.versions[0].article_count, 3);
    }

    #[test]
    fn lists_document_relations() {
        let connection = fixture_connection();
        let response = get_law_relations(
            &connection,
            GetLawRelationsRequest {
                document_id: "cn-civil-code".to_owned(),
                direction: Some(RelationDirection::Outgoing),
            },
        )
        .expect("relation lookup succeeds");

        assert_eq!(response.relations.len(), 1);
        assert_eq!(response.relations[0].relation_type, "replaces");
        assert_eq!(response.relations[0].to_document_id, "cn-contract-law-1999");
    }
}
