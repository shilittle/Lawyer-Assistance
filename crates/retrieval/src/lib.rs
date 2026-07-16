use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{self, Display},
};

use domain::law::{
    generate_article_citation_id, ArticleSearchResult, GetArticleRequest, GetArticleResponse,
    GetLawDocumentRequest, GetLawDocumentResponse, GetLawRelationsRequest, GetLawRelationsResponse,
    GetLawVersionsRequest, GetLawVersionsResponse, LawArticleDetail, LawRelationInfo,
    LawSearchResult, LawVersionInfo, RelationDirection, SearchArticlesRequest,
    SearchArticlesResponse, SearchLawsRequest, SearchLawsResponse,
};
use rusqlite::{named_params, types::Value, OptionalExtension, ToSql};

const DEFAULT_SEARCH_LIMIT: u32 = 20;
const MAX_SEARCH_LIMIT: u32 = 50;
const MAX_SEARCH_TERMS: usize = 16;
const MIN_FTS_SEED_LIMIT: i64 = 64;
const MAX_FTS_SEED_LIMIT: i64 = 128;
const MAX_LIKE_CANDIDATES: i64 = 512;
const TERM_MATCH_SCORE: f64 = 1_000_000.0;
const SUBSTANTIVE_MATCH_SCORE: f64 = 10_000.0;
const ARTICLE_TITLE_MATCH_SCORE: f64 = 100.0;
const CURRENT_VERSION_SCORE: f64 = 50.0;
const MAX_ARTICLE_ORDINAL: u32 = 99_999;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedArticleNumber {
    base: u32,
    subarticle: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StructuredArticleQuery {
    law_name: Option<String>,
    article_number: ParsedArticleNumber,
}

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
              AND NOT (
                versions.status = 'repealed'
                AND versions.effective_to IS NULL
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

pub fn get_law_document(
    connection: &rusqlite::Connection,
    request: GetLawDocumentRequest,
) -> Result<GetLawDocumentResponse, RetrievalError> {
    let document = connection
        .query_row(
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
                  AND NOT (
                    versions.status = 'repealed'
                    AND versions.effective_to IS NULL
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
                documents.summary
            FROM law_documents documents
            JOIN issuing_authorities authorities ON authorities.id = documents.authority_id
            LEFT JOIN current_versions ON current_versions.document_id = documents.id
            WHERE documents.id = ?1
            ",
            [request.document_id],
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
                    matched_alias: None,
                    summary: row.get(9)?,
                    score: 1.0,
                })
            },
        )
        .optional()?;

    Ok(GetLawDocumentResponse { document })
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

    if let Some(structured_query) = parse_structured_article_query(query) {
        let results = search_articles_structured(connection, &request, &structured_query, limit)?;
        return Ok(SearchArticlesResponse { results });
    }

    if query.is_empty() {
        let results = search_articles_like(connection, &request, query, limit)?;
        return Ok(SearchArticlesResponse { results });
    }

    let search_terms = split_search_terms(query);
    let may_expand_like = requires_bounded_like_expansion(&search_terms);
    // A saturated single-term FTS page already has enough deterministic
    // candidates. Running `%term%` over every row in all seed versions adds no
    // recall to that page and is disproportionately expensive for common CJK
    // words. Multi-term OR ranking still merges the bounded LIKE candidates.
    let fts_limit = if search_terms.len() > 1 {
        expanded_fts_seed_limit(limit)
    } else {
        limit
    };
    let fts_results = match search_articles_fts(connection, &request, query, fts_limit) {
        Ok(results) => results,
        Err(RetrievalError::Sqlite(_)) => Vec::new(),
        Err(error @ RetrievalError::InvalidRequest(_)) => return Err(error),
    };
    let expand_like =
        should_expand_bounded_like(&search_terms, may_expand_like, fts_results.len(), limit);

    if !expand_like && !fts_results.is_empty() {
        return Ok(SearchArticlesResponse {
            results: merge_article_candidates(fts_results, Vec::new(), limit),
        });
    }

    let mut seen_versions = HashSet::new();
    let seed_versions = fts_results
        .iter()
        .filter(|result| seen_versions.insert(result.version_id.clone()))
        .map(|result| result.version_id.clone())
        .collect::<Vec<_>>();
    let like_results = search_articles_like_candidates(
        connection,
        &request,
        &search_terms,
        (!seed_versions.is_empty()).then_some(seed_versions.as_slice()),
        MAX_LIKE_CANDIDATES,
    )?;
    let results = merge_article_candidates(fts_results, like_results, limit);

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

fn search_articles_structured(
    connection: &rusqlite::Connection,
    request: &SearchArticlesRequest,
    query: &StructuredArticleQuery,
    limit: i64,
) -> Result<Vec<ArticleSearchResult>, RetrievalError> {
    let article_numbers = expanded_article_numbers(query.article_number);
    let article_parameters = (0..article_numbers.len())
        .map(|index| format!(":structured_article_{index}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
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
            articles.article_order,
            documents.effectiveness_level
        FROM law_articles articles
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
        WHERE articles.article_number IN ({article_parameters})
          AND (:document_id IS NULL OR articles.document_id = :document_id)
          AND (
            :law_name IS NULL
            OR documents.title = :law_name
            OR EXISTS (
              SELECT 1 FROM law_aliases exact_aliases
              WHERE exact_aliases.document_id = documents.id
                AND exact_aliases.normalized_alias = :law_name
            )
            OR (
              NOT EXISTS (
                SELECT 1 FROM law_aliases global_exact_aliases
                WHERE global_exact_aliases.normalized_alias = :law_name
              )
              AND (
                documents.title LIKE :law_like ESCAPE '\\'
                OR EXISTS (
                  SELECT 1 FROM law_aliases partial_aliases
                  WHERE partial_aliases.document_id = documents.id
                    AND partial_aliases.alias LIKE :law_like ESCAPE '\\'
                )
              )
            )
          )
          AND (
            :case_date IS NULL
            OR (
              versions.effective_from <= :case_date
              AND NOT (
                versions.status = 'repealed'
                AND versions.effective_to IS NULL
              )
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
            )
          )
        ORDER BY
          CASE documents.effectiveness_level
            WHEN 'constitution' THEN 0
            WHEN 'national_law' THEN 1
            WHEN 'administrative_regulation' THEN 2
            WHEN 'supervision_regulation' THEN 2
            WHEN 'judicial_interpretation' THEN 3
            WHEN 'department_rule' THEN 4
            WHEN 'autonomous_regulation' THEN 5
            WHEN 'special_zone_regulation' THEN 5
            WHEN 'local_regulation' THEN 6
            WHEN 'local_government_rule' THEN 7
            ELSE 8
          END,
          CASE WHEN versions.status = 'in_force' THEN 0 ELSE 1 END,
          documents.title ASC,
          articles.article_order ASC,
          articles.id ASC
        LIMIT :limit
        "
    );

    let mut parameters = article_numbers
        .into_iter()
        .enumerate()
        .map(|(index, article_number)| {
            (
                format!(":structured_article_{index}"),
                Value::Text(article_number),
            )
        })
        .collect::<Vec<_>>();
    parameters.push((
        ":document_id".to_owned(),
        request
            .document_id
            .clone()
            .map(Value::Text)
            .unwrap_or(Value::Null),
    ));
    parameters.push((
        ":law_name".to_owned(),
        query
            .law_name
            .clone()
            .map(Value::Text)
            .unwrap_or(Value::Null),
    ));
    parameters.push((
        ":law_like".to_owned(),
        query
            .law_name
            .as_deref()
            .map(like_pattern)
            .map(Value::Text)
            .unwrap_or(Value::Null),
    ));
    parameters.push((
        ":case_date".to_owned(),
        request
            .case_date
            .clone()
            .map(Value::Text)
            .unwrap_or(Value::Null),
    ));
    parameters.push((":limit".to_owned(), Value::Integer(limit)));
    let parameter_refs = named_parameter_refs(&parameters);
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(parameter_refs.as_slice(), |row| {
        let document_id: String = row.get(1)?;
        let version_id: String = row.get(2)?;
        let content: String = row.get(6)?;
        let article_order: i64 = row.get(11)?;
        let citation_id = row.get::<_, Option<String>>(7)?.unwrap_or_else(|| {
            generate_article_citation_id(&document_id, &version_id, &article_order.to_string())
        });
        let effectiveness_level: String = row.get(12)?;
        Ok(ArticleSearchResult {
            article_id: row.get(0)?,
            document_id,
            version_id,
            document_title: row.get(3)?,
            article_number: row.get(4)?,
            article_title: row.get(5)?,
            snippet: snippet_for("", &content),
            citation_id,
            effective_from: row.get(8)?,
            effective_to: row.get(9)?,
            version_status: row.get(10)?,
            score: 2_000_000.0 + effectiveness_level_score(&effectiveness_level),
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn search_articles_fts(
    connection: &rusqlite::Connection,
    request: &SearchArticlesRequest,
    query: &str,
    limit: i64,
) -> Result<Vec<ArticleSearchResult>, RetrievalError> {
    let search_terms = split_search_terms(query);
    if search_terms.is_empty() {
        return Ok(Vec::new());
    }
    let fts_query = quote_fts_terms(&search_terms);
    // The compact runtime database exposes `law_articles` as a compatibility
    // view that joins the deduplicated content table.  Candidate ranking does
    // not need article text, so use its metadata table directly when present;
    // the outer query still reads content for only the final bounded page.
    let ranked_article_source = if has_runtime_article_rows(connection)? {
        "law_article_rows"
    } else {
        "law_articles"
    };
    let sql = format!(
        "
        WITH ranked_matches AS MATERIALIZED (
          SELECT
            law_articles_fts.rowid AS article_rowid,
            bm25(law_articles_fts) AS rank
          FROM law_articles_fts
          JOIN {ranked_article_source} articles ON articles.rowid = law_articles_fts.rowid
          JOIN law_documents documents ON documents.id = articles.document_id
          JOIN law_versions versions ON versions.id = articles.version_id
          WHERE law_articles_fts MATCH :fts_query
            AND (:document_id IS NULL OR articles.document_id = :document_id)
            AND (
              :case_date IS NULL
              OR (
                versions.effective_from <= :case_date
                AND NOT (
                  versions.status = 'repealed'
                  AND versions.effective_to IS NULL
                )
                AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
              )
            )
          ORDER BY rank ASC, documents.title ASC, articles.article_order ASC
          LIMIT :limit
        )
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
            ranked_matches.rank,
            articles.article_order,
            documents.effectiveness_level
        FROM ranked_matches
        JOIN law_articles articles ON articles.rowid = ranked_matches.article_rowid
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
        ORDER BY ranked_matches.rank ASC, documents.title ASC, articles.article_order ASC
        LIMIT :limit
        "
    );
    let mut statement = connection.prepare(&sql)?;

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
            let document_title: String = row.get(3)?;
            let article_number: String = row.get(4)?;
            let article_title: Option<String> = row.get(5)?;
            let content: String = row.get(6)?;
            let article_order: i64 = row.get(12)?;
            let citation_id = row.get::<_, Option<String>>(7)?.unwrap_or_else(|| {
                generate_article_citation_id(&document_id, &version_id, &article_order.to_string())
            });
            let version_status: String = row.get(10)?;
            let effectiveness_level: String = row.get(13)?;
            let score = article_relevance_score(
                &document_title,
                &article_number,
                article_title.as_deref(),
                &content,
                &effectiveness_level,
                &version_status,
                &search_terms,
            );

            Ok(ArticleSearchResult {
                article_id: row.get(0)?,
                document_id,
                version_id,
                document_title,
                article_number,
                article_title,
                snippet: snippet_for_terms(&search_terms, &content),
                citation_id,
                effective_from: row.get(8)?,
                effective_to: row.get(9)?,
                version_status,
                score,
            })
        },
    )?;
    let results = rows.collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

fn has_runtime_article_rows(connection: &rusqlite::Connection) -> Result<bool, RetrievalError> {
    connection
        .query_row(
            "
            SELECT EXISTS(
              SELECT 1
              FROM sqlite_schema
              WHERE type = 'table' AND name = 'law_article_rows'
            )
            ",
            [],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn search_articles_like(
    connection: &rusqlite::Connection,
    request: &SearchArticlesRequest,
    query: &str,
    limit: i64,
) -> Result<Vec<ArticleSearchResult>, RetrievalError> {
    let search_terms = split_search_terms(query);
    if search_terms.is_empty() {
        return search_articles_like_empty(connection, request, limit);
    }
    let candidates = search_articles_like_candidates(
        connection,
        request,
        &search_terms,
        None,
        MAX_LIKE_CANDIDATES,
    )?;
    Ok(merge_article_candidates(candidates, Vec::new(), limit))
}

fn search_articles_like_empty(
    connection: &rusqlite::Connection,
    request: &SearchArticlesRequest,
    limit: i64,
) -> Result<Vec<ArticleSearchResult>, RetrievalError> {
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
            articles.article_order
        FROM law_articles articles
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
        WHERE (:document_id IS NULL OR articles.document_id = :document_id)
          AND (
            :case_date IS NULL
            OR (
              versions.effective_from <= :case_date
              AND NOT (
                versions.status = 'repealed'
                AND versions.effective_to IS NULL
              )
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
            )
          )
        ORDER BY documents.title ASC, articles.article_order ASC, articles.id ASC
        LIMIT :limit
        ",
    )?;

    let rows = statement.query_map(
        named_params! {
            ":document_id": request.document_id.as_deref(),
            ":case_date": request.case_date.as_deref(),
            ":limit": limit,
        },
        |row| {
            let document_id: String = row.get(1)?;
            let version_id: String = row.get(2)?;
            let content: String = row.get(6)?;
            let article_order: i64 = row.get(11)?;
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
                snippet: snippet_for("", &content),
                citation_id,
                effective_from: row.get(8)?,
                effective_to: row.get(9)?,
                version_status: row.get(10)?,
                score: 10.0,
            })
        },
    )?;
    let results = rows.collect::<Result<Vec<_>, _>>()?;

    Ok(results)
}

fn search_articles_like_candidates(
    connection: &rusqlite::Connection,
    request: &SearchArticlesRequest,
    search_terms: &[String],
    seed_versions: Option<&[String]>,
    limit: i64,
) -> Result<Vec<ArticleSearchResult>, RetrievalError> {
    if search_terms.is_empty() {
        return search_articles_like_empty(connection, request, limit);
    }

    let match_expressions = (0..search_terms.len())
        .map(|index| article_term_match_expression(&format!(":like_{index}")))
        .collect::<Vec<_>>();
    let match_count_expression = match_expressions
        .iter()
        .map(|expression| format!("CASE WHEN ({expression}) THEN 1 ELSE 0 END"))
        .collect::<Vec<_>>()
        .join(" + ");
    let any_match_expression = match_expressions
        .iter()
        .map(|expression| format!("({expression})"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let seed_filter = seed_versions
        .filter(|versions| !versions.is_empty())
        .map(|versions| {
            let parameters = (0..versions.len())
                .map(|index| format!(":seed_version_{index}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("AND articles.version_id IN ({parameters})")
        })
        .unwrap_or_default();
    let sql = format!(
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
            ({match_count_expression}) AS matched_terms,
            articles.article_order,
            documents.effectiveness_level
        FROM law_articles articles
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        LEFT JOIN citation_metadata ON citation_metadata.article_id = articles.id
        WHERE ({any_match_expression})
          {seed_filter}
          AND (:document_id IS NULL OR articles.document_id = :document_id)
          AND (
            :case_date IS NULL
            OR (
              versions.effective_from <= :case_date
              AND NOT (
                versions.status = 'repealed'
                AND versions.effective_to IS NULL
              )
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
            )
          )
        ORDER BY
          matched_terms DESC,
          CASE documents.effectiveness_level
            WHEN 'constitution' THEN 0
            WHEN 'national_law' THEN 1
            WHEN 'administrative_regulation' THEN 2
            WHEN 'supervision_regulation' THEN 2
            WHEN 'judicial_interpretation' THEN 3
            WHEN 'department_rule' THEN 4
            WHEN 'autonomous_regulation' THEN 5
            WHEN 'special_zone_regulation' THEN 5
            WHEN 'local_regulation' THEN 6
            WHEN 'local_government_rule' THEN 7
            ELSE 8
          END,
          CASE WHEN versions.status = 'in_force' THEN 0 ELSE 1 END,
          documents.title ASC,
          articles.article_order ASC,
          articles.id ASC
        LIMIT :limit
        "
    );

    let mut parameters = search_terms
        .iter()
        .enumerate()
        .map(|(index, term)| (format!(":like_{index}"), Value::Text(like_pattern(term))))
        .collect::<Vec<_>>();
    if let Some(seed_versions) = seed_versions {
        parameters.extend(seed_versions.iter().enumerate().map(|(index, version_id)| {
            (
                format!(":seed_version_{index}"),
                Value::Text(version_id.clone()),
            )
        }));
    }
    parameters.push((
        ":document_id".to_owned(),
        request
            .document_id
            .clone()
            .map(Value::Text)
            .unwrap_or(Value::Null),
    ));
    parameters.push((
        ":case_date".to_owned(),
        request
            .case_date
            .clone()
            .map(Value::Text)
            .unwrap_or(Value::Null),
    ));
    parameters.push((":limit".to_owned(), Value::Integer(limit)));
    let parameter_refs = named_parameter_refs(&parameters);
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(parameter_refs.as_slice(), |row| {
        let document_id: String = row.get(1)?;
        let version_id: String = row.get(2)?;
        let document_title: String = row.get(3)?;
        let article_number: String = row.get(4)?;
        let article_title: Option<String> = row.get(5)?;
        let content: String = row.get(6)?;
        let article_order: i64 = row.get(12)?;
        let citation_id = row.get::<_, Option<String>>(7)?.unwrap_or_else(|| {
            generate_article_citation_id(&document_id, &version_id, &article_order.to_string())
        });
        let version_status: String = row.get(10)?;
        let effectiveness_level: String = row.get(13)?;
        let score = article_relevance_score(
            &document_title,
            &article_number,
            article_title.as_deref(),
            &content,
            &effectiveness_level,
            &version_status,
            search_terms,
        );

        Ok(ArticleSearchResult {
            article_id: row.get(0)?,
            document_id,
            version_id,
            document_title,
            article_number,
            article_title,
            snippet: snippet_for_terms(search_terms, &content),
            citation_id,
            effective_from: row.get(8)?,
            effective_to: row.get(9)?,
            version_status,
            score,
        })
    })?;

    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
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

fn named_parameter_refs(parameters: &[(String, Value)]) -> Vec<(&str, &dyn ToSql)> {
    parameters
        .iter()
        .map(|(name, value)| (name.as_str(), value as &dyn ToSql))
        .collect()
}

fn article_term_match_expression(parameter: &str) -> String {
    format!(
        "documents.title LIKE {parameter} ESCAPE '\\'
         OR articles.article_number LIKE {parameter} ESCAPE '\\'
         OR COALESCE(articles.title, '') LIKE {parameter} ESCAPE '\\'
         OR articles.content LIKE {parameter} ESCAPE '\\'"
    )
}

fn requires_bounded_like_expansion(search_terms: &[String]) -> bool {
    search_terms.len() > 1
        || search_terms
            .iter()
            .any(|term| term.chars().any(is_cjk_ideograph))
}

fn should_expand_bounded_like(
    search_terms: &[String],
    may_expand_like: bool,
    fts_result_count: usize,
    limit: i64,
) -> bool {
    // Two-character CJK words such as “合同” and “保护” have broad saturated
    // FTS result sets; a full substring pass adds little recall and dominates
    // latency. Four-character legal concepts such as “违约责任” are much more
    // selective, while FTS ranking can still bury their substantive provision
    // below heading/definition matches, so retain the bounded LIKE supplement.
    let selective_cjk_compound = search_terms.iter().any(|term| {
        let characters = term.chars().collect::<Vec<_>>();
        characters.len() >= 4 && characters.iter().copied().all(is_cjk_ideograph)
    });
    may_expand_like
        && (search_terms.len() > 1
            || selective_cjk_compound
            || fts_result_count < limit.max(0) as usize)
}

fn is_cjk_ideograph(character: char) -> bool {
    matches!(
        character as u32,
        0x3400..=0x4dbf
            | 0x4e00..=0x9fff
            | 0xf900..=0xfaff
            | 0x20000..=0x2fa1f
            | 0x30000..=0x323af
    )
}

fn expanded_fts_seed_limit(limit: i64) -> i64 {
    limit
        .saturating_mul(8)
        .clamp(MIN_FTS_SEED_LIMIT, MAX_FTS_SEED_LIMIT)
}

fn merge_article_candidates(
    primary: Vec<ArticleSearchResult>,
    secondary: Vec<ArticleSearchResult>,
    limit: i64,
) -> Vec<ArticleSearchResult> {
    let mut by_article = HashMap::new();
    for candidate in primary.into_iter().chain(secondary) {
        match by_article.entry(candidate.article_id.clone()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::hash_map::Entry::Occupied(mut entry)
                if candidate.score > entry.get().score =>
            {
                entry.insert(candidate);
            }
            std::collections::hash_map::Entry::Occupied(_) => {}
        }
    }

    let mut results = by_article.into_values().collect::<Vec<_>>();
    results.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.document_title.cmp(&right.document_title))
            .then_with(|| left.article_number.cmp(&right.article_number))
            .then_with(|| left.article_id.cmp(&right.article_id))
    });
    results.truncate(limit.max(0) as usize);
    results
}

fn article_relevance_score(
    document_title: &str,
    article_number: &str,
    article_title: Option<&str>,
    content: &str,
    effectiveness_level: &str,
    version_status: &str,
    search_terms: &[String],
) -> f64 {
    let mut matched_terms = 0_u32;
    let mut substantive_matches = 0_u32;
    let mut article_title_matches = 0_u32;

    for term in search_terms {
        let title_matches = article_title.is_some_and(|title| title.contains(term));
        let content_matches = content.contains(term);
        if document_title.contains(term)
            || article_number.contains(term)
            || title_matches
            || content_matches
        {
            matched_terms += 1;
        }
        if content_matches && term_has_substantive_content_match(content, term) {
            substantive_matches += 1;
        }
        if title_matches {
            article_title_matches += 1;
        }
    }

    f64::from(matched_terms) * TERM_MATCH_SCORE
        + f64::from(substantive_matches) * SUBSTANTIVE_MATCH_SCORE
        + f64::from(article_title_matches) * ARTICLE_TITLE_MATCH_SCORE
        + effectiveness_level_score(effectiveness_level)
        + if version_status == "in_force" {
            CURRENT_VERSION_SCORE
        } else {
            0.0
        }
}

fn effectiveness_level_score(effectiveness_level: &str) -> f64 {
    match effectiveness_level {
        "constitution" => 1_200.0,
        "national_law" => 1_000.0,
        "administrative_regulation" | "supervision_regulation" => 800.0,
        "judicial_interpretation" => 700.0,
        "department_rule" => 500.0,
        "autonomous_regulation" | "special_zone_regulation" => 350.0,
        "local_regulation" => 250.0,
        "local_government_rule" => 150.0,
        _ => 0.0,
    }
}

fn term_has_substantive_content_match(content: &str, term: &str) -> bool {
    content
        .lines()
        .any(|line| line.contains(term) && !looks_like_embedded_heading(line))
}

fn looks_like_embedded_heading(line: &str) -> bool {
    let compact = line.trim();
    compact.chars().count() <= 48
        && compact.starts_with('第')
        && ['编', '篇', '章', '节']
            .into_iter()
            .any(|marker| compact.contains(marker))
}

fn parse_structured_article_query(query: &str) -> Option<StructuredArticleQuery> {
    let (marker_start, article_number) = find_article_marker(query)?;
    let mut law_name = query[..marker_start].trim().trim_matches([
        '《', '》', '，', ',', '。', '；', ';', '：', ':', '、', '（', '）', '(', ')',
    ]);
    for prefix in [
        "请查询",
        "请检索",
        "请查",
        "查询",
        "检索",
        "依据",
        "根据",
        "参照",
        "适用",
    ] {
        if let Some(stripped) = law_name.strip_prefix(prefix) {
            law_name = stripped.trim();
            break;
        }
    }
    Some(StructuredArticleQuery {
        law_name: (!law_name.is_empty()).then(|| law_name.to_owned()),
        article_number,
    })
}

fn find_article_marker(value: &str) -> Option<(usize, ParsedArticleNumber)> {
    let mut cursor = 0;
    while cursor < value.len() {
        let character = value[cursor..].chars().next()?;
        if character == '第' {
            let ordinal_start = cursor + character.len_utf8();
            if let Some(relative_end) = value[ordinal_start..].find('条') {
                let base_end = ordinal_start + relative_end + '条'.len_utf8();
                let end = extend_through_subarticle_ordinal(value, base_end);
                if let Some(article_number) = parse_article_number(&value[cursor..end]) {
                    return Some((cursor, article_number));
                }
            }
        }
        if character.is_ascii_digit()
            && !value[..cursor]
                .chars()
                .next_back()
                .is_some_and(|previous| previous.is_ascii_alphanumeric())
        {
            let mut digits_end = cursor;
            while digits_end < value.len() {
                let next = value[digits_end..].chars().next()?;
                if !next.is_ascii_digit() {
                    break;
                }
                digits_end += next.len_utf8();
            }
            if value[digits_end..].starts_with('条') {
                let base_end = digits_end + '条'.len_utf8();
                let end = extend_through_subarticle_ordinal(value, base_end);
                if let Some(article_number) = parse_article_number(&value[cursor..end]) {
                    return Some((cursor, article_number));
                }
            }
        }
        cursor += character.len_utf8();
    }
    None
}

fn extend_through_subarticle_ordinal(value: &str, base_end: usize) -> usize {
    if !value[base_end..].starts_with('之') {
        return base_end;
    }
    let mut cursor = base_end + '之'.len_utf8();
    while cursor < value.len() {
        let character = value[cursor..]
            .chars()
            .next()
            .expect("sub-article cursor remains in bounds");
        if !(character.is_ascii_digit()
            || chinese_digit(character).is_some()
            || matches!(character, '十' | '百' | '千' | '万'))
        {
            break;
        }
        cursor += character.len_utf8();
    }
    cursor
}

fn parse_article_number(value: &str) -> Option<ParsedArticleNumber> {
    let value = value.trim();
    let (base, subarticle) = if let Some((base, subarticle)) = value.split_once('之') {
        if subarticle.contains('之') || !base.ends_with('条') {
            return None;
        }
        (base, Some(parse_ordinal_component(subarticle)?))
    } else {
        (value, None)
    };
    Some(ParsedArticleNumber {
        base: parse_ordinal_component(base)?,
        subarticle,
    })
}

fn parse_ordinal_component(value: &str) -> Option<u32> {
    let mut ordinal = value.trim();
    if let Some(stripped) = ordinal.strip_prefix('第') {
        ordinal = stripped;
    }
    if let Some(stripped) = ordinal.strip_suffix('条') {
        ordinal = stripped;
    }
    if ordinal.is_empty() || ordinal.chars().any(char::is_whitespace) {
        return None;
    }
    let parsed = if ordinal.chars().all(|character| character.is_ascii_digit()) {
        ordinal.parse::<u32>().ok()
    } else {
        parse_chinese_ordinal(ordinal)
    }?;
    (1..=MAX_ARTICLE_ORDINAL)
        .contains(&parsed)
        .then_some(parsed)
}

fn parse_chinese_ordinal(value: &str) -> Option<u32> {
    let mut sections = value.split('万');
    let first = sections.next()?;
    let second = sections.next();
    if sections.next().is_some() {
        return None;
    }
    let value = if let Some(lower) = second {
        if first.is_empty() {
            return None;
        }
        let upper = parse_chinese_under_ten_thousand(first)?;
        let lower = if lower.is_empty() {
            0
        } else {
            parse_chinese_under_ten_thousand(lower)?
        };
        upper.checked_mul(10_000)?.checked_add(lower)?
    } else {
        parse_chinese_under_ten_thousand(first)?
    };
    (value > 0).then_some(value)
}

fn parse_chinese_under_ten_thousand(value: &str) -> Option<u32> {
    if value.is_empty() {
        return None;
    }
    if value
        .chars()
        .all(|character| chinese_digit(character).is_some())
    {
        return value.chars().try_fold(0_u32, |accumulator, character| {
            accumulator
                .checked_mul(10)?
                .checked_add(chinese_digit(character)?)
        });
    }
    let mut total = 0_u32;
    let mut pending_digit = None;
    let mut previous_unit = 10_000_u32;
    let mut saw_unit = false;
    for character in value.chars() {
        if let Some(digit) = chinese_digit(character) {
            if digit == 0 {
                pending_digit = None;
            } else if pending_digit.replace(digit).is_some() {
                return None;
            }
            continue;
        }
        let unit = match character {
            '十' => 10,
            '百' => 100,
            '千' => 1_000,
            _ => return None,
        };
        if unit >= previous_unit {
            return None;
        }
        total = total.checked_add(pending_digit.take().unwrap_or(1).checked_mul(unit)?)?;
        previous_unit = unit;
        saw_unit = true;
    }
    if !saw_unit {
        return None;
    }
    total.checked_add(pending_digit.unwrap_or(0))
}

fn chinese_digit(character: char) -> Option<u32> {
    match character {
        '零' | '〇' => Some(0),
        '一' => Some(1),
        '二' | '两' => Some(2),
        '三' => Some(3),
        '四' => Some(4),
        '五' => Some(5),
        '六' => Some(6),
        '七' => Some(7),
        '八' => Some(8),
        '九' => Some(9),
        _ => None,
    }
}

fn integer_to_chinese(value: u32) -> String {
    const DIGITS: [&str; 10] = ["零", "一", "二", "三", "四", "五", "六", "七", "八", "九"];
    const UNITS: [&str; 5] = ["", "十", "百", "千", "万"];
    const POWERS: [u32; 5] = [1, 10, 100, 1_000, 10_000];
    let mut output = String::new();
    let mut started = false;
    let mut zero_pending = false;
    for position in (0..POWERS.len()).rev() {
        let digit = (value / POWERS[position]) % 10;
        if digit == 0 {
            if started && !value.is_multiple_of(POWERS[position]) {
                zero_pending = true;
            }
            continue;
        }
        if zero_pending {
            output.push_str(DIGITS[0]);
            zero_pending = false;
        }
        if !(digit == 1 && position == 1 && !started) {
            output.push_str(DIGITS[digit as usize]);
        }
        output.push_str(UNITS[position]);
        started = true;
    }
    output
}

fn expanded_article_numbers(value: ParsedArticleNumber) -> Vec<String> {
    let base_variants = [
        format!("第{}条", integer_to_chinese(value.base)),
        format!("第{}条", value.base),
        format!("{}条", value.base),
    ];
    let mut expanded = Vec::new();
    if let Some(subarticle) = value.subarticle {
        let subarticle_variants = [integer_to_chinese(subarticle), subarticle.to_string()];
        for base in base_variants {
            for subarticle in &subarticle_variants {
                expanded.push(format!("{base}之{subarticle}"));
            }
        }
    } else {
        expanded.extend(base_variants);
        expanded.push(value.base.to_string());
    }
    expanded.sort();
    expanded.dedup();
    expanded
}

fn split_search_terms(query: &str) -> Vec<String> {
    let raw_terms = query
        .split(|character: char| {
            character.is_whitespace()
                || matches!(character, ',' | '，' | '、' | ';' | '；' | '|' | '｜')
        })
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .collect::<Vec<_>>();
    if raw_terms.len() == 1 {
        let term = raw_terms[0]
            .trim_matches(['。', '？', '?', '！', '!', '，', ','])
            .trim_start_matches("请问");
        if term.chars().all(is_cjk_ideograph) {
            let cue_index = [
                "如何",
                "怎么",
                "怎样",
                "是否",
                "能否",
                "可否",
                "为什么",
                "为何",
            ]
            .into_iter()
            .filter_map(|cue| term.find(cue))
            .min();
            let core = cue_index.map(|index| &term[..index]).unwrap_or(term).trim();
            let characters = core.chars().collect::<Vec<_>>();
            if characters.len() > 4 {
                return characters
                    .windows(4)
                    .map(|window| window.iter().collect::<String>())
                    .take(MAX_SEARCH_TERMS)
                    .collect();
            }
        }
    }

    let mut seen = HashSet::new();
    raw_terms
        .into_iter()
        .filter_map(|term| {
            if !seen.insert(term.to_lowercase()) {
                None
            } else {
                Some(term.to_owned())
            }
        })
        .take(MAX_SEARCH_TERMS)
        .collect()
}

fn quote_fts_terms(terms: &[String]) -> String {
    terms
        .iter()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn snippet_for_terms(terms: &[String], content: &str) -> String {
    let query = terms
        .iter()
        .filter_map(|term| content.find(term).map(|index| (index, term.as_str())))
        .min_by_key(|(index, _)| *index)
        .map(|(_, term)| term)
        .unwrap_or_default();
    snippet_for(query, content)
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
    fn gets_law_document_by_exact_id_without_title_search() {
        let connection = fixture_connection();
        let response = get_law_document(
            &connection,
            GetLawDocumentRequest {
                document_id: "cn-civil-code".to_owned(),
            },
        )
        .expect("exact document lookup succeeds");
        let document = response.document.expect("document exists");

        assert_eq!(document.document_id, "cn-civil-code");
        assert_eq!(
            document.current_version_id.as_deref(),
            Some("cn-civil-code-20210101")
        );

        let search = search_laws(
            &connection,
            SearchLawsRequest {
                query: "cn-civil-code".to_owned(),
                limit: Some(50),
            },
        )
        .expect("title search succeeds");
        assert!(
            search.results.is_empty(),
            "exact ID lookup must not rely on title search"
        );
    }

    #[test]
    fn exact_law_document_lookup_returns_none_for_unknown_id() {
        let connection = fixture_connection();
        let response = get_law_document(
            &connection,
            GetLawDocumentRequest {
                document_id: "missing-document".to_owned(),
            },
        )
        .expect("unknown lookup succeeds");

        assert!(response.document.is_none());
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
    fn multi_keyword_article_search_uses_literal_or_terms_in_fts_and_like() {
        let connection = fixture_connection();
        let request = SearchArticlesRequest {
            query: "违约责任、继续履行、赔偿损失".to_owned(),
            document_id: None,
            case_date: Some("2024-06-01".to_owned()),
            limit: Some(10),
        };

        let response = search_articles(&connection, request.clone()).expect("FTS search succeeds");
        let like_results = search_articles_like(&connection, &request, &request.query, 10)
            .expect("multi-term LIKE fallback succeeds");

        assert_eq!(
            split_search_terms(&request.query),
            vec!["违约责任", "继续履行", "赔偿损失"]
        );
        assert!(response
            .results
            .iter()
            .any(|result| result.article_id == "cn-civil-code-20210101-577"));
        assert!(like_results
            .iter()
            .any(|result| result.article_id == "cn-civil-code-20210101-577"));
        assert!(like_results
            .windows(2)
            .all(|pair| pair[0].score >= pair[1].score));
    }

    #[test]
    fn saturated_single_cjk_fts_page_skips_expensive_like_expansion() {
        let single = vec!["保护".to_owned()];
        let multiple = vec!["违约责任".to_owned(), "继续履行".to_owned()];

        assert!(!should_expand_bounded_like(&single, true, 20, 20));
        assert!(should_expand_bounded_like(&single, true, 19, 20));
        assert!(should_expand_bounded_like(&multiple, true, 20, 20));
        assert!(!should_expand_bounded_like(&single, false, 0, 20));
    }

    #[test]
    fn saturated_selective_cjk_compound_keeps_bounded_recall_expansion() {
        let selective_compound = vec!["违约责任".to_owned()];

        assert!(should_expand_bounded_like(
            &selective_compound,
            true,
            20,
            20
        ));
    }

    #[test]
    fn bounded_chinese_expansion_prefers_substantive_article_over_embedded_heading() {
        let connection = fixture_connection();
        connection
            .execute(
                "
                INSERT INTO law_articles (
                  id, document_id, version_id, article_number, article_order, title, content,
                  updated_on
                ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7)
                ",
                rusqlite::params![
                    "cn-civil-code-20210101-576-heading",
                    "cn-civil-code",
                    "cn-civil-code-20210101",
                    "第五百七十六条",
                    576,
                    "债权债务终止。\n第八章 违约责任",
                    "2026-07-15"
                ],
            )
            .expect("embedded heading fixture inserts");
        connection
            .execute(
                "
                INSERT INTO law_articles_fts (
                  rowid, article_id, document_id, version_id, document_title,
                  article_number, article_title, content
                )
                SELECT articles.rowid, articles.id, articles.document_id, articles.version_id,
                       documents.title, articles.article_number, articles.title, articles.content
                FROM law_articles articles
                JOIN law_documents documents ON documents.id = articles.document_id
                WHERE articles.id = ?1
                ",
                ["cn-civil-code-20210101-576-heading"],
            )
            .expect("embedded heading FTS fixture inserts");

        for query in ["违约责任", "违约责任、继续履行、赔偿损失"] {
            let response = search_articles(
                &connection,
                SearchArticlesRequest {
                    query: query.to_owned(),
                    document_id: None,
                    case_date: None,
                    limit: Some(10),
                },
            )
            .expect("bounded Chinese search succeeds");
            let substantive_position = response
                .results
                .iter()
                .position(|result| result.article_id == "cn-civil-code-20210101-577")
                .expect("substantive article 577 is recalled");
            let heading_position = response
                .results
                .iter()
                .position(|result| result.article_id == "cn-civil-code-20210101-576-heading")
                .expect("heading-only seed remains reviewable");

            assert!(substantive_position < heading_position, "query: {query}");
        }
    }

    #[test]
    fn structured_law_article_queries_bypass_broad_candidate_truncation() {
        let connection = fixture_connection();
        for query in ["民法典第577条", "民法典 第577条"] {
            let response = search_articles(
                &connection,
                SearchArticlesRequest {
                    query: query.to_owned(),
                    document_id: None,
                    case_date: Some("2024-06-01".to_owned()),
                    limit: Some(10),
                },
            )
            .expect("structured article search succeeds");
            assert_eq!(response.results.len(), 1, "query={query}");
            assert_eq!(response.results[0].document_id, "cn-civil-code");
            assert_eq!(response.results[0].article_number, "第五百七十七条");
        }
    }

    #[test]
    fn structured_subarticle_search_is_exact_and_never_falls_back_to_base_article() {
        let connection = fixture_connection();
        connection
            .execute_batch(
                "
                INSERT INTO law_articles (
                  id, document_id, version_id, article_number, article_order, title, content,
                  updated_on
                ) VALUES (
                  'cn-civil-code-20210101-120-1', 'cn-civil-code',
                  'cn-civil-code-20210101', '第120条之一', 120001,
                  '增设条文测试', '增设条文内容。', '2026-07-15'
                );
                INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label)
                VALUES (
                  'cite-civil-code-120-1', 'cn-civil-code-20210101-120-1',
                  'law:cn-civil-code:cn-civil-code-20210101:art:120-1',
                  '《中华人民共和国民法典》第120条之一'
                );
                ",
            )
            .expect("sub-article fixture inserts");

        let found = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "民法典第120条之1".to_owned(),
                document_id: None,
                case_date: Some("2024-06-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("sub-article search succeeds");
        assert_eq!(found.results.len(), 1);
        assert_eq!(found.results[0].article_number, "第120条之一");

        let nonexistent = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "民法典第577条之99999".to_owned(),
                document_id: None,
                case_date: Some("2024-06-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("nonexistent sub-article search is safe");
        assert!(nonexistent.results.is_empty());
    }

    #[test]
    fn continuous_natural_chinese_question_recalls_civil_code_article() {
        let connection = fixture_connection();
        let response = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "合同违约责任如何承担".to_owned(),
                document_id: None,
                case_date: Some("2024-06-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("continuous natural-language search succeeds");
        assert!(response
            .results
            .iter()
            .any(|result| result.article_id == "cn-civil-code-20210101-577"));
        assert!(!response
            .results
            .iter()
            .any(|result| result.document_id == "cn-contract-law-1999"));
    }

    #[test]
    fn single_term_search_and_fts_literal_escaping_remain_stable() {
        let connection = fixture_connection();
        let single = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "违约责任".to_owned(),
                document_id: None,
                case_date: Some("2024-06-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("single-term search succeeds");
        let injection_request = SearchArticlesRequest {
            query: "违约责任\" OR 赔偿损失*".to_owned(),
            document_id: None,
            case_date: Some("2024-06-01".to_owned()),
            limit: Some(10),
        };
        let injection_shaped = search_articles(&connection, injection_request.clone())
            .expect("operator-shaped text is handled safely");
        let direct_fts = search_articles_fts(
            &connection,
            &injection_request,
            &injection_request.query,
            10,
        )
        .expect("operator-shaped text remains a valid literal FTS expression");

        assert!(single
            .results
            .iter()
            .any(|result| result.article_id == "cn-civil-code-20210101-577"));
        assert!(injection_shaped.results.len() <= 10);
        assert!(direct_fts.len() <= 10);
        assert_eq!(
            quote_fts_terms(&["违约责任\"".to_owned(), "OR".to_owned()]),
            "\"违约责任\"\"\" OR \"OR\""
        );
    }

    #[test]
    fn materialized_fts_candidate_query_matches_direct_join_semantics() {
        let connection = fixture_connection();
        let request = SearchArticlesRequest {
            query: "违约责任 继续履行".to_owned(),
            document_id: None,
            case_date: Some("2024-06-01".to_owned()),
            limit: Some(10),
        };
        let optimized = search_articles_fts(&connection, &request, &request.query, 10)
            .expect("materialized query succeeds")
            .into_iter()
            .map(|result| result.article_id)
            .collect::<Vec<_>>();
        let fts_query = quote_fts_terms(&split_search_terms(&request.query));
        let mut statement = connection
            .prepare(
                "
                SELECT articles.id
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
                      AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)
                      AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
                    )
                  )
                ORDER BY bm25(law_articles_fts) ASC, documents.title ASC, articles.article_order ASC
                LIMIT :limit
                ",
            )
            .expect("reference query prepares");
        let reference = statement
            .query_map(
                named_params! {
                    ":fts_query": fts_query,
                    ":document_id": request.document_id.as_deref(),
                    ":case_date": request.case_date.as_deref(),
                    ":limit": 10,
                },
                |row| row.get::<_, String>(0),
            )
            .expect("reference query runs")
            .collect::<Result<Vec<_>, _>>()
            .expect("reference rows decode");

        assert_eq!(optimized, reference);
    }

    #[test]
    fn dated_search_fails_closed_for_repealed_version_with_unknown_end_date() {
        let connection = fixture_connection();
        connection
            .execute(
                "UPDATE law_versions SET effective_to = NULL WHERE id = ?1",
                ["cn-contract-law-19991001"],
            )
            .expect("fixture terminal date is removed");

        let dated = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "违约责任".to_owned(),
                document_id: None,
                case_date: Some("2019-01-01".to_owned()),
                limit: Some(10),
            },
        )
        .expect("dated search succeeds");
        let undated = search_articles(
            &connection,
            SearchArticlesRequest {
                query: "违约责任".to_owned(),
                document_id: None,
                case_date: None,
                limit: Some(10),
            },
        )
        .expect("undated review search succeeds");

        assert!(!dated
            .results
            .iter()
            .any(|result| result.version_id == "cn-contract-law-19991001"));
        assert!(undated
            .results
            .iter()
            .any(|result| result.version_id == "cn-contract-law-19991001"));
    }

    #[test]
    fn law_search_does_not_present_repealed_unknown_end_as_current() {
        let connection = fixture_connection();
        connection
            .execute(
                "UPDATE law_versions SET effective_to = NULL WHERE id = ?1",
                ["cn-contract-law-19991001"],
            )
            .expect("fixture terminal date is removed");

        let response = search_laws(
            &connection,
            SearchLawsRequest {
                query: "合同法".to_owned(),
                limit: Some(10),
            },
        )
        .expect("law search succeeds");
        let contract_law = response
            .results
            .iter()
            .find(|result| result.document_id == "cn-contract-law-1999")
            .expect("contract law is returned for reference");

        assert_eq!(contract_law.current_version_id, None);
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
