//! Source-bounded citation parsing, context assembly, and validation.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt::{self, Display},
};

use domain::qa::{
    CitationInvalidReason, CitationStatus, CitationValidationReport, LegalAnswerCandidatesRequest,
    LegalAnswerContext, LegalSource, ParsedCitation, StructuredLegalQuery, ValidatedCitation,
};
use rusqlite::{types::Value, OptionalExtension, ToSql};

const DEFAULT_SOURCE_LIMIT: u32 = 8;
const MAX_SOURCE_LIMIT: u32 = 16;
const MAX_STRUCTURED_FILTER_VALUES: usize = 16;
const MAX_CONTEXT_CHARS_PER_SOURCE: usize = 1600;
const MAX_SOURCE_SNIPPET_CHARS: usize = 180;
const MIN_FTS_SEED_LIMIT: i64 = 64;
const MAX_FTS_SEED_LIMIT: i64 = 128;
const MAX_LIKE_CANDIDATES: i64 = 512;
const MAX_ARTICLE_ORDINAL: u32 = 99_999;

#[derive(Clone, Debug, Eq, PartialEq)]
struct LawArticlePair {
    law_name: String,
    article_number: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArticleOccurrence {
    article_number: String,
    start: usize,
    bare_ascii: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum InferredPairing {
    None,
    Paired(Vec<LawArticlePair>),
    Ambiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedArticleNumber {
    base: u32,
    subarticle: Option<u32>,
}

#[derive(Debug)]
pub enum CitationError {
    InvalidRequest(String),
    Sqlite(rusqlite::Error),
}

impl Display for CitationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid citation request: {message}")
            }
            Self::Sqlite(error) => write!(formatter, "citation database error: {error}"),
        }
    }
}

impl Error for CitationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRequest(_) => None,
            Self::Sqlite(error) => Some(error),
        }
    }
}

impl From<rusqlite::Error> for CitationError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub fn build_legal_answer_context(
    connection: &rusqlite::Connection,
    request: &LegalAnswerCandidatesRequest,
) -> Result<LegalAnswerContext, CitationError> {
    ensure_valid_case_date(request.case_date.as_deref())?;
    let query = extract_structured_query(request);
    let mut warnings = Vec::new();
    let limit = bounded_limit(request.limit);
    let pairing = if request
        .law_name
        .as_deref()
        .and_then(trimmed_non_empty)
        .is_none()
        && request
            .article_number
            .as_deref()
            .and_then(trimmed_non_empty)
            .is_none()
    {
        inferred_pairing(&request.question, &query)
    } else {
        InferredPairing::None
    };

    let mut sources = if pairing == InferredPairing::Ambiguous {
        warnings.push("ambiguous_law_article_pairing".to_owned());
        Vec::new()
    } else {
        let retrieval_limit = match &pairing {
            InferredPairing::Paired(pairs) => limit
                .saturating_mul(i64::try_from(pairs.len()).unwrap_or(i64::MAX))
                .saturating_mul(2)
                .clamp(limit, MAX_LIKE_CANDIDATES),
            InferredPairing::None | InferredPairing::Ambiguous => limit,
        };
        let mut candidates =
            retrieve_context_sources(connection, &query, retrieval_limit, &mut warnings)?;
        if let InferredPairing::Paired(pairs) = &pairing {
            candidates = filter_sources_by_pairs(connection, candidates, pairs)?;
        }

        // A quoted title may be the name of a contract, book, or case rather
        // than a law.  Inferred titles are therefore relaxed only after a
        // strict zero-hit search and only when useful topic terms remain.
        // Explicit lawName values are never relaxed.
        if candidates.is_empty()
            && request
                .law_name
                .as_deref()
                .and_then(trimmed_non_empty)
                .is_none()
            && query.law_names.len() == 1
            && !query.keywords.is_empty()
            && pairing == InferredPairing::None
        {
            let mut relaxed_query = query.clone();
            relaxed_query.law_names.clear();
            let relaxed =
                retrieve_context_sources(connection, &relaxed_query, limit, &mut warnings)?;
            if !relaxed.is_empty() {
                warnings.push("inferred_law_name_filter_relaxed".to_owned());
                candidates = relaxed;
            }
        }
        candidates
    };
    sources.truncate(limit as usize);

    if has_unknown_ended_historical_candidate(connection, &query)? {
        warnings.push("historical_effective_to_unknown_excluded".to_owned());
    }
    if sources
        .iter()
        .any(|source| source.version_status == "repealed" && source.effective_to.is_none())
    {
        warnings.push("historical_effective_to_unknown_included_for_review".to_owned());
    }

    if sources.is_empty() {
        warnings.push("no_local_sources_found".to_owned());
    }

    let prompt = assemble_source_bounded_prompt(&query, &sources, &mut warnings);

    Ok(LegalAnswerContext {
        query,
        sources,
        prompt,
        warnings,
    })
}

fn retrieve_context_sources(
    connection: &rusqlite::Connection,
    query: &StructuredLegalQuery,
    limit: i64,
    warnings: &mut Vec<String>,
) -> Result<Vec<LegalSource>, CitationError> {
    let sources = if !query.keywords.is_empty()
        && !query.law_names.is_empty()
        && !query.article_numbers.is_empty()
    {
        // A precise law/article pair defines the candidate set.  Evaluate the
        // optional keywords against that small set instead of turning them
        // into a second hard SQL filter (and potentially losing the exact
        // provision because of wording differences).
        let mut relaxed_query = query.clone();
        relaxed_query.keywords.clear();
        let exact_candidates = search_sources_like(connection, &relaxed_query, limit)?;
        let mut keyword_matches = exact_candidates
            .iter()
            .filter(|source| keyword_match_count(source, query) > 0)
            .cloned()
            .collect::<Vec<_>>();
        if keyword_matches.is_empty() && !exact_candidates.is_empty() {
            warnings.push("keyword_search_relaxed_for_exact_filters".to_owned());
            exact_candidates
        } else {
            rank_sources_by_keywords(&mut keyword_matches, query);
            keyword_matches
        }
    } else {
        let search_terms = primary_search_terms(query);
        let expand_like = requires_bounded_like_expansion(&search_terms);
        let fts_limit = if expand_like {
            expanded_fts_seed_limit(limit)
        } else {
            limit
        };
        let fts_sources = search_sources_fts(connection, query, fts_limit)?;
        if !expand_like && !fts_sources.is_empty() {
            fts_sources
        } else {
            let seed_versions = fts_sources
                .iter()
                .map(|source| source.version_id.clone())
                .collect::<Vec<_>>();
            let like_sources = search_sources_like_candidates(
                connection,
                query,
                &search_terms,
                (!seed_versions.is_empty()).then_some(seed_versions.as_slice()),
                MAX_LIKE_CANDIDATES,
            )?;
            merge_and_rank_sources(connection, fts_sources, like_sources, &search_terms, limit)?
        }
    };
    Ok(sources)
}

pub fn extract_structured_query(request: &LegalAnswerCandidatesRequest) -> StructuredLegalQuery {
    let mut law_names = Vec::new();
    if let Some(law_name) = normalized_non_empty(request.law_name.as_deref()) {
        law_names.push(law_name);
    } else {
        law_names.extend(extract_quoted_law_names(&request.question));
    }
    dedup_preserve_order(&mut law_names);
    law_names.truncate(MAX_STRUCTURED_FILTER_VALUES);

    let mut article_numbers = Vec::new();
    if let Some(article_number) = normalized_non_empty(request.article_number.as_deref()) {
        article_numbers.push(normalize_article_filter_value(&article_number));
    } else {
        article_numbers.extend(extract_article_markers(&request.question));
        article_numbers.extend(
            extract_law_article_pairs(&request.question)
                .into_iter()
                .map(|pair| pair.article_number),
        );
    }
    dedup_preserve_order(&mut article_numbers);
    article_numbers.truncate(MAX_STRUCTURED_FILTER_VALUES);

    let mut keywords = request
        .keywords
        .iter()
        .filter_map(|keyword| normalized_non_empty(Some(keyword)))
        .collect::<Vec<_>>();
    if keywords.is_empty() {
        keywords.extend(extract_keywords(
            &request.question,
            &law_names,
            &article_numbers,
        ));
    }
    dedup_preserve_order(&mut keywords);
    keywords.truncate(8);

    let mut effectiveness_levels = request
        .effectiveness_levels
        .iter()
        .filter_map(|level| normalized_non_empty(Some(level)))
        .collect::<Vec<_>>();
    dedup_preserve_order(&mut effectiveness_levels);
    effectiveness_levels.truncate(MAX_STRUCTURED_FILTER_VALUES);

    StructuredLegalQuery {
        law_names,
        article_numbers,
        keywords,
        legal_issue: request.question.trim().to_owned(),
        case_date: normalized_non_empty(request.case_date.as_deref()),
        effectiveness_levels,
        include_expired: request.include_expired,
    }
}

pub fn assemble_source_bounded_prompt(
    query: &StructuredLegalQuery,
    sources: &[LegalSource],
    warnings: &mut Vec<String>,
) -> String {
    let mut prompt = String::new();
    prompt.push_str(
        "你只能依据下列本地法律来源回答。每个独立法律结论必须在该结论句末紧跟对应的 [SRC:...] 标记；同一来源可在多个结论后重复标记。\n",
    );
    prompt.push_str(
        "不得让一个标记覆盖以逗号、顿号、分号、冒号或并列连词连接的多个结论。例如同一法条支持三种责任时，应拆成三句，并在每句末重复该 [SRC:...]。\n",
    );
    prompt.push_str(
        "不得引用未列出的来源，不得编造 source id。输出前逐句自检；如果来源不足，直接说明无法由当前来源支持，不要补写无引用建议。\n\n",
    );
    prompt.push_str("用户问题：\n");
    prompt.push_str(&query.legal_issue);
    prompt.push_str("\n\n");

    if let Some(case_date) = &query.case_date {
        prompt.push_str("案件发生日期：");
        prompt.push_str(case_date);
        prompt.push_str("\n\n");
    }

    prompt.push_str("本地来源：\n");
    if sources.is_empty() {
        prompt.push_str("（无候选来源）\n");
        return prompt;
    }

    for (index, source) in sources.iter().enumerate() {
        let content = truncate_chars(&source.content, MAX_CONTEXT_CHARS_PER_SOURCE);
        if content.chars().count() < source.content.chars().count() {
            warnings.push(format!("source_truncated:{}", source.source_id));
        }

        prompt.push_str(&format!(
            "{}. [SRC:{}] {} {}，效力：{} 至 {}，版本状态：{}\n{}\n\n",
            index + 1,
            source.source_id,
            source.document_title,
            source.article_number,
            source.effective_from,
            effective_to_label(source),
            source.version_status,
            content
        ));
    }

    prompt
}

pub fn parse_source_markers(answer: &str) -> Vec<ParsedCitation> {
    let mut citations = Vec::new();
    let mut seen = HashSet::new();
    let mut offset = 0;

    while let Some(relative_start) = answer[offset..].find("[SRC:") {
        let start = offset + relative_start;
        let source_start = start + "[SRC:".len();
        let Some(relative_end) = answer[source_start..].find(']') else {
            break;
        };
        let end = source_start + relative_end + 1;
        let source_id = answer[source_start..end - 1].trim().to_owned();
        let raw_marker = answer[start..end].to_owned();
        let valid_syntax = is_valid_source_id(&source_id);
        let duplicate = !seen.insert(source_id.clone());

        citations.push(ParsedCitation {
            raw_marker,
            source_id,
            start_index: start,
            end_index: end,
            valid_syntax,
            duplicate,
        });
        offset = end;
    }

    citations
}

pub fn validate_answer_citations(
    connection: &rusqlite::Connection,
    answer: &str,
    allowed_sources: &[LegalSource],
    case_date: Option<&str>,
    include_expired: bool,
) -> Result<CitationValidationReport, CitationError> {
    ensure_valid_case_date(case_date)?;
    let parsed = parse_source_markers(answer);
    let allowed_source_ids = allowed_sources
        .iter()
        .map(|source| source.source_id.as_str())
        .collect::<HashSet<_>>();
    let mut citations = Vec::new();

    for citation in &parsed {
        let (status, reason, source) = if !citation.valid_syntax {
            (
                CitationStatus::Invalid,
                Some(CitationInvalidReason::InvalidSyntax),
                None,
            )
        } else {
            let database_source = source_by_citation_id(connection, &citation.source_id)?;
            match database_source {
                None => (
                    CitationStatus::Invalid,
                    Some(infer_missing_reason(connection, &citation.source_id)?),
                    None,
                ),
                Some(source) if !allowed_source_ids.contains(citation.source_id.as_str()) => (
                    CitationStatus::Invalid,
                    Some(CitationInvalidReason::NotInContext),
                    Some(source),
                ),
                Some(source) if !is_effective_on(&source, case_date, include_expired) => (
                    CitationStatus::Invalid,
                    Some(CitationInvalidReason::DateOutOfRange),
                    Some(source),
                ),
                Some(source) => (CitationStatus::Valid, None, Some(source)),
            }
        };

        citations.push(ValidatedCitation {
            raw_marker: citation.raw_marker.clone(),
            source_id: citation.source_id.clone(),
            status,
            reason,
            source,
        });
    }

    let valid_count = citations
        .iter()
        .filter(|citation| citation.status == CitationStatus::Valid)
        .count() as u32;
    let invalid_count = citations
        .iter()
        .filter(|citation| citation.status == CitationStatus::Invalid)
        .count() as u32;
    let unsupported_legal_conclusion =
        has_unsupported_legal_conclusion(answer, &parsed, &citations);

    Ok(CitationValidationReport {
        citations,
        valid_count,
        invalid_count,
        unsupported_legal_conclusion,
        semantic_support_verified: false,
    })
}

pub fn source_by_citation_id(
    connection: &rusqlite::Connection,
    citation_id: &str,
) -> Result<Option<LegalSource>, CitationError> {
    connection
        .query_row(
            "
            SELECT
                citation_metadata.citation_id,
                articles.id,
                articles.document_id,
                articles.version_id,
                documents.title,
                versions.version_label,
                articles.article_number,
                articles.title,
                citation_metadata.canonical_label,
                articles.content,
                articles.content,
                versions.effective_from,
                versions.effective_to,
                versions.status
            FROM citation_metadata
            JOIN law_articles articles ON articles.id = citation_metadata.article_id
            JOIN law_documents documents ON documents.id = articles.document_id
            JOIN law_versions versions ON versions.id = articles.version_id
            WHERE citation_metadata.citation_id = ?1
            ",
            [citation_id],
            legal_source_from_row,
        )
        .optional()
        .map_err(Into::into)
}

fn search_sources_fts(
    connection: &rusqlite::Connection,
    query: &StructuredLegalQuery,
    limit: i64,
) -> Result<Vec<LegalSource>, CitationError> {
    let search_terms = primary_search_terms(query);
    if search_terms.is_empty() {
        return Ok(Vec::new());
    }

    let fts_query = quote_fts_terms(&search_terms);
    let multi_value_filters = multi_value_filter_sql(query);
    let sql = format!(
        "
        SELECT
            citation_metadata.citation_id,
            articles.id,
            articles.document_id,
            articles.version_id,
            documents.title,
            versions.version_label,
            articles.article_number,
            articles.title,
            citation_metadata.canonical_label,
            articles.content,
            articles.content,
            versions.effective_from,
            versions.effective_to,
            versions.status
        FROM law_articles_fts
        JOIN law_articles articles ON articles.rowid = law_articles_fts.rowid
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        JOIN citation_metadata ON citation_metadata.article_id = articles.id
        WHERE law_articles_fts MATCH :fts_query
          {multi_value_filters}
          AND (
            :case_date IS NULL
            OR (
              versions.effective_from <= :case_date
              AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
            )
          )
          AND (
            :include_expired = 1
            OR (
              :case_date IS NULL
              AND versions.status = 'in_force'
            )
            OR (
              :case_date IS NOT NULL
              AND versions.effective_from <= :case_date
              AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
              AND (versions.status = 'in_force' OR versions.effective_to IS NOT NULL)
            )
          )
        ORDER BY bm25(law_articles_fts) ASC, documents.title ASC, articles.article_order ASC
        LIMIT :limit
        "
    );

    let mut statement = connection.prepare(&sql)?;
    let parameters = source_search_parameters(query, Some(fts_query), None, limit);
    let parameter_refs = named_parameter_refs(&parameters);

    let sources = statement
        .query_map(parameter_refs.as_slice(), |row| {
            let mut source = legal_source_from_row(row)?;
            source.snippet = snippet_for_terms(&search_terms, &source.content);
            Ok(source)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(dedup_sources(sources))
}

fn search_sources_like(
    connection: &rusqlite::Connection,
    query: &StructuredLegalQuery,
    limit: i64,
) -> Result<Vec<LegalSource>, CitationError> {
    let search_terms = primary_search_terms(query);
    if search_terms.is_empty() {
        return search_sources_like_term(connection, query, "", limit);
    }
    let sources = search_sources_like_candidates(
        connection,
        query,
        &search_terms,
        None,
        MAX_LIKE_CANDIDATES,
    )?;
    merge_and_rank_sources(connection, sources, Vec::new(), &search_terms, limit)
}

fn rank_sources_by_keywords(sources: &mut [LegalSource], query: &StructuredLegalQuery) {
    sources.sort_by(|left, right| {
        keyword_match_count(right, query)
            .cmp(&keyword_match_count(left, query))
            .then_with(|| left.document_title.cmp(&right.document_title))
            .then_with(|| left.article_number.cmp(&right.article_number))
    });
}

fn search_sources_like_term(
    connection: &rusqlite::Connection,
    query: &StructuredLegalQuery,
    search_text: &str,
    limit: i64,
) -> Result<Vec<LegalSource>, CitationError> {
    let is_empty = search_text.trim().is_empty();
    let search_like = like_pattern(search_text);
    let multi_value_filters = multi_value_filter_sql(query);
    let sql = format!(
        "
        SELECT
            citation_metadata.citation_id,
            articles.id,
            articles.document_id,
            articles.version_id,
            documents.title,
            versions.version_label,
            articles.article_number,
            articles.title,
            citation_metadata.canonical_label,
            articles.content,
            articles.content,
            versions.effective_from,
            versions.effective_to,
            versions.status
        FROM law_articles articles
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        JOIN citation_metadata ON citation_metadata.article_id = articles.id
        WHERE (
            :is_empty = 1
            OR documents.title LIKE :search_like ESCAPE '\\'
            OR articles.article_number LIKE :search_like ESCAPE '\\'
            OR COALESCE(articles.title, '') LIKE :search_like ESCAPE '\\'
            OR articles.content LIKE :search_like ESCAPE '\\'
          )
          {multi_value_filters}
          AND (
            :case_date IS NULL
            OR (
              versions.effective_from <= :case_date
              AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
            )
          )
          AND (
            :include_expired = 1
            OR (
              :case_date IS NULL
              AND versions.status = 'in_force'
            )
            OR (
              :case_date IS NOT NULL
              AND versions.effective_from <= :case_date
              AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
              AND (versions.status = 'in_force' OR versions.effective_to IS NOT NULL)
            )
          )
        ORDER BY
          CASE
            WHEN documents.title LIKE :search_like ESCAPE '\\' THEN 0
            WHEN articles.article_number LIKE :search_like ESCAPE '\\' THEN 1
            WHEN COALESCE(articles.title, '') LIKE :search_like ESCAPE '\\' THEN 2
            WHEN articles.content LIKE :search_like ESCAPE '\\' THEN 3
            ELSE 4
          END,
          documents.title ASC,
          articles.article_order ASC
        LIMIT :limit
        "
    );

    let mut statement = connection.prepare(&sql)?;
    let parameters = source_search_parameters(query, None, Some((is_empty, search_like)), limit);
    let parameter_refs = named_parameter_refs(&parameters);

    let sources = statement
        .query_map(parameter_refs.as_slice(), legal_source_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(dedup_sources(sources))
}

fn search_sources_like_candidates(
    connection: &rusqlite::Connection,
    query: &StructuredLegalQuery,
    search_terms: &[String],
    seed_versions: Option<&[String]>,
    limit: i64,
) -> Result<Vec<LegalSource>, CitationError> {
    if search_terms.is_empty() {
        return search_sources_like_term(connection, query, "", limit);
    }

    let match_expressions = (0..search_terms.len())
        .map(|index| source_term_match_expression(&format!(":candidate_like_{index}")))
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
                .map(|index| format!(":candidate_version_{index}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("AND articles.version_id IN ({parameters})")
        })
        .unwrap_or_default();
    let multi_value_filters = multi_value_filter_sql(query);
    let sql = format!(
        "
        SELECT
            citation_metadata.citation_id,
            articles.id,
            articles.document_id,
            articles.version_id,
            documents.title,
            versions.version_label,
            articles.article_number,
            articles.title,
            citation_metadata.canonical_label,
            articles.content,
            articles.content,
            versions.effective_from,
            versions.effective_to,
            versions.status,
            ({match_count_expression}) AS matched_terms
        FROM law_articles articles
        JOIN law_documents documents ON documents.id = articles.document_id
        JOIN law_versions versions ON versions.id = articles.version_id
        JOIN citation_metadata ON citation_metadata.article_id = articles.id
        WHERE ({any_match_expression})
          {seed_filter}
          {multi_value_filters}
          AND (
            :case_date IS NULL
            OR (
              versions.effective_from <= :case_date
              AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
            )
          )
          AND (
            :include_expired = 1
            OR (:case_date IS NULL AND versions.status = 'in_force')
            OR (
              :case_date IS NOT NULL
              AND versions.effective_from <= :case_date
              AND NOT (versions.status = 'repealed' AND versions.effective_to IS NULL)
              AND (versions.effective_to IS NULL OR versions.effective_to >= :case_date)
              AND (versions.status = 'in_force' OR versions.effective_to IS NOT NULL)
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

    let mut parameters = source_search_parameters(query, None, None, limit);
    parameters.extend(search_terms.iter().enumerate().map(|(index, term)| {
        (
            format!(":candidate_like_{index}"),
            Value::Text(like_pattern(term)),
        )
    }));
    if let Some(seed_versions) = seed_versions {
        parameters.extend(seed_versions.iter().enumerate().map(|(index, version_id)| {
            (
                format!(":candidate_version_{index}"),
                Value::Text(version_id.clone()),
            )
        }));
    }
    let parameter_refs = named_parameter_refs(&parameters);
    let mut statement = connection.prepare(&sql)?;
    let sources = statement
        .query_map(parameter_refs.as_slice(), legal_source_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(dedup_sources(sources))
}

fn legal_source_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LegalSource> {
    let content: String = row.get(9)?;
    let raw_snippet: String = row.get(10)?;

    Ok(LegalSource {
        source_id: row.get(0)?,
        article_id: row.get(1)?,
        document_id: row.get(2)?,
        version_id: row.get(3)?,
        document_title: row.get(4)?,
        version_label: row.get(5)?,
        article_number: row.get(6)?,
        article_title: row.get(7)?,
        canonical_label: row.get(8)?,
        content: content.clone(),
        snippet: clean_snippet(&raw_snippet, &content),
        effective_from: row.get(11)?,
        effective_to: row.get(12)?,
        version_status: row.get(13)?,
    })
}

fn effective_to_label(source: &LegalSource) -> &str {
    match source.effective_to.as_deref() {
        Some(effective_to) => effective_to,
        None if source.version_status == "repealed" => "终止日未知（仅供核验）",
        None => "现行/未注明终止",
    }
}

fn has_unknown_ended_historical_candidate(
    connection: &rusqlite::Connection,
    query: &StructuredLegalQuery,
) -> Result<bool, CitationError> {
    let Some(case_date) = query.case_date.as_deref() else {
        return Ok(false);
    };
    if query.law_names.is_empty()
        && query.article_numbers.is_empty()
        && query.keywords.is_empty()
        && query.effectiveness_levels.is_empty()
    {
        return Ok(false);
    }

    let mut document_filters = String::new();
    append_law_name_clause(&mut document_filters, "law_like", &query.law_names);
    append_like_any_clause(
        &mut document_filters,
        "documents.effectiveness_level",
        "level_like",
        &query.effectiveness_levels,
    );
    let mut article_filters = String::new();
    append_exact_any_clause(
        &mut article_filters,
        "historical_articles.article_number",
        "article_exact",
        &expanded_article_filter_values(&query.article_numbers),
    );
    let article_exists_filter = if article_filters.is_empty() {
        String::new()
    } else {
        format!(
            "AND EXISTS (
               SELECT 1
               FROM law_articles historical_articles
               WHERE historical_articles.version_id = versions.id
                 {article_filters}
            )"
        )
    };
    let filter_unknown_by_keywords = !query.keywords.is_empty()
        && (query.law_names.is_empty() || query.article_numbers.is_empty());
    let keyword_exists_filter = if !filter_unknown_by_keywords {
        String::new()
    } else {
        let document_expression = like_any_expression(
            &["documents.title"],
            "historical_keyword_like",
            query.keywords.len(),
        );
        let article_expression = like_any_expression(
            &[
                "keyword_articles.article_number",
                "COALESCE(keyword_articles.title, '')",
                "keyword_articles.content",
            ],
            "historical_keyword_like",
            query.keywords.len(),
        );
        format!(
            "AND (
               {document_expression}
               OR EXISTS (
                 SELECT 1
                 FROM law_articles keyword_articles
                 WHERE keyword_articles.version_id = versions.id
                   AND ({article_expression})
               )
             )"
        )
    };
    let sql = format!(
        "
        SELECT EXISTS (
          SELECT 1
          FROM law_versions versions
          JOIN law_documents documents ON documents.id = versions.document_id
          WHERE versions.status = 'repealed'
            AND versions.effective_to IS NULL
            AND versions.effective_from <= :case_date
            {document_filters}
            {article_exists_filter}
            {keyword_exists_filter}
        )
        "
    );
    let mut parameters = Vec::new();
    append_law_parameters(&mut parameters, "law_like", &query.law_names);
    append_exact_parameters(
        &mut parameters,
        "article_exact",
        &expanded_article_filter_values(&query.article_numbers),
    );
    append_like_parameters(&mut parameters, "level_like", &query.effectiveness_levels);
    if filter_unknown_by_keywords {
        append_like_parameters(&mut parameters, "historical_keyword_like", &query.keywords);
    }
    parameters.push((":case_date".to_owned(), Value::Text(case_date.to_owned())));
    let parameter_refs = named_parameter_refs(&parameters);

    connection
        .query_row(&sql, parameter_refs.as_slice(), |row| row.get(0))
        .map_err(Into::into)
}

fn like_any_expression(columns: &[&str], prefix: &str, value_count: usize) -> String {
    let mut expressions = Vec::with_capacity(columns.len() * value_count);
    for column in columns {
        for index in 0..value_count {
            expressions.push(format!("{column} LIKE :{prefix}_{index} ESCAPE '\\'"));
        }
    }
    expressions.join(" OR ")
}

fn infer_missing_reason(
    connection: &rusqlite::Connection,
    source_id: &str,
) -> Result<CitationInvalidReason, CitationError> {
    let Some((document_id, version_id, article_part)) = parse_law_source_id(source_id) else {
        return Ok(CitationInvalidReason::InvalidSyntax);
    };

    let version_document = connection
        .query_row(
            "SELECT document_id FROM law_versions WHERE id = ?1",
            [version_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    if let Some(version_document) = version_document.as_ref() {
        if version_document != &document_id
            && !stable_document_id_belongs_to_version(connection, &document_id, &version_id)?
        {
            return Ok(CitationInvalidReason::VersionMismatch);
        }
    }

    let article_exists: Option<i64> = connection
        .query_row(
            "
            SELECT 1
            FROM law_articles
            WHERE document_id = ?1
              AND version_id = ?2
              AND CAST(article_order AS TEXT) = ?3
            ",
            (
                version_document.as_deref().unwrap_or(document_id.as_str()),
                &version_id,
                &article_part,
            ),
            |row| row.get(0),
        )
        .optional()?;

    if article_exists.is_some() {
        Ok(CitationInvalidReason::NotFound)
    } else if version_document.is_some() {
        Ok(CitationInvalidReason::ParagraphNotFound)
    } else {
        Ok(CitationInvalidReason::NotFound)
    }
}

fn stable_document_id_belongs_to_version(
    connection: &rusqlite::Connection,
    stable_document_id: &str,
    version_id: &str,
) -> Result<bool, CitationError> {
    let citation_prefix = format!("law:{stable_document_id}:{version_id}:art:");
    connection
        .query_row(
            "
            SELECT EXISTS (
              SELECT 1
              FROM citation_metadata
              JOIN law_articles articles ON articles.id = citation_metadata.article_id
              WHERE articles.version_id = ?1
                AND substr(citation_metadata.citation_id, 1, length(?2)) = ?2
            )
            ",
            (version_id, citation_prefix),
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn parse_law_source_id(source_id: &str) -> Option<(String, String, String)> {
    let mut parts = source_id.split(':').collect::<Vec<_>>();
    if parts.len() < 5 || parts.first().copied() != Some("law") {
        return None;
    }

    let article_marker_index = parts.iter().position(|part| *part == "art")?;
    if article_marker_index < 3 || article_marker_index + 1 >= parts.len() {
        return None;
    }

    let article_part = parts.split_off(article_marker_index + 1).join(":");
    let version_id = parts.get(article_marker_index - 1)?.to_string();
    let document_id = parts[1..article_marker_index - 1].join(":");

    Some((document_id, version_id, article_part))
}

fn is_effective_on(source: &LegalSource, case_date: Option<&str>, include_expired: bool) -> bool {
    let Some(case_date) = case_date else {
        return include_expired || source.version_status == "in_force";
    };

    // A repealed version without a verified terminal date is not an open-ended
    // effective version.  It must remain unusable for dated advice until the
    // archive data supplies a reliable boundary.
    if source.version_status == "repealed" && source.effective_to.is_none() {
        return false;
    }

    let date_matches = source.effective_from.as_str() <= case_date
        && source
            .effective_to
            .as_deref()
            .map(|effective_to| effective_to >= case_date)
            .unwrap_or(true);
    date_matches
}

fn looks_like_legal_answer(answer: &str) -> bool {
    let without_markers = remove_source_markers(answer);
    let trimmed = without_markers.trim();
    if trimmed.is_empty()
        || is_pure_source_refusal(trimmed)
        || is_pure_formatting_or_heading(trimmed)
    {
        return false;
    }

    // This is intentionally conservative.  A finite legal-keyword allowlist
    // is trivial to evade (for example, "甲方须支付十万元" contains none of
    // the traditional keywords).  Except for a narrowly recognised refusal or
    // presentation-only heading, every segment containing prose or a number is
    // treated as a substantive assertion and therefore needs its own trailing
    // valid source marker.  The UI separately explains that marker coverage is
    // not proof of semantic support, so false positives are safer than silently
    // accepting an uncited legal conclusion.
    trimmed.chars().any(char::is_alphanumeric)
}

fn remove_source_markers(answer: &str) -> String {
    let mut remainder = answer;
    let mut result = String::with_capacity(answer.len());

    while let Some(relative_start) = remainder.find("[SRC:") {
        result.push_str(&remainder[..relative_start]);
        let marker_start = relative_start + "[SRC:".len();
        let Some(relative_end) = remainder[marker_start..].find(']') else {
            // An unterminated marker is ordinary substantive text; retain it
            // so malformed syntax cannot suppress the coverage warning.
            result.push_str(&remainder[relative_start..]);
            return result;
        };
        remainder = &remainder[marker_start + relative_end + 1..];
    }

    result.push_str(remainder);
    result
}

fn is_pure_formatting_or_heading(value: &str) -> bool {
    let trimmed = value.trim();
    let heading_colon = trimmed.ends_with('：') || trimmed.ends_with(':');
    let mut compact = value
        .chars()
        .filter(|character| {
            !character.is_whitespace()
                && !matches!(
                    character,
                    '#' | '*' | '_' | '`' | '：' | ':' | '。' | '；' | ';' | '-' | '—'
                )
        })
        .collect::<String>();

    if is_pure_provision_label(&compact) {
        return true;
    }

    // Models commonly emit short labels such as “一般规则：”. Treat only a
    // short colon-terminated phrase with no legal predicate as presentation;
    // claim-shaped text such as “合同有效：” remains substantive.
    if heading_colon && compact.chars().count() <= 32 && !contains_legal_predicate(&compact) {
        return true;
    }

    loop {
        let previous = compact.clone();
        compact = strip_heading_ordinal(&compact).to_owned();
        if compact == previous {
            break;
        }
    }

    matches!(
        compact.as_str(),
        "案情概述"
            | "事实概述"
            | "争议焦点"
            | "法律分析"
            | "法律依据"
            | "证据分析"
            | "处理建议"
            | "诉讼策略"
            | "风险提示"
            | "请求事项"
            | "答复"
            | "结论"
            | "引用来源"
            | "综上"
            | "据此"
            | "具体如下"
            | "分析如下"
            | "答复如下"
            | "结论如下"
    ) || !compact.chars().any(char::is_alphanumeric)
}

fn is_pure_provision_label(value: &str) -> bool {
    let value = value.trim_matches([
        '：', ':', '。', '；', ';', '，', ',', '（', '）', '(', ')', '[', ']', '【', '】',
    ]);
    let Some(ordinal_start) = value.rfind('第') else {
        return false;
    };
    let (law_name, ordinal) = value.split_at(ordinal_start);
    let Some(terminal) = ordinal.chars().next_back() else {
        return false;
    };
    if !matches!(terminal, '条' | '款' | '项' | '章' | '节') {
        return false;
    }

    let ordinal_body = &ordinal['第'.len_utf8()..ordinal.len() - terminal.len_utf8()];
    let valid_ordinal = !ordinal_body.is_empty()
        && ordinal_body.chars().count() <= 24
        && ordinal_body.chars().all(|character| {
            character.is_ascii_digit()
                || matches!(
                    character,
                    '一' | '二'
                        | '三'
                        | '四'
                        | '五'
                        | '六'
                        | '七'
                        | '八'
                        | '九'
                        | '十'
                        | '百'
                        | '千'
                        | '万'
                        | '零'
                        | '〇'
                        | '两'
                        | '之'
                )
        });
    let valid_law_name =
        law_name.is_empty() || (law_name.starts_with('《') && law_name.ends_with('》'));
    valid_ordinal && valid_law_name
}

fn strip_heading_ordinal(value: &str) -> &str {
    let value = value.trim_start_matches(['（', '(', '[', '【']);
    let ordinal_length = value
        .char_indices()
        .take_while(|(_, character)| {
            character.is_ascii_digit()
                || matches!(
                    character,
                    '一' | '二'
                        | '三'
                        | '四'
                        | '五'
                        | '六'
                        | '七'
                        | '八'
                        | '九'
                        | '十'
                        | '百'
                        | '千'
                        | '第'
                        | '部'
                        | '分'
                        | '章'
                        | '节'
                )
        })
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0);
    if ordinal_length == 0 {
        return value;
    }

    value[ordinal_length..]
        .trim_start_matches(['）', ')', ']', '】', '、', '.', '．', ':', '：', '-', '—'])
}

fn is_pure_source_refusal(answer: &str) -> bool {
    let mut remainder = answer.to_owned();
    let mut found_refusal = false;
    for refusal in [
        "无法由当前来源支持",
        "当前来源不足",
        "未找到本地来源",
        "不能据此得出法律结论",
    ] {
        if remainder.contains(refusal) {
            found_refusal = true;
            remainder = remainder.replace(refusal, "");
        }
    }
    if !found_refusal {
        return false;
    }
    for connective in [
        "但", "因此", "所以", "故", "仅", "只能", "暂时", "目前", "尚",
    ] {
        remainder = remainder.replace(connective, "");
    }

    remainder.chars().all(|character| {
        character.is_whitespace()
            || matches!(
                character,
                '，' | ','
                    | '。'
                    | '！'
                    | '？'
                    | '!'
                    | '?'
                    | '；'
                    | ';'
                    | '：'
                    | ':'
                    | '、'
                    | '（'
                    | '）'
                    | '('
                    | ')'
                    | '“'
                    | '”'
                    | '‘'
                    | '’'
                    | '《'
                    | '》'
                    | '-'
                    | '—'
            )
    })
}

fn has_unsupported_legal_conclusion(
    answer: &str,
    parsed: &[ParsedCitation],
    validated: &[ValidatedCitation],
) -> bool {
    if answer.trim().is_empty() {
        return false;
    }

    let valid_marker_spans = parsed
        .iter()
        .zip(validated)
        .filter_map(|(parsed, validated)| {
            (validated.status == CitationStatus::Valid)
                .then_some((parsed.start_index, parsed.end_index))
        })
        .collect::<Vec<_>>();

    legal_conclusion_segments(answer)
        .into_iter()
        .any(|(start, end)| {
            segment_has_unsupported_trailing_conclusion(answer, start, end, &valid_marker_spans)
        })
}

fn segment_has_unsupported_trailing_conclusion(
    answer: &str,
    start: usize,
    end: usize,
    valid_marker_spans: &[(usize, usize)],
) -> bool {
    // A marker supports only the conclusion immediately before it.  Text after
    // the last valid marker is deliberately left uncovered, so a marker at the
    // beginning of a clause cannot shield a later assertion.
    let trailing_start = valid_marker_spans
        .iter()
        .filter(|(marker_start, marker_end)| *marker_start >= start && *marker_end <= end)
        .map(|(_, marker_end)| *marker_end)
        .max()
        .unwrap_or(start);

    looks_like_legal_answer(&answer[trailing_start..end])
}

fn legal_conclusion_segments(answer: &str) -> Vec<(usize, usize)> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut cursor = 0;

    while cursor < answer.len() {
        if answer[cursor..].starts_with("[SRC:") {
            cursor = answer[cursor..]
                .find(']')
                .map(|relative_end| cursor + relative_end + 1)
                .unwrap_or(answer.len());
            continue;
        }

        if let Some(connector) = legal_connector_at(answer, cursor) {
            let connector_end = cursor + connector.len();
            if should_split_at_legal_connector(answer, start, cursor, connector_end) {
                push_nonempty_segment(&mut segments, answer, start, cursor);
                start = connector_end;
                cursor = connector_end;
                continue;
            }
        }

        let character = answer[cursor..]
            .chars()
            .next()
            .expect("cursor remains on a character boundary");
        let character_end = cursor + character.len_utf8();
        if matches!(character, ',' | '，' | '、')
            && should_split_at_clause_list_delimiter(
                answer,
                start,
                cursor,
                character_end,
                character,
            )
        {
            push_nonempty_segment(&mut segments, answer, start, character_end);
            start = character_end;
            cursor = character_end;
            continue;
        }
        if cursor >= start && is_legal_segment_delimiter(answer, cursor, character) {
            let sentence_end = character_end;
            let end = extend_through_trailing_markers(answer, sentence_end);
            push_nonempty_segment(&mut segments, answer, start, end);
            start = end;
            cursor = end;
            continue;
        }
        cursor += character.len_utf8();
    }

    if start < answer.len() {
        push_nonempty_segment(&mut segments, answer, start, answer.len());
    }

    segments
}

fn should_split_at_clause_list_delimiter(
    answer: &str,
    segment_start: usize,
    delimiter_start: usize,
    delimiter_end: usize,
    delimiter: char,
) -> bool {
    let left = &answer[segment_start..delimiter_start];
    if segment_start >= delimiter_start
        || (matches!(delimiter, ',' | '，')
            && delimiter_is_between_ascii_digits(answer, delimiter_start, delimiter))
        || !looks_like_legal_answer(left)
        || !contains_legal_predicate(&remove_source_markers(left))
        || looks_like_dependent_condition(left)
        || looks_like_short_bullet_label(left)
    {
        return false;
    }

    let right_end = answer[delimiter_end..]
        .char_indices()
        .find_map(|(relative_index, character)| {
            matches!(
                character,
                '。' | '！' | '？' | '!' | '?' | '；' | ';' | '\n'
            )
            .then_some(delimiter_end + relative_index)
        })
        .unwrap_or(answer.len());
    has_explicit_subject_before_legal_predicate(&answer[delimiter_end..right_end])
}

fn looks_like_dependent_condition(value: &str) -> bool {
    let without_markers = remove_source_markers(value);
    let compact = without_markers
        .trim()
        .trim_start_matches(['-', '*', '•', '·', ' '])
        .trim();
    if ["应当", "必须", "不得", "有权", "无权", "可以", "须"]
        .into_iter()
        .any(|modal| compact.contains(modal))
    {
        return false;
    }

    [
        "如果",
        "若",
        "如",
        "当",
        "因",
        "由于",
        "在",
        "一旦",
        "不履行",
        "未履行",
        "履行不符合",
        "不符合约定",
        "未按约",
        "造成",
        "导致",
    ]
    .into_iter()
    .any(|condition| compact.starts_with(condition) || compact.contains(condition))
        || compact.ends_with(['的', '时', '后'])
        || compact.ends_with("情况下")
}

fn looks_like_short_bullet_label(value: &str) -> bool {
    let trimmed = remove_source_markers(value).trim().to_owned();
    if !(trimmed.starts_with("- ") || trimmed.starts_with("* ") || trimmed.starts_with("• ")) {
        return false;
    }
    let label = trimmed.trim_start_matches(['-', '*', '•', '·', ' ']).trim();
    label.chars().count() <= 12
        && !["应当", "必须", "不得", "有权", "无权", "可以", "须"]
            .into_iter()
            .any(|modal| label.contains(modal))
}

fn push_nonempty_segment(
    segments: &mut Vec<(usize, usize)>,
    answer: &str,
    start: usize,
    end: usize,
) {
    if start < end
        && answer[start..end]
            .chars()
            .any(|character| !character.is_whitespace())
    {
        segments.push((start, end));
    }
}

fn legal_connector_at(answer: &str, index: usize) -> Option<&'static str> {
    // Longest forms must come first so `并可` is not consumed as bare `并`
    // and `或者` is not consumed as bare `或`.
    const CONNECTORS: [&str; 18] = [
        "并且", "而且", "同时", "以及", "但是", "此外", "然而", "或者", "并可", "并应", "亦", "又",
        "还", "或", "且", "但", "并", "而",
    ];
    CONNECTORS
        .into_iter()
        .find(|connector| answer[index..].starts_with(connector))
}

fn should_split_at_legal_connector(
    answer: &str,
    segment_start: usize,
    connector_start: usize,
    connector_end: usize,
) -> bool {
    if segment_start >= connector_start
        || !looks_like_legal_answer(&answer[segment_start..connector_start])
    {
        return false;
    }

    let right_end = answer[connector_end..]
        .char_indices()
        .find_map(|(relative_index, character)| {
            is_legal_segment_delimiter(answer, connector_end + relative_index, character)
                .then_some(connector_end + relative_index)
        })
        .unwrap_or(answer.len());
    has_explicit_subject_before_legal_predicate(&answer[connector_end..right_end])
}

fn has_explicit_subject_before_legal_predicate(value: &str) -> bool {
    const PREDICATES: [&str; 27] = [
        "应当", "必须", "不得", "无权", "有权", "可以", "承担", "负责", "支付", "赔偿", "履行",
        "采取", "返还", "构成", "有效", "无效", "解除", "终止", "撤销", "确认", "判令", "支持",
        "驳回", "归还", "给付", "应", "须",
    ];
    let without_markers = remove_source_markers(value);
    let trimmed = without_markers.trim_start_matches(|character: char| {
        character.is_whitespace() || matches!(character, '，' | ',' | '：' | ':' | '、')
    });
    let Some(predicate_index) = PREDICATES
        .into_iter()
        .filter_map(|predicate| trimmed.find(predicate))
        .min()
    else {
        return false;
    };
    if predicate_index == 0 {
        return false;
    }
    let subject = trimmed[..predicate_index].trim();
    let character_count = subject.chars().count();
    (1..=24).contains(&character_count) && subject.chars().any(char::is_alphanumeric)
}

fn contains_legal_predicate(value: &str) -> bool {
    const PREDICATES: [&str; 27] = [
        "应当", "必须", "不得", "无权", "有权", "可以", "承担", "负责", "支付", "赔偿", "履行",
        "采取", "返还", "构成", "有效", "无效", "解除", "终止", "撤销", "确认", "判令", "支持",
        "驳回", "归还", "给付", "应", "须",
    ];
    PREDICATES
        .into_iter()
        .any(|predicate| value.contains(predicate))
}

fn is_legal_segment_delimiter(answer: &str, index: usize, character: char) -> bool {
    if matches!(character, ':' | '：') {
        // Do not split times/ratios (12:30, 1:2). A pure provision label is
        // presentation-only after it becomes its own segment; this prevents
        // claim-shaped text ending in “第1条：” from suppressing a boundary.
        return !delimiter_is_between_ascii_digits(answer, index, character);
    }

    matches!(
        character,
        '。' | '！' | '？' | '!' | '?' | '；' | ';' | '\n'
    )
}

fn delimiter_is_between_ascii_digits(answer: &str, index: usize, character: char) -> bool {
    let previous_is_digit = answer[..index]
        .chars()
        .next_back()
        .is_some_and(|previous| previous.is_ascii_digit());
    let next_index = index + character.len_utf8();
    let next_is_digit = answer[next_index..]
        .chars()
        .next()
        .is_some_and(|next| next.is_ascii_digit());
    previous_is_digit && next_is_digit
}

fn extend_through_trailing_markers(answer: &str, mut cursor: usize) -> usize {
    loop {
        while cursor < answer.len() {
            let character = answer[cursor..]
                .chars()
                .next()
                .expect("cursor is within the answer");
            if !character.is_whitespace() {
                break;
            }
            cursor += character.len_utf8();
        }

        if !answer[cursor..].starts_with("[SRC:") {
            return cursor;
        }
        let Some(relative_end) = answer[cursor..].find(']') else {
            return cursor;
        };
        cursor += relative_end + 1;
    }
}

fn is_valid_source_id(source_id: &str) -> bool {
    !source_id.is_empty()
        && source_id.starts_with("law:")
        && source_id.contains(":art:")
        && !source_id.contains("..")
        && !source_id.contains(',')
        && source_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, ':' | '-' | '_' | '.' | '/')
        })
}

fn extract_quoted_law_names(question: &str) -> Vec<String> {
    extract_quoted_law_occurrences(question)
        .into_iter()
        .map(|(name, _, _)| name)
        .collect()
}

fn extract_quoted_law_occurrences(question: &str) -> Vec<(String, usize, usize)> {
    let mut occurrences = Vec::new();
    let mut cursor = 0;
    while cursor < question.len() {
        let Some(relative_start) = question[cursor..].find('《') else {
            break;
        };
        let start = cursor + relative_start;
        let name_start = start + '《'.len_utf8();
        let Some(relative_end) = question[name_start..].find('》') else {
            break;
        };
        let name_end = name_start + relative_end;
        let end = name_end + '》'.len_utf8();
        if let Some(name) = normalized_non_empty(Some(&question[name_start..name_end])) {
            occurrences.push((name, start, end));
        }
        cursor = end;
    }
    occurrences
}

fn extract_article_markers(question: &str) -> Vec<String> {
    let mut markers = extract_article_occurrences(question, false)
        .into_iter()
        .map(|occurrence| occurrence.article_number)
        .collect::<Vec<_>>();
    dedup_preserve_order(&mut markers);
    markers
}

fn extract_article_occurrences(text: &str, include_bare_ascii: bool) -> Vec<ArticleOccurrence> {
    let mut occurrences = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let character = text[cursor..]
            .chars()
            .next()
            .expect("cursor remains on a character boundary");

        if character == '第' {
            let after_prefix = cursor + character.len_utf8();
            if let Some(relative_end) = text[after_prefix..].find('条') {
                let base_end = after_prefix + relative_end + '条'.len_utf8();
                let end = extend_through_subarticle_ordinal(text, base_end);
                let raw = &text[cursor..end];
                if raw.chars().count() <= 24 {
                    if let Some(article_number) = parse_article_number(raw) {
                        occurrences.push(ArticleOccurrence {
                            article_number: canonical_parsed_article_number(article_number),
                            start: cursor,
                            bare_ascii: false,
                        });
                        cursor = end;
                        continue;
                    }
                }
            }
        }

        if character.is_ascii_digit()
            && !text[..cursor]
                .chars()
                .next_back()
                .is_some_and(|previous| previous.is_ascii_alphanumeric())
        {
            let mut digits_end = cursor;
            while digits_end < text.len() {
                let next = text[digits_end..]
                    .chars()
                    .next()
                    .expect("digits cursor remains in bounds");
                if !next.is_ascii_digit() {
                    break;
                }
                digits_end += next.len_utf8();
            }
            let has_article_suffix = text[digits_end..].starts_with('条');
            let base_end = if has_article_suffix {
                digits_end + '条'.len_utf8()
            } else {
                digits_end
            };
            let end = if has_article_suffix {
                extend_through_subarticle_ordinal(text, base_end)
            } else {
                base_end
            };
            let raw = &text[cursor..end];
            let next_character = text[end..].chars().next();
            let safe_bare_boundary = include_bare_ascii
                && !next_character.is_some_and(|next| {
                    next.is_ascii_alphanumeric()
                        || matches!(
                            next,
                            '年' | '月' | '日' | '时' | '分' | '秒' | '元' | '万' | '%' | '％'
                        )
                });
            if has_article_suffix || safe_bare_boundary {
                if let Some(article_number) = parse_article_number(raw) {
                    occurrences.push(ArticleOccurrence {
                        article_number: canonical_parsed_article_number(article_number),
                        start: cursor,
                        bare_ascii: !has_article_suffix,
                    });
                    cursor = end;
                    continue;
                }
            }
        }

        cursor += character.len_utf8();
    }
    occurrences
}

fn extend_through_subarticle_ordinal(text: &str, base_end: usize) -> usize {
    if !text[base_end..].starts_with('之') {
        return base_end;
    }
    let mut cursor = base_end + '之'.len_utf8();
    while cursor < text.len() {
        let character = text[cursor..]
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

fn extract_law_article_pairs(question: &str) -> Vec<LawArticlePair> {
    let laws = extract_quoted_law_occurrences(question);
    let mut pairs = Vec::new();
    for (index, (law_name, _, law_end)) in laws.iter().enumerate() {
        let segment_end = laws
            .get(index + 1)
            .map(|(_, next_start, _)| *next_start)
            .unwrap_or(question.len());
        let Some(segment) = question.get(*law_end..segment_end) else {
            continue;
        };
        for occurrence in extract_article_occurrences(segment, true) {
            if occurrence.bare_ascii {
                let prefix = segment[..occurrence.start].trim();
                if !matches!(prefix, "" | "第") {
                    continue;
                }
            }
            pairs.push(LawArticlePair {
                law_name: law_name.clone(),
                article_number: occurrence.article_number,
            });
        }
    }
    pairs.sort_by(|left, right| {
        left.law_name
            .cmp(&right.law_name)
            .then_with(|| left.article_number.cmp(&right.article_number))
    });
    pairs.dedup();
    pairs
}

fn inferred_pairing(question: &str, query: &StructuredLegalQuery) -> InferredPairing {
    if query.law_names.len() < 2 || query.article_numbers.len() < 2 {
        return InferredPairing::None;
    }

    let pairs = extract_law_article_pairs(question)
        .into_iter()
        .filter(|pair| {
            query.law_names.contains(&pair.law_name)
                && query
                    .article_numbers
                    .iter()
                    .any(|article| article_numbers_equivalent(article, &pair.article_number))
        })
        .collect::<Vec<_>>();
    let every_law_is_paired = query
        .law_names
        .iter()
        .all(|law_name| pairs.iter().any(|pair| &pair.law_name == law_name));
    let every_article_is_paired = query.article_numbers.iter().all(|article| {
        pairs
            .iter()
            .any(|pair| article_numbers_equivalent(article, pair.article_number.as_str()))
    });
    if every_law_is_paired && every_article_is_paired {
        InferredPairing::Paired(pairs)
    } else {
        InferredPairing::Ambiguous
    }
}

fn normalize_article_filter_value(value: &str) -> String {
    parse_article_number(value)
        .map(canonical_parsed_article_number)
        .unwrap_or_else(|| value.trim().to_owned())
}

fn expanded_article_filter_values(values: &[String]) -> Vec<String> {
    let mut expanded = Vec::new();
    for value in values {
        if let Some(article_number) = parse_article_number(value) {
            expanded.push(canonical_parsed_article_number(article_number));
            let base_variants = [
                format!("第{}条", integer_to_chinese(article_number.base)),
                format!("第{}条", article_number.base),
                format!("{}条", article_number.base),
            ];
            if let Some(subarticle) = article_number.subarticle {
                let subarticle_variants = [integer_to_chinese(subarticle), subarticle.to_string()];
                for base in base_variants {
                    for subarticle in &subarticle_variants {
                        expanded.push(format!("{base}之{subarticle}"));
                    }
                }
            } else {
                expanded.extend(base_variants);
                expanded.push(article_number.base.to_string());
            }
        } else if let Some(value) = normalized_non_empty(Some(value)) {
            expanded.push(value);
        }
    }
    dedup_preserve_order(&mut expanded);
    expanded
}

fn article_numbers_equivalent(left: &str, right: &str) -> bool {
    match (parse_article_number(left), parse_article_number(right)) {
        (Some(left), Some(right)) => left == right,
        _ => left.trim() == right.trim(),
    }
}

#[cfg(test)]
fn parse_article_ordinal(value: &str) -> Option<u32> {
    let parsed = parse_article_number(value)?;
    parsed.subarticle.is_none().then_some(parsed.base)
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
        let digit = pending_digit.take().unwrap_or(1);
        total = total.checked_add(digit.checked_mul(unit)?)?;
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

fn canonical_article_number(value: u32) -> String {
    format!("第{}条", integer_to_chinese(value))
}

fn canonical_parsed_article_number(value: ParsedArticleNumber) -> String {
    let mut canonical = canonical_article_number(value.base);
    if let Some(subarticle) = value.subarticle {
        canonical.push('之');
        canonical.push_str(&integer_to_chinese(subarticle));
    }
    canonical
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

fn extract_keywords(
    question: &str,
    law_names: &[String],
    article_numbers: &[String],
) -> Vec<String> {
    let mut cleaned = question.to_owned();
    for law_name in law_names {
        cleaned = cleaned.replace(law_name, " ");
    }
    for article_number in article_numbers {
        for equivalent in expanded_article_filter_values(std::slice::from_ref(article_number)) {
            cleaned = cleaned.replace(&equivalent, " ");
        }
    }
    for separator in [
        '，', '。', '？', '?', '！', '!', '；', ';', '、', '：', ':', '（', '）', '(', ')', '《',
        '》', '"', '\'',
    ] {
        cleaned = cleaned.replace(separator, " ");
    }

    cleaned
        .split_whitespace()
        .flat_map(extract_keyword_fragments)
        .collect()
}

fn extract_keyword_fragments(part: &str) -> Vec<String> {
    const QUESTION_CUES: [&str; 11] = [
        "如何",
        "怎么",
        "怎样",
        "是否",
        "能否",
        "什么",
        "哪些",
        "为何",
        "为什么",
        "可否",
        "吗",
    ];

    let part = part.trim().trim_start_matches("请问");
    if part.chars().count() < 2 {
        return Vec::new();
    }
    let cue = QUESTION_CUES
        .iter()
        .filter_map(|cue| part.find(cue).map(|index| (index, *cue)))
        .min_by_key(|(index, _)| *index);
    let core = match cue {
        Some((0, cue)) => &part[cue.len()..],
        Some((index, _)) => &part[..index],
        None => part,
    }
    .trim();
    let core = ["中的", "关于", "依据", "根据", "中", "就"]
        .into_iter()
        .find_map(|prefix| core.strip_prefix(prefix))
        .unwrap_or(core)
        .trim();
    let characters = core.chars().collect::<Vec<_>>();
    if characters.len() < 2 {
        return Vec::new();
    }
    if characters.len() < 4 || !characters.iter().copied().all(is_cjk_ideograph) {
        return vec![core.to_owned()];
    }

    if characters.len() == 4 {
        let mut fragments = vec![core.to_owned()];
        fragments.push(characters[..2].iter().collect());
        fragments.push(characters[2..].iter().collect());
        dedup_preserve_order(&mut fragments);
        return fragments;
    }

    characters
        .windows(4)
        .map(|window| window.iter().collect::<String>())
        .filter(|fragment| !QUESTION_CUES.iter().any(|cue| fragment.contains(cue)))
        .take(8)
        .collect()
}

fn primary_search_terms(query: &StructuredLegalQuery) -> Vec<String> {
    if !query.keywords.is_empty() {
        return query.keywords.clone();
    }

    if !query.law_names.is_empty()
        || !query.article_numbers.is_empty()
        || !query.effectiveness_levels.is_empty()
    {
        return Vec::new();
    }

    normalized_non_empty(Some(&query.legal_issue))
        .into_iter()
        .collect()
}

fn bounded_limit(limit: Option<u32>) -> i64 {
    i64::from(
        limit
            .unwrap_or(DEFAULT_SOURCE_LIMIT)
            .clamp(1, MAX_SOURCE_LIMIT),
    )
}

fn multi_value_filter_sql(query: &StructuredLegalQuery) -> String {
    let mut sql = String::new();
    append_law_name_clause(&mut sql, "law_like", &query.law_names);
    append_exact_any_clause(
        &mut sql,
        "articles.article_number",
        "article_exact",
        &expanded_article_filter_values(&query.article_numbers),
    );
    append_like_any_clause(
        &mut sql,
        "documents.effectiveness_level",
        "level_like",
        &query.effectiveness_levels,
    );
    sql
}

fn append_law_name_clause(sql: &mut String, prefix: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    sql.push_str("AND (");
    for (index, _) in values.iter().enumerate() {
        if index > 0 {
            sql.push_str(" OR ");
        }
        let like_parameter = format!(":{prefix}_like_{index}");
        let exact_parameter = format!(":{prefix}_exact_{index}");
        sql.push('(');
        sql.push_str("documents.title = ");
        sql.push_str(&exact_parameter);
        sql.push_str(" OR EXISTS (");
        sql.push_str("SELECT 1 FROM law_aliases law_name_aliases ");
        sql.push_str("WHERE law_name_aliases.document_id = documents.id ");
        sql.push_str("AND law_name_aliases.normalized_alias = ");
        sql.push_str(&exact_parameter);
        sql.push_str(") OR (NOT EXISTS (");
        sql.push_str("SELECT 1 FROM law_aliases exact_law_aliases ");
        sql.push_str("WHERE exact_law_aliases.normalized_alias = ");
        sql.push_str(&exact_parameter);
        sql.push_str(") AND (documents.title LIKE ");
        sql.push_str(&like_parameter);
        sql.push_str(" ESCAPE '\\' OR EXISTS (");
        sql.push_str("SELECT 1 FROM law_aliases partial_law_aliases ");
        sql.push_str("WHERE partial_law_aliases.document_id = documents.id ");
        sql.push_str("AND partial_law_aliases.alias LIKE ");
        sql.push_str(&like_parameter);
        sql.push_str(" ESCAPE '\\'))))");
    }
    sql.push_str(")\n");
}

fn append_exact_any_clause(sql: &mut String, column: &str, prefix: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    sql.push_str("AND (");
    for (index, _) in values.iter().enumerate() {
        if index > 0 {
            sql.push_str(" OR ");
        }
        sql.push_str(column);
        sql.push_str(" = :");
        sql.push_str(prefix);
        sql.push('_');
        sql.push_str(&index.to_string());
    }
    sql.push_str(")\n");
}

fn append_like_any_clause(sql: &mut String, column: &str, prefix: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }

    sql.push_str("AND (");
    for (index, _) in values.iter().enumerate() {
        if index > 0 {
            sql.push_str(" OR ");
        }
        sql.push_str(column);
        sql.push_str(" LIKE :");
        sql.push_str(prefix);
        sql.push('_');
        sql.push_str(&index.to_string());
        sql.push_str(" ESCAPE '\\'");
    }
    sql.push_str(")\n");
}

fn source_search_parameters(
    query: &StructuredLegalQuery,
    fts_query: Option<String>,
    like_search: Option<(bool, String)>,
    limit: i64,
) -> Vec<(String, Value)> {
    let mut parameters = Vec::new();

    if let Some(fts_query) = fts_query {
        parameters.push((":fts_query".to_owned(), Value::Text(fts_query)));
    }
    if let Some((is_empty, search_like)) = like_search {
        parameters.push((
            ":is_empty".to_owned(),
            Value::Integer(if is_empty { 1 } else { 0 }),
        ));
        parameters.push((":search_like".to_owned(), Value::Text(search_like)));
    }

    append_law_parameters(&mut parameters, "law_like", &query.law_names);
    append_exact_parameters(
        &mut parameters,
        "article_exact",
        &expanded_article_filter_values(&query.article_numbers),
    );
    append_like_parameters(&mut parameters, "level_like", &query.effectiveness_levels);

    parameters.push((
        ":case_date".to_owned(),
        query
            .case_date
            .clone()
            .map(Value::Text)
            .unwrap_or(Value::Null),
    ));
    parameters.push((
        ":include_expired".to_owned(),
        Value::Integer(if query.include_expired { 1 } else { 0 }),
    ));
    parameters.push((":limit".to_owned(), Value::Integer(limit)));
    parameters
}

fn append_like_parameters(parameters: &mut Vec<(String, Value)>, prefix: &str, values: &[String]) {
    parameters.extend(values.iter().enumerate().map(|(index, value)| {
        (
            format!(":{prefix}_{index}"),
            Value::Text(like_pattern(value)),
        )
    }));
}

fn append_law_parameters(parameters: &mut Vec<(String, Value)>, prefix: &str, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        parameters.push((
            format!(":{prefix}_like_{index}"),
            Value::Text(like_pattern(value)),
        ));
        parameters.push((
            format!(":{prefix}_exact_{index}"),
            Value::Text(value.trim().to_owned()),
        ));
    }
}

fn append_exact_parameters(parameters: &mut Vec<(String, Value)>, prefix: &str, values: &[String]) {
    parameters.extend(
        values
            .iter()
            .enumerate()
            .map(|(index, value)| (format!(":{prefix}_{index}"), Value::Text(value.clone()))),
    );
}

fn named_parameter_refs(parameters: &[(String, Value)]) -> Vec<(&str, &dyn ToSql)> {
    parameters
        .iter()
        .map(|(name, value)| (name.as_str(), value as &dyn ToSql))
        .collect()
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

fn source_term_match_expression(parameter: &str) -> String {
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

fn merge_and_rank_sources(
    connection: &rusqlite::Connection,
    primary: Vec<LegalSource>,
    secondary: Vec<LegalSource>,
    search_terms: &[String],
    limit: i64,
) -> Result<Vec<LegalSource>, CitationError> {
    let mut sources = dedup_sources(primary.into_iter().chain(secondary).collect());
    let effectiveness_levels = load_effectiveness_levels(connection, &sources)?;
    sources.sort_by(|left, right| {
        let left_stats = source_match_stats(left, search_terms);
        let right_stats = source_match_stats(right, search_terms);
        right_stats
            .cmp(&left_stats)
            .then_with(|| {
                source_authority_rank(
                    effectiveness_levels
                        .get(&right.document_id)
                        .map(String::as_str)
                        .unwrap_or(""),
                )
                .cmp(&source_authority_rank(
                    effectiveness_levels
                        .get(&left.document_id)
                        .map(String::as_str)
                        .unwrap_or(""),
                ))
            })
            .then_with(|| {
                (right.version_status == "in_force").cmp(&(left.version_status == "in_force"))
            })
            .then_with(|| left.document_title.cmp(&right.document_title))
            .then_with(|| left.article_number.cmp(&right.article_number))
            .then_with(|| left.source_id.cmp(&right.source_id))
    });
    sources.truncate(limit.max(0) as usize);
    Ok(sources)
}

fn filter_sources_by_pairs(
    connection: &rusqlite::Connection,
    sources: Vec<LegalSource>,
    pairs: &[LawArticlePair],
) -> Result<Vec<LegalSource>, CitationError> {
    let aliases = load_document_aliases(connection, &sources)?;
    let exact_alias_owners = load_exact_alias_owners(connection, pairs)?;
    Ok(sources
        .into_iter()
        .filter(|source| {
            pairs.iter().any(|pair| {
                let exact_owners = exact_alias_owners.get(&pair.law_name);
                let law_matches = source.document_title == pair.law_name
                    || exact_owners
                        .filter(|owners| !owners.is_empty())
                        .map(|owners| owners.contains(&source.document_id))
                        .unwrap_or_else(|| {
                            source.document_title.contains(&pair.law_name)
                                || aliases.get(&source.document_id).is_some_and(
                                    |document_aliases| {
                                        document_aliases
                                            .iter()
                                            .any(|alias| alias.contains(&pair.law_name))
                                    },
                                )
                        });
                article_numbers_equivalent(&source.article_number, &pair.article_number)
                    && law_matches
            })
        })
        .collect())
}

fn source_match_stats(source: &LegalSource, search_terms: &[String]) -> (usize, usize, usize) {
    let mut matched_terms = 0;
    let mut substantive_matches = 0;
    let mut article_title_matches = 0;
    for term in search_terms {
        let title_matches = source
            .article_title
            .as_deref()
            .is_some_and(|title| title.contains(term));
        let content_matches = source.content.contains(term);
        if source.document_title.contains(term)
            || source.article_number.contains(term)
            || title_matches
            || content_matches
        {
            matched_terms += 1;
        }
        if content_matches && term_has_substantive_content_match(&source.content, term) {
            substantive_matches += 1;
        }
        if title_matches {
            article_title_matches += 1;
        }
    }
    (matched_terms, substantive_matches, article_title_matches)
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

fn load_effectiveness_levels(
    connection: &rusqlite::Connection,
    sources: &[LegalSource],
) -> Result<HashMap<String, String>, CitationError> {
    let document_ids = sources
        .iter()
        .map(|source| source.document_id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if document_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = std::iter::repeat_n("?", document_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql =
        format!("SELECT id, effectiveness_level FROM law_documents WHERE id IN ({placeholders})");
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(document_ids.iter()), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    rows.collect::<rusqlite::Result<HashMap<_, _>>>()
        .map_err(Into::into)
}

fn load_document_aliases(
    connection: &rusqlite::Connection,
    sources: &[LegalSource],
) -> Result<HashMap<String, Vec<String>>, CitationError> {
    let document_ids = sources
        .iter()
        .map(|source| source.document_id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if document_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let placeholders = std::iter::repeat_n("?", document_ids.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql =
        format!("SELECT document_id, alias FROM law_aliases WHERE document_id IN ({placeholders})");
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(document_ids.iter()), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut aliases: HashMap<String, Vec<String>> = HashMap::new();
    for row in rows {
        let (document_id, alias) = row?;
        aliases.entry(document_id).or_default().push(alias);
    }
    Ok(aliases)
}

fn load_exact_alias_owners(
    connection: &rusqlite::Connection,
    pairs: &[LawArticlePair],
) -> Result<HashMap<String, HashSet<String>>, CitationError> {
    let law_names = pairs
        .iter()
        .map(|pair| pair.law_name.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if law_names.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = std::iter::repeat_n("?", law_names.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT normalized_alias, document_id FROM law_aliases \
         WHERE normalized_alias IN ({placeholders})"
    );
    let mut statement = connection.prepare(&sql)?;
    let rows = statement.query_map(rusqlite::params_from_iter(law_names.iter()), |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut owners: HashMap<String, HashSet<String>> = HashMap::new();
    for row in rows {
        let (alias, document_id) = row?;
        owners.entry(alias).or_default().insert(document_id);
    }
    Ok(owners)
}

fn source_authority_rank(effectiveness_level: &str) -> u8 {
    match effectiveness_level {
        "constitution" => 9,
        "national_law" => 8,
        "administrative_regulation" | "supervision_regulation" => 7,
        "judicial_interpretation" => 6,
        "department_rule" => 5,
        "autonomous_regulation" | "special_zone_regulation" => 4,
        "local_regulation" => 3,
        "local_government_rule" => 2,
        _ => 1,
    }
}

fn quote_fts_terms(terms: &[String]) -> String {
    terms
        .iter()
        .map(|term| format!("\"{}\"", term.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn clean_snippet(raw_snippet: &str, content: &str) -> String {
    let trimmed = raw_snippet.trim();
    if trimmed.is_empty() {
        truncate_chars(content, MAX_SOURCE_SNIPPET_CHARS)
    } else {
        truncate_chars(trimmed, MAX_SOURCE_SNIPPET_CHARS)
    }
}

fn keyword_match_count(source: &LegalSource, query: &StructuredLegalQuery) -> usize {
    query
        .keywords
        .iter()
        .filter(|keyword| {
            source.document_title.contains(keyword.as_str())
                || source.article_number.contains(keyword.as_str())
                || source
                    .article_title
                    .as_deref()
                    .is_some_and(|title| title.contains(keyword.as_str()))
                || source.content.contains(keyword.as_str())
        })
        .count()
}

fn snippet_for_terms(terms: &[String], content: &str) -> String {
    let Some((byte_index, _)) = terms
        .iter()
        .filter_map(|term| content.find(term).map(|index| (index, term)))
        .min_by_key(|(index, _)| *index)
    else {
        return truncate_chars(content, MAX_SOURCE_SNIPPET_CHARS);
    };
    let leading_chars = MAX_SOURCE_SNIPPET_CHARS / 3;
    let start = content[..byte_index]
        .char_indices()
        .rev()
        .nth(leading_chars)
        .map(|(index, _)| index)
        .unwrap_or(0);
    let snippet = content[start..]
        .chars()
        .take(MAX_SOURCE_SNIPPET_CHARS)
        .collect::<String>();
    let prefix = if start > 0 { "..." } else { "" };
    let suffix = if start + snippet.len() < content.len() {
        "..."
    } else {
        ""
    };
    format!("{prefix}{snippet}{suffix}")
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut output = value.chars().take(max_chars).collect::<String>();
    if value.chars().count() > max_chars {
        output.push_str("...");
    }
    output
}

fn normalized_non_empty(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

fn trimmed_non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

fn dedup_preserve_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn ensure_valid_case_date(case_date: Option<&str>) -> Result<(), CitationError> {
    if let Some(case_date) = case_date {
        if !domain::date::is_iso_calendar_date(case_date) {
            return Err(CitationError::InvalidRequest(
                "case_date must be a valid YYYY-MM-DD calendar date".to_owned(),
            ));
        }
    }

    Ok(())
}

fn dedup_sources(sources: Vec<LegalSource>) -> Vec<LegalSource> {
    let mut seen = HashSet::new();
    sources
        .into_iter()
        .filter(|source| seen.insert(source.source_id.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

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

    fn request() -> LegalAnswerCandidatesRequest {
        LegalAnswerCandidatesRequest {
            question: "contract liability".to_owned(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: None,
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(4),
        }
    }

    #[test]
    fn context_and_validator_reject_invalid_case_dates() {
        let connection = fixture_connection();
        let mut invalid_request = request();
        invalid_request.case_date = Some("2024-02-30".to_owned());

        let context_error = build_legal_answer_context(&connection, &invalid_request)
            .expect_err("invalid context date is rejected");
        assert!(matches!(context_error, CitationError::InvalidRequest(_)));

        let validation_error =
            validate_answer_citations(&connection, "No citation.", &[], Some("not-a-date"), false)
                .expect_err("invalid validation date is rejected");
        assert!(matches!(validation_error, CitationError::InvalidRequest(_)));
    }

    fn insert_historical_civil_code_version(connection: &rusqlite::Connection) {
        connection
            .execute_batch(
                "
                INSERT INTO law_versions (
                  id, document_id, version_label, status, effective_from, effective_to,
                  published_on, source_reference
                ) VALUES (
                  'cn-civil-code-20150101', 'cn-civil-code', '2015年历史测试版本',
                  'repealed', '2015-01-01', '2020-12-31', '2014-12-01', '测试 fixture'
                );
                INSERT INTO law_articles (
                  id, document_id, version_id, article_number, article_order, title, content, updated_on
                ) VALUES (
                  'cn-civil-code-20150101-577', 'cn-civil-code', 'cn-civil-code-20150101',
                  '第五百七十七条', 577, '违约责任历史版本',
                  '历史版本规定当事人应当承担违约责任。', '2026-07-10'
                );
                INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label) VALUES (
                  'cite-civil-code-old-577', 'cn-civil-code-20150101-577',
                  'law:cn-civil-code:cn-civil-code-20150101:art:577',
                  '《中华人民共和国民法典》第五百七十七条（历史测试版本）'
                );
                INSERT INTO law_articles_fts (
                  rowid, article_id, document_id, version_id, document_title,
                  article_number, article_title, content
                )
                SELECT rowid, id, document_id, version_id, '中华人民共和国民法典',
                       article_number, title, content
                FROM law_articles WHERE id = 'cn-civil-code-20150101-577';
                ",
            )
            .expect("historical fixture version inserts");
    }

    fn insert_normalized_historical_citation_shape(connection: &rusqlite::Connection) {
        connection
            .execute_batch(
                "
                INSERT INTO law_versions (
                  id, document_id, version_label, status, effective_from, effective_to,
                  published_on, source_reference
                ) VALUES (
                  'flk-version-history-20150101', 'cn-civil-code', '正式归并历史版本',
                  'repealed', '2015-01-01', '2020-12-31', '2014-12-01', '国家法律法规数据库'
                );
                INSERT INTO law_articles (
                  id, document_id, version_id, article_number, article_order, title, content, updated_on
                ) VALUES (
                  'flk-history-577', 'cn-civil-code', 'flk-version-history-20150101',
                  '第五百七十七条', 577, '违约责任历史版本',
                  '历史版本规定当事人应当承担违约责任。', '2026-07-12'
                );
                INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label) VALUES (
                  'cite-flk-history-577', 'flk-history-577',
                  'law:flk-historical-document:flk-version-history-20150101:art:577',
                  '《中华人民共和国民法典》第五百七十七条（正式归并历史版本）'
                );
                ",
            )
            .expect("normalized historical citation shape inserts");
    }

    fn insert_unknown_ended_repealed_version(connection: &rusqlite::Connection) {
        connection
            .execute_batch(
                "
                INSERT INTO law_versions (
                  id, document_id, version_label, status, effective_from, effective_to,
                  published_on, source_reference
                ) VALUES (
                  'cn-contract-law-unknown-end', 'cn-contract-law-1999', '终止日待核验版本',
                  'repealed', '1999-10-01', NULL, '1999-03-15', '测试 fixture'
                );
                INSERT INTO law_articles (
                  id, document_id, version_id, article_number, article_order, title, content, updated_on
                ) VALUES (
                  'cn-contract-law-unknown-end-107', 'cn-contract-law-1999',
                  'cn-contract-law-unknown-end', '第一百零七条', 107, '违约责任',
                  '当事人一方不履行合同义务的，应当承担违约责任。', '2026-07-14'
                );
                INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label) VALUES (
                  'cite-contract-law-unknown-end-107', 'cn-contract-law-unknown-end-107',
                  'law:cn-contract-law-1999:cn-contract-law-unknown-end:art:107',
                  '《中华人民共和国合同法》第一百零七条（终止日待核验版本）'
                );
                INSERT INTO law_articles_fts (
                  rowid, article_id, document_id, version_id, document_title,
                  article_number, article_title, content
                )
                SELECT rowid, id, document_id, version_id, '中华人民共和国合同法',
                       article_number, title, content
                FROM law_articles WHERE id = 'cn-contract-law-unknown-end-107';
                ",
            )
            .expect("unknown-ended historical fixture version inserts");
    }

    fn insert_cross_pair_decoys(connection: &rusqlite::Connection) {
        connection
            .execute_batch(
                "
                INSERT INTO law_articles (
                  id, document_id, version_id, article_number, article_order, title, content, updated_on
                ) VALUES
                  (
                    'cn-civil-code-20210101-82-decoy', 'cn-civil-code',
                    'cn-civil-code-20210101', '第八十二条', 82,
                    '配对测试干扰条文', '该条仅用于验证法名与条号不得笛卡尔交叉。', '2026-07-15'
                  ),
                  (
                    'cn-labor-contract-law-20130701-577-decoy', 'cn-labor-contract-law',
                    'cn-labor-contract-law-20130701', '第五百七十七条', 577,
                    '配对测试干扰条文', '该条仅用于验证法名与条号不得笛卡尔交叉。', '2026-07-15'
                  );
                INSERT INTO citation_metadata (id, article_id, citation_id, canonical_label) VALUES
                  (
                    'cite-civil-code-82-decoy', 'cn-civil-code-20210101-82-decoy',
                    'law:cn-civil-code:cn-civil-code-20210101:art:82-decoy',
                    '《中华人民共和国民法典》第八十二条（配对测试干扰）'
                  ),
                  (
                    'cite-labor-contract-577-decoy',
                    'cn-labor-contract-law-20130701-577-decoy',
                    'law:cn-labor-contract-law:cn-labor-contract-law-20130701:art:577-decoy',
                    '《中华人民共和国劳动合同法》第五百七十七条（配对测试干扰）'
                  );
                ",
            )
            .expect("pair decoys insert");
    }

    #[test]
    fn parser_reports_valid_invalid_duplicate_and_cross_paragraph_markers() {
        let answer = concat!(
            "ok [SRC:law:cn-civil-code:cn-civil-code-20210101:art:577] ",
            "dup [SRC:law:cn-civil-code:cn-civil-code-20210101:art:577] ",
            "bad [SRC:not a source] ",
            "range [SRC:law:cn-civil-code:cn-civil-code-20210101:art:577..580]"
        );

        let parsed = parse_source_markers(answer);

        assert_eq!(parsed.len(), 4);
        assert!(parsed[0].valid_syntax);
        assert!(parsed[1].duplicate);
        assert!(!parsed[2].valid_syntax);
        assert!(!parsed[3].valid_syntax);
    }

    #[test]
    fn structured_query_bounds_dynamic_multi_value_filters() {
        let law_names = (0..24)
            .map(|index| format!("《测试法{index}》"))
            .collect::<String>();
        let article_numbers = [
            "第一条",
            "第二条",
            "第三条",
            "第四条",
            "第五条",
            "第六条",
            "第七条",
            "第八条",
            "第九条",
            "第十条",
            "第十一条",
            "第十二条",
            "第十三条",
            "第十四条",
            "第十五条",
            "第十六条",
            "第十七条",
            "第十八条",
            "第十九条",
            "第二十条",
        ]
        .join("、");
        let request = LegalAnswerCandidatesRequest {
            question: format!("{law_names}{article_numbers}"),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: None,
            effectiveness_levels: (0..64).map(|index| format!("level-{index}")).collect(),
            include_expired: false,
            limit: Some(16),
        };

        let query = extract_structured_query(&request);

        assert_eq!(query.law_names.len(), MAX_STRUCTURED_FILTER_VALUES);
        assert_eq!(query.article_numbers.len(), MAX_STRUCTURED_FILTER_VALUES);
        assert_eq!(
            query.effectiveness_levels.len(),
            MAX_STRUCTURED_FILTER_VALUES
        );
    }

    #[test]
    fn article_ordinals_are_normalized_with_strict_numeric_boundaries() {
        for value in ["577", "577条", "第577条", "第五百七十七条"] {
            assert_eq!(parse_article_ordinal(value), Some(577), "value={value}");
            assert_eq!(normalize_article_filter_value(value), "第五百七十七条");
        }
        assert_eq!(parse_article_ordinal("1"), Some(1));
        assert_eq!(parse_article_ordinal("99999"), Some(99_999));
        for value in ["0", "100000", "第十万条", "第一个条件", "577.0"] {
            assert_eq!(parse_article_ordinal(value), None, "value={value}");
        }
        assert_eq!(
            extract_article_markers("第577条、第五百七十七条"),
            vec!["第五百七十七条"]
        );
        assert!(extract_article_markers("案号A577条和第A577条").is_empty());
        assert_eq!(
            extract_article_markers("第577条之1、第五百七十七条之一"),
            vec!["第五百七十七条之一"]
        );
        assert_eq!(
            parse_article_number("第120条之一"),
            Some(ParsedArticleNumber {
                base: 120,
                subarticle: Some(1),
            })
        );
    }

    #[test]
    fn invalid_article_like_language_is_ignored_without_hiding_a_later_marker() {
        let mut invalid_only = request();
        invalid_only.question = "第一个条件是先协商".to_owned();
        assert!(extract_structured_query(&invalid_only)
            .article_numbers
            .is_empty());

        let mut later_valid = request();
        later_valid.question = "第一次协商后，依据第577条处理".to_owned();
        assert_eq!(
            extract_structured_query(&later_valid).article_numbers,
            vec!["第五百七十七条"]
        );
    }

    #[test]
    fn quoted_law_pairs_do_not_consume_unrelated_enumeration_numbers() {
        let pairs =
            extract_law_article_pairs("《民法典》与以下法律：1、《劳动合同法》第1条、第82条");
        assert!(!pairs
            .iter()
            .any(|pair| { pair.law_name == "民法典" && pair.article_number == "第一条" }));
        assert!(pairs.iter().any(|pair| {
            pair.law_name == "劳动合同法" && pair.article_number == "第一条"
        }));
        assert!(pairs.iter().any(|pair| {
            pair.law_name == "劳动合同法" && pair.article_number == "第八十二条"
        }));
    }

    #[test]
    fn validator_keeps_repeated_existing_citations_valid_and_maps_other_failures() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let answer = concat!(
            "valid [SRC:law:cn-civil-code:cn-civil-code-20210101:art:577] ",
            "duplicate [SRC:law:cn-civil-code:cn-civil-code-20210101:art:577] ",
            "outside [SRC:law:cn-labor-contract-law:cn-labor-contract-law-20130701:art:82] ",
            "missing [SRC:law:cn-civil-code:cn-civil-code-20210101:art:999]"
        );

        let report =
            validate_answer_citations(&connection, answer, &[source], Some("2024-01-01"), false)
                .expect("citations validate");

        assert_eq!(report.valid_count, 2);
        assert_eq!(report.invalid_count, 2);
        assert_eq!(report.citations[1].status, CitationStatus::Valid);
        assert_eq!(report.citations[1].reason, None);
        assert_eq!(
            report.citations[2].reason,
            Some(CitationInvalidReason::NotInContext)
        );
        assert_eq!(
            report.citations[3].reason,
            Some(CitationInvalidReason::ParagraphNotFound)
        );
    }

    #[test]
    fn normalized_historical_stable_id_maps_to_canonical_document() {
        let connection = fixture_connection();
        insert_normalized_historical_citation_shape(&connection);

        let source = source_by_citation_id(
            &connection,
            "law:flk-historical-document:flk-version-history-20150101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("historical source exists");

        assert_eq!(source.document_id, "cn-civil-code");
        assert_eq!(source.version_id, "flk-version-history-20150101");
    }

    #[test]
    fn missing_paragraph_under_historical_stable_id_is_not_a_version_mismatch() {
        let connection = fixture_connection();
        insert_normalized_historical_citation_shape(&connection);
        let source = source_by_citation_id(
            &connection,
            "law:flk-historical-document:flk-version-history-20150101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("historical source exists");

        let report = validate_answer_citations(
            &connection,
            "[SRC:law:flk-historical-document:flk-version-history-20150101:art:999]",
            &[source],
            Some("2019-01-01"),
            false,
        )
        .expect("citations validate");

        assert_eq!(
            report.citations[0].reason,
            Some(CitationInvalidReason::ParagraphNotFound)
        );
    }

    #[test]
    fn historical_compatibility_does_not_hide_a_real_version_mismatch() {
        let connection = fixture_connection();
        insert_normalized_historical_citation_shape(&connection);

        let report = validate_answer_citations(
            &connection,
            "[SRC:law:cn-labor-contract-law:flk-version-history-20150101:art:999]",
            &[],
            Some("2019-01-01"),
            false,
        )
        .expect("citations validate");

        assert_eq!(
            report.citations[0].reason,
            Some(CitationInvalidReason::VersionMismatch)
        );
    }

    #[test]
    fn validator_rejects_case_date_outside_effective_version() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-contract-law-1999:cn-contract-law-19991001:art:107",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let report = validate_answer_citations(
            &connection,
            "[SRC:law:cn-contract-law-1999:cn-contract-law-19991001:art:107]",
            &[source],
            Some("2024-01-01"),
            false,
        )
        .expect("citations validate");

        assert_eq!(
            report.citations[0].reason,
            Some(CitationInvalidReason::DateOutOfRange)
        );
    }

    #[test]
    fn unsupported_legal_conclusion_is_flagged_when_no_valid_sources_exist() {
        let connection = fixture_connection();
        let report = validate_answer_citations(
            &connection,
            "当事人应当承担违约责任。",
            &[],
            Some("2024-01-01"),
            false,
        )
        .expect("citations validate");

        assert!(report.unsupported_legal_conclusion);
    }

    #[test]
    fn one_valid_marker_does_not_mask_a_later_uncited_legal_conclusion() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let answer = concat!(
            "违约方应当承担违约责任。",
            "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577] ",
            "法院可以直接判令其赔偿一百万元。"
        );

        let report =
            validate_answer_citations(&connection, answer, &[source], Some("2024-01-01"), false)
                .expect("citations validate");

        assert_eq!(report.valid_count, 1);
        assert!(report.unsupported_legal_conclusion);
    }

    #[test]
    fn keyword_free_payment_order_cannot_hide_behind_a_later_valid_marker() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let answer = concat!(
            "甲方须向乙方支付十万元。",
            "另据民法典，违约方应当承担违约责任。",
            "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
        );

        let report =
            validate_answer_citations(&connection, answer, &[source], Some("2024-01-01"), false)
                .expect("citations validate");

        assert_eq!(report.valid_count, 1);
        assert!(report.unsupported_legal_conclusion);
    }

    #[test]
    fn substantive_assertions_do_not_depend_on_a_finite_keyword_list() {
        let connection = fixture_connection();

        for assertion in [
            "诉请应获支持。",
            "该项请求应予驳回。",
            "被告承担十万元。",
            "甲方须向乙方支付十万元。",
        ] {
            let report =
                validate_answer_citations(&connection, assertion, &[], Some("2024-01-01"), false)
                    .expect("assertion validates");
            assert!(
                report.unsupported_legal_conclusion,
                "uncited assertion escaped coverage: {assertion}"
            );
        }
    }

    #[test]
    fn presentation_only_headings_remain_exempt_from_citation_coverage() {
        let connection = fixture_connection();
        let report = validate_answer_citations(
            &connection,
            "## 法律分析\n（一）争议焦点\n2. 结论\n— 风险提示 —",
            &[],
            Some("2024-01-01"),
            false,
        )
        .expect("headings validate");

        assert!(!report.unsupported_legal_conclusion);
        assert!(!report.semantic_support_verified);
    }

    #[test]
    fn a_real_trailing_marker_never_claims_semantic_entailment() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let report = validate_answer_citations(
            &connection,
            "法院必然判令对方赔偿一百万元。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
            &[source],
            Some("2024-01-01"),
            false,
        )
        .expect("citation structure validates");

        assert!(!report.unsupported_legal_conclusion);
        assert!(!report.semantic_support_verified);
    }

    #[test]
    fn leading_marker_cannot_support_a_following_legal_conclusion() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let answer = concat!(
            "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577] ",
            "法院可以直接判令对方赔偿一百万元。"
        );

        let report =
            validate_answer_citations(&connection, answer, &[source], Some("2024-01-01"), false)
                .expect("citations validate");

        assert_eq!(report.valid_count, 1);
        assert!(report.unsupported_legal_conclusion);
    }

    #[test]
    fn trailing_marker_cannot_cover_multiple_comma_separated_conclusions() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let answer = concat!(
            "违约方应当承担违约责任，",
            "法院可以直接判令对方赔偿一百万元。",
            "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
        );

        let report =
            validate_answer_citations(&connection, answer, &[source], Some("2024-01-01"), false)
                .expect("citations validate");

        assert_eq!(report.valid_count, 1);
        assert!(report.unsupported_legal_conclusion);
    }

    #[test]
    fn conjunction_cannot_let_one_marker_cover_two_independent_legal_claims() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        for answer in [
            concat!(
                "甲方应支付全部价款且乙方应承担刑事责任。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
            concat!(
                "甲方应支付全部价款并且法院可以判令乙方承担责任。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
        ] {
            let report = validate_answer_citations(
                &connection,
                answer,
                std::slice::from_ref(&source),
                Some("2024-06-01"),
                false,
            )
            .expect("citation validates");
            assert_eq!(report.valid_count, 1);
            assert!(report.unsupported_legal_conclusion, "answer={answer}");
        }
    }

    #[test]
    fn alternative_and_additive_connectors_cannot_hide_a_second_claim() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        for connector in ["或者", "或", "亦", "又", "还", "并可", "并应"] {
            let answer = format!(
                "合同有效{connector}合同无效。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            );
            let report = validate_answer_citations(
                &connection,
                &answer,
                std::slice::from_ref(&source),
                Some("2024-06-01"),
                false,
            )
            .expect("citation validates");

            assert_eq!(report.valid_count, 1);
            assert!(
                report.unsupported_legal_conclusion,
                "connector escaped coverage: {connector}"
            );
        }
    }

    #[test]
    fn conjunction_does_not_split_same_subject_remedy_enumerations() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        for answer in [
            concat!(
                "甲方应继续履行并且赔偿损失。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
            concat!(
                "甲方应继续履行以及赔偿损失。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
        ] {
            let report = validate_answer_citations(
                &connection,
                answer,
                std::slice::from_ref(&source),
                Some("2024-06-01"),
                false,
            )
            .expect("citation validates");
            assert_eq!(report.valid_count, 1);
            assert!(!report.unsupported_legal_conclusion, "answer={answer}");
        }
    }

    #[test]
    fn dependent_comma_and_same_subject_remedy_list_need_only_one_trailing_marker() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        for answer in [
            concat!(
                "一方不履行合同义务的，应当承担违约责任。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
            concat!(
                "违约方可以承担继续履行、采取补救措施或者赔偿损失等责任。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
            concat!(
                "一般规则：违约方应当承担违约责任。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
            concat!(
                "当事人一方不履行合同义务，守约方可以请求继续履行。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
            concat!(
                "当事人履行不符合约定，守约方可以请求采取补救措施。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
            concat!(
                "因违约造成对方损失，违约方应当赔偿损失。",
                "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            ),
        ] {
            let report = validate_answer_citations(
                &connection,
                answer,
                std::slice::from_ref(&source),
                Some("2024-06-01"),
                false,
            )
            .expect("citation validates");
            assert_eq!(report.valid_count, 1);
            assert!(!report.unsupported_legal_conclusion, "answer={answer}");
        }
    }

    #[test]
    fn trailing_marker_cannot_cover_enumerated_or_colon_separated_conclusions() {
        let connection = fixture_connection();
        let allowed = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("lookup succeeds")
        .into_iter()
        .collect::<Vec<_>>();

        for answer in [
            "甲方应支付全部价款、乙方应承担刑事责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
            "甲方应支付全部价款：乙方应承担刑事责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
            "甲方应支付全部价款:乙方应承担刑事责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
            "甲方应付款第1条：乙方应承担刑事责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
        ] {
            let report = validate_answer_citations(
                &connection,
                answer,
                &allowed,
                Some("2024-01-01"),
                false,
            )
            .expect("validation succeeds");

            assert!(report.unsupported_legal_conclusion, "answer: {answer}");
        }
    }

    #[test]
    fn enumeration_prefix_time_ratio_and_provision_label_do_not_create_false_gaps() {
        let connection = fixture_connection();
        let allowed = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("lookup succeeds")
        .into_iter()
        .collect::<Vec<_>>();

        for answer in [
            "1、违约方应承担责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
            "违约金比例为1:2。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
            "《民法典》第五百七十七条：违约方应承担责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
        ] {
            let report = validate_answer_citations(
                &connection,
                answer,
                &allowed,
                Some("2024-01-01"),
                false,
            )
            .expect("validation succeeds");

            assert!(!report.unsupported_legal_conclusion, "answer: {answer}");
        }
    }

    #[test]
    fn marker_after_first_clause_cannot_cover_an_appended_claim() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let answer = concat!(
            "违约方应当承担违约责任",
            "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]，",
            "法院可以直接判处其有期徒刑。"
        );

        let report =
            validate_answer_citations(&connection, answer, &[source], Some("2024-01-01"), false)
                .expect("citations validate");

        assert_eq!(report.valid_count, 1);
        assert!(report.unsupported_legal_conclusion);
    }

    #[test]
    fn only_a_pure_source_refusal_is_exempt_from_coverage() {
        let connection = fixture_connection();
        let pure_refusal = validate_answer_citations(
            &connection,
            "当前来源不足，但不能据此得出法律结论。",
            &[],
            Some("2024-01-01"),
            false,
        )
        .expect("pure refusal validates");
        let mixed_claim = validate_answer_citations(
            &connection,
            "当前来源不足，但法院可以直接判令对方赔偿一百万元。",
            &[],
            Some("2024-01-01"),
            false,
        )
        .expect("mixed refusal validates");

        assert!(!pure_refusal.unsupported_legal_conclusion);
        assert!(mixed_claim.unsupported_legal_conclusion);
    }

    #[test]
    fn thousands_separators_do_not_create_false_uncovered_clauses() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");

        for amount in ["1,000,000", "1，000，000"] {
            let answer = format!(
                "法院可以判令赔偿{amount}元。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
            );
            let report = validate_answer_citations(
                &connection,
                &answer,
                std::slice::from_ref(&source),
                Some("2024-01-01"),
                false,
            )
            .expect("citation validates");

            assert!(!report.unsupported_legal_conclusion, "amount {amount}");
        }
    }

    #[test]
    fn every_cited_legal_sentence_passes_nearby_marker_coverage() {
        let connection = fixture_connection();
        let source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        let answer = concat!(
            "违约方应当承担违约责任。",
            "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]\n",
            "守约方可以请求赔偿损失。",
            "[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]"
        );

        let report =
            validate_answer_citations(&connection, answer, &[source], Some("2024-01-01"), false)
                .expect("citations validate");

        assert_eq!(report.valid_count, 2);
        assert!(!report.unsupported_legal_conclusion);
    }

    #[test]
    fn context_builder_returns_source_bounded_prompt() {
        let connection = fixture_connection();
        let mut req = request();
        req.question = String::new();
        let context = build_legal_answer_context(&connection, &req).expect("context builds");

        assert!(!context.sources.is_empty());
        assert!(context.prompt.contains("[SRC:"));
        assert!(context.prompt.contains("不得编造 source id"));
    }

    #[test]
    fn arabic_article_number_matches_chinese_database_number_without_keyword_fallback() {
        let connection = fixture_connection();
        let request = LegalAnswerCandidatesRequest {
            question: "《民法典》第577条".to_owned(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: Some("2024-06-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(8),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");
        assert_eq!(context.query.article_numbers, vec!["第五百七十七条"]);
        assert!(context.query.keywords.is_empty());
        assert_eq!(context.sources.len(), 1);
        assert_eq!(context.sources[0].document_id, "cn-civil-code");
        assert_eq!(context.sources[0].article_number, "第五百七十七条");
        assert!(!context
            .warnings
            .contains(&"keyword_search_relaxed_for_exact_filters".to_owned()));

        let nonexistent_subarticle = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: Some("民法典".to_owned()),
            article_number: Some("第577条之99999".to_owned()),
            keywords: Vec::new(),
            case_date: Some("2024-06-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(8),
        };
        let nonexistent = build_legal_answer_context(&connection, &nonexistent_subarticle)
            .expect("nonexistent sub-article search is safe");
        assert!(nonexistent.sources.is_empty());
    }

    #[test]
    fn law_aliases_are_resolved_without_leaking_into_longer_law_titles() {
        let connection = fixture_connection();
        connection
            .execute(
                "INSERT INTO law_aliases (id, document_id, alias, normalized_alias)
                 VALUES ('alias-civil-code-test-nonsubstring', 'cn-civil-code', ?1, ?1)",
                ["民事基本法典"],
            )
            .expect("test alias inserts");
        let alias_request = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: Some("民事基本法典".to_owned()),
            article_number: Some("577".to_owned()),
            keywords: Vec::new(),
            case_date: Some("2024-06-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(8),
        };
        let alias_context =
            build_legal_answer_context(&connection, &alias_request).expect("alias context builds");
        assert_eq!(alias_context.sources.len(), 1);
        assert_eq!(alias_context.sources[0].document_id, "cn-civil-code");

        let ambiguous_substring_request = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: Some("合同法".to_owned()),
            article_number: Some("第十条".to_owned()),
            keywords: Vec::new(),
            case_date: Some("2019-06-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(8),
        };
        let substring_context =
            build_legal_answer_context(&connection, &ambiguous_substring_request)
                .expect("substring context builds");
        assert!(substring_context.sources.is_empty());
    }

    #[test]
    fn inferred_non_law_book_title_relaxes_only_after_strict_zero_hit() {
        let connection = fixture_connection();
        let inferred_request = LegalAnswerCandidatesRequest {
            question: "《房屋买卖合同》中的违约条款是否有效？".to_owned(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: Some("2024-06-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(8),
        };
        let inferred = build_legal_answer_context(&connection, &inferred_request)
            .expect("inferred-title context builds");
        assert!(inferred
            .warnings
            .contains(&"inferred_law_name_filter_relaxed".to_owned()));
        assert!(inferred.sources.iter().any(|source| {
            source.document_id == "cn-civil-code" && source.article_number == "第五百七十七条"
        }));

        let explicit_request = LegalAnswerCandidatesRequest {
            law_name: Some("房屋买卖合同".to_owned()),
            ..inferred_request
        };
        let explicit = build_legal_answer_context(&connection, &explicit_request)
            .expect("explicit-title context builds");
        assert!(explicit.sources.is_empty());
        assert!(!explicit
            .warnings
            .contains(&"inferred_law_name_filter_relaxed".to_owned()));
    }

    #[test]
    fn natural_question_four_grams_recall_current_civil_code_article() {
        let connection = fixture_connection();
        let request = LegalAnswerCandidatesRequest {
            question: "当事人不履行合同义务如何处理".to_owned(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: Some("2024-06-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(8),
        };
        let context = build_legal_answer_context(&connection, &request).expect("context builds");
        assert_eq!(context.query.keywords.len(), 7);
        assert!(context
            .query
            .keywords
            .iter()
            .all(|keyword| keyword.chars().count() == 4 && !keyword.contains("如何")));
        assert!(context.sources.iter().any(|source| {
            source.document_id == "cn-civil-code" && source.article_number == "第五百七十七条"
        }));
        assert!(context
            .sources
            .iter()
            .all(|source| source.document_id != "cn-contract-law-1999"));
    }

    #[test]
    fn paired_multi_law_question_rejects_cross_product_decoys() {
        let connection = fixture_connection();
        insert_cross_pair_decoys(&connection);
        let paired_request = LegalAnswerCandidatesRequest {
            question: "《民法典》第577条；《劳动合同法》第82条分别如何适用？".to_owned(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: Some("2024-06-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };
        let paired = build_legal_answer_context(&connection, &paired_request)
            .expect("paired context builds");
        let source_ids = paired
            .sources
            .iter()
            .map(|source| source.source_id.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(source_ids.len(), 2);
        assert!(source_ids.contains("law:cn-civil-code:cn-civil-code-20210101:art:577"));
        assert!(
            source_ids.contains("law:cn-labor-contract-law:cn-labor-contract-law-20130701:art:82")
        );

        let ambiguous_request = LegalAnswerCandidatesRequest {
            question: "《民法典》《劳动合同法》第577条、第82条".to_owned(),
            ..paired_request
        };
        let ambiguous = build_legal_answer_context(&connection, &ambiguous_request)
            .expect("ambiguous context fails closed");
        assert!(ambiguous.sources.is_empty());
        assert!(ambiguous
            .warnings
            .contains(&"ambiguous_law_article_pairing".to_owned()));
        assert!(ambiguous
            .warnings
            .contains(&"no_local_sources_found".to_owned()));
    }

    #[test]
    fn context_builder_includes_multiple_laws() {
        let connection = fixture_connection();
        let request = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: Some("2024-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");
        let document_ids = context
            .sources
            .iter()
            .map(|source| source.document_id.as_str())
            .collect::<HashSet<_>>();

        assert!(document_ids.contains("cn-civil-code"));
        assert!(document_ids.contains("cn-labor-contract-law"));
    }

    #[test]
    fn explicit_law_and_article_override_question_inferences() {
        let connection = fixture_connection();
        let request = LegalAnswerCandidatesRequest {
            question: "对比《中华人民共和国劳动合同法》第八十二条".to_owned(),
            law_name: Some("中华人民共和国民法典".to_owned()),
            article_number: Some("577".to_owned()),
            keywords: vec!["违约责任".to_owned()],
            case_date: Some("2024-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");
        assert_eq!(context.query.law_names, vec!["中华人民共和国民法典"]);
        assert_eq!(context.query.article_numbers, vec!["第五百七十七条"]);
        assert_eq!(context.sources.len(), 1);
        assert_eq!(context.sources[0].document_id, "cn-civil-code");
        assert_eq!(context.sources[0].article_number, "第五百七十七条");
    }

    #[test]
    fn context_builder_applies_every_article_number_filter_without_keywords() {
        let connection = fixture_connection();
        let request = LegalAnswerCandidatesRequest {
            question: "第五百七十七条、第八十二条".to_owned(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: Some("2024-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");
        let article_numbers = context
            .sources
            .iter()
            .map(|source| source.article_number.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(context.query.article_numbers.len(), 2);
        assert!(article_numbers.contains("第五百七十七条"));
        assert!(article_numbers.contains("第八十二条"));
        assert_eq!(article_numbers.len(), 2);
    }

    #[test]
    fn context_builder_matches_multiple_keywords_as_individual_terms() {
        let connection = fixture_connection();
        let request = LegalAnswerCandidatesRequest {
            question: "违约责任如何承担".to_owned(),
            law_name: Some("中华人民共和国民法典".to_owned()),
            article_number: None,
            keywords: vec![
                "违约责任".to_owned(),
                "继续履行".to_owned(),
                "赔偿损失".to_owned(),
            ],
            case_date: Some("2024-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");

        assert!(context
            .sources
            .iter()
            .any(|source| source.article_number == "第五百七十七条"));
    }

    #[test]
    fn exact_law_and_article_relax_zero_hit_keywords_with_warning() {
        let connection = fixture_connection();
        let request = LegalAnswerCandidatesRequest {
            question: "查询明确法条".to_owned(),
            law_name: Some("中华人民共和国民法典".to_owned()),
            article_number: Some("第五百七十七条".to_owned()),
            keywords: vec!["该法条绝不包含的关键词".to_owned()],
            case_date: Some("2024-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");

        assert_eq!(context.sources.len(), 1);
        assert_eq!(context.sources[0].article_number, "第五百七十七条");
        assert!(context
            .warnings
            .iter()
            .any(|warning| warning == "keyword_search_relaxed_for_exact_filters"));
    }

    #[test]
    fn dated_search_excludes_repealed_unknown_end_even_when_expired_is_requested() {
        let connection = fixture_connection();
        insert_unknown_ended_repealed_version(&connection);
        let request = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: Some("中华人民共和国合同法".to_owned()),
            article_number: Some("第一百零七条".to_owned()),
            keywords: Vec::new(),
            case_date: Some("2019-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: true,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");

        assert!(context
            .sources
            .iter()
            .all(|source| source.version_id != "cn-contract-law-unknown-end"));
        assert!(context
            .warnings
            .iter()
            .any(|warning| warning == "historical_effective_to_unknown_excluded"));
    }

    #[test]
    fn keyword_only_dated_search_warns_when_unknown_end_candidates_are_excluded() {
        let connection = fixture_connection();
        insert_unknown_ended_repealed_version(&connection);
        let request = LegalAnswerCandidatesRequest {
            question: "违约责任如何承担".to_owned(),
            law_name: None,
            article_number: None,
            keywords: vec!["违约责任".to_owned()],
            case_date: Some("2019-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");

        assert!(context
            .sources
            .iter()
            .all(|source| source.version_id != "cn-contract-law-unknown-end"));
        assert!(context
            .warnings
            .iter()
            .any(|warning| warning == "historical_effective_to_unknown_excluded"));
    }

    #[test]
    fn validator_never_treats_repealed_unknown_end_as_effective_on_a_dated_case() {
        let connection = fixture_connection();
        insert_unknown_ended_repealed_version(&connection);
        let source = source_by_citation_id(
            &connection,
            "law:cn-contract-law-1999:cn-contract-law-unknown-end:art:107",
        )
        .expect("source lookup succeeds")
        .expect("source exists");

        let report = validate_answer_citations(
            &connection,
            "当事人应当承担违约责任。[SRC:law:cn-contract-law-1999:cn-contract-law-unknown-end:art:107]",
            &[source],
            Some("2019-01-01"),
            true,
        )
        .expect("citations validate");

        assert_eq!(report.valid_count, 0);
        assert_eq!(report.invalid_count, 1);
        assert_eq!(
            report.citations[0].reason,
            Some(CitationInvalidReason::DateOutOfRange)
        );
        assert!(report.unsupported_legal_conclusion);
    }

    #[test]
    fn context_builder_applies_every_effectiveness_level_filter() {
        let connection = fixture_connection();
        connection
            .execute_batch(
                "
                UPDATE law_documents
                SET effectiveness_level = 'administrative_regulation'
                WHERE id = 'cn-labor-contract-law';
                UPDATE law_documents
                SET effectiveness_level = 'judicial_interpretation'
                WHERE id = 'cn-contract-law-1999';
                ",
            )
            .expect("fixture effectiveness levels update");
        let request = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: None,
            effectiveness_levels: vec![
                "national_law".to_owned(),
                "administrative_regulation".to_owned(),
            ],
            include_expired: true,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");
        let document_ids = context
            .sources
            .iter()
            .map(|source| source.document_id.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(context.query.effectiveness_levels.len(), 2);
        assert!(document_ids.contains("cn-civil-code"));
        assert!(document_ids.contains("cn-labor-contract-law"));
        assert!(!document_ids.contains("cn-contract-law-1999"));
        assert_eq!(document_ids.len(), 2);
    }

    #[test]
    fn context_builder_can_include_multiple_versions_when_fixture_supplies_them() {
        let connection = fixture_connection();
        insert_historical_civil_code_version(&connection);
        let request = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: Some("中华人民共和国民法典".to_owned()),
            article_number: Some("第五百七十七条".to_owned()),
            keywords: Vec::new(),
            case_date: None,
            effectiveness_levels: Vec::new(),
            include_expired: true,
            limit: Some(16),
        };

        let context = build_legal_answer_context(&connection, &request).expect("context builds");
        let versions = context
            .sources
            .iter()
            .map(|source| source.version_id.as_str())
            .collect::<HashSet<_>>();

        assert!(versions.contains("cn-civil-code-20150101"));
        assert!(versions.contains("cn-civil-code-20210101"));
    }

    #[test]
    fn context_builder_filters_expired_versions_by_case_date() {
        let connection = fixture_connection();
        insert_historical_civil_code_version(&connection);
        let mut request = LegalAnswerCandidatesRequest {
            question: "违约责任".to_owned(),
            law_name: Some("中华人民共和国民法典".to_owned()),
            article_number: None,
            keywords: vec!["违约责任".to_owned()],
            case_date: Some("2019-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };

        let historical =
            build_legal_answer_context(&connection, &request).expect("historical context builds");
        assert!(historical
            .sources
            .iter()
            .any(|source| source.version_id == "cn-civil-code-20150101"));
        assert!(historical
            .sources
            .iter()
            .all(|source| source.version_id != "cn-civil-code-20210101"));

        request.case_date = Some("2024-01-01".to_owned());
        let current =
            build_legal_answer_context(&connection, &request).expect("current context builds");
        assert!(current
            .sources
            .iter()
            .any(|source| source.version_id == "cn-civil-code-20210101"));
        assert!(current
            .sources
            .iter()
            .all(|source| source.version_id != "cn-civil-code-20150101"));
    }

    #[test]
    fn context_prompt_truncates_long_articles_and_records_warning() {
        let connection = fixture_connection();
        let mut source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        source.content = format!("{}TAIL", "长".repeat(MAX_CONTEXT_CHARS_PER_SOURCE + 20));
        let query = extract_structured_query(&request());
        let mut warnings = Vec::new();

        let prompt = assemble_source_bounded_prompt(&query, &[source.clone()], &mut warnings);

        assert!(warnings.contains(&format!("source_truncated:{}", source.source_id)));
        assert!(prompt.contains("长长长"));
        assert!(!prompt.contains("TAIL"));
    }

    #[test]
    fn context_assembly_matches_multi_law_version_truncation_and_expiry_snapshot() {
        let connection = fixture_connection();
        insert_historical_civil_code_version(&connection);
        let mut snapshot = String::new();

        let multi_law_request = LegalAnswerCandidatesRequest {
            question: concat!(
                "《中华人民共和国民法典》第五百七十七条；",
                "《中华人民共和国劳动合同法》第八十二条"
            )
            .to_owned(),
            law_name: None,
            article_number: None,
            keywords: Vec::new(),
            case_date: Some("2024-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };
        let multi_law =
            build_legal_answer_context(&connection, &multi_law_request).expect("context builds");
        writeln!(snapshot, "== multi-law ==").expect("snapshot writes");
        writeln!(snapshot, "law_names={:?}", multi_law.query.law_names).expect("snapshot writes");
        writeln!(
            snapshot,
            "article_numbers={:?}",
            multi_law.query.article_numbers
        )
        .expect("snapshot writes");
        write_source_snapshot(&mut snapshot, &multi_law.sources);

        let multi_version_request = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: Some("中华人民共和国民法典".to_owned()),
            article_number: Some("第五百七十七条".to_owned()),
            keywords: Vec::new(),
            case_date: None,
            effectiveness_levels: Vec::new(),
            include_expired: true,
            limit: Some(16),
        };
        let multi_version = build_legal_answer_context(&connection, &multi_version_request)
            .expect("context builds");
        writeln!(snapshot, "== multi-version ==").expect("snapshot writes");
        write_source_snapshot(&mut snapshot, &multi_version.sources);

        let mut long_source = source_by_citation_id(
            &connection,
            "law:cn-civil-code:cn-civil-code-20210101:art:577",
        )
        .expect("source lookup succeeds")
        .expect("source exists");
        long_source.content = format!("{}TAIL", "长".repeat(MAX_CONTEXT_CHARS_PER_SOURCE + 20));
        let mut truncation_warnings = Vec::new();
        let truncated_prompt = assemble_source_bounded_prompt(
            &multi_law.query,
            &[long_source],
            &mut truncation_warnings,
        );
        writeln!(snapshot, "== truncation ==").expect("snapshot writes");
        writeln!(snapshot, "warnings={truncation_warnings:?}").expect("snapshot writes");
        writeln!(
            snapshot,
            "retained_long_chars={} tail_visible={}",
            truncated_prompt.matches('长').count(),
            truncated_prompt.contains("TAIL")
        )
        .expect("snapshot writes");

        let mut expired_request = LegalAnswerCandidatesRequest {
            question: String::new(),
            law_name: Some("中华人民共和国合同法".to_owned()),
            article_number: Some("第一百零七条".to_owned()),
            keywords: Vec::new(),
            case_date: None,
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(16),
        };
        let expired_filtered = build_legal_answer_context(&connection, &expired_request)
            .expect("filtered context builds");
        expired_request.include_expired = true;
        let expired_included = build_legal_answer_context(&connection, &expired_request)
            .expect("included context builds");
        writeln!(snapshot, "== expired-filter ==").expect("snapshot writes");
        writeln!(
            snapshot,
            "filtered_count={}",
            expired_filtered.sources.len()
        )
        .expect("snapshot writes");
        write_source_snapshot(&mut snapshot, &expired_included.sources);

        assert_eq!(
            normalize_newlines(&snapshot),
            normalize_newlines(include_str!("../testdata/context_assembly.snap"))
        );
    }

    fn normalize_newlines(value: &str) -> String {
        value.replace("\r\n", "\n").replace('\r', "\n")
    }

    fn write_source_snapshot(snapshot: &mut String, sources: &[LegalSource]) {
        for source in sources {
            writeln!(
                snapshot,
                "{} | {} | {} | {}",
                source.document_title, source.version_id, source.article_number, source.source_id
            )
            .expect("snapshot writes");
        }
    }
}
