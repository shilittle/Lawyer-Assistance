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
    let mut sources = search_sources_fts(connection, &query, bounded_limit(request.limit))?;

    if sources.is_empty() {
        sources = search_sources_like(connection, &query, bounded_limit(request.limit))?;
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

pub fn extract_structured_query(request: &LegalAnswerCandidatesRequest) -> StructuredLegalQuery {
    let mut law_names = Vec::new();
    if let Some(law_name) = normalized_non_empty(request.law_name.as_deref()) {
        law_names.push(law_name);
    }
    law_names.extend(extract_quoted_law_names(&request.question));
    dedup_preserve_order(&mut law_names);
    law_names.truncate(MAX_STRUCTURED_FILTER_VALUES);

    let mut article_numbers = Vec::new();
    if let Some(article_number) = normalized_non_empty(request.article_number.as_deref()) {
        article_numbers.push(article_number);
    }
    article_numbers.extend(extract_article_markers(&request.question));
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
        "你只能依据下列本地法律来源回答。每个法律结论必须紧跟对应的 [SRC:...] 标记；如果来源不足，直接说明无法由当前来源支持。\n",
    );
    prompt.push_str("不得引用未列出的来源，不得编造 source id。\n\n");
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
            source.effective_to.as_deref().unwrap_or("现行/未注明终止"),
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
    let allowed_by_id = allowed_sources
        .iter()
        .map(|source| (source.source_id.as_str(), source))
        .collect::<HashMap<_, _>>();
    let mut citations = Vec::new();

    for citation in parsed {
        let (status, reason, source) = if !citation.valid_syntax {
            (
                CitationStatus::Invalid,
                Some(CitationInvalidReason::InvalidSyntax),
                None,
            )
        } else if citation.duplicate {
            (
                CitationStatus::Invalid,
                Some(CitationInvalidReason::Duplicate),
                allowed_by_id
                    .get(citation.source_id.as_str())
                    .map(|source| (*source).clone()),
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
            raw_marker: citation.raw_marker,
            source_id: citation.source_id,
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

    Ok(CitationValidationReport {
        citations,
        valid_count,
        invalid_count,
        unsupported_legal_conclusion: valid_count == 0 && looks_like_legal_answer(answer),
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
    let Some(search_text) = primary_search_text(query) else {
        return Ok(Vec::new());
    };

    let fts_query = quote_fts_query(&search_text);
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
            source.snippet = snippet_for(&search_text, &source.content);
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
    let search_text = primary_search_text(query).unwrap_or_default();
    let is_empty = search_text.trim().is_empty();
    let search_like = like_pattern(&search_text);
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
    if include_expired {
        return true;
    }

    let Some(case_date) = case_date else {
        return source.version_status == "in_force";
    };

    let date_matches = source.effective_from.as_str() <= case_date
        && source
            .effective_to
            .as_deref()
            .map(|effective_to| effective_to >= case_date)
            .unwrap_or(true);
    let status_matches = source.version_status == "in_force" || source.effective_to.is_some();

    date_matches && status_matches
}

fn looks_like_legal_answer(answer: &str) -> bool {
    let trimmed = answer.trim();
    !trimmed.is_empty()
        && [
            "应当", "可以", "不得", "责任", "义务", "权利", "法律", "法院", "合同", "赔偿",
        ]
        .iter()
        .any(|keyword| trimmed.contains(keyword))
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
    let mut names = Vec::new();
    let mut rest = question;

    while let Some(start) = rest.find('《') {
        let after_start = &rest[start + '《'.len_utf8()..];
        let Some(end) = after_start.find('》') else {
            break;
        };
        if let Some(name) = normalized_non_empty(Some(&after_start[..end])) {
            names.push(name);
        }
        rest = &after_start[end + '》'.len_utf8()..];
    }

    names
}

fn extract_article_markers(question: &str) -> Vec<String> {
    let mut markers = Vec::new();
    let mut rest = question;

    while let Some(start) = rest.find('第') {
        let after_start = &rest[start..];
        let Some(end) = after_start.find('条') else {
            break;
        };
        let marker = &after_start[..end + '条'.len_utf8()];
        if marker.chars().count() <= 18 {
            markers.push(marker.to_owned());
        }
        rest = &after_start[end + '条'.len_utf8()..];
    }

    markers
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
        cleaned = cleaned.replace(article_number, " ");
    }
    for separator in [
        '，', '。', '？', '?', '！', '!', '；', ';', '、', '：', ':', '（', '）', '(', ')', '《',
        '》', '"', '\'',
    ] {
        cleaned = cleaned.replace(separator, " ");
    }

    cleaned
        .split_whitespace()
        .filter_map(|part| {
            let part = part.trim();
            if part.chars().count() >= 2 {
                Some(part.to_owned())
            } else {
                None
            }
        })
        .collect()
}

fn primary_search_text(query: &StructuredLegalQuery) -> Option<String> {
    if !query.keywords.is_empty() {
        return Some(query.keywords.join(" "));
    }

    if !query.law_names.is_empty()
        || !query.article_numbers.is_empty()
        || !query.effectiveness_levels.is_empty()
    {
        return None;
    }

    normalized_non_empty(Some(&query.legal_issue))
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
    append_like_any_clause(&mut sql, "documents.title", "law_like", &query.law_names);
    append_like_any_clause(
        &mut sql,
        "articles.article_number",
        "article_like",
        &query.article_numbers,
    );
    append_like_any_clause(
        &mut sql,
        "documents.effectiveness_level",
        "level_like",
        &query.effectiveness_levels,
    );
    sql
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

    append_like_parameters(&mut parameters, "law_like", &query.law_names);
    append_like_parameters(&mut parameters, "article_like", &query.article_numbers);
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

fn quote_fts_query(query: &str) -> String {
    format!("\"{}\"", query.replace('"', "\"\""))
}

fn clean_snippet(raw_snippet: &str, content: &str) -> String {
    let trimmed = raw_snippet.trim();
    if trimmed.is_empty() {
        truncate_chars(content, MAX_SOURCE_SNIPPET_CHARS)
    } else {
        truncate_chars(trimmed, MAX_SOURCE_SNIPPET_CHARS)
    }
}

fn snippet_for(query: &str, content: &str) -> String {
    let query = query.trim();
    if query.is_empty() {
        return truncate_chars(content, MAX_SOURCE_SNIPPET_CHARS);
    }

    let Some(byte_index) = content.find(query) else {
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
    fn validator_maps_existing_missing_duplicate_and_out_of_context_sources() {
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

        assert_eq!(report.valid_count, 1);
        assert_eq!(report.invalid_count, 3);
        assert_eq!(
            report.citations[1].reason,
            Some(CitationInvalidReason::Duplicate)
        );
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
    fn context_builder_applies_every_law_name_filter() {
        let connection = fixture_connection();
        let request = LegalAnswerCandidatesRequest {
            question: "《中华人民共和国劳动合同法》中的合同规则".to_owned(),
            law_name: Some("中华人民共和国民法典".to_owned()),
            article_number: None,
            keywords: vec!["合同".to_owned()],
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

        assert_eq!(context.query.law_names.len(), 2);
        assert!(document_ids.contains("cn-civil-code"));
        assert!(document_ids.contains("cn-labor-contract-law"));
        assert_eq!(document_ids.len(), 2);
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
            question:
                "《中华人民共和国民法典》《中华人民共和国劳动合同法》第五百七十七条、第八十二条"
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

        assert_eq!(snapshot, include_str!("../testdata/context_assembly.snap"));
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
