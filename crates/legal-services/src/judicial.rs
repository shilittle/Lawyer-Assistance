use crate::{
    filesystem::PathIdentityGuard, require_schema_version, validate_identifier, validate_text,
    LegalServices, ServiceError, SERVICE_SCHEMA_VERSION,
};
use rusqlite::{params_from_iter, types::Value, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use url::Url;

const JUDICIAL_CASE_SCHEMA_VERSION: &str = "1";
const MAX_SEARCH_QUERY_BYTES: usize = 16 * 1024;
const MAX_SEARCH_LIMIT: u32 = 50;
const MAX_SEARCH_OFFSET: u32 = 10_000;
const MAX_CASE_ID_BYTES: usize = 128;
const MAX_CASE_TITLE_BYTES: usize = 2 * 1024;
const MAX_CASE_TEXT_BYTES: usize = 512 * 1024;
const MAX_MATCHED_TEXT_CHARS: usize = 1_500;
const MAX_KEYWORDS: usize = 64;
const MAX_KEYWORD_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JudicialCaseSearchRequest {
    pub schema_version: u16,
    pub query: String,
    /// `guiding` covers Supreme People's Court guiding cases. `reference`
    /// covers the supplementary, official reference corpus. `typical` covers
    /// an official typical-case collection article as one searchable document;
    /// a collection article is deliberately not flattened into references.
    pub case_type: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub include_withdrawn: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JudicialCaseSummary {
    pub case_id: String,
    pub title: String,
    pub case_type: String,
    pub guiding_number: Option<u32>,
    pub reference_number: Option<String>,
    pub keywords: Vec<String>,
    pub publication_date: Option<String>,
    pub court: Option<String>,
    pub case_number: Option<String>,
    pub status: String,
    pub source_url: String,
    pub matched_text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JudicialCaseSearchResponse {
    pub schema_version: u16,
    pub cases: Vec<JudicialCaseSummary>,
    pub total: u32,
    pub database_version: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JudicialCaseGetRequest {
    pub schema_version: u16,
    pub case_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JudicialCaseDetail {
    #[serde(flatten)]
    pub summary: JudicialCaseSummary,
    pub key_points: Vec<String>,
    pub basic_facts: String,
    pub judgment_result: String,
    pub reasoning: String,
    pub related_laws: Vec<String>,
    pub full_text: String,
    pub fetched_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JudicialCaseGetResponse {
    pub schema_version: u16,
    pub case: JudicialCaseDetail,
    pub database_version: String,
    pub warnings: Vec<String>,
}

/// Availability deliberately has a separate response from query failures so
/// callers can keep statute retrieval usable while the optional sidecar is
/// absent or being replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JudicialCaseStatusResponse {
    pub schema_version: u16,
    pub available: bool,
    pub database_version: Option<String>,
    pub total: u64,
    pub guiding_count: u64,
    pub reference_count: u64,
    pub typical_count: u64,
    pub last_fetched_at: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct JudicialCaseDatabaseIdentity {
    database_version: String,
}

#[derive(Debug)]
struct JudicialCaseRow {
    case_id: String,
    title: String,
    case_type: String,
    guiding_number: Option<i64>,
    reference_number: Option<String>,
    keywords_json: String,
    publication_date: Option<String>,
    court: Option<String>,
    case_number: Option<String>,
    status: String,
    source_url: String,
    search_text: String,
    key_points_json: Option<String>,
    basic_facts: Option<String>,
    judgment_result: Option<String>,
    reasoning: Option<String>,
    related_laws_json: Option<String>,
    full_text: Option<String>,
    fetched_at: Option<String>,
    content_sha256: Option<String>,
}

impl LegalServices {
    pub fn judicial_case_search(
        &self,
        request: JudicialCaseSearchRequest,
    ) -> Result<JudicialCaseSearchResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_text("query", &request.query, MAX_SEARCH_QUERY_BYTES, false)?;
        let case_type = validate_case_type(request.case_type.as_deref())?;
        let limit = request.limit.unwrap_or(20);
        if !(1..=MAX_SEARCH_LIMIT).contains(&limit) {
            return Err(ServiceError::invalid(
                "limit",
                "limit must be between 1 and 50",
            ));
        }
        let offset = request.offset.unwrap_or(0);
        if offset > MAX_SEARCH_OFFSET {
            return Err(ServiceError::invalid(
                "offset",
                "offset must not exceed 10000",
            ));
        }
        let (connection, identity) =
            open_validated_judicial_cases_database(self.legal_core_path())?;
        let normalized = normalize_query(&request.query);
        let exact_guiding_number = guiding_number_from_query(&normalized);
        let terms = search_terms(&normalized);
        let (where_clause, bindings) = search_where_clause(
            case_type.as_deref(),
            request.include_withdrawn.unwrap_or(false),
            exact_guiding_number,
            &terms,
        );
        let count_sql = format!("SELECT COUNT(*) FROM judicial_cases WHERE {where_clause}");
        let total: i64 =
            connection.query_row(&count_sql, params_from_iter(bindings.iter()), |row| {
                row.get(0)
            })?;
        let (ranking_sql, ranking_bindings) =
            ranking_expression(&normalized, &terms, exact_guiding_number);
        let select_sql = format!(
            "SELECT case_id, title, case_type, guiding_number, reference_number, keywords_json, \
                    publication_date, court, case_number, status, source_url, search_text, \
                    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL \
             FROM judicial_cases WHERE {where_clause} \
             ORDER BY ({ranking_sql}) DESC, CASE case_type WHEN 'guiding' THEN 1 ELSE 0 END DESC, \
                      publication_date DESC, case_id ASC LIMIT ? OFFSET ?"
        );
        let mut all_bindings = bindings;
        all_bindings.extend(ranking_bindings);
        all_bindings.push(Value::Integer(i64::from(limit)));
        all_bindings.push(Value::Integer(i64::from(offset)));
        let mut statement = connection.prepare(&select_sql)?;
        let rows = statement
            .query_map(
                params_from_iter(all_bindings.iter()),
                judicial_case_row_from_search,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut cases = Vec::with_capacity(rows.len());
        for row in rows {
            cases.push(summary_from_row(&row, &normalized, &terms)?);
        }
        let mut warnings = Vec::new();
        if cases.is_empty() {
            warnings.push("no_local_results_found".to_owned());
        }
        if !request.include_withdrawn.unwrap_or(false) {
            warnings.push("withdrawn_cases_excluded".to_owned());
        }
        Ok(JudicialCaseSearchResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            cases,
            total: u32::try_from(total).unwrap_or(u32::MAX),
            database_version: identity.database_version,
            warnings,
        })
    }

    pub fn judicial_case_get(
        &self,
        request: JudicialCaseGetRequest,
    ) -> Result<JudicialCaseGetResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("caseId", &request.case_id)?;
        let (connection, identity) =
            open_validated_judicial_cases_database(self.legal_core_path())?;
        let row = connection
            .query_row(
                "SELECT case_id, title, case_type, guiding_number, reference_number, keywords_json, \
                        publication_date, court, case_number, status, source_url, search_text, \
                        key_points_json, basic_facts, judgment_result, reasoning, related_laws_json, \
                        full_text, fetched_at, content_sha256 \
                 FROM judicial_cases WHERE case_id = ?1",
                [&request.case_id],
                judicial_case_row_from_detail,
            )
            .optional()?
            .ok_or_else(|| ServiceError::not_found("judicial_case"))?;
        let case = detail_from_row(row)?;
        Ok(JudicialCaseGetResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            case,
            database_version: identity.database_version,
            warnings: Vec::new(),
        })
    }

    pub fn judicial_case_status(&self) -> Result<JudicialCaseStatusResponse, ServiceError> {
        match open_validated_judicial_cases_database(self.legal_core_path()) {
            Ok((connection, identity)) => {
                let (total, guiding_count, reference_count, typical_count, last_fetched_at) =
                    connection.query_row(
                        "SELECT COUNT(*), \
                            COALESCE(SUM(CASE WHEN case_type = 'guiding' THEN 1 ELSE 0 END), 0), \
                            COALESCE(SUM(CASE WHEN case_type = 'reference' THEN 1 ELSE 0 END), 0), \
                            COALESCE(SUM(CASE WHEN case_type = 'typical' THEN 1 ELSE 0 END), 0), \
                            MAX(fetched_at) FROM judicial_cases",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, i64>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, Option<String>>(4)?,
                            ))
                        },
                    )?;
                Ok(JudicialCaseStatusResponse {
                    schema_version: SERVICE_SCHEMA_VERSION,
                    available: true,
                    database_version: Some(identity.database_version),
                    total: u64::try_from(total).unwrap_or(0),
                    guiding_count: u64::try_from(guiding_count).unwrap_or(0),
                    reference_count: u64::try_from(reference_count).unwrap_or(0),
                    typical_count: u64::try_from(typical_count).unwrap_or(0),
                    last_fetched_at,
                    warnings: Vec::new(),
                })
            }
            Err(error) if is_judicial_case_availability_error(&error) => {
                Ok(JudicialCaseStatusResponse {
                    schema_version: SERVICE_SCHEMA_VERSION,
                    available: false,
                    database_version: None,
                    total: 0,
                    guiding_count: 0,
                    reference_count: 0,
                    typical_count: 0,
                    last_fetched_at: None,
                    warnings: vec![error.code],
                })
            }
            Err(error) => Err(error),
        }
    }
}

fn judicial_case_database_path(legal_core_path: &Path) -> Result<PathBuf, ServiceError> {
    legal_core_path
        .parent()
        .map(|parent| parent.join("judicial_cases.sqlite"))
        .ok_or_else(|| {
            ServiceError::new(
                "judicial_case_database_missing",
                "judicial case database parent directory is unavailable",
                false,
            )
        })
}

fn open_validated_judicial_cases_database(
    legal_core_path: &Path,
) -> Result<(Connection, JudicialCaseDatabaseIdentity), ServiceError> {
    let path = judicial_case_database_path(legal_core_path)?;
    require_regular_judicial_database_file(&path)?;
    let guard = PathIdentityGuard::regular_file(&path, true)?;
    let connection = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    connection.pragma_update(None, "query_only", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    guard.verify()?;
    let identity = inspect_judicial_cases_database(&connection)?;
    guard.verify()?;
    Ok((connection, identity))
}

fn require_regular_judicial_database_file(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ServiceError::new(
            "judicial_case_database_missing",
            "judicial case database file is missing or inaccessible",
            false,
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ServiceError::new(
            "judicial_case_database_path_rejected",
            "judicial case database path must name a regular non-symlink file",
            false,
        ));
    }
    Ok(())
}

fn inspect_judicial_cases_database(
    connection: &Connection,
) -> Result<JudicialCaseDatabaseIdentity, ServiceError> {
    let metadata_table: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'database_metadata')",
        [],
        |row| row.get(0),
    )?;
    if !metadata_table {
        return Err(judicial_schema_error("database metadata table is missing"));
    }
    let entries = connection
        .prepare("SELECT key, value FROM database_metadata")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<BTreeMap<_, _>>>()?;
    if entries.get("schema_version").map(String::as_str) != Some(JUDICIAL_CASE_SCHEMA_VERSION) {
        return Err(judicial_schema_error(
            "judicial case database schema version is not supported",
        ));
    }
    let user_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if user_version != 1 {
        return Err(judicial_schema_error(
            "judicial case database PRAGMA user_version is inconsistent",
        ));
    }
    let columns = connection
        .prepare("PRAGMA table_info(judicial_cases)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
    for column in [
        "case_id",
        "title",
        "case_type",
        "guiding_number",
        "reference_number",
        "keywords_json",
        "publication_date",
        "court",
        "case_number",
        "status",
        "source_url",
        "search_text",
        "key_points_json",
        "basic_facts",
        "judgment_result",
        "reasoning",
        "related_laws_json",
        "full_text",
        "fetched_at",
        "content_sha256",
    ] {
        if !columns.contains(column) {
            return Err(judicial_schema_error(
                "judicial case database is missing a required column",
            ));
        }
    }
    let database_version = entries
        .get("dataset_version")
        .cloned()
        .unwrap_or_else(|| "schema-1".to_owned());
    validate_text("datasetVersion", &database_version, 256, false)?;
    Ok(JudicialCaseDatabaseIdentity { database_version })
}

fn judicial_schema_error(message: &'static str) -> ServiceError {
    ServiceError::new("judicial_case_database_incompatible", message, false)
}

fn is_judicial_case_availability_error(error: &ServiceError) -> bool {
    matches!(
        error.code.as_str(),
        "judicial_case_database_missing"
            | "judicial_case_database_path_rejected"
            | "judicial_case_database_incompatible"
            | "filesystem_path_rejected"
            | "filesystem_hardlink_rejected"
    )
}

fn validate_case_type(value: Option<&str>) -> Result<Option<String>, ServiceError> {
    match value {
        None => Ok(None),
        Some("guiding") => Ok(Some("guiding".to_owned())),
        Some("reference") => Ok(Some("reference".to_owned())),
        Some("typical") => Ok(Some("typical".to_owned())),
        Some(_) => Err(ServiceError::invalid(
            "caseType",
            "caseType must be guiding, reference, or typical",
        )),
    }
}

fn search_where_clause(
    case_type: Option<&str>,
    include_withdrawn: bool,
    guiding_number: Option<u32>,
    terms: &[String],
) -> (String, Vec<Value>) {
    let mut predicates = Vec::new();
    let mut bindings = Vec::new();
    if let Some(case_type) = case_type {
        predicates.push("case_type = ?".to_owned());
        bindings.push(Value::Text(case_type.to_owned()));
    }
    if !include_withdrawn {
        predicates.push("status <> 'withdrawn'".to_owned());
    }
    if let Some(guiding_number) = guiding_number {
        predicates.push("guiding_number = ?".to_owned());
        bindings.push(Value::Integer(i64::from(guiding_number)));
    } else {
        let mut matches = Vec::new();
        for term in terms {
            matches.push("instr(lower(title), lower(?)) > 0".to_owned());
            bindings.push(Value::Text(term.clone()));
            matches.push("instr(lower(keywords_json), lower(?)) > 0".to_owned());
            bindings.push(Value::Text(term.clone()));
            matches.push("instr(lower(key_points_json), lower(?)) > 0".to_owned());
            bindings.push(Value::Text(term.clone()));
            matches.push("instr(lower(case_number), lower(?)) > 0".to_owned());
            bindings.push(Value::Text(term.clone()));
            matches.push("instr(lower(reference_number), lower(?)) > 0".to_owned());
            bindings.push(Value::Text(term.clone()));
            matches.push("instr(lower(search_text), lower(?)) > 0".to_owned());
            bindings.push(Value::Text(term.clone()));
        }
        predicates.push(format!("({})", matches.join(" OR ")));
    }
    (predicates.join(" AND "), bindings)
}

fn ranking_expression(
    normalized: &str,
    terms: &[String],
    guiding_number: Option<u32>,
) -> (String, Vec<Value>) {
    if guiding_number.is_some() {
        return (
            "1000000 + CASE case_type WHEN 'guiding' THEN 100 ELSE 0 END".to_owned(),
            Vec::new(),
        );
    }
    let mut score = Vec::new();
    let mut bindings = Vec::new();
    for (column, weight) in [
        ("title", 6000),
        ("case_number", 5500),
        ("reference_number", 5000),
        ("keywords_json", 3200),
        ("key_points_json", 2800),
        ("search_text", 1600),
    ] {
        score.push(format!(
            "CASE WHEN instr(lower({column}), lower(?)) > 0 THEN {weight} ELSE 0 END"
        ));
        bindings.push(Value::Text(normalized.to_owned()));
    }
    for term in terms {
        score.push("CASE WHEN instr(lower(title), lower(?)) > 0 THEN 600 ELSE 0 END".to_owned());
        bindings.push(Value::Text(term.clone()));
        score.push(
            "CASE WHEN instr(lower(keywords_json), lower(?)) > 0 THEN 400 ELSE 0 END".to_owned(),
        );
        bindings.push(Value::Text(term.clone()));
        score.push(
            "CASE WHEN instr(lower(key_points_json), lower(?)) > 0 THEN 360 ELSE 0 END".to_owned(),
        );
        bindings.push(Value::Text(term.clone()));
        score.push(
            "CASE WHEN instr(lower(search_text), lower(?)) > 0 THEN 120 ELSE 0 END".to_owned(),
        );
        bindings.push(Value::Text(term.clone()));
    }
    (score.join(" + "), bindings)
}

fn normalize_query(query: &str) -> String {
    query.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn guiding_number_from_query(query: &str) -> Option<u32> {
    let compact: String = query
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    for prefix in ["指导案例", "指导性案例"] {
        let Some(rest) = compact.strip_prefix(prefix) else {
            continue;
        };
        let Some(digits) = rest.strip_suffix('号') else {
            continue;
        };
        if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return digits.parse().ok();
        }
    }
    None
}

fn search_terms(query: &str) -> Vec<String> {
    let mut terms = Vec::new();
    if !query.is_empty() {
        terms.push(query.to_owned());
    }
    for word in query.split(|character: char| !character.is_alphanumeric()) {
        let word = word.trim();
        if word.len() >= 2 && !terms.iter().any(|term| term == word) {
            terms.push(word.to_owned());
        }
    }
    let chinese: Vec<char> = query
        .chars()
        .filter(|character| ('\u{4e00}'..='\u{9fff}').contains(character))
        .collect();
    for window in chinese.windows(2).take(32) {
        let term: String = window.iter().collect();
        if !terms.iter().any(|existing| existing == &term) {
            terms.push(term);
        }
    }
    terms.truncate(40);
    terms
}

fn judicial_case_row_from_search(row: &rusqlite::Row<'_>) -> rusqlite::Result<JudicialCaseRow> {
    judicial_case_row_from_columns(row)
}

fn judicial_case_row_from_detail(row: &rusqlite::Row<'_>) -> rusqlite::Result<JudicialCaseRow> {
    judicial_case_row_from_columns(row)
}

fn judicial_case_row_from_columns(row: &rusqlite::Row<'_>) -> rusqlite::Result<JudicialCaseRow> {
    Ok(JudicialCaseRow {
        case_id: row.get(0)?,
        title: row.get(1)?,
        case_type: row.get(2)?,
        guiding_number: row.get(3)?,
        reference_number: row.get(4)?,
        keywords_json: row.get(5)?,
        publication_date: row.get(6)?,
        court: row.get(7)?,
        case_number: row.get(8)?,
        status: row.get(9)?,
        source_url: row.get(10)?,
        search_text: row.get(11)?,
        key_points_json: row.get(12)?,
        basic_facts: row.get(13)?,
        judgment_result: row.get(14)?,
        reasoning: row.get(15)?,
        related_laws_json: row.get(16)?,
        full_text: row.get(17)?,
        fetched_at: row.get(18)?,
        content_sha256: row.get(19)?,
    })
}

fn summary_from_row(
    row: &JudicialCaseRow,
    query: &str,
    terms: &[String],
) -> Result<JudicialCaseSummary, ServiceError> {
    validate_identifier("caseId", &row.case_id)?;
    if row.case_id.len() > MAX_CASE_ID_BYTES {
        return Err(judicial_schema_error("case id exceeds maximum length"));
    }
    validate_required_case_text("title", &row.title, MAX_CASE_TITLE_BYTES)?;
    if !matches!(row.case_type.as_str(), "guiding" | "reference" | "typical") {
        return Err(judicial_schema_error("case type is invalid"));
    }
    if let Some(number) = row.guiding_number {
        if !(1..=u32::MAX as i64).contains(&number) {
            return Err(judicial_schema_error("guiding number is invalid"));
        }
    }
    if row.case_type == "guiding" && row.guiding_number.is_none() {
        return Err(judicial_schema_error("guiding case is missing its number"));
    }
    if row.case_type == "reference" && row.reference_number.as_deref().is_none_or(str::is_empty) {
        return Err(judicial_schema_error(
            "reference case is missing its number",
        ));
    }
    validate_required_case_text("status", &row.status, 64)?;
    validate_official_source_url(&row.source_url)?;
    let keywords = json_array(&row.keywords_json)?;
    if keywords.len() > MAX_KEYWORDS {
        return Err(judicial_schema_error("case has too many keywords"));
    }
    for keyword in &keywords {
        validate_required_case_text("keyword", keyword, MAX_KEYWORD_BYTES)?;
    }
    for (field, value, max) in [
        ("referenceNumber", row.reference_number.as_deref(), 256),
        ("publicationDate", row.publication_date.as_deref(), 64),
        ("court", row.court.as_deref(), 512),
        ("caseNumber", row.case_number.as_deref(), 512),
        (
            "searchText",
            Some(row.search_text.as_str()),
            MAX_CASE_TEXT_BYTES,
        ),
    ] {
        if let Some(value) = value {
            validate_required_case_text(field, value, max)?;
        }
    }
    Ok(JudicialCaseSummary {
        case_id: row.case_id.clone(),
        title: row.title.clone(),
        case_type: row.case_type.clone(),
        guiding_number: row.guiding_number.map(|value| value as u32),
        reference_number: row.reference_number.clone(),
        keywords,
        publication_date: row.publication_date.clone(),
        court: row.court.clone(),
        case_number: row.case_number.clone(),
        status: row.status.clone(),
        source_url: row.source_url.clone(),
        matched_text: matched_text(&row.search_text, query, terms),
    })
}

fn detail_from_row(row: JudicialCaseRow) -> Result<JudicialCaseDetail, ServiceError> {
    let summary = summary_from_row(&row, "", &[])?;
    let key_points = json_array(
        row.key_points_json
            .as_deref()
            .ok_or_else(|| judicial_schema_error("case key points are missing"))?,
    )?;
    let related_laws = json_array(
        row.related_laws_json
            .as_deref()
            .ok_or_else(|| judicial_schema_error("case related laws are missing"))?,
    )?;
    if key_points.len() > MAX_KEYWORDS || related_laws.len() > MAX_KEYWORDS {
        return Err(judicial_schema_error(
            "case detail contains too many list items",
        ));
    }
    for value in key_points.iter().chain(related_laws.iter()) {
        validate_required_case_text("case detail list value", value, MAX_KEYWORD_BYTES)?;
    }
    let basic_facts = row.basic_facts.unwrap_or_default();
    let judgment_result = row.judgment_result.unwrap_or_default();
    let reasoning = row.reasoning.unwrap_or_default();
    let full_text = row
        .full_text
        .ok_or_else(|| judicial_schema_error("case full text is missing"))?;
    let fetched_at = row
        .fetched_at
        .ok_or_else(|| judicial_schema_error("case fetched time is missing"))?;
    let content_sha256 = row
        .content_sha256
        .ok_or_else(|| judicial_schema_error("case content digest is missing"))?;
    for (field, value, required) in [
        ("basicFacts", &basic_facts, false),
        ("judgmentResult", &judgment_result, false),
        ("reasoning", &reasoning, false),
        ("fullText", &full_text, true),
        ("fetchedAt", &fetched_at, true),
    ] {
        if required || !value.is_empty() {
            validate_required_case_text(field, value, MAX_CASE_TEXT_BYTES)?;
        }
    }
    if !valid_sha256(&content_sha256)
        || format!("{:x}", Sha256::digest(full_text.as_bytes())) != content_sha256
    {
        return Err(judicial_schema_error(
            "case full text does not match its content digest",
        ));
    }
    Ok(JudicialCaseDetail {
        summary,
        key_points,
        basic_facts,
        judgment_result,
        reasoning,
        related_laws,
        full_text,
        fetched_at,
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn json_array(value: &str) -> Result<Vec<String>, ServiceError> {
    serde_json::from_str(value).map_err(|_| judicial_schema_error("case JSON array is invalid"))
}

fn validate_required_case_text(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ServiceError> {
    validate_text(field, value, max, true)
        .map_err(|_| judicial_schema_error("case text is invalid or exceeds its limit"))
}

fn validate_official_source_url(value: &str) -> Result<(), ServiceError> {
    let url = Url::parse(value).map_err(|_| judicial_schema_error("case source URL is invalid"))?;
    let allowed_host = matches!(
        url.host_str(),
        Some(
            "court.gov.cn"
                | "www.court.gov.cn"
                | "rmfyalk.court.gov.cn"
                | "ipc.court.gov.cn"
                | "hnlyzy.hncourt.gov.cn"
                | "gongbao.court.gov.cn"
        )
    );
    if url.scheme() != "https"
        || !allowed_host
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
    {
        return Err(judicial_schema_error(
            "case source URL is not an allowed official URL",
        ));
    }
    Ok(())
}

fn matched_text(search_text: &str, query: &str, terms: &[String]) -> String {
    let needle = std::iter::once(query)
        .chain(terms.iter().map(String::as_str))
        .find(|needle| !needle.is_empty() && search_text.contains(*needle));
    let matched_byte = needle
        .and_then(|needle| search_text.find(needle))
        .unwrap_or(0);
    let matched_char = search_text[..matched_byte].chars().count();
    let start = matched_char.saturating_sub(MAX_MATCHED_TEXT_CHARS / 3);
    let mut result = search_text
        .chars()
        .skip(start)
        .take(MAX_MATCHED_TEXT_CHARS)
        .collect::<String>();
    if start > 0 {
        result.insert(0, '…');
    }
    if result.chars().count() < search_text.chars().count().saturating_sub(start) {
        result.push('…');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};

    fn fixture() -> (tempfile::TempDir, LegalServices) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let legal_core_path = directory.path().join("legal_core.sqlite");
        fs::write(&legal_core_path, []).expect("placeholder legal core");
        let sidecar_path = directory.path().join("judicial_cases.sqlite");
        let connection = Connection::open(&sidecar_path).expect("sidecar opens");
        connection
            .execute_batch(include_str!("../../../data/schema/judicial_cases.sql"))
            .expect("sidecar schema");
        connection
            .execute_batch("INSERT INTO database_metadata VALUES ('schema_version', '1'), ('dataset_version', 'test-cases-v1');")
            .expect("sidecar metadata");
        insert_case(
            &connection,
            "spc-guiding-1",
            "guiding",
            Some(1),
            None,
            "劳动关系认定指导案例",
            "劳动关系 根据用工事实认定",
            "published",
        );
        insert_case(
            &connection,
            "spc-reference-1",
            "reference",
            None,
            Some("民事参考-1"),
            "竞业限制参考案例",
            "竞业限制 约定效力",
            "published",
        );
        insert_case(
            &connection,
            "spc-guiding-2",
            "guiding",
            Some(2),
            None,
            "劳动关系历史案例",
            "劳动关系 历史资料",
            "withdrawn",
        );
        insert_case(
            &connection,
            "spc-typical-1",
            "typical",
            None,
            None,
            "拒不执行判决典型案例合集",
            "拒不执行 判决 典型案例",
            "published",
        );
        connection
            .execute(
                "UPDATE judicial_cases SET keywords_json = '[\"典型案例\"]', key_points_json = '[\"拒不执行判决\"]', related_laws_json = '[]' WHERE case_id = 'spc-typical-1'",
                [],
            )
            .expect("typical fixture fields");
        drop(connection);
        let services = LegalServices::new_public(legal_core_path).expect("public service");
        (directory, services)
    }

    #[allow(clippy::too_many_arguments)] // Test fixture columns are deliberately explicit.
    fn insert_case(
        connection: &Connection,
        case_id: &str,
        case_type: &str,
        guiding_number: Option<i64>,
        reference_number: Option<&str>,
        title: &str,
        search_text: &str,
        status: &str,
    ) {
        let full_text = format!("{title}。{search_text}。");
        let digest = format!("{:x}", Sha256::digest(full_text.as_bytes()));
        connection.execute(
            "INSERT INTO judicial_cases (case_id, case_type, guiding_number, reference_number, title, keywords_json, publication_date, court, case_number, status, source_url, search_text, key_points_json, basic_facts, judgment_result, reasoning, related_laws_json, full_text, fetched_at, content_sha256) VALUES (?1, ?2, ?3, ?4, ?5, '[\"劳动关系\", \"竞业限制\"]', '2026-09-09', '最高人民法院', NULL, ?6, 'https://www.court.gov.cn/shenpan/xiangqing/1.html', ?7, '[\"根据用工事实认定劳动关系\"]', '基本案情', '裁判结果', '裁判理由', '[\"劳动合同法\"]', ?8, '2026-09-09T00:00:00Z', ?9)",
            params![case_id, case_type, guiding_number, reference_number, title, status, search_text, full_text, digest],
        ).expect("case insert");
    }

    #[test]
    fn exact_guiding_number_and_detail_are_read_from_the_sidecar() {
        let (_directory, services) = fixture();
        let search = services
            .judicial_case_search(JudicialCaseSearchRequest {
                schema_version: 1,
                query: "指导性案例 1号".into(),
                case_type: None,
                limit: None,
                offset: None,
                include_withdrawn: None,
            })
            .expect("guiding search");
        assert_eq!(search.total, 1);
        assert_eq!(search.cases[0].case_id, "spc-guiding-1");
        assert_eq!(search.cases[0].guiding_number, Some(1));
        let detail = services
            .judicial_case_get(JudicialCaseGetRequest {
                schema_version: 1,
                case_id: "spc-guiding-1".into(),
            })
            .expect("case detail");
        assert!(detail.case.full_text.contains("劳动关系"));
        assert_eq!(detail.database_version, "test-cases-v1");
    }

    #[test]
    fn keywords_are_or_matched_and_withdrawn_history_is_explicit() {
        let (_directory, services) = fixture();
        let search = services
            .judicial_case_search(JudicialCaseSearchRequest {
                schema_version: 1,
                query: "劳动关系 竞业限制".into(),
                case_type: None,
                limit: Some(50),
                offset: Some(0),
                include_withdrawn: Some(false),
            })
            .expect("OR case search");
        assert_eq!(search.total, 2);
        assert_eq!(search.cases.len(), 2);
        let historical = services
            .judicial_case_search(JudicialCaseSearchRequest {
                schema_version: 1,
                query: "劳动关系".into(),
                case_type: Some("guiding".into()),
                limit: None,
                offset: None,
                include_withdrawn: Some(true),
            })
            .expect("historical case search");
        assert_eq!(historical.total, 2);
        assert!(historical
            .cases
            .iter()
            .any(|case| case.status == "withdrawn"));
    }

    #[test]
    fn status_reports_coverage_and_missing_sidecar_is_nonfatal() {
        let (_directory, services) = fixture();
        let status = services.judicial_case_status().expect("case status");
        assert!(status.available);
        assert_eq!(status.total, 4);
        assert_eq!(status.guiding_count, 2);
        assert_eq!(status.reference_count, 1);
        assert_eq!(status.typical_count, 1);

        let temporary = tempfile::tempdir().expect("temporary directory");
        let services = LegalServices::new_public(temporary.path().join("legal_core.sqlite"))
            .expect("public service");
        let absent = services.judicial_case_status().expect("absent status");
        assert!(!absent.available);
        assert_eq!(absent.total, 0);
        assert_eq!(absent.warnings, ["judicial_case_database_missing"]);
    }

    #[test]
    fn only_official_https_sources_are_accepted() {
        assert!(validate_official_source_url("https://www.court.gov.cn/shenpan/1.html").is_ok());
        for source in [
            "https://rmfyalk.court.gov.cn/view/content.html?id=1",
            "https://ipc.court.gov.cn/upload/file/1.pdf",
            "https://hnlyzy.hncourt.gov.cn/public/detail.php?id=6738",
            "https://gongbao.court.gov.cn/a",
        ] {
            assert!(validate_official_source_url(source).is_ok(), "{source}");
        }
        for source in [
            "http://www.court.gov.cn/a",
            "https://court.gov.cn.evil.test/a",
            "https://user@www.court.gov.cn/a",
            "https://evil.hncourt.gov.cn/a",
        ] {
            assert!(validate_official_source_url(source).is_err(), "{source}");
        }
    }

    #[test]
    fn typical_collection_is_a_searchable_case_type_with_full_text() {
        let (_directory, services) = fixture();
        let search = services
            .judicial_case_search(JudicialCaseSearchRequest {
                schema_version: 1,
                query: "典型案例".into(),
                case_type: Some("typical".into()),
                limit: None,
                offset: None,
                include_withdrawn: None,
            })
            .expect("typical search");
        assert_eq!(search.total, 1);
        assert_eq!(search.cases[0].case_id, "spc-typical-1");
        let detail = services
            .judicial_case_get(JudicialCaseGetRequest {
                schema_version: 1,
                case_id: "spc-typical-1".into(),
            })
            .expect("typical detail");
        assert!(detail.case.full_text.contains("典型案例"));
    }
}
