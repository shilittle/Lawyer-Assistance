use domain::law::{
    GetArticleRequest, GetArticleResponse, GetLawRelationsRequest, GetLawRelationsResponse,
    GetLawVersionsRequest, GetLawVersionsResponse, SearchArticlesRequest, SearchArticlesResponse,
    SearchLawsRequest, SearchLawsResponse,
};
use domain::qa::{
    CancelLegalAnswerRequest, CancelLegalAnswerResponse, CitationStatus,
    LegalAnswerCandidatesRequest, LegalAnswerCandidatesResponse, LegalAnswerRequest,
    LegalAnswerResponse, LegalAnswerStreamEvent, LegalAnswerStreamEventType,
    LegalAnswerStreamUsage,
};
use domain::validation::{self, TextMode};
use providers::{
    ChatMessage, ChatMessageRole, ChatRequest, CredentialStore, ProviderError, ProviderErrorKind,
    ProviderProfile, ReqwestStreamingTransport, StreamEvent, StreamParser,
};
use serde::Serialize;
use std::time::Duration;
use tauri::{ipc::Channel, State};
use uuid::Uuid;

use crate::state::AppState;

const MAX_PROVIDER_STREAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_ANSWER_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDER_STREAM_EVENTS: usize = 16_384;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_PROVIDER_ID_BYTES: usize = 128;
const MAX_SEARCH_QUERY_BYTES: usize = 4_096;
const MAX_QUESTION_BYTES: usize = 32 * 1_024;
const MAX_FILTER_BYTES: usize = 512;
const MAX_ARTICLE_NUMBER_BYTES: usize = 128;
const MAX_STRUCTURED_FILTER_VALUES: usize = 16;
const MAX_SEARCH_RESULTS: u32 = 50;
const MAX_ANSWER_SOURCES: u32 = 16;
const MAX_CHAT_OUTPUT_TOKENS: u32 = 65_536;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl IpcError {
    fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        let error_type = normalize_ipc_error_type(&error_type.into());
        Self {
            error_type,
            message: providers::redact_sensitive(&message.into()),
        }
    }
}

fn normalize_ipc_error_type(value: &str) -> String {
    let normalized = value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        .take(64)
        .collect::<String>();

    if normalized.is_empty() {
        "provider_error".to_owned()
    } else {
        normalized
    }
}

impl From<database::DatabaseInitError> for IpcError {
    fn from(error: database::DatabaseInitError) -> Self {
        Self::new("database", error.to_string())
    }
}

impl From<retrieval::RetrievalError> for IpcError {
    fn from(error: retrieval::RetrievalError) -> Self {
        match error {
            retrieval::RetrievalError::InvalidRequest(message) => {
                Self::new("invalid_request", message)
            }
            error => Self::new("retrieval", error.to_string()),
        }
    }
}

impl From<citations::CitationError> for IpcError {
    fn from(error: citations::CitationError) -> Self {
        match error {
            citations::CitationError::InvalidRequest(message) => {
                Self::new("invalid_request", message)
            }
            error => Self::new("citation", error.to_string()),
        }
    }
}

impl From<providers::ProviderError> for IpcError {
    fn from(error: providers::ProviderError) -> Self {
        Self::new(error.kind.as_str(), error.to_string())
    }
}

impl From<rusqlite::Error> for IpcError {
    fn from(error: rusqlite::Error) -> Self {
        Self::new("database", error.to_string())
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(error: serde_json::Error) -> Self {
        Self::new("serialization", error.to_string())
    }
}

#[tauri::command]
pub fn search_laws(
    state: State<'_, AppState>,
    request: SearchLawsRequest,
) -> Result<SearchLawsResponse, IpcError> {
    validate_search_laws_request(&request)?;
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::search_laws(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn search_articles(
    state: State<'_, AppState>,
    request: SearchArticlesRequest,
) -> Result<SearchArticlesResponse, IpcError> {
    validate_search_articles_request(&request)?;
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::search_articles(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn get_article(
    state: State<'_, AppState>,
    request: GetArticleRequest,
) -> Result<GetArticleResponse, IpcError> {
    validate_identifier("articleId", &request.article_id)?;
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::get_article(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn get_law_versions(
    state: State<'_, AppState>,
    request: GetLawVersionsRequest,
) -> Result<GetLawVersionsResponse, IpcError> {
    validate_identifier("documentId", &request.document_id)?;
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::get_law_versions(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn get_law_relations(
    state: State<'_, AppState>,
    request: GetLawRelationsRequest,
) -> Result<GetLawRelationsResponse, IpcError> {
    validate_identifier("documentId", &request.document_id)?;
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::get_law_relations(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn find_legal_answer_candidates(
    state: State<'_, AppState>,
    request: LegalAnswerCandidatesRequest,
) -> Result<LegalAnswerCandidatesResponse, IpcError> {
    validate_candidate_request(&request)?;
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let context = citations::build_legal_answer_context(&connection, &request)?;

    Ok(LegalAnswerCandidatesResponse { context })
}

#[tauri::command]
pub async fn answer_legal_question(
    state: State<'_, AppState>,
    request: LegalAnswerRequest,
    on_event: Channel<LegalAnswerStreamEvent>,
) -> Result<LegalAnswerResponse, IpcError> {
    validate_answer_request(&request)?;
    let request_id = request.request_id.clone();
    let result = answer_legal_question_inner(state.inner(), request, &on_event).await;

    if let Err(error) = &result {
        let _ = on_event.send(error_stream_event(
            &request_id,
            &error.error_type,
            &error.message,
        ));
    }

    result
}

#[tauri::command]
pub fn cancel_legal_answer(
    state: State<'_, AppState>,
    request: CancelLegalAnswerRequest,
) -> Result<CancelLegalAnswerResponse, IpcError> {
    validate_identifier_with_limit("requestId", &request.request_id, MAX_REQUEST_ID_BYTES)?;
    let cancelled = state.cancel_legal_answer(&request.request_id);

    Ok(CancelLegalAnswerResponse {
        request_id: request.request_id,
        cancelled,
    })
}

async fn answer_legal_question_inner(
    state: &AppState,
    request: LegalAnswerRequest,
    on_event: &Channel<LegalAnswerStreamEvent>,
) -> Result<LegalAnswerResponse, IpcError> {
    validate_answer_request(&request)?;
    let cancellation_guard = state
        .begin_legal_answer(&request.request_id)
        .map_err(|message| IpcError::new("duplicate_request", message))?;
    let cancellation = cancellation_guard.token();
    let prepared = prepare_legal_answer(
        state,
        &providers::windows_credentials::WindowsCredentialStore::new(),
        &request,
    )?;
    let transport = ReqwestStreamingTransport::new(Duration::from_secs(90))?;
    let mut response = tokio::select! {
        _ = cancellation.cancelled() => return Err(cancelled_error()),
        response = transport.send_chat(&prepared.profile, &prepared.secret, &prepared.chat_request) => response?,
    };

    if !(200..300).contains(&response.status()) {
        return tokio::select! {
            _ = cancellation.cancelled() => Err(cancelled_error()),
            error = response.into_http_error(&prepared.secret) => Err(provider_reported_http_error(error)),
        };
    }

    let mut parser = StreamParser::new();
    let mut accumulator = AnswerStreamAccumulator::default();
    let mut received_stream_bytes = 0;
    let mut emit = |event| send_stream_event(on_event, event);

    loop {
        let chunk = tokio::select! {
            _ = cancellation.cancelled() => return Err(cancelled_error()),
            chunk = response.next_chunk() => chunk?,
        };

        match chunk {
            Some(chunk) => {
                add_stream_bytes(&mut received_stream_bytes, chunk.len())?;
                consume_stream_results_with_secret(
                    &request.request_id,
                    parser.push(&chunk),
                    &mut accumulator,
                    Some(&prepared.secret),
                    &mut emit,
                )?;
                if accumulator.provider_done {
                    break;
                }
            }
            None => {
                consume_stream_results_with_secret(
                    &request.request_id,
                    parser.finish(),
                    &mut accumulator,
                    Some(&prepared.secret),
                    &mut emit,
                )?;
                break;
            }
        }
    }

    ensure_stream_complete(&accumulator)?;

    if !cancellation_guard.begin_finalization() {
        return Err(cancelled_error());
    }

    // No database connection is held across the network await. Validation and
    // persistence happen only after the complete provider answer is available.
    let final_answer = redact_known_secret(&accumulator.answer, Some(&prepared.secret));
    let finalized = finalize_answer(state, &request, prepared.context, final_answer)?;
    notify_answer_done(&request.request_id, &mut emit);

    Ok(finalized)
}

fn validate_answer_request(request: &LegalAnswerRequest) -> Result<(), IpcError> {
    validate_identifier_with_limit("requestId", &request.request_id, MAX_REQUEST_ID_BYTES)?;
    validate_identifier_with_limit("providerId", &request.provider_id, MAX_PROVIDER_ID_BYTES)?;
    validate_candidate_fields(
        &request.question,
        request.law_name.as_deref(),
        request.article_number.as_deref(),
        &request.keywords,
        request.case_date.as_deref(),
        &request.effectiveness_levels,
        request.limit,
    )?;
    validation::optional_finite_f32("temperature", request.temperature, 0.0, 2.0)
        .map_err(invalid_request)?;
    validation::optional_positive_u32("maxTokens", request.max_tokens, MAX_CHAT_OUTPUT_TOKENS)
        .map_err(invalid_request)?;
    Ok(())
}

fn validate_search_laws_request(request: &SearchLawsRequest) -> Result<(), IpcError> {
    validation::bounded_text(
        "query",
        &request.query,
        MAX_SEARCH_QUERY_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_request)?;
    validation::optional_positive_u32("limit", request.limit, MAX_SEARCH_RESULTS)
        .map_err(invalid_request)
}

fn validate_search_articles_request(request: &SearchArticlesRequest) -> Result<(), IpcError> {
    validation::bounded_text(
        "query",
        &request.query,
        MAX_SEARCH_QUERY_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_request)?;
    if let Some(document_id) = request.document_id.as_deref() {
        validate_identifier("documentId", document_id)?;
    }
    validate_case_date(request.case_date.as_deref())?;
    validation::optional_positive_u32("limit", request.limit, MAX_SEARCH_RESULTS)
        .map_err(invalid_request)
}

fn validate_candidate_request(request: &LegalAnswerCandidatesRequest) -> Result<(), IpcError> {
    validate_candidate_fields(
        &request.question,
        request.law_name.as_deref(),
        request.article_number.as_deref(),
        &request.keywords,
        request.case_date.as_deref(),
        &request.effectiveness_levels,
        request.limit,
    )
}

fn validate_candidate_fields(
    question: &str,
    law_name: Option<&str>,
    article_number: Option<&str>,
    keywords: &[String],
    case_date: Option<&str>,
    effectiveness_levels: &[String],
    limit: Option<u32>,
) -> Result<(), IpcError> {
    validation::required_text(
        "question",
        question,
        MAX_QUESTION_BYTES,
        TextMode::MultiLine,
    )
    .map_err(invalid_request)?;
    validation::optional_text("lawName", law_name, MAX_FILTER_BYTES, TextMode::SingleLine)
        .map_err(invalid_request)?;
    validation::optional_text(
        "articleNumber",
        article_number,
        MAX_ARTICLE_NUMBER_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_request)?;
    validation::required_string_list(
        "keywords",
        keywords,
        MAX_STRUCTURED_FILTER_VALUES,
        MAX_FILTER_BYTES,
    )
    .map_err(invalid_request)?;
    validation::required_string_list(
        "effectivenessLevels",
        effectiveness_levels,
        MAX_STRUCTURED_FILTER_VALUES,
        MAX_FILTER_BYTES,
    )
    .map_err(invalid_request)?;
    validate_case_date(case_date)?;
    validation::optional_positive_u32("limit", limit, MAX_ANSWER_SOURCES).map_err(invalid_request)
}

fn validate_case_date(value: Option<&str>) -> Result<(), IpcError> {
    if let Some(value) = value {
        validation::required_text("caseDate", value, 10, TextMode::SingleLine)
            .map_err(invalid_request)?;
        if !domain::date::is_iso_calendar_date(value) {
            return Err(IpcError::new(
                "invalid_request",
                "caseDate must be a valid YYYY-MM-DD calendar date",
            ));
        }
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), IpcError> {
    validate_identifier_with_limit(field, value, MAX_FILTER_BYTES)
}

fn validate_identifier_with_limit(
    field: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), IpcError> {
    validation::identifier(field, value, max_bytes).map_err(invalid_request)
}

fn invalid_request(error: validation::InputValidationError) -> IpcError {
    IpcError::new("invalid_request", error.to_string())
}

struct PreparedLegalAnswer {
    context: domain::qa::LegalAnswerContext,
    profile: ProviderProfile,
    secret: providers::ApiSecret,
    chat_request: ChatRequest,
}

fn prepare_legal_answer<S>(
    state: &AppState,
    credential_store: &S,
    request: &LegalAnswerRequest,
) -> Result<PreparedLegalAnswer, IpcError>
where
    S: CredentialStore<Error = ProviderError>,
{
    validate_answer_request(request)?;
    let legal_connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let user_connection = database::open_user_database(state.user_database_path())?;
    let context_request = LegalAnswerCandidatesRequest {
        question: request.question.clone(),
        law_name: request.law_name.clone(),
        article_number: request.article_number.clone(),
        keywords: request.keywords.clone(),
        case_date: request.case_date.clone(),
        effectiveness_levels: request.effectiveness_levels.clone(),
        include_expired: request.include_expired,
        limit: request.limit,
    };
    let context = citations::build_legal_answer_context(&legal_connection, &context_request)?;
    if context.sources.is_empty() {
        return Err(IpcError::new(
            "no_local_sources",
            "no local legal sources matched the question",
        ));
    }

    let (profile, secret) = super::provider::provider_profile_and_credential_snapshot(
        &user_connection,
        &request.provider_id,
        credential_store,
    )
    .map_err(|error| IpcError::new(error.error_type, error.message))?;
    let secret = secret.ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::MissingCredential,
            "API key is not configured",
        )
    })?;
    let chat_request = ChatRequest {
        messages: vec![
            ChatMessage {
                role: ChatMessageRole::System,
                content: "你是严格的中国法律检索助手。只能依据用户消息中的本地来源回答，并且所有法律结论都必须使用 [SRC:...] 引用。".to_owned(),
            },
            ChatMessage {
                role: ChatMessageRole::User,
                content: context.prompt.clone(),
            },
        ],
        stream: true,
        temperature: request.temperature.or(Some(0.1)),
        max_tokens: request.max_tokens.or(Some(1024)),
    };

    Ok(PreparedLegalAnswer {
        context,
        profile,
        secret,
        chat_request,
    })
}

#[derive(Debug, Default)]
struct AnswerStreamAccumulator {
    answer: String,
    provider_done: bool,
    event_count: usize,
    pending_secret_prefix: String,
}

fn add_stream_bytes(total: &mut usize, chunk_len: usize) -> Result<(), IpcError> {
    *total = total.saturating_add(chunk_len);
    if *total > MAX_PROVIDER_STREAM_BYTES {
        return Err(response_too_large_error(
            "provider stream exceeded the 4 MiB wire-size limit",
        ));
    }

    Ok(())
}

fn ensure_stream_complete(accumulator: &AnswerStreamAccumulator) -> Result<(), IpcError> {
    if accumulator.answer.trim().is_empty() {
        return Err(IpcError::new(
            "empty_response",
            "provider stream did not include answer content",
        ));
    }
    if !accumulator.provider_done {
        return Err(IpcError::new(
            "interrupted",
            "provider stream ended before the done event",
        ));
    }

    Ok(())
}

#[cfg(test)]
fn consume_stream_results<F>(
    request_id: &str,
    results: Vec<Result<StreamEvent, ProviderError>>,
    accumulator: &mut AnswerStreamAccumulator,
    emit: &mut F,
) -> Result<(), IpcError>
where
    F: FnMut(LegalAnswerStreamEvent) -> Result<(), IpcError>,
{
    consume_stream_results_with_secret(request_id, results, accumulator, None, emit)
}

fn consume_stream_results_with_secret<F>(
    request_id: &str,
    results: Vec<Result<StreamEvent, ProviderError>>,
    accumulator: &mut AnswerStreamAccumulator,
    known_secret: Option<&providers::ApiSecret>,
    emit: &mut F,
) -> Result<(), IpcError>
where
    F: FnMut(LegalAnswerStreamEvent) -> Result<(), IpcError>,
{
    for result in results {
        accumulator.event_count = accumulator.event_count.saturating_add(1);
        if accumulator.event_count > MAX_PROVIDER_STREAM_EVENTS {
            return Err(response_too_large_error(
                "provider stream exceeded the event-count limit",
            ));
        }

        let event = result.map_err(|error| provider_stream_error(error, known_secret))?;
        match event {
            StreamEvent::Delta { content, .. } => {
                let content = drain_secret_safe_content(
                    &mut accumulator.pending_secret_prefix,
                    &content,
                    known_secret,
                    false,
                );
                emit_answer_content(request_id, content, accumulator, emit)?;
            }
            StreamEvent::Usage(usage) => emit(LegalAnswerStreamEvent {
                request_id: request_id.to_owned(),
                event_type: LegalAnswerStreamEventType::Usage,
                content: None,
                usage: Some(LegalAnswerStreamUsage {
                    prompt_tokens: usage.prompt_tokens,
                    completion_tokens: usage.completion_tokens,
                    total_tokens: usage.total_tokens,
                }),
                error_type: None,
                message: None,
            })?,
            StreamEvent::Error {
                error_type,
                message,
            } => {
                return Err(provider_reported_stream_error(error_type, message));
            }
            StreamEvent::Done => {
                let remaining = drain_secret_safe_content(
                    &mut accumulator.pending_secret_prefix,
                    "",
                    known_secret,
                    true,
                );
                emit_answer_content(request_id, remaining, accumulator, emit)?;
                accumulator.provider_done = true;
                break;
            }
        }
    }

    Ok(())
}

fn emit_answer_content<F>(
    request_id: &str,
    content: String,
    accumulator: &mut AnswerStreamAccumulator,
    emit: &mut F,
) -> Result<(), IpcError>
where
    F: FnMut(LegalAnswerStreamEvent) -> Result<(), IpcError>,
{
    if content.is_empty() {
        return Ok(());
    }
    if accumulator.answer.len().saturating_add(content.len()) > MAX_ANSWER_BYTES {
        return Err(response_too_large_error(
            "provider answer exceeded the 2 MiB text limit",
        ));
    }

    accumulator.answer.push_str(&content);
    emit(LegalAnswerStreamEvent {
        request_id: request_id.to_owned(),
        event_type: LegalAnswerStreamEventType::Delta,
        content: Some(content),
        usage: None,
        error_type: None,
        message: None,
    })
}

fn drain_secret_safe_content(
    pending: &mut String,
    content: &str,
    known_secret: Option<&providers::ApiSecret>,
    finish: bool,
) -> String {
    let Some(secret) = known_secret.map(providers::ApiSecret::expose_secret) else {
        return content.to_owned();
    };
    if secret.is_empty() {
        return content.to_owned();
    }

    pending.push_str(content);
    *pending = pending.replace(secret, "<redacted>");
    let keep_bytes = longest_suffix_matching_secret_prefix(pending, secret);
    let safe_bytes = pending.len().saturating_sub(keep_bytes);
    let mut safe = pending[..safe_bytes].to_owned();
    let tail = pending[safe_bytes..].to_owned();

    if finish {
        if !tail.is_empty() {
            safe.push_str("<redacted>");
        }
        pending.clear();
    } else {
        *pending = tail;
    }

    safe
}

fn longest_suffix_matching_secret_prefix(value: &str, secret: &str) -> usize {
    let mut longest = 0;
    for (prefix_bytes, _) in secret.char_indices().skip(1) {
        if value.ends_with(&secret[..prefix_bytes]) {
            longest = prefix_bytes;
        }
    }
    longest
}

fn provider_stream_error(
    mut error: ProviderError,
    known_secret: Option<&providers::ApiSecret>,
) -> IpcError {
    error.message = redact_known_secret(&error.message, known_secret);
    IpcError::new(error.kind.as_str(), error.to_string())
}

fn provider_reported_http_error(error: ProviderError) -> IpcError {
    match error.http_status {
        Some(status) => IpcError::new("http", format!("provider returned HTTP {status}")),
        None => IpcError::new("provider_error", "provider request failed"),
    }
}

fn provider_reported_stream_error(_error_type: String, _message: String) -> IpcError {
    IpcError::new("provider_error", "provider stream returned an error")
}

fn redact_known_secret(value: &str, known_secret: Option<&providers::ApiSecret>) -> String {
    let Some(secret) = known_secret else {
        return value.to_owned();
    };
    if secret.expose_secret().is_empty() {
        value.to_owned()
    } else {
        value.replace(secret.expose_secret(), "<redacted>")
    }
}

fn finalize_answer(
    state: &AppState,
    request: &LegalAnswerRequest,
    context: domain::qa::LegalAnswerContext,
    answer: String,
) -> Result<LegalAnswerResponse, IpcError> {
    validate_answer_request(request)?;
    let legal_connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let user_connection = database::open_user_database(state.user_database_path())?;
    let citation_report = citations::validate_answer_citations(
        &legal_connection,
        &answer,
        &context.sources,
        request.case_date.as_deref(),
        request.include_expired,
    )?;
    let record_id = insert_answer_record(
        &user_connection,
        request,
        &answer,
        &context,
        &citation_report,
    )?;

    Ok(LegalAnswerResponse {
        provider_id: request.provider_id.clone(),
        answer,
        context,
        citation_report,
        record_id: Some(record_id),
    })
}

fn send_stream_event(
    channel: &Channel<LegalAnswerStreamEvent>,
    event: LegalAnswerStreamEvent,
) -> Result<(), IpcError> {
    channel.send(event).map_err(|_| {
        IpcError::new(
            "consumer_disconnected",
            "legal answer stream consumer disconnected",
        )
    })
}

fn error_stream_event(request_id: &str, error_type: &str, message: &str) -> LegalAnswerStreamEvent {
    LegalAnswerStreamEvent {
        request_id: request_id.to_owned(),
        event_type: LegalAnswerStreamEventType::Error,
        content: None,
        usage: None,
        error_type: Some(error_type.to_owned()),
        message: Some(providers::redact_sensitive(message)),
    }
}

fn done_stream_event(request_id: &str) -> LegalAnswerStreamEvent {
    LegalAnswerStreamEvent {
        request_id: request_id.to_owned(),
        event_type: LegalAnswerStreamEventType::Done,
        content: None,
        usage: None,
        error_type: None,
        message: Some("citations_validated_and_answer_saved".to_owned()),
    }
}

fn notify_answer_done<F>(request_id: &str, emit: &mut F)
where
    F: FnMut(LegalAnswerStreamEvent) -> Result<(), IpcError>,
{
    // Persistence and the invoke response are authoritative. A channel can be
    // released in the narrow window after the record commits; failing this
    // best-effort notification must not turn a committed answer into an error
    // and prompt a duplicate retry.
    let _ = emit(done_stream_event(request_id));
}

fn cancelled_error() -> IpcError {
    IpcError::new("cancelled", "legal answer request was cancelled")
}

fn response_too_large_error(message: &str) -> IpcError {
    IpcError::new("response_too_large", message)
}

fn insert_answer_record(
    connection: &rusqlite::Connection,
    request: &LegalAnswerRequest,
    answer: &str,
    context: &domain::qa::LegalAnswerContext,
    citation_report: &domain::qa::CitationValidationReport,
) -> Result<String, IpcError> {
    let record_id = next_answer_record_id();
    let verified = citation_report
        .citations
        .iter()
        .filter(|citation| citation.status == CitationStatus::Valid)
        .cloned()
        .collect::<Vec<_>>();
    let invalid = citation_report
        .citations
        .iter()
        .filter(|citation| citation.status == CitationStatus::Invalid)
        .cloned()
        .collect::<Vec<_>>();
    let source_ids = context
        .sources
        .iter()
        .map(|source| source.source_id.clone())
        .collect::<Vec<_>>();

    database::insert_legal_answer_record(
        connection,
        &database::LegalAnswerRecordRow {
            record_id: record_id.clone(),
            provider_id: request.provider_id.clone(),
            question: request.question.clone(),
            answer_text: answer.to_owned(),
            case_date: request.case_date.clone(),
            query_json: serde_json::to_string(&context.query)?,
            source_ids_json: serde_json::to_string(&source_ids)?,
            verified_citations_json: serde_json::to_string(&verified)?,
            invalid_citations_json: serde_json::to_string(&invalid)?,
            unsupported_legal_conclusion: citation_report.unsupported_legal_conclusion,
            created_at: String::new(),
        },
    )?;

    Ok(record_id)
}

fn next_answer_record_id() -> String {
    format!("answer-{}", Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::*;
    use providers::{
        ApiSecret, ProviderCapabilities, ProviderCredentialKey, ProviderKind, ProviderOptions,
    };
    use tempfile::TempDir;

    const RETRIEVAL_FIXTURE_SQL: &str =
        include_str!("../../../../../data/fixtures/legal_core_retrieval_fixture.sql");

    #[test]
    fn legal_ipc_validation_accepts_chinese_and_rejects_oversized_or_abnormal_inputs() {
        let valid = answer_request();
        validate_answer_request(&valid).expect("normal Chinese legal request is accepted");

        let mut invalid_requests = Vec::new();
        let mut request = valid.clone();
        request.request_id = "r".repeat(MAX_REQUEST_ID_BYTES + 1);
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.question = format!("sensitive-question-{}", "问".repeat(MAX_QUESTION_BYTES));
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.law_name = Some("法".repeat(MAX_FILTER_BYTES));
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.article_number = Some("条".repeat(MAX_ARTICLE_NUMBER_BYTES));
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.keywords = (0..=MAX_STRUCTURED_FILTER_VALUES)
            .map(|index| format!("关键词{index}"))
            .collect();
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.effectiveness_levels = vec!["x".repeat(MAX_FILTER_BYTES + 1)];
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.case_date = Some("2024-02-30".to_owned());
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.limit = Some(MAX_ANSWER_SOURCES + 1);
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.temperature = Some(f32::NAN);
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.temperature = Some(f32::INFINITY);
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.temperature = Some(-0.01);
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.temperature = Some(2.01);
        invalid_requests.push(request);

        let mut request = valid.clone();
        request.max_tokens = Some(0);
        invalid_requests.push(request);

        let mut request = valid;
        request.max_tokens = Some(MAX_CHAT_OUTPUT_TOKENS + 1);
        invalid_requests.push(request);

        for invalid in invalid_requests {
            let error = validate_answer_request(&invalid)
                .expect_err("invalid request is rejected at the Rust IPC boundary");
            assert_eq!(error.error_type, "invalid_request");
            assert!(!error.message.contains("sensitive-question"));
        }
    }

    #[test]
    fn legal_search_and_candidate_filters_are_bounded_before_fts() {
        let search_error = validate_search_laws_request(&SearchLawsRequest {
            query: "法".repeat(MAX_SEARCH_QUERY_BYTES),
            limit: Some(20),
        })
        .expect_err("oversized UTF-8 search query is rejected");
        assert_eq!(search_error.error_type, "invalid_request");

        let article_error = validate_search_articles_request(&SearchArticlesRequest {
            query: "合同".to_owned(),
            document_id: Some("doc\nother".to_owned()),
            case_date: None,
            limit: Some(20),
        })
        .expect_err("control characters in a filter are rejected");
        assert_eq!(article_error.error_type, "invalid_request");

        let candidate_error = validate_candidate_request(&LegalAnswerCandidatesRequest {
            question: "合同责任是什么？".to_owned(),
            law_name: None,
            article_number: None,
            keywords: vec!["关键词".to_owned(); MAX_STRUCTURED_FILTER_VALUES + 1],
            case_date: None,
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(8),
        })
        .expect_err("oversized filter array is rejected");
        assert_eq!(candidate_error.error_type, "invalid_request");

        validate_candidate_request(&LegalAnswerCandidatesRequest {
            question: "中文问题\n包含必要背景".to_owned(),
            law_name: Some("中华人民共和国民法典".to_owned()),
            article_number: Some("第五百七十七条".to_owned()),
            keywords: vec!["违约责任".to_owned()],
            case_date: Some("2024-02-29".to_owned()),
            effectiveness_levels: vec!["national_law".to_owned()],
            include_expired: false,
            limit: Some(8),
        })
        .expect("bounded Chinese filters are accepted");
    }

    #[test]
    fn invalid_answer_input_is_rejected_before_any_database_or_credential_access() {
        let state = AppState::new("missing-legal.sqlite".into(), "missing-user.sqlite".into());
        let mut request = answer_request();
        request.question = "x".repeat(MAX_QUESTION_BYTES + 1);

        let error = match prepare_legal_answer(
            &state,
            &MockCredentialStore::new(Some(ApiSecret::new("unused-secret"))),
            &request,
        ) {
            Ok(_) => panic!("invalid request must not reach database or credential access"),
            Err(error) => error,
        };

        assert_eq!(error.error_type, "invalid_request");
    }

    #[test]
    fn answer_record_ids_are_uuid_v4_and_unique() {
        let ids = (0..1_024)
            .map(|_| next_answer_record_id())
            .collect::<std::collections::HashSet<_>>();

        assert_eq!(ids.len(), 1_024);
        for id in ids {
            let uuid = Uuid::parse_str(
                id.strip_prefix("answer-")
                    .expect("answer record id has the expected prefix"),
            )
            .expect("answer record id contains a UUID");
            assert_eq!(uuid.get_version_num(), 4);
        }
    }

    struct TestHarness {
        _directory: TempDir,
        state: AppState,
    }

    fn test_harness() -> TestHarness {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let legal_path = directory.path().join("legal_core.sqlite");
        let connection = rusqlite::Connection::open(&legal_path).expect("legal database opens");
        database::initialize_legal_core_database(&connection).expect("fixture schema loads");
        connection
            .execute_batch(RETRIEVAL_FIXTURE_SQL)
            .expect("retrieval fixture loads");
        drop(connection);

        let user_path =
            database::ensure_user_database(directory.path()).expect("user database path");
        let connection = database::open_user_database(&user_path).expect("user database opens");
        database::upsert_provider_profile(
            &connection,
            &database::ProviderProfileRow {
                id: "mock-provider".to_owned(),
                kind: serde_json::to_value(ProviderKind::DeepSeek)
                    .expect("kind serializes")
                    .as_str()
                    .expect("kind is string")
                    .to_owned(),
                display_name: "Mock Provider".to_owned(),
                model_id: "mock-model".to_owned(),
                base_url: "https://api.deepseek.com".to_owned(),
                credential_account_id: "default".to_owned(),
                capabilities_json: serde_json::to_string(&ProviderCapabilities::chat_defaults())
                    .expect("capabilities serialize"),
                options_json: serde_json::to_string(&ProviderOptions::default())
                    .expect("options serialize"),
            },
        )
        .expect("profile inserts");

        TestHarness {
            _directory: directory,
            state: AppState::new(legal_path, user_path),
        }
    }

    #[test]
    fn mock_stream_accepts_valid_citation_and_persists_only_after_validation() {
        let harness = test_harness();
        let (response, events) = run_mock_answer(
            &harness,
            "应当承担违约责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
        );

        assert_eq!(response.citation_report.valid_count, 1);
        assert_eq!(response.citation_report.invalid_count, 0);
        assert!(response.record_id.is_some());
        assert!(events.iter().any(|event| {
            event.event_type == LegalAnswerStreamEventType::Delta
                && event
                    .content
                    .as_deref()
                    .is_some_and(|content| !content.is_empty())
        }));
        assert_eq!(
            database::list_legal_answer_records(
                &database::open_user_database(harness.state.user_database_path())
                    .expect("user database opens"),
                10,
            )
            .expect("records list")
            .len(),
            1
        );
    }

    #[test]
    fn mock_stream_reports_invalid_citation() {
        let harness = test_harness();
        let (response, _) = run_mock_answer(
            &harness,
            "应当承担责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:999]",
        );

        assert_eq!(response.citation_report.valid_count, 0);
        assert_eq!(response.citation_report.invalid_count, 1);
        assert!(response.citation_report.unsupported_legal_conclusion);
    }

    #[test]
    fn mock_stream_reports_mixed_valid_and_invalid_citations() {
        let harness = test_harness();
        let (response, _) = run_mock_answer(
            &harness,
            concat!(
                "应当承担违约责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577] ",
                "另见伪造来源。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:999]"
            ),
        );

        assert_eq!(response.citation_report.valid_count, 1);
        assert_eq!(response.citation_report.invalid_count, 1);
        assert!(!response.citation_report.unsupported_legal_conclusion);
    }

    #[test]
    fn mock_stream_flags_legal_conclusion_without_citations() {
        let harness = test_harness();
        let (response, _) = run_mock_answer(&harness, "当事人应当承担违约责任。");

        assert_eq!(response.citation_report.valid_count, 0);
        assert_eq!(response.citation_report.invalid_count, 0);
        assert!(response.citation_report.unsupported_legal_conclusion);
    }

    #[test]
    fn empty_mock_stream_is_rejected_before_persistence() {
        let harness = test_harness();
        let mut accumulator = AnswerStreamAccumulator::default();
        let mut events = Vec::new();
        consume_stream_results(
            "answer-mock",
            StreamParser::new().push(b"data: [DONE]\n\n"),
            &mut accumulator,
            &mut |event| {
                events.push(event);
                Ok(())
            },
        )
        .expect("done event parses");

        assert!(accumulator.answer.is_empty());
        assert!(accumulator.provider_done);
        assert_eq!(
            ensure_stream_complete(&accumulator)
                .expect_err("empty response is rejected")
                .error_type,
            "empty_response"
        );
        assert!(events.is_empty(), "provider done is not trusted final done");
        assert!(database::list_legal_answer_records(
            &database::open_user_database(harness.state.user_database_path())
                .expect("user database opens"),
            10,
        )
        .expect("records list")
        .is_empty());
    }

    #[test]
    fn disconnected_stream_consumer_stops_before_persistence() {
        let harness = test_harness();
        let mut accumulator = AnswerStreamAccumulator::default();
        let mut parser = StreamParser::new();
        let error = consume_stream_results(
            "answer-disconnected",
            parser.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"),
            &mut accumulator,
            &mut |_| {
                Err(IpcError::new(
                    "consumer_disconnected",
                    "stream consumer left the page",
                ))
            },
        )
        .expect_err("channel failure stops stream processing");

        assert_eq!(error.error_type, "consumer_disconnected");
        assert!(database::list_legal_answer_records(
            &database::open_user_database(harness.state.user_database_path())
                .expect("user database opens"),
            10,
        )
        .expect("records list")
        .is_empty());
    }

    #[test]
    fn interrupted_mock_stream_is_not_finalized_or_persisted() {
        let harness = test_harness();
        let mut accumulator = AnswerStreamAccumulator::default();
        let mut parser = StreamParser::new();
        let mut events = Vec::new();
        consume_stream_results(
            "answer-interrupted",
            parser.push(b"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n"),
            &mut accumulator,
            &mut |event| {
                events.push(event);
                Ok(())
            },
        )
        .expect("partial event parses");

        assert_eq!(accumulator.answer, "partial");
        assert!(!accumulator.provider_done);
        assert_eq!(
            ensure_stream_complete(&accumulator)
                .expect_err("missing done event is interrupted")
                .error_type,
            "interrupted"
        );
        assert!(database::list_legal_answer_records(
            &database::open_user_database(harness.state.user_database_path())
                .expect("user database opens"),
            10,
        )
        .expect("records list")
        .is_empty());
    }

    #[test]
    fn provider_stream_wire_size_has_a_typed_limit() {
        let mut total = MAX_PROVIDER_STREAM_BYTES;
        let error = add_stream_bytes(&mut total, 1).expect_err("wire limit rejects overflow");

        assert_eq!(error.error_type, "response_too_large");
        assert!(error.message.contains("4 MiB"));
    }

    #[test]
    fn provider_answer_text_and_event_count_have_typed_limits() {
        let mut accumulator = AnswerStreamAccumulator {
            answer: "x".repeat(MAX_ANSWER_BYTES),
            ..AnswerStreamAccumulator::default()
        };
        let mut emitted = Vec::new();
        let error = consume_stream_results(
            "answer-too-large",
            vec![Ok(StreamEvent::Delta {
                content: "x".to_owned(),
                model: None,
            })],
            &mut accumulator,
            &mut |event| {
                emitted.push(event);
                Ok(())
            },
        )
        .expect_err("answer limit rejects overflow");
        assert_eq!(error.error_type, "response_too_large");
        assert!(emitted.is_empty());

        let mut event_limited = AnswerStreamAccumulator {
            event_count: MAX_PROVIDER_STREAM_EVENTS,
            ..AnswerStreamAccumulator::default()
        };
        let error = consume_stream_results(
            "answer-too-many-events",
            vec![Ok(StreamEvent::Delta {
                content: String::new(),
                model: None,
            })],
            &mut event_limited,
            &mut |_| Ok(()),
        )
        .expect_err("event limit rejects overflow");
        assert_eq!(error.error_type, "response_too_large");
    }

    #[test]
    fn final_done_disconnect_does_not_overturn_a_committed_answer() {
        let mut attempts = 0;
        notify_answer_done("answer-committed", &mut |event| {
            attempts += 1;
            assert_eq!(event.event_type, LegalAnswerStreamEventType::Done);
            Err(IpcError::new(
                "consumer_disconnected",
                "stream consumer left after persistence",
            ))
        });

        assert_eq!(attempts, 1);
    }

    #[test]
    fn provider_reported_errors_never_echo_remote_message_question_model_or_output() {
        let secret = ApiSecret::new("exact-secret-1234");
        let confidential = "confidential-question confidential-model confidential-output";
        let mut accumulator = AnswerStreamAccumulator::default();
        let error = consume_stream_results_with_secret(
            "answer-secret-error",
            vec![Ok(StreamEvent::Error {
                error_type: format!("rate limit/{}", secret.expose_secret()),
                message: format!("provider echoed {} {confidential}", secret.expose_secret()),
            })],
            &mut accumulator,
            Some(&secret),
            &mut |_| Ok(()),
        )
        .expect_err("provider error stops the stream");

        assert_eq!(error.error_type, "provider_error");
        assert_eq!(error.message, "provider stream returned an error");
        assert!(!error.message.contains(secret.expose_secret()));
        assert!(!error.message.contains(confidential));

        let http = provider_reported_http_error(ProviderError::with_status(
            ProviderErrorKind::Http,
            422,
            format!(
                "remote body echoed {} {confidential}",
                secret.expose_secret()
            ),
        ));
        assert_eq!(http.error_type, "http");
        assert_eq!(http.message, "provider returned HTTP 422");
        assert!(!http.message.contains(secret.expose_secret()));
        assert!(!http.message.contains(confidential));
    }

    #[test]
    fn provider_stream_content_redacts_a_secret_split_across_delta_events() {
        let secret = ApiSecret::new("exact-secret-1234");
        let mut accumulator = AnswerStreamAccumulator::default();
        let mut events = Vec::new();

        consume_stream_results_with_secret(
            "answer-secret-content",
            vec![
                Ok(StreamEvent::Delta {
                    content: "before exact-secret-".to_owned(),
                    model: None,
                }),
                Ok(StreamEvent::Delta {
                    content: "1234 after".to_owned(),
                    model: None,
                }),
                Ok(StreamEvent::Done),
            ],
            &mut accumulator,
            Some(&secret),
            &mut |event| {
                events.push(event);
                Ok(())
            },
        )
        .expect("split secret is consumed safely");

        assert_eq!(accumulator.answer, "before <redacted> after");
        assert!(accumulator.pending_secret_prefix.is_empty());
        let visible = events
            .iter()
            .filter_map(|event| event.content.as_deref())
            .collect::<String>();
        assert_eq!(visible, accumulator.answer);
        assert!(!visible.contains(secret.expose_secret()));
    }

    #[test]
    fn provider_stream_does_not_flush_a_trailing_secret_prefix() {
        let secret = ApiSecret::new("exact-secret-1234");
        let mut accumulator = AnswerStreamAccumulator::default();
        let mut events = Vec::new();

        consume_stream_results_with_secret(
            "answer-secret-prefix",
            vec![
                Ok(StreamEvent::Delta {
                    content: "answer exact-secret-".to_owned(),
                    model: None,
                }),
                Ok(StreamEvent::Done),
            ],
            &mut accumulator,
            Some(&secret),
            &mut |event| {
                events.push(event);
                Ok(())
            },
        )
        .expect("trailing secret prefix is consumed safely");

        assert_eq!(accumulator.answer, "answer <redacted>");
        assert!(!events
            .iter()
            .filter_map(|event| event.content.as_deref())
            .collect::<String>()
            .contains("exact-secret-"));
    }

    fn run_mock_answer(
        harness: &TestHarness,
        answer: &str,
    ) -> (LegalAnswerResponse, Vec<LegalAnswerStreamEvent>) {
        let request = answer_request();
        let prepared = prepare_legal_answer(
            &harness.state,
            &MockCredentialStore::new(Some(ApiSecret::new("mock-secret-1234"))),
            &request,
        )
        .expect("answer prepares");
        assert!(prepared.chat_request.stream);

        let user = database::open_user_database(harness.state.user_database_path())
            .expect("user database opens");
        assert!(database::list_legal_answer_records(&user, 10)
            .expect("records list")
            .is_empty());
        drop(user);

        let body = format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":{}}}}}]}}\n\ndata: [DONE]\n\n",
            serde_json::to_string(answer).expect("answer serializes")
        );
        let split = body.len() / 2;
        let mut parser = StreamParser::new();
        let mut accumulator = AnswerStreamAccumulator::default();
        let mut events = Vec::new();
        let mut emit = |event| {
            events.push(event);
            Ok(())
        };
        consume_stream_results(
            &request.request_id,
            parser.push(&body.as_bytes()[..split]),
            &mut accumulator,
            &mut emit,
        )
        .expect("first network chunk parses");
        consume_stream_results(
            &request.request_id,
            parser.push(&body.as_bytes()[split..]),
            &mut accumulator,
            &mut emit,
        )
        .expect("second network chunk parses");
        assert!(accumulator.provider_done);

        let response = finalize_answer(
            &harness.state,
            &request,
            prepared.context,
            accumulator.answer,
        )
        .expect("answer validates and persists");
        events.push(done_stream_event(&request.request_id));

        (response, events)
    }

    fn answer_request() -> LegalAnswerRequest {
        LegalAnswerRequest {
            request_id: "answer-mock".to_owned(),
            provider_id: "mock-provider".to_owned(),
            question: "违约责任如何承担？".to_owned(),
            law_name: None,
            article_number: None,
            keywords: vec!["违约责任".to_owned()],
            case_date: Some("2024-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(4),
            temperature: Some(0.0),
            max_tokens: Some(256),
        }
    }

    #[derive(Debug)]
    struct MockCredentialStore {
        secret: Option<ApiSecret>,
    }

    impl MockCredentialStore {
        fn new(secret: Option<ApiSecret>) -> Self {
            Self { secret }
        }
    }

    impl CredentialStore for MockCredentialStore {
        type Error = ProviderError;

        fn read_api_key(
            &self,
            _key: &ProviderCredentialKey,
        ) -> Result<Option<ApiSecret>, Self::Error> {
            Ok(self.secret.clone())
        }

        fn write_api_key(
            &self,
            _key: &ProviderCredentialKey,
            _secret: ApiSecret,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn delete_api_key(&self, _key: &ProviderCredentialKey) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}
