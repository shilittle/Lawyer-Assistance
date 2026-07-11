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
use providers::{
    ChatMessage, ChatMessageRole, ChatRequest, CredentialStore, ProviderCredentialKey,
    ProviderError, ProviderErrorKind, ProviderProfile, ReqwestStreamingTransport, StreamEvent,
    StreamParser,
};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{ipc::Channel, State};

use crate::state::AppState;

const MAX_PROVIDER_STREAM_BYTES: usize = 4 * 1024 * 1024;
const MAX_ANSWER_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROVIDER_STREAM_EVENTS: usize = 16_384;

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
        Self {
            error_type: "database".to_owned(),
            message: error.to_string(),
        }
    }
}

impl From<retrieval::RetrievalError> for IpcError {
    fn from(error: retrieval::RetrievalError) -> Self {
        Self {
            error_type: "retrieval".to_owned(),
            message: error.to_string(),
        }
    }
}

impl From<citations::CitationError> for IpcError {
    fn from(error: citations::CitationError) -> Self {
        Self {
            error_type: "citation".to_owned(),
            message: error.to_string(),
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
        Self {
            error_type: "database".to_owned(),
            message: error.to_string(),
        }
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(error: serde_json::Error) -> Self {
        Self {
            error_type: "serialization".to_owned(),
            message: error.to_string(),
        }
    }
}

#[tauri::command]
pub fn search_laws(
    state: State<'_, AppState>,
    request: SearchLawsRequest,
) -> Result<SearchLawsResponse, IpcError> {
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::search_laws(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn search_articles(
    state: State<'_, AppState>,
    request: SearchArticlesRequest,
) -> Result<SearchArticlesResponse, IpcError> {
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::search_articles(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn get_article(
    state: State<'_, AppState>,
    request: GetArticleRequest,
) -> Result<GetArticleResponse, IpcError> {
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::get_article(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn get_law_versions(
    state: State<'_, AppState>,
    request: GetLawVersionsRequest,
) -> Result<GetLawVersionsResponse, IpcError> {
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::get_law_versions(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn get_law_relations(
    state: State<'_, AppState>,
    request: GetLawRelationsRequest,
) -> Result<GetLawRelationsResponse, IpcError> {
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    retrieval::get_law_relations(&connection, request).map_err(Into::into)
}

#[tauri::command]
pub fn find_legal_answer_candidates(
    state: State<'_, AppState>,
    request: LegalAnswerCandidatesRequest,
) -> Result<LegalAnswerCandidatesResponse, IpcError> {
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
) -> CancelLegalAnswerResponse {
    let cancelled = state.cancel_legal_answer(&request.request_id);

    CancelLegalAnswerResponse {
        request_id: request.request_id,
        cancelled,
    }
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
            error = response.into_http_error(&prepared.secret) => Err(error.into()),
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
    let finalized = finalize_answer(state, &request, prepared.context, accumulator.answer)?;
    notify_answer_done(&request.request_id, &mut emit);

    Ok(finalized)
}

fn validate_answer_request(request: &LegalAnswerRequest) -> Result<(), ProviderError> {
    if request.request_id.trim().is_empty()
        || request.provider_id.trim().is_empty()
        || request.question.trim().is_empty()
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "request_id, provider_id and question are required",
        ));
    }

    Ok(())
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

    let profile = database::get_provider_profile(&user_connection, &request.provider_id)?
        .ok_or_else(|| ProviderError::new(ProviderErrorKind::InvalidProfile, "profile not found"))
        .and_then(super::provider::profile_from_row)?;
    let key = ProviderCredentialKey::new(&profile.id, &profile.credential_account_id);
    let secret = credential_store.read_api_key(&key)?.ok_or_else(|| {
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
                if content.is_empty() {
                    continue;
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
                })?;
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
                return Err(IpcError::new(
                    redact_known_secret(&error_type, known_secret),
                    redact_known_secret(&message, known_secret),
                ));
            }
            StreamEvent::Done => {
                accumulator.provider_done = true;
                break;
            }
        }
    }

    Ok(())
}

fn provider_stream_error(
    mut error: ProviderError,
    known_secret: Option<&providers::ApiSecret>,
) -> IpcError {
    error.message = redact_known_secret(&error.message, known_secret);
    IpcError::new(error.kind.as_str(), error.to_string())
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
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();

    format!("answer-{millis}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use providers::{ApiSecret, ProviderCapabilities, ProviderKind, ProviderOptions};
    use tempfile::TempDir;

    const RETRIEVAL_FIXTURE_SQL: &str =
        include_str!("../../../../../data/fixtures/legal_core_retrieval_fixture.sql");

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
    fn provider_stream_errors_redact_the_exact_credential_and_normalize_type() {
        let secret = ApiSecret::new("exact-secret-1234");
        let mut accumulator = AnswerStreamAccumulator::default();
        let error = consume_stream_results_with_secret(
            "answer-secret-error",
            vec![Ok(StreamEvent::Error {
                error_type: "rate limit/exact-secret-1234".to_owned(),
                message: "provider echoed exact-secret-1234".to_owned(),
            })],
            &mut accumulator,
            Some(&secret),
            &mut |_| Ok(()),
        )
        .expect_err("provider error stops the stream");

        assert_eq!(error.error_type, "ratelimitredacted");
        assert!(!error.message.contains(secret.expose_secret()));
        assert!(error.message.contains("<redacted>"));
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
