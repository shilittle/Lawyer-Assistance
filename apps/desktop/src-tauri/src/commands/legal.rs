use domain::law::{
    GetArticleRequest, GetArticleResponse, GetLawRelationsRequest, GetLawRelationsResponse,
    GetLawVersionsRequest, GetLawVersionsResponse, SearchArticlesRequest, SearchArticlesResponse,
    SearchLawsRequest, SearchLawsResponse,
};
use domain::qa::{
    CitationStatus, LegalAnswerCandidatesRequest, LegalAnswerCandidatesResponse,
    LegalAnswerRequest, LegalAnswerResponse, LegalAnswerStreamEvent, LegalAnswerStreamEventType,
};
use providers::{
    ChatMessage, ChatMessageRole, ChatRequest, ChatTransport, CredentialStore,
    OpenAiCompatibleAdapter, ProviderCredentialKey, ProviderError, ProviderErrorKind,
    ReqwestTransport, StreamEvent, StreamParser, TransportResponse,
};
use serde::Serialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub message: String,
}

impl From<database::DatabaseInitError> for IpcError {
    fn from(error: database::DatabaseInitError) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

impl From<retrieval::RetrievalError> for IpcError {
    fn from(error: retrieval::RetrievalError) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

impl From<citations::CitationError> for IpcError {
    fn from(error: citations::CitationError) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

impl From<providers::ProviderError> for IpcError {
    fn from(error: providers::ProviderError) -> Self {
        Self {
            message: providers::redact_sensitive(&error.to_string()),
        }
    }
}

impl From<rusqlite::Error> for IpcError {
    fn from(error: rusqlite::Error) -> Self {
        Self {
            message: error.to_string(),
        }
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(error: serde_json::Error) -> Self {
        Self {
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
pub fn answer_legal_question(
    state: State<'_, AppState>,
    request: LegalAnswerRequest,
) -> Result<LegalAnswerResponse, IpcError> {
    let legal_connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let user_connection = database::open_user_database(state.user_database_path())?;
    let transport = ReqwestTransport::new(Duration::from_secs(90))?;
    let credential_store = providers::windows_credentials::WindowsCredentialStore::new();

    answer_legal_question_with_transport(
        &legal_connection,
        &user_connection,
        &credential_store,
        transport,
        request,
    )
}

pub(crate) fn answer_legal_question_with_transport<T, S>(
    legal_connection: &rusqlite::Connection,
    user_connection: &rusqlite::Connection,
    credential_store: &S,
    transport: T,
    request: LegalAnswerRequest,
) -> Result<LegalAnswerResponse, IpcError>
where
    T: ChatTransport,
    S: CredentialStore<Error = ProviderError>,
{
    validate_answer_request(&request)?;
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
    let context = citations::build_legal_answer_context(legal_connection, &context_request)?;
    if context.sources.is_empty() {
        return Err(IpcError {
            message: "no local legal sources matched the question".to_owned(),
        });
    }

    let profile = database::get_provider_profile(user_connection, &request.provider_id)?
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
    let response =
        OpenAiCompatibleAdapter::new(transport).send_chat(&profile, &secret, &chat_request)?;
    let (answer, stream_events) = parse_answer_response(response)?;
    let citation_report = citations::validate_answer_citations(
        legal_connection,
        &answer,
        &context.sources,
        request.case_date.as_deref(),
        request.include_expired,
    )?;
    let record_id = insert_answer_record(
        user_connection,
        &request,
        &answer,
        &context,
        &citation_report,
    )?;

    Ok(LegalAnswerResponse {
        provider_id: request.provider_id,
        answer,
        context,
        citation_report,
        stream_events,
        record_id: Some(record_id),
    })
}

fn validate_answer_request(request: &LegalAnswerRequest) -> Result<(), ProviderError> {
    if request.provider_id.trim().is_empty() || request.question.trim().is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider_id and question are required",
        ));
    }

    Ok(())
}

fn parse_answer_response(
    response: TransportResponse,
) -> Result<(String, Vec<LegalAnswerStreamEvent>), ProviderError> {
    if !(200..300).contains(&response.status) {
        return Err(ProviderError::with_status(
            ProviderErrorKind::Http,
            response.status,
            format!("provider returned HTTP {}", response.status),
        ));
    }

    if response.body.contains("data:") || response.body.contains("[DONE]") {
        parse_streaming_answer(&response.body)
    } else {
        parse_json_answer(&response.body)
    }
}

fn parse_streaming_answer(
    body: &str,
) -> Result<(String, Vec<LegalAnswerStreamEvent>), ProviderError> {
    let mut parser = StreamParser::new();
    let mut bytes = body.as_bytes().to_vec();
    if !body.ends_with("\n\n") && !body.ends_with("\r\n\r\n") {
        bytes.extend_from_slice(b"\n\n");
    }

    let mut answer = String::new();
    let mut stream_events = Vec::new();
    for event in parser.push(&bytes) {
        match event? {
            StreamEvent::Delta { content } => {
                answer.push_str(&content);
                stream_events.push(LegalAnswerStreamEvent {
                    event_type: LegalAnswerStreamEventType::Delta,
                    content: Some(content),
                    error_type: None,
                    message: None,
                });
            }
            StreamEvent::Usage(usage) => {
                stream_events.push(LegalAnswerStreamEvent {
                    event_type: LegalAnswerStreamEventType::Usage,
                    content: Some(serde_json::to_string(&usage).map_err(|error| {
                        ProviderError::new(ProviderErrorKind::Parse, error.to_string())
                    })?),
                    error_type: None,
                    message: None,
                });
            }
            StreamEvent::Error {
                error_type,
                message,
            } => {
                stream_events.push(LegalAnswerStreamEvent {
                    event_type: LegalAnswerStreamEventType::Error,
                    content: None,
                    error_type: Some(error_type.clone()),
                    message: Some(message.clone()),
                });
                return Err(ProviderError::new(
                    ProviderErrorKind::Http,
                    format!("{error_type}: {message}"),
                ));
            }
            StreamEvent::Done => stream_events.push(LegalAnswerStreamEvent {
                event_type: LegalAnswerStreamEventType::Done,
                content: None,
                error_type: None,
                message: None,
            }),
        }
    }

    if answer.trim().is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::Parse,
            "provider stream did not include answer content",
        ));
    }

    Ok((answer, stream_events))
}

fn parse_json_answer(body: &str) -> Result<(String, Vec<LegalAnswerStreamEvent>), ProviderError> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|error| {
        ProviderError::new(
            ProviderErrorKind::Parse,
            format!("provider response was not valid JSON: {error}"),
        )
    })?;
    if let Some(error) = value.get("error") {
        return Err(ProviderError::new(
            ProviderErrorKind::Http,
            error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("provider returned an error"),
        ));
    }

    let answer = value
        .get("choices")
        .and_then(serde_json::Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .get("choices")
                .and_then(serde_json::Value::as_array)
                .and_then(|choices| choices.first())
                .and_then(|choice| choice.get("delta"))
                .and_then(|delta| delta.get("content"))
                .and_then(serde_json::Value::as_str)
        })
        .unwrap_or_default()
        .to_owned();

    if answer.trim().is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::Parse,
            "provider response did not include answer content",
        ));
    }

    Ok((
        answer.clone(),
        vec![LegalAnswerStreamEvent {
            event_type: LegalAnswerStreamEventType::Delta,
            content: Some(answer),
            error_type: None,
            message: None,
        }],
    ))
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
    use providers::{
        ApiSecret, ProviderCapabilities, ProviderKind, ProviderOptions, TransportRequest,
    };
    use std::sync::{Arc, Mutex};

    const RETRIEVAL_FIXTURE_SQL: &str =
        include_str!("../../../../../data/fixtures/legal_core_retrieval_fixture.sql");

    fn legal_connection() -> rusqlite::Connection {
        let connection = rusqlite::Connection::open_in_memory().expect("memory database opens");
        database::initialize_legal_core_database(&connection).expect("fixture schema loads");
        connection
            .execute_batch(RETRIEVAL_FIXTURE_SQL)
            .expect("retrieval fixture loads");
        connection
    }

    fn user_connection() -> rusqlite::Connection {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            database::ensure_user_database(directory.path()).expect("user database path");
        let connection = database::open_user_database(database_path).expect("user database opens");
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
        connection
    }

    #[test]
    fn answer_flow_accepts_valid_citation_from_mock_provider() {
        let legal = legal_connection();
        let user = user_connection();
        let store = MockCredentialStore::new(Some(ApiSecret::new("mock-secret-1234")));
        let transport = MockTransport::new(stream_body(
            "应当承担违约责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:577]",
        ));

        let response = answer_legal_question_with_transport(
            &legal,
            &user,
            &store,
            transport.clone(),
            answer_request(),
        )
        .expect("answer succeeds");

        assert_eq!(response.citation_report.valid_count, 1);
        assert_eq!(response.citation_report.invalid_count, 0);
        assert!(response.record_id.is_some());
        assert_eq!(
            database::list_legal_answer_records(&user, 10)
                .expect("records list")
                .len(),
            1
        );
        let sent = transport.requests.lock().expect("requests lock");
        assert!(sent[0].body.contains("stream"));
        assert!(!format!("{:?}", sent[0]).contains("mock-secret-1234"));
    }

    #[test]
    fn answer_flow_reports_invalid_and_unsupported_mock_outputs() {
        let legal = legal_connection();
        let user = user_connection();
        let store = MockCredentialStore::new(Some(ApiSecret::new("mock-secret-1234")));
        let transport = MockTransport::new(stream_body(
            "应当承担责任。[SRC:law:cn-civil-code:cn-civil-code-20210101:art:999]",
        ));

        let response = answer_legal_question_with_transport(
            &legal,
            &user,
            &store,
            transport,
            answer_request(),
        )
        .expect("answer succeeds");

        assert_eq!(response.citation_report.valid_count, 0);
        assert_eq!(response.citation_report.invalid_count, 1);
        assert!(response.citation_report.unsupported_legal_conclusion);
    }

    fn answer_request() -> LegalAnswerRequest {
        LegalAnswerRequest {
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

    fn stream_body(answer: &str) -> TransportResponse {
        TransportResponse {
            status: 200,
            body: format!(
                "data: {{\"choices\":[{{\"delta\":{{\"content\":{}}}}}]}}\n\ndata: [DONE]\n\n",
                serde_json::to_string(answer).expect("answer serializes")
            ),
            first_byte_latency_ms: 1,
            total_latency_ms: 2,
        }
    }

    #[derive(Debug, Clone)]
    struct MockTransport {
        response: TransportResponse,
        requests: Arc<Mutex<Vec<TransportRequest>>>,
    }

    impl MockTransport {
        fn new(response: TransportResponse) -> Self {
            Self {
                response,
                requests: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl ChatTransport for MockTransport {
        fn send(&self, request: TransportRequest) -> Result<TransportResponse, ProviderError> {
            self.requests.lock().expect("requests lock").push(request);
            Ok(self.response.clone())
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
