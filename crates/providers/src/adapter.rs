use crate::{
    credentials::ApiSecret,
    redaction::truncate_for_log,
    types::{
        ChatMessageRole, ChatRequest, ChatUsage, ConnectionTest, ProviderError, ProviderErrorKind,
        ProviderKind, ProviderOptions, ProviderProfile,
    },
};
use serde_json::{json, Map, Value};
use std::{
    fmt,
    io::Read,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crate::stream::{StreamEvent, StreamParser};

const MAX_PROVIDER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct TransportHeader {
    pub name: String,
    pub value: String,
}

impl TransportHeader {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    fn is_sensitive(&self) -> bool {
        let lower = self.name.to_ascii_lowercase();
        lower == "authorization" || lower.contains("api-key")
    }
}

impl fmt::Debug for TransportHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = if self.is_sensitive() {
            "<redacted>"
        } else {
            self.value.as_str()
        };

        formatter
            .debug_struct("TransportHeader")
            .field("name", &self.name)
            .field("value", &value)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransportRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<TransportHeader>,
    pub body: String,
    pub expects_stream: bool,
}

impl TransportRequest {
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }
}

impl fmt::Debug for TransportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TransportResponse {
    pub status: u16,
    pub body: String,
    pub first_content_token_latency_ms: Option<u128>,
    pub total_latency_ms: u128,
}

impl fmt::Debug for TransportResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportResponse")
            .field("status", &self.status)
            .field("body", &"<redacted>")
            .field(
                "first_content_token_latency_ms",
                &self.first_content_token_latency_ms,
            )
            .field("total_latency_ms", &self.total_latency_ms)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestCancellation {
    cancelled: Arc<AtomicBool>,
}

impl RequestCancellation {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub trait ChatTransport: Send + Sync {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, ProviderError>;

    fn send_with_cancellation(
        &self,
        request: TransportRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError> {
        if cancellation.is_cancelled() {
            return Err(cancelled_error());
        }

        let response = self.send(request)?;
        if cancellation.is_cancelled() {
            Err(cancelled_error())
        } else {
            Ok(response)
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    pub fn new(timeout: Duration) -> Result<Self, ProviderError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| ProviderError::new(ProviderErrorKind::Network, error.to_string()))?;

        Ok(Self { client })
    }
}

impl ChatTransport for ReqwestTransport {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, ProviderError> {
        self.send_inner(request, &RequestCancellation::default())
    }

    fn send_with_cancellation(
        &self,
        request: TransportRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError> {
        self.send_inner(request, cancellation)
    }
}

impl ReqwestTransport {
    fn send_inner(
        &self,
        request: TransportRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError> {
        if cancellation.is_cancelled() {
            return Err(cancelled_error());
        }

        let started_at = Instant::now();
        let expects_stream = request.expects_stream;
        let mut builder = self.client.post(&request.url);

        for header in &request.headers {
            builder = builder.header(&header.name, &header.value);
        }

        let response = builder
            .body(request.body)
            .send()
            .map_err(map_reqwest_error)?;
        let mut response = response;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
        {
            return Err(response_too_large_error(
                MAX_PROVIDER_RESPONSE_BYTES,
                Some(status),
            ));
        }
        let mut body = Vec::new();
        let mut buffer = [0_u8; 8192];
        let mut parser = StreamParser::new();
        let mut first_content_token_latency_ms = None;

        loop {
            if cancellation.is_cancelled() {
                return Err(cancelled_error());
            }

            let bytes_read = response.read(&mut buffer).map_err(map_read_error)?;
            if cancellation.is_cancelled() {
                return Err(cancelled_error());
            }
            if bytes_read == 0 {
                if expects_stream
                    && first_content_token_latency_ms.is_none()
                    && stream_finish_has_content(&mut parser)
                {
                    first_content_token_latency_ms = Some(elapsed_millis(&started_at));
                }
                break;
            }

            let chunk = &buffer[..bytes_read];
            append_bounded_response_chunk(
                &mut body,
                chunk,
                MAX_PROVIDER_RESPONSE_BYTES,
                Some(status),
            )?;
            if expects_stream
                && first_content_token_latency_ms.is_none()
                && stream_chunk_has_content(&mut parser, chunk)
            {
                first_content_token_latency_ms = Some(elapsed_millis(&started_at));
            }
        }

        let body = String::from_utf8(body).map_err(|error| {
            ProviderError::new(
                ProviderErrorKind::Parse,
                format!("provider response was not valid UTF-8: {error}"),
            )
        })?;
        if cancellation.is_cancelled() {
            return Err(cancelled_error());
        }

        Ok(TransportResponse {
            status,
            body,
            first_content_token_latency_ms,
            total_latency_ms: elapsed_millis(&started_at),
        })
    }
}

#[derive(Debug)]
pub struct OpenAiCompatibleAdapter<T> {
    transport: T,
}

impl<T> OpenAiCompatibleAdapter<T>
where
    T: ChatTransport,
{
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn build_transport_request(
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
    ) -> Result<TransportRequest, ProviderError> {
        let url = chat_completions_url(profile)?;
        let headers = vec![
            TransportHeader::new(
                "Authorization",
                format!("Bearer {}", secret.expose_secret()),
            ),
            TransportHeader::new("Content-Type", "application/json"),
            TransportHeader::new(
                "Accept",
                if request.stream {
                    "text/event-stream"
                } else {
                    "application/json"
                },
            ),
        ];

        let body = build_chat_body(profile, request)?;

        Ok(TransportRequest {
            method: "POST".to_owned(),
            url,
            headers,
            body: serde_json::to_string(&body).map_err(|error| {
                ProviderError::new(ProviderErrorKind::InvalidRequest, error.to_string())
            })?,
            expects_stream: request.stream,
        })
    }

    pub fn send_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
    ) -> Result<TransportResponse, ProviderError> {
        let transport_request = Self::build_transport_request(profile, secret, request)?;
        self.transport.send(transport_request)
    }

    pub fn send_chat_with_cancellation(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError> {
        let transport_request = Self::build_transport_request(profile, secret, request)?;
        self.transport
            .send_with_cancellation(transport_request, cancellation)
    }

    pub fn test_connection(&self, profile: &ProviderProfile, secret: &ApiSecret) -> ConnectionTest {
        let request = ChatRequest::connection_probe();
        let started_at = Instant::now();

        match self.send_chat(profile, secret, &request) {
            Ok(response) if (200..300).contains(&response.status) => {
                let parsed = parse_chat_completion_metadata(&response.body).and_then(|metadata| {
                    match response.first_content_token_latency_ms {
                        Some(first_latency)
                            if first_latency > 0 && first_latency <= response.total_latency_ms =>
                        {
                            Ok(metadata)
                        }
                        Some(_) => Err(ProviderError::new(
                            ProviderErrorKind::Parse,
                            "provider returned an invalid first content token latency",
                        )),
                        None => Err(ProviderError::new(
                            ProviderErrorKind::Parse,
                            "provider stream did not include a content token",
                        )),
                    }
                });

                match parsed {
                    Ok((model, usage)) => ConnectionTest::succeeded(
                        profile.id.clone(),
                        response.status,
                        model,
                        response.first_content_token_latency_ms,
                        response.total_latency_ms,
                        usage,
                    ),
                    Err(error) => {
                        let error = redact_known_secret(error, secret);
                        ConnectionTest::failed(
                            profile.id.clone(),
                            Some(response.status),
                            response.first_content_token_latency_ms,
                            response.total_latency_ms,
                            &error,
                        )
                    }
                }
            }
            Ok(response) => {
                let error =
                    redact_known_secret(map_http_error(response.status, &response.body), secret);
                ConnectionTest::failed(
                    profile.id.clone(),
                    Some(response.status),
                    response.first_content_token_latency_ms,
                    response.total_latency_ms,
                    &error,
                )
            }
            Err(error) => {
                let http_status = error.http_status;
                let error = redact_known_secret(error, secret);
                ConnectionTest::failed(
                    profile.id.clone(),
                    http_status,
                    None,
                    elapsed_millis(&started_at),
                    &error,
                )
            }
        }
    }
}

fn chat_completions_url(profile: &ProviderProfile) -> Result<String, ProviderError> {
    let resolved_base_url = resolve_base_url(profile)?;
    let base_url = resolved_base_url.as_str();
    let trimmed = base_url.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(trimmed).map_err(|error| {
        ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            format!("invalid provider base URL: {error}"),
        )
    })?;

    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "provider base URL must not contain credentials, query parameters, or fragments",
        ));
    }

    match parsed.scheme() {
        "https" => {}
        "http" => {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidProfile,
                "provider base URL must use HTTPS",
            ));
        }
        _ => {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidProfile,
                "provider base URL must be an HTTPS URL",
            ));
        }
    }

    if let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) {
        if host == "localhost" || host == "127.0.0.1" || host == "::1" {
            return Err(ProviderError::new(
                ProviderErrorKind::InvalidProfile,
                "localhost provider endpoints are not supported",
            ));
        }
    }

    if trimmed.ends_with("/chat/completions") {
        Ok(trimmed.to_owned())
    } else {
        Ok(format!("{trimmed}/chat/completions"))
    }
}

fn resolve_base_url(profile: &ProviderProfile) -> Result<String, ProviderError> {
    let Some(workspace_id) = non_empty(profile.options.workspace_id.as_deref()) else {
        return Ok(profile.base_url.clone());
    };

    if profile.kind != ProviderKind::Qwen
        || (!profile.base_url.contains("{workspace_id}")
            && !profile.base_url.contains("{workspaceId}")
            && !profile.base_url.contains("{WorkspaceId}"))
    {
        return Ok(profile.base_url.clone());
    }

    if !workspace_id
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "workspace ID contains unsupported characters",
        ));
    }

    Ok(profile
        .base_url
        .replace("{workspace_id}", workspace_id)
        .replace("{workspaceId}", workspace_id)
        .replace("{WorkspaceId}", workspace_id))
}

fn build_chat_body(
    profile: &ProviderProfile,
    request: &ChatRequest,
) -> Result<Value, ProviderError> {
    if request.messages.is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "chat request must include at least one message",
        ));
    }
    if request.max_tokens == Some(0) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "max tokens must be greater than zero",
        ));
    }
    if profile.kind == ProviderKind::SiliconFlow
        && profile
            .options
            .thinking_budget
            .is_some_and(|budget| !(128..=32_768).contains(&budget))
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "SiliconFlow thinking budget must be between 128 and 32768",
        ));
    }
    if profile.kind == ProviderKind::Qwen && profile.options.thinking_budget == Some(0) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "Qwen thinking budget must be greater than zero",
        ));
    }

    let model_id = if profile.kind == ProviderKind::VolcengineArk {
        non_empty(profile.options.endpoint_id.as_deref()).unwrap_or(&profile.model_id)
    } else {
        &profile.model_id
    };

    let mut body = Map::new();
    body.insert("model".to_owned(), json!(model_id));
    body.insert("stream".to_owned(), json!(request.stream));
    body.insert(
        "messages".to_owned(),
        Value::Array(
            request
                .messages
                .iter()
                .map(|message| {
                    json!({
                        "role": role_name(message.role),
                        "content": message.content,
                    })
                })
                .collect(),
        ),
    );

    if let Some(temperature) = request.temperature {
        body.insert("temperature".to_owned(), json!(temperature));
    }

    if let Some(max_tokens) = request.max_tokens {
        body.insert("max_tokens".to_owned(), json!(max_tokens));
    }

    if request.stream && profile.kind != ProviderKind::SiliconFlow {
        body.insert(
            "stream_options".to_owned(),
            json!({ "include_usage": true }),
        );
    }

    apply_provider_options(profile.kind, &profile.options, &mut body);

    Ok(Value::Object(body))
}

fn apply_provider_options(
    kind: ProviderKind,
    options: &ProviderOptions,
    body: &mut Map<String, Value>,
) {
    match kind {
        ProviderKind::DeepSeek => {
            insert_option(body, "reasoning_effort", options.reasoning_effort);
            insert_thinking_object(body, options.thinking);
        }
        ProviderKind::Qwen => {
            insert_option(body, "enable_thinking", options.enable_thinking);
            insert_option(body, "thinking_budget", options.thinking_budget);
        }
        ProviderKind::SiliconFlow => {
            insert_option(
                body,
                "enable_thinking",
                options.enable_thinking.or(options.thinking),
            );
            insert_option(body, "thinking_budget", options.thinking_budget);
        }
        ProviderKind::VolcengineArk => {
            insert_option(body, "reasoning_effort", options.reasoning_effort);
            insert_thinking_object(body, options.thinking);
        }
    }
}

fn insert_thinking_object(body: &mut Map<String, Value>, thinking: Option<bool>) {
    if let Some(thinking) = thinking {
        body.insert(
            "thinking".to_owned(),
            json!({ "type": if thinking { "enabled" } else { "disabled" } }),
        );
    }
}

fn insert_option<T>(body: &mut Map<String, Value>, name: &str, value: Option<T>)
where
    T: serde::Serialize,
{
    if let Some(value) = value {
        body.insert(name.to_owned(), json!(value));
    }
}

fn role_name(role: ChatMessageRole) -> &'static str {
    match role {
        ChatMessageRole::System => "system",
        ChatMessageRole::User => "user",
        ChatMessageRole::Assistant => "assistant",
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn parse_chat_completion_metadata(
    body: &str,
) -> Result<(Option<String>, Option<ChatUsage>), ProviderError> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        if value.get("error").is_some() {
            return Err(map_http_error(200, body));
        }

        let has_content = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("message"))
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .is_some_and(|content| !content.is_empty());
        if !has_content {
            return Err(ProviderError::new(
                ProviderErrorKind::Parse,
                "provider response did not include response content",
            ));
        }

        let model = value
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let usage = value
            .get("usage")
            .filter(|usage| usage.is_object())
            .map(parse_usage);

        return Ok((model, usage));
    }

    parse_streaming_completion_metadata(body)
}

fn parse_streaming_completion_metadata(
    body: &str,
) -> Result<(Option<String>, Option<ChatUsage>), ProviderError> {
    let mut parser = StreamParser::new();
    let mut model = None;
    let mut usage = None;
    let mut has_content = false;

    let mut events = parser.push(body.as_bytes());
    events.extend(parser.finish());
    for event in events {
        match event? {
            StreamEvent::Delta {
                content,
                model: event_model,
            } => {
                has_content |= !content.is_empty();
                if event_model.is_some() {
                    model = event_model;
                }
            }
            StreamEvent::Usage(event_usage) => usage = Some(event_usage),
            StreamEvent::Error {
                error_type,
                message,
            } => {
                return Err(ProviderError::new(
                    ProviderErrorKind::Http,
                    format!("{error_type}: {message}"),
                ));
            }
            StreamEvent::Done => {}
        }
    }

    if !has_content {
        return Err(ProviderError::new(
            ProviderErrorKind::Parse,
            "provider stream did not include a content token",
        ));
    }

    Ok((model, usage))
}

fn parse_usage(value: &Value) -> ChatUsage {
    ChatUsage {
        prompt_tokens: value
            .get("prompt_tokens")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        completion_tokens: value
            .get("completion_tokens")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        total_tokens: value
            .get("total_tokens")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
    }
}

fn map_http_error(status: u16, body: &str) -> ProviderError {
    let parsed: Result<Value, _> = serde_json::from_str(body);
    let message = parsed
        .ok()
        .and_then(|value| {
            let error = value.get("error").unwrap_or(&value);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| value.get("message").and_then(Value::as_str));
            let error_type = error
                .get("type")
                .and_then(Value::as_str)
                .or_else(|| value.get("code").and_then(Value::as_str));

            match (error_type, message) {
                (Some(error_type), Some(message)) => Some(format!("{error_type}: {message}")),
                (None, Some(message)) => Some(message.to_owned()),
                (Some(error_type), None) => Some(error_type.to_owned()),
                (None, None) => None,
            }
        })
        .unwrap_or_else(|| format!("provider returned HTTP {status}"));

    ProviderError::with_status(
        ProviderErrorKind::Http,
        status,
        truncate_for_log(&message, 240),
    )
}

fn map_reqwest_error(error: reqwest::Error) -> ProviderError {
    ProviderError::new(
        if error.is_timeout() {
            ProviderErrorKind::Timeout
        } else {
            ProviderErrorKind::Network
        },
        error.to_string(),
    )
}

fn map_read_error(error: std::io::Error) -> ProviderError {
    ProviderError::new(
        if error.kind() == std::io::ErrorKind::TimedOut {
            ProviderErrorKind::Timeout
        } else {
            ProviderErrorKind::Network
        },
        error.to_string(),
    )
}

fn append_bounded_response_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
    http_status: Option<u16>,
) -> Result<(), ProviderError> {
    if chunk.len() > limit.saturating_sub(body.len()) {
        return Err(response_too_large_error(limit, http_status));
    }

    body.extend_from_slice(chunk);
    Ok(())
}

fn response_too_large_error(limit: usize, http_status: Option<u16>) -> ProviderError {
    let message = format!("provider response exceeded the {limit}-byte safety limit");
    match http_status {
        Some(status) => ProviderError::with_status(ProviderErrorKind::Parse, status, message),
        None => ProviderError::new(ProviderErrorKind::Parse, message),
    }
}

fn elapsed_millis(started_at: &Instant) -> u128 {
    started_at.elapsed().as_micros().saturating_add(999) / 1_000
}

fn cancelled_error() -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::Cancelled,
        "provider request was cancelled",
    )
}

fn stream_chunk_has_content(parser: &mut StreamParser, chunk: &[u8]) -> bool {
    stream_events_have_content(parser.push(chunk))
}

fn stream_finish_has_content(parser: &mut StreamParser) -> bool {
    stream_events_have_content(parser.finish())
}

fn stream_events_have_content(events: Vec<Result<StreamEvent, ProviderError>>) -> bool {
    events.into_iter().any(|event| {
        matches!(
            event,
            Ok(StreamEvent::Delta { content, .. }) if !content.is_empty()
        )
    })
}

fn redact_known_secret(mut error: ProviderError, secret: &ApiSecret) -> ProviderError {
    if !secret.expose_secret().is_empty() {
        error.message = error.message.replace(secret.expose_secret(), "<redacted>");
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ChatMessage, ChatMessageRole, ProviderCapabilities, ProviderOptions, ReasoningEffort,
    };
    use std::sync::{Arc, Mutex};

    fn profile(kind: ProviderKind) -> ProviderProfile {
        ProviderProfile {
            id: format!("{kind:?}-profile"),
            display_name: format!("{kind:?}"),
            kind,
            model_id: kind.default_model_id().to_owned(),
            base_url: kind.default_base_url().to_owned(),
            credential_account_id: "default".to_owned(),
            capabilities: ProviderCapabilities::chat_defaults(),
            options: ProviderOptions::default(),
        }
    }

    fn request_for_contract() -> ChatRequest {
        ChatRequest {
            messages: vec![ChatMessage {
                role: ChatMessageRole::User,
                content: "ping".to_owned(),
            }],
            stream: true,
            temperature: Some(0.2),
            max_tokens: Some(16),
        }
    }

    fn build(kind: ProviderKind, options: ProviderOptions) -> TransportRequest {
        let mut profile = profile(kind);
        profile.options = options;
        OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &profile,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect("request builds")
    }

    #[test]
    fn deepseek_contract_maps_url_headers_body_and_reasoning() {
        let request = build(
            ProviderKind::DeepSeek,
            ProviderOptions {
                reasoning_effort: Some(ReasoningEffort::Max),
                thinking: Some(true),
                thinking_budget: Some(2048),
                ..ProviderOptions::default()
            },
        );
        let body: Value = serde_json::from_str(&request.body).expect("body is JSON");

        assert_eq!(request.url, "https://api.deepseek.com/chat/completions");
        assert_eq!(
            request.header_value("Authorization"),
            Some("Bearer contract-secret-1234")
        );
        assert_eq!(body["model"], "deepseek-v4-flash");
        assert_eq!(body["stream"], true);
        assert_eq!(body["stream_options"]["include_usage"], true);
        assert_eq!(body["reasoning_effort"], "max");
        assert_eq!(body["thinking"]["type"], "enabled");
        assert!(body.get("thinking_budget").is_none());
        assert!(!format!("{request:?}").contains("contract-secret-1234"));
        assert!(!format!("{request:?}").contains("ping"));
    }

    #[test]
    fn qwen_contract_maps_compatible_base_and_thinking_flags() {
        let request = build(
            ProviderKind::Qwen,
            ProviderOptions {
                enable_thinking: Some(false),
                thinking_budget: Some(512),
                ..ProviderOptions::default()
            },
        );
        let body: Value = serde_json::from_str(&request.body).expect("body is JSON");

        assert_eq!(
            request.url,
            "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
        );
        assert_eq!(body["model"], "qwen-plus");
        assert_eq!(body["enable_thinking"], false);
        assert_eq!(body["thinking_budget"], 512);
    }

    #[test]
    fn qwen_contract_expands_workspace_placeholder_in_base_url() {
        let mut profile = profile(ProviderKind::Qwen);
        profile.base_url =
            "https://{WorkspaceId}.cn-beijing.maas.aliyuncs.com/compatible-mode/v1".to_owned();
        profile.options.workspace_id = Some("ws-example-1".to_owned());

        let request = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &profile,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect("workspace URL builds");

        assert_eq!(
            request.url,
            "https://ws-example-1.cn-beijing.maas.aliyuncs.com/compatible-mode/v1/chat/completions"
        );
    }

    #[test]
    fn siliconflow_contract_maps_thinking_flags() {
        let request = build(
            ProviderKind::SiliconFlow,
            ProviderOptions {
                thinking: Some(true),
                thinking_budget: Some(1024),
                enable_thinking: Some(true),
                ..ProviderOptions::default()
            },
        );
        let body: Value = serde_json::from_str(&request.body).expect("body is JSON");

        assert_eq!(
            request.url,
            "https://api.siliconflow.cn/v1/chat/completions"
        );
        assert_eq!(body["model"], "deepseek-ai/DeepSeek-V3.2");
        assert_eq!(body["enable_thinking"], true);
        assert_eq!(body["thinking_budget"], 1024);
        assert!(body.get("thinking").is_none());
        assert!(body.get("stream_options").is_none());
    }

    #[test]
    fn siliconflow_rejects_out_of_range_thinking_budget() {
        let mut profile = profile(ProviderKind::SiliconFlow);
        profile.options.enable_thinking = Some(true);
        profile.options.thinking_budget = Some(64);

        let error = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &profile,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect_err("out-of-range thinking budget is rejected");

        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
    }

    #[test]
    fn volcengine_contract_maps_endpoint_id_and_thinking_object() {
        let request = build(
            ProviderKind::VolcengineArk,
            ProviderOptions {
                endpoint_id: Some("ep-ark-custom".to_owned()),
                workspace_id: Some("workspace-a".to_owned()),
                reasoning_effort: Some(ReasoningEffort::Low),
                thinking: Some(false),
                ..ProviderOptions::default()
            },
        );
        let body: Value = serde_json::from_str(&request.body).expect("body is JSON");

        assert_eq!(
            request.url,
            "https://ark.cn-beijing.volces.com/api/v3/chat/completions"
        );
        assert_eq!(body["model"], "ep-ark-custom");
        assert_eq!(body["reasoning_effort"], "low");
        assert_eq!(body["thinking"]["type"], "disabled");
        assert!(request.header_value("X-Volcengine-Workspace").is_none());
    }

    #[test]
    fn invalid_localhost_endpoint_is_rejected() {
        let mut profile = profile(ProviderKind::DeepSeek);
        profile.base_url = "https://localhost:3000/v1".to_owned();

        let error = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &profile,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect_err("localhost is rejected");

        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
    }

    #[test]
    fn sensitive_base_url_components_are_rejected_without_echoing_them() {
        let mut profile = profile(ProviderKind::DeepSeek);
        profile.base_url = "https://api.deepseek.com/v1?api_key=url-secret-1234".to_owned();

        let error = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &profile,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect_err("query parameters are rejected");

        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
        assert!(!error.to_string().contains("url-secret-1234"));
    }

    #[test]
    fn connection_test_maps_success_response_from_mock_transport() {
        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: concat!(
                "data: {\"model\":\"mock-model\",\"choices\":[{\"delta\":{\"content\":\"pong\"}}],\"usage\":null}\n\n",
                "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}\n\n",
                "data: [DONE]\n\n"
            )
            .to_owned(),
            first_content_token_latency_ms: Some(7),
            total_latency_ms: 11,
        });
        let adapter = OpenAiCompatibleAdapter::new(transport.clone());
        let result = adapter.test_connection(
            &profile(ProviderKind::DeepSeek),
            &ApiSecret::new("contract-secret-1234"),
        );

        assert_eq!(result.status, crate::types::ConnectionTestStatus::Succeeded);
        assert_eq!(result.model, Some("mock-model".to_owned()));
        assert_eq!(result.first_token_latency_ms, Some(7));
        assert_eq!(result.total_latency_ms, 11);
        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].expects_stream);
        assert_eq!(
            requests[0].header_value("Accept"),
            Some("text/event-stream")
        );
    }

    #[test]
    fn json_completion_metadata_is_parsed_but_cannot_fake_stream_latency() {
        let body = r#"{"model":"mock-json-model","choices":[{"message":{"content":"pong"}}],"usage":null}"#;
        let (model, usage) =
            parse_chat_completion_metadata(body).expect("valid JSON completion parses");
        assert_eq!(model.as_deref(), Some("mock-json-model"));
        assert_eq!(usage, None);

        let adapter = OpenAiCompatibleAdapter::new(MockTransport::new(TransportResponse {
            status: 200,
            body: body.to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 5,
        }));
        let result = adapter.test_connection(
            &profile(ProviderKind::DeepSeek),
            &ApiSecret::new("contract-secret-1234"),
        );

        assert_eq!(result.status, crate::types::ConnectionTestStatus::Failed);
        assert_eq!(result.error_type.as_deref(), Some("parse"));
        assert_eq!(result.first_token_latency_ms, None);
    }

    #[test]
    fn json_error_inside_success_status_is_not_accepted_as_a_completion() {
        let error = parse_chat_completion_metadata(
            r#"{"error":{"type":"upstream_error","message":"generation failed"}}"#,
        )
        .expect_err("JSON error envelope is rejected");

        assert_eq!(error.kind, ProviderErrorKind::Http);
        assert!(error.message.contains("generation failed"));
    }

    #[test]
    fn connection_test_maps_error_response_without_full_body() {
        let transport = MockTransport::new(TransportResponse {
            status: 401,
            body: r#"{"error":{"type":"auth_error","message":"Authorization: Bearer contract-secret-1234 failed"},"debug":"full response body"}"#.to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 6,
        });
        let adapter = OpenAiCompatibleAdapter::new(transport);
        let result = adapter.test_connection(
            &profile(ProviderKind::DeepSeek),
            &ApiSecret::new("contract-secret-1234"),
        );

        assert_eq!(result.status, crate::types::ConnectionTestStatus::Failed);
        assert_eq!(result.http_status, Some(401));
        assert_eq!(result.error_type, Some("http".to_owned()));
        assert!(!result.message.contains("contract-secret-1234"));
        assert!(!result.message.contains("full response body"));
    }

    #[test]
    fn transport_response_debug_redacts_complete_body() {
        let response = TransportResponse {
            status: 401,
            body: "provider body with contract-secret-1234".to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 6,
        };
        let debug = format!("{response:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("provider body"));
        assert!(!debug.contains("contract-secret-1234"));
    }

    #[test]
    fn first_content_token_ignores_keepalive_role_and_empty_deltas() {
        let mut parser = StreamParser::new();

        assert!(!stream_chunk_has_content(
            &mut parser,
            b": keep-alive\n\ndata: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n"
        ));
        assert!(stream_chunk_has_content(
            &mut parser,
            b"data: {\"choices\":[{\"delta\":{\"content\":\"p\"}}]}\n\n"
        ));
    }

    #[test]
    fn first_content_token_is_detected_when_eof_terminates_the_event() {
        let mut parser = StreamParser::new();

        assert!(!stream_chunk_has_content(
            &mut parser,
            br#"data: {"choices":[{"delta":{"content":"pong"}}]}"#
        ));
        assert!(stream_finish_has_content(&mut parser));
    }

    #[test]
    fn response_buffer_limit_rejects_oversize_chunk_without_retaining_it() {
        let mut body = b"1234".to_vec();
        append_bounded_response_chunk(&mut body, b"5678", 8, Some(200))
            .expect("response at the exact limit is accepted");
        let error =
            append_bounded_response_chunk(&mut body, b"secret-response-content", 8, Some(200))
                .expect_err("response beyond the limit is rejected");

        assert_eq!(body, b"12345678");
        assert_eq!(error.kind, ProviderErrorKind::Parse);
        assert_eq!(error.http_status, Some(200));
        assert!(!error.message.contains("secret-response-content"));
        assert!(error.message.contains("8-byte safety limit"));
    }

    #[test]
    fn cancellation_is_reported_before_transport_runs() {
        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: String::new(),
            first_content_token_latency_ms: None,
            total_latency_ms: 0,
        });
        let cancellation = RequestCancellation::default();
        cancellation.cancel();
        let adapter = OpenAiCompatibleAdapter::new(transport.clone());

        let error = adapter
            .send_chat_with_cancellation(
                &profile(ProviderKind::DeepSeek),
                &ApiSecret::new("contract-secret-1234"),
                &request_for_contract(),
                &cancellation,
            )
            .expect_err("cancelled request does not run");

        assert_eq!(error.kind, ProviderErrorKind::Cancelled);
        assert!(transport.requests.lock().expect("requests lock").is_empty());
    }

    #[test]
    fn connection_test_preserves_timeout_type_and_redacts_known_secret() {
        let adapter = OpenAiCompatibleAdapter::new(FailingTransport {
            error: ProviderError::new(
                ProviderErrorKind::Timeout,
                "request timed out for contract-secret-1234",
            ),
        });
        let result = adapter.test_connection(
            &profile(ProviderKind::DeepSeek),
            &ApiSecret::new("contract-secret-1234"),
        );

        assert_eq!(result.status, crate::types::ConnectionTestStatus::Failed);
        assert_eq!(result.error_type.as_deref(), Some("timeout"));
        assert!(!result.message.contains("contract-secret-1234"));
        assert!(result.message.contains("<redacted>"));
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

    #[derive(Debug, Clone)]
    struct FailingTransport {
        error: ProviderError,
    }

    impl ChatTransport for FailingTransport {
        fn send(&self, _request: TransportRequest) -> Result<TransportResponse, ProviderError> {
            Err(self.error.clone())
        }
    }
}
