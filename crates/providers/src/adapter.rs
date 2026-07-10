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
    time::{Duration, Instant},
};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportResponse {
    pub status: u16,
    pub body: String,
    pub first_byte_latency_ms: u128,
    pub total_latency_ms: u128,
}

pub trait ChatTransport: Send + Sync {
    fn send(&self, request: TransportRequest) -> Result<TransportResponse, ProviderError>;
}

#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

/// Async transport used by business commands that must consume provider bytes
/// as they arrive. The existing blocking transport remains unchanged for the
/// stage 2 connection probe contract.
#[derive(Debug, Clone)]
pub struct ReqwestStreamingTransport {
    client: reqwest::Client,
}

#[derive(Debug)]
pub struct StreamingTransportResponse {
    status: u16,
    response: reqwest::Response,
}

impl ReqwestStreamingTransport {
    pub fn new(timeout: Duration) -> Result<Self, ProviderError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| ProviderError::new(ProviderErrorKind::Network, error.to_string()))?;

        Ok(Self { client })
    }

    pub async fn send_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
    ) -> Result<StreamingTransportResponse, ProviderError> {
        let request = build_transport_request(profile, secret, request)?;
        let mut builder = self.client.post(&request.url);

        for header in &request.headers {
            builder = builder.header(&header.name, &header.value);
        }

        let response =
            builder.body(request.body).send().await.map_err(|error| {
                ProviderError::new(ProviderErrorKind::Network, error.to_string())
            })?;

        Ok(StreamingTransportResponse {
            status: response.status().as_u16(),
            response,
        })
    }
}

impl StreamingTransportResponse {
    pub fn status(&self) -> u16 {
        self.status
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProviderError> {
        self.response
            .chunk()
            .await
            .map(|chunk| chunk.map(|chunk| chunk.to_vec()))
            .map_err(|error| ProviderError::new(ProviderErrorKind::Network, error.to_string()))
    }

    pub async fn into_http_error(mut self) -> ProviderError {
        const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;
        let mut body = Vec::new();

        while body.len() < MAX_ERROR_BODY_BYTES {
            match self.response.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = MAX_ERROR_BODY_BYTES - body.len();
                    body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                }
                Ok(None) => break,
                Err(error) => {
                    return ProviderError::with_status(
                        ProviderErrorKind::Network,
                        self.status,
                        error.to_string(),
                    );
                }
            }
        }

        map_http_error(self.status, &String::from_utf8_lossy(&body))
    }
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
        let started_at = Instant::now();
        let mut builder = self.client.post(&request.url);

        for header in &request.headers {
            builder = builder.header(&header.name, &header.value);
        }

        let response = builder
            .body(request.body)
            .send()
            .map_err(|error| ProviderError::new(ProviderErrorKind::Network, error.to_string()))?;
        let first_byte_latency_ms = started_at.elapsed().as_millis();
        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(|error| ProviderError::new(ProviderErrorKind::Network, error.to_string()))?;

        Ok(TransportResponse {
            status,
            body,
            first_byte_latency_ms,
            total_latency_ms: started_at.elapsed().as_millis(),
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
        build_transport_request(profile, secret, request)
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

    pub fn test_connection(&self, profile: &ProviderProfile, secret: &ApiSecret) -> ConnectionTest {
        let request = ChatRequest::connection_probe();

        match self.send_chat(profile, secret, &request) {
            Ok(response) if (200..300).contains(&response.status) => {
                match parse_chat_completion_metadata(&response.body) {
                    Ok((model, usage)) => ConnectionTest::succeeded(
                        profile.id.clone(),
                        response.status,
                        model,
                        Some(response.first_byte_latency_ms),
                        response.total_latency_ms,
                        usage,
                    ),
                    Err(error) => ConnectionTest::failed(
                        profile.id.clone(),
                        Some(response.status),
                        Some(response.first_byte_latency_ms),
                        response.total_latency_ms,
                        &error,
                    ),
                }
            }
            Ok(response) => {
                let error = map_http_error(response.status, &response.body);
                ConnectionTest::failed(
                    profile.id.clone(),
                    Some(response.status),
                    Some(response.first_byte_latency_ms),
                    response.total_latency_ms,
                    &error,
                )
            }
            Err(error) => ConnectionTest::failed(profile.id.clone(), None, None, 0, &error),
        }
    }
}

fn build_transport_request(
    profile: &ProviderProfile,
    secret: &ApiSecret,
    request: &ChatRequest,
) -> Result<TransportRequest, ProviderError> {
    let url = chat_completions_url(&profile.base_url)?;
    let mut headers = vec![
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

    if profile.kind == ProviderKind::VolcengineArk {
        if let Some(workspace_id) = non_empty(profile.options.workspace_id.as_deref()) {
            headers.push(TransportHeader::new("X-Volcengine-Workspace", workspace_id));
        }
    }

    let body = build_chat_body(profile, request)?;

    Ok(TransportRequest {
        method: "POST".to_owned(),
        url,
        headers,
        body: serde_json::to_string(&body).map_err(|error| {
            ProviderError::new(ProviderErrorKind::InvalidRequest, error.to_string())
        })?,
    })
}

fn chat_completions_url(base_url: &str) -> Result<String, ProviderError> {
    let trimmed = base_url.trim().trim_end_matches('/');
    let parsed = reqwest::Url::parse(trimmed).map_err(|error| {
        ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            format!("invalid provider base URL: {error}"),
        )
    })?;

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
            insert_option(body, "thinking", options.thinking);
            insert_option(body, "thinking_budget", options.thinking_budget);
        }
        ProviderKind::Qwen => {
            insert_option(body, "enable_thinking", options.enable_thinking);
            insert_option(body, "thinking_budget", options.thinking_budget);
        }
        ProviderKind::SiliconFlow => {
            insert_option(body, "enable_thinking", options.enable_thinking);
            if let Some(thinking) = options.thinking {
                let mut thinking_object = Map::new();
                thinking_object.insert(
                    "type".to_owned(),
                    json!(if thinking { "enabled" } else { "disabled" }),
                );
                if let Some(budget) = options.thinking_budget {
                    thinking_object.insert("budget_tokens".to_owned(), json!(budget));
                }
                body.insert("thinking".to_owned(), Value::Object(thinking_object));
            } else {
                insert_option(body, "thinking_budget", options.thinking_budget);
            }
        }
        ProviderKind::VolcengineArk => {
            insert_option(body, "reasoning_effort", options.reasoning_effort);
            insert_option(body, "thinking", options.thinking);
        }
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
    let value: Value = serde_json::from_str(body).map_err(|error| {
        ProviderError::new(
            ProviderErrorKind::Parse,
            format!("provider response was not valid JSON: {error}"),
        )
    })?;

    let model = value
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let usage = value.get("usage").map(parse_usage);

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
                reasoning_effort: Some(ReasoningEffort::High),
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
        assert_eq!(body["model"], "deepseek-chat");
        assert_eq!(body["stream"], true);
        assert_eq!(body["reasoning_effort"], "high");
        assert_eq!(body["thinking_budget"], 2048);
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
    fn siliconflow_contract_maps_thinking_object() {
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
        assert_eq!(body["model"], "deepseek-ai/DeepSeek-V3");
        assert_eq!(body["enable_thinking"], true);
        assert_eq!(body["thinking"]["type"], "enabled");
        assert_eq!(body["thinking"]["budget_tokens"], 1024);
    }

    #[test]
    fn volcengine_contract_maps_endpoint_id_and_workspace_header() {
        let request = build(
            ProviderKind::VolcengineArk,
            ProviderOptions {
                endpoint_id: Some("ep-ark-custom".to_owned()),
                workspace_id: Some("workspace-a".to_owned()),
                reasoning_effort: Some(ReasoningEffort::Low),
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
        assert_eq!(
            request.header_value("X-Volcengine-Workspace"),
            Some("workspace-a")
        );
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
    fn connection_test_maps_success_response_from_mock_transport() {
        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: r#"{"model":"mock-model","usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#.to_owned(),
            first_byte_latency_ms: 7,
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
        assert_eq!(transport.requests.lock().expect("requests lock").len(), 1);
    }

    #[test]
    fn connection_test_maps_error_response_without_full_body() {
        let transport = MockTransport::new(TransportResponse {
            status: 401,
            body: r#"{"error":{"type":"auth_error","message":"Authorization: Bearer contract-secret-1234 failed"},"debug":"full response body"}"#.to_owned(),
            first_byte_latency_ms: 4,
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
}
