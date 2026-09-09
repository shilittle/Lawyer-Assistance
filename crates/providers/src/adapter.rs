use crate::{
    credentials::ApiSecret,
    redaction::truncate_for_log,
    types::{
        ApprovedChatBinding, ApprovedChatDraft, ApprovedChatRequest, ChatCompletion, ChatMessage,
        ChatMessageRole, ChatRequest, ChatRequestAuthority, ChatUsage, ConnectionTest,
        ProviderError, ProviderErrorKind, ProviderKind, ProviderOptions, ProviderProfile,
        WorkspaceAuthorizedRequest,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    error::Error as StdError,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::stream::{StreamEvent, StreamParser};

const MAX_PROVIDER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Hard ceiling for visible text returned by the public non-stream parser.
/// Callers must provide a positive limit no greater than this value.
pub const MAX_CHAT_COMPLETION_CONTENT_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_ABSOLUTE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const PRIVATE_DNS_REJECTION: &str = "provider-dns-rejected-special-address";
static SYNCHRONOUS_TRANSPORT_RUNTIME: OnceLock<
    Result<Arc<tokio::runtime::Runtime>, ProviderError>,
> = OnceLock::new();

const APPROVED_CHAT_SCHEMA_VERSION: u16 = 1;
const WORKSPACE_AUTHORIZED_SCHEMA_VERSION: u16 = 1;
const EXTERNAL_PROVIDER_DESTINATION: &str = "external_provider";
const WORKSPACE_REDACTION_ASSISTANCE_PURPOSE: &str = "redaction_assistance";
const WORKSPACE_SELECTED_CONTEXT_CHAT_PURPOSE: &str = "selected_context_chat";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalApprovedChatEnvelopeV1 {
    schema_version: u16,
    messages: Vec<ChatMessage>,
    stream: bool,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    transport_body_sha256: String,
    provider_id: String,
    provider_kind: ProviderKind,
    model_id: String,
    endpoint_origin: String,
    destination_kind: String,
    purpose: String,
    policy_id: String,
    policy_version: u32,
    detector_version: String,
    approval_generation_id: String,
    approved_redacted_content_sha256: String,
    ocr_provenance_sha256: String,
    expires_at_unix: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalWorkspaceAuthorizedEnvelopeV1 {
    schema_version: u16,
    messages: Vec<ChatMessage>,
    stream: bool,
    transport_body_sha256: String,
    profile_sha256: String,
    provider_id: String,
    provider_kind: ProviderKind,
    model_id: String,
    endpoint_origin: String,
    destination_kind: String,
    purpose: String,
    source_binding_sha256: String,
    expires_at_unix: u64,
}

#[derive(Debug)]
struct ProviderDnsResolver {
    allow_private_network: bool,
}

impl ProviderDnsResolver {
    fn new(allow_private_network: bool) -> Self {
        Self {
            allow_private_network,
        }
    }
}

impl reqwest::dns::Resolve for ProviderDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let allow_private_network = self.allow_private_network;
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| Box::new(error) as Box<dyn StdError + Send + Sync>)?
                .collect::<Vec<_>>();
            validate_resolved_addresses(&addresses, allow_private_network)
                .map_err(|error| Box::new(error) as Box<dyn StdError + Send + Sync>)?;
            let addresses: reqwest::dns::Addrs = Box::new(addresses.into_iter());
            Ok(addresses)
        })
    }
}

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

#[derive(Clone)]
struct ApprovedTransportAuthorization {
    canonical_payload: Arc<[u8]>,
    canonical_payload_sha256: String,
    body_sha256: String,
    provider_id: String,
    provider_kind: ProviderKind,
    model_id: String,
    endpoint_origin: String,
    purpose: String,
    policy_id: String,
    policy_version: u32,
    detector_version: String,
    approval_generation_id: String,
    approved_redacted_content_sha256: String,
    ocr_provenance_sha256: String,
    expires_at_unix: u64,
    receipt_id: String,
    transport_consumed: Arc<AtomicBool>,
}

#[derive(Clone)]
struct WorkspaceTransportAuthorization {
    canonical_payload: Arc<[u8]>,
    canonical_payload_sha256: String,
    body_sha256: String,
    profile_sha256: String,
    provider_id: String,
    provider_kind: ProviderKind,
    model_id: String,
    endpoint_origin: String,
    purpose: String,
    source_binding_sha256: String,
    expires_at_unix: u64,
    transport_consumed: Arc<AtomicBool>,
}

#[derive(Clone)]
enum TransportAuthorization {
    Public {
        body_sha256: String,
        endpoint_origin: String,
        authority: ChatRequestAuthority,
    },
    Approved(Box<ApprovedTransportAuthorization>),
    WorkspaceAuthorized(Box<WorkspaceTransportAuthorization>),
}

#[derive(Clone)]
pub struct TransportRequest {
    pub(crate) method: String,
    pub(crate) url: String,
    pub(crate) headers: Vec<TransportHeader>,
    pub(crate) body: String,
    pub(crate) expects_stream: bool,
    pub(crate) allow_private_network: bool,
    authorization: TransportAuthorization,
}

impl TransportRequest {
    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn headers(&self) -> &[TransportHeader] {
        &self.headers
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    pub fn body(&self) -> &str {
        &self.body
    }

    pub const fn expects_stream(&self) -> bool {
        self.expects_stream
    }

    pub const fn allow_private_network(&self) -> bool {
        self.allow_private_network
    }
}

impl fmt::Debug for TransportRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let authorization = match &self.authorization {
            TransportAuthorization::Public { .. } => "public",
            TransportAuthorization::Approved(_) => "approved_case",
            TransportAuthorization::WorkspaceAuthorized(_) => "workspace_authorized",
        };
        formatter
            .debug_struct("TransportRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body", &"<redacted>")
            .field("authorization", &authorization)
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
    safe_client: reqwest::Client,
    private_network_client: reqwest::Client,
    runtime: Arc<tokio::runtime::Runtime>,
}

/// Async transport used by business commands that must consume provider bytes
/// as they arrive. `ReqwestTransport` exposes the existing synchronous API but
/// now drives the same async/read-idle semantics on its private runtime.
#[derive(Debug, Clone)]
pub struct ReqwestStreamingTransport {
    safe_client: reqwest::Client,
    private_network_client: reqwest::Client,
}

#[derive(Debug)]
pub struct StreamingTransportResponse {
    status: u16,
    response: reqwest::Response,
}

impl ReqwestStreamingTransport {
    /// Builds clients with independent connection/read-idle timeouts and a
    /// generous absolute deadline.
    ///
    /// The historical single argument is retained for API compatibility, but
    /// it is no longer an end-to-end deadline. Each successfully received
    /// response chunk resets reqwest's read timeout, so provider queues and SSE
    /// keep-alives can remain active longer than this duration, up to the
    /// absolute 15-minute safety limit.
    pub fn new(timeout: Duration) -> Result<Self, ProviderError> {
        Self::new_with_limits(timeout, timeout, DEFAULT_ABSOLUTE_REQUEST_TIMEOUT)
    }

    pub fn new_with_timeouts(
        connect_timeout: Duration,
        read_idle_timeout: Duration,
    ) -> Result<Self, ProviderError> {
        Self::new_with_limits(
            connect_timeout,
            read_idle_timeout,
            DEFAULT_ABSOLUTE_REQUEST_TIMEOUT,
        )
    }

    pub fn new_with_limits(
        connect_timeout: Duration,
        read_idle_timeout: Duration,
        absolute_timeout: Duration,
    ) -> Result<Self, ProviderError> {
        let (safe_client, private_network_client) =
            build_reqwest_clients(connect_timeout, read_idle_timeout, absolute_timeout)?;

        Ok(Self {
            safe_client,
            private_network_client,
        })
    }

    pub async fn send_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
    ) -> Result<StreamingTransportResponse, ProviderError> {
        let request = build_transport_request(profile, secret, request)?;
        self.send_transport_request(secret, request).await
    }

    pub async fn send_approved_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ApprovedChatRequest,
    ) -> Result<StreamingTransportResponse, ProviderError> {
        let request = build_approved_transport_request(profile, secret, request)?;
        self.send_transport_request(secret, request).await
    }

    /// Sends a request produced by the trusted workspace-authorization
    /// boundary. This is the only provider path that may carry original
    /// material for `redaction_assistance`.
    pub async fn send_workspace_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &WorkspaceAuthorizedRequest,
    ) -> Result<StreamingTransportResponse, ProviderError> {
        let request = build_workspace_transport_request(profile, secret, request)?;
        self.send_transport_request(secret, request).await
    }

    async fn send_transport_request(
        &self,
        secret: &ApiSecret,
        request: TransportRequest,
    ) -> Result<StreamingTransportResponse, ProviderError> {
        let client = select_client(&self.safe_client, &self.private_network_client, &request)?;
        validate_transport_authorization(&request, true)?;
        let mut builder = client.post(&request.url);

        for header in &request.headers {
            builder = builder.header(&header.name, &header.value);
        }

        let response = builder
            .body(request.body)
            .send()
            .await
            .map_err(|error| redact_known_secret(map_reqwest_error(error), secret))?;

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
            .map_err(map_reqwest_error)
    }

    pub async fn into_http_error(mut self, secret: &ApiSecret) -> ProviderError {
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
                    return redact_known_secret(
                        ProviderError::with_status(
                            if error.is_timeout() {
                                ProviderErrorKind::Timeout
                            } else {
                                ProviderErrorKind::Network
                            },
                            self.status,
                            error.to_string(),
                        ),
                        secret,
                    );
                }
            }
        }

        redact_known_secret(
            map_http_error(self.status, &String::from_utf8_lossy(&body), secret),
            secret,
        )
    }
}

impl ReqwestTransport {
    /// Builds clients with independent connection/read-idle timeouts and a
    /// generous absolute deadline.
    ///
    /// This preserves the original constructor while allowing a healthy
    /// long-lived stream to outlive the idle timeout. A separate 15-minute
    /// absolute deadline prevents a hostile keep-alive stream from running
    /// forever.
    pub fn new(timeout: Duration) -> Result<Self, ProviderError> {
        Self::new_with_limits(timeout, timeout, DEFAULT_ABSOLUTE_REQUEST_TIMEOUT)
    }

    pub fn new_with_timeouts(
        connect_timeout: Duration,
        read_idle_timeout: Duration,
    ) -> Result<Self, ProviderError> {
        Self::new_with_limits(
            connect_timeout,
            read_idle_timeout,
            DEFAULT_ABSOLUTE_REQUEST_TIMEOUT,
        )
    }

    pub fn new_with_limits(
        connect_timeout: Duration,
        read_idle_timeout: Duration,
        absolute_timeout: Duration,
    ) -> Result<Self, ProviderError> {
        let runtime = synchronous_transport_runtime()?;
        let (safe_client, private_network_client) =
            build_reqwest_clients(connect_timeout, read_idle_timeout, absolute_timeout)?;

        Ok(Self {
            safe_client,
            private_network_client,
            runtime,
        })
    }
}

fn build_reqwest_clients(
    connect_timeout: Duration,
    read_idle_timeout: Duration,
    absolute_timeout: Duration,
) -> Result<(reqwest::Client, reqwest::Client), ProviderError> {
    if connect_timeout.is_zero() || read_idle_timeout.is_zero() || absolute_timeout.is_zero() {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider transport timeouts must be greater than zero",
        ));
    }

    Ok((
        build_reqwest_client(connect_timeout, read_idle_timeout, absolute_timeout, false)?,
        build_reqwest_client(connect_timeout, read_idle_timeout, absolute_timeout, true)?,
    ))
}

fn build_reqwest_client(
    connect_timeout: Duration,
    read_idle_timeout: Duration,
    absolute_timeout: Duration,
    allow_private_network: bool,
) -> Result<reqwest::Client, ProviderError> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout)
        .read_timeout(read_idle_timeout)
        .timeout(absolute_timeout)
        .dns_resolver(Arc::new(ProviderDnsResolver::new(allow_private_network)))
        .build()
        .map_err(|error| ProviderError::new(ProviderErrorKind::Network, error.to_string()))
}

fn select_client<'a>(
    safe_client: &'a reqwest::Client,
    private_network_client: &'a reqwest::Client,
    request: &TransportRequest,
) -> Result<&'a reqwest::Client, ProviderError> {
    validate_transport_destination(request)?;
    validate_transport_authorization(request, false)?;
    Ok(if request.allow_private_network {
        private_network_client
    } else {
        safe_client
    })
}

fn synchronous_transport_runtime() -> Result<Arc<tokio::runtime::Runtime>, ProviderError> {
    SYNCHRONOUS_TRANSPORT_RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .map(Arc::new)
                .map_err(|error| ProviderError::new(ProviderErrorKind::Network, error.to_string()))
        })
        .clone()
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
        let client =
            select_client(&self.safe_client, &self.private_network_client, &request)?.clone();

        // A synchronous caller may itself run on a Tokio worker. Entering a
        // second runtime there would panic, so drive the request from a scoped
        // OS thread in that uncommon case while preserving the sync API.
        if tokio::runtime::Handle::try_current().is_ok() {
            return std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        self.runtime
                            .block_on(Self::send_inner_async(client, request, cancellation))
                    })
                    .join()
                    .map_err(|_| {
                        ProviderError::new(
                            ProviderErrorKind::Network,
                            "provider transport worker terminated unexpectedly",
                        )
                    })?
            });
        }

        self.runtime
            .block_on(Self::send_inner_async(client, request, cancellation))
    }

    async fn send_inner_async(
        client: reqwest::Client,
        request: TransportRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError> {
        if cancellation.is_cancelled() {
            return Err(cancelled_error());
        }
        validate_transport_authorization(&request, true)?;

        let started_at = Instant::now();
        let expects_stream = request.expects_stream;
        let mut builder = client.post(&request.url);

        for header in &request.headers {
            builder = builder.header(&header.name, &header.value);
        }

        let response = builder
            .body(request.body)
            .send()
            .await
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
        let mut parser = StreamParser::new();
        let mut first_content_token_latency_ms = None;

        loop {
            if cancellation.is_cancelled() {
                return Err(cancelled_error());
            }

            let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? else {
                if expects_stream
                    && first_content_token_latency_ms.is_none()
                    && stream_finish_has_activity(&mut parser)
                {
                    first_content_token_latency_ms = Some(elapsed_millis(&started_at));
                }
                break;
            };
            if cancellation.is_cancelled() {
                return Err(cancelled_error());
            }

            append_bounded_response_chunk(
                &mut body,
                &chunk,
                MAX_PROVIDER_RESPONSE_BYTES,
                Some(status),
            )?;
            if expects_stream
                && first_content_token_latency_ms.is_none()
                && stream_chunk_has_activity(&mut parser, &chunk)
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

/// Provider-facing boundary shared by all supported BYOK profiles.
///
/// Provider-specific URL and body differences stay inside the adapter while
/// callers depend on one typed chat/connection contract.
pub trait ProviderAdapter: Send + Sync {
    fn send_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
    ) -> Result<TransportResponse, ProviderError>;

    fn send_approved_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ApprovedChatRequest,
    ) -> Result<TransportResponse, ProviderError>;

    fn send_chat_with_cancellation(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError>;

    fn send_approved_chat_with_cancellation(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ApprovedChatRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError>;

    fn test_connection(&self, profile: &ProviderProfile, secret: &ApiSecret) -> ConnectionTest;
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

    pub fn build_approved_transport_request(
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ApprovedChatRequest,
    ) -> Result<TransportRequest, ProviderError> {
        build_approved_transport_request(profile, secret, request)
    }

    fn build_workspace_transport_request(
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &WorkspaceAuthorizedRequest,
    ) -> Result<TransportRequest, ProviderError> {
        build_workspace_transport_request(profile, secret, request)
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

    pub fn send_approved_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ApprovedChatRequest,
    ) -> Result<TransportResponse, ProviderError> {
        let transport_request = Self::build_approved_transport_request(profile, secret, request)?;
        self.transport.send(transport_request)
    }

    /// Synchronously sends an opaque trusted-workspace authorization. Unlike
    /// `send_chat`, this is the sole synchronous entry point for original
    /// material authorized for redaction assistance.
    pub fn send_workspace_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &WorkspaceAuthorizedRequest,
    ) -> Result<TransportResponse, ProviderError> {
        let transport_request = Self::build_workspace_transport_request(profile, secret, request)?;
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

    pub fn send_approved_chat_with_cancellation(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ApprovedChatRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError> {
        let transport_request = Self::build_approved_transport_request(profile, secret, request)?;
        self.transport
            .send_with_cancellation(transport_request, cancellation)
    }

    pub fn test_connection(&self, profile: &ProviderProfile, secret: &ApiSecret) -> ConnectionTest {
        let request = ChatRequest::connection_probe();
        let started_at = Instant::now();

        match self.send_chat(profile, secret, &request) {
            Ok(response) if (200..300).contains(&response.status) => {
                let parsed =
                    parse_chat_completion_metadata(&response.body, secret).and_then(|metadata| {
                        match response.first_content_token_latency_ms {
                            Some(first_latency)
                                if first_latency > 0
                                    && first_latency <= response.total_latency_ms =>
                            {
                                Ok(metadata)
                            }
                            Some(_) => Err(ProviderError::new(
                                ProviderErrorKind::Parse,
                                "provider returned an invalid first content token latency",
                            )),
                            None => Err(ProviderError::new(
                                ProviderErrorKind::Parse,
                                "provider stream did not include a content or reasoning token",
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
                let error = map_http_error(response.status, &response.body, secret);
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

impl<T> ProviderAdapter for OpenAiCompatibleAdapter<T>
where
    T: ChatTransport,
{
    fn send_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
    ) -> Result<TransportResponse, ProviderError> {
        OpenAiCompatibleAdapter::send_chat(self, profile, secret, request)
    }

    fn send_approved_chat(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ApprovedChatRequest,
    ) -> Result<TransportResponse, ProviderError> {
        OpenAiCompatibleAdapter::send_approved_chat(self, profile, secret, request)
    }

    fn send_chat_with_cancellation(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError> {
        OpenAiCompatibleAdapter::send_chat_with_cancellation(
            self,
            profile,
            secret,
            request,
            cancellation,
        )
    }

    fn send_approved_chat_with_cancellation(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ApprovedChatRequest,
        cancellation: &RequestCancellation,
    ) -> Result<TransportResponse, ProviderError> {
        OpenAiCompatibleAdapter::send_approved_chat_with_cancellation(
            self,
            profile,
            secret,
            request,
            cancellation,
        )
    }

    fn test_connection(&self, profile: &ProviderProfile, secret: &ApiSecret) -> ConnectionTest {
        OpenAiCompatibleAdapter::test_connection(self, profile, secret)
    }
}

fn build_transport_request(
    profile: &ProviderProfile,
    secret: &ApiSecret,
    request: &ChatRequest,
) -> Result<TransportRequest, ProviderError> {
    if !matches!(
        request.authority,
        ChatRequestAuthority::ConnectionProbe
            | ChatRequestAuthority::LegalPublic
            | ChatRequestAuthority::ProductPublic
            | ChatRequestAuthority::InteractiveUserContent
    ) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved case chat requires an opaque approved request",
        ));
    }
    let url = chat_completions_url(profile)?;
    let endpoint_origin = provider_endpoint_origin(profile)?;
    let body = serde_json::to_string(&build_chat_body(profile, request, ChatBodyPath::Ordinary)?)
        .map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider request serialization failed",
        )
    })?;
    let authorization = TransportAuthorization::Public {
        body_sha256: privacy::sha256_hex(body.as_bytes()),
        endpoint_origin,
        authority: request.authority,
    };
    Ok(TransportRequest {
        method: "POST".to_owned(),
        url,
        headers: provider_headers(secret, request.stream),
        body,
        expects_stream: request.stream,
        allow_private_network: private_network_is_explicitly_allowed(profile),
        authorization,
    })
}

fn build_approved_transport_request(
    profile: &ProviderProfile,
    secret: &ApiSecret,
    approved: &ApprovedChatRequest,
) -> Result<TransportRequest, ProviderError> {
    validate_approved_request_for_profile(profile, approved)?;
    let request = &approved.draft.request;
    let url = chat_completions_url(profile)?;
    let body = serde_json::to_string(&build_chat_body(
        profile,
        request,
        ChatBodyPath::ApprovedCase,
    )?)
    .map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request serialization failed",
        )
    })?;
    let receipt_id = approved.receipt_id().ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request receipt is missing",
        )
    })?;
    if approved
        .consumed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request has already been consumed",
        ));
    }
    let authorization =
        TransportAuthorization::Approved(Box::new(ApprovedTransportAuthorization {
            canonical_payload: Arc::from(approved.draft.canonical_payload.clone()),
            canonical_payload_sha256: approved.draft.canonical_payload_sha256.clone(),
            body_sha256: privacy::sha256_hex(body.as_bytes()),
            provider_id: approved.draft.provider_id.clone(),
            provider_kind: approved.draft.provider_kind,
            model_id: approved.draft.model_id.clone(),
            endpoint_origin: approved.draft.endpoint_origin.clone(),
            purpose: approved.draft.binding.purpose.clone(),
            policy_id: approved.draft.binding.policy_id.clone(),
            policy_version: approved.draft.binding.policy_version,
            detector_version: approved.draft.binding.detector_version.clone(),
            approval_generation_id: approved.draft.binding.approval_generation_id.clone(),
            approved_redacted_content_sha256: approved
                .draft
                .binding
                .approved_redacted_content_sha256
                .clone(),
            ocr_provenance_sha256: approved.draft.binding.ocr_provenance_sha256.clone(),
            expires_at_unix: approved.draft.binding.expires_at_unix,
            receipt_id: receipt_id.to_owned(),
            transport_consumed: Arc::new(AtomicBool::new(false)),
        }));
    Ok(TransportRequest {
        method: "POST".to_owned(),
        url,
        headers: provider_headers(secret, request.stream),
        body,
        expects_stream: request.stream,
        allow_private_network: private_network_is_explicitly_allowed(profile),
        authorization,
    })
}

fn build_workspace_transport_request(
    profile: &ProviderProfile,
    secret: &ApiSecret,
    workspace: &WorkspaceAuthorizedRequest,
) -> Result<TransportRequest, ProviderError> {
    validate_workspace_request_for_profile(profile, workspace)?;
    let request = &workspace.request;
    let url = chat_completions_url(profile)?;
    let body = serde_json::to_string(&build_chat_body(
        profile,
        request,
        ChatBodyPath::WorkspaceAuthorized,
    )?)
    .map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request serialization failed",
        )
    })?;
    if workspace
        .consumed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request has already been consumed",
        ));
    }
    let authorization =
        TransportAuthorization::WorkspaceAuthorized(Box::new(WorkspaceTransportAuthorization {
            canonical_payload: workspace.canonical_payload.clone(),
            canonical_payload_sha256: workspace.canonical_payload_sha256.clone(),
            body_sha256: privacy::sha256_hex(body.as_bytes()),
            profile_sha256: workspace.profile_sha256.clone(),
            provider_id: workspace.provider_id.clone(),
            provider_kind: workspace.provider_kind,
            model_id: workspace.model_id.clone(),
            endpoint_origin: workspace.endpoint_origin.clone(),
            purpose: workspace.purpose.clone(),
            source_binding_sha256: workspace.source_binding_sha256.clone(),
            expires_at_unix: workspace.expires_at_unix,
            transport_consumed: Arc::new(AtomicBool::new(false)),
        }));
    Ok(TransportRequest {
        method: "POST".to_owned(),
        url,
        headers: provider_headers(secret, request.stream),
        body,
        expects_stream: request.stream,
        allow_private_network: private_network_is_explicitly_allowed(profile),
        authorization,
    })
}

fn validate_approved_request_for_profile(
    profile: &ProviderProfile,
    approved: &ApprovedChatRequest,
) -> Result<(), ProviderError> {
    validate_approved_draft(&approved.draft)?;
    let now_unix = system_unix_time()?;
    let endpoint_origin = provider_endpoint_origin(profile)?;
    let destination = approved.outbound.destination();
    let active_transport_body_sha256 =
        approved_transport_body_sha256(profile, &approved.draft.request)?;
    if approved.outbound.classification() != privacy::DataClassification::CaseRedactedApproved
        || approved.outbound.payload() != approved.draft.canonical_payload
        || approved.outbound.payload_sha256() != approved.draft.canonical_payload_sha256
        || destination.kind != privacy::DestinationKind::ExternalProvider
        || destination.identifier != approved.draft.provider_id
        || profile.id != approved.draft.provider_id
        || profile.kind != approved.draft.provider_kind
        || effective_model_id(profile) != approved.draft.model_id
        || endpoint_origin != approved.draft.endpoint_origin
        || approved.draft.binding.expires_at_unix <= now_unix
        || active_transport_body_sha256 != approved.draft.transport_body_sha256
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request no longer matches the active provider profile",
        ));
    }
    Ok(())
}

fn validate_workspace_request_for_profile(
    profile: &ProviderProfile,
    workspace: &WorkspaceAuthorizedRequest,
) -> Result<(), ProviderError> {
    validate_workspace_request(workspace)?;
    let now_unix = system_unix_time()?;
    let endpoint_origin = provider_endpoint_origin(profile)?;
    let active_profile_sha256 = workspace_profile_sha256(profile)?;
    let active_transport_body_sha256 =
        workspace_transport_body_sha256(profile, &workspace.request)?;
    if profile.id != workspace.provider_id
        || profile.kind != workspace.provider_kind
        || effective_model_id(profile) != workspace.model_id
        || endpoint_origin != workspace.endpoint_origin
        || active_profile_sha256 != workspace.profile_sha256
        || workspace.expires_at_unix <= now_unix
        || active_transport_body_sha256 != workspace.transport_body_sha256
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request no longer matches the active provider profile",
        ));
    }
    Ok(())
}

fn provider_headers(secret: &ApiSecret, stream: bool) -> Vec<TransportHeader> {
    vec![
        TransportHeader::new(
            "Authorization",
            format!("Bearer {}", secret.expose_secret()),
        ),
        TransportHeader::new("Content-Type", "application/json"),
        TransportHeader::new(
            "Accept",
            if stream {
                "text/event-stream"
            } else {
                "application/json"
            },
        ),
    ]
}

pub fn provider_endpoint_origin(profile: &ProviderProfile) -> Result<String, ProviderError> {
    let (_, parsed) = parsed_provider_base_url(profile)?;
    Ok(parsed.origin().ascii_serialization())
}

fn approved_transport_body_sha256(
    profile: &ProviderProfile,
    request: &ChatRequest,
) -> Result<String, ProviderError> {
    let body = build_chat_body(profile, request, ChatBodyPath::ApprovedCase)?;
    let bytes = serde_json::to_vec(&body).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request serialization failed",
        )
    })?;
    Ok(privacy::sha256_hex(&bytes))
}

fn workspace_transport_body_sha256(
    profile: &ProviderProfile,
    request: &ChatRequest,
) -> Result<String, ProviderError> {
    let body = build_chat_body(profile, request, ChatBodyPath::WorkspaceAuthorized)?;
    let bytes = serde_json::to_vec(&body).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request serialization failed",
        )
    })?;
    Ok(privacy::sha256_hex(&bytes))
}

fn workspace_profile_sha256(profile: &ProviderProfile) -> Result<String, ProviderError> {
    let bytes = serde_json::to_vec(profile).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "provider profile canonicalization failed",
        )
    })?;
    Ok(privacy::sha256_hex(&bytes))
}

/// Builds the opaque one-shot authorization required to send sensitive
/// workspace content to a Provider.
///
/// This function is intentionally a trusted backend boundary. Its caller must
/// already have atomically consumed a persisted, version-bound workspace batch
/// authorization and verified that the current source material corresponds to
/// `source_binding_sha256`. WebUI and MCP request handlers must never accept a
/// serialized form of `WorkspaceAuthorizedRequest`, must not create it from
/// client input directly, and remain responsible for confirming that selected
/// redacted context is active before using `selected_context_chat`.
pub fn authorize_workspace_request(
    profile: &ProviderProfile,
    messages: Vec<ChatMessage>,
    stream: bool,
    purpose: &str,
    source_binding_sha256: &str,
    expires_at_unix: u64,
) -> Result<WorkspaceAuthorizedRequest, ProviderError> {
    validate_workspace_purpose(purpose)?;
    if !valid_lower_sha256(source_binding_sha256) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace source binding is invalid",
        ));
    }
    if expires_at_unix <= system_unix_time()? {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request expiry must be in the future",
        ));
    }
    validate_chat_shape(&messages, None, None)?;
    let endpoint_origin = provider_endpoint_origin(profile)?;
    let model_id = effective_model_id(profile).to_owned();
    validate_provider_binding_text("provider ID", &profile.id)?;
    validate_provider_binding_text("model ID", &model_id)?;
    let profile_sha256 = workspace_profile_sha256(profile)?;

    let request = ChatRequest {
        messages,
        stream,
        temperature: None,
        max_tokens: None,
        authority: ChatRequestAuthority::WorkspaceAuthorized,
    };
    // The exact opaque workspace authority is the only non-interactive path
    // permitted to carry residual PII. `build_chat_body` still validates the
    // full request shape and provider-specific options before it is bound.
    let transport_body_sha256 = workspace_transport_body_sha256(profile, &request)?;
    let envelope = CanonicalWorkspaceAuthorizedEnvelopeV1 {
        schema_version: WORKSPACE_AUTHORIZED_SCHEMA_VERSION,
        messages: request.messages.clone(),
        stream: request.stream,
        transport_body_sha256: transport_body_sha256.clone(),
        profile_sha256: profile_sha256.clone(),
        provider_id: profile.id.clone(),
        provider_kind: profile.kind,
        model_id: model_id.clone(),
        endpoint_origin: endpoint_origin.clone(),
        destination_kind: EXTERNAL_PROVIDER_DESTINATION.to_owned(),
        purpose: purpose.to_owned(),
        source_binding_sha256: source_binding_sha256.to_owned(),
        expires_at_unix,
    };
    let canonical_payload = serde_json::to_vec(&envelope).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request canonicalization failed",
        )
    })?;
    let canonical_payload_sha256 = privacy::sha256_hex(&canonical_payload);
    Ok(WorkspaceAuthorizedRequest {
        request,
        canonical_payload: Arc::from(canonical_payload),
        canonical_payload_sha256,
        transport_body_sha256,
        profile_sha256,
        provider_id: profile.id.clone(),
        provider_kind: profile.kind,
        model_id,
        endpoint_origin,
        purpose: purpose.to_owned(),
        source_binding_sha256: source_binding_sha256.to_owned(),
        expires_at_unix,
        consumed: Arc::new(AtomicBool::new(false)),
    })
}

pub fn prepare_approved_chat(
    profile: &ProviderProfile,
    messages: Vec<ChatMessage>,
    stream: bool,
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    binding: ApprovedChatBinding,
) -> Result<ApprovedChatDraft, ProviderError> {
    validate_chat_shape(&messages, temperature, max_tokens)?;
    validate_approved_binding(&binding)?;
    if binding.expires_at_unix <= system_unix_time()? {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request expiry must be in the future",
        ));
    }
    let endpoint_origin = provider_endpoint_origin(profile)?;
    let model_id = effective_model_id(profile).to_owned();
    validate_provider_binding_text("provider ID", &profile.id)?;
    validate_provider_binding_text("model ID", &model_id)?;
    scan_message_content(&messages, ChatRequestAuthority::ApprovedCase)?;

    let request = ChatRequest::approved_case(messages, stream, temperature, max_tokens);
    let transport_body_sha256 = approved_transport_body_sha256(profile, &request)?;
    let envelope = CanonicalApprovedChatEnvelopeV1 {
        schema_version: APPROVED_CHAT_SCHEMA_VERSION,
        messages: request.messages.clone(),
        transport_body_sha256: transport_body_sha256.clone(),
        stream: request.stream,
        temperature: request.temperature,
        max_tokens: request.max_tokens,
        provider_id: profile.id.clone(),
        provider_kind: profile.kind,
        model_id: model_id.clone(),
        endpoint_origin: endpoint_origin.clone(),
        destination_kind: EXTERNAL_PROVIDER_DESTINATION.to_owned(),
        purpose: binding.purpose.clone(),
        policy_id: binding.policy_id.clone(),
        policy_version: binding.policy_version,
        detector_version: binding.detector_version.clone(),
        approval_generation_id: binding.approval_generation_id.clone(),
        approved_redacted_content_sha256: binding.approved_redacted_content_sha256.clone(),
        ocr_provenance_sha256: binding.ocr_provenance_sha256.clone(),
        expires_at_unix: binding.expires_at_unix,
    };
    let canonical_payload = serde_json::to_vec(&envelope).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request canonicalization failed",
        )
    })?;
    let residual = privacy::scan_residual(&canonical_payload).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request privacy validation failed",
        )
    })?;
    if !residual.passed {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request contains residual sensitive content",
        ));
    }
    let canonical_payload_sha256 = privacy::sha256_hex(&canonical_payload);
    Ok(ApprovedChatDraft {
        transport_body_sha256,
        request,
        canonical_payload,
        canonical_payload_sha256,
        provider_id: profile.id.clone(),
        provider_kind: profile.kind,
        model_id,
        endpoint_origin,
        binding,
    })
}

pub fn authorize_approved_chat(
    draft: ApprovedChatDraft,
    signer: privacy::ReceiptSigner,
    receipt: &privacy::SignedRedactionReceipt,
) -> Result<ApprovedChatRequest, ProviderError> {
    validate_approved_draft(&draft)?;
    let now_unix = system_unix_time()?;
    if draft.binding.expires_at_unix <= now_unix {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request has expired",
        ));
    }
    let destination = privacy::DestinationScope {
        kind: privacy::DestinationKind::ExternalProvider,
        identifier: draft.provider_id.clone(),
    };
    if receipt.claims.destination != destination
        || receipt.claims.purpose != draft.binding.purpose
        || receipt.claims.policy_id != draft.binding.policy_id
        || receipt.claims.policy_version != draft.binding.policy_version
        || receipt.claims.detector_version != draft.binding.detector_version
        || receipt.claims.redacted_content_sha256 != draft.binding.approved_redacted_content_sha256
        || receipt.claims.extraction_sha256 != draft.binding.ocr_provenance_sha256
        || receipt.claims.expires_at_unix != Some(draft.binding.expires_at_unix)
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request receipt binding mismatch",
        ));
    }
    let engine = privacy::EgressPolicyEngine::new(
        signer,
        draft.binding.policy_id.clone(),
        draft.binding.policy_version,
    )
    .map_err(map_egress_error)?;
    let outbound = engine
        .authorize(&privacy::EgressCandidate {
            payload: &draft.canonical_payload,
            classification: privacy::DataClassification::CaseRedactedApproved,
            destination: &destination,
            purpose: &draft.binding.purpose,
            receipt: Some(receipt),
            now_unix,
        })
        .map_err(map_egress_error)?;
    if outbound.payload_sha256() != draft.canonical_payload_sha256
        || outbound.payload() != draft.canonical_payload
        || outbound.classification() != privacy::DataClassification::CaseRedactedApproved
        || outbound.destination() != &destination
        || outbound.receipt_id() != Some(receipt.claims.receipt_id.as_str())
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request authorization proof mismatch",
        ));
    }
    Ok(ApprovedChatRequest {
        draft,
        outbound,
        consumed: Arc::new(AtomicBool::new(false)),
    })
}

fn validate_approved_draft(draft: &ApprovedChatDraft) -> Result<(), ProviderError> {
    validate_approved_binding(&draft.binding)?;
    let expected = CanonicalApprovedChatEnvelopeV1 {
        schema_version: APPROVED_CHAT_SCHEMA_VERSION,
        messages: draft.request.messages.clone(),
        transport_body_sha256: draft.transport_body_sha256.clone(),
        stream: draft.request.stream,
        temperature: draft.request.temperature,
        max_tokens: draft.request.max_tokens,
        provider_id: draft.provider_id.clone(),
        provider_kind: draft.provider_kind,
        model_id: draft.model_id.clone(),
        endpoint_origin: draft.endpoint_origin.clone(),
        destination_kind: EXTERNAL_PROVIDER_DESTINATION.to_owned(),
        purpose: draft.binding.purpose.clone(),
        policy_id: draft.binding.policy_id.clone(),
        policy_version: draft.binding.policy_version,
        detector_version: draft.binding.detector_version.clone(),
        approval_generation_id: draft.binding.approval_generation_id.clone(),
        approved_redacted_content_sha256: draft.binding.approved_redacted_content_sha256.clone(),
        ocr_provenance_sha256: draft.binding.ocr_provenance_sha256.clone(),
        expires_at_unix: draft.binding.expires_at_unix,
    };
    let decoded: CanonicalApprovedChatEnvelopeV1 = serde_json::from_slice(&draft.canonical_payload)
        .map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "approved provider request canonical payload is invalid",
            )
        })?;
    let rebuilt = serde_json::to_vec(&expected).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request canonicalization failed",
        )
    })?;
    if decoded != expected
        || rebuilt != draft.canonical_payload
        || privacy::sha256_hex(&draft.canonical_payload) != draft.canonical_payload_sha256
        || draft.request.authority != ChatRequestAuthority::ApprovedCase
        || !valid_lower_sha256(&draft.transport_body_sha256)
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request canonical payload mismatch",
        ));
    }
    Ok(())
}

fn validate_workspace_request(workspace: &WorkspaceAuthorizedRequest) -> Result<(), ProviderError> {
    validate_workspace_purpose(&workspace.purpose)?;
    validate_provider_binding_text("provider ID", &workspace.provider_id)?;
    validate_provider_binding_text("model ID", &workspace.model_id)?;
    if !valid_lower_sha256(&workspace.source_binding_sha256)
        || !valid_lower_sha256(&workspace.transport_body_sha256)
        || !valid_lower_sha256(&workspace.profile_sha256)
        || workspace.expires_at_unix == 0
        || workspace.request.authority != ChatRequestAuthority::WorkspaceAuthorized
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request binding is invalid",
        ));
    }
    validate_chat_shape(
        &workspace.request.messages,
        workspace.request.temperature,
        workspace.request.max_tokens,
    )?;
    let expected = CanonicalWorkspaceAuthorizedEnvelopeV1 {
        schema_version: WORKSPACE_AUTHORIZED_SCHEMA_VERSION,
        messages: workspace.request.messages.clone(),
        stream: workspace.request.stream,
        transport_body_sha256: workspace.transport_body_sha256.clone(),
        profile_sha256: workspace.profile_sha256.clone(),
        provider_id: workspace.provider_id.clone(),
        provider_kind: workspace.provider_kind,
        model_id: workspace.model_id.clone(),
        endpoint_origin: workspace.endpoint_origin.clone(),
        destination_kind: EXTERNAL_PROVIDER_DESTINATION.to_owned(),
        purpose: workspace.purpose.clone(),
        source_binding_sha256: workspace.source_binding_sha256.clone(),
        expires_at_unix: workspace.expires_at_unix,
    };
    let decoded: CanonicalWorkspaceAuthorizedEnvelopeV1 =
        serde_json::from_slice(&workspace.canonical_payload).map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "workspace provider request canonical payload is invalid",
            )
        })?;
    let rebuilt = serde_json::to_vec(&expected).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request canonicalization failed",
        )
    })?;
    if decoded != expected
        || rebuilt.as_slice() != workspace.canonical_payload.as_ref()
        || privacy::sha256_hex(&workspace.canonical_payload) != workspace.canonical_payload_sha256
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request canonical payload mismatch",
        ));
    }
    Ok(())
}

fn validate_approved_binding(binding: &ApprovedChatBinding) -> Result<(), ProviderError> {
    validate_provider_binding_text("purpose", &binding.purpose)?;
    validate_provider_binding_text("policy ID", &binding.policy_id)?;
    validate_provider_binding_text("detector version", &binding.detector_version)?;
    validate_provider_binding_text("approval generation ID", &binding.approval_generation_id)?;
    if binding.policy_version == 0
        || binding.detector_version != privacy::REDACTION_VERSION
        || !valid_lower_sha256(&binding.approved_redacted_content_sha256)
        || !valid_lower_sha256(&binding.ocr_provenance_sha256)
        || binding.expires_at_unix == 0
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "approved provider request binding is invalid",
        ));
    }
    Ok(())
}

fn validate_workspace_purpose(purpose: &str) -> Result<(), ProviderError> {
    if matches!(
        purpose,
        WORKSPACE_REDACTION_ASSISTANCE_PURPOSE | WORKSPACE_SELECTED_CONTEXT_CHAT_PURPOSE
    ) {
        Ok(())
    } else {
        Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "workspace provider request purpose is invalid",
        ))
    }
}

fn validate_provider_binding_text(name: &str, value: &str) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            format!("{name} is invalid"),
        ));
    }
    Ok(())
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn map_egress_error(error: privacy::EgressError) -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::InvalidRequest,
        format!("approved provider request rejected: {}", error.code()),
    )
}

fn system_unix_time() -> Result<u64, ProviderError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            ProviderError::new(
                ProviderErrorKind::InvalidRequest,
                "system clock is before the Unix epoch",
            )
        })
}

fn chat_completions_url(profile: &ProviderProfile) -> Result<String, ProviderError> {
    let (trimmed, _) = parsed_provider_base_url(profile)?;

    if trimmed.ends_with("/chat/completions") {
        Ok(trimmed)
    } else {
        Ok(format!("{trimmed}/chat/completions"))
    }
}

fn parsed_provider_base_url(
    profile: &ProviderProfile,
) -> Result<(String, reqwest::Url), ProviderError> {
    let resolved_base_url = resolve_base_url(profile)?;
    let base_url = resolved_base_url.as_str();
    let trimmed = base_url.trim().trim_end_matches('/').to_owned();
    let parsed = reqwest::Url::parse(&trimmed).map_err(|error| {
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
        "http" if literal_loopback_http_is_explicitly_allowed(profile, &parsed) => {}
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
        if is_private_provider_host(&host) && !private_network_is_explicitly_allowed(profile) {
            return Err(private_network_profile_error());
        }
    }

    Ok((trimmed, parsed))
}

/// Plain HTTP is allowed solely for an explicit custom profile targeting a
/// literal loopback IP. `localhost` and names ending in `.localhost` are
/// deliberately rejected: the URL parser alone cannot prove the resolver will
/// not later select a non-loopback address.
fn literal_loopback_http_is_explicitly_allowed(
    profile: &ProviderProfile,
    parsed: &reqwest::Url,
) -> bool {
    profile.kind == ProviderKind::Custom
        && private_network_is_explicitly_allowed(profile)
        && parsed.host_str().is_some_and(|host| {
            let host = host
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .unwrap_or(host);
            host.parse::<IpAddr>().is_ok_and(|address| match address {
                IpAddr::V4(address) => address == Ipv4Addr::LOCALHOST,
                IpAddr::V6(address) => address == Ipv6Addr::LOCALHOST,
            })
        })
}

fn private_network_is_explicitly_allowed(profile: &ProviderProfile) -> bool {
    profile.kind == ProviderKind::Custom && profile.options.allow_private_network == Some(true)
}

fn validate_transport_destination(request: &TransportRequest) -> Result<(), ProviderError> {
    let parsed = reqwest::Url::parse(&request.url).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "invalid provider request URL",
        )
    })?;
    if !request.allow_private_network && parsed.host_str().is_some_and(is_private_provider_host) {
        return Err(private_network_profile_error());
    }
    Ok(())
}

fn validate_transport_authorization(
    request: &TransportRequest,
    consume_approved: bool,
) -> Result<(), ProviderError> {
    if request.method != "POST"
        || request.header_value("Content-Type") != Some("application/json")
        || request
            .header_value("Authorization")
            .is_none_or(|value| !value.starts_with("Bearer ") || value.len() <= "Bearer ".len())
    {
        return Err(transport_authorization_error());
    }
    let parsed = reqwest::Url::parse(&request.url).map_err(|_| transport_authorization_error())?;
    let endpoint_origin = parsed.origin().ascii_serialization();
    let body_sha256 = privacy::sha256_hex(request.body.as_bytes());

    match &request.authorization {
        TransportAuthorization::Public {
            body_sha256: expected_body_sha256,
            endpoint_origin: expected_endpoint_origin,
            authority,
        } => {
            if body_sha256 != *expected_body_sha256
                || endpoint_origin != *expected_endpoint_origin
                || !matches!(
                    authority,
                    ChatRequestAuthority::ConnectionProbe
                        | ChatRequestAuthority::LegalPublic
                        | ChatRequestAuthority::ProductPublic
                        | ChatRequestAuthority::InteractiveUserContent
                )
            {
                return Err(transport_authorization_error());
            }
        }
        TransportAuthorization::Approved(authorization) => {
            let now_unix = system_unix_time()?;
            let canonical_sha256 = privacy::sha256_hex(&authorization.canonical_payload);
            let envelope: CanonicalApprovedChatEnvelopeV1 =
                serde_json::from_slice(&authorization.canonical_payload)
                    .map_err(|_| transport_authorization_error())?;
            let rebuilt_canonical =
                serde_json::to_vec(&envelope).map_err(|_| transport_authorization_error())?;
            let canonical_bytes: &[u8] = authorization.canonical_payload.as_ref();
            let body_matches_signed_envelope = body_sha256 == envelope.transport_body_sha256;
            let body: Value =
                serde_json::from_str(&request.body).map_err(|_| transport_authorization_error())?;
            if canonical_sha256 != authorization.canonical_payload_sha256
                || rebuilt_canonical.as_slice() != canonical_bytes
                || !body_matches_signed_envelope
                || envelope.transport_body_sha256 != authorization.body_sha256
                || body_sha256 != authorization.body_sha256
                || endpoint_origin != authorization.endpoint_origin
                || envelope.schema_version != APPROVED_CHAT_SCHEMA_VERSION
                || envelope.destination_kind != EXTERNAL_PROVIDER_DESTINATION
                || envelope.provider_id != authorization.provider_id
                || envelope.provider_kind != authorization.provider_kind
                || envelope.model_id != authorization.model_id
                || envelope.endpoint_origin != authorization.endpoint_origin
                || envelope.purpose != authorization.purpose
                || envelope.policy_id != authorization.policy_id
                || envelope.policy_version != authorization.policy_version
                || envelope.detector_version != authorization.detector_version
                || envelope.approval_generation_id != authorization.approval_generation_id
                || envelope.approved_redacted_content_sha256
                    != authorization.approved_redacted_content_sha256
                || envelope.ocr_provenance_sha256 != authorization.ocr_provenance_sha256
                || envelope.expires_at_unix != authorization.expires_at_unix
                || envelope.expires_at_unix <= now_unix
                || authorization.receipt_id.is_empty()
                || authorization.receipt_id.len() > 128
                || authorization.receipt_id.chars().any(char::is_control)
                || body.get("model").and_then(Value::as_str)
                    != Some(authorization.model_id.as_str())
                || body.get("stream").and_then(Value::as_bool) != Some(envelope.stream)
                || request.expects_stream != envelope.stream
            {
                return Err(transport_authorization_error());
            }
            if consume_approved
                && authorization
                    .transport_consumed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    "approved provider request has already been consumed",
                ));
            }
        }
        TransportAuthorization::WorkspaceAuthorized(authorization) => {
            let now_unix = system_unix_time()?;
            let canonical_sha256 = privacy::sha256_hex(&authorization.canonical_payload);
            let envelope: CanonicalWorkspaceAuthorizedEnvelopeV1 =
                serde_json::from_slice(&authorization.canonical_payload)
                    .map_err(|_| transport_authorization_error())?;
            let rebuilt_canonical =
                serde_json::to_vec(&envelope).map_err(|_| transport_authorization_error())?;
            let canonical_bytes: &[u8] = authorization.canonical_payload.as_ref();
            let body_matches_envelope = body_sha256 == envelope.transport_body_sha256;
            let body: Value =
                serde_json::from_str(&request.body).map_err(|_| transport_authorization_error())?;
            if canonical_sha256 != authorization.canonical_payload_sha256
                || rebuilt_canonical.as_slice() != canonical_bytes
                || !body_matches_envelope
                || envelope.transport_body_sha256 != authorization.body_sha256
                || body_sha256 != authorization.body_sha256
                || endpoint_origin != authorization.endpoint_origin
                || envelope.schema_version != WORKSPACE_AUTHORIZED_SCHEMA_VERSION
                || envelope.destination_kind != EXTERNAL_PROVIDER_DESTINATION
                || envelope.profile_sha256 != authorization.profile_sha256
                || envelope.provider_id != authorization.provider_id
                || envelope.provider_kind != authorization.provider_kind
                || envelope.model_id != authorization.model_id
                || envelope.endpoint_origin != authorization.endpoint_origin
                || envelope.purpose != authorization.purpose
                || envelope.source_binding_sha256 != authorization.source_binding_sha256
                || !valid_lower_sha256(&envelope.profile_sha256)
                || !valid_lower_sha256(&envelope.source_binding_sha256)
                || envelope.expires_at_unix != authorization.expires_at_unix
                || envelope.expires_at_unix <= now_unix
                || !matches!(
                    envelope.purpose.as_str(),
                    WORKSPACE_REDACTION_ASSISTANCE_PURPOSE
                        | WORKSPACE_SELECTED_CONTEXT_CHAT_PURPOSE
                )
                || body.get("model").and_then(Value::as_str)
                    != Some(authorization.model_id.as_str())
                || body.get("stream").and_then(Value::as_bool) != Some(envelope.stream)
                || request.expects_stream != envelope.stream
            {
                return Err(transport_authorization_error());
            }
            if consume_approved
                && authorization
                    .transport_consumed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidRequest,
                    "workspace provider request has already been consumed",
                ));
            }
        }
    }
    Ok(())
}

fn transport_authorization_error() -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::InvalidRequest,
        "provider transport authorization is invalid",
    )
}

fn validate_resolved_addresses(
    addresses: &[SocketAddr],
    allow_private_network: bool,
) -> io::Result<()> {
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "provider DNS lookup returned no addresses",
        ));
    }
    if !allow_private_network && addresses.iter().any(|address| is_private_ip(address.ip())) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            PRIVATE_DNS_REJECTION,
        ));
    }
    Ok(())
}

fn private_network_profile_error() -> ProviderError {
    ProviderError::new(
        ProviderErrorKind::InvalidProfile,
        "private-network provider endpoints require explicit opt-in on a custom profile",
    )
}

fn is_private_provider_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
        .trim_end_matches('.');

    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }

    host.parse::<IpAddr>().is_ok_and(is_private_ip)
}

fn is_private_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_private_ipv4(address),
        IpAddr::V6(address) => is_private_ipv6(address),
    }
}

fn is_private_ipv4(address: Ipv4Addr) -> bool {
    let [first, second, third, _] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || first == 0
        || (first == 100 && (64..=127).contains(&second))
        || (first == 192 && second == 0)
        || (first == 192 && second == 88 && third == 99)
        || (first == 198 && (second == 18 || second == 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113)
        || first >= 224
}

fn is_private_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    // Provider traffic is internet-bound by default. Fail closed for every
    // address outside IPv6 global unicast (2000::/3), including IPv4-mapped,
    // translation, loopback, ULA, link-local, multicast, discard-only, dummy,
    // and future/reserved ranges. A custom profile can still explicitly opt in
    // to private/special routing.
    let outside_global_unicast = (segments[0] & 0xe000) != 0x2000;

    outside_global_unicast
        // IANA's 2001::/23 protocol-assignment block is not globally
        // reachable as a whole. Reject it rather than maintaining a brittle
        // exception list for anycast/experimental sub-prefixes that are not
        // appropriate provider endpoints.
        || (segments[0] == 0x2001 && segments[1] <= 0x01ff)
        // Documentation, transition, and other non-provider special ranges
        // inside otherwise global-unicast space.
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || segments[0] == 0x2002
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChatBodyPath {
    Ordinary,
    ApprovedCase,
    WorkspaceAuthorized,
}

fn build_chat_body(
    profile: &ProviderProfile,
    request: &ChatRequest,
    path: ChatBodyPath,
) -> Result<Value, ProviderError> {
    let authority_matches = match path {
        ChatBodyPath::Ordinary => matches!(
            request.authority,
            ChatRequestAuthority::ConnectionProbe
                | ChatRequestAuthority::LegalPublic
                | ChatRequestAuthority::ProductPublic
                | ChatRequestAuthority::InteractiveUserContent
        ),
        ChatBodyPath::ApprovedCase => request.authority == ChatRequestAuthority::ApprovedCase,
        ChatBodyPath::WorkspaceAuthorized => {
            request.authority == ChatRequestAuthority::WorkspaceAuthorized
        }
    };
    if !authority_matches {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider request authority does not match the selected send path",
        ));
    }
    validate_chat_shape(&request.messages, request.temperature, request.max_tokens)?;
    scan_message_content(&request.messages, request.authority)?;
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

    let model_id = effective_model_id(profile);
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

    if request.stream
        && !matches!(
            profile.kind,
            ProviderKind::SiliconFlow | ProviderKind::Custom
        )
    {
        body.insert(
            "stream_options".to_owned(),
            json!({ "include_usage": true }),
        );
    }

    let normalized_options = profile.kind.options_with_defaults(profile.options.clone());
    apply_provider_options(profile.kind, &normalized_options, &mut body);

    let body = Value::Object(body);
    let serialized = serde_json::to_vec(&body).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider request privacy validation failed",
        )
    })?;
    let residual = privacy::scan_residual(&serialized).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider request privacy validation failed",
        )
    })?;
    if !matches!(
        request.authority,
        ChatRequestAuthority::InteractiveUserContent | ChatRequestAuthority::WorkspaceAuthorized
    ) && !residual.passed
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider request rejected by privacy policy",
        ));
    }
    Ok(body)
}

fn validate_chat_shape(
    messages: &[ChatMessage],
    temperature: Option<f32>,
    max_tokens: Option<u32>,
) -> Result<(), ProviderError> {
    if messages.is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "chat request must include at least one message",
        ));
    }
    if temperature.is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value)) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "temperature must be finite and between 0 and 2",
        ));
    }
    if max_tokens == Some(0) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "max tokens must be greater than zero",
        ));
    }
    Ok(())
}

fn scan_message_content(
    messages: &[ChatMessage],
    authority: ChatRequestAuthority,
) -> Result<(), ProviderError> {
    let serialized = serde_json::to_vec(messages).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider message privacy validation failed",
        )
    })?;
    let residual = privacy::scan_residual(&serialized).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider message privacy validation failed",
        )
    })?;
    if !matches!(
        authority,
        ChatRequestAuthority::InteractiveUserContent | ChatRequestAuthority::WorkspaceAuthorized
    ) && !residual.passed
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "provider message contains residual sensitive content",
        ));
    }
    Ok(())
}

fn effective_model_id(profile: &ProviderProfile) -> &str {
    if profile.kind == ProviderKind::VolcengineArk {
        non_empty(profile.options.endpoint_id.as_deref()).unwrap_or(&profile.model_id)
    } else {
        &profile.model_id
    }
}

fn apply_provider_options(
    kind: ProviderKind,
    options: &ProviderOptions,
    body: &mut Map<String, Value>,
) {
    match kind {
        ProviderKind::DeepSeek => {
            // DeepSeek V4 exposes only two effective levels. Its compatibility
            // aliases `low` and `medium` both behave as `high`, so normalize
            // them at the provider boundary instead of sending a misleading
            // independent strength.
            insert_option(
                body,
                "reasoning_effort",
                options.reasoning_effort.map(|effort| match effort {
                    crate::types::ReasoningEffort::Low | crate::types::ReasoningEffort::Medium => {
                        crate::types::ReasoningEffort::High
                    }
                    supported => supported,
                }),
            );
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
        ProviderKind::Custom => {}
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

/// Parses exactly one complete, non-stream OpenAI-compatible Chat Completions
/// JSON response and returns only user-visible message content.
///
/// Unknown provider fields are ignored. SSE, concatenated JSON values,
/// reasoning-only responses, and non-string `message.content` fail closed.
/// `max_content_bytes` is measured in UTF-8 bytes and must be within the
/// public hard ceiling. The caller must separately require a successful HTTP
/// status before passing the response body to this parser.
pub fn parse_chat_completion(
    body: &str,
    max_content_bytes: usize,
) -> Result<ChatCompletion, ProviderError> {
    if max_content_bytes == 0 || max_content_bytes > MAX_CHAT_COMPLETION_CONTENT_BYTES {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidRequest,
            "chat completion content limit is outside the supported range",
        ));
    }
    if body.len() > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(response_too_large_error(MAX_PROVIDER_RESPONSE_BYTES, None));
    }

    let value = serde_json::from_str::<Value>(body).map_err(|_| {
        ProviderError::new(
            ProviderErrorKind::Parse,
            "provider response was not one complete JSON value",
        )
    })?;
    if value.get("error").is_some() {
        return Err(completion_shape_error(
            "provider JSON response was an error envelope",
        ));
    }
    let parsed = parse_chat_completion_value(&value)?;
    if parsed.content.len() > max_content_bytes {
        return Err(response_too_large_error(max_content_bytes, None));
    }

    Ok(ChatCompletion {
        content: parsed.content.to_owned(),
        model: parsed.model.map(str::to_owned),
        usage: parsed.usage,
    })
}

struct ParsedChatCompletion<'a> {
    content: &'a str,
    model: Option<&'a str>,
    usage: Option<ChatUsage>,
}

fn parse_chat_completion_value(value: &Value) -> Result<ParsedChatCompletion<'_>, ProviderError> {
    let choices = value
        .get("choices")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            completion_shape_error("provider JSON response did not include a choices array")
        })?;
    let choice = choices.first().and_then(Value::as_object).ok_or_else(|| {
        completion_shape_error("provider JSON response did not include choices[0] as an object")
    })?;
    let message = choice
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            completion_shape_error("provider JSON response did not include a message object")
        })?;
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            completion_shape_error("provider JSON response did not include string message content")
        })?;
    if content.trim().is_empty() {
        return Err(completion_shape_error(
            "provider JSON response did not include visible message content",
        ));
    }

    Ok(ParsedChatCompletion {
        content,
        model: value.get("model").and_then(Value::as_str),
        usage: value
            .get("usage")
            .filter(|usage| usage.is_object())
            .map(parse_usage),
    })
}

fn completion_shape_error(message: &'static str) -> ProviderError {
    ProviderError::new(ProviderErrorKind::Parse, message)
}

fn parse_chat_completion_metadata(
    body: &str,
    secret: &ApiSecret,
) -> Result<(Option<String>, Option<ChatUsage>), ProviderError> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        if value.get("error").is_some() {
            return Err(map_http_error(200, body, secret));
        }

        let parsed = parse_chat_completion_value(&value)?;

        let model = parsed
            .model
            .map(|model| redact_known_secret_text(model, secret));

        return Ok((model, parsed.usage));
    }

    parse_streaming_completion_metadata(body, secret)
}

fn parse_streaming_completion_metadata(
    body: &str,
    secret: &ApiSecret,
) -> Result<(Option<String>, Option<ChatUsage>), ProviderError> {
    let mut parser = StreamParser::new();
    let mut model = None;
    let mut usage = None;
    let mut has_content = false;

    let mut events = parser.push(body.as_bytes());
    events.extend(parser.finish());
    let has_reasoning_content = parser.saw_reasoning_content();
    for event in events {
        match event? {
            StreamEvent::Delta {
                content,
                model: event_model,
            } => {
                has_content |= !content.is_empty();
                if let Some(event_model) = event_model {
                    model = Some(redact_known_secret_text(&event_model, secret));
                }
            }
            StreamEvent::Usage(event_usage) => usage = Some(event_usage),
            StreamEvent::Error {
                error_type,
                message,
            } => {
                return Err(ProviderError::new(
                    ProviderErrorKind::Http,
                    redact_known_secret_text(&format!("{error_type}: {message}"), secret),
                ));
            }
            StreamEvent::Done => {}
        }
    }

    if !has_content && !has_reasoning_content {
        return Err(ProviderError::new(
            ProviderErrorKind::Parse,
            "provider stream did not include a content or reasoning token",
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

fn map_http_error(status: u16, body: &str, secret: &ApiSecret) -> ProviderError {
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

    let message = redact_known_secret_text(&message, secret);
    ProviderError::with_status(
        ProviderErrorKind::Http,
        status,
        truncate_for_log(&message, 240),
    )
}

fn map_reqwest_error(error: reqwest::Error) -> ProviderError {
    if error_chain_contains(&error, PRIVATE_DNS_REJECTION) {
        return private_network_profile_error();
    }
    ProviderError::new(
        if error.is_timeout() {
            ProviderErrorKind::Timeout
        } else {
            ProviderErrorKind::Network
        },
        error.to_string(),
    )
}

fn error_chain_contains(error: &(dyn StdError + 'static), needle: &str) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.to_string().contains(needle) {
            return true;
        }
        current = error.source();
    }
    false
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
        Some(status) => {
            ProviderError::with_status(ProviderErrorKind::ResponseTooLarge, status, message)
        }
        None => ProviderError::new(ProviderErrorKind::ResponseTooLarge, message),
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

fn stream_chunk_has_activity(parser: &mut StreamParser, chunk: &[u8]) -> bool {
    let already_saw_reasoning = parser.saw_reasoning_content();
    let has_visible_content = stream_events_have_content(parser.push(chunk));
    has_visible_content || (!already_saw_reasoning && parser.saw_reasoning_content())
}

fn stream_finish_has_activity(parser: &mut StreamParser) -> bool {
    let already_saw_reasoning = parser.saw_reasoning_content();
    let has_visible_content = stream_events_have_content(parser.finish());
    has_visible_content || (!already_saw_reasoning && parser.saw_reasoning_content())
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
    error.message = redact_known_secret_text(&error.message, secret);
    error
}

fn redact_known_secret_text(message: &str, secret: &ApiSecret) -> String {
    if secret.expose_secret().is_empty() {
        message.to_owned()
    } else {
        message.replace(secret.expose_secret(), "<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        ChatMessage, ChatMessageRole, ProviderCapabilities, ProviderOptions, ReasoningEffort,
    };
    use std::{
        io::{Read, Write},
        net::{Shutdown, TcpListener, TcpStream},
        sync::{mpsc, Arc, Mutex},
        thread,
    };

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
        ChatRequest::product_public(
            vec![ChatMessage {
                role: ChatMessageRole::User,
                content: "ping".to_owned(),
            }],
            true,
            Some(0.2),
            Some(16),
        )
    }

    fn test_transport_request(
        url: String,
        mut headers: Vec<TransportHeader>,
        body: impl Into<String>,
        expects_stream: bool,
        allow_private_network: bool,
    ) -> TransportRequest {
        if headers
            .iter()
            .all(|header| !header.name.eq_ignore_ascii_case("Authorization"))
        {
            headers.push(TransportHeader::new(
                "Authorization",
                "Bearer not-a-real-synthetic-transport-test-key",
            ));
        }
        if headers
            .iter()
            .all(|header| !header.name.eq_ignore_ascii_case("Content-Type"))
        {
            headers.push(TransportHeader::new("Content-Type", "application/json"));
        }
        let endpoint_origin = reqwest::Url::parse(&url)
            .expect("synthetic transport URL parses")
            .origin()
            .ascii_serialization();
        let body = body.into();
        let body_sha256 = privacy::sha256_hex(body.as_bytes());
        TransportRequest {
            method: "POST".to_owned(),
            url,
            headers,
            body,
            expects_stream,
            allow_private_network,
            authorization: TransportAuthorization::Public {
                body_sha256,
                endpoint_origin,
                authority: ChatRequestAuthority::ProductPublic,
            },
        }
    }

    fn approved_test_profile(base_url: impl Into<String>) -> ProviderProfile {
        let mut value = profile(ProviderKind::Custom);
        value.id = "local-approved-provider".to_owned();
        value.display_name = "Local approved provider".to_owned();
        value.model_id = "approved-chat-model".to_owned();
        value.base_url = base_url.into();
        value.options.allow_private_network = Some(true);
        value
    }

    fn workspace_test_request(
        provider_profile: &ProviderProfile,
        stream: bool,
    ) -> WorkspaceAuthorizedRequest {
        authorize_workspace_request(
            provider_profile,
            vec![ChatMessage {
                role: ChatMessageRole::User,
                content: "Original material: client phone 13800138000. RAW_WORKSPACE_CANARY."
                    .to_owned(),
            }],
            stream,
            WORKSPACE_REDACTION_ASSISTANCE_PURPOSE,
            &privacy::sha256_hex(b"workspace-material-v1"),
            system_unix_time().expect("system time") + 300,
        )
        .expect("trusted workspace authorization builds")
    }

    fn approved_test_binding(expires_at_unix: u64) -> ApprovedChatBinding {
        ApprovedChatBinding {
            purpose: "assistant_chat".to_owned(),
            policy_id: "cn-legal-default".to_owned(),
            policy_version: 1,
            detector_version: privacy::REDACTION_VERSION.to_owned(),
            approval_generation_id: "approved-generation-1".to_owned(),
            approved_redacted_content_sha256: privacy::sha256_hex(
                b"approved-redacted-case-generation",
            ),
            ocr_provenance_sha256: privacy::sha256_hex(b"local-ocr-provenance"),
            expires_at_unix,
        }
    }

    fn approved_test_draft(
        provider_profile: &ProviderProfile,
        expires_at_unix: u64,
    ) -> (ApprovedChatDraft, privacy::ReceiptSigner) {
        let draft = prepare_approved_chat(
            provider_profile,
            vec![
                ChatMessage {
                    role: ChatMessageRole::System,
                    content: "Only use the approved redacted case context.".to_owned(),
                },
                ChatMessage {
                    role: ChatMessageRole::User,
                    content: "Approved redacted case: [PARTY_1] requests a procedural summary."
                        .to_owned(),
                },
            ],
            false,
            Some(0.0),
            Some(64),
            approved_test_binding(expires_at_unix),
        )
        .expect("synthetic approved draft is valid");
        let signer = privacy::ReceiptSigner::new([0x5a_u8; 32]).expect("receipt signer");
        (draft, signer)
    }

    fn approved_test_receipt(
        draft: &ApprovedChatDraft,
        signer: &privacy::ReceiptSigner,
        purpose: &str,
    ) -> privacy::SignedRedactionReceipt {
        signer
            .issue(privacy::RedactionReceiptClaims {
                receipt_id: String::new(),
                source_sha256: vec![privacy::sha256_hex(b"synthetic-source")],
                extraction_sha256: draft.binding.ocr_provenance_sha256.clone(),
                redacted_content_sha256: draft.binding.approved_redacted_content_sha256.clone(),
                approved_payload_sha256: draft.canonical_payload_sha256.clone(),
                policy_id: draft.binding.policy_id.clone(),
                policy_version: draft.binding.policy_version,
                detector_version: draft.binding.detector_version.clone(),
                destination: privacy::DestinationScope {
                    kind: privacy::DestinationKind::ExternalProvider,
                    identifier: draft.provider_id.clone(),
                },
                purpose: purpose.to_owned(),
                unresolved_high_risk_count: 0,
                review_state: privacy::ReviewState::Approved,
                issued_at_unix: system_unix_time().expect("system time"),
                expires_at_unix: Some(draft.binding.expires_at_unix),
                key_version: 1,
            })
            .expect("synthetic receipt is valid")
    }

    fn approved_test_request(provider_profile: &ProviderProfile) -> ApprovedChatRequest {
        let expires_at_unix = system_unix_time().expect("system time") + 300;
        let (draft, signer) = approved_test_draft(provider_profile, expires_at_unix);
        let receipt = approved_test_receipt(&draft, &signer, &draft.binding.purpose);
        authorize_approved_chat(draft, signer, &receipt)
            .expect("synthetic approved request is authorized")
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
        assert!(!request.allow_private_network);
        assert!(!format!("{request:?}").contains("contract-secret-1234"));
        assert!(!format!("{request:?}").contains("ping"));
    }

    #[test]
    fn every_provider_rejects_case_and_secret_classifications_before_serialization() {
        let request = ChatRequest {
            messages: vec![
                ChatMessage {
                    role: ChatMessageRole::System,
                    content: "仅处理用户提供的案件材料。".to_owned(),
                },
                ChatMessage {
                    role: ChatMessageRole::User,
                    content: "原告：张三，身份证号11010519491231002X，手机号13800138000，邮箱zhang.san@example.com，银行卡4532015112830366。张三请求判令被告还款。".to_owned(),
                },
                ChatMessage {
                    role: ChatMessageRole::User,
                    content: r#"{"当事人":"李四","案号":"（2024）京0105民初1234号","护照号":"E12345678","车牌号":"京A12345"}"#.to_owned(),
                },
            ],
            stream: false,
            temperature: Some(0.0),
            max_tokens: None,
            authority: ChatRequestAuthority::ApprovedCase,
        };
        for authority in [ChatRequestAuthority::ApprovedCase] {
            let mut classified_request = request.clone();
            classified_request.authority = authority;
            for kind in [
                ProviderKind::DeepSeek,
                ProviderKind::Qwen,
                ProviderKind::SiliconFlow,
                ProviderKind::VolcengineArk,
                ProviderKind::Custom,
            ] {
                let mut profile = profile(kind);
                if kind == ProviderKind::Custom {
                    profile.base_url = "https://provider.example/v1".to_owned();
                    profile.model_id = "custom-model".to_owned();
                }
                let error = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
                    &profile,
                    &ApiSecret::new("contract-secret-1234"),
                    &classified_request,
                )
                .expect_err("non-public classifications must fail before transport serialization");
                assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
                assert!(error.to_string().contains("opaque approved request"));
                assert!(!error.to_string().contains("case material"));
            }
        }
    }
    #[test]
    fn every_provider_blocks_non_public_send_paths_before_transport_without_canary_leakage() {
        const CANARIES: [&str; 7] = [
            "PII_NAME_ZHANG_SAN_7F9C",
            "PII_ID_11010519491231002X",
            "PII_PHONE_13800138000",
            "PII_EMAIL_zhang.san@example.com",
            "PII_BANK_4532015112830366",
            "PII_CASE_2024-JING-0105-1234",
            "PROVIDER_SECRET_CANARY_A91E",
        ];

        let request = ChatRequest {
            messages: vec![
                ChatMessage {
                    role: ChatMessageRole::System,
                    content: format!("Handle case material containing {}", CANARIES[0]),
                },
                ChatMessage {
                    role: ChatMessageRole::User,
                    content: CANARIES[1..6].join(" | "),
                },
            ],
            stream: false,
            temperature: Some(0.0),
            max_tokens: None,
            authority: ChatRequestAuthority::ApprovedCase,
        };
        let secret = ApiSecret::new(CANARIES[6]);

        for authority in [ChatRequestAuthority::ApprovedCase] {
            let mut classified_request = request.clone();
            classified_request.authority = authority;

            for kind in [
                ProviderKind::DeepSeek,
                ProviderKind::Qwen,
                ProviderKind::SiliconFlow,
                ProviderKind::VolcengineArk,
                ProviderKind::Custom,
            ] {
                let mut provider_profile = profile(kind);
                if kind == ProviderKind::Custom {
                    provider_profile.base_url = "https://provider.example/v1".to_owned();
                    provider_profile.model_id = "custom-model".to_owned();
                }

                for send_with_cancellation in [false, true] {
                    let transport = MockTransport::new(TransportResponse {
                        status: 200,
                        body: "transport must not run".to_owned(),
                        first_content_token_latency_ms: None,
                        total_latency_ms: 0,
                    });
                    let adapter = OpenAiCompatibleAdapter::new(transport.clone());
                    let cancellation = RequestCancellation::default();

                    let result = if send_with_cancellation {
                        adapter.send_chat_with_cancellation(
                            &provider_profile,
                            &secret,
                            &classified_request,
                            &cancellation,
                        )
                    } else {
                        adapter.send_chat(&provider_profile, &secret, &classified_request)
                    };
                    let error = result.expect_err(
                        "non-public classifications must fail before transport serialization",
                    );

                    assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
                    assert!(error.to_string().contains("opaque approved request"));
                    assert!(
                        transport.requests.lock().expect("requests lock").is_empty(),
                        "transport ran for {kind:?}, {authority:?}, cancellation={send_with_cancellation}",
                    );
                    let display = error.to_string();
                    let debug = format!("{error:?}");
                    for canary in CANARIES {
                        assert!(
                            !display.contains(canary),
                            "Display leaked canary for {kind:?}, {authority:?}, cancellation={send_with_cancellation}",
                        );
                        assert!(
                            !debug.contains(canary),
                            "Debug leaked canary for {kind:?}, {authority:?}, cancellation={send_with_cancellation}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn caller_cannot_self_classify_raw_case_content_as_public() {
        const RAW_MARKER: &str = "RAW_CASE_CANARY_NEVER_TRANSPORT";
        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: "transport must not run".to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 0,
        });
        let adapter = OpenAiCompatibleAdapter::new(transport.clone());
        let request = ChatRequest::product_public(
            vec![ChatMessage {
                role: ChatMessageRole::User,
                content: format!(
                    "Synthetic case material. Client mobile: 13800138000. Marker: {RAW_MARKER}"
                ),
            }],
            false,
            Some(0.0),
            Some(32),
        );

        let error = adapter
            .send_chat(
                &profile(ProviderKind::DeepSeek),
                &ApiSecret::new("synthetic-secret"),
                &request,
            )
            .expect_err("a caller-provided public label cannot bypass residual scanning");

        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
        assert!(error.to_string().contains("residual sensitive content"));
        assert!(transport.requests.lock().expect("requests lock").is_empty());
        assert!(!error.to_string().contains(RAW_MARKER));
        assert!(!format!("{error:?}").contains("13800138000"));
    }

    #[test]
    fn interactive_user_content_with_pii_reaches_direct_provider_but_public_content_does_not() {
        let messages = vec![ChatMessage {
            role: ChatMessageRole::User,
            content: "Please call me at 13800138000 about my question.".to_owned(),
        }];
        let interactive =
            ChatRequest::interactive_user_content(messages.clone(), false, Some(0.0), Some(32));
        assert_eq!(
            interactive.data_classification(),
            privacy::DataClassification::InteractiveUserProvided
        );
        let provider_profile = profile(ProviderKind::DeepSeek);
        let secret = ApiSecret::new("synthetic-secret");
        let built = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &provider_profile,
            &secret,
            &interactive,
        )
        .expect("interactive user content builds");
        validate_transport_authorization(&built, false)
            .expect("interactive authority survives the transport boundary");
        let serialized_messages = serde_json::to_vec(&messages).expect("messages serialize");
        assert!(
            !privacy::scan_residual(&serialized_messages)
                .expect("detector runs")
                .passed,
            "the fixture must exercise the interactive residual exception"
        );

        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: r#"{"choices":[{"message":{"content":"ok"}}]}"#.to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 1,
        });
        let adapter = OpenAiCompatibleAdapter::new(transport.clone());
        adapter
            .send_chat(&provider_profile, &secret, &interactive)
            .expect("interactive user content reaches the direct provider transport");
        assert_eq!(transport.requests.lock().expect("requests lock").len(), 1);

        let public = ChatRequest::product_public(messages, false, Some(0.0), Some(32));
        let error = adapter
            .send_chat(&provider_profile, &secret, &public)
            .expect_err("public authority must retain residual rejection");
        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
        assert!(error.to_string().contains("residual sensitive content"));
        assert_eq!(
            transport.requests.lock().expect("requests lock").len(),
            1,
            "rejected public content must not reach transport"
        );
    }

    #[test]
    fn raw_workspace_content_requires_the_opaque_workspace_authorization_and_is_one_shot() {
        const RAW_MARKER: &str = "RAW_WORKSPACE_CANARY";
        let provider_profile = approved_test_profile("https://provider.example/v1");
        let secret = ApiSecret::new("synthetic-secret");
        let raw_messages = vec![ChatMessage {
            role: ChatMessageRole::User,
            content: "Original material: client phone 13800138000. RAW_WORKSPACE_CANARY."
                .to_owned(),
        }];
        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: r#"{"choices":[{"message":{"content":"ok"}}]}"#.to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 1,
        });
        let adapter = OpenAiCompatibleAdapter::new(transport.clone());

        let public = ChatRequest::product_public(raw_messages, false, None, None);
        let error = adapter
            .send_chat(&provider_profile, &secret, &public)
            .expect_err("ordinary public chat must never send original workspace material");
        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
        assert!(transport.requests.lock().expect("requests lock").is_empty());

        let workspace = workspace_test_request(&provider_profile, false);
        let debug = format!("{workspace:?}");
        assert!(!debug.contains(RAW_MARKER));
        assert!(!debug.contains("13800138000"));
        assert_eq!(workspace.purpose(), WORKSPACE_REDACTION_ASSISTANCE_PURPOSE);

        adapter
            .send_workspace_chat(&provider_profile, &secret, &workspace)
            .expect("opaque workspace authorization may send raw redaction input");
        let replay = adapter
            .send_workspace_chat(&provider_profile, &secret, &workspace)
            .expect_err("workspace authorization is one-shot");
        assert_eq!(replay.kind, ProviderErrorKind::InvalidRequest);
        assert!(replay.to_string().contains("already been consumed"));

        let requests = transport.requests.lock().expect("requests lock");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].body().contains(RAW_MARKER));
        assert!(!format!("{:?}", requests[0]).contains(RAW_MARKER));
        assert!(!format!("{:?}", requests[0]).contains("13800138000"));
    }

    #[test]
    fn workspace_authorization_rejects_invalid_purpose_expiry_and_complete_profile_drift() {
        let provider_profile = approved_test_profile("https://provider.example/v1");
        let source_binding_sha256 = privacy::sha256_hex(b"workspace-material-v1");
        let messages = vec![ChatMessage {
            role: ChatMessageRole::User,
            content: "Original material: phone 13800138000.".to_owned(),
        }];
        let now = system_unix_time().expect("system time");

        let purpose_error = authorize_workspace_request(
            &provider_profile,
            messages.clone(),
            false,
            "assistant_chat",
            &source_binding_sha256,
            now + 300,
        )
        .expect_err("only the explicit workspace purposes are allowed");
        assert_eq!(purpose_error.kind, ProviderErrorKind::InvalidRequest);

        let expiry_error = authorize_workspace_request(
            &provider_profile,
            messages,
            false,
            WORKSPACE_REDACTION_ASSISTANCE_PURPOSE,
            &source_binding_sha256,
            now.saturating_sub(1),
        )
        .expect_err("expired workspace authority is rejected at construction");
        assert_eq!(expiry_error.kind, ProviderErrorKind::InvalidRequest);

        let workspace = workspace_test_request(&provider_profile, false);
        let mut drifted = provider_profile.clone();
        drifted.display_name = "edited display name also changes full profile binding".to_owned();
        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: "transport must not run".to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 0,
        });
        let error = OpenAiCompatibleAdapter::new(transport.clone())
            .send_workspace_chat(&drifted, &ApiSecret::new("synthetic-secret"), &workspace)
            .expect_err("any provider profile drift invalidates the workspace authorization");
        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
        assert!(transport.requests.lock().expect("requests lock").is_empty());
        assert!(!error.to_string().contains("13800138000"));
    }

    #[test]
    fn workspace_transport_rejects_tampering_and_expiry_before_loopback_io() {
        let fixture = spawn_approved_json_fixture();
        let provider_profile = approved_test_profile(fixture.base_url.clone());
        let secret = ApiSecret::new("synthetic-loopback-secret");
        let workspace = workspace_test_request(&provider_profile, false);
        let mut tampered =
            OpenAiCompatibleAdapter::<ReqwestTransport>::build_workspace_transport_request(
                &provider_profile,
                &secret,
                &workspace,
            )
            .expect("workspace transport request builds");
        tampered.body.push(' ');

        let transport =
            ReqwestTransport::new_with_timeouts(Duration::from_secs(1), Duration::from_secs(1))
                .expect("transport builds");
        let tamper_error = transport
            .send(tampered)
            .expect_err("tampered workspace body is rejected before network I/O");
        assert_eq!(tamper_error.kind, ProviderErrorKind::InvalidRequest);

        let workspace = workspace_test_request(&provider_profile, false);
        let mut expired =
            OpenAiCompatibleAdapter::<ReqwestTransport>::build_workspace_transport_request(
                &provider_profile,
                &secret,
                &workspace,
            )
            .expect("workspace transport request builds");
        let expired_at = system_unix_time().expect("system time").saturating_sub(1);
        let authorization = match &mut expired.authorization {
            TransportAuthorization::WorkspaceAuthorized(value) => value,
            _ => panic!("workspace authorization expected"),
        };
        let mut envelope: CanonicalWorkspaceAuthorizedEnvelopeV1 =
            serde_json::from_slice(&authorization.canonical_payload)
                .expect("workspace canonical envelope parses");
        envelope.expires_at_unix = expired_at;
        let canonical_payload =
            serde_json::to_vec(&envelope).expect("workspace canonical envelope serializes");
        authorization.canonical_payload_sha256 = privacy::sha256_hex(&canonical_payload);
        authorization.canonical_payload = Arc::<[u8]>::from(canonical_payload);
        authorization.expires_at_unix = expired_at;
        let expiry_error = transport
            .send(expired)
            .expect_err("expired workspace authorization is rejected before network I/O");
        assert_eq!(expiry_error.kind, ProviderErrorKind::InvalidRequest);
        assert!(fixture.finish().is_empty());
    }

    #[test]
    fn streaming_workspace_chat_reads_a_non_streaming_provider_body() {
        let fixture = spawn_approved_json_fixture();
        let provider_profile = approved_test_profile(fixture.base_url.clone());
        let workspace = workspace_test_request(&provider_profile, false);
        let transport = ReqwestStreamingTransport::new_with_timeouts(
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("streaming transport builds");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");

        let (status, body) = runtime.block_on(async {
            let mut response = transport
                .send_workspace_chat(
                    &provider_profile,
                    &ApiSecret::new("synthetic-loopback-secret"),
                    &workspace,
                )
                .await
                .expect("non-stream workspace request reaches the provider");
            let status = response.status();
            let mut body = Vec::new();
            while let Some(chunk) = response.next_chunk().await.expect("response chunk reads") {
                body.extend_from_slice(&chunk);
            }
            (status, body)
        });

        assert_eq!(status, 200);
        assert!(String::from_utf8_lossy(&body).contains("\"content\":\"ok\""));
        assert_eq!(fixture.finish().len(), 1);
    }

    #[test]
    fn approved_receipt_purpose_mismatch_never_reaches_transport() {
        let provider_profile = approved_test_profile("https://provider.example/v1");
        let expires_at_unix = system_unix_time().expect("system time") + 300;
        let (draft, signer) = approved_test_draft(&provider_profile, expires_at_unix);
        let receipt = approved_test_receipt(&draft, &signer, "different_purpose");
        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: "transport must not run".to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 0,
        });

        let error = authorize_approved_chat(draft, signer, &receipt)
            .expect_err("receipt purpose must exactly match the canonical request");

        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
        assert!(error.to_string().contains("receipt binding mismatch"));
        assert!(transport.requests.lock().expect("requests lock").is_empty());
    }

    #[test]
    fn approved_request_rejects_model_and_endpoint_drift_before_transport() {
        let provider_profile = approved_test_profile("https://provider.example/v1");
        let approved = approved_test_request(&provider_profile);
        let transport = MockTransport::new(TransportResponse {
            status: 200,
            body: "transport must not run".to_owned(),
            first_content_token_latency_ms: None,
            total_latency_ms: 0,
        });
        let adapter = OpenAiCompatibleAdapter::new(transport.clone());

        let mut wrong_model = provider_profile.clone();
        wrong_model.model_id = "different-approved-model".to_owned();
        let model_error = adapter
            .send_approved_chat(&wrong_model, &ApiSecret::new("synthetic-secret"), &approved)
            .expect_err("model drift invalidates approval");
        assert_eq!(model_error.kind, ProviderErrorKind::InvalidRequest);

        let mut wrong_endpoint = provider_profile;
        wrong_endpoint.base_url = "https://different.example/v1".to_owned();
        let endpoint_error = adapter
            .send_approved_chat(
                &wrong_endpoint,
                &ApiSecret::new("synthetic-secret"),
                &approved,
            )
            .expect_err("endpoint-origin drift invalidates approval");
        assert_eq!(endpoint_error.kind, ProviderErrorKind::InvalidRequest);
        assert!(transport.requests.lock().expect("requests lock").is_empty());
    }

    #[test]
    fn approved_chat_reaches_loopback_once_and_cannot_be_replayed() {
        const RAW_MARKER: &str = "RAW_CASE_CANARY_NEVER_SEND";
        let fixture = spawn_approved_json_fixture();
        let provider_profile = approved_test_profile(fixture.base_url.clone());
        let approved = approved_test_request(&provider_profile);
        thread::sleep(Duration::from_millis(750));
        let transport =
            ReqwestTransport::new_with_timeouts(Duration::from_secs(5), Duration::from_secs(5))
                .expect("transport builds");
        let adapter = OpenAiCompatibleAdapter::new(transport);

        let response = adapter
            .send_approved_chat(
                &provider_profile,
                &ApiSecret::new("synthetic-loopback-secret"),
                &approved,
            )
            .expect("valid approved chat reaches the local fixture");
        assert_eq!(response.status, 200);

        let replay = adapter
            .send_approved_chat(
                &provider_profile,
                &ApiSecret::new("synthetic-loopback-secret"),
                &approved,
            )
            .expect_err("approved chat authorization is one-shot");
        assert_eq!(replay.kind, ProviderErrorKind::InvalidRequest);
        assert!(replay.to_string().contains("already been consumed"));

        let requests = fixture.finish();
        assert_eq!(requests.len(), 1, "exactly one HTTP request is permitted");
        let wire = String::from_utf8_lossy(&requests[0]);
        let header_end = requests[0]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4);
        let body_bytes = header_end
            .map(|index| requests[0].len().saturating_sub(index))
            .unwrap_or_default();
        assert!(
            wire.contains("Approved redacted case: [PARTY_1] requests a procedural summary."),
            "approved request body is incomplete: total_bytes={}, body_bytes={}, complete={}",
            requests[0].len(),
            body_bytes,
            request_is_complete(&requests[0])
        );
        assert!(wire.contains("\"model\":\"approved-chat-model\""));
        assert!(!wire.contains(RAW_MARKER));
        assert!(!wire.contains("13800138000"));
    }

    #[test]
    fn tampered_approved_body_is_rejected_with_zero_loopback_requests() {
        let fixture = spawn_approved_json_fixture();
        let provider_profile = approved_test_profile(fixture.base_url.clone());
        let approved = approved_test_request(&provider_profile);
        let secret = ApiSecret::new("synthetic-loopback-secret");
        let mut request =
            OpenAiCompatibleAdapter::<ReqwestTransport>::build_approved_transport_request(
                &provider_profile,
                &secret,
                &approved,
            )
            .expect("approved transport request builds");
        request.body.push(' ');
        if let TransportAuthorization::Approved(authorization) = &mut request.authorization {
            authorization.body_sha256 = privacy::sha256_hex(request.body.as_bytes());
        }
        let transport =
            ReqwestTransport::new_with_timeouts(Duration::from_secs(1), Duration::from_secs(1))
                .expect("transport builds");

        let error = transport
            .send(request)
            .expect_err("body tampering is rejected before network I/O");

        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
        assert!(fixture.finish().is_empty());
    }

    #[test]
    fn expired_approved_authorization_is_rejected_with_zero_loopback_requests() {
        let fixture = spawn_approved_json_fixture();
        let provider_profile = approved_test_profile(fixture.base_url.clone());
        let approved = approved_test_request(&provider_profile);
        let secret = ApiSecret::new("synthetic-loopback-secret");
        let mut request =
            OpenAiCompatibleAdapter::<ReqwestTransport>::build_approved_transport_request(
                &provider_profile,
                &secret,
                &approved,
            )
            .expect("approved transport request builds");
        let expired_at = system_unix_time().expect("system time").saturating_sub(1);
        let authorization = match &mut request.authorization {
            TransportAuthorization::Approved(value) => value,
            TransportAuthorization::Public { .. } => panic!("approved authorization expected"),
            TransportAuthorization::WorkspaceAuthorized(_) => {
                panic!("approved authorization expected")
            }
        };
        let mut envelope: CanonicalApprovedChatEnvelopeV1 =
            serde_json::from_slice(&authorization.canonical_payload)
                .expect("canonical envelope parses");
        envelope.expires_at_unix = expired_at;
        let canonical_payload =
            serde_json::to_vec(&envelope).expect("canonical envelope serializes");
        authorization.canonical_payload_sha256 = privacy::sha256_hex(&canonical_payload);
        authorization.canonical_payload = Arc::<[u8]>::from(canonical_payload);
        authorization.expires_at_unix = expired_at;
        let transport =
            ReqwestTransport::new_with_timeouts(Duration::from_secs(1), Duration::from_secs(1))
                .expect("transport builds");

        let error = transport
            .send(request)
            .expect_err("expired authorization is rejected before network I/O");

        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
        assert!(fixture.finish().is_empty());
    }

    #[test]
    fn deepseek_legacy_unspecified_thinking_is_explicitly_disabled() {
        let request = build(ProviderKind::DeepSeek, ProviderOptions::default());
        let body: Value = serde_json::from_str(&request.body).expect("body is JSON");

        assert_eq!(body["thinking"]["type"], "disabled");
    }

    #[test]
    fn deepseek_normalizes_compatibility_reasoning_aliases_to_high() {
        for alias in [ReasoningEffort::Low, ReasoningEffort::Medium] {
            let request = build(
                ProviderKind::DeepSeek,
                ProviderOptions {
                    reasoning_effort: Some(alias),
                    thinking: Some(true),
                    ..ProviderOptions::default()
                },
            );
            let body: Value = serde_json::from_str(&request.body).expect("body is JSON");

            assert_eq!(body["reasoning_effort"], "high");
        }
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
    fn custom_contract_sends_only_openai_compatible_core_fields() {
        let mut profile = profile(ProviderKind::Custom);
        profile.display_name = "Private Gateway".to_owned();
        profile.model_id = "private-chat-model".to_owned();
        profile.base_url = "https://models.example.com/openai/v1".to_owned();
        profile.options = ProviderOptions {
            thinking: Some(true),
            enable_thinking: Some(true),
            reasoning_effort: Some(ReasoningEffort::High),
            endpoint_id: Some("vendor-endpoint".to_owned()),
            workspace_id: Some("vendor-workspace".to_owned()),
            ..ProviderOptions::default()
        };

        let request = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &profile,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect("custom OpenAI-compatible request builds");
        let body: Value = serde_json::from_str(&request.body).expect("body is JSON");

        assert_eq!(
            request.url,
            "https://models.example.com/openai/v1/chat/completions"
        );
        assert_eq!(body["model"], "private-chat-model");
        assert_eq!(body["stream"], true);
        assert_eq!(body["temperature"].as_f64(), Some(f64::from(0.2_f32)));
        assert_eq!(body["max_tokens"], 16);
        for provider_specific in [
            "stream_options",
            "thinking",
            "enable_thinking",
            "thinking_budget",
            "reasoning_effort",
            "endpoint_id",
            "workspace_id",
        ] {
            assert!(
                body.get(provider_specific).is_none(),
                "custom request leaked provider-specific field {provider_specific}"
            );
        }
    }

    #[test]
    fn custom_contract_accepts_a_full_chat_completions_url_without_duplication() {
        let mut profile = profile(ProviderKind::Custom);
        profile.model_id = "private-chat-model".to_owned();
        profile.base_url = "https://models.example.com/openai/v1/chat/completions".to_owned();

        let request = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &profile,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect("full custom endpoint builds");

        assert_eq!(
            request.url,
            "https://models.example.com/openai/v1/chat/completions"
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
    fn custom_private_endpoint_requires_and_honors_explicit_opt_in() {
        for endpoint in [
            "https://localhost:3000/v1",
            "https://localhost.:3000/v1",
            "https://127.0.0.1:3000/v1",
            "https://192.168.10.20/v1",
            "https://[::1]:3000/v1",
            "https://[fd00::20]/v1",
            "https://[fe80::20]/v1",
            "https://[ff02::1]/v1",
        ] {
            let mut profile = profile(ProviderKind::Custom);
            profile.base_url = endpoint.to_owned();

            let error = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
                &profile,
                &ApiSecret::new("contract-secret-1234"),
                &request_for_contract(),
            )
            .expect_err("private endpoint is denied by default");
            assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);

            profile.options.allow_private_network = Some(true);
            let request = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
                &profile,
                &ApiSecret::new("contract-secret-1234"),
                &request_for_contract(),
            )
            .expect("explicitly opted-in custom private endpoint builds");
            assert!(request.url.ends_with("/chat/completions"));
            assert!(request.allow_private_network);
        }
    }

    #[test]
    fn plain_http_requires_explicit_custom_literal_loopback_target() {
        for endpoint in ["http://127.0.0.1:3000/v1", "http://[::1]:3000/v1"] {
            let mut profile = profile(ProviderKind::Custom);
            profile.base_url = endpoint.to_owned();
            profile.options.allow_private_network = Some(true);

            let request = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
                &profile,
                &ApiSecret::new("contract-secret-1234"),
                &request_for_contract(),
            )
            .expect("explicit custom literal-loopback HTTP endpoint builds");
            assert!(request.url.starts_with(endpoint));
        }

        for endpoint in [
            "http://localhost:3000/v1",
            "http://localhost.:3000/v1",
            "http://127.0.0.2:3000/v1",
            "http://192.168.10.20:3000/v1",
            "http://provider.example/v1",
        ] {
            let mut profile = profile(ProviderKind::Custom);
            profile.base_url = endpoint.to_owned();
            profile.options.allow_private_network = Some(true);

            let error = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
                &profile,
                &ApiSecret::new("contract-secret-1234"),
                &request_for_contract(),
            )
            .expect_err("plain HTTP outside literal loopback is rejected");
            assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
        }

        let mut built_in = profile(ProviderKind::DeepSeek);
        built_in.base_url = "http://127.0.0.1:3000/v1".to_owned();
        built_in.options.allow_private_network = Some(true);
        let error = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &built_in,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect_err("built-in provider cannot use loopback HTTP");
        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
    }

    #[test]
    fn built_in_profile_cannot_opt_in_to_a_private_endpoint() {
        let mut profile = profile(ProviderKind::DeepSeek);
        profile.base_url = "https://10.0.0.20/v1".to_owned();
        profile.options.allow_private_network = Some(true);

        let error = OpenAiCompatibleAdapter::<MockTransport>::build_transport_request(
            &profile,
            &ApiSecret::new("contract-secret-1234"),
            &request_for_contract(),
        )
        .expect_err("built-in profiles cannot opt in to private targets");

        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
    }

    #[test]
    fn resolved_address_policy_rejects_any_private_or_special_answer() {
        let public = SocketAddr::from(([93, 184, 216, 34], 0));
        for forbidden in [
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([10, 0, 0, 1], 0)),
            SocketAddr::from(([169, 254, 1, 1], 0)),
            SocketAddr::from(([192, 0, 2, 1], 0)),
            SocketAddr::from(([198, 51, 100, 1], 0)),
            SocketAddr::from(([203, 0, 113, 1], 0)),
            SocketAddr::new("::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("fd00::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("fe80::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("2001:db8::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("64:ff9b::c0a8:1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("100:0:0:1::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("2001:2::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("3fff::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("5f00::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("4000::1".parse().expect("IPv6 parses"), 0),
            SocketAddr::new("::ffff:8.8.8.8".parse().expect("IPv6 parses"), 0),
        ] {
            let error = validate_resolved_addresses(&[public, forbidden], false)
                .expect_err("one forbidden DNS answer rejects the complete resolution");
            assert!(error.to_string().contains(PRIVATE_DNS_REJECTION));
            validate_resolved_addresses(&[forbidden], true)
                .expect("explicit custom opt-in accepts private resolution");
        }

        for public_ipv6 in ["2400:3200::1", "2606:4700:4700::1111"] {
            let public_ipv6 = SocketAddr::new(public_ipv6.parse().expect("IPv6 parses"), 0);
            validate_resolved_addresses(&[public_ipv6], false)
                .expect("ordinary global-unicast IPv6 remains available");
        }
    }

    #[test]
    fn safe_dns_resolver_rejects_loopback_after_name_resolution() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        let name = "localhost".parse().expect("DNS name parses");
        let safe = ProviderDnsResolver::new(false);
        let safe_error = match runtime.block_on(reqwest::dns::Resolve::resolve(&safe, name)) {
            Ok(_) => panic!("resolved loopback is denied"),
            Err(error) => error,
        };
        assert!(safe_error.to_string().contains(PRIVATE_DNS_REJECTION));

        let opted_in = ProviderDnsResolver::new(true);
        let addresses = runtime
            .block_on(reqwest::dns::Resolve::resolve(
                &opted_in,
                "localhost".parse().expect("DNS name parses"),
            ))
            .expect("opted-in resolver accepts loopback")
            .collect::<Vec<_>>();
        assert!(!addresses.is_empty());
        assert!(addresses.iter().all(|address| is_private_ip(address.ip())));
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
    fn connection_test_accepts_reasoning_only_length_limited_stream() {
        let body = concat!(
            "data: {\"model\":\"deepseek-v4-flash\",\"choices\":[{\"delta\":{\"reasoning_content\":\"hidden analysis\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":64,\"total_tokens\":68}}\n\n",
            "data: [DONE]\n\n"
        );
        let adapter = OpenAiCompatibleAdapter::new(MockTransport::new(TransportResponse {
            status: 200,
            body: body.to_owned(),
            first_content_token_latency_ms: Some(5),
            total_latency_ms: 9,
        }));

        let result = adapter.test_connection(
            &profile(ProviderKind::DeepSeek),
            &ApiSecret::new("contract-secret-1234"),
        );

        assert_eq!(result.status, crate::types::ConnectionTestStatus::Succeeded);
        assert_eq!(result.model.as_deref(), Some("deepseek-v4-flash"));
        assert_eq!(result.first_token_latency_ms, Some(5));
        assert_eq!(result.usage.and_then(|usage| usage.total_tokens), Some(68));
        assert!(!result.message.contains("hidden analysis"));
    }

    #[test]
    fn json_completion_metadata_is_parsed_but_cannot_fake_stream_latency() {
        let body = r#"{"model":"mock-json-model","choices":[{"message":{"content":"pong"}}],"usage":null}"#;
        let (model, usage) =
            parse_chat_completion_metadata(body, &ApiSecret::new("contract-secret-1234"))
                .expect("valid JSON completion parses");
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
    fn bounded_non_stream_parser_returns_visible_content_model_and_usage() {
        let body = r#"{
            "id":"chatcmpl-1",
            "model":"mock-model",
            "provider_extension":{"region":"test"},
            "choices":[{
                "index":0,
                "finish_reason":"stop",
                "message":{"role":"assistant","content":"visible"}
            }],
            "usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5,"cached_tokens":1}
        }"#;

        let completion = parse_chat_completion(body, "visible".len()).unwrap();
        assert_eq!(completion.content, "visible");
        assert_eq!(completion.model.as_deref(), Some("mock-model"));
        assert_eq!(
            completion.usage,
            Some(ChatUsage {
                prompt_tokens: Some(2),
                completion_tokens: Some(3),
                total_tokens: Some(5),
            })
        );
    }

    #[test]
    fn bounded_non_stream_parser_accepts_missing_and_partial_usage() {
        let missing =
            parse_chat_completion(r#"{"choices":[{"message":{"content":"one"}}]}"#, 16).unwrap();
        assert_eq!(missing.usage, None);
        assert_eq!(missing.model, None);

        let partial = parse_chat_completion(
            r#"{"choices":[{"message":{"content":"two"}}],"usage":{"prompt_tokens":4,"completion_tokens":"unknown"}}"#,
            16,
        )
        .unwrap();
        assert_eq!(
            partial.usage,
            Some(ChatUsage {
                prompt_tokens: Some(4),
                completion_tokens: None,
                total_tokens: None,
            })
        );

        let non_object_usage = parse_chat_completion(
            r#"{"choices":[{"message":{"content":"three"}}],"usage":"not-supported"}"#,
            16,
        )
        .unwrap();
        assert_eq!(non_object_usage.usage, None);
    }

    #[test]
    fn bounded_non_stream_parser_ignores_reasoning_and_debug_redacts_visible_fields() {
        let body = r#"{
            "model":"model-secret-1234",
            "choices":[{"message":{
                "reasoning_content":"hidden-chain-secret-5678",
                "content":"visible-content-secret-9999"
            }}]
        }"#;
        let completion = parse_chat_completion(body, 128).unwrap();
        assert_eq!(completion.content, "visible-content-secret-9999");
        assert_eq!(completion.model.as_deref(), Some("model-secret-1234"));
        let serialized = serde_json::to_value(&completion).unwrap();
        assert!(serialized.get("reasoningContent").is_none());
        assert!(!serialized.to_string().contains("hidden-chain-secret-5678"));

        let debug = format!("{completion:?}");
        assert!(!debug.contains("visible-content-secret-9999"));
        assert!(!debug.contains("model-secret-1234"));
        assert!(!debug.contains("hidden-chain-secret-5678"));
    }

    #[test]
    fn bounded_non_stream_parser_rejects_reasoning_only_and_bad_shapes() {
        for body in [
            r#"{"choices":[{"message":{"reasoning_content":"hidden"}}]}"#,
            r#"{"choices":[{"message":{"content":"   "}}]}"#,
            r#"{"choices":[{"message":{"content":[{"type":"text","text":"no"}]}}]}"#,
            r#"{"choices":[{}]}"#,
            r#"{"choices":[]}"#,
            r#"{"choices":"wrong"}"#,
            r#"{"error":{"message":"secret upstream detail"}}"#,
            r#"[]"#,
        ] {
            let error = parse_chat_completion(body, 128).unwrap_err();
            assert_eq!(error.kind, ProviderErrorKind::Parse);
            assert!(!error.to_string().contains("hidden"));
            assert!(!error.to_string().contains("secret upstream detail"));
        }
    }

    #[test]
    fn bounded_non_stream_parser_enforces_utf8_byte_and_hard_limits() {
        let unicode = r#"{"choices":[{"message":{"content":"你好"}}]}"#;
        assert_eq!(
            parse_chat_completion(unicode, 5).unwrap_err().kind,
            ProviderErrorKind::ResponseTooLarge
        );
        assert_eq!(parse_chat_completion(unicode, 6).unwrap().content, "你好");

        for invalid_limit in [0, MAX_CHAT_COMPLETION_CONTENT_BYTES + 1] {
            assert_eq!(
                parse_chat_completion(unicode, invalid_limit)
                    .unwrap_err()
                    .kind,
                ProviderErrorKind::InvalidRequest
            );
        }

        let oversized_body = "x".repeat(MAX_PROVIDER_RESPONSE_BYTES + 1);
        assert_eq!(
            parse_chat_completion(&oversized_body, 16).unwrap_err().kind,
            ProviderErrorKind::ResponseTooLarge
        );
    }

    #[test]
    fn bounded_non_stream_parser_rejects_non_json_sse_and_concatenated_json_without_leaks() {
        let secret = "parser-secret-1234";
        for body in [
            format!("not-json {secret}"),
            format!("data: {{\"choices\":[{{\"message\":{{\"content\":\"{secret}\"}}}}]}}\n\n"),
            format!(
                "{{\"choices\":[{{\"message\":{{\"content\":\"ok\"}}}}]}}{{\"debug\":\"{secret}\"}}"
            ),
        ] {
            let error = parse_chat_completion(&body, 128).unwrap_err();
            assert_eq!(error.kind, ProviderErrorKind::Parse);
            assert!(!format!("{error:?}").contains(secret));
            assert!(!error.to_string().contains(secret));
            assert!(!serde_json::to_string(&error).unwrap().contains(secret));
        }
    }

    #[test]
    fn bounded_non_stream_parser_works_for_every_profile_without_native_tools() {
        for kind in [
            ProviderKind::DeepSeek,
            ProviderKind::Qwen,
            ProviderKind::SiliconFlow,
            ProviderKind::VolcengineArk,
            ProviderKind::Custom,
        ] {
            let transport = MockTransport::new(TransportResponse {
                status: 200,
                body: r#"{"model":"compatible-model","choices":[{"message":{"content":"structured-json-text"}}]}"#.to_owned(),
                first_content_token_latency_ms: None,
                total_latency_ms: 1,
            });
            let adapter = OpenAiCompatibleAdapter::new(transport.clone());
            let mut profile = profile(kind);
            if kind == ProviderKind::Custom {
                profile.base_url = "https://provider.example/v1".to_owned();
                profile.model_id = "custom-model".to_owned();
            }
            let mut request = request_for_contract();
            request.stream = false;
            let response = adapter
                .send_chat(&profile, &ApiSecret::new("contract-secret-1234"), &request)
                .unwrap();
            let completion = parse_chat_completion(&response.body, 256).unwrap();
            assert_eq!(completion.content, "structured-json-text");

            let requests = transport.requests.lock().unwrap();
            let request_json: Value = serde_json::from_str(&requests[0].body).unwrap();
            assert_eq!(request_json["stream"], false);
            assert!(request_json.get("tools").is_none());
            assert!(request_json.get("tool_choice").is_none());
            assert_eq!(requests[0].header_value("Accept"), Some("application/json"));
        }
    }

    #[test]
    fn json_and_sse_model_metadata_cannot_echo_the_known_secret() {
        let secret = ApiSecret::new("model-echo-secret-1234");
        let json =
            r#"{"model":"model-echo-secret-1234","choices":[{"message":{"content":"pong"}}]}"#;
        let (json_model, _) =
            parse_chat_completion_metadata(json, &secret).expect("JSON completion metadata parses");
        assert_eq!(json_model.as_deref(), Some("<redacted>"));

        let sse = concat!(
            "data: {\"model\":\"model-echo-secret-1234\",\"choices\":[{\"delta\":{\"content\":\"pong\"}}]}\n\n",
            "data: [DONE]\n\n"
        );
        let (sse_model, _) = parse_streaming_completion_metadata(sse, &secret)
            .expect("SSE completion metadata parses");
        assert_eq!(sse_model.as_deref(), Some("<redacted>"));
    }

    #[test]
    fn json_error_inside_success_status_is_not_accepted_as_a_completion() {
        let error = parse_chat_completion_metadata(
            r#"{"error":{"type":"upstream_error","message":"generation failed"}}"#,
            &ApiSecret::new("contract-secret-1234"),
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
    fn http_error_redacts_known_secret_before_message_truncation() {
        let secret = "boundary-secret-that-must-never-be-partially-returned-1234";
        let filler = "x".repeat(210);
        let body = serde_json::json!({
            "error": {
                "type": "auth_error",
                "message": format!("{filler}{secret} rejected")
            }
        })
        .to_string();
        let adapter = OpenAiCompatibleAdapter::new(MockTransport::new(TransportResponse {
            status: 401,
            body,
            first_content_token_latency_ms: None,
            total_latency_ms: 6,
        }));

        let result =
            adapter.test_connection(&profile(ProviderKind::DeepSeek), &ApiSecret::new(secret));

        assert_eq!(result.status, crate::types::ConnectionTestStatus::Failed);
        assert!(!result.message.contains(secret));
        assert!(!result.message.contains(&secret[..16]));
        assert!(result.message.contains("<redacted>"));
    }

    #[test]
    fn provider_endpoint_origin_normalizes_path_and_default_port() {
        let mut profile = profile(ProviderKind::DeepSeek);
        profile.base_url = "https://API.DeepSeek.com:443/v1/".to_owned();

        assert_eq!(
            provider_endpoint_origin(&profile).expect("origin resolves"),
            "https://api.deepseek.com"
        );
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
    fn first_provider_token_ignores_keepalive_role_and_empty_deltas() {
        let mut parser = StreamParser::new();

        assert!(!stream_chunk_has_activity(
            &mut parser,
            b": keep-alive\n\ndata: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n"
        ));
        assert!(stream_chunk_has_activity(
            &mut parser,
            b"data: {\"choices\":[{\"delta\":{\"content\":\"p\"}}]}\n\n"
        ));
    }

    #[test]
    fn first_provider_token_is_detected_when_eof_terminates_the_event() {
        let mut parser = StreamParser::new();

        assert!(!stream_chunk_has_activity(
            &mut parser,
            br#"data: {"choices":[{"delta":{"content":"pong"}}]}"#
        ));
        assert!(stream_finish_has_activity(&mut parser));
    }

    #[test]
    fn hidden_reasoning_counts_as_provider_activity_without_becoming_content() {
        let mut parser = StreamParser::new();
        let events = parser.push(
            b"data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"private chain\"}}]}\n\n",
        );

        assert!(parser.saw_reasoning_content());
        assert!(!stream_events_have_content(events.clone()));
        assert!(!format!("{events:?}").contains("private chain"));

        let mut activity_parser = StreamParser::new();
        assert!(stream_chunk_has_activity(
            &mut activity_parser,
            b"data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"private chain\"}}]}\n\n"
        ));
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
        assert_eq!(error.kind, ProviderErrorKind::ResponseTooLarge);
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

    #[test]
    fn synchronous_reqwest_transport_never_follows_307_or_308() {
        for status in [307, 308] {
            let (source_url, target_requests, source_thread, target_thread) =
                spawn_redirect_fixture(status);
            let transport =
                ReqwestTransport::new_with_timeouts(Duration::from_secs(1), Duration::from_secs(1))
                    .expect("transport builds");

            let response = transport
                .send(test_transport_request(
                    source_url,
                    vec![
                        TransportHeader::new("Authorization", redirect_authorization_value()),
                        TransportHeader::new("Content-Type", "application/json"),
                    ],
                    "{\"case\":\"confidential-lawyer-body\"}",
                    false,
                    true,
                ))
                .expect("redirect response is returned without following it");

            assert_eq!(response.status, status);
            source_thread.join().expect("source fixture exits");
            target_thread.join().expect("target fixture exits");
            assert!(
                target_requests.try_recv().is_err(),
                "redirect target must receive neither Authorization nor request body"
            );
        }
    }

    #[test]
    fn asynchronous_reqwest_transport_never_follows_307_or_308() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");

        for status in [307, 308] {
            let (source_url, target_requests, source_thread, target_thread) =
                spawn_redirect_fixture(status);
            let transport = ReqwestStreamingTransport::new_with_timeouts(
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .expect("transport builds");

            let returned_status = runtime.block_on(async {
                transport
                    .private_network_client
                    .post(source_url)
                    .header("Authorization", redirect_authorization_value())
                    .body("confidential-lawyer-body")
                    .send()
                    .await
                    .expect("redirect response is returned")
                    .status()
                    .as_u16()
            });

            assert_eq!(returned_status, status);
            source_thread.join().expect("source fixture exits");
            target_thread.join().expect("target fixture exits");
            assert!(
                target_requests.try_recv().is_err(),
                "redirect target must receive neither Authorization nor request body"
            );
        }
    }

    #[test]
    fn synchronous_transport_uses_read_idle_instead_of_total_timeout() {
        let read_idle_timeout = Duration::from_millis(200);
        let (url, server_thread) = spawn_slow_chunked_sse_fixture(Duration::from_millis(80));
        let transport =
            ReqwestTransport::new_with_timeouts(Duration::from_secs(1), read_idle_timeout)
                .expect("transport builds");

        let response = transport
            .send(test_transport_request(
                url,
                vec![TransportHeader::new("Content-Type", "application/json")],
                "{}",
                true,
                true,
            ))
            .expect("regular chunks keep a stream alive beyond the old total deadline");

        server_thread.join().expect("SSE fixture exits");
        assert_eq!(response.status, 200);
        assert!(response.body.contains("pong"));
        assert!(response.first_content_token_latency_ms.is_some());
        assert!(
            response.total_latency_ms >= read_idle_timeout.as_millis(),
            "fixture must outlive the configured idle window"
        );
    }

    #[test]
    fn asynchronous_transport_uses_read_idle_instead_of_total_timeout() {
        let read_idle_timeout = Duration::from_millis(200);
        let (url, server_thread) = spawn_slow_chunked_sse_fixture(Duration::from_millis(80));
        let transport =
            ReqwestStreamingTransport::new_with_timeouts(Duration::from_secs(1), read_idle_timeout)
                .expect("transport builds");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        let started_at = Instant::now();

        let body = runtime.block_on(async {
            transport
                .private_network_client
                .post(url)
                .body("{}")
                .send()
                .await
                .expect("response headers arrive")
                .bytes()
                .await
                .expect("regular chunks keep the response alive")
        });

        server_thread.join().expect("SSE fixture exits");
        assert!(String::from_utf8_lossy(&body).contains("pong"));
        assert!(
            started_at.elapsed() >= read_idle_timeout,
            "fixture must outlive the configured idle window"
        );
    }

    #[test]
    fn read_idle_timeout_still_fails_a_stalled_response() {
        let (url, server_thread) = spawn_stalled_response_fixture(Duration::from_millis(250));
        let transport =
            ReqwestTransport::new_with_timeouts(Duration::from_secs(1), Duration::from_millis(80))
                .expect("transport builds");

        let error = transport
            .send(test_transport_request(url, Vec::new(), "{}", true, true))
            .expect_err("a response with no bytes inside the idle window times out");

        server_thread.join().expect("stalled fixture exits");
        assert_eq!(error.kind, ProviderErrorKind::Timeout);
    }

    #[test]
    fn synchronous_transport_enforces_absolute_limit_despite_keepalives() {
        let (url, server_thread) = spawn_slow_chunked_sse_fixture(Duration::from_millis(50));
        let transport = ReqwestTransport::new_with_limits(
            Duration::from_secs(1),
            Duration::from_millis(200),
            Duration::from_millis(110),
        )
        .expect("transport builds");

        let error = transport
            .send(test_transport_request(url, Vec::new(), "{}", true, true))
            .expect_err("regular keepalives cannot extend the absolute deadline");

        let _ = server_thread.join();
        assert_eq!(error.kind, ProviderErrorKind::Timeout);
    }

    #[test]
    fn streaming_response_enforces_absolute_limit_despite_keepalives() {
        let (url, server_thread) = spawn_slow_chunked_sse_fixture(Duration::from_millis(50));
        let transport = ReqwestStreamingTransport::new_with_limits(
            Duration::from_secs(1),
            Duration::from_millis(200),
            Duration::from_millis(110),
        )
        .expect("transport builds");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");

        let error = runtime.block_on(async {
            let response = transport
                .private_network_client
                .post(url)
                .body("{}")
                .send()
                .await
                .expect("response headers arrive");
            let mut response = StreamingTransportResponse {
                status: response.status().as_u16(),
                response,
            };
            loop {
                match response.next_chunk().await {
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("fixture ended before the absolute deadline"),
                    Err(error) => break error,
                }
            }
        });

        let _ = server_thread.join();
        assert_eq!(error.kind, ProviderErrorKind::Timeout);
    }

    #[test]
    fn transport_rejects_zero_absolute_timeout() {
        let error = ReqwestTransport::new_with_limits(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .expect_err("zero absolute timeout is invalid");
        assert_eq!(error.kind, ProviderErrorKind::InvalidRequest);
    }

    #[test]
    fn synchronous_transport_is_safe_when_called_from_a_tokio_context() {
        let (url, server_thread) = spawn_slow_chunked_sse_fixture(Duration::from_millis(1));
        let transport = ReqwestTransport::new(Duration::from_secs(1)).expect("transport builds");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("outer runtime builds");

        let response = runtime.block_on(async {
            transport.send(test_transport_request(url, Vec::new(), "{}", true, true))
        });

        server_thread.join().expect("SSE fixture exits");
        assert_eq!(response.expect("nested runtime is avoided").status, 200);
    }

    struct ApprovedJsonFixture {
        base_url: String,
        shutdown: mpsc::Sender<()>,
        server_thread: Option<thread::JoinHandle<Vec<Vec<u8>>>>,
    }

    impl ApprovedJsonFixture {
        fn finish(mut self) -> Vec<Vec<u8>> {
            let _ = self.shutdown.send(());
            self.server_thread
                .take()
                .expect("approved provider fixture thread is owned")
                .join()
                .expect("approved provider fixture exits")
        }
    }

    impl Drop for ApprovedJsonFixture {
        fn drop(&mut self) {
            let _ = self.shutdown.send(());
            if let Some(server_thread) = self.server_thread.take() {
                if server_thread.join().is_err() {
                    if thread::panicking() {
                        eprintln!("approved provider fixture thread terminated unexpectedly");
                    } else {
                        panic!("approved provider fixture thread terminated unexpectedly");
                    }
                }
            }
        }
    }

    fn spawn_approved_json_fixture() -> ApprovedJsonFixture {
        let listener = TcpListener::bind("127.0.0.1:0").expect("approved provider listener binds");
        listener
            .set_nonblocking(true)
            .expect("approved provider listener becomes nonblocking");
        let base_url = format!(
            "http://{}/v1",
            listener
                .local_addr()
                .expect("approved provider address resolves")
        );
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (shutdown, shutdown_receiver) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            const BODY: &[u8] = br#"{"model":"approved-chat-model","choices":[{"message":{"content":"ok"}}],"usage":null}"#;
            let mut requests = Vec::new();
            if ready_sender.send(()).is_err() {
                return requests;
            }
            loop {
                match shutdown_receiver.try_recv() {
                    Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_nonblocking(false)
                            .expect("approved provider connection becomes blocking");
                        let request = read_http_request(&mut stream);
                        requests.push(request);
                        let headers = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            BODY.len()
                        );
                        stream
                            .write_all(headers.as_bytes())
                            .and_then(|_| stream.write_all(BODY))
                            .and_then(|_| stream.flush())
                            .and_then(|_| stream.shutdown(Shutdown::Write))
                            .expect("approved provider fixture writes response");
                        let mut peer_close = [0_u8; 1];
                        let _ = stream.read(&mut peer_close);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("approved provider fixture failed: {error}"),
                }
            }
            requests
        });
        let fixture = ApprovedJsonFixture {
            base_url,
            shutdown,
            server_thread: Some(server_thread),
        };
        ready_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("approved provider fixture becomes ready");
        fixture
    }

    fn spawn_redirect_fixture(
        status: u16,
    ) -> (
        String,
        mpsc::Receiver<Vec<u8>>,
        thread::JoinHandle<()>,
        thread::JoinHandle<()>,
    ) {
        let target_listener = TcpListener::bind("127.0.0.1:0").expect("target listener binds");
        target_listener
            .set_nonblocking(true)
            .expect("target listener becomes nonblocking");
        let target_url = format!(
            "http://{}/redirect-target",
            target_listener
                .local_addr()
                .expect("target address resolves")
        );
        let (target_sender, target_requests) = mpsc::channel();
        let target_thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(350);
            while Instant::now() < deadline {
                match target_listener.accept() {
                    Ok((mut stream, _)) => {
                        let request = read_http_request(&mut stream);
                        let _ = target_sender.send(request);
                        let _ = stream.write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });

        let source_listener = TcpListener::bind("127.0.0.1:0").expect("source listener binds");
        let source_url = format!(
            "http://{}/chat/completions",
            source_listener
                .local_addr()
                .expect("source address resolves")
        );
        let source_thread = thread::spawn(move || {
            let (mut stream, _) = source_listener.accept().expect("source accepts request");
            let source_request = read_http_request(&mut stream);
            assert!(source_request
                .windows(b"redirect-secret-must-not-cross-origin".len())
                .any(|window| window == b"redirect-secret-must-not-cross-origin"));
            assert!(source_request
                .windows(b"confidential-lawyer-body".len())
                .any(|window| window == b"confidential-lawyer-body"));
            let response = format!(
                "HTTP/1.1 {status} Temporary Redirect\r\nLocation: {target_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .expect("source writes redirect");
        });

        (source_url, target_requests, source_thread, target_thread)
    }

    fn redirect_authorization_value() -> String {
        let scheme = ["Bear", "er"].concat();
        let token = ["redirect", "-secret", "-must-not-cross-origin"].concat();
        format!("{scheme} {token}")
    }

    fn spawn_slow_chunked_sse_fixture(gap: Duration) -> (String, thread::JoinHandle<()>) {
        const CHUNKS: [&[u8]; 4] = [
            b": keep-alive\n\n",
            b"data: {\"model\":\"deepseek-v4-flash\",\"choices\":[{\"delta\":{\"reasoning_content\":\"hidden\"}}]}\n\n",
            b"data: {\"choices\":[{\"delta\":{\"content\":\"pong\"}}]}\n\n",
            b"data: [DONE]\n\n",
        ];
        let listener = TcpListener::bind("127.0.0.1:0").expect("SSE listener binds");
        let url = format!(
            "http://{}/chat/completions",
            listener.local_addr().expect("SSE address resolves")
        );
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("SSE fixture accepts request");
            let _ = read_http_request(&mut stream);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .expect("SSE fixture writes headers");

            for (index, chunk) in CHUNKS.iter().enumerate() {
                if index > 0 {
                    thread::sleep(gap);
                }
                let prefix = format!("{:X}\r\n", chunk.len());
                if stream
                    .write_all(prefix.as_bytes())
                    .and_then(|_| stream.write_all(chunk))
                    .and_then(|_| stream.write_all(b"\r\n"))
                    .and_then(|_| stream.flush())
                    .is_err()
                {
                    return;
                }
            }
            let _ = stream.write_all(b"0\r\n\r\n");
        });

        (url, server_thread)
    }

    fn spawn_stalled_response_fixture(stall: Duration) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("stall listener binds");
        let url = format!(
            "http://{}/chat/completions",
            listener.local_addr().expect("stall address resolves")
        );
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("stall fixture accepts request");
            let _ = read_http_request(&mut stream);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .expect("stall fixture writes headers");
            stream.flush().expect("stall fixture flushes headers");
            thread::sleep(stall);
            let _ = stream.write_all(b"0\r\n\r\n");
        });

        (url, server_thread)
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("fixture read timeout is configured");
        let mut request = Vec::new();
        let mut buffer = [0_u8; 2048];

        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    request.extend_from_slice(&buffer[..read]);
                    if request_is_complete(&request) {
                        break;
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(error) => panic!("fixture request read failed: {error}"),
            }
        }

        request
    }

    fn request_is_complete(request: &[u8]) -> bool {
        let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|index| index + 4)
        else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);

        request.len() >= header_end + content_length
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
