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
    error::Error as StdError,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};

use crate::stream::{StreamEvent, StreamParser};

const MAX_PROVIDER_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_ABSOLUTE_REQUEST_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const PRIVATE_DNS_REJECTION: &str = "provider-dns-rejected-special-address";
static SYNCHRONOUS_TRANSPORT_RUNTIME: OnceLock<
    Result<Arc<tokio::runtime::Runtime>, ProviderError>,
> = OnceLock::new();

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

#[derive(Clone, PartialEq, Eq)]
pub struct TransportRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<TransportHeader>,
    pub body: String,
    pub expects_stream: bool,
    pub allow_private_network: bool,
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
        let client = select_client(&self.safe_client, &self.private_network_client, &request)?;
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

    fn send_chat_with_cancellation(
        &self,
        profile: &ProviderProfile,
        secret: &ApiSecret,
        request: &ChatRequest,
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

    fn test_connection(&self, profile: &ProviderProfile, secret: &ApiSecret) -> ConnectionTest {
        OpenAiCompatibleAdapter::test_connection(self, profile, secret)
    }
}

fn build_transport_request(
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
        allow_private_network: private_network_is_explicitly_allowed(profile),
    })
}

pub fn provider_endpoint_origin(profile: &ProviderProfile) -> Result<String, ProviderError> {
    let (_, parsed) = parsed_provider_base_url(profile)?;
    Ok(parsed.origin().ascii_serialization())
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

    // Apply the same explicit defaults used by newly-created profiles even if
    // a legacy/imported profile omitted a toggle. DeepSeek V4 otherwise turns
    // thinking on at the service boundary and can consume the entire output
    // allowance before producing user-visible content.
    let normalized_options = profile.kind.options_with_defaults(profile.options.clone());
    apply_provider_options(profile.kind, &normalized_options, &mut body);

    Ok(Value::Object(body))
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

fn parse_chat_completion_metadata(
    body: &str,
    secret: &ApiSecret,
) -> Result<(Option<String>, Option<ChatUsage>), ProviderError> {
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        if value.get("error").is_some() {
            return Err(map_http_error(200, body, secret));
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
            .map(|model| redact_known_secret_text(model, secret));
        let usage = value
            .get("usage")
            .filter(|usage| usage.is_object())
            .map(parse_usage);

        return Ok((model, usage));
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
        net::{TcpListener, TcpStream},
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
        assert!(!request.allow_private_network);
        assert!(!format!("{request:?}").contains("contract-secret-1234"));
        assert!(!format!("{request:?}").contains("ping"));
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
                .send(TransportRequest {
                    method: "POST".to_owned(),
                    url: source_url,
                    headers: vec![
                        TransportHeader::new("Authorization", redirect_authorization_value()),
                        TransportHeader::new("Content-Type", "application/json"),
                    ],
                    body: "{\"case\":\"confidential-lawyer-body\"}".to_owned(),
                    expects_stream: false,
                    allow_private_network: true,
                })
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
            .send(TransportRequest {
                method: "POST".to_owned(),
                url,
                headers: vec![TransportHeader::new("Content-Type", "application/json")],
                body: "{}".to_owned(),
                expects_stream: true,
                allow_private_network: true,
            })
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
            .send(TransportRequest {
                method: "POST".to_owned(),
                url,
                headers: Vec::new(),
                body: "{}".to_owned(),
                expects_stream: true,
                allow_private_network: true,
            })
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
            .send(TransportRequest {
                method: "POST".to_owned(),
                url,
                headers: Vec::new(),
                body: "{}".to_owned(),
                expects_stream: true,
                allow_private_network: true,
            })
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
            transport.send(TransportRequest {
                method: "POST".to_owned(),
                url,
                headers: Vec::new(),
                body: "{}".to_owned(),
                expects_stream: true,
                allow_private_network: true,
            })
        });

        server_thread.join().expect("SSE fixture exits");
        assert_eq!(response.expect("nested runtime is avoided").status, 200);
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
