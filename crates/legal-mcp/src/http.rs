use crate::{
    config::{parse_bearer, BearerSecret, Limits, ResolvedConfig},
    handler::{LegalMcpServer, STABLE_PROTOCOL_VERSION},
    privacy_backend::DaemonPrivacyBackendFactory,
    registry::{PrivacyProfile, ToolRegistry},
    service_adapter::{InFlightOperations, PrivacyWorkspaceError, ServiceAdapter},
};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, HOST, ORIGIN, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Json, Router,
};
use legal_services::LegalServices;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use url::Url;

pub const MCP_PATH: &str = "/mcp";
const PROTOCOL_HEADER: &str = "mcp-protocol-version";

/// Request-only capability selected before rmcp sees a message. `Privacy` is
/// only a candidate: every private tools/call still creates a request-scoped
/// backend and the local application verifies that bearer token and group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpClientScope {
    Public,
    Privacy,
}

/// Configuration for embedding one Streamable HTTP endpoint in the application
/// server. A public token, when configured, is explicitly restricted to the
/// seven public tools. Any other syntactically valid bearer is passed only to a
/// new request-scoped daemon adapter for a privacy tool; it is never saved in
/// router state or used for another request.
#[derive(Debug, Clone)]
pub struct ProxyRouterConfig {
    pub daemon_url: Url,
    pub limits: Limits,
    pub public_token: Option<BearerSecret>,
}

impl ProxyRouterConfig {
    pub fn new(daemon_url: Url, limits: Limits) -> Self {
        Self {
            daemon_url,
            limits,
            public_token: None,
        }
    }
}

#[derive(Clone)]
struct HttpSecurity {
    bind: SocketAddr,
    public_token: Option<BearerSecret>,
    max_body_bytes: usize,
    request_timeout: std::time::Duration,
    concurrency: Arc<Semaphore>,
    in_flight: InFlightOperations,
}

/// Build a server-owned privacy MCP router. It does not open the application's
/// private database. Legal queries use `LegalServices`; each privacy call is
/// routed through the supplied loopback daemon origin.
pub fn build_proxy_router(
    legal_services: LegalServices,
    bind: SocketAddr,
    proxy: ProxyRouterConfig,
    cancellation: CancellationToken,
) -> Result<Router, PrivacyWorkspaceError> {
    if !bind.ip().is_loopback() {
        return Err(PrivacyWorkspaceError::new(
            "invalid_daemon_configuration",
            false,
        ));
    }
    let factory = DaemonPrivacyBackendFactory::new(proxy.daemon_url, proxy.limits.clone())?;
    let server = LegalMcpServer::new(
        ToolRegistry::for_profile(PrivacyProfile::PrivacyWorkspace),
        ServiceAdapter::for_privacy_workspace_proxy(legal_services, Arc::new(factory)),
    );
    Ok(build_router_with_security(
        server,
        bind,
        proxy.public_token,
        proxy.limits,
        cancellation,
    ))
}

pub async fn serve_http(
    server: LegalMcpServer,
    config: &ResolvedConfig,
) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    let cancellation = CancellationToken::new();
    let serving = serve_http_on_listener(server, config, listener, cancellation.clone());
    tokio::pin!(serving);
    tokio::select! {
        result = &mut serving => result,
        _ = tokio::signal::ctrl_c() => {
            cancellation.cancel();
            serving.await
        }
    }
}

pub async fn serve_http_on_listener(
    server: LegalMcpServer,
    config: &ResolvedConfig,
    listener: tokio::net::TcpListener,
    cancellation: CancellationToken,
) -> Result<(), std::io::Error> {
    let address = listener.local_addr()?;
    let in_flight = server.in_flight_operations();
    let router = build_router(server, config, cancellation.child_token());
    tracing::info!(bind = %address, endpoint = MCP_PATH, "MCP HTTP server listening");
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancellation.cancelled().await })
        .await;
    in_flight.close_and_wait().await;
    result
}

/// Build the standalone binary router. `privacy_workspace` is request scoped
/// only when the caller constructed its adapter with
/// `ServiceAdapter::for_privacy_workspace_proxy`; the packaged binary does so
/// for HTTP while stdio uses a token loaded once from a file/environment.
pub fn build_router(
    server: LegalMcpServer,
    config: &ResolvedConfig,
    cancellation: CancellationToken,
) -> Router {
    build_router_with_security(
        server,
        config.bind,
        None,
        config.limits.clone(),
        cancellation,
    )
}

fn build_router_with_security(
    server: LegalMcpServer,
    bind: SocketAddr,
    public_token: Option<BearerSecret>,
    limits: Limits,
    cancellation: CancellationToken,
) -> Router {
    let in_flight = server.in_flight_operations();
    let service: StreamableHttpService<LegalMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default()
                .with_stateful_mode(false)
                .with_json_response(true)
                .with_sse_keep_alive(None)
                .with_sse_retry(None)
                .with_allowed_hosts(default_allowed_hosts(bind))
                .with_cancellation_token(cancellation),
        );
    Router::new()
        .nest_service(MCP_PATH, service)
        .layer(middleware::from_fn_with_state(
            HttpSecurity {
                bind,
                public_token,
                max_body_bytes: limits.max_body_bytes,
                request_timeout: limits.request_timeout,
                concurrency: Arc::new(Semaphore::new(limits.max_concurrency)),
                in_flight,
            },
            enforce_http_boundary,
        ))
}

async fn enforce_http_boundary(
    State(security): State<HttpSecurity>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    if request.uri().path() != MCP_PATH {
        return rejection(StatusCode::NOT_FOUND, "not_found", false);
    }
    if !valid_host(request.headers(), security.bind) || !valid_origin(request.headers()) {
        return rejection(StatusCode::FORBIDDEN, "origin_not_allowed", false);
    }
    let scope = match classify_client(request.headers(), security.public_token.as_ref()) {
        Ok(scope) => scope,
        Err(()) => return rejection(StatusCode::UNAUTHORIZED, "unauthorized", true),
    };
    if request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > security.max_body_bytes)
    {
        return rejection(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_body_too_large",
            false,
        );
    }
    let Ok(permit) = Arc::clone(&security.concurrency).try_acquire_owned() else {
        return rejection(
            StatusCode::TOO_MANY_REQUESTS,
            "concurrency_limit_exceeded",
            false,
        );
    };
    let Some(request_guard) = security.in_flight.try_begin() else {
        drop(permit);
        return rejection(StatusCode::SERVICE_UNAVAILABLE, "server_stopping", false);
    };
    let deadline = tokio::time::Instant::now() + security.request_timeout;
    let (mut parts, body) = request.into_parts();
    let body =
        match tokio::time::timeout_at(deadline, to_bytes(body, security.max_body_bytes)).await {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                drop(permit);
                return rejection(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request_body_too_large",
                    false,
                );
            }
            Err(_) => {
                drop(permit);
                return rejection(StatusCode::REQUEST_TIMEOUT, "request_timeout", false);
            }
        };
    if !valid_protocol_header(&parts.headers, &body) {
        drop(permit);
        return rejection(
            StatusCode::BAD_REQUEST,
            "unsupported_protocol_version",
            false,
        );
    }
    parts.extensions.insert(scope);
    let request = Request::from_parts(parts, Body::from(body));
    let mut task = tokio::spawn(async move {
        // Keep the admission permit with the detached task. A timeout only
        // ends the client response; it must not advertise free capacity while
        // the local daemon request may still be processing the operation.
        let _permit = permit;
        let _request_guard = request_guard;
        next.run(request).await
    });
    let mut response = match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => rejection(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_server_error",
            false,
        ),
        Err(_) => rejection(StatusCode::REQUEST_TIMEOUT, "request_timeout", false),
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    tracing::debug!(
        elapsed_ms = started.elapsed().as_millis(),
        "MCP HTTP request completed"
    );
    response
}

fn classify_client(
    headers: &HeaderMap,
    public_token: Option<&BearerSecret>,
) -> Result<HttpClientScope, ()> {
    let values = headers.get_all(AUTHORIZATION).iter().collect::<Vec<_>>();
    match values.as_slice() {
        [] => Ok(HttpClientScope::Public),
        [value] => {
            let value = value.to_str().map_err(|_| ())?;
            if public_token.is_some_and(|token| token.authorizes(value)) {
                return Ok(HttpClientScope::Public);
            }
            if parse_bearer(value).is_some() {
                Ok(HttpClientScope::Privacy)
            } else {
                Err(())
            }
        }
        _ => Err(()),
    }
}

fn valid_host(headers: &HeaderMap, bind: SocketAddr) -> bool {
    let values = headers.get_all(HOST).iter().collect::<Vec<_>>();
    match values.as_slice() {
        [] => true,
        [value] => value.to_str().ok().is_some_and(|host| {
            default_allowed_hosts(bind)
                .iter()
                .any(|allowed| allowed == host)
        }),
        _ => false,
    }
}

fn valid_origin(headers: &HeaderMap) -> bool {
    let values = headers.get_all(ORIGIN).iter().collect::<Vec<_>>();
    match values.as_slice() {
        [] => true,
        [value] => value.to_str().ok().is_some_and(|origin| {
            let Ok(url) = Url::parse(origin) else {
                return false;
            };
            url.scheme() == "http"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && matches!(url.path(), "" | "/")
                && url
                    .host_str()
                    .and_then(|host| host.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback())
        }),
        _ => false,
    }
}

fn valid_protocol_header(headers: &HeaderMap, body: &[u8]) -> bool {
    let values = headers.get_all(PROTOCOL_HEADER).iter().collect::<Vec<_>>();
    if values.len() > 1 {
        return false;
    }
    let initialize = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|method| method == "initialize");
    if initialize {
        return true;
    }
    values
        .first()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|version| version == STABLE_PROTOCOL_VERSION)
}

fn default_allowed_hosts(bind: SocketAddr) -> Vec<String> {
    let mut hosts = vec![
        format!("127.0.0.1:{}", bind.port()),
        format!("localhost:{}", bind.port()),
    ];
    if bind.ip().is_ipv6() {
        hosts.push(format!("[::1]:{}", bind.port()));
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

fn rejection(status: StatusCode, code: &'static str, authenticate: bool) -> Response {
    let retryable = matches!(
        code,
        "concurrency_limit_exceeded" | "request_timeout" | "server_stopping"
    );
    let mut response = (
        status,
        Json(json!({"error":{"code":code,"retryable":retryable}})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if authenticate {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"lawyer-assistance-mcp\""),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        http::{
            header::{ACCEPT, CONTENT_TYPE},
            Method,
        },
        routing::post,
    };
    use std::path::PathBuf;
    use tower::ServiceExt;

    fn limits() -> Limits {
        Limits {
            max_body_bytes: 16 * 1024,
            request_timeout: std::time::Duration::from_secs(2),
            max_concurrency: 2,
            max_daemon_response_bytes: 16 * 1024,
        }
    }

    fn router() -> Router {
        let services = LegalServices::new_public(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("legal.sqlite"),
        )
        .expect("service");
        build_proxy_router(
            services,
            "127.0.0.1:8787".parse().expect("bind"),
            ProxyRouterConfig::new(
                Url::parse("http://127.0.0.1:8877").expect("daemon"),
                limits(),
            ),
            CancellationToken::new(),
        )
        .expect("router")
    }

    #[tokio::test]
    async fn public_and_privacy_bearers_see_different_tool_lists() {
        let public = router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(MCP_PATH)
                    .header(CONTENT_TYPE, "application/json")
                    .header(ACCEPT, "application/json, text/event-stream")
                    .header(HOST, "127.0.0.1:8787")
                    .header(PROTOCOL_HEADER, STABLE_PROTOCOL_VERSION)
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(public.status(), StatusCode::OK);
        let bytes = to_bytes(public.into_body(), 64 * 1024).await.expect("body");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["result"]["tools"].as_array().map(Vec::len), Some(7));

        let privacy = router()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(MCP_PATH)
                    .header(CONTENT_TYPE, "application/json")
                    .header(ACCEPT, "application/json, text/event-stream")
                    .header(HOST, "127.0.0.1:8787")
                    .header(PROTOCOL_HEADER, STABLE_PROTOCOL_VERSION)
                    .header(AUTHORIZATION, "Bearer 0123456789abcdef0123456789abcdef")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        let bytes = to_bytes(privacy.into_body(), 64 * 1024)
            .await
            .expect("body");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
        assert_eq!(value["result"]["tools"].as_array().map(Vec::len), Some(10));
    }

    #[test]
    fn malformed_or_multiple_auth_headers_are_rejected_without_echo() {
        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer one"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Bearer two"));
        assert!(classify_client(&headers, None).is_err());
        headers.clear();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer C:\\secret"));
        assert!(classify_client(&headers, None).is_err());
    }

    #[tokio::test]
    async fn timeout_keeps_the_concurrency_permit_until_the_daemon_call_finishes() {
        let daemon_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("daemon listener");
        let daemon_address = daemon_listener.local_addr().expect("daemon address");
        let daemon = tokio::spawn(async move {
            let app = Router::new().route(
                "/api/v1/mcp/status",
                post(|| async {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    Json(json!({"status":"processing"}))
                }),
            );
            let _ = axum::serve(daemon_listener, app).await;
        });
        let mut slow_limits = limits();
        slow_limits.request_timeout = std::time::Duration::from_millis(40);
        slow_limits.max_concurrency = 1;
        let services = LegalServices::new_public(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("legal.sqlite"),
        )
        .expect("service");
        let app = build_proxy_router(
            services,
            "127.0.0.1:8787".parse().expect("bind"),
            ProxyRouterConfig::new(
                Url::parse(&format!("http://{daemon_address}")).expect("daemon URL"),
                slow_limits,
            ),
            CancellationToken::new(),
        )
        .expect("router");
        let request = || {
            Request::builder()
                .method(Method::POST)
                .uri(MCP_PATH)
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json, text/event-stream")
                .header(HOST, "127.0.0.1:8787")
                .header(PROTOCOL_HEADER, STABLE_PROTOCOL_VERSION)
                .header(AUTHORIZATION, "Bearer 0123456789abcdef0123456789abcdef")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"privacy_workspace.status","arguments":{"task_id":"task_1"}}}"#,
                ))
                .expect("request")
        };
        let timed_out = app
            .clone()
            .oneshot(request())
            .await
            .expect("timeout response");
        assert_eq!(timed_out.status(), StatusCode::REQUEST_TIMEOUT);
        let rejected = app.oneshot(request()).await.expect("capacity response");
        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
        daemon.abort();
    }
}
