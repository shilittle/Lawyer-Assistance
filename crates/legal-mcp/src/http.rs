use crate::{
    config::{normalize_request_origin, ResolvedConfig},
    handler::{LegalMcpServer, STABLE_PROTOCOL_VERSION},
    service_adapter::InFlightOperations,
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
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use serde_json::json;
use std::{sync::Arc, time::Instant};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const MCP_PATH: &str = "/mcp";
const PROTOCOL_HEADER: &str = "mcp-protocol-version";

#[derive(Debug, Clone)]
struct HttpSecurity {
    allowed_origins: Arc<Vec<String>>,
    allowed_hosts: Arc<Vec<String>>,
    bearer: Option<crate::config::BearerSecret>,
    max_body_bytes: usize,
    request_timeout: std::time::Duration,
    concurrency: Arc<Semaphore>,
    in_flight: InFlightOperations,
}

impl HttpSecurity {
    fn from_config(config: &ResolvedConfig, in_flight: InFlightOperations) -> Self {
        Self {
            allowed_origins: Arc::new(config.allowed_origins.clone()),
            allowed_hosts: Arc::new(config.allowed_hosts.clone()),
            bearer: config.bearer.clone(),
            max_body_bytes: config.limits.max_body_bytes,
            request_timeout: config.limits.request_timeout,
            concurrency: Arc::new(Semaphore::new(config.limits.max_concurrency)),
            in_flight,
        }
    }
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

/// Serve an embedded HTTP MCP endpoint on an already-bound listener until the
/// caller cancels `cancellation`.
///
/// This entry point deliberately does not install a process signal handler.
/// Binding before calling it lets an embedding application report startup
/// failures and the listener's actual address before it marks the service as
/// running.
pub async fn serve_http_on_listener(
    server: LegalMcpServer,
    config: &ResolvedConfig,
    listener: tokio::net::TcpListener,
    cancellation: CancellationToken,
) -> Result<(), std::io::Error> {
    let in_flight = server.in_flight_operations();
    let router = build_router(server, config, cancellation.child_token());
    let address = listener.local_addr()?;
    tracing::info!(bind = %address, endpoint = MCP_PATH, "MCP HTTP server listening");
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(async move { cancellation.cancelled().await })
        .await;
    // `spawn_blocking` service calls cannot be aborted. Close the admission
    // gate and wait for every request/operation guard before the embedding
    // application is allowed to report a fully stopped server.
    in_flight.close_and_wait().await;
    result
}

pub fn build_router(
    server: LegalMcpServer,
    config: &ResolvedConfig,
    cancellation: CancellationToken,
) -> Router {
    let in_flight = server.in_flight_operations();
    let mcp_config = StreamableHttpServerConfig::default()
        .with_stateful_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_sse_retry(None)
        .with_allowed_hosts(config.allowed_hosts.clone())
        .with_allowed_origins(config.allowed_origins.clone())
        .with_cancellation_token(cancellation);
    let service: StreamableHttpService<LegalMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(LocalSessionManager::default()),
            mcp_config,
        );
    Router::new()
        .nest_service(MCP_PATH, service)
        .layer(middleware::from_fn_with_state(
            HttpSecurity::from_config(config, in_flight),
            enforce_http_boundary,
        ))
}

async fn enforce_http_boundary(
    State(security): State<HttpSecurity>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let started = Instant::now();
    let method = request.method().clone();

    if request.uri().path() != MCP_PATH {
        return rejection(StatusCode::NOT_FOUND, "not_found", &request_id, false);
    }
    if let Err((status, code)) = validate_host(request.headers(), &security.allowed_hosts) {
        return rejection(status, code, &request_id, false);
    }
    if let Err((status, code)) = validate_origin(request.headers(), &security.allowed_origins) {
        return rejection(status, code, &request_id, false);
    }
    if let Err((status, code)) = validate_authorization(request.headers(), security.bearer.as_ref())
    {
        return rejection(status, code, &request_id, true);
    }
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
            &request_id,
            false,
        );
    }

    let Ok(permit) = Arc::clone(&security.concurrency).try_acquire_owned() else {
        let mut response = rejection(
            StatusCode::TOO_MANY_REQUESTS,
            "concurrency_limit_exceeded",
            &request_id,
            false,
        );
        response
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
        return response;
    };

    let deadline = tokio::time::Instant::now() + security.request_timeout;
    let (parts, body) = request.into_parts();
    let body =
        match tokio::time::timeout_at(deadline, to_bytes(body, security.max_body_bytes)).await {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                return rejection(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request_body_too_large",
                    &request_id,
                    false,
                )
            }
            Err(_) => {
                return rejection(
                    StatusCode::REQUEST_TIMEOUT,
                    "request_timeout",
                    &request_id,
                    false,
                )
            }
        };
    let initialize = body_is_initialize(&body);
    if let Err((status, code)) = validate_protocol_header(&parts.headers, initialize) {
        return rejection(status, code, &request_id, false);
    }
    let body = if initialize {
        match normalize_initialize_protocol(&body) {
            Some(body) if body.len() <= security.max_body_bytes => body,
            Some(_) => {
                return rejection(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request_body_too_large",
                    &request_id,
                    false,
                )
            }
            None => body.to_vec(),
        }
    } else {
        body.to_vec()
    };
    let timeout_details = timeout_details(&body);
    let request = Request::from_parts(parts, Body::from(body));
    // Run the downstream request in its own task. If the client-facing deadline
    // expires, the task is deliberately allowed to finish while retaining the
    // concurrency permit. Dropping the future here could detach a
    // `spawn_blocking` database write and falsely advertise free capacity.
    let Some(request_guard) = security.in_flight.try_begin() else {
        drop(permit);
        return rejection(
            StatusCode::SERVICE_UNAVAILABLE,
            "server_stopping",
            &request_id,
            false,
        );
    };
    let mut request_task = tokio::spawn(async move {
        let _request_guard = request_guard;
        next.run(request).await
    });
    let mut response = match tokio::time::timeout_at(deadline, &mut request_task).await {
        Ok(Ok(response)) => {
            drop(permit);
            response
        }
        Ok(Err(_)) => {
            drop(permit);
            rejection(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_server_error",
                &request_id,
                false,
            )
        }
        Err(_) => {
            tokio::spawn(async move {
                let _permit = permit;
                let _ = request_task.await;
            });
            rejection_with_details(
                StatusCode::GATEWAY_TIMEOUT,
                "request_timeout",
                &request_id,
                false,
                timeout_details,
            )
        }
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    tracing::info!(
        request_id = %request_id,
        method = %method,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis(),
        "MCP HTTP request completed"
    );
    response
}

fn validate_host(
    headers: &HeaderMap,
    allowed_hosts: &[String],
) -> Result<(), (StatusCode, &'static str)> {
    let values = headers.get_all(HOST).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return Err((StatusCode::BAD_REQUEST, "invalid_host"));
    }
    let host = values[0]
        .to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_host"))?
        .trim()
        .to_ascii_lowercase();
    if host.is_empty()
        || host.len() > 255
        || host.contains('/')
        || host.contains('\\')
        || host.contains('@')
        || host.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err((StatusCode::BAD_REQUEST, "invalid_host"));
    }
    if !allowed_hosts.iter().any(|allowed| allowed == &host) {
        return Err((StatusCode::FORBIDDEN, "host_not_allowed"));
    }
    Ok(())
}

fn validate_origin(
    headers: &HeaderMap,
    allowed_origins: &[String],
) -> Result<(), (StatusCode, &'static str)> {
    let values = headers.get_all(ORIGIN).iter().collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(());
    }
    if values.len() != 1 {
        return Err((StatusCode::FORBIDDEN, "origin_not_allowed"));
    }
    let raw = values[0]
        .to_str()
        .map_err(|_| (StatusCode::FORBIDDEN, "origin_not_allowed"))?;
    let normalized =
        normalize_request_origin(raw).ok_or((StatusCode::FORBIDDEN, "origin_not_allowed"))?;
    if !allowed_origins.iter().any(|allowed| allowed == &normalized) {
        return Err((StatusCode::FORBIDDEN, "origin_not_allowed"));
    }
    Ok(())
}

fn validate_authorization(
    headers: &HeaderMap,
    bearer: Option<&crate::config::BearerSecret>,
) -> Result<(), (StatusCode, &'static str)> {
    let Some(bearer) = bearer else {
        return Ok(());
    };
    let values = headers.get_all(AUTHORIZATION).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let header = values[0]
        .to_str()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "unauthorized"))?;
    if !bearer.authorizes(header) {
        return Err((StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(())
}

fn validate_protocol_header(
    headers: &HeaderMap,
    initialize: bool,
) -> Result<(), (StatusCode, &'static str)> {
    let values = headers.get_all(PROTOCOL_HEADER).iter().collect::<Vec<_>>();
    if values.len() > 1 {
        return Err((StatusCode::BAD_REQUEST, "unsupported_protocol_version"));
    }
    if initialize {
        return Ok(());
    }
    let version = values
        .first()
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::BAD_REQUEST, "unsupported_protocol_version"))?;
    if version != STABLE_PROTOCOL_VERSION {
        return Err((StatusCode::BAD_REQUEST, "unsupported_protocol_version"));
    }
    Ok(())
}

fn body_is_initialize(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|method| method == "initialize")
}

fn normalize_initialize_protocol(body: &[u8]) -> Option<Vec<u8>> {
    let mut value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    if value.get("method").and_then(serde_json::Value::as_str) != Some("initialize") {
        return None;
    }
    value.get_mut("params")?.as_object_mut()?.insert(
        "protocolVersion".to_owned(),
        serde_json::Value::String(STABLE_PROTOCOL_VERSION.to_owned()),
    );
    serde_json::to_vec(&value).ok()
}

fn timeout_details(body: &[u8]) -> serde_json::Value {
    let tool_name = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .filter(|value| {
            value.get("method").and_then(serde_json::Value::as_str) == Some("tools/call")
        })
        .and_then(|value| {
            value
                .get("params")
                .and_then(|params| params.get("name"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    if matches!(
        tool_name.as_deref(),
        Some("case_apply_patch" | "document_export")
    ) {
        json!({
            "outcome": "unknown",
            "remediation": "retry_same_idempotency_key",
            "idempotency_key_contract": "reuse the exact original idempotency_key and arguments"
        })
    } else {
        json!({"outcome":"unknown"})
    }
}

fn rejection(
    status: StatusCode,
    code: &'static str,
    request_id: &str,
    authenticate: bool,
) -> Response {
    rejection_with_details(status, code, request_id, authenticate, json!({}))
}

fn rejection_with_details(
    status: StatusCode,
    code: &'static str,
    request_id: &str,
    authenticate: bool,
    details: serde_json::Value,
) -> Response {
    let message = match code {
        "not_found" => "未找到请求的服务。",
        "invalid_host" | "host_not_allowed" | "origin_not_allowed" => "当前访问来源不受允许。",
        "unauthorized" => "请先完成访问授权。",
        "request_body_too_large" => "提交内容超过单次处理上限。",
        "concurrency_limit_exceeded" => "当前请求较多，请稍后重试。",
        "unsupported_protocol_version" => "当前客户端版本不受支持，请更新后重试。",
        "request_timeout" => "本次处理超时，请稍后重试。",
        "server_stopping" => "服务正在停止，请稍后重试。",
        "internal_server_error" => "服务暂时无法完成操作，请稍后重试。",
        _ => "本次请求未能受理。",
    };
    let retryable = matches!(
        code,
        "concurrency_limit_exceeded" | "request_timeout" | "server_stopping"
    );
    let mut response = (
        status,
        Json(json!({
            "schema_version": 1,
            "ok": false,
            "error": {
                "code": code,
                "message": message,
                "retryable": retryable,
                "details": details
            },
            "request_id": request_id,
            "warnings": []
        })),
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        config::{BearerSecret, Command, Limits},
        registry::ToolRegistry,
        service_adapter::ServiceAdapter,
    };
    use axum::{routing::post, Router};
    use legal_services::{LegalServices, ServiceConfig};
    use std::{
        fs,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };
    use tokio::sync::Notify;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    fn security(authenticated: bool) -> HttpSecurity {
        HttpSecurity {
            allowed_origins: Arc::new(vec!["https://client.example".into()]),
            allowed_hosts: Arc::new(vec!["127.0.0.1:8787".into()]),
            bearer: authenticated
                .then(|| BearerSecret::new(Zeroizing::new(vec![b'x'; 32])).unwrap()),
            max_body_bytes: 16 * 1024,
            request_timeout: Duration::from_secs(1),
            concurrency: Arc::new(Semaphore::new(1)),
            in_flight: InFlightOperations::default(),
        }
    }

    fn app(state: HttpSecurity) -> Router {
        Router::new()
            .route(MCP_PATH, post(|| async { StatusCode::OK }))
            .layer(middleware::from_fn_with_state(state, enforce_http_boundary))
    }

    fn request() -> axum::http::request::Builder {
        Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header(HOST, "127.0.0.1:8787")
            .header(PROTOCOL_HEADER, STABLE_PROTOCOL_VERSION)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
    }

    #[tokio::test]
    async fn bearer_and_origin_are_enforced() {
        let state = security(true);
        let response = app(state.clone())
            .oneshot(request().body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app(state.clone())
            .oneshot(
                request()
                    .header(AUTHORIZATION, format!("Bearer {}", "x".repeat(32)))
                    .header(ORIGIN, "https://evil.example")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app(state)
            .oneshot(
                request()
                    .header(AUTHORIZATION, format!("Bearer {}", "x".repeat(32)))
                    .header(ORIGIN, "https://client.example")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn body_concurrency_and_protocol_limits_are_enforced() {
        let state = security(false);
        let response = app(state.clone())
            .oneshot(
                request()
                    .body(Body::from(vec![b'x'; 16 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let permit = Arc::clone(&state.concurrency)
            .acquire_owned()
            .await
            .unwrap();
        let response = app(state.clone())
            .oneshot(request().body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(permit);

        let response = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(MCP_PATH)
                    .header(HOST, "127.0.0.1:8787")
                    .body(Body::from(
                        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn timed_out_write_retains_capacity_until_work_finishes() {
        let mut state = security(false);
        state.request_timeout = Duration::from_millis(80);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_entered = Arc::clone(&entered);
        let handler_release = Arc::clone(&release);
        let handler_calls = Arc::clone(&calls);
        let app = Router::new()
            .route(
                MCP_PATH,
                post(move || {
                    let entered = Arc::clone(&handler_entered);
                    let release = Arc::clone(&handler_release);
                    let call = handler_calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if call == 0 {
                            entered.notify_one();
                            release.notified().await;
                        }
                        StatusCode::OK
                    }
                }),
            )
            .layer(middleware::from_fn_with_state(
                state.clone(),
                enforce_http_boundary,
            ));
        let write_body = Body::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"document_export","arguments":{"idempotency_key":"retry-key-123456"}}}"#,
        );
        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(request().body(write_body).unwrap())
                .await
                .unwrap()
        });
        entered.notified().await;
        let first = first.await.unwrap();
        assert_eq!(first.status(), StatusCode::GATEWAY_TIMEOUT);
        let first_body = to_bytes(first.into_body(), 16 * 1024).await.unwrap();
        let timeout: serde_json::Value = serde_json::from_slice(&first_body).unwrap();
        assert_eq!(timeout["error"]["details"]["outcome"], "unknown");
        assert_eq!(
            timeout["error"]["details"]["remediation"],
            "retry_same_idempotency_key"
        );

        let second = app
            .clone()
            .oneshot(request().body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while state.concurrency.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let third = app
            .oneshot(request().body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(third.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn externally_cancelled_listener_server_releases_its_socket() {
        let temporary = tempfile::tempdir().unwrap();
        let legal_db = temporary.path().join("legal_core.sqlite");
        let user_db = temporary.path().join("user.sqlite");
        let materials = temporary.path().join("materials");
        let output = temporary.path().join("exports");
        fs::write(&legal_db, []).unwrap();
        fs::write(&user_db, []).unwrap();
        fs::create_dir(&materials).unwrap();
        fs::create_dir(&output).unwrap();

        let services = LegalServices::new(ServiceConfig {
            legal_core_path: legal_db.clone(),
            user_database_path: user_db.clone(),
            allowed_file_roots: vec![materials.clone()],
            allowed_output_root: output.clone(),
        })
        .unwrap();
        let server = LegalMcpServer::new(ToolRegistry::new(), ServiceAdapter::new(services));
        let in_flight = server.in_flight_operations();
        let pending_operation = in_flight
            .try_begin()
            .expect("server initially admits an operation");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let config = ResolvedConfig {
            legal_db,
            user_db,
            allowed_roots: vec![materials],
            output_root: output,
            privacy_profile: crate::registry::PrivacyProfile::default(),
            bind: address,
            allowed_origins: Vec::new(),
            allowed_hosts: vec![address.to_string()],
            bearer: None,
            dangerously_allow_insecure_non_loopback_http: false,
            limits: Limits {
                max_body_bytes: 16 * 1024,
                request_timeout: Duration::from_secs(1),
                max_concurrency: 1,
            },
            command: Command::Serve {
                bind: Some(address),
            },
        };
        let cancellation = CancellationToken::new();
        let server_cancellation = cancellation.clone();
        let mut task = tokio::spawn(async move {
            serve_http_on_listener(server, &config, listener, server_cancellation).await
        });

        tokio::task::yield_now().await;
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), async {
            while in_flight.is_accepting() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown closes operation admission");
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut task)
            .await
            .is_err());
        assert!(in_flight.try_begin().is_none());

        drop(pending_operation);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("external cancellation stops the listener server")
            .expect("listener task joins")
            .expect("listener server shuts down cleanly");

        let rebound = tokio::net::TcpListener::bind(address)
            .await
            .expect("cancelled server releases its listener");
        drop(rebound);
    }
}
