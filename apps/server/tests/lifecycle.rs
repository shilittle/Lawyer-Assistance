use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, Response, StatusCode},
    Router,
};
use lawyer_assistance_server::{router, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use workspace_service::Workspace;

const HOST: &str = "127.0.0.1:8877";
const ORIGIN: &str = "http://127.0.0.1:8877";
const BOOTSTRAP: &str = "lifecycle-test-bootstrap";

struct Fixture {
    app: Router,
    shutdown: CancellationToken,
    _root: TempDir,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("temporary workspace");
    let legal_db = root.path().join("legal-not-created.sqlite");
    let workspace = Workspace::open(root.path().to_path_buf(), legal_db).expect("workspace");
    let shutdown = CancellationToken::new();
    let state = AppState::with_shutdown(
        Arc::clone(&workspace),
        ORIGIN.to_owned(),
        BOOTSTRAP.to_owned(),
        shutdown.clone(),
    );
    Fixture {
        _root: root,
        app: router(state),
        shutdown,
    }
}

fn request(
    method: Method,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(csrf) = csrf {
        builder = builder.header("x-csrf-token", csrf);
    }
    builder
        .body(Body::from(serde_json::to_vec(&body).expect("request JSON")))
        .expect("request")
}

async fn send(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.expect("router response")
}

async fn json_body(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("JSON response")
}

async fn login(app: &Router) -> (String, String) {
    let response = send(
        app,
        request(
            Method::POST,
            "/api/v1/session",
            json!({"token": BOOTSTRAP}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .expect("cookie value")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned();
    let body = json_body(response).await;
    let csrf = body["csrf_token"].as_str().expect("csrf token").to_owned();
    (cookie, csrf)
}

#[tokio::test]
async fn shutdown_requires_authenticated_cookie_and_csrf() {
    let fixture = fixture();

    let response = send(
        &fixture.app,
        request(Method::POST, "/api/v1/shutdown", json!({}), None, None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!fixture.shutdown.is_cancelled());

    let (cookie, csrf) = login(&fixture.app).await;
    let response = send(
        &fixture.app,
        request(
            Method::POST,
            "/api/v1/shutdown",
            json!({}),
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!fixture.shutdown.is_cancelled());

    let response = send(
        &fixture.app,
        request(
            Method::POST,
            "/api/v1/shutdown",
            json!({}),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["ok"], true);
    assert!(fixture.shutdown.is_cancelled());
}
