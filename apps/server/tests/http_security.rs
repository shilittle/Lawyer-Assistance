use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderValue, Method, Request, Response, StatusCode},
    Router,
};
use lawyer_assistance_server::{router, AppState};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tempfile::TempDir;
use tower::ServiceExt;
use workspace_service::Workspace;

const HOST: &str = "127.0.0.1:8877";
const ORIGIN: &str = "http://127.0.0.1:8877";
const BOOTSTRAP: &str = "http-security-test-bootstrap";

#[tokio::test]
async fn judicial_case_routes_keep_auth_csrf_and_missing_corpus_boundaries() {
    let fixture = fixture();
    for path in [
        "/api/v1/legal/cases?query=test",
        "/api/v1/legal/cases/status",
        "/api/v1/legal/cases/spc-guiding-1",
    ] {
        let response = send(&fixture.app, request(Method::GET, path, Body::empty())).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let (cookie, csrf) = login(&fixture.app).await;
    let status = send(
        &fixture.app,
        json_request(
            Method::GET,
            "/api/v1/legal/cases/status",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(json_body(status).await["available"], false);
    let response = send(
        &fixture.app,
        json_request(
            Method::GET,
            "/api/v1/legal/cases?query=test",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(body["error"]["code"], "judicial_case_database_missing");
    assert!(!body.to_string().contains("sqlite"));
    let input =
        json!({"query":"劳动关系认定", "provider_id":"provider_test", "model":"test-model"});
    let response = send(
        &fixture.app,
        json_request(
            Method::POST,
            "/api/v1/legal/cases/understand",
            input.clone(),
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = send(
        &fixture.app,
        json_request(
            Method::POST,
            "/api/v1/legal/cases/understand",
            input,
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"]["code"],
        "judicial_case_database_missing"
    );
}

struct Fixture {
    app: Router,
    workspace: Arc<Workspace>,
    _root: TempDir,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("temporary workspace");
    let legal_db = root.path().join("legal-not-created.sqlite");
    let workspace =
        Workspace::open(root.path().to_path_buf(), legal_db).expect("open temporary workspace");
    let state = AppState::new(workspace.clone(), ORIGIN.to_owned(), BOOTSTRAP.to_owned());
    Fixture {
        _root: root,
        app: router(state),
        workspace,
    }
}

fn request(method: Method, path: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST)
        .body(body)
        .expect("build request")
}

fn json_request(
    method: Method,
    path: &str,
    value: Value,
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
        .body(Body::from(
            serde_json::to_vec(&value).expect("json request"),
        ))
        .expect("build json request")
}

fn bearer_json_request(path: &str, value: Value, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&value).expect("json request"),
        ))
        .expect("build bearer request")
}

fn multipart_request(
    path: &str,
    boundary: &str,
    fields: &[(&str, &str)],
    filename: &str,
    content: &str,
    cookie: &str,
    csrf: &str,
) -> Request<Body> {
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\nContent-Type: text/plain\r\n\r\n{content}\r\n--{boundary}--\r\n"));
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::HOST, HOST)
        .header(header::COOKIE, cookie)
        .header("x-csrf-token", csrf)
        .header(
            header::CONTENT_TYPE,
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .expect("build multipart request")
}

async fn send(app: &Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.expect("router response")
}

async fn json_body(response: Response<Body>) -> Value {
    let bytes = to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .expect("read response");
    serde_json::from_slice(&bytes).expect("json response")
}

async fn login(app: &Router) -> (String, String) {
    let response = send(
        app,
        json_request(
            Method::POST,
            "/api/v1/session",
            json!({"token": BOOTSTRAP}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("session cookie")
        .to_str()
        .expect("cookie header");
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let cookie = set_cookie
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned();
    let body = json_body(response).await;
    let csrf = body["csrf_token"].as_str().expect("csrf token").to_owned();
    (cookie, csrf)
}

async fn poll_task(app: &Router, cookie: &str, csrf: &str, task_id: &str) -> Value {
    for _ in 0..120 {
        let response = send(
            app,
            json_request(
                Method::GET,
                &format!("/api/v1/tasks/{task_id}"),
                Value::Null,
                Some(cookie),
                Some(csrf),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let status = body["status"].as_str().unwrap_or_default();
        if matches!(
            status,
            "ready" | "needs_review" | "awaiting_consent" | "partial" | "failed" | "cancelled"
        ) {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("temporary HTTP task did not settle");
}

#[tokio::test]
async fn http_security_requires_local_host_session_and_csrf() {
    let fixture = fixture();

    let wrong_host = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/session")
        .header(header::HOST, "evil.example")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"token":"http-security-test-bootstrap"}"#))
        .expect("wrong host request");
    let response = send(&fixture.app, wrong_host).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let mut wrong_origin = json_request(
        Method::POST,
        "/api/v1/session",
        json!({"token": BOOTSTRAP}),
        None,
        None,
    );
    wrong_origin.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("http://evil.example"),
    );
    let response = send(&fixture.app, wrong_origin).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = send(
        &fixture.app,
        request(Method::GET, "/api/v1/health", Body::empty()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (cookie, csrf) = login(&fixture.app).await;
    let response = send(
        &fixture.app,
        json_request(
            Method::GET,
            "/api/v1/health",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    let health = json_body(response).await;
    assert_eq!(health["ocr"]["available"], false);

    let response = send(
        &fixture.app,
        json_request(
            Method::POST,
            "/api/v1/groups",
            json!({"name":"csrf missing"}),
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = send(
        &fixture.app,
        json_request(
            Method::POST,
            "/api/v1/groups",
            json!({"name":"security group"}),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let group = json_body(response).await;
    assert!(group["id"].as_str().is_some());

    let response = send(
        &fixture.app,
        json_request(
            Method::GET,
            "/api/v1/session",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["authenticated"], true);
}

#[tokio::test]
async fn http_business_flow_redacts_replaces_exports_and_configures_mcp() {
    let fixture = fixture();
    let worker = fixture.workspace.start_worker();
    let (cookie, csrf) = login(&fixture.app).await;

    let response = send(
        &fixture.app,
        json_request(
            Method::POST,
            "/api/v1/groups",
            json!({"name":"HTTP acceptance group"}),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let group_id = json_body(response).await["id"]
        .as_str()
        .expect("group id")
        .to_owned();

    let source = "请在联系时使用号码 13800138000。";
    let import = send(
        &fixture.app,
        multipart_request(
            "/api/v1/imports",
            "http-security-import",
            &[
                ("group_id", &group_id),
                ("request_id", "http-security-import-1"),
            ],
            "case.txt",
            source,
            &cookie,
            &csrf,
        ),
    )
    .await;
    assert_eq!(import.status(), StatusCode::OK);
    let import_body = json_body(import).await;
    let task_id = import_body["id"].as_str().expect("task id").to_owned();
    let material_id = import_body["materials"][0]["id"]
        .as_str()
        .expect("material id")
        .to_owned();
    let task = poll_task(&fixture.app, &cookie, &csrf, &task_id).await;
    assert_eq!(task["status"], "ready");
    let material_response = send(
        &fixture.app,
        json_request(
            Method::GET,
            &format!("/api/v1/materials/{material_id}"),
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(material_response.status(), StatusCode::OK);
    let material = json_body(material_response).await;
    assert_eq!(material["status"], "ready");
    assert_eq!(material["analysis"]["needsReview"], false);
    assert!(material["analysis"]["outputSha256"].as_str().is_some());
    let old_result = material["result_id"]
        .as_str()
        .expect("ready result")
        .to_owned();
    let old_revision = material["revision"].as_u64().expect("revision");

    let exported = send(&fixture.app, {
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/results/{old_result}/export?format=txt"))
            .header(header::HOST, HOST)
            .header(header::COOKIE, &cookie);
        request.body(Body::empty()).expect("export request")
    })
    .await;
    assert_eq!(exported.status(), StatusCode::OK);
    assert_eq!(
        exported
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );

    let replacement = "请改用号码 13900139000。";
    let replacement_revision = old_revision.to_string();
    let replaced = send(
        &fixture.app,
        multipart_request(
            &format!("/api/v1/materials/{material_id}/replace"),
            "http-security-replace",
            &[
                ("revision", replacement_revision.as_str()),
                ("encoding", "utf-8"),
            ],
            "replacement.txt",
            replacement,
            &cookie,
            &csrf,
        ),
    )
    .await;
    assert_eq!(replaced.status(), StatusCode::OK);
    let replaced_body = json_body(replaced).await;
    assert_eq!(replaced_body["id"].as_str(), Some(material_id.as_str()));
    assert!(replaced_body["revision"].as_u64().expect("new revision") > old_revision);

    let revoked = send(&fixture.app, {
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("/api/v1/results/{old_result}/export?format=txt"))
            .header(header::HOST, HOST)
            .header(header::COOKIE, &cookie);
        request.body(Body::empty()).expect("revoked export request")
    })
    .await;
    assert_eq!(revoked.status(), StatusCode::BAD_REQUEST);
    let revoked_body = json_body(revoked).await;
    assert_eq!(revoked_body["error"]["code"], "result_revoked");

    let replacement_task = replaced_body["task_id"]
        .as_str()
        .expect("replacement task id");
    let replacement_task_body = poll_task(&fixture.app, &cookie, &csrf, replacement_task).await;
    assert_eq!(replacement_task_body["status"], "ready");
    let replacement_material = send(
        &fixture.app,
        json_request(
            Method::GET,
            &format!("/api/v1/materials/{material_id}"),
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(replacement_material.status(), StatusCode::OK);
    let replacement_material_body = json_body(replacement_material).await;
    let replacement_result = replacement_material_body["result_id"]
        .as_str()
        .expect("replacement result")
        .to_owned();

    let templates = send(
        &fixture.app,
        json_request(
            Method::GET,
            "/api/v1/templates",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(templates.status(), StatusCode::OK);
    let templates_body = json_body(templates).await;
    assert_eq!(
        templates_body["templates"].as_array().map(Vec::len),
        Some(6)
    );
    let template_input = json!({
        "template_id":"complaint",
        "input":{"title":"测试文书","party_a":"甲方","party_b":"乙方","facts":"事实经过","requests":"请求事项","evidence":"证据一","requirements":"复核要求"}
    });
    let preview = send(
        &fixture.app,
        json_request(
            Method::POST,
            "/api/v1/templates/preview",
            template_input.clone(),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(preview.status(), StatusCode::OK);
    assert!(json_body(preview).await["text"].as_str().is_some());
    let exported_template = send(
        &fixture.app,
        json_request(
            Method::POST,
            "/api/v1/templates/export",
            json!({"template_id":"complaint","input":template_input["input"],"format":"md"}),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(exported_template.status(), StatusCode::OK);
    assert!(exported_template
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .starts_with("text/markdown"));

    let client = send(
        &fixture.app,
        json_request(
            Method::POST,
            "/api/v1/mcp/clients",
            json!({"name":"HTTP smoke client","group_id":group_id}),
            Some(&cookie),
            Some(&csrf),
        ),
    )
    .await;
    assert_eq!(client.status(), StatusCode::OK);
    let client_body = json_body(client).await;
    let client_id = client_body["client"]["id"]
        .as_str()
        .expect("client id")
        .to_owned();
    let client_token = client_body["token"]
        .as_str()
        .expect("one-time client token")
        .to_owned();
    assert!(client_token.len() >= 32);
    let mcp_read = send(
        &fixture.app,
        bearer_json_request(
            "/api/v1/mcp/read-result",
            json!({"result_id":replacement_result}),
            &client_token,
        ),
    )
    .await;
    assert_eq!(mcp_read.status(), StatusCode::OK);
    assert_eq!(
        mcp_read
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let mcp_read_body = json_body(mcp_read).await;
    assert!(!mcp_read_body["text"]
        .as_str()
        .unwrap_or_default()
        .contains("13900139000"));
    let clients = send(
        &fixture.app,
        json_request(
            Method::GET,
            "/api/v1/mcp/clients",
            Value::Null,
            Some(&cookie),
            None,
        ),
    )
    .await;
    assert_eq!(clients.status(), StatusCode::OK);
    let clients_bytes = to_bytes(clients.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read clients");
    assert!(!String::from_utf8_lossy(&clients_bytes).contains(client_token.as_str()));

    let revoke = send(&fixture.app, {
        let request = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/api/v1/mcp/clients/{client_id}"))
            .header(header::HOST, HOST)
            .header(header::COOKIE, &cookie)
            .header("x-csrf-token", &csrf);
        request.body(Body::empty()).expect("revoke client request")
    })
    .await;
    assert_eq!(revoke.status(), StatusCode::OK);
    let revoked_mcp = send(
        &fixture.app,
        bearer_json_request(
            "/api/v1/mcp/read-result",
            json!({"result_id":replacement_result}),
            &client_token,
        ),
    )
    .await;
    assert_eq!(revoked_mcp.status(), StatusCode::UNAUTHORIZED);
    worker.abort();
}
