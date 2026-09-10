//! Actual HTTP routes, DPAPI storage, optimistic concurrency and restart tests.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use lawyer_assistance_server::{router, AppState};
use serde_json::{json, Value};
use std::path::Path;
use tower::ServiceExt;
use workspace_service::Workspace;

fn app(root: &Path) -> Router {
    let workspace = Workspace::open(root.to_path_buf(), root.join("missing-legal.sqlite")).unwrap();
    router(AppState::new(
        workspace,
        "http://127.0.0.1:8877".into(),
        "audit-bootstrap".into(),
    ))
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Value,
    auth: Option<&(String, String)>,
) -> (StatusCode, Value, String) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "127.0.0.1:8877")
        .header("content-type", "application/json");
    if let Some((cookie, csrf)) = auth {
        request = request
            .header("cookie", cookie)
            .header("x-csrf-token", csrf);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .to_owned();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap(), cookie)
}

async fn login(app: &Router) -> (String, String) {
    let (status, body, cookie) = call(
        app,
        "POST",
        "/api/v1/session",
        json!({"token":"audit-bootstrap"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (cookie, body["csrf_token"].as_str().unwrap().to_owned())
}

#[tokio::test]
async fn ai_search_rejects_invalid_visible_scope_before_provider_access() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let auth = login(&app).await;
    for invalid in [
        json!({"case_date":"2026-02-30"}),
        json!({"version_scope":"as_of"}),
        json!({"version_scope":"current","case_date":"2019-12-31"}),
        json!({"version_scope":"all","case_date":"2019-12-31"}),
        json!({"match_mode":"unbounded"}),
    ] {
        let mut request = json!({"kind":"search","prompt":"仅合成测试"});
        request
            .as_object_mut()
            .unwrap()
            .extend(invalid.as_object().unwrap().clone());
        let (status, body, _) = call(&app, "POST", "/api/v1/ai/runs", request, Some(&auth)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], "invalid_search_request");
    }
}

#[tokio::test]
async fn old_versionless_writes_return_an_actionable_revision_error() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let auth = login(&app).await;
    for (method, uri, value) in [
        (
            "PUT",
            "/api/v1/ai/runs/missing/content",
            json!({"content":"synthetic edit"}),
        ),
        (
            "POST",
            "/api/v1/ai/runs/missing/citations/recheck",
            json!({}),
        ),
        (
            "PUT",
            "/api/v1/ai/drafts/writing-current",
            json!({"content":{}}),
        ),
        (
            "PUT",
            "/api/v1/ai/conversations/missing/context",
            json!({"materials":[],"attachment_ids":[]}),
        ),
        (
            "POST",
            "/api/v1/ai/conversations/missing/context/prepare",
            json!({}),
        ),
    ] {
        let (status, body, _) = call(&app, method, uri, value, Some(&auth)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(body["error"]["code"], "revision_required", "{uri}");
    }
}

#[tokio::test]
async fn summary_http_pages_cover_all_rows_without_repeating_private_bodies() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let auth = login(&app).await;
    let mut expected = std::collections::BTreeSet::new();
    for n in 0..7 {
        let (status, body, _) = call(
            &app,
            "POST",
            "/api/v1/ai/conversations",
            json!({"title":format!("合成会话 {n}")}),
            Some(&auth),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        expected.insert(body["id"].as_str().unwrap().to_owned());
    }
    let mut actual = std::collections::BTreeSet::new();
    let mut cursor = None::<String>;
    loop {
        let uri = format!(
            "/api/v1/ai/conversations?limit=2{}",
            cursor
                .as_ref()
                .map(|v| format!("&cursor={v}"))
                .unwrap_or_default()
        );
        let (status, body, _) = call(&app, "GET", &uri, Value::Null, Some(&auth)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 7);
        assert_eq!(body["corrupt_count"], 0);
        let rows = body["conversations"].as_array().unwrap();
        assert!(rows.len() <= 2);
        for row in rows {
            assert!(row.get("messages").is_none());
            assert!(actual.insert(row["id"].as_str().unwrap().to_owned()));
        }
        cursor = body["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(actual, expected);
    for route in [
        "/api/v1/ai/conversations?limit=0",
        "/api/v1/ai/materials?limit=101",
        "/api/v1/ai/runs?cursor=bad",
    ] {
        let (status, body, _) = call(&app, "GET", route, Value::Null, Some(&auth)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "invalid_pagination");
    }
}

#[tokio::test]
async fn draft_http_preserves_encryption_and_revision_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let first = app(dir.path());
    let route = "/api/v1/ai/drafts/writing";
    let (status, _, _) = call(&first, "GET", route, Value::Null, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let auth = login(&first).await;
    let content = json!({"prompt":"audit-confidential-draft-9f45", "requirements":"保留日期金额", "document_type":"起诉状", "materials":[],"attachment_ids":[]});
    let payload = json!({"expected_revision":0,"content":content});
    let no_csrf = (auth.0.clone(), String::new());
    assert_eq!(
        call(&first, "PUT", route, payload.clone(), Some(&no_csrf))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, saved, _) = call(&first, "PUT", route, payload.clone(), Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["revision"], 1);
    assert_eq!(
        call(&first, "PUT", route, payload, Some(&auth)).await.0,
        StatusCode::CONFLICT
    );
    let (_, loaded, _) = call(&first, "GET", route, Value::Null, Some(&auth)).await;
    assert_eq!(loaded["content"]["prompt"], content["prompt"]);
    drop(first);

    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            let bytes = std::fs::read(entry.path()).unwrap();
            assert!(!bytes
                .windows(b"audit-confidential-draft-9f45".len())
                .any(|s| s == b"audit-confidential-draft-9f45"));
        }
    }
    let restarted = app(dir.path());
    let auth = login(&restarted).await;
    let (status, restored, _) = call(&restarted, "GET", route, Value::Null, Some(&auth)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restored["content"]["prompt"], content["prompt"]);
    let payload = json!({"expected_revision":1,"content":content});
    let (a, b) = tokio::join!(
        call(&restarted, "PUT", route, payload.clone(), Some(&auth)),
        call(&restarted, "PUT", route, payload, Some(&auth))
    );
    assert!(
        (a.0 == StatusCode::OK && b.0 == StatusCode::CONFLICT)
            || (b.0 == StatusCode::OK && a.0 == StatusCode::CONFLICT)
    );
    assert_eq!(
        call(
            &restarted,
            "DELETE",
            "/api/v1/ai/drafts/writing?expected_revision=1",
            Value::Null,
            Some(&auth)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &restarted,
            "DELETE",
            "/api/v1/ai/drafts/writing?expected_revision=2",
            Value::Null,
            Some(&auth)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&restarted, "GET", route, Value::Null, Some(&auth))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn context_http_requires_revision_and_persists_explicit_empty_selection() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(dir.path());
    let auth = login(&app).await;
    let (status, conversation, _) = call(
        &app,
        "POST",
        "/api/v1/ai/conversations",
        json!({"title":"审查回归会话"}),
        Some(&auth),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id = conversation["id"].as_str().unwrap();
    let route = format!("/api/v1/ai/conversations/{id}/context");
    let revision = conversation["context_revision"].as_u64().unwrap_or(0);
    assert_eq!(
        call(
            &app,
            "PUT",
            &route,
            json!({"materials":[],"attachment_ids":[]}),
            Some(&auth)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let payload = json!({"expected_revision":revision,"materials":[],"attachment_ids":[]});
    let (status, value, _) = call(&app, "PUT", &route, payload.clone(), Some(&auth)).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(
        call(&app, "PUT", &route, payload, Some(&auth)).await.0,
        StatusCode::CONFLICT
    );
    let (_, value, _) = call(
        &app,
        "GET",
        &format!("/api/v1/ai/conversations/{id}"),
        Value::Null,
        Some(&auth),
    )
    .await;
    assert_eq!(value["materials"], json!([]));
    assert_eq!(value["attachment_ids"], json!([]));
}
