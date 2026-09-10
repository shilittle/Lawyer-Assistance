use axum::{body::to_bytes, http::StatusCode, response::IntoResponse};
use lawyer_assistance_server::ApiError;
use workspace_service::Error;

#[tokio::test]
async fn capacity_and_storage_failures_are_distinguishable_from_bad_input() {
    for (code, expected, retry_after) in [
        ("capacity_exceeded", StatusCode::TOO_MANY_REQUESTS, true),
        ("storage_busy", StatusCode::SERVICE_UNAVAILABLE, true),
        ("storage_full", StatusCode::INSUFFICIENT_STORAGE, false),
        ("storage_failed", StatusCode::INTERNAL_SERVER_ERROR, false),
        ("invalid_request", StatusCode::BAD_REQUEST, false),
        ("revision_conflict", StatusCode::CONFLICT, false),
    ] {
        let response = ApiError(Error::new(code)).into_response();
        assert_eq!(response.status(), expected, "{code}");
        assert_eq!(response.headers().contains_key("retry-after"), retry_after);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], code);
    }
}
