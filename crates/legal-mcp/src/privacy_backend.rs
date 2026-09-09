use async_trait::async_trait;
use reqwest::{header::AUTHORIZATION, redirect::Policy, Client, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    config::{parse_bearer, validate_daemon_url, ClientToken, ConfigError, Limits},
    service_adapter::{
        PrivacyWorkspaceBackend, PrivacyWorkspaceBackendFactory, PrivacyWorkspaceError,
    },
};

const SUBMIT_PATH: &str = "/api/v1/mcp/submit";
const STATUS_PATH: &str = "/api/v1/mcp/status";
const READ_RESULT_PATH: &str = "/api/v1/mcp/read-result";

/// HTTP-only adapter for the local backend. It accepts only literal loopback
/// origins, disables redirects, applies both request and body limits, and
/// intentionally retains no diagnostics from a failed backend response.
pub struct DaemonPrivacyBackend {
    client: Client,
    daemon_url: Url,
    authorization: Zeroizing<String>,
    max_response_bytes: usize,
}

impl std::fmt::Debug for DaemonPrivacyBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DaemonPrivacyBackend")
            .field("daemon_url", &self.daemon_url)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl DaemonPrivacyBackend {
    pub fn from_client_token(
        daemon_url: Url,
        token: ClientToken,
        limits: &Limits,
    ) -> Result<Self, PrivacyWorkspaceError> {
        Self::new(daemon_url, format!("Bearer {}", token.as_str()), limits)
    }

    pub fn from_authorization(
        daemon_url: Url,
        authorization: &str,
        limits: &Limits,
    ) -> Result<Self, PrivacyWorkspaceError> {
        if parse_bearer(authorization).is_none() {
            return Err(PrivacyWorkspaceError::new("unauthorized", false));
        }
        Self::new(daemon_url, authorization.to_owned(), limits)
    }

    fn new(
        daemon_url: Url,
        authorization: String,
        limits: &Limits,
    ) -> Result<Self, PrivacyWorkspaceError> {
        validate_daemon_url(daemon_url.as_str()).map_err(config_error)?;
        let client = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5).min(limits.request_timeout))
            .timeout(limits.request_timeout)
            .build()
            .map_err(|_| PrivacyWorkspaceError::new("privacy_backend_unavailable", true))?;
        Ok(Self {
            client,
            daemon_url,
            authorization: Zeroizing::new(authorization),
            max_response_bytes: limits.max_daemon_response_bytes,
        })
    }

    async fn post(&self, path: &str, payload: Value) -> Result<Value, PrivacyWorkspaceError> {
        let endpoint = self
            .daemon_url
            .join(path)
            .map_err(|_| PrivacyWorkspaceError::new("privacy_backend_unavailable", true))?;
        let mut response = self
            .client
            .post(endpoint)
            .header(AUTHORIZATION, self.authorization.as_str())
            .json(&payload)
            .send()
            .await
            .map_err(|_| PrivacyWorkspaceError::new("daemon_offline", true))?;
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(PrivacyWorkspaceError::new(
                "backend_response_too_large",
                false,
            ));
        }
        let mut body = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|_| PrivacyWorkspaceError::new("privacy_backend_unavailable", true))?;
            let Some(chunk) = chunk else {
                break;
            };
            if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                return Err(PrivacyWorkspaceError::new(
                    "backend_response_too_large",
                    false,
                ));
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(parse_backend_error(status, &body));
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| PrivacyWorkspaceError::new("backend_invalid_response", false))?;
        if let Some(error) = value.get("error") {
            return Err(parse_error_value(error, false));
        }
        Ok(value)
    }
}

#[async_trait]
impl PrivacyWorkspaceBackend for DaemonPrivacyBackend {
    async fn submit(
        &self,
        request_id: String,
        inbox_relative_paths: Vec<String>,
    ) -> Result<Value, PrivacyWorkspaceError> {
        self.post(
            SUBMIT_PATH,
            json!({"request_id":request_id,"inbox_relative_paths":inbox_relative_paths}),
        )
        .await
    }

    async fn status(&self, task_id: String) -> Result<Value, PrivacyWorkspaceError> {
        self.post(STATUS_PATH, json!({"task_id":task_id})).await
    }

    async fn read_result(
        &self,
        result_id: String,
        cursor: Option<String>,
    ) -> Result<Value, PrivacyWorkspaceError> {
        self.post(
            READ_RESULT_PATH,
            json!({"result_id":result_id,"cursor":cursor}),
        )
        .await
    }
}

/// Factory for the embedded Streamable HTTP router. The factory retains only
/// a safe daemon origin and connection limits. It creates a new adapter from
/// the request's bearer header for every tools/call, so one HTTP client cannot
/// accidentally inherit another client's workspace authorization.
#[derive(Debug, Clone)]
pub struct DaemonPrivacyBackendFactory {
    daemon_url: Url,
    limits: Limits,
}

impl DaemonPrivacyBackendFactory {
    pub fn new(daemon_url: Url, limits: Limits) -> Result<Self, PrivacyWorkspaceError> {
        validate_daemon_url(daemon_url.as_str()).map_err(config_error)?;
        Ok(Self { daemon_url, limits })
    }
}

impl PrivacyWorkspaceBackendFactory for DaemonPrivacyBackendFactory {
    fn for_authorization(
        &self,
        authorization: &str,
    ) -> Result<Arc<dyn PrivacyWorkspaceBackend>, PrivacyWorkspaceError> {
        DaemonPrivacyBackend::from_authorization(
            self.daemon_url.clone(),
            authorization,
            &self.limits,
        )
        .map(|backend| Arc::new(backend) as Arc<dyn PrivacyWorkspaceBackend>)
    }
}

#[derive(Debug, Deserialize)]
struct BackendErrorEnvelope {
    code: String,
    #[serde(default)]
    retryable: bool,
}

fn parse_backend_error(status: StatusCode, body: &[u8]) -> PrivacyWorkspaceError {
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        if let Some(error) = value.get("error") {
            return parse_error_value(
                error,
                status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS,
            );
        }
    }
    let (code, retryable) = match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ("unauthorized", false),
        StatusCode::NOT_FOUND => ("not_found", false),
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS => ("daemon_unavailable", true),
        _ if status.is_server_error() => ("daemon_unavailable", true),
        _ => ("backend_rejected", false),
    };
    PrivacyWorkspaceError::new(code, retryable)
}

fn parse_error_value(value: &Value, fallback_retryable: bool) -> PrivacyWorkspaceError {
    let parsed: Result<BackendErrorEnvelope, _> = serde_json::from_value(value.clone());
    match parsed {
        Ok(error) => PrivacyWorkspaceError::new(error.code, error.retryable || fallback_retryable),
        Err(_) => PrivacyWorkspaceError::new("backend_rejected", fallback_retryable),
    }
}

fn config_error(_error: ConfigError) -> PrivacyWorkspaceError {
    PrivacyWorkspaceError::new("invalid_daemon_configuration", false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Limits;

    fn limits() -> Limits {
        Limits {
            max_body_bytes: 16 * 1024,
            request_timeout: Duration::from_secs(2),
            max_concurrency: 1,
            max_daemon_response_bytes: 4096,
        }
    }

    #[test]
    fn rejects_non_loopback_and_malformed_bearers_before_any_connection() {
        let url = Url::parse("http://127.0.0.1:8877").expect("URL");
        assert!(
            DaemonPrivacyBackend::from_authorization(url.clone(), "Basic token", &limits())
                .is_err()
        );
        assert!(DaemonPrivacyBackendFactory::new(
            Url::parse("http://example.com:8877").expect("URL"),
            limits()
        )
        .is_err());
        assert!(DaemonPrivacyBackend::from_authorization(
            url,
            "Bearer 0123456789abcdef0123456789abcdef",
            &limits()
        )
        .is_ok());
    }

    #[test]
    fn backend_error_drops_messages_and_unknown_shapes() {
        let error = parse_backend_error(
            StatusCode::BAD_REQUEST,
            br#"{"error":{"code":"path_changed","retryable":false,"message":"C:\\secret"}}"#,
        );
        assert_eq!(error.code(), "path_changed");
        let malformed = parse_backend_error(StatusCode::BAD_REQUEST, b"C:\\secret");
        assert_eq!(malformed.code(), "backend_rejected");
    }

    #[tokio::test]
    async fn offline_daemon_returns_only_a_generic_retryable_code() {
        // Reserving then dropping this listener guarantees a loopback port
        // with no daemon, without relying on a conventional fixed port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve a loopback port");
        let address = listener.local_addr().expect("listener address");
        drop(listener);

        let token = "x".repeat(32);
        let backend = DaemonPrivacyBackend::from_authorization(
            Url::parse(&format!("http://{address}")).expect("loopback URL"),
            &format!("Bearer {token}"),
            &limits(),
        )
        .expect("backend configuration");
        let error = backend
            .status("task_1".to_owned())
            .await
            .expect_err("offline");

        assert_eq!(error.code(), "daemon_offline");
        assert!(error.retryable());
        assert!(!format!("{error:?}").contains(&token));
        assert!(!format!("{error:?}").contains("127.0.0.1"));
    }
}
