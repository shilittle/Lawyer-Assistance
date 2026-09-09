use async_trait::async_trait;
use legal_services::{LegalServices, ServiceError, SERVICE_SCHEMA_VERSION};
use rmcp::{
    model::{CallToolResult, ContentBlock, ErrorCode, JsonObject},
    ErrorData,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

use crate::{
    privacy_gate, public_output,
    registry::{PrivacyProfile, PRIVACY_WORKSPACE_TOOL_NAMES},
};

const MAX_TOOL_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// The only private-workspace boundary exposed to MCP. Implementations receive
/// no LegalServices handle and therefore cannot open the application's private
/// database themselves.
#[async_trait]
pub trait PrivacyWorkspaceBackend: Send + Sync {
    async fn submit(
        &self,
        request_id: String,
        inbox_relative_paths: Vec<String>,
    ) -> Result<Value, PrivacyWorkspaceError>;

    async fn status(&self, task_id: String) -> Result<Value, PrivacyWorkspaceError>;

    async fn read_result(
        &self,
        result_id: String,
        cursor: Option<String>,
    ) -> Result<Value, PrivacyWorkspaceError>;
}

/// Creates a request-scoped private backend from an incoming HTTP bearer
/// header. Implementations must not retain the raw header after returning the
/// backend; `DaemonPrivacyBackendFactory` follows that rule.
pub trait PrivacyWorkspaceBackendFactory: Send + Sync {
    fn for_authorization(
        &self,
        authorization: &str,
    ) -> Result<Arc<dyn PrivacyWorkspaceBackend>, PrivacyWorkspaceError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyWorkspaceError {
    code: String,
    retryable: bool,
}

impl PrivacyWorkspaceError {
    pub fn new(code: impl AsRef<str>, retryable: bool) -> Self {
        let code = code.as_ref();
        let code = if is_safe_error_code(code) {
            code.to_owned()
        } else {
            "backend_rejected".to_owned()
        };
        Self { code, retryable }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub const fn retryable(&self) -> bool {
        self.retryable
    }
}

#[derive(Debug)]
struct InFlightState {
    accepting: bool,
    active: usize,
}

#[derive(Debug)]
struct InFlightInner {
    state: Mutex<InFlightState>,
    idle: Notify,
}

/// Tracks work that may outlive an HTTP request. The HTTP router closes this
/// gate before shutdown so it never reports completion while a database query
/// is still running in a blocking worker.
#[derive(Debug, Clone)]
pub(crate) struct InFlightOperations {
    inner: Arc<InFlightInner>,
}

impl Default for InFlightOperations {
    fn default() -> Self {
        Self {
            inner: Arc::new(InFlightInner {
                state: Mutex::new(InFlightState {
                    accepting: true,
                    active: 0,
                }),
                idle: Notify::new(),
            }),
        }
    }
}

impl InFlightOperations {
    pub(crate) fn try_begin(&self) -> Option<InFlightGuard> {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting {
            return None;
        }
        state.active = state.active.saturating_add(1);
        Some(InFlightGuard {
            inner: Arc::clone(&self.inner),
        })
    }

    pub(crate) async fn close_and_wait(&self) {
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.accepting = false;
        }
        loop {
            let idle = self.inner.idle.notified();
            tokio::pin!(idle);
            idle.as_mut().enable();
            if self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .active
                == 0
            {
                return;
            }
            idle.await;
        }
    }
}

#[derive(Debug)]
pub(crate) struct InFlightGuard {
    inner: Arc<InFlightInner>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let became_idle = {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.active = state.active.saturating_sub(1);
            state.active == 0
        };
        if became_idle {
            self.inner.idle.notify_waiters();
        }
    }
}

#[derive(Clone)]
pub struct ServiceAdapter {
    services: Arc<LegalServices>,
    profile: PrivacyProfile,
    static_privacy_backend: Option<Arc<dyn PrivacyWorkspaceBackend>>,
    request_backend_factory: Option<Arc<dyn PrivacyWorkspaceBackendFactory>>,
    in_flight: InFlightOperations,
}

impl std::fmt::Debug for ServiceAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceAdapter")
            .field("profile", &self.profile)
            .field(
                "static_privacy_backend",
                &self.static_privacy_backend.is_some(),
            )
            .field(
                "request_backend_factory",
                &self.request_backend_factory.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl ServiceAdapter {
    pub fn new(services: LegalServices) -> Self {
        Self::for_profile(services, PrivacyProfile::PublicLawOnly)
    }

    pub fn for_profile(services: LegalServices, profile: PrivacyProfile) -> Self {
        Self {
            services: Arc::new(services),
            profile,
            static_privacy_backend: None,
            request_backend_factory: None,
            in_flight: InFlightOperations::default(),
        }
    }

    pub fn for_privacy_workspace(
        services: LegalServices,
        backend: Arc<dyn PrivacyWorkspaceBackend>,
    ) -> Self {
        Self {
            services: Arc::new(services),
            profile: PrivacyProfile::PrivacyWorkspace,
            static_privacy_backend: Some(backend),
            request_backend_factory: None,
            in_flight: InFlightOperations::default(),
        }
    }

    pub fn for_privacy_workspace_proxy(
        services: LegalServices,
        backend_factory: Arc<dyn PrivacyWorkspaceBackendFactory>,
    ) -> Self {
        Self {
            services: Arc::new(services),
            profile: PrivacyProfile::PrivacyWorkspace,
            static_privacy_backend: None,
            request_backend_factory: Some(backend_factory),
            in_flight: InFlightOperations::default(),
        }
    }

    pub(crate) fn in_flight_operations(&self) -> InFlightOperations {
        self.in_flight.clone()
    }

    pub async fn call(
        &self,
        tool_name: &str,
        arguments: Option<JsonObject>,
    ) -> Result<CallToolResult, ErrorData> {
        self.call_with_request_id(tool_name, arguments, None).await
    }

    pub(crate) async fn call_with_request_id(
        &self,
        tool_name: &str,
        arguments: Option<JsonObject>,
        authorization: Option<&str>,
    ) -> Result<CallToolResult, ErrorData> {
        if !self.profile.allows_tool(tool_name) {
            return Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "未识别的功能请求。",
                None,
            ));
        }
        let arguments = arguments.unwrap_or_default();
        match tool_name {
            "system_status" => self.system_status(arguments).await,
            "legal_search" => {
                self.invoke("legal_search", arguments, |services, request| {
                    services.legal_search(request)
                })
                .await
            }
            "legal_get_article" => {
                self.invoke("legal_get_article", arguments, |services, request| {
                    services.legal_get_article(request)
                })
                .await
            }
            "legal_get_versions" => {
                self.invoke("legal_get_versions", arguments, |services, request| {
                    services.legal_get_versions(request)
                })
                .await
            }
            "legal_get_relations" => {
                self.invoke("legal_get_relations", arguments, |services, request| {
                    services.legal_get_relations(request)
                })
                .await
            }
            name if PRIVACY_WORKSPACE_TOOL_NAMES.contains(&name) => {
                self.privacy_call(name, arguments, authorization).await
            }
            _ => Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "未识别的功能请求。",
                None,
            )),
        }
    }

    async fn system_status(&self, arguments: JsonObject) -> Result<CallToolResult, ErrorData> {
        let input: StatusInput = match decode(arguments) {
            Ok(input) => input,
            Err(error) => return Ok(public_error("system_status", error)),
        };
        if input.schema_version != SERVICE_SCHEMA_VERSION {
            return Ok(public_error(
                "system_status",
                ServiceError::new("unsupported_schema_version", "unsupported schema", false),
            ));
        }
        let services = Arc::clone(&self.services);
        let operation = self.begin_blocking_operation()?;
        let result = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            services.system_status()
        })
        .await
        .map_err(|_| internal_error())?;
        match result {
            Ok(response) => public_success("system_status", response),
            Err(error) => Ok(public_error("system_status", error)),
        }
    }

    async fn invoke<Request, Response, Invoke>(
        &self,
        tool_name: &str,
        arguments: JsonObject,
        invoke: Invoke,
    ) -> Result<CallToolResult, ErrorData>
    where
        Request: DeserializeOwned + Send + 'static,
        Response: Serialize + Send + 'static,
        Invoke: FnOnce(&LegalServices, Request) -> Result<Response, ServiceError> + Send + 'static,
    {
        let request: Request = match decode(arguments) {
            Ok(request) => request,
            Err(error) => return Ok(public_error(tool_name, error)),
        };
        let services = Arc::clone(&self.services);
        let operation = self.begin_blocking_operation()?;
        let result = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            invoke(&services, request)
        })
        .await
        .map_err(|_| internal_error())?;
        match result {
            Ok(response) => public_success(tool_name, response),
            Err(error) => Ok(public_error(tool_name, error)),
        }
    }

    async fn privacy_call(
        &self,
        tool_name: &str,
        arguments: JsonObject,
        authorization: Option<&str>,
    ) -> Result<CallToolResult, ErrorData> {
        let backend = match self.privacy_backend(authorization) {
            Ok(backend) => backend,
            Err(error) => return Ok(privacy_error(error)),
        };
        let result = match tool_name {
            "privacy_workspace.submit" => {
                let input: PrivacySubmitInput = match decode_plain(arguments) {
                    Ok(input) => input,
                    Err(_) => {
                        return Ok(privacy_error(PrivacyWorkspaceError::new(
                            "invalid_request",
                            false,
                        )))
                    }
                };
                if !valid_request_id(&input.request_id)
                    || input.inbox_relative_paths.is_empty()
                    || input.inbox_relative_paths.len() > 100
                    || input
                        .inbox_relative_paths
                        .iter()
                        .any(|path| !valid_relative_path(path))
                {
                    return Ok(privacy_error(PrivacyWorkspaceError::new(
                        "invalid_request",
                        false,
                    )));
                }
                backend
                    .submit(input.request_id, input.inbox_relative_paths)
                    .await
            }
            "privacy_workspace.status" => {
                let input: PrivacyStatusInput = match decode_plain(arguments) {
                    Ok(input) => input,
                    Err(_) => {
                        return Ok(privacy_error(PrivacyWorkspaceError::new(
                            "invalid_request",
                            false,
                        )))
                    }
                };
                if !valid_identifier(&input.task_id) {
                    return Ok(privacy_error(PrivacyWorkspaceError::new(
                        "invalid_request",
                        false,
                    )));
                }
                backend.status(input.task_id).await
            }
            "privacy_workspace.read_result" => {
                let input: PrivacyReadResultInput = match decode_plain(arguments) {
                    Ok(input) => input,
                    Err(_) => {
                        return Ok(privacy_error(PrivacyWorkspaceError::new(
                            "invalid_request",
                            false,
                        )))
                    }
                };
                if !valid_identifier(&input.result_id)
                    || input
                        .cursor
                        .as_deref()
                        .is_some_and(|cursor| cursor.is_empty() || cursor.len() > 2048)
                {
                    return Ok(privacy_error(PrivacyWorkspaceError::new(
                        "invalid_request",
                        false,
                    )));
                }
                backend.read_result(input.result_id, input.cursor).await
            }
            _ => return Err(internal_error()),
        };
        match result {
            Ok(value) => Ok(privacy_success(value)),
            Err(error) => Ok(privacy_error(error)),
        }
    }

    fn privacy_backend(
        &self,
        authorization: Option<&str>,
    ) -> Result<Arc<dyn PrivacyWorkspaceBackend>, PrivacyWorkspaceError> {
        if let Some(backend) = &self.static_privacy_backend {
            return Ok(Arc::clone(backend));
        }
        let Some(factory) = &self.request_backend_factory else {
            return Err(PrivacyWorkspaceError::new(
                "privacy_backend_unavailable",
                true,
            ));
        };
        let Some(authorization) = authorization else {
            return Err(PrivacyWorkspaceError::new("unauthorized", false));
        };
        factory.for_authorization(authorization)
    }

    fn begin_blocking_operation(&self) -> Result<InFlightGuard, ErrorData> {
        self.in_flight.try_begin().ok_or_else(internal_error)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusInput {
    schema_version: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacySubmitInput {
    request_id: String,
    inbox_relative_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacyStatusInput {
    task_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacyReadResultInput {
    result_id: String,
    #[serde(default)]
    cursor: Option<String>,
}

fn decode<T: DeserializeOwned>(arguments: JsonObject) -> Result<T, ServiceError> {
    let value = convert_object_keys(Value::Object(arguments), snake_to_camel);
    serde_json::from_value(value).map_err(|_| {
        ServiceError::new(
            "invalid_request",
            "tool arguments do not match the declared schema",
            false,
        )
    })
}

fn decode_plain<T: DeserializeOwned>(arguments: JsonObject) -> Result<T, ()> {
    serde_json::from_value(Value::Object(arguments)).map_err(|_| ())
}

fn public_success<T: Serialize>(tool_name: &str, response: T) -> Result<CallToolResult, ErrorData> {
    let data = serde_json::to_value(response).map_err(|_| internal_error())?;
    let data = convert_object_keys(data, camel_to_snake);
    let public_text = public_output::success_text(tool_name, &data);
    let public_data = public_output::success_structured_content(tool_name, &data, &public_text);
    if !privacy_gate::model_visible_output_is_safe(&public_text, &public_data)
        || serialized_len(&public_data) > MAX_TOOL_ENVELOPE_BYTES
    {
        return Ok(public_error(
            tool_name,
            ServiceError::new(
                "sensitive_content_blocked",
                "privacy boundary blocked result",
                false,
            ),
        ));
    }
    let mut result = CallToolResult::structured(public_data);
    result.content = vec![ContentBlock::text(public_text)];
    Ok(result)
}

fn public_error(tool_name: &str, error: ServiceError) -> CallToolResult {
    tracing::warn!(tool = tool_name, error_code = %error.code, "public MCP tool failed");
    let public_message = public_output::error_message(&error.code);
    let envelope = public_output::error_structured_content(&error.code);
    let mut result = CallToolResult::structured_error(envelope);
    result.content = vec![ContentBlock::text(public_message)];
    result
}

fn privacy_success(value: Value) -> CallToolResult {
    if serialized_len(&value) > MAX_TOOL_ENVELOPE_BYTES || !privacy_value_is_safe(&value) {
        return privacy_error(PrivacyWorkspaceError::new(
            "privacy_response_rejected",
            false,
        ));
    }
    let mut result = CallToolResult::structured(value);
    result.content = vec![ContentBlock::text("脱敏工作区请求已完成。")];
    result
}

fn privacy_error(error: PrivacyWorkspaceError) -> CallToolResult {
    tracing::warn!(
        error_code = error.code(),
        retryable = error.retryable(),
        "privacy MCP tool failed"
    );
    let mut result = CallToolResult::structured_error(json!({
        "error": {"code": error.code(), "retryable": error.retryable()}
    }));
    result.content = vec![ContentBlock::text("脱敏工作区请求未完成。")];
    result
}

fn privacy_value_is_safe(value: &Value) -> bool {
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(object) => object.iter().all(|(key, value)| {
                let key = key.to_ascii_lowercase();
                ![
                    "path",
                    "filename",
                    "file_name",
                    "original",
                    "source",
                    "mapping",
                    "raw",
                    "unredacted",
                    "stack",
                    "trace",
                    "diagnostic",
                    "inbox_relative_paths",
                ]
                .iter()
                .any(|forbidden| key.contains(forbidden))
                    && walk(value)
            }),
            Value::Array(values) => values.iter().all(walk),
            Value::String(text) => {
                !text.contains(":\\")
                    && !text.contains("file://")
                    && !text.contains("\\\\")
                    && !text.contains("http://")
                    && !text.contains("https://")
            }
            _ => true,
        }
    }
    walk(value) && privacy_gate::model_visible_output_is_safe("脱敏工作区请求已完成。", value)
}

fn serialized_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |value| value.len())
}

fn valid_request_id(value: &str) -> bool {
    value.len() >= 16 && value.len() <= 128 && valid_identifier(value)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn valid_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.starts_with(['/', '\\'])
        && !path.contains('\0')
        && !path
            .split(['/', '\\'])
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        && path.as_bytes().get(1).is_none_or(|byte| *byte != b':')
}

fn is_safe_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn convert_object_keys(value: Value, convert: fn(&str) -> String) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (convert(&key), convert_object_keys(value, convert)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| convert_object_keys(value, convert))
                .collect(),
        ),
        value => value,
    }
}

fn snake_to_camel(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut uppercase = false;
    for character in value.chars() {
        if character == '_' {
            uppercase = true;
        } else if uppercase {
            output.extend(character.to_uppercase());
            uppercase = false;
        } else {
            output.push(character);
        }
    }
    output
}

fn camel_to_snake(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_ascii_uppercase() {
            if !output.is_empty() {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
    }
    output
}

fn internal_error() -> ErrorData {
    ErrorData::internal_error("服务暂时无法完成操作，请稍后重试。".to_owned(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use legal_services::LegalServices;
    use serde_json::json;
    use std::path::PathBuf;

    #[derive(Debug)]
    struct MockPrivacyBackend;

    #[async_trait]
    impl PrivacyWorkspaceBackend for MockPrivacyBackend {
        async fn submit(
            &self,
            request_id: String,
            _inbox_relative_paths: Vec<String>,
        ) -> Result<Value, PrivacyWorkspaceError> {
            Ok(json!({"task_id": format!("task_{request_id}")}))
        }

        async fn status(&self, _task_id: String) -> Result<Value, PrivacyWorkspaceError> {
            Ok(json!({"status":"published","result_id":"result_1"}))
        }

        async fn read_result(
            &self,
            _result_id: String,
            _cursor: Option<String>,
        ) -> Result<Value, PrivacyWorkspaceError> {
            Ok(json!({"text":"[姓名1]已脱敏","next_cursor":null}))
        }
    }

    #[tokio::test]
    async fn privacy_tools_forward_only_declared_inputs() {
        let services = LegalServices::new_public(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test.sqlite"),
        )
        .expect("public service");
        let adapter = ServiceAdapter::for_privacy_workspace(services, Arc::new(MockPrivacyBackend));
        let result = adapter
            .call(
                "privacy_workspace.submit",
                Some(
                    json!({
                        "request_id":"request_0000000001",
                        "inbox_relative_paths":["incoming/example.txt"]
                    })
                    .as_object()
                    .expect("arguments")
                    .clone(),
                ),
            )
            .await
            .expect("call result");
        let value = serde_json::to_value(result).expect("json result");
        assert_eq!(value["isError"], false);
        assert!(value["structuredContent"].get("task_id").is_some());
    }

    #[test]
    fn privacy_response_never_accepts_paths_or_raw_backend_diagnostics() {
        assert!(!privacy_value_is_safe(
            &json!({"source_path":"C:\\\\private\\\\raw.txt"})
        ));
        assert!(!privacy_value_is_safe(&json!({"mapping": {"a":"b"}})));
        assert!(privacy_value_is_safe(
            &json!({"result_id":"result_1","status":"published"})
        ));
    }
}
