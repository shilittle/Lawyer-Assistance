use async_trait::async_trait;
use legal_services::{LegalServices, ServiceError, SERVICE_SCHEMA_VERSION};
use rmcp::{
    model::{CallToolResult, ContentBlock, ErrorCode, JsonObject},
    ErrorData,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::{
    privacy_gate, public_output,
    registry::{PrivacyProfile, PRIVACY_WORKSPACE_TOOL_NAMES},
};

const MAX_TOOL_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;

/// Transport teardown may drop the call future before its cancellation branch
/// is polled. The database worker still owns its admission until it exits.
struct CancelSqliteOnDrop(legal_services::SearchCancellation);
impl Drop for CancelSqliteOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// A host-supplied admission boundary for public legal queries.  The trait is
/// intentionally independent of workspace-service so the standalone MCP
/// binary keeps a local bounded implementation while an embedded router can
/// share the workspace's Search budget.
#[async_trait]
pub trait PublicQueryAdmission: Send + Sync {
    async fn acquire(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn Send>, PublicQueryAdmissionError>;
}

/// Only stable, non-diagnostic codes cross the adapter boundary.  They are
/// later rendered through the existing public error envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicQueryAdmissionError {
    code: String,
    retryable: bool,
}

impl PublicQueryAdmissionError {
    pub fn new(code: impl AsRef<str>, retryable: bool) -> Self {
        let code = match code.as_ref() {
            "capacity_exceeded" | "cancelled" | "workspace_unavailable" => code.as_ref(),
            _ => "query_admission_failed",
        };
        Self {
            code: code.to_owned(),
            retryable,
        }
    }

    pub fn code(&self) -> &str {
        &self.code
    }

    pub const fn retryable(&self) -> bool {
        self.retryable
    }
}

/// Default standalone admission: at most two active public queries and at
/// most sixteen waiting callers.  The owned permit is moved into the blocking
/// worker and therefore lasts until the synchronous SQLite call actually
/// returns, even when the HTTP caller has timed out or disconnected.
#[derive(Debug)]
pub struct BoundedPublicQueryAdmission {
    active: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
}

impl Default for BoundedPublicQueryAdmission {
    fn default() -> Self {
        Self::new(2, 16)
    }
}

impl BoundedPublicQueryAdmission {
    pub fn new(active: usize, waiting: usize) -> Self {
        Self {
            active: Arc::new(Semaphore::new(active)),
            waiting: Arc::new(Semaphore::new(waiting)),
        }
    }
}

#[async_trait]
impl PublicQueryAdmission for BoundedPublicQueryAdmission {
    async fn acquire(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Box<dyn Send>, PublicQueryAdmissionError> {
        if cancellation.is_cancelled() {
            return Err(PublicQueryAdmissionError::new("cancelled", false));
        }
        if let Ok(active) = Arc::clone(&self.active).try_acquire_owned() {
            return Ok(Box::new(active));
        }
        let waiting = Arc::clone(&self.waiting)
            .try_acquire_owned()
            .map_err(|_| PublicQueryAdmissionError::new("capacity_exceeded", true))?;
        let active = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(PublicQueryAdmissionError::new("cancelled", false)),
            acquired = Arc::clone(&self.active).acquire_owned() => acquired.map_err(|_| PublicQueryAdmissionError::new("workspace_unavailable", true))?,
        };
        drop(waiting);
        if cancellation.is_cancelled() {
            return Err(PublicQueryAdmissionError::new("cancelled", false));
        }
        Ok(Box::new(active))
    }
}

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
    public_query_admission: Arc<dyn PublicQueryAdmission>,
    static_privacy_backend: Option<Arc<dyn PrivacyWorkspaceBackend>>,
    request_backend_factory: Option<Arc<dyn PrivacyWorkspaceBackendFactory>>,
    in_flight: InFlightOperations,
}

impl std::fmt::Debug for ServiceAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceAdapter")
            .field("profile", &self.profile)
            .field("public_query_admission", &"configured")
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
            public_query_admission: Arc::new(BoundedPublicQueryAdmission::default()),
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
            public_query_admission: Arc::new(BoundedPublicQueryAdmission::default()),
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
            public_query_admission: Arc::new(BoundedPublicQueryAdmission::default()),
            static_privacy_backend: None,
            request_backend_factory: Some(backend_factory),
            in_flight: InFlightOperations::default(),
        }
    }

    /// Use the embedding host's public-query budget.  The adapter never
    /// receives a workspace handle, preserving the one-way MCP boundary.
    pub fn with_public_query_admission(mut self, admission: Arc<dyn PublicQueryAdmission>) -> Self {
        self.public_query_admission = admission;
        self
    }

    pub(crate) fn in_flight_operations(&self) -> InFlightOperations {
        self.in_flight.clone()
    }

    pub async fn call(
        &self,
        tool_name: &str,
        arguments: Option<JsonObject>,
    ) -> Result<CallToolResult, ErrorData> {
        self.call_with_request_id(tool_name, arguments, None, CancellationToken::new())
            .await
    }

    pub(crate) async fn call_with_request_id(
        &self,
        tool_name: &str,
        arguments: Option<JsonObject>,
        authorization: Option<&str>,
        cancellation: CancellationToken,
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
            "system_status" => self.system_status(arguments, cancellation).await,
            "legal_search" => self.invoke_legal_search(arguments, cancellation).await,
            "legal_get_article" => {
                self.invoke(
                    "legal_get_article",
                    arguments,
                    cancellation,
                    |services, request, cancel| {
                        services.legal_get_article_cancellable(request, cancel)
                    },
                )
                .await
            }
            "legal_get_versions" => {
                self.invoke(
                    "legal_get_versions",
                    arguments,
                    cancellation,
                    |services, request, cancel| {
                        services.legal_get_versions_cancellable(request, cancel)
                    },
                )
                .await
            }
            "legal_get_relations" => {
                self.invoke(
                    "legal_get_relations",
                    arguments,
                    cancellation,
                    |services, request, cancel| {
                        services.legal_get_relations_cancellable(request, cancel)
                    },
                )
                .await
            }
            "legal_search_cases" => {
                self.invoke(
                    "legal_search_cases",
                    arguments,
                    cancellation,
                    |services, request, cancel| {
                        services.judicial_case_search_cancellable(request, cancel)
                    },
                )
                .await
            }
            "legal_get_case" => {
                self.invoke(
                    "legal_get_case",
                    arguments,
                    cancellation,
                    |services, request, cancel| {
                        services.judicial_case_get_cancellable(request, cancel)
                    },
                )
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

    async fn system_status(
        &self,
        arguments: JsonObject,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, ErrorData> {
        self.invoke(
            "system_status",
            arguments,
            cancellation,
            |services, input: StatusInput, cancel| {
                if input.schema_version != SERVICE_SCHEMA_VERSION {
                    return Err(ServiceError::new(
                        "unsupported_schema_version",
                        "unsupported schema",
                        false,
                    ));
                }
                services.system_status_cancellable(cancel)
            },
        )
        .await
    }

    /// `legal_search` has a cancellable SQLite implementation.  Keep the
    /// caller token and the SQLite interrupt token separate: a request may
    /// cancel its subscription without the worker releasing its admission
    /// permit before the database returns.
    async fn invoke_legal_search(
        &self,
        arguments: JsonObject,
        cancellation: CancellationToken,
    ) -> Result<CallToolResult, ErrorData> {
        let request: legal_services::LegalSearchRequest = match decode(arguments) {
            Ok(request) => request,
            Err(error) => return Ok(public_error("legal_search", error)),
        };
        let permit = match self.public_query_admission.acquire(&cancellation).await {
            Ok(permit) => permit,
            Err(error) => {
                return Ok(public_error(
                    "legal_search",
                    ServiceError::new(
                        error.code(),
                        "public query admission rejected the request",
                        error.retryable(),
                    ),
                ));
            }
        };
        let services = Arc::clone(&self.services);
        let operation = self.begin_blocking_operation()?;
        let sqlite_cancellation = legal_services::SearchCancellation::new();
        let _cancel_on_drop = CancelSqliteOnDrop(sqlite_cancellation.clone());
        let worker_cancellation = sqlite_cancellation.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _operation = operation;
            services.legal_search_cancellable(request, &worker_cancellation)
        });
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                sqlite_cancellation.cancel();
                return Ok(public_error(
                    "legal_search",
                    ServiceError::new("cancelled", "public query cancelled", false),
                ));
            }
            result = task => result.map_err(|_| internal_error())?,
        };
        match result {
            Ok(response) => public_success("legal_search", response),
            Err(error) => Ok(public_error("legal_search", error)),
        }
    }

    async fn invoke<Request, Response, Invoke>(
        &self,
        tool_name: &str,
        arguments: JsonObject,
        cancellation: CancellationToken,
        invoke: Invoke,
    ) -> Result<CallToolResult, ErrorData>
    where
        Request: DeserializeOwned + Send + 'static,
        Response: Serialize + Send + 'static,
        Invoke: FnOnce(
                &LegalServices,
                Request,
                &legal_services::SearchCancellation,
            ) -> Result<Response, ServiceError>
            + Send
            + 'static,
    {
        let request: Request = match decode(arguments) {
            Ok(request) => request,
            Err(error) => return Ok(public_error(tool_name, error)),
        };
        let permit = match self.public_query_admission.acquire(&cancellation).await {
            Ok(permit) => permit,
            Err(error) => {
                return Ok(public_error(
                    tool_name,
                    ServiceError::new(
                        error.code(),
                        "public query admission rejected the request",
                        error.retryable(),
                    ),
                ));
            }
        };
        let services = Arc::clone(&self.services);
        let operation = self.begin_blocking_operation()?;
        let sqlite_cancellation = legal_services::SearchCancellation::new();
        let _cancel_on_drop = CancelSqliteOnDrop(sqlite_cancellation.clone());
        let worker_cancellation = sqlite_cancellation.clone();
        let task = tokio::task::spawn_blocking(move || {
            // Both permits live in the worker, not the HTTP future.  A client
            // cancellation can return a public cancellation response while
            // the resource remains accounted for until SQLite actually exits.
            let _permit = permit;
            let _operation = operation;
            invoke(&services, request, &worker_cancellation)
        });
        let result = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                sqlite_cancellation.cancel();
                return Ok(public_error(
                    tool_name,
                    ServiceError::new("cancelled", "public query cancelled", false),
                ));
            },
            result = task => result.map_err(|_| internal_error())?,
        };
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
    let verified_public_case = public_output::verified_case_output_is_safe(tool_name, &data);
    if matches!(tool_name, "legal_search_cases" | "legal_get_case") && !verified_public_case {
        return Ok(public_error(
            tool_name,
            ServiceError::new(
                "case_output_blocked",
                "case output failed public-source boundary validation",
                false,
            ),
        ));
    }
    if (!verified_public_case
        && !privacy_gate::model_visible_output_is_safe(&public_text, &public_data))
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

    #[tokio::test]
    async fn bounded_public_query_admission_rejects_overflow_and_releases_cancelled_waiters() {
        let admission = Arc::new(BoundedPublicQueryAdmission::new(1, 1));
        let active_cancel = CancellationToken::new();
        let active = admission
            .acquire(&active_cancel)
            .await
            .expect("first public query is active");

        let waiting_cancel = CancellationToken::new();
        let waiting_admission = Arc::clone(&admission);
        let waiting_token = waiting_cancel.clone();
        let waiting =
            tokio::spawn(
                async move { waiting_admission.acquire(&waiting_token).await.map(|_| ()) },
            );
        tokio::task::yield_now().await;
        let overflow = match admission.acquire(&active_cancel).await {
            Ok(_) => panic!("second waiting public query is rejected"),
            Err(error) => error,
        };
        assert_eq!(overflow.code(), "capacity_exceeded");

        waiting_cancel.cancel();
        assert_eq!(
            match waiting.await.expect("waiting admission task joins") {
                Ok(_) => panic!("cancelled request does not remain queued"),
                Err(error) => error.code().to_owned(),
            },
            "cancelled"
        );

        let replacement_cancel = CancellationToken::new();
        let replacement_admission = Arc::clone(&admission);
        let replacement_token = replacement_cancel.clone();
        let replacement =
            tokio::spawn(async move { replacement_admission.acquire(&replacement_token).await });
        tokio::task::yield_now().await;
        drop(active);
        drop(
            replacement
                .await
                .expect("replacement joins")
                .expect("cancelled queue place was released"),
        );
    }

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

    #[test]
    fn verified_official_case_full_text_can_cross_the_public_boundary() {
        let data = json!({
            "case": {
                "case_id":"spc-guiding-1", "title":"指导案例", "case_type":"guiding",
                "guiding_number":1, "reference_number":null, "keywords":["劳动关系"],
                "publication_date":"2026-09-09", "court":"最高人民法院", "case_number":null,
                "status":"published", "source_url":"https://www.court.gov.cn/shenpan/1.html",
                "matched_text":"劳动关系", "key_points":[], "basic_facts":"原告：张三",
                "judgment_result":"", "reasoning":"", "related_laws":[],
                "full_text":"原告：张三。公开指导案例全文。", "fetched_at":"2026-09-09T00:00:00Z"
            }
        });
        assert!(!privacy_gate::model_visible_output_is_safe(
            "原告：张三",
            &data
        ));
        let result = public_success("legal_get_case", data).expect("official case result");
        let value = serde_json::to_value(result).expect("result JSON");
        assert_eq!(value["isError"], false);
        assert!(value["structuredContent"]["内容"]["案例全文"]
            .as_str()
            .unwrap_or_default()
            .contains("公开指导案例全文"));
    }

    #[test]
    fn case_tools_reject_unverified_sources_without_falling_back_to_the_general_gate() {
        let data = json!({
            "case": {
                "case_id":"spc-guiding-1", "title":"指导案例", "case_type":"guiding",
                "guiding_number":1, "reference_number":null, "keywords":[],
                "status":"published", "source_url":"https://court.gov.cn.example.test/case/1",
                "full_text":"公开文本", "fetched_at":"2026-09-09T00:00:00Z"
            }
        });
        let result = public_success("legal_get_case", data).expect("blocked result");
        let value = serde_json::to_value(result).expect("result JSON");
        assert_eq!(value["isError"], true);
        assert!(!serde_json::to_string(&value)
            .expect("result JSON")
            .contains("example.test"));
    }
}
