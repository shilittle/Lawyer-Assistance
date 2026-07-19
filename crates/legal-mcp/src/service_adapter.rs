use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use legal_services::{
    CaseAnalyzeGapsRequest, CaseApplyPatchRequest, CaseGetStateRequest, CaseProposePatchRequest,
    CitationValidateRequest, DocumentExportRequest, DocumentGenerateRequest,
    LegalGetArticleRequest, LegalGetRelationsRequest, LegalGetVersionsRequest, LegalSearchRequest,
    LegalServices, ServiceError, SERVICE_SCHEMA_VERSION,
};
use rmcp::{
    model::{CallToolResult, ContentBlock, ErrorCode, JsonObject},
    ErrorData,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;
use uuid::Uuid;

use crate::{
    privacy_gate, public_output, receipt_gate::RedactedReceiptGate, registry::PrivacyProfile,
};

const MAX_TOOL_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
const CURSOR_LIFETIME_SECONDS: u64 = 30 * 60;
type HmacSha256 = Hmac<Sha256>;

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

/// Tracks work that may outlive its client-facing HTTP request.
///
/// Tokio cannot cancel a `spawn_blocking` closure after it starts. The HTTP
/// listener therefore closes this gate during shutdown and waits until every
/// admitted request and blocking service operation has released its guard.
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
        self.close_and_wait_inner(|| std::future::ready(())).await;
    }

    async fn close_and_wait_inner<F, Fut>(&self, mut after_active_check: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
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
            // `notify_waiters` does not retain a permit for a future waiter.
            // Register this waiter before reading `active`, so the final guard
            // cannot disappear in the check-to-await window.
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
            after_active_check().await;
            idle.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn is_accepting(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .accepting
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
            debug_assert!(state.active > 0);
            state.active = state.active.saturating_sub(1);
            state.active == 0
        };
        if became_idle {
            self.inner.idle.notify_waiters();
        }
    }
}

#[derive(Debug, Clone)]
pub struct ServiceAdapter {
    services: Arc<LegalServices>,
    profile: PrivacyProfile,
    receipt_gate: Option<RedactedReceiptGate>,
    cursors: CursorCodec,
    in_flight: InFlightOperations,
}

impl ServiceAdapter {
    pub fn new(services: LegalServices) -> Self {
        Self::for_profile(services, PrivacyProfile::default())
    }

    pub fn for_profile(services: LegalServices, profile: PrivacyProfile) -> Self {
        let receipt_gate = match profile {
            PrivacyProfile::PublicLawOnly => None,
            PrivacyProfile::RedactedCase => RedactedReceiptGate::load_from_windows_credentials(
                &services.config().user_database_path,
            )
            .ok(),
        };
        Self::from_parts(services, profile, receipt_gate)
    }

    pub fn for_profile_with_receipt_gate(
        services: LegalServices,
        receipt_gate: RedactedReceiptGate,
    ) -> Self {
        Self::from_parts(services, PrivacyProfile::RedactedCase, Some(receipt_gate))
    }

    fn from_parts(
        services: LegalServices,
        profile: PrivacyProfile,
        receipt_gate: Option<RedactedReceiptGate>,
    ) -> Self {
        Self {
            services: Arc::new(services),
            profile,
            receipt_gate,
            cursors: CursorCodec::new(),
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
        if !self.profile.allows_tool(tool_name) {
            return Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "Unknown tool request.",
                None,
            ));
        }
        let arguments = arguments.unwrap_or_default();
        match tool_name {
            "system_status" => self.system_status(arguments).await,
            "legal_search" => {
                self.invoke::<LegalSearchRequest, _, _>(
                    tool_name,
                    arguments,
                    |services, request| services.legal_search(request),
                )
                .await
            }
            "legal_get_article" => {
                self.invoke::<LegalGetArticleRequest, _, _>(
                    tool_name,
                    arguments,
                    |services, request| services.legal_get_article(request),
                )
                .await
            }
            "legal_get_versions" => {
                self.invoke::<LegalGetVersionsRequest, _, _>(
                    tool_name,
                    arguments,
                    |services, request| services.legal_get_versions(request),
                )
                .await
            }
            "legal_get_relations" => {
                self.invoke::<LegalGetRelationsRequest, _, _>(
                    tool_name,
                    arguments,
                    |services, request| services.legal_get_relations(request),
                )
                .await
            }
            "citation_validate" => self.citation_validate(arguments).await,
            "case_get_state" => self.case_get_state(arguments).await,
            "case_propose_patch" => {
                self.invoke::<CaseProposePatchRequest, _, _>(
                    tool_name,
                    arguments,
                    |services, request| services.case_propose_patch(request),
                )
                .await
            }
            "case_apply_patch" => {
                self.invoke::<CaseApplyPatchRequest, _, _>(
                    tool_name,
                    arguments,
                    |services, request| services.case_apply_patch(request),
                )
                .await
            }
            "case_analyze_gaps" => {
                self.invoke::<CaseAnalyzeGapsRequest, _, _>(
                    tool_name,
                    arguments,
                    |services, request| services.case_analyze_gaps(request),
                )
                .await
            }
            "document_generate" => {
                self.invoke::<DocumentGenerateRequest, _, _>(
                    tool_name,
                    arguments,
                    |services, request| services.document_generate(request),
                )
                .await
            }
            "document_export" => self.document_export(arguments).await,
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
            Err(error) => return Ok(tool_error("system_status", error)),
        };
        if input.schema_version != SERVICE_SCHEMA_VERSION {
            return Ok(tool_error(
                "system_status",
                ServiceError::new(
                    "unsupported_schema_version",
                    "request schema_version is not supported",
                    false,
                )
                .with_details(json!({
                    "supported": SERVICE_SCHEMA_VERSION,
                    "actual": input.schema_version
                })),
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
            Ok(response) => tool_success("system_status", response, None),
            Err(error) => Ok(tool_error("system_status", error)),
        }
    }

    async fn case_get_state(&self, arguments: JsonObject) -> Result<CallToolResult, ErrorData> {
        let input: CaseStateInput = match decode(arguments) {
            Ok(input) => input,
            Err(error) => return Ok(tool_error("case_get_state", error)),
        };
        if input.schema_version != SERVICE_SCHEMA_VERSION {
            return Ok(tool_error(
                "case_get_state",
                ServiceError::new(
                    "unsupported_schema_version",
                    "request schema_version is not supported",
                    false,
                ),
            ));
        }
        let (page, page_size, expected_revision) = match input.cursor.as_deref() {
            Some(cursor) => {
                let decoded = match self.cursors.decode(cursor, &input.project_id) {
                    Ok(decoded) => decoded,
                    Err(message) => {
                        return Ok(tool_error(
                            "case_get_state",
                            ServiceError::new("invalid_cursor", message, false)
                                .with_details(json!({"field":"cursor"})),
                        ))
                    }
                };
                if input.limit.is_some_and(|limit| limit != decoded.page_size) {
                    return Ok(tool_error(
                        "case_get_state",
                        ServiceError::new(
                            "invalid_request",
                            "limit must be omitted when continuing with a cursor",
                            false,
                        )
                        .with_details(json!({"field":"limit"})),
                    ));
                }
                (decoded.page, decoded.page_size, Some(decoded.revision))
            }
            None => (0, input.limit.unwrap_or(50), None),
        };
        if !(1..=100).contains(&page_size) {
            return Ok(tool_error(
                "case_get_state",
                ServiceError::new("invalid_request", "limit must be between 1 and 100", false)
                    .with_details(json!({"field":"limit"})),
            ));
        }
        let request = CaseGetStateRequest {
            schema_version: input.schema_version,
            project_id: input.project_id.clone(),
            page: Some(page),
            page_size: Some(page_size),
        };
        let services = Arc::clone(&self.services);
        let operation = self.begin_blocking_operation()?;
        let result = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            services.case_get_state(request)
        })
        .await
        .map_err(|_| internal_error())?;
        match result {
            Ok(response) => {
                if expected_revision
                    .as_deref()
                    .is_some_and(|revision| revision != response.revision)
                {
                    return Ok(tool_error(
                        "case_get_state",
                        ServiceError::new(
                            "revision_conflict",
                            "case state changed while the cursor was in use; restart pagination",
                            false,
                        )
                        .with_details(json!({"remediation":"restart_pagination"})),
                    ));
                }
                let next = if response.has_more {
                    Some(
                        self.cursors
                            .encode(
                                &input.project_id,
                                response.page.saturating_add(1),
                                response.page_size,
                                &response.revision,
                            )
                            .map_err(|_| internal_error())?,
                    )
                } else {
                    None
                };
                tool_success("case_get_state", response, next)
            }
            Err(error) => Ok(tool_error("case_get_state", error)),
        }
    }

    async fn citation_validate(&self, arguments: JsonObject) -> Result<CallToolResult, ErrorData> {
        let gate = self.receipt_gate.as_ref().ok_or_else(receipt_rejected)?;
        let request: CitationValidateRequest = gate
            .verify_citation_call(arguments)
            .map_err(|_| receipt_rejected())?;
        let services = Arc::clone(&self.services);
        let operation = self.begin_blocking_operation()?;
        let result = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            services.citation_validate(request)
        })
        .await
        .map_err(|_| internal_error())?;
        match result {
            Ok(response) => tool_success("citation_validate", response, None),
            Err(error) => Ok(tool_error("citation_validate", error)),
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
            Err(error) => return Ok(tool_error(tool_name, error)),
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
            Ok(response) => tool_success(tool_name, response, None),
            Err(error) => Ok(tool_error(tool_name, error)),
        }
    }

    async fn document_export(&self, arguments: JsonObject) -> Result<CallToolResult, ErrorData> {
        let request: DocumentExportRequest = match decode(arguments) {
            Ok(request) => request,
            Err(error) => return Ok(tool_error("document_export", error)),
        };
        let relative_path = request.relative_path.clone();
        let services = Arc::clone(&self.services);
        let operation = self.begin_blocking_operation()?;
        let result = tokio::task::spawn_blocking(move || {
            let _operation = operation;
            services.document_export(request)
        })
        .await
        .map_err(|_| internal_error())?;
        match result {
            Ok(mut response) => {
                // The service uses the canonical absolute path for its audit
                // transaction. The MCP boundary returns only the caller's
                // already-validated path relative to the configured root.
                response.export_path = relative_path;
                tool_success("document_export", response, None)
            }
            Err(error) => Ok(tool_error("document_export", error)),
        }
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaseStateInput {
    schema_version: u16,
    project_id: String,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

fn decode<T: DeserializeOwned>(arguments: JsonObject) -> Result<T, ServiceError> {
    let value = convert_external_arguments(Value::Object(arguments))?;
    serde_json::from_value(value).map_err(|_| {
        ServiceError::new(
            "invalid_request",
            "tool arguments do not match the declared input schema",
            false,
        )
        .with_details(json!({"reason":"schema_mismatch"}))
    })
}

fn tool_success<T: Serialize>(
    tool_name: &str,
    response: T,
    next_cursor: Option<String>,
) -> Result<CallToolResult, ErrorData> {
    let data = serde_json::to_value(response).map_err(|_| internal_error())?;
    let data = convert_object_keys(data, camel_to_snake);
    let public_text = public_output::success_text(tool_name, &data);
    let public_data = public_output::success_structured_content(tool_name, &data, &public_text);
    if !privacy_gate::model_visible_output_is_safe(&public_text, &public_data) {
        tracing::warn!(
            tool = tool_name,
            reason_code = "sensitive_content_blocked",
            "MCP model-visible result blocked by privacy boundary"
        );
        return Ok(tool_error(
            tool_name,
            ServiceError::new(
                "sensitive_content_blocked",
                "privacy boundary blocked the result",
                false,
            ),
        ));
    }
    let envelope_size = serde_json::to_vec(&public_data)
        .map_err(|_| internal_error())?
        .len();
    if envelope_size > MAX_TOOL_ENVELOPE_BYTES {
        return Ok(tool_error(
            tool_name,
            ServiceError::new(
                "limit_exceeded",
                "tool result exceeded the configured response limit",
                false,
            ),
        ));
    }
    // Pagination cursors and all other coordination values remain server-side.
    // They must never be placed in either model-visible result channel.
    let _ = next_cursor;
    let mut result = CallToolResult::structured(public_data);
    result.content = vec![ContentBlock::text(public_text)];
    Ok(result)
}

fn tool_error(tool_name: &str, error: ServiceError) -> CallToolResult {
    tracing::warn!(
        tool = tool_name,
        error_code = %error.code,
        "MCP tool call failed"
    );
    let public_message = public_output::error_message(&error.code);
    let envelope = public_output::error_structured_content(&error.code);
    let envelope_size = serde_json::to_vec(&envelope).map_or(usize::MAX, |value| value.len());
    debug_assert!(envelope_size <= MAX_TOOL_ENVELOPE_BYTES);
    let mut result = CallToolResult::structured_error(envelope);
    result.content = vec![ContentBlock::text(public_message)];
    result
}

fn receipt_rejected() -> ErrorData {
    ErrorData::invalid_params(
        "A valid App-issued receipt bound to the exact approved payload is required.",
        None,
    )
}

fn internal_error() -> ErrorData {
    tracing::error!("MCP request failed at an internal boundary");
    ErrorData::internal_error("服务暂时无法完成操作，请稍后重试。".to_owned(), None)
}

#[derive(Debug, Clone)]
struct CursorCodec {
    key: Arc<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    version: u8,
    tool: String,
    project_hash: String,
    page: u32,
    page_size: u32,
    revision: String,
    expires_at: u64,
}

#[derive(Debug)]
struct DecodedCursor {
    page: u32,
    page_size: u32,
    revision: String,
}

impl CursorCodec {
    fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(Uuid::new_v4().as_bytes());
        hasher.update(Uuid::new_v4().as_bytes());
        hasher.update(now_seconds().to_le_bytes());
        Self {
            key: Arc::new(hasher.finalize().into()),
        }
    }

    fn encode(
        &self,
        project_id: &str,
        page: u32,
        page_size: u32,
        revision: &str,
    ) -> Result<String, ()> {
        let payload = CursorPayload {
            version: 1,
            tool: "case_get_state".to_owned(),
            project_hash: hash_identifier(project_id),
            page,
            page_size,
            revision: revision.to_owned(),
            expires_at: now_seconds().saturating_add(CURSOR_LIFETIME_SECONDS),
        };
        let payload = serde_json::to_vec(&payload).map_err(|_| ())?;
        let mut mac = HmacSha256::new_from_slice(self.key.as_slice()).map_err(|_| ())?;
        mac.update(&payload);
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn decode(&self, token: &str, project_id: &str) -> Result<DecodedCursor, &'static str> {
        if token.len() > 2048 {
            return Err("cursor is invalid or expired");
        }
        let (payload, signature) = token
            .split_once('.')
            .ok_or("cursor is invalid or expired")?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "cursor is invalid or expired")?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| "cursor is invalid or expired")?;
        let mut mac = HmacSha256::new_from_slice(self.key.as_slice())
            .map_err(|_| "cursor is invalid or expired")?;
        mac.update(&payload);
        mac.verify_slice(&signature)
            .map_err(|_| "cursor is invalid or expired")?;
        let payload: CursorPayload =
            serde_json::from_slice(&payload).map_err(|_| "cursor is invalid or expired")?;
        if payload.version != 1
            || payload.tool != "case_get_state"
            || payload.project_hash != hash_identifier(project_id)
            || payload.page_size == 0
            || payload.page_size > 100
            || payload.expires_at < now_seconds()
        {
            return Err("cursor is invalid or expired");
        }
        Ok(DecodedCursor {
            page: payload.page,
            page_size: payload.page_size,
            revision: payload.revision,
        })
    }
}

fn hash_identifier(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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
        other => other,
    }
}

fn convert_external_arguments(value: Value) -> Result<Value, ServiceError> {
    match value {
        Value::Object(object) => {
            let mut converted = Map::new();
            for (key, value) in object {
                if !is_declared_external_key(&key) {
                    return Err(argument_schema_error("keys_must_use_declared_snake_case"));
                }
                if key == "idempotency_key" {
                    validate_public_idempotency_key(&value)?;
                }
                let internal_key = snake_to_camel(&key);
                if converted
                    .insert(internal_key, convert_external_arguments(value)?)
                    .is_some()
                {
                    return Err(argument_schema_error("argument_key_collision"));
                }
            }
            Ok(Value::Object(converted))
        }
        Value::Array(values) => values
            .into_iter()
            .map(convert_external_arguments)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        other => Ok(other),
    }
}

fn is_declared_external_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        && !bytes.windows(2).any(|pair| pair == b"__")
}

fn validate_public_idempotency_key(value: &Value) -> Result<(), ServiceError> {
    let valid = value.as_str().is_some_and(|key| {
        (16..=128).contains(&key.len())
            && key.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-')
            })
    });
    if valid {
        Ok(())
    } else {
        Err(argument_schema_error("invalid_idempotency_key"))
    }
}

fn argument_schema_error(reason: &'static str) -> ServiceError {
    ServiceError::new(
        "invalid_request",
        "tool arguments do not match the declared input schema",
        false,
    )
    .with_details(json!({"reason":reason}))
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closing_the_in_flight_gate_waits_for_admitted_work_and_rejects_new_work() {
        let tracker = InFlightOperations::default();
        let guard = tracker.try_begin().expect("gate initially accepts work");
        let closing_tracker = tracker.clone();
        let mut closing = tokio::spawn(async move { closing_tracker.close_and_wait().await });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut closing)
                .await
                .is_err()
        );
        assert!(tracker.try_begin().is_none());

        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), closing)
            .await
            .expect("closing gate observes idle")
            .expect("closing task joins");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closing_gate_cannot_miss_the_last_release_between_check_and_await() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let tracker = InFlightOperations::default();
        let guard = tracker.try_begin().expect("gate initially accepts work");
        let checked_active = Arc::new(tokio::sync::Barrier::new(2));
        let allow_await = Arc::new(tokio::sync::Barrier::new(2));
        let first_check = Arc::new(AtomicBool::new(true));
        let closing_tracker = tracker.clone();
        let closing_checked_active = Arc::clone(&checked_active);
        let closing_allow_await = Arc::clone(&allow_await);
        let closing_first_check = Arc::clone(&first_check);
        let closing = tokio::spawn(async move {
            closing_tracker
                .close_and_wait_inner(move || {
                    let checked_active = Arc::clone(&closing_checked_active);
                    let allow_await = Arc::clone(&closing_allow_await);
                    let is_first = closing_first_check.swap(false, Ordering::AcqRel);
                    async move {
                        if is_first {
                            checked_active.wait().await;
                            allow_await.wait().await;
                        }
                    }
                })
                .await;
        });

        checked_active.wait().await;
        assert!(!tracker.is_accepting());
        // The last guard notifies while close_and_wait is deliberately paused
        // after observing active work but before awaiting the notification.
        drop(guard);
        allow_await.wait().await;

        tokio::time::timeout(std::time::Duration::from_secs(1), closing)
            .await
            .expect("the pre-registered waiter observes the last release")
            .expect("closing task joins");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_the_async_caller_does_not_untrack_spawn_blocking_work() {
        let directory = tempfile::tempdir().unwrap();
        let legal = directory.path().join("legal.sqlite");
        let user = directory.path().join("user.sqlite");
        let materials = directory.path().join("materials");
        let output = directory.path().join("output");
        std::fs::write(&legal, []).unwrap();
        std::fs::write(&user, []).unwrap();
        std::fs::create_dir(&materials).unwrap();
        std::fs::create_dir(&output).unwrap();
        let services = LegalServices::new(legal_services::ServiceConfig {
            legal_core_path: legal,
            user_database_path: user,
            allowed_file_roots: vec![materials],
            allowed_output_root: output,
        })
        .unwrap();
        let adapter = ServiceAdapter::new(services);
        let tracker = adapter.in_flight_operations();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let call_adapter = adapter.clone();
        let call = tokio::spawn(async move {
            call_adapter
                .invoke::<StatusInput, String, _>(
                    "test_blocking_operation",
                    json_object(json!({"schema_version":1})),
                    move |_, _| {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        Ok("finished".to_owned())
                    },
                )
                .await
        });
        tokio::task::spawn_blocking(move || {
            entered_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("blocking operation starts")
        })
        .await
        .unwrap();

        call.abort();
        let _ = call.await;
        let closing_tracker = tracker.clone();
        let mut closing = tokio::spawn(async move { closing_tracker.close_and_wait().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut closing)
                .await
                .is_err()
        );

        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), closing)
            .await
            .expect("blocking operation releases lifecycle barrier")
            .expect("closing task joins");
    }

    #[test]
    fn input_accepts_only_unambiguous_snake_case_keys() {
        assert!(decode::<StatusInput>(json_object(json!({"schema_version":1}))).is_ok());
        assert!(decode::<StatusInput>(json_object(json!({"schemaVersion":1}))).is_err());
        assert!(decode::<StatusInput>(json_object(json!({
            "schema_version":1,
            "schemaVersion":1
        })))
        .is_err());
        assert!(decode::<StatusInput>(json_object(json!({"schema__version":1}))).is_err());
        assert!(convert_external_arguments(json!({
            "outer":{"sourceRefs":[]}
        }))
        .is_err());
    }

    #[tokio::test]
    async fn redacted_profile_lists_citation_but_missing_receipt_state_fails_closed() {
        let directory = tempfile::tempdir().expect("temporary service directory");
        let legal = directory.path().join("legal.sqlite");
        let user = directory.path().join("user.sqlite");
        let materials = directory.path().join("materials");
        let output = directory.path().join("output");
        std::fs::write(&legal, []).expect("legal database placeholder");
        std::fs::write(&user, []).expect("user database placeholder");
        std::fs::create_dir(&materials).expect("materials directory");
        std::fs::create_dir(&output).expect("output directory");
        let services = LegalServices::new(legal_services::ServiceConfig {
            legal_core_path: legal,
            user_database_path: user,
            allowed_file_roots: vec![materials],
            allowed_output_root: output,
        })
        .expect("service configuration");
        let adapter = ServiceAdapter::for_profile(services, PrivacyProfile::RedactedCase);
        let registry = crate::registry::ToolRegistry::for_profile(PrivacyProfile::RedactedCase);
        assert!(registry.get("citation_validate").is_some());

        let payload = r#"{"schemaVersion":1,"answer":"private-canary","allowedSourceIds":[],"caseDate":null,"includeExpired":false}"#;
        let token = format!("rct_v1.not-real.{}", "a".repeat(64));
        let error = adapter
            .call(
                "citation_validate",
                Some(json_object(json!({
                    "approved_payload_json":payload,
                    "redaction_receipt":token
                }))),
            )
            .await
            .expect_err("missing receipt state must reject");
        let wire = serde_json::to_string(&error).expect("serialize MCP error");
        let value: Value = serde_json::from_str(&wire).expect("MCP error JSON");
        assert_eq!(value["code"], -32602);
        assert!(!wire.contains(payload));
        assert!(!wire.contains(&token));
        assert!(!wire.contains("private-canary"));
    }

    #[test]
    fn public_idempotency_key_contract_is_enforced_before_service_decode() {
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct WriteInput {
            idempotency_key: String,
        }

        let valid = decode::<WriteInput>(json_object(json!({
            "idempotency_key":"retry-key-123456"
        })))
        .unwrap();
        assert_eq!(valid.idempotency_key, "retry-key-123456");
        assert!(decode::<WriteInput>(json_object(json!({
            "idempotency_key":"too-short"
        })))
        .is_err());
        assert!(decode::<WriteInput>(json_object(json!({
            "idempotency_key":"contains spaces 123456"
        })))
        .is_err());
        assert!(decode::<WriteInput>(json_object(json!({
            "idempotencyKey":"retry-key-123456"
        })))
        .is_err());
    }

    #[test]
    fn content_and_structured_content_are_both_public_only() {
        let success = tool_success(
            "legal_search",
            json!({
                "schemaVersion":1,
                "laws":[],
                "articles":[{
                    "articleId":"article-secret",
                    "documentTitle":"中华人民共和国民法典",
                    "articleNumber":"第五百七十七条",
                    "articleTitle":null,
                    "snippet":"当事人一方不履行合同义务的，应当承担违约责任。",
                    "effectiveFrom":"2021-01-01"
                }]
            }),
            None,
        )
        .unwrap();
        let success = serde_json::to_value(success).unwrap();
        let success_text = success["content"][0]["text"].as_str().unwrap();
        assert!(success_text.contains("《中华人民共和国民法典》第五百七十七条"));
        assert!(!success_text.contains("article-secret"));
        assert!(serde_json::from_str::<Value>(success_text).is_err());
        assert_eq!(success["structuredContent"]["结果"], "已完成");
        assert_eq!(
            success["structuredContent"]["内容"]["相关条文"][0]["法律名称"],
            "中华人民共和国民法典"
        );
        assert!(success["structuredContent"]["内容"]["相关条文"][0]
            .get("article_id")
            .is_none());
        let success_wire = serde_json::to_string(&success).unwrap();
        for forbidden in [
            "article-secret",
            "schema_version",
            "request_id",
            "snippet",
            "score",
            "structuredContent\":{\"data",
        ] {
            assert!(!success_wire.contains(forbidden), "leaked {forbidden}");
        }

        let error = tool_error(
            "fixture",
            ServiceError::new(
                "internal_contract_error",
                "failed at C:\\Users\\person\\AppData\\secret.sqlite",
                false,
            )
            .with_details(json!({
                "path":"C:\\Users\\person\\AppData\\secret.sqlite",
                "reason":"database_open_failed"
            })),
        );
        let error = serde_json::to_value(error).unwrap();
        let error_text = error["content"][0]["text"].as_str().unwrap();
        assert!(!error_text.contains("AppData"));
        assert_eq!(error["structuredContent"]["结果"], "未完成");
        assert!(error["structuredContent"]["内容"].is_null());
        let error_wire = serde_json::to_string(&error).unwrap();
        for forbidden in [
            "AppData",
            "secret.sqlite",
            "internal_contract_error",
            "database_open_failed",
            "retryable",
            "details",
        ] {
            assert!(!error_wire.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn cursors_are_bound_to_project_and_tamper_evident() {
        let codec = CursorCodec::new();
        let cursor = codec.encode("project-1", 2, 50, &"a".repeat(64)).unwrap();
        let decoded = codec.decode(&cursor, "project-1").unwrap();
        assert_eq!(decoded.page, 2);
        assert_eq!(decoded.page_size, 50);
        assert_eq!(decoded.revision, "a".repeat(64));
        assert!(codec.decode(&cursor, "project-2").is_err());
        assert!(codec.decode(&(cursor + "x"), "project-1").is_err());
    }

    fn json_object(value: Value) -> JsonObject {
        value.as_object().cloned().unwrap()
    }
}
