//! Qualified execution backend for the `approved_case_workspace` MCP profile.
//!
//! The backend never accepts paths or raw-material locators. Every operation is
//! bound to a caller-issued, persistent, one-time ticket before it can touch an
//! approved generation or work product.

use crate::approved_workspace;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use privacy::{
    mcp_ticket::{
        McpAccessTargetV1, McpAccessTicketRequestV1, McpAccessTicketStore, McpTicketError,
        McpTicketVerificationContextV1, McpTransportBindingV1,
    },
    scan_residual, sha256_hex,
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, ApprovedMaterialRefV1, CaseId, MaterialId,
        PublicationId, Sha256Hex, WorkProductId,
    },
    work_products::{
        PublishedWorkProductV1, WorkProductError, WorkProductPublisher, WorkProductService,
        WorkProductWriteV1,
    },
    workspace::{
        ApprovedWorkspaceOperationGuard, ApprovedWorkspaceService, WorkspaceError,
        APPROVED_MATERIAL_READ_PURPOSE, APPROVED_WORKSPACE_DESTINATION_SCOPE,
    },
};
use rmcp::model::{CallToolResult, ContentBlock, JsonObject};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const MAX_APPROVED_RESULT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CURSOR_BYTES: usize = 512;
const CURSOR_TTL_SECONDS: u64 = 30 * 60;
const PLACEHOLDER_POLICY_VERSION: &str = "privacy-egress-v1";
const AUTHOR_TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovedBackendInitError {
    #[error("approved backend binding is invalid")]
    InvalidBinding,
    #[error("approved backend components are bound to different workspaces")]
    WorkspaceBindingMismatch,
    #[error("approved backend recovery failed")]
    RecoveryFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovedWorkspaceQualificationError {
    #[error("approved workspace qualification is unavailable")]
    Unavailable,
}

/// Independent qualification evidence for the App -> approved MCP boundary.
/// OCR authorization is deliberately absent: approved MCP consumes only an
/// already-human-approved immutable generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovedMcpQualificationSnapshotV1 {
    pub evidence_id: String,
    pub evidence_sha256: Sha256Hex,
    pub stdio_canary_passed: bool,
    pub streamable_http_canary_passed: bool,
    pub exact_app_policy_binding: bool,
    pub exact_server_key_binding: bool,
    pub mcp_binary_path_identity_sha256: Sha256Hex,
    pub mcp_binary_file_identity_sha256: Sha256Hex,
    pub mcp_binary_sha256: Sha256Hex,
    pub mcp_binary_version: String,
    pub app_version: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub server_key_id: String,
    pub server_key_version: u64,
    pub revocation_epoch: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub revoked: bool,
}

impl ApprovedMcpQualificationSnapshotV1 {
    pub fn approved_workspace_qualified_at(&self, now_unix: u64) -> bool {
        self.evidence_id
            .strip_prefix("mcpq_")
            .is_some_and(|suffix| {
                suffix.len() == 32
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            && self.stdio_canary_passed
            && self.streamable_http_canary_passed
            && self.exact_app_policy_binding
            && self.exact_server_key_binding
            && !self.mcp_binary_version.is_empty()
            && !self.app_version.is_empty()
            && !self.policy_id.is_empty()
            && self.policy_version > 0
            && !self.server_key_id.is_empty()
            && self.server_key_version > 0
            && self.issued_at_unix > 0
            && self.issued_at_unix <= now_unix
            && now_unix < self.expires_at_unix
            && !self.revoked
    }
}
/// The desktop host must remeasure or reload signed qualification evidence for
/// every call. A one-time boolean or startup-only snapshot is not sufficient.
pub trait ApprovedWorkspaceQualificationProvider: Send + Sync {
    fn current_qualification(
        &self,
        now_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError>;
}

struct ApprovedWorkspaceBackendInner {
    qualification: Arc<dyn ApprovedWorkspaceQualificationProvider>,
    approved: ApprovedWorkspaceService,
    work_product_publisher: WorkProductPublisher,
    work_products: WorkProductService,
    tickets: McpAccessTicketStore,
    transport: McpTransportBindingV1,
    session_id: String,
    cursors: ApprovedCursorCodec,
}

/// Cloneable execution capability injected by the desktop host only after it
/// has opened the exact approved workspace and ticket database.
#[derive(Clone)]
pub struct ApprovedWorkspaceBackend {
    inner: Arc<ApprovedWorkspaceBackendInner>,
}

impl fmt::Debug for ApprovedWorkspaceBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovedWorkspaceBackend")
            .field(
                "workspace_instance_id",
                self.inner.tickets.workspace_instance_id(),
            )
            .field(
                "server_instance_id",
                &self.inner.tickets.server_instance_id(),
            )
            .field("transport", &self.inner.transport)
            .field("session_id", &"[BOUND]")
            .finish()
    }
}

impl ApprovedWorkspaceBackend {
    #[allow(clippy::too_many_arguments)]
    pub fn initialize(
        qualification: Arc<dyn ApprovedWorkspaceQualificationProvider>,
        approved: ApprovedWorkspaceService,
        work_product_publisher: WorkProductPublisher,
        work_products: WorkProductService,
        tickets: McpAccessTicketStore,
        transport: McpTransportBindingV1,
        session_id: impl Into<String>,
        now_unix: u64,
    ) -> Result<Self, ApprovedBackendInitError> {
        let session_id = session_id.into();
        if now_unix == 0 || !valid_session_binding(&session_id) {
            return Err(ApprovedBackendInitError::InvalidBinding);
        }
        if work_product_publisher.workspace_instance_id() != tickets.workspace_instance_id()
            || work_products.workspace_instance_id() != tickets.workspace_instance_id()
        {
            return Err(ApprovedBackendInitError::WorkspaceBindingMismatch);
        }
        approved
            .recover(now_unix)
            .map_err(|_| ApprovedBackendInitError::RecoveryFailed)?;
        work_product_publisher
            .recover(&approved)
            .map_err(|_| ApprovedBackendInitError::RecoveryFailed)?;
        Ok(Self {
            inner: Arc::new(ApprovedWorkspaceBackendInner {
                qualification,
                approved,
                work_product_publisher,
                work_products,
                tickets,
                transport,
                session_id,
                cursors: ApprovedCursorCodec::new(),
            }),
        })
    }

    pub fn workspace_instance_id(&self) -> &privacy::vnext::WorkspaceInstanceId {
        self.inner.tickets.workspace_instance_id()
    }

    pub fn server_instance_id(&self) -> &str {
        self.inner.tickets.server_instance_id()
    }

    pub fn transport(&self) -> McpTransportBindingV1 {
        self.inner.transport
    }

    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    /// Build the exact request claims the desktop ticket issuer must sign.
    /// The signing key remains owned by `McpAccessTicketStore`; this helper has
    /// no fallback key and does not issue a token by itself.
    pub fn ticket_request(
        &self,
        tool_name: &str,
        business_arguments: &JsonObject,
        issued_at_unix: u64,
        expires_at_unix: u64,
    ) -> Result<McpAccessTicketRequestV1, ApprovedBackendInitError> {
        let request = make_access_ticket_request(
            &self.inner.tickets,
            self.inner.transport,
            &self.inner.session_id,
            tool_name,
            business_arguments,
            issued_at_unix,
            expires_at_unix,
        )?;
        let operation = self
            .inner
            .approved
            .acquire_operation_guard()
            .map_err(|_| ApprovedBackendInitError::InvalidBinding)?;
        self.preflight_access_target_locked(&operation, &request.target, issued_at_unix)
            .map_err(|_| ApprovedBackendInitError::InvalidBinding)?;
        Ok(request)
    }

    pub(crate) fn call(
        &self,
        tool_name: &str,
        access_ticket: &str,
        business_arguments: JsonObject,
    ) -> CallToolResult {
        let now_unix = now_seconds();
        let qualified = if now_unix == 0 {
            false
        } else {
            self.inner
                .qualification
                .current_qualification(now_unix)
                .is_ok_and(|snapshot| snapshot.approved_workspace_qualified_at(now_unix))
        };
        if !qualified {
            return approved_unavailable();
        }
        let binding = match bind_business_request(tool_name, &business_arguments) {
            Ok(binding) => binding,
            Err(code) => return approved_error(code),
        };
        let verification = McpTicketVerificationContextV1 {
            workspace_instance_id: self.inner.tickets.workspace_instance_id().clone(),
            server_instance_id: self.inner.tickets.server_instance_id().to_owned(),
            transport: self.inner.transport,
            session_id: self.inner.session_id.clone(),
            tool_name: tool_name.to_owned(),
            purpose: binding.purpose,
            canonical_request_sha256: binding.canonical_request_sha256,
            target: binding.target,
            now_unix,
        };
        if let Err(error) = self.inner.tickets.consume(access_ticket, &verification) {
            return approved_error(ticket_error_code(error));
        }
        let operation = match self.inner.approved.acquire_operation_guard() {
            Ok(operation) => operation,
            Err(error) => return approved_error(workspace_error_code(error)),
        };
        if let Err(code) =
            self.preflight_access_target_locked(&operation, &verification.target, now_unix)
        {
            return approved_error(code);
        }
        let response =
            match self.dispatch_locked(&operation, tool_name, &business_arguments, now_unix) {
                Ok(data) => approved_success(tool_name, data),
                Err(code) => approved_error(code),
            };
        // Keep the cross-process boundary alive until the complete MCP response has been
        // constructed. A concurrent revoke can therefore only linearize before this call
        // starts reading or after the response no longer depends on workspace state.
        drop(operation);
        response
    }

    /// Revalidates the exact immutable target before issuing or consuming a ticket. Publication
    /// revocation therefore invalidates already-prepared App, stdio, and HTTP calls without
    /// revoking a mixed session that may still legitimately read native-text publications.
    fn preflight_access_target_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        target: &McpAccessTargetV1,
        now_unix: u64,
    ) -> Result<(), &'static str> {
        match (
            target.case_id.as_ref(),
            target.material_id.as_ref(),
            target.publication_id.as_ref(),
        ) {
            (Some(case_id), Some(material_id), Some(publication_id)) => {
                let verified = self
                    .inner
                    .approved
                    .read_publication_locked(
                        operation,
                        case_id,
                        material_id,
                        publication_id,
                        now_unix,
                        Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                        Some(APPROVED_MATERIAL_READ_PURPOSE),
                    )
                    .map_err(workspace_error_code)?;
                self.require_workspace(verified.summary().workspace_instance_id.as_str())?;
            }
            (_, Some(_), _) | (_, _, Some(_)) => return Err("INVALID_REQUEST"),
            _ => {}
        }
        match (
            target.case_id.as_ref(),
            target.work_product_id.as_ref(),
            target.version,
        ) {
            (Some(case_id), Some(work_product_id), Some(version)) => {
                self.inner
                    .work_products
                    .read_locked(
                        operation,
                        case_id,
                        work_product_id,
                        version,
                        &self.inner.approved,
                        now_unix,
                    )
                    .map_err(work_product_error_code)?;
            }
            (_, Some(_), _) | (_, _, Some(_)) => return Err("INVALID_REQUEST"),
            _ => {}
        }
        Ok(())
    }

    fn dispatch_locked(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        tool_name: &str,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        match tool_name {
            "case_list" => self.case_list(operation, arguments, now_unix),
            "case_get_public_metadata" => self.case_metadata(operation, arguments, now_unix),
            "case_list_approved_materials" => self.case_materials(operation, arguments, now_unix),
            "case_read_approved_material" => self.read_material(operation, arguments, now_unix),
            "case_search_approved_materials" => {
                self.search_materials(operation, arguments, now_unix)
            }
            "case_list_work_products" => self.list_work_products(operation, arguments, now_unix),
            "case_read_work_product" => self.read_work_product(operation, arguments, now_unix),
            "case_write_work_product" => self.write_work_product(operation, arguments, now_unix),
            "case_update_work_product" => self.update_work_product(operation, arguments, now_unix),
            "case_export_work_product_manifest" => {
                self.export_work_product_manifest(operation, arguments, now_unix)
            }
            _ => Err("UNKNOWN_TOOL"),
        }
    }

    fn case_list(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let cases = self
            .inner
            .approved
            .list_cases_locked(operation, now_unix)
            .map_err(workspace_error_code)?;
        let values = cases
            .into_iter()
            .map(|item| {
                json!({
                    "case_id": item.case_id,
                    "approved_material_count": item.approved_material_count
                })
            })
            .collect::<Vec<_>>();
        let (items, next_cursor) = self.page(arguments, "case_list", None, values, now_unix)?;
        Ok(json!({"items":items,"next_cursor":next_cursor}))
    }

    fn case_metadata(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let materials = self.verified_material_summaries(operation, &case_id, now_unix)?;
        if materials.is_empty() {
            return Err("CASE_NOT_AVAILABLE");
        }
        let work_products = self
            .inner
            .work_products
            .list_case_locked(operation, &case_id, &self.inner.approved, now_unix)
            .map_err(work_product_error_code)?;
        Ok(json!({
            "case_id":case_id,
            "approved_material_count":materials.len(),
            "work_product_count":work_products.len()
        }))
    }

    fn case_materials(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let summaries = self.verified_material_summaries(operation, &case_id, now_unix)?;
        let values = summaries
            .into_iter()
            .map(material_summary_json)
            .collect::<Vec<_>>();
        let (items, next_cursor) = self.page(
            arguments,
            "case_list_approved_materials",
            Some(&case_id),
            values,
            now_unix,
        )?;
        Ok(json!({"case_id":case_id,"items":items,"next_cursor":next_cursor}))
    }

    fn read_material(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let material_id = parse_material_id(arguments)?;
        let publication_id = parse_publication_id(arguments)?;
        let verified = self
            .inner
            .approved
            .read_publication_locked(
                operation,
                &case_id,
                &material_id,
                &publication_id,
                now_unix,
                Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                Some(APPROVED_MATERIAL_READ_PURPOSE),
            )
            .map_err(workspace_error_code)?;
        self.require_workspace(verified.summary().workspace_instance_id.as_str())?;
        let content =
            std::str::from_utf8(verified.content()).map_err(|_| "APPROVED_CONTENT_INVALID")?;
        let summary = verified.summary();
        Ok(json!({
            "classification":"CASE_REDACTED_APPROVED",
            "case_id":summary.case_id,
            "material_id":summary.material_id,
            "document_version":summary.document_version,
            "publication_id":summary.publication_id,
            "content_media_type":summary.content_media_type,
            "content_sha256":summary.content_sha256,
            "manifest_sha256":summary.manifest_sha256,
            "expires_at_unix":summary.expires_at_unix,
            "content":content
        }))
    }

    fn search_materials(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let query = string_argument(arguments, "query")?;
        let normalized_query = query.to_lowercase();
        let summaries = self.verified_material_summaries(operation, &case_id, now_unix)?;
        let mut matches = Vec::new();
        for summary in summaries {
            let verified = self
                .inner
                .approved
                .read_publication_locked(
                    operation,
                    &case_id,
                    &summary.material_id,
                    &summary.publication_id,
                    now_unix,
                    Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                    Some(APPROVED_MATERIAL_READ_PURPOSE),
                )
                .map_err(workspace_error_code)?;
            let content =
                std::str::from_utf8(verified.content()).map_err(|_| "APPROVED_CONTENT_INVALID")?;
            let count = content
                .to_lowercase()
                .match_indices(&normalized_query)
                .count();
            if count > 0 {
                matches.push(json!({
                    "material_id":summary.material_id,
                    "document_version":summary.document_version,
                    "publication_id":summary.publication_id,
                    "match_count":count
                }));
            }
        }
        let (items, next_cursor) = self.page(
            arguments,
            "case_search_approved_materials",
            Some(&case_id),
            matches,
            now_unix,
        )?;
        Ok(json!({"case_id":case_id,"items":items,"next_cursor":next_cursor}))
    }

    fn list_work_products(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let summaries = self
            .inner
            .work_products
            .list_case_locked(operation, &case_id, &self.inner.approved, now_unix)
            .map_err(work_product_error_code)?;
        let values = summaries
            .into_iter()
            .map(|summary| {
                json!({
                    "case_id":summary.case_id,
                    "work_product_id":summary.work_product_id,
                    "version":summary.version,
                    "task_type":summary.task_type,
                    "status":summary.status,
                    "manifest_sha256":summary.manifest_sha256,
                    "content_sha256":summary.content_sha256,
                    "created_at_unix":summary.created_at_unix
                })
            })
            .collect::<Vec<_>>();
        let (items, next_cursor) = self.page(
            arguments,
            "case_list_work_products",
            Some(&case_id),
            values,
            now_unix,
        )?;
        Ok(json!({"case_id":case_id,"items":items,"next_cursor":next_cursor}))
    }

    fn read_work_product(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let work_product_id = parse_work_product_id(arguments)?;
        let version = u64_argument(arguments, "version")?;
        let verified = self
            .inner
            .work_products
            .read_locked(
                operation,
                &case_id,
                &work_product_id,
                version,
                &self.inner.approved,
                now_unix,
            )
            .map_err(work_product_error_code)?;
        let content =
            std::str::from_utf8(verified.content()).map_err(|_| "WORK_PRODUCT_CONTENT_INVALID")?;
        let claims = &verified.manifest().claims;
        let sources = claims
            .source_approved_refs
            .iter()
            .map(|source| {
                json!({
                    "material_id":source.material_id,
                    "document_version":source.document_version,
                    "publication_id":source.publication_id,
                    "manifest_sha256":source.manifest_sha256
                })
            })
            .collect::<Vec<_>>();
        Ok(json!({
            "classification":"CASE_REDACTED_APPROVED",
            "case_id":claims.case_id,
            "work_product_id":claims.work_product_id,
            "version":claims.version,
            "task_type":claims.task_type,
            "status":claims.status,
            "source_approved_refs":sources,
            "content_media_type":claims.content_media_type,
            "content_sha256":claims.content_sha256,
            "manifest_sha256":verified.manifest_sha256(),
            "created_at_unix":claims.created_at_unix,
            "content":content
        }))
    }

    fn write_work_product(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let sources = self.resolve_sources(operation, arguments, &case_id, now_unix)?;
        let request = WorkProductWriteV1 {
            task_type: string_argument(arguments, "task_type")?.to_owned(),
            status: string_argument(arguments, "status")?.to_owned(),
            source_approved_refs: sources,
            content_media_type: string_argument(arguments, "content_media_type")?.to_owned(),
            placeholder_policy_version: PLACEHOLDER_POLICY_VERSION.to_owned(),
            author_tool: "case_write_work_product".to_owned(),
            author_tool_version: AUTHOR_TOOL_VERSION.to_owned(),
            idempotency_key: string_argument(arguments, "idempotency_key")?.to_owned(),
        };
        let content = string_argument(arguments, "content")?.as_bytes();
        let published = self
            .inner
            .work_product_publisher
            .create_locked(
                operation,
                &case_id,
                request,
                content,
                &self.inner.approved,
                now_unix,
            )
            .map_err(work_product_error_code)?;
        Ok(published_json(published))
    }

    fn update_work_product(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let work_product_id = parse_work_product_id(arguments)?;
        let expected_parent_version = u64_argument(arguments, "expected_parent_version")?;
        let prior = self
            .inner
            .work_products
            .read_locked(
                operation,
                &case_id,
                &work_product_id,
                expected_parent_version,
                &self.inner.approved,
                now_unix,
            )
            .map_err(work_product_error_code)?;
        let sources = self.resolve_sources(operation, arguments, &case_id, now_unix)?;
        let request = WorkProductWriteV1 {
            task_type: prior.manifest().claims.task_type.clone(),
            status: string_argument(arguments, "status")?.to_owned(),
            source_approved_refs: sources,
            content_media_type: string_argument(arguments, "content_media_type")?.to_owned(),
            placeholder_policy_version: PLACEHOLDER_POLICY_VERSION.to_owned(),
            author_tool: "case_update_work_product".to_owned(),
            author_tool_version: AUTHOR_TOOL_VERSION.to_owned(),
            idempotency_key: string_argument(arguments, "idempotency_key")?.to_owned(),
        };
        let content = string_argument(arguments, "content")?.as_bytes();
        let published = self
            .inner
            .work_product_publisher
            .update_locked(
                operation,
                &case_id,
                &work_product_id,
                expected_parent_version,
                request,
                content,
                &self.inner.approved,
                now_unix,
            )
            .map_err(work_product_error_code)?;
        Ok(published_json(published))
    }

    fn export_work_product_manifest(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        now_unix: u64,
    ) -> Result<Value, &'static str> {
        let case_id = parse_case_id(arguments)?;
        let work_product_id = parse_work_product_id(arguments)?;
        let version = u64_argument(arguments, "version")?;
        let manifest = self
            .inner
            .work_products
            .export_manifest_locked(
                operation,
                &case_id,
                &work_product_id,
                version,
                &self.inner.approved,
                now_unix,
            )
            .map_err(work_product_error_code)?;
        let canonical =
            canonical_json_v1(&manifest).map_err(|_| "WORK_PRODUCT_MANIFEST_INVALID")?;
        Ok(json!({
            "case_id":case_id,
            "work_product_id":work_product_id,
            "version":version,
            "manifest_sha256":sha256_hex(&canonical),
            "manifest":manifest
        }))
    }

    fn resolve_sources(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        arguments: &JsonObject,
        case_id: &CaseId,
        now_unix: u64,
    ) -> Result<Vec<ApprovedMaterialRefV1>, &'static str> {
        let values = arguments
            .get("source_approved_refs")
            .and_then(Value::as_array)
            .ok_or("INVALID_REQUEST")?;
        let mut sources = Vec::with_capacity(values.len());
        for value in values {
            let object = value.as_object().ok_or("INVALID_REQUEST")?;
            let material_id = object
                .get("material_id")
                .and_then(Value::as_str)
                .ok_or("INVALID_REQUEST")?;
            let publication_id = object
                .get("publication_id")
                .and_then(Value::as_str)
                .ok_or("INVALID_REQUEST")?;
            let material_id =
                MaterialId::parse(material_id.to_owned()).map_err(|_| "INVALID_REQUEST")?;
            let publication_id =
                PublicationId::parse(publication_id.to_owned()).map_err(|_| "INVALID_REQUEST")?;
            let verified = self
                .inner
                .approved
                .read_publication_locked(
                    operation,
                    case_id,
                    &material_id,
                    &publication_id,
                    now_unix,
                    Some(APPROVED_WORKSPACE_DESTINATION_SCOPE),
                    Some(APPROVED_MATERIAL_READ_PURPOSE),
                )
                .map_err(workspace_error_code)?;
            self.require_workspace(verified.summary().workspace_instance_id.as_str())?;
            sources.push(ApprovedMaterialRefV1 {
                material_id,
                document_version: verified.summary().document_version,
                publication_id,
                manifest_sha256: verified.summary().manifest_sha256.clone(),
            });
        }
        Ok(sources)
    }

    fn verified_material_summaries(
        &self,
        operation: &ApprovedWorkspaceOperationGuard,
        case_id: &CaseId,
        now_unix: u64,
    ) -> Result<Vec<privacy::workspace::ApprovedMaterialSummaryV1>, &'static str> {
        let summaries = self
            .inner
            .approved
            .list_case_materials_locked(operation, case_id, now_unix)
            .map_err(workspace_error_code)?;
        for summary in &summaries {
            self.require_workspace(summary.workspace_instance_id.as_str())?;
        }
        Ok(summaries)
    }

    fn require_workspace(&self, actual: &str) -> Result<(), &'static str> {
        if actual == self.inner.tickets.workspace_instance_id().as_str() {
            Ok(())
        } else {
            Err("WORKSPACE_BINDING_MISMATCH")
        }
    }

    fn page(
        &self,
        arguments: &JsonObject,
        tool_name: &str,
        case_id: Option<&CaseId>,
        values: Vec<Value>,
        now_unix: u64,
    ) -> Result<(Vec<Value>, Option<String>), &'static str> {
        let limit = arguments.get("limit").and_then(Value::as_u64).unwrap_or(50);
        let limit = usize::try_from(limit).map_err(|_| "INVALID_REQUEST")?;
        let offset = match arguments.get("cursor") {
            Some(Value::String(cursor)) => self
                .inner
                .cursors
                .decode(cursor, tool_name, case_id, now_unix)?,
            Some(Value::Null) | None => 0,
            _ => return Err("INVALID_CURSOR"),
        };
        if offset > values.len() {
            return Err("INVALID_CURSOR");
        }
        let end = offset.saturating_add(limit).min(values.len());
        let page = values[offset..end].to_vec();
        let next = if end < values.len() {
            Some(
                self.inner
                    .cursors
                    .encode(tool_name, case_id, end, now_unix)?,
            )
        } else {
            None
        };
        Ok((page, next))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn make_access_ticket_request(
    tickets: &McpAccessTicketStore,
    transport: McpTransportBindingV1,
    session_id: &str,
    tool_name: &str,
    business_arguments: &JsonObject,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> Result<McpAccessTicketRequestV1, ApprovedBackendInitError> {
    if !valid_session_binding(session_id)
        || !approved_workspace::request_is_valid(tool_name, business_arguments)
    {
        return Err(ApprovedBackendInitError::InvalidBinding);
    }
    let binding = bind_business_request(tool_name, business_arguments)
        .map_err(|_| ApprovedBackendInitError::InvalidBinding)?;
    Ok(McpAccessTicketRequestV1 {
        workspace_instance_id: tickets.workspace_instance_id().clone(),
        server_instance_id: tickets.server_instance_id().to_owned(),
        transport,
        session_id: session_id.to_owned(),
        tool_name: tool_name.to_owned(),
        purpose: binding.purpose,
        canonical_request_sha256: binding.canonical_request_sha256,
        target: binding.target,
        issued_at_unix,
        expires_at_unix,
    })
}

struct BusinessRequestBinding {
    purpose: String,
    canonical_request_sha256: Sha256Hex,
    target: McpAccessTargetV1,
}

fn bind_business_request(
    tool_name: &str,
    arguments: &JsonObject,
) -> Result<BusinessRequestBinding, &'static str> {
    if !approved_workspace::request_is_valid(tool_name, arguments) {
        return Err("INVALID_REQUEST");
    }
    let canonical =
        canonical_json_v1(&Value::Object(arguments.clone())).map_err(|_| "INVALID_REQUEST")?;
    let canonical_request_sha256 =
        Sha256Hex::parse(sha256_hex(&canonical)).map_err(|_| "INVALID_REQUEST")?;
    let mut target = McpAccessTargetV1::default();
    if tool_name != "case_list" {
        target.case_id = Some(parse_case_id(arguments)?);
    }
    match tool_name {
        "case_read_approved_material" => {
            target.material_id = Some(parse_material_id(arguments)?);
            target.publication_id = Some(parse_publication_id(arguments)?);
        }
        "case_read_work_product" | "case_export_work_product_manifest" => {
            target.work_product_id = Some(parse_work_product_id(arguments)?);
            target.version = Some(u64_argument(arguments, "version")?);
        }
        "case_update_work_product" => {
            target.work_product_id = Some(parse_work_product_id(arguments)?);
            target.version = Some(u64_argument(arguments, "expected_parent_version")?);
        }
        _ => {}
    }
    Ok(BusinessRequestBinding {
        purpose: format!("mcp.{tool_name}.v1"),
        canonical_request_sha256,
        target,
    })
}

fn parse_case_id(arguments: &JsonObject) -> Result<CaseId, &'static str> {
    CaseId::parse(string_argument(arguments, "case_id")?.to_owned()).map_err(|_| "INVALID_REQUEST")
}

fn parse_material_id(arguments: &JsonObject) -> Result<MaterialId, &'static str> {
    MaterialId::parse(string_argument(arguments, "material_id")?.to_owned())
        .map_err(|_| "INVALID_REQUEST")
}

fn parse_publication_id(arguments: &JsonObject) -> Result<PublicationId, &'static str> {
    PublicationId::parse(string_argument(arguments, "publication_id")?.to_owned())
        .map_err(|_| "INVALID_REQUEST")
}

fn parse_work_product_id(arguments: &JsonObject) -> Result<WorkProductId, &'static str> {
    WorkProductId::parse(string_argument(arguments, "work_product_id")?.to_owned())
        .map_err(|_| "INVALID_REQUEST")
}

fn string_argument<'a>(arguments: &'a JsonObject, name: &str) -> Result<&'a str, &'static str> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or("INVALID_REQUEST")
}

fn u64_argument(arguments: &JsonObject, name: &str) -> Result<u64, &'static str> {
    arguments
        .get(name)
        .and_then(Value::as_u64)
        .ok_or("INVALID_REQUEST")
}

fn material_summary_json(summary: privacy::workspace::ApprovedMaterialSummaryV1) -> Value {
    json!({
        "case_id":summary.case_id,
        "material_id":summary.material_id,
        "document_version":summary.document_version,
        "publication_id":summary.publication_id,
        "content_media_type":summary.content_media_type,
        "content_sha256":summary.content_sha256,
        "manifest_sha256":summary.manifest_sha256,
        "expires_at_unix":summary.expires_at_unix
    })
}

fn published_json(published: PublishedWorkProductV1) -> Value {
    json!({
        "case_id":published.case_id,
        "work_product_id":published.work_product_id,
        "version":published.version,
        "manifest_sha256":published.manifest_sha256,
        "content_sha256":published.content_sha256,
        "replayed":published.replayed
    })
}

fn approved_success(tool_name: &str, data: Value) -> CallToolResult {
    let envelope = json!({
        "schema_version":1,
        "status":"success",
        "tool":tool_name,
        "data":data
    });
    checked_result(envelope, false)
}

pub(crate) fn approved_broker_error_result(reason_code: &'static str) -> CallToolResult {
    approved_error(reason_code)
}

fn approved_error(reason_code: &'static str) -> CallToolResult {
    let envelope = json!({
        "schema_version":1,
        "status":"error",
        "reason_code":reason_code
    });
    checked_result(envelope, true)
}

fn approved_unavailable() -> CallToolResult {
    let envelope = json!({
        "schema_version":1,
        "status":"unavailable",
        "reason_code":"PROFILE_NOT_QUALIFIED"
    });
    checked_result(envelope, true)
}

fn checked_result(envelope: Value, is_error: bool) -> CallToolResult {
    let structured = match serde_json::to_vec(&envelope) {
        Ok(value) if value.len() <= MAX_APPROVED_RESULT_BYTES => value,
        _ => return egress_blocked_result("RESULT_TOO_LARGE"),
    };
    let structured_scan = scan_residual(&structured);
    if !matches!(structured_scan, Ok(scan) if scan.passed) {
        return egress_blocked_result("EGRESS_BLOCKED");
    }
    let text = match serde_json::to_string(&envelope) {
        Ok(value) => value,
        Err(_) => return egress_blocked_result("EGRESS_BLOCKED"),
    };
    let text_scan = scan_residual(text.as_bytes());
    if !matches!(text_scan, Ok(scan) if scan.passed) {
        return egress_blocked_result("EGRESS_BLOCKED");
    }
    let mut result = if is_error {
        CallToolResult::structured_error(envelope)
    } else {
        CallToolResult::structured(envelope)
    };
    result.content = vec![ContentBlock::text(text)];
    result
}

fn egress_blocked_result(reason_code: &'static str) -> CallToolResult {
    let envelope = json!({"schema_version":1,"status":"error","reason_code":reason_code});
    let mut result = CallToolResult::structured_error(envelope);
    result.content = vec![ContentBlock::text(format!(
        "Approved workspace request failed: {reason_code}."
    ))];
    result
}

fn ticket_error_code(error: McpTicketError) -> &'static str {
    match error {
        McpTicketError::TicketExpired => "ACCESS_TICKET_EXPIRED",
        McpTicketError::TicketRevoked => "ACCESS_TICKET_REVOKED",
        McpTicketError::TicketReplayed => "ACCESS_TICKET_REPLAYED",
        McpTicketError::BindingMismatch => "ACCESS_TICKET_BINDING_MISMATCH",
        McpTicketError::DatabaseFailed
        | McpTicketError::PlatformUnavailable
        | McpTicketError::InvalidRoot
        | McpTicketError::UnsafeFilesystem => "ACCESS_TICKET_UNAVAILABLE",
        McpTicketError::InvalidInput | McpTicketError::InvalidTicket => "ACCESS_TICKET_INVALID",
    }
}

fn workspace_error_code(error: WorkspaceError) -> &'static str {
    match error {
        WorkspaceError::PublicationNotAvailable => "APPROVED_MATERIAL_NOT_AVAILABLE",
        WorkspaceError::PublicationExpired => "APPROVED_MATERIAL_EXPIRED",
        WorkspaceError::PublicationRevoked => "APPROVED_MATERIAL_REVOKED",
        WorkspaceError::DestinationMismatch => "APPROVED_MATERIAL_SCOPE_MISMATCH",
        WorkspaceError::PurposeMismatch => "APPROVED_MATERIAL_PURPOSE_MISMATCH",
        WorkspaceError::ResidualSensitiveContent => "APPROVED_MATERIAL_RESIDUAL_DETECTED",
        WorkspaceError::SignatureInvalid => "APPROVED_MATERIAL_SIGNATURE_INVALID",
        WorkspaceError::ContentMismatch => "APPROVED_MATERIAL_CONTENT_MISMATCH",
        WorkspaceError::ManifestInvalid => "APPROVED_MATERIAL_MANIFEST_INVALID",
        WorkspaceError::InvalidInput | WorkspaceError::ContentTooLarge => "INVALID_REQUEST",
        WorkspaceError::AlreadyExists => "APPROVED_GENERATION_ALREADY_EXISTS",
        WorkspaceError::PlatformUnavailable
        | WorkspaceError::InvalidRoot
        | WorkspaceError::UnsafeFilesystem
        | WorkspaceError::DatabaseFailed
        | WorkspaceError::IoFailed
        | WorkspaceError::RecoveryFailed => "APPROVED_WORKSPACE_UNAVAILABLE",
    }
}

fn work_product_error_code(error: WorkProductError) -> &'static str {
    match error {
        WorkProductError::ResidualSensitiveContent => "WORK_PRODUCT_RESIDUAL_DETECTED",
        WorkProductError::ApprovedSourceUnavailable => "APPROVED_SOURCE_NOT_AVAILABLE",
        WorkProductError::ApprovedSourceStale => "APPROVED_SOURCE_STALE",
        WorkProductError::ManifestInvalid => "WORK_PRODUCT_MANIFEST_INVALID",
        WorkProductError::SignatureInvalid => "WORK_PRODUCT_SIGNATURE_INVALID",
        WorkProductError::ContentMismatch => "WORK_PRODUCT_CONTENT_MISMATCH",
        WorkProductError::VersionConflict => "WORK_PRODUCT_VERSION_CONFLICT",
        WorkProductError::IdempotencyConflict => "WORK_PRODUCT_IDEMPOTENCY_CONFLICT",
        WorkProductError::AlreadyExists => "WORK_PRODUCT_ALREADY_EXISTS",
        WorkProductError::NotAvailable => "WORK_PRODUCT_NOT_AVAILABLE",
        WorkProductError::Revoked => "WORK_PRODUCT_REVOKED",
        WorkProductError::InvalidInput | WorkProductError::ContentTooLarge => "INVALID_REQUEST",
        WorkProductError::PlatformUnavailable
        | WorkProductError::InvalidRoot
        | WorkProductError::UnsafeFilesystem
        | WorkProductError::DatabaseFailed
        | WorkProductError::IoFailed
        | WorkProductError::RecoveryFailed => "WORK_PRODUCT_UNAVAILABLE",
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CursorClaimsV1 {
    schema_version: u8,
    tool_name: String,
    case_id: Option<CaseId>,
    offset: u64,
    expires_at_unix: u64,
}

struct ApprovedCursorCodec {
    key: [u8; 32],
}

impl ApprovedCursorCodec {
    fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(Uuid::new_v4().as_bytes());
        hasher.update(Uuid::new_v4().as_bytes());
        hasher.update(now_seconds().to_le_bytes());
        Self {
            key: hasher.finalize().into(),
        }
    }

    fn encode(
        &self,
        tool_name: &str,
        case_id: Option<&CaseId>,
        offset: usize,
        now_unix: u64,
    ) -> Result<String, &'static str> {
        let claims = CursorClaimsV1 {
            schema_version: 1,
            tool_name: tool_name.to_owned(),
            case_id: case_id.cloned(),
            offset: u64::try_from(offset).map_err(|_| "INVALID_CURSOR")?,
            expires_at_unix: now_unix.saturating_add(CURSOR_TTL_SECONDS),
        };
        let canonical = canonical_json_v1(&claims).map_err(|_| "INVALID_CURSOR")?;
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| "INVALID_CURSOR")?;
        mac.update(&canonical);
        let signature = mac.finalize().into_bytes();
        let token = format!(
            "cur_{}_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical),
            hex(&signature)
        );
        if token.len() > MAX_CURSOR_BYTES {
            return Err("INVALID_CURSOR");
        }
        Ok(token)
    }

    fn decode(
        &self,
        token: &str,
        tool_name: &str,
        case_id: Option<&CaseId>,
        now_unix: u64,
    ) -> Result<usize, &'static str> {
        let suffix = token.strip_prefix("cur_").ok_or("INVALID_CURSOR")?;
        if suffix.len() <= 65 {
            return Err("INVALID_CURSOR");
        }
        let split = suffix.len() - 65;
        if suffix.as_bytes().get(split) != Some(&b'_') {
            return Err("INVALID_CURSOR");
        }
        let canonical = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&suffix[..split])
            .map_err(|_| "INVALID_CURSOR")?;
        let signature = decode_hex(&suffix[split + 1..]).ok_or("INVALID_CURSOR")?;
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| "INVALID_CURSOR")?;
        mac.update(&canonical);
        mac.verify_slice(&signature).map_err(|_| "INVALID_CURSOR")?;
        let claims: CursorClaimsV1 =
            strict_json_v1_from_slice(&canonical).map_err(|_| "INVALID_CURSOR")?;
        if canonical_json_v1(&claims).map_err(|_| "INVALID_CURSOR")? != canonical
            || claims.schema_version != 1
            || claims.tool_name != tool_name
            || claims.case_id.as_ref() != case_id
            || now_unix >= claims.expires_at_unix
            || claims.offset == 0
        {
            return Err("INVALID_CURSOR");
        }
        usize::try_from(claims.offset).map_err(|_| "INVALID_CURSOR")
    }
}

impl Drop for ApprovedCursorCodec {
    fn drop(&mut self) {
        self.key.fill(0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(text, 16).ok()
        })
        .collect()
}

fn valid_session_binding(value: &str) -> bool {
    (16..=160).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::config::{BearerSecret, Command, Limits, ResolvedConfig};
    use crate::http::build_router;
    use crate::{
        handler::LegalMcpServer,
        registry::{PrivacyProfile, ToolRegistry},
        service_adapter::ServiceAdapter,
        stdio::StableProtocolTransport,
    };
    use legal_services::{LegalServices, ServiceConfig};
    use privacy::{
        mcp_ticket::McpTicketSigningKey,
        vnext::{
            ApprovalMode, ApprovedMaterialManifestV1, ReceiptId, WorkspaceInstanceId,
            WorkspaceIsolationLevel, APPROVED_CLASSIFICATION, APPROVED_MATERIAL_MANIFEST_VERSION,
        },
        workspace::{ManifestSigningKey, WorkspacePublisher},
    };
    use rmcp::{transport::async_rw::AsyncRwTransport, RoleServer, ServiceExt};
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{Read, Write};
    use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, Lines};
    use tokio_util::sync::CancellationToken;

    struct Fixture {
        _root: tempfile::TempDir,
        backend: ApprovedWorkspaceBackend,
        approved_control: ApprovedWorkspaceService,
        tickets: McpAccessTicketStore,
        adapter: ServiceAdapter,
        case_id: CaseId,
        material_id: MaterialId,
        publication_id: PublicationId,
    }

    #[derive(Clone)]
    struct SyntheticQualificationProvider(ApprovedMcpQualificationSnapshotV1);

    impl ApprovedWorkspaceQualificationProvider for SyntheticQualificationProvider {
        fn current_qualification(
            &self,
            _now_unix: u64,
        ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError>
        {
            Ok(self.0.clone())
        }
    }

    fn fixed_id<T>(
        value: &str,
        parse: impl FnOnce(String) -> Result<T, privacy::vnext::VNextSchemaError>,
    ) -> T {
        parse(value.to_owned()).expect("synthetic opaque id")
    }

    fn hash(value: &[u8]) -> Sha256Hex {
        Sha256Hex::parse(sha256_hex(value)).expect("synthetic hash")
    }

    fn object(value: Value) -> JsonObject {
        value.as_object().cloned().expect("JSON object")
    }

    fn qualification(now: u64) -> ApprovedMcpQualificationSnapshotV1 {
        ApprovedMcpQualificationSnapshotV1 {
            evidence_id: "mcpq_00000000000000000000000000000001".to_owned(),
            evidence_sha256: hash(b"synthetic qualification"),
            stdio_canary_passed: true,
            streamable_http_canary_passed: true,
            exact_app_policy_binding: true,
            exact_server_key_binding: true,
            mcp_binary_path_identity_sha256: hash(b"synthetic mcp binary path"),
            mcp_binary_file_identity_sha256: hash(b"synthetic mcp binary file identity"),
            mcp_binary_sha256: hash(b"synthetic mcp binary"),
            mcp_binary_version: env!("CARGO_PKG_VERSION").to_owned(),
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: "approved-mcp-local-egress-v1".to_owned(),
            policy_version: 1,
            server_key_id: "ticket-key-v1".to_owned(),
            server_key_version: 1,
            revocation_epoch: 1,
            issued_at_unix: now.saturating_sub(1),
            expires_at_unix: now + 3_600,
            revoked: false,
        }
    }

    fn fixture(transport: McpTransportBindingV1) -> Fixture {
        let root = tempfile::tempdir().expect("fixture root");
        let now = now_seconds();
        let workspace_instance_id = fixed_id(
            "ws_00000000000000000000000000000001",
            WorkspaceInstanceId::parse,
        );
        let case_id = fixed_id("case_00000000000000000000000000000001", CaseId::parse);
        let material_id = fixed_id("mat_00000000000000000000000000000001", MaterialId::parse);
        let publication_id = fixed_id("pub_00000000000000000000000000000001", PublicationId::parse);
        let receipt_id = fixed_id("rct_00000000000000000000000000000001", ReceiptId::parse);
        let approved_root = root.path().join("approved");
        let work_product_root = root.path().join("work-products");
        let ticket_root = root.path().join("tickets");
        let manifest_key = [0x23_u8; 32];
        let publisher_signer =
            ManifestSigningKey::from_bytes(manifest_key, 1).expect("publisher key");
        let approved_verifier = publisher_signer.verification_key();
        let approved_control_verifier = publisher_signer.verification_key();
        let publisher = WorkspacePublisher::initialize(&approved_root, publisher_signer)
            .expect("approved publisher");
        let content = b"[PERSON_001] synthetic approved material";
        publisher
            .publish(
                ApprovedMaterialManifestV1 {
                    schema_version: APPROVED_MATERIAL_MANIFEST_VERSION.to_owned(),
                    classification: APPROVED_CLASSIFICATION.to_owned(),
                    workspace_instance_id: workspace_instance_id.clone(),
                    case_id: case_id.clone(),
                    material_id: material_id.clone(),
                    document_version: 1,
                    publication_id: publication_id.clone(),
                    content_media_type: "text/plain".to_owned(),
                    content_sha256: hash(content),
                    content_bytes: u64::try_from(content.len()).expect("content length"),
                    source_sha256: hash(b"synthetic source"),
                    source_name_sha256: hash(b"synthetic-source.pdf"),
                    source_revision_hash: hash(b"synthetic source revision"),
                    extraction_sha256: hash(b"synthetic extraction"),
                    ocr_output_sha256: None,
                    finding_summary_hash: hash(b"synthetic findings"),
                    hard_gate_evaluation_hash: hash(b"synthetic gates"),
                    policy_id: "strict".to_owned(),
                    policy_version: 1,
                    policy_sha256: hash(b"synthetic policy"),
                    detector_versions: BTreeMap::from([(
                        "deterministic".to_owned(),
                        "v1".to_owned(),
                    )]),
                    model_versions: BTreeMap::from([(
                        "mineru".to_owned(),
                        "synthetic-v1".to_owned(),
                    )]),
                    worker_sha256: Some(hash(b"synthetic worker")),
                    model_manifest_sha256: Some(hash(b"synthetic model manifest")),
                    qualification_report_id: Some("qualification_synthetic_v1".to_owned()),
                    calibration_evidence_version: Some("synthetic-v1".to_owned()),
                    dictionary_revision_hash: hash(b"synthetic dictionary"),
                    mapping_revision_hash: hash(b"synthetic mapping"),
                    approval_mode: ApprovalMode::Human,
                    readiness_score: 100,
                    unresolved_p0: 0,
                    unresolved_p1: 0,
                    unresolved_p2: 0,
                    destination_scope: APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
                    purpose: APPROVED_MATERIAL_READ_PURPOSE.to_owned(),
                    workspace_isolation_level: WorkspaceIsolationLevel::UserBoundaryOnly,
                    issued_at_unix: now - 1,
                    expires_at_unix: now + 3_600,
                    receipt_id,
                    receipt_nonce: "synthetic-receipt-nonce".to_owned(),
                    revocation_epoch: 0,
                },
                content,
            )
            .expect("publish approved generation");
        let approved = ApprovedWorkspaceService::open(&approved_root, approved_verifier)
            .expect("approved service");
        let approved_control =
            ApprovedWorkspaceService::open(&approved_root, approved_control_verifier)
                .expect("approved control service");
        let work_product_publisher = WorkProductPublisher::initialize(
            &work_product_root,
            workspace_instance_id.clone(),
            ManifestSigningKey::from_bytes(manifest_key, 1).expect("work product key"),
        )
        .expect("work product publisher");
        let work_products = WorkProductService::open(
            &work_product_root,
            workspace_instance_id.clone(),
            ManifestSigningKey::from_bytes(manifest_key, 1)
                .expect("work product verification key source")
                .verification_key(),
        )
        .expect("work product service");
        let tickets = McpAccessTicketStore::initialize(
            &ticket_root,
            McpTicketSigningKey::from_bytes([0x5a; 32], "ticket-key-v1", 1).expect("ticket key"),
            workspace_instance_id,
            format!("srv_{}", "a".repeat(32)),
        )
        .expect("ticket store");
        let backend = ApprovedWorkspaceBackend::initialize(
            Arc::new(SyntheticQualificationProvider(qualification(now))),
            approved,
            work_product_publisher,
            work_products,
            tickets.clone(),
            transport,
            format!("session_{}", "b".repeat(32)),
            now,
        )
        .expect("approved backend");
        let legal = root.path().join("legal.sqlite");
        let user = root.path().join("user.sqlite");
        let materials = root.path().join("materials");
        let output = root.path().join("output");
        std::fs::write(&legal, []).expect("legal placeholder");
        std::fs::write(&user, []).expect("user placeholder");
        std::fs::create_dir(&materials).expect("materials root");
        std::fs::create_dir(&output).expect("output root");
        let services = LegalServices::new(ServiceConfig {
            legal_core_path: legal,
            user_database_path: user,
            allowed_file_roots: vec![materials],
            allowed_output_root: output,
        })
        .expect("legal services");
        let adapter = ServiceAdapter::for_approved_workspace(services, backend.clone());
        Fixture {
            _root: root,
            backend,
            approved_control,
            tickets,
            adapter,
            case_id,
            material_id,
            publication_id,
        }
    }

    fn publish_native_text_generation(fixture: &Fixture) -> (MaterialId, PublicationId) {
        let now = now_seconds();
        let material_id = fixed_id("mat_00000000000000000000000000000002", MaterialId::parse);
        let publication_id = fixed_id("pub_00000000000000000000000000000002", PublicationId::parse);
        let receipt_id = fixed_id("rct_00000000000000000000000000000002", ReceiptId::parse);
        let workspace_instance_id = fixed_id(
            "ws_00000000000000000000000000000001",
            WorkspaceInstanceId::parse,
        );
        let content = b"[PERSON_002] native approved material";
        let signer = ManifestSigningKey::from_bytes([0x23_u8; 32], 1).expect("native signer");
        let publisher =
            WorkspacePublisher::initialize(fixture._root.path().join("approved"), signer)
                .expect("native publisher");
        publisher
            .publish(
                ApprovedMaterialManifestV1 {
                    schema_version: APPROVED_MATERIAL_MANIFEST_VERSION.to_owned(),
                    classification: APPROVED_CLASSIFICATION.to_owned(),
                    workspace_instance_id,
                    case_id: fixture.case_id.clone(),
                    material_id: material_id.clone(),
                    document_version: 1,
                    publication_id: publication_id.clone(),
                    content_media_type: "text/plain".to_owned(),
                    content_sha256: hash(content),
                    content_bytes: u64::try_from(content.len()).expect("native content length"),
                    source_sha256: hash(b"native source"),
                    source_name_sha256: hash(b"native-source.txt"),
                    source_revision_hash: hash(b"native source revision"),
                    extraction_sha256: hash(b"native extraction"),
                    ocr_output_sha256: None,
                    finding_summary_hash: hash(b"native findings"),
                    hard_gate_evaluation_hash: hash(b"native gates"),
                    policy_id: "strict".to_owned(),
                    policy_version: 1,
                    policy_sha256: hash(b"native policy"),
                    detector_versions: BTreeMap::from([(
                        "deterministic".to_owned(),
                        "v1".to_owned(),
                    )]),
                    model_versions: BTreeMap::from([(
                        "processing_chain".to_owned(),
                        "native-v1".to_owned(),
                    )]),
                    worker_sha256: None,
                    model_manifest_sha256: None,
                    qualification_report_id: Some("native-text-qualified-v1".to_owned()),
                    calibration_evidence_version: None,
                    dictionary_revision_hash: hash(b"synthetic dictionary"),
                    mapping_revision_hash: hash(b"native mapping"),
                    approval_mode: ApprovalMode::Human,
                    readiness_score: 100,
                    unresolved_p0: 0,
                    unresolved_p1: 0,
                    unresolved_p2: 0,
                    destination_scope: APPROVED_WORKSPACE_DESTINATION_SCOPE.to_owned(),
                    purpose: APPROVED_MATERIAL_READ_PURPOSE.to_owned(),
                    workspace_isolation_level: WorkspaceIsolationLevel::UserBoundaryOnly,
                    issued_at_unix: now - 1,
                    expires_at_unix: now + 3_600,
                    receipt_id,
                    receipt_nonce: "native-receipt-nonce".to_owned(),
                    revocation_epoch: 0,
                },
                content,
            )
            .expect("publish native generation");
        (material_id, publication_id)
    }

    async fn call(fixture: &Fixture, tool_name: &str, business: JsonObject) -> Value {
        let now = now_seconds();
        let request = fixture
            .backend
            .ticket_request(tool_name, &business, now, now + 60)
            .expect("ticket request");
        let ticket = fixture.tickets.issue(request).expect("issue ticket");
        let mut arguments = business;
        arguments.insert("access_ticket".to_owned(), json!(ticket));
        call_prepared(fixture, tool_name, arguments).await
    }

    async fn call_prepared(fixture: &Fixture, tool_name: &str, arguments: JsonObject) -> Value {
        let result = fixture
            .adapter
            .call(tool_name, Some(arguments))
            .await
            .expect("tool call");
        serde_json::to_value(result).expect("tool response")
    }

    fn data(response: &Value) -> &Value {
        assert_eq!(response["isError"], false, "{response:#}");
        assert_eq!(
            response["structuredContent"]["status"], "success",
            "{response:#}"
        );
        &response["structuredContent"]["data"]
    }

    fn assert_error_without_content(
        response: &Value,
        expected_reason: &str,
        forbidden_content: &[&str],
    ) {
        assert_eq!(response["isError"], true, "{response:#}");
        assert_eq!(
            response["structuredContent"]["status"], "error",
            "{response:#}"
        );
        assert_eq!(
            response["structuredContent"]["reason_code"], expected_reason,
            "{response:#}"
        );
        assert!(
            response["structuredContent"].get("data").is_none(),
            "error response must not carry a data payload: {response:#}"
        );
        let serialized = serde_json::to_string(response).expect("error response JSON");
        for forbidden in forbidden_content {
            assert!(
                !serialized.contains(forbidden),
                "error response leaked content {forbidden:?}: {response:#}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn all_ten_tools_execute_positive_flow_and_replay_fails_closed() {
        let fixture = fixture(McpTransportBindingV1::Stdio);
        let case = fixture.case_id.as_str();
        let material = fixture.material_id.as_str();
        let publication = fixture.publication_id.as_str();

        let listed = call(&fixture, "case_list", object(json!({"schema_version":1}))).await;
        assert_eq!(data(&listed)["items"][0]["case_id"], case);
        let metadata = call(
            &fixture,
            "case_get_public_metadata",
            object(json!({
                "schema_version":1,"case_id":case
            })),
        )
        .await;
        assert_eq!(data(&metadata)["approved_material_count"], 1);
        let materials = call(
            &fixture,
            "case_list_approved_materials",
            object(json!({
                "schema_version":1,"case_id":case
            })),
        )
        .await;
        assert_eq!(data(&materials)["items"][0]["publication_id"], publication);
        let read = call(&fixture, "case_read_approved_material", object(json!({
            "schema_version":1,"case_id":case,"material_id":material,"publication_id":publication
        }))).await;
        assert!(data(&read)["content"]
            .as_str()
            .is_some_and(|value| value.contains("[PERSON_001]")));
        let searched = call(
            &fixture,
            "case_search_approved_materials",
            object(json!({
                "schema_version":1,"case_id":case,"query":"approved"
            })),
        )
        .await;
        assert_eq!(data(&searched)["items"][0]["match_count"], 1);
        let empty_products = call(
            &fixture,
            "case_list_work_products",
            object(json!({
                "schema_version":1,"case_id":case
            })),
        )
        .await;
        assert_eq!(data(&empty_products)["items"], json!([]));

        let written = call(&fixture, "case_write_work_product", object(json!({
            "schema_version":1,"case_id":case,"task_type":"case_analysis","status":"draft",
            "source_approved_refs":[{"material_id":material,"publication_id":publication}],
            "content_media_type":"text/markdown","content":"[PERSON_001] synthetic work product",
            "idempotency_key":format!("idem_{}", "A".repeat(32))
        }))).await;
        let work_product_id = data(&written)["work_product_id"]
            .as_str()
            .expect("work product id")
            .to_owned();
        let products = call(
            &fixture,
            "case_list_work_products",
            object(json!({
                "schema_version":1,"case_id":case
            })),
        )
        .await;
        assert_eq!(
            data(&products)["items"][0]["work_product_id"],
            work_product_id
        );
        let product = call(
            &fixture,
            "case_read_work_product",
            object(json!({
                "schema_version":1,"case_id":case,"work_product_id":work_product_id,"version":1
            })),
        )
        .await;
        assert_eq!(data(&product)["status"], "draft");
        let updated = call(&fixture, "case_update_work_product", object(json!({
            "schema_version":1,"case_id":case,"work_product_id":work_product_id,
            "expected_parent_version":1,"status":"final",
            "source_approved_refs":[{"material_id":material,"publication_id":publication}],
            "content_media_type":"text/markdown","content":"[PERSON_001] final synthetic work product",
            "idempotency_key":format!("idem_{}", "B".repeat(32))
        }))).await;
        assert_eq!(data(&updated)["version"], 2);
        let manifest = call(
            &fixture,
            "case_export_work_product_manifest",
            object(json!({
                "schema_version":1,"case_id":case,"work_product_id":work_product_id,"version":2
            })),
        )
        .await;
        assert_eq!(data(&manifest)["manifest"]["claims"]["version"], 2);

        let business = object(json!({"schema_version":1}));
        let now = now_seconds();
        let ticket = fixture
            .tickets
            .issue(
                fixture
                    .backend
                    .ticket_request("case_list", &business, now, now + 60)
                    .expect("request"),
            )
            .expect("ticket");
        let first = fixture.backend.call("case_list", &ticket, business.clone());
        let first = serde_json::to_value(first).expect("first call");
        assert_eq!(first["isError"], false);
        let replay = fixture.backend.call("case_list", &ticket, business);
        let replay = serde_json::to_value(replay).expect("replay call");
        assert_eq!(
            replay["structuredContent"]["reason_code"],
            "ACCESS_TICKET_REPLAYED"
        );
        let serialized = serde_json::to_string(&replay).expect("replay JSON");
        assert!(!serialized.contains(&ticket));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ocr_revocation_invalidates_old_stdio_and_http_targets_without_killing_native_session()
    {
        for transport in [
            McpTransportBindingV1::Stdio,
            McpTransportBindingV1::StreamableHttp,
        ] {
            let fixture = fixture(transport);
            let (native_material_id, native_publication_id) =
                publish_native_text_generation(&fixture);
            let ocr_business = object(json!({
                "schema_version":1,
                "case_id":fixture.case_id,
                "material_id":fixture.material_id,
                "publication_id":fixture.publication_id
            }));
            let native_business = object(json!({
                "schema_version":1,
                "case_id":fixture.case_id,
                "material_id":native_material_id,
                "publication_id":native_publication_id
            }));
            let (ocr_arguments, ocr_ticket) = wire_arguments(
                &fixture,
                "case_read_approved_material",
                ocr_business.clone(),
            );
            let (native_arguments, native_ticket) =
                wire_arguments(&fixture, "case_read_approved_material", native_business);

            assert_eq!(
                fixture
                    .approved_control
                    .revoke_ocr_derived_publications(now_seconds())
                    .expect("selective OCR revoke"),
                1
            );
            assert!(matches!(
                fixture.backend.ticket_request(
                    "case_read_approved_material",
                    &ocr_business,
                    now_seconds(),
                    now_seconds() + 60,
                ),
                Err(ApprovedBackendInitError::InvalidBinding)
            ));

            let revoked =
                call_prepared(&fixture, "case_read_approved_material", ocr_arguments).await;
            assert_error_without_content(
                &revoked,
                "APPROVED_MATERIAL_REVOKED",
                &["synthetic approved material", &ocr_ticket],
            );

            let native =
                call_prepared(&fixture, "case_read_approved_material", native_arguments).await;
            assert_eq!(
                data(&native)["content"],
                "[PERSON_002] native approved material"
            );
            let serialized = serde_json::to_string(&native).expect("native response JSON");
            assert!(!serialized.contains(&native_ticket));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn lifecycle_revoked_work_product_rejects_new_and_prepared_exact_calls() {
        const WORK_PRODUCT_CONTENT: &str = "[PERSON_001] lifecycle-bound work product";
        let fixture = fixture(McpTransportBindingV1::Stdio);
        let case = fixture.case_id.as_str();
        let material = fixture.material_id.as_str();
        let publication = fixture.publication_id.as_str();
        let written = call(
            &fixture,
            "case_write_work_product",
            object(json!({
                "schema_version":1,"case_id":case,"task_type":"case_analysis","status":"draft",
                "source_approved_refs":[{"material_id":material,"publication_id":publication}],
                "content_media_type":"text/markdown","content":WORK_PRODUCT_CONTENT,
                "idempotency_key":format!("idem_{}", "L".repeat(32))
            })),
        )
        .await;
        let work_product_id = data(&written)["work_product_id"]
            .as_str()
            .expect("work product id")
            .to_owned();
        let read_business = object(json!({
            "schema_version":1,"case_id":case,
            "work_product_id":work_product_id,"version":1
        }));
        let (prepared_arguments, prepared_ticket) =
            wire_arguments(&fixture, "case_read_work_product", read_business.clone());

        assert_eq!(
            fixture
                .backend
                .inner
                .work_products
                .prepare_retention_revocation_by_sources(
                    &fixture.backend.inner.approved,
                    &BTreeSet::from([fixture.publication_id.clone()]),
                    now_seconds(),
                    "privacy_retention_sweep",
                )
                .expect("revoke lifecycle work product"),
            1
        );
        fixture
            .backend
            .inner
            .work_products
            .recover_retention_cleanup(&fixture.backend.inner.approved, now_seconds())
            .expect("clean lifecycle work product bundle");
        assert!(matches!(
            fixture.backend.ticket_request(
                "case_read_work_product",
                &read_business,
                now_seconds(),
                now_seconds() + 60,
            ),
            Err(ApprovedBackendInitError::InvalidBinding)
        ));
        let revoked = call_prepared(&fixture, "case_read_work_product", prepared_arguments).await;
        assert_error_without_content(
            &revoked,
            "WORK_PRODUCT_REVOKED",
            &[WORK_PRODUCT_CONTENT, &prepared_ticket],
        );
        let products = call(
            &fixture,
            "case_list_work_products",
            object(json!({"schema_version":1,"case_id":case})),
        )
        .await;
        assert_eq!(data(&products)["items"], json!([]));
        let source = call(
            &fixture,
            "case_read_approved_material",
            object(json!({
                "schema_version":1,"case_id":case,"material_id":material,
                "publication_id":publication
            })),
        )
        .await;
        assert_eq!(
            data(&source)["content"],
            "[PERSON_001] synthetic approved material"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publication_revoke_closes_material_and_work_product_exit_matrix() {
        const APPROVED_CONTENT: &str = "[PERSON_001] synthetic approved material";
        const WORK_PRODUCT_CONTENT: &str = "[PERSON_001] synthetic revocation matrix work product";
        const UPDATE_CONTENT: &str = "[PERSON_001] post-revoke update must not escape";
        const CREATE_CONTENT: &str = "[PERSON_001] post-revoke create must not escape";

        let fixture = fixture(McpTransportBindingV1::Stdio);
        let case = fixture.case_id.as_str();
        let material = fixture.material_id.as_str();
        let publication = fixture.publication_id.as_str();

        let written = call(
            &fixture,
            "case_write_work_product",
            object(json!({
                "schema_version":1,"case_id":case,"task_type":"case_analysis","status":"draft",
                "source_approved_refs":[{"material_id":material,"publication_id":publication}],
                "content_media_type":"text/markdown","content":WORK_PRODUCT_CONTENT,
                "idempotency_key":format!("idem_{}", "R".repeat(32))
            })),
        )
        .await;
        let work_product_id = data(&written)["work_product_id"]
            .as_str()
            .expect("work product id")
            .to_owned();

        // Exact-target tickets are deliberately prepared before revocation. A revoked target
        // cannot receive a new ticket request, and an already-issued ticket must still fail at
        // the call boundary.
        let (material_read_arguments, _) = wire_arguments(
            &fixture,
            "case_read_approved_material",
            object(json!({
                "schema_version":1,"case_id":case,"material_id":material,
                "publication_id":publication
            })),
        );
        let (product_read_arguments, _) = wire_arguments(
            &fixture,
            "case_read_work_product",
            object(json!({
                "schema_version":1,"case_id":case,"work_product_id":work_product_id,
                "version":1
            })),
        );
        let (product_export_arguments, _) = wire_arguments(
            &fixture,
            "case_export_work_product_manifest",
            object(json!({
                "schema_version":1,"case_id":case,"work_product_id":work_product_id,
                "version":1
            })),
        );
        let (product_update_arguments, _) = wire_arguments(
            &fixture,
            "case_update_work_product",
            object(json!({
                "schema_version":1,"case_id":case,"work_product_id":work_product_id,
                "expected_parent_version":1,"status":"final",
                "source_approved_refs":[{"material_id":material,"publication_id":publication}],
                "content_media_type":"text/markdown","content":UPDATE_CONTENT,
                "idempotency_key":format!("idem_{}", "S".repeat(32))
            })),
        );

        fixture
            .approved_control
            .revoke(
                &fixture.case_id,
                &fixture.material_id,
                1,
                &fixture.publication_id,
                now_seconds(),
            )
            .expect("revoke approved publication");

        let materials = call(
            &fixture,
            "case_list_approved_materials",
            object(json!({"schema_version":1,"case_id":case})),
        )
        .await;
        assert_eq!(data(&materials)["items"], json!([]));
        let search = call(
            &fixture,
            "case_search_approved_materials",
            object(json!({
                "schema_version":1,"case_id":case,"query":"approved"
            })),
        )
        .await;
        assert_eq!(data(&search)["items"], json!([]));

        let material_read = call_prepared(
            &fixture,
            "case_read_approved_material",
            material_read_arguments,
        )
        .await;
        assert_error_without_content(
            &material_read,
            "APPROVED_MATERIAL_REVOKED",
            &[APPROVED_CONTENT],
        );

        let product_list = call(
            &fixture,
            "case_list_work_products",
            object(json!({"schema_version":1,"case_id":case})),
        )
        .await;
        assert_error_without_content(
            &product_list,
            "APPROVED_SOURCE_STALE",
            &[APPROVED_CONTENT, WORK_PRODUCT_CONTENT],
        );
        let product_read =
            call_prepared(&fixture, "case_read_work_product", product_read_arguments).await;
        assert_error_without_content(
            &product_read,
            "APPROVED_SOURCE_STALE",
            &[APPROVED_CONTENT, WORK_PRODUCT_CONTENT],
        );
        let product_export = call_prepared(
            &fixture,
            "case_export_work_product_manifest",
            product_export_arguments,
        )
        .await;
        assert_error_without_content(
            &product_export,
            "APPROVED_SOURCE_STALE",
            &[APPROVED_CONTENT, WORK_PRODUCT_CONTENT],
        );
        let product_update = call_prepared(
            &fixture,
            "case_update_work_product",
            product_update_arguments,
        )
        .await;
        assert_error_without_content(
            &product_update,
            "APPROVED_SOURCE_STALE",
            &[APPROVED_CONTENT, WORK_PRODUCT_CONTENT, UPDATE_CONTENT],
        );

        let post_revoke_create = call(
            &fixture,
            "case_write_work_product",
            object(json!({
                "schema_version":1,"case_id":case,"task_type":"case_analysis","status":"draft",
                "source_approved_refs":[{"material_id":material,"publication_id":publication}],
                "content_media_type":"text/markdown","content":CREATE_CONTENT,
                "idempotency_key":format!("idem_{}", "T".repeat(32))
            })),
        )
        .await;
        assert_error_without_content(
            &post_revoke_create,
            "APPROVED_MATERIAL_REVOKED",
            &[APPROVED_CONTENT, WORK_PRODUCT_CONTENT, CREATE_CONTENT],
        );
    }

    fn wire_arguments(
        fixture: &Fixture,
        tool_name: &str,
        business: JsonObject,
    ) -> (JsonObject, String) {
        let now = now_seconds();
        let request = fixture
            .backend
            .ticket_request(tool_name, &business, now, now + 60)
            .expect("wire ticket request");
        let ticket = fixture.tickets.issue(request).expect("wire ticket");
        let mut arguments = business;
        arguments.insert("access_ticket".to_owned(), json!(ticket));
        (arguments, ticket)
    }

    async fn send_line<W: AsyncWrite + Unpin>(writer: &mut W, value: Value) {
        let mut bytes = serde_json::to_vec(&value).expect("wire request JSON");
        bytes.push(b'\n');
        writer.write_all(&bytes).await.expect("wire request write");
        writer.flush().await.expect("wire request flush");
    }

    async fn receive_line<R: AsyncBufRead + Unpin>(lines: &mut Lines<R>) -> (String, Value) {
        let line = lines
            .next_line()
            .await
            .expect("wire response read")
            .expect("wire response line");
        let value = serde_json::from_str(&line).expect("wire response JSON");
        (line, value)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn approved_stdio_wire_reads_writes_rereads_and_rejects_replay() {
        let fixture = fixture(McpTransportBindingV1::Stdio);
        let server = LegalMcpServer::new(
            ToolRegistry::for_profile(PrivacyProfile::ApprovedCaseWorkspace),
            fixture.adapter.clone(),
        );
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let (server_read, server_write) = tokio::io::split(server_io);
        let transport = StableProtocolTransport::new(
            AsyncRwTransport::<RoleServer, _, _>::new_server(server_read, server_write),
        );
        let server_task = tokio::spawn(async move {
            let running = server.serve(transport).await.expect("serve approved stdio");
            running.waiting().await.expect("wait approved stdio");
        });
        let (client_read, mut client_write) = tokio::io::split(client_io);
        let mut client_lines = BufReader::new(client_read).lines();
        send_line(
            &mut client_write,
            json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"approved-stdio-synthetic","version":"1"}
                }
            }),
        )
        .await;
        let (_, initialized) = receive_line(&mut client_lines).await;
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");
        send_line(
            &mut client_write,
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await;

        let case_id = fixture.case_id.as_str();
        let material_id = fixture.material_id.as_str();
        let publication_id = fixture.publication_id.as_str();
        let (read_arguments, read_ticket) = wire_arguments(
            &fixture,
            "case_read_approved_material",
            object(json!({
                "schema_version":1,"case_id":case_id,
                "material_id":material_id,"publication_id":publication_id
            })),
        );
        send_line(
            &mut client_write,
            json!({
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"case_read_approved_material","arguments":read_arguments}
            }),
        )
        .await;
        let (read_line, read) = receive_line(&mut client_lines).await;
        assert_eq!(read["result"]["isError"], false, "{read:#}");
        assert!(read["result"]["structuredContent"]["data"]["content"]
            .as_str()
            .is_some_and(|value| value.contains("[PERSON_001]")));
        assert!(!read_line.contains(&read_ticket));

        let (write_arguments, write_ticket) = wire_arguments(
            &fixture,
            "case_write_work_product",
            object(json!({
                "schema_version":1,"case_id":case_id,"task_type":"case_analysis","status":"draft",
                "source_approved_refs":[{"material_id":material_id,"publication_id":publication_id}],
                "content_media_type":"text/plain","content":"[PERSON_001] wire work product",
                "idempotency_key":format!("idem_{}", "C".repeat(32))
            })),
        );
        send_line(
            &mut client_write,
            json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"case_write_work_product","arguments":write_arguments}
            }),
        )
        .await;
        let (write_line, written) = receive_line(&mut client_lines).await;
        assert_eq!(written["result"]["isError"], false, "{written:#}");
        assert!(!write_line.contains(&write_ticket));
        let work_product_id = written["result"]["structuredContent"]["data"]["work_product_id"]
            .as_str()
            .expect("wire work product id")
            .to_owned();

        let (product_arguments, product_ticket) = wire_arguments(
            &fixture,
            "case_read_work_product",
            object(json!({
                "schema_version":1,"case_id":case_id,
                "work_product_id":work_product_id,"version":1
            })),
        );
        send_line(
            &mut client_write,
            json!({
                "jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name":"case_read_work_product","arguments":product_arguments.clone()}
            }),
        )
        .await;
        let (product_line, product) = receive_line(&mut client_lines).await;
        assert_eq!(product["result"]["isError"], false, "{product:#}");
        assert!(!product_line.contains(&product_ticket));
        send_line(
            &mut client_write,
            json!({
                "jsonrpc":"2.0","id":5,"method":"tools/call",
                "params":{"name":"case_read_work_product","arguments":product_arguments}
            }),
        )
        .await;
        let (replay_line, replay) = receive_line(&mut client_lines).await;
        assert_eq!(
            replay["result"]["structuredContent"]["reason_code"],
            "ACCESS_TICKET_REPLAYED"
        );
        assert!(!replay_line.contains(&product_ticket));

        client_write
            .shutdown()
            .await
            .expect("shutdown stdio client");
        drop(client_write);
        tokio::time::timeout(std::time::Duration::from_secs(10), server_task)
            .await
            .expect("approved stdio timeout")
            .expect("approved stdio task");
    }
    const APPROVED_HTTP_TOKEN: &str = "synthetic-approved-http-token-0001";
    const MAX_APPROVED_HTTP_RAW_BYTES: usize = 4 * 1024 * 1024 + 64 * 1024;

    #[derive(Debug)]
    struct ApprovedHttpResponse {
        status: u16,
        body: Vec<u8>,
    }

    async fn post_approved_http(
        address: std::net::SocketAddr,
        body: Value,
    ) -> ApprovedHttpResponse {
        tokio::task::spawn_blocking(move || {
            let body = serde_json::to_vec(&body).expect("approved HTTP request JSON");
            let request_head = format!(
                concat!(
                    "POST /mcp HTTP/1.1\r\n",
                    "Host: {}\r\n",
                    "Content-Type: application/json\r\n",
                    "Accept: application/json, text/event-stream\r\n",
                    "Content-Length: {}\r\n",
                    "Authorization: Bearer {}\r\n",
                    "Origin: https://client.example\r\n",
                    "MCP-Protocol-Version: 2025-11-25\r\n",
                    "Connection: close\r\n\r\n"
                ),
                address,
                body.len(),
                APPROVED_HTTP_TOKEN
            );
            let mut stream =
                std::net::TcpStream::connect(address).expect("connect approved HTTP fixture");
            let timeout = Some(std::time::Duration::from_secs(5));
            stream
                .set_read_timeout(timeout)
                .expect("approved HTTP read timeout");
            stream
                .set_write_timeout(timeout)
                .expect("approved HTTP write timeout");
            stream
                .write_all(request_head.as_bytes())
                .expect("approved HTTP request head");
            stream.write_all(&body).expect("approved HTTP request body");
            stream.flush().expect("flush approved HTTP request");

            let mut raw = Vec::new();
            stream
                .take(
                    u64::try_from(MAX_APPROVED_HTTP_RAW_BYTES + 1)
                        .expect("approved HTTP limit fits u64"),
                )
                .read_to_end(&mut raw)
                .expect("approved HTTP response");
            assert!(
                raw.len() <= MAX_APPROVED_HTTP_RAW_BYTES,
                "approved HTTP response exceeded bounded test limit"
            );
            parse_approved_http_response(&raw)
        })
        .await
        .expect("approved HTTP blocking task")
    }

    fn parse_approved_http_response(raw: &[u8]) -> ApprovedHttpResponse {
        let separator = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("approved HTTP header terminator");
        let head = std::str::from_utf8(&raw[..separator]).expect("approved HTTP headers are UTF-8");
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .expect("approved HTTP status");
        let mut content_length = None;
        let mut chunked = false;
        for line in lines {
            let (name, value) = line.split_once(':').expect("approved HTTP header");
            if name.eq_ignore_ascii_case("content-length") {
                let parsed = value
                    .trim()
                    .parse::<usize>()
                    .expect("approved HTTP Content-Length");
                assert!(
                    content_length.is_none_or(|existing| existing == parsed),
                    "conflicting approved HTTP Content-Length"
                );
                content_length = Some(parsed);
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value
                    .split(',')
                    .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"));
            }
        }
        assert!(
            !(chunked && content_length.is_some()),
            "approved HTTP response used ambiguous framing"
        );
        let wire_body = &raw[separator + 4..];
        let body = if chunked {
            decode_approved_chunked_body(wire_body)
        } else if let Some(length) = content_length {
            assert!(
                length <= 4 * 1024 * 1024 && wire_body.len() >= length,
                "approved HTTP Content-Length is invalid"
            );
            wire_body[..length].to_vec()
        } else {
            assert!(
                wire_body.len() <= 4 * 1024 * 1024,
                "approved HTTP body exceeded test limit"
            );
            wire_body.to_vec()
        };
        ApprovedHttpResponse { status, body }
    }

    fn decode_approved_chunked_body(mut wire: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();
        loop {
            let line_end = wire
                .windows(2)
                .position(|window| window == b"\r\n")
                .expect("approved HTTP chunk-size terminator");
            let size_token = std::str::from_utf8(&wire[..line_end])
                .expect("approved HTTP chunk size ASCII")
                .split(';')
                .next()
                .expect("approved HTTP chunk size")
                .trim();
            let size =
                usize::from_str_radix(size_token, 16).expect("approved HTTP chunk size value");
            wire = &wire[line_end + 2..];
            if size == 0 {
                return decoded;
            }
            let new_length = decoded
                .len()
                .checked_add(size)
                .expect("approved HTTP chunk length");
            assert!(
                new_length <= 4 * 1024 * 1024 && wire.len() >= size + 2,
                "approved HTTP chunk exceeds test limit"
            );
            decoded.extend_from_slice(&wire[..size]);
            assert_eq!(&wire[size..size + 2], b"\r\n");
            wire = &wire[size + 2..];
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn approved_streamable_http_tcp_reads_writes_rereads_and_rejects_replay() {
        let fixture = fixture(McpTransportBindingV1::StreamableHttp);
        let server = LegalMcpServer::new(
            ToolRegistry::for_profile(PrivacyProfile::ApprovedCaseWorkspace),
            fixture.adapter.clone(),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind approved HTTP fixture");
        let address = listener.local_addr().expect("approved HTTP address");
        let root = fixture._root.path();
        let config = ResolvedConfig {
            legal_db: root.join("legal.sqlite"),
            user_db: root.join("user.sqlite"),
            allowed_roots: vec![root.join("materials")],
            output_root: root.join("output"),
            privacy_profile: PrivacyProfile::ApprovedCaseWorkspace,
            bind: address,
            allowed_origins: vec!["https://client.example".to_owned()],
            allowed_hosts: vec![address.to_string()],
            bearer: Some(
                BearerSecret::from_token_bytes(APPROVED_HTTP_TOKEN.as_bytes().to_vec())
                    .expect("approved HTTP bearer"),
            ),
            dangerously_allow_insecure_non_loopback_http: false,
            limits: Limits {
                max_body_bytes: 128 * 1024,
                request_timeout: std::time::Duration::from_secs(5),
                max_concurrency: 2,
            },
            command: Command::Serve {
                bind: Some(address),
            },
        };
        let cancellation = CancellationToken::new();
        let router = build_router(server, &config, cancellation.clone());
        let server_task = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve approved HTTP fixture");
        });

        let initialized = post_approved_http(
            address,
            json!({
                "jsonrpc":"2.0","id":1,"method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25","capabilities":{},
                    "clientInfo":{"name":"approved-http-synthetic","version":"1"}
                }
            }),
        )
        .await;
        assert_eq!(initialized.status, 200);
        let initialized: Value =
            serde_json::from_slice(&initialized.body).expect("approved HTTP initialize JSON");
        assert_eq!(initialized["result"]["protocolVersion"], "2025-11-25");

        let case_id = fixture.case_id.as_str();
        let material_id = fixture.material_id.as_str();
        let publication_id = fixture.publication_id.as_str();
        let (read_arguments, read_ticket) = wire_arguments(
            &fixture,
            "case_read_approved_material",
            object(json!({
                "schema_version":1,"case_id":case_id,
                "material_id":material_id,"publication_id":publication_id
            })),
        );
        let read = post_approved_http(
            address,
            json!({
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"case_read_approved_material","arguments":read_arguments}
            }),
        )
        .await;
        assert_eq!(read.status, 200);
        let read_text = String::from_utf8(read.body).expect("approved HTTP read UTF-8");
        assert!(!read_text.contains(&read_ticket));
        let read: Value = serde_json::from_str(&read_text).expect("approved HTTP read JSON");
        assert_eq!(read["result"]["isError"], false, "{read:#}");
        assert!(read["result"]["structuredContent"]["data"]["content"]
            .as_str()
            .is_some_and(|value| value.contains("[PERSON_001]")));

        let (write_arguments, write_ticket) = wire_arguments(
            &fixture,
            "case_write_work_product",
            object(json!({
                "schema_version":1,"case_id":case_id,"task_type":"case_analysis","status":"draft",
                "source_approved_refs":[{"material_id":material_id,"publication_id":publication_id}],
                "content_media_type":"text/plain","content":"[PERSON_001] HTTP work product",
                "idempotency_key":format!("idem_{}", "D".repeat(32))
            })),
        );
        let written = post_approved_http(
            address,
            json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"case_write_work_product","arguments":write_arguments}
            }),
        )
        .await;
        assert_eq!(written.status, 200);
        let written_text = String::from_utf8(written.body).expect("approved HTTP write UTF-8");
        assert!(!written_text.contains(&write_ticket));
        let written: Value = serde_json::from_str(&written_text).expect("approved HTTP write JSON");
        assert_eq!(written["result"]["isError"], false, "{written:#}");
        let work_product_id = written["result"]["structuredContent"]["data"]["work_product_id"]
            .as_str()
            .expect("approved HTTP work product id")
            .to_owned();

        let (product_arguments, product_ticket) = wire_arguments(
            &fixture,
            "case_read_work_product",
            object(json!({
                "schema_version":1,"case_id":case_id,
                "work_product_id":work_product_id,"version":1
            })),
        );
        let product = post_approved_http(
            address,
            json!({
                "jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name":"case_read_work_product","arguments":product_arguments.clone()}
            }),
        )
        .await;
        assert_eq!(product.status, 200);
        let product_text =
            String::from_utf8(product.body).expect("approved HTTP work product UTF-8");
        assert!(!product_text.contains(&product_ticket));
        let product: Value =
            serde_json::from_str(&product_text).expect("approved HTTP work product JSON");
        assert_eq!(product["result"]["isError"], false, "{product:#}");
        assert_eq!(
            product["result"]["structuredContent"]["data"]["content"],
            "[PERSON_001] HTTP work product"
        );

        let replay = post_approved_http(
            address,
            json!({
                "jsonrpc":"2.0","id":5,"method":"tools/call",
                "params":{"name":"case_read_work_product","arguments":product_arguments}
            }),
        )
        .await;
        assert_eq!(replay.status, 200);
        let replay_text = String::from_utf8(replay.body).expect("approved HTTP replay UTF-8");
        assert!(!replay_text.contains(&product_ticket));
        let replay: Value = serde_json::from_str(&replay_text).expect("approved HTTP replay JSON");
        assert_eq!(
            replay["result"]["structuredContent"]["reason_code"],
            "ACCESS_TICKET_REPLAYED"
        );

        cancellation.cancel();
        server_task.abort();
        let _ = server_task.await;
    }
}
