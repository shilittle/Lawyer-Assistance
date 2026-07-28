//! DPAPI-protected, signed capability descriptors for a standalone approved
//! workspace MCP process.
//!
//! The descriptor contains no case body or one-time access ticket.  It is
//! stored only below the App's fixed local state root and is authenticated by
//! the production MCP ticket identity held in Windows Credential Manager.

use crate::{
    approved_backend::{
        approved_broker_error_result, ApprovedBackendInitError, ApprovedMcpQualificationSnapshotV1,
        ApprovedWorkspaceBackend, ApprovedWorkspaceQualificationError,
        ApprovedWorkspaceQualificationProvider, APPROVED_MCP_POLICY_ID,
        APPROVED_MCP_POLICY_VERSION,
    },
    config::{normalize_allowed_origins, BearerSecret, Command, Limits, ResolvedConfig},
    registry::PrivacyProfile,
    release_binary::measure_release_binary,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use privacy::{
    mcp_ticket::{
        McpAccessTicketRequestV1, McpAccessTicketStore, McpTicketSigningKey, McpTransportBindingV1,
    },
    protect_local, sha256_hex, unprotect_local, validate_fixed_local_directory,
    validate_fixed_local_regular_file,
    vnext::{canonical_json_v1, strict_json_v1_from_slice, WorkspaceInstanceId},
    work_products::{WorkProductPublisher, WorkProductService},
    workspace::{ApprovedWorkspaceService, ManifestSigningKey},
};
use providers::{
    windows_credentials::WindowsCredentialStore, ApiSecret, CredentialStore, ProviderCredentialKey,
    ProviderStoreLock,
};
use rusqlite::{params, Connection};
use serde::{ser::SerializeStruct, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{compiler_fence, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

#[cfg(not(feature = "standalone-mcp-e2e"))]
pub const APP_IDENTIFIER: &str = "com.shilittle.lawyer-assistance";
#[cfg(feature = "standalone-mcp-e2e")]
pub const APP_IDENTIFIER: &str = "com.shilittle.lawyer-assistance.mcp-e2e";
const QUALIFICATION_CANARY_APP_IDENTIFIER: &str =
    "com.shilittle.lawyer-assistance.mcp-qualification-canary";
pub const APPROVED_MCP_STATE_RELATIVE: &str = "privacy/approved-mcp";
const QUALIFICATION_CANARY_RUNS_DIRECTORY: &str = "canary-runs";
pub const STANDALONE_DESCRIPTOR_FILE: &str = "standalone-session-v2.dpapi";
const PROCESS_LOCK_FILE: &str = "standalone-process-lock.sqlite";
pub const WIRE_REPLAY_DATABASE_FILE: &str = "standalone-wire-replay-v2.sqlite";
const LEGACY_WIRE_REPLAY_DATABASE_FILE: &str = "standalone-wire-replay-v1.sqlite";
const WIRE_REPLAY_STATE_SCHEMA: &str = "lawyer-assistance-standalone-wire-replay-state-v2";
const WIRE_REPLAY_PENDING_SCHEMA: &str = "lawyer-assistance-standalone-wire-replay-pending-v1";
const WIRE_REPLAY_STATE_PREFIX: &str = "approved-mcp-wire-replay-state-v2.";
const REPLAY_STATE_PROVIDER: &str = "standalone-wire-replay-v2";
// V1 used this unversioned Credential Manager provider target. It is never
// read or migrated; explicit revocation only exact-deletes it.
const LEGACY_REPLAY_STATE_PROVIDER: &str = "standalone-wire-replay";
const WIRE_REPLAY_KEY_DOMAIN: &[u8] = b"lawyer-assistance\0standalone-wire-replay-key-v2\0";
const WIRE_REPLAY_CHAIN_DOMAIN: &[u8] = b"lawyer-assistance\0standalone-wire-replay-chain-v2\0";
const WIRE_REPLAY_STATE_DOMAIN: &[u8] = b"lawyer-assistance\0standalone-wire-replay-state-v2\0";
const WIRE_REPLAY_TAIL_DOMAIN: &[u8] = b"lawyer-assistance\0standalone-wire-replay-tail-v1\0";
const WIRE_REPLAY_TICKET_REQUEST_DOMAIN: &[u8] =
    b"lawyer-assistance\0standalone-wire-replay-ticket-request-v1\0";
const MAX_WIRE_REPLAY_ROWS: u64 = 10_000;
const MAX_WIRE_REPLAY_DATABASE_BYTES: u64 = 8 * 1024 * 1024;
const EVIDENCE_FILE: &str = "active-evidence-v1.json";
const TICKET_DATABASE_FILE: &str = "mcp-access-tickets.sqlite";
const KEY_SERVICE_PREFIX: &str = "LawyerAssistanceApprovedMcp";
const KEY_ACCOUNT: &str = "user-boundary-v1";
const KEY_FORMAT_PREFIX: &str = "approved-mcp-key-v1.";
const SESSION_SECRET_PREFIX: &str = "approved-mcp-session-secret-v1.";
const SESSION_SECRET_PROVIDER: &str = "standalone-session";
const DESCRIPTOR_SCHEMA: &str = "lawyer-assistance-approved-mcp-standalone-session-v2";
const DESCRIPTOR_DOMAIN: &[u8] = b"lawyer-assistance\0approved-mcp-standalone-session-v2\0";
const KEY_VERSION: u64 = 1;
const MAX_DESCRIPTOR_BYTES: usize = 256 * 1024;
const MAX_SESSION_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_HTTP_SESSION_TTL_SECONDS: u64 = 24 * 60 * 60;
const MAX_ARGUMENT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StandaloneApprovedError {
    #[error("standalone approved MCP session is unavailable")]
    Unavailable,
    #[error("standalone approved MCP session binding is invalid")]
    InvalidBinding,
    #[error("standalone approved MCP session is expired")]
    Expired,
    #[error("standalone approved MCP session is revoked")]
    Revoked,
    #[error("standalone approved MCP session is already running")]
    AlreadyRunning,
    #[error("standalone approved MCP ticket operation failed")]
    TicketFailed,
}

impl StandaloneApprovedError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unavailable => "approved_mcp_standalone_unavailable",
            Self::InvalidBinding => "approved_mcp_standalone_binding_invalid",
            Self::Expired => "approved_mcp_standalone_expired",
            Self::Revoked => "approved_mcp_standalone_revoked",
            Self::AlreadyRunning => "approved_mcp_standalone_already_running",
            Self::TicketFailed => "approved_mcp_standalone_ticket_failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovedMcpGrantGroupV1 {
    Read,
    Write,
    DiagramRead,
    DiagramWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovedMcpToolGrantV1 {
    pub tool_name: String,
    pub purpose: String,
}

const READ_GRANT_TOOLS: [&str; 8] = [
    "case_list",
    "case_get_public_metadata",
    "case_list_approved_materials",
    "case_read_approved_material",
    "case_search_approved_materials",
    "case_list_work_products",
    "case_read_work_product",
    "case_export_work_product_manifest",
];
const WRITE_GRANT_TOOLS: [&str; 2] = ["case_write_work_product", "case_update_work_product"];
const DIAGRAM_READ_GRANT_TOOLS: [&str; 4] = [
    "diagram.list_templates",
    "diagram.get_schema",
    "diagram.validate",
    "diagram.export",
];
const DIAGRAM_WRITE_GRANT_TOOLS: [&str; 2] = ["diagram.render", "diagram.update"];

fn canonical_grants(
    requested: &[ApprovedMcpGrantGroupV1],
) -> Result<(Vec<ApprovedMcpGrantGroupV1>, Vec<ApprovedMcpToolGrantV1>), StandaloneApprovedError> {
    if requested.is_empty() || requested.len() > 4 {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let read = requested.contains(&ApprovedMcpGrantGroupV1::Read);
    let write = requested.contains(&ApprovedMcpGrantGroupV1::Write);
    let diagram_read = requested.contains(&ApprovedMcpGrantGroupV1::DiagramRead);
    let diagram_write = requested.contains(&ApprovedMcpGrantGroupV1::DiagramWrite);
    if usize::from(read)
        + usize::from(write)
        + usize::from(diagram_read)
        + usize::from(diagram_write)
        != requested.len()
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let mut groups = Vec::with_capacity(requested.len());
    let mut grants = Vec::with_capacity(
        READ_GRANT_TOOLS.len()
            + WRITE_GRANT_TOOLS.len()
            + DIAGRAM_READ_GRANT_TOOLS.len()
            + DIAGRAM_WRITE_GRANT_TOOLS.len(),
    );
    if read {
        groups.push(ApprovedMcpGrantGroupV1::Read);
        grants.extend(READ_GRANT_TOOLS.into_iter().map(tool_grant));
    }
    if write {
        groups.push(ApprovedMcpGrantGroupV1::Write);
        grants.extend(WRITE_GRANT_TOOLS.into_iter().map(tool_grant));
    }
    if diagram_read {
        groups.push(ApprovedMcpGrantGroupV1::DiagramRead);
        grants.extend(DIAGRAM_READ_GRANT_TOOLS.into_iter().map(tool_grant));
    }
    if diagram_write {
        groups.push(ApprovedMcpGrantGroupV1::DiagramWrite);
        grants.extend(DIAGRAM_WRITE_GRANT_TOOLS.into_iter().map(tool_grant));
    }
    Ok((groups, grants))
}

fn tool_grant(tool_name: &str) -> ApprovedMcpToolGrantV1 {
    ApprovedMcpToolGrantV1 {
        tool_name: tool_name.to_owned(),
        purpose: format!("mcp.{tool_name}.v1"),
    }
}

fn grant_allows(grants: &[ApprovedMcpToolGrantV1], tool_name: &str, purpose: &str) -> bool {
    grants
        .iter()
        .any(|grant| grant.tool_name == tool_name && grant.purpose == purpose)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StandaloneSessionMetadataV1 {
    pub descriptor_id: String,
    pub connector_id: String,
    pub workspace_instance_id: String,
    pub server_instance_id: String,
    pub session_id: String,
    pub transport: McpTransportBindingV1,
    pub grant_groups: Vec<ApprovedMcpGrantGroupV1>,
    pub grants: Vec<ApprovedMcpToolGrantV1>,
    pub endpoint: Option<String>,
    pub qualification_evidence_id: String,
    pub qualification_evidence_sha256: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub active: bool,
    pub reason_code: String,
}

#[derive(Clone)]
pub struct StandaloneSessionProvisioningV1 {
    pub app_local_data_directory: PathBuf,
    pub approved_root: PathBuf,
    pub work_product_root: PathBuf,
    pub ticket_root: PathBuf,
    pub legal_database_path: PathBuf,
    pub user_database_path: PathBuf,
    pub allowed_roots: Vec<PathBuf>,
    pub output_root: PathBuf,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub server_instance_id: String,
    pub session_id: String,
    pub connector_id: String,
    pub transport: McpTransportBindingV1,
    pub grant_groups: Vec<ApprovedMcpGrantGroupV1>,
    pub qualification: ApprovedMcpQualificationSnapshotV1,
    pub ticket_revocation_epoch: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub http_bind: Option<SocketAddr>,
    pub allowed_origins: Vec<String>,
}

impl std::fmt::Debug for StandaloneSessionProvisioningV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StandaloneSessionProvisioningV1")
            .field("server_instance_id", &self.server_instance_id)
            .field("session_id", &"[BOUND]")
            .field("connector_id", &self.connector_id)
            .field("transport", &self.transport)
            .field("roots", &"[FIXED_LOCAL_STATE]")
            .finish()
    }
}

pub struct ProvisionedStandaloneSessionV1 {
    pub metadata: StandaloneSessionMetadataV1,
    http_bearer: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for ProvisionedStandaloneSessionV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProvisionedStandaloneSessionV1")
            .field("metadata", &self.metadata)
            .field(
                "http_bearer",
                &self.http_bearer.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl Serialize for ProvisionedStandaloneSessionV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct(
            "ProvisionedStandaloneSessionV1",
            if self.http_bearer.is_some() { 2 } else { 1 },
        )?;
        state.serialize_field("session", &self.metadata)?;
        if let Some(bearer) = self.http_bearer.as_ref() {
            state.serialize_field("oneTimeHttpBearer", bearer.as_str())?;
        }
        state.end()
    }
}

impl ProvisionedStandaloneSessionV1 {
    pub fn take_http_bearer(&mut self) -> Option<Zeroizing<String>> {
        self.http_bearer.take()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StandaloneDescriptorClaimsV1 {
    schema_version: String,
    descriptor_id: String,
    connector_id: String,
    workspace_instance_id: WorkspaceInstanceId,
    server_instance_id: String,
    session_id: String,
    transport: McpTransportBindingV1,
    grant_groups: Vec<ApprovedMcpGrantGroupV1>,
    grants: Vec<ApprovedMcpToolGrantV1>,
    app_version: String,
    policy_id: String,
    policy_version: u64,
    approved_root: PathBuf,
    work_product_root: PathBuf,
    ticket_root: PathBuf,
    qualification_evidence_path: PathBuf,
    legal_database_path: PathBuf,
    user_database_path: PathBuf,
    allowed_roots: Vec<PathBuf>,
    output_root: PathBuf,
    qualification: ApprovedMcpQualificationSnapshotV1,
    ticket_revocation_epoch: u64,
    session_secret_sha256: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    http_bind: Option<SocketAddr>,
    allowed_origins: Vec<String>,
    http_bearer: Option<String>,
}

impl Drop for StandaloneDescriptorClaimsV1 {
    fn drop(&mut self) {
        if let Some(value) = self.http_bearer.as_mut() {
            value.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedStandaloneDescriptorV1 {
    claims: StandaloneDescriptorClaimsV1,
    canonical_claims_sha256: String,
    signing_key_id: String,
    signing_key_version: u64,
    mac_hex: String,
}

struct ApprovedKeyRing {
    manifest: [u8; 32],
    work_product: [u8; 32],
    ticket: [u8; 32],
    qualification_epoch: [u8; 32],
}

impl Drop for ApprovedKeyRing {
    fn drop(&mut self) {
        zeroize(&mut self.manifest);
        zeroize(&mut self.work_product);
        zeroize(&mut self.ticket);
        zeroize(&mut self.qualification_epoch);
    }
}

pub struct LoadedStandaloneApprovedSession {
    pub config: ResolvedConfig,
    pub broker: StandaloneCallBroker,
    _process_lock: StandaloneProcessLock,
}

#[derive(Clone)]
pub struct StandaloneCallBroker {
    inner: Arc<StandaloneCallBrokerInner>,
}

struct StandaloneCallBrokerInner {
    app_directory: PathBuf,
    server_instance_id: String,
    descriptor_sha256: String,
    transport: McpTransportBindingV1,
    backend: ApprovedWorkspaceBackend,
    tickets: McpAccessTicketStore,
    replay: Mutex<WireReplayGuard>,
}

impl std::fmt::Debug for StandaloneCallBroker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StandaloneCallBroker")
            .field("server_instance_id", &self.inner.server_instance_id)
            .field("transport", &self.inner.transport)
            .field("descriptor", &"[APP_SIGNED_AND_DPAPI_PROTECTED]")
            .field("tickets", &"[INTERNAL_ONLY]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireReplayError {
    Replayed,
    Unavailable,
}

fn accepted_standalone_call_params(
    call_params: &Value,
    tool_name: &str,
    arguments: &Map<String, Value>,
) -> bool {
    let Some(params) = call_params.as_object() else {
        return false;
    };
    if params
        .keys()
        .any(|key| !matches!(key.as_str(), "name" | "arguments" | "_meta"))
        || params.get("name").and_then(Value::as_str) != Some(tool_name)
        || params.get("_meta").is_some_and(|meta| !meta.is_object())
        || contains_access_ticket(call_params)
    {
        return false;
    }
    match params.get("arguments") {
        Some(Value::Object(value)) => value == arguments,
        None => arguments.is_empty(),
        _ => false,
    }
}

fn contains_access_ticket(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("access_ticket")
                || key.eq_ignore_ascii_case("accessTicket")
                || contains_access_ticket(value)
        }),
        Value::Array(values) => values.iter().any(contains_access_ticket),
        _ => false,
    }
}
impl StandaloneCallBroker {
    pub fn call(
        &self,
        request_id: Value,
        tool_name: &str,
        mut arguments: Map<String, Value>,
        call_params: Value,
    ) -> rmcp::model::CallToolResult {
        if !accepted_standalone_call_params(&call_params, tool_name, &arguments)
            || !approved_request_is_valid(tool_name, &arguments)
        {
            return approved_broker_error_result("INVALID_REQUEST");
        }
        let now = match now_seconds() {
            Ok(now) => now,
            Err(_) => return approved_broker_error_result("STANDALONE_SESSION_UNAVAILABLE"),
        };
        let loaded = match load_verified_descriptor(
            &self.inner.app_directory,
            &self.inner.server_instance_id,
            Some(&self.inner.descriptor_sha256),
            now,
        ) {
            Ok(loaded) => loaded,
            Err(_) => return approved_broker_error_result("STANDALONE_SESSION_NOT_ACTIVE"),
        };
        let claims = &loaded.descriptor.claims;
        if claims.transport != self.inner.transport {
            return approved_broker_error_result("STANDALONE_SESSION_BINDING_MISMATCH");
        }
        let expires = now
            .checked_add(30)
            .map(|value| value.min(claims.expires_at_unix))
            .filter(|value| *value > now);
        let Some(expires) = expires else {
            return approved_broker_error_result("STANDALONE_SESSION_NOT_ACTIVE");
        };
        let ticket_request = match self
            .inner
            .backend
            .ticket_request(tool_name, &arguments, now, expires)
        {
            Ok(request) => request,
            Err(_) => return approved_broker_error_result("INVALID_REQUEST"),
        };
        if !grant_allows(&claims.grants, tool_name, &ticket_request.purpose) {
            return approved_broker_error_result("STANDALONE_GRANT_DENIED");
        }
        let diagram_read = claims
            .grant_groups
            .contains(&ApprovedMcpGrantGroupV1::DiagramRead);
        let ticket_request_canonical = match replay_ticket_request_canonical(&ticket_request) {
            Ok(value) => value,
            Err(_) => return approved_broker_error_result("STANDALONE_REPLAY_GUARD_UNAVAILABLE"),
        };
        match self.reserve_wire_request(
            &request_id,
            tool_name,
            &call_params,
            &ticket_request_canonical,
            now,
        ) {
            Ok(()) => {}
            Err(WireReplayError::Replayed) => {
                return approved_broker_error_result("WIRE_REQUEST_REPLAYED")
            }
            Err(WireReplayError::Unavailable) => {
                return approved_broker_error_result("STANDALONE_REPLAY_GUARD_UNAVAILABLE")
            }
        }
        let ticket = match self.inner.tickets.issue(ticket_request) {
            Ok(ticket) => ticket,
            Err(_) => return approved_broker_error_result("ACCESS_TICKET_UNAVAILABLE"),
        };
        arguments.insert("access_ticket".to_owned(), Value::String(ticket));
        let (ticket, business_arguments) =
            match crate::approved_workspace::split_access_ticket(arguments) {
                Ok(parts) => parts,
                Err(_) => return approved_broker_error_result("ACCESS_TICKET_UNAVAILABLE"),
            };
        self.inner
            .backend
            .call_for_standalone(tool_name, &ticket, business_arguments, diagram_read)
    }

    fn reserve_wire_request(
        &self,
        request_id: &Value,
        tool_name: &str,
        call_params: &Value,
        ticket_request_canonical: &[u8],
        now: u64,
    ) -> Result<(), WireReplayError> {
        self.inner
            .replay
            .lock()
            .map_err(|_| WireReplayError::Unavailable)?
            .reserve(
                &self.inner.server_instance_id,
                self.inner.transport,
                request_id,
                tool_name,
                call_params,
                ticket_request_canonical,
                now,
            )
    }
}

fn approved_request_is_valid(tool_name: &str, arguments: &Map<String, Value>) -> bool {
    if crate::approved_workspace::is_approved_workspace_tool(tool_name) {
        crate::approved_workspace::request_is_valid(tool_name, arguments)
    } else {
        crate::diagram_mcp::approved_request_is_valid(tool_name, arguments)
    }
}

struct StandaloneProcessLock {
    _connection: Connection,
}

impl std::fmt::Debug for StandaloneProcessLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StandaloneProcessLock([HELD])")
    }
}

#[derive(Clone)]
struct DescriptorQualificationProvider {
    app_directory: PathBuf,
    server_instance_id: String,
    descriptor_sha256: String,
}

impl ApprovedWorkspaceQualificationProvider for DescriptorQualificationProvider {
    fn current_qualification(
        &self,
        now_unix: u64,
    ) -> Result<ApprovedMcpQualificationSnapshotV1, ApprovedWorkspaceQualificationError> {
        let loaded = load_verified_descriptor(
            &self.app_directory,
            &self.server_instance_id,
            Some(&self.descriptor_sha256),
            now_unix,
        )
        .map_err(|_| ApprovedWorkspaceQualificationError::Unavailable)?;
        Ok(loaded.descriptor.claims.qualification.clone())
    }
}

struct LoadedDescriptor {
    descriptor: SignedStandaloneDescriptorV1,
    descriptor_sha256: String,
    key_ring: ApprovedKeyRing,
}

pub fn default_app_local_data_directory() -> Result<PathBuf, StandaloneApprovedError> {
    // `dirs` resolves FOLDERID_LocalAppData through SHGetKnownFolderPath on
    // Windows. Host-controlled environment variables are never consulted.
    let root = known_local_data_directory()?;
    Ok(root.join(APP_IDENTIFIER))
}

fn known_local_data_directory() -> Result<PathBuf, StandaloneApprovedError> {
    dirs::data_local_dir()
        .filter(|path| path.is_absolute())
        .ok_or(StandaloneApprovedError::Unavailable)
}

fn qualification_canary_run_path_at(
    local_data_directory: &Path,
    canary_id: &str,
) -> Result<PathBuf, StandaloneApprovedError> {
    if !opaque_hex(canary_id, "mcpqcanary_", 32) {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    Ok(local_data_directory
        .join(QUALIFICATION_CANARY_APP_IDENTIFIER)
        .join(QUALIFICATION_CANARY_RUNS_DIRECTORY)
        .join(canary_id))
}

fn canonical_exact_directory(path: &Path) -> Result<PathBuf, StandaloneApprovedError> {
    let canonical = canonical_directory(path)?;
    if canonical != path {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    Ok(canonical)
}

fn ensure_canary_parent_directory(path: &Path) -> Result<(), StandaloneApprovedError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(StandaloneApprovedError::Unavailable),
    }
    canonical_exact_directory(path).map(|_| ())
}

fn create_qualification_canary_run_directory_at(
    local_data_directory: &Path,
    canary_id: &str,
) -> Result<PathBuf, StandaloneApprovedError> {
    let local_data_directory = canonical_directory(local_data_directory)?;
    let path = qualification_canary_run_path_at(&local_data_directory, canary_id)?;
    let namespace = local_data_directory.join(QUALIFICATION_CANARY_APP_IDENTIFIER);
    ensure_canary_parent_directory(&namespace)?;
    let runs = namespace.join(QUALIFICATION_CANARY_RUNS_DIRECTORY);
    ensure_canary_parent_directory(&runs)?;
    fs::create_dir(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            StandaloneApprovedError::InvalidBinding
        } else {
            StandaloneApprovedError::Unavailable
        }
    })?;
    canonical_exact_directory(&path)
}

pub fn create_qualification_canary_run_directory(
    canary_id: &str,
) -> Result<PathBuf, StandaloneApprovedError> {
    create_qualification_canary_run_directory_at(&known_local_data_directory()?, canary_id)
}

fn qualification_canary_app_local_data_directory_at(
    local_data_directory: &Path,
    canary_id: &str,
) -> Result<PathBuf, StandaloneApprovedError> {
    let local_data_directory = canonical_directory(local_data_directory)?;
    let run = qualification_canary_run_path_at(&local_data_directory, canary_id)?;
    let run = canonical_exact_directory(&run)?;
    let app_local = run.join("app-local");
    canonical_exact_directory(&app_local)
}

pub fn qualification_canary_app_local_data_directory(
    canary_id: &str,
) -> Result<PathBuf, StandaloneApprovedError> {
    qualification_canary_app_local_data_directory_at(&known_local_data_directory()?, canary_id)
}

fn validate_canary_cleanup_tree(path: &Path) -> Result<(), StandaloneApprovedError> {
    validate_fixed_local_directory(path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    for entry in fs::read_dir(path).map_err(|_| StandaloneApprovedError::Unavailable)? {
        let entry = entry.map_err(|_| StandaloneApprovedError::Unavailable)?;
        let child = entry.path();
        let metadata =
            fs::symlink_metadata(&child).map_err(|_| StandaloneApprovedError::Unavailable)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            validate_canary_cleanup_tree(&child)?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            validate_fixed_local_regular_file(&child)
                .map_err(|_| StandaloneApprovedError::Unavailable)?;
        } else {
            return Err(StandaloneApprovedError::Unavailable);
        }
    }
    Ok(())
}

fn remove_qualification_canary_run_directory_at(
    local_data_directory: &Path,
    canary_id: &str,
) -> Result<(), StandaloneApprovedError> {
    let local_data_directory = canonical_directory(local_data_directory)?;
    let path = qualification_canary_run_path_at(&local_data_directory, canary_id)?;
    canonical_exact_directory(&path)?;
    validate_canary_cleanup_tree(&path)?;
    fs::remove_dir_all(&path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(StandaloneApprovedError::Unavailable),
    }
}

pub fn remove_qualification_canary_run_directory(
    canary_id: &str,
) -> Result<(), StandaloneApprovedError> {
    remove_qualification_canary_run_directory_at(&known_local_data_directory()?, canary_id)
}

pub fn provision_standalone_session(
    request: StandaloneSessionProvisioningV1,
) -> Result<ProvisionedStandaloneSessionV1, StandaloneApprovedError> {
    validate_provisioning(&request)?;
    let (grant_groups, grants) = canonical_grants(&request.grant_groups)?;
    let app_directory = canonical_directory(&request.app_local_data_directory)?;
    let state_root = canonical_directory(&app_directory.join(APPROVED_MCP_STATE_RELATIVE))?;
    let approved_root = canonical_directory(&request.approved_root)?;
    let work_product_root = canonical_directory(&request.work_product_root)?;
    let ticket_root = canonical_directory(&request.ticket_root)?;

    let qualification_evidence_path = state_root.join("qualification").join(EVIDENCE_FILE);
    validate_fixed_local_regular_file(&qualification_evidence_path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let evidence = read_bounded(&qualification_evidence_path, MAX_DESCRIPTOR_BYTES)?;
    if sha256_hex(&evidence) != request.qualification.evidence_sha256.as_str() {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let key_ring = load_key_ring()?;
    validate_key_binding(&request.qualification, &key_ring)?;
    let server_instance_id = request.server_instance_id.clone();
    initialize_wire_replay_guard(
        &ticket_root,
        &server_instance_id,
        &request.session_id,
        request.ticket_revocation_epoch,
        &key_ring.ticket,
    )?;
    let mut session_secret = match create_session_secret(&server_instance_id) {
        Ok(secret) => secret,
        Err(error) => {
            let _ = cleanup_new_wire_replay_guard(&ticket_root, &server_instance_id);
            return Err(error);
        }
    };
    let result = (|| {
        let http_bearer = match request.transport {
            McpTransportBindingV1::Stdio => None,
            McpTransportBindingV1::StreamableHttp => Some(Zeroizing::new(format!(
                "mcp-http-{}{}",
                Uuid::new_v4().simple(),
                Uuid::new_v4().simple()
            ))),
        };
        let claims = StandaloneDescriptorClaimsV1 {
            schema_version: DESCRIPTOR_SCHEMA.to_owned(),
            descriptor_id: format!("mcpd_{}", Uuid::new_v4().simple()),
            connector_id: request.connector_id,
            workspace_instance_id: request.workspace_instance_id,
            server_instance_id,
            session_id: request.session_id,
            transport: request.transport,
            grant_groups,
            grants,
            app_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: APPROVED_MCP_POLICY_ID.to_owned(),
            policy_version: APPROVED_MCP_POLICY_VERSION,
            approved_root,
            work_product_root,
            ticket_root: ticket_root.clone(),
            qualification_evidence_path,
            legal_database_path: canonical_file(&request.legal_database_path)?,
            user_database_path: canonical_file(&request.user_database_path)?,
            allowed_roots: canonical_directories(&request.allowed_roots)?,
            output_root: canonical_directory(&request.output_root)?,
            qualification: request.qualification,
            ticket_revocation_epoch: request.ticket_revocation_epoch,
            session_secret_sha256: sha256_hex(&session_secret),
            issued_at_unix: request.issued_at_unix,
            expires_at_unix: request.expires_at_unix,
            http_bind: request.http_bind,
            allowed_origins: request.allowed_origins,
            http_bearer: http_bearer.as_ref().map(|value| value.to_string()),
        };
        validate_claims_layout(&app_directory, &claims, request.issued_at_unix)?;
        let descriptor = sign_descriptor(claims, &key_ring.ticket)?;
        let plaintext = Zeroizing::new(
            canonical_json_v1(&descriptor).map_err(|_| StandaloneApprovedError::InvalidBinding)?,
        );
        if plaintext.len() > MAX_DESCRIPTOR_BYTES {
            return Err(StandaloneApprovedError::InvalidBinding);
        }
        let protected =
            protect_local(&plaintext).map_err(|_| StandaloneApprovedError::Unavailable)?;
        let descriptor_path = ticket_root.join(STANDALONE_DESCRIPTOR_FILE);
        write_new_synced(&descriptor_path, &protected)?;
        let metadata = metadata(&descriptor.claims, true, "ACTIVE");
        Ok(ProvisionedStandaloneSessionV1 {
            metadata,
            http_bearer,
        })
    })();
    zeroize(&mut session_secret);
    if result.is_err() {
        let _ = delete_session_secret(&request.server_instance_id);
        let _ = cleanup_new_wire_replay_guard(&ticket_root, &request.server_instance_id);
    }
    result
}

pub fn load_standalone_for_binary(
    app_directory: &Path,
    server_instance_id: &str,
    command: &Command,
) -> Result<LoadedStandaloneApprovedSession, StandaloneApprovedError> {
    let now = now_seconds()?;
    let loaded = load_verified_descriptor(app_directory, server_instance_id, None, now)?;
    validate_transport_command(&loaded.descriptor.claims, command)?;
    let lock = acquire_process_lock(&loaded.descriptor.claims.ticket_root)?;
    let descriptor_sha256 = loaded.descriptor_sha256.clone();
    let ticket_root = loaded.descriptor.claims.ticket_root.clone();
    let transport = loaded.descriptor.claims.transport;
    let replay = open_wire_replay_guard(
        &ticket_root,
        server_instance_id,
        &loaded.descriptor.claims.session_id,
        loaded.descriptor.claims.ticket_revocation_epoch,
        &loaded.key_ring.ticket,
    )?;
    let (backend, tickets) = build_backend(app_directory, loaded, descriptor_sha256.clone(), now)?;
    let verified = load_verified_descriptor(
        app_directory,
        server_instance_id,
        Some(&descriptor_sha256),
        now,
    )?;
    let config = config_from_claims(&verified.descriptor.claims, command.clone())?;
    let broker = StandaloneCallBroker {
        inner: Arc::new(StandaloneCallBrokerInner {
            app_directory: app_directory.to_path_buf(),
            server_instance_id: server_instance_id.to_owned(),
            descriptor_sha256,
            transport,
            backend,
            tickets,
            replay: Mutex::new(replay),
        }),
    };
    Ok(LoadedStandaloneApprovedSession {
        config,
        broker,
        _process_lock: lock,
    })
}

pub fn inspect_standalone_sessions(
    app_directory: &Path,
) -> Result<Vec<StandaloneSessionMetadataV1>, StandaloneApprovedError> {
    let app_directory = canonical_directory(app_directory)?;
    let state_root = app_directory.join(APPROVED_MCP_STATE_RELATIVE);
    validate_fixed_local_directory(&state_root)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let session_root = state_root.join("ticket-sessions");
    if !session_root.exists() {
        return Ok(Vec::new());
    }
    validate_fixed_local_directory(&session_root)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let mut sessions = Vec::new();
    for entry in fs::read_dir(&session_root).map_err(|_| StandaloneApprovedError::Unavailable)? {
        let entry = entry.map_err(|_| StandaloneApprovedError::Unavailable)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !opaque_hex(&name, "srv_", 32) {
            continue;
        }
        let path = entry.path().join(STANDALONE_DESCRIPTOR_FILE);
        if !path.exists() {
            continue;
        }
        let authenticated = load_authenticated_descriptor(&app_directory, &name)?;
        let now = now_seconds()?;
        let (active, reason) = match validate_live(&authenticated, now) {
            Ok(()) => (true, "ACTIVE"),
            Err(StandaloneApprovedError::Expired) => (false, "EXPIRED"),
            Err(StandaloneApprovedError::Revoked) => (false, "REVOKED"),
            Err(_) => (false, "INVALID"),
        };
        sessions.push(metadata(&authenticated.descriptor.claims, active, reason));
    }
    sessions.sort_by_key(|session| std::cmp::Reverse(session.issued_at_unix));
    Ok(sessions)
}

pub fn revoke_standalone_session(
    app_directory: &Path,
    server_instance_id: &str,
) -> Result<(), StandaloneApprovedError> {
    let authenticated = load_authenticated_descriptor(app_directory, server_instance_id)?;
    let claims = &authenticated.descriptor.claims;
    let signer = ticket_signer(&authenticated.key_ring.ticket)?;
    let tickets = McpAccessTicketStore::initialize(
        &claims.ticket_root,
        signer,
        claims.workspace_instance_id.clone(),
        claims.server_instance_id.clone(),
    )
    .map_err(|_| StandaloneApprovedError::TicketFailed)?;
    let epoch_result = tickets.bump_revocation_epoch();
    let secret_result = delete_session_secret(server_instance_id);
    let replay_result = delete_wire_replay_artifacts(&claims.ticket_root, server_instance_id);
    if epoch_result.is_err() || secret_result.is_err() || replay_result.is_err() {
        return Err(StandaloneApprovedError::TicketFailed);
    }
    Ok(())
}

fn build_backend(
    app_directory: &Path,
    loaded: LoadedDescriptor,
    descriptor_sha256: String,
    now: u64,
) -> Result<(ApprovedWorkspaceBackend, McpAccessTicketStore), StandaloneApprovedError> {
    let claims = &loaded.descriptor.claims;
    let manifest_signer = ManifestSigningKey::from_bytes(loaded.key_ring.manifest, KEY_VERSION)
        .map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    let approved =
        ApprovedWorkspaceService::open(&claims.approved_root, manifest_signer.verification_key())
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let work_signer = ManifestSigningKey::from_bytes(loaded.key_ring.work_product, KEY_VERSION)
        .map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    let work_verifier = work_signer.verification_key();
    let publisher = WorkProductPublisher::initialize(
        &claims.work_product_root,
        claims.workspace_instance_id.clone(),
        work_signer,
    )
    .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let products = WorkProductService::open(
        &claims.work_product_root,
        claims.workspace_instance_id.clone(),
        work_verifier,
    )
    .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let tickets = McpAccessTicketStore::initialize(
        &claims.ticket_root,
        ticket_signer(&loaded.key_ring.ticket)?,
        claims.workspace_instance_id.clone(),
        claims.server_instance_id.clone(),
    )
    .map_err(|_| StandaloneApprovedError::TicketFailed)?;
    let provider = Arc::new(DescriptorQualificationProvider {
        app_directory: app_directory.to_path_buf(),
        server_instance_id: claims.server_instance_id.clone(),
        descriptor_sha256,
    });
    let backend = ApprovedWorkspaceBackend::initialize(
        provider,
        approved,
        publisher,
        products,
        tickets.clone(),
        claims.transport,
        claims.session_id.clone(),
        now,
    )
    .map_err(map_backend_error)?;
    Ok((backend, tickets))
}

fn load_verified_descriptor(
    app_directory: &Path,
    server_instance_id: &str,
    expected_sha256: Option<&str>,
    now: u64,
) -> Result<LoadedDescriptor, StandaloneApprovedError> {
    let loaded = load_authenticated_descriptor(app_directory, server_instance_id)?;
    if expected_sha256.is_some_and(|expected| expected != loaded.descriptor_sha256) {
        return Err(StandaloneApprovedError::Revoked);
    }
    validate_live(&loaded, now)?;
    Ok(loaded)
}

fn load_authenticated_descriptor(
    app_directory: &Path,
    server_instance_id: &str,
) -> Result<LoadedDescriptor, StandaloneApprovedError> {
    if !opaque_hex(server_instance_id, "srv_", 32) {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let app_directory = canonical_directory(app_directory)?;
    let descriptor_path = descriptor_path(&app_directory, server_instance_id);
    validate_fixed_local_regular_file(&descriptor_path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let protected = read_bounded(&descriptor_path, MAX_DESCRIPTOR_BYTES * 2)?;
    let plaintext = Zeroizing::new(
        unprotect_local(&protected).map_err(|_| StandaloneApprovedError::InvalidBinding)?,
    );
    if plaintext.is_empty() || plaintext.len() > MAX_DESCRIPTOR_BYTES {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let descriptor: SignedStandaloneDescriptorV1 = strict_json_v1_from_slice(&plaintext)
        .map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    if canonical_json_v1(&descriptor).map_err(|_| StandaloneApprovedError::InvalidBinding)?
        != plaintext.as_slice()
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let key_ring = load_key_ring()?;
    verify_descriptor(&descriptor, &key_ring.ticket)?;
    validate_claims_layout(
        &app_directory,
        &descriptor.claims,
        descriptor.claims.issued_at_unix,
    )?;
    if descriptor.claims.server_instance_id != server_instance_id {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    Ok(LoadedDescriptor {
        descriptor_sha256: sha256_hex(&plaintext),
        descriptor,
        key_ring,
    })
}

fn validate_live(loaded: &LoadedDescriptor, now: u64) -> Result<(), StandaloneApprovedError> {
    let claims = &loaded.descriptor.claims;
    if now < claims.issued_at_unix || now >= claims.expires_at_unix {
        return Err(StandaloneApprovedError::Expired);
    }
    validate_key_binding(&claims.qualification, &loaded.key_ring)?;
    if !claims.qualification.approved_workspace_qualified_at(now) {
        return Err(StandaloneApprovedError::Revoked);
    }
    let current_exe = std::env::current_exe().map_err(|_| StandaloneApprovedError::Unavailable)?;
    let measured = measure_release_binary(&current_exe)
        .map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    if claims.qualification.mcp_binary_path_identity_sha256 != measured.path_identity_sha256
        || claims.qualification.mcp_binary_file_identity_sha256 != measured.file_identity_sha256
        || claims.qualification.mcp_binary_sha256 != measured.binary_sha256
        || claims.qualification.mcp_binary_version != env!("CARGO_PKG_VERSION")
    {
        return Err(StandaloneApprovedError::Revoked);
    }
    let evidence = read_bounded(&claims.qualification_evidence_path, MAX_DESCRIPTOR_BYTES)?;
    if sha256_hex(&evidence) != claims.qualification.evidence_sha256.as_str() {
        return Err(StandaloneApprovedError::Revoked);
    }
    let secret =
        read_session_secret(&claims.server_instance_id)?.ok_or(StandaloneApprovedError::Revoked)?;
    if !constant_time_eq(
        sha256_hex(&secret).as_bytes(),
        claims.session_secret_sha256.as_bytes(),
    ) {
        return Err(StandaloneApprovedError::Revoked);
    }
    let tickets = McpAccessTicketStore::initialize(
        &claims.ticket_root,
        ticket_signer(&loaded.key_ring.ticket)?,
        claims.workspace_instance_id.clone(),
        claims.server_instance_id.clone(),
    )
    .map_err(|_| StandaloneApprovedError::TicketFailed)?;
    if tickets
        .current_revocation_epoch()
        .map_err(|_| StandaloneApprovedError::TicketFailed)?
        != claims.ticket_revocation_epoch
    {
        return Err(StandaloneApprovedError::Revoked);
    }
    Ok(())
}

fn validate_provisioning(
    request: &StandaloneSessionProvisioningV1,
) -> Result<(), StandaloneApprovedError> {
    if canonical_grants(&request.grant_groups).is_err()
        || !opaque_hex(&request.server_instance_id, "srv_", 32)
        || !safe_binding(&request.session_id, 16, 160)
        || !matches!(
            request.connector_id.as_str(),
            "app" | "workbuddy" | "codex" | "opencode"
        )
        || request.issued_at_unix == 0
        || request.expires_at_unix <= request.issued_at_unix
        || request
            .expires_at_unix
            .saturating_sub(request.issued_at_unix)
            > MAX_SESSION_TTL_SECONDS
        || request.expires_at_unix > request.qualification.expires_at_unix
        || !request
            .qualification
            .approved_workspace_qualified_at(request.issued_at_unix)
        || request.allowed_roots.is_empty()
        || request.allowed_roots.len() > 64
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let duration = request
        .expires_at_unix
        .saturating_sub(request.issued_at_unix);
    if request.transport == McpTransportBindingV1::StreamableHttp
        && duration > MAX_HTTP_SESSION_TTL_SECONDS
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let normalized_origins = normalize_allowed_origins(request.allowed_origins.clone())
        .map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    if normalized_origins != request.allowed_origins {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    match (request.transport, request.http_bind) {
        (McpTransportBindingV1::Stdio, None) => {
            if !request.allowed_origins.is_empty() {
                return Err(StandaloneApprovedError::InvalidBinding);
            }
        }
        (McpTransportBindingV1::StreamableHttp, Some(bind))
            if bind.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) && bind.port() >= 1024 => {}
        _ => return Err(StandaloneApprovedError::InvalidBinding),
    }
    Ok(())
}

fn validate_claims_layout(
    app_directory: &Path,
    claims: &StandaloneDescriptorClaimsV1,
    now: u64,
) -> Result<(), StandaloneApprovedError> {
    let (expected_groups, expected_grants) = canonical_grants(&claims.grant_groups)?;
    let state_root = app_directory.join(APPROVED_MCP_STATE_RELATIVE);
    let expected_ticket_root = state_root
        .join("ticket-sessions")
        .join(&claims.server_instance_id);
    if claims.schema_version != DESCRIPTOR_SCHEMA
        || !opaque_hex(&claims.descriptor_id, "mcpd_", 32)
        || !opaque_hex(&claims.server_instance_id, "srv_", 32)
        || !safe_binding(&claims.session_id, 16, 160)
        || !matches!(
            claims.connector_id.as_str(),
            "app" | "workbuddy" | "codex" | "opencode"
        )
        || claims.grant_groups != expected_groups
        || claims.grants != expected_grants
        || claims.app_version != env!("CARGO_PKG_VERSION")
        || claims.policy_id != APPROVED_MCP_POLICY_ID
        || claims.policy_version != APPROVED_MCP_POLICY_VERSION
        || claims.approved_root != state_root.join("approved-generations")
        || claims.work_product_root != state_root.join("work-products")
        || claims.ticket_root != expected_ticket_root
        || claims.qualification_evidence_path
            != state_root.join("qualification").join(EVIDENCE_FILE)
        || claims.expires_at_unix <= claims.issued_at_unix
        || claims.expires_at_unix.saturating_sub(claims.issued_at_unix) > MAX_SESSION_TTL_SECONDS
        || claims.expires_at_unix > claims.qualification.expires_at_unix
        || claims.issued_at_unix > now
        || claims.session_secret_sha256.len() != 64
        || !lower_hex(&claims.session_secret_sha256, 64)
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let duration = claims.expires_at_unix.saturating_sub(claims.issued_at_unix);
    if claims.transport == McpTransportBindingV1::StreamableHttp
        && duration > MAX_HTTP_SESSION_TTL_SECONDS
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let normalized_origins = normalize_allowed_origins(claims.allowed_origins.clone())
        .map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    if normalized_origins != claims.allowed_origins {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    validate_fixed_local_directory(&state_root)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    validate_fixed_local_directory(&claims.approved_root)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    validate_fixed_local_directory(&claims.work_product_root)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    validate_fixed_local_directory(&claims.ticket_root)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    validate_fixed_local_regular_file(&claims.ticket_root.join(TICKET_DATABASE_FILE))
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    validate_fixed_local_regular_file(&claims.qualification_evidence_path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    for path in &claims.allowed_roots {
        validate_fixed_local_directory(path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    }
    validate_fixed_local_directory(&claims.output_root)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    validate_fixed_local_regular_file(&claims.legal_database_path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    validate_fixed_local_regular_file(&claims.user_database_path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    match (
        claims.transport,
        claims.http_bind,
        claims.http_bearer.as_deref(),
    ) {
        (McpTransportBindingV1::Stdio, None, None) if claims.allowed_origins.is_empty() => Ok(()),
        (McpTransportBindingV1::StreamableHttp, Some(bind), Some(token))
            if bind.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
                && bind.port() >= 1024
                && (32..=512).contains(&token.len())
                && token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) =>
        {
            Ok(())
        }
        _ => Err(StandaloneApprovedError::InvalidBinding),
    }
}

fn validate_key_binding(
    qualification: &ApprovedMcpQualificationSnapshotV1,
    key_ring: &ApprovedKeyRing,
) -> Result<(), StandaloneApprovedError> {
    let ticket_key_id = format!("mcpkey_{}", &sha256_hex(&key_ring.ticket)[..24]);
    let mut epoch = [0_u8; 8];
    epoch.copy_from_slice(&key_ring.qualification_epoch[..8]);
    let mut epoch = u64::from_be_bytes(epoch);
    if epoch == 0 {
        epoch = 1;
    }
    if qualification.server_key_id != ticket_key_id
        || qualification.server_key_version != KEY_VERSION
        || qualification.revocation_epoch != epoch
        || !qualification.exact_app_policy_binding
        || !qualification.exact_server_key_binding
        || qualification.app_version != env!("CARGO_PKG_VERSION")
        || qualification.policy_id != APPROVED_MCP_POLICY_ID
        || qualification.policy_version != APPROVED_MCP_POLICY_VERSION
    {
        return Err(StandaloneApprovedError::Revoked);
    }
    Ok(())
}

fn validate_transport_command(
    claims: &StandaloneDescriptorClaimsV1,
    command: &Command,
) -> Result<(), StandaloneApprovedError> {
    match (claims.transport, command) {
        (McpTransportBindingV1::Stdio, Command::Stdio) => Ok(()),
        (McpTransportBindingV1::StreamableHttp, Command::Serve { bind })
            if bind.is_none() || *bind == claims.http_bind =>
        {
            Ok(())
        }
        _ => Err(StandaloneApprovedError::InvalidBinding),
    }
}

fn config_from_claims(
    claims: &StandaloneDescriptorClaimsV1,
    command: Command,
) -> Result<ResolvedConfig, StandaloneApprovedError> {
    let bind = claims
        .http_bind
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787));
    let bearer = claims
        .http_bearer
        .as_ref()
        .map(|token| BearerSecret::from_token_bytes(token.as_bytes().to_vec()))
        .transpose()
        .map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    Ok(ResolvedConfig {
        legal_db: claims.legal_database_path.clone(),
        user_db: claims.user_database_path.clone(),
        allowed_roots: claims.allowed_roots.clone(),
        output_root: claims.output_root.clone(),
        privacy_profile: PrivacyProfile::ApprovedCaseWorkspace,
        bind,
        allowed_origins: claims.allowed_origins.clone(),
        allowed_hosts: vec![bind.to_string()],
        bearer,
        dangerously_allow_insecure_non_loopback_http: false,
        limits: Limits {
            max_body_bytes: 2 * 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            max_concurrency: 8,
        },
        command,
    })
}

fn sign_descriptor(
    claims: StandaloneDescriptorClaimsV1,
    ticket_key: &[u8; 32],
) -> Result<SignedStandaloneDescriptorV1, StandaloneApprovedError> {
    let canonical =
        canonical_json_v1(&claims).map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    let signing_key_id = format!("mcpkey_{}", &sha256_hex(ticket_key)[..24]);
    Ok(SignedStandaloneDescriptorV1 {
        claims,
        canonical_claims_sha256: sha256_hex(&canonical),
        signing_key_id,
        signing_key_version: KEY_VERSION,
        mac_hex: hmac_hex(ticket_key, &canonical)?,
    })
}

fn verify_descriptor(
    descriptor: &SignedStandaloneDescriptorV1,
    ticket_key: &[u8; 32],
) -> Result<(), StandaloneApprovedError> {
    let canonical = canonical_json_v1(&descriptor.claims)
        .map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    let expected_key_id = format!("mcpkey_{}", &sha256_hex(ticket_key)[..24]);
    if descriptor.canonical_claims_sha256 != sha256_hex(&canonical)
        || descriptor.signing_key_id != expected_key_id
        || descriptor.signing_key_version != KEY_VERSION
        || !verify_hmac(ticket_key, &canonical, &descriptor.mac_hex)
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    Ok(())
}

fn hmac_hex(key: &[u8; 32], bytes: &[u8]) -> Result<String, StandaloneApprovedError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| StandaloneApprovedError::InvalidBinding)?;
    mac.update(DESCRIPTOR_DOMAIN);
    mac.update(bytes);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn verify_hmac(key: &[u8; 32], bytes: &[u8], expected_hex: &str) -> bool {
    let Some(expected) = hex_decode_32(expected_hex) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(DESCRIPTOR_DOMAIN);
    mac.update(bytes);
    mac.verify_slice(&expected).is_ok()
}

fn load_key_ring() -> Result<ApprovedKeyRing, StandaloneApprovedError> {
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
    Ok(ApprovedKeyRing {
        manifest: read_core_key(&store, "approved-manifest")?,
        work_product: read_core_key(&store, "work-product-manifest")?,
        ticket: read_core_key(&store, "mcp-access-ticket")?,
        qualification_epoch: read_core_key(&store, "mcp-qualification-revocation-epoch")?,
    })
}

fn read_core_key(
    store: &WindowsCredentialStore,
    role: &str,
) -> Result<[u8; 32], StandaloneApprovedError> {
    let secret = store
        .read_api_key(&ProviderCredentialKey::new(role, KEY_ACCOUNT))
        .map_err(|_| StandaloneApprovedError::Unavailable)?
        .ok_or(StandaloneApprovedError::Unavailable)?;
    decode_secret(secret.expose_secret(), KEY_FORMAT_PREFIX)
}

fn create_session_secret(server_id: &str) -> Result<[u8; 32], StandaloneApprovedError> {
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
    let key = ProviderCredentialKey::new(SESSION_SECRET_PROVIDER, server_id);
    if store
        .read_api_key(&key)
        .map_err(|_| StandaloneApprovedError::Unavailable)?
        .is_some()
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let mut bytes = [0_u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    let encoded = format!("{SESSION_SECRET_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    store
        .write_api_key(&key, ApiSecret::new(encoded))
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    Ok(bytes)
}

fn read_session_secret(server_id: &str) -> Result<Option<[u8; 32]>, StandaloneApprovedError> {
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
    store
        .read_api_key(&ProviderCredentialKey::new(
            SESSION_SECRET_PROVIDER,
            server_id,
        ))
        .map_err(|_| StandaloneApprovedError::Unavailable)?
        .map(|secret| decode_secret(secret.expose_secret(), SESSION_SECRET_PREFIX))
        .transpose()
}

fn delete_session_secret(server_id: &str) -> Result<(), StandaloneApprovedError> {
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX)
        .delete_api_key(&ProviderCredentialKey::new(
            SESSION_SECRET_PROVIDER,
            server_id,
        ))
        .map_err(|_| StandaloneApprovedError::Unavailable)
}

fn decode_secret(value: &str, prefix: &str) -> Result<[u8; 32], StandaloneApprovedError> {
    let mut decoded = URL_SAFE_NO_PAD
        .decode(
            value
                .strip_prefix(prefix)
                .ok_or(StandaloneApprovedError::Unavailable)?,
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    if decoded.len() != 32 || decoded.iter().all(|byte| *byte == 0) {
        zeroize(&mut decoded);
        return Err(StandaloneApprovedError::Unavailable);
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded);
    zeroize(&mut decoded);
    Ok(key)
}

fn ticket_signer(key: &[u8; 32]) -> Result<McpTicketSigningKey, StandaloneApprovedError> {
    McpTicketSigningKey::from_bytes(
        *key,
        format!("mcpkey_{}", &sha256_hex(key)[..24]),
        KEY_VERSION,
    )
    .map_err(|_| StandaloneApprovedError::TicketFailed)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireReplayPendingTransitionV1 {
    schema_version: String,
    server_instance_id: String,
    session_id: String,
    database_id: String,
    ticket_revocation_epoch: u64,
    transition_nonce: String,
    ticket_request_mac_hex: String,
    wire_identity_sha256: String,
    canonical_wire_sha256: String,
    old_count: u64,
    old_chain_head_sha256: String,
    new_count: u64,
    new_chain_head_sha256: String,
    expected_tail_sequence: u64,
    expected_tail_mac_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireReplayCredentialStateV2 {
    schema_version: String,
    server_instance_id: String,
    session_id: String,
    database_id: String,
    ticket_revocation_epoch: u64,
    sequence: u64,
    chain_head_sha256: String,
    pending: Option<WireReplayPendingTransitionV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignedWireReplayCredentialStateV2 {
    state: WireReplayCredentialStateV2,
    mac_hex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireReplayDatabaseEntryV2 {
    sequence: u64,
    wire_identity_sha256: String,
    server_instance_id: String,
    transport: String,
    request_id_json: String,
    canonical_wire_sha256: String,
    tool_name: String,
    created_at_unix: u64,
    previous_chain_sha256: String,
    chain_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedWireReplayChainV2 {
    count: u64,
    chain_head_sha256: String,
    tail_mac_hex: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WireReplayFaultPoint {
    None,
    #[cfg(test)]
    AfterPendingBeforeDatabase,
    #[cfg(test)]
    AfterDatabaseBeforeCredentialHead,
    #[cfg(test)]
    AfterCredentialHeadBeforePendingCleanup,
}

struct WireReplayGuard {
    connection: Connection,
    path: PathBuf,
    auth_key: [u8; 32],
    state: WireReplayCredentialStateV2,
}

impl Drop for WireReplayGuard {
    fn drop(&mut self) {
        zeroize(&mut self.auth_key);
    }
}

fn initialize_wire_replay_guard(
    root: &Path,
    server_instance_id: &str,
    session_id: &str,
    ticket_revocation_epoch: u64,
    ticket_key: &[u8; 32],
) -> Result<(), StandaloneApprovedError> {
    if !opaque_hex(server_instance_id, "srv_", 32) || !safe_binding(session_id, 16, 160) {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    validate_fixed_local_directory(root).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let path = root.join(WIRE_REPLAY_DATABASE_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    if file.sync_all().is_err() {
        drop(file);
        let _ = delete_wire_replay_database_file(root, WIRE_REPLAY_DATABASE_FILE);
        return Err(StandaloneApprovedError::Unavailable);
    }
    drop(file);
    let result = (|| {
        validate_replay_file(&path)?;
        let connection =
            Connection::open(&path).map_err(|_| StandaloneApprovedError::Unavailable)?;
        configure_new_wire_replay_guard(&connection)?;
        let database_id = format!("wrdb_{}", Uuid::new_v4().simple());
        connection
            .execute(
                "INSERT INTO replay_meta(
                    singleton,database_id,server_instance_id,session_id,ticket_revocation_epoch
                 ) VALUES(1,?1,?2,?3,?4)",
                params![
                    database_id,
                    server_instance_id,
                    session_id,
                    i64::try_from(ticket_revocation_epoch)
                        .map_err(|_| StandaloneApprovedError::InvalidBinding)?
                ],
            )
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        drop(connection);
        validate_replay_file(&path)?;
        let auth_key = replay_auth_key(ticket_key, server_instance_id)?;
        let state = WireReplayCredentialStateV2 {
            schema_version: WIRE_REPLAY_STATE_SCHEMA.to_owned(),
            server_instance_id: server_instance_id.to_owned(),
            session_id: session_id.to_owned(),
            database_id: database_id.clone(),
            ticket_revocation_epoch,
            sequence: 0,
            chain_head_sha256: replay_genesis(&auth_key, server_instance_id, &database_id)?,
            pending: None,
        };
        create_wire_replay_state(&state, &auth_key)
    })();
    if result.is_err() {
        // `create_new` above proves this invocation created the V2 database.
        // Never remove a pre-existing path on an initialization failure.
        let _ = delete_wire_replay_database_file(root, WIRE_REPLAY_DATABASE_FILE);
    }
    result
}

fn open_wire_replay_guard(
    root: &Path,
    server_instance_id: &str,
    session_id: &str,
    ticket_revocation_epoch: u64,
    ticket_key: &[u8; 32],
) -> Result<WireReplayGuard, StandaloneApprovedError> {
    validate_fixed_local_directory(root).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let path = root.join(WIRE_REPLAY_DATABASE_FILE);
    validate_replay_file(&path)?;
    let auth_key = replay_auth_key(ticket_key, server_instance_id)?;
    let mut state = read_wire_replay_state(server_instance_id, &auth_key)?
        .ok_or(StandaloneApprovedError::Unavailable)?;
    validate_wire_replay_state(
        &state,
        server_instance_id,
        session_id,
        ticket_revocation_epoch,
    )?;
    let connection = Connection::open(&path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    configure_existing_wire_replay_guard(&connection)?;
    state = recover_wire_replay_pending_transition(&connection, state, &auth_key)?;
    verify_wire_replay_chain(&connection, &state, &auth_key)?;
    validate_replay_file(&path)?;
    Ok(WireReplayGuard {
        connection,
        path,
        auth_key,
        state,
    })
}

impl WireReplayGuard {
    #[allow(clippy::too_many_arguments)]
    fn reserve(
        &mut self,
        server_instance_id: &str,
        transport: McpTransportBindingV1,
        request_id: &Value,
        tool_name: &str,
        call_params: &Value,
        ticket_request_canonical: &[u8],
        now: u64,
    ) -> Result<(), WireReplayError> {
        self.reserve_with_fault_point(
            server_instance_id,
            transport,
            request_id,
            tool_name,
            call_params,
            ticket_request_canonical,
            now,
            WireReplayFaultPoint::None,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn reserve_with_fault(
        &mut self,
        server_instance_id: &str,
        transport: McpTransportBindingV1,
        request_id: &Value,
        tool_name: &str,
        call_params: &Value,
        ticket_request_canonical: &[u8],
        now: u64,
        fault: WireReplayFaultPoint,
    ) -> Result<(), WireReplayError> {
        self.reserve_with_fault_point(
            server_instance_id,
            transport,
            request_id,
            tool_name,
            call_params,
            ticket_request_canonical,
            now,
            fault,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn reserve_with_fault_point(
        &mut self,
        server_instance_id: &str,
        transport: McpTransportBindingV1,
        request_id: &Value,
        tool_name: &str,
        call_params: &Value,
        ticket_request_canonical: &[u8],
        now: u64,
        fault: WireReplayFaultPoint,
    ) -> Result<(), WireReplayError> {
        let _ = fault;
        validate_replay_file(&self.path).map_err(|_| WireReplayError::Unavailable)?;
        self.verify_current_head()
            .map_err(|_| WireReplayError::Unavailable)?;
        if server_instance_id != self.state.server_instance_id
            || self.state.pending.is_some()
            || ticket_request_canonical.is_empty()
            || ticket_request_canonical.len() > MAX_ARGUMENT_BYTES + 4096
            || self.state.sequence >= MAX_WIRE_REPLAY_ROWS
        {
            return Err(WireReplayError::Unavailable);
        }
        let request_id_bytes =
            canonical_json_v1(request_id).map_err(|_| WireReplayError::Unavailable)?;
        if request_id_bytes.is_empty() || request_id_bytes.len() > 512 {
            return Err(WireReplayError::Unavailable);
        }
        let transport = transport_name(transport);
        let wire_bytes = canonical_standalone_wire(request_id, call_params)?;
        let identity = json!({
            "server_instance_id":server_instance_id,
            "transport":transport,
            "request_id":request_id
        });
        let identity_bytes =
            canonical_json_v1(&identity).map_err(|_| WireReplayError::Unavailable)?;
        let identity_sha256 = sha256_hex(&identity_bytes);
        let replayed: i64 = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM wire_requests WHERE wire_identity_sha256=?1)",
                params![identity_sha256],
                |row| row.get(0),
            )
            .map_err(|_| WireReplayError::Unavailable)?;
        if replayed != 0 {
            return Err(WireReplayError::Replayed);
        }

        let sequence = self
            .state
            .sequence
            .checked_add(1)
            .ok_or(WireReplayError::Unavailable)?;
        let request_id_json =
            String::from_utf8(request_id_bytes).map_err(|_| WireReplayError::Unavailable)?;
        let wire_sha256 = sha256_hex(&wire_bytes);
        let created_at = i64::try_from(now).map_err(|_| WireReplayError::Unavailable)?;
        let previous_chain_sha256 = self.state.chain_head_sha256.clone();
        let chain_sha256 = replay_entry_chain(
            &self.auth_key,
            &self.state.database_id,
            sequence,
            &previous_chain_sha256,
            &identity_sha256,
            server_instance_id,
            transport,
            &request_id_json,
            &wire_sha256,
            tool_name,
            now,
        )
        .map_err(|_| WireReplayError::Unavailable)?;
        let entry = WireReplayDatabaseEntryV2 {
            sequence,
            wire_identity_sha256: identity_sha256.clone(),
            server_instance_id: server_instance_id.to_owned(),
            transport: transport.to_owned(),
            request_id_json: request_id_json.clone(),
            canonical_wire_sha256: wire_sha256.clone(),
            tool_name: tool_name.to_owned(),
            created_at_unix: now,
            previous_chain_sha256: previous_chain_sha256.clone(),
            chain_sha256: chain_sha256.clone(),
        };
        let pending = WireReplayPendingTransitionV1 {
            schema_version: WIRE_REPLAY_PENDING_SCHEMA.to_owned(),
            server_instance_id: self.state.server_instance_id.clone(),
            session_id: self.state.session_id.clone(),
            database_id: self.state.database_id.clone(),
            ticket_revocation_epoch: self.state.ticket_revocation_epoch,
            transition_nonce: replay_transition_nonce(),
            ticket_request_mac_hex: replay_ticket_request_mac(
                &self.auth_key,
                ticket_request_canonical,
            )
            .map_err(|_| WireReplayError::Unavailable)?,
            wire_identity_sha256: identity_sha256,
            canonical_wire_sha256: wire_sha256,
            old_count: self.state.sequence,
            old_chain_head_sha256: previous_chain_sha256,
            new_count: sequence,
            new_chain_head_sha256: chain_sha256,
            expected_tail_sequence: sequence,
            expected_tail_mac_hex: replay_tail_mac(&self.auth_key, &entry)
                .map_err(|_| WireReplayError::Unavailable)?,
        };
        let expected_state = self.state.clone();
        let mut pending_state = expected_state.clone();
        pending_state.pending = Some(pending);
        replace_wire_replay_state(&expected_state, &pending_state, &self.auth_key)
            .map_err(|_| WireReplayError::Unavailable)?;
        self.state = pending_state;

        #[cfg(test)]
        if fault == WireReplayFaultPoint::AfterPendingBeforeDatabase {
            return Err(WireReplayError::Unavailable);
        }

        self.connection
            .execute(
                "INSERT INTO wire_requests(
                    sequence,wire_identity_sha256,server_instance_id,transport,request_id_json,
                    canonical_wire_sha256,tool_name,created_at_unix,previous_chain_sha256,
                    chain_sha256
                ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    i64::try_from(entry.sequence).map_err(|_| WireReplayError::Unavailable)?,
                    &entry.wire_identity_sha256,
                    &entry.server_instance_id,
                    &entry.transport,
                    &entry.request_id_json,
                    &entry.canonical_wire_sha256,
                    &entry.tool_name,
                    created_at,
                    &entry.previous_chain_sha256,
                    &entry.chain_sha256
                ],
            )
            .map_err(|_| WireReplayError::Unavailable)?;

        #[cfg(test)]
        if fault == WireReplayFaultPoint::AfterDatabaseBeforeCredentialHead {
            return Err(WireReplayError::Unavailable);
        }

        let expected_pending_state = self.state.clone();
        let mut next_state = expected_pending_state.clone();
        next_state.sequence = entry.sequence;
        next_state.chain_head_sha256 = entry.chain_sha256;
        replace_wire_replay_state(&expected_pending_state, &next_state, &self.auth_key)
            .map_err(|_| WireReplayError::Unavailable)?;
        self.state = next_state;

        #[cfg(test)]
        if fault == WireReplayFaultPoint::AfterCredentialHeadBeforePendingCleanup {
            return Err(WireReplayError::Unavailable);
        }

        let expected_next_state = self.state.clone();
        let mut committed_state = expected_next_state.clone();
        committed_state.pending = None;
        replace_wire_replay_state(&expected_next_state, &committed_state, &self.auth_key)
            .map_err(|_| WireReplayError::Unavailable)?;
        self.state = committed_state;
        validate_replay_file(&self.path).map_err(|_| WireReplayError::Unavailable)
    }

    fn verify_current_head(&self) -> Result<(), StandaloneApprovedError> {
        if self.state.pending.is_some() {
            return Err(StandaloneApprovedError::Unavailable);
        }
        let (count, sequence, head): (i64, Option<i64>, Option<String>) = self
            .connection
            .query_row(
                "SELECT COUNT(*),MAX(sequence),(SELECT chain_sha256 FROM wire_requests ORDER BY sequence DESC LIMIT 1) FROM wire_requests",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let count = u64::try_from(count).map_err(|_| StandaloneApprovedError::Unavailable)?;
        let sequence = sequence
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        if count != self.state.sequence
            || sequence.unwrap_or(0) != self.state.sequence
            || head.as_deref().unwrap_or(&self.state.chain_head_sha256)
                != self.state.chain_head_sha256
        {
            return Err(StandaloneApprovedError::Unavailable);
        }
        Ok(())
    }
}

fn canonical_standalone_wire(
    request_id: &Value,
    call_params: &Value,
) -> Result<Vec<u8>, WireReplayError> {
    let wire = json!({
        "jsonrpc":"2.0",
        "id":request_id,
        "method":"tools/call",
        "params":call_params
    });
    let bytes = canonical_json_v1(&wire).map_err(|_| WireReplayError::Unavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_ARGUMENT_BYTES + 4096 {
        return Err(WireReplayError::Unavailable);
    }
    Ok(bytes)
}

fn replay_ticket_request_canonical(
    request: &McpAccessTicketRequestV1,
) -> Result<Vec<u8>, StandaloneApprovedError> {
    canonical_json_v1(&json!({
        "workspace_instance_id":request.workspace_instance_id.as_str(),
        "server_instance_id":request.server_instance_id,
        "transport":transport_name(request.transport),
        "session_id":request.session_id,
        "tool_name":request.tool_name,
        "purpose":request.purpose,
        "canonical_request_sha256":request.canonical_request_sha256.as_str(),
        "target":request.target,
        "issued_at_unix":request.issued_at_unix,
        "expires_at_unix":request.expires_at_unix
    }))
    .map_err(|_| StandaloneApprovedError::Unavailable)
}

fn replay_ticket_request_mac(
    auth_key: &[u8; 32],
    canonical: &[u8],
) -> Result<String, StandaloneApprovedError> {
    let mut mac =
        HmacSha256::new_from_slice(auth_key).map_err(|_| StandaloneApprovedError::Unavailable)?;
    mac.update(WIRE_REPLAY_TICKET_REQUEST_DOMAIN);
    mac.update(canonical);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn replay_transition_nonce() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn replay_tail_mac(
    auth_key: &[u8; 32],
    entry: &WireReplayDatabaseEntryV2,
) -> Result<String, StandaloneApprovedError> {
    let canonical = canonical_json_v1(entry).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let mut mac =
        HmacSha256::new_from_slice(auth_key).map_err(|_| StandaloneApprovedError::Unavailable)?;
    mac.update(WIRE_REPLAY_TAIL_DOMAIN);
    mac.update(&canonical);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn configure_new_wire_replay_guard(connection: &Connection) -> Result<(), StandaloneApprovedError> {
    configure_wire_replay_connection(connection)?;
    connection
        .execute_batch(
            "CREATE TABLE replay_meta(
                 singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
                 database_id TEXT NOT NULL UNIQUE CHECK(length(database_id)=37),
                 server_instance_id TEXT NOT NULL CHECK(length(server_instance_id)=36),
                 session_id TEXT NOT NULL CHECK(length(session_id) BETWEEN 16 AND 160),
                 ticket_revocation_epoch INTEGER NOT NULL CHECK(ticket_revocation_epoch>=0)
             ) STRICT;
             CREATE TABLE wire_requests(
                 sequence INTEGER PRIMARY KEY NOT NULL CHECK(sequence BETWEEN 1 AND 10000),
                 wire_identity_sha256 TEXT NOT NULL UNIQUE CHECK(length(wire_identity_sha256)=64),
                 server_instance_id TEXT NOT NULL CHECK(length(server_instance_id)=36),
                 transport TEXT NOT NULL CHECK(transport IN ('stdio','streamable_http')),
                 request_id_json TEXT NOT NULL CHECK(length(request_id_json) BETWEEN 1 AND 512),
                 canonical_wire_sha256 TEXT NOT NULL CHECK(length(canonical_wire_sha256)=64),
                 tool_name TEXT NOT NULL CHECK(length(tool_name) BETWEEN 1 AND 96),
                 created_at_unix INTEGER NOT NULL CHECK(created_at_unix>0),
                 previous_chain_sha256 TEXT NOT NULL CHECK(length(previous_chain_sha256)=64),
                 chain_sha256 TEXT NOT NULL UNIQUE CHECK(length(chain_sha256)=64)
             ) STRICT;",
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)
}

fn configure_existing_wire_replay_guard(
    connection: &Connection,
) -> Result<(), StandaloneApprovedError> {
    configure_wire_replay_connection(connection)?;
    let table_count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('replay_meta','wire_requests')",
            [],
            |row| row.get(0),
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    if table_count != 2 {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(())
}

fn configure_wire_replay_connection(
    connection: &Connection,
) -> Result<(), StandaloneApprovedError> {
    connection
        .busy_timeout(Duration::from_secs(2))
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    connection
        .execute_batch(
            "PRAGMA page_size=4096;
             PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             PRAGMA max_page_count=2048;",
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let page_size: i64 = connection
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    if page_size != 4096 {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(())
}

fn verify_wire_replay_chain(
    connection: &Connection,
    state: &WireReplayCredentialStateV2,
    auth_key: &[u8; 32],
) -> Result<(), StandaloneApprovedError> {
    if state.pending.is_some() {
        return Err(StandaloneApprovedError::Unavailable);
    }
    let verified = verified_wire_replay_chain(connection, state, auth_key)?;
    if verified.count != state.sequence || verified.chain_head_sha256 != state.chain_head_sha256 {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(())
}

fn recover_wire_replay_pending_transition(
    connection: &Connection,
    mut state: WireReplayCredentialStateV2,
    auth_key: &[u8; 32],
) -> Result<WireReplayCredentialStateV2, StandaloneApprovedError> {
    let Some(pending) = state.pending.clone() else {
        return Ok(state);
    };
    validate_wire_replay_pending(&state, &pending)?;
    let verified = verified_wire_replay_chain(connection, &state, auth_key)?;
    if verified.count != pending.new_count
        || verified.chain_head_sha256 != pending.new_chain_head_sha256
        || verified.tail_mac_hex.as_deref() != Some(pending.expected_tail_mac_hex.as_str())
    {
        // A pre-DB crash, missing row, multi-step advance, fork, or tamper is
        // deliberately not rolled back. Revocation and reprovisioning are the
        // only safe recovery for any state other than the exact next tail.
        return Err(StandaloneApprovedError::Unavailable);
    }

    let credential_is_old = state.sequence == pending.old_count
        && state.chain_head_sha256 == pending.old_chain_head_sha256;
    let credential_is_new = state.sequence == pending.new_count
        && state.chain_head_sha256 == pending.new_chain_head_sha256;
    if !credential_is_old && !credential_is_new {
        return Err(StandaloneApprovedError::Unavailable);
    }
    if credential_is_old {
        let expected_state = state.clone();
        state.sequence = pending.new_count;
        state.chain_head_sha256 = pending.new_chain_head_sha256.clone();
        replace_wire_replay_state(&expected_state, &state, auth_key)?;
    }
    let expected_state = state.clone();
    state.pending = None;
    replace_wire_replay_state(&expected_state, &state, auth_key)?;
    Ok(state)
}

fn validate_wire_replay_pending(
    state: &WireReplayCredentialStateV2,
    pending: &WireReplayPendingTransitionV1,
) -> Result<(), StandaloneApprovedError> {
    if pending.schema_version != WIRE_REPLAY_PENDING_SCHEMA
        || pending.server_instance_id != state.server_instance_id
        || pending.session_id != state.session_id
        || pending.database_id != state.database_id
        || pending.ticket_revocation_epoch != state.ticket_revocation_epoch
        || !lower_hex(&pending.transition_nonce, 64)
        || !lower_hex(&pending.ticket_request_mac_hex, 64)
        || !lower_hex(&pending.wire_identity_sha256, 64)
        || !lower_hex(&pending.canonical_wire_sha256, 64)
        || !lower_hex(&pending.old_chain_head_sha256, 64)
        || !lower_hex(&pending.new_chain_head_sha256, 64)
        || !lower_hex(&pending.expected_tail_mac_hex, 64)
        || pending.old_count >= MAX_WIRE_REPLAY_ROWS
        || pending.new_count != pending.old_count.saturating_add(1)
        || pending.new_count > MAX_WIRE_REPLAY_ROWS
        || pending.expected_tail_sequence != pending.new_count
        || (state.sequence != pending.old_count && state.sequence != pending.new_count)
    {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(())
}

fn verified_wire_replay_chain(
    connection: &Connection,
    state: &WireReplayCredentialStateV2,
    auth_key: &[u8; 32],
) -> Result<VerifiedWireReplayChainV2, StandaloneApprovedError> {
    let (database_id, server_instance_id, session_id, ticket_revocation_epoch): (
        String,
        String,
        String,
        i64,
    ) = connection
        .query_row(
            "SELECT database_id,server_instance_id,session_id,ticket_revocation_epoch
             FROM replay_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    if database_id != state.database_id
        || server_instance_id != state.server_instance_id
        || session_id != state.session_id
        || u64::try_from(ticket_revocation_epoch)
            .map_err(|_| StandaloneApprovedError::Unavailable)?
            != state.ticket_revocation_epoch
    {
        return Err(StandaloneApprovedError::Unavailable);
    }
    let mut expected_sequence = 0_u64;
    let mut expected_head =
        replay_genesis(auth_key, &state.server_instance_id, &state.database_id)?;
    let mut tail_mac_hex = None;
    let mut statement = connection
        .prepare(
            "SELECT sequence,wire_identity_sha256,server_instance_id,transport,request_id_json,
                    canonical_wire_sha256,tool_name,created_at_unix,previous_chain_sha256,chain_sha256
             FROM wire_requests ORDER BY sequence",
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    let mut rows = statement
        .query([])
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    while let Some(row) = rows
        .next()
        .map_err(|_| StandaloneApprovedError::Unavailable)?
    {
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(StandaloneApprovedError::Unavailable)?;
        let sequence = u64::try_from(
            row.get::<_, i64>(0)
                .map_err(|_| StandaloneApprovedError::Unavailable)?,
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let identity: String = row
            .get(1)
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let row_server: String = row
            .get(2)
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let transport: String = row
            .get(3)
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let request_id: String = row
            .get(4)
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let wire: String = row
            .get(5)
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let tool: String = row
            .get(6)
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let created_at = u64::try_from(
            row.get::<_, i64>(7)
                .map_err(|_| StandaloneApprovedError::Unavailable)?,
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let previous: String = row
            .get(8)
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        let chain: String = row
            .get(9)
            .map_err(|_| StandaloneApprovedError::Unavailable)?;
        if sequence != expected_sequence
            || row_server != state.server_instance_id
            || previous != expected_head
            || !lower_hex(&identity, 64)
            || !lower_hex(&wire, 64)
            || !lower_hex(&chain, 64)
            || replay_entry_chain(
                auth_key,
                &state.database_id,
                sequence,
                &previous,
                &identity,
                &row_server,
                &transport,
                &request_id,
                &wire,
                &tool,
                created_at,
            )? != chain
        {
            return Err(StandaloneApprovedError::Unavailable);
        }
        let entry = WireReplayDatabaseEntryV2 {
            sequence,
            wire_identity_sha256: identity,
            server_instance_id: row_server,
            transport,
            request_id_json: request_id,
            canonical_wire_sha256: wire,
            tool_name: tool,
            created_at_unix: created_at,
            previous_chain_sha256: previous,
            chain_sha256: chain.clone(),
        };
        tail_mac_hex = Some(replay_tail_mac(auth_key, &entry)?);
        expected_head = chain;
    }
    Ok(VerifiedWireReplayChainV2 {
        count: expected_sequence,
        chain_head_sha256: expected_head,
        tail_mac_hex,
    })
}

#[allow(clippy::too_many_arguments)]
fn replay_entry_chain(
    auth_key: &[u8; 32],
    database_id: &str,
    sequence: u64,
    previous_chain_sha256: &str,
    wire_identity_sha256: &str,
    server_instance_id: &str,
    transport: &str,
    request_id_json: &str,
    canonical_wire_sha256: &str,
    tool_name: &str,
    created_at_unix: u64,
) -> Result<String, StandaloneApprovedError> {
    replay_chain_hash(
        auth_key,
        &json!({
            "schema_version":WIRE_REPLAY_STATE_SCHEMA,
            "database_id":database_id,
            "sequence":sequence,
            "previous_chain_sha256":previous_chain_sha256,
            "wire_identity_sha256":wire_identity_sha256,
            "server_instance_id":server_instance_id,
            "transport":transport,
            "request_id_json":request_id_json,
            "canonical_wire_sha256":canonical_wire_sha256,
            "tool_name":tool_name,
            "created_at_unix":created_at_unix
        }),
    )
}

fn replay_genesis(
    auth_key: &[u8; 32],
    server_instance_id: &str,
    database_id: &str,
) -> Result<String, StandaloneApprovedError> {
    replay_chain_hash(
        auth_key,
        &json!({
            "schema_version":WIRE_REPLAY_STATE_SCHEMA,
            "server_instance_id":server_instance_id,
            "database_id":database_id,
            "genesis":true
        }),
    )
}

fn replay_chain_hash(
    auth_key: &[u8; 32],
    value: &Value,
) -> Result<String, StandaloneApprovedError> {
    let canonical = canonical_json_v1(value).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let mut mac =
        HmacSha256::new_from_slice(auth_key).map_err(|_| StandaloneApprovedError::Unavailable)?;
    mac.update(WIRE_REPLAY_CHAIN_DOMAIN);
    mac.update(&canonical);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn replay_auth_key(
    ticket_key: &[u8; 32],
    server_instance_id: &str,
) -> Result<[u8; 32], StandaloneApprovedError> {
    let mut mac =
        HmacSha256::new_from_slice(ticket_key).map_err(|_| StandaloneApprovedError::Unavailable)?;
    mac.update(WIRE_REPLAY_KEY_DOMAIN);
    mac.update(server_instance_id.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut key = [0_u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn replay_state_key(server_instance_id: &str) -> ProviderCredentialKey {
    ProviderCredentialKey::new(REPLAY_STATE_PROVIDER, server_instance_id)
}

fn legacy_replay_state_key(server_instance_id: &str) -> ProviderCredentialKey {
    ProviderCredentialKey::new(LEGACY_REPLAY_STATE_PROVIDER, server_instance_id)
}

fn create_wire_replay_state(
    state: &WireReplayCredentialStateV2,
    auth_key: &[u8; 32],
) -> Result<(), StandaloneApprovedError> {
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
    let key = replay_state_key(&state.server_instance_id);
    if store
        .read_api_key(&key)
        .map_err(|_| StandaloneApprovedError::Unavailable)?
        .is_some()
    {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    write_wire_replay_state_locked(&store, &key, state, auth_key)
}

fn replace_wire_replay_state(
    expected: &WireReplayCredentialStateV2,
    next: &WireReplayCredentialStateV2,
    auth_key: &[u8; 32],
) -> Result<(), StandaloneApprovedError> {
    if expected.server_instance_id != next.server_instance_id {
        return Err(StandaloneApprovedError::Unavailable);
    }
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
    let key = replay_state_key(&expected.server_instance_id);
    let current = read_wire_replay_state_locked(&store, &key, auth_key)?;
    if current.as_ref() != Some(expected) {
        return Err(StandaloneApprovedError::Unavailable);
    }
    write_wire_replay_state_locked(&store, &key, next, auth_key)
}

fn write_wire_replay_state_locked(
    store: &WindowsCredentialStore,
    key: &ProviderCredentialKey,
    state: &WireReplayCredentialStateV2,
    auth_key: &[u8; 32],
) -> Result<(), StandaloneApprovedError> {
    let signed = SignedWireReplayCredentialStateV2 {
        state: state.clone(),
        mac_hex: wire_replay_state_mac(auth_key, state)?,
    };
    let canonical = canonical_json_v1(&signed).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let encoded = format!(
        "{WIRE_REPLAY_STATE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(canonical)
    );
    store
        .write_api_key(key, ApiSecret::new(encoded))
        .map_err(|_| StandaloneApprovedError::Unavailable)
}

fn read_wire_replay_state(
    server_instance_id: &str,
    auth_key: &[u8; 32],
) -> Result<Option<WireReplayCredentialStateV2>, StandaloneApprovedError> {
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
    read_wire_replay_state_locked(&store, &replay_state_key(server_instance_id), auth_key)
}

fn read_wire_replay_state_locked(
    store: &WindowsCredentialStore,
    key: &ProviderCredentialKey,
    auth_key: &[u8; 32],
) -> Result<Option<WireReplayCredentialStateV2>, StandaloneApprovedError> {
    let Some(secret) = store
        .read_api_key(key)
        .map_err(|_| StandaloneApprovedError::Unavailable)?
    else {
        return Ok(None);
    };
    let encoded = secret
        .expose_secret()
        .strip_prefix(WIRE_REPLAY_STATE_PREFIX)
        .ok_or(StandaloneApprovedError::Unavailable)?;
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| StandaloneApprovedError::Unavailable)?,
    );
    let signed: SignedWireReplayCredentialStateV2 =
        strict_json_v1_from_slice(&bytes).map_err(|_| StandaloneApprovedError::Unavailable)?;
    if canonical_json_v1(&signed).map_err(|_| StandaloneApprovedError::Unavailable)?
        != bytes.as_slice()
        || !lower_hex(&signed.mac_hex, 64)
        || !constant_time_eq(
            signed.mac_hex.as_bytes(),
            wire_replay_state_mac(auth_key, &signed.state)?.as_bytes(),
        )
    {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(Some(signed.state))
}

fn wire_replay_state_mac(
    auth_key: &[u8; 32],
    state: &WireReplayCredentialStateV2,
) -> Result<String, StandaloneApprovedError> {
    let canonical = canonical_json_v1(state).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let mut mac =
        HmacSha256::new_from_slice(auth_key).map_err(|_| StandaloneApprovedError::Unavailable)?;
    mac.update(WIRE_REPLAY_STATE_DOMAIN);
    mac.update(&canonical);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn validate_wire_replay_state(
    state: &WireReplayCredentialStateV2,
    server_instance_id: &str,
    session_id: &str,
    ticket_revocation_epoch: u64,
) -> Result<(), StandaloneApprovedError> {
    if state.schema_version != WIRE_REPLAY_STATE_SCHEMA
        || state.server_instance_id != server_instance_id
        || state.session_id != session_id
        || !opaque_hex(&state.database_id, "wrdb_", 32)
        || state.ticket_revocation_epoch != ticket_revocation_epoch
        || state.sequence > MAX_WIRE_REPLAY_ROWS
        || !lower_hex(&state.chain_head_sha256, 64)
    {
        return Err(StandaloneApprovedError::Unavailable);
    }
    if let Some(pending) = state.pending.as_ref() {
        validate_wire_replay_pending(state, pending)?;
    }
    Ok(())
}

fn delete_wire_replay_state(server_instance_id: &str) -> Result<(), StandaloneApprovedError> {
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX)
        .delete_api_key(&replay_state_key(server_instance_id))
        .map_err(|_| StandaloneApprovedError::Unavailable)
}

fn delete_legacy_wire_replay_state(
    server_instance_id: &str,
) -> Result<(), StandaloneApprovedError> {
    let _lock = ProviderStoreLock::acquire().map_err(|_| StandaloneApprovedError::Unavailable)?;
    WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX)
        .delete_api_key(&legacy_replay_state_key(server_instance_id))
        .map_err(|_| StandaloneApprovedError::Unavailable)
}

fn delete_wire_replay_database_file(
    root: &Path,
    file_name: &str,
) -> Result<(), StandaloneApprovedError> {
    if !matches!(
        file_name,
        WIRE_REPLAY_DATABASE_FILE | LEGACY_WIRE_REPLAY_DATABASE_FILE
    ) {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    validate_fixed_local_directory(root).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let path = root.join(file_name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(StandaloneApprovedError::Unavailable),
    }
    validate_fixed_local_regular_file(&path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    fs::remove_file(&path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(StandaloneApprovedError::Unavailable),
    }
}

fn cleanup_new_wire_replay_guard(
    root: &Path,
    server_instance_id: &str,
) -> Result<(), StandaloneApprovedError> {
    let credential_result = delete_wire_replay_state(server_instance_id);
    let database_result = delete_wire_replay_database_file(root, WIRE_REPLAY_DATABASE_FILE);
    if credential_result.is_err() || database_result.is_err() {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(())
}

fn delete_wire_replay_artifacts(
    root: &Path,
    server_instance_id: &str,
) -> Result<(), StandaloneApprovedError> {
    // Evaluate every exact cleanup even after one failure. Revocation has
    // already advanced its epoch, and partial cleanup must never be reported
    // as success or cause legacy state to be trusted.
    let credential_result = delete_wire_replay_state(server_instance_id);
    let legacy_credential_result = delete_legacy_wire_replay_state(server_instance_id);
    let current_result = delete_wire_replay_database_file(root, WIRE_REPLAY_DATABASE_FILE);
    let legacy_result = delete_wire_replay_database_file(root, LEGACY_WIRE_REPLAY_DATABASE_FILE);
    if credential_result.is_err()
        || legacy_credential_result.is_err()
        || current_result.is_err()
        || legacy_result.is_err()
    {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(())
}

fn validate_replay_file(path: &Path) -> Result<(), StandaloneApprovedError> {
    validate_fixed_local_regular_file(path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let length = fs::metadata(path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?
        .len();
    if length > MAX_WIRE_REPLAY_DATABASE_BYTES {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(())
}

fn transport_name(transport: McpTransportBindingV1) -> &'static str {
    match transport {
        McpTransportBindingV1::Stdio => "stdio",
        McpTransportBindingV1::StreamableHttp => "streamable_http",
    }
}

fn acquire_process_lock(root: &Path) -> Result<StandaloneProcessLock, StandaloneApprovedError> {
    validate_fixed_local_directory(root).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let path = root.join(PROCESS_LOCK_FILE);
    let connection = Connection::open(path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    connection
        .busy_timeout(Duration::from_millis(50))
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS process_lock(singleton INTEGER PRIMARY KEY CHECK(singleton=1), marker INTEGER NOT NULL) STRICT; INSERT OR IGNORE INTO process_lock(singleton,marker) VALUES(1,1);",
        )
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    connection
        .execute_batch("BEGIN IMMEDIATE; UPDATE process_lock SET marker=marker WHERE singleton=1;")
        .map_err(|_| StandaloneApprovedError::AlreadyRunning)?;
    Ok(StandaloneProcessLock {
        _connection: connection,
    })
}

fn descriptor_path(app_directory: &Path, server_id: &str) -> PathBuf {
    app_directory
        .join(APPROVED_MCP_STATE_RELATIVE)
        .join("ticket-sessions")
        .join(server_id)
        .join(STANDALONE_DESCRIPTOR_FILE)
}

fn metadata(
    claims: &StandaloneDescriptorClaimsV1,
    active: bool,
    reason: &str,
) -> StandaloneSessionMetadataV1 {
    StandaloneSessionMetadataV1 {
        descriptor_id: claims.descriptor_id.clone(),
        connector_id: claims.connector_id.clone(),
        workspace_instance_id: claims.workspace_instance_id.as_str().to_owned(),
        server_instance_id: claims.server_instance_id.clone(),
        session_id: claims.session_id.clone(),
        transport: claims.transport,
        grant_groups: claims.grant_groups.clone(),
        grants: claims.grants.clone(),
        endpoint: claims.http_bind.map(|bind| format!("http://{bind}/mcp")),
        qualification_evidence_id: claims.qualification.evidence_id.clone(),
        qualification_evidence_sha256: claims.qualification.evidence_sha256.as_str().to_owned(),
        issued_at_unix: claims.issued_at_unix,
        expires_at_unix: claims.expires_at_unix,
        active,
        reason_code: reason.to_owned(),
    }
}

fn canonical_directory(path: &Path) -> Result<PathBuf, StandaloneApprovedError> {
    validate_fixed_local_directory(path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    fs::canonicalize(path).map_err(|_| StandaloneApprovedError::Unavailable)
}

fn canonical_file(path: &Path) -> Result<PathBuf, StandaloneApprovedError> {
    validate_fixed_local_regular_file(path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    fs::canonicalize(path).map_err(|_| StandaloneApprovedError::Unavailable)
}

fn canonical_directories(paths: &[PathBuf]) -> Result<Vec<PathBuf>, StandaloneApprovedError> {
    paths.iter().map(|path| canonical_directory(path)).collect()
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, StandaloneApprovedError> {
    validate_fixed_local_regular_file(path).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let length = fs::metadata(path)
        .ok()
        .and_then(|metadata| usize::try_from(metadata.len()).ok())
        .filter(|length| *length > 0 && *length <= limit)
        .ok_or(StandaloneApprovedError::Unavailable)?;
    let mut bytes = Vec::with_capacity(length);
    File::open(path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?
        .take(u64::try_from(limit + 1).map_err(|_| StandaloneApprovedError::Unavailable)?)
        .read_to_end(&mut bytes)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    if bytes.len() != length || bytes.len() > limit {
        return Err(StandaloneApprovedError::Unavailable);
    }
    Ok(bytes)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), StandaloneApprovedError> {
    if bytes.is_empty() || bytes.len() > MAX_DESCRIPTOR_BYTES * 2 {
        return Err(StandaloneApprovedError::InvalidBinding);
    }
    let parent = path.parent().ok_or(StandaloneApprovedError::Unavailable)?;
    validate_fixed_local_directory(parent).map_err(|_| StandaloneApprovedError::Unavailable)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| StandaloneApprovedError::Unavailable)?;
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(StandaloneApprovedError::Unavailable);
    }
    drop(file);
    validate_fixed_local_regular_file(path).map_err(|_| StandaloneApprovedError::Unavailable)
}

fn map_backend_error(_error: ApprovedBackendInitError) -> StandaloneApprovedError {
    StandaloneApprovedError::InvalidBinding
}

fn now_seconds() -> Result<u64, StandaloneApprovedError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
        .filter(|value| *value > 0)
        .ok_or(StandaloneApprovedError::Unavailable)
}

fn opaque_hex(value: &str, prefix: &str, digits: usize) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|suffix| lower_hex(suffix, digits))
}

fn lower_hex(value: &str, digits: usize) -> bool {
    value.len() == digits
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_binding(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode_32(value: &str) -> Option<[u8; 32]> {
    if !lower_hex(value, 64) {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(output)
}

fn zeroize(bytes: &mut [u8]) {
    bytes.fill(0);
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualification_canary_namespace_is_feature_independent_and_leaf_scoped() {
        let local_data = tempfile::tempdir().expect("temporary local data root");
        let local_data =
            fs::canonicalize(local_data.path()).expect("canonical temporary local data root");
        let canary_id = format!("mcpqcanary_{}", "a".repeat(32));
        let run = create_qualification_canary_run_directory_at(&local_data, &canary_id)
            .expect("create isolated qualification canary leaf");
        assert_eq!(
            run,
            local_data
                .join(QUALIFICATION_CANARY_APP_IDENTIFIER)
                .join(QUALIFICATION_CANARY_RUNS_DIRECTORY)
                .join(&canary_id)
        );
        assert_eq!(
            QUALIFICATION_CANARY_APP_IDENTIFIER,
            "com.shilittle.lawyer-assistance.mcp-qualification-canary"
        );
        assert_ne!(QUALIFICATION_CANARY_APP_IDENTIFIER, APP_IDENTIFIER);

        let app_local = run.join("app-local");
        fs::create_dir(&app_local).expect("create canary app-local leaf");
        assert_eq!(
            qualification_canary_app_local_data_directory_at(&local_data, &canary_id)
                .expect("resolve exact canary app-local leaf"),
            app_local
        );
        assert_eq!(
            create_qualification_canary_run_directory_at(&local_data, &canary_id)
                .expect_err("pre-existing canary leaf is rejected"),
            StandaloneApprovedError::InvalidBinding
        );
        for invalid in [
            "mcpqcanary_",
            "mcpqcanary_../escape",
            "mcpqcanary_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "mcpqcanary_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert_eq!(
                create_qualification_canary_run_directory_at(&local_data, invalid)
                    .expect_err("invalid canary id is rejected"),
                StandaloneApprovedError::InvalidBinding
            );
        }

        remove_qualification_canary_run_directory_at(&local_data, &canary_id)
            .expect("remove exact qualification canary leaf");
        assert!(!run.exists());
        assert!(local_data
            .join(QUALIFICATION_CANARY_APP_IDENTIFIER)
            .join(QUALIFICATION_CANARY_RUNS_DIRECTORY)
            .is_dir());
    }

    #[cfg(windows)]
    #[test]
    fn qualification_canary_reparse_leaf_is_rejected_without_following_it() {
        use std::os::windows::fs::symlink_dir;

        let local_data = tempfile::tempdir().expect("temporary local data root");
        let local_data =
            fs::canonicalize(local_data.path()).expect("canonical temporary local data root");
        let canary_id = format!("mcpqcanary_{}", "b".repeat(32));
        let run = create_qualification_canary_run_directory_at(&local_data, &canary_id)
            .expect("initialize qualification canary parents");
        remove_qualification_canary_run_directory_at(&local_data, &canary_id)
            .expect("remove initial ordinary canary leaf");

        let target = local_data.join("reparse-target");
        fs::create_dir(&target).expect("create reparse target");
        fs::create_dir(target.join("app-local")).expect("create target app-local");
        if symlink_dir(&target, &run).is_err() {
            return;
        }

        assert!(qualification_canary_app_local_data_directory_at(&local_data, &canary_id).is_err());
        assert!(create_qualification_canary_run_directory_at(&local_data, &canary_id).is_err());
        assert!(remove_qualification_canary_run_directory_at(&local_data, &canary_id).is_err());
        assert!(target.join("app-local").is_dir());
        fs::remove_dir(&run).expect("remove reparse leaf without following target");
        assert!(target.is_dir());
    }

    fn sample_metadata(transport: McpTransportBindingV1) -> StandaloneSessionMetadataV1 {
        StandaloneSessionMetadataV1 {
            descriptor_id: format!("mcpd_{}", "1".repeat(32)),
            connector_id: "workbuddy".to_owned(),
            workspace_instance_id: format!("ws_{}", "2".repeat(32)),
            server_instance_id: format!("srv_{}", "3".repeat(32)),
            session_id: format!("session_http_{}", "4".repeat(32)),
            transport,
            grant_groups: vec![ApprovedMcpGrantGroupV1::Read],
            grants: vec![tool_grant("case_list")],
            endpoint: Some("http://127.0.0.1:8787/mcp".to_owned()),
            qualification_evidence_id: format!("mcpqe_{}", "5".repeat(32)),
            qualification_evidence_sha256: "6".repeat(64),
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_003_600,
            active: true,
            reason_code: "ACTIVE".to_owned(),
        }
    }

    fn occurrences(haystack: &str, needle: &str) -> usize {
        haystack.match_indices(needle).count()
    }

    #[test]
    fn opaque_ids_and_transport_binding_are_strict() {
        assert!(opaque_hex(&format!("srv_{}", "a".repeat(32)), "srv_", 32));
        assert!(!opaque_hex("srv_AAAA", "srv_", 32));
        assert!(safe_binding(
            &format!("session_stdio_{}", "b".repeat(32)),
            16,
            160
        ));
    }

    #[test]
    fn grant_groups_are_canonical_and_exact() {
        let (groups, grants) = canonical_grants(&[
            ApprovedMcpGrantGroupV1::Write,
            ApprovedMcpGrantGroupV1::Read,
        ])
        .expect("canonical grants");
        assert_eq!(
            groups,
            vec![
                ApprovedMcpGrantGroupV1::Read,
                ApprovedMcpGrantGroupV1::Write
            ]
        );
        assert_eq!(grants.len(), 10);
        assert!(grant_allows(
            &grants,
            "case_read_approved_material",
            "mcp.case_read_approved_material.v1"
        ));
        assert!(!grant_allows(
            &grants,
            "diagram.render",
            "mcp.diagram.render.v1"
        ));

        let (groups, grants) = canonical_grants(&[
            ApprovedMcpGrantGroupV1::DiagramWrite,
            ApprovedMcpGrantGroupV1::Read,
            ApprovedMcpGrantGroupV1::DiagramRead,
            ApprovedMcpGrantGroupV1::Write,
        ])
        .expect("all canonical grants");
        assert_eq!(
            groups,
            vec![
                ApprovedMcpGrantGroupV1::Read,
                ApprovedMcpGrantGroupV1::Write,
                ApprovedMcpGrantGroupV1::DiagramRead,
                ApprovedMcpGrantGroupV1::DiagramWrite,
            ]
        );
        assert_eq!(grants.len(), 16);
        assert!(grant_allows(
            &grants,
            "diagram.render",
            "mcp.diagram.render.v1"
        ));
        assert!(canonical_grants(&[]).is_err());
        assert!(
            canonical_grants(&[ApprovedMcpGrantGroupV1::Read, ApprovedMcpGrantGroupV1::Read,])
                .is_err()
        );
    }
    #[test]
    fn complete_host_metadata_is_accepted_and_bound_into_the_canonical_wire() {
        let arguments = Map::from_iter([("schema_version".to_owned(), json!(1))]);
        let params_without_meta = json!({
            "name":"case_list",
            "arguments":arguments
        });
        let params_with_meta = json!({
            "name":"case_list",
            "arguments":arguments,
            "_meta":{
                "progressToken":"synthetic-progress-1",
                "nested":{"trace":"synthetic-trace-1"}
            }
        });
        assert!(accepted_standalone_call_params(
            &params_with_meta,
            "case_list",
            &arguments
        ));
        assert!(!accepted_standalone_call_params(
            &json!({"name":"case_list","arguments":arguments,"_meta":"invalid"}),
            "case_list",
            &arguments
        ));
        let plain = canonical_standalone_wire(&json!(17), &params_without_meta)
            .unwrap_or_else(|_| panic!("plain canonical wire"));
        let with_meta = canonical_standalone_wire(&json!(17), &params_with_meta)
            .unwrap_or_else(|_| panic!("metadata canonical wire"));
        assert_ne!(sha256_hex(&plain), sha256_hex(&with_meta));
        let canonical = String::from_utf8(with_meta).expect("canonical JSON is UTF-8");
        assert!(canonical.contains("progressToken"));
        assert!(canonical.contains("synthetic-trace-1"));
    }

    #[test]
    fn http_bearer_serializes_once_only_on_create_and_disappears_after_take() {
        let bearer = format!("mcp-http-{}", "a".repeat(64));
        let metadata = sample_metadata(McpTransportBindingV1::StreamableHttp);
        let mut provisioned = ProvisionedStandaloneSessionV1 {
            metadata: metadata.clone(),
            http_bearer: Some(Zeroizing::new(bearer.clone())),
        };

        let create_wire = serde_json::to_string(&provisioned).expect("serialize create response");
        assert_eq!(occurrences(&create_wire, &bearer), 1);
        assert_eq!(occurrences(&create_wire, "oneTimeHttpBearer"), 1);
        assert!(!format!("{provisioned:?}").contains(&bearer));

        let list_wire = serde_json::to_string(&metadata).expect("serialize list metadata");
        assert!(!list_wire.contains(&bearer));
        assert!(!list_wire.contains("oneTimeHttpBearer"));

        let taken = provisioned.take_http_bearer().expect("take bearer once");
        assert_eq!(taken.as_str(), bearer);
        assert!(provisioned.take_http_bearer().is_none());
        let after_take = serde_json::to_string(&provisioned).expect("serialize after take");
        assert!(!after_take.contains("oneTimeHttpBearer"));
        assert!(!after_take.contains(&bearer));

        let stdio = ProvisionedStandaloneSessionV1 {
            metadata: sample_metadata(McpTransportBindingV1::Stdio),
            http_bearer: None,
        };
        let stdio_wire = serde_json::to_string(&stdio).expect("serialize stdio response");
        assert!(!stdio_wire.contains("oneTimeHttpBearer"));
    }

    #[cfg(windows)]
    mod replay_journal {
        use super::*;
        use tempfile::{tempdir, TempDir};

        const TEST_NOW: u64 = 1_700_000_100;

        struct ReplayFixture {
            root: TempDir,
            server_instance_id: String,
            session_id: String,
            ticket_revocation_epoch: u64,
            ticket_key: [u8; 32],
        }

        impl ReplayFixture {
            fn new() -> Self {
                let fixture = Self {
                    root: tempdir().expect("create replay fixture root"),
                    server_instance_id: format!("srv_{}", Uuid::new_v4().simple()),
                    session_id: format!("session_stdio_{}", Uuid::new_v4().simple()),
                    ticket_revocation_epoch: 7,
                    ticket_key: [0x42; 32],
                };
                initialize_wire_replay_guard(
                    fixture.root.path(),
                    &fixture.server_instance_id,
                    &fixture.session_id,
                    fixture.ticket_revocation_epoch,
                    &fixture.ticket_key,
                )
                .expect("initialize replay fixture");
                fixture
            }

            fn open(&self) -> Result<WireReplayGuard, StandaloneApprovedError> {
                open_wire_replay_guard(
                    self.root.path(),
                    &self.server_instance_id,
                    &self.session_id,
                    self.ticket_revocation_epoch,
                    &self.ticket_key,
                )
            }

            fn auth_key(&self) -> [u8; 32] {
                replay_auth_key(&self.ticket_key, &self.server_instance_id)
                    .expect("derive replay fixture authentication key")
            }

            fn credential_state(&self) -> WireReplayCredentialStateV2 {
                read_wire_replay_state(&self.server_instance_id, &self.auth_key())
                    .expect("read authenticated replay credential")
                    .expect("replay credential exists")
            }
        }

        impl Drop for ReplayFixture {
            fn drop(&mut self) {
                let _ = delete_wire_replay_state(&self.server_instance_id);
            }
        }

        fn call_params() -> Value {
            json!({
                "name":"case_list",
                "arguments":{"schema_version":1},
                "_meta":{"synthetic":true}
            })
        }

        fn reserve_at_fault(
            guard: &mut WireReplayGuard,
            fixture: &ReplayFixture,
            request_id: u64,
            fault: WireReplayFaultPoint,
        ) -> Result<(), WireReplayError> {
            let ticket_request = format!("synthetic-ticket-request-{request_id}");
            guard.reserve_with_fault(
                &fixture.server_instance_id,
                McpTransportBindingV1::Stdio,
                &json!(request_id),
                "case_list",
                &call_params(),
                ticket_request.as_bytes(),
                TEST_NOW + request_id,
                fault,
            )
        }

        fn force_authenticated_state(state: &WireReplayCredentialStateV2, auth_key: &[u8; 32]) {
            let _lock = ProviderStoreLock::acquire().expect("lock credential test fixture");
            let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
            write_wire_replay_state_locked(
                &store,
                &replay_state_key(&state.server_instance_id),
                state,
                auth_key,
            )
            .expect("force authenticated replay state");
        }

        fn overwrite_raw_credential_at(key: &ProviderCredentialKey, value: String) {
            let _lock = ProviderStoreLock::acquire().expect("lock raw credential test fixture");
            WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX)
                .write_api_key(key, ApiSecret::new(value))
                .expect("overwrite raw replay credential");
        }

        fn overwrite_raw_credential(server_instance_id: &str, value: String) {
            overwrite_raw_credential_at(&replay_state_key(server_instance_id), value);
        }

        fn raw_credential(server_instance_id: &str) -> String {
            let _lock = ProviderStoreLock::acquire().expect("lock raw credential test fixture");
            WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX)
                .read_api_key(&replay_state_key(server_instance_id))
                .expect("read raw replay credential")
                .expect("raw replay credential exists")
                .expose_secret()
                .to_owned()
        }

        fn append_valid_second_database_entry(guard: &WireReplayGuard, fixture: &ReplayFixture) {
            let pending = guard
                .state
                .pending
                .as_ref()
                .expect("first transition remains pending");
            let request_id = json!(9_002_u64);
            let request_id_json = String::from_utf8(
                canonical_json_v1(&request_id).expect("canonical second request id"),
            )
            .expect("canonical request id is UTF-8");
            let transport = transport_name(McpTransportBindingV1::Stdio);
            let identity_sha256 = sha256_hex(
                &canonical_json_v1(&json!({
                    "server_instance_id":fixture.server_instance_id.as_str(),
                    "transport":transport,
                    "request_id":request_id
                }))
                .expect("canonical second identity"),
            );
            let canonical_wire_sha256 = sha256_hex(
                &canonical_standalone_wire(&request_id, &call_params())
                    .expect("canonical second wire"),
            );
            let sequence = pending.new_count + 1;
            let created_at_unix = TEST_NOW + 9_002;
            let chain_sha256 = replay_entry_chain(
                &guard.auth_key,
                &guard.state.database_id,
                sequence,
                &pending.new_chain_head_sha256,
                &identity_sha256,
                &fixture.server_instance_id,
                transport,
                &request_id_json,
                &canonical_wire_sha256,
                "case_list",
                created_at_unix,
            )
            .expect("authenticate second replay row");
            guard
                .connection
                .execute(
                    "INSERT INTO wire_requests(
                         sequence,wire_identity_sha256,server_instance_id,transport,request_id_json,
                         canonical_wire_sha256,tool_name,created_at_unix,previous_chain_sha256,
                         chain_sha256
                     ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![
                        i64::try_from(sequence).expect("second sequence fits SQLite"),
                        identity_sha256,
                        &fixture.server_instance_id,
                        transport,
                        request_id_json,
                        canonical_wire_sha256,
                        "case_list",
                        i64::try_from(created_at_unix).expect("second timestamp fits SQLite"),
                        &pending.new_chain_head_sha256,
                        chain_sha256
                    ],
                )
                .expect("append fully authenticated second replay row");
        }

        #[test]
        fn crash_after_pending_before_database_stays_fail_closed() {
            let fixture = ReplayFixture::new();
            let mut guard = fixture.open().expect("open new replay guard");
            assert_eq!(
                reserve_at_fault(
                    &mut guard,
                    &fixture,
                    1,
                    WireReplayFaultPoint::AfterPendingBeforeDatabase
                ),
                Err(WireReplayError::Unavailable)
            );
            let rows: i64 = guard
                .connection
                .query_row("SELECT COUNT(*) FROM wire_requests", [], |row| row.get(0))
                .expect("count replay rows");
            assert_eq!(rows, 0);
            drop(guard);

            assert!(matches!(
                fixture.open(),
                Err(StandaloneApprovedError::Unavailable)
            ));
            let state = fixture.credential_state();
            assert_eq!(state.sequence, 0);
            assert!(state.pending.is_some(), "pending must not be cleared");
        }

        #[test]
        fn crash_after_database_before_credential_head_recovers_exactly_once() {
            let fixture = ReplayFixture::new();
            let mut guard = fixture.open().expect("open new replay guard");
            assert_eq!(
                reserve_at_fault(
                    &mut guard,
                    &fixture,
                    11,
                    WireReplayFaultPoint::AfterDatabaseBeforeCredentialHead
                ),
                Err(WireReplayError::Unavailable)
            );
            drop(guard);

            let mut recovered = fixture.open().expect("recover exact committed tail");
            assert_eq!(recovered.state.sequence, 1);
            assert!(recovered.state.pending.is_none());
            assert_eq!(
                reserve_at_fault(&mut recovered, &fixture, 11, WireReplayFaultPoint::None),
                Err(WireReplayError::Replayed)
            );
            reserve_at_fault(&mut recovered, &fixture, 12, WireReplayFaultPoint::None)
                .expect("a distinct request remains available");
        }

        #[test]
        fn crash_after_credential_head_before_cleanup_recovers_exactly_once() {
            let fixture = ReplayFixture::new();
            let mut guard = fixture.open().expect("open new replay guard");
            assert_eq!(
                reserve_at_fault(
                    &mut guard,
                    &fixture,
                    21,
                    WireReplayFaultPoint::AfterCredentialHeadBeforePendingCleanup
                ),
                Err(WireReplayError::Unavailable)
            );
            assert_eq!(guard.state.sequence, 1);
            assert!(guard.state.pending.is_some());
            drop(guard);

            let mut recovered = fixture.open().expect("clean exact promoted transition");
            assert_eq!(recovered.state.sequence, 1);
            assert!(recovered.state.pending.is_none());
            assert_eq!(
                reserve_at_fault(&mut recovered, &fixture, 21, WireReplayFaultPoint::None),
                Err(WireReplayError::Replayed)
            );
        }

        #[test]
        fn unauthenticated_pending_tamper_is_rejected() {
            let fixture = ReplayFixture::new();
            let mut guard = fixture.open().expect("open new replay guard");
            assert_eq!(
                reserve_at_fault(
                    &mut guard,
                    &fixture,
                    31,
                    WireReplayFaultPoint::AfterDatabaseBeforeCredentialHead
                ),
                Err(WireReplayError::Unavailable)
            );
            drop(guard);

            let raw = raw_credential(&fixture.server_instance_id);
            let encoded = raw
                .strip_prefix(WIRE_REPLAY_STATE_PREFIX)
                .expect("credential uses V2 prefix");
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .expect("decode replay credential");
            let mut signed: Value =
                strict_json_v1_from_slice(&bytes).expect("parse signed replay credential");
            signed["state"]["pending"]["expectedTailMacHex"] = Value::String("f".repeat(64));
            let tampered = format!(
                "{WIRE_REPLAY_STATE_PREFIX}{}",
                URL_SAFE_NO_PAD.encode(
                    canonical_json_v1(&signed).expect("canonicalize tampered replay credential")
                )
            );
            overwrite_raw_credential(&fixture.server_instance_id, tampered);

            assert!(matches!(
                fixture.open(),
                Err(StandaloneApprovedError::Unavailable)
            ));
        }

        #[test]
        fn authenticated_pending_wrong_session_and_epoch_is_rejected() {
            let fixture = ReplayFixture::new();
            let mut guard = fixture.open().expect("open new replay guard");
            assert_eq!(
                reserve_at_fault(
                    &mut guard,
                    &fixture,
                    41,
                    WireReplayFaultPoint::AfterDatabaseBeforeCredentialHead
                ),
                Err(WireReplayError::Unavailable)
            );
            let mut invalid = guard.state.clone();
            let pending = invalid.pending.as_mut().expect("pending transition exists");
            pending.session_id = format!("session_stdio_{}", Uuid::new_v4().simple());
            pending.ticket_revocation_epoch += 1;
            force_authenticated_state(&invalid, &fixture.auth_key());
            drop(guard);

            assert!(matches!(
                fixture.open(),
                Err(StandaloneApprovedError::Unavailable)
            ));
        }

        #[test]
        fn authenticated_multi_step_database_advance_is_ambiguous_and_rejected() {
            let fixture = ReplayFixture::new();
            let mut guard = fixture.open().expect("open new replay guard");
            assert_eq!(
                reserve_at_fault(
                    &mut guard,
                    &fixture,
                    51,
                    WireReplayFaultPoint::AfterDatabaseBeforeCredentialHead
                ),
                Err(WireReplayError::Unavailable)
            );
            append_valid_second_database_entry(&guard, &fixture);
            drop(guard);

            assert!(matches!(
                fixture.open(),
                Err(StandaloneApprovedError::Unavailable)
            ));
            let state = fixture.credential_state();
            assert_eq!(state.sequence, 0);
            assert!(state.pending.is_some());
        }

        #[test]
        fn database_ahead_without_pending_is_rejected_without_rollback() {
            let fixture = ReplayFixture::new();
            let mut guard = fixture.open().expect("open new replay guard");
            assert_eq!(
                reserve_at_fault(
                    &mut guard,
                    &fixture,
                    61,
                    WireReplayFaultPoint::AfterDatabaseBeforeCredentialHead
                ),
                Err(WireReplayError::Unavailable)
            );
            let mut missing_pending = guard.state.clone();
            missing_pending.pending = None;
            force_authenticated_state(&missing_pending, &fixture.auth_key());
            drop(guard);

            assert!(matches!(
                fixture.open(),
                Err(StandaloneApprovedError::Unavailable)
            ));
            let state = fixture.credential_state();
            assert_eq!(state.sequence, 0);
            assert!(state.pending.is_none());
        }

        #[test]
        fn revoke_and_reconfigure_cannot_be_undone_by_stale_transition() {
            let fixture = ReplayFixture::new();
            let mut guard = fixture.open().expect("open new replay guard");
            assert_eq!(
                reserve_at_fault(
                    &mut guard,
                    &fixture,
                    71,
                    WireReplayFaultPoint::AfterPendingBeforeDatabase
                ),
                Err(WireReplayError::Unavailable)
            );
            let stale_expected = guard.state.clone();
            let mut stale_next = stale_expected.clone();
            let stale_pending = stale_next
                .pending
                .as_ref()
                .expect("stale pending transition");
            stale_next.sequence = stale_pending.new_count;
            stale_next.chain_head_sha256 = stale_pending.new_chain_head_sha256.clone();

            delete_wire_replay_state(&fixture.server_instance_id)
                .expect("revoke removes replay credential");
            assert!(
                read_wire_replay_state(&fixture.server_instance_id, &fixture.auth_key())
                    .expect("query deleted replay credential")
                    .is_none()
            );

            let replacement_root = tempdir().expect("create replacement replay root");
            let replacement_session = format!("session_stdio_{}", Uuid::new_v4().simple());
            let replacement_epoch = fixture.ticket_revocation_epoch + 1;
            initialize_wire_replay_guard(
                replacement_root.path(),
                &fixture.server_instance_id,
                &replacement_session,
                replacement_epoch,
                &fixture.ticket_key,
            )
            .expect("reconfigure after complete credential cleanup");
            assert!(matches!(
                replace_wire_replay_state(&stale_expected, &stale_next, &fixture.auth_key()),
                Err(StandaloneApprovedError::Unavailable)
            ));
            let replacement =
                read_wire_replay_state(&fixture.server_instance_id, &fixture.auth_key())
                    .expect("read replacement replay credential")
                    .expect("replacement replay credential exists");
            assert_eq!(replacement.session_id, replacement_session);
            assert_eq!(replacement.ticket_revocation_epoch, replacement_epoch);
            assert_eq!(replacement.sequence, 0);
            assert!(replacement.pending.is_none());
            drop(guard);
            delete_wire_replay_state(&fixture.server_instance_id)
                .expect("clean replacement replay credential");
        }

        #[test]
        fn failed_initialization_removes_only_the_new_v2_database_for_retry() {
            let root = tempdir().expect("create failed-initialization root");
            let server_instance_id = format!("srv_{}", Uuid::new_v4().simple());
            let session_id = format!("session_stdio_{}", Uuid::new_v4().simple());
            let ticket_key = [0x55; 32];
            overwrite_raw_credential(
                &server_instance_id,
                format!("{WIRE_REPLAY_STATE_PREFIX}invalid-existing-current-state"),
            );

            assert!(matches!(
                initialize_wire_replay_guard(
                    root.path(),
                    &server_instance_id,
                    &session_id,
                    8,
                    &ticket_key,
                ),
                Err(StandaloneApprovedError::InvalidBinding)
            ));
            assert!(!root.path().join(WIRE_REPLAY_DATABASE_FILE).exists());

            delete_wire_replay_state(&server_instance_id)
                .expect("remove colliding current credential");
            initialize_wire_replay_guard(
                root.path(),
                &server_instance_id,
                &session_id,
                8,
                &ticket_key,
            )
            .expect("same clean root can be initialized again");
            cleanup_new_wire_replay_guard(root.path(), &server_instance_id)
                .expect("clean successful retry fixture");
        }

        #[test]
        fn legacy_v1_only_session_fails_closed_without_migration() {
            let root = tempdir().expect("create V1-only replay root");
            let server_instance_id = format!("srv_{}", Uuid::new_v4().simple());
            let session_id = format!("session_stdio_{}", Uuid::new_v4().simple());
            let ticket_key = [0x63; 32];
            fs::write(
                root.path().join(LEGACY_WIRE_REPLAY_DATABASE_FILE),
                b"synthetic V1-only replay database",
            )
            .expect("create V1-only replay database");
            overwrite_raw_credential_at(
                &legacy_replay_state_key(&server_instance_id),
                "approved-mcp-wire-replay-state-v1.synthetic".to_owned(),
            );

            assert!(read_wire_replay_state(
                &server_instance_id,
                &replay_auth_key(&ticket_key, &server_instance_id)
                    .expect("derive V2 authentication key"),
            )
            .expect("V2 credential query succeeds")
            .is_none());
            assert!(matches!(
                open_wire_replay_guard(
                    root.path(),
                    &server_instance_id,
                    &session_id,
                    9,
                    &ticket_key,
                ),
                Err(StandaloneApprovedError::Unavailable)
            ));
            delete_wire_replay_artifacts(root.path(), &server_instance_id)
                .expect("explicitly clean V1-only artifacts");
        }

        #[test]
        fn legacy_v1_state_is_not_read_and_explicit_cleanup_prevents_revival() {
            let fixture = ReplayFixture::new();
            let legacy_path = fixture.root.path().join(LEGACY_WIRE_REPLAY_DATABASE_FILE);
            fs::write(&legacy_path, b"synthetic legacy replay database")
                .expect("create ordinary legacy replay database fixture");
            let legacy = canonical_json_v1(&json!({
                "state":{
                    "schemaVersion":"lawyer-assistance-standalone-wire-replay-state-v1",
                    "serverInstanceId":fixture.server_instance_id.as_str(),
                    "databaseId":format!("wrdb_{}", Uuid::new_v4().simple()),
                    "sequence":0,
                    "chainHeadSha256":"0".repeat(64)
                },
                "macHex":"0".repeat(64)
            }))
            .expect("canonical legacy V1 fixture");
            overwrite_raw_credential_at(
                &legacy_replay_state_key(&fixture.server_instance_id),
                format!(
                    "approved-mcp-wire-replay-state-v1.{}",
                    URL_SAFE_NO_PAD.encode(legacy)
                ),
            );

            // V2 never reads or auto-migrates the legacy credential target.
            assert!(fixture.credential_state().pending.is_none());
            assert!(fixture.open().is_ok());
            delete_wire_replay_artifacts(fixture.root.path(), &fixture.server_instance_id)
                .expect("explicit revocation cleans V1 and V2 artifacts");
            assert!(!fixture.root.path().join(WIRE_REPLAY_DATABASE_FILE).exists());
            assert!(!legacy_path.exists());
            let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
            assert!(store
                .read_api_key(&replay_state_key(&fixture.server_instance_id))
                .expect("query removed V2 credential")
                .is_none());
            assert!(store
                .read_api_key(&legacy_replay_state_key(&fixture.server_instance_id))
                .expect("query removed V1 credential")
                .is_none());
            assert!(matches!(
                fixture.open(),
                Err(StandaloneApprovedError::Unavailable)
            ));

            initialize_wire_replay_guard(
                fixture.root.path(),
                &fixture.server_instance_id,
                &fixture.session_id,
                fixture.ticket_revocation_epoch + 1,
                &fixture.ticket_key,
            )
            .expect("explicitly cleaned root can be reprovisioned as V2");
        }

        #[test]
        fn legacy_hardlink_cleanup_is_best_effort_and_fails_closed() {
            let fixture = ReplayFixture::new();
            let source = fixture.root.path().join("synthetic-legacy-source.bin");
            let legacy_path = fixture.root.path().join(LEGACY_WIRE_REPLAY_DATABASE_FILE);
            fs::write(&source, b"synthetic legacy hardlink target")
                .expect("create synthetic hardlink source");
            fs::hard_link(&source, &legacy_path).expect("create legacy replay hardlink");
            overwrite_raw_credential_at(
                &legacy_replay_state_key(&fixture.server_instance_id),
                "approved-mcp-wire-replay-state-v1.synthetic".to_owned(),
            );

            assert!(matches!(
                delete_wire_replay_artifacts(fixture.root.path(), &fixture.server_instance_id),
                Err(StandaloneApprovedError::Unavailable)
            ));
            assert!(!fixture.root.path().join(WIRE_REPLAY_DATABASE_FILE).exists());
            assert!(source.exists());
            assert!(legacy_path.exists());
            let store = WindowsCredentialStore::with_service_prefix(KEY_SERVICE_PREFIX);
            assert!(store
                .read_api_key(&replay_state_key(&fixture.server_instance_id))
                .expect("query best-effort removed V2 credential")
                .is_none());
            assert!(store
                .read_api_key(&legacy_replay_state_key(&fixture.server_instance_id))
                .expect("query best-effort removed V1 credential")
                .is_none());
            assert!(matches!(
                fixture.open(),
                Err(StandaloneApprovedError::Unavailable)
            ));

            fs::remove_file(&legacy_path).expect("remove synthetic legacy hardlink");
            fs::remove_file(&source).expect("remove synthetic hardlink source");
        }
    }
}
