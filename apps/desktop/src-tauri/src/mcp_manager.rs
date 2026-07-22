use crate::approved_mcp::{
    ApprovedMcpServerSession, ApprovedMcpWorkspace, StandaloneMcpHostBinding,
};
use legal_mcp::{
    config::{normalize_allowed_origins, BearerSecret, EmbeddedHttpConfig},
    handler::LegalMcpServer,
    registry::{PrivacyProfile, ToolRegistry},
    service_adapter::ServiceAdapter,
    standalone_approved::{
        ApprovedMcpGrantGroupV1, ProvisionedStandaloneSessionV1, StandaloneSessionMetadataV1,
    },
};
use legal_services::{LegalServices, ServiceConfig};
use privacy::mcp_ticket::McpTransportBindingV1;
use providers::{ApiSecret, CredentialStore, ProviderCredentialKey, ProviderStoreLock};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::oneshot, sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use providers::windows_credentials::WindowsCredentialStore;

const CONFIG_SCHEMA_VERSION: u16 = 1;
const CONFIG_FILE_NAME: &str = "server-config.json";
const CONFIG_DIRECTORY_NAME: &str = "mcp";
const DEFAULT_MATERIALS_DIRECTORY_NAME: &str = "materials";
const DEFAULT_EXPORTS_DIRECTORY_NAME: &str = "exports";
const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MIN_PORT: u16 = 1024;
const MAX_ALLOWED_ROOTS: usize = 64;
const STOP_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const CREDENTIAL_SERVICE_PREFIX: &str = "LawyerAssistanceMcp";
const CREDENTIAL_PROVIDER_ID: &str = "local-http";
const CREDENTIAL_ACCOUNT_ID: &str = "default";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct McpServerConfig {
    pub schema_version: u16,
    pub auto_start: bool,
    pub port: u16,
    pub allowed_roots: Vec<PathBuf>,
    pub output_root: PathBuf,
    pub allowed_origins: Vec<String>,
    pub max_body_bytes: usize,
    pub request_timeout_ms: u64,
    pub max_concurrency: usize,
}

impl McpServerConfig {
    fn defaults(materials: PathBuf, exports: PathBuf) -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            auto_start: false,
            port: 8787,
            allowed_roots: vec![materials],
            output_root: exports,
            allowed_origins: Vec::new(),
            max_body_bytes: legal_mcp::config::DEFAULT_MAX_BODY_BYTES,
            request_timeout_ms: legal_mcp::config::DEFAULT_REQUEST_TIMEOUT_MS,
            max_concurrency: legal_mcp::config::DEFAULT_MAX_CONCURRENCY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpServerStatus {
    pub phase: &'static str,
    pub endpoint: Option<String>,
    pub started_at: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpConfigurationSnapshot {
    pub config: McpServerConfig,
    pub legal_database_path: String,
    pub user_database_path: String,
    pub bearer_token_configured: bool,
    pub bearer_token_masked: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpManagerError {
    code: &'static str,
    message: String,
}

impl McpManagerError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: providers::redact_sensitive(&message.into()),
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for McpManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for McpManagerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerPhase {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

impl ServerPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Failed => "failed",
        }
    }

    const fn permits_configuration_change(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

#[derive(Debug)]
struct ServerRuntime {
    generation: u64,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
    approved_session: Option<ApprovedMcpServerSession>,
}

#[derive(Debug)]
struct ManagerState {
    config: McpServerConfig,
    config_valid: bool,
    phase: ServerPhase,
    endpoint: Option<String>,
    started_at: Option<String>,
    last_error: Option<String>,
    runtime: Option<ServerRuntime>,
    startup_cancellation: Option<CancellationToken>,
    next_generation: u64,
    control_operation: Option<(u64, &'static str)>,
    next_control_operation: u64,
    exiting: bool,
}

#[derive(Debug)]
struct McpManagerShared {
    app_local_data_directory: PathBuf,
    config_path: PathBuf,
    legal_database_path: PathBuf,
    user_database_path: PathBuf,
    credential_store: WindowsCredentialStore,
    credential_key: ProviderCredentialKey,
    lifecycle_notify: Notify,
    approved_workspace: Option<ApprovedMcpWorkspace>,
    state: Mutex<ManagerState>,
}

impl Drop for McpManagerShared {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(token) = state.startup_cancellation.as_ref() {
            token.cancel();
        }
        if let Some(runtime) = state.runtime.as_ref() {
            if let Some(session) = runtime.approved_session.as_ref() {
                let _ = session.revoke_all();
            }
            runtime.cancellation.cancel();
            runtime.task.abort();
        }
    }
}

#[derive(Clone, Debug)]
pub struct McpManager {
    shared: Arc<McpManagerShared>,
}

impl McpManager {
    #[cfg(test)]
    pub fn new(
        app_local_data_directory: PathBuf,
        legal_database_path: PathBuf,
        user_database_path: PathBuf,
    ) -> Result<Self, McpManagerError> {
        Self::new_internal(
            app_local_data_directory,
            legal_database_path,
            user_database_path,
            CREDENTIAL_SERVICE_PREFIX.to_owned(),
            None,
        )
    }

    pub(crate) fn new_with_approved_workspace(
        app_local_data_directory: PathBuf,
        legal_database_path: PathBuf,
        user_database_path: PathBuf,
        approved_workspace: ApprovedMcpWorkspace,
    ) -> Result<Self, McpManagerError> {
        Self::new_internal(
            app_local_data_directory,
            legal_database_path,
            user_database_path,
            CREDENTIAL_SERVICE_PREFIX.to_owned(),
            Some(approved_workspace),
        )
    }

    #[cfg(test)]
    fn new_with_credential_prefix(
        app_local_data_directory: PathBuf,
        legal_database_path: PathBuf,
        user_database_path: PathBuf,
        credential_service_prefix: String,
    ) -> Result<Self, McpManagerError> {
        Self::new_internal(
            app_local_data_directory,
            legal_database_path,
            user_database_path,
            credential_service_prefix,
            None,
        )
    }

    fn new_internal(
        app_local_data_directory: PathBuf,
        legal_database_path: PathBuf,
        user_database_path: PathBuf,
        credential_service_prefix: String,
        approved_workspace: Option<ApprovedMcpWorkspace>,
    ) -> Result<Self, McpManagerError> {
        let app_local_data_directory = ensure_directory(&app_local_data_directory, true)?;
        let legal_database_path = validate_managed_database_path(&legal_database_path)?;
        let user_database_path = validate_managed_database_path(&user_database_path)?;
        let mcp_directory =
            ensure_directory(&app_local_data_directory.join(CONFIG_DIRECTORY_NAME), true)?;
        let materials_directory =
            ensure_directory(&mcp_directory.join(DEFAULT_MATERIALS_DIRECTORY_NAME), true)?;
        let exports_directory =
            ensure_directory(&mcp_directory.join(DEFAULT_EXPORTS_DIRECTORY_NAME), true)?;
        let config_path = mcp_directory.join(CONFIG_FILE_NAME);
        let default_config = McpServerConfig::defaults(materials_directory, exports_directory);
        // MCP is an optional subsystem. A malformed saved file or an offline
        // external root must fail the MCP manager closed, but must not make the
        // entire desktop application unlaunchable. Keep the file untouched and
        // expose either its parsed values or safe defaults so the settings page
        // can perform an explicit, validated repair.
        let (config, config_valid, initial_phase, initial_error) =
            match fs::symlink_metadata(&config_path) {
                Ok(_) => match read_config(&config_path) {
                    Ok(config) => match validate_config(
                        &config,
                        &app_local_data_directory,
                        &config_path,
                        &legal_database_path,
                        &user_database_path,
                    ) {
                        Ok(()) => (config, true, ServerPhase::Stopped, None),
                        Err(error) => (
                            config,
                            false,
                            ServerPhase::Failed,
                            Some(error.message().to_owned()),
                        ),
                    },
                    Err(error) => (
                        default_config.clone(),
                        false,
                        ServerPhase::Failed,
                        Some(error.message().to_owned()),
                    ),
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    validate_config(
                        &default_config,
                        &app_local_data_directory,
                        &config_path,
                        &legal_database_path,
                        &user_database_path,
                    )?;
                    persist_config(&config_path, &default_config)?;
                    (default_config, true, ServerPhase::Stopped, None)
                }
                Err(_) => (
                    default_config,
                    false,
                    ServerPhase::Failed,
                    Some("MCP configuration could not be inspected".to_owned()),
                ),
            };

        Ok(Self {
            shared: Arc::new(McpManagerShared {
                app_local_data_directory,
                config_path,
                legal_database_path,
                user_database_path,
                credential_store: WindowsCredentialStore::with_service_prefix(
                    credential_service_prefix,
                ),
                credential_key: ProviderCredentialKey::new(
                    CREDENTIAL_PROVIDER_ID,
                    CREDENTIAL_ACCOUNT_ID,
                ),
                approved_workspace,
                lifecycle_notify: Notify::new(),
                state: Mutex::new(ManagerState {
                    config,
                    config_valid,
                    phase: initial_phase,
                    endpoint: None,
                    started_at: None,
                    last_error: initial_error,
                    runtime: None,
                    startup_cancellation: None,
                    next_generation: 1,
                    control_operation: None,
                    next_control_operation: 1,
                    exiting: false,
                }),
            }),
        })
    }

    pub fn auto_start_enabled(&self) -> bool {
        let state = self.state();
        state.config_valid && state.phase == ServerPhase::Stopped && state.config.auto_start
    }

    pub async fn auto_start_if_enabled(&self) -> Result<Option<McpServerStatus>, McpManagerError> {
        if !self.auto_start_enabled() {
            return Ok(None);
        }
        self.start().await.map(Some)
    }

    pub async fn configuration_snapshot(
        &self,
    ) -> Result<McpConfigurationSnapshot, McpManagerError> {
        let config = self.state().config.clone();
        let shared = self.shared.clone();
        let (configured, masked) = tokio::task::spawn_blocking(move || {
            bearer_status(&shared.credential_store, &shared.credential_key)
        })
        .await
        .map_err(|_| {
            McpManagerError::new("runtime_failure", "MCP credential worker did not complete")
        })??;
        Ok(McpConfigurationSnapshot {
            config,
            legal_database_path: self
                .shared
                .legal_database_path
                .to_string_lossy()
                .into_owned(),
            user_database_path: self
                .shared
                .user_database_path
                .to_string_lossy()
                .into_owned(),
            bearer_token_configured: configured,
            bearer_token_masked: masked,
        })
    }

    pub fn status(&self) -> McpServerStatus {
        status_from_state(&self.state())
    }

    pub async fn save_config(&self, config: McpServerConfig) -> Result<(), McpManagerError> {
        let _operation = self.begin_control_operation("save_config")?;
        ensure_configuration_mutable(&self.state())?;
        let shared = self.shared.clone();
        let config_for_worker = config.clone();
        tokio::task::spawn_blocking(move || {
            validate_config(
                &config_for_worker,
                &shared.app_local_data_directory,
                &shared.config_path,
                &shared.legal_database_path,
                &shared.user_database_path,
            )?;
            persist_config(&shared.config_path, &config_for_worker)
        })
        .await
        .map_err(|_| {
            McpManagerError::new(
                "runtime_failure",
                "MCP configuration worker did not complete",
            )
        })??;

        let mut state = self.state();
        ensure_configuration_mutable(&state)?;
        state.config = config;
        state.config_valid = true;
        state.phase = ServerPhase::Stopped;
        state.last_error = None;
        Ok(())
    }

    pub async fn write_bearer_token(&self, token: ApiSecret) -> Result<(), McpManagerError> {
        let _operation = self.begin_control_operation("write_bearer_token")?;
        ensure_configuration_mutable(&self.state())?;
        BearerSecret::from_token_bytes(token.expose_secret().as_bytes().to_vec())
            .map_err(|_| invalid_token_error())?;
        let shared = self.shared.clone();
        tokio::task::spawn_blocking(move || {
            let _credential_lock = ProviderStoreLock::acquire().map_err(credential_error)?;
            shared
                .credential_store
                .write_api_key(&shared.credential_key, token)
                .map_err(credential_error)
        })
        .await
        .map_err(|_| {
            McpManagerError::new("runtime_failure", "MCP credential worker did not complete")
        })??;
        let mut state = self.state();
        ensure_configuration_mutable(&state)?;
        if state.config_valid {
            state.phase = ServerPhase::Stopped;
            state.last_error = None;
        }
        Ok(())
    }

    pub async fn delete_bearer_token(&self) -> Result<(), McpManagerError> {
        let _operation = self.begin_control_operation("delete_bearer_token")?;
        ensure_configuration_mutable(&self.state())?;
        let shared = self.shared.clone();
        tokio::task::spawn_blocking(move || {
            let _credential_lock = ProviderStoreLock::acquire().map_err(credential_error)?;
            shared
                .credential_store
                .delete_api_key(&shared.credential_key)
                .map_err(credential_error)
        })
        .await
        .map_err(|_| {
            McpManagerError::new("runtime_failure", "MCP credential worker did not complete")
        })??;
        let mut state = self.state();
        ensure_configuration_mutable(&state)?;
        if state.config_valid {
            state.phase = ServerPhase::Stopped;
            state.last_error = None;
        }
        Ok(())
    }

    pub async fn start(&self) -> Result<McpServerStatus, McpManagerError> {
        let _operation = self.begin_control_operation("start")?;
        let (config, generation, startup_cancellation) = {
            let mut state = self.state();
            if state.exiting {
                return Err(McpManagerError::new(
                    "application_exiting",
                    "The application is exiting and cannot start MCP work",
                ));
            }
            match state.phase {
                ServerPhase::Running => return Ok(status_from_state(&state)),
                ServerPhase::Starting | ServerPhase::Stopping => {
                    return Err(McpManagerError::new(
                        "server_busy",
                        "MCP server lifecycle transition is already in progress",
                    ));
                }
                ServerPhase::Stopped | ServerPhase::Failed => {}
            }
            let generation = state.next_generation;
            state.next_generation = state.next_generation.saturating_add(1);
            let cancellation = CancellationToken::new();
            state.phase = ServerPhase::Starting;
            state.endpoint = None;
            state.started_at = None;
            state.last_error = None;
            state.startup_cancellation = Some(cancellation.clone());
            (state.config.clone(), generation, cancellation)
        };

        let startup = self
            .prepare_server(config, startup_cancellation.clone())
            .await;
        let PreparedServer {
            server,
            resolved,
            listener,
            approved_session,
        } = match startup {
            Ok(prepared) => prepared,
            Err(error) => {
                self.record_start_failure(generation, error.message());
                return Err(error);
            }
        };
        if startup_cancellation.is_cancelled() {
            if let Some(session) = approved_session.as_ref() {
                let _ = session.revoke_all();
            }
            let error = McpManagerError::new(
                "server_cancelled",
                "MCP server startup was cancelled because the application is exiting",
            );
            self.record_start_failure(generation, error.message());
            return Err(error);
        }

        let endpoint = format!("http://127.0.0.1:{}/mcp", resolved.bind.port());
        let cancellation = startup_cancellation;
        let weak = Arc::downgrade(&self.shared);
        let (begin_tx, begin_rx) = oneshot::channel::<()>();
        let runtime_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            if begin_rx.await.is_err() {
                return;
            }
            let result = legal_mcp::http::serve_http_on_listener(
                server,
                &resolved,
                listener,
                runtime_cancellation,
            )
            .await;
            record_server_exit(weak, generation, result);
        });

        {
            let mut state = self.state();
            if state.phase != ServerPhase::Starting
                || state
                    .startup_cancellation
                    .as_ref()
                    .is_none_or(CancellationToken::is_cancelled)
            {
                drop(state);
                task.abort();
                self.record_cancelled_start_commit(generation);
                return Err(McpManagerError::new(
                    "server_cancelled",
                    "MCP server startup was cancelled",
                ));
            }
            state.phase = ServerPhase::Running;
            state.endpoint = Some(endpoint);
            state.started_at = Some(current_utc_timestamp());
            state.last_error = None;
            state.startup_cancellation = None;
            state.runtime = Some(ServerRuntime {
                generation,
                cancellation,
                task,
                approved_session,
            });
        }
        if begin_tx.send(()).is_err() {
            let mut state = self.state();
            let mut state_changed = false;
            let mut failed_session = None;
            if state
                .runtime
                .as_ref()
                .is_some_and(|runtime| runtime.generation == generation)
            {
                let was_stopping = state.phase == ServerPhase::Stopping;
                failed_session = state
                    .runtime
                    .take()
                    .and_then(|runtime| runtime.approved_session);
                state.phase = if was_stopping {
                    ServerPhase::Stopped
                } else {
                    ServerPhase::Failed
                };
                state.endpoint = None;
                state.started_at = None;
                state.last_error = if was_stopping {
                    None
                } else {
                    Some("MCP server task could not be started".to_owned())
                };
                state_changed = true;
            }
            drop(state);
            if let Some(session) = failed_session.as_ref() {
                let _ = session.revoke_all();
            }
            if state_changed {
                self.shared.lifecycle_notify.notify_waiters();
            }
            return Err(McpManagerError::new(
                "runtime_failure",
                "MCP server task could not be started",
            ));
        }
        Ok(self.status())
    }

    pub async fn stop(&self) -> Result<McpServerStatus, McpManagerError> {
        let approved_session = {
            let mut state = self.state();
            match state.phase {
                ServerPhase::Stopped => return Ok(status_from_state(&state)),
                ServerPhase::Failed => {
                    if !state.config_valid {
                        return Ok(status_from_state(&state));
                    }
                    state.phase = ServerPhase::Stopped;
                    state.endpoint = None;
                    state.started_at = None;
                    state.last_error = None;
                    return Ok(status_from_state(&state));
                }
                ServerPhase::Starting => {
                    if let Some(cancellation) = state.startup_cancellation.as_ref() {
                        cancellation.cancel();
                    }
                    state.phase = ServerPhase::Stopping;
                }
                ServerPhase::Running | ServerPhase::Stopping => {
                    if let Some(runtime) = state.runtime.as_ref() {
                        runtime.cancellation.cancel();
                    }
                    state.phase = ServerPhase::Stopping;
                    state.last_error = None;
                }
            }
            state
                .runtime
                .as_ref()
                .and_then(|runtime| runtime.approved_session.clone())
        };
        if let Some(session) = approved_session.as_ref() {
            session.revoke_all().map_err(map_approved_mcp_error)?;
        }

        let deadline = tokio::time::Instant::now() + STOP_WAIT_TIMEOUT;
        loop {
            let notified = self.shared.lifecycle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let status = self.status();
            if status.phase != ServerPhase::Stopping.as_str() {
                return Ok(status);
            }
            match tokio::time::timeout_at(deadline, notified).await {
                Ok(()) => continue,
                Err(_) => {
                    // Cancellation has already stopped new accepts. Keep the
                    // truthful `stopping` phase until the HTTP task confirms
                    // that all graceful shutdown work has ended.
                    return Err(McpManagerError::new(
                        "stop_timeout",
                        "MCP server is still stopping; check its status again shortly",
                    ));
                }
            }
        }
    }

    pub fn cancel_for_exit(&self) {
        let mut state = self.state();
        state.exiting = true;
        let approved_session = state
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.approved_session.clone());
        if let Some(cancellation) = state.startup_cancellation.as_ref() {
            cancellation.cancel();
        }
        if let Some(runtime) = state.runtime.as_ref() {
            runtime.cancellation.cancel();
        }
        if matches!(state.phase, ServerPhase::Starting | ServerPhase::Running) {
            state.phase = ServerPhase::Stopping;
        }
        drop(state);
        if let Some(session) = approved_session.as_ref() {
            let _ = session.revoke_all();
        }
        self.shared.lifecycle_notify.notify_waiters();
    }

    /// Permanently close MCP admission for this process and wait without a UI
    /// timeout until startup, server requests, blocking writes, and any current
    /// configuration/credential operation have all reached a terminal state.
    pub async fn shutdown_for_exit(&self) {
        self.cancel_for_exit();
        loop {
            let notified = self.shared.lifecycle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let done = {
                let mut state = self.state();
                if let Some(cancellation) = state.startup_cancellation.as_ref() {
                    cancellation.cancel();
                }
                if let Some(runtime) = state.runtime.as_ref() {
                    runtime.cancellation.cancel();
                }
                if state.phase == ServerPhase::Stopping
                    && state.runtime.is_none()
                    && state.startup_cancellation.is_none()
                {
                    state.phase = ServerPhase::Stopped;
                    state.endpoint = None;
                    state.started_at = None;
                }
                matches!(state.phase, ServerPhase::Stopped | ServerPhase::Failed)
                    && state.control_operation.is_none()
                    && state.runtime.is_none()
                    && state.startup_cancellation.is_none()
            };
            if done {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn provision_standalone_approved_session(
        &self,
        connector_id: String,
        transport: McpTransportBindingV1,
        grant_groups: Vec<ApprovedMcpGrantGroupV1>,
        ttl_seconds: u64,
        http_port: Option<u16>,
        allowed_origins: Vec<String>,
    ) -> Result<ProvisionedStandaloneSessionV1, McpManagerError> {
        let (config, workspace) = {
            let state = self.state();
            if !state.config_valid {
                return Err(McpManagerError::new(
                    "configuration_invalid",
                    "The saved MCP configuration is invalid",
                ));
            }
            let workspace = self.shared.approved_workspace.clone().ok_or_else(|| {
                McpManagerError::new(
                    "approved_mcp_session_unavailable",
                    "The approved MCP workspace is unavailable",
                )
            })?;
            (state.config.clone(), workspace)
        };
        let allowed_origins = normalize_allowed_origins(allowed_origins).map_err(|_| {
            McpManagerError::new(
                "approved_mcp_standalone_origin_invalid",
                "The standalone approved MCP allowed-origin list is invalid",
            )
        })?;
        let http_bind = match (transport, http_port) {
            (McpTransportBindingV1::Stdio, None) if allowed_origins.is_empty() => None,
            (McpTransportBindingV1::StreamableHttp, Some(port)) if port >= MIN_PORT => Some(
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
            ),
            _ => {
                return Err(McpManagerError::new(
                    "approved_mcp_standalone_binding_invalid",
                    "The standalone approved MCP transport binding is invalid",
                ))
            }
        };
        workspace
            .provision_standalone_session(
                connector_id,
                transport,
                grant_groups,
                ttl_seconds,
                StandaloneMcpHostBinding {
                    legal_database_path: self.shared.legal_database_path.clone(),
                    user_database_path: self.shared.user_database_path.clone(),
                    allowed_roots: config.allowed_roots,
                    output_root: config.output_root,
                    http_bind,
                    allowed_origins,
                },
            )
            .map_err(map_approved_mcp_error)
    }

    pub(crate) fn list_standalone_approved_sessions(
        &self,
    ) -> Result<Vec<StandaloneSessionMetadataV1>, McpManagerError> {
        self.shared
            .approved_workspace
            .as_ref()
            .ok_or_else(|| {
                McpManagerError::new(
                    "approved_mcp_session_unavailable",
                    "The approved MCP workspace is unavailable",
                )
            })?
            .list_standalone_sessions()
            .map_err(map_approved_mcp_error)
    }

    pub(crate) fn revoke_standalone_approved_session(
        &self,
        server_instance_id: &str,
    ) -> Result<(), McpManagerError> {
        self.shared
            .approved_workspace
            .as_ref()
            .ok_or_else(|| {
                McpManagerError::new(
                    "approved_mcp_session_unavailable",
                    "The approved MCP workspace is unavailable",
                )
            })?
            .revoke_standalone_session(server_instance_id)
            .map_err(map_approved_mcp_error)
    }

    pub(crate) fn revoke_active_approved_tickets(&self) -> Result<(), McpManagerError> {
        let session = self
            .state()
            .runtime
            .as_ref()
            .and_then(|runtime| runtime.approved_session.clone());
        session.map_or(Ok(()), |value| {
            value.revoke_all().map_err(map_approved_mcp_error)
        })
    }

    pub async fn shutdown_for_exit_with_timeout(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, self.shutdown_for_exit())
            .await
            .is_ok()
    }

    async fn prepare_server(
        &self,
        config: McpServerConfig,
        cancellation: CancellationToken,
    ) -> Result<PreparedServer, McpManagerError> {
        let shared = self.shared.clone();
        let bearer = tokio::task::spawn_blocking(move || {
            read_bearer_secret(&shared.credential_store, &shared.credential_key)
        })
        .await
        .map_err(|_| {
            McpManagerError::new("runtime_failure", "MCP credential worker did not complete")
        })??
        .ok_or_else(|| {
            McpManagerError::new(
                "bearer_token_required",
                "Configure a Bearer token before starting the MCP server",
            )
        })?;
        if cancellation.is_cancelled() {
            return Err(McpManagerError::new(
                "server_cancelled",
                "MCP server startup was cancelled",
            ));
        }

        validate_config(
            &config,
            &self.shared.app_local_data_directory,
            &self.shared.config_path,
            &self.shared.legal_database_path,
            &self.shared.user_database_path,
        )?;
        let embedded = EmbeddedHttpConfig {
            legal_db: self.shared.legal_database_path.clone(),
            user_db: self.shared.user_database_path.clone(),
            allowed_roots: config.allowed_roots.clone(),
            output_root: config.output_root.clone(),
            port: config.port,
            allowed_origins: config.allowed_origins.clone(),
            bearer: Some(bearer),
            max_body_bytes: config.max_body_bytes,
            request_timeout_ms: config.request_timeout_ms,
            max_concurrency: config.max_concurrency,
        };
        let mut resolved = embedded.resolve().map_err(|_| {
            McpManagerError::new(
                "invalid_configuration",
                "The saved MCP server configuration is invalid",
            )
        })?;
        let services = LegalServices::new(ServiceConfig {
            legal_core_path: self.shared.legal_database_path.clone(),
            user_database_path: self.shared.user_database_path.clone(),
            allowed_file_roots: config.allowed_roots,
            allowed_output_root: config.output_root,
        })
        .map_err(|_| {
            McpManagerError::new(
                "invalid_configuration",
                "The saved MCP filesystem configuration is unavailable",
            )
        })?;
        let status_services = services.clone();
        let service_status = tokio::task::spawn_blocking(move || status_services.system_status())
            .await
            .map_err(|_| {
                McpManagerError::new(
                    "runtime_failure",
                    "MCP database preflight worker did not complete",
                )
            })?
            .map_err(|_| {
                McpManagerError::new(
                    "database_unavailable",
                    "MCP databases did not pass the local readiness check",
                )
            })?;
        require_ready_database_status(&service_status.status)?;
        if cancellation.is_cancelled() {
            return Err(McpManagerError::new(
                "server_cancelled",
                "MCP server startup was cancelled",
            ));
        }
        let approved_session = if let Some(workspace) = self.shared.approved_workspace.clone() {
            tokio::task::spawn_blocking(move || {
                workspace.prepare_session(McpTransportBindingV1::StreamableHttp)
            })
            .await
            .map_err(|_| {
                McpManagerError::new(
                    "runtime_failure",
                    "Approved MCP session preparation did not complete",
                )
            })?
            .map_err(map_approved_mcp_error)?
        } else {
            None
        };
        if cancellation.is_cancelled() {
            if let Some(session) = approved_session.as_ref() {
                let _ = session.revoke_all();
            }
            return Err(McpManagerError::new(
                "server_cancelled",
                "MCP server startup was cancelled",
            ));
        }
        let server = if let Some(session) = approved_session.as_ref() {
            resolved.privacy_profile = PrivacyProfile::ApprovedCaseWorkspace;
            LegalMcpServer::new(
                ToolRegistry::for_profile(PrivacyProfile::ApprovedCaseWorkspace),
                ServiceAdapter::for_approved_workspace(services, session.backend().clone()),
            )
        } else {
            LegalMcpServer::new(ToolRegistry::new(), ServiceAdapter::new(services))
        };
        let listener = match TcpListener::bind(resolved.bind).await {
            Ok(listener) => listener,
            Err(_) => {
                if let Some(session) = approved_session.as_ref() {
                    let _ = session.revoke_all();
                }
                return Err(McpManagerError::new(
                    "port_unavailable",
                    "The configured local MCP port is unavailable",
                ));
            }
        };
        Ok(PreparedServer {
            server,
            resolved,
            listener,
            approved_session,
        })
    }

    fn record_start_failure(&self, generation: u64, message: &str) {
        let mut state = self.state();
        if matches!(state.phase, ServerPhase::Starting | ServerPhase::Stopping)
            && state.next_generation.saturating_sub(1) == generation
            && state.runtime.is_none()
        {
            let was_stopping = state.phase == ServerPhase::Stopping;
            state.phase = if was_stopping {
                ServerPhase::Stopped
            } else {
                ServerPhase::Failed
            };
            state.endpoint = None;
            state.started_at = None;
            state.last_error = if was_stopping {
                None
            } else {
                Some(providers::redact_sensitive(message))
            };
            state.startup_cancellation = None;
            state.runtime = None;
            drop(state);
            self.shared.lifecycle_notify.notify_waiters();
        }
    }

    fn record_cancelled_start_commit(&self, generation: u64) {
        let mut state = self.state();
        if matches!(state.phase, ServerPhase::Starting | ServerPhase::Stopping)
            && state.next_generation.saturating_sub(1) == generation
            && state.runtime.is_none()
        {
            state.phase = ServerPhase::Stopped;
            state.endpoint = None;
            state.started_at = None;
            state.last_error = None;
            state.startup_cancellation = None;
            drop(state);
            self.shared.lifecycle_notify.notify_waiters();
        }
    }

    fn begin_control_operation(
        &self,
        name: &'static str,
    ) -> Result<ControlOperationGuard, McpManagerError> {
        let mut state = self.state();
        if state.exiting {
            return Err(McpManagerError::new(
                "application_exiting",
                "The application is exiting and cannot accept MCP control operations",
            ));
        }
        if let Some((_, active)) = state.control_operation {
            return Err(McpManagerError::new(
                "operation_in_progress",
                format!("Another MCP control operation is already in progress ({active})"),
            ));
        }
        let id = state.next_control_operation;
        state.next_control_operation = state.next_control_operation.saturating_add(1);
        state.control_operation = Some((id, name));
        Ok(ControlOperationGuard {
            shared: Arc::downgrade(&self.shared),
            id,
        })
    }

    fn state(&self) -> MutexGuard<'_, ManagerState> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

struct PreparedServer {
    server: LegalMcpServer,
    resolved: legal_mcp::config::ResolvedConfig,
    listener: TcpListener,
    approved_session: Option<ApprovedMcpServerSession>,
}

#[derive(Debug)]
struct ControlOperationGuard {
    shared: Weak<McpManagerShared>,
    id: u64,
}

impl Drop for ControlOperationGuard {
    fn drop(&mut self) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        let mut state = shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .control_operation
            .is_some_and(|(active_id, _)| active_id == self.id)
        {
            state.control_operation = None;
            drop(state);
            shared.lifecycle_notify.notify_waiters();
        }
    }
}

fn record_server_exit(
    shared: Weak<McpManagerShared>,
    generation: u64,
    result: Result<(), std::io::Error>,
) {
    let Some(shared) = shared.upgrade() else {
        return;
    };
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if state
        .runtime
        .as_ref()
        .is_none_or(|runtime| runtime.generation != generation)
    {
        return;
    }
    let expected_shutdown = state.phase == ServerPhase::Stopping
        || state
            .runtime
            .as_ref()
            .is_some_and(|runtime| runtime.cancellation.is_cancelled());
    let approved_session = state
        .runtime
        .take()
        .and_then(|runtime| runtime.approved_session);
    state.endpoint = None;
    state.started_at = None;
    if expected_shutdown {
        state.phase = ServerPhase::Stopped;
        state.last_error = None;
    } else {
        state.phase = ServerPhase::Failed;
        state.last_error = Some(if result.is_ok() {
            "MCP server stopped unexpectedly".to_owned()
        } else {
            "MCP server listener failed unexpectedly".to_owned()
        });
    }
    drop(state);
    if let Some(session) = approved_session.as_ref() {
        let _ = session.revoke_all();
    }
    shared.lifecycle_notify.notify_waiters();
}

fn status_from_state(state: &ManagerState) -> McpServerStatus {
    McpServerStatus {
        phase: state.phase.as_str(),
        endpoint: state.endpoint.clone(),
        started_at: state.started_at.clone(),
        last_error: state.last_error.clone(),
    }
}

fn ensure_configuration_mutable(state: &ManagerState) -> Result<(), McpManagerError> {
    if state.phase.permits_configuration_change() {
        Ok(())
    } else {
        Err(McpManagerError::new(
            "server_running",
            "Stop the MCP server before changing its configuration or Bearer token",
        ))
    }
}

fn validate_config(
    config: &McpServerConfig,
    app_local_data_directory: &Path,
    config_path: &Path,
    legal_database_path: &Path,
    user_database_path: &Path,
) -> Result<(), McpManagerError> {
    if config.schema_version != CONFIG_SCHEMA_VERSION {
        return Err(McpManagerError::new(
            "invalid_configuration",
            "MCP configuration schema version is not supported",
        ));
    }
    if config.port < MIN_PORT {
        return Err(McpManagerError::new(
            "invalid_configuration",
            "MCP port must be between 1024 and 65535",
        ));
    }
    if config.allowed_roots.len() > MAX_ALLOWED_ROOTS {
        return Err(McpManagerError::new(
            "invalid_configuration",
            "MCP configuration contains too many allowed material roots",
        ));
    }

    let canonical_app_data = canonical_directory(app_local_data_directory)?;
    let canonical_config_parent = canonical_directory(config_path.parent().ok_or_else(|| {
        McpManagerError::new(
            "invalid_configuration",
            "MCP configuration path has no parent directory",
        )
    })?)?;
    let canonical_legal = canonical_regular_file(legal_database_path)?;
    let canonical_user = canonical_regular_file(user_database_path)?;
    let canonical_output = canonical_directory(&config.output_root)?;
    let mut canonical_roots = Vec::with_capacity(config.allowed_roots.len());
    for root in &config.allowed_roots {
        let canonical = canonical_directory(root)?;
        if canonical_roots.contains(&canonical) {
            return Err(McpManagerError::new(
                "invalid_configuration",
                "MCP allowed material roots must be unique",
            ));
        }
        canonical_roots.push(canonical);
    }

    for root in &canonical_roots {
        if paths_overlap(root, &canonical_output) {
            return Err(McpManagerError::new(
                "invalid_configuration",
                "MCP material roots and output root must not overlap",
            ));
        }
        if protected_path_is_within(root, &canonical_legal)
            || protected_path_is_within(root, &canonical_user)
            || protected_path_is_within(root, &canonical_config_parent)
            || *root == canonical_app_data
        {
            return Err(McpManagerError::new(
                "invalid_configuration",
                "An MCP material root would expose application-managed state",
            ));
        }
    }
    if protected_path_is_within(&canonical_output, &canonical_legal)
        || protected_path_is_within(&canonical_output, &canonical_user)
        || protected_path_is_within(&canonical_output, &canonical_config_parent)
        || *canonical_output == canonical_app_data
    {
        return Err(McpManagerError::new(
            "invalid_configuration",
            "The MCP output root would overlap application-managed state",
        ));
    }
    probe_output_root(&canonical_output)?;

    let embedded = EmbeddedHttpConfig {
        legal_db: legal_database_path.to_path_buf(),
        user_db: user_database_path.to_path_buf(),
        allowed_roots: config.allowed_roots.clone(),
        output_root: config.output_root.clone(),
        port: config.port,
        allowed_origins: config.allowed_origins.clone(),
        bearer: None,
        max_body_bytes: config.max_body_bytes,
        request_timeout_ms: config.request_timeout_ms,
        max_concurrency: config.max_concurrency,
    };
    embedded.resolve().map_err(|_| {
        McpManagerError::new(
            "invalid_configuration",
            "MCP network limits or allowed origins are invalid",
        )
    })?;
    LegalServices::new(ServiceConfig {
        legal_core_path: legal_database_path.to_path_buf(),
        user_database_path: user_database_path.to_path_buf(),
        allowed_file_roots: config.allowed_roots.clone(),
        allowed_output_root: config.output_root.clone(),
    })
    .map_err(|_| {
        McpManagerError::new(
            "invalid_configuration",
            "MCP filesystem configuration is invalid or unavailable",
        )
    })?;
    Ok(())
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

fn protected_path_is_within(root: &Path, protected: &Path) -> bool {
    protected.starts_with(root)
}

fn validate_managed_database_path(path: &Path) -> Result<PathBuf, McpManagerError> {
    if !is_normal_absolute(path) {
        return Err(McpManagerError::new(
            "invalid_configuration",
            "Managed database paths must be absolute and normalized",
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        McpManagerError::new(
            "database_unavailable",
            "A managed database file is missing or inaccessible",
        )
    })?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(McpManagerError::new(
            "database_unavailable",
            "Managed database paths must name ordinary files",
        ));
    }
    Ok(path.to_path_buf())
}

fn ensure_directory(path: &Path, create: bool) -> Result<PathBuf, McpManagerError> {
    if !is_normal_absolute(path) {
        return Err(McpManagerError::new(
            "invalid_configuration",
            "MCP directories must use absolute normalized paths",
        ));
    }
    if create {
        fs::create_dir_all(path).map_err(|_| {
            McpManagerError::new(
                "filesystem_unavailable",
                "An MCP application directory could not be created",
            )
        })?;
    }
    // Validate through the canonical target, but retain the caller's ordinary
    // absolute spelling for persistence and UI display. Windows canonical
    // paths commonly carry a `\\?\` prefix that is an implementation detail,
    // not a useful user-facing configuration value.
    canonical_directory(path)?;
    Ok(path.to_path_buf())
}

fn canonical_directory(path: &Path) -> Result<PathBuf, McpManagerError> {
    if !is_normal_absolute(path) {
        return Err(McpManagerError::new(
            "invalid_configuration",
            "MCP directories must use absolute normalized paths",
        ));
    }
    reject_existing_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        McpManagerError::new(
            "filesystem_unavailable",
            "An MCP directory is missing or inaccessible",
        )
    })?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(McpManagerError::new(
            "filesystem_rejected",
            "MCP directories must not be links or reparse points",
        ));
    }
    fs::canonicalize(path).map_err(|_| {
        McpManagerError::new(
            "filesystem_unavailable",
            "An MCP directory could not be resolved",
        )
    })
}

fn canonical_regular_file(path: &Path) -> Result<PathBuf, McpManagerError> {
    if !is_normal_absolute(path) {
        return Err(McpManagerError::new(
            "invalid_configuration",
            "Managed files must use absolute normalized paths",
        ));
    }
    reject_existing_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        McpManagerError::new(
            "filesystem_unavailable",
            "A managed file is missing or inaccessible",
        )
    })?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(McpManagerError::new(
            "filesystem_rejected",
            "Managed files must not be links or reparse points",
        ));
    }
    fs::canonicalize(path).map_err(|_| {
        McpManagerError::new(
            "filesystem_unavailable",
            "A managed file could not be resolved",
        )
    })
}

fn is_normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn reject_existing_reparse_components(path: &Path) -> Result<(), McpManagerError> {
    let mut ancestors = path.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| {
            McpManagerError::new(
                "filesystem_unavailable",
                "A configured filesystem path is missing or inaccessible",
            )
        })?;
        if is_reparse_point(&metadata) {
            return Err(McpManagerError::new(
                "filesystem_rejected",
                "Configured filesystem paths must not contain links or reparse points",
            ));
        }
    }
    Ok(())
}

fn probe_output_root(root: &Path) -> Result<(), McpManagerError> {
    let probe = root.join(format!(
        ".lawyer-assistance-mcp-write-probe-{}.tmp",
        Uuid::new_v4()
    ));
    let probe_result = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)?;
        file.write_all(b"MCP output root write probe")?;
        file.sync_all()?;
        drop(file);
        fs::remove_file(&probe)
    })();
    if probe_result.is_err() {
        let _ = fs::remove_file(&probe);
        return Err(McpManagerError::new(
            "output_root_unavailable",
            "The MCP output root is not durably writable",
        ));
    }
    Ok(())
}

fn read_config(path: &Path) -> Result<McpServerConfig, McpManagerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        McpManagerError::new(
            "configuration_unavailable",
            "MCP configuration could not be read",
        )
    })?;
    if !metadata.is_file()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(McpManagerError::new(
            "configuration_invalid",
            "MCP configuration must be an ordinary bounded JSON file",
        ));
    }
    let bytes = fs::read(path).map_err(|_| {
        McpManagerError::new(
            "configuration_unavailable",
            "MCP configuration could not be read",
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        McpManagerError::new("configuration_invalid", "MCP configuration JSON is invalid")
    })
}

fn persist_config(path: &Path, config: &McpServerConfig) -> Result<(), McpManagerError> {
    let bytes = serde_json::to_vec_pretty(config).map_err(|_| {
        McpManagerError::new(
            "configuration_invalid",
            "MCP configuration could not be serialized",
        )
    })?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(McpManagerError::new(
            "configuration_invalid",
            "MCP configuration exceeds its size limit",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        McpManagerError::new(
            "configuration_invalid",
            "MCP configuration path has no parent directory",
        )
    })?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || is_reparse_point(&metadata) => {
            return Err(McpManagerError::new(
                "configuration_invalid",
                "MCP configuration destination must be an ordinary file",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(McpManagerError::new(
                "configuration_unavailable",
                "MCP configuration destination could not be inspected",
            ));
        }
    }
    let incoming = parent.join(format!(".{CONFIG_FILE_NAME}.{}.incoming", Uuid::new_v4()));
    let write_result = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&incoming)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        // ReplaceFileW needs to open the incoming file itself. Close our
        // durability handle first so Windows sharing rules cannot make every
        // update fail after the initial create.
        drop(file);
        crate::atomic_file::install(&incoming, path, None)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&incoming);
        return Err(McpManagerError::new(
            "configuration_unavailable",
            "MCP configuration could not be saved atomically",
        ));
    }
    Ok(())
}

fn bearer_status(
    store: &WindowsCredentialStore,
    key: &ProviderCredentialKey,
) -> Result<(bool, Option<String>), McpManagerError> {
    let _credential_lock = ProviderStoreLock::acquire().map_err(credential_error)?;
    let secret = store.read_api_key(key).map_err(credential_error)?;
    Ok(match secret {
        Some(secret) => (true, Some(secret.masked_last_four())),
        None => (false, None),
    })
}

fn read_bearer_secret(
    store: &WindowsCredentialStore,
    key: &ProviderCredentialKey,
) -> Result<Option<BearerSecret>, McpManagerError> {
    let _credential_lock = ProviderStoreLock::acquire().map_err(credential_error)?;
    let secret = store.read_api_key(key).map_err(credential_error)?;
    secret
        .map(|secret| {
            BearerSecret::from_token_bytes(secret.expose_secret().as_bytes().to_vec())
                .map_err(|_| invalid_token_error())
        })
        .transpose()
}

fn map_approved_mcp_error(error: crate::approved_mcp::ApprovedMcpError) -> McpManagerError {
    McpManagerError::new(error.code(), error.message())
}

fn credential_error(_error: providers::ProviderError) -> McpManagerError {
    McpManagerError::new(
        "credential_unavailable",
        "The MCP Bearer credential store is unavailable",
    )
}

fn invalid_token_error() -> McpManagerError {
    McpManagerError::new(
        "invalid_bearer_token",
        "Bearer token must contain 32 to 512 visible ASCII characters",
    )
}

fn require_ready_database_status(status: &str) -> Result<(), McpManagerError> {
    if status == "ready" {
        Ok(())
    } else {
        Err(McpManagerError::new(
            "database_unavailable",
            "MCP databases did not pass the local readiness check",
        ))
    }
}

fn current_utc_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    format_unix_timestamp(seconds)
}

fn format_unix_timestamp(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let seconds_of_day = seconds % 86_400;
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    let (year, month, day) = civil_date_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

// Gregorian civil date conversion adapted from the public-domain algorithm by
// Howard Hinnant. `days` is counted from the Unix epoch (1970-01-01).
fn civil_date_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days.saturating_add(719_468);
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager_fixture() -> (tempfile::TempDir, McpManager) {
        let directory = tempfile::tempdir().expect("temporary application directory");
        let legal = directory.path().join("legal.sqlite");
        let user = directory.path().join("user.sqlite");
        fs::write(&legal, b"legal").expect("legal placeholder");
        fs::write(&user, b"user").expect("user placeholder");
        let manager = McpManager::new_with_credential_prefix(
            directory.path().to_path_buf(),
            legal,
            user,
            format!("LawyerAssistanceMcpTest-{}", Uuid::new_v4()),
        )
        .expect("manager initializes");
        (directory, manager)
    }

    #[test]
    fn timestamp_is_utc_rfc3339_without_milliseconds() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_timestamp(1_721_236_496), "2024-07-17T17:14:56Z");
    }

    #[test]
    fn database_preflight_fails_closed_with_a_path_free_error() {
        assert!(require_ready_database_status("ready").is_ok());
        let error =
            require_ready_database_status("degraded").expect_err("degraded databases are rejected");
        assert_eq!(error.code(), "database_unavailable");
        assert!(!error.message().contains(':'));
        assert!(!error.message().contains('\\'));
    }

    #[test]
    fn configuration_json_is_strict_and_contains_no_credential() {
        let (_directory, manager) = manager_fixture();
        let config = manager.state().config.clone();
        let json = serde_json::to_string(&config).expect("configuration serializes");
        assert!(!json.to_ascii_lowercase().contains("token"));
        let mut value = serde_json::to_value(config).expect("configuration value");
        value
            .as_object_mut()
            .expect("configuration object")
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<McpServerConfig>(value).is_err());
    }

    #[tokio::test]
    async fn configuration_save_is_atomic_and_reloads() {
        let (directory, manager) = manager_fixture();
        let extra_root = directory.path().join("case-materials");
        let output = directory.path().join("case-exports");
        fs::create_dir(&extra_root).expect("material directory");
        fs::create_dir(&output).expect("output directory");
        let mut config = manager.state().config.clone();
        config.port = 9898;
        config.allowed_roots = vec![extra_root];
        config.output_root = output;
        manager
            .save_config(config.clone())
            .await
            .expect("configuration saves");
        assert!(fs::read_dir(&config.output_root)
            .expect("output directory reads")
            .all(|entry| !entry
                .expect("output entry reads")
                .file_name()
                .to_string_lossy()
                .starts_with(".lawyer-assistance-mcp-write-probe-")));

        let reopened = McpManager::new(
            directory.path().to_path_buf(),
            directory.path().join("legal.sqlite"),
            directory.path().join("user.sqlite"),
        )
        .expect("manager reloads");
        assert_eq!(reopened.state().config, config);
    }

    #[tokio::test]
    async fn protected_and_overlapping_roots_are_rejected_without_replacing_config() {
        let (directory, manager) = manager_fixture();
        let original = manager.state().config.clone();
        let mut invalid = original.clone();
        invalid.allowed_roots = vec![directory.path().to_path_buf()];
        invalid.output_root = directory.path().join("mcp").join("exports");
        let error = manager
            .save_config(invalid)
            .await
            .expect_err("managed state root is rejected");
        assert_eq!(error.code(), "invalid_configuration");
        assert_eq!(manager.state().config, original);
        assert_eq!(
            read_config(&manager.shared.config_path).expect("persisted config reads"),
            original
        );
    }

    #[tokio::test]
    async fn corrupt_persisted_configuration_fails_only_the_optional_manager_and_can_be_repaired() {
        let (directory, manager) = manager_fixture();
        fs::write(&manager.shared.config_path, b"{not-json").expect("corrupt configuration writes");
        let reopened = McpManager::new(
            directory.path().to_path_buf(),
            directory.path().join("legal.sqlite"),
            directory.path().join("user.sqlite"),
        )
        .expect("corrupt optional configuration must not block the desktop app");
        assert_eq!(reopened.status().phase, "failed");
        assert_eq!(
            fs::read(&reopened.shared.config_path).unwrap(),
            b"{not-json"
        );

        let repair = reopened.state().config.clone();
        reopened
            .save_config(repair.clone())
            .await
            .expect("an explicit validated save repairs the file");
        assert_eq!(reopened.status().phase, "stopped");
        assert_eq!(read_config(&reopened.shared.config_path).unwrap(), repair);
    }

    #[tokio::test]
    async fn offline_saved_root_is_exposed_for_repair_without_blocking_manager_creation() {
        let (directory, manager) = manager_fixture();
        let external = directory.path().join("external-materials");
        fs::create_dir(&external).unwrap();
        let mut saved = manager.state().config.clone();
        saved.allowed_roots = vec![external.clone()];
        manager.save_config(saved.clone()).await.unwrap();
        drop(manager);
        fs::remove_dir(&external).unwrap();

        let reopened = McpManager::new(
            directory.path().to_path_buf(),
            directory.path().join("legal.sqlite"),
            directory.path().join("user.sqlite"),
        )
        .expect("offline optional root must not block the desktop app");
        assert_eq!(reopened.status().phase, "failed");
        assert_eq!(reopened.state().config, saved);

        let replacement = directory.path().join("replacement-materials");
        fs::create_dir(&replacement).unwrap();
        let mut repaired = saved;
        repaired.allowed_roots = vec![replacement];
        reopened.save_config(repaired).await.unwrap();
        assert_eq!(reopened.status().phase, "stopped");
    }

    #[tokio::test]
    async fn runtime_configuration_cannot_change() {
        let (_directory, manager) = manager_fixture();
        let config = manager.state().config.clone();
        manager.state().phase = ServerPhase::Running;
        let error = manager
            .save_config(config)
            .await
            .expect_err("running server protects configuration");
        assert_eq!(error.code(), "server_running");
    }

    #[tokio::test]
    async fn start_without_an_explicit_bearer_fails_closed_before_binding() {
        let (_directory, manager) = manager_fixture();
        let error = manager
            .start()
            .await
            .expect_err("missing Bearer credential rejects startup");
        assert_eq!(error.code(), "bearer_token_required");
        let status = manager.status();
        assert_eq!(status.phase, "failed");
        assert_eq!(status.endpoint, None);
        assert_eq!(status.started_at, None);
        assert_eq!(status.last_error.as_deref(), Some(error.message()));
    }

    #[tokio::test]
    async fn stop_waits_for_runtime_exit_notification_before_reporting_stopped() {
        let (_directory, manager) = manager_fixture();
        let generation = 7;
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let weak = Arc::downgrade(&manager.shared);
        let task = tokio::spawn(async move {
            task_cancellation.cancelled().await;
            record_server_exit(weak, generation, Ok(()));
        });
        {
            let mut state = manager.state();
            state.phase = ServerPhase::Running;
            state.endpoint = Some("http://127.0.0.1:8787/mcp".to_owned());
            state.started_at = Some("2026-07-17T12:00:00Z".to_owned());
            state.runtime = Some(ServerRuntime {
                generation,
                cancellation,
                task,
                approved_session: None,
            });
        }

        let status = manager.stop().await.expect("graceful stop completes");
        assert_eq!(status.phase, "stopped");
        assert_eq!(status.endpoint, None);
        assert_eq!(status.started_at, None);
        assert_eq!(status.last_error, None);
    }

    #[tokio::test]
    async fn stop_can_cancel_startup_while_the_start_control_operation_is_active() {
        let (_directory, manager) = manager_fixture();
        let operation = manager.begin_control_operation("start").unwrap();
        let cancellation = CancellationToken::new();
        {
            let mut state = manager.state();
            state.phase = ServerPhase::Starting;
            state.next_generation = 2;
            state.startup_cancellation = Some(cancellation.clone());
        }
        let stopping_manager = manager.clone();
        let stopping = tokio::spawn(async move { stopping_manager.stop().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cancellation.is_cancelled() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stop cancels startup despite the active start operation");
        manager.record_start_failure(1, "cancelled startup");
        let status = stopping.await.unwrap().unwrap();
        assert_eq!(status.phase, "stopped");
        drop(operation);
    }

    #[tokio::test]
    async fn cancelled_start_commit_wakes_a_stop_waiter() {
        let (_directory, manager) = manager_fixture();
        let cancellation = CancellationToken::new();
        {
            let mut state = manager.state();
            state.phase = ServerPhase::Starting;
            state.next_generation = 2;
            state.startup_cancellation = Some(cancellation.clone());
        }

        let stopping_manager = manager.clone();
        let stopping = tokio::spawn(async move { stopping_manager.stop().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if cancellation.is_cancelled() && manager.state().phase == ServerPhase::Stopping {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stop reaches its wait state");
        tokio::task::yield_now().await;

        manager.record_cancelled_start_commit(1);
        let status = tokio::time::timeout(Duration::from_secs(1), stopping)
            .await
            .expect("the cancelled start commit wakes stop")
            .expect("stop task joins")
            .expect("stop completes");
        assert_eq!(status.phase, "stopped");
    }

    #[tokio::test]
    async fn exit_shutdown_waits_for_current_control_operation_and_blocks_new_work() {
        let (_directory, manager) = manager_fixture();
        let operation = manager.begin_control_operation("save_config").unwrap();
        let draining_manager = manager.clone();
        let mut draining = tokio::spawn(async move { draining_manager.shutdown_for_exit().await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !manager.state().exiting {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("exit admission closes");
        assert_eq!(
            manager
                .begin_control_operation("start")
                .expect_err("new work is rejected during exit")
                .code(),
            "application_exiting"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut draining)
                .await
                .is_err()
        );

        drop(operation);
        tokio::time::timeout(Duration::from_secs(1), draining)
            .await
            .expect("exit drain completes after control operation")
            .expect("drain task joins");
    }

    #[tokio::test]
    async fn exit_watchdog_times_out_without_falsely_reporting_a_running_server_stopped() {
        let (_directory, manager) = manager_fixture();
        let generation = 17;
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(std::future::pending());
        {
            let mut state = manager.state();
            state.phase = ServerPhase::Running;
            state.endpoint = Some("http://127.0.0.1:8787/mcp".to_owned());
            state.runtime = Some(ServerRuntime {
                generation,
                cancellation: cancellation.clone(),
                task,
                approved_session: None,
            });
        }

        assert!(
            !manager
                .shutdown_for_exit_with_timeout(Duration::from_millis(20))
                .await
        );
        assert!(cancellation.is_cancelled());
        assert_eq!(manager.status().phase, "stopping");
        manager.state().runtime.take().unwrap().task.abort();
    }

    #[test]
    fn exit_cancellation_wins_a_startup_race_without_leaving_starting_state() {
        let (_directory, manager) = manager_fixture();
        let cancellation = CancellationToken::new();
        {
            let mut state = manager.state();
            state.phase = ServerPhase::Starting;
            state.next_generation = 2;
            state.startup_cancellation = Some(cancellation.clone());
        }

        manager.cancel_for_exit();
        assert!(cancellation.is_cancelled());
        assert_eq!(manager.status().phase, "stopping");
        manager.record_start_failure(1, "a private path must never be retained");
        let status = manager.status();
        assert_eq!(status.phase, "stopped");
        assert_eq!(status.last_error, None);
    }

    #[test]
    fn a_reparse_ancestor_is_rejected_even_when_the_final_directory_is_ordinary() {
        use std::os::windows::fs::symlink_dir;

        let directory = tempfile::tempdir().expect("temporary directory");
        let real = directory.path().join("real");
        let child = real.join("child");
        let alias = directory.path().join("alias");
        fs::create_dir_all(&child).expect("real child directory");
        if symlink_dir(&real, &alias).is_err() {
            // Windows installations without Developer Mode may prohibit
            // unprivileged symlink creation. The production check still runs;
            // this environment cannot construct the adversarial fixture.
            return;
        }
        let error =
            canonical_directory(&alias.join("child")).expect_err("reparse ancestor is rejected");
        assert_eq!(error.code(), "filesystem_rejected");
    }
}
