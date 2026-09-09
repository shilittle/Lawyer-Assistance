pub mod config;
pub mod handler;
pub mod http;
pub mod privacy_backend;
mod privacy_gate;
mod public_output;
pub mod registry;
pub mod service_adapter;
pub mod stdio;

use clap::Parser;
use config::{Cli, Command};
use handler::LegalMcpServer;
use legal_services::LegalServices;
use privacy_backend::{DaemonPrivacyBackend, DaemonPrivacyBackendFactory};
use registry::{PrivacyProfile, ToolRegistry};
use rmcp::{transport::async_rw::AsyncRwTransport, RoleServer, ServiceExt};
use service_adapter::ServiceAdapter;
use stdio::StableProtocolTransport;

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Configuration(#[from] config::ConfigError),
    #[error("service initialization failed: {0}")]
    Service(#[from] legal_services::ServiceError),
    #[error("runtime initialization failed")]
    Runtime(#[source] std::io::Error),
    #[error("profile_disabled")]
    ProfileDisabled,
    #[error("MCP transport failed: {0}")]
    Transport(String),
}

/// Parse configuration and run the selected MCP transport. Logging is confined
/// to stderr so stdio remains a clean JSON-RPC stream.
pub fn run() -> Result<(), StartupError> {
    init_stderr_tracing();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(StartupError::Runtime)?;
    runtime.block_on(run_cli(cli))
}

pub async fn run_cli(cli: Cli) -> Result<(), StartupError> {
    let mut config = cli.resolve()?;
    if config.privacy_profile.is_disabled() {
        return Err(StartupError::ProfileDisabled);
    }
    let services = LegalServices::new_public(config.legal_db.clone())?;
    let command = config.command.clone();
    let adapter = match (config.privacy_profile, &command) {
        (PrivacyProfile::PublicLawOnly, _) => {
            ServiceAdapter::for_profile(services, PrivacyProfile::PublicLawOnly)
        }
        (PrivacyProfile::PrivacyWorkspace, Command::Stdio) => {
            let token = config.client_token.take().ok_or_else(|| {
                StartupError::Transport("privacy_workspace requires a client token".to_owned())
            })?;
            let backend = DaemonPrivacyBackend::from_client_token(
                config.daemon_url.clone(),
                token,
                &config.limits,
            )
            .map_err(|_| StartupError::Transport("privacy backend unavailable".to_owned()))?;
            ServiceAdapter::for_privacy_workspace(services, std::sync::Arc::new(backend))
        }
        (PrivacyProfile::PrivacyWorkspace, Command::Serve { .. }) => {
            let factory =
                DaemonPrivacyBackendFactory::new(config.daemon_url.clone(), config.limits.clone())
                    .map_err(|_| {
                        StartupError::Transport("privacy backend unavailable".to_owned())
                    })?;
            ServiceAdapter::for_privacy_workspace_proxy(services, std::sync::Arc::new(factory))
        }
        (_, _) => return Err(StartupError::ProfileDisabled),
    };
    let server = LegalMcpServer::new(ToolRegistry::for_profile(config.privacy_profile), adapter);
    match command {
        Command::Stdio => {
            let transport =
                StableProtocolTransport::new(AsyncRwTransport::<RoleServer, _, _>::new_server(
                    tokio::io::stdin(),
                    tokio::io::stdout(),
                ));
            let running = server
                .serve(transport)
                .await
                .map_err(|error| StartupError::Transport(error.to_string()))?;
            running
                .waiting()
                .await
                .map_err(|error| StartupError::Transport(error.to_string()))?;
            Ok(())
        }
        Command::Serve { .. } => http::serve_http(server, &config)
            .await
            .map_err(|error| StartupError::Transport(error.to_string())),
    }
}

fn init_stderr_tracing() {
    use tracing_subscriber::{
        filter::{LevelFilter, Targets},
        fmt,
        layer::SubscriberExt,
        util::SubscriberInitExt,
        Layer,
    };

    let own_level =
        configured_log_level(std::env::var("LAWYER_ASSISTANCE_MCP_LOG").ok().as_deref());
    let filter = Targets::new()
        .with_default(LevelFilter::WARN)
        .with_target("rmcp", LevelFilter::OFF)
        .with_target("legal_mcp", own_level);
    let formatter = fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(filter);
    let _ = tracing_subscriber::registry().with(formatter).try_init();
}

fn configured_log_level(value: Option<&str>) -> tracing_subscriber::filter::LevelFilter {
    use tracing_subscriber::filter::LevelFilter;

    match value.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("off") => LevelFilter::OFF,
        Some("error") => LevelFilter::ERROR,
        Some("warn") | Some("warning") => LevelFilter::WARN,
        Some("debug") | Some("trace") => LevelFilter::DEBUG,
        _ => LevelFilter::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn legacy_profiles_are_explicitly_disabled_before_service_startup() {
        let cli = Cli::try_parse_from([
            "lawyer-assistance-mcp",
            "--privacy-profile",
            "approved_case_workspace",
            "stdio",
        ])
        .expect("CLI parses legacy profile for a clear migration error");
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        assert!(matches!(
            runtime.block_on(run_cli(cli)),
            Err(StartupError::ProfileDisabled)
        ));
    }
}
