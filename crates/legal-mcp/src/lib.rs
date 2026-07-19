pub mod config;
pub mod handler;
pub mod http;
mod privacy_gate;
mod public_output;
pub mod receipt_gate;
pub mod registry;
pub mod service_adapter;
pub mod stdio;

use clap::Parser;
use config::{Cli, Command};
use handler::LegalMcpServer;
use legal_services::{LegalServices, ServiceConfig};
use registry::ToolRegistry;
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
    #[error("user database initialization failed: {0}")]
    Database(#[from] database::DatabaseInitError),
    #[error("MCP transport failed: {0}")]
    Transport(String),
}

/// Parse configuration and run the selected MCP transport.
///
/// This synchronous entry point keeps `main` small and guarantees that no
/// tracing formatter can accidentally select stdout before the runtime starts.
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
    if matches!(cli.command, Command::InitUserDb) {
        let requested = cli.resolve_user_db_only()?;
        let expected_name = std::ffi::OsStr::new(database::USER_DB_FILE_NAME);
        if requested.file_name() != Some(expected_name) {
            return Err(StartupError::Transport(format!(
                "init-user-db requires the configured filename {}",
                database::USER_DB_FILE_NAME
            )));
        }
        let parent = requested.parent().ok_or_else(|| {
            StartupError::Transport("configured user database has no parent directory".to_owned())
        })?;
        let created = database::ensure_user_database(parent)?;
        let created = std::fs::canonicalize(created).map_err(StartupError::Runtime)?;
        let requested = std::fs::canonicalize(requested).map_err(StartupError::Runtime)?;
        if created != requested {
            return Err(StartupError::Transport(
                "database initializer returned an unexpected path".to_owned(),
            ));
        }
        println!("initialized {}", created.display());
        return Ok(());
    }
    let config = cli.resolve()?;
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: config.legal_db.clone(),
        user_database_path: config.user_db.clone(),
        allowed_file_roots: config.allowed_roots.clone(),
        allowed_output_root: config.output_root.clone(),
    })?;
    let profile = config.privacy_profile;
    let adapter = ServiceAdapter::for_profile(services, profile);
    let server = LegalMcpServer::new(ToolRegistry::for_profile(profile), adapter);
    match config.command.clone() {
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
        Command::InitUserDb => unreachable!("handled before service construction"),
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
    // Do not accept arbitrary tracing directives. Dependencies are capped at
    // WARN so a user cannot turn on protocol/body/header traces by environment.
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
    use tracing_subscriber::filter::LevelFilter;

    #[test]
    fn log_configuration_accepts_only_a_bounded_level() {
        assert_eq!(configured_log_level(Some("debug")), LevelFilter::DEBUG);
        assert_eq!(configured_log_level(Some("rmcp=trace")), LevelFilter::INFO);
        assert_eq!(configured_log_level(Some("trace")), LevelFilter::DEBUG);
    }
}
