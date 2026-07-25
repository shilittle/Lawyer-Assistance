pub mod approved_backend;
pub mod approved_workspace;
pub mod config;
mod diagram_mcp;
pub mod handler;
pub mod http;
mod privacy_gate;
mod public_output;
pub mod receipt_gate;
pub mod registry;
pub mod release_binary;
pub mod service_adapter;
pub mod standalone_approved;
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
    #[error(transparent)]
    ApprovedSession(#[from] standalone_approved::StandaloneApprovedError),
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
    if cli.approved_session_id.is_none() && cli.approved_qualification_canary_id.is_some() {
        return Err(StartupError::ApprovedSession(
            standalone_approved::StandaloneApprovedError::InvalidBinding,
        ));
    }
    let standalone = if let Some(server_instance_id) = cli.approved_session_id.as_deref() {
        validate_standalone_cli_boundary(&cli)?;
        let app_directory = match cli.approved_qualification_canary_id.as_deref() {
            Some(canary_id) => {
                standalone_approved::qualification_canary_app_local_data_directory(canary_id)?
            }
            None => standalone_approved::default_app_local_data_directory()?,
        };
        Some(standalone_approved::load_standalone_for_binary(
            &app_directory,
            server_instance_id,
            &cli.command,
        )?)
    } else {
        None
    };
    let config = match standalone.as_ref() {
        Some(loaded) => loaded.config.clone(),
        None => cli.resolve()?,
    };
    let services = LegalServices::new(ServiceConfig {
        legal_core_path: config.legal_db.clone(),
        user_database_path: config.user_db.clone(),
        allowed_file_roots: config.allowed_roots.clone(),
        allowed_output_root: config.output_root.clone(),
    })?;
    let profile = config.privacy_profile;
    let adapter = match standalone.as_ref() {
        Some(loaded) => ServiceAdapter::for_standalone_approved(services, loaded.broker.clone()),
        None => ServiceAdapter::for_profile(services, profile),
    };
    let registry = if standalone.is_some() {
        ToolRegistry::for_standalone_approved()
    } else {
        ToolRegistry::for_profile(profile)
    };
    let server = LegalMcpServer::new(registry, adapter);
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

fn validate_standalone_cli_boundary(
    cli: &Cli,
) -> Result<(), standalone_approved::StandaloneApprovedError> {
    use registry::PrivacyProfile;

    let profile_valid = cli
        .privacy_profile
        .is_none_or(|profile| profile == PrivacyProfile::ApprovedCaseWorkspace);
    if !profile_valid
        || cli.config.is_some()
        || cli.legal_db.is_some()
        || cli.user_db.is_some()
        || !cli.allowed_root.is_empty()
        || cli.output_dir.is_some()
        || cli.bearer_env.is_some()
        || cli.bearer_token_file.is_some()
        || !cli.allowed_origin.is_empty()
        || !cli.allowed_host.is_empty()
        || cli.max_body_bytes.is_some()
        || cli.request_timeout_ms.is_some()
        || cli.max_concurrency.is_some()
        || cli.dangerously_allow_insecure_non_loopback_http
        || matches!(cli.command, Command::InitUserDb)
    {
        return Err(standalone_approved::StandaloneApprovedError::InvalidBinding);
    }
    Ok(())
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
