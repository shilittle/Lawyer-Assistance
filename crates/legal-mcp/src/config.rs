use crate::registry::PrivacyProfile;
use clap::{ArgAction, Parser, Subcommand};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fmt, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
pub const DEFAULT_DAEMON_URL: &str = "http://127.0.0.1:8877";
pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_MAX_CONCURRENCY: usize = 8;
pub const DEFAULT_DAEMON_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_TOKEN_FILE_BYTES: u64 = 4096;
const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 512;

#[derive(Debug, Parser)]
#[command(
    name = "lawyer-assistance-mcp",
    version,
    about = "Local MCP server for public legal research and approved privacy workspace access"
)]
pub struct Cli {
    /// Compatibility TOML or JSON configuration file. Only legal_db and the
    /// new MCP settings are read; old user/workspace fields are ignored.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Offline legal corpus. Defaults to data/runtime/legal_core.sqlite or LEGAL_DB.
    #[arg(long, global = true)]
    pub legal_db: Option<PathBuf>,

    /// MCP data-exposure profile. The legacy sensitive profiles are disabled.
    #[arg(long, global = true, value_enum)]
    pub privacy_profile: Option<PrivacyProfile>,

    /// Loopback Lawyer Assistance backend for privacy_workspace.
    #[arg(long, global = true)]
    pub daemon_url: Option<String>,

    /// A file containing the client bearer token for privacy_workspace.
    #[arg(long, global = true)]
    pub client_token_file: Option<PathBuf>,

    /// Deprecated compatibility option. The public MCP profile never opens a
    /// user database, so this value is deliberately ignored.
    #[arg(long, global = true, hide = true)]
    pub user_db: Option<PathBuf>,

    /// Deprecated compatibility option, ignored by the public MCP profile.
    #[arg(long, global = true, hide = true, action = ArgAction::Append)]
    pub allowed_root: Vec<PathBuf>,

    /// Deprecated compatibility option, ignored by the public MCP profile.
    #[arg(long, global = true, hide = true)]
    pub output_dir: Option<PathBuf>,

    /// Deprecated compatibility option. Use MCP_TOKEN or --client-token-file
    /// for privacy_workspace stdio instead.
    #[arg(long, global = true, hide = true)]
    pub bearer_env: Option<String>,

    /// Deprecated compatibility spelling for --client-token-file.
    #[arg(long, global = true, hide = true)]
    pub bearer_token_file: Option<PathBuf>,

    #[arg(long, global = true, hide = true, action = ArgAction::Append)]
    pub allowed_origin: Vec<String>,

    #[arg(long, global = true, hide = true, action = ArgAction::Append)]
    pub allowed_host: Vec<String>,

    #[arg(long, global = true, hide = true, action = ArgAction::SetTrue)]
    pub dangerously_allow_insecure_non_loopback_http: bool,

    #[arg(long, global = true)]
    pub max_body_bytes: Option<usize>,

    #[arg(long, global = true)]
    pub request_timeout_ms: Option<u64>,

    #[arg(long, global = true)]
    pub max_concurrency: Option<usize>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Serve MCP over stdin/stdout. Protocol frames are the only stdout output.
    Stdio,
    /// Serve Streamable HTTP at /mcp. This endpoint binds loopback only.
    Serve {
        #[arg(long)]
        bind: Option<SocketAddr>,
    },
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrency: usize,
    pub max_daemon_response_bytes: usize,
}

/// Digest-only token matcher for the optional public HTTP client class.
/// It never exposes token bytes in Debug or error output.
#[derive(Clone)]
pub struct BearerSecret {
    digest: [u8; 32],
}

impl fmt::Debug for BearerSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerSecret([REDACTED])")
    }
}

impl BearerSecret {
    pub fn from_token_bytes(raw: Vec<u8>) -> Result<Self, ConfigError> {
        validate_token(&raw)?;
        Ok(Self {
            digest: Sha256::digest(&raw).into(),
        })
    }

    pub fn authorizes(&self, header: &str) -> bool {
        let Some(token) = parse_bearer(header) else {
            return false;
        };
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        bool::from(self.digest.ct_eq(&digest))
    }
}

/// A token loaded from a file or MCP_TOKEN. It is only used for the lifetime
/// of a stdio process; the HTTP proxy creates a fresh backend per request.
pub struct ClientToken(Zeroizing<String>);

impl fmt::Debug for ClientToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientToken([REDACTED])")
    }
}

impl ClientToken {
    pub fn from_token_bytes(raw: Vec<u8>) -> Result<Self, ConfigError> {
        validate_token(&raw)?;
        let value = String::from_utf8(raw)
            .map_err(|_| ConfigError::Invalid("client token must be visible ASCII".to_owned()))?;
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug)]
pub struct ResolvedConfig {
    pub legal_db: PathBuf,
    pub privacy_profile: PrivacyProfile,
    pub daemon_url: Url,
    pub client_token: Option<ClientToken>,
    pub bind: SocketAddr,
    pub limits: Limits,
    pub command: Command,
}

/// Ambient-state-free configuration for an application embedding the MCP
/// HTTP router. Authentication is supplied separately through
/// `ProxyRouterConfig`, so each incoming bearer token can receive its own
/// backend instance.
#[derive(Debug, Clone)]
pub struct EmbeddedHttpConfig {
    pub legal_db: PathBuf,
    pub port: u16,
    pub max_body_bytes: usize,
    pub request_timeout_ms: u64,
    pub max_concurrency: usize,
}

impl EmbeddedHttpConfig {
    pub fn resolve(self) -> Result<ResolvedConfig, ConfigError> {
        if !self.legal_db.is_absolute() || self.legal_db.file_name().is_none() {
            return Err(ConfigError::Invalid(
                "legal database path must be absolute and name a file".to_owned(),
            ));
        }
        validate_limits(
            self.max_body_bytes,
            self.request_timeout_ms,
            self.max_concurrency,
        )?;
        Ok(ResolvedConfig {
            legal_db: self.legal_db,
            privacy_profile: PrivacyProfile::PublicLawOnly,
            daemon_url: validate_daemon_url(DEFAULT_DAEMON_URL)?,
            client_token: None,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
            limits: Limits {
                max_body_bytes: self.max_body_bytes,
                request_timeout: Duration::from_millis(self.request_timeout_ms),
                max_concurrency: self.max_concurrency,
                max_daemon_response_bytes: DEFAULT_DAEMON_RESPONSE_BYTES,
            },
            command: Command::Serve {
                bind: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port)),
            },
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration is invalid: {0}")]
    Invalid(String),
    #[error("failed to read client token file")]
    ReadToken(#[source] std::io::Error),
    #[error("failed to read compatibility configuration file")]
    ReadConfig(#[source] std::io::Error),
    #[error("compatibility configuration file is not valid TOML")]
    ParseConfig,
}

#[derive(Debug, Default, Deserialize)]
struct CompatibilityFileConfig {
    legal_db: Option<PathBuf>,
    privacy_profile: Option<PrivacyProfile>,
    daemon_url: Option<String>,
    client_token_file: Option<PathBuf>,
    bearer_token_file: Option<PathBuf>,
    bind: Option<String>,
}

impl Cli {
    pub fn resolve(self) -> Result<ResolvedConfig, ConfigError> {
        let cwd = env::current_dir().map_err(ConfigError::ReadToken)?;
        let config_path = self
            .config
            .or_else(|| env_path("LAWYER_ASSISTANCE_MCP_CONFIG"));
        let file = config_path
            .as_deref()
            .map(load_compatibility_file)
            .transpose()?;
        let config_base = config_path
            .as_deref()
            .and_then(Path::parent)
            .map(|path| absolutize(path.to_path_buf(), &cwd))
            .unwrap_or_else(|| cwd.clone());
        let legal_db = absolutize(
            self.legal_db
                .or_else(|| env_path("LEGAL_DB"))
                .or_else(|| env_path("LAWYER_ASSISTANCE_LEGAL_DB"))
                .or_else(|| file.as_ref().and_then(|file| file.legal_db.clone()))
                .unwrap_or_else(|| PathBuf::from("data/runtime/legal_core.sqlite")),
            &config_base,
        );
        if legal_db.file_name().is_none() {
            return Err(ConfigError::Invalid(
                "legal database path must name a file".to_owned(),
            ));
        }
        let privacy_profile = self
            .privacy_profile
            .or_else(|| env_parse_profile("LAWYER_ASSISTANCE_MCP_PRIVACY_PROFILE"))
            .or_else(|| file.as_ref().and_then(|file| file.privacy_profile))
            .unwrap_or_default();
        let daemon_url_setting = self
            .daemon_url
            .or_else(|| env::var("LAWYER_ASSISTANCE_DAEMON_URL").ok())
            .or_else(|| file.as_ref().and_then(|file| file.daemon_url.clone()))
            .unwrap_or_else(|| DEFAULT_DAEMON_URL.to_owned());
        let daemon_url = validate_daemon_url(&daemon_url_setting)?;
        let command_bind = match &self.command {
            Command::Stdio => None,
            Command::Serve { bind } => *bind,
        };
        let bind = command_bind
            .or_else(|| env::var("LAWYER_ASSISTANCE_MCP_BIND").ok()?.parse().ok())
            .or_else(|| {
                file.as_ref()
                    .and_then(|file| file.bind.as_deref())
                    .and_then(|bind| bind.parse().ok())
            })
            .unwrap_or_else(|| DEFAULT_BIND.parse().expect("fixed loopback bind is valid"));
        if self.dangerously_allow_insecure_non_loopback_http || !bind.ip().is_loopback() {
            return Err(ConfigError::Invalid(
                "MCP HTTP server may bind only a loopback address".to_owned(),
            ));
        }
        let max_body_bytes = self
            .max_body_bytes
            .or_else(|| env_parse("LAWYER_ASSISTANCE_MCP_MAX_BODY_BYTES"))
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);
        let request_timeout_ms = self
            .request_timeout_ms
            .or_else(|| env_parse("LAWYER_ASSISTANCE_MCP_REQUEST_TIMEOUT_MS"))
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
        let max_concurrency = self
            .max_concurrency
            .or_else(|| env_parse("LAWYER_ASSISTANCE_MCP_MAX_CONCURRENCY"))
            .unwrap_or(DEFAULT_MAX_CONCURRENCY);
        validate_limits(max_body_bytes, request_timeout_ms, max_concurrency)?;

        let token_file = self
            .client_token_file
            .or(self.bearer_token_file)
            .or_else(|| env_path("LAWYER_ASSISTANCE_MCP_CLIENT_TOKEN_FILE"))
            .or_else(|| {
                file.as_ref()
                    .and_then(|file| file.client_token_file.clone())
            })
            .or_else(|| {
                file.as_ref()
                    .and_then(|file| file.bearer_token_file.clone())
            })
            .map(|path| absolutize(path, &config_base));
        let client_token = load_client_token(token_file.as_deref())?;
        if privacy_profile == PrivacyProfile::PrivacyWorkspace
            && matches!(&self.command, Command::Stdio)
            && client_token.is_none()
        {
            return Err(ConfigError::Invalid(
                "privacy_workspace requires --client-token-file or MCP_TOKEN".to_owned(),
            ));
        }

        Ok(ResolvedConfig {
            legal_db,
            privacy_profile,
            daemon_url,
            client_token,
            bind,
            limits: Limits {
                max_body_bytes,
                request_timeout: Duration::from_millis(request_timeout_ms),
                max_concurrency,
                max_daemon_response_bytes: DEFAULT_DAEMON_RESPONSE_BYTES,
            },
            command: self.command,
        })
    }
}

fn load_compatibility_file(path: &Path) -> Result<CompatibilityFileConfig, ConfigError> {
    let bytes = fs::read(path).map_err(ConfigError::ReadConfig)?;
    if bytes.len() > 256 * 1024 {
        return Err(ConfigError::Invalid(
            "compatibility configuration file must be at most 256 KiB".to_owned(),
        ));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::ParseConfig)?;
    if text.trim_start().starts_with('{') {
        serde_json::from_str(text).map_err(|_| ConfigError::ParseConfig)
    } else {
        toml::from_str(text).map_err(|_| ConfigError::ParseConfig)
    }
}

pub fn validate_daemon_url(raw: &str) -> Result<Url, ConfigError> {
    let url =
        Url::parse(raw).map_err(|_| ConfigError::Invalid("daemon URL is invalid".to_owned()))?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ConfigError::Invalid(
            "daemon URL must be a bare loopback http origin".to_owned(),
        ));
    }
    let loopback = match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    };
    if !loopback {
        return Err(ConfigError::Invalid(
            "daemon URL must use a literal loopback IP address".to_owned(),
        ));
    }
    Ok(url)
}

fn load_client_token(file: Option<&Path>) -> Result<Option<ClientToken>, ConfigError> {
    if let Some(value) = env::var_os("MCP_TOKEN").filter(|value| !value.is_empty()) {
        return ClientToken::from_token_bytes(value.to_string_lossy().as_bytes().to_vec())
            .map(Some);
    }
    let Some(file) = file else {
        return Ok(None);
    };
    let metadata = fs::metadata(file).map_err(ConfigError::ReadToken)?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_FILE_BYTES {
        return Err(ConfigError::Invalid(
            "client token file must be a regular file no larger than 4096 bytes".to_owned(),
        ));
    }
    let mut token = fs::read(file).map_err(ConfigError::ReadToken)?;
    while token
        .last()
        .is_some_and(|byte| matches!(*byte, b'\r' | b'\n'))
    {
        token.pop();
    }
    ClientToken::from_token_bytes(token).map(Some)
}

fn validate_token(raw: &[u8]) -> Result<(), ConfigError> {
    if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&raw.len())
        || raw.iter().any(|byte| !safe_token_byte(*byte))
    {
        return Err(ConfigError::Invalid(
            "client token must contain 32 to 512 visible ASCII characters".to_owned(),
        ));
    }
    Ok(())
}

pub fn parse_bearer(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len())
        || token.bytes().any(|byte| !safe_token_byte(byte))
    {
        return None;
    }
    Some(token)
}

fn safe_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'~')
}

fn validate_limits(body: usize, timeout_ms: u64, concurrency: usize) -> Result<(), ConfigError> {
    if !(16 * 1024..=16 * 1024 * 1024).contains(&body) {
        return Err(ConfigError::Invalid(
            "max_body_bytes must be between 16384 and 16777216".to_owned(),
        ));
    }
    if !(100..=120_000).contains(&timeout_ms) {
        return Err(ConfigError::Invalid(
            "request_timeout_ms must be between 100 and 120000".to_owned(),
        ));
    }
    if !(1..=64).contains(&concurrency) {
        return Err(ConfigError::Invalid(
            "max_concurrency must be between 1 and 64".to_owned(),
        ));
    }
    Ok(())
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    env::var(name).ok()?.parse().ok()
}

fn env_parse_profile(name: &str) -> Option<PrivacyProfile> {
    env::var(name).ok()?.parse().ok()
}

fn absolutize(path: PathBuf, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_url_accepts_only_literal_loopback_http_origins() {
        assert!(validate_daemon_url("http://127.0.0.1:8877").is_ok());
        assert!(validate_daemon_url("http://[::1]:8877").is_ok());
        for invalid in [
            "https://127.0.0.1:8877",
            "http://localhost:8877",
            "http://127.0.0.1:8877/path",
            "http://example.com:8877",
            "http://127.0.0.1:8877/?q=1",
        ] {
            assert!(validate_daemon_url(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn bearer_secret_never_accepts_a_near_match() {
        let secret = BearerSecret::from_token_bytes(vec![b'x'; 32]).expect("valid token");
        assert!(secret.authorizes(&format!("Bearer {}", "x".repeat(32))));
        assert!(!secret.authorizes(&format!("Bearer {}", "y".repeat(32))));
        assert!(!secret.authorizes("Basic xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
    }

    #[test]
    fn old_public_launcher_options_are_accepted_but_do_not_select_private_storage() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let config_path = temporary.path().join("legacy.toml");
        std::fs::write(
            &config_path,
            "legal_db = \"legal.sqlite\"\nuser_db = \"private.sqlite\"\n",
        )
        .expect("compatibility config");
        let cli = Cli::try_parse_from([
            "lawyer-assistance-mcp",
            "--config",
            config_path.to_str().expect("path"),
            "--user-db",
            "another-private.sqlite",
            "--allowed-root",
            "private-cases",
            "--output-dir",
            "private-exports",
            "stdio",
        ])
        .expect("legacy launcher syntax");
        let resolved = cli.resolve().expect("public launcher resolves");
        assert_eq!(resolved.privacy_profile, PrivacyProfile::PublicLawOnly);
        assert_eq!(resolved.legal_db, temporary.path().join("legal.sqlite"));
    }

    #[test]
    fn legacy_json_config_still_supplies_the_public_legal_database() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let config_path = temporary.path().join("legacy.json");
        std::fs::write(
            &config_path,
            r#"{"legal_db":"legal.sqlite","user_db":"private.sqlite","output_root":"exports"}"#,
        )
        .expect("compatibility config");
        let cli = Cli::try_parse_from([
            "lawyer-assistance-mcp",
            "--config",
            config_path.to_str().expect("path"),
            "stdio",
        ])
        .expect("legacy JSON syntax");
        assert_eq!(
            cli.resolve().expect("public launcher resolves").legal_db,
            temporary.path().join("legal.sqlite")
        );
    }
}
