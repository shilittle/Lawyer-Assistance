use crate::registry::PrivacyProfile;
use clap::{ArgAction, Parser, Subcommand};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fmt, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

pub const DEFAULT_BIND: &str = "127.0.0.1:8787";
pub const DEFAULT_BEARER_ENV: &str = "LAWYER_ASSISTANCE_MCP_TOKEN";
pub const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_MAX_CONCURRENCY: usize = 8;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_TOKEN_FILE_BYTES: u64 = 4096;
const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 512;
const MAX_ALLOWLIST_ENTRIES: usize = 64;

#[derive(Debug, Parser)]
#[command(
    name = "lawyer-assistance-mcp",
    version,
    about = "Local-first MCP server for Lawyer Assistance"
)]
pub struct Cli {
    /// Optional TOML or JSON configuration file.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[arg(long, global = true)]
    pub legal_db: Option<PathBuf>,

    #[arg(long, global = true)]
    pub user_db: Option<PathBuf>,

    #[arg(long, global = true, action = ArgAction::Append)]
    pub allowed_root: Vec<PathBuf>,

    #[arg(long, global = true)]
    pub output_dir: Option<PathBuf>,

    /// MCP data-exposure profile. Defaults to public_law_only; redacted_case is explicit.
    #[arg(long, global = true, value_enum)]
    pub privacy_profile: Option<PrivacyProfile>,

    /// Name of the environment variable containing the bearer token.
    #[arg(long, global = true)]
    pub bearer_env: Option<String>,

    /// Read the bearer token from this file if the selected environment variable is unset.
    #[arg(long, global = true)]
    pub bearer_token_file: Option<PathBuf>,

    #[arg(long, global = true, action = ArgAction::Append)]
    pub allowed_origin: Vec<String>,

    #[arg(long, global = true, action = ArgAction::Append)]
    pub allowed_host: Vec<String>,

    #[arg(long, global = true)]
    pub max_body_bytes: Option<usize>,

    #[arg(long, global = true)]
    pub request_timeout_ms: Option<u64>,

    #[arg(long, global = true)]
    pub max_concurrency: Option<usize>,

    /// DANGEROUS: allow this cleartext HTTP server to bind to a non-loopback address.
    /// A bearer token is still required. Prefer a loopback bind behind a TLS reverse proxy.
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub dangerously_allow_insecure_non_loopback_http: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Serve MCP over stdin/stdout. Protocol output is the only stdout output.
    Stdio,
    /// Serve stateless Streamable HTTP at /mcp.
    Serve {
        #[arg(long)]
        bind: Option<SocketAddr>,
    },
    /// Explicitly create or migrate the configured user database, then exit.
    InitUserDb,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrency: usize,
}

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
        Self::new(Zeroizing::new(raw))
    }

    pub(crate) fn new(raw: Zeroizing<Vec<u8>>) -> Result<Self, ConfigError> {
        if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&raw.len()) {
            return Err(ConfigError::Invalid(
                "bearer token must contain 32 to 512 bytes".to_owned(),
            ));
        }
        if raw.iter().any(|byte| !(0x21..=0x7e).contains(byte)) {
            return Err(ConfigError::Invalid(
                "bearer token must contain only visible ASCII characters".to_owned(),
            ));
        }
        let digest: [u8; 32] = Sha256::digest(raw.as_slice()).into();
        Ok(Self { digest })
    }

    pub fn authorizes(&self, header: &str) -> bool {
        if header.len() > MAX_TOKEN_BYTES + 16 {
            return false;
        }
        let Some((scheme, candidate)) = header.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("bearer")
            || candidate.is_empty()
            || candidate.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return false;
        }
        let candidate_digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        bool::from(self.digest.ct_eq(&candidate_digest))
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub legal_db: PathBuf,
    pub user_db: PathBuf,
    pub allowed_roots: Vec<PathBuf>,
    pub output_root: PathBuf,
    pub privacy_profile: PrivacyProfile,
    pub bind: SocketAddr,
    pub allowed_origins: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub bearer: Option<BearerSecret>,
    pub dangerously_allow_insecure_non_loopback_http: bool,
    pub limits: Limits,
    pub command: Command,
}

impl ResolvedConfig {
    pub fn is_http(&self) -> bool {
        matches!(self.command, Command::Serve { .. })
    }

    pub fn bind_is_loopback(&self) -> bool {
        self.bind.ip().is_loopback()
    }
}

/// Complete, environment-independent configuration for an HTTP server embedded
/// in another Rust application.
///
/// Unlike [`Cli::resolve`], this boundary never reads process arguments,
/// environment variables, a configuration file, or the current working
/// directory. The caller must provide absolute filesystem paths. Embedded
/// servers are deliberately restricted to IPv4 loopback and cannot enable the
/// standalone server's dangerous non-loopback cleartext opt-in.
#[derive(Debug, Clone)]
pub struct EmbeddedHttpConfig {
    pub legal_db: PathBuf,
    pub user_db: PathBuf,
    pub allowed_roots: Vec<PathBuf>,
    pub output_root: PathBuf,
    pub port: u16,
    pub allowed_origins: Vec<String>,
    pub bearer: Option<BearerSecret>,
    pub max_body_bytes: usize,
    pub request_timeout_ms: u64,
    pub max_concurrency: usize,
}

impl EmbeddedHttpConfig {
    /// Validate and resolve an embedded server configuration without consulting
    /// any ambient process state.
    pub fn resolve(self) -> Result<ResolvedConfig, ConfigError> {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port);
        let allowed_origins = normalize_origins(self.allowed_origins)?;
        let allowed_hosts = default_allowed_hosts(bind);
        validate_limits(
            self.max_body_bytes,
            self.request_timeout_ms,
            self.max_concurrency,
        )?;

        let resolved = ResolvedConfig {
            legal_db: self.legal_db,
            user_db: self.user_db,
            allowed_roots: self.allowed_roots,
            output_root: self.output_root,
            privacy_profile: PrivacyProfile::default(),
            bind,
            allowed_origins,
            allowed_hosts,
            bearer: self.bearer,
            dangerously_allow_insecure_non_loopback_http: false,
            limits: Limits {
                max_body_bytes: self.max_body_bytes,
                request_timeout: Duration::from_millis(self.request_timeout_ms),
                max_concurrency: self.max_concurrency,
            },
            command: Command::Serve { bind: Some(bind) },
        };
        validate_runtime_paths(&resolved)?;
        validate_http_auth_requirement(true, resolved.bind, resolved.bearer.as_ref(), false)?;
        Ok(resolved)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration is invalid: {0}")]
    Invalid(String),
    #[error("failed to read configuration file")]
    ReadConfig(#[source] std::io::Error),
    #[error("configuration file is not valid TOML or JSON")]
    ParseConfig,
    #[error("failed to read bearer token file")]
    ReadToken(#[source] std::io::Error),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    legal_db: Option<PathBuf>,
    user_db: Option<PathBuf>,
    #[serde(default)]
    allowed_roots: Vec<PathBuf>,
    output_root: Option<PathBuf>,
    privacy_profile: Option<PrivacyProfile>,
    bind: Option<String>,
    bearer_env: Option<String>,
    bearer_token_file: Option<PathBuf>,
    #[serde(default)]
    allowed_origins: Vec<String>,
    #[serde(default)]
    allowed_hosts: Vec<String>,
    #[serde(default)]
    dangerously_allow_insecure_non_loopback_http: bool,
    limits: Option<FileLimits>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileLimits {
    max_body_bytes: Option<usize>,
    request_timeout_ms: Option<u64>,
    max_concurrency: Option<usize>,
}

impl Cli {
    pub fn resolve(self) -> Result<ResolvedConfig, ConfigError> {
        let config_path = self
            .config
            .clone()
            .or_else(|| env_path("LAWYER_ASSISTANCE_MCP_CONFIG"));
        let mut file = match config_path.as_deref() {
            Some(path) => load_file_config(path)?,
            None => FileConfig::default(),
        };
        if let Some(path) = config_path.as_deref() {
            resolve_file_relative_paths(&mut file, path)?;
        }

        let cwd = env::current_dir().map_err(ConfigError::ReadConfig)?;
        let legal_db = absolutize(
            self.legal_db
                .or_else(|| env_path("LAWYER_ASSISTANCE_LEGAL_DB"))
                .or(file.legal_db)
                .ok_or_else(|| ConfigError::Invalid("legal database path is required".into()))?,
            &cwd,
        );
        let user_db = absolutize(
            self.user_db
                .or_else(|| env_path("LAWYER_ASSISTANCE_USER_DB"))
                .or(file.user_db)
                .ok_or_else(|| ConfigError::Invalid("user database path is required".into()))?,
            &cwd,
        );
        let output_root = absolutize(
            self.output_dir
                .or_else(|| env_path("LAWYER_ASSISTANCE_OUTPUT_ROOT"))
                .or(file.output_root)
                .ok_or_else(|| ConfigError::Invalid("output root is required".into()))?,
            &cwd,
        );

        let privacy_profile = self
            .privacy_profile
            .or(env_parse("LAWYER_ASSISTANCE_MCP_PRIVACY_PROFILE")?)
            .or(file.privacy_profile)
            .unwrap_or_default();
        let allowed_roots = choose_paths(
            self.allowed_root,
            env::var_os("LAWYER_ASSISTANCE_ALLOWED_ROOTS")
                .map(|value| env::split_paths(&value).collect()),
            file.allowed_roots,
        )
        .into_iter()
        .map(|path| absolutize(path, &cwd))
        .collect::<Vec<_>>();

        let command_bind = match &self.command {
            Command::Serve { bind } => *bind,
            Command::Stdio | Command::InitUserDb => None,
        };
        let environment_bind: Option<SocketAddr> = env_parse("LAWYER_ASSISTANCE_MCP_BIND")?;
        let file_bind = file
            .bind
            .as_deref()
            .map(|value| {
                value
                    .parse::<SocketAddr>()
                    .map_err(|_| ConfigError::Invalid("bind address is invalid".into()))
            })
            .transpose()?;
        let bind = command_bind
            .or(environment_bind)
            .or(file_bind)
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8787));

        let allowed_origins = normalize_origins(choose_strings(
            self.allowed_origin,
            env_csv("LAWYER_ASSISTANCE_MCP_ALLOWED_ORIGINS"),
            file.allowed_origins,
        ))?;
        let mut allowed_hosts = normalize_hosts(choose_strings(
            self.allowed_host,
            env_csv("LAWYER_ASSISTANCE_MCP_ALLOWED_HOSTS"),
            file.allowed_hosts,
        ))?;
        if allowed_hosts.is_empty() {
            allowed_hosts = default_allowed_hosts(bind);
        }

        let file_limits = file.limits.unwrap_or_default();
        let max_body_bytes = self
            .max_body_bytes
            .or(env_parse("LAWYER_ASSISTANCE_MCP_MAX_BODY_BYTES")?)
            .or(file_limits.max_body_bytes)
            .unwrap_or(DEFAULT_MAX_BODY_BYTES);
        let request_timeout_ms = self
            .request_timeout_ms
            .or(env_parse("LAWYER_ASSISTANCE_MCP_REQUEST_TIMEOUT_MS")?)
            .or(file_limits.request_timeout_ms)
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
        let max_concurrency = self
            .max_concurrency
            .or(env_parse("LAWYER_ASSISTANCE_MCP_MAX_CONCURRENCY")?)
            .or(file_limits.max_concurrency)
            .unwrap_or(DEFAULT_MAX_CONCURRENCY);
        validate_limits(max_body_bytes, request_timeout_ms, max_concurrency)?;

        let bearer_env = self
            .bearer_env
            .or_else(|| env::var("LAWYER_ASSISTANCE_MCP_BEARER_ENV").ok())
            .or(file.bearer_env)
            .unwrap_or_else(|| DEFAULT_BEARER_ENV.to_owned());
        validate_env_name(&bearer_env)?;
        let token_file = self
            .bearer_token_file
            .or_else(|| env_path("LAWYER_ASSISTANCE_MCP_TOKEN_FILE"))
            .or(file.bearer_token_file)
            .map(|path| absolutize(path, &cwd));
        let bearer = load_bearer(&bearer_env, token_file.as_deref())?;
        let dangerously_allow_insecure_non_loopback_http = self
            .dangerously_allow_insecure_non_loopback_http
            || env_parse::<bool>(
                "LAWYER_ASSISTANCE_MCP_DANGEROUSLY_ALLOW_INSECURE_NON_LOOPBACK_HTTP",
            )?
            .unwrap_or(false)
            || file.dangerously_allow_insecure_non_loopback_http;

        let resolved = ResolvedConfig {
            legal_db,
            user_db,
            allowed_roots,
            output_root,
            privacy_profile,
            bind,
            allowed_origins,
            allowed_hosts,
            bearer,
            dangerously_allow_insecure_non_loopback_http,
            limits: Limits {
                max_body_bytes,
                request_timeout: Duration::from_millis(request_timeout_ms),
                max_concurrency,
            },
            command: self.command,
        };
        validate_runtime_paths(&resolved)?;
        validate_http_auth_requirement(
            resolved.is_http(),
            resolved.bind,
            resolved.bearer.as_ref(),
            resolved.dangerously_allow_insecure_non_loopback_http,
        )?;
        Ok(resolved)
    }

    pub fn resolve_user_db_only(self) -> Result<PathBuf, ConfigError> {
        let config_path = self
            .config
            .clone()
            .or_else(|| env_path("LAWYER_ASSISTANCE_MCP_CONFIG"));
        let mut file = match config_path.as_deref() {
            Some(path) => load_file_config(path)?,
            None => FileConfig::default(),
        };
        if let Some(path) = config_path.as_deref() {
            resolve_file_relative_paths(&mut file, path)?;
        }
        let cwd = env::current_dir().map_err(ConfigError::ReadConfig)?;
        Ok(absolutize(
            self.user_db
                .or_else(|| env_path("LAWYER_ASSISTANCE_USER_DB"))
                .or(file.user_db)
                .ok_or_else(|| ConfigError::Invalid("user database path is required".into()))?,
            &cwd,
        ))
    }
}

fn load_file_config(path: &Path) -> Result<FileConfig, ConfigError> {
    let metadata = fs::metadata(path).map_err(ConfigError::ReadConfig)?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid(
            "configuration file must be a regular file no larger than 256 KiB".into(),
        ));
    }
    let bytes = fs::read(path).map_err(ConfigError::ReadConfig)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::ParseConfig)?;
    if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
    {
        serde_json::from_str(text).map_err(|_| ConfigError::ParseConfig)
    } else {
        toml::from_str(text).map_err(|_| ConfigError::ParseConfig)
    }
}

fn resolve_file_relative_paths(
    file: &mut FileConfig,
    config_path: &Path,
) -> Result<(), ConfigError> {
    let absolute_config = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(ConfigError::ReadConfig)?
            .join(config_path)
    };
    let base = absolute_config.parent().ok_or_else(|| {
        ConfigError::Invalid("configuration file path has no parent directory".into())
    })?;
    for path in [&mut file.legal_db, &mut file.user_db, &mut file.output_root] {
        if let Some(value) = path.take() {
            *path = Some(absolutize(value, base));
        }
    }
    if let Some(value) = file.bearer_token_file.take() {
        file.bearer_token_file = Some(absolutize(value, base));
    }
    file.allowed_roots = file
        .allowed_roots
        .drain(..)
        .map(|value| absolutize(value, base))
        .collect();
    Ok(())
}

fn validate_runtime_paths(config: &ResolvedConfig) -> Result<(), ConfigError> {
    if !config.legal_db.is_absolute()
        || !config.user_db.is_absolute()
        || !config.output_root.is_absolute()
        || config.allowed_roots.iter().any(|path| !path.is_absolute())
    {
        return Err(ConfigError::Invalid(
            "database, allowed root, and output paths must be absolute".into(),
        ));
    }
    if config.legal_db.file_name().is_none() {
        return Err(ConfigError::Invalid(
            "legal database path must name a file".into(),
        ));
    }
    if config.user_db.file_name().is_none() {
        return Err(ConfigError::Invalid(
            "user database path must name a file".into(),
        ));
    }
    if config.allowed_roots.len() > MAX_ALLOWLIST_ENTRIES {
        return Err(ConfigError::Invalid(
            "allowed roots contains too many entries".into(),
        ));
    }
    Ok(())
}

fn validate_limits(body: usize, timeout_ms: u64, concurrency: usize) -> Result<(), ConfigError> {
    if !(16 * 1024..=16 * 1024 * 1024).contains(&body) {
        return Err(ConfigError::Invalid(
            "max_body_bytes must be between 16384 and 16777216".into(),
        ));
    }
    if !(100..=120_000).contains(&timeout_ms) {
        return Err(ConfigError::Invalid(
            "request_timeout_ms must be between 100 and 120000".into(),
        ));
    }
    if !(1..=64).contains(&concurrency) {
        return Err(ConfigError::Invalid(
            "max_concurrency must be between 1 and 64".into(),
        ));
    }
    Ok(())
}

fn validate_http_auth_requirement(
    is_http: bool,
    bind: SocketAddr,
    bearer: Option<&BearerSecret>,
    dangerously_allow_insecure_non_loopback_http: bool,
) -> Result<(), ConfigError> {
    if !is_http || bind.ip().is_loopback() {
        return Ok(());
    }
    if !dangerously_allow_insecure_non_loopback_http {
        return Err(ConfigError::Invalid(
            "cleartext HTTP binding to a non-loopback address is disabled; bind to loopback behind a TLS reverse proxy, or explicitly opt in with --dangerously-allow-insecure-non-loopback-http only on a trusted network"
                .to_owned(),
        ));
    }
    if bearer.is_none() {
        return Err(ConfigError::Invalid(
            "insecure non-loopback HTTP opt-in also requires bearer authentication".to_owned(),
        ));
    }
    Ok(())
}

fn load_bearer(
    env_name: &str,
    token_file: Option<&Path>,
) -> Result<Option<BearerSecret>, ConfigError> {
    if let Some(value) = env::var_os(env_name) {
        let text = value.into_string().map_err(|_| {
            ConfigError::Invalid("bearer token environment variable is not valid UTF-8".into())
        })?;
        return BearerSecret::new(Zeroizing::new(text.into_bytes())).map(Some);
    }
    let Some(path) = token_file else {
        return Ok(None);
    };
    let link_metadata = fs::symlink_metadata(path).map_err(ConfigError::ReadToken)?;
    if link_metadata.file_type().is_symlink()
        || !link_metadata.is_file()
        || link_metadata.len() > MAX_TOKEN_FILE_BYTES
    {
        return Err(ConfigError::Invalid(
            "bearer token file must be a non-symlink regular file no larger than 4096 bytes".into(),
        ));
    }
    let mut bytes = Zeroizing::new(fs::read(path).map_err(ConfigError::ReadToken)?);
    while matches!(bytes.last(), Some(b'\r' | b'\n')) {
        bytes.pop();
    }
    BearerSecret::new(bytes).map(Some)
}

fn validate_env_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
    {
        return Err(ConfigError::Invalid(
            "bearer environment variable name is invalid".into(),
        ));
    }
    Ok(())
}

fn normalize_origins(values: Vec<String>) -> Result<Vec<String>, ConfigError> {
    if values.len() > MAX_ALLOWLIST_ENTRIES {
        return Err(ConfigError::Invalid(
            "allowed origins contains too many entries".into(),
        ));
    }
    let mut normalized = Vec::with_capacity(values.len());
    for raw in values {
        let parsed = Url::parse(raw.trim())
            .map_err(|_| ConfigError::Invalid("allowed origin is not a valid URL origin".into()))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(ConfigError::Invalid(
                "allowed origin must contain only an http(s) scheme, host, and optional port"
                    .into(),
            ));
        }
        let origin = parsed.origin().ascii_serialization().to_ascii_lowercase();
        if !normalized.contains(&origin) {
            normalized.push(origin);
        }
    }
    Ok(normalized)
}

fn normalize_hosts(values: Vec<String>) -> Result<Vec<String>, ConfigError> {
    if values.len() > MAX_ALLOWLIST_ENTRIES {
        return Err(ConfigError::Invalid(
            "allowed hosts contains too many entries".into(),
        ));
    }
    let mut normalized = Vec::with_capacity(values.len());
    for raw in values {
        let host = raw.trim().to_ascii_lowercase();
        if host.is_empty()
            || host.len() > 255
            || host.contains('/')
            || host.contains('\\')
            || host.contains('@')
            || host.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ConfigError::Invalid("allowed host is invalid".into()));
        }
        if !normalized.contains(&host) {
            normalized.push(host);
        }
    }
    Ok(normalized)
}

fn default_allowed_hosts(bind: SocketAddr) -> Vec<String> {
    let mut hosts = vec![bind.to_string().to_ascii_lowercase()];
    if bind.ip().is_loopback() {
        hosts.push(format!("localhost:{}", bind.port()));
        match bind.ip() {
            IpAddr::V4(_) => hosts.push(format!("127.0.0.1:{}", bind.port())),
            IpAddr::V6(_) => hosts.push(format!("[::1]:{}", bind.port())),
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

fn choose_paths(
    cli: Vec<PathBuf>,
    environment: Option<Vec<PathBuf>>,
    file: Vec<PathBuf>,
) -> Vec<PathBuf> {
    if !cli.is_empty() {
        cli
    } else if let Some(environment) = environment.filter(|values| !values.is_empty()) {
        environment
    } else {
        file
    }
}

fn choose_strings(
    cli: Vec<String>,
    environment: Option<Vec<String>>,
    file: Vec<String>,
) -> Vec<String> {
    if !cli.is_empty() {
        cli
    } else if let Some(environment) = environment.filter(|values| !values.is_empty()) {
        environment
    } else {
        file
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn env_csv(name: &str) -> Option<Vec<String>> {
    env::var(name).ok().map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
}

fn env_parse<T>(name: &str) -> Result<Option<T>, ConfigError>
where
    T: FromStr,
{
    env::var(name)
        .ok()
        .map(|value| {
            value.parse().map_err(|_| {
                ConfigError::Invalid(format!("environment variable {name} has an invalid value"))
            })
        })
        .transpose()
}

fn absolutize(path: PathBuf, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

pub fn normalize_request_origin(raw: &str) -> Option<String> {
    let parsed = Url::parse(raw).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization().to_ascii_lowercase())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn embedded_config() -> EmbeddedHttpConfig {
        #[cfg(windows)]
        let root = PathBuf::from(r"C:\lawyer-assistance-embedded-config-test");
        #[cfg(not(windows))]
        let root = PathBuf::from("/tmp/lawyer-assistance-embedded-config-test");
        EmbeddedHttpConfig {
            legal_db: root.join("legal_core.sqlite"),
            user_db: root.join("user.sqlite"),
            allowed_roots: vec![root.join("materials")],
            output_root: root.join("exports"),
            port: 9876,
            allowed_origins: vec!["HTTPS://CLIENT.EXAMPLE:443".to_owned()],
            bearer: Some(BearerSecret::new(Zeroizing::new(vec![b'x'; 32])).expect("valid token")),
            max_body_bytes: 64 * 1024,
            request_timeout_ms: 4_000,
            max_concurrency: 3,
        }
    }

    #[test]
    fn bearer_comparison_accepts_only_exact_token() {
        let secret = BearerSecret::new(Zeroizing::new(vec![b'x'; 32])).expect("valid token");
        assert!(secret.authorizes(&format!("Bearer {}", "x".repeat(32))));
        assert!(secret.authorizes(&format!("bearer {}", "x".repeat(32))));
        assert!(!secret.authorizes(&format!("Bearer {}", "y".repeat(32))));
        assert!(!secret.authorizes(&format!("Basic {}", "x".repeat(32))));
    }

    #[test]
    fn origins_are_canonical_and_pathless() {
        assert_eq!(
            normalize_origins(vec!["HTTPS://EXAMPLE.COM:443".into()]).expect("valid origin"),
            vec!["https://example.com"]
        );
        assert!(normalize_origins(vec!["https://example.com/path".into()]).is_err());
        assert!(normalize_request_origin("null").is_none());
    }

    #[test]
    fn non_loopback_plain_http_requires_explicit_dangerous_opt_in_and_auth() {
        let bind = "0.0.0.0:8787".parse::<SocketAddr>().expect("valid bind");
        let token = BearerSecret::new(Zeroizing::new(vec![b'x'; 32])).expect("valid token");
        assert!(validate_http_auth_requirement(true, bind, None, false).is_err());
        assert!(validate_http_auth_requirement(true, bind, Some(&token), false).is_err());
        assert!(validate_http_auth_requirement(true, bind, None, true).is_err());
        assert!(validate_http_auth_requirement(true, bind, Some(&token), true).is_ok());
        assert!(validate_http_auth_requirement(false, bind, None, false).is_ok());
        assert!(validate_http_auth_requirement(
            true,
            "127.0.0.1:8787".parse().unwrap(),
            None,
            false
        )
        .is_ok());
    }

    #[test]
    fn insecure_non_loopback_opt_in_is_explicit_in_cli_and_file_config() {
        let cli = Cli::try_parse_from([
            "lawyer-assistance-mcp",
            "--dangerously-allow-insecure-non-loopback-http",
            "stdio",
        ])
        .unwrap();
        assert!(cli.dangerously_allow_insecure_non_loopback_http);

        let file: FileConfig =
            toml::from_str("dangerously_allow_insecure_non_loopback_http = true\n").unwrap();
        assert!(file.dangerously_allow_insecure_non_loopback_http);
    }

    #[test]
    fn embedded_http_configuration_is_loopback_only_and_ambient_state_independent() {
        let expected = embedded_config();
        let resolved = expected
            .clone()
            .resolve()
            .expect("embedded config resolves");

        assert_eq!(resolved.legal_db, expected.legal_db);
        assert_eq!(resolved.user_db, expected.user_db);
        assert_eq!(resolved.allowed_roots, expected.allowed_roots);
        assert_eq!(resolved.output_root, expected.output_root);
        assert_eq!(resolved.bind, "127.0.0.1:9876".parse().unwrap());
        assert_eq!(
            resolved.allowed_origins,
            vec!["https://client.example".to_owned()]
        );
        assert_eq!(
            resolved.allowed_hosts,
            vec!["127.0.0.1:9876".to_owned(), "localhost:9876".to_owned()]
        );
        assert!(resolved.bearer.is_some());
        assert!(!resolved.dangerously_allow_insecure_non_loopback_http);
        assert_eq!(resolved.limits.max_body_bytes, 64 * 1024);
        assert_eq!(resolved.limits.request_timeout, Duration::from_secs(4));
        assert_eq!(resolved.limits.max_concurrency, 3);
        assert!(matches!(
            resolved.command,
            Command::Serve { bind: Some(bind) } if bind == resolved.bind
        ));
    }

    #[test]
    fn embedded_http_configuration_reuses_origin_limit_and_path_validation() {
        let mut invalid_origin = embedded_config();
        invalid_origin.allowed_origins = vec!["https://client.example/path".to_owned()];
        assert!(invalid_origin.resolve().is_err());

        let mut invalid_limits = embedded_config();
        invalid_limits.max_concurrency = 0;
        assert!(invalid_limits.resolve().is_err());

        let mut relative_path = embedded_config();
        relative_path.legal_db = PathBuf::from("legal_core.sqlite");
        assert!(relative_path.resolve().is_err());
    }
}
