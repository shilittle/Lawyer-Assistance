use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};
use workspace_service::{Error, Result, Workspace};

#[derive(Parser)]
#[command(version, about = "本地脱敏与法律检索 WebUI")]
struct Cli {
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    legal_db: Option<PathBuf>,
    #[arg(long, default_value_t = 8877, global = true)]
    port: u16,
    #[arg(long, global = true)]
    open: bool,
    #[command(subcommand)]
    command: Option<Command>,
}
#[derive(Subcommand)]
enum Command {
    Serve,
    Login,
    Stop,
}
#[derive(Serialize, Deserialize)]
struct Connection {
    origin: String,
    bootstrap: String,
    pid: u32,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run(Cli::parse()).await {
        eprintln!("{}", e.code);
        std::process::exit(1);
    }
}

fn root(cli: &Cli) -> Result<PathBuf> {
    let path = cli
        .data_dir
        .clone()
        .or_else(|| dirs::data_local_dir().map(|p| p.join("LawyerAssistanceWeb")))
        .ok_or_else(|| Error::new("data_directory_unavailable"))?;
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
fn legal_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(path) = cli
        .legal_db
        .clone()
        .or_else(|| std::env::var_os("LEGAL_DB").map(PathBuf::from))
    {
        return if path.is_absolute() {
            Ok(path)
        } else {
            Ok(std::env::current_dir()?.join(path))
        };
    }
    let exe = std::env::current_exe()?;
    let folder = exe
        .parent()
        .ok_or_else(|| Error::new("runtime_unavailable"))?;
    for candidate in [
        folder.join("data/runtime/legal_core.sqlite"),
        std::env::current_dir()?.join("data/runtime/legal_core.sqlite"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Ok(folder.join("data/runtime/legal_core.sqlite"))
}
async fn run(cli: Cli) -> Result<()> {
    let root = root(&cli)?;
    if matches!(cli.command, Some(Command::Login)) {
        return open_saved(&root);
    }
    if matches!(cli.command, Some(Command::Stop)) {
        return stop_saved(&root).await;
    }
    let workspace = match Workspace::open(root.clone(), legal_path(&cli)?) {
        Ok(w) => w,
        Err(e) if e.code == "workspace_in_use" && cli.open => return open_saved(&root),
        Err(e) => return Err(e),
    };
    let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, cli.port)))
        .await
        .map_err(|_| Error::new("port_in_use"))?;
    let address = listener.local_addr()?;
    let origin = format!("http://{address}");
    let bootstrap = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let connection = Connection {
        origin: origin.clone(),
        bootstrap: bootstrap.clone(),
        pid: std::process::id(),
    };
    let path = root.join("connection.dpapi");
    if path.exists() {
        workspace_service::filesystem::ordinary_chain(&path)?;
    }
    let body = serde_json::to_vec(&connection)?;
    let sealed =
        privacy::protect_local(&body).map_err(|_| Error::new("local_encryption_failed"))?;
    std::fs::write(&path, sealed)?;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let proxy = legal_mcp::http::ProxyRouterConfig::new(
        url::Url::parse(&origin).map_err(|_| Error::new("invalid_origin"))?,
        legal_mcp::config::Limits {
            max_body_bytes: 2 * 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            max_concurrency: 8,
            max_daemon_response_bytes: 2 * 1024 * 1024,
        },
    );
    let mcp = legal_mcp::http::build_proxy_router(
        workspace.legal().clone(),
        address,
        proxy,
        shutdown.clone(),
    )
    .map_err(|_| Error::new("mcp_configuration_invalid"))?;
    let app = lawyer_assistance_server::router(lawyer_assistance_server::AppState::with_shutdown(
        workspace.clone(),
        origin.clone(),
        bootstrap,
        shutdown.clone(),
    ))
    .merge(mcp);
    let worker = workspace.start_worker();
    eprintln!("Lawyer Assistance listening at {origin}");
    if cli.open {
        open_browser(&format!(
            "{}#token={}",
            connection.origin, connection.bootstrap
        ))?;
    }
    let signal = shutdown.clone();
    let result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => signal.cancel(),
                _ = signal.cancelled() => {}
            }
        })
        .await;
    worker.abort();
    let _ = worker.await;
    shutdown.cancel();
    result.map_err(|_| Error::new("server_failed"))
}
fn open_saved(root: &std::path::Path) -> Result<()> {
    let (connection, _lock) = saved_connection(root)?;
    open_browser(&format!(
        "{}#token={}",
        connection.origin, connection.bootstrap
    ))
}
fn running_lock(root: &std::path::Path) -> Result<File> {
    let lock_path = root.join("workspace.lock");
    workspace_service::filesystem::ordinary_chain(&lock_path)?;
    let lock = OpenOptions::new().read(true).write(true).open(lock_path)?;
    if lock.try_lock().is_ok() {
        return Err(Error::new("server_not_running"));
    }
    Ok(lock)
}
fn saved_connection(root: &std::path::Path) -> Result<(Connection, File)> {
    let lock = running_lock(root)?;
    let path = root.join("connection.dpapi");
    workspace_service::filesystem::ordinary_chain(&path)?;
    let bytes = privacy::unprotect_local(&std::fs::read(path)?)
        .map_err(|_| Error::new("login_unavailable"))?;
    let connection: Connection = serde_json::from_slice(&bytes)?;
    if !owner_running(connection.pid)? {
        return Err(Error::new("server_not_running"));
    }
    validate_origin(&connection.origin)?;
    Ok((connection, lock))
}
fn validate_origin(origin: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(origin).map_err(|_| Error::new("login_unavailable"))?;
    if parsed.scheme() != "http"
        || parsed.host_str() != Some("127.0.0.1")
        || parsed.port().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(Error::new("login_unavailable"));
    }
    Ok(parsed)
}
#[derive(Deserialize)]
struct LoginResponse {
    csrf_token: String,
}
fn session_cookie(headers: &reqwest::header::HeaderMap) -> Result<String> {
    for value in headers.get_all(reqwest::header::SET_COOKIE).iter() {
        let Ok(value) = value.to_str() else {
            continue;
        };
        if let Some(cookie) = value
            .split(';')
            .next()
            .filter(|value| value.starts_with("la_session="))
        {
            return Ok(cookie.to_owned());
        }
    }
    Err(Error::new("shutdown_unavailable"))
}
async fn stop_saved(root: &std::path::Path) -> Result<()> {
    let (connection, _lock) = saved_connection(root)?;
    let origin = validate_origin(&connection.origin)?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|_| Error::new("shutdown_unavailable"))?;
    let session = client
        .post(
            origin
                .join("api/v1/session")
                .map_err(|_| Error::new("shutdown_unavailable"))?,
        )
        .header(reqwest::header::ORIGIN, connection.origin.as_str())
        .json(&serde_json::json!({"token": connection.bootstrap}))
        .send()
        .await
        .map_err(|_| Error::new("shutdown_unavailable"))?;
    if !session.status().is_success() {
        return Err(Error::new("shutdown_unavailable"));
    }
    let cookie = session_cookie(session.headers())?;
    let login: LoginResponse = session
        .json()
        .await
        .map_err(|_| Error::new("shutdown_unavailable"))?;
    if login.csrf_token.is_empty() {
        return Err(Error::new("shutdown_unavailable"));
    }
    let response = client
        .post(
            origin
                .join("api/v1/shutdown")
                .map_err(|_| Error::new("shutdown_unavailable"))?,
        )
        .header(reqwest::header::ORIGIN, connection.origin.as_str())
        .header(reqwest::header::COOKIE, cookie)
        .header("x-csrf-token", login.csrf_token)
        .send()
        .await
        .map_err(|_| Error::new("shutdown_unavailable"))?;
    if !response.status().is_success() {
        return Err(Error::new("shutdown_unavailable"));
    }
    for _ in 0..50 {
        if !owner_running(connection.pid)? {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(Error::new("shutdown_timeout"))
}
fn owner_running(pid: u32) -> Result<bool> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{
                GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
        };
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Ok(false);
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process, &mut exit_code) } == 0 || exit_code != 259 {
            unsafe {
                CloseHandle(process);
            }
            return Ok(false);
        }
        let mut name = vec![0u16; 32768];
        let mut len = name.len() as u32;
        let success =
            unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut len) };
        unsafe {
            CloseHandle(process);
        }
        if success == 0 {
            return Ok(false);
        }
        let actual = PathBuf::from(std::ffi::OsString::from_wide(&name[..len as usize]));
        Ok(std::fs::canonicalize(actual)? == std::fs::canonicalize(std::env::current_exe()?)?)
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Ok(false)
    }
}
fn open_browser(url: &str) -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|_| Error::new("browser_open_failed"))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = url;
        Err(Error::new("windows_required"))
    }
}
