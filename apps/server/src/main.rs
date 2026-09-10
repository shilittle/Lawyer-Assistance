use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
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
    #[command(name = "document-worker", hide = true)]
    DocumentWorker,
}
#[derive(Serialize, Deserialize)]
struct Connection {
    origin: String,
    bootstrap: String,
    pid: u32,
}

#[tokio::main]
async fn main() {
    // Panic payloads may contain formatted user input or provider bodies. Keep
    // stderr useful for native diagnostics without emitting that payload.
    std::panic::set_hook(Box::new(|info| {
        if let Some(location) = info.location() {
            let file = location
                .file()
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("unknown");
            eprintln!(
                "task_panicked module={file} line={} column={}",
                location.line(),
                location.column()
            );
        } else {
            eprintln!("task_panicked");
        }
    }));
    let cli = Cli::parse();
    // The portable VBS launcher intentionally hides the console.  Keep its
    // error path visible without changing the normal CLI behavior.
    let should_show_launch_error = cli.open
        && !matches!(
            cli.command.as_ref(),
            Some(Command::Stop | Command::DocumentWorker)
        );
    if let Err(e) = run(cli).await {
        eprintln!("{}", e.code);
        if should_show_launch_error {
            show_launch_error(&e.code);
        }
        std::process::exit(1);
    }
}

fn launch_error_message(code: &str) -> String {
    match code {
        "workspace_owned_by_other_installation" => concat!(
            "检测到另一安装目录中的“律师助手”正在使用当前数据工作区。\n\n",
            "为保护资料，本程序不会停止或接管那个服务。请到旧安装目录双击 ",
            "Stop-Lawyer-Assistance.vbs 停止旧服务，然后重新启动本程序。\n\n",
            "错误代码：workspace_owned_by_other_installation"
        )
        .to_owned(),
        "port_in_use" => concat!(
            "律师助手未能启动，因为本机端口已被占用。\n\n",
            "请先关闭占用该端口的程序，或使用其他端口后重试。\n\n",
            "错误代码：port_in_use"
        )
        .to_owned(),
        _ => format!(
            "律师助手未能启动。请确认便携包已完整解压，并在关闭相关服务后重试。\n\n错误代码：{code}"
        ),
    }
}

fn browser_open_warning(origin: &str, code: &str) -> String {
    format!(
        "律师助手已经在后台启动，但未能自动打开浏览器。\n\n请手动访问：{origin}\n\n错误代码：{code}"
    )
}

fn show_launch_error(code: &str) {
    #[cfg(windows)]
    show_windows_message(&launch_error_message(code), "律师助手启动失败", true);

    #[cfg(not(windows))]
    {
        let _ = code;
    }
}

fn show_browser_open_warning(origin: &str, code: &str) {
    #[cfg(windows)]
    show_windows_message(&browser_open_warning(origin, code), "律师助手已启动", false);

    #[cfg(not(windows))]
    {
        let _ = (origin, code);
    }
}

#[cfg(windows)]
fn show_browser_open_warning_nonblocking(origin: String, code: String) {
    // Do not show a modal dialog on the server task before it begins serving
    // HTTP.  Dropping the thread handle deliberately detaches this optional
    // notification from the service lifecycle.
    let _ = std::thread::Builder::new()
        .name("lawyer-assistance-browser-warning".to_owned())
        .spawn(move || {
            show_windows_message(
                &browser_open_warning(&origin, &code),
                "律师助手已启动",
                false,
            )
        });
}

#[cfg(not(windows))]
fn show_browser_open_warning_nonblocking(_origin: String, _code: String) {}

#[cfg(windows)]
fn show_windows_message(message: &str, title: &str, error: bool) {
    use std::{ffi::OsStr, iter, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_ICONWARNING, MB_OK,
    };

    let message = OsStr::new(message)
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let title = OsStr::new(title)
        .encode_wide()
        .chain(iter::once(0))
        .collect::<Vec<_>>();
    let style = MB_OK | if error { MB_ICONERROR } else { MB_ICONWARNING };
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            style,
        );
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
    if matches!(cli.command, Some(Command::DocumentWorker)) {
        return workspace_service::run_internal_document_worker();
    }
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
    let mcp = legal_mcp::http::build_proxy_router_with_query_admission(
        workspace.legal().clone(),
        address,
        proxy,
        shutdown.clone(),
        std::sync::Arc::new(lawyer_assistance_server::WorkspaceQueryAdmission(
            workspace.clone(),
        )),
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
        let url = format!("{}#token={}", connection.origin, connection.bootstrap);
        if let Err(error) = open_browser(&url) {
            // A browser launch is a convenience.  The server and its accepted
            // background work must remain available if Windows cannot open it.
            let code = error.code;
            eprintln!("{code}");
            show_browser_open_warning_nonblocking(connection.origin.clone(), code);
        }
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
fn open_saved(root: &Path) -> Result<()> {
    let (connection, _lock) = saved_connection(root)?;
    let url = format!("{}#token={}", connection.origin, connection.bootstrap);
    if let Err(error) = open_browser(&url) {
        eprintln!("{}", error.code);
        show_browser_open_warning(&connection.origin, &error.code);
    }
    Ok(())
}
fn running_lock(root: &Path) -> Result<File> {
    let lock_path = root.join("workspace.lock");
    workspace_service::filesystem::ordinary_chain(&lock_path)?;
    let lock = OpenOptions::new().read(true).write(true).open(lock_path)?;
    if lock.try_lock().is_ok() {
        return Err(Error::new("server_not_running"));
    }
    Ok(lock)
}
fn saved_connection(root: &Path) -> Result<(Connection, File)> {
    let lock = running_lock(root)?;
    let path = root.join("connection.dpapi");
    workspace_service::filesystem::ordinary_chain(&path)?;
    let bytes = privacy::unprotect_local(&std::fs::read(path)?)
        .map_err(|_| Error::new("login_unavailable"))?;
    let connection: Connection = serde_json::from_slice(&bytes)?;
    match owner_status(connection.pid)? {
        OwnerStatus::CurrentExecutable => {}
        OwnerStatus::OtherExecutable => {
            return Err(Error::new("workspace_owned_by_other_installation"));
        }
        OwnerStatus::NotRunning => return Err(Error::new("server_not_running")),
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
async fn stop_saved(root: &Path) -> Result<()> {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerStatus {
    NotRunning,
    CurrentExecutable,
    OtherExecutable,
}

fn same_executable_path(actual: &Path, current: &Path) -> Result<bool> {
    Ok(std::fs::canonicalize(actual)? == std::fs::canonicalize(current)?)
}

fn owner_status(pid: u32) -> Result<OwnerStatus> {
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
            return Ok(OwnerStatus::NotRunning);
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process, &mut exit_code) } == 0 || exit_code != 259 {
            unsafe {
                CloseHandle(process);
            }
            return Ok(OwnerStatus::NotRunning);
        }
        let mut name = vec![0u16; 32768];
        let mut len = name.len() as u32;
        let success =
            unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut len) };
        unsafe {
            CloseHandle(process);
        }
        if success == 0 {
            return Ok(OwnerStatus::NotRunning);
        }
        let actual = PathBuf::from(std::ffi::OsString::from_wide(&name[..len as usize]));
        if same_executable_path(&actual, &std::env::current_exe()?)? {
            Ok(OwnerStatus::CurrentExecutable)
        } else {
            Ok(OwnerStatus::OtherExecutable)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
        Ok(OwnerStatus::NotRunning)
    }
}

fn owner_running(pid: u32) -> Result<bool> {
    Ok(owner_status(pid)? == OwnerStatus::CurrentExecutable)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_installation_error_explains_the_safe_recovery() {
        let message = launch_error_message("workspace_owned_by_other_installation");
        assert!(message.contains("Stop-Lawyer-Assistance.vbs"));
        assert!(message.contains("不会停止或接管"));
        assert!(message.contains("错误代码：workspace_owned_by_other_installation"));
    }

    #[test]
    fn generic_launch_errors_remain_actionable_and_include_the_code() {
        let generic = launch_error_message("local_encryption_failed");
        assert!(generic.contains("未能启动"));
        assert!(generic.contains("错误代码：local_encryption_failed"));

        let port = launch_error_message("port_in_use");
        assert!(port.contains("端口已被占用"));
        assert!(port.contains("错误代码：port_in_use"));
    }

    #[test]
    fn browser_failure_warning_keeps_a_safe_manual_url() {
        let message = browser_open_warning("http://127.0.0.1:8877", "browser_open_failed");
        assert!(message.contains("已经在后台启动"));
        assert!(message.contains("http://127.0.0.1:8877"));
        assert!(message.contains("错误代码：browser_open_failed"));
    }

    #[test]
    fn executable_comparison_requires_the_same_resolved_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let current = directory.path().join("current.exe");
        let other = directory.path().join("other.exe");
        std::fs::write(&current, b"current").expect("write current executable fixture");
        std::fs::write(&other, b"other").expect("write other executable fixture");

        assert!(same_executable_path(&current, &current).expect("compare same file"));
        assert!(!same_executable_path(&other, &current).expect("compare distinct files"));
    }
}
