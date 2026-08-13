use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};
use tauri::{Manager, Runtime, WebviewWindowBuilder};
use uuid::Uuid;

const RUN_ID_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_RUN_ID";
const APP_IDENTIFIER_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_APP_IDENTIFIER";
const APP_ROOT_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_APP_ROOT";
const CREDENTIAL_PREFIX_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_CREDENTIAL_PREFIX";
const CDP_PORT_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_CDP_PORT";
const WINDOW_CLASS_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_WINDOW_CLASS";
const APP_IDENTIFIER_PREFIX: &str = "com.shilittle.lawyer-assistance.r3-";
const CREDENTIAL_PREFIX: &str = "LawyerAssistanceV031RestartTest-";
const WINDOW_CLASS_PREFIX: &str = "LawyerAssistanceR3V040";

#[derive(Debug)]
struct HarnessConfiguration {
    app_identifier: String,
    app_root: PathBuf,
    credential_prefix: String,
    cdp_port: u16,
    window_class: String,
}

static CONFIGURATION: OnceLock<HarnessConfiguration> = OnceLock::new();

fn environment_text(name: &str) -> Result<String, std::io::Error> {
    std::env::var(name)
        .map_err(|_| std::io::Error::other(format!("missing R3 harness environment {name}")))
}

fn canonical_uuid(value: &str) -> Result<Uuid, std::io::Error> {
    let parsed = Uuid::parse_str(value)
        .map_err(|_| std::io::Error::other("R3 current harness run id is not a UUID"))?;
    if parsed.hyphenated().to_string() != value {
        return Err(std::io::Error::other(
            "R3 current harness run id is not canonical lowercase hyphenated UUID",
        ));
    }
    Ok(parsed)
}

pub(crate) fn initialize(config_identifier: &str) -> Result<(), std::io::Error> {
    if CONFIGURATION.get().is_some() {
        return Err(std::io::Error::other(
            "R3 current harness configuration initialized twice",
        ));
    }
    let run_id_text = environment_text(RUN_ID_ENV)?;
    let run_id = canonical_uuid(&run_id_text)?;
    let simple_run_id = run_id.simple().to_string();
    let app_identifier = environment_text(APP_IDENTIFIER_ENV)?;
    let identifier_suffix = app_identifier
        .strip_prefix(APP_IDENTIFIER_PREFIX)
        .ok_or_else(|| std::io::Error::other("R3 current harness identifier prefix mismatch"))?;
    if identifier_suffix.len() != 20
        || identifier_suffix != &simple_run_id[..20]
        || !identifier_suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || app_identifier.as_str() != config_identifier
    {
        return Err(std::io::Error::other(
            "R3 current harness application identifier mismatch",
        ));
    }

    let credential_prefix = environment_text(CREDENTIAL_PREFIX_ENV)?;
    let credential_uuid = credential_prefix
        .strip_prefix(CREDENTIAL_PREFIX)
        .ok_or_else(|| std::io::Error::other("R3 current harness credential prefix mismatch"))?;
    canonical_uuid(credential_uuid)?;
    if credential_prefix == CREDENTIAL_PREFIX {
        return Err(std::io::Error::other(
            "R3 current harness credential namespace mismatch",
        ));
    }
    let window_class = environment_text(WINDOW_CLASS_ENV)?;
    if window_class != format!("{WINDOW_CLASS_PREFIX}{simple_run_id}")
        || !window_class
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(std::io::Error::other(
            "R3 current harness window class mismatch",
        ));
    }
    let cdp_port = environment_text(CDP_PORT_ENV)?
        .parse::<u16>()
        .map_err(|_| std::io::Error::other("R3 current harness CDP port is invalid"))?;
    if cdp_port < 1024 {
        return Err(std::io::Error::other(
            "R3 current harness CDP port is privileged",
        ));
    }
    let app_root = PathBuf::from(environment_text(APP_ROOT_ENV)?);
    if !app_root.is_absolute() {
        return Err(std::io::Error::other(
            "R3 current harness application root is not absolute",
        ));
    }
    let canonical_root = std::fs::canonicalize(&app_root).map_err(|_| {
        std::io::Error::other("R3 current harness application root is not canonicalizable")
    })?;
    if !same_windows_path(&canonical_root, &app_root) {
        return Err(std::io::Error::other(
            "R3 current harness application root is not canonical",
        ));
    }
    CONFIGURATION
        .set(HarnessConfiguration {
            app_identifier,
            app_root,
            credential_prefix,
            cdp_port,
            window_class,
        })
        .map_err(|_| std::io::Error::other("R3 current harness configuration conflict"))
}

fn normalized_windows_path(path: &Path) -> String {
    let value = path.as_os_str().to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(&value)
        .replace('/', r"\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn same_windows_path(left: &Path, right: &Path) -> bool {
    normalized_windows_path(left) == normalized_windows_path(right)
}

fn configuration() -> &'static HarnessConfiguration {
    CONFIGURATION
        .get()
        .expect("R3 current harness configuration must be authenticated before use")
}

pub(crate) fn is_initialized() -> bool {
    CONFIGURATION.get().is_some()
}

pub(crate) fn credential_prefix_if_initialized() -> Option<&'static str> {
    CONFIGURATION
        .get()
        .map(|configuration| configuration.credential_prefix.as_str())
}

pub(crate) fn credential_prefix() -> &'static str {
    &configuration().credential_prefix
}

pub(crate) fn validate_resolved_app_root<R: Runtime>(
    app: &tauri::App<R>,
    resolved: &Path,
) -> Result<(), std::io::Error> {
    let configuration = configuration();
    if app.config().identifier.as_str() != configuration.app_identifier.as_str() {
        return Err(std::io::Error::other(
            "R3 current harness runtime identifier changed",
        ));
    }
    let canonical = std::fs::canonicalize(resolved)
        .map_err(|_| std::io::Error::other("R3 current harness resolved root is unavailable"))?;
    if !same_windows_path(&canonical, &configuration.app_root)
        || !same_windows_path(resolved, &configuration.app_root)
    {
        return Err(std::io::Error::other(
            "R3 current harness resolved a non-canonical application root",
        ));
    }
    Ok(())
}

pub(crate) fn configure_main_window<'a, R: Runtime, M: Manager<R>>(
    builder: WebviewWindowBuilder<'a, R, M>,
) -> WebviewWindowBuilder<'a, R, M> {
    let configuration = configuration();
    let browser_arguments = format!(
        "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --remote-debugging-address=127.0.0.1 --remote-debugging-port={} --remote-allow-origins=*",
        configuration.cdp_port
    );
    builder
        .title("Lawyer Assistance R3 v0.4.0 acceptance")
        .window_classname(&configuration.window_class)
        .additional_browser_args(&browser_arguments)
        .inner_size(1200.0, 800.0)
        .min_inner_size(640.0, 420.0)
        .maximized(false)
        .visible(false)
        .resizable(true)
}
