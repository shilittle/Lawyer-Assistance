use base64::{engine::general_purpose::STANDARD, Engine as _};
use minisign_verify::{PublicKey, Signature};
use reqwest::{header, Client, Url};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager};
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOW};

const UPDATE_ENDPOINT: &str =
    "https://github.com/shilittle/Lawyer-Assistance/releases/latest/download/latest.json";
const UPDATE_EVENT: &str = "lawyer-assistance://updater-progress";
const MANIFEST_LIMIT_BYTES: usize = 64 * 1024;
const INSTALLER_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
const VERIFICATION_TEXT_LIMIT_BYTES: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const INSTALLER_ARGUMENTS: &str = "/P /R /UPDATE /ARGS";
const EMBEDDED_PUBLIC_KEY_BASE64: &str = include_str!("../../updater-public.key");
static UPDATE_INSTALL_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl IpcError {
    fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_type: error_type.into(),
            message: providers::redact_sensitive(&message.into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    version: Version,
    notes: Option<String>,
    pub_date: Option<String>,
    platforms: ReleasePlatforms,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasePlatforms {
    #[serde(rename = "windows-x86_64")]
    windows_x86_64: ReleasePlatform,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleasePlatform {
    signature: String,
    url: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationUpdateInfo {
    current_version: String,
    version: String,
    date: Option<String>,
    body: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InstallApplicationUpdateRequest {
    version: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StartedData {
    content_length: Option<u64>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressData {
    chunk_length: u64,
}

#[derive(Clone, Serialize)]
#[serde(tag = "event")]
enum UpdateProgressEvent {
    Started { data: StartedData },
    Progress { data: ProgressData },
    Finished,
}

struct DownloadTarget {
    directory: PathBuf,
    installer: PathBuf,
}

#[derive(Debug)]
struct UpdateInstallGuard;

impl UpdateInstallGuard {
    fn acquire() -> Result<Self, IpcError> {
        UPDATE_INSTALL_IN_PROGRESS
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                IpcError::new(
                    "updater_in_progress",
                    "Another update download or installation is already in progress",
                )
            })?;
        Ok(Self)
    }
}

impl Drop for UpdateInstallGuard {
    fn drop(&mut self) {
        UPDATE_INSTALL_IN_PROGRESS.store(false, Ordering::Release);
    }
}

#[tauri::command]
pub async fn check_for_application_update() -> Result<Option<ApplicationUpdateInfo>, IpcError> {
    let client = build_http_client()?;
    let manifest = fetch_manifest(&client).await?;
    let current_version = current_version()?;
    validate_manifest(&manifest)?;
    Ok(select_update(&manifest, &current_version))
}

#[tauri::command]
pub async fn download_install_application_update(
    app: AppHandle,
    request: InstallApplicationUpdateRequest,
) -> Result<(), IpcError> {
    let _install_guard = UpdateInstallGuard::acquire()?;
    let requested_version = Version::parse(request.version.trim()).map_err(|_| {
        IpcError::new(
            "updater_schema",
            "Requested update version is not valid semantic version text",
        )
    })?;
    let client = build_http_client()?;
    let manifest = fetch_manifest(&client).await?;
    validate_manifest(&manifest)?;

    let current_version = current_version()?;
    if manifest.version <= current_version {
        return Err(IpcError::new(
            "updater_stale",
            "The selected update is no longer newer than the installed version",
        ));
    }
    if manifest.version != requested_version {
        return Err(IpcError::new(
            "updater_changed",
            "The available update changed; check for updates again before installing",
        ));
    }

    let platform = &manifest.platforms.windows_x86_64;
    let (download_url, filename) =
        validate_declared_download_url(&platform.url, &manifest.version)?;
    let (public_key, signature) =
        decode_verification_material(EMBEDDED_PUBLIC_KEY_BASE64, &platform.signature, &filename)?;
    let target = create_download_target(&app, &filename)?;

    let result = download_and_verify(
        &app,
        &client,
        download_url,
        &target.installer,
        &public_key,
        &signature,
    )
    .await;
    if let Err(error) = result {
        remove_download_target(&target);
        return Err(error);
    }

    if let Err(error) = launch_nsis_installer(&target.installer) {
        remove_download_target(&target);
        return Err(error);
    }
    app.cleanup_before_exit();
    std::process::exit(0)
}

#[tauri::command]
pub fn relaunch_application(app: AppHandle) {
    app.request_restart();
}

/// Removes verified installers left by an updater process that successfully
/// handed off to NSIS and exited. Only the exact, flat UUID directory shape
/// created by this module is eligible; reparse points and unknown contents are
/// never traversed or deleted.
pub fn cleanup_stale_update_downloads(app_local_data_dir: &Path) -> Result<(), IpcError> {
    let updater_root = app_local_data_dir.join("updates");
    if !updater_root.exists() {
        return Ok(());
    }
    let root_metadata = fs::symlink_metadata(&updater_root).map_err(|_| {
        IpcError::new(
            "updater_io",
            "Unable to inspect the update download directory",
        )
    })?;
    if !root_metadata.is_dir() || is_reparse_point(&root_metadata) {
        return Err(IpcError::new(
            "updater_security",
            "The update download root is not a safe local directory",
        ));
    }

    for entry in fs::read_dir(&updater_root)
        .map_err(|_| IpcError::new("updater_io", "Unable to enumerate stale update downloads"))?
    {
        let entry = entry.map_err(|_| {
            IpcError::new("updater_io", "Unable to inspect a stale update download")
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(identifier) = Uuid::parse_str(&name) else {
            continue;
        };
        if identifier.hyphenated().to_string() != name {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| {
            IpcError::new("updater_io", "Unable to inspect a stale update directory")
        })?;
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            continue;
        }

        let children = fs::read_dir(entry.path())
            .map_err(|_| IpcError::new("updater_io", "Unable to inspect stale update files"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| IpcError::new("updater_io", "Unable to inspect stale update files"))?;
        if children.iter().any(|child| {
            let Ok(metadata) = fs::symlink_metadata(child.path()) else {
                return true;
            };
            !metadata.is_file()
                || is_reparse_point(&metadata)
                || !is_release_installer_filename(&child.file_name().to_string_lossy())
        }) {
            continue;
        }

        for child in children {
            let metadata = fs::metadata(child.path()).map_err(|_| {
                IpcError::new("updater_io", "Unable to inspect a stale update installer")
            })?;
            make_file_writable(&child.path(), &metadata).map_err(|_| {
                IpcError::new("updater_io", "Unable to unlock a stale update installer")
            })?;
            fs::remove_file(child.path()).map_err(|_| {
                IpcError::new("updater_io", "Unable to remove a stale update installer")
            })?;
        }
        fs::remove_dir(entry.path()).map_err(|_| {
            IpcError::new("updater_io", "Unable to remove a stale update directory")
        })?;
    }
    Ok(())
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn is_release_installer_filename(name: &str) -> bool {
    name.strip_prefix("Lawyer Assistance_")
        .and_then(|value| value.strip_suffix("_x64-setup.exe"))
        .is_some_and(|version| Version::parse(version).is_ok())
}

fn current_version() -> Result<Version, IpcError> {
    Version::parse(env!("CARGO_PKG_VERSION")).map_err(|_| {
        IpcError::new(
            "updater_schema",
            "The installed application version is not valid semantic version text",
        )
    })
}

fn build_http_client() -> Result<Client, IpcError> {
    Client::builder()
        .https_only(true)
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .user_agent(concat!(
            "Lawyer-Assistance/",
            env!("CARGO_PKG_VERSION"),
            " updater"
        ))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !is_allowed_github_transport_url(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|_| IpcError::new("updater_network", "Unable to initialize the update client"))
}

async fn fetch_manifest(client: &Client) -> Result<ReleaseManifest, IpcError> {
    let endpoint = Url::parse(UPDATE_ENDPOINT)
        .map_err(|_| IpcError::new("updater_schema", "The embedded update endpoint is invalid"))?;
    if !is_strict_github_url(&endpoint) {
        return Err(IpcError::new(
            "updater_security",
            "The embedded update endpoint failed the GitHub HTTPS policy",
        ));
    }

    let mut response = client
        .get(endpoint)
        .header(header::ACCEPT, "application/json")
        .header(header::ACCEPT_ENCODING, "identity")
        .timeout(MANIFEST_TIMEOUT)
        .send()
        .await
        .map_err(|_| IpcError::new("updater_network", "Unable to fetch the update manifest"))?;
    if !response.status().is_success() {
        return Err(IpcError::new(
            "updater_network",
            format!(
                "The update manifest server returned HTTP {}",
                response.status()
            ),
        ));
    }
    if !is_allowed_github_transport_url(response.url()) {
        return Err(IpcError::new(
            "updater_security",
            "The update manifest redirected outside approved GitHub download hosts",
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MANIFEST_LIMIT_BYTES as u64)
    {
        return Err(IpcError::new(
            "updater_schema",
            "The update manifest exceeds the allowed size",
        ));
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        IpcError::new(
            "updater_network",
            "The update manifest download was interrupted",
        )
    })? {
        if body.len().saturating_add(chunk.len()) > MANIFEST_LIMIT_BYTES {
            return Err(IpcError::new(
                "updater_schema",
                "The update manifest exceeds the allowed size",
            ));
        }
        body.extend_from_slice(&chunk);
    }

    parse_manifest(&body)
}

fn parse_manifest(bytes: &[u8]) -> Result<ReleaseManifest, IpcError> {
    let manifest: ReleaseManifest = serde_json::from_slice(bytes).map_err(|_| {
        IpcError::new(
            "updater_schema",
            "The update manifest does not match the required schema",
        )
    })?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<(), IpcError> {
    if manifest.version.to_string().len() > 128 {
        return Err(IpcError::new(
            "updater_schema",
            "The update version is unexpectedly long",
        ));
    }
    if manifest
        .notes
        .as_ref()
        .is_some_and(|value| value.len() > 32 * 1024 || value.contains('\0'))
    {
        return Err(IpcError::new(
            "updater_schema",
            "The update notes are invalid or too long",
        ));
    }
    if manifest.pub_date.as_ref().is_some_and(|value| {
        value.is_empty()
            || value.len() > 128
            || value.chars().any(|character| character.is_control())
    }) {
        return Err(IpcError::new(
            "updater_schema",
            "The update publication date is invalid",
        ));
    }
    let platform = &manifest.platforms.windows_x86_64;
    if platform.signature.is_empty()
        || platform.signature.len() > VERIFICATION_TEXT_LIMIT_BYTES
        || platform.url.len() > 2048
    {
        return Err(IpcError::new(
            "updater_schema",
            "The Windows update entry is invalid or too large",
        ));
    }
    Ok(())
}

fn select_update(
    manifest: &ReleaseManifest,
    current_version: &Version,
) -> Option<ApplicationUpdateInfo> {
    (manifest.version > *current_version).then(|| ApplicationUpdateInfo {
        current_version: current_version.to_string(),
        version: manifest.version.to_string(),
        date: manifest.pub_date.clone(),
        body: manifest.notes.clone(),
    })
}

fn is_strict_github_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some("github.com")
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn is_allowed_github_transport_url(url: &Url) -> bool {
    if url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    matches!(
        url.host_str(),
        Some("github.com")
            | Some("objects.githubusercontent.com")
            | Some("release-assets.githubusercontent.com")
    )
}

fn validate_declared_download_url(
    value: &str,
    version: &Version,
) -> Result<(Url, String), IpcError> {
    let url = Url::parse(value).map_err(|_| {
        IpcError::new(
            "updater_security",
            "The update download URL is not a valid URL",
        )
    })?;
    if !is_strict_github_url(&url) {
        return Err(IpcError::new(
            "updater_security",
            "Updates may only be downloaded from github.com over HTTPS",
        ));
    }

    let expected_prefix = format!("/shilittle/Lawyer-Assistance/releases/download/v{version}/");
    if !url.path().starts_with(&expected_prefix) {
        return Err(IpcError::new(
            "updater_security",
            "The update URL does not belong to the official release path",
        ));
    }
    let encoded_filename = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .ok_or_else(|| IpcError::new("updater_security", "The update URL has no filename"))?;
    let filename = percent_decode_filename(encoded_filename)?;
    let expected_filename = format!("Lawyer Assistance_{version}_x64-setup.exe");
    if filename != expected_filename || url.path() != format!("{expected_prefix}{encoded_filename}")
    {
        return Err(IpcError::new(
            "updater_security",
            "The update filename does not match the signed release version",
        ));
    }

    Ok((url, filename))
}

fn percent_decode_filename(value: &str) -> Result<String, IpcError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(IpcError::new(
                    "updater_security",
                    "The update filename contains invalid percent encoding",
                ));
            }
            let high = decode_hex(bytes[index + 1]);
            let low = decode_hex(bytes[index + 2]);
            let byte = match (high, low) {
                (Some(high), Some(low)) => high * 16 + low,
                _ => {
                    return Err(IpcError::new(
                        "updater_security",
                        "The update filename contains invalid percent encoding",
                    ));
                }
            };
            if matches!(byte, 0 | b'/' | b'\\') {
                return Err(IpcError::new(
                    "updater_security",
                    "The update filename contains a forbidden character",
                ));
            }
            decoded.push(byte);
            index += 3;
        } else {
            if matches!(bytes[index], 0 | b'/' | b'\\') {
                return Err(IpcError::new(
                    "updater_security",
                    "The update filename contains a forbidden character",
                ));
            }
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded)
        .map_err(|_| IpcError::new("updater_security", "The update filename is not valid UTF-8"))
}

fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn decode_base64_text(value: &str, kind: &str) -> Result<String, IpcError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > VERIFICATION_TEXT_LIMIT_BYTES {
        return Err(IpcError::new(
            "updater_signature",
            format!("The {kind} verification material is empty or too large"),
        ));
    }
    let decoded = STANDARD.decode(trimmed).map_err(|_| {
        IpcError::new(
            "updater_signature",
            format!("The {kind} verification material is not valid base64"),
        )
    })?;
    if decoded.len() > VERIFICATION_TEXT_LIMIT_BYTES {
        return Err(IpcError::new(
            "updater_signature",
            format!("The decoded {kind} verification material is too large"),
        ));
    }
    String::from_utf8(decoded).map_err(|_| {
        IpcError::new(
            "updater_signature",
            format!("The decoded {kind} verification material is not UTF-8 text"),
        )
    })
}

fn decode_verification_material(
    public_key_base64: &str,
    signature_base64: &str,
    expected_filename: &str,
) -> Result<(PublicKey, Signature), IpcError> {
    let public_key_text = decode_base64_text(public_key_base64, "public key")?;
    if public_key_text.lines().count() != 2 {
        return Err(IpcError::new(
            "updater_signature",
            "The decoded updater public key has an invalid line count",
        ));
    }
    let signature_text = decode_base64_text(signature_base64, "signature")?;
    if signature_text.lines().count() != 4 {
        return Err(IpcError::new(
            "updater_signature",
            "The decoded updater signature has an invalid line count",
        ));
    }

    let public_key = PublicKey::decode(&public_key_text).map_err(|_| {
        IpcError::new(
            "updater_signature",
            "The embedded updater public key is invalid",
        )
    })?;
    let signature = Signature::decode(&signature_text).map_err(|_| {
        IpcError::new(
            "updater_signature",
            "The update signature has an invalid minisign format",
        )
    })?;
    validate_trusted_filename(signature.trusted_comment(), expected_filename)?;
    public_key.verify_stream(&signature).map_err(|_| {
        IpcError::new(
            "updater_signature",
            "The update signature does not match the embedded public key",
        )
    })?;
    Ok((public_key, signature))
}

fn validate_trusted_filename(
    trusted_comment: &str,
    expected_filename: &str,
) -> Result<(), IpcError> {
    let (timestamp, filename) = trusted_comment.split_once("\tfile:").ok_or_else(|| {
        IpcError::new(
            "updater_signature",
            "The signed trusted comment does not bind an installer filename",
        )
    })?;
    let timestamp = timestamp.strip_prefix("timestamp:").unwrap_or_default();
    if timestamp.is_empty()
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
        || filename != expected_filename
    {
        return Err(IpcError::new(
            "updater_signature",
            "The signed trusted comment does not match this installer filename",
        ));
    }
    Ok(())
}

fn create_download_target(app: &AppHandle, filename: &str) -> Result<DownloadTarget, IpcError> {
    let updater_root = app
        .path()
        .app_local_data_dir()
        .map_err(|_| {
            IpcError::new(
                "updater_io",
                "Unable to resolve the application data directory",
            )
        })?
        .join("updates");
    fs::create_dir_all(&updater_root).map_err(|_| {
        IpcError::new(
            "updater_io",
            "Unable to create the update download directory",
        )
    })?;

    let directory = updater_root.join(Uuid::new_v4().to_string());
    fs::create_dir(&directory)
        .map_err(|_| IpcError::new("updater_io", "Unable to create a private update directory"))?;
    Ok(DownloadTarget {
        installer: directory.join(filename),
        directory,
    })
}

async fn download_and_verify(
    app: &AppHandle,
    client: &Client,
    url: Url,
    destination: &Path,
    public_key: &PublicKey,
    signature: &Signature,
) -> Result<(), IpcError> {
    let mut response = client
        .get(url)
        .header(header::ACCEPT, "application/octet-stream")
        .header(header::ACCEPT_ENCODING, "identity")
        .timeout(DOWNLOAD_TIMEOUT)
        .send()
        .await
        .map_err(|_| IpcError::new("updater_network", "Unable to start the update download"))?;
    if !response.status().is_success() {
        return Err(IpcError::new(
            "updater_network",
            format!("The update server returned HTTP {}", response.status()),
        ));
    }
    if !is_allowed_github_transport_url(response.url()) {
        return Err(IpcError::new(
            "updater_security",
            "The installer download redirected outside approved GitHub download hosts",
        ));
    }

    let content_length = response.content_length();
    if content_length.is_some_and(|length| length == 0 || length > INSTALLER_LIMIT_BYTES) {
        return Err(IpcError::new(
            "updater_security",
            "The installer size is empty or exceeds the allowed limit",
        ));
    }
    emit_progress(
        app,
        UpdateProgressEvent::Started {
            data: StartedData { content_length },
        },
    );

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| IpcError::new("updater_io", "Unable to create the installer download file"))?;
    let mut verifier = public_key.verify_stream(signature).map_err(|_| {
        IpcError::new(
            "updater_signature",
            "The update signature cannot be verified in streaming mode",
        )
    })?;
    let mut downloaded = 0u64;
    let mut executable_header = [0u8; 2];
    let mut executable_header_len = 0usize;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| IpcError::new("updater_network", "The installer download was interrupted"))?
    {
        let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
            IpcError::new(
                "updater_security",
                "The installer download chunk is too large",
            )
        })?;
        downloaded = downloaded.checked_add(chunk_length).ok_or_else(|| {
            IpcError::new("updater_security", "The installer download size overflowed")
        })?;
        if downloaded > INSTALLER_LIMIT_BYTES {
            return Err(IpcError::new(
                "updater_security",
                "The installer exceeds the allowed size limit",
            ));
        }

        if executable_header_len < executable_header.len() {
            let take = (executable_header.len() - executable_header_len).min(chunk.len());
            executable_header[executable_header_len..executable_header_len + take]
                .copy_from_slice(&chunk[..take]);
            executable_header_len += take;
        }
        verifier.update(&chunk);
        output
            .write_all(&chunk)
            .map_err(|_| IpcError::new("updater_io", "Unable to write the installer download"))?;
        emit_progress(
            app,
            UpdateProgressEvent::Progress {
                data: ProgressData { chunk_length },
            },
        );
    }

    if downloaded == 0 || content_length.is_some_and(|expected| expected != downloaded) {
        return Err(IpcError::new(
            "updater_network",
            "The installer download ended before the expected number of bytes arrived",
        ));
    }
    if executable_header != *b"MZ" {
        return Err(IpcError::new(
            "updater_security",
            "The signed update payload is not a Windows executable",
        ));
    }
    output
        .flush()
        .and_then(|_| output.sync_all())
        .map_err(|_| IpcError::new("updater_io", "Unable to finalize the installer download"))?;
    verifier.finalize().map_err(|_| {
        IpcError::new(
            "updater_signature",
            "The installer signature is invalid; the downloaded file was rejected",
        )
    })?;
    drop(output);

    let mut permissions = fs::metadata(destination)
        .map_err(|_| IpcError::new("updater_io", "Unable to inspect the verified installer"))?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(destination, permissions).map_err(|_| {
        IpcError::new(
            "updater_io",
            "Unable to protect the verified installer from modification",
        )
    })?;
    emit_progress(app, UpdateProgressEvent::Finished);
    Ok(())
}

fn emit_progress(app: &AppHandle, event: UpdateProgressEvent) {
    let _ = app.emit(UPDATE_EVENT, event);
}

fn remove_download_target(target: &DownloadTarget) {
    if target.installer.is_file() {
        if let Ok(metadata) = fs::metadata(&target.installer) {
            let _ = make_file_writable(&target.installer, &metadata);
        }
        let _ = fs::remove_file(&target.installer);
    }
    let _ = fs::remove_dir(&target.directory);
}

fn make_file_writable(path: &Path, metadata: &fs::Metadata) -> std::io::Result<()> {
    let mut permissions = metadata.permissions();
    if permissions.readonly() {
        // This application and updater are Windows-only. Clearing the DOS
        // read-only attribute does not broaden Unix mode bits.
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

fn launch_nsis_installer(path: &Path) -> Result<(), IpcError> {
    if !path.is_file() {
        return Err(IpcError::new(
            "updater_install",
            "The verified installer is no longer available",
        ));
    }
    let operation = wide_null(OsStr::new("open"));
    let executable = wide_null(path.as_os_str());
    let parameters = wide_null(OsStr::new(INSTALLER_ARGUMENTS));
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            executable.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            SW_SHOW,
        )
    };
    if result as isize <= 32 {
        return Err(IpcError::new(
            "updater_install",
            "Windows refused to start the verified update installer",
        ));
    }
    Ok(())
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PUBLIC_KEY: &str = "untrusted comment: minisign public key E7620F1842B4E81F\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const TEST_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==";

    fn valid_manifest(version: &str) -> Vec<u8> {
        format!(
            r#"{{
              "version": "{version}",
              "notes": "Security update",
              "pub_date": "2026-07-16T00:00:00Z",
              "platforms": {{
                "windows-x86_64": {{
                  "signature": "{}",
                  "url": "https://github.com/shilittle/Lawyer-Assistance/releases/download/v{version}/Lawyer%20Assistance_{version}_x64-setup.exe"
                }}
              }}
            }}"#,
            STANDARD.encode(TEST_SIGNATURE)
        )
        .into_bytes()
    }

    #[test]
    fn manifest_schema_accepts_release_shape_and_rejects_unknown_fields() {
        let parsed = parse_manifest(&valid_manifest("0.2.1")).expect("valid manifest parses");
        assert_eq!(parsed.version, Version::parse("0.2.1").unwrap());
        assert_eq!(parsed.notes.as_deref(), Some("Security update"));

        let invalid = br#"{
          "version":"0.2.1",
          "platforms":{"windows-x86_64":{"signature":"abc","url":"https://github.com/example"}},
          "unexpected":true
        }"#;
        assert_eq!(
            parse_manifest(invalid).unwrap_err().error_type,
            "updater_schema"
        );
    }

    #[test]
    fn same_or_older_version_does_not_offer_an_update() {
        let manifest = parse_manifest(&valid_manifest("0.2.0")).unwrap();
        assert!(select_update(&manifest, &Version::parse("0.2.0").unwrap()).is_none());
        assert!(select_update(&manifest, &Version::parse("0.2.1").unwrap()).is_none());
    }

    #[test]
    fn stream_verifier_rejects_tampering() {
        let public_key_base64 = STANDARD.encode(TEST_PUBLIC_KEY);
        let signature_base64 = STANDARD.encode(TEST_SIGNATURE);
        let (public_key, signature) =
            decode_verification_material(&public_key_base64, &signature_base64, "test")
                .expect("test material parses");

        let mut valid = public_key.verify_stream(&signature).unwrap();
        valid.update(b"te");
        valid.update(b"st");
        valid.finalize().expect("original bytes verify");

        let mut tampered = public_key.verify_stream(&signature).unwrap();
        tampered.update(b"Test");
        assert!(tampered.finalize().is_err());
    }

    #[test]
    fn download_url_is_limited_to_the_official_github_release() {
        let version = Version::parse("0.2.1").unwrap();
        let valid = "https://github.com/shilittle/Lawyer-Assistance/releases/download/v0.2.1/Lawyer%20Assistance_0.2.1_x64-setup.exe";
        assert_eq!(
            validate_declared_download_url(valid, &version).unwrap().1,
            "Lawyer Assistance_0.2.1_x64-setup.exe"
        );

        for invalid in [
            "http://github.com/shilittle/Lawyer-Assistance/releases/download/v0.2.1/Lawyer%20Assistance_0.2.1_x64-setup.exe",
            "https://github.example/shilittle/Lawyer-Assistance/releases/download/v0.2.1/Lawyer%20Assistance_0.2.1_x64-setup.exe",
            "https://github.com/other/Lawyer-Assistance/releases/download/v0.2.1/Lawyer%20Assistance_0.2.1_x64-setup.exe",
            "https://github.com/shilittle/Lawyer-Assistance/releases/download/v0.2.1/other.exe",
        ] {
            assert!(validate_declared_download_url(invalid, &version).is_err());
        }
    }

    #[test]
    fn trusted_comment_must_bind_the_exact_filename() {
        assert!(validate_trusted_filename(
            "timestamp:1556193335\tfile:Lawyer Assistance_0.2.1_x64-setup.exe",
            "Lawyer Assistance_0.2.1_x64-setup.exe"
        )
        .is_ok());
        assert!(validate_trusted_filename(
            "timestamp:1556193335\tfile:other.exe",
            "Lawyer Assistance_0.2.1_x64-setup.exe"
        )
        .is_err());
    }

    #[test]
    fn install_guard_rejects_concurrent_update_attempts() {
        let first = UpdateInstallGuard::acquire().expect("first update acquires the guard");
        assert_eq!(
            UpdateInstallGuard::acquire().unwrap_err().error_type,
            "updater_in_progress"
        );
        drop(first);
        assert!(UpdateInstallGuard::acquire().is_ok());
    }

    #[test]
    fn startup_cleanup_removes_only_owned_flat_update_directories() {
        let directory = tempfile::tempdir().unwrap();
        let updates = directory.path().join("updates");
        fs::create_dir(&updates).unwrap();
        let owned = updates.join(Uuid::new_v4().hyphenated().to_string());
        fs::create_dir(&owned).unwrap();
        let installer = owned.join("Lawyer Assistance_0.2.0_x64-setup.exe");
        fs::write(&installer, b"MZ stale installer").unwrap();
        let mut permissions = fs::metadata(&installer).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&installer, permissions).unwrap();
        let unrelated = updates.join("user-files");
        fs::create_dir(&unrelated).unwrap();
        fs::write(unrelated.join("keep.txt"), b"keep").unwrap();

        cleanup_stale_update_downloads(directory.path()).unwrap();

        assert!(!owned.exists());
        assert_eq!(fs::read(unrelated.join("keep.txt")).unwrap(), b"keep");
    }

    #[test]
    fn startup_cleanup_keeps_uuid_directories_with_unknown_contents() {
        let directory = tempfile::tempdir().unwrap();
        let owned = directory
            .path()
            .join("updates")
            .join(Uuid::new_v4().hyphenated().to_string());
        fs::create_dir_all(&owned).unwrap();
        fs::write(owned.join("not-created-by-updater.txt"), b"keep").unwrap();

        cleanup_stale_update_downloads(directory.path()).unwrap();

        assert!(owned.join("not-created-by-updater.txt").exists());
    }
}
