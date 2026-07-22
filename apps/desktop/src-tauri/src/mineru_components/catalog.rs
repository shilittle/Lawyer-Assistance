use super::{error, package, CatalogEntryView, ComponentResult};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use minisign_verify::{PublicKey, Signature};
use reqwest::{header, redirect, Client, Url};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{ffi::OsStr, fs::OpenOptions, io::Write, path::Path, time::Duration};

const CATALOG_SCHEMA_VERSION: u16 = 1;
const STORED_CATALOG_SCHEMA_VERSION: u16 = 1;
const PROTOCOL_VERSION: &str = "la-mineru-worker-v1";
const PLATFORM: &str = "windows-x86_64";
const PROVENANCE_FILE: &str = "mineru-component-provenance.json";
const STORED_CATALOG_FILE: &str = "trusted-catalog.json";
const MAX_CATALOG_BYTES: u64 = 2 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(6 * 60 * 60);
const EMBEDDED_PUBLIC_KEY_BASE64: &str = include_str!("../../updater-public.key");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ComponentCatalogV1 {
    pub schema_version: u16,
    pub catalog_id: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub entries: Vec<ComponentCatalogEntryV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ComponentCatalogEntryV1 {
    pub package_id: String,
    pub component_version: Version,
    pub mineru_version: String,
    pub protocol_version: String,
    pub platform: String,
    pub package_size_bytes: u64,
    pub package_sha256: String,
    pub package_manifest_sha256: String,
    pub provenance_file_name: String,
    pub provenance_size_bytes: u64,
    pub provenance_sha256: String,
    pub provenance_download_url: String,
    pub download_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_set_manifest_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_set_manifest_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<ComponentPackagePartV1>,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ComponentPackagePartV1 {
    pub number: u16,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub download_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredCatalogV1 {
    schema_version: u16,
    source_filename: String,
    catalog_base64: String,
    signature_base64: String,
}

pub(super) fn entry_view(entry: &ComponentCatalogEntryV1) -> CatalogEntryView {
    CatalogEntryView {
        package_id: entry.package_id.clone(),
        component_version: entry.component_version.to_string(),
        mineru_version: entry.mineru_version.clone(),
        package_size_bytes: entry.package_size_bytes,
        package_sha256: entry.package_sha256.clone(),
        package_manifest_sha256: entry.package_manifest_sha256.clone(),
        download_url: entry.download_url.clone(),
    }
}

pub(super) fn read_and_verify_catalog(
    catalog_path: &Path,
    signature_path: &Path,
) -> ComponentResult<(ComponentCatalogV1, Vec<u8>, Vec<u8>)> {
    let catalog = package::read_pinned_local_file(catalog_path, MAX_CATALOG_BYTES)?;
    let signature = package::read_pinned_local_file(signature_path, MAX_SIGNATURE_BYTES)?;
    let filename = catalog_path
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| safe_filename(name))
        .ok_or_else(|| error("catalog_filename_invalid"))?;
    if signature_path.file_name().and_then(OsStr::to_str)
        != Some(format!("{filename}.minisig").as_str())
    {
        return Err(error("catalog_signature_filename_invalid"));
    }
    verify_signature(&catalog, &signature, filename, &embedded_public_key()?)?;
    let parsed = validate_catalog(&catalog, package::unix_now()?)?;
    Ok((parsed, catalog, signature))
}

pub(super) fn persist_trusted_catalog(
    root: &Path,
    catalog: &[u8],
    signature: &[u8],
) -> ComponentResult<()> {
    let signature_text =
        std::str::from_utf8(signature).map_err(|_| error("catalog_signature_invalid"))?;
    let decoded =
        Signature::decode(signature_text).map_err(|_| error("catalog_signature_invalid"))?;
    let filename = decoded
        .trusted_comment()
        .split_once("\tfile:")
        .map(|(_, filename)| filename)
        .filter(|name| safe_filename(name))
        .ok_or_else(|| error("catalog_signature_invalid"))?;
    let envelope = StoredCatalogV1 {
        schema_version: STORED_CATALOG_SCHEMA_VERSION,
        source_filename: filename.to_owned(),
        catalog_base64: STANDARD.encode(catalog),
        signature_base64: STANDARD.encode(signature),
    };
    let bytes = serde_json::to_vec(&envelope).map_err(|_| error("catalog_persist_failed"))?;
    package::atomic_write(&root.join(STORED_CATALOG_FILE), &bytes)
}

pub(super) fn load_trusted_catalog(root: &Path) -> ComponentResult<ComponentCatalogV1> {
    let bytes = package::read_pinned_local_file(
        &root.join(STORED_CATALOG_FILE),
        MAX_CATALOG_BYTES + MAX_SIGNATURE_BYTES,
    )?;
    let stored: StoredCatalogV1 =
        serde_json::from_slice(&bytes).map_err(|_| error("stored_catalog_invalid"))?;
    if stored.schema_version != STORED_CATALOG_SCHEMA_VERSION
        || !safe_filename(&stored.source_filename)
    {
        return Err(error("stored_catalog_invalid"));
    }
    let catalog = STANDARD
        .decode(stored.catalog_base64)
        .map_err(|_| error("stored_catalog_invalid"))?;
    let signature = STANDARD
        .decode(stored.signature_base64)
        .map_err(|_| error("stored_catalog_invalid"))?;
    if catalog.is_empty()
        || catalog.len() as u64 > MAX_CATALOG_BYTES
        || signature.is_empty()
        || signature.len() as u64 > MAX_SIGNATURE_BYTES
    {
        return Err(error("stored_catalog_invalid"));
    }
    verify_signature(
        &catalog,
        &signature,
        &stored.source_filename,
        &embedded_public_key()?,
    )?;
    super::state::verify_catalog_high_water(
        root,
        validate_catalog(&catalog, package::unix_now()?)?.issued_at_unix,
        &package::sha256_bytes(&catalog),
    )?;
    validate_catalog(&catalog, package::unix_now()?)
}

pub(super) fn embedded_public_key() -> ComponentResult<String> {
    let bytes = STANDARD
        .decode(EMBEDDED_PUBLIC_KEY_BASE64.trim())
        .map_err(|_| error("catalog_trust_root_invalid"))?;
    let text = String::from_utf8(bytes).map_err(|_| error("catalog_trust_root_invalid"))?;
    if text.lines().count() != 2 {
        return Err(error("catalog_trust_root_invalid"));
    }
    Ok(text)
}

pub(super) fn verify_signature(
    catalog: &[u8],
    signature: &[u8],
    expected_filename: &str,
    public_key: &str,
) -> ComponentResult<()> {
    let signature_text =
        std::str::from_utf8(signature).map_err(|_| error("catalog_signature_invalid"))?;
    if signature_text.lines().count() != 4 {
        return Err(error("catalog_signature_invalid"));
    }
    let key = PublicKey::decode(public_key).map_err(|_| error("catalog_trust_root_invalid"))?;
    let signature =
        Signature::decode(signature_text).map_err(|_| error("catalog_signature_invalid"))?;
    let (timestamp, filename) = signature
        .trusted_comment()
        .split_once("\tfile:")
        .ok_or_else(|| error("catalog_signature_invalid"))?;
    if !timestamp
        .strip_prefix("timestamp:")
        .is_some_and(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        || filename != expected_filename
    {
        return Err(error("catalog_signature_invalid"));
    }
    key.verify(catalog, &signature, false)
        .map_err(|_| error("catalog_signature_invalid"))
}

pub(super) fn validate_catalog(bytes: &[u8], now: u64) -> ComponentResult<ComponentCatalogV1> {
    let catalog: ComponentCatalogV1 =
        serde_json::from_slice(bytes).map_err(|_| error("catalog_schema_invalid"))?;
    if !matches!(catalog.schema_version, CATALOG_SCHEMA_VERSION | 2)
        || !valid_identifier(&catalog.catalog_id)
        || catalog.issued_at_unix == 0
        || catalog.issued_at_unix > now.saturating_add(300)
        || catalog.expires_at_unix <= now
        || catalog.expires_at_unix <= catalog.issued_at_unix
        || catalog.entries.is_empty()
        || catalog.entries.len() > 256
    {
        return Err(error("catalog_schema_invalid"));
    }
    let mut identifiers = std::collections::BTreeSet::new();
    let mut versions = std::collections::BTreeSet::new();
    for entry in &catalog.entries {
        if !valid_identifier(&entry.package_id)
            || !identifiers.insert(entry.package_id.clone())
            || !versions.insert(entry.component_version.clone())
            || entry.component_version == Version::new(0, 0, 0)
            || entry.mineru_version.is_empty()
            || entry.mineru_version.len() > 64
            || entry.protocol_version != PROTOCOL_VERSION
            || entry.platform != PLATFORM
            || entry.package_size_bytes < 16
            || entry.package_size_bytes > package::MAX_PACKAGE_BYTES
            || !package::valid_hash(&entry.package_sha256)
            || !package::valid_hash(&entry.package_manifest_sha256)
            || entry.provenance_file_name != PROVENANCE_FILE
            || entry.provenance_size_bytes == 0
            || entry.provenance_size_bytes > package::MAX_PROVENANCE_BYTES
            || !package::valid_hash(&entry.provenance_sha256)
        {
            return Err(error("catalog_schema_invalid"));
        }
        validate_official_url(&entry.download_url, entry)?;
        validate_official_provenance_url(&entry.provenance_download_url, entry)?;
        if catalog.schema_version == CATALOG_SCHEMA_VERSION {
            if entry.part_set_manifest_size_bytes.is_some()
                || entry.part_set_manifest_sha256.is_some()
                || !entry.parts.is_empty()
            {
                return Err(error("catalog_schema_invalid"));
            }
        } else {
            validate_sharded_entry(entry)?;
        }
    }
    if catalog.schema_version == 2
        && privacy::vnext::canonical_json_v1(&catalog)
            .map_err(|_| error("catalog_schema_invalid"))?
            != bytes
    {
        return Err(error("catalog_not_canonical"));
    }
    Ok(catalog)
}

fn validate_official_provenance_url(
    value: &str,
    entry: &ComponentCatalogEntryV1,
) -> ComponentResult<Url> {
    let url = Url::parse(value).map_err(|_| error("catalog_provenance_url_invalid"))?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().bytes().any(|byte| matches!(byte, b'%' | b'\\'))
    {
        return Err(error("catalog_provenance_url_invalid"));
    }
    let expected_path = format!(
        "/shilittle/Lawyer-Assistance/releases/download/mineru-components-v{}/{PROVENANCE_FILE}",
        entry.component_version
    );
    if url.path() != expected_path {
        return Err(error("catalog_provenance_url_invalid"));
    }
    Ok(url)
}

fn validate_official_url(value: &str, entry: &ComponentCatalogEntryV1) -> ComponentResult<Url> {
    let url = Url::parse(value).map_err(|_| error("catalog_url_invalid"))?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().bytes().any(|byte| matches!(byte, b'%' | b'\\'))
    {
        return Err(error("catalog_url_invalid"));
    }
    let package_filename = format!(
        "lawyer-assistance-mineru-{}-windows-x86_64.laocrpkg",
        entry.component_version
    );
    let filename = if entry.parts.is_empty() {
        package_filename
    } else {
        format!("{package_filename}.laocrparts")
    };
    let expected_path = format!(
        "/shilittle/Lawyer-Assistance/releases/download/mineru-components-v{}/{filename}",
        entry.component_version
    );
    if url.path() != expected_path {
        return Err(error("catalog_url_invalid"));
    }
    Ok(url)
}

fn validate_sharded_entry(entry: &ComponentCatalogEntryV1) -> ComponentResult<()> {
    const RELEASE_ASSET_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
    if entry
        .part_set_manifest_size_bytes
        .is_none_or(|size| size == 0 || size > 2 * 1024 * 1024)
        || entry
            .part_set_manifest_sha256
            .as_deref()
            .is_none_or(|hash| !package::valid_hash(hash))
        || entry.parts.is_empty()
        || entry.parts.len() > 128
    {
        return Err(error("catalog_part_manifest_invalid"));
    }
    let count = entry.parts.len();
    let package_filename = format!(
        "lawyer-assistance-mineru-{}-windows-x86_64.laocrpkg",
        entry.component_version
    );
    let mut total = 0u64;
    for (offset, part) in entry.parts.iter().enumerate() {
        let number = u16::try_from(offset + 1).map_err(|_| error("catalog_schema_invalid"))?;
        let expected = format!("{package_filename}.part{number:04}-of-{count:04}");
        if part.number != number
            || part.file_name != expected
            || part.size_bytes == 0
            || part.size_bytes >= RELEASE_ASSET_LIMIT
            || !package::valid_hash(&part.sha256)
        {
            return Err(error("catalog_part_invalid"));
        }
        validate_official_asset_url(&part.download_url, entry, &expected)?;
        total = total
            .checked_add(part.size_bytes)
            .ok_or_else(|| error("catalog_schema_invalid"))?;
    }
    if total != entry.package_size_bytes {
        return Err(error("catalog_part_total_invalid"));
    }
    Ok(())
}

fn validate_official_asset_url(
    value: &str,
    entry: &ComponentCatalogEntryV1,
    filename: &str,
) -> ComponentResult<Url> {
    let url = Url::parse(value).map_err(|_| error("catalog_url_invalid"))?;
    let expected_path = format!(
        "/shilittle/Lawyer-Assistance/releases/download/mineru-components-v{}/{filename}",
        entry.component_version
    );
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().bytes().any(|byte| matches!(byte, b'%' | b'\\'))
        || url.path() != expected_path
    {
        return Err(error("catalog_url_invalid"));
    }
    Ok(url)
}

pub(super) async fn download_catalog_package(
    entry: &ComponentCatalogEntryV1,
    destination: &Path,
) -> ComponentResult<()> {
    let url = validate_official_url(&entry.download_url, entry)?;
    let client = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .redirect(redirect::Policy::custom(|attempt| {
            let url = attempt.url();
            let safe = attempt.previous().len() <= 5
                && url.scheme() == "https"
                && url.port().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && matches!(
                    url.host_str(),
                    Some("github.com")
                        | Some("objects.githubusercontent.com")
                        | Some("release-assets.githubusercontent.com")
                );
            if safe {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|_| error("download_client_failed"))?;
    download_exact(
        &client,
        url,
        destination,
        entry.package_size_bytes,
        &entry.package_sha256,
        true,
    )
    .await
}

pub(super) async fn download_catalog_parts(
    entry: &ComponentCatalogEntryV1,
    directory: &Path,
) -> ComponentResult<std::path::PathBuf> {
    if entry.parts.is_empty() {
        return Err(error("catalog_schema_invalid"));
    }
    let client = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(DOWNLOAD_TIMEOUT)
        .redirect(redirect::Policy::custom(|attempt| {
            let url = attempt.url();
            let safe = attempt.previous().len() <= 5
                && url.scheme() == "https"
                && url.port().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && matches!(
                    url.host_str(),
                    Some("github.com")
                        | Some("objects.githubusercontent.com")
                        | Some("release-assets.githubusercontent.com")
                );
            if safe {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|_| error("download_client_failed"))?;
    let descriptor_url = validate_official_url(&entry.download_url, entry)?;
    let descriptor_name = descriptor_url
        .path_segments()
        .and_then(Iterator::last)
        .ok_or_else(|| error("catalog_url_invalid"))?;
    let descriptor = directory.join(descriptor_name);
    let descriptor_valid = entry
        .part_set_manifest_size_bytes
        .zip(entry.part_set_manifest_sha256.as_deref())
        .is_some_and(|(size, hash)| {
            package::sha256_pinned_file(&descriptor, size).is_ok_and(
                |(observed_hash, observed_size)| observed_size == size && observed_hash == hash,
            )
        });
    if !descriptor_valid {
        let _ = std::fs::remove_file(&descriptor);
        let result = download_exact(
            &client,
            descriptor_url,
            &descriptor,
            entry
                .part_set_manifest_size_bytes
                .ok_or_else(|| error("catalog_schema_invalid"))?,
            entry
                .part_set_manifest_sha256
                .as_deref()
                .ok_or_else(|| error("catalog_schema_invalid"))?,
            true,
        )
        .await;
        if result.is_err() {
            let _ = std::fs::remove_file(&descriptor);
        }
        result?;
    }
    package::read_part_set_manifest(&descriptor, entry)?;
    for part in &entry.parts {
        let destination = directory.join(&part.file_name);
        if package::sha256_pinned_file(&destination, part.size_bytes)
            .is_ok_and(|(hash, size)| hash == part.sha256 && size == part.size_bytes)
        {
            continue;
        }
        let _ = std::fs::remove_file(&destination);
        let url = validate_official_asset_url(&part.download_url, entry, &part.file_name)?;
        let result = download_exact(
            &client,
            url,
            &destination,
            part.size_bytes,
            &part.sha256,
            true,
        )
        .await;
        if result.is_err() {
            let _ = std::fs::remove_file(&destination);
        }
        result?;
    }
    Ok(descriptor)
}

pub(super) async fn download_exact(
    client: &Client,
    url: Url,
    destination: &Path,
    expected_size: u64,
    expected_sha256: &str,
    official_origin: bool,
) -> ComponentResult<()> {
    if url.scheme() != "https"
        || expected_size == 0
        || expected_size > package::MAX_PACKAGE_BYTES
        || !package::valid_hash(expected_sha256)
    {
        return Err(error("download_policy_rejected"));
    }
    let mut response = client
        .get(url)
        .header(header::ACCEPT, "application/octet-stream")
        .header(header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .map_err(|_| error("download_failed"))?;
    if !response.status().is_success() {
        return Err(error("download_failed"));
    }
    if official_origin
        && !(response.url().scheme() == "https"
            && response.url().port().is_none()
            && response.url().username().is_empty()
            && response.url().password().is_none()
            && matches!(
                response.url().host_str(),
                Some("github.com")
                    | Some("objects.githubusercontent.com")
                    | Some("release-assets.githubusercontent.com")
            ))
    {
        return Err(error("download_policy_rejected"));
    }
    if response.content_length() != Some(expected_size) {
        return Err(error("download_size_mismatch"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| error("download_write_failed"))?;
    let mut downloaded = 0u64;
    let mut hasher = Sha256::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| error("download_failed"))?
    {
        downloaded = downloaded
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| error("download_size_mismatch"))?;
        if downloaded > expected_size {
            return Err(error("download_size_mismatch"));
        }
        output
            .write_all(&chunk)
            .map_err(|_| error("download_write_failed"))?;
        hasher.update(&chunk);
    }
    if downloaded != expected_size || format!("{:x}", hasher.finalize()) != expected_sha256 {
        return Err(error("download_integrity_mismatch"));
    }
    output
        .flush()
        .and_then(|_| output.sync_all())
        .map_err(|_| error("download_write_failed"))?;
    drop(output);
    package::ordinary_file(destination, expected_size)
}

fn safe_filename(value: &str) -> bool {
    (5..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        && !value.contains("..")
}

fn valid_identifier(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}
