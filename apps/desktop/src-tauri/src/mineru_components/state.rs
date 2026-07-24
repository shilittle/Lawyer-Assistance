use super::{error, package, ComponentResult, CurrentComponentV1};
use privacy::{protect_local, unprotect_local};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    sync::atomic::{compiler_fence, Ordering},
};
use uuid::Uuid;

const KEY_FILE: &str = "component-state-key.dpapi";
const CURRENT_FILE: &str = "current.json";
const CATALOG_HIGH_WATER_FILE: &str = "catalog-high-water.json";
const KEY_BYTES: usize = 32;
const MAX_KEY_FILE_BYTES: u64 = 4096;
const MAX_STATE_BYTES: u64 = 256 * 1024;
const CURRENT_DOMAIN: &[u8] = b"LawyerAssistance/MinerU/current/v1\0";
const CATALOG_DOMAIN: &[u8] = b"LawyerAssistance/MinerU/catalog-high-water/v1\0";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedCurrentV1 {
    claims: CurrentComponentV1,
    signature_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogHighWaterV1 {
    schema_version: u16,
    issued_at_unix: u64,
    catalog_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedCatalogHighWaterV1 {
    claims: CatalogHighWaterV1,
    signature_sha256: String,
}

struct SensitiveKey(Vec<u8>);

impl SensitiveKey {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SensitiveKey {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

pub(super) fn write_current(root: &Path, claims: &CurrentComponentV1) -> ComponentResult<()> {
    let key = load_or_create_key(root)?;
    let signed = SignedCurrentV1 {
        signature_sha256: sign(CURRENT_DOMAIN, key.as_slice(), claims)?,
        claims: claims.clone(),
    };
    let bytes = serde_json::to_vec(&signed).map_err(|_| error("current_state_invalid"))?;
    package::atomic_write(&root.join(CURRENT_FILE), &bytes)
}

pub(super) fn read_current(root: &Path) -> ComponentResult<CurrentComponentV1> {
    let bytes = package::read_pinned_local_file(&root.join(CURRENT_FILE), MAX_STATE_BYTES)?;
    let signed: SignedCurrentV1 =
        serde_json::from_slice(&bytes).map_err(|_| error("current_state_invalid"))?;
    let key = load_existing_key(root)?;
    let expected = sign(CURRENT_DOMAIN, key.as_slice(), &signed.claims)?;
    if !constant_time_eq(expected.as_bytes(), signed.signature_sha256.as_bytes()) {
        return Err(error("current_state_signature_invalid"));
    }
    Ok(signed.claims)
}

pub(super) fn authorize_catalog_import(
    root: &Path,
    issued_at_unix: u64,
    catalog_sha256: &str,
) -> ComponentResult<()> {
    let current = read_catalog_high_water(root);
    match current {
        Ok(value) if issued_at_unix < value.issued_at_unix => {
            return Err(error("catalog_rollback_rejected"));
        }
        Ok(value)
            if issued_at_unix == value.issued_at_unix && catalog_sha256 != value.catalog_sha256 =>
        {
            return Err(error("catalog_equivocation_rejected"));
        }
        Ok(value)
            if issued_at_unix == value.issued_at_unix && catalog_sha256 == value.catalog_sha256 =>
        {
            return Ok(());
        }
        Ok(_) => {}
        Err(failure) if failure.code() == "component_file_missing" => {}
        Err(failure) => return Err(failure),
    }
    write_catalog_high_water(root, issued_at_unix, catalog_sha256)
}

pub(super) fn verify_catalog_high_water(
    root: &Path,
    issued_at_unix: u64,
    catalog_sha256: &str,
) -> ComponentResult<()> {
    let value = read_catalog_high_water(root).map_err(|failure| {
        if failure.code() == "component_file_missing" {
            error("catalog_high_water_missing")
        } else {
            failure
        }
    })?;
    if issued_at_unix < value.issued_at_unix {
        return Err(error("catalog_rollback_rejected"));
    }
    if issued_at_unix == value.issued_at_unix && catalog_sha256 != value.catalog_sha256 {
        return Err(error("catalog_equivocation_rejected"));
    }
    if issued_at_unix > value.issued_at_unix {
        // A crash can commit the new externally signed catalog immediately
        // before advancing the local high-water. Advancing here is safe because
        // the caller has already verified the embedded release trust root.
        write_catalog_high_water(root, issued_at_unix, catalog_sha256)?;
    }
    Ok(())
}

fn read_catalog_high_water(root: &Path) -> ComponentResult<CatalogHighWaterV1> {
    let bytes =
        package::read_pinned_local_file(&root.join(CATALOG_HIGH_WATER_FILE), MAX_STATE_BYTES)?;
    let signed: SignedCatalogHighWaterV1 =
        serde_json::from_slice(&bytes).map_err(|_| error("catalog_high_water_invalid"))?;
    if signed.claims.schema_version != 1
        || signed.claims.issued_at_unix == 0
        || !package::valid_hash(&signed.claims.catalog_sha256)
    {
        return Err(error("catalog_high_water_invalid"));
    }
    let key = load_existing_key(root)?;
    let expected = sign(CATALOG_DOMAIN, key.as_slice(), &signed.claims)?;
    if !constant_time_eq(expected.as_bytes(), signed.signature_sha256.as_bytes()) {
        return Err(error("catalog_high_water_signature_invalid"));
    }
    Ok(signed.claims)
}

fn write_catalog_high_water(
    root: &Path,
    issued_at_unix: u64,
    catalog_sha256: &str,
) -> ComponentResult<()> {
    if issued_at_unix == 0 || !package::valid_hash(catalog_sha256) {
        return Err(error("catalog_high_water_invalid"));
    }
    let claims = CatalogHighWaterV1 {
        schema_version: 1,
        issued_at_unix,
        catalog_sha256: catalog_sha256.to_owned(),
    };
    let key = load_or_create_key(root)?;
    let signed = SignedCatalogHighWaterV1 {
        signature_sha256: sign(CATALOG_DOMAIN, key.as_slice(), &claims)?,
        claims,
    };
    let bytes = serde_json::to_vec(&signed).map_err(|_| error("catalog_high_water_invalid"))?;
    package::atomic_write(&root.join(CATALOG_HIGH_WATER_FILE), &bytes)
}

fn load_or_create_key(root: &Path) -> ComponentResult<SensitiveKey> {
    let path = root.join(KEY_FILE);
    if path.exists() {
        return load_existing_key(root);
    }
    let mut key = Vec::with_capacity(KEY_BYTES);
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    let protected = protect_local(&key).map_err(|_| error("component_state_key_unavailable"))?;
    let incoming = root.join(format!(".state-key-{}.incoming", Uuid::new_v4()));
    package::write_new_file(&incoming, &protected)?;
    match fs::rename(&incoming, &path) {
        Ok(()) => Ok(SensitiveKey(key)),
        Err(failure) if failure.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&incoming);
            load_existing_key(root)
        }
        Err(_) => {
            let _ = fs::remove_file(&incoming);
            Err(error("component_state_key_unavailable"))
        }
    }
}

fn load_existing_key(root: &Path) -> ComponentResult<SensitiveKey> {
    let protected = package::read_pinned_local_file(&root.join(KEY_FILE), MAX_KEY_FILE_BYTES)?;
    let key = unprotect_local(&protected).map_err(|_| error("component_state_key_unavailable"))?;
    if key.len() != KEY_BYTES {
        return Err(error("component_state_key_invalid"));
    }
    Ok(SensitiveKey(key))
}

fn sign<T: Serialize>(domain: &[u8], key: &[u8], claims: &T) -> ComponentResult<String> {
    let bytes = serde_json::to_vec(claims).map_err(|_| error("component_state_sign_failed"))?;
    Ok(hex(&hmac_sha256(key, domain, &bytes)))
}

fn hmac_sha256(key: &[u8], domain: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(domain);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |difference, (left, right)| difference | (left ^ right))
            == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}
