use privacy::{fixed_local_file_identity, validate_fixed_local_regular_file, vnext::Sha256Hex};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const PATH_DOMAIN: &[u8] = b"lawyer-assistance\0mcp-release-binary-path-v1\0";
const FILE_ID_DOMAIN: &[u8] = b"lawyer-assistance\0mcp-release-binary-file-id-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseBinaryMeasurement {
    pub canonical_path: PathBuf,
    pub path_identity_sha256: Sha256Hex,
    pub file_identity_sha256: Sha256Hex,
    pub binary_sha256: Sha256Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReleaseBinaryError {
    #[error("release binary is unavailable or unsafe")]
    Unsafe,
}

pub fn measure_release_binary(path: &Path) -> Result<ReleaseBinaryMeasurement, ReleaseBinaryError> {
    if !path.is_absolute() || path.file_name() != Some(std::ffi::OsStr::new(binary_file_name())) {
        return Err(ReleaseBinaryError::Unsafe);
    }
    let canonical_path = fs::canonicalize(path).map_err(|_| ReleaseBinaryError::Unsafe)?;
    if canonical_path.file_name() != Some(std::ffi::OsStr::new(binary_file_name())) {
        return Err(ReleaseBinaryError::Unsafe);
    }
    let parent = canonical_path.parent().ok_or(ReleaseBinaryError::Unsafe)?;
    if fs::canonicalize(parent).map_err(|_| ReleaseBinaryError::Unsafe)? != parent {
        return Err(ReleaseBinaryError::Unsafe);
    }
    let metadata = fs::symlink_metadata(&canonical_path).map_err(|_| ReleaseBinaryError::Unsafe)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_BINARY_BYTES
    {
        return Err(ReleaseBinaryError::Unsafe);
    }
    validate_fixed_local_regular_file(&canonical_path).map_err(|_| ReleaseBinaryError::Unsafe)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(&canonical_path)
        .map_err(|_| ReleaseBinaryError::Unsafe)?;
    let opened = file.metadata().map_err(|_| ReleaseBinaryError::Unsafe)?;
    let opened_identity =
        fixed_local_file_identity(&file).map_err(|_| ReleaseBinaryError::Unsafe)?;
    let modified = opened
        .modified()
        .map_err(|_| ReleaseBinaryError::Unsafe)?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReleaseBinaryError::Unsafe)?;
    let created = opened
        .created()
        .map_err(|_| ReleaseBinaryError::Unsafe)?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReleaseBinaryError::Unsafe)?;
    let mut file_identity = Vec::with_capacity(FILE_ID_DOMAIN.len() + 96);
    file_identity.extend_from_slice(FILE_ID_DOMAIN);
    file_identity.extend_from_slice(path_identity(&canonical_path).as_bytes());
    file_identity.extend_from_slice(&opened_identity);
    file_identity.extend_from_slice(&opened.len().to_le_bytes());
    file_identity.extend_from_slice(&modified.as_secs().to_le_bytes());
    file_identity.extend_from_slice(&modified.subsec_nanos().to_le_bytes());
    file_identity.extend_from_slice(&created.as_secs().to_le_bytes());
    file_identity.extend_from_slice(&created.subsec_nanos().to_le_bytes());
    let mut hasher = Sha256::new();
    let copied = std::io::copy(&mut (&mut file).take(MAX_BINARY_BYTES + 1), &mut hasher)
        .map_err(|_| ReleaseBinaryError::Unsafe)?;
    if copied != opened.len() || copied > MAX_BINARY_BYTES {
        return Err(ReleaseBinaryError::Unsafe);
    }
    validate_fixed_local_regular_file(&canonical_path).map_err(|_| ReleaseBinaryError::Unsafe)?;
    let post_path_file = OpenOptions::new()
        .read(true)
        .open(&canonical_path)
        .map_err(|_| ReleaseBinaryError::Unsafe)?;
    let post_path_metadata = post_path_file
        .metadata()
        .map_err(|_| ReleaseBinaryError::Unsafe)?;
    if fixed_local_file_identity(&post_path_file).map_err(|_| ReleaseBinaryError::Unsafe)?
        != opened_identity
        || post_path_metadata.len() != opened.len()
    {
        return Err(ReleaseBinaryError::Unsafe);
    }
    let binary_sha256 =
        Sha256Hex::parse(hex_encode(&hasher.finalize())).map_err(|_| ReleaseBinaryError::Unsafe)?;
    let path_identity_sha256 =
        Sha256Hex::parse(path_identity(&canonical_path)).map_err(|_| ReleaseBinaryError::Unsafe)?;
    let file_identity_sha256 =
        Sha256Hex::parse(hash_bytes(&file_identity)).map_err(|_| ReleaseBinaryError::Unsafe)?;
    Ok(ReleaseBinaryMeasurement {
        canonical_path,
        path_identity_sha256,
        file_identity_sha256,
        binary_sha256,
    })
}

pub const fn binary_file_name() -> &'static str {
    if cfg!(windows) {
        "lawyer-assistance-mcp.exe"
    } else {
        "lawyer-assistance-mcp"
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn path_identity(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PATH_DOMAIN);
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        for unit in path.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
    }
    #[cfg(not(windows))]
    hasher.update(path.as_os_str().as_encoded_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
