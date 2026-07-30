#[cfg(windows)]
fn validate_vault_file_identity(path: &Path) -> Result<(), VaultStoreError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| VaultStoreError::ObjectNotAvailable)?;
    fixed_local_file_identity(&file).map(|_| ())
}

/// Return the fixed-volume OS identity for an already-open regular file.
///
/// The identity is obtained from the open handle, so callers can authenticate
/// that same handle and compare it with a fresh path open to detect replacement.
#[cfg(windows)]
pub fn fixed_local_file_identity(file: &File) -> Result<Vec<u8>, VaultStoreError> {
    use std::{mem::zeroed, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    let success = unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            &mut information,
        )
    };
    if success == 0
        || information.nNumberOfLinks != 1
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    let mut identity = Vec::with_capacity(12);
    identity.extend_from_slice(&information.dwVolumeSerialNumber.to_le_bytes());
    identity.extend_from_slice(&file_index.to_le_bytes());
    Ok(identity)
}

#[cfg(not(windows))]
fn validate_vault_file_identity(path: &Path) -> Result<(), VaultStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fs::symlink_metadata(path)
            .map_err(|_| VaultStoreError::ObjectNotAvailable)?
            .nlink()
            != 1
        {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn fixed_local_file_identity(file: &File) -> Result<Vec<u8>, VaultStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file
            .metadata()
            .map_err(|_| VaultStoreError::ObjectNotAvailable)?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        let mut identity = Vec::with_capacity(16);
        identity.extend_from_slice(&metadata.dev().to_le_bytes());
        identity.extend_from_slice(&metadata.ino().to_le_bytes());
        Ok(identity)
    }
    #[cfg(not(unix))]
    Err(VaultStoreError::PlatformUnavailable)
}
