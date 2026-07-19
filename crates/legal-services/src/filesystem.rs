use crate::{audit::sha256_hex, ServiceError};
#[cfg(unix)]
use std::{ffi::OsStr, path::Component};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    first: u64,
    second: u64,
}

/// Keeps an existing filesystem object open while a path-based API opens or
/// mutates it. On Windows the handle deliberately omits delete sharing, so a
/// checked database or directory cannot be swapped out between validation and
/// use. Other platforms still receive before/after device+inode checks.
#[derive(Debug)]
pub(crate) struct PathIdentityGuard {
    path: PathBuf,
    _handle: fs::File,
    identity: FileIdentity,
    directory: bool,
    require_single_link: bool,
    verify_path: bool,
}

impl PathIdentityGuard {
    pub(crate) fn regular_file(
        path: &Path,
        require_single_link: bool,
    ) -> Result<Self, ServiceError> {
        Self::open(path, false, require_single_link)
    }

    pub(crate) fn directory(path: &Path) -> Result<Self, ServiceError> {
        Self::open(path, true, false)
    }

    fn open(path: &Path, directory: bool, require_single_link: bool) -> Result<Self, ServiceError> {
        let handle = open_identity_handle(path, directory).map_err(|_| path_rejected())?;
        Self::from_handle(
            path.to_path_buf(),
            handle,
            directory,
            require_single_link,
            true,
        )
    }

    fn from_handle(
        path: PathBuf,
        handle: fs::File,
        directory: bool,
        require_single_link: bool,
        verify_path: bool,
    ) -> Result<Self, ServiceError> {
        let metadata = handle.metadata().map_err(|_| path_rejected())?;
        if is_reparse_or_symlink(&metadata)
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            return Err(path_rejected());
        }
        if require_single_link && link_count(&handle, &metadata)? != 1 {
            return Err(ServiceError::new(
                "filesystem_hardlink_rejected",
                "security-sensitive files must have exactly one filesystem link",
                false,
            ));
        }
        let identity = file_identity(&handle, &metadata)?;
        Ok(Self {
            path: path.to_path_buf(),
            _handle: handle,
            identity,
            directory,
            require_single_link,
            verify_path,
        })
    }

    pub(crate) fn verify(&self) -> Result<(), ServiceError> {
        let metadata = self._handle.metadata().map_err(|_| path_rejected())?;
        if file_identity(&self._handle, &metadata)? != self.identity
            || (self.require_single_link && link_count(&self._handle, &metadata)? != 1)
        {
            return Err(ServiceError::new(
                "filesystem_identity_changed",
                "a security-sensitive filesystem object changed during the operation",
                true,
            ));
        }
        if self.verify_path {
            let current = Self::open(&self.path, self.directory, self.require_single_link)?;
            if current.identity != self.identity {
                return Err(ServiceError::new(
                    "filesystem_identity_changed",
                    "a security-sensitive filesystem object changed during the operation",
                    true,
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn opaque_identity(&self) -> String {
        sha256_hex(format!("v1:{}:{}", self.identity.first, self.identity.second).as_bytes())
    }

    /// Reads a regular file through the exact handle whose identity and link
    /// count were validated. This avoids reopening a checked path and keeps
    /// the byte limit effective even if the file grows while it is read.
    pub(crate) fn read_bounded(&self, max_bytes: usize) -> Result<Vec<u8>, ServiceError> {
        if self.directory {
            return Err(path_rejected());
        }
        let metadata = self._handle.metadata().map_err(|_| path_rejected())?;
        if metadata.len() > max_bytes as u64 {
            return Err(ServiceError::new(
                "material_file_too_large",
                "source material exceeds the configured file size limit",
                false,
            ));
        }
        let mut handle = self._handle.try_clone()?;
        handle.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len())
                .unwrap_or(max_bytes)
                .min(max_bytes),
        );
        handle
            .take(
                u64::try_from(max_bytes)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)?;
        if bytes.len() > max_bytes {
            return Err(ServiceError::new(
                "material_file_too_large",
                "source material exceeds the configured file size limit",
                false,
            ));
        }
        self.verify()?;
        Ok(bytes)
    }

    #[cfg(unix)]
    pub(crate) fn directory_child(
        &self,
        name: &OsStr,
        display_path: PathBuf,
    ) -> Result<Self, ServiceError> {
        use rustix::fs::{openat, Mode, OFlags};

        require_single_component(name)?;
        let descriptor = openat(
            &self._handle,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        Self::from_handle(display_path, descriptor.into(), true, false, false)
    }

    #[cfg(unix)]
    pub(crate) fn open_regular_child(
        &self,
        name: &OsStr,
        require_single_link: bool,
    ) -> Result<fs::File, ServiceError> {
        use rustix::fs::{openat, Mode, OFlags};

        require_single_component(name)?;
        let descriptor = openat(
            &self._handle,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let file: fs::File = descriptor.into();
        validate_open_regular_file(&file, require_single_link)?;
        Ok(file)
    }

    #[cfg(unix)]
    pub(crate) fn regular_child(
        &self,
        name: &OsStr,
        display_path: PathBuf,
        require_single_link: bool,
    ) -> Result<Self, ServiceError> {
        let file = self.open_regular_child(name, require_single_link)?;
        Self::from_handle(display_path, file, false, require_single_link, false)
    }

    #[cfg(unix)]
    pub(crate) fn create_new_child(&self, name: &OsStr) -> Result<fs::File, ServiceError> {
        use rustix::fs::{openat, Mode, OFlags};

        require_single_component(name)?;
        let descriptor = openat(
            &self._handle,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(std::io::Error::from)?;
        Ok(descriptor.into())
    }

    #[cfg(unix)]
    pub(crate) fn hard_link_child(
        &self,
        source: &OsStr,
        destination: &OsStr,
    ) -> Result<(), ServiceError> {
        use rustix::fs::{linkat, AtFlags};

        require_single_component(source)?;
        require_single_component(destination)?;
        linkat(
            &self._handle,
            source,
            &self._handle,
            destination,
            AtFlags::empty(),
        )
        .map_err(std::io::Error::from)?;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn rename_child(
        &self,
        source: &OsStr,
        destination: &OsStr,
    ) -> Result<(), ServiceError> {
        use rustix::fs::renameat;

        require_single_component(source)?;
        require_single_component(destination)?;
        renameat(&self._handle, source, &self._handle, destination)
            .map_err(std::io::Error::from)?;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn unlink_child(&self, name: &OsStr) -> Result<(), ServiceError> {
        use rustix::fs::{unlinkat, AtFlags};

        require_single_component(name)?;
        unlinkat(&self._handle, name, AtFlags::empty()).map_err(std::io::Error::from)?;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn child_exists(&self, name: &OsStr) -> Result<bool, ServiceError> {
        use rustix::fs::{statat, AtFlags};

        require_single_component(name)?;
        match statat(&self._handle, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(error) => Err(std::io::Error::from(error).into()),
        }
    }

    #[cfg(unix)]
    pub(crate) fn sync_all(&self) -> Result<(), ServiceError> {
        self._handle.sync_all()?;
        self.verify()
    }
}

#[cfg(unix)]
fn require_single_component(name: &OsStr) -> Result<(), ServiceError> {
    let path = Path::new(name);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(path_rejected());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_open_regular_file(
    file: &fs::File,
    require_single_link: bool,
) -> Result<(), ServiceError> {
    let metadata = file.metadata().map_err(|_| path_rejected())?;
    if is_reparse_or_symlink(&metadata) || !metadata.is_file() {
        return Err(path_rejected());
    }
    if require_single_link && link_count(file, &metadata)? != 1 {
        return Err(ServiceError::new(
            "filesystem_hardlink_rejected",
            "security-sensitive files must have exactly one filesystem link",
            false,
        ));
    }
    Ok(())
}

fn path_rejected() -> ServiceError {
    ServiceError::new(
        "filesystem_path_rejected",
        "security-sensitive path must name an accessible non-reparse filesystem object",
        false,
    )
}

#[cfg(windows)]
fn open_identity_handle(path: &Path, directory: bool) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    options.custom_flags(flags);
    options.open(path)
}

#[cfg(unix)]
fn open_identity_handle(path: &Path, directory: bool) -> std::io::Result<fs::File> {
    use rustix::fs::{open, Mode, OFlags};

    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    open(path, flags, Mode::empty())
        .map(Into::into)
        .map_err(Into::into)
}

#[cfg(not(any(unix, windows)))]
fn open_identity_handle(path: &Path, _directory: bool) -> std::io::Result<fs::File> {
    fs::File::open(path)
}

#[cfg(windows)]
fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn windows_file_information(
    handle: &fs::File,
) -> Result<windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION, ServiceError> {
    use std::{mem, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION},
    };

    // SAFETY: `handle` is live for the duration of the call and `information`
    // points to an initialized, correctly-sized output structure.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    let result =
        unsafe { GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut information) };
    if result == 0 {
        return Err(path_rejected());
    }
    Ok(information)
}

#[cfg(windows)]
fn link_count(handle: &fs::File, _metadata: &fs::Metadata) -> Result<u64, ServiceError> {
    Ok(u64::from(windows_file_information(handle)?.nNumberOfLinks))
}

#[cfg(unix)]
fn link_count(_handle: &fs::File, metadata: &fs::Metadata) -> Result<u64, ServiceError> {
    use std::os::unix::fs::MetadataExt;
    Ok(metadata.nlink())
}

#[cfg(not(any(unix, windows)))]
fn link_count(_handle: &fs::File, _metadata: &fs::Metadata) -> Result<u64, ServiceError> {
    Ok(1)
}

#[cfg(windows)]
fn file_identity(
    handle: &fs::File,
    _metadata: &fs::Metadata,
) -> Result<FileIdentity, ServiceError> {
    let information = windows_file_information(handle)?;
    Ok(FileIdentity {
        first: u64::from(information.dwVolumeSerialNumber),
        second: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(unix)]
fn file_identity(
    _handle: &fs::File,
    metadata: &fs::Metadata,
) -> Result<FileIdentity, ServiceError> {
    use std::os::unix::fs::MetadataExt;
    Ok(FileIdentity {
        first: metadata.dev(),
        second: metadata.ino(),
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(
    _handle: &fs::File,
    metadata: &fs::Metadata,
) -> Result<FileIdentity, ServiceError> {
    use std::time::UNIX_EPOCH;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |value| value.as_nanos() as u64);
    Ok(FileIdentity {
        first: metadata.len(),
        second: modified,
    })
}
