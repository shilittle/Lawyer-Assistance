use std::{fs, io, os::windows::ffi::OsStrExt, path::Path, ptr};

use windows_sys::Win32::Storage::FileSystem::{ReplaceFileW, REPLACEFILE_WRITE_THROUGH};

fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Atomically installs `replacement` at `destination` on Windows.
///
/// When `destination` exists, Windows performs one ReplaceFile transaction and
/// optionally preserves the previous destination at `backup`. All paths must
/// be sibling files so the replacement cannot cross a volume boundary.
pub fn install(replacement: &Path, destination: &Path, backup: Option<&Path>) -> io::Result<()> {
    if replacement.parent() != destination.parent()
        || backup.is_some_and(|path| path.parent() != destination.parent())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic replacement files must share one directory",
        ));
    }

    if !destination.exists() {
        return fs::rename(replacement, destination);
    }

    let destination = wide_path(destination);
    let replacement = wide_path(replacement);
    let backup = backup.map(wide_path);
    let backup_pointer = backup.as_ref().map_or(ptr::null(), |path| path.as_ptr());
    // SAFETY: all UTF-16 buffers are NUL terminated and live through the call;
    // the reserved pointer arguments are required to be null by ReplaceFileW.
    let succeeded = unsafe {
        ReplaceFileW(
            destination.as_ptr(),
            replacement.as_ptr(),
            backup_pointer,
            REPLACEFILE_WRITE_THROUGH,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_is_atomic_and_preserves_the_previous_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let destination = directory.path().join("active.bin");
        let replacement = directory.path().join("incoming.bin");
        let backup = directory.path().join("previous.bin");
        fs::write(&destination, b"old").expect("old file");
        fs::write(&replacement, b"new").expect("incoming file");

        install(&replacement, &destination, Some(&backup)).expect("atomic replacement");

        assert_eq!(fs::read(&destination).unwrap(), b"new");
        assert_eq!(fs::read(&backup).unwrap(), b"old");
        assert!(!replacement.exists());
    }

    #[test]
    fn paths_from_different_directories_are_rejected() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let error = install(
            &first.path().join("incoming"),
            &second.path().join("active"),
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}
