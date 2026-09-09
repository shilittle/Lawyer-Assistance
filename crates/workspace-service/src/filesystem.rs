use crate::{Error, Result};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::{Component, Path, PathBuf},
};

pub fn ordinary_chain(path: &Path) -> Result<()> {
    #[cfg(windows)]
    if path.components().any(|c| matches!(c,Component::Prefix(p) if !matches!(p.kind(),std::path::Prefix::Disk(_)|std::path::Prefix::VerbatimDisk(_)))) {
        return Err(Error::new("input_path_rejected"));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(Error::new("input_path_rejected"));
        }
        current.push(component);
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| Error::new("input_path_rejected"))?;
        if metadata.file_type().is_symlink() {
            return Err(Error::new("input_path_rejected"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & (0x400 | 0x1000 | 0x400000) != 0 {
                return Err(Error::new("input_path_rejected"));
            }
        }
    }
    Ok(())
}

pub fn read_inbox(root: &Path, relative: &str) -> Result<(String, Vec<u8>)> {
    if relative.is_empty()
        || relative.len() > 500
        || relative.contains(['\\', ':', '\0'])
        || relative.starts_with('/')
        || relative
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(Error::new("input_path_rejected"));
    }
    ordinary_chain(root)?;
    let path = root.join(relative);
    ordinary_chain(&path)?;
    // Keep all parent directory identities fixed while opening and copying the source.
    #[cfg(windows)]
    let _parents = lock_parent_chain(&path)?;
    let canonical = fs::canonicalize(&path)?;
    if !canonical.starts_with(fs::canonicalize(root)?) {
        return Err(Error::new("input_path_rejected"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let mut file = options
        .open(&path)
        .map_err(|_| Error::new("input_path_rejected"))?;
    #[cfg(windows)]
    if final_handle_path(&file)? != canonical {
        return Err(Error::new("input_changed"));
    }
    ordinary_chain(&path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > 20 * 1024 * 1024 {
        return Err(Error::new("file_too_large"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(20 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || bytes.len() as u64 != before.len()
    {
        return Err(Error::new("input_changed"));
    }
    ordinary_chain(&path)?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| Error::new("input_path_rejected"))?
        .to_owned();
    Ok((name, bytes))
}

#[cfg(windows)]
fn lock_parent_chain(path: &Path) -> Result<Vec<std::fs::File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let mut locked = Vec::new();
    let mut current = PathBuf::new();
    for component in path
        .parent()
        .ok_or_else(|| Error::new("input_path_rejected"))?
        .components()
    {
        current.push(component);
        if !current.is_absolute() {
            continue;
        }
        let file = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x02000000 | 0x00200000)
            .open(&current)
            .map_err(|_| Error::new("input_path_rejected"))?;
        let meta = file.metadata()?;
        if !meta.is_dir() || meta.file_attributes() & (0x400 | 0x1000 | 0x400000) != 0 {
            return Err(Error::new("input_path_rejected"));
        }
        locked.push(file);
    }
    Ok(locked)
}

#[cfg(windows)]
fn final_handle_path(file: &std::fs::File) -> Result<PathBuf> {
    use std::os::windows::{ffi::OsStringExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    let mut buffer = vec![0u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(Error::new("input_path_rejected"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length],
    )))
}
