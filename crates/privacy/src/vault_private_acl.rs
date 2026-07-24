// Included from vault_store.rs. This is intentionally a Windows current-user boundary. It
// prevents inherited broad-user access but cannot isolate another process running as the same
// Windows account. A service-identity broker can replace the App broker without changing the
// encrypted object protocol.

#[cfg(windows)]
fn enforce_vault_private_acl_tree(root: &Path) -> Result<(), VaultStoreError> {
    use std::os::windows::fs::MetadataExt as _;

    const REPARSE_POINT: u32 = 0x0000_0400;
    const MAX_ENTRIES: usize = 500_000;

    fn collect(path: &Path, paths: &mut Vec<PathBuf>) -> Result<(), VaultStoreError> {
        if paths.len() >= MAX_ENTRIES {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| VaultStoreError::IoFailed)?;
        if metadata.file_type().is_symlink() || metadata.file_attributes() & REPARSE_POINT != 0 {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        if metadata.is_file() {
            validate_vault_file_identity(path)?;
        } else if !metadata.is_dir() {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        paths.push(path.to_path_buf());
        if metadata.is_dir() {
            let mut children = fs::read_dir(path)
                .map_err(|_| VaultStoreError::IoFailed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| VaultStoreError::IoFailed)?;
            children.sort_by_key(std::fs::DirEntry::file_name);
            for child in children {
                collect(&child.path(), paths)?;
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    collect(root, &mut paths)?;
    let descriptor = windows_private_descriptor()?;
    for path in paths {
        set_private_acl(&path, descriptor.as_ptr())?;
    }
    if verify_vault_private_acl(root)? {
        Ok(())
    } else {
        Err(VaultStoreError::UnsafeFilesystem)
    }
}

#[cfg(not(windows))]
fn enforce_vault_private_acl_tree(_root: &Path) -> Result<(), VaultStoreError> {
    Err(VaultStoreError::PlatformUnavailable)
}

#[cfg(windows)]
fn verify_vault_private_acl(path: &Path) -> Result<bool, VaultStoreError> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt as _};
    const DACL: u32 = 0x0000_0004;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetFileSecurityW(
            name: *const u16,
            requested: u32,
            descriptor: *mut c_void,
            length: u32,
            needed: *mut u32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *const c_void,
            revision: u32,
            information: u32,
            output: *mut *mut u16,
            output_len: *mut u32,
        ) -> i32;
    }
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut needed = 0_u32;
    // SAFETY: A null buffer intentionally queries the required descriptor size.
    unsafe {
        GetFileSecurityW(wide.as_ptr(), DACL, std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    let mut descriptor =
        vec![0_u8; usize::try_from(needed).map_err(|_| VaultStoreError::IoFailed)?];
    // SAFETY: The buffer has the exact size returned by Windows.
    if unsafe {
        GetFileSecurityW(
            wide.as_ptr(),
            DACL,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    let mut sddl = std::ptr::null_mut::<u16>();
    let mut sddl_len = 0_u32;
    // SAFETY: Windows populated the descriptor and returns a LocalAlloc-owned string.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.as_ptr().cast(),
            1,
            DACL,
            &mut sddl,
            &mut sddl_len,
        )
    } == 0
        || sddl.is_null()
    {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    let _owned = LocalAllocation(sddl.cast());
    // SAFETY: Windows reports the UTF-16 length excluding the trailing nul.
    let text = String::from_utf16(unsafe {
        std::slice::from_raw_parts(
            sddl,
            usize::try_from(sddl_len).map_err(|_| VaultStoreError::IoFailed)?,
        )
    })
    .map_err(|_| VaultStoreError::UnsafeFilesystem)?;
    let aces = text
        .split('(')
        .skip(1)
        .filter_map(|entry| entry.split_once(')').map(|pair| pair.0))
        .collect::<Vec<_>>();
    let trustees = aces
        .iter()
        .filter_map(|ace| ace.rsplit(';').next())
        .collect::<BTreeSet<_>>();
    Ok(text.starts_with("D:P")
        && aces.len() == 3
        && aces.iter().all(|ace| ace.starts_with("A;OICI;FA;;;"))
        && trustees == BTreeSet::from(["BA", "OW", "SY"]))
}

#[cfg(not(windows))]
fn verify_vault_private_acl(_path: &Path) -> Result<bool, VaultStoreError> {
    Err(VaultStoreError::PlatformUnavailable)
}

#[cfg(windows)]
struct LocalAllocation(*mut std::ffi::c_void);

#[cfg(windows)]
impl LocalAllocation {
    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0
    }
}

#[cfg(windows)]
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        }
        // SAFETY: The pointer was allocated by a Windows SDDL conversion API.
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[cfg(windows)]
fn windows_private_descriptor() -> Result<LocalAllocation, VaultStoreError> {
    use std::ffi::c_void;
    const SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)";
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            input: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            descriptor_size: *mut u32,
        ) -> i32;
    }
    let wide = SDDL.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut::<c_void>();
    let mut size = 0_u32;
    // SAFETY: The SDDL is nul-terminated and output pointers are valid.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            1,
            &mut descriptor,
            &mut size,
        )
    } == 0
        || descriptor.is_null()
        || size == 0
    {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    Ok(LocalAllocation(descriptor))
}

#[cfg(windows)]
fn set_private_acl(path: &Path, descriptor: *mut std::ffi::c_void) -> Result<(), VaultStoreError> {
    use std::os::windows::ffi::OsStrExt as _;
    const DACL: u32 = 0x0000_0004;
    const PROTECTED_DACL: u32 = 0x8000_0000;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn SetFileSecurityW(
            name: *const u16,
            information: u32,
            descriptor: *mut std::ffi::c_void,
        ) -> i32;
    }
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: The path is nul-terminated and descriptor remains owned by the caller.
    if unsafe { SetFileSecurityW(wide.as_ptr(), DACL | PROTECTED_DACL, descriptor) } == 0 {
        Err(VaultStoreError::UnsafeFilesystem)
    } else {
        Ok(())
    }
}

#[cfg(all(test, windows))]
#[test]
fn private_acl_is_protected_and_excludes_broad_principals() {
    let root = std::env::temp_dir().join(format!(
        "la-vault-private-acl-test-{}",
        random_hex(16).expect("random")
    ));
    let workspace =
        WorkspaceInstanceId::parse("ws_0123456789abcdef0123456789abcdef").expect("workspace");
    let store = VaultStore::initialize(&root, workspace).expect("private vault");
    let status = store.isolation_status().expect("isolation status");
    assert!(status.private_acl_enforced);
    assert!(status.content_indexing_disabled);
    assert!(!status.strong_service_identity_boundary);
    assert!(verify_vault_private_acl(&root).expect("verified DACL"));
    fs::remove_dir_all(&root).expect("remove private vault");
}
