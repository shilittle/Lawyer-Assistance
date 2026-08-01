#![allow(unsafe_code)]

pub const LOCAL_PROTECTION_SCHEME: &str = "windows_dpapi_current_user_v1";
pub const MAX_PROTECTED_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(windows)]
const OPTIONAL_ENTROPY: &[u8] = b"LawyerAssistance/privacy/local-protected-blob/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedBlobError {
    EmptyInput,
    InputTooLarge,
    PlatformUnavailable,
    ProtectFailed,
    UnprotectFailed,
    InvalidOutput,
}

impl ProtectedBlobError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyInput => "protected_blob_empty",
            Self::InputTooLarge => "protected_blob_too_large",
            Self::PlatformUnavailable => "protected_blob_platform_unavailable",
            Self::ProtectFailed => "protected_blob_protect_failed",
            Self::UnprotectFailed => "protected_blob_unprotect_failed",
            Self::InvalidOutput => "protected_blob_invalid_output",
        }
    }
}

impl std::fmt::Display for ProtectedBlobError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProtectedBlobError {}

pub fn protect_local(plaintext: &[u8]) -> Result<Vec<u8>, ProtectedBlobError> {
    if plaintext.is_empty() {
        return Err(ProtectedBlobError::EmptyInput);
    }
    if plaintext.len() > MAX_PROTECTED_PLAINTEXT_BYTES {
        return Err(ProtectedBlobError::InputTooLarge);
    }
    platform::protect(plaintext)
}

pub fn unprotect_local(ciphertext: &[u8]) -> Result<Vec<u8>, ProtectedBlobError> {
    if ciphertext.is_empty() {
        return Err(ProtectedBlobError::EmptyInput);
    }
    if ciphertext.len() > MAX_PROTECTED_PLAINTEXT_BYTES.saturating_mul(2) {
        return Err(ProtectedBlobError::InputTooLarge);
    }
    platform::unprotect(ciphertext)
}

#[cfg(windows)]
mod platform {
    use super::{ProtectedBlobError, OPTIONAL_ENTROPY};
    use std::{
        ffi::c_void,
        ptr, slice,
        sync::atomic::{compiler_fence, Ordering},
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, ProtectedBlobError> {
        let input_len =
            u32::try_from(plaintext.len()).map_err(|_| ProtectedBlobError::InputTooLarge)?;
        let entropy_len =
            u32::try_from(OPTIONAL_ENTROPY.len()).map_err(|_| ProtectedBlobError::InputTooLarge)?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: input_len,
            pbData: plaintext.as_ptr().cast_mut(),
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: entropy_len,
            pbData: OPTIONAL_ENTROPY.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptProtectData(
                &input,
                ptr::null(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            free_output(&mut output, false);
            return Err(ProtectedBlobError::ProtectFailed);
        }
        copy_and_free(&mut output, false)
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, ProtectedBlobError> {
        let input_len =
            u32::try_from(ciphertext.len()).map_err(|_| ProtectedBlobError::InputTooLarge)?;
        let entropy_len =
            u32::try_from(OPTIONAL_ENTROPY.len()).map_err(|_| ProtectedBlobError::InputTooLarge)?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: input_len,
            pbData: ciphertext.as_ptr().cast_mut(),
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: entropy_len,
            pbData: OPTIONAL_ENTROPY.as_ptr().cast_mut(),
        };
        let mut output = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                &entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            free_output(&mut output, true);
            return Err(ProtectedBlobError::UnprotectFailed);
        }
        copy_and_free(&mut output, true)
    }

    fn copy_and_free(
        output: &mut CRYPT_INTEGER_BLOB,
        clear_before_free: bool,
    ) -> Result<Vec<u8>, ProtectedBlobError> {
        if output.pbData.is_null() || output.cbData == 0 {
            free_output(output, clear_before_free);
            return Err(ProtectedBlobError::InvalidOutput);
        }
        let length = output.cbData as usize;
        let bytes = unsafe { slice::from_raw_parts(output.pbData, length) }.to_vec();
        free_output(output, clear_before_free);
        Ok(bytes)
    }

    fn free_output(output: &mut CRYPT_INTEGER_BLOB, clear_before_free: bool) {
        if !output.pbData.is_null() {
            if clear_before_free {
                for index in 0..output.cbData as usize {
                    unsafe {
                        ptr::write_volatile(output.pbData.add(index), 0);
                    }
                }
                compiler_fence(Ordering::SeqCst);
            }
            let _ = unsafe { LocalFree(output.pbData.cast::<c_void>()) };
            output.pbData = ptr::null_mut();
            output.cbData = 0;
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::ProtectedBlobError;

    pub fn protect(_plaintext: &[u8]) -> Result<Vec<u8>, ProtectedBlobError> {
        Err(ProtectedBlobError::PlatformUnavailable)
    }

    pub fn unprotect(_ciphertext: &[u8]) -> Result<Vec<u8>, ProtectedBlobError> {
        Err(ProtectedBlobError::PlatformUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn dpapi_round_trip_does_not_store_plaintext_and_detects_tampering() {
        let plaintext = "张三|11010519491231002X|映射表".as_bytes();
        let protected = protect_local(plaintext).expect("protect");
        assert_ne!(protected, plaintext);
        assert!(!protected
            .windows("11010519491231002X".len())
            .any(|window| window == b"11010519491231002X"));
        assert_eq!(unprotect_local(&protected).expect("unprotect"), plaintext);

        let mut tampered = protected;
        let middle = tampered.len() / 2;
        tampered[middle] ^= 0x5a;
        assert!(unprotect_local(&tampered).is_err());
    }

    #[test]
    fn empty_values_are_rejected_without_calling_the_platform() {
        assert_eq!(protect_local(b""), Err(ProtectedBlobError::EmptyInput));
        assert_eq!(unprotect_local(b""), Err(ProtectedBlobError::EmptyInput));
    }
}
