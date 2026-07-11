#[cfg(windows)]
mod platform {
    use crate::{
        credentials::{ApiSecret, CredentialStore, ProviderCredentialKey},
        types::{ProviderError, ProviderErrorKind},
    };
    use std::{ffi::c_void, ptr, slice};
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_NOT_FOUND},
        Security::Credentials::{
            CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
            CRED_TYPE_GENERIC,
        },
    };

    #[derive(Debug, Clone)]
    pub struct WindowsCredentialStore {
        service_prefix: String,
    }

    impl Default for WindowsCredentialStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WindowsCredentialStore {
        pub fn new() -> Self {
            Self {
                service_prefix: "LawyerAssistance".to_owned(),
            }
        }

        pub fn with_service_prefix(service_prefix: impl Into<String>) -> Self {
            Self {
                service_prefix: service_prefix.into(),
            }
        }

        fn target_name(&self, key: &ProviderCredentialKey) -> String {
            format!(
                "{}/provider/{}/account/{}",
                self.service_prefix,
                sanitize_component(&key.provider_id),
                sanitize_component(&key.account_id)
            )
        }
    }

    impl CredentialStore for WindowsCredentialStore {
        type Error = ProviderError;

        fn read_api_key(
            &self,
            key: &ProviderCredentialKey,
        ) -> Result<Option<ApiSecret>, Self::Error> {
            let target_name = wide_null(self.target_name(key));
            let mut credential_ptr: *mut CREDENTIALW = ptr::null_mut();

            let ok = unsafe {
                CredReadW(
                    target_name.as_ptr(),
                    CRED_TYPE_GENERIC,
                    0,
                    &mut credential_ptr,
                )
            };

            if ok == 0 {
                let error_code = unsafe { GetLastError() };
                if error_code == ERROR_NOT_FOUND {
                    return Ok(None);
                }

                return Err(ProviderError::new(
                    ProviderErrorKind::Credential,
                    format!("Credential Manager read failed with Windows error {error_code}"),
                ));
            }

            let result = unsafe {
                let credential = &*credential_ptr;
                let bytes = slice::from_raw_parts(
                    credential.CredentialBlob,
                    credential.CredentialBlobSize as usize,
                );
                let value = String::from_utf8(bytes.to_vec()).map_err(|error| {
                    ProviderError::new(
                        ProviderErrorKind::Credential,
                        format!("Credential Manager value was not UTF-8: {error}"),
                    )
                });
                CredFree(credential_ptr.cast::<c_void>());
                value
            }?;

            Ok(Some(ApiSecret::new(result)))
        }

        fn write_api_key(
            &self,
            key: &ProviderCredentialKey,
            secret: ApiSecret,
        ) -> Result<(), Self::Error> {
            let mut target_name = wide_null(self.target_name(key));
            let mut user_name = wide_null("Lawyer Assistance");
            let mut secret_bytes = secret.expose_secret().as_bytes().to_vec();

            let credential = CREDENTIALW {
                Flags: 0,
                Type: CRED_TYPE_GENERIC,
                TargetName: target_name.as_mut_ptr(),
                Comment: ptr::null_mut(),
                LastWritten: Default::default(),
                CredentialBlobSize: secret_bytes.len() as u32,
                CredentialBlob: secret_bytes.as_mut_ptr(),
                Persist: CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount: 0,
                Attributes: ptr::null_mut(),
                TargetAlias: ptr::null_mut(),
                UserName: user_name.as_mut_ptr(),
            };

            let ok = unsafe { CredWriteW(&credential, 0) };

            if ok == 0 {
                let error_code = unsafe { GetLastError() };
                return Err(ProviderError::new(
                    ProviderErrorKind::Credential,
                    format!("Credential Manager write failed with Windows error {error_code}"),
                ));
            }

            Ok(())
        }

        fn delete_api_key(&self, key: &ProviderCredentialKey) -> Result<(), Self::Error> {
            let target_name = wide_null(self.target_name(key));
            let ok = unsafe { CredDeleteW(target_name.as_ptr(), CRED_TYPE_GENERIC, 0) };

            if ok == 0 {
                let error_code = unsafe { GetLastError() };
                if error_code == ERROR_NOT_FOUND {
                    return Ok(());
                }

                return Err(ProviderError::new(
                    ProviderErrorKind::Credential,
                    format!("Credential Manager delete failed with Windows error {error_code}"),
                ));
            }

            Ok(())
        }
    }

    fn wide_null(value: impl AsRef<str>) -> Vec<u16> {
        value.as_ref().encode_utf16().chain([0]).collect()
    }

    fn sanitize_component(value: &str) -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::{SystemTime, UNIX_EPOCH};

        fn test_store() -> (String, WindowsCredentialStore, ProviderCredentialKey) {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time is after epoch")
                .as_nanos();
            let prefix = format!("LawyerAssistanceTest-{}-{suffix}", std::process::id());
            let key = ProviderCredentialKey::new("deepseek-test", "default");

            (
                prefix.clone(),
                WindowsCredentialStore::with_service_prefix(prefix),
                key,
            )
        }

        #[test]
        fn credential_manager_covers_write_query_overwrite_delete_and_missing_key() {
            let (prefix, store, key) = test_store();
            store
                .delete_api_key(&key)
                .expect("pre-test cleanup succeeds");

            assert!(store
                .read_api_key(&key)
                .expect("missing credential can be queried")
                .is_none());

            store
                .write_api_key(&key, ApiSecret::new("cred-manager-secret-1111"))
                .expect("credential writes");
            let reopened_store = WindowsCredentialStore::with_service_prefix(prefix.clone());
            let secret = reopened_store
                .read_api_key(&key)
                .expect("credential reads after store recreation")
                .expect("credential persists after store recreation");
            assert_eq!(secret.expose_secret(), "cred-manager-secret-1111");
            assert_eq!(secret.masked_last_four(), "****1111");

            store
                .write_api_key(&key, ApiSecret::new("cred-manager-secret-2222"))
                .expect("credential overwrites");
            let secret = store
                .read_api_key(&key)
                .expect("credential reads after overwrite")
                .expect("credential exists after overwrite");
            assert_eq!(secret.expose_secret(), "cred-manager-secret-2222");

            WindowsCredentialStore::with_service_prefix(prefix)
                .delete_api_key(&key)
                .expect("credential deletes after another store recreation");
            assert!(store
                .read_api_key(&key)
                .expect("deleted credential can be queried")
                .is_none());
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use crate::{
        credentials::{ApiSecret, CredentialStore, ProviderCredentialKey},
        types::{ProviderError, ProviderErrorKind},
    };

    #[derive(Debug, Clone, Default)]
    pub struct WindowsCredentialStore;

    impl WindowsCredentialStore {
        pub fn new() -> Self {
            Self
        }
    }

    impl CredentialStore for WindowsCredentialStore {
        type Error = ProviderError;

        fn read_api_key(
            &self,
            _key: &ProviderCredentialKey,
        ) -> Result<Option<ApiSecret>, Self::Error> {
            Err(ProviderError::new(
                ProviderErrorKind::Credential,
                "Windows Credential Manager is only available on Windows",
            ))
        }

        fn write_api_key(
            &self,
            _key: &ProviderCredentialKey,
            _secret: ApiSecret,
        ) -> Result<(), Self::Error> {
            Err(ProviderError::new(
                ProviderErrorKind::Credential,
                "Windows Credential Manager is only available on Windows",
            ))
        }

        fn delete_api_key(&self, _key: &ProviderCredentialKey) -> Result<(), Self::Error> {
            Err(ProviderError::new(
                ProviderErrorKind::Credential,
                "Windows Credential Manager is only available on Windows",
            ))
        }
    }
}

pub use platform::WindowsCredentialStore;
