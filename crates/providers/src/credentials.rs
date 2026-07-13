use serde::Deserialize;
use std::fmt::{self, Debug};

#[derive(Clone, PartialEq, Eq)]
pub struct ApiSecret(String);

impl ApiSecret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn masked_last_four(&self) -> String {
        mask_secret_last_four(&self.0)
    }
}

impl Debug for ApiSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiSecret")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl<'de> Deserialize<'de> for ApiSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self)
    }
}

pub fn mask_secret_last_four(secret: &str) -> String {
    let character_count = secret.chars().count();
    if character_count == 0 {
        return "not_configured".to_owned();
    }
    if character_count <= 4 {
        return "****".to_owned();
    }

    let suffix_chars: Vec<char> = secret.chars().rev().take(4).collect();
    let suffix: String = suffix_chars.into_iter().rev().collect();
    format!("****{suffix}")
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProviderCredentialKey {
    pub provider_id: String,
    pub account_id: String,
}

impl ProviderCredentialKey {
    pub fn new(provider_id: impl Into<String>, account_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            account_id: account_id.into(),
        }
    }
}

pub trait CredentialStore {
    type Error;

    fn read_api_key(&self, key: &ProviderCredentialKey) -> Result<Option<ApiSecret>, Self::Error>;

    fn write_api_key(
        &self,
        key: &ProviderCredentialKey,
        secret: ApiSecret,
    ) -> Result<(), Self::Error>;

    fn delete_api_key(&self, key: &ProviderCredentialKey) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = ApiSecret::new("not-for-config-files");

        assert_eq!(format!("{secret:?}"), "ApiSecret { value: \"<redacted>\" }");
    }

    #[test]
    fn secret_mask_exposes_only_last_four_characters() {
        let secret = ApiSecret::new("lawyer-assistance-secret-1234");

        assert_eq!(secret.masked_last_four(), "****1234");
    }

    #[test]
    fn secret_mask_never_exposes_a_complete_short_secret() {
        assert_eq!(mask_secret_last_four(""), "not_configured");
        assert_eq!(mask_secret_last_four("a"), "****");
        assert_eq!(mask_secret_last_four("abcd"), "****");
        assert_eq!(mask_secret_last_four("abcde"), "****bcde");
        assert_eq!(mask_secret_last_four("密钥一二"), "****");
        assert_eq!(mask_secret_last_four("密钥一二三"), "****钥一二三");
    }

    #[test]
    fn secret_deserializes_without_serializing_support() {
        let secret: ApiSecret =
            serde_json::from_str("\"lawyer-assistance-secret-5678\"").expect("secret decodes");

        assert_eq!(secret.masked_last_four(), "****5678");
        assert!(!format!("{secret:?}").contains("5678"));
    }
}
