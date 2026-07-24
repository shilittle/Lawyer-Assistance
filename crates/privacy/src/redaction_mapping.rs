#![allow(unsafe_code)]

use std::{
    fmt,
    sync::atomic::{compiler_fence, Ordering},
};

/// An owned local-only alias-to-original mapping produced by [`crate::Redactor`].
///
/// This type intentionally does not implement `Serialize`. Its sensitive value
/// is hidden from `Debug` and zeroized when the snapshot entry is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactionMappingEntry {
    pub alias: String,
    pub sensitive_value: String,
}

impl RedactionMappingEntry {
    pub(crate) fn new(alias: String, sensitive_value: String) -> Self {
        Self {
            alias,
            sensitive_value,
        }
    }

    /// Transfers this snapshot into the encrypted lifecycle payload without
    /// making another plaintext copy. Any values left in `self` are empty when
    /// its zeroizing destructor runs.
    pub fn into_parts(mut self) -> (String, String) {
        (
            std::mem::take(&mut self.alias),
            std::mem::take(&mut self.sensitive_value),
        )
    }
}

impl fmt::Debug for RedactionMappingEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactionMappingEntry")
            .field("alias", &self.alias)
            .field("sensitive_value", &"[REDACTED_SENSITIVE_VALUE]")
            .finish()
    }
}

impl Drop for RedactionMappingEntry {
    fn drop(&mut self) {
        zeroize_string(&mut self.sensitive_value);
    }
}

fn zeroize_string(value: &mut String) {
    unsafe {
        for byte in value.as_mut_vec() {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
    value.clear();
}

#[cfg(test)]
mod tests {
    use crate::{RedactionOptions, Redactor};

    #[test]
    fn snapshot_contains_only_emitted_aliases_and_debug_hides_originals() {
        let options = RedactionOptions {
            custom_terms: vec![
                "synthetic-present-secret".to_owned(),
                "absent-secret".to_owned(),
            ],
            ..RedactionOptions::default()
        }
        .validated()
        .expect("options");
        let mut redactor = Redactor::new(options);
        redactor
            .discover("synthetic-present-secret")
            .expect("discover");
        assert!(redactor.detected_alias_mappings().is_empty());

        let redacted = redactor.redact("synthetic-present-secret");
        let mappings = redactor.detected_alias_mappings();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].alias, redacted);
        assert_eq!(mappings[0].sensitive_value, "synthetic-present-secret");
        let debug = format!("{:?}", mappings[0]);
        assert!(!debug.contains("synthetic-present-secret"));
        assert!(debug.contains("[REDACTED_SENSITIVE_VALUE]"));
    }
}
