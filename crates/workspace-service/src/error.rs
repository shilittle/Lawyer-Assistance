use serde::Serialize;

/// Stable, non-sensitive errors. Never carry filenames, SQL, provider bodies or original text.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Error {
    pub code: String,
    pub retryable: bool,
    #[serde(skip_serializing)]
    internal: Option<InternalDiagnostic>,
}

/// Local-only error classification used by the supervisor.  It is intentionally
/// constrained to an error family and stable platform code, never the database
/// query, filename, provider response, original document or secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InternalDiagnostic {
    category: &'static str,
    detail: Option<String>,
}
impl Error {
    pub fn new(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            retryable: false,
            internal: None,
        }
    }
    pub fn retry(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            retryable: true,
            internal: None,
        }
    }
    fn with_diagnostic(mut self, category: &'static str, detail: Option<String>) -> Self {
        self.internal = Some(InternalDiagnostic { category, detail });
        self
    }
    pub(crate) fn diagnostic_category(&self) -> Option<&'static str> {
        self.internal.as_ref().map(|value| value.category)
    }
    pub(crate) fn diagnostic_detail(&self) -> Option<&str> {
        self.internal
            .as_ref()
            .and_then(|value| value.detail.as_deref())
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.code)
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;
        match error {
            rusqlite::Error::SqliteFailure(code, _) => {
                let detail = Some(format!("sqlite_extended_code={}", code.extended_code));
                let error = match code.code {
                    ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                        Self::retry("storage_busy")
                    }
                    ErrorCode::DiskFull => Self::new("storage_full"),
                    _ => Self::new("storage_failed"),
                };
                error.with_diagnostic("sqlite", detail)
            }
            _ => Self::new("storage_failed").with_diagnostic("sqlite", None),
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        let kind = error.kind();
        let code = if kind == std::io::ErrorKind::StorageFull {
            "storage_full"
        } else {
            "file_operation_failed"
        };
        Self::new(code).with_diagnostic("io", Some(format!("io_kind={kind:?}")))
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::new("invalid_data").with_diagnostic("json", None)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_diagnostics_keep_the_public_error_non_sensitive() {
        let error: Error = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            Some("SELECT private_body FROM documents WHERE token='secret'".to_owned()),
        )
        .into();
        assert_eq!(error.code, "storage_busy");
        assert!(error.retryable);
        assert_eq!(error.diagnostic_category(), Some("sqlite"));
        assert!(error
            .diagnostic_detail()
            .is_some_and(|detail| detail.starts_with("sqlite_extended_code=")));

        let public = serde_json::to_string(&error).expect("stable error serializes");
        assert!(!public.contains("private_body"));
        assert!(!public.contains("secret"));
        assert!(!public.contains("sqlite_extended_code"));
    }
}
