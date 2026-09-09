use serde::Serialize;

/// Stable, non-sensitive errors. Never carry filenames, SQL, provider bodies or original text.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Error {
    pub code: String,
    pub retryable: bool,
}
impl Error {
    pub fn new(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            retryable: false,
        }
    }
    pub fn retry(code: &str) -> Self {
        Self {
            code: code.to_owned(),
            retryable: true,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.code)
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::new("storage_failed")
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::new("file_operation_failed")
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::new("invalid_data")
    }
}
pub type Result<T> = std::result::Result<T, Error>;
