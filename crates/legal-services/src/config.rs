use crate::ServiceError;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOrigin {
    Desktop,
    Mcp,
}

impl ServiceOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Mcp => "mcp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub legal_core_path: PathBuf,
    pub user_database_path: PathBuf,
    pub allowed_file_roots: Vec<PathBuf>,
    pub allowed_output_root: PathBuf,
}

impl ServiceConfig {
    pub(crate) fn validate(mut self) -> Result<Self, ServiceError> {
        if self.allowed_file_roots.len() > 64 {
            return Err(ServiceError::new(
                "invalid_configuration",
                "at most 64 allowed file roots may be configured",
                false,
            )
            .with_details(serde_json::json!({ "field": "allowedFileRoots" })));
        }
        for (label, path) in [
            ("legalCorePath", &self.legal_core_path),
            ("userDatabasePath", &self.user_database_path),
            ("allowedOutputRoot", &self.allowed_output_root),
        ] {
            if !path.is_absolute() {
                return Err(ServiceError::new(
                    "invalid_configuration",
                    "configured database and output paths must be absolute",
                    false,
                )
                .with_details(serde_json::json!({ "field": label })));
            }
        }

        let mut canonical_file_roots = Vec::with_capacity(self.allowed_file_roots.len());
        for root in &self.allowed_file_roots {
            if !root.is_absolute() {
                return Err(ServiceError::new(
                    "invalid_configuration",
                    "allowed file roots must be absolute",
                    false,
                )
                .with_details(serde_json::json!({ "field": "allowedFileRoots" })));
            }
            let metadata = fs::metadata(root).map_err(|_| {
                ServiceError::new(
                    "file_root_unavailable",
                    "an allowed file root does not exist or is not accessible",
                    false,
                )
            })?;
            if !metadata.is_dir() {
                return Err(ServiceError::new(
                    "invalid_configuration",
                    "every allowed file root must be a directory",
                    false,
                ));
            }
            canonical_file_roots.push(fs::canonicalize(root).map_err(|_| {
                ServiceError::new(
                    "file_root_unavailable",
                    "an allowed file root could not be resolved",
                    false,
                )
            })?);
        }
        canonical_file_roots.sort();
        canonical_file_roots.dedup();
        self.allowed_file_roots = canonical_file_roots;

        let metadata = fs::metadata(&self.allowed_output_root).map_err(|_| {
            ServiceError::new(
                "output_root_unavailable",
                "configured output root does not exist or is not accessible",
                false,
            )
        })?;
        if !metadata.is_dir() {
            return Err(ServiceError::new(
                "invalid_configuration",
                "configured output root must be a directory",
                false,
            ));
        }
        self.allowed_output_root = fs::canonicalize(&self.allowed_output_root).map_err(|_| {
            ServiceError::new(
                "output_root_unavailable",
                "configured output root could not be resolved",
                false,
            )
        })?;
        Ok(self)
    }
}
