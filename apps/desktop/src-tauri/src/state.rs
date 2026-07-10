use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

#[derive(Debug)]
struct AppStateInner {
    legal_core_path: PathBuf,
    user_database_path: PathBuf,
}

impl AppState {
    pub fn new(legal_core_path: PathBuf, user_database_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                legal_core_path,
                user_database_path,
            }),
        }
    }

    pub fn legal_core_path(&self) -> &Path {
        &self.inner.legal_core_path
    }

    #[allow(dead_code)]
    pub fn user_database_path(&self) -> &Path {
        &self.inner.user_database_path
    }
}
