use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

#[derive(Debug)]
struct AppStateInner {
    legal_core_path: PathBuf,
    user_database_path: PathBuf,
    legal_answer_cancellations: Mutex<HashMap<String, CancellationToken>>,
}

impl AppState {
    pub fn new(legal_core_path: PathBuf, user_database_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                legal_core_path,
                user_database_path,
                legal_answer_cancellations: Mutex::new(HashMap::new()),
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

    pub fn begin_legal_answer(
        &self,
        request_id: &str,
    ) -> Result<LegalAnswerCancellationGuard, &'static str> {
        let mut cancellations = self
            .inner
            .legal_answer_cancellations
            .lock()
            .expect("legal answer cancellation registry lock");
        if cancellations.contains_key(request_id) {
            return Err("a legal answer request with this id is already active");
        }

        let token = CancellationToken::new();
        cancellations.insert(request_id.to_owned(), token.clone());

        Ok(LegalAnswerCancellationGuard {
            state: self.clone(),
            request_id: request_id.to_owned(),
            token,
        })
    }

    pub fn cancel_legal_answer(&self, request_id: &str) -> bool {
        let cancellation = self
            .inner
            .legal_answer_cancellations
            .lock()
            .expect("legal answer cancellation registry lock")
            .get(request_id)
            .cloned();

        if let Some(cancellation) = cancellation {
            cancellation.cancel();
            true
        } else {
            false
        }
    }

    fn finish_legal_answer(&self, request_id: &str) {
        self.inner
            .legal_answer_cancellations
            .lock()
            .expect("legal answer cancellation registry lock")
            .remove(request_id);
    }
}

#[derive(Debug)]
pub struct LegalAnswerCancellationGuard {
    state: AppState,
    request_id: String,
    token: CancellationToken,
}

impl LegalAnswerCancellationGuard {
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

impl Drop for LegalAnswerCancellationGuard {
    fn drop(&mut self) {
        self.state.finish_legal_answer(&self.request_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AppState {
        AppState::new(PathBuf::from("legal.sqlite"), PathBuf::from("user.sqlite"))
    }

    #[test]
    fn cancellation_registry_cancels_and_releases_request_ids() {
        let state = state();
        let guard = state
            .begin_legal_answer("answer-1")
            .expect("request registers");
        assert!(state.begin_legal_answer("answer-1").is_err());
        assert!(state.cancel_legal_answer("answer-1"));
        assert!(guard.token().is_cancelled());

        drop(guard);
        assert!(!state.cancel_legal_answer("answer-1"));
        assert!(state.begin_legal_answer("answer-1").is_ok());
    }
}
