use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
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
    legal_answer_cancellations: Mutex<HashMap<String, LegalAnswerCancellationEntry>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegalAnswerPhase {
    Streaming,
    Finalizing,
}

#[derive(Debug)]
struct LegalAnswerCancellationEntry {
    token: CancellationToken,
    phase: LegalAnswerPhase,
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
        let mut cancellations = self.legal_answer_cancellations();
        if cancellations.contains_key(request_id) {
            return Err("a legal answer request with this id is already active");
        }

        let token = CancellationToken::new();
        cancellations.insert(
            request_id.to_owned(),
            LegalAnswerCancellationEntry {
                token: token.clone(),
                phase: LegalAnswerPhase::Streaming,
            },
        );

        Ok(LegalAnswerCancellationGuard {
            state: self.clone(),
            request_id: request_id.to_owned(),
            token,
        })
    }

    pub fn cancel_legal_answer(&self, request_id: &str) -> bool {
        let mut cancellations = self.legal_answer_cancellations();
        match cancellations.get_mut(request_id) {
            Some(entry) if entry.phase == LegalAnswerPhase::Streaming => {
                entry.token.cancel();
                true
            }
            Some(_) | None => false,
        }
    }

    fn begin_legal_answer_finalization(&self, request_id: &str) -> bool {
        let mut cancellations = self.legal_answer_cancellations();
        let Some(entry) = cancellations.get_mut(request_id) else {
            return false;
        };
        if entry.phase != LegalAnswerPhase::Streaming || entry.token.is_cancelled() {
            return false;
        }

        // This transition is serialized with cancel_legal_answer. Once it
        // succeeds, cancellation reports false and cannot race an answer into
        // persistence after claiming that it was cancelled.
        entry.phase = LegalAnswerPhase::Finalizing;
        true
    }

    fn finish_legal_answer(&self, request_id: &str) {
        self.legal_answer_cancellations().remove(request_id);
    }

    fn legal_answer_cancellations(
        &self,
    ) -> MutexGuard<'_, HashMap<String, LegalAnswerCancellationEntry>> {
        self.inner
            .legal_answer_cancellations
            .lock()
            // The registry only contains independently valid tokens and an
            // enum phase, so recovery is safe and avoids a process-wide panic
            // if another thread unwinds while holding the mutex.
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    pub fn begin_finalization(&self) -> bool {
        self.state.begin_legal_answer_finalization(&self.request_id)
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

    #[test]
    fn finalization_and_cancellation_have_a_single_winner() {
        let state = state();
        let guard = state
            .begin_legal_answer("finalizes-first")
            .expect("request registers");
        assert!(guard.begin_finalization());
        assert!(!state.cancel_legal_answer("finalizes-first"));
        assert!(!guard.token().is_cancelled());

        let cancelled_guard = state
            .begin_legal_answer("cancels-first")
            .expect("request registers");
        assert!(state.cancel_legal_answer("cancels-first"));
        assert!(!cancelled_guard.begin_finalization());
        assert!(cancelled_guard.token().is_cancelled());
    }

    #[test]
    fn poisoned_registry_is_recovered_without_panicking() {
        let state = state();
        let poison_target = state.clone();
        let _ = std::thread::spawn(move || {
            let _lock = poison_target
                .inner
                .legal_answer_cancellations
                .lock()
                .expect("registry initially healthy");
            panic!("poison registry for recovery test");
        })
        .join();

        let guard = state
            .begin_legal_answer("after-poison")
            .expect("poisoned registry recovers");
        assert!(state.cancel_legal_answer("after-poison"));
        assert!(guard.token().is_cancelled());
        drop(guard);
        assert!(!state.cancel_legal_answer("after-poison"));
    }
}
