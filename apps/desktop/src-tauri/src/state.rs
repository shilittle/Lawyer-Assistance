use std::{
    collections::{hash_map::Entry, HashMap},
    error::Error,
    fmt::{self, Display},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const PENDING_EXTRACTION_REVIEW_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_PENDING_EXTRACTION_REVIEWS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingExtractionReview {
    pub project_id: String,
    pub provider_id: String,
    pub source_file_ids: Vec<String>,
}

#[derive(Debug)]
struct ActiveExtractionReview {
    review: PendingExtractionReview,
    created_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReviewRegistryError {
    Unavailable,
    CapacityExceeded,
    IdentifierCollision,
}

impl Display for PendingReviewRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(formatter, "pending review registry is unavailable"),
            Self::CapacityExceeded => write!(formatter, "pending review registry is full"),
            Self::IdentifierCollision => write!(formatter, "pending review identifier collision"),
        }
    }
}

impl Error for PendingReviewRegistryError {}

#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

#[derive(Debug)]
struct AppStateInner {
    legal_core_path: PathBuf,
    user_database_path: PathBuf,
    legal_answer_cancellations: Mutex<HashMap<String, LegalAnswerCancellationEntry>>,
    pending_extraction_reviews: Mutex<HashMap<String, ActiveExtractionReview>>,
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
                pending_extraction_reviews: Mutex::new(HashMap::new()),
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

impl AppState {
    pub fn register_extraction_review(
        &self,
        review_id: String,
        review: PendingExtractionReview,
    ) -> Result<(), PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        prune_expired_reviews(&mut reviews);
        match reviews.entry(review_id.clone()) {
            Entry::Occupied(_) => return Err(PendingReviewRegistryError::IdentifierCollision),
            Entry::Vacant(_) => {}
        }
        reviews.retain(|_, active| active.review.project_id != review.project_id);
        if reviews.len() >= MAX_PENDING_EXTRACTION_REVIEWS {
            return Err(PendingReviewRegistryError::CapacityExceeded);
        }
        reviews.insert(
            review_id,
            ActiveExtractionReview {
                review,
                created_at: Instant::now(),
            },
        );
        Ok(())
    }

    pub fn take_matching_extraction_review(
        &self,
        review_id: &str,
        expected: &PendingExtractionReview,
    ) -> Result<Option<PendingExtractionReview>, PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        prune_expired_reviews(&mut reviews);
        if reviews.get(review_id).map(|active| &active.review) != Some(expected) {
            return Ok(None);
        }
        Ok(reviews.remove(review_id).map(|active| active.review))
    }

    pub fn discard_extraction_review(
        &self,
        review_id: &str,
    ) -> Result<bool, PendingReviewRegistryError> {
        Ok(self
            .pending_extraction_reviews()?
            .remove(review_id)
            .is_some())
    }

    pub fn restore_extraction_review(
        &self,
        review_id: String,
        review: PendingExtractionReview,
    ) -> Result<(), PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        prune_expired_reviews(&mut reviews);
        if reviews.contains_key(&review_id)
            || reviews
                .values()
                .any(|active| active.review.project_id == review.project_id)
        {
            return Err(PendingReviewRegistryError::IdentifierCollision);
        }
        if reviews.len() >= MAX_PENDING_EXTRACTION_REVIEWS {
            return Err(PendingReviewRegistryError::CapacityExceeded);
        }
        reviews.insert(
            review_id,
            ActiveExtractionReview {
                review,
                created_at: Instant::now(),
            },
        );
        Ok(())
    }

    pub fn discard_project_extraction_reviews(
        &self,
        project_id: &str,
    ) -> Result<(), PendingReviewRegistryError> {
        self.pending_extraction_reviews()?
            .retain(|_, active| active.review.project_id != project_id);
        Ok(())
    }

    fn pending_extraction_reviews(
        &self,
    ) -> Result<MutexGuard<'_, HashMap<String, ActiveExtractionReview>>, PendingReviewRegistryError>
    {
        self.inner
            .pending_extraction_reviews
            .lock()
            .map_err(|_| PendingReviewRegistryError::Unavailable)
    }
}

fn prune_expired_reviews(reviews: &mut HashMap<String, ActiveExtractionReview>) {
    reviews.retain(|_, active| active.created_at.elapsed() <= PENDING_EXTRACTION_REVIEW_TTL);
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

    fn review() -> PendingExtractionReview {
        PendingExtractionReview {
            project_id: "project-1".to_owned(),
            provider_id: "provider-1".to_owned(),
            source_file_ids: vec!["file-1".to_owned()],
        }
    }

    #[test]
    fn pending_review_requires_exact_generation_provenance_and_is_single_use() {
        let state = state();
        state
            .register_extraction_review("review-1".to_owned(), review())
            .expect("review registers");
        assert_eq!(
            state.register_extraction_review("review-1".to_owned(), review()),
            Err(PendingReviewRegistryError::IdentifierCollision)
        );

        let mut rebound = review();
        rebound.source_file_ids = vec!["file-2".to_owned()];
        assert!(state
            .take_matching_extraction_review("review-1", &rebound)
            .expect("registry reads")
            .is_none());
        assert_eq!(
            state
                .take_matching_extraction_review("review-1", &review())
                .expect("registry reads"),
            Some(review())
        );
        assert!(state
            .take_matching_extraction_review("review-1", &review())
            .expect("registry reads")
            .is_none());
    }

    #[test]
    fn discarded_review_cannot_be_consumed() {
        let state = state();
        state
            .register_extraction_review("review-1".to_owned(), review())
            .expect("review registers");
        assert!(state
            .discard_extraction_review("review-1")
            .expect("review discards"));
        assert!(state
            .take_matching_extraction_review("review-1", &review())
            .expect("registry reads")
            .is_none());
    }

    #[test]
    fn new_review_replaces_abandoned_review_for_the_same_project() {
        let state = state();
        state
            .register_extraction_review("old".to_owned(), review())
            .expect("old review registers");
        state
            .register_extraction_review("new".to_owned(), review())
            .expect("new review registers");

        assert!(state
            .take_matching_extraction_review("old", &review())
            .expect("registry reads")
            .is_none());
        assert!(state
            .take_matching_extraction_review("new", &review())
            .expect("registry reads")
            .is_some());
    }

    #[test]
    fn expired_reviews_are_pruned_before_registration() {
        let state = state();
        state
            .inner
            .pending_extraction_reviews
            .lock()
            .expect("test lock")
            .insert(
                "expired".to_owned(),
                ActiveExtractionReview {
                    review: review(),
                    created_at: Instant::now()
                        .checked_sub(PENDING_EXTRACTION_REVIEW_TTL + Duration::from_secs(1))
                        .expect("test instant can move backwards"),
                },
            );
        state
            .register_extraction_review("fresh".to_owned(), review())
            .expect("fresh review registers");

        assert!(state
            .take_matching_extraction_review("expired", &review())
            .expect("registry reads")
            .is_none());
    }

    #[test]
    fn poisoned_registry_returns_a_typed_error_instead_of_panicking() {
        let state = state();
        let poisoned = state.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned
                .inner
                .pending_extraction_reviews
                .lock()
                .expect("test acquires lock");
            panic!("poison registry for test");
        })
        .join();

        assert_eq!(
            state.discard_extraction_review("review-1"),
            Err(PendingReviewRegistryError::Unavailable)
        );
    }
}
