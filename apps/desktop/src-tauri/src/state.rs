use std::{
    collections::{hash_map::Entry, HashMap},
    error::Error,
    fmt::{self, Display},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

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
    pending_extraction_reviews: Mutex<HashMap<String, ActiveExtractionReview>>,
}

impl AppState {
    pub fn new(legal_core_path: PathBuf, user_database_path: PathBuf) -> Self {
        Self {
            inner: Arc::new(AppStateInner {
                legal_core_path,
                user_database_path,
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
