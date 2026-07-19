use std::{
    collections::{hash_map::Entry, HashMap},
    error::Error,
    fmt::{self, Display},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const PENDING_EXTRACTION_REVIEW_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
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
    phase: PendingExtractionReviewPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingExtractionReviewPhase {
    Ready,
    Claimed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingReviewRegistryError {
    Unavailable,
    CapacityExceeded,
    IdentifierCollision,
    ReviewInFlight,
    ClaimChanged,
}

impl Display for PendingReviewRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(formatter, "pending review registry is unavailable"),
            Self::CapacityExceeded => write!(formatter, "pending review registry is full"),
            Self::IdentifierCollision => write!(formatter, "pending review identifier collision"),
            Self::ReviewInFlight => write!(
                formatter,
                "pending review is currently being confirmed; retry after it finishes"
            ),
            Self::ClaimChanged => write!(
                formatter,
                "pending review claim changed unexpectedly; retry the operation"
            ),
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
    crash_log_path: PathBuf,
    legal_answer_cancellations: Mutex<HashMap<String, LegalAnswerCancellationEntry>>,
    assistant_run_cancellations: Mutex<HashMap<String, AssistantRunCancellationEntry>>,
    pending_extraction_reviews: Mutex<HashMap<String, ActiveExtractionReview>>,
    // A document export spans SQLite persistence, a crash-recovery marker and
    // an atomic destination-file swap. Serialize the protocol so concurrent
    // exports cannot race recovery-marker cleanup or overwrite one another.
    document_export_lock: Mutex<()>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssistantRunPhase {
    Running,
    Finalizing,
}

#[derive(Debug)]
struct AssistantRunCancellationEntry {
    token: CancellationToken,
    provider_cancellation: providers::RequestCancellation,
    phase: AssistantRunPhase,
}

impl AppState {
    pub fn new(legal_core_path: PathBuf, user_database_path: PathBuf) -> Self {
        let crash_log_path = user_database_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("crash-events.log");
        Self {
            inner: Arc::new(AppStateInner {
                legal_core_path,
                user_database_path,
                crash_log_path,
                legal_answer_cancellations: Mutex::new(HashMap::new()),
                assistant_run_cancellations: Mutex::new(HashMap::new()),
                pending_extraction_reviews: Mutex::new(HashMap::new()),
                document_export_lock: Mutex::new(()),
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

    pub fn crash_log_path(&self) -> &Path {
        &self.inner.crash_log_path
    }

    /// Build the transport-neutral application service used by both the
    /// desktop IPC adapters and the standalone MCP server. The desktop keeps
    /// its file boundary at LocalAppData; user-selected export destinations
    /// continue to pass through the existing reviewed desktop export flow.
    pub fn legal_services(
        &self,
    ) -> Result<legal_services::LegalServices, legal_services::ServiceError> {
        let local_root = self.user_database_path().parent().ok_or_else(|| {
            legal_services::ServiceError::new(
                "invalid_configuration",
                "user database path has no parent directory",
                false,
            )
        })?;
        legal_services::LegalServices::new_with_origin(
            legal_services::ServiceConfig {
                legal_core_path: self.legal_core_path().to_path_buf(),
                user_database_path: self.user_database_path().to_path_buf(),
                allowed_file_roots: vec![local_root.to_path_buf()],
                allowed_output_root: local_root.to_path_buf(),
            },
            legal_services::ServiceOrigin::Desktop,
        )
    }

    pub fn begin_document_export(&self) -> MutexGuard<'_, ()> {
        self.inner
            .document_export_lock
            .lock()
            // No protected value can be left inconsistent: the mutex is only
            // an operation gate. Recovering after an unwind is therefore safe.
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    pub fn begin_assistant_run(
        &self,
        run_id: &str,
    ) -> Result<AssistantRunCancellationGuard, &'static str> {
        let mut cancellations = self.assistant_run_cancellations();
        if cancellations.contains_key(run_id) {
            return Err("an assistant run with this id is already active");
        }

        let token = CancellationToken::new();
        let provider_cancellation = providers::RequestCancellation::default();
        cancellations.insert(
            run_id.to_owned(),
            AssistantRunCancellationEntry {
                token: token.clone(),
                provider_cancellation: provider_cancellation.clone(),
                phase: AssistantRunPhase::Running,
            },
        );

        Ok(AssistantRunCancellationGuard {
            state: self.clone(),
            run_id: run_id.to_owned(),
            token,
            provider_cancellation,
        })
    }

    pub fn cancel_assistant_run(&self, run_id: &str) -> bool {
        let mut cancellations = self.assistant_run_cancellations();
        match cancellations.get_mut(run_id) {
            Some(entry) if entry.phase == AssistantRunPhase::Running => {
                entry.token.cancel();
                entry.provider_cancellation.cancel();
                true
            }
            Some(_) | None => false,
        }
    }

    fn begin_assistant_run_finalization(&self, run_id: &str) -> bool {
        let mut cancellations = self.assistant_run_cancellations();
        let Some(entry) = cancellations.get_mut(run_id) else {
            return false;
        };
        if entry.phase != AssistantRunPhase::Running || entry.token.is_cancelled() {
            return false;
        }

        entry.phase = AssistantRunPhase::Finalizing;
        true
    }

    fn finish_assistant_run(&self, run_id: &str) {
        self.assistant_run_cancellations().remove(run_id);
    }

    fn assistant_run_cancellations(
        &self,
    ) -> MutexGuard<'_, HashMap<String, AssistantRunCancellationEntry>> {
        self.inner
            .assistant_run_cancellations
            .lock()
            // The registry contains independent cancellation tokens and an
            // enum phase, so recovering after an unwind is safe.
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

#[derive(Debug)]
pub struct AssistantRunCancellationGuard {
    state: AppState,
    run_id: String,
    token: CancellationToken,
    provider_cancellation: providers::RequestCancellation,
}

impl AssistantRunCancellationGuard {
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Cancellation handle consumed by the synchronous provider transport.
    /// Keeping it in the same registry entry as the Tokio token makes the
    /// public cancel command interrupt both local orchestration and HTTP I/O.
    pub fn provider_cancellation(&self) -> providers::RequestCancellation {
        self.provider_cancellation.clone()
    }

    pub fn begin_finalization(&self) -> bool {
        self.state.begin_assistant_run_finalization(&self.run_id)
    }
}

impl Drop for AssistantRunCancellationGuard {
    fn drop(&mut self) {
        self.state.finish_assistant_run(&self.run_id);
    }
}

impl AppState {
    pub fn register_extraction_review(
        &self,
        review_id: String,
        review: PendingExtractionReview,
    ) -> Result<(), PendingReviewRegistryError> {
        self.register_extraction_review_at(review_id, review, Instant::now())
    }

    fn register_extraction_review_at(
        &self,
        review_id: String,
        review: PendingExtractionReview,
        now: Instant,
    ) -> Result<(), PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        prune_expired_reviews_at(&mut reviews, now);
        match reviews.entry(review_id.clone()) {
            Entry::Occupied(_) => return Err(PendingReviewRegistryError::IdentifierCollision),
            Entry::Vacant(_) => {}
        }
        if reviews.values().any(|active| {
            active.review.project_id == review.project_id
                && active.phase == PendingExtractionReviewPhase::Claimed
        }) {
            return Err(PendingReviewRegistryError::ReviewInFlight);
        }
        reviews.retain(|_, active| active.review.project_id != review.project_id);
        if reviews.len() >= MAX_PENDING_EXTRACTION_REVIEWS {
            return Err(PendingReviewRegistryError::CapacityExceeded);
        }
        reviews.insert(
            review_id,
            ActiveExtractionReview {
                review,
                created_at: now,
                phase: PendingExtractionReviewPhase::Ready,
            },
        );
        Ok(())
    }

    pub fn claim_matching_extraction_review(
        &self,
        review_id: &str,
        expected: &PendingExtractionReview,
    ) -> Result<Option<PendingExtractionReviewClaim>, PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        prune_expired_reviews(&mut reviews);
        let Some(active) = reviews.get_mut(review_id) else {
            return Ok(None);
        };
        if &active.review != expected {
            return Ok(None);
        }
        if active.phase == PendingExtractionReviewPhase::Claimed {
            return Err(PendingReviewRegistryError::ReviewInFlight);
        }
        active.phase = PendingExtractionReviewPhase::Claimed;
        Ok(Some(PendingExtractionReviewClaim {
            state: self.clone(),
            review_id: review_id.to_owned(),
            review: expected.clone(),
            finished: false,
        }))
    }

    pub fn claim_project_extraction_review(
        &self,
        review_id: &str,
        project_id: &str,
    ) -> Result<Option<PendingExtractionReviewClaim>, PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        prune_expired_reviews(&mut reviews);
        let Some(active) = reviews.get_mut(review_id) else {
            return Ok(None);
        };
        if active.review.project_id != project_id {
            return Ok(None);
        }
        if active.phase == PendingExtractionReviewPhase::Claimed {
            return Err(PendingReviewRegistryError::ReviewInFlight);
        }
        active.phase = PendingExtractionReviewPhase::Claimed;
        Ok(Some(PendingExtractionReviewClaim {
            state: self.clone(),
            review_id: review_id.to_owned(),
            review: active.review.clone(),
            finished: false,
        }))
    }

    pub fn discard_extraction_review(
        &self,
        review_id: &str,
    ) -> Result<bool, PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        prune_expired_reviews(&mut reviews);
        if reviews
            .get(review_id)
            .is_some_and(|active| active.phase == PendingExtractionReviewPhase::Claimed)
        {
            return Err(PendingReviewRegistryError::ReviewInFlight);
        }
        Ok(reviews.remove(review_id).is_some())
    }

    pub fn discard_project_extraction_reviews(
        &self,
        project_id: &str,
    ) -> Result<(), PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        prune_expired_reviews(&mut reviews);
        if reviews.values().any(|active| {
            active.review.project_id == project_id
                && active.phase == PendingExtractionReviewPhase::Claimed
        }) {
            return Err(PendingReviewRegistryError::ReviewInFlight);
        }
        reviews.retain(|_, active| active.review.project_id != project_id);
        Ok(())
    }

    fn finish_extraction_review_claim(
        &self,
        review_id: &str,
        expected: &PendingExtractionReview,
        consume: bool,
    ) -> Result<(), PendingReviewRegistryError> {
        let mut reviews = self.pending_extraction_reviews()?;
        let Some(active) = reviews.get_mut(review_id) else {
            return Err(PendingReviewRegistryError::ClaimChanged);
        };
        if &active.review != expected || active.phase != PendingExtractionReviewPhase::Claimed {
            return Err(PendingReviewRegistryError::ClaimChanged);
        }

        if consume {
            reviews.remove(review_id);
        } else {
            active.phase = PendingExtractionReviewPhase::Ready;
        }
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
    prune_expired_reviews_at(reviews, Instant::now());
}

fn prune_expired_reviews_at(reviews: &mut HashMap<String, ActiveExtractionReview>, now: Instant) {
    reviews.retain(|_, active| {
        active.phase == PendingExtractionReviewPhase::Claimed
            || now.saturating_duration_since(active.created_at) <= PENDING_EXTRACTION_REVIEW_TTL
    });
}

#[derive(Debug)]
pub struct PendingExtractionReviewClaim {
    state: AppState,
    review_id: String,
    review: PendingExtractionReview,
    finished: bool,
}

impl PendingExtractionReviewClaim {
    pub fn consume(mut self) -> Result<(), PendingReviewRegistryError> {
        self.state
            .finish_extraction_review_claim(&self.review_id, &self.review, true)?;
        self.finished = true;
        Ok(())
    }

    pub fn release(mut self) -> Result<(), PendingReviewRegistryError> {
        self.state
            .finish_extraction_review_claim(&self.review_id, &self.review, false)?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for PendingExtractionReviewClaim {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self
                .state
                .finish_extraction_review_claim(&self.review_id, &self.review, false);
        }
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
    fn assistant_run_ids_are_unique_until_the_guard_is_released() {
        let state = state();
        let guard = state
            .begin_assistant_run("run-1")
            .expect("assistant run registers");
        assert!(state.begin_assistant_run("run-1").is_err());
        assert!(state.cancel_assistant_run("run-1"));
        assert!(guard.token().is_cancelled());
        assert!(guard.provider_cancellation().is_cancelled());

        drop(guard);
        assert!(!state.cancel_assistant_run("run-1"));
        assert!(state.begin_assistant_run("run-1").is_ok());
    }

    #[test]
    fn assistant_finalization_and_cancellation_have_a_single_winner() {
        let state = state();
        let guard = state
            .begin_assistant_run("finalizes-first")
            .expect("assistant run registers");
        assert!(guard.begin_finalization());
        assert!(!state.cancel_assistant_run("finalizes-first"));
        assert!(!guard.token().is_cancelled());
        assert!(!guard.provider_cancellation().is_cancelled());

        let cancelled_guard = state
            .begin_assistant_run("cancels-first")
            .expect("assistant run registers");
        assert!(state.cancel_assistant_run("cancels-first"));
        assert!(!cancelled_guard.begin_finalization());
        assert!(cancelled_guard.token().is_cancelled());
        assert!(cancelled_guard.provider_cancellation().is_cancelled());
    }

    #[test]
    fn legal_answer_and_assistant_run_namespaces_do_not_collide() {
        let state = state();
        let legal = state
            .begin_legal_answer("shared-id")
            .expect("legal answer registers");
        let assistant = state
            .begin_assistant_run("shared-id")
            .expect("assistant run registers independently");

        assert!(state.cancel_assistant_run("shared-id"));
        assert!(assistant.token().is_cancelled());
        assert!(!legal.token().is_cancelled());
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
            .claim_matching_extraction_review("review-1", &rebound)
            .expect("registry reads")
            .is_none());
        let claim = state
            .claim_matching_extraction_review("review-1", &review())
            .expect("registry reads")
            .expect("matching review claims");
        assert!(matches!(
            state.claim_matching_extraction_review("review-1", &review()),
            Err(PendingReviewRegistryError::ReviewInFlight)
        ));
        claim
            .consume()
            .expect("successful confirmation consumes claim");
        assert!(state
            .claim_matching_extraction_review("review-1", &review())
            .expect("registry reads")
            .is_none());
    }

    #[test]
    fn project_scoped_claim_rejects_wrong_owner_and_serializes_discard_with_confirmation() {
        let state = state();
        state
            .register_extraction_review("review-project".to_owned(), review())
            .expect("review registers");
        assert!(state
            .claim_project_extraction_review("review-project", "other-project")
            .expect("wrong-owner lookup succeeds")
            .is_none());
        let claim = state
            .claim_project_extraction_review("review-project", "project-1")
            .expect("owner claim succeeds")
            .expect("owner review exists");
        assert!(matches!(
            state.claim_project_extraction_review("review-project", "project-1"),
            Err(PendingReviewRegistryError::ReviewInFlight)
        ));
        claim.release().expect("claim releases");
        assert!(state
            .claim_project_extraction_review("review-project", "project-1")
            .expect("released claim retries")
            .is_some());
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
            .claim_matching_extraction_review("review-1", &review())
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
            .claim_matching_extraction_review("old", &review())
            .expect("registry reads")
            .is_none());
        let claim = state
            .claim_matching_extraction_review("new", &review())
            .expect("registry reads")
            .expect("new review remains");
        claim.consume().expect("claim consumes");
    }

    #[test]
    fn expired_reviews_are_pruned_before_registration() {
        let state = state();
        let created_at = Instant::now();
        state
            .inner
            .pending_extraction_reviews
            .lock()
            .expect("test lock")
            .insert(
                "expired".to_owned(),
                ActiveExtractionReview {
                    review: review(),
                    created_at,
                    phase: PendingExtractionReviewPhase::Ready,
                },
            );
        state
            .register_extraction_review_at(
                "fresh".to_owned(),
                review(),
                created_at
                    .checked_add(PENDING_EXTRACTION_REVIEW_TTL + Duration::from_secs(1))
                    .expect("test instant can move forwards"),
            )
            .expect("fresh review registers");

        assert!(state
            .claim_matching_extraction_review("expired", &review())
            .expect("registry reads")
            .is_none());
    }

    #[test]
    fn claimed_review_blocks_replacement_and_discard_until_released() {
        let state = state();
        state
            .register_extraction_review("review-1".to_owned(), review())
            .expect("review registers");
        let created_at = state
            .inner
            .pending_extraction_reviews
            .lock()
            .expect("registry lock")
            .get("review-1")
            .expect("review exists")
            .created_at;
        let claim = state
            .claim_matching_extraction_review("review-1", &review())
            .expect("claim succeeds")
            .expect("review exists");

        assert_eq!(
            state.register_extraction_review("review-2".to_owned(), review()),
            Err(PendingReviewRegistryError::ReviewInFlight)
        );
        assert_eq!(
            state.discard_extraction_review("review-1"),
            Err(PendingReviewRegistryError::ReviewInFlight)
        );

        claim.release().expect("failed confirmation releases claim");
        assert_eq!(
            state
                .inner
                .pending_extraction_reviews
                .lock()
                .expect("registry lock")
                .get("review-1")
                .expect("review remains")
                .created_at,
            created_at,
            "release preserves the original expiry instant"
        );
        state
            .register_extraction_review("review-2".to_owned(), review())
            .expect("new generation can replace a released review");
    }

    #[test]
    fn dropping_a_claim_restores_the_same_review_without_resetting_ttl() {
        let state = state();
        state
            .register_extraction_review("review-1".to_owned(), review())
            .expect("review registers");
        let created_at = state
            .inner
            .pending_extraction_reviews
            .lock()
            .expect("registry lock")
            .get("review-1")
            .expect("review exists")
            .created_at;
        let claim = state
            .claim_matching_extraction_review("review-1", &review())
            .expect("claim succeeds")
            .expect("review exists");

        drop(claim);

        let reviews = state
            .inner
            .pending_extraction_reviews
            .lock()
            .expect("registry lock");
        let active = reviews.get("review-1").expect("review is restored");
        assert_eq!(active.phase, PendingExtractionReviewPhase::Ready);
        assert_eq!(active.created_at, created_at);
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
