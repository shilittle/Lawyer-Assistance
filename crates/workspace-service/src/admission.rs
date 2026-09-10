use crate::{Error, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Resource classes are deliberately separate.  A slow legal query must not
/// consume a slot reserved for parsing a document or for an authorized model
/// run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionClass {
    Search,
    Ai,
    Parse,
}

pub(crate) struct Admission {
    search: Pool,
    ai: Pool,
    parse: Pool,
}

struct Pool {
    active: Arc<Semaphore>,
    waiting: Arc<Semaphore>,
    active_limit: usize,
    waiting_limit: usize,
}

/// Retaining this value owns exactly one active resource slot.  Waiting slots
/// are released as soon as the caller becomes active, so they cannot be held
/// for the duration of expensive work.
#[derive(Debug)]
pub struct AdmissionPermit {
    _active: OwnedSemaphorePermit,
}

/// A bounded reservation is made synchronously at a submission boundary.  It
/// either already owns an active slot or owns a single waiting place that can
/// later be activated by the background task.  Dropping it in either state
/// releases the reserved capacity, which makes failed submission and queued
/// cancellation cheap and deterministic.
#[derive(Debug)]
pub(crate) enum AdmissionReservation {
    Active(OwnedSemaphorePermit),
    Waiting {
        waiting: OwnedSemaphorePermit,
        active: Arc<Semaphore>,
    },
}

impl Admission {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            search: Pool::new(2, 16),
            ai: Pool::new(2, 6),
            parse: Pool::new(1, 2),
        })
    }

    pub(crate) async fn acquire(
        &self,
        class: AdmissionClass,
        cancel: &CancellationToken,
    ) -> Result<AdmissionPermit> {
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled"));
        }
        self.reserve(class)?.activate(cancel).await
    }

    /// Reserve capacity without awaiting.  Synchronous request handlers use
    /// this before they touch provider profiles, material rows or source
    /// bodies, so a full queue is rejected as `capacity_exceeded` at the
    /// submission boundary rather than becoming an unbounded durable queue.
    pub(crate) fn reserve(&self, class: AdmissionClass) -> Result<AdmissionReservation> {
        let pool = self.pool(class);
        if let Ok(active) = Arc::clone(&pool.active).try_acquire_owned() {
            return Ok(AdmissionReservation::Active(active));
        }

        // The bounded waiting permit is acquired before joining the fair Tokio
        // semaphore queue.  Once it is exhausted, no source is opened, decoded,
        // parsed or copied merely to wait for capacity.
        let waiting = Arc::clone(&pool.waiting)
            .try_acquire_owned()
            .map_err(|_| Error::retry("capacity_exceeded"))?;
        Ok(AdmissionReservation::Waiting {
            waiting,
            active: Arc::clone(&pool.active),
        })
    }

    /// Bounded operational counters for health only.  They contain no task
    /// identifiers, query values, paths, provider data, or document content.
    pub(crate) fn snapshot(&self) -> Value {
        json!({
            "search": self.search.snapshot(),
            "ai": self.ai.snapshot(),
            "parse": self.parse.snapshot(),
        })
    }

    fn pool(&self, class: AdmissionClass) -> &Pool {
        match class {
            AdmissionClass::Search => &self.search,
            AdmissionClass::Ai => &self.ai,
            AdmissionClass::Parse => &self.parse,
        }
    }
}

impl AdmissionReservation {
    pub(crate) async fn activate(self, cancel: &CancellationToken) -> Result<AdmissionPermit> {
        if cancel.is_cancelled() {
            return Err(Error::new("cancelled"));
        }
        match self {
            Self::Active(active) => Ok(AdmissionPermit { _active: active }),
            Self::Waiting { waiting, active } => {
                let active = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(Error::new("cancelled")),
                        acquired = active.acquire_owned() => acquired.map_err(|_| Error::new("workspace_unavailable"))?,
                    };
                drop(waiting);
                if cancel.is_cancelled() {
                    return Err(Error::new("cancelled"));
                }
                Ok(AdmissionPermit { _active: active })
            }
        }
    }
}

impl Pool {
    fn new(active: usize, waiting: usize) -> Self {
        Self {
            active: Arc::new(Semaphore::new(active)),
            waiting: Arc::new(Semaphore::new(waiting)),
            active_limit: active,
            waiting_limit: waiting,
        }
    }

    fn snapshot(&self) -> Value {
        json!({
            "active": self.active_limit.saturating_sub(self.active.available_permits()),
            "waiting": self.waiting_limit.saturating_sub(self.waiting.available_permits()),
            "limits": {"active": self.active_limit, "waiting": self.waiting_limit},
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn fill_waiting_queue(
        admission: &Arc<Admission>,
        class: AdmissionClass,
        count: usize,
    ) -> Vec<(
        CancellationToken,
        tokio::task::JoinHandle<Result<AdmissionPermit>>,
    )> {
        let mut entries = Vec::new();
        for _ in 0..count {
            let cancel = CancellationToken::new();
            let service = Arc::clone(admission);
            let wait_cancel = cancel.clone();
            entries.push((
                cancel,
                tokio::spawn(async move { service.acquire(class, &wait_cancel).await }),
            ));
            tokio::task::yield_now().await;
        }
        entries
    }

    #[tokio::test]
    async fn resource_classes_enforce_their_own_active_and_waiting_limits() {
        let admission = Admission::new();
        let search_cancel = CancellationToken::new();
        let first = admission
            .acquire(AdmissionClass::Search, &search_cancel)
            .await
            .expect("first search starts");
        let second = admission
            .acquire(AdmissionClass::Search, &search_cancel)
            .await
            .expect("second search starts");
        let waiting = fill_waiting_queue(&admission, AdmissionClass::Search, 16).await;
        let overflow = admission
            .acquire(AdmissionClass::Search, &search_cancel)
            .await
            .expect_err("seventeenth search waiter is rejected before work");
        assert_eq!(overflow.code, "capacity_exceeded");

        let parse = admission
            .acquire(AdmissionClass::Parse, &search_cancel)
            .await
            .expect("parse has an independent active slot");
        drop(parse);
        for (cancel, handle) in waiting {
            cancel.cancel();
            let error = handle
                .await
                .expect("wait task joins")
                .expect_err("cancelled wait never acquires a source slot");
            assert_eq!(error.code, "cancelled");
        }
        drop((first, second));
    }

    #[tokio::test]
    async fn cancelled_waiter_releases_its_queue_place_before_any_work_starts() {
        let admission = Admission::new();
        let cancel = CancellationToken::new();
        let first = admission
            .acquire(AdmissionClass::Ai, &cancel)
            .await
            .expect("first AI run starts");
        let second = admission
            .acquire(AdmissionClass::Ai, &cancel)
            .await
            .expect("second AI run starts");

        let waiting_cancel = CancellationToken::new();
        let waiting_admission = Arc::clone(&admission);
        let waiting_token = waiting_cancel.clone();
        let waiting = tokio::spawn(async move {
            waiting_admission
                .acquire(AdmissionClass::Ai, &waiting_token)
                .await
        });
        tokio::task::yield_now().await;
        waiting_cancel.cancel();
        assert_eq!(
            waiting
                .await
                .expect("wait task joins")
                .expect_err("cancelled wait stops")
                .code,
            "cancelled"
        );

        let queued = fill_waiting_queue(&admission, AdmissionClass::Ai, 6).await;
        let overflow = admission
            .acquire(AdmissionClass::Ai, &cancel)
            .await
            .expect_err("sixth queued AI waiter fills the only queue");
        assert_eq!(overflow.code, "capacity_exceeded");
        for (cancel, handle) in queued {
            cancel.cancel();
            let _ = handle.await.expect("queued task joins");
        }
        drop((first, second));
    }

    #[tokio::test]
    async fn synchronous_ai_reservations_reject_before_background_work_is_created() {
        let admission = Admission::new();
        let first = admission
            .reserve(AdmissionClass::Ai)
            .expect("first reservation owns an active place");
        let second = admission
            .reserve(AdmissionClass::Ai)
            .expect("second reservation owns an active place");
        let mut waiting = Vec::new();
        for _ in 0..6 {
            waiting.push(
                admission
                    .reserve(AdmissionClass::Ai)
                    .expect("bounded queue has a place"),
            );
        }
        let snapshot = admission.snapshot();
        assert_eq!(snapshot["ai"]["active"], json!(2));
        assert_eq!(snapshot["ai"]["waiting"], json!(6));
        assert_eq!(snapshot["ai"]["limits"], json!({"active":2,"waiting":6}));
        assert_eq!(
            admission
                .reserve(AdmissionClass::Ai)
                .expect_err("ninth submission is rejected before it can spawn work")
                .code,
            "capacity_exceeded"
        );

        drop(first);
        let permit = waiting
            .pop()
            .expect("queued reservation exists")
            .activate(&CancellationToken::new())
            .await
            .expect("a queued reservation becomes active after release");
        drop((permit, second, waiting));
        assert_eq!(admission.snapshot()["ai"]["active"], json!(0));
        assert_eq!(admission.snapshot()["ai"]["waiting"], json!(0));
    }
}
