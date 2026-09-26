use std::sync::Arc;
use tokio::sync::{Mutex, OwnedMutexGuard};

/// Coordination primitive providing mutual exclusion between
/// reachability-altering mutations and garbage collection reachability revalidation.
///
/// # Concurrency Contract
/// 1. Only one mutation path (upload commit, tag mutation, manifest publication,
///    repository membership change, proxy blob ingestion) alters reachability at a time.
/// 2. Garbage collection revalidation and conditional deletion are mutually exclusive
///    with all reachability mutations.
/// 3. Candidates for GC are enumerated without holding this coordinator; the guard
///    is acquired per candidate immediately before revalidation and released before
///    advancing to the next candidate.
///
/// # Composition Policy
/// `ConsistencyCoordinator` is a library-level composition primitive.
/// Each application runtime composition root (e.g. server supervisor) or isolated
/// maintenance CLI execution MUST construct exactly one instance and inject clones
/// into all coordinator-dependent services. Independent coordinators do NOT synchronize.
///
/// # Important
/// This coordinator provides in-process mutual exclusion via RAII guards.
/// It is **not** a database transaction and provides no automatic rollback.
#[derive(Clone, Debug)]
pub struct ConsistencyCoordinator {
    gate: Arc<Mutex<()>>,
}

/// An unforgeable RAII guard proving that a reachability-altering mutation is actively in progress.
///
/// Dropping this guard releases the mutual exclusion lock.
#[derive(Debug)]
pub struct MutationGuard {
    _guard: OwnedMutexGuard<()>,
}

/// An unforgeable RAII guard proving that a GC reachability revalidation check is actively in progress.
///
/// Dropping this guard releases the mutual exclusion lock.
#[derive(Debug)]
pub struct GcRevalidationGuard {
    _guard: OwnedMutexGuard<()>,
}

impl ConsistencyCoordinator {
    /// Creates a new, unlocked `ConsistencyCoordinator`.
    pub fn new() -> Self {
        Self {
            gate: Arc::new(Mutex::new(())),
        }
    }

    /// Asynchronously acquires exclusive execution for a reachability mutation.
    pub async fn acquire_mutation(&self) -> MutationGuard {
        let guard = self.gate.clone().lock_owned().await;
        MutationGuard { _guard: guard }
    }

    /// Asynchronously acquires exclusive execution for GC reachability revalidation.
    pub async fn acquire_gc_revalidation(&self) -> GcRevalidationGuard {
        let guard = self.gate.clone().lock_owned().await;
        GcRevalidationGuard { _guard: guard }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::{Barrier, oneshot};

    // 1. Clones share state
    #[tokio::test]
    async fn test_coordinator_clones_share_state() {
        let coord1 = ConsistencyCoordinator::new();
        let coord2 = coord1.clone();

        let guard1 = coord1.acquire_mutation().await;

        let (entered_tx, entered_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            let _guard2 = coord2.acquire_mutation().await;
            let _ = entered_tx.send(true);
        });

        tokio::task::yield_now().await;

        drop(guard1);
        let entered = entered_rx.await.expect("task acquires");
        assert!(entered);
        handle.await.expect("task completes");
    }

    // 2. Mutation excludes GC revalidation
    #[tokio::test]
    async fn test_mutation_excludes_gc_revalidation() {
        let coord = ConsistencyCoordinator::new();
        let mut_guard = coord.acquire_mutation().await;

        let (entered_tx, mut entered_rx) = oneshot::channel();
        let coord_clone = coord.clone();

        let handle = tokio::spawn(async move {
            let _gc_guard = coord_clone.acquire_gc_revalidation().await;
            let _ = entered_tx.send(true);
        });

        tokio::task::yield_now().await;
        assert!(entered_rx.try_recv().is_err());

        drop(mut_guard);
        let entered = entered_rx.await.expect("gc task acquires");
        assert!(entered);
        handle.await.expect("task completes");
    }

    // 3. GC revalidation excludes mutation
    #[tokio::test]
    async fn test_gc_revalidation_excludes_mutation() {
        let coord = ConsistencyCoordinator::new();
        let gc_guard = coord.acquire_gc_revalidation().await;

        let (entered_tx, mut entered_rx) = oneshot::channel();
        let coord_clone = coord.clone();

        let handle = tokio::spawn(async move {
            let _mut_guard = coord_clone.acquire_mutation().await;
            let _ = entered_tx.send(true);
        });

        tokio::task::yield_now().await;
        assert!(entered_rx.try_recv().is_err());

        drop(gc_guard);
        let entered = entered_rx.await.expect("mut task acquires");
        assert!(entered);
        handle.await.expect("task completes");
    }

    // 4. Guard release on error
    #[tokio::test]
    async fn test_guard_release_on_error() {
        let coord = ConsistencyCoordinator::new();

        let failing_op = || async {
            let _guard = coord.acquire_mutation().await;
            Err::<(), &'static str>("operation failed")
        };

        let res = failing_op().await;
        assert!(res.is_err());

        // Coordinator must be immediately re-acquirable
        let _gc_guard = coord.acquire_gc_revalidation().await;
    }

    // 5. Guard release on cancellation
    #[tokio::test]
    async fn test_guard_release_on_cancellation() {
        let coord = ConsistencyCoordinator::new();
        let coord_clone = coord.clone();

        let (started_tx, started_rx) = oneshot::channel();
        let (hang_tx, hang_rx) = oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            let _guard = coord_clone.acquire_mutation().await;
            let _ = started_tx.send(());
            let _ = hang_rx.await;
        });

        started_rx.await.expect("task started and acquired guard");

        // Abort the task holding the guard
        handle.abort();
        let _ = handle.await;
        drop(hang_tx);

        // Coordinator must be immediately acquirable after task abort
        let _gc_guard = coord.acquire_gc_revalidation().await;
    }

    // 6. Sequential alternating mutations and revalidations
    #[tokio::test]
    async fn test_sequential_mutations_and_revalidations() {
        let coord = ConsistencyCoordinator::new();

        for _ in 0..100 {
            let m_guard = coord.acquire_mutation().await;
            drop(m_guard);

            let g_guard = coord.acquire_gc_revalidation().await;
            drop(g_guard);
        }
    }

    // 9. Multiple concurrent mutation waiters serialize cleanly
    #[tokio::test]
    async fn test_multiple_concurrent_mutation_waiters_serialize() {
        let coord = ConsistencyCoordinator::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicBool::new(false));

        let barrier = Arc::new(Barrier::new(11));
        let mut handles = Vec::new();

        for _ in 0..10 {
            let c = coord.clone();
            let cnt = counter.clone();
            let inf = in_flight.clone();
            let b = barrier.clone();

            handles.push(tokio::spawn(async move {
                b.wait().await;
                let _guard = c.acquire_mutation().await;
                // Verify mutual exclusion: no other task should be inside
                assert!(
                    !inf.swap(true, Ordering::SeqCst),
                    "mutual exclusion violated"
                );
                tokio::task::yield_now().await;
                cnt.fetch_add(1, Ordering::SeqCst);
                inf.store(false, Ordering::SeqCst);
            }));
        }

        barrier.wait().await;
        for h in handles {
            h.await.expect("task finished");
        }

        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }

    // 10. Multiple concurrent GC revalidation waiters serialize cleanly
    #[tokio::test]
    async fn test_multiple_concurrent_gc_revalidation_waiters_serialize() {
        let coord = ConsistencyCoordinator::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicBool::new(false));

        let barrier = Arc::new(Barrier::new(11));
        let mut handles = Vec::new();

        for _ in 0..10 {
            let c = coord.clone();
            let cnt = counter.clone();
            let inf = in_flight.clone();
            let b = barrier.clone();

            handles.push(tokio::spawn(async move {
                b.wait().await;
                let _guard = c.acquire_gc_revalidation().await;
                // Verify mutual exclusion: no other task should be inside
                assert!(
                    !inf.swap(true, Ordering::SeqCst),
                    "mutual exclusion violated"
                );
                tokio::task::yield_now().await;
                cnt.fetch_add(1, Ordering::SeqCst);
                inf.store(false, Ordering::SeqCst);
            }));
        }

        barrier.wait().await;
        for h in handles {
            h.await.expect("task finished");
        }

        assert_eq!(counter.load(Ordering::SeqCst), 10);
    }

    // 11. RAII drop unblocks waiting task deterministically
    #[tokio::test]
    async fn test_raii_drop_unblocks_waiting_task() {
        let coord = ConsistencyCoordinator::new();
        let coord_clone = coord.clone();

        let (ready_tx, ready_rx) = oneshot::channel();
        let (unblocked_tx, unblocked_rx) = oneshot::channel();

        let guard = coord.acquire_mutation().await;

        let handle = tokio::spawn(async move {
            let _ = ready_tx.send(());
            let _g = coord_clone.acquire_gc_revalidation().await;
            let _ = unblocked_tx.send(());
        });

        ready_rx.await.expect("waiter spawned and waiting");
        tokio::task::yield_now().await;

        // Drop guard unblocks waiter
        drop(guard);
        unblocked_rx.await.expect("waiter unblocked");
        handle.await.expect("task completes");
    }
}
