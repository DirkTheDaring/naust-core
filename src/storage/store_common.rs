//! Shared helpers for translating backend-neutral [`StoreError`]s into the
//! registry taxonomy — pieces common to every migrated object family.

use storage_core::object_store::StoreError;

/// Structured detection of an exhausted-storage failure (`ENOSPC` /
/// `StorageFull`) anywhere in a backend error's source chain.
///
/// The filesystem backend historically classified `ENOSPC` as
/// [`crate::storage::StorageError::InsufficientStorage`] (HTTP 507). The
/// generic adapter reports such failures as `StoreError::Backend` with the
/// causal `std::io::Error` preserved in the source chain; this walks that
/// chain looking for the STRUCTURED signal (`ErrorKind::StorageFull` or a
/// raw `ENOSPC`), never message text. Remote backends carry no such cause
/// and keep their accepted `Backend` classification.
pub(crate) fn store_error_is_storage_full(err: &StoreError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = match err {
        StoreError::Backend { source, .. } | StoreError::PermissionDenied { source, .. } => source
            .as_deref()
            .map(|s| s as &(dyn std::error::Error + 'static)),
        _ => None,
    };
    while let Some(err) = source {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            if io_err.kind() == std::io::ErrorKind::StorageFull
                || io_err.raw_os_error() == Some(libc::ENOSPC)
            {
                return true;
            }
        }
        source = err.source();
    }
    false
}

/// Single authoritative exclusion domain for test scenarios that touch the
/// process-global storage-fs fault-injection table.
///
/// The table and `fault::reset` are process-global, and `reset` clears EVERY
/// armed rule, not just the caller's, so needle-scoped arming does not protect
/// a scenario from a concurrent reset. Two scenarios serialized by DIFFERENT
/// locks can therefore still interfere: one scenario's global reset lands
/// between another's arm and consume, wiping the armed rule so the "must
/// fail" operation silently succeeds. That exact interleaving was captured
/// live (the four domain-level durable-barrier fault tests failing with
/// "failed durable barrier must propagate" while the storage-fs fault tests
/// ran under a second, independent module-local lock). Every scenario in this
/// process must hold THIS guard for its entire arm -> operate -> observe ->
/// reset lifetime; do not introduce a second lock over the same table.
#[cfg(test)]
pub(crate) mod fault_scenario {
    static SCENARIO_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// An exclusive fault-injection scenario. Hold it for the full scenario
    /// lifetime; Drop clears any remaining armed rules BEFORE the lock is
    /// released (`Drop::drop` runs before field drop), so a scenario that
    /// panics or returns early cannot leak rules into the next scenario, and
    /// cleanup can never erase a newer scenario's state.
    /// `tokio::sync::Mutex` does not poison, so a failed fault test does not
    /// cascade into spurious lock failures across the rest of the suite.
    pub(crate) struct FaultScenario {
        _lock: tokio::sync::MutexGuard<'static, ()>,
    }

    /// Begin a scenario: acquire the single scenario lock, then clear any
    /// stale armed rules so the scenario starts from a clean table.
    pub(crate) async fn begin() -> FaultScenario {
        let lock = SCENARIO_LOCK.lock().await;
        storage_fs::mutate::fault::reset();
        FaultScenario { _lock: lock }
    }

    impl Drop for FaultScenario {
        fn drop(&mut self) {
            storage_fs::mutate::fault::reset();
        }
    }
}
