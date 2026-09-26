use crate::blob_gc::{
    BlobGcLimits, BlobGcPolicy, BlobGcStats, blob_gc_delete, blob_gc_delete_with_authority,
    blob_gc_plan, blob_gc_quarantine, blob_gc_quarantine_with_authority,
};
use crate::blob_ref_index::BlobRefIndex;
use crate::storage;
use fs2::FileExt;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum GcServiceError {
    #[error("gc already running")]
    AlreadyRunning,

    #[error("gc disabled")]
    Disabled,

    #[error("gc delete disabled")]
    DeleteDisabled,

    #[error("unsupported storage strategy: {message}")]
    StrategyUnsupported {
        message: &'static str,
        #[source]
        source: Option<crate::storage::StorageError>,
    },

    #[error("reference index error: {0}")]
    RefIndex(#[from] crate::blob_ref_index::RefIndexError),

    #[error("mutation authority unavailable or inactive")]
    AuthorityUnavailable,

    #[error("mutation authority released")]
    AuthorityReleased,

    #[error("gc operation failed: {0}")]
    GcOperation(#[from] crate::blob_gc::BlobGcError),

    #[error("filesystem gc lock error: {0}")]
    Lock(#[source] std::io::Error),

    #[error("storage operation failed: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("repository membership ledger operation failed: {0}")]
    Ledger(#[from] crate::repository_membership_ledger::LedgerError),

    #[error("background task join failed: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
}

#[derive(Clone, Debug)]
pub struct GcBudgets {
    pub max_blobs: usize,
    pub max_bytes: u64,
    pub max_seconds: u64,
}

impl GcBudgets {
    pub fn to_limits(&self) -> BlobGcLimits {
        BlobGcLimits {
            max_per_run: self.max_blobs,
            max_bytes: self.max_bytes,
            max_seconds: self.max_seconds,
        }
    }
}

use crate::storage::mutation_authority::RuntimeMutationAuthority;

#[derive(Clone)]
pub struct GcService {
    policy: Arc<crate::policy::GcPolicy>,
    storage: Arc<dyn storage::GcServiceStoragePort>,
    idx: Arc<BlobRefIndex>,
    run_lock: Arc<Mutex<()>>,
    consistency: crate::consistency::ConsistencyCoordinator,
    mutation_authority: Arc<Mutex<Option<RuntimeMutationAuthority>>>,
}

struct FsGcLock {
    _file: std::fs::File,
}

#[derive(Clone, Debug, Default)]
pub struct MembershipSweepStats {
    pub scanned: u64,
    pub activated: u64,
    pub candidated: u64,
    pub unlinked: u64,
    pub skipped: u64,
    pub failed: u64,
}

#[derive(Clone, Debug)]
pub struct ScheduledCleanupStats {
    pub quarantine: BlobGcStats,
    pub delete: Option<BlobGcStats>,
}

impl GcService {
    pub fn new(
        policy: Arc<crate::policy::GcPolicy>,
        storage: Arc<dyn storage::GcServiceStoragePort>,
        idx: Arc<BlobRefIndex>,
        consistency: crate::consistency::ConsistencyCoordinator,
    ) -> Self {
        Self::with_coordinator_and_authority(
            policy,
            storage,
            idx,
            consistency,
            Arc::new(Mutex::new(None)),
        )
    }

    pub fn with_authority(
        policy: Arc<crate::policy::GcPolicy>,
        storage: Arc<dyn storage::GcServiceStoragePort>,
        idx: Arc<BlobRefIndex>,
        consistency: crate::consistency::ConsistencyCoordinator,
        authority: RuntimeMutationAuthority,
    ) -> Self {
        Self::with_coordinator_and_authority(
            policy,
            storage,
            idx,
            consistency,
            Arc::new(Mutex::new(Some(authority))),
        )
    }

    pub fn with_coordinator_and_authority(
        policy: Arc<crate::policy::GcPolicy>,
        storage: Arc<dyn storage::GcServiceStoragePort>,
        idx: Arc<BlobRefIndex>,
        consistency: crate::consistency::ConsistencyCoordinator,
        mutation_authority: Arc<Mutex<Option<RuntimeMutationAuthority>>>,
    ) -> Self {
        Self {
            policy,
            storage,
            idx,
            run_lock: Arc::new(Mutex::new(())),
            consistency,
            mutation_authority,
        }
    }

    pub async fn release_authority(&self) -> Result<(), storage::StorageError> {
        if let Some(mut auth) = self.mutation_authority.lock().await.take() {
            auth.release().await?;
        }
        Ok(())
    }

    async fn ensure_ref_index_ready(&self) -> Result<(), GcServiceError> {
        let auto = self.policy.auto_rebuild_ref_index_on_corruption;
        self.idx
            .ensure_healthy_or_rebuild(self.storage.as_ref(), auto, false)
            .await?;
        Ok(())
    }

    async fn refresh_tag_rooted_index_if_needed(
        &self,
        policy: BlobGcPolicy,
    ) -> Result<(), GcServiceError> {
        if policy != BlobGcPolicy::TagRooted {
            return Ok(());
        }

        let t0 = Instant::now();
        let stats = self
            .idx
            .refresh_tag_rooted_conservative(self.storage.as_ref())
            .await?;

        tracing::info!(
            event = "blob_gc",
            action = "tag_rooted_refresh",
            refresh_ms = t0.elapsed().as_millis() as u64,
            repos_scanned = stats.repos_scanned,
            tags_scanned = stats.tags_scanned,
            roots_ingested = stats.roots_ingested,
            tags_updated = stats.tags_updated,
            "ref-index refreshed conservatively for tag-rooted gc"
        );

        Ok(())
    }

    async fn try_acquire_fs_gc_lock(&self) -> Result<Option<FsGcLock>, GcServiceError> {
        if self.storage.gc_strategy() != storage::GcStorageStrategy::FilesystemQuarantine {
            return Ok(None);
        }

        let lock_path: PathBuf = self.policy.fs_root.join("quarantine").join("gc.lock");

        let res = tokio::task::spawn_blocking(move || {
            if let Some(parent) = lock_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(&lock_path)?;

            match file.try_lock_exclusive() {
                Ok(()) => Ok(Some(FsGcLock { _file: file })),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(e),
            }
        })
        .await
        .map_err(GcServiceError::TaskJoin)?;

        match res {
            Ok(Some(lock)) => Ok(Some(lock)),
            Ok(None) => Err(GcServiceError::AlreadyRunning),
            Err(e) => Err(GcServiceError::Lock(e)),
        }
    }

    pub async fn health(&self) -> Result<(), GcServiceError> {
        self.ensure_ref_index_ready().await
    }

    pub async fn plan(
        &self,
        policy: BlobGcPolicy,
        min_age: Duration,
        budgets: GcBudgets,
    ) -> Result<BlobGcStats, GcServiceError> {
        let t0 = Instant::now();
        let _guard = self
            .run_lock
            .try_lock()
            .map_err(|_| GcServiceError::AlreadyRunning)?;
        let _fs_gc_lock = self.try_acquire_fs_gc_lock().await?;
        self.ensure_ref_index_ready().await?;
        self.refresh_tag_rooted_index_if_needed(policy).await?;
        blob_gc_plan(
            &self.storage,
            &self.idx,
            policy,
            min_age,
            budgets.to_limits(),
        )
        .await
        .map_err(GcServiceError::GcOperation)
        .inspect(|stats| {
            tracing::info!(
                event = "blob_gc",
                action = "plan",
                policy = ?policy,
                elapsed_ms = t0.elapsed().as_millis() as u64,
                scanned_blobs = stats.scanned_blobs,
                scanned_bytes = stats.scanned_bytes,
                eligible_blobs = stats.eligible_blobs,
                eligible_bytes = stats.eligible_bytes,
                "blob gc plan finished"
            );
        })
    }

    pub async fn quarantine(
        &self,
        policy: BlobGcPolicy,
        min_age: Duration,
        budgets: GcBudgets,
    ) -> Result<BlobGcStats, GcServiceError> {
        let t0 = Instant::now();

        if self.storage.gc_strategy() == storage::GcStorageStrategy::S3DirectConditional {
            return Err(GcServiceError::StrategyUnsupported {
                message: "quarantine is not supported for S3 storage backend; use delete or scheduled cleanup with S3DirectConditional",
                source: None,
            });
        }

        // -----------------------------------------------------------------------------------------
        // LOCK ORDER (strictly preserved across all GC mutation paths):
        // 1. self.run_lock: In-process mutual exclusion between concurrent GC executions.
        // 2. _fs_gc_lock: Cross-process file lock on `quarantine/gc.lock` (for filesystem backend).
        // 3. (auth_guard & consistency_coordinator): Acquired per bounded candidate check inside
        //    blob_gc_quarantine / blob_gc_delete.
        // -----------------------------------------------------------------------------------------
        let _run_guard = self
            .run_lock
            .try_lock()
            .map_err(|_| GcServiceError::AlreadyRunning)?;

        let _fs_gc_lock = self.try_acquire_fs_gc_lock().await?;

        if !self.policy.enabled {
            return Err(GcServiceError::Disabled);
        }

        // Validate authority is present and active before starting run
        {
            let auth_guard = self.mutation_authority.lock().await;
            let Some(ref auth) = *auth_guard else {
                return Err(GcServiceError::AuthorityUnavailable);
            };
            if !auth.is_active() {
                return Err(GcServiceError::AuthorityReleased);
            }
        }

        self.ensure_ref_index_ready().await?;
        self.refresh_tag_rooted_index_if_needed(policy).await?;

        blob_gc_quarantine(
            &self.storage,
            &self.idx,
            &self.consistency,
            &self.mutation_authority,
            policy,
            min_age,
            budgets.to_limits(),
        )
        .await
        .map_err(GcServiceError::GcOperation)
        .inspect(|stats| {
            tracing::info!(
                event = "blob_gc",
                action = "quarantine",
                policy = ?policy,
                elapsed_ms = t0.elapsed().as_millis() as u64,
                scanned_blobs = stats.scanned_blobs,
                scanned_bytes = stats.scanned_bytes,
                quarantined_blobs = stats.quarantined_blobs,
                quarantined_bytes = stats.quarantined_bytes,
                restored_blobs = stats.restored_blobs,
                restored_bytes = stats.restored_bytes,
                "blob gc quarantine finished"
            );
        })
    }

    pub async fn quarantine_with_authority(
        &self,
        authority: &RuntimeMutationAuthority,
        policy: BlobGcPolicy,
        min_age: Duration,
        budgets: GcBudgets,
    ) -> Result<BlobGcStats, GcServiceError> {
        let t0 = Instant::now();

        if self.storage.gc_strategy() == storage::GcStorageStrategy::S3DirectConditional {
            return Err(GcServiceError::StrategyUnsupported {
                message: "quarantine is not supported for S3 storage backend; use delete or scheduled cleanup with S3DirectConditional",
                source: None,
            });
        }

        let _run_guard = self
            .run_lock
            .try_lock()
            .map_err(|_| GcServiceError::AlreadyRunning)?;

        let _fs_gc_lock = self.try_acquire_fs_gc_lock().await?;

        if !self.policy.enabled {
            return Err(GcServiceError::Disabled);
        }

        if !authority.is_active() {
            return Err(GcServiceError::AuthorityReleased);
        }

        self.ensure_ref_index_ready().await?;
        self.refresh_tag_rooted_index_if_needed(policy).await?;

        blob_gc_quarantine_with_authority(
            &self.storage,
            &self.idx,
            &self.consistency,
            authority,
            policy,
            min_age,
            budgets.to_limits(),
        )
        .await
        .map_err(GcServiceError::GcOperation)
        .inspect(|stats| {
            tracing::info!(
                event = "blob_gc",
                action = "quarantine",
                policy = ?policy,
                elapsed_ms = t0.elapsed().as_millis() as u64,
                scanned_blobs = stats.scanned_blobs,
                scanned_bytes = stats.scanned_bytes,
                quarantined_blobs = stats.quarantined_blobs,
                quarantined_bytes = stats.quarantined_bytes,
                restored_blobs = stats.restored_blobs,
                restored_bytes = stats.restored_bytes,
                "blob gc quarantine finished"
            );
        })
    }

    pub async fn delete(
        &self,
        policy: BlobGcPolicy,
        quarantine_delay: Duration,
        budgets: GcBudgets,
    ) -> Result<BlobGcStats, GcServiceError> {
        let t0 = Instant::now();

        // -----------------------------------------------------------------------------------------
        // LOCK ORDER (strictly preserved across all GC mutation paths):
        // 1. self.run_lock: In-process mutual exclusion between concurrent GC executions.
        // 2. _fs_gc_lock: Cross-process file lock on `quarantine/gc.lock` (for filesystem backend).
        // 3. (auth_guard & consistency_coordinator): Acquired per bounded candidate check inside
        //    blob_gc_delete.
        // -----------------------------------------------------------------------------------------
        let _run_guard = self
            .run_lock
            .try_lock()
            .map_err(|_| GcServiceError::AlreadyRunning)?;

        let _fs_gc_lock = self.try_acquire_fs_gc_lock().await?;

        if !self.policy.enabled {
            return Err(GcServiceError::Disabled);
        }
        if !self.policy.enable_delete {
            return Err(GcServiceError::DeleteDisabled);
        }

        // Validate authority is present and active before starting run
        {
            let auth_guard = self.mutation_authority.lock().await;
            let Some(ref auth) = *auth_guard else {
                return Err(GcServiceError::AuthorityUnavailable);
            };
            if !auth.is_active() {
                return Err(GcServiceError::AuthorityReleased);
            }
        }

        self.ensure_ref_index_ready().await?;
        self.refresh_tag_rooted_index_if_needed(policy).await?;

        if self.storage.gc_strategy() == storage::GcStorageStrategy::S3DirectConditional {
            self.storage
                .check_bucket_versioning_for_gc()
                .await
                .map_err(|e| GcServiceError::StrategyUnsupported {
                    message: "S3 bucket versioning check failed",
                    source: Some(e),
                })?;
        }

        blob_gc_delete(
            &self.policy.fs_root,
            &self.storage,
            &self.idx,
            &self.consistency,
            &self.mutation_authority,
            policy,
            quarantine_delay,
            budgets.to_limits(),
        )
        .await
        .map_err(GcServiceError::GcOperation)
        .inspect(|stats| {
            tracing::info!(
                event = "blob_gc",
                action = "delete",
                policy = ?policy,
                elapsed_ms = t0.elapsed().as_millis() as u64,
                restored_blobs = stats.restored_blobs,
                restored_bytes = stats.restored_bytes,
                deleted_blobs = stats.deleted_blobs,
                deleted_bytes = stats.deleted_bytes,
                "blob gc delete finished"
            );
        })
    }

    pub async fn delete_with_authority(
        &self,
        authority: &RuntimeMutationAuthority,
        policy: BlobGcPolicy,
        quarantine_delay: Duration,
        budgets: GcBudgets,
    ) -> Result<BlobGcStats, GcServiceError> {
        let t0 = Instant::now();

        let _run_guard = self
            .run_lock
            .try_lock()
            .map_err(|_| GcServiceError::AlreadyRunning)?;

        let _fs_gc_lock = self.try_acquire_fs_gc_lock().await?;

        if !self.policy.enabled {
            return Err(GcServiceError::Disabled);
        }
        if !self.policy.enable_delete {
            return Err(GcServiceError::DeleteDisabled);
        }

        if !authority.is_active() {
            return Err(GcServiceError::AuthorityReleased);
        }

        self.ensure_ref_index_ready().await?;
        self.refresh_tag_rooted_index_if_needed(policy).await?;

        if self.storage.gc_strategy() == storage::GcStorageStrategy::S3DirectConditional {
            self.storage
                .check_bucket_versioning_for_gc()
                .await
                .map_err(|e| GcServiceError::StrategyUnsupported {
                    message: "S3 bucket versioning check failed",
                    source: Some(e),
                })?;
        }

        blob_gc_delete_with_authority(
            &self.policy.fs_root,
            &self.storage,
            &self.idx,
            &self.consistency,
            authority,
            policy,
            quarantine_delay,
            budgets.to_limits(),
        )
        .await
        .map_err(GcServiceError::GcOperation)
        .inspect(|stats| {
            tracing::info!(
                event = "blob_gc",
                action = "delete",
                policy = ?policy,
                elapsed_ms = t0.elapsed().as_millis() as u64,
                restored_blobs = stats.restored_blobs,
                restored_bytes = stats.restored_bytes,
                deleted_blobs = stats.deleted_blobs,
                deleted_bytes = stats.deleted_bytes,
                "blob gc delete finished"
            );
        })
    }

    pub async fn sweep_repository_memberships(
        &self,
        grace_period: Duration,
        page_limit: usize,
    ) -> Result<MembershipSweepStats, GcServiceError> {
        let guard = self
            .run_lock
            .try_lock()
            .map_err(|_| GcServiceError::AlreadyRunning)?;
        self.sweep_repository_memberships_with_guard(&guard, grace_period, page_limit)
            .await
    }

    pub async fn sweep_repository_memberships_with_guard(
        &self,
        _run_guard: &tokio::sync::MutexGuard<'_, ()>,
        grace_period: Duration,
        page_limit: usize,
    ) -> Result<MembershipSweepStats, GcServiceError> {
        use crate::storage::repo_membership::MembershipState;
        use std::time::UNIX_EPOCH;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut stats = MembershipSweepStats::default();
        let ledger = crate::repository_membership_ledger::RepositoryMembershipLedger::new(
            Arc::new(self.storage.clone()),
            Some(Arc::clone(&self.idx)),
            self.consistency.clone(),
        );

        let mut continuation: Option<String> = None;
        loop {
            let (records, next_tok) = self
                .storage
                .list_all_repo_blob_memberships_page(continuation.as_deref(), page_limit)
                .await?;

            for rec in records {
                stats.scanned += 1;
                let is_referenced = crate::blob_delete_safety::find_repo_blob_reference(
                    self.storage.as_ref(),
                    rec.repo.as_str(),
                    &rec.digest,
                )
                .await?
                .is_some();

                if is_referenced {
                    if rec.state == MembershipState::Candidate
                        || rec.unreferenced_since_unix_secs.is_some()
                    {
                        if ledger.reactivate(rec.repo.as_str(), &rec.digest).await? {
                            stats.activated += 1;
                        } else {
                            stats.skipped += 1;
                        }
                    } else {
                        stats.skipped += 1;
                    }
                } else {
                    // Unreferenced in repository
                    if rec.state == MembershipState::Active
                        || rec.unreferenced_since_unix_secs.is_none()
                    {
                        if ledger
                            .set_candidate(rec.repo.as_str(), &rec.digest, now)
                            .await?
                        {
                            stats.candidated += 1;
                        } else {
                            stats.skipped += 1;
                        }
                    } else if rec.state == MembershipState::Candidate {
                        let unref_time = rec
                            .unreferenced_since_unix_secs
                            .unwrap_or(rec.created_at_unix_secs);
                        if now.saturating_sub(unref_time) >= grace_period.as_secs() {
                            // Revalidate before unlinking
                            let still_referenced =
                                match crate::blob_delete_safety::find_repo_blob_reference(
                                    self.storage.as_ref(),
                                    rec.repo.as_str(),
                                    &rec.digest,
                                )
                                .await
                                {
                                    Ok(r) => r.is_some(),
                                    Err(_) => true,
                                };

                            if !still_referenced {
                                if ledger.unlink(rec.repo.as_str(), &rec.digest).await? {
                                    stats.unlinked += 1;
                                } else {
                                    stats.skipped += 1;
                                }
                            } else {
                                stats.skipped += 1;
                            }
                        } else {
                            stats.skipped += 1;
                        }
                    }
                }
            }

            match next_tok {
                Some(tok) => continuation = Some(tok),
                None => break,
            }
        }

        tracing::info!(
            event = "blob_membership_gc",
            scanned = stats.scanned,
            activated = stats.activated,
            candidated = stats.candidated,
            unlinked = stats.unlinked,
            skipped = stats.skipped,
            failed = stats.failed,
            "repository membership gc sweep completed"
        );

        Ok(stats)
    }

    pub async fn scheduled_cleanup_once(&self) -> Result<ScheduledCleanupStats, GcServiceError> {
        let _run_guard = self
            .run_lock
            .try_lock()
            .map_err(|_| GcServiceError::AlreadyRunning)?;

        let _fs_gc_lock = self.try_acquire_fs_gc_lock().await?;

        if !self.policy.enabled {
            return Err(GcServiceError::Disabled);
        }

        {
            let auth_guard = self.mutation_authority.lock().await;
            let Some(ref auth) = *auth_guard else {
                return Err(GcServiceError::AuthorityUnavailable);
            };
            if !auth.is_active() {
                return Err(GcServiceError::AuthorityReleased);
            }
        }

        self.ensure_ref_index_ready().await?;

        let min_age = Duration::from_secs(self.policy.default_min_age_secs);

        // 1. Sweep repository memberships: Active -> Candidate(unreferenced_since) -> Unlink
        let _membership_stats = self
            .sweep_repository_memberships_with_guard(&_run_guard, min_age, 256)
            .await?;

        let policy = BlobGcPolicy::ManifestRooted;
        let budgets = GcBudgets {
            max_blobs: self.policy.default_max_blobs,
            max_bytes: self.policy.default_max_bytes,
            max_seconds: self.policy.default_max_seconds,
        };

        match self.storage.gc_strategy() {
            storage::GcStorageStrategy::S3DirectConditional => {
                if !self.policy.enable_delete {
                    return Ok(ScheduledCleanupStats {
                        quarantine: Default::default(),
                        delete: None,
                    });
                }
                self.storage
                    .check_bucket_versioning_for_gc()
                    .await
                    .map_err(|e| GcServiceError::StrategyUnsupported {
                        message: "S3 bucket versioning check failed",
                        source: Some(e),
                    })?;
                let delete = blob_gc_delete(
                    &self.policy.fs_root,
                    &self.storage,
                    &self.idx,
                    &self.consistency,
                    &self.mutation_authority,
                    policy,
                    min_age,
                    budgets.to_limits(),
                )
                .await
                .map_err(GcServiceError::GcOperation)?;

                Ok(ScheduledCleanupStats {
                    quarantine: Default::default(),
                    delete: Some(delete),
                })
            }
            storage::GcStorageStrategy::FilesystemQuarantine => {
                let quarantine = blob_gc_quarantine(
                    &self.storage,
                    &self.idx,
                    &self.consistency,
                    &self.mutation_authority,
                    policy,
                    min_age,
                    budgets.to_limits(),
                )
                .await
                .map_err(GcServiceError::GcOperation)?;

                let delete = if self.policy.enable_delete {
                    let quarantine_delay =
                        Duration::from_secs(self.policy.default_quarantine_delay_secs);
                    Some(
                        blob_gc_delete(
                            &self.policy.fs_root,
                            &self.storage,
                            &self.idx,
                            &self.consistency,
                            &self.mutation_authority,
                            policy,
                            quarantine_delay,
                            budgets.to_limits(),
                        )
                        .await
                        .map_err(GcServiceError::GcOperation)?,
                    )
                } else {
                    None
                };

                Ok(ScheduledCleanupStats { quarantine, delete })
            }
        }
    }

    pub fn try_lock_run(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        self.run_lock.try_lock().ok()
    }

    #[doc(hidden)]
    pub fn test_try_lock(&self) -> Option<tokio::sync::MutexGuard<'_, ()>> {
        self.try_lock_run()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::digest::Digest;
    use crate::storage::fs::FsStorage;
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
    use sha2::Digest as _;
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn tmp_dir(prefix: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("naust-{prefix}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    const TEST_MAX_UPLOAD_BYTES: u64 = 5 * 1024 * 1024;

    fn minimal_policy(fs_root: PathBuf) -> crate::policy::GcPolicy {
        crate::policy::GcPolicy {
            enabled: true,
            enable_delete: true,
            default_min_age_secs: 7 * 24 * 3600,
            default_quarantine_delay_secs: 24 * 3600,
            default_max_blobs: 1000,
            default_max_bytes: u64::MAX,
            default_max_seconds: 60,
            auto_rebuild_ref_index_on_corruption: true,
            fs_root,
        }
    }

    #[tokio::test]
    async fn scheduled_cleanup_runs_quarantine_and_delete_when_enabled() {
        let fs_root = tmp_dir("sched-gc");
        let ref_index_path = fs_root.join("ref-index");
        let mut cfg = minimal_policy(fs_root.clone());

        cfg.enabled = true;
        cfg.enable_delete = true;
        cfg.default_min_age_secs = 0;
        cfg.default_quarantine_delay_secs = 0;
        cfg.default_max_blobs = 1000;

        let cfg = Arc::new(cfg);
        let backend = Arc::new(FsStorage::new(fs_root.clone(), TEST_MAX_UPLOAD_BYTES));
        let wiring = storage::StorageWiring::from_backend(backend.clone());
        let idx = Arc::new(BlobRefIndex::open(ref_index_path.clone()).expect("open idx"));
        idx.ensure_healthy_or_rebuild(wiring.blob_ref_index().as_ref(), true, true)
            .await
            .expect("ensure idx");

        let authority = crate::storage::mutation_authority::RuntimeMutationAuthority::acquire(
            wiring.cluster_lock(),
            "test-sched-gc",
        )
        .await
        .expect("authority");

        // Create an unreferenced blob in live store.
        let data = b"scheduled-cleanup";
        let hex = hex::encode(sha2::Sha256::digest(data));
        let digest = Digest::parse(&format!("sha256:{hex}")).expect("digest");
        let live = fs_root
            .join("blobs")
            .join("sha256")
            .join(&hex[0..2])
            .join(&hex);
        std::fs::create_dir_all(live.parent().unwrap()).expect("mkdir");
        std::fs::write(&live, data).expect("write");

        let coordinator = crate::consistency::ConsistencyCoordinator::new();
        let service = GcService::with_authority(
            cfg.clone(),
            wiring.gc_service_port(),
            idx.clone(),
            coordinator,
            authority,
        );

        let stats = service
            .scheduled_cleanup_once()
            .await
            .expect("scheduled cleanup");

        assert!(stats.quarantine.scanned_blobs >= 1);
        assert!(stats.delete.is_some());
        assert!(!live.exists(), "blob should be moved out of live");

        let q = fs_root
            .join("quarantine")
            .join("blobs")
            .join("sha256")
            .join(&hex[0..2])
            .join(&hex);
        assert!(!q.exists(), "blob should be deleted from quarantine");
        let _ = digest;
    }

    async fn write_blob(fs_root: &std::path::Path, digest: &Digest, bytes: &[u8]) {
        let dir = fs_root.join("blobs").join("sha256").join(digest.prefix2());
        tokio::fs::create_dir_all(&dir).await.expect("mkdir");
        tokio::fs::write(dir.join(digest.hex()), bytes)
            .await
            .expect("write blob");
    }

    async fn write_tag_and_manifest(
        fs_root: &std::path::Path,
        repo: &str,
        tag: &str,
        root_manifest: &Digest,
        manifest_bytes: &[u8],
    ) {
        let repo_dir = fs_root.join("repos").join(repo);
        let tags_dir = repo_dir.join("tags");
        let manifests_dir = repo_dir.join("manifests");
        tokio::fs::create_dir_all(&tags_dir)
            .await
            .expect("mkdir tags");
        tokio::fs::create_dir_all(&manifests_dir)
            .await
            .expect("mkdir manifests");

        tokio::fs::write(tags_dir.join(tag), format!("{}\n", root_manifest.as_str()))
            .await
            .expect("write tag");
        tokio::fs::write(manifests_dir.join(root_manifest.hex()), manifest_bytes)
            .await
            .expect("write manifest");
    }

    #[tokio::test]
    async fn quarantine_then_restore_when_becomes_referenced() {
        let fs_root = tmp_dir("gc-fsroot");
        let ref_index_path = tmp_dir("gc-refindex");

        let cfg = Arc::new(minimal_policy(fs_root.clone()));
        let backend = Arc::new(FsStorage::new(fs_root.clone(), TEST_MAX_UPLOAD_BYTES));
        let wiring = storage::StorageWiring::from_backend(backend.clone());

        let idx = Arc::new(BlobRefIndex::open(ref_index_path.clone()).expect("open idx"));
        idx.rebuild(wiring.blob_ref_index().as_ref())
            .await
            .expect("rebuild empty");

        let authority = crate::storage::mutation_authority::RuntimeMutationAuthority::acquire(
            wiring.cluster_lock(),
            "test-quarantine-restore",
        )
        .await
        .expect("authority");

        let coordinator = crate::consistency::ConsistencyCoordinator::new();
        let service = GcService::with_authority(
            cfg.clone(),
            wiring.gc_service_port(),
            idx.clone(),
            coordinator,
            authority,
        );

        let blob = Digest::parse(&format!("sha256:{}", "a".repeat(64))).expect("digest");
        write_blob(&fs_root, &blob, b"blobdata").await;

        let budgets = GcBudgets {
            max_blobs: 1000,
            max_bytes: u64::MAX,
            max_seconds: u64::MAX,
        };

        let q = service
            .quarantine(
                BlobGcPolicy::TagRooted,
                Duration::from_secs(0),
                budgets.clone(),
            )
            .await
            .expect("quarantine");
        assert_eq!(q.quarantined_blobs, 1);

        // Now create a tag root manifest referencing this blob, and rebuild the index.
        let root = Digest::parse(&format!("sha256:{}", "b".repeat(64))).expect("digest");
        let cfg_digest = Digest::parse(&format!("sha256:{}", "c".repeat(64))).expect("digest");
        let manifest = format!(
            "{{\"schemaVersion\":2,\"config\":{{\"digest\":\"{}\"}},\"layers\":[{{\"digest\":\"{}\"}}]}}",
            cfg_digest.as_str(),
            blob.as_str()
        );
        write_tag_and_manifest(&fs_root, "org/repo", "latest", &root, manifest.as_bytes()).await;

        idx.rebuild(wiring.blob_ref_index().as_ref())
            .await
            .expect("rebuild with tag");

        // With quarantine_delay=0, delete phase should restore instead of deleting.
        let d = service
            .delete(BlobGcPolicy::TagRooted, Duration::from_secs(0), budgets)
            .await
            .expect("delete");
        assert_eq!(d.restored_blobs, 1);
        assert_eq!(d.deleted_blobs, 0);

        // Sanity: blob should be readable from live path now.
        let live_path = fs_root
            .join("blobs")
            .join("sha256")
            .join(blob.prefix2())
            .join(blob.hex());
        assert!(tokio::fs::metadata(&live_path).await.is_ok());

        let _ = std::fs::remove_dir_all(&fs_root);
        let _ = std::fs::remove_dir_all(&ref_index_path);
    }

    #[tokio::test]
    async fn pinned_blobs_are_skipped() {
        let fs_root = tmp_dir("gc-fsroot2");
        let ref_index_path = tmp_dir("gc-refindex2");

        let cfg = Arc::new(minimal_policy(fs_root.clone()));
        let backend = Arc::new(FsStorage::new(fs_root.clone(), TEST_MAX_UPLOAD_BYTES));
        let wiring = storage::StorageWiring::from_backend(backend.clone());
        let idx = Arc::new(BlobRefIndex::open(ref_index_path.clone()).expect("open idx"));
        idx.rebuild(wiring.blob_ref_index().as_ref())
            .await
            .expect("rebuild");

        let authority = crate::storage::mutation_authority::RuntimeMutationAuthority::acquire(
            wiring.cluster_lock(),
            "test-pinned",
        )
        .await
        .expect("authority");

        let coordinator = crate::consistency::ConsistencyCoordinator::new();
        let service = GcService::with_authority(
            cfg.clone(),
            wiring.gc_service_port(),
            idx.clone(),
            coordinator,
            authority,
        );

        let blob = Digest::parse(&format!("sha256:{}", "d".repeat(64))).expect("digest");
        write_blob(&fs_root, &blob, b"blobdata").await;

        idx.pin_blob(
            &blob,
            SystemTime::now() + Duration::from_secs(10_000),
            "test",
        )
        .expect("pin");

        let budgets = GcBudgets {
            max_blobs: 1000,
            max_bytes: u64::MAX,
            max_seconds: u64::MAX,
        };

        let q = service
            .quarantine(BlobGcPolicy::TagRooted, Duration::from_secs(0), budgets)
            .await
            .expect("quarantine");
        assert_eq!(q.quarantined_blobs, 0);

        let _ = std::fs::remove_dir_all(&fs_root);
        let _ = std::fs::remove_dir_all(&ref_index_path);
    }

    #[tokio::test]
    async fn service_is_single_run() {
        let fs_root = tmp_dir("gc-fsroot3");
        let ref_index_path = tmp_dir("gc-refindex3");

        let cfg = Arc::new(minimal_policy(fs_root.clone()));
        let backend = Arc::new(FsStorage::new(fs_root.clone(), TEST_MAX_UPLOAD_BYTES));
        let wiring = storage::StorageWiring::from_backend(backend.clone());
        let idx = Arc::new(BlobRefIndex::open(ref_index_path.clone()).expect("open idx"));
        idx.rebuild(wiring.blob_ref_index().as_ref())
            .await
            .expect("rebuild");

        let service = GcService::new(
            cfg.clone(),
            wiring.gc_service_port(),
            idx.clone(),
            crate::consistency::ConsistencyCoordinator::new(),
        );

        // Hold the lock manually, then ensure plan refuses.
        let _held = service.run_lock.try_lock().expect("lock");
        let budgets = GcBudgets {
            max_blobs: 1,
            max_bytes: 1,
            max_seconds: 1,
        };
        let err = service
            .plan(BlobGcPolicy::TagRooted, Duration::from_secs(0), budgets)
            .await
            .expect_err("should refuse");
        assert!(matches!(err, GcServiceError::AlreadyRunning));

        let _ = std::fs::remove_dir_all(&fs_root);
        let _ = std::fs::remove_dir_all(&ref_index_path);
    }

    #[tokio::test]
    async fn test_gc_service_membership_aging_lifecycle() {
        use crate::storage::repo_membership::{MembershipState, RepoBlobMembershipRecord};

        let fs_root = tmp_dir("gc-fsroot-aging");
        let ref_index_path = tmp_dir("gc-refindex-aging");

        let cfg = Arc::new(minimal_policy(fs_root.clone()));
        let backend = Arc::new(FsStorage::new(fs_root.clone(), TEST_MAX_UPLOAD_BYTES));
        let wiring = storage::StorageWiring::from_backend(backend.clone());
        let idx = Arc::new(BlobRefIndex::open(ref_index_path.clone()).expect("open idx"));
        idx.rebuild(wiring.blob_ref_index().as_ref())
            .await
            .expect("rebuild");

        let service = GcService::new(
            cfg.clone(),
            wiring.gc_service_port(),
            idx.clone(),
            crate::consistency::ConsistencyCoordinator::new(),
        );

        let repo = "aging-repo";
        let blob = Digest::parse(&format!("sha256:{}", "e".repeat(64))).expect("digest");
        write_blob(&fs_root, &blob, b"agingdata").await;

        let canonical_repo =
            crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap();
        let rec = RepoBlobMembershipRecord::new_upload(canonical_repo, blob.clone(), None);
        backend.link_repo_blob(&rec).await.unwrap();
        idx.record_membership(&blob, repo).unwrap();

        // 1. First scan: blob is unreferenced by any manifest, so Active -> Candidate with unreferenced_since
        let s1 = service
            .sweep_repository_memberships(Duration::from_secs(10), 256)
            .await
            .unwrap();
        assert_eq!(s1.candidated, 1);
        assert_eq!(s1.unlinked, 0);

        let mem1 = backend
            .get_repo_blob_membership(repo, &blob)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mem1.state, MembershipState::Candidate);
        assert!(mem1.unreferenced_since_unix_secs.is_some());

        // 2. Second scan within grace period: stays Candidate, no unlink
        let s2 = service
            .sweep_repository_memberships(Duration::from_secs(10), 256)
            .await
            .unwrap();
        assert_eq!(s2.candidated, 0);
        assert_eq!(s2.unlinked, 0);

        // 3. Third scan with 0 grace period: unlinks membership
        let s3 = service
            .sweep_repository_memberships(Duration::from_secs(0), 256)
            .await
            .unwrap();
        assert_eq!(s3.unlinked, 1);

        let mem_after = backend.get_repo_blob_membership(repo, &blob).await.unwrap();
        assert!(mem_after.is_none());
        assert!(!idx.has_any_repo_membership(&blob).unwrap());

        let _ = std::fs::remove_dir_all(&fs_root);
        let _ = std::fs::remove_dir_all(&ref_index_path);
    }

    #[tokio::test]
    async fn fs_gc_lock_follows_port_strategy_not_backend_identity() {
        // FilesystemQuarantine strategy: the ambient quarantine/gc.lock is taken.
        let fs_root = tmp_dir("gc-lock-strategy");
        let policy = Arc::new(minimal_policy(fs_root.clone()));
        let backend = Arc::new(FsStorage::new(fs_root.clone(), TEST_MAX_UPLOAD_BYTES));
        let wiring = storage::StorageWiring::from_backend(backend);
        let idx = Arc::new(BlobRefIndex::open(fs_root.join("ref-index")).expect("open idx"));
        let svc = GcService::new(
            policy.clone(),
            wiring.gc_service_port(),
            idx.clone(),
            crate::consistency::ConsistencyCoordinator::new(),
        );
        assert_eq!(
            svc.storage.gc_strategy(),
            storage::GcStorageStrategy::FilesystemQuarantine
        );
        let lock = svc.try_acquire_fs_gc_lock().await.expect("fs lock path");
        assert!(lock.is_some(), "FS strategy must take the quarantine lock");
        drop(lock);

        // S3DirectConditional strategy: no filesystem lock is attempted even
        // though the policy still carries an fs_root (equivalence with the
        // former `config.storage_backend != Filesystem` branch).
        let (s3_storage, _driver) = crate::storage::s3::tests::create_mock_storage();
        let wiring_s3 = storage::StorageWiring::from_backend(Arc::new(s3_storage));
        let svc_s3 = GcService::new(
            policy,
            wiring_s3.gc_service_port(),
            idx,
            crate::consistency::ConsistencyCoordinator::new(),
        );
        assert_eq!(
            svc_s3.storage.gc_strategy(),
            storage::GcStorageStrategy::S3DirectConditional
        );
        let none = svc_s3
            .try_acquire_fs_gc_lock()
            .await
            .expect("s3 strategy skips the fs lock");
        assert!(none.is_none());

        let _ = std::fs::remove_dir_all(&fs_root);
    }
}
