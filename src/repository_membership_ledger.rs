use crate::blob_ref_index::{BlobRefIndex, RefIndexError};
use crate::registry::digest::Digest;
use crate::storage::{RepoBlobMembershipRecord, StorageError};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("ref-index error: {0}")]
    RefIndex(#[from] RefIndexError),

    #[error("index required: {0}")]
    IndexRequired(String),

    #[error("ledger corrupt: {0}")]
    Corrupt(String),
}

#[derive(Clone)]
pub enum LedgerIndexMode {
    Indexed(Arc<BlobRefIndex>),
    StorageOnly,
}

use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

/// Dedicated, narrowly scoped application service that coordinates mutations between
/// authoritative storage membership markers and the rebuildable reverse index.
#[derive(Clone)]
pub struct RepositoryMembershipLedger {
    storage: Arc<dyn RepositoryBlobMembershipStorage>,
    mode: LedgerIndexMode,
    consistency: crate::consistency::ConsistencyCoordinator,
}

impl RepositoryMembershipLedger {
    pub fn new(
        storage: Arc<dyn RepositoryBlobMembershipStorage>,
        ref_index: Option<Arc<BlobRefIndex>>,
        consistency: crate::consistency::ConsistencyCoordinator,
    ) -> Self {
        match ref_index {
            Some(idx) => Self::indexed(storage, idx, consistency),
            None => Self::storage_only(storage, consistency),
        }
    }

    pub fn indexed(
        storage: Arc<dyn RepositoryBlobMembershipStorage>,
        ref_index: Arc<BlobRefIndex>,
        consistency: crate::consistency::ConsistencyCoordinator,
    ) -> Self {
        Self {
            storage,
            mode: LedgerIndexMode::Indexed(ref_index),
            consistency,
        }
    }

    pub fn storage_only(
        storage: Arc<dyn RepositoryBlobMembershipStorage>,
        consistency: crate::consistency::ConsistencyCoordinator,
    ) -> Self {
        Self {
            storage,
            mode: LedgerIndexMode::StorageOnly,
            consistency,
        }
    }

    pub fn storage(&self) -> &Arc<dyn RepositoryBlobMembershipStorage> {
        &self.storage
    }

    pub fn mode(&self) -> &LedgerIndexMode {
        &self.mode
    }

    pub fn ref_index(&self) -> Option<&Arc<BlobRefIndex>> {
        match &self.mode {
            LedgerIndexMode::Indexed(idx) => Some(idx),
            LedgerIndexMode::StorageOnly => None,
        }
    }

    pub fn is_indexed(&self) -> bool {
        matches!(&self.mode, LedgerIndexMode::Indexed(_))
    }

    pub fn consistency(&self) -> &crate::consistency::ConsistencyCoordinator {
        &self.consistency
    }

    /// Durable link with internal coordinator acquisition.
    pub async fn link(&self, record: &RepoBlobMembershipRecord) -> Result<(), LedgerError> {
        let guard = self.consistency.acquire_mutation().await;
        self.link_with_guard(&guard, record).await
    }

    /// Durable link using an existing lock guard (avoids lock inversion / re-entrancy).
    pub async fn link_with_guard(
        &self,
        _guard: &crate::consistency::MutationGuard,
        record: &RepoBlobMembershipRecord,
    ) -> Result<(), LedgerError> {
        // 1. Ensure reverse index is healthy
        if let LedgerIndexMode::Indexed(ref idx) = self.mode {
            idx.check_health()?;
            // 2. Durably mark index dirty before mutating storage
            idx.mark_dirty()?;
        }

        // 3. Create / confirm authoritative marker in storage
        self.storage.link_repo_blob(record).await?;

        // 4. Update and flush reverse index
        if let LedgerIndexMode::Indexed(ref idx) = self.mode {
            idx.record_membership(&record.digest, record.repo.as_str())?;
            idx.flush()?;
            // 5. Mark index ready
            idx.mark_ready()?;
        }

        Ok(())
    }

    /// Durable unlink with internal coordinator acquisition.
    pub async fn unlink(&self, repo: &str, digest: &Digest) -> Result<bool, LedgerError> {
        let guard = self.consistency.acquire_mutation().await;
        self.unlink_with_guard(&guard, repo, digest).await
    }

    /// Durable unlink using an existing lock guard.
    pub async fn unlink_with_guard(
        &self,
        _guard: &crate::consistency::MutationGuard,
        repo: &str,
        digest: &Digest,
    ) -> Result<bool, LedgerError> {
        // 1. Ensure reverse index is healthy
        if let LedgerIndexMode::Indexed(ref idx) = self.mode {
            idx.check_health()?;
            // 2. Durably mark dirty before removal
            idx.mark_dirty()?;
        }

        // 3. Remove authoritative marker conditionally
        let removed = self.storage.unlink_repo_blob(repo, digest).await?;

        // 4. Update and flush reverse index
        if let LedgerIndexMode::Indexed(ref idx) = self.mode {
            if removed {
                idx.remove_membership(digest, repo)?;
            }
            idx.flush()?;
            // 5. Mark index ready
            idx.mark_ready()?;
        }

        Ok(removed)
    }

    /// Set candidate state with internal coordinator acquisition.
    pub async fn set_candidate(
        &self,
        repo: &str,
        digest: &Digest,
        since_unix_secs: u64,
    ) -> Result<bool, LedgerError> {
        let guard = self.consistency.acquire_mutation().await;
        self.set_candidate_with_guard(&guard, repo, digest, since_unix_secs)
            .await
    }

    /// Set candidate state using an existing lock guard.
    pub async fn set_candidate_with_guard(
        &self,
        _guard: &crate::consistency::MutationGuard,
        repo: &str,
        digest: &Digest,
        since_unix_secs: u64,
    ) -> Result<bool, LedgerError> {
        // Candidates remain in reverse index so GC will not collect them prematurely.
        let changed = self
            .storage
            .set_membership_candidate(repo, digest, since_unix_secs)
            .await?;
        Ok(changed)
    }

    /// Reactivate candidate to Active with internal coordinator acquisition.
    pub async fn reactivate(&self, repo: &str, digest: &Digest) -> Result<bool, LedgerError> {
        let guard = self.consistency.acquire_mutation().await;
        self.reactivate_with_guard(&guard, repo, digest).await
    }

    /// Reactivate candidate to Active using an existing lock guard.
    pub async fn reactivate_with_guard(
        &self,
        _guard: &crate::consistency::MutationGuard,
        repo: &str,
        digest: &Digest,
    ) -> Result<bool, LedgerError> {
        let changed = self
            .storage
            .clear_membership_candidate(repo, digest)
            .await?;
        if changed && let LedgerIndexMode::Indexed(ref idx) = self.mode {
            // Ensure reverse index records this active membership
            let _ = idx.record_membership(digest, repo);
        }
        Ok(changed)
    }

    /// Direct lookup of authoritative repository membership record.
    pub async fn get_membership(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<Option<RepoBlobMembershipRecord>, StorageError> {
        self.storage.get_repo_blob_membership(repo, digest).await
    }

    /// Check if any repository has a membership link for this digest.
    pub async fn has_any_membership(&self, digest: &Digest) -> Result<bool, LedgerError> {
        match &self.mode {
            LedgerIndexMode::Indexed(idx) => {
                idx.check_health()?;
                let has = idx.has_any_repo_membership(digest)?;
                Ok(has)
            }
            LedgerIndexMode::StorageOnly => {
                let count = self.storage.count_repo_blob_memberships(digest).await?;
                Ok(count > 0)
            }
        }
    }

    /// Explicitly reconcile reverse index memberships against authoritative storage markers.
    pub async fn reconcile_memberships(&self) -> Result<(), LedgerError> {
        let _guard = self.consistency.acquire_mutation().await;
        if let LedgerIndexMode::Indexed(ref idx) = self.mode {
            let mut cursor: Option<String> = None;
            loop {
                let (records, next) = self
                    .storage
                    .list_all_repo_blob_memberships_page(cursor.as_deref(), 256)
                    .await?;
                for rec in records {
                    idx.record_membership(&rec.digest, rec.repo.as_str())?;
                }
                cursor = next;
                if cursor.is_none() {
                    break;
                }
            }
            idx.flush()?;
            idx.mark_ready()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fs::FsStorage;
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

    async fn setup_test_ledger() -> (
        tempfile::TempDir,
        RepositoryMembershipLedger,
        Arc<BlobRefIndex>,
        Arc<dyn RepositoryBlobMembershipStorage>,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs_root = dir.path().join("data");
        std::fs::create_dir_all(&fs_root).expect("mkdir data");

        let storage: Arc<dyn RepositoryBlobMembershipStorage> =
            Arc::new(FsStorage::new(fs_root.clone(), 10 * 1024 * 1024));
        let index_dir = dir.path().join("index");
        let idx = Arc::new(BlobRefIndex::open(index_dir).expect("open index"));
        let concrete_storage = FsStorage::new(fs_root.clone(), 10 * 1024 * 1024);
        idx.ensure_healthy_or_rebuild(&concrete_storage, true, true)
            .await
            .expect("rebuild index");

        let coordinator = crate::consistency::ConsistencyCoordinator::new();
        let ledger = RepositoryMembershipLedger::indexed(
            Arc::clone(&storage),
            Arc::clone(&idx),
            coordinator,
        );

        (dir, ledger, idx, storage)
    }

    #[tokio::test]
    async fn test_ledger_link_and_unlink_transitions() {
        let (_dir, ledger, idx, storage) = setup_test_ledger().await;
        let digest = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let repo = "my-test-app";

        let canonical_repo =
            crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap();
        let record = RepoBlobMembershipRecord::new_upload(canonical_repo, digest.clone(), None);

        // 1. Link via ledger
        ledger.link(&record).await.expect("link");

        // Verify authoritative marker in storage
        let mem = storage
            .get_repo_blob_membership(repo, &digest)
            .await
            .unwrap();
        assert!(mem.is_some());

        // Verify reverse index
        assert!(idx.has_any_repo_membership(&digest).unwrap());
        assert_eq!(idx.get_membership_count(&digest).unwrap(), 1);

        // 2. Unlink via ledger
        let removed = ledger.unlink(repo, &digest).await.expect("unlink");
        assert!(removed);

        // Verify authoritative marker removed
        let mem_after = storage
            .get_repo_blob_membership(repo, &digest)
            .await
            .unwrap();
        assert!(mem_after.is_none());

        // Verify reverse index removed
        assert!(!idx.has_any_repo_membership(&digest).unwrap());
        assert_eq!(idx.get_membership_count(&digest).unwrap(), 0);
    }

    #[tokio::test]
    async fn test_ledger_dirty_index_rebuilds_from_storage() {
        let (_dir, ledger, idx, storage) = setup_test_ledger().await;
        let digest = Digest::parse(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let repo = "reconcile-app";

        // Create storage marker directly
        let canonical_repo =
            crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap();
        let record = RepoBlobMembershipRecord::new_upload(canonical_repo, digest.clone(), None);
        storage.link_repo_blob(&record).await.unwrap();

        // Mark index dirty
        idx.mark_dirty().unwrap();

        // Reconcile memberships from authoritative storage markers
        ledger
            .reconcile_memberships()
            .await
            .expect("reconcile memberships");

        let has = ledger
            .has_any_membership(&digest)
            .await
            .expect("has membership");
        assert!(
            has,
            "Reconcile must populate membership from authoritative storage markers"
        );
    }

    #[tokio::test]
    async fn test_ledger_storage_only_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs_root = dir.path().join("data");
        std::fs::create_dir_all(&fs_root).expect("mkdir data");

        let storage: Arc<dyn RepositoryBlobMembershipStorage> =
            Arc::new(FsStorage::new(fs_root.clone(), 10 * 1024 * 1024));
        let coordinator = crate::consistency::ConsistencyCoordinator::new();
        let ledger = RepositoryMembershipLedger::storage_only(Arc::clone(&storage), coordinator);

        assert!(!ledger.is_indexed());
        assert!(ledger.ref_index().is_none());

        let digest = Digest::parse(
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();
        let repo = "storage-only-app";

        let canonical_repo =
            crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap();
        let record = RepoBlobMembershipRecord::new_upload(canonical_repo, digest.clone(), None);
        ledger.link(&record).await.expect("link");

        let has = ledger.has_any_membership(&digest).await.expect("has");
        assert!(has);

        let removed = ledger.unlink(repo, &digest).await.expect("unlink");
        assert!(removed);

        let has_after = ledger.has_any_membership(&digest).await.expect("has");
        assert!(!has_after);
    }
}
