use std::sync::Arc;

use crate::blob_delete_safety::{BlobDeleteResult, BlobDeleteService};
use crate::blob_ref_index::BlobRefIndex;
use crate::consistency::ConsistencyCoordinator;
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::repository_membership_ledger::RepositoryMembershipLedger;
use crate::storage::BlobUploadCoordinatorStoragePort;
use crate::storage::repo_membership::RepoBlobMembershipRecord;
use crate::storage::upload_session::UploadByteStream;
use crate::upload_coordinator::{
    AppendResult, BlobUploadCoordinator, BlobUploadCoordinatorConfig, CrossMountResult,
    FinalizeResult, MonolithicUploadResult, StartUploadResult, UploadStatusResult,
};

use super::errors::BlobMutationError;

pub struct BlobMutationService {
    coordinator: Arc<BlobUploadCoordinator>,
    delete_service: Arc<BlobDeleteService>,
    membership_ledger: Arc<RepositoryMembershipLedger>,
}

impl BlobMutationService {
    pub fn new(
        storage: Arc<dyn BlobUploadCoordinatorStoragePort>,
        ref_index: Option<Arc<BlobRefIndex>>,
        consistency: ConsistencyCoordinator,
        config: BlobUploadCoordinatorConfig,
    ) -> Self {
        let coordinator = Arc::new(BlobUploadCoordinator::new(
            storage.clone(),
            ref_index.clone(),
            consistency.clone(),
            config,
        ));
        let membership_ledger = Arc::new(RepositoryMembershipLedger::new(
            storage.clone(),
            ref_index.clone(),
            consistency.clone(),
        ));
        let delete_service = Arc::new(BlobDeleteService::new(
            Arc::new(storage.clone()),
            (*membership_ledger).clone(),
        ));

        Self {
            coordinator,
            delete_service,
            membership_ledger,
        }
    }

    pub fn from_components(
        coordinator: Arc<BlobUploadCoordinator>,
        delete_service: Arc<BlobDeleteService>,
        membership_ledger: Arc<RepositoryMembershipLedger>,
    ) -> Self {
        Self {
            coordinator,
            delete_service,
            membership_ledger,
        }
    }

    pub fn membership_ledger(&self) -> &Arc<RepositoryMembershipLedger> {
        &self.membership_ledger
    }

    pub fn delete_service(&self) -> &Arc<BlobDeleteService> {
        &self.delete_service
    }

    pub async fn start_upload(&self, repo: &str) -> Result<StartUploadResult, BlobMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.coordinator
            .start_upload(canonical_repo.as_str())
            .await
            .map_err(BlobMutationError::from)
    }

    pub async fn get_upload_status(
        &self,
        repo: &str,
        session_id: &str,
        state_token: Option<&str>,
    ) -> Result<UploadStatusResult, BlobMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.coordinator
            .get_upload_status(canonical_repo.as_str(), session_id, state_token)
            .await
            .map_err(BlobMutationError::from)
    }

    pub async fn append_chunk(
        &self,
        repo: &str,
        session_id: &str,
        state_token: &str,
        range: Option<(u64, u64)>,
        content_len: Option<u64>,
        stream: UploadByteStream,
    ) -> Result<AppendResult, BlobMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.coordinator
            .append_upload(
                canonical_repo.as_str(),
                session_id,
                state_token,
                range,
                content_len,
                stream,
            )
            .await
            .map_err(BlobMutationError::from)
    }

    pub async fn abort_upload(
        &self,
        repo: &str,
        session_id: &str,
        state_token: Option<&str>,
    ) -> Result<(), BlobMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.coordinator
            .abort_upload(canonical_repo.as_str(), session_id, state_token)
            .await
            .map_err(BlobMutationError::from)
    }

    pub async fn finalize_upload(
        &self,
        repo: &str,
        session_id: &str,
        state_token: Option<&str>,
        range: Option<(u64, u64)>,
        trailing_stream: Option<UploadByteStream>,
        digest: &Digest,
    ) -> Result<FinalizeResult, BlobMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.coordinator
            .finalize_upload(
                canonical_repo.as_str(),
                session_id,
                state_token,
                range,
                trailing_stream,
                digest,
            )
            .await
            .map_err(BlobMutationError::from)
    }

    pub async fn monolithic_upload(
        &self,
        repo: &str,
        digest: &Digest,
        stream: Option<UploadByteStream>,
    ) -> Result<MonolithicUploadResult, BlobMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.coordinator
            .monolithic_upload(canonical_repo.as_str(), digest, stream)
            .await
            .map_err(BlobMutationError::from)
    }

    pub async fn cross_mount(
        &self,
        target_repo: &str,
        from_repo: Option<&str>,
        digest: &Digest,
    ) -> Result<CrossMountResult, BlobMutationError> {
        let canonical_target = CanonicalRepoName::parse(target_repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: target_repo.to_string(),
                source,
            }
        })?;
        self.coordinator
            .cross_mount_blob(canonical_target.as_str(), from_repo, digest)
            .await
            .map_err(BlobMutationError::from)
    }

    pub async fn publish_verified_proxy_blob(
        &self,
        repo: &CanonicalRepoName,
        digest: &Digest,
        stream: UploadByteStream,
    ) -> Result<(), BlobMutationError> {
        self.coordinator
            .publish_proxy_blob(repo, digest, stream)
            .await
            .map_err(BlobMutationError::from)
    }

    pub async fn publish_proxy_blob(
        &self,
        repo: &CanonicalRepoName,
        digest: &Digest,
        stream: UploadByteStream,
    ) -> Result<(), BlobMutationError> {
        self.publish_verified_proxy_blob(repo, digest, stream).await
    }

    pub async fn link_proxy_blob_membership(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<(), BlobMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        let record = RepoBlobMembershipRecord::new_proxy(canonical_repo, digest.clone());
        self.membership_ledger
            .link(&record)
            .await
            .map_err(BlobMutationError::Ledger)
    }

    pub async fn delete_repo_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<BlobDeleteResult, BlobMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            BlobMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.delete_service
            .delete_repo_blob(canonical_repo.as_str(), digest)
            .await
            .map_err(BlobMutationError::Storage)
    }

    pub async fn reap_expired_uploads(
        &self,
        max_age_secs: u64,
        receipt_ttl_secs: u64,
    ) -> Result<usize, BlobMutationError> {
        self.coordinator
            .reap_expired_uploads(max_age_secs, receipt_ttl_secs)
            .await
            .map_err(BlobMutationError::from)
    }
}
