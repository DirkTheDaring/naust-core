use std::sync::Arc;

use crate::consistency::ConsistencyCoordinator;
use crate::manifest_lifecycle::{
    ManifestDeleteResult, ManifestLifecycleService, ProxyEvictionResult, ProxyPublicationEvidence,
    PublishManifestRequest, PublishedManifest, TagDeleteResult,
};
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::ManifestLifecycleStoragePort;

use super::errors::ManifestMutationError;

pub struct ManifestMutationService {
    lifecycle: Arc<ManifestLifecycleService>,
}

impl ManifestMutationService {
    pub fn new(
        storage: Arc<dyn ManifestLifecycleStoragePort>,
        ref_index: Option<Arc<crate::blob_ref_index::BlobRefIndex>>,
        consistency: ConsistencyCoordinator,
    ) -> Self {
        let lifecycle = Arc::new(ManifestLifecycleService::new(
            storage,
            ref_index,
            consistency,
        ));
        Self { lifecycle }
    }

    pub fn from_lifecycle(lifecycle: Arc<ManifestLifecycleService>) -> Self {
        Self { lifecycle }
    }

    pub async fn publish_manifest(
        &self,
        req: PublishManifestRequest,
    ) -> Result<PublishedManifest, ManifestMutationError> {
        CanonicalRepoName::parse(&req.repo).map_err(|source| {
            ManifestMutationError::InvalidRepoName {
                name: req.repo.clone(),
                source,
            }
        })?;
        self.lifecycle
            .publish_manifest(req)
            .await
            .map_err(ManifestMutationError::from)
    }

    pub async fn delete_manifest(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<ManifestDeleteResult, ManifestMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            ManifestMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.lifecycle
            .delete_manifest(canonical_repo.as_str(), digest)
            .await
            .map_err(ManifestMutationError::from)
    }

    pub async fn delete_tag(
        &self,
        repo: &str,
        tag: &str,
        allow_tag_overwrite: bool,
    ) -> Result<TagDeleteResult, ManifestMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            ManifestMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        if !allow_tag_overwrite {
            return Err(ManifestMutationError::TagImmutable);
        }
        self.lifecycle
            .delete_tag(canonical_repo.as_str(), tag)
            .await
            .map_err(ManifestMutationError::from)
    }

    pub async fn publish_verified_proxy_manifest(
        &self,
        evidence: ProxyPublicationEvidence,
    ) -> Result<PublishedManifest, ManifestMutationError> {
        self.publish_manifest_from_proxy(evidence).await
    }

    pub async fn publish_manifest_from_proxy(
        &self,
        evidence: ProxyPublicationEvidence,
    ) -> Result<PublishedManifest, ManifestMutationError> {
        CanonicalRepoName::parse(&evidence.repo).map_err(|source| {
            ManifestMutationError::InvalidRepoName {
                name: evidence.repo.clone(),
                source,
            }
        })?;
        self.lifecycle
            .publish_proxy_cached_manifest(evidence)
            .await
            .map_err(ManifestMutationError::from)
    }

    pub async fn evict_proxy_manifest_and_memberships(
        &self,
        repo: &str,
        target_digest: &Digest,
        tag: Option<&str>,
    ) -> Result<ProxyEvictionResult, ManifestMutationError> {
        let canonical_repo = CanonicalRepoName::parse(repo).map_err(|source| {
            ManifestMutationError::InvalidRepoName {
                name: repo.to_string(),
                source,
            }
        })?;
        self.lifecycle
            .evict_proxy_cached_entry(canonical_repo.as_str(), tag, target_digest)
            .await
            .map_err(ManifestMutationError::from)
    }
}
