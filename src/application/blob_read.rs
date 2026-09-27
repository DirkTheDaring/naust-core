use futures_util::StreamExt;
use std::sync::Arc;
use tokio_util::io::ReaderStream;

use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::ports::{BlobCasReader, ProxyStoragePort};
use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
use crate::storage::upload_session::{UploadByteStream, UploadStreamError};

use super::blob::BlobMutationService;
use super::errors::BlobReadError;
use super::proxy::ProxyTarget;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobHeadResult {
    pub digest: Digest,
    pub size: u64,
    pub media_type: String,
}

pub struct BlobGetResult {
    pub digest: Digest,
    pub size: u64,
    pub media_type: String,
    pub stream: UploadByteStream,
}

pub struct BlobReadService {
    blob_reader: Arc<dyn BlobCasReader>,
    membership_reader: Arc<dyn RepositoryBlobMembershipStorage>,
    blob_mutation: Arc<BlobMutationService>,
}

impl BlobReadService {
    pub fn new(
        blob_reader: Arc<dyn BlobCasReader>,
        membership_reader: Arc<dyn RepositoryBlobMembershipStorage>,
        blob_mutation: Arc<BlobMutationService>,
    ) -> Self {
        Self {
            blob_reader,
            membership_reader,
            blob_mutation,
        }
    }

    pub fn blob_reader(&self) -> &Arc<dyn BlobCasReader> {
        &self.blob_reader
    }

    pub fn membership_reader(&self) -> &Arc<dyn RepositoryBlobMembershipStorage> {
        &self.membership_reader
    }

    pub async fn head_blob(
        &self,
        repo: &str,
        digest: &Digest,
        proxy_target: Option<&ProxyTarget>,
        proxy_only: bool,
    ) -> Result<BlobHeadResult, BlobReadError> {
        CanonicalRepoName::parse(repo).map_err(|source| BlobReadError::InvalidRepoName {
            name: repo.to_string(),
            source,
        })?;

        if !proxy_only {
            let membership = self
                .membership_reader
                .get_repo_blob_membership(repo, digest)
                .await
                .map_err(BlobReadError::Storage)?;

            if membership.is_some() {
                match self.blob_reader.head_blob(digest).await {
                    Ok(meta) => {
                        return Ok(BlobHeadResult {
                            digest: digest.clone(),
                            size: meta.size,
                            media_type: "application/octet-stream".to_string(),
                        });
                    }
                    Err(crate::storage::StorageError::NotFound) => {
                        return Err(BlobReadError::NotFound);
                    }
                    Err(e) => return Err(BlobReadError::Storage(e)),
                }
            }
        }

        // Proxy fallback if configured
        if let Some(target) = proxy_target {
            if let Ok(meta) = target.cache_storage.head_blob(digest).await {
                target.proxy.note_blob_access(digest);
                if let Err(e) = self
                    .blob_mutation
                    .link_proxy_blob_membership(repo, digest)
                    .await
                {
                    tracing::error!(
                        error = %e,
                        repo,
                        digest = digest.as_str(),
                        "failed to link proxy blob membership"
                    );
                    return Err(BlobReadError::Mutation(e));
                }
                return Ok(BlobHeadResult {
                    digest: digest.clone(),
                    size: meta.size,
                    media_type: "application/octet-stream".to_string(),
                });
            }

            if let Ok(decision) = target.proxy.decision_for_repo(repo) {
                if let Ok(size) = target.proxy.head_blob_upstream(&decision, digest).await {
                    return Ok(BlobHeadResult {
                        digest: digest.clone(),
                        size,
                        media_type: "application/octet-stream".to_string(),
                    });
                }
            }
        }

        Err(BlobReadError::NotFound)
    }

    pub async fn get_blob(
        &self,
        repo: &str,
        digest: &Digest,
        proxy_target: Option<&ProxyTarget>,
        proxy_only: bool,
    ) -> Result<BlobGetResult, BlobReadError> {
        self.get_blob_span(repo, digest, proxy_target, proxy_only, None)
            .await
    }

    pub async fn get_blob_range(
        &self,
        repo: &str,
        digest: &Digest,
        start: u64,
        end_inclusive: u64,
        proxy_target: Option<&ProxyTarget>,
        proxy_only: bool,
    ) -> Result<BlobGetResult, BlobReadError> {
        self.get_blob_span(
            repo,
            digest,
            proxy_target,
            proxy_only,
            Some((start, end_inclusive)),
        )
        .await
    }

    async fn get_blob_span(
        &self,
        repo: &str,
        digest: &Digest,
        proxy_target: Option<&ProxyTarget>,
        proxy_only: bool,
        range: Option<(u64, u64)>,
    ) -> Result<BlobGetResult, BlobReadError> {
        CanonicalRepoName::parse(repo).map_err(|source| BlobReadError::InvalidRepoName {
            name: repo.to_string(),
            source,
        })?;

        if !proxy_only {
            let membership = self
                .membership_reader
                .get_repo_blob_membership(repo, digest)
                .await
                .map_err(BlobReadError::Storage)?;

            if membership.is_some() {
                match open_cas_reader(self.blob_reader.as_ref(), digest, range).await {
                    Ok((meta, reader)) => {
                        let stream =
                            ReaderStream::new(reader).map(|r| r.map_err(UploadStreamError::Io));
                        return Ok(BlobGetResult {
                            digest: digest.clone(),
                            size: meta.size,
                            media_type: "application/octet-stream".to_string(),
                            stream: Box::pin(stream),
                        });
                    }
                    Err(crate::storage::StorageError::NotFound) => {
                        return Err(BlobReadError::NotFound);
                    }
                    Err(e) => return Err(BlobReadError::Storage(e)),
                }
            }
        }

        // Proxy fallback if configured
        if let Some(target) = proxy_target {
            if let Ok((meta, reader)) =
                open_cas_reader(target.cache_storage.as_blob_reader(), digest, range).await
            {
                target.proxy.note_blob_access(digest);
                if let Err(e) = self
                    .blob_mutation
                    .link_proxy_blob_membership(repo, digest)
                    .await
                {
                    tracing::error!(
                        error = %e,
                        repo,
                        digest = digest.as_str(),
                        "failed to link proxy blob membership"
                    );
                    return Err(BlobReadError::Mutation(e));
                }
                let stream = ReaderStream::new(reader).map(|r| r.map_err(UploadStreamError::Io));
                return Ok(BlobGetResult {
                    digest: digest.clone(),
                    size: meta.size,
                    media_type: "application/octet-stream".to_string(),
                    stream: Box::pin(stream),
                });
            }

            if let Ok(decision) = target.proxy.decision_for_repo(repo) {
                if target
                    .proxy
                    .fetch_blob_into_storage(
                        &decision,
                        digest,
                        &target.cache_storage,
                        &self.blob_mutation,
                    )
                    .await
                    .is_ok()
                {
                    if let Ok((meta, reader)) =
                        open_cas_reader(target.cache_storage.as_blob_reader(), digest, range).await
                    {
                        target.proxy.note_blob_access(digest);
                        let stream =
                            ReaderStream::new(reader).map(|r| r.map_err(UploadStreamError::Io));
                        return Ok(BlobGetResult {
                            digest: digest.clone(),
                            size: meta.size,
                            media_type: "application/octet-stream".to_string(),
                            stream: Box::pin(stream),
                        });
                    }
                }
            }
        }

        Err(BlobReadError::NotFound)
    }
}

async fn open_cas_reader(
    reader: &dyn BlobCasReader,
    digest: &Digest,
    range: Option<(u64, u64)>,
) -> Result<
    (
        crate::storage::BlobMeta,
        std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    ),
    crate::storage::StorageError,
> {
    match range {
        Some((start, end_inclusive)) => reader.open_blob_range(digest, start, end_inclusive).await,
        None => reader.open_blob(digest).await,
    }
}
