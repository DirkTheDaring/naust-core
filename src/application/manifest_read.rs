use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::policy::TagPolicy;
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::StorageError;
use crate::storage::ports::{ManifestReader, TagReader};

use super::errors::ManifestReadError;
use super::manifest::ManifestMutationService;
use super::proxy::ProxyTarget;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestHeadResult {
    pub digest: Digest,
    pub size: u64,
    pub media_type: String,
    pub subject: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestGetResult {
    pub digest: Digest,
    pub size: u64,
    pub media_type: String,
    pub payload: Bytes,
    pub subject: Option<Digest>,
}

pub struct ManifestReadService {
    manifest_reader: Arc<dyn ManifestReader>,
    tag_reader: Arc<dyn TagReader>,
    manifest_mutation: Arc<ManifestMutationService>,
    max_request_body_bytes: usize,
    buffered_body_sem: Option<Arc<Semaphore>>,
}

impl ManifestReadService {
    pub fn new(
        manifest_reader: Arc<dyn ManifestReader>,
        tag_reader: Arc<dyn TagReader>,
        manifest_mutation: Arc<ManifestMutationService>,
        max_request_body_bytes: usize,
        buffered_body_sem: Option<Arc<Semaphore>>,
    ) -> Self {
        Self {
            manifest_reader,
            tag_reader,
            manifest_mutation,
            max_request_body_bytes,
            buffered_body_sem,
        }
    }

    pub fn manifest_reader(&self) -> &Arc<dyn ManifestReader> {
        &self.manifest_reader
    }

    pub fn tag_reader(&self) -> &Arc<dyn TagReader> {
        &self.tag_reader
    }

    async fn acquire_buffered_body_permit(
        &self,
    ) -> Result<Option<tokio::sync::OwnedSemaphorePermit>, ManifestReadError> {
        if let Some(ref sem) = self.buffered_body_sem {
            let permit = sem
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| ManifestReadError::Internal(e.to_string()))?;
            Ok(Some(permit))
        } else {
            Ok(None)
        }
    }

    async fn ensure_tag_fresh(
        &self,
        proxy: &dyn crate::upstream::UpstreamFetcher,
        decision: &crate::upstream::RepoDecision,
        tag: &str,
        ttl_secs: u64,
        always_revalidate: bool,
    ) -> Result<(), ManifestReadError> {
        let now = crate::upstream::now_unix();
        let current_digest = self
            .tag_reader
            .resolve_tag(decision.local_repo.as_str(), tag)
            .await
            .ok();
        let meta = proxy.get_tag_meta(decision.local_repo.as_str(), tag);

        if !always_revalidate {
            if let (Some(d), Some(m)) = (&current_digest, &meta) {
                if m.expires_at_unix > now && m.digest == d.as_str() {
                    return Ok(());
                }
            }
        }

        if current_digest.is_none() {
            let _permit = self.acquire_buffered_body_permit().await?;
            let res = proxy
                .fetch_manifest_and_cache(
                    decision,
                    tag,
                    self.max_request_body_bytes,
                    false,
                    None,
                    &self.manifest_mutation,
                )
                .await;
            return match res {
                Ok(_) => Ok(()),
                Err(crate::upstream::ProxyError::NotFound) => Err(ManifestReadError::TagNotFound),
                Err(e) => Err(ManifestReadError::Proxy(e)),
            };
        }

        // Revalidate via HEAD (conditional if we have an ETag).
        let if_none_match = meta.as_ref().and_then(|m| m.etag.clone());
        let head = proxy
            .fetch_manifest_and_cache(
                decision,
                tag,
                self.max_request_body_bytes,
                true,
                if_none_match,
                &self.manifest_mutation,
            )
            .await;

        match head {
            Ok(crate::upstream::FetchManifestResult::NotModified { etag, digest }) => {
                // If we don't have the manifest locally (or no tag pointer), fetch the body.
                if current_digest.is_none()
                    || self
                        .manifest_reader
                        .head_manifest(
                            decision.local_repo.as_str(),
                            current_digest.as_ref().unwrap(),
                        )
                        .await
                        .is_err()
                {
                    let _permit = self.acquire_buffered_body_permit().await?;
                    let _ = proxy
                        .fetch_manifest_and_cache(
                            decision,
                            tag,
                            self.max_request_body_bytes,
                            false,
                            None,
                            &self.manifest_mutation,
                        )
                        .await
                        .map_err(|e| {
                            tracing::warn!(
                                error = %e,
                                repo = %decision.local_repo,
                                tag,
                                "proxy: fetch manifest after 304 failed"
                            );
                            ManifestReadError::Proxy(e)
                        })?;
                }

                if let Some(d) = self
                    .tag_reader
                    .resolve_tag(decision.local_repo.as_str(), tag)
                    .await
                    .ok()
                    .or(digest)
                {
                    let m = crate::upstream::TagMeta {
                        digest: d.as_str(),
                        expires_at_unix: if always_revalidate {
                            now
                        } else {
                            crate::upstream::ttl_expires_at(ttl_secs)
                        },
                        etag,
                    };
                    proxy.put_tag_meta(decision.local_repo.as_str(), tag, &m);
                }
                Ok(())
            }
            Ok(crate::upstream::FetchManifestResult::HeadOk { etag, digest, .. }) => {
                let needs_get = match (&current_digest, &digest) {
                    (Some(local), Some(up)) if local.hex() == up.hex() => self
                        .manifest_reader
                        .head_manifest(decision.local_repo.as_str(), local)
                        .await
                        .is_err(),
                    _ => true,
                };

                if needs_get {
                    let _permit = self.acquire_buffered_body_permit().await?;
                    let fetched = proxy
                        .fetch_manifest_and_cache(
                            decision,
                            tag,
                            self.max_request_body_bytes,
                            false,
                            None,
                            &self.manifest_mutation,
                        )
                        .await
                        .map_err(|e| {
                            tracing::warn!(
                                error = %e,
                                repo = %decision.local_repo,
                                tag,
                                "proxy: fetch manifest failed"
                            );
                            ManifestReadError::Proxy(e)
                        })?;
                    if let crate::upstream::FetchManifestResult::Fetched { digest, etag, .. } =
                        fetched
                    {
                        let m = crate::upstream::TagMeta {
                            digest: digest.as_str(),
                            expires_at_unix: if always_revalidate {
                                now
                            } else {
                                crate::upstream::ttl_expires_at(ttl_secs)
                            },
                            etag,
                        };
                        proxy.put_tag_meta(decision.local_repo.as_str(), tag, &m);
                    }
                } else if let Some(d) = digest {
                    let m = crate::upstream::TagMeta {
                        digest: d.as_str(),
                        expires_at_unix: if always_revalidate {
                            now
                        } else {
                            crate::upstream::ttl_expires_at(ttl_secs)
                        },
                        etag,
                    };
                    proxy.put_tag_meta(decision.local_repo.as_str(), tag, &m);
                }
                Ok(())
            }
            Ok(crate::upstream::FetchManifestResult::Fetched { digest, etag, .. }) => {
                let m = crate::upstream::TagMeta {
                    digest: digest.as_str(),
                    expires_at_unix: if always_revalidate {
                        now
                    } else {
                        crate::upstream::ttl_expires_at(ttl_secs)
                    },
                    etag,
                };
                proxy.put_tag_meta(decision.local_repo.as_str(), tag, &m);
                Ok(())
            }
            Err(e) => Err(ManifestReadError::Proxy(e)),
        }
    }

    pub async fn resolve_reference_digest(
        &self,
        repo: &str,
        reference: &str,
        proxy_target: Option<&ProxyTarget>,
        proxy_only: bool,
        request_host: Option<&str>,
    ) -> Result<Digest, ManifestReadError> {
        CanonicalRepoName::parse(repo).map_err(|source| ManifestReadError::InvalidRepoName {
            name: repo.to_string(),
            source,
        })?;

        if let Ok(d) = Digest::parse(reference) {
            return Ok(d);
        }

        // Reference is a tag
        let Some(target) = proxy_target else {
            if !proxy_only {
                return self
                    .tag_reader
                    .resolve_tag(repo, reference)
                    .await
                    .map_err(|e| match e {
                        StorageError::NotFound => ManifestReadError::TagNotFound,
                        other => ManifestReadError::Storage(other),
                    });
            }
            return Err(ManifestReadError::TagNotFound);
        };

        let Ok(decision) = target.proxy.decision_for_repo(repo) else {
            if !proxy_only {
                return self
                    .tag_reader
                    .resolve_tag(repo, reference)
                    .await
                    .map_err(|e| match e {
                        StorageError::NotFound => ManifestReadError::TagNotFound,
                        other => ManifestReadError::Storage(other),
                    });
            }
            return Err(ManifestReadError::TagNotFound);
        };

        match decision.tag_policy.clone() {
            TagPolicy::DigestOnly => {
                if !proxy_only {
                    if let Ok(d) = target.cache_storage.resolve_tag(repo, reference).await {
                        return Ok(d);
                    }
                }
                let _permit = self.acquire_buffered_body_permit().await?;
                match target
                    .proxy
                    .fetch_manifest_and_cache(
                        &decision,
                        reference,
                        self.max_request_body_bytes,
                        false,
                        None,
                        &self.manifest_mutation,
                    )
                    .await
                {
                    Ok(crate::upstream::FetchManifestResult::Fetched { digest, .. }) => Ok(digest),
                    Ok(_) => Err(ManifestReadError::Internal(
                        "unexpected fetch result".to_string(),
                    )),
                    Err(crate::upstream::ProxyError::NotFound) => {
                        Err(ManifestReadError::TagNotFound)
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            request_host = request_host.unwrap_or("<missing>"),
                            proxy_upstream = target.proxy.upstream_base_url_for_log().unwrap_or("<unset>"),
                            repo,
                            tag = reference,
                            "proxy: resolve tag failed"
                        );
                        Err(ManifestReadError::Proxy(err))
                    }
                }
            }
            TagPolicy::TtlSeconds(ttl) => {
                self.ensure_tag_fresh(target.proxy.as_ref(), &decision, reference, ttl, false)
                    .await?;
                match target.cache_storage.resolve_tag(repo, reference).await {
                    Ok(d) => Ok(d),
                    Err(StorageError::NotFound) => Err(ManifestReadError::TagNotFound),
                    Err(e) => Err(ManifestReadError::Storage(e)),
                }
            }
            TagPolicy::AlwaysRevalidate => {
                self.ensure_tag_fresh(target.proxy.as_ref(), &decision, reference, 0, true)
                    .await?;
                match target.cache_storage.resolve_tag(repo, reference).await {
                    Ok(d) => Ok(d),
                    Err(StorageError::NotFound) => Err(ManifestReadError::TagNotFound),
                    Err(e) => Err(ManifestReadError::Storage(e)),
                }
            }
        }
    }

    pub async fn head_manifest(
        &self,
        repo: &str,
        reference: &str,
        proxy_target: Option<&ProxyTarget>,
        proxy_only: bool,
        request_host: Option<&str>,
    ) -> Result<ManifestHeadResult, ManifestReadError> {
        let digest = self
            .resolve_reference_digest(repo, reference, proxy_target, proxy_only, request_host)
            .await?;

        let is_tag = Digest::parse(reference).is_err();
        if is_tag {
            if let Some(target) = proxy_target {
                target.proxy.note_tag_access(repo, reference);
            }
        }

        if !proxy_only {
            match self.manifest_reader.get_manifest(repo, &digest).await {
                Ok((meta, bytes)) => {
                    let subject = crate::manifest_refs::extract_subject_digest(&bytes)
                        .ok()
                        .flatten();
                    return Ok(ManifestHeadResult {
                        digest,
                        size: meta.size,
                        media_type: meta.media_type,
                        subject,
                    });
                }
                Err(StorageError::NotFound) => {}
                Err(e) => return Err(ManifestReadError::Storage(e)),
            }
        }

        if let Some(target) = proxy_target {
            if let Ok((meta, bytes)) = target.cache_storage.get_manifest(repo, &digest).await {
                target.proxy.note_manifest_access(repo, &digest);
                if let Some(refs) = target.proxy.get_manifest_refs(repo, &digest) {
                    for blob in refs.blob_references() {
                        target.proxy.note_blob_access(blob);
                    }
                }
                let subject = crate::manifest_refs::extract_subject_digest(&bytes)
                    .ok()
                    .flatten();
                return Ok(ManifestHeadResult {
                    digest,
                    size: meta.size,
                    media_type: meta.media_type,
                    subject,
                });
            }

            if let Ok(decision) = target.proxy.decision_for_repo(repo) {
                let _permit = self.acquire_buffered_body_permit().await?;
                let digest_str;
                let upstream_ref: &str = if is_tag {
                    reference
                } else {
                    digest_str = digest.as_str();
                    digest_str.as_str()
                };

                match target
                    .proxy
                    .fetch_manifest_and_cache(
                        &decision,
                        upstream_ref,
                        self.max_request_body_bytes,
                        false,
                        None,
                        &self.manifest_mutation,
                    )
                    .await
                {
                    Ok(_) => {
                        if let Ok((meta, bytes)) =
                            target.cache_storage.get_manifest(repo, &digest).await
                        {
                            let subject = crate::manifest_refs::extract_subject_digest(&bytes)
                                .ok()
                                .flatten();
                            return Ok(ManifestHeadResult {
                                digest,
                                size: meta.size,
                                media_type: meta.media_type,
                                subject,
                            });
                        }
                    }
                    Err(crate::upstream::ProxyError::NotFound) => {
                        return Err(ManifestReadError::NotFound);
                    }
                    Err(e) => return Err(ManifestReadError::Proxy(e)),
                }
            }
        }

        Err(ManifestReadError::NotFound)
    }

    pub async fn get_manifest(
        &self,
        repo: &str,
        reference: &str,
        proxy_target: Option<&ProxyTarget>,
        proxy_only: bool,
        request_host: Option<&str>,
    ) -> Result<ManifestGetResult, ManifestReadError> {
        let digest = self
            .resolve_reference_digest(repo, reference, proxy_target, proxy_only, request_host)
            .await?;

        let is_tag = Digest::parse(reference).is_err();
        if is_tag {
            if let Some(target) = proxy_target {
                target.proxy.note_tag_access(repo, reference);
            }
        }

        if !proxy_only {
            match self.manifest_reader.get_manifest(repo, &digest).await {
                Ok((meta, bytes)) => {
                    let subject = crate::manifest_refs::extract_subject_digest(&bytes)
                        .ok()
                        .flatten();
                    return Ok(ManifestGetResult {
                        digest,
                        size: meta.size,
                        media_type: meta.media_type,
                        payload: bytes,
                        subject,
                    });
                }
                Err(StorageError::NotFound) => {}
                Err(e) => return Err(ManifestReadError::Storage(e)),
            }
        }

        if let Some(target) = proxy_target {
            if let Ok((meta, bytes)) = target.cache_storage.get_manifest(repo, &digest).await {
                target.proxy.note_manifest_access(repo, &digest);
                if let Some(refs) = target.proxy.get_manifest_refs(repo, &digest) {
                    for blob in refs.blob_references() {
                        target.proxy.note_blob_access(blob);
                    }
                }
                let subject = crate::manifest_refs::extract_subject_digest(&bytes)
                    .ok()
                    .flatten();
                return Ok(ManifestGetResult {
                    digest,
                    size: meta.size,
                    media_type: meta.media_type,
                    payload: bytes,
                    subject,
                });
            }

            if let Ok(decision) = target.proxy.decision_for_repo(repo) {
                let _permit = self.acquire_buffered_body_permit().await?;
                let digest_str;
                let upstream_ref: &str = if is_tag {
                    reference
                } else {
                    digest_str = digest.as_str();
                    digest_str.as_str()
                };

                match target
                    .proxy
                    .fetch_manifest_and_cache(
                        &decision,
                        upstream_ref,
                        self.max_request_body_bytes,
                        false,
                        None,
                        &self.manifest_mutation,
                    )
                    .await
                {
                    Ok(_) => {
                        if let Ok((meta, bytes)) =
                            target.cache_storage.get_manifest(repo, &digest).await
                        {
                            let subject = crate::manifest_refs::extract_subject_digest(&bytes)
                                .ok()
                                .flatten();
                            return Ok(ManifestGetResult {
                                digest,
                                size: meta.size,
                                media_type: meta.media_type,
                                payload: bytes,
                                subject,
                            });
                        }
                    }
                    Err(crate::upstream::ProxyError::NotFound) => {
                        return Err(ManifestReadError::NotFound);
                    }
                    Err(e) => return Err(ManifestReadError::Proxy(e)),
                }
            }
        }

        Err(ManifestReadError::NotFound)
    }
}
