//! Upstream-fetch seam (ADR-010 §2.2).
//!
//! The core-owned contract between proxy-aware application services and an
//! upstream pull-through engine. The reqwest-based engine (`crate::proxy`)
//! stays on the server side and implements [`UpstreamFetcher`]; core code only
//! ever sees this trait and these types.

use crate::application::{BlobMutationService, ManifestMutationService};
use crate::manifest_refs::ManifestRefs;
use crate::policy::{EvictionPolicy, TagPolicy};
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::ports::ProxyStoragePort;
use async_trait::async_trait;
use bytes::Bytes;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Routing decision for a repository under proxy rules (moved from `proxy`).
#[derive(Clone, Debug)]
pub struct RepoDecision {
    pub local_repo: CanonicalRepoName,
    pub upstream_repo: CanonicalRepoName,
    pub tag_policy: TagPolicy,
    pub eviction_policy: EvictionPolicy,
}

/// Cached tag metadata for proxy freshness decisions (moved from `proxy`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TagMeta {
    pub digest: String,
    pub expires_at_unix: u64,
    pub etag: Option<String>,
}

/// Upstream failure taxonomy (moved from `proxy`). Message-only: transport
/// details never leak library types across the seam.
#[derive(thiserror::Error, Debug)]
pub enum ProxyError {
    #[error("proxy disabled")]
    Disabled,
    #[error("repo not allowed")]
    RepoNotAllowed,
    #[error("upstream not configured")]
    UpstreamNotConfigured,
    #[error("invalid upstream url")]
    InvalidUpstreamUrl,
    #[error("upstream host not allowed: {0}")]
    UpstreamHostNotAllowed(String),
    #[error("blocked upstream egress to private network: {0}")]
    BlockedEgress(String),
    #[error("upstream request failed: {0}")]
    Upstream(String),
    #[error("digest mismatch")]
    DigestMismatch,
    #[error("not found")]
    NotFound,
    #[error("too large")]
    TooLarge,
    #[error("internal: {0}")]
    Internal(String),
}

/// Outcome of an upstream manifest fetch/revalidation (moved from `proxy`).
pub enum FetchManifestResult {
    Fetched {
        digest: Digest,
        media_type: String,
        etag: Option<String>,
        bytes: Bytes,
    },
    HeadOk {
        media_type: String,
        etag: Option<String>,
        digest: Option<Digest>,
    },
    NotModified {
        etag: Option<String>,
        digest: Option<Digest>,
    },
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

pub fn ttl_expires_at(ttl_secs: u64) -> u64 {
    now_unix().saturating_add(ttl_secs)
}

/// Exactly the engine surface the application layer consumes (G2-audited:
/// 12 cohesive methods, no transport/config types). Publication back-calls
/// take the core mutation services so cached content flows through the same
/// verified write paths as client pushes.
#[async_trait]
pub trait UpstreamFetcher: Send + Sync {
    fn decision_for_repo(&self, repo: &str) -> Result<RepoDecision, ProxyError>;
    fn upstream_base_url_for_log(&self) -> Option<&str>;

    async fn head_blob_upstream(
        &self,
        decision: &RepoDecision,
        digest: &Digest,
    ) -> Result<u64, ProxyError>;

    async fn fetch_blob_into_storage(
        &self,
        decision: &RepoDecision,
        digest: &Digest,
        cache_storage: &dyn ProxyStoragePort,
        mutation_service: &BlobMutationService,
    ) -> Result<(), ProxyError>;

    #[allow(clippy::too_many_arguments)]
    async fn fetch_manifest_and_cache(
        &self,
        decision: &RepoDecision,
        reference: &str,
        max_bytes: usize,
        revalidate_only: bool,
        if_none_match: Option<String>,
        manifest_service: &ManifestMutationService,
    ) -> Result<FetchManifestResult, ProxyError>;

    fn get_tag_meta(&self, repo: &str, tag: &str) -> Option<TagMeta>;
    fn put_tag_meta(&self, repo: &str, tag: &str, meta: &TagMeta);
    fn note_blob_access(&self, digest: &Digest);
    fn note_manifest_access(&self, repo: &str, digest: &Digest);
    fn note_tag_access(&self, repo: &str, tag: &str);
    fn get_manifest_refs(&self, repo: &str, digest: &Digest) -> Option<ManifestRefs>;
}
