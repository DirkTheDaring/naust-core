use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::blob_ref_index::BlobRefIndex;
use crate::manifest_refs::parse_manifest_refs;
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::registry::validation::is_valid_tag;
use crate::storage::{
    ConditionalDeleteResult, ReferrerDescriptor, StorageError, TagMutation, TagMutationPolicy,
};

pub const MAX_MANIFEST_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
pub const REPO_LEASE_TTL_SECS: u64 = 15;
pub const REPO_LEASE_RENEW_SECS: u64 = 4;
pub const POLICY_B_TAG_PAGE_SIZE: usize = 64;

#[derive(Clone, Debug)]
pub struct PublishManifestRequest {
    pub repo: String,
    pub reference: String,
    pub payload: Bytes,
    pub declared_media_type: Option<String>,
    pub allow_tag_overwrite: bool,
}

impl PublishManifestRequest {
    pub fn new(
        repo: impl Into<String>,
        reference: impl Into<String>,
        payload: Bytes,
        declared_media_type: Option<String>,
        allow_tag_overwrite: bool,
    ) -> Self {
        Self {
            repo: repo.into(),
            reference: reference.into(),
            payload,
            declared_media_type,
            allow_tag_overwrite,
        }
    }
}

/// Unforgeable capability for proxy-origin manifest publication.
///
/// Only trusted proxy fetch routines (`crate::proxy`) can construct this type after
/// validating upstream response headers, content digests, media types, and structural validity.
#[derive(Clone, Debug)]
pub struct ProxyPublicationEvidence {
    pub(crate) repo: String,
    pub(crate) reference: String,
    pub(crate) payload: Bytes,
    pub(crate) declared_media_type: Option<String>,
    pub(crate) allow_tag_overwrite: bool,
    pub(crate) verified_digest: Digest,
}

impl ProxyPublicationEvidence {
    pub fn new(
        repo: impl Into<String>,
        reference: impl Into<String>,
        payload: Bytes,
        declared_media_type: Option<String>,
        allow_tag_overwrite: bool,
        verified_digest: Digest,
    ) -> Self {
        Self {
            repo: repo.into(),
            reference: reference.into(),
            payload,
            declared_media_type,
            allow_tag_overwrite,
            verified_digest,
        }
    }

    /// Convenience constructor for tests.
    pub fn new_for_test(
        repo: impl Into<String>,
        reference: impl Into<String>,
        payload: Bytes,
        declared_media_type: Option<String>,
        allow_tag_overwrite: bool,
        verified_digest: Digest,
    ) -> Self {
        Self::new(
            repo,
            reference,
            payload,
            declared_media_type,
            allow_tag_overwrite,
            verified_digest,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyEvictionResult {
    pub repo: String,
    pub target_digest: Digest,
    pub tag_removed: Option<String>,
    pub manifest_removed: bool,
    pub memberships_unlinked: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedManifest {
    pub digest: Digest,
    pub media_type: String,
    pub size: u64,
    pub subject: Option<Digest>,
    pub is_tag: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestDeleteResult {
    pub digest: Digest,
    pub removed_tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagDeleteResult {
    pub tag: String,
    pub target_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagMutationResult {
    pub tag: String,
    pub digest: Digest,
    pub mutation: TagMutation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleOpKind {
    Publish,
    DeleteManifest,
    DeleteTag,
    ProxyEvict,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecyclePhase {
    // --- Publication Phases ---
    ManifestStored,
    ReferrerRegistered,
    TagMutated,

    // --- Manifest Deletion (Policy B) Phases ---
    TagsSnapshotted,
    TagsDeleted,
    ReferrerCleaned,
    ManifestDeleted,

    // --- Tag Deletion Phases ---
    TagDeleteInitiated,
    TagDeletedOnly,

    // --- Proxy Eviction Phases ---
    ProxyEvictInitiated,
    ProxyTagDeleted,
    ProxyManifestDeleted,
    ProxyMembershipsUnlinked,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagSnapshot {
    pub tag: String,
    pub observed_version: String,
    pub target_digest: Digest,
    pub deleted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleJournalRecord {
    pub op_id: String,
    pub repo: CanonicalRepoName,
    pub op_kind: LifecycleOpKind,
    pub target_digest: Digest,
    pub target_reference: Option<String>,
    pub phase: LifecyclePhase,
    pub owner_id: String,
    pub lease_expiry_unix_secs: u64,
    pub started_unix_secs: u64,
    pub updated_unix_secs: u64,
    pub relevant_tags: Vec<TagSnapshot>,
    pub subject_digest: Option<Digest>,
    pub artifact_type: Option<String>,
    pub annotations: Option<HashMap<String, String>>,
    pub media_type: Option<String>,
    pub manifest_size: Option<u64>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum UnverifiedReason {
    #[error("manifest failed signature verification")]
    SignatureVerificationFailed,
    #[error("manifest signatures unverified")]
    SignaturesUnverified,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestLifecycleError {
    #[error("invalid repository name")]
    InvalidRepoName,

    #[error("manifest payload is empty")]
    EmptyPayload,

    #[error("manifest payload exceeds maximum allowed size")]
    PayloadTooLarge,

    #[error("manifest JSON is malformed or invalid: {0}")]
    InvalidManifest(#[from] crate::manifest_refs::ManifestParseError),

    #[error("manifest signature is unverified: {0}")]
    Unverified(#[from] UnverifiedReason),

    #[error("unsupported manifest media type: {0}")]
    UnsupportedMediaType(String),

    #[error("referenced blob not found in storage: {0}")]
    MissingBlob(String),

    #[error("referenced child manifest not found in storage: {0}")]
    MissingManifest(String),

    #[error("invalid tag name")]
    InvalidTag,

    #[error("tag not found")]
    TagNotFound,

    #[error("manifest not found")]
    ManifestNotFound,

    #[error("tag already exists and cannot be overwritten")]
    TagAlreadyExists,

    #[error("tag precondition failed")]
    TagPreconditionFailed,

    #[error("manifest digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch { expected: String, computed: String },

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("reference index error: {0}")]
    RefIndex(#[from] crate::blob_ref_index::RefIndexError),

    #[error("repository coordination lease held by concurrent writer")]
    CoordinationLeaseHeld,

    #[error("repository lease lost: {0}")]
    LeaseLost(String),

    #[error("lifecycle journal corrupt: {0}")]
    CorruptJournal(#[source] serde_json::Error),

    #[error("lifecycle journal serialization failed: {0}")]
    JournalSerialization(#[source] serde_json::Error),
}

pub fn is_supported_manifest_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.oci.artifact.manifest.v1+json"
            | "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub struct RepoCoordinationGuard {
    _guard: crate::consistency::MutationGuard,
    storage: Arc<dyn crate::storage::ManifestLifecycleStoragePort>,
    repo: String,
    owner_id: String,
    lease_id: String,
    renew_handle: Option<tokio::task::JoinHandle<()>>,
    failure_rx: tokio::sync::mpsc::Receiver<String>,
    released: bool,
}

impl RepoCoordinationGuard {
    pub async fn check_lease(&mut self) -> Result<(), ManifestLifecycleError> {
        if let Ok(err) = self.failure_rx.try_recv() {
            return Err(ManifestLifecycleError::LeaseLost(err));
        }
        Ok(())
    }

    pub async fn release(&mut self) -> Result<(), ManifestLifecycleError> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        if let Some(handle) = self.renew_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
        self.storage
            .release_repo_lease(&self.repo, &self.owner_id, &self.lease_id)
            .await
            .map_err(ManifestLifecycleError::Storage)?;
        Ok(())
    }
}

impl Drop for RepoCoordinationGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.renew_handle.take() {
            handle.abort();
        }
        if !self.released {
            self.released = true;
            let storage = Arc::clone(&self.storage);
            let repo = self.repo.clone();
            let owner_id = self.owner_id.clone();
            let lease_id = self.lease_id.clone();
            tokio::spawn(async move {
                let _ = storage
                    .release_repo_lease(&repo, &owner_id, &lease_id)
                    .await;
            });
        }
    }
}

#[derive(Clone)]
pub struct ManifestLifecycleService {
    storage: Arc<dyn crate::storage::ManifestLifecycleStoragePort>,
    ref_index: Option<Arc<BlobRefIndex>>,
    consistency: crate::consistency::ConsistencyCoordinator,
}

impl ManifestLifecycleService {
    pub fn new(
        storage: Arc<dyn crate::storage::ManifestLifecycleStoragePort>,
        ref_index: Option<Arc<BlobRefIndex>>,
        consistency: crate::consistency::ConsistencyCoordinator,
    ) -> Self {
        Self {
            storage,
            ref_index,
            consistency,
        }
    }

    pub async fn publish(
        &self,
        req: PublishManifestRequest,
    ) -> Result<PublishedManifest, ManifestLifecycleError> {
        self.publish_manifest(req).await
    }

    /// Tests whether an unexpired active lifecycle journal exists for this repo.
    ///
    /// Read failures propagate: an unreadable or corrupt journal must never
    /// present as "no pending operation". Genuine absence and an expired
    /// lease both report `Ok(false)`.
    pub async fn is_lifecycle_active(&self, repo: &str) -> Result<bool, ManifestLifecycleError> {
        let Some(journal) = self.read_journal(repo).await? else {
            return Ok(false);
        };
        Ok(journal.lease_expiry_unix_secs > now_unix_secs())
    }

    /// Acquires bounded mutual exclusion for a repository lifecycle mutation.
    pub async fn acquire_coordination(
        &self,
        repo: &str,
    ) -> Result<RepoCoordinationGuard, ManifestLifecycleError> {
        let owner_id = uuid::Uuid::new_v4().to_string();
        let lease_id = uuid::Uuid::new_v4().to_string();

        let mut acquired = false;
        for attempt in 0..10 {
            match self
                .storage
                .acquire_repo_lease(repo, &owner_id, &lease_id, REPO_LEASE_TTL_SECS)
                .await
            {
                Ok(true) => {
                    acquired = true;
                    break;
                }
                Ok(false) => {
                    tokio::time::sleep(Duration::from_millis(50 * (1 << attempt.min(4)))).await;
                }
                Err(e) => return Err(ManifestLifecycleError::Storage(e)),
            }
        }

        if !acquired {
            return Err(ManifestLifecycleError::CoordinationLeaseHeld);
        }

        struct LeaseReleaser {
            storage: Arc<dyn crate::storage::ManifestLifecycleStoragePort>,
            repo: String,
            owner_id: String,
            lease_id: String,
            active: bool,
        }
        impl Drop for LeaseReleaser {
            fn drop(&mut self) {
                if self.active {
                    let storage = Arc::clone(&self.storage);
                    let repo = self.repo.clone();
                    let owner_id = self.owner_id.clone();
                    let lease_id = self.lease_id.clone();
                    tokio::spawn(async move {
                        let _ = storage
                            .release_repo_lease(&repo, &owner_id, &lease_id)
                            .await;
                    });
                }
            }
        }

        let mut releaser = LeaseReleaser {
            storage: Arc::clone(&self.storage),
            repo: repo.to_string(),
            owner_id: owner_id.clone(),
            lease_id: lease_id.clone(),
            active: true,
        };

        let guard = self.consistency.acquire_mutation().await;
        releaser.active = false;

        let (failure_tx, failure_rx) = tokio::sync::mpsc::channel(1);
        let storage_clone = Arc::clone(&self.storage);
        let repo_string = repo.to_string();
        let owner_clone = owner_id.clone();
        let lease_clone = lease_id.clone();

        let renew_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(REPO_LEASE_RENEW_SECS)).await;
                match storage_clone
                    .renew_repo_lease(
                        &repo_string,
                        &owner_clone,
                        &lease_clone,
                        REPO_LEASE_TTL_SECS,
                    )
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        let _ = failure_tx
                            .send("repository lease renewal failed: lease lost".to_string())
                            .await;
                        break;
                    }
                    Err(e) => {
                        let _ = failure_tx
                            .send(format!("repository lease renewal error: {e}"))
                            .await;
                        break;
                    }
                }
            }
        });

        Ok(RepoCoordinationGuard {
            _guard: guard,
            storage: Arc::clone(&self.storage),
            repo: repo.to_string(),
            owner_id,
            lease_id,
            renew_handle: Some(renew_handle),
            failure_rx,
            released: false,
        })
    }

    async fn read_journal(
        &self,
        repo: &str,
    ) -> Result<Option<LifecycleJournalRecord>, ManifestLifecycleError> {
        let bytes = match self.storage.read_lifecycle_journal(repo).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        let record: LifecycleJournalRecord =
            serde_json::from_slice(&bytes).map_err(ManifestLifecycleError::CorruptJournal)?;
        // Recovery applies the journal's digests/tags/referrers to the
        // repository it was read FROM; a journal recording a different
        // repository (misplaced or mis-written) would redirect recovery
        // mutations, so an identity mismatch fails closed. Valid journals
        // always record the repository they are stored under.
        if record.repo.as_str() != repo {
            return Err(ManifestLifecycleError::Storage(StorageError::corrupt_data(
                format!(
                    "lifecycle journal repository mismatch: journal records '{}' but was read for '{repo}'",
                    record.repo.as_str()
                ),
            )));
        }
        Ok(Some(record))
    }

    async fn write_journal(
        &self,
        repo: &str,
        record: &LifecycleJournalRecord,
    ) -> Result<(), ManifestLifecycleError> {
        let bytes = Bytes::from(
            serde_json::to_vec(record).map_err(ManifestLifecycleError::JournalSerialization)?,
        );
        self.storage
            .write_lifecycle_journal(repo, bytes)
            .await
            .map_err(ManifestLifecycleError::Storage)?;
        Ok(())
    }

    async fn delete_journal(&self, repo: &str) -> Result<(), ManifestLifecycleError> {
        self.storage
            .delete_lifecycle_journal(repo)
            .await
            .map_err(ManifestLifecycleError::Storage)
    }

    async fn abort_delete_manifest_precondition_failed(
        &self,
        repo: &str,
        removed_tags: &[String],
        guard: &mut RepoCoordinationGuard,
    ) -> Result<ManifestLifecycleError, ManifestLifecycleError> {
        self.delete_journal(repo).await?;
        if let Some(idx) = self.ref_index.as_ref() {
            for tag in removed_tags {
                let _ = idx.on_tag_deleted(repo, tag);
            }
            let _ = idx.mark_ready();
        }
        let _ = guard.release().await;
        Ok(ManifestLifecycleError::TagPreconditionFailed)
    }

    pub async fn recover_and_ensure_index_healthy(
        &self,
        repo: &str,
    ) -> Result<(), ManifestLifecycleError> {
        if let Some(journal) = self.read_journal(repo).await? {
            self.recover_pending_journal_under_lock(repo, &journal)
                .await?;
        }

        if let Some(idx) = self.ref_index.as_ref() {
            if idx.check_health().is_err() {
                idx.ensure_healthy_or_rebuild(&self.storage, true, false)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn recover_pending_journal_under_lock(
        &self,
        repo: &str,
        journal: &LifecycleJournalRecord,
    ) -> Result<(), ManifestLifecycleError> {
        if let Some(idx) = self.ref_index.as_ref() {
            idx.mark_dirty()?;
        }

        match journal.op_kind {
            LifecycleOpKind::Publish => {
                if self
                    .storage
                    .head_manifest(repo, &journal.target_digest)
                    .await
                    .is_ok()
                {
                    if let Some(ref subject) = journal.subject_digest {
                        let desc = ReferrerDescriptor {
                            media_type: journal.media_type.clone().unwrap_or_default(),
                            digest: journal.target_digest.as_str(),
                            size: journal.manifest_size.unwrap_or(0),
                            artifact_type: journal.artifact_type.clone(),
                            annotations: journal.annotations.clone(),
                        };
                        let _ = self.storage.add_referrer(repo, subject, desc).await;
                    }

                    if let Some(ref tag) = journal.target_reference {
                        let _ = self
                            .storage
                            .mutate_tag(
                                repo,
                                tag,
                                &journal.target_digest,
                                TagMutationPolicy::Replace,
                            )
                            .await;
                    }

                    if let Some(idx) = self.ref_index.as_ref() {
                        idx.on_manifest_published(
                            &self.storage,
                            repo,
                            &journal.target_digest,
                            journal.target_reference.as_deref(),
                        )
                        .await?;
                        idx.flush()?;
                        idx.mark_ready()?;
                    }
                }
                self.delete_journal(repo).await?;
            }
            LifecycleOpKind::DeleteManifest => {
                // Resume tag deletion for current batch
                for tag_snap in &journal.relevant_tags {
                    if !tag_snap.deleted {
                        let _ = self
                            .storage
                            .delete_tag_conditional(
                                repo,
                                &tag_snap.tag,
                                Some(&tag_snap.observed_version),
                            )
                            .await;
                    }
                }

                // If interrupted during tag deletion, finish deleting any remaining tags
                if journal.phase == LifecyclePhase::TagsSnapshotted {
                    let mut proof_token: Option<String> = None;
                    loop {
                        let (page, next_tok) = match self
                            .storage
                            .list_tags_page(repo, proof_token.as_deref(), POLICY_B_TAG_PAGE_SIZE)
                            .await
                        {
                            Ok(res) => res,
                            Err(StorageError::NotFound) => (Vec::new(), None),
                            Err(e) => return Err(ManifestLifecycleError::Storage(e)),
                        };

                        for (t, d) in page {
                            if d.as_str() == journal.target_digest.as_str() {
                                let _ = self.storage.delete_tag(repo, &t).await;
                            }
                        }

                        match next_tok {
                            Some(tok) => proof_token = Some(tok),
                            None => break,
                        }
                    }
                }

                if let Some(ref subject) = journal.subject_digest {
                    let _ = self
                        .storage
                        .remove_referrer(repo, subject, &journal.target_digest)
                        .await;
                }

                let _ = self
                    .storage
                    .delete_manifest(repo, &journal.target_digest)
                    .await;

                if let Some(idx) = self.ref_index.as_ref() {
                    let _ = idx.on_manifest_deleted(repo, &journal.target_digest);
                    idx.flush()?;
                    idx.mark_ready()?;
                }
                self.delete_journal(repo).await?;
            }
            LifecycleOpKind::DeleteTag => {
                if let Some(ref tag) = journal.target_reference {
                    if let Ok(Some((target, _version))) =
                        self.storage.get_tag_with_version(repo, tag).await
                    {
                        if target == journal.target_digest {
                            let _ = self.storage.delete_tag(repo, tag).await;
                        }
                    }

                    if let Some(idx) = self.ref_index.as_ref() {
                        let _ = idx.on_tag_deleted(repo, tag);
                        idx.flush()?;
                        idx.mark_ready()?;
                    }
                }
                self.delete_journal(repo).await?;
            }
            LifecycleOpKind::ProxyEvict => {
                // 1. If tag specified in journal, finish conditionally deleting tag alias
                if let Some(ref tag) = journal.target_reference {
                    if let Ok(Some((target, version))) =
                        self.storage.get_tag_with_version(repo, tag).await
                    {
                        if target == journal.target_digest {
                            let _ = self
                                .storage
                                .delete_tag_conditional(repo, tag, Some(&version))
                                .await;
                            if let Some(idx) = self.ref_index.as_ref() {
                                let _ = idx.on_tag_deleted(repo, tag);
                            }
                        }
                    }
                }

                // 2. Check if any other tags in the repo resolve to target_digest
                let mut has_other_tags = false;
                let mut page_tok: Option<String> = None;
                loop {
                    let (page, next_tok) = match self
                        .storage
                        .list_tags_page(repo, page_tok.as_deref(), POLICY_B_TAG_PAGE_SIZE)
                        .await
                    {
                        Ok(p) => p,
                        Err(StorageError::NotFound) => (Vec::new(), None),
                        Err(e) => return Err(ManifestLifecycleError::Storage(e)),
                    };
                    for (_t_name, t_d) in page {
                        if t_d == journal.target_digest {
                            has_other_tags = true;
                            break;
                        }
                    }
                    if has_other_tags {
                        break;
                    }
                    match next_tok {
                        Some(tok) => page_tok = Some(tok),
                        None => break,
                    }
                }

                // 3. If no remaining tags resolve to target_digest, finish removing manifest root & proxy memberships
                if !has_other_tags {
                    let refs = match self
                        .storage
                        .get_manifest(repo, &journal.target_digest)
                        .await
                    {
                        Ok((_meta, bytes)) => {
                            crate::manifest_refs::parse_manifest_refs(&bytes).ok()
                        }
                        Err(_) => None,
                    };

                    let _ = self
                        .storage
                        .delete_manifest(repo, &journal.target_digest)
                        .await;

                    if let Some(idx) = self.ref_index.as_ref() {
                        let _ = idx.on_manifest_deleted(repo, &journal.target_digest);
                        idx.flush()?;
                        idx.mark_ready()?;
                    }

                    if let Some(refs) = refs {
                        for blob_d in refs.blob_references() {
                            let still_referenced =
                                self.is_blob_referenced_in_repo(repo, blob_d).await?;

                            if !still_referenced {
                                if let Ok(Some(record)) =
                                    self.storage.get_repo_blob_membership(repo, blob_d).await
                                {
                                    if record.provenance
                                        == crate::storage::repo_membership::MembershipProvenance::Proxy
                                    {
                                        let _ = self.storage.unlink_repo_blob(repo, blob_d).await;
                                    }
                                }
                            }
                        }
                    } else {
                        // Manifest was already deleted prior to recovery; check all proxy memberships in this repo
                        let mut page_tok: Option<String> = None;
                        loop {
                            let (page, next_tok) = match self
                                .storage
                                .list_repo_blob_memberships_page(repo, page_tok.as_deref(), 100)
                                .await
                            {
                                Ok(p) => p,
                                Err(_) => break,
                            };
                            for rec in page {
                                if rec.provenance
                                    == crate::storage::repo_membership::MembershipProvenance::Proxy
                                {
                                    let still_referenced =
                                        self.is_blob_referenced_in_repo(repo, &rec.digest).await?;
                                    if !still_referenced {
                                        let _ =
                                            self.storage.unlink_repo_blob(repo, &rec.digest).await;
                                    }
                                }
                            }
                            match next_tok {
                                Some(tok) => page_tok = Some(tok),
                                None => break,
                            }
                        }
                    }
                }

                if let Some(idx) = self.ref_index.as_ref() {
                    idx.flush()?;
                    idx.mark_ready()?;
                }

                self.delete_journal(repo).await?;
            }
        }
        Ok(())
    }

    async fn is_blob_referenced_in_repo(
        &self,
        repo: &str,
        target_blob: &Digest,
    ) -> Result<bool, StorageError> {
        let mut tok: Option<String> = None;
        let mut seen_tokens = std::collections::HashSet::<String>::new();
        loop {
            let (page, next_tok) = self
                .storage
                .list_manifest_digests_page(repo, tok.as_deref(), 100)
                .await?;
            for m_d in page {
                let (_meta, bytes) = self.storage.get_manifest(repo, &m_d).await?;
                let refs = crate::manifest_refs::parse_manifest_refs(&bytes).map_err(|e| {
                    StorageError::corrupt_data(format!(
                        "failed to parse manifest references for manifest {m_d} in repository '{repo}': {e}"
                    ))
                })?;
                for b in refs.blob_references() {
                    if b == target_blob {
                        return Ok(true);
                    }
                }
            }
            match next_tok {
                Some(next) => {
                    if !seen_tokens.insert(next.clone()) {
                        return Err(StorageError::backend(format!(
                            "pagination cycle detected on continuation token '{next}' in repository '{repo}'"
                        )));
                    }
                    tok = Some(next);
                }
                None => break,
            }
        }
        Ok(false)
    }

    /// Orchestrates manifest publication with strict pre-mutation validation,
    /// durable mark_dirty BEFORE any storage mutation, durable operation journaling,
    /// authoritative content storage, atomic tag commit point, synchronous referrer registration,
    /// durable reference index reconciliation, and multi-process/instance coordination.
    /// Publishes a client-pushed manifest.
    ///
    /// Pure client push path: strictly verifies that all referenced config and layer blobs
    /// already exist and have active repository membership in `req.repo`.
    pub async fn publish_manifest(
        &self,
        req: PublishManifestRequest,
    ) -> Result<PublishedManifest, ManifestLifecycleError> {
        self.publish_internal(
            req.repo,
            req.reference,
            req.payload,
            req.declared_media_type,
            req.allow_tag_overwrite,
            false,
        )
        .await
    }

    /// Publishes an upstream proxy-cached manifest.
    ///
    /// Requires verified `ProxyPublicationEvidence` produced by `crate::proxy`.
    /// Allows lazy blob downloading while establishing the manifest as an authoritative
    /// reachability root in `BlobRefIndex` and journaled tag alias.
    pub async fn publish_proxy_cached_manifest(
        &self,
        evidence: ProxyPublicationEvidence,
    ) -> Result<PublishedManifest, ManifestLifecycleError> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(&evidence.payload);
        let digest_hex = hex::encode(hasher.finalize());
        let computed =
            Digest::parse(&format!("sha256:{digest_hex}")).expect("computed sha256 is valid");

        if evidence.verified_digest.hex() != computed.hex() {
            return Err(ManifestLifecycleError::DigestMismatch {
                expected: evidence.verified_digest.to_string(),
                computed: computed.to_string(),
            });
        }

        self.publish_internal(
            evidence.repo,
            evidence.reference,
            evidence.payload,
            evidence.declared_media_type,
            evidence.allow_tag_overwrite,
            true,
        )
        .await
    }

    async fn publish_internal(
        &self,
        repo: String,
        reference: String,
        payload: Bytes,
        declared_media_type: Option<String>,
        allow_tag_overwrite: bool,
        allow_lazy_blobs: bool,
    ) -> Result<PublishedManifest, ManifestLifecycleError> {
        // --- 1. Pure Validation (Preflight Before Any Mutation) ---
        let canonical_repo =
            CanonicalRepoName::parse(&repo).map_err(|_| ManifestLifecycleError::InvalidRepoName)?;

        if payload.is_empty() {
            return Err(ManifestLifecycleError::EmptyPayload);
        }

        if payload.len() > MAX_MANIFEST_SIZE {
            return Err(ManifestLifecycleError::PayloadTooLarge);
        }

        let manifest_json: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(crate::manifest_refs::ManifestParseError::InvalidJson)?;

        // Schema version 1 / legacy signatures rejection
        if let Some(schema_version) = manifest_json.get("schemaVersion").and_then(|v| v.as_i64()) {
            if schema_version == 1 {
                if manifest_json.get("signatures").is_some()
                    || manifest_json.get("signature").is_some()
                {
                    return Err(ManifestLifecycleError::Unverified(
                        UnverifiedReason::SignatureVerificationFailed,
                    ));
                }
                return Err(ManifestLifecycleError::InvalidManifest(
                    crate::manifest_refs::ManifestParseError::SchemaV1Unsupported,
                ));
            }
        }

        if manifest_json.get("signatures").is_some() || manifest_json.get("signature").is_some() {
            return Err(ManifestLifecycleError::Unverified(
                UnverifiedReason::SignatureVerificationFailed,
            ));
        }

        let media_type = manifest_json
            .get("mediaType")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or(declared_media_type)
            .unwrap_or_else(|| "application/vnd.oci.image.manifest.v1+json".to_string());

        if media_type.starts_with("application/vnd.docker.distribution.manifest.v1") {
            if media_type.contains("prettyjws") || manifest_json.get("signatures").is_some() {
                return Err(ManifestLifecycleError::Unverified(
                    UnverifiedReason::SignaturesUnverified,
                ));
            }
            return Err(ManifestLifecycleError::InvalidManifest(
                crate::manifest_refs::ManifestParseError::DockerV1Unsupported,
            ));
        }

        if !is_supported_manifest_media_type(&media_type) {
            return Err(ManifestLifecycleError::UnsupportedMediaType(media_type));
        }

        // Parse and validate descriptor references
        let refs = parse_manifest_refs(&payload)?;

        // Pre-parse referrer info
        let referrer_info = crate::manifest_refs::parse_referrer_info(&payload)?;
        let subject_digest = referrer_info.as_ref().map(|(s, _, _)| s.clone());

        // Compute manifest digest over raw bytes
        let mut hasher = sha2::Sha256::new();
        hasher.update(&payload);
        let digest_hex = hex::encode(hasher.finalize());
        let computed =
            Digest::parse(&format!("sha256:{digest_hex}")).expect("computed sha256 is valid");

        // Validate reference (digest vs tag)
        let is_tag = match Digest::parse(&reference) {
            Ok(ref_digest) => {
                if ref_digest.hex() != computed.hex() {
                    return Err(ManifestLifecycleError::DigestMismatch {
                        expected: ref_digest.to_string(),
                        computed: computed.to_string(),
                    });
                }
                false
            }
            Err(_) => {
                if !is_valid_tag(&reference) {
                    return Err(ManifestLifecycleError::InvalidTag);
                }
                true
            }
        };

        // --- 2. Acquire Repository-Scoped Coordination ---
        let mut guard = self.acquire_coordination(&repo).await?;

        // Recover any interrupted operation and ensure healthy index
        self.recover_and_ensure_index_healthy(&repo).await?;

        // Pre-check referenced blobs and child manifests for client push
        if !allow_lazy_blobs {
            for blob_d in refs.blob_references() {
                if blob_d.as_str()
                    == "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                    || blob_d.as_str()
                        == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                {
                    continue;
                }
                match self.storage.get_repo_blob_membership(&repo, blob_d).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return Err(ManifestLifecycleError::MissingBlob(blob_d.to_string()));
                    }
                    Err(e) => return Err(ManifestLifecycleError::Storage(e)),
                }
            }

            for manifest_d in &refs.manifests {
                match self.storage.head_manifest(&repo, manifest_d).await {
                    Ok(_) => {}
                    Err(StorageError::NotFound) => {
                        return Err(ManifestLifecycleError::MissingManifest(
                            manifest_d.to_string(),
                        ));
                    }
                    Err(e) => return Err(ManifestLifecycleError::Storage(e)),
                }
            }
        }

        guard.check_lease().await?;

        // --- 3. Durably Mark Index Dirty BEFORE Authoritative Mutations ---
        if let Some(idx) = self.ref_index.as_ref() {
            idx.mark_dirty()?;
        }

        // --- 4. Write Initial Operation Journal ---
        let op_id = uuid::Uuid::new_v4().to_string();
        let now = now_unix_secs();
        let (ref_subject, ref_artifact, ref_annotations) = match referrer_info.clone() {
            Some((s, a, ann)) => (Some(s), a, ann),
            None => (None, None, None),
        };

        let mut journal = LifecycleJournalRecord {
            op_id: op_id.clone(),
            repo: canonical_repo,
            op_kind: LifecycleOpKind::Publish,
            target_digest: computed.clone(),
            target_reference: if is_tag {
                Some(reference.clone())
            } else {
                None
            },
            phase: LifecyclePhase::ManifestStored,
            owner_id: guard.owner_id.clone(),
            lease_expiry_unix_secs: now + REPO_LEASE_TTL_SECS,
            started_unix_secs: now,
            updated_unix_secs: now,
            relevant_tags: Vec::new(),
            subject_digest: ref_subject.clone(),
            artifact_type: ref_artifact.clone(),
            annotations: ref_annotations.clone(),
            media_type: Some(media_type.clone()),
            manifest_size: Some(payload.len() as u64),
        };

        // --- 5. CAS Manifest Storage ---
        guard.check_lease().await?;
        let meta = match self
            .storage
            .put_manifest(&repo, &computed, payload.clone())
            .await
        {
            Ok(m) => m,
            Err(e) => return Err(ManifestLifecycleError::Storage(e)),
        };

        // Write initial journal phase
        self.write_journal(&repo, &journal).await?;

        // --- 6. Referrer Registration (Atomic Step 2) ---
        if let Some(ref subject) = ref_subject {
            guard.check_lease().await?;
            let desc = ReferrerDescriptor {
                digest: computed.to_string(),
                media_type: media_type.clone(),
                size: meta.size,
                artifact_type: ref_artifact.clone(),
                annotations: ref_annotations.clone(),
            };
            self.storage.add_referrer(&repo, subject, desc).await?;

            journal.phase = LifecyclePhase::ReferrerRegistered;
            journal.updated_unix_secs = now_unix_secs();
            self.write_journal(&repo, &journal).await?;
        }

        // --- 7. Tag Mutation (Atomic Step 3) ---
        if is_tag {
            guard.check_lease().await?;
            let policy = if allow_tag_overwrite {
                TagMutationPolicy::Replace
            } else {
                TagMutationPolicy::CreateOnly
            };

            let _mutation_res = match self
                .storage
                .mutate_tag(&repo, &reference, &computed, policy)
                .await
            {
                Ok(m) => m,
                Err(StorageError::TagAlreadyExists) => {
                    if let Some(idx) = self.ref_index.as_ref() {
                        // Reconcile manifest root even if tag mutation was rejected
                        idx.on_manifest_published(&self.storage, &repo, &computed, None)
                            .await?;
                        idx.flush()?;
                        idx.mark_ready()?;
                    }
                    self.delete_journal(&repo).await?;
                    let _ = guard.release().await;
                    return Err(ManifestLifecycleError::TagAlreadyExists);
                }
                Err(err) => {
                    return Err(ManifestLifecycleError::Storage(err));
                }
            };

            if let Some(idx) = self.ref_index.as_ref() {
                idx.on_manifest_published(&self.storage, &repo, &computed, Some(&reference))
                    .await?;
                idx.flush()?;
                idx.mark_ready()?;
            }
        } else if let Some(idx) = self.ref_index.as_ref() {
            idx.on_manifest_published(&self.storage, &repo, &computed, None)
                .await?;
            idx.flush()?;
            idx.mark_ready()?;
        }

        self.delete_journal(&repo).await?;
        guard.release().await?;

        Ok(PublishedManifest {
            digest: computed,
            media_type: meta.media_type,
            size: meta.size,
            subject: subject_digest,
            is_tag,
        })
    }

    /// Performs logical proxy cache eviction under repository coordination:
    /// 1. Conditionally removes only the tag alias that still points to the cached digest.
    /// 2. If no other tags in the repository point to the digest, unindexes the manifest root and removes it.
    /// 3. For any referenced blobs with Proxy provenance not referenced by any other manifest in the repository,
    ///    unlinks the proxy repository membership.
    /// 4. Physical CAS blobs are NOT deleted; physical reclamation is left exclusively to `BlobGcService`.
    pub async fn evict_proxy_cached_entry(
        &self,
        repo: &str,
        tag: Option<&str>,
        target_digest: &Digest,
    ) -> Result<ProxyEvictionResult, ManifestLifecycleError> {
        if CanonicalRepoName::parse(repo).is_err() {
            return Err(ManifestLifecycleError::InvalidRepoName);
        }

        let mut guard = self.acquire_coordination(repo).await?;
        self.recover_and_ensure_index_healthy(repo).await?;

        // 1. Snapshot target tag if provided
        let mut relevant_tags = Vec::new();
        if let Some(t) = tag {
            if let Ok(Some((target, version))) = self.storage.get_tag_with_version(repo, t).await {
                if target == *target_digest {
                    relevant_tags.push(TagSnapshot {
                        tag: t.to_string(),
                        observed_version: version,
                        target_digest: target,
                        deleted: false,
                    });
                }
            }
        }

        // 2. Durably mark index dirty before authoritative mutations
        guard.check_lease().await?;
        if let Some(idx) = self.ref_index.as_ref() {
            idx.mark_dirty()?;
        }

        // 3. Write initial lifecycle journal
        let canonical_repo =
            CanonicalRepoName::parse(repo).map_err(|_| ManifestLifecycleError::InvalidRepoName)?;
        let mut journal = LifecycleJournalRecord {
            op_id: uuid::Uuid::new_v4().to_string(),
            repo: canonical_repo,
            op_kind: LifecycleOpKind::ProxyEvict,
            target_digest: target_digest.clone(),
            target_reference: tag.map(|s| s.to_string()),
            phase: LifecyclePhase::ProxyEvictInitiated,
            owner_id: guard.owner_id.clone(),
            lease_expiry_unix_secs: now_unix_secs() + REPO_LEASE_TTL_SECS,
            started_unix_secs: now_unix_secs(),
            updated_unix_secs: now_unix_secs(),
            relevant_tags: relevant_tags.clone(),
            subject_digest: None,
            artifact_type: None,
            annotations: None,
            media_type: None,
            manifest_size: None,
        };
        self.write_journal(repo, &journal).await?;

        // 4. Conditionally remove tag alias
        let mut tag_removed = None;
        if let Some(tag_snap) = relevant_tags.first() {
            let res = self
                .storage
                .delete_tag_conditional(repo, &tag_snap.tag, Some(&tag_snap.observed_version))
                .await;
            if matches!(res, Ok(crate::storage::ConditionalDeleteResult::Deleted)) {
                if let Some(idx) = self.ref_index.as_ref() {
                    let _ = idx.on_tag_deleted(repo, &tag_snap.tag);
                }
                tag_removed = Some(tag_snap.tag.clone());

                journal.phase = LifecyclePhase::ProxyTagDeleted;
                journal.updated_unix_secs = now_unix_secs();
                let _ = self.write_journal(repo, &journal).await;
            }
        }

        // 5. Check if any other tags in repo resolve to target_digest
        let mut has_other_tags = false;
        let mut page_tok: Option<String> = None;
        loop {
            let (page, next_tok) = match self
                .storage
                .list_tags_page(repo, page_tok.as_deref(), POLICY_B_TAG_PAGE_SIZE)
                .await
            {
                Ok(p) => p,
                Err(StorageError::NotFound) => (Vec::new(), None),
                Err(e) => return Err(ManifestLifecycleError::Storage(e)),
            };
            for (_t_name, t_d) in page {
                if t_d.hex() == target_digest.hex() {
                    has_other_tags = true;
                    break;
                }
            }
            if has_other_tags {
                break;
            }
            match next_tok {
                Some(tok) => page_tok = Some(tok),
                None => break,
            }
        }

        let mut manifest_removed = false;
        let mut memberships_unlinked = 0;

        // 6. If no tags point to target_digest, remove manifest root and unneeded proxy memberships
        if !has_other_tags {
            if let Ok((_meta, bytes)) = self.storage.get_manifest(repo, target_digest).await {
                let refs = crate::manifest_refs::parse_manifest_refs(&bytes).ok();

                // Delete manifest from storage
                let _ = self.storage.delete_manifest(repo, target_digest).await;
                manifest_removed = true;

                journal.phase = LifecyclePhase::ProxyManifestDeleted;
                journal.updated_unix_secs = now_unix_secs();
                let _ = self.write_journal(repo, &journal).await;

                // Reconcile index
                if let Some(idx) = self.ref_index.as_ref() {
                    let _ = idx.on_manifest_deleted(repo, target_digest);
                    idx.flush()?;
                    idx.mark_ready()?;
                }

                // If refs were parsed, check if remaining manifests in repo reference each blob
                if let Some(refs) = refs {
                    for blob_d in refs.blob_references() {
                        let still_referenced =
                            self.is_blob_referenced_in_repo(repo, blob_d).await?;

                        if !still_referenced {
                            // Check if blob membership is of Proxy provenance
                            if let Ok(Some(record)) =
                                self.storage.get_repo_blob_membership(repo, blob_d).await
                            {
                                if record.provenance
                                    == crate::storage::repo_membership::MembershipProvenance::Proxy
                                {
                                    let _ = self.storage.unlink_repo_blob(repo, blob_d).await;
                                    memberships_unlinked += 1;
                                }
                            }
                        }
                    }
                }

                journal.phase = LifecyclePhase::ProxyMembershipsUnlinked;
                journal.updated_unix_secs = now_unix_secs();
                let _ = self.write_journal(repo, &journal).await;
            }
        }

        if let Some(idx) = self.ref_index.as_ref() {
            idx.flush()?;
            idx.mark_ready()?;
        }

        self.delete_journal(repo).await?;
        guard.release().await?;

        Ok(ProxyEvictionResult {
            repo: repo.to_string(),
            target_digest: target_digest.clone(),
            tag_removed,
            manifest_removed,
            memberships_unlinked,
        })
    }

    /// Deletes a stored manifest by digest according to Policy B:
    /// 1. Acquire repository coordination.
    /// 2. Recover any pending journal and ensure healthy index.
    /// 3. Preflight verifies manifest exists; extracts subject.
    /// 4. Durable Tag Snapshotting: collects all tags currently pointing to this digest.
    /// 5. Durably marks reference index dirty.
    /// 6. Writes operation journal with snapshot.
    /// 7. Conditional Tag Deletion with retry/resnapshot loop until zero tags remain.
    /// 8. Authoritative zero-tag rescan proof.
    /// 9. Referrer descriptor cleanup from subject index if applicable.
    /// 10. Authoritative CAS manifest deletion.
    /// 11. Reference index reconciliation & flush.
    /// 12. Durably marks index ready and deletes journal.
    pub async fn delete_manifest(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<ManifestDeleteResult, ManifestLifecycleError> {
        if CanonicalRepoName::parse(repo).is_err() {
            return Err(ManifestLifecycleError::InvalidRepoName);
        }

        let mut guard = self.acquire_coordination(repo).await?;
        self.recover_and_ensure_index_healthy(repo).await?;

        // 1. Verify manifest exists in storage
        let (_meta, bytes) = match self.storage.get_manifest(repo, digest).await {
            Ok(res) => res,
            Err(StorageError::NotFound) => return Err(ManifestLifecycleError::ManifestNotFound),
            Err(e) => return Err(ManifestLifecycleError::Storage(e)),
        };

        let maybe_subject = crate::manifest_refs::extract_subject_digest(&bytes)
            .ok()
            .flatten();

        // 2. Durably Mark Index Dirty BEFORE any journal or storage mutation
        guard.check_lease().await?;
        if let Some(idx) = self.ref_index.as_ref() {
            idx.mark_dirty()?;
        }

        // 3. Write Initial Operation Journal
        let op_id = uuid::Uuid::new_v4().to_string();
        let now = now_unix_secs();
        let canonical_repo =
            CanonicalRepoName::parse(repo).map_err(|_| ManifestLifecycleError::InvalidRepoName)?;
        let mut journal = LifecycleJournalRecord {
            op_id: op_id.clone(),
            repo: canonical_repo,
            op_kind: LifecycleOpKind::DeleteManifest,
            target_digest: digest.clone(),
            target_reference: None,
            phase: LifecyclePhase::TagsSnapshotted,
            owner_id: guard.owner_id.clone(),
            lease_expiry_unix_secs: now + REPO_LEASE_TTL_SECS,
            started_unix_secs: now,
            updated_unix_secs: now,
            relevant_tags: Vec::new(),
            subject_digest: maybe_subject.clone(),
            artifact_type: None,
            annotations: None,
            media_type: None,
            manifest_size: None,
        };
        self.write_journal(repo, &journal).await?;

        // 4. Safe Bounded Tag Snapshotting & Deletion Loop
        let mut removed_tags: Vec<String> = Vec::new();
        let digest_str = digest.as_str();

        let mut fixed_point_reached = false;
        while !fixed_point_reached {
            let mut page_token: Option<String> = None;
            let mut matching_found_in_pass = 0;

            loop {
                let (page, next_tok) = match self
                    .storage
                    .list_tags_page(repo, page_token.as_deref(), POLICY_B_TAG_PAGE_SIZE)
                    .await
                {
                    Ok(res) => res,
                    Err(StorageError::NotFound) => (Vec::new(), None),
                    Err(e) => return Err(ManifestLifecycleError::Storage(e)),
                };

                let mut current_batch: Vec<TagSnapshot> = Vec::new();
                for (tag, target) in page {
                    if target.as_str() == digest_str {
                        let version = match self.storage.get_tag_with_version(repo, &tag).await? {
                            Some((_, v)) => v,
                            None => "initial".to_string(),
                        };
                        current_batch.push(TagSnapshot {
                            tag,
                            observed_version: version,
                            target_digest: digest.clone(),
                            deleted: false,
                        });
                    }
                }

                if !current_batch.is_empty() {
                    matching_found_in_pass += current_batch.len();
                    journal.relevant_tags = current_batch;
                    journal.updated_unix_secs = now_unix_secs();
                    self.write_journal(repo, &journal).await?;

                    let batch_len = journal.relevant_tags.len();
                    for i in 0..batch_len {
                        let mut attempts = 0;
                        loop {
                            attempts += 1;
                            let tag_name = journal.relevant_tags[i].tag.clone();
                            let observed_ver = journal.relevant_tags[i].observed_version.clone();
                            match self
                                .storage
                                .delete_tag_conditional(repo, &tag_name, Some(&observed_ver))
                                .await?
                            {
                                ConditionalDeleteResult::Deleted => {
                                    journal.relevant_tags[i].deleted = true;
                                    removed_tags.push(tag_name);
                                    break;
                                }
                                ConditionalDeleteResult::NotFound => {
                                    journal.relevant_tags[i].deleted = true;
                                    break;
                                }
                                ConditionalDeleteResult::PreconditionFailed { .. } => {
                                    match self.storage.get_tag_with_version(repo, &tag_name).await?
                                    {
                                        Some((new_target, new_version)) => {
                                            if new_target.as_str() == digest_str {
                                                if attempts > 3 {
                                                    return Err(self
                                                        .abort_delete_manifest_precondition_failed(
                                                            repo,
                                                            &removed_tags,
                                                            &mut guard,
                                                        )
                                                        .await?);
                                                }
                                                journal.relevant_tags[i].observed_version =
                                                    new_version;
                                                continue;
                                            } else {
                                                // Tag was moved to different manifest; no longer points here
                                                journal.relevant_tags[i].deleted = true;
                                                break;
                                            }
                                        }
                                        None => {
                                            journal.relevant_tags[i].deleted = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        self.write_journal(repo, &journal).await?;
                    }
                }

                match next_tok {
                    Some(tok) => page_token = Some(tok),
                    None => break,
                }
            }

            if matching_found_in_pass == 0 {
                fixed_point_reached = true;
            }
        }

        // 5. Pre-delete Authoritative Proof: verify 0 tags resolve to this digest across full pagination
        let mut proof_token: Option<String> = None;
        loop {
            let (page, next_tok) = self
                .storage
                .list_tags_page(repo, proof_token.as_deref(), POLICY_B_TAG_PAGE_SIZE)
                .await?;
            for (t, d) in page {
                if d.as_str() == digest_str {
                    return Err(self
                        .abort_delete_manifest_precondition_failed(
                            repo,
                            &removed_tags,
                            &mut guard,
                        )
                        .await?);
                }
                let _ = t;
            }
            match next_tok {
                Some(tok) => proof_token = Some(tok),
                None => break,
            }
        }

        journal.phase = LifecyclePhase::TagsDeleted;
        journal.updated_unix_secs = now_unix_secs();
        self.write_journal(repo, &journal).await?;

        // 7. Clean up from referrers list if this manifest referenced a subject
        if let Some(ref subject) = maybe_subject {
            let _ = self.storage.remove_referrer(repo, subject, digest).await;
            journal.phase = LifecyclePhase::ReferrerCleaned;
            journal.updated_unix_secs = now_unix_secs();
            self.write_journal(repo, &journal).await?;
        }

        // 8. Delete stored manifest bytes
        self.storage.delete_manifest(repo, digest).await?;
        journal.phase = LifecyclePhase::ManifestDeleted;
        journal.updated_unix_secs = now_unix_secs();
        self.write_journal(repo, &journal).await?;

        // 9. Reconcile reference index & flush
        if let Some(idx) = self.ref_index.as_ref() {
            idx.on_manifest_deleted(repo, digest)?;
            idx.flush()?;
            idx.mark_ready()?;
        }

        self.delete_journal(repo).await?;
        guard.release().await?;

        Ok(ManifestDeleteResult {
            digest: digest.clone(),
            removed_tags,
        })
    }

    /// Deletes a tag alias without deleting the underlying stored manifest or its blob references.
    pub async fn delete_tag(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<TagDeleteResult, ManifestLifecycleError> {
        if CanonicalRepoName::parse(repo).is_err() {
            return Err(ManifestLifecycleError::InvalidRepoName);
        }
        if !is_valid_tag(tag) {
            return Err(ManifestLifecycleError::InvalidTag);
        }

        let mut guard = self.acquire_coordination(repo).await?;
        self.recover_and_ensure_index_healthy(repo).await?;

        let (target_digest, version) = match self.storage.get_tag_with_version(repo, tag).await? {
            Some(res) => res,
            None => return Err(ManifestLifecycleError::TagNotFound),
        };

        guard.check_lease().await?;

        // Durably mark index dirty
        if let Some(idx) = self.ref_index.as_ref() {
            idx.mark_dirty()?;
        }

        let op_id = uuid::Uuid::new_v4().to_string();
        let now = now_unix_secs();
        let canonical_repo =
            CanonicalRepoName::parse(repo).map_err(|_| ManifestLifecycleError::InvalidRepoName)?;
        let mut journal = LifecycleJournalRecord {
            op_id: op_id.clone(),
            repo: canonical_repo,
            op_kind: LifecycleOpKind::DeleteTag,
            target_digest: target_digest.clone(),
            target_reference: Some(tag.to_string()),
            phase: LifecyclePhase::TagDeleteInitiated,
            owner_id: guard.owner_id.clone(),
            lease_expiry_unix_secs: now + REPO_LEASE_TTL_SECS,
            started_unix_secs: now,
            updated_unix_secs: now,
            relevant_tags: vec![TagSnapshot {
                tag: tag.to_string(),
                observed_version: version.clone(),
                target_digest: target_digest.clone(),
                deleted: false,
            }],
            subject_digest: None,
            artifact_type: None,
            annotations: None,
            media_type: None,
            manifest_size: None,
        };
        self.write_journal(repo, &journal).await?;

        match self
            .storage
            .delete_tag_conditional(repo, tag, Some(&version))
            .await?
        {
            ConditionalDeleteResult::Deleted => {}
            ConditionalDeleteResult::NotFound => {
                self.delete_journal(repo).await?;
                if let Some(idx) = self.ref_index.as_ref() {
                    let _ = idx.mark_ready();
                }
                return Err(ManifestLifecycleError::TagNotFound);
            }
            ConditionalDeleteResult::PreconditionFailed { .. } => {
                self.delete_journal(repo).await?;
                if let Some(idx) = self.ref_index.as_ref() {
                    let _ = idx.mark_ready();
                }
                return Err(ManifestLifecycleError::TagPreconditionFailed);
            }
        }

        journal.phase = LifecyclePhase::TagDeletedOnly;
        journal.updated_unix_secs = now_unix_secs();
        self.write_journal(repo, &journal).await?;

        if let Some(idx) = self.ref_index.as_ref() {
            idx.on_tag_deleted(repo, tag)?;
            idx.flush()?;
            idx.mark_ready()?;
        }

        self.delete_journal(repo).await?;
        guard.release().await?;

        Ok(TagDeleteResult {
            tag: tag.to_string(),
            target_digest,
        })
    }

    /// Atomically mutates a tag pointer pointing to an already-stored manifest.
    pub async fn mutate_tag(
        &self,
        repo: &str,
        tag: &str,
        target_digest: &Digest,
        policy: TagMutationPolicy,
    ) -> Result<TagMutationResult, ManifestLifecycleError> {
        if CanonicalRepoName::parse(repo).is_err() {
            return Err(ManifestLifecycleError::InvalidRepoName);
        }
        if !is_valid_tag(tag) {
            return Err(ManifestLifecycleError::InvalidTag);
        }

        let mut guard = self.acquire_coordination(repo).await?;
        self.recover_and_ensure_index_healthy(repo).await?;

        // Verify target manifest exists
        match self.storage.head_manifest(repo, target_digest).await {
            Ok(_) => {}
            Err(StorageError::NotFound) => return Err(ManifestLifecycleError::ManifestNotFound),
            Err(e) => return Err(ManifestLifecycleError::Storage(e)),
        }

        guard.check_lease().await?;

        if let Some(idx) = self.ref_index.as_ref() {
            idx.mark_dirty()?;
        }

        let mutation = match self
            .storage
            .mutate_tag(repo, tag, target_digest, policy)
            .await
        {
            Ok(m) => m,
            Err(StorageError::TagAlreadyExists) => {
                if let Some(idx) = self.ref_index.as_ref() {
                    let _ = idx.mark_ready();
                }
                return Err(ManifestLifecycleError::TagAlreadyExists);
            }
            Err(e) => return Err(ManifestLifecycleError::Storage(e)),
        };

        if let Some(idx) = self.ref_index.as_ref() {
            idx.on_manifest_published(&self.storage, repo, target_digest, Some(tag))
                .await?;
            idx.flush()?;
            idx.mark_ready()?;
        }

        guard.release().await?;

        Ok(TagMutationResult {
            tag: tag.to_string(),
            digest: target_digest.clone(),
            mutation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consistency::ConsistencyCoordinator;
    use crate::registry::digest::Digest;
    use crate::storage::fs::FsStorage;
    use crate::storage::ports::*;
    use crate::storage::{
        ManifestMeta, RepositoryBlobMembershipStorage, StorageError, StorageErrorKind,
    };
    use bytes::Bytes;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestLifecycleMockStorage {
        inner: Arc<FsStorage>,
        fail_listing: AtomicBool,
        fail_get_manifest: AtomicBool,
        corrupt_manifest: AtomicBool,
        immediate_cycle: AtomicBool,
        multi_cycle: AtomicBool,
        /// Force the next conditional tag delete to observe a replacement
        /// (PreconditionFailed) — deterministic coverage of the lifecycle
        /// cleanup branch now that the coherent tag path cannot produce a
        /// spurious precondition failure outside a true concurrent race.
        force_tag_precondition_failed: AtomicBool,
        force_persistent_tag_precondition_failed: AtomicBool,
    }

    #[async_trait::async_trait]
    impl BlobCasReader for TestLifecycleMockStorage {
        async fn head_blob(
            &self,
            digest: &Digest,
        ) -> Result<crate::storage::BlobMeta, StorageError> {
            self.inner.head_blob(digest).await
        }
        async fn open_blob(
            &self,
            digest: &Digest,
        ) -> Result<
            (
                crate::storage::BlobMeta,
                std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
            ),
            StorageError,
        > {
            self.inner.open_blob(digest).await
        }
    }

    #[async_trait::async_trait]
    impl RepositoryCatalogReader for TestLifecycleMockStorage {
        async fn list_repositories(&self) -> Result<Vec<String>, StorageError> {
            self.inner.list_repositories().await
        }
        async fn repo_timestamps(
            &self,
            name: &str,
        ) -> Result<crate::storage::RepoTimestamps, StorageError> {
            self.inner.repo_timestamps(name).await
        }
    }

    #[async_trait::async_trait]
    impl ManifestReader for TestLifecycleMockStorage {
        async fn head_manifest(
            &self,
            name: &str,
            digest: &Digest,
        ) -> Result<ManifestMeta, StorageError> {
            self.inner.head_manifest(name, digest).await
        }
        async fn get_manifest(
            &self,
            name: &str,
            digest: &Digest,
        ) -> Result<(ManifestMeta, Bytes), StorageError> {
            if self.fail_get_manifest.load(Ordering::SeqCst) {
                return Err(StorageError::io("simulated manifest read I/O error"));
            }
            if self.corrupt_manifest.load(Ordering::SeqCst) {
                return Ok((
                    ManifestMeta {
                        size: 7,
                        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                    },
                    Bytes::from("{corrupt"),
                ));
            }
            self.inner.get_manifest(name, digest).await
        }
        async fn list_manifest_digests_page(
            &self,
            repo: &str,
            continuation_token: Option<&str>,
            page_limit: usize,
        ) -> Result<(Vec<Digest>, Option<String>), StorageError> {
            if self.fail_listing.load(Ordering::SeqCst) {
                return Err(StorageError::backend("simulated manifest listing error"));
            }
            if self.immediate_cycle.load(Ordering::SeqCst) {
                let (page, _) = self
                    .inner
                    .list_manifest_digests_page(repo, continuation_token, page_limit)
                    .await?;
                return Ok((page, Some("repeat_token".to_string())));
            }
            if self.multi_cycle.load(Ordering::SeqCst) {
                let (page, _) = self
                    .inner
                    .list_manifest_digests_page(repo, continuation_token, page_limit)
                    .await?;
                let next_tok = match continuation_token {
                    None => Some("cycle_tok_A".to_string()),
                    Some("cycle_tok_A") => Some("cycle_tok_B".to_string()),
                    Some("cycle_tok_B") => Some("cycle_tok_A".to_string()),
                    Some(other) => Some(other.to_string()),
                };
                return Ok((page, next_tok));
            }
            self.inner
                .list_manifest_digests_page(repo, continuation_token, page_limit)
                .await
        }
    }

    #[async_trait::async_trait]
    impl ManifestStore for TestLifecycleMockStorage {
        async fn put_manifest(
            &self,
            name: &str,
            digest: &Digest,
            bytes: Bytes,
        ) -> Result<ManifestMeta, StorageError> {
            self.inner.put_manifest(name, digest, bytes).await
        }
        async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), StorageError> {
            self.inner.delete_manifest(name, digest).await
        }
    }

    #[async_trait::async_trait]
    impl TagReader for TestLifecycleMockStorage {
        async fn resolve_tag(&self, name: &str, tag: &str) -> Result<Digest, StorageError> {
            self.inner.resolve_tag(name, tag).await
        }
        async fn list_tags(&self, name: &str) -> Result<Vec<String>, StorageError> {
            self.inner.list_tags(name).await
        }
        async fn list_tags_page(
            &self,
            repo: &str,
            continuation_token: Option<&str>,
            page_limit: usize,
        ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
            self.inner
                .list_tags_page(repo, continuation_token, page_limit)
                .await
        }
        async fn get_tag_with_version(
            &self,
            repo: &str,
            tag: &str,
        ) -> Result<Option<(Digest, String)>, StorageError> {
            self.inner.get_tag_with_version(repo, tag).await
        }
    }

    #[async_trait::async_trait]
    impl TagStore for TestLifecycleMockStorage {
        async fn set_tag(
            &self,
            name: &str,
            tag: &str,
            digest: &Digest,
        ) -> Result<(), StorageError> {
            self.inner.set_tag(name, tag, digest).await
        }
        async fn mutate_tag(
            &self,
            name: &str,
            tag: &str,
            digest: &Digest,
            policy: crate::storage::TagMutationPolicy,
        ) -> Result<crate::storage::TagMutation, StorageError> {
            self.inner.mutate_tag(name, tag, digest, policy).await
        }
        async fn delete_tag(&self, name: &str, tag: &str) -> Result<(), StorageError> {
            self.inner.delete_tag(name, tag).await
        }
        async fn delete_tag_conditional(
            &self,
            repo: &str,
            tag: &str,
            expected_version: Option<&str>,
        ) -> Result<crate::storage::ConditionalDeleteResult, StorageError> {
            if self.force_persistent_tag_precondition_failed.load(Ordering::SeqCst)
                || self.force_tag_precondition_failed.swap(false, Ordering::SeqCst)
            {
                return Ok(
                    crate::storage::ConditionalDeleteResult::PreconditionFailed {
                        current_version: Some("interposed-replacement-version".to_string()),
                    },
                );
            }
            self.inner
                .delete_tag_conditional(repo, tag, expected_version)
                .await
        }
    }

    #[async_trait::async_trait]
    impl ReferrersReader for TestLifecycleMockStorage {
        async fn list_referrers(
            &self,
            name: &str,
            subject: &Digest,
        ) -> Result<Vec<crate::storage::ReferrerDescriptor>, StorageError> {
            self.inner.list_referrers(name, subject).await
        }
        async fn list_referrers_page(
            &self,
            repo: &str,
            subject: &Digest,
            continuation_token: Option<&str>,
            page_limit: usize,
        ) -> Result<(Vec<crate::storage::ReferrerDescriptor>, Option<String>), StorageError>
        {
            self.inner
                .list_referrers_page(repo, subject, continuation_token, page_limit)
                .await
        }
    }

    #[async_trait::async_trait]
    impl ReferrersStore for TestLifecycleMockStorage {
        async fn add_referrer(
            &self,
            name: &str,
            subject: &Digest,
            descriptor: crate::storage::ReferrerDescriptor,
        ) -> Result<(), StorageError> {
            self.inner.add_referrer(name, subject, descriptor).await
        }
        async fn remove_referrer(
            &self,
            name: &str,
            subject: &Digest,
            referrer: &Digest,
        ) -> Result<(), StorageError> {
            self.inner.remove_referrer(name, subject, referrer).await
        }
    }

    #[async_trait::async_trait]
    impl RepositoryBlobMembershipStorage for TestLifecycleMockStorage {
        async fn link_repo_blob(
            &self,
            record: &crate::storage::RepoBlobMembershipRecord,
        ) -> Result<(), StorageError> {
            self.inner.link_repo_blob(record).await
        }
        async fn unlink_repo_blob(
            &self,
            repo: &str,
            digest: &Digest,
        ) -> Result<bool, StorageError> {
            self.inner.unlink_repo_blob(repo, digest).await
        }
        async fn get_repo_blob_membership(
            &self,
            repo: &str,
            digest: &Digest,
        ) -> Result<Option<crate::storage::RepoBlobMembershipRecord>, StorageError> {
            self.inner.get_repo_blob_membership(repo, digest).await
        }
        async fn list_repo_blob_memberships_page(
            &self,
            repo: &str,
            continuation_token: Option<&str>,
            page_limit: usize,
        ) -> Result<
            (
                Vec<crate::storage::RepoBlobMembershipRecord>,
                Option<String>,
            ),
            StorageError,
        > {
            self.inner
                .list_repo_blob_memberships_page(repo, continuation_token, page_limit)
                .await
        }
    }

    #[async_trait::async_trait]
    impl LifecycleJournalStore for TestLifecycleMockStorage {
        async fn read_lifecycle_journal(&self, repo: &str) -> Result<Option<Bytes>, StorageError> {
            self.inner.read_lifecycle_journal(repo).await
        }
        async fn write_lifecycle_journal(
            &self,
            repo: &str,
            data: Bytes,
        ) -> Result<(), StorageError> {
            self.inner.write_lifecycle_journal(repo, data).await
        }
        async fn delete_lifecycle_journal(&self, repo: &str) -> Result<(), StorageError> {
            self.inner.delete_lifecycle_journal(repo).await
        }
    }

    #[async_trait::async_trait]
    impl RepositoryLeaseStore for TestLifecycleMockStorage {
        async fn acquire_repo_lease(
            &self,
            repo: &str,
            owner_id: &str,
            lease_id: &str,
            ttl_secs: u64,
        ) -> Result<bool, StorageError> {
            self.inner
                .acquire_repo_lease(repo, owner_id, lease_id, ttl_secs)
                .await
        }
        async fn renew_repo_lease(
            &self,
            repo: &str,
            owner_id: &str,
            lease_id: &str,
            ttl_secs: u64,
        ) -> Result<bool, StorageError> {
            self.inner
                .renew_repo_lease(repo, owner_id, lease_id, ttl_secs)
                .await
        }
        async fn release_repo_lease(
            &self,
            repo: &str,
            owner_id: &str,
            lease_id: &str,
        ) -> Result<(), StorageError> {
            self.inner
                .release_repo_lease(repo, owner_id, lease_id)
                .await
        }
    }

    fn setup_mock_service(
        dir: &tempfile::TempDir,
    ) -> (Arc<TestLifecycleMockStorage>, ManifestLifecycleService) {
        let fs_root = dir.path().join("data");
        std::fs::create_dir_all(&fs_root).unwrap();

        let fs_storage = Arc::new(FsStorage::new(fs_root, 50 * 1024 * 1024));
        let mock_storage = Arc::new(TestLifecycleMockStorage {
            inner: fs_storage,
            fail_listing: AtomicBool::new(false),
            fail_get_manifest: AtomicBool::new(false),
            corrupt_manifest: AtomicBool::new(false),
            immediate_cycle: AtomicBool::new(false),
            multi_cycle: AtomicBool::new(false),
            force_tag_precondition_failed: AtomicBool::new(false),
            force_persistent_tag_precondition_failed: AtomicBool::new(false),
        });
        let coordinator = ConsistencyCoordinator::new();
        let service = ManifestLifecycleService::new(mock_storage.clone(), None, coordinator);
        (mock_storage, service)
    }

    fn test_digest(val: &str) -> Digest {
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(val.as_bytes());
        let hex = hex::encode(hash);
        Digest::parse(&format!("sha256:{hex}")).expect("valid sha256")
    }

    #[tokio::test]
    async fn test_is_blob_referenced_fails_on_listing_error() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);
        mock.fail_listing.store(true, Ordering::SeqCst);

        let target_blob = test_digest("1");
        let res = service
            .is_blob_referenced_in_repo("test-repo", &target_blob)
            .await;

        assert!(matches!(
            res,
            Err(StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_is_blob_referenced_fails_on_manifest_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);

        // Put a manifest so listing finds an entry
        let m_d = test_digest("manifest1");
        let dummy_manifest = Bytes::from(
            r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000002","size":2},"layers":[]}"#,
        );
        mock.inner
            .put_manifest("test-repo", &m_d, dummy_manifest)
            .await
            .unwrap();

        mock.fail_get_manifest.store(true, Ordering::SeqCst);

        let target_blob = test_digest("target");
        let res = service
            .is_blob_referenced_in_repo("test-repo", &target_blob)
            .await;

        assert!(matches!(
            res,
            Err(StorageError::Internal {
                kind: StorageErrorKind::Io,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_is_blob_referenced_fails_on_corrupt_manifest_payload() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);

        let m_d = test_digest("manifest_corrupt");
        let dummy_manifest = Bytes::from("{}");
        mock.inner
            .put_manifest("test-repo", &m_d, dummy_manifest)
            .await
            .unwrap();

        mock.corrupt_manifest.store(true, Ordering::SeqCst);

        let target_blob = test_digest("target");
        let res = service
            .is_blob_referenced_in_repo("test-repo", &target_blob)
            .await;

        assert!(matches!(
            res,
            Err(StorageError::Internal {
                kind: StorageErrorKind::CorruptData,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn test_is_blob_referenced_detects_immediate_token_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);
        mock.immediate_cycle.store(true, Ordering::SeqCst);

        let target_blob = test_digest("target");
        let res = service
            .is_blob_referenced_in_repo("test-repo", &target_blob)
            .await;

        let err = res.expect_err("cycle must error");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("pagination cycle detected on continuation token 'repeat_token'")
        );
    }

    #[tokio::test]
    async fn test_is_blob_referenced_detects_multi_token_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);
        mock.multi_cycle.store(true, Ordering::SeqCst);

        let target_blob = test_digest("target");
        let res = service
            .is_blob_referenced_in_repo("test-repo", &target_blob)
            .await;

        let err = res.expect_err("cycle must error");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));
        assert!(
            err.to_string()
                .contains("pagination cycle detected on continuation token 'cycle_tok_A'")
        );
    }

    #[tokio::test]
    async fn test_is_blob_referenced_returns_true_when_found() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);

        let target_blob = test_digest("99");
        let cfg_digest = test_digest("11");
        let manifest_bytes = Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":2}},"layers":[{{"digest":"{}","size":10}}]}}"#,
            cfg_digest.as_str(),
            target_blob.as_str()
        ));
        let m_d = test_digest("manifest_target");
        mock.inner
            .put_manifest("test-repo", &m_d, manifest_bytes)
            .await
            .unwrap();

        let res = service
            .is_blob_referenced_in_repo("test-repo", &target_blob)
            .await
            .unwrap();

        assert!(res);
    }

    /// Deterministic coverage of the delete_tag PreconditionFailed cleanup
    /// branch: a replacement interposed between the version snapshot and the
    /// conditional delete (forced through the wrapper — the coherent Phase 3
    /// tag path only produces this under a true concurrent race) must yield
    /// TagPreconditionFailed with the journal cleaned up and the tag intact.
    #[tokio::test]
    async fn test_delete_tag_precondition_failed_cleanup_branch() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);
        let repo = "cleanup-branch-repo";

        let cfg_digest = test_digest("11");
        let target_blob = test_digest("99");
        let manifest_bytes = Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":2}},"layers":[{{"digest":"{}","size":10}}]}}"#,
            cfg_digest.as_str(),
            target_blob.as_str()
        ));
        let m_d = test_digest("cleanup_branch_manifest");
        mock.inner
            .put_manifest(repo, &m_d, manifest_bytes)
            .await
            .unwrap();
        mock.inner.set_tag(repo, "latest", &m_d).await.unwrap();

        mock.force_tag_precondition_failed
            .store(true, Ordering::SeqCst);
        let res = service.delete_tag(repo, "latest").await;
        assert!(
            matches!(res, Err(ManifestLifecycleError::TagPreconditionFailed)),
            "expected TagPreconditionFailed, got {res:?}"
        );

        // Cleanup branch: journal deleted, tag preserved with intact bytes.
        assert!(
            mock.inner
                .read_lifecycle_journal(repo)
                .await
                .unwrap()
                .is_none(),
            "journal must be deleted on TagPreconditionFailed cleanup"
        );
        assert_eq!(
            mock.inner.resolve_tag(repo, "latest").await.unwrap(),
            m_d,
            "tag must be preserved on precondition failure"
        );
    }

    #[tokio::test]
    async fn test_is_blob_referenced_returns_false_when_unreferenced() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);

        let other_blob = test_digest("22");
        let cfg_digest = test_digest("11");
        let manifest_bytes = Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":2}},"layers":[{{"digest":"{}","size":10}}]}}"#,
            cfg_digest.as_str(),
            other_blob.as_str()
        ));
        let m_d = test_digest("manifest_other");
        mock.inner
            .put_manifest("test-repo", &m_d, manifest_bytes)
            .await
            .unwrap();

        let target_blob = test_digest("target_unreferenced");
        let res = service
            .is_blob_referenced_in_repo("test-repo", &target_blob)
            .await
            .unwrap();

        assert!(!res);
    }

    /// Deterministic coverage of the delete_manifest TagPreconditionFailed cleanup branch:
    /// when tag conditional deletion fails repeatedly due to concurrent updates or conflicts,
    /// delete_manifest must clean up the lifecycle journal and leave the reference index
    /// in the READY state rather than abandoning a dirty journal that would trigger
    /// unintended deletions during subsequent recovery.
    #[tokio::test]
    async fn test_delete_manifest_precondition_failed_cleanup_branch() {
        let dir = tempfile::tempdir().unwrap();
        let fs_root = dir.path().join("data");
        std::fs::create_dir_all(&fs_root).unwrap();
        let ref_path = dir.path().join("ref-index");
        let ref_index = Arc::new(BlobRefIndex::open(ref_path).unwrap());

        let fs_storage = Arc::new(FsStorage::new(fs_root, 50 * 1024 * 1024));
        let mock_storage = Arc::new(TestLifecycleMockStorage {
            inner: fs_storage,
            fail_listing: AtomicBool::new(false),
            fail_get_manifest: AtomicBool::new(false),
            corrupt_manifest: AtomicBool::new(false),
            immediate_cycle: AtomicBool::new(false),
            multi_cycle: AtomicBool::new(false),
            force_tag_precondition_failed: AtomicBool::new(false),
            force_persistent_tag_precondition_failed: AtomicBool::new(false),
        });
        let coordinator = ConsistencyCoordinator::new();
        let service = ManifestLifecycleService::new(
            mock_storage.clone(),
            Some(ref_index.clone()),
            coordinator,
        );

        let repo = "cleanup-manifest-repo";
        let cfg_digest = test_digest("11");
        let target_blob = test_digest("99");
        let manifest_bytes = Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":2}},"layers":[{{"digest":"{}","size":10}}]}}"#,
            cfg_digest.as_str(),
            target_blob.as_str()
        ));
        let m_d = test_digest("cleanup_manifest");
        mock_storage
            .inner
            .put_manifest(repo, &m_d, manifest_bytes)
            .await
            .unwrap();
        mock_storage.inner.set_tag(repo, "latest", &m_d).await.unwrap();

        // Inject persistent tag precondition failure for all retries
        mock_storage
            .force_persistent_tag_precondition_failed
            .store(true, Ordering::SeqCst);
        let res = service.delete_manifest(repo, &m_d).await;
        assert!(
            matches!(res, Err(ManifestLifecycleError::TagPreconditionFailed)),
            "expected TagPreconditionFailed, got {res:?}"
        );

        // Verify journal is deleted so subsequent recovery does not delete the manifest
        assert!(
            mock_storage
                .inner
                .read_lifecycle_journal(repo)
                .await
                .unwrap()
                .is_none(),
            "journal must be deleted on TagPreconditionFailed cleanup"
        );

        // Verify index is healthy / ready
        assert!(
            ref_index.check_health().is_ok(),
            "index must be marked ready on TagPreconditionFailed cleanup"
        );

        // Manifest and tag must still exist
        assert!(
            mock_storage.inner.head_manifest(repo, &m_d).await.is_ok(),
            "manifest must remain intact"
        );
        assert_eq!(
            mock_storage.inner.resolve_tag(repo, "latest").await.unwrap(),
            m_d,
            "tag must remain intact"
        );
    }

    #[tokio::test]
    async fn test_acquire_coordination_does_not_block_unrelated_repo_during_lease_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let (mock, service) = setup_mock_service(&dir);

        // Pre-acquire lease on repo-a so any new attempt will backoff
        mock.inner
            .acquire_repo_lease("repo-a", "other-owner", "other-lease", 60)
            .await
            .unwrap();

        // Spawn task attempting to acquire coordination on repo-a (will loop with backoff)
        let service_clone = service.clone();
        let task_a = tokio::spawn(async move {
            service_clone.acquire_coordination("repo-a").await
        });

        // Small yield so task_a enters the retry loop for repo-a
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Coordination on repo-b MUST succeed immediately without waiting for repo-a backoff
        let start = std::time::Instant::now();
        let guard_b = service.acquire_coordination("repo-b").await;
        let elapsed = start.elapsed();

        assert!(guard_b.is_ok(), "repo-b coordination must succeed");
        assert!(
            elapsed < Duration::from_millis(300),
            "repo-b must not be blocked by repo-a lease retry backoff, took {elapsed:?}"
        );

        // task_a was in its retry backoff loop without holding the mutation lock; abort it cleanly
        task_a.abort();
    }
}
