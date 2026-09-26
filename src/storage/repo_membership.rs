use crate::registry::canonical_name::{CanonicalRepoName, RepoNameError};
use crate::registry::digest::Digest;
use crate::storage::StorageError;
use async_trait::async_trait;
use base64::prelude::*;
use serde::{Deserialize, Serialize};

pub const MEMBERSHIP_SCHEMA_VERSION: u32 = 1;
pub const MEMBERSHIP_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RepoKeyDecodeError {
    #[error("malformed base64 encoding: {0}")]
    MalformedEncoding(String),
    #[error("non-utf8 bytes in decoded repository key")]
    NonUtf8,
    #[error("decoded value violates repository grammar: {0}")]
    InvalidRepoName(#[from] RepoNameError),
    #[error("unsupported key version: {0}")]
    UnsupportedKeyVersion(String),
}

/// Encode canonical repository name into a collision-free, single-segment URL-safe base64 string.
pub(crate) fn encode_canonical_repo_key(repo: &CanonicalRepoName) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(repo.as_str().as_bytes())
}

/// Decode a base64 URL-safe repository key back to its canonical repository identity with classified errors.
pub(crate) fn decode_canonical_repo_key(
    encoded: &str,
) -> Result<CanonicalRepoName, RepoKeyDecodeError> {
    if encoded.is_empty() {
        return Err(RepoKeyDecodeError::MalformedEncoding(
            "empty encoded repository key".to_string(),
        ));
    }
    let bytes = BASE64_URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|e| RepoKeyDecodeError::MalformedEncoding(e.to_string()))?;
    let s = String::from_utf8(bytes).map_err(|_| RepoKeyDecodeError::NonUtf8)?;
    let canonical = CanonicalRepoName::parse(&s)?;
    Ok(canonical)
}

/// Returns the canonical relative storage path for a repository blob membership record.
pub(crate) fn canonical_repo_membership_relpath(
    repo: &CanonicalRepoName,
    digest: &Digest,
) -> String {
    format!(
        "repo-memberships/by-repo/{}/{}/{}.json",
        encode_canonical_repo_key(repo),
        digest.algorithm(),
        digest.hex()
    )
}

/// Returns the canonical relative storage prefix for all blob memberships of a specific repository.
pub(crate) fn canonical_repo_membership_prefix(repo: &CanonicalRepoName) -> String {
    format!(
        "repo-memberships/by-repo/{}/",
        encode_canonical_repo_key(repo)
    )
}

/// Returns the global root prefix for all repository blob memberships.
pub(crate) fn canonical_all_memberships_prefix() -> &'static str {
    "repo-memberships/by-repo/"
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MembershipProvenance {
    Upload,
    CrossMount { from_repo: CanonicalRepoName },
    Proxy,
    Migration,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MembershipState {
    Active,
    Candidate,
}

fn default_membership_state() -> MembershipState {
    MembershipState::Active
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoBlobMembershipRecord {
    pub schema_version: u32,
    pub repo: CanonicalRepoName,
    pub digest: Digest,
    pub created_at_unix_secs: u64,
    pub provenance: MembershipProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub format_version: u32,
    #[serde(default = "default_membership_state")]
    pub state: MembershipState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unreferenced_since_unix_secs: Option<u64>,
}

impl RepoBlobMembershipRecord {
    pub fn new_upload(repo: CanonicalRepoName, digest: Digest, session_id: Option<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            repo,
            digest,
            created_at_unix_secs: now,
            provenance: MembershipProvenance::Upload,
            session_id,
            format_version: MEMBERSHIP_FORMAT_VERSION,
            state: MembershipState::Active,
            unreferenced_since_unix_secs: None,
        }
    }

    pub fn new_cross_mount(
        repo: CanonicalRepoName,
        digest: Digest,
        from_repo: CanonicalRepoName,
    ) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            repo,
            digest,
            created_at_unix_secs: now,
            provenance: MembershipProvenance::CrossMount { from_repo },
            session_id: None,
            format_version: MEMBERSHIP_FORMAT_VERSION,
            state: MembershipState::Active,
            unreferenced_since_unix_secs: None,
        }
    }

    pub fn new_proxy(repo: CanonicalRepoName, digest: Digest) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            repo,
            digest,
            created_at_unix_secs: now,
            provenance: MembershipProvenance::Proxy,
            session_id: None,
            format_version: MEMBERSHIP_FORMAT_VERSION,
            state: MembershipState::Active,
            unreferenced_since_unix_secs: None,
        }
    }

    pub fn new_migration(repo: CanonicalRepoName, digest: Digest) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            repo,
            digest,
            created_at_unix_secs: now,
            provenance: MembershipProvenance::Migration,
            session_id: None,
            format_version: MEMBERSHIP_FORMAT_VERSION,
            state: MembershipState::Active,
            unreferenced_since_unix_secs: None,
        }
    }

    pub fn try_new_upload(
        repo: &str,
        digest: Digest,
        session_id: Option<String>,
    ) -> Result<Self, RepoNameError> {
        let canonical_repo = CanonicalRepoName::parse(repo)?;
        Ok(Self::new_upload(canonical_repo, digest, session_id))
    }

    pub fn try_new_cross_mount(
        repo: &str,
        digest: Digest,
        from_repo: &str,
    ) -> Result<Self, RepoNameError> {
        let canonical_repo = CanonicalRepoName::parse(repo)?;
        let canonical_from = CanonicalRepoName::parse(from_repo)?;
        Ok(Self::new_cross_mount(
            canonical_repo,
            digest,
            canonical_from,
        ))
    }

    pub fn try_new_proxy(repo: &str, digest: Digest) -> Result<Self, RepoNameError> {
        let canonical_repo = CanonicalRepoName::parse(repo)?;
        Ok(Self::new_proxy(canonical_repo, digest))
    }

    pub fn try_new_migration(repo: &str, digest: Digest) -> Result<Self, RepoNameError> {
        let canonical_repo = CanonicalRepoName::parse(repo)?;
        Ok(Self::new_migration(canonical_repo, digest))
    }

    pub fn mark_candidate(&mut self, since_unix_secs: u64) {
        self.state = MembershipState::Candidate;
        self.unreferenced_since_unix_secs = Some(since_unix_secs);
    }

    pub fn mark_active(&mut self) {
        self.state = MembershipState::Active;
        self.unreferenced_since_unix_secs = None;
    }
}

/// Dedicated storage capability for repository-scoped blob membership ledger.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationPhase {
    Uninitialized,
    Planning,
    Applying,
    Verifying,
    Ready,
    Failed,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationStats {
    pub repositories_scanned: usize,
    pub manifests_scanned: usize,
    pub memberships_created: usize,
    pub memberships_already_present: usize,
    pub legacy_markers_migrated: usize,
    pub legacy_markers_deleted: usize,
    pub unattributable_blobs_detected: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationCheckpointRecord {
    pub schema_version: u32,
    pub phase: MigrationPhase,
    pub owner_id: Option<String>,
    pub lease_expiry_unix_secs: Option<u64>,
    pub source_continuation_token: Option<String>,
    pub current_repository: Option<CanonicalRepoName>,
    pub current_cursor: Option<String>,
    pub stats: MigrationStats,
    pub started_unix_secs: u64,
    pub last_updated_unix_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_info: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_result: Option<bool>,
}

#[async_trait]
pub trait RepositoryBlobMembershipStorage: Send + Sync {
    /// Retrieve the authoritative repository-blob membership record if one exists.
    async fn get_repo_blob_membership(
        &self,
        _repo: &str,
        _digest: &Digest,
    ) -> Result<Option<RepoBlobMembershipRecord>, StorageError> {
        Ok(None)
    }

    /// Create or overwrite a repository-blob membership record.
    async fn link_repo_blob(&self, _record: &RepoBlobMembershipRecord) -> Result<(), StorageError> {
        Ok(())
    }

    /// Transition a membership record from Active to Candidate with an unreferenced timestamp.
    async fn set_membership_candidate(
        &self,
        _repo: &str,
        _digest: &Digest,
        _since_unix_secs: u64,
    ) -> Result<bool, StorageError> {
        Ok(false)
    }

    /// Transition a membership record from Candidate back to Active (clearing timestamp).
    async fn clear_membership_candidate(
        &self,
        _repo: &str,
        _digest: &Digest,
    ) -> Result<bool, StorageError> {
        Ok(false)
    }

    /// Unlink (delete) an existing repository-blob membership record.
    async fn unlink_repo_blob(&self, _repo: &str, _digest: &Digest) -> Result<bool, StorageError> {
        Ok(true)
    }

    /// List a bounded page of repository-blob memberships for a single repository.
    async fn list_repo_blob_memberships_page(
        &self,
        _repo: &str,
        _continuation_token: Option<&str>,
        _page_limit: usize,
    ) -> Result<(Vec<RepoBlobMembershipRecord>, Option<String>), StorageError> {
        Ok((Vec::new(), None))
    }

    /// List a bounded page of repository-blob memberships across ALL repositories globally.
    async fn list_all_repo_blob_memberships_page(
        &self,
        _continuation_token: Option<&str>,
        _page_limit: usize,
    ) -> Result<(Vec<RepoBlobMembershipRecord>, Option<String>), StorageError> {
        Ok((Vec::new(), None))
    }

    /// Count how many repositories currently have an active membership link for this digest.
    async fn count_repo_blob_memberships(&self, _digest: &Digest) -> Result<usize, StorageError> {
        Ok(0)
    }

    /// Check if the membership subsystem is initialized and ready.
    async fn is_membership_ready(&self) -> Result<bool, StorageError> {
        Ok(true)
    }

    /// Mark the membership subsystem as initialized and ready.
    async fn mark_membership_ready(&self) -> Result<(), StorageError> {
        Ok(())
    }

    /// Retrieve durable migration checkpoint record if present.
    async fn get_migration_checkpoint(
        &self,
    ) -> Result<Option<MigrationCheckpointRecord>, StorageError> {
        Ok(None)
    }

    /// Save durable migration checkpoint record.
    async fn save_migration_checkpoint(
        &self,
        _checkpoint: &MigrationCheckpointRecord,
    ) -> Result<(), StorageError> {
        Ok(())
    }
}

#[async_trait]
impl<T: ?Sized + RepositoryBlobMembershipStorage + Send + Sync> RepositoryBlobMembershipStorage
    for std::sync::Arc<T>
{
    async fn get_repo_blob_membership(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<Option<RepoBlobMembershipRecord>, StorageError> {
        (**self).get_repo_blob_membership(repo, digest).await
    }

    async fn link_repo_blob(&self, record: &RepoBlobMembershipRecord) -> Result<(), StorageError> {
        (**self).link_repo_blob(record).await
    }

    async fn set_membership_candidate(
        &self,
        repo: &str,
        digest: &Digest,
        since_unix_secs: u64,
    ) -> Result<bool, StorageError> {
        (**self)
            .set_membership_candidate(repo, digest, since_unix_secs)
            .await
    }

    async fn clear_membership_candidate(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        (**self).clear_membership_candidate(repo, digest).await
    }

    async fn unlink_repo_blob(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError> {
        (**self).unlink_repo_blob(repo, digest).await
    }

    async fn list_repo_blob_memberships_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<RepoBlobMembershipRecord>, Option<String>), StorageError> {
        (**self)
            .list_repo_blob_memberships_page(repo, continuation_token, page_limit)
            .await
    }

    async fn list_all_repo_blob_memberships_page(
        &self,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<RepoBlobMembershipRecord>, Option<String>), StorageError> {
        (**self)
            .list_all_repo_blob_memberships_page(continuation_token, page_limit)
            .await
    }

    async fn count_repo_blob_memberships(&self, digest: &Digest) -> Result<usize, StorageError> {
        (**self).count_repo_blob_memberships(digest).await
    }

    async fn is_membership_ready(&self) -> Result<bool, StorageError> {
        (**self).is_membership_ready().await
    }

    async fn mark_membership_ready(&self) -> Result<(), StorageError> {
        (**self).mark_membership_ready().await
    }

    async fn get_migration_checkpoint(
        &self,
    ) -> Result<Option<MigrationCheckpointRecord>, StorageError> {
        (**self).get_migration_checkpoint().await
    }

    async fn save_migration_checkpoint(
        &self,
        checkpoint: &MigrationCheckpointRecord,
    ) -> Result<(), StorageError> {
        (**self).save_migration_checkpoint(checkpoint).await
    }
}
