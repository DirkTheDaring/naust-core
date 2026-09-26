use crate::registry::digest::Digest;
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;
use std::{pin::Pin, sync::Arc};
use thiserror::Error;
use tokio::io::AsyncRead;

// `pub` for the server composition root (storage wiring); curated in plan Phase 3.
pub mod facade;
pub mod fs;
pub(crate) mod journal_domain;
pub(crate) mod manifest_domain;
pub(crate) mod membership_domain;
pub mod mutation_authority;
pub mod ports;
pub(crate) mod referrer_domain;
pub mod repo_membership;
pub(crate) mod repo_timestamp_domain;
pub mod s3;
pub(crate) mod store_common;
pub(crate) mod tag_domain;
pub mod upload_session;

#[allow(unused_imports)]
pub use mutation_authority::*;
pub use ports::*;
pub use repo_membership::*;
pub use upload_session::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageErrorKind {
    /// Low-level filesystem or local operating system I/O failure (e.g. read, write, rename, open, mkdir).
    Io,
    /// Remote storage service, network transport, or SDK communication failure.
    Backend,
    /// Permission or access denied by the operating system or storage backend (e.g. HTTP 403, EACCES).
    PermissionDenied,
    /// Corrupt, unparseable, or malformed data stored in the repository, index, or metadata.
    CorruptData,
    /// Serialization failure when preparing in-memory structures for storage.
    Serialization,
    /// Invalid storage configuration or unsupported backend capability (e.g. bucket versioning incompatible with GC).
    Configuration,
    /// Concurrency or precondition conflict on storage resources (e.g. CAS ETag mismatch, active lease conflict).
    Conflict,
    /// Internal invariant violation or inconsistent state-machine transition in registry logic.
    InternalInvariant,
}

impl std::fmt::Display for StorageErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => write!(f, "io"),
            Self::Backend => write!(f, "backend"),
            Self::PermissionDenied => write!(f, "permission_denied"),
            Self::CorruptData => write!(f, "corrupt_data"),
            Self::Serialization => write!(f, "serialization"),
            Self::Configuration => write!(f, "configuration"),
            Self::Conflict => write!(f, "conflict"),
            Self::InternalInvariant => write!(f, "internal_invariant"),
        }
    }
}

#[derive(Clone, Debug, Error)]
pub enum StorageError {
    #[error("not found")]
    NotFound,

    #[error("digest mismatch")]
    DigestMismatch,

    #[error("unsupported")]
    Unsupported,

    #[error("too large")]
    TooLarge,

    #[error("insufficient storage")]
    InsufficientStorage,

    #[error("tag already exists")]
    TagAlreadyExists,

    #[error("precondition failed")]
    PreconditionFailed,

    #[error("exclusive writer lock held by another deployment/instance: {0}")]
    ExclusiveWriterLocked(String),

    #[error("invalid repository name: {0}")]
    InvalidRepoName(String),

    #[error("migration required: {0}")]
    MigrationRequired(String),

    #[error("internal error: {message}")]
    Internal {
        kind: StorageErrorKind,
        message: String,
    },
}

impl StorageError {
    #[inline]
    pub fn internal(kind: StorageErrorKind, message: impl Into<String>) -> Self {
        Self::Internal {
            kind,
            message: message.into(),
        }
    }

    #[inline]
    pub fn io(err: impl std::fmt::Display) -> Self {
        Self::Internal {
            kind: StorageErrorKind::Io,
            message: err.to_string(),
        }
    }

    #[inline]
    pub fn backend(err: impl std::fmt::Display) -> Self {
        Self::Internal {
            kind: StorageErrorKind::Backend,
            message: err.to_string(),
        }
    }

    #[inline]
    pub fn corrupt_data(err: impl std::fmt::Display) -> Self {
        Self::Internal {
            kind: StorageErrorKind::CorruptData,
            message: err.to_string(),
        }
    }

    #[inline]
    pub fn serialization(err: impl std::fmt::Display) -> Self {
        Self::Internal {
            kind: StorageErrorKind::Serialization,
            message: err.to_string(),
        }
    }

    #[inline]
    pub fn configuration(err: impl std::fmt::Display) -> Self {
        Self::Internal {
            kind: StorageErrorKind::Configuration,
            message: err.to_string(),
        }
    }

    #[inline]
    pub fn conflict(err: impl std::fmt::Display) -> Self {
        Self::Internal {
            kind: StorageErrorKind::Conflict,
            message: err.to_string(),
        }
    }

    #[inline]
    pub fn internal_invariant(err: impl std::fmt::Display) -> Self {
        Self::Internal {
            kind: StorageErrorKind::InternalInvariant,
            message: err.to_string(),
        }
    }

    #[inline]
    pub fn permission_denied(err: impl std::fmt::Display) -> Self {
        Self::Internal {
            kind: StorageErrorKind::PermissionDenied,
            message: err.to_string(),
        }
    }

    #[inline]
    pub fn internal_kind(&self) -> Option<StorageErrorKind> {
        match self {
            Self::Internal { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    #[inline]
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Internal { message, .. } => Some(message.as_str()),
            Self::ExclusiveWriterLocked(msg) => Some(msg.as_str()),
            Self::InvalidRepoName(msg) => Some(msg.as_str()),
            Self::MigrationRequired(msg) => Some(msg.as_str()),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagMutationPolicy {
    CreateOnly,
    Replace,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TagMutation {
    Created,
    Unchanged,
    Replaced { previous: Digest },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobMeta {
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestMeta {
    pub size: u64,
    pub media_type: String,
}

#[derive(Clone, Debug)]
pub struct UploadMeta {
    pub uuid: String,
    pub offset: u64,
}

#[derive(Clone, Debug, Default)]
pub struct RepoTimestamps {
    pub last_tag_update: Option<SystemTime>,
    pub last_manifest_update: Option<SystemTime>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionalDeleteResult {
    Deleted,
    NotFound,
    PreconditionFailed { current_version: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobObjectVersion(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcCursor(pub String);

#[derive(Clone, Debug)]
pub struct GcBlobCandidate {
    pub digest: Digest,
    pub size: u64,
    pub last_modified: SystemTime,
    pub version: BlobObjectVersion,
}

#[derive(Clone, Debug)]
pub struct GcBlobPage {
    pub items: Vec<GcBlobCandidate>,
    pub next_cursor: Option<GcCursor>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcDeleteResult {
    Deleted,
    NotFound,
    PreconditionFailed {
        current_version: Option<BlobObjectVersion>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcQuarantineResult {
    Quarantined {
        size: u64,
    },
    Skipped,
    /// The current object no longer matches the version the GC candidate was
    /// based on (stale candidate). The live object is left untouched — the
    /// quarantine analogue of [`GcDeleteResult::PreconditionFailed`].
    PreconditionFailed {
        current_version: Option<BlobObjectVersion>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GcStorageStrategy {
    FilesystemQuarantine,
    S3DirectConditional,
}

#[async_trait]
pub trait GcStorage: Send + Sync {
    /// Checks whether bucket versioning capabilities allow physical GC.
    /// Fails closed if versioning is Enabled, Suspended, Unknown, or Permission Denied.
    async fn check_bucket_versioning_for_gc(&self) -> Result<(), StorageError> {
        Ok(())
    }

    async fn list_cas_blobs_page(
        &self,
        _cursor: Option<&GcCursor>,
        _limit: usize,
    ) -> Result<GcBlobPage, StorageError> {
        Ok(GcBlobPage {
            items: Vec::new(),
            next_cursor: None,
        })
    }

    async fn quarantine_blob(
        &self,
        _permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        _digest: &Digest,
        _version: &BlobObjectVersion,
    ) -> Result<GcQuarantineResult, StorageError> {
        Ok(GcQuarantineResult::Skipped)
    }

    async fn restore_quarantined_blob(
        &self,
        _permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        _digest: &Digest,
    ) -> Result<Option<u64>, StorageError> {
        Ok(None)
    }

    async fn quarantined_blob_version(
        &self,
        _digest: &Digest,
    ) -> Result<Option<BlobObjectVersion>, StorageError> {
        Ok(None)
    }

    async fn delete_blob_conditional(
        &self,
        _permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        _digest: &Digest,
        _version: Option<&BlobObjectVersion>,
    ) -> Result<GcDeleteResult, StorageError> {
        Ok(GcDeleteResult::NotFound)
    }

    fn gc_strategy(&self) -> GcStorageStrategy {
        GcStorageStrategy::FilesystemQuarantine
    }

    /// Discovers manifest references beneath the storage root if supported natively.
    /// Required trait method without default implementation.
    async fn discover_manifest_references(&self) -> Result<Option<HashSet<Digest>>, StorageError>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReferrerDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,
}

#[async_trait]
pub trait Storage:
    Send + Sync + UploadSessionStorage + RepositoryBlobMembershipStorage + GcStorage
{
    fn kind(&self) -> &'static str;

    // Best-effort listing of repositories known to the backend.
    // Returned names are in canonical OCI/Docker form, e.g. "org/repo".
    async fn list_repositories(&self) -> Result<Vec<String>, StorageError>;

    // Best-effort timestamp metadata for a repository.
    // - last_tag_update: latest modification in repo's tag pointers (often correlates with last push/tag)
    // - last_manifest_update: latest modification in repo's manifest blobs
    async fn repo_timestamps(&self, name: &str) -> Result<RepoTimestamps, StorageError>;

    /// Positively checks if the underlying storage contains any repository records,
    /// blobs, manifests, uploads, or membership markers. Fails closed on any I/O or S3 error.
    async fn is_storage_empty(&self) -> Result<bool, StorageError>;

    async fn head_blob(&self, digest: &Digest) -> Result<BlobMeta, StorageError>;

    async fn open_blob(
        &self,
        digest: &Digest,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError>;

    async fn resolve_tag(&self, name: &str, tag: &str) -> Result<Digest, StorageError>;

    async fn list_tags(&self, name: &str) -> Result<Vec<String>, StorageError>;

    async fn head_manifest(
        &self,
        name: &str,
        digest: &Digest,
    ) -> Result<ManifestMeta, StorageError>;

    async fn get_manifest(
        &self,
        name: &str,
        digest: &Digest,
    ) -> Result<(ManifestMeta, Bytes), StorageError>;

    async fn put_manifest(
        &self,
        name: &str,
        digest: &Digest,
        bytes: Bytes,
    ) -> Result<ManifestMeta, StorageError>;

    async fn set_tag(&self, name: &str, tag: &str, digest: &Digest) -> Result<(), StorageError>;

    async fn mutate_tag(
        &self,
        name: &str,
        tag: &str,
        digest: &Digest,
        policy: TagMutationPolicy,
    ) -> Result<TagMutation, StorageError>;

    async fn delete_tag(&self, name: &str, tag: &str) -> Result<(), StorageError>;

    /// Bounded pagination of stored manifest digests in a repository.
    async fn list_manifest_digests_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<Digest>, Option<String>), StorageError>;

    /// Bounded pagination of tags and their target digests in a repository.
    async fn list_tags_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError>;

    /// Bounded pagination of referrers for a subject in a repository.
    async fn list_referrers_page(
        &self,
        repo: &str,
        subject: &Digest,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<ReferrerDescriptor>, Option<String>), StorageError>;

    /// Retrieve a tag's target digest along with its backend version/ETag.
    async fn get_tag_with_version(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<Option<(Digest, String)>, StorageError>;

    /// Conditionally delete a tag if its version matches (or unconditionally if expected_version is None).
    async fn delete_tag_conditional(
        &self,
        repo: &str,
        tag: &str,
        expected_version: Option<&str>,
    ) -> Result<ConditionalDeleteResult, StorageError>;

    /// Reads the durable lifecycle journal for a repository if present.
    async fn read_lifecycle_journal(&self, repo: &str) -> Result<Option<Bytes>, StorageError>;

    /// Durably writes the lifecycle journal for a repository.
    async fn write_lifecycle_journal(&self, repo: &str, data: Bytes) -> Result<(), StorageError>;

    /// Deletes the durable lifecycle journal for a repository.
    async fn delete_lifecycle_journal(&self, repo: &str) -> Result<(), StorageError>;

    /// Acquires an exclusive repository lease (on S3 via conditional lease object; on FS via OS file lock).
    async fn acquire_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
        ttl_secs: u64,
    ) -> Result<bool, StorageError>;

    /// Renews an active repository lease.
    async fn renew_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
        ttl_secs: u64,
    ) -> Result<bool, StorageError>;

    /// Releases an active repository lease.
    async fn release_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
    ) -> Result<(), StorageError>;

    /// Acquires a deployment-wide exclusive writer lock with structured ownership metadata.
    async fn acquire_deployment_writer_lock(
        &self,
        _doc: &mutation_authority::DeploymentWriterLockDoc,
    ) -> Result<(bool, Option<String>), StorageError> {
        Ok((true, None))
    }

    /// Conditionally releases a deployment-wide exclusive writer lock upon clean shutdown.
    async fn release_deployment_writer_lock(
        &self,
        _doc: &mutation_authority::DeploymentWriterLockDoc,
        _expected_etag: Option<&str>,
    ) -> Result<bool, StorageError> {
        Ok(true)
    }

    /// Inspects the deployment writer lock without mutating it.
    async fn inspect_deployment_writer_lock(
        &self,
    ) -> Result<Option<(mutation_authority::DeploymentWriterLockDoc, Option<String>)>, StorageError>
    {
        Ok(None)
    }

    /// Administratively clears an abandoned deployment writer lock matching expected owner and ETag.
    async fn admin_clear_deployment_writer_lock(
        &self,
        _expected_owner: &str,
        _expected_etag: &str,
    ) -> Result<(), StorageError> {
        Ok(())
    }

    async fn create_upload(&self) -> Result<UploadMeta, StorageError>;

    async fn upload_status(&self, uuid: &str) -> Result<UploadMeta, StorageError>;

    async fn append_upload(&self, uuid: &str, chunk: Bytes) -> Result<UploadMeta, StorageError>;

    async fn finalize_upload(&self, uuid: &str, digest: &Digest) -> Result<BlobMeta, StorageError>;

    // Best-effort cleanup for failed/abandoned uploads.
    async fn abort_upload(&self, uuid: &str) -> Result<(), StorageError>;

    // Content Discovery: referrers API.
    async fn list_referrers(
        &self,
        name: &str,
        subject: &Digest,
    ) -> Result<Vec<ReferrerDescriptor>, StorageError>;

    async fn add_referrer(
        &self,
        name: &str,
        subject: &Digest,
        descriptor: ReferrerDescriptor,
    ) -> Result<(), StorageError>;

    async fn remove_referrer(
        &self,
        name: &str,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<(), StorageError>;

    // Content Management: manifest deletion.
    async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), StorageError>;
}

#[async_trait]
impl<T: ?Sized + GcStorage + Send + Sync> GcStorage for Arc<T> {
    async fn check_bucket_versioning_for_gc(&self) -> Result<(), StorageError> {
        (**self).check_bucket_versioning_for_gc().await
    }
    async fn list_cas_blobs_page(
        &self,
        cursor: Option<&GcCursor>,
        limit: usize,
    ) -> Result<GcBlobPage, StorageError> {
        (**self).list_cas_blobs_page(cursor, limit).await
    }
    async fn quarantine_blob(
        &self,
        permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        digest: &Digest,
        version: &BlobObjectVersion,
    ) -> Result<GcQuarantineResult, StorageError> {
        (**self).quarantine_blob(permit, digest, version).await
    }
    async fn restore_quarantined_blob(
        &self,
        permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        digest: &Digest,
    ) -> Result<Option<u64>, StorageError> {
        (**self).restore_quarantined_blob(permit, digest).await
    }
    async fn quarantined_blob_version(
        &self,
        digest: &Digest,
    ) -> Result<Option<BlobObjectVersion>, StorageError> {
        (**self).quarantined_blob_version(digest).await
    }
    async fn delete_blob_conditional(
        &self,
        permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        digest: &Digest,
        version: Option<&BlobObjectVersion>,
    ) -> Result<GcDeleteResult, StorageError> {
        (**self)
            .delete_blob_conditional(permit, digest, version)
            .await
    }
    fn gc_strategy(&self) -> GcStorageStrategy {
        (**self).gc_strategy()
    }
    async fn discover_manifest_references(&self) -> Result<Option<HashSet<Digest>>, StorageError> {
        (**self).discover_manifest_references().await
    }
}

#[async_trait]
impl<T: ?Sized + Storage + Send + Sync> Storage for Arc<T> {
    fn kind(&self) -> &'static str {
        (**self).kind()
    }
    async fn list_repositories(&self) -> Result<Vec<String>, StorageError> {
        (**self).list_repositories().await
    }
    async fn repo_timestamps(&self, name: &str) -> Result<RepoTimestamps, StorageError> {
        (**self).repo_timestamps(name).await
    }
    async fn is_storage_empty(&self) -> Result<bool, StorageError> {
        (**self).is_storage_empty().await
    }
    async fn head_blob(&self, digest: &Digest) -> Result<BlobMeta, StorageError> {
        (**self).head_blob(digest).await
    }
    async fn open_blob(
        &self,
        digest: &Digest,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError> {
        (**self).open_blob(digest).await
    }
    async fn resolve_tag(&self, name: &str, tag: &str) -> Result<Digest, StorageError> {
        (**self).resolve_tag(name, tag).await
    }
    async fn list_tags(&self, name: &str) -> Result<Vec<String>, StorageError> {
        (**self).list_tags(name).await
    }
    async fn head_manifest(
        &self,
        name: &str,
        digest: &Digest,
    ) -> Result<ManifestMeta, StorageError> {
        (**self).head_manifest(name, digest).await
    }
    async fn get_manifest(
        &self,
        name: &str,
        digest: &Digest,
    ) -> Result<(ManifestMeta, Bytes), StorageError> {
        (**self).get_manifest(name, digest).await
    }
    async fn put_manifest(
        &self,
        name: &str,
        digest: &Digest,
        bytes: Bytes,
    ) -> Result<ManifestMeta, StorageError> {
        (**self).put_manifest(name, digest, bytes).await
    }
    async fn set_tag(&self, name: &str, tag: &str, digest: &Digest) -> Result<(), StorageError> {
        (**self).set_tag(name, tag, digest).await
    }
    async fn mutate_tag(
        &self,
        name: &str,
        tag: &str,
        digest: &Digest,
        policy: TagMutationPolicy,
    ) -> Result<TagMutation, StorageError> {
        (**self).mutate_tag(name, tag, digest, policy).await
    }
    async fn delete_tag(&self, name: &str, tag: &str) -> Result<(), StorageError> {
        (**self).delete_tag(name, tag).await
    }
    async fn list_manifest_digests_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<Digest>, Option<String>), StorageError> {
        (**self)
            .list_manifest_digests_page(repo, continuation_token, page_limit)
            .await
    }
    async fn list_tags_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
        (**self)
            .list_tags_page(repo, continuation_token, page_limit)
            .await
    }
    async fn list_referrers_page(
        &self,
        repo: &str,
        subject: &Digest,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<ReferrerDescriptor>, Option<String>), StorageError> {
        (**self)
            .list_referrers_page(repo, subject, continuation_token, page_limit)
            .await
    }
    async fn get_tag_with_version(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<Option<(Digest, String)>, StorageError> {
        (**self).get_tag_with_version(repo, tag).await
    }
    async fn delete_tag_conditional(
        &self,
        repo: &str,
        tag: &str,
        expected_version: Option<&str>,
    ) -> Result<ConditionalDeleteResult, StorageError> {
        (**self)
            .delete_tag_conditional(repo, tag, expected_version)
            .await
    }
    async fn read_lifecycle_journal(&self, repo: &str) -> Result<Option<Bytes>, StorageError> {
        (**self).read_lifecycle_journal(repo).await
    }
    async fn write_lifecycle_journal(&self, repo: &str, data: Bytes) -> Result<(), StorageError> {
        (**self).write_lifecycle_journal(repo, data).await
    }
    async fn delete_lifecycle_journal(&self, repo: &str) -> Result<(), StorageError> {
        (**self).delete_lifecycle_journal(repo).await
    }
    async fn acquire_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
        ttl_secs: u64,
    ) -> Result<bool, StorageError> {
        (**self)
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
        (**self)
            .renew_repo_lease(repo, owner_id, lease_id, ttl_secs)
            .await
    }
    async fn release_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
    ) -> Result<(), StorageError> {
        (**self).release_repo_lease(repo, owner_id, lease_id).await
    }
    async fn acquire_deployment_writer_lock(
        &self,
        doc: &mutation_authority::DeploymentWriterLockDoc,
    ) -> Result<(bool, Option<String>), StorageError> {
        (**self).acquire_deployment_writer_lock(doc).await
    }
    async fn release_deployment_writer_lock(
        &self,
        doc: &mutation_authority::DeploymentWriterLockDoc,
        expected_etag: Option<&str>,
    ) -> Result<bool, StorageError> {
        (**self)
            .release_deployment_writer_lock(doc, expected_etag)
            .await
    }
    async fn inspect_deployment_writer_lock(
        &self,
    ) -> Result<Option<(mutation_authority::DeploymentWriterLockDoc, Option<String>)>, StorageError>
    {
        (**self).inspect_deployment_writer_lock().await
    }
    async fn admin_clear_deployment_writer_lock(
        &self,
        expected_owner: &str,
        expected_etag: &str,
    ) -> Result<(), StorageError> {
        (**self)
            .admin_clear_deployment_writer_lock(expected_owner, expected_etag)
            .await
    }
    async fn create_upload(&self) -> Result<UploadMeta, StorageError> {
        (**self).create_upload().await
    }
    async fn upload_status(&self, uuid: &str) -> Result<UploadMeta, StorageError> {
        (**self).upload_status(uuid).await
    }
    async fn append_upload(&self, uuid: &str, chunk: Bytes) -> Result<UploadMeta, StorageError> {
        (**self).append_upload(uuid, chunk).await
    }
    async fn finalize_upload(&self, uuid: &str, digest: &Digest) -> Result<BlobMeta, StorageError> {
        (**self).finalize_upload(uuid, digest).await
    }
    async fn abort_upload(&self, uuid: &str) -> Result<(), StorageError> {
        (**self).abort_upload(uuid).await
    }
    async fn list_referrers(
        &self,
        name: &str,
        subject: &Digest,
    ) -> Result<Vec<ReferrerDescriptor>, StorageError> {
        (**self).list_referrers(name, subject).await
    }
    async fn add_referrer(
        &self,
        name: &str,
        subject: &Digest,
        descriptor: ReferrerDescriptor,
    ) -> Result<(), StorageError> {
        (**self).add_referrer(name, subject, descriptor).await
    }
    async fn remove_referrer(
        &self,
        name: &str,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<(), StorageError> {
        (**self).remove_referrer(name, subject, referrer).await
    }
    async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), StorageError> {
        (**self).delete_manifest(name, digest).await
    }
}

pub(crate) fn ensure_dir(path: impl AsRef<std::path::Path>) -> Result<(), StorageError> {
    let p = path.as_ref();
    std::fs::create_dir_all(p).map_err(|err| {
        StorageError::io(format!(
            "failed to create storage dir {}: {err}",
            p.display()
        ))
    })
}

#[cfg(test)]
mod tests;
