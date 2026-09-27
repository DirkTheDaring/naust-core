use crate::registry::digest::Digest;
use crate::storage::mutation_authority::{DeploymentWriterLockDoc, GcMutationPermit};
use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
use crate::storage::upload_session::UploadSessionStorage;
use crate::storage::{
    BlobMeta, BlobObjectVersion, ConditionalDeleteResult, GcBlobPage, GcCursor, GcDeleteResult,
    GcQuarantineResult, GcStorageStrategy, ManifestMeta, ReferrerDescriptor, RepoTimestamps,
    StorageError, TagMutation, TagMutationPolicy, UploadMeta,
};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::AsyncRead;

/// Read-only CAS blob access and streaming port.
#[async_trait]
pub trait BlobCasReader: Send + Sync {
    async fn head_blob(&self, digest: &Digest) -> Result<BlobMeta, StorageError>;
    async fn open_blob(
        &self,
        digest: &Digest,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError>;

    /// Reads the inclusive span `[start, end_inclusive]`.
    ///
    /// `BlobMeta.size` is the full object size. The default opens the whole
    /// object and discards the prefix. Production filesystem and S3 readers
    /// override it.
    async fn open_blob_range(
        &self,
        digest: &Digest,
        start: u64,
        end_inclusive: u64,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError> {
        if start > end_inclusive {
            return Err(StorageError::backend("byte range exceeds object"));
        }
        let (meta, reader) = self.open_blob(digest).await?;
        if end_inclusive >= meta.size {
            return Err(StorageError::backend("byte range exceeds object"));
        }
        let length = end_inclusive - start + 1;
        let reader = crate::storage::span_reader(reader, start, length).await?;
        Ok((meta, reader))
    }
}

/// CAS blob upload and creation port.
#[async_trait]
pub trait BlobCasWriter: Send + Sync {
    async fn create_upload(&self) -> Result<UploadMeta, StorageError>;
    async fn upload_status(&self, uuid: &str) -> Result<UploadMeta, StorageError>;
    async fn append_upload(&self, uuid: &str, chunk: Bytes) -> Result<UploadMeta, StorageError>;
    async fn finalize_upload(&self, uuid: &str, digest: &Digest) -> Result<BlobMeta, StorageError>;
    async fn abort_upload(&self, uuid: &str) -> Result<(), StorageError>;
}

/// Read-only repository catalog and timestamp metadata port.
#[async_trait]
pub trait RepositoryCatalogReader: Send + Sync {
    async fn list_repositories(&self) -> Result<Vec<String>, StorageError>;
    async fn repo_timestamps(&self, name: &str) -> Result<RepoTimestamps, StorageError>;
}

/// Read-only manifest query and pagination port.
#[async_trait]
pub trait ManifestReader: Send + Sync {
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
    async fn list_manifest_digests_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<Digest>, Option<String>), StorageError>;
}

/// Manifest storage mutation port.
#[async_trait]
pub trait ManifestStore: ManifestReader + Send + Sync {
    async fn put_manifest(
        &self,
        name: &str,
        digest: &Digest,
        bytes: Bytes,
    ) -> Result<ManifestMeta, StorageError>;
    async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), StorageError>;
}

/// Read-only tag resolution and listing port.
#[async_trait]
pub trait TagReader: Send + Sync {
    async fn resolve_tag(&self, name: &str, tag: &str) -> Result<Digest, StorageError>;
    async fn list_tags(&self, name: &str) -> Result<Vec<String>, StorageError>;
    async fn list_tags_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError>;
    async fn get_tag_with_version(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<Option<(Digest, String)>, StorageError>;
}

/// Tag storage mutation port.
#[async_trait]
pub trait TagStore: TagReader + Send + Sync {
    async fn set_tag(&self, name: &str, tag: &str, digest: &Digest) -> Result<(), StorageError>;
    async fn mutate_tag(
        &self,
        name: &str,
        tag: &str,
        digest: &Digest,
        policy: TagMutationPolicy,
    ) -> Result<TagMutation, StorageError>;
    async fn delete_tag(&self, name: &str, tag: &str) -> Result<(), StorageError>;
    async fn delete_tag_conditional(
        &self,
        repo: &str,
        tag: &str,
        expected_version: Option<&str>,
    ) -> Result<ConditionalDeleteResult, StorageError>;
}

/// Read-only referrers discovery port.
#[async_trait]
pub trait ReferrersReader: Send + Sync {
    async fn list_referrers(
        &self,
        name: &str,
        subject: &Digest,
    ) -> Result<Vec<ReferrerDescriptor>, StorageError>;
    async fn list_referrers_page(
        &self,
        repo: &str,
        subject: &Digest,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<ReferrerDescriptor>, Option<String>), StorageError>;
}

/// Referrers storage mutation port.
#[async_trait]
pub trait ReferrersStore: ReferrersReader + Send + Sync {
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
}

/// Repository lifecycle WAL journal storage port.
#[async_trait]
pub trait LifecycleJournalStore: Send + Sync {
    async fn read_lifecycle_journal(&self, repo: &str) -> Result<Option<Bytes>, StorageError>;
    async fn write_lifecycle_journal(&self, repo: &str, data: Bytes) -> Result<(), StorageError>;
    async fn delete_lifecycle_journal(&self, repo: &str) -> Result<(), StorageError>;
}

/// Repository lease coordination storage port.
#[async_trait]
pub trait RepositoryLeaseStore: Send + Sync {
    async fn acquire_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
        ttl_secs: u64,
    ) -> Result<bool, StorageError>;
    async fn renew_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
        ttl_secs: u64,
    ) -> Result<bool, StorageError>;
    async fn release_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
    ) -> Result<(), StorageError>;
}

/// Deployment-wide cluster lock storage port.
#[async_trait]
pub trait ClusterLockStore: Send + Sync {
    async fn acquire_deployment_writer_lock(
        &self,
        doc: &DeploymentWriterLockDoc,
    ) -> Result<(bool, Option<String>), StorageError>;
    async fn release_deployment_writer_lock(
        &self,
        doc: &DeploymentWriterLockDoc,
        expected_etag: Option<&str>,
    ) -> Result<bool, StorageError>;
    async fn inspect_deployment_writer_lock(
        &self,
    ) -> Result<Option<(DeploymentWriterLockDoc, Option<String>)>, StorageError>;
    async fn admin_clear_deployment_writer_lock(
        &self,
        expected_owner: &str,
        expected_etag: &str,
    ) -> Result<(), StorageError>;
}

/// Garbage collection storage port.
#[async_trait]
pub trait GcStoragePort: Send + Sync {
    fn kind(&self) -> &'static str;
    fn gc_strategy(&self) -> GcStorageStrategy;
    async fn check_bucket_versioning_for_gc(&self) -> Result<(), StorageError>;
    async fn list_cas_blobs_page(
        &self,
        cursor: Option<&GcCursor>,
        limit: usize,
    ) -> Result<GcBlobPage, StorageError>;
    async fn quarantine_blob(
        &self,
        permit: &GcMutationPermit<'_>,
        digest: &Digest,
        version: &BlobObjectVersion,
    ) -> Result<GcQuarantineResult, StorageError>;
    async fn restore_quarantined_blob(
        &self,
        permit: &GcMutationPermit<'_>,
        digest: &Digest,
    ) -> Result<Option<u64>, StorageError>;
    async fn quarantined_blob_version(
        &self,
        digest: &Digest,
    ) -> Result<Option<BlobObjectVersion>, StorageError>;
    async fn delete_blob_conditional(
        &self,
        permit: &GcMutationPermit<'_>,
        digest: &Digest,
        version: Option<&BlobObjectVersion>,
    ) -> Result<GcDeleteResult, StorageError>;

    /// Port view forwarding native contained manifest reference discovery.
    /// Required trait method without default implementation.
    async fn discover_manifest_references(&self) -> Result<Option<HashSet<Digest>>, StorageError>;
}

/// Dedicated startup and readiness storage capability for whole-registry state inspection.
#[async_trait]
pub trait StorageReadinessInspector: Send + Sync {
    async fn is_storage_empty(&self) -> Result<bool, StorageError>;
}

// -----------------------------------------------------------------------------
// Focused Consumer Composite Ports
// -----------------------------------------------------------------------------

/// Minimum cohesive storage capability required by `BlobRefIndex`.
pub trait BlobRefIndexStoragePort:
    RepositoryCatalogReader + TagReader + ManifestReader + RepositoryBlobMembershipStorage + Send + Sync
{
}
impl<T: ?Sized> BlobRefIndexStoragePort for T where
    T: RepositoryCatalogReader
        + TagReader
        + ManifestReader
        + RepositoryBlobMembershipStorage
        + Send
        + Sync
{
}

/// Minimum cohesive storage capability required by `BlobUploadCoordinator`.
pub trait BlobUploadCoordinatorStoragePort:
    UploadSessionStorage
    + RepositoryBlobMembershipStorage
    + BlobCasReader
    + BlobCasWriter
    + BlobRefIndexStoragePort
    + Send
    + Sync
{
}
impl<T: ?Sized> BlobUploadCoordinatorStoragePort for T where
    T: UploadSessionStorage
        + RepositoryBlobMembershipStorage
        + BlobCasReader
        + BlobCasWriter
        + BlobRefIndexStoragePort
        + Send
        + Sync
{
}

/// Minimum cohesive storage capability required by `ProxyTarget`.
/// Cache-scoped physical eviction capability (remediation A3/R2, KI-02).
///
/// Deliberately permit-free, unlike `GcStoragePort`: the proxy cache store is
/// exclusively owned by this process (per-upstream roots/prefixes), so the
/// primary CAS's GC-vs-mutation permit protocol does not apply. Safety comes
/// from (a) version-conditional deletes on S3 (the enumerated ETag must still
/// match) and (b) POSIX unlink semantics on FS (a concurrently open read keeps
/// its handle; a later cache miss re-fetches from upstream).
#[async_trait]
pub trait CacheEvictionPort: Send + Sync {
    async fn list_cache_blobs_page(
        &self,
        cursor: Option<&GcCursor>,
        limit: usize,
    ) -> Result<GcBlobPage, StorageError>;

    /// Physically removes one cached blob. `version` is required on S3
    /// (conditional delete); on FS a `Some` version is validated against the
    /// live leaf before unlinking.
    async fn evict_cache_blob(
        &self,
        digest: &Digest,
        version: Option<&BlobObjectVersion>,
    ) -> Result<GcDeleteResult, StorageError>;
}

#[async_trait]
impl<T: ?Sized + CacheEvictionPort + Send + Sync> CacheEvictionPort for Arc<T> {
    async fn list_cache_blobs_page(
        &self,
        cursor: Option<&GcCursor>,
        limit: usize,
    ) -> Result<GcBlobPage, StorageError> {
        (**self).list_cache_blobs_page(cursor, limit).await
    }
    async fn evict_cache_blob(
        &self,
        digest: &Digest,
        version: Option<&BlobObjectVersion>,
    ) -> Result<GcDeleteResult, StorageError> {
        (**self).evict_cache_blob(digest, version).await
    }
}

pub trait ProxyStoragePort:
    BlobUploadCoordinatorStoragePort
    + BlobIndexStoragePort
    + ReferrersReader
    + CacheEvictionPort
    + Send
    + Sync
{
    fn as_blob_upload_coordinator_storage_port(&self) -> &dyn BlobUploadCoordinatorStoragePort;
    fn as_catalog_reader(&self) -> &dyn RepositoryCatalogReader;
    fn as_tag_reader(&self) -> &dyn TagReader;
    fn as_referrers_reader(&self) -> &dyn ReferrersReader;
    fn as_manifest_reader(&self) -> &dyn ManifestReader;
    fn as_blob_reader(&self) -> &dyn BlobCasReader;
}

impl<T> ProxyStoragePort for T
where
    T: BlobUploadCoordinatorStoragePort
        + BlobIndexStoragePort
        + ReferrersReader
        + CacheEvictionPort
        + Send
        + Sync,
{
    fn as_blob_upload_coordinator_storage_port(&self) -> &dyn BlobUploadCoordinatorStoragePort {
        self
    }
    fn as_catalog_reader(&self) -> &dyn RepositoryCatalogReader {
        self
    }
    fn as_tag_reader(&self) -> &dyn TagReader {
        self
    }
    fn as_referrers_reader(&self) -> &dyn ReferrersReader {
        self
    }
    fn as_manifest_reader(&self) -> &dyn ManifestReader {
        self
    }
    fn as_blob_reader(&self) -> &dyn BlobCasReader {
        self
    }
}

/// Minimum cohesive storage capability required by `ManifestLifecycleService`.
pub trait ManifestLifecycleStoragePort:
    ManifestStore
    + TagStore
    + ReferrersStore
    + RepositoryBlobMembershipStorage
    + LifecycleJournalStore
    + RepositoryLeaseStore
    + BlobRefIndexStoragePort
    + Send
    + Sync
{
}
impl<T: ?Sized> ManifestLifecycleStoragePort for T where
    T: ManifestStore
        + TagStore
        + ReferrersStore
        + RepositoryBlobMembershipStorage
        + LifecycleJournalStore
        + RepositoryLeaseStore
        + BlobRefIndexStoragePort
        + Send
        + Sync
{
}

/// Minimum cohesive storage capability required by `BlobDeleteService`.
pub trait BlobIndexStoragePort:
    RepositoryCatalogReader + TagReader + ManifestReader + Send + Sync
{
}
impl<T: ?Sized> BlobIndexStoragePort for T where
    T: RepositoryCatalogReader + TagReader + ManifestReader + Send + Sync
{
}

/// Minimum cohesive storage capability required by `GcService`.
pub trait GcServiceStoragePort:
    GcStoragePort
    + BlobRefIndexStoragePort
    + RepositoryBlobMembershipStorage
    + LifecycleJournalStore
    + Send
    + Sync
{
}
impl<T: ?Sized> GcServiceStoragePort for T where
    T: GcStoragePort
        + BlobRefIndexStoragePort
        + RepositoryBlobMembershipStorage
        + LifecycleJournalStore
        + Send
        + Sync
{
}

// -----------------------------------------------------------------------------
// Port Implementation Macros and Concrete Backend Implementations
// -----------------------------------------------------------------------------

#[macro_export]
macro_rules! impl_storage_ports {
    ($target:ty) => {
        #[async_trait::async_trait]
        impl $crate::storage::ports::BlobCasReader for $target {
            async fn head_blob(&self, digest: &$crate::registry::digest::Digest) -> Result<$crate::storage::BlobMeta, $crate::storage::StorageError> {
                $crate::storage::Storage::head_blob(self, digest).await
            }
            async fn open_blob(
                &self,
                digest: &$crate::registry::digest::Digest,
            ) -> Result<($crate::storage::BlobMeta, std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>), $crate::storage::StorageError> {
                $crate::storage::Storage::open_blob(self, digest).await
            }
            async fn open_blob_range(
                &self,
                digest: &$crate::registry::digest::Digest,
                start: u64,
                end_inclusive: u64,
            ) -> Result<($crate::storage::BlobMeta, std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>), $crate::storage::StorageError> {
                $crate::storage::Storage::open_blob_range(self, digest, start, end_inclusive).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::BlobCasWriter for $target {
            async fn create_upload(&self) -> Result<$crate::storage::UploadMeta, $crate::storage::StorageError> {
                $crate::storage::Storage::create_upload(self).await
            }
            async fn upload_status(&self, uuid: &str) -> Result<$crate::storage::UploadMeta, $crate::storage::StorageError> {
                $crate::storage::Storage::upload_status(self, uuid).await
            }
            async fn append_upload(&self, uuid: &str, chunk: bytes::Bytes) -> Result<$crate::storage::UploadMeta, $crate::storage::StorageError> {
                $crate::storage::Storage::append_upload(self, uuid, chunk).await
            }
            async fn finalize_upload(&self, uuid: &str, digest: &$crate::registry::digest::Digest) -> Result<$crate::storage::BlobMeta, $crate::storage::StorageError> {
                $crate::storage::Storage::finalize_upload(self, uuid, digest).await
            }
            async fn abort_upload(&self, uuid: &str) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::abort_upload(self, uuid).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::RepositoryCatalogReader for $target {
            async fn list_repositories(&self) -> Result<Vec<String>, $crate::storage::StorageError> {
                $crate::storage::Storage::list_repositories(self).await
            }
            async fn repo_timestamps(&self, name: &str) -> Result<$crate::storage::RepoTimestamps, $crate::storage::StorageError> {
                $crate::storage::Storage::repo_timestamps(self, name).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::StorageReadinessInspector for $target {
            async fn is_storage_empty(&self) -> Result<bool, $crate::storage::StorageError> {
                $crate::storage::Storage::is_storage_empty(self).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::ManifestReader for $target {
            async fn head_manifest(
                &self,
                name: &str,
                digest: &$crate::registry::digest::Digest,
            ) -> Result<$crate::storage::ManifestMeta, $crate::storage::StorageError> {
                $crate::storage::Storage::head_manifest(self, name, digest).await
            }
            async fn get_manifest(
                &self,
                name: &str,
                digest: &$crate::registry::digest::Digest,
            ) -> Result<($crate::storage::ManifestMeta, bytes::Bytes), $crate::storage::StorageError> {
                $crate::storage::Storage::get_manifest(self, name, digest).await
            }
            async fn list_manifest_digests_page(
                &self,
                repo: &str,
                continuation_token: Option<&str>,
                page_limit: usize,
            ) -> Result<(Vec<$crate::registry::digest::Digest>, Option<String>), $crate::storage::StorageError> {
                $crate::storage::Storage::list_manifest_digests_page(self, repo, continuation_token, page_limit).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::ManifestStore for $target {
            async fn put_manifest(
                &self,
                name: &str,
                digest: &$crate::registry::digest::Digest,
                bytes: bytes::Bytes,
            ) -> Result<$crate::storage::ManifestMeta, $crate::storage::StorageError> {
                $crate::storage::Storage::put_manifest(self, name, digest, bytes).await
            }
            async fn delete_manifest(&self, name: &str, digest: &$crate::registry::digest::Digest) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::delete_manifest(self, name, digest).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::TagReader for $target {
            async fn resolve_tag(&self, name: &str, tag: &str) -> Result<$crate::registry::digest::Digest, $crate::storage::StorageError> {
                $crate::storage::Storage::resolve_tag(self, name, tag).await
            }
            async fn list_tags(&self, name: &str) -> Result<Vec<String>, $crate::storage::StorageError> {
                $crate::storage::Storage::list_tags(self, name).await
            }
            async fn list_tags_page(
                &self,
                repo: &str,
                continuation_token: Option<&str>,
                page_limit: usize,
            ) -> Result<(Vec<(String, $crate::registry::digest::Digest)>, Option<String>), $crate::storage::StorageError> {
                $crate::storage::Storage::list_tags_page(self, repo, continuation_token, page_limit).await
            }
            async fn get_tag_with_version(
                &self,
                repo: &str,
                tag: &str,
            ) -> Result<Option<($crate::registry::digest::Digest, String)>, $crate::storage::StorageError> {
                $crate::storage::Storage::get_tag_with_version(self, repo, tag).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::TagStore for $target {
            async fn set_tag(&self, name: &str, tag: &str, digest: &$crate::registry::digest::Digest) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::set_tag(self, name, tag, digest).await
            }
            async fn mutate_tag(
                &self,
                name: &str,
                tag: &str,
                digest: &$crate::registry::digest::Digest,
                policy: $crate::storage::TagMutationPolicy,
            ) -> Result<$crate::storage::TagMutation, $crate::storage::StorageError> {
                $crate::storage::Storage::mutate_tag(self, name, tag, digest, policy).await
            }
            async fn delete_tag(&self, name: &str, tag: &str) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::delete_tag(self, name, tag).await
            }
            async fn delete_tag_conditional(
                &self,
                repo: &str,
                tag: &str,
                expected_version: Option<&str>,
            ) -> Result<$crate::storage::ConditionalDeleteResult, $crate::storage::StorageError> {
                $crate::storage::Storage::delete_tag_conditional(self, repo, tag, expected_version).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::ReferrersReader for $target {
            async fn list_referrers(
                &self,
                name: &str,
                subject: &$crate::registry::digest::Digest,
            ) -> Result<Vec<$crate::storage::ReferrerDescriptor>, $crate::storage::StorageError> {
                $crate::storage::Storage::list_referrers(self, name, subject).await
            }
            async fn list_referrers_page(
                &self,
                repo: &str,
                subject: &$crate::registry::digest::Digest,
                continuation_token: Option<&str>,
                page_limit: usize,
            ) -> Result<(Vec<$crate::storage::ReferrerDescriptor>, Option<String>), $crate::storage::StorageError> {
                $crate::storage::Storage::list_referrers_page(self, repo, subject, continuation_token, page_limit).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::ReferrersStore for $target {
            async fn add_referrer(
                &self,
                name: &str,
                subject: &$crate::registry::digest::Digest,
                descriptor: $crate::storage::ReferrerDescriptor,
            ) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::add_referrer(self, name, subject, descriptor).await
            }
            async fn remove_referrer(
                &self,
                name: &str,
                subject: &$crate::registry::digest::Digest,
                referrer: &$crate::registry::digest::Digest,
            ) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::remove_referrer(self, name, subject, referrer).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::LifecycleJournalStore for $target {
            async fn read_lifecycle_journal(&self, repo: &str) -> Result<Option<bytes::Bytes>, $crate::storage::StorageError> {
                $crate::storage::Storage::read_lifecycle_journal(self, repo).await
            }
            async fn write_lifecycle_journal(&self, repo: &str, data: bytes::Bytes) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::write_lifecycle_journal(self, repo, data).await
            }
            async fn delete_lifecycle_journal(&self, repo: &str) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::delete_lifecycle_journal(self, repo).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::RepositoryLeaseStore for $target {
            async fn acquire_repo_lease(
                &self,
                repo: &str,
                owner_id: &str,
                lease_id: &str,
                ttl_secs: u64,
            ) -> Result<bool, $crate::storage::StorageError> {
                $crate::storage::Storage::acquire_repo_lease(self, repo, owner_id, lease_id, ttl_secs).await
            }
            async fn renew_repo_lease(
                &self,
                repo: &str,
                owner_id: &str,
                lease_id: &str,
                ttl_secs: u64,
            ) -> Result<bool, $crate::storage::StorageError> {
                $crate::storage::Storage::renew_repo_lease(self, repo, owner_id, lease_id, ttl_secs).await
            }
            async fn release_repo_lease(
                &self,
                repo: &str,
                owner_id: &str,
                lease_id: &str,
            ) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::release_repo_lease(self, repo, owner_id, lease_id).await
            }
        }

        #[async_trait::async_trait]
        impl $crate::storage::ports::ClusterLockStore for $target {
            async fn acquire_deployment_writer_lock(
                &self,
                doc: &$crate::storage::mutation_authority::DeploymentWriterLockDoc,
            ) -> Result<(bool, Option<String>), $crate::storage::StorageError> {
                $crate::storage::Storage::acquire_deployment_writer_lock(self, doc).await
            }
            async fn release_deployment_writer_lock(
                &self,
                doc: &$crate::storage::mutation_authority::DeploymentWriterLockDoc,
                expected_etag: Option<&str>,
            ) -> Result<bool, $crate::storage::StorageError> {
                $crate::storage::Storage::release_deployment_writer_lock(self, doc, expected_etag).await
            }
            async fn inspect_deployment_writer_lock(
                &self,
            ) -> Result<Option<($crate::storage::mutation_authority::DeploymentWriterLockDoc, Option<String>)>, $crate::storage::StorageError> {
                $crate::storage::Storage::inspect_deployment_writer_lock(self).await
            }
            async fn admin_clear_deployment_writer_lock(
                &self,
                expected_owner: &str,
                expected_etag: &str,
            ) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::Storage::admin_clear_deployment_writer_lock(self, expected_owner, expected_etag).await
            }
        }
    };
}

#[macro_export]
macro_rules! impl_gc_storage_port {
    ($target:ty) => {
        #[async_trait::async_trait]
        impl $crate::storage::ports::GcStoragePort for $target {
            fn kind(&self) -> &'static str {
                $crate::storage::Storage::kind(self)
            }
            fn gc_strategy(&self) -> $crate::storage::GcStorageStrategy {
                $crate::storage::GcStorage::gc_strategy(self)
            }
            async fn check_bucket_versioning_for_gc(
                &self,
            ) -> Result<(), $crate::storage::StorageError> {
                $crate::storage::GcStorage::check_bucket_versioning_for_gc(self).await
            }
            async fn list_cas_blobs_page(
                &self,
                cursor: Option<&$crate::storage::GcCursor>,
                limit: usize,
            ) -> Result<$crate::storage::GcBlobPage, $crate::storage::StorageError> {
                $crate::storage::GcStorage::list_cas_blobs_page(self, cursor, limit).await
            }
            async fn quarantine_blob(
                &self,
                permit: &$crate::storage::mutation_authority::GcMutationPermit<'_>,
                digest: &$crate::registry::digest::Digest,
                version: &$crate::storage::BlobObjectVersion,
            ) -> Result<$crate::storage::GcQuarantineResult, $crate::storage::StorageError> {
                $crate::storage::GcStorage::quarantine_blob(self, permit, digest, version).await
            }
            async fn restore_quarantined_blob(
                &self,
                permit: &$crate::storage::mutation_authority::GcMutationPermit<'_>,
                digest: &$crate::registry::digest::Digest,
            ) -> Result<Option<u64>, $crate::storage::StorageError> {
                $crate::storage::GcStorage::restore_quarantined_blob(self, permit, digest).await
            }
            async fn quarantined_blob_version(
                &self,
                digest: &$crate::registry::digest::Digest,
            ) -> Result<Option<$crate::storage::BlobObjectVersion>, $crate::storage::StorageError>
            {
                $crate::storage::GcStorage::quarantined_blob_version(self, digest).await
            }
            async fn delete_blob_conditional(
                &self,
                permit: &$crate::storage::mutation_authority::GcMutationPermit<'_>,
                digest: &$crate::registry::digest::Digest,
                version: Option<&$crate::storage::BlobObjectVersion>,
            ) -> Result<$crate::storage::GcDeleteResult, $crate::storage::StorageError> {
                $crate::storage::GcStorage::delete_blob_conditional(self, permit, digest, version)
                    .await
            }
            async fn discover_manifest_references(
                &self,
            ) -> Result<
                Option<::std::collections::HashSet<$crate::registry::digest::Digest>>,
                $crate::storage::StorageError,
            > {
                $crate::storage::GcStorage::discover_manifest_references(self).await
            }
        }
    };
}

/// Delegating `CacheEvictionPort` for test doubles that already implement the
/// omnibus `GcStorage` (listing forwards; eviction is unsupported). The real
/// backends implement the port manually (contained unlink / conditional delete).
#[macro_export]
macro_rules! impl_cache_eviction_port {
    ($target:ty) => {
        #[async_trait::async_trait]
        impl $crate::storage::ports::CacheEvictionPort for $target {
            async fn list_cache_blobs_page(
                &self,
                cursor: Option<&$crate::storage::GcCursor>,
                limit: usize,
            ) -> Result<$crate::storage::GcBlobPage, $crate::storage::StorageError> {
                $crate::storage::GcStorage::list_cas_blobs_page(self, cursor, limit).await
            }
            async fn evict_cache_blob(
                &self,
                _digest: &$crate::registry::digest::Digest,
                _version: Option<&$crate::storage::BlobObjectVersion>,
            ) -> Result<$crate::storage::GcDeleteResult, $crate::storage::StorageError> {
                Err($crate::storage::StorageError::Unsupported)
            }
        }
    };
}

impl_storage_ports!(crate::storage::fs::FsStorage);
impl_storage_ports!(crate::storage::s3::S3Storage);

impl_gc_storage_port!(crate::storage::fs::FsStorage);
impl_gc_storage_port!(crate::storage::s3::S3Storage);

#[async_trait]
impl<T: ?Sized + BlobCasReader + Send + Sync> BlobCasReader for Arc<T> {
    async fn head_blob(&self, digest: &Digest) -> Result<BlobMeta, StorageError> {
        (**self).head_blob(digest).await
    }
    async fn open_blob(
        &self,
        digest: &Digest,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError> {
        (**self).open_blob(digest).await
    }
    async fn open_blob_range(
        &self,
        digest: &Digest,
        start: u64,
        end_inclusive: u64,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError> {
        (**self).open_blob_range(digest, start, end_inclusive).await
    }
}

#[async_trait]
impl<T: ?Sized + BlobCasWriter + Send + Sync> BlobCasWriter for Arc<T> {
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
}

#[async_trait]
impl<T: ?Sized + RepositoryCatalogReader + Send + Sync> RepositoryCatalogReader for Arc<T> {
    async fn list_repositories(&self) -> Result<Vec<String>, StorageError> {
        (**self).list_repositories().await
    }
    async fn repo_timestamps(&self, name: &str) -> Result<RepoTimestamps, StorageError> {
        (**self).repo_timestamps(name).await
    }
}

#[async_trait]
impl<T: ?Sized + StorageReadinessInspector + Send + Sync> StorageReadinessInspector for Arc<T> {
    async fn is_storage_empty(&self) -> Result<bool, StorageError> {
        (**self).is_storage_empty().await
    }
}

#[async_trait]
impl<T: ?Sized + ManifestReader + Send + Sync> ManifestReader for Arc<T> {
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
}

#[async_trait]
impl<T: ?Sized + ManifestStore + Send + Sync> ManifestStore for Arc<T> {
    async fn put_manifest(
        &self,
        name: &str,
        digest: &Digest,
        bytes: Bytes,
    ) -> Result<ManifestMeta, StorageError> {
        (**self).put_manifest(name, digest, bytes).await
    }
    async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), StorageError> {
        (**self).delete_manifest(name, digest).await
    }
}

#[async_trait]
impl<T: ?Sized + TagReader + Send + Sync> TagReader for Arc<T> {
    async fn resolve_tag(&self, name: &str, tag: &str) -> Result<Digest, StorageError> {
        (**self).resolve_tag(name, tag).await
    }
    async fn list_tags(&self, name: &str) -> Result<Vec<String>, StorageError> {
        (**self).list_tags(name).await
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
    async fn get_tag_with_version(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<Option<(Digest, String)>, StorageError> {
        (**self).get_tag_with_version(repo, tag).await
    }
}

#[async_trait]
impl<T: ?Sized + TagStore + Send + Sync> TagStore for Arc<T> {
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
}

#[async_trait]
impl<T: ?Sized + ReferrersReader + Send + Sync> ReferrersReader for Arc<T> {
    async fn list_referrers(
        &self,
        name: &str,
        subject: &Digest,
    ) -> Result<Vec<ReferrerDescriptor>, StorageError> {
        (**self).list_referrers(name, subject).await
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
}

#[async_trait]
impl<T: ?Sized + ReferrersStore + Send + Sync> ReferrersStore for Arc<T> {
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
}

#[async_trait]
impl<T: ?Sized + LifecycleJournalStore + Send + Sync> LifecycleJournalStore for Arc<T> {
    async fn read_lifecycle_journal(&self, repo: &str) -> Result<Option<Bytes>, StorageError> {
        (**self).read_lifecycle_journal(repo).await
    }
    async fn write_lifecycle_journal(&self, repo: &str, data: Bytes) -> Result<(), StorageError> {
        (**self).write_lifecycle_journal(repo, data).await
    }
    async fn delete_lifecycle_journal(&self, repo: &str) -> Result<(), StorageError> {
        (**self).delete_lifecycle_journal(repo).await
    }
}

#[async_trait]
impl<T: ?Sized + RepositoryLeaseStore + Send + Sync> RepositoryLeaseStore for Arc<T> {
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
}

#[async_trait]
impl<T: ?Sized + ClusterLockStore + Send + Sync> ClusterLockStore for Arc<T> {
    async fn acquire_deployment_writer_lock(
        &self,
        doc: &DeploymentWriterLockDoc,
    ) -> Result<(bool, Option<String>), StorageError> {
        (**self).acquire_deployment_writer_lock(doc).await
    }
    async fn release_deployment_writer_lock(
        &self,
        doc: &DeploymentWriterLockDoc,
        expected_etag: Option<&str>,
    ) -> Result<bool, StorageError> {
        (**self)
            .release_deployment_writer_lock(doc, expected_etag)
            .await
    }
    async fn inspect_deployment_writer_lock(
        &self,
    ) -> Result<Option<(DeploymentWriterLockDoc, Option<String>)>, StorageError> {
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
}

#[async_trait]
impl<T: ?Sized + GcStoragePort + Send + Sync> GcStoragePort for Arc<T> {
    fn kind(&self) -> &'static str {
        (**self).kind()
    }
    fn gc_strategy(&self) -> GcStorageStrategy {
        (**self).gc_strategy()
    }
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
        permit: &GcMutationPermit<'_>,
        digest: &Digest,
        version: &BlobObjectVersion,
    ) -> Result<GcQuarantineResult, StorageError> {
        (**self).quarantine_blob(permit, digest, version).await
    }
    async fn restore_quarantined_blob(
        &self,
        permit: &GcMutationPermit<'_>,
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
        permit: &GcMutationPermit<'_>,
        digest: &Digest,
        version: Option<&BlobObjectVersion>,
    ) -> Result<GcDeleteResult, StorageError> {
        (**self)
            .delete_blob_conditional(permit, digest, version)
            .await
    }
    async fn discover_manifest_references(&self) -> Result<Option<HashSet<Digest>>, StorageError> {
        (**self).discover_manifest_references().await
    }
}

// -----------------------------------------------------------------------------
// Storage Wiring: Single Backend Instance Shared Across Port Views
// -----------------------------------------------------------------------------

/// Concrete storage port provider wiring one single underlying backend instance
/// into typed capability port views without leaking the full omnibus trait.
#[derive(Clone)]
pub struct StorageWiring {
    backend_kind: &'static str,
    blob_mutation: Arc<dyn BlobUploadCoordinatorStoragePort>,
    manifest_lifecycle: Arc<dyn ManifestLifecycleStoragePort>,
    blob_reader: Arc<dyn BlobCasReader>,
    membership_reader: Arc<dyn RepositoryBlobMembershipStorage>,
    manifest_reader: Arc<dyn ManifestReader>,
    tag_reader: Arc<dyn TagReader>,
    catalog_reader: Arc<dyn RepositoryCatalogReader>,
    referrers_reader: Arc<dyn ReferrersReader>,
    proxy_storage: Arc<dyn ProxyStoragePort>,
    gc_port: Arc<dyn GcStoragePort>,
    gc_service_port: Arc<dyn GcServiceStoragePort>,
    cluster_lock: Arc<dyn ClusterLockStore>,
    blob_index: Arc<dyn BlobIndexStoragePort>,
    blob_ref_index: Arc<dyn BlobRefIndexStoragePort>,
    readiness_inspector: Arc<dyn StorageReadinessInspector>,
}

impl StorageWiring {
    pub fn from_backend<S>(backend: Arc<S>) -> Self
    where
        S: BlobUploadCoordinatorStoragePort
            + ManifestLifecycleStoragePort
            + BlobIndexStoragePort
            + BlobRefIndexStoragePort
            + GcServiceStoragePort
            + ClusterLockStore
            + GcStoragePort
            + CacheEvictionPort
            + StorageReadinessInspector
            + 'static,
    {
        Self {
            backend_kind: backend.kind(),
            blob_mutation: backend.clone(),
            manifest_lifecycle: backend.clone(),
            blob_reader: backend.clone(),
            membership_reader: backend.clone(),
            manifest_reader: backend.clone(),
            tag_reader: backend.clone(),
            catalog_reader: backend.clone(),
            referrers_reader: backend.clone(),
            proxy_storage: backend.clone(),
            gc_port: backend.clone(),
            gc_service_port: backend.clone(),
            cluster_lock: backend.clone(),
            blob_index: backend.clone(),
            blob_ref_index: backend.clone(),
            readiness_inspector: backend,
        }
    }

    pub fn backend_kind(&self) -> &'static str {
        self.backend_kind
    }

    pub fn blob_mutation(&self) -> Arc<dyn BlobUploadCoordinatorStoragePort> {
        Arc::clone(&self.blob_mutation)
    }

    pub fn manifest_lifecycle(&self) -> Arc<dyn ManifestLifecycleStoragePort> {
        Arc::clone(&self.manifest_lifecycle)
    }

    pub fn blob_reader(&self) -> Arc<dyn BlobCasReader> {
        Arc::clone(&self.blob_reader)
    }

    pub fn membership_reader(&self) -> Arc<dyn RepositoryBlobMembershipStorage> {
        Arc::clone(&self.membership_reader)
    }

    pub fn manifest_reader(&self) -> Arc<dyn ManifestReader> {
        Arc::clone(&self.manifest_reader)
    }

    pub fn tag_reader(&self) -> Arc<dyn TagReader> {
        Arc::clone(&self.tag_reader)
    }

    pub fn catalog_reader(&self) -> Arc<dyn RepositoryCatalogReader> {
        Arc::clone(&self.catalog_reader)
    }

    pub fn referrers_reader(&self) -> Arc<dyn ReferrersReader> {
        Arc::clone(&self.referrers_reader)
    }

    pub fn proxy_storage(&self) -> Arc<dyn ProxyStoragePort> {
        Arc::clone(&self.proxy_storage)
    }

    pub fn gc_port(&self) -> Arc<dyn GcStoragePort> {
        Arc::clone(&self.gc_port)
    }

    pub fn gc_service_port(&self) -> Arc<dyn GcServiceStoragePort> {
        Arc::clone(&self.gc_service_port)
    }

    pub fn cluster_lock(&self) -> Arc<dyn ClusterLockStore> {
        Arc::clone(&self.cluster_lock)
    }

    pub fn blob_index(&self) -> Arc<dyn BlobIndexStoragePort> {
        Arc::clone(&self.blob_index)
    }

    pub fn blob_ref_index(&self) -> Arc<dyn BlobRefIndexStoragePort> {
        Arc::clone(&self.blob_ref_index)
    }

    pub fn readiness_inspector(&self) -> Arc<dyn StorageReadinessInspector> {
        Arc::clone(&self.readiness_inspector)
    }
}
