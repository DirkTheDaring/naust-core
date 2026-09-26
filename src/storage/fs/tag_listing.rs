//! Filesystem tag-listing support: configured resource limits and the
//! repository-existence probe.
//!
//! The tag LISTING MECHANICS that previously lived here (the contained
//! `contained_list_tags_seam` / `contained_list_tags_page_seam`
//! implementations) migrated to the backend-neutral shared tag domain
//! (`crate::storage::tag_domain`) over `storage_core::ObjectStore` in the
//! Phase 3 tag-family cutover. What remains is deliberately NOT tag storage
//! mechanics:
//! - the configured [`TagListingLimits`] (wired into the FS object store's
//!   enumeration budget and the shared tag domain's payload/collection
//!   bounds);
//! - [`FsTagRepoProbe`], the contained repository-existence probe backing
//!   the `list_tags` missing-repository contract (`Err(NotFound)` when
//!   `repos/<repo>` is absent). Repository existence is REPOSITORY-family
//!   state; the probe stays backend-specific until that family migrates in
//!   a later phase.

use crate::storage::StorageError;
use crate::storage::tag_domain::{TagRepoProbe, validate_path_component};
use async_trait::async_trait;
use std::sync::Arc;
use storage_core::ObjectKey;
use storage_fs::{DirEnumerationLimits, FsDirError, FsMetadataReader};

/// Default maximum number of tag directory entries to enumerate during tag listing.
pub const DEFAULT_TAG_LISTING_MAX_ENTRIES: usize = 10_000;
/// Default maximum cumulative bytes of entry filenames during tag listing.
pub const DEFAULT_TAG_LISTING_MAX_NAME_BYTES: usize = 1_500_000;
/// Default maximum number of directory entries to inspect when probing repo existence on tags NotFound.
pub const DEFAULT_TAG_LISTING_REPO_PROBE_MAX_ENTRIES: usize = 64;
/// Default maximum cumulative filename bytes when probing repo existence.
pub const DEFAULT_TAG_LISTING_REPO_PROBE_MAX_NAME_BYTES: usize = 4_096;
/// Default maximum candidate payload size in bytes for tag payload reads.
pub const DEFAULT_TAG_LISTING_MAX_PAYLOAD_BYTES: u64 = 1_024;

/// Minimum allowable value for `tag_listing_max_entries`.
pub const MIN_TAG_LISTING_ENTRIES: usize = 1;
/// Minimum allowable value for `tag_listing_max_name_bytes` (accommodates a 128-byte tag name).
pub const MIN_TAG_LISTING_NAME_BYTES: usize = 128;
/// Minimum allowable value for `tag_listing_repo_probe_max_entries`.
pub const MIN_TAG_LISTING_REPO_PROBE_ENTRIES: usize = 1;
/// Minimum allowable value for `tag_listing_repo_probe_max_name_bytes`.
pub const MIN_TAG_LISTING_REPO_PROBE_NAME_BYTES: usize = 64;
/// Minimum allowable value for `tag_listing_max_payload_bytes` (accommodates SHA-512 text and whitespace).
pub const MIN_TAG_LISTING_PAYLOAD_BYTES: u64 = 256;

/// Caller-supplied ceiling for tag payload reads (formerly
/// `fs::tag_read::TagReadLimits`; the contained read seams it configured
/// migrated to the shared tag domain, the config shape is unchanged).
/// `None` means no configured ceiling; the shared tag domain then applies
/// [`DEFAULT_TAG_LISTING_MAX_PAYLOAD_BYTES`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct TagReadLimits {
    pub max_payload_bytes: Option<u64>,
}

/// Configuration limits for tag listing and repository existence probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagListingLimits {
    pub repo_probe_limits: storage_fs::DirEnumerationLimits,
    pub tags_dir_limits: storage_fs::DirEnumerationLimits,
    pub payload_limits: TagReadLimits,
}

impl Default for TagListingLimits {
    fn default() -> Self {
        Self {
            repo_probe_limits: storage_fs::DirEnumerationLimits::new(usize::MAX, usize::MAX),
            tags_dir_limits: storage_fs::DirEnumerationLimits::new(
                DEFAULT_TAG_LISTING_MAX_ENTRIES,
                DEFAULT_TAG_LISTING_MAX_NAME_BYTES,
            ),
            payload_limits: TagReadLimits {
                max_payload_bytes: Some(DEFAULT_TAG_LISTING_MAX_PAYLOAD_BYTES),
            },
        }
    }
}

impl TagListingLimits {
    #[allow(dead_code)]
    pub fn new(
        repo_probe_limits: storage_fs::DirEnumerationLimits,
        tags_dir_limits: storage_fs::DirEnumerationLimits,
        payload_limits: TagReadLimits,
    ) -> Self {
        Self {
            repo_probe_limits,
            tags_dir_limits,
            payload_limits,
        }
    }

    /// Constructs unbounded tag listing limits.
    #[allow(dead_code)]
    pub fn unbounded() -> Self {
        Self {
            repo_probe_limits: storage_fs::DirEnumerationLimits::new(usize::MAX, usize::MAX),
            tags_dir_limits: storage_fs::DirEnumerationLimits::new(usize::MAX, usize::MAX),
            payload_limits: TagReadLimits {
                max_payload_bytes: None,
            },
        }
    }
}

/// Translates directory enumeration errors from [`FsDirError`] into [`StorageError`].
pub(crate) fn translate_tag_dir_error(err: FsDirError, dir_key: &str) -> StorageError {
    match err {
        FsDirError::NotFound { .. } => {
            StorageError::io(format!("directory vanished before enumeration: {dir_key}"))
        }
        FsDirError::NotADirectory { path } => {
            StorageError::corrupt_data(format!("path is not a directory ({path:?}): {dir_key}"))
        }
        FsDirError::PermissionDenied { source, .. } => StorageError::permission_denied(format!(
            "permission denied enumerating directory {dir_key}: {source}"
        )),
        FsDirError::ResolutionRejected { source, .. } => StorageError::io(format!(
            "path resolution rejected for directory {dir_key}: {source}"
        )),
        FsDirError::SyscallUnsupported(source) => StorageError::configuration(format!(
            "openat2 is unavailable in this execution environment for {dir_key}: {source}"
        )),
        FsDirError::PlatformUnsupported => StorageError::configuration(format!(
            "platform unsupported: descriptor-relative containment requires Linux openat2 for {dir_key}"
        )),
        FsDirError::LimitExceeded { reason } => StorageError::backend(format!(
            "directory enumeration resource limit exceeded for {dir_key}: {reason:?}"
        )),
        FsDirError::EntryDisappeared { name } => StorageError::io(format!(
            "directory entry disappeared during inspection in {dir_key}: {name:?}"
        )),
        FsDirError::Io { source } => StorageError::io(format!(
            "I/O error enumerating directory {dir_key}: {source}"
        )),
        FsDirError::RuntimeMissing(err) => StorageError::backend(format!(
            "tokio runtime missing during enumeration of {dir_key}: {err}"
        )),
        FsDirError::TaskJoinFailed(err) => StorageError::backend(format!(
            "blocking enumeration task join failed for {dir_key}: {err}"
        )),
        other => StorageError::backend(format!(
            "unexpected directory enumeration error for {dir_key}: {other}"
        )),
    }
}

fn repo_key(repo: &str) -> Result<ObjectKey, StorageError> {
    validate_path_component(repo, "repository name")?;
    let key_str = format!("repos/{repo}");
    ObjectKey::parse(&key_str).map_err(|e| StorageError::InvalidRepoName(e.to_string()))
}

/// Contained repository-existence probe for the `list_tags`
/// missing-repository contract: opens `repos/<repo>` beneath the
/// pinned root directly without enumerating directory entries when unbounded,
/// or enforces explicit caller bounds when limits are configured.
pub(crate) struct FsTagRepoProbe {
    reader: Arc<FsMetadataReader>,
    limits: Option<DirEnumerationLimits>,
}

impl FsTagRepoProbe {
    pub(crate) fn new(reader: Arc<FsMetadataReader>, limits: DirEnumerationLimits) -> Self {
        Self {
            reader,
            limits: Some(limits),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn unbounded(reader: Arc<FsMetadataReader>) -> Self {
        Self {
            reader,
            limits: None,
        }
    }
}

fn translate_probe_error(err: storage_fs::FsMutateError, dir_key: &str) -> StorageError {
    match err {
        storage_fs::FsMutateError::NotFound => {
            StorageError::io(format!("directory vanished before probe: {dir_key}"))
        }
        storage_fs::FsMutateError::NotADirectory => {
            StorageError::corrupt_data(format!("path is not a directory: {dir_key}"))
        }
        storage_fs::FsMutateError::PermissionDenied => StorageError::permission_denied(format!(
            "permission denied opening directory {dir_key}"
        )),
        storage_fs::FsMutateError::ResolutionRejected { raw_os_error } => StorageError::io(
            format!("path resolution rejected for directory {dir_key} (os error {raw_os_error:?})"),
        ),
        storage_fs::FsMutateError::PlatformUnsupported => {
            StorageError::configuration(format!("platform unsupported for {dir_key}"))
        }
        storage_fs::FsMutateError::Io(source) => {
            StorageError::io(format!("I/O error probing directory {dir_key}: {source}"))
        }
        storage_fs::FsMutateError::RuntimeMissing(err) => StorageError::backend(format!(
            "tokio runtime missing during probe of {dir_key}: {err}"
        )),
        storage_fs::FsMutateError::TaskJoinFailed(err) => {
            StorageError::backend(format!("blocking task join failed for {dir_key}: {err}"))
        }
        other => StorageError::backend(format!(
            "unexpected error probing directory {dir_key}: {other}"
        )),
    }
}

#[async_trait]
impl TagRepoProbe for FsTagRepoProbe {
    async fn repo_exists(&self, repo: &str) -> Result<bool, StorageError> {
        let key = repo_key(repo)?;
        if let Some(limits) = self.limits {
            if limits.max_entries() < usize::MAX || limits.max_total_name_bytes() < usize::MAX {
                return match self.reader.enumerate_dir(Some(&key), limits).await {
                    Ok(_) => Ok(true),
                    Err(FsDirError::NotFound { .. }) => Ok(false),
                    Err(err) => Err(translate_tag_dir_error(err, key.as_str())),
                };
            }
        }
        match self.reader.open_contained_dir(key.as_str()).await {
            Ok(_) => Ok(true),
            Err(storage_fs::FsMutateError::NotFound) => Ok(false),
            Err(storage_fs::FsMutateError::NotADirectory) => Ok(false),
            Err(err) => Err(translate_probe_error(err, key.as_str())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_repo_probe_unbounded_by_entry_count() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let reader = Arc::new(FsMetadataReader::open(root).unwrap());
        let probe = FsTagRepoProbe::unbounded(reader);

        // 1. Missing repo returns false
        assert_eq!(probe.repo_exists("my-repo").await.unwrap(), false);

        // 2. Existing repo with 200 entries (> 64 limit) succeeds with true
        let repo_path = root.join("repos").join("my-repo");
        std::fs::create_dir_all(&repo_path).unwrap();
        for i in 0..200 {
            std::fs::write(repo_path.join(format!("entry_{i}")), b"test").unwrap();
        }

        assert_eq!(probe.repo_exists("my-repo").await.unwrap(), true);
    }
}
