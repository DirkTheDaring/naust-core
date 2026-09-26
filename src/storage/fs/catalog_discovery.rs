//! Contained filesystem repository-catalog discovery for `naust`.
//!
//! # Architecture and Scope
//!
//! Implements the production repository-catalog walk (`FsStorage::list_repo_names`,
//! surfaced as `Storage::list_repositories`) beneath the pinned storage root
//! descriptor via [`storage_fs::FsMetadataReader::enumerate_dir`]. It reuses the
//! traversal mechanics of GC discovery ([`super::repo_discovery`]: enumerator
//! seam, budget helpers, retained-path-byte tracker) while keeping the
//! **catalog recognition policy**, which is intentionally distinct from GC
//! manifest-directory discovery:
//!
//! - Catalog: a directory is a repository iff it directly contains a
//!   `tags/`, `manifests/`, `blobs/`, or `meta/` subdirectory; reserved layout
//!   names (`tags`, `manifests`, `referrers`, `blobs`, `meta`) are never listed
//!   and never descended into; output is sorted deduplicated relative names.
//! - GC discovery: descends everywhere (including reserved names), treats
//!   `manifests` as a terminal leaf, returns manifest-directory `ObjectKey`s,
//!   and fails closed on non-UTF-8 or unaddressable names.
//!
//! Do not substitute one for the other: `/v2/_catalog` presentation and GC
//! reachability have different completeness requirements (see
//! `docs/architecture/filesystem-gc-repository-discovery-decisions.md`).
//!
//! # Preserved Catalog Recognition Semantics
//!
//! - Missing `repos/` root: empty success `Ok(vec![])`.
//! - A directory observed in its parent that is missing when opened
//!   (concurrent removal) is skipped, matching the legacy `NotFound => continue`.
//! - Recognition markers must be **directory** entries; regular files named
//!   `tags` etc. are not markers.
//! - Symlinked child entries are skipped (dirent type is not a directory),
//!   exactly as before.
//! - Non-UTF-8 entry names are skipped together with their subtrees (legacy
//!   catalog behavior; GC discovery instead fails closed).
//! - Hidden (dot-prefixed) directories are not filtered.
//! - Nested repositories and repositories that are also namespace parents are
//!   both listed; results are sorted lexicographically and deduplicated.
//! - Wrong-type `repos/` root and unreadable directories map to the legacy
//!   [`StorageErrorKind::Io`] taxonomy.
//!
//! # Intentional Containment Changes (relative to the ambient implementation)
//!
//! - Traversal resolves beneath the pinned root descriptor (`openat2` with
//!   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`). A
//!   symlinked path component — including a symlinked `repos/` root — is
//!   rejected with [`StorageErrorKind::Io`] instead of silently followed.
//! - Recognition markers are judged by dirent type from the contained
//!   enumeration; a **symlinked** `tags`/`manifests`/`blobs`/`meta` entry no
//!   longer recognizes a repository (previously an ambient symlink-following
//!   `stat` did).
//! - Mid-iteration enumeration errors previously terminated the directory scan
//!   silently (`while let Ok(Some(..))`), returning a truncated catalog as
//!   success. They now propagate as errors; no successful partial catalog is
//!   returned.
//! - UTF-8 entry names that cannot compose a valid contained [`ObjectKey`]
//!   (backslashes, control characters) **fail the walk closed** with
//!   [`StorageErrorKind::CorruptData`]. Such names were previously listed even
//!   though every contained read path (manifest listing, tag listing,
//!   referrers) rejects them with `InvalidRepoName`; silently skipping them
//!   instead would turn visible downstream failures into successful incomplete
//!   discovery, which safety-relevant consumers (membership migration
//!   application/verification, index rebuild, deletion-safety fallbacks) could
//!   mistake for completion.
//!
//! # Resource Model
//!
//! [`CatalogDiscoveryLimits`] bounds the complete walk, not just one directory:
//! per-directory entry/name-byte ceilings (`per_dir_limits`), traversal depth,
//! number of directory enumerations, cumulative entries inspected, retained
//! repository names, and cumulative logical path bytes retained across the
//! pending queue and output. Exceeding any bound fails the whole walk closed
//! ([`StorageErrorKind::Backend`]); no truncated catalog is returned.
//!
//! These are logical accounting bounds, not exact peak-allocation or
//! memory-capacity bounds. The retained-path-byte tracker counts exactly the
//! bytes of what the walk stores: the `ObjectKey` strings held in the pending
//! traversal queue (charged on enqueue, debited on dequeue) plus the
//! repository-name strings held in the output list (charged when a repository
//! is recognized, never debited). Temporary strings, per-directory enumeration
//! batches, `Vec`/`VecDeque` capacity growth, allocator overhead, and
//! concurrent requests remain additional costs beyond the accounted bytes. No
//! global memory or concurrency budget follows from per-walk limits. Paged
//! catalog callers re-run the full walk per page (pagination is applied
//! in-memory by the application layer).
//!
//! The production default is [`CatalogDiscoveryLimits::unbounded()`], which
//! preserves the ambient implementation's unbounded traversal baseline.
//! Operational numeric ceilings remain undecided; there is currently **no
//! production configuration path** for non-default limits — adopting finite
//! ceilings requires actual production wiring (constructor/limit plumbing and
//! validation) in addition to the decision itself.
//!
//! # Concurrency and Coherence Demarcation
//!
//! Descriptor containment does **not** establish snapshot isolation, hard-link
//! isolation, or mount isolation. Directories may appear, vanish, or change
//! between enumerations within one walk; repeated walks (including successive
//! catalog pages) may observe different states. Pinned-root resolution means a
//! replaced root pathname is not followed; descendants are re-resolved beneath
//! the originally opened root inode on every enumeration.

use std::collections::VecDeque;

use storage_core::ObjectKey;
use storage_fs::{DirEnumerationLimits, FsDirError};

use super::repo_discovery::{
    DiscoveryDirEnumerator, RetainedPathBytesTracker, checked_increment_depth,
    checked_increment_enumerations, checked_increment_total_entries,
};
use crate::storage::StorageError;

/// Reserved layout directory names that are never listed as repositories and
/// never descended into by the catalog walk.
const RESERVED_LAYOUT_NAMES: [&str; 5] = ["tags", "manifests", "referrers", "blobs", "meta"];

/// Directory entry names whose presence (as directories) recognizes the
/// containing directory as a repository. `referrers` is intentionally not a
/// recognition marker.
const RECOGNITION_MARKERS: [&str; 4] = ["tags", "manifests", "blobs", "meta"];

/// Caller-supplied limits for the bounded repository-catalog walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CatalogDiscoveryLimits {
    /// Maximum directory depth relative to `repos/` (the `repos/` root is depth 0).
    pub max_depth: usize,
    /// Maximum number of directory enumerations performed during the walk.
    pub max_dir_enumerations: usize,
    /// Maximum cumulative directory entries inspected across all enumerations,
    /// including entries that are subsequently skipped.
    pub max_total_entries: usize,
    /// Maximum number of repository names retained in the output.
    pub max_repositories: usize,
    /// Maximum cumulative logical path bytes retained across the pending
    /// traversal queue and the output name list.
    pub max_retained_path_bytes: usize,
    /// Per-directory limits passed to each `enumerate_dir` call.
    pub per_dir_limits: DirEnumerationLimits,
}

impl CatalogDiscoveryLimits {
    /// Effectively unbounded limits preserving the ambient implementation's
    /// unbounded traversal baseline. This is the production default until
    /// operational numeric ceilings are decided.
    pub(crate) fn unbounded() -> Self {
        Self {
            max_depth: usize::MAX,
            max_dir_enumerations: usize::MAX,
            max_total_entries: usize::MAX,
            max_repositories: usize::MAX,
            max_retained_path_bytes: usize::MAX,
            per_dir_limits: DirEnumerationLimits::new(usize::MAX, usize::MAX),
        }
    }
}

impl Default for CatalogDiscoveryLimits {
    fn default() -> Self {
        Self::unbounded()
    }
}

/// Maps a directory enumeration failure to the legacy-compatible
/// [`StorageError`] taxonomy shared by the contained catalog, timestamp, and
/// emptiness walks.
///
/// Unlike GC discovery, permission and wrong-type failures keep the legacy
/// [`StorageErrorKind::Io`] mapping that ambient `tokio::fs::read_dir` errors
/// produced; budget exhaustion maps to `Backend`; unsupported environments map
/// to `Configuration`. `NotFound` is handled by callers (missing roots and
/// concurrently removed observed children have caller-specific contracts) and
/// must not reach this function.
pub(crate) fn map_contained_dir_error(err: FsDirError, dir_key: &str) -> StorageError {
    match err {
        FsDirError::NotADirectory { .. } => {
            StorageError::io(format!("target path is not a directory: {dir_key}"))
        }
        FsDirError::PermissionDenied { source, .. } => {
            StorageError::io(format!("failed to enumerate {dir_key}: {source}"))
        }
        FsDirError::ResolutionRejected { source, .. } => StorageError::io(format!(
            "containment rejected path resolution for {dir_key}: {source}"
        )),
        FsDirError::LimitExceeded { reason } => StorageError::backend(format!(
            "contained per-directory enumeration limit exceeded in {dir_key}: {reason:?}"
        )),
        FsDirError::EntryDisappeared { name } => StorageError::io(format!(
            "directory entry disappeared during type inspection in {dir_key}: {name:?}"
        )),
        FsDirError::Io { source } => {
            StorageError::io(format!("failed to enumerate {dir_key}: {source}"))
        }
        FsDirError::SyscallUnsupported(source) => StorageError::configuration(format!(
            "openat2 is unavailable in this execution environment: {source}"
        )),
        FsDirError::PlatformUnsupported => StorageError::configuration(
            "platform unsupported: descriptor-relative containment requires Linux openat2",
        ),
        FsDirError::RuntimeMissing(err) => {
            StorageError::backend(format!("tokio runtime missing: {err}"))
        }
        FsDirError::TaskJoinFailed(err) => {
            StorageError::backend(format!("blocking enumeration task join failed: {err}"))
        }
        FsDirError::NotFound { .. } => StorageError::internal_invariant(format!(
            "NotFound must be handled before contained dir error mapping: {dir_key}"
        )),
        other => StorageError::backend(format!(
            "unexpected directory enumeration error in {dir_key}: {other}"
        )),
    }
}

/// Verifies the retained-repository output capacity before pushing a new name.
#[inline]
fn checked_check_repositories_capacity(current_len: usize, max: usize) -> Result<(), StorageError> {
    if current_len >= max {
        return Err(StorageError::backend(
            "catalog discovery limit exceeded: max repositories limit reached",
        ));
    }
    Ok(())
}

/// Discovers repository names beneath `repos/` using descriptor-relative
/// containment, preserving catalog recognition semantics.
///
/// Returns sorted, deduplicated repository names relative to `repos/`
/// (e.g. `library/ubuntu`). See the module documentation for the recognition
/// contract, intentional containment changes, and the resource model.
pub(crate) async fn discover_catalog_repositories_impl(
    enumerator: &(impl DiscoveryDirEnumerator + ?Sized),
    limits: &CatalogDiscoveryLimits,
) -> Result<Vec<String>, StorageError> {
    let repos_key = ObjectKey::parse("repos")
        .map_err(|e| StorageError::internal_invariant(format!("invalid root object key: {e}")))?;

    let mut path_bytes = RetainedPathBytesTracker::new(limits.max_retained_path_bytes);
    path_bytes.charge(repos_key.as_str().len())?;

    // Queue entries: (directory key beneath the root, depth). The
    // repository-relative name is derived from the key on recognition, so the
    // pending queue retains exactly the key strings the tracker charges.
    let mut queue: VecDeque<(ObjectKey, usize)> = VecDeque::new();
    queue.push_back((repos_key, 0usize));

    let mut dir_enumerations: usize = 0;
    let mut total_entries: usize = 0;
    let mut repositories: Vec<String> = Vec::new();

    while let Some((current_key, current_depth)) = queue.pop_front() {
        path_bytes.debit(current_key.as_str().len())?;

        // Capacity check BEFORE calling enumerate_dir.
        dir_enumerations =
            checked_increment_enumerations(dir_enumerations, limits.max_dir_enumerations)?;

        let entries = match enumerator
            .enumerate_dir(Some(&current_key), limits.per_dir_limits)
            .await
        {
            Ok(entries) => entries,
            Err(FsDirError::NotFound { .. }) => {
                // Missing repos/ root yields empty success; a child directory
                // observed in its parent but removed before opening is skipped,
                // both matching the legacy `NotFound => continue` behavior.
                continue;
            }
            Err(other) => return Err(map_contained_dir_error(other, current_key.as_str())),
        };

        let mut recognized = false;

        for entry in entries {
            total_entries =
                checked_increment_total_entries(total_entries, limits.max_total_entries)?;

            // Only directory entries participate in recognition and traversal;
            // symlinks, regular files, and other types are skipped (dirent-type
            // policy, matching the legacy `file_type.is_dir()` gate).
            match entry.file_type() {
                storage_fs::DirEntryType::Directory => {}
                _ => continue,
            }

            // Legacy catalog behavior: non-UTF-8 entry names are skipped along
            // with their subtrees (GC discovery instead fails closed).
            let Some(name) = entry.name().to_str() else {
                continue;
            };

            if RESERVED_LAYOUT_NAMES.contains(&name) {
                // Reserved layout names are never listed and never descended.
                // Marker presence recognizes the containing directory as a
                // repository — except the repos/ root itself (depth 0).
                if current_depth > 0 && RECOGNITION_MARKERS.contains(&name) {
                    recognized = true;
                }
                continue;
            }

            let child_key_str = format!("{}/{name}", current_key.as_str());
            let child_key = ObjectKey::parse(&child_key_str).map_err(|err| {
                // A UTF-8 name that cannot compose a contained ObjectKey
                // (backslashes, control characters) makes its subtree
                // unaddressable by every contained read path. Failing closed
                // prevents silent omission from safety-relevant consumers
                // (membership migration, index rebuild, deletion safety).
                StorageError::corrupt_data(format!(
                    "directory name in {} cannot form a contained object key: {name:?}: {err}",
                    current_key.as_str()
                ))
            })?;

            let child_depth = checked_increment_depth(current_depth, limits.max_depth)?;

            path_bytes.charge(child_key.as_str().len())?;
            queue.push_back((child_key, child_depth));
        }

        if recognized {
            checked_check_repositories_capacity(repositories.len(), limits.max_repositories)?;
            let rel = current_key
                .as_str()
                .strip_prefix("repos/")
                .ok_or_else(|| {
                    StorageError::internal_invariant(format!(
                        "recognized repository key lacks repos/ prefix: {}",
                        current_key.as_str()
                    ))
                })?
                .to_string();
            path_bytes.charge(rel.len())?;
            repositories.push(rel);
        }
    }

    repositories.sort();
    repositories.dedup();
    Ok(repositories)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageErrorKind;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};
    use storage_fs::{DirEntry, DirEntryType};

    struct RecordingFakeEnumerator {
        calls: Arc<Mutex<Vec<(Option<ObjectKey>, DirEnumerationLimits)>>>,
        responses:
            Arc<Mutex<HashMap<Option<ObjectKey>, VecDeque<Result<Vec<DirEntry>, FsDirError>>>>>,
    }

    impl RecordingFakeEnumerator {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn script(&self, target: Option<ObjectKey>, response: Result<Vec<DirEntry>, FsDirError>) {
            self.responses
                .lock()
                .unwrap()
                .entry(target)
                .or_default()
                .push_back(response);
        }

        fn calls(&self) -> Vec<(Option<ObjectKey>, DirEnumerationLimits)> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DiscoveryDirEnumerator for RecordingFakeEnumerator {
        async fn enumerate_dir(
            &self,
            target: Option<&ObjectKey>,
            limits: DirEnumerationLimits,
        ) -> Result<Vec<DirEntry>, FsDirError> {
            self.calls.lock().unwrap().push((target.cloned(), limits));
            let mut responses = self.responses.lock().unwrap();
            let queue = responses.get_mut(&target.cloned()).unwrap_or_else(|| {
                panic!("unexpected call to enumerate_dir with target: {target:?}")
            });
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted responses for target: {target:?}"))
        }
    }

    fn dir_entry(name: &str, file_type: DirEntryType) -> DirEntry {
        DirEntry::new(OsString::from(name), file_type)
    }

    fn key(s: &str) -> ObjectKey {
        ObjectKey::parse(s).unwrap()
    }

    fn permissive_limits() -> CatalogDiscoveryLimits {
        CatalogDiscoveryLimits {
            max_depth: 32,
            max_dir_enumerations: 10_000,
            max_total_entries: 100_000,
            max_repositories: 10_000,
            max_retained_path_bytes: 1_000_000,
            per_dir_limits: DirEnumerationLimits::new(1000, 100_000),
        }
    }

    // ========================================================================
    // Fake-enumerator recognition and policy tests
    // ========================================================================

    #[tokio::test]
    async fn test_fake_missing_root_empty_success_single_call() {
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Err(FsDirError::NotFound {
                path: Some("repos".to_string()),
            }),
        );

        let repos = discover_catalog_repositories_impl(&fake, &permissive_limits())
            .await
            .unwrap();
        assert!(repos.is_empty());
        assert_eq!(fake.calls().len(), 1);
    }

    #[tokio::test]
    async fn test_fake_recognition_markers_and_reserved_pruning() {
        let fake = RecordingFakeEnumerator::new();
        // Root has: repoA (tags marker), repoB (referrers only), and reserved dirs.
        fake.script(
            Some(key("repos")),
            Ok(vec![
                dir_entry("repoA", DirEntryType::Directory),
                dir_entry("repoB", DirEntryType::Directory),
                dir_entry("tags", DirEntryType::Directory),
                dir_entry("manifests", DirEntryType::Directory),
                dir_entry("referrers", DirEntryType::Directory),
                dir_entry("blobs", DirEntryType::Directory),
                dir_entry("meta", DirEntryType::Directory),
            ]),
        );
        fake.script(
            Some(key("repos/repoA")),
            Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
        );
        fake.script(
            Some(key("repos/repoB")),
            Ok(vec![dir_entry("referrers", DirEntryType::Directory)]),
        );

        let repos = discover_catalog_repositories_impl(&fake, &permissive_limits())
            .await
            .unwrap();
        assert_eq!(repos, vec!["repoA".to_string()]);

        // Reserved names at root were never descended: only 3 calls total.
        let called: Vec<String> = fake
            .calls()
            .iter()
            .map(|(k, _)| k.as_ref().unwrap().as_str().to_string())
            .collect();
        assert_eq!(called, vec!["repos", "repos/repoA", "repos/repoB"]);
    }

    #[tokio::test]
    async fn test_fake_marker_must_be_directory_dirent() {
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Ok(vec![
                dir_entry("file_marker_repo", DirEntryType::Directory),
                dir_entry("symlink_marker_repo", DirEntryType::Directory),
            ]),
        );
        // Regular file named "tags" is not a marker.
        fake.script(
            Some(key("repos/file_marker_repo")),
            Ok(vec![dir_entry("tags", DirEntryType::Regular)]),
        );
        // Symlinked "meta" is not a marker under the dirent-type policy.
        fake.script(
            Some(key("repos/symlink_marker_repo")),
            Ok(vec![dir_entry("meta", DirEntryType::Symlink)]),
        );

        let repos = discover_catalog_repositories_impl(&fake, &permissive_limits())
            .await
            .unwrap();
        assert!(
            repos.is_empty(),
            "non-directory marker dirents must not recognize repositories"
        );
    }

    #[tokio::test]
    async fn test_fake_root_markers_never_recognize_root() {
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
        );
        let repos = discover_catalog_repositories_impl(&fake, &permissive_limits())
            .await
            .unwrap();
        assert!(repos.is_empty(), "repos/ root itself is never a repository");
    }

    #[tokio::test]
    async fn test_fake_observed_child_disappearance_skipped_legacy() {
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Ok(vec![
                dir_entry("ghost", DirEntryType::Directory),
                dir_entry("real", DirEntryType::Directory),
            ]),
        );
        fake.script(
            Some(key("repos/ghost")),
            Err(FsDirError::NotFound {
                path: Some("repos/ghost".to_string()),
            }),
        );
        fake.script(
            Some(key("repos/real")),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );

        let repos = discover_catalog_repositories_impl(&fake, &permissive_limits())
            .await
            .unwrap();
        assert_eq!(
            repos,
            vec!["real".to_string()],
            "concurrently removed observed directories are skipped, not errors"
        );
    }

    #[tokio::test]
    async fn test_fake_unaddressable_names_fail_closed() {
        for bad_name in ["bad\\backslash", "bad\x07control"] {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(key("repos")),
                Ok(vec![
                    dir_entry(bad_name, DirEntryType::Directory),
                    dir_entry("good", DirEntryType::Directory),
                ]),
            );

            let err = discover_catalog_repositories_impl(&fake, &permissive_limits())
                .await
                .expect_err("unaddressable UTF-8 names must fail the walk closed");
            match err {
                StorageError::Internal { kind, ref message } => {
                    assert_eq!(kind, StorageErrorKind::CorruptData, "for {bad_name:?}");
                    assert!(
                        message.contains("cannot form a contained object key")
                            && message.contains("repos"),
                        "error must carry name/context for {bad_name:?}: {message}"
                    );
                }
                other => panic!("expected CorruptData for {bad_name:?}, got {other:?}"),
            }
            // No partial success and no further enumerations after the failure.
            assert_eq!(fake.calls().len(), 1, "for {bad_name:?}");
        }
    }

    #[tokio::test]
    async fn test_fake_non_utf8_entries_skipped() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let fake = RecordingFakeEnumerator::new();
            let non_utf8 = std::ffi::OsStr::from_bytes(b"bad_\xff\xfe").to_os_string();
            fake.script(
                Some(key("repos")),
                Ok(vec![
                    DirEntry::new(non_utf8, DirEntryType::Directory),
                    dir_entry("ok_repo", DirEntryType::Directory),
                ]),
            );
            fake.script(
                Some(key("repos/ok_repo")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );

            let repos = discover_catalog_repositories_impl(&fake, &permissive_limits())
                .await
                .unwrap();
            assert_eq!(
                repos,
                vec!["ok_repo".to_string()],
                "non-UTF-8 entries are skipped (legacy catalog behavior, diverging from GC)"
            );
        }
    }

    #[tokio::test]
    async fn test_fake_mid_walk_io_error_no_partial_success() {
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Ok(vec![
                dir_entry("discovered", DirEntryType::Directory),
                dir_entry("broken", DirEntryType::Directory),
            ]),
        );
        fake.script(
            Some(key("repos/discovered")),
            Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
        );
        fake.script(
            Some(key("repos/broken")),
            Err(FsDirError::Io {
                source: std::io::Error::other("disk I/O error"),
            }),
        );

        let err = discover_catalog_repositories_impl(&fake, &permissive_limits())
            .await
            .expect_err("mid-walk I/O failure must fail the whole walk");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: StorageErrorKind::Io,
                    ..
                }
            ),
            "no successful partial catalog after earlier discoveries; got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_fake_error_taxonomy_mappings() {
        let limits = permissive_limits();

        // PermissionDenied -> legacy Io
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Err(FsDirError::PermissionDenied {
                path: Some("repos".to_string()),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }),
        );
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // NotADirectory -> legacy Io
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Err(FsDirError::NotADirectory {
                path: Some("repos".to_string()),
            }),
        );
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // ResolutionRejected -> Io
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Err(FsDirError::ResolutionRejected {
                raw_os_error: libc::ELOOP,
                source: std::io::Error::from_raw_os_error(libc::ELOOP),
            }),
        );
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Per-directory LimitExceeded -> Backend
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Err(FsDirError::LimitExceeded {
                reason: storage_fs::LimitExceededReason::MaxEntries(10),
            }),
        );
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));

        // EntryDisappeared -> Io
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Err(FsDirError::EntryDisappeared {
                name: OsString::from("ghost"),
            }),
        );
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // SyscallUnsupported -> Configuration
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(key("repos")),
            Err(FsDirError::SyscallUnsupported(
                std::io::Error::from_raw_os_error(libc::ENOSYS),
            )),
        );
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Configuration));

        // PlatformUnsupported -> Configuration
        let fake = RecordingFakeEnumerator::new();
        fake.script(Some(key("repos")), Err(FsDirError::PlatformUnsupported));
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Configuration));
    }

    // ========================================================================
    // Budget boundary tests
    // ========================================================================

    #[tokio::test]
    async fn test_fake_dir_enumeration_budget_boundary_and_one_over() {
        // Layout: repos -> a (tags), b (tags): 3 enumerations total.
        fn scripted() -> RecordingFakeEnumerator {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(key("repos")),
                Ok(vec![
                    dir_entry("a", DirEntryType::Directory),
                    dir_entry("b", DirEntryType::Directory),
                ]),
            );
            fake.script(
                Some(key("repos/a")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );
            fake.script(
                Some(key("repos/b")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );
            fake
        }

        // Boundary success at exactly 3.
        let fake = scripted();
        let mut limits = permissive_limits();
        limits.max_dir_enumerations = 3;
        let repos = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .unwrap();
        assert_eq!(repos, vec!["a".to_string(), "b".to_string()]);

        // One under: fails closed before the third call, despite `a` having
        // already been recognized — no partial result.
        let fake = scripted();
        limits.max_dir_enumerations = 2;
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .expect_err("budget exhaustion must fail the whole walk");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
        assert_eq!(fake.calls().len(), 2, "no further calls after exhaustion");
    }

    #[tokio::test]
    async fn test_fake_total_entries_budget_counts_skipped_entries() {
        fn scripted() -> RecordingFakeEnumerator {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(key("repos")),
                Ok(vec![
                    dir_entry("skipped_file", DirEntryType::Regular),
                    dir_entry("skipped_symlink", DirEntryType::Symlink),
                    dir_entry("repo", DirEntryType::Directory),
                ]),
            );
            fake.script(
                Some(key("repos/repo")),
                Ok(vec![dir_entry("meta", DirEntryType::Directory)]),
            );
            fake
        }

        // 4 entries total (3 in root incl. skipped + 1 marker).
        let mut limits = permissive_limits();
        limits.max_total_entries = 4;
        let repos = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .unwrap();
        assert_eq!(repos, vec!["repo".to_string()]);

        limits.max_total_entries = 3;
        let err = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .expect_err("entry accounting includes skipped entries");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    }

    #[tokio::test]
    async fn test_fake_depth_budget_boundary() {
        fn scripted() -> RecordingFakeEnumerator {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(key("repos")),
                Ok(vec![dir_entry("org", DirEntryType::Directory)]),
            );
            fake.script(
                Some(key("repos/org")),
                Ok(vec![dir_entry("team", DirEntryType::Directory)]),
            );
            fake.script(
                Some(key("repos/org/team")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );
            fake
        }

        // org depth 1, team depth 2: max_depth 2 succeeds.
        let mut limits = permissive_limits();
        limits.max_depth = 2;
        let repos = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .unwrap();
        assert_eq!(repos, vec!["org/team".to_string()]);

        // max_depth 1 fails when enqueueing team.
        limits.max_depth = 1;
        let err = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .expect_err("depth budget must fail closed");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    }

    #[tokio::test]
    async fn test_fake_max_repositories_budget_boundary() {
        fn scripted() -> RecordingFakeEnumerator {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(key("repos")),
                Ok(vec![
                    dir_entry("r1", DirEntryType::Directory),
                    dir_entry("r2", DirEntryType::Directory),
                ]),
            );
            fake.script(
                Some(key("repos/r1")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );
            fake.script(
                Some(key("repos/r2")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );
            fake
        }

        let mut limits = permissive_limits();
        limits.max_repositories = 2;
        let repos = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .unwrap();
        assert_eq!(repos.len(), 2);

        limits.max_repositories = 1;
        let err = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .expect_err("retained repository budget must fail closed");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    }

    #[tokio::test]
    async fn test_fake_retained_path_bytes_budget() {
        // The tracker counts exactly what the walk stores: pending queue
        // ObjectKey strings plus output repository-name strings.
        // "repos" is 5 bytes; pending key "repos/r1" is 8 bytes; output "r1" is 2.
        fn scripted() -> RecordingFakeEnumerator {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(key("repos")),
                Ok(vec![dir_entry("r1", DirEntryType::Directory)]),
            );
            fake.script(
                Some(key("repos/r1")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );
            fake
        }

        // Peak: repos popped (0), r1 enqueued (8), r1 popped (0), "r1" output (2). Peak = 8.
        let mut limits = permissive_limits();
        limits.max_retained_path_bytes = 8;
        let repos = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .unwrap();
        assert_eq!(repos, vec!["r1".to_string()]);

        limits.max_retained_path_bytes = 7;
        let err = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .expect_err("retained path byte budget must fail closed");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));

        // Below the root key length itself.
        limits.max_retained_path_bytes = 4;
        let fake = RecordingFakeEnumerator::new();
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .expect_err("cap below root key must fail before any call");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
        assert_eq!(fake.calls().len(), 0);
    }

    #[tokio::test]
    async fn test_fake_retained_path_bytes_multiple_pending_entries() {
        // Two siblings pending simultaneously: keys "repos/r1" + "repos/r2"
        // (8 + 8 = 16 bytes) are both retained after the root is processed.
        fn scripted() -> RecordingFakeEnumerator {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(key("repos")),
                Ok(vec![
                    dir_entry("r1", DirEntryType::Directory),
                    dir_entry("r2", DirEntryType::Directory),
                ]),
            );
            fake.script(
                Some(key("repos/r1")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );
            fake.script(
                Some(key("repos/r2")),
                Ok(vec![dir_entry("tags", DirEntryType::Directory)]),
            );
            fake
        }

        // Peak = 16 (both siblings pending). Afterwards: pop r1 (8 pending)
        // + output "r1" (2) = 10; pop r2 (2) + output "r2" (2) = 4.
        let mut limits = permissive_limits();
        limits.max_retained_path_bytes = 16;
        let repos = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .unwrap();
        assert_eq!(repos, vec!["r1".to_string(), "r2".to_string()]);

        // One byte under the peak fails while enqueueing the second sibling,
        // with no partial catalog and no further enumerations.
        let fake = scripted();
        limits.max_retained_path_bytes = 15;
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .expect_err("simultaneous pending entries must be accounted together");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
        assert_eq!(fake.calls().len(), 1, "failed during root processing");
    }

    #[tokio::test]
    async fn test_fake_retained_path_bytes_output_and_pending_simultaneously() {
        // Nested layout where retained output coexists with a pending entry:
        // repos/parent is a repository (tags) AND has a child repository.
        // Sequence: charge "repos" (5) -> pop (0) -> enqueue "repos/parent"
        // (12) -> pop (0) -> enqueue "repos/parent/child" (18) -> recognize
        // parent: charge output "parent" (6) => peak 24 with the child still
        // pending -> pop child (6) -> recognize: charge "parent/child" (12)
        // => 18. Peak = 24.
        fn scripted() -> RecordingFakeEnumerator {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(key("repos")),
                Ok(vec![dir_entry("parent", DirEntryType::Directory)]),
            );
            fake.script(
                Some(key("repos/parent")),
                Ok(vec![
                    dir_entry("tags", DirEntryType::Directory),
                    dir_entry("child", DirEntryType::Directory),
                ]),
            );
            fake.script(
                Some(key("repos/parent/child")),
                Ok(vec![dir_entry("meta", DirEntryType::Directory)]),
            );
            fake
        }

        let mut limits = permissive_limits();
        limits.max_retained_path_bytes = 24;
        let repos = discover_catalog_repositories_impl(&scripted(), &limits)
            .await
            .unwrap();
        assert_eq!(
            repos,
            vec!["parent".to_string(), "parent/child".to_string()]
        );

        // One byte under: fails while charging the output name "parent" with
        // "repos/parent/child" still pending. Parent was already recognized in
        // this walk — the failure returns Err with no partial catalog.
        let fake = scripted();
        limits.max_retained_path_bytes = 23;
        let err = discover_catalog_repositories_impl(&fake, &limits)
            .await
            .expect_err("output names and pending entries must be accounted together");
        match err {
            StorageError::Internal { kind, ref message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(
                    message.contains("max retained path bytes"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("expected Backend error, got {other:?}"),
        }
        assert_eq!(
            fake.calls().len(),
            2,
            "failed before the pending child could be enumerated"
        );
    }

    // ========================================================================
    // Linux-gated real filesystem tests
    // ========================================================================

    #[cfg(target_os = "linux")]
    mod real_fs_tests {
        use super::*;
        use storage_fs::FsMetadataReader;

        fn create_test_root() -> (tempfile::TempDir, std::path::PathBuf) {
            let fixture = tempfile::tempdir().expect("create tempdir");
            let root = fixture.path().join("storage_root");
            std::fs::create_dir_all(&root).expect("create storage root");
            (fixture, root)
        }

        #[tokio::test]
        async fn test_real_recognition_and_nesting() {
            let (_fixture, root) = create_test_root();
            let repos = root.join("repos");
            std::fs::create_dir_all(repos.join("org").join("meta")).unwrap();
            std::fs::create_dir_all(repos.join("org").join("team").join("tags")).unwrap();
            std::fs::create_dir_all(repos.join("zebra").join("manifests")).unwrap();
            std::fs::create_dir_all(repos.join("alpha").join("blobs")).unwrap();
            std::fs::create_dir_all(repos.join("norepo").join("misc")).unwrap();
            std::fs::create_dir_all(repos.join("refsonly").join("referrers")).unwrap();
            std::fs::create_dir_all(repos.join(".hidden").join("tags")).unwrap();

            let reader = FsMetadataReader::open(&root).expect("open reader");
            let result = discover_catalog_repositories_impl(&reader, &permissive_limits())
                .await
                .unwrap();
            assert_eq!(
                result,
                vec![
                    ".hidden".to_string(),
                    "alpha".to_string(),
                    "org".to_string(),
                    "org/team".to_string(),
                    "zebra".to_string(),
                ],
                "markers recognize repos, hidden dirs unfiltered, referrers-only and marker-less dirs excluded"
            );
        }

        #[tokio::test]
        async fn test_real_symlinked_repos_root_rejected() {
            let (fixture, root) = create_test_root();
            let outside = fixture.path().join("outside_repos");
            std::fs::create_dir_all(outside.join("ext_repo").join("tags")).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("repos")).unwrap();

            let reader = FsMetadataReader::open(&root).expect("open reader");
            let err = discover_catalog_repositories_impl(&reader, &permissive_limits())
                .await
                .expect_err("symlinked repos/ root must be rejected, not followed");
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
        }

        #[tokio::test]
        async fn test_real_symlinked_marker_not_recognized_and_symlinked_child_skipped() {
            let (fixture, root) = create_test_root();
            let repos = root.join("repos");
            std::fs::create_dir_all(&repos).unwrap();

            // Symlinked marker: repo exists, tags -> outside dir.
            let ext_tags = fixture.path().join("ext_tags");
            std::fs::create_dir_all(&ext_tags).unwrap();
            let repo_symlink_marker = repos.join("repo_symlink_marker");
            std::fs::create_dir_all(&repo_symlink_marker).unwrap();
            std::os::unix::fs::symlink(&ext_tags, repo_symlink_marker.join("tags")).unwrap();

            // Symlinked child repo entry -> skipped.
            let ext_repo = fixture.path().join("ext_repo");
            std::fs::create_dir_all(ext_repo.join("manifests")).unwrap();
            std::os::unix::fs::symlink(&ext_repo, repos.join("symlink_repo")).unwrap();

            // Ordinary repo for contrast.
            std::fs::create_dir_all(repos.join("real_repo").join("tags")).unwrap();

            let reader = FsMetadataReader::open(&root).expect("open reader");
            let result = discover_catalog_repositories_impl(&reader, &permissive_limits())
                .await
                .unwrap();
            assert_eq!(
                result,
                vec!["real_repo".to_string()],
                "symlinked markers no longer recognize repos; symlinked children remain skipped"
            );
        }

        #[tokio::test]
        async fn test_real_pinned_root_replacement() {
            let (fixture, root) = create_test_root();
            std::fs::create_dir_all(root.join("repos").join("old_repo").join("tags")).unwrap();

            let reader = FsMetadataReader::open(&root).expect("open reader");
            let initial = discover_catalog_repositories_impl(&reader, &permissive_limits())
                .await
                .unwrap();
            assert_eq!(initial, vec!["old_repo".to_string()]);

            // Replace the root pathname.
            let renamed = fixture.path().join("storage_root_old");
            std::fs::rename(&root, &renamed).unwrap();
            std::fs::create_dir_all(root.join("repos").join("new_repo").join("tags")).unwrap();

            let pinned = discover_catalog_repositories_impl(&reader, &permissive_limits())
                .await
                .unwrap();
            assert_eq!(
                pinned,
                vec!["old_repo".to_string()],
                "pinned reader observes the originally opened root inode"
            );
        }

        #[tokio::test]
        async fn test_real_wide_layout_and_per_dir_budget() {
            let (_fixture, root) = create_test_root();
            let repos = root.join("repos");
            for i in 0..20 {
                std::fs::create_dir_all(repos.join(format!("repo{i:02}")).join("tags")).unwrap();
            }

            let reader = FsMetadataReader::open(&root).expect("open reader");

            // Permissive limits succeed for all 20.
            let result = discover_catalog_repositories_impl(&reader, &permissive_limits())
                .await
                .unwrap();
            assert_eq!(result.len(), 20);

            // Per-directory ceiling below 20 fails the whole walk closed.
            let mut limits = permissive_limits();
            limits.per_dir_limits = DirEnumerationLimits::new(10, 100_000);
            let err = discover_catalog_repositories_impl(&reader, &limits)
                .await
                .expect_err("per-directory entry ceiling must fail closed");
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
        }
    }
}
