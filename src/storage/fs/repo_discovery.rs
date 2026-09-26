//! Contained manifest-directory discovery for filesystem GC.
//!
//! # Architecture and Scope
//!
//! This module implements bounded breadth-first manifest-directory discovery for
//! filesystem garbage collection reachability in `naust`. Traversal executes
//! beneath the pinned storage root descriptor via [`storage_fs::FsMetadataReader`].
//!
//! # Discovery Contract
//!
//! - **Output**: Returns `Result<Vec<ObjectKey>, StorageError>` containing observed
//!   terminal manifest-directory paths, not repository names or digests.
//!   Examples: `repos/library/ubuntu/manifests`, `repos/tags/sub1/sub2/manifests`,
//!   `repos/manifests`, `repos/C:drive/manifests`.
//! - **Starting Point**: Begins traversal at `ObjectKey("repos")`.
//! - **Traversal Policy**: Bounded breadth-first traversal descending into subdirectories
//!   regardless of name (`tags`, `blobs`, `meta`, `referrers`, or nested namespaces).
//! - **Terminal Leaves**: Directories named `manifests` are recorded as terminal leaves
//!   without opening or traversing their contents. This includes root-adjacent
//!   `repos/manifests`.
//! - **Containment**: Uses `storage_fs::FsMetadataReader::enumerate_dir` beneath a pinned
//!   root directory descriptor via [`DiscoveryDirEnumerator`].
//!
//! # Clarifications & Architectural Guarantees
//!
//! 1. **Enumeration Count**:
//!    Counts attempted directory enumeration calls, including the initial call on `repos`
//!    returning `NotFound`. Capacity is checked *before* the call; then incremented.
//!    A missing `repos/` root therefore requires one permitted attempt and returns empty
//!    success `Ok(Vec::new())`. It does not mean zero calls.
//!
//! 2. **Depth**:
//!    `repos` has depth 0. Child depth is computed using checked arithmetic (`depth + 1`).
//!    The depth limit (`max_depth`) is applied to every directory child, including terminal
//!    `manifests` directories, before enqueueing or retaining it.
//!
//! 3. **Counters and Bounds**:
//!    Inclusive limits and checked arithmetic are used throughout.
//!    Output capacity is checked before retaining a terminal path.
//!    Zero-limit behavior is explicit: zero limits fail closed before or on the first
//!    relevant event.
//!    All returned entries in a batch are counted toward `max_total_entries`, including
//!    entries later skipped (regular files, symlinks, other non-directories).
//!    Whole-walk checks occur after a bounded enumeration batch has already been allocated
//!    by `enumerate_dir`.
//!
//! 4. **Retained Paths**:
//!    Tracks logical path bytes retained in the pending traversal collection (queue) and
//!    output collection (`manifest_dirs`), with a caller-supplied test-only cap
//!    (`max_retained_path_bytes`). Capacity is checked before retaining new paths, and
//!    bytes are consistently debited upon dequeue.
//!    This is a logical path byte accounting guarantee, not a total heap-memory guarantee:
//!    temporary strings, enumeration batches, and collection overhead remain separate.
//!
//! 5. **Errors and Entry Policy**:
//!    - Initial `repos` `NotFound`: empty success `Ok(Vec::new())`.
//!    - Previously observed non-terminal directory `NotFound` on opening: `StorageError::io`.
//!    - Symlink directory entries: skipped during iteration.
//!    - Path-resolution rejection (`ResolutionRejected`): propagated as `StorageError::io`.
//!    - Non-directory entries (regular files, FIFOs, sockets): skipped during iteration.
//!    - Non-UTF-8 directory names or invalid `ObjectKey` composition: `StorageError::corrupt_data`.
//!    - Wrong-type `repos` root (`NotADirectory`): `StorageError::corrupt_data`.
//!    - Permission errors (`PermissionDenied`): `StorageError::permission_denied`.
//!    - Budget exhaustion or arithmetic overflow: `StorageError::backend`.
//!    - Raw directory components are validated before composition to ensure an injected
//!      name containing a slash or traversal token cannot become an unintended nested key.
//!      Components are not subject to whole-key drive-prefix checks or public OCI repository
//!      naming regexes, matching `ObjectKey` semantics.
//!
//! 6. **Terminal-Directory Limitation**:
//!    Terminal `manifests` directories are observed in a parent directory listing but are
//!    **not** reopened or enumerated by this seam. Their subsequent disappearance,
//!    replacement, permissions, or contents are not verified here. This seam does not
//!    claim that every observed disappearance is detected, nor does it guarantee complete
//!    reachability or point-in-time snapshot isolation.

use std::collections::VecDeque;

use async_trait::async_trait;
use storage_core::ObjectKey;
use storage_fs::{DirEntry, DirEnumerationLimits, FsDirError, FsMetadataReader};

use crate::storage::StorageError;

/// Caller-supplied limits for bounded repository directory discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryLimits {
    /// Maximum directory depth relative to `repos/` (root `repos/` is depth 0).
    pub max_depth: usize,
    /// Maximum number of directory enumerations performed during the walk.
    pub max_dir_enumerations: usize,
    /// Maximum cumulative directory entries inspected across all enumerations.
    pub max_total_entries: usize,
    /// Maximum number of terminal manifest directory ObjectKeys retained.
    pub max_manifest_dirs: usize,
    /// Maximum cumulative logical path bytes retained across pending traversal collection and output.
    pub max_retained_path_bytes: usize,
    /// Per-directory limits passed to each `enumerate_dir` call.
    pub per_dir_limits: DirEnumerationLimits,
}

/// Backward compatibility alias for test code.
#[allow(dead_code)]
pub(crate) type DiscoveryTestLimits = DiscoveryLimits;

impl DiscoveryLimits {
    /// Effectively unbounded limits preserving ambient traversal without artificial caps.
    pub(crate) fn unbounded() -> Self {
        Self {
            max_depth: usize::MAX,
            max_dir_enumerations: usize::MAX,
            max_total_entries: usize::MAX,
            max_manifest_dirs: usize::MAX,
            max_retained_path_bytes: usize::MAX,
            per_dir_limits: DirEnumerationLimits::new(usize::MAX, usize::MAX),
        }
    }
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self::unbounded()
    }
}

#[cfg(test)]
impl DiscoveryLimits {
    /// Test helper constructing permissive limits suitable for happy-path integration tests.
    pub(crate) fn test_default() -> Self {
        Self {
            max_depth: 32,
            max_dir_enumerations: 10_000,
            max_total_entries: 100_000,
            max_manifest_dirs: 10_000,
            max_retained_path_bytes: 1_000_000,
            per_dir_limits: DirEnumerationLimits::new(1000, 100_000),
        }
    }
}

/// Narrow test abstraction for descriptor-relative directory enumeration.
///
/// Enables deterministic test fakes and fault injection without requiring private
/// hooks in `storage-fs`.
#[async_trait]
pub(crate) trait DiscoveryDirEnumerator: Send + Sync {
    /// Enumerates entries within a single directory relative to the pinned storage root.
    async fn enumerate_dir(
        &self,
        target: Option<&ObjectKey>,
        limits: DirEnumerationLimits,
    ) -> Result<Vec<DirEntry>, FsDirError>;
}

#[async_trait]
impl DiscoveryDirEnumerator for FsMetadataReader {
    async fn enumerate_dir(
        &self,
        target: Option<&ObjectKey>,
        limits: DirEnumerationLimits,
    ) -> Result<Vec<DirEntry>, FsDirError> {
        self.enumerate_dir(target, limits).await
    }
}

/// Helper tracking retained logical path bytes in queue and output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetainedPathBytesTracker {
    current_bytes: usize,
    limit: usize,
}

impl RetainedPathBytesTracker {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            current_bytes: 0,
            limit,
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    pub(crate) fn charge(&mut self, additional: usize) -> Result<(), StorageError> {
        let new_total = self
            .current_bytes
            .checked_add(additional)
            .ok_or_else(|| StorageError::backend("arithmetic overflow in retained path bytes"))?;
        if new_total > self.limit {
            return Err(StorageError::backend(
                "discovery limit exceeded: max retained path bytes limit reached",
            ));
        }
        self.current_bytes = new_total;
        Ok(())
    }

    pub(crate) fn debit(&mut self, removed: usize) -> Result<(), StorageError> {
        self.current_bytes = self
            .current_bytes
            .checked_sub(removed)
            .ok_or_else(|| StorageError::backend("arithmetic underflow in retained path bytes"))?;
        Ok(())
    }
}

/// Helper computing child depth with checked arithmetic and depth limit check.
#[inline]
pub(crate) fn checked_increment_depth(
    current_depth: usize,
    max_depth: usize,
) -> Result<usize, StorageError> {
    let child_depth = current_depth
        .checked_add(1)
        .ok_or_else(|| StorageError::backend("arithmetic overflow computing traversal depth"))?;
    if child_depth > max_depth {
        return Err(StorageError::backend(
            "discovery limit exceeded: max traversal depth reached",
        ));
    }
    Ok(child_depth)
}

/// Helper incrementing directory enumeration count with capacity check.
#[inline]
pub(crate) fn checked_increment_enumerations(
    current: usize,
    max: usize,
) -> Result<usize, StorageError> {
    if current >= max {
        return Err(StorageError::backend(
            "discovery limit exceeded: max directory enumerations reached",
        ));
    }
    current
        .checked_add(1)
        .ok_or_else(|| StorageError::backend("arithmetic overflow in directory enumerations count"))
}

/// Helper incrementing total entries count with capacity check.
#[inline]
pub(crate) fn checked_increment_total_entries(
    current: usize,
    max: usize,
) -> Result<usize, StorageError> {
    let next = current
        .checked_add(1)
        .ok_or_else(|| StorageError::backend("arithmetic overflow in total entries count"))?;
    if next > max {
        return Err(StorageError::backend(
            "discovery limit exceeded: max total entries limit reached",
        ));
    }
    Ok(next)
}

/// Helper verifying manifest directories output capacity.
#[inline]
pub(crate) fn checked_check_manifest_dirs_capacity(
    current_len: usize,
    max: usize,
) -> Result<(), StorageError> {
    if current_len >= max {
        return Err(StorageError::backend(
            "discovery limit exceeded: max manifest directories limit reached",
        ));
    }
    Ok(())
}

/// Validates that a raw directory entry name represents a single, valid path component
/// before composing it into an [`ObjectKey`].
///
/// Enforces segment-level safety:
/// - Rejects empty component.
/// - Rejects `.` and `..` segments.
/// - Rejects path separators (`/`), backslashes (`\\`), and NUL bytes (`\0`).
/// - Rejects ASCII and Unicode control characters.
///
/// Does NOT reject Windows drive prefix patterns (e.g. `C:drive`) because `ObjectKey`
/// permits them in non-root positions (`repos/C:drive` is valid). Does NOT impose
/// public OCI repository-name formatting constraints.
fn validate_dir_component(component: &str) -> Result<(), StorageError> {
    if component.is_empty() {
        return Err(StorageError::corrupt_data(
            "directory component cannot be empty",
        ));
    }
    if component == "." || component == ".." {
        return Err(StorageError::corrupt_data(format!(
            "directory component cannot be dot or dot-dot segment: {component:?}"
        )));
    }
    if component.contains('/') {
        return Err(StorageError::corrupt_data(format!(
            "directory component cannot contain path separators: {component:?}"
        )));
    }
    if component.contains('\\') {
        return Err(StorageError::corrupt_data(format!(
            "directory component cannot contain backslashes: {component:?}"
        )));
    }
    if component.contains('\0') {
        return Err(StorageError::corrupt_data(format!(
            "directory component cannot contain NUL bytes: {component:?}"
        )));
    }
    if component.chars().any(|c| c.is_control()) {
        return Err(StorageError::corrupt_data(format!(
            "directory component cannot contain control characters: {component:?}"
        )));
    }
    Ok(())
}

/// Discovers terminal manifest-directory [`ObjectKey`]s beneath `repos/`.
///
/// Performs a bounded breadth-first traversal using descriptor-relative enumeration.
/// Enforces all caller-supplied bounds with checked arithmetic and inclusive checks.
pub(crate) async fn discover_manifest_dirs_impl(
    enumerator: &(impl DiscoveryDirEnumerator + ?Sized),
    limits: DiscoveryLimits,
) -> Result<Vec<ObjectKey>, StorageError> {
    let repos_key = ObjectKey::parse("repos")
        .map_err(|e| StorageError::corrupt_data(format!("invalid root object key: {e}")))?;
    let repos_len = repos_key.as_str().len();

    let mut path_bytes = RetainedPathBytesTracker::new(limits.max_retained_path_bytes);
    // Check logical path bytes capacity before retaining the initial repos root in pending queue.
    path_bytes.charge(repos_len)?;

    let mut queue = VecDeque::new();
    queue.push_back((repos_key, 0usize));

    let mut dir_enumerations: usize = 0;
    let mut total_entries: usize = 0;
    let mut manifest_dirs: Vec<ObjectKey> = Vec::new();

    while let Some((current_key, current_depth)) = queue.pop_front() {
        // Debit popped key from retained pending path bytes.
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
                if current_depth == 0 {
                    // Missing initial repos/ root: clean empty success.
                    // Loop will terminate because queue is now empty.
                    continue;
                } else {
                    return Err(StorageError::io(format!(
                        "observed directory disappeared before enumeration: {}",
                        current_key.as_str()
                    )));
                }
            }
            Err(FsDirError::NotADirectory { .. }) => {
                if current_depth == 0 {
                    return Err(StorageError::corrupt_data(
                        "target path is not a directory: repos",
                    ));
                } else {
                    return Err(StorageError::corrupt_data(format!(
                        "target path is not a directory: {}",
                        current_key.as_str()
                    )));
                }
            }
            Err(FsDirError::PermissionDenied { source, .. }) => {
                return Err(StorageError::permission_denied(source.to_string()));
            }
            Err(FsDirError::ResolutionRejected { source, .. }) => {
                return Err(StorageError::io(source.to_string()));
            }
            Err(FsDirError::LimitExceeded { reason }) => {
                return Err(StorageError::backend(format!(
                    "enumeration resource limit exceeded: {reason:?}"
                )));
            }
            Err(FsDirError::EntryDisappeared { name }) => {
                return Err(StorageError::io(format!(
                    "directory entry disappeared during type inspection: {name:?}"
                )));
            }
            Err(FsDirError::Io { source }) => {
                return Err(StorageError::io(source.to_string()));
            }
            Err(FsDirError::SyscallUnsupported(source)) => {
                return Err(StorageError::configuration(format!(
                    "openat2 is unavailable in this execution environment: {source}"
                )));
            }
            Err(FsDirError::PlatformUnsupported) => {
                return Err(StorageError::configuration(
                    "platform unsupported: descriptor-relative containment requires Linux openat2",
                ));
            }
            Err(FsDirError::RuntimeMissing(err)) => {
                return Err(StorageError::backend(format!(
                    "tokio runtime missing: {err}"
                )));
            }
            Err(FsDirError::TaskJoinFailed(err)) => {
                return Err(StorageError::backend(format!(
                    "blocking enumeration task join failed: {err}"
                )));
            }
            Err(other) => {
                return Err(StorageError::backend(format!(
                    "unexpected directory enumeration error: {other}"
                )));
            }
        };

        // Note: whole-walk checks occur after a bounded enumeration batch has already been allocated.
        for entry in entries {
            total_entries =
                checked_increment_total_entries(total_entries, limits.max_total_entries)?;

            // Entry policy: symlinks, regular files, other types, and any future variants are skipped.
            match entry.file_type() {
                storage_fs::DirEntryType::Directory => {}
                storage_fs::DirEntryType::Symlink
                | storage_fs::DirEntryType::Regular
                | storage_fs::DirEntryType::Other
                | _ => continue,
            }

            let name_str = match entry.name().to_str() {
                Some(s) => s,
                None => {
                    return Err(StorageError::corrupt_data(format!(
                        "unrepresentable non-UTF-8 directory name: {:?}",
                        entry.name()
                    )));
                }
            };

            // Validate raw single directory component before composition.
            validate_dir_component(name_str)?;

            // Apply depth limit to every directory child, including terminal manifests directories.
            let child_depth = checked_increment_depth(current_depth, limits.max_depth)?;

            let child_key_str = format!("{}/{name_str}", current_key.as_str());
            let child_key = ObjectKey::parse(&child_key_str).map_err(|err| {
                StorageError::corrupt_data(format!(
                    "composed path cannot form valid ObjectKey: {err}"
                ))
            })?;
            let child_key_len = child_key.as_str().len();

            if name_str == "manifests" {
                // Terminal leaf: check output capacity before retaining.
                checked_check_manifest_dirs_capacity(
                    manifest_dirs.len(),
                    limits.max_manifest_dirs,
                )?;

                path_bytes.charge(child_key_len)?;
                manifest_dirs.push(child_key);
            } else {
                // Non-manifest directory: enqueue for bounded traversal.
                path_bytes.charge(child_key_len)?;
                queue.push_back((child_key, child_depth));
            }
        }
    }

    manifest_dirs.sort();
    manifest_dirs.dedup();
    Ok(manifest_dirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageErrorKind;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};
    use storage_fs::{DirEntryType, LimitExceededReason};

    // --- Deterministic Fake Enumerator ---

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

    // --- Deterministic Fake Enumeration Tests ---

    #[tokio::test]
    async fn test_fake_missing_root_returns_empty_success_with_one_call() {
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(ObjectKey::parse("repos").unwrap()),
            Err(FsDirError::NotFound {
                path: Some("repos".to_string()),
            }),
        );

        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_dir_enumerations = 1;

        let result = discover_manifest_dirs_impl(&fake, limits).await.unwrap();
        assert!(
            result.is_empty(),
            "missing repos root must return empty success"
        );

        let calls = fake.calls();
        assert_eq!(
            calls.len(),
            1,
            "missing repos root requires exactly 1 attempted enumeration call"
        );
        assert_eq!(calls[0].0.as_ref().unwrap().as_str(), "repos");
    }

    #[tokio::test]
    async fn test_fake_zero_dir_enumerations_limit_fails_before_call() {
        let fake = RecordingFakeEnumerator::new();
        // No responses scripted; call must fail before calling enumerate_dir.
        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_dir_enumerations = 0;

        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .expect_err("max_dir_enumerations == 0 must fail immediately");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("max directory enumerations"));
            }
            other => panic!("expected Backend error, got {other:?}"),
        }

        assert_eq!(
            fake.calls().len(),
            0,
            "zero limit must not make any enumeration calls"
        );
    }

    #[tokio::test]
    async fn test_fake_dir_enumerations_limit_boundary_and_one_over() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let sub_key = ObjectKey::parse("repos/sub").unwrap();

        // 1. Boundary success: max_dir_enumerations = 2
        fake.script(
            Some(repos_key.clone()),
            Ok(vec![dir_entry("sub", DirEntryType::Directory)]),
        );
        fake.script(
            Some(sub_key.clone()),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );

        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_dir_enumerations = 2;

        let result = discover_manifest_dirs_impl(&fake, limits).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].as_str(), "repos/sub/manifests");
        assert_eq!(fake.calls().len(), 2);

        // 2. One-over failure: max_dir_enumerations = 1
        let fake2 = RecordingFakeEnumerator::new();
        fake2.script(
            Some(repos_key),
            Ok(vec![dir_entry("sub", DirEntryType::Directory)]),
        );

        let mut limits2 = DiscoveryTestLimits::test_default();
        limits2.max_dir_enumerations = 1;

        let err = discover_manifest_dirs_impl(&fake2, limits2)
            .await
            .expect_err("exceeding max_dir_enumerations must fail");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("max directory enumerations"));
            }
            other => panic!("expected Backend error, got {other:?}"),
        }
        assert_eq!(fake2.calls().len(), 1, "failed before second call");
    }

    #[tokio::test]
    async fn test_fake_depth_limits_zero_boundary_and_terminal_leaf_check() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();

        // 1. max_depth == 0 with empty repos succeeds
        fake.script(Some(repos_key.clone()), Ok(vec![]));
        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_depth = 0;
        let res = discover_manifest_dirs_impl(&fake, limits).await.unwrap();
        assert!(res.is_empty());

        // 2. max_depth == 0 with child directory fails immediately on child
        let fake2 = RecordingFakeEnumerator::new();
        fake2.script(
            Some(repos_key.clone()),
            Ok(vec![dir_entry("child", DirEntryType::Directory)]),
        );
        let err = discover_manifest_dirs_impl(&fake2, limits)
            .await
            .expect_err("depth 1 with max_depth 0 must fail");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));

        // 3. max_depth == 0 with terminal manifests fails (depth limit applies to terminal leaves too!)
        let fake3 = RecordingFakeEnumerator::new();
        fake3.script(
            Some(repos_key.clone()),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );
        let err = discover_manifest_dirs_impl(&fake3, limits)
            .await
            .expect_err("root-adjacent manifests at depth 1 with max_depth 0 must fail");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));

        // 4. max_depth == 1 permits root-adjacent manifests (depth 1 <= 1)
        let fake4 = RecordingFakeEnumerator::new();
        fake4.script(
            Some(repos_key),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );
        let mut limits1 = DiscoveryTestLimits::test_default();
        limits1.max_depth = 1;
        let res = discover_manifest_dirs_impl(&fake4, limits1).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].as_str(), "repos/manifests");
    }

    #[tokio::test]
    async fn test_fake_depth_limits_nested_boundary_and_one_over() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let a_key = ObjectKey::parse("repos/a").unwrap();

        fake.script(
            Some(repos_key.clone()),
            Ok(vec![dir_entry("a", DirEntryType::Directory)]),
        );
        fake.script(
            Some(a_key.clone()),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );

        // a is depth 1; manifests is depth 2.
        // max_depth == 1 must fail on manifests child
        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_depth = 1;

        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .expect_err("depth 2 manifests must fail under max_depth 1");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));

        // max_depth == 2 must succeed
        let fake2 = RecordingFakeEnumerator::new();
        fake2.script(
            Some(repos_key),
            Ok(vec![dir_entry("a", DirEntryType::Directory)]),
        );
        fake2.script(
            Some(a_key),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );
        limits.max_depth = 2;
        let res = discover_manifest_dirs_impl(&fake2, limits).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].as_str(), "repos/a/manifests");
    }

    #[tokio::test]
    async fn test_fake_total_entries_counter_counts_skipped_entries() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();

        // Batch contains 4 entries: 1 symlink, 1 regular file, 1 other, 1 directory
        fake.script(
            Some(repos_key),
            Ok(vec![
                dir_entry("symlink_entry", DirEntryType::Symlink),
                dir_entry("file_entry", DirEntryType::Regular),
                dir_entry("fifo_entry", DirEntryType::Other),
                dir_entry("manifests", DirEntryType::Directory),
            ]),
        );

        // max_total_entries = 4: boundary success
        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_total_entries = 4;
        let res = discover_manifest_dirs_impl(&fake, limits).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].as_str(), "repos/manifests");

        // max_total_entries = 3: fails on 4th entry even though earlier entries were skipped
        let fake2 = RecordingFakeEnumerator::new();
        fake2.script(
            Some(ObjectKey::parse("repos").unwrap()),
            Ok(vec![
                dir_entry("symlink_entry", DirEntryType::Symlink),
                dir_entry("file_entry", DirEntryType::Regular),
                dir_entry("fifo_entry", DirEntryType::Other),
                dir_entry("manifests", DirEntryType::Directory),
            ]),
        );
        let mut limits2 = DiscoveryTestLimits::test_default();
        limits2.max_total_entries = 3;
        let err = discover_manifest_dirs_impl(&fake2, limits2)
            .await
            .expect_err("max_total_entries exceeded by skipped entries");
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("max total entries"));
            }
            other => panic!("expected Backend error, got {other:?}"),
        }

        // max_total_entries = 0: fails on first entry
        let fake3 = RecordingFakeEnumerator::new();
        fake3.script(
            Some(ObjectKey::parse("repos").unwrap()),
            Ok(vec![dir_entry("symlink_entry", DirEntryType::Symlink)]),
        );
        let mut limits3 = DiscoveryTestLimits::test_default();
        limits3.max_total_entries = 0;
        let err = discover_manifest_dirs_impl(&fake3, limits3)
            .await
            .expect_err("max_total_entries == 0 must fail on first entry");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_fake_manifest_dirs_output_limit_boundary_and_zero() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let sub_key = ObjectKey::parse("repos/sub").unwrap();

        // 1. max_manifest_dirs == 0 fails on first terminal manifests
        fake.script(
            Some(repos_key.clone()),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );
        let mut limits0 = DiscoveryTestLimits::test_default();
        limits0.max_manifest_dirs = 0;
        let err = discover_manifest_dirs_impl(&fake, limits0)
            .await
            .expect_err("max_manifest_dirs == 0 must fail");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));

        // 2. max_manifest_dirs == 1 fails on second terminal manifests
        let fake2 = RecordingFakeEnumerator::new();
        fake2.script(
            Some(repos_key.clone()),
            Ok(vec![
                dir_entry("manifests", DirEntryType::Directory),
                dir_entry("sub", DirEntryType::Directory),
            ]),
        );
        fake2.script(
            Some(sub_key),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );
        let mut limits1 = DiscoveryTestLimits::test_default();
        limits1.max_manifest_dirs = 1;
        let err = discover_manifest_dirs_impl(&fake2, limits1)
            .await
            .expect_err("max_manifest_dirs == 1 must fail on second manifest dir");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));

        // 3. max_manifest_dirs == 2 succeeds for both
        let fake3 = RecordingFakeEnumerator::new();
        fake3.script(
            Some(repos_key),
            Ok(vec![
                dir_entry("manifests", DirEntryType::Directory),
                dir_entry("sub", DirEntryType::Directory),
            ]),
        );
        fake3.script(
            Some(ObjectKey::parse("repos/sub").unwrap()),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );
        let mut limits2 = DiscoveryTestLimits::test_default();
        limits2.max_manifest_dirs = 2;
        let res = discover_manifest_dirs_impl(&fake3, limits2).await.unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].as_str(), "repos/manifests");
        assert_eq!(res[1].as_str(), "repos/sub/manifests");
    }

    #[tokio::test]
    async fn test_fake_retained_path_bytes_limit_accounting_and_boundaries() {
        // "repos" has length 5.
        // 1. Cap < 5 fails before enqueueing repos
        let fake = RecordingFakeEnumerator::new();
        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_retained_path_bytes = 4;
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .expect_err("cap < 5 must fail immediately");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));

        // 2. Cap = 5: repos enqueued (5 bytes). When repos is popped, 0 bytes retained.
        // Child "repos/manifests" has 15 bytes. 0 + 15 = 15 > 5 -> fails!
        let fake2 = RecordingFakeEnumerator::new();
        fake2.script(
            Some(ObjectKey::parse("repos").unwrap()),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );
        limits.max_retained_path_bytes = 5;
        let err = discover_manifest_dirs_impl(&fake2, limits)
            .await
            .expect_err("child exceeds retained path bytes cap");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));

        // 3. Cap = 15: boundary success for repos/manifests (15 bytes <= 15 bytes)
        let fake3 = RecordingFakeEnumerator::new();
        fake3.script(
            Some(ObjectKey::parse("repos").unwrap()),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );
        limits.max_retained_path_bytes = 15;
        let res = discover_manifest_dirs_impl(&fake3, limits).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].as_str(), "repos/manifests");
    }

    #[tokio::test]
    async fn test_fake_retained_path_bytes_siblings_and_retained_output_exact_boundary() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let sibling_a_key = ObjectKey::parse("repos/sibling_a").unwrap();
        let sibling_b_key = ObjectKey::parse("repos/sibling_b").unwrap();

        // repos (5 bytes)
        // Entries of repos:
        // - manifests (15 bytes: "repos/manifests", terminal output)
        // - sibling_a (15 bytes: "repos/sibling_a", enqueued in queue)
        // - sibling_b (15 bytes: "repos/sibling_b", enqueued in queue)
        //
        // Peak combined bytes during repos processing:
        // repos popped (-5, now 0)
        // repos/manifests retained in output (+15 -> 15)
        // repos/sibling_a enqueued (+15 -> 30)
        // repos/sibling_b enqueued (+15 -> 45)
        // Peak combined bytes in queue + output = 45 bytes!
        //
        // Next, sibling_a is dequeued:
        // debit 15 -> retained drops to 30 (15 output + 15 in queue).
        // sibling_a returns empty entries vec![].
        //
        // Next, sibling_b is dequeued:
        // debit 15 -> retained drops to 15 (15 output + 0 in queue).
        // Note: repos/manifests (15 bytes) continues charging while sibling_b is processed!
        // sibling_b returns manifests (terminal leaf: "repos/sibling_b/manifests", len 25).
        // retained increases by 25: 15 + 25 = 40 bytes (<= 45).
        //
        // 1. Exact boundary success at max_retained_path_bytes = 45:
        fake.script(
            Some(repos_key.clone()),
            Ok(vec![
                dir_entry("manifests", DirEntryType::Directory),
                dir_entry("sibling_a", DirEntryType::Directory),
                dir_entry("sibling_b", DirEntryType::Directory),
            ]),
        );
        fake.script(Some(sibling_a_key.clone()), Ok(vec![]));
        fake.script(
            Some(sibling_b_key.clone()),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );

        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_retained_path_bytes = 45;

        let res = discover_manifest_dirs_impl(&fake, limits).await.unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].as_str(), "repos/manifests");
        assert_eq!(res[1].as_str(), "repos/sibling_b/manifests");
        assert_eq!(fake.calls().len(), 3);

        // 2. One-byte-under failure at max_retained_path_bytes = 44:
        // Fails while enqueueing sibling_b (when combined reaches 45 > 44).
        let fake2 = RecordingFakeEnumerator::new();
        fake2.script(
            Some(repos_key),
            Ok(vec![
                dir_entry("manifests", DirEntryType::Directory),
                dir_entry("sibling_a", DirEntryType::Directory),
                dir_entry("sibling_b", DirEntryType::Directory),
            ]),
        );
        fake2.script(Some(sibling_a_key), Ok(vec![]));
        fake2.script(
            Some(sibling_b_key),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );

        let mut limits_under = DiscoveryTestLimits::test_default();
        limits_under.max_retained_path_bytes = 44;

        let err = discover_manifest_dirs_impl(&fake2, limits_under)
            .await
            .expect_err("44 bytes limit must fail when combined retained bytes reaches 45");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("max retained path bytes"));
            }
            other => panic!("expected Backend error, got {other:?}"),
        }

        // Must have failed during repos enumeration; neither sibling_a nor sibling_b was called!
        assert_eq!(
            fake2.calls().len(),
            1,
            "failed before sibling calls could be issued"
        );
    }

    #[tokio::test]
    async fn test_fake_observed_child_disappearance_returns_io() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let ghost_key = ObjectKey::parse("repos/ghost_repo").unwrap();

        // repos listing observes ghost_repo
        fake.script(
            Some(repos_key),
            Ok(vec![dir_entry("ghost_repo", DirEntryType::Directory)]),
        );
        // ghost_repo opening fails with NotFound
        fake.script(
            Some(ghost_key),
            Err(FsDirError::NotFound {
                path: Some("repos/ghost_repo".to_string()),
            }),
        );

        let limits = DiscoveryTestLimits::test_default();
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .expect_err("disappeared observed directory must fail with Io");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(message.contains(
                    "observed directory disappeared before enumeration: repos/ghost_repo"
                ));
            }
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_fake_atomic_failure_on_error_after_earlier_discoveries() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let err_key = ObjectKey::parse("repos/err_dir").unwrap();

        fake.script(
            Some(repos_key),
            Ok(vec![
                dir_entry("manifests", DirEntryType::Directory),
                dir_entry("err_dir", DirEntryType::Directory),
            ]),
        );
        fake.script(
            Some(err_key),
            Err(FsDirError::Io {
                source: std::io::Error::new(std::io::ErrorKind::Other, "disk I/O error"),
            }),
        );

        let limits = DiscoveryTestLimits::test_default();
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .expect_err("must fail completely, zero partial success");

        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Io,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn test_fake_failure_after_earlier_discovery_due_to_budget_limit_no_further_calls() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let sub1_key = ObjectKey::parse("repos/sub1").unwrap();
        let sub2_key = ObjectKey::parse("repos/sub2").unwrap();

        // repos discovers:
        // - terminal manifests ("repos/manifests", retained in output)
        // - sub1 (enqueued)
        // - sub2 (enqueued)
        fake.script(
            Some(repos_key),
            Ok(vec![
                dir_entry("manifests", DirEntryType::Directory),
                dir_entry("sub1", DirEntryType::Directory),
                dir_entry("sub2", DirEntryType::Directory),
            ]),
        );
        // sub1 returns empty
        fake.script(Some(sub1_key), Ok(vec![]));
        // sub2 has scripted response, but must NEVER be called because budget is exhausted!
        fake.script(
            Some(sub2_key),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );

        // Budget: exactly 2 directory enumerations allowed.
        // Call 1: repos
        // Call 2: sub1
        // Step 3: before calling sub2, capacity check trips!
        let mut limits = DiscoveryTestLimits::test_default();
        limits.max_dir_enumerations = 2;

        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .expect_err("must fail when dir enumeration limit is reached");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("max directory enumerations"));
            }
            other => panic!("expected Backend error, got {other:?}"),
        }

        // Verify that NO partial result was returned and NO further call was made for sub2!
        let calls = fake.calls();
        assert_eq!(
            calls.len(),
            2,
            "must stop immediately on budget limit with no subsequent calls"
        );
        assert_eq!(calls[0].0.as_ref().unwrap().as_str(), "repos");
        assert_eq!(calls[1].0.as_ref().unwrap().as_str(), "repos/sub1");
    }

    #[tokio::test]
    async fn test_fake_terminal_manifests_leaves_never_opened_or_traversed() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let app_key = ObjectKey::parse("repos/app").unwrap();

        fake.script(
            Some(repos_key),
            Ok(vec![
                dir_entry("manifests", DirEntryType::Directory),
                dir_entry("app", DirEntryType::Directory),
            ]),
        );
        fake.script(
            Some(app_key),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );

        let limits = DiscoveryTestLimits::test_default();
        let res = discover_manifest_dirs_impl(&fake, limits).await.unwrap();
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].as_str(), "repos/app/manifests");
        assert_eq!(res[1].as_str(), "repos/manifests");

        // Verify that NO calls were made for repos/manifests or repos/app/manifests!
        let calls = fake.calls();
        assert_eq!(calls.len(), 2);
        let called_keys: Vec<&str> = calls
            .iter()
            .map(|(k, _)| k.as_ref().unwrap().as_str())
            .collect();
        assert_eq!(called_keys, vec!["repos", "repos/app"]);
    }

    #[tokio::test]
    async fn test_fake_invalid_injected_components_rejected_with_corrupt_data() {
        let bad_components = [
            "nested/dir",
            "nested\\dir",
            "nul\0byte",
            ".",
            "..",
            "",
            "ctrl\x07bell",
            "ctrl\nnewline",
        ];

        for bad in bad_components {
            let fake = RecordingFakeEnumerator::new();
            fake.script(
                Some(ObjectKey::parse("repos").unwrap()),
                Ok(vec![dir_entry(bad, DirEntryType::Directory)]),
            );

            let limits = DiscoveryTestLimits::test_default();
            let err = discover_manifest_dirs_impl(&fake, limits)
                .await
                .unwrap_err();

            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, StorageErrorKind::CorruptData, "for {bad:?}");
                    assert!(
                        message.contains("directory component")
                            || message.contains("cannot form valid ObjectKey"),
                        "for {bad:?}: {message}"
                    );
                }
                other => panic!("expected CorruptData for {bad:?}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_fake_component_with_colon_allowed_and_preserved() {
        let fake = RecordingFakeEnumerator::new();
        let repos_key = ObjectKey::parse("repos").unwrap();
        let c_drive_key = ObjectKey::parse("repos/C:drive").unwrap();

        fake.script(
            Some(repos_key),
            Ok(vec![dir_entry("C:drive", DirEntryType::Directory)]),
        );
        fake.script(
            Some(c_drive_key),
            Ok(vec![dir_entry("manifests", DirEntryType::Directory)]),
        );

        let limits = DiscoveryTestLimits::test_default();
        let res = discover_manifest_dirs_impl(&fake, limits).await.unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(
            res[0].as_str(),
            "repos/C:drive/manifests",
            "repos/C:drive/manifests must be representable and preserved byte-for-byte"
        );
    }

    #[test]
    fn test_accounting_helpers_overflow_and_underflow_handling() {
        // 1. RetainedPathBytesTracker charge overflow
        let mut tracker = RetainedPathBytesTracker::new(usize::MAX);
        tracker.charge(1).unwrap();
        let err = tracker.charge(usize::MAX).unwrap_err();
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("arithmetic overflow in retained path bytes"));
            }
            other => panic!("expected Backend overflow, got {other:?}"),
        }

        // 2. RetainedPathBytesTracker debit underflow
        let mut empty_tracker = RetainedPathBytesTracker::new(100);
        let err = empty_tracker.debit(1).unwrap_err();
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("arithmetic underflow in retained path bytes"));
            }
            other => panic!("expected Backend underflow, got {other:?}"),
        }

        // 3. checked_increment_depth overflow
        let err = checked_increment_depth(usize::MAX, usize::MAX).unwrap_err();
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("arithmetic overflow computing traversal depth"));
            }
            other => panic!("expected Backend overflow, got {other:?}"),
        }

        // 4. checked_increment_total_entries overflow
        let err = checked_increment_total_entries(usize::MAX, usize::MAX).unwrap_err();
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("arithmetic overflow in total entries count"));
            }
            other => panic!("expected Backend overflow, got {other:?}"),
        }

        // Note on checked_increment_enumerations:
        // checked_increment_enumerations checks `current >= max` first. If current == usize::MAX,
        // it fails with capacity exceeded. An arithmetic overflow branch would only execute if
        // max > usize::MAX, which is impossible for the usize type. The capacity check guarantees
        // overflow can never occur in checked_increment_enumerations.
    }

    #[tokio::test]
    async fn test_fake_non_utf8_directory_rejected_with_corrupt_data() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let fake = RecordingFakeEnumerator::new();
            let non_utf8_os = std::ffi::OsStr::from_bytes(b"bad_\xff\xfe").to_os_string();
            fake.script(
                Some(ObjectKey::parse("repos").unwrap()),
                Ok(vec![DirEntry::new(non_utf8_os, DirEntryType::Directory)]),
            );

            let limits = DiscoveryTestLimits::test_default();
            let err = discover_manifest_dirs_impl(&fake, limits)
                .await
                .expect_err("non-UTF-8 directory name must fail");

            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, StorageErrorKind::CorruptData);
                    assert!(message.contains("non-UTF-8"));
                }
                other => panic!("expected CorruptData, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_fake_explicit_fs_dir_error_mappings() {
        let repos_key = ObjectKey::parse("repos").unwrap();
        let sub_key = ObjectKey::parse("repos/sub").unwrap();
        let limits = DiscoveryTestLimits::test_default();

        // 1. NotADirectory on repos -> CorruptData("target path is not a directory: repos")
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(repos_key.clone()),
            Err(FsDirError::NotADirectory {
                path: Some("repos".to_string()),
            }),
        );
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .unwrap_err();
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::CorruptData);
                assert_eq!(message, "target path is not a directory: repos");
            }
            other => panic!("expected CorruptData, got {other:?}"),
        }

        // 2. PermissionDenied -> PermissionDenied
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(repos_key.clone()),
            Err(FsDirError::PermissionDenied {
                path: Some("repos".to_string()),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied"),
            }),
        );
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::PermissionDenied,
                ..
            }
        ));

        // 3. ResolutionRejected -> Io
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(repos_key.clone()),
            Err(FsDirError::ResolutionRejected {
                raw_os_error: libc::ELOOP,
                source: std::io::Error::from_raw_os_error(libc::ELOOP),
            }),
        );
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Io,
                ..
            }
        ));

        // 4. LimitExceeded -> Backend
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(repos_key.clone()),
            Err(FsDirError::LimitExceeded {
                reason: LimitExceededReason::MaxEntries(10),
            }),
        );
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));

        // 5. EntryDisappeared -> Io
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(repos_key.clone()),
            Err(FsDirError::EntryDisappeared {
                name: OsString::from("ghost"),
            }),
        );
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Io,
                ..
            }
        ));

        // 6. SyscallUnsupported -> Configuration
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(repos_key.clone()),
            Err(FsDirError::SyscallUnsupported(
                std::io::Error::from_raw_os_error(libc::ENOSYS),
            )),
        );
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Configuration,
                ..
            }
        ));

        // 7. PlatformUnsupported -> Configuration
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(repos_key.clone()),
            Err(FsDirError::PlatformUnsupported),
        );
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Configuration,
                ..
            }
        ));

        // 8. NotADirectory on child -> CorruptData
        let fake = RecordingFakeEnumerator::new();
        fake.script(
            Some(repos_key),
            Ok(vec![dir_entry("sub", DirEntryType::Directory)]),
        );
        fake.script(
            Some(sub_key),
            Err(FsDirError::NotADirectory {
                path: Some("repos/sub".to_string()),
            }),
        );
        let err = discover_manifest_dirs_impl(&fake, limits)
            .await
            .unwrap_err();
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::CorruptData);
                assert!(message.contains("target path is not a directory: repos/sub"));
            }
            other => panic!("expected CorruptData, got {other:?}"),
        }
    }

    // --- Linux-Gated Real Filesystem Tests ---

    #[cfg(target_os = "linux")]
    fn create_test_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let fixture = tempfile::tempdir().expect("create tempdir");
        let root = fixture.path().join("storage_root");
        std::fs::create_dir_all(&root).expect("create storage root");
        (fixture, root)
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_repo_discovery_real_fs_ordinary_nested_and_reserved_ancestor_layouts() {
        let (_fixture, root) = create_test_root();

        // Layout:
        // repos/manifests (root-adjacent)
        // repos/library/ubuntu/manifests (ordinary nested)
        // repos/tags/sub1/sub2/manifests (reserved ancestor "tags")
        // repos/blobs/internal/manifests (reserved ancestor "blobs")
        // repos/meta/some_other_dir (no manifests)
        let root_manifests = root.join("repos").join("manifests");
        let ubuntu_manifests = root
            .join("repos")
            .join("library")
            .join("ubuntu")
            .join("manifests");
        let tags_manifests = root
            .join("repos")
            .join("tags")
            .join("sub1")
            .join("sub2")
            .join("manifests");
        let blobs_manifests = root
            .join("repos")
            .join("blobs")
            .join("internal")
            .join("manifests");
        let meta_dir = root.join("repos").join("meta").join("some_other_dir");

        std::fs::create_dir_all(&root_manifests).unwrap();
        std::fs::create_dir_all(&ubuntu_manifests).unwrap();
        std::fs::create_dir_all(&tags_manifests).unwrap();
        std::fs::create_dir_all(&blobs_manifests).unwrap();
        std::fs::create_dir_all(&meta_dir).unwrap();

        let reader = FsMetadataReader::open(&root).expect("open reader");
        let limits = DiscoveryTestLimits::test_default();

        let results = discover_manifest_dirs_impl(&reader, limits).await.unwrap();

        let expected = vec![
            "repos/blobs/internal/manifests",
            "repos/library/ubuntu/manifests",
            "repos/manifests",
            "repos/tags/sub1/sub2/manifests",
        ];
        let actual: Vec<&str> = results.iter().map(|k| k.as_str()).collect();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_repo_discovery_real_fs_terminal_manifests_leaf_non_recursion() {
        let (_fixture, root) = create_test_root();

        let app_manifests = root.join("repos").join("app").join("manifests");
        let nested_inside_manifests = app_manifests.join("nested_manifests_dir");
        std::fs::create_dir_all(&nested_inside_manifests).unwrap();

        let reader = FsMetadataReader::open(&root).expect("open reader");
        let limits = DiscoveryTestLimits::test_default();

        let results = discover_manifest_dirs_impl(&reader, limits).await.unwrap();

        // Only repos/app/manifests is returned; nested_manifests_dir is NOT traversed
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_str(), "repos/app/manifests");
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_repo_discovery_real_fs_symlink_entries_skipped_vs_path_symlink_failure() {
        let (_fixture, root) = create_test_root();

        let repos_dir = root.join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        // 1. Symlink entry within repos/ -> skipped cleanly
        let external_target = root.join("external_target");
        std::fs::create_dir_all(&external_target).unwrap();
        std::os::unix::fs::symlink(&external_target, repos_dir.join("symlink_repo")).unwrap();

        // Real repo with manifests
        let valid_manifests = repos_dir.join("valid_repo").join("manifests");
        std::fs::create_dir_all(&valid_manifests).unwrap();

        let reader = FsMetadataReader::open(&root).expect("open reader");
        let limits = DiscoveryTestLimits::test_default();

        let results = discover_manifest_dirs_impl(&reader, limits).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_str(), "repos/valid_repo/manifests");

        // 2. Path symlink: repos itself is a symlink -> openat2 ResolutionRejected -> Io
        let (_fixture2, root2) = create_test_root();
        let outside_repos = root2.join("outside_repos");
        std::fs::create_dir_all(&outside_repos).unwrap();
        std::os::unix::fs::symlink(&outside_repos, root2.join("repos")).unwrap();

        let reader2 = FsMetadataReader::open(&root2).expect("open reader");
        let err = discover_manifest_dirs_impl(&reader2, limits)
            .await
            .expect_err("path symlink must fail with ResolutionRejected -> Io");

        assert!(matches!(
            err,
            StorageError::Internal {
                kind: StorageErrorKind::Io,
                ..
            }
        ));
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_repo_discovery_real_fs_non_utf8_directory_rejection() {
        use std::os::unix::ffi::OsStrExt;

        let (_fixture, root) = create_test_root();
        let repos_dir = root.join("repos");
        std::fs::create_dir_all(&repos_dir).unwrap();

        let non_utf8_name = std::ffi::OsStr::from_bytes(b"non_utf8_\xff\xfe");
        let non_utf8_dir = repos_dir.join(non_utf8_name);
        std::fs::create_dir_all(&non_utf8_dir).unwrap();

        let reader = FsMetadataReader::open(&root).expect("open reader");
        let limits = DiscoveryTestLimits::test_default();

        let err = discover_manifest_dirs_impl(&reader, limits)
            .await
            .expect_err("non-UTF-8 directory must fail closed with CorruptData");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::CorruptData);
                assert!(message.contains("non-UTF-8"));
            }
            other => panic!("expected CorruptData, got {other:?}"),
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_repo_discovery_real_fs_wrong_type_root_returns_corrupt_data() {
        let (_fixture, root) = create_test_root();
        // repos is a regular file instead of a directory
        std::fs::write(root.join("repos"), b"not a directory").unwrap();

        let reader = FsMetadataReader::open(&root).expect("open reader");
        let limits = DiscoveryTestLimits::test_default();

        let err = discover_manifest_dirs_impl(&reader, limits)
            .await
            .expect_err("wrong-type repos root must fail with CorruptData");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::CorruptData);
                assert_eq!(message, "target path is not a directory: repos");
            }
            other => panic!("expected CorruptData, got {other:?}"),
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_repo_discovery_real_fs_per_directory_exhaustion() {
        let (_fixture, root) = create_test_root();
        let repos_dir = root.join("repos");
        std::fs::create_dir_all(repos_dir.join("repo1")).unwrap();
        std::fs::create_dir_all(repos_dir.join("repo2")).unwrap();
        std::fs::create_dir_all(repos_dir.join("repo3")).unwrap();

        let reader = FsMetadataReader::open(&root).expect("open reader");
        let mut limits = DiscoveryTestLimits::test_default();
        // Set per-dir limit to 2 entries, while repos has 3 entries
        limits.per_dir_limits = DirEnumerationLimits::new(2, 100_000);

        let err = discover_manifest_dirs_impl(&reader, limits)
            .await
            .expect_err("per-directory limit exhaustion must fail closed with Backend");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert!(message.contains("MaxEntries"));
            }
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_repo_discovery_real_fs_pinned_root_across_replacement() {
        let (fixture, root) = create_test_root();
        let orig_manifests = root.join("repos").join("orig_repo").join("manifests");
        std::fs::create_dir_all(&orig_manifests).unwrap();

        let reader = FsMetadataReader::open(&root).expect("open reader");
        let limits = DiscoveryTestLimits::test_default();

        // 1. Initial discovery observes orig_repo
        let res1 = discover_manifest_dirs_impl(&reader, limits).await.unwrap();
        assert_eq!(res1.len(), 1);
        assert_eq!(res1[0].as_str(), "repos/orig_repo/manifests");

        // 2. Replace storage_root directory on host filesystem
        let renamed = fixture.path().join("storage_root_old");
        std::fs::rename(&root, &renamed).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let repl_manifests = root.join("repos").join("repl_repo").join("manifests");
        std::fs::create_dir_all(&repl_manifests).unwrap();

        // 3. Pinned reader continues resolving relative to original file descriptor
        let res_pinned = discover_manifest_dirs_impl(&reader, limits).await.unwrap();
        assert_eq!(res_pinned.len(), 1);
        assert_eq!(
            res_pinned[0].as_str(),
            "repos/orig_repo/manifests",
            "pinned reader must observe original hierarchy across path replacement"
        );
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
    async fn test_repo_discovery_real_fs_permission_denied_restoration_guard() {
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;

        if unsafe { libc::geteuid() } == 0 {
            panic!("ineffective permissions: running as root (UID 0) bypasses DAC");
        }

        let (_fixture, root) = create_test_root();
        let restricted = root.join("repos").join("restricted");
        std::fs::create_dir_all(&restricted).unwrap();

        let orig_perms = std::fs::metadata(&restricted).unwrap().permissions();

        struct ScopedPermReset<'a> {
            path: &'a Path,
            original_permissions: std::fs::Permissions,
        }

        impl<'a> Drop for ScopedPermReset<'a> {
            fn drop(&mut self) {
                if let Err(err) =
                    std::fs::set_permissions(self.path, self.original_permissions.clone())
                {
                    if std::thread::panicking() {
                        eprintln!(
                            "ScopedPermReset: failed to restore permissions on {:?} during unwinding: {err}",
                            self.path
                        );
                    } else {
                        panic!(
                            "ScopedPermReset: failed to restore permissions on {:?}: {err}",
                            self.path
                        );
                    }
                }
            }
        }

        {
            let _guard = ScopedPermReset {
                path: &restricted,
                original_permissions: orig_perms.clone(),
            };

            let mut denied_perms = orig_perms;
            denied_perms.set_mode(0o000);
            std::fs::set_permissions(&restricted, denied_perms).expect("chmod 000");

            let reader = FsMetadataReader::open(&root).expect("open reader");
            let limits = DiscoveryTestLimits::test_default();

            let err = discover_manifest_dirs_impl(&reader, limits)
                .await
                .expect_err("permission denied must fail");

            assert!(matches!(
                err,
                StorageError::Internal {
                    kind: StorageErrorKind::PermissionDenied,
                    ..
                }
            ));
        }

        // Guard dropped: verify permissions restored and can be accessed
        assert!(std::fs::metadata(&restricted).is_ok());
    }
}
