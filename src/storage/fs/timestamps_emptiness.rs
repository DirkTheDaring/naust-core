//! Contained filesystem storage-emptiness inspection for `naust`.
//!
//! # Architecture and Scope
//!
//! Implements the subtree probes of `FsStorage::is_storage_empty` (formerly
//! the ambient recursive `fs_dir_has_any_entry`). All filesystem observation
//! resolves beneath the shared pinned root descriptor via
//! [`storage_fs::FsMetadataReader`]: directory enumeration through
//! `enumerate_dir` (`openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`).
//! Blocking work executes off async executor threads inside the dependency's
//! `spawn_blocking` offload.
//!
//! (The repository-timestamp derivation that previously shared this module
//! moved to the shared backend-neutral `repo_timestamp_domain` in
//! STORAGE-LAYER-MIGRATION Phase 8; its frozen contract is documented and
//! pinned there.)
//!
//! # Preserved Semantics (emptiness)
//!
//! - A missing probed subtree contributes "empty"; any regular or
//!   non-directory entry anywhere in a probed subtree makes storage
//!   non-empty (short-circuit).
//! - A child directory that vanishes between enumeration and descent
//!   contributes "empty" for that branch.
//!
//! # Intentional Containment and Failure-Handling Changes (test-frozen)
//!
//! - Pinned-root resolution: root pathname replacement does not redirect the
//!   probes.
//! - Symlinked probed areas are rejected (fail closed) instead of silently
//!   followed; a symlink ENTRY inside a probed area still counts as an entry
//!   without being followed or decoded.
//! - No unsafe incomplete success: enumeration failures propagate instead of
//!   presenting as "empty" (an incorrect "empty" would gate destructive
//!   startup decisions).
//!
//! # Resource Costs (no new ceilings)
//!
//! Per-call `DirEnumerationLimits` are effectively unbounded, matching the
//! ambient baseline; the probe holds one entry batch per enumerated
//! directory and a breadth-first queue of pending directory keys.

use std::collections::VecDeque;

use async_trait::async_trait;
use storage_core::ObjectKey;
use storage_fs::{DirEntry, DirEntryType, DirEnumerationLimits, FsDirError, FsMetadataReader};

use super::catalog_discovery::map_contained_dir_error;
use crate::storage::StorageError;

/// Unbounded per-call enumeration limits preserving the ambient baseline.
fn unbounded_dir_limits() -> DirEnumerationLimits {
    DirEnumerationLimits::new(usize::MAX, usize::MAX)
}

/// Narrow seam over the pinned reader operations used by timestamp and
/// emptiness inspection, enabling deterministic fault-injection fakes for
/// failures real filesystems cannot reproduce reliably.
#[async_trait]
pub(crate) trait RepoMetaInspector: Send + Sync {
    /// Enumerates entries of one directory relative to the pinned storage root.
    async fn enumerate_dir(
        &self,
        target: Option<&ObjectKey>,
        limits: DirEnumerationLimits,
    ) -> Result<Vec<DirEntry>, FsDirError>;
}

#[async_trait]
impl RepoMetaInspector for FsMetadataReader {
    async fn enumerate_dir(
        &self,
        target: Option<&ObjectKey>,
        limits: DirEnumerationLimits,
    ) -> Result<Vec<DirEntry>, FsDirError> {
        FsMetadataReader::enumerate_dir(self, target, limits).await
    }
}

/// Determines whether a storage subtree beneath the pinned root contains any
/// non-directory entry, preserving the legacy `fs_dir_has_any_entry` contract
/// (see module docs). Returns `true` as soon as one qualifying entry is
/// observed; an unreadable or non-descendable area fails closed instead of
/// contributing a false empty result.
pub(crate) async fn contained_subtree_has_any_entry(
    ops: &(impl RepoMetaInspector + ?Sized),
    subtree: &str,
) -> Result<bool, StorageError> {
    let root_key = ObjectKey::parse(subtree).map_err(|e| {
        StorageError::internal_invariant(format!("invalid subtree key {subtree:?}: {e}"))
    })?;

    let mut queue: VecDeque<ObjectKey> = VecDeque::new();
    queue.push_back(root_key);

    while let Some(current_key) = queue.pop_front() {
        let entries = match ops
            .enumerate_dir(Some(&current_key), unbounded_dir_limits())
            .await
        {
            Ok(entries) => entries,
            Err(FsDirError::NotFound { .. }) => {
                // Missing subtree root or a directory removed after being
                // observed: both count as empty contributions (legacy).
                continue;
            }
            Err(other) => return Err(map_contained_dir_error(other, current_key.as_str())),
        };

        for entry in entries {
            if entry.file_type() != DirEntryType::Directory {
                // Any non-directory entry makes storage non-empty; no name
                // decoding is required for this conclusion.
                return Ok(true);
            }

            let Some(name) = entry.name().to_str() else {
                return Err(StorageError::corrupt_data(format!(
                    "non-UTF-8 directory name in {} prevents contained emptiness inspection: {:?}",
                    current_key.as_str(),
                    entry.name()
                )));
            };
            let child_str = format!("{}/{name}", current_key.as_str());
            let child_key = ObjectKey::parse(&child_str).map_err(|err| {
                StorageError::corrupt_data(format!(
                    "directory name in {} cannot form a contained object key: {name:?}: {err}",
                    current_key.as_str()
                ))
            })?;
            queue.push_back(child_key);
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageErrorKind;
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};

    struct RecordingFakeInspector {
        dir_calls: Arc<Mutex<Vec<Option<ObjectKey>>>>,
        dir_responses:
            Arc<Mutex<HashMap<Option<ObjectKey>, VecDeque<Result<Vec<DirEntry>, FsDirError>>>>>,
    }

    impl RecordingFakeInspector {
        fn new() -> Self {
            Self {
                dir_calls: Arc::new(Mutex::new(Vec::new())),
                dir_responses: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn script_dir(
            &self,
            target: Option<ObjectKey>,
            response: Result<Vec<DirEntry>, FsDirError>,
        ) {
            self.dir_responses
                .lock()
                .unwrap()
                .entry(target)
                .or_default()
                .push_back(response);
        }

        fn dir_calls(&self) -> Vec<Option<ObjectKey>> {
            self.dir_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl RepoMetaInspector for RecordingFakeInspector {
        async fn enumerate_dir(
            &self,
            target: Option<&ObjectKey>,
            _limits: DirEnumerationLimits,
        ) -> Result<Vec<DirEntry>, FsDirError> {
            self.dir_calls.lock().unwrap().push(target.cloned());
            let mut responses = self.dir_responses.lock().unwrap();
            let queue = responses
                .get_mut(&target.cloned())
                .unwrap_or_else(|| panic!("unexpected enumerate_dir call with target: {target:?}"));
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted dir responses for: {target:?}"))
        }
    }

    fn dir_entry(name: &str, file_type: DirEntryType) -> DirEntry {
        DirEntry::new(OsString::from(name), file_type)
    }

    fn key(s: &str) -> ObjectKey {
        ObjectKey::parse(s).unwrap()
    }

    // ========================================================================
    // Emptiness: fake-driven contract tests
    // ========================================================================

    #[tokio::test]
    async fn test_fake_emptiness_missing_root_and_empty_nested_dirs() {
        let fake = RecordingFakeInspector::new();
        fake.script_dir(
            Some(key("blobs")),
            Err(FsDirError::NotFound {
                path: Some("blobs".to_string()),
            }),
        );
        assert!(
            !contained_subtree_has_any_entry(&fake, "blobs")
                .await
                .unwrap()
        );

        // Nested empty directories only -> still empty, fully descended.
        let fake = RecordingFakeInspector::new();
        fake.script_dir(
            Some(key("uploads")),
            Ok(vec![dir_entry("a", DirEntryType::Directory)]),
        );
        fake.script_dir(
            Some(key("uploads/a")),
            Ok(vec![dir_entry("b", DirEntryType::Directory)]),
        );
        fake.script_dir(Some(key("uploads/a/b")), Ok(vec![]));
        assert!(
            !contained_subtree_has_any_entry(&fake, "uploads")
                .await
                .unwrap()
        );
        assert_eq!(fake.dir_calls().len(), 3);
    }

    #[tokio::test]
    async fn test_fake_emptiness_early_not_empty_on_any_nondir_entry() {
        for ft in [
            DirEntryType::Regular,
            DirEntryType::Symlink,
            DirEntryType::Other,
        ] {
            let fake = RecordingFakeInspector::new();
            fake.script_dir(
                Some(key("quarantine")),
                Ok(vec![
                    dir_entry("hit", ft),
                    dir_entry("never_descended", DirEntryType::Directory),
                ]),
            );
            assert!(
                contained_subtree_has_any_entry(&fake, "quarantine")
                    .await
                    .unwrap(),
                "non-directory entry type {ft:?} must conclude non-empty"
            );
            assert_eq!(
                fake.dir_calls().len(),
                1,
                "conclusion is reached without further enumerations for {ft:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_fake_emptiness_nondir_entry_name_never_decoded() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let fake = RecordingFakeInspector::new();
            let non_utf8 = std::ffi::OsStr::from_bytes(b"weird_\xff\xfe").to_os_string();
            fake.script_dir(
                Some(key("journals")),
                Ok(vec![DirEntry::new(non_utf8, DirEntryType::Regular)]),
            );
            assert!(
                contained_subtree_has_any_entry(&fake, "journals")
                    .await
                    .unwrap(),
                "a non-directory entry concludes non-empty regardless of its name bytes"
            );
        }
    }

    #[tokio::test]
    async fn test_fake_emptiness_vanished_child_dir_is_empty_contribution() {
        let fake = RecordingFakeInspector::new();
        fake.script_dir(
            Some(key("repo-blobs")),
            Ok(vec![dir_entry("ghost", DirEntryType::Directory)]),
        );
        fake.script_dir(
            Some(key("repo-blobs/ghost")),
            Err(FsDirError::NotFound {
                path: Some("repo-blobs/ghost".to_string()),
            }),
        );
        assert!(
            !contained_subtree_has_any_entry(&fake, "repo-blobs")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_fake_emptiness_uninspectable_areas_fail_closed_no_false_empty() {
        // Unreadable subtree root.
        let fake = RecordingFakeInspector::new();
        fake.script_dir(
            Some(key("blobs")),
            Err(FsDirError::PermissionDenied {
                path: Some("blobs".to_string()),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }),
        );
        let err = contained_subtree_has_any_entry(&fake, "blobs")
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Symlinked subtree root rejected by contained resolution.
        let fake = RecordingFakeInspector::new();
        fake.script_dir(
            Some(key("blobs")),
            Err(FsDirError::ResolutionRejected {
                raw_os_error: libc::ELOOP,
                source: std::io::Error::from_raw_os_error(libc::ELOOP),
            }),
        );
        let err = contained_subtree_has_any_entry(&fake, "blobs")
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Wrong-type subtree root (legacy Io).
        let fake = RecordingFakeInspector::new();
        fake.script_dir(
            Some(key("uploads")),
            Err(FsDirError::NotADirectory {
                path: Some("uploads".to_string()),
            }),
        );
        let err = contained_subtree_has_any_entry(&fake, "uploads")
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Mid-walk I/O failure after an earlier empty observation.
        let fake = RecordingFakeInspector::new();
        fake.script_dir(
            Some(key("repos")),
            Ok(vec![
                dir_entry("empty_ok", DirEntryType::Directory),
                dir_entry("broken", DirEntryType::Directory),
            ]),
        );
        fake.script_dir(Some(key("repos/empty_ok")), Ok(vec![]));
        fake.script_dir(
            Some(key("repos/broken")),
            Err(FsDirError::Io {
                source: std::io::Error::other("disk error"),
            }),
        );
        let err = contained_subtree_has_any_entry(&fake, "repos")
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Non-descendable directory names fail closed.
        let fake = RecordingFakeInspector::new();
        fake.script_dir(
            Some(key("meta")),
            Ok(vec![dir_entry("bad\\dir", DirEntryType::Directory)]),
        );
        let err = contained_subtree_has_any_entry(&fake, "meta")
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let fake = RecordingFakeInspector::new();
            let non_utf8 = std::ffi::OsStr::from_bytes(b"dir_\xff").to_os_string();
            fake.script_dir(
                Some(key("meta")),
                Ok(vec![DirEntry::new(non_utf8, DirEntryType::Directory)]),
            );
            let err = contained_subtree_has_any_entry(&fake, "meta")
                .await
                .unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));
        }
    }

    // ========================================================================
    // Linux-gated real filesystem tests (production entry points)
    // ========================================================================

    #[cfg(target_os = "linux")]
    mod real_fs_tests {
        use super::*;
        use crate::storage::Storage;
        use crate::storage::fs::FsStorage;

        fn fixture_root() -> (tempfile::TempDir, std::path::PathBuf) {
            let fixture = tempfile::tempdir().expect("create tempdir");
            let root = fixture.path().join("storage_root");
            std::fs::create_dir_all(&root).expect("create storage root");
            (fixture, root)
        }

        #[tokio::test]
        async fn test_real_is_storage_empty_areas_and_short_circuit() {
            let (_fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);

            // Fully missing tree -> empty.
            assert!(storage.is_storage_empty().await.unwrap());

            // Nested empty directories only -> still empty.
            std::fs::create_dir_all(root.join("uploads").join("a").join("b")).unwrap();
            std::fs::create_dir_all(root.join("blobs").join("sha256")).unwrap();
            assert!(storage.is_storage_empty().await.unwrap());

            // One file in each area (checked one at a time) -> not empty.
            for area in [
                "blobs",
                "uploads",
                "quarantine",
                "repo-blobs",
                "repo-memberships",
                "repos",
                "journals",
            ] {
                let (_f2, root2) = fixture_root();
                let storage2 = FsStorage::new(root2.clone(), 1024 * 1024);
                let dir = root2.join(area).join("nested");
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("payload"), b"x").unwrap();
                assert!(
                    !storage2.is_storage_empty().await.unwrap(),
                    "a file under {area}/ must make storage non-empty"
                );
            }
        }

        #[tokio::test]
        async fn test_real_is_storage_empty_symlinked_area_fails_closed() {
            let (fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);

            // blobs is a symlink to an outside directory holding data: the
            // ambient walk followed it; contained resolution rejects it, so an
            // uninspectable area can never produce a false empty result.
            let outside = fixture.path().join("outside_blobs");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("data"), b"x").unwrap();
            std::os::unix::fs::symlink(&outside, root.join("blobs")).unwrap();

            let err = storage.is_storage_empty().await.unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

            // The readiness-inspector port (consumed by runtime startup before
            // mark_membership_ready) sees the same fail-closed error.
            let wiring = crate::storage::ports::StorageWiring::from_backend(std::sync::Arc::new(
                FsStorage::new(root.clone(), 1024 * 1024),
            ));
            let err = wiring
                .readiness_inspector()
                .is_storage_empty()
                .await
                .unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
        }

        #[tokio::test]
        async fn test_real_is_storage_empty_symlink_entry_counts_as_entry() {
            let (fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);

            // A symlink ENTRY inside an area is a non-directory dirent: it
            // counts as an entry (non-empty), exactly as before.
            std::fs::create_dir_all(root.join("journals")).unwrap();
            let target = fixture.path().join("target");
            std::fs::write(&target, b"x").unwrap();
            std::os::unix::fs::symlink(&target, root.join("journals").join("link")).unwrap();

            assert!(!storage.is_storage_empty().await.unwrap());
        }

        #[tokio::test]
        async fn test_real_is_storage_empty_pinned_root_replacement() {
            let (fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);
            assert!(storage.is_storage_empty().await.unwrap());

            // Replace the root pathname with a populated tree: the pinned
            // reader still observes the original (empty) root.
            let renamed = fixture.path().join("storage_root_old");
            std::fs::rename(&root, &renamed).unwrap();
            std::fs::create_dir_all(root.join("blobs")).unwrap();
            std::fs::write(root.join("blobs").join("data"), b"x").unwrap();

            assert!(
                storage.is_storage_empty().await.unwrap(),
                "emptiness remains tied to the pinned original root"
            );
        }
    }
}
