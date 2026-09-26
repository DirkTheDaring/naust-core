//! Cross-backend shared repository-timestamp behavior suite (Phase 8).
//!
//! ONE expectation set executed against BOTH production storage backends
//! over their real migrated derivation paths (FsStorage over a real
//! temporary root; S3Storage over the real `S3ObjectStore` adapter driven by
//! the deterministic mock client with an explicit per-key mtime seam). The
//! family is READ-DERIVED and ZERO-WRITE: there is no payload to corrupt, no
//! write/overwrite/CAS to race, and no StorageFull row — those §18 items are
//! documented as not part of the actual contract rather than manufactured.
//!
//! The retired `timestamps_emptiness` real-filesystem tests (max selection,
//! symlink policy, pinned root, wrong-type `tags`) are relocated here with
//! the accepted adapter kind convergences pinned explicitly.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::super::s3::tests::{MockS3Driver, TagBridgeDriver, create_mock_storage};
use crate::storage::fs::FsStorage;
use crate::storage::s3::S3Storage;
use crate::storage::{Storage, StorageError, StorageErrorKind};

fn write_with_mtime(path: &std::path::Path, ts: SystemTime) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"x").unwrap();
    let file = std::fs::File::options().write(true).open(path).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(ts))
        .unwrap();
}

fn secs(s: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(s)
}

fn fs_fixture() -> (tempfile::TempDir, std::path::PathBuf, FsStorage) {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 1024 * 1024).unwrap();
    (fixture, root, storage)
}

/// Seeds an S3 mock object at the OLD physical key with an explicit
/// modification time (unix seconds).
fn s3_seed(driver: &MockS3Driver, key: &str, mtime_secs: Option<u64>) {
    driver.objects.lock().unwrap().insert(
        key.to_string(),
        (bytes::Bytes::from_static(b"x"), "\"seeded\"".to_string()),
    );
    if let Some(s) = mtime_secs {
        driver
            .object_mtimes
            .lock()
            .unwrap()
            .insert(key.to_string(), s);
    }
}

// ---------------------------------------------------------------------------
// Shared contract
// ---------------------------------------------------------------------------

/// Invalid repository grammar fails closed with `InvalidRepoName` before any
/// backend access on BOTH backends. (The retired S3 body interpolated raw
/// names; its empty-prefix listings produced `NotFound` — the same 404 at
/// the only error-distinguishing HTTP caller. Converged, C1.)
#[tokio::test]
async fn shared_invalid_repo_grammar() {
    let (_f, _root, fs) = fs_fixture();
    let (s3, _driver) = create_mock_storage();
    for bad in ["../escape", "a/../b", "bad\\name", "", "a//b"] {
        assert!(
            matches!(
                fs.repo_timestamps(bad).await,
                Err(StorageError::InvalidRepoName(_))
            ),
            "[fs] rejects {bad:?}"
        );
        assert!(
            matches!(
                s3.repo_timestamps(bad).await,
                Err(StorageError::InvalidRepoName(_))
            ),
            "[s3] rejects {bad:?}"
        );
    }
}

/// Old-layout seeded objects derive the frozen maxima: max per namespace,
/// direct children only, dotfiles included; a repo with content in only one
/// namespace yields `None` for the other.
#[tokio::test]
async fn shared_old_layout_max_selection() {
    // FS: real files with explicit mtimes (nanosecond-capable clock).
    let (_f, root, fs) = fs_fixture();
    let repo = root.join("repos").join("r1");
    write_with_mtime(&repo.join("tags").join("older"), secs(1_600_000_000));
    write_with_mtime(&repo.join("tags").join("newer"), secs(1_700_000_000));
    // Hidden regular files still contribute (frozen: persisted .lock.* files).
    write_with_mtime(&repo.join("tags").join(".lock.newest"), secs(1_750_000_000));
    write_with_mtime(&repo.join("manifests").join("m1"), secs(1_650_000_000));
    // A subdirectory inside tags does not contribute.
    std::fs::create_dir_all(repo.join("tags").join("subdir")).unwrap();

    let ts = fs.repo_timestamps("r1").await.unwrap();
    assert_eq!(
        ts.last_tag_update,
        Some(secs(1_750_000_000)),
        "[fs] max incl. dotfile"
    );
    assert_eq!(ts.last_manifest_update, Some(secs(1_650_000_000)), "[fs]");

    // S3: mock objects at the old keys with explicit listing mtimes.
    let (s3, driver) = create_mock_storage();
    s3_seed(&driver, "repos/r1/tags/older", Some(1_600_000_000));
    s3_seed(&driver, "repos/r1/tags/newer", Some(1_700_000_000));
    s3_seed(&driver, "repos/r1/manifests/m1", Some(1_650_000_000));
    let ts = s3.repo_timestamps("r1").await.unwrap();
    assert_eq!(ts.last_tag_update, Some(secs(1_700_000_000)), "[s3] max");
    assert_eq!(ts.last_manifest_update, Some(secs(1_650_000_000)), "[s3]");

    // Only manifests present: tag field None (both backends).
    s3_seed(&driver, "repos/only-m/manifests/m1", Some(42));
    let ts = s3.repo_timestamps("only-m").await.unwrap();
    assert_eq!(ts.last_tag_update, None, "[s3]");
    assert_eq!(ts.last_manifest_update, Some(secs(42)), "[s3]");
}

/// FS precision: modification times pass through as full-precision
/// `SystemTime` (nanoseconds preserved; the retired seam pinned
/// nanosecond-capable checked conversion).
#[tokio::test]
async fn fs_precision_nanoseconds_preserved() {
    let (_f, root, fs) = fs_fixture();
    let precise = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
    write_with_mtime(
        &root.join("repos").join("p").join("tags").join("t"),
        precise,
    );
    let ts = fs.repo_timestamps("p").await.unwrap();
    assert_eq!(
        ts.last_tag_update,
        Some(precise),
        "nanosecond precision preserved"
    );
}

/// The absent-repository rule — the accepted INTENTIONAL BACKEND DIFFERENCE
/// (the Phase 3 repository-existence pattern), preserved exactly per
/// backend:
/// - FS: absent repository directory → `NotFound`; a present "bare"
///   repository (no/empty tag/manifest namespaces) → `Ok(None, None)`.
/// - S3: no repository-existence notion — zero rows in BOTH namespaces IS
///   absence → `NotFound`.
#[tokio::test]
async fn absent_repository_rules_per_backend() {
    let (_f, root, fs) = fs_fixture();
    assert!(
        matches!(
            fs.repo_timestamps("absent").await,
            Err(StorageError::NotFound)
        ),
        "[fs] absent repo dir"
    );
    std::fs::create_dir_all(root.join("repos").join("bare")).unwrap();
    let ts = fs.repo_timestamps("bare").await.unwrap();
    assert_eq!(
        (ts.last_tag_update, ts.last_manifest_update),
        (None, None),
        "[fs] bare repo"
    );
    std::fs::create_dir_all(root.join("repos").join("emptydirs").join("tags")).unwrap();
    let ts = fs.repo_timestamps("emptydirs").await.unwrap();
    assert_eq!(ts.last_tag_update, None, "[fs] empty tags dir");

    let (s3, driver) = create_mock_storage();
    assert!(
        matches!(
            s3.repo_timestamps("absent").await,
            Err(StorageError::NotFound)
        ),
        "[s3] zero rows in both namespaces is absence"
    );
    // Content in one namespace defeats the absence rule.
    s3_seed(&driver, "repos/present/tags/t", None);
    assert!(s3.repo_timestamps("present").await.is_ok(), "[s3]");
}

/// Rows WITHOUT a modification timestamp are content evidence (they defeat
/// the S3 absence rule) but contribute no timestamp — the frozen
/// "metadata without timestamp contributes nothing" rule, and the
/// convergence from the retired S3 `unwrap_or(0)` epoch fabrication (C1:
/// real S3 listings always carry LastModified).
#[tokio::test]
async fn s3_rows_without_mtimes_count_but_contribute_nothing() {
    let (s3, driver) = create_mock_storage();
    s3_seed(&driver, "repos/r/tags/t1", None);
    s3_seed(&driver, "repos/r/manifests/m1", None);
    let ts = s3.repo_timestamps("r").await.unwrap();
    assert_eq!(ts.last_tag_update, None);
    assert_eq!(ts.last_manifest_update, None);
}

/// End-to-end freshness: publishing through the migrated tag/manifest
/// domains implicitly advances the derived timestamps (no stored timestamp
/// object exists — the derivation source is the publication itself).
#[tokio::test]
async fn shared_publication_advances_derived_timestamps() {
    let (_f, _root, fs) = fs_fixture();
    let (s3, _driver) = create_mock_storage();
    let manifest =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
    let digest = {
        use sha2::Digest as _;
        crate::registry::digest::Digest::parse(&format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(manifest))
        ))
        .unwrap()
    };
    for (n, st) in [("fs", &fs as &dyn Storage), ("s3", &s3 as &dyn Storage)] {
        st.put_manifest("fresh", &digest, bytes::Bytes::from_static(manifest))
            .await
            .unwrap();
        st.set_tag("fresh", "v1", &digest).await.unwrap();
        let ts = st.repo_timestamps("fresh").await.unwrap();
        // Publication rows are content evidence on both backends (no
        // NotFound). Timestamp VALUES are asserted on FS only: the mock
        // bridge lists domain-written objects without modification times,
        // whereas real S3 always supplies LastModified.
        if n == "fs" {
            assert!(
                ts.last_manifest_update.is_some(),
                "[{n}] manifest activity observed"
            );
            assert!(ts.last_tag_update.is_some(), "[{n}] tag activity observed");
        }
    }
}

// ---------------------------------------------------------------------------
// FS containment (relocated from the retired timestamps_emptiness real-fs
// tests, adapted to the accepted adapter convergences)
// ---------------------------------------------------------------------------

/// Symlink policy: a symlinked ENTRY never contributes (excluded as a
/// non-object, exactly as before); a symlinked `manifests/` directory or a
/// symlinked repository directory fails closed. (The retired seam classified
/// the failures as `Io`; the pinned adapter reports its containment refusal
/// as `PermissionDenied` — the accepted production-inert C2 convergence.)
#[tokio::test]
async fn fs_symlink_policy() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 1024 * 1024).unwrap();
    let repo = root.join("repos").join("r1");
    write_with_mtime(&repo.join("tags").join("real_tag"), secs(1_600_000_000));

    // Symlinked file entry with a NEWER outside target: excluded.
    let outside_file = fixture.path().join("outside_tag");
    write_with_mtime(&outside_file, secs(1_900_000_000));
    std::os::unix::fs::symlink(&outside_file, repo.join("tags").join("sym_tag")).unwrap();
    let ts = storage.repo_timestamps("r1").await.unwrap();
    assert_eq!(
        ts.last_tag_update,
        Some(secs(1_600_000_000)),
        "symlinked entries do not contribute timestamps"
    );

    // Symlinked manifests directory is rejected instead of followed.
    let outside_dir = fixture.path().join("outside_manifests");
    std::fs::create_dir_all(&outside_dir).unwrap();
    std::os::unix::fs::symlink(&outside_dir, repo.join("manifests")).unwrap();
    let err = storage.repo_timestamps("r1").await.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );

    // Symlinked repository directory is rejected instead of followed.
    let outside_repo = fixture.path().join("outside_repo");
    std::fs::create_dir_all(outside_repo.join("tags")).unwrap();
    std::os::unix::fs::symlink(&outside_repo, root.join("repos").join("symrepo")).unwrap();
    let err = storage.repo_timestamps("symrepo").await.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
}

/// Pinned root: replacing the root pathname does not redirect the
/// derivation.
#[tokio::test]
async fn fs_pinned_root_replacement() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 1024 * 1024).unwrap();
    write_with_mtime(
        &root.join("repos").join("r1").join("tags").join("t"),
        secs(1_600_000_000),
    );
    assert_eq!(
        storage.repo_timestamps("r1").await.unwrap().last_tag_update,
        Some(secs(1_600_000_000))
    );

    let renamed = fixture.path().join("storage_root_old");
    std::fs::rename(&root, &renamed).unwrap();
    write_with_mtime(
        &root.join("repos").join("r1").join("tags").join("t"),
        secs(1_800_000_000),
    );
    assert_eq!(
        storage.repo_timestamps("r1").await.unwrap().last_tag_update,
        Some(secs(1_600_000_000)),
        "timestamps remain tied to the pinned original root"
    );
}

/// A regular FILE at the `tags` path: the retired seam errored (`Io`,
/// EISDIR); under the pinned adapter a file at an intermediate component is
/// STRUCTURAL ABSENCE (the accepted tag-family Phase 3 row — no supported
/// writer produces this state), so the namespace reads as empty and the
/// present repository yields `Ok(None, None)`.
#[tokio::test]
async fn fs_wrong_type_tags_is_structural_absence() {
    let (_f, root, storage) = fs_fixture();
    let repo = root.join("repos").join("r1");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("tags"), b"file, not dir").unwrap();

    let ts = storage.repo_timestamps("r1").await.unwrap();
    assert_eq!(
        (ts.last_tag_update, ts.last_manifest_update),
        (None, None),
        "file-at-tags is structural absence; the present repository still resolves"
    );
}

// ---------------------------------------------------------------------------
// S3 adversarial
// ---------------------------------------------------------------------------

/// S3 fault classification and tenant-prefix isolation.
#[tokio::test]
async fn s3_faults_and_prefix_isolation() {
    let (s3, driver) = create_mock_storage();
    s3_seed(&driver, "repos/r/tags/t", Some(5));

    driver.set_hook_before(|method, key| {
        if method == "list_objects_v2" && key.contains("repos/r/") {
            Some(StorageError::permission_denied("injected 403"))
        } else {
            None
        }
    });
    let err = s3.repo_timestamps("r").await.expect_err("403 propagates");
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    driver.clear_hooks();

    driver.set_hook_before(|method, key| {
        if method == "list_objects_v2" && key.contains("repos/r/") {
            Some(StorageError::backend("injected backend fault"))
        } else {
            None
        }
    });
    let err = s3
        .repo_timestamps("r")
        .await
        .expect_err("backend fault propagates");
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    driver.clear_hooks();

    // Prefix isolation: the derivation observes only the tenant's keys.
    let driver2 = Arc::new(MockS3Driver::new(1000));
    let tenant_a = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "tenant-a".to_string(),
        100 * 1024 * 1024,
        Arc::new(TagBridgeDriver::new(driver2.clone())),
    );
    let tenant_b = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "tenant-b".to_string(),
        100 * 1024 * 1024,
        Arc::new(TagBridgeDriver::new(driver2.clone())),
    );
    driver2.objects.lock().unwrap().insert(
        "tenant-a/repos/iso/tags/t".to_string(),
        (bytes::Bytes::from_static(b"x"), "\"s\"".to_string()),
    );
    driver2
        .object_mtimes
        .lock()
        .unwrap()
        .insert("tenant-a/repos/iso/tags/t".to_string(), 7);
    assert_eq!(
        tenant_a
            .repo_timestamps("iso")
            .await
            .unwrap()
            .last_tag_update,
        Some(secs(7)),
        "tenant-a sees its own key"
    );
    assert!(
        matches!(
            tenant_b.repo_timestamps("iso").await,
            Err(StorageError::NotFound)
        ),
        "tenant-b is isolated"
    );
}
