//! Cross-backend shared registry lifecycle-journal behavior suite (Phase 7).
//!
//! ONE expectation set executed against BOTH production storage backends
//! over their real migrated journal paths (FsStorage over a real temporary
//! root; S3Storage over the real `S3ObjectStore` adapter driven by the
//! deterministic mock client). Raw seeding/reading uses each backend's OLD
//! physical representation (`<root>/repos/<repo>/meta/lifecycle_journal.json`
//! file / the same bucket key), so the suite doubles as the existing-data /
//! byte-layout compatibility proof: no migration job.
//!
//! The caller-boundary contracts formerly pinned by the retired
//! `fs/journal_read.rs` real-filesystem tests (recovery-boundary abort on an
//! unreadable journal, corrupt-journal preservation, repository-identity
//! fail-closed, `is_lifecycle_active`) are relocated here against the public
//! surface.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use naust_storage_core::ObjectKey;
use naust_storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ListPage, ObjectMeta, ObjectRead,
    ObjectStore, ObjectVersion, PageToken, ReplaceOutcome, StoreError, VersionedRead,
};

use super::super::s3::tests::{MockS3Driver, TagBridgeDriver, create_mock_storage};
use super::JournalDomain;
use crate::storage::fs::FsStorage;
use crate::storage::s3::S3Storage;
use crate::storage::{Storage, StorageError, StorageErrorKind};
use std::num::NonZeroUsize;
use std::path::PathBuf;

fn journal_relpath(repo: &str) -> String {
    format!("repos/{repo}/meta/lifecycle_journal.json")
}

enum Backend {
    Fs {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        storage: FsStorage,
    },
    S3 {
        storage: S3Storage,
        driver: Arc<MockS3Driver>,
    },
}

fn fs_backend() -> Backend {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();
    Backend::Fs {
        _tmp: tmp,
        root,
        storage,
    }
}

fn s3_backend() -> Backend {
    let (storage, driver) = create_mock_storage();
    Backend::S3 { storage, driver }
}

fn both() -> Vec<Backend> {
    vec![fs_backend(), s3_backend()]
}

impl Backend {
    fn name(&self) -> &'static str {
        match self {
            Backend::Fs { .. } => "fs",
            Backend::S3 { .. } => "s3",
        }
    }

    fn seed_raw(&self, repo: &str, bytes: &[u8]) {
        match self {
            Backend::Fs { root, .. } => {
                let path = root.join(journal_relpath(repo));
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            Backend::S3 { driver, .. } => {
                driver.objects.lock().unwrap().insert(
                    journal_relpath(repo),
                    (Bytes::from(bytes.to_vec()), "\"seeded\"".to_string()),
                );
            }
        }
    }

    fn read_raw(&self, repo: &str) -> Option<Vec<u8>> {
        match self {
            Backend::Fs { root, .. } => std::fs::read(root.join(journal_relpath(repo))).ok(),
            Backend::S3 { driver, .. } => driver
                .objects
                .lock()
                .unwrap()
                .get(&journal_relpath(repo))
                .map(|(b, _)| b.to_vec()),
        }
    }

    fn storage(&self) -> &dyn Storage {
        match self {
            Backend::Fs { storage, .. } => storage,
            Backend::S3 { storage, .. } => storage,
        }
    }
}

// ---------------------------------------------------------------------------
// Reads / old-layout compatibility
// ---------------------------------------------------------------------------

/// Absence (any missing path component) reads as `None`; invalid repository
/// grammar fails closed with `InvalidRepoName` on all three operations with
/// zero side effects; deleting an absent journal — including for a
/// never-seen repository — is success.
#[tokio::test]
async fn shared_absent_and_grammar() {
    for b in both() {
        let n = b.name();
        assert!(
            b.storage()
                .read_lifecycle_journal("norepo")
                .await
                .unwrap()
                .is_none(),
            "[{n}] absent repo"
        );
        b.storage()
            .delete_lifecycle_journal("never/existed")
            .await
            .unwrap();
        for bad in ["", "UPPER/Repo", "../escape", "a//b"] {
            assert!(
                matches!(
                    b.storage().read_lifecycle_journal(bad).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "[{n}] read rejects {bad:?}"
            );
            assert!(
                matches!(
                    b.storage()
                        .write_lifecycle_journal(bad, Bytes::from_static(b"{}"))
                        .await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "[{n}] write rejects {bad:?}"
            );
            assert!(
                matches!(
                    b.storage().delete_lifecycle_journal(bad).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "[{n}] delete rejects {bad:?}"
            );
        }
        if let Backend::Fs { root, .. } = &b {
            assert!(
                !root.join("repos").join("norepo").exists()
                    && !root.join("repos").join("never").exists(),
                "[{n}] no directories created by absent/no-op operations"
            );
        }
    }
}

/// Pre-migration seeded journals read back as EXACT raw bytes through the
/// shared layer — including a syntactically corrupt payload (the storage
/// layer never parses) and an EMPTY file (`Some(b\"\")`, never absence).
#[tokio::test]
async fn shared_old_layout_raw_passthrough() {
    for b in both() {
        let n = b.name();
        b.seed_raw("lib/app", br#"{"op_id":"op-1"}"#);
        assert_eq!(
            b.storage()
                .read_lifecycle_journal("lib/app")
                .await
                .unwrap()
                .unwrap(),
            Bytes::from_static(br#"{"op_id":"op-1"}"#),
            "[{n}] raw passthrough"
        );
        b.seed_raw("corrupt", b"{broken");
        assert_eq!(
            b.storage()
                .read_lifecycle_journal("corrupt")
                .await
                .unwrap()
                .unwrap(),
            Bytes::from_static(b"{broken"),
            "[{n}] corrupt bytes pass through unparsed"
        );
        b.seed_raw("empty", b"");
        let read = b
            .storage()
            .read_lifecycle_journal("empty")
            .await
            .unwrap()
            .expect("[{n}] empty journal file is NOT absence");
        assert!(read.is_empty(), "[{n}]");
    }
}

/// Writes land at the EXACT pre-migration physical location with the exact
/// bytes and remain unconditional last-writer-wins replacements.
#[tokio::test]
async fn shared_write_physical_compatibility_and_overwrite() {
    for b in both() {
        let n = b.name();
        b.storage()
            .write_lifecycle_journal("org/team/app", Bytes::from_static(b"{\"v\":1}"))
            .await
            .unwrap();
        assert_eq!(
            b.read_raw("org/team/app")
                .expect("journal at the old physical key"),
            b"{\"v\":1}".to_vec(),
            "[{n}] exact bytes at the exact key"
        );
        b.storage()
            .write_lifecycle_journal("org/team/app", Bytes::from_static(b"{\"v\":2}"))
            .await
            .unwrap();
        assert_eq!(
            b.read_raw("org/team/app").unwrap(),
            b"{\"v\":2}".to_vec(),
            "[{n}] unconditional replacement"
        );

        if let Backend::Fs { root, .. } = &b {
            use std::os::unix::fs::MetadataExt;
            let mode = std::fs::metadata(root.join(journal_relpath("org/team/app")))
                .unwrap()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "[{n}] journal file mode");
        }
    }
}

/// Delete removes the object; absence and repeats are success; the removal
/// is physically observed at the old location.
#[tokio::test]
async fn shared_delete_semantics() {
    for b in both() {
        let n = b.name();
        b.seed_raw("r", b"{}");
        b.storage().delete_lifecycle_journal("r").await.unwrap();
        assert!(b.read_raw("r").is_none(), "[{n}] physically removed");
        b.storage().delete_lifecycle_journal("r").await.unwrap();
        assert!(
            b.storage()
                .read_lifecycle_journal("r")
                .await
                .unwrap()
                .is_none(),
            "[{n}] absent after delete"
        );
    }
}

// ---------------------------------------------------------------------------
// Deterministic fault mechanics at the domain layer (decorators)
// ---------------------------------------------------------------------------

/// Decorator failing selected primitives with injected store errors.
struct FaultStore {
    inner: Arc<dyn ObjectStore>,
    fail_delete: Option<fn() -> StoreError>,
    fail_write: Option<fn() -> StoreError>,
}

#[async_trait]
impl ObjectStore for FaultStore {
    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, StoreError> {
        self.inner.head(key).await
    }
    async fn read(&self, key: &ObjectKey, max_len: u64) -> Result<Option<ObjectRead>, StoreError> {
        self.inner.read(key, max_len).await
    }
    async fn read_with_version(
        &self,
        key: &ObjectKey,
        max_len: u64,
    ) -> Result<Option<VersionedRead>, StoreError> {
        self.inner.read_with_version(key, max_len).await
    }
    async fn write(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<ObjectVersion, StoreError> {
        if let Some(f) = self.fail_write {
            return Err(f());
        }
        self.inner.write(key, bytes, durability).await
    }
    async fn write_if_absent(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<CreateOutcome, StoreError> {
        self.inner.write_if_absent(key, bytes, durability).await
    }
    async fn replace_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<ReplaceOutcome, StoreError> {
        self.inner
            .replace_if_version(key, expected, bytes, durability)
            .await
    }
    async fn delete(&self, key: &ObjectKey) -> Result<(), StoreError> {
        if let Some(f) = self.fail_delete {
            return Err(f());
        }
        self.inner.delete(key).await
    }
    async fn delete_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
    ) -> Result<ConditionalDeleteOutcome, StoreError> {
        self.inner.delete_if_version(key, expected).await
    }
    async fn list_page(
        &self,
        prefix: Option<&ObjectKey>,
        after: Option<&PageToken>,
        limit: NonZeroUsize,
    ) -> Result<ListPage, StoreError> {
        self.inner.list_page(prefix, after, limit).await
    }
}

fn raw_stores() -> Vec<(&'static str, tempfile::TempDir, Arc<dyn ObjectStore>)> {
    let mut out: Vec<(&'static str, tempfile::TempDir, Arc<dyn ObjectStore>)> = Vec::new();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    out.push((
        "fs",
        tmp,
        Arc::new(naust_storage_fs::FsObjectStore::open(&root).unwrap()),
    ));
    let tmp2 = tempfile::tempdir().unwrap();
    let client = Arc::new(naust_storage_s3::mock::MockS3Client::new());
    out.push((
        "s3",
        tmp2,
        Arc::new(naust_storage_s3::S3ObjectStore::new(client, None).unwrap()),
    ));
    out
}

/// A delete failure PROPAGATES truthfully on both backends and the journal
/// survives — the reconciled contract (the retired S3 body discarded every
/// delete error while all production callers `?`-propagate; matrix row R).
#[tokio::test]
async fn domain_delete_failure_propagates() {
    for (n, _guard, inner) in raw_stores() {
        let key = ObjectKey::parse(&journal_relpath("r")).unwrap();
        inner
            .write(&key, Bytes::from_static(b"{}"), Durability::Durable)
            .await
            .unwrap();
        let dom = JournalDomain::new(Arc::new(FaultStore {
            inner: Arc::clone(&inner),
            fail_delete: Some(|| StoreError::backend("injected delete fault")),
            fail_write: None,
        }));
        let err = dom
            .delete_lifecycle_journal("r")
            .await
            .expect_err("delete fault must propagate — never a silent success");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::Backend),
            "[{n}] {err:?}"
        );
        assert!(
            inner.read(&key, u64::MAX).await.unwrap().is_some(),
            "[{n}] journal survives the failed delete"
        );
    }
}

/// A structured ENOSPC in the write path's source chain maps to
/// `InsufficientStorage` through the shared `store_common` detection
/// (deterministic decorator drive: the fault table's needle matching cannot
/// isolate the journal family because the leaf name is a constant shared by
/// every parallel journal-writing test).
#[tokio::test]
async fn domain_enospc_write_maps_to_insufficient_storage() {
    for (n, _guard, inner) in raw_stores() {
        let dom = JournalDomain::new(Arc::new(FaultStore {
            inner: Arc::clone(&inner),
            fail_delete: None,
            fail_write: Some(|| StoreError::Backend {
                message: "staged publication failed".to_string(),
                source: Some(Box::new(std::io::Error::from_raw_os_error(libc::ENOSPC))),
            }),
        }));
        let err = dom
            .write_lifecycle_journal("r", Bytes::from_static(b"{}"))
            .await
            .expect_err("ENOSPC write must fail");
        assert!(
            matches!(err, StorageError::InsufficientStorage),
            "[{n}] structured ENOSPC restores InsufficientStorage, got {err:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// S3 adversarial
// ---------------------------------------------------------------------------

/// S3 fault classification through the real adapter and tenant-prefix
/// isolation at the exact physical key.
#[tokio::test]
async fn s3_fault_classification_and_prefix_isolation() {
    let (storage, driver) = create_mock_storage();
    driver.objects.lock().unwrap().insert(
        journal_relpath("r"),
        (Bytes::from_static(b"{}"), "\"s\"".to_string()),
    );

    driver.set_hook_before(|method, key| {
        if method == "get_object" && key.ends_with("lifecycle_journal.json") {
            Some(StorageError::permission_denied("injected 403"))
        } else {
            None
        }
    });
    let err = storage
        .read_lifecycle_journal("r")
        .await
        .expect_err("403 propagates — an unreadable journal is never absence");
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    driver.clear_hooks();

    driver.set_hook_before(|method, key| {
        if method == "put_object" && key.ends_with("lifecycle_journal.json") {
            Some(StorageError::backend("injected put fault"))
        } else {
            None
        }
    });
    let err = storage
        .write_lifecycle_journal("r", Bytes::from_static(b"{}"))
        .await
        .expect_err("write fault propagates");
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    driver.clear_hooks();

    // Delete faults now PROPAGATE (matrix row R; the retired body swallowed).
    driver.set_hook_before(|method, key| {
        if method == "delete_object" && key.ends_with("lifecycle_journal.json") {
            Some(StorageError::backend("injected delete fault"))
        } else {
            None
        }
    });
    let err = storage
        .delete_lifecycle_journal("r")
        .await
        .expect_err("delete fault propagates");
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    driver.clear_hooks();
    assert!(
        driver
            .objects
            .lock()
            .unwrap()
            .contains_key(&journal_relpath("r")),
        "journal survives the failed delete"
    );

    // Prefix isolation.
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
    tenant_a
        .write_lifecycle_journal("r", Bytes::from_static(b"{\"t\":\"a\"}"))
        .await
        .unwrap();
    assert!(
        driver2
            .objects
            .lock()
            .unwrap()
            .contains_key(&format!("tenant-a/{}", journal_relpath("r"))),
        "exact prefixed physical key"
    );
    assert!(
        tenant_b
            .read_lifecycle_journal("r")
            .await
            .unwrap()
            .is_none(),
        "prefix isolation"
    );
}

// ---------------------------------------------------------------------------
// FS containment (relocated from the retired fs/journal_read.rs real-fs
// tests, adapted to the accepted adapter kind convergences)
// ---------------------------------------------------------------------------

fn journal_path(root: &std::path::Path, repo: &str) -> std::path::PathBuf {
    root.join("repos")
        .join(repo)
        .join("meta")
        .join("lifecycle_journal.json")
}

/// Symlinked journal leaf and symlinked `meta/` ancestor fail closed on read
/// AND mutation, external targets untouched. (The retired contained seam
/// reported `Internal{Io}`; the pinned adapter reports its containment
/// refusal as `Internal{PermissionDenied}` — the accepted production-inert
/// convergence.) A DIRECTORY planted at the journal path is structural
/// absence under the shared adapter contract (the accepted
/// tag/manifest/membership row): not a read FAILURE — an actor able to plant
/// a directory could equally have deleted the journal — so it reads as
/// `None` rather than the retired `Io` error.
#[tokio::test]
async fn fs_symlinks_nonregular_and_pinned_root() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 1024 * 1024).unwrap();

    // Symlinked journal file -> fails closed, never absence.
    let outside = fixture.path().join("outside_journal.json");
    std::fs::write(&outside, b"{}").unwrap();
    let jp = journal_path(&root, "linkrepo");
    std::fs::create_dir_all(jp.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&outside, &jp).unwrap();
    let err = storage
        .read_lifecycle_journal("linkrepo")
        .await
        .unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    // Writing over a symlinked LEAF REPLACES the symlink entry with a real
    // file via the atomic rename (rename never follows the destination
    // entry — identical to the retired staged write); the external target is
    // untouched and never written through.
    storage
        .write_lifecycle_journal("linkrepo", Bytes::from_static(b"{\"new\":1}"))
        .await
        .unwrap();
    assert!(
        std::fs::symlink_metadata(&jp)
            .unwrap()
            .file_type()
            .is_file(),
        "the symlink entry was replaced by a regular file"
    );
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"{}",
        "external target untouched"
    );
    assert_eq!(
        storage
            .read_lifecycle_journal("linkrepo")
            .await
            .unwrap()
            .unwrap()
            .as_ref(),
        b"{\"new\":1}"
    );
    // Deleting removes the (now regular) entry; had the leaf still been a
    // symlink, unlinkat would remove the ENTRY itself, never the target.
    storage.delete_lifecycle_journal("linkrepo").await.unwrap();
    assert!(std::fs::symlink_metadata(&jp).is_err(), "entry removed");
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"{}",
        "external target untouched"
    );

    // Symlinked meta/ ancestor -> fails closed on read and write.
    let outside_meta = fixture.path().join("outside_meta");
    std::fs::create_dir_all(&outside_meta).unwrap();
    std::fs::write(outside_meta.join("lifecycle_journal.json"), b"{}").unwrap();
    let repo_dir = root.join("repos").join("ancrepo");
    std::fs::create_dir_all(&repo_dir).unwrap();
    std::os::unix::fs::symlink(&outside_meta, repo_dir.join("meta")).unwrap();
    let err = storage.read_lifecycle_journal("ancrepo").await.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    let err = storage
        .write_lifecycle_journal("ancrepo", Bytes::from_static(b"{}"))
        .await
        .unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    assert_eq!(
        std::fs::read(outside_meta.join("lifecycle_journal.json")).unwrap(),
        b"{}",
        "external meta tree untouched"
    );

    // Directory at the journal path -> structural absence (see doc above).
    let dirjp = journal_path(&root, "dirrepo");
    std::fs::create_dir_all(&dirjp).unwrap();
    assert!(
        storage
            .read_lifecycle_journal("dirrepo")
            .await
            .unwrap()
            .is_none(),
        "non-regular leaf is structural absence under the adapter contract"
    );

    // Pinned root: replacing the root pathname does not redirect reads.
    let fixture2 = tempfile::tempdir().unwrap();
    let root2 = fixture2.path().join("storage_root");
    std::fs::create_dir_all(&root2).unwrap();
    let storage2 = FsStorage::try_new(root2.clone(), 1024 * 1024).unwrap();
    storage2
        .write_lifecycle_journal("pinrepo", Bytes::from_static(b"{\"v\":1}"))
        .await
        .unwrap();
    let renamed = fixture2.path().join("storage_root_old");
    std::fs::rename(&root2, &renamed).unwrap();
    std::fs::create_dir_all(journal_path(&root2, "pinrepo").parent().unwrap()).unwrap();
    std::fs::write(journal_path(&root2, "pinrepo"), b"{\"v\":2}").unwrap();
    let read = storage2
        .read_lifecycle_journal("pinrepo")
        .await
        .unwrap()
        .expect("journal from pinned original root");
    assert_eq!(read.as_ref(), b"{\"v\":1}");
}

// ---------------------------------------------------------------------------
// Caller-boundary contracts (relocated from the retired journal_read.rs
// real-fs tests: the journal's recovery role through the PUBLIC lifecycle
// surface)
// ---------------------------------------------------------------------------

mod lifecycle_caller_contracts {
    use super::*;
    use crate::consistency::ConsistencyCoordinator;
    use crate::manifest_lifecycle::{
        LifecycleJournalRecord, LifecycleOpKind, LifecyclePhase, ManifestLifecycleError,
        ManifestLifecycleService,
    };
    use crate::registry::digest::Digest;

    fn fixture_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let fixture = tempfile::tempdir().expect("create tempdir");
        let root = fixture.path().join("storage_root");
        std::fs::create_dir_all(&root).expect("create storage root");
        (fixture, root)
    }

    fn journal_record(repo: &str, target: &Digest) -> LifecycleJournalRecord {
        LifecycleJournalRecord {
            op_id: "op-test".to_string(),
            repo: crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap(),
            op_kind: LifecycleOpKind::Publish,
            target_digest: target.clone(),
            target_reference: None,
            phase: LifecyclePhase::ManifestStored,
            owner_id: "owner-test".to_string(),
            lease_expiry_unix_secs: 9_999_999_999,
            started_unix_secs: 100,
            updated_unix_secs: 100,
            relevant_tags: Vec::new(),
            subject_digest: None,
            artifact_type: None,
            annotations: None,
            media_type: Some("application/vnd.oci.image.manifest.v1+json".to_string()),
            manifest_size: Some(100),
        }
    }

    async fn seed_manifest_and_tag(storage: &FsStorage, repo: &str, tag: &str) -> Digest {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": 2,
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            },
            "layers": []
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, &bytes);
        let digest = Digest::parse(&format!(
            "sha256:{}",
            hex::encode(sha2::Digest::finalize(hasher))
        ))
        .unwrap();
        storage
            .put_manifest(repo, &digest, bytes.into())
            .await
            .expect("put manifest");
        storage.set_tag(repo, tag, &digest).await.expect("set tag");
        digest
    }

    /// An unreadable journal (symlinked leaf) aborts the outer mutation at
    /// the recovery boundary; the journal is neither deleted nor
    /// overwritten; the tag survives; clearing the fault lets the same
    /// mutation succeed and clear its journal.
    #[tokio::test]
    async fn test_real_outer_mutation_aborts_on_unreadable_journal_then_recovers() {
        let (fixture, root) = fixture_root();
        let storage =
            std::sync::Arc::new(FsStorage::try_new(root.clone(), 50 * 1024 * 1024).unwrap());
        let service =
            ManifestLifecycleService::new(storage.clone(), None, ConsistencyCoordinator::new());

        let digest = seed_manifest_and_tag(&storage, "reporec", "v1").await;

        let outside = fixture.path().join("outside_journal.json");
        let planted = serde_json::to_vec(&journal_record("reporec", &digest)).unwrap();
        std::fs::write(&outside, &planted).unwrap();
        let jp = journal_path(&root, "reporec");
        std::fs::create_dir_all(jp.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &jp).unwrap();

        let err = service
            .delete_tag("reporec", "v1")
            .await
            .expect_err("outer mutation must abort when the journal is unreadable");
        assert!(
            matches!(err, ManifestLifecycleError::Storage(_)),
            "expected propagated storage error, got {err:?}"
        );
        assert!(
            std::fs::symlink_metadata(&jp)
                .unwrap()
                .file_type()
                .is_symlink(),
            "unreadable journal must not be deleted or overwritten"
        );
        assert_eq!(
            std::fs::read(&outside).unwrap(),
            planted,
            "symlink target must remain unmodified"
        );
        assert!(
            storage.resolve_tag("reporec", "v1").await.is_ok(),
            "tag must survive the aborted mutation"
        );

        std::fs::remove_file(&jp).unwrap();
        service
            .delete_tag("reporec", "v1")
            .await
            .expect("mutation succeeds after the fault is cleared");
        assert!(
            storage.resolve_tag("reporec", "v1").await.is_err(),
            "tag deleted after successful retry"
        );
        assert!(
            storage
                .read_lifecycle_journal("reporec")
                .await
                .unwrap()
                .is_none(),
            "successful flow completes and clears its journal"
        );
    }

    /// A corrupt journal aborts the outer mutation and is preserved
    /// byte-for-byte (never deleted or overwritten by recovery).
    #[tokio::test]
    async fn test_real_corrupt_journal_aborts_outer_mutation_and_is_preserved() {
        let (_fixture, root) = fixture_root();
        let storage =
            std::sync::Arc::new(FsStorage::try_new(root.clone(), 50 * 1024 * 1024).unwrap());
        let service =
            ManifestLifecycleService::new(storage.clone(), None, ConsistencyCoordinator::new());
        seed_manifest_and_tag(&storage, "reporec", "v1").await;

        storage
            .write_lifecycle_journal("reporec", Bytes::from_static(b"{broken"))
            .await
            .unwrap();

        let err = service
            .delete_tag("reporec", "v1")
            .await
            .expect_err("corrupt journal must abort the outer mutation");
        assert!(
            matches!(err, ManifestLifecycleError::CorruptJournal(_)),
            "expected CorruptJournal, got {err:?}"
        );
        assert_eq!(
            std::fs::read(journal_path(&root, "reporec")).unwrap(),
            b"{broken"
        );
        assert!(storage.resolve_tag("reporec", "v1").await.is_ok());
    }

    /// A journal recording a DIFFERENT repository fails recovery closed
    /// (identity mismatch) and is preserved.
    #[tokio::test]
    async fn test_real_repo_identity_mismatch_fails_closed() {
        let (_fixture, root) = fixture_root();
        let storage =
            std::sync::Arc::new(FsStorage::try_new(root.clone(), 50 * 1024 * 1024).unwrap());
        let service =
            ManifestLifecycleService::new(storage.clone(), None, ConsistencyCoordinator::new());
        let digest = seed_manifest_and_tag(&storage, "reporec", "v1").await;

        let foreign = journal_record("otherrepo", &digest);
        let foreign_bytes = serde_json::to_vec(&foreign).unwrap();
        storage
            .write_lifecycle_journal("reporec", Bytes::from(foreign_bytes.clone()))
            .await
            .unwrap();

        let err = service
            .delete_tag("reporec", "v1")
            .await
            .expect_err("repository identity mismatch must abort recovery");
        match err {
            ManifestLifecycleError::Storage(StorageError::Internal { kind, .. }) => {
                assert_eq!(kind, StorageErrorKind::CorruptData);
            }
            other => panic!("expected Storage(CorruptData), got {other:?}"),
        }
        assert_eq!(
            std::fs::read(journal_path(&root, "reporec")).unwrap(),
            foreign_bytes
        );
        assert!(storage.resolve_tag("reporec", "v1").await.is_ok());
    }

    /// `is_lifecycle_active`: absent → false; unexpired journal → true;
    /// expired lease → false; a read FAILURE propagates instead of
    /// presenting as inactive.
    #[tokio::test]
    async fn test_real_is_lifecycle_active_contract() {
        let (fixture, root) = fixture_root();
        let storage = std::sync::Arc::new(FsStorage::try_new(root.clone(), 1024 * 1024).unwrap());
        let service =
            ManifestLifecycleService::new(storage.clone(), None, ConsistencyCoordinator::new());
        let d = Digest::parse(
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();

        assert!(!service.is_lifecycle_active("myrepo").await.unwrap());

        let mut rec = journal_record("myrepo", &d);
        storage
            .write_lifecycle_journal("myrepo", Bytes::from(serde_json::to_vec(&rec).unwrap()))
            .await
            .unwrap();
        assert!(service.is_lifecycle_active("myrepo").await.unwrap());

        rec.lease_expiry_unix_secs = 1;
        storage
            .write_lifecycle_journal("myrepo", Bytes::from(serde_json::to_vec(&rec).unwrap()))
            .await
            .unwrap();
        assert!(!service.is_lifecycle_active("myrepo").await.unwrap());

        let outside = fixture.path().join("outside_journal.json");
        std::fs::write(&outside, b"{}").unwrap();
        storage.delete_lifecycle_journal("myrepo").await.unwrap();
        std::os::unix::fs::symlink(&outside, journal_path(&root, "myrepo")).unwrap();
        assert!(service.is_lifecycle_active("myrepo").await.is_err());
    }
}
