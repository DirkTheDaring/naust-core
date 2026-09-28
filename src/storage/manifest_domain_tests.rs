//! Cross-backend shared registry manifest behavior suite (Phase 4).
//!
//! ONE expectation set executed against BOTH production storage backends
//! over their real migrated manifest paths (FsStorage over a real temporary
//! root; S3Storage over the real `S3ObjectStore` adapter driven by the
//! deterministic mock client). Raw seeding/reading uses each backend's OLD
//! physical representation (`<root>/repos/<repo>/manifests/<hex>` file /
//! `repos/<repo>/manifests/<hex>` bucket key), so the suite doubles as the
//! existing-data / byte-layout compatibility proof: no migration job.

use super::super::s3::tests::{MockS3Driver, TagBridgeDriver, create_mock_storage};
use crate::registry::digest::Digest;
use crate::storage::fs::FsStorage;
use crate::storage::s3::S3Storage;
use crate::storage::{ManifestMeta, Storage, StorageError, StorageErrorKind};
use std::path::PathBuf;
use std::sync::Arc;

const HEX1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HEX2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const HEX512: &str = "4444444444444444444444444444444444444444444444444444444444444444\
4444444444444444444444444444444444444444444444444444444444444444";

fn d(hex: &str) -> Digest {
    Digest::parse(&format!("sha256:{hex}")).unwrap()
}

fn d512(hex: &str) -> Digest {
    Digest::parse(&format!("sha512:{hex}")).unwrap()
}

fn manifest_json() -> Vec<u8> {
    br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#.to_vec()
}

fn manifest_json_no_media_type() -> Vec<u8> {
    br#"{"schemaVersion": 2}"#.to_vec()
}

fn manifest_json_with_subject(subject_hex: &str) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "subject": {{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:{subject_hex}", "size": 2}}}}"#
    )
    .into_bytes()
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

    fn seed_manifest_raw(&self, repo: &str, hex: &str, bytes: &[u8]) {
        match self {
            Backend::Fs { root, .. } => {
                let path = root.join("repos").join(repo).join("manifests").join(hex);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            Backend::S3 { driver, .. } => {
                driver.objects.lock().unwrap().insert(
                    format!("repos/{repo}/manifests/{hex}"),
                    (bytes::Bytes::from(bytes.to_vec()), "\"seeded\"".to_string()),
                );
            }
        }
    }

    fn read_manifest_raw(&self, repo: &str, hex: &str) -> Option<Vec<u8>> {
        match self {
            Backend::Fs { root, .. } => {
                std::fs::read(root.join("repos").join(repo).join("manifests").join(hex)).ok()
            }
            Backend::S3 { driver, .. } => driver
                .objects
                .lock()
                .unwrap()
                .get(&format!("repos/{repo}/manifests/{hex}"))
                .map(|(b, _)| b.to_vec()),
        }
    }

    fn seed_tag_raw(&self, repo: &str, tag: &str, bytes: &[u8]) {
        match self {
            Backend::Fs { root, .. } => {
                let path = root.join("repos").join(repo).join("tags").join(tag);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            Backend::S3 { driver, .. } => {
                driver.objects.lock().unwrap().insert(
                    format!("repos/{repo}/tags/{tag}"),
                    (bytes::Bytes::from(bytes.to_vec()), "\"seeded\"".to_string()),
                );
            }
        }
    }

    fn tag_exists_raw(&self, repo: &str, tag: &str) -> bool {
        match self {
            Backend::Fs { root, .. } => root
                .join("repos")
                .join(repo)
                .join("tags")
                .join(tag)
                .exists(),
            Backend::S3 { driver, .. } => driver
                .objects
                .lock()
                .unwrap()
                .contains_key(&format!("repos/{repo}/tags/{tag}")),
        }
    }

    async fn get(
        &self,
        r: &str,
        dg: &Digest,
    ) -> Result<(ManifestMeta, bytes::Bytes), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.get_manifest(r, dg).await,
            Backend::S3 { storage, .. } => storage.get_manifest(r, dg).await,
        }
    }
    async fn head(&self, r: &str, dg: &Digest) -> Result<ManifestMeta, StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.head_manifest(r, dg).await,
            Backend::S3 { storage, .. } => storage.head_manifest(r, dg).await,
        }
    }
    async fn put(&self, r: &str, dg: &Digest, b: Vec<u8>) -> Result<ManifestMeta, StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.put_manifest(r, dg, bytes::Bytes::from(b)).await,
            Backend::S3 { storage, .. } => storage.put_manifest(r, dg, bytes::Bytes::from(b)).await,
        }
    }
    async fn delete(&self, r: &str, dg: &Digest) -> Result<(), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.delete_manifest(r, dg).await,
            Backend::S3 { storage, .. } => storage.delete_manifest(r, dg).await,
        }
    }
    async fn list(
        &self,
        r: &str,
        token: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<Digest>, Option<String>), StorageError> {
        match self {
            Backend::Fs { storage, .. } => {
                storage.list_manifest_digests_page(r, token, limit).await
            }
            Backend::S3 { storage, .. } => {
                storage.list_manifest_digests_page(r, token, limit).await
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reads / old-layout compatibility
// ---------------------------------------------------------------------------

/// Pre-migration seeded manifests read identically through the new shared
/// layer: exact bytes, size = bytes read, media type from the payload
/// (explicit, defaulted, and non-object JSON), including through HEAD.
#[tokio::test]
async fn shared_existing_data_read_compatibility() {
    for b in both() {
        let n = b.name();
        b.seed_manifest_raw("old-repo", HEX1, &manifest_json());
        b.seed_manifest_raw("old-repo", HEX2, &manifest_json_no_media_type());

        let (meta, bytes) = b.get("old-repo", &d(HEX1)).await.unwrap();
        assert_eq!(bytes.to_vec(), manifest_json(), "[{n}] exact bytes");
        assert_eq!(meta.size, manifest_json().len() as u64, "[{n}]");
        assert_eq!(
            meta.media_type, "application/vnd.oci.image.manifest.v1+json",
            "[{n}] explicit mediaType"
        );

        let meta2 = b.head("old-repo", &d(HEX2)).await.unwrap();
        assert_eq!(
            meta2.media_type, "application/vnd.oci.image.manifest.v1+json",
            "[{n}] missing mediaType defaults"
        );
        assert_eq!(meta2.size, manifest_json_no_media_type().len() as u64);
    }
}

/// Absent manifest: NotFound from get AND head.
#[tokio::test]
async fn shared_absent_manifest() {
    for b in both() {
        let n = b.name();
        let err = b.get("absent-repo", &d(HEX1)).await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound), "[{n}] get");
        let err = b.head("absent-repo", &d(HEX1)).await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound), "[{n}] head");
    }
}

/// Malformed stored payload: CorruptData on get AND head (media type is
/// parsed from the body — the frozen full-read contract).
#[tokio::test]
async fn shared_malformed_payload_reads() {
    for b in both() {
        let n = b.name();
        b.seed_manifest_raw("mal-repo", HEX1, b"not json at all");
        b.seed_manifest_raw("mal-repo", HEX2, b"");
        for dg in [d(HEX1), d(HEX2)] {
            let err = b.get("mal-repo", &dg).await.unwrap_err();
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::CorruptData),
                "[{n}] get malformed/empty -> CorruptData"
            );
            let err = b.head("mal-repo", &dg).await.unwrap_err();
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::CorruptData),
                "[{n}]"
            );
        }
    }
}

/// Reads remain UNBOUNDED (frozen operational limitation): a payload larger
/// than the HTTP ingress cap still reads fully.
#[tokio::test]
async fn shared_oversized_payload_reads_preserved() {
    let mut big = Vec::with_capacity(5 * 1024 * 1024 + 64);
    big.extend_from_slice(br#"{"mediaType": "application/big+json", "pad": ""#);
    big.resize(5 * 1024 * 1024, b'a');
    big.extend_from_slice(br#""}"#);
    for b in both() {
        let n = b.name();
        b.seed_manifest_raw("big-repo", HEX1, &big);
        let (meta, bytes) = b.get("big-repo", &d(HEX1)).await.unwrap();
        assert_eq!(bytes.len(), big.len(), "[{n}] unbounded read preserved");
        assert_eq!(meta.media_type, "application/big+json", "[{n}]");
    }
}

// ---------------------------------------------------------------------------
// Writes / exact-write compatibility
// ---------------------------------------------------------------------------

/// Write through the NEW implementation, inspect the OLD physical location:
/// exact bytes at the exact historical path/key, no staging residue.
#[tokio::test]
async fn shared_exact_write_physical_compatibility() {
    for b in both() {
        let n = b.name();
        let meta = b.put("w-repo", &d(HEX1), manifest_json()).await.unwrap();
        assert_eq!(meta.size, manifest_json().len() as u64, "[{n}]");
        assert_eq!(
            meta.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(
            b.read_manifest_raw("w-repo", HEX1).unwrap(),
            manifest_json(),
            "[{n}] exact bytes at the old physical location"
        );
        // sha512 manifests use the 128-hex leaf.
        b.put("w-repo", &d512(HEX512), manifest_json())
            .await
            .unwrap();
        assert!(b.read_manifest_raw("w-repo", HEX512).is_some(), "[{n}]");
        if let Backend::Fs { root, .. } = &b {
            let mdir = root.join("repos").join("w-repo").join("manifests");
            let mut names: Vec<String> = std::fs::read_dir(&mdir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(
                names,
                vec![HEX1.to_string(), HEX512.to_string()],
                "[fs] only the digest leaves; no staging residue in the manifests dir"
            );
        }
    }
}

/// Same-digest republication: unconditional last-writer-wins rewrite of the
/// identical canonical bytes succeeds and leaves the payload intact.
#[tokio::test]
async fn shared_same_digest_republication() {
    for b in both() {
        let n = b.name();
        b.put("same-repo", &d(HEX1), manifest_json()).await.unwrap();
        b.put("same-repo", &d(HEX1), manifest_json()).await.unwrap();
        assert_eq!(
            b.read_manifest_raw("same-repo", HEX1).unwrap(),
            manifest_json(),
            "[{n}]"
        );
        assert_eq!(
            b.get("same-repo", &d(HEX1)).await.unwrap().1.to_vec(),
            manifest_json()
        );
    }
}

/// Malformed payload on write: CorruptData and NOTHING is published.
#[tokio::test]
async fn shared_malformed_write_publishes_nothing() {
    for b in both() {
        let n = b.name();
        let err = b
            .put("malw-repo", &d(HEX1), b"{{{ not json".to_vec())
            .await
            .unwrap_err();
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}]"
        );
        assert!(
            b.read_manifest_raw("malw-repo", HEX1).is_none(),
            "[{n}] nothing written"
        );
    }
}

/// Grammar: traversal-like and structurally invalid repositories are
/// rejected before any backend access; nested repositories work.
#[tokio::test]
async fn shared_repository_grammar() {
    for b in both() {
        let n = b.name();
        for bad in [
            "", "/x", "x/", "a//b", "a/../b", ".", "..", "a\\b", "a\u{1}b",
        ] {
            let err = b.put(bad, &d(HEX1), manifest_json()).await.unwrap_err();
            assert!(
                matches!(err, StorageError::InvalidRepoName(_)),
                "[{n}] {bad:?} -> InvalidRepoName, got {err:?}"
            );
        }
        b.put("a/b/c", &d(HEX1), manifest_json()).await.unwrap();
        assert!(
            b.read_manifest_raw("a/b/c", HEX1).is_some(),
            "[{n}] nested repo"
        );
        assert_eq!(
            b.get("a/b/c", &d(HEX1)).await.unwrap().0.size,
            manifest_json().len() as u64
        );
    }
}

// ---------------------------------------------------------------------------
// Deletes: ordering, side effects, failure behavior
// ---------------------------------------------------------------------------

/// Present manifest: payload deleted; matching tags cleaned (shared Phase 3
/// helper); non-matching and legacy dot artifacts survive; referrer cleanup
/// (unmigrated family) runs last best-effort.
#[tokio::test]
async fn shared_delete_manifest_with_side_effects() {
    for b in both() {
        let n = b.name();
        let dg = d(HEX1);
        b.put("del-repo", &dg, manifest_json()).await.unwrap();
        b.seed_tag_raw("del-repo", "match", format!("{}\n", dg.as_str()).as_bytes());
        b.seed_tag_raw("del-repo", "keep", format!("sha256:{HEX2}\n").as_bytes());
        b.seed_tag_raw("del-repo", ".lock.legacy", b"legacy artifact");

        b.delete("del-repo", &dg).await.unwrap();

        assert!(
            b.read_manifest_raw("del-repo", HEX1).is_none(),
            "[{n}] payload gone"
        );
        assert!(
            !b.tag_exists_raw("del-repo", "match"),
            "[{n}] matching tag cleaned"
        );
        assert!(
            b.tag_exists_raw("del-repo", "keep"),
            "[{n}] non-matching tag survives"
        );
        assert!(
            b.tag_exists_raw("del-repo", ".lock.legacy"),
            "[{n}] legacy dot artifact protected"
        );

        // Absent manifest -> NotFound (frozen non-idempotent contract).
        let err = b.delete("del-repo", &dg).await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound), "[{n}]");
    }
}

/// A manifest whose structure cannot be parsed is undeletable (CorruptData)
/// and SURVIVES — the frozen fail-closed contract on both backends.
#[tokio::test]
async fn shared_delete_malformed_structure_fails_closed() {
    for b in both() {
        let n = b.name();
        // Valid JSON but structurally malformed for reference extraction:
        // a subject with an invalid digest.
        let bad = br#"{"schemaVersion": 2, "subject": {"digest": "not-a-digest", "size": 1}}"#;
        b.seed_manifest_raw("badstruct", HEX1, bad);
        let err = b.delete("badstruct", &d(HEX1)).await.unwrap_err();
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}] got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("cannot delete manifest with malformed structure"),
            "[{n}] frozen message: {err}"
        );
        assert!(
            b.read_manifest_raw("badstruct", HEX1).is_some(),
            "[{n}] manifest survives (fail-closed before delete)"
        );
    }
}

/// Subject extraction feeds the referrer cleanup boundary: deleting a
/// manifest with a valid subject succeeds (referrer cleanup is best-effort
/// against an absent referrers namespace).
#[tokio::test]
async fn shared_delete_with_subject_invokes_referrer_boundary() {
    for b in both() {
        let n = b.name();
        b.seed_manifest_raw("subj-repo", HEX1, &manifest_json_with_subject(HEX2));
        b.delete("subj-repo", &d(HEX1)).await.unwrap();
        assert!(b.read_manifest_raw("subj-repo", HEX1).is_none(), "[{n}]");
    }
}

/// Failure ordering: a tag-cleanup read failure AFTER the payload delete
/// propagates while the payload stays deleted (partial success, frozen
/// non-transactional contract; deterministic via an invalid-UTF-8 tag).
#[tokio::test]
async fn shared_delete_tag_cleanup_failure_after_payload_delete() {
    for b in both() {
        let n = b.name();
        let dg = d(HEX1);
        b.put("ord-repo", &dg, manifest_json()).await.unwrap();
        b.seed_tag_raw("ord-repo", "broken", &[0xff, 0xfe, 0xfd]);

        let err = b.delete("ord-repo", &dg).await.unwrap_err();
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}] cleanup failure propagates: {err:?}"
        );
        assert!(
            b.read_manifest_raw("ord-repo", HEX1).is_none(),
            "[{n}] payload already deleted (partial success, no rollback)"
        );
        assert!(b.tag_exists_raw("ord-repo", "broken"), "[{n}]");
    }
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

/// Common listing contract: canonical hex names (sha256 AND sha512 — the
/// retired S3 listing dropped sha512), malformed names filtered, sorted,
/// deduplicated, strictly-after tokens, zero page, absent repo.
#[tokio::test]
async fn shared_listing_contract() {
    for b in both() {
        let n = b.name();
        let hexes = [HEX1, HEX2];
        for h in hexes {
            b.seed_manifest_raw("list-repo", h, &manifest_json());
        }
        b.seed_manifest_raw("list-repo", HEX512, &manifest_json());
        // Malformed names: wrong length, uppercase, non-hex — all filtered.
        b.seed_manifest_raw("list-repo", "deadbeef", &manifest_json());
        b.seed_manifest_raw(
            "list-repo",
            "ABCDEF11111111111111111111111111111111111111111111111111111111AB",
            &manifest_json(),
        );
        b.seed_manifest_raw("list-repo", "not-hex-at-all", &manifest_json());

        let (all, tok) = b.list("list-repo", None, 10).await.unwrap();
        assert_eq!(
            all,
            vec![d(HEX1), d(HEX2), d512(HEX512)],
            "[{n}] sha256+sha512, sorted, malformed filtered"
        );
        assert!(tok.is_none(), "[{n}]");

        // Strictly-after pagination.
        let (p1, t1) = b.list("list-repo", None, 2).await.unwrap();
        assert_eq!(p1, vec![d(HEX1), d(HEX2)], "[{n}]");
        assert_eq!(
            t1.as_deref(),
            Some(format!("sha256:{HEX2}").as_str()),
            "[{n}]"
        );
        let (p2, t2) = b.list("list-repo", t1.as_deref(), 2).await.unwrap();
        assert_eq!(p2, vec![d512(HEX512)], "[{n}]");
        assert!(t2.is_none(), "[{n}]");

        // Zero page: empty terminal page before enumeration.
        let (p0, t0) = b.list("list-repo", None, 0).await.unwrap();
        assert!(p0.is_empty() && t0.is_none(), "[{n}]");

        // Absent repo: empty terminal page (both backends).
        let (pa, ta) = b.list("no-such-repo", None, 5).await.unwrap();
        assert!(pa.is_empty() && ta.is_none(), "[{n}]");
    }
}

/// Deleted-token resumption: a token whose digest vanished resumes at the
/// correct position (insertion point).
#[tokio::test]
async fn shared_listing_deleted_token_resumes() {
    for b in both() {
        let n = b.name();
        for h in [HEX1, HEX2] {
            b.seed_manifest_raw("tok-repo", h, &manifest_json());
        }
        let hex3 = "3333333333333333333333333333333333333333333333333333333333333333";
        b.seed_manifest_raw("tok-repo", hex3, &manifest_json());

        let (p1, t1) = b.list("tok-repo", None, 2).await.unwrap();
        assert_eq!(p1, vec![d(HEX1), d(HEX2)]);
        // Delete the token digest, then resume.
        b.delete("tok-repo", &d(HEX2)).await.unwrap();
        let (p2, t2) = b.list("tok-repo", t1.as_deref(), 2).await.unwrap();
        assert_eq!(p2, vec![d(hex3)], "[{n}] deleted token resumes correctly");
        assert!(t2.is_none());
    }
}

/// Listing resource exhaustion is a truthful error, never a silent
/// end-of-list (shared function driven directly with a tiny bound over the
/// real S3 adapter and the real FS adapter).
/// Listing is unbounded by architecture: streaming pagination over multiple
/// entries succeeds without arbitrary ceiling limits over real S3 and FS adapters.
#[tokio::test]
async fn shared_listing_unbounded_streaming() {
    use crate::storage::manifest_domain::{ManifestDomainConfig, list_manifest_digests_page};

    // S3 adapter over the deterministic mock client.
    {
        let client = Arc::new(naust_storage_s3::mock::MockS3Client::new());
        for h in [HEX1, HEX2] {
            client.raw_insert_bytes(&format!("repos/r/manifests/{h}"), manifest_json());
        }
        let hex3 = "3333333333333333333333333333333333333333333333333333333333333333";
        client.raw_insert_bytes(&format!("repos/r/manifests/{hex3}"), manifest_json());
        let store = naust_storage_s3::S3ObjectStore::new(client, None).unwrap();
        let cfg = ManifestDomainConfig {
            max_listing_entries: usize::MAX,
        };
        let (page, next) = list_manifest_digests_page(&store, &cfg, "r", None, 10)
            .await
            .expect("streaming listing must succeed without hitting limits");
        assert_eq!(page.len(), 3);
        assert!(next.is_none());
    }
    // FS adapter over a real root.
    {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let mdir = root.join("repos").join("r").join("manifests");
        std::fs::create_dir_all(&mdir).unwrap();
        for h in [
            HEX1,
            HEX2,
            "3333333333333333333333333333333333333333333333333333333333333333",
        ] {
            std::fs::write(mdir.join(h), manifest_json()).unwrap();
        }
        let store = naust_storage_fs::FsObjectStore::open(&root).unwrap();
        let cfg = ManifestDomainConfig {
            max_listing_entries: usize::MAX,
        };
        let (page, next) = list_manifest_digests_page(&store, &cfg, "r", None, 10)
            .await
            .expect("streaming listing must succeed without hitting limits");
        assert_eq!(page.len(), 3);
        assert!(next.is_none());
    }
}

// ---------------------------------------------------------------------------
// FS containment / durability / ENOSPC restoration
// ---------------------------------------------------------------------------

/// Root-replacement pinning at the migrated manifest boundary.
#[tokio::test]
async fn fs_root_replacement_pinning() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();

    storage
        .put_manifest("pin-repo", &d(HEX1), bytes::Bytes::from(manifest_json()))
        .await
        .unwrap();

    // Replace the whole root pathname.
    let old_root = tmp.path().join("storage-root-old");
    std::fs::rename(&root, &old_root).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let replacement = root
        .join("repos")
        .join("pin-repo")
        .join("manifests")
        .join(HEX2);
    std::fs::create_dir_all(replacement.parent().unwrap()).unwrap();
    std::fs::write(&replacement, manifest_json()).unwrap();

    // The pinned instance still reads/writes/deletes the ORIGINAL tree.
    let (_, bytes) = storage.get_manifest("pin-repo", &d(HEX1)).await.unwrap();
    assert_eq!(bytes.to_vec(), manifest_json());
    storage.delete_manifest("pin-repo", &d(HEX1)).await.unwrap();
    assert!(
        !old_root
            .join("repos")
            .join("pin-repo")
            .join("manifests")
            .join(HEX1)
            .exists(),
        "delete landed on the pinned original tree"
    );
    // The ambient replacement tree is untouched and invisible.
    assert!(replacement.exists(), "replacement tree untouched");
    assert!(
        matches!(
            storage.get_manifest("pin-repo", &d(HEX2)).await,
            Err(StorageError::NotFound)
        ),
        "the pinned instance never resolves the replacement tree"
    );
    // A fresh instance resolves the replacement root.
    let storage_b = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();
    assert!(storage_b.get_manifest("pin-repo", &d(HEX2)).await.is_ok());
}

/// Symlinked manifest leaf and symlinked manifests directory fail closed;
/// external targets untouched.
#[tokio::test]
#[cfg(unix)]
async fn fs_symlink_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("storage-root");
    let external = tmp.path().join("external");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&external).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();

    // Symlinked leaf.
    let ext_file = external.join("payload");
    std::fs::write(&ext_file, manifest_json()).unwrap();
    let mdir = root.join("repos").join("sym-repo").join("manifests");
    std::fs::create_dir_all(&mdir).unwrap();
    std::os::unix::fs::symlink(&ext_file, mdir.join(HEX1)).unwrap();
    let err = storage
        .get_manifest("sym-repo", &d(HEX1))
        .await
        .unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied),
        "symlinked leaf fails closed: {err:?}"
    );
    let err = storage
        .delete_manifest("sym-repo", &d(HEX1))
        .await
        .unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    assert_eq!(
        std::fs::read(&ext_file).unwrap(),
        manifest_json(),
        "target untouched"
    );

    // Symlinked manifests directory component.
    let ext_dir = external.join("ext-manifests");
    std::fs::create_dir_all(&ext_dir).unwrap();
    std::fs::write(ext_dir.join(HEX2), manifest_json()).unwrap();
    let repo2 = root.join("repos").join("sym2");
    std::fs::create_dir_all(&repo2).unwrap();
    std::os::unix::fs::symlink(&ext_dir, repo2.join("manifests")).unwrap();
    let err = storage.get_manifest("sym2", &d(HEX2)).await.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    assert!(ext_dir.join(HEX2).exists(), "external dir untouched");
}

/// §33-style FS fault injection at the registry boundary: a failed staged
/// rename or durable barrier propagates from put_manifest; ENOSPC restores
/// the historical InsufficientStorage classification (structured
/// source-chain detection, both for manifests and — regression-pinned
/// here — for tag publication).
#[tokio::test]
async fn fs_durability_and_enospc_classification() {
    use naust_storage_fs::mutate::fault::{self, FaultPoint};

    let _fault_guard = crate::storage::store_common::fault_scenario::begin().await;
    let b = fs_backend();
    let Backend::Fs { storage, .. } = &b else {
        unreachable!()
    };

    // ENOSPC on the manifest staged rename -> InsufficientStorage (507 row).
    let uniq1 = "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1";
    let uniq2 = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2";
    fault::arm(FaultPoint::RenameLeaf, Some(uniq1), 1, libc::ENOSPC);
    let err = storage
        .put_manifest(
            "zzm4faultrepo",
            &d(uniq1),
            bytes::Bytes::from(manifest_json()),
        )
        .await
        .expect_err("ENOSPC publication must fail");
    assert!(
        matches!(err, StorageError::InsufficientStorage),
        "ENOSPC restores InsufficientStorage, got {err:?}"
    );
    assert!(b.read_manifest_raw("zzm4faultrepo", uniq1).is_none());

    // EIO on the durable directory barrier -> propagates (no false success).
    fault::arm(FaultPoint::DirSync, Some("zzm4faultrepo"), 1, libc::EIO);
    let err = storage
        .put_manifest(
            "zzm4faultrepo",
            &d(uniq2),
            bytes::Bytes::from(manifest_json()),
        )
        .await
        .expect_err("failed durable barrier must propagate");
    assert!(err.internal_kind().is_some(), "classified error: {err:?}");

    // ENOSPC on a TAG publication -> InsufficientStorage (restored Phase 3 row).
    fault::arm(FaultPoint::RenameLeaf, Some("zzenospctag"), 1, libc::ENOSPC);
    let err = storage
        .set_tag("zzm4faultrepo", "zzenospctag", &d(uniq1))
        .await
        .expect_err("ENOSPC tag publication must fail");
    assert!(
        matches!(err, StorageError::InsufficientStorage),
        "tag ENOSPC restores InsufficientStorage, got {err:?}"
    );
    fault::reset();

    // Negative control.
    storage
        .put_manifest(
            "zzm4faultrepo",
            &d(uniq1),
            bytes::Bytes::from(manifest_json()),
        )
        .await
        .expect("publication succeeds after faults cleared");
}

// ---------------------------------------------------------------------------
// S3-specific: prefix compatibility, failure classification, payload-delete
// failure ordering
// ---------------------------------------------------------------------------

fn s3_backend_with_prefix(prefix: &str) -> (S3Storage, Arc<MockS3Driver>) {
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        prefix.to_string(),
        100 * 1024 * 1024,
        Arc::new(TagBridgeDriver::new(driver.clone())),
    );
    (storage, driver)
}

/// Configured-prefix physical compatibility and isolation.
#[tokio::test]
async fn s3_prefix_physical_compatibility() {
    let (storage, driver) = s3_backend_with_prefix("tenant-a");
    storage
        .put_manifest("iso", &d(HEX1), bytes::Bytes::from(manifest_json()))
        .await
        .unwrap();
    {
        let objs = driver.objects.lock().unwrap();
        assert_eq!(
            objs.get(&format!("tenant-a/repos/iso/manifests/{HEX1}"))
                .map(|(b, _)| b.to_vec()),
            Some(manifest_json()),
            "exact old physical key under the configured prefix"
        );
    }
    // Foreign sibling namespaces are invisible.
    driver.objects.lock().unwrap().insert(
        format!("tenant-b/repos/iso/manifests/{HEX2}"),
        (bytes::Bytes::from(manifest_json()), "\"x\"".to_string()),
    );
    assert!(matches!(
        storage.get_manifest("iso", &d(HEX2)).await,
        Err(StorageError::NotFound)
    ));
    let (page, _) = storage
        .list_manifest_digests_page("iso", None, 10)
        .await
        .unwrap();
    assert_eq!(page, vec![d(HEX1)], "sibling prefixes invisible in listing");
}

/// S3 failure classification at the registry boundary: GET/PUT/DELETE
/// AccessDenied -> PermissionDenied; backend failures -> Backend; and a
/// payload-delete failure PREVENTS the tag cleanup (frozen ordering).
#[tokio::test]
async fn s3_failure_classification_and_delete_ordering() {
    let b = s3_backend();
    let Backend::S3 { storage, driver } = &b else {
        unreachable!()
    };
    let key = format!("repos/errs/manifests/{HEX1}");
    b.seed_manifest_raw("errs", HEX1, &manifest_json());
    b.seed_tag_raw(
        "errs",
        "match",
        format!("{}\n", d(HEX1).as_str()).as_bytes(),
    );

    // GET AccessDenied.
    driver.set_hook_before({
        let key = key.clone();
        move |method, k| {
            if method == "get_object" && k == key {
                Some(StorageError::permission_denied("s3:GetObject forbidden"))
            } else {
                None
            }
        }
    });
    let err = storage.get_manifest("errs", &d(HEX1)).await.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    driver.clear_hooks();

    // PUT backend failure.
    driver.set_hook_before(|method, k| {
        if method == "put_object" && k.contains("/manifests/") {
            Some(StorageError::backend("s3 503 slow down"))
        } else {
            None
        }
    });
    let err = storage
        .put_manifest("errs", &d(HEX2), bytes::Bytes::from(manifest_json()))
        .await
        .unwrap_err();
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    driver.clear_hooks();

    // Payload-delete failure: tag cleanup must NOT run (frozen ordering).
    driver.set_hook_before({
        let key = key.clone();
        move |method, k| {
            if method == "delete_object" && k == key {
                Some(StorageError::permission_denied("s3:DeleteObject forbidden"))
            } else {
                None
            }
        }
    });
    let err = storage.delete_manifest("errs", &d(HEX1)).await.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    driver.clear_hooks();
    assert!(
        b.read_manifest_raw("errs", HEX1).is_some(),
        "payload survives"
    );
    assert!(
        b.tag_exists_raw("errs", "match"),
        "tag cleanup did not run after a failed payload delete"
    );

    // With the fault cleared the same deletion completes with cleanup.
    storage.delete_manifest("errs", &d(HEX1)).await.unwrap();
    assert!(!b.tag_exists_raw("errs", "match"));
}

/// Vanished listing candidate on S3: an object deleted between LIST and the
/// (name-only) digest parse never yields a phantom entry; and delete during
/// pagination is tolerated (covered by shared_listing_deleted_token_resumes).
#[tokio::test]
async fn s3_listing_is_name_only() {
    let b = s3_backend();
    let Backend::S3 { storage, driver } = &b else {
        unreachable!()
    };
    // A manifest whose payload is unreadable garbage still LISTS (name-only
    // listing performs no payload reads — frozen contract).
    driver.objects.lock().unwrap().insert(
        format!("repos/nameonly/manifests/{HEX1}"),
        (
            bytes::Bytes::from_static(&[0xff, 0xfe]),
            "\"x\"".to_string(),
        ),
    );
    let (page, _) = storage
        .list_manifest_digests_page("nameonly", None, 10)
        .await
        .unwrap();
    assert_eq!(page, vec![d(HEX1)]);
}

#[tokio::test]
async fn shared_manifest_pagination_two_phase_mixed_sha256_and_sha512() {
    for b in both() {
        let repo = "mixed-manifests";
        let mut expected_digests = Vec::new();
        for i in 0..15 {
            let hex_256 = format!("{:064x}", i);
            b.seed_manifest_raw(repo, &hex_256, &manifest_json());
            expected_digests.push(Digest::parse(&format!("sha256:{hex_256}")).unwrap());
        }
        for j in 0..15 {
            let hex_512 = format!("{:0128x}", j);
            b.seed_manifest_raw(repo, &hex_512, &manifest_json());
            expected_digests.push(Digest::parse(&format!("sha512:{hex_512}")).unwrap());
        }
        expected_digests.sort();

        let mut collected = Vec::new();
        let mut continuation_token = None;
        let page_limit = 7;

        loop {
            let (page, next_tok) = b
                .list(repo, continuation_token.as_deref(), page_limit)
                .await
                .unwrap();
            assert!(page.len() <= page_limit);
            collected.extend(page);
            continuation_token = next_tok;
            if continuation_token.is_none() {
                break;
            }
        }

        assert_eq!(collected.len(), 30, "backend: {}", b.name());
        assert_eq!(collected, expected_digests, "backend: {}", b.name());
    }
}

#[tokio::test]
async fn shared_manifest_pagination_adversarial_boundary_tokens() {
    for b in both() {
        let repo = "adversarial-boundary-manifests";
        let hex_256_0 = format!("{:064x}", 0);
        let hex_256_1 = format!("{:064x}", 1);
        let hex_256_f = format!("{:064x}", 0x0f);
        let hex_512_0 = format!("{:0128x}", 0);
        let hex_512_1 = format!("{:0128x}", 1);

        b.seed_manifest_raw(repo, &hex_256_0, &manifest_json());
        b.seed_manifest_raw(repo, &hex_256_1, &manifest_json());
        b.seed_manifest_raw(repo, &hex_256_f, &manifest_json());
        b.seed_manifest_raw(repo, &hex_512_0, &manifest_json());
        b.seed_manifest_raw(repo, &hex_512_1, &manifest_json());

        let d256_0 = Digest::parse(&format!("sha256:{hex_256_0}")).unwrap();
        let d256_1 = Digest::parse(&format!("sha256:{hex_256_1}")).unwrap();
        let d256_f = Digest::parse(&format!("sha256:{hex_256_f}")).unwrap();
        let d512_0 = Digest::parse(&format!("sha512:{hex_512_0}")).unwrap();
        let d512_1 = Digest::parse(&format!("sha512:{hex_512_1}")).unwrap();

        let tok_d256_0 = d256_0.as_str();
        let tok_d512_0 = d512_0.as_str();

        // 1. page_limit = 0 -> empty terminal page immediately
        let (page, next) = b.list(repo, None, 0).await.unwrap();
        assert!(page.is_empty());
        assert!(next.is_none());

        // 2. page_limit = usize::MAX -> returns all 5 manifests without OOM or panic
        let (page, next) = b.list(repo, None, usize::MAX).await.unwrap();
        assert_eq!(
            page,
            vec![
                d256_0.clone(),
                d256_1.clone(),
                d256_f.clone(),
                d512_0.clone(),
                d512_1.clone()
            ]
        );
        assert!(next.is_none());

        // 3. Token: Some("") (less than "sha256:") -> starts from the beginning of sha256
        let (page, next) = b.list(repo, Some(""), 1).await.unwrap();
        assert_eq!(page, vec![d256_0.clone()]);
        assert_eq!(next, Some(d256_0.as_str()));

        // 4. Token: Some("sha1:abcdef") (less than "sha256:") -> starts from beginning of sha256
        let (page, next) = b.list(repo, Some("sha1:abcdef"), 2).await.unwrap();
        assert_eq!(page, vec![d256_0.clone(), d256_1.clone()]);
        assert_eq!(next, Some(d256_1.as_str()));

        // 5. Token: Some("sha256") (without colon, less than "sha256:") -> starts from beginning of sha256
        let (page, next) = b.list(repo, Some("sha256"), 1).await.unwrap();
        assert_eq!(page, vec![d256_0.clone()]);
        assert_eq!(next, Some(d256_0.as_str()));

        // 6. Token: Some("sha256:0000000000000000000000000000000000000000000000000000000000000000")
        // Resumes strictly after d256_0
        let (page, next) = b.list(repo, Some(&tok_d256_0), 2).await.unwrap();
        assert_eq!(page, vec![d256_1.clone(), d256_f.clone()]);
        assert_eq!(next, Some(d256_f.as_str()));

        // 7. Token: Some("sha256~") (between all sha256 and sha512) -> skips sha256, starts sha512 from beginning!
        let (page, next) = b.list(repo, Some("sha256~"), 1).await.unwrap();
        assert_eq!(page, vec![d512_0.clone()]);
        assert_eq!(next, Some(d512_0.as_str()));

        // 8. Token: Some("sha384:abcdef") (between sha256 and sha512) -> skips sha256, starts sha512 from beginning!
        let (page, next) = b.list(repo, Some("sha384:abcdef"), 1).await.unwrap();
        assert_eq!(page, vec![d512_0.clone()]);
        assert_eq!(next, Some(d512_0.as_str()));

        // 9. Token: Some("sha512") (without colon, between sha256 and sha512) -> starts sha512 from beginning!
        let (page, next) = b.list(repo, Some("sha512"), 1).await.unwrap();
        assert_eq!(page, vec![d512_0.clone()]);
        assert_eq!(next, Some(d512_0.as_str()));

        // 10. Token: Some(d512_0.as_str()) -> resumes strictly after d512_0
        let (page, next) = b.list(repo, Some(&tok_d512_0), 5).await.unwrap();
        assert_eq!(page, vec![d512_1.clone()]);
        assert!(next.is_none());

        // 11. Token: Some("sha512~") (after all sha512) -> empty terminal page
        let (page, next) = b.list(repo, Some("sha512~"), 5).await.unwrap();
        assert!(page.is_empty());
        assert!(next.is_none());

        // 12. Token: Some("sha513:1234") (after all sha512) -> empty terminal page
        let (page, next) = b.list(repo, Some("sha513:1234"), 5).await.unwrap();
        assert!(page.is_empty());
        assert!(next.is_none());

        // 13. Token: Some("zzz") (after all sha512) -> empty terminal page
        let (page, next) = b.list(repo, Some("zzz"), 5).await.unwrap();
        assert!(page.is_empty());
        assert!(next.is_none());
    }
}

#[tokio::test]
async fn shared_manifest_pagination_adversarial_only_sha512() {
    for b in both() {
        let repo = "only-sha512-repo";
        let mut expected = Vec::new();
        for i in 0..7 {
            let hex_512 = format!("{:0128x}", i);
            b.seed_manifest_raw(repo, &hex_512, &manifest_json());
            expected.push(Digest::parse(&format!("sha512:{hex_512}")).unwrap());
        }
        expected.sort();

        let mut collected = Vec::new();
        let mut token = None;
        let page_limit = 3;

        loop {
            let (page, next_tok) = b.list(repo, token.as_deref(), page_limit).await.unwrap();
            assert!(page.len() <= page_limit);
            collected.extend(page);
            token = next_tok;
            if token.is_none() {
                break;
            }
        }

        assert_eq!(collected, expected, "backend: {}", b.name());
    }
}
