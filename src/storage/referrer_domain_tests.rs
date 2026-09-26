//! Cross-backend shared registry referrer behavior suite (Phase 5).
//!
//! ONE expectation set executed against BOTH production storage backends
//! over their real migrated referrer paths (FsStorage over a real temporary
//! root; S3Storage over the real `S3ObjectStore` adapter driven by the
//! deterministic mock client). Raw seeding/reading uses each backend's OLD
//! physical representation (`<root>/repos/<repo>/referrers/<hex>.json` file
//! / `repos/<repo>/referrers/<hex>.json` bucket key), so the suite doubles
//! as the existing-data / byte-layout compatibility proof: no migration job.
//!
//! The conditional read-modify-write mechanics (stale replace, stale final
//! delete, creation race, bounded-retry exhaustion, best-effort delete) are
//! driven deterministically at the domain layer through an interposing
//! [`ObjectStore`] decorator over BOTH real adapters — an "external writer"
//! that mutates the object between the domain's read and its conditional
//! action.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use storage_core::ObjectKey;
use storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ListPage, ObjectMeta, ObjectRead,
    ObjectStore, ObjectVersion, PageToken, ReplaceOutcome, StoreError, VersionedRead,
};

use super::super::s3::tests::{MockS3Driver, TagBridgeDriver, create_mock_storage};
use super::{ReferrerDomain, ReferrerLockShards};
use crate::registry::digest::Digest;
use crate::storage::fs::FsStorage;
use crate::storage::s3::S3Storage;
use crate::storage::{ReferrerDescriptor, Storage, StorageError, StorageErrorKind};
use std::path::PathBuf;

const SUBJ: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SUBJ512: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REF_A: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const REF_B: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const REF_C: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const REF_X: &str = "sha256:9999999999999999999999999999999999999999999999999999999999999999";

fn d(s: &str) -> Digest {
    Digest::parse(s).unwrap()
}

fn subj() -> Digest {
    Digest::parse(&format!("sha256:{SUBJ}")).unwrap()
}

fn subj512() -> Digest {
    Digest::parse(&format!("sha512:{SUBJ512}")).unwrap()
}

fn desc(digest: &str) -> ReferrerDescriptor {
    ReferrerDescriptor {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        digest: digest.to_string(),
        size: 42,
        artifact_type: None,
        annotations: None,
    }
}

fn desc_full(digest: &str) -> ReferrerDescriptor {
    let mut annotations = std::collections::HashMap::new();
    annotations.insert("org.example.key".to_string(), "value".to_string());
    ReferrerDescriptor {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        digest: digest.to_string(),
        size: 7,
        artifact_type: Some("application/vnd.example.sbom".to_string()),
        annotations: Some(annotations),
    }
}

fn index_bytes(descs: &[ReferrerDescriptor]) -> Vec<u8> {
    serde_json::to_vec(&descs.to_vec()).unwrap()
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

    /// Seeds a referrer index in the exact PRE-MIGRATION physical layout.
    fn seed_index_raw(&self, repo: &str, subject_hex: &str, bytes: &[u8]) {
        match self {
            Backend::Fs { root, .. } => {
                let path = root
                    .join("repos")
                    .join(repo)
                    .join("referrers")
                    .join(format!("{subject_hex}.json"));
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            Backend::S3 { driver, .. } => {
                driver.objects.lock().unwrap().insert(
                    format!("repos/{repo}/referrers/{subject_hex}.json"),
                    (Bytes::from(bytes.to_vec()), "\"seeded\"".to_string()),
                );
            }
        }
    }

    /// Reads the raw index at the exact pre-migration physical location.
    fn read_index_raw(&self, repo: &str, subject_hex: &str) -> Option<Vec<u8>> {
        match self {
            Backend::Fs { root, .. } => std::fs::read(
                root.join("repos")
                    .join(repo)
                    .join("referrers")
                    .join(format!("{subject_hex}.json")),
            )
            .ok(),
            Backend::S3 { driver, .. } => driver
                .objects
                .lock()
                .unwrap()
                .get(&format!("repos/{repo}/referrers/{subject_hex}.json"))
                .map(|(b, _)| b.to_vec()),
        }
    }

    async fn list(&self, r: &str, s: &Digest) -> Result<Vec<ReferrerDescriptor>, StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.list_referrers(r, s).await,
            Backend::S3 { storage, .. } => storage.list_referrers(r, s).await,
        }
    }

    async fn page(
        &self,
        r: &str,
        s: &Digest,
        token: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<ReferrerDescriptor>, Option<String>), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.list_referrers_page(r, s, token, limit).await,
            Backend::S3 { storage, .. } => storage.list_referrers_page(r, s, token, limit).await,
        }
    }

    async fn add(&self, r: &str, s: &Digest, de: ReferrerDescriptor) -> Result<(), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.add_referrer(r, s, de).await,
            Backend::S3 { storage, .. } => storage.add_referrer(r, s, de).await,
        }
    }

    async fn remove(&self, r: &str, s: &Digest, re: &Digest) -> Result<(), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.remove_referrer(r, s, re).await,
            Backend::S3 { storage, .. } => storage.remove_referrer(r, s, re).await,
        }
    }
}

fn digests(list: &[ReferrerDescriptor]) -> Vec<&str> {
    list.iter().map(|d| d.digest.as_str()).collect()
}

// ---------------------------------------------------------------------------
// Reads / old-layout compatibility (§16 items 1, 2, 3, 9, 13, 15, 16, 17, 18)
// ---------------------------------------------------------------------------

/// Absent repository, absent referrers namespace, and absent index all read
/// as an EMPTY list (never NotFound) — the frozen contract of both backends.
#[tokio::test]
async fn shared_absent_index_reads_empty() {
    for b in both() {
        let n = b.name();
        assert_eq!(b.list("no-such-repo", &subj()).await.unwrap(), vec![]);
        b.seed_index_raw("other", SUBJ, &index_bytes(&[desc(REF_A)]));
        assert_eq!(
            b.list("other", &subj512()).await.unwrap(),
            vec![],
            "[{n}] different subject is absent"
        );
        let (page, token) = b.page("no-such-repo", &subj(), None, 10).await.unwrap();
        assert!(page.is_empty() && token.is_none(), "[{n}] empty page");
    }
}

/// Pre-migration seeded indexes read identically through the new shared
/// layer: exact descriptors, PHYSICAL (insertion) order preserved without
/// sorting or deduplication, snake_case field names, unknown fields ignored,
/// missing optional fields → None, sha512 subjects at their 128-hex stems.
#[tokio::test]
async fn shared_old_layout_read_compatibility() {
    for b in both() {
        let n = b.name();
        // Unsorted on purpose: C, A, B — order must be preserved.
        b.seed_index_raw(
            "old-repo",
            SUBJ,
            &index_bytes(&[desc(REF_C), desc_full(REF_A), desc(REF_B)]),
        );
        let listed = b.list("old-repo", &subj()).await.unwrap();
        assert_eq!(
            digests(&listed),
            vec![REF_C, REF_A, REF_B],
            "[{n}] physical order preserved"
        );
        assert_eq!(
            listed[1],
            desc_full(REF_A),
            "[{n}] full descriptor roundtrip"
        );

        // Unknown fields ignored; missing optionals -> None; snake_case names.
        b.seed_index_raw(
            "old-repo",
            SUBJ512,
            br#"[{"media_type":"application/x","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":3,"future_field":true}]"#,
        );
        let listed = b.list("old-repo", &subj512()).await.unwrap();
        assert_eq!(listed.len(), 1, "[{n}] sha512 subject stem read");
        assert_eq!(listed[0].media_type, "application/x", "[{n}]");
        assert_eq!(listed[0].artifact_type, None, "[{n}] missing optional");
        assert_eq!(listed[0].annotations, None, "[{n}] missing optional");
    }
}

/// Corrupt index taxonomy: malformed JSON, invalid UTF-8, and a wrong
/// top-level shape are the preserved legacy `Internal{Io}` failure carrying
/// the verbatim serde message (the retired S3 CorruptData kind converges —
/// both kinds were production-inert). Mutations FAIL CLOSED: the stored
/// bytes are untouched.
#[tokio::test]
async fn shared_corrupt_index_taxonomy_and_fail_closed_mutations() {
    let corrupt_payloads: [&[u8]; 4] = [
        b"{not json",
        b"\xff\xfe\xfd",
        br#"{"media_type":"top-level object"}"#,
        b"",
    ];
    for b in both() {
        let n = b.name();
        for (i, payload) in corrupt_payloads.iter().enumerate() {
            let repo = format!("corrupt-{i}");
            b.seed_index_raw(&repo, SUBJ, payload);

            let err = b.list(&repo, &subj()).await.expect_err("corrupt must fail");
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::Io),
                "[{n}/{i}] legacy Io taxonomy, got {err:?}"
            );

            let err = b
                .add(&repo, &subj(), desc(REF_B))
                .await
                .expect_err("[add] corrupt index must fail closed");
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io), "[{n}/{i}]");

            let err = b
                .remove(&repo, &subj(), &d(REF_A))
                .await
                .expect_err("[remove] corrupt index must fail closed");
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io), "[{n}/{i}]");

            assert_eq!(
                b.read_index_raw(&repo, SUBJ).unwrap(),
                payload.to_vec(),
                "[{n}/{i}] fail-closed: stored bytes untouched"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Add (§16 items 6, 7, 8, 15, 17, 18)
// ---------------------------------------------------------------------------

/// First add creates the index at the EXACT pre-migration physical location
/// with the exact compact snake_case array bytes; second add appends at the
/// tail. sha256 and sha512 subjects land at their algorithm's hex stem.
#[tokio::test]
async fn shared_add_first_and_second_physical_compatibility() {
    for b in both() {
        let n = b.name();
        b.add("r", &subj(), desc_full(REF_A)).await.unwrap();
        let raw = b
            .read_index_raw("r", SUBJ)
            .expect("index created at old physical key");
        assert_eq!(
            raw,
            index_bytes(&[desc_full(REF_A)]),
            "[{n}] exact compact snake_case bytes"
        );
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains("\"media_type\""), "[{n}] snake_case on disk");
        assert!(text.contains("\"artifact_type\""), "[{n}]");
        assert!(!text.contains("mediaType"), "[{n}] no camelCase on disk");

        b.add("r", &subj(), desc(REF_B)).await.unwrap();
        let listed = b.list("r", &subj()).await.unwrap();
        assert_eq!(digests(&listed), vec![REF_A, REF_B], "[{n}] tail append");

        // None optionals are omitted entirely from the serialized bytes.
        let raw = b.read_index_raw("r", SUBJ).unwrap();
        let text = String::from_utf8(raw).unwrap();
        assert_eq!(
            text.matches("artifact_type").count(),
            1,
            "[{n}] None artifact_type omitted for the second entry"
        );

        // sha512 subject → 128-hex stem in the same flat namespace.
        b.add("r", &subj512(), desc(REF_C)).await.unwrap();
        assert!(
            b.read_index_raw("r", SUBJ512).is_some(),
            "[{n}] sha512 physical stem"
        );
    }
}

/// Duplicate add: dedup by digest string only — the array does not grow and
/// the FIRST descriptor's metadata is never refreshed.
#[tokio::test]
async fn shared_duplicate_add_semantics() {
    for b in both() {
        let n = b.name();
        b.add("r", &subj(), desc_full(REF_A)).await.unwrap();
        // Same digest, different metadata: must be a content no-op.
        let mut altered = desc(REF_A);
        altered.media_type = "application/x-altered".to_string();
        altered.size = 9999;
        b.add("r", &subj(), altered).await.unwrap();

        let listed = b.list("r", &subj()).await.unwrap();
        assert_eq!(listed.len(), 1, "[{n}] duplicate does not grow the array");
        assert_eq!(
            listed[0],
            desc_full(REF_A),
            "[{n}] first-written metadata wins; never refreshed"
        );
    }
}

// ---------------------------------------------------------------------------
// Remove (§16 items 10, 11, 12)
// ---------------------------------------------------------------------------

/// Remove one of several (survivor order preserved), remove an absent
/// descriptor (no write at all — raw bytes byte-identical), and remove the
/// final descriptor (the index OBJECT is deleted; an empty index is never
/// persisted as `[]`).
#[tokio::test]
async fn shared_remove_semantics() {
    for b in both() {
        let n = b.name();
        b.seed_index_raw(
            "r",
            SUBJ,
            &index_bytes(&[desc(REF_C), desc(REF_A), desc(REF_B)]),
        );

        // Remove the middle entry: survivors keep physical order.
        b.remove("r", &subj(), &d(REF_A)).await.unwrap();
        let listed = b.list("r", &subj()).await.unwrap();
        assert_eq!(digests(&listed), vec![REF_C, REF_B], "[{n}] survivor order");

        // Absent descriptor: Ok with NO write (bytes stay identical).
        let before = b.read_index_raw("r", SUBJ).unwrap();
        b.remove("r", &subj(), &d(REF_X)).await.unwrap();
        assert_eq!(
            b.read_index_raw("r", SUBJ).unwrap(),
            before,
            "[{n}] absent-descriptor removal writes nothing"
        );

        // Remove the remaining two: the index object itself is deleted.
        b.remove("r", &subj(), &d(REF_C)).await.unwrap();
        b.remove("r", &subj(), &d(REF_B)).await.unwrap();
        assert!(
            b.read_index_raw("r", SUBJ).is_none(),
            "[{n}] empty index is deleted, never persisted as []"
        );
        assert_eq!(b.list("r", &subj()).await.unwrap(), vec![], "[{n}]");

        // Absent index: Ok, and nothing is created. (The retired FS mutation
        // pre-created `repos/<repo>/referrers/` as an authority-resolution
        // side effect even for no-ops; the shared domain performs no write
        // and creates nothing — pinned here. No production caller reaches a
        // no-op remove on a nonexistent repository: manifest-delete cleanup
        // and recovery replay both operate on repositories that exist.)
        b.remove("fresh-repo", &subj(), &d(REF_A)).await.unwrap();
        if let Backend::Fs { root, .. } = &b {
            assert!(
                !root.join("repos").join("fresh-repo").exists(),
                "[{n}] no-op remove creates no directories"
            );
        }
    }
}

/// Removal matches every descriptor with the digest (all duplicates go),
/// using the canonical `algo:hex` string form.
#[tokio::test]
async fn shared_remove_matches_all_duplicates() {
    for b in both() {
        let n = b.name();
        // Duplicates can exist on disk via non-add_referrer writers.
        b.seed_index_raw(
            "r",
            SUBJ,
            &index_bytes(&[desc(REF_A), desc(REF_B), desc(REF_A)]),
        );
        b.remove("r", &subj(), &d(REF_A)).await.unwrap();
        let listed = b.list("r", &subj()).await.unwrap();
        assert_eq!(digests(&listed), vec![REF_B], "[{n}] all matches removed");
    }
}

// ---------------------------------------------------------------------------
// Repository / digest grammar (§16 items 14, 15)
// ---------------------------------------------------------------------------

/// Structural repository grammar fails closed with InvalidRepoName on every
/// operation, before any backend access; multi-segment repositories map to
/// nested physical paths exactly as before.
#[tokio::test]
async fn shared_repository_grammar() {
    for b in both() {
        let n = b.name();
        for bad in [
            "", "/lead", "trail/", "a//b", "a/./b", "a/../b", "a\\b", "a\0b",
        ] {
            assert!(
                matches!(
                    b.list(bad, &subj()).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "[{n}] list rejects {bad:?}"
            );
            assert!(
                matches!(
                    b.add(bad, &subj(), desc(REF_A)).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "[{n}] add rejects {bad:?}"
            );
            assert!(
                matches!(
                    b.remove(bad, &subj(), &d(REF_A)).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "[{n}] remove rejects {bad:?}"
            );
            // Frozen page contract: EVERY failure — including the grammar
            // rejection — is swallowed into an empty terminal page.
            let (p, t) = b.page(bad, &subj(), None, 10).await.unwrap();
            assert!(
                p.is_empty() && t.is_none(),
                "[{n}] page swallows {bad:?} into an empty page"
            );
        }

        b.add("org/team/app", &subj(), desc(REF_A)).await.unwrap();
        assert!(
            b.read_index_raw("org/team/app", SUBJ).is_some(),
            "[{n}] nested repository physical path"
        );
    }
}

// ---------------------------------------------------------------------------
// Pagination (§16 item — list_referrers_page contract; no production caller)
// ---------------------------------------------------------------------------

/// The frozen `list_referrers_page` contract: digest-ascending sort,
/// strictly-after tokens (vanished token resumes at its insertion point),
/// last-returned-digest next token, page_limit 0 dead-end, and EVERY read
/// failure swallowed into an empty terminal page.
#[tokio::test]
async fn shared_pagination_contract() {
    for b in both() {
        let n = b.name();
        b.seed_index_raw(
            "r",
            SUBJ,
            &index_bytes(&[desc(REF_C), desc(REF_A), desc(REF_B)]),
        );

        let (p1, t1) = b.page("r", &subj(), None, 2).await.unwrap();
        assert_eq!(digests(&p1), vec![REF_A, REF_B], "[{n}] digest sort");
        assert_eq!(t1.as_deref(), Some(REF_B), "[{n}] last returned digest");

        let (p2, t2) = b.page("r", &subj(), t1.as_deref(), 2).await.unwrap();
        assert_eq!(digests(&p2), vec![REF_C], "[{n}] strictly-after resumption");
        assert!(t2.is_none(), "[{n}] terminal page");

        // Vanished token resumes at the insertion point.
        let (p3, _) = b
            .page("r", &subj(), Some(REF_A), 10)
            .await
            .map(|(p, t)| (p, t))
            .unwrap();
        assert_eq!(digests(&p3), vec![REF_B, REF_C], "[{n}]");
        b.remove("r", &subj(), &d(REF_B)).await.unwrap();
        let (p4, _) = b.page("r", &subj(), Some(REF_B), 10).await.unwrap();
        assert_eq!(digests(&p4), vec![REF_C], "[{n}] vanished token");

        // page_limit == 0: empty page, no token (frozen dead-end).
        let (p5, t5) = b.page("r", &subj(), None, 0).await.unwrap();
        assert!(p5.is_empty() && t5.is_none(), "[{n}] page_limit 0");

        // Corrupt index: swallowed into an empty terminal page (while the
        // direct list propagates).
        b.seed_index_raw("swallow", SUBJ, b"{corrupt");
        assert!(b.list("swallow", &subj()).await.is_err(), "[{n}]");
        let (p6, t6) = b.page("swallow", &subj(), None, 10).await.unwrap();
        assert!(p6.is_empty() && t6.is_none(), "[{n}] error swallowed");
    }
}

// ---------------------------------------------------------------------------
// Concurrency through the public Storage surface (§16 items 23, 24)
// ---------------------------------------------------------------------------

/// Concurrent same-subject adds of distinct descriptors all survive — the
/// historical in-process guarantee, preserved by the shared domain's shard
/// lock (and additionally version-safe underneath).
#[tokio::test]
async fn shared_concurrent_adds_all_survive() {
    // FS
    {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let storage = Arc::new(FsStorage::try_new(root, 10 * 1024 * 1024).unwrap());
        run_concurrent_adds("fs", storage).await;
    }
    // S3 (clones share one lock-shard set via Arc)
    {
        let (storage, _driver) = create_mock_storage();
        run_concurrent_adds("s3", Arc::new(storage)).await;
    }
}

async fn run_concurrent_adds<S: Storage + 'static>(n: &str, storage: Arc<S>) {
    let subject = subj();
    let mut handles = Vec::new();
    for i in 0..8 {
        let st = Arc::clone(&storage);
        let subject = subject.clone();
        handles.push(tokio::spawn(async move {
            let digest = format!(
                "sha256:{}",
                format!("{i}")
                    .repeat(64)
                    .chars()
                    .take(64)
                    .collect::<String>()
            );
            st.add_referrer("race", &subject, desc(&digest)).await
        }));
    }
    for h in handles {
        h.await
            .unwrap()
            .unwrap_or_else(|e| panic!("[{n}] concurrent add failed: {e:?}"));
    }
    let listed = storage.list_referrers("race", &subject).await.unwrap();
    assert_eq!(listed.len(), 8, "[{n}] all 8 concurrent adds survive");
}

/// Concurrent add(B) and remove(A) from a seeded [A] converge without losing
/// either mutation: the end state is exactly [B].
#[tokio::test]
async fn shared_concurrent_add_remove_converge() {
    // FS
    {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        std::fs::create_dir_all(&root).unwrap();
        let seeded = root
            .join("repos")
            .join("r")
            .join("referrers")
            .join(format!("{SUBJ}.json"));
        std::fs::create_dir_all(seeded.parent().unwrap()).unwrap();
        std::fs::write(&seeded, index_bytes(&[desc(REF_A)])).unwrap();
        let storage = Arc::new(FsStorage::try_new(root, 10 * 1024 * 1024).unwrap());
        run_add_remove_race("fs", storage).await;
    }
    // S3
    {
        let (storage, driver) = create_mock_storage();
        driver.objects.lock().unwrap().insert(
            format!("repos/r/referrers/{SUBJ}.json"),
            (
                Bytes::from(index_bytes(&[desc(REF_A)])),
                "\"s\"".to_string(),
            ),
        );
        run_add_remove_race("s3", Arc::new(storage)).await;
    }
}

async fn run_add_remove_race<S: Storage + 'static>(n: &str, storage: Arc<S>) {
    let subject = subj();
    let st1 = Arc::clone(&storage);
    let sub1 = subject.clone();
    let add = tokio::spawn(async move { st1.add_referrer("r", &sub1, desc(REF_B)).await });
    let st2 = Arc::clone(&storage);
    let sub2 = subject.clone();
    let remove = tokio::spawn(async move { st2.remove_referrer("r", &sub2, &d(REF_A)).await });
    add.await.unwrap().unwrap();
    remove.await.unwrap().unwrap();
    let listed = storage.list_referrers("r", &subject).await.unwrap();
    assert_eq!(digests(&listed), vec![REF_B], "[{n}] both mutations landed");
}

// ---------------------------------------------------------------------------
// Manifest-delete integration (§16 items 27, 28)
// ---------------------------------------------------------------------------

fn manifest_with_subject(subject: &Digest) -> Vec<u8> {
    format!(
        r#"{{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "subject": {{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "{}", "size": 2}}}}"#,
        subject.as_str()
    )
    .into_bytes()
}

/// Deleting a manifest that names a subject removes ITS referrer entry as
/// the final step; other entries survive; the removal stays best-effort.
#[tokio::test]
async fn shared_manifest_delete_referrer_cleanup() {
    for b in both() {
        let n = b.name();
        let referrer_manifest = manifest_with_subject(&subj());
        let referrer_digest = {
            use sha2::Digest as _;
            let h = sha2::Sha256::digest(&referrer_manifest);
            Digest::parse(&format!("sha256:{}", hex::encode(h))).unwrap()
        };
        let (storage_put, storage_del): (&dyn Storage, &dyn Storage) = match &b {
            Backend::Fs { storage, .. } => (storage, storage),
            Backend::S3 { storage, .. } => (storage, storage),
        };
        storage_put
            .put_manifest("r", &referrer_digest, Bytes::from(referrer_manifest))
            .await
            .unwrap();
        // The index holds the referrer's entry plus an unrelated survivor.
        b.add("r", &subj(), desc(&referrer_digest.as_str()))
            .await
            .unwrap();
        b.add("r", &subj(), desc(REF_B)).await.unwrap();

        storage_del
            .delete_manifest("r", &referrer_digest)
            .await
            .unwrap();

        let listed = b.list("r", &subj()).await.unwrap();
        assert_eq!(
            digests(&listed),
            vec![REF_B],
            "[{n}] referrer cleanup ran last and removed exactly the deleted manifest's entry"
        );
        assert!(
            matches!(
                storage_del.get_manifest("r", &referrer_digest).await,
                Err(StorageError::NotFound)
            ),
            "[{n}] manifest payload gone"
        );
    }
}

/// Referrer-cleanup failure never blocks manifest deletion (frozen
/// best-effort ordering): with a CORRUPT referrer index the delete still
/// succeeds, the manifest is gone, and the dangling index is untouched.
#[tokio::test]
async fn shared_manifest_delete_survives_referrer_cleanup_failure() {
    for b in both() {
        let n = b.name();
        let referrer_manifest = manifest_with_subject(&subj());
        let referrer_digest = {
            use sha2::Digest as _;
            let h = sha2::Sha256::digest(&referrer_manifest);
            Digest::parse(&format!("sha256:{}", hex::encode(h))).unwrap()
        };
        let storage: &dyn Storage = match &b {
            Backend::Fs { storage, .. } => storage,
            Backend::S3 { storage, .. } => storage,
        };
        storage
            .put_manifest("r", &referrer_digest, Bytes::from(referrer_manifest))
            .await
            .unwrap();
        b.seed_index_raw("r", SUBJ, b"{corrupt referrer index");

        storage
            .delete_manifest("r", &referrer_digest)
            .await
            .unwrap();
        assert!(
            matches!(
                storage.get_manifest("r", &referrer_digest).await,
                Err(StorageError::NotFound)
            ),
            "[{n}] manifest deletion succeeded despite referrer-cleanup failure"
        );
        assert_eq!(
            b.read_index_raw("r", SUBJ).unwrap(),
            b"{corrupt referrer index".to_vec(),
            "[{n}] failed cleanup left the index untouched (fail closed + swallowed)"
        );
    }
}

// ---------------------------------------------------------------------------
// Deterministic CAS mechanics at the domain layer (§16 items 19-21, 23-26)
// ---------------------------------------------------------------------------

/// An "external writer" decorator: before delegating the first
/// `interpositions` conditional mutations, it writes `external` bytes (or
/// deletes the object when `external` is None) through the inner store —
/// deterministically staling the version the domain observed.
struct InterposingStore {
    inner: Arc<dyn ObjectStore>,
    remaining: AtomicUsize,
    seq: AtomicUsize,
    // Bytes for the i-th interposition. MUST vary per call when more than
    // one interposition can land within one filesystem timestamp tick: the
    // FS adapter's version is content+mtime derived, so byte-identical
    // rapid rewrites can legitimately share a version.
    external: Box<dyn Fn(usize) -> Vec<u8> + Send + Sync>,
}

impl InterposingStore {
    fn new(
        inner: Arc<dyn ObjectStore>,
        interpositions: usize,
        external: impl Fn(usize) -> Vec<u8> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner,
            remaining: AtomicUsize::new(interpositions),
            seq: AtomicUsize::new(0),
            external: Box::new(external),
        }
    }

    async fn maybe_interpose(&self, key: &ObjectKey) {
        let mut cur = self.remaining.load(Ordering::SeqCst);
        loop {
            if cur == 0 {
                return;
            }
            match self
                .remaining
                .compare_exchange(cur, cur - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(now) => cur = now,
            }
        }
        let i = self.seq.fetch_add(1, Ordering::SeqCst);
        let bytes = (self.external)(i);
        self.inner
            .write(key, Bytes::from(bytes), Durability::Durable)
            .await
            .expect("external interposed write");
    }
}

#[async_trait]
impl ObjectStore for InterposingStore {
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
        self.inner.write(key, bytes, durability).await
    }
    async fn write_if_absent(
        &self,
        key: &ObjectKey,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<CreateOutcome, StoreError> {
        self.maybe_interpose(key).await;
        self.inner.write_if_absent(key, bytes, durability).await
    }
    async fn replace_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
        bytes: Bytes,
        durability: Durability,
    ) -> Result<ReplaceOutcome, StoreError> {
        self.maybe_interpose(key).await;
        self.inner
            .replace_if_version(key, expected, bytes, durability)
            .await
    }
    async fn delete(&self, key: &ObjectKey) -> Result<(), StoreError> {
        self.inner.delete(key).await
    }
    async fn delete_if_version(
        &self,
        key: &ObjectKey,
        expected: &ObjectVersion,
    ) -> Result<ConditionalDeleteOutcome, StoreError> {
        self.maybe_interpose(key).await;
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

/// A decorator failing every conditional delete with a backend fault
/// (delegating everything else) — drives the historical best-effort
/// empty-index removal swallow.
struct FailingDeleteStore {
    inner: Arc<dyn ObjectStore>,
}

#[async_trait]
impl ObjectStore for FailingDeleteStore {
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
        self.inner.delete(key).await
    }
    async fn delete_if_version(
        &self,
        _key: &ObjectKey,
        _expected: &ObjectVersion,
    ) -> Result<ConditionalDeleteOutcome, StoreError> {
        Err(StoreError::backend("injected conditional-delete fault"))
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

/// Raw adapter stores for domain-layer tests: the REAL FS adapter over a
/// temporary root and the REAL S3 adapter over the deterministic mock
/// client.
fn raw_stores() -> Vec<(&'static str, tempfile::TempDir, Arc<dyn ObjectStore>)> {
    let mut out: Vec<(&'static str, tempfile::TempDir, Arc<dyn ObjectStore>)> = Vec::new();
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    out.push((
        "fs",
        tmp,
        Arc::new(storage_fs::FsObjectStore::open(&root).unwrap()),
    ));
    let tmp2 = tempfile::tempdir().unwrap();
    let client = Arc::new(storage_s3::mock::MockS3Client::new());
    out.push((
        "s3",
        tmp2,
        Arc::new(storage_s3::S3ObjectStore::new(client, None).unwrap()),
    ));
    out
}

fn domain_over(store: Arc<dyn ObjectStore>) -> ReferrerDomain {
    ReferrerDomain::new(store, Arc::new(ReferrerLockShards::new()))
}

async fn seed_via_store(store: &dyn ObjectStore, descs: &[ReferrerDescriptor]) {
    let key = super::referrers_key("r", &subj()).unwrap();
    store
        .write(&key, Bytes::from(index_bytes(descs)), Durability::Durable)
        .await
        .unwrap();
}

/// Stale replace survives: an external writer replaces the generation the
/// domain read; the conditional replace refuses, the domain re-reads and
/// merges — ALL updates survive (the retired unconditional PUT lost one).
#[tokio::test]
async fn domain_stale_replace_survives_external_update() {
    for (n, _guard, inner) in raw_stores() {
        seed_via_store(inner.as_ref(), &[desc(REF_A)]).await;
        let interposed = Arc::new(InterposingStore::new(Arc::clone(&inner), 1, |_| {
            index_bytes(&[desc(REF_A), desc(REF_X)])
        }));
        let dom = domain_over(interposed);
        dom.add_referrer("r", &subj(), desc(REF_B)).await.unwrap();

        let listed = dom.list_referrers("r", &subj()).await.unwrap();
        assert_eq!(
            digests(&listed),
            vec![REF_A, REF_X, REF_B],
            "[{n}] external update AND the domain add both survive"
        );
    }
}

/// Creation race: the external writer creates the index between the
/// domain's absent read and its write_if_absent; the loser re-reads and
/// appends instead of clobbering.
#[tokio::test]
async fn domain_creation_race_retries_and_merges() {
    for (n, _guard, inner) in raw_stores() {
        let interposed = Arc::new(InterposingStore::new(Arc::clone(&inner), 1, |_| {
            index_bytes(&[desc(REF_X)])
        }));
        let dom = domain_over(interposed);
        dom.add_referrer("r", &subj(), desc(REF_B)).await.unwrap();

        let listed = dom.list_referrers("r", &subj()).await.unwrap();
        assert_eq!(
            digests(&listed),
            vec![REF_X, REF_B],
            "[{n}] creation loser merged instead of clobbering"
        );
    }
}

/// Stale final-delete never erases a replacement: removal reads [A],
/// decides to delete the (empty-after-removal) index, an external writer
/// replaces the index with [A, B] first — the conditional delete refuses,
/// the retry re-reads and rewrites [B]. B is never silently erased.
#[tokio::test]
async fn domain_stale_final_delete_never_erases_replacement() {
    for (n, _guard, inner) in raw_stores() {
        seed_via_store(inner.as_ref(), &[desc(REF_A)]).await;
        let interposed = Arc::new(InterposingStore::new(Arc::clone(&inner), 1, |_| {
            index_bytes(&[desc(REF_A), desc(REF_B)])
        }));
        let dom = domain_over(interposed);
        dom.remove_referrer("r", &subj(), &d(REF_A)).await.unwrap();

        let listed = dom.list_referrers("r", &subj()).await.unwrap();
        assert_eq!(
            digests(&listed),
            vec![REF_B],
            "[{n}] replacement generation survived the stale delete"
        );
    }
}

/// Bounded retry exhaustion is a truthful Backend-kind error (never a
/// silent lost update): under sustained external interference the mutation
/// gives up after the fixed budget and the LAST external generation is
/// preserved untouched.
#[tokio::test]
async fn domain_contention_exhaustion_truthful() {
    for (n, _guard, inner) in raw_stores() {
        seed_via_store(inner.as_ref(), &[desc(REF_A)]).await;
        // Varying content per interposition: the sustained external writer
        // must produce a genuinely new generation each time.
        let interposed = Arc::new(InterposingStore::new(Arc::clone(&inner), usize::MAX, |i| {
            let mut ext = desc(REF_X);
            ext.size = i as u64;
            index_bytes(&[ext])
        }));
        let dom = domain_over(interposed);
        let err = dom
            .add_referrer("r", &subj(), desc(REF_B))
            .await
            .expect_err("sustained interference must exhaust the bounded budget");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::Backend),
            "[{n}] got {err:?}"
        );
        assert!(
            err.to_string().contains("optimistic-concurrency attempts"),
            "[{n}] truthful exhaustion message: {err}"
        );

        let listed = dom.list_referrers("r", &subj()).await.unwrap();
        assert_eq!(
            digests(&listed),
            vec![REF_X],
            "[{n}] the external generation is never clobbered"
        );

        let err = dom
            .remove_referrer("r", &subj(), &d(REF_X))
            .await
            .expect_err("removal exhausts the same bounded budget");
        assert!(
            err.to_string().contains("optimistic-concurrency attempts"),
            "[{n}] {err}"
        );
    }
}

/// Backend failure of the empty-index conditional delete is swallowed —
/// the historical best-effort removal (P1 Option A), preserved exactly:
/// remove returns Ok and the index object remains.
#[tokio::test]
async fn domain_empty_index_delete_failure_swallowed() {
    for (n, _guard, inner) in raw_stores() {
        seed_via_store(inner.as_ref(), &[desc(REF_A)]).await;
        let dom = domain_over(Arc::new(FailingDeleteStore {
            inner: Arc::clone(&inner),
        }));
        dom.remove_referrer("r", &subj(), &d(REF_A))
            .await
            .expect("[{n}] historical best-effort: delete failure swallowed");
        let listed = dom.list_referrers("r", &subj()).await.unwrap();
        assert_eq!(
            digests(&listed),
            vec![REF_A],
            "[{n}] index object remains after the swallowed failure"
        );
    }
}

// ---------------------------------------------------------------------------
// Backend fault classification through the public surface (§16 items 19-22)
// ---------------------------------------------------------------------------

/// S3 fault classification through the real adapter: GET AccessDenied →
/// PermissionDenied (propagated by list/add, swallowed by page); PUT fault
/// propagates from add; the conditional-delete fault on the last-entry
/// removal is swallowed.
#[tokio::test]
async fn s3_backend_fault_classification() {
    let (storage, driver) = create_mock_storage();
    driver.objects.lock().unwrap().insert(
        format!("repos/r/referrers/{SUBJ}.json"),
        (
            Bytes::from(index_bytes(&[desc(REF_A)])),
            "\"s\"".to_string(),
        ),
    );

    // GET AccessDenied.
    driver.set_hook_before(|method, key| {
        if method == "get_object" && key.contains("/referrers/") {
            Some(StorageError::permission_denied("injected 403"))
        } else {
            None
        }
    });
    let err = storage
        .list_referrers("r", &subj())
        .await
        .expect_err("403 propagates");
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    let err = storage
        .add_referrer("r", &subj(), desc(REF_B))
        .await
        .expect_err("mutation-side read fault fails closed");
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    let (page, token) = storage
        .list_referrers_page("r", &subj(), None, 10)
        .await
        .unwrap();
    assert!(
        page.is_empty() && token.is_none(),
        "page swallows the fault"
    );
    driver.clear_hooks();

    // PUT backend fault propagates from add.
    driver.set_hook_before(|method, key| {
        if method == "put_object" && key.contains("/referrers/") {
            Some(StorageError::backend("injected put fault"))
        } else {
            None
        }
    });
    let err = storage
        .add_referrer("r", &subj(), desc(REF_B))
        .await
        .expect_err("write fault propagates");
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    driver.clear_hooks();

    // Conditional-delete fault on the final-entry removal is swallowed.
    driver.set_hook_before(|method, key| {
        if method == "delete_object_if_match" && key.contains("/referrers/") {
            Some(StorageError::backend("injected delete fault"))
        } else {
            None
        }
    });
    storage
        .remove_referrer("r", &subj(), &d(REF_A))
        .await
        .expect("best-effort empty-index removal swallows the fault");
    assert!(
        driver
            .objects
            .lock()
            .unwrap()
            .contains_key(&format!("repos/r/referrers/{SUBJ}.json")),
        "index object remains"
    );
    driver.clear_hooks();
}

/// S3 prefix isolation: with a configured root prefix every referrer object
/// lands under `<prefix>/repos/...` and instances with different prefixes
/// never observe each other's indexes.
#[tokio::test]
async fn s3_prefix_isolation() {
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage_a = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "tenant-a".to_string(),
        100 * 1024 * 1024,
        Arc::new(TagBridgeDriver::new(driver.clone())),
    );
    let storage_b = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "tenant-b".to_string(),
        100 * 1024 * 1024,
        Arc::new(TagBridgeDriver::new(driver.clone())),
    );

    storage_a
        .add_referrer("r", &subj(), desc(REF_A))
        .await
        .unwrap();
    assert!(
        driver
            .objects
            .lock()
            .unwrap()
            .contains_key(&format!("tenant-a/repos/r/referrers/{SUBJ}.json")),
        "exact prefixed physical key"
    );
    assert_eq!(
        storage_b.list_referrers("r", &subj()).await.unwrap(),
        vec![],
        "prefix isolation"
    );
}

// ---------------------------------------------------------------------------
// FS containment / durability / ENOSPC (§16 items 22, 29, 30)
// ---------------------------------------------------------------------------

/// Root-replacement pinning at the migrated referrer boundary: the pinned
/// instance keeps operating on the ORIGINAL tree; the ambient replacement
/// tree is untouched and invisible.
#[tokio::test]
async fn fs_root_replacement_pinning() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();

    storage
        .add_referrer("pin", &subj(), desc(REF_A))
        .await
        .unwrap();

    let old_root = tmp.path().join("storage-root-old");
    std::fs::rename(&root, &old_root).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let replacement = root
        .join("repos")
        .join("pin")
        .join("referrers")
        .join(format!("{SUBJ}.json"));
    std::fs::create_dir_all(replacement.parent().unwrap()).unwrap();
    std::fs::write(&replacement, index_bytes(&[desc(REF_X)])).unwrap();

    // Reads and mutations still act on the pinned original tree.
    let listed = storage.list_referrers("pin", &subj()).await.unwrap();
    assert_eq!(digests(&listed), vec![REF_A], "pinned tree read");
    storage
        .add_referrer("pin", &subj(), desc(REF_B))
        .await
        .unwrap();
    let moved = old_root
        .join("repos")
        .join("pin")
        .join("referrers")
        .join(format!("{SUBJ}.json"));
    let raw = std::fs::read(&moved).unwrap();
    assert_eq!(
        raw,
        index_bytes(&[desc(REF_A), desc(REF_B)]),
        "mutation landed on the pinned original tree"
    );
    assert_eq!(
        std::fs::read(&replacement).unwrap(),
        index_bytes(&[desc(REF_X)]),
        "ambient replacement tree untouched"
    );
}

/// Symlinked index leaf and symlinked path component fail closed on read
/// and mutation; the external target is never touched. (The retired
/// contained seam classified these as `Internal{Io}`; the adapter reports
/// its containment refusal as `Internal{PermissionDenied}` — an equally
/// fail-closed, production-inert kind, per the Phase 5 semantic matrix.)
#[tokio::test]
async fn fs_symlink_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();

    // External target the symlinks point at.
    let external = tmp.path().join("external.json");
    std::fs::write(&external, index_bytes(&[desc(REF_X)])).unwrap();

    // Symlinked leaf.
    let refdir = root.join("repos").join("sym").join("referrers");
    std::fs::create_dir_all(&refdir).unwrap();
    std::os::unix::fs::symlink(&external, refdir.join(format!("{SUBJ}.json"))).unwrap();

    let err = storage
        .list_referrers("sym", &subj())
        .await
        .expect_err("read fails closed");
    assert!(err.internal_kind().is_some(), "classified: {err:?}");
    let err = storage
        .add_referrer("sym", &subj(), desc(REF_B))
        .await
        .expect_err("mutation fails closed");
    assert!(err.internal_kind().is_some(), "classified: {err:?}");
    let err = storage
        .remove_referrer("sym", &subj(), &d(REF_X))
        .await
        .expect_err("removal fails closed");
    assert!(err.internal_kind().is_some(), "classified: {err:?}");
    assert_eq!(
        std::fs::read(&external).unwrap(),
        index_bytes(&[desc(REF_X)]),
        "external target untouched"
    );

    // Symlinked directory component.
    let extdir = tmp.path().join("external-dir");
    std::fs::create_dir_all(&extdir).unwrap();
    let repo2 = root.join("repos").join("sym2");
    std::fs::create_dir_all(&repo2).unwrap();
    std::os::unix::fs::symlink(&extdir, repo2.join("referrers")).unwrap();
    let err = storage
        .add_referrer("sym2", &subj(), desc(REF_B))
        .await
        .expect_err("symlinked component fails closed");
    assert!(err.internal_kind().is_some(), "classified: {err:?}");
    assert!(
        std::fs::read_dir(&extdir).unwrap().next().is_none(),
        "external directory untouched"
    );
}

/// FS durability faults at the referrer boundary: ENOSPC on the staged
/// rename restores the historical `InsufficientStorage` (507)
/// classification via the shared structured source-chain detection; a
/// failed durable directory barrier propagates truthfully.
#[tokio::test]
async fn fs_enospc_and_durability_classification() {
    use storage_fs::mutate::fault::{self, FaultPoint};

    let _fault_guard = crate::storage::store_common::fault_scenario::begin().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();

    // Unique subject hex: the global fault table matches needles against
    // EVERY test's renames, so this needle must not collide with the shared
    // SUBJ constant used by parallel tests.
    let fault_subj_hex = "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5";
    let fault_subj = Digest::parse(&format!("sha256:{fault_subj_hex}")).unwrap();

    // ENOSPC on the staged rename of the index leaf -> InsufficientStorage.
    fault::arm(
        FaultPoint::RenameLeaf,
        Some(fault_subj_hex),
        1,
        libc::ENOSPC,
    );
    let err = storage
        .add_referrer("zzreffaultrepo", &fault_subj, desc(REF_A))
        .await
        .expect_err("ENOSPC publication must fail");
    assert!(
        matches!(err, StorageError::InsufficientStorage),
        "ENOSPC restores InsufficientStorage, got {err:?}"
    );

    // EIO on the durable directory barrier -> propagates (no false success).
    fault::arm(FaultPoint::DirSync, Some("zzreffaultrepo"), 1, libc::EIO);
    let err = storage
        .add_referrer("zzreffaultrepo", &fault_subj, desc(REF_A))
        .await
        .expect_err("failed durable barrier must propagate");
    assert!(err.internal_kind().is_some(), "classified error: {err:?}");
    fault::reset();

    // Negative control.
    storage
        .add_referrer("zzreffaultrepo", &fault_subj, desc(REF_A))
        .await
        .expect("clean add after faults");
    let listed = storage
        .list_referrers("zzreffaultrepo", &fault_subj)
        .await
        .unwrap();
    assert_eq!(digests(&listed), vec![REF_A]);
}

/// A duplicate add still rewrites the (unchanged) array — pinned on FS via
/// the atomic-replacement inode change.
#[tokio::test]
async fn fs_duplicate_add_still_rewrites() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();

    storage
        .add_referrer("r", &subj(), desc(REF_A))
        .await
        .unwrap();
    let leaf = root
        .join("repos")
        .join("r")
        .join("referrers")
        .join(format!("{SUBJ}.json"));
    let ino_before = std::fs::metadata(&leaf).unwrap().ino();
    let bytes_before = std::fs::read(&leaf).unwrap();

    storage
        .add_referrer("r", &subj(), desc(REF_A))
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(&leaf).unwrap(),
        bytes_before,
        "content unchanged"
    );
    assert_ne!(
        std::fs::metadata(&leaf).unwrap().ino(),
        ino_before,
        "duplicate add rewrote the array (atomic replacement), as before"
    );
}
