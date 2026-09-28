//! Cross-backend shared registry membership behavior suite (Phase 6, point
//! operations).
//!
//! ONE expectation set executed against BOTH production storage backends
//! over their real migrated membership paths (FsStorage over a real
//! temporary root; S3Storage over the real `S3ObjectStore` adapter driven by
//! the deterministic mock client). Raw seeding/reading uses each backend's
//! OLD physical representation
//! (`<root>/repo-memberships/by-repo/<b64url(repo)>/<algo>/<hex>.json` file
//! / the same bucket key), so the suite doubles as the existing-data /
//! byte-layout compatibility proof: no migration job.
//!
//! The conditional-mutation race mechanics (stale transition, stale unlink,
//! vanish-between-observation-and-delete, truthful delete failure) are
//! driven deterministically at the domain layer through an interposing
//! [`ObjectStore`] decorator over BOTH real adapters.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use base64::prelude::*;
use bytes::Bytes;
use naust_storage_core::ObjectKey;
use naust_storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ListPage, ObjectMeta, ObjectRead,
    ObjectStore, ObjectVersion, PageToken, ReplaceOutcome, StoreError, VersionedRead,
};

use super::super::s3::tests::{MockS3Driver, TagBridgeDriver, create_mock_storage};
use super::MembershipDomain;
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::fs::FsStorage;
use crate::storage::repo_membership::{
    MembershipProvenance, MembershipState, RepoBlobMembershipRecord,
    RepositoryBlobMembershipStorage,
};
use crate::storage::s3::S3Storage;
use crate::storage::{StorageError, StorageErrorKind};
use std::path::PathBuf;

const HEX1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HEX512: &str = "4444444444444444444444444444444444444444444444444444444444444444\
4444444444444444444444444444444444444444444444444444444444444444";

fn d(hex: &str) -> Digest {
    Digest::parse(&format!("sha256:{hex}")).unwrap()
}

fn d512() -> Digest {
    Digest::parse(&format!("sha512:{HEX512}")).unwrap()
}

fn b64(repo: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(repo.as_bytes())
}

/// Deterministic record (fixed timestamp — no SystemTime).
fn record(repo: &str, digest: &Digest) -> RepoBlobMembershipRecord {
    RepoBlobMembershipRecord {
        schema_version: 1,
        repo: CanonicalRepoName::parse(repo).unwrap(),
        digest: digest.clone(),
        created_at_unix_secs: 1_700_000_000,
        provenance: MembershipProvenance::Upload,
        session_id: Some("sess-1".to_string()),
        format_version: 1,
        state: MembershipState::Active,
        unreferenced_since_unix_secs: None,
    }
}

fn record_bytes(rec: &RepoBlobMembershipRecord) -> Vec<u8> {
    serde_json::to_vec(rec).unwrap()
}

fn relpath(repo: &str, digest: &Digest) -> String {
    format!(
        "repo-memberships/by-repo/{}/{}/{}.json",
        b64(repo),
        digest.algorithm(),
        digest.hex()
    )
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

    /// Seeds a record in the exact PRE-MIGRATION physical layout.
    fn seed_raw(&self, repo: &str, digest: &Digest, bytes: &[u8]) {
        match self {
            Backend::Fs { root, .. } => {
                let path = root.join(relpath(repo, digest));
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            }
            Backend::S3 { driver, .. } => {
                driver.objects.lock().unwrap().insert(
                    relpath(repo, digest),
                    (Bytes::from(bytes.to_vec()), "\"seeded\"".to_string()),
                );
            }
        }
    }

    fn read_raw(&self, repo: &str, digest: &Digest) -> Option<Vec<u8>> {
        match self {
            Backend::Fs { root, .. } => std::fs::read(root.join(relpath(repo, digest))).ok(),
            Backend::S3 { driver, .. } => driver
                .objects
                .lock()
                .unwrap()
                .get(&relpath(repo, digest))
                .map(|(b, _)| b.to_vec()),
        }
    }

    fn storage(&self) -> &dyn RepositoryBlobMembershipStorage {
        match self {
            Backend::Fs { storage, .. } => storage,
            Backend::S3 { storage, .. } => storage,
        }
    }
}

// ---------------------------------------------------------------------------
// Reads / old-layout compatibility
// ---------------------------------------------------------------------------

/// Absent records (any missing path level) read as `None`; invalid repo
/// grammar fails closed with `InvalidRepoName` before any backend access.
#[tokio::test]
async fn shared_get_absent_and_grammar() {
    for b in both() {
        let n = b.name();
        assert_eq!(
            b.storage()
                .get_repo_blob_membership("norepo", &d(HEX1))
                .await
                .unwrap(),
            None,
            "[{n}] absent repo"
        );
        // Existing repo dir, absent algo/leaf.
        b.seed_raw(
            "seeded",
            &d(HEX1),
            &record_bytes(&record("seeded", &d(HEX1))),
        );
        assert_eq!(
            b.storage()
                .get_repo_blob_membership("seeded", &d512())
                .await
                .unwrap(),
            None,
            "[{n}] absent algo level"
        );
        for bad in ["", "UPPER/Repo", "../escape", "a//b"] {
            assert!(
                matches!(
                    b.storage().get_repo_blob_membership(bad, &d(HEX1)).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "[{n}] get rejects {bad:?}"
            );
        }
    }
}

/// Pre-migration seeded records read back exactly through the shared layer:
/// full field round-trip (incl. cross_mount provenance), legacy records
/// WITHOUT the `state` field default to `Active`, unknown fields are
/// tolerated, sha512 digests resolve their 128-hex stems.
#[tokio::test]
async fn shared_old_layout_read_compatibility() {
    for b in both() {
        let n = b.name();
        let mut full = record("org/team/app", &d(HEX1));
        full.provenance = MembershipProvenance::CrossMount {
            from_repo: CanonicalRepoName::parse("lib/base").unwrap(),
        };
        full.state = MembershipState::Candidate;
        full.unreferenced_since_unix_secs = Some(42);
        b.seed_raw("org/team/app", &d(HEX1), &record_bytes(&full));
        let got = b
            .storage()
            .get_repo_blob_membership("org/team/app", &d(HEX1))
            .await
            .unwrap()
            .expect("seeded record");
        assert_eq!(got, full, "[{n}] full round-trip");

        // Legacy shape: no `state`, no `unreferenced_since`, unknown field.
        b.seed_raw(
            "legacy",
            &d(HEX1),
            format!(
                r#"{{"schema_version":1,"repo":"legacy","digest":"sha256:{HEX1}","created_at_unix_secs":5,"provenance":{{"type":"upload"}},"format_version":1,"future_field":true}}"#
            )
            .as_bytes(),
        );
        let got = b
            .storage()
            .get_repo_blob_membership("legacy", &d(HEX1))
            .await
            .unwrap()
            .expect("legacy record readable");
        assert_eq!(got.state, MembershipState::Active, "[{n}] state defaults");
        assert_eq!(got.unreferenced_since_unix_secs, None, "[{n}]");

        // sha512 stem.
        b.seed_raw("legacy", &d512(), &record_bytes(&record("legacy", &d512())));
        assert!(
            b.storage()
                .get_repo_blob_membership("legacy", &d512())
                .await
                .unwrap()
                .is_some(),
            "[{n}] sha512 physical stem"
        );
    }
}

/// Corrupt record taxonomy: the point read carries the record key; the
/// mutation-side parse keeps the BYTE-FROZEN `corrupt membership record: {e}`
/// message. Mutations fail closed with the stored bytes untouched.
#[tokio::test]
async fn shared_corrupt_record_fail_closed() {
    for b in both() {
        let n = b.name();
        b.seed_raw("c", &d(HEX1), b"{not json");

        let err = b
            .storage()
            .get_repo_blob_membership("c", &d(HEX1))
            .await
            .expect_err("corrupt get fails");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}]"
        );
        assert!(
            err.to_string().contains(&relpath("c", &d(HEX1))),
            "[{n}] point-read message carries the key: {err}"
        );

        let err = b
            .storage()
            .set_membership_candidate("c", &d(HEX1), 7)
            .await
            .expect_err("corrupt set fails closed");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}]"
        );
        assert!(
            err.to_string().contains("corrupt membership record: "),
            "[{n}] frozen mutation-side message: {err}"
        );
        let err = b
            .storage()
            .clear_membership_candidate("c", &d(HEX1))
            .await
            .expect_err("corrupt clear fails closed");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}]"
        );
        assert_eq!(
            b.read_raw("c", &d(HEX1)).unwrap(),
            b"{not json".to_vec(),
            "[{n}] fail-closed: bytes untouched"
        );

        // The record is NEVER parsed on unlink: corrupt records stay
        // unlinkable (frozen on both retired backends).
        assert!(
            b.storage().unlink_repo_blob("c", &d(HEX1)).await.unwrap(),
            "[{n}] corrupt record unlinks"
        );
        assert!(b.read_raw("c", &d(HEX1)).is_none(), "[{n}]");
    }
}

// ---------------------------------------------------------------------------
// link / physical compatibility
// ---------------------------------------------------------------------------

/// `link_repo_blob` creates the record at the EXACT pre-migration physical
/// location with the exact compact snake_case bytes, and remains an
/// unconditional last-writer-wins overwrite.
#[tokio::test]
async fn shared_link_physical_compatibility_and_overwrite() {
    for b in both() {
        let n = b.name();
        let rec = record("org/team/app", &d(HEX1));
        b.storage().link_repo_blob(&rec).await.unwrap();
        assert_eq!(
            b.read_raw("org/team/app", &d(HEX1))
                .expect("record at old physical key"),
            record_bytes(&rec),
            "[{n}] exact bytes at the exact key"
        );
        let text = String::from_utf8(b.read_raw("org/team/app", &d(HEX1)).unwrap()).unwrap();
        assert!(text.contains("\"schema_version\""), "[{n}] snake_case");
        assert!(
            text.contains(r#""provenance":{"type":"upload"}"#),
            "[{n}] tagged provenance"
        );
        assert!(
            !text.contains("unreferenced_since_unix_secs"),
            "[{n}] None optionals omitted"
        );

        // Last-writer-wins overwrite.
        let mut rec2 = rec.clone();
        rec2.session_id = None;
        rec2.created_at_unix_secs = 1_700_000_001;
        b.storage().link_repo_blob(&rec2).await.unwrap();
        assert_eq!(
            b.read_raw("org/team/app", &d(HEX1)).unwrap(),
            record_bytes(&rec2),
            "[{n}] unconditional overwrite"
        );
    }
}

// ---------------------------------------------------------------------------
// Candidate transitions
// ---------------------------------------------------------------------------

/// The frozen candidate state table: absent → false (no side effects);
/// Active → Candidate persists durably with the given timestamp → true;
/// already-Candidate → false with NO rewrite and the FIRST timestamp
/// preserved (even for a different `since` argument — the converged guard;
/// the sole production caller never issues that call); clear normalizes an
/// Active record carrying a stale timestamp.
#[tokio::test]
async fn shared_candidate_transition_state_table() {
    for b in both() {
        let n = b.name();

        // Absent: false, and on FS no directories may appear.
        assert!(
            !b.storage()
                .set_membership_candidate("absent", &d(HEX1), 7)
                .await
                .unwrap()
        );
        assert!(
            !b.storage()
                .clear_membership_candidate("absent", &d(HEX1))
                .await
                .unwrap()
        );
        if let Backend::Fs { root, .. } = &b {
            assert!(
                !root
                    .join("repo-memberships")
                    .join("by-repo")
                    .join(b64("absent"))
                    .exists(),
                "[{n}] no per-repo directories created by no-op transitions"
            );
        }

        // Active -> Candidate.
        let rec = record("r", &d(HEX1));
        b.seed_raw("r", &d(HEX1), &record_bytes(&rec));
        assert!(
            b.storage()
                .set_membership_candidate("r", &d(HEX1), 100)
                .await
                .unwrap(),
            "[{n}] transition persisted"
        );
        let mut expected = rec.clone();
        expected.state = MembershipState::Candidate;
        expected.unreferenced_since_unix_secs = Some(100);
        assert_eq!(
            b.read_raw("r", &d(HEX1)).unwrap(),
            record_bytes(&expected),
            "[{n}] exact candidate bytes"
        );

        // Already-Candidate: false, first timestamp preserved, no rewrite —
        // including a DIFFERENT since argument.
        let before = b.read_raw("r", &d(HEX1)).unwrap();
        assert!(
            !b.storage()
                .set_membership_candidate("r", &d(HEX1), 100)
                .await
                .unwrap()
        );
        assert!(
            !b.storage()
                .set_membership_candidate("r", &d(HEX1), 999)
                .await
                .unwrap(),
            "[{n}] state-only guard: differing timestamp is still a no-op"
        );
        assert_eq!(
            b.read_raw("r", &d(HEX1)).unwrap(),
            before,
            "[{n}] no rewrite"
        );

        // Candidate -> Active.
        assert!(
            b.storage()
                .clear_membership_candidate("r", &d(HEX1))
                .await
                .unwrap()
        );
        assert_eq!(
            b.read_raw("r", &d(HEX1)).unwrap(),
            record_bytes(&rec),
            "[{n}] cleared back to the exact active bytes"
        );
        // Already-Active clean: false, no rewrite.
        let before = b.read_raw("r", &d(HEX1)).unwrap();
        assert!(
            !b.storage()
                .clear_membership_candidate("r", &d(HEX1))
                .await
                .unwrap()
        );
        assert_eq!(b.read_raw("r", &d(HEX1)).unwrap(), before, "[{n}]");

        // Active WITH stale timestamp: clear normalizes (frozen asymmetry).
        let mut stale = record("stale", &d(HEX1));
        stale.unreferenced_since_unix_secs = Some(55);
        b.seed_raw("stale", &d(HEX1), &record_bytes(&stale));
        assert!(
            b.storage()
                .clear_membership_candidate("stale", &d(HEX1))
                .await
                .unwrap(),
            "[{n}] Active-with-timestamp is dirty for clear"
        );
        let normalized = record("stale", &d(HEX1));
        assert_eq!(
            b.read_raw("stale", &d(HEX1)).unwrap(),
            record_bytes(&normalized),
            "[{n}]"
        );
    }
}

// ---------------------------------------------------------------------------
// unlink existence semantics
// ---------------------------------------------------------------------------

/// The parity-closure existence contract: absent → false; present → true
/// (record physically gone); repeat → false; invalid grammar rejected.
#[tokio::test]
async fn shared_unlink_existence_contract() {
    for b in both() {
        let n = b.name();
        assert!(
            !b.storage().unlink_repo_blob("r", &d(HEX1)).await.unwrap(),
            "[{n}] absent"
        );
        b.seed_raw("r", &d(HEX1), &record_bytes(&record("r", &d(HEX1))));
        assert!(
            b.storage().unlink_repo_blob("r", &d(HEX1)).await.unwrap(),
            "[{n}] present"
        );
        assert!(
            b.read_raw("r", &d(HEX1)).is_none(),
            "[{n}] physically removed"
        );
        assert!(
            !b.storage().unlink_repo_blob("r", &d(HEX1)).await.unwrap(),
            "[{n}] repeat"
        );
        assert!(
            matches!(
                b.storage().unlink_repo_blob("UPPER", &d(HEX1)).await,
                Err(StorageError::InvalidRepoName(_))
            ),
            "[{n}] grammar"
        );
        if let Backend::Fs { root, .. } = &b {
            assert!(
                !root
                    .join("repo-memberships")
                    .join("by-repo")
                    .join(b64("nonexistent"))
                    .exists(),
                "[{n}] no directories created by absent unlink"
            );
            assert!(
                !b.storage()
                    .unlink_repo_blob("nonexistent", &d(HEX1))
                    .await
                    .unwrap(),
                "[{n}]"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic race mechanics at the domain layer (interposing decorator)
// ---------------------------------------------------------------------------

/// External-writer decorator: before delegating the first `interpositions`
/// conditional mutations, applies `external` through the inner store
/// (`Some(bytes)` = replacement write, `None` = deletion).
struct InterposingStore {
    inner: Arc<dyn ObjectStore>,
    remaining: AtomicUsize,
    external: Option<Vec<u8>>,
}

impl InterposingStore {
    fn new(inner: Arc<dyn ObjectStore>, interpositions: usize, external: Option<Vec<u8>>) -> Self {
        Self {
            inner,
            remaining: AtomicUsize::new(interpositions),
            external,
        }
    }

    async fn maybe_interpose(&self, key: &ObjectKey) {
        if self
            .remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |c| c.checked_sub(1))
            .is_err()
        {
            return;
        }
        match &self.external {
            Some(bytes) => {
                self.inner
                    .write(key, Bytes::from(bytes.clone()), Durability::Durable)
                    .await
                    .expect("interposed external write");
            }
            None => self
                .inner
                .delete(key)
                .await
                .expect("interposed external delete"),
        }
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

/// Decorator failing every conditional delete with a backend fault.
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

/// Raw adapter stores for domain-layer tests.
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

async fn seed_via_store(store: &dyn ObjectStore, repo: &str, digest: &Digest, bytes: Vec<u8>) {
    let key = ObjectKey::parse(&relpath(repo, digest)).unwrap();
    store
        .write(&key, Bytes::from(bytes), Durability::Durable)
        .await
        .unwrap();
}

async fn read_via_store(store: &dyn ObjectStore, repo: &str, digest: &Digest) -> Option<Vec<u8>> {
    let key = ObjectKey::parse(&relpath(repo, digest)).unwrap();
    store
        .read(&key, u64::MAX)
        .await
        .unwrap()
        .map(|r| r.bytes.to_vec())
}

/// A replacement racing a candidate transition survives: the stale
/// conditional replace refuses (`Ok(false)`, the pinned precondition-loss
/// contract) and the external generation is preserved byte-for-byte.
#[tokio::test]
async fn domain_stale_transition_never_overwrites_replacement() {
    for (n, _guard, inner) in raw_stores() {
        let rec = record("r", &d(HEX1));
        seed_via_store(inner.as_ref(), "r", &d(HEX1), record_bytes(&rec)).await;

        let mut external = rec.clone();
        external.created_at_unix_secs = 1_800_000_000; // a different generation
        let interposed = Arc::new(InterposingStore::new(
            Arc::clone(&inner),
            1,
            Some(record_bytes(&external)),
        ));
        let dom = MembershipDomain::new(interposed);

        let changed = dom
            .set_membership_candidate("r", &d(HEX1), 100)
            .await
            .unwrap();
        assert!(!changed, "[{n}] lost precondition reports Ok(false)");
        assert_eq!(
            read_via_store(inner.as_ref(), "r", &d(HEX1)).await.unwrap(),
            record_bytes(&external),
            "[{n}] the replacement generation survives byte-identically"
        );

        // Same shape for clear (seed a candidate so the guard passes).
        let mut cand = rec.clone();
        cand.state = MembershipState::Candidate;
        cand.unreferenced_since_unix_secs = Some(9);
        seed_via_store(inner.as_ref(), "c", &d(HEX1), record_bytes(&cand)).await;
        let interposed = Arc::new(InterposingStore::new(
            Arc::clone(&inner),
            1,
            Some(record_bytes(&external)),
        ));
        let dom = MembershipDomain::new(interposed);
        assert!(
            !dom.clear_membership_candidate("c", &d(HEX1)).await.unwrap(),
            "[{n}]"
        );
    }
}

/// A record that VANISHES between the observation and the conditional write
/// reports `Ok(false)` (absent semantics), never an error and never a
/// resurrection.
#[tokio::test]
async fn domain_vanished_between_read_and_write_is_false() {
    for (n, _guard, inner) in raw_stores() {
        seed_via_store(
            inner.as_ref(),
            "r",
            &d(HEX1),
            record_bytes(&record("r", &d(HEX1))),
        )
        .await;
        let interposed = Arc::new(InterposingStore::new(Arc::clone(&inner), 1, None));
        let dom = MembershipDomain::new(interposed);
        assert!(
            !dom.set_membership_candidate("r", &d(HEX1), 5)
                .await
                .unwrap(),
            "[{n}] vanished record -> false"
        );
        assert!(
            read_via_store(inner.as_ref(), "r", &d(HEX1))
                .await
                .is_none(),
            "[{n}] nothing resurrected"
        );
    }
}

/// A stale unlink can never delete a replacement: the conditional delete
/// refuses with `Internal{{Conflict}}` and the replacement survives
/// byte-for-byte (the pinned parity-closure contract, now on both backends).
#[tokio::test]
async fn domain_stale_unlink_never_deletes_replacement() {
    for (n, _guard, inner) in raw_stores() {
        let rec = record("r", &d(HEX1));
        seed_via_store(inner.as_ref(), "r", &d(HEX1), record_bytes(&rec)).await;
        let mut external = rec.clone();
        external.created_at_unix_secs = 1_800_000_000;
        let interposed = Arc::new(InterposingStore::new(
            Arc::clone(&inner),
            1,
            Some(record_bytes(&external)),
        ));
        let dom = MembershipDomain::new(interposed);

        let err = dom
            .unlink_repo_blob("r", &d(HEX1))
            .await
            .expect_err("stale unlink must fail closed");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::Conflict),
            "[{n}] got {err:?}"
        );
        assert!(
            err.to_string()
                .contains("changed concurrently during unlink"),
            "[{n}] {err}"
        );
        assert_eq!(
            read_via_store(inner.as_ref(), "r", &d(HEX1)).await.unwrap(),
            record_bytes(&external),
            "[{n}] replacement survives byte-identically"
        );
    }
}

/// A record that vanishes between the unlink observation and the conditional
/// delete reports `Ok(false)` — never a false `true`.
#[tokio::test]
async fn domain_unlink_vanished_between_read_and_delete_is_false() {
    for (n, _guard, inner) in raw_stores() {
        seed_via_store(
            inner.as_ref(),
            "r",
            &d(HEX1),
            record_bytes(&record("r", &d(HEX1))),
        )
        .await;
        let interposed = Arc::new(InterposingStore::new(Arc::clone(&inner), 1, None));
        let dom = MembershipDomain::new(interposed);
        assert!(
            !dom.unlink_repo_blob("r", &d(HEX1)).await.unwrap(),
            "[{n}] vanished -> false"
        );
    }
}

/// Backend failure of the conditional delete PROPAGATES truthfully (the
/// frozen membership contract — unlike the referrer family's best-effort
/// empty-index removal) and the record survives.
#[tokio::test]
async fn domain_unlink_backend_failure_propagates() {
    for (n, _guard, inner) in raw_stores() {
        let rec = record("r", &d(HEX1));
        seed_via_store(inner.as_ref(), "r", &d(HEX1), record_bytes(&rec)).await;
        let dom = MembershipDomain::new(Arc::new(FailingDeleteStore {
            inner: Arc::clone(&inner),
        }));
        let err = dom
            .unlink_repo_blob("r", &d(HEX1))
            .await
            .expect_err("delete fault must propagate — never a false true");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::Backend),
            "[{n}] {err:?}"
        );
        assert_eq!(
            read_via_store(inner.as_ref(), "r", &d(HEX1)).await.unwrap(),
            record_bytes(&rec),
            "[{n}] record survives the failed delete"
        );
    }
}

// ---------------------------------------------------------------------------
// S3 adversarial
// ---------------------------------------------------------------------------

/// S3 fault classification through the real adapter: GET 403 propagates as
/// PermissionDenied from reads and mutations; PUT faults propagate from
/// link/transitions; prefix isolation puts every record under the configured
/// tenant prefix.
#[tokio::test]
async fn s3_fault_classification_and_prefix_isolation() {
    let (storage, driver) = create_mock_storage();
    let rec = record("r", &d(HEX1));
    driver.objects.lock().unwrap().insert(
        relpath("r", &d(HEX1)),
        (Bytes::from(record_bytes(&rec)), "\"s\"".to_string()),
    );

    driver.set_hook_before(|method, key| {
        if method == "get_object" && key.contains("repo-memberships/") {
            Some(StorageError::permission_denied("injected 403"))
        } else {
            None
        }
    });
    let err = storage
        .get_repo_blob_membership("r", &d(HEX1))
        .await
        .expect_err("403 propagates");
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    let err = storage
        .set_membership_candidate("r", &d(HEX1), 5)
        .await
        .expect_err("mutation-side read fault fails closed");
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    let err = storage
        .unlink_repo_blob("r", &d(HEX1))
        .await
        .expect_err("unlink observation fault propagates");
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    driver.clear_hooks();

    driver.set_hook_before(|method, key| {
        if method == "put_object" && key.contains("repo-memberships/") {
            Some(StorageError::backend("injected put fault"))
        } else {
            None
        }
    });
    let err = storage
        .link_repo_blob(&rec)
        .await
        .expect_err("link write fault propagates");
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    let err = storage
        .set_membership_candidate("r", &d(HEX1), 5)
        .await
        .expect_err("transition write fault propagates");
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    driver.clear_hooks();

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
    tenant_a.link_repo_blob(&rec).await.unwrap();
    assert!(
        driver2
            .objects
            .lock()
            .unwrap()
            .contains_key(&format!("tenant-a/{}", relpath("r", &d(HEX1)))),
        "exact prefixed physical key"
    );
    assert_eq!(
        tenant_b
            .get_repo_blob_membership("r", &d(HEX1))
            .await
            .unwrap(),
        None,
        "prefix isolation"
    );
}

// ---------------------------------------------------------------------------
// FS adversarial
// ---------------------------------------------------------------------------

/// Root replacement stays pinned: the instance keeps operating on the
/// ORIGINAL tree; the ambient replacement tree is untouched and invisible.
#[tokio::test]
async fn fs_root_replacement_pinning() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();

    let rec = record("pin", &d(HEX1));
    storage.link_repo_blob(&rec).await.unwrap();

    let old_root = tmp.path().join("storage-root-old");
    std::fs::rename(&root, &old_root).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let replacement = root.join(relpath("pin", &d(HEX1)));
    std::fs::create_dir_all(replacement.parent().unwrap()).unwrap();
    let mut other = rec.clone();
    other.created_at_unix_secs = 1;
    std::fs::write(&replacement, record_bytes(&other)).unwrap();

    // The pinned instance reads and mutates the ORIGINAL tree.
    let got = storage
        .get_repo_blob_membership("pin", &d(HEX1))
        .await
        .unwrap()
        .expect("pinned tree record");
    assert_eq!(got, rec, "pinned tree read");
    assert!(storage.unlink_repo_blob("pin", &d(HEX1)).await.unwrap());
    assert!(
        !old_root.join(relpath("pin", &d(HEX1))).exists(),
        "unlink landed on the pinned original tree"
    );
    assert_eq!(
        std::fs::read(&replacement).unwrap(),
        record_bytes(&other),
        "ambient replacement tree untouched"
    );
}

/// Symlinked path component and symlinked record leaf fail closed on read
/// and mutation; external targets untouched. (The retired seams reported
/// `Internal{{Io}}`; the pinned adapter reports its containment refusal as
/// `Internal{{PermissionDenied}}` — the accepted production-inert
/// convergence.)
#[tokio::test]
async fn fs_symlink_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();
    let rec = record("sym", &d(HEX1));

    // Symlinked leaf.
    let external = tmp.path().join("external.json");
    std::fs::write(&external, record_bytes(&rec)).unwrap();
    let leaf = root.join(relpath("sym", &d(HEX1)));
    std::fs::create_dir_all(leaf.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&external, &leaf).unwrap();

    assert!(
        storage
            .get_repo_blob_membership("sym", &d(HEX1))
            .await
            .is_err()
    );
    assert!(
        storage
            .set_membership_candidate("sym", &d(HEX1), 5)
            .await
            .is_err()
    );
    assert!(storage.unlink_repo_blob("sym", &d(HEX1)).await.is_err());
    assert_eq!(
        std::fs::read(&external).unwrap(),
        record_bytes(&rec),
        "external target untouched"
    );
    assert!(
        std::fs::symlink_metadata(&leaf)
            .unwrap()
            .file_type()
            .is_symlink(),
        "symlink still in place"
    );

    // Symlinked directory component (the encoded repo dir).
    let extdir = tmp.path().join("external-dir");
    std::fs::create_dir_all(&extdir).unwrap();
    let by_repo = root.join("repo-memberships").join("by-repo");
    std::fs::create_dir_all(&by_repo).unwrap();
    std::os::unix::fs::symlink(&extdir, by_repo.join(b64("linked"))).unwrap();
    let rec2 = record("linked", &d(HEX1));
    assert!(
        storage.link_repo_blob(&rec2).await.is_err(),
        "creating write fails closed"
    );
    assert!(
        std::fs::read_dir(&extdir).unwrap().next().is_none(),
        "external directory untouched"
    );
}

/// FS durability faults: ENOSPC on the staged rename maps to
/// `InsufficientStorage`; a failed durable directory barrier propagates.
#[tokio::test]
async fn fs_enospc_and_durability_classification() {
    use naust_storage_fs::mutate::fault::{self, FaultPoint};

    let _fault_guard = crate::storage::store_common::fault_scenario::begin().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 10 * 1024 * 1024).unwrap();

    // Unique fault needle (global fault table).
    let hexm = "d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6d6";
    let dm = d(hexm);
    let rec = record("zzmemfaultrepo", &dm);

    fault::arm(FaultPoint::RenameLeaf, Some(hexm), 1, libc::ENOSPC);
    let err = storage
        .link_repo_blob(&rec)
        .await
        .expect_err("ENOSPC link must fail");
    assert!(
        matches!(err, StorageError::InsufficientStorage),
        "ENOSPC restores InsufficientStorage, got {err:?}"
    );

    fault::arm(
        FaultPoint::DirSync,
        Some(&b64("zzmemfaultrepo")),
        1,
        libc::EIO,
    );
    let err = storage
        .link_repo_blob(&rec)
        .await
        .expect_err("failed durable barrier must propagate");
    assert!(err.internal_kind().is_some(), "classified error: {err:?}");
    fault::reset();

    // Negative control + conditional transition after faults.
    storage
        .link_repo_blob(&rec)
        .await
        .expect("clean link after faults");
    assert!(
        storage
            .set_membership_candidate("zzmemfaultrepo", &dm, 9)
            .await
            .unwrap()
    );
}
