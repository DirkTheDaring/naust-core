//! Cross-backend shared registry tag behavior suite (Phase 3).
//!
//! Runs the SAME registry-domain expectations against BOTH production
//! storage backends over their real migrated tag paths:
//! - filesystem: `FsStorage` over a real temporary root (the shared tag
//!   domain over `FsObjectStore` pinned at that root);
//! - S3: `S3Storage` over the real `S3ObjectStore` adapter driven by the
//!   deterministic mock client (the s3 test bridge).
//!
//! Raw seeding/reading goes through each backend's OLD physical
//! representation (`<root>/repos/<repo>/tags/<tag>` file /
//! `repos/<repo>/tags/<tag>` bucket key), so every check that reads seeded
//! state doubles as an existing-data / byte-layout compatibility proof: no
//! migration job, byte-for-byte identical physical locations.
//!
//! This suite is registry-domain — distinct from the lower generic
//! ObjectStore contract suite in `storage-core`.

use super::super::s3::tests::{MockS3Driver, TagBridgeDriver, create_mock_storage};
use crate::registry::digest::Digest;
use crate::storage::fs::FsStorage;
use crate::storage::s3::S3Storage;
use crate::storage::{
    ConditionalDeleteResult, Storage, StorageError, StorageErrorKind, TagMutation,
    TagMutationPolicy,
};
use sha2::Digest as Sha2Digest;
use std::path::PathBuf;
use std::sync::Arc;

const HEX1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HEX2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn d(hex: &str) -> Digest {
    Digest::parse(&format!("sha256:{hex}")).unwrap()
}

/// The `test_hooks` seams are process-global: tests that install a hook
/// serialize on this lock so a concurrent test cannot overwrite another's
/// interposition (same pattern as the storage-fs fault-table lock).
static HOOK_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
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
    let storage = FsStorage::try_new(root.clone(), 1024 * 1024).unwrap();
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

    /// `list_tags` missing-repository contract is the one deliberate
    /// backend difference: FS models repository existence (NotFound), S3
    /// does not (empty listing) — each backend's exact historical behavior.
    fn missing_repo_lists_not_found(&self) -> bool {
        matches!(self, Backend::Fs { .. })
    }

    /// Seed a tag object at the backend's OLD physical representation.
    fn seed_raw(&self, repo: &str, tag: &str, bytes: &[u8]) {
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

    /// Read the raw physical bytes at the OLD representation (layout proof).
    fn read_raw(&self, repo: &str, tag: &str) -> Option<Vec<u8>> {
        match self {
            Backend::Fs { root, .. } => {
                std::fs::read(root.join("repos").join(repo).join("tags").join(tag)).ok()
            }
            Backend::S3 { driver, .. } => driver
                .objects
                .lock()
                .unwrap()
                .get(&format!("repos/{repo}/tags/{tag}"))
                .map(|(b, _)| b.to_vec()),
        }
    }

    /// Materialize the repository namespace WITHOUT any tag (for the
    /// empty-repository listing row).
    fn seed_repo(&self, repo: &str) {
        match self {
            Backend::Fs { root, .. } => {
                std::fs::create_dir_all(root.join("repos").join(repo)).unwrap();
            }
            Backend::S3 { driver, .. } => {
                // No repository-existence notion on S3; an unrelated object
                // under the repo prefix is the closest analogue.
                driver.objects.lock().unwrap().insert(
                    format!("repos/{repo}/manifests/{HEX1}"),
                    (bytes::Bytes::from_static(b"{}"), "\"m\"".to_string()),
                );
            }
        }
    }

    async fn resolve_tag(&self, r: &str, t: &str) -> Result<Digest, StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.resolve_tag(r, t).await,
            Backend::S3 { storage, .. } => storage.resolve_tag(r, t).await,
        }
    }
    async fn get_tag_with_version(
        &self,
        r: &str,
        t: &str,
    ) -> Result<Option<(Digest, String)>, StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.get_tag_with_version(r, t).await,
            Backend::S3 { storage, .. } => storage.get_tag_with_version(r, t).await,
        }
    }
    async fn mutate_tag(
        &self,
        r: &str,
        t: &str,
        digest: &Digest,
        policy: TagMutationPolicy,
    ) -> Result<TagMutation, StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.mutate_tag(r, t, digest, policy).await,
            Backend::S3 { storage, .. } => storage.mutate_tag(r, t, digest, policy).await,
        }
    }
    async fn set_tag(&self, r: &str, t: &str, digest: &Digest) -> Result<(), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.set_tag(r, t, digest).await,
            Backend::S3 { storage, .. } => storage.set_tag(r, t, digest).await,
        }
    }
    async fn delete_tag(&self, r: &str, t: &str) -> Result<(), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.delete_tag(r, t).await,
            Backend::S3 { storage, .. } => storage.delete_tag(r, t).await,
        }
    }
    async fn delete_tag_conditional(
        &self,
        r: &str,
        t: &str,
        v: Option<&str>,
    ) -> Result<ConditionalDeleteResult, StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.delete_tag_conditional(r, t, v).await,
            Backend::S3 { storage, .. } => storage.delete_tag_conditional(r, t, v).await,
        }
    }
    async fn list_tags(&self, r: &str) -> Result<Vec<String>, StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.list_tags(r).await,
            Backend::S3 { storage, .. } => storage.list_tags(r).await,
        }
    }
    async fn list_tags_page(
        &self,
        r: &str,
        token: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.list_tags_page(r, token, limit).await,
            Backend::S3 { storage, .. } => storage.list_tags_page(r, token, limit).await,
        }
    }
    async fn put_manifest(&self, r: &str, digest: &Digest, bytes: bytes::Bytes) {
        match self {
            Backend::Fs { storage, .. } => {
                storage.put_manifest(r, digest, bytes).await.unwrap();
            }
            Backend::S3 { storage, .. } => {
                storage.put_manifest(r, digest, bytes).await.unwrap();
            }
        }
    }
    async fn delete_manifest(&self, r: &str, digest: &Digest) -> Result<(), StorageError> {
        match self {
            Backend::Fs { storage, .. } => storage.delete_manifest(r, digest).await,
            Backend::S3 { storage, .. } => storage.delete_manifest(r, digest).await,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared cross-backend checks
// ---------------------------------------------------------------------------

/// Exact write bytes at the exact old physical representation.
#[tokio::test]
async fn shared_write_bytes_and_physical_layout() {
    for b in both() {
        let n = b.name();
        b.set_tag("compat-repo", "v1", &d(HEX1)).await.unwrap();
        let raw = b
            .read_raw("compat-repo", "v1")
            .unwrap_or_else(|| panic!("[{n}] tag exists at the OLD physical location"));
        assert_eq!(
            raw,
            format!("sha256:{HEX1}\n").into_bytes(),
            "[{n}] exact historical bytes: `{{digest}}\\n`"
        );
    }
}

/// Pre-migration seeded data reads identically through the new shared layer:
/// canonical, newline-less, and padded-within-bound payloads all resolve;
/// the version token is the raw-byte SHA-256 in every case.
#[tokio::test]
async fn shared_existing_data_read_compatibility() {
    let canonical = format!("sha256:{HEX1}\n");
    let bare = format!("sha256:{HEX1}");
    let padded = format!("  \t\r\n sha256:{HEX1} \r\n\t ");
    for b in both() {
        let n = b.name();
        b.seed_raw("old-repo", "canonical", canonical.as_bytes());
        b.seed_raw("old-repo", "bare", bare.as_bytes());
        b.seed_raw("old-repo", "padded", padded.as_bytes());
        for (tag, raw) in [
            ("canonical", canonical.as_bytes()),
            ("bare", bare.as_bytes()),
            ("padded", padded.as_bytes()),
        ] {
            let resolved = b.resolve_tag("old-repo", tag).await.unwrap();
            assert_eq!(resolved.hex(), HEX1, "[{n}] {tag} resolves");
            let (dg, version) = b
                .get_tag_with_version("old-repo", tag)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(dg.hex(), HEX1, "[{n}] {tag} digest");
            assert_eq!(
                version,
                sha256_hex(raw),
                "[{n}] {tag} version is the raw-byte SHA-256"
            );
        }
    }
}

/// Absent-object contracts across every operation.
#[tokio::test]
async fn shared_absent_contracts() {
    for b in both() {
        let n = b.name();
        b.seed_repo("absent-repo");
        let err = b.resolve_tag("absent-repo", "ghost").await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound), "[{n}] resolve");
        assert!(
            b.get_tag_with_version("absent-repo", "ghost")
                .await
                .unwrap()
                .is_none(),
            "[{n}] get_tag_with_version"
        );
        let err = b.delete_tag("absent-repo", "ghost").await.unwrap_err();
        assert!(
            matches!(err, StorageError::NotFound),
            "[{n}] unconditional delete of an absent tag is NotFound (converged)"
        );
        let res = b
            .delete_tag_conditional("absent-repo", "ghost", Some("deadbeef"))
            .await
            .unwrap();
        assert_eq!(res, ConditionalDeleteResult::NotFound, "[{n}] conditional");
        assert!(
            b.list_tags("absent-repo").await.unwrap().is_empty(),
            "[{n}] empty tag namespace lists empty for an existing repository"
        );
    }
}

/// Malformed / empty payload taxonomy; the listing omission contract.
#[tokio::test]
async fn shared_malformed_and_empty_payload_taxonomy() {
    for b in both() {
        let n = b.name();
        b.seed_raw("mal-repo", "good", format!("sha256:{HEX1}\n").as_bytes());
        b.seed_raw("mal-repo", "malformed", b"not-a-digest\n");
        b.seed_raw("mal-repo", "empty", b"");

        for tag in ["malformed", "empty"] {
            let err = b.resolve_tag("mal-repo", tag).await.unwrap_err();
            assert!(
                matches!(err, StorageError::NotFound),
                "[{n}] resolve {tag} -> NotFound"
            );
            let err = b.get_tag_with_version("mal-repo", tag).await.unwrap_err();
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::CorruptData),
                "[{n}] get_tag_with_version {tag} -> CorruptData"
            );
        }

        // Name-only listing does not inspect payloads.
        assert_eq!(
            b.list_tags("mal-repo").await.unwrap(),
            vec!["empty", "good", "malformed"],
            "[{n}] list_tags returns names without payload validation"
        );
        // Digest-bearing listing silently omits malformed/empty payloads.
        let (page, next) = b.list_tags_page("mal-repo", None, 10).await.unwrap();
        assert_eq!(
            page.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
            vec!["good"],
            "[{n}] list_tags_page omits malformed/empty"
        );
        assert!(next.is_none(), "[{n}]");
    }
}

/// Invalid UTF-8: CorruptData on point reads; listing fails the page closed.
#[tokio::test]
async fn shared_invalid_utf8_fails_closed() {
    for b in both() {
        let n = b.name();
        b.seed_raw("utf8-repo", "good", format!("sha256:{HEX1}\n").as_bytes());
        b.seed_raw("utf8-repo", "broken", &[0xff, 0xfe, 0xfd]);

        let err = b.resolve_tag("utf8-repo", "broken").await.unwrap_err();
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}] resolve invalid UTF-8 -> CorruptData"
        );
        let err = b
            .get_tag_with_version("utf8-repo", "broken")
            .await
            .unwrap_err();
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}] get_tag_with_version invalid UTF-8 -> CorruptData"
        );
        let err = b.list_tags_page("utf8-repo", None, 10).await.unwrap_err();
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "[{n}] list_tags_page fails closed on invalid UTF-8"
        );
        assert!(
            err.to_string().contains("invalid UTF-8 in tag payload"),
            "[{n}] diagnostic names the payload: {err}"
        );
        // Name-only listing still lists it (no payload inspection).
        assert_eq!(
            b.list_tags("utf8-repo").await.unwrap(),
            vec!["broken", "good"],
            "[{n}]"
        );
    }
}

/// Oversized payloads map to the accepted drain-overflow CorruptData on
/// every read path (bounded reads, never unbounded buffering).
#[tokio::test]
async fn shared_oversized_payload_bounded_reads() {
    let padding = " ".repeat(1500);
    let oversized = format!("sha256:{HEX1}{padding}");
    for b in both() {
        let n = b.name();
        b.seed_raw("big-repo", "big", oversized.as_bytes());
        for err in [
            b.resolve_tag("big-repo", "big").await.unwrap_err(),
            b.get_tag_with_version("big-repo", "big")
                .await
                .map(|_| ())
                .unwrap_err(),
            b.list_tags_page("big-repo", None, 10)
                .await
                .map(|_| ())
                .unwrap_err(),
        ] {
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::CorruptData),
                "[{n}] oversized payload -> CorruptData: {err}"
            );
            assert!(err.to_string().contains("exceeds limit"), "[{n}] {err}");
        }
    }
}

/// CreateOnly: one creator, Unchanged on identical digest ahead of the
/// policy rejection, conflict on different digest, corrupt-existing treated
/// as absent (overwritten).
#[tokio::test]
async fn shared_create_only_policy() {
    for b in both() {
        let n = b.name();
        let created = b
            .mutate_tag("co-repo", "t", &d(HEX1), TagMutationPolicy::CreateOnly)
            .await
            .unwrap();
        assert_eq!(created, TagMutation::Created, "[{n}]");

        let unchanged = b
            .mutate_tag("co-repo", "t", &d(HEX1), TagMutationPolicy::CreateOnly)
            .await
            .unwrap();
        assert_eq!(
            unchanged,
            TagMutation::Unchanged,
            "[{n}] same digest short-circuits before the policy rejection"
        );

        let conflict = b
            .mutate_tag("co-repo", "t", &d(HEX2), TagMutationPolicy::CreateOnly)
            .await
            .unwrap_err();
        assert!(
            matches!(conflict, StorageError::TagAlreadyExists),
            "[{n}] different digest -> TagAlreadyExists"
        );

        // Corrupt existing tag: treated as absent, replaced.
        b.seed_raw("co-repo", "corrupt", b"garbage-not-a-digest");
        let over = b
            .mutate_tag(
                "co-repo",
                "corrupt",
                &d(HEX1),
                TagMutationPolicy::CreateOnly,
            )
            .await
            .unwrap();
        assert_eq!(
            over,
            TagMutation::Created,
            "[{n}] corrupt existing tag is treated as absent by CreateOnly"
        );
        assert_eq!(
            b.read_raw("co-repo", "corrupt").unwrap(),
            format!("sha256:{HEX1}\n").into_bytes(),
            "[{n}]"
        );
    }
}

/// Replace: unconditional replacement of existing-or-absent; Unchanged on
/// identical digest performs no write; corrupt existing reports Created.
#[tokio::test]
async fn shared_replace_policy() {
    for b in both() {
        let n = b.name();
        let created = b
            .mutate_tag("rp-repo", "t", &d(HEX1), TagMutationPolicy::Replace)
            .await
            .unwrap();
        assert_eq!(created, TagMutation::Created, "[{n}] absent -> Created");

        let unchanged = b
            .mutate_tag("rp-repo", "t", &d(HEX1), TagMutationPolicy::Replace)
            .await
            .unwrap();
        assert_eq!(unchanged, TagMutation::Unchanged, "[{n}]");

        let replaced = b
            .mutate_tag("rp-repo", "t", &d(HEX2), TagMutationPolicy::Replace)
            .await
            .unwrap();
        assert_eq!(
            replaced,
            TagMutation::Replaced { previous: d(HEX1) },
            "[{n}] reports the prior digest"
        );
        assert_eq!(
            b.read_raw("rp-repo", "t").unwrap(),
            format!("sha256:{HEX2}\n").into_bytes(),
            "[{n}]"
        );

        b.seed_raw("rp-repo", "corrupt", b"garbage");
        let over = b
            .mutate_tag("rp-repo", "corrupt", &d(HEX1), TagMutationPolicy::Replace)
            .await
            .unwrap();
        assert_eq!(
            over,
            TagMutation::Created,
            "[{n}] corrupt existing reports Created (treated as absent)"
        );
    }
}

/// Unconditional delete: present -> success + gone; absent -> NotFound.
#[tokio::test]
async fn shared_unconditional_delete() {
    for b in both() {
        let n = b.name();
        b.set_tag("del-repo", "t", &d(HEX1)).await.unwrap();
        b.delete_tag("del-repo", "t").await.unwrap();
        assert!(b.read_raw("del-repo", "t").is_none(), "[{n}] gone");
        let err = b.delete_tag("del-repo", "t").await.unwrap_err();
        assert!(matches!(err, StorageError::NotFound), "[{n}]");
    }
}

/// Conditional delete: matching registry version deletes; stale version
/// preserves the tag and reports the CURRENT registry token; None gates on
/// existence only.
#[tokio::test]
async fn shared_conditional_delete() {
    for b in both() {
        let n = b.name();
        b.set_tag("cd-repo", "t", &d(HEX1)).await.unwrap();
        let (_, version) = b
            .get_tag_with_version("cd-repo", "t")
            .await
            .unwrap()
            .unwrap();

        // Stale token: survives, reports current.
        let stale = b
            .delete_tag_conditional("cd-repo", "t", Some("not-the-version"))
            .await
            .unwrap();
        assert_eq!(
            stale,
            ConditionalDeleteResult::PreconditionFailed {
                current_version: Some(version.clone()),
            },
            "[{n}] stale precondition reports the current registry token"
        );
        assert!(b.read_raw("cd-repo", "t").is_some(), "[{n}] tag survives");

        // Matching token deletes.
        let ok = b
            .delete_tag_conditional("cd-repo", "t", Some(&version))
            .await
            .unwrap();
        assert_eq!(ok, ConditionalDeleteResult::Deleted, "[{n}]");
        assert!(b.read_raw("cd-repo", "t").is_none(), "[{n}]");

        // None: existence-gated unconditional delete.
        b.set_tag("cd-repo", "u", &d(HEX2)).await.unwrap();
        let ok = b
            .delete_tag_conditional("cd-repo", "u", None)
            .await
            .unwrap();
        assert_eq!(ok, ConditionalDeleteResult::Deleted, "[{n}]");
    }
}

/// §16 replacement race: interpose a replacement INSIDE the window between
/// the registry precondition check and the backend conditional delete. The
/// replacement must survive with the existing precondition-failure
/// semantics — identically on both backends.
#[tokio::test]
async fn shared_conditional_delete_replacement_race() {
    let _hook_guard = HOOK_LOCK.lock().await;
    for b in both() {
        let n = b.name();
        let repo = match b {
            Backend::Fs { .. } => "race-repo-fs",
            Backend::S3 { .. } => "race-repo-s3",
        };
        b.set_tag(repo, "t", &d(HEX1)).await.unwrap();
        let (_, version_a) = b.get_tag_with_version(repo, "t").await.unwrap().unwrap();

        // Interpose replacement B exactly between the registry version check
        // and the backend conditional delete.
        let replacement = format!("sha256:{HEX2}\n");
        {
            let repl = replacement.clone();
            let hook_repo = repo.to_string();
            match &b {
                Backend::Fs { root, .. } => {
                    let path = root.join("repos").join(repo).join("tags").join("t");
                    super::test_hooks::set_conditional_delete_boundary(move |r, t| {
                        if r == hook_repo && t == "t" {
                            std::fs::write(&path, repl.as_bytes()).unwrap();
                        }
                    });
                }
                Backend::S3 { driver, .. } => {
                    let driver = driver.clone();
                    let key = format!("repos/{repo}/tags/t");
                    super::test_hooks::set_conditional_delete_boundary(move |r, t| {
                        if r == hook_repo && t == "t" {
                            driver.objects.lock().unwrap().insert(
                                key.clone(),
                                (
                                    bytes::Bytes::from(repl.clone().into_bytes()),
                                    "\"replacement\"".to_string(),
                                ),
                            );
                        }
                    });
                }
            }
        }

        let res = b
            .delete_tag_conditional(repo, "t", Some(&version_a))
            .await
            .unwrap();
        super::test_hooks::clear_conditional_delete_boundary();

        assert_eq!(
            res,
            ConditionalDeleteResult::PreconditionFailed {
                current_version: Some(sha256_hex(replacement.as_bytes())),
            },
            "[{n}] the backend token protects the replacement; the registry \
             reports precondition failure with the CURRENT registry token"
        );
        assert_eq!(
            b.read_raw(repo, "t").unwrap(),
            replacement.clone().into_bytes(),
            "[{n}] replacement B survives"
        );
    }
}

/// Storage-grammar dot-prefixed tag: writable, resolvable, conditionally
/// deletable — but never listed (the frozen dot-skip protects legacy
/// bookkeeping artifacts). Identical on both backends.
#[tokio::test]
async fn shared_dot_prefixed_tag_storage_grammar() {
    for b in both() {
        let n = b.name();
        b.set_tag("dot-repo", "visible", &d(HEX2)).await.unwrap();
        let created = b
            .mutate_tag(
                "dot-repo",
                ".hidden",
                &d(HEX1),
                TagMutationPolicy::CreateOnly,
            )
            .await
            .unwrap();
        assert_eq!(created, TagMutation::Created, "[{n}]");
        assert_eq!(
            b.resolve_tag("dot-repo", ".hidden").await.unwrap().hex(),
            HEX1,
            "[{n}] dot tag resolves"
        );
        assert_eq!(
            b.list_tags("dot-repo").await.unwrap(),
            vec!["visible"],
            "[{n}] dot tag never listed"
        );
        let (page, _) = b.list_tags_page("dot-repo", None, 10).await.unwrap();
        assert_eq!(
            page.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
            vec!["visible"],
            "[{n}]"
        );
        let (_, v) = b
            .get_tag_with_version("dot-repo", ".hidden")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            b.delete_tag_conditional("dot-repo", ".hidden", Some(&v))
                .await
                .unwrap(),
            ConditionalDeleteResult::Deleted,
            "[{n}]"
        );
    }
}

/// Nested (multi-segment) tags remain READABLE for layout compatibility but
/// are rejected by mutations and invisible to listings (structural non-tag
/// entries) — identically on both backends.
#[tokio::test]
async fn shared_nested_tag_read_only_compatibility() {
    for b in both() {
        let n = b.name();
        b.seed_raw(
            "nest-repo",
            "sub/inner",
            format!("sha256:{HEX1}\n").as_bytes(),
        );
        b.set_tag("nest-repo", "top", &d(HEX2)).await.unwrap();

        assert_eq!(
            b.resolve_tag("nest-repo", "sub/inner").await.unwrap().hex(),
            HEX1,
            "[{n}] nested tag reads through the historical multi-segment grammar"
        );
        let err = b
            .set_tag("nest-repo", "sub/other", &d(HEX1))
            .await
            .unwrap_err();
        assert!(
            matches!(err, StorageError::InvalidRepoName(_)),
            "[{n}] mutations reject multi-segment tags"
        );
        assert_eq!(
            b.list_tags("nest-repo").await.unwrap(),
            vec!["top"],
            "[{n}] nested entries are structural non-tags in listings"
        );
    }
}

/// Listing pagination: lexical order, strictly-after tokens, resume from a
/// deleted token, page_limit == 0, missing repository empty terminal page.
#[tokio::test]
async fn shared_listing_pagination() {
    for b in both() {
        let n = b.name();
        for t in ["a1", "b2", "c3", "d4", "e5"] {
            b.set_tag("page-repo", t, &d(HEX1)).await.unwrap();
        }

        let (p1, t1) = b.list_tags_page("page-repo", None, 2).await.unwrap();
        assert_eq!(
            p1.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
            vec!["a1", "b2"],
            "[{n}]"
        );
        assert_eq!(t1.as_deref(), Some("b2"), "[{n}]");

        let (p2, t2) = b
            .list_tags_page("page-repo", t1.as_deref(), 2)
            .await
            .unwrap();
        assert_eq!(
            p2.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
            vec!["c3", "d4"],
            "[{n}]"
        );

        // Deleting the token tag still resumes strictly after it.
        b.delete_tag("page-repo", "d4").await.unwrap();
        let (p3, t3) = b
            .list_tags_page("page-repo", t2.as_deref(), 2)
            .await
            .unwrap();
        assert_eq!(
            p3.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
            vec!["e5"],
            "[{n}] deleted token resumes at the correct position"
        );
        assert!(t3.is_none(), "[{n}]");

        // Zero page: empty, no token, no payload inspection required.
        let (p0, t0) = b.list_tags_page("page-repo", None, 0).await.unwrap();
        assert!(p0.is_empty() && t0.is_none(), "[{n}]");

        // Missing repository: empty terminal page on BOTH backends.
        let (pm, tm) = b.list_tags_page("no-such-repo", None, 5).await.unwrap();
        assert!(pm.is_empty() && tm.is_none(), "[{n}]");
    }
}

/// `list_tags` missing-repository contract: the one deliberate per-backend
/// difference, preserved exactly (FS: NotFound; S3: empty).
#[tokio::test]
async fn shared_list_tags_missing_repository_contract() {
    for b in both() {
        let n = b.name();
        let res = b.list_tags("never-created-repo").await;
        if b.missing_repo_lists_not_found() {
            assert!(
                matches!(res, Err(StorageError::NotFound)),
                "[{n}] FS models repository existence: NotFound, got {res:?}"
            );
        } else {
            assert_eq!(
                res.unwrap(),
                Vec::<String>::new(),
                "[{n}] S3 has no repository-existence notion: empty"
            );
        }
    }
}

/// Manifest-delete tag cleanup through the shared helper: matching tags
/// removed best-effort, non-matching and dot-prefixed (legacy bookkeeping)
/// entries survive, manifest-first ordering.
#[tokio::test]
async fn shared_manifest_delete_tag_cleanup() {
    let manifest =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
    for b in both() {
        let n = b.name();
        let dd = d(HEX1);
        let de = d(HEX2);
        b.put_manifest("cln-repo", &dd, bytes::Bytes::from_static(manifest))
            .await;
        b.set_tag("cln-repo", "match-1", &dd).await.unwrap();
        b.set_tag("cln-repo", "match-2", &dd).await.unwrap();
        b.set_tag("cln-repo", "keep", &de).await.unwrap();
        // Legacy dot-prefixed bookkeeping artifact: must survive untouched.
        b.seed_raw("cln-repo", ".lock.legacy", b"legacy lock artifact");

        b.delete_manifest("cln-repo", &dd).await.unwrap();

        assert!(b.read_raw("cln-repo", "match-1").is_none(), "[{n}]");
        assert!(b.read_raw("cln-repo", "match-2").is_none(), "[{n}]");
        assert_eq!(
            b.read_raw("cln-repo", "keep").unwrap(),
            format!("sha256:{HEX2}\n").into_bytes(),
            "[{n}] non-matching tag survives"
        );
        assert_eq!(
            b.read_raw("cln-repo", ".lock.legacy").unwrap(),
            b"legacy lock artifact".to_vec(),
            "[{n}] dot-prefixed legacy artifact protected"
        );
    }
}

/// Concurrent CreateOnly for one absent tag: exactly one semantic creator on
/// both backends (the losers report Unchanged/TagAlreadyExists, never a
/// second Created), and the winner's bytes are never overwritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_create_only_single_creator_race() {
    // FS backend.
    {
        let b = Arc::new(fs_backend());
        run_create_only_race(b).await;
    }
    // S3 backend.
    {
        let b = Arc::new(s3_backend());
        run_create_only_race(b).await;
    }
}

async fn run_create_only_race(b: Arc<Backend>) {
    let n = b.name();
    let digests: Vec<Digest> = (0..8)
        .map(|i| {
            let mut hex = String::new();
            for _ in 0..64 {
                hex.push(char::from_digit((i % 10) as u32, 10).unwrap());
            }
            d(&hex)
        })
        .collect();
    let mut handles = Vec::new();
    for digest in digests.clone() {
        let b = b.clone();
        handles.push(tokio::spawn(async move {
            b.mutate_tag("race-co", "t", &digest, TagMutationPolicy::CreateOnly)
                .await
        }));
    }
    let mut created = 0usize;
    let mut conflicts = 0usize;
    let mut unchanged = 0usize;
    for h in handles {
        match h.await.unwrap() {
            Ok(TagMutation::Created) => created += 1,
            Ok(TagMutation::Unchanged) => unchanged += 1,
            Ok(other) => panic!("[{n}] unexpected outcome {other:?}"),
            Err(StorageError::TagAlreadyExists) => conflicts += 1,
            Err(e) => panic!("[{n}] unexpected error {e:?}"),
        }
    }
    assert_eq!(created, 1, "[{n}] exactly one semantic creator");
    assert_eq!(created + conflicts + unchanged, 8, "[{n}]");
    // The final bytes are the winner's canonical payload — some digest from
    // the set, still parseable, never torn.
    let raw = b.read_raw("race-co", "t").unwrap();
    let s = String::from_utf8(raw).unwrap();
    let final_digest = Digest::parse(s.trim()).unwrap();
    assert!(
        digests.contains(&final_digest),
        "[{n}] winner's digest published intact"
    );
}

// ---------------------------------------------------------------------------
// FS-specific: containment / root replacement / fault injection (§31, §33)
// ---------------------------------------------------------------------------

/// Root-replacement pinning at the migrated boundary: the storage instance
/// pinned to root A keeps reading AND mutating A after the pathname is
/// replaced with B; a NEW instance resolves B; B is untouched by the old
/// instance's mutations.
#[tokio::test]
async fn fs_root_replacement_pinning_and_coherence() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::try_new(root.clone(), 1024 * 1024).unwrap();

    storage.set_tag("pin-repo", "t", &d(HEX1)).await.unwrap();

    // Replace the whole root pathname.
    let old_root = tmp.path().join("storage-root-old");
    std::fs::rename(&root, &old_root).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let replacement_leaf = root.join("repos").join("pin-repo").join("tags").join("t");
    std::fs::create_dir_all(replacement_leaf.parent().unwrap()).unwrap();
    std::fs::write(&replacement_leaf, format!("sha256:{HEX2}\n")).unwrap();

    // The pinned instance still observes the OLD tree...
    assert_eq!(
        storage.resolve_tag("pin-repo", "t").await.unwrap().hex(),
        HEX1,
        "pinned instance reads the original root"
    );
    // ...and its version token drives a conditional delete on that SAME tree.
    let (_, v) = storage
        .get_tag_with_version("pin-repo", "t")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        storage
            .delete_tag_conditional("pin-repo", "t", Some(&v))
            .await
            .unwrap(),
        ConditionalDeleteResult::Deleted,
        "read and write are coherent on the pinned root"
    );
    // The ambient replacement tree is untouched.
    assert_eq!(
        std::fs::read(&replacement_leaf).unwrap(),
        format!("sha256:{HEX2}\n").into_bytes(),
        "replacement tree untouched by the pinned instance"
    );
    // A NEW instance resolves the replacement tree.
    let storage_b = FsStorage::try_new(root.clone(), 1024 * 1024).unwrap();
    assert_eq!(
        storage_b.resolve_tag("pin-repo", "t").await.unwrap().hex(),
        HEX2,
        "a fresh instance observes the replacement root"
    );
}

/// The FS object store's internal bookkeeping namespace is structurally
/// unaddressable through the registry tag grammar (control characters are
/// rejected before any storage access).
#[tokio::test]
async fn fs_internal_namespace_unaddressable() {
    let b = fs_backend();
    let internal = naust_storage_fs::object_store::INTERNAL_DIR;
    let err = b.resolve_tag(internal, "t").await.unwrap_err();
    assert!(
        matches!(err, StorageError::InvalidRepoName(_)),
        "internal tree as repository -> InvalidRepoName, got {err:?}"
    );
    let err = b.set_tag("repo", internal, &d(HEX1)).await.unwrap_err();
    assert!(
        matches!(err, StorageError::InvalidRepoName(_)),
        "internal tree as tag -> InvalidRepoName, got {err:?}"
    );
    // And after real mutations, the internal tree never leaks into listings.
    b.set_tag("leak-repo", "t", &d(HEX1)).await.unwrap();
    assert_eq!(b.list_tags("leak-repo").await.unwrap(), vec!["t"]);
}

/// §33 FS fault injection at the registry boundary: a durable publication
/// failure (staged-rename or directory-sync fault below the ObjectStore)
/// surfaces from the registry tag write instead of reporting success.
#[tokio::test]
async fn fs_durable_publication_fault_propagates() {
    use naust_storage_fs::mutate::fault::{self, FaultPoint};

    let _fault_guard = crate::storage::store_common::fault_scenario::begin().await;
    let b = fs_backend();

    // Rename fault: the staged publication of this unique leaf fails.
    fault::arm(FaultPoint::RenameLeaf, Some("zzregfaulttag"), 1, libc::EIO);
    let err = b
        .set_tag("zztagfaultrepo", "zzregfaulttag", &d(HEX1))
        .await
        .expect_err("failed staged rename must propagate");
    assert!(
        err.internal_kind().is_some(),
        "classified internal error: {err:?}"
    );
    assert!(
        b.read_raw("zztagfaultrepo", "zzregfaulttag").is_none(),
        "no partial tag published"
    );

    // Directory-sync fault: Durable publication reports the barrier failure.
    fault::arm(FaultPoint::DirSync, Some("zztagfaultrepo"), 1, libc::EIO);
    let err = b
        .set_tag("zztagfaultrepo", "zzregfaultsync", &d(HEX1))
        .await
        .expect_err("failed durable barrier must propagate");
    assert!(
        err.internal_kind().is_some(),
        "classified internal error: {err:?}"
    );
    fault::reset();

    // Negative control: with faults cleared the same write succeeds.
    b.set_tag("zztagfaultrepo", "zzregfaulttag", &d(HEX1))
        .await
        .expect("write succeeds after faults cleared");
}

// ---------------------------------------------------------------------------
// S3-specific: prefix isolation / fault propagation / vanished candidates
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

/// §9/§31 configured-prefix compatibility and isolation: the physical key is
/// exactly `<prefix>/repos/<repo>/tags/<tag>` (no double prefix, no
/// separator drift), and sibling prefixes stay invisible and untouched.
#[tokio::test]
async fn s3_prefix_physical_compatibility_and_isolation() {
    let (storage, driver) = s3_backend_with_prefix("tenant-a");

    storage.set_tag("iso-repo", "v1", &d(HEX1)).await.unwrap();
    {
        let objs = driver.objects.lock().unwrap();
        assert_eq!(
            objs.get("tenant-a/repos/iso-repo/tags/v1")
                .map(|(b, _)| b.to_vec()),
            Some(format!("sha256:{HEX1}\n").into_bytes()),
            "exact old physical key under the configured prefix"
        );
    }

    // Foreign sibling namespaces: same logical repo/tag under OTHER roots.
    for key in [
        "tenant-b/repos/iso-repo/tags/v2",
        "repos/iso-repo/tags/v3",
        "tenant-a-suffix/repos/iso-repo/tags/v4",
    ] {
        driver.objects.lock().unwrap().insert(
            key.to_string(),
            (
                bytes::Bytes::from(format!("sha256:{HEX2}\n").into_bytes()),
                "\"x\"".to_string(),
            ),
        );
    }

    assert_eq!(
        storage.list_tags("iso-repo").await.unwrap(),
        vec!["v1"],
        "sibling prefixes are invisible"
    );
    assert!(
        matches!(
            storage.resolve_tag("iso-repo", "v2").await,
            Err(StorageError::NotFound)
        ),
        "sibling-prefix objects are unreachable"
    );
    // Cleanup of a matching digest under the prefix never touches siblings.
    let manifest =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
    storage
        .put_manifest("iso-repo", &d(HEX2), bytes::Bytes::from_static(manifest))
        .await
        .unwrap();
    storage.delete_manifest("iso-repo", &d(HEX2)).await.unwrap();
    let objs = driver.objects.lock().unwrap();
    assert!(
        objs.contains_key("tenant-b/repos/iso-repo/tags/v2")
            && objs.contains_key("repos/iso-repo/tags/v3")
            && objs.contains_key("tenant-a-suffix/repos/iso-repo/tags/v4"),
        "foreign namespaces untouched by tag cleanup"
    );
}

/// §33 S3 fault propagation at the registry boundary: DELETE AccessDenied
/// maps to PermissionDenied through the one shared translation path.
#[tokio::test]
async fn s3_delete_access_denied_propagates_permission_denied() {
    let b = s3_backend();
    let Backend::S3 { storage, driver } = &b else {
        unreachable!()
    };
    storage.set_tag("perm-repo", "t", &d(HEX1)).await.unwrap();
    driver.set_hook_before(|method, key| {
        if method == "delete_object" && key == "repos/perm-repo/tags/t" {
            Some(StorageError::permission_denied("s3:DeleteObject forbidden"))
        } else {
            None
        }
    });
    let err = storage.delete_tag("perm-repo", "t").await.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied),
        "AccessDenied surfaces as PermissionDenied: {err:?}"
    );
    driver.clear_hooks();
}

/// Vanished listing candidate (deterministic on the S3 seam): an object
/// listed but deleted before its payload read is OMITTED, exactly like a
/// vanished filesystem candidate.
#[tokio::test]
async fn s3_vanished_listing_candidate_omitted() {
    let b = s3_backend();
    let Backend::S3 { storage, driver } = &b else {
        unreachable!()
    };
    storage
        .set_tag("van-repo", "stays", &d(HEX1))
        .await
        .unwrap();
    storage
        .set_tag("van-repo", "vanishes", &d(HEX2))
        .await
        .unwrap();

    // The read hook deletes the object then lets the GET proceed (absent).
    let driver_clone = driver.clone();
    driver.set_hook_before(move |method, key| {
        if method == "get_object" && key == "repos/van-repo/tags/vanishes" {
            driver_clone.objects.lock().unwrap().remove(key);
        }
        None
    });
    let (page, next) = storage.list_tags_page("van-repo", None, 10).await.unwrap();
    driver.clear_hooks();
    assert_eq!(
        page.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["stays"],
        "vanished candidate omitted, page otherwise intact"
    );
    assert!(next.is_none());
}

// ---------------------------------------------------------------------------
// Phase 3 semantic reconciliation: cleanup replacement timelines (§15) and
// Replace race outcomes (§11)
// ---------------------------------------------------------------------------

const MANIFEST_JSON: &[u8] =
    br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;

/// Timeline: cleanup observes tag t -> X (matching the deleted digest); a
/// replacement B -> Y lands between inspection and the conditional delete.
/// B must survive — observing A never authorizes deleting an unobserved B.
#[tokio::test]
async fn shared_cleanup_replacement_pointing_elsewhere_survives() {
    let _hook_guard = HOOK_LOCK.lock().await;
    for b in both() {
        let n = b.name();
        let repo = match b {
            Backend::Fs { .. } => "clnrace-fs",
            Backend::S3 { .. } => "clnrace-s3",
        };
        let x = d(HEX1);
        b.put_manifest(repo, &x, bytes::Bytes::from_static(MANIFEST_JSON))
            .await;
        b.set_tag(repo, "t", &x).await.unwrap();

        let replacement = format!("sha256:{HEX2}\n");
        {
            let repl = replacement.clone();
            let hook_repo = repo.to_string();
            match &b {
                Backend::Fs { root, .. } => {
                    let path = root.join("repos").join(repo).join("tags").join("t");
                    super::test_hooks::set_cleanup_boundary(move |r, t| {
                        if r == hook_repo && t == "t" {
                            std::fs::write(&path, repl.as_bytes()).unwrap();
                        }
                    });
                }
                Backend::S3 { driver, .. } => {
                    let driver = driver.clone();
                    let key = format!("repos/{repo}/tags/t");
                    super::test_hooks::set_cleanup_boundary(move |r, t| {
                        if r == hook_repo && t == "t" {
                            driver.objects.lock().unwrap().insert(
                                key.clone(),
                                (
                                    bytes::Bytes::from(repl.clone().into_bytes()),
                                    "\"replacement\"".to_string(),
                                ),
                            );
                        }
                    });
                }
            }
        }

        b.delete_manifest(repo, &x)
            .await
            .expect("cleanup is best-effort; a lost race is not an error");
        super::test_hooks::clear_cleanup_boundary();

        assert_eq!(
            b.read_raw(repo, "t").unwrap(),
            replacement.clone().into_bytes(),
            "[{n}] replacement B -> Y survives the cleanup window"
        );
    }
}

/// Timeline: the replacement B ALSO points at the deleted digest X. Accepted
/// result: B survives THIS best-effort pass (its generation was never
/// observed); the lifecycle layer's snapshot/proof passes own re-matching.
#[tokio::test]
async fn shared_cleanup_replacement_same_target_survives_this_pass() {
    let _hook_guard = HOOK_LOCK.lock().await;
    for b in both() {
        let n = b.name();
        let repo = match b {
            Backend::Fs { .. } => "clnsame-fs",
            Backend::S3 { .. } => "clnsame-s3",
        };
        let x = d(HEX1);
        b.put_manifest(repo, &x, bytes::Bytes::from_static(MANIFEST_JSON))
            .await;
        b.set_tag(repo, "t", &x).await.unwrap();

        // Replacement with the SAME canonical bytes: a NEW backend generation.
        let same = format!("sha256:{HEX1}\n");
        {
            let repl = same.clone();
            let hook_repo = repo.to_string();
            match &b {
                Backend::Fs { root, .. } => {
                    let path = root.join("repos").join(repo).join("tags").join("t");
                    super::test_hooks::set_cleanup_boundary(move |r, t| {
                        if r == hook_repo && t == "t" {
                            // Recreate the leaf so even identical bytes are a
                            // distinct generation (fresh inode/mtime).
                            std::fs::remove_file(&path).unwrap();
                            std::fs::write(&path, repl.as_bytes()).unwrap();
                        }
                    });
                }
                Backend::S3 { driver, .. } => {
                    let driver = driver.clone();
                    let key = format!("repos/{repo}/tags/t");
                    super::test_hooks::set_cleanup_boundary(move |r, t| {
                        if r == hook_repo && t == "t" {
                            driver.objects.lock().unwrap().insert(
                                key.clone(),
                                (
                                    bytes::Bytes::from(repl.clone().into_bytes()),
                                    "\"replacement-gen\"".to_string(),
                                ),
                            );
                        }
                    });
                }
            }
        }

        b.delete_manifest(repo, &x).await.unwrap();
        super::test_hooks::clear_cleanup_boundary();

        assert_eq!(
            b.read_raw(repo, "t").unwrap(),
            same.clone().into_bytes(),
            "[{n}] an unobserved same-target replacement generation survives this pass"
        );
    }
}

/// Timeline: the matching candidate vanishes between inspection and delete —
/// the conditional delete reports absence and the pass tolerates it.
#[tokio::test]
async fn shared_cleanup_candidate_vanishes_in_window() {
    let _hook_guard = HOOK_LOCK.lock().await;
    for b in both() {
        let n = b.name();
        let repo = match b {
            Backend::Fs { .. } => "clnvan-fs",
            Backend::S3 { .. } => "clnvan-s3",
        };
        let x = d(HEX1);
        b.put_manifest(repo, &x, bytes::Bytes::from_static(MANIFEST_JSON))
            .await;
        b.set_tag(repo, "t", &x).await.unwrap();
        {
            let hook_repo = repo.to_string();
            match &b {
                Backend::Fs { root, .. } => {
                    let path = root.join("repos").join(repo).join("tags").join("t");
                    super::test_hooks::set_cleanup_boundary(move |r, t| {
                        if r == hook_repo && t == "t" {
                            let _ = std::fs::remove_file(&path);
                        }
                    });
                }
                Backend::S3 { driver, .. } => {
                    let driver = driver.clone();
                    let key = format!("repos/{repo}/tags/t");
                    super::test_hooks::set_cleanup_boundary(move |r, t| {
                        if r == hook_repo && t == "t" {
                            driver.objects.lock().unwrap().remove(&key);
                        }
                    });
                }
            }
        }
        b.delete_manifest(repo, &x)
            .await
            .expect("[cleanup] vanish in the window is tolerated");
        super::test_hooks::clear_cleanup_boundary();
        assert!(b.read_raw(repo, "t").is_none(), "[{n}]");
    }
}

/// §11 Replace race: concurrent Replace(B) / Replace(C) over existing A.
/// Final state is exactly one racer's canonical bytes; every outcome is
/// Replaced with a `previous` naming one of the involved digests (never an
/// invented value, never Created/Unchanged); attribution beyond that is
/// best-effort (no supported caller consumes it — see the reconciliation
/// call-graph evidence).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_replace_race_outcomes() {
    let hex_a = HEX1;
    let hex_b = HEX2;
    let hex_c = "3333333333333333333333333333333333333333333333333333333333333333";
    for b in [Arc::new(fs_backend()), Arc::new(s3_backend())] {
        let n = b.name();
        b.set_tag("rprace", "t", &d(hex_a)).await.unwrap();

        let b1 = b.clone();
        let h1 = tokio::spawn(async move {
            b1.mutate_tag("rprace", "t", &d(HEX2), TagMutationPolicy::Replace)
                .await
        });
        let b2 = b.clone();
        let h2 = tokio::spawn(async move {
            let hex_c = "3333333333333333333333333333333333333333333333333333333333333333";
            b2.mutate_tag("rprace", "t", &d(hex_c), TagMutationPolicy::Replace)
                .await
        });
        let (r1, r2) = tokio::join!(h1, h2);
        let outcomes = [(r1.unwrap().unwrap(), hex_b), (r2.unwrap().unwrap(), hex_c)];

        let final_bytes = b.read_raw("rprace", "t").unwrap();
        let final_s = String::from_utf8(final_bytes).unwrap();
        let final_digest = Digest::parse(final_s.trim()).unwrap();
        assert!(
            final_digest == d(hex_b) || final_digest == d(hex_c),
            "[{n}] final state is one racer's digest, canonical bytes intact"
        );

        for (outcome, own_hex) in outcomes {
            match outcome {
                TagMutation::Replaced { previous } => {
                    assert!(
                        [hex_a, hex_b, hex_c]
                            .iter()
                            .any(|h| previous == d(h) && previous != d(own_hex)),
                        "[{n}] previous names another involved digest, got {previous:?}"
                    );
                }
                other => panic!(
                    "[{n}] Replace over an existing valid tag reports Replaced, got {other:?}"
                ),
            }
        }
    }
}

/// A continuation token that was deleted in the interim still resumes at the
/// exact same position: strictly-after value semantics guarantee no skipping
/// and no duplicate rows.
#[tokio::test]
async fn shared_listing_deleted_continuation_token_resumes() {
    for b in both() {
        let repo = "deleted-tok-repo";
        b.set_tag(repo, "tag-01", &d(HEX1)).await.unwrap();
        b.set_tag(repo, "tag-02", &d(HEX2)).await.unwrap();
        b.set_tag(repo, "tag-03", &d(HEX1)).await.unwrap();
        b.set_tag(repo, "tag-04", &d(HEX2)).await.unwrap();
        b.set_tag(repo, "tag-05", &d(HEX1)).await.unwrap();

        // Page 1
        let (p1, tok1) = b.list_tags_page(repo, None, 2).await.unwrap();
        assert_eq!(p1.len(), 2, "backend: {}", b.name());
        assert_eq!(p1[0].0, "tag-01");
        assert_eq!(p1[1].0, "tag-02");
        assert_eq!(tok1, Some("tag-02".to_string()));

        // Delete tag-02 (the continuation token)
        b.delete_tag(repo, "tag-02").await.unwrap();

        // Page 2 resuming from tag-02
        let (p2, tok2) = b.list_tags_page(repo, tok1.as_deref(), 2).await.unwrap();
        assert_eq!(p2.len(), 2, "backend: {}", b.name());
        assert_eq!(p2[0].0, "tag-03");
        assert_eq!(p2[1].0, "tag-04");
        assert_eq!(tok2, Some("tag-04".to_string()));

        // Page 3
        let (p3, tok3) = b.list_tags_page(repo, tok2.as_deref(), 2).await.unwrap();
        assert_eq!(p3.len(), 1, "backend: {}", b.name());
        assert_eq!(p3[0].0, "tag-05");
        assert_eq!(tok3, None);
    }
}

/// Concurrent mutations (writes, updates, unlinks) during bounded pagination:
/// guarantees monotonic ascending order, zero torn reads, and zero panics.
#[tokio::test]
async fn shared_concurrent_tag_mutations_during_bounded_pagination() {
    for b in both() {
        let repo = "concur-pag-repo";
        // Seed 30 tags
        for i in 0..30 {
            let name = format!("tag-{:03}", i);
            b.set_tag(repo, &name, &d(HEX1)).await.unwrap();
        }

        let b = Arc::new(b);
        let b_clone = b.clone();
        let repo_s = repo.to_string();

        let mutator = tokio::spawn(async move {
            for i in 0..10 {
                let _ = b_clone
                    .set_tag(&repo_s, &format!("tag-dyn-{:03}", i), &d(HEX2))
                    .await;
                let _ = b_clone
                    .delete_tag(&repo_s, &format!("tag-{:03}", i * 2))
                    .await;
            }
        });

        // Reader continuously paginates
        let mut continuation_token = None;
        let mut last_seen_tag = String::new();
        let mut total_pages = 0;

        loop {
            let (page, next_tok) = b
                .list_tags_page(repo, continuation_token.as_deref(), 5)
                .await
                .unwrap();
            total_pages += 1;
            assert!(page.len() <= 5, "backend: {}", b.name());

            for (tag, digest) in &page {
                assert!(
                    tag.as_str() > last_seen_tag.as_str(),
                    "monotonic ordering invariant breached: {tag} <= {last_seen_tag}"
                );
                assert!(
                    *digest == d(HEX1) || *digest == d(HEX2),
                    "torn or invalid digest observed under race: {digest:?}"
                );
                last_seen_tag = tag.clone();
            }

            continuation_token = next_tok;
            if continuation_token.is_none() || total_pages > 20 {
                break;
            }
        }

        let _ = mutator.await;
    }
}

#[tokio::test]
async fn shared_tag_listing_adversarial_page_limit_extremes_and_boundary_tokens() {
    for b in both() {
        let repo = "adv-tag-limits";
        b.set_tag(repo, "tag-01", &d(HEX1)).await.unwrap();
        b.set_tag(repo, "tag-02", &d(HEX1)).await.unwrap();
        b.set_tag(repo, "tag-03", &d(HEX2)).await.unwrap();

        // 1. page_limit = 0 -> empty terminal page immediately, no reads
        let (page, next) = b.list_tags_page(repo, None, 0).await.unwrap();
        assert!(page.is_empty());
        assert!(next.is_none());

        // 2. page_limit = usize::MAX -> returns all 3 tags without panic or allocation failure
        let (page, next) = b.list_tags_page(repo, None, usize::MAX).await.unwrap();
        assert_eq!(page.len(), 3);
        assert_eq!(page[0].0, "tag-01");
        assert_eq!(page[1].0, "tag-02");
        assert_eq!(page[2].0, "tag-03");
        assert!(next.is_none());

        // 3. page_limit = usize::MAX - 1 -> safe from integer overflow
        let (page, next) = b.list_tags_page(repo, None, usize::MAX - 1).await.unwrap();
        assert_eq!(page.len(), 3);
        assert!(next.is_none());

        // 4. Token: Some("") -> starts from beginning
        let (page, next) = b.list_tags_page(repo, Some(""), 1).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].0, "tag-01");
        assert_eq!(next.as_deref(), Some("tag-01"));

        // 5. Token: Some("tag-01") -> resumes strictly after tag-01
        let (page, next) = b.list_tags_page(repo, Some("tag-01"), 1).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].0, "tag-02");
        assert_eq!(next.as_deref(), Some("tag-02"));

        // 6. Token: Some("tag-015") (non-existent token between tag-01 and tag-02) -> resumes at tag-02
        let (page, next) = b.list_tags_page(repo, Some("tag-015"), 5).await.unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].0, "tag-02");
        assert_eq!(page[1].0, "tag-03");
        assert!(next.is_none());

        // 7. Token: Some("zzz") -> past end
        let (page, next) = b.list_tags_page(repo, Some("zzz"), 5).await.unwrap();
        assert!(page.is_empty());
        assert!(next.is_none());
    }
}

/// Verifies that high-cardinality repositories stream across pages without
/// memory explosion or artificial listing limit errors, and that manifest
/// deletion cleanup runs to completion unlinking all tags.
#[tokio::test]
async fn shared_high_cardinality_unbounded_streaming_and_cleanup() {
    for b in both() {
        let repo = "high-card-repo";
        let target_digest = d(HEX1);
        let other_digest = d(HEX2);

        // Seed 300 tags pointing to target_digest and 100 pointing to other_digest
        for i in 0..300 {
            let name = format!("tag-{:04}", i);
            b.set_tag(repo, &name, &target_digest).await.unwrap();
        }
        for i in 300..400 {
            let name = format!("tag-{:04}", i);
            b.set_tag(repo, &name, &other_digest).await.unwrap();
        }

        // 1. Paginate through all 400 tags with a prime page size (17)
        let mut token = None;
        let mut total_listed = 0;
        let mut last_tag = String::new();

        loop {
            let (page, next) = b.list_tags_page(repo, token.as_deref(), 17).await.unwrap();
            assert!(page.len() <= 17);
            for (tag, _) in &page {
                assert!(
                    tag.as_str() > last_tag.as_str(),
                    "monotonic ascending order"
                );
                last_tag = tag.clone();
                total_listed += 1;
            }
            token = next;
            if token.is_none() {
                break;
            }
        }
        assert_eq!(
            total_listed, 400,
            "all 400 tags listed under unbounded streaming"
        );

        // 2. Put manifest and then delete it -> triggers unbounded streaming cleanup
        let manifest =
            br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
        b.put_manifest(repo, &target_digest, bytes::Bytes::from_static(manifest))
            .await;

        b.delete_manifest(repo, &target_digest).await.unwrap();

        // 3. Verify exactly 100 surviving tags remain (the other_digest ones)
        let mut surviving = Vec::new();
        let mut token = None;
        loop {
            let (page, next) = b.list_tags_page(repo, token.as_deref(), 32).await.unwrap();
            for (tag, digest) in page {
                assert_eq!(digest, other_digest);
                surviving.push(tag);
            }
            token = next;
            if token.is_none() {
                break;
            }
        }
        assert_eq!(
            surviving.len(),
            100,
            "cleanup correctly unlinked all 300 target tags"
        );
        assert_eq!(surviving.first().unwrap(), "tag-0300");
        assert_eq!(surviving.last().unwrap(), "tag-0399");
    }
}
