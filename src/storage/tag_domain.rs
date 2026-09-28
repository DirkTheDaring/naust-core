//! Shared registry tag-domain implementation over the backend-neutral
//! [`ObjectStore`] contract (STORAGE-LAYER-MIGRATION Phase 3).
//!
//! This is the ONE registry implementation of tag semantics. It owns:
//! - repository/tag structural validation and the `(repo, tag)` →
//!   [`ObjectKey`] mapping (`repos/<repo>/tags/<tag>`, the accepted physical
//!   layout on both backends);
//! - tag payload encoding (`{digest}\n`) and decoding (trim + digest parse),
//!   including the per-operation malformed/absent error taxonomy;
//! - the CreateOnly/Replace mutation policy, the same-digest short-circuit,
//!   and corrupt-tag-treated-as-absent mutation semantics;
//! - the registry's externally visible conditional version token: the
//!   SHA-256 hex of the exact raw payload bytes (NEVER a backend
//!   ETag/inode token — those stay below the [`ObjectStore`] boundary);
//! - bounded payload reads and bounded listing collection with truthful
//!   resource errors (never silent truncation);
//! - ONE common `StoreError` → [`StorageError`] translation.
//!
//! Filesystem containment (pinned roots, symlink fail-closed, contained
//! staging/locks) and S3 request/version mechanics (`If-Match` /
//! `If-None-Match`, ETag opacity, physical-prefix isolation) live entirely
//! below the [`ObjectStore`] boundary in `storage-fs` / `storage-s3`. This
//! module never inspects which backend it is running on.
//!
//! # Converged semantics (documented FS↔S3 divergence resolutions)
//! The pre-migration backends disagreed on several storage-level rows; the
//! shared implementation converges each (see the Phase 3 parity matrix):
//! - invalid UTF-8 in a stored tag payload is `CorruptData` on every path
//!   (old FS reported kind `Io` on some paths; old S3 skipped it silently in
//!   the manifest-delete scan). Externally both kinds surfaced as HTTP 500.
//! - a corrupt (unparseable) existing tag is treated as ABSENT by mutations,
//!   exactly like the old FS backend: `Replace` overwrites it (`Created`),
//!   `CreateOnly` replaces it guarded by the backend version observed with
//!   those corrupt bytes (old S3 returned `TagAlreadyExists`/`NotFound`).
//! - unconditional delete of an absent tag is `Err(NotFound)` (old FS
//!   behavior; old S3 returned `Ok(())`). Production callers ignore the
//!   result (best-effort journal recovery), so this is production-invisible.
//! - the conditional-delete version token is the raw-byte SHA-256 on BOTH
//!   backends (old S3 used the object ETag). Tokens are never client
//!   supplied; persisted journal snapshots from a pre-migration S3 run
//!   degrade to the recovery path's fresh-read sweep.
//! - point reads are bounded (old backends buffered unbounded objects); an
//!   oversized object maps to the accepted drain-overflow `CorruptData`.
//! - listing collection is bounded with a truthful `Backend` error on
//!   exhaustion (old FS was bounded identically via directory-enumeration
//!   limits; old S3 accumulated without bound).
//! - `mutate_tag(Replace)` performs read-then-atomic-publish without the old
//!   FS advisory `.lock.<tag>` and without the old S3 CAS retry loop: every
//!   individual publication is atomic below the boundary, CreateOnly's
//!   one-creator guarantee rides on `write_if_absent`, and conditional
//!   deletes ride on `delete_if_version`, so no composed sequence can
//!   clobber a concurrent winner. The old S3 `Conflict("tag mutation
//!   contention limit exceeded")` failure mode no longer exists. The
//!   `TagMutation` outcome is discarded by the only production caller
//!   (`publish_internal`), so outcome attribution under races is not a
//!   protected invariant.

use std::num::NonZeroUsize;
use std::sync::Arc;

use async_trait::async_trait;
use naust_storage_core::ObjectKey;
use naust_storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ObjectStore, ReplaceOutcome, StoreError,
    adapter,
};
use sha2::Digest as Sha2Digest;

use crate::registry::digest::Digest;

use super::{ConditionalDeleteResult, StorageError, TagMutation, TagMutationPolicy};

/// Internal page size for listing collection round trips.
const LIST_PAGE_SIZE: usize = 1000;

/// Default byte ceiling for one tag payload read (mirrors the accepted FS
/// tag-listing payload bound; backends without their own configured bound —
/// S3 — wire this).
pub(crate) const DEFAULT_MAX_PAYLOAD_BYTES: u64 = 1_024;

/// Default ceiling on tag rows observed by one listing/cleanup pass.
/// Obsolete with streaming pagination; defaults to unbounded.
pub(crate) const DEFAULT_MAX_LISTING_ENTRIES: usize = usize::MAX;

/// Bounded attempts for the CreateOnly observe/decide/publish sequence under
/// racing creators (each attempt is individually atomic; the loop only
/// re-observes after losing a race).
const CREATE_ONLY_MAX_ATTEMPTS: usize = 3;

/// Backend-neutral tag-domain resource policy, supplied by each storage
/// backend at wiring time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TagDomainConfig {
    /// Byte ceiling for one tag payload read. Every payload the registry
    /// writes is `{digest}\n` (≤ 136 bytes for sha512); the ceiling exists
    /// to keep corrupt/foreign objects from being buffered unbounded and is
    /// wired from the accepted tag-listing payload bound.
    pub max_payload_bytes: u64,
    /// Ceiling on tag-namespace rows observed by one listing/cleanup pass.
    /// Obsolete with streaming pagination; retained for backwards-compatible wiring.
    #[allow(dead_code)]
    pub max_listing_entries: usize,
}

/// Repository-existence probe used ONLY by `list_tags` to preserve each
/// backend's historical missing-repository contract (filesystem: probe the
/// contained `repos/<repo>` directory, `Err(NotFound)` when absent; S3: no
/// repository-existence notion, always "exists" → empty listing).
///
/// Repository existence is REPOSITORY-family state, not tag-family storage
/// mechanics; this seam is deliberately retained per-backend until the
/// repository-discovery family migrates in a later phase.
#[async_trait]
pub(crate) trait TagRepoProbe: Send + Sync {
    async fn repo_exists(&self, repo: &str) -> Result<bool, StorageError>;
}

/// S3 probe: the backend has no repository-existence notion; an absent
/// repository has always listed as empty. Also used by any backend without
/// a repository-existence concept.
pub(crate) struct AlwaysExistsRepoProbe;

#[async_trait]
impl TagRepoProbe for AlwaysExistsRepoProbe {
    async fn repo_exists(&self, _repo: &str) -> Result<bool, StorageError> {
        Ok(true)
    }
}

/// Structural validation shared by repository names and tag references
/// (moved verbatim from the retired `fs::tag_read` seam; also reused by
/// non-tag FS modules for repository/uuid components).
pub(crate) fn validate_path_component(
    component: &str,
    field_name: &str,
) -> Result<(), StorageError> {
    if component.is_empty() {
        return Err(StorageError::InvalidRepoName(format!(
            "{field_name} cannot be empty"
        )));
    }
    if component.starts_with('/') || component.ends_with('/') {
        return Err(StorageError::InvalidRepoName(format!(
            "{field_name} cannot have leading or trailing slashes"
        )));
    }
    if component.contains('\\') {
        return Err(StorageError::InvalidRepoName(format!(
            "{field_name} cannot contain backslashes"
        )));
    }
    if component.contains(|c: char| c == '\0' || c.is_ascii_control()) {
        return Err(StorageError::InvalidRepoName(format!(
            "{field_name} cannot contain NUL bytes or control characters"
        )));
    }

    for segment in component.split('/') {
        if segment.is_empty() {
            return Err(StorageError::InvalidRepoName(format!(
                "{field_name} cannot contain empty segments (repeated slashes)"
            )));
        }
        if segment == "." {
            return Err(StorageError::InvalidRepoName(format!(
                "{field_name} cannot contain '.' segments"
            )));
        }
        if segment == ".." {
            return Err(StorageError::InvalidRepoName(format!(
                "{field_name} cannot contain '..' segments (path traversal attempt)"
            )));
        }
    }
    Ok(())
}

/// THE tag-domain key mapping: `(repository, tag)` →
/// `repos/<repository>/tags/<tag>` (identical to the accepted physical
/// layout of both backends — the FS adapter roots at the storage root and
/// the S3 adapter roots at the configured bucket prefix, so the physical
/// location/key of every tag is byte-for-byte unchanged).
///
/// Validation is the retired seams' shared structural contract; nested
/// (slash-separated) tags remain READABLE for layout compatibility, while
/// mutations additionally require a single-segment leaf (see
/// [`tag_mutation_leaf`]). Strict OCI tag grammar stays at the HTTP layer.
pub(crate) fn tag_key(repo: &str, tag: &str) -> Result<ObjectKey, StorageError> {
    validate_path_component(repo, "repository name")?;
    validate_path_component(tag, "tag name")?;

    let key_str = format!("repos/{repo}/tags/{tag}");
    ObjectKey::parse(&key_str).map_err(|e| StorageError::InvalidRepoName(e.to_string()))
}

/// Listing prefix mapping: `repos/<repository>/tags`.
fn tags_dir_key(repo: &str) -> Result<ObjectKey, StorageError> {
    validate_path_component(repo, "repository name")?;
    let key_str = format!("repos/{repo}/tags");
    ObjectKey::parse(&key_str).map_err(|e| StorageError::InvalidRepoName(e.to_string()))
}

/// Mutations address exactly one directory leaf / one direct-child object:
/// a multi-segment tag is rejected with the retired FS mutation contract's
/// message. (The old S3 backend interpolated slashed tags into nested keys;
/// converged on the stricter FS rule — nested keys under `tags/` are
/// structural non-tag entries per the accepted listing contract.)
fn tag_mutation_leaf(tag: &str) -> Result<(), StorageError> {
    validate_path_component(tag, "tag name")?;
    if tag.contains('/') {
        return Err(StorageError::InvalidRepoName(
            "tag name cannot span path components".to_string(),
        ));
    }
    Ok(())
}

/// The registry's externally visible tag version token: SHA-256 hex of the
/// exact raw payload bytes (never a reparsed/reformatted digest, never a
/// backend version token).
pub(crate) fn registry_tag_version(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// The exact bytes the registry writes for a tag: `{digest}\n`.
fn tag_payload(digest: &Digest) -> bytes::Bytes {
    bytes::Bytes::from(format!("{}\n", digest.as_str()).into_bytes())
}

/// Mutation-side payload inspection: lossy UTF-8, trim, parse; a corrupt
/// payload is `None` (treated as absent by mutation policy, the accepted FS
/// behavior).
fn parse_tag_bytes_lossy(bytes: &[u8]) -> Option<Digest> {
    let s = String::from_utf8_lossy(bytes);
    Digest::parse(s.trim()).ok()
}

/// ONE common translation of generic store failures into the registry error
/// taxonomy for tag operations. Absence never reaches this function (it is
/// structural in the [`ObjectStore`] contract); conditional outcomes are
/// interpreted per-operation before translation.
///
/// `TooLarge` keeps the accepted drain-overflow contract (`CorruptData`
/// with the historical message); adapter enumeration-limit exhaustion
/// arrives as `Backend` and keeps the historical `Backend` kind.
fn translate_store_error(err: StoreError, what: &str) -> StorageError {
    match err {
        StoreError::TooLarge { limit } => StorageError::corrupt_data(format!(
            "tag payload stream length exceeds limit of {limit} bytes"
        )),
        StoreError::PermissionDenied { message, .. } => {
            StorageError::permission_denied(format!("{what}: {message}"))
        }
        StoreError::Corrupt { message } => StorageError::corrupt_data(format!("{what}: {message}")),
        StoreError::InvalidInput { message } => {
            StorageError::internal_invariant(format!("{what}: {message}"))
        }
        StoreError::Backend { .. } => {
            // RESTORED (Phase 4 reconciliation of an unnoticed Phase 3 row):
            // the filesystem backend historically classified ENOSPC as
            // InsufficientStorage (HTTP 507); detect it structurally from
            // the preserved io::Error source chain.
            if crate::storage::store_common::store_error_is_storage_full(&err) {
                return StorageError::InsufficientStorage;
            }
            let StoreError::Backend { message, .. } = err else {
                unreachable!()
            };
            StorageError::backend(format!("{what}: {message}"))
        }
    }
}

/// Resolves a tag to its target [`Digest`].
///
/// Frozen contract (both retired backends agreed except where noted):
/// - absent object → [`StorageError::NotFound`];
/// - invalid UTF-8 → `CorruptData` (converged; old FS kind was `Io`);
/// - whitespace trimmed before parsing;
/// - empty/malformed digest text → [`StorageError::NotFound`];
/// - oversized payload → drain-overflow `CorruptData`.
pub(crate) async fn resolve_tag(
    store: &dyn ObjectStore,
    cfg: &TagDomainConfig,
    repo: &str,
    tag: &str,
) -> Result<Digest, StorageError> {
    let key = tag_key(repo, tag)?;
    let read = store
        .read(&key, cfg.max_payload_bytes)
        .await
        .map_err(|e| translate_store_error(e, "tag read"))?;
    let Some(read) = read else {
        return Err(StorageError::NotFound);
    };
    let s = std::str::from_utf8(&read.bytes).map_err(|e| {
        StorageError::corrupt_data(format!("invalid utf-8 sequence in tag file {key}: {e}"))
    })?;
    Digest::parse(s.trim()).map_err(|_| StorageError::NotFound)
}

/// Retrieves a tag target [`Digest`] plus the registry version token.
///
/// Frozen contract:
/// - absent object → `Ok(None)`;
/// - lossy UTF-8 decode, trim, parse; empty/malformed/replacement-character
///   text → `CorruptData` (`corrupt tag {tag}: {e}` — both retired backends
///   used this exact shape);
/// - version = SHA-256 hex of the exact raw bytes (converged; old S3
///   returned the backend ETag — tokens are never client-supplied and
///   journal-persisted snapshots degrade to recovery's fresh-read sweep).
pub(crate) async fn get_tag_with_version(
    store: &dyn ObjectStore,
    cfg: &TagDomainConfig,
    repo: &str,
    tag: &str,
) -> Result<Option<(Digest, String)>, StorageError> {
    let key = tag_key(repo, tag)?;
    let read = store
        .read(&key, cfg.max_payload_bytes)
        .await
        .map_err(|e| translate_store_error(e, "tag read"))?;
    let Some(read) = read else {
        return Ok(None);
    };
    let s = String::from_utf8_lossy(&read.bytes);
    let digest = Digest::parse(s.trim())
        .map_err(|e| StorageError::corrupt_data(format!("corrupt tag {tag}: {e}")))?;
    Ok(Some((digest, registry_tag_version(&read.bytes))))
}

/// Applies a tag mutation under `policy`, composing atomic [`ObjectStore`]
/// primitives (no advisory locks, no observe-then-unconditional conditional
/// sequences):
///
/// - the same-digest short-circuit runs BEFORE policy rejection: an existing
///   equal target returns [`TagMutation::Unchanged`] without a write (this
///   also keeps backend version tokens stable for identical content);
/// - `CreateOnly` on an absent tag uses `write_if_absent` — concurrent
///   creators have exactly one semantic winner; losers re-observe and report
///   `Unchanged` (same digest) or [`StorageError::TagAlreadyExists`];
/// - `CreateOnly` on a CORRUPT existing tag replaces it guarded by the
///   backend version observed with those corrupt bytes (`replace_if_version`
///   can never clobber a concurrent valid write);
/// - `Replace` publishes unconditionally (atomic below the boundary) and
///   reports `Created`/`Replaced { previous }` from its pre-write
///   observation;
/// - all writes request [`Durability::Durable`] — the FS backend's accepted
///   contained durable atomic publication; S3 satisfies both strengths with
///   one acknowledged PUT.
pub(crate) async fn mutate_tag(
    store: &dyn ObjectStore,
    cfg: &TagDomainConfig,
    repo: &str,
    tag: &str,
    digest: &Digest,
    policy: TagMutationPolicy,
) -> Result<TagMutation, StorageError> {
    tag_mutation_leaf(tag)?;
    let key = tag_key(repo, tag)?;
    let body = tag_payload(digest);

    for _ in 0..CREATE_ONLY_MAX_ATTEMPTS {
        let observed = store
            .read_with_version(&key, cfg.max_payload_bytes)
            .await
            .map_err(|e| translate_store_error(e, "tag mutation inspection"))?;

        match observed {
            Some(vr) => {
                let existing = parse_tag_bytes_lossy(&vr.bytes);
                if let Some(ref prev) = existing {
                    if prev == digest {
                        return Ok(TagMutation::Unchanged);
                    }
                }
                match policy {
                    TagMutationPolicy::CreateOnly => match existing {
                        Some(_) => return Err(StorageError::TagAlreadyExists),
                        None => {
                            // Corrupt existing tag: treated as absent (the
                            // accepted FS contract), but replaced only if the
                            // observed generation is still current.
                            match store
                                .replace_if_version(
                                    &key,
                                    &vr.version,
                                    body.clone(),
                                    Durability::Durable,
                                )
                                .await
                                .map_err(|e| translate_store_error(e, "tag publication"))?
                            {
                                ReplaceOutcome::Replaced(_) => return Ok(TagMutation::Created),
                                ReplaceOutcome::Absent
                                | ReplaceOutcome::PreconditionFailed { .. } => continue,
                            }
                        }
                    },
                    TagMutationPolicy::Replace => {
                        store
                            .write(&key, body, Durability::Durable)
                            .await
                            .map_err(|e| translate_store_error(e, "tag publication"))?;
                        return Ok(match existing {
                            Some(prev) => TagMutation::Replaced { previous: prev },
                            None => TagMutation::Created,
                        });
                    }
                }
            }
            None => match policy {
                TagMutationPolicy::CreateOnly => {
                    match store
                        .write_if_absent(&key, body.clone(), Durability::Durable)
                        .await
                        .map_err(|e| translate_store_error(e, "tag publication"))?
                    {
                        CreateOutcome::Created(_) => return Ok(TagMutation::Created),
                        // Lost a creation race: re-observe to distinguish
                        // Unchanged (same digest) from TagAlreadyExists.
                        CreateOutcome::AlreadyExists { .. } => continue,
                    }
                }
                TagMutationPolicy::Replace => {
                    store
                        .write(&key, body, Durability::Durable)
                        .await
                        .map_err(|e| translate_store_error(e, "tag publication"))?;
                    return Ok(TagMutation::Created);
                }
            },
        }
    }
    // Only reachable for CreateOnly under sustained racing mutation of the
    // same tag: a competing creator exists.
    Err(StorageError::TagAlreadyExists)
}

/// Unconditional tag deletion.
///
/// Frozen contract (the retired FS backend's, preserved): present →
/// `Ok(())` with immediate namespace mutation (P1 delete-durability policy:
/// no new crash-persistence promise); absent → [`StorageError::NotFound`].
/// The generic `delete` primitive deliberately makes no prior-existence
/// claim, so absence is distinguished by a preceding `head` observation;
/// the head→delete window is a benign race (production callers are
/// best-effort journal recovery that ignores the result). Old S3 returned
/// `Ok(())` for absent tags — converged on the FS contract.
pub(crate) async fn delete_tag(
    store: &dyn ObjectStore,
    repo: &str,
    tag: &str,
) -> Result<(), StorageError> {
    let key = tag_key(repo, tag)?;
    let observed = store
        .head(&key)
        .await
        .map_err(|e| translate_store_error(e, "tag inspection"))?;
    if observed.is_none() {
        return Err(StorageError::NotFound);
    }
    store
        .delete(&key)
        .await
        .map_err(|e| translate_store_error(e, "tag deletion"))
}

/// Test-only deterministic interposition seam: invoked between the registry
/// version-precondition check and the backend conditional delete, with
/// `(repo, tag)`. Lets regressions interpose a replacement in exactly the
/// window the backend token protects, on BOTH backends, and prove the
/// replacement survives with a truthful precondition failure.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::{Arc, Mutex};

    type Hook = Arc<dyn Fn(&str, &str) + Send + Sync>;
    static COND_DELETE_BOUNDARY: Mutex<Option<Hook>> = Mutex::new(None);

    pub(crate) fn set_conditional_delete_boundary<F>(f: F)
    where
        F: Fn(&str, &str) + Send + Sync + 'static,
    {
        *COND_DELETE_BOUNDARY.lock().unwrap() = Some(Arc::new(f));
    }

    pub(crate) fn clear_conditional_delete_boundary() {
        *COND_DELETE_BOUNDARY.lock().unwrap() = None;
    }

    pub(crate) fn fire_conditional_delete_boundary(repo: &str, tag: &str) {
        let hook = COND_DELETE_BOUNDARY.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(repo, tag);
        }
    }

    static CLEANUP_BOUNDARY: Mutex<Option<Hook>> = Mutex::new(None);

    /// Interposition seam between the cleanup scan's matching inspection and
    /// its version-conditional best-effort delete, with `(repo, tag)`.
    pub(crate) fn set_cleanup_boundary<F>(f: F)
    where
        F: Fn(&str, &str) + Send + Sync + 'static,
    {
        *CLEANUP_BOUNDARY.lock().unwrap() = Some(Arc::new(f));
    }

    pub(crate) fn clear_cleanup_boundary() {
        *CLEANUP_BOUNDARY.lock().unwrap() = None;
    }

    pub(crate) fn fire_cleanup_boundary(repo: &str, tag: &str) {
        let hook = CLEANUP_BOUNDARY.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook(repo, tag);
        }
    }
}

/// Conditional tag deletion — the registry version precondition composed
/// over `read_with_version` + `delete_if_version` (the accepted Phase 3
/// shape):
///
/// 1. one observation yields raw bytes AND the backend-private
///    [`naust_storage_core::object_store::ObjectVersion`] of the same generation;
/// 2. the registry computes its raw-byte SHA-256 token from those bytes;
/// 3. a caller mismatch → `PreconditionFailed { current_version }` (no
///    delete is attempted);
/// 4. a match → `delete_if_version` with the backend token: a replacement
///    that lands between observation and delete keeps the replacement and
///    reports `PreconditionFailed` (current registry version re-read
///    best-effort) — a stale registry token can NEVER delete a replacement;
/// 5. `expected_version == None` → existence-gated unconditional delete
///    (both retired backends' contract).
///
/// Backend tokens never escape this function.
pub(crate) async fn delete_tag_conditional(
    store: &dyn ObjectStore,
    cfg: &TagDomainConfig,
    repo: &str,
    tag: &str,
    expected_version: Option<&str>,
) -> Result<ConditionalDeleteResult, StorageError> {
    let key = tag_key(repo, tag)?;
    let observed = store
        .read_with_version(&key, cfg.max_payload_bytes)
        .await
        .map_err(|e| translate_store_error(e, "tag read"))?;
    let Some(vr) = observed else {
        return Ok(ConditionalDeleteResult::NotFound);
    };

    if let Some(expected) = expected_version {
        let current_version = registry_tag_version(&vr.bytes);
        if current_version != expected {
            return Ok(ConditionalDeleteResult::PreconditionFailed {
                current_version: Some(current_version),
            });
        }
        #[cfg(test)]
        test_hooks::fire_conditional_delete_boundary(repo, tag);
        match store
            .delete_if_version(&key, &vr.version)
            .await
            .map_err(|e| translate_store_error(e, "tag deletion"))?
        {
            ConditionalDeleteOutcome::Deleted => Ok(ConditionalDeleteResult::Deleted),
            // Vanished between observation and delete: nothing was deleted
            // by this call and the tag is gone — truthful NotFound.
            ConditionalDeleteOutcome::Absent => Ok(ConditionalDeleteResult::NotFound),
            ConditionalDeleteOutcome::PreconditionFailed { .. } => {
                // Replaced between observation and delete. The replacement
                // survives; report the CURRENT registry version best-effort
                // (never the backend token).
                let current_version = match store.read(&key, cfg.max_payload_bytes).await {
                    Ok(Some(read)) => Some(registry_tag_version(&read.bytes)),
                    _ => None,
                };
                Ok(ConditionalDeleteResult::PreconditionFailed { current_version })
            }
        }
    } else {
        store
            .delete(&key)
            .await
            .map_err(|e| translate_store_error(e, "tag deletion"))?;
        Ok(ConditionalDeleteResult::Deleted)
    }
}

/// Bounded collection of tag leaf names via generic pagination.
///
/// Registry-domain filtering: dot-prefixed leaves are non-tag entries
/// (legacy FS bookkeeping such as `.lock.<tag>`/`.tmp.*` artifacts remain
/// protected; the retired FS listing skipped them, and the accepted S3
/// listing contract classifies them with the other structural non-tag
/// shapes). Structural filtering (non-regular entries, nested keys, names
/// outside the generic grammar) already happened below the boundary.
///
/// The collection is bounded by `cfg.max_listing_entries` observed rows;
/// exhaustion is a truthful `Backend` error, mirroring the retired
/// directory-enumeration-limit contract — an internal bound is never
/// evidence of end-of-namespace.
async fn collect_tag_leaves(
    store: &dyn ObjectStore,
    _cfg: &TagDomainConfig,
    repo: &str,
) -> Result<Vec<String>, StorageError> {
    let prefix = tags_dir_key(repo)?;
    let page_size = NonZeroUsize::new(LIST_PAGE_SIZE).expect("nonzero page size");
    let mut leaves: Vec<String> = Vec::new();
    let mut token = None;
    loop {
        let page = store
            .list_page(Some(&prefix), token.as_ref(), page_size)
            .await
            .map_err(|e| translate_store_error(e, "tag listing"))?;
        for row in page.objects {
            if row.leaf.starts_with('.') {
                continue;
            }
            leaves.push(row.leaf);
        }
        match page.next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    leaves.sort_unstable();
    Ok(leaves)
}

/// Name-only tag listing (`list_tags`).
///
/// Frozen contract: names only, no payload reads or digest validation;
/// lexically sorted. An empty result consults the backend's
/// [`TagRepoProbe`]: a missing repository is [`StorageError::NotFound`]
/// where the backend models repository existence (FS), and an empty list
/// where it does not (S3) — each backend's historical external behavior.
pub(crate) async fn list_tags(
    store: &dyn ObjectStore,
    cfg: &TagDomainConfig,
    probe: &dyn TagRepoProbe,
    repo: &str,
) -> Result<Vec<String>, StorageError> {
    let leaves = collect_tag_leaves(store, cfg, repo).await?;
    if leaves.is_empty() && !probe.repo_exists(repo).await? {
        return Err(StorageError::NotFound);
    }
    Ok(leaves)
}

/// Digest-bearing paginated tag listing (`list_tags_page`).
///
/// Frozen logical contract (identical on both retired backends after the
/// accepted S3 listing closure):
/// - collect ALL candidate names (bounded), then read each payload bounded;
/// - a candidate that vanished between listing and read is omitted;
/// - invalid UTF-8 payload fails the page closed (`CorruptData`, converged
///   kind — old FS used `Io` with the same message);
/// - empty/malformed digest text is silently omitted;
/// - oversized payload → drain-overflow `CorruptData`;
/// - in-memory lexical sort; continuation token = last returned tag name
///   with strictly-after resume semantics (a deleted token still resumes at
///   the correct position); `page_limit == 0` → empty page, no payload
///   reads; missing repository → empty terminal page.
///
/// The page is sliced AFTER filtering, so a filtered candidate can never
/// silently shorten the logical page, and the collection bound errors
/// truthfully rather than masquerading as end-of-tags.
pub(crate) async fn list_tags_page(
    store: &dyn ObjectStore,
    cfg: &TagDomainConfig,
    repo: &str,
    continuation_token: Option<&str>,
    page_limit: usize,
) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
    if page_limit == 0 {
        return Ok((Vec::new(), None));
    }
    let prefix = tags_dir_key(repo)?;

    let mut tags_with_digest: Vec<(String, Digest)> = Vec::with_capacity(page_limit.min(1024));
    let mut after_token = continuation_token.map(adapter::page_token);
    let mut next_token: Option<String> = None;

    let batch_size = NonZeroUsize::new(page_limit.saturating_add(16).clamp(32, 1000))
        .expect("nonzero batch size");

    'outer: loop {
        let page = store
            .list_page(Some(&prefix), after_token.as_ref(), batch_size)
            .await
            .map_err(|e| translate_store_error(e, "tag listing"))?;

        if page.objects.is_empty() {
            break 'outer;
        }

        let total_in_page = page.objects.len();
        let has_next_page = page.next.is_some();

        for (idx, row) in page.objects.into_iter().enumerate() {
            if row.leaf.starts_with('.') {
                continue;
            }

            let key = tag_key(repo, &row.leaf)?;
            let read = match store.read(&key, cfg.max_payload_bytes).await {
                Ok(Some(r)) => r,
                Ok(None) => continue, // Benign race: vanished tag between list and read
                Err(e) => return Err(translate_store_error(e, "tag listing payload read")),
            };

            let s = std::str::from_utf8(&read.bytes).map_err(|err| {
                StorageError::corrupt_data(format!(
                    "invalid UTF-8 in tag payload {}: {err}",
                    row.leaf
                ))
            })?;

            if let Ok(digest) = Digest::parse(s.trim()) {
                tags_with_digest.push((row.leaf, digest));
                if tags_with_digest.len() == page_limit {
                    let has_more_in_batch = idx + 1 < total_in_page;
                    if has_more_in_batch || has_next_page {
                        next_token = tags_with_digest.last().map(|(t, _)| t.clone());
                    }
                    break 'outer;
                }
            }
        }

        if let Some(next) = page.next {
            after_token = Some(next);
        } else {
            break 'outer;
        }
    }

    Ok((tags_with_digest, next_token))
}

/// Manifest-delete tag cleanup: remove every tag whose trimmed payload
/// equals `digest_str` (exact string equality, never a reparsed digest).
pub(crate) async fn delete_manifest_tag_cleanup(
    store: &dyn ObjectStore,
    cfg: &TagDomainConfig,
    repo: &str,
    digest_str: &str,
) -> Result<(), StorageError> {
    let prefix = tags_dir_key(repo)?;
    let page_size = NonZeroUsize::new(LIST_PAGE_SIZE).expect("nonzero page size");
    let mut token = None;
    loop {
        let page = store
            .list_page(Some(&prefix), token.as_ref(), page_size)
            .await
            .map_err(|e| translate_store_error(e, "tag cleanup listing"))?;
        for row in page.objects {
            if row.leaf.starts_with('.') {
                continue;
            }
            let key = tag_key(repo, &row.leaf)?;
            let read = match store.read_with_version(&key, cfg.max_payload_bytes).await {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e) => return Err(translate_store_error(e, "tag cleanup read")),
            };
            let content = match std::str::from_utf8(&read.bytes) {
                Ok(s) => s,
                Err(err) => {
                    return Err(StorageError::corrupt_data(format!(
                        "invalid UTF-8 in tag payload {}: {err}",
                        row.leaf
                    )));
                }
            };
            if content.trim() == digest_str {
                #[cfg(test)]
                test_hooks::fire_cleanup_boundary(repo, &row.leaf);
                let _ = store.delete_if_version(&key, &read.version).await;
            }
        }
        match page.next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    Ok(())
}

/// Transitional wiring container: the backend-neutral handle each storage
/// backend exposes for its migrated tag family.
#[derive(Clone)]
pub(crate) struct TagDomain {
    store: Arc<dyn ObjectStore>,
    cfg: TagDomainConfig,
    probe: Arc<dyn TagRepoProbe>,
}

impl std::fmt::Debug for TagDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TagDomain").field("cfg", &self.cfg).finish()
    }
}

impl TagDomain {
    pub(crate) fn new(
        store: Arc<dyn ObjectStore>,
        cfg: TagDomainConfig,
        probe: Arc<dyn TagRepoProbe>,
    ) -> Self {
        Self { store, cfg, probe }
    }

    pub(crate) async fn resolve_tag(&self, repo: &str, tag: &str) -> Result<Digest, StorageError> {
        resolve_tag(self.store.as_ref(), &self.cfg, repo, tag).await
    }

    pub(crate) async fn get_tag_with_version(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<Option<(Digest, String)>, StorageError> {
        get_tag_with_version(self.store.as_ref(), &self.cfg, repo, tag).await
    }

    pub(crate) async fn mutate_tag(
        &self,
        repo: &str,
        tag: &str,
        digest: &Digest,
        policy: TagMutationPolicy,
    ) -> Result<TagMutation, StorageError> {
        mutate_tag(self.store.as_ref(), &self.cfg, repo, tag, digest, policy).await
    }

    pub(crate) async fn delete_tag(&self, repo: &str, tag: &str) -> Result<(), StorageError> {
        delete_tag(self.store.as_ref(), repo, tag).await
    }

    pub(crate) async fn delete_tag_conditional(
        &self,
        repo: &str,
        tag: &str,
        expected_version: Option<&str>,
    ) -> Result<ConditionalDeleteResult, StorageError> {
        delete_tag_conditional(self.store.as_ref(), &self.cfg, repo, tag, expected_version).await
    }

    pub(crate) async fn list_tags(&self, repo: &str) -> Result<Vec<String>, StorageError> {
        list_tags(self.store.as_ref(), &self.cfg, self.probe.as_ref(), repo).await
    }

    pub(crate) async fn list_tags_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
        list_tags_page(
            self.store.as_ref(),
            &self.cfg,
            repo,
            continuation_token,
            page_limit,
        )
        .await
    }

    pub(crate) async fn delete_manifest_tag_cleanup(
        &self,
        repo: &str,
        digest_str: &str,
    ) -> Result<(), StorageError> {
        delete_manifest_tag_cleanup(self.store.as_ref(), &self.cfg, repo, digest_str).await
    }
}

#[cfg(test)]
#[path = "tag_domain_tests.rs"]
mod tests;
