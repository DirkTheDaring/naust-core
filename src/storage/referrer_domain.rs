//! Shared registry referrer-domain implementation over the backend-neutral
//! [`ObjectStore`] contract (STORAGE-LAYER-MIGRATION Phase 5).
//!
//! This is the ONE registry implementation of referrer-index semantics. It
//! owns:
//! - the `(repository, subject)` → [`ObjectKey`] mapping
//!   (`repos/<repo>/referrers/<subject.hex()>.json` — the accepted physical
//!   layout of both backends: bare lowercase hex, `.json` suffix, no
//!   algorithm prefix, no sharding);
//! - the frozen payload contract: a bare compact JSON array of snake_case
//!   [`ReferrerDescriptor`] objects, insertion-ordered, never normalized;
//! - reads (absent index → empty list; parse failure → the preserved legacy
//!   `Internal{Io}` registry taxonomy carrying the verbatim serde message);
//! - mutations as REPLACEMENT-SAFE optimistic read-modify-write over the
//!   store's conditional primitives (`read_with_version` →
//!   `replace_if_version` / `write_if_absent` / `delete_if_version`) — a
//!   stale observed generation can never mutate or delete a newer one;
//! - the historical same-instance same-subject serialization (64-shard
//!   in-process mutex keyed `{repo}:{subject.hex()}`, now backend-neutral);
//! - the digest-sorted in-memory pagination of `list_referrers_page`
//!   (including its historical swallow-to-empty error contract).
//!
//! Filesystem containment and S3 request mechanics stay below the
//! [`ObjectStore`] boundary; OCI referrer POLICY above the stored index
//! (artifact-type filtering, `last`/`n` HTTP pagination, camelCase response
//! shape) stays with the application/HTTP callers.
//!
//! # Preserved historical semantics (both retired backends agreed)
//! - absent index (any missing path component) → `Ok(vec![])`, never
//!   `NotFound`;
//! - reads and mutation-side reads are UNBOUNDED (`u64::MAX` ceiling — the
//!   documented pre-existing operational limitation is preserved; no new
//!   resource policy is introduced for referrer indexes);
//! - a corrupt index FAILS CLOSED for reads and both mutations (nothing is
//!   overwritten or deleted through a payload the registry cannot parse);
//! - add dedups by descriptor `digest` string ONLY (existing metadata is
//!   never refreshed) and a duplicate add still rewrites the (unchanged)
//!   array, as before;
//! - new descriptors append at the tail; stored order is insertion order;
//! - remove matches `descriptor.digest != referrer.as_str()` (the canonical
//!   `algo:hex` form) and removes every match; removing nothing performs no
//!   write; removing the final descriptor DELETES the index object (an empty
//!   index is never persisted as `[]`), with backend failures of that
//!   removal swallowed (historical best-effort; the P1 Option A deletion
//!   policy acquires no new crash-persistence promise);
//! - non-empty index writes are authoritative durable publications
//!   ([`Durability::Durable`] — the accepted FS temp-fsync/rename/dir-fsync
//!   sequence; S3 = one acknowledged conditional PUT);
//! - `list_referrers_page` (no production caller; contract pinned by tests)
//!   sorts by raw `digest` string, resumes strictly after the token, and
//!   swallows every read failure into an empty terminal page.
//!
//! # Replacement-safe concurrency (the Phase 5 correctness upgrade)
//! The retired backends guarded the read-modify-write ONLY with the
//! in-process shard mutex; the S3 PUT was unconditional and the FS rewrite
//! relied on the retained authority, so an external/cross-process writer
//! could silently lose updates. The shared implementation keeps the
//! historical in-process serialization (so same-instance concurrent
//! mutations never contend on versions, exactly as before) and adds version
//! preconditions underneath: every rewrite is `replace_if_version` against
//! the generation actually read, creation is `write_if_absent`, and the
//! empty-index removal is `delete_if_version` — a replacement racing the
//! mutation survives, and the loser re-reads and retries within a BOUNDED
//! budget ([`MAX_CAS_ATTEMPTS`]). Exhaustion surfaces truthfully as a
//! `Backend`-kind internal error (publication propagates it; the deletion /
//! recovery cleanup paths swallow it exactly as they historically swallowed
//! every `remove_referrer` failure). No `ObjectVersion` internals are
//! inspected and no version token escapes this module.

use std::sync::Arc;

use storage_core::ObjectKey;
use storage_core::object_store::{
    ConditionalDeleteOutcome, CreateOutcome, Durability, ObjectStore, ReplaceOutcome, StoreError,
};

use crate::registry::digest::Digest;

use super::{ReferrerDescriptor, StorageError};

/// Same-subject mutation serialization shards (the historical in-process
/// scope and identity: 64 shards keyed `{repo}:{subject.hex()}`).
const REFERRER_SHARDS: usize = 64;

/// Bounded optimistic-concurrency retry budget for one mutation. In-process
/// same-subject mutations are serialized by the shard lock and never consume
/// retries; the budget only absorbs external/cross-process interference,
/// where the retired backends offered no guarantee at all (silent lost
/// updates). Exhaustion is a truthful error, never a silent lost update.
const MAX_CAS_ATTEMPTS: usize = 8;

/// Referrer index reads are deliberately unbounded: both retired backends
/// buffered complete index payloads without a ceiling (a documented
/// pre-existing operational limitation), and Phase 5 preserves that contract
/// rather than introducing a new externally visible resource policy.
const REFERRER_READ_CEILING: u64 = u64::MAX;

/// Constructs the relative [`ObjectKey`] for a subject's referrer index:
/// `repos/<repository>/referrers/<subject.hex()>.json` (moved verbatim from
/// the retired `fs::referrers_read` seam; identical to the retired S3 key
/// modulo the adapter's configured prefix).
///
/// Validation is the shared structural repository grammar
/// (`tag_domain::validate_path_component` + `ObjectKey` composition),
/// failing closed with [`StorageError::InvalidRepoName`] before any backend
/// access. Canonical OCI repository grammar remains a higher-layer concern.
pub(crate) fn referrers_key(repo: &str, subject: &Digest) -> Result<ObjectKey, StorageError> {
    crate::storage::tag_domain::validate_path_component(repo, "repository name")?;
    let key_str = format!("repos/{repo}/referrers/{}.json", subject.hex());
    ObjectKey::parse(&key_str).map_err(|e| StorageError::InvalidRepoName(e.to_string()))
}

/// Parses stored referrer-index bytes: a bare JSON array of snake_case
/// descriptors. Parse failures (malformed JSON, invalid UTF-8, empty file,
/// wrong top-level shape) map to the PRESERVED legacy registry taxonomy —
/// `StorageError::Internal { kind: Io }` carrying the verbatim serde message
/// (moved from the retired `fs::referrers_read::parse_referrers_bytes`; the
/// retired S3 path used the production-inert `CorruptData` kind, converged
/// per the Phase 5 semantic matrix).
pub(crate) fn parse_referrers_bytes(bytes: &[u8]) -> Result<Vec<ReferrerDescriptor>, StorageError> {
    serde_json::from_slice(bytes).map_err(|err| StorageError::io(err.to_string()))
}

/// ONE common translation of generic store failures into the registry error
/// taxonomy for referrer operations. Absence and precondition mismatches
/// never reach this function (they are structural outcomes in the
/// [`ObjectStore`] contract).
fn translate_store_error(err: StoreError, what: &str) -> StorageError {
    match err {
        // Unreachable for referrer indexes (reads pass u64::MAX); kept
        // truthful should a backend ever surface it.
        StoreError::TooLarge { limit } => StorageError::backend(format!(
            "{what}: payload exceeds the read ceiling of {limit} bytes"
        )),
        StoreError::PermissionDenied { message, .. } => {
            StorageError::permission_denied(format!("{what}: {message}"))
        }
        StoreError::Corrupt { message } => StorageError::corrupt_data(format!("{what}: {message}")),
        StoreError::InvalidInput { message } => {
            StorageError::internal_invariant(format!("{what}: {message}"))
        }
        StoreError::Backend { .. } => {
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

/// Truthful bounded-retry exhaustion: only reachable under sustained
/// external same-subject interference (the shard lock serializes in-process
/// mutations), where the retired backends silently lost updates instead.
fn contention_exhausted(what: &str, repo: &str, subject: &Digest) -> StorageError {
    StorageError::backend(format!(
        "{what} for {repo}/{} exceeded {MAX_CAS_ATTEMPTS} optimistic-concurrency attempts",
        subject.as_str()
    ))
}

/// The historical in-process same-subject mutation serialization, now
/// backend-neutral: 64 `tokio::sync::Mutex` shards keyed
/// `{repo}:{subject.hex()}` (the exact retired identity and scope on both
/// backends). Shared via `Arc` so every clone of a storage backend
/// serializes against the same shard set, exactly as before. No
/// cross-process claim is made — cross-process safety comes from the version
/// preconditions, not from this lock.
pub(crate) struct ReferrerLockShards {
    shards: Vec<tokio::sync::Mutex<()>>,
}

impl ReferrerLockShards {
    pub(crate) fn new() -> Self {
        let mut shards = Vec::with_capacity(REFERRER_SHARDS);
        for _ in 0..REFERRER_SHARDS {
            shards.push(tokio::sync::Mutex::new(()));
        }
        Self { shards }
    }

    fn shard(&self, repo: &str, subject: &Digest) -> &tokio::sync::Mutex<()> {
        let key = format!("{repo}:{}", subject.hex());
        let mut hasher = std::hash::DefaultHasher::new();
        std::hash::Hash::hash(&key, &mut hasher);
        let idx = std::hash::Hasher::finish(&hasher) as usize % self.shards.len();
        &self.shards[idx]
    }
}

impl std::fmt::Debug for ReferrerLockShards {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReferrerLockShards")
            .field("shards", &self.shards.len())
            .finish()
    }
}

/// Reads the complete referrer index for one subject.
///
/// Frozen contract: absent (any missing component) → `Ok(vec![])`; full
/// unbounded buffering; physical (insertion) order preserved without
/// sorting, deduplication, or normalization; parse failure → the preserved
/// legacy `Internal{Io}` taxonomy.
pub(crate) async fn list_referrers(
    store: &dyn ObjectStore,
    repo: &str,
    subject: &Digest,
) -> Result<Vec<ReferrerDescriptor>, StorageError> {
    let key = referrers_key(repo, subject)?;
    let read = store
        .read(&key, REFERRER_READ_CEILING)
        .await
        .map_err(|e| translate_store_error(e, "referrers read"))?;
    match read {
        None => Ok(Vec::new()),
        Some(read) => parse_referrers_bytes(&read.bytes),
    }
}

/// Digest-sorted in-memory pagination over one subject index (moved verbatim
/// from the byte-identical retired FS/S3 bodies; NO production caller — the
/// public query service paginates in the application layer).
///
/// Frozen contract, pinned by tests: EVERY read failure (corrupt index,
/// permission denied, backend fault) is swallowed into an empty terminal
/// page; sorting is by raw `digest` string; the continuation token is the
/// last returned digest and resumption is strictly-after (a vanished token
/// resumes at its insertion point).
pub(crate) async fn list_referrers_page(
    store: &dyn ObjectStore,
    repo: &str,
    subject: &Digest,
    continuation_token: Option<&str>,
    page_limit: usize,
) -> Result<(Vec<ReferrerDescriptor>, Option<String>), StorageError> {
    let mut refs = list_referrers(store, repo, subject)
        .await
        .unwrap_or_default();
    refs.sort_by(|a, b| a.digest.cmp(&b.digest));

    let start_idx = if let Some(token) = continuation_token {
        match refs.binary_search_by(|r| r.digest.as_str().cmp(token)) {
            Ok(idx) => idx + 1,
            Err(idx) => idx,
        }
    } else {
        0
    };

    let end_idx = start_idx.saturating_add(page_limit).min(refs.len());
    let page_slice = &refs[start_idx.min(refs.len())..end_idx];

    let next_token = if end_idx < refs.len() {
        page_slice.last().map(|r| r.digest.clone())
    } else {
        None
    };

    Ok((page_slice.to_vec(), next_token))
}

/// Registers one referrer descriptor under a subject.
///
/// Frozen policy: dedup by `digest` string only (existing metadata is never
/// refreshed); append at the tail; a duplicate add still rewrites the
/// (unchanged) array; corrupt index fails closed; serialization failure →
/// `Internal{Serialization}`; writes are authoritative durable publications.
///
/// Concurrency: shard-lock serialized in-process (historical), version-
/// conditional underneath (Phase 5) — absent index created with
/// `write_if_absent`, existing index rewritten with `replace_if_version`
/// against the generation actually read, bounded retry on interference.
async fn add_referrer(
    store: &dyn ObjectStore,
    locks: &ReferrerLockShards,
    repo: &str,
    subject: &Digest,
    descriptor: ReferrerDescriptor,
) -> Result<(), StorageError> {
    let key = referrers_key(repo, subject)?;
    let _lock = locks.shard(repo, subject).lock().await;

    for _ in 0..MAX_CAS_ATTEMPTS {
        let read = store
            .read_with_version(&key, REFERRER_READ_CEILING)
            .await
            .map_err(|e| translate_store_error(e, "referrers read"))?;
        match read {
            None => {
                let created = vec![descriptor.clone()];
                let bytes = serde_json::to_vec(&created)
                    .map_err(|err| StorageError::serialization(err.to_string()))?;
                match store
                    .write_if_absent(&key, bytes.into(), Durability::Durable)
                    .await
                    .map_err(|e| translate_store_error(e, "referrers write"))?
                {
                    CreateOutcome::Created(_) => return Ok(()),
                    // Lost the creation race: observe the winner and retry.
                    CreateOutcome::AlreadyExists { .. } => continue,
                }
            }
            Some(read) => {
                let mut existing = parse_referrers_bytes(&read.bytes)?;
                if !existing.iter().any(|d| d.digest == descriptor.digest) {
                    existing.push(descriptor.clone());
                }
                // A duplicate add still rewrites the (unchanged) array, as
                // before.
                let bytes = serde_json::to_vec(&existing)
                    .map_err(|err| StorageError::serialization(err.to_string()))?;
                match store
                    .replace_if_version(&key, &read.version, bytes.into(), Durability::Durable)
                    .await
                    .map_err(|e| translate_store_error(e, "referrers write"))?
                {
                    ReplaceOutcome::Replaced(_) => return Ok(()),
                    // The generation moved (replacement) or vanished
                    // (deletion) after the read; the newer state survives
                    // untouched — re-read and retry.
                    ReplaceOutcome::PreconditionFailed { .. } | ReplaceOutcome::Absent => continue,
                }
            }
        }
    }
    Err(contention_exhausted("referrer registration", repo, subject))
}

/// Removes every descriptor matching `referrer` (canonical `algo:hex` form)
/// from a subject's index.
///
/// Frozen policy: absent index or absent descriptor → `Ok(())` with no
/// write; corrupt index fails closed; survivors keep their order and are
/// durably rewritten; removing the final descriptor DELETES the index
/// object, with backend failures of that removal swallowed (historical
/// best-effort; P1 Option A — no new crash-persistence promise).
///
/// Concurrency: shard-lock serialized in-process (historical); the rewrite
/// is `replace_if_version` and the empty-index removal is
/// `delete_if_version` against the generation actually read (Phase 5) — a
/// stale observation can never mutate or delete a newer generation; the
/// loser re-reads and retries within the bounded budget.
async fn remove_referrer(
    store: &dyn ObjectStore,
    locks: &ReferrerLockShards,
    repo: &str,
    subject: &Digest,
    referrer: &Digest,
) -> Result<(), StorageError> {
    let key = referrers_key(repo, subject)?;
    let _lock = locks.shard(repo, subject).lock().await;

    for _ in 0..MAX_CAS_ATTEMPTS {
        let read = store
            .read_with_version(&key, REFERRER_READ_CEILING)
            .await
            .map_err(|e| translate_store_error(e, "referrers read"))?;
        let Some(read) = read else {
            // Absent index: nothing to remove, nothing is written.
            return Ok(());
        };
        let mut existing = parse_referrers_bytes(&read.bytes)?;
        let orig_len = existing.len();
        let referrer_str = referrer.as_str();
        existing.retain(|d| d.digest != referrer_str);
        if existing.len() == orig_len {
            // Absent descriptor: no write at all, as before.
            return Ok(());
        }

        if existing.is_empty() {
            match store.delete_if_version(&key, &read.version).await {
                Ok(ConditionalDeleteOutcome::Deleted) | Ok(ConditionalDeleteOutcome::Absent) => {
                    return Ok(());
                }
                // A newer generation replaced the one we read; it survives
                // untouched — re-read and re-decide.
                Ok(ConditionalDeleteOutcome::PreconditionFailed { .. }) => continue,
                // Historical best-effort empty-index removal: backend
                // failures are swallowed (P1 Option A), exactly as the
                // retired unlink/DeleteObject results were discarded.
                Err(_) => return Ok(()),
            }
        } else {
            let bytes = serde_json::to_vec(&existing)
                .map_err(|err| StorageError::serialization(err.to_string()))?;
            match store
                .replace_if_version(&key, &read.version, bytes.into(), Durability::Durable)
                .await
                .map_err(|e| translate_store_error(e, "referrers write"))?
            {
                ReplaceOutcome::Replaced(_) => return Ok(()),
                ReplaceOutcome::PreconditionFailed { .. } | ReplaceOutcome::Absent => continue,
            }
        }
    }
    Err(contention_exhausted("referrer removal", repo, subject))
}

/// Transitional wiring container: the backend-neutral handle each storage
/// backend exposes for its migrated referrer family. The lock shards are a
/// shared `Arc` so per-call construction (the S3 wiring pattern) still
/// serializes against one instance-wide shard set.
#[derive(Clone)]
pub(crate) struct ReferrerDomain {
    store: Arc<dyn ObjectStore>,
    locks: Arc<ReferrerLockShards>,
}

impl std::fmt::Debug for ReferrerDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReferrerDomain")
            .field("locks", &self.locks)
            .finish()
    }
}

impl ReferrerDomain {
    pub(crate) fn new(store: Arc<dyn ObjectStore>, locks: Arc<ReferrerLockShards>) -> Self {
        Self { store, locks }
    }

    pub(crate) async fn list_referrers(
        &self,
        repo: &str,
        subject: &Digest,
    ) -> Result<Vec<ReferrerDescriptor>, StorageError> {
        list_referrers(self.store.as_ref(), repo, subject).await
    }

    pub(crate) async fn list_referrers_page(
        &self,
        repo: &str,
        subject: &Digest,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<ReferrerDescriptor>, Option<String>), StorageError> {
        list_referrers_page(
            self.store.as_ref(),
            repo,
            subject,
            continuation_token,
            page_limit,
        )
        .await
    }

    pub(crate) async fn add_referrer(
        &self,
        repo: &str,
        subject: &Digest,
        descriptor: ReferrerDescriptor,
    ) -> Result<(), StorageError> {
        add_referrer(self.store.as_ref(), &self.locks, repo, subject, descriptor).await
    }

    pub(crate) async fn remove_referrer(
        &self,
        repo: &str,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<(), StorageError> {
        remove_referrer(self.store.as_ref(), &self.locks, repo, subject, referrer).await
    }
}

#[cfg(test)]
#[path = "referrer_domain_tests.rs"]
mod tests;
