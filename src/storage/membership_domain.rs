//! Shared registry membership-domain implementation over the backend-neutral
//! [`ObjectStore`] contract (STORAGE-LAYER-MIGRATION Phase 6).
//!
//! This is the ONE registry implementation of the membership-record POINT
//! operations — the five operations addressing exactly one record at a known
//! key: `get_repo_blob_membership`, `link_repo_blob`,
//! `set_membership_candidate`, `clear_membership_candidate`,
//! `unlink_repo_blob`. It owns:
//! - the `(repository, digest)` → [`ObjectKey`] mapping
//!   (`repo-memberships/by-repo/<base64url(repo)>/<algo>/<hex>.json`, the
//!   accepted physical layout of both backends, via the frozen
//!   `repo_membership` codec);
//! - registry identifier validation (`CanonicalRepoName::parse` →
//!   `InvalidRepoName` before any backend access — the registry validates
//!   the DOMAIN identifier; `ObjectKey` merely re-validates the storage key
//!   the codec composes);
//! - the frozen record payload contract (bare compact snake_case
//!   `RepoBlobMembershipRecord` JSON; `state` defaults to `Active` on read;
//!   unknown fields tolerated);
//! - replacement-safe conditional mutation over the store's primitives.
//!
//! # Deliberately NOT in this module (Phase 6 scoping, see the evidence docs)
//! - The multi-level tree ENUMERATION operations
//!   (`list_repo_blob_memberships_page`, `list_all_repo_blob_memberships_page`,
//!   `count_repo_blob_memberships`): the membership namespace is a
//!   three-level tree and the accepted `ObjectStore::list_page` returns only
//!   DIRECT-CHILD OBJECTS of a prefix (no directory/common-prefix rows), so
//!   the repo/algo levels cannot be discovered through the contract. They
//!   remain on the existing per-backend seams, unchanged.
//! - The `meta/` readiness marker and migration checkpoint (migration-
//!   protocol control state outside the record namespace).
//! - The upload-family BLOCKING commit writer (`fs::write_membership_sync`),
//!   which persists the same frozen layout inside the upload commit
//!   transaction (membership durable BEFORE the receipt — upload-family
//!   policy, not migrated in Phase 6).
//!
//! # Preserved historical semantics
//! - absence is never an error: absent record → `Ok(None)` / `Ok(false)`;
//! - `link_repo_blob` is an UNCONDITIONAL durable last-writer-wins
//!   publication (both retired backends agreed; records are always created
//!   `Active` by every supported writer);
//! - candidate transitions: absent → `false`; already in the target state →
//!   `false` with NO rewrite (bytes untouched); a persisted transition →
//!   `true` with a DURABLE write; corrupt record fails closed with the
//!   byte-frozen `corrupt membership record: {e}` taxonomy; the `set` guard
//!   is state-only (an already-`Candidate` record keeps its FIRST
//!   `unreferenced_since` timestamp — the grace-aging input; the retired S3
//!   guard also compared timestamps, a branch the only production caller,
//!   the GC sweep, never reaches);
//! - `unlink_repo_blob` keeps the parity-closure existence contract:
//!   `true` ⇔ an existing record was actually removed; `false` = absent;
//!   the record is NEVER parsed (a corrupt record remains unlinkable);
//!   deletion failures propagate truthfully;
//! - a lost precondition on a candidate transition is `Ok(false)` (the
//!   pinned S3 contract — the caller records a skip), while a lost
//!   precondition on unlink is `Err(Internal{Conflict})` (the pinned
//!   parity-closure contract — never a false `true`, never a deleted
//!   replacement). Neither retries: precondition outcomes ARE the results
//!   consumed by the callers, so no retry budget exists to exhaust.
//!
//! # Replacement safety (the Phase 6 correctness upgrade for FS)
//! Every state-dependent mutation is conditional on the generation actually
//! read: transitions use `read_with_version` → `replace_if_version`, removal
//! uses `read_with_version` → `delete_if_version`. A stale observation can
//! never overwrite or delete a newer generation (the retired FS candidate
//! transitions were UNSYNCHRONIZED read-modify-write — the ADR-009-documented
//! cross-backend gap — and the retired FS unlink was an atomic syscall with
//! no observation window). In-process serialization remains the consistency
//! coordinator's contract ABOVE storage, exactly as before: the family has
//! never had, and does not gain, a storage-layer lock; no cross-process
//! serialization is claimed. No `ObjectVersion` internals are inspected and
//! no version token escapes this module.

use std::sync::Arc;

use storage_core::ObjectKey;
use storage_core::object_store::{
    ConditionalDeleteOutcome, Durability, ObjectStore, ReplaceOutcome, StoreError,
};

use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::repo_membership::{MembershipState, RepoBlobMembershipRecord};

use super::StorageError;

/// Membership records are metadata-sized; reads are deliberately unbounded
/// (both retired backends buffered complete records without a ceiling — the
/// documented pre-existing operational posture, preserved).
const MEMBERSHIP_READ_CEILING: u64 = u64::MAX;

/// Registry-domain identifier validation THEN storage-key composition:
/// `CanonicalRepoName` grammar failing closed with
/// [`StorageError::InvalidRepoName`] before any backend access (the frozen
/// contract of both retired backends), then the frozen codec relpath
/// `repo-memberships/by-repo/<b64url(repo)>/<algo>/<hex>.json` parsed as an
/// [`ObjectKey`] (the codec output is structurally valid by construction;
/// a parse failure is an internal invariant, never caller input).
pub(crate) fn membership_key(
    repo: &CanonicalRepoName,
    digest: &Digest,
) -> Result<ObjectKey, StorageError> {
    let rel = crate::storage::repo_membership::canonical_repo_membership_relpath(repo, digest);
    ObjectKey::parse(&rel).map_err(|e| {
        StorageError::internal_invariant(format!(
            "canonical membership relpath failed object-key validation: {e}"
        ))
    })
}

fn parse_repo(repo: &str) -> Result<CanonicalRepoName, StorageError> {
    CanonicalRepoName::parse(repo).map_err(|e| StorageError::InvalidRepoName(e.to_string()))
}

/// ONE common translation of generic store failures into the registry error
/// taxonomy for membership operations. Absence and precondition mismatches
/// never reach this function (they are structural outcomes in the
/// [`ObjectStore`] contract).
fn translate_store_error(err: StoreError, what: &str) -> StorageError {
    match err {
        // Unreachable for membership records (reads pass u64::MAX); kept
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

/// Retrieves the authoritative membership record if one exists.
///
/// Frozen contract: absent (any missing path component) → `Ok(None)`;
/// corrupt JSON → `CorruptData` carrying the record key
/// (`corrupt membership record in <key>: <serde error>` — the retired FS
/// read-seam shape; the retired S3 text differed only in wording).
pub(crate) async fn get_repo_blob_membership(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
) -> Result<Option<RepoBlobMembershipRecord>, StorageError> {
    let canonical = parse_repo(repo)?;
    let key = membership_key(&canonical, digest)?;
    let read = store
        .read(&key, MEMBERSHIP_READ_CEILING)
        .await
        .map_err(|e| translate_store_error(e, "membership read"))?;
    match read {
        None => Ok(None),
        Some(read) => {
            let record =
                serde_json::from_slice::<RepoBlobMembershipRecord>(&read.bytes).map_err(|e| {
                    StorageError::corrupt_data(format!(
                        "corrupt membership record in {}: {e}",
                        key.as_str()
                    ))
                })?;
            Ok(Some(record))
        }
    }
}

/// Creates or overwrites a membership record: the frozen UNCONDITIONAL
/// durable last-writer-wins publication (both retired backends agreed; the
/// record carries a typed `CanonicalRepoName`, so no re-validation happens).
pub(crate) async fn link_repo_blob(
    store: &dyn ObjectStore,
    record: &RepoBlobMembershipRecord,
) -> Result<(), StorageError> {
    let key = membership_key(&record.repo, &record.digest)?;
    let bytes = serde_json::to_vec(record)
        .map_err(|e| StorageError::serialization(format!("serialize membership: {e}")))?;
    store
        .write(&key, bytes.into(), Durability::Durable)
        .await
        .map_err(|e| translate_store_error(e, "membership write"))?;
    Ok(())
}

/// The shared conditional state-transition core for the two candidate
/// mutations. `mutate` inspects the parsed record and either declines
/// (`false`: already in the target state — NO write, the frozen no-op
/// contract) or applies the transition in place (`true`).
///
/// Outcome mapping (frozen consumed contract):
/// - absent record (or vanished before the conditional write) → `Ok(false)`;
/// - corrupt record → fail closed with the BYTE-FROZEN mutation-side
///   taxonomy `corrupt membership record: <serde error>`;
/// - persisted transition → `Ok(true)` (authoritative durable write);
/// - lost precondition (an independent writer replaced the generation after
///   the read) → `Ok(false)` — the pinned S3 contract; the GC-sweep caller
///   records a skip and re-observes on its next pass. A stale observation
///   can never overwrite the newer generation.
async fn transition_membership(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
    mutate: impl FnOnce(&mut RepoBlobMembershipRecord) -> bool,
) -> Result<bool, StorageError> {
    let canonical = parse_repo(repo)?;
    let key = membership_key(&canonical, digest)?;
    let read = store
        .read_with_version(&key, MEMBERSHIP_READ_CEILING)
        .await
        .map_err(|e| translate_store_error(e, "membership read"))?;
    let Some(read) = read else {
        return Ok(false);
    };
    let mut record = serde_json::from_slice::<RepoBlobMembershipRecord>(&read.bytes)
        .map_err(|e| StorageError::corrupt_data(format!("corrupt membership record: {e}")))?;
    if !mutate(&mut record) {
        return Ok(false);
    }
    let bytes = serde_json::to_vec(&record)
        .map_err(|e| StorageError::serialization(format!("serialize membership: {e}")))?;
    match store
        .replace_if_version(&key, &read.version, bytes.into(), Durability::Durable)
        .await
        .map_err(|e| translate_store_error(e, "membership write"))?
    {
        ReplaceOutcome::Replaced(_) => Ok(true),
        ReplaceOutcome::PreconditionFailed { .. } | ReplaceOutcome::Absent => Ok(false),
    }
}

/// Active → Candidate with an unreferenced timestamp.
///
/// Frozen guard (the retired FS shape, the only shape the sole production
/// caller — the GC sweep — can reach): an already-`Candidate` record is a
/// no-op that PRESERVES its first `unreferenced_since` timestamp, the
/// grace-aging input. (The retired S3 guard additionally compared the
/// timestamp and would have refreshed it — restarting the aging clock — on
/// a call the sweep never makes; converged per the Phase 6 matrix.)
pub(crate) async fn set_membership_candidate(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
    since_unix_secs: u64,
) -> Result<bool, StorageError> {
    transition_membership(store, repo, digest, |record| {
        if record.state == MembershipState::Candidate {
            return false;
        }
        record.state = MembershipState::Candidate;
        record.unreferenced_since_unix_secs = Some(since_unix_secs);
        true
    })
    .await
}

/// Candidate → Active, clearing the timestamp. The frozen guard (identical
/// on both retired backends) also normalizes an `Active` record carrying a
/// stale `unreferenced_since` timestamp.
pub(crate) async fn clear_membership_candidate(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
) -> Result<bool, StorageError> {
    transition_membership(store, repo, digest, |record| {
        if record.state == MembershipState::Active && record.unreferenced_since_unix_secs.is_none()
        {
            return false;
        }
        record.state = MembershipState::Active;
        record.unreferenced_since_unix_secs = None;
        true
    })
    .await
}

/// Removes an existing membership record, reporting whether one existed —
/// the parity-closure existence contract: `true` ⇔ the observed generation
/// was actually removed; `false` = absent (at the read, or vanished before
/// the conditional delete). The payload is NEVER parsed: a corrupt record
/// remains unlinkable, exactly as on both retired backends.
///
/// Race semantics (frozen from the accepted S3 parity closure, now shared):
/// the removal is conditional on the generation actually read, so a record
/// REPLACED between the observation and the delete is preserved
/// byte-for-byte and the operation fails closed with
/// `Internal{Conflict}` — never a false `true`, never a deleted
/// replacement, no retry (within the supported coordination model — every
/// membership mutation serialized by the consistency coordinator under the
/// exclusive deployment writer lock — the precondition cannot fail).
/// Deletion failures propagate truthfully; crash-persistence of the removal
/// follows the accepted P1 Option A policy (success = the immediate
/// namespace mutation; no new crash-persistence promise is acquired).
pub(crate) async fn unlink_repo_blob(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
) -> Result<bool, StorageError> {
    let canonical = parse_repo(repo)?;
    let key = membership_key(&canonical, digest)?;
    let read = store
        .read_with_version(&key, MEMBERSHIP_READ_CEILING)
        .await
        .map_err(|e| translate_store_error(e, "membership read"))?;
    let Some(read) = read else {
        return Ok(false);
    };
    match store
        .delete_if_version(&key, &read.version)
        .await
        .map_err(|e| translate_store_error(e, "membership unlink"))?
    {
        ConditionalDeleteOutcome::Deleted => Ok(true),
        ConditionalDeleteOutcome::Absent => Ok(false),
        ConditionalDeleteOutcome::PreconditionFailed { .. } => {
            Err(StorageError::conflict(format!(
                "membership record {} changed concurrently during unlink",
                key.as_str()
            )))
        }
    }
}

/// Transitional wiring container: the backend-neutral handle each storage
/// backend exposes for its migrated membership point operations. No locks
/// and no configuration: the family has never had a storage-layer lock
/// (serialization is the consistency coordinator's contract above storage)
/// and the point operations have no resource policy.
#[derive(Clone)]
pub(crate) struct MembershipDomain {
    store: Arc<dyn ObjectStore>,
}

impl std::fmt::Debug for MembershipDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipDomain").finish()
    }
}

impl MembershipDomain {
    pub(crate) fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    pub(crate) async fn get_repo_blob_membership(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<Option<RepoBlobMembershipRecord>, StorageError> {
        get_repo_blob_membership(self.store.as_ref(), repo, digest).await
    }

    pub(crate) async fn link_repo_blob(
        &self,
        record: &RepoBlobMembershipRecord,
    ) -> Result<(), StorageError> {
        link_repo_blob(self.store.as_ref(), record).await
    }

    pub(crate) async fn set_membership_candidate(
        &self,
        repo: &str,
        digest: &Digest,
        since_unix_secs: u64,
    ) -> Result<bool, StorageError> {
        set_membership_candidate(self.store.as_ref(), repo, digest, since_unix_secs).await
    }

    pub(crate) async fn clear_membership_candidate(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        clear_membership_candidate(self.store.as_ref(), repo, digest).await
    }

    pub(crate) async fn unlink_repo_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        unlink_repo_blob(self.store.as_ref(), repo, digest).await
    }
}

#[cfg(test)]
#[path = "membership_domain_tests.rs"]
mod tests;
