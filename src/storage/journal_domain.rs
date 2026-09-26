//! Shared registry lifecycle-journal implementation over the backend-neutral
//! [`ObjectStore`] contract (STORAGE-LAYER-MIGRATION Phase 7).
//!
//! This is the ONE registry implementation of lifecycle-journal persistence:
//! three point operations on one exact key per repository,
//! `repos/<canonical repo>/meta/lifecycle_journal.json` (the accepted
//! physical layout of both backends; S3 under its configured root prefix).
//! The journal is AUTHORITATIVE recovery state — GC's pre-delete
//! revalidation treats its presence as protection for in-flight manifest
//! lifecycle operations, and every lifecycle mutation replays it first — but
//! the STORAGE layer moves opaque bytes only: parsing into
//! `LifecycleJournalRecord`, the repository-identity fail-closed check, the
//! lease-expiry policy, and the phase machine all remain registry policy in
//! `manifest_lifecycle` (above this boundary), exactly as before.
//!
//! # Preserved historical semantics (both retired backends agreed)
//! - repository grammar is `CanonicalRepoName` (→ `InvalidRepoName` before
//!   any backend access); the composed key is validated as an [`ObjectKey`]
//!   (failure = internal invariant, never caller input);
//! - reads are RAW-BYTE passthrough and UNBOUNDED (`u64::MAX` ceiling — the
//!   documented pre-existing "no approved journal ceiling" baseline, the
//!   same accepted device as the Phase 4 manifest reads); an EMPTY journal
//!   file is `Ok(Some(b""))`, never absence; genuine absence (any missing
//!   path component) is `Ok(None)`;
//! - read FAILURES never become absence — "an unreadable or corrupt journal
//!   must never present as 'no pending operation'" (permission/containment/
//!   backend failures propagate; a corrupt journal is preserved, never
//!   deleted or overwritten, and aborts the outer mutation at the caller);
//! - writes are UNCONDITIONAL durable publications
//!   ([`Durability::Durable`] — the accepted FS payload-fsync + atomic
//!   rename + directory-fsync sequence, all propagated; S3 = one
//!   acknowledged PUT). No generation condition is INVENTED: journal
//!   mutations are serialized ABOVE storage by the repository lease and the
//!   consistency coordinator (`acquire_coordination` + `check_lease`), the
//!   frozen contract of both retired backends;
//! - deletes are idempotent (absent → success) with the accepted P1-shape
//!   deletion durability: success guarantees the immediate namespace
//!   mutation; crash-persistence of the removal follows the adapter's
//!   accepted deletion policy (journal resurrection after a crash only makes
//!   GC more conservative and recovery re-run — the safe direction).
//!
//! # Reconciled divergence (Phase 7 semantic matrix)
//! The retired S3 delete discarded EVERY error (`let _ = delete_object`),
//! while the retired FS delete propagated failures and every production
//! caller `?`-propagates the result. The shared implementation reports
//! delete failures truthfully on both backends (the R row: the swallow
//! contradicted the shared caller contract; a lingering journal was always
//! safe but the silent success was untruthful).

use std::sync::Arc;

use bytes::Bytes;
use storage_core::ObjectKey;
use storage_core::object_store::{Durability, ObjectStore, StoreError};

use crate::registry::canonical_name::CanonicalRepoName;

use super::StorageError;

/// Journal reads are deliberately unbounded: both retired backends buffered
/// the complete journal without a ceiling (no approved journal limit
/// exists), and Phase 7 preserves that contract rather than introducing a
/// new externally visible resource policy.
const JOURNAL_READ_CEILING: u64 = u64::MAX;

/// Registry-domain identifier validation THEN storage-key composition:
/// `CanonicalRepoName` grammar failing closed with
/// [`StorageError::InvalidRepoName`] before any backend access, then the
/// frozen key `repos/<repo>/meta/lifecycle_journal.json` parsed as an
/// [`ObjectKey`] (structurally valid by construction; a parse failure is an
/// internal invariant, never caller input).
pub(crate) fn journal_key(repo: &str) -> Result<ObjectKey, StorageError> {
    let canonical =
        CanonicalRepoName::parse(repo).map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
    let key_str = format!("repos/{}/meta/lifecycle_journal.json", canonical.as_str());
    ObjectKey::parse(&key_str).map_err(|e| {
        StorageError::internal_invariant(format!("invalid journal key {key_str:?}: {e}"))
    })
}

/// ONE common translation of generic store failures into the registry error
/// taxonomy for journal operations. Absence never reaches this function (it
/// is structural in the [`ObjectStore`] contract), and no failure class is
/// ever converted into absence.
fn translate_store_error(err: StoreError, what: &str) -> StorageError {
    match err {
        // Unreachable for journals (reads pass u64::MAX); kept truthful
        // should a backend ever surface it.
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

/// Reads the raw journal bytes: absence → `Ok(None)`; an existing empty
/// journal → `Ok(Some(b""))`; failures propagate (never absence).
pub(crate) async fn read_lifecycle_journal(
    store: &dyn ObjectStore,
    repo: &str,
) -> Result<Option<Bytes>, StorageError> {
    let key = journal_key(repo)?;
    let read = store
        .read(&key, JOURNAL_READ_CEILING)
        .await
        .map_err(|e| translate_store_error(e, "lifecycle journal read"))?;
    Ok(read.map(|r| r.bytes))
}

/// Publishes the journal bytes: the frozen UNCONDITIONAL durable
/// last-writer-wins publication (serialization is the caller's repository
/// lease + coordinator contract, above storage).
pub(crate) async fn write_lifecycle_journal(
    store: &dyn ObjectStore,
    repo: &str,
    data: Bytes,
) -> Result<(), StorageError> {
    let key = journal_key(repo)?;
    store
        .write(&key, data, Durability::Durable)
        .await
        .map_err(|e| translate_store_error(e, "lifecycle journal write"))?;
    Ok(())
}

/// Removes the journal: idempotent (absent → success); failures propagate
/// truthfully on BOTH backends (the reconciled contract every production
/// caller already `?`-propagates); P1-shape deletion durability.
pub(crate) async fn delete_lifecycle_journal(
    store: &dyn ObjectStore,
    repo: &str,
) -> Result<(), StorageError> {
    let key = journal_key(repo)?;
    store
        .delete(&key)
        .await
        .map_err(|e| translate_store_error(e, "lifecycle journal delete"))?;
    Ok(())
}

/// Transitional wiring container: the backend-neutral handle each storage
/// backend exposes for its migrated lifecycle-journal family. No locks and
/// no configuration: the family has never had a storage-layer lock or a
/// resource policy.
#[derive(Clone)]
pub(crate) struct JournalDomain {
    store: Arc<dyn ObjectStore>,
}

impl std::fmt::Debug for JournalDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalDomain").finish()
    }
}

impl JournalDomain {
    pub(crate) fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    pub(crate) async fn read_lifecycle_journal(
        &self,
        repo: &str,
    ) -> Result<Option<Bytes>, StorageError> {
        read_lifecycle_journal(self.store.as_ref(), repo).await
    }

    pub(crate) async fn write_lifecycle_journal(
        &self,
        repo: &str,
        data: Bytes,
    ) -> Result<(), StorageError> {
        write_lifecycle_journal(self.store.as_ref(), repo, data).await
    }

    pub(crate) async fn delete_lifecycle_journal(&self, repo: &str) -> Result<(), StorageError> {
        delete_lifecycle_journal(self.store.as_ref(), repo).await
    }
}

#[cfg(test)]
#[path = "journal_domain_tests.rs"]
mod tests;
