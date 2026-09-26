//! Contained filesystem repository-blob membership, readiness, and migration
//! checkpoint reads for `naust` (gap items R-7–R-11).
//!
//! # Architecture and Scope
//!
//! Implements the production read paths behind the `RepositoryBlobMembershipStorage`
//! trait on `FsStorage`: `get_repo_blob_membership`,
//! `list_repo_blob_memberships_page`, `list_all_repo_blob_memberships_page`,
//! `count_repo_blob_memberships`, the readiness-marker leg of
//! `is_membership_ready`, and `get_migration_checkpoint`. All filesystem
//! observation resolves beneath the shared pinned root descriptor via
//! [`storage_fs::FsMetadataReader`]: directory enumeration (`enumerate_dir`,
//! `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`),
//! payload acquisition (`open_payload`, two-phase `O_PATH` + `S_IFREG` +
//! procfs reopen), and attribute inspection (`inspect_file_metadata`).
//! Blocking work executes inside the dependency's `spawn_blocking` offload.
//!
//! # On-Disk Layout (unchanged)
//!
//! - Membership record: `repo-memberships/by-repo/<base64url(repo)>/<algo>/<hex>.json`
//!   (JSON `RepoBlobMembershipRecord`).
//! - Readiness marker: `meta/membership_ready.json`.
//! - Migration checkpoint: `meta/migration_checkpoint.json`
//!   (JSON `MigrationCheckpointRecord`).
//!
//! # Preserved Contracts
//!
//! - `get_repo_blob_membership`: strict `CanonicalRepoName` grammar; missing
//!   record -> `Ok(None)`; malformed JSON -> `CorruptData`; other read
//!   failures -> legacy `Io` taxonomy.
//! - Listing pages: page limit clamped to `[1, 1000]` (pre-existing embedded
//!   cap, not a new ceiling); candidates are `*.json` names excluding
//!   `.tmp.`-marked temporaries; continuation filter skips entries with
//!   `sort key <= token`; a bounded min-heap retains the `limit + 1` smallest
//!   candidates; ascending sort; `next_token` is the last returned sort key
//!   when more remain. Per-repo sort key is `<algo>:<hex>`; global sort key is
//!   `<encoded-repo>/<algo>/<hex>`. Missing membership roots -> empty page.
//! - `list_all_...`: an undecodable repository directory name (base64/grammar)
//!   still fails with `CorruptData`; file names that do not parse as digests
//!   are still skipped (they cannot be membership records, which are only
//!   written under digest names).
//! - Record loads after candidate selection still fail the page closed:
//!   vanished records map to `Io`, malformed records to `CorruptData` — no
//!   partial page is returned.
//! - `count_repo_blob_memberships`: a genuinely missing membership root
//!   counts zero; a present marker object of any observed type still counts
//!   (the legacy existence probe counted any object; counting protects the
//!   blob from deletion, so over-counting is the safe direction).
//! - `get_migration_checkpoint`: genuinely missing checkpoint -> `Ok(None)`
//!   (a fresh migration remains permitted only by true absence); malformed
//!   -> `CorruptData`; other failures -> `Io`.
//! - Readiness: marker absence -> not ready; the checkpoint-phase conjunction
//!   in `is_membership_ready` is unchanged.
//!
//! # Intentional Containment and Failure-Handling Changes (test-frozen)
//!
//! - Pinned-root resolution: root pathname replacement no longer redirects
//!   membership, readiness, or checkpoint reads.
//! - Symlinked path components (membership roots, repo/algo directories,
//!   record files, `meta/`, marker, checkpoint) are rejected (`Io`) instead of
//!   silently followed; symlinked directory entries at repository/algorithm
//!   levels were already skipped by the dirent-type gate and remain skipped.
//!   **Name-qualifying record candidates whose observed dirent type is not a
//!   regular file fail the page closed with `CorruptData`** — they are never
//!   silently omitted from authoritative pages (unsafe for ledger
//!   reconciliation, which marks the reverse index ready from these pages)
//!   and are never followed or opened (dirent evidence only; no potentially
//!   blocking special-file opens). Previously any `.json` dirent was read:
//!   directories failed only when selected into the current page, and
//!   symlinks were silently followed. Rejection now occurs during candidate
//!   scanning, before token filtering and selection.
//! - **No unsafe incomplete success.** The ambient implementations converted
//!   every failure of the root probe (`metadata(..).is_err()`), directory
//!   opens (`if let Ok(..)`), and iteration (`while let Ok(Some(..))`) into
//!   empty pages or a **zero count**. A silently-zero count previously fed
//!   `blob_gc` pre-delete validation and eligibility (`count == 0` permits
//!   deletion) and `RepositoryMembershipLedger::has_any_membership`; silently
//!   empty `list_all` pages fed the ledger's `reconcile_memberships`, which
//!   marks the reverse index ready. All such failures (permission, I/O,
//!   wrong-type, containment rejection, mid-iteration errors) now propagate;
//!   only genuine `NotFound` retains its documented absence meaning.
//! - Containment resolution rejection (`ELOOP`/`EXDEV`) never proves absence
//!   or a harmless leaf substitution (it can involve an ancestor); it always
//!   propagates, for point reads, candidate loads, marker/checkpoint reads,
//!   and count probes alike.
//! - Readiness-marker failures other than `NotFound` now propagate instead of
//!   silently reporting "not ready" (absence is distinguished from failure);
//!   a non-regular object at the marker path is `CorruptData` instead of
//!   counting as a present marker (readiness must not be establishable by a
//!   directory or other non-regular object).
//! - Non-UTF-8 directory-entry names fail closed with `CorruptData` (the
//!   ambient code lossy-decoded them, fabricating sort keys/paths that could
//!   never resolve back to real records). This applies to every entry in the
//!   record directories regardless of its dirent type.
//! - Counting remains conservative and is deliberately NOT aligned with the
//!   listing rejection: `count_repo_blob_memberships` still counts a present
//!   marker object of any observed type (over-counting protects the blob from
//!   deletion), while authoritative listings fail closed on the same object.
//!
//! # Resource Costs (no new ceilings)
//!
//! Per-call `DirEnumerationLimits` are effectively unbounded, matching the
//! ambient baseline; no approved production limit's scope covers these reads,
//! and any numeric policy remains a consolidated open decision. Actual costs:
//! point reads buffer one record payload and its parsed form simultaneously;
//! page listings enumerate the repo (or all repos) directory tree per page —
//! one entry batch per directory, a bounded `limit + 1` candidate heap, and
//! `limit` record payloads parsed per page; successive pages repeat the
//! enumeration work. Counting performs one `openat2`+`fstat` probe per
//! repository directory. These bound nothing globally: no memory or
//! concurrency budget follows, and descriptor containment provides neither
//! snapshot isolation nor hard-link/mount isolation — records and directories
//! may change between enumeration and load within one call.

use std::collections::BinaryHeap;

use async_trait::async_trait;
use storage_core::{ObjectKey, ObjectPayload, ObjectPayloadReader, ReadError};
use storage_fs::{
    DirEntry, DirEntryType, DirEnumerationLimits, FsDirError, FsFileMetadata, FsMetadataReader,
};
use tokio::io::AsyncReadExt;

use super::catalog_discovery::map_contained_dir_error;
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::StorageError;
use crate::storage::repo_membership::{
    MigrationCheckpointRecord, RepoBlobMembershipRecord, canonical_all_memberships_prefix,
    decode_canonical_repo_key, encode_canonical_repo_key,
};

const READY_MARKER_KEY: &str = "meta/membership_ready.json";
const MIGRATION_CHECKPOINT_KEY: &str = "meta/migration_checkpoint.json";

/// Unbounded per-call enumeration limits preserving the ambient baseline.
fn unbounded_dir_limits() -> DirEnumerationLimits {
    DirEnumerationLimits::new(usize::MAX, usize::MAX)
}

/// Narrow seam over the pinned reader operations used by membership reads,
/// enabling deterministic fault injection for failures a real filesystem
/// cannot reproduce reliably.
#[async_trait]
pub(crate) trait MembershipReadOps: Send + Sync {
    async fn enumerate_dir(
        &self,
        target: Option<&ObjectKey>,
        limits: DirEnumerationLimits,
    ) -> Result<Vec<DirEntry>, FsDirError>;

    async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError>;

    async fn inspect_file_metadata(&self, key: &ObjectKey) -> Result<FsFileMetadata, ReadError>;
}

#[async_trait]
impl MembershipReadOps for FsMetadataReader {
    async fn enumerate_dir(
        &self,
        target: Option<&ObjectKey>,
        limits: DirEnumerationLimits,
    ) -> Result<Vec<DirEntry>, FsDirError> {
        FsMetadataReader::enumerate_dir(self, target, limits).await
    }

    async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError> {
        ObjectPayloadReader::open_payload(self, key).await
    }

    async fn inspect_file_metadata(&self, key: &ObjectKey) -> Result<FsFileMetadata, ReadError> {
        FsMetadataReader::inspect_file_metadata(self, key).await
    }
}

fn parse_internal_key(key_str: &str) -> Result<ObjectKey, StorageError> {
    ObjectKey::parse(key_str).map_err(|e| {
        StorageError::internal_invariant(format!("invalid internal object key {key_str:?}: {e}"))
    })
}

/// Drains a payload stream completely (no seam-imposed ceiling, matching the
/// ambient `tokio::fs::read` baseline).
async fn drain_payload(payload: ObjectPayload, context: &str) -> Result<Vec<u8>, StorageError> {
    let (_metadata, mut stream) = payload.into_parts();
    let mut buffer = Vec::new();
    stream
        .read_to_end(&mut buffer)
        .await
        .map_err(|e| StorageError::io(format!("failed to read {context}: {e}")))?;
    Ok(buffer)
}

fn parse_membership_record(
    bytes: &[u8],
    key_str: &str,
) -> Result<RepoBlobMembershipRecord, StorageError> {
    serde_json::from_slice::<RepoBlobMembershipRecord>(bytes).map_err(|e| {
        StorageError::corrupt_data(format!("corrupt membership record in {key_str}: {e}"))
    })
}

/// Reads and parses a single membership record for a candidate selected from
/// an enumeration. The record was just observed, so its disappearance is a
/// load failure (legacy `Io`), not absence.
async fn load_selected_record(
    ops: &(impl MembershipReadOps + ?Sized),
    key_str: &str,
) -> Result<RepoBlobMembershipRecord, StorageError> {
    let key = parse_internal_key(key_str)?;
    let payload = match ops.open_payload(&key).await {
        Ok(p) => p,
        Err(ReadError::NotFound { .. }) => {
            return Err(StorageError::io(format!(
                "failed to read membership in {key_str}: record disappeared before read"
            )));
        }
        Err(other) => return Err(super::read_adapter::translate_payload_read_error(other)),
    };
    let bytes = drain_payload(payload, &format!("membership in {key_str}")).await?;
    parse_membership_record(&bytes, key_str)
}

/// Requires a UTF-8 directory-entry name; the ambient implementation
/// lossy-decoded names, fabricating identifiers that could never resolve.
fn require_utf8_name<'a>(entry: &'a DirEntry, dir_key: &str) -> Result<&'a str, StorageError> {
    entry.name().to_str().ok_or_else(|| {
        StorageError::corrupt_data(format!(
            "non-UTF-8 entry name in {dir_key} prevents contained membership inspection: {:?}",
            entry.name()
        ))
    })
}

/// Enumerates one directory for the membership walks: `NotFound` yields
/// `None` (caller-specific absence semantics), everything else fails closed.
async fn enumerate_or_absent(
    ops: &(impl MembershipReadOps + ?Sized),
    key_str: &str,
) -> Result<Option<Vec<DirEntry>>, StorageError> {
    let key = parse_internal_key(key_str)?;
    match ops.enumerate_dir(Some(&key), unbounded_dir_limits()).await {
        Ok(entries) => Ok(Some(entries)),
        Err(FsDirError::NotFound { .. }) => Ok(None),
        Err(other) => Err(map_contained_dir_error(other, key_str)),
    }
}

/// Extracts the digest hex from a candidate record file name, applying the
/// preserved filters: `*.json` only, excluding `.tmp.`-marked temporaries.
fn candidate_hex(file_name: &str) -> Option<&str> {
    if file_name.ends_with(".json") && !file_name.contains(".tmp.") {
        Some(file_name.trim_end_matches(".json"))
    } else {
        None
    }
}

/// Rejects a name-qualifying membership-record candidate whose observed
/// dirent type is not a regular file. Uses dirent evidence only: symlinks are
/// not followed and no payload open (which could block on special files) is
/// attempted. `CorruptData` matches the batch's non-regular-object precedent
/// (readiness marker) — a non-regular object at a record name is structurally
/// invalid membership data, and silently omitting it would let authoritative
/// pages under-report records (unsafe for ledger reconciliation, which marks
/// the reverse index ready from these pages).
///
/// Rejection happens during candidate scanning, deliberately BEFORE
/// continuation-token filtering and heap selection (and therefore earlier
/// than the legacy read-time failure, which only surfaced for records
/// selected into the current page and silently followed symlinks): a complete
/// traversal must never silently omit a qualifying record on any page.
fn require_regular_candidate(
    file_entry: &DirEntry,
    dir_key: &str,
    file_name: &str,
) -> Result<(), StorageError> {
    if file_entry.file_type() != DirEntryType::Regular {
        return Err(StorageError::corrupt_data(format!(
            "membership record candidate {dir_key}/{file_name} is not a regular file (observed type {:?})",
            file_entry.file_type()
        )));
    }
    Ok(())
}

#[derive(Eq, PartialEq)]
struct Candidate {
    sort_key: String,
    record_key: String,
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sort_key.cmp(&other.sort_key)
    }
}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Pushes a candidate into the bounded max-heap retaining the `limit + 1`
/// smallest sort keys (preserved legacy selection mechanics).
fn heap_offer(heap: &mut BinaryHeap<Candidate>, limit: usize, cand: Candidate) {
    if heap.len() < limit + 1 {
        heap.push(cand);
    } else if let Some(top) = heap.peek()
        && cand.sort_key < top.sort_key
    {
        heap.pop();
        heap.push(cand);
    }
}

/// Finalizes heap selection into (records, next_token), loading each selected
/// record through contained payload reads (preserved fail-closed loads).
async fn finalize_page(
    ops: &(impl MembershipReadOps + ?Sized),
    heap: BinaryHeap<Candidate>,
    limit: usize,
) -> Result<(Vec<RepoBlobMembershipRecord>, Option<String>), StorageError> {
    let mut sorted: Vec<Candidate> = heap.into_sorted_vec();
    let has_more = sorted.len() > limit;
    if has_more {
        sorted.truncate(limit);
    }
    let next_token = if has_more {
        sorted.last().map(|c| c.sort_key.clone())
    } else {
        None
    };

    let mut records = Vec::with_capacity(sorted.len());
    for cand in sorted {
        records.push(load_selected_record(ops, &cand.record_key).await?);
    }
    Ok((records, next_token))
}

/// Contained per-repository membership page listing.
pub(crate) async fn list_repo_blob_memberships_page_impl(
    ops: &(impl MembershipReadOps + ?Sized),
    repo: &str,
    continuation_token: Option<&str>,
    page_limit: usize,
) -> Result<(Vec<RepoBlobMembershipRecord>, Option<String>), StorageError> {
    let max_limit = 1000;
    let limit = page_limit.min(max_limit).max(1);

    let canonical =
        CanonicalRepoName::parse(repo).map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
    let repo_dir_key = format!(
        "{}{}",
        canonical_all_memberships_prefix(),
        encode_canonical_repo_key(&canonical)
    );

    // Genuinely missing repository membership directory: empty page (legacy).
    // Any other failure now fails closed instead of returning an empty page.
    let Some(algo_entries) = enumerate_or_absent(ops, &repo_dir_key).await? else {
        return Ok((Vec::new(), None));
    };

    let mut heap: BinaryHeap<Candidate> = BinaryHeap::with_capacity(limit + 2);

    for algo_entry in algo_entries {
        if algo_entry.file_type() != DirEntryType::Directory {
            continue;
        }
        let algo_str = require_utf8_name(&algo_entry, &repo_dir_key)?;
        let algo_dir_key = format!("{repo_dir_key}/{algo_str}");

        // An algorithm directory observed then removed contributes nothing.
        let Some(file_entries) = enumerate_or_absent(ops, &algo_dir_key).await? else {
            continue;
        };

        for file_entry in file_entries {
            let file_name = require_utf8_name(&file_entry, &algo_dir_key)?;
            let Some(hex) = candidate_hex(file_name) else {
                continue;
            };
            require_regular_candidate(&file_entry, &algo_dir_key, file_name)?;
            let digest_str = format!("{algo_str}:{hex}");

            if let Some(token) = continuation_token
                && digest_str.as_str() <= token
            {
                continue;
            }

            let record_key = format!("{algo_dir_key}/{file_name}");
            heap_offer(
                &mut heap,
                limit,
                Candidate {
                    sort_key: digest_str,
                    record_key,
                },
            );
        }
    }

    finalize_page(ops, heap, limit).await
}

/// Contained global membership page listing across all repositories.
pub(crate) async fn list_all_repo_blob_memberships_page_impl(
    ops: &(impl MembershipReadOps + ?Sized),
    continuation_token: Option<&str>,
    page_limit: usize,
) -> Result<(Vec<RepoBlobMembershipRecord>, Option<String>), StorageError> {
    let max_limit = 1000;
    let limit = page_limit.min(max_limit).max(1);

    let root_key = canonical_all_memberships_prefix().trim_end_matches('/');

    let Some(repo_entries) = enumerate_or_absent(ops, root_key).await? else {
        return Ok((Vec::new(), None));
    };

    let mut heap: BinaryHeap<Candidate> = BinaryHeap::with_capacity(limit + 2);

    for repo_entry in repo_entries {
        if repo_entry.file_type() != DirEntryType::Directory {
            continue;
        }
        let repo_encoded = require_utf8_name(&repo_entry, root_key)?;
        // Preserved: an undecodable repository directory fails the page closed.
        decode_canonical_repo_key(repo_encoded).map_err(|e| {
            StorageError::corrupt_data(format!(
                "corrupt repository membership directory '{repo_encoded}': {e}"
            ))
        })?;
        let repo_dir_key = format!("{root_key}/{repo_encoded}");

        let Some(algo_entries) = enumerate_or_absent(ops, &repo_dir_key).await? else {
            continue;
        };

        for algo_entry in algo_entries {
            if algo_entry.file_type() != DirEntryType::Directory {
                continue;
            }
            let algo_str = require_utf8_name(&algo_entry, &repo_dir_key)?;
            let algo_dir_key = format!("{repo_dir_key}/{algo_str}");

            let Some(file_entries) = enumerate_or_absent(ops, &algo_dir_key).await? else {
                continue;
            };

            for file_entry in file_entries {
                let file_name = require_utf8_name(&file_entry, &algo_dir_key)?;
                let Some(hex) = candidate_hex(file_name) else {
                    continue;
                };
                // Preserved: names that do not parse as digests are skipped
                // (membership records are only written under digest names).
                if Digest::parse(&format!("{algo_str}:{hex}")).is_err() {
                    continue;
                }
                require_regular_candidate(&file_entry, &algo_dir_key, file_name)?;
                let sort_key = format!("{repo_encoded}/{algo_str}/{hex}");

                if let Some(token) = continuation_token
                    && sort_key.as_str() <= token
                {
                    continue;
                }

                let record_key = format!("{algo_dir_key}/{file_name}");
                heap_offer(
                    &mut heap,
                    limit,
                    Candidate {
                        sort_key,
                        record_key,
                    },
                );
            }
        }
    }

    finalize_page(ops, heap, limit).await
}

/// Contained membership count for one digest across all repositories.
///
/// The count feeds blob-deletion protection: a genuinely missing membership
/// root counts zero, and a genuinely absent marker is not counted, but every
/// other probe or enumeration failure propagates — an unreadable membership
/// area must never present as "zero memberships" and thereby permit deletion.
/// A present marker object of any observed type still counts (over-counting
/// protects the blob, matching the legacy any-object existence probe).
pub(crate) async fn count_repo_blob_memberships_impl(
    ops: &(impl MembershipReadOps + ?Sized),
    digest: &Digest,
) -> Result<usize, StorageError> {
    let root_key = canonical_all_memberships_prefix().trim_end_matches('/');

    let Some(repo_entries) = enumerate_or_absent(ops, root_key).await? else {
        return Ok(0);
    };

    let mut count: usize = 0;
    for repo_entry in repo_entries {
        if repo_entry.file_type() != DirEntryType::Directory {
            continue;
        }
        let repo_encoded = require_utf8_name(&repo_entry, root_key)?;
        let marker_key_str = format!(
            "{root_key}/{repo_encoded}/{}/{}.json",
            digest.algorithm(),
            digest.hex()
        );
        let marker_key = parse_internal_key(&marker_key_str)?;
        match ops.inspect_file_metadata(&marker_key).await {
            Ok(_) => count += 1,
            Err(ReadError::NotFound { .. }) => {}
            Err(err) if inspection_confirms_non_regular(&err) => {
                // Something exists at the marker path even though it is not a
                // regular file: count it (protective direction, legacy
                // any-object existence semantics).
                count += 1;
            }
            Err(other) => {
                return Err(super::read_adapter::translate_metadata_read_error(other));
            }
        }
    }
    Ok(count)
}

/// True only for a confirmed non-regular object at the inspected leaf
/// (`fstat` on the acquired descriptor). Containment resolution rejection is
/// NOT included: it does not establish the leaf's type and can involve an
/// ancestor, so it must propagate.
fn inspection_confirms_non_regular(err: &ReadError) -> bool {
    match err {
        ReadError::Backend {
            source: Some(source),
            ..
        } => matches!(
            source.downcast_ref::<storage_fs::FsMetadataError>(),
            Some(storage_fs::FsMetadataError::UnsupportedObjectType { .. })
        ),
        _ => false,
    }
}

/// Contained readiness-marker presence check for `is_membership_ready`.
///
/// - Regular marker file present -> `Ok(true)`.
/// - Genuinely absent -> `Ok(false)`.
/// - Non-regular object at the marker path -> `CorruptData` (readiness must
///   not be establishable by a directory or other non-regular object; the
///   ambient existence probe treated any object as a present marker).
/// - Every other failure (permission, I/O, containment rejection) propagates
///   instead of silently reporting "not ready".
pub(crate) async fn membership_ready_marker_present(
    ops: &(impl MembershipReadOps + ?Sized),
) -> Result<bool, StorageError> {
    let key = parse_internal_key(READY_MARKER_KEY)?;
    match ops.inspect_file_metadata(&key).await {
        Ok(_) => Ok(true),
        Err(ReadError::NotFound { .. }) => Ok(false),
        Err(err) if inspection_confirms_non_regular(&err) => Err(StorageError::corrupt_data(
            format!("membership readiness marker {READY_MARKER_KEY} is not a regular file"),
        )),
        Err(other) => Err(super::read_adapter::translate_metadata_read_error(other)),
    }
}

/// Contained migration checkpoint read.
///
/// Genuine absence returns `Ok(None)` (only true absence permits a fresh
/// migration); malformed JSON -> `CorruptData`; every other failure,
/// including containment rejection, propagates instead of presenting as a
/// missing checkpoint.
pub(crate) async fn get_migration_checkpoint_impl(
    ops: &(impl MembershipReadOps + ?Sized),
) -> Result<Option<MigrationCheckpointRecord>, StorageError> {
    let key = parse_internal_key(MIGRATION_CHECKPOINT_KEY)?;
    let payload = match ops.open_payload(&key).await {
        Ok(p) => p,
        Err(ReadError::NotFound { .. }) => return Ok(None),
        Err(other) => return Err(super::read_adapter::translate_payload_read_error(other)),
    };
    let bytes = drain_payload(payload, "migration checkpoint").await?;
    let rec = serde_json::from_slice::<MigrationCheckpointRecord>(&bytes)
        .map_err(|e| StorageError::corrupt_data(format!("corrupt migration checkpoint: {e}")))?;
    Ok(Some(rec))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageErrorKind;
    use crate::storage::repo_membership::{MigrationPhase, MigrationStats};
    use std::collections::{HashMap, VecDeque};
    use std::ffi::OsString;
    use std::sync::{Arc, Mutex};
    use storage_core::{ObjectMetadata, ObjectStream};

    struct RecordingFakeOps {
        dir_calls: Arc<Mutex<Vec<Option<ObjectKey>>>>,
        payload_calls: Arc<Mutex<Vec<ObjectKey>>>,
        inspect_calls: Arc<Mutex<Vec<ObjectKey>>>,
        dir_responses:
            Arc<Mutex<HashMap<Option<ObjectKey>, VecDeque<Result<Vec<DirEntry>, FsDirError>>>>>,
        payload_responses:
            Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<ObjectPayload, ReadError>>>>>,
        inspect_responses:
            Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<FsFileMetadata, ReadError>>>>>,
    }

    impl RecordingFakeOps {
        fn new() -> Self {
            Self {
                dir_calls: Arc::new(Mutex::new(Vec::new())),
                payload_calls: Arc::new(Mutex::new(Vec::new())),
                inspect_calls: Arc::new(Mutex::new(Vec::new())),
                dir_responses: Arc::new(Mutex::new(HashMap::new())),
                payload_responses: Arc::new(Mutex::new(HashMap::new())),
                inspect_responses: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn script_dir(&self, target: Option<ObjectKey>, resp: Result<Vec<DirEntry>, FsDirError>) {
            self.dir_responses
                .lock()
                .unwrap()
                .entry(target)
                .or_default()
                .push_back(resp);
        }

        fn script_payload(&self, key: ObjectKey, resp: Result<ObjectPayload, ReadError>) {
            self.payload_responses
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push_back(resp);
        }

        fn script_inspect(&self, key: ObjectKey, resp: Result<FsFileMetadata, ReadError>) {
            self.inspect_responses
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push_back(resp);
        }

        fn payload_calls(&self) -> Vec<ObjectKey> {
            self.payload_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl MembershipReadOps for RecordingFakeOps {
        async fn enumerate_dir(
            &self,
            target: Option<&ObjectKey>,
            _limits: DirEnumerationLimits,
        ) -> Result<Vec<DirEntry>, FsDirError> {
            self.dir_calls.lock().unwrap().push(target.cloned());
            let mut responses = self.dir_responses.lock().unwrap();
            let queue = responses
                .get_mut(&target.cloned())
                .unwrap_or_else(|| panic!("unexpected enumerate_dir call: {target:?}"));
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted dir responses for: {target:?}"))
        }

        async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError> {
            self.payload_calls.lock().unwrap().push(key.clone());
            let mut responses = self.payload_responses.lock().unwrap();
            let queue = responses
                .get_mut(key)
                .unwrap_or_else(|| panic!("unexpected open_payload call: {key}"));
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted payload responses for: {key}"))
        }

        async fn inspect_file_metadata(
            &self,
            key: &ObjectKey,
        ) -> Result<FsFileMetadata, ReadError> {
            self.inspect_calls.lock().unwrap().push(key.clone());
            let mut responses = self.inspect_responses.lock().unwrap();
            let queue = responses
                .get_mut(key)
                .unwrap_or_else(|| panic!("unexpected inspect call: {key}"));
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted inspect responses for: {key}"))
        }
    }

    fn dir_entry(name: &str, file_type: DirEntryType) -> DirEntry {
        DirEntry::new(OsString::from(name), file_type)
    }

    fn key(s: &str) -> ObjectKey {
        ObjectKey::parse(s).unwrap()
    }

    fn payload_of(bytes: Vec<u8>) -> ObjectPayload {
        let meta = ObjectMetadata::new(bytes.len() as u64);
        let stream: ObjectStream = Box::pin(std::io::Cursor::new(bytes));
        ObjectPayload::new(meta, stream)
    }

    fn canonical(repo: &str) -> CanonicalRepoName {
        CanonicalRepoName::parse(repo).unwrap()
    }

    fn digest_n(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    fn record_for(repo: &str, digest: &Digest) -> RepoBlobMembershipRecord {
        RepoBlobMembershipRecord::new_migration(canonical(repo), digest.clone())
    }

    fn record_bytes(repo: &str, digest: &Digest) -> Vec<u8> {
        serde_json::to_vec(&record_for(repo, digest)).unwrap()
    }

    fn enc(repo: &str) -> String {
        encode_canonical_repo_key(&canonical(repo))
    }

    fn rejection(code: i32) -> ReadError {
        ReadError::backend_with_source(
            "resolution rejected",
            Box::new(storage_fs::FsMetadataError::ResolutionRejected {
                raw_os_error: code,
                source: std::io::Error::from_raw_os_error(code),
            }),
        )
    }

    fn dir_rejection(code: i32) -> FsDirError {
        FsDirError::ResolutionRejected {
            raw_os_error: code,
            source: std::io::Error::from_raw_os_error(code),
        }
    }

    // (The point-read seam moved to the shared membership domain in Phase 6;
    // its taxonomy — absent -> None, corrupt -> CorruptData with the record
    // key, grammar -> InvalidRepoName, adapter containment refusal fails
    // closed — is pinned by the cross-backend membership_domain suite.)

    // ========================================================================
    // Per-repo page listing
    // ========================================================================

    fn repo_dir_key(repo: &str) -> String {
        format!("repo-memberships/by-repo/{}", enc(repo))
    }

    #[tokio::test]
    async fn test_fake_repo_page_missing_dir_empty_but_failures_propagate() {
        let d = digest_n(1);
        let rk = repo_dir_key("myrepo");

        // Genuinely missing repo membership dir -> empty page (legacy).
        let fake = RecordingFakeOps::new();
        fake.script_dir(Some(key(&rk)), Err(FsDirError::NotFound { path: None }));
        let (recs, tok) = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 10)
            .await
            .unwrap();
        assert!(recs.is_empty());
        assert_eq!(tok, None);

        // Permission failure no longer becomes an empty page.
        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(&rk)),
            Err(FsDirError::PermissionDenied {
                path: None,
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }),
        );
        let err = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 10)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Containment rejection of the repo dir propagates.
        let fake = RecordingFakeOps::new();
        fake.script_dir(Some(key(&rk)), Err(dir_rejection(libc::ELOOP)));
        let err = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 10)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
        let _ = d;
    }

    #[tokio::test]
    async fn test_fake_repo_page_pagination_filters_and_ordering() {
        let rk = repo_dir_key("myrepo");
        let d1 = digest_n(1);
        let d2 = digest_n(2);
        let d3 = digest_n(3);

        fn scripted(rk: &str, d1: &Digest, d2: &Digest, d3: &Digest) -> RecordingFakeOps {
            let fake = RecordingFakeOps::new();
            fake.script_dir(
                Some(key(rk)),
                Ok(vec![
                    dir_entry("sha256", DirEntryType::Directory),
                    dir_entry("stray_file", DirEntryType::Regular),
                    dir_entry("symdir", DirEntryType::Symlink),
                ]),
            );
            fake.script_dir(
                Some(key(&format!("{rk}/sha256"))),
                Ok(vec![
                    // Written unsorted; also filtered names and non-regular entries.
                    dir_entry(&format!("{}.json", d3.hex()), DirEntryType::Regular),
                    dir_entry(&format!("{}.json", d1.hex()), DirEntryType::Regular),
                    dir_entry(&format!("{}.json", d2.hex()), DirEntryType::Regular),
                    dir_entry(
                        &format!(".tmp.{}.json.123", d1.hex()),
                        DirEntryType::Regular,
                    ),
                    dir_entry("notes.txt", DirEntryType::Regular),
                ]),
            );
            for d in [d1, d2, d3] {
                fake.script_payload(
                    key(&format!("{rk}/sha256/{}.json", d.hex())),
                    Ok(payload_of(record_bytes("myrepo", d))),
                );
            }
            fake
        }

        // Page 1 with limit 2: two smallest digests, has_more token.
        let fake = scripted(&rk, &d1, &d2, &d3);
        let (recs, tok) = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 2)
            .await
            .unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].digest, d1);
        assert_eq!(recs[1].digest, d2);
        assert_eq!(tok, Some(format!("sha256:{}", d2.hex())));
        // Only the two returned records were loaded.
        assert_eq!(fake.payload_calls().len(), 2);

        // Page 2 with the token: remaining record, terminal.
        let fake = scripted(&rk, &d1, &d2, &d3);
        let token = format!("sha256:{}", d2.hex());
        let (recs, tok) = list_repo_blob_memberships_page_impl(&fake, "myrepo", Some(&token), 2)
            .await
            .unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].digest, d3);
        assert_eq!(tok, None);

        // Zero page limit clamps to 1 (legacy).
        let fake = scripted(&rk, &d1, &d2, &d3);
        let (recs, tok) = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 0)
            .await
            .unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].digest, d1);
        assert_eq!(tok, Some(format!("sha256:{}", d1.hex())));
    }

    #[tokio::test]
    async fn test_fake_repo_page_no_partial_page_on_load_failures() {
        let rk = repo_dir_key("myrepo");
        let d1 = digest_n(1);
        let d2 = digest_n(2);

        // Selected record vanished before load -> Io error (legacy), no page.
        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(&rk)),
            Ok(vec![dir_entry("sha256", DirEntryType::Directory)]),
        );
        fake.script_dir(
            Some(key(&format!("{rk}/sha256"))),
            Ok(vec![
                dir_entry(&format!("{}.json", d1.hex()), DirEntryType::Regular),
                dir_entry(&format!("{}.json", d2.hex()), DirEntryType::Regular),
            ]),
        );
        fake.script_payload(
            key(&format!("{rk}/sha256/{}.json", d1.hex())),
            Ok(payload_of(record_bytes("myrepo", &d1))),
        );
        let vanished_key = key(&format!("{rk}/sha256/{}.json", d2.hex()));
        fake.script_payload(
            vanished_key.clone(),
            Err(ReadError::not_found(vanished_key)),
        );
        let err = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 10)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Corrupt selected record -> CorruptData (preserved), no page.
        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(&rk)),
            Ok(vec![dir_entry("sha256", DirEntryType::Directory)]),
        );
        fake.script_dir(
            Some(key(&format!("{rk}/sha256"))),
            Ok(vec![dir_entry(
                &format!("{}.json", d1.hex()),
                DirEntryType::Regular,
            )]),
        );
        fake.script_payload(
            key(&format!("{rk}/sha256/{}.json", d1.hex())),
            Ok(payload_of(b"{broken".to_vec())),
        );
        let err = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 10)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));

        // Mid-walk algo-dir failure after earlier observations -> error.
        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(&rk)),
            Ok(vec![
                dir_entry("sha256", DirEntryType::Directory),
                dir_entry("sha512", DirEntryType::Directory),
            ]),
        );
        fake.script_dir(
            Some(key(&format!("{rk}/sha256"))),
            Ok(vec![dir_entry(
                &format!("{}.json", d1.hex()),
                DirEntryType::Regular,
            )]),
        );
        fake.script_dir(
            Some(key(&format!("{rk}/sha512"))),
            Err(FsDirError::Io {
                source: std::io::Error::other("disk error"),
            }),
        );
        let err = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 10)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
    }

    #[tokio::test]
    async fn test_fake_repo_page_non_utf8_name_fails_closed() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let rk = repo_dir_key("myrepo");
            let fake = RecordingFakeOps::new();
            let non_utf8 = std::ffi::OsStr::from_bytes(b"sha\xff256").to_os_string();
            fake.script_dir(
                Some(key(&rk)),
                Ok(vec![DirEntry::new(non_utf8, DirEntryType::Directory)]),
            );
            let err = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 10)
                .await
                .unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));
        }
    }

    #[tokio::test]
    async fn test_fake_nonregular_record_candidates_fail_closed_both_listings() {
        // Injected dirent evidence: a name-qualifying record candidate whose
        // observed type is a directory, symlink, or other special object must
        // fail the page closed with CorruptData — never a silently smaller
        // page — and must be rejected WITHOUT any payload open (no symlink
        // following, no potentially blocking special-file open).
        let d_ok = digest_n(1);
        let d_bad = digest_n(2);
        let rk = repo_dir_key("myrepo");
        let root = "repo-memberships/by-repo";

        for bad_type in [
            DirEntryType::Directory,
            DirEntryType::Symlink,
            DirEntryType::Other,
        ] {
            // Per-repo listing: rejection after an earlier successful
            // observation; no partial page, no payload opens at all (the
            // failure precedes selected-record loading).
            let fake = RecordingFakeOps::new();
            fake.script_dir(
                Some(key(&rk)),
                Ok(vec![dir_entry("sha256", DirEntryType::Directory)]),
            );
            fake.script_dir(
                Some(key(&format!("{rk}/sha256"))),
                Ok(vec![
                    dir_entry(&format!("{}.json", d_ok.hex()), DirEntryType::Regular),
                    dir_entry(&format!("{}.json", d_bad.hex()), bad_type),
                ]),
            );
            let err = list_repo_blob_memberships_page_impl(&fake, "myrepo", None, 10)
                .await
                .expect_err("nonregular qualifying candidate must fail the page closed");
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::CorruptData),
                "for {bad_type:?}"
            );
            assert!(
                fake.payload_calls().is_empty(),
                "rejection must use dirent evidence only, with zero payload opens ({bad_type:?})"
            );

            // Rejection precedes token filtering: even a candidate whose sort
            // key is <= the continuation token fails the traversal (a complete
            // traversal must not silently omit it on any page). d_bad sorts
            // after d_ok, so use a token past both.
            let fake = RecordingFakeOps::new();
            fake.script_dir(
                Some(key(&rk)),
                Ok(vec![dir_entry("sha256", DirEntryType::Directory)]),
            );
            fake.script_dir(
                Some(key(&format!("{rk}/sha256"))),
                Ok(vec![dir_entry(&format!("{}.json", d_bad.hex()), bad_type)]),
            );
            let token = format!("sha256:{}", digest_n(9).hex());
            let err = list_repo_blob_memberships_page_impl(&fake, "myrepo", Some(&token), 10)
                .await
                .expect_err("rejection is deliberately earlier than token filtering");
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));

            // Global listing: same policy; digest-parse skip still applies
            // first (a non-digest name of any type remains excluded).
            let fake = RecordingFakeOps::new();
            fake.script_dir(
                Some(key(root)),
                Ok(vec![dir_entry(&enc("myrepo"), DirEntryType::Directory)]),
            );
            fake.script_dir(
                Some(key(&rk)),
                Ok(vec![dir_entry("sha256", DirEntryType::Directory)]),
            );
            fake.script_dir(
                Some(key(&format!("{rk}/sha256"))),
                Ok(vec![
                    dir_entry("not-a-digest.json", bad_type),
                    dir_entry(&format!("{}.json", d_bad.hex()), bad_type),
                ]),
            );
            let err = list_all_repo_blob_memberships_page_impl(&fake, None, 10)
                .await
                .expect_err("nonregular qualifying candidate must fail the global page closed");
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::CorruptData),
                "for {bad_type:?}"
            );
            assert!(fake.payload_calls().is_empty());
        }
    }

    // ========================================================================
    // Global page listing
    // ========================================================================

    #[tokio::test]
    async fn test_fake_all_page_nested_repos_ordering_and_preserved_policies() {
        let root = "repo-memberships/by-repo";
        let d1 = digest_n(1);
        let d2 = digest_n(2);
        let repo_a = "arepo";
        let repo_b = "org/nested";
        // Sort keys are "<encoded>/<algo>/<hex>": order repos by encoding.
        let (first_repo, second_repo) = if enc(repo_a) < enc(repo_b) {
            (repo_a, repo_b)
        } else {
            (repo_b, repo_a)
        };

        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(root)),
            Ok(vec![
                dir_entry(&enc(repo_a), DirEntryType::Directory),
                dir_entry(&enc(repo_b), DirEntryType::Directory),
                dir_entry("stray_file", DirEntryType::Regular),
            ]),
        );
        for repo in [repo_a, repo_b] {
            fake.script_dir(
                Some(key(&format!("{root}/{}", enc(repo)))),
                Ok(vec![dir_entry("sha256", DirEntryType::Directory)]),
            );
        }
        // repo_a holds d1; repo_b holds d2; plus a non-digest json (skipped, preserved).
        fake.script_dir(
            Some(key(&format!("{root}/{}/sha256", enc(repo_a)))),
            Ok(vec![
                dir_entry(&format!("{}.json", d1.hex()), DirEntryType::Regular),
                dir_entry("not-a-digest.json", DirEntryType::Regular),
            ]),
        );
        fake.script_dir(
            Some(key(&format!("{root}/{}/sha256", enc(repo_b)))),
            Ok(vec![dir_entry(
                &format!("{}.json", d2.hex()),
                DirEntryType::Regular,
            )]),
        );
        fake.script_payload(
            key(&format!("{root}/{}/sha256/{}.json", enc(repo_a), d1.hex())),
            Ok(payload_of(record_bytes(repo_a, &d1))),
        );
        fake.script_payload(
            key(&format!("{root}/{}/sha256/{}.json", enc(repo_b), d2.hex())),
            Ok(payload_of(record_bytes(repo_b, &d2))),
        );

        let (recs, tok) = list_all_repo_blob_memberships_page_impl(&fake, None, 10)
            .await
            .unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].repo.as_str(), first_repo);
        assert_eq!(recs[1].repo.as_str(), second_repo);
        assert_eq!(tok, None);

        // Undecodable repository directory fails closed (preserved).
        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(root)),
            Ok(vec![dir_entry("!!!not-base64!!!", DirEntryType::Directory)]),
        );
        let err = list_all_repo_blob_memberships_page_impl(&fake, None, 10)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));

        // Missing root -> empty page; unreadable root -> error, not empty.
        let fake = RecordingFakeOps::new();
        fake.script_dir(Some(key(root)), Err(FsDirError::NotFound { path: None }));
        let (recs, tok) = list_all_repo_blob_memberships_page_impl(&fake, None, 10)
            .await
            .unwrap();
        assert!(recs.is_empty() && tok.is_none());

        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(root)),
            Err(FsDirError::PermissionDenied {
                path: None,
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }),
        );
        let err = list_all_repo_blob_memberships_page_impl(&fake, None, 10)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
    }

    #[tokio::test]
    async fn test_fake_all_page_token_pagination_across_repos() {
        let root = "repo-memberships/by-repo";
        let d1 = digest_n(1);
        let d2 = digest_n(2);
        let repo = "myrepo";

        fn scripted(root: &str, repo: &str, d1: &Digest, d2: &Digest) -> RecordingFakeOps {
            let fake = RecordingFakeOps::new();
            fake.script_dir(
                Some(key(root)),
                Ok(vec![dir_entry(&enc(repo), DirEntryType::Directory)]),
            );
            fake.script_dir(
                Some(key(&format!("{root}/{}", enc(repo)))),
                Ok(vec![dir_entry("sha256", DirEntryType::Directory)]),
            );
            fake.script_dir(
                Some(key(&format!("{root}/{}/sha256", enc(repo)))),
                Ok(vec![
                    dir_entry(&format!("{}.json", d1.hex()), DirEntryType::Regular),
                    dir_entry(&format!("{}.json", d2.hex()), DirEntryType::Regular),
                ]),
            );
            for d in [d1, d2] {
                fake.script_payload(
                    key(&format!("{root}/{}/sha256/{}.json", enc(repo), d.hex())),
                    Ok(payload_of(record_bytes(repo, d))),
                );
            }
            fake
        }

        // Page 1: limit 1 -> first record + token.
        let fake = scripted(root, repo, &d1, &d2);
        let (recs, tok) = list_all_repo_blob_memberships_page_impl(&fake, None, 1)
            .await
            .unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].digest, d1);
        let expected_tok = format!("{}/sha256/{}", enc(repo), d1.hex());
        assert_eq!(tok, Some(expected_tok.clone()));

        // Page 2 with token -> second record, terminal.
        let fake = scripted(root, repo, &d1, &d2);
        let (recs, tok) = list_all_repo_blob_memberships_page_impl(&fake, Some(&expected_tok), 1)
            .await
            .unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].digest, d2);
        assert_eq!(tok, None);
    }

    // ========================================================================
    // Counting
    // ========================================================================

    #[tokio::test]
    async fn test_fake_count_semantics_and_no_silent_zero() {
        let root = "repo-memberships/by-repo";
        let d = digest_n(7);
        let marker = |repo: &str| format!("{root}/{}/sha256/{}.json", enc(repo), d.hex());

        // Two of three repos hold the marker; the third is genuinely absent.
        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(root)),
            Ok(vec![
                dir_entry(&enc("r1"), DirEntryType::Directory),
                dir_entry(&enc("r2"), DirEntryType::Directory),
                dir_entry(&enc("r3"), DirEntryType::Directory),
                dir_entry("stray_file", DirEntryType::Regular),
            ]),
        );
        fake.script_inspect(key(&marker("r1")), Ok(FsFileMetadata::new(10, None)));
        let absent = key(&marker("r2"));
        fake.script_inspect(absent.clone(), Err(ReadError::not_found(absent)));
        fake.script_inspect(key(&marker("r3")), Ok(FsFileMetadata::new(10, None)));
        assert_eq!(
            count_repo_blob_memberships_impl(&fake, &d).await.unwrap(),
            2
        );

        // Missing membership root -> zero (genuine absence).
        let fake = RecordingFakeOps::new();
        fake.script_dir(Some(key(root)), Err(FsDirError::NotFound { path: None }));
        assert_eq!(
            count_repo_blob_memberships_impl(&fake, &d).await.unwrap(),
            0
        );

        // Unreadable membership root -> error, never a silent zero that could
        // permit blob deletion.
        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(root)),
            Err(FsDirError::PermissionDenied {
                path: None,
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }),
        );
        let err = count_repo_blob_memberships_impl(&fake, &d)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Symlinked root -> error.
        let fake = RecordingFakeOps::new();
        fake.script_dir(Some(key(root)), Err(dir_rejection(libc::ELOOP)));
        let err = count_repo_blob_memberships_impl(&fake, &d)
            .await
            .unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        // Marker probe: confirmed non-regular object still counts (protective,
        // legacy any-object existence); permission and containment rejection
        // propagate even after earlier successful counts.
        let fake = RecordingFakeOps::new();
        fake.script_dir(
            Some(key(root)),
            Ok(vec![
                dir_entry(&enc("r1"), DirEntryType::Directory),
                dir_entry(&enc("r2"), DirEntryType::Directory),
            ]),
        );
        fake.script_inspect(
            key(&marker("r1")),
            Err(ReadError::backend_with_source(
                "unsupported object type",
                Box::new(storage_fs::FsMetadataError::UnsupportedObjectType {
                    mode: libc::S_IFDIR,
                }),
            )),
        );
        let k2 = key(&marker("r2"));
        fake.script_inspect(k2.clone(), Err(ReadError::not_found(k2)));
        assert_eq!(
            count_repo_blob_memberships_impl(&fake, &d).await.unwrap(),
            1
        );

        for err_case in [
            ReadError::permission_denied(key(&marker("r2"))),
            rejection(libc::EXDEV),
        ] {
            let fake = RecordingFakeOps::new();
            fake.script_dir(
                Some(key(root)),
                Ok(vec![
                    dir_entry(&enc("r1"), DirEntryType::Directory),
                    dir_entry(&enc("r2"), DirEntryType::Directory),
                ]),
            );
            fake.script_inspect(key(&marker("r1")), Ok(FsFileMetadata::new(10, None)));
            fake.script_inspect(key(&marker("r2")), Err(err_case));
            let err = count_repo_blob_memberships_impl(&fake, &d)
                .await
                .unwrap_err();
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::Io),
                "no partial count after a probe failure"
            );
        }
    }

    // ========================================================================
    // Readiness marker and migration checkpoint
    // ========================================================================

    #[tokio::test]
    async fn test_fake_ready_marker_absence_vs_failure() {
        let k = key(READY_MARKER_KEY);

        let fake = RecordingFakeOps::new();
        fake.script_inspect(k.clone(), Ok(FsFileMetadata::new(30, None)));
        assert!(membership_ready_marker_present(&fake).await.unwrap());

        let fake = RecordingFakeOps::new();
        fake.script_inspect(k.clone(), Err(ReadError::not_found(k.clone())));
        assert!(!membership_ready_marker_present(&fake).await.unwrap());

        // Non-regular object at the marker path must not establish readiness.
        let fake = RecordingFakeOps::new();
        fake.script_inspect(
            k.clone(),
            Err(ReadError::backend_with_source(
                "unsupported object type",
                Box::new(storage_fs::FsMetadataError::UnsupportedObjectType {
                    mode: libc::S_IFDIR,
                }),
            )),
        );
        let err = membership_ready_marker_present(&fake).await.unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));

        // Permission and containment failures propagate instead of silently
        // reporting "not ready".
        let fake = RecordingFakeOps::new();
        fake.script_inspect(k.clone(), Err(ReadError::permission_denied(k.clone())));
        let err = membership_ready_marker_present(&fake).await.unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

        let fake = RecordingFakeOps::new();
        fake.script_inspect(k.clone(), Err(rejection(libc::ELOOP)));
        let err = membership_ready_marker_present(&fake).await.unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
    }

    #[tokio::test]
    async fn test_fake_checkpoint_absence_corrupt_and_rejection() {
        let k = key(MIGRATION_CHECKPOINT_KEY);
        let now = 1_700_000_000u64;
        let cp = MigrationCheckpointRecord {
            schema_version: 1,
            phase: MigrationPhase::Applying,
            owner_id: Some("owner".to_string()),
            lease_expiry_unix_secs: Some(now + 60),
            source_continuation_token: Some("repo-a".to_string()),
            current_repository: None,
            current_cursor: None,
            stats: MigrationStats::default(),
            started_unix_secs: now,
            last_updated_unix_secs: now,
            failure_info: None,
            verification_result: None,
        };

        // Valid round-trip preserves continuation and lease fields.
        let fake = RecordingFakeOps::new();
        fake.script_payload(k.clone(), Ok(payload_of(serde_json::to_vec(&cp).unwrap())));
        let read = get_migration_checkpoint_impl(&fake)
            .await
            .unwrap()
            .expect("checkpoint present");
        assert_eq!(read.phase, MigrationPhase::Applying);
        assert_eq!(read.source_continuation_token.as_deref(), Some("repo-a"));
        assert_eq!(read.lease_expiry_unix_secs, Some(now + 60));

        // Genuine absence -> None (only true absence permits fresh migration).
        let fake = RecordingFakeOps::new();
        fake.script_payload(k.clone(), Err(ReadError::not_found(k.clone())));
        assert!(
            get_migration_checkpoint_impl(&fake)
                .await
                .unwrap()
                .is_none()
        );

        // Corrupt -> CorruptData (preserved).
        let fake = RecordingFakeOps::new();
        fake.script_payload(k.clone(), Ok(payload_of(b"{broken".to_vec())));
        let err = get_migration_checkpoint_impl(&fake).await.unwrap_err();
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));

        // Containment rejection must not present as a missing checkpoint.
        for code in [libc::ELOOP, libc::EXDEV] {
            let fake = RecordingFakeOps::new();
            fake.script_payload(k.clone(), Err(rejection(code)));
            let err = get_migration_checkpoint_impl(&fake).await.unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
        }
    }

    // ========================================================================
    // Linux-gated real filesystem tests (production entry points)
    // ========================================================================

    #[cfg(target_os = "linux")]
    mod real_fs_tests {
        use super::*;
        use crate::storage::fs::FsStorage;
        use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

        fn fixture_root() -> (tempfile::TempDir, std::path::PathBuf) {
            let fixture = tempfile::tempdir().expect("create tempdir");
            let root = fixture.path().join("storage_root");
            std::fs::create_dir_all(&root).expect("create storage root");
            (fixture, root)
        }

        async fn seed(storage: &FsStorage, repo: &str, digest: &Digest) {
            storage
                .link_repo_blob(&record_for(repo, digest))
                .await
                .expect("link membership");
        }

        #[tokio::test]
        async fn test_real_membership_roundtrips_pagination_and_count() {
            let (_fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);
            let d1 = digest_n(1);
            let d2 = digest_n(2);
            let d3 = digest_n(3);

            seed(&storage, "alpha", &d1).await;
            seed(&storage, "alpha", &d2).await;
            seed(&storage, "alpha", &d3).await;
            seed(&storage, "org/nested", &d1).await;

            // Point read.
            let rec = storage
                .get_repo_blob_membership("alpha", &d1)
                .await
                .unwrap()
                .expect("record present");
            assert_eq!(rec.digest, d1);
            assert!(
                storage
                    .get_repo_blob_membership("alpha", &digest_n(9))
                    .await
                    .unwrap()
                    .is_none()
            );

            // Per-repo pagination with token continuation.
            let (page1, tok1) = storage
                .list_repo_blob_memberships_page("alpha", None, 2)
                .await
                .unwrap();
            assert_eq!(page1.len(), 2);
            assert_eq!(page1[0].digest, d1);
            assert_eq!(page1[1].digest, d2);
            let tok1 = tok1.expect("more pages");
            let (page2, tok2) = storage
                .list_repo_blob_memberships_page("alpha", Some(&tok1), 2)
                .await
                .unwrap();
            assert_eq!(page2.len(), 1);
            assert_eq!(page2[0].digest, d3);
            assert_eq!(tok2, None);

            // Global listing sees all four records across pages.
            let mut all = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let (recs, next) = storage
                    .list_all_repo_blob_memberships_page(cursor.as_deref(), 3)
                    .await
                    .unwrap();
                all.extend(recs);
                cursor = next;
                if cursor.is_none() {
                    break;
                }
            }
            assert_eq!(all.len(), 4);

            // Counting across repositories.
            assert_eq!(storage.count_repo_blob_memberships(&d1).await.unwrap(), 2);
            assert_eq!(storage.count_repo_blob_memberships(&d2).await.unwrap(), 1);
            assert_eq!(
                storage
                    .count_repo_blob_memberships(&digest_n(9))
                    .await
                    .unwrap(),
                0
            );
        }

        #[tokio::test]
        async fn test_real_symlinked_membership_root_fails_closed_everywhere() {
            let (fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);
            let d = digest_n(1);

            // repo-memberships/by-repo is a symlink to an outside tree that
            // ambient reads would have followed.
            let outside = fixture.path().join("outside_memberships");
            let outside_repo = outside.join(enc("alpha")).join("sha256");
            std::fs::create_dir_all(&outside_repo).unwrap();
            std::fs::write(
                outside_repo.join(format!("{}.json", d.hex())),
                record_bytes("alpha", &d),
            )
            .unwrap();
            std::fs::create_dir_all(root.join("repo-memberships")).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("repo-memberships").join("by-repo"))
                .unwrap();

            // Counting must error, never silently report zero (which would
            // permit blob deletion in blob_gc validation/eligibility).
            let err = storage.count_repo_blob_memberships(&d).await.unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

            // Listings must error, never return empty pages (which would let
            // ledger reconciliation mark an incomplete index ready).
            let err = storage
                .list_all_repo_blob_memberships_page(None, 10)
                .await
                .unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
            let err = storage
                .list_repo_blob_memberships_page("alpha", None, 10)
                .await
                .unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

            // Point reads must error, never report absence. (Phase 6: the
            // point read routes through the shared domain over the pinned
            // adapter, which reports its containment refusal as
            // PermissionDenied — the retired seam said Io; accepted C2.)
            let err = storage
                .get_repo_blob_membership("alpha", &d)
                .await
                .unwrap_err();
            assert_eq!(
                err.internal_kind(),
                Some(StorageErrorKind::PermissionDenied)
            );

            // Actual safety-relevant caller: the storage-only membership
            // ledger propagates instead of answering "no memberships".
            let ledger = crate::repository_membership_ledger::RepositoryMembershipLedger::new(
                std::sync::Arc::new(FsStorage::new(root.clone(), 1024 * 1024)),
                None,
                crate::consistency::ConsistencyCoordinator::new(),
            );
            assert!(ledger.has_any_membership(&d).await.is_err());
        }

        #[tokio::test]
        async fn test_real_checkpoint_and_readiness_production_contracts() {
            let (fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);

            // Absent checkpoint and marker.
            assert!(storage.get_migration_checkpoint().await.unwrap().is_none());
            assert!(!storage.is_membership_ready().await.unwrap());

            // mark_membership_ready round-trip (production writes preserved).
            storage.mark_membership_ready().await.unwrap();
            assert!(storage.is_membership_ready().await.unwrap());
            let cp = storage
                .get_migration_checkpoint()
                .await
                .unwrap()
                .expect("checkpoint persisted");
            assert_eq!(
                cp.phase,
                crate::storage::repo_membership::MigrationPhase::Ready
            );

            // Corrupt checkpoint -> CorruptData (preserved), and readiness
            // fails closed through the checkpoint leg.
            std::fs::write(root.join("meta").join("migration_checkpoint.json"), b"{x").unwrap();
            let err = storage.get_migration_checkpoint().await.unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));
            assert!(storage.is_membership_ready().await.is_err());

            // Symlinked meta/ redirects were previously followed; contained
            // reads reject them and never present a missing checkpoint.
            let (fixture2, root2) = fixture_root();
            let storage2 = FsStorage::new(root2.clone(), 1024 * 1024);
            let outside_meta = fixture2.path().join("outside_meta");
            std::fs::create_dir_all(&outside_meta).unwrap();
            std::fs::write(outside_meta.join("membership_ready.json"), b"{}").unwrap();
            std::os::unix::fs::symlink(&outside_meta, root2.join("meta")).unwrap();
            let err = storage2.get_migration_checkpoint().await.unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
            let err = storage2.is_membership_ready().await.unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

            let _ = fixture;
        }

        #[tokio::test]
        async fn test_real_directory_marker_does_not_establish_readiness() {
            let (_fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);

            // A DIRECTORY at the marker path previously counted as a present
            // marker (ambient existence probe); readiness must now fail closed.
            std::fs::create_dir_all(root.join("meta").join("membership_ready.json")).unwrap();
            let err = storage.is_membership_ready().await.unwrap_err();
            assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));
        }

        #[tokio::test]
        async fn test_real_reconciliation_fails_closed_on_nonregular_candidate() {
            use crate::blob_ref_index::BlobRefIndex;
            use crate::repository_membership_ledger::RepositoryMembershipLedger;

            let (_fixture, root) = fixture_root();
            let storage = std::sync::Arc::new(FsStorage::new(root.clone(), 1024 * 1024));
            let d1 = digest_n(1);
            seed(&storage, "alpha", &d1).await;

            // Control: rebuild initializes the reverse index (schema + ready
            // state) from valid records; actual reconciliation then succeeds
            // and the index stays healthy with the membership present.
            let idx_dir = tempfile::tempdir().unwrap();
            let idx = std::sync::Arc::new(
                BlobRefIndex::open(idx_dir.path().join("idx")).expect("open index"),
            );
            idx.rebuild(storage.as_ref())
                .await
                .expect("initial rebuild succeeds on valid records");
            idx.check_health().expect("index ready after rebuild");
            assert!(idx.has_any_repo_membership(&d1).unwrap());

            let ledger = RepositoryMembershipLedger::new(
                storage.clone(),
                Some(idx.clone()),
                crate::consistency::ConsistencyCoordinator::new(),
            );
            ledger
                .reconcile_memberships()
                .await
                .expect("control reconciliation succeeds on valid records");
            idx.check_health().expect("index remains healthy");

            // Poison: a directory named as a qualifying membership record.
            let d2 = digest_n(2);
            let bad = root
                .join("repo-memberships")
                .join("by-repo")
                .join(enc("alpha"))
                .join("sha256")
                .join(format!("{}.json", d2.hex()));
            std::fs::create_dir_all(&bad).unwrap();

            // Actual reconciliation against the real reverse index fails
            // closed. The previously-ready index keeps its earlier
            // legitimately built state: reconcile is additive (it clears
            // nothing and mark_ready is only reached after complete
            // discovery), so its ready state reflects the earlier complete
            // rebuild, not the failed run — no rollback is claimed or needed.
            assert!(
                ledger.reconcile_memberships().await.is_err(),
                "reconciliation must fail closed on a nonregular record candidate"
            );
            idx.check_health()
                .expect("prior legitimate ready state is preserved");
            assert!(idx.has_any_repo_membership(&d1).unwrap());
            assert!(!idx.has_any_repo_membership(&d2).unwrap());

            // A never-ready index must not become ready from the failed,
            // incomplete discovery.
            let idx2_dir = tempfile::tempdir().unwrap();
            let idx2 = std::sync::Arc::new(
                BlobRefIndex::open(idx2_dir.path().join("idx2")).expect("open second index"),
            );
            assert!(idx2.check_health().is_err(), "fresh index is not ready");
            let ledger2 = RepositoryMembershipLedger::new(
                storage.clone(),
                Some(idx2.clone()),
                crate::consistency::ConsistencyCoordinator::new(),
            );
            assert!(ledger2.reconcile_memberships().await.is_err());
            assert!(
                idx2.check_health().is_err(),
                "failed incomplete reconciliation must not establish readiness"
            );
        }

        #[tokio::test]
        async fn test_real_pinned_root_replacement() {
            let (fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);
            let d = digest_n(1);
            seed(&storage, "alpha", &d).await;
            storage.mark_membership_ready().await.unwrap();

            // Replace the root pathname with a divergent tree.
            let renamed = fixture.path().join("storage_root_old");
            std::fs::rename(&root, &renamed).unwrap();
            std::fs::create_dir_all(&root).unwrap();

            // Contained reads keep observing the original pinned tree.
            assert!(
                storage
                    .get_repo_blob_membership("alpha", &d)
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(storage.count_repo_blob_memberships(&d).await.unwrap(), 1);
            assert!(storage.is_membership_ready().await.unwrap());
            assert!(storage.get_migration_checkpoint().await.unwrap().is_some());
        }
    }
}
