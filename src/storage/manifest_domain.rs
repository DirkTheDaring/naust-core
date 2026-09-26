//! Shared registry manifest-domain implementation over the backend-neutral
//! [`ObjectStore`] contract (STORAGE-LAYER-MIGRATION Phase 4).
//!
//! This is the ONE registry implementation of manifest object semantics. It
//! owns:
//! - the `(repository, digest)` → [`ObjectKey`] mapping
//!   (`repos/<repo>/manifests/<digest.hex()>`, the accepted physical layout
//!   of both backends — bare lowercase hex, no algorithm prefix, no suffix);
//! - payload reads (full buffering, absent → `NotFound`), media-type
//!   detection from the payload bytes, and `ManifestMeta` production
//!   (`size` = bytes actually read);
//! - unconditional durable publication (`Durability::Durable` — the
//!   accepted FS contained atomic durable write; S3 satisfies it with one
//!   acknowledged PUT);
//! - the manifest-deletion payload steps with their frozen ordering and
//!   taxonomy (pre-read → subject extraction → payload delete), leaving tag
//!   cleanup to the accepted Phase 3 shared tag domain and referrer cleanup
//!   to the existing unmigrated-family port invoked by the backend wrapper;
//! - bounded digest listing with the common contract (canonical-hex names,
//!   sha256/sha512 by length, strictly-after `digest.as_str()` tokens).
//!
//! Filesystem containment and S3 request mechanics stay below the
//! [`ObjectStore`] boundary; OCI/Docker manifest PARSING policy beyond
//! media-type detection and subject extraction stays with the callers.
//!
//! # Preserved historical semantics (both retired backends agreed)
//! - reads/head are FULL payload reads (media type is parsed from the JSON
//!   body; a malformed payload fails `head_manifest` too, `CorruptData`);
//! - reads are UNBOUNDED (the documented pre-existing operational
//!   limitation is preserved — no new resource policy is introduced for
//!   manifest payloads; `u64::MAX` is passed as the read ceiling);
//! - `put_manifest` detects the media type BEFORE writing (malformed JSON
//!   publishes nothing) and performs NO digest-vs-bytes verification —
//!   content-address integrity is enforced by the publication layer
//!   (`publish_internal` writes under its own computed digest);
//! - `put_manifest` is an UNCONDITIONAL last-writer-wins publication (no
//!   compare-and-swap existed on either backend; same-digest republication
//!   rewrites identical canonical bytes);
//! - `delete_manifest`: absent → `NotFound` (the pre-read gates existence);
//!   a manifest whose structure `extract_subject_digest` cannot parse is
//!   undeletable (`CorruptData`, frozen taxonomy); the payload delete is
//!   idempotent-at-the-backend and NOT version-conditional (content-
//!   addressed payloads have no supported replacement contract — digest
//!   verification upstream makes a same-key different-byte replacement
//!   unreachable through supported publication);
//! - listing: absent repository/namespace → empty terminal page;
//!   `page_limit == 0` → empty page before any enumeration; malformed names
//!   silently skipped; sorted by digest with strictly-after resumption.
//!
//! # Converged listing rows (see the Phase 4 semantic matrix)
//! The retired S3 listing dropped bare-hex sha512 manifests entirely (a GC
//! protection defect), sorted by hex while resuming tokens by
//! `algo:hex`, never deduplicated, accepted legacy `*.json`/`algo:hex` key
//! shapes no supported writer ever produced, and drained the prefix
//! unboundedly. The shared implementation is the FS contract: canonical
//! 64/128 lowercase-hex leaf names, `Digest`-ordered, deduplicated,
//! `digest.as_str()` tokens, bounded collection with a truthful error.

use std::sync::Arc;

use storage_core::ObjectKey;
use storage_core::object_store::{Durability, ObjectStore, StoreError, adapter};

use crate::registry::digest::Digest;
use crate::storage::tag_domain::TagDomain;

use super::{ManifestMeta, StorageError};

/// Internal page size for listing collection round trips.
const LIST_PAGE_SIZE: usize = 1000;

/// Default ceiling on manifest-namespace rows observed by one listing pass
/// (mirrors the accepted FS manifest-listing enumeration bound; backends
/// without their own configured bound — S3 — wire this; the retired S3
/// listing drained without bound).
pub(crate) const DEFAULT_MAX_LISTING_ENTRIES: usize = usize::MAX;

/// Manifest payload reads are deliberately unbounded: both retired backends
/// buffered complete payloads without a ceiling (a documented pre-existing
/// operational limitation), and Phase 4 preserves that contract rather than
/// introducing a new externally visible resource policy.
const MANIFEST_READ_CEILING: u64 = u64::MAX;

/// Backend-neutral manifest-domain resource policy, supplied by each
/// storage backend at wiring time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ManifestDomainConfig {
    /// Ceiling on manifest-namespace rows observed by one listing pass.
    /// Obsolete with streaming pagination; retained for backwards-compatible wiring.
    #[allow(dead_code)]
    pub max_listing_entries: usize,
}

/// Constructs the relative [`ObjectKey`] for a repository manifest:
/// `repos/<repository>/manifests/<digest.hex()>` (moved verbatim from the
/// retired `fs::manifest` seam; identical to the retired S3 key modulo the
/// adapter's configured prefix).
///
/// Validation rejects empty repositories, leading/trailing slashes,
/// backslashes, NUL/control characters, empty segments, and `.`/`..`
/// segments — failing closed with [`StorageError::InvalidRepoName`] before
/// any backend access. Canonical OCI repository grammar remains a
/// higher-layer concern.
pub(crate) fn manifest_key(repo: &str, digest: &Digest) -> Result<ObjectKey, StorageError> {
    validate_repo(repo)?;
    let key_str = format!("repos/{repo}/manifests/{}", digest.hex());
    ObjectKey::parse(&key_str).map_err(|e| StorageError::InvalidRepoName(e.to_string()))
}

/// Listing prefix mapping: `repos/<repository>/manifests`.
fn manifests_dir_key(repo: &str) -> Result<ObjectKey, StorageError> {
    validate_repo(repo)?;
    let key_str = format!("repos/{repo}/manifests");
    ObjectKey::parse(&key_str).map_err(|e| StorageError::InvalidRepoName(e.to_string()))
}

fn validate_repo(repo: &str) -> Result<(), StorageError> {
    if repo.is_empty() {
        return Err(StorageError::InvalidRepoName(
            "repository name cannot be empty".to_string(),
        ));
    }
    if repo.starts_with('/') || repo.ends_with('/') {
        return Err(StorageError::InvalidRepoName(
            "repository name cannot have leading or trailing slashes".to_string(),
        ));
    }
    if repo.contains('\\') {
        return Err(StorageError::InvalidRepoName(
            "repository name cannot contain backslashes".to_string(),
        ));
    }
    if repo.contains(|c: char| c == '\0' || c.is_ascii_control()) {
        return Err(StorageError::InvalidRepoName(
            "repository name cannot contain NUL bytes or control characters".to_string(),
        ));
    }
    for segment in repo.split('/') {
        if segment.is_empty() {
            return Err(StorageError::InvalidRepoName(
                "repository name cannot contain empty segments (repeated slashes)".to_string(),
            ));
        }
        if segment == "." {
            return Err(StorageError::InvalidRepoName(
                "repository name cannot contain '.' segments".to_string(),
            ));
        }
        if segment == ".." {
            return Err(StorageError::InvalidRepoName(
                "repository name cannot contain '..' segments (path traversal attempt)".to_string(),
            ));
        }
    }
    Ok(())
}

/// Detects the media type of a manifest payload (moved verbatim from the
/// retired duplicated FS/S3 helpers):
/// - JSON object with a top-level string `"mediaType"` → that value;
/// - any other valid JSON (missing/non-string field, scalars, arrays) →
///   `application/vnd.oci.image.manifest.v1+json`;
/// - empty or malformed non-JSON payload → `CorruptData`.
pub(crate) fn detect_manifest_media_type(bytes: &[u8]) -> Result<String, StorageError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|err| StorageError::corrupt_data(err.to_string()))?;
    let media_type = value
        .get("mediaType")
        .and_then(|v| v.as_str())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json");
    Ok(media_type.to_string())
}

/// ONE common translation of generic store failures into the registry error
/// taxonomy for manifest operations. Absence never reaches this function
/// (it is structural in the [`ObjectStore`] contract).
fn translate_store_error(err: StoreError, what: &str) -> StorageError {
    match err {
        // Unreachable for manifest payloads (reads pass u64::MAX); kept
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

/// Reads the complete manifest payload and derives metadata.
///
/// Frozen contract: absent → [`StorageError::NotFound`]; full buffering;
/// `size` = bytes actually read; media type parsed from the payload
/// (malformed JSON → `CorruptData`); no digest verification of read bytes.
pub(crate) async fn get_manifest(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
) -> Result<(ManifestMeta, bytes::Bytes), StorageError> {
    let key = manifest_key(repo, digest)?;
    let read = store
        .read(&key, MANIFEST_READ_CEILING)
        .await
        .map_err(|e| translate_store_error(e, "manifest read"))?;
    let Some(read) = read else {
        return Err(StorageError::NotFound);
    };
    let media_type = detect_manifest_media_type(&read.bytes)?;
    let size = read.bytes.len() as u64;
    Ok((ManifestMeta { size, media_type }, read.bytes))
}

/// Reads the complete payload and discards the bytes (frozen full-read
/// semantics: media type comes from the body, so `head` fails on malformed
/// payloads exactly like `get`).
pub(crate) async fn head_manifest(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
) -> Result<ManifestMeta, StorageError> {
    let (meta, _bytes) = get_manifest(store, repo, digest).await?;
    Ok(meta)
}

/// Publishes a manifest payload.
///
/// Frozen contract: media type detected BEFORE the write (malformed JSON
/// publishes nothing, `CorruptData`); unconditional last-writer-wins
/// publication with [`Durability::Durable`] (the accepted FS contained
/// atomic durable write; S3 = one acknowledged PUT); no digest-vs-bytes
/// verification (content-address integrity is the publication layer's
/// contract — `publish_internal` writes under its own computed digest).
pub(crate) async fn put_manifest(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
    bytes: bytes::Bytes,
) -> Result<ManifestMeta, StorageError> {
    let key = manifest_key(repo, digest)?;
    let media_type = detect_manifest_media_type(&bytes)?;
    let size = bytes.len() as u64;
    store
        .write(&key, bytes, Durability::Durable)
        .await
        .map_err(|e| translate_store_error(e, "manifest publication"))?;
    Ok(ManifestMeta { size, media_type })
}

/// The manifest-deletion PAYLOAD steps with their frozen ordering and
/// taxonomy:
/// 1. pre-read the payload (absent → [`StorageError::NotFound`] — deletion
///    of an absent manifest is not idempotent at this layer);
/// 2. extract the optional OCI `subject` for the caller's referrer cleanup
///    (structurally malformed manifest → `CorruptData`
///    "cannot delete manifest with malformed structure", i.e. undeletable —
///    the frozen contract on both retired backends);
/// 3. delete the payload object (idempotent at the backend; deliberately
///    NOT version-conditional: manifest payloads are content-addressed and
///    supported publication verifies digests upstream, so a same-key
///    different-byte replacement is unreachable — no coordination is
///    invented, per the accepted Phase 4 analysis).
///
/// Returns the extracted subject so the BACKEND WRAPPER can invoke the
/// existing unmigrated-family referrer cleanup as the final best-effort
/// step, preserving the frozen side-effect ordering
/// (payload → tags → referrers) without pulling referrer policy into this
/// module.
pub(crate) async fn delete_manifest_payload(
    store: &dyn ObjectStore,
    repo: &str,
    digest: &Digest,
) -> Result<Option<Digest>, StorageError> {
    let key = manifest_key(repo, digest)?;
    let read = store
        .read(&key, MANIFEST_READ_CEILING)
        .await
        .map_err(|e| translate_store_error(e, "manifest read"))?;
    let Some(read) = read else {
        return Err(StorageError::NotFound);
    };
    let maybe_subject = crate::manifest_refs::extract_subject_digest(&read.bytes).map_err(|e| {
        StorageError::corrupt_data(format!(
            "cannot delete manifest with malformed structure: {e}"
        ))
    })?;
    store
        .delete(&key)
        .await
        .map_err(|e| translate_store_error(e, "manifest deletion"))?;
    Ok(maybe_subject)
}

/// Bounded digest listing (`list_manifest_digests_page`).
///
/// Frozen logical contract (the FS contract, which the retired S3 listing
/// approximated with the defects documented in the module header):
/// - `page_limit == 0` → empty terminal page before any enumeration;
/// - absent repository/namespace → empty terminal page;
/// - candidates are REGULAR objects (structural filtering below the
///   boundary) whose leaf names are canonical lowercase hex — 64 chars →
///   sha256, 128 chars → sha512; dot-prefixed leaves (legacy `.tmp.*` /
///   `.lock.*` artifacts) and every other shape are silently skipped;
/// - digests are sorted (`Digest` order), deduplicated, and paginated with
///   strictly-after `digest.as_str()` tokens (a vanished token still
///   resumes at the correct position);
/// - collection is bounded by `cfg.max_listing_entries` observed rows with
///   a truthful error on exhaustion — never a silent end-of-list.
pub(crate) async fn list_manifest_digests_page(
    store: &dyn ObjectStore,
    _cfg: &ManifestDomainConfig,
    repo: &str,
    continuation_token: Option<&str>,
    page_limit: usize,
) -> Result<(Vec<Digest>, Option<String>), StorageError> {
    let dir = manifests_dir_key(repo)?;
    if page_limit == 0 {
        return Ok((Vec::new(), None));
    }

    let target_count = page_limit.saturating_add(1);
    let page_size = std::num::NonZeroUsize::new(LIST_PAGE_SIZE).expect("nonzero page size");

    enum TokenPosition<'a> {
        Start,
        WithinSha256(&'a str),
        StartSha512,
        WithinSha512(&'a str),
        PastEnd,
    }

    let token_pos = match continuation_token {
        None => TokenPosition::Start,
        Some(token) => {
            if let Some(hex) = token.strip_prefix("sha256:") {
                TokenPosition::WithinSha256(hex.trim())
            } else if let Some(hex) = token.strip_prefix("sha512:") {
                TokenPosition::WithinSha512(hex.trim())
            } else if token < "sha256:" {
                TokenPosition::Start
            } else if token < "sha512:" {
                TokenPosition::StartSha512
            } else {
                TokenPosition::PastEnd
            }
        }
    };

    if let TokenPosition::PastEnd = token_pos {
        return Ok((Vec::new(), None));
    }

    if matches!(
        token_pos,
        TokenPosition::WithinSha512(_) | TokenPosition::StartSha512
    ) {
        let mut collected: Vec<Digest> = Vec::with_capacity(target_count.min(1024));
        let mut token = match token_pos {
            TokenPosition::WithinSha512(after_hex) => {
                Some(adapter::page_token(after_hex.to_ascii_lowercase()))
            }
            _ => None,
        };

        'sha512_resume: loop {
            let page = store
                .list_page(Some(&dir), token.as_ref(), page_size)
                .await
                .map_err(|e| translate_store_error(e, "manifest listing"))?;
            if page.objects.is_empty() {
                break 'sha512_resume;
            }
            let has_more = page.next.is_some();
            for row in page.objects {
                let name = row.leaf.as_str();
                if name.len() == 128 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                {
                    if let Ok(digest) = Digest::parse(&format!("sha512:{name}")) {
                        collected.push(digest);
                        if collected.len() == target_count {
                            break 'sha512_resume;
                        }
                    }
                }
            }
            if has_more {
                token = page.next;
            } else {
                break 'sha512_resume;
            }
        }

        if collected.len() > page_limit {
            collected.truncate(page_limit);
            let next_token = collected.last().map(|d| d.as_str());
            return Ok((collected, next_token));
        } else {
            return Ok((collected, None));
        }
    }

    let mut token = match token_pos {
        TokenPosition::WithinSha256(after_hex) => {
            Some(adapter::page_token(after_hex.to_ascii_lowercase()))
        }
        _ => None,
    };

    let mut collected_sha256: Vec<Digest> = Vec::with_capacity(target_count.min(1024));
    let mut collected_sha512: Vec<Digest> = Vec::with_capacity(target_count.min(1024));
    let mut directory_reached_eof = false;

    'sha256_loop: loop {
        let page = store
            .list_page(Some(&dir), token.as_ref(), page_size)
            .await
            .map_err(|e| translate_store_error(e, "manifest listing"))?;
        if page.objects.is_empty() {
            directory_reached_eof = true;
            break 'sha256_loop;
        }
        let has_more = page.next.is_some();
        for row in page.objects {
            let name = row.leaf.as_str();
            if !name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                continue;
            }
            if name.len() == 64 {
                if let Ok(digest) = Digest::parse(&format!("sha256:{name}")) {
                    collected_sha256.push(digest);
                    if collected_sha256.len() == target_count {
                        break 'sha256_loop;
                    }
                }
            } else if name.len() == 128 && matches!(token_pos, TokenPosition::Start) {
                if collected_sha512.len() < target_count {
                    if let Ok(digest) = Digest::parse(&format!("sha512:{name}")) {
                        collected_sha512.push(digest);
                    }
                }
            }
        }
        if has_more {
            token = page.next;
        } else {
            directory_reached_eof = true;
            break 'sha256_loop;
        }
    }

    if collected_sha256.len() > page_limit {
        collected_sha256.truncate(page_limit);
        let next_token = collected_sha256.last().map(|d| d.as_str());
        return Ok((collected_sha256, next_token));
    }

    if directory_reached_eof && matches!(token_pos, TokenPosition::Start) {
        collected_sha256.extend(collected_sha512);
        if collected_sha256.len() > page_limit {
            collected_sha256.truncate(page_limit);
            let next_token = collected_sha256.last().map(|d| d.as_str());
            return Ok((collected_sha256, next_token));
        } else {
            return Ok((collected_sha256, None));
        }
    }

    if collected_sha256.len() < target_count {
        let mut token = None;
        'sha512_fresh: loop {
            let page = store
                .list_page(Some(&dir), token.as_ref(), page_size)
                .await
                .map_err(|e| translate_store_error(e, "manifest listing"))?;
            if page.objects.is_empty() {
                break 'sha512_fresh;
            }
            let has_more = page.next.is_some();
            for row in page.objects {
                let name = row.leaf.as_str();
                if name.len() == 128 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                {
                    if let Ok(digest) = Digest::parse(&format!("sha512:{name}")) {
                        collected_sha256.push(digest);
                        if collected_sha256.len() == target_count {
                            break 'sha512_fresh;
                        }
                    }
                }
            }
            if has_more {
                token = page.next;
            } else {
                break 'sha512_fresh;
            }
        }
    }

    if collected_sha256.len() > page_limit {
        collected_sha256.truncate(page_limit);
        let next_token = collected_sha256.last().map(|d| d.as_str());
        Ok((collected_sha256, next_token))
    } else {
        Ok((collected_sha256, None))
    }
}

/// Transitional wiring container: the backend-neutral handle each storage
/// backend exposes for its migrated manifest family.
#[derive(Clone)]
pub(crate) struct ManifestDomain {
    store: Arc<dyn ObjectStore>,
    cfg: ManifestDomainConfig,
}

impl std::fmt::Debug for ManifestDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestDomain")
            .field("cfg", &self.cfg)
            .finish()
    }
}

impl ManifestDomain {
    pub(crate) fn new(store: Arc<dyn ObjectStore>, cfg: ManifestDomainConfig) -> Self {
        Self { store, cfg }
    }

    pub(crate) async fn get_manifest(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<(ManifestMeta, bytes::Bytes), StorageError> {
        get_manifest(self.store.as_ref(), repo, digest).await
    }

    pub(crate) async fn head_manifest(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<ManifestMeta, StorageError> {
        head_manifest(self.store.as_ref(), repo, digest).await
    }

    pub(crate) async fn put_manifest(
        &self,
        repo: &str,
        digest: &Digest,
        bytes: bytes::Bytes,
    ) -> Result<ManifestMeta, StorageError> {
        put_manifest(self.store.as_ref(), repo, digest, bytes).await
    }

    /// Frozen manifest-deletion orchestration minus the final referrer step:
    /// payload steps (pre-read → subject extraction → payload delete), then
    /// the accepted Phase 3 replacement-safe shared tag cleanup. Returns the
    /// extracted subject; the backend wrapper performs the existing
    /// best-effort referrer cleanup LAST (unmigrated-family boundary).
    pub(crate) async fn delete_manifest(
        &self,
        tags: &TagDomain,
        repo: &str,
        digest: &Digest,
    ) -> Result<Option<Digest>, StorageError> {
        let maybe_subject = delete_manifest_payload(self.store.as_ref(), repo, digest).await?;
        let digest_str = digest.as_str();
        tags.delete_manifest_tag_cleanup(repo, &digest_str).await?;
        Ok(maybe_subject)
    }

    pub(crate) async fn list_manifest_digests_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<Digest>, Option<String>), StorageError> {
        list_manifest_digests_page(
            self.store.as_ref(),
            &self.cfg,
            repo,
            continuation_token,
            page_limit,
        )
        .await
    }
}

#[cfg(test)]
#[path = "manifest_domain_tests.rs"]
mod tests;
