//! Contained manifest-reference collection for filesystem GC.
//!
//! # Architecture and Scope
//!
//! This module implements contained manifest reference collection for filesystem
//! garbage collection reachability in `naust`. It enumerates terminal directories
//! discovered by [`super::repo_discovery::discover_manifest_dirs_impl`], reads manifest payloads
//! using the pinned root descriptor via [`naust_storage_fs::FsMetadataReader`], and extracts protected digests.
//!
//! # Contract and Topology
//!
//! - **Inputs**: Takes observed terminal manifest directory [`ObjectKey`]s produced
//!   by [`super::repo_discovery::discover_manifest_dirs_impl`].
//! - **Reader Topology**: Uses the same [`ManifestRefReader`] instance across directory
//!   discovery, terminal directory enumeration, and payload opening beneath the pinned
//!   root descriptor.
//! - **Path Handling**: Directly composes child [`ObjectKey`]s (`${dir_key}/${filename}`)
//!   without routing through repository-name parsers or passing empty strings.
//! - **Filename Validation**: Supports canonical lowercase 64-character SHA-256 and
//!   128-character SHA-512 filenames as an experimental compatibility choice.
//! - **Reference Extraction**: Parses payloads via canonical [`parse_manifest_refs`]
//!   and records manifest roots and referenced digests without recursive fetching.
//! - **Failure Atomicity**: Any error halts the scan immediately and returns `Err`;
//!   zero partial successful sets are returned.

use async_trait::async_trait;
use naust_storage_core::{ObjectKey, ObjectPayloadReader, ReadError};
use naust_storage_fs::{DirEntryType, DirEnumerationLimits, FsDirError, FsMetadataError};
use std::collections::HashSet;
use tokio::io::AsyncReadExt;

use crate::manifest_refs::parse_manifest_refs;
use crate::registry::digest::Digest;
use crate::storage::StorageError;

/// Unified test-only reader abstraction composing directory enumeration with payload reading.
#[async_trait]
pub(crate) trait ManifestRefReader:
    super::repo_discovery::DiscoveryDirEnumerator + ObjectPayloadReader
{
}

impl<T> ManifestRefReader for T where
    T: super::repo_discovery::DiscoveryDirEnumerator + ObjectPayloadReader + ?Sized
{
}

/// Caller-supplied limits for manifest reference collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestReferenceLimits {
    /// Maximum directory enumeration calls across all terminal directories.
    pub max_terminal_dir_enumerations: usize,
    /// Per-directory limits passed to each `reader.enumerate_dir` call.
    pub per_dir_limits: DirEnumerationLimits,
    /// Maximum directory entries inspected across all terminal directories combined.
    pub max_total_manifest_entries: usize,
    /// Maximum manifest payload files opened and parsed.
    pub max_manifests_read: usize,
    /// Maximum unique digests permitted in the protected reference set.
    pub max_total_references: usize,
    /// Maximum cumulative logical path and digest bytes retained.
    pub max_retained_logical_bytes: usize,
    /// Optional ceiling on single manifest payload size.
    pub max_manifest_payload_bytes: Option<u64>,
}

/// Backward compatibility alias for test code.
#[allow(dead_code)]
pub(crate) type ManifestReferenceTestLimits = ManifestReferenceLimits;

impl ManifestReferenceLimits {
    /// Effectively unbounded limits preserving ambient reference extraction without artificial caps.
    pub(crate) fn unbounded() -> Self {
        Self {
            max_terminal_dir_enumerations: usize::MAX,
            per_dir_limits: DirEnumerationLimits::new(usize::MAX, usize::MAX),
            max_total_manifest_entries: usize::MAX,
            max_manifests_read: usize::MAX,
            max_total_references: usize::MAX,
            max_retained_logical_bytes: usize::MAX,
            max_manifest_payload_bytes: None,
        }
    }
}

impl Default for ManifestReferenceLimits {
    fn default() -> Self {
        Self::unbounded()
    }
}

#[cfg(test)]
impl ManifestReferenceLimits {
    /// Returns liberal limits suitable for functional unit and integration tests.
    pub fn test_default() -> Self {
        Self {
            max_terminal_dir_enumerations: 10_000,
            per_dir_limits: DirEnumerationLimits::new(10_000, 1_500_000),
            max_total_manifest_entries: 50_000,
            max_manifests_read: 10_000,
            max_total_references: 100_000,
            max_retained_logical_bytes: 10_000_000,
            max_manifest_payload_bytes: None,
        }
    }
}

/// Accumulated reference collection results and accounting metrics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManifestReferenceObservationSet {
    /// Deduplicated set of all observed protected digests (roots + references).
    pub protected_digests: HashSet<Digest>,
    /// Exact count of terminal directories where enumeration was attempted.
    pub terminal_dirs_enumerated: usize,
    /// Exact count of manifest files successfully opened, read, and parsed.
    pub manifests_parsed: usize,
    /// Exact total directory entries inspected across all terminal directories.
    pub total_dirents_observed: usize,
    /// Total logical bytes accounted across seen object keys and protected digests.
    pub retained_logical_bytes: usize,
    /// Cumulative payload bytes read across all manifests.
    pub total_payload_bytes_read: u64,
}

/// Internal state tracker enforcing checked resource accounting.
struct ReferenceAccountingTracker {
    terminal_dirs_enumerated: usize,
    manifests_read: usize,
    total_dirents_observed: usize,
    retained_logical_bytes: usize,
    total_payload_bytes_read: u64,
    seen_terminal_dirs: HashSet<ObjectKey>,
    seen_manifest_keys: HashSet<ObjectKey>,
    protected_digests: HashSet<Digest>,
}

impl ReferenceAccountingTracker {
    fn new() -> Self {
        Self {
            terminal_dirs_enumerated: 0,
            manifests_read: 0,
            total_dirents_observed: 0,
            retained_logical_bytes: 0,
            total_payload_bytes_read: 0,
            seen_terminal_dirs: HashSet::new(),
            seen_manifest_keys: HashSet::new(),
            protected_digests: HashSet::new(),
        }
    }

    fn charge_retained_bytes(
        &mut self,
        bytes: usize,
        max_bytes: usize,
    ) -> Result<(), StorageError> {
        let next = self
            .retained_logical_bytes
            .checked_add(bytes)
            .ok_or_else(|| StorageError::backend("retained_logical_bytes arithmetic overflow"))?;
        if next > max_bytes {
            return Err(StorageError::backend(format!(
                "retained_logical_bytes limit exceeded: {next} > {max_bytes}"
            )));
        }
        self.retained_logical_bytes = next;
        Ok(())
    }

    fn retain_digest(
        &mut self,
        digest: Digest,
        limits: &ManifestReferenceTestLimits,
    ) -> Result<(), StorageError> {
        if self.protected_digests.contains(&digest) {
            // Duplicate digests remain acceptable when unique-reference limit is reached.
            return Ok(());
        }

        let next_count = self
            .protected_digests
            .len()
            .checked_add(1)
            .ok_or_else(|| StorageError::backend("protected_digests count overflow"))?;
        if next_count > limits.max_total_references {
            return Err(StorageError::backend(format!(
                "max_total_references exceeded: {next_count} > {}",
                limits.max_total_references
            )));
        }

        let d_bytes = digest.as_str().len();
        self.charge_retained_bytes(d_bytes, limits.max_retained_logical_bytes)?;
        self.protected_digests.insert(digest);
        Ok(())
    }
}

/// Translates strongly typed [`FsDirError`] outcomes into [`StorageError`].
fn translate_terminal_dir_error(err: FsDirError, dir_key: &ObjectKey) -> StorageError {
    match err {
        FsDirError::NotFound { .. } => StorageError::io(format!(
            "observed terminal directory vanished before enumeration: {dir_key}"
        )),
        FsDirError::NotADirectory { path } => StorageError::corrupt_data(format!(
            "terminal path is not a directory ({path:?}): {dir_key}"
        )),
        FsDirError::PermissionDenied { source, .. } => StorageError::permission_denied(format!(
            "permission denied enumerating terminal directory {dir_key}: {source}"
        )),
        FsDirError::ResolutionRejected { source, .. } => StorageError::io(format!(
            "path resolution rejected for terminal directory {dir_key}: {source}"
        )),
        FsDirError::SyscallUnsupported(source) => StorageError::configuration(format!(
            "openat2 is unavailable in this execution environment for {dir_key}: {source}"
        )),
        FsDirError::PlatformUnsupported => StorageError::configuration(format!(
            "platform unsupported: descriptor-relative containment requires Linux openat2 for {dir_key}"
        )),
        FsDirError::LimitExceeded { reason } => StorageError::backend(format!(
            "terminal enumeration resource limit exceeded for {dir_key}: {reason:?}"
        )),
        FsDirError::EntryDisappeared { name } => StorageError::io(format!(
            "directory entry disappeared during inspection in {dir_key}: {name:?}"
        )),
        FsDirError::Io { source } => StorageError::io(format!(
            "I/O error enumerating terminal directory {dir_key}: {source}"
        )),
        FsDirError::RuntimeMissing(err) => StorageError::backend(format!(
            "tokio runtime missing during enumeration of {dir_key}: {err}"
        )),
        FsDirError::TaskJoinFailed(err) => StorageError::backend(format!(
            "blocking enumeration task join failed for {dir_key}: {err}"
        )),
        other => StorageError::backend(format!(
            "unexpected directory enumeration error for {dir_key}: {other}"
        )),
    }
}

/// Translates strongly typed [`ReadError`] outcomes into [`StorageError`], inspecting
/// typed `FsMetadataError` source variants through downcasts.
fn translate_manifest_payload_error(err: ReadError, manifest_key: &ObjectKey) -> StorageError {
    match err {
        ReadError::NotFound { .. } => StorageError::io(format!(
            "observed manifest payload vanished before opening: {manifest_key}"
        )),
        ReadError::PermissionDenied { source, .. } => StorageError::permission_denied(format!(
            "permission denied opening manifest payload {manifest_key}: {source:?}"
        )),
        ReadError::Backend {
            message, source, ..
        } => {
            if let Some(src) = source.as_ref() {
                if let Some(fs_err) = src.downcast_ref::<FsMetadataError>() {
                    match fs_err {
                        FsMetadataError::UnsupportedObjectType { mode, .. } => {
                            return StorageError::corrupt_data(format!(
                                "target is not a regular file (mode: {mode:#o}): {manifest_key}"
                            ));
                        }
                        FsMetadataError::ResolutionRejected { source, .. } => {
                            return StorageError::io(format!(
                                "path resolution rejected for manifest payload {manifest_key}: {source}"
                            ));
                        }
                        FsMetadataError::SyscallUnsupported(io_err) => {
                            return StorageError::configuration(format!(
                                "openat2 is unavailable in this execution environment for {manifest_key}: {io_err}"
                            ));
                        }
                        FsMetadataError::PlatformUnsupported => {
                            return StorageError::configuration(format!(
                                "platform unsupported: descriptor-relative containment requires Linux openat2 for {manifest_key}"
                            ));
                        }
                        FsMetadataError::RuntimeMissing(err) => {
                            return StorageError::backend(format!(
                                "tokio runtime missing for payload acquisition of {manifest_key}: {err}"
                            ));
                        }
                        FsMetadataError::TaskJoinFailed(err) => {
                            return StorageError::backend(format!(
                                "blocking task join failed for payload acquisition of {manifest_key}: {err}"
                            ));
                        }
                        FsMetadataError::ProcfsReopenFailed { source } => {
                            return StorageError::io(format!(
                                "failed to reopen descriptor via procfs for {manifest_key}: {source}"
                            ));
                        }
                        FsMetadataError::IdentityMismatch { .. } => {
                            return StorageError::io(format!(
                                "descriptor identity mismatch during procfs reopen for {manifest_key}"
                            ));
                        }
                        FsMetadataError::StatFailed { stage, source } => {
                            return StorageError::io(format!(
                                "failed to stat {stage} descriptor for {manifest_key}: {source}"
                            ));
                        }
                        other_fs => {
                            return StorageError::backend(format!(
                                "storage metadata backend error for {manifest_key}: {other_fs}"
                            ));
                        }
                    }
                }
                if let Some(io_err) = src.downcast_ref::<std::io::Error>() {
                    return StorageError::io(format!(
                        "I/O error opening manifest payload {manifest_key}: {io_err}"
                    ));
                }
                return StorageError::backend(format!(
                    "payload acquisition backend error for {manifest_key} ({message}): {src}"
                ));
            }
            StorageError::backend(format!(
                "payload acquisition backend error for {manifest_key}: {message}"
            ))
        }
        other => StorageError::backend(format!(
            "unexpected payload read error for {manifest_key}: {other}"
        )),
    }
}

/// Reads a payload stream to completion with optional sentinel-byte oversize detection.
async fn read_payload_stream_bounded<S>(
    mut stream: S,
    max_bytes: Option<u64>,
    manifest_key: &ObjectKey,
) -> Result<Vec<u8>, StorageError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let Some(limit) = max_bytes else {
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.map_err(|e| {
            StorageError::io(format!(
                "I/O error reading manifest payload stream {manifest_key}: {e}"
            ))
        })?;
        return Ok(buf);
    };

    let sentinel_limit = limit
        .checked_add(1)
        .ok_or_else(|| StorageError::backend("payload ceiling limit arithmetic overflow"))?;

    let mut buf = Vec::new();
    let mut take_stream = stream.take(sentinel_limit);
    take_stream.read_to_end(&mut buf).await.map_err(|e| {
        StorageError::io(format!(
            "I/O error reading manifest payload stream {manifest_key}: {e}"
        ))
    })?;

    if buf.len() as u64 > limit {
        return Err(StorageError::backend(format!(
            "manifest payload exceeded size ceiling of {limit} bytes: {manifest_key}"
        )));
    }

    Ok(buf)
}

/// Core implementation of contained GC manifest reference collection.
pub(crate) async fn collect_manifest_references_impl<R>(
    reader: &R,
    terminal_dirs: &[ObjectKey],
    limits: ManifestReferenceLimits,
) -> Result<ManifestReferenceObservationSet, StorageError>
where
    R: ManifestRefReader + ?Sized,
{
    let mut tracker = ReferenceAccountingTracker::new();

    for dir_key in terminal_dirs {
        // Deduplicate identical terminal directory inputs
        if tracker.seen_terminal_dirs.contains(dir_key) {
            continue;
        }

        // Check and charge terminal enumeration limit
        if tracker.terminal_dirs_enumerated >= limits.max_terminal_dir_enumerations {
            return Err(StorageError::backend(format!(
                "terminal directory enumerations limit exceeded: {} >= {}",
                tracker.terminal_dirs_enumerated, limits.max_terminal_dir_enumerations
            )));
        }
        tracker.terminal_dirs_enumerated = tracker
            .terminal_dirs_enumerated
            .checked_add(1)
            .ok_or_else(|| StorageError::backend("terminal_dirs_enumerated arithmetic overflow"))?;

        // Retain terminal directory key
        let dir_key_bytes = dir_key.as_str().len();
        tracker.charge_retained_bytes(dir_key_bytes, limits.max_retained_logical_bytes)?;
        tracker.seen_terminal_dirs.insert(dir_key.clone());

        // Enumerate candidate manifest entries beneath pinned root
        let entries = reader
            .enumerate_dir(Some(dir_key), limits.per_dir_limits)
            .await
            .map_err(|err| translate_terminal_dir_error(err, dir_key))?;

        for entry in entries {
            // Charge every returned dirent towards total manifest entries
            tracker.total_dirents_observed = tracker
                .total_dirents_observed
                .checked_add(1)
                .ok_or_else(|| {
                    StorageError::backend("total_dirents_observed arithmetic overflow")
                })?;
            if tracker.total_dirents_observed > limits.max_total_manifest_entries {
                return Err(StorageError::backend(format!(
                    "max_total_manifest_entries exceeded: {} > {}",
                    tracker.total_dirents_observed, limits.max_total_manifest_entries
                )));
            }

            // Filter: only regular files
            if entry.file_type() != DirEntryType::Regular {
                continue;
            }

            let Some(name) = entry.name().to_str() else {
                continue;
            };

            // Filter: temporary, lockfiles, or non-hex names
            if name.starts_with(".tmp.") || name.starts_with(".lock.") {
                continue;
            }
            if !name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                continue;
            }

            // Digest parsing: SHA-256 (64 hex) or SHA-512 (128 hex)
            let manifest_digest = if name.len() == 64 {
                Digest::parse(&format!("sha256:{name}")).ok()
            } else if name.len() == 128 {
                Digest::parse(&format!("sha512:{name}")).ok()
            } else {
                None
            };
            let Some(manifest_digest) = manifest_digest else {
                continue;
            };

            // Compose direct ObjectKey without repository parser
            let manifest_key_str = format!("{}/{}", dir_key.as_str(), name);
            let manifest_key = ObjectKey::parse(&manifest_key_str).map_err(|e| {
                StorageError::corrupt_data(format!("invalid composed manifest object key: {e}"))
            })?;

            // Deduplicate identical object paths (but do not skip distinct paths with matching digest)
            if tracker.seen_manifest_keys.contains(&manifest_key) {
                continue;
            }

            // Charge and retain manifest key
            let manifest_key_bytes = manifest_key.as_str().len();
            tracker.charge_retained_bytes(manifest_key_bytes, limits.max_retained_logical_bytes)?;
            tracker.seen_manifest_keys.insert(manifest_key.clone());

            // Check manifests read limit
            let next_manifests_read = tracker
                .manifests_read
                .checked_add(1)
                .ok_or_else(|| StorageError::backend("manifests_read arithmetic overflow"))?;
            if next_manifests_read > limits.max_manifests_read {
                return Err(StorageError::backend(format!(
                    "max_manifests_read exceeded: {next_manifests_read} > {}",
                    limits.max_manifests_read
                )));
            }
            tracker.manifests_read = next_manifests_read;

            // Open payload beneath pinned descriptor
            let payload = reader
                .open_payload(&manifest_key)
                .await
                .map_err(|err| translate_manifest_payload_error(err, &manifest_key))?;

            let (_meta, stream) = payload.into_parts();
            let bytes = read_payload_stream_bounded(
                stream,
                limits.max_manifest_payload_bytes,
                &manifest_key,
            )
            .await?;

            tracker.total_payload_bytes_read = tracker
                .total_payload_bytes_read
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| {
                    StorageError::backend("total_payload_bytes_read arithmetic overflow")
                })?;

            // Parse manifest references
            let refs = parse_manifest_refs(&bytes).map_err(|e| {
                StorageError::corrupt_data(format!(
                    "malformed manifest payload {manifest_key}: {e}"
                ))
            })?;

            // Retain manifest root digest
            tracker.retain_digest(manifest_digest, &limits)?;

            // Retain all referenced digests (layers, config, blobs, manifests, subject)
            for child_ref in refs.all_references() {
                tracker.retain_digest(child_ref.clone(), &limits)?;
            }
        }
    }

    Ok(ManifestReferenceObservationSet {
        protected_digests: tracker.protected_digests,
        terminal_dirs_enumerated: tracker.terminal_dirs_enumerated,
        manifests_parsed: tracker.manifests_read,
        total_dirents_observed: tracker.total_dirents_observed,
        retained_logical_bytes: tracker.retained_logical_bytes,
        total_payload_bytes_read: tracker.total_payload_bytes_read,
    })
}

/// End-to-end orchestration executing discovery and reference collection sequentially over
/// the exact same reader instance.
pub(crate) async fn collect_manifest_references_end_to_end<R>(
    reader: &R,
    discovery_limits: super::repo_discovery::DiscoveryLimits,
    ref_limits: ManifestReferenceLimits,
) -> Result<ManifestReferenceObservationSet, StorageError>
where
    R: ManifestRefReader + ?Sized,
{
    let terminal_dirs =
        super::repo_discovery::discover_manifest_dirs_impl(reader, discovery_limits).await?;
    collect_manifest_references_impl(reader, &terminal_dirs, ref_limits).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use naust_storage_core::{ObjectMetadata, ObjectPayload, ObjectStream};
    use naust_storage_fs::DirEntry;
    use std::collections::{HashMap, VecDeque};
    use std::ffi::OsString;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncRead;

    /// Deterministic recording fake reader for discovery, enumeration, and payload opening.
    struct RecordingFakeManifestRefReader {
        dir_calls: Arc<Mutex<Vec<Option<ObjectKey>>>>,
        dir_responses:
            Arc<Mutex<HashMap<Option<ObjectKey>, VecDeque<Result<Vec<DirEntry>, FsDirError>>>>>,
        payload_calls: Arc<Mutex<Vec<ObjectKey>>>,
        payload_responses:
            Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<ObjectPayload, ReadError>>>>>,
    }

    impl RecordingFakeManifestRefReader {
        fn new() -> Self {
            Self {
                dir_calls: Arc::new(Mutex::new(Vec::new())),
                dir_responses: Arc::new(Mutex::new(HashMap::new())),
                payload_calls: Arc::new(Mutex::new(Vec::new())),
                payload_responses: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn script_dir(
            &self,
            target: Option<&ObjectKey>,
            result: Result<Vec<DirEntry>, FsDirError>,
        ) {
            let key = target.cloned();
            let mut guard = self.dir_responses.lock().unwrap();
            guard.entry(key).or_default().push_back(result);
        }

        fn script_payload(&self, key: &ObjectKey, result: Result<ObjectPayload, ReadError>) {
            let mut guard = self.payload_responses.lock().unwrap();
            guard.entry(key.clone()).or_default().push_back(result);
        }

        fn dir_calls(&self) -> Vec<Option<ObjectKey>> {
            self.dir_calls.lock().unwrap().clone()
        }

        fn payload_calls(&self) -> Vec<ObjectKey> {
            self.payload_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl super::super::repo_discovery::DiscoveryDirEnumerator for RecordingFakeManifestRefReader {
        async fn enumerate_dir(
            &self,
            target: Option<&ObjectKey>,
            _limits: DirEnumerationLimits,
        ) -> Result<Vec<DirEntry>, FsDirError> {
            self.dir_calls.lock().unwrap().push(target.cloned());
            let mut guard = self.dir_responses.lock().unwrap();
            if let Some(queue) = guard.get_mut(&target.cloned()) {
                if let Some(res) = queue.pop_front() {
                    return res;
                }
            }
            Err(FsDirError::NotFound {
                path: target.map(|k| k.as_str().to_string()),
            })
        }
    }

    #[async_trait]
    impl ObjectPayloadReader for RecordingFakeManifestRefReader {
        async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError> {
            self.payload_calls.lock().unwrap().push(key.clone());
            let mut guard = self.payload_responses.lock().unwrap();
            if let Some(queue) = guard.get_mut(key) {
                if let Some(res) = queue.pop_front() {
                    return res;
                }
            }
            Err(ReadError::not_found(key.clone()))
        }
    }

    fn make_entry(name: &str, file_type: DirEntryType) -> DirEntry {
        DirEntry::new(OsString::from(name), file_type)
    }

    fn mock_payload(bytes: Vec<u8>) -> ObjectPayload {
        let meta = ObjectMetadata::new(bytes.len() as u64);
        let stream: ObjectStream = Box::pin(std::io::Cursor::new(bytes));
        ObjectPayload::new(meta, stream)
    }

    struct FailingStream {
        head_bytes: Vec<u8>,
        cursor: usize,
        error_kind: std::io::ErrorKind,
        message: &'static str,
    }

    impl FailingStream {
        fn new(head_bytes: Vec<u8>, error_kind: std::io::ErrorKind, message: &'static str) -> Self {
            Self {
                head_bytes,
                cursor: 0,
                error_kind,
                message,
            }
        }
    }

    impl AsyncRead for FailingStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.cursor < self.head_bytes.len() {
                let to_write = std::cmp::min(buf.remaining(), self.head_bytes.len() - self.cursor);
                buf.put_slice(&self.head_bytes[self.cursor..self.cursor + to_write]);
                self.cursor += to_write;
                std::task::Poll::Ready(Ok(()))
            } else {
                std::task::Poll::Ready(Err(std::io::Error::new(self.error_kind, self.message)))
            }
        }
    }

    fn sample_manifest_json(layer_hex: &str) -> Vec<u8> {
        format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "size": 7023
                }},
                "layers": [
                    {{
                        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": "sha256:{layer_hex}",
                        "size": 32654
                    }}
                ]
            }}"#
        )
        .into_bytes()
    }

    fn parse_digest(s: &str) -> Digest {
        Digest::parse(s).expect("valid digest string")
    }

    // ========================================================================
    // 1. Filename policy: SHA-256 and SHA-512 accepted, roots recorded
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_filename_sha256_and_sha512_accepted_and_roots_recorded() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();

        let sha256_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let sha512_hex = "22222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";

        fake.script_dir(
            Some(&dir),
            Ok(vec![
                make_entry(sha256_hex, DirEntryType::Regular),
                make_entry(sha512_hex, DirEntryType::Regular),
            ]),
        );

        let key256 = ObjectKey::parse(&format!("repos/app/manifests/{sha256_hex}")).unwrap();
        let key512 = ObjectKey::parse(&format!("repos/app/manifests/{sha512_hex}")).unwrap();

        fake.script_payload(
            &key256,
            Ok(mock_payload(sample_manifest_json(
                "3333333333333333333333333333333333333333333333333333333333333333",
            ))),
        );
        fake.script_payload(
            &key512,
            Ok(mock_payload(sample_manifest_json(
                "4444444444444444444444444444444444444444444444444444444444444444",
            ))),
        );

        let limits = ManifestReferenceTestLimits::test_default();
        let res = collect_manifest_references_impl(&fake, &[dir], limits)
            .await
            .expect("should succeed");

        assert_eq!(res.terminal_dirs_enumerated, 1);
        assert_eq!(res.manifests_parsed, 2);
        assert_eq!(res.total_dirents_observed, 2);

        // Verify root digests are recorded in protected_digests
        let d256 = parse_digest(&format!("sha256:{sha256_hex}"));
        let d512 = parse_digest(&format!("sha512:{sha512_hex}"));
        assert!(res.protected_digests.contains(&d256));
        assert!(res.protected_digests.contains(&d512));

        // Verify child layers are recorded
        let layer3 =
            parse_digest("sha256:3333333333333333333333333333333333333333333333333333333333333333");
        let layer4 =
            parse_digest("sha256:4444444444444444444444444444444444444444444444444444444444444444");
        assert!(res.protected_digests.contains(&layer3));
        assert!(res.protected_digests.contains(&layer4));
    }

    // ========================================================================
    // 2. Uppercase hex, prefixed, and invalid names are skipped
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_uppercase_hex_and_invalid_names_skipped() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();

        let valid_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let upper_hex = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        fake.script_dir(
            Some(&dir),
            Ok(vec![
                make_entry(valid_hex, DirEntryType::Regular),
                make_entry(upper_hex, DirEntryType::Regular),
                make_entry(".tmp.upload123", DirEntryType::Regular),
                make_entry(".lock.exclusive", DirEntryType::Regular),
                make_entry("sha256:prefixed", DirEntryType::Regular),
                make_entry("too_short", DirEntryType::Regular),
                make_entry(
                    "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
                    DirEntryType::Regular,
                ),
            ]),
        );

        let valid_key = ObjectKey::parse(&format!("repos/app/manifests/{valid_hex}")).unwrap();
        fake.script_payload(
            &valid_key,
            Ok(mock_payload(sample_manifest_json(
                "5555555555555555555555555555555555555555555555555555555555555555",
            ))),
        );

        let limits = ManifestReferenceTestLimits::test_default();
        let res = collect_manifest_references_impl(&fake, &[dir], limits)
            .await
            .expect("should succeed");

        assert_eq!(res.manifests_parsed, 1);
        assert_eq!(res.total_dirents_observed, 7);
        assert_eq!(fake.payload_calls().len(), 1);
    }

    // ========================================================================
    // 3. Non-regular entries skipped
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_nonregular_entries_skipped() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();
        let valid_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        fake.script_dir(
            Some(&dir),
            Ok(vec![
                make_entry(valid_hex, DirEntryType::Directory),
                make_entry(valid_hex, DirEntryType::Symlink),
                make_entry(valid_hex, DirEntryType::Other),
            ]),
        );

        let limits = ManifestReferenceTestLimits::test_default();
        let res = collect_manifest_references_impl(&fake, &[dir], limits)
            .await
            .expect("should succeed");

        assert_eq!(res.manifests_parsed, 0);
        assert_eq!(res.total_dirents_observed, 3);
        assert_eq!(fake.payload_calls().len(), 0);
    }

    // ========================================================================
    // 4. Duplicate dirents and duplicate terminal inputs deduplicated
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_duplicate_terminal_inputs_and_dirents_deduplicated() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();
        let hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        // Directory yields duplicate dirent
        fake.script_dir(
            Some(&dir),
            Ok(vec![
                make_entry(hex, DirEntryType::Regular),
                make_entry(hex, DirEntryType::Regular),
            ]),
        );

        let key = ObjectKey::parse(&format!("repos/app/manifests/{hex}")).unwrap();
        fake.script_payload(
            &key,
            Ok(mock_payload(sample_manifest_json(
                "6666666666666666666666666666666666666666666666666666666666666666",
            ))),
        );

        let limits = ManifestReferenceTestLimits::test_default();
        // Pass duplicate terminal inputs
        let res = collect_manifest_references_impl(&fake, &[dir.clone(), dir.clone()], limits)
            .await
            .expect("should succeed");

        // Exactly 1 directory enumeration, exactly 1 payload read
        assert_eq!(res.terminal_dirs_enumerated, 1);
        assert_eq!(res.manifests_parsed, 1);
        assert_eq!(fake.dir_calls().len(), 1);
        assert_eq!(fake.payload_calls().len(), 1);
    }

    // ========================================================================
    // 5. Identical digest at distinct paths: both paths are read
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_identical_digests_at_distinct_paths_both_read() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir1 = ObjectKey::parse("repos/app1/manifests").unwrap();
        let dir2 = ObjectKey::parse("repos/app2/manifests").unwrap();
        let hex = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

        fake.script_dir(
            Some(&dir1),
            Ok(vec![make_entry(hex, DirEntryType::Regular)]),
        );
        fake.script_dir(
            Some(&dir2),
            Ok(vec![make_entry(hex, DirEntryType::Regular)]),
        );

        let key1 = ObjectKey::parse(&format!("repos/app1/manifests/{hex}")).unwrap();
        let key2 = ObjectKey::parse(&format!("repos/app2/manifests/{hex}")).unwrap();

        // Different payloads referencing different child layers
        let layer1 = "7777777777777777777777777777777777777777777777777777777777777777";
        let layer2 = "8888888888888888888888888888888888888888888888888888888888888888";
        fake.script_payload(&key1, Ok(mock_payload(sample_manifest_json(layer1))));
        fake.script_payload(&key2, Ok(mock_payload(sample_manifest_json(layer2))));

        let limits = ManifestReferenceTestLimits::test_default();
        let res = collect_manifest_references_impl(&fake, &[dir1, dir2], limits)
            .await
            .expect("should succeed");

        // Both distinct paths must be read
        assert_eq!(res.manifests_parsed, 2);
        assert_eq!(fake.payload_calls().len(), 2);

        // References from both must be protected
        let l1 = parse_digest(&format!("sha256:{layer1}"));
        let l2 = parse_digest(&format!("sha256:{layer2}"));
        assert!(res.protected_digests.contains(&l1));
        assert!(res.protected_digests.contains(&l2));
    }

    // ========================================================================
    // 6. Parser behavior: record-only child references, no recursive fetches
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_parser_behavior_and_record_only_child_references() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/index_app/manifests").unwrap();
        let index_hex = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

        fake.script_dir(
            Some(&dir),
            Ok(vec![make_entry(index_hex, DirEntryType::Regular)]),
        );

        let child_manifest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let index_json = format!(
            r#"{{
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [
                    {{
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "digest": "sha256:{child_manifest}",
                        "size": 1234
                    }}
                ]
            }}"#
        )
        .into_bytes();

        let index_key =
            ObjectKey::parse(&format!("repos/index_app/manifests/{index_hex}")).unwrap();
        fake.script_payload(&index_key, Ok(mock_payload(index_json)));

        let limits = ManifestReferenceTestLimits::test_default();
        let res = collect_manifest_references_impl(&fake, &[dir], limits)
            .await
            .expect("should succeed");

        assert_eq!(res.manifests_parsed, 1);
        let child_digest = parse_digest(&format!("sha256:{child_manifest}"));
        assert!(res.protected_digests.contains(&child_digest));

        // Verifies NO recursive payload calls were made for child_manifest
        assert_eq!(fake.payload_calls().len(), 1);
        assert_eq!(fake.payload_calls()[0], index_key);
    }

    // ========================================================================
    // 7. Missing observed terminal or payload fails closed with Io
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_missing_observed_terminal_or_payload_fails_closed() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();

        // Case A: Missing observed terminal directory
        fake.script_dir(
            Some(&dir),
            Err(FsDirError::NotFound {
                path: Some("repos/app/manifests".to_string()),
            }),
        );

        let limits = ManifestReferenceTestLimits::test_default();
        let err = collect_manifest_references_impl(&fake, &[dir.clone()], limits.clone())
            .await
            .expect_err("vanished terminal must fail with Io");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Io);
                assert!(message.contains("observed terminal directory vanished"));
                assert!(message.contains("repos/app/manifests"));
            }
            other => panic!("expected StorageError::Internal(Io), got {other:?}"),
        }

        // Case B: Missing observed manifest payload
        let fake2 = RecordingFakeManifestRefReader::new();
        let hex = "1212121212121212121212121212121212121212121212121212121212121212";
        fake2.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));

        let payload_key = ObjectKey::parse(&format!("repos/app/manifests/{hex}")).unwrap();
        fake2.script_payload(&payload_key, Err(ReadError::not_found(payload_key.clone())));

        let err2 = collect_manifest_references_impl(&fake2, &[dir], limits)
            .await
            .expect_err("vanished payload must fail with Io");

        match err2 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Io);
                assert!(message.contains("observed manifest payload vanished"));
                assert!(message.contains(&payload_key.as_str()));
            }
            other => panic!("expected StorageError::Internal(Io), got {other:?}"),
        }
    }

    // ========================================================================
    // 8. Terminal directory error mappings
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_terminal_error_mappings() {
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();
        let limits = ManifestReferenceTestLimits::test_default();

        // Subcase 1: NotADirectory -> CorruptData
        let fake1 = RecordingFakeManifestRefReader::new();
        fake1.script_dir(
            Some(&dir),
            Err(FsDirError::NotADirectory {
                path: Some("repos/app/manifests".to_string()),
            }),
        );
        let err1 = collect_manifest_references_impl(&fake1, &[dir.clone()], limits.clone())
            .await
            .expect_err("not a directory must fail with CorruptData");
        match err1 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::CorruptData);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("terminal path is not a directory"));
            }
            other => panic!("expected CorruptData, got {other:?}"),
        }

        // Subcase 2: PermissionDenied -> PermissionDenied
        let fake2 = RecordingFakeManifestRefReader::new();
        fake2.script_dir(
            Some(&dir),
            Err(FsDirError::PermissionDenied {
                path: Some("repos/app/manifests".to_string()),
                source: std::io::Error::from_raw_os_error(libc::EACCES),
            }),
        );
        let err2 = collect_manifest_references_impl(&fake2, &[dir.clone()], limits.clone())
            .await
            .expect_err("permission denied must fail with PermissionDenied");
        match err2 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::PermissionDenied);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("permission denied"));
            }
            other => panic!("expected PermissionDenied, got {other:?}"),
        }

        // Subcase 3: ResolutionRejected -> Io
        let fake3 = RecordingFakeManifestRefReader::new();
        fake3.script_dir(
            Some(&dir),
            Err(FsDirError::ResolutionRejected {
                raw_os_error: libc::ELOOP,
                source: std::io::Error::from_raw_os_error(libc::ELOOP),
            }),
        );
        let err3 = collect_manifest_references_impl(&fake3, &[dir.clone()], limits.clone())
            .await
            .expect_err("resolution rejected must fail with Io");
        match err3 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Io);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("path resolution rejected"));
            }
            other => panic!("expected Io, got {other:?}"),
        }

        // Subcase 4: LimitExceeded -> Backend
        let fake4 = RecordingFakeManifestRefReader::new();
        fake4.script_dir(
            Some(&dir),
            Err(FsDirError::LimitExceeded {
                reason: naust_storage_fs::LimitExceededReason::MaxEntries(100),
            }),
        );
        let err4 = collect_manifest_references_impl(&fake4, &[dir.clone()], limits.clone())
            .await
            .expect_err("limit exceeded must fail with Backend");
        match err4 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("terminal enumeration resource limit exceeded"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }

        // Subcase 5: EntryDisappeared -> Io
        let fake5 = RecordingFakeManifestRefReader::new();
        fake5.script_dir(
            Some(&dir),
            Err(FsDirError::EntryDisappeared {
                name: OsString::from("disappeared_manifest"),
            }),
        );
        let err5 = collect_manifest_references_impl(&fake5, &[dir.clone()], limits.clone())
            .await
            .expect_err("entry disappeared must fail with Io");
        match err5 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Io);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("directory entry disappeared"));
            }
            other => panic!("expected Io, got {other:?}"),
        }

        // Subcase 6: SyscallUnsupported -> Configuration
        let fake6 = RecordingFakeManifestRefReader::new();
        fake6.script_dir(
            Some(&dir),
            Err(FsDirError::SyscallUnsupported(
                std::io::Error::from_raw_os_error(libc::ENOSYS),
            )),
        );
        let err6 = collect_manifest_references_impl(&fake6, &[dir.clone()], limits.clone())
            .await
            .expect_err("syscall unsupported must fail with Configuration");
        match err6 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Configuration);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("openat2 is unavailable"));
            }
            other => panic!("expected Configuration, got {other:?}"),
        }

        // Subcase 7: PlatformUnsupported -> Configuration
        let fake7 = RecordingFakeManifestRefReader::new();
        fake7.script_dir(Some(&dir), Err(FsDirError::PlatformUnsupported));
        let err7 = collect_manifest_references_impl(&fake7, &[dir.clone()], limits.clone())
            .await
            .expect_err("platform unsupported must fail with Configuration");
        match err7 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Configuration);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("platform unsupported"));
            }
            other => panic!("expected Configuration, got {other:?}"),
        }

        // Subcase 8: RuntimeMissing -> Backend
        let genuine_runtime_missing =
            std::thread::spawn(|| tokio::runtime::Handle::try_current().unwrap_err())
                .join()
                .expect("thread join");
        let fake8 = RecordingFakeManifestRefReader::new();
        fake8.script_dir(
            Some(&dir),
            Err(FsDirError::RuntimeMissing(genuine_runtime_missing)),
        );
        let err8 = collect_manifest_references_impl(&fake8, &[dir.clone()], limits.clone())
            .await
            .expect_err("runtime missing must fail with Backend");
        match err8 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("tokio runtime missing"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }

        // Subcase 9: TaskJoinFailed -> Backend
        let genuine_join_error = tokio::task::spawn(async {
            panic!("simulated panic for genuine JoinError fixture in terminal error test");
        })
        .await
        .unwrap_err();
        let fake9 = RecordingFakeManifestRefReader::new();
        fake9.script_dir(
            Some(&dir),
            Err(FsDirError::TaskJoinFailed(genuine_join_error)),
        );
        let err9 = collect_manifest_references_impl(&fake9, &[dir.clone()], limits)
            .await
            .expect_err("task join failed must fail with Backend");
        match err9 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                assert!(message.contains(&dir.as_str()));
                assert!(message.contains("blocking enumeration task join failed"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    // ========================================================================
    // 9. Typed error downcast mappings and fallback inspection
    // ========================================================================
    #[derive(Debug)]
    struct UnrelatedCustomError(&'static str);

    impl std::fmt::Display for UnrelatedCustomError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "unrelated custom error: {}", self.0)
        }
    }

    impl std::error::Error for UnrelatedCustomError {}

    #[tokio::test]
    async fn test_manifest_refs_typed_error_downcasts_and_fallbacks() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();
        let hex = "3434343434343434343434343434343434343434343434343434343434343434";
        let key = ObjectKey::parse(&format!("repos/app/manifests/{hex}")).unwrap();

        // Subcase 1: UnsupportedObjectType -> CorruptData
        fake.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake.script_payload(
            &key,
            Err(ReadError::backend_with_source(
                "not a regular file",
                Box::new(FsMetadataError::UnsupportedObjectType { mode: 0o040755 }),
            )),
        );

        let limits = ManifestReferenceTestLimits::test_default();
        let err1 = collect_manifest_references_impl(&fake, &[dir.clone()], limits.clone())
            .await
            .expect_err("unsupported object type must fail with CorruptData");
        match err1 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::CorruptData);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("target is not a regular file"));
            }
            other => panic!("expected CorruptData, got {other:?}"),
        }

        // Subcase 2: ResolutionRejected -> Io
        let fake2 = RecordingFakeManifestRefReader::new();
        fake2.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake2.script_payload(
            &key,
            Err(ReadError::backend_with_source(
                "symlink prohibited",
                Box::new(FsMetadataError::ResolutionRejected {
                    raw_os_error: libc::ELOOP,
                    source: std::io::Error::from_raw_os_error(libc::ELOOP),
                }),
            )),
        );

        let err2 = collect_manifest_references_impl(&fake2, &[dir.clone()], limits.clone())
            .await
            .expect_err("resolution rejected must fail with Io");
        match err2 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Io);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("path resolution rejected"));
            }
            other => panic!("expected Io, got {other:?}"),
        }

        // Subcase 3: SyscallUnsupported -> Configuration
        let fake3 = RecordingFakeManifestRefReader::new();
        fake3.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake3.script_payload(
            &key,
            Err(ReadError::backend_with_source(
                "openat2 unavailable",
                Box::new(FsMetadataError::SyscallUnsupported(
                    std::io::Error::from_raw_os_error(libc::ENOSYS),
                )),
            )),
        );

        let err3 = collect_manifest_references_impl(&fake3, &[dir.clone()], limits.clone())
            .await
            .expect_err("syscall unsupported must fail with Configuration");
        match err3 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Configuration);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("openat2 is unavailable"));
            }
            other => panic!("expected Configuration, got {other:?}"),
        }

        // Subcase 4: PlatformUnsupported -> Configuration
        let fake_plat = RecordingFakeManifestRefReader::new();
        fake_plat.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake_plat.script_payload(
            &key,
            Err(ReadError::backend_with_source(
                "platform unsupported",
                Box::new(FsMetadataError::PlatformUnsupported),
            )),
        );

        let err_plat = collect_manifest_references_impl(&fake_plat, &[dir.clone()], limits.clone())
            .await
            .expect_err("platform unsupported must fail with Configuration");
        match err_plat {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Configuration);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("platform unsupported"));
            }
            other => panic!("expected Configuration, got {other:?}"),
        }

        // Subcase 5: RuntimeMissing -> Backend
        let genuine_runtime_missing =
            std::thread::spawn(|| tokio::runtime::Handle::try_current().unwrap_err())
                .join()
                .expect("thread join");
        let fake_rt = RecordingFakeManifestRefReader::new();
        fake_rt.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake_rt.script_payload(
            &key,
            Err(ReadError::backend_with_source(
                "runtime missing",
                Box::new(FsMetadataError::RuntimeMissing(genuine_runtime_missing)),
            )),
        );

        let err_rt = collect_manifest_references_impl(&fake_rt, &[dir.clone()], limits.clone())
            .await
            .expect_err("runtime missing must fail with Backend");
        match err_rt {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("tokio runtime missing"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }

        // Subcase 6: TaskJoinFailed -> Backend
        let genuine_join_error = tokio::task::spawn(async {
            panic!("simulated panic for genuine JoinError fixture in payload error test");
        })
        .await
        .unwrap_err();
        let fake_tj = RecordingFakeManifestRefReader::new();
        fake_tj.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake_tj.script_payload(
            &key,
            Err(ReadError::backend_with_source(
                "join failed",
                Box::new(FsMetadataError::TaskJoinFailed(genuine_join_error)),
            )),
        );

        let err_tj = collect_manifest_references_impl(&fake_tj, &[dir.clone()], limits.clone())
            .await
            .expect_err("task join failed must fail with Backend");
        match err_tj {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("blocking task join failed"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }

        // Subcase 7: PermissionDenied -> PermissionDenied
        let fake4 = RecordingFakeManifestRefReader::new();
        fake4.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake4.script_payload(
            &key,
            Err(ReadError::permission_denied_with_source(
                key.clone(),
                Box::new(std::io::Error::from_raw_os_error(libc::EACCES)),
            )),
        );

        let err4 = collect_manifest_references_impl(&fake4, &[dir.clone()], limits.clone())
            .await
            .expect_err("permission denied must fail with PermissionDenied");
        match err4 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::PermissionDenied);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("permission denied"));
            }
            other => panic!("expected PermissionDenied, got {other:?}"),
        }

        // Subcase 8: Backend source containing std::io::Error -> Io
        let fake_io = RecordingFakeManifestRefReader::new();
        fake_io.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake_io.script_payload(
            &key,
            Err(ReadError::backend_with_source(
                "underlying io failure",
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pipe broken",
                )),
            )),
        );

        let err_io = collect_manifest_references_impl(&fake_io, &[dir.clone()], limits.clone())
            .await
            .expect_err("io source must map to Io");
        match err_io {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Io);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("pipe broken"));
            }
            other => panic!("expected Io, got {other:?}"),
        }

        // Subcase 9: Backend source containing unrelated custom error -> Backend
        let fake_unrelated = RecordingFakeManifestRefReader::new();
        fake_unrelated.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake_unrelated.script_payload(
            &key,
            Err(ReadError::backend_with_source(
                "custom failure",
                Box::new(UnrelatedCustomError("foreign error detail")),
            )),
        );

        let err_unrelated =
            collect_manifest_references_impl(&fake_unrelated, &[dir.clone()], limits.clone())
                .await
                .expect_err("unrelated error must map to Backend");
        match err_unrelated {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("foreign error detail"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }

        // Subcase 10: Fallback for absent source -> Backend with message
        let fake5 = RecordingFakeManifestRefReader::new();
        fake5.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake5.script_payload(&key, Err(ReadError::backend("unspecified storage fault")));

        let err5 = collect_manifest_references_impl(&fake5, &[dir], limits)
            .await
            .expect_err("absent source must fallback to Backend");
        match err5 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                assert!(message.contains(&key.as_str()));
                assert!(message.contains("unspecified storage fault"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    // ========================================================================
    // 9. Stream I/O failure and malformed JSON parse errors
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_stream_io_and_parse_failures() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();
        let hex = "5656565656565656565656565656565656565656565656565656565656565656";
        let key = ObjectKey::parse(&format!("repos/app/manifests/{hex}")).unwrap();

        // Stream failure mid-read
        let stream = FailingStream::new(
            vec![b'{', b'"'],
            std::io::ErrorKind::UnexpectedEof,
            "stream severed",
        );
        let failing_payload = ObjectPayload::new(ObjectMetadata::new(100), Box::pin(stream));

        fake.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake.script_payload(&key, Ok(failing_payload));

        let limits = ManifestReferenceTestLimits::test_default();
        let err1 = collect_manifest_references_impl(&fake, &[dir.clone()], limits.clone())
            .await
            .expect_err("stream error must fail with Io");
        assert!(matches!(
            err1,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Io,
                ..
            }
        ));

        // Malformed JSON parse failure
        let fake2 = RecordingFakeManifestRefReader::new();
        fake2.script_dir(Some(&dir), Ok(vec![make_entry(hex, DirEntryType::Regular)]));
        fake2.script_payload(&key, Ok(mock_payload(b"not json at all".to_vec())));

        let err2 = collect_manifest_references_impl(&fake2, &[dir], limits)
            .await
            .expect_err("malformed json must fail with CorruptData");
        assert!(matches!(
            err2,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::CorruptData,
                ..
            }
        ));
    }

    // ========================================================================
    // 10. Failure after earlier success asserts no subsequent reads
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_failure_after_earlier_success_asserts_no_subsequent_reads() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir1 = ObjectKey::parse("repos/app1/manifests").unwrap();
        let dir2 = ObjectKey::parse("repos/app2/manifests").unwrap();
        let hex1 = "7878787878787878787878787878787878787878787878787878787878787878";
        let hex2 = "9090909090909090909090909090909090909090909090909090909090909090";

        fake.script_dir(
            Some(&dir1),
            Ok(vec![make_entry(hex1, DirEntryType::Regular)]),
        );
        fake.script_dir(
            Some(&dir2),
            Ok(vec![make_entry(hex2, DirEntryType::Regular)]),
        );

        let key1 = ObjectKey::parse(&format!("repos/app1/manifests/{hex1}")).unwrap();
        let key2 = ObjectKey::parse(&format!("repos/app2/manifests/{hex2}")).unwrap();

        // Manifest 1 succeeds
        fake.script_payload(
            &key1,
            Ok(mock_payload(sample_manifest_json(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ))),
        );
        // Manifest 2 fails with corrupt data
        fake.script_payload(&key2, Ok(mock_payload(b"malformed json".to_vec())));

        let limits = ManifestReferenceTestLimits::test_default();
        let err = collect_manifest_references_impl(&fake, &[dir1, dir2], limits)
            .await
            .expect_err("must fail on manifest 2");

        assert!(matches!(
            err,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::CorruptData,
                ..
            }
        ));
        // Exactly 2 payload reads attempted, none after the failure
        assert_eq!(fake.payload_calls().len(), 2);
    }

    // ========================================================================
    // 11. Exact and one-over budgets
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_exact_and_one_over_budgets() {
        let hex1 = "1111111111111111111111111111111111111111111111111111111111111111";
        let hex2 = "2222222222222222222222222222222222222222222222222222222222222222";
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();
        let key1 = ObjectKey::parse(&format!("repos/app/manifests/{hex1}")).unwrap();
        let key2 = ObjectKey::parse(&format!("repos/app/manifests/{hex2}")).unwrap();

        // ====================================================================
        // Category 1: max_manifests_read
        // ====================================================================
        {
            let fake_exact = RecordingFakeManifestRefReader::new();
            fake_exact.script_dir(
                Some(&dir),
                Ok(vec![
                    make_entry(hex1, DirEntryType::Regular),
                    make_entry(hex2, DirEntryType::Regular),
                ]),
            );
            fake_exact.script_payload(
                &key1,
                Ok(mock_payload(sample_manifest_json(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ))),
            );
            fake_exact.script_payload(
                &key2,
                Ok(mock_payload(sample_manifest_json(
                    "4444444444444444444444444444444444444444444444444444444444444444",
                ))),
            );

            let mut limits_exact = ManifestReferenceTestLimits::test_default();
            limits_exact.max_manifests_read = 2;
            let res = collect_manifest_references_impl(&fake_exact, &[dir.clone()], limits_exact)
                .await
                .expect("exact boundary for max_manifests_read must succeed");
            assert_eq!(res.manifests_parsed, 2);
            assert_eq!(fake_exact.payload_calls().len(), 2);

            let fake_over = RecordingFakeManifestRefReader::new();
            fake_over.script_dir(
                Some(&dir),
                Ok(vec![
                    make_entry(hex1, DirEntryType::Regular),
                    make_entry(hex2, DirEntryType::Regular),
                ]),
            );
            fake_over.script_payload(
                &key1,
                Ok(mock_payload(sample_manifest_json(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ))),
            );

            let mut limits_over = ManifestReferenceTestLimits::test_default();
            limits_over.max_manifests_read = 1;
            let err = collect_manifest_references_impl(&fake_over, &[dir.clone()], limits_over)
                .await
                .expect_err("one-over limit for max_manifests_read must fail with Backend");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                    assert!(message.contains("max_manifests_read exceeded: 2 > 1"));
                }
                other => panic!("expected Backend, got {other:?}"),
            }
            assert_eq!(fake_over.payload_calls().len(), 1);
        }

        // ====================================================================
        // Category 2: max_terminal_dir_enumerations
        // ====================================================================
        {
            let dir1 = ObjectKey::parse("repos/app1/manifests").unwrap();
            let dir2 = ObjectKey::parse("repos/app2/manifests").unwrap();

            // Subcase A: Exact boundary (2) succeeds
            let fake_exact = RecordingFakeManifestRefReader::new();
            fake_exact.script_dir(Some(&dir1), Ok(vec![]));
            fake_exact.script_dir(Some(&dir2), Ok(vec![]));

            let mut limits_exact = ManifestReferenceTestLimits::test_default();
            limits_exact.max_terminal_dir_enumerations = 2;
            let res = collect_manifest_references_impl(
                &fake_exact,
                &[dir1.clone(), dir2.clone()],
                limits_exact,
            )
            .await
            .expect("exact boundary for terminal enumerations must succeed");
            assert_eq!(res.terminal_dirs_enumerated, 2);
            assert_eq!(fake_exact.dir_calls().len(), 2);

            // Subcase B: One-over (1 limit with 2 directories) fails before 2nd call
            let fake_over = RecordingFakeManifestRefReader::new();
            fake_over.script_dir(Some(&dir1), Ok(vec![]));

            let mut limits_over = ManifestReferenceTestLimits::test_default();
            limits_over.max_terminal_dir_enumerations = 1;
            let err = collect_manifest_references_impl(
                &fake_over,
                &[dir1.clone(), dir2.clone()],
                limits_over,
            )
            .await
            .expect_err("one-over limit for terminal enumerations must fail with Backend");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                    assert!(
                        message.contains("terminal directory enumerations limit exceeded: 1 >= 1")
                    );
                }
                other => panic!("expected Backend, got {other:?}"),
            }
            assert_eq!(fake_over.dir_calls().len(), 1);

            // Subcase C: Duplicate terminal input does NOT consume additional enumerations
            let fake_dedup = RecordingFakeManifestRefReader::new();
            fake_dedup.script_dir(Some(&dir1), Ok(vec![]));

            let mut limits_dedup = ManifestReferenceTestLimits::test_default();
            limits_dedup.max_terminal_dir_enumerations = 1;
            let res = collect_manifest_references_impl(
                &fake_dedup,
                &[dir1.clone(), dir1.clone()],
                limits_dedup,
            )
            .await
            .expect("duplicate terminal input must be deduplicated without extra charge");
            assert_eq!(res.terminal_dirs_enumerated, 1);
            assert_eq!(fake_dedup.dir_calls().len(), 1);
        }

        // ====================================================================
        // Category 3: max_total_manifest_entries (cumulative returned dirents)
        // ====================================================================
        {
            // Directory returns 3 entries: 1 regular file, 1 non-regular symlink, 1 duplicate name
            let fake_exact = RecordingFakeManifestRefReader::new();
            fake_exact.script_dir(
                Some(&dir),
                Ok(vec![
                    make_entry(hex1, DirEntryType::Regular),
                    make_entry("symlink_entry", DirEntryType::Symlink),
                    make_entry(hex1, DirEntryType::Regular),
                ]),
            );
            fake_exact.script_payload(&key1, Ok(mock_payload(b"{}".to_vec())));

            let mut limits_exact = ManifestReferenceTestLimits::test_default();
            limits_exact.max_total_manifest_entries = 3;
            let res = collect_manifest_references_impl(&fake_exact, &[dir.clone()], limits_exact)
                .await
                .expect("exact boundary for max_total_manifest_entries must succeed");
            assert_eq!(res.total_dirents_observed, 3);
            assert_eq!(res.manifests_parsed, 1);

            let fake_over = RecordingFakeManifestRefReader::new();
            fake_over.script_dir(
                Some(&dir),
                Ok(vec![
                    make_entry(hex1, DirEntryType::Regular),
                    make_entry("symlink_entry", DirEntryType::Symlink),
                    make_entry(hex1, DirEntryType::Regular),
                ]),
            );
            fake_over.script_payload(&key1, Ok(mock_payload(b"{}".to_vec())));

            let mut limits_over = ManifestReferenceTestLimits::test_default();
            limits_over.max_total_manifest_entries = 2;
            let err = collect_manifest_references_impl(&fake_over, &[dir.clone()], limits_over)
                .await
                .expect_err("one-over limit for max_total_manifest_entries must fail with Backend");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                    assert!(message.contains("max_total_manifest_entries exceeded: 3 > 2"));
                }
                other => panic!("expected Backend, got {other:?}"),
            }
        }

        // ====================================================================
        // Category 4: max_total_references
        // ====================================================================
        {
            // Manifest has root digest + 2 layer references = 4 unique references including config
            let layer1 = "3333333333333333333333333333333333333333333333333333333333333333";
            let layer2 = "4444444444444444444444444444444444444444444444444444444444444444";
            let manifest_bytes = format!(
                r#"{{
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "config": {{
                        "mediaType": "application/vnd.oci.image.config.v1+json",
                        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "size": 100
                    }},
                    "layers": [
                        {{ "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:{layer1}", "size": 10 }},
                        {{ "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:{layer2}", "size": 20 }}
                    ]
                }}"#
            )
            .into_bytes();

            // Root digest + config (1) + layer1 (1) + layer2 (1) = 4 unique references
            let fake_exact = RecordingFakeManifestRefReader::new();
            fake_exact.script_dir(
                Some(&dir),
                Ok(vec![make_entry(hex1, DirEntryType::Regular)]),
            );
            fake_exact.script_payload(&key1, Ok(mock_payload(manifest_bytes.clone())));

            let mut limits_exact = ManifestReferenceTestLimits::test_default();
            limits_exact.max_total_references = 4;
            let res = collect_manifest_references_impl(&fake_exact, &[dir.clone()], limits_exact)
                .await
                .expect("exact boundary for max_total_references must succeed");
            assert_eq!(res.protected_digests.len(), 4);

            let fake_over = RecordingFakeManifestRefReader::new();
            fake_over.script_dir(
                Some(&dir),
                Ok(vec![make_entry(hex1, DirEntryType::Regular)]),
            );
            fake_over.script_payload(&key1, Ok(mock_payload(manifest_bytes)));

            let mut limits_over = ManifestReferenceTestLimits::test_default();
            limits_over.max_total_references = 3;
            let err = collect_manifest_references_impl(&fake_over, &[dir.clone()], limits_over)
                .await
                .expect_err("one-over limit for max_total_references must fail with Backend");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                    assert!(message.contains("max_total_references exceeded: 4 > 3"));
                }
                other => panic!("expected Backend, got {other:?}"),
            }
        }

        // ====================================================================
        // Category 5: max_retained_logical_bytes
        // ====================================================================
        {
            // Exact byte breakdown:
            // dir_key: "repos/app/manifests" (19 bytes: "repos" [5] + "/" [1] + "app" [3] + "/" [1] + "manifests" [9] = 19)
            // manifest_key: "repos/app/manifests/1111111111111111111111111111111111111111111111111111111111111111" (19 + 1 + 64 = 84 bytes)
            // root_digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111" (7 + 64 = 71 bytes)
            // Total = 19 + 84 + 71 = 174 bytes
            let empty_manifest = b"{}".to_vec();

            // Derive expected byte counts directly from fixture key/digest lengths
            let dir_bytes = dir.as_str().len();
            let key_bytes = key1.as_str().len();
            let root_digest_str = format!("sha256:{hex1}");
            let digest_bytes = root_digest_str.len();
            let expected_total_bytes = dir_bytes + key_bytes + digest_bytes;

            // Independently assert literal fixture lengths
            assert_eq!(dir_bytes, 19, "dir key literal length must be 19 bytes");
            assert_eq!(
                key_bytes, 84,
                "manifest key literal length must be 84 bytes"
            );
            assert_eq!(
                digest_bytes, 71,
                "root digest literal length must be 71 bytes"
            );
            assert_eq!(
                expected_total_bytes, 174,
                "exact total retained bytes must be 174"
            );

            // Subcase A: Exact boundary succeeds with duplicate terminal & manifest inputs
            let fake_exact = RecordingFakeManifestRefReader::new();
            fake_exact.script_dir(
                Some(&dir),
                Ok(vec![
                    make_entry(hex1, DirEntryType::Regular),
                    make_entry(hex1, DirEntryType::Regular), // duplicate manifest entry
                ]),
            );
            fake_exact.script_payload(&key1, Ok(mock_payload(empty_manifest.clone())));

            let mut limits_exact = ManifestReferenceTestLimits::test_default();
            limits_exact.max_retained_logical_bytes = expected_total_bytes;
            let res = collect_manifest_references_impl(
                &fake_exact,
                &[dir.clone(), dir.clone()], // duplicate terminal directory input
                limits_exact,
            )
            .await
            .expect("exact boundary for retained bytes must succeed with deduplication");
            assert_eq!(res.retained_logical_bytes, expected_total_bytes);
            assert_eq!(fake_exact.dir_calls().len(), 1);
            assert_eq!(fake_exact.payload_calls().len(), 1);

            // Subcase B: One-over on root digest fails during retain_digest
            let fake_over = RecordingFakeManifestRefReader::new();
            fake_over.script_dir(
                Some(&dir),
                Ok(vec![make_entry(hex1, DirEntryType::Regular)]),
            );
            fake_over.script_payload(&key1, Ok(mock_payload(empty_manifest)));

            let mut limits_over = ManifestReferenceTestLimits::test_default();
            limits_over.max_retained_logical_bytes = expected_total_bytes - 1;
            let err = collect_manifest_references_impl(&fake_over, &[dir.clone()], limits_over)
                .await
                .expect_err("one-over on retained bytes must fail with Backend");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                    assert!(message.contains(&format!(
                        "retained_logical_bytes limit exceeded: {expected_total_bytes} > {}",
                        expected_total_bytes - 1
                    )));
                }
                other => panic!("expected Backend, got {other:?}"),
            }
            assert_eq!(fake_over.dir_calls().len(), 1);
            assert_eq!(fake_over.payload_calls().len(), 1);

            // Subcase C: Fail before open_payload on manifest_key charge
            let fake_key_limit = RecordingFakeManifestRefReader::new();
            fake_key_limit.script_dir(
                Some(&dir),
                Ok(vec![make_entry(hex1, DirEntryType::Regular)]),
            );

            let mut limits_key = ManifestReferenceTestLimits::test_default();
            limits_key.max_retained_logical_bytes = dir_bytes + key_bytes - 1;
            let err_key =
                collect_manifest_references_impl(&fake_key_limit, &[dir.clone()], limits_key)
                    .await
                    .expect_err(
                        "manifest key charge exceeding budget must fail before payload call",
                    );
            match err_key {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                    assert!(message.contains(&format!(
                        "retained_logical_bytes limit exceeded: {} > {}",
                        dir_bytes + key_bytes,
                        dir_bytes + key_bytes - 1
                    )));
                }
                other => panic!("expected Backend, got {other:?}"),
            }
            assert_eq!(fake_key_limit.dir_calls().len(), 1);
            assert_eq!(fake_key_limit.payload_calls().len(), 0);

            // Subcase D: Fail before enumerate_dir on dir_key charge
            let fake_dir_limit = RecordingFakeManifestRefReader::new();

            let mut limits_dir = ManifestReferenceTestLimits::test_default();
            limits_dir.max_retained_logical_bytes = dir_bytes - 1;
            let err_dir =
                collect_manifest_references_impl(&fake_dir_limit, &[dir.clone()], limits_dir)
                    .await
                    .expect_err("terminal key charge exceeding budget must fail before dir call");
            match err_dir {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                    assert!(message.contains(&format!(
                        "retained_logical_bytes limit exceeded: {dir_bytes} > {}",
                        dir_bytes - 1
                    )));
                }
                other => panic!("expected Backend, got {other:?}"),
            }
            assert_eq!(fake_dir_limit.dir_calls().len(), 0);
        }

        // ====================================================================
        // Category 6: Retained-byte arithmetic overflow through tracker
        // ====================================================================
        {
            let mut tracker = ReferenceAccountingTracker::new();
            tracker.retained_logical_bytes = usize::MAX - 10;
            let err = tracker
                .charge_retained_bytes(20, usize::MAX)
                .expect_err("arithmetic overflow must fail closed");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                    assert!(message.contains("retained_logical_bytes arithmetic overflow"));
                }
                other => panic!("expected Backend, got {other:?}"),
            }
        }
    }

    // ========================================================================
    // 12. Duplicate digests at capacity succeed; new digest fails
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_duplicate_at_capacity_succeeds() {
        let fake = RecordingFakeManifestRefReader::new();
        let dir = ObjectKey::parse("repos/app/manifests").unwrap();
        let hex1 = "1111111111111111111111111111111111111111111111111111111111111111";
        let hex2 = "2222222222222222222222222222222222222222222222222222222222222222";

        fake.script_dir(
            Some(&dir),
            Ok(vec![
                make_entry(hex1, DirEntryType::Regular),
                make_entry(hex2, DirEntryType::Regular),
            ]),
        );

        let key1 = ObjectKey::parse(&format!("repos/app/manifests/{hex1}")).unwrap();
        let key2 = ObjectKey::parse(&format!("repos/app/manifests/{hex2}")).unwrap();

        // Empty manifest payload (only the root digest is inserted)
        let empty_json = b"{}".to_vec();
        fake.script_payload(&key1, Ok(mock_payload(empty_json.clone())));
        fake.script_payload(&key2, Ok(mock_payload(empty_json)));

        let mut limits = ManifestReferenceTestLimits::test_default();
        // Allow exactly 2 references
        limits.max_total_references = 2;

        let res = collect_manifest_references_impl(&fake, &[dir], limits.clone())
            .await
            .expect("should succeed with 2 digests at capacity");
        assert_eq!(res.protected_digests.len(), 2);

        // Now test duplicate digest insertion at capacity directly on tracker
        let mut tracker = ReferenceAccountingTracker::new();
        let d1 = parse_digest(&format!("sha256:{hex1}"));
        let d2 = parse_digest(&format!("sha256:{hex2}"));
        let d3 =
            parse_digest("sha256:3333333333333333333333333333333333333333333333333333333333333333");

        tracker.retain_digest(d1.clone(), &limits).unwrap();
        tracker.retain_digest(d2, &limits).unwrap();
        assert_eq!(tracker.protected_digests.len(), 2);

        // Duplicate of d1 at capacity must SUCCEED
        tracker
            .retain_digest(d1, &limits)
            .expect("duplicate digest at capacity must succeed");

        // 3rd unique digest at capacity must FAIL
        let err = tracker
            .retain_digest(d3, &limits)
            .expect_err("new digest exceeding capacity must fail");
        assert!(matches!(
            err,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Backend,
                ..
            }
        ));
    }

    // ========================================================================
    // 13. Payload ceiling boundaries and sentinel-byte oversize detection
    // ========================================================================
    #[tokio::test]
    async fn test_manifest_refs_payload_ceiling_exact_and_sentinel_oversize() {
        let key = ObjectKey::parse("repos/app/manifests/test").unwrap();

        // Subcase A: Exact boundary succeeds
        let exact_bytes = vec![b'x'; 100];
        let stream = Box::pin(std::io::Cursor::new(exact_bytes.clone()));
        let res = read_payload_stream_bounded(stream, Some(100), &key)
            .await
            .expect("exact boundary must succeed");
        assert_eq!(res.len(), 100);

        // Subcase B: 1-over boundary detected via sentinel byte
        let over_bytes = vec![b'x'; 101];
        let stream_over = Box::pin(std::io::Cursor::new(over_bytes));
        let err = read_payload_stream_bounded(stream_over, Some(100), &key)
            .await
            .expect_err("oversized stream must fail closed");

        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Backend);
                assert!(message.contains("exceeded size ceiling of 100 bytes"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }

        // Subcase C: Arithmetic overflow protection on sentinel byte
        let stream_overflow = Box::pin(std::io::Cursor::new(vec![b'a']));
        let err_overflow = read_payload_stream_bounded(stream_overflow, Some(u64::MAX), &key)
            .await
            .expect_err("u64::MAX limit must fail on limit + 1 sentinel overflow");
        assert!(matches!(
            err_overflow,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Backend,
                ..
            }
        ));
    }

    // ========================================================================
    // 14. Real Filesystem Tests (Linux-gated)
    // ========================================================================
    #[cfg(target_os = "linux")]
    fn create_test_root() -> (tempfile::TempDir, std::path::PathBuf) {
        let fixture = tempfile::tempdir().expect("create tempdir");
        let root = fixture.path().join("storage_root");
        std::fs::create_dir_all(&root).expect("create storage root");
        (fixture, root)
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_manifest_refs_linux_real_fs_same_reader_end_to_end() {
        let (_fixture, root) = create_test_root();

        // 1. Create directory layout with root-adjacent and reserved ancestor paths
        let root_adj_manifests = root.join("repos").join("manifests");
        let nested_manifests = root
            .join("repos")
            .join("library")
            .join("ubuntu")
            .join("manifests");
        let reserved_manifests = root
            .join("repos")
            .join("blobs")
            .join("internal")
            .join("manifests");

        std::fs::create_dir_all(&root_adj_manifests).unwrap();
        std::fs::create_dir_all(&nested_manifests).unwrap();
        std::fs::create_dir_all(&reserved_manifests).unwrap();

        // 2. Write manifest files with distinct content
        let hex1 = "1111111111111111111111111111111111111111111111111111111111111111";
        let hex2 = "2222222222222222222222222222222222222222222222222222222222222222";
        let hex3 = "3333333333333333333333333333333333333333333333333333333333333333";

        let layer1 = "4444444444444444444444444444444444444444444444444444444444444444";
        let layer2 = "5555555555555555555555555555555555555555555555555555555555555555";
        let layer3 = "6666666666666666666666666666666666666666666666666666666666666666";

        std::fs::write(root_adj_manifests.join(hex1), sample_manifest_json(layer1)).unwrap();
        std::fs::write(nested_manifests.join(hex2), sample_manifest_json(layer2)).unwrap();
        std::fs::write(reserved_manifests.join(hex3), sample_manifest_json(layer3)).unwrap();

        // 3. Open single FsMetadataReader
        let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open reader");

        let discovery_limits = super::super::repo_discovery::DiscoveryTestLimits::test_default();
        let ref_limits = ManifestReferenceTestLimits::test_default();

        // 4. Run end-to-end orchestration over same reader
        let res = collect_manifest_references_end_to_end(&reader, discovery_limits, ref_limits)
            .await
            .expect("end to end must succeed");

        assert_eq!(res.terminal_dirs_enumerated, 3);
        assert_eq!(res.manifests_parsed, 3);

        // Verify root digests
        let d1 = parse_digest(&format!("sha256:{hex1}"));
        let d2 = parse_digest(&format!("sha256:{hex2}"));
        let d3 = parse_digest(&format!("sha256:{hex3}"));
        assert!(res.protected_digests.contains(&d1));
        assert!(res.protected_digests.contains(&d2));
        assert!(res.protected_digests.contains(&d3));

        // Verify referenced layer digests
        let l1 = parse_digest(&format!("sha256:{layer1}"));
        let l2 = parse_digest(&format!("sha256:{layer2}"));
        let l3 = parse_digest(&format!("sha256:{layer3}"));
        assert!(res.protected_digests.contains(&l1));
        assert!(res.protected_digests.contains(&l2));
        assert!(res.protected_digests.contains(&l3));
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_manifest_refs_linux_real_fs_symlink_entries_skipped() {
        let (_fixture, root) = create_test_root();
        let manifests_dir = root.join("repos").join("app").join("manifests");
        std::fs::create_dir_all(&manifests_dir).unwrap();

        let real_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let target_file = manifests_dir.join(real_hex);
        std::fs::write(
            &target_file,
            sample_manifest_json(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        )
        .unwrap();

        // Symlink pointing to another file
        let symlink_path =
            manifests_dir.join("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        std::os::unix::fs::symlink(&target_file, &symlink_path).unwrap();

        let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open reader");
        let terminal = ObjectKey::parse("repos/app/manifests").unwrap();
        let limits = ManifestReferenceTestLimits::test_default();

        let res = collect_manifest_references_impl(&reader, &[terminal], limits)
            .await
            .expect("should succeed");

        // Exactly 1 regular file parsed, symlink skipped
        assert_eq!(res.manifests_parsed, 1);
        let real_digest = parse_digest(&format!("sha256:{real_hex}"));
        assert!(res.protected_digests.contains(&real_digest));
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_manifest_refs_linux_real_fs_pinned_root_across_replacement() {
        let (fixture, root) = create_test_root();
        let orig_manifests = root.join("repos").join("app").join("manifests");
        std::fs::create_dir_all(&orig_manifests).unwrap();

        let hex = "1111111111111111111111111111111111111111111111111111111111111111";
        std::fs::write(
            orig_manifests.join(hex),
            sample_manifest_json(
                "2222222222222222222222222222222222222222222222222222222222222222",
            ),
        )
        .unwrap();

        let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open reader");

        // Rename original root and create replacement with different contents
        let renamed = fixture.path().join("storage_root_old");
        std::fs::rename(&root, &renamed).unwrap();
        std::fs::create_dir_all(&root).unwrap();

        let terminal = ObjectKey::parse("repos/app/manifests").unwrap();
        let limits = ManifestReferenceTestLimits::test_default();

        // Pinned reader continues resolving against original inode
        let res = collect_manifest_references_impl(&reader, &[terminal], limits)
            .await
            .expect("pinned reader must resolve original tree");

        assert_eq!(res.manifests_parsed, 1);
        let d = parse_digest(&format!("sha256:{hex}"));
        assert!(res.protected_digests.contains(&d));
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    #[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
    async fn test_manifest_refs_linux_real_fs_permission_denied_restoration_guard() {
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;

        if unsafe { libc::geteuid() } == 0 {
            panic!("ineffective permissions: running as root (UID 0) bypasses DAC");
        }

        let (_fixture, root) = create_test_root();
        let restricted = root.join("repos").join("restricted").join("manifests");
        std::fs::create_dir_all(&restricted).unwrap();

        let orig_perms = std::fs::metadata(&restricted).unwrap().permissions();

        struct ScopedPermReset<'a> {
            path: &'a Path,
            original_permissions: std::fs::Permissions,
        }

        impl<'a> Drop for ScopedPermReset<'a> {
            fn drop(&mut self) {
                if let Err(err) =
                    std::fs::set_permissions(self.path, self.original_permissions.clone())
                {
                    if std::thread::panicking() {
                        eprintln!(
                            "ScopedPermReset: failed to restore permissions on {:?} during unwinding: {err}",
                            self.path
                        );
                    } else {
                        panic!(
                            "ScopedPermReset: failed to restore permissions on {:?}: {err}",
                            self.path
                        );
                    }
                }
            }
        }

        {
            let _guard = ScopedPermReset {
                path: &restricted,
                original_permissions: orig_perms.clone(),
            };

            let mut denied_perms = orig_perms.clone();
            denied_perms.set_mode(0o000);
            std::fs::set_permissions(&restricted, denied_perms).expect("chmod 000");

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open reader");
            let terminal = ObjectKey::parse("repos/restricted/manifests").unwrap();
            let limits = ManifestReferenceTestLimits::test_default();

            let err = collect_manifest_references_impl(&reader, &[terminal], limits)
                .await
                .expect_err("permission denied must fail closed");

            assert!(matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::PermissionDenied,
                    ..
                }
            ));
        }

        let restored_mode = std::fs::metadata(&restricted)
            .expect("metadata should be readable after restore")
            .permissions()
            .mode();
        assert_eq!(
            restored_mode,
            orig_perms.mode(),
            "restored permissions mode ({restored_mode:#o}) must match original ({:#o})",
            orig_perms.mode()
        );
    }
}
