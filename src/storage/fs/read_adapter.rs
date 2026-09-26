//! Consolidated filesystem CAS blob read adapter for `naust`.
//!
//! Provides a unified [`BlobCasReader`] implementation wrapping extracted
//! storage-layer readers ([`storage_core::ObjectMetadataReader`] and
//! [`storage_core::ObjectPayloadReader`]) over an owned [`Arc<R>`].
//!
//! # Architectural Scope & Status
//! This module consolidates metadata and payload seam logic into a single
//! registry-owned adapter wired into production `FsStorage`.
//! - The adapter accepts an already-constructed and probed reader; it does not
//!   open roots or invoke capability probing itself.
//! - Startup open and probing failures are translated by [`map_fs_startup_error`].
//! - Read operations (`head_blob`, `open_blob`) are translated by [`translate_read_error`].

use crate::registry::digest::Digest;
use crate::storage::ports::BlobCasReader;
use crate::storage::{BlobMeta, StorageError, StorageErrorKind};
use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::AsyncRead;

/// Translates strongly typed [`storage_fs::FsMetadataError`] startup and capability-probing
/// failures into registry [`StorageError`] taxonomy.
pub(crate) fn map_fs_startup_error(err: storage_fs::FsMetadataError) -> StorageError {
    match err {
        storage_fs::FsMetadataError::PlatformUnsupported => StorageError::configuration(
            "platform unsupported: descriptor-relative containment requires Linux openat2",
        ),
        storage_fs::FsMetadataError::SyscallUnsupported(e) => StorageError::configuration(format!(
            "openat2 is unavailable in this execution environment: {e}"
        )),
        storage_fs::FsMetadataError::EmptyRootPath => {
            StorageError::configuration("root path cannot be empty")
        }
        storage_fs::FsMetadataError::NulInRootPath => {
            StorageError::configuration("root path contains embedded NUL byte")
        }
        storage_fs::FsMetadataError::UnsupportedObjectType { mode } => {
            StorageError::configuration(format!("root path is not a directory (mode: {mode:#o})"))
        }
        storage_fs::FsMetadataError::ProbeDenied(e) => {
            StorageError::backend(format!("openat2 capability probe denied: {e}"))
        }
        storage_fs::FsMetadataError::ProbeFailed { source } => {
            StorageError::backend(format!("openat2 capability probe failed: {source}"))
        }
        storage_fs::FsMetadataError::RootOpenFailed { source } => {
            StorageError::io(format!("failed to open root directory: {source}"))
        }
        // Documented conservative fallback: non-exhaustive variants or unexpected errors during
        // initialization/probing are treated as backend errors with diagnostics preserved.
        other => StorageError::backend(format!(
            "unexpected storage initialization failure: {other}"
        )),
    }
}

/// Constructs the primary CAS object key for a blob digest: `blobs/<alg>/<prefix2>/<hex>`.
pub(crate) fn blob_primary_key(digest: &Digest) -> Result<storage_core::ObjectKey, StorageError> {
    let key_str = format!(
        "blobs/{}/{}/{}",
        digest.algorithm(),
        digest.prefix2(),
        digest.hex()
    );
    storage_core::ObjectKey::parse(&key_str)
        .map_err(|e| StorageError::internal(StorageErrorKind::InternalInvariant, e.to_string()))
}

/// Constructs the quarantine CAS object key for a blob digest: `quarantine/blobs/<alg>/<prefix2>/<hex>`.
pub(crate) fn blob_quarantine_key(
    digest: &Digest,
) -> Result<storage_core::ObjectKey, StorageError> {
    let key_str = format!(
        "quarantine/blobs/{}/{}/{}",
        digest.algorithm(),
        digest.prefix2(),
        digest.hex()
    );
    storage_core::ObjectKey::parse(&key_str)
        .map_err(|e| StorageError::internal(StorageErrorKind::InternalInvariant, e.to_string()))
}

/// Identifies the read operation context for diagnostic differentiation on unknown errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadOp {
    Metadata,
    Payload,
}

/// Translates strongly typed [`storage_core::ReadError`] outcomes into legacy [`StorageError`] taxonomy.
pub(crate) fn translate_read_error(err: storage_core::ReadError, op: ReadOp) -> StorageError {
    match err {
        storage_core::ReadError::NotFound { .. } => StorageError::NotFound,
        storage_core::ReadError::PermissionDenied { ref source, .. } => {
            if let Some(src) = source {
                if let Some(io_err) = src.downcast_ref::<std::io::Error>() {
                    return StorageError::io(io_err.to_string());
                }
                StorageError::io(src.to_string())
            } else {
                StorageError::io("permission denied")
            }
        }
        storage_core::ReadError::Backend {
            ref message,
            ref source,
            ..
        } => {
            if let Some(src) = source {
                if let Some(fs_err) = src.downcast_ref::<storage_fs::FsMetadataError>() {
                    match fs_err {
                        storage_fs::FsMetadataError::ResolutionRejected { source, .. } => {
                            return StorageError::io(source.to_string());
                        }
                        storage_fs::FsMetadataError::UnsupportedObjectType { mode, .. } => {
                            return StorageError::io(format!(
                                "unsupported object type (mode: {mode:#o})"
                            ));
                        }
                        storage_fs::FsMetadataError::SyscallUnsupported(io_err) => {
                            return StorageError::configuration(format!(
                                "openat2 is unavailable in this execution environment: {io_err}"
                            ));
                        }
                        storage_fs::FsMetadataError::StatFailed { stage, source } => {
                            return StorageError::io(format!(
                                "failed to stat {stage} descriptor: {source}"
                            ));
                        }
                        storage_fs::FsMetadataError::ProcfsReopenFailed { source } => {
                            return StorageError::io(format!(
                                "failed to reopen descriptor via procfs: {source}"
                            ));
                        }
                        storage_fs::FsMetadataError::IdentityMismatch { .. } => {
                            return StorageError::io(fs_err.to_string());
                        }
                        storage_fs::FsMetadataError::InvalidMetadata { .. } => {
                            return StorageError::io(fs_err.to_string());
                        }
                        storage_fs::FsMetadataError::PlatformUnsupported => {
                            return StorageError::io(fs_err.to_string());
                        }
                        storage_fs::FsMetadataError::RuntimeMissing(_) => {
                            return StorageError::backend(fs_err.to_string());
                        }
                        storage_fs::FsMetadataError::TaskJoinFailed(_) => {
                            return StorageError::backend(fs_err.to_string());
                        }
                        _ => return StorageError::io(fs_err.to_string()),
                    }
                } else if let Some(io_err) = src.downcast_ref::<std::io::Error>() {
                    StorageError::io(io_err.to_string())
                } else {
                    StorageError::io(src.to_string())
                }
            } else {
                StorageError::io(message)
            }
        }
        _ => match op {
            ReadOp::Metadata => StorageError::io("unknown storage metadata read failure"),
            ReadOp::Payload => StorageError::io("unknown storage payload read failure"),
        },
    }
}

/// Translates metadata read errors into [`StorageError`].
pub(crate) fn translate_metadata_read_error(err: storage_core::ReadError) -> StorageError {
    translate_read_error(err, ReadOp::Metadata)
}

/// Translates payload read errors into [`StorageError`].
pub(crate) fn translate_payload_read_error(err: storage_core::ReadError) -> StorageError {
    translate_read_error(err, ReadOp::Payload)
}

/// Queries blob metadata via an [`storage_core::ObjectMetadataReader`].
///
/// Implements two-stage digest resolution:
/// 1. Primary lookup at `blobs/<algorithm>/<prefix2>/<hex>`.
/// 2. Quarantine fallback at `quarantine/blobs/<algorithm>/<prefix2>/<hex>` **only** if the primary
///    lookup returns [`storage_core::ReadError::NotFound`].
///
/// Any other failure on primary immediately returns without attempting quarantine.
/// Any failure on quarantine returns immediately without further lookup.
pub(crate) async fn head_blob_seam(
    reader: &(impl storage_core::ObjectMetadataReader + ?Sized),
    digest: &Digest,
) -> Result<BlobMeta, StorageError> {
    let primary_key = blob_primary_key(digest)?;

    match reader.head(&primary_key).await {
        Ok(meta) => Ok(BlobMeta { size: meta.size() }),
        Err(storage_core::ReadError::NotFound { .. }) => {
            let quarantine_key = blob_quarantine_key(digest)?;

            match reader.head(&quarantine_key).await {
                Ok(meta) => Ok(BlobMeta { size: meta.size() }),
                Err(storage_core::ReadError::NotFound { .. }) => Err(StorageError::NotFound),
                Err(other) => Err(translate_metadata_read_error(other)),
            }
        }
        Err(other) => Err(translate_metadata_read_error(other)),
    }
}

/// Acquires readable blob payload stream via an [`storage_core::ObjectPayloadReader`].
///
/// Implements two-stage digest resolution:
/// 1. Primary lookup at `blobs/<algorithm>/<prefix2>/<hex>`.
/// 2. Quarantine fallback at `quarantine/blobs/<algorithm>/<prefix2>/<hex>` **only** if the primary
///    lookup returns [`storage_core::ReadError::NotFound`].
///
/// Any other failure on primary immediately returns without attempting quarantine.
/// Any failure on quarantine returns immediately without further lookup.
///
/// Returns the registry-compatible [`BlobMeta`] and owned [`Pin<Box<dyn AsyncRead + Send>>`].
/// Preserves the exact `u64` size without reading, buffering, or collecting bytes during acquisition.
/// Once acquired, stream read failures are surfaced directly as [`std::io::Error`] during polling,
/// without triggering re-acquisition or fallback.
pub(crate) async fn open_blob_seam(
    reader: &(impl storage_core::ObjectPayloadReader + ?Sized),
    digest: &Digest,
) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError> {
    let primary_key = blob_primary_key(digest)?;

    match reader.open_payload(&primary_key).await {
        Ok(payload) => {
            let (meta, stream) = payload.into_parts();
            Ok((BlobMeta { size: meta.size() }, stream))
        }
        Err(storage_core::ReadError::NotFound { .. }) => {
            let quarantine_key = blob_quarantine_key(digest)?;

            match reader.open_payload(&quarantine_key).await {
                Ok(payload) => {
                    let (meta, stream) = payload.into_parts();
                    Ok((BlobMeta { size: meta.size() }, stream))
                }
                Err(storage_core::ReadError::NotFound { .. }) => Err(StorageError::NotFound),
                Err(other) => Err(translate_payload_read_error(other)),
            }
        }
        Err(other) => Err(translate_payload_read_error(other)),
    }
}

/// Registry-owned filesystem CAS blob read adapter wrapping a unified reader into [`BlobCasReader`].
///
/// Accepts an already-constructed reader `R` implementing both [`storage_core::ObjectMetadataReader`]
/// and [`storage_core::ObjectPayloadReader`].
#[derive(Debug)]
pub struct FsBlobCasReadAdapter<R: ?Sized> {
    reader: Arc<R>,
}

impl<R: ?Sized> FsBlobCasReadAdapter<R> {
    /// Creates a new adapter wrapping the provided reader instance.
    pub(crate) fn new(reader: Arc<R>) -> Self {
        Self { reader }
    }

    /// Returns a reference to the inner shared reader.
    #[cfg(any(test, feature = "test-mocks"))]
    #[doc(hidden)] // white-box window for wiring tests; curated in plan Phase 3
    pub fn reader(&self) -> &Arc<R> {
        &self.reader
    }
}

#[async_trait]
impl<R> BlobCasReader for FsBlobCasReadAdapter<R>
where
    R: storage_core::ObjectMetadataReader
        + storage_core::ObjectPayloadReader
        + Send
        + Sync
        + ?Sized
        + 'static,
{
    async fn head_blob(&self, digest: &Digest) -> Result<BlobMeta, StorageError> {
        head_blob_seam(self.reader.as_ref(), digest).await
    }

    async fn open_blob(
        &self,
        digest: &Digest,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError> {
        open_blob_seam(self.reader.as_ref(), digest).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, VecDeque};
    use std::sync::Mutex;
    use storage_core::{
        ObjectKey, ObjectMetadata, ObjectPayload, ObjectPayloadReader, ObjectStream, ReadError,
    };
    use tokio::io::AsyncReadExt;

    struct UnifiedRecordingFakeReader {
        meta_calls: Arc<Mutex<Vec<ObjectKey>>>,
        payload_calls: Arc<Mutex<Vec<ObjectKey>>>,
        meta_responses: Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<ObjectMetadata, ReadError>>>>>,
        payload_responses:
            Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<ObjectPayload, ReadError>>>>>,
    }

    impl UnifiedRecordingFakeReader {
        fn new() -> Self {
            Self {
                meta_calls: Arc::new(Mutex::new(Vec::new())),
                payload_calls: Arc::new(Mutex::new(Vec::new())),
                meta_responses: Arc::new(Mutex::new(HashMap::new())),
                payload_responses: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn script_meta(&self, key: ObjectKey, response: Result<ObjectMetadata, ReadError>) {
            self.meta_responses
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push_back(response);
        }

        fn script_payload(&self, key: ObjectKey, response: Result<ObjectPayload, ReadError>) {
            self.payload_responses
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push_back(response);
        }

        fn meta_calls(&self) -> Vec<ObjectKey> {
            self.meta_calls.lock().unwrap().clone()
        }

        fn payload_calls(&self) -> Vec<ObjectKey> {
            self.payload_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl storage_core::ObjectMetadataReader for UnifiedRecordingFakeReader {
        async fn head(&self, key: &ObjectKey) -> Result<ObjectMetadata, ReadError> {
            self.meta_calls.lock().unwrap().push(key.clone());
            let mut responses = self.meta_responses.lock().unwrap();
            let queue = responses
                .get_mut(key)
                .unwrap_or_else(|| panic!("unexpected meta call with key: {key}"));
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted meta responses for key: {key}"))
        }
    }

    #[async_trait]
    impl ObjectPayloadReader for UnifiedRecordingFakeReader {
        async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError> {
            self.payload_calls.lock().unwrap().push(key.clone());
            let mut responses = self.payload_responses.lock().unwrap();
            let queue = responses
                .get_mut(key)
                .unwrap_or_else(|| panic!("unexpected payload call with key: {key}"));
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted payload responses for key: {key}"))
        }
    }

    fn test_digest(hex: &str) -> Digest {
        Digest::parse(&format!("sha256:{hex}")).expect("valid sha256 digest")
    }

    fn mock_payload(bytes: Vec<u8>) -> ObjectPayload {
        let meta = ObjectMetadata::new(bytes.len() as u64);
        let stream: ObjectStream = Box::pin(std::io::Cursor::new(bytes));
        ObjectPayload::new(meta, stream)
    }

    #[tokio::test]
    async fn test_adapter_implements_blob_cas_reader_port() {
        let fake = Arc::new(UnifiedRecordingFakeReader::new());
        let adapter = FsBlobCasReadAdapter::new(fake.clone());

        let digest =
            test_digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();

        fake.script_meta(primary_key.clone(), Ok(ObjectMetadata::new(1024)));
        fake.script_payload(primary_key.clone(), Ok(mock_payload(vec![0x42; 1024])));

        // Explicit dynamic/trait assertion that FsBlobCasReadAdapter satisfies BlobCasReader
        let port_reader: &dyn BlobCasReader = &adapter;

        let meta = port_reader
            .head_blob(&digest)
            .await
            .expect("head_blob succeeds via port");
        assert_eq!(meta.size, 1024);

        let (payload_meta, mut stream) = port_reader
            .open_blob(&digest)
            .await
            .expect("open_blob succeeds via port");
        assert_eq!(payload_meta.size, 1024);

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read stream");
        assert_eq!(buf.len(), 1024);

        // Verify both methods dispatched through the exact same underlying Arc instance
        assert!(Arc::ptr_eq(&adapter.reader, &fake));
        assert_eq!(fake.meta_calls(), vec![primary_key.clone()]);
        assert_eq!(fake.payload_calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_adapter_both_methods_operate_through_same_owned_reader() {
        let fake = Arc::new(UnifiedRecordingFakeReader::new());
        let adapter = FsBlobCasReadAdapter::new(fake.clone());

        assert!(Arc::ptr_eq(adapter.reader(), &fake));

        let digest =
            test_digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        let quarantine_key = ObjectKey::parse(
            "quarantine/blobs/sha256/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();

        // 1. Primary not found, quarantine success on metadata
        fake.script_meta(
            primary_key.clone(),
            Err(ReadError::not_found(primary_key.clone())),
        );
        fake.script_meta(quarantine_key.clone(), Ok(ObjectMetadata::new(2048)));

        let meta = adapter
            .head_blob(&digest)
            .await
            .expect("quarantine meta ok");
        assert_eq!(meta.size, 2048);
        assert_eq!(
            fake.meta_calls(),
            vec![primary_key.clone(), quarantine_key.clone()]
        );

        // 2. Primary not found, quarantine success on payload
        fake.script_payload(
            primary_key.clone(),
            Err(ReadError::not_found(primary_key.clone())),
        );
        fake.script_payload(quarantine_key.clone(), Ok(mock_payload(vec![0xbb; 2048])));

        let (meta, mut stream) = adapter
            .open_blob(&digest)
            .await
            .expect("quarantine payload ok");
        assert_eq!(meta.size, 2048);
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read stream");
        assert_eq!(buf, vec![0xbb; 2048]);
        assert_eq!(fake.payload_calls(), vec![primary_key, quarantine_key]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_adapter_real_fs_metadata_and_payload_shared_reader() {
        let fixture = tempfile::tempdir().expect("create tempdir");
        let root = fixture.path().join("storage_root");
        std::fs::create_dir_all(&root).expect("create storage root");

        let digest =
            test_digest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let rel_path =
            "blobs/sha256/cc/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let full_path = root.join(rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dirs");
        }
        let content = b"real linux fs content via FsBlobCasReadAdapter";
        std::fs::write(&full_path, content).expect("write blob file");

        let reader = Arc::new(storage_fs::FsMetadataReader::open(&root).expect("open root reader"));
        let adapter = FsBlobCasReadAdapter::new(reader.clone());

        // Verify head_blob via BlobCasReader
        let meta = adapter.head_blob(&digest).await.expect("head_blob ok");
        assert_eq!(meta.size, content.len() as u64);

        // Verify open_blob via BlobCasReader
        let (payload_meta, mut stream) = adapter.open_blob(&digest).await.expect("open_blob ok");
        assert_eq!(payload_meta.size, content.len() as u64);

        let mut read_bytes = Vec::new();
        stream
            .read_to_end(&mut read_bytes)
            .await
            .expect("read stream");
        assert_eq!(read_bytes, content);
    }
}
