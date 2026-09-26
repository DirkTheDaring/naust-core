//! Registry payload integration seam for evaluating `storage-fs` and `storage-core`
//! payload streaming against `naust` CAS semantics and quarantine orchestration.
//!
//! # Architectural Ownership Boundaries
//! - `storage-core`: Defines domain-neutral contracts ([`storage_core::ObjectPayloadReader`],
//!   [`storage_core::ObjectPayload`], [`storage_core::ObjectStream`], [`storage_core::ReadError`]).
//! - `storage-fs`: Implements Linux descriptor-relative containment (`openat2` + `O_PATH`),
//!   type validation (`S_IFREG`), and Phase 2 readable reopening via `/proc/self/fd/N`.
//! - `naust`: Owns CAS digest layout rules (`blobs/` vs `quarantine/blobs/`),
//!   quarantine fallback orchestration, and legacy [`StorageError`] translation.
//!
//! # Explicit Procfs Trust Assumption
//! When delegating to `storage-fs`, payload acquisition relies on `/proc/self/fd/N` reopening under
//! the explicit assumption that `/proc/self/fd` is genuine, accessible, and stable. Reopening
//! failures are backend mechanism errors and are never reported as missing objects (`NotFound`)
//! or allowed to trigger uncontained pathname fallbacks.
//!
//! # Error Taxonomy Mapping
//! In `storage-core`, any failure other than [`storage_core::ReadError::NotFound`] or
//! [`storage_core::ReadError::PermissionDenied`] is classified generically as [`storage_core::ReadError::Backend`].
//! In `naust`:
//! - Local operating system syscall and descriptor failures ([`storage_fs::FsMetadataError::StatFailed`],
//!   [`storage_fs::FsMetadataError::ProcfsReopenFailed`], [`storage_fs::FsMetadataError::IdentityMismatch`],
//!   [`storage_fs::FsMetadataError::ResolutionRejected`], [`storage_fs::FsMetadataError::UnsupportedObjectType`],
//!   [`storage_fs::FsMetadataError::InvalidMetadata`], [`storage_fs::FsMetadataError::PlatformUnsupported`])
//!   map to [`StorageErrorKind::Io`].
//! - Syscall unavailability ([`storage_fs::FsMetadataError::SyscallUnsupported`]) maps to [`StorageErrorKind::Configuration`].
//! - Tokio runtime / task join failures ([`storage_fs::FsMetadataError::RuntimeMissing`],
//!   [`storage_fs::FsMetadataError::TaskJoinFailed`]) map to [`StorageErrorKind::Backend`].
//! - Boxed error source chains do not survive translation into [`StorageError::Internal`], which stores only
//!   `kind: StorageErrorKind` and `message: String`. Useful diagnostic text is preserved within the message.

use crate::registry::digest::Digest;
use crate::storage::{StorageError, StorageErrorKind};
use std::pin::Pin;
use tokio::io::AsyncRead;

pub(crate) use super::read_adapter::open_blob_seam;

/// Translates strongly typed [`storage_core::ReadError`] outcomes into legacy [`StorageError`] taxonomy
/// by delegating to the shared [`super::read_adapter::translate_payload_read_error`].
#[allow(dead_code)] // Preserved for symmetry with metadata_seam translation helper
pub(crate) fn translate_read_error(err: storage_core::ReadError) -> StorageError {
    super::read_adapter::translate_payload_read_error(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use storage_core::{
        ObjectKey, ObjectMetadata, ObjectPayload, ObjectPayloadReader, ObjectStream, ReadError,
    };
    use tokio::io::AsyncReadExt;

    struct RecordingFakePayloadReader {
        calls: Arc<Mutex<Vec<ObjectKey>>>,
        responses: Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<ObjectPayload, ReadError>>>>>,
    }

    impl RecordingFakePayloadReader {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn script(&self, key: ObjectKey, response: Result<ObjectPayload, ReadError>) {
            self.responses
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push_back(response);
        }

        fn calls(&self) -> Vec<ObjectKey> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ObjectPayloadReader for RecordingFakePayloadReader {
        async fn open_payload(&self, key: &ObjectKey) -> Result<ObjectPayload, ReadError> {
            self.calls.lock().unwrap().push(key.clone());
            let mut responses = self.responses.lock().unwrap();
            let queue = responses.get_mut(key).unwrap_or_else(|| {
                panic!("unexpected call to ObjectPayloadReader with key: {key}")
            });
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted responses for key: {key}"))
        }
    }

    fn expect_seam_err<T>(res: Result<T, StorageError>, msg: &str) -> StorageError {
        match res {
            Ok(_) => panic!("expected error ({msg}), got Ok"),
            Err(e) => e,
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

    struct PollTrackingReader {
        inner: std::io::Cursor<Vec<u8>>,
        poll_count: Arc<AtomicUsize>,
    }

    impl AsyncRead for PollTrackingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.poll_count.fetch_add(1, Ordering::SeqCst);
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    struct FailingStream {
        error_kind: std::io::ErrorKind,
        message: &'static str,
    }

    impl AsyncRead for FailingStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::new(self.error_kind, self.message)))
        }
    }

    // ========================================================================
    // Category A: Recording Fake Payload Reader Tests
    // ========================================================================

    #[tokio::test]
    async fn test_fake_primary_success() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/11/11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        )
        .unwrap();

        let content = b"primary payload bytes".to_vec();
        fake.script(primary_key.clone(), Ok(mock_payload(content.clone())));

        let (meta, mut stream) = open_blob_seam(&fake, &digest)
            .await
            .expect("primary acquisition succeeds");
        assert_eq!(meta.size, content.len() as u64);
        assert_eq!(fake.calls(), vec![primary_key]);

        let mut read_bytes = Vec::new();
        stream
            .read_to_end(&mut read_bytes)
            .await
            .expect("read stream");
        assert_eq!(read_bytes, content);
    }

    #[tokio::test]
    async fn test_fake_primary_not_found_quarantine_success() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/22/22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff",
        )
        .unwrap();
        let quarantine_key = ObjectKey::parse(
            "quarantine/blobs/sha256/22/22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff",
        )
        .unwrap();

        let q_content = b"quarantined payload bytes".to_vec();
        fake.script(
            primary_key.clone(),
            Err(ReadError::not_found(primary_key.clone())),
        );
        fake.script(quarantine_key.clone(), Ok(mock_payload(q_content.clone())));

        let (meta, mut stream) = open_blob_seam(&fake, &digest)
            .await
            .expect("quarantine acquisition succeeds");
        assert_eq!(meta.size, q_content.len() as u64);
        assert_eq!(fake.calls(), vec![primary_key, quarantine_key]);

        let mut read_bytes = Vec::new();
        stream
            .read_to_end(&mut read_bytes)
            .await
            .expect("read stream");
        assert_eq!(read_bytes, q_content);
    }

    #[tokio::test]
    async fn test_fake_both_missing_returns_not_found() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("33445566778899001122aabbccddeeff33445566778899001122aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/33/33445566778899001122aabbccddeeff33445566778899001122aabbccddeeff",
        )
        .unwrap();
        let quarantine_key = ObjectKey::parse(
            "quarantine/blobs/sha256/33/33445566778899001122aabbccddeeff33445566778899001122aabbccddeeff",
        )
        .unwrap();

        fake.script(
            primary_key.clone(),
            Err(ReadError::not_found(primary_key.clone())),
        );
        fake.script(
            quarantine_key.clone(),
            Err(ReadError::not_found(quarantine_key.clone())),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "both missing returns NotFound",
        );
        assert!(matches!(err, StorageError::NotFound));
        assert_eq!(fake.calls(), vec![primary_key, quarantine_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_permission_denied_suppresses_quarantine() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("44556677889900112233aabbccddeeff44556677889900112233aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/44/44556677889900112233aabbccddeeff44556677889900112233aabbccddeeff",
        )
        .unwrap();

        fake.script(
            primary_key.clone(),
            Err(ReadError::permission_denied(primary_key.clone())),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "permission denied must suppress quarantine",
        );
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(message.contains("permission denied"));
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_containment_rejection_suppresses_quarantine() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("55667788990011223344aabbccddeeff55667788990011223344aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/55/55667788990011223344aabbccddeeff55667788990011223344aabbccddeeff",
        )
        .unwrap();

        let fs_err = storage_fs::FsMetadataError::ResolutionRejected {
            raw_os_error: libc::ELOOP,
            source: std::io::Error::from_raw_os_error(libc::ELOOP),
        };
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "containment rejected",
                Box::new(fs_err),
            )),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "containment failure must suppress quarantine",
        );
        match err {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_unsupported_object_type_suppresses_quarantine() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("66778899001122334455aabbccddeeff66778899001122334455aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/66/66778899001122334455aabbccddeeff66778899001122334455aabbccddeeff",
        )
        .unwrap();

        let fs_err = storage_fs::FsMetadataError::UnsupportedObjectType {
            mode: libc::S_IFDIR as u32,
        };
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "unsupported object type",
                Box::new(fs_err),
            )),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "directory object must suppress quarantine",
        );
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(message.contains("unsupported object type"));
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_stat_failed_suppresses_quarantine() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("77889900112233445566aabbccddeeff77889900112233445566aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/77/77889900112233445566aabbccddeeff77889900112233445566aabbccddeeff",
        )
        .unwrap();

        let fs_err = storage_fs::FsMetadataError::StatFailed {
            stage: "Phase 1 contained",
            source: std::io::Error::from_raw_os_error(libc::EIO),
        };
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "failed to stat descriptor",
                Box::new(fs_err),
            )),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "stat failure must suppress quarantine",
        );
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(message.contains("failed to stat Phase 1 contained descriptor"));
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_procfs_reopen_failure_classified_backend_even_when_enoent_eacces_eperm()
     {
        for (err_code, label) in [
            (libc::ENOENT, "ENOENT"),
            (libc::EACCES, "EACCES"),
            (libc::EPERM, "EPERM"),
        ] {
            let fake = RecordingFakePayloadReader::new();
            let digest =
                test_digest("88990011223344556677aabbccddeeff88990011223344556677aabbccddeeff");
            let primary_key = ObjectKey::parse(
                "blobs/sha256/88/88990011223344556677aabbccddeeff88990011223344556677aabbccddeeff",
            )
            .unwrap();

            // Note: synthetic error fixture demonstrating Phase 2 procfs reopen failure handling.
            let fs_err = storage_fs::FsMetadataError::ProcfsReopenFailed {
                source: std::io::Error::from_raw_os_error(err_code),
            };
            fake.script(
                primary_key.clone(),
                Err(ReadError::backend_with_source(
                    "failed to reopen descriptor via procfs",
                    Box::new(fs_err),
                )),
            );

            let err = expect_seam_err(
                open_blob_seam(&fake, &digest).await,
                &format!("reopen failure with {label} must fail and suppress quarantine"),
            );

            // Must NOT be mapped to NotFound or PermissionDenied
            assert!(
                !matches!(err, StorageError::NotFound),
                "reopen {label} must never map to StorageError::NotFound"
            );
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, StorageErrorKind::Io);
                    assert!(
                        message.contains("failed to reopen descriptor via procfs"),
                        "expected procfs reopen diagnostic, got: {message}"
                    );
                }
                other => panic!("expected StorageError::Internal(Io) for {label}, got: {other:?}"),
            }

            // Quarantine fallback must be suppressed
            assert_eq!(fake.calls(), vec![primary_key]);
        }
    }

    #[tokio::test]
    async fn test_fake_primary_identity_mismatch_suppresses_quarantine() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("99001122334455667788aabbccddeeff99001122334455667788aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/99/99001122334455667788aabbccddeeff99001122334455667788aabbccddeeff",
        )
        .unwrap();

        // Note: synthetic error fixture demonstrating identity mismatch handling.
        let fs_err = storage_fs::FsMetadataError::IdentityMismatch {
            expected_dev: 10,
            expected_ino: 20,
            actual_dev: 10,
            actual_ino: 30,
        };
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "reopened descriptor identity mismatch",
                Box::new(fs_err),
            )),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "identity mismatch must suppress quarantine",
        );
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(message.contains("identity mismatch"));
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_runtime_missing_suppresses_quarantine() {
        // Obtain genuine TryCurrentError by checking outside runtime context on a clean OS thread
        let try_current_err = match tokio::runtime::Handle::try_current() {
            Ok(_) => std::thread::spawn(|| {
                tokio::runtime::Handle::try_current()
                    .expect_err("clean OS thread must not have an entered Tokio runtime")
            })
            .join()
            .expect("join thread"),
            Err(e) => e,
        };

        let fs_err = storage_fs::FsMetadataError::RuntimeMissing(try_current_err);
        let expected_msg = fs_err.to_string();

        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/a0/a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
        )
        .unwrap();

        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "tokio runtime required",
                Box::new(fs_err),
            )),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "runtime missing must suppress quarantine",
        );
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert_eq!(message, expected_msg);
            }
            other => panic!("expected StorageError::Internal(Backend), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[test]
    fn test_fake_primary_task_join_failed_suppresses_quarantine() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");

        let join_err = rt.block_on(async {
            let task = tokio::task::spawn_blocking(|| {
                panic!("deliberate worker panic to construct genuine JoinError fixture");
            });
            task.await
                .expect_err("task deliberate panic must yield JoinError")
        });

        assert!(join_err.is_panic());
        let fs_err = storage_fs::FsMetadataError::TaskJoinFailed(join_err);
        let expected_msg = fs_err.to_string();

        rt.block_on(async {
            let fake = RecordingFakePayloadReader::new();
            let digest =
                test_digest("b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0");
            let primary_key = ObjectKey::parse(
                "blobs/sha256/b0/b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
            )
            .unwrap();

            fake.script(
                primary_key.clone(),
                Err(ReadError::backend_with_source(
                    "blocking task join failed",
                    Box::new(fs_err),
                )),
            );

            let err = expect_seam_err(
                open_blob_seam(&fake, &digest).await,
                "join failure must suppress quarantine",
            );
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, StorageErrorKind::Backend);
                    assert_eq!(message, expected_msg);
                }
                other => panic!("expected StorageError::Internal(Backend), got: {other:?}"),
            }
            assert_eq!(fake.calls(), vec![primary_key]);
        });
    }

    #[tokio::test]
    async fn test_fake_primary_syscall_unsupported_suppresses_quarantine() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/c0/c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
        )
        .unwrap();

        let fs_err = storage_fs::FsMetadataError::SyscallUnsupported(
            std::io::Error::from_raw_os_error(libc::ENOSYS),
        );
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "openat2 unavailable",
                Box::new(fs_err),
            )),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "syscall unsupported must suppress quarantine",
        );
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Configuration);
                assert!(message.contains("openat2 is unavailable in this execution environment"));
            }
            other => panic!("expected StorageError::Internal(Configuration), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_source_free_and_misleading_diagnostics() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/d0/d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
        )
        .unwrap();

        // Misleading diagnostic text "NotFound" in a Backend error without source
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend(
                "NotFound: object was not located in external service",
            )),
        );

        let err = expect_seam_err(
            open_blob_seam(&fake, &digest).await,
            "misleading message must not bypass typed matching",
        );

        // Must NOT become StorageError::NotFound
        assert!(
            !matches!(err, StorageError::NotFound),
            "source-free Backend with string 'NotFound' must not map to StorageError::NotFound"
        );
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(message.contains("NotFound: object was not located"));
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_size_preservation_above_u32_max_without_large_allocation() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/e0/e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0",
        )
        .unwrap();

        let large_size: u64 = (u32::MAX as u64) + 65536;
        let meta = ObjectMetadata::new(large_size);
        let stream: ObjectStream = Box::pin(std::io::Cursor::new(Vec::new()));
        fake.script(primary_key.clone(), Ok(ObjectPayload::new(meta, stream)));

        let (blob_meta, _stream) = open_blob_seam(&fake, &digest)
            .await
            .expect("open_blob_seam succeeds");
        assert_eq!(blob_meta.size, large_size);
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_no_payload_polling_during_acquisition() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/f0/f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0",
        )
        .unwrap();

        let poll_count = Arc::new(AtomicUsize::new(0));
        let reader_inner = PollTrackingReader {
            inner: std::io::Cursor::new(b"hello world".to_vec()),
            poll_count: Arc::clone(&poll_count),
        };
        let stream: ObjectStream = Box::pin(reader_inner);
        let meta = ObjectMetadata::new(11);
        fake.script(primary_key.clone(), Ok(ObjectPayload::new(meta, stream)));

        let (_blob_meta, mut stream) = open_blob_seam(&fake, &digest)
            .await
            .expect("open_blob_seam succeeds");

        // Zero polls during acquisition
        assert_eq!(
            poll_count.load(Ordering::SeqCst),
            0,
            "acquisition must not poll or buffer the stream"
        );

        // Explicit poll by caller
        let mut buf = [0u8; 5];
        let n = stream.read(&mut buf).await.expect("read chunk");
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
        assert_eq!(
            poll_count.load(Ordering::SeqCst),
            1,
            "polling only occurs when caller drives the stream"
        );
    }

    #[tokio::test]
    async fn test_fake_read_time_io_error_propagates_without_second_reader_call() {
        let fake = RecordingFakePayloadReader::new();
        let digest =
            test_digest("f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/f1/f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1",
        )
        .unwrap();

        let stream: ObjectStream = Box::pin(FailingStream {
            error_kind: std::io::ErrorKind::ConnectionReset,
            message: "simulated stream connection reset",
        });
        let meta = ObjectMetadata::new(100);
        fake.script(primary_key.clone(), Ok(ObjectPayload::new(meta, stream)));

        let (_blob_meta, mut stream) = open_blob_seam(&fake, &digest)
            .await
            .expect("acquisition succeeds");

        // Caller reads from stream and encounters read-time io::Error
        let mut buf = [0u8; 16];
        let err = stream
            .read(&mut buf)
            .await
            .expect_err("stream read must return simulated io::Error");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(
            err.to_string()
                .contains("simulated stream connection reset")
        );

        // Confirm reader was called exactly once: no second lookup or quarantine fallback
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    // ========================================================================
    // Category B: Real storage-fs Filesystem Tests (Linux-gated)
    // ========================================================================

    #[cfg(target_os = "linux")]
    mod linux_fs_tests {
        use super::*;
        use std::path::{Path, PathBuf};

        fn create_test_root() -> (tempfile::TempDir, PathBuf) {
            let fixture = tempfile::tempdir().expect("create tempdir");
            let root = fixture.path().join("storage_root");
            std::fs::create_dir_all(&root).expect("create storage root");
            (fixture, root)
        }

        fn write_blob(root: &Path, rel_path: &str, content: &[u8]) -> PathBuf {
            let path = root.join(rel_path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create parent dirs");
            }
            std::fs::write(&path, content).expect("write blob file");
            path
        }

        #[tokio::test]
        async fn test_real_fs_primary_payload_bytes_and_metadata() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("1010101010101010101010101010101010101010101010101010101010101010");
            let content = b"real storage-fs primary payload content 0123456789";
            write_blob(
                &root,
                "blobs/sha256/10/1010101010101010101010101010101010101010101010101010101010101010",
                content,
            );

            let reader = storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let (meta, mut stream) = open_blob_seam(&reader, &digest)
                .await
                .expect("open_blob_seam succeeds on real primary blob");
            assert_eq!(meta.size, content.len() as u64);

            let mut read_bytes = Vec::new();
            stream
                .read_to_end(&mut read_bytes)
                .await
                .expect("read stream");
            assert_eq!(read_bytes, content);
        }

        #[tokio::test]
        async fn test_real_fs_genuine_primary_missing_quarantine_fallback() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("2020202020202020202020202020202020202020202020202020202020202020");
            let content = b"quarantined real blob content 9876543210";
            write_blob(
                &root,
                "quarantine/blobs/sha256/20/2020202020202020202020202020202020202020202020202020202020202020",
                content,
            );

            let reader = storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let (meta, mut stream) = open_blob_seam(&reader, &digest)
                .await
                .expect("quarantine fallback succeeds when primary is missing");
            assert_eq!(meta.size, content.len() as u64);

            let mut read_bytes = Vec::new();
            stream
                .read_to_end(&mut read_bytes)
                .await
                .expect("read stream");
            assert_eq!(read_bytes, content);
        }

        #[tokio::test]
        async fn test_real_fs_returned_stream_usable_after_dropping_reader_and_digest() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("3030303030303030303030303030303030303030303030303030303030303030");
            let content = b"decoupled stream lifetime verification content";
            write_blob(
                &root,
                "blobs/sha256/30/3030303030303030303030303030303030303030303030303030303030303030",
                content,
            );

            let reader = storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let (meta, mut stream) = open_blob_seam(&reader, &digest)
                .await
                .expect("open_blob_seam succeeds");
            assert_eq!(meta.size, content.len() as u64);

            // Explicitly drop originating reader and digest
            drop(reader);
            drop(digest);

            // Stream remains fully functional
            let mut read_bytes = Vec::new();
            stream
                .read_to_end(&mut read_bytes)
                .await
                .expect("read stream after drops");
            assert_eq!(read_bytes, content);
        }

        #[tokio::test]
        async fn test_real_fs_primary_containment_rejection_suppresses_valid_quarantine() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("4040404040404040404040404040404040404040404040404040404040404040");

            // Dangling or rejected primary symlink
            let non_existent = root.join("blobs/nonexistent.bin");
            let blob_path = root.join(
                "blobs/sha256/40/4040404040404040404040404040404040404040404040404040404040404040",
            );
            std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&non_existent, &blob_path).unwrap();

            // Valid quarantine regular file
            write_blob(
                &root,
                "quarantine/blobs/sha256/40/4040404040404040404040404040404040404040404040404040404040404040",
                b"valid quarantine blob that must not be accessed",
            );

            let reader = storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = expect_seam_err(
                open_blob_seam(&reader, &digest).await,
                "containment failure on primary must suppress quarantine",
            );
            match err {
                StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_primary_directory_rejection_suppresses_quarantine() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("5050505050505050505050505050505050505050505050505050505050505050");

            // Primary is a directory
            let dir_blob = root.join(
                "blobs/sha256/50/5050505050505050505050505050505050505050505050505050505050505050",
            );
            std::fs::create_dir_all(&dir_blob).unwrap();

            // Valid quarantine regular file
            write_blob(
                &root,
                "quarantine/blobs/sha256/50/5050505050505050505050505050505050505050505050505050505050505050",
                b"valid quarantine blob that must not be accessed",
            );

            let reader = storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = expect_seam_err(
                open_blob_seam(&reader, &digest).await,
                "directory on primary must suppress quarantine",
            );
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, StorageErrorKind::Io);
                    assert!(message.contains("unsupported object type"));
                }
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_shared_reader_pinned_root_across_rename() {
            let (fixture, root) = create_test_root();
            let digest =
                test_digest("6060606060606060606060606060606060606060606060606060606060606060");
            let content = b"pinned root descriptor content across rename";
            write_blob(
                &root,
                "blobs/sha256/60/6060606060606060606060606060606060606060606060606060606060606060",
                content,
            );

            // Open reader once against initial storage root
            let reader = storage_fs::FsMetadataReader::open(&root).expect("open root reader");

            // Rename storage root and create a brand-new empty directory at original path
            let old_root = fixture.path().join("storage_root_old");
            std::fs::rename(&root, &old_root).expect("rename storage root");
            std::fs::create_dir_all(&root).expect("recreate empty storage root");

            // 1. Query metadata via shared reader using metadata seam
            let meta = crate::storage::fs::metadata_seam::head_blob_seam(&reader, &digest)
                .await
                .expect("metadata query succeeds via pinned root");
            assert_eq!(meta.size, content.len() as u64);

            // 2. Open payload via the same shared reader using payload seam
            let (blob_meta, mut stream) = open_blob_seam(&reader, &digest)
                .await
                .expect("payload stream succeeds via pinned root");
            assert_eq!(blob_meta.size, content.len() as u64);

            // 3. Verify content matches exactly
            let mut read_bytes = Vec::new();
            stream
                .read_to_end(&mut read_bytes)
                .await
                .expect("read stream");
            assert_eq!(read_bytes, content);
        }
    }
}
