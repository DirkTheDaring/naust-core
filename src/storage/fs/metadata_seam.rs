//! Registry metadata integration seam for evaluating `storage-fs` against
//! `naust` storage semantics and quarantine orchestration.

use crate::registry::digest::Digest;
use crate::storage::{StorageError, StorageErrorKind};

pub(crate) use super::read_adapter::head_blob_seam;

/// Translates strongly typed [`naust_storage_core::ReadError`] outcomes into legacy [`StorageError`] taxonomy
/// by delegating to the shared [`super::read_adapter::translate_metadata_read_error`].
pub(crate) fn translate_read_error(err: naust_storage_core::ReadError) -> StorageError {
    super::read_adapter::translate_metadata_read_error(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use naust_storage_core::{ObjectKey, ObjectMetadata, ObjectMetadataReader, ReadError};
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    struct RecordingFakeReader {
        calls: Arc<Mutex<Vec<ObjectKey>>>,
        responses: Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<ObjectMetadata, ReadError>>>>>,
    }

    impl RecordingFakeReader {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                responses: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn script(&self, key: ObjectKey, response: Result<ObjectMetadata, ReadError>) {
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
    impl ObjectMetadataReader for RecordingFakeReader {
        async fn head(&self, key: &ObjectKey) -> Result<ObjectMetadata, ReadError> {
            self.calls.lock().unwrap().push(key.clone());
            let mut responses = self.responses.lock().unwrap();
            let queue = responses.get_mut(key).unwrap_or_else(|| {
                panic!("unexpected call to ObjectMetadataReader with key: {key}")
            });
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted responses for key: {key}"))
        }
    }

    fn test_digest(hex: &str) -> Digest {
        Digest::parse(&format!("sha256:{hex}")).expect("valid sha256 digest")
    }

    // ========================================================================
    // Category A: Recording Fake Reader Tests
    // ========================================================================

    #[tokio::test]
    async fn test_fake_primary_success() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/11/11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        )
        .unwrap();

        fake.script(primary_key.clone(), Ok(ObjectMetadata::new(12345)));

        let meta = head_blob_seam(&fake, &digest)
            .await
            .expect("primary lookup succeeds");
        assert_eq!(meta.size, 12345);
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_missing_quarantine_success() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/22/22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff",
        )
        .unwrap();
        let quarantine_key = ObjectKey::parse("quarantine/blobs/sha256/22/22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff").unwrap();

        fake.script(
            primary_key.clone(),
            Err(ReadError::not_found(primary_key.clone())),
        );
        fake.script(quarantine_key.clone(), Ok(ObjectMetadata::new(67890)));

        let meta = head_blob_seam(&fake, &digest)
            .await
            .expect("quarantine lookup succeeds");
        assert_eq!(meta.size, 67890);
        assert_eq!(fake.calls(), vec![primary_key, quarantine_key]);
    }

    #[tokio::test]
    async fn test_fake_both_missing_returns_not_found() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("33445566778899001122aabbccddeeff33445566778899001122aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/33/33445566778899001122aabbccddeeff33445566778899001122aabbccddeeff",
        )
        .unwrap();
        let quarantine_key = ObjectKey::parse("quarantine/blobs/sha256/33/33445566778899001122aabbccddeeff33445566778899001122aabbccddeeff").unwrap();

        fake.script(
            primary_key.clone(),
            Err(ReadError::not_found(primary_key.clone())),
        );
        fake.script(
            quarantine_key.clone(),
            Err(ReadError::not_found(quarantine_key.clone())),
        );

        let err = head_blob_seam(&fake, &digest)
            .await
            .expect_err("both missing must fail with NotFound");
        assert!(matches!(err, StorageError::NotFound));
        assert_eq!(fake.calls(), vec![primary_key, quarantine_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_permission_denied_suppresses_quarantine() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("44556677889900112233aabbccddeeff44556677889900112233aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/44/44556677889900112233aabbccddeeff44556677889900112233aabbccddeeff",
        )
        .unwrap();

        let io_err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "DAC search permission denied",
        );
        let expected_msg = io_err.to_string();
        fake.script(
            primary_key.clone(),
            Err(ReadError::permission_denied_with_source(
                primary_key.clone(),
                Box::new(io_err),
            )),
        );

        let err = head_blob_seam(&fake, &digest)
            .await
            .expect_err("primary permission denied must return immediately");
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert_eq!(message, expected_msg);
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_ordinary_io_error_suppresses_quarantine() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("55667788990011223344aabbccddeeff55667788990011223344aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/55/55667788990011223344aabbccddeeff55667788990011223344aabbccddeeff",
        )
        .unwrap();

        let io_err =
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "bad sector read failed");
        let expected_msg = io_err.to_string();
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "storage failure",
                Box::new(io_err),
            )),
        );

        let err = head_blob_seam(&fake, &digest)
            .await
            .expect_err("primary ordinary io error must return immediately");
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert_eq!(message, expected_msg);
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_resolution_rejection_suppresses_quarantine() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("66778899001122334455aabbccddeeff66778899001122334455aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/66/66778899001122334455aabbccddeeff66778899001122334455aabbccddeeff",
        )
        .unwrap();

        let underlying_io = std::io::Error::from_raw_os_error(libc::ELOOP);
        let expected_msg = underlying_io.to_string();
        let fs_err = naust_storage_fs::FsMetadataError::ResolutionRejected {
            raw_os_error: libc::ELOOP,
            source: underlying_io,
        };
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "containment policy rejected",
                Box::new(fs_err),
            )),
        );

        let err = head_blob_seam(&fake, &digest)
            .await
            .expect_err("resolution rejection must suppress quarantine");
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert_eq!(message, expected_msg);
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_unsupported_object_type_suppresses_quarantine() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("77889900112233445566aabbccddeeff77889900112233445566aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/77/77889900112233445566aabbccddeeff77889900112233445566aabbccddeeff",
        )
        .unwrap();

        let fs_err = naust_storage_fs::FsMetadataError::UnsupportedObjectType { mode: 0o040755 };
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "unsupported object",
                Box::new(fs_err),
            )),
        );

        let err = head_blob_seam(&fake, &digest)
            .await
            .expect_err("directory rejection must suppress quarantine");
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(message.contains("unsupported object type (mode: 0o40755)"));
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_primary_syscall_unsupported_suppresses_quarantine() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("88990011223344556677aabbccddeeff88990011223344556677aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/88/88990011223344556677aabbccddeeff88990011223344556677aabbccddeeff",
        )
        .unwrap();

        let underlying_io = std::io::Error::from_raw_os_error(libc::ENOSYS);
        let fs_err = naust_storage_fs::FsMetadataError::SyscallUnsupported(underlying_io);
        fake.script(
            primary_key.clone(),
            Err(ReadError::backend_with_source(
                "openat2 unavailable",
                Box::new(fs_err),
            )),
        );

        let err = head_blob_seam(&fake, &digest)
            .await
            .expect_err("syscall unsupported must suppress quarantine");
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Configuration);
                assert!(message.contains("openat2 is unavailable in this execution environment"));
                assert!(
                    message.contains(&std::io::Error::from_raw_os_error(libc::ENOSYS).to_string())
                );
            }
            other => panic!("expected StorageError::Internal(Configuration), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[test]
    fn test_fake_primary_runtime_missing_suppresses_quarantine() {
        // Obtain genuine TryCurrentError outside an entered Tokio runtime.
        let try_current_err = match tokio::runtime::Handle::try_current() {
            Ok(_) => std::thread::spawn(|| {
                tokio::runtime::Handle::try_current()
                    .expect_err("clean OS thread must not have an entered Tokio runtime")
            })
            .join()
            .expect("join thread"),
            Err(e) => e,
        };

        let try_current_err_str = try_current_err.to_string();
        let fs_err = naust_storage_fs::FsMetadataError::RuntimeMissing(try_current_err);
        let expected_msg = fs_err.to_string();
        assert!(
            expected_msg.starts_with("tokio runtime required: "),
            "expected diagnostic prefix, got: {expected_msg}"
        );
        assert_eq!(
            expected_msg,
            format!("tokio runtime required: {try_current_err_str}")
        );

        // 1. Direct translation check
        let try_current_err_direct = match tokio::runtime::Handle::try_current() {
            Ok(_) => std::thread::spawn(|| {
                tokio::runtime::Handle::try_current()
                    .expect_err("clean OS thread must not have an entered Tokio runtime")
            })
            .join()
            .expect("join thread"),
            Err(e) => e,
        };
        let fs_err_direct =
            naust_storage_fs::FsMetadataError::RuntimeMissing(try_current_err_direct);
        let expected_msg_direct = fs_err_direct.to_string();
        let direct_err = translate_read_error(ReadError::backend_with_source(
            "tokio runtime missing",
            Box::new(fs_err_direct),
        ));
        match direct_err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert_eq!(message, expected_msg_direct);
            }
            other => panic!("expected StorageError::Internal(Backend), got: {other:?}"),
        }

        // 2. Seam execution in dedicated runtime
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build isolated test runtime");

        rt.block_on(async {
            let fake = RecordingFakeReader::new();
            let digest =
                test_digest("1010101010101010101010101010101010101010101010101010101010101010");
            let primary_key = ObjectKey::parse(
                "blobs/sha256/10/1010101010101010101010101010101010101010101010101010101010101010",
            )
            .unwrap();

            fake.script(
                primary_key.clone(),
                Err(ReadError::backend_with_source(
                    "tokio runtime missing",
                    Box::new(fs_err),
                )),
            );

            let err = head_blob_seam(&fake, &digest)
                .await
                .expect_err("runtime missing must return error and suppress quarantine");

            match &err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(*kind, StorageErrorKind::Backend);
                    assert_eq!(message, &expected_msg);
                    assert_eq!(
                        message,
                        &format!("tokio runtime required: {try_current_err_str}")
                    );
                }
                other => panic!("expected StorageError::Internal(Backend), got: {other:?}"),
            }

            // Verify error does not become NotFound or PermissionDenied
            assert!(!matches!(err, StorageError::NotFound));
            assert_ne!(
                match &err {
                    StorageError::Internal { kind, .. } => *kind,
                    _ => StorageErrorKind::InternalInvariant,
                },
                StorageErrorKind::PermissionDenied
            );

            // Verify quarantine fallback is suppressed and fake records only primary lookup
            assert_eq!(fake.calls(), vec![primary_key]);
        });
    }

    #[test]
    fn test_fake_primary_task_join_failed_suppresses_quarantine() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build isolated test runtime");

        // Obtain genuine JoinError from an explicitly awaited task that intentionally panics
        // in an isolated test runtime. This fixture demonstrates translation of a genuine
        // JoinError; it does not represent or prove that a storage syscall panicked.
        let (join_err, join_err_direct) = rt.block_on(async {
            let task1 = tokio::task::spawn_blocking(|| {
                panic!("deliberate worker panic to construct genuine JoinError fixture");
            });
            let task2 = tokio::task::spawn_blocking(|| {
                panic!("deliberate worker panic to construct genuine JoinError fixture");
            });
            let err1 = task1
                .await
                .expect_err("task1 deliberate panic must yield JoinError");
            let err2 = task2
                .await
                .expect_err("task2 deliberate panic must yield JoinError");
            (err1, err2)
        });

        assert!(
            join_err.is_panic(),
            "constructed JoinError must represent a panic"
        );
        let fs_err = naust_storage_fs::FsMetadataError::TaskJoinFailed(join_err);
        let expected_msg = fs_err.to_string();
        assert!(
            expected_msg.starts_with("blocking metadata task failed: "),
            "expected diagnostic prefix, got: {expected_msg}"
        );

        // 1. Direct translation check
        let fs_err_direct = naust_storage_fs::FsMetadataError::TaskJoinFailed(join_err_direct);
        let expected_msg_direct = fs_err_direct.to_string();
        let direct_err = translate_read_error(ReadError::backend_with_source(
            "blocking task failed",
            Box::new(fs_err_direct),
        ));
        match direct_err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Backend);
                assert_eq!(message, expected_msg_direct);
            }
            other => panic!("expected StorageError::Internal(Backend), got: {other:?}"),
        }

        // 2. Seam execution in dedicated runtime
        rt.block_on(async {
            let fake = RecordingFakeReader::new();
            let digest =
                test_digest("2020202020202020202020202020202020202020202020202020202020202020");
            let primary_key = ObjectKey::parse(
                "blobs/sha256/20/2020202020202020202020202020202020202020202020202020202020202020",
            )
            .unwrap();

            fake.script(
                primary_key.clone(),
                Err(ReadError::backend_with_source(
                    "blocking metadata task failed",
                    Box::new(fs_err),
                )),
            );

            let err = head_blob_seam(&fake, &digest)
                .await
                .expect_err("task join failure must return error and suppress quarantine");

            match &err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(*kind, StorageErrorKind::Backend);
                    assert_eq!(message, &expected_msg);
                }
                other => panic!("expected StorageError::Internal(Backend), got: {other:?}"),
            }

            // Verify error does not become NotFound or PermissionDenied
            assert!(!matches!(err, StorageError::NotFound));
            assert_ne!(
                match &err {
                    StorageError::Internal { kind, .. } => *kind,
                    _ => StorageErrorKind::InternalInvariant,
                },
                StorageErrorKind::PermissionDenied
            );

            // Verify quarantine fallback is suppressed and fake records only primary lookup
            assert_eq!(fake.calls(), vec![primary_key]);
        });
    }

    #[tokio::test]
    async fn test_fake_quarantine_permission_denied_returns_without_further_lookup() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("99001122334455667788aabbccddeeff99001122334455667788aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/99/99001122334455667788aabbccddeeff99001122334455667788aabbccddeeff",
        )
        .unwrap();
        let quarantine_key = ObjectKey::parse("quarantine/blobs/sha256/99/99001122334455667788aabbccddeeff99001122334455667788aabbccddeeff").unwrap();

        let io_err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "quarantine permission denied",
        );
        let expected_msg = io_err.to_string();

        fake.script(
            primary_key.clone(),
            Err(ReadError::not_found(primary_key.clone())),
        );
        fake.script(
            quarantine_key.clone(),
            Err(ReadError::permission_denied_with_source(
                quarantine_key.clone(),
                Box::new(io_err),
            )),
        );

        let err = head_blob_seam(&fake, &digest)
            .await
            .expect_err("quarantine permission denied must return immediately");
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert_eq!(message, expected_msg);
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key, quarantine_key]);
    }

    #[tokio::test]
    async fn test_fake_quarantine_backend_error_returns_without_further_lookup() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/aa/aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        )
        .unwrap();
        let quarantine_key = ObjectKey::parse("quarantine/blobs/sha256/aa/aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899").unwrap();

        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "quarantine volume corrupted");
        let expected_msg = io_err.to_string();

        fake.script(
            primary_key.clone(),
            Err(ReadError::not_found(primary_key.clone())),
        );
        fake.script(
            quarantine_key.clone(),
            Err(ReadError::backend_with_source(
                "disk read fault",
                Box::new(io_err),
            )),
        );

        let err = head_blob_seam(&fake, &digest)
            .await
            .expect_err("quarantine backend error must return immediately");
        match err {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert_eq!(message, expected_msg);
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        assert_eq!(fake.calls(), vec![primary_key, quarantine_key]);
    }

    #[tokio::test]
    async fn test_fake_size_preservation_above_u32_max() {
        let fake = RecordingFakeReader::new();
        let digest =
            test_digest("bb223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");
        let primary_key = ObjectKey::parse(
            "blobs/sha256/bb/bb223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        )
        .unwrap();

        let large_size: u64 = (u32::MAX as u64) + 987_654_321;
        fake.script(primary_key.clone(), Ok(ObjectMetadata::new(large_size)));

        let meta = head_blob_seam(&fake, &digest)
            .await
            .expect("metadata query succeeds");
        assert_eq!(meta.size, large_size);
        assert_eq!(fake.calls(), vec![primary_key]);
    }

    #[tokio::test]
    async fn test_fake_source_free_and_misleading_diagnostics() {
        let fake = RecordingFakeReader::new();
        let digest1 =
            test_digest("ccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb");
        let primary_key1 = ObjectKey::parse(
            "blobs/sha256/cc/ccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb",
        )
        .unwrap();

        // 1. Source-free permission denied
        fake.script(
            primary_key1.clone(),
            Err(ReadError::permission_denied(primary_key1.clone())),
        );
        let err1 = head_blob_seam(&fake, &digest1)
            .await
            .expect_err("permission denied without source");
        match err1 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert_eq!(message, "permission denied");
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }

        // 2. Misleading string containing "object not found" inside Backend variant without source
        let digest2 =
            test_digest("ddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc");
        let primary_key2 = ObjectKey::parse(
            "blobs/sha256/dd/ddeeff00112233445566778899aabbccddeeff00112233445566778899aabbcc",
        )
        .unwrap();

        fake.script(
            primary_key2.clone(),
            Err(ReadError::backend(
                "object not found: misleading diagnostic text",
            )),
        );
        let err2 = head_blob_seam(&fake, &digest2)
            .await
            .expect_err("backend error with misleading string");
        // Must NOT match StorageError::NotFound!
        match err2 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert_eq!(message, "object not found: misleading diagnostic text");
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
        // Quarantine must never be called for Backend error
        assert_eq!(fake.calls(), vec![primary_key1, primary_key2]);

        // 3. Non-io source in Backend error
        #[derive(Debug, thiserror::Error)]
        #[error("custom non-io failure description")]
        struct CustomNonIoError;

        let digest3 =
            test_digest("eeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd");
        let primary_key3 = ObjectKey::parse(
            "blobs/sha256/ee/eeff00112233445566778899aabbccddeeff00112233445566778899aabbccdd",
        )
        .unwrap();

        fake.script(
            primary_key3.clone(),
            Err(ReadError::backend_with_source(
                "message",
                Box::new(CustomNonIoError),
            )),
        );
        let err3 = head_blob_seam(&fake, &digest3)
            .await
            .expect_err("non-io source translates safely");
        match err3 {
            StorageError::Internal { kind, message } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert_eq!(message, "custom non-io failure description");
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }
    }

    // ========================================================================
    // Category B: Real storage-fs Filesystem Tests (Linux-gated)
    // ========================================================================

    #[cfg(target_os = "linux")]
    mod linux_fs_tests {
        use super::*;
        use std::path::{Path, PathBuf};
        use std::sync::mpsc;
        use std::time::Duration;

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
        async fn test_real_fs_regular_file() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0101010101010101010101010101010101010101010101010101010101010101");
            let content = b"real regular file blob content";
            write_blob(
                &root,
                "blobs/sha256/01/0101010101010101010101010101010101010101010101010101010101010101",
                content,
            );

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let meta = head_blob_seam(&reader, &digest)
                .await
                .expect("head_blob_seam succeeds on real regular file");
            assert_eq!(meta.size, content.len() as u64);
        }

        #[tokio::test]
        async fn test_real_fs_both_locations_missing() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0202020202020202020202020202020202020202020202020202020202020202");

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = head_blob_seam(&reader, &digest)
                .await
                .expect_err("both missing must return NotFound");
            assert!(matches!(err, StorageError::NotFound));
        }

        #[tokio::test]
        async fn test_real_fs_missing_primary_valid_quarantine() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0303030303030303030303030303030303030303030303030303030303030303");
            let content = b"quarantined valid blob content";
            write_blob(
                &root,
                "quarantine/blobs/sha256/03/0303030303030303030303030303030303030303030303030303030303030303",
                content,
            );

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let meta = head_blob_seam(&reader, &digest)
                .await
                .expect("quarantine lookup succeeds when primary is missing");
            assert_eq!(meta.size, content.len() as u64);
        }

        #[tokio::test]
        async fn test_real_fs_final_symlink_inside_root() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0404040404040404040404040404040404040404040404040404040404040404");
            let target = write_blob(&root, "blobs/inside_target.bin", b"target payload");
            let blob_path = root.join(
                "blobs/sha256/04/0404040404040404040404040404040404040404040404040404040404040404",
            );
            std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&target, &blob_path).unwrap();

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = head_blob_seam(&reader, &digest)
                .await
                .expect_err("symlink inside root must be rejected");
            match err {
                StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_final_symlink_outside_root() {
            let (fixture, root) = create_test_root();
            let digest =
                test_digest("0505050505050505050505050505050505050505050505050505050505050505");
            let outside_target = fixture.path().join("outside.bin");
            std::fs::write(&outside_target, b"outside target payload").unwrap();

            let blob_path = root.join(
                "blobs/sha256/05/0505050505050505050505050505050505050505050505050505050505050505",
            );
            std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&outside_target, &blob_path).unwrap();

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = head_blob_seam(&reader, &digest)
                .await
                .expect_err("symlink outside root must be rejected");
            match err {
                StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_intermediate_symlink() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0606060606060606060606060606060606060606060606060606060606060606");
            let real_dir = root.join("blobs/real_prefix");
            std::fs::create_dir_all(&real_dir).unwrap();
            std::fs::write(
                real_dir.join("0606060606060606060606060606060606060606060606060606060606060606"),
                b"payload",
            )
            .unwrap();

            let prefix_parent = root.join("blobs/sha256");
            std::fs::create_dir_all(&prefix_parent).unwrap();
            std::os::unix::fs::symlink(&real_dir, prefix_parent.join("06")).unwrap();

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = head_blob_seam(&reader, &digest)
                .await
                .expect_err("intermediate symlink must be rejected");
            match err {
                StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_dangling_primary_symlink_with_valid_quarantine() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0707070707070707070707070707070707070707070707070707070707070707");

            // Dangling primary symlink
            let non_existent = root.join("blobs/nonexistent.bin");
            let blob_path = root.join(
                "blobs/sha256/07/0707070707070707070707070707070707070707070707070707070707070707",
            );
            std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&non_existent, &blob_path).unwrap();

            // Valid quarantine regular file
            write_blob(
                &root,
                "quarantine/blobs/sha256/07/0707070707070707070707070707070707070707070707070707070707070707",
                b"valid quarantine",
            );

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = head_blob_seam(&reader, &digest)
                .await
                .expect_err("dangling symlink on primary must NOT fall back to quarantine");
            match err {
                StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_directory_rejection() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0808080808080808080808080808080808080808080808080808080808080808");
            let dir_blob = root.join(
                "blobs/sha256/08/0808080808080808080808080808080808080808080808080808080808080808",
            );
            std::fs::create_dir_all(&dir_blob).unwrap();

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = head_blob_seam(&reader, &digest)
                .await
                .expect_err("directory object must be rejected");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, StorageErrorKind::Io);
                    assert!(message.contains("unsupported object type"));
                }
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[test]
        fn test_real_fs_fifo_rejection_bounded() {
            // Use an OS thread with bounded timeout channel to guarantee the test terminates
            // even if a blocking syscall were somehow triggered.
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current thread runtime");

                rt.block_on(async {
                    let (_fixture, root) = create_test_root();
                    let digest = test_digest("0909090909090909090909090909090909090909090909090909090909090909");
                    let fifo_path = root.join("blobs/sha256/09/0909090909090909090909090909090909090909090909090909090909090909");
                    std::fs::create_dir_all(fifo_path.parent().unwrap()).unwrap();

                    let c_path = std::ffi::CString::new(fifo_path.to_str().unwrap()).unwrap();
                    let res = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
                    assert_eq!(res, 0, "mkfifo must succeed");

                    let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
                    let res = head_blob_seam(&reader, &digest).await;
                    tx.send(res).unwrap();
                });
            });

            let res = rx
                .recv_timeout(Duration::from_secs(5))
                .expect("FIFO metadata check must complete without blocking");
            let err = res.expect_err("FIFO object must be rejected as unsupported");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, StorageErrorKind::Io);
                    assert!(message.contains("unsupported object type"));
                }
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_missing_primary_quarantine_symlink_rejection() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a");
            let target = write_blob(&root, "quarantine/target.bin", b"target");
            let qblob_path = root.join("quarantine/blobs/sha256/0a/0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a");
            std::fs::create_dir_all(qblob_path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&target, &qblob_path).unwrap();

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = head_blob_seam(&reader, &digest)
                .await
                .expect_err("quarantine symlink must be rejected");
            match err {
                StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_missing_primary_quarantine_directory_rejection() {
            let (_fixture, root) = create_test_root();
            let digest =
                test_digest("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            let qdir_path = root.join("quarantine/blobs/sha256/0b/0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            std::fs::create_dir_all(&qdir_path).unwrap();

            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");
            let err = head_blob_seam(&reader, &digest)
                .await
                .expect_err("quarantine directory must be rejected");
            match err {
                StorageError::Internal { kind, message } => {
                    assert_eq!(kind, StorageErrorKind::Io);
                    assert!(message.contains("unsupported object type"));
                }
                other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
            }
        }

        #[tokio::test]
        async fn test_real_fs_root_rename_replacement_retains_pinned_root() {
            let (fixture, root) = create_test_root();
            let digest =
                test_digest("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
            let content = b"pinned root inode blob content";
            write_blob(
                &root,
                "blobs/sha256/0c/0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                content,
            );

            // Open descriptor to initial storage root
            let reader = naust_storage_fs::FsMetadataReader::open(&root).expect("open root reader");

            // Rename existing storage root and create a brand-new directory at original path
            let old_root = fixture.path().join("storage_root_old");
            std::fs::rename(&root, &old_root).expect("rename storage root");
            std::fs::create_dir_all(&root).expect("recreate storage root");

            // Query via the reader: because it pinned the root descriptor at open time,
            // it queries the original inode and still locates the blob!
            let meta = head_blob_seam(&reader, &digest)
                .await
                .expect("query succeeds via pinned directory descriptor despite pathname rename");
            assert_eq!(meta.size, content.len() as u64);
        }
    }
}
