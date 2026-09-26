//! Contained filesystem quarantine and upload-inspection point reads for
//! `naust` (gap items R-13–R-15, partial).
//!
//! # Architecture and Scope
//!
//! Implements the three standalone inspection point reads behind
//! `FsStorage::quarantined_blob_version`, `FsStorage::read_quarantine_timestamp`,
//! and `FsStorage::get_finalized_receipt`, all over the shared pinned
//! [`storage_fs::FsMetadataReader`] via the existing
//! [`super::membership_read::MembershipReadOps`] seam (`open_payload`,
//! `inspect_file_metadata`; blocking work on the dependency's `spawn_blocking`
//! offload; no ambient fallback after a contained failure).
//!
//! # Deferred: the reaper's inspection reads (`reap_expired_sessions`)
//!
//! `reap_expired_sessions` INSPECTS session-meta and receipt records and then
//! ACTS on them (session lock, `recover_session`, `abort_session` meta/data
//! unlink, receipt `remove_file`). Its inspection reads are deliberately NOT
//! routed through this module: the reaper stays on its pre-batch, internally
//! coherent AMBIENT implementation in `fs.rs`, which reads and acts through one
//! and the same ambient pathnames.
//!
//! Routing only the inspection through the pinned reader while these mutations
//! resolve fresh ambient pathnames is an inspection-to-action mismatch: after a
//! root replacement the pinned descriptor keeps the ORIGINAL tree readable,
//! while the mutations resolve a REPLACEMENT tree at the same pathname, so a
//! detached tree's expiry could drive deletion of a same-UUID replacement
//! record in the current tree. Binding inspection to the mutations requires
//! write-side containment (O-04), out of this batch's scope. The rejected
//! promotion and this boundary are frozen by the regression
//! `tests::real_fs_tests::test_real_reaper_root_replacement_acts_only_on_current_tree`.
//!
//! The reaper's LOCKING and MUTATIONS and the GC quarantine/restore/
//! conditional-delete mutations remain in `fs.rs`, unchanged and ambient —
//! containing these point reads does not contain the reaper or GC lifecycle
//! (see the write-boundary audit in the implementation record).
//!
//! # Preserved Contracts
//!
//! - **Quarantine version token**: `fs:{len}:{mtime_nanos}:{sha256hex}` with
//!   byte-identical semantics to the ambient `compute_fs_blob_version` still
//!   used by `delete_blob_conditional`: length from the file metadata; mtime
//!   as whole nanoseconds since the Unix epoch with pre-epoch or unavailable
//!   timestamps mapping to `0` (legacy `unwrap_or_default`/`unwrap_or(0)`);
//!   streaming SHA-256 over the full content in 64 KiB chunks. The contained
//!   query and the unchanged ambient conditional-delete comparison agree for
//!   the same unchanged object (test-verified through a real conditional
//!   delete). Genuinely missing quarantined object -> `Ok(None)`.
//! - **Quarantine timestamp**: text file `quarantine/meta/<algo>/<p2>/<hex>.ts`
//!   holding whole seconds; surrounding whitespace trimmed; second precision;
//!   future timestamps are returned as stored (age policy is the caller's).
//!   Genuinely missing timestamp -> `Ok(None)`.
//! - **Finalized receipt**: `uploads/.finalized/<uuid>.json`; malformed JSON
//!   -> `CorruptData` (preserved); the repository/session identity check is
//!   preserved with its existing safe meaning — a receipt whose `repo`/`uuid`
//!   do not match the requested session is treated as `Ok(None)` ("no receipt
//!   for THIS session"), so a receipt is never accepted for another session
//!   and upload retry behavior is unchanged.
//!
//! # Intentional Containment and Failure-Handling Changes (test-frozen)
//!
//! - Pinned-root resolution for every point read; symlinked roots, ancestors,
//!   and leaves are rejected instead of silently followed; non-regular objects
//!   are rejected from contained type evidence (`fstat`) without following
//!   symlinks or opening potentially blocking special files.
//! - `quarantined_blob_version` no longer converts every initial metadata
//!   failure into `None` ("no quarantined object"): only genuine `NotFound`
//!   is absence; permission, wrong-type, containment, and I/O failures
//!   propagate. An object that vanishes between inspection and hashing is a
//!   read failure (legacy behavior), not absence.
//! - `read_quarantine_timestamp` no longer converts read or parse failures
//!   into `None`: non-UTF-8 content, unparseable text, and stored values that
//!   cannot be represented as a `SystemTime` (checked arithmetic replaces the
//!   previously unchecked `UNIX_EPOCH + Duration`) fail with a descriptive
//!   `CorruptData`; acquisition failures keep the `Io` taxonomy.
//!
//! # Resource Costs
//!
//! No numeric ceilings are introduced (no approved limit covers these reads;
//! ambient baselines were unbounded). Version hashing streams the quarantined
//! blob once in 64 KiB chunks (no whole-blob buffering); timestamp/receipt
//! reads buffer one small payload plus its parsed form. These are per-call
//! costs with no global memory or concurrency budget, and descriptor
//! containment provides no snapshot isolation: objects may change between
//! inspection and any later action.

use std::time::SystemTime;

use sha2::Digest as Sha2Digest;
use storage_core::{ObjectKey, ReadError};
use tokio::io::AsyncReadExt;

use super::membership_read::MembershipReadOps;
use crate::registry::digest::Digest;
#[cfg(test)]
use crate::storage::upload_session::{FinalizedReceipt, UploadSessionId};
use crate::storage::{BlobObjectVersion, StorageError};

fn parse_internal_key(key_str: &str) -> Result<ObjectKey, StorageError> {
    ObjectKey::parse(key_str).map_err(|e| {
        StorageError::internal_invariant(format!("invalid internal object key {key_str:?}: {e}"))
    })
}

fn quarantine_ts_key(digest: &Digest) -> String {
    format!(
        "quarantine/meta/{}/{}/{}.ts",
        digest.algorithm(),
        digest.prefix2(),
        digest.hex()
    )
}

/// True only for a confirmed non-regular object at the inspected leaf.
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

/// Contained quarantined-blob version query.
///
/// Token semantics are byte-identical to the ambient `compute_fs_blob_version`
/// consumed by the unchanged `delete_blob_conditional` comparison. Only a
/// genuinely missing quarantined object yields `Ok(None)`; every other
/// inspection failure propagates instead of presenting as absence.
pub(crate) async fn quarantined_blob_version_impl(
    ops: &(impl MembershipReadOps + ?Sized),
    digest: &Digest,
) -> Result<Option<BlobObjectVersion>, StorageError> {
    let key = super::read_adapter::blob_quarantine_key(digest)?;

    let meta = match ops.inspect_file_metadata(&key).await {
        Ok(m) => m,
        Err(ReadError::NotFound { .. }) => return Ok(None),
        Err(err) if inspection_confirms_non_regular(&err) => {
            // Legacy: metadata() succeeded on any object type and the
            // subsequent open failed (e.g. EISDIR) -> Io. Preserve the error
            // outcome with contained type evidence.
            return Err(super::read_adapter::translate_metadata_read_error(err));
        }
        Err(other) => return Err(super::read_adapter::translate_metadata_read_error(other)),
    };

    let len = meta.size();
    // Legacy mtime semantics: nanoseconds since the Unix epoch, with pre-epoch
    // or unavailable timestamps mapping to 0 (`unwrap_or_default`).
    let mtime: u128 = meta
        .modified()
        .map(|t| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        })
        .unwrap_or(0);

    let payload = match ops.open_payload(&key).await {
        Ok(p) => p,
        Err(ReadError::NotFound { .. }) => {
            // Vanished between inspection and hashing: a read failure (legacy
            // open-after-stat behavior), never absence.
            return Err(StorageError::io(format!(
                "quarantined blob {} disappeared before hashing",
                key.as_str()
            )));
        }
        Err(other) => return Err(super::read_adapter::translate_payload_read_error(other)),
    };

    let (_meta, mut stream) = payload.into_parts();
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = stream.read(&mut buf).await.map_err(|e| {
            StorageError::io(format!(
                "failed to read quarantined blob {}: {e}",
                key.as_str()
            ))
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hex::encode(hasher.finalize());
    Ok(Some(BlobObjectVersion(format!("fs:{len}:{mtime}:{hash}"))))
}

/// Contained quarantine timestamp read with checked representability.
pub(crate) async fn read_quarantine_timestamp_impl(
    ops: &(impl MembershipReadOps + ?Sized),
    digest: &Digest,
) -> Result<Option<SystemTime>, StorageError> {
    let key_str = quarantine_ts_key(digest);
    let key = parse_internal_key(&key_str)?;

    let payload = match ops.open_payload(&key).await {
        Ok(p) => p,
        Err(ReadError::NotFound { .. }) => return Ok(None),
        Err(other) => return Err(super::read_adapter::translate_payload_read_error(other)),
    };
    let (_meta, mut stream) = payload.into_parts();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.map_err(|e| {
        StorageError::io(format!(
            "failed to read quarantine timestamp {key_str}: {e}"
        ))
    })?;

    let content = std::str::from_utf8(&bytes).map_err(|e| {
        StorageError::corrupt_data(format!(
            "corrupt quarantine timestamp {key_str}: invalid UTF-8: {e}"
        ))
    })?;
    let secs: u64 = content.trim().parse().map_err(|e| {
        StorageError::corrupt_data(format!(
            "corrupt quarantine timestamp {key_str}: not a whole-second value: {e}"
        ))
    })?;
    let ts = SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(secs))
        .ok_or_else(|| {
            StorageError::corrupt_data(format!(
                "corrupt quarantine timestamp {key_str}: stored value {secs}s is not representable as a system time"
            ))
        })?;
    Ok(Some(ts))
}

/// Contained finalized-receipt read with the preserved identity check.
///
/// NOTE: This resolves `uploads/.finalized` from the pinned root via the reader on
/// every call and is therefore NOT used in production — `FsStorage::get_finalized_receipt`
/// routes through the cached finalized-directory authority so it agrees with the
/// writers after a `.finalized` / `uploads` replacement. It is retained only as a
/// test oracle characterizing the reader-path semantics the public method preserves.
#[cfg(test)]
pub(crate) async fn get_finalized_receipt_impl(
    ops: &(impl MembershipReadOps + ?Sized),
    session: &UploadSessionId,
) -> Result<Option<FinalizedReceipt>, StorageError> {
    crate::storage::tag_domain::validate_path_component(&session.uuid, "upload session id")?;
    let key_str = format!("uploads/.finalized/{}.json", session.uuid);
    let key = parse_internal_key(&key_str)?;

    let payload = match ops.open_payload(&key).await {
        Ok(p) => p,
        Err(ReadError::NotFound { .. }) => return Ok(None),
        Err(other) => return Err(super::read_adapter::translate_payload_read_error(other)),
    };
    let (_meta, mut stream) = payload.into_parts();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.map_err(|e| {
        StorageError::io(format!("failed to read finalized receipt {key_str}: {e}"))
    })?;

    let receipt: FinalizedReceipt =
        serde_json::from_slice(&bytes).map_err(|e| StorageError::corrupt_data(e.to_string()))?;
    // Preserved identity semantics: a receipt for another repository/session
    // is "no receipt for THIS session", never an accepted foreign receipt.
    if receipt.repo == session.repo && receipt.uuid == session.uuid {
        Ok(Some(receipt))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::canonical_name::CanonicalRepoName;
    use crate::storage::StorageErrorKind;
    use async_trait::async_trait;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use storage_core::{ObjectMetadata, ObjectPayload, ObjectStream};
    use storage_fs::{DirEntry, DirEnumerationLimits, FsDirError, FsFileMetadata};

    struct RecordingFakeOps {
        payload_calls: Arc<Mutex<Vec<ObjectKey>>>,
        payload_responses:
            Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<ObjectPayload, ReadError>>>>>,
        inspect_responses:
            Arc<Mutex<HashMap<ObjectKey, VecDeque<Result<FsFileMetadata, ReadError>>>>>,
    }

    impl RecordingFakeOps {
        fn new() -> Self {
            Self {
                payload_calls: Arc::new(Mutex::new(Vec::new())),
                payload_responses: Arc::new(Mutex::new(HashMap::new())),
                inspect_responses: Arc::new(Mutex::new(HashMap::new())),
            }
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
        fn payload_calls(&self) -> usize {
            self.payload_calls.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl MembershipReadOps for RecordingFakeOps {
        async fn enumerate_dir(
            &self,
            _target: Option<&ObjectKey>,
            _limits: DirEnumerationLimits,
        ) -> Result<Vec<DirEntry>, FsDirError> {
            // The kept point-read contracts never enumerate; the deferred
            // reaper is the only enumeration consumer and lives in `fs.rs`.
            unreachable!("enumerate_dir is not exercised by the point-read tests")
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
            let mut responses = self.inspect_responses.lock().unwrap();
            let queue = responses
                .get_mut(key)
                .unwrap_or_else(|| panic!("unexpected inspect call: {key}"));
            queue
                .pop_front()
                .unwrap_or_else(|| panic!("no more scripted inspect responses for: {key}"))
        }
    }

    fn key(s: &str) -> ObjectKey {
        ObjectKey::parse(s).unwrap()
    }
    fn payload_of(bytes: Vec<u8>) -> ObjectPayload {
        let meta = ObjectMetadata::new(bytes.len() as u64);
        let stream: ObjectStream = Box::pin(std::io::Cursor::new(bytes));
        ObjectPayload::new(meta, stream)
    }
    fn digest_n(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
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

    // ========================================================================
    // Quarantine version (fake-driven)
    // ========================================================================

    #[tokio::test]
    async fn test_fake_version_absence_vs_failure_and_vanish() {
        let d = digest_n(1);
        let k = super::super::read_adapter::blob_quarantine_key(&d).unwrap();

        // Genuine absence -> None.
        let fake = RecordingFakeOps::new();
        fake.script_inspect(k.clone(), Err(ReadError::not_found(k.clone())));
        assert!(
            quarantined_blob_version_impl(&fake, &d)
                .await
                .unwrap()
                .is_none()
        );

        // Permission / containment failures propagate, never None
        // (legacy converted every metadata failure into None).
        for err in [
            ReadError::permission_denied(k.clone()),
            rejection(libc::ELOOP),
            rejection(libc::EXDEV),
        ] {
            let fake = RecordingFakeOps::new();
            fake.script_inspect(k.clone(), Err(err));
            let e = quarantined_blob_version_impl(&fake, &d).await.unwrap_err();
            assert_eq!(e.internal_kind(), Some(StorageErrorKind::Io));
        }

        // Vanished between inspection and hashing: read failure, not absence.
        let fake = RecordingFakeOps::new();
        fake.script_inspect(k.clone(), Ok(FsFileMetadata::new(4, None)));
        fake.script_payload(k.clone(), Err(ReadError::not_found(k.clone())));
        let e = quarantined_blob_version_impl(&fake, &d).await.unwrap_err();
        assert_eq!(e.internal_kind(), Some(StorageErrorKind::Io));

        // Token assembly: unavailable mtime maps to 0 (legacy unwrap_or(0)).
        let fake = RecordingFakeOps::new();
        fake.script_inspect(k.clone(), Ok(FsFileMetadata::new(4, None)));
        fake.script_payload(k.clone(), Ok(payload_of(b"abcd".to_vec())));
        let v = quarantined_blob_version_impl(&fake, &d)
            .await
            .unwrap()
            .unwrap();
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"abcd");
        assert_eq!(v.0, format!("fs:4:0:{}", hex::encode(hasher.finalize())));

        // Pre-epoch mtime maps to 0 as well (legacy unwrap_or_default).
        let fake = RecordingFakeOps::new();
        let pre_epoch = SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(10);
        fake.script_inspect(k.clone(), Ok(FsFileMetadata::new(4, Some(pre_epoch))));
        fake.script_payload(k.clone(), Ok(payload_of(b"abcd".to_vec())));
        let v2 = quarantined_blob_version_impl(&fake, &d)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(v, v2);
    }

    // ========================================================================
    // Quarantine timestamp (fake-driven)
    // ========================================================================

    #[tokio::test]
    async fn test_fake_timestamp_contracts() {
        let d = digest_n(2);
        let k = key(&quarantine_ts_key(&d));

        // Valid with surrounding whitespace; future values returned as stored.
        for (body, secs) in [
            (b"  1700000000 \n".to_vec(), 1_700_000_000u64),
            (b"9999999999\n".to_vec(), 9_999_999_999u64),
        ] {
            let fake = RecordingFakeOps::new();
            fake.script_payload(k.clone(), Ok(payload_of(body)));
            let ts = read_quarantine_timestamp_impl(&fake, &d)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                ts,
                SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)
            );
        }

        // Genuine absence -> None.
        let fake = RecordingFakeOps::new();
        fake.script_payload(k.clone(), Err(ReadError::not_found(k.clone())));
        assert!(
            read_quarantine_timestamp_impl(&fake, &d)
                .await
                .unwrap()
                .is_none()
        );

        // Malformed / non-UTF-8 / unrepresentable -> CorruptData (was None).
        for body in [
            b"not-a-number\n".to_vec(),
            b"\xff\xfe".to_vec(),
            format!("{}\n", u64::MAX).into_bytes(),
            b"-5\n".to_vec(),
            b"".to_vec(),
        ] {
            let fake = RecordingFakeOps::new();
            fake.script_payload(k.clone(), Ok(payload_of(body.clone())));
            let e = read_quarantine_timestamp_impl(&fake, &d).await.unwrap_err();
            assert_eq!(
                e.internal_kind(),
                Some(StorageErrorKind::CorruptData),
                "for body {body:?}"
            );
        }

        // Acquisition failures propagate as Io, never None.
        for err in [
            ReadError::permission_denied(k.clone()),
            rejection(libc::ELOOP),
        ] {
            let fake = RecordingFakeOps::new();
            fake.script_payload(k.clone(), Err(err));
            let e = read_quarantine_timestamp_impl(&fake, &d).await.unwrap_err();
            assert_eq!(e.internal_kind(), Some(StorageErrorKind::Io));
        }
    }

    // ========================================================================
    // Finalized receipt (fake-driven)
    // ========================================================================

    fn receipt_for(repo: &str, uuid: &str) -> FinalizedReceipt {
        FinalizedReceipt {
            repo: CanonicalRepoName::parse(repo).unwrap(),
            uuid: uuid.to_string(),
            digest: digest_n(3).as_str(),
            size: 42,
            finalized_at_unix_secs: 1_700_000_000,
            format_version: 1,
        }
    }

    #[tokio::test]
    async fn test_fake_receipt_identity_and_failure_contracts() {
        let session = UploadSessionId::new(CanonicalRepoName::parse("myrepo").unwrap(), "sess-1");
        let k = key("uploads/.finalized/sess-1.json");

        // Valid receipt for this session.
        let fake = RecordingFakeOps::new();
        fake.script_payload(
            k.clone(),
            Ok(payload_of(
                serde_json::to_vec(&receipt_for("myrepo", "sess-1")).unwrap(),
            )),
        );
        let r = get_finalized_receipt_impl(&fake, &session)
            .await
            .unwrap()
            .expect("receipt present");
        assert_eq!(r.size, 42);

        // Preserved identity semantics: foreign repo or uuid -> None, never an
        // accepted foreign receipt.
        for foreign in [
            receipt_for("otherrepo", "sess-1"),
            receipt_for("myrepo", "sess-2"),
        ] {
            let fake = RecordingFakeOps::new();
            fake.script_payload(
                k.clone(),
                Ok(payload_of(serde_json::to_vec(&foreign).unwrap())),
            );
            assert!(
                get_finalized_receipt_impl(&fake, &session)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        // Missing -> None; corrupt -> CorruptData (preserved); acquisition
        // failures propagate.
        let fake = RecordingFakeOps::new();
        fake.script_payload(k.clone(), Err(ReadError::not_found(k.clone())));
        assert!(
            get_finalized_receipt_impl(&fake, &session)
                .await
                .unwrap()
                .is_none()
        );

        let fake = RecordingFakeOps::new();
        fake.script_payload(k.clone(), Ok(payload_of(b"{broken".to_vec())));
        let e = get_finalized_receipt_impl(&fake, &session)
            .await
            .unwrap_err();
        assert_eq!(e.internal_kind(), Some(StorageErrorKind::CorruptData));

        let fake = RecordingFakeOps::new();
        fake.script_payload(k.clone(), Err(rejection(libc::EXDEV)));
        let e = get_finalized_receipt_impl(&fake, &session)
            .await
            .unwrap_err();
        assert_eq!(e.internal_kind(), Some(StorageErrorKind::Io));

        // Structural session-id validation with zero reader calls.
        let fake = RecordingFakeOps::new();
        let bad = UploadSessionId::new(CanonicalRepoName::parse("myrepo").unwrap(), "../escape");
        let e = get_finalized_receipt_impl(&fake, &bad).await.unwrap_err();
        assert!(matches!(e, StorageError::InvalidRepoName(_)));
        assert_eq!(fake.payload_calls(), 0);
    }

    // ========================================================================
    // Linux-gated real filesystem and actual-caller tests
    // ========================================================================

    #[cfg(target_os = "linux")]
    mod real_fs_tests {
        use super::*;
        use crate::storage::fs::FsSessionMetaRecord;
        use crate::storage::fs::FsStorage;
        use crate::storage::{GcStorage, UploadSessionStorage};

        fn fixture_root() -> (tempfile::TempDir, std::path::PathBuf) {
            let fixture = tempfile::tempdir().expect("create tempdir");
            let root = fixture.path().join("storage_root");
            std::fs::create_dir_all(&root).expect("create storage root");
            (fixture, root)
        }

        fn quarantine_blob_path(root: &std::path::Path, d: &Digest) -> std::path::PathBuf {
            root.join("quarantine")
                .join("blobs")
                .join(d.algorithm())
                .join(d.prefix2())
                .join(d.hex())
        }

        #[tokio::test]
        async fn test_real_version_compat_with_ambient_conditional_delete_comparison() {
            let (_fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);
            let d = digest_n(1);
            let p = quarantine_blob_path(&root, &d);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"quarantined-bytes-for-version").unwrap();

            // Contained production query.
            let v = storage
                .quarantined_blob_version(&d)
                .await
                .unwrap()
                .expect("version present");

            // Byte-identical to the ambient computation still used by the
            // unchanged delete_blob_conditional comparison.
            let ambient = super::super::super::compute_fs_blob_version(&p)
                .await
                .unwrap();
            assert_eq!(
                v, ambient,
                "contained and ambient version tokens must agree"
            );

            // Genuine absence.
            assert!(
                storage
                    .quarantined_blob_version(&digest_n(9))
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        #[tokio::test]
        async fn test_real_version_and_timestamp_fail_closed_on_symlinks_and_pinned_root() {
            let (fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);
            let d = digest_n(1);

            // Symlinked quarantine root: version/timestamp error, never None
            // (legacy version reported None on ANY metadata failure).
            let outside = fixture.path().join("outside_quarantine");
            std::fs::create_dir_all(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("quarantine")).unwrap();
            let e = storage.quarantined_blob_version(&d).await.unwrap_err();
            assert_eq!(e.internal_kind(), Some(StorageErrorKind::Io));
            let e = storage.read_quarantine_timestamp(&d).await.unwrap_err();
            assert_eq!(e.internal_kind(), Some(StorageErrorKind::Io));

            // Pinned root: replacing the root pathname does not redirect reads.
            let (fixture2, root2) = fixture_root();
            let storage2 = FsStorage::new(root2.clone(), 1024 * 1024);
            let p = quarantine_blob_path(&root2, &d);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"original").unwrap();
            let v1 = storage2
                .quarantined_blob_version(&d)
                .await
                .unwrap()
                .unwrap();
            let renamed = fixture2.path().join("storage_root_old");
            std::fs::rename(&root2, &renamed).unwrap();
            let p_new = quarantine_blob_path(&root2, &d);
            std::fs::create_dir_all(p_new.parent().unwrap()).unwrap();
            std::fs::write(&p_new, b"replacement-different").unwrap();
            let v_pinned = storage2
                .quarantined_blob_version(&d)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                v_pinned.0.split(':').next_back(),
                v1.0.split(':').next_back(),
                "hash still comes from the pinned original tree"
            );
        }

        #[tokio::test]
        async fn test_real_timestamp_roundtrip_and_corruption() {
            let (_fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);
            let d = digest_n(2);

            // Production write -> contained read round-trip (second precision).
            let at = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_123);
            storage.write_quarantine_timestamp(&d, at).await.unwrap();
            assert_eq!(
                storage.read_quarantine_timestamp(&d).await.unwrap(),
                Some(at)
            );

            // Corrupt stored value -> CorruptData (was silently None).
            let ts_path = root
                .join("quarantine")
                .join("meta")
                .join(d.algorithm())
                .join(d.prefix2())
                .join(format!("{}.ts", d.hex()));
            std::fs::write(&ts_path, b"garbage").unwrap();
            let e = storage.read_quarantine_timestamp(&d).await.unwrap_err();
            assert_eq!(e.internal_kind(), Some(StorageErrorKind::CorruptData));
        }

        #[tokio::test]
        async fn test_real_receipt_production_roundtrip_and_symlink_rejection() {
            let (fixture, root) = fixture_root();
            let storage = FsStorage::new(root.clone(), 1024 * 1024);
            let session =
                UploadSessionId::new(CanonicalRepoName::parse("myrepo").unwrap(), "sess-xyz");

            // Absent -> None.
            assert!(
                storage
                    .get_finalized_receipt(&session)
                    .await
                    .unwrap()
                    .is_none()
            );

            // Present-and-matching -> Some; foreign session -> None (preserved).
            let finalized = root.join("uploads").join(".finalized");
            std::fs::create_dir_all(&finalized).unwrap();
            std::fs::write(
                finalized.join("sess-xyz.json"),
                serde_json::to_vec(&receipt_for("myrepo", "sess-xyz")).unwrap(),
            )
            .unwrap();
            assert!(
                storage
                    .get_finalized_receipt(&session)
                    .await
                    .unwrap()
                    .is_some()
            );
            let other =
                UploadSessionId::new(CanonicalRepoName::parse("otherrepo").unwrap(), "sess-xyz");
            assert!(
                storage
                    .get_finalized_receipt(&other)
                    .await
                    .unwrap()
                    .is_none()
            );

            // Symlinked receipt file -> Io, never None or a foreign receipt.
            let outside = fixture.path().join("outside_receipt.json");
            std::fs::write(
                &outside,
                serde_json::to_vec(&receipt_for("myrepo", "linked")).unwrap(),
            )
            .unwrap();
            std::os::unix::fs::symlink(&outside, finalized.join("linked.json")).unwrap();
            let linked =
                UploadSessionId::new(CanonicalRepoName::parse("myrepo").unwrap(), "linked");
            let e = storage.get_finalized_receipt(&linked).await.unwrap_err();
            assert_eq!(e.internal_kind(), Some(StorageErrorKind::Io));
        }

        /// Root-replacement regression: the reaper inspects AND mutates through
        /// one pinned authority, so it acts coherently on a single tree.
        ///
        /// Under the Option A contained lifecycle the reaper enumerates, locks,
        /// recovers, and aborts entirely through the process-lifetime pinned
        /// uploads/finalized authorities captured at construction. After the
        /// original storage root is renamed away, those authorities continue to
        /// resolve the ORIGINAL (now detached) inode — both for inspection and
        /// for the destructive actions it authorizes. A fresh replacement tree
        /// created at the same ambient pathname is therefore never touched: the
        /// reaper cannot abort/unlink a same-UUID replacement on the strength of
        /// the detached tree's expiry, because it never resolves the ambient
        /// pathname at all.
        ///
        /// Conversely, the detached tree's own expired records ARE reaped
        /// coherently through the pinned authority (the deliberate Option A
        /// tradeoff: a pinned ancestor follows its inode until restart).
        /// Assertions check the files themselves in BOTH trees, distinguishing
        /// an actual deletion from the returned confirmed-cleanup counter.
        #[tokio::test]
        async fn test_real_reaper_root_replacement_acts_only_on_current_tree() {
            let fixture = tempfile::tempdir().unwrap();
            let root = fixture.path().join("storage_root");
            std::fs::create_dir_all(&root).unwrap();
            // Pins the root descriptor to THIS inode.
            let storage = FsStorage::new(root.clone(), 1024 * 1024);

            let repo = CanonicalRepoName::parse("myrepo").unwrap();
            let uuid = "shared-uuid";

            // Original tree: an EXPIRED session record and an EXPIRED receipt.
            let uploads = root.join("uploads");
            let finalized = uploads.join(".finalized");
            std::fs::create_dir_all(&finalized).unwrap();
            let aged_meta = FsSessionMetaRecord {
                format_version: 1,
                repo: repo.clone(),
                uuid: uuid.to_string(),
                state: crate::storage::upload_session::UploadSessionState::Active,
                committed_offset: 0,
                hash_generation: 0,
                created_at_unix_secs: 1_000,
                last_active_at_unix_secs: 1_000,
                finalizing_info: None,
            };
            std::fs::write(
                uploads.join(format!("{uuid}.meta.json")),
                serde_json::to_vec(&aged_meta).unwrap(),
            )
            .unwrap();
            let aged_receipt = FinalizedReceipt {
                repo: repo.clone(),
                uuid: uuid.to_string(),
                digest: digest_n(4).as_str(),
                size: 1,
                finalized_at_unix_secs: 1_000,
                format_version: 1,
            };
            std::fs::write(
                finalized.join(format!("{uuid}.json")),
                serde_json::to_vec(&aged_receipt).unwrap(),
            )
            .unwrap();

            // Detach the original tree; the pinned descriptor follows this inode.
            let old_root = fixture.path().join("storage_root_old");
            std::fs::rename(&root, &old_root).unwrap();

            // Fresh replacement tree at the SAME ambient path: same UUID, NOT
            // expired.
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let new_uploads = root.join("uploads");
            let new_finalized = new_uploads.join(".finalized");
            std::fs::create_dir_all(&new_finalized).unwrap();
            let fresh_meta = FsSessionMetaRecord {
                last_active_at_unix_secs: now,
                ..aged_meta.clone()
            };
            std::fs::write(
                new_uploads.join(format!("{uuid}.meta.json")),
                serde_json::to_vec(&fresh_meta).unwrap(),
            )
            .unwrap();
            let fresh_receipt = FinalizedReceipt {
                finalized_at_unix_secs: now,
                ..aged_receipt.clone()
            };
            std::fs::write(
                new_finalized.join(format!("{uuid}.json")),
                serde_json::to_vec(&fresh_receipt).unwrap(),
            )
            .unwrap();

            let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();

            assert!(
                new_uploads.join(format!("{uuid}.meta.json")).exists(),
                "fresh replacement session meta must survive: the pinned authority \
                 never resolves the ambient replacement tree"
            );
            assert!(
                new_finalized.join(format!("{uuid}.json")).exists(),
                "fresh replacement receipt must survive: the pinned authority never \
                 resolves the ambient replacement tree"
            );
            assert!(
                !old_root
                    .join("uploads")
                    .join(format!("{uuid}.meta.json"))
                    .exists(),
                "detached-tree expired session meta is reaped coherently through the \
                 pinned authority"
            );
            assert!(
                !old_root
                    .join("uploads")
                    .join(".finalized")
                    .join(format!("{uuid}.json"))
                    .exists(),
                "detached-tree expired receipt is reaped coherently through the \
                 pinned authority"
            );
            assert_eq!(
                count, 2,
                "the pinned authority confirms exactly two cleanups on the detached \
                 tree: the expired session abort and the expired receipt unlink"
            );
        }
    }
}
