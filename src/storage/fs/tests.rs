use super::test_helpers::{
    detach_for_swap, make_test_stream, prepare_finalizable_session, tmp_fs_root, write_file,
};
use super::*;
use crate::storage::StorageErrorKind;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

async fn expect_open_blob_err(
    storage: &FsStorage,
    digest: &Digest,
    panic_msg: &str,
) -> StorageError {
    match storage.open_blob(digest).await {
        Ok(_) => panic!("{panic_msg}"),
        Err(err) => err,
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[tokio::test]
async fn referrers_add_list_remove_and_delete_manifest() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let subject =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let ref1 =
        Digest::parse("sha256:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();
    let ref2 =
        Digest::parse("sha256:3333333333333333333333333333333333333333333333333333333333333333")
            .unwrap();

    let desc1 = ReferrerDescriptor {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        digest: ref1.as_str().to_string(),
        size: 100,
        artifact_type: Some("application/vnd.example.sbom.v1".to_string()),
        annotations: None,
    };

    let desc2 = ReferrerDescriptor {
        media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
        digest: ref2.as_str().to_string(),
        size: 200,
        artifact_type: Some("application/vnd.example.sig.v1".to_string()),
        annotations: None,
    };

    // Add both referrers
    storage
        .add_referrer("testrepo", &subject, desc1)
        .await
        .expect("add ref1");
    storage
        .add_referrer("testrepo", &subject, desc2)
        .await
        .expect("add ref2");

    let list = storage
        .list_referrers("testrepo", &subject)
        .await
        .expect("list referrers");
    assert_eq!(list.len(), 2);

    // Remove ref1 directly
    storage
        .remove_referrer("testrepo", &subject, &ref1)
        .await
        .expect("remove ref1");
    let list = storage
        .list_referrers("testrepo", &subject)
        .await
        .expect("list referrers");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].digest, ref2.as_str());

    // Put a manifest for ref2 that declares subject
    let manifest_ref2 = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "subject": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": subject.as_str(),
            "size": 500
        }
    });
    let bytes = serde_json::to_vec(&manifest_ref2).unwrap();
    storage
        .put_manifest("testrepo", &ref2, bytes.into())
        .await
        .expect("put manifest");

    // Delete ref2 manifest -> should remove from referrers
    storage
        .delete_manifest("testrepo", &ref2)
        .await
        .expect("delete manifest");
    let list = storage
        .list_referrers("testrepo", &subject)
        .await
        .expect("list referrers");
    assert_eq!(list.len(), 0);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn head_and_open_blob_fall_back_to_quarantine() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("valid digest");

    let content = b"hello from quarantine";
    let qpath = storage.quarantine_blob_path(&digest);
    write_file(&qpath, content);

    let meta = storage.head_blob(&digest).await.expect("head_blob");
    assert_eq!(meta.size, content.len() as u64);

    let (meta, mut reader) = storage.open_blob(&digest).await.expect("open_blob");
    assert_eq!(meta.size, content.len() as u64);

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.expect("read blob");
    assert_eq!(buf, content);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn open_blob_prefers_live_over_quarantine() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .expect("valid digest");

    let live_content = b"live";
    let quarantine_content = b"quarantine";

    write_file(&storage.blob_path(&digest), live_content);
    write_file(&storage.quarantine_blob_path(&digest), quarantine_content);

    let (meta, mut reader) = storage.open_blob(&digest).await.expect("open_blob");
    assert_eq!(meta.size, live_content.len() as u64);

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.expect("read blob");
    assert_eq!(buf, live_content);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn delete_manifest_fails_safe_on_malformed_manifest() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "library/delete-malformed";
    let digest =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();

    // Write a malformed manifest on disk
    let malformed_manifest = serde_json::json!({
        "schemaVersion": 2,
        "subject": { "digest": "sha256:invalid-subject-hex" }
    });
    storage
        .put_manifest(
            repo,
            &digest,
            serde_json::to_vec(&malformed_manifest).unwrap().into(),
        )
        .await
        .unwrap();
    storage.set_tag(repo, "tag1", &digest).await.unwrap();

    // Attempt deletion
    let err = storage
        .delete_manifest(repo, &digest)
        .await
        .expect_err("should abort on malformed manifest");
    match err {
        StorageError::Internal { kind, message } => {
            assert_eq!(kind, crate::storage::StorageErrorKind::CorruptData);
            assert!(message.contains("malformed"));
        }
        other => panic!("expected StorageError::Internal, got {other:?}"),
    }

    // Verify manifest and tag are still present (not mutated)
    assert!(storage.get_manifest(repo, &digest).await.is_ok());
    assert_eq!(storage.resolve_tag(repo, "tag1").await.unwrap(), digest);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_fs_direct_concurrent_create_only() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(FsStorage::new(
        temp_dir.path().to_path_buf(),
        10 * 1024 * 1024,
    ));

    let d1 =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let d2 =
        Digest::parse("sha256:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();

    let s1 = storage.clone();
    let d1_clone = d1.clone();
    let h1 = tokio::spawn(async move {
        s1.mutate_tag(
            "repo",
            "tag",
            &d1_clone,
            crate::storage::TagMutationPolicy::CreateOnly,
        )
        .await
    });

    let s2 = storage.clone();
    let d2_clone = d2.clone();
    let h2 = tokio::spawn(async move {
        s2.mutate_tag(
            "repo",
            "tag",
            &d2_clone,
            crate::storage::TagMutationPolicy::CreateOnly,
        )
        .await
    });

    let (r1, r2) = tokio::join!(h1, h2);
    let res1 = r1.unwrap();
    let res2 = r2.unwrap();

    let success_count = (res1.is_ok() as usize) + (res2.is_ok() as usize);
    assert_eq!(success_count, 1, "Exactly one CreateOnly must succeed");

    let conflict_count = (matches!(res1, Err(StorageError::TagAlreadyExists)) as usize)
        + (matches!(res2, Err(StorageError::TagAlreadyExists)) as usize);
    assert_eq!(conflict_count, 1, "The loser must get TagAlreadyExists");

    // The winning tag on disk must match the winning mutation result
    let final_d = storage.resolve_tag("repo", "tag").await.unwrap();
    if let Ok(mut_res) = res1 {
        assert_eq!(final_d, d1);
        assert_eq!(mut_res, crate::storage::TagMutation::Created);
    } else {
        assert_eq!(final_d, d2);
        assert_eq!(res2.unwrap(), crate::storage::TagMutation::Created);
    }
}

#[tokio::test]
async fn test_fs_direct_concurrent_replacements_chain() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(FsStorage::new(
        temp_dir.path().to_path_buf(),
        10 * 1024 * 1024,
    ));

    let d1 =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let d2 =
        Digest::parse("sha256:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();

    let s1 = storage.clone();
    let d1_clone = d1.clone();
    let h1 = tokio::spawn(async move {
        s1.mutate_tag(
            "repo",
            "tag",
            &d1_clone,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
    });

    let s2 = storage.clone();
    let d2_clone = d2.clone();
    let h2 = tokio::spawn(async move {
        s2.mutate_tag(
            "repo",
            "tag",
            &d2_clone,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
    });

    let (r1, r2) = tokio::join!(h1, h2);
    let res1 = r1.unwrap().unwrap();
    let res2 = r2.unwrap().unwrap();

    // Phase 3 converged contract: each publication is atomic, the final
    // state is exactly ONE writer's canonical bytes, and any Replaced
    // outcome truthfully names the other writer's digest. Outcome
    // ATTRIBUTION under a race is best-effort (the retired advisory
    // .lock.<tag> serialization is gone; the only production caller
    // discards the outcome), so both writers may observe absence and report
    // Created.
    let final_d = storage.resolve_tag("repo", "tag").await.unwrap();
    assert!(
        final_d == d1 || final_d == d2,
        "final state is one writer's digest"
    );

    for (res, own, other) in [(&res1, &d1, &d2), (&res2, &d2, &d1)] {
        match res {
            crate::storage::TagMutation::Created => {}
            crate::storage::TagMutation::Unchanged => {
                panic!("distinct digests can never report Unchanged: {own}")
            }
            crate::storage::TagMutation::Replaced { previous } => {
                assert_eq!(
                    previous, other,
                    "a Replaced outcome names the competing writer's digest"
                );
            }
        }
    }
}

#[tokio::test]
async fn test_fs_direct_repeated_replacements() {
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(FsStorage::new(
        temp_dir.path().to_path_buf(),
        10 * 1024 * 1024,
    ));

    let d1 =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let d2 =
        Digest::parse("sha256:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();

    let m1 = storage
        .mutate_tag(
            "repo",
            "v1",
            &d1,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
        .unwrap();
    assert_eq!(m1, crate::storage::TagMutation::Created);

    // Same digest -> Unchanged
    let m1_same = storage
        .mutate_tag(
            "repo",
            "v1",
            &d1,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
        .unwrap();
    assert_eq!(m1_same, crate::storage::TagMutation::Unchanged);

    // Overwrite -> Replaced { previous: d1 }
    let m2 = storage
        .mutate_tag(
            "repo",
            "v1",
            &d2,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
        .unwrap();
    assert_eq!(m2, crate::storage::TagMutation::Replaced { previous: d1 });
}

fn make_failing_stream(first_chunk: Bytes, err: UploadStreamError) -> UploadByteStream {
    let items = vec![Ok(first_chunk), Err(err)];
    Box::pin(futures_util::stream::iter(items))
}

/// A stream that yields exactly one chunk and then pends forever. The supervised
/// worker writes the in-flight chunk to the data file, then blocks in
/// `blocking_recv` while still holding the session lock, giving a deterministic
/// in-flight boundary for cancellation tests.
fn make_paused_stream(first_chunk: Bytes) -> UploadByteStream {
    use futures_util::StreamExt as _;
    let head =
        futures_util::stream::once(async move { Ok::<Bytes, UploadStreamError>(first_chunk) });
    let tail = futures_util::stream::pending::<Result<Bytes, UploadStreamError>>();
    Box::pin(head.chain(tail))
}

fn on_disk_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[tokio::test]
async fn test_fs_session_same_offset_concurrent_append() {
    let root = tmp_fs_root();
    let s1 = Arc::new(FsStorage::new(root.clone(), 10 * 1024 * 1024));
    let s2 = Arc::new(FsStorage::new(root.clone(), 10 * 1024 * 1024));

    let session = s1.create_session("myrepo").await.unwrap();

    let s1_clone = s1.clone();
    let session1 = session.clone();
    let handle1 = tokio::spawn(async move {
        let stream = make_test_stream(vec![Bytes::from_static(b"CHUNK_AAAAA")]);
        s1_clone
            .append_if_offset(
                &session1,
                UploadOffsetPrecondition::Exact(0),
                stream,
                10 * 1024 * 1024,
            )
            .await
    });

    let s2_clone = s2.clone();
    let session2 = session.clone();
    let handle2 = tokio::spawn(async move {
        let stream = make_test_stream(vec![Bytes::from_static(b"CHUNK_BBBBB")]);
        s2_clone
            .append_if_offset(
                &session2,
                UploadOffsetPrecondition::Exact(0),
                stream,
                10 * 1024 * 1024,
            )
            .await
    });

    let res1 = handle1.await.unwrap().unwrap();
    let res2 = handle2.await.unwrap().unwrap();

    let mut committed_count = 0;
    let mut mismatch_or_conflict_count = 0;

    for r in [res1, res2] {
        match r {
            UploadAppendResult::Committed { new_offset } => {
                assert_eq!(new_offset, 11);
                committed_count += 1;
            }
            UploadAppendResult::OffsetMismatch { current_offset } => {
                assert_eq!(current_offset, 11);
                mismatch_or_conflict_count += 1;
            }
            UploadAppendResult::Conflict => {
                mismatch_or_conflict_count += 1;
            }
        }
    }

    assert_eq!(
        committed_count, 1,
        "Exactly one concurrent append from offset 0 must commit"
    );
    assert_eq!(
        mismatch_or_conflict_count, 1,
        "Loser must receive offset mismatch or conflict"
    );

    let status = s1.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 11);
}

/// Requirement #2 (append): a real append paused at a controlled in-flight boundary,
/// then cancelled, must keep its supervised owner in exclusive possession of the lock
/// until the in-flight write is rolled back to the committed offset. A competing append
/// is excluded until then, and afterwards observes only consistent, committed state.
#[tokio::test]
async fn test_fs_append_cancellation_excludes_competing_until_rolled_back() {
    let root = tmp_fs_root();
    let storage = Arc::new(FsStorage::new(root.clone(), 10 * 1024 * 1024));
    let session = storage.create_session("myrepo").await.unwrap();
    let uuid = session.uuid.clone();

    // Commit a base prefix so there is a committed offset to roll back to.
    let r = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"BASE_PREFIX_0123")]), // 16 bytes
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(r, UploadAppendResult::Committed { new_offset: 16 });

    let data_path = storage.session_data_path(&uuid);
    let meta_path = storage.session_meta_path(&uuid);

    // Start a paused append that writes an in-flight chunk, then blocks holding the lock.
    let s_a = storage.clone();
    let sess_a = session.clone();
    let paused = tokio::spawn(async move {
        let stream = make_paused_stream(Bytes::from_static(b"AAAA_INFLIGHT")); // 13 bytes
        s_a.append_if_offset(
            &sess_a,
            UploadOffsetPrecondition::Exact(16),
            stream,
            10 * 1024 * 1024,
        )
        .await
    });

    // Wait until the worker has written the in-flight chunk (data grows past committed).
    let mut waited = 0;
    while on_disk_len(&data_path) <= 16 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
        assert!(
            waited < 500,
            "paused append never reached in-flight boundary"
        );
    }
    assert_eq!(
        on_disk_len(&data_path),
        29,
        "in-flight chunk is on disk ahead of the committed offset"
    );
    // The in-flight write is NOT committed: metadata still records the base offset.
    let meta_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
    assert_eq!(meta_json["committed_offset"].as_u64(), Some(16));

    // A competing append must be excluded while the paused op holds the lock.
    let s_b = storage.clone();
    let sess_b = session.clone();
    let competing = tokio::spawn(async move {
        let stream = make_test_stream(vec![Bytes::from_static(b"BBBB")]);
        s_b.append_if_offset(
            &sess_b,
            UploadOffsetPrecondition::Exact(16),
            stream,
            10 * 1024 * 1024,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !competing.is_finished(),
        "competing append must be excluded while the paused op holds the lock"
    );

    // Cancel the request task. The supervised owner retains the lock, rolls the
    // in-flight write back to the committed offset, then releases.
    paused.abort();
    let _ = paused.await; // await termination of the request task

    // The competing append only proceeds once the supervised owner has released the
    // lock, and it observes only consistent, committed state (no stray in-flight bytes).
    let res = competing.await.unwrap().unwrap();
    assert_eq!(res, UploadAppendResult::Committed { new_offset: 20 });
    assert_eq!(
        on_disk_len(&data_path),
        20,
        "only base + competing bytes remain; no stray in-flight bytes survived"
    );

    // Metadata + retry consistency: finalize over base+competing succeeds, proving the
    // cancelled op left no residue in the committed prefix.
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"BASE_PREFIX_0123BBBB");
    let digest = Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize()))).unwrap();
    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(20),
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    assert_eq!(prepared.committed_offset, 20);
}

/// Requirement #2 (finalize): the trailing stream of a `begin_finalize` is a mutation
/// under the same supervised-owner guarantee. Paused mid-drain and cancelled, it must
/// roll the trailing write back and hold the lock until it does, excluding a competing
/// append until the session is once again coherent and Active.
#[tokio::test]
async fn test_fs_finalize_cancellation_excludes_competing_until_rolled_back() {
    let root = tmp_fs_root();
    let storage = Arc::new(FsStorage::new(root.clone(), 10 * 1024 * 1024));
    let session = storage.create_session("myrepo").await.unwrap();
    let uuid = session.uuid.clone();

    let r = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"BASE_PREFIX_0123")]), // 16 bytes
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(r, UploadAppendResult::Committed { new_offset: 16 });

    let data_path = storage.session_data_path(&uuid);

    // Paused finalize: the trailing stream writes an in-flight chunk, then blocks. The
    // digest and expected offset are never reached because the op is cancelled mid-drain.
    let s_a = storage.clone();
    let sess_a = session.clone();
    let dummy =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let paused = tokio::spawn(async move {
        let stream = make_paused_stream(Bytes::from_static(b"TRAIL_INFLIGHT")); // 14 bytes
        s_a.begin_finalize(
            &sess_a,
            UploadOffsetPrecondition::Exact(30),
            Some(stream),
            &dummy,
            10 * 1024 * 1024,
            false,
        )
        .await
    });

    let mut waited = 0;
    while on_disk_len(&data_path) <= 16 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
        assert!(
            waited < 500,
            "paused finalize never reached in-flight boundary"
        );
    }
    assert_eq!(
        on_disk_len(&data_path),
        30,
        "trailing in-flight chunk on disk"
    );

    // Competing append excluded while the paused finalize holds the lock.
    let s_b = storage.clone();
    let sess_b = session.clone();
    let competing = tokio::spawn(async move {
        let stream = make_test_stream(vec![Bytes::from_static(b"BBBB")]);
        s_b.append_if_offset(
            &sess_b,
            UploadOffsetPrecondition::Exact(16),
            stream,
            10 * 1024 * 1024,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !competing.is_finished(),
        "competing append must be excluded while the paused finalize holds the lock"
    );

    paused.abort();
    let _ = paused.await;

    // The competing append proceeds only after the supervised owner releases the lock;
    // the session was never advanced to Finalizing and its data stays consistent.
    let res = competing.await.unwrap().unwrap();
    assert_eq!(res, UploadAppendResult::Committed { new_offset: 20 });

    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 20);

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"BASE_PREFIX_0123BBBB");
    let digest = Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize()))).unwrap();
    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(20),
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    assert_eq!(prepared.committed_offset, 20);
}

/// Requirement #2 (direct rollback observation): with no competing consumer touching
/// the data file, a cancelled in-flight append is deterministically rolled back to the
/// committed offset by its supervised owner before the lock is released. Afterwards the
/// session is Active at the committed offset and accepts a fresh append.
#[tokio::test]
async fn test_fs_append_cancellation_rolls_back_under_lock() {
    let root = tmp_fs_root();
    let storage = Arc::new(FsStorage::new(root.clone(), 10 * 1024 * 1024));
    let session = storage.create_session("myrepo").await.unwrap();
    let uuid = session.uuid.clone();

    let r = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"BASE_PREFIX_0123")]), // 16 bytes
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(r, UploadAppendResult::Committed { new_offset: 16 });

    let data_path = storage.session_data_path(&uuid);

    let s_a = storage.clone();
    let sess_a = session.clone();
    let paused = tokio::spawn(async move {
        let stream = make_paused_stream(Bytes::from_static(b"AAAA_INFLIGHT")); // 13 bytes
        s_a.append_if_offset(
            &sess_a,
            UploadOffsetPrecondition::Exact(16),
            stream,
            10 * 1024 * 1024,
        )
        .await
    });

    // Reach the in-flight boundary (data ahead of the committed offset).
    let mut waited = 0;
    while on_disk_len(&data_path) <= 16 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
        assert!(
            waited < 500,
            "paused append never reached in-flight boundary"
        );
    }
    assert_eq!(on_disk_len(&data_path), 29);

    paused.abort();
    let _ = paused.await;

    // No other operation touches the file, so the rollback to the committed offset is
    // deterministically observable.
    let mut waited = 0;
    while on_disk_len(&data_path) != 16 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
        assert!(
            waited < 500,
            "supervised owner never rolled the in-flight write back to the committed offset"
        );
    }

    // The session is intact: Active at the committed offset, and a fresh append works.
    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 16);
    assert_eq!(status.state, UploadSessionState::Active);

    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(16),
            make_test_stream(vec![Bytes::from_static(b"CCCC")]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(res, UploadAppendResult::Committed { new_offset: 20 });
    assert_eq!(on_disk_len(&data_path), 20);
}

// ---------------------------------------------------------------------------
// Requirement #1: shared, stable lifecycle subtree authority.
//
// These tests exercise the contract that each lifecycle subtree is pinned once
// (lazily) and shared thereafter, so that once an operation resolves a subtree
// every later access, lock, read, write, recovery, and commit flows through the
// same pinned inode — a later rename/replacement of the subtree *pathname* on
// disk cannot redirect any in-progress or subsequent operation. Root replacement
// is covered by the existing regression
// `test_real_reaper_root_replacement_acts_only_on_current_tree`.
// ---------------------------------------------------------------------------

/// Category: a later lifecycle call retains a compatible (identical) pinned
/// authority; the subtree is shared, not re-derived, across separate calls, and
/// distinct subtrees are distinct authorities.
#[tokio::test]
async fn test_fs_authority_shared_across_separate_lifecycle_calls() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Resolving the uploads authority initializes the shared cell.
    let id1 = storage
        .upload_authorities
        .uploads()
        .await
        .unwrap()
        .authority_id();

    // A real lifecycle call, then a fresh resolution: same pinned authority.
    let _session = storage.create_session("myrepo").await.unwrap();
    let id2 = storage
        .upload_authorities
        .uploads()
        .await
        .unwrap()
        .authority_id();
    assert_eq!(
        id1, id2,
        "uploads authority must be shared, not re-derived, across separate calls"
    );

    // The `.finalized` authority is likewise stable, and distinct from uploads.
    let f1 = storage
        .upload_authorities
        .finalized()
        .await
        .unwrap()
        .authority_id();
    let f2 = storage
        .upload_authorities
        .finalized()
        .await
        .unwrap()
        .authority_id();
    assert_eq!(f1, f2, "finalized authority must be shared across calls");
    assert_ne!(
        id1, f1,
        "uploads and finalized must be distinct pinned authorities"
    );
}

/// Category: concurrent lazy initialization cannot install competing authorities;
/// every racing caller observes exactly one shared authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_fs_authority_concurrent_lazy_init_single_authority() {
    let root = tmp_fs_root();
    let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));

    let mut handles = Vec::new();
    for _ in 0..32 {
        let s = storage.clone();
        handles.push(tokio::spawn(async move {
            s.upload_authorities.uploads().await.unwrap().authority_id()
        }));
    }
    let mut ids = Vec::new();
    for h in handles {
        ids.push(h.await.unwrap());
    }
    let first = ids[0];
    assert!(
        ids.iter().all(|&i| i == first),
        "concurrent lazy init must yield exactly one shared authority; got {ids:?}"
    );
}

/// Category: uploads-subtree replacement beneath an unchanged root. After the
/// uploads authority is pinned, replacing the `uploads` directory on disk with a
/// fresh inode must not redirect subsequent operations.
#[tokio::test]
async fn test_fs_authority_uploads_replacement_beneath_unchanged_root() {
    use std::os::unix::fs::MetadataExt as _;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 10 * 1024 * 1024);
    let session = storage.create_session("myrepo").await.unwrap();
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"HELLO")]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let uploads_dir = storage.uploads_dir();
    let old_ino = std::fs::metadata(&uploads_dir).unwrap().ino();

    // Replace the uploads subtree beneath the unchanged root with a fresh inode.
    let detached = root.join("uploads.detached");
    std::fs::rename(&uploads_dir, &detached).unwrap();
    std::fs::create_dir(&uploads_dir).unwrap();
    let new_ino = std::fs::metadata(&uploads_dir).unwrap().ino();
    assert_ne!(old_ino, new_ino, "replacement must be a fresh inode");

    // The next append flows through the pinned authority (the detached inode where
    // the session actually lives), not the ambient replacement.
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(5),
            make_test_stream(vec![Bytes::from_static(b"WORLD")]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(res, UploadAppendResult::Committed { new_offset: 10 });

    // The fresh ambient uploads dir is untouched; committed data lives in the pin.
    assert!(
        std::fs::read_dir(&uploads_dir).unwrap().next().is_none(),
        "operation must not touch the ambient replacement subtree"
    );
    let data_in_pin = detached.join(format!("{}.data", session.uuid));
    assert_eq!(std::fs::metadata(&data_in_pin).unwrap().len(), 10);
}

/// Category: `.finalized`-subtree replacement beneath an unchanged root. After the
/// receipt authority is pinned by a finalize, replacing `uploads/.finalized` must
/// not hide the receipt from a later idempotent replay.
#[tokio::test]
async fn test_fs_authority_finalized_replacement_beneath_unchanged_root() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Fully finalize a session: writes a receipt and pins the `.finalized` authority.
    let data = b"FINALIZED_PAYLOAD";
    let (session, prepared, digest) = prepare_finalizable_session(&storage, "myrepo", data).await;
    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: data.len() as u64
        })
    );

    let finalized_dir = storage.finalized_dir();
    let receipt = storage.finalized_receipt_path(&session.uuid);
    assert!(receipt.exists(), "receipt written before replacement");

    // Replace the `.finalized` subtree with a fresh, empty inode.
    let detached = storage.uploads_dir().join(".finalized.detached");
    std::fs::rename(&finalized_dir, &detached).unwrap();
    std::fs::create_dir(&finalized_dir).unwrap();
    assert!(
        std::fs::read_dir(&finalized_dir).unwrap().next().is_none(),
        "ambient replacement is empty"
    );

    // An idempotent replay (meta is gone after commit) consults the receipt through
    // the pinned authority (detached inode), not the empty ambient replacement.
    let replay = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .expect("replay must find the receipt through the pinned .finalized authority");
    assert_eq!(replay.size, data.len() as u64);
}

/// Category: subtree replacement interposed *between* lock acquisition and the
/// later mutation. A test-controlled stream keeps an append in-flight (lock held)
/// while the `uploads` pathname is replaced; the commit must still land on the
/// pinned inode.
#[tokio::test]
async fn test_fs_authority_uploads_replacement_between_lock_and_mutation() {
    use std::os::unix::fs::MetadataExt as _;

    let root = tmp_fs_root();
    let storage = Arc::new(FsStorage::new(root.clone(), 10 * 1024 * 1024));
    let session = storage.create_session("myrepo").await.unwrap();

    let uploads_dir = storage.uploads_dir();
    let data_path = storage.session_data_path(&session.uuid);

    // A test-controlled stream lets us interpose a replacement after the lock is
    // held and the first bytes are already written.
    let (feed_tx, feed_rx) = tokio::sync::mpsc::channel::<Result<Bytes, UploadStreamError>>(4);
    let stream: UploadByteStream = Box::pin(tokio_stream::wrappers::ReceiverStream::new(feed_rx));
    let s = storage.clone();
    let sess = session.clone();
    let handle = tokio::spawn(async move {
        s.append_if_offset(
            &sess,
            UploadOffsetPrecondition::Exact(0),
            stream,
            10 * 1024 * 1024,
        )
        .await
    });

    // First chunk in-flight: the worker holds the lock on the pinned authority.
    feed_tx
        .send(Ok(Bytes::from_static(b"HELLO")))
        .await
        .unwrap();
    let mut waited = 0;
    while on_disk_len(&data_path) < 5 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
        assert!(waited < 500, "first chunk never landed in-flight");
    }

    // Replace the uploads subtree while the lock is held and the write is mid-flight.
    let old_ino = std::fs::metadata(&uploads_dir).unwrap().ino();
    let detached = root.join("uploads.detached");
    std::fs::rename(&uploads_dir, &detached).unwrap();
    std::fs::create_dir(&uploads_dir).unwrap();
    assert_ne!(
        old_ino,
        std::fs::metadata(&uploads_dir).unwrap().ino(),
        "replacement is a fresh inode"
    );

    // Complete the stream; the commit must land on the pinned (detached) inode.
    feed_tx
        .send(Ok(Bytes::from_static(b"WORLD")))
        .await
        .unwrap();
    drop(feed_tx);
    let res = handle.await.unwrap().unwrap();
    assert_eq!(res, UploadAppendResult::Committed { new_offset: 10 });

    // The ambient replacement stays empty; committed data + metadata live in the pin.
    assert!(
        std::fs::read_dir(&uploads_dir).unwrap().next().is_none(),
        "mid-flight replacement must not capture the mutation"
    );
    let data_in_pin = detached.join(format!("{}.data", session.uuid));
    assert_eq!(std::fs::metadata(&data_in_pin).unwrap().len(), 10);
    let meta_in_pin = detached.join(format!("{}.meta.json", session.uuid));
    let meta_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&meta_in_pin).unwrap()).unwrap();
    assert_eq!(meta_json["committed_offset"].as_u64(), Some(10));
}

#[tokio::test]
async fn test_fs_session_stream_failure_rollback() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 10 * 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();

    // 1. Successful initial append
    let stream = make_test_stream(vec![Bytes::from_static(b"INITIAL_BYTES_100_")]);
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(res, UploadAppendResult::Committed { new_offset: 18 });

    // 2. Failing append mid-chunk
    let failing_stream = make_failing_stream(
        Bytes::from_static(b"PARTIAL_FAIL_CHUNK"),
        UploadStreamError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "client disconnected",
        )),
    );
    let err = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(18),
            failing_stream,
            10 * 1024 * 1024,
        )
        .await
        .unwrap_err();

    assert!(matches!(err, UploadTransitionError::Stream(_)));

    // 3. Verify physical file is truncated back to exact committed offset 18
    let data_path = storage.session_data_path(&session.uuid);
    let file_meta = tokio::fs::metadata(&data_path).await.unwrap();
    assert_eq!(file_meta.len(), 18);

    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 18);
}

#[tokio::test]
async fn test_fs_session_size_overflow_rollback() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 500);

    let session = storage.create_session("myrepo").await.unwrap();

    // 1. Append 400 bytes -> Ok
    let chunk1 = vec![b'A'; 400];
    let stream1 = make_test_stream(vec![Bytes::from(chunk1)]);
    let res1 = storage
        .append_if_offset(&session, UploadOffsetPrecondition::Exact(0), stream1, 500)
        .await
        .unwrap();
    assert_eq!(res1, UploadAppendResult::Committed { new_offset: 400 });

    // 2. Append 200 bytes -> exceeds limit 500
    let chunk2 = vec![b'B'; 200];
    let stream2 = make_test_stream(vec![Bytes::from(chunk2)]);
    let err = storage
        .append_if_offset(&session, UploadOffsetPrecondition::Exact(400), stream2, 500)
        .await
        .unwrap_err();

    assert!(matches!(err, UploadTransitionError::TooLarge));

    // 3. Staging file is truncated back to 400
    let data_path = storage.session_data_path(&session.uuid);
    assert_eq!(tokio::fs::metadata(&data_path).await.unwrap().len(), 400);

    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 400);
}

#[tokio::test]
async fn test_fs_session_crash_recovery_extra_staging_bytes() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();

    let stream = make_test_stream(vec![Bytes::from_static(b"COMMITTED_DATA_300")]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    // Simulate crash: simulate orphan uncommitted bytes written to .data
    let data_path = storage.session_data_path(&session.uuid);
    let mut f = tokio::fs::OpenOptions::new()
        .append(true)
        .open(&data_path)
        .await
        .unwrap();
    f.write_all(b"UNCOMMITTED_CRASH_BYTES").await.unwrap();
    f.sync_all().await.unwrap();
    drop(f);

    assert_eq!(
        tokio::fs::metadata(&data_path).await.unwrap().len(),
        18 + 23
    );

    // Next operation recovers physical file to 18
    let stream2 = make_test_stream(vec![Bytes::from_static(b"_NEXT_CHUNK")]);
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(18),
            stream2,
            1024 * 1024,
        )
        .await
        .unwrap();

    assert_eq!(
        res,
        UploadAppendResult::Committed {
            new_offset: 18 + 11
        }
    );
    let content = tokio::fs::read(&data_path).await.unwrap();
    assert_eq!(content, b"COMMITTED_DATA_300_NEXT_CHUNK");
}

#[tokio::test]
async fn test_fs_session_crash_orphan_hash_generation() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let stream = make_test_stream(vec![Bytes::from_static(b"HELLO_GEN_0")]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    // Create orphan hash gen 2 file on disk
    let orphan_hash = storage.session_hash_path(&session.uuid, 2);
    tokio::fs::write(&orphan_hash, b"CORRUPTED_ORPHAN")
        .await
        .unwrap();

    // Next append moves from gen 1 to gen 2 atomically overwriting orphan
    let stream2 = make_test_stream(vec![Bytes::from_static(b"_WORLD")]);
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(11),
            stream2,
            1024 * 1024,
        )
        .await
        .unwrap();

    assert_eq!(res, UploadAppendResult::Committed { new_offset: 17 });
}

#[tokio::test]
async fn test_fs_session_missing_referenced_hash_generation() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let stream = make_test_stream(vec![Bytes::from_static(b"HELLO_WORLD_TEST")]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    // Delete gen 1 hash file
    let hash_gen_1 = storage.session_hash_path(&session.uuid, 1);
    tokio::fs::remove_file(&hash_gen_1).await.unwrap();

    // Next append automatically recomputes hash from .data and commits gen 2
    let stream2 = make_test_stream(vec![Bytes::from_static(b"_AGAIN")]);
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(16),
            stream2,
            1024 * 1024,
        )
        .await
        .unwrap();

    assert_eq!(res, UploadAppendResult::Committed { new_offset: 22 });
}

#[tokio::test]
async fn test_fs_session_patch_finalize_race() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let data = b"BLOB_CONTENT_FOR_FINALIZATION";
    let stream = make_test_stream(vec![Bytes::from_static(data)]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let digest_hex = hex::encode(hasher.finalize());
    let digest = Digest::parse(&format!("sha256:{digest_hex}")).unwrap();

    // Begin finalize transitions to Finalizing
    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap();

    // Concurrent append is rejected with Conflict
    let stream2 = make_test_stream(vec![Bytes::from_static(b"LATE_CHUNK")]);
    let append_res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            stream2,
            1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(append_res, UploadAppendResult::Conflict);

    // Commit finalize succeeds
    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: data.len() as u64
        })
    );
}

#[tokio::test]
async fn test_fs_session_abort_append_race() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    storage.abort_session(&session).await.unwrap();

    let stream = make_test_stream(vec![Bytes::from_static(b"LATE_CHUNK")]);
    let err = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, UploadTransitionError::NotFound));
}

#[tokio::test]
async fn test_fs_session_two_begin_finalize_attempts() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let data = b"LAYER_BYTES";
    let stream = make_test_stream(vec![Bytes::from_static(data)]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let digest_hex = hex::encode(hasher.finalize());
    let digest = Digest::parse(&format!("sha256:{digest_hex}")).unwrap();

    let p1 = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap();

    let p2_err = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap_err();

    assert!(matches!(p2_err, UploadTransitionError::Conflict));

    let outcome = storage.commit_finalize(&p1).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: data.len() as u64
        })
    );
}

#[tokio::test]
async fn test_fs_session_duplicate_commit_finalize() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let data = b"BLOB_FOR_DUPLICATE_COMMIT";
    let stream = make_test_stream(vec![Bytes::from_static(data)]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let digest_hex = hex::encode(hasher.finalize());
    let digest = Digest::parse(&format!("sha256:{digest_hex}")).unwrap();

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap();

    let outcome1 = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome1,
        FinalizeOutcome::Published(BlobMeta {
            size: data.len() as u64
        })
    );

    let outcome2 = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome2,
        FinalizeOutcome::AlreadyFinalized(BlobMeta {
            size: data.len() as u64
        })
    );
}

#[tokio::test]
async fn test_fs_session_lost_response_receipt_lookup() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let data = b"RECEIPT_LOOKUP_DATA";
    let stream = make_test_stream(vec![Bytes::from_static(data)]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let digest_hex = hex::encode(hasher.finalize());
    let digest = Digest::parse(&format!("sha256:{digest_hex}")).unwrap();

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap();

    storage.commit_finalize(&prepared).await.unwrap();

    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.repo.as_str(), "myrepo");
    assert_eq!(receipt.uuid, session.uuid);
    assert_eq!(receipt.digest, digest.as_str());
    assert_eq!(receipt.size, data.len() as u64);
}

#[tokio::test]
async fn test_fs_session_reaper_skips_locked() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let lock_path = storage.session_lock_path(&session.uuid);
    let _active_lock = acquire_fs_session_lock(lock_path).await.unwrap();

    // Reaper with 0 max_age attempts to reap, but skips locked session
    let reaped = storage.reap_expired_sessions(0, 0).await.unwrap();
    assert_eq!(reaped, 0, "Reaper must skip active locked session");

    drop(_active_lock);

    // Once unlocked, reaper reaps expired session
    let reaped2 = storage.reap_expired_sessions(0, 0).await.unwrap();
    assert_eq!(reaped2, 1, "Reaper must reap unlocked expired session");
}

#[tokio::test]
async fn test_fs_session_reaper_recovers_expired_finalizing() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let data = b"EXP_FIN_RECOVER_DATA";
    let stream = make_test_stream(vec![Bytes::from_static(data)]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let digest_hex = hex::encode(hasher.finalize());
    let digest = Digest::parse(&format!("sha256:{digest_hex}")).unwrap();

    let _prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap();

    // Simulate crash after blob publication: move blob to destination manually
    let dest_dir = root
        .join("blobs")
        .join(digest.algorithm())
        .join(digest.prefix2());
    ensure_dir(&dest_dir).unwrap();
    let dest_path = dest_dir.join(digest.hex());
    tokio::fs::write(&dest_path, data).await.unwrap();

    // Reaper runs recovery with max_age = 0 and receipt_ttl = 600
    let _ = storage.reap_expired_sessions(0, 600).await.unwrap();

    // Receipt should now be created
    let receipt = storage.get_finalized_receipt(&session).await.unwrap();
    assert!(receipt.is_some());
}

// ---------------------------------------------------------------------------
// Requirement #3: reaper / publication fault-injection matrix.
//
// These drive the real production entry points against post-crash on-disk
// states (the honest, deterministic form of fault injection available without a
// syscall-level fault FS): CAS present/absent/mismatch, membership-before-
// receipt crash + retry, receipt loss + retry, existing-receipt/missing-
// membership, recover roll-forward, abort interruption + retry, and exact
// reaper success/skip counting. Pure syscall-failure injection into the atomic
// write helper (ENOSPC/EIO on the temp write, EXDEV rename, cleanup-unlink
// failure) is not deterministically inducible from a unit test and is recorded
// as a scoped gap in the evidence notes.
// ---------------------------------------------------------------------------

/// The ambient CAS path of a published blob: `blobs/{algo}/{prefix2}/{hex}`.
fn cas_blob_path(root: &Path, digest: &Digest) -> PathBuf {
    root.join("blobs")
        .join(digest.algorithm())
        .join(digest.prefix2())
        .join(digest.hex())
}

/// Rewrite a single top-level numeric field of a JSON record on disk (used to
/// backdate `last_active_at_unix_secs` / `finalized_at_unix_secs` so the reaper
/// treats a record as expired without waiting real time).
fn backdate_json_u64_field(path: &Path, field: &str, value: u64) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    v[field] = serde_json::json!(value);
    std::fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
}

/// Exact success/skip counting: the reaper tallies only CONFIRMED cleanups
/// (aborted expired sessions + unlinked past-TTL receipts), skipping fresh
/// sessions, live-locked sessions, and fresh receipts.
#[tokio::test]
async fn test_fs_reaper_counts_only_confirmed_cleanups() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let now = now_unix_secs();
    let stale = now.saturating_sub(100_000);

    // Two expired sessions -> aborted -> counted.
    let s1 = storage.create_session("repo").await.unwrap();
    let s2 = storage.create_session("repo").await.unwrap();
    backdate_json_u64_field(
        &storage.session_meta_path(&s1.uuid),
        "last_active_at_unix_secs",
        stale,
    );
    backdate_json_u64_field(
        &storage.session_meta_path(&s2.uuid),
        "last_active_at_unix_secs",
        stale,
    );

    // One fresh session -> skipped (not expired).
    let s_fresh = storage.create_session("repo").await.unwrap();

    // One expired but live-locked session -> skipped.
    let s_locked = storage.create_session("repo").await.unwrap();
    backdate_json_u64_field(
        &storage.session_meta_path(&s_locked.uuid),
        "last_active_at_unix_secs",
        stale,
    );
    let _held = acquire_fs_session_lock(storage.session_lock_path(&s_locked.uuid))
        .await
        .unwrap();

    // Two past-TTL receipts -> unlinked -> counted; one fresh receipt -> skipped.
    let (r1, p1, _) = prepare_finalizable_session(&storage, "repo", b"RECEIPT_ONE_DATA").await;
    storage.commit_finalize(&p1).await.unwrap();
    let (r2, p2, _) = prepare_finalizable_session(&storage, "repo", b"RECEIPT_TWO_DATA").await;
    storage.commit_finalize(&p2).await.unwrap();
    let (r_fresh, p_fresh, _) =
        prepare_finalizable_session(&storage, "repo", b"RECEIPT_FRESH_DATA").await;
    storage.commit_finalize(&p_fresh).await.unwrap();
    backdate_json_u64_field(
        &storage.finalized_receipt_path(&r1.uuid),
        "finalized_at_unix_secs",
        stale,
    );
    backdate_json_u64_field(
        &storage.finalized_receipt_path(&r2.uuid),
        "finalized_at_unix_secs",
        stale,
    );

    // max_age = 3600, receipt_ttl = 3600: only the backdated records qualify.
    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 4, "2 aborted sessions + 2 unlinked receipts");

    // Confirm exactly which records were acted on.
    assert!(!storage.session_meta_path(&s1.uuid).exists());
    assert!(!storage.session_meta_path(&s2.uuid).exists());
    assert!(
        storage.session_meta_path(&s_fresh.uuid).exists(),
        "fresh session survives"
    );
    assert!(
        storage.session_meta_path(&s_locked.uuid).exists(),
        "locked session survives"
    );
    assert!(!storage.finalized_receipt_path(&r1.uuid).exists());
    assert!(!storage.finalized_receipt_path(&r2.uuid).exists());
    assert!(
        storage.finalized_receipt_path(&r_fresh.uuid).exists(),
        "fresh receipt survives"
    );
}

/// CAS mismatch: after the source data file is gone, a destination blob of the
/// WRONG size must fail the publish rather than assert a bogus finalization.
#[tokio::test]
async fn test_fs_commit_finalize_cas_mismatch_is_error() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let (session, prepared, digest) =
        prepare_finalizable_session(&storage, "repo", b"PAYLOAD_TWELVE").await;

    // Destination holds a wrong-size blob and the staging data is gone.
    let cas = cas_blob_path(&root, &digest);
    ensure_dir(cas.parent().unwrap()).unwrap();
    std::fs::write(&cas, b"X").unwrap();
    std::fs::remove_file(storage.session_data_path(&session.uuid)).unwrap();

    let res = storage.commit_finalize(&prepared).await;
    assert!(
        res.is_err(),
        "a wrong-size CAS destination with a missing source must fail the publish"
    );
    // No receipt was asserted for the mismatched publish.
    assert!(!storage.finalized_receipt_path(&session.uuid).exists());
}

/// CAS present (partial-publication roll-forward): if the source data was already
/// renamed into CAS at the correct size, a retry tolerates the missing source and
/// completes membership + receipt, reporting a published finalize.
#[tokio::test]
async fn test_fs_commit_finalize_tolerates_prior_cas_publication() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"ROLL_FORWARD_DATA";
    let (session, prepared, digest) = prepare_finalizable_session(&storage, "repo", data).await;

    // Simulate a crash right after the CAS rename: the blob is present at the
    // correct size, but the staging data file is gone.
    let cas = cas_blob_path(&root, &digest);
    ensure_dir(cas.parent().unwrap()).unwrap();
    std::fs::copy(storage.session_data_path(&session.uuid), &cas).unwrap();
    std::fs::remove_file(storage.session_data_path(&session.uuid)).unwrap();

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: data.len() as u64
        })
    );
    assert!(membership_record_path(&root, "repo", &digest).exists());
    assert!(storage.finalized_receipt_path(&session.uuid).exists());
}

/// Membership failure before receipt + retry: from a post-crash state where the
/// CAS blob is present but meta/membership/receipt are all gone, a retry heals
/// both membership and receipt and reports an idempotent finalization.
#[tokio::test]
async fn test_fs_commit_finalize_retry_heals_membership_and_receipt() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"HEAL_BOTH_DATA";
    let (session, prepared, digest) = prepare_finalizable_session(&storage, "repo", data).await;

    // CAS present at the correct size; every staging + index record removed.
    let cas = cas_blob_path(&root, &digest);
    ensure_dir(cas.parent().unwrap()).unwrap();
    std::fs::copy(storage.session_data_path(&session.uuid), &cas).unwrap();
    std::fs::remove_file(storage.session_data_path(&session.uuid)).unwrap();
    let _ = std::fs::remove_file(storage.session_meta_path(&session.uuid));
    let _ = std::fs::remove_file(storage.session_hash_path(&session.uuid, 1));
    let _ = std::fs::remove_file(membership_record_path(&root, "repo", &digest));
    assert!(!membership_record_path(&root, "repo", &digest).exists());

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::AlreadyFinalized(BlobMeta {
            size: data.len() as u64
        })
    );
    assert!(
        membership_record_path(&root, "repo", &digest).exists(),
        "membership healed"
    );
    assert!(
        storage.finalized_receipt_path(&session.uuid).exists(),
        "receipt healed"
    );
}

/// Receipt failure after membership success + retry: from a fully published blob
/// whose receipt was lost, a retry re-asserts the receipt (membership already
/// present) and reports an idempotent finalization.
#[tokio::test]
async fn test_fs_commit_finalize_retry_restores_lost_receipt() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"RESTORE_RECEIPT";
    let (session, prepared, digest) = prepare_finalizable_session(&storage, "repo", data).await;
    storage.commit_finalize(&prepared).await.unwrap();

    // The receipt is lost post-crash; CAS + membership remain.
    std::fs::remove_file(storage.finalized_receipt_path(&session.uuid)).unwrap();
    assert!(membership_record_path(&root, "repo", &digest).exists());

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::AlreadyFinalized(BlobMeta {
            size: data.len() as u64
        })
    );
    assert!(
        storage.finalized_receipt_path(&session.uuid).exists(),
        "receipt restored"
    );
}

/// Existing receipt with missing membership: a commit replay is receipt-
/// authoritative — it reports the finalization from the receipt without
/// re-deriving the CAS state, so the membership index is NOT rewritten by replay.
/// (Recovery is the path that re-asserts membership; see the recover test below.)
#[tokio::test]
async fn test_fs_commit_finalize_replay_is_receipt_authoritative() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"RECEIPT_AUTHORITATIVE";
    let (_session, prepared, digest) = prepare_finalizable_session(&storage, "repo", data).await;
    storage.commit_finalize(&prepared).await.unwrap();

    // Receipt present, membership dropped.
    std::fs::remove_file(membership_record_path(&root, "repo", &digest)).unwrap();

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::AlreadyFinalized(BlobMeta {
            size: data.len() as u64
        })
    );
    assert!(
        !membership_record_path(&root, "repo", &digest).exists(),
        "receipt-authoritative replay does not rewrite membership"
    );
}

/// Recover roll-forward: a Finalizing session whose CAS blob is present at the
/// expected size re-asserts BOTH membership and receipt (self-healing the index
/// that a receipt-authoritative replay leaves alone).
#[tokio::test]
async fn test_fs_recover_session_rolls_forward_membership_and_receipt() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"RECOVER_ROLLFORWARD";
    let (session, _prepared, digest) = prepare_finalizable_session(&storage, "repo", data).await;

    // CAS present at the expected size; no membership, no receipt yet.
    let cas = cas_blob_path(&root, &digest);
    ensure_dir(cas.parent().unwrap()).unwrap();
    std::fs::copy(storage.session_data_path(&session.uuid), &cas).unwrap();
    assert!(!membership_record_path(&root, "repo", &digest).exists());
    assert!(!storage.finalized_receipt_path(&session.uuid).exists());

    let status = storage.recover_session(&session).await.unwrap();
    assert_eq!(status.state, UploadSessionState::Finalizing);
    assert!(
        membership_record_path(&root, "repo", &digest).exists(),
        "membership rolled forward"
    );
    assert!(
        storage.finalized_receipt_path(&session.uuid).exists(),
        "receipt rolled forward"
    );
}

/// Abort interruption before metadata removal + retry: with the staging data
/// already gone (as after a crash mid-abort) but the meta still present, a retry
/// completes the abort (meta removed) and is idempotent on a further retry.
#[tokio::test]
async fn test_fs_abort_session_retry_after_partial_interruption() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage.create_session("repo").await.unwrap();
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"ABORT_DATA")]),
            1024 * 1024,
        )
        .await
        .unwrap();

    // Simulate a crash after the data was unlinked but before the meta was removed.
    std::fs::remove_file(storage.session_data_path(&session.uuid)).unwrap();
    assert!(storage.session_meta_path(&session.uuid).exists());

    // Retry completes the abort: meta removed LAST, and the operation is total.
    storage.abort_session(&session).await.unwrap();
    assert!(!storage.session_meta_path(&session.uuid).exists());

    // Idempotent: a further retry against an already-aborted session still succeeds.
    storage.abort_session(&session).await.unwrap();
}

// --------------------------------------------------------------------------
// #1 Reaper lock-gap regressions
//
// The reaper inspects, decides expiry, revalidates, and acts on each candidate
// inside ONE continuously-held `.lock.{uuid}` (acquired once, never dropped and
// reacquired). These tests exercise the former inspection/action boundary
// directly through the production reaper via the test-only boundary hook.
// --------------------------------------------------------------------------

/// A cooperating session update attempted at the former inspection/action boundary
/// cannot slip between the locked expiry check and the destructive action: it blocks
/// on the continuously-held session lock and, once released, observes the session as
/// already reaped. (Not a root-replacement test: the same live session is contended.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_fs_reaper_locked_boundary_excludes_cooperating_update() {
    use std::sync::mpsc as std_mpsc;

    let root = tmp_fs_root();
    let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));

    // An expired Appending session with committed bytes.
    let session = storage.create_session("repo").await.unwrap();
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"HALF")]),
            1024 * 1024,
        )
        .await
        .unwrap();
    let stale = now_unix_secs().saturating_sub(100_000);
    backdate_json_u64_field(
        &storage.session_meta_path(&session.uuid),
        "last_active_at_unix_secs",
        stale,
    );

    // Boundary hook: signal the test once the reaper reaches the post-expiry-check,
    // pre-action boundary while holding the session lock, then block (still holding
    // the lock) until the test releases it.
    let (reached_tx, reached_rx) = std_mpsc::channel::<()>();
    let (release_tx, release_rx) = std_mpsc::channel::<()>();
    let reached_tx = std::sync::Mutex::new(Some(reached_tx));
    let release_rx = std::sync::Mutex::new(release_rx);
    let target = session.uuid.clone();
    storage.set_reaper_boundary_hook(Arc::new(move |uuid: &str| {
        if uuid == target {
            if let Some(tx) = reached_tx.lock().unwrap().take() {
                tx.send(()).unwrap();
            }
            release_rx.lock().unwrap().recv().unwrap();
        }
    }));

    // Run the reaper; it parks at the boundary holding the lock.
    let s = storage.clone();
    let reaper = tokio::spawn(async move { s.reap_expired_sessions(3600, 3600).await });

    // Wait until the reaper is parked at the boundary (lock held, expiry decided).
    tokio::task::spawn_blocking(move || reached_rx.recv().unwrap())
        .await
        .unwrap();

    // A cooperating update now attempts to advance the SAME session. It must block on
    // the still-held session lock and cannot slip in before the reaper's action.
    let s2 = storage.clone();
    let sess2 = session.clone();
    let update = tokio::spawn(async move {
        s2.append_if_offset(
            &sess2,
            UploadOffsetPrecondition::Exact(4),
            make_test_stream(vec![Bytes::from_static(b"MORE")]),
            1024 * 1024,
        )
        .await
    });

    // While the reaper holds the lock, the update must NOT complete.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !update.is_finished(),
        "a cooperating update must not slip between the locked expiry check and the destructive action"
    );

    // Release the reaper: it aborts the expired session and drops the lock.
    release_tx.send(()).unwrap();
    let reaped = reaper.await.unwrap().unwrap();
    assert_eq!(reaped, 1, "the expired session is confirmed reaped");
    assert!(
        !storage.session_meta_path(&session.uuid).exists(),
        "the reaper aborted the session (meta removed) under the held lock"
    );

    // The update, unblocked only AFTER the destructive action, now finds no session
    // and fails — it did not mutate a reaped session.
    let update_res = update.await.unwrap();
    assert!(
        update_res.is_err(),
        "the update ran strictly after the abort and must observe the session as gone"
    );
}

/// An update that COMPLETED before the reaper's locked expiry check is respected: the
/// reaper reads `last_active` freshly under the lock (never a stale listing snapshot),
/// so a session that was expired on disk but has since been refreshed survives.
#[tokio::test]
async fn test_fs_reaper_honors_update_completed_before_locked_check() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // A session that is expired on disk...
    let session = storage.create_session("repo").await.unwrap();
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"AAAA")]),
            1024 * 1024,
        )
        .await
        .unwrap();
    let stale = now_unix_secs().saturating_sub(100_000);
    backdate_json_u64_field(
        &storage.session_meta_path(&session.uuid),
        "last_active_at_unix_secs",
        stale,
    );

    // ...but a cooperating update lands and refreshes `last_active` to now BEFORE the
    // reaper runs. The reaper's expiry decision reads the meta freshly under the lock.
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(4),
            make_test_stream(vec![Bytes::from_static(b"BBBB")]),
            1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(res, UploadAppendResult::Committed { new_offset: 8 });

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 0, "the freshly-updated session is not expired");
    assert!(
        storage.session_meta_path(&session.uuid).exists(),
        "the reaper honored the completed update and left the session in place"
    );
}

// --------------------------------------------------------------------------
// #2 Receipt-cleanup locking regressions
//
// Each finalized receipt is unlinked only under the matching `.lock.{uuid}`
// session lock, re-reading the receipt under the lock. These tests cover a busy
// lock, concurrent (re)publication, a changed receipt identity, disappearance,
// and a fresh same-UUID session's receipt.
// --------------------------------------------------------------------------

/// A receipt whose session lock is held by a live participant is left untouched: the
/// reaper's per-receipt `try_lock` yields busy and the receipt is skipped.
#[tokio::test]
async fn test_fs_reaper_receipt_busy_lock_is_skipped() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let (session, prepared, _digest) =
        prepare_finalizable_session(&storage, "repo", b"BUSY_RECEIPT_DATA").await;
    storage.commit_finalize(&prepared).await.unwrap();
    backdate_json_u64_field(
        &storage.finalized_receipt_path(&session.uuid),
        "finalized_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    // Hold the session lock: a live same-UUID participant owns the receipt.
    let _held = acquire_fs_session_lock(storage.session_lock_path(&session.uuid))
        .await
        .unwrap();

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 0, "a busy-locked receipt is not reaped");
    assert!(
        storage.finalized_receipt_path(&session.uuid).exists(),
        "the busy-locked receipt is preserved"
    );
}

/// A receipt (re)published fresh at the under-lock boundary is respected: the reaper
/// re-reads the CURRENT receipt under the lock, sees a fresh `finalized_at`, and keeps
/// it rather than acting on the stale listing-time snapshot.
#[tokio::test]
async fn test_fs_reaper_receipt_concurrent_publication_is_respected() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let (session, prepared, _digest) =
        prepare_finalizable_session(&storage, "repo", b"REPUBLISH_RECEIPT").await;
    storage.commit_finalize(&prepared).await.unwrap();
    // Backdate so the LISTING-time snapshot looks expired.
    let receipt_path = storage.finalized_receipt_path(&session.uuid);
    backdate_json_u64_field(
        &receipt_path,
        "finalized_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    // At the under-lock boundary, a concurrent publisher refreshes the receipt.
    let target = session.uuid.clone();
    let refreshed_path = receipt_path.clone();
    let fresh = now_unix_secs();
    storage.set_reaper_receipt_boundary_hook(Arc::new(move |uuid: &str| {
        if uuid == target {
            backdate_json_u64_field(&refreshed_path, "finalized_at_unix_secs", fresh);
        }
    }));

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 0, "a concurrently-republished receipt is not reaped");
    assert!(
        receipt_path.exists(),
        "the reaper re-read the fresh receipt under the lock and preserved it"
    );
}

/// A receipt whose stored identity no longer matches its leaf name (a same-UUID
/// replacement) is preserved: identity revalidation under the lock reports Changed.
#[tokio::test]
async fn test_fs_reaper_receipt_changed_identity_is_preserved() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let (session, prepared, _digest) =
        prepare_finalizable_session(&storage, "repo", b"IDENTITY_RECEIPT").await;
    storage.commit_finalize(&prepared).await.unwrap();
    let receipt_path = storage.finalized_receipt_path(&session.uuid);
    backdate_json_u64_field(
        &receipt_path,
        "finalized_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    // Rewrite the receipt's stored uuid so it no longer matches the leaf name.
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    v["uuid"] = serde_json::json!(format!("{}-rotated", session.uuid));
    std::fs::write(&receipt_path, serde_json::to_vec(&v).unwrap()).unwrap();

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 0, "a receipt with a changed identity is not reaped");
    assert!(
        receipt_path.exists(),
        "the reaper preserved the identity-changed receipt"
    );
}

/// A receipt that disappears at the under-lock boundary (a concurrent non-locked
/// removal) is handled as absent: the reaper's re-read returns nothing and no cleanup
/// is counted, with no error.
#[tokio::test]
async fn test_fs_reaper_receipt_disappearance_is_absent() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let (session, prepared, _digest) =
        prepare_finalizable_session(&storage, "repo", b"VANISHING_RECEIPT").await;
    storage.commit_finalize(&prepared).await.unwrap();
    let receipt_path = storage.finalized_receipt_path(&session.uuid);
    backdate_json_u64_field(
        &receipt_path,
        "finalized_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    // At the under-lock boundary, the receipt vanishes out from under the reaper.
    let target = session.uuid.clone();
    let vanish_path = receipt_path.clone();
    storage.set_reaper_receipt_boundary_hook(Arc::new(move |uuid: &str| {
        if uuid == target {
            let _ = std::fs::remove_file(&vanish_path);
        }
    }));

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 0, "a vanished receipt is not counted as a cleanup");
    assert!(!receipt_path.exists(), "the receipt is (still) gone");
}

/// A fresh same-UUID session's receipt is preserved: even with an expired listing-time
/// snapshot, the reaper re-reads under the lock, and a fresh `finalized_at` keeps it.
#[tokio::test]
async fn test_fs_reaper_receipt_fresh_same_uuid_is_preserved() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let (session, prepared, _digest) =
        prepare_finalizable_session(&storage, "repo", b"FRESH_SAME_UUID").await;
    storage.commit_finalize(&prepared).await.unwrap();
    let receipt_path = storage.finalized_receipt_path(&session.uuid);

    // The receipt is fresh (never backdated): a same-UUID session just finalized.
    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 0, "a fresh receipt is not reaped");
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_some(),
        "the fresh same-UUID receipt is preserved and still resolvable"
    );
    assert!(receipt_path.exists());
}

// --------------------------------------------------------------------------
// #3 Public receipt lookup routes through the pinned finalized authority
//
// `get_finalized_receipt` must resolve through the SAME pinned `.finalized`
// authority the writers publish through, so reader and writer agree after a
// `.finalized` or `uploads` pathname replacement.
// --------------------------------------------------------------------------

/// After the `.finalized` subtree is replaced beneath an unchanged root, the public
/// `get_finalized_receipt` still resolves the receipt through the pinned authority
/// (the detached inode where the writer published it), agreeing with commit.
#[tokio::test]
async fn test_fs_get_finalized_receipt_after_finalized_replacement_uses_pin() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let data = b"PUBLIC_LOOKUP_FINALIZED_REPLACE";
    let (session, prepared, digest) = prepare_finalizable_session(&storage, "myrepo", data).await;
    storage.commit_finalize(&prepared).await.unwrap();

    // Agreement before replacement.
    let before = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .expect("receipt present after commit");
    assert_eq!(before.digest, digest.as_str());

    // Replace the `.finalized` subtree with a fresh, empty inode.
    let finalized_dir = storage.finalized_dir();
    let detached = storage.uploads_dir().join(".finalized.detached");
    std::fs::rename(&finalized_dir, &detached).unwrap();
    std::fs::create_dir(&finalized_dir).unwrap();
    assert!(
        std::fs::read_dir(&finalized_dir).unwrap().next().is_none(),
        "ambient replacement is empty"
    );

    // The public lookup consults the pinned authority (detached inode), not the empty
    // ambient replacement — so it still agrees with the writer.
    let after = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .expect("public lookup must find the receipt through the pinned .finalized authority");
    assert_eq!(after.digest, digest.as_str());
    assert_eq!(after.uuid, session.uuid);
    assert_eq!(after.repo, session.repo);
}

/// After the `uploads` subtree is replaced beneath an unchanged root, the public
/// `get_finalized_receipt` still resolves through the pinned `.finalized` authority
/// (nested in the detached uploads inode), agreeing with a recovery roll-forward.
#[tokio::test]
async fn test_fs_get_finalized_receipt_after_uploads_replacement_uses_pin() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let data = b"PUBLIC_LOOKUP_UPLOADS_REPLACE";
    let (session, prepared, digest) = prepare_finalizable_session(&storage, "myrepo", data).await;
    storage.commit_finalize(&prepared).await.unwrap();
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_some()
    );

    // Replace the uploads subtree (which nests `.finalized`) with a fresh inode.
    let uploads_dir = storage.uploads_dir();
    let detached = root.join("uploads.detached");
    std::fs::rename(&uploads_dir, &detached).unwrap();
    std::fs::create_dir(&uploads_dir).unwrap();
    assert!(
        std::fs::read_dir(&uploads_dir).unwrap().next().is_none(),
        "ambient replacement is empty"
    );

    // The public lookup still finds the receipt through the pinned authority, and a
    // recovery roll-forward (also pinned) agrees on the same finalized state.
    let after = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .expect("public lookup must resolve through the pinned authority after uploads replace");
    assert_eq!(after.digest, digest.as_str());
    let recovered = storage.recover_session(&session).await.unwrap();
    assert_eq!(recovered.state, UploadSessionState::Finalizing);
}

// --------------------------------------------------------------------------
// #5 Deterministic atomic-write failure semantics
//
// These drive the dependency's `write_leaf_atomic` primitive through the
// production membership/finalize paths and inject faults at each internal step
// via the opt-in `storage_fs::mutate::fault` seam (enabled ONLY through the
// registry dev-dependency; production builds never contain it). The global fault
// registry is shared process-wide, so these tests serialize on a dedicated lock
// and reset the table before and after each case.
// --------------------------------------------------------------------------

/// Begins an exclusive fault-injection scenario on the process-wide guard
/// (`store_common::fault_scenario`): the dep's fault registry is a single
/// process-global table and `fault::reset` clears every armed rule, so ALL
/// scenarios — these and the domain-level fault tests — must serialize on the
/// same lock. A second, module-local lock here is exactly the historical
/// defect (a reset under one lock wiped rules armed under the other). The
/// returned guard resets the table on entry and again on Drop, so cleanup
/// survives assertion panics and early returns.
async fn fault_test_guard() -> crate::storage::store_common::fault_scenario::FaultScenario {
    crate::storage::store_common::fault_scenario::begin().await
}

/// Isolation: a scenario's armed rules cannot be wiped by another scenario's
/// begin/reset. A competing `begin()` must block until the open scenario
/// drops, and the open scenario's armed fault must still fire when consumed.
/// This is the deterministic regression for the historical two-lock defect
/// (domain fault tests failing "failed durable barrier must propagate" when a
/// storage-fs fault test's global reset landed between their arm and consume).
#[tokio::test]
async fn test_fault_scenario_serializes_and_preserves_armed_rules() {
    use crate::storage::repo_membership::{
        RepoBlobMembershipRecord, RepositoryBlobMembershipStorage,
    };
    use storage_fs::mutate::fault::{FaultPoint, arm};

    let scenario = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = CanonicalRepoName::parse("repo").unwrap();
    let digest = membership_digest(0xA1);
    let record = RepoBlobMembershipRecord::new_upload(repo.clone(), digest.clone(), None);
    arm(FaultPoint::RenameLeaf, Some(digest.hex()), 1, libc::EIO);

    // A competing scenario (historically: an fs fault test's guard, which
    // globally reset the table under an independent lock) must not begin
    // while this scenario is open.
    let b_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let b_flag = b_done.clone();
    let b = tokio::spawn(async move {
        let _competing = crate::storage::store_common::fault_scenario::begin().await;
        b_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        !b_done.load(std::sync::atomic::Ordering::SeqCst),
        "a second scenario must not begin (and reset the table) while a scenario is open"
    );

    // The armed rule survived the competing begin attempt and still fires.
    storage
        .link_repo_blob(&record)
        .await
        .expect_err("the armed publication fault must still fire: no concurrent reset wiped it");

    drop(scenario);
    b.await.unwrap();
    assert!(
        b_done.load(std::sync::atomic::Ordering::SeqCst),
        "the competing scenario proceeds once the open scenario drops"
    );
}

/// Needle scoping: an armed rule anchored to one storage root must never fire
/// for operations on a different root, and must still fire for its own. This
/// is the regression for the historical broad DirSync needles
/// ("blobs"/"quarantine"), which matched the authority display path of ANY
/// concurrent test's tree — injecting spurious EIO into unrelated tests
/// (observed live as reaper-test EIO failures) while eating the arming test's
/// own expected fault.
#[tokio::test]
async fn test_fault_scenario_root_anchored_needle_does_not_cross_roots() {
    use storage_fs::mutate::fault::{FaultPoint, arm};

    let _g = fault_test_guard().await;

    let root_a = tmp_fs_root();
    let root_b = tmp_fs_root();
    let storage_a = FsStorage::new(root_a.clone(), 1024 * 1024);
    let storage_b = FsStorage::new(root_b.clone(), 1024 * 1024);
    let (_session_a, prepared_a, _digest_a) =
        prepare_finalizable_session(&storage_a, "xroota", b"cross-root-payload-a").await;
    let (_session_b, prepared_b, _digest_b) =
        prepare_finalizable_session(&storage_b, "xrootb", b"cross-root-payload-b").await;

    // Arm the publication-barrier fault anchored to root A's CAS tree.
    let needle_a = format!("{}/blobs", root_a.display());
    arm(FaultPoint::DirSync, Some(&needle_a), 1, libc::EIO);

    // The same publication on root B must not consume root A's rule.
    storage_b
        .commit_finalize(&prepared_b)
        .await
        .expect("a rule anchored to another root must not fire here");

    // Root A's own publication still observes the armed fault.
    storage_a
        .commit_finalize(&prepared_a)
        .await
        .expect_err("the root-anchored rule must still fire for its own root");
}

/// Cleanup: dropping a scenario clears its remaining armed rules, so
/// operations after the scenario (here: outside any scenario, with no
/// entry-reset to mask the Drop path) do not inherit its faults. The needle
/// is the probe record's own digest — unique to this test, per the fault
/// seam's needle-uniqueness contract (a broad/None needle would be consumed
/// by unrelated concurrent tests' operations, injecting spurious faults).
#[tokio::test]
async fn test_fault_scenario_drop_clears_unconsumed_rules() {
    use crate::storage::repo_membership::{
        RepoBlobMembershipRecord, RepositoryBlobMembershipStorage,
    };
    use storage_fs::mutate::fault::{FaultPoint, arm};

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = CanonicalRepoName::parse("repo").unwrap();
    let digest = membership_digest(0xA2);
    let record = RepoBlobMembershipRecord::new_upload(repo.clone(), digest.clone(), None);

    let scenario = fault_test_guard().await;
    arm(FaultPoint::AtomicWrite, Some(digest.hex()), 1, libc::EIO);
    drop(scenario);

    storage
        .link_repo_blob(&record)
        .await
        .expect("no fault inherited from the dropped scenario");
}

/// Failure cleanup: a scenario that panics mid-test (the shape of any failed
/// fault-test assertion between arm and reset) still clears its armed rules
/// via Drop during unwind, and the guard is usable afterwards — the tokio
/// mutex does not poison, so one failing fault test cannot cascade. The
/// armed needle targets this test's own probe digest only.
#[tokio::test]
async fn test_fault_scenario_panic_clears_rules_and_does_not_poison() {
    use crate::storage::repo_membership::{
        RepoBlobMembershipRecord, RepositoryBlobMembershipStorage,
    };
    use storage_fs::mutate::fault::{FaultPoint, arm};

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = CanonicalRepoName::parse("repo").unwrap();
    let digest = membership_digest(0xA3);
    let record = RepoBlobMembershipRecord::new_upload(repo.clone(), digest.clone(), None);

    let needle = digest.hex().to_string();
    let failed = tokio::spawn(async move {
        let _scenario = crate::storage::store_common::fault_scenario::begin().await;
        arm(FaultPoint::AtomicWrite, Some(&needle), 1, libc::EIO);
        panic!("simulated failing fault test");
    })
    .await;
    assert!(
        failed.is_err(),
        "the simulated fault test must have panicked"
    );

    // The rule armed by the panicked scenario was cleared by Drop during
    // unwind: the write it targeted succeeds.
    storage
        .link_repo_blob(&record)
        .await
        .expect("no fault survives a panicked scenario");

    // And the scenario guard remains acquirable (no poisoning).
    let _next = fault_test_guard().await;
}

fn membership_digest(seed: u8) -> Digest {
    let mut hasher = sha2::Sha256::new();
    hasher.update([seed; 32]);
    Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize()))).unwrap()
}

/// Publication failure surfaces: an ENOSPC on the publish rename (the
/// destination-anchored step of the adapter's staged write; the temp-file
/// staging now happens under the adapter's PRIVATE tmp tree with unique
/// names and is pinned by the dependency's own suite) surfaces as
/// `InsufficientStorage` and leaves no destination behind.
#[tokio::test]
async fn test_fs_atomic_primary_write_failure_surfaces_and_leaves_no_destination() {
    use crate::storage::repo_membership::{
        RepoBlobMembershipRecord, RepositoryBlobMembershipStorage,
    };
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = CanonicalRepoName::parse("repo").unwrap();
    let digest = membership_digest(0x11);
    let record = RepoBlobMembershipRecord::new_upload(repo.clone(), digest.clone(), None);

    arm(FaultPoint::RenameLeaf, Some(digest.hex()), 1, libc::ENOSPC);
    let err = storage
        .link_repo_blob(&record)
        .await
        .expect_err("a publication failure must surface, not silently succeed");
    assert!(
        matches!(err, StorageError::InsufficientStorage),
        "ENOSPC keeps the InsufficientStorage classification, got {err:?}"
    );
    assert!(
        !membership_record_path(&root, "repo", &digest).exists(),
        "a failed publication must not publish a destination record"
    );

    storage_fs::mutate::fault::reset();
}

/// Rename failure with prior-destination preservation: when the publish `renameat`
/// fails, any pre-existing destination is preserved untouched and the temp is cleaned
/// up (no residual, no partial overwrite).
#[tokio::test]
async fn test_fs_atomic_rename_failure_preserves_prior_destination() {
    use crate::storage::repo_membership::{
        MembershipState, RepoBlobMembershipRecord, RepositoryBlobMembershipStorage,
    };
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = CanonicalRepoName::parse("repo").unwrap();
    let digest = membership_digest(0x22);
    let path = membership_record_path(&root, "repo", &digest);

    // Publish an initial record (Active) with no fault.
    let original = RepoBlobMembershipRecord::new_upload(repo.clone(), digest.clone(), None);
    storage.link_repo_blob(&original).await.unwrap();
    let original_bytes = std::fs::read(&path).unwrap();

    // Attempt to overwrite with a mutated record while the publish rename fails.
    let mut mutated = original.clone();
    mutated.state = MembershipState::Candidate;
    mutated.unreferenced_since_unix_secs = Some(now_unix_secs());
    arm(FaultPoint::RenameLeaf, Some(digest.hex()), 1, libc::EIO);
    storage
        .link_repo_blob(&mutated)
        .await
        .expect_err("a failed publish rename must surface an error");

    // The prior destination is preserved byte-for-byte; no temp residue remains.
    assert_eq!(
        std::fs::read(&path).unwrap(),
        original_bytes,
        "a failed rename must preserve the prior destination unchanged"
    );
    let algo_dir = path.parent().unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(algo_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != &format!("{}.json", digest.hex()))
        .collect();
    assert!(
        leftovers.is_empty(),
        "the failed write must leave no temp residual: {leftovers:?}"
    );

    storage_fs::mutate::fault::reset();
}

/// A failed publication leaves the OBJECT directory free of any staging
/// residue and the prior destination intact. (The retired direct-staging
/// shape could leave `.tmp.` residue in the record directory when its
/// cleanup also failed — the `CleanupFailed` surfacing pin. The adapter
/// stages under its PRIVATE tmp tree with unique names, so object
/// directories structurally never contain staging entries; staging-cleanup
/// mechanics are pinned by the dependency's own suite.)
#[tokio::test]
async fn test_fs_atomic_secondary_cleanup_failure_surfaces() {
    use crate::storage::repo_membership::{
        RepoBlobMembershipRecord, RepositoryBlobMembershipStorage,
    };
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = CanonicalRepoName::parse("repo").unwrap();
    let digest = membership_digest(0x33);
    let path = membership_record_path(&root, "repo", &digest);

    let original = RepoBlobMembershipRecord::new_upload(repo.clone(), digest.clone(), None);
    storage.link_repo_blob(&original).await.unwrap();
    let original_bytes = std::fs::read(&path).unwrap();

    arm(FaultPoint::RenameLeaf, Some(digest.hex()), 1, libc::EIO);
    storage
        .link_repo_blob(&original)
        .await
        .expect_err("a failed publication must surface an error");

    // The prior destination is intact and the record directory holds no
    // staging residue of any kind.
    assert_eq!(std::fs::read(&path).unwrap(), original_bytes);
    let algo_dir = path.parent().unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(algo_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != &format!("{}.json", digest.hex()))
        .collect();
    assert!(
        leftovers.is_empty(),
        "the object directory must never contain staging residue: {leftovers:?}"
    );

    storage_fs::mutate::fault::reset();
}

/// Retry after a transient write failure heals: once the injected fault is cleared, a
/// retry of the same operation completes and publishes the record.
#[tokio::test]
async fn test_fs_atomic_write_failure_retry_heals() {
    use crate::storage::repo_membership::{
        RepoBlobMembershipRecord, RepositoryBlobMembershipStorage,
    };
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = CanonicalRepoName::parse("repo").unwrap();
    let digest = membership_digest(0x44);
    let record = RepoBlobMembershipRecord::new_upload(repo.clone(), digest.clone(), None);

    // First attempt fails on the publication step (count 1).
    arm(FaultPoint::RenameLeaf, Some(digest.hex()), 1, libc::ENOSPC);
    storage
        .link_repo_blob(&record)
        .await
        .expect_err("the first attempt fails under the armed fault");
    assert!(!membership_record_path(&root, "repo", &digest).exists());

    // The rule has drained (count 0); a retry heals.
    storage.link_repo_blob(&record).await.unwrap();
    assert!(
        membership_record_path(&root, "repo", &digest).exists(),
        "a retry after the transient fault clears must publish the record"
    );

    storage_fs::mutate::fault::reset();
}

/// End-to-end honest propagation: a write fault injected on the membership record
/// during `commit_finalize` must fail the finalize (not report a spurious success),
/// demonstrating that per-step write failures are surfaced rather than suppressed.
#[tokio::test]
async fn test_fs_commit_finalize_membership_write_failure_is_surfaced() {
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"HONEST_FINALIZE_FAILURE";
    let (session, prepared, digest) = prepare_finalizable_session(&storage, "repo", data).await;

    arm(FaultPoint::AtomicWrite, Some(digest.hex()), 1, libc::EIO);
    let res = storage.commit_finalize(&prepared).await;
    assert!(
        res.is_err(),
        "a membership write failure during finalize must surface, not report success"
    );
    // The receipt (published after membership) was not asserted for the failed commit.
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_none(),
        "no finalized receipt is published when the membership write fails"
    );

    storage_fs::mutate::fault::reset();
}

// --------------------------------------------------------------------------
// Abort failure boundary (honest cleanup) — requirement #1.
//
// abort_session_locked must remove staging data + every hash generation and
// then the meta LAST, propagating a genuine cleanup failure and PRESERVING the
// meta (so the session stays recoverable and an incomplete abort is never
// counted as a cleanup). A genuine missing leaf is idempotent absence. Hash
// discovery is driven by the recorded generation (and a contained scan when the
// meta is corrupt), never a fixed 0..100 range, so a later/sparse generation is
// never orphaned while the meta is deleted. Faults are injected at the dep's
// `Unlink` fault point through the dev-only fault seam.
// --------------------------------------------------------------------------

/// Advance a session's rolling-hash generation to `appends` by streaming that
/// many single-byte appends, leaving `meta.hash_generation == appends` with only
/// the current generation's hash leaf on disk.
async fn append_n(storage: &FsStorage, session: &UploadSessionId, appends: u64) {
    let mut offset = 0u64;
    for _ in 0..appends {
        let stream = make_test_stream(vec![Bytes::from_static(b"x")]);
        storage
            .append_if_offset(
                session,
                UploadOffsetPrecondition::Exact(offset),
                stream,
                1024 * 1024,
            )
            .await
            .unwrap();
        offset += 1;
    }
}

/// Data-unlink failure: an EIO on the staging data unlink surfaces through the
/// public abort, PRESERVES the meta (session stays recoverable), and a retry
/// after clearing the fault completes the abort.
#[tokio::test]
async fn test_fs_abort_data_unlink_failure_preserves_meta_and_retries() {
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage.create_session("repo").await.unwrap();
    let uuid = session.uuid.clone();
    let meta_path = storage.session_meta_path(&uuid);
    let data_path = storage.session_data_path(&uuid);
    let hash_path = storage.session_hash_path(&uuid, 0);

    // The data unlink (leaf `{uuid}.data`) fails once with EIO.
    arm(
        FaultPoint::Unlink,
        Some(&format!("{uuid}.data")),
        1,
        libc::EIO,
    );
    storage
        .abort_session(&session)
        .await
        .expect_err("a failed data unlink must surface, not report a clean abort");

    // Meta is preserved (removed LAST, and only after data/hash cleanup); the data
    // and hash leaves also survive because cleanup stopped at the first failure.
    assert!(meta_path.exists(), "meta must survive an incomplete abort");
    assert!(
        data_path.exists(),
        "the data leaf that failed to unlink survives"
    );
    assert!(
        hash_path.exists(),
        "the hash leaf survives an incomplete abort"
    );

    // Clearing the fault and retrying completes the abort.
    storage_fs::mutate::fault::reset();
    storage.abort_session(&session).await.unwrap();
    assert!(!meta_path.exists(), "retry removes the meta");
    assert!(!data_path.exists(), "retry removes the data leaf");
    assert!(!hash_path.exists(), "retry removes the hash leaf");
}

/// Hash-unlink failure AFTER an earlier successful deletion: with stray hash
/// generations around the recorded generation, the abort deletes the data leaf
/// and the earlier generations, then fails on a later generation's unlink. The
/// meta is preserved and only the failed generation remains; a retry heals it.
#[tokio::test]
async fn test_fs_abort_hash_unlink_failure_after_earlier_deletion_preserves_meta() {
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage.create_session("repo").await.unwrap();
    let uuid = session.uuid.clone();

    // One append advances the generation to 1 (hash.1 present, hash.0 unlinked).
    append_n(&storage, &session, 1).await;
    // Simulate crash residue: stray hash generations at 0 and 2 around meta gen 1.
    std::fs::write(storage.session_hash_path(&uuid, 0), b"g0").unwrap();
    std::fs::write(storage.session_hash_path(&uuid, 2), b"g2").unwrap();

    let meta_path = storage.session_meta_path(&uuid);
    let data_path = storage.session_data_path(&uuid);
    let (h0, h1, h2) = (
        storage.session_hash_path(&uuid, 0),
        storage.session_hash_path(&uuid, 1),
        storage.session_hash_path(&uuid, 2),
    );
    assert!(h0.exists() && h1.exists() && h2.exists());

    // Fail the unlink of the LAST generation in the window {0,1,2}; deletions of
    // the data leaf and generations 0 and 1 succeed first.
    arm(
        FaultPoint::Unlink,
        Some(&format!("{uuid}.hash.2")),
        1,
        libc::EIO,
    );
    storage
        .abort_session(&session)
        .await
        .expect_err("a failed hash unlink must surface");

    assert!(
        meta_path.exists(),
        "meta survives when hash cleanup is incomplete"
    );
    assert!(
        !data_path.exists(),
        "the data leaf was removed before the failure"
    );
    assert!(!h0.exists(), "generation 0 was removed before the failure");
    assert!(!h1.exists(), "generation 1 was removed before the failure");
    assert!(h2.exists(), "the generation whose unlink failed remains");

    // Retry after clearing the fault completes the abort (window is re-derived).
    storage_fs::mutate::fault::reset();
    storage.abort_session(&session).await.unwrap();
    assert!(
        !meta_path.exists() && !h2.exists(),
        "retry heals the remaining leaf"
    );
}

/// Genuine missing files: aborting a session whose data + hash leaves are already
/// gone is idempotent absence, not a failure, and still removes the meta.
#[tokio::test]
async fn test_fs_abort_tolerates_genuinely_missing_leaves() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage.create_session("repo").await.unwrap();
    let uuid = session.uuid.clone();

    // Remove the data + hash leaves out from under the session, leaving only meta.
    std::fs::remove_file(storage.session_data_path(&uuid)).unwrap();
    std::fs::remove_file(storage.session_hash_path(&uuid, 0)).unwrap();

    storage
        .abort_session(&session)
        .await
        .expect("missing leaves are idempotent absence, not an abort failure");
    assert!(
        !storage.session_meta_path(&uuid).exists(),
        "abort still removes the meta when leaves were already absent"
    );
}

/// Sparse/later hash generation: a session whose recorded generation is far above
/// the old fixed 0..100 range must have its later generations removed, not
/// orphaned while the meta (needed for rediscovery) is deleted.
#[tokio::test]
async fn test_fs_abort_removes_sparse_later_hash_generations() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage.create_session("repo").await.unwrap();
    let uuid = session.uuid.clone();

    // Move the recorded generation well past the former fixed scan bound and place
    // stray leaves in the {G-1, G, G+1} crash window.
    const G: u64 = 250;
    backdate_json_u64_field(&storage.session_meta_path(&uuid), "hash_generation", G);
    std::fs::remove_file(storage.session_hash_path(&uuid, 0)).unwrap();
    for generation in [G - 1, G, G + 1] {
        std::fs::write(storage.session_hash_path(&uuid, generation), b"stray").unwrap();
    }

    storage.abort_session(&session).await.unwrap();

    for generation in [G - 1, G, G + 1] {
        assert!(
            !storage.session_hash_path(&uuid, generation).exists(),
            "abort must remove later hash generation {generation}, not orphan it"
        );
    }
    assert!(
        !storage.session_meta_path(&uuid).exists(),
        "meta removed only after the later generations were cleaned"
    );
}

/// The reaper must count an aborted (non-finalizing) session but NOT count — and
/// must PRESERVE — a session whose data unlink fails: an incomplete abort is a
/// per-candidate failure, logged and skipped, never a confirmed cleanup.
#[tokio::test]
async fn test_fs_reaper_does_not_count_incomplete_abort() {
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let now = now_unix_secs();
    let stale = now.saturating_sub(100_000);

    let session = storage.create_session("repo").await.unwrap();
    let uuid = session.uuid.clone();
    backdate_json_u64_field(
        &storage.session_meta_path(&uuid),
        "last_active_at_unix_secs",
        stale,
    );

    arm(
        FaultPoint::Unlink,
        Some(&format!("{uuid}.data")),
        1,
        libc::EIO,
    );
    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 0, "an incomplete abort is not a confirmed cleanup");
    assert!(
        storage.session_meta_path(&uuid).exists(),
        "the session survives an incomplete reaper abort and stays recoverable"
    );

    storage_fs::mutate::fault::reset();
}

/// Out-of-window residual from a REAL append old-hash unlink failure. This is the
/// production boundary the previous `{G-1, G, G+1}` derivation missed: the append
/// commit protocol persists generation `G+1` in the meta and then cleans up the old
/// `G` leaf with a *suppressed* unlink (`let _ = dir.unlink(...)`). A genuine unlink
/// failure there leaves `G` behind while the recorded generation keeps advancing on
/// later appends, so a residual can sit arbitrarily far below `hash_generation - 1`.
/// The scan-based abort must still remove it.
#[tokio::test]
async fn test_fs_abort_removes_residual_generation_from_real_append_unlink_failure() {
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage.create_session("repo").await.unwrap();
    let uuid = session.uuid.clone();

    // Append 0 -> 1. The append writes `hash.1`, persists meta generation 1, then the
    // best-effort cleanup of `hash.0` FAILS with EIO. Because that unlink result is
    // suppressed in production, the append still commits and `hash.0` is orphaned.
    arm(
        FaultPoint::Unlink,
        Some(&format!("{uuid}.hash.0")),
        1,
        libc::EIO,
    );
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"x")]),
            1024 * 1024,
        )
        .await
        .expect("append commits even though the suppressed old-hash cleanup failed");
    storage_fs::mutate::fault::reset();

    // Append 1 -> 2 with normal cleanup: `hash.2` written, meta generation 2, `hash.1`
    // removed. The recorded generation is now 2, so the OLD window {G-1,G,G+1}={1,2,3}
    // would never revisit the orphaned `hash.0`.
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(1),
            make_test_stream(vec![Bytes::from_static(b"y")]),
            1024 * 1024,
        )
        .await
        .unwrap();

    let meta_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(storage.session_meta_path(&uuid)).unwrap()).unwrap();
    assert_eq!(
        meta_json["hash_generation"].as_u64().unwrap(),
        2,
        "recorded generation advanced past the orphaned residual"
    );
    let (h0, h1, h2) = (
        storage.session_hash_path(&uuid, 0),
        storage.session_hash_path(&uuid, 1),
        storage.session_hash_path(&uuid, 2),
    );
    assert!(
        h0.exists(),
        "generation 0 is an out-of-window residual (0 < hash_generation - 1 = 1)"
    );
    assert!(
        !h1.exists(),
        "generation 1 was cleaned by the second append"
    );
    assert!(h2.exists(), "generation 2 is the current committed hash");

    // The scan-based abort removes EVERY residual for this UUID, not a fixed window.
    storage.abort_session(&session).await.unwrap();
    assert!(
        !h0.exists(),
        "abort removed the out-of-window residual hash.0"
    );
    assert!(!h2.exists(), "abort removed the current hash.2");
    assert!(
        !storage.session_data_path(&uuid).exists(),
        "abort removed the data leaf"
    );
    assert!(
        !storage.session_meta_path(&uuid).exists(),
        "abort removed the meta last"
    );
}

/// Residual from a REAL `begin_finalize` trailing-stream old-hash unlink failure. The
/// trailing-stream branch of `begin_finalize` advances the generation exactly like an
/// append and cleans the old leaf with the same suppressed unlink, so it can orphan a
/// residual too. The scan-based abort removes it. (A finalize residual is at most
/// `G-1` because the session becomes `Finalizing` and cannot advance further, so this
/// covers the second suppressed-cleanup site rather than the out-of-window case.)
#[tokio::test]
async fn test_fs_abort_removes_residual_generation_from_real_finalize_unlink_failure() {
    use storage_fs::mutate::fault::{FaultPoint, arm};
    let _g = fault_test_guard().await;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage.create_session("repo").await.unwrap();
    let uuid = session.uuid.clone();

    // Commit "he" via a normal append: offset 2, generation 1, `hash.1` present.
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"he")]),
            1024 * 1024,
        )
        .await
        .unwrap();

    // begin_finalize with a trailing "llo": drains the tail, writes `hash.2`, persists
    // generation 2, then the suppressed cleanup of `hash.1` FAILS. begin_finalize still
    // prepares successfully (digest matches "hello"), leaving `hash.1` orphaned.
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"hello");
    let digest = Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize()))).unwrap();
    arm(
        FaultPoint::Unlink,
        Some(&format!("{uuid}.hash.1")),
        1,
        libc::EIO,
    );
    storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(5),
            Some(make_test_stream(vec![Bytes::from_static(b"llo")])),
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .expect("begin_finalize prepares even though the suppressed old-hash cleanup failed");
    storage_fs::mutate::fault::reset();

    let (h1, h2) = (
        storage.session_hash_path(&uuid, 1),
        storage.session_hash_path(&uuid, 2),
    );
    assert!(h1.exists(), "the finalize path orphaned generation 1");
    assert!(h2.exists(), "generation 2 is the finalize-committed hash");

    // Aborting the (still-unpublished) Finalizing session scans and removes all leaves.
    storage.abort_session(&session).await.unwrap();
    assert!(!h1.exists(), "abort removed the orphaned finalize residual");
    assert!(!h2.exists(), "abort removed the current hash.2");
    assert!(
        !storage.session_data_path(&uuid).exists(),
        "abort removed the data leaf"
    );
    assert!(
        !storage.session_meta_path(&uuid).exists(),
        "abort removed the meta last"
    );
}

/// Absent meta with a residual hash leaf: the old absent-meta path removed only the
/// data leaf and returned, orphaning any `{uuid}.hash.*` residual forever. The
/// scan-based abort now cleans the residual hash leaves even when the meta is already
/// gone, while staying contained to this UUID.
#[tokio::test]
async fn test_fs_abort_absent_meta_still_removes_residual_hash() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage.create_session("repo").await.unwrap();
    let uuid = session.uuid.clone();

    // Remove ONLY the meta, leaving the data leaf and the `hash.0` residual behind.
    std::fs::remove_file(storage.session_meta_path(&uuid)).unwrap();
    let (data_path, h0) = (
        storage.session_data_path(&uuid),
        storage.session_hash_path(&uuid, 0),
    );
    assert!(data_path.exists() && h0.exists());

    storage
        .abort_session(&session)
        .await
        .expect("absent meta is idempotent, and the residual hash is still cleaned");
    assert!(!data_path.exists(), "abort removed the data leaf");
    assert!(
        !h0.exists(),
        "abort removed the residual hash leaf even with the meta already absent"
    );
}

// --------------------------------------------------------------------------
// Reaper Finalizing policy (baseline preserved) — requirement #2.
//
// The reaper attempts recovery for an expired Finalizing session but NEVER
// aborts it. A fully-published CAS blob rolls forward and counts; a not-yet-
// published / size-mismatched / invalid finalization stays intact and available
// for later completion (not counted); staging data + meta survive the pending
// and error cases.
// --------------------------------------------------------------------------

/// Rewrite `finalizing_info.expected_digest` on the session meta on disk.
fn corrupt_finalizing_digest(path: &Path, bogus: &str) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    v["finalizing_info"]["expected_digest"] = serde_json::json!(bogus);
    std::fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
}

/// Expired Finalizing with staging data present and CAS absent: recovery leaves
/// it pending. The reaper counts nothing and preserves staging data + meta.
#[tokio::test]
async fn test_fs_reaper_leaves_pending_finalizing_with_cas_absent() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let (session, _prepared, _digest) =
        prepare_finalizable_session(&storage, "repo", b"PENDING_FIN_NO_CAS").await;
    let uuid = session.uuid.clone();
    backdate_json_u64_field(
        &storage.session_meta_path(&uuid),
        "last_active_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(
        count, 0,
        "an unpublished finalizing session is not cleaned up"
    );
    assert!(storage.session_meta_path(&uuid).exists(), "meta survives");
    assert!(
        storage.session_data_path(&uuid).exists(),
        "staging data survives"
    );
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_none(),
        "no receipt is fabricated for an unpublished finalization"
    );
}

/// Expired Finalizing whose CAS blob is present but the WRONG size: recovery
/// declines to roll forward, the reaper counts nothing, staging survives.
#[tokio::test]
async fn test_fs_reaper_leaves_finalizing_with_cas_size_mismatch() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let (session, _prepared, digest) =
        prepare_finalizable_session(&storage, "repo", b"MISMATCH_DATA").await;
    let uuid = session.uuid.clone();

    // Publish a blob of the wrong size at the expected CAS path.
    let cas = cas_blob_path(&root, &digest);
    std::fs::create_dir_all(cas.parent().unwrap()).unwrap();
    std::fs::write(&cas, b"WRONG_SIZE_BLOB_CONTENTS").unwrap();

    backdate_json_u64_field(
        &storage.session_meta_path(&uuid),
        "last_active_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 0, "a size-mismatched CAS blob must not roll forward");
    assert!(storage.session_meta_path(&uuid).exists(), "meta survives");
    assert!(
        storage.session_data_path(&uuid).exists(),
        "staging data survives"
    );
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_none(),
        "no receipt for a mismatched blob"
    );
}

/// Expired Finalizing with invalid finalizing information: recovery cannot parse
/// the expected digest, leaves it pending, the reaper counts nothing, survives.
#[tokio::test]
async fn test_fs_reaper_leaves_finalizing_with_invalid_finalizing_info() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let (session, _prepared, _digest) =
        prepare_finalizable_session(&storage, "repo", b"INVALID_FIN_INFO").await;
    let uuid = session.uuid.clone();
    let meta_path = storage.session_meta_path(&uuid);

    corrupt_finalizing_digest(&meta_path, "not-a-valid-digest");
    backdate_json_u64_field(
        &meta_path,
        "last_active_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(
        count, 0,
        "invalid finalizing info must not authorize cleanup"
    );
    assert!(meta_path.exists(), "meta survives");
    assert!(
        storage.session_data_path(&uuid).exists(),
        "staging data survives"
    );
}

/// A pending finalization that is later published rolls forward on the next
/// reaper pass, counting exactly one and publishing the receipt.
#[tokio::test]
async fn test_fs_reaper_finalizing_publication_then_retry_rolls_forward() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"PUBLISH_THEN_RETRY";
    let (session, _prepared, digest) = prepare_finalizable_session(&storage, "repo", data).await;
    let uuid = session.uuid.clone();
    backdate_json_u64_field(
        &storage.session_meta_path(&uuid),
        "last_active_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    // First pass: CAS absent -> pending, nothing counted, staging survives.
    assert_eq!(storage.reap_expired_sessions(3600, 3600).await.unwrap(), 0);
    assert!(storage.session_meta_path(&uuid).exists());
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_none()
    );

    // Publish the CAS blob of the correct size, then reap again -> roll forward.
    let cas = cas_blob_path(&root, &digest);
    std::fs::create_dir_all(cas.parent().unwrap()).unwrap();
    std::fs::write(&cas, data).unwrap();

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(
        count, 1,
        "a now-published finalization rolls forward exactly once"
    );
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_some(),
        "roll-forward publishes the finalized receipt"
    );
}

/// Accurate counting: a fully-published expired Finalizing session rolls forward
/// (counted) while a fresh session is skipped — the reaper counts exactly one.
#[tokio::test]
async fn test_fs_reaper_rolls_forward_published_finalizing_with_accurate_count() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"ROLL_FORWARD_COUNTED";
    let (session, _prepared, digest) = prepare_finalizable_session(&storage, "repo", data).await;
    let uuid = session.uuid.clone();

    // Publish the CAS blob (correct size) and expire the session.
    let cas = cas_blob_path(&root, &digest);
    std::fs::create_dir_all(cas.parent().unwrap()).unwrap();
    std::fs::write(&cas, data).unwrap();
    backdate_json_u64_field(
        &storage.session_meta_path(&uuid),
        "last_active_at_unix_secs",
        now_unix_secs().saturating_sub(100_000),
    );

    // A second, fresh finalizing session must be skipped (not expired).
    let (fresh, _p, _d) = prepare_finalizable_session(&storage, "repo", b"FRESH_FIN").await;

    let count = storage.reap_expired_sessions(3600, 3600).await.unwrap();
    assert_eq!(count, 1, "only the published+expired session is counted");
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_some(),
        "the expired session rolled forward"
    );
    assert!(
        storage.session_meta_path(&fresh.uuid).exists(),
        "the fresh finalizing session is left intact"
    );
}

// --------------------------------------------------------------------------
// Option A contained upload-lifecycle invariants
//
// These exercise the production entry points against a real filesystem and
// assert the guarantees introduced by the coherent contained lifecycle:
// the stable session-lock file is never unlinked during cleanup; commit
// publishes a repository-membership record before the finalized receipt; and
// commit is idempotent when the CAS blob was already published but the staging
// meta was lost to a crash (a partial-publication retry).
// --------------------------------------------------------------------------

/// Drive a session through create -> append(sha256) -> begin_finalize and return
/// the prepared handle plus the payload digest.

/// The ambient on-disk path of the membership record written by the lifecycle,
/// mirroring `repo-memberships/by-repo/{key}/{algo}/{hex}.json`.
fn membership_record_path(root: &Path, repo: &str, digest: &Digest) -> PathBuf {
    let canonical = CanonicalRepoName::parse(repo).unwrap();
    let key = crate::storage::repo_membership::encode_canonical_repo_key(&canonical);
    root.join("repo-memberships")
        .join("by-repo")
        .join(key)
        .join(digest.algorithm())
        .join(format!("{}.json", digest.hex()))
}

#[tokio::test]
async fn test_fs_session_lock_file_retained_through_abort_and_reaper() {
    use std::os::unix::fs::MetadataExt;
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Aborting an active session removes its staging state but MUST retain the
    // stable `.lock.{uuid}` file (never unlinked): the lock domain is stable for
    // the process lifetime so a racing acquirer can never observe a recreated
    // lock inode.
    let aborted = storage.create_session("myrepo").await.unwrap();
    let aborted_lock = storage.session_lock_path(&aborted.uuid);
    let aborted_meta = storage.session_meta_path(&aborted.uuid);
    let aborted_data = storage.session_data_path(&aborted.uuid);
    assert!(
        aborted_lock.exists(),
        "create must materialize the lock file"
    );
    let lock_ino_before = std::fs::metadata(&aborted_lock).unwrap().ino();

    storage.abort_session(&aborted).await.unwrap();
    assert!(
        !aborted_meta.exists() && !aborted_data.exists(),
        "abort must remove staging meta and data"
    );
    assert!(
        aborted_lock.exists(),
        "abort must NOT unlink the stable session lock file"
    );
    assert_eq!(
        lock_ino_before,
        std::fs::metadata(&aborted_lock).unwrap().ino(),
        "the retained lock file must keep the same inode"
    );

    // The reaper aborts an expired session, and likewise must never unlink the
    // lock file it just probed.
    let reaped = storage.create_session("myrepo").await.unwrap();
    let reaped_lock = storage.session_lock_path(&reaped.uuid);
    assert!(reaped_lock.exists());
    let reaped_ino_before = std::fs::metadata(&reaped_lock).unwrap().ino();

    let count = storage.reap_expired_sessions(0, 0).await.unwrap();
    assert_eq!(count, 1, "the single expired session is confirmed reaped");
    assert!(
        !storage.session_meta_path(&reaped.uuid).exists(),
        "reaper must remove the expired session meta"
    );
    assert!(
        reaped_lock.exists(),
        "reaper must NOT unlink the stable session lock file"
    );
    assert_eq!(
        reaped_ino_before,
        std::fs::metadata(&reaped_lock).unwrap().ino(),
        "the retained lock file must keep the same inode after reaping"
    );
}

#[tokio::test]
async fn test_fs_session_commit_publishes_membership_and_receipt() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"OPTION_A_COMMIT_PUBLISHES_MEMBERSHIP";

    let (session, prepared, digest) = prepare_finalizable_session(&storage, "myrepo", data).await;

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: data.len() as u64
        })
    );

    // CAS blob published under the pinned blobs authority.
    let cas_path = root
        .join("blobs")
        .join(digest.algorithm())
        .join(digest.prefix2())
        .join(digest.hex());
    assert!(cas_path.exists(), "commit must publish the CAS blob");

    // Membership record written under the pinned memberships authority. Commit
    // orders the membership write before the receipt write, so at the instant of a
    // successful commit the membership is present. This ordering is not a standing
    // invariant that "an observed receipt implies a durable membership": a receipt-
    // authoritative replay does not rewrite membership, and membership may later be
    // reclaimed independently (see
    // `test_fs_commit_finalize_replay_is_receipt_authoritative`).
    let membership_path = membership_record_path(&root, "myrepo", &digest);
    assert!(
        membership_path.exists(),
        "commit must write the repository membership record"
    );

    // Finalized receipt present and coherent.
    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.digest, digest.as_str());
    assert_eq!(receipt.size, data.len() as u64);

    // Staging meta + hash removed LAST.
    assert!(!storage.session_meta_path(&session.uuid).exists());
}

#[tokio::test]
async fn test_fs_session_commit_idempotent_after_partial_publication() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let data = b"OPTION_A_PARTIAL_PUBLICATION_RETRY";

    let (session, prepared, digest) = prepare_finalizable_session(&storage, "myrepo", data).await;

    // Simulate a crash AFTER the CAS blob was published but BEFORE the receipt
    // and membership were written, and with the staging meta already gone.
    let cas_dir = root
        .join("blobs")
        .join(digest.algorithm())
        .join(digest.prefix2());
    ensure_dir(&cas_dir).unwrap();
    std::fs::write(cas_dir.join(digest.hex()), data).unwrap();
    std::fs::remove_file(storage.session_meta_path(&session.uuid)).unwrap();

    // Commit observes the pre-published blob at the expected size and reports an
    // idempotent success rather than a spurious NotFound, (re)asserting the
    // receipt and membership.
    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::AlreadyFinalized(BlobMeta {
            size: data.len() as u64
        })
    );
    assert!(
        membership_record_path(&root, "myrepo", &digest).exists(),
        "idempotent commit must (re)assert the membership record"
    );
    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_some(),
        "idempotent commit must (re)assert the finalized receipt"
    );
}

#[tokio::test]
async fn test_fs_session_digest_mismatch_policy() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // 1. abort_on_digest_mismatch = true
    let session1 = storage.create_session("myrepo").await.unwrap();
    let stream1 = make_test_stream(vec![Bytes::from_static(b"REAL_BYTES_1")]);
    storage
        .append_if_offset(
            &session1,
            UploadOffsetPrecondition::Exact(0),
            stream1,
            1024 * 1024,
        )
        .await
        .unwrap();

    let wrong_digest =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();

    let err1 = storage
        .begin_finalize(
            &session1,
            UploadOffsetPrecondition::Exact(12),
            None,
            &wrong_digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap_err();
    assert!(matches!(err1, UploadTransitionError::DigestMismatch { .. }));

    // Staging files cleaned up
    let data1 = storage.session_data_path(&session1.uuid);
    assert!(!tokio::fs::try_exists(&data1).await.unwrap());

    // 2. abort_on_digest_mismatch = false
    let session2 = storage.create_session("myrepo").await.unwrap();
    let stream2 = make_test_stream(vec![Bytes::from_static(b"REAL_BYTES_2")]);
    storage
        .append_if_offset(
            &session2,
            UploadOffsetPrecondition::Exact(0),
            stream2,
            1024 * 1024,
        )
        .await
        .unwrap();

    let err2 = storage
        .begin_finalize(
            &session2,
            UploadOffsetPrecondition::Exact(12),
            None,
            &wrong_digest,
            1024 * 1024,
            false,
        )
        .await
        .unwrap_err();
    assert!(matches!(err2, UploadTransitionError::DigestMismatch { .. }));

    // Staging files retained
    let data2 = storage.session_data_path(&session2.uuid);
    assert!(tokio::fs::try_exists(&data2).await.unwrap());
}

#[tokio::test]
async fn test_fs_session_sha512_finalization() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let session = storage.create_session("myrepo").await.unwrap();
    let data = b"SHA512_STREAMING_FINALIZATION_PAYLOAD";
    let stream = make_test_stream(vec![Bytes::from_static(data)]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    let mut hasher = sha2::Sha512::new();
    hasher.update(data);
    let digest_hex = hex::encode(hasher.finalize());
    let digest = Digest::parse(&format!("sha512:{digest_hex}")).unwrap();

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap();

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: data.len() as u64
        })
    );
}

#[tokio::test]
async fn test_fs_session_restart_resume_finalize_restart_receipt() {
    let root = tmp_fs_root();
    let repo = "restart/repo";
    let chunk1 = b"first chunk before restart;";
    let chunk2 = b" second chunk after restart.";
    let mut full = chunk1.to_vec();
    full.extend_from_slice(chunk2);
    let digest = Digest::parse(&format!("sha256:{}", hex_sha256(&full))).unwrap();

    // 1. Initial process: create session & append chunk 1
    let storage1 = FsStorage::new(root.clone(), 1024 * 1024);
    let session = storage1.create_session(repo).await.unwrap();
    let stream1 = make_test_stream(vec![Bytes::from_static(chunk1)]);
    let app1 = storage1
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream1,
            1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        app1,
        UploadAppendResult::Committed {
            new_offset: chunk1.len() as u64
        }
    );
    drop(storage1);

    // 2. Second process (simulated restart): resume session & append chunk 2 & finalize
    let storage2 = FsStorage::new(root.clone(), 1024 * 1024);
    let status2 = storage2.session_status(&session).await.unwrap();
    assert_eq!(status2.committed_offset, chunk1.len() as u64);
    assert_eq!(status2.state, UploadSessionState::Active);

    let stream2 = make_test_stream(vec![Bytes::from_static(chunk2)]);
    let app2 = storage2
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(chunk1.len() as u64),
            stream2,
            1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        app2,
        UploadAppendResult::Committed {
            new_offset: full.len() as u64
        }
    );

    let prepared = storage2
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(full.len() as u64),
            None,
            &digest,
            1024 * 1024,
            false,
        )
        .await
        .unwrap();
    let outcome = storage2.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: full.len() as u64
        })
    );
    drop(storage2);

    // 3. Third process (second restart): retrieve receipt
    let storage3 = FsStorage::new(root.clone(), 1024 * 1024);
    let receipt = storage3
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .expect("receipt exists");
    assert_eq!(receipt.repo.as_str(), repo);
    assert_eq!(receipt.uuid, session.uuid);
    assert_eq!(receipt.digest, digest.as_str());
    assert_eq!(receipt.size, full.len() as u64);

    // Verify canonical files exist
    let receipt_file = storage3.finalized_receipt_path(&session.uuid);
    assert!(tokio::fs::try_exists(&receipt_file).await.unwrap());
    let blob_file = storage3.blob_path(&digest);
    assert!(tokio::fs::try_exists(&blob_file).await.unwrap());
}

#[tokio::test]
async fn test_fs_legacy_fixture_migration() {
    let root = tmp_fs_root();
    let uploads_dir = root.join("uploads");
    tokio::fs::create_dir_all(&uploads_dir).await.unwrap();

    let legacy_uuid = uuid::Uuid::new_v4().to_string();
    let legacy_data = b"LEGACY_UPLOAD_FIXTURE_PAYLOAD";

    // Write raw legacy flat file at uploads/<uuid>
    let legacy_file = uploads_dir.join(&legacy_uuid);
    tokio::fs::write(&legacy_file, legacy_data).await.unwrap();

    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let session = UploadSessionId::new(
        crate::registry::canonical_name::CanonicalRepoName::parse("legacy/repo").unwrap(),
        &legacy_uuid,
    );

    // First access via session_status triggers migration
    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, legacy_data.len() as u64);
    assert_eq!(status.state, UploadSessionState::Active);

    // Verify canonical layout exists
    let data_path = storage.session_data_path(&legacy_uuid);
    let meta_path = storage.session_meta_path(&legacy_uuid);
    let hash_path = storage.session_hash_path(&legacy_uuid, 0);

    assert!(tokio::fs::try_exists(&data_path).await.unwrap());
    assert!(tokio::fs::try_exists(&meta_path).await.unwrap());
    assert!(tokio::fs::try_exists(&hash_path).await.unwrap());
    assert!(!tokio::fs::try_exists(&legacy_file).await.unwrap());

    // Finalize the migrated session
    let digest = Digest::parse(&format!("sha256:{}", hex_sha256(legacy_data))).unwrap();
    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(legacy_data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            false,
        )
        .await
        .unwrap();
    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: legacy_data.len() as u64
        })
    );
}

#[tokio::test]
async fn test_storage_try_from_config_invalid_path_fails_cleanly() {
    let temp_dir = tempfile::tempdir().unwrap();
    // Create a regular file at the target root path to make directory creation fail
    let file_path = temp_dir.path().join("existing_file");
    std::fs::write(&file_path, b"not a directory").unwrap();
    let invalid_root = file_path.join("sub_dir");

    let res = FsStorage::try_new(invalid_root.clone(), 1024 * 1024);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io)
    );
    let err_msg = err.to_string();
    assert!(err_msg.contains(&invalid_root.display().to_string()));
    assert!(err_msg.contains("failed to create storage dir"));
}

#[tokio::test]
async fn test_fs_membership_record_round_trip_and_lifecycle() {
    use crate::storage::repo_membership::{
        MembershipProvenance, MembershipState, RepoBlobMembershipRecord,
        RepositoryBlobMembershipStorage,
    };
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let repo = "my-test-repo";
    let d1 =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
    let d2 =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000002")
            .unwrap();

    let canonical_repo = crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap();
    let canonical_source =
        crate::registry::canonical_name::CanonicalRepoName::parse("source-repo").unwrap();

    let r_upload = RepoBlobMembershipRecord::new_upload(
        canonical_repo.clone(),
        d1.clone(),
        Some("sess-1".to_string()),
    );
    let r_cross = RepoBlobMembershipRecord::new_cross_mount(
        canonical_repo.clone(),
        d2.clone(),
        canonical_source.clone(),
    );

    storage.link_repo_blob(&r_upload).await.unwrap();
    storage.link_repo_blob(&r_cross).await.unwrap();

    let fetched1 = storage
        .get_repo_blob_membership(repo, &d1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched1.provenance, MembershipProvenance::Upload);
    assert_eq!(fetched1.session_id, Some("sess-1".to_string()));
    assert_eq!(fetched1.state, MembershipState::Active);

    let fetched2 = storage
        .get_repo_blob_membership(repo, &d2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        fetched2.provenance,
        MembershipProvenance::CrossMount {
            from_repo: canonical_source
        }
    );

    // Candidate aging transition
    storage
        .set_membership_candidate(repo, &d1, 1000)
        .await
        .unwrap();
    let cand = storage
        .get_repo_blob_membership(repo, &d1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cand.state, MembershipState::Candidate);
    assert_eq!(cand.unreferenced_since_unix_secs, Some(1000));

    // Candidate clearing transition
    storage.clear_membership_candidate(repo, &d1).await.unwrap();
    let active = storage
        .get_repo_blob_membership(repo, &d1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.state, MembershipState::Active);
    assert_eq!(active.unreferenced_since_unix_secs, None);

    // Pagination
    let (page, next_tok) = storage
        .list_repo_blob_memberships_page(repo, None, 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert!(next_tok.is_some());
    let (page2, next_tok2) = storage
        .list_repo_blob_memberships_page(repo, next_tok.as_deref(), 1)
        .await
        .unwrap();
    assert_eq!(page2.len(), 1);
    assert!(next_tok2.is_none());

    // Unlink
    assert!(storage.unlink_repo_blob(repo, &d1).await.unwrap());
    assert!(!storage.unlink_repo_blob(repo, &d1).await.unwrap());
    assert!(
        storage
            .get_repo_blob_membership(repo, &d1)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_fs_cas_enumeration_fails_closed_on_malformed_prefix_dir() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Put an invalid file directly in blobs/sha256/
    let invalid_file = root.join("blobs").join("sha256").join("not_a_dir.txt");
    tokio::fs::create_dir_all(invalid_file.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&invalid_file, b"corrupted").await.unwrap();

    let res = storage.list_cas_blobs_page(None, 100).await;
    assert!(
        res.is_err(),
        "enumeration must fail closed on non-dir prefix"
    );
    assert_eq!(
        res.unwrap_err().internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
}

#[tokio::test]
async fn test_fs_cas_enumeration_fails_closed_on_malformed_blob_file() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Put an invalid file name in blobs/sha256/ab/
    let invalid_blob = root
        .join("blobs")
        .join("sha256")
        .join("ab")
        .join("short_hex");
    tokio::fs::create_dir_all(invalid_blob.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&invalid_blob, b"corrupted").await.unwrap();

    let res = storage.list_cas_blobs_page(None, 100).await;
    assert!(
        res.is_err(),
        "enumeration must fail closed on malformed hex filename"
    );
    assert_eq!(
        res.unwrap_err().internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
}

#[tokio::test]
async fn test_atomic_write_file_invalid_path_invariant() {
    let res = atomic_write_file(Path::new(""), b"test-payload").await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::InternalInvariant),
        "atomic_write_file with path having no parent must return StorageErrorKind::InternalInvariant"
    );
    assert_eq!(err.message(), Some("invalid path"));
    assert_eq!(err.to_string(), "internal error: invalid path");
}

#[tokio::test]
async fn test_detect_manifest_media_type_malformed_json_is_corrupt_data() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root, 1024 * 1024);

    let malformed_bytes = b"{{{ malformed JSON";
    let expected_err = serde_json::from_slice::<serde_json::Value>(malformed_bytes).unwrap_err();
    let expected_message = expected_err.to_string();

    let _ = &storage;
    let res = crate::storage::manifest_domain::detect_manifest_media_type(malformed_bytes);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Malformed manifest JSON in detect_manifest_media_type must classify as CorruptData"
    );

    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_repository_enumeration_io_failure_is_io() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Create a regular file at the 'repos' path so contained enumeration fails
    // with NotADirectory (deterministic, root-safe)
    let repos_path = root.join("repos");
    std::fs::write(&repos_path, b"not a directory").unwrap();

    let res = storage.list_repositories().await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io),
        "wrong-type repos root must keep the legacy StorageErrorKind::Io classification"
    );

    let expected_message = "target path is not a directory: repos";
    assert_eq!(err.message(), Some(expected_message));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_get_upload_session_malformed_json_is_corrupt_data() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let canonical_repo =
        crate::registry::canonical_name::CanonicalRepoName::parse("testrepo").unwrap();
    let uuid = uuid::Uuid::new_v4().to_string();
    let session = UploadSessionId::new(canonical_repo, &uuid);

    // Ensure uploads directory exists and write malformed session metadata JSON
    let uploads_dir = storage.uploads_dir();
    std::fs::create_dir_all(&uploads_dir).unwrap();
    let meta_path = storage.session_meta_path(&session.uuid);
    let malformed_bytes = b"{{{ malformed session json";
    std::fs::write(&meta_path, malformed_bytes).unwrap();

    let expected_err = serde_json::from_slice::<FsSessionMetaRecord>(malformed_bytes).unwrap_err();
    let expected_message = expected_err.to_string();

    let res = storage.session_status(&session).await;
    match res {
        Err(UploadTransitionError::Storage(err)) => {
            assert_eq!(
                err.internal_kind(),
                Some(crate::storage::StorageErrorKind::CorruptData),
                "Malformed session metadata in session_status must classify as CorruptData"
            );
            assert_eq!(err.message(), Some(expected_message.as_str()));
            assert_eq!(
                err.to_string(),
                format!("internal error: {expected_message}")
            );
        }
        other => panic!("expected UploadTransitionError::Storage with CorruptData, got {other:?}"),
    }
}

#[tokio::test]
async fn test_upload_session_mutation_malformed_json_is_corrupt_data() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let canonical_repo =
        crate::registry::canonical_name::CanonicalRepoName::parse("testrepo").unwrap();
    let uuid = uuid::Uuid::new_v4().to_string();
    let session = UploadSessionId::new(canonical_repo, &uuid);

    // Ensure uploads directory exists and write malformed session metadata JSON
    let uploads_dir = storage.uploads_dir();
    std::fs::create_dir_all(&uploads_dir).unwrap();
    let meta_path = storage.session_meta_path(&session.uuid);
    let malformed_bytes = b"{{{ malformed mutation session json";
    std::fs::write(&meta_path, malformed_bytes).unwrap();

    let expected_err = serde_json::from_slice::<FsSessionMetaRecord>(malformed_bytes).unwrap_err();
    let expected_message = expected_err.to_string();

    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![]),
            1024 * 1024,
        )
        .await;

    match res {
        Err(UploadTransitionError::Storage(err)) => {
            assert_eq!(
                err.internal_kind(),
                Some(crate::storage::StorageErrorKind::CorruptData),
                "Malformed session metadata in append_if_offset must classify as CorruptData"
            );
            assert_eq!(err.message(), Some(expected_message.as_str()));
            assert_eq!(
                err.to_string(),
                format!("internal error: {expected_message}")
            );
        }
        other => panic!("expected UploadTransitionError::Storage with CorruptData, got {other:?}"),
    }
}

#[tokio::test]
async fn test_begin_finalize_malformed_json_is_corrupt_data() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let canonical_repo =
        crate::registry::canonical_name::CanonicalRepoName::parse("testrepo").unwrap();
    let uuid = uuid::Uuid::new_v4().to_string();
    let session = UploadSessionId::new(canonical_repo, &uuid);

    // Ensure uploads directory exists and write malformed session metadata JSON
    let uploads_dir = storage.uploads_dir();
    std::fs::create_dir_all(&uploads_dir).unwrap();
    let meta_path = storage.session_meta_path(&session.uuid);
    let malformed_bytes = b"{{{ malformed finalize session json";
    std::fs::write(&meta_path, malformed_bytes).unwrap();

    let expected_err = serde_json::from_slice::<FsSessionMetaRecord>(malformed_bytes).unwrap_err();
    let expected_message = expected_err.to_string();

    let digest =
        Digest::parse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();

    let res = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(0),
            None,
            &digest,
            1024 * 1024,
            false,
        )
        .await;

    match res {
        Err(UploadTransitionError::Storage(err)) => {
            assert_eq!(
                err.internal_kind(),
                Some(crate::storage::StorageErrorKind::CorruptData),
                "Malformed session metadata in begin_finalize must classify as CorruptData"
            );
            assert_eq!(err.message(), Some(expected_message.as_str()));
            assert_eq!(
                err.to_string(),
                format!("internal error: {expected_message}")
            );
        }
        other => panic!("expected UploadTransitionError::Storage with CorruptData, got {other:?}"),
    }
}

#[tokio::test]
async fn test_commit_finalize_malformed_json_is_corrupt_data() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let canonical_repo =
        crate::registry::canonical_name::CanonicalRepoName::parse("testrepo").unwrap();
    let uuid = uuid::Uuid::new_v4().to_string();
    let session = UploadSessionId::new(canonical_repo, &uuid);

    // Ensure uploads directory exists and write malformed session metadata JSON
    let uploads_dir = storage.uploads_dir();
    std::fs::create_dir_all(&uploads_dir).unwrap();
    let meta_path = storage.session_meta_path(&session.uuid);
    let malformed_bytes = b"{{{ malformed commit finalize session json";
    std::fs::write(&meta_path, malformed_bytes).unwrap();

    let expected_err = serde_json::from_slice::<FsSessionMetaRecord>(malformed_bytes).unwrap_err();
    let expected_message = expected_err.to_string();

    let digest =
        Digest::parse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();

    let prepared = crate::storage::upload_session::PreparedFinalize {
        session,
        operation_id: "op-test-123".to_string(),
        expected_digest: digest,
        committed_offset: 0,
        size: 0,
    };

    let res = storage.commit_finalize(&prepared).await;

    match res {
        Err(UploadTransitionError::Storage(err)) => {
            assert_eq!(
                err.internal_kind(),
                Some(crate::storage::StorageErrorKind::CorruptData),
                "Malformed session metadata in commit_finalize must classify as CorruptData"
            );
            assert_eq!(err.message(), Some(expected_message.as_str()));
            assert_eq!(
                err.to_string(),
                format!("internal error: {expected_message}")
            );
        }
        other => panic!("expected UploadTransitionError::Storage with CorruptData, got {other:?}"),
    }
}

#[tokio::test]
async fn test_get_finalized_receipt_malformed_json_is_corrupt_data() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let canonical_repo =
        crate::registry::canonical_name::CanonicalRepoName::parse("testrepo").unwrap();
    let uuid = uuid::Uuid::new_v4().to_string();
    let session = UploadSessionId::new(canonical_repo, &uuid);

    // Ensure finalized directory exists and write malformed receipt JSON
    let finalized_dir = storage.finalized_dir();
    std::fs::create_dir_all(&finalized_dir).unwrap();
    let receipt_path = storage.finalized_receipt_path(&session.uuid);
    let malformed_bytes = b"{{{ malformed receipt json";
    std::fs::write(&receipt_path, malformed_bytes).unwrap();

    let expected_err = serde_json::from_slice::<FinalizedReceipt>(malformed_bytes).unwrap_err();
    let expected_message = expected_err.to_string();

    let res = storage.get_finalized_receipt(&session).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Malformed finalized receipt JSON must classify as CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_get_repo_blob_membership_malformed_json_is_corrupt_data() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let canonical = CanonicalRepoName::parse("testrepo").unwrap();
    let digest =
        Digest::parse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();

    let path = root.join(
        crate::storage::repo_membership::canonical_repo_membership_relpath(&canonical, &digest),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let malformed_bytes = b"{{{ malformed membership json";
    std::fs::write(&path, malformed_bytes).unwrap();

    let expected_err = serde_json::from_slice::<
        crate::storage::repo_membership::RepoBlobMembershipRecord,
    >(malformed_bytes)
    .unwrap_err();
    // Contained reads report the storage-relative object key, not an ambient
    // absolute path.
    let expected_message = format!(
        "corrupt membership record in {}: {expected_err}",
        crate::storage::repo_membership::canonical_repo_membership_relpath(&canonical, &digest)
    );

    let res = storage.get_repo_blob_membership("testrepo", &digest).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Malformed repo blob membership JSON must classify as CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_set_membership_candidate_malformed_json_is_corrupt_data() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let canonical = CanonicalRepoName::parse("testrepo").unwrap();
    let digest =
        Digest::parse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();

    let path = root.join(
        crate::storage::repo_membership::canonical_repo_membership_relpath(&canonical, &digest),
    );
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    let malformed_bytes = b"{{{ malformed candidate membership json";
    std::fs::write(&path, malformed_bytes).unwrap();

    let expected_err = serde_json::from_slice::<
        crate::storage::repo_membership::RepoBlobMembershipRecord,
    >(malformed_bytes)
    .unwrap_err();
    let expected_message = format!("corrupt membership record: {expected_err}");

    let res = storage
        .set_membership_candidate("testrepo", &digest, 12345)
        .await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Malformed candidate membership JSON must classify as CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_list_all_repo_blob_memberships_page_corrupt_repo_dir_is_corrupt_data() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let invalid_repo_encoded = "invalid!!repo++name";
    let repo_dir = root
        .join("repo-memberships")
        .join("by-repo")
        .join(invalid_repo_encoded);
    std::fs::create_dir_all(&repo_dir).unwrap();

    let expected_err =
        crate::storage::repo_membership::decode_canonical_repo_key(invalid_repo_encoded)
            .unwrap_err();
    let expected_message =
        format!("corrupt repository membership directory '{invalid_repo_encoded}': {expected_err}");

    let res = storage.list_all_repo_blob_memberships_page(None, 10).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Corrupt repository membership directory name must classify as CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_list_repo_blob_memberships_page_nonregular_json_candidate_fails_closed() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let canonical = CanonicalRepoName::parse("testrepo").unwrap();
    let encoded_repo = crate::storage::repo_membership::encode_canonical_repo_key(&canonical);
    let algo_dir = root
        .join("repo-memberships")
        .join("by-repo")
        .join(encoded_repo)
        .join("sha256");

    // Create a directory instead of a regular file at a name-qualifying
    // record path. Under the contained implementation this is an explicit
    // failure: a nonregular object at a membership-record name must never be
    // silently omitted from an authoritative page (unsafe for ledger
    // reconciliation) and is rejected from dirent evidence without being
    // opened. The legacy ambient listing surfaced an OS I/O error only when
    // the entry was selected into the page (and silently followed symlinks).
    let cand_path =
        algo_dir.join("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.json");
    std::fs::create_dir_all(&cand_path).unwrap();

    let err = storage
        .list_repo_blob_memberships_page("testrepo", None, 10)
        .await
        .expect_err("a nonregular name-qualifying candidate must fail the page closed");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "nonregular record candidates classify as CorruptData"
    );
}

#[tokio::test]
async fn test_get_migration_checkpoint_malformed_json_is_corrupt_data() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let meta_dir = root.join("meta");
    std::fs::create_dir_all(&meta_dir).unwrap();
    let cp_path = meta_dir.join("migration_checkpoint.json");
    let malformed_bytes = b"{{{ malformed migration checkpoint json";
    std::fs::write(&cp_path, malformed_bytes).unwrap();

    let expected_err = serde_json::from_slice::<
        crate::storage::repo_membership::MigrationCheckpointRecord,
    >(malformed_bytes)
    .unwrap_err();
    let expected_message = format!("corrupt migration checkpoint: {expected_err}");

    let res = storage.get_migration_checkpoint().await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Malformed migration checkpoint JSON must classify as CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_list_cas_blobs_for_gc_malformed_prefix_is_corrupt_data() {
    use crate::storage::GcStorage;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let invalid_prefix_name = "invalid_prefix_name";
    let invalid_prefix = root.join("blobs").join("sha256").join(invalid_prefix_name);
    std::fs::create_dir_all(&invalid_prefix).unwrap();

    let expected_message =
        format!("malformed 2-char prefix directory name in CAS root: {invalid_prefix_name}");

    let res = storage.list_cas_blobs_page(None, 10).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Malformed 2-char prefix directory name in CAS root must classify as CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_list_cas_blobs_for_gc_malformed_blob_filename_is_corrupt_data() {
    use crate::storage::GcStorage;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let shard_name = "e3";
    let shard_dir = root.join("blobs").join("sha256").join(shard_name);
    std::fs::create_dir_all(&shard_dir).unwrap();

    let invalid_filename = "not_a_valid_64_char_hex_hash.bin";
    let invalid_file = shard_dir.join(invalid_filename);
    std::fs::write(&invalid_file, b"test content").unwrap();

    // Contained listing identifies the shard by its 2-char prefix rather than host path
    let expected_message =
        format!("malformed blob file name in CAS shard {shard_name}: {invalid_filename}");

    let res = storage.list_cas_blobs_page(None, 10).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Malformed blob filename in CAS shard must classify as CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_blocking_task_join_error_is_internal_invariant() {
    let join_handle = tokio::task::spawn_blocking(|| {
        panic!("deliberate worker panic for join error test");
    });
    let join_res = join_handle.await;
    assert!(join_res.is_err(), "deliberate panic must yield JoinError");
    let join_err = join_res.unwrap_err();
    let expected_message = join_err.to_string();

    let err = map_blocking_join_error(join_err);
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::InternalInvariant)
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_list_cas_blobs_for_gc_non_directory_root_is_corrupt_data() {
    use crate::storage::GcStorage;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let blobs_dir = root.join("blobs");
    std::fs::create_dir_all(&blobs_dir).unwrap();
    let cas_root_file = blobs_dir.join("sha256");
    std::fs::write(&cas_root_file, b"not a directory").unwrap();

    // Under the approved cutover, an intermediate or final non-directory component
    // maps to StorageErrorKind::CorruptData rather than legacy generic Io.
    let expected_message = "target path is not a directory: Some(\"blobs/sha256\")";

    let res = storage.list_cas_blobs_page(None, 10).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "Non-directory CAS root component must classify as CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_delete_blob_conditional_missing_version_precondition_is_conflict() {
    use crate::storage::GcStorage;
    use crate::storage::mutation_authority::RuntimeMutationAuthority;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let authority = RuntimeMutationAuthority::acquire(
        Arc::new(FsStorage::new(root.clone(), 1024 * 1024)),
        "test-gc-node",
    )
    .await
    .expect("acquire mutation authority");
    let permit = authority.gc_mutation_permit();
    let digest =
        Digest::parse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .expect("valid digest");

    let expected_message = "conditional delete on filesystem storage requires expected version";
    let res = storage
        .delete_blob_conditional(&permit, &digest, None)
        .await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Conflict),
        "Missing version precondition must classify as Conflict"
    );
    assert_eq!(err.message(), Some(expected_message));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_quarantine_blob_invalid_permit_is_permission_denied() {
    use crate::storage::GcStorage;
    use crate::storage::mutation_authority::RuntimeMutationAuthority;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let authority = RuntimeMutationAuthority::acquire(
        Arc::new(FsStorage::new(root.clone(), 1024 * 1024)),
        "test-gc-node",
    )
    .await
    .expect("acquire mutation authority");
    let permit = authority.gc_mutation_permit();
    let _guard = authority.set_test_inactive_guard();
    assert!(!permit.is_valid());

    let digest =
        Digest::parse("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .expect("valid digest");
    let version = BlobObjectVersion("fs:0:0:dummy".to_string());

    let expected_message = "invalid or inactive GC mutation permit";
    let res = storage.quarantine_blob(&permit, &digest, &version).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied),
        "Invalid permit must classify as PermissionDenied"
    );
    assert_eq!(err.message(), Some(expected_message));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_fs_metadata_size_sparse_file_preserves_exact_size_above_u32() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 10 * 1024 * 1024 * 1024);

    let hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let digest = Digest::parse(&format!("sha256:{hex}")).unwrap();
    let path = storage.blob_path(&digest);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }

    let expected_size: u64 = 8_589_934_592; // 8 GiB (> 4 GiB u32 boundary)
    let file = std::fs::File::create(&path).expect("create sparse file");
    file.set_len(expected_size).expect("set sparse file length");

    // Test the low-level mechanism directly
    let size = fs_metadata_size(&path)
        .await
        .expect("fs_metadata_size must succeed");
    assert_eq!(size, expected_size);

    // Test delegation through head_blob
    let meta = storage
        .head_blob(&digest)
        .await
        .expect("head_blob must succeed");
    assert_eq!(meta.size, expected_size);

    let _ = std::fs::remove_dir_all(&root);
}

#[cfg(unix)]
struct PermGuard<'a>(&'a Path);

#[cfg(unix)]
impl<'a> Drop for PermGuard<'a> {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
    }
}

#[tokio::test]
async fn test_fs_metadata_size_deterministic_typed_io_errors() {
    let root = tmp_fs_root();

    // 1. NotFound case: nonexistent path returns typed NotFound
    let missing_path = root.join("nonexistent_blob.bin");
    let err_not_found = fs_metadata_size(&missing_path)
        .await
        .expect_err("nonexistent file must fail");
    assert_eq!(err_not_found.kind(), std::io::ErrorKind::NotFound);

    // 2. Intermediate regular file component: non-NotFound typed I/O error
    let intermediate_file = root.join("intermediate_regular_file.bin");
    std::fs::write(&intermediate_file, b"content").expect("write intermediate regular file");
    let child_path = intermediate_file.join("sub_item");
    let err_not_dir = fs_metadata_size(&child_path)
        .await
        .expect_err("metadata lookup through regular file must fail");
    assert_ne!(
        err_not_dir.kind(),
        std::io::ErrorKind::NotFound,
        "Intermediate regular file must yield a non-NotFound I/O error"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[cfg(unix)]
#[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
async fn test_fs_metadata_size_environment_permission_denied() {
    use std::os::unix::fs::PermissionsExt;
    let root = tmp_fs_root();
    let restricted_dir = root.join("restricted_dir");
    std::fs::create_dir_all(&restricted_dir).expect("create restricted dir");
    let inaccessible_path = restricted_dir.join("inaccessible.bin");
    std::fs::write(&inaccessible_path, b"secret").expect("write test file");

    {
        let _guard = PermGuard(&restricted_dir);
        std::fs::set_permissions(&restricted_dir, std::fs::Permissions::from_mode(0o000))
            .expect("set permissions 0o000");

        let err_perm = fs_metadata_size(&inaccessible_path)
            .await
            .expect_err("metadata query on inaccessible path must fail");
        assert_eq!(err_perm.kind(), std::io::ErrorKind::PermissionDenied);
    }

    std::fs::remove_dir_all(&root).expect("cleanup test temp directory");
}

#[tokio::test]
async fn test_head_blob_ordinary_wins_over_quarantine() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
            .unwrap();
    let live_content = b"live payload";
    let quarantine_content = b"quarantine payload is different length";

    write_file(&storage.blob_path(&digest), live_content);
    write_file(&storage.quarantine_blob_path(&digest), quarantine_content);

    let meta = storage
        .head_blob(&digest)
        .await
        .expect("head_blob must succeed");
    assert_eq!(meta.size, live_content.len() as u64);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_head_blob_quarantine_only_and_both_missing_baselines() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest_quarantine =
        Digest::parse("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    let quarantine_content = b"quarantined content";
    write_file(
        &storage.quarantine_blob_path(&digest_quarantine),
        quarantine_content,
    );

    // Quarantine-only succeeds
    let meta = storage
        .head_blob(&digest_quarantine)
        .await
        .expect("head_blob must fall back to quarantine");
    assert_eq!(meta.size, quarantine_content.len() as u64);

    // Both missing returns StorageError::NotFound
    let digest_missing =
        Digest::parse("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();
    let res = storage.head_blob(&digest_missing).await;
    assert!(matches!(res, Err(StorageError::NotFound)));

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn test_head_blob_deterministic_non_not_found_suppresses_quarantine_and_preserves_error() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
            .unwrap();

    // Quarantine blob exists
    let quarantine_content = b"quarantine blob exists";
    write_file(&storage.quarantine_blob_path(&digest), quarantine_content);

    // Live blob path is: <root>/blobs/<prefix>/<hex_rest>
    // Create <root>/blobs/<prefix> as a regular file so directory traversal fails
    let blob_path = storage.blob_path(&digest);
    let parent = blob_path.parent().expect("blob path parent");
    if let Some(grandparent) = parent.parent() {
        std::fs::create_dir_all(grandparent).expect("create grandparent dirs");
    }
    std::fs::write(parent, b"regular file blocking directory").expect("write blocking file");

    // Capture the exact low-level I/O error from fs_metadata_size
    let expected_io_err = fs_metadata_size(&blob_path)
        .await
        .expect_err("metadata on child of regular file must fail");
    assert_ne!(expected_io_err.kind(), std::io::ErrorKind::NotFound);

    let expected_msg = expected_io_err.to_string();
    let expected_display = format!("internal error: {expected_msg}");

    let res = storage.head_blob(&digest).await;
    assert!(res.is_err(), "head_blob must fail on non-not-found error");
    let err = res.unwrap_err();

    // Outward error must remain StorageErrorKind::Io without falling back to quarantine
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io),
        "Non-NotFound error must produce StorageErrorKind::Io without falling back to quarantine"
    );
    // Compare exact diagnostic and Display string by equality against original reference
    assert_eq!(err.message(), Some(expected_msg.as_str()));
    assert_eq!(err.to_string(), expected_display);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[cfg(unix)]
#[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
async fn test_head_blob_environment_permission_denied_suppresses_quarantine() {
    use std::os::unix::fs::PermissionsExt;
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
            .unwrap();

    // Quarantine blob exists
    let quarantine_content = b"quarantine blob exists";
    write_file(&storage.quarantine_blob_path(&digest), quarantine_content);

    let blob_path = storage.blob_path(&digest);
    let parent = blob_path.parent().expect("blob path parent");
    std::fs::create_dir_all(parent).expect("create parent dirs");
    write_file(&blob_path, b"live blob");

    {
        // RAII guard ensures 0o700 is restored on drop even if an assertion panics
        let _guard = PermGuard(parent);
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o000))
            .expect("set parent permissions 0o000");

        // Capture expected I/O error directly from the low-level helper
        let expected_io_err = fs_metadata_size(&blob_path)
            .await
            .expect_err("metadata on permission-denied path must fail");
        assert_eq!(expected_io_err.kind(), std::io::ErrorKind::PermissionDenied);

        let expected_msg = expected_io_err.to_string();
        let expected_display = format!("internal error: {expected_msg}");

        let res = storage.head_blob(&digest).await;
        assert!(res.is_err(), "head_blob must fail on permission error");
        let err = res.unwrap_err();

        // Outward error must remain StorageErrorKind::Io without falling back to quarantine
        assert_eq!(
            err.internal_kind(),
            Some(crate::storage::StorageErrorKind::Io),
            "Permission error must produce StorageErrorKind::Io without falling back to quarantine"
        );
        // Compare exact diagnostic and Display string by equality against OS reference
        assert_eq!(err.message(), Some(expected_msg.as_str()));
        assert_eq!(err.to_string(), expected_display);
    }

    std::fs::remove_dir_all(&root).expect("cleanup test temp directory");
}

#[tokio::test]
async fn test_storage_error_conversion_evidence_permission_denied() {
    // Synthetic conversion evidence: verifies outward boundary conversion preserves
    // StorageErrorKind::Io and formatting for PermissionDenied without needing OS chmod.
    let synthetic_io_err = std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "synthetic permission denied for conversion verification",
    );
    let expected_msg = synthetic_io_err.to_string();
    let expected_display = format!("internal error: {expected_msg}");

    let outward_err = StorageError::io(synthetic_io_err.to_string());
    assert_eq!(
        outward_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io)
    );
    assert_eq!(outward_err.message(), Some(expected_msg.as_str()));
    assert_eq!(outward_err.to_string(), expected_display);
}

#[tokio::test]
#[cfg(unix)]
async fn test_fs_metadata_containment_symlink_inside_root() {
    // Characterizes Case 1: Final blob entry is a symlink to an ordinary file inside configured root.
    // Under accepted Policy C: symlinks below root are strictly rejected during acquisition.
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111101")
            .unwrap();
    let target_inside = root.join("blobs").join("target_inside.bin");
    let target_content = b"inside root regular file target";
    write_file(&target_inside, target_content);

    let blob_path = storage.blob_path(&digest);
    if let Some(parent) = blob_path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::os::unix::fs::symlink(&target_inside, &blob_path).expect("create inside-root symlink");

    // Legacy helper fs_metadata_size follows symlink (historical baseline preserved)
    let size = fs_metadata_size(&blob_path)
        .await
        .expect("fs_metadata_size follows inside-root symlink");
    assert_eq!(size, target_content.len() as u64);

    // Production head_blob rejects symlink under accepted containment policy
    let head_err = storage
        .head_blob(&digest)
        .await
        .expect_err("production head_blob must reject inside-root symlink under containment");
    assert_eq!(
        head_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io),
        "containment rejection must map to StorageErrorKind::Io"
    );

    // Production open_blob rejects symlink under accepted containment policy
    let open_err = expect_open_blob_err(
        &storage,
        &digest,
        "production open_blob must reject inside-root symlink under containment",
    )
    .await;
    assert_eq!(
        open_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io),
        "containment rejection must map to StorageErrorKind::Io"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn test_fs_metadata_containment_symlink_outside_root() {
    // Characterizes Case 2: Final blob entry points outside configured root but inside test fixture.
    // Under accepted Policy C: symlinks escaping root boundary are strictly rejected.
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    let outside = fixture.path().join("outside_target");
    std::fs::create_dir_all(&root).expect("create storage root");
    std::fs::create_dir_all(&outside).expect("create outside target dir");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:2222222222222222222222222222222222222222222222222222222222222202")
            .unwrap();
    let target_outside = outside.join("target_outside.bin");
    let outside_content = b"outside root regular file payload";
    write_file(&target_outside, outside_content);

    let blob_path = storage.blob_path(&digest);
    if let Some(parent) = blob_path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::os::unix::fs::symlink(&target_outside, &blob_path).expect("create outside-root symlink");

    // Legacy helper fs_metadata_size follows symlink (historical baseline preserved)
    let size = fs_metadata_size(&blob_path)
        .await
        .expect("fs_metadata_size follows outside-root symlink");
    assert_eq!(size, outside_content.len() as u64);

    // Production head_blob rejects outside-root symlink under accepted containment policy
    let head_err = storage
        .head_blob(&digest)
        .await
        .expect_err("production head_blob must reject outside-root symlink under containment");
    assert_eq!(
        head_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io)
    );

    // Production open_blob rejects outside-root symlink under accepted containment policy
    let open_err = expect_open_blob_err(
        &storage,
        &digest,
        "production open_blob must reject outside-root symlink under containment",
    )
    .await;
    assert_eq!(
        open_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io)
    );
}

#[tokio::test]
#[cfg(unix)]
async fn test_fs_metadata_containment_intermediate_dir_symlink_outside_root() {
    // Characterizes Case 3: Intermediate directory is a symlink pointing outside root.
    // Under accepted Policy C: intermediate directory symlinks are rejected during openat2 resolution.
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    let outside = fixture.path().join("outside_dir");
    std::fs::create_dir_all(&root).expect("create storage root");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:3333333333333333333333333333333333333333333333333333333333333303")
            .unwrap();
    let blob_path = storage.blob_path(&digest);
    let parent = blob_path.parent().expect("blob path parent");
    let grandparent = parent.parent().expect("blob path grandparent");
    std::fs::create_dir_all(grandparent).expect("create grandparent dirs");

    // parent is <root>/blobs/sha256/33; link it to outside
    std::os::unix::fs::symlink(&outside, parent).expect("create intermediate dir symlink");

    // Write target file in outside directory with name matching digest.hex()
    let target_file = outside.join(digest.hex());
    let content = b"intermediate directory symlink outside target";
    write_file(&target_file, content);

    // Legacy helper fs_metadata_size traverses intermediate dir symlink (historical baseline preserved)
    let size = fs_metadata_size(&blob_path)
        .await
        .expect("fs_metadata_size traverses intermediate dir symlink");
    assert_eq!(size, content.len() as u64);

    // Production head_blob rejects intermediate directory symlink
    let head_err = storage
        .head_blob(&digest)
        .await
        .expect_err("production head_blob must reject intermediate directory symlink");
    assert_eq!(
        head_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io)
    );

    // Production open_blob rejects intermediate directory symlink
    let open_err = expect_open_blob_err(
        &storage,
        &digest,
        "production open_blob must reject intermediate directory symlink",
    )
    .await;
    assert_eq!(
        open_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io)
    );
}

#[tokio::test]
#[cfg(unix)]
async fn test_fs_metadata_containment_dangling_symlink_falls_back_to_quarantine() {
    // Characterizes Case 4: Dangling ordinary blob symlink with a valid quarantine blob.
    // Under accepted Policy C: Dangling and ordinary primary symlinks suppress quarantine fallback.
    // Only genuine primary NotFound permits quarantine fallback.
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:4444444444444444444444444444444444444444444444444444444444444404")
            .unwrap();

    // Quarantine blob exists with valid content
    let quarantine_content = b"quarantine fallback for dangling symlink";
    write_file(&storage.quarantine_blob_path(&digest), quarantine_content);

    // Ordinary blob path is a dangling symlink to a non-existent file
    let blob_path = storage.blob_path(&digest);
    if let Some(parent) = blob_path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    let nonexistent_target = root.join("nonexistent_target.bin");
    std::os::unix::fs::symlink(&nonexistent_target, &blob_path).expect("create dangling symlink");

    // Direct fs_metadata_size on dangling symlink yields NotFound (historical baseline preserved)
    let io_err = fs_metadata_size(&blob_path)
        .await
        .expect_err("metadata on dangling symlink must fail");
    assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);

    // Production head_blob rejects dangling symlink via openat2 containment (ResolutionRejected),
    // strictly suppressing quarantine fallback and returning StorageErrorKind::Io.
    let head_err = storage
        .head_blob(&digest)
        .await
        .expect_err("production head_blob must suppress quarantine fallback on dangling symlink");
    assert_eq!(
        head_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io),
        "dangling symlink containment rejection must map to StorageErrorKind::Io"
    );

    // Production open_blob also suppresses quarantine fallback on dangling symlink
    let open_err = expect_open_blob_err(
        &storage,
        &digest,
        "production open_blob must suppress quarantine fallback on dangling symlink",
    )
    .await;
    assert_eq!(
        open_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io),
        "dangling symlink containment rejection must map to StorageErrorKind::Io"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn test_fs_metadata_containment_quarantine_symlink_outside_root() {
    // Characterizes Case 5: Quarantine-path symlink to target outside configured root, ordinary path absent.
    // Under accepted Policy C: Ordinary lookup fails with NotFound (permitting quarantine fallback),
    // but quarantine lookup fails containment on the symlink, returning StorageErrorKind::Io.
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    let outside = fixture.path().join("outside_quarantine");
    std::fs::create_dir_all(&root).expect("create storage root");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:5555555555555555555555555555555555555555555555555555555555555505")
            .unwrap();

    // Ordinary blob is absent (does not exist)

    // Quarantine path is a symlink pointing outside root
    let qpath = storage.quarantine_blob_path(&digest);
    if let Some(parent) = qpath.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    let target_outside = outside.join("quarantine_target.bin");
    let outside_content = b"quarantine outside root payload";
    write_file(&target_outside, outside_content);
    std::os::unix::fs::symlink(&target_outside, &qpath).expect("create quarantine symlink");

    // Legacy helper fs_metadata_size follows quarantine symlink (historical baseline preserved)
    let size = fs_metadata_size(&qpath)
        .await
        .expect("fs_metadata_size follows quarantine symlink outside root");
    assert_eq!(size, outside_content.len() as u64);

    // Production head_blob falls back to quarantine on primary NotFound, then rejects quarantine symlink
    let head_err = storage
        .head_blob(&digest)
        .await
        .expect_err("production head_blob must reject quarantine symlink");
    assert_eq!(
        head_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io)
    );

    // Production open_blob also rejects quarantine symlink
    let open_err = expect_open_blob_err(
        &storage,
        &digest,
        "production open_blob must reject quarantine symlink",
    )
    .await;
    assert_eq!(
        open_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io)
    );
}

#[tokio::test]
#[cfg(unix)]
async fn test_fs_metadata_containment_storage_root_is_symlink() {
    // Characterizes Case 6: Configured storage root itself supplied through directory symlink.
    // Behavior: FsStorage initialization succeeds and metadata lookup succeeds through symlinked root.
    // Distinguishes root configuration policy from symlinks below the established root.
    let fixture = tempfile::tempdir().expect("create test fixture");
    let real_root = fixture.path().join("real_storage_root");
    let symlink_root = fixture.path().join("symlink_storage_root");
    std::fs::create_dir_all(&real_root).expect("create real storage root");
    std::os::unix::fs::symlink(&real_root, &symlink_root).expect("create symlink storage root");

    let storage = FsStorage::try_new(symlink_root.clone(), 1024 * 1024)
        .expect("FsStorage::try_new succeeds with symlinked root");

    let digest =
        Digest::parse("sha256:6666666666666666666666666666666666666666666666666666666666666606")
            .unwrap();
    let content = b"blob stored under symlinked root";
    write_file(&storage.blob_path(&digest), content);

    let blob_path = storage.blob_path(&digest);
    let size = fs_metadata_size(&blob_path)
        .await
        .expect("fs_metadata_size succeeds through symlinked root");
    assert_eq!(size, content.len() as u64);

    let meta = storage
        .head_blob(&digest)
        .await
        .expect("head_blob succeeds through symlinked root");
    assert_eq!(meta.size, content.len() as u64);

    let (payload_meta, mut stream) = storage
        .open_blob(&digest)
        .await
        .expect("open_blob succeeds through symlinked root");
    assert_eq!(payload_meta.size, content.len() as u64);

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read stream");
    assert_eq!(buf, content);
}

#[tokio::test]
async fn test_fs_metadata_containment_directory_blob_returns_metadata_size() {
    // Characterizes Case 7: Ordinary blob path resolves to a directory rather than a regular file.
    // Under accepted Policy C: Directories and other non-regular objects fail during acquisition
    // with UnsupportedObjectType -> StorageErrorKind::Io.
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:7777777777777777777777777777777777777777777777777777777777777707")
            .unwrap();
    let blob_path = storage.blob_path(&digest);
    std::fs::create_dir_all(&blob_path).expect("create directory at blob path");

    // Legacy helper fs_metadata_size returns directory metadata length (historical baseline preserved)
    let expected_dir_size = std::fs::metadata(&blob_path)
        .expect("query directory metadata")
        .len();

    let size = fs_metadata_size(&blob_path)
        .await
        .expect("fs_metadata_size returns directory size");
    assert_eq!(size, expected_dir_size);

    // Under Policy C: Production head_blob rejects directory blob during acquisition (UnsupportedObjectType)
    let head_err = storage
        .head_blob(&digest)
        .await
        .expect_err("production head_blob must reject directory blob");
    assert_eq!(
        head_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io),
        "directory rejection must map to StorageErrorKind::Io"
    );

    // Production open_blob also rejects directory blob
    let open_err = expect_open_blob_err(
        &storage,
        &digest,
        "production open_blob must reject directory blob",
    )
    .await;
    assert_eq!(
        open_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Io),
        "directory rejection must map to StorageErrorKind::Io"
    );
}

// --------------------------------------------------------------------------------------------
// Focused Production Cutover Verification Tests (Policies A, B, and C)
// --------------------------------------------------------------------------------------------

#[tokio::test]
async fn test_production_read_cutover_head_and_open_blob_execute_extracted_path() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:8888888888888888888888888888888888888888888888888888888888888808")
            .unwrap();
    let content = b"verified payload through extracted production cutover adapter";
    write_file(&storage.blob_path(&digest), content);

    // Verify head_blob executes extracted path and returns accurate metadata
    let meta = storage
        .head_blob(&digest)
        .await
        .expect("production head_blob succeeds on regular blob file");
    assert_eq!(meta.size, content.len() as u64);

    // Verify open_blob executes extracted path and streams identical payload bytes
    let (payload_meta, mut stream) = storage
        .open_blob(&digest)
        .await
        .expect("production open_blob succeeds on regular blob file");
    assert_eq!(payload_meta.size, content.len() as u64);

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read stream");
    assert_eq!(buf, content);

    // Verify underlying read_adapter points to the configured root
    assert_eq!(storage.read_adapter().reader().root_path(), &root);
}

#[tokio::test]
async fn test_production_read_cutover_quarantine_fallback_on_primary_not_found() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:9999999999999999999999999999999999999999999999999999999999999909")
            .unwrap();
    let quarantine_content = b"quarantine payload for genuine primary not found fallback";
    write_file(&storage.quarantine_blob_path(&digest), quarantine_content);

    // Primary is absent: head_blob falls back to quarantine
    let meta = storage
        .head_blob(&digest)
        .await
        .expect("head_blob falls back to quarantine on genuine primary NotFound");
    assert_eq!(meta.size, quarantine_content.len() as u64);

    // Primary is absent: open_blob falls back to quarantine and streams payload
    let (payload_meta, mut stream) = storage
        .open_blob(&digest)
        .await
        .expect("open_blob falls back to quarantine on genuine primary NotFound");
    assert_eq!(payload_meta.size, quarantine_content.len() as u64);

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read stream");
    assert_eq!(buf, quarantine_content);

    // When both primary and quarantine are absent, returns NotFound
    let missing_digest =
        Digest::parse("sha256:9999999999999999999999999999999999999999999999999999999999999999")
            .unwrap();
    let head_missing = storage.head_blob(&missing_digest).await;
    assert!(matches!(head_missing, Err(StorageError::NotFound)));

    let open_missing = storage.open_blob(&missing_digest).await;
    assert!(matches!(open_missing, Err(StorageError::NotFound)));
}

#[tokio::test]
#[cfg(unix)]
async fn test_production_read_cutover_primary_symlinks_suppress_quarantine_fallback() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    let outside = fixture.path().join("outside_store");
    std::fs::create_dir_all(&root).expect("create storage root");
    std::fs::create_dir_all(&outside).expect("create outside store");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Case A: Ordinary symlink pointing to an existing file outside root
    let digest_symlink =
        Digest::parse("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa01")
            .unwrap();
    let outside_target = outside.join("target.bin");
    write_file(&outside_target, b"outside target payload");
    write_file(
        &storage.quarantine_blob_path(&digest_symlink),
        b"valid quarantine payload",
    );

    let blob_path_a = storage.blob_path(&digest_symlink);
    if let Some(parent) = blob_path_a.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::os::unix::fs::symlink(&outside_target, &blob_path_a).expect("create symlink");

    // Both head_blob and open_blob must reject the symlink and suppress quarantine fallback
    let head_err_a = storage
        .head_blob(&digest_symlink)
        .await
        .expect_err("head_blob must reject ordinary symlink and suppress quarantine fallback");
    assert_eq!(head_err_a.internal_kind(), Some(StorageErrorKind::Io));

    let open_err_a = expect_open_blob_err(
        &storage,
        &digest_symlink,
        "open_blob must reject ordinary symlink and suppress quarantine fallback",
    )
    .await;
    assert_eq!(open_err_a.internal_kind(), Some(StorageErrorKind::Io));

    // Case B: Dangling symlink pointing to a nonexistent file
    let digest_dangling =
        Digest::parse("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa02")
            .unwrap();
    write_file(
        &storage.quarantine_blob_path(&digest_dangling),
        b"valid quarantine payload for dangling case",
    );

    let blob_path_b = storage.blob_path(&digest_dangling);
    if let Some(parent) = blob_path_b.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    let nonexistent = root.join("nonexistent_path.bin");
    std::os::unix::fs::symlink(&nonexistent, &blob_path_b).expect("create dangling symlink");

    // Both head_blob and open_blob must reject the dangling symlink and suppress quarantine fallback
    let head_err_b = storage
        .head_blob(&digest_dangling)
        .await
        .expect_err("head_blob must reject dangling symlink and suppress quarantine fallback");
    assert_eq!(head_err_b.internal_kind(), Some(StorageErrorKind::Io));

    let open_err_b = expect_open_blob_err(
        &storage,
        &digest_dangling,
        "open_blob must reject dangling symlink and suppress quarantine fallback",
    )
    .await;
    assert_eq!(open_err_b.internal_kind(), Some(StorageErrorKind::Io));
}

#[tokio::test]
async fn test_production_read_cutover_nonregular_objects_rejected_during_acquisition() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01")
            .unwrap();
    let blob_path = storage.blob_path(&digest);
    std::fs::create_dir_all(&blob_path).expect("create directory at blob path");

    // head_blob must reject directory blob during acquisition
    let head_err = storage
        .head_blob(&digest)
        .await
        .expect_err("head_blob must reject directory at blob path");
    assert_eq!(head_err.internal_kind(), Some(StorageErrorKind::Io));
    assert!(
        head_err.to_string().contains("unsupported object type"),
        "expected unsupported object type diagnostic, got: {head_err}"
    );

    // open_blob must reject directory blob during acquisition
    let open_err = expect_open_blob_err(
        &storage,
        &digest,
        "open_blob must reject directory at blob path",
    )
    .await;
    assert_eq!(open_err.internal_kind(), Some(StorageErrorKind::Io));
    assert!(
        open_err.to_string().contains("unsupported object type"),
        "expected unsupported object type diagnostic, got: {open_err}"
    );
}

#[tokio::test]
async fn test_production_read_cutover_both_methods_share_reader_and_root_ownership() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage_root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Verify that storage owns exactly one shared FsBlobCasReadAdapter
    let adapter_a = storage.read_adapter();
    let adapter_b = storage.read_adapter();
    assert!(std::sync::Arc::ptr_eq(adapter_a, adapter_b));

    // Verify that the adapter's reader has the exact root path
    assert_eq!(adapter_a.reader().root_path(), &root);
}

#[test]
fn test_production_read_cutover_startup_error_mapping_categories_and_diagnostics() {
    use crate::storage::fs::read_adapter::map_fs_startup_error;

    // 1. PlatformUnsupported -> StorageErrorKind::Configuration
    let err = map_fs_startup_error(storage_fs::FsMetadataError::PlatformUnsupported);
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Configuration));
    assert!(err.to_string().contains("platform unsupported"));

    // 2. SyscallUnsupported -> StorageErrorKind::Configuration
    let err = map_fs_startup_error(storage_fs::FsMetadataError::SyscallUnsupported(
        std::io::Error::from_raw_os_error(libc::ENOSYS),
    ));
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Configuration));
    assert!(err.to_string().contains("openat2 is unavailable"));

    // 3. EmptyRootPath -> StorageErrorKind::Configuration
    let err = map_fs_startup_error(storage_fs::FsMetadataError::EmptyRootPath);
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Configuration));
    assert!(err.to_string().contains("cannot be empty"));

    // 4. NulInRootPath -> StorageErrorKind::Configuration
    let err = map_fs_startup_error(storage_fs::FsMetadataError::NulInRootPath);
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Configuration));
    assert!(err.to_string().contains("embedded NUL byte"));

    // 5. UnsupportedObjectType -> StorageErrorKind::Configuration
    let err = map_fs_startup_error(storage_fs::FsMetadataError::UnsupportedObjectType {
        mode: libc::S_IFREG as u32 | 0o644,
    });
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Configuration));
    assert!(err.to_string().contains("not a directory"));

    // 6. ProbeDenied -> StorageErrorKind::Backend
    let err = map_fs_startup_error(storage_fs::FsMetadataError::ProbeDenied(
        std::io::Error::from_raw_os_error(libc::EACCES),
    ));
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    assert!(err.to_string().contains("probe denied"));

    // 7. ProbeFailed -> StorageErrorKind::Backend
    let err = map_fs_startup_error(storage_fs::FsMetadataError::ProbeFailed {
        source: std::io::Error::from_raw_os_error(libc::EMFILE),
    });
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    assert!(err.to_string().contains("probe failed"));

    // 8. RootOpenFailed -> StorageErrorKind::Io
    let err = map_fs_startup_error(storage_fs::FsMetadataError::RootOpenFailed {
        source: std::io::Error::from_raw_os_error(libc::ENOENT),
    });
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
    assert!(err.to_string().contains("failed to open root directory"));

    // 9. Conservative fallback for unexpected/non-exhaustive variants -> StorageErrorKind::Backend
    let err = map_fs_startup_error(storage_fs::FsMetadataError::ResolutionRejected {
        raw_os_error: libc::ELOOP,
        source: std::io::Error::from_raw_os_error(libc::ELOOP),
    });
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    assert!(
        err.to_string()
            .contains("unexpected storage initialization failure")
    );
}

// --- CAS Blob Listing & Pagination Characterization Tests ---

fn put_cas_blob_file(root: &Path, hex: &str, content: &[u8]) {
    let p2 = &hex[0..2];
    let path = root.join("blobs").join("sha256").join(p2).join(hex);
    write_file(&path, content);
}

#[tokio::test]
async fn test_list_cas_blobs_missing_or_empty_root_returns_empty_page() {
    use crate::storage::GcStorage;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Case 1: Configured storage root exists, but CAS listing directory (blobs/sha256) is absent
    let page = storage
        .list_cas_blobs_page(None, 100)
        .await
        .expect("absent CAS listing directory returns empty page");
    assert!(page.items.is_empty());
    assert_eq!(page.next_cursor, None);

    // Case 2: blobs/sha256 exists but has no shard directories
    let cas_root = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&cas_root).expect("create cas root");
    let page = storage
        .list_cas_blobs_page(None, 100)
        .await
        .expect("empty cas root returns empty page");
    assert!(page.items.is_empty());
    assert_eq!(page.next_cursor, None);

    // Case 3: blobs/sha256 contains an empty shard directory
    let empty_shard = cas_root.join("aa");
    std::fs::create_dir_all(&empty_shard).expect("create empty shard");
    let page = storage
        .list_cas_blobs_page(None, 100)
        .await
        .expect("empty shard returns empty page");
    assert!(page.items.is_empty());
    assert_eq!(page.next_cursor, None);

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_list_cas_blobs_initial_metadata_error_not_suppressed() {
    use crate::storage::{GcStorage, StorageError, StorageErrorKind};

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Make 'blobs' a regular file so contained openat2("blobs/sha256") fails with NotADirectory (ENOTDIR)
    let blobs_file = root.join("blobs");
    std::fs::write(&blobs_file, b"not-a-directory").expect("write blobs as file");

    // Under production cutover authorization, initial non-directory errors are NO LONGER
    // suppressed into an empty page; they fail closed with StorageErrorKind::CorruptData.
    let err = storage
        .list_cas_blobs_page(None, 100)
        .await
        .expect_err("initial non-directory error must fail closed with CorruptData");
    match err {
        StorageError::Internal { kind, .. } => {
            assert_eq!(
                kind,
                StorageErrorKind::CorruptData,
                "initial NotADirectory must map to CorruptData"
            );
        }
        other => panic!("expected StorageErrorKind::CorruptData, got {other:?}"),
    }

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_list_cas_blobs_ordering_and_pagination_boundaries() {
    use crate::storage::GcStorage;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let hexes = [
        "0a00000000000000000000000000000000000000000000000000000000000001",
        "0a00000000000000000000000000000000000000000000000000000000000002",
        "1b00000000000000000000000000000000000000000000000000000000000001",
        "ff00000000000000000000000000000000000000000000000000000000000001",
        "ff00000000000000000000000000000000000000000000000000000000000002",
    ];
    for hex in &hexes {
        put_cas_blob_file(&root, hex, b"blob-payload");
    }

    // Page 1 with limit = 2
    let page1 = storage.list_cas_blobs_page(None, 2).await.expect("page 1");
    assert_eq!(page1.items.len(), 2);
    assert_eq!(page1.items[0].digest.hex(), hexes[0]);
    assert_eq!(page1.items[1].digest.hex(), hexes[1]);
    let expected_c1 = format!("sha256:{}", hexes[1]);
    assert_eq!(
        page1.next_cursor.as_ref().map(|c| c.0.as_str()),
        Some(expected_c1.as_str())
    );

    // Page 2 with cursor from Page 1 and limit = 2
    let page2 = storage
        .list_cas_blobs_page(page1.next_cursor.as_ref(), 2)
        .await
        .expect("page 2");
    assert_eq!(page2.items.len(), 2);
    assert_eq!(page2.items[0].digest.hex(), hexes[2]);
    assert_eq!(page2.items[1].digest.hex(), hexes[3]);
    let expected_c2 = format!("sha256:{}", hexes[3]);
    assert_eq!(
        page2.next_cursor.as_ref().map(|c| c.0.as_str()),
        Some(expected_c2.as_str())
    );

    // Page 3 with cursor from Page 2 and limit = 2 (final item)
    let page3 = storage
        .list_cas_blobs_page(page2.next_cursor.as_ref(), 2)
        .await
        .expect("page 3");
    assert_eq!(page3.items.len(), 1);
    assert_eq!(page3.items[0].digest.hex(), hexes[4]);
    // Since items.len() (1) < limit (2), next_cursor must be None
    assert_eq!(page3.next_cursor, None);

    // Calling with a cursor matching the final element yields an empty page and None
    let cursor_final = crate::storage::GcCursor(format!("sha256:{}", hexes[4]));
    let page_empty = storage
        .list_cas_blobs_page(Some(&cursor_final), 2)
        .await
        .expect("page empty");
    assert!(page_empty.items.is_empty());
    assert_eq!(page_empty.next_cursor, None);

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_list_cas_blobs_exact_full_final_page() {
    use crate::storage::GcStorage;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let hexes = [
        "0a00000000000000000000000000000000000000000000000000000000000001",
        "0a00000000000000000000000000000000000000000000000000000000000002",
        "1b00000000000000000000000000000000000000000000000000000000000001",
        "1b00000000000000000000000000000000000000000000000000000000000002",
    ];
    for hex in &hexes {
        put_cas_blob_file(&root, hex, b"exact-page-payload");
    }

    // Limit = 2 with exactly 4 items (2 full pages):
    // Page 1: items 0 and 1
    let page1 = storage.list_cas_blobs_page(None, 2).await.expect("page 1");
    assert_eq!(page1.items.len(), 2);
    let c1 = page1.next_cursor.expect("page 1 cursor");

    // Page 2: items 2 and 3 (exact-full final page, items.len() == limit)
    let page2 = storage
        .list_cas_blobs_page(Some(&c1), 2)
        .await
        .expect("page 2");
    assert_eq!(page2.items.len(), 2);
    assert_eq!(page2.items[0].digest.hex(), hexes[2]);
    assert_eq!(page2.items[1].digest.hex(), hexes[3]);
    // Since items.len() == limit, list_cas_blobs_page cannot know it was the final object; returns cursor:
    let c2 = page2
        .next_cursor
        .expect("exact-full page must return cursor");
    assert_eq!(c2.0, format!("sha256:{}", hexes[3]));

    // Page 3: subsequent query with c2 returns empty terminal page with next_cursor None
    let page3 = storage
        .list_cas_blobs_page(Some(&c2), 2)
        .await
        .expect("page 3 terminal");
    assert!(page3.items.is_empty(), "terminal page must be empty");
    assert_eq!(page3.next_cursor, None, "terminal page must have no cursor");

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_list_cas_blobs_limit_clamping_zero_and_large_fixture() {
    use crate::storage::GcStorage;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Populate exactly 1,001 distinct valid CAS objects across shards:
    // Shards: "00" (items 0..499), "01" (items 500..999), "02" (item 1000)
    let total_objects = 1001;
    let mut hexes = Vec::with_capacity(total_objects);
    for i in 0..total_objects {
        let p2 = format!("{:02x}", i / 500);
        let hex = format!("{}{:062x}", p2, i);
        put_cas_blob_file(&root, &hex, b"large-fixture-payload");
        hexes.push(hex);
    }
    hexes.sort();

    // 1. Zero-limit assertion: limit 0 is clamped to 1
    let page_zero = storage
        .list_cas_blobs_page(None, 0)
        .await
        .expect("limit 0 clamped to 1");
    assert_eq!(page_zero.items.len(), 1);
    assert_eq!(page_zero.items[0].digest.hex(), hexes[0]);
    assert_eq!(
        page_zero.next_cursor.as_ref().map(|c| c.0.as_str()),
        Some(format!("sha256:{}", hexes[0]).as_str())
    );

    // 2. Upper-limit assertion: request limit 50,000, clamped to 1,000
    let page1 = storage
        .list_cas_blobs_page(None, 50_000)
        .await
        .expect("request limit 50000");
    assert_eq!(
        page1.items.len(),
        1000,
        "upper limit must be clamped to exactly 1000 items"
    );
    assert_eq!(page1.items[0].digest.hex(), hexes[0]);
    assert_eq!(page1.items[999].digest.hex(), hexes[999]);
    let c1 = page1
        .next_cursor
        .expect("page 1 of large fixture must return next cursor");
    assert_eq!(c1.0, format!("sha256:{}", hexes[999]));

    // Page 2: fetches the 1,001st item
    let page2 = storage
        .list_cas_blobs_page(Some(&c1), 50_000)
        .await
        .expect("page 2 of large fixture");
    assert_eq!(
        page2.items.len(),
        1,
        "remaining item must be returned on page 2"
    );
    assert_eq!(page2.items[0].digest.hex(), hexes[1000]);
    assert_eq!(
        page2.next_cursor, None,
        "page 2 has fewer than limit items; next_cursor must be None"
    );

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_list_cas_blobs_cursor_lexical_filtering_and_malformed_values() {
    use crate::storage::GcStorage;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let hex1 = "0a00000000000000000000000000000000000000000000000000000000000001";
    let hex2 = "1b00000000000000000000000000000000000000000000000000000000000001";
    put_cas_blob_file(&root, hex1, b"item1");
    put_cas_blob_file(&root, hex2, b"item2");

    // Cursor "zzz": all valid sha256 digests are lexicographically <= "zzz", so all are skipped
    let cursor_zzz = crate::storage::GcCursor("zzz".to_string());
    let page_zzz = storage
        .list_cas_blobs_page(Some(&cursor_zzz), 10)
        .await
        .expect("cursor zzz");
    assert!(page_zzz.items.is_empty());
    assert_eq!(page_zzz.next_cursor, None);

    // Cursor "aaa": all valid sha256 digests are lexicographically > "aaa", so none are skipped
    let cursor_aaa = crate::storage::GcCursor("aaa".to_string());
    let page_aaa = storage
        .list_cas_blobs_page(Some(&cursor_aaa), 10)
        .await
        .expect("cursor aaa");
    assert_eq!(page_aaa.items.len(), 2);

    // Cursor lexicographically between item1 and item2 but malformed (non-digest string)
    let cursor_mid = crate::storage::GcCursor("sha256:0a_synthetic_middle_marker".to_string());
    let page_mid = storage
        .list_cas_blobs_page(Some(&cursor_mid), 10)
        .await
        .expect("cursor mid");
    assert_eq!(page_mid.items.len(), 1);
    assert_eq!(page_mid.items[0].digest.hex(), hex2);

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_list_cas_blobs_fails_closed_on_symlinks() {
    use crate::storage::GcStorage;
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let cas_root = root.join("blobs").join("sha256");
    std::fs::create_dir_all(&cas_root).expect("create cas root");

    // Case 1: Symlinked shard directory (e.g. blobs/sha256/2b -> target_dir)
    // DirEntry::file_type().is_dir() returns false for a symlink, triggering CorruptData
    let target_shard = fixture.path().join("external_shard");
    std::fs::create_dir_all(&target_shard).expect("create target shard");
    let link_shard = cas_root.join("2b");
    symlink(&target_shard, &link_shard).expect("create shard symlink");

    let res = storage.list_cas_blobs_page(None, 10).await;
    assert!(res.is_err(), "symlinked shard directory must fail closed");
    let err = res.unwrap_err();
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));
    assert!(
        err.to_string()
            .contains("malformed non-directory entry in CAS prefix directory root"),
        "error must report non-directory entry in CAS prefix directory root: got {err}"
    );

    // Clean up shard symlink to test file symlink inside a valid shard
    std::fs::remove_file(&link_shard).expect("remove shard symlink");

    // Case 2: Symlinked blob file inside a valid shard directory
    // DirEntry::file_type().is_file() returns false for a symlink, triggering CorruptData
    let real_shard = cas_root.join("0a");
    std::fs::create_dir_all(&real_shard).expect("create real shard");
    let target_file = fixture.path().join("target_blob.bin");
    std::fs::write(&target_file, b"symlinked blob data").expect("write target blob");
    let valid_hex_name = "0a00000000000000000000000000000000000000000000000000000000000001";
    let link_file = real_shard.join(valid_hex_name);
    symlink(&target_file, &link_file).expect("create blob symlink");

    let res = storage.list_cas_blobs_page(None, 10).await;
    assert!(res.is_err(), "symlinked blob file must fail closed");
    let err = res.unwrap_err();
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));
    assert!(
        err.to_string()
            .contains("malformed non-file entry in CAS shard directory"),
        "error must report non-file entry in CAS shard directory: got {err}"
    );

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_list_cas_blobs_fails_closed_on_nested_subdirectories_in_shard() {
    use crate::storage::GcStorage;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let shard = root.join("blobs").join("sha256").join("0a");
    let nested_subdir = shard.join("nested_subdir");
    std::fs::create_dir_all(&nested_subdir).expect("create nested subdir in shard");

    let res = storage.list_cas_blobs_page(None, 10).await;
    assert!(
        res.is_err(),
        "nested directory inside shard must fail closed"
    );
    let err = res.unwrap_err();
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::CorruptData));
    assert!(
        err.to_string()
            .contains("malformed non-file entry in CAS shard directory"),
        "nested directory in shard must be rejected as non-file entry: got {err}"
    );

    drop(storage);
    drop(fixture);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_list_cas_blobs_symlink_resolution_through_ancestor_paths() {
    use crate::storage::GcStorage;
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let hex = "0a00000000000000000000000000000000000000000000000000000000000001";

    // Case A: Configured storage root itself is a symlink pointing to another directory
    {
        let target_root = fixture.path().join("target_root_a");
        put_cas_blob_file(&target_root, hex, b"payload-root-symlink");
        let sym_root = fixture.path().join("sym_root_a");
        symlink(&target_root, &sym_root).expect("symlink storage root");

        let storage = FsStorage::new(sym_root, 1024 * 1024);
        let page = storage
            .list_cas_blobs_page(None, 10)
            .await
            .expect("listing through symlinked storage root succeeds");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].digest.hex(), hex);
        drop(storage);
    }

    // Case B: 'blobs' directory is a symlink pointing to an external directory
    // Under descriptor containment (openat2 with RESOLVE_NO_SYMLINKS), symlinks beneath
    // the root descriptor are rejected with StorageErrorKind::Io.
    {
        let root_b = fixture.path().join("root_b");
        std::fs::create_dir_all(&root_b).expect("create root_b");
        let target_blobs = fixture.path().join("target_blobs_b");
        let target_cas = target_blobs.join("sha256");
        let target_shard = target_cas.join("0a");
        std::fs::create_dir_all(&target_shard).expect("create target shard");
        std::fs::write(target_shard.join(hex), b"payload-blobs-symlink").expect("write blob");
        symlink(&target_blobs, root_b.join("blobs")).expect("symlink blobs dir");

        let storage = FsStorage::new(root_b, 1024 * 1024);
        let err = storage
            .list_cas_blobs_page(None, 10)
            .await
            .expect_err("listing through symlinked blobs dir must fail closed with Io");
        match err {
            crate::storage::StorageError::Internal { kind, .. } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Io);
            }
            other => panic!("expected StorageErrorKind::Io, got {other:?}"),
        }
        drop(storage);
    }

    // Case C: 'blobs/sha256' is a symlink pointing to an external CAS root
    // Under descriptor containment (openat2 with RESOLVE_NO_SYMLINKS), symlinks beneath
    // the root descriptor are rejected with StorageErrorKind::Io.
    {
        let root_c = fixture.path().join("root_c");
        let blobs_dir = root_c.join("blobs");
        std::fs::create_dir_all(&blobs_dir).expect("create root_c/blobs");
        let target_cas_c = fixture.path().join("target_cas_c");
        let target_shard_c = target_cas_c.join("0a");
        std::fs::create_dir_all(&target_shard_c).expect("create target shard c");
        std::fs::write(target_shard_c.join(hex), b"payload-cas-symlink").expect("write blob");
        symlink(&target_cas_c, blobs_dir.join("sha256")).expect("symlink blobs/sha256 dir");

        let storage = FsStorage::new(root_c, 1024 * 1024);
        let err = storage
            .list_cas_blobs_page(None, 10)
            .await
            .expect_err("listing through symlinked blobs/sha256 dir must fail closed with Io");
        match err {
            crate::storage::StorageError::Internal { kind, .. } => {
                assert_eq!(kind, crate::storage::StorageErrorKind::Io);
            }
            other => panic!("expected StorageErrorKind::Io, got {other:?}"),
        }
        drop(storage);
    }

    drop(fixture);
}

#[tokio::test]
async fn test_list_cas_blobs_deterministic_inter_page_mutation_no_snapshot() {
    use crate::storage::GcStorage;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let hex_0a = "0a00000000000000000000000000000000000000000000000000000000000001";
    let hex_ff = "ff00000000000000000000000000000000000000000000000000000000000001";
    put_cas_blob_file(&root, hex_0a, b"first");
    put_cas_blob_file(&root, hex_ff, b"last");

    // Fetch page 1 (limit 1): returns 0a
    let page1 = storage.list_cas_blobs_page(None, 1).await.expect("page 1");
    assert_eq!(page1.items.len(), 1);
    assert_eq!(page1.items[0].digest.hex(), hex_0a);
    let cursor1 = page1.next_cursor.expect("cursor after page 1");

    // Deterministic mutation between page calls (characterizing absence of snapshot isolation):
    // 1. Insert a blob behind the cursor (hex_01 < hex_0a)
    let hex_01 = "0100000000000000000000000000000000000000000000000000000000000001";
    put_cas_blob_file(&root, hex_01, b"behind-cursor");

    // 2. Insert a blob ahead of the cursor (hex_88 between 0a and ff)
    let hex_88 = "8800000000000000000000000000000000000000000000000000000000000001";
    put_cas_blob_file(&root, hex_88, b"ahead-of-cursor");

    // Fetch page 2 (cursor = cursor1, limit = 10):
    // hex_01 is skipped because "sha256:01..." <= "sha256:0a..." (missed by this traversal cycle)
    // hex_88 is observed because "sha256:88..." > "sha256:0a..."
    // hex_ff is observed because "sha256:ff..." > "sha256:0a..."
    let page2 = storage
        .list_cas_blobs_page(Some(&cursor1), 10)
        .await
        .expect("page 2");
    assert_eq!(page2.items.len(), 2);
    assert_eq!(page2.items[0].digest.hex(), hex_88);
    assert_eq!(page2.items[1].digest.hex(), hex_ff);

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_shared_reader_allocation_pointer_equality() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).expect("create storage root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Verify byte-for-byte that FsStorage.reader and read_adapter share the exact same Arc
    assert!(
        std::sync::Arc::ptr_eq(storage.reader(), storage.read_adapter().reader()),
        "FsStorage.reader and read_adapter must share the identical Arc<FsMetadataReader>"
    );

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_fs_storage_list_cas_blobs_page_production_delegation() {
    use crate::storage::GcStorage;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let hex = "0a00000000000000000000000000000000000000000000000000000000000001";
    put_cas_blob_file(&root, hex, b"production-delegation-payload");

    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let page = storage
        .list_cas_blobs_page(None, 10)
        .await
        .expect("production listing must succeed");
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].digest.hex(), hex);
    assert_eq!(
        page.items[0].size,
        b"production-delegation-payload".len() as u64
    );
    assert_eq!(page.next_cursor, None);

    drop(storage);
    drop(fixture);
}

#[tokio::test]
async fn test_cas_blob_traverser_over_real_fs_storage() {
    use crate::blob_gc::traverser::CasBlobTraverser;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");

    let hexes = [
        "0a00000000000000000000000000000000000000000000000000000000000001",
        "0a00000000000000000000000000000000000000000000000000000000000002",
        "0b00000000000000000000000000000000000000000000000000000000000001",
        "0c00000000000000000000000000000000000000000000000000000000000001",
        "0c00000000000000000000000000000000000000000000000000000000000002",
    ];

    for hex in &hexes {
        put_cas_blob_file(&root, hex, hex.as_bytes());
    }

    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Run CasBlobTraverser with batch size 2 over production FsStorage
    let mut traverser = CasBlobTraverser::new(&storage, 2);

    let batch1 = traverser.next_batch().await.unwrap().expect("batch 1");
    assert_eq!(batch1.len(), 2);
    assert_eq!(batch1[0].digest.hex(), hexes[0]);
    assert_eq!(batch1[1].digest.hex(), hexes[1]);

    let batch2 = traverser.next_batch().await.unwrap().expect("batch 2");
    assert_eq!(batch2.len(), 2);
    assert_eq!(batch2[0].digest.hex(), hexes[2]);
    assert_eq!(batch2[1].digest.hex(), hexes[3]);

    let batch3 = traverser.next_batch().await.unwrap().expect("batch 3");
    assert_eq!(batch3.len(), 1);
    assert_eq!(batch3[0].digest.hex(), hexes[4]);

    let batch4 = traverser.next_batch().await.unwrap();
    assert!(
        batch4.is_none(),
        "traversal must terminate at end of repository"
    );

    drop(storage);
    drop(fixture);
}

// --- Filesystem Manifest Read Characterization Tests (head_manifest & get_manifest) ---

fn put_manifest_file(root: &Path, repo: &str, hex: &str, content: &[u8]) {
    let path = root.join("repos").join(repo).join("manifests").join(hex);
    write_file(&path, content);
}

#[tokio::test]
async fn test_manifest_read_representative_valid_oci_manifest() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let repo = "testrepo";
    let manifest_bytes = br#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size": 0
        },
        "layers": []
    }"#;
    let hex = hex_sha256(manifest_bytes);
    let digest = Digest::parse(&format!("sha256:{hex}")).expect("valid digest");
    put_manifest_file(&root, repo, &hex, manifest_bytes);

    // 1. Characterize head_manifest via Storage
    let meta = storage
        .head_manifest(repo, &digest)
        .await
        .expect("head_manifest must succeed for valid manifest");
    assert_eq!(meta.size, manifest_bytes.len() as u64);
    assert_eq!(
        meta.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );

    // 2. Characterize get_manifest via Storage
    let (get_meta, payload) = storage
        .get_manifest(repo, &digest)
        .await
        .expect("get_manifest must succeed for valid manifest");
    assert_eq!(get_meta.size, manifest_bytes.len() as u64);
    assert_eq!(
        get_meta.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(get_meta, meta);
    assert_eq!(payload.as_ref(), manifest_bytes);
    assert_eq!(payload.len() as u64, get_meta.size);

    // 3. Characterize identical behavior through ManifestReader port trait
    let port_meta = <FsStorage as crate::storage::ports::ManifestReader>::head_manifest(
        &storage, repo, &digest,
    )
    .await
    .expect("ManifestReader::head_manifest must succeed");
    assert_eq!(port_meta, meta);

    let (port_get_meta, port_payload) =
        <FsStorage as crate::storage::ports::ManifestReader>::get_manifest(&storage, repo, &digest)
            .await
            .expect("ManifestReader::get_manifest must succeed");
    assert_eq!(port_get_meta, meta);
    assert_eq!(port_payload, payload);
}

#[tokio::test]
async fn test_manifest_read_media_type_detection_variants() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "testrepo";

    // Variant 1: Explicit custom mediaType string
    let custom_json =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.custom.manifest.v1+json"}"#;
    let hex1 = hex_sha256(custom_json);
    let d1 = Digest::parse(&format!("sha256:{hex1}")).expect("digest 1");
    put_manifest_file(&root, repo, &hex1, custom_json);

    let meta1 = storage.head_manifest(repo, &d1).await.unwrap();
    assert_eq!(meta1.media_type, "application/vnd.custom.manifest.v1+json");
    let (get_meta1, _) = storage.get_manifest(repo, &d1).await.unwrap();
    assert_eq!(
        get_meta1.media_type,
        "application/vnd.custom.manifest.v1+json"
    );

    // Variant 2: Missing mediaType field in valid JSON object -> falls back to OCI manifest default
    let missing_media_json = br#"{"schemaVersion": 2, "layers": []}"#;
    let hex2 = hex_sha256(missing_media_json);
    let d2 = Digest::parse(&format!("sha256:{hex2}")).expect("digest 2");
    put_manifest_file(&root, repo, &hex2, missing_media_json);

    let meta2 = storage.head_manifest(repo, &d2).await.unwrap();
    assert_eq!(
        meta2.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );
    let (get_meta2, _) = storage.get_manifest(repo, &d2).await.unwrap();
    assert_eq!(
        get_meta2.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );

    // Variant 3: Non-string mediaType value (e.g. integer 42) -> falls back to OCI default
    let non_string_json = br#"{"schemaVersion": 2, "mediaType": 42}"#;
    let hex3 = hex_sha256(non_string_json);
    let d3 = Digest::parse(&format!("sha256:{hex3}")).expect("digest 3");
    put_manifest_file(&root, repo, &hex3, non_string_json);

    let meta3 = storage.head_manifest(repo, &d3).await.unwrap();
    assert_eq!(
        meta3.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );
    let (get_meta3, _) = storage.get_manifest(repo, &d3).await.unwrap();
    assert_eq!(
        get_meta3.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );

    // Variant 4: Valid JSON but not an object (e.g. top-level string or array) -> falls back to OCI default without error
    let scalar_json = br#""just a json string""#;
    let hex4 = hex_sha256(scalar_json);
    let d4 = Digest::parse(&format!("sha256:{hex4}")).expect("digest 4");
    put_manifest_file(&root, repo, &hex4, scalar_json);

    let meta4 = storage.head_manifest(repo, &d4).await.unwrap();
    assert_eq!(
        meta4.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );
    let (get_meta4, payload4) = storage.get_manifest(repo, &d4).await.unwrap();
    assert_eq!(
        get_meta4.media_type,
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(payload4.as_ref(), scalar_json);
}

#[tokio::test]
async fn test_manifest_read_empty_and_malformed_payloads_classify_as_corrupt_data() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "testrepo";

    // Case 1: Empty file (0 bytes) -> serde_json EOF error classified as CorruptData
    let empty_bytes = b"";
    let hex_empty = hex_sha256(empty_bytes);
    let d_empty = Digest::parse(&format!("sha256:{hex_empty}")).expect("digest empty");
    put_manifest_file(&root, repo, &hex_empty, empty_bytes);

    let head_err1 = storage.head_manifest(repo, &d_empty).await.unwrap_err();
    match head_err1 {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => panic!("expected StorageErrorKind::CorruptData for empty payload, got: {other:?}"),
    }

    let get_err1 = storage.get_manifest(repo, &d_empty).await.unwrap_err();
    match get_err1 {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => panic!("expected StorageErrorKind::CorruptData for empty payload, got: {other:?}"),
    }

    // Case 2: Malformed non-JSON payload -> classified as CorruptData
    let malformed_bytes = b"<html><head><title>502 Bad Gateway</title></head></html>";
    let hex_malformed = hex_sha256(malformed_bytes);
    let d_malformed = Digest::parse(&format!("sha256:{hex_malformed}")).expect("digest malformed");
    put_manifest_file(&root, repo, &hex_malformed, malformed_bytes);

    let head_err2 = storage.head_manifest(repo, &d_malformed).await.unwrap_err();
    match head_err2 {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => {
            panic!("expected StorageErrorKind::CorruptData for malformed json, got: {other:?}")
        }
    }

    let get_err2 = storage.get_manifest(repo, &d_malformed).await.unwrap_err();
    match get_err2 {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => {
            panic!("expected StorageErrorKind::CorruptData for malformed json, got: {other:?}")
        }
    }
}

#[tokio::test]
async fn test_manifest_read_missing_paths_return_not_found() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("valid digest");

    // Case 1: Entire repository directory absent
    let err_missing_repo_head = storage
        .head_manifest("nonexistent_repo", &digest)
        .await
        .unwrap_err();
    assert!(matches!(err_missing_repo_head, StorageError::NotFound));

    let err_missing_repo_get = storage
        .get_manifest("nonexistent_repo", &digest)
        .await
        .unwrap_err();
    assert!(matches!(err_missing_repo_get, StorageError::NotFound));

    // Case 2: Repository directory exists, but manifests/ subdirectory is absent
    let repo_dir = root.join("repos").join("existing_repo");
    std::fs::create_dir_all(&repo_dir).expect("create repo dir");

    let err_missing_manifests_head = storage
        .head_manifest("existing_repo", &digest)
        .await
        .unwrap_err();
    assert!(matches!(err_missing_manifests_head, StorageError::NotFound));

    let err_missing_manifests_get = storage
        .get_manifest("existing_repo", &digest)
        .await
        .unwrap_err();
    assert!(matches!(err_missing_manifests_get, StorageError::NotFound));

    // Case 3: manifests/ directory exists, but the manifest digest file is absent
    let manifests_dir = repo_dir.join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let err_missing_file_head = storage
        .head_manifest("existing_repo", &digest)
        .await
        .unwrap_err();
    assert!(matches!(err_missing_file_head, StorageError::NotFound));

    let err_missing_file_get = storage
        .get_manifest("existing_repo", &digest)
        .await
        .unwrap_err();
    assert!(matches!(err_missing_file_get, StorageError::NotFound));
}

#[tokio::test]
async fn test_manifest_read_nondirectory_components_structural_absence() {
    // Phase 4 converged (accepted Phase 1 adapter contract): a regular file
    // occupying an intermediate component, or a directory sitting where the
    // manifest leaf should be, is NOT a manifest object — structural
    // absence (NotFound), not an Io error. Symlinks still fail closed (see
    // the containment tests).
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let digest =
        Digest::parse("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("valid digest");

    // Case 1: repository component is a regular file instead of a directory.
    let repos_dir = root.join("repos");
    std::fs::create_dir_all(&repos_dir).expect("create repos dir");
    write_file(&repos_dir.join("file_repo"), b"not a dir");
    assert!(matches!(
        storage.head_manifest("file_repo", &digest).await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        storage.get_manifest("file_repo", &digest).await,
        Err(StorageError::NotFound)
    ));

    // Case 2: manifests component is a regular file instead of a directory.
    let repo2_dir = repos_dir.join("repo_with_file_manifests");
    std::fs::create_dir_all(&repo2_dir).expect("create repo2 dir");
    write_file(&repo2_dir.join("manifests"), b"not a dir");
    assert!(matches!(
        storage
            .head_manifest("repo_with_file_manifests", &digest)
            .await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        storage
            .get_manifest("repo_with_file_manifests", &digest)
            .await,
        Err(StorageError::NotFound)
    ));

    // Case 3: target manifest path is a directory instead of a regular file.
    let repo3_manifests = repos_dir.join("repo3").join("manifests");
    std::fs::create_dir_all(repo3_manifests.join(digest.hex()))
        .expect("create dir at manifest path");
    assert!(matches!(
        storage.head_manifest("repo3", &digest).await,
        Err(StorageError::NotFound)
    ));
    assert!(matches!(
        storage.get_manifest("repo3", &digest).await,
        Err(StorageError::NotFound)
    ));
}

#[tokio::test]
async fn test_manifest_read_repository_naming_single_and_multisegment() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let manifest_bytes =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
    let hex = hex_sha256(manifest_bytes);
    let digest = Digest::parse(&format!("sha256:{hex}")).expect("valid digest");

    let test_repos = [
        "alpine",
        "library/ubuntu",
        "org/team/sub/service",
        "a/b/c/d/e",
    ];

    for repo in &test_repos {
        put_manifest_file(&root, repo, &hex, manifest_bytes);

        // Verify head_manifest and get_manifest succeed
        let head_res = storage.head_manifest(repo, &digest).await;
        assert!(
            head_res.is_ok(),
            "head_manifest failed for repo '{repo}': {head_res:?}"
        );

        let get_res = storage.get_manifest(repo, &digest).await;
        assert!(
            get_res.is_ok(),
            "get_manifest failed for repo '{repo}': {get_res:?}"
        );

        // Compare with proposed relative ObjectKey representation
        let key_str = format!("repos/{repo}/manifests/{hex}");
        let obj_key = storage_core::ObjectKey::parse(&key_str);
        assert!(
            obj_key.is_ok(),
            "ObjectKey::parse failed for '{key_str}': {obj_key:?}"
        );
        assert_eq!(obj_key.unwrap().as_str(), key_str);
    }
}

#[tokio::test]
async fn test_manifest_read_supported_digest_algorithms_and_filename_forms() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "algo_repo";

    let manifest_bytes =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;

    // 1. SHA-256 (64-char hex)
    let hex256 = hex_sha256(manifest_bytes);
    assert_eq!(hex256.len(), 64);
    let d256 = Digest::parse(&format!("sha256:{hex256}")).expect("valid sha256");
    put_manifest_file(&root, repo, &hex256, manifest_bytes);

    let head256 = storage
        .head_manifest(repo, &d256)
        .await
        .expect("head sha256");
    assert_eq!(head256.size, manifest_bytes.len() as u64);
    let (get256, _) = storage.get_manifest(repo, &d256).await.expect("get sha256");
    assert_eq!(get256.size, manifest_bytes.len() as u64);

    // 2. SHA-512 (128-char hex)
    use sha2::Digest as ShaDigest;
    let mut hasher512 = sha2::Sha512::new();
    hasher512.update(manifest_bytes);
    let hex512 = hex::encode(hasher512.finalize());
    assert_eq!(hex512.len(), 128);
    let d512 = Digest::parse(&format!("sha512:{hex512}")).expect("valid sha512");
    put_manifest_file(&root, repo, &hex512, manifest_bytes);

    let head512 = storage
        .head_manifest(repo, &d512)
        .await
        .expect("head sha512");
    assert_eq!(head512.size, manifest_bytes.len() as u64);
    let (get512, _) = storage.get_manifest(repo, &d512).await.expect("get sha512");
    assert_eq!(get512.size, manifest_bytes.len() as u64);

    // Filename form invariant: raw hex string in manifests/ directory without algorithm prefix
    let path256 = root
        .join("repos")
        .join(repo)
        .join("manifests")
        .join(&hex256);
    let path512 = root
        .join("repos")
        .join(repo)
        .join("manifests")
        .join(&hex512);
    assert!(path256.is_file());
    assert!(path512.is_file());
}

#[tokio::test]
async fn test_manifest_read_unvalidated_caller_path_traversal_gap() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let manifest_bytes =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
    let hex = hex_sha256(manifest_bytes);
    let digest = Digest::parse(&format!("sha256:{hex}")).expect("valid digest");

    // Construct a path that escapes root/repos via dot-dot traversal
    let repos_dir = root.join("repos");
    std::fs::create_dir_all(&repos_dir).expect("create repos dir");
    let escaped_target_dir = fixture.path().join("escaped_repo").join("manifests");
    std::fs::create_dir_all(&escaped_target_dir).expect("create escaped dir");
    let escaped_file = escaped_target_dir.join(&hex);
    write_file(&escaped_file, manifest_bytes);

    let traversal_repo_input = "../../escaped_repo";

    // Contained production behavior: manifest_key strictly rejects dot-dot segments with InvalidRepoName
    let head_res = storage.head_manifest(traversal_repo_input, &digest).await;
    assert!(
        matches!(head_res, Err(StorageError::InvalidRepoName(_))),
        "head_manifest must reject '..' traversal with InvalidRepoName: got {head_res:?}"
    );

    let get_res = storage.get_manifest(traversal_repo_input, &digest).await;
    assert!(
        matches!(get_res, Err(StorageError::InvalidRepoName(_))),
        "get_manifest must reject '..' traversal with InvalidRepoName: got {get_res:?}"
    );

    // Also verify that ManifestReader port forwarding rejects '..' traversal with InvalidRepoName
    let port_head_res = <FsStorage as crate::storage::ports::ManifestReader>::head_manifest(
        &storage,
        traversal_repo_input,
        &digest,
    )
    .await;
    assert!(
        matches!(port_head_res, Err(StorageError::InvalidRepoName(_))),
        "ManifestReader::head_manifest must reject '..' traversal with InvalidRepoName: got {port_head_res:?}"
    );

    let port_get_res = <FsStorage as crate::storage::ports::ManifestReader>::get_manifest(
        &storage,
        traversal_repo_input,
        &digest,
    )
    .await;
    assert!(
        matches!(port_get_res, Err(StorageError::InvalidRepoName(_))),
        "ManifestReader::get_manifest must reject '..' traversal with InvalidRepoName: got {port_get_res:?}"
    );

    // Focused production-path checks for pre-composition rejection cases:
    let unsafe_repo_inputs = &[
        ("", "empty repository name"),
        ("/leading_slash", "leading slash"),
        ("trailing_slash/", "trailing slash"),
        ("back\\slash", "backslash"),
        ("repo\0nul", "embedded NUL"),
        ("repo\x1fcontrol", "ASCII control character"),
        ("double//slash", "repeated slashes"),
        ("dot/./segment", "single dot segment"),
    ];

    for (unsafe_repo, desc) in unsafe_repo_inputs {
        let head_err = storage
            .head_manifest(unsafe_repo, &digest)
            .await
            .expect_err(&format!("head_manifest must reject {desc}"));
        assert!(
            matches!(head_err, StorageError::InvalidRepoName(_)),
            "head_manifest must return InvalidRepoName for {desc}: got {head_err:?}"
        );

        let get_err = storage
            .get_manifest(unsafe_repo, &digest)
            .await
            .expect_err(&format!("get_manifest must reject {desc}"));
        assert!(
            matches!(get_err, StorageError::InvalidRepoName(_)),
            "get_manifest must return InvalidRepoName for {desc}: got {get_err:?}"
        );
    }

    // Preserved acceptance of C:/repo on Linux:
    // When repo is "C:/repo", manifest_key composes "repos/C:/repo/manifests/<hex>".
    // On Linux, this is a valid relative path with a colon-bearing segment.
    #[cfg(target_os = "linux")]
    {
        // 1. Missing C:/repo manifests returns NotFound, proving manifest_key accepted it
        let missing_digest = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("valid digest");
        let missing_c_head = storage.head_manifest("C:/repo", &missing_digest).await;
        assert!(
            matches!(missing_c_head, Err(StorageError::NotFound)),
            "head_manifest for non-existent C:/repo must return NotFound on Linux (not InvalidRepoName): got {missing_c_head:?}"
        );

        // 2. Existing C:/repo manifest succeeds and reads content
        put_manifest_file(&root, "C:/repo", &hex, manifest_bytes);
        let c_head = storage
            .head_manifest("C:/repo", &digest)
            .await
            .expect("head_manifest for C:/repo must succeed on Linux");
        assert_eq!(c_head.size, manifest_bytes.len() as u64);
        assert_eq!(
            c_head.media_type,
            "application/vnd.oci.image.manifest.v1+json"
        );

        let (c_get_meta, c_payload) = storage
            .get_manifest("C:/repo", &digest)
            .await
            .expect("get_manifest for C:/repo must succeed on Linux");
        assert_eq!(c_get_meta, c_head);
        assert_eq!(c_payload.as_ref(), manifest_bytes);
    }
}

#[tokio::test]
#[cfg(unix)]
async fn test_manifest_read_containment_symlink_traversal() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let outside = fixture.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let repo = "symlink_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let manifest_bytes =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
    let hex = hex_sha256(manifest_bytes);
    let digest = Digest::parse(&format!("sha256:{hex}")).expect("valid digest");

    // Scenario 1: Manifest file is a symlink pointing to an outside file
    let outside_file = outside.join("external_manifest.json");
    write_file(&outside_file, manifest_bytes);
    let symlink_file = manifests_dir.join(&hex);
    symlink(&outside_file, &symlink_file).expect("create symlink to outside file");

    // Contained behavior: openat2 resolution rejection fails closed with StorageErrorKind::PermissionDenied
    let head_sym_outside = storage.head_manifest(repo, &digest).await;
    match head_sym_outside {
        Err(StorageError::Internal { kind, .. }) => {
            assert_eq!(
                kind,
                StorageErrorKind::PermissionDenied,
                "External symlink must be rejected with the converged PermissionDenied kind"
            );
        }
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for external symlink, got {other:?}"
        ),
    }
    let get_sym_outside = storage.get_manifest(repo, &digest).await;
    match get_sym_outside {
        Err(StorageError::Internal { kind, .. }) => {
            assert_eq!(
                kind,
                StorageErrorKind::PermissionDenied,
                "External symlink must be rejected with the converged PermissionDenied kind"
            );
        }
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for external symlink, got {other:?}"
        ),
    }

    // Scenario 2: Manifest file is a symlink pointing inside storage root
    std::fs::remove_file(&symlink_file).expect("remove symlink 1");
    let inside_target = root.join("repos").join(repo).join("inside_target.json");
    write_file(&inside_target, manifest_bytes);
    symlink(&inside_target, &symlink_file).expect("create symlink inside root");

    let head_sym_inside = storage.head_manifest(repo, &digest).await;
    match head_sym_inside {
        Err(StorageError::Internal { kind, .. }) => {
            assert_eq!(
                kind,
                StorageErrorKind::PermissionDenied,
                "Internal symlink must be rejected with the converged PermissionDenied kind"
            );
        }
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for internal symlink, got {other:?}"
        ),
    }
    let get_sym_inside = storage.get_manifest(repo, &digest).await;
    match get_sym_inside {
        Err(StorageError::Internal { kind, .. }) => {
            assert_eq!(
                kind,
                StorageErrorKind::PermissionDenied,
                "Internal symlink must be rejected with the converged PermissionDenied kind"
            );
        }
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for internal symlink, got {other:?}"
        ),
    }

    // Scenario 3: Intermediate manifests directory is a symlink to an outside directory
    let repo_outside_manifests = root.join("repos").join("repo_sym_dir");
    std::fs::create_dir_all(&repo_outside_manifests).expect("create repo_sym_dir");
    let outside_manifests_dir = outside.join("manifests_store");
    std::fs::create_dir_all(&outside_manifests_dir).expect("create outside manifests store");
    let outside_manifest_file = outside_manifests_dir.join(&hex);
    write_file(&outside_manifest_file, manifest_bytes);

    let symlink_manifests_dir = repo_outside_manifests.join("manifests");
    symlink(&outside_manifests_dir, &symlink_manifests_dir).expect("symlink manifests dir");

    let head_dir_sym = storage.head_manifest("repo_sym_dir", &digest).await;
    match head_dir_sym {
        Err(StorageError::Internal { kind, .. }) => {
            assert_eq!(
                kind,
                StorageErrorKind::PermissionDenied,
                "Ancestor directory symlink must be rejected with the converged PermissionDenied kind"
            );
        }
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for ancestor symlink, got {other:?}"
        ),
    }
    let get_dir_sym = storage.get_manifest("repo_sym_dir", &digest).await;
    match get_dir_sym {
        Err(StorageError::Internal { kind, .. }) => {
            assert_eq!(
                kind,
                StorageErrorKind::PermissionDenied,
                "Ancestor directory symlink must be rejected with the converged PermissionDenied kind"
            );
        }
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for ancestor symlink, got {other:?}"
        ),
    }

    // Scenario 4: Dangling symlink fails closed with Io (openat2 resolution rejection overrides NotFound)
    std::fs::remove_file(&symlink_file).expect("remove symlink");
    let nonexistent_target = root.join("nonexistent_target_file");
    symlink(&nonexistent_target, &symlink_file).expect("create dangling symlink");

    let head_dangling = storage.head_manifest(repo, &digest).await;
    match head_dangling {
        Err(StorageError::Internal { kind, .. }) => {
            assert_eq!(
                kind,
                StorageErrorKind::PermissionDenied,
                "Dangling symlink must produce StorageErrorKind::PermissionDenied (ResolutionRejected overrides NotFound)"
            );
        }
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for dangling symlink, got {other:?}"
        ),
    }
    let get_dangling = storage.get_manifest(repo, &digest).await;
    match get_dangling {
        Err(StorageError::Internal { kind, .. }) => {
            assert_eq!(
                kind,
                StorageErrorKind::PermissionDenied,
                "Dangling symlink must produce StorageErrorKind::PermissionDenied (ResolutionRejected overrides NotFound)"
            );
        }
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for dangling symlink, got {other:?}"
        ),
    }

    // Genuine missing paths (without a rejected symlink) remain NotFound:
    let missing_digest =
        Digest::parse("sha256:baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("valid digest");
    let genuine_missing_head = storage.head_manifest(repo, &missing_digest).await;
    assert!(
        matches!(genuine_missing_head, Err(StorageError::NotFound)),
        "Genuine missing path must return NotFound: got {genuine_missing_head:?}"
    );
    let genuine_missing_get = storage.get_manifest(repo, &missing_digest).await;
    assert!(
        matches!(genuine_missing_get, Err(StorageError::NotFound)),
        "Genuine missing path must return NotFound: got {genuine_missing_get:?}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_manifest_read_production_pinned_root_across_rename() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let renamed_root = fixture.path().join("storage-root-renamed");

    let repo = "pinned_repo";
    let content_a = br#"{"schemaVersion": 2, "mediaType": "application/vnd.manifest.a+json"}"#;
    let hex_a = hex_sha256(content_a);
    let digest_a = Digest::parse(&format!("sha256:{hex_a}")).expect("valid digest");

    // Put manifest A in root before storage initialization
    put_manifest_file(&root, repo, &hex_a, content_a);

    // Initialize production FsStorage (opens shared reader pinned to root descriptor)
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Rename root to renamed_root
    std::fs::rename(&root, &renamed_root).expect("rename storage root");

    // Recreate the old pathname with distinguishable content B under the same repo & digest
    let content_b = br#"{"schemaVersion": 2, "mediaType": "application/vnd.manifest.b+json"}"#;
    put_manifest_file(&root, repo, &hex_a, content_b);

    // 1. Production head_manifest must observe content A via pinned reader
    let head_meta = storage
        .head_manifest(repo, &digest_a)
        .await
        .expect("head_manifest succeeds through pinned reader");
    assert_eq!(head_meta.media_type, "application/vnd.manifest.a+json");
    assert_eq!(head_meta.size, content_a.len() as u64);

    // 2. Production get_manifest must observe content A bytes via pinned reader
    let (get_meta, payload) = storage
        .get_manifest(repo, &digest_a)
        .await
        .expect("get_manifest succeeds through pinned reader");
    assert_eq!(get_meta.media_type, "application/vnd.manifest.a+json");
    assert_eq!(get_meta.size, content_a.len() as u64);
    assert_eq!(payload.as_ref(), content_a);

    // 3. Port forwarding through ManifestReader must also observe content A
    let port_head_meta = <FsStorage as crate::storage::ports::ManifestReader>::head_manifest(
        &storage, repo, &digest_a,
    )
    .await
    .expect("port head_manifest succeeds through pinned reader");
    assert_eq!(port_head_meta.media_type, "application/vnd.manifest.a+json");
    assert_eq!(port_head_meta.size, content_a.len() as u64);

    let (port_get_meta, port_payload) =
        <FsStorage as crate::storage::ports::ManifestReader>::get_manifest(
            &storage, repo, &digest_a,
        )
        .await
        .expect("port get_manifest succeeds through pinned reader");
    assert_eq!(port_get_meta.media_type, "application/vnd.manifest.a+json");
    assert_eq!(port_get_meta.size, content_a.len() as u64);
    assert_eq!(port_payload.as_ref(), content_a);
}

#[tokio::test]
#[cfg(unix)]
#[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
async fn test_manifest_read_permission_denied_ignored() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let repo = "perm_repo";
    let manifest_bytes =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
    let hex = hex_sha256(manifest_bytes);
    let digest = Digest::parse(&format!("sha256:{hex}")).expect("valid digest");
    put_manifest_file(&root, repo, &hex, manifest_bytes);

    let manifest_path = root.join("repos").join(repo).join("manifests").join(&hex);
    let orig_perms = std::fs::metadata(&manifest_path)
        .expect("metadata")
        .permissions();

    struct ScopedPermReset<'a> {
        path: &'a Path,
        original_permissions: std::fs::Permissions,
    }

    impl<'a> Drop for ScopedPermReset<'a> {
        fn drop(&mut self) {
            if let Err(err) = std::fs::set_permissions(self.path, self.original_permissions.clone())
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
        // Install guard BEFORE permissions are restricted
        let _guard = ScopedPermReset {
            path: &manifest_path,
            original_permissions: orig_perms.clone(),
        };
        std::fs::set_permissions(&manifest_path, std::fs::Permissions::from_mode(0o000))
            .expect("set mode 0o000");

        // Fail fast if permissions are ineffective (e.g. running under root UID 0)
        if std::fs::read(&manifest_path).is_ok() {
            panic!("ineffective permissions: std::fs::read succeeded under mode 0o000");
        }

        let head_err = storage.head_manifest(repo, &digest).await.unwrap_err();
        match head_err {
            StorageError::Internal { kind, .. } => {
                assert_eq!(
                    kind,
                    StorageErrorKind::Io,
                    "PermissionDenied maps to StorageErrorKind::Io"
                );
            }
            StorageError::NotFound => panic!("Permission denied must NOT map to NotFound"),
            other => panic!("expected StorageErrorKind::Io, got: {other:?}"),
        }

        let get_err = storage.get_manifest(repo, &digest).await.unwrap_err();
        match get_err {
            StorageError::Internal { kind, .. } => {
                assert_eq!(
                    kind,
                    StorageErrorKind::Io,
                    "PermissionDenied maps to StorageErrorKind::Io"
                );
            }
            StorageError::NotFound => panic!("Permission denied must NOT map to NotFound"),
            other => panic!("expected StorageErrorKind::Io, got: {other:?}"),
        }
    }

    // On normal path, verify restored permissions against saved original permissions
    let restored_perms = std::fs::metadata(&manifest_path)
        .expect("metadata after permission restore")
        .permissions();
    assert_eq!(
        restored_perms.mode(),
        orig_perms.mode(),
        "restored permission bits must match saved original permissions"
    );
    assert!(
        std::fs::read(&manifest_path).is_ok(),
        "permissions must be restored and file readable after guard drop"
    );

    // Drop storage handles before checking fixture cleanup
    drop(storage);
    fixture
        .close()
        .expect("fixture directory close must succeed");
}

// --- Filesystem Manifest Listing Characterization Tests (list_manifest_digests_page) ---

#[tokio::test]
async fn test_manifest_listing_missing_and_empty_paths() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Case 1: Entire repository directory absent -> returns Ok(([], None))
    let res_missing_repo = storage
        .list_manifest_digests_page("nonexistent_repo", None, 10)
        .await
        .expect("missing repo succeeds with empty page");
    assert_eq!(res_missing_repo.0, Vec::<Digest>::new());
    assert_eq!(res_missing_repo.1, None);

    // Case 2: Repository directory exists, but manifests/ subdirectory is absent -> returns Ok(([], None))
    let repo_dir = root.join("repos").join("no_manifests_repo");
    std::fs::create_dir_all(&repo_dir).expect("create repo dir");
    let res_missing_manifests = storage
        .list_manifest_digests_page("no_manifests_repo", None, 10)
        .await
        .expect("missing manifests dir succeeds with empty page");
    assert_eq!(res_missing_manifests.0, Vec::<Digest>::new());
    assert_eq!(res_missing_manifests.1, None);

    // Case 3: manifests/ subdirectory exists and is empty -> returns Ok(([], None))
    let manifests_dir = repo_dir.join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");
    let res_empty = storage
        .list_manifest_digests_page("no_manifests_repo", None, 10)
        .await
        .expect("empty manifests dir succeeds with empty page");
    assert_eq!(res_empty.0, Vec::<Digest>::new());
    assert_eq!(res_empty.1, None);
}

#[tokio::test]
async fn test_manifest_listing_ordering_independent_of_creation_order() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "order_repo";

    // Create files in deliberate non-alphabetical creation order
    let hexes = [
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ];
    for hex in &hexes {
        put_manifest_file(&root, repo, hex, b"{}");
    }

    let (digests, token) = storage
        .list_manifest_digests_page(repo, None, 10)
        .await
        .expect("list manifests");
    assert_eq!(digests.len(), 4);
    assert_eq!(token, None);

    // Expected order: sorted strictly by hex() ascending
    let returned_hexes: Vec<String> = digests.iter().map(|d| d.hex().to_string()).collect();
    assert_eq!(
        returned_hexes,
        vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ]
    );
}

#[tokio::test]
async fn test_manifest_listing_complete_traversal_and_continuation_tokens() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "pagination_repo";

    let hexes = [
        "1000000000000000000000000000000000000000000000000000000000000000",
        "2000000000000000000000000000000000000000000000000000000000000000",
        "3000000000000000000000000000000000000000000000000000000000000000",
        "4000000000000000000000000000000000000000000000000000000000000000",
        "5000000000000000000000000000000000000000000000000000000000000000",
    ];
    for hex in &hexes {
        put_manifest_file(&root, repo, hex, b"{}");
    }

    // Page 1: limit 2
    let (p1, tok1) = storage
        .list_manifest_digests_page(repo, None, 2)
        .await
        .unwrap();
    assert_eq!(p1.len(), 2);
    assert_eq!(p1[0].hex(), hexes[0]);
    assert_eq!(p1[1].hex(), hexes[1]);
    assert_eq!(tok1, Some(format!("sha256:{}", hexes[1])));

    // Page 2: limit 2 with tok1
    let (p2, tok2) = storage
        .list_manifest_digests_page(repo, tok1.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(p2.len(), 2);
    assert_eq!(p2[0].hex(), hexes[2]);
    assert_eq!(p2[1].hex(), hexes[3]);
    assert_eq!(tok2, Some(format!("sha256:{}", hexes[3])));

    // Page 3: limit 2 with tok2 (final partial page)
    let (p3, tok3) = storage
        .list_manifest_digests_page(repo, tok2.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(p3.len(), 1);
    assert_eq!(p3[0].hex(), hexes[4]);
    assert_eq!(tok3, None, "final page continuation token must be None");

    // Page 4: calling with token of last item returns empty and None
    let (p4, tok4) = storage
        .list_manifest_digests_page(repo, Some(&format!("sha256:{}", hexes[4])), 2)
        .await
        .unwrap();
    assert_eq!(p4.len(), 0);
    assert_eq!(tok4, None);
}

#[tokio::test]
async fn test_manifest_listing_filename_interpretation_variants() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "filename_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    // 1. Raw 64-hex SHA-256 filename -> parsed as sha256:<hex>
    let raw_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_file(&manifests_dir.join(raw_sha256), b"{}");

    // 2. Raw 128-hex SHA-512 filename -> discovered by contained manifest listing!
    let raw_sha512 = "55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
    write_file(&manifests_dir.join(raw_sha512), b"{}");

    // 3. Algorithm-prefixed filename: sha256:<hex> -> skipped (not canonical raw hex)
    let prefixed_sha256 = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    write_file(&manifests_dir.join(prefixed_sha256), b"{}");

    // 4. Algorithm-prefixed filename: sha512:<hex> -> skipped (not canonical raw hex)
    let prefixed_sha512 = "sha512:66666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666";
    write_file(&manifests_dir.join(prefixed_sha512), b"{}");

    // 5. Uppercase SHA-256 filename -> skipped (must be lowercase ascii hex)
    let upper_sha256 = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
    write_file(&manifests_dir.join(upper_sha256), b"{}");

    // 6. Temporary and lock files -> skipped
    write_file(&manifests_dir.join(".tmp.upload123"), b"{}");
    write_file(&manifests_dir.join(".lock.exclusive"), b"{}");

    // 7. Non-digest filenames -> ignored
    write_file(&manifests_dir.join("README.txt"), b"{}");
    write_file(&manifests_dir.join(".DS_Store"), b"{}");
    write_file(&manifests_dir.join("short_hex"), b"{}");

    let (digests, _) = storage
        .list_manifest_digests_page(repo, None, 100)
        .await
        .unwrap();

    let as_strings: Vec<String> = digests.iter().map(|d| d.as_str()).collect();

    // Verify raw sha256 was included
    assert!(as_strings.contains(&format!("sha256:{raw_sha256}")));
    // Verify raw sha512 was included (discovered by contained manifest listing)
    assert!(as_strings.contains(&format!("sha512:{raw_sha512}")));
    // Verify prefixed sha256 was skipped
    assert!(!as_strings.contains(&prefixed_sha256.to_string()));
    // Verify prefixed sha512 was skipped
    assert!(!as_strings.contains(&prefixed_sha512.to_string()));
    // Verify uppercase sha256 was skipped
    assert!(!as_strings.contains(&format!("sha256:{}", upper_sha256.to_lowercase())));

    // Total listed count is 2 (raw_sha256 and raw_sha512)
    assert_eq!(digests.len(), 2);
}

#[tokio::test]
async fn test_manifest_listing_duplicate_digest_filenames_not_deduplicated() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "dup_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    // Write raw hex and prefixed hex
    let hex = "1212121212121212121212121212121212121212121212121212121212121212";
    write_file(&manifests_dir.join(hex), b"{}");
    write_file(&manifests_dir.join(format!("sha256:{hex}")), b"{}");

    let (digests, _) = storage
        .list_manifest_digests_page(repo, None, 10)
        .await
        .unwrap();

    // Contained listing deduplicates and only recognizes canonical raw hex: 1 digest returned
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0].as_str(), format!("sha256:{hex}"));
}

#[tokio::test]
#[cfg(unix)]
async fn test_manifest_listing_non_utf8_filename_ignored() {
    use std::os::unix::ffi::OsStrExt;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "non_utf8_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    // Create a filename containing invalid UTF-8 (0xFF)
    let non_utf8_bytes = b"0123456789abcdef\xff123456789abcdef0123456789abcdef0123456789abcdef";
    let non_utf8_os = std::ffi::OsStr::from_bytes(non_utf8_bytes);
    std::fs::write(manifests_dir.join(non_utf8_os), b"{}").expect("write non-utf8 file");

    let (digests, _) = storage
        .list_manifest_digests_page(repo, None, 10)
        .await
        .unwrap();

    // to_string_lossy replaces 0xFF with U+FFFD, failing hexdigit validation -> ignored
    assert_eq!(digests.len(), 0);
}

#[tokio::test]
async fn test_manifest_listing_page_limits_zero_and_oversized() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "limits_repo";

    let hex = "1111111111111111111111111111111111111111111111111111111111111111";
    put_manifest_file(&root, repo, hex, b"{}");

    // Zero page limit: returns empty slice, next_token is None even though items exist!
    let (p_zero, tok_zero) = storage
        .list_manifest_digests_page(repo, None, 0)
        .await
        .unwrap();
    assert_eq!(p_zero.len(), 0);
    assert_eq!(tok_zero, None);

    // Oversized page limit (1000): returns all entries, next_token is None
    let (p_over, tok_over) = storage
        .list_manifest_digests_page(repo, None, 1000)
        .await
        .unwrap();
    assert_eq!(p_over.len(), 1);
    assert_eq!(p_over[0].hex(), hex);
    assert_eq!(tok_over, None);
}

#[tokio::test]
async fn test_manifest_listing_arbitrary_tokens_boundary_cases() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "tokens_repo";

    let hexes = [
        "2000000000000000000000000000000000000000000000000000000000000000",
        "4000000000000000000000000000000000000000000000000000000000000000",
        "6000000000000000000000000000000000000000000000000000000000000000",
    ];
    for hex in &hexes {
        put_manifest_file(&root, repo, hex, b"{}");
    }

    // 1. Token before all existing digests -> returns from index 0
    let token_before = "sha256:1000000000000000000000000000000000000000000000000000000000000000";
    let (p_before, _) = storage
        .list_manifest_digests_page(repo, Some(token_before), 10)
        .await
        .unwrap();
    assert_eq!(p_before.len(), 3);
    assert_eq!(p_before[0].hex(), hexes[0]);

    // 2. Token between existing digests -> starts at insertion point (index 1)
    let token_between = "sha256:3000000000000000000000000000000000000000000000000000000000000000";
    let (p_between, _) = storage
        .list_manifest_digests_page(repo, Some(token_between), 10)
        .await
        .unwrap();
    assert_eq!(p_between.len(), 2);
    assert_eq!(p_between[0].hex(), hexes[1]);
    assert_eq!(p_between[1].hex(), hexes[2]);

    // 3. Token after all existing digests -> returns empty page
    let token_after = "sha256:7000000000000000000000000000000000000000000000000000000000000000";
    let (p_after, tok_after) = storage
        .list_manifest_digests_page(repo, Some(token_after), 10)
        .await
        .unwrap();
    assert_eq!(p_after.len(), 0);
    assert_eq!(tok_after, None);
}

#[tokio::test]
async fn test_manifest_listing_mixed_algorithm_sorting_and_cursor_mismatch() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "mismatch_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    // Item B: SHA-512 with hex starting with "1111..." (raw hex filename)
    let hex_b = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
    write_file(&manifests_dir.join(hex_b), b"{}");

    // Item C: SHA-256 with hex starting with "2222..."
    let hex_c = "2222222222222222222222222222222222222222222222222222222222222222";
    write_file(&manifests_dir.join(hex_c), b"{}");

    // Item A: SHA-256 with hex starting with "8888..."
    let hex_a = "8888888888888888888888888888888888888888888888888888888888888888";
    write_file(&manifests_dir.join(hex_a), b"{}");

    // 1. Establish deterministic ordering:
    // In a single unpaginated listing (limit 10), all entries are returned.
    let (all_items, token) = storage
        .list_manifest_digests_page(repo, None, 10)
        .await
        .unwrap();
    assert_eq!(all_items.len(), 3);
    assert_eq!(token, None);

    // Contained listing sorts by Digest::cmp (algorithm ascending, then hex ascending):
    // sha256:2222... < sha256:8888... < sha512:1111...
    assert_eq!(all_items[0].as_str(), format!("sha256:{hex_c}"));
    assert_eq!(all_items[1].as_str(), format!("sha256:{hex_a}"));
    assert_eq!(all_items[2].as_str(), format!("sha512:{hex_b}"));
    assert!(all_items[0] < all_items[1]);
    assert!(all_items[1] < all_items[2]);

    // 2. Exercise pagination across items.
    // Because the slice is sorted by Digest::cmp and continuation tokens use string comparison
    // matching Digest's algorithm-first order, binary search finds each item without mismatch or omission.
    const MAX_PAGINATION_STEPS: usize = 5;
    let mut collected: Vec<Digest> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut step_count = 0;
    let mut termination_reason = "exhausted iteration bound";

    for _ in 0..MAX_PAGINATION_STEPS {
        step_count += 1;
        let (page, next_cursor) = storage
            .list_manifest_digests_page(repo, cursor.as_deref(), 1)
            .await
            .unwrap();

        if page.is_empty() {
            termination_reason = "empty page";
            break;
        }

        if let Some(ref current_cur) = cursor {
            if let Some(ref next_cur) = next_cursor {
                if next_cur == current_cur {
                    termination_reason = "repeated token";
                    collected.extend(page);
                    break;
                }
            }
        }

        collected.extend(page);
        cursor = next_cursor;
        if cursor.is_none() {
            termination_reason = "no continuation token";
            break;
        }
    }

    let omitted: Vec<String> = all_items
        .iter()
        .filter(|d| !collected.contains(d))
        .map(|d| d.as_str())
        .collect();

    assert_eq!(step_count, 3);
    assert_eq!(termination_reason, "no continuation token");
    assert_eq!(omitted.len(), 0);
    assert_eq!(collected.len(), 3);
    assert_eq!(collected, all_items);
}

#[tokio::test]
#[cfg(unix)]
async fn test_manifest_listing_entry_types_unfiltered() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let outside = fixture.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "entry_types_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    // 1. Regular file with 64-hex name
    let hex_reg = "1111111111111111111111111111111111111111111111111111111111111111";
    write_file(&manifests_dir.join(hex_reg), b"{}");

    // 2. Directory with 64-hex name
    let hex_dir = "2222222222222222222222222222222222222222222222222222222222222222";
    std::fs::create_dir(manifests_dir.join(hex_dir)).expect("create dir entry");

    // 3. Symlink pointing to outside file with 64-hex name
    let hex_sym = "3333333333333333333333333333333333333333333333333333333333333333";
    let outside_file = outside.join("outside_manifest.json");
    write_file(&outside_file, b"{}");
    symlink(&outside_file, manifests_dir.join(hex_sym)).expect("create symlink entry");

    // 4. Dangling symlink with 64-hex name
    let hex_dangling = "4444444444444444444444444444444444444444444444444444444444444444";
    symlink(
        outside.join("nonexistent_file"),
        manifests_dir.join(hex_dangling),
    )
    .expect("create dangling symlink");

    let (digests, _) = storage
        .list_manifest_digests_page(repo, None, 10)
        .await
        .unwrap();

    // Contained listing checks entry file types: only Regular files are listed.
    // Directories, valid symlinks, and dangling symlinks are skipped!
    let listed_hexes: Vec<String> = digests.iter().map(|d| d.hex().to_string()).collect();
    assert_eq!(listed_hexes.len(), 1);
    assert_eq!(listed_hexes[0], hex_reg);
}

#[tokio::test]
#[cfg(unix)]
async fn test_manifest_listing_symlinked_manifests_and_ancestors() {
    use std::os::unix::fs::symlink;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let outside = fixture.path().join("outside");
    std::fs::create_dir_all(&outside).expect("create outside dir");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Case 1: manifests/ directory itself is a symlink to outside directory
    let repo1 = "sym_manifests_repo";
    let repo1_dir = root.join("repos").join(repo1);
    std::fs::create_dir_all(&repo1_dir).expect("create repo1 dir");
    let outside_manifests1 = outside.join("ext_manifests1");
    std::fs::create_dir_all(&outside_manifests1).expect("create ext_manifests1");
    let hex1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_file(&outside_manifests1.join(hex1), b"{}");
    symlink(&outside_manifests1, repo1_dir.join("manifests")).expect("symlink manifests dir");

    let res1 = storage.list_manifest_digests_page(repo1, None, 10).await;
    let err1 = res1.expect_err("symlinked manifests dir must fail closed");
    assert_eq!(
        err1.internal_kind(),
        Some(StorageErrorKind::PermissionDenied),
        "containment refusal (Phase 4 converged kind)"
    );

    // Case 2: Ancestor repo directory is a symlink to outside directory
    let outside_repo2 = outside.join("ext_repo2");
    let outside_manifests2 = outside_repo2.join("manifests");
    std::fs::create_dir_all(&outside_manifests2).expect("create ext_manifests2");
    let hex2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    write_file(&outside_manifests2.join(hex2), b"{}");

    let repos_dir = root.join("repos");
    std::fs::create_dir_all(&repos_dir).expect("create repos dir");
    symlink(&outside_repo2, repos_dir.join("sym_ancestor_repo")).expect("symlink repo ancestor");

    let res2 = storage
        .list_manifest_digests_page("sym_ancestor_repo", None, 10)
        .await;
    let err2 = res2.expect_err("symlinked ancestor dir must fail closed");
    assert_eq!(
        err2.internal_kind(),
        Some(StorageErrorKind::PermissionDenied),
        "containment refusal (Phase 4 converged kind)"
    );
}

#[tokio::test]
async fn test_manifest_listing_path_traversal_and_absolute_paths() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Create an escaped repo outside root/repos
    let escaped_manifests = fixture.path().join("escaped_repo").join("manifests");
    std::fs::create_dir_all(&escaped_manifests).expect("create escaped manifests");
    let hex_escaped = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    write_file(&escaped_manifests.join(hex_escaped), b"{}");

    // Ensure root/repos exists
    std::fs::create_dir_all(root.join("repos")).expect("create repos dir");

    // Path traversal input: "../../escaped_repo" fails closed with InvalidRepoName
    let res_traversal = storage
        .list_manifest_digests_page("../../escaped_repo", None, 10)
        .await;
    match res_traversal {
        Err(StorageError::InvalidRepoName(msg)) => {
            assert!(msg.contains("path traversal attempt") || msg.contains(".."));
        }
        other => panic!("expected InvalidRepoName error, got: {other:?}"),
    }

    // Absolute path input fails closed with InvalidRepoName
    let escaped_dir_path = fixture.path().join("escaped_repo");
    let abs_repo_input = escaped_dir_path.to_str().unwrap();
    let res_abs = storage
        .list_manifest_digests_page(abs_repo_input, None, 10)
        .await;
    match res_abs {
        Err(StorageError::InvalidRepoName(_)) => {}
        other => panic!("expected InvalidRepoName error, got: {other:?}"),
    }
}

#[tokio::test]
async fn test_manifest_listing_component_wrong_type_suppressed() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repos_dir = root.join("repos");
    std::fs::create_dir_all(&repos_dir).expect("create repos dir");

    // Phase 4 converged (accepted Phase 1 adapter contract): a regular file
    // occupying an intermediate component means NOTHING can exist beneath it
    // — structural absence, an empty terminal page (the retired FS listing
    // errored CorruptData; on S3 such shadowing is impossible: prefix
    // listings are independent of any same-named object). The FS-native GC
    // discovery path already treated a file named "manifests" as
    // contributing nothing, so no reachable object loses protection.

    // Case 1: manifests component is a regular file instead of a directory.
    let repo1_dir = repos_dir.join("file_manifests_repo");
    std::fs::create_dir_all(&repo1_dir).expect("create repo1 dir");
    write_file(&repo1_dir.join("manifests"), b"regular file, not a dir");

    let (p1, t1) = storage
        .list_manifest_digests_page("file_manifests_repo", None, 10)
        .await
        .expect("structural absence lists empty");
    assert!(p1.is_empty() && t1.is_none());

    // Case 2: repo component itself is a regular file instead of a directory.
    write_file(&repos_dir.join("file_repo"), b"regular file, not a dir");
    let (p2, t2) = storage
        .list_manifest_digests_page("file_repo", None, 10)
        .await
        .expect("structural absence lists empty");
    assert!(p2.is_empty() && t2.is_none());
}

#[tokio::test]
#[cfg(unix)]
#[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
async fn test_manifest_listing_permission_denied_ignored() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "perm_list_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let hex = "1111111111111111111111111111111111111111111111111111111111111111";
    write_file(&manifests_dir.join(hex), b"{}");

    let orig_perms = std::fs::metadata(&manifests_dir).unwrap().permissions();

    struct ScopedPermReset<'a> {
        path: &'a std::path::Path,
        original_permissions: std::fs::Permissions,
    }

    impl<'a> Drop for ScopedPermReset<'a> {
        fn drop(&mut self) {
            if let Err(err) = std::fs::set_permissions(self.path, self.original_permissions.clone())
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
            path: &manifests_dir,
            original_permissions: orig_perms.clone(),
        };
        std::fs::set_permissions(&manifests_dir, std::fs::Permissions::from_mode(0o000))
            .expect("set mode 0o000");

        // Fail-fast assertion: verify permissions actually deny access with PermissionDenied
        match std::fs::read_dir(&manifests_dir) {
            Ok(_) => {
                panic!("ineffective permissions: std::fs::read_dir succeeded under mode 0o000")
            }
            Err(err) => assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected PermissionDenied error under mode 0o000, got: {err:?}"
            ),
        }

        // list_manifest_digests_page: fails closed with StorageErrorKind::PermissionDenied
        let res = storage.list_manifest_digests_page(repo, None, 10).await;
        let err =
            res.expect_err("PermissionDenied on readdir must fail closed with PermissionDenied");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::PermissionDenied)
        );
    }

    let restored_perms = std::fs::metadata(&manifests_dir).unwrap().permissions();
    assert_eq!(restored_perms.mode(), orig_perms.mode());
}

#[tokio::test]
async fn test_manifest_listing_inter_page_mutation_lacks_snapshot_isolation() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "mutation_repo";

    let hex_a = "1000000000000000000000000000000000000000000000000000000000000000";
    let hex_c = "3000000000000000000000000000000000000000000000000000000000000000";
    put_manifest_file(&root, repo, hex_a, b"{}");
    put_manifest_file(&root, repo, hex_c, b"{}");

    // Page 1 with limit 1: returns item A, token = A
    let (p1, tok1) = storage
        .list_manifest_digests_page(repo, None, 1)
        .await
        .unwrap();
    assert_eq!(p1.len(), 1);
    assert_eq!(p1[0].hex(), hex_a);
    assert_eq!(tok1, Some(format!("sha256:{hex_a}")));

    // Sequentially insert item B between completed page calls (between A and C) before Page 2
    let hex_b = "2000000000000000000000000000000000000000000000000000000000000000";
    put_manifest_file(&root, repo, hex_b, b"{}");

    // Page 2: Request with tok1 (A) observes the newly inserted item B!
    let (p2, tok2) = storage
        .list_manifest_digests_page(repo, tok1.as_deref(), 1)
        .await
        .unwrap();
    assert_eq!(
        p2.len(),
        1,
        "inter-page insertion is visible to subsequent page"
    );
    assert_eq!(p2[0].hex(), hex_b);
    assert_eq!(tok2, Some(format!("sha256:{hex_b}")));
}

#[tokio::test]
async fn test_manifest_listing_manifest_reader_port_forwarding() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repo = "port_repo";

    let hex1 = "1111111111111111111111111111111111111111111111111111111111111111";
    let hex2 = "2222222222222222222222222222222222222222222222222222222222222222";
    put_manifest_file(&root, repo, hex1, b"{}");
    put_manifest_file(&root, repo, hex2, b"{}");

    // Invoke through ManifestReader port trait directly
    let (page, tok) =
        <FsStorage as crate::storage::ports::ManifestReader>::list_manifest_digests_page(
            &storage, repo, None, 1,
        )
        .await
        .expect("ManifestReader::list_manifest_digests_page succeeds");

    assert_eq!(page.len(), 1);
    assert_eq!(page[0].hex(), hex1);
    assert_eq!(tok, Some(format!("sha256:{hex1}")));
}

#[tokio::test]
async fn test_manifest_listing_constructor_validation() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");

    // 1. try_new_with_limits validates max_entries >= 1
    let err_entries = FsStorage::try_new_with_limits(
        root.clone(),
        1024 * 1024,
        storage_fs::DirEnumerationLimits::new(0, 1_500_000),
    )
    .expect_err("entries = 0 must fail constructor validation");
    assert_eq!(
        err_entries.internal_kind(),
        Some(StorageErrorKind::Configuration)
    );
    assert!(
        err_entries
            .to_string()
            .contains("manifest_listing_max_entries must be at least 1")
    );

    // 2. try_new_with_limits validates max_total_name_bytes >= 128
    let err_bytes = FsStorage::try_new_with_limits(
        root.clone(),
        1024 * 1024,
        storage_fs::DirEnumerationLimits::new(10_000, 127),
    )
    .expect_err("name_bytes = 127 must fail constructor validation");
    assert_eq!(
        err_bytes.internal_kind(),
        Some(StorageErrorKind::Configuration)
    );
    assert!(
        err_bytes
            .to_string()
            .contains("manifest_listing_max_name_bytes must be at least 128")
    );

    // 3. Valid limits succeed and are wired into the manifest listing
    // budget (Phase 4: the configured limits bound the manifest object
    // store's enumeration; exceeding max_entries fails truthfully).
    let storage_custom = FsStorage::try_new_with_limits(
        root.clone(),
        1024 * 1024,
        storage_fs::DirEnumerationLimits::new(2, 50_000),
    )
    .expect("valid limits succeed");
    let hexes = [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
    ];
    let mdir = root.join("repos").join("limitrepo").join("manifests");
    std::fs::create_dir_all(&mdir).unwrap();
    for h in &hexes[..2] {
        std::fs::write(mdir.join(h), br#"{"schemaVersion":2}"#).unwrap();
    }
    let (page, _) = storage_custom
        .list_manifest_digests_page("limitrepo", None, 10)
        .await
        .expect("2 entries within max_entries=2 succeeds");
    assert_eq!(page.len(), 2);
    std::fs::write(mdir.join(hexes[2]), br#"{"schemaVersion":2}"#).unwrap();
    let (page, _) = storage_custom
        .list_manifest_digests_page("limitrepo", None, 10)
        .await
        .expect("3 entries stream successfully without artificial limits");
    assert_eq!(page.len(), 3);

    // 4. Default constructor succeeds with the approved defaults wired.
    let storage_default =
        FsStorage::try_new(root.clone(), 1024 * 1024).expect("default constructor succeeds");
    let (dpage, _) = storage_default
        .list_manifest_digests_page("limitrepo", None, 10)
        .await
        .expect("defaults (10_000 entries) accommodate the fixture");
    assert_eq!(dpage.len(), 3);
}

#[tokio::test]
async fn test_manifest_listing_exact_entry_boundary() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let repo = "boundary_entry_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let hex1 = "1111111111111111111111111111111111111111111111111111111111111111";
    let hex2 = "2222222222222222222222222222222222222222222222222222222222222222";
    write_file(&manifests_dir.join(hex1), b"{}");
    write_file(&manifests_dir.join(hex2), b"{}");

    // Limits with exactly 2 entries: enumeration of 2 entries succeeds
    let storage2 = FsStorage::try_new_with_limits(
        root.clone(),
        1024 * 1024,
        storage_fs::DirEnumerationLimits::new(2, 1_500_000),
    )
    .unwrap();
    let (items, _) = storage2
        .list_manifest_digests_page(repo, None, 10)
        .await
        .unwrap();
    assert_eq!(items.len(), 2);

    // Unbounded streaming: listing succeeds without hitting artificial entry limits
    let storage1 = FsStorage::try_new_with_limits(
        root.clone(),
        1024 * 1024,
        storage_fs::DirEnumerationLimits::new(1, 1_500_000),
    )
    .unwrap();
    let (items1, _) = storage1
        .list_manifest_digests_page(repo, None, 10)
        .await
        .expect("unbounded streaming succeeds without hitting entry limits");
    assert_eq!(items1.len(), 2);
}

#[tokio::test]
async fn test_manifest_listing_exact_name_byte_boundary_including_128_byte_sha512() {
    let fixture = tempfile::tempdir().expect("create test fixture");
    let root = fixture.path().join("storage-root");
    let repo = "boundary_bytes_repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    std::fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    // 128-byte SHA-512 filename
    let hex_512 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(hex_512.len(), 128);
    write_file(&manifests_dir.join(hex_512), b"{}");

    // Exactly 128 name bytes limit: single 128-byte filename fits!
    let storage128 = FsStorage::try_new_with_limits(
        root.clone(),
        1024 * 1024,
        storage_fs::DirEnumerationLimits::new(100, 128),
    )
    .unwrap();
    let (items, _) = storage128
        .list_manifest_digests_page(repo, None, 10)
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].as_str(), format!("sha512:{hex_512}"));

    // Add another file (64 bytes): cumulative bytes = 192 > 128 -> limit exceeded!
    let hex_256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    write_file(&manifests_dir.join(hex_256), b"{}");

    let (items, _) = storage128
        .list_manifest_digests_page(repo, None, 10)
        .await
        .expect("unbounded streaming succeeds without name byte limits");
    assert_eq!(items.len(), 2);
}

// --- Filesystem Repository Discovery Characterization Tests (list_repositories) ---

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_missing_and_empty_repos_dir() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    assert!(!root.join("repos").exists());
    let repos = storage
        .list_repositories()
        .await
        .expect("missing repos dir must succeed");
    assert!(repos.is_empty(), "missing repos dir must return empty list");

    std::fs::create_dir_all(root.join("repos")).expect("create empty repos dir");
    let repos = storage
        .list_repositories()
        .await
        .expect("empty repos dir must succeed");
    assert!(repos.is_empty(), "empty repos dir must return empty list");
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_leaf_directory_recognition_rules() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repos_dir = root.join("repos");

    let no_leaf = repos_dir.join("no_leaf");
    std::fs::create_dir_all(no_leaf.join("arbitrary_subdir")).unwrap();
    write_file(&no_leaf.join("file.txt"), b"hello");

    let referrers_only = repos_dir.join("referrers_only");
    std::fs::create_dir_all(referrers_only.join("referrers")).unwrap();

    std::fs::create_dir_all(repos_dir.join("tags_only").join("tags")).unwrap();
    std::fs::create_dir_all(repos_dir.join("manifests_only").join("manifests")).unwrap();
    std::fs::create_dir_all(repos_dir.join("blobs_only").join("blobs")).unwrap();
    std::fs::create_dir_all(repos_dir.join("meta_only").join("meta")).unwrap();

    let all_leaves = repos_dir.join("all_leaves");
    std::fs::create_dir_all(all_leaves.join("tags")).unwrap();
    std::fs::create_dir_all(all_leaves.join("manifests")).unwrap();
    std::fs::create_dir_all(all_leaves.join("blobs")).unwrap();
    std::fs::create_dir_all(all_leaves.join("meta")).unwrap();

    let mut repos = storage.list_repositories().await.unwrap();
    repos.sort();

    assert_eq!(
        repos,
        vec![
            "all_leaves".to_string(),
            "blobs_only".to_string(),
            "manifests_only".to_string(),
            "meta_only".to_string(),
            "tags_only".to_string(),
        ],
        "only directories with tags, manifests, blobs, or meta are recognized; referrers-only and no-leaf are excluded"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_nested_hierarchy_parent_child_sorting_dedup() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repos_dir = root.join("repos");

    std::fs::create_dir_all(repos_dir.join("org").join("meta")).unwrap();
    std::fs::create_dir_all(repos_dir.join("org").join("team").join("tags")).unwrap();
    std::fs::create_dir_all(
        repos_dir
            .join("org")
            .join("team")
            .join("project")
            .join("manifests"),
    )
    .unwrap();

    std::fs::create_dir_all(repos_dir.join("zebra").join("manifests")).unwrap();
    std::fs::create_dir_all(repos_dir.join("alpha").join("team").join("blobs")).unwrap();
    std::fs::create_dir_all(repos_dir.join("alpha").join("blobs")).unwrap();

    let repos = storage.list_repositories().await.unwrap();

    assert_eq!(
        repos,
        vec![
            "alpha".to_string(),
            "alpha/team".to_string(),
            "org".to_string(),
            "org/team".to_string(),
            "org/team/project".to_string(),
            "zebra".to_string(),
        ]
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_reserved_leaf_names_excluded_and_gc_divergence() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repos_dir = root.join("repos");

    fn create_manifest(config_digest: &str, layer_digest: &str) -> (Vec<u8>, String, String) {
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": 100,
                "digest": config_digest
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": 200,
                    "digest": layer_digest
                }
            ]
        });
        let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap();
        let hex = hex_sha256(&manifest_bytes);
        let manifest_digest = format!("sha256:{hex}");
        (manifest_bytes, hex, manifest_digest)
    }

    // 1. Direct repos/manifests/<hex> (manifests directory directly under repos)
    let config_direct = "sha256:11111111111111111111111111111111111111111111111111111111111111c1";
    let layer_direct = "sha256:11111111111111111111111111111111111111111111111111111111111111d1";
    let (bytes_direct, hex_direct, digest_direct) = create_manifest(config_direct, layer_direct);
    let direct_manifests_dir = repos_dir.join("manifests");
    std::fs::create_dir_all(&direct_manifests_dir).unwrap();
    write_file(&direct_manifests_dir.join(&hex_direct), &bytes_direct);

    // 2. Reserved 'tags' segment: repos/tags/subrepo/manifests/<hex>
    let config_tags = "sha256:22222222222222222222222222222222222222222222222222222222222222c2";
    let layer_tags = "sha256:22222222222222222222222222222222222222222222222222222222222222d2";
    let (bytes_tags, hex_tags, digest_tags) = create_manifest(config_tags, layer_tags);
    let tags_manifests_dir = repos_dir.join("tags").join("subrepo").join("manifests");
    std::fs::create_dir_all(&tags_manifests_dir).unwrap();
    write_file(&tags_manifests_dir.join(&hex_tags), &bytes_tags);

    // 3. Reserved 'referrers' segment: repos/referrers/subrepo/manifests/<hex>
    let config_referrers =
        "sha256:33333333333333333333333333333333333333333333333333333333333333c3";
    let layer_referrers = "sha256:33333333333333333333333333333333333333333333333333333333333333d3";
    let (bytes_referrers, hex_referrers, digest_referrers) =
        create_manifest(config_referrers, layer_referrers);
    let referrers_manifests_dir = repos_dir
        .join("referrers")
        .join("subrepo")
        .join("manifests");
    std::fs::create_dir_all(&referrers_manifests_dir).unwrap();
    write_file(
        &referrers_manifests_dir.join(&hex_referrers),
        &bytes_referrers,
    );

    // 4. Reserved 'blobs' segment: repos/blobs/subrepo/manifests/<hex>
    let config_blobs = "sha256:44444444444444444444444444444444444444444444444444444444444444c4";
    let layer_blobs = "sha256:44444444444444444444444444444444444444444444444444444444444444d4";
    let (bytes_blobs, hex_blobs, digest_blobs) = create_manifest(config_blobs, layer_blobs);
    let blobs_manifests_dir = repos_dir.join("blobs").join("subrepo").join("manifests");
    std::fs::create_dir_all(&blobs_manifests_dir).unwrap();
    write_file(&blobs_manifests_dir.join(&hex_blobs), &bytes_blobs);

    // 5. Reserved 'meta' segment: repos/meta/subrepo/manifests/<hex>
    let config_meta = "sha256:55555555555555555555555555555555555555555555555555555555555555c5";
    let layer_meta = "sha256:55555555555555555555555555555555555555555555555555555555555555d5";
    let (bytes_meta, hex_meta, digest_meta) = create_manifest(config_meta, layer_meta);
    let meta_manifests_dir = repos_dir.join("meta").join("subrepo").join("manifests");
    std::fs::create_dir_all(&meta_manifests_dir).unwrap();
    write_file(&meta_manifests_dir.join(&hex_meta), &bytes_meta);

    // 6. Nested beneath 'manifests' segment: repos/manifests/nested_repo/manifests/<hex>
    // The GC walker treats 'manifests' as a leaf scan and does not recursively traverse it.
    let config_nested = "sha256:66666666666666666666666666666666666666666666666666666666666666c6";
    let layer_nested = "sha256:66666666666666666666666666666666666666666666666666666666666666d6";
    let (bytes_nested, hex_nested, digest_nested) = create_manifest(config_nested, layer_nested);
    let nested_manifests_dir = repos_dir
        .join("manifests")
        .join("nested_repo")
        .join("manifests");
    std::fs::create_dir_all(&nested_manifests_dir).unwrap();
    write_file(&nested_manifests_dir.join(&hex_nested), &bytes_nested);

    // Assert list_repositories behavior:
    // All 5 reserved names (tags, manifests, referrers, blobs, meta) are skipped at top level.
    // Therefore, list_repositories discovers zero repositories.
    let repos = storage.list_repositories().await.unwrap();
    assert!(
        repos.is_empty(),
        "list_repositories skips all reserved directory names (tags, manifests, referrers, blobs, meta); expected empty, got: {repos:?}"
    );

    // Assert build_manifest_protected_set behavior with contained discovery:
    let protected = crate::blob_gc::policy::build_manifest_protected_set(&storage)
        .await
        .unwrap();

    // 1. Direct manifests leaf under repos/ is scanned by the GC walker:
    assert!(
        protected.contains(&digest_direct),
        "GC walker discovers direct manifest in repos/manifests"
    );
    assert!(
        protected.contains(config_direct),
        "GC walker protects config reference from direct manifest"
    );
    assert!(
        protected.contains(layer_direct),
        "GC walker protects layer reference from direct manifest"
    );

    // 2. Manifests under reserved 'tags' ancestor are traversed and discovered:
    assert!(
        protected.contains(&digest_tags),
        "GC walker descends through 'tags' ancestor and discovers manifest"
    );
    assert!(
        protected.contains(config_tags),
        "GC walker protects config reference beneath 'tags'"
    );
    assert!(
        protected.contains(layer_tags),
        "GC walker protects layer reference beneath 'tags'"
    );

    // 3. Manifests under reserved 'referrers' ancestor are traversed and discovered:
    assert!(
        protected.contains(&digest_referrers),
        "GC walker descends through 'referrers' ancestor and discovers manifest"
    );
    assert!(
        protected.contains(config_referrers),
        "GC walker protects config reference beneath 'referrers'"
    );
    assert!(
        protected.contains(layer_referrers),
        "GC walker protects layer reference beneath 'referrers'"
    );

    // 4. Manifests under reserved 'blobs' ancestor are traversed and discovered:
    assert!(
        protected.contains(&digest_blobs),
        "GC walker descends through 'blobs' ancestor and discovers manifest"
    );
    assert!(
        protected.contains(config_blobs),
        "GC walker protects config reference beneath 'blobs'"
    );
    assert!(
        protected.contains(layer_blobs),
        "GC walker protects layer reference beneath 'blobs'"
    );

    // 5. Manifests under reserved 'meta' ancestor are traversed and discovered:
    assert!(
        protected.contains(&digest_meta),
        "GC walker descends through 'meta' ancestor and discovers manifest"
    );
    assert!(
        protected.contains(config_meta),
        "GC walker protects config reference beneath 'meta'"
    );
    assert!(
        protected.contains(layer_meta),
        "GC walker protects layer reference beneath 'meta'"
    );

    // 6. Subtree nested inside 'manifests' is NOT traversed by the GC walker (manifests is a leaf scan):
    assert!(
        !protected.contains(&digest_nested),
        "GC walker does NOT recursively traverse subdirectories within 'manifests'"
    );
    assert!(
        !protected.contains(config_nested),
        "config reference from repository nested inside 'manifests' is omitted from protected set"
    );
    assert!(
        !protected.contains(layer_nested),
        "layer reference from repository nested inside 'manifests' is omitted from protected set"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_non_utf8_ancestors_skipped_vs_gc_walker() {
    use std::os::unix::ffi::OsStrExt;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repos_dir = root.join("repos");

    let non_utf8_name = std::ffi::OsStr::from_bytes(b"non_utf8_\xff\xfe");
    let non_utf8_ancestor = repos_dir.join(non_utf8_name);
    let subrepo_manifests = non_utf8_ancestor.join("subrepo").join("manifests");
    std::fs::create_dir_all(&subrepo_manifests).unwrap();

    let layer_digest = "sha256:77777777777777777777777777777777777777777777777777777777777777d7";
    let config_digest = "sha256:77777777777777777777777777777777777777777777777777777777777777c7";
    let manifest_json = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 50,
            "digest": config_digest
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "size": 150,
                "digest": layer_digest
            }
        ]
    });
    let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap();
    let hex = hex_sha256(&manifest_bytes);
    let _manifest_digest = format!("sha256:{hex}");
    write_file(&subrepo_manifests.join(&hex), &manifest_bytes);

    let repos = storage.list_repositories().await.unwrap();
    assert!(
        repos.is_empty(),
        "list_repositories skips non-UTF-8 ancestor entries"
    );

    // Under contained discovery, non-UTF-8 directory names fail closed with StorageError::corrupt_data (D-06)
    let err = crate::blob_gc::policy::build_manifest_protected_set(&storage)
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::blob_gc::policy::GcPolicyError::ManifestDiscovery(ref e) if e.internal_kind() == Some(crate::storage::StorageErrorKind::CorruptData)),
        "contained discovery fails closed on non-UTF-8 directory names (D-06); got: {err:?}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_unaddressable_repo_name_fails_closed() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repos_dir = root.join("repos");

    let bad_repo_name = "invalid\\backslash";
    let bad_repo_dir = repos_dir.join(bad_repo_name);
    std::fs::create_dir_all(bad_repo_dir.join("manifests")).unwrap();
    std::fs::create_dir_all(repos_dir.join("valid_repo").join("manifests")).unwrap();

    // Contained catalog discovery fails closed on UTF-8 entry names that
    // cannot compose a contained ObjectKey. Silently skipping them would turn
    // previously visible downstream failures into successful incomplete
    // discovery, which safety-relevant consumers could mistake for completion.
    let err = storage
        .list_repositories()
        .await
        .expect_err("unaddressable repository names must fail catalog discovery closed");
    match err {
        StorageError::Internal { kind, ref message } => {
            assert_eq!(kind, StorageErrorKind::CorruptData);
            assert!(
                message.contains("cannot form a contained object key")
                    && message.contains("invalid"),
                "error must carry name/context, got: {message}"
            );
        }
        other => panic!("expected Internal(CorruptData), got: {other:?}"),
    }

    // Downstream contained manifest listing continues to reject the name.
    let listing_res = storage
        .list_manifest_digests_page(bad_repo_name, None, 10)
        .await;
    let err = listing_res.expect_err("manifest_dir_key must reject invalid repository name");
    match err {
        StorageError::InvalidRepoName(msg) => {
            assert!(
                msg.contains("backslashes"),
                "expected error message about backslashes, got: {msg}"
            );
        }
        other => panic!("expected StorageError::InvalidRepoName, got: {other:?}"),
    }
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_symlink_semantics() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // Case A: Initial repos/ directory as a symlink is now rejected by
    // contained resolution instead of silently followed.
    let external_repos = fixture.path().join("external_repos");
    std::fs::create_dir_all(external_repos.join("repo_in_ext").join("tags")).unwrap();
    std::os::unix::fs::symlink(&external_repos, root.join("repos")).unwrap();

    let err = storage
        .list_repositories()
        .await
        .expect_err("symlinked repos/ root must be rejected, not followed");
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

    // Replace the symlink with a real repos/ directory for the entry cases.
    std::fs::remove_file(root.join("repos")).unwrap();
    let repos_dir = root.join("repos");
    std::fs::create_dir_all(repos_dir.join("plain_repo").join("tags")).unwrap();

    // Case B: Symlinked repository entry within repos/ remains skipped
    // (dirent type is not a directory), matching legacy behavior.
    let ext_target_repo = fixture.path().join("ext_target_repo");
    std::fs::create_dir_all(ext_target_repo.join("manifests")).unwrap();
    std::os::unix::fs::symlink(&ext_target_repo, repos_dir.join("symlink_repo")).unwrap();

    let repos_after_symlink = storage.list_repositories().await.unwrap();
    assert_eq!(
        repos_after_symlink,
        vec!["plain_repo".to_string()],
        "symlinked repository entries are skipped because the dirent type is not a directory"
    );

    // Case C: Symlinked recognition leaf (tags/) no longer recognizes the
    // repository: markers are judged by contained dirent type, not by an
    // ambient symlink-following stat.
    let ext_tags = fixture.path().join("ext_tags");
    std::fs::create_dir_all(&ext_tags).unwrap();
    let real_repo = repos_dir.join("repo_with_symlink_leaf");
    std::fs::create_dir_all(&real_repo).unwrap();
    std::os::unix::fs::symlink(&ext_tags, real_repo.join("tags")).unwrap();

    let repos_with_symlink_leaf = storage.list_repositories().await.unwrap();
    assert_eq!(
        repos_with_symlink_leaf,
        vec!["plain_repo".to_string()],
        "symlinked recognition markers no longer recognize repositories"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_wrong_type_paths() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    write_file(&root.join("repos"), b"not a directory");
    let err = storage
        .list_repositories()
        .await
        .expect_err("repos as file must fail");
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));

    let root2 = tmp_fs_root();
    let storage2 = FsStorage::new(root2.clone(), 1024 * 1024);
    let repos_dir = root2.join("repos");
    std::fs::create_dir_all(&repos_dir).unwrap();
    write_file(&repos_dir.join("file_entry"), b"not a repo");
    let repos = storage2.list_repositories().await.unwrap();
    assert!(
        repos.is_empty(),
        "regular file entry in repos/ must be skipped"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
#[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
async fn test_repo_discovery_permission_denied_ignored() {
    use std::os::unix::fs::PermissionsExt;

    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let repos_dir = root.join("repos");
    std::fs::create_dir_all(&repos_dir).unwrap();
    std::fs::create_dir_all(repos_dir.join("valid_repo").join("tags")).unwrap();

    let orig_perms = std::fs::metadata(&repos_dir).unwrap().permissions();

    struct ScopedPermReset<'a> {
        path: &'a std::path::Path,
        original_permissions: std::fs::Permissions,
    }

    impl<'a> Drop for ScopedPermReset<'a> {
        fn drop(&mut self) {
            if let Err(err) = std::fs::set_permissions(self.path, self.original_permissions.clone())
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
            path: &repos_dir,
            original_permissions: orig_perms.clone(),
        };
        std::fs::set_permissions(&repos_dir, std::fs::Permissions::from_mode(0o000))
            .expect("set mode 0o000");

        match std::fs::read_dir(&repos_dir) {
            Ok(_) => {
                panic!("ineffective permissions: std::fs::read_dir succeeded under mode 0o000");
            }
            Err(err) => assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "expected PermissionDenied, got: {err:?}"
            ),
        }

        let res = storage.list_repositories().await;
        let err = res.expect_err("PermissionDenied on read_dir(&repos_root) must fail");
        assert_eq!(
            err.internal_kind(),
            Some(StorageErrorKind::Io),
            "list_repo_names maps read_dir error to StorageErrorKind::Io"
        );
    }

    let restored_perms = std::fs::metadata(&repos_dir).unwrap().permissions();
    assert_eq!(restored_perms.mode(), orig_perms.mode());
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn test_repo_discovery_root_replacement_vs_repos_replacement() {
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture.path();

    // Part 1: Rename/Replacement of the storage-root pathname
    let active_root = base.join("active_root");
    std::fs::create_dir_all(&active_root).unwrap();

    let hex_old = "1111111111111111111111111111111111111111111111111111111111111111";
    let old_manifests = active_root.join("repos").join("repo_old").join("manifests");
    std::fs::create_dir_all(&old_manifests).unwrap();
    write_file(&old_manifests.join(hex_old), b"{}");

    let storage = FsStorage::new(active_root.clone(), 1024 * 1024);

    let initial_repos = storage.list_repositories().await.unwrap();
    assert_eq!(initial_repos, vec!["repo_old".to_string()]);

    let backup_root = base.join("backup_root");
    std::fs::rename(&active_root, &backup_root).unwrap();
    std::fs::create_dir_all(&active_root).unwrap();

    let hex_new = "2222222222222222222222222222222222222222222222222222222222222222";
    let new_manifests = active_root.join("repos").join("repo_new").join("manifests");
    std::fs::create_dir_all(&new_manifests).unwrap();
    write_file(&new_manifests.join(hex_new), b"{}");

    // Contained catalog discovery resolves beneath the pinned root descriptor:
    // it continues to observe the ORIGINAL tree after the root pathname is
    // replaced (previously the ambient walk followed the replacement tree).
    let pinned_repos = storage.list_repositories().await.unwrap();
    assert_eq!(
        pinned_repos,
        vec!["repo_old".to_string()],
        "catalog discovery observes the pinned original root across pathname replacement"
    );

    // Contained manifest listing agrees: repo_old remains visible beneath the
    // pinned root, and repo_new (which exists only in the replacement tree) is
    // an empty page.
    let (page_old, _) = storage
        .list_manifest_digests_page("repo_old", None, 10)
        .await
        .unwrap();
    assert_eq!(
        page_old.len(),
        1,
        "pinned root_fd still contains repo_old after pathname replacement"
    );
    assert_eq!(page_old[0].hex(), hex_old);

    let (page, _) = storage
        .list_manifest_digests_page("repo_new", None, 10)
        .await
        .unwrap();
    assert!(
        page.is_empty(),
        "pinned root_fd does not contain repo_new; translates NotFound to empty page without error"
    );

    // Part 2: Replacement of repos/ beneath the SAME storage root
    let root_b = base.join("root_b");
    std::fs::create_dir_all(&root_b).unwrap();
    let storage_b = FsStorage::new(root_b.clone(), 1024 * 1024);

    let hex_b1 = "3333333333333333333333333333333333333333333333333333333333333333";
    let repos_dir_b = root_b.join("repos");
    let b1_manifests = repos_dir_b.join("repo_b1").join("manifests");
    std::fs::create_dir_all(&b1_manifests).unwrap();
    write_file(&b1_manifests.join(hex_b1), b"{}");

    let b_initial = storage_b.list_repositories().await.unwrap();
    assert_eq!(b_initial, vec!["repo_b1".to_string()]);

    let repos_backup = root_b.join("repos_backup");
    std::fs::rename(&repos_dir_b, &repos_backup).unwrap();
    std::fs::create_dir_all(&repos_dir_b).unwrap();

    let hex_b2 = "4444444444444444444444444444444444444444444444444444444444444444";
    let b2_manifests = repos_dir_b.join("repo_b2").join("manifests");
    std::fs::create_dir_all(&b2_manifests).unwrap();
    write_file(&b2_manifests.join(hex_b2), b"{}");

    let b_replaced = storage_b.list_repositories().await.unwrap();
    assert_eq!(b_replaced, vec!["repo_b2".to_string()]);

    let (page_b2, _) = storage_b
        .list_manifest_digests_page("repo_b2", None, 10)
        .await
        .unwrap();
    assert_eq!(
        page_b2.len(),
        1,
        "contained lookup relative to root_fd observes replacement repos/ beneath the same root"
    );
    assert_eq!(page_b2[0].hex(), hex_b2);
}

#[test]
fn test_fs_storage_try_new_with_gc_limits_validation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_path_buf();

    // 1. Valid default limits succeed
    assert!(
        FsStorage::try_new_with_gc_limits(
            root.clone(),
            50 * 1024 * 1024,
            storage_fs::DirEnumerationLimits::new(1000, 100_000),
            super::repo_discovery::DiscoveryLimits::default(),
            super::manifest_refs::ManifestReferenceLimits::default(),
        )
        .is_ok()
    );

    // 2. max_depth == 0
    let mut disc = super::repo_discovery::DiscoveryLimits::default();
    disc.max_depth = 0;
    let err = FsStorage::try_new_with_gc_limits(
        root.clone(),
        50 * 1024 * 1024,
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        disc,
        super::manifest_refs::ManifestReferenceLimits::default(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("max_depth"));

    // 3. max_manifests_read == 0
    let mut refs = super::manifest_refs::ManifestReferenceLimits::default();
    refs.max_manifests_read = 0;
    let err = FsStorage::try_new_with_gc_limits(
        root.clone(),
        50 * 1024 * 1024,
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        super::repo_discovery::DiscoveryLimits::default(),
        refs,
    )
    .unwrap_err();
    assert!(err.to_string().contains("max_manifests_read"));

    // 4. terminal name bytes < 128
    let mut refs_name = super::manifest_refs::ManifestReferenceLimits::default();
    refs_name.per_dir_limits = storage_fs::DirEnumerationLimits::new(1000, 64);
    let err = FsStorage::try_new_with_gc_limits(
        root.clone(),
        50 * 1024 * 1024,
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        super::repo_discovery::DiscoveryLimits::default(),
        refs_name,
    )
    .unwrap_err();
    assert!(err.to_string().contains("max_name_bytes"));
}

// --- Filesystem Tag Read Characterization Tests (resolve_tag & get_tag_with_version) ---

#[tokio::test]
async fn test_tag_read_missing_tag_and_missing_repository() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // 1. Missing repository directory
    let res_resolve = storage.resolve_tag("missing-repo", "missing-tag").await;
    assert!(matches!(res_resolve, Err(StorageError::NotFound)));

    let res_version = storage
        .get_tag_with_version("missing-repo", "missing-tag")
        .await
        .unwrap();
    assert_eq!(res_version, None);

    // 2. Existing repository with tags/ directory, but missing tag file
    let repo_dir = root.join("repos").join("existing-repo").join("tags");
    std::fs::create_dir_all(&repo_dir).unwrap();

    let res_resolve = storage.resolve_tag("existing-repo", "missing-tag").await;
    assert!(matches!(res_resolve, Err(StorageError::NotFound)));

    let res_version = storage
        .get_tag_with_version("existing-repo", "missing-tag")
        .await
        .unwrap();
    assert_eq!(res_version, None);
}

#[tokio::test]
async fn test_tag_read_valid_sha256_and_sha512_with_and_without_newline() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");

    // 1. SHA-256 with newline
    let hex256 = "1111111111111111111111111111111111111111111111111111111111111111";
    let bytes256_nl = format!("sha256:{hex256}\n").into_bytes();
    write_file(&tags_dir.join("tag256_nl"), &bytes256_nl);

    let d = storage.resolve_tag("myrepo", "tag256_nl").await.unwrap();
    assert_eq!(d.as_str(), format!("sha256:{hex256}"));
    let (d_v, v) = storage
        .get_tag_with_version("myrepo", "tag256_nl")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_v, d);
    assert_eq!(v, hex_sha256(&bytes256_nl));

    // 2. SHA-256 without newline
    let bytes256_raw = format!("sha256:{hex256}").into_bytes();
    write_file(&tags_dir.join("tag256_raw"), &bytes256_raw);

    let d = storage.resolve_tag("myrepo", "tag256_raw").await.unwrap();
    assert_eq!(d.as_str(), format!("sha256:{hex256}"));
    let (d_v, v) = storage
        .get_tag_with_version("myrepo", "tag256_raw")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_v, d);
    assert_eq!(v, hex_sha256(&bytes256_raw));

    // 3. SHA-512 with newline
    let hex512 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let bytes512_nl = format!("sha512:{hex512}\n").into_bytes();
    write_file(&tags_dir.join("tag512_nl"), &bytes512_nl);

    let d = storage.resolve_tag("myrepo", "tag512_nl").await.unwrap();
    assert_eq!(d.as_str(), format!("sha512:{hex512}"));
    let (d_v, v) = storage
        .get_tag_with_version("myrepo", "tag512_nl")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_v, d);
    assert_eq!(v, hex_sha256(&bytes512_nl));

    // 4. SHA-512 without newline
    let bytes512_raw = format!("sha512:{hex512}").into_bytes();
    write_file(&tags_dir.join("tag512_raw"), &bytes512_raw);

    let d = storage.resolve_tag("myrepo", "tag512_raw").await.unwrap();
    assert_eq!(d.as_str(), format!("sha512:{hex512}"));
    let (d_v, v) = storage
        .get_tag_with_version("myrepo", "tag512_raw")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_v, d);
    assert_eq!(v, hex_sha256(&bytes512_raw));
}

#[tokio::test]
async fn test_tag_read_whitespace_tabs_crlf_and_substantial_padding() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    let hex = "3333333333333333333333333333333333333333333333333333333333333333";

    // 1. Leading/trailing spaces, tabs, CRLF
    let bytes_crlf = format!("  \t \r\n sha256:{hex} \r\n\t  \n").into_bytes();
    write_file(&tags_dir.join("tag_crlf"), &bytes_crlf);

    let d = storage.resolve_tag("myrepo", "tag_crlf").await.unwrap();
    assert_eq!(d.hex(), hex);
    let (d_v, v) = storage
        .get_tag_with_version("myrepo", "tag_crlf")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_v, d);
    assert_eq!(v, hex_sha256(&bytes_crlf));

    // 2. Substantial whitespace padding exceeding 256 bytes
    let pad_before = " ".repeat(300);
    let pad_after = " ".repeat(300);
    let bytes_padded = format!("{pad_before}sha256:{hex}\n{pad_after}").into_bytes();
    assert!(bytes_padded.len() > 600, "padding must exceed 256 bytes");
    write_file(&tags_dir.join("tag_padded"), &bytes_padded);

    let d = storage.resolve_tag("myrepo", "tag_padded").await.unwrap();
    assert_eq!(d.hex(), hex);
    let (d_v, v) = storage
        .get_tag_with_version("myrepo", "tag_padded")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_v, d);
    assert_eq!(v, hex_sha256(&bytes_padded));
}

#[tokio::test]
async fn test_tag_read_empty_malformed_digest_and_invalid_utf8() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");

    // 1. Empty content (0 bytes)
    write_file(&tags_dir.join("tag_empty"), b"");
    let err_resolve = storage
        .resolve_tag("myrepo", "tag_empty")
        .await
        .unwrap_err();
    assert!(
        matches!(err_resolve, StorageError::NotFound),
        "empty tag content maps to NotFound in resolve_tag"
    );

    let err_version = storage
        .get_tag_with_version("myrepo", "tag_empty")
        .await
        .unwrap_err();
    match err_version {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => panic!("expected StorageErrorKind::CorruptData, got {other:?}"),
    }

    // 2. Malformed digest text
    write_file(&tags_dir.join("tag_malformed"), b"not-a-valid-digest\n");
    let err_resolve = storage
        .resolve_tag("myrepo", "tag_malformed")
        .await
        .unwrap_err();
    assert!(
        matches!(err_resolve, StorageError::NotFound),
        "malformed digest maps to NotFound in resolve_tag"
    );

    let err_version = storage
        .get_tag_with_version("myrepo", "tag_malformed")
        .await
        .unwrap_err();
    match err_version {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => panic!("expected StorageErrorKind::CorruptData, got {other:?}"),
    }

    // 3. Invalid UTF-8 sequence
    let invalid_utf8_bytes = b"\xff\xfe\xfd";
    write_file(&tags_dir.join("tag_invalid_utf8"), invalid_utf8_bytes);

    // Phase 3 converged: invalid UTF-8 in a stored tag payload is
    // CorruptData on every tag read path (the retired FS seam used Io).
    let err_resolve = storage
        .resolve_tag("myrepo", "tag_invalid_utf8")
        .await
        .unwrap_err();
    match err_resolve {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => {
            panic!("expected StorageErrorKind::CorruptData for invalid UTF-8, got {other:?}")
        }
    }

    // get_tag_with_version uses from_utf8_lossy -> Digest::parse fails -> StorageErrorKind::CorruptData
    let err_version = storage
        .get_tag_with_version("myrepo", "tag_invalid_utf8")
        .await
        .unwrap_err();
    match err_version {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => panic!("expected StorageErrorKind::CorruptData, got {other:?}"),
    }
}

#[tokio::test]
async fn test_tag_read_version_hashes_raw_byte_sensitivity() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    let hex = "5555555555555555555555555555555555555555555555555555555555555555";

    let c1 = format!("sha256:{hex}\n").into_bytes();
    let c2 = format!("sha256:{hex}").into_bytes();
    let c3 = format!("sha256:{hex}\r\n").into_bytes();
    let c4 = format!("  sha256:{hex}\n").into_bytes();

    write_file(&tags_dir.join("t1"), &c1);
    write_file(&tags_dir.join("t2"), &c2);
    write_file(&tags_dir.join("t3"), &c3);
    write_file(&tags_dir.join("t4"), &c4);

    let (d1, v1) = storage
        .get_tag_with_version("myrepo", "t1")
        .await
        .unwrap()
        .unwrap();
    let (d2, v2) = storage
        .get_tag_with_version("myrepo", "t2")
        .await
        .unwrap()
        .unwrap();
    let (d3, v3) = storage
        .get_tag_with_version("myrepo", "t3")
        .await
        .unwrap()
        .unwrap();
    let (d4, v4) = storage
        .get_tag_with_version("myrepo", "t4")
        .await
        .unwrap()
        .unwrap();

    // All 4 parse to the exact same logical Digest
    assert_eq!(d1, d2);
    assert_eq!(d2, d3);
    assert_eq!(d3, d4);
    assert_eq!(d1.hex(), hex);

    // But all 4 produce pairwise distinct version strings because hasher hashes raw bytes
    assert_ne!(
        v1, v2,
        "newline vs no newline must produce different versions"
    );
    assert_ne!(v1, v3, "LF vs CRLF must produce different versions");
    assert_ne!(v1, v4, "plain vs padded must produce different versions");
    assert_ne!(v2, v3);
    assert_ne!(v2, v4);
    assert_ne!(v3, v4);

    // Re-reading identical content produces identical version
    let (_, v1_again) = storage
        .get_tag_with_version("myrepo", "t1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(v1, v1_again);
}

#[tokio::test]
#[cfg(unix)]
async fn test_tag_read_controlled_symlinks() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("storage-root");
    let ext_dir = fixture.path().join("external-dir");
    std::fs::create_dir_all(&ext_dir).unwrap();

    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex_internal = "6666666666666666666666666666666666666666666666666666666666666666";
    let hex_external = "7777777777777777777777777777777777777777777777777777777777777777";
    let hex_ancestor = "8888888888888888888888888888888888888888888888888888888888888888";

    // 1. Final tag symlink targeting inside the fixture storage root
    let target_file = tags_dir.join("real_tag");
    write_file(&target_file, format!("sha256:{hex_internal}\n").as_bytes());
    std::os::unix::fs::symlink(&target_file, tags_dir.join("symlink_internal")).unwrap();

    let err_resolve = storage
        .resolve_tag("myrepo", "symlink_internal")
        .await
        .unwrap_err();
    match err_resolve {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::PermissionDenied),
        other => {
            panic!(
                "expected StorageErrorKind::PermissionDenied for symlink_internal resolve_tag, got {other:?}"
            )
        }
    }
    let err_version = storage
        .get_tag_with_version("myrepo", "symlink_internal")
        .await
        .unwrap_err();
    match err_version {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::PermissionDenied),
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for symlink_internal get_tag_with_version, got {other:?}"
        ),
    }

    // 2. Final tag symlink targeting a sibling directory outside that root but inside the temporary fixture
    let ext_file = ext_dir.join("ext_tag_file");
    write_file(&ext_file, format!("sha256:{hex_external}\n").as_bytes());
    std::os::unix::fs::symlink(&ext_file, tags_dir.join("symlink_external")).unwrap();

    let err_ext = storage
        .resolve_tag("myrepo", "symlink_external")
        .await
        .unwrap_err();
    match err_ext {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::PermissionDenied),
        other => {
            panic!(
                "expected StorageErrorKind::PermissionDenied for symlink_external resolve_tag, got {other:?}"
            )
        }
    }
    let err_ext_v = storage
        .get_tag_with_version("myrepo", "symlink_external")
        .await
        .unwrap_err();
    match err_ext_v {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::PermissionDenied),
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for symlink_external get_tag_with_version, got {other:?}"
        ),
    }

    // 3. Ancestor directory symlink (symlinked tags/ directory)
    let ext_tags_dir = ext_dir.join("external_tags");
    std::fs::create_dir_all(&ext_tags_dir).unwrap();
    write_file(
        &ext_tags_dir.join("ancestor_tag"),
        format!("sha256:{hex_ancestor}\n").as_bytes(),
    );

    let repo_ancestor_dir = root.join("repos").join("ancestor_repo");
    std::fs::create_dir_all(&repo_ancestor_dir).unwrap();
    std::os::unix::fs::symlink(&ext_tags_dir, repo_ancestor_dir.join("tags")).unwrap();

    let err_anc = storage
        .resolve_tag("ancestor_repo", "ancestor_tag")
        .await
        .unwrap_err();
    match err_anc {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::PermissionDenied),
        other => {
            panic!(
                "expected StorageErrorKind::PermissionDenied for ancestor symlink resolve_tag, got {other:?}"
            )
        }
    }
    let err_anc_v = storage
        .get_tag_with_version("ancestor_repo", "ancestor_tag")
        .await
        .unwrap_err();
    match err_anc_v {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::PermissionDenied),
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for ancestor symlink get_tag_with_version, got {other:?}"
        ),
    }

    // 4. Dangling symlink
    std::os::unix::fs::symlink(
        ext_dir.join("non_existent_target"),
        tags_dir.join("dangling_symlink"),
    )
    .unwrap();
    let err_dang = storage
        .resolve_tag("myrepo", "dangling_symlink")
        .await
        .unwrap_err();
    match err_dang {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::PermissionDenied),
        other => {
            panic!(
                "expected StorageErrorKind::PermissionDenied for dangling symlink resolve_tag, got {other:?}"
            )
        }
    }
    let err_dang_v = storage
        .get_tag_with_version("myrepo", "dangling_symlink")
        .await
        .unwrap_err();
    match err_dang_v {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::PermissionDenied),
        other => panic!(
            "expected StorageErrorKind::PermissionDenied for dangling symlink get_tag_with_version, got {other:?}"
        ),
    }
}

#[tokio::test]
async fn test_tag_read_directory_in_place_of_file() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");

    // Directory in place of a tag file
    let dir_tag_path = tags_dir.join("dir_tag");
    std::fs::create_dir_all(&dir_tag_path).unwrap();

    // Phase 3 converged: a non-regular leaf is NOT a tag object — structural
    // absence, matching the generic listing contract (the retired FS seam
    // surfaced an Io error; on S3 a "directory" is nothing at all).
    let err_resolve = storage.resolve_tag("myrepo", "dir_tag").await.unwrap_err();
    assert!(
        matches!(err_resolve, StorageError::NotFound),
        "directory in place of a tag is structural absence, got {err_resolve:?}"
    );

    let version_res = storage
        .get_tag_with_version("myrepo", "dir_tag")
        .await
        .expect("structural absence is not an error for get_tag_with_version");
    assert!(version_res.is_none());
}

#[tokio::test]
#[cfg(unix)]
#[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
async fn test_tag_read_permission_denied() {
    use std::os::unix::fs::PermissionsExt;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    let tag_file = tags_dir.join("perm_tag");
    write_file(
        &tag_file,
        b"sha256:1111111111111111111111111111111111111111111111111111111111111111\n",
    );

    let orig_perms = std::fs::metadata(&tag_file).unwrap().permissions();

    struct ScopedPermReset<'a> {
        path: &'a std::path::Path,
        original_permissions: std::fs::Permissions,
    }
    impl<'a> Drop for ScopedPermReset<'a> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, self.original_permissions.clone());
        }
    }

    {
        let _guard = ScopedPermReset {
            path: &tag_file,
            original_permissions: orig_perms.clone(),
        };
        std::fs::set_permissions(&tag_file, std::fs::Permissions::from_mode(0o000)).unwrap();

        match std::fs::read(&tag_file) {
            Ok(_) => panic!("ineffective permissions: read succeeded under mode 0o000"),
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied),
        }

        let err_resolve = storage.resolve_tag("myrepo", "perm_tag").await.unwrap_err();
        match err_resolve {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected StorageErrorKind::Io for permission denial, got {other:?}"),
        }

        let err_version = storage
            .get_tag_with_version("myrepo", "perm_tag")
            .await
            .unwrap_err();
        match err_version {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected StorageErrorKind::Io for permission denial, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_tag_read_path_component_and_traversal_cases() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("storage-root");
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let hex = "9999999999999999999999999999999999999999999999999999999999999999";

    // 1. Carefully scoped traversal input: target placed in parent repos/ directory
    // When tags/ directory exists, tag_path("myrepo", "../outside.txt") evaluates to
    // root/repos/myrepo/tags/../outside.txt, traversing through '..' back to root/repos/myrepo/outside.txt
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();
    let outside_file = root.join("repos").join("myrepo").join("outside.txt");
    write_file(&outside_file, format!("sha256:{hex}\n").as_bytes());

    let err_outside = storage
        .resolve_tag("myrepo", "../outside.txt")
        .await
        .unwrap_err();
    assert!(
        matches!(err_outside, StorageError::InvalidRepoName(_)),
        "resolve_tag rejects '..' traversal in tag name with InvalidRepoName, got {err_outside:?}"
    );
    let err_outside_v = storage
        .get_tag_with_version("myrepo", "../outside.txt")
        .await
        .unwrap_err();
    assert!(
        matches!(err_outside_v, StorageError::InvalidRepoName(_)),
        "get_tag_with_version rejects '..' traversal in tag name with InvalidRepoName, got {err_outside_v:?}"
    );

    // 2. Subdirectory component in tag: "sub/nested_tag"
    let nested_file = root
        .join("repos")
        .join("myrepo")
        .join("tags")
        .join("sub")
        .join("nested_tag");
    write_file(&nested_file, format!("sha256:{hex}\n").as_bytes());

    let d_sub = storage
        .resolve_tag("myrepo", "sub/nested_tag")
        .await
        .unwrap();
    assert_eq!(
        d_sub.hex(),
        hex,
        "nested tag path components remain supported under contained tag reading"
    );
    let (d_sub_v, _) = storage
        .get_tag_with_version("myrepo", "sub/nested_tag")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_sub_v.hex(), hex);

    // 3. Controlled repository-argument traversal case for both read methods
    // When repos/ directory exists, tag_path("../sibling_repo", "mytag") evaluates to
    // root/repos/../sibling_repo/tags/mytag -> root/sibling_repo/tags/mytag
    let sibling_tag_file = root.join("sibling_repo").join("tags").join("mytag");
    write_file(&sibling_tag_file, format!("sha256:{hex}\n").as_bytes());

    let err_repo = storage
        .resolve_tag("../sibling_repo", "mytag")
        .await
        .unwrap_err();
    assert!(
        matches!(err_repo, StorageError::InvalidRepoName(_)),
        "resolve_tag rejects '..' in repository argument with InvalidRepoName, got {err_repo:?}"
    );
    let err_repo_v = storage
        .get_tag_with_version("../sibling_repo", "mytag")
        .await
        .unwrap_err();
    assert!(
        matches!(err_repo_v, StorageError::InvalidRepoName(_)),
        "get_tag_with_version rejects '..' in repository argument with InvalidRepoName, got {err_repo_v:?}"
    );
}

#[tokio::test]
async fn test_tag_read_sequential_root_replacement_observed_tree() {
    let fixture = tempfile::tempdir().unwrap();
    let root_path = fixture.path().join("storage-root");
    std::fs::create_dir_all(&root_path).unwrap();

    let storage = FsStorage::new(root_path.clone(), 1024 * 1024);

    let hex_orig = "1111111111111111111111111111111111111111111111111111111111111111";
    let hex_repl = "2222222222222222222222222222222222222222222222222222222222222222";

    // 1. Initial tag write
    write_file(
        &root_path
            .join("repos")
            .join("myrepo")
            .join("tags")
            .join("latest"),
        format!("sha256:{hex_orig}\n").as_bytes(),
    );

    let d_orig = storage.resolve_tag("myrepo", "latest").await.unwrap();
    assert_eq!(d_orig.hex(), hex_orig);
    let (d_orig_v, v_orig) = storage
        .get_tag_with_version("myrepo", "latest")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_orig_v.hex(), hex_orig);
    assert_eq!(
        v_orig,
        hex_sha256(format!("sha256:{hex_orig}\n").as_bytes())
    );

    // 2. Sequential root directory replacement: rename root to root_old, and recreate fresh directory at root_path
    let root_old = fixture.path().join("storage-root-old");
    std::fs::rename(&root_path, &root_old).unwrap();
    std::fs::create_dir_all(&root_path).unwrap();

    write_file(
        &root_path
            .join("repos")
            .join("myrepo")
            .join("tags")
            .join("latest"),
        format!("sha256:{hex_repl}\n").as_bytes(),
    );

    // 3. Contained resolve_tag and get_tag_with_version use self.reader;
    // self.reader retains its descriptor pinned to root_old, observing hex_orig!
    let d_observed = storage.resolve_tag("myrepo", "latest").await.unwrap();
    assert_eq!(
        d_observed.hex(),
        hex_orig,
        "contained resolve_tag observes pinned root_fd tree, demonstrating root pinning"
    );
    let (d_observed_v, v_observed) = storage
        .get_tag_with_version("myrepo", "latest")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        d_observed_v.hex(),
        hex_orig,
        "contained get_tag_with_version observes pinned root digest"
    );
    assert_eq!(
        v_observed,
        hex_sha256(format!("sha256:{hex_orig}\n").as_bytes()),
        "contained get_tag_with_version computes version from pinned root bytes"
    );
}

#[tokio::test]
async fn test_tag_conditional_delete_version_precondition_role() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");

    let hex1 = "1111111111111111111111111111111111111111111111111111111111111111";
    let hex2 = "2222222222222222222222222222222222222222222222222222222222222222";

    let c1 = format!("sha256:{hex1}\n").into_bytes();
    let tag_file = tags_dir.join("mytag");
    write_file(&tag_file, &c1);

    // 1. Observe initial tag version
    let (d1, v1) = storage
        .get_tag_with_version("myrepo", "mytag")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d1.hex(), hex1);
    assert_eq!(v1, hex_sha256(&c1));

    // 2. Case A: Changed bytes cause expected PreconditionFailed and preserve replacement
    let c2 = format!("sha256:{hex2}\n").into_bytes();
    write_file(&tag_file, &c2);

    let del_res = storage
        .delete_tag_conditional("myrepo", "mytag", Some(&v1))
        .await
        .unwrap();

    let v2 = hex_sha256(&c2);
    assert_eq!(
        del_res,
        crate::storage::ConditionalDeleteResult::PreconditionFailed {
            current_version: Some(v2.clone())
        },
        "changed bytes must cause PreconditionFailed"
    );
    assert!(
        tag_file.exists(),
        "replacement tag file must be preserved on disk"
    );
    assert_eq!(std::fs::read(&tag_file).unwrap(), c2);

    // 3. Case B: Changed whitespace (same parsed digest) also causes PreconditionFailed
    let c2_no_nl = format!("sha256:{hex2}").into_bytes();
    write_file(&tag_file, &c2_no_nl);

    let del_res_ws = storage
        .delete_tag_conditional("myrepo", "mytag", Some(&v2))
        .await
        .unwrap();

    let v2_no_nl = hex_sha256(&c2_no_nl);
    assert_eq!(
        del_res_ws,
        crate::storage::ConditionalDeleteResult::PreconditionFailed {
            current_version: Some(v2_no_nl.clone())
        },
        "whitespace changes cause PreconditionFailed because version hashes raw bytes"
    );

    // 4. Case C: Deletion succeeds with matching expected version
    let del_success = storage
        .delete_tag_conditional("myrepo", "mytag", Some(&v2_no_nl))
        .await
        .unwrap();
    assert_eq!(
        del_success,
        crate::storage::ConditionalDeleteResult::Deleted
    );
    assert!(
        !tag_file.exists(),
        "tag file must be unlinked after successful deletion"
    );

    // 5. Case D: Identical byte content produces same version; version does not detect intervening write
    write_file(&tag_file, &c1);
    let (_, v1_recreated) = storage
        .get_tag_with_version("myrepo", "mytag")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        v1_recreated, v1,
        "identical byte content produces identical version hash; version does not detect replacement if bytes match"
    );
}

#[tokio::test]
async fn test_fs_storage_tag_read_production_contract_and_entry_points() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    // 1. Valid SHA-256 with leading/trailing whitespace
    let hex_val_256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let raw_sha256 = format!("  \n sha256:{hex_val_256} \t\n ");
    write_file(&tags_dir.join("tag-sha256"), raw_sha256.as_bytes());

    let d256 = storage.resolve_tag("myrepo", "tag-sha256").await.unwrap();
    assert_eq!(d256.hex(), hex_val_256);
    let (d256_v, v256) = storage
        .get_tag_with_version("myrepo", "tag-sha256")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d256_v.hex(), hex_val_256);
    assert_eq!(v256, hex_sha256(raw_sha256.as_bytes()));

    // 2. Valid SHA-512
    let hex_val_512 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let raw_sha512 = format!("sha512:{hex_val_512}\n");
    write_file(&tags_dir.join("tag-sha512"), raw_sha512.as_bytes());

    let d512 = storage.resolve_tag("myrepo", "tag-sha512").await.unwrap();
    assert_eq!(d512.hex(), hex_val_512);
    let (d512_v, v512) = storage
        .get_tag_with_version("myrepo", "tag-sha512")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d512_v.hex(), hex_val_512);
    assert_eq!(v512, hex_sha256(raw_sha512.as_bytes()));

    // 3. Phase 3 converged: point reads are BOUNDED by the configured tag
    // payload ceiling (default 1024); an oversized object maps to the
    // accepted drain-overflow CorruptData instead of unbounded buffering.
    let padding = " ".repeat(70 * 1024);
    let raw_large = format!("{padding}sha256:{hex_val_256}\n{padding}");
    assert!(raw_large.len() > 64 * 1024);
    write_file(&tags_dir.join("tag-large"), raw_large.as_bytes());

    let err_large = storage
        .resolve_tag("myrepo", "tag-large")
        .await
        .unwrap_err();
    assert_eq!(
        err_large.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );
    assert!(err_large.to_string().contains("exceeds limit"));
    let err_large_v = storage
        .get_tag_with_version("myrepo", "tag-large")
        .await
        .unwrap_err();
    assert_eq!(
        err_large_v.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );

    // Padded payloads WITHIN the ceiling keep the exact historical
    // trim/parse/raw-byte-version behavior.
    let small_padding = " ".repeat(64);
    let raw_padded = format!("{small_padding}sha256:{hex_val_256}\n{small_padding}");
    write_file(&tags_dir.join("tag-padded"), raw_padded.as_bytes());
    let d_padded = storage.resolve_tag("myrepo", "tag-padded").await.unwrap();
    assert_eq!(d_padded.hex(), hex_val_256);
    let (d_padded_v, v_padded) = storage
        .get_tag_with_version("myrepo", "tag-padded")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(d_padded_v.hex(), hex_val_256);
    assert_eq!(v_padded, hex_sha256(raw_padded.as_bytes()));

    // 4. Missing tag
    let err_missing = storage
        .resolve_tag("myrepo", "nonexistent")
        .await
        .unwrap_err();
    assert!(matches!(err_missing, StorageError::NotFound));
    let opt_missing = storage
        .get_tag_with_version("myrepo", "nonexistent")
        .await
        .unwrap();
    assert_eq!(opt_missing, None);

    // 5. Empty file: resolve_tag -> NotFound; get_tag_with_version -> CorruptData
    write_file(&tags_dir.join("tag-empty"), b"");
    let err_empty_res = storage
        .resolve_tag("myrepo", "tag-empty")
        .await
        .unwrap_err();
    assert!(matches!(err_empty_res, StorageError::NotFound));
    let err_empty_ver = storage
        .get_tag_with_version("myrepo", "tag-empty")
        .await
        .unwrap_err();
    match err_empty_ver {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => panic!("expected CorruptData for empty tag file, got {other:?}"),
    }

    // 6. Malformed digest text: resolve_tag -> NotFound; get_tag_with_version -> CorruptData
    write_file(&tags_dir.join("tag-malformed"), b"not-a-digest\n");
    let err_mal_res = storage
        .resolve_tag("myrepo", "tag-malformed")
        .await
        .unwrap_err();
    assert!(matches!(err_mal_res, StorageError::NotFound));
    let err_mal_ver = storage
        .get_tag_with_version("myrepo", "tag-malformed")
        .await
        .unwrap_err();
    match err_mal_ver {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => panic!("expected CorruptData for malformed tag text, got {other:?}"),
    }

    // 7. Invalid UTF-8 bytes: CorruptData on both readers (Phase 3
    // convergence; the retired FS seam used Io on resolve_tag).
    write_file(&tags_dir.join("tag-invalid-utf8"), &[0xff, 0xfe, 0xfd]);
    let err_utf8_res = storage
        .resolve_tag("myrepo", "tag-invalid-utf8")
        .await
        .unwrap_err();
    match err_utf8_res {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => panic!("expected CorruptData for invalid UTF-8 in resolve_tag, got {other:?}"),
    }
    let err_utf8_ver = storage
        .get_tag_with_version("myrepo", "tag-invalid-utf8")
        .await
        .unwrap_err();
    match err_utf8_ver {
        StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::CorruptData),
        other => {
            panic!("expected CorruptData for invalid UTF-8 in get_tag_with_version, got {other:?}")
        }
    }

    // 8. Structural validation rejections
    for bad_repo in [
        "",
        "/leading",
        "trailing/",
        "a//b",
        "a\\b",
        "a\0b",
        "a\x01b",
        ".",
        "..",
    ] {
        let res = storage.resolve_tag(bad_repo, "latest").await;
        assert!(
            matches!(res, Err(StorageError::InvalidRepoName(_))),
            "repo '{bad_repo}' must be rejected with InvalidRepoName, got {res:?}"
        );
        let ver = storage.get_tag_with_version(bad_repo, "latest").await;
        assert!(
            matches!(ver, Err(StorageError::InvalidRepoName(_))),
            "repo '{bad_repo}' must be rejected with InvalidRepoName, got {ver:?}"
        );
    }

    for bad_tag in [
        "",
        "/leading",
        "trailing/",
        "a//b",
        "a\\b",
        "a\0b",
        "a\x1fb",
        ".",
        "..",
    ] {
        let res = storage.resolve_tag("myrepo", bad_tag).await;
        assert!(
            matches!(res, Err(StorageError::InvalidRepoName(_))),
            "tag '{bad_tag}' must be rejected with InvalidRepoName, got {res:?}"
        );
        let ver = storage.get_tag_with_version("myrepo", bad_tag).await;
        assert!(
            matches!(ver, Err(StorageError::InvalidRepoName(_))),
            "tag '{bad_tag}' must be rejected with InvalidRepoName, got {ver:?}"
        );
    }
}

#[tokio::test]
async fn test_tag_listing_missing_and_empty_directories() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    // 1. Missing repository: list_tags yields StorageError::NotFound, but list_tags_page yields Ok(([], None))
    let res_list = storage.list_tags("nonexistent-repo").await;
    assert!(
        matches!(res_list, Err(StorageError::NotFound)),
        "list_tags on missing repo must return StorageError::NotFound, got: {res_list:?}"
    );

    let res_page = storage
        .list_tags_page("nonexistent-repo", None, 10)
        .await
        .unwrap();
    assert_eq!(
        res_page,
        (Vec::new(), None),
        "list_tags_page on missing repo returns empty page without error"
    );

    // 2. Repository exists, but tags/ directory does not:
    let repo_dir = root.join("repos").join("existing-no-tags");
    std::fs::create_dir_all(repo_dir.join("manifests")).unwrap();

    let res_no_tags = storage.list_tags("existing-no-tags").await.unwrap();
    assert!(
        res_no_tags.is_empty(),
        "list_tags on repo without tags dir returns empty list"
    );

    let res_page_no_tags = storage
        .list_tags_page("existing-no-tags", None, 10)
        .await
        .unwrap();
    assert_eq!(
        res_page_no_tags,
        (Vec::new(), None),
        "list_tags_page on repo without tags dir returns empty page"
    );

    // 3. tags/ directory exists but is empty:
    let empty_tags_dir = root.join("repos").join("empty-tags-repo").join("tags");
    std::fs::create_dir_all(&empty_tags_dir).unwrap();

    let res_empty = storage.list_tags("empty-tags-repo").await.unwrap();
    assert!(
        res_empty.is_empty(),
        "list_tags on empty tags directory returns empty list"
    );

    let res_page_empty = storage
        .list_tags_page("empty-tags-repo", None, 10)
        .await
        .unwrap();
    assert_eq!(
        res_page_empty,
        (Vec::new(), None),
        "list_tags_page on empty tags directory returns empty page"
    );
}

#[tokio::test]
async fn test_tag_listing_valid_sha256_and_sha512_formats() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let hex512 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    write_file(
        &tags_dir.join("tag-sha256"),
        format!("sha256:{hex256}\n").as_bytes(),
    );
    write_file(
        &tags_dir.join("tag-sha512"),
        format!("sha512:{hex512}\n").as_bytes(),
    );

    let tags = storage.list_tags("myrepo").await.unwrap();
    assert_eq!(tags, vec!["tag-sha256", "tag-sha512"]);

    let (page, next_tok) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
    assert_eq!(next_tok, None);
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].0, "tag-sha256");
    assert_eq!(page[0].1.as_str(), format!("sha256:{hex256}"));
    assert_eq!(page[1].0, "tag-sha512");
    assert_eq!(page[1].1.as_str(), format!("sha512:{hex512}"));
}

#[tokio::test]
async fn test_tag_listing_whitespace_tabs_crlf_and_substantial_padding() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex = "1111111111111111111111111111111111111111111111111111111111111111";
    write_file(
        &tags_dir.join("t1-clean"),
        format!("sha256:{hex}").as_bytes(),
    );
    write_file(
        &tags_dir.join("t2-crlf"),
        format!("\r\n  sha256:{hex}\r\n").as_bytes(),
    );
    write_file(
        &tags_dir.join("t3-tabs"),
        format!("\t\tsha256:{hex}\t\n").as_bytes(),
    );
    let mut padded = Vec::new();
    padded.extend(b"\n");
    padded.extend(vec![b' '; 1024]);
    padded.extend(format!("sha256:{hex}").as_bytes());
    padded.extend(vec![b' '; 512]);
    padded.extend(b"\n");
    write_file(&tags_dir.join("t4-padded"), &padded);

    let tags = storage.list_tags("myrepo").await.unwrap();
    assert_eq!(tags, vec!["t1-clean", "t2-crlf", "t3-tabs", "t4-padded"]);

    // In contained paged listing, t4-padded exceeds the 1024-byte ceiling and fails closed with CorruptData
    let paged_err = storage
        .list_tags_page("myrepo", None, 10)
        .await
        .expect_err("t4-padded exceeds 1024-byte payload ceiling");
    assert_eq!(
        paged_err.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );
    assert!(
        paged_err
            .to_string()
            .contains("stream length exceeds limit of 1024 bytes")
    );

    // Phase 3 converged: point reads share the SAME configured payload
    // ceiling, so the oversized t4-padded fails them identically (the
    // retired FS seams read point payloads unbounded).
    let err_point = storage
        .resolve_tag("myrepo", "t4-padded")
        .await
        .expect_err("resolve_tag is bounded by the configured payload ceiling");
    assert_eq!(
        err_point.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );

    let err_point_v = storage
        .get_tag_with_version("myrepo", "t4-padded")
        .await
        .expect_err("get_tag_with_version is bounded by the configured payload ceiling");
    assert_eq!(
        err_point_v.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );

    // Remove oversized t4-padded and replace with t4-fit within 1024 bytes
    std::fs::remove_file(tags_dir.join("t4-padded")).unwrap();
    let mut fit = Vec::new();
    fit.extend(b"\r\n");
    fit.extend(vec![b' '; 200]);
    fit.extend(format!("sha256:{hex}").as_bytes());
    fit.extend(vec![b' '; 100]);
    fit.extend(b"\r\n");
    write_file(&tags_dir.join("t4-fit"), &fit);

    let (page, _) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
    assert_eq!(page.len(), 4);
    for (_name, digest) in page {
        assert_eq!(digest.as_str(), format!("sha256:{hex}"));
    }
}

#[tokio::test]
async fn test_tag_listing_empty_malformed_and_invalid_utf8_taxonomy() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex = "2222222222222222222222222222222222222222222222222222222222222222";
    write_file(
        &tags_dir.join("tag-valid"),
        format!("sha256:{hex}").as_bytes(),
    );
    write_file(&tags_dir.join("tag-empty"), b"");
    write_file(&tags_dir.join("tag-malformed"), b"not-a-digest\n");
    write_file(
        &tags_dir.join("tag-bad-hex"),
        b"sha256:zzzz000000000000000000000000000000000000000000000000000000000000\n",
    );
    write_file(&tags_dir.join("tag-invalid-utf8"), &[0xff, 0xfe, 0xfd]);

    // 1. list_tags returns ALL valid filenames without inspecting file contents
    let tags = storage.list_tags("myrepo").await.unwrap();
    assert_eq!(
        tags,
        vec![
            "tag-bad-hex",
            "tag-empty",
            "tag-invalid-utf8",
            "tag-malformed",
            "tag-valid"
        ]
    );

    // 2. list_tags_page fails closed with CorruptData when encountering
    // tag-invalid-utf8 (Phase 3 converged kind; the retired FS seam used Io)
    let err_page = storage
        .list_tags_page("myrepo", None, 10)
        .await
        .expect_err("invalid UTF-8 payload must fail closed");
    assert_eq!(
        err_page.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );
    assert!(
        err_page
            .to_string()
            .contains("invalid UTF-8 in tag payload")
    );

    // 3. When invalid UTF-8 file is removed, list_tags_page silently omits corrupt, empty, and unparsable files
    std::fs::remove_file(tags_dir.join("tag-invalid-utf8")).unwrap();
    let (page, next_tok) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
    assert_eq!(next_tok, None);
    assert_eq!(
        page.len(),
        1,
        "list_tags_page must silently omit unparsable and empty files"
    );
    assert_eq!(page[0].0, "tag-valid");
    assert_eq!(page[0].1.hex(), hex);
}

#[tokio::test]
async fn test_tag_listing_dotfiles_locks_temps_and_nested_directories() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex = "3333333333333333333333333333333333333333333333333333333333333333";
    write_file(
        &tags_dir.join("normal-tag"),
        format!("sha256:{hex}").as_bytes(),
    );
    write_file(
        &tags_dir.join(".hidden-tag"),
        format!("sha256:{hex}").as_bytes(),
    );
    write_file(&tags_dir.join(".lock.normal-tag"), b"lock-meta");
    write_file(
        &tags_dir.join(".tmp.upload.123"),
        format!("sha256:{hex}").as_bytes(),
    );
    write_file(
        &tags_dir.join("non-dot-temp.upload"),
        format!("sha256:{hex}").as_bytes(),
    );

    // Create a nested subdirectory inside tags/
    std::fs::create_dir_all(tags_dir.join("nested-dir")).unwrap();

    // 1. In contained listing, list_tags filters out dotfiles AND non-regular entries (nested-dir)
    let tags = storage.list_tags("myrepo").await.unwrap();
    assert_eq!(
        tags,
        vec!["non-dot-temp.upload", "normal-tag"],
        "contained list_tags excludes non-dot directories because it filters by Regular file type"
    );

    // 2. list_tags_page filters out dotfiles and excludes non-regular entries
    let (page, _) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
    assert_eq!(
        page.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["non-dot-temp.upload", "normal-tag"],
        "contained list_tags_page excludes directories via file type filtering"
    );
}

#[tokio::test]
async fn test_tag_listing_non_utf8_filenames() {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let tags_dir = root.join("repos").join("myrepo").join("tags");
        std::fs::create_dir_all(&tags_dir).unwrap();

        let hex = "4444444444444444444444444444444444444444444444444444444444444444";
        write_file(
            &tags_dir.join("valid-tag"),
            format!("sha256:{hex}").as_bytes(),
        );

        let invalid_os_str = std::ffi::OsStr::from_bytes(b"invalid-\xff-tag");
        let invalid_path = tags_dir.join(invalid_os_str);
        std::fs::write(&invalid_path, format!("sha256:{hex}").as_bytes()).unwrap();

        // Both list_tags and list_tags_page filter entries via file_name().to_str(),
        // so invalid UTF-8 filenames return None and are silently skipped.
        let tags = storage.list_tags("myrepo").await.unwrap();
        assert_eq!(tags, vec!["valid-tag"]);

        let (page, _) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].0, "valid-tag");
    }
}

#[tokio::test]
async fn test_tag_listing_path_traversal_and_structural_inputs() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);

    let hex = "9999999999999999999999999999999999999999999999999999999999999999";

    // 1. Populated Traversal Fixture:
    // Create repos/target_repo/tags/target_tag
    let target_tags = root.join("repos").join("target_repo").join("tags");
    std::fs::create_dir_all(&target_tags).unwrap();
    write_file(
        &target_tags.join("target_tag"),
        format!("sha256:{hex}\n").as_bytes(),
    );

    // Create repos/dummy_dir
    let dummy_dir = root.join("repos").join("dummy_dir");
    std::fs::create_dir_all(&dummy_dir).unwrap();

    // 1. Path traversal attempts are rejected upfront with InvalidRepoName
    let listed_err = storage
        .list_tags("dummy_dir/../target_repo")
        .await
        .expect_err("path traversal in list_tags must fail upfront");
    assert!(matches!(listed_err, StorageError::InvalidRepoName(_)));

    let page_err = storage
        .list_tags_page("dummy_dir/../target_repo", None, 10)
        .await
        .expect_err("path traversal in list_tags_page must fail upfront");
    assert!(matches!(page_err, StorageError::InvalidRepoName(_)));

    // 2. Nested multi-segment repository input:
    let nested_tags = root
        .join("repos")
        .join("org")
        .join("team")
        .join("nested_repo")
        .join("tags");
    std::fs::create_dir_all(&nested_tags).unwrap();
    write_file(
        &nested_tags.join("nested_tag"),
        format!("sha256:{hex}\n").as_bytes(),
    );

    let nested_list = storage.list_tags("org/team/nested_repo").await.unwrap();
    assert_eq!(nested_list, vec!["nested_tag"]);
    let (nested_page, _) = storage
        .list_tags_page("org/team/nested_repo", None, 10)
        .await
        .unwrap();
    assert_eq!(nested_page.len(), 1);
    assert_eq!(nested_page[0].0, "nested_tag");

    // 3. Absolute path input:
    // Leading slashes are rejected upfront with InvalidRepoName:
    let abs_fixture = tempfile::tempdir().unwrap();
    let abs_tags = abs_fixture.path().join("tags");
    std::fs::create_dir_all(&abs_tags).unwrap();
    write_file(
        &abs_tags.join("abs_tag"),
        format!("sha256:{hex}\n").as_bytes(),
    );

    let abs_repo_str = abs_fixture.path().to_str().unwrap();
    let abs_list_err = storage
        .list_tags(abs_repo_str)
        .await
        .expect_err("absolute repo path must be rejected with InvalidRepoName");
    assert!(matches!(abs_list_err, StorageError::InvalidRepoName(_)));
    let abs_page_err = storage
        .list_tags_page(abs_repo_str, None, 10)
        .await
        .expect_err("absolute repo path must be rejected with InvalidRepoName");
    assert!(matches!(abs_page_err, StorageError::InvalidRepoName(_)));

    // 4. Invalid inputs:
    // Empty repository name "": rejected upfront with InvalidRepoName
    let empty_res = storage
        .list_tags("")
        .await
        .expect_err("empty repo name must be rejected with InvalidRepoName");
    assert!(matches!(empty_res, StorageError::InvalidRepoName(_)));
    let empty_page_err = storage
        .list_tags_page("", None, 10)
        .await
        .expect_err("empty repo name must be rejected with InvalidRepoName");
    assert!(matches!(empty_page_err, StorageError::InvalidRepoName(_)));

    // Absent traversal path "../absent": rejected upfront with InvalidRepoName
    let absent_res = storage
        .list_tags("../absent")
        .await
        .expect_err("traversal repo name must be rejected with InvalidRepoName");
    assert!(matches!(absent_res, StorageError::InvalidRepoName(_)));
    let absent_page_err = storage
        .list_tags_page("../absent", None, 10)
        .await
        .expect_err("traversal repo name must be rejected with InvalidRepoName");
    assert!(matches!(absent_page_err, StorageError::InvalidRepoName(_)));
}

#[tokio::test]
async fn test_tag_listing_controlled_symlinks() {
    #[cfg(unix)]
    {
        let root = tmp_fs_root();
        let outside = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let tags_dir = root.join("repos").join("myrepo").join("tags");
        std::fs::create_dir_all(&tags_dir).unwrap();

        let hex_in = "5555555555555555555555555555555555555555555555555555555555555555";
        let hex_out = "6666666666666666666666666666666666666666666666666666666666666666";
        write_file(
            &tags_dir.join("real-tag"),
            format!("sha256:{hex_in}\n").as_bytes(),
        );
        write_file(
            &outside.join("target-ext"),
            format!("sha256:{hex_out}\n").as_bytes(),
        );

        // 1. Internal symlink
        std::os::unix::fs::symlink(tags_dir.join("real-tag"), tags_dir.join("sym-internal"))
            .unwrap();

        // 2. External symlink escaping storage root
        std::os::unix::fs::symlink(outside.join("target-ext"), tags_dir.join("sym-external"))
            .unwrap();

        // 3. Dangling symlink
        std::os::unix::fs::symlink(
            tags_dir.join("nonexistent-target"),
            tags_dir.join("sym-dangling"),
        )
        .unwrap();

        // In contained listing:
        // Reads directory entries filtering by Regular file type; all 3 symlinks are excluded!
        let tags = storage.list_tags("myrepo").await.unwrap();
        assert_eq!(
            tags,
            vec!["real-tag"],
            "contained list_tags excludes symlinks via file_type filtering"
        );

        // Contained list_tags_page excludes all symlinks:
        let (page, _) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].0, "real-tag");
        assert_eq!(page[0].1.hex(), hex_in);

        // 4. Ancestor directory symlink:
        let sym_repo_dir = root.join("repos").join("sym-repo");
        std::fs::create_dir_all(&sym_repo_dir).unwrap();
        std::os::unix::fs::symlink(&tags_dir, sym_repo_dir.join("tags")).unwrap();

        // openat2 resolution with RESOLVE_NO_SYMLINKS rejects directory symlinks
        let sym_list_res = storage.list_tags("sym-repo").await;
        assert!(
            sym_list_res.is_err(),
            "contained list_tags rejects directory symlinks"
        );

        let sym_page_res = storage.list_tags_page("sym-repo", None, 10).await;
        assert!(
            sym_page_res.is_err(),
            "contained list_tags_page rejects directory symlinks"
        );
    }
}

#[tokio::test]
async fn test_tag_listing_non_regular_objects() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex = "7777777777777777777777777777777777777777777777777777777777777777";
    write_file(
        &tags_dir.join("regular-tag"),
        format!("sha256:{hex}").as_bytes(),
    );
    std::fs::create_dir_all(tags_dir.join("dir-entry")).unwrap();

    // Contained list_tags excludes non-regular entries
    let tags = storage.list_tags("myrepo").await.unwrap();
    assert_eq!(tags, vec!["regular-tag"]);

    // Contained list_tags_page excludes non-regular entries
    let (page, _) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].0, "regular-tag");
}

#[tokio::test]
#[cfg(unix)]
#[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
async fn test_tag_listing_permission_denied() {
    use std::os::unix::fs::PermissionsExt;

    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("permrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex = "8888888888888888888888888888888888888888888888888888888888888888";
    let readable_file = tags_dir.join("readable_tag");
    write_file(&readable_file, format!("sha256:{hex}\n").as_bytes());

    let unreadable_file = tags_dir.join("unreadable_tag");
    write_file(&unreadable_file, format!("sha256:{hex}\n").as_bytes());

    struct ScopedPermReset<'a> {
        path: &'a std::path::Path,
        original_permissions: std::fs::Permissions,
    }
    impl<'a> Drop for ScopedPermReset<'a> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, self.original_permissions.clone());
        }
    }

    let orig_file_perms = std::fs::metadata(&unreadable_file).unwrap().permissions();
    let orig_dir_perms = std::fs::metadata(&tags_dir).unwrap().permissions();

    // 1. File permission case: directory remains accessible, individual tag file is unreadable (0o000)
    {
        let _file_guard = ScopedPermReset {
            path: &unreadable_file,
            original_permissions: orig_file_perms.clone(),
        };
        std::fs::set_permissions(&unreadable_file, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Verify the target file genuinely produces PermissionDenied on read
        match std::fs::read(&unreadable_file) {
            Ok(_) => panic!("ineffective file permissions: read succeeded under mode 0o000"),
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied),
        }

        // list_tags only reads directory entries, so it returns both tag names
        let tags = storage.list_tags("permrepo").await.unwrap();
        assert_eq!(tags, vec!["readable_tag", "unreadable_tag"]);

        // list_tags_page attempts payload acquisition; unreadable_tag fails closed with StorageErrorKind::Io
        let err_page = storage
            .list_tags_page("permrepo", None, 10)
            .await
            .expect_err("unreadable payload must fail closed with Io");
        assert_eq!(err_page.internal_kind(), Some(StorageErrorKind::Io));
    }

    // 2. Directory permission case: tags directory itself is unreadable (0o000)
    {
        let _dir_guard = ScopedPermReset {
            path: &tags_dir,
            original_permissions: orig_dir_perms.clone(),
        };
        std::fs::set_permissions(&tags_dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Verify the directory genuinely produces PermissionDenied on read_dir
        match std::fs::read_dir(&tags_dir) {
            Ok(_) => {
                panic!("ineffective directory permissions: read_dir succeeded under mode 0o000")
            }
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied),
        }

        // Both list_tags and list_tags_page encounter PermissionDenied during directory enumeration
        let res_list = storage.list_tags("permrepo").await;
        match res_list {
            Err(StorageError::Internal { kind, .. }) => {
                assert_eq!(kind, StorageErrorKind::PermissionDenied);
            }
            other => {
                panic!(
                    "expected StorageErrorKind::PermissionDenied on permission denied in list_tags, got {other:?}"
                )
            }
        }

        let res_page = storage.list_tags_page("permrepo", None, 10).await;
        match res_page {
            Err(StorageError::Internal { kind, .. }) => {
                assert_eq!(kind, StorageErrorKind::PermissionDenied);
            }
            other => panic!(
                "expected StorageErrorKind::PermissionDenied on permission denied in list_tags_page, got {other:?}"
            ),
        }
    }
}

#[tokio::test]
async fn test_tag_listing_pagination_boundaries_cursors_and_zero_limit() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex = "8888888888888888888888888888888888888888888888888888888888888888";
    for tag_name in ["t1", "t2", "t3", "t4", "t5"] {
        write_file(&tags_dir.join(tag_name), format!("sha256:{hex}").as_bytes());
    }

    // 1. Page 1 (limit 2, token None)
    let (p1, tok1) = storage.list_tags_page("myrepo", None, 2).await.unwrap();
    assert_eq!(
        p1.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t1", "t2"]
    );
    assert_eq!(tok1, Some("t2".to_string()));

    // 2. Page 2 (limit 2, token "t2")
    let (p2, tok2) = storage
        .list_tags_page("myrepo", tok1.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(
        p2.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t3", "t4"]
    );
    assert_eq!(tok2, Some("t4".to_string()));

    // 3. Page 3 (limit 2, token "t4")
    let (p3, tok3) = storage
        .list_tags_page("myrepo", tok2.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(
        p3.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t5"]
    );
    assert_eq!(tok3, None, "terminal page must have None next_token");

    // 4. Terminal cursor query (token "t5")
    let (p_term, tok_term) = storage
        .list_tags_page("myrepo", Some("t5"), 2)
        .await
        .unwrap();
    assert!(p_term.is_empty());
    assert_eq!(tok_term, None);

    // 5. Missing cursor anchor: token between t2 and t3 ("t2.5")
    let (p_anchor, tok_anchor) = storage
        .list_tags_page("myrepo", Some("t2.5"), 2)
        .await
        .unwrap();
    assert_eq!(
        p_anchor.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t3", "t4"]
    );
    assert_eq!(tok_anchor, Some("t4".to_string()));

    // 6. Token before all tags ("000")
    let (p_early, tok_early) = storage
        .list_tags_page("myrepo", Some("000"), 2)
        .await
        .unwrap();
    assert_eq!(
        p_early.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t1", "t2"]
    );
    assert_eq!(tok_early, Some("t2".to_string()));

    // 7. Token after all tags ("zzz")
    let (p_late, tok_late) = storage
        .list_tags_page("myrepo", Some("zzz"), 2)
        .await
        .unwrap();
    assert!(p_late.is_empty());
    assert_eq!(tok_late, None);

    // 8. Raw lexical handling with structurally unusual tokens (no token validation or schema check):
    // Empty string token "": lexicographically before "t1", starts at index 0
    let (p_empty, tok_empty) = storage.list_tags_page("myrepo", Some(""), 2).await.unwrap();
    assert_eq!(
        p_empty.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t1", "t2"]
    );
    assert_eq!(tok_empty, Some("t2".to_string()));

    // Token with slash "t2/nested/slash": '/' (ASCII 47) < '3' (ASCII 51), lands between t2 and t3
    let (p_slash, tok_slash) = storage
        .list_tags_page("myrepo", Some("t2/nested/slash"), 2)
        .await
        .unwrap();
    assert_eq!(
        p_slash.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t3", "t4"]
    );
    assert_eq!(tok_slash, Some("t4".to_string()));

    // Token with space and emoji "t2 🏷️": space (ASCII 32) < '3' (ASCII 51), lands between t2 and t3
    let (p_emoji, tok_emoji) = storage
        .list_tags_page("myrepo", Some("t2 🏷️"), 2)
        .await
        .unwrap();
    assert_eq!(
        p_emoji.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t3", "t4"]
    );
    assert_eq!(tok_emoji, Some("t4".to_string()));

    // Token with embedded null byte "t2\0suffix": null (ASCII 0) < '3' (ASCII 51), lands between t2 and t3
    let (p_null, tok_null) = storage
        .list_tags_page("myrepo", Some("t2\0suffix"), 2)
        .await
        .unwrap();
    assert_eq!(
        p_null.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t3", "t4"]
    );
    assert_eq!(tok_null, Some("t4".to_string()));

    // Oversized 10KB token "t4" + 10,000 'z's: lexicographically between "t4" and "t5"
    let long_token = "t4".to_string() + &"z".repeat(10_000);
    let (p_long, tok_long) = storage
        .list_tags_page("myrepo", Some(&long_token), 2)
        .await
        .unwrap();
    assert_eq!(
        p_long.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t5"]
    );
    assert_eq!(tok_long, None);

    // High ASCII token "~end": lexicographically after all tags
    let (p_high, tok_high) = storage
        .list_tags_page("myrepo", Some("~end"), 2)
        .await
        .unwrap();
    assert!(p_high.is_empty());
    assert_eq!(tok_high, None);

    // 9. Zero page limit
    let (p_zero, tok_zero) = storage.list_tags_page("myrepo", None, 0).await.unwrap();
    assert!(p_zero.is_empty());
    assert_eq!(tok_zero, None);

    // 10. Oversized page limit
    let (p_over, tok_over) = storage.list_tags_page("myrepo", None, 100).await.unwrap();
    assert_eq!(p_over.len(), 5);
    assert_eq!(tok_over, None);
}

#[tokio::test]
async fn test_tag_listing_deterministic_mutations_between_pages() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 1024 * 1024);
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex_v1 = "9999999999999999999999999999999999999999999999999999999999999999";
    for tag_name in ["t1", "t2", "t3", "t4"] {
        write_file(
            &tags_dir.join(tag_name),
            format!("sha256:{hex_v1}").as_bytes(),
        );
    }

    // Call page 1
    let (p1, tok1) = storage.list_tags_page("myrepo", None, 2).await.unwrap();
    assert_eq!(
        p1.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t1", "t2"]
    );
    assert_eq!(tok1, Some("t2".to_string()));

    // Mutation 1: Insert tag "t2.5" between t2 and t3
    write_file(
        &tags_dir.join("t2.5"),
        format!("sha256:{hex_v1}").as_bytes(),
    );

    // Page 2 using tok1 ("t2") observes the newly inserted "t2.5"!
    let (p2, tok2) = storage
        .list_tags_page("myrepo", tok1.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(
        p2.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t2.5", "t3"]
    );
    assert_eq!(tok2, Some("t3".to_string()));

    // Mutation 2: Remove the cursor tag "t3"
    std::fs::remove_file(tags_dir.join("t3")).unwrap();

    // Page 3 using tok2 ("t3") uses binary_search Err insertion point to find "t4"
    let (p3, tok3) = storage
        .list_tags_page("myrepo", tok2.as_deref(), 2)
        .await
        .unwrap();
    assert_eq!(
        p3.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["t4"]
    );
    assert_eq!(tok3, None);

    // Mutation 3: Modify target digest of t4
    let hex_v2 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    write_file(&tags_dir.join("t4"), format!("sha256:{hex_v2}").as_bytes());

    // Querying with token "t2.5" observes the updated digest of t4!
    let (p_mod, _) = storage
        .list_tags_page("myrepo", Some("t2.5"), 10)
        .await
        .unwrap();
    assert_eq!(p_mod.len(), 1);
    assert_eq!(p_mod[0].0, "t4");
    assert_eq!(p_mod[0].1.hex(), hex_v2);
}

#[tokio::test]
async fn test_tag_listing_root_replacement_divergence() {
    let temp_fixture = tempfile::tempdir().unwrap();
    let root = temp_fixture.path().join("storage-root");
    std::fs::create_dir_all(&root).unwrap();

    let storage = FsStorage::try_new(root.clone(), 1024 * 1024).expect("storage init");
    let tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex_tree_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let raw_bytes_tree_a = format!("sha256:{hex_tree_a}\n").into_bytes();
    write_file(&tags_dir.join("tag-tree-a"), &raw_bytes_tree_a);

    // Compute expected original raw byte SHA-256 version hash:
    let expected_version_tree_a = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&raw_bytes_tree_a);
        hex::encode(hasher.finalize())
    };

    // Initial observations: both contained reads and ambient listing observe Tree A
    assert_eq!(
        storage
            .resolve_tag("myrepo", "tag-tree-a")
            .await
            .unwrap()
            .hex(),
        hex_tree_a
    );
    let (v_d, v_ver) = storage
        .get_tag_with_version("myrepo", "tag-tree-a")
        .await
        .unwrap()
        .expect("tag-tree-a must exist in Tree A");
    assert_eq!(v_d.hex(), hex_tree_a);
    assert_eq!(
        v_ver, expected_version_tree_a,
        "version hashes original raw bytes"
    );

    assert_eq!(
        storage.list_tags("myrepo").await.unwrap(),
        vec!["tag-tree-a"]
    );
    let (page_a, _) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
    assert_eq!(page_a.len(), 1);
    assert_eq!(page_a[0].0, "tag-tree-a");

    // Replace root directory sequentially:
    // Rename root to root-old, create brand new root directory at original path
    let root_old = temp_fixture.path().join("storage-root-old");
    std::fs::rename(&root, &root_old).unwrap();
    std::fs::create_dir_all(&root).unwrap();

    let new_tags_dir = root.join("repos").join("myrepo").join("tags");
    std::fs::create_dir_all(&new_tags_dir).unwrap();
    let hex_tree_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    write_file(
        &new_tags_dir.join("tag-tree-b"),
        format!("sha256:{hex_tree_b}\n").as_bytes(),
    );

    // 1. Contained tag reads resolve via the pinned descriptor (openat2 on root_fd) -> observe Tree A!
    let d_read = storage.resolve_tag("myrepo", "tag-tree-a").await.unwrap();
    assert_eq!(
        d_read.hex(),
        hex_tree_a,
        "contained resolve_tag observes pinned Tree A"
    );

    let ver_tree_a = storage
        .get_tag_with_version("myrepo", "tag-tree-a")
        .await
        .unwrap()
        .expect("get_tag_with_version observes pinned Tree A");
    assert_eq!(ver_tree_a.0.hex(), hex_tree_a);
    assert_eq!(
        ver_tree_a.1, expected_version_tree_a,
        "contained get_tag_with_version maintains bit-exact version against pinned Tree A"
    );

    let d_missing = storage.resolve_tag("myrepo", "tag-tree-b").await;
    assert!(
        matches!(d_missing, Err(StorageError::NotFound)),
        "contained resolve_tag does not observe tag-tree-b because it is not in pinned Tree A"
    );

    let ver_missing = storage
        .get_tag_with_version("myrepo", "tag-tree-b")
        .await
        .unwrap();
    assert_eq!(
        ver_missing, None,
        "contained get_tag_with_version returns None for tag-tree-b because it is not in pinned Tree A"
    );

    // 2. Contained tag listing operations resolve via self.reader pinned descriptor -> observe Tree A!
    let tags_listed = storage.list_tags("myrepo").await.unwrap();
    assert_eq!(
        tags_listed,
        vec!["tag-tree-a"],
        "contained list_tags observes pinned Tree A without root pathname divergence"
    );

    let (page_a_again, _) = storage.list_tags_page("myrepo", None, 10).await.unwrap();
    assert_eq!(
        page_a_again.len(),
        1,
        "contained list_tags_page observes pinned Tree A without root pathname divergence"
    );
    assert_eq!(page_a_again[0].0, "tag-tree-a");
    assert_eq!(page_a_again[0].1.hex(), hex_tree_a);
}

#[tokio::test]
async fn test_tag_listing_ignores_configured_manifest_enumeration_limits() {
    let root = tmp_fs_root();
    // Construct storage with restrictive DirEnumerationLimits: max_entries = 1, max_total_name_bytes = 128
    let storage = FsStorage::try_new_with_limits(
        root.clone(),
        1024 * 1024,
        storage_fs::DirEnumerationLimits::new(1, 128),
    )
    .unwrap();

    let repo = "limited-repo";
    let manifests_dir = root.join("repos").join(repo).join("manifests");
    let tags_dir = root.join("repos").join(repo).join("tags");
    std::fs::create_dir_all(&manifests_dir).unwrap();
    std::fs::create_dir_all(&tags_dir).unwrap();

    let hex1 = "1111111111111111111111111111111111111111111111111111111111111111";
    let hex2 = "2222222222222222222222222222222222222222222222222222222222222222";
    let hex3 = "3333333333333333333333333333333333333333333333333333333333333333";

    // 1. Demonstrate the effect of configured limits on the intended manifest-listing operation:
    // With 2 manifests, exceeding max_entries = 1 causes an explicit Backend error
    write_file(&manifests_dir.join(hex1), b"manifest-1");
    write_file(&manifests_dir.join(hex2), b"manifest-2");

    let (manifests, _) = storage
        .list_manifest_digests_page(repo, None, 10)
        .await
        .expect("manifest listing succeeds under unbounded streaming");
    assert_eq!(manifests.len(), 2);

    // 2. Characterize tag-listing behavior under the same configured limits:
    // Create 3 tags (exceeding max_entries = 1 and max_total_name_bytes = 128)
    write_file(
        &tags_dir.join("tag-1"),
        format!("sha256:{hex1}\n").as_bytes(),
    );
    write_file(
        &tags_dir.join("tag-2"),
        format!("sha256:{hex2}\n").as_bytes(),
    );
    write_file(
        &tags_dir.join("tag-3"),
        format!("sha256:{hex3}\n").as_bytes(),
    );

    // Tag listing is unconstrained by manifest_listing_limits, but bounded by its own tag_listing_limits
    let tags = storage
        .list_tags(repo)
        .await
        .expect("list_tags ignores manifest listing limits");
    assert_eq!(tags, vec!["tag-1", "tag-2", "tag-3"]);

    // list_tags_page is also unconstrained by manifest_listing_limits
    let (page, next_tok) = storage
        .list_tags_page(repo, None, 10)
        .await
        .expect("list_tags_page ignores manifest listing limits");
    assert_eq!(page.len(), 3);
    assert_eq!(next_tok, None);
}

#[tokio::test]
async fn test_tag_listing_cutover_shared_reader_identity() {
    let root = tmp_fs_root();

    // 1. Pointer identity assertion:
    // Verify that FsStorage.reader() and FsStorage.read_adapter().reader() share the identical Arc<FsMetadataReader>
    let storage_default = FsStorage::new(root.clone(), 1024 * 1024);
    assert!(
        std::sync::Arc::ptr_eq(
            storage_default.reader(),
            storage_default.read_adapter().reader()
        ),
        "FsStorage.reader and read_adapter must share the identical Arc<FsMetadataReader>"
    );

    let listing_limits = crate::storage::fs::tag_listing::TagListingLimits::new(
        storage_fs::DirEnumerationLimits::new(64, 4096),
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        crate::storage::fs::tag_listing::TagReadLimits {
            max_payload_bytes: Some(1024),
        },
    );
    let storage_custom = FsStorage::try_new_with_all_limits(
        root.clone(),
        1024 * 1024,
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        repo_discovery::DiscoveryLimits::default(),
        manifest_refs::ManifestReferenceLimits::default(),
        listing_limits.clone(),
    )
    .expect("storage init with all limits");
    assert!(
        std::sync::Arc::ptr_eq(
            storage_custom.reader(),
            storage_custom.read_adapter().reader()
        ),
        "custom FsStorage.reader and read_adapter must share the identical Arc<FsMetadataReader>"
    );

    // 2. Behavioral checks on the Phase 3 shared tag domain: production
    // list_tags / list_tags_page route through ONE backend-neutral tag
    // implementation over the FS object store pinned at the same storage
    // root, preserving the frozen listing contract.
    let repo = "shared-reader-identity-repo";
    let tags_dir = root.join("repos").join(repo).join("tags");
    std::fs::create_dir_all(&tags_dir).expect("create tags dir");
    let hex = "1111111111111111111111111111111111111111111111111111111111111111";
    write_file(
        &tags_dir.join("tag-1"),
        format!("sha256:{hex}\n").as_bytes(),
    );

    let direct_tags = storage_custom
        .list_tags(repo)
        .await
        .expect("direct list_tags succeeds");
    assert_eq!(direct_tags, vec!["tag-1".to_string()]);

    let (direct_page, next) = storage_custom
        .list_tags_page(repo, None, 10)
        .await
        .expect("direct list_tags_page succeeds");
    assert_eq!(direct_page.len(), 1);
    assert_eq!(direct_page[0].0, "tag-1");
    assert_eq!(direct_page[0].1.hex(), hex);
    assert!(next.is_none());
}

#[tokio::test]
async fn test_tag_point_reads_share_configured_payload_ceiling() {
    let root = tmp_fs_root();
    let listing_limits = crate::storage::fs::tag_listing::TagListingLimits::new(
        storage_fs::DirEnumerationLimits::new(64, 4096),
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        crate::storage::fs::tag_listing::TagReadLimits {
            max_payload_bytes: Some(256),
        },
    );
    let storage = FsStorage::try_new_with_all_limits(
        root.clone(),
        10 * 1024 * 1024,
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        repo_discovery::DiscoveryLimits::default(),
        manifest_refs::ManifestReferenceLimits::default(),
        listing_limits,
    )
    .expect("storage init");

    let repo = "oversized-tag-repo";
    let tags_dir = root.join("repos").join(repo).join("tags");
    std::fs::create_dir_all(&tags_dir).expect("create tags dir");

    let hex = "1111111111111111111111111111111111111111111111111111111111111111";
    // Construct 300-byte valid payload: "sha256:<hex>" (71 bytes) + 229 spaces = 300 bytes
    let padding = " ".repeat(229);
    let payload = format!("sha256:{hex}{padding}");
    assert_eq!(payload.len(), 300);
    write_file(&tags_dir.join("large-tag"), payload.as_bytes());

    // 1. list_tags_page enforces tag_listing_max_payload_bytes (256) -> fails CorruptData
    let err_page = storage
        .list_tags_page(repo, None, 10)
        .await
        .expect_err("payload exceeding 256 bytes must fail list_tags_page");
    assert_eq!(
        err_page.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );
    assert!(err_page.to_string().contains("exceeds limit"));

    // 2. list_tags (name only) does NOT open or read candidate payload -> succeeds
    let tag_names = storage
        .list_tags(repo)
        .await
        .expect("name-only listing must succeed without opening payloads");
    assert_eq!(tag_names, vec!["large-tag"]);

    // 3. Phase 3 converged contract: point reads share the configured
    // payload ceiling (the retired FS seams read unbounded). An oversized
    // payload maps to the accepted drain-overflow CorruptData on resolve_tag
    // and get_tag_with_version alike.
    let err_resolve = storage
        .resolve_tag(repo, "large-tag")
        .await
        .expect_err("resolve_tag is bounded by the configured payload ceiling");
    assert_eq!(
        err_resolve.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );
    assert!(err_resolve.to_string().contains("exceeds limit"));

    let err_version = storage
        .get_tag_with_version(repo, "large-tag")
        .await
        .expect_err("get_tag_with_version is bounded by the configured payload ceiling");
    assert_eq!(
        err_version.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );

    // 4. A payload INSIDE the ceiling resolves through every point read.
    let hex_ok = "4444444444444444444444444444444444444444444444444444444444444444";
    write_file(
        &tags_dir.join("ok-tag"),
        format!("sha256:{hex_ok}\n").as_bytes(),
    );
    assert_eq!(
        storage.resolve_tag(repo, "ok-tag").await.unwrap().hex(),
        hex_ok
    );
    let (ver_digest, _version) = storage
        .get_tag_with_version(repo, "ok-tag")
        .await
        .unwrap()
        .expect("tag must exist");
    assert_eq!(ver_digest.hex(), hex_ok);
}

#[tokio::test]
async fn test_tag_listing_zero_page_avoidance_and_offpage_failure() {
    let root = tmp_fs_root();
    let listing_limits = crate::storage::fs::tag_listing::TagListingLimits::new(
        storage_fs::DirEnumerationLimits::new(64, 4096),
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        crate::storage::fs::tag_listing::TagReadLimits {
            max_payload_bytes: Some(256),
        },
    );
    let storage = FsStorage::try_new_with_all_limits(
        root.clone(),
        10 * 1024 * 1024,
        storage_fs::DirEnumerationLimits::new(1000, 100_000),
        repo_discovery::DiscoveryLimits::default(),
        manifest_refs::ManifestReferenceLimits::default(),
        listing_limits,
    )
    .expect("storage init");

    let repo = "zero-page-repo";
    let tags_dir = root.join("repos").join(repo).join("tags");
    std::fs::create_dir_all(&tags_dir).expect("create tags dir");

    let hex_a = "1111111111111111111111111111111111111111111111111111111111111111";
    write_file(
        &tags_dir.join("tag-a"),
        format!("sha256:{hex_a}").as_bytes(),
    );

    // tag-b has oversized payload (300 bytes > 256)
    let padding = " ".repeat(229);
    write_file(
        &tags_dir.join("tag-b"),
        format!("sha256:{hex_a}{padding}").as_bytes(),
    );

    // 1. Zero-page request (page_limit = 0) validates and enumerates but opens ZERO candidate payloads
    let (empty_page, next_tok) = storage
        .list_tags_page(repo, None, 0)
        .await
        .expect("zero-page request must succeed without opening candidate payloads");
    assert_eq!(empty_page.len(), 0);
    assert!(next_tok.is_none());

    // 2. Nonzero page request (page_limit = 1):
    // Under page-bounded lookahead, page 1 retrieves tag-a without reading off-page candidate (tag-b).
    let (page1, next_tok1) = storage
        .list_tags_page(repo, None, 1)
        .await
        .expect("page 1 request must succeed with valid tag-a");
    assert_eq!(page1.len(), 1);
    assert_eq!(page1[0].0, "tag-a");
    assert_eq!(next_tok1, Some("tag-a".to_string()));

    // 3. Page 2 request (continuation_token = Some("tag-a")):
    // Acquires tag-b, detects oversized payload (> 256 bytes), and fails closed with CorruptData!
    let err_page2 = storage
        .list_tags_page(repo, next_tok1.as_deref(), 1)
        .await
        .expect_err("acquiring oversized tag-b on page 2 must fail closed");
    assert_eq!(
        err_page2.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );
}

#[tokio::test]
async fn test_tag_listing_bounded_lookahead_io_isolation() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 10 * 1024 * 1024);
    let repo = "io-isolation-repo";
    let tags_dir = root.join("repos").join(repo).join("tags");
    std::fs::create_dir_all(&tags_dir).expect("create tags dir");

    let hex = "1111111111111111111111111111111111111111111111111111111111111111";
    // Seed 5 valid tags: tag-01 .. tag-05
    for i in 1..=5 {
        write_file(
            &tags_dir.join(format!("tag-{:02}", i)),
            format!("sha256:{hex}").as_bytes(),
        );
    }
    // Seed corrupt tag: tag-06 has invalid UTF-8
    write_file(&tags_dir.join("tag-06"), &[0xff, 0xfe, 0xfd]);

    // Page 1 with limit = 5: all 5 tags are valid, corrupt tag-06 is off-page and NOT opened!
    let (page1, next_tok1) = storage
        .list_tags_page(repo, None, 5)
        .await
        .expect("page 1 must succeed without reading off-page corrupt candidate");
    assert_eq!(page1.len(), 5);
    assert_eq!(page1[0].0, "tag-01");
    assert_eq!(page1[4].0, "tag-05");
    assert_eq!(next_tok1, Some("tag-05".to_string()));

    // Page 2 with limit = 5 starting at tag-05: opens tag-06, fails closed with CorruptData!
    let err_page2 = storage
        .list_tags_page(repo, next_tok1.as_deref(), 5)
        .await
        .expect_err("page 2 must fail closed on encountering corrupt tag-06");
    assert_eq!(
        err_page2.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );
}

#[tokio::test]
async fn test_tag_listing_mutation_path_delete_manifest_cleanup_preserved() {
    let root = tmp_fs_root();
    let storage = FsStorage::new(root.clone(), 10 * 1024 * 1024);
    let repo = "mutation-test-repo";

    let manifest1_digest =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let manifest2_digest =
        Digest::parse("sha256:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();

    let manifest_bytes =
        br#"{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}"#;
    storage
        .put_manifest(repo, &manifest1_digest, Bytes::from_static(manifest_bytes))
        .await
        .unwrap();
    storage
        .put_manifest(repo, &manifest2_digest, Bytes::from_static(manifest_bytes))
        .await
        .unwrap();

    // Create tag-1 referencing manifest1, and tag-2 referencing manifest2
    let tags_dir = root.join("repos").join(repo).join("tags");
    std::fs::create_dir_all(&tags_dir).unwrap();
    write_file(
        &tags_dir.join("tag-1"),
        manifest1_digest.as_str().as_bytes(),
    );
    write_file(
        &tags_dir.join("tag-2"),
        manifest2_digest.as_str().as_bytes(),
    );

    // Both tag leaves are present before deletion.
    let mut before: Vec<String> = std::fs::read_dir(&tags_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    before.sort();
    assert_eq!(before, vec!["tag-1".to_string(), "tag-2".to_string()]);

    // delete_manifest for manifest1 runs the contained tag-cleanup scan.
    storage
        .delete_manifest(repo, &manifest1_digest)
        .await
        .unwrap();

    // tag-1 pointing to manifest1 must be unlinked; tag-2 pointing to manifest2 must remain
    let mut after: Vec<String> = std::fs::read_dir(&tags_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    after.sort();
    assert_eq!(after, vec!["tag-2".to_string()]);

    // Contained list_tags also observes tag-2
    let tags_after = storage.list_tags(repo).await.unwrap();
    assert_eq!(tags_after, vec!["tag-2"]);
}

// ============================================================================
// OCI Referrers Read Characterization Slice
// ============================================================================
mod referrers_read_characterization {
    use super::*;
    use crate::application::ReferrersQueryError;
    use crate::application::referrers::{ReferrersQueryParams, ReferrersQueryService};
    use crate::storage::ports::StorageWiring;
    use crate::storage::{ReferrerDescriptor, StorageErrorKind};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_descriptor(
        digest: &str,
        size: u64,
        artifact_type: Option<&str>,
        annotations: Option<HashMap<String, String>>,
    ) -> ReferrerDescriptor {
        ReferrerDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: digest.to_string(),
            size,
            artifact_type: artifact_type.map(|s| s.to_string()),
            annotations,
        }
    }

    fn write_referrers_file(
        root: &std::path::Path,
        repo: &str,
        subject: &Digest,
        bytes: &[u8],
    ) -> PathBuf {
        let path = root
            .join("repos")
            .join(repo)
            .join("referrers")
            .join(format!("{}.json", subject.hex()));
        write_file(&path, bytes);
        path
    }

    #[cfg(unix)]
    struct ScopedPermReset<'a> {
        path: &'a std::path::Path,
        original_permissions: std::fs::Permissions,
    }

    #[cfg(unix)]
    impl<'a> Drop for ScopedPermReset<'a> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.path, self.original_permissions.clone());
        }
    }

    // ------------------------------------------------------------------------
    // Group 1: Missing and successful reads
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn test_missing_repository() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let list = storage
            .list_referrers("nonexistent_repo", &subject)
            .await
            .expect("missing repo yields Ok(vec![])");
        assert!(list.is_empty());

        let (page, token) = storage
            .list_referrers_page("nonexistent_repo", &subject, None, 10)
            .await
            .expect("missing repo yields Ok((vec![], None))");
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_missing_referrers_dir() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        // Create repo dir without referrers/ subdirectory
        std::fs::create_dir_all(root.join("repos").join("existing_repo")).unwrap();

        let list = storage
            .list_referrers("existing_repo", &subject)
            .await
            .expect("missing referrers dir yields Ok(vec![])");
        assert!(list.is_empty());

        let (page, token) = storage
            .list_referrers_page("existing_repo", &subject, None, 10)
            .await
            .expect("missing referrers dir yields Ok((vec![], None))");
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_missing_subject_file() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        // Create referrers/ directory, but do not create <hex>.json
        std::fs::create_dir_all(root.join("repos").join("myrepo").join("referrers")).unwrap();

        let list = storage
            .list_referrers("myrepo", &subject)
            .await
            .expect("missing subject file yields Ok(vec![])");
        assert!(list.is_empty());

        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .expect("missing subject file yields Ok((vec![], None))");
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_empty_json_array() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        write_referrers_file(&root, "myrepo", &subject, b"[]");

        let list = storage
            .list_referrers("myrepo", &subject)
            .await
            .expect("empty json array yields Ok(vec![])");
        assert!(list.is_empty());

        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .expect("empty json array yields Ok((vec![], None))");
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_valid_multi_descriptor_ordering_and_fields() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let mut annotations = HashMap::new();
        annotations.insert(
            "org.opencontainers.image.created".to_string(),
            "2026-09-12T00:00:00Z".to_string(),
        );
        annotations.insert("vnd.custom.field".to_string(), "custom_value".to_string());

        let desc_c = make_descriptor(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            300,
            Some("application/vnd.example.sbom.v1"),
            Some(annotations.clone()),
        );
        let desc_a = make_descriptor(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            100,
            None,
            None,
        );
        let desc_b = make_descriptor(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            200,
            Some("application/vnd.example.signature.v1"),
            None,
        );

        // Intentionally written in order: C, A, B
        let descriptors = vec![desc_c.clone(), desc_a.clone(), desc_b.clone()];
        let json_bytes = serde_json::to_vec(&descriptors).unwrap();
        write_referrers_file(&root, "myrepo", &subject, &json_bytes);

        // Direct read preserves file order [C, A, B]
        let direct = storage
            .list_referrers("myrepo", &subject)
            .await
            .expect("list_referrers succeeds");
        assert_eq!(direct.len(), 3);
        assert_eq!(direct[0], desc_c);
        assert_eq!(direct[1], desc_a);
        assert_eq!(direct[2], desc_b);

        // Verify descriptor fields
        assert_eq!(direct[0].size, 300);
        assert_eq!(
            direct[0].artifact_type.as_deref(),
            Some("application/vnd.example.sbom.v1")
        );
        assert_eq!(
            direct[0]
                .annotations
                .as_ref()
                .unwrap()
                .get("vnd.custom.field")
                .unwrap(),
            "custom_value"
        );
        assert_eq!(direct[1].artifact_type, None);
        assert_eq!(direct[1].annotations, None);

        // Paged read sorts by digest lexicographically [A, B, C]
        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .expect("list_referrers_page succeeds");
        assert_eq!(page.len(), 3);
        assert_eq!(page[0], desc_a);
        assert_eq!(page[1], desc_b);
        assert_eq!(page[2], desc_c);
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_valid_sha256_and_sha512_subject_paths() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        let subject_sha256 = Digest::parse(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let sha512_hex = "55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555";
        let subject_sha512 = Digest::parse(&format!("sha512:{sha512_hex}")).unwrap();

        let desc256 = make_descriptor(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            100,
            None,
            None,
        );
        let desc512 = make_descriptor(
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            200,
            None,
            None,
        );

        let path256 = write_referrers_file(
            &root,
            "repo256",
            &subject_sha256,
            &serde_json::to_vec(&vec![desc256.clone()]).unwrap(),
        );
        let path512 = write_referrers_file(
            &root,
            "repo512",
            &subject_sha512,
            &serde_json::to_vec(&vec![desc512.clone()]).unwrap(),
        );

        // Assert expected filename formatting: <hex>.json
        assert!(
            path256
                .ends_with("2222222222222222222222222222222222222222222222222222222222222222.json")
        );
        assert!(path512.ends_with(&format!("{sha512_hex}.json")));

        let res256 = storage
            .list_referrers("repo256", &subject_sha256)
            .await
            .unwrap();
        assert_eq!(res256, vec![desc256]);

        let res512 = storage
            .list_referrers("repo512", &subject_sha512)
            .await
            .unwrap();
        assert_eq!(res512, vec![desc512]);
    }

    // ------------------------------------------------------------------------
    // Group 2: Payload parsing and errors
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn test_empty_file_serde_eof_error() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        write_referrers_file(&root, "myrepo", &subject, b"");

        let err = storage
            .list_referrers("myrepo", &subject)
            .await
            .unwrap_err();
        match err {
            StorageError::Internal {
                kind, ref message, ..
            } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(
                    message.contains("EOF while parsing a value"),
                    "expected EOF parse error: {message}"
                );
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }

        // Paged read suppresses error
        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_whitespace_only_file() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        write_referrers_file(&root, "myrepo", &subject, b"   \n\t  \r\n ");

        let err = storage
            .list_referrers("myrepo", &subject)
            .await
            .unwrap_err();
        match err {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }

        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_truncated_json() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        write_referrers_file(
            &root,
            "myrepo",
            &subject,
            b"[{\"mediaType\": \"application/vnd.oci.image.manifest.v1+json\"",
        );

        let err = storage
            .list_referrers("myrepo", &subject)
            .await
            .unwrap_err();
        match err {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }

        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_invalid_json_syntax() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        write_referrers_file(&root, "myrepo", &subject, b"{not-valid-json}");

        let err = storage
            .list_referrers("myrepo", &subject)
            .await
            .unwrap_err();
        match err {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }

        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_wrong_toplevel_json_type() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        // Object instead of array
        write_referrers_file(
            &root,
            "myrepo",
            &subject,
            b"{\"mediaType\": \"application/vnd.oci.image.manifest.v1+json\"}",
        );

        let err = storage
            .list_referrers("myrepo", &subject)
            .await
            .unwrap_err();
        match err {
            StorageError::Internal {
                kind, ref message, ..
            } => {
                assert_eq!(kind, StorageErrorKind::Io);
                assert!(
                    message.contains("invalid type"),
                    "expected invalid type error: {message}"
                );
            }
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }

        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_invalid_utf8_payload() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        write_referrers_file(&root, "myrepo", &subject, b"[\xFF\xFE\xFD]");

        let err = storage
            .list_referrers("myrepo", &subject)
            .await
            .unwrap_err();
        match err {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected StorageError::Internal(Io), got: {other:?}"),
        }

        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_valid_json_with_whitespace_formatting() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let formatted = br#"
        [
            {
                "media_type": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
                "size": 54321
            }
        ]
        "#;
        write_referrers_file(&root, "myrepo", &subject, formatted);

        let list = storage.list_referrers("myrepo", &subject).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].size, 54321);

        let (page, _) = storage
            .list_referrers_page("myrepo", &subject, None, 10)
            .await
            .unwrap();
        assert_eq!(page.len(), 1);
    }

    #[tokio::test]
    async fn test_moderate_payload_absence_of_read_ceiling() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        // 100 descriptors (~15-20 KB of JSON)
        let mut descriptors = Vec::with_capacity(100);
        for i in 0..100 {
            let digest_hex = format!("{:064x}", i);
            descriptors.push(make_descriptor(
                &format!("sha256:{digest_hex}"),
                1000 + i as u64,
                Some("application/vnd.example.item"),
                None,
            ));
        }
        let json_bytes = serde_json::to_vec(&descriptors).unwrap();
        write_referrers_file(&root, "myrepo", &subject, &json_bytes);

        // Reads all 100 descriptors successfully without a configured payload limit check
        let list = storage.list_referrers("myrepo", &subject).await.unwrap();
        assert_eq!(list.len(), 100);

        let (page, token) = storage
            .list_referrers_page("myrepo", &subject, None, 100)
            .await
            .unwrap();
        assert_eq!(page.len(), 100);
        assert_eq!(token, None);
    }

    // ------------------------------------------------------------------------
    // Group 3: Contained path behavior (production cutover)
    //
    // These tests originally froze the ambient pathname behavior (symlinks
    // followed, traversal permitted). After the contained referrers read
    // cutover, `list_referrers` resolves beneath the pinned root descriptor
    // with symlink rejection and structural repository-name validation, and
    // the tests freeze the new production contract instead.
    // ------------------------------------------------------------------------

    #[tokio::test]
    #[cfg(unix)]
    async fn test_contained_symlink_inside_root_rejected() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let target_path = root.join("shared_referrers.json");
        let desc = make_descriptor(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            100,
            None,
            None,
        );
        let json_bytes = serde_json::to_vec(&vec![desc.clone()]).unwrap();
        write_file(&target_path, &json_bytes);

        let link_path = root
            .join("repos")
            .join("testrepo")
            .join("referrers")
            .join(format!("{}.json", subject.hex()));
        std::fs::create_dir_all(link_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

        // Contained read rejects the symlink even though the target is inside the root.
        let direct_err = storage
            .list_referrers("testrepo", &subject)
            .await
            .unwrap_err();
        match direct_err {
            // Phase 5: the pinned adapter reports its containment refusal as
            // PermissionDenied (the retired contained seam said Io — both are
            // production-inert Internal kinds; accepted C2 convergence).
            StorageError::Internal { kind, .. } => {
                assert_eq!(kind, StorageErrorKind::PermissionDenied)
            }
            other => panic!("expected PermissionDenied on symlink rejection, got {other:?}"),
        }

        // Paged read continues to suppress the rejection into empty success.
        let paged = storage
            .list_referrers_page("testrepo", &subject, None, 10)
            .await
            .unwrap();
        assert_eq!(paged, (vec![], None));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_contained_symlink_outside_storage_root_rejected() {
        let fixture = tempfile::tempdir().expect("create test fixture");
        let root = fixture.path().join("storage_root");
        let outside = fixture.path().join("outside_target");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let target_path = outside.join("external_referrers.json");
        let desc = make_descriptor(
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            250,
            None,
            None,
        );
        let json_bytes = serde_json::to_vec(&vec![desc.clone()]).unwrap();
        write_file(&target_path, &json_bytes);

        let link_path = root
            .join("repos")
            .join("testrepo")
            .join("referrers")
            .join(format!("{}.json", subject.hex()));
        std::fs::create_dir_all(link_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target_path, &link_path).unwrap();

        // Contained read rejects escape through the file symlink.
        let direct_err = storage
            .list_referrers("testrepo", &subject)
            .await
            .unwrap_err();
        match direct_err {
            // Phase 5: the pinned adapter reports its containment refusal as
            // PermissionDenied (the retired contained seam said Io — both are
            // production-inert Internal kinds; accepted C2 convergence).
            StorageError::Internal { kind, .. } => {
                assert_eq!(kind, StorageErrorKind::PermissionDenied)
            }
            other => panic!("expected PermissionDenied on symlink escape rejection, got {other:?}"),
        }

        let paged = storage
            .list_referrers_page("testrepo", &subject, None, 10)
            .await
            .unwrap();
        assert_eq!(paged, (vec![], None));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_contained_directory_symlink_rejected() {
        let fixture = tempfile::tempdir().expect("create test fixture");
        let root = fixture.path().join("storage_root");
        let outside_dir = fixture.path().join("outside_referrers");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside_dir).unwrap();

        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let desc = make_descriptor(
            "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            400,
            None,
            None,
        );
        let target_file = outside_dir.join(format!("{}.json", subject.hex()));
        let json_bytes = serde_json::to_vec(&vec![desc.clone()]).unwrap();
        write_file(&target_file, &json_bytes);

        let repo_dir = root.join("repos").join("testrepo");
        std::fs::create_dir_all(&repo_dir).unwrap();
        std::os::unix::fs::symlink(&outside_dir, repo_dir.join("referrers")).unwrap();

        // Contained read rejects the intermediate directory symlink.
        let direct_err = storage
            .list_referrers("testrepo", &subject)
            .await
            .unwrap_err();
        match direct_err {
            // Phase 5: the pinned adapter reports its containment refusal as
            // PermissionDenied (the retired contained seam said Io — both are
            // production-inert Internal kinds; accepted C2 convergence).
            StorageError::Internal { kind, .. } => {
                assert_eq!(kind, StorageErrorKind::PermissionDenied)
            }
            other => {
                panic!("expected PermissionDenied on directory symlink rejection, got {other:?}")
            }
        }

        let paged = storage
            .list_referrers_page("testrepo", &subject, None, 10)
            .await
            .unwrap();
        assert_eq!(paged, (vec![], None));
    }

    #[tokio::test]
    async fn test_repo_name_path_traversal_rejected_at_storage_boundary() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        // Plant a file where the legacy ambient path "repos/../escaped_repo/..." resolved,
        // to prove the contained read no longer reaches it.
        std::fs::create_dir_all(root.join("repos")).unwrap();
        let escaped_path = root
            .join("escaped_repo")
            .join("referrers")
            .join(format!("{}.json", subject.hex()));
        let desc = make_descriptor(
            "sha256:5555555555555555555555555555555555555555555555555555555555555555",
            500,
            None,
            None,
        );
        let json_bytes = serde_json::to_vec(&vec![desc]).unwrap();
        write_file(&escaped_path, &json_bytes);

        // Structural validation rejects the traversal name before any reader call.
        let direct_err = storage
            .list_referrers("../escaped_repo", &subject)
            .await
            .unwrap_err();
        assert!(
            matches!(direct_err, StorageError::InvalidRepoName(_)),
            "expected InvalidRepoName for traversal repository name, got {direct_err:?}"
        );

        // Paged read suppresses the rejection into empty success instead of leaking data.
        let paged = storage
            .list_referrers_page("../escaped_repo", &subject, None, 10)
            .await
            .unwrap();
        assert_eq!(paged, (vec![], None));
    }

    // ------------------------------------------------------------------------
    // Group 4: Object types and permission behavior
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn test_directory_in_place_of_json_file() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let dir_path = root
            .join("repos")
            .join("testrepo")
            .join("referrers")
            .join(format!("{}.json", subject.hex()));
        std::fs::create_dir_all(&dir_path).unwrap();

        // Phase 5: a non-regular object at the index leaf is STRUCTURAL
        // ABSENCE under the shared adapter contract (the accepted
        // tag/manifest convergence row) — the retired contained seam
        // reported Internal{Io} (EISDIR). Reads observe an empty index; the
        // unreadable garbage is never parsed or served.
        assert_eq!(
            storage.list_referrers("testrepo", &subject).await.unwrap(),
            vec![],
            "directory leaf reads as structurally absent"
        );

        let paged_res = storage
            .list_referrers_page("testrepo", &subject, None, 10)
            .await
            .unwrap();
        assert_eq!(paged_res, (vec![], None));
    }

    #[tokio::test]
    #[cfg(unix)]
    #[ignore = "requires unprivileged user environment where chmod 0o000 denies filesystem access"]
    async fn test_permission_denied_file() {
        use std::os::unix::fs::PermissionsExt;

        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let file_path = write_referrers_file(&root, "testrepo", &subject, b"[]");

        let orig_perms = std::fs::metadata(&file_path).unwrap().permissions();
        let _guard = ScopedPermReset {
            path: &file_path,
            original_permissions: orig_perms.clone(),
        };
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        match std::fs::read(&file_path) {
            Ok(_) => panic!("ineffective permissions: read succeeded under mode 0o000"),
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied),
        }

        let direct_err = storage
            .list_referrers("testrepo", &subject)
            .await
            .unwrap_err();
        match direct_err {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected StorageErrorKind::Io for permission denial, got {other:?}"),
        }

        let paged_res = storage
            .list_referrers_page("testrepo", &subject, None, 10)
            .await
            .unwrap();
        assert_eq!(paged_res, (vec![], None));
    }

    // ------------------------------------------------------------------------
    // Group 5: Pagination
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn test_pagination_lexical_sorting_and_pages() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let desc_a = make_descriptor(
            "sha256:111111111111111111111111111111111111111111111111111111111111111a",
            100,
            None,
            None,
        );
        let desc_b = make_descriptor(
            "sha256:222222222222222222222222222222222222222222222222222222222222222b",
            200,
            None,
            None,
        );
        let desc_c = make_descriptor(
            "sha256:333333333333333333333333333333333333333333333333333333333333333c",
            300,
            None,
            None,
        );

        // Write in non-sorted order C, A, B
        write_referrers_file(
            &root,
            "testrepo",
            &subject,
            &serde_json::to_vec(&vec![desc_c.clone(), desc_a.clone(), desc_b.clone()]).unwrap(),
        );

        // Page 1: limit 1, token None -> [A], token = Some(A)
        let (page1, token1) = storage
            .list_referrers_page("testrepo", &subject, None, 1)
            .await
            .unwrap();
        assert_eq!(page1, vec![desc_a.clone()]);
        assert_eq!(token1, Some(desc_a.digest.clone()));

        // Page 2: limit 1, token Some(A) -> [B], token = Some(B)
        let (page2, token2) = storage
            .list_referrers_page("testrepo", &subject, token1.as_deref(), 1)
            .await
            .unwrap();
        assert_eq!(page2, vec![desc_b.clone()]);
        assert_eq!(token2, Some(desc_b.digest.clone()));

        // Page 3: limit 1, token Some(B) -> [C], token = None (terminal page because end_idx == refs.len())
        let (page3, token3) = storage
            .list_referrers_page("testrepo", &subject, token2.as_deref(), 1)
            .await
            .unwrap();
        assert_eq!(page3, vec![desc_c.clone()]);
        assert_eq!(token3, None);

        // Query beyond terminal page: token Some(C) -> [], token = None
        let (page4, token4) = storage
            .list_referrers_page("testrepo", &subject, Some(&desc_c.digest), 1)
            .await
            .unwrap();
        assert!(page4.is_empty());
        assert_eq!(token4, None);
    }

    #[tokio::test]
    async fn test_pagination_continuation_tokens_absent() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let desc_a = make_descriptor(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            100,
            None,
            None,
        );
        let desc_c = make_descriptor(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            300,
            None,
            None,
        );
        write_referrers_file(
            &root,
            "testrepo",
            &subject,
            &serde_json::to_vec(&vec![desc_a.clone(), desc_c.clone()]).unwrap(),
        );

        // Absent token before stored digests: Err(0) -> start_idx = 0 -> returns from beginning
        let (page_before, token_before) = storage
            .list_referrers_page(
                "testrepo",
                &subject,
                Some("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
                1,
            )
            .await
            .unwrap();
        assert_eq!(page_before, vec![desc_a.clone()]);
        assert_eq!(token_before, Some(desc_a.digest.clone()));

        // Absent token between stored digests: Err(1) -> start_idx = 1 -> returns from desc_c
        let (page_between, token_between) = storage
            .list_referrers_page(
                "testrepo",
                &subject,
                Some("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                1,
            )
            .await
            .unwrap();
        assert_eq!(page_between, vec![desc_c.clone()]);
        assert_eq!(token_between, None); // terminal page

        // Absent token after all stored digests: Err(2) -> start_idx = 2 -> returns empty slice
        let (page_after, token_after) = storage
            .list_referrers_page(
                "testrepo",
                &subject,
                Some("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                1,
            )
            .await
            .unwrap();
        assert!(page_after.is_empty());
        assert_eq!(token_after, None);
    }

    #[tokio::test]
    async fn test_pagination_duplicate_descriptor_digests() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let dup_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let desc_1 = make_descriptor(dup_digest, 100, None, None);
        let desc_2 = make_descriptor(dup_digest, 200, None, None);

        write_referrers_file(
            &root,
            "testrepo",
            &subject,
            &serde_json::to_vec(&vec![desc_1.clone(), desc_2.clone()]).unwrap(),
        );

        // Page 1 with limit 1 yields one descriptor with duplicate digest
        let (page1, token1) = storage
            .list_referrers_page("testrepo", &subject, None, 1)
            .await
            .unwrap();
        assert_eq!(page1.len(), 1);
        assert_eq!(page1[0].digest, dup_digest);
        assert_eq!(token1, Some(dup_digest.to_string()));

        // Next page with duplicate digest token:
        // Rust's binary_search_by on equal keys may return either matching index.
        // Observable characterization: start_idx is either 1 or 2, returning at most 1 item.
        let (page2, token2) = storage
            .list_referrers_page("testrepo", &subject, token1.as_deref(), 1)
            .await
            .unwrap();
        assert!(page2.len() <= 1);
        assert_eq!(token2, None);
    }

    #[tokio::test]
    async fn test_pagination_zero_page_limit_behavior() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let desc_a = make_descriptor(
            "sha256:111111111111111111111111111111111111111111111111111111111111111a",
            100,
            None,
            None,
        );
        let desc_b = make_descriptor(
            "sha256:222222222222222222222222222222222222222222222222222222222222222b",
            200,
            None,
            None,
        );
        write_referrers_file(
            &root,
            "testrepo",
            &subject,
            &serde_json::to_vec(&vec![desc_a, desc_b]).unwrap(),
        );

        // Zero limit on valid file: returns Ok((vec![], None)).
        // Observable behavior: end_idx = (0 + 0).min(2) = 0.
        // Although end_idx < refs.len() (0 < 2) is true, page_slice is empty, so page_slice.last() is None.
        let (page, token) = storage
            .list_referrers_page("testrepo", &subject, None, 0)
            .await
            .unwrap();
        assert!(page.is_empty());
        assert_eq!(token, None);

        // Zero limit on corrupted file: also returns Ok((vec![], None)).
        // Behavioral observation alone does not distinguish an early return from error suppression,
        // because unwrap_or_default() suppresses all errors into an empty vector.
        // Source inspection of src/storage/fs.rs:1239 establishes that self.list_referrers()
        // is invoked unconditionally before page_limit slicing occurs.
        let corrupt_subject = Digest::parse(
            "sha256:9999999999999999999999999999999999999999999999999999999999999999",
        )
        .unwrap();
        write_referrers_file(&root, "testrepo", &corrupt_subject, b"not-json");

        let (corrupt_page, corrupt_token) = storage
            .list_referrers_page("testrepo", &corrupt_subject, None, 0)
            .await
            .unwrap();
        assert!(corrupt_page.is_empty());
        assert_eq!(corrupt_token, None);
    }

    #[tokio::test]
    async fn test_pagination_large_limit_start_idx_zero() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let desc = make_descriptor(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            100,
            None,
            None,
        );
        write_referrers_file(
            &root,
            "testrepo",
            &subject,
            &serde_json::to_vec(&vec![desc.clone()]).unwrap(),
        );

        // start_idx = 0: (0 + usize::MAX).min(refs.len()) does not overflow addition.
        let (page, token) = storage
            .list_referrers_page("testrepo", &subject, None, usize::MAX)
            .await
            .unwrap();
        assert_eq!(page, vec![desc]);
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn test_pagination_large_limit_start_idx_gt_zero_saturates() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        let desc_a = make_descriptor(
            "sha256:111111111111111111111111111111111111111111111111111111111111111a",
            100,
            None,
            None,
        );
        let desc_b = make_descriptor(
            "sha256:222222222222222222222222222222222222222222222222222222222222222b",
            200,
            None,
            None,
        );
        write_referrers_file(
            &root,
            "testrepo",
            &subject,
            &serde_json::to_vec(&vec![desc_a.clone(), desc_b.clone()]).unwrap(),
        );

        // Continuation token matches desc_a at index 0 -> start_idx = 1.
        // The retired body computed (start_idx + page_limit) unchecked and
        // PANICKED on usize::MAX in debug builds (wrapped + slice-panicked in
        // release). The shared domain saturates: the full remainder is
        // returned with a terminal page — no panic, no truncated lie.
        // (No production caller exists; accepted convergence row.)
        let token = desc_a.digest.clone();
        let (page, next) = storage
            .list_referrers_page("testrepo", &subject, Some(&token), usize::MAX)
            .await
            .expect("saturating pagination completes");
        assert_eq!(page.len(), 1, "remainder after the token");
        assert_eq!(page[0].digest, desc_b.digest);
        assert!(next.is_none(), "terminal page");
    }

    // ------------------------------------------------------------------------
    // Group 6: Caller boundaries
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn test_service_caller_referrers_query_corrupt_json_error_propagation() {
        let root = tmp_fs_root();
        let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));
        let wiring = StorageWiring::from_backend(storage.clone());
        let service = ReferrersQueryService::new(wiring.referrers_reader());

        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        write_referrers_file(&root, "validrepo", &subject, b"invalid-json-content");

        // The public query service calls list_referrers directly (NOT list_referrers_page).
        // Therefore, it does NOT swallow errors; it propagates the error as ReferrersQueryError::Storage.
        let err = service
            .query_referrers("validrepo", &subject, ReferrersQueryParams::default(), None)
            .await
            .expect_err("corrupt JSON must fail in ReferrersQueryService");

        match err {
            ReferrersQueryError::Storage(StorageError::Internal { kind, .. }) => {
                assert_eq!(kind, StorageErrorKind::Io);
            }
            other => panic!("expected ReferrersQueryError::Storage(Internal(Io)), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_service_caller_rejects_path_traversal_repo_name() {
        let root = tmp_fs_root();
        let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));
        let wiring = StorageWiring::from_backend(storage.clone());
        let service = ReferrersQueryService::new(wiring.referrers_reader());

        let subject = Digest::parse(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();

        // At the service boundary, CanonicalRepoName::parse rejects path traversal syntax before storage is called
        let err = service
            .query_referrers(
                "../escape_repo",
                &subject,
                ReferrersQueryParams::default(),
                None,
            )
            .await
            .expect_err("service must reject path traversal repository name");

        match err {
            ReferrersQueryError::InvalidRepoName { name, .. } => {
                assert_eq!(name, "../escape_repo");
            }
            other => panic!("expected InvalidRepoName, got: {other:?}"),
        }
    }
}

/// Mutation-read compatibility and production wiring coverage for the contained
/// referrers read cutover.
///
/// Promoting `FsStorage::list_referrers` to the contained reader is not a
/// query-only change: `add_referrer`, `remove_referrer`, and `delete_manifest`
/// (via `remove_referrer`) consume the promoted read. These tests freeze the
/// mutation-side consequences of the cutover.
#[cfg(target_os = "linux")]
mod referrers_contained_mutation_compat {
    use super::*;
    use crate::application::ReferrersQueryError;
    use crate::application::referrers::{ReferrersQueryParams, ReferrersQueryService};
    use crate::storage::ports::StorageWiring;
    use crate::storage::{ReferrerDescriptor, StorageErrorKind};

    fn make_descriptor(digest: &str, size: u64) -> ReferrerDescriptor {
        ReferrerDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: digest.to_string(),
            size,
            artifact_type: None,
            annotations: None,
        }
    }

    fn subject_sha256() -> Digest {
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap()
    }

    fn referrers_file_path(root: &Path, repo: &str, subject: &Digest) -> PathBuf {
        root.join("repos")
            .join(repo)
            .join("referrers")
            .join(format!("{}.json", subject.hex()))
    }

    /// A tempdir-scoped fixture root so traversal side effects stay inside the fixture.
    fn fixture_root() -> (tempfile::TempDir, PathBuf) {
        let fixture = tempfile::tempdir().expect("create test fixture");
        let root = fixture.path().join("storage_root");
        std::fs::create_dir_all(&root).unwrap();
        (fixture, root)
    }

    #[tokio::test]
    async fn test_add_referrer_traversal_rejected_fails_closed_no_side_effect() {
        let (fixture, root) = fixture_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = subject_sha256();

        let desc = make_descriptor(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            100,
        );

        // repos/ exists so an ambient "repos/.." component COULD resolve if any
        // uncontained directory creation remained.
        std::fs::create_dir_all(root.join("repos")).unwrap();

        let err = storage
            .add_referrer("../escaped_repo", &subject, desc)
            .await
            .expect_err("contained authority must reject traversal repository name");
        assert!(
            matches!(err, StorageError::InvalidRepoName(_)),
            "expected InvalidRepoName from add_referrer, got {err:?}"
        );

        // The rejection happens fail-closed before serialization/writeback: no referrers
        // file is created at the escaped location.
        let escaped_file = root
            .join("escaped_repo")
            .join("referrers")
            .join(format!("{}.json", subject.hex()));
        assert!(
            !escaped_file.exists(),
            "no referrers file may be written at the escaped path"
        );

        // Contained cutover: repository-name validation now precedes ALL directory
        // creation, so the former ambient `ensure_dir` escape side effect
        // (`<fixture>/escaped_repo/referrers` being created and not rolled back)
        // no longer occurs. The mutation fails closed with zero filesystem effect.
        let escaped_dir = root.join("escaped_repo").join("referrers");
        assert!(
            !escaped_dir.exists(),
            "traversal rejection must not create any directory outside repos/"
        );

        drop(fixture);
    }

    #[tokio::test]
    async fn test_add_referrer_symlinked_file_fails_closed_without_overwrite() {
        let (fixture, root) = fixture_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = subject_sha256();

        // Symlink the referrers file to an outside target holding valid JSON.
        let outside_target = fixture.path().join("outside_referrers.json");
        let planted = serde_json::to_vec(&vec![make_descriptor(
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            300,
        )])
        .unwrap();
        write_file(&outside_target, &planted);

        let link_path = referrers_file_path(&root, "testrepo", &subject);
        std::fs::create_dir_all(link_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside_target, &link_path).unwrap();

        let err = storage
            .add_referrer(
                "testrepo",
                &subject,
                make_descriptor(
                    "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                    400,
                ),
            )
            .await
            .expect_err("contained pre-read must reject the symlinked referrers file");
        match err {
            // Phase 5: adapter containment refusal is PermissionDenied (was Io;
            // both production-inert Internal kinds; accepted C2 convergence).
            StorageError::Internal { kind, .. } => {
                assert_eq!(kind, StorageErrorKind::PermissionDenied)
            }
            other => panic!(
                "expected PermissionDenied on symlink rejection in add_referrer, got {other:?}"
            ),
        }

        // Fail-closed: neither the symlink nor its target was replaced or rewritten.
        assert!(
            std::fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink must remain in place"
        );
        assert_eq!(
            std::fs::read(&outside_target).unwrap(),
            planted,
            "symlink target bytes must remain unmodified"
        );
    }

    #[tokio::test]
    async fn test_add_referrer_corrupt_existing_file_fails_closed() {
        let (_fixture, root) = fixture_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = subject_sha256();

        let path = referrers_file_path(&root, "testrepo", &subject);
        write_file(&path, b"corrupt-not-json");

        let err = storage
            .add_referrer(
                "testrepo",
                &subject,
                make_descriptor(
                    "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                    500,
                ),
            )
            .await
            .expect_err("corrupt existing referrers file must abort add_referrer");
        match err {
            StorageError::Internal { kind, .. } => assert_eq!(kind, StorageErrorKind::Io),
            other => panic!("expected Io on corrupt pre-read, got {other:?}"),
        }

        // The corrupted file must not be overwritten with a fresh single-entry array.
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"corrupt-not-json",
            "corrupt file must remain untouched after fail-closed abort"
        );
    }

    #[tokio::test]
    async fn test_remove_referrer_symlinked_file_fails_closed() {
        let (fixture, root) = fixture_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = subject_sha256();
        let referrer = Digest::parse(
            "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        )
        .unwrap();

        let outside_target = fixture.path().join("outside_referrers.json");
        let planted = serde_json::to_vec(&vec![make_descriptor(&referrer.as_str(), 600)]).unwrap();
        write_file(&outside_target, &planted);

        let link_path = referrers_file_path(&root, "testrepo", &subject);
        std::fs::create_dir_all(link_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside_target, &link_path).unwrap();

        let err = storage
            .remove_referrer("testrepo", &subject, &referrer)
            .await
            .expect_err("contained pre-read must reject the symlinked referrers file");
        match err {
            // Phase 5: adapter containment refusal is PermissionDenied (was Io;
            // both production-inert Internal kinds; accepted C2 convergence).
            StorageError::Internal { kind, .. } => {
                assert_eq!(kind, StorageErrorKind::PermissionDenied)
            }
            other => panic!(
                "expected PermissionDenied on symlink rejection in remove_referrer, got {other:?}"
            ),
        }

        // Fail-closed: no unlink and no writeback happened.
        assert!(
            std::fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink must remain in place"
        );
        assert_eq!(
            std::fs::read(&outside_target).unwrap(),
            planted,
            "symlink target bytes must remain unmodified"
        );
    }

    #[tokio::test]
    async fn test_delete_manifest_swallows_contained_referrer_cleanup_failure() {
        let (fixture, root) = fixture_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = subject_sha256();
        let manifest_digest = Digest::parse(
            "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        )
        .unwrap();

        // Store a manifest declaring the subject.
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": subject.as_str(),
                "size": 500
            }
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();
        storage
            .put_manifest("testrepo", &manifest_digest, bytes.into())
            .await
            .expect("put manifest");

        // Symlink the subject's referrers file so remove_referrer's contained read fails.
        let outside_target = fixture.path().join("outside_referrers.json");
        let planted =
            serde_json::to_vec(&vec![make_descriptor(&manifest_digest.as_str(), 700)]).unwrap();
        write_file(&outside_target, &planted);
        let link_path = referrers_file_path(&root, "testrepo", &subject);
        std::fs::create_dir_all(link_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside_target, &link_path).unwrap();

        // delete_manifest ignores the remove_referrer failure and reports success;
        // the manifest is already removed by then, and the cleanup failure does not
        // resurrect it.
        storage
            .delete_manifest("testrepo", &manifest_digest)
            .await
            .expect("delete_manifest suppresses referrer cleanup failure");

        let manifest_path = root
            .join("repos")
            .join("testrepo")
            .join("manifests")
            .join(manifest_digest.hex());
        assert!(
            !manifest_path.exists(),
            "manifest must be removed despite referrer cleanup failure"
        );

        // The rejected referrers file remains untouched: stale-cleanup residue is the
        // documented consequence of the ignored remove_referrer result.
        assert!(
            std::fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink must remain in place"
        );
        assert_eq!(
            std::fs::read(&outside_target).unwrap(),
            planted,
            "symlink target bytes must remain unmodified"
        );
    }

    #[tokio::test]
    async fn test_list_referrers_pinned_root_divergence() {
        let (fixture, root) = fixture_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let subject = subject_sha256();

        let desc_old = make_descriptor(
            "sha256:8888888888888888888888888888888888888888888888888888888888888888",
            800,
        );
        write_file(
            &referrers_file_path(&root, "testrepo", &subject),
            &serde_json::to_vec(&vec![desc_old.clone()]).unwrap(),
        );

        let initial = storage.list_referrers("testrepo", &subject).await.unwrap();
        assert_eq!(initial, vec![desc_old.clone()]);

        // Replace the root pathname with a fresh tree holding different content.
        let root_old = fixture.path().join("storage_root_old");
        std::fs::rename(&root, &root_old).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let desc_new = make_descriptor(
            "sha256:9999999999999999999999999999999999999999999999999999999999999999",
            900,
        );
        write_file(
            &referrers_file_path(&root, "testrepo", &subject),
            &serde_json::to_vec(&vec![desc_new]).unwrap(),
        );

        // Production list_referrers resolves beneath the pinned root descriptor and
        // continues to observe the originally opened tree, proving contained wiring.
        let pinned = storage.list_referrers("testrepo", &subject).await.unwrap();
        assert_eq!(
            pinned,
            vec![desc_old],
            "contained production read must observe the pinned old root"
        );
    }

    #[tokio::test]
    async fn test_service_caller_symlinked_referrers_fails_closed() {
        let (fixture, root) = fixture_root();
        let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));
        let wiring = StorageWiring::from_backend(storage.clone());
        let service = ReferrersQueryService::new(wiring.referrers_reader());
        let subject = subject_sha256();

        let outside_target = fixture.path().join("outside_referrers.json");
        write_file(&outside_target, b"[]");
        let link_path = referrers_file_path(&root, "validrepo", &subject);
        std::fs::create_dir_all(link_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside_target, &link_path).unwrap();

        // The public query service propagates the containment rejection instead of
        // serving symlinked content (HTTP handler maps this to HTTP 500).
        let err = service
            .query_referrers("validrepo", &subject, ReferrersQueryParams::default(), None)
            .await
            .expect_err("symlinked referrers file must fail closed on the public route");
        match err {
            // Phase 5: the containment refusal surfaces as PermissionDenied
            // (was Io; both map to HTTP 500 — accepted C2 convergence).
            ReferrersQueryError::Storage(StorageError::Internal { kind, .. }) => {
                assert_eq!(kind, StorageErrorKind::PermissionDenied);
            }
            other => panic!("expected Storage(Internal(PermissionDenied)), got: {other:?}"),
        }
    }
}

/// Production wiring and caller-propagation coverage for the contained
/// repository-catalog discovery cutover.
///
/// `FsStorage::list_repositories` (via `list_repo_names`) now routes through
/// `catalog_discovery::discover_catalog_repositories_impl` over the shared
/// pinned reader. These tests freeze the caller-visible consequences: symlink
/// path rejection, fail-closed propagation into safety-sensitive callers, and
/// preserved application-level pagination semantics.
#[cfg(target_os = "linux")]
mod catalog_discovery_contained_integration {
    use super::*;
    use crate::application::CatalogQueryError;
    use crate::application::catalog::{CatalogQueryParams, CatalogQueryService};
    use crate::storage::ports::StorageWiring;

    fn fixture_root() -> (tempfile::TempDir, PathBuf) {
        let fixture = tempfile::tempdir().expect("create test fixture");
        let root = fixture.path().join("storage_root");
        std::fs::create_dir_all(&root).unwrap();
        (fixture, root)
    }

    fn catalog_service(storage: Arc<FsStorage>) -> CatalogQueryService {
        let wiring = StorageWiring::from_backend(storage);
        CatalogQueryService::new(
            wiring.catalog_reader(),
            wiring.tag_reader(),
            wiring.manifest_reader(),
            wiring.blob_reader(),
        )
    }

    #[tokio::test]
    async fn test_catalog_service_contained_listing_and_pagination_preserved() {
        let (_fixture, root) = fixture_root();
        let repos_dir = root.join("repos");
        std::fs::create_dir_all(repos_dir.join("alpha").join("tags")).unwrap();
        std::fs::create_dir_all(repos_dir.join("beta").join("manifests")).unwrap();
        std::fs::create_dir_all(repos_dir.join("gamma").join("meta")).unwrap();

        let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));
        let service = catalog_service(storage);

        // Page 1: n=2 -> [alpha, beta], has_more with next_last = beta.
        let page1 = service
            .query_catalog(
                CatalogQueryParams {
                    n: Some(2),
                    last: None,
                },
                None,
            )
            .await
            .expect("catalog page 1 succeeds through contained discovery");
        assert_eq!(page1.repositories, vec!["alpha", "beta"]);
        assert!(page1.has_more);
        assert_eq!(page1.next_last.as_deref(), Some("beta"));

        // Page 2: last=beta -> [gamma], terminal.
        let page2 = service
            .query_catalog(
                CatalogQueryParams {
                    n: Some(2),
                    last: Some("beta".to_string()),
                },
                None,
            )
            .await
            .expect("catalog page 2 succeeds");
        assert_eq!(page2.repositories, vec!["gamma"]);
        assert!(!page2.has_more);
        assert_eq!(page2.next_last, None);
    }

    #[tokio::test]
    async fn test_catalog_service_fails_closed_on_symlinked_repos_root() {
        let (fixture, root) = fixture_root();
        let outside = fixture.path().join("outside_repos");
        std::fs::create_dir_all(outside.join("ext_repo").join("tags")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("repos")).unwrap();

        let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));
        let service = catalog_service(storage);

        // The public catalog path propagates the containment rejection instead
        // of serving repositories discovered through a symlinked root
        // (HTTP handler maps this to HTTP 500).
        let err = service
            .query_catalog(
                CatalogQueryParams {
                    n: None,
                    last: None,
                },
                None,
            )
            .await
            .expect_err("symlinked repos/ root must fail closed on the catalog route");
        match err {
            CatalogQueryError::Storage(StorageError::Internal { kind, .. }) => {
                assert_eq!(kind, StorageErrorKind::Io);
            }
            other => panic!("expected Storage(Internal(Io)), got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_second_storage_instance_proxy_cache_role_contained() {
        // Primary and proxy-cache filesystem storages are separate FsStorage
        // instances sharing the same trait path; both must route contained.
        let (_fixture_a, root_a) = fixture_root();
        std::fs::create_dir_all(root_a.join("repos").join("primary_repo").join("tags")).unwrap();
        let primary = Arc::new(FsStorage::new(root_a.clone(), 1024 * 1024));

        let (fixture_b, root_b) = fixture_root();
        let outside = fixture_b.path().join("outside_repos");
        std::fs::create_dir_all(outside.join("cache_repo").join("tags")).unwrap();
        std::os::unix::fs::symlink(&outside, root_b.join("repos")).unwrap();
        let proxy_cache = Arc::new(FsStorage::new(root_b.clone(), 1024 * 1024));

        let primary_repos = primary.list_repositories().await.unwrap();
        assert_eq!(primary_repos, vec!["primary_repo".to_string()]);

        let err = proxy_cache
            .list_repositories()
            .await
            .expect_err("proxy-cache instance must also reject symlinked repos/ root");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
    }

    #[tokio::test]
    async fn test_is_storage_empty_propagates_discovery_failure() {
        let (fixture, root) = fixture_root();
        let outside = fixture.path().join("outside_repos");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("repos")).unwrap();

        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let err = storage
            .is_storage_empty()
            .await
            .expect_err("readiness probing must not mistake a discovery failure for emptiness");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
    }

    #[tokio::test]
    async fn test_membership_migration_planning_propagates_discovery_failure() {
        let (fixture, root) = fixture_root();
        let outside = fixture.path().join("outside_repos");
        std::fs::create_dir_all(outside.join("mig_repo").join("tags")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("repos")).unwrap();

        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let err = crate::membership_migration::plan_membership_migration(&storage)
            .await
            .expect_err("migration planning must fail closed on discovery failure");
        assert_eq!(err.internal_kind(), Some(StorageErrorKind::Io));
    }

    /// Real-FsStorage regression for the unaddressable-name fail-closed policy:
    /// membership migration APPLICATION and VERIFICATION must fail explicitly
    /// and must not establish readiness when catalog discovery encounters a
    /// directory name that cannot form a contained object key. Under the
    /// earlier silent-skip policy, both would have proceeded without the
    /// affected repository and could have established Ready.
    #[tokio::test]
    async fn test_membership_migration_apply_and_verify_fail_closed_on_unaddressable_name() {
        let (_fixture, root) = fixture_root();
        let repos_dir = root.join("repos");
        std::fs::create_dir_all(repos_dir.join("validrepo").join("tags")).unwrap();
        std::fs::create_dir_all(repos_dir.join("bad\\name").join("manifests")).unwrap();

        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        // Application: fails with the explicit discovery error.
        let apply_err = crate::membership_migration::apply_membership_migration(&storage)
            .await
            .expect_err("application must fail closed instead of omitting the repository");
        assert_eq!(
            apply_err.internal_kind(),
            Some(StorageErrorKind::CorruptData),
            "expected the catalog discovery CorruptData error, got: {apply_err:?}"
        );

        // Application persists its initial Applying checkpoint (with an owner
        // lease) BEFORE catalog discovery runs; the discovery failure aborts
        // further processing but that earlier legitimate write is not rolled
        // back. The checkpoint therefore exists and is NOT Ready.
        let checkpoint = storage
            .get_migration_checkpoint()
            .await
            .expect("checkpoint read succeeds")
            .expect("initial Applying checkpoint was persisted before discovery");
        assert_eq!(
            checkpoint.phase,
            crate::storage::repo_membership::MigrationPhase::Applying,
            "discovery failure aborts before any later phase transition"
        );

        // Readiness is not established.
        assert!(
            !storage.is_membership_ready().await.unwrap(),
            "failed application must not establish membership readiness"
        );

        // Verification: also fails explicitly rather than reporting a verdict
        // computed from an incomplete repository set.
        let verify_err = crate::membership_migration::verify_membership_migration(&storage)
            .await
            .expect_err("verification must fail closed instead of verifying a partial catalog");
        assert_eq!(
            verify_err.internal_kind(),
            Some(StorageErrorKind::CorruptData)
        );

        assert!(
            !storage.is_membership_ready().await.unwrap(),
            "readiness must remain unestablished after failed verification"
        );
    }
}

// --- Filesystem Tag Mutation Write Characterization Tests -------------------
//
// These freeze the CURRENT (ambient, not-yet-contained) behaviour of the
// tag-mutation write paths at the production `FsStorage` boundary, ahead of the
// O-04 repo-scoped write-containment cutover. They deliberately assert the
// on-disk artifacts the cutover must reproduce byte-for-byte: the contained
// `repos/<repo>/tags/<tag>` location, the exact `<digest>\n` body, the
// temp-then-rename discipline (no `.tmp.*` residue), and the retained
// `.lock.<tag>` file. They also pin the subtle control-flow outcomes
// (same-digest short-circuit ahead of the policy check; corrupt-existing bytes
// treated as absent; the `None`/absent conditional-delete branches;
// unconditional `delete_tag`). Concurrency, and the version-precondition role
// of `delete_tag_conditional`, are already covered above and are not repeated.
//
// Per the characterization mandate these freeze behaviour only; they assert no
// fail-closed containment property that the ambient code does not yet provide.
mod tag_mutation_write_characterization {
    use super::*;
    use crate::storage::{ConditionalDeleteResult, TagMutation, TagMutationPolicy};

    fn d(hex: &str) -> Digest {
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    const HEX1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const HEX2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn sorted_entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read tags dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // set_tag writes `<digest.as_str()>\n` at exactly repos/<repo>/tags/<tag>,
    // via a temp-then-rename that leaves no `.tmp.*` residue but does retain a
    // persistent `.lock.<tag>` file, and writes nothing outside repos/.
    #[tokio::test]
    async fn test_set_tag_writes_canonical_bytes_at_contained_path() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(HEX1);

        storage.set_tag("myrepo", "mytag", &digest).await.unwrap();

        // Exact contained path and body.
        let tag_path = root.join("repos").join("myrepo").join("tags").join("mytag");
        assert!(tag_path.exists(), "tag written at contained path");
        let expected_body = format!("{}\n", digest.as_str());
        assert_eq!(
            std::fs::read(&tag_path).unwrap(),
            expected_body.as_bytes(),
            "on-disk body is `<digest.as_str()>\\n`"
        );
        // Freeze the concrete algorithm-prefixed layout the body relies on.
        assert_eq!(digest.as_str(), format!("sha256:{HEX1}"));

        // Phase 3: staged publication and per-key locks live in the object
        // store's private control-character bookkeeping tree, never in the
        // tag namespace - the tags directory holds ONLY the tag leaf.
        let tags_dir = tag_path.parent().unwrap();
        assert_eq!(
            sorted_entry_names(tags_dir),
            vec!["mytag".to_string()],
            "only the tag remains; no .lock.* / .tmp.* residue in the tag namespace"
        );

        // Containment: besides repos/, only the object store's internal
        // bookkeeping tree (structurally unaddressable by any generic key)
        // exists at the root.
        assert_eq!(
            sorted_entry_names(&root),
            vec![
                storage_fs::object_store::INTERNAL_DIR.to_string(),
                "repos".to_string()
            ],
            "set_tag writes only under repos/ plus the store-internal tree"
        );

        // Round-trips through both point-read entry points.
        assert_eq!(
            storage.resolve_tag("myrepo", "mytag").await.unwrap(),
            digest
        );
        let (rd, _ver) = storage
            .get_tag_with_version("myrepo", "mytag")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rd, digest);
    }

    // Replace across create -> same-digest -> overwrite never leaves a temp
    // file, the Unchanged case performs no write, and the lock file persists
    // across all three.
    #[tokio::test]
    async fn test_mutate_tag_replace_temp_rename_leaves_no_residue() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let d1 = d(HEX1);
        let d2 = d(HEX2);
        let tags_dir = root.join("repos").join("myrepo").join("tags");

        let created = storage
            .mutate_tag("myrepo", "t", &d1, TagMutationPolicy::Replace)
            .await
            .unwrap();
        assert_eq!(created, TagMutation::Created);
        assert_eq!(sorted_entry_names(&tags_dir), vec!["t".to_string()]);

        // Same digest short-circuits to Unchanged and rewrites nothing.
        let before = std::fs::read(tags_dir.join("t")).unwrap();
        let unchanged = storage
            .mutate_tag("myrepo", "t", &d1, TagMutationPolicy::Replace)
            .await
            .unwrap();
        assert_eq!(unchanged, TagMutation::Unchanged);
        assert_eq!(
            std::fs::read(tags_dir.join("t")).unwrap(),
            before,
            "Unchanged performs no write"
        );
        assert_eq!(
            sorted_entry_names(&tags_dir),
            vec!["t".to_string()],
            "Unchanged leaves no temp"
        );

        // Divergent digest overwrites and reports the prior digest.
        let replaced = storage
            .mutate_tag("myrepo", "t", &d2, TagMutationPolicy::Replace)
            .await
            .unwrap();
        assert_eq!(replaced, TagMutation::Replaced { previous: d1 });
        assert_eq!(
            std::fs::read(tags_dir.join("t")).unwrap(),
            format!("{}\n", d2.as_str()).as_bytes()
        );
        assert_eq!(
            sorted_entry_names(&tags_dir),
            vec!["t".to_string()],
            "Replace leaves no temp"
        );
    }

    // The same-digest equality check runs BEFORE the CreateOnly existence
    // check, so CreateOnly against an identical existing digest returns
    // Unchanged, not TagAlreadyExists.
    #[tokio::test]
    async fn test_create_only_same_digest_returns_unchanged_not_conflict() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(HEX1);

        let first = storage
            .mutate_tag("myrepo", "t", &digest, TagMutationPolicy::CreateOnly)
            .await
            .unwrap();
        assert_eq!(first, TagMutation::Created);

        let second = storage
            .mutate_tag("myrepo", "t", &digest, TagMutationPolicy::CreateOnly)
            .await
            .unwrap();
        assert_eq!(
            second,
            TagMutation::Unchanged,
            "CreateOnly with the identical digest is Unchanged, not a conflict"
        );
    }

    // CreateOnly against a DIFFERENT existing digest is a TagAlreadyExists
    // error and leaves the existing tag byte-identical.
    #[tokio::test]
    async fn test_create_only_conflict_on_divergent_digest() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let d1 = d(HEX1);
        let d2 = d(HEX2);
        let tag_path = root.join("repos").join("myrepo").join("tags").join("t");

        storage
            .mutate_tag("myrepo", "t", &d1, TagMutationPolicy::CreateOnly)
            .await
            .unwrap();

        let err = storage
            .mutate_tag("myrepo", "t", &d2, TagMutationPolicy::CreateOnly)
            .await
            .expect_err("divergent CreateOnly must conflict");
        assert!(
            matches!(err, StorageError::TagAlreadyExists),
            "expected TagAlreadyExists, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&tag_path).unwrap(),
            format!("{}\n", d1.as_str()).as_bytes(),
            "the existing tag is untouched by the failed CreateOnly"
        );
    }

    // Existing tag bytes that do not parse as a digest are treated as absent:
    // CreateOnly succeeds as Created and Replace reports Created (not
    // Replaced), overwriting the corrupt content with the canonical body.
    #[tokio::test]
    async fn test_mutate_tag_treats_corrupt_existing_as_absent() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(HEX1);
        let tags_dir = root.join("repos").join("myrepo").join("tags");

        // CreateOnly over corrupt bytes -> Created.
        let corrupt_create = tags_dir.join("corrupt-create");
        write_file(&corrupt_create, b"this is not a digest at all");
        let created = storage
            .mutate_tag(
                "myrepo",
                "corrupt-create",
                &digest,
                TagMutationPolicy::CreateOnly,
            )
            .await
            .unwrap();
        assert_eq!(
            created,
            TagMutation::Created,
            "unparseable existing content is treated as no existing tag"
        );
        assert_eq!(
            std::fs::read(&corrupt_create).unwrap(),
            format!("{}\n", digest.as_str()).as_bytes(),
            "corrupt content is overwritten with the canonical body"
        );

        // Replace over corrupt bytes -> Created (there is no `previous`).
        let corrupt_replace = tags_dir.join("corrupt-replace");
        write_file(&corrupt_replace, b"\xff\xfe garbage");
        let replaced = storage
            .mutate_tag(
                "myrepo",
                "corrupt-replace",
                &digest,
                TagMutationPolicy::Replace,
            )
            .await
            .unwrap();
        assert_eq!(
            replaced,
            TagMutation::Created,
            "Replace over corrupt content reports Created, not Replaced"
        );
    }

    // delete_tag_conditional with expected_version = None deletes
    // unconditionally; against an absent tag it reports NotFound.
    #[tokio::test]
    async fn test_delete_tag_conditional_unconditional_and_absent() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(HEX1);
        let tag_path = root.join("repos").join("myrepo").join("tags").join("t");

        storage.set_tag("myrepo", "t", &digest).await.unwrap();
        let res = storage
            .delete_tag_conditional("myrepo", "t", None)
            .await
            .unwrap();
        assert_eq!(
            res,
            ConditionalDeleteResult::Deleted,
            "None precondition deletes unconditionally"
        );
        assert!(!tag_path.exists(), "tag file removed");

        let absent = storage
            .delete_tag_conditional("myrepo", "never-existed", None)
            .await
            .unwrap();
        assert_eq!(
            absent,
            ConditionalDeleteResult::NotFound,
            "absent tag reports NotFound"
        );
    }

    // Unconditional delete_tag removes an existing tag and maps an absent tag
    // to StorageError::NotFound.
    #[tokio::test]
    async fn test_delete_tag_unconditional_success_and_absent() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(HEX1);
        let tag_path = root.join("repos").join("myrepo").join("tags").join("t");

        storage.set_tag("myrepo", "t", &digest).await.unwrap();
        storage.delete_tag("myrepo", "t").await.unwrap();
        assert!(!tag_path.exists(), "delete_tag removes the tag file");

        let err = storage
            .delete_tag("myrepo", "never-existed")
            .await
            .expect_err("absent delete_tag must error");
        assert!(
            matches!(err, StorageError::NotFound),
            "absent delete_tag maps to StorageError::NotFound, got {err:?}"
        );
    }
}

// Production-boundary regressions for the tag-mutation *write containment*
// cutover (O-04). These exercise the real `FsStorage` boundary (not the
// validator in isolation) and prove the properties the cutover claims:
// namespace resolution is contained and fails closed on traversal/symlink
// escape; the stable-top-level-`repos` + fresh-per-op resolution authority
// model tolerates repository deletion/recreation without stale-inode writes;
// and read/write namespace + version-token semantics remain coherent.
mod tag_mutation_write_containment {
    use super::*;
    use crate::storage::{ConditionalDeleteResult, TagMutationPolicy};
    use std::os::unix::fs::{MetadataExt as _, symlink};

    fn d(hex: &str) -> Digest {
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    const HEX1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const HEX2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn sorted_entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // A repository name whose component structure escapes (contains a `..`
    // segment) is rejected structurally as InvalidRepoName BEFORE any
    // filesystem authority is resolved — it never reaches the contained
    // primitive, and nothing is written.
    #[tokio::test]
    async fn test_repo_traversal_component_rejected() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        for bad in ["../escape", "a/../../b", ".."] {
            let err = storage
                .set_tag(bad, "t", &d(HEX1))
                .await
                .expect_err("traversal repo name must be rejected");
            assert!(
                matches!(err, StorageError::InvalidRepoName(_)),
                "repo {bad:?} -> InvalidRepoName, got {err:?}"
            );
        }
        // Fails closed: no `repos/` tree materialized by the rejected calls.
        assert!(
            !root.join("repos").join("escape").exists() && !root.join("escape").exists(),
            "no escape path was created"
        );
    }

    // A structurally valid repository name that resolves through an on-disk
    // symlink fails closed at the contained primitive (RESOLVE_NO_SYMLINKS):
    // the mutation errors and does NOT write through the symlink to the
    // external target.
    #[tokio::test]
    async fn test_repo_symlink_escape_fails_closed() {
        let root = tmp_fs_root();
        // External target the symlink points at; must remain untouched.
        let external = tmp_fs_root();

        // Pre-create repos/ and plant a symlink component `linkrepo` -> external.
        let repos = root.join("repos");
        std::fs::create_dir_all(&repos).unwrap();
        symlink(&external, repos.join("linkrepo")).unwrap();

        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let err = storage
            .set_tag("linkrepo", "t", &d(HEX1))
            .await
            .expect_err("symlinked repo component must fail closed");
        // Containment refusal fails closed as a permission-class error
        // (Phase 3 converged kind; the retired path reported Io).
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::PermissionDenied,
                    ..
                }
            ),
            "symlink escape -> PermissionDenied, got {err:?}"
        );
        // The external target was never written through.
        assert_eq!(
            sorted_entry_names(&external),
            Vec::<String>::new(),
            "no bytes written through the symlink to the external tree"
        );
    }

    // A tag that would span path components (an interior slash, or a `..`
    // segment) is rejected before any write; the tag leaf must stay a single
    // contained component.
    #[tokio::test]
    async fn test_tag_path_component_escape_rejected() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        for bad in ["a/b", "..", "../x", "x/.."] {
            let err = storage
                .set_tag("myrepo", bad, &d(HEX1))
                .await
                .expect_err("multi-component / traversal tag must be rejected");
            assert!(
                matches!(err, StorageError::InvalidRepoName(_)),
                "tag {bad:?} -> InvalidRepoName, got {err:?}"
            );
        }
    }

    // A valid nested repository name (interior slashes) resolves through the
    // contained authority to the expected `repos/a/b/c/tags/<tag>` leaf, leaves
    // only the tag and its retained lock, and round-trips through the read path.
    #[tokio::test]
    async fn test_nested_repo_happy_path() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(HEX1);

        storage.set_tag("a/b/c", "rel", &digest).await.unwrap();

        let tags_dir = root
            .join("repos")
            .join("a")
            .join("b")
            .join("c")
            .join("tags");
        assert_eq!(
            std::fs::read(tags_dir.join("rel")).unwrap(),
            format!("{}\n", digest.as_str()).as_bytes(),
            "nested repo tag body is canonical"
        );
        assert_eq!(
            sorted_entry_names(&tags_dir),
            vec!["rel".to_string()],
            "only the tag; locks/staging live in the store-internal tree"
        );
        assert_eq!(
            storage.resolve_tag("a/b/c", "rel").await.unwrap(),
            digest,
            "read path resolves the same nested namespace"
        );
    }

    // Repository deletion/recreation coherence: with only the fixed top-level
    // `repos` authority pinned and the per-repo `tags` authority resolved fresh
    // per operation, removing and recreating a repository beneath `repos`
    // causes the next mutation to target the NEW inode (visible through the
    // path), never a detached/stale old per-repo directory. This distinguishes
    // the approved model from the rejected indefinitely-cached-per-repo design,
    // which would have written into the unlinked old inode.
    #[tokio::test]
    async fn test_repo_deletion_recreation_no_stale_inode_write() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let repo_dir = root.join("repos").join("delrepo");

        // (1) First op initializes and pins the top-level `repos` authority and
        // creates repos/delrepo/tags/t1.
        storage.set_tag("delrepo", "t1", &d(HEX1)).await.unwrap();
        let old_inode = std::fs::metadata(&repo_dir).unwrap().ino();
        assert!(repo_dir.join("tags").join("t1").exists());

        // (2) Externally remove the whole repository namespace (its inode is now
        // detached). A cached-per-repo authority would still point at it.
        let _detached = detach_for_swap(&repo_dir);

        // (3) Another mutation for the same logical repository.
        storage.set_tag("delrepo", "t2", &d(HEX2)).await.unwrap();

        // (4) It is visible through the newly named repository tree...
        let new_inode = std::fs::metadata(&repo_dir).unwrap().ino();
        assert_ne!(
            old_inode, new_inode,
            "repository was recreated as a fresh inode"
        );
        assert_eq!(
            storage.resolve_tag("delrepo", "t2").await.unwrap(),
            d(HEX2),
            "the mutation is visible through the recreated repository"
        );
        // (5) ...and it did not resurrect the detached old tree: only t2 exists
        // (plus its lock); t1 from the removed inode is gone.
        let tags_dir = repo_dir.join("tags");
        assert_eq!(
            sorted_entry_names(&tags_dir),
            vec!["t2".to_string()],
            "write landed in the recreated tree, not a stale per-repo inode"
        );
    }

    // Read/write namespace + version-token coherence: the raw-byte SHA-256
    // token returned by `get_tag_with_version` after a contained mutation is
    // byte-compatible with the token a conditional delete recomputes from the
    // same leaf. A correct token deletes; a wrong token yields
    // PreconditionFailed carrying that exact current token.
    #[tokio::test]
    async fn test_version_token_byte_compatible_with_conditional_delete() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(HEX1);

        storage.set_tag("myrepo", "t", &digest).await.unwrap();

        let (read_digest, version) = storage
            .get_tag_with_version("myrepo", "t")
            .await
            .unwrap()
            .expect("tag present");
        assert_eq!(read_digest, digest, "get_tag sees the contained write");
        // The version token is the SHA-256 over the exact on-disk bytes.
        assert_eq!(
            version,
            hex_sha256(format!("{}\n", digest.as_str()).as_bytes()),
            "version token is raw-byte SHA-256 of `sha256:<hex>\\n`"
        );

        // A wrong precondition preserves the tag and returns the SAME current
        // token representation.
        let mismatch = storage
            .delete_tag_conditional("myrepo", "t", Some("deadbeef"))
            .await
            .unwrap();
        assert_eq!(
            mismatch,
            ConditionalDeleteResult::PreconditionFailed {
                current_version: Some(version.clone()),
            },
            "mismatch reports the byte-compatible current token"
        );
        assert!(
            root.join("repos")
                .join("myrepo")
                .join("tags")
                .join("t")
                .exists(),
            "failed precondition leaves the tag in place"
        );

        // The token from get_tag_with_version drives a successful delete on the
        // same namespace/leaf.
        let deleted = storage
            .delete_tag_conditional("myrepo", "t", Some(&version))
            .await
            .unwrap();
        assert_eq!(deleted, ConditionalDeleteResult::Deleted);
        assert!(
            !root
                .join("repos")
                .join("myrepo")
                .join("tags")
                .join("t")
                .exists(),
            "matching precondition deleted the same leaf"
        );
    }

    // A successful CreateOnly mutation at the real boundary leaves exactly the
    // final leaf plus its retained lock and no `.tmp.*` residue, and writes
    // nothing outside `repos/`.
    #[tokio::test]
    async fn test_successful_mutation_leaves_expected_leaf_and_lock_no_residue() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        let created = storage
            .mutate_tag("myrepo", "t", &d(HEX1), TagMutationPolicy::CreateOnly)
            .await
            .unwrap();
        assert_eq!(created, crate::storage::TagMutation::Created);

        let tags_dir = root.join("repos").join("myrepo").join("tags");
        assert_eq!(
            sorted_entry_names(&tags_dir),
            vec!["t".to_string()],
            "final leaf only; locks/staging live in the store-internal tree"
        );
        assert_eq!(
            sorted_entry_names(&root),
            vec![
                storage_fs::object_store::INTERNAL_DIR.to_string(),
                "repos".to_string()
            ],
            "nothing written outside repos/ plus the store-internal tree"
        );
    }
}

// Production-boundary containment regressions for the manifest payload write
// slice: `put_manifest` (formerly fully ambient) and the manifest-namespace
// read+unlink inside `delete_manifest` (closing the R-18 subject pre-read) now
// resolve through the pinned `repos` authority — fresh per operation, no
// per-repo cache — exactly like the already-contained manifest reads. These
// tests exercise the real `FsStorage` boundary.
mod manifest_write_containment {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    // 64 hex chars each — a valid `sha256:` digest body.
    const MHEX1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MHEX2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn d(hex: &str) -> Digest {
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    // Valid OCI image manifest JSON carrying no `subject` field, so
    // `extract_subject_digest` yields `None` (no referrer cleanup) and
    // `detect_manifest_media_type` returns the OCI image manifest media type.
    fn manifest_body() -> Vec<u8> {
        br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#.to_vec()
    }

    fn sorted_entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn manifest_leaf_path(root: &Path, repo: &str, digest: &Digest) -> PathBuf {
        let mut p = root.join("repos");
        for seg in repo.split('/') {
            p = p.join(seg);
        }
        p.join("manifests").join(digest.hex())
    }

    // put_manifest persists the exact bytes at the contained
    // `repos/<repo>/manifests/<hex>` leaf, reports faithful metadata, and the
    // already-contained read path round-trips the same bytes (write/read
    // coherence). Also freezes delta D1: the contained atomic write creates the
    // leaf with mode 0o600 (repo-wide contract for every contained write).
    #[tokio::test]
    async fn test_put_manifest_writes_exact_bytes_at_contained_path_and_reads_back() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(MHEX1);
        let body = manifest_body();

        let meta = storage
            .put_manifest("lib/app", &digest, bytes::Bytes::from(body.clone()))
            .await
            .expect("put_manifest");
        assert_eq!(
            meta.size,
            body.len() as u64,
            "reported size matches payload"
        );
        assert_eq!(
            meta.media_type, "application/vnd.oci.image.manifest.v1+json",
            "media type detected from payload"
        );

        let path = manifest_leaf_path(&root, "lib/app", &digest);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            body,
            "exact manifest bytes persisted at the contained path"
        );
        // D1: contained atomic write creates the leaf mode 0o600.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "contained manifest leaf mode is 0o600");

        // Read/write coherence: the contained reader returns the same bytes.
        let (rmeta, rbytes) = storage
            .get_manifest("lib/app", &digest)
            .await
            .expect("get_manifest");
        assert_eq!(rbytes.as_ref(), body.as_slice(), "read round-trips bytes");
        assert_eq!(rmeta.size, body.len() as u64, "read size matches");
    }

    // A repository name whose component structure escapes (a `..` segment, an
    // empty segment, or a lone `.`) is rejected structurally as
    // InvalidRepoName by the shared manifest key grammar BEFORE any authority is
    // resolved; nothing is written and no escape path is materialized.
    #[tokio::test]
    async fn test_put_manifest_repo_traversal_rejected_no_escape() {
        let root = tmp_fs_root();
        std::fs::create_dir_all(root.join("repos")).unwrap();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(MHEX1);

        for bad in ["../escape", "a/../../b", "..", "a//b", "a/./b"] {
            let err = storage
                .put_manifest(bad, &digest, bytes::Bytes::from(manifest_body()))
                .await
                .expect_err("traversal repo name must be rejected");
            assert!(
                matches!(err, StorageError::InvalidRepoName(_)),
                "repo {bad:?} -> InvalidRepoName, got {err:?}"
            );
        }
        assert!(
            !root.join("escape").exists() && !root.join("repos").join("escape").exists(),
            "no escape path was created"
        );
    }

    // A structurally valid repository name that resolves through an on-disk
    // symlink fails closed at the contained primitive (RESOLVE_NO_SYMLINKS): the
    // write errors and does NOT create a manifests tree in the external target.
    #[tokio::test]
    async fn test_put_manifest_repo_symlink_escape_fails_closed() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();

        let repos = root.join("repos");
        std::fs::create_dir_all(&repos).unwrap();
        symlink(&external, repos.join("linkrepo")).unwrap();

        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let err = storage
            .put_manifest("linkrepo", &d(MHEX1), bytes::Bytes::from(manifest_body()))
            .await
            .expect_err("symlinked repo component must fail closed");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::PermissionDenied,
                    ..
                }
            ),
            "symlink escape fails closed as PermissionDenied (Phase 4 converged kind), got {err:?}"
        );
        assert_eq!(
            sorted_entry_names(&external),
            Vec::<String>::new(),
            "no manifests tree written through the symlink to the external tree"
        );
    }

    // The manifest write grammar equals the manifest READ grammar (manifest_key):
    // both a deeply nested repo (`a/b/c`) and a colon-bearing repo (`C:/repo`,
    // valid on Linux and accepted by the reader) write to the expected contained
    // leaf AND round-trip through the contained read path. This proves the write
    // accepts a name iff the matching read accepts it (no second grammar).
    #[tokio::test]
    async fn test_put_manifest_nested_and_colon_repo_coherent_with_read() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let body = manifest_body();

        for repo in ["a/b/c", "C:/repo"] {
            let digest = d(MHEX1);
            storage
                .put_manifest(repo, &digest, bytes::Bytes::from(body.clone()))
                .await
                .unwrap_or_else(|e| panic!("put_manifest repo {repo:?}: {e:?}"));

            let path = manifest_leaf_path(&root, repo, &digest);
            assert_eq!(
                std::fs::read(&path).unwrap(),
                body,
                "repo {repo:?} bytes at contained path"
            );
            let (_m, rb) = storage
                .get_manifest(repo, &digest)
                .await
                .unwrap_or_else(|e| panic!("get_manifest repo {repo:?}: {e:?}"));
            assert_eq!(
                rb.as_ref(),
                body.as_slice(),
                "repo {repo:?} read/write coherent"
            );
        }
    }

    // After the fixed `repos` authority is pinned, removing and recreating a
    // repository directory at the same pathname must NOT strand writes on a stale
    // inode: because `repos/<repo>/manifests` is resolved fresh per operation, the
    // next put lands under the NEW inode, visible via the current path. This
    // distinguishes the stable-`repos`+fresh-resolution model from a rejected
    // cached-per-repo authority.
    #[tokio::test]
    async fn test_put_manifest_repo_deletion_recreation_no_stale_inode_write() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let body = manifest_body();

        // First put pins `repos` on first use and creates repos/delrepo/manifests.
        storage
            .put_manifest("delrepo", &d(MHEX1), bytes::Bytes::from(body.clone()))
            .await
            .expect("first put");
        let first_inode = std::fs::metadata(root.join("repos").join("delrepo"))
            .unwrap()
            .ino();

        // Remove and recreate the repository directory at the same pathname
        // (detached, not deleted: the old inode must stay occupied — ext4).
        let _detached = detach_for_swap(&root.join("repos").join("delrepo"));
        std::fs::create_dir_all(root.join("repos").join("delrepo")).unwrap();
        let second_inode = std::fs::metadata(root.join("repos").join("delrepo"))
            .unwrap()
            .ino();
        assert_ne!(
            first_inode, second_inode,
            "test precondition: recreated repository dir is a new inode"
        );

        // The next put must resolve fresh and land under the NEW inode.
        let digest2 = d(MHEX2);
        storage
            .put_manifest("delrepo", &digest2, bytes::Bytes::from(body.clone()))
            .await
            .expect("second put after recreation");
        let path2 = manifest_leaf_path(&root, "delrepo", &digest2);
        assert_eq!(
            std::fs::read(&path2).unwrap(),
            body,
            "second manifest visible via the recreated repository path (no stale-inode write)"
        );
    }

    // A successful put leaves exactly the digest leaf in the manifests directory
    // — the temp-then-rename atomic write leaves no `.tmp.*` residue.
    #[tokio::test]
    async fn test_put_manifest_leaves_only_digest_leaf_no_temp_residue() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(MHEX1);

        storage
            .put_manifest("repoX", &digest, bytes::Bytes::from(manifest_body()))
            .await
            .expect("put_manifest");

        let manifests_dir = root.join("repos").join("repoX").join("manifests");
        assert_eq!(
            sorted_entry_names(&manifests_dir),
            vec![digest.hex()],
            "exactly the digest leaf; no temp residue"
        );
    }

    // delete_manifest's subject pre-read is contained: a symlinked manifest leaf
    // fails closed (RESOLVE_NO_SYMLINKS) BEFORE any unlink — the symlink is not
    // followed for the read and not removed, and the external target is
    // untouched. (Previously the ambient path followed the symlink to read the
    // subject and then removed the link.)
    #[tokio::test]
    async fn test_delete_manifest_symlinked_leaf_fails_closed_no_unlink() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(MHEX1);

        // Plant a symlinked manifest leaf pointing at an external file that holds
        // valid manifest JSON (so only containment — not a parse error — can
        // reject it).
        let ext_target = external.join("outside_manifest.json");
        write_file(&ext_target, &manifest_body());
        let manifests_dir = root.join("repos").join("symrepo").join("manifests");
        std::fs::create_dir_all(&manifests_dir).unwrap();
        let leaf = manifests_dir.join(digest.hex());
        symlink(&ext_target, &leaf).unwrap();

        let err = storage
            .delete_manifest("symrepo", &digest)
            .await
            .expect_err("symlinked manifest leaf must fail closed");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::PermissionDenied,
                    ..
                }
            ),
            "symlink leaf fails closed as PermissionDenied (Phase 4 converged kind), got {err:?}"
        );

        // Fail closed: the symlink remains and the external target is untouched.
        assert!(
            std::fs::symlink_metadata(&leaf)
                .unwrap()
                .file_type()
                .is_symlink(),
            "manifest symlink still present (not unlinked)"
        );
        assert_eq!(
            std::fs::read(&ext_target).unwrap(),
            manifest_body(),
            "external target left unmodified"
        );
    }

    // delete_manifest on an absent manifest maps the contained NotFound to
    // StorageError::NotFound (the subject pre-read short-circuits before the tag
    // and referrer cleanup).
    #[tokio::test]
    async fn test_delete_manifest_absent_returns_not_found() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        let err = storage
            .delete_manifest("norepo", &d(MHEX1))
            .await
            .expect_err("absent manifest -> NotFound");
        assert!(
            matches!(err, StorageError::NotFound),
            "absent manifest -> NotFound, got {err:?}"
        );
    }

    // delete_manifest round-trips a real manifest through the contained read +
    // unlink: after deletion the leaf is gone and the reader reports NotFound,
    // proving the subject pre-read and unlink act on the same pinned namespace.
    #[tokio::test]
    async fn test_delete_manifest_contained_read_then_unlink_removes_leaf() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d(MHEX1);

        storage
            .put_manifest("lib/app", &digest, bytes::Bytes::from(manifest_body()))
            .await
            .expect("put_manifest");
        let path = manifest_leaf_path(&root, "lib/app", &digest);
        assert!(path.exists(), "precondition: manifest present");

        storage
            .delete_manifest("lib/app", &digest)
            .await
            .expect("delete_manifest");

        assert!(!path.exists(), "manifest leaf removed by contained unlink");
        assert!(
            matches!(
                storage.get_manifest("lib/app", &digest).await,
                Err(StorageError::NotFound)
            ),
            "reader reports NotFound after delete"
        );
    }
}

// Production-boundary containment regressions for the referrer write slice:
// `add_referrer` and `remove_referrer` (formerly ambient `ensure_dir` +
// reconstructed-path writes behind a contained read) now resolve a contained
// `repos/<repo>/referrers` authority — fresh per operation, no per-repo cache,
// validated by the referrers READ grammar — with the retained in-process shard
// lock held across the full read/modify/write. These tests exercise the real
// `FsStorage` boundary.
mod referrer_write_containment {
    use super::*;
    use crate::storage::ReferrerDescriptor;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
    use std::sync::Arc;

    fn subject() -> Digest {
        Digest::parse("sha256:9999999999999999999999999999999999999999999999999999999999999999")
            .unwrap()
    }

    fn desc(hex_prefix: char, size: u64) -> ReferrerDescriptor {
        ReferrerDescriptor {
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            digest: format!("sha256:{}", hex_prefix.to_string().repeat(64)),
            size,
            artifact_type: None,
            annotations: None,
        }
    }

    fn referrers_dir(root: &Path, repo: &str) -> PathBuf {
        let mut p = root.join("repos");
        for seg in repo.split('/') {
            p = p.join(seg);
        }
        p.join("referrers")
    }

    fn index_path(root: &Path, repo: &str, subject: &Digest) -> PathBuf {
        referrers_dir(root, repo).join(format!("{}.json", subject.hex()))
    }

    fn sorted_entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // add_referrer persists the exact serde_json array at the contained
    // `repos/<repo>/referrers/<hex>.json` leaf with mode 0o600, leaves no temp
    // residue, and the contained read sees the write.
    #[tokio::test]
    async fn test_add_referrer_writes_exact_json_at_contained_path_and_reads_back() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let d1 = desc('a', 100);

        storage
            .add_referrer("lib/app", &s, d1.clone())
            .await
            .expect("add_referrer");

        let path = index_path(&root, "lib/app", &s);
        let expected = serde_json::to_vec(&vec![d1.clone()]).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            expected,
            "exact single-entry JSON array persisted at the contained path"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "contained referrers index mode is 0o600");
        assert_eq!(
            sorted_entry_names(&referrers_dir(&root, "lib/app")),
            vec![format!("{}.json", s.hex())],
            "exactly the index leaf; no temp residue"
        );
        assert_eq!(
            storage.list_referrers("lib/app", &s).await.unwrap(),
            vec![d1],
            "contained read sees the contained write"
        );
    }

    // A duplicate add does not grow the array; the (unchanged) single-entry
    // array is rewritten, preserving the prior unconditional-rewrite semantics.
    #[tokio::test]
    async fn test_add_referrer_duplicate_is_idempotent_content() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let d1 = desc('a', 100);

        storage.add_referrer("dup", &s, d1.clone()).await.unwrap();
        storage.add_referrer("dup", &s, d1.clone()).await.unwrap();

        assert_eq!(
            std::fs::read(index_path(&root, "dup", &s)).unwrap(),
            serde_json::to_vec(&vec![d1.clone()]).unwrap(),
            "duplicate add leaves exactly one entry with identical bytes"
        );
        assert_eq!(storage.list_referrers("dup", &s).await.unwrap(), vec![d1]);
    }

    // remove_referrer rewrites the exact remaining array; removing the last
    // entry deletes the index leaf (empty-index unlink) while the referrers
    // directory itself remains.
    #[tokio::test]
    async fn test_remove_referrer_rewrites_then_unlinks_empty_index() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let d1 = desc('a', 100);
        let d2 = desc('b', 200);
        let d1_digest = Digest::parse(&d1.digest).unwrap();
        let d2_digest = Digest::parse(&d2.digest).unwrap();

        storage.add_referrer("rm", &s, d1.clone()).await.unwrap();
        storage.add_referrer("rm", &s, d2.clone()).await.unwrap();

        storage
            .remove_referrer("rm", &s, &d1_digest)
            .await
            .expect("remove first referrer");
        let path = index_path(&root, "rm", &s);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            serde_json::to_vec(&vec![d2.clone()]).unwrap(),
            "remaining array rewritten with exact bytes"
        );

        storage
            .remove_referrer("rm", &s, &d2_digest)
            .await
            .expect("remove last referrer");
        assert!(!path.exists(), "empty index leaf is unlinked");
        assert!(
            referrers_dir(&root, "rm").is_dir(),
            "referrers directory itself remains"
        );
        assert_eq!(
            storage.list_referrers("rm", &s).await.unwrap(),
            Vec::<ReferrerDescriptor>::new(),
            "read reports empty after final removal"
        );
    }

    // Removing an absent referrer is a no-op Ok: the index bytes are untouched
    // (no rewrite). On a wholly absent repository the call also returns Ok;
    // contained authority resolution ensures the (empty) referrers directory as
    // a side effect — same class as the accepted delete_tag/delete_manifest
    // ensure-on-absent behavior (frozen here as delta D-B).
    #[tokio::test]
    async fn test_remove_referrer_absent_is_ok_no_rewrite() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let d1 = desc('a', 100);
        let missing = Digest::parse(&desc('f', 0).digest).unwrap();

        storage.add_referrer("abs", &s, d1.clone()).await.unwrap();
        let path = index_path(&root, "abs", &s);
        let before = std::fs::read(&path).unwrap();
        let ino_before = std::fs::metadata(&path).unwrap().ino();

        storage
            .remove_referrer("abs", &s, &missing)
            .await
            .expect("absent referrer removal is Ok");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "index bytes untouched by no-op removal"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            ino_before,
            "no rewrite happened (same inode)"
        );

        // Absent repository: Ok, and NOTHING is created. (The retired
        // authority resolution pre-created repos/<repo>/referrers/ even for
        // no-ops — a mechanics side effect with no production observer; the
        // shared domain performs no write at all. Accepted C1 row.)
        storage
            .remove_referrer("neverseen", &s, &missing)
            .await
            .expect("absent repository removal is Ok");
        assert!(
            !root.join("repos").join("neverseen").exists(),
            "no directories created by the no-op removal"
        );
    }

    // Traversal repository names are rejected as InvalidRepoName by the shared
    // referrers grammar BEFORE any directory creation — for both mutations —
    // and nothing escapes the fixture's repos/ tree.
    #[tokio::test]
    async fn test_referrer_mutation_repo_traversal_rejected_no_side_effect() {
        let root = tmp_fs_root();
        std::fs::create_dir_all(root.join("repos")).unwrap();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let ref_digest = Digest::parse(&desc('a', 0).digest).unwrap();

        for bad in ["../escape", "a/../../b", "..", "a//b", "a/./b"] {
            let err = storage
                .add_referrer(bad, &s, desc('a', 1))
                .await
                .expect_err("traversal repo must be rejected by add_referrer");
            assert!(
                matches!(err, StorageError::InvalidRepoName(_)),
                "add repo {bad:?} -> InvalidRepoName, got {err:?}"
            );
            let err = storage
                .remove_referrer(bad, &s, &ref_digest)
                .await
                .expect_err("traversal repo must be rejected by remove_referrer");
            assert!(
                matches!(err, StorageError::InvalidRepoName(_)),
                "remove repo {bad:?} -> InvalidRepoName, got {err:?}"
            );
        }
        assert!(
            !root.join("escape").exists() && !root.join("repos").join("escape").exists(),
            "no escape path was created"
        );
    }

    // A structurally valid repository name that resolves through an on-disk
    // symlink fails closed at authority resolution (RESOLVE_NO_SYMLINKS): the
    // mutation errors and the external target receives NO directories or bytes.
    // (Previously the ambient ensure_dir followed the symlink and created a
    // referrers/ directory inside the external tree before the read rejected.)
    #[tokio::test]
    async fn test_add_referrer_repo_symlink_escape_fails_closed_no_external_dirs() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();

        let repos = root.join("repos");
        std::fs::create_dir_all(&repos).unwrap();
        symlink(&external, repos.join("linkrepo")).unwrap();

        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let err = storage
            .add_referrer("linkrepo", &subject(), desc('a', 1))
            .await
            .expect_err("symlinked repo component must fail closed");
        // Phase 5: adapter containment refusal is PermissionDenied (was Io;
        // accepted C2 convergence).
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::PermissionDenied,
                    ..
                }
            ),
            "symlink escape -> PermissionDenied error, got {err:?}"
        );
        assert_eq!(
            sorted_entry_names(&external),
            Vec::<String>::new(),
            "no referrers directory or bytes created inside the external tree"
        );
    }

    // A nested repository resolves through the contained authority to
    // `repos/a/b/c/referrers/<hex>.json` and round-trips through the read path.
    #[tokio::test]
    async fn test_nested_repo_happy_path() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let d1 = desc('a', 100);

        storage.add_referrer("a/b/c", &s, d1.clone()).await.unwrap();
        assert_eq!(
            std::fs::read(index_path(&root, "a/b/c", &s)).unwrap(),
            serde_json::to_vec(&vec![d1.clone()]).unwrap(),
            "nested repo index at contained path"
        );
        assert_eq!(
            storage.list_referrers("a/b/c", &s).await.unwrap(),
            vec![d1],
            "read resolves the same nested namespace"
        );
    }

    // After the fixed `repos` authority is pinned, removing and recreating a
    // repository directory must NOT strand writes on a stale inode: the fresh
    // per-op resolution lands the next add under the NEW inode.
    #[tokio::test]
    async fn test_repo_deletion_recreation_no_stale_inode_write() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();

        storage
            .add_referrer("delrepo", &s, desc('a', 1))
            .await
            .expect("first add pins repos");
        let first_inode = std::fs::metadata(root.join("repos").join("delrepo"))
            .unwrap()
            .ino();

        let _detached = detach_for_swap(&root.join("repos").join("delrepo"));
        std::fs::create_dir_all(root.join("repos").join("delrepo")).unwrap();
        let second_inode = std::fs::metadata(root.join("repos").join("delrepo"))
            .unwrap()
            .ino();
        assert_ne!(
            first_inode, second_inode,
            "test precondition: recreated repository dir is a new inode"
        );

        let d2 = desc('b', 2);
        storage
            .add_referrer("delrepo", &s, d2.clone())
            .await
            .expect("second add after recreation");
        assert_eq!(
            std::fs::read(index_path(&root, "delrepo", &s)).unwrap(),
            serde_json::to_vec(&vec![d2]).unwrap(),
            "index visible via the recreated repository path (no stale-inode write)"
        );
    }

    // Whole-root replacement coherence: reads and writes both resolve through
    // roots pinned at construction, so after the storage root is renamed away
    // and recreated, a mutation lands in the OLD (pinned) tree, the contained
    // read still sees it, and the replacement tree is left untouched.
    #[tokio::test]
    async fn test_root_replacement_read_write_coherent() {
        let parent = tmp_fs_root();
        let root = parent.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let d1 = desc('a', 100);
        let d2 = desc('b', 200);

        storage.add_referrer("repl", &s, d1.clone()).await.unwrap();

        // Rename the whole root away and recreate a fresh tree at the old path.
        let moved = parent.join("root.moved");
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir_all(root.join("repos")).unwrap();

        storage
            .add_referrer("repl", &s, d2.clone())
            .await
            .expect("add after root replacement");

        // The mutation landed in the pinned OLD tree...
        assert_eq!(
            std::fs::read(index_path(&moved, "repl", &s)).unwrap(),
            serde_json::to_vec(&vec![d1.clone(), d2.clone()]).unwrap(),
            "write resolved through the pinned old root"
        );
        // ...the pinned contained read sees both entries (coherence)...
        assert_eq!(
            storage.list_referrers("repl", &s).await.unwrap(),
            vec![d1, d2],
            "read/write coherent across root replacement"
        );
        // ...and the replacement tree was not written through ambiently.
        assert!(
            !index_path(&root, "repl", &s).exists(),
            "replacement tree untouched (no ambient reconstruction)"
        );
    }

    // The retained in-process shard lock serializes concurrent read/modify/write
    // sequences on the same subject: N concurrent adds of distinct digests all
    // survive into the final index (no lost update).
    #[tokio::test]
    async fn test_concurrent_adds_serialized_by_shard_lock() {
        let root = tmp_fs_root();
        let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));
        let s = subject();

        let mut handles = Vec::new();
        for i in 0..8u32 {
            let st = Arc::clone(&storage);
            let subj = s.clone();
            handles.push(tokio::spawn(async move {
                let d = ReferrerDescriptor {
                    media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
                    digest: format!("sha256:{:064x}", u128::from(i) + 1),
                    size: u64::from(i),
                    artifact_type: None,
                    annotations: None,
                };
                st.add_referrer("conc", &subj, d).await
            }));
        }
        for h in handles {
            h.await.unwrap().expect("concurrent add succeeds");
        }

        let listed = storage.list_referrers("conc", &s).await.unwrap();
        assert_eq!(
            listed.len(),
            8,
            "all 8 concurrent adds survive (locked read/modify/write, no lost update)"
        );
    }

    // CRITICAL same-authority regression (add): a repository/referrers
    // namespace replacement injected BETWEEN mutation-authority acquisition and
    // mutation inspection must not split the tree that is inspected from the
    // tree that is mutated.
    //
    // Namespace-replacement coherence at the PUBLIC referrer boundary
    // (Phase 5 successor of the retired retained-authority seam regressions).
    //
    // The retired implementation kept an in-flight mutation wholly on the
    // authority resolved BEFORE a repository-namespace replacement (tree A).
    // The shared domain ties inspection and action together with a version
    // precondition instead: the mutation acts wholly on the generation it
    // read — the CURRENT namespace (tree B) — and can never split "read tree
    // X, write tree Y" or clobber a replacement it did not observe. Both
    // shapes are coherent; the new one additionally cannot resurrect an
    // abandoned tree (accepted C2 row of the Phase 5 semantic matrix).
    #[tokio::test]
    async fn test_add_referrer_namespace_replacement_coherence() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let da = desc('a', 100);
        let db = desc('b', 200);
        let dc = desc('c', 300);

        // Tree A holds descriptor A.
        storage.add_referrer("race", &s, da.clone()).await.unwrap();

        // Replace the repository namespace: pathname resolution now reaches
        // tree B, whose index holds descriptor B.
        let repo_dir = root.join("repos").join("race");
        let moved_a = root.join("repos").join("race-tree-a");
        std::fs::rename(&repo_dir, &moved_a).unwrap();
        let tree_b_referrers = repo_dir.join("referrers");
        std::fs::create_dir_all(&tree_b_referrers).unwrap();
        let index_name = format!("{}.json", s.hex());
        std::fs::write(
            tree_b_referrers.join(&index_name),
            serde_json::to_vec(&vec![db.clone()]).unwrap(),
        )
        .unwrap();

        // The mutation acts WHOLLY on the current namespace (tree B): its
        // read and its conditional write name the same generation.
        storage.add_referrer("race", &s, dc.clone()).await.unwrap();

        assert_eq!(
            std::fs::read(tree_b_referrers.join(&index_name)).unwrap(),
            serde_json::to_vec(&vec![db.clone(), dc]).unwrap(),
            "inspection and action both landed on the current tree — no split"
        );
        // The abandoned tree is untouched: exactly [A].
        assert_eq!(
            std::fs::read(moved_a.join("referrers").join(&index_name)).unwrap(),
            serde_json::to_vec(&vec![da]).unwrap(),
            "abandoned tree untouched by the mutation"
        );
    }

    // Removal under the same replacement: the domain observes the CURRENT
    // tree (B), in which the target descriptor is absent — the no-change
    // short-circuit applies to B, and neither tree is mutated. (The retired
    // shape unlinked the abandoned tree A's leaf instead; both outcomes are
    // coherent, and the descriptor's index entry lives only on the abandoned
    // tree either way.)
    #[tokio::test]
    async fn test_remove_referrer_namespace_replacement_coherence() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let s = subject();
        let da = desc('a', 100);
        let db = desc('b', 200);
        let da_digest = Digest::parse(&da.digest).unwrap();

        storage
            .add_referrer("race-rm", &s, da.clone())
            .await
            .unwrap();

        let repo_dir = root.join("repos").join("race-rm");
        let moved_a = root.join("repos").join("race-rm-tree-a");
        std::fs::rename(&repo_dir, &moved_a).unwrap();
        let tree_b_referrers = repo_dir.join("referrers");
        std::fs::create_dir_all(&tree_b_referrers).unwrap();
        let index_name = format!("{}.json", s.hex());
        std::fs::write(
            tree_b_referrers.join(&index_name),
            serde_json::to_vec(&vec![db.clone()]).unwrap(),
        )
        .unwrap();

        storage
            .remove_referrer("race-rm", &s, &da_digest)
            .await
            .unwrap();

        // Tree B (current): descriptor A absent -> no-change short-circuit,
        // exactly [B] and the leaf still present.
        assert_eq!(
            std::fs::read(tree_b_referrers.join(&index_name)).unwrap(),
            serde_json::to_vec(&vec![db]).unwrap(),
            "current tree untouched by the no-change removal"
        );
        // The abandoned tree keeps its index: the removal never reached
        // across namespaces.
        assert_eq!(
            std::fs::read(moved_a.join("referrers").join(&index_name)).unwrap(),
            serde_json::to_vec(&vec![da]).unwrap(),
            "abandoned tree untouched by the removal"
        );
    }
}

// Production-boundary containment regressions for the membership mutation
// slice: `set_membership_candidate`, `clear_membership_candidate`, and
// `unlink_repo_blob` (formerly ambient `repo_blob_path` + `tokio::fs`
// read/write/remove) now resolve ONE contained authority for
// `repo-memberships/by-repo/<key>/<algo>` beneath the pinned memberships root
// — non-creating (absent components preserve the Ok(false) contract with zero
// directory creation) — and retain it across each inspect/rewrite transition.
// Membership records are regular JSON files (no hard links). There is NO lock
// on these transitions (unchanged); no cross-process serialization is claimed.
mod membership_mutation_containment {
    use super::*;
    use crate::storage::repo_membership::{
        MembershipState, RepoBlobMembershipRecord, canonical_repo_membership_relpath,
        encode_canonical_repo_key,
    };
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

    fn d1() -> Digest {
        Digest::parse("sha256:c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1")
            .unwrap()
    }

    fn canonical(repo: &str) -> CanonicalRepoName {
        CanonicalRepoName::parse(repo).unwrap()
    }

    fn record_path(root: &Path, repo: &str, digest: &Digest) -> PathBuf {
        root.join(canonical_repo_membership_relpath(&canonical(repo), digest))
    }

    fn algo_dir(root: &Path, repo: &str) -> PathBuf {
        root.join("repo-memberships")
            .join("by-repo")
            .join(encode_canonical_repo_key(&canonical(repo)))
            .join("sha256")
    }

    fn sorted_entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    async fn link(storage: &FsStorage, repo: &str, digest: &Digest) -> RepoBlobMembershipRecord {
        let rec = RepoBlobMembershipRecord::new_upload(canonical(repo), digest.clone(), None);
        storage.link_repo_blob(&rec).await.expect("link_repo_blob");
        rec
    }

    // Candidate set/clear write the exact serde bytes of the transitioned
    // record at the contained path (mode 0o600), leave no temp residue, and
    // the contained read seam observes each transition.
    #[tokio::test]
    async fn test_candidate_set_clear_exact_bytes_and_read_coherent() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d1();
        let mut rec = link(&storage, "lib/app", &digest).await;

        assert!(
            storage
                .set_membership_candidate("lib/app", &digest, 1234)
                .await
                .unwrap(),
            "transition Active -> Candidate reports true"
        );
        rec.state = MembershipState::Candidate;
        rec.unreferenced_since_unix_secs = Some(1234);
        let path = record_path(&root, "lib/app", &digest);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            serde_json::to_vec(&rec).unwrap(),
            "exact candidate record bytes persisted at the contained path"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "contained rewrite mode is 0o600");
        assert_eq!(
            sorted_entry_names(&algo_dir(&root, "lib/app")),
            vec![format!("{}.json", digest.hex())],
            "exactly the record leaf; no temp residue"
        );
        let seen = storage
            .get_repo_blob_membership("lib/app", &digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seen.state, MembershipState::Candidate);
        assert_eq!(seen.unreferenced_since_unix_secs, Some(1234));

        assert!(
            storage
                .clear_membership_candidate("lib/app", &digest)
                .await
                .unwrap(),
            "transition Candidate -> Active reports true"
        );
        rec.state = MembershipState::Active;
        rec.unreferenced_since_unix_secs = None;
        assert_eq!(
            std::fs::read(&path).unwrap(),
            serde_json::to_vec(&rec).unwrap(),
            "exact cleared record bytes persisted"
        );
    }

    // Already-candidate set and already-active clear short-circuit with
    // Ok(false) BEFORE any rewrite (same inode, same bytes).
    #[tokio::test]
    async fn test_candidate_transitions_idempotent_no_rewrite() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d1();
        link(&storage, "idem", &digest).await;
        let path = record_path(&root, "idem", &digest);

        // Clear while already Active with no since: no-op.
        let before = std::fs::read(&path).unwrap();
        let ino = std::fs::metadata(&path).unwrap().ino();
        assert!(
            !storage
                .clear_membership_candidate("idem", &digest)
                .await
                .unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "bytes untouched");
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino, "no rewrite");

        // Set twice: second is a no-op.
        assert!(
            storage
                .set_membership_candidate("idem", &digest, 99)
                .await
                .unwrap()
        );
        let before = std::fs::read(&path).unwrap();
        let ino = std::fs::metadata(&path).unwrap().ino();
        assert!(
            !storage
                .set_membership_candidate("idem", &digest, 4242)
                .await
                .unwrap(),
            "already-candidate set reports false"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "bytes untouched");
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), ino, "no rewrite");
    }

    // Absent record/repository: all three mutations preserve the Ok(false)
    // contract AND (non-creating authority) leave ZERO directories behind —
    // exactly the prior ambient behavior, with containment added.
    #[tokio::test]
    async fn test_mutations_absent_states_ok_false_zero_side_effects() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d1();

        assert!(
            !storage
                .set_membership_candidate("ghost/repo", &digest, 1)
                .await
                .unwrap()
        );
        assert!(
            !storage
                .clear_membership_candidate("ghost/repo", &digest)
                .await
                .unwrap()
        );
        assert!(
            !storage
                .unlink_repo_blob("ghost/repo", &digest)
                .await
                .unwrap()
        );

        let by_repo = root.join("repo-memberships").join("by-repo");
        assert!(
            !by_repo
                .join(encode_canonical_repo_key(&canonical("ghost/repo")))
                .exists(),
            "no repository key directory created by absent-state mutations"
        );

        // Absent leaf with existing directories: unlink is idempotent.
        link(&storage, "once", &digest).await;
        assert!(storage.unlink_repo_blob("once", &digest).await.unwrap());
        assert!(
            !storage.unlink_repo_blob("once", &digest).await.unwrap(),
            "second unlink reports false"
        );
        assert!(
            storage
                .get_repo_blob_membership("once", &digest)
                .await
                .unwrap()
                .is_none(),
            "read seam agrees the record is gone"
        );
    }

    // Structurally invalid repository names are rejected by the upstream
    // CanonicalRepoName grammar as InvalidRepoName for all three mutations,
    // with zero filesystem effect.
    #[tokio::test]
    async fn test_invalid_repo_rejected_no_side_effect() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d1();

        for bad in ["../escape", "a//b", "", "UPPER/Repo"] {
            assert!(
                matches!(
                    storage.set_membership_candidate(bad, &digest, 1).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "set: repo {bad:?} -> InvalidRepoName"
            );
            assert!(
                matches!(
                    storage.clear_membership_candidate(bad, &digest).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "clear: repo {bad:?} -> InvalidRepoName"
            );
            assert!(
                matches!(
                    storage.unlink_repo_blob(bad, &digest).await,
                    Err(StorageError::InvalidRepoName(_))
                ),
                "unlink: repo {bad:?} -> InvalidRepoName"
            );
        }
        assert!(
            !root.join("repo-memberships").exists() && !root.join("escape").exists(),
            "no membership tree or escape path created"
        );
    }

    // A symlinked repository-key component fails closed at the non-creating
    // contained resolution (RESOLVE_NO_SYMLINKS -> Io): the record inside the
    // external tree is neither read into a decision nor mutated. (Previously
    // the ambient read/write followed the symlink and transitioned the
    // external record.)
    #[tokio::test]
    async fn test_symlinked_key_component_fails_closed_external_untouched() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d1();

        // External tree holds a valid Active record.
        let rec = RepoBlobMembershipRecord::new_upload(canonical("symrepo"), digest.clone(), None);
        let ext_algo = external.join("sha256");
        std::fs::create_dir_all(&ext_algo).unwrap();
        let ext_leaf = ext_algo.join(format!("{}.json", digest.hex()));
        std::fs::write(&ext_leaf, serde_json::to_vec(&rec).unwrap()).unwrap();

        // Plant the key component as a symlink to the external tree.
        let by_repo = root.join("repo-memberships").join("by-repo");
        std::fs::create_dir_all(&by_repo).unwrap();
        symlink(
            &external,
            by_repo.join(encode_canonical_repo_key(&canonical("symrepo"))),
        )
        .unwrap();

        for (op, res) in [
            (
                "set",
                storage
                    .set_membership_candidate("symrepo", &digest, 7)
                    .await,
            ),
            (
                "clear",
                storage.clear_membership_candidate("symrepo", &digest).await,
            ),
            ("unlink", storage.unlink_repo_blob("symrepo", &digest).await),
        ] {
            let err = res.expect_err("symlinked key component must fail closed");
            // Phase 6: the pinned adapter reports its containment refusal as
            // PermissionDenied (the retired contained seam said Io — both are
            // production-inert Internal kinds; accepted C2 convergence).
            assert!(
                matches!(
                    err,
                    StorageError::Internal {
                        kind: crate::storage::StorageErrorKind::PermissionDenied,
                        ..
                    }
                ),
                "{op}: symlink escape -> PermissionDenied error, got {err:?}"
            );
        }
        assert_eq!(
            std::fs::read(&ext_leaf).unwrap(),
            serde_json::to_vec(&rec).unwrap(),
            "external record neither mutated nor removed"
        );
    }

    // Removing and recreating the repository's membership tree between
    // operations: the next mutation freshly resolves the named repository and
    // addresses the NEW tree (no stale per-repo authority is cached).
    #[tokio::test]
    async fn test_repo_membership_tree_delete_recreate_fresh_resolution() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d1();
        link(&storage, "delrepo", &digest).await;
        storage
            .set_membership_candidate("delrepo", &digest, 5)
            .await
            .unwrap();

        let key_dir = root
            .join("repo-memberships")
            .join("by-repo")
            .join(encode_canonical_repo_key(&canonical("delrepo")));
        let first_inode = std::fs::metadata(&key_dir).unwrap().ino();
        let _detached = detach_for_swap(&key_dir);

        // Recreate via the production link path; new inode.
        let mut rec = link(&storage, "delrepo", &digest).await;
        assert_ne!(
            std::fs::metadata(&key_dir).unwrap().ino(),
            first_inode,
            "test precondition: recreated key directory is a new inode"
        );

        // Fresh resolution addresses the NEW tree.
        assert!(
            storage
                .set_membership_candidate("delrepo", &digest, 11)
                .await
                .unwrap()
        );
        rec.state = MembershipState::Candidate;
        rec.unreferenced_since_unix_secs = Some(11);
        assert_eq!(
            std::fs::read(record_path(&root, "delrepo", &digest)).unwrap(),
            serde_json::to_vec(&rec).unwrap(),
            "mutation landed on the recreated tree via fresh resolution"
        );
    }

    // Namespace-replacement coherence at the PUBLIC membership boundary
    // (Phase 6 successor of the retired retained-authority seam regressions).
    //
    // The retired implementation kept an in-flight transition wholly on the
    // authority resolved BEFORE a membership-namespace replacement (tree A).
    // The shared domain ties inspection and action together with a version
    // precondition instead: the transition acts wholly on the generation it
    // read — the CURRENT namespace (tree B) — and can never split "read tree
    // X, write tree Y" or overwrite a generation it did not observe. Both
    // shapes are coherent; the new one additionally cannot resurrect an
    // abandoned tree (accepted C2 row of the Phase 6 semantic matrix).
    #[tokio::test]
    async fn test_set_candidate_namespace_replacement_coherence() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d1();
        let rec_a = link(&storage, "race", &digest).await;

        // Replace the repository's membership namespace: pathname resolution
        // now reaches tree B (distinguishable Active record).
        let key_dir = root
            .join("repo-memberships")
            .join("by-repo")
            .join(encode_canonical_repo_key(&canonical("race")));
        let moved_a = key_dir.with_file_name("race-tree-a");
        std::fs::rename(&key_dir, &moved_a).unwrap();
        let mut rec_b = rec_a.clone();
        rec_b.created_at_unix_secs = 42;
        let tree_b_algo = key_dir.join("sha256");
        std::fs::create_dir_all(&tree_b_algo).unwrap();
        let leaf_name = format!("{}.json", digest.hex());
        std::fs::write(
            tree_b_algo.join(&leaf_name),
            serde_json::to_vec(&rec_b).unwrap(),
        )
        .unwrap();

        // The transition acts WHOLLY on the current namespace (tree B): its
        // read and its conditional write name the same generation.
        assert!(
            storage
                .set_membership_candidate("race", &digest, 777)
                .await
                .unwrap(),
            "transition applies against the current tree"
        );
        let mut expect_b = rec_b.clone();
        expect_b.state = MembershipState::Candidate;
        expect_b.unreferenced_since_unix_secs = Some(777);
        assert_eq!(
            std::fs::read(tree_b_algo.join(&leaf_name)).unwrap(),
            serde_json::to_vec(&expect_b).unwrap(),
            "inspection and action both landed on the current tree — no split"
        );
        // The abandoned tree is untouched: still the original Active record.
        assert_eq!(
            std::fs::read(moved_a.join("sha256").join(&leaf_name)).unwrap(),
            serde_json::to_vec(&rec_a).unwrap(),
            "abandoned tree untouched by the transition"
        );
    }

    // Clear under the same replacement: the domain observes the CURRENT tree
    // (B), whose Active/no-since record takes the no-change short-circuit —
    // neither tree is mutated. (The retired retained-authority shape cleared
    // the abandoned tree A's candidate instead; both outcomes are coherent,
    // and the candidate state lives only on the abandoned tree either way.)
    #[tokio::test]
    async fn test_clear_candidate_namespace_replacement_coherence() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let digest = d1();
        let rec_a = link(&storage, "race-clr", &digest).await;
        storage
            .set_membership_candidate("race-clr", &digest, 55)
            .await
            .unwrap();
        let mut cand_a = rec_a.clone();
        cand_a.state = MembershipState::Candidate;
        cand_a.unreferenced_since_unix_secs = Some(55);

        // Replace with tree B: Active record, no since (the no-change state).
        let key_dir = root
            .join("repo-memberships")
            .join("by-repo")
            .join(encode_canonical_repo_key(&canonical("race-clr")));
        let moved_a = key_dir.with_file_name("race-clr-tree-a");
        std::fs::rename(&key_dir, &moved_a).unwrap();
        let mut rec_b = rec_a.clone();
        rec_b.created_at_unix_secs = 42;
        let tree_b_algo = key_dir.join("sha256");
        std::fs::create_dir_all(&tree_b_algo).unwrap();
        let leaf_name = format!("{}.json", digest.hex());
        std::fs::write(
            tree_b_algo.join(&leaf_name),
            serde_json::to_vec(&rec_b).unwrap(),
        )
        .unwrap();

        // The current tree's record is already Active/no-since: no-change.
        assert!(
            !storage
                .clear_membership_candidate("race-clr", &digest)
                .await
                .unwrap(),
            "current tree short-circuits; the removal never reaches across \
             namespaces"
        );
        assert_eq!(
            std::fs::read(tree_b_algo.join(&leaf_name)).unwrap(),
            serde_json::to_vec(&rec_b).unwrap(),
            "current tree untouched by the no-change clear"
        );
        // The abandoned tree keeps its candidate record.
        assert_eq!(
            std::fs::read(moved_a.join("sha256").join(&leaf_name)).unwrap(),
            serde_json::to_vec(&cand_a).unwrap(),
            "abandoned tree untouched by the clear"
        );
    }
}

// Production-boundary containment regressions for the R-6 slice: the
// `delete_manifest` tag-cleanup scan (formerly ambient `list_tag_files` +
// `read_to_string` + ignored `remove_file`) now enumerates, inspects, and
// deletes matching tags ALL through ONE retained contained `repos/<repo>/tags`
// authority, resolved non-creating (absent tags directory -> empty scan with
// zero directory creation). The scan takes no per-tag locks (unchanged
// historical semantics) and delete_manifest's ordering (manifest unlink ->
// tag scan -> referrer cleanup) is preserved.
mod delete_manifest_tag_cleanup_containment {
    use super::*;
    use std::os::unix::fs::symlink;

    const DHEX: &str = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1";
    const EHEX: &str = "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2";

    fn d(hex: &str) -> Digest {
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    fn manifest_body() -> bytes::Bytes {
        bytes::Bytes::from_static(
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#,
        )
    }

    async fn put(storage: &FsStorage, repo: &str, digest: &Digest) {
        storage
            .put_manifest(repo, digest, manifest_body())
            .await
            .expect("put_manifest");
    }

    fn tags_dir(root: &Path, repo: &str) -> PathBuf {
        let mut p = root.join("repos");
        for seg in repo.split('/') {
            p = p.join(seg);
        }
        p.join("tags")
    }

    fn tag_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .expect("read tags dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    // Deleting a manifest removes ALL tags pointing at its digest (created via
    // the production set_tag, i.e. canonical `sha256:<hex>\n` bodies) and
    // leaves unrelated tags untouched.
    #[tokio::test]
    async fn test_delete_manifest_removes_matching_tags_leaves_unrelated() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let dd = d(DHEX);
        let de = d(EHEX);
        put(&storage, "clean", &dd).await;
        put(&storage, "clean", &de).await;

        storage.set_tag("clean", "v1", &dd).await.unwrap();
        storage.set_tag("clean", "v1-alias", &dd).await.unwrap();
        storage.set_tag("clean", "other", &de).await.unwrap();

        storage.delete_manifest("clean", &dd).await.unwrap();

        assert_eq!(
            tag_names(&tags_dir(&root, "clean")),
            vec!["other".to_string()],
            "both matching tags removed; unrelated tag remains"
        );
        assert_eq!(
            storage.resolve_tag("clean", "other").await.unwrap(),
            de,
            "unrelated tag still resolves"
        );
        assert!(
            matches!(
                storage.resolve_tag("clean", "v1").await,
                Err(StorageError::NotFound)
            ),
            "matching tag no longer resolves"
        );
    }

    // Absent tags directory: the cleanup is an empty scan and — non-creating
    // resolution — does NOT create the tags directory. Empty tags directory:
    // no-op success.
    #[tokio::test]
    async fn test_delete_manifest_absent_and_empty_tags_dir_zero_side_effects() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let dd = d(DHEX);

        // No tags directory at all.
        put(&storage, "notags", &dd).await;
        storage.delete_manifest("notags", &dd).await.unwrap();
        assert!(
            !tags_dir(&root, "notags").exists(),
            "absent tags directory is not created by the cleanup scan"
        );

        // Empty tags directory.
        let de = d(EHEX);
        put(&storage, "emptytags", &de).await;
        std::fs::create_dir_all(tags_dir(&root, "emptytags")).unwrap();
        storage.delete_manifest("emptytags", &de).await.unwrap();
        assert_eq!(
            tag_names(&tags_dir(&root, "emptytags")),
            Vec::<String>::new()
        );
    }

    // Non-UTF-8 tag content propagates as CorruptData (Phase 3 converged
    // kind; the retired scan used Io), and - frozen ordering - the manifest
    // itself is already unlinked by then (partial cleanup is an accepted
    // possibility; no rollback is claimed).
    #[tokio::test]
    async fn test_delete_manifest_malformed_tag_content_propagates_after_unlink() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let dd = d(DHEX);
        put(&storage, "badtag", &dd).await;
        let tdir = tags_dir(&root, "badtag");
        std::fs::create_dir_all(&tdir).unwrap();
        std::fs::write(tdir.join("broken"), [0xFF, 0xFE, 0x00, 0x01]).unwrap();

        let err = storage
            .delete_manifest("badtag", &dd)
            .await
            .expect_err("non-UTF-8 tag content must propagate");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::CorruptData,
                    ..
                }
            ),
            "non-UTF-8 tag content -> CorruptData, got {err:?}"
        );
        // Ordering frozen: the manifest was unlinked before the tag scan.
        let manifest_path = root
            .join("repos")
            .join("badtag")
            .join("manifests")
            .join(dd.hex());
        assert!(
            !manifest_path.exists(),
            "manifest unlink precedes the tag scan (partial cleanup accepted)"
        );
    }

    // A symlinked tag entry is NOT a tag object: the shared scan's
    // structural filter (non-regular entries are not generic objects)
    // excludes it, so the cleanup completes without following it; the
    // symlink survives and the external target is untouched. Directly
    // ADDRESSING it as a tag still fails closed (PermissionDenied). The
    // retired FS-only scan instead aborted the whole cleanup with Io.
    #[tokio::test]
    async fn test_delete_manifest_symlinked_tag_entry_excluded_and_untouched() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let dd = d(DHEX);
        put(&storage, "symtag", &dd).await;

        // External target whose content WOULD match the deleted digest.
        let ext_target = external.join("outside_tag");
        std::fs::write(&ext_target, format!("{}\n", dd.as_str())).unwrap();
        let tdir = tags_dir(&root, "symtag");
        std::fs::create_dir_all(&tdir).unwrap();
        let link = tdir.join("linked-tag");
        symlink(&ext_target, &link).unwrap();

        storage
            .delete_manifest("symtag", &dd)
            .await
            .expect("symlinked entry is structurally excluded; cleanup completes");
        // Directly addressing the symlinked name as a tag fails closed.
        let read_err = storage
            .resolve_tag("symtag", "linked-tag")
            .await
            .expect_err("symlinked leaf fails closed when addressed directly");
        assert!(
            matches!(
                read_err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::PermissionDenied,
                    ..
                }
            ),
            "symlinked tag leaf -> PermissionDenied, got {read_err:?}"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink not removed"
        );
        assert_eq!(
            std::fs::read_to_string(&ext_target).unwrap(),
            format!("{}\n", dd.as_str()),
            "external target untouched"
        );
    }

    // Nested repository: the cleanup resolves `repos/a/b/c/tags` through the
    // contained chain and removes the matching tag there.
    #[tokio::test]
    async fn test_delete_manifest_nested_repo_tag_cleanup() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let dd = d(DHEX);
        put(&storage, "a/b/c", &dd).await;
        storage.set_tag("a/b/c", "rel", &dd).await.unwrap();

        storage.delete_manifest("a/b/c", &dd).await.unwrap();
        assert_eq!(
            tag_names(&tags_dir(&root, "a/b/c")),
            Vec::<String>::new(),
            "matching tag removed from the nested repository"
        );
    }

    // Repository deletion/recreation BETWEEN operations: the next
    // delete_manifest freshly resolves the named repository and cleans the NEW
    // tree (no stale per-repo authority).
    #[tokio::test]
    async fn test_delete_manifest_tag_cleanup_repo_recreate_between_operations() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let dd = d(DHEX);
        put(&storage, "recreate", &dd).await;
        storage.set_tag("recreate", "v1", &dd).await.unwrap();
        storage.delete_manifest("recreate", &dd).await.unwrap();

        // Remove and recreate the whole repository, repopulate.
        std::fs::remove_dir_all(root.join("repos").join("recreate")).unwrap();
        put(&storage, "recreate", &dd).await;
        storage.set_tag("recreate", "v2", &dd).await.unwrap();

        storage.delete_manifest("recreate", &dd).await.unwrap();
        assert_eq!(
            tag_names(&tags_dir(&root, "recreate")),
            Vec::<String>::new(),
            "cleanup acted on the recreated repository tree"
        );
    }

    // Phase 3 converged cleanup profile: the shared tag-domain cleanup
    // resolves each key freshly beneath the PINNED root (the generic
    // ObjectStore is stateless by key; the retired one-retained-authority
    // property was an FS implementation detail the S3 backend never had).
    // A tags-namespace replacement under the same pinned root is therefore
    // observed by the scan — while root pinning and symlink fail-closed
    // containment remain fully in force (see the containment regressions).
    #[tokio::test]
    async fn test_tag_cleanup_fresh_resolution_under_pinned_root() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let dd = d(DHEX);
        let de = d(EHEX);
        put(&storage, "race", &dd).await;

        // Tree A: one matching tag and one unrelated tag.
        let tree_a = tags_dir(&root, "race");
        std::fs::create_dir_all(&tree_a).unwrap();
        std::fs::write(tree_a.join("match-me"), format!("{}\n", dd.as_str())).unwrap();
        std::fs::write(tree_a.join("keep-me"), format!("{}\n", de.as_str())).unwrap();

        // Replace the tags namespace BEFORE the cleanup pass: resolution now
        // reaches tree B (still under the pinned root).
        let moved_a = tree_a.with_file_name("tags-tree-a");
        std::fs::rename(&tree_a, &moved_a).unwrap();
        std::fs::create_dir_all(&tree_a).unwrap();
        std::fs::write(tree_a.join("match-me"), format!("{}\n", dd.as_str())).unwrap();

        // delete_manifest's cleanup acts on the CURRENT namespace (tree B):
        // its matching tag is removed; the detached tree A is untouched.
        storage.delete_manifest("race", &dd).await.unwrap();
        assert_eq!(
            tag_names(&tree_a),
            Vec::<String>::new(),
            "cleanup acted on the current (replacement) tree under the pinned root"
        );
        let mut detached = tag_names(&moved_a);
        detached.sort();
        assert_eq!(
            detached,
            vec!["keep-me".to_string(), "match-me".to_string()],
            "the detached tree is not reachable by fresh key resolution"
        );
    }
}

// Production-boundary containment regressions for the GC quarantine protocol:
// `quarantine_blob` / `restore_quarantined_blob` (contained cross-authority
// rename between the pinned `blobs` and `quarantine` roots), the quarantine
// timestamp helpers, and `delete_blob_conditional` (revalidation via fstat +
// streaming hash on the fd opened through ONE retained quarantine shard
// authority, unlink through that same authority). Shard resolution is
// non-creating for inspection paths, so absent-state contracts keep zero
// directory-creation side effects.
mod gc_quarantine_containment {
    use super::*;
    use crate::storage::mutation_authority::RuntimeMutationAuthority;
    use crate::storage::{BlobObjectVersion, GcDeleteResult, GcQuarantineResult, GcStorage};
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    const QHEX: &str = "f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5";

    fn d(hex: &str) -> Digest {
        Digest::parse(&format!("sha256:{hex}")).unwrap()
    }

    fn cas_path(root: &Path, digest: &Digest) -> PathBuf {
        root.join("blobs")
            .join(digest.algorithm())
            .join(digest.prefix2())
            .join(digest.hex())
    }

    fn q_path(root: &Path, digest: &Digest) -> PathBuf {
        root.join("quarantine")
            .join("blobs")
            .join(digest.algorithm())
            .join(digest.prefix2())
            .join(digest.hex())
    }

    fn ts_path(root: &Path, digest: &Digest) -> PathBuf {
        root.join("quarantine")
            .join("meta")
            .join(digest.algorithm())
            .join(digest.prefix2())
            .join(format!("{}.ts", digest.hex()))
    }

    fn plant_cas_blob(root: &Path, digest: &Digest, bytes: &[u8]) {
        let p = cas_path(root, digest);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, bytes).unwrap();
    }

    async fn authority_for(root: &Path) -> RuntimeMutationAuthority {
        RuntimeMutationAuthority::acquire(
            Arc::new(FsStorage::new(root.to_path_buf(), 1024 * 1024)),
            "gc-containment-test",
        )
        .await
        .expect("acquire mutation authority")
    }

    fn dummy_version() -> BlobObjectVersion {
        BlobObjectVersion("fs:0:0:dummy".to_string())
    }

    /// The current live CAS leaf's candidate token, derived by the shared
    /// production rules (`listing::candidate_version`) — what a GC listing
    /// pass would have produced for this leaf, and what `quarantine_blob`
    /// validates against.
    fn live_candidate_version(root: &Path, digest: &Digest) -> BlobObjectVersion {
        let meta = std::fs::metadata(cas_path(root, digest)).expect("live blob metadata");
        listing::candidate_version(meta.modified().ok(), meta.len())
    }

    /// Deterministically pin a file's mtime (whole seconds) so version tokens
    /// can be forced equal or distinct without sleeps.
    fn set_mtime_secs(path: &Path, secs: i64) {
        use std::os::unix::ffi::OsStrExt as _;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: secs,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: secs,
                tv_nsec: 0,
            },
        ];
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "utimensat({path:?}) failed");
    }

    // Full protocol round trip with exact artifacts: quarantine moves the CAS
    // leaf into the quarantine shard byte-identically, writes the `<secs>\n`
    // timestamp (mode 0o600, no temp residue), the contained read seam
    // observes the quarantined version, and the conditional delete removes the
    // leaf and the timestamp.
    #[tokio::test]
    async fn test_quarantine_version_delete_roundtrip_exact_artifacts() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        let body = b"gc-quarantine-payload".to_vec();
        plant_cas_blob(&root, &digest, &body);

        let res = storage
            .quarantine_blob(&permit, &digest, &live_candidate_version(&root, &digest))
            .await
            .expect("quarantine_blob");
        assert_eq!(
            res,
            GcQuarantineResult::Quarantined {
                size: body.len() as u64
            },
            "reports the pre-move size"
        );
        assert!(!cas_path(&root, &digest).exists(), "CAS leaf moved away");
        assert_eq!(
            std::fs::read(q_path(&root, &digest)).unwrap(),
            body,
            "quarantined bytes identical (rename, not copy)"
        );

        let tsp = ts_path(&root, &digest);
        let ts_content = std::fs::read_to_string(&tsp).unwrap();
        let secs: u64 = ts_content.trim().parse().expect("parseable seconds");
        assert!(ts_content.ends_with('\n') && secs > 0, "canonical ts body");
        assert_eq!(
            std::fs::metadata(&tsp).unwrap().permissions().mode() & 0o777,
            0o600,
            "contained ts write mode is 0o600"
        );
        // No temp residue in either shard directory.
        for dir in [
            q_path(&root, &digest).parent().unwrap().to_path_buf(),
            tsp.parent().unwrap().to_path_buf(),
        ] {
            let mut names: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            assert_eq!(names.len(), 1, "exactly one leaf in {dir:?}: {names:?}");
        }

        let version = storage
            .quarantined_blob_version(&digest)
            .await
            .unwrap()
            .expect("contained read seam sees the quarantined blob");

        let del = storage
            .delete_blob_conditional(&permit, &digest, Some(&version))
            .await
            .expect("delete_blob_conditional");
        assert_eq!(del, GcDeleteResult::Deleted);
        assert!(!q_path(&root, &digest).exists(), "quarantined leaf removed");
        assert!(!tsp.exists(), "timestamp removed after deletion");
    }

    // Rescue path: restore moves the quarantined leaf back into CAS
    // byte-identically and removes the timestamp; a second restore is None.
    #[tokio::test]
    async fn test_restore_rescue_roundtrip() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        let body = b"rescued-payload".to_vec();
        plant_cas_blob(&root, &digest, &body);

        storage
            .quarantine_blob(&permit, &digest, &live_candidate_version(&root, &digest))
            .await
            .unwrap();
        assert!(ts_path(&root, &digest).exists());

        let restored = storage
            .restore_quarantined_blob(&permit, &digest)
            .await
            .expect("restore");
        assert_eq!(restored, Some(body.len() as u64));
        assert_eq!(
            std::fs::read(cas_path(&root, &digest)).unwrap(),
            body,
            "blob restored byte-identically"
        );
        assert!(!q_path(&root, &digest).exists(), "quarantine leaf gone");
        assert!(!ts_path(&root, &digest).exists(), "timestamp removed");

        assert_eq!(
            storage
                .restore_quarantined_blob(&permit, &digest)
                .await
                .unwrap(),
            None,
            "second restore reports absence"
        );
    }

    // Absent-digest contracts keep their results AND (non-creating shard
    // resolution) create no shard directories.
    #[tokio::test]
    async fn test_absent_states_preserved_zero_shard_side_effects() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);

        assert_eq!(
            storage
                .quarantine_blob(&permit, &digest, &dummy_version())
                .await
                .unwrap(),
            GcQuarantineResult::Skipped,
            "absent CAS blob -> Skipped"
        );
        assert_eq!(
            storage
                .restore_quarantined_blob(&permit, &digest)
                .await
                .unwrap(),
            None,
            "absent quarantined blob -> None"
        );
        assert_eq!(
            storage
                .delete_blob_conditional(&permit, &digest, Some(&dummy_version()))
                .await
                .unwrap(),
            GcDeleteResult::NotFound,
            "absent quarantined blob -> NotFound"
        );

        for p in [
            root.join("blobs").join("sha256"),
            root.join("quarantine").join("blobs"),
            root.join("quarantine").join("meta"),
        ] {
            assert!(
                !p.exists(),
                "no shard directories created by absent-state operations: {p:?}"
            );
        }
    }

    // The deletion predicate is preserved: a content change after version
    // capture yields PreconditionFailed carrying the recomputed version, and
    // neither the object nor its timestamp is touched.
    #[tokio::test]
    async fn test_delete_precondition_mismatch_preserves_object_and_ts() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"original");
        storage
            .quarantine_blob(&permit, &digest, &live_candidate_version(&root, &digest))
            .await
            .unwrap();
        let stale_version = storage
            .quarantined_blob_version(&digest)
            .await
            .unwrap()
            .unwrap();

        // Concurrent mutation of the quarantined object.
        std::fs::write(q_path(&root, &digest), b"changed-content").unwrap();

        let res = storage
            .delete_blob_conditional(&permit, &digest, Some(&stale_version))
            .await
            .unwrap();
        let GcDeleteResult::PreconditionFailed {
            current_version: Some(current),
        } = res
        else {
            panic!("expected PreconditionFailed with current version, got {res:?}");
        };
        assert_ne!(current, stale_version);
        // Coherence: the returned current version equals the contained read
        // seam's view of the same object.
        assert_eq!(
            storage
                .quarantined_blob_version(&digest)
                .await
                .unwrap()
                .unwrap(),
            current,
            "recomputed version coherent with the contained read seam"
        );
        assert_eq!(
            std::fs::read(q_path(&root, &digest)).unwrap(),
            b"changed-content",
            "object preserved on precondition failure"
        );
        assert!(
            ts_path(&root, &digest).exists(),
            "timestamp preserved on precondition failure"
        );
    }

    // Concurrent deletion by another worker: the conditional delete reports
    // NotFound and cleans up the orphaned timestamp.
    #[tokio::test]
    async fn test_delete_already_deleted_by_other_worker() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"raced");
        storage
            .quarantine_blob(&permit, &digest, &live_candidate_version(&root, &digest))
            .await
            .unwrap();
        let version = storage
            .quarantined_blob_version(&digest)
            .await
            .unwrap()
            .unwrap();

        // Another worker wins the race.
        std::fs::remove_file(q_path(&root, &digest)).unwrap();

        assert_eq!(
            storage
                .delete_blob_conditional(&permit, &digest, Some(&version))
                .await
                .unwrap(),
            GcDeleteResult::NotFound
        );
        assert!(
            !ts_path(&root, &digest).exists(),
            "orphaned timestamp cleaned up on NotFound"
        );
    }

    // A symlinked quarantined leaf fails closed at the contained open: the
    // revalidation never hashes the external target, nothing is unlinked, and
    // the timestamp stays. (Previously the ambient stat+open+hash FOLLOWED the
    // symlink and a matching version deleted the link.)
    #[tokio::test]
    async fn test_delete_symlinked_leaf_fails_closed() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);

        let ext_target = external.join("outside_blob");
        std::fs::write(&ext_target, b"external-bytes").unwrap();
        let qp = q_path(&root, &digest);
        std::fs::create_dir_all(qp.parent().unwrap()).unwrap();
        symlink(&ext_target, &qp).unwrap();
        let tsp = ts_path(&root, &digest);
        std::fs::create_dir_all(tsp.parent().unwrap()).unwrap();
        std::fs::write(&tsp, "1700000000\n").unwrap();

        let err = storage
            .delete_blob_conditional(&permit, &digest, Some(&dummy_version()))
            .await
            .expect_err("symlinked quarantined leaf must fail closed");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::Io,
                    ..
                }
            ),
            "symlink -> Io error, got {err:?}"
        );
        assert!(
            std::fs::symlink_metadata(&qp)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink not unlinked"
        );
        assert_eq!(
            std::fs::read(&ext_target).unwrap(),
            b"external-bytes",
            "external target untouched"
        );
        assert!(tsp.exists(), "timestamp preserved on fail-closed abort");
    }

    // A symlinked CAS shard component fails closed for quarantine_blob: the
    // external tree is neither inspected into a decision nor renamed from.
    // (Previously the ambient metadata/rename followed the symlink.)
    #[tokio::test]
    async fn test_quarantine_blob_symlinked_shard_fails_closed() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);

        // External dir holds a blob under the digest name.
        std::fs::write(external.join(digest.hex()), b"external-blob").unwrap();
        let algo_dir = root.join("blobs").join("sha256");
        std::fs::create_dir_all(&algo_dir).unwrap();
        symlink(&external, algo_dir.join(digest.prefix2())).unwrap();

        let err = storage
            .quarantine_blob(&permit, &digest, &dummy_version())
            .await
            .expect_err("symlinked shard component must fail closed");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::Io,
                    ..
                }
            ),
            "symlink escape -> Io error, got {err:?}"
        );
        assert_eq!(
            std::fs::read(external.join(digest.hex())).unwrap(),
            b"external-blob",
            "external blob untouched"
        );
        assert!(
            !root.join("quarantine").exists(),
            "no quarantine tree created by the failed operation"
        );
    }

    // CRITICAL same-authority regression (destructive delete): a quarantine
    // shard replacement injected BETWEEN authority acquisition and the
    // revalidate/unlink pass at the production seam (quarantine_blobs_shard +
    // delete_blob_conditional_in) must not split the object that is
    // revalidated from the leaf that is unlinked.
    //
    //   BROKEN:   authority A -> independent re-resolution revalidates B ->
    //             version mismatch (or worse, unlink of B's leaf)
    //   REQUIRED: authority A -> open/fstat/hash A's leaf -> match -> unlink
    //             ON TREE A; replacement tree B untouched.
    #[tokio::test]
    async fn test_delete_same_authority_across_namespace_replacement() {
        use storage_fs::FileName;

        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"tree-a-content");
        storage
            .quarantine_blob(&permit, &digest, &live_candidate_version(&root, &digest))
            .await
            .unwrap();
        let version_a = storage
            .quarantined_blob_version(&digest)
            .await
            .unwrap()
            .unwrap();

        // Acquire the mutation authority (tree A's shard).
        let shard = storage
            .quarantine_blobs_shard(&digest, false)
            .await
            .unwrap()
            .expect("shard resolves for the quarantined blob");
        let leaf = FileName::new(digest.hex()).unwrap();

        // Injected boundary: replace the shard so pathname resolution now
        // reaches tree B with different content under the same digest name.
        let shard_path = q_path(&root, &digest).parent().unwrap().to_path_buf();
        let moved_a = shard_path.with_file_name("shard-tree-a");
        std::fs::rename(&shard_path, &moved_a).unwrap();
        std::fs::create_dir_all(&shard_path).unwrap();
        std::fs::write(shard_path.join(digest.hex()), b"tree-b-content").unwrap();

        // Negative control: an independent re-resolution (the read a
        // two-resolution shape would consume) observes tree B's version.
        let version_b = storage
            .quarantined_blob_version(&digest)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            version_b, version_a,
            "re-resolving read observes the replacement tree at the injected boundary"
        );

        // Continue the production inner sequence on the RETAINED authority.
        let res = FsStorage::delete_blob_conditional_in(&shard, &leaf, &version_a)
            .await
            .expect("inner conditional delete on retained authority");
        assert_eq!(
            res,
            GcDeleteResult::Deleted,
            "revalidation matched tree A through the retained authority \
             (a two-resolution implementation reads tree B and fails the precondition)"
        );
        assert!(
            !moved_a.join(digest.hex()).exists(),
            "unlink acted on the retained authority's tree"
        );
        assert_eq!(
            std::fs::read(shard_path.join(digest.hex())).unwrap(),
            b"tree-b-content",
            "replacement tree untouched by the in-flight deletion"
        );
    }

    // ---- GC-QUARANTINE-VERSION: the quarantine conditional-version guard ----
    //
    // Established token contract (two stages, deliberately distinct):
    //   * quarantine guards against the CANDIDATE token produced by CAS
    //     listing — "{mtime_whole_seconds}:{size}" (shared derivation:
    //     `listing::candidate_version`; S3 parity: the S3 listing fallback
    //     token is the same shape when no ETag exists);
    //   * final conditional deletion guards against the QUARANTINED-object
    //     token — "fs:{len}:{mtime_nanos}:{sha256}" via
    //     `quarantined_blob_version` / `compute_blob_version_from_file`.

    // T1: a token obtained through the production candidate inspection path
    // (list_cas_blobs_page) is accepted and the quarantine proceeds with the
    // established artifacts.
    #[tokio::test]
    async fn test_quarantine_matching_version_from_production_listing_succeeds() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        let body = b"guarded-quarantine-payload".to_vec();
        plant_cas_blob(&root, &digest, &body);
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_100);

        // Production inspection path: the same candidate the GC sweep consumes.
        let page = storage
            .list_cas_blobs_page(None, 16)
            .await
            .expect("list_cas_blobs_page");
        let candidate = page
            .items
            .iter()
            .find(|c| c.digest == digest)
            .expect("planted blob listed as a candidate");
        assert_eq!(
            candidate.version,
            BlobObjectVersion(format!("1700000100:{}", body.len())),
            "listing token binds (mtime_secs, size)"
        );

        let res = storage
            .quarantine_blob(&permit, &digest, &candidate.version)
            .await
            .expect("quarantine with the matching candidate token");
        assert_eq!(
            res,
            GcQuarantineResult::Quarantined {
                size: body.len() as u64
            }
        );
        assert!(!cas_path(&root, &digest).exists(), "live leaf moved away");
        assert_eq!(
            std::fs::read(q_path(&root, &digest)).unwrap(),
            body,
            "quarantined contents unchanged"
        );
        assert!(
            ts_path(&root, &digest).exists(),
            "success timestamp written"
        );
    }

    // T2: a stale candidate token is rejected as PreconditionFailed carrying
    // the current token, with ZERO side effects — the current live blob and
    // contents remain, no quarantine destination is created, and no success
    // timestamp is published.
    #[tokio::test]
    async fn test_quarantine_stale_version_rejected_without_side_effects() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"first-generation");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_000);
        let v1 = live_candidate_version(&root, &digest);

        // The blob is replaced after candidate inspection (re-publication).
        let replacement = b"second-generation-content";
        std::fs::remove_file(cas_path(&root, &digest)).unwrap();
        plant_cas_blob(&root, &digest, replacement);
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_777);

        let res = storage
            .quarantine_blob(&permit, &digest, &v1)
            .await
            .expect("stale token classifies, not errors");
        assert_eq!(
            res,
            GcQuarantineResult::PreconditionFailed {
                current_version: Some(BlobObjectVersion(format!(
                    "1700000777:{}",
                    replacement.len()
                )))
            },
            "mismatch reports the recomputed current token"
        );
        assert_eq!(
            std::fs::read(cas_path(&root, &digest)).unwrap(),
            replacement,
            "current live blob and contents preserved"
        );
        assert!(
            !root.join("quarantine").join("blobs").exists(),
            "no quarantine destination created on the mismatch path"
        );
        assert!(
            !ts_path(&root, &digest).exists(),
            "no success timestamp side effect"
        );
    }

    // T3: stage-token pipeline. The quarantine stage accepts exactly the
    // listing candidate token — NOT the delete-stage token (the established
    // contract keeps the two stages distinct) — and the quarantined object
    // then flows through `quarantined_blob_version` into the unchanged
    // conditional final deletion.
    #[tokio::test]
    async fn test_quarantine_and_delete_stage_tokens_end_to_end() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        let body = b"stage-token-pipeline".to_vec();
        plant_cas_blob(&root, &digest, &body);
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_200);

        // The delete-stage token shape is NOT valid at the quarantine stage.
        let delete_style = compute_fs_blob_version(&cas_path(&root, &digest))
            .await
            .expect("reference token helper");
        let res = storage
            .quarantine_blob(&permit, &digest, &delete_style)
            .await
            .unwrap();
        assert!(
            matches!(res, GcQuarantineResult::PreconditionFailed { .. }),
            "delete-stage token rejected at the quarantine stage, got {res:?}"
        );
        assert!(
            cas_path(&root, &digest).exists(),
            "live blob untouched by the rejected attempt"
        );

        // The quarantine stage accepts the listing candidate token.
        let cand = live_candidate_version(&root, &digest);
        assert_eq!(
            storage
                .quarantine_blob(&permit, &digest, &cand)
                .await
                .unwrap(),
            GcQuarantineResult::Quarantined {
                size: body.len() as u64
            }
        );

        // The delete stage accepts the quarantined-object token (unchanged
        // reference implementation).
        let qv = storage
            .quarantined_blob_version(&digest)
            .await
            .unwrap()
            .expect("quarantined version");
        assert_eq!(
            storage
                .delete_blob_conditional(&permit, &digest, Some(&qv))
                .await
                .unwrap(),
            GcDeleteResult::Deleted
        );
        assert!(!q_path(&root, &digest).exists());
        assert!(!ts_path(&root, &digest).exists());
    }

    // T4: replacement changing either token component — mtime second (same
    // length) or size (same mtime second) — makes the stale token fail.
    #[tokio::test]
    async fn test_quarantine_content_replacement_changes_token_and_is_rejected() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"aaaa-content");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_000);
        let v1 = live_candidate_version(&root, &digest);

        // Same length, different mtime second: rejected via the mtime component.
        std::fs::remove_file(cas_path(&root, &digest)).unwrap();
        plant_cas_blob(&root, &digest, b"bbbb-content");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_001);
        let res = storage
            .quarantine_blob(&permit, &digest, &v1)
            .await
            .unwrap();
        assert!(
            matches!(res, GcQuarantineResult::PreconditionFailed { .. }),
            "same-length different-mtime replacement rejected, got {res:?}"
        );
        assert_eq!(
            std::fs::read(cas_path(&root, &digest)).unwrap(),
            b"bbbb-content"
        );

        // Different length, same mtime second: rejected via the size component.
        std::fs::remove_file(cas_path(&root, &digest)).unwrap();
        plant_cas_blob(&root, &digest, b"tiny");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_000);
        let res = storage
            .quarantine_blob(&permit, &digest, &v1)
            .await
            .unwrap();
        assert!(
            matches!(res, GcQuarantineResult::PreconditionFailed { .. }),
            "different-length same-mtime replacement rejected, got {res:?}"
        );
        assert_eq!(std::fs::read(cas_path(&root, &digest)).unwrap(), b"tiny");
        assert!(!root.join("quarantine").join("blobs").exists());
        assert!(!ts_path(&root, &digest).exists());
    }

    // T5: the established candidate token binds (mtime_secs, size) — it
    // intentionally identifies neither content bytes nor inode identity
    // (S3 listing parity). A replacement reproducing both components carries
    // the SAME logical version and is accepted; this pins the token strength
    // honestly rather than inventing a stronger contract.
    #[tokio::test]
    async fn test_quarantine_same_token_replacement_accepted_per_contract() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"original-bytes!!");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_300);
        let v1 = live_candidate_version(&root, &digest);

        // New inode, different bytes, SAME length and mtime second.
        std::fs::remove_file(cas_path(&root, &digest)).unwrap();
        plant_cas_blob(&root, &digest, b"different-bytes!");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_300);
        assert_eq!(
            live_candidate_version(&root, &digest),
            v1,
            "replacement reproduces the logical token"
        );

        let res = storage
            .quarantine_blob(&permit, &digest, &v1)
            .await
            .unwrap();
        assert_eq!(
            res,
            GcQuarantineResult::Quarantined { size: 16 },
            "same logical token accepted per the established contract"
        );
        assert_eq!(
            std::fs::read(q_path(&root, &digest)).unwrap(),
            b"different-bytes!"
        );
    }

    // T6: a validation failure (leaf unreadable) propagates as an error
    // BEFORE any mutation: no rename, no quarantine destination, no
    // timestamp publication.
    #[tokio::test]
    async fn test_quarantine_validation_failure_propagates_without_mutation() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"unreadable-leaf");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_400);
        let v1 = live_candidate_version(&root, &digest);

        {
            use std::os::unix::fs::PermissionsExt as _;
            let leaf = cas_path(&root, &digest);
            let _guard = PermGuard(&leaf);
            std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o000)).unwrap();

            let err = storage
                .quarantine_blob(&permit, &digest, &v1)
                .await
                .expect_err("unreadable leaf must fail validation");
            assert!(
                matches!(err, StorageError::Internal { .. }),
                "validation failure propagates as an internal storage error, got {err:?}"
            );
        }

        assert_eq!(
            std::fs::read(cas_path(&root, &digest)).unwrap(),
            b"unreadable-leaf",
            "live blob untouched by the failed validation"
        );
        assert!(
            !root.join("quarantine").join("blobs").exists(),
            "no quarantine destination created"
        );
        assert!(!ts_path(&root, &digest).exists(), "no timestamp published");
    }

    // T7: containment across ambient root replacement — the validation AND
    // the action both act through the authorities pinned at construction;
    // a replacement tree at the original ambient pathname is untouched.
    #[tokio::test]
    async fn test_quarantine_root_replacement_acts_only_on_pinned_tree() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"pinned-tree-blob");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_500);
        let v1 = live_candidate_version(&root, &digest);

        // Pin the storage's contained authorities (first use memoizes the
        // pinned roots) with a read-only operation before the swap.
        let _ = storage.list_cas_blobs_page(None, 1).await.unwrap();

        // Replace the ambient root: tree A keeps living under a new pathname,
        // an unrelated tree B takes over the original pathname.
        let moved_a = root.with_file_name(format!(
            "{}-tree-a",
            root.file_name().unwrap().to_string_lossy()
        ));
        std::fs::rename(&root, &moved_a).unwrap();
        plant_cas_blob(&root, &digest, b"ambient-replacement-blob");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_500);

        let res = storage
            .quarantine_blob(&permit, &digest, &v1)
            .await
            .expect("quarantine through the pinned authorities");
        assert_eq!(
            res,
            GcQuarantineResult::Quarantined {
                size: b"pinned-tree-blob".len() as u64
            }
        );

        // Tree A (the pinned tree, now at the moved pathname): leaf moved into
        // ITS quarantine namespace.
        assert!(
            !cas_path(&moved_a, &digest).exists(),
            "pinned tree's live leaf moved"
        );
        assert_eq!(
            std::fs::read(q_path(&moved_a, &digest)).unwrap(),
            b"pinned-tree-blob",
            "pinned tree's blob quarantined byte-identically"
        );
        assert!(
            ts_path(&moved_a, &digest).exists(),
            "timestamp written in the pinned tree"
        );

        // Tree B (ambient replacement): completely untouched.
        assert_eq!(
            std::fs::read(cas_path(&root, &digest)).unwrap(),
            b"ambient-replacement-blob",
            "replacement tree's blob untouched"
        );
        assert!(
            !root.join("quarantine").exists(),
            "no quarantine namespace created in the replacement tree"
        );

        std::fs::remove_dir_all(&moved_a).ok();
    }

    // T8: a symlinked live CAS leaf fails closed at the contained open used
    // for validation — the external target is neither read into a decision
    // nor renamed, and nothing is quarantined.
    #[tokio::test]
    async fn test_quarantine_symlinked_leaf_fails_closed() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);

        let ext_target = external.join("outside_blob");
        std::fs::write(&ext_target, b"external-bytes").unwrap();
        let leaf = cas_path(&root, &digest);
        std::fs::create_dir_all(leaf.parent().unwrap()).unwrap();
        symlink(&ext_target, &leaf).unwrap();

        let err = storage
            .quarantine_blob(&permit, &digest, &dummy_version())
            .await
            .expect_err("symlinked live leaf must fail closed");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::Io,
                    ..
                }
            ),
            "symlink -> Io error, got {err:?}"
        );
        assert!(
            std::fs::symlink_metadata(&leaf)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink left in place (not renamed)"
        );
        assert_eq!(
            std::fs::read(&ext_target).unwrap(),
            b"external-bytes",
            "external target untouched"
        );
        assert!(
            !root.join("quarantine").join("blobs").exists(),
            "nothing quarantined"
        );
    }

    // CRITICAL validation/action race regression: a leaf replacement injected
    // at the test seam BETWEEN the conditional-version validation and the
    // quarantine rename — the window that the deployment writer lock plus the
    // consistency coordinator exclude for every protocol-compliant writer —
    // must not leave the replacement quarantined under the stale token. The
    // implementation is deliberately NOT an atomic compare-and-rename: it
    // detects the swap by post-rename object-identity (dev/ino) verification
    // through the GC-exclusive quarantine authority and deterministically
    // restores the replacement to the live CAS leaf, reporting
    // PreconditionFailed.
    #[tokio::test]
    async fn test_quarantine_boundary_replacement_not_captured_under_stale_token() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = authority_for(&root).await;
        let permit = authority.gc_mutation_permit();
        let digest = d(QHEX);
        plant_cas_blob(&root, &digest, b"validated-generation");
        set_mtime_secs(&cas_path(&root, &digest), 1_700_000_000);
        let v1 = live_candidate_version(&root, &digest);

        let replacement = b"replacement-generation-longer";
        let hook_root = root.clone();
        let hook_digest = digest.clone();
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired_hook = fired.clone();
        storage.set_quarantine_boundary_hook(Arc::new(move |hex| {
            assert_eq!(hex, hook_digest.hex());
            let leaf = cas_path(&hook_root, &hook_digest);
            let _detached = detach_for_swap(&leaf);
            std::fs::write(&leaf, replacement).unwrap();
            set_mtime_secs(&leaf, 1_700_000_555);
            fired_hook.store(true, std::sync::atomic::Ordering::SeqCst);
        }));

        let res = storage
            .quarantine_blob(&permit, &digest, &v1)
            .await
            .expect("swap detection classifies, not errors");
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "boundary hook fired inside the validate->rename window"
        );
        assert_eq!(
            res,
            GcQuarantineResult::PreconditionFailed {
                current_version: Some(BlobObjectVersion(format!(
                    "1700000555:{}",
                    replacement.len()
                )))
            },
            "swap detected and reported with the replacement's token"
        );
        assert_eq!(
            std::fs::read(cas_path(&root, &digest)).unwrap(),
            replacement,
            "replacement restored to the live CAS leaf"
        );
        assert!(
            !q_path(&root, &digest).exists(),
            "the replacement is NOT left quarantined under the stale token"
        );
        assert!(
            !ts_path(&root, &digest).exists(),
            "no success timestamp side effect"
        );
    }
}

// Production-boundary containment regressions for the legacy streaming upload
// lifecycle (`create_upload` / `upload_status` / `append_upload` /
// `finalize_upload` / `abort_upload` — the storage-trait contract retained for
// both backends and used by tests as the supported fixture path; production
// HTTP uploads flow through the PHASE5 coordinator/session API). The lifecycle
// now operates entirely beneath the pinned `uploads` authority: the data leaf
// is created/appended/read through contained opens (kernel `O_APPEND`
// preserved), streaming I/O stays on the securely opened file description
// inside owned blocking closures, and finalize publishes via the contained
// cross-authority rename into the CAS shard. No locks existed on this legacy
// path and none were added.
mod legacy_streaming_upload_containment {
    use super::*;
    use std::os::unix::fs::symlink;

    fn digest_of(bytes: &[u8]) -> Digest {
        Digest::parse(&format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(bytes))
        ))
        .unwrap()
    }

    fn upload_leaf_path(root: &Path, uuid: &str) -> PathBuf {
        root.join("uploads").join(format!("{uuid}.data"))
    }

    fn hash_state_path(root: &Path, uuid: &str) -> PathBuf {
        root.join("uploads").join(format!("{uuid}.sha256state"))
    }

    fn cas_path(root: &Path, digest: &Digest) -> PathBuf {
        root.join("blobs")
            .join(digest.algorithm())
            .join(digest.prefix2())
            .join(digest.hex())
    }

    // Full lifecycle with exact artifacts: chunked appends report exact
    // offsets and persist exact bytes at the contained leaf; finalize verifies
    // the digest, publishes the exact bytes into the CAS shard via rename, and
    // removes the upload leaf and its hash-state cache with no residue.
    #[tokio::test]
    async fn test_create_append_finalize_roundtrip_exact_artifacts() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        let meta = storage.create_upload().await.expect("create_upload");
        assert_eq!(meta.offset, 0);
        let uuid = meta.uuid.clone();
        assert_eq!(
            std::fs::read(upload_leaf_path(&root, &uuid)).unwrap(),
            b"",
            "created leaf is empty"
        );
        assert!(
            hash_state_path(&root, &uuid).exists(),
            "hash-state cache initialized"
        );

        let c1 = b"first-chunk-".to_vec();
        let c2 = b"second-chunk".to_vec();
        let m1 = storage
            .append_upload(&uuid, Bytes::from(c1.clone()))
            .await
            .expect("append 1");
        assert_eq!(m1.offset, c1.len() as u64, "exact offset after chunk 1");
        let m2 = storage
            .append_upload(&uuid, Bytes::from(c2.clone()))
            .await
            .expect("append 2");
        assert_eq!(
            m2.offset,
            (c1.len() + c2.len()) as u64,
            "exact offset after chunk 2"
        );

        let mut full = c1.clone();
        full.extend_from_slice(&c2);
        assert_eq!(
            std::fs::read(upload_leaf_path(&root, &uuid)).unwrap(),
            full,
            "exact bytes at the contained upload leaf"
        );

        let digest = digest_of(&full);
        let blob_meta = storage
            .finalize_upload(&uuid, &digest)
            .await
            .expect("finalize");
        assert_eq!(blob_meta.size, full.len() as u64);
        assert_eq!(
            std::fs::read(cas_path(&root, &digest)).unwrap(),
            full,
            "exact bytes published into the CAS shard"
        );
        assert!(
            !upload_leaf_path(&root, &uuid).exists(),
            "upload leaf moved (rename, not copy)"
        );
        assert!(
            !hash_state_path(&root, &uuid).exists(),
            "hash-state cache removed"
        );
        let residue: Vec<String> = std::fs::read_dir(root.join("uploads"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            residue.is_empty(),
            "no residue in uploads/ after finalize: {residue:?}"
        );
    }

    // Empty appends and status report exact lengths from the contained leaf.
    #[tokio::test]
    async fn test_empty_append_and_status() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let uuid = storage.create_upload().await.unwrap().uuid;

        let m = storage
            .append_upload(&uuid, Bytes::new())
            .await
            .expect("empty append");
        assert_eq!(m.offset, 0);
        assert_eq!(storage.upload_status(&uuid).await.unwrap().offset, 0);

        storage
            .append_upload(&uuid, Bytes::from_static(b"abc"))
            .await
            .unwrap();
        assert_eq!(storage.upload_status(&uuid).await.unwrap().offset, 3);
    }

    // Absent-upload contracts: NotFound for status/append/finalize; Ok for
    // abort. TooLarge preserved before any write.
    #[tokio::test]
    async fn test_absent_upload_and_too_large_contracts() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 16);

        for res in [
            storage.upload_status("no-such-upload").await.err(),
            storage
                .append_upload("no-such-upload", Bytes::from_static(b"x"))
                .await
                .err(),
            storage
                .finalize_upload("no-such-upload", &digest_of(b"x"))
                .await
                .err(),
        ] {
            assert!(
                matches!(res, Some(StorageError::NotFound)),
                "absent upload -> NotFound, got {res:?}"
            );
        }
        storage
            .abort_upload("no-such-upload")
            .await
            .expect("absent abort is Ok");

        // TooLarge: enforced before any byte is written.
        let uuid = storage.create_upload().await.unwrap().uuid;
        let err = storage
            .append_upload(&uuid, Bytes::from(vec![0u8; 17]))
            .await
            .expect_err("over-limit append must fail");
        assert!(matches!(err, StorageError::TooLarge));
        assert_eq!(
            std::fs::read(upload_leaf_path(&root, &uuid)).unwrap(),
            b"",
            "no bytes written by the rejected append"
        );
    }

    // A caller-supplied identifier that cannot form a contained leaf is an
    // absent upload — and, critically, ambient escapes are gone: an abort with
    // a traversal identifier no longer deletes a file outside the uploads
    // namespace (previously `remove_file(root/uploads/../victim.data)` removed
    // `root/victim.data`).
    #[tokio::test]
    async fn test_traversal_uuid_treated_as_absent_no_escape() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        // Plant a victim file where the old ambient join would have resolved.
        std::fs::write(root.join("victim.data"), b"do-not-delete").unwrap();

        assert!(matches!(
            storage.upload_status("../victim").await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            storage
                .append_upload("../victim", Bytes::from_static(b"x"))
                .await,
            Err(StorageError::NotFound)
        ));
        assert!(matches!(
            storage.finalize_upload("../victim", &digest_of(b"x")).await,
            Err(StorageError::NotFound)
        ));
        storage
            .abort_upload("../victim")
            .await
            .expect("traversal abort is an absent no-op");

        assert_eq!(
            std::fs::read(root.join("victim.data")).unwrap(),
            b"do-not-delete",
            "file outside the uploads namespace untouched by traversal identifiers"
        );
    }

    // Digest mismatch aborts finalize BEFORE any publish: the upload leaf and
    // its hash-state cache remain, and a retry with the correct digest
    // succeeds.
    #[tokio::test]
    async fn test_finalize_digest_mismatch_preserves_upload() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let uuid = storage.create_upload().await.unwrap().uuid;
        storage
            .append_upload(&uuid, Bytes::from_static(b"payload"))
            .await
            .unwrap();

        let wrong = digest_of(b"different");
        let err = storage
            .finalize_upload(&uuid, &wrong)
            .await
            .expect_err("mismatch must fail");
        assert!(matches!(err, StorageError::DigestMismatch));
        assert_eq!(
            std::fs::read(upload_leaf_path(&root, &uuid)).unwrap(),
            b"payload",
            "upload preserved on mismatch"
        );
        assert!(!cas_path(&root, &wrong).exists(), "nothing published");

        let right = digest_of(b"payload");
        storage
            .finalize_upload(&uuid, &right)
            .await
            .expect("retry with correct digest succeeds");
        assert_eq!(std::fs::read(cas_path(&root, &right)).unwrap(), b"payload");
    }

    // A symlinked upload leaf fails closed for the contained opens: append and
    // finalize error with Io, status fails closed, and the external target is
    // neither read, written, nor published. (Previously the ambient
    // open/stat/hash followed the symlink.)
    #[tokio::test]
    async fn test_symlinked_upload_leaf_fails_closed() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        let ext_target = external.join("outside_upload");
        std::fs::write(&ext_target, b"external-bytes").unwrap();
        let uuid = "11111111-2222-3333-4444-555555555555";
        std::fs::create_dir_all(root.join("uploads")).unwrap();
        symlink(&ext_target, upload_leaf_path(&root, uuid)).unwrap();

        for (op, err) in [
            (
                "append",
                storage
                    .append_upload(uuid, Bytes::from_static(b"x"))
                    .await
                    .expect_err("append through symlink must fail closed"),
            ),
            (
                "finalize",
                storage
                    .finalize_upload(uuid, &digest_of(b"external-bytes"))
                    .await
                    .expect_err("finalize through symlink must fail closed"),
            ),
            (
                "status",
                storage
                    .upload_status(uuid)
                    .await
                    .expect_err("status through symlink must fail closed"),
            ),
        ] {
            assert!(
                matches!(
                    err,
                    StorageError::Internal {
                        kind: crate::storage::StorageErrorKind::Io,
                        ..
                    }
                ),
                "{op}: symlinked leaf -> Io, got {err:?}"
            );
        }
        assert_eq!(
            std::fs::read(&ext_target).unwrap(),
            b"external-bytes",
            "external target untouched"
        );
        assert!(
            !cas_path(&root, &digest_of(b"external-bytes")).exists(),
            "nothing published from the symlinked leaf"
        );
    }

    // Kernel O_APPEND semantics preserved: bytes appended to the leaf by an
    // external writer between two append_upload calls are not overwritten, and
    // the returned offset is the true end-of-file after the kernel append.
    #[tokio::test]
    async fn test_append_kernel_o_append_semantics() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let uuid = storage.create_upload().await.unwrap().uuid;

        storage
            .append_upload(&uuid, Bytes::from_static(b"AAA"))
            .await
            .unwrap();

        // External writer appends concurrently (simulated between calls).
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(upload_leaf_path(&root, &uuid))
                .unwrap();
            f.write_all(b"XX").unwrap();
        }

        let m = storage
            .append_upload(&uuid, Bytes::from_static(b"BBB"))
            .await
            .unwrap();
        assert_eq!(
            m.offset, 8,
            "offset reflects true end-of-file under kernel O_APPEND"
        );
        assert_eq!(
            std::fs::read(upload_leaf_path(&root, &uuid)).unwrap(),
            b"AAAXXBBB",
            "no external bytes overwritten (O_APPEND, not positional write)"
        );
    }

    // Fixed-top-level authority boundary: the pinned `uploads` authority
    // follows its inode. After the whole uploads directory is renamed away and
    // recreated with a decoy leaf, the next append resolves through the PINNED
    // old directory — the decoy tree receives no bytes.
    #[tokio::test]
    async fn test_uploads_replacement_append_stays_on_pinned_authority() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let uuid = storage.create_upload().await.unwrap().uuid;
        storage
            .append_upload(&uuid, Bytes::from_static(b"orig-"))
            .await
            .unwrap();

        // Replace the fixed top-level uploads directory wholesale.
        let uploads = root.join("uploads");
        let moved = root.join("uploads-old");
        std::fs::rename(&uploads, &moved).unwrap();
        std::fs::create_dir_all(&uploads).unwrap();
        std::fs::write(uploads.join(format!("{uuid}.data")), b"decoy").unwrap();

        let m = storage
            .append_upload(&uuid, Bytes::from_static(b"more"))
            .await
            .expect("append via pinned authority");
        assert_eq!(m.offset, 9, "offset from the pinned tree's leaf");
        assert_eq!(
            std::fs::read(moved.join(format!("{uuid}.data"))).unwrap(),
            b"orig-more",
            "write landed on the pinned (old) uploads tree"
        );
        assert_eq!(
            std::fs::read(uploads.join(format!("{uuid}.data"))).unwrap(),
            b"decoy",
            "replacement tree untouched by the in-flight lifecycle"
        );
    }
}

// Durability-barrier regressions from the repository-wide fsync audit: the CAS
// publication barriers in PHASE5 commit (now propagated, ordered before the
// durable membership/receipt), the GC restore re-publication barriers, and the
// contained + durable lifecycle journal. Fault injection demonstrates
// mutation -> failed sync -> returned error with the mutation still visible
// (no rollback fiction) and, for commit, that the retry path heals.
mod durability_barriers {
    use super::*;
    use crate::storage::mutation_authority::RuntimeMutationAuthority;
    use crate::storage::{GcQuarantineResult, GcStorage};
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use storage_fs::mutate::fault::{FaultPoint, arm};

    // A failed publication directory sync in commit_finalize propagates BEFORE
    // the membership/receipt writes: the CAS entry is already visible (rename
    // happened; no rollback), no receipt or membership was persisted, the
    // staging state survives, and a retry heals to a successful publication.
    #[tokio::test]
    async fn test_commit_publication_dir_sync_failure_propagates_and_retry_heals() {
        let _g = fault_test_guard().await;
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let data = b"DURABILITY_COMMIT_BARRIER";
        let (session, prepared, digest) =
            prepare_finalizable_session(&storage, "myrepo", data).await;

        // Fail the blobs-shard directory sync (the second barrier), once.
        // The needle is anchored to this test's unique root: DirSync matches
        // the authority DISPLAY PATH, so a bare "blobs" needle is consumed by
        // whichever concurrent test syncs a blobs directory first — injecting
        // a spurious EIO there and eating this test's own expected fault.
        let blobs_needle = format!("{}/blobs", root.display());
        arm(FaultPoint::DirSync, Some(&blobs_needle), 1, libc::EIO);
        let err = storage.commit_finalize(&prepared).await;
        assert!(err.is_err(), "publication sync failure must propagate");

        // The rename already happened: the CAS entry is visible (no rollback).
        let cas_path = root
            .join("blobs")
            .join(digest.algorithm())
            .join(digest.prefix2())
            .join(digest.hex());
        assert!(
            cas_path.exists(),
            "publication is visible despite the error"
        );
        // The barrier is ordered BEFORE membership + receipt: neither exists.
        assert!(
            storage
                .get_finalized_receipt(&session)
                .await
                .unwrap()
                .is_none(),
            "no receipt may be persisted when the publication barrier failed"
        );
        assert!(
            !membership_record_path(&root, "myrepo", &digest).exists(),
            "no membership may be persisted when the publication barrier failed"
        );

        // Retry (fault consumed): heals via the tolerated-existing branch.
        let outcome = storage
            .commit_finalize(&prepared)
            .await
            .expect("retry after barrier failure heals");
        assert_eq!(
            outcome,
            FinalizeOutcome::Published(BlobMeta {
                size: data.len() as u64
            })
        );
        assert!(
            storage
                .get_finalized_receipt(&session)
                .await
                .unwrap()
                .is_some(),
            "receipt persisted on the healed retry"
        );
        storage_fs::mutate::fault::reset();
    }

    // A failed directory sync in restore_quarantined_blob propagates while the
    // restored blob is already visible in the CAS namespace (no rollback).
    #[tokio::test]
    async fn test_restore_dir_sync_failure_propagates_blob_visible() {
        let _g = fault_test_guard().await;
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let authority = RuntimeMutationAuthority::acquire(
            Arc::new(FsStorage::new(root.clone(), 1024 * 1024)),
            "durability-test",
        )
        .await
        .expect("acquire mutation authority");
        let permit = authority.gc_mutation_permit();
        let digest = Digest::parse(&format!("sha256:{}", "e7".repeat(32))).unwrap();

        // Plant + quarantine a CAS blob.
        let cas_path = root
            .join("blobs")
            .join(digest.algorithm())
            .join(digest.prefix2())
            .join(digest.hex());
        std::fs::create_dir_all(cas_path.parent().unwrap()).unwrap();
        std::fs::write(&cas_path, b"restore-barrier-payload").unwrap();
        // Current candidate token ("{mtime_secs}:{size}"), which quarantine
        // now validates before moving anything.
        let meta = std::fs::metadata(&cas_path).unwrap();
        let secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let q = storage
            .quarantine_blob(
                &permit,
                &digest,
                &BlobObjectVersion(format!("{secs}:{}", meta.len())),
            )
            .await
            .unwrap();
        assert!(matches!(q, GcQuarantineResult::Quarantined { .. }));

        // Fail the quarantine-shard (source) directory sync, once. Anchored
        // to this test's unique root for the same display-path-matching
        // reason as the blobs needle above.
        let quarantine_needle = format!("{}/quarantine", root.display());
        arm(FaultPoint::DirSync, Some(&quarantine_needle), 1, libc::EIO);
        let err = storage
            .restore_quarantined_blob(&permit, &digest)
            .await
            .expect_err("restore barrier failure must propagate");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::Io,
                    ..
                }
            ),
            "restore sync failure -> Io, got {err:?}"
        );
        // The rename already happened: blob is back in CAS (no rollback), gone
        // from quarantine.
        assert_eq!(
            std::fs::read(&cas_path).unwrap(),
            b"restore-barrier-payload",
            "restored blob visible despite the barrier error"
        );
        assert!(
            !root
                .join("quarantine")
                .join("blobs")
                .join(digest.algorithm())
                .join(digest.prefix2())
                .join(digest.hex())
                .exists(),
            "quarantine leaf gone (rename visible)"
        );
        storage_fs::mutate::fault::reset();
    }

    // The lifecycle journal (authoritative GC-protection recovery state) is now
    // written contained and durably: exact bytes at the contained key, mode
    // 0o600, coherent with the contained reader; deletion is contained with the
    // frozen absent contract.
    #[tokio::test]
    async fn test_lifecycle_journal_contained_durable_roundtrip() {
        let root = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);
        let repo = "lib/journaled";
        let body = br#"{"target_digest":"sha256:aa","phase":"prepare"}"#.to_vec();

        storage
            .write_lifecycle_journal(repo, Bytes::from(body.clone()))
            .await
            .expect("journal write");
        let path = root
            .join("repos")
            .join("lib")
            .join("journaled")
            .join("meta")
            .join("lifecycle_journal.json");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            body,
            "exact journal bytes at the contained key"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "contained durable write mode"
        );
        assert_eq!(
            storage
                .read_lifecycle_journal(repo)
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            body.as_slice(),
            "contained reader observes the write"
        );

        // Replacement write.
        let body2 = br#"{"target_digest":"sha256:bb","phase":"commit"}"#.to_vec();
        storage
            .write_lifecycle_journal(repo, Bytes::from(body2.clone()))
            .await
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), body2);

        // Contained deletion; absent deletion stays Ok.
        storage.delete_lifecycle_journal(repo).await.unwrap();
        assert!(!path.exists(), "journal removed");
        assert!(
            storage
                .read_lifecycle_journal(repo)
                .await
                .unwrap()
                .is_none()
        );
        storage
            .delete_lifecycle_journal(repo)
            .await
            .expect("absent journal deletion is Ok");
        storage
            .delete_lifecycle_journal("never/existed")
            .await
            .expect("absent repository deletion is Ok");
    }

    // A symlinked `meta` component fails closed for both journal mutations: the
    // external tree is neither written through nor unlinked from. (Previously
    // the ambient write/remove followed the symlink.)
    #[tokio::test]
    async fn test_lifecycle_journal_symlinked_meta_fails_closed() {
        let root = tmp_fs_root();
        let external = tmp_fs_root();
        let storage = FsStorage::new(root.clone(), 1024 * 1024);

        let ext_journal = external.join("lifecycle_journal.json");
        std::fs::write(&ext_journal, b"external").unwrap();
        let repo_dir = root.join("repos").join("symjournal");
        std::fs::create_dir_all(&repo_dir).unwrap();
        symlink(&external, repo_dir.join("meta")).unwrap();

        // Phase 7: the pinned adapter reports its containment refusal as
        // PermissionDenied (the retired contained seam said Io — both are
        // production-inert Internal kinds; accepted C2 convergence).
        let err = storage
            .write_lifecycle_journal("symjournal", Bytes::from_static(b"x"))
            .await
            .expect_err("symlinked meta must fail closed on write");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::PermissionDenied,
                    ..
                }
            ),
            "write -> PermissionDenied, got {err:?}"
        );
        let err = storage
            .delete_lifecycle_journal("symjournal")
            .await
            .expect_err("symlinked meta must fail closed on delete");
        assert!(
            matches!(
                err,
                StorageError::Internal {
                    kind: crate::storage::StorageErrorKind::PermissionDenied,
                    ..
                }
            ),
            "delete -> PermissionDenied, got {err:?}"
        );
        assert_eq!(
            std::fs::read(&ext_journal).unwrap(),
            b"external",
            "external journal untouched"
        );
    }
}
