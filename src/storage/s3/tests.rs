pub(crate) use super::mock::*;
use super::*;
use crate::storage::fs::test_helpers::make_test_stream;

// ==========================================
// 1. Serialization Round-Trip Tests
// ==========================================

#[test]
fn test_s3_session_doc_serialization_roundtrip() {
    let doc = S3SessionDoc {
        format_version: 1,
        repo: crate::registry::canonical_name::CanonicalRepoName::parse("test/repo").unwrap(),
        uuid: "12345678-1234-1234-1234-1234567890ab".to_string(),
        multipart_upload_id: "mp_upload_id_123".to_string(),
        state: UploadSessionState::Active,
        committed_offset: 10485760,
        committed_parts: vec![
            S3CommittedPart {
                part_number: 1,
                size: 5242880,
                etag: "\"etag_1\"".to_string(),
            },
            S3CommittedPart {
                part_number: 2,
                size: 5242880,
                etag: "\"etag_2\"".to_string(),
            },
        ],
        pending_buffer_key: Some("uploads/1234/pending/op_1.bin".to_string()),
        pending_bytes: 65536,
        created_at_unix_secs: 1740000000,
        last_active_at_unix_secs: 1740000050,
        current_operation: Some(S3CurrentOperation {
            operation_id: "op_2".to_string(),
            expected_offset: 10551296,
            target_part_number: 3,
            lease_expires_at_unix_secs: 1740000350,
        }),
        finalizing_info: None,
    };

    let json = serde_json::to_vec(&doc).unwrap();
    let decoded: S3SessionDoc = serde_json::from_slice(&json).unwrap();

    assert_eq!(decoded.format_version, 1);
    assert_eq!(decoded.repo, "test/repo");
    assert_eq!(decoded.uuid, "12345678-1234-1234-1234-1234567890ab");
    assert_eq!(decoded.state, UploadSessionState::Active);
    assert_eq!(decoded.committed_offset, 10485760);
    assert_eq!(decoded.committed_parts.len(), 2);
    assert_eq!(decoded.pending_bytes, 65536);
    assert_eq!(
        decoded.current_operation.as_ref().unwrap().operation_id,
        "op_2"
    );
}

#[test]
fn test_s3_finalized_receipt_serialization_roundtrip() {
    let receipt = FinalizedReceipt {
        repo: crate::registry::canonical_name::CanonicalRepoName::parse("my/repo").unwrap(),
        uuid: "98765432-1234-1234-1234-1234567890ab".to_string(),
        digest: "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            .to_string(),
        size: 10485760,
        finalized_at_unix_secs: 1740000100,
        format_version: 1,
    };

    let json = serde_json::to_vec(&receipt).unwrap();
    let decoded: FinalizedReceipt = serde_json::from_slice(&json).unwrap();

    assert_eq!(decoded.repo.as_str(), "my/repo");
    assert_eq!(decoded.uuid, "98765432-1234-1234-1234-1234567890ab");
    assert_eq!(decoded.size, 10485760);
    assert_eq!(decoded.format_version, 1);
}

// ==========================================
// 2. Lease Renewal & Concurrency Tests
// ==========================================

#[tokio::test]
async fn test_s3_lease_renewal_during_long_stream() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("myrepo").await.unwrap();

    // 10 chunks of 600 KiB (total 6 MiB).
    let chunks: Vec<Bytes> = (0..10)
        .map(|i| Bytes::from(vec![b'A' + i; 600 * 1024]))
        .collect();
    let stream = make_test_stream(chunks);

    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            100 * 1024 * 1024,
        )
        .await
        .unwrap();

    assert_eq!(
        res,
        UploadAppendResult::Committed {
            new_offset: 10 * 600 * 1024
        }
    );

    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 10 * 600 * 1024);
    assert_eq!(status.state, UploadSessionState::Active);

    // Verify that 1 part of 5 MiB was committed and remaining 1 MiB is in pending buffer
    let doc_bytes = driver
        .objects
        .lock()
        .unwrap()
        .get(&format!("uploads/{}/session.json", session.uuid))
        .unwrap()
        .0
        .clone();
    let doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    assert_eq!(doc.committed_parts.len(), 1);
    assert_eq!(doc.committed_parts[0].size, S3_PART_SIZE as u64);
    assert_eq!(doc.pending_bytes, 10 * 600 * 1024 - S3_PART_SIZE as u64);
}

#[tokio::test]
async fn test_s3_active_renewal_prevents_recovery() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("myrepo").await.unwrap();

    // Reserve session
    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, etag) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let mut doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    doc.state = UploadSessionState::Appending;
    doc.current_operation = Some(S3CurrentOperation {
        operation_id: "op-active".to_string(),
        expected_offset: 0,
        target_part_number: 1,
        lease_expires_at_unix_secs: 1300,
    });
    driver
        .put_object_conditional(
            "test-bucket",
            &key,
            Bytes::from(serde_json::to_vec(&doc).unwrap()),
            Some(etag),
            None,
        )
        .await
        .unwrap();

    // Clock is at 1100 (within lease)
    driver.set_time(1100);
    let recovered = storage.recover_session(&session).await.unwrap();
    // Lease active -> state remains Appending, not rolled back
    assert_eq!(recovered.state, UploadSessionState::Appending);
}

#[tokio::test]
async fn test_s3_renewal_cas_412_stops_operation() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("myrepo").await.unwrap();

    // Inject 412 on session.json during streaming
    let session_key = format!("uploads/{}/session.json", session.uuid);
    driver.inject_412_on_key(&session_key);

    let chunk = vec![Bytes::from(vec![b'X'; 100 * 1024])];
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(chunk),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    assert_eq!(res, UploadAppendResult::Conflict);
}

#[tokio::test]
async fn test_s3_expired_non_renewing_owner_can_be_recovered() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("myrepo").await.unwrap();

    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, etag) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let mut doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    doc.state = UploadSessionState::Appending;
    doc.current_operation = Some(S3CurrentOperation {
        operation_id: "op-stalled".to_string(),
        expected_offset: 0,
        target_part_number: 1,
        lease_expires_at_unix_secs: 1300,
    });
    driver
        .put_object_conditional(
            "test-bucket",
            &key,
            Bytes::from(serde_json::to_vec(&doc).unwrap()),
            Some(etag),
            None,
        )
        .await
        .unwrap();

    // Advance clock past lease expiration
    driver.set_time(1400);
    let recovered = storage.recover_session(&session).await.unwrap();
    assert_eq!(recovered.state, UploadSessionState::Active);
}

#[tokio::test]
async fn test_s3_original_worker_cannot_commit_after_recovery() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("myrepo").await.unwrap();

    // Worker 1 reserves at etag 1
    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, etag1) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let mut doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    doc.state = UploadSessionState::Appending;
    doc.current_operation = Some(S3CurrentOperation {
        operation_id: "op-w1".to_string(),
        expected_offset: 0,
        target_part_number: 1,
        lease_expires_at_unix_secs: 1300,
    });
    driver
        .put_object_conditional(
            "test-bucket",
            &key,
            Bytes::from(serde_json::to_vec(&doc).unwrap()),
            Some(etag1),
            None,
        )
        .await
        .unwrap();

    // Clock expires and recovery runs (changes ETag)
    driver.set_time(1400);
    let _ = storage.recover_session(&session).await.unwrap();

    // Worker 1 tries to commit using its old etag1 -> receives TagAlreadyExists / 412
    doc.committed_offset = 500;
    doc.state = UploadSessionState::Active;
    let commit_res = driver
        .put_object_conditional(
            "test-bucket",
            &key,
            Bytes::from(serde_json::to_vec(&doc).unwrap()),
            Some("stale_etag".to_string()),
            None,
        )
        .await;
    assert!(matches!(commit_res, Err(StorageError::TagAlreadyExists)));
}

// ==========================================
// 3. Conditional S3 Requests Tests
// ==========================================

#[tokio::test]
async fn test_s3_create_session_uses_if_none_match() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("repo1").await.unwrap();

    let log = driver.get_call_log();
    let put_entry = log
        .iter()
        .find(|e| e.method == "put_object" && e.key.ends_with("/session.json"))
        .unwrap();
    assert_eq!(put_entry.if_none_match.as_deref(), Some("*"));
    assert_eq!(session.repo.as_str(), "repo1");
}

#[tokio::test]
async fn test_s3_reservation_uses_if_match_with_observed_etag() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("repo1").await.unwrap();

    let stream = make_test_stream(vec![Bytes::from_static(b"HELLO")]);
    let res = storage
        .append_if_offset(&session, UploadOffsetPrecondition::Exact(0), stream, 1000)
        .await
        .unwrap();
    assert_eq!(res, UploadAppendResult::Committed { new_offset: 5 });

    let log = driver.get_call_log();
    let reservations: Vec<&S3CallLogEntry> = log
        .iter()
        .filter(|e| e.method == "put_object" && e.key.ends_with("/session.json"))
        .collect();
    assert!(reservations.len() >= 2); // Initial create + reservation + final commit
    assert!(reservations[1].if_match.is_some());
}

#[tokio::test]
async fn test_s3_competing_reservation_receives_412_and_does_not_consume_body() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("repo1").await.unwrap();

    // Put session into Appending state with active lease
    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, etag) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let mut doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    doc.state = UploadSessionState::Appending;
    doc.current_operation = Some(S3CurrentOperation {
        operation_id: "op-competing".to_string(),
        expected_offset: 0,
        target_part_number: 1,
        lease_expires_at_unix_secs: 1300,
    });
    driver
        .put_object_conditional(
            "test-bucket",
            &key,
            Bytes::from(serde_json::to_vec(&doc).unwrap()),
            Some(etag),
            None,
        )
        .await
        .unwrap();

    // Second worker tries append -> receives Conflict immediately without consuming stream or writing parts
    let stream = make_test_stream(vec![Bytes::from_static(b"LOSER_PAYLOAD")]);
    let res = storage
        .append_if_offset(&session, UploadOffsetPrecondition::Exact(0), stream, 1000)
        .await
        .unwrap();
    assert_eq!(res, UploadAppendResult::Conflict);
}

#[tokio::test]
async fn test_s3_retry_exhaustion_returns_conflict() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("exhaust_repo").await.unwrap();

    let session_key = format!("uploads/{}/session.json", session.uuid);
    driver.inject_412_on_key(&session_key);

    let stream = make_test_stream(vec![Bytes::from_static(b"DATA")]);
    let res = storage
        .append_if_offset(&session, UploadOffsetPrecondition::Exact(0), stream, 1000)
        .await
        .unwrap();

    assert_eq!(res, UploadAppendResult::Conflict);
}

// ==========================================
// 4. Small-Chunk S3 Implementation Tests
// ==========================================

#[tokio::test]
async fn test_s3_small_chunk_below_5mib() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("smallrepo").await.unwrap();

    let chunk = Bytes::from(vec![b'A'; 1024 * 1024]); // 1 MiB
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res,
        UploadAppendResult::Committed {
            new_offset: 1024 * 1024
        }
    );

    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 1024 * 1024);

    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, _) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    assert_eq!(doc.pending_bytes, 1024 * 1024);
    assert!(doc.pending_buffer_key.is_some());
    assert_eq!(doc.committed_parts.len(), 0);
}

#[tokio::test]
async fn test_s3_multiple_small_patch_requests() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("smallrepo").await.unwrap();

    // PATCH 1: 1 MiB
    let chunk1 = Bytes::from(vec![b'1'; 1024 * 1024]);
    let res1 = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk1]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res1,
        UploadAppendResult::Committed {
            new_offset: 1024 * 1024
        }
    );

    // PATCH 2: 2 MiB
    let chunk2 = Bytes::from(vec![b'2'; 2 * 1024 * 1024]);
    let res2 = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(1024 * 1024),
            make_test_stream(vec![chunk2]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res2,
        UploadAppendResult::Committed {
            new_offset: 3 * 1024 * 1024
        }
    );

    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 3 * 1024 * 1024);
}

#[tokio::test]
async fn test_s3_pending_plus_incoming_crosses_5mib() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("smallrepo").await.unwrap();

    // 1. 3 MiB
    let chunk1 = Bytes::from(vec![b'A'; 3 * 1024 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk1]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    // 2. 4 MiB -> total 7 MiB -> 1 part of 5 MiB + 2 MiB pending
    let chunk2 = Bytes::from(vec![b'B'; 4 * 1024 * 1024]);
    let res2 = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(3 * 1024 * 1024),
            make_test_stream(vec![chunk2]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res2,
        UploadAppendResult::Committed {
            new_offset: 7 * 1024 * 1024
        }
    );

    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, _) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    assert_eq!(doc.committed_parts.len(), 1);
    assert_eq!(doc.committed_parts[0].size, 5 * 1024 * 1024);
    assert_eq!(doc.pending_bytes, 2 * 1024 * 1024);
}

#[tokio::test]
async fn test_s3_large_stream_produces_multiple_parts_bounded() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("largerepo").await.unwrap();

    // 13 MiB stream -> Part 1 (5 MiB), Part 2 (5 MiB), Pending (3 MiB)
    let chunk = Bytes::from(vec![b'Z'; 13 * 1024 * 1024]);
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk]),
            20 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res,
        UploadAppendResult::Committed {
            new_offset: 13 * 1024 * 1024
        }
    );

    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, _) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    assert_eq!(doc.committed_parts.len(), 2);
    assert_eq!(doc.committed_parts[0].size, 5 * 1024 * 1024);
    assert_eq!(doc.committed_parts[1].size, 5 * 1024 * 1024);
    assert_eq!(doc.pending_bytes, 3 * 1024 * 1024);
}

#[tokio::test]
async fn test_s3_failed_session_cas_preserves_authoritative_pending() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("failed_cas").await.unwrap();

    // 1. Initial 2 MiB
    let chunk1 = Bytes::from(vec![b'P'; 2 * 1024 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk1]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    // 2. Inject 412 for subsequent CAS
    let key = format!("uploads/{}/session.json", session.uuid);
    driver.inject_412_on_key(&key);

    let chunk2 = Bytes::from(vec![b'Q'; 1024 * 1024]);
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(2 * 1024 * 1024),
            make_test_stream(vec![chunk2]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(res, UploadAppendResult::Conflict);

    // Authoritative offset remains 2 MiB
    driver.clear_injected_412();
    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 2 * 1024 * 1024);
}

#[tokio::test]
async fn test_s3_size_overflow_preserves_pending() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("overflow_repo").await.unwrap();

    // 1. Initial 100 bytes
    let chunk1 = Bytes::from(vec![b'A'; 100]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk1]),
            500,
        )
        .await
        .unwrap();

    // 2. Next chunk 600 bytes exceeds limit of 500
    let chunk2 = Bytes::from(vec![b'B'; 600]);
    let err = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(100),
            make_test_stream(vec![chunk2]),
            500,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, UploadTransitionError::TooLarge));

    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 100);
}

// ==========================================
// 5. Two-Phase S3 Finalization Tests
// ==========================================

#[tokio::test]
async fn test_s3_two_phase_finalization_with_pending_buffer() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("finrepo").await.unwrap();

    // Append 2 MiB
    let payload = Bytes::from(vec![b'F'; 2 * 1024 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let digest = compute_sha256_digest(&payload);

    // Phase 1: begin_finalize
    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(2 * 1024 * 1024),
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    assert_eq!(prepared.size, 2 * 1024 * 1024);
    assert_eq!(prepared.expected_digest, digest);

    // Phase 2: commit_finalize
    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: 2 * 1024 * 1024
        })
    );

    // Duplicate commit_finalize -> AlreadyFinalized
    let dup = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        dup,
        FinalizeOutcome::AlreadyFinalized(BlobMeta {
            size: 2 * 1024 * 1024
        })
    );

    // Receipt check
    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.digest, digest.as_str());
    assert_eq!(receipt.size, 2 * 1024 * 1024);
}

#[tokio::test]
async fn test_s3_begin_finalize_with_trailing_stream() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("trailingrepo").await.unwrap();

    // 1 MiB initial
    let chunk1 = Bytes::from(vec![b'1'; 1024 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk1]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    // 1 MiB trailing
    let chunk2 = Bytes::from(vec![b'2'; 1024 * 1024]);
    let mut full = Vec::new();
    full.extend_from_slice(&vec![b'1'; 1024 * 1024]);
    full.extend_from_slice(&vec![b'2'; 1024 * 1024]);
    let digest = compute_sha256_digest(&full);

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(1024 * 1024),
            Some(make_test_stream(vec![chunk2])),
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    assert_eq!(prepared.size, 2 * 1024 * 1024);

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: 2 * 1024 * 1024
        })
    );
}

#[tokio::test]
async fn test_s3_stale_prepared_handle_rejected() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("finrepo").await.unwrap();

    let payload = Bytes::from(vec![b'X'; 100 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let digest = compute_sha256_digest(&payload);
    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(100 * 1024),
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();

    let mut fake_prepared = prepared.clone();
    fake_prepared.operation_id = "stale-op-id".to_string();

    let err = storage.commit_finalize(&fake_prepared).await.unwrap_err();
    assert!(matches!(err, UploadTransitionError::InvalidPreparedHandle));
}

// ==========================================
// 6. Reaper Behavior Tests
// ==========================================

#[tokio::test]
async fn test_s3_reaper_skips_unexpired_and_reaps_expired() {
    let (storage, driver) = create_mock_storage();
    let session1 = storage.create_session("reap1").await.unwrap();
    let session2 = storage.create_session("reap2").await.unwrap();

    // Advance clock past expiration
    driver.advance_time(400);

    // Update session 1 last_active to current time (active)
    let key1 = format!("uploads/{}/session.json", session1.uuid);
    let (doc1_bytes, etag1) = driver.objects.lock().unwrap().get(&key1).unwrap().clone();
    let mut doc1: S3SessionDoc = serde_json::from_slice(&doc1_bytes).unwrap();
    doc1.last_active_at_unix_secs = driver.now_unix_secs();
    driver
        .put_object_conditional(
            "test-bucket",
            &key1,
            Bytes::from(serde_json::to_vec(&doc1).unwrap()),
            Some(etag1),
            None,
        )
        .await
        .unwrap();

    // Reaper with max_age = 300
    let reaped = storage.reap_expired_sessions(300, 300).await.unwrap();
    assert_eq!(reaped, 1);

    // session1 still exists, session2 was deleted
    assert!(storage.session_status(&session1).await.is_ok());
    assert!(matches!(
        storage.session_status(&session2).await,
        Err(UploadTransitionError::NotFound)
    ));
}

#[tokio::test]
async fn test_s3_reaper_recovers_expired_finalizing_to_receipt() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("reap_fin").await.unwrap();

    let payload = Bytes::from(vec![b'Z'; 50 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let digest = compute_sha256_digest(&payload);
    let _prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(50 * 1024),
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();

    // Advance clock past expiration
    driver.advance_time(500);

    // Reaper recovers finalizing session into CAS destination + receipt
    let reaped = storage.reap_expired_sessions(300, 300).await.unwrap();
    assert_eq!(reaped, 1);

    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.digest, digest.as_str());
    assert_eq!(receipt.size, 50 * 1024);
}

#[tokio::test]
async fn test_s3_small_chunk_end_to_end_lifecycle() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("lifecycle_repo").await.unwrap();

    // 1. Initial status: 0 bytes committed, pending buffer None
    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 0);

    // 2. PATCH 1 MiB chunk at offset 0
    let chunk1 = Bytes::from(vec![b'A'; 1024 * 1024]);
    let res1 = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk1.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res1,
        UploadAppendResult::Committed {
            new_offset: 1024 * 1024
        }
    );
    let s_key = format!("uploads/{}/session.json", session.uuid);
    let (doc1_bytes, _) = driver.objects.lock().unwrap().get(&s_key).unwrap().clone();
    let doc1: S3SessionDoc = serde_json::from_slice(&doc1_bytes).unwrap();
    assert_eq!(doc1.committed_offset, 1024 * 1024);
    assert_eq!(doc1.committed_parts.len(), 0);
    assert_eq!(doc1.pending_bytes, 1024 * 1024);

    // 3. PATCH 2 MiB chunk at offset 1 MiB -> committed 3 MiB
    let chunk2 = Bytes::from(vec![b'B'; 2 * 1024 * 1024]);
    let res2 = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(1024 * 1024),
            make_test_stream(vec![chunk2.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res2,
        UploadAppendResult::Committed {
            new_offset: 3 * 1024 * 1024
        }
    );
    let (doc2_bytes, _) = driver.objects.lock().unwrap().get(&s_key).unwrap().clone();
    let doc2: S3SessionDoc = serde_json::from_slice(&doc2_bytes).unwrap();
    assert_eq!(doc2.committed_offset, 3 * 1024 * 1024);
    assert_eq!(doc2.committed_parts.len(), 0);
    assert_eq!(doc2.pending_bytes, 3 * 1024 * 1024);

    // 4. PATCH 4 MiB chunk at offset 3 MiB -> total 7 MiB (1 part of 5 MiB + 2 MiB pending)
    let chunk3 = Bytes::from(vec![b'C'; 4 * 1024 * 1024]);
    let res3 = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(3 * 1024 * 1024),
            make_test_stream(vec![chunk3.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res3,
        UploadAppendResult::Committed {
            new_offset: 7 * 1024 * 1024
        }
    );
    let (doc3_bytes, _) = driver.objects.lock().unwrap().get(&s_key).unwrap().clone();
    let doc3: S3SessionDoc = serde_json::from_slice(&doc3_bytes).unwrap();
    assert_eq!(doc3.committed_offset, 7 * 1024 * 1024);
    assert_eq!(doc3.committed_parts.len(), 1);
    assert_eq!(doc3.committed_parts[0].size, 5 * 1024 * 1024);
    assert_eq!(doc3.pending_bytes, 2 * 1024 * 1024);

    // 5. Finalize at offset 7 MiB
    let mut full_payload = Vec::new();
    full_payload.extend_from_slice(&chunk1);
    full_payload.extend_from_slice(&chunk2);
    full_payload.extend_from_slice(&chunk3);
    let full_digest = compute_sha256_digest(&full_payload);

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(7 * 1024 * 1024),
            None,
            &full_digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    assert_eq!(prepared.size, 7 * 1024 * 1024);

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: 7 * 1024 * 1024
        })
    );

    // CAS destination blob exists and receipt exists
    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.digest, full_digest.as_str());
    assert_eq!(receipt.size, 7 * 1024 * 1024);
}

#[tokio::test]
async fn test_s3_monolithic_single_request_upload() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("mono_repo").await.unwrap();

    let payload = Bytes::from(vec![b'M'; 1024 * 1024]);
    let digest = compute_sha256_digest(&payload);

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(0),
            Some(make_test_stream(vec![payload.clone()])),
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    assert_eq!(prepared.size, 1024 * 1024);

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta { size: 1024 * 1024 })
    );
}

#[tokio::test]
async fn test_s3_stream_failure_preserves_pending() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("stream_fail").await.unwrap();

    // 1. Initial 1 MiB
    let chunk1 = Bytes::from(vec![b'1'; 1024 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk1]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    // 2. Stream that errors mid-transfer
    let failing_stream: UploadByteStream = Box::pin(futures_util::stream::iter(vec![
        Ok(Bytes::from(vec![b'2'; 100])),
        Err(UploadStreamError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "stream broken",
        ))),
    ]));

    let err = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(1024 * 1024),
            failing_stream,
            10 * 1024 * 1024,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, UploadTransitionError::Stream(_)));

    // Authoritative offset preserved at 1 MiB
    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 1024 * 1024);
}

#[tokio::test]
async fn test_s3_recovery_multipart_part_uploaded_before_cas() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("crash_part").await.unwrap();

    // Reserve session
    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, etag) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let mut doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    doc.state = UploadSessionState::Appending;
    doc.current_operation = Some(S3CurrentOperation {
        operation_id: "op-crashed".to_string(),
        expected_offset: 0,
        target_part_number: 1,
        lease_expires_at_unix_secs: 1200,
    });
    driver
        .put_object_conditional(
            "test-bucket",
            &key,
            Bytes::from(serde_json::to_vec(&doc).unwrap()),
            Some(etag),
            None,
        )
        .await
        .unwrap();

    // Upload an orphan part directly to mock
    let _ = driver
        .upload_part(
            "test-bucket",
            &storage.multipart_data_key(&session.uuid),
            &doc.multipart_upload_id,
            1,
            Bytes::from(vec![b'U'; 5 * 1024 * 1024]),
        )
        .await
        .unwrap();

    // Advance clock past expiration
    driver.advance_time(500);

    // Recovery runs
    let recovered = storage.recover_session(&session).await.unwrap();
    assert_eq!(recovered.state, UploadSessionState::Active);
    assert_eq!(recovered.committed_offset, 0);
}

#[tokio::test]
async fn test_s3_recovery_pending_buffer_uploaded_before_cas() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("crash_pending").await.unwrap();

    // Write orphan pending buffer
    let orphan_key = format!("uploads/{}/pending/orphan.bin", session.uuid);
    driver
        .put_object_conditional(
            "test-bucket",
            &orphan_key,
            Bytes::from(vec![b'P'; 100 * 1024]),
            None,
            None,
        )
        .await
        .unwrap();

    // Set session into Appending with expired lease
    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, etag) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let mut doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    doc.state = UploadSessionState::Appending;
    doc.current_operation = Some(S3CurrentOperation {
        operation_id: "op-orphan".to_string(),
        expected_offset: 0,
        target_part_number: 1,
        lease_expires_at_unix_secs: 1100,
    });
    driver
        .put_object_conditional(
            "test-bucket",
            &key,
            Bytes::from(serde_json::to_vec(&doc).unwrap()),
            Some(etag),
            None,
        )
        .await
        .unwrap();

    driver.advance_time(500);

    // Recovery rolls back to Active and clears uncommitted operation
    let recovered = storage.recover_session(&session).await.unwrap();
    assert_eq!(recovered.state, UploadSessionState::Active);
    assert_eq!(recovered.committed_offset, 0);
}

#[tokio::test]
async fn test_s3_recovered_session_requires_no_state_token() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("notoken_repo").await.unwrap();

    // 1. Initial 1 MiB
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from(vec![b'1'; 1024 * 1024])]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    // 2. Put into stalled Appending state
    let key = format!("uploads/{}/session.json", session.uuid);
    let (doc_bytes, etag) = driver.objects.lock().unwrap().get(&key).unwrap().clone();
    let mut doc: S3SessionDoc = serde_json::from_slice(&doc_bytes).unwrap();
    doc.state = UploadSessionState::Appending;
    doc.current_operation = Some(S3CurrentOperation {
        operation_id: "op-stall".to_string(),
        expected_offset: 1024 * 1024,
        target_part_number: 1,
        lease_expires_at_unix_secs: 1100,
    });
    driver
        .put_object_conditional(
            "test-bucket",
            &key,
            Bytes::from(serde_json::to_vec(&doc).unwrap()),
            Some(etag),
            None,
        )
        .await
        .unwrap();

    // Expire lease and recover
    driver.advance_time(500);
    let recovered = storage.recover_session(&session).await.unwrap();
    assert_eq!(recovered.state, UploadSessionState::Active);
    assert_eq!(recovered.committed_offset, 1024 * 1024);

    // Next append with expected_offset = 1 MiB succeeds directly
    let res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(1024 * 1024),
            make_test_stream(vec![Bytes::from(vec![b'2'; 1024 * 1024])]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(
        res,
        UploadAppendResult::Committed {
            new_offset: 2 * 1024 * 1024
        }
    );
}

#[tokio::test]
async fn test_s3_begin_finalize_exact_multiple_no_pending() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("exact_5mib").await.unwrap();

    // Exactly 5 MiB
    let payload = Bytes::from(vec![b'E'; 5 * 1024 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let digest = compute_sha256_digest(&payload);
    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(5 * 1024 * 1024),
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    assert_eq!(prepared.size, 5 * 1024 * 1024);

    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::Published(BlobMeta {
            size: 5 * 1024 * 1024
        })
    );
}

#[tokio::test]
async fn test_s3_begin_finalize_digest_mismatch_abort_true() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("mismatch_abort_true").await.unwrap();

    let payload = Bytes::from(vec![b'M'; 100 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let wrong_digest =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let err = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(100 * 1024),
            None,
            &wrong_digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, UploadTransitionError::DigestMismatch { .. }));

    // Session was deleted on abort_true
    assert!(matches!(
        storage.session_status(&session).await,
        Err(UploadTransitionError::NotFound)
    ));
}

#[tokio::test]
async fn test_s3_begin_finalize_digest_mismatch_abort_false() {
    let (storage, _driver) = create_mock_storage();
    let session = storage
        .create_session("mismatch_abort_false")
        .await
        .unwrap();

    let payload = Bytes::from(vec![b'N'; 100 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let wrong_digest =
        Digest::parse("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let err = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(100 * 1024),
            None,
            &wrong_digest,
            10 * 1024 * 1024,
            false,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, UploadTransitionError::DigestMismatch { .. }));

    // Session preserved at committed offset
    let status = storage.session_status(&session).await.unwrap();
    assert_eq!(status.committed_offset, 100 * 1024);
}

#[tokio::test]
async fn test_s3_begin_finalize_offset_mismatch() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("offset_mismatch").await.unwrap();

    let payload = Bytes::from(vec![b'O'; 100 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let digest = compute_sha256_digest(&payload);
    let err = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(50 * 1024), // Wrong offset
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, UploadTransitionError::OffsetMismatch { .. }));
}

#[tokio::test]
async fn test_s3_finalize_retry_different_digest_fails() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("diff_digest_repo").await.unwrap();

    let payload = Bytes::from(vec![b'D'; 100 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let digest = compute_sha256_digest(&payload);
    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(100 * 1024),
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();

    storage.commit_finalize(&prepared).await.unwrap();

    // Second begin_finalize with different digest -> already finalized or NotFound
    let diff_digest =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let err = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(100 * 1024),
            None,
            &diff_digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        UploadTransitionError::NotFound | UploadTransitionError::DigestMismatch { .. }
    ));
}

#[tokio::test]
async fn test_s3_recovery_cas_blob_exists_receipt_absent() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("cas_exists").await.unwrap();

    let payload = Bytes::from(vec![b'C'; 50 * 1024]);
    let digest = compute_sha256_digest(&payload);

    // Put blob in CAS destination
    let dest_key = storage.blob_key2(&digest);
    driver
        .put_object_conditional("test-bucket", &dest_key, payload.clone(), None, None)
        .await
        .unwrap();

    // Delete session doc to simulate crash after blob copy
    let key = format!("uploads/{}/session.json", session.uuid);
    driver.delete_object("test-bucket", &key).await.unwrap();

    // Commit finalize with prepared handle detects CAS blob and writes receipt
    let prepared = PreparedFinalize {
        session: session.clone(),
        operation_id: "op-cas".to_string(),
        expected_digest: digest.clone(),
        committed_offset: 50 * 1024,
        size: 50 * 1024,
    };
    let outcome = storage.commit_finalize(&prepared).await.unwrap();
    assert_eq!(
        outcome,
        FinalizeOutcome::AlreadyFinalized(BlobMeta { size: 50 * 1024 })
    );

    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.digest, digest.as_str());
}

#[tokio::test]
async fn test_s3_recovery_staging_intact_completes_finalization() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("staging_intact").await.unwrap();

    let payload = Bytes::from(vec![b'S'; 60 * 1024]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![payload.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let digest = compute_sha256_digest(&payload);
    let _prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(60 * 1024),
            None,
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();

    // Crash before commit_finalize. Advance clock and run recover_session
    driver.advance_time(500);
    let recovered = storage.recover_session(&session).await.unwrap();
    assert_eq!(recovered.state, UploadSessionState::Finalizing);

    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.digest, digest.as_str());
}

#[tokio::test]
async fn test_s3_recovery_crash_after_finalizing_cas_before_multipart_completion() {
    let (storage, driver) = create_mock_storage();
    let session = storage
        .create_session("crash_before_complete")
        .await
        .unwrap();

    let part_bytes = Bytes::from(vec![b'Z'; 5 * 1024 * 1024]);
    let digest = compute_sha256_digest(&part_bytes);

    // Upload part directly to multipart upload
    let (doc, etag) = storage
        .get_session_doc_with_etag(&session.uuid)
        .await
        .unwrap()
        .unwrap();
    let data_key = storage.multipart_data_key(&session.uuid);
    let part_etag = driver
        .upload_part(
            "test-bucket",
            &data_key,
            &doc.multipart_upload_id,
            1,
            part_bytes.clone(),
        )
        .await
        .unwrap();

    // Simulate crash right after Finalizing CAS: state is Finalizing, multipart_completed is false, staging object does not exist yet
    let now = driver.now_unix_secs();
    let finalizing_doc = S3SessionDoc {
        format_version: 1,
        repo: session.repo.clone(),
        uuid: session.uuid.clone(),
        multipart_upload_id: doc.multipart_upload_id.clone(),
        state: UploadSessionState::Finalizing,
        committed_offset: 5 * 1024 * 1024,
        committed_parts: vec![S3CommittedPart {
            part_number: 1,
            size: 5 * 1024 * 1024,
            etag: part_etag,
        }],
        pending_buffer_key: None,
        pending_bytes: 0,
        created_at_unix_secs: now,
        last_active_at_unix_secs: now,
        current_operation: None,
        finalizing_info: Some(S3FinalizingInfo {
            operation_id: "crash-op-1".to_string(),
            expected_digest: digest.as_str().to_string(),
            size: 5 * 1024 * 1024,
            finalizing_at_unix_secs: now,
            multipart_completed: false,
        }),
    };
    storage
        .put_session_doc_conditional(&session.uuid, &finalizing_doc, Some(&etag))
        .await
        .unwrap();

    // Verify staging object does not exist yet
    assert!(
        driver
            .head_object("test-bucket", &data_key)
            .await
            .unwrap()
            .is_none()
    );

    // Run recovery
    driver.advance_time(500);
    let recovered = storage.recover_session(&session).await.unwrap();
    assert_eq!(recovered.state, UploadSessionState::Finalizing);

    // Receipt is written and CAS destination blob exists with correct content
    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.digest, digest.as_str());
    assert_eq!(receipt.size, 5 * 1024 * 1024);

    let cas_key = format!("blobs/sha256/{}/{}", &digest.hex()[..2], digest.hex());
    let (cas_bytes, _) = driver
        .get_object("test-bucket", &cas_key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cas_bytes, part_bytes);
}

#[tokio::test]
async fn test_s3_recovery_neither_cas_blob_nor_staging_errors() {
    let (storage, _driver) = create_mock_storage();
    let session = storage.create_session("neither_repo").await.unwrap();

    let digest =
        Digest::parse("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();
    let fake_prepared = PreparedFinalize {
        session: session.clone(),
        operation_id: "op-fake".to_string(),
        expected_digest: digest,
        committed_offset: 100,
        size: 100,
    };

    let err = storage.commit_finalize(&fake_prepared).await.unwrap_err();
    assert!(matches!(err, UploadTransitionError::InvalidPreparedHandle));
}

#[tokio::test]
async fn test_s3_reaper_aborts_expired_active_session() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("reap_active").await.unwrap();

    // Advance past expiration
    driver.advance_time(600);

    let reaped = storage.reap_expired_sessions(300, 300).await.unwrap();
    assert_eq!(reaped, 1);

    assert!(matches!(
        storage.session_status(&session).await,
        Err(UploadTransitionError::NotFound)
    ));
}

#[tokio::test]
async fn test_s3_reaper_preserves_young_receipt() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("young_receipt").await.unwrap();

    let payload = Bytes::from(vec![b'Y'; 10 * 1024]);
    let digest = compute_sha256_digest(&payload);

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(0),
            Some(make_test_stream(vec![payload])),
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    storage.commit_finalize(&prepared).await.unwrap();

    // Advance clock by 100s (receipt_ttl is 300s)
    driver.advance_time(100);

    let reaped = storage.reap_expired_sessions(300, 300).await.unwrap();
    assert_eq!(reaped, 0);

    let receipt = storage
        .get_finalized_receipt(&session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.digest, digest.as_str());
}

#[tokio::test]
async fn test_s3_reaper_deletes_expired_receipt() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("old_receipt").await.unwrap();

    let payload = Bytes::from(vec![b'O'; 10 * 1024]);
    let digest = compute_sha256_digest(&payload);

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(0),
            Some(make_test_stream(vec![payload])),
            &digest,
            10 * 1024 * 1024,
            true,
        )
        .await
        .unwrap();
    storage.commit_finalize(&prepared).await.unwrap();

    // Advance clock past receipt TTL
    driver.advance_time(500);

    let reaped = storage.reap_expired_sessions(300, 300).await.unwrap();
    assert_eq!(reaped, 1);

    assert!(
        storage
            .get_finalized_receipt(&session)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_s3_reaper_cleans_orphan_pending_buffers() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("orphan_reap").await.unwrap();

    // Write orphan pending buffer
    let orphan_key = format!("uploads/{}/pending/orphan123.bin", session.uuid);
    driver
        .put_object_conditional(
            "test-bucket",
            &orphan_key,
            Bytes::from_static(b"ORPHAN"),
            None,
            None,
        )
        .await
        .unwrap();

    // Advance time past expiration
    driver.advance_time(600);

    let reaped = storage.reap_expired_sessions(300, 300).await.unwrap();
    assert_eq!(reaped, 1);

    // Orphan pending object was deleted
    assert!(driver.objects.lock().unwrap().get(&orphan_key).is_none());
}

#[tokio::test]
async fn test_s3_appending_lease_recovery() {
    let (storage, driver) = create_mock_storage();
    let session = storage.create_session("appending_recovery").await.unwrap();

    // 1. Session begins an append and acquires lease
    let (mut doc, etag) = storage
        .get_session_doc_with_etag(&session.uuid)
        .await
        .unwrap()
        .unwrap();
    doc.state = UploadSessionState::Appending;
    doc.current_operation = Some(S3CurrentOperation {
        operation_id: "op-stalled-append".to_string(),
        expected_offset: 0,
        target_part_number: 1,
        lease_expires_at_unix_secs: driver.now_unix_secs() + 10,
    });
    storage
        .put_session_doc_conditional(&session.uuid, &doc, Some(&etag))
        .await
        .unwrap();

    // While lease is active, concurrent append is rejected with Conflict
    let conflict_res = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"HELLO")]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(conflict_res, UploadAppendResult::Conflict);

    // 2. Advance time past lease expiration
    driver.advance_time(50);

    // 3. Recovery resets state to Active and clears stale lease operation
    let recovered = storage.recover_session(&session).await.unwrap();
    assert_eq!(recovered.state, UploadSessionState::Active);

    let doc_after = storage
        .get_session_doc_with_etag(&session.uuid)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(doc_after.state, UploadSessionState::Active);
    assert!(doc_after.current_operation.is_none());

    // 4. Now a new append succeeds cleanly
    let append_ok = storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![Bytes::from_static(b"SUCCESS")]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    assert_eq!(append_ok, UploadAppendResult::Committed { new_offset: 7 });
}

#[tokio::test]
async fn test_s3_raw_multipart_reaper_comprehensive_safety() {
    let (mut storage, driver) = create_mock_storage();
    storage = storage.with_session_config(S3SessionConfig {
        legacy_multipart_cleanup_policy:
            crate::policy::LegacyMultipartCleanupPolicy::OperatorConfirmedAllUnknown,
        ..S3SessionConfig::default()
    });
    driver.advance_time(100_000);

    let now = driver.now_unix_secs();
    let cutoff = now.saturating_sub(3600);

    // 1. Create an expired orphan multipart upload under registry prefix (no session doc exists)
    let orphan_uuid = uuid::Uuid::new_v4().to_string();
    let orphan_key = format!("uploads/{orphan_uuid}/multipart.data");
    let orphan_mp_id = driver
        .create_multipart_upload("test-bucket", &orphan_key)
        .await
        .unwrap();
    // Set its initiation time in the past
    driver
        .multiparts
        .lock()
        .unwrap()
        .get_mut(&orphan_mp_id)
        .unwrap()
        .2 = now.saturating_sub(7200);

    // 2. Create an active valid session upload (should NOT be reaped)
    let active_session = storage.create_session("active_repo").await.unwrap();
    let active_doc = storage
        .get_session_doc_with_etag(&active_session.uuid)
        .await
        .unwrap()
        .unwrap()
        .0;

    // 3. Create a multipart upload OUTSIDE the registry prefix (must NEVER be touched)
    let external_key = "other_service/uploads/data.bin";
    let external_mp_id = driver
        .create_multipart_upload("test-bucket", external_key)
        .await
        .unwrap();
    driver
        .multiparts
        .lock()
        .unwrap()
        .get_mut(&external_mp_id)
        .unwrap()
        .2 = now.saturating_sub(7200);

    // 4. Create a young orphan multipart upload under registry prefix (younger than cutoff -> should NOT be reaped)
    let young_uuid = uuid::Uuid::new_v4().to_string();
    let young_key = format!("uploads/{young_uuid}/multipart.data");
    let young_mp_id = driver
        .create_multipart_upload("test-bucket", &young_key)
        .await
        .unwrap();
    driver
        .multiparts
        .lock()
        .unwrap()
        .get_mut(&young_mp_id)
        .unwrap()
        .2 = now.saturating_sub(300);

    // 5. Run reaper
    let reaped_count = storage
        .reap_orphaned_multipart_uploads(cutoff)
        .await
        .unwrap();
    assert_eq!(
        reaped_count, 1,
        "Exactly one expired orphan should be reaped"
    );

    // Verify:
    // - Expired orphan was aborted
    assert!(
        !driver
            .multiparts
            .lock()
            .unwrap()
            .contains_key(&orphan_mp_id)
    );
    // - Active session multipart upload is untouched
    assert!(
        driver
            .multiparts
            .lock()
            .unwrap()
            .contains_key(&active_doc.multipart_upload_id)
    );
    // - Unrelated external multipart upload outside prefix is untouched
    assert!(
        driver
            .multiparts
            .lock()
            .unwrap()
            .contains_key(&external_mp_id)
    );
    // - Young multipart upload is untouched
    assert!(driver.multiparts.lock().unwrap().contains_key(&young_mp_id));

    // Verify adapter observed calls
    let call_log = driver.get_call_log();
    assert!(
        call_log
            .iter()
            .any(|c| c.method == "list_multipart_uploads" && c.key == "uploads/")
    );
    assert!(
        call_log
            .iter()
            .any(|c| c.method == "abort_multipart_upload" && c.key == orphan_key)
    );
    assert!(
        !call_log
            .iter()
            .any(|c| c.method == "abort_multipart_upload" && c.key == external_key),
        "Must never abort multipart upload outside registry-owned prefix"
    );
}

#[tokio::test]
async fn test_s3_all_eight_finalization_crash_boundaries() {
    let (storage, driver) = create_mock_storage();

    // --------------------------------------------------------------------
    // Boundary 1: Before Finalizing CAS
    // Fault injection: inject 412 / failure on put_object when setting state=Finalizing
    // --------------------------------------------------------------------
    let session1 = storage.create_session("boundary1").await.unwrap();
    let chunk1 = Bytes::from(vec![b'1'; 5 * 1024 * 1024]);
    let d1 = compute_sha256_digest(&chunk1);
    storage
        .append_if_offset(
            &session1,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk1.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let s1_key = format!("uploads/{}/session.json", session1.uuid);
    driver.set_hook_before(move |method, key| {
        if method == "put_object" && key == s1_key {
            Some(StorageError::TagAlreadyExists)
        } else {
            None
        }
    });

    let err1 = storage
        .begin_finalize(
            &session1,
            UploadOffsetPrecondition::Exact(5 * 1024 * 1024),
            None,
            &d1,
            10 * 1024 * 1024,
            false,
        )
        .await
        .unwrap_err();
    assert!(matches!(err1, UploadTransitionError::Storage(_)));

    // Verify state is still Active
    driver.clear_hooks();
    let status1 = storage.session_status(&session1).await.unwrap();
    assert_eq!(status1.state, UploadSessionState::Active);

    // Retry succeeds
    let prep1 = storage
        .begin_finalize(
            &session1,
            UploadOffsetPrecondition::Exact(5 * 1024 * 1024),
            None,
            &d1,
            10 * 1024 * 1024,
            false,
        )
        .await
        .unwrap();
    storage.commit_finalize(&prep1).await.unwrap();

    // --------------------------------------------------------------------
    // Boundary 2: After Finalizing CAS, before multipart completion
    // Fault injection: complete_multipart_upload fails
    // --------------------------------------------------------------------
    let session2 = storage.create_session("boundary2").await.unwrap();
    let chunk2 = Bytes::from(vec![b'2'; 5 * 1024 * 1024]);
    let d2 = compute_sha256_digest(&chunk2);
    storage
        .append_if_offset(
            &session2,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk2.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    driver.set_hook_before(move |method, _key| {
        if method == "complete_multipart_upload" {
            Some(StorageError::backend("simulated s3 network cut"))
        } else {
            None
        }
    });

    let err2 = storage
        .begin_finalize(
            &session2,
            UploadOffsetPrecondition::Exact(5 * 1024 * 1024),
            None,
            &d2,
            10 * 1024 * 1024,
            false,
        )
        .await
        .unwrap_err();
    assert!(matches!(err2, UploadTransitionError::Storage(_)));

    driver.clear_hooks();
    let doc2 = storage
        .get_session_doc_with_etag(&session2.uuid)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(doc2.state, UploadSessionState::Finalizing);
    assert!(!doc2.finalizing_info.as_ref().unwrap().multipart_completed);

    // Recovery / retry successfully completes multipart and publishes CAS blob
    driver.advance_time(500);
    let rec2 = storage.recover_session(&session2).await.unwrap();
    assert_eq!(rec2.state, UploadSessionState::Finalizing);
    let r2 = storage
        .get_finalized_receipt(&session2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r2.digest, d2.as_str());

    // --------------------------------------------------------------------
    // Boundary 3: After multipart completion, before begin_finalize returns
    // Staged object exists, session doc has multipart_completed: true
    // --------------------------------------------------------------------
    let session3 = storage.create_session("boundary3").await.unwrap();
    let chunk3 = Bytes::from(vec![b'3'; 5 * 1024 * 1024]);
    let d3 = compute_sha256_digest(&chunk3);
    storage
        .append_if_offset(
            &session3,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk3.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();

    let _prep3 = storage
        .begin_finalize(
            &session3,
            UploadOffsetPrecondition::Exact(5 * 1024 * 1024),
            None,
            &d3,
            10 * 1024 * 1024,
            false,
        )
        .await
        .unwrap();

    // Verify staging object exists, CAS blob does not exist yet
    let upload_key3 = storage.multipart_data_key(&session3.uuid);
    assert!(
        driver
            .head_object("test-bucket", &upload_key3)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        driver
            .head_object("test-bucket", &storage.blob_key2(&d3))
            .await
            .unwrap()
            .is_none()
    );

    // Recovery drives staging object to CAS blob and receipt
    driver.advance_time(500);
    let rec3 = storage.recover_session(&session3).await.unwrap();
    assert_eq!(rec3.state, UploadSessionState::Finalizing);
    assert!(
        driver
            .head_object("test-bucket", &storage.blob_key2(&d3))
            .await
            .unwrap()
            .is_some()
    );

    // --------------------------------------------------------------------
    // Boundary 4: After coordinator pin acquisition, before CAS publication
    // --------------------------------------------------------------------
    // Tested end-to-end in coordinator integration suite (proves GC cannot delete)

    // --------------------------------------------------------------------
    // Boundary 5: After CAS publication, before receipt persistence
    // Fault injection: copy_object succeeds, but put_object on finalized.json fails
    // --------------------------------------------------------------------
    let session5 = storage.create_session("boundary5").await.unwrap();
    let chunk5 = Bytes::from(vec![b'5'; 5 * 1024 * 1024]);
    let d5 = compute_sha256_digest(&chunk5);
    storage
        .append_if_offset(
            &session5,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk5.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    let prep5 = storage
        .begin_finalize(
            &session5,
            UploadOffsetPrecondition::Exact(5 * 1024 * 1024),
            None,
            &d5,
            10 * 1024 * 1024,
            false,
        )
        .await
        .unwrap();

    let f5_key = storage.finalized_key(&session5.uuid);
    driver.set_hook_before(move |method, key| {
        if method == "put_object" && key == f5_key {
            Some(StorageError::backend("disk full writing receipt"))
        } else {
            None
        }
    });

    let err5 = storage.commit_finalize(&prep5).await.unwrap_err();
    assert!(matches!(err5, UploadTransitionError::Storage(_)));

    // State: CAS blob exists, receipt does not
    driver.clear_hooks();
    assert!(
        driver
            .head_object("test-bucket", &storage.blob_key2(&d5))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .get_finalized_receipt(&session5)
            .await
            .unwrap()
            .is_none()
    );

    // Recovery / retry detects CAS blob already exists and writes receipt
    driver.advance_time(500);
    let rec5 = storage.recover_session(&session5).await.unwrap();
    assert_eq!(rec5.state, UploadSessionState::Finalizing);
    let r5 = storage
        .get_finalized_receipt(&session5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r5.digest, d5.as_str());

    // --------------------------------------------------------------------
    // Boundary 6: After receipt persistence, before session cleanup
    // Fault injection: delete_object on session.json fails
    // --------------------------------------------------------------------
    let session6 = storage.create_session("boundary6").await.unwrap();
    let chunk6 = Bytes::from(vec![b'6'; 5 * 1024 * 1024]);
    let d6 = compute_sha256_digest(&chunk6);
    storage
        .append_if_offset(
            &session6,
            UploadOffsetPrecondition::Exact(0),
            make_test_stream(vec![chunk6.clone()]),
            10 * 1024 * 1024,
        )
        .await
        .unwrap();
    let prep6 = storage
        .begin_finalize(
            &session6,
            UploadOffsetPrecondition::Exact(5 * 1024 * 1024),
            None,
            &d6,
            10 * 1024 * 1024,
            false,
        )
        .await
        .unwrap();

    let s6_key = storage.session_key(&session6.uuid);
    driver.set_hook_before(move |method, key| {
        if method == "delete_object" && key == s6_key {
            Some(StorageError::backend("failed to delete session.json"))
        } else {
            None
        }
    });

    // commit_finalize succeeds or completes publication with receipt
    let _ = storage.commit_finalize(&prep6).await;
    driver.clear_hooks();

    // Receipt exists
    let r6 = storage
        .get_finalized_receipt(&session6)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r6.digest, d6.as_str());

    // --------------------------------------------------------------------
    // Boundary 7: After session cleanup, before HTTP response
    // Client retries PUT .../blobs/uploads/<uuid>?digest=...
    // --------------------------------------------------------------------
    let outcome6_retry = storage.commit_finalize(&prep6).await.unwrap();
    assert_eq!(
        outcome6_retry,
        FinalizeOutcome::AlreadyFinalized(BlobMeta {
            size: 5 * 1024 * 1024
        })
    );

    // --------------------------------------------------------------------
    // Boundary 8: Retrying begin_finalize on already finalized session
    // --------------------------------------------------------------------
    let prep6_again = storage
        .begin_finalize(
            &session6,
            UploadOffsetPrecondition::Exact(5 * 1024 * 1024),
            None,
            &d6,
            10 * 1024 * 1024,
            false,
        )
        .await
        .unwrap();
    assert_eq!(prep6_again.operation_id, "already-finalized");
}

#[tokio::test]
async fn test_s3_reaper_fail_closed_on_metadata_read_error() {
    let (mut storage, driver) = create_mock_storage();
    storage = storage.with_session_config(S3SessionConfig {
        legacy_multipart_cleanup_policy:
            crate::policy::LegacyMultipartCleanupPolicy::OperatorConfirmedAllUnknown,
        ..S3SessionConfig::default()
    });

    // Create an orphaned multipart upload older than cutoff
    let raw_key = storage.key("uploads/orphan-err-uuid/data");
    let mp_id = driver
        .create_multipart_upload("test-bucket", &raw_key)
        .await
        .unwrap();
    driver.multiparts.lock().unwrap().get_mut(&mp_id).unwrap().2 = 100;

    // Inject S3 error when fetching session.json (e.g. transient 500 / network error)
    let s_key = storage.session_key("orphan-err-uuid");
    driver.set_hook_before(move |method, key| {
        if method == "get_object" && key == s_key {
            Some(StorageError::backend("transient S3 500 error"))
        } else {
            None
        }
    });

    // Run orphan reaper with older_than = 200
    let reaped = storage.reap_orphaned_multipart_uploads(200).await.unwrap();
    // FAIL CLOSED: Must NOT abort multipart upload
    assert_eq!(reaped, 0);

    // Verify raw multipart upload still exists and was not aborted
    let res = driver
        .list_multipart_uploads("test-bucket", &storage.key("uploads/"), None, None)
        .await
        .unwrap();
    assert_eq!(res.uploads.len(), 1);
}

#[tokio::test]
async fn test_s3_reaper_legacy_cleanup_policy_modes() {
    let (storage_disabled, driver) = create_mock_storage();
    // Default policy: Disabled
    assert_eq!(
        storage_disabled
            .session_config
            .legacy_multipart_cleanup_policy,
        crate::policy::LegacyMultipartCleanupPolicy::Disabled
    );

    // Create raw legacy multipart upload without session.json
    let raw_key = storage_disabled.key("uploads/legacy-uuid/data");
    let mp_id = driver
        .create_multipart_upload("test-bucket", &raw_key)
        .await
        .unwrap();
    driver.multiparts.lock().unwrap().get_mut(&mp_id).unwrap().2 = 100;

    // 1. Under Disabled policy -> 0 reaped
    let reaped = storage_disabled
        .reap_orphaned_multipart_uploads(200)
        .await
        .unwrap();
    assert_eq!(reaped, 0);

    // 2. Under CurrentFormatOnly policy -> 0 reaped (cannot prove current format)
    let storage_current = storage_disabled
        .clone()
        .with_session_config(S3SessionConfig {
            legacy_multipart_cleanup_policy:
                crate::policy::LegacyMultipartCleanupPolicy::CurrentFormatOnly,
            ..S3SessionConfig::default()
        });
    let reaped_current = storage_current
        .reap_orphaned_multipart_uploads(200)
        .await
        .unwrap();
    assert_eq!(reaped_current, 0);

    // 3. Under OperatorConfirmedAllUnknown policy -> 1 reaped
    let storage_confirmed = storage_disabled
        .clone()
        .with_session_config(S3SessionConfig {
            legacy_multipart_cleanup_policy:
                crate::policy::LegacyMultipartCleanupPolicy::OperatorConfirmedAllUnknown,
            ..S3SessionConfig::default()
        });
    let reaped_confirmed = storage_confirmed
        .reap_orphaned_multipart_uploads(200)
        .await
        .unwrap();
    assert_eq!(reaped_confirmed, 1);

    // Multipart upload was aborted
    let res = driver
        .list_multipart_uploads("test-bucket", &storage_disabled.key("uploads/"), None, None)
        .await
        .unwrap();
    assert!(res.uploads.is_empty());
}

#[tokio::test]
async fn test_s3_reaper_revalidation_race_protects_upload() {
    let (mut storage, driver) = create_mock_storage();
    storage = storage.with_session_config(S3SessionConfig {
        legacy_multipart_cleanup_policy:
            crate::policy::LegacyMultipartCleanupPolicy::OperatorConfirmedAllUnknown,
        ..S3SessionConfig::default()
    });

    let raw_key = storage.key("uploads/race-uuid/data");
    let mp_id = driver
        .create_multipart_upload("test-bucket", &raw_key)
        .await
        .unwrap();
    driver.multiparts.lock().unwrap().get_mut(&mp_id).unwrap().2 = 100;

    // Simulate a race where during the second (pre-abort) check, a session doc appears
    let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let lookups_clone = Arc::clone(&lookups);
    let driver_clone = Arc::clone(&driver);
    let s_key = storage.session_key("race-uuid");

    driver.set_hook_before(move |method, key| {
        if method == "get_object" && key == s_key {
            let count = lookups_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                // First lookup: Not found
                None
            } else {
                // Second lookup: A session doc was created concurrently!
                let doc = S3SessionDoc {
                    format_version: 1,
                    state: UploadSessionState::Active,
                    repo: crate::registry::canonical_name::CanonicalRepoName::parse("race-repo")
                        .unwrap(),
                    uuid: "race-uuid".into(),
                    created_at_unix_secs: 100,
                    last_active_at_unix_secs: 150,
                    multipart_upload_id: "race-upload-id".into(),
                    committed_offset: 0,
                    committed_parts: vec![],
                    pending_buffer_key: None,
                    pending_bytes: 0,
                    current_operation: None,
                    finalizing_info: None,
                };
                let bytes = Bytes::from(serde_json::to_vec(&doc).unwrap());
                driver_clone
                    .objects
                    .lock()
                    .unwrap()
                    .insert(s_key.clone(), (bytes, "\"etag\"".to_string()));
                None
            }
        } else {
            None
        }
    });

    let reaped = storage.reap_orphaned_multipart_uploads(200).await.unwrap();
    // Abort must be skipped because second check detected the new session doc
    assert_eq!(reaped, 0);

    // Upload was NOT aborted
    let res = driver
        .list_multipart_uploads("test-bucket", &storage.key("uploads/"), None, None)
        .await
        .unwrap();
    assert_eq!(res.uploads.len(), 1);
}

#[tokio::test]
async fn test_s3_reaper_error_matrix_all_non_not_found_fail_closed() {
    let test_cases = vec![
        (
            "timeout",
            StorageError::backend("RequestTimeout: connection timed out"),
        ),
        (
            "throttling",
            StorageError::backend("SlowDown: Please reduce your request rate"),
        ),
        (
            "access_denied",
            StorageError::permission_denied("AccessDenied: 403 Forbidden"),
        ),
        (
            "internal_error",
            StorageError::backend("InternalError: 500 Internal Server Error"),
        ),
    ];

    for (name, error) in test_cases {
        let (mut storage, driver) = create_mock_storage();
        storage = storage.with_session_config(S3SessionConfig {
            legacy_multipart_cleanup_policy:
                crate::policy::LegacyMultipartCleanupPolicy::OperatorConfirmedAllUnknown,
            ..S3SessionConfig::default()
        });

        let raw_key = storage.key(&format!("uploads/orphan-{name}/data"));
        let mp_id = driver
            .create_multipart_upload("test-bucket", &raw_key)
            .await
            .unwrap();
        driver.multiparts.lock().unwrap().get_mut(&mp_id).unwrap().2 = 100;

        let s_key = storage.session_key(&format!("orphan-{name}"));
        let err_clone = error.clone();

        driver.set_hook_before(move |method, key| {
            if method == "get_object" && key == s_key {
                Some(err_clone.clone())
            } else {
                None
            }
        });

        let reaped = storage.reap_orphaned_multipart_uploads(200).await.unwrap();
        assert_eq!(
            reaped, 0,
            "Error case {name} must fail closed and produce 0 aborts"
        );

        // Verify upload was NOT aborted
        let res = driver
            .list_multipart_uploads("test-bucket", &storage.key("uploads/"), None, None)
            .await
            .unwrap();
        assert_eq!(
            res.uploads.len(),
            1,
            "Upload for {name} must remain present"
        );
    }
}

#[tokio::test]
async fn test_s3_reaper_malformed_session_json_fails_closed() {
    let (mut storage, driver) = create_mock_storage();
    storage = storage.with_session_config(S3SessionConfig {
        legacy_multipart_cleanup_policy:
            crate::policy::LegacyMultipartCleanupPolicy::OperatorConfirmedAllUnknown,
        ..S3SessionConfig::default()
    });

    let raw_key = storage.key("uploads/orphan-malformed/data");
    let mp_id = driver
        .create_multipart_upload("test-bucket", &raw_key)
        .await
        .unwrap();
    driver.multiparts.lock().unwrap().get_mut(&mp_id).unwrap().2 = 100;

    // Put malformed JSON in session.json
    let s_key = storage.session_key("orphan-malformed");
    driver.objects.lock().unwrap().insert(
        s_key.clone(),
        (
            Bytes::from_static(b"THIS_IS_NOT_VALID_JSON{:::"),
            "\"etag\"".into(),
        ),
    );

    let reaped = storage.reap_orphaned_multipart_uploads(200).await.unwrap();
    // Malformed session doc must fail closed (0 aborts)
    assert_eq!(reaped, 0);

    let res = driver
        .list_multipart_uploads("test-bucket", &storage.key("uploads/"), None, None)
        .await
        .unwrap();
    assert_eq!(res.uploads.len(), 1);
}

#[tokio::test]
async fn test_s3_reaper_pre_abort_revalidation_error_fails_closed() {
    let (mut storage, driver) = create_mock_storage();
    storage = storage.with_session_config(S3SessionConfig {
        legacy_multipart_cleanup_policy:
            crate::policy::LegacyMultipartCleanupPolicy::OperatorConfirmedAllUnknown,
        ..S3SessionConfig::default()
    });

    let raw_key = storage.key("uploads/orphan-preabort-err/data");
    let mp_id = driver
        .create_multipart_upload("test-bucket", &raw_key)
        .await
        .unwrap();
    driver.multiparts.lock().unwrap().get_mut(&mp_id).unwrap().2 = 100;

    let lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let lookups_clone = Arc::clone(&lookups);
    let s_key = storage.session_key("orphan-preabort-err");

    driver.set_hook_before(move |method, key| {
        if method == "get_object" && key == s_key {
            let count = lookups_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count == 0 {
                // First lookup: Not found (proceeds toward abort)
                None
            } else {
                // Second (pre-abort) lookup: Transient error!
                Some(StorageError::backend("S3 500 during pre-abort check"))
            }
        } else {
            None
        }
    });

    let reaped = storage.reap_orphaned_multipart_uploads(200).await.unwrap();
    // Must fail closed when pre-abort revalidation errors
    assert_eq!(reaped, 0);

    let res = driver
        .list_multipart_uploads("test-bucket", &storage.key("uploads/"), None, None)
        .await
        .unwrap();
    assert_eq!(res.uploads.len(), 1);
}

#[tokio::test]
async fn test_s3_membership_two_concurrent_link_operations_are_idempotent() {
    let (storage, _driver) = create_mock_storage();
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let rec1 = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse("repo-a").unwrap(),
        digest.clone(),
        Some("uuid-1".into()),
    );
    let rec2 = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse("repo-a").unwrap(),
        digest.clone(),
        Some("uuid-2".into()),
    );

    // Both link calls succeed idempotently
    storage.link_repo_blob(&rec1).await.unwrap();
    storage.link_repo_blob(&rec2).await.unwrap();

    let fetched = storage
        .get_repo_blob_membership("repo-a", &digest)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.repo.as_str(), "repo-a");
    assert_eq!(fetched.digest, digest);
}

#[tokio::test]
async fn test_s3_membership_candidate_transition_racing_activation_fails_safe_on_412() {
    let (storage, driver) = create_mock_storage();
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let rec = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse("racing-repo").unwrap(),
        digest.clone(),
        None,
    );
    storage.link_repo_blob(&rec).await.unwrap();

    // Phase 6: simulate a REAL concurrent modification — the hook replaces
    // the record with a new generation between the domain's versioned read
    // and its conditional replace, so the precondition genuinely fails.
    let canonical_racing =
        crate::registry::canonical_name::CanonicalRepoName::parse("racing-repo").unwrap();
    let key = storage.repo_blob_key(&canonical_racing, &digest);
    let key_clone = key.clone();
    let driver_for_hook = driver.clone();
    let racing_bytes = {
        let mut racing = rec.clone();
        racing.created_at_unix_secs = 1;
        bytes::Bytes::from(serde_json::to_vec(&racing).unwrap())
    };
    let racing_for_check = racing_bytes.clone();
    driver.set_hook_before(move |method, k| {
        if method == "put_object" && k == key_clone {
            driver_for_hook.objects.lock().unwrap().insert(
                k.to_string(),
                (racing_bytes.clone(), "\"racing-generation\"".to_string()),
            );
        }
        None
    });

    let res = storage
        .set_membership_candidate("racing-repo", &digest, 1740000000)
        .await;
    assert_eq!(
        res.unwrap(),
        false,
        "lost precondition on candidate transition must fail-safe returning Ok(false)"
    );
    driver.clear_hooks();
    assert_eq!(
        driver
            .objects
            .lock()
            .unwrap()
            .get(&key)
            .map(|(b, _)| b.clone()),
        Some(racing_for_check),
        "the racing generation survives byte-identically"
    );
}

#[tokio::test]
async fn test_s3_membership_corrupt_record_fails_closed() {
    let (storage, driver) = create_mock_storage();
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let canonical_corrupt =
        crate::registry::canonical_name::CanonicalRepoName::parse("corrupt-repo").unwrap();
    let key = storage.repo_blob_key(&canonical_corrupt, &digest);

    // Put invalid JSON in the membership key
    driver.objects.lock().unwrap().insert(
        key.clone(),
        (Bytes::from_static(b"NOT_VALID_JSON{:::"), "\"etag\"".into()),
    );

    let res = storage
        .get_repo_blob_membership("corrupt-repo", &digest)
        .await;
    assert!(
        res.is_err(),
        "Corrupt membership JSON must fail closed with error"
    );
}

#[tokio::test]
async fn test_s3_membership_pagination_bounded_and_consistent() {
    let (storage, _driver) = create_mock_storage();
    let repo = "paged-repo";

    let d_sha256 =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let d_sha512 = Digest::parse("sha512:ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f").unwrap();

    let rec1 = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap(),
        d_sha256.clone(),
        None,
    );
    let rec2 = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap(),
        d_sha512.clone(),
        None,
    );

    storage.link_repo_blob(&rec1).await.unwrap();
    storage.link_repo_blob(&rec2).await.unwrap();

    // Page size 1
    let (p1, next_tok) = storage
        .list_repo_blob_memberships_page(repo, None, 1)
        .await
        .unwrap();
    assert_eq!(p1.len(), 1);
    assert!(next_tok.is_some());

    let (p2, next_tok2) = storage
        .list_repo_blob_memberships_page(repo, next_tok.as_deref(), 1)
        .await
        .unwrap();
    assert_eq!(p2.len(), 1);
    assert!(next_tok2.is_none());

    assert_ne!(p1[0].digest, p2[0].digest);
}

#[tokio::test]
async fn test_s3_membership_repo_prefix_encoding_isolation() {
    let (storage, _driver) = create_mock_storage();
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();

    // Repo "foo" vs Repo "foo/bar" vs Repo "foo-bar"
    let rec_foo = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse("foo").unwrap(),
        digest.clone(),
        None,
    );
    let rec_foo_bar = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse("foo/bar").unwrap(),
        digest.clone(),
        None,
    );
    let rec_foo_dash = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse("foo-bar").unwrap(),
        digest.clone(),
        None,
    );

    storage.link_repo_blob(&rec_foo).await.unwrap();
    storage.link_repo_blob(&rec_foo_bar).await.unwrap();
    storage.link_repo_blob(&rec_foo_dash).await.unwrap();

    let (p_foo, _) = storage
        .list_repo_blob_memberships_page("foo", None, 10)
        .await
        .unwrap();
    let (p_bar, _) = storage
        .list_repo_blob_memberships_page("foo/bar", None, 10)
        .await
        .unwrap();
    let (p_dash, _) = storage
        .list_repo_blob_memberships_page("foo-bar", None, 10)
        .await
        .unwrap();

    assert_eq!(p_foo.len(), 1);
    assert_eq!(p_bar.len(), 1);
    assert_eq!(p_dash.len(), 1);
    assert_eq!(p_foo[0].repo.as_str(), "foo");
    assert_eq!(p_bar[0].repo.as_str(), "foo/bar");
    assert_eq!(p_dash[0].repo.as_str(), "foo-bar");
}

#[tokio::test]
async fn test_s3_migration_plan_performs_zero_writes() {
    let (storage, driver) = create_mock_storage();
    let storage_arc = Arc::new(storage);

    let stats = crate::membership_migration::plan_membership_migration(&storage_arc)
        .await
        .expect("plan");
    assert_eq!(stats.repositories_scanned, 0);

    // Verify driver object store is completely empty
    let objects = driver.objects.lock().unwrap();
    assert!(
        objects.is_empty(),
        "Plan must perform zero writes to S3 object store"
    );
}

#[tokio::test]
async fn test_s3_migration_conditional_state_acquisition_and_lease_renewal() {
    let (storage, _driver) = create_mock_storage();
    let storage_arc = Arc::new(storage);

    // First apply acquires lease and succeeds
    let stats = crate::membership_migration::apply_membership_migration(&storage_arc)
        .await
        .expect("apply");
    assert_eq!(stats.repositories_scanned, 0);

    // Checkpoint is Ready
    let ready = storage_arc.is_membership_ready().await.unwrap();
    assert!(ready);
}

#[tokio::test]
async fn test_s3_migration_concurrent_owner_rejection() {
    let (storage, _driver) = create_mock_storage();
    let storage_arc = Arc::new(storage);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let active_lease = crate::storage::repo_membership::MigrationCheckpointRecord {
        schema_version: 1,
        phase: crate::storage::repo_membership::MigrationPhase::Applying,
        owner_id: Some("migrator-owner-A".to_string()),
        lease_expiry_unix_secs: Some(now + 3600),
        source_continuation_token: None,
        current_repository: None,
        current_cursor: None,
        stats: crate::storage::repo_membership::MigrationStats::default(),
        started_unix_secs: now,
        last_updated_unix_secs: now,
        failure_info: None,
        verification_result: None,
    };
    storage_arc
        .save_migration_checkpoint(&active_lease)
        .await
        .unwrap();

    // Second owner attempts apply -> fails closed
    let res = crate::membership_migration::apply_membership_migration(&storage_arc).await;
    assert!(res.is_err(), "Must reject concurrent migrator");
}

#[tokio::test]
async fn test_s3_migration_interrupted_apply_and_cursor_resume() {
    let (storage, _driver) = create_mock_storage();
    let storage_arc = Arc::new(storage);

    let now = 10000;
    // Pre-seed checkpoint with completed token "repo-a"
    let cp = crate::storage::repo_membership::MigrationCheckpointRecord {
        schema_version: 1,
        phase: crate::storage::repo_membership::MigrationPhase::Applying,
        owner_id: None,
        lease_expiry_unix_secs: None,
        source_continuation_token: Some("repo-a".to_string()),
        current_repository: None,
        current_cursor: None,
        stats: crate::storage::repo_membership::MigrationStats::default(),
        started_unix_secs: now,
        last_updated_unix_secs: now,
        failure_info: None,
        verification_result: None,
    };
    storage_arc.save_migration_checkpoint(&cp).await.unwrap();

    // Apply resumes from cursor and finishes
    let res = crate::membership_migration::apply_membership_migration(&storage_arc).await;
    assert!(res.is_ok());
    assert!(storage_arc.is_membership_ready().await.unwrap());
}

#[tokio::test]
async fn test_s3_membership_migration_multiarch_manifest_list_traversal() {
    use crate::storage::Storage;
    let (storage, _driver) = create_mock_storage();
    let storage_arc = Arc::new(storage);
    let repo = "s3-multi-arch-repo";

    let blob_digest = |data: &[u8]| {
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(data);
        Digest::parse(&format!("sha256:{}", hex::encode(hash))).unwrap()
    };
    let config_amd64 = blob_digest(b"cfg_amd64");
    let layer_amd64 = blob_digest(b"layer_amd64");
    let config_arm64 = blob_digest(b"cfg_arm64");
    let layer_arm64 = blob_digest(b"layer_arm64");

    for (d, b) in [
        (&config_amd64, b"cfg_amd64" as &[u8]),
        (&layer_amd64, b"layer_amd64"),
        (&config_arm64, b"cfg_arm64"),
        (&layer_arm64, b"layer_arm64"),
    ] {
        let up = storage_arc.create_upload().await.unwrap();
        storage_arc
            .append_upload(&up.uuid, Bytes::copy_from_slice(b))
            .await
            .unwrap();
        storage_arc.finalize_upload(&up.uuid, d).await.unwrap();
    }

    let manifest_amd64_bytes = Bytes::from(format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":9}},"layers":[{{"digest":"{}","size":11}}]}}"#,
        config_amd64.as_str(),
        layer_amd64.as_str()
    ));
    let digest_amd64 = blob_digest(&manifest_amd64_bytes);
    storage_arc
        .put_manifest(repo, &digest_amd64, manifest_amd64_bytes)
        .await
        .unwrap();

    let manifest_arm64_bytes = Bytes::from(format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":9}},"layers":[{{"digest":"{}","size":11}}]}}"#,
        config_arm64.as_str(),
        layer_arm64.as_str()
    ));
    let digest_arm64 = blob_digest(&manifest_arm64_bytes);
    storage_arc
        .put_manifest(repo, &digest_arm64, manifest_arm64_bytes)
        .await
        .unwrap();

    let index_bytes = Bytes::from(format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":100}},{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":100}}]}}"#,
        digest_amd64.as_str(),
        digest_arm64.as_str()
    ));
    let digest_index = blob_digest(&index_bytes);
    storage_arc
        .put_manifest(repo, &digest_index, index_bytes)
        .await
        .unwrap();

    storage_arc.set_tag(repo, "latest", &digest_index).await.unwrap();

    let plan_stats = crate::membership_migration::plan_membership_migration(&storage_arc).await.unwrap();
    assert_eq!(plan_stats.manifests_scanned, 3);
    assert_eq!(plan_stats.memberships_created, 4);

    let apply_stats = crate::membership_migration::apply_membership_migration(&storage_arc).await.unwrap();
    assert_eq!(apply_stats.manifests_scanned, 3);
    assert_eq!(apply_stats.memberships_created, 4);

    let verified = crate::membership_migration::verify_membership_migration(&storage_arc).await.unwrap();
    assert!(verified, "membership verification must pass for multi-arch manifest lists on S3");

    for blob in [&config_amd64, &layer_amd64, &config_arm64, &layer_arm64] {
        assert!(
            storage_arc
                .get_repo_blob_membership(repo, blob)
                .await
                .unwrap()
                .is_some(),
            "blob {blob} must have repo membership on S3"
        );
    }
}

#[tokio::test]
async fn test_s3_manifest_lifecycle_delete_manifest_and_coordination() {
    use crate::consistency::ConsistencyCoordinator;
    use crate::manifest_lifecycle::{ManifestLifecycleService, PublishManifestRequest};
    use crate::storage::Storage;

    let (storage, _driver) = create_mock_storage();
    let storage_arc = Arc::new(storage);
    let coordinator = ConsistencyCoordinator::new();
    let service = ManifestLifecycleService::new(storage_arc.clone(), None, coordinator);
    let repo = "s3-lifecycle-repo";

    let cfg_payload = b"{}";
    use sha2::Digest as _;
    let cfg_digest = Digest::parse(&format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(cfg_payload))
    ))
    .unwrap();

    let up = storage_arc.create_upload().await.unwrap();
    storage_arc
        .append_upload(&up.uuid, Bytes::from_static(cfg_payload))
        .await
        .unwrap();
    storage_arc
        .finalize_upload(&up.uuid, &cfg_digest)
        .await
        .unwrap();

    let manifest_bytes = Bytes::from(format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":{}}},"layers":[]}}"#,
        cfg_digest.as_str(),
        cfg_payload.len()
    ));
    let digest = Digest::parse(&format!(
        "sha256:{}",
        hex::encode(sha2::Sha256::digest(&manifest_bytes))
    ))
    .unwrap();

    // 1. Publish manifest with tag "latest"
    let req = PublishManifestRequest::new(
        repo,
        "latest",
        manifest_bytes.clone(),
        Some("application/vnd.oci.image.manifest.v1+json".to_string()),
        true,
    );
    let pub_res = service.publish(req).await.expect("publish manifest on S3");
    assert_eq!(pub_res.digest, digest);

    // Verify tag and manifest exist on S3
    assert_eq!(
        storage_arc.resolve_tag(repo, "latest").await.unwrap(),
        digest
    );
    assert!(storage_arc.head_manifest(repo, &digest).await.is_ok());

    // 2. Delete manifest through lifecycle service on S3
    let del_res = service
        .delete_manifest(repo, &digest)
        .await
        .expect("delete manifest on S3");
    assert_eq!(del_res.digest, digest);
    assert_eq!(del_res.removed_tags, vec!["latest"]);

    // Verify manifest and tag are deleted from S3
    assert!(storage_arc.resolve_tag(repo, "latest").await.is_err());
    assert!(storage_arc.head_manifest(repo, &digest).await.is_err());

    // Verify lifecycle journal is deleted from S3
    assert!(storage_arc
        .read_lifecycle_journal(repo)
        .await
        .unwrap()
        .is_none());

    // Verify lease was released on S3 (new coordination can be acquired immediately)
    let coord = service.acquire_coordination(repo).await;
    assert!(coord.is_ok(), "S3 repo lease must be cleanly released");
}

#[tokio::test]
async fn test_s3_acquire_coordination_does_not_block_unrelated_repo_during_lease_backoff() {
    use crate::consistency::ConsistencyCoordinator;
    use crate::manifest_lifecycle::ManifestLifecycleService;
    use crate::storage::Storage;

    let (storage, _driver) = create_mock_storage();
    let storage_arc = Arc::new(storage);
    let coordinator = ConsistencyCoordinator::new();
    let service = ManifestLifecycleService::new(storage_arc.clone(), None, coordinator);

    // Pre-acquire lease on repo-a in S3
    storage_arc
        .acquire_repo_lease("repo-a", "other-owner", "other-lease", 60)
        .await
        .unwrap();

    // Spawn task attempting to acquire coordination on repo-a (will loop with backoff on S3)
    let service_clone = service.clone();
    let task_a = tokio::spawn(async move {
        service_clone.acquire_coordination("repo-a").await
    });

    // Small yield so task_a enters the retry loop for repo-a
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    // Coordination on repo-b MUST succeed immediately on S3 without waiting for repo-a backoff
    let start = std::time::Instant::now();
    let guard_b = service.acquire_coordination("repo-b").await;
    let elapsed = start.elapsed();

    assert!(guard_b.is_ok(), "repo-b coordination must succeed on S3");
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "repo-b must not be blocked by repo-a lease retry backoff on S3, took {elapsed:?}"
    );

    task_a.abort();
}

#[tokio::test]
async fn test_s3_no_normal_membership_op_reads_or_deletes_legacy_markers() {
    let (storage, driver) = create_mock_storage();
    let digest =
        Digest::parse("sha256:4444444444444444444444444444444444444444444444444444444444444444")
            .unwrap();
    let repo = "legacy-test-repo";

    // Seed a legacy key directly in S3 driver
    let legacy_key = format!("repos/{repo}/blobs/sha256/{}.json", digest.hex());
    let legacy_payload = serde_json::json!({
        "schema_version": 1,
        "repo": repo,
        "digest": digest.to_string(),
        "created_at_unix_secs": 1000,
        "provenance": { "type": "upload" },
        "format_version": 1
    });
    driver.objects.lock().unwrap().insert(
        format!("test-bucket/{legacy_key}"),
        (
            Bytes::from(serde_json::to_vec(&legacy_payload).unwrap()),
            "etag-1".to_string(),
        ),
    );

    // Normal get_repo_blob_membership must return None (no silent fallback or auto-migration)
    let mem = storage
        .get_repo_blob_membership(repo, &digest)
        .await
        .unwrap();
    assert!(mem.is_none(), "Normal read must not query legacy key");

    // Normal unlink must NOT delete legacy key; with no CANONICAL record
    // present it reports Ok(false) (FS-parity absent semantics).
    let unlinked = storage.unlink_repo_blob(repo, &digest).await.unwrap();
    assert!(
        !unlinked,
        "absent canonical membership record must report false"
    );

    // Legacy key must remain intact in driver
    let objects = driver.objects.lock().unwrap();
    assert!(
        objects.contains_key(&format!("test-bucket/{legacy_key}")),
        "Normal unlink must not delete legacy key"
    );
}

#[tokio::test]
async fn test_s3_cas_enumeration_fails_closed_on_malformed_key() {
    let (storage, driver) = create_mock_storage();

    // Insert a malformed CAS key directly into S3
    driver.objects.lock().unwrap().insert(
        "blobs/sha256/invalid_key_format".to_string(),
        (Bytes::from_static(b"data"), "etag-bad".to_string()),
    );

    let res = storage.list_cas_blobs_page(None, 100).await;
    assert!(
        res.is_err(),
        "S3 enumeration must fail closed on malformed key format"
    );
    let err = res.unwrap_err();
    let expected_message = "malformed CAS object key structure in S3 (expected 2 parts): blobs/sha256/invalid_key_format";
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
    assert_eq!(err.message(), Some(expected_message));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_aws_s3_driver_missing_region_is_configuration() {
    let driver = AwsS3Driver::new(Some("http://127.0.0.1:9000".into()), None);
    let res = driver.client().await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Configuration),
        "Missing S3 region must classify as Configuration"
    );
    assert_eq!(err.message(), Some("STORAGE_S3_REGION is required"));
    assert_eq!(
        err.to_string(),
        "internal error: STORAGE_S3_REGION is required"
    );
}

#[tokio::test]
async fn test_aws_s3_driver_missing_upload_id_is_backend() {
    let success = validate_multipart_upload_id(Some("valid-upload-id-123")).unwrap();
    assert_eq!(success, "valid-upload-id-123");

    let res = validate_multipart_upload_id(None);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(err.message(), Some("missing upload_id"));
    assert_eq!(err.to_string(), "internal error: missing upload_id");
}

#[tokio::test]
async fn test_aws_s3_driver_continuation_token_cycle_is_backend() {
    let mut seen = HashSet::new();
    let token = "test-pagination-token-xyz";

    assert!(track_continuation_token(&mut seen, token).is_ok());

    let res = track_continuation_token(&mut seen, token);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(
        err.message(),
        Some("cyclic continuation token from S3 list_objects_v2")
    );
    assert_eq!(
        err.to_string(),
        "internal error: cyclic continuation token from S3 list_objects_v2"
    );
}

#[tokio::test]
async fn test_s3_storage_missing_bucket_is_configuration() {
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(None, "".to_string(), 100_000_000, driver);
    let res = storage.bucket();
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Configuration)
    );
    assert_eq!(err.message(), Some("STORAGE_S3_BUCKET is required"));
    assert_eq!(
        err.to_string(),
        "internal error: STORAGE_S3_BUCKET is required"
    );
}

#[tokio::test]
async fn test_detect_manifest_media_type_malformed_json_is_corrupt_data() {
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver,
    );
    let malformed_bytes = b"{{{ malformed manifest json bytes";
    let expected_err = serde_json::from_slice::<serde_json::Value>(malformed_bytes).unwrap_err();
    let expected_message = expected_err.to_string();

    let _ = &storage;
    let res = crate::storage::manifest_domain::detect_manifest_media_type(malformed_bytes);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_delete_blob_conditional_missing_version_is_conflict() {
    use crate::storage::GcStorage;
    use crate::storage::mutation_authority::RuntimeMutationAuthority;
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = Arc::new(S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver,
    ));
    let authority = RuntimeMutationAuthority::acquire(storage.clone(), "test-gc-owner")
        .await
        .expect("acquire");
    let permit = authority.gc_mutation_permit();
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();

    let res = GcStorage::delete_blob_conditional(&*storage, &permit, &digest, None).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Conflict)
    );
    assert_eq!(
        err.message(),
        Some(
            "S3 conditional delete requires an explicit object version/ETag; unconditional delete is forbidden in GC"
        )
    );
    assert_eq!(
        err.to_string(),
        "internal error: S3 conditional delete requires an explicit object version/ETag; unconditional delete is forbidden in GC"
    );
}

#[tokio::test]
async fn test_s3_mutate_tag_shared_semantics_and_error_propagation() {
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let other =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let tag_key = "repos/test-repo/tags/v1.0.0";

    // 1. CreateOnly on an absent tag -> Created (service-atomic
    //    If-None-Match publication); repeated CreateOnly with the SAME
    //    digest -> Unchanged; different digest -> TagAlreadyExists.
    let (storage, driver) = create_mock_storage();
    let created = storage
        .mutate_tag(
            "test-repo",
            "v1.0.0",
            &digest,
            crate::storage::TagMutationPolicy::CreateOnly,
        )
        .await
        .unwrap();
    assert_eq!(created, crate::storage::TagMutation::Created);
    assert_eq!(
        driver.objects.lock().unwrap().get(tag_key).unwrap().0,
        Bytes::from(format!("{}\n", digest.as_str())),
        "exact historical bytes: digest + newline"
    );
    let unchanged = storage
        .mutate_tag(
            "test-repo",
            "v1.0.0",
            &digest,
            crate::storage::TagMutationPolicy::CreateOnly,
        )
        .await
        .unwrap();
    assert_eq!(unchanged, crate::storage::TagMutation::Unchanged);
    let conflict = storage
        .mutate_tag(
            "test-repo",
            "v1.0.0",
            &other,
            crate::storage::TagMutationPolicy::CreateOnly,
        )
        .await
        .unwrap_err();
    assert!(matches!(conflict, StorageError::TagAlreadyExists));

    // 2. Replace on an existing tag -> Replaced { previous }; same digest
    //    short-circuits to Unchanged WITHOUT rewriting (etag stable).
    let replaced = storage
        .mutate_tag(
            "test-repo",
            "v1.0.0",
            &other,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
        .unwrap();
    assert_eq!(
        replaced,
        crate::storage::TagMutation::Replaced {
            previous: digest.clone()
        }
    );
    let etag_before = driver
        .objects
        .lock()
        .unwrap()
        .get(tag_key)
        .unwrap()
        .1
        .clone();
    let unchanged2 = storage
        .mutate_tag(
            "test-repo",
            "v1.0.0",
            &other,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
        .unwrap();
    assert_eq!(unchanged2, crate::storage::TagMutation::Unchanged);
    let etag_after = driver
        .objects
        .lock()
        .unwrap()
        .get(tag_key)
        .unwrap()
        .1
        .clone();
    assert_eq!(
        etag_before, etag_after,
        "same-digest short-circuit performs no write"
    );

    // 3. Underlying backend transport/service failure -> Backend.
    let (storage3, driver3) = create_mock_storage();
    driver3.set_hook_before(|method, key| {
        if method == "put_object" && key == "repos/test-repo/tags/v1.0.0" {
            Some(StorageError::backend("s3 service 503 slow down"))
        } else {
            None
        }
    });
    let err_backend = storage3
        .mutate_tag(
            "test-repo",
            "v1.0.0",
            &digest,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
        .unwrap_err();
    assert_eq!(
        err_backend.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert!(
        err_backend.to_string().contains("s3 service 503 slow down"),
        "underlying diagnostic preserved: {err_backend}"
    );

    // 4. Underlying permission failure -> PermissionDenied.
    let (storage4, driver4) = create_mock_storage();
    driver4.set_hook_before(|method, key| {
        if method == "put_object" && key == "repos/test-repo/tags/v1.0.0" {
            Some(StorageError::permission_denied("s3:PutObject forbidden"))
        } else {
            None
        }
    });
    let err_perm = storage4
        .mutate_tag(
            "test-repo",
            "v1.0.0",
            &digest,
            crate::storage::TagMutationPolicy::Replace,
        )
        .await
        .unwrap_err();
    assert_eq!(
        err_perm.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert!(err_perm.to_string().contains("s3:PutObject forbidden"));
}

#[tokio::test]
async fn test_s3_get_tag_with_version_corrupt_digest_is_corrupt_data() {
    let (storage, driver) = create_mock_storage();

    // Phase 3: the version token is the registry raw-byte SHA-256, never the
    // backend ETag.
    let hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let payload = format!("sha256:{hex}\n");
    driver.objects.lock().unwrap().insert(
        "repos/test-repo/tags/good-tag".to_string(),
        (
            bytes::Bytes::from(payload.clone()),
            "\"etag-opaque\"".to_string(),
        ),
    );
    let (d, version) = storage
        .get_tag_with_version("test-repo", "good-tag")
        .await
        .unwrap()
        .expect("tag exists");
    assert_eq!(d.hex(), hex);
    {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(payload.as_bytes());
        assert_eq!(version, hex::encode(hasher.finalize()));
    }

    let tag_key = "repos/test-repo/tags/corrupt-tag";
    driver.objects.lock().unwrap().insert(
        tag_key.to_string(),
        (
            bytes::Bytes::from_static(b"not-a-valid-sha256-digest"),
            "etag-tag-1".to_string(),
        ),
    );

    let res = storage
        .get_tag_with_version("test-repo", "corrupt-tag")
        .await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_parse_err = Digest::parse("not-a-valid-sha256-digest").unwrap_err();
    let expected_message = format!("corrupt tag corrupt-tag: {expected_parse_err}");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_s3_get_finalized_receipt_malformed_json_is_corrupt_data() {
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver.clone(),
    );
    let session = UploadSessionId::new(
        CanonicalRepoName::parse("test-repo").unwrap(),
        "session-uuid-123",
    );
    let key = format!("uploads/{}/finalized.json", session.uuid);
    let malformed_bytes = b"{{{ malformed finalized receipt json";
    driver.objects.lock().unwrap().insert(
        key,
        (
            bytes::Bytes::from_static(malformed_bytes),
            "etag-rec-1".to_string(),
        ),
    );

    let res = storage.get_finalized_receipt(&session).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_err = serde_json::from_slice::<FinalizedReceipt>(malformed_bytes).unwrap_err();
    let expected_message = expected_err.to_string();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_s3_membership_candidate_preserves_backend_and_permission_denied() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let canonical = CanonicalRepoName::parse("test-repo").unwrap();
    let key =
        crate::storage::repo_membership::canonical_repo_membership_relpath(&canonical, &digest);

    // 1. Malformed membership record -> CorruptData (baseline line 3427)
    let driver1 = Arc::new(MockS3Driver::new(1000));
    let storage1 = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        Arc::new(TagBridgeDriver::new(driver1.clone())),
    );
    let malformed_bytes = b"{{{ malformed membership json";
    driver1.objects.lock().unwrap().insert(
        key.clone(),
        (
            bytes::Bytes::from_static(malformed_bytes),
            "etag-mem-1".to_string(),
        ),
    );
    let res_get = storage1
        .get_repo_blob_membership("test-repo", &digest)
        .await;
    assert!(res_get.is_err());
    let err_get = res_get.unwrap_err();
    let expected_parse_err = serde_json::from_slice::<
        crate::storage::repo_membership::RepoBlobMembershipRecord,
    >(malformed_bytes)
    .unwrap_err();
    // Phase 6: the shared domain's point-read message carries the record
    // key without the retired backend-specific "s3 key" wording.
    let expected_get_msg = format!("corrupt membership record in {key}: {expected_parse_err}");
    assert_eq!(
        err_get.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
    assert_eq!(err_get.message(), Some(expected_get_msg.as_str()));
    assert_eq!(
        err_get.to_string(),
        format!("internal error: {expected_get_msg}")
    );

    // 2. Underlying backend failure during candidate mutation -> Backend (baseline line 3481)
    let driver2 = Arc::new(MockS3Driver::new(1000));
    let storage2 = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        Arc::new(TagBridgeDriver::new(driver2.clone())),
    );
    let record = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        canonical.clone(),
        digest.clone(),
        None,
    );
    let rec_bytes = serde_json::to_vec(&record).unwrap();
    driver2.objects.lock().unwrap().insert(
        key.clone(),
        (bytes::Bytes::from(rec_bytes), "etag-mem-2".to_string()),
    );
    let hook_key = key.clone();
    driver2.set_hook_before(move |method, k| {
        if method == "put_object" && k == hook_key {
            Some(StorageError::backend("s3 service 500 error"))
        } else {
            None
        }
    });
    let res_backend = storage2
        .set_membership_candidate("test-repo", &digest, 200)
        .await;
    assert!(res_backend.is_err());
    let err_backend = res_backend.unwrap_err();
    assert_eq!(
        err_backend.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    // Phase 6: the injected cause survives inside the shared translation's
    // "membership write: ..." wrapper (the retired path surfaced it bare).
    assert!(
        err_backend.message().is_some_and(
            |m| m.starts_with("membership write: ") && m.contains("s3 service 500 error")
        ),
        "cause preserved: {err_backend:?}"
    );

    // 3. Underlying permission failure during candidate mutation -> PermissionDenied
    let driver3 = Arc::new(MockS3Driver::new(1000));
    let storage3 = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        Arc::new(TagBridgeDriver::new(driver3.clone())),
    );
    driver3.objects.lock().unwrap().insert(
        key.clone(),
        (
            bytes::Bytes::from(serde_json::to_vec(&record).unwrap()),
            "etag-mem-3".to_string(),
        ),
    );
    let hook_key3 = key.clone();
    driver3.set_hook_before(move |method, k| {
        if method == "put_object" && k == hook_key3 {
            Some(StorageError::permission_denied(
                "s3:PutObject access denied",
            ))
        } else {
            None
        }
    });
    let res_perm = storage3
        .set_membership_candidate("test-repo", &digest, 200)
        .await;
    assert!(res_perm.is_err());
    let err_perm = res_perm.unwrap_err();
    assert_eq!(
        err_perm.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert!(
        err_perm.message().is_some_and(
            |m| m.starts_with("membership write: ") && m.contains("s3:PutObject access denied")
        ),
        "cause preserved: {err_perm:?}"
    );

    // 4. Concurrently deleted membership record during pagination is skipped gracefully
    let driver4 = Arc::new(MockS3Driver::new(1000));
    let storage4 = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver4.clone(),
    );
    driver4.objects.lock().unwrap().insert(
        key.clone(),
        (
            bytes::Bytes::from(serde_json::to_vec(&record).unwrap()),
            "etag-mem-4".to_string(),
        ),
    );
    let driver4_for_hook = driver4.clone();
    let hook_key4 = key.clone();
    driver4.set_hook_before(move |method, k| {
        if method == "get_object" && k == hook_key4 {
            // Simulate another actor deleting the membership record concurrently
            driver4_for_hook.objects.lock().unwrap().remove(k);
        }
        None
    });
    let res_list = storage4
        .list_repo_blob_memberships_page("test-repo", None, 10)
        .await;
    assert!(res_list.is_ok());
    let (records, next_token) = res_list.unwrap();
    assert!(records.is_empty());
    assert_eq!(next_token, None);

    // Verify both listing and point fetch were actually executed
    let call_log = driver4.get_call_log();
    assert!(
        call_log
            .iter()
            .any(|entry| entry.method == "list_objects_v2"),
        "list_objects_v2 must have been called during pagination traversal"
    );
    assert!(
        call_log
            .iter()
            .any(|entry| entry.method == "get_object" && entry.key == key),
        "get_object must have been called on the listed key before observing disappearance"
    );

    // 5. Structured Conflict from put_object_conditional becomes Ok(false) in set_membership_candidate (baseline line 3481)
    let driver5 = Arc::new(MockS3Driver::new(1000));
    let storage5 = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        Arc::new(TagBridgeDriver::new(driver5.clone())),
    );
    driver5.objects.lock().unwrap().insert(
        key.clone(),
        (
            bytes::Bytes::from(serde_json::to_vec(&record).unwrap()),
            "etag-mem-5".to_string(),
        ),
    );
    // Phase 6: a REAL replacement between the versioned read and the
    // conditional write (the retired test injected an opaque conflict error).
    let hook_key5 = key.clone();
    let driver5_for_hook = driver5.clone();
    let replaced5 = {
        let mut r = record.clone();
        r.created_at_unix_secs = 5;
        bytes::Bytes::from(serde_json::to_vec(&r).unwrap())
    };
    driver5.set_hook_before(move |method, k| {
        if method == "put_object" && k == hook_key5 {
            driver5_for_hook
                .objects
                .lock()
                .unwrap()
                .insert(k.to_string(), (replaced5.clone(), "\"gen-5b\"".to_string()));
        }
        None
    });
    let res_set_conf = storage5
        .set_membership_candidate("test-repo", &digest, 200)
        .await;
    assert_eq!(res_set_conf.unwrap(), false);

    // 6. Structured Conflict from put_object_conditional becomes Ok(false) in clear_membership_candidate (baseline line 3529)
    let driver6 = Arc::new(MockS3Driver::new(1000));
    let storage6 = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        Arc::new(TagBridgeDriver::new(driver6.clone())),
    );
    let mut candidate_record = record.clone();
    candidate_record.mark_candidate(200);
    driver6.objects.lock().unwrap().insert(
        key.clone(),
        (
            bytes::Bytes::from(serde_json::to_vec(&candidate_record).unwrap()),
            "etag-mem-6".to_string(),
        ),
    );
    let hook_key6 = key.clone();
    let driver6_for_hook = driver6.clone();
    let replaced6 = {
        let mut r = candidate_record.clone();
        r.created_at_unix_secs = 6;
        bytes::Bytes::from(serde_json::to_vec(&r).unwrap())
    };
    driver6.set_hook_before(move |method, k| {
        if method == "put_object" && k == hook_key6 {
            driver6_for_hook
                .objects
                .lock()
                .unwrap()
                .insert(k.to_string(), (replaced6.clone(), "\"gen-6b\"".to_string()));
        }
        None
    });
    let res_clear_conf = storage6
        .clear_membership_candidate("test-repo", &digest)
        .await;
    assert_eq!(res_clear_conf.unwrap(), false);
}

#[tokio::test]
async fn test_s3_list_all_repo_blob_memberships_page_concurrent_disappearance_advances_safely() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver.clone(),
    );

    let digest1 =
        Digest::parse("sha256:1111111111111111111111111111111111111111111111111111111111111111")
            .unwrap();
    let digest2 =
        Digest::parse("sha256:2222222222222222222222222222222222222222222222222222222222222222")
            .unwrap();
    let canonical = CanonicalRepoName::parse("test-repo").unwrap();
    let key1 =
        crate::storage::repo_membership::canonical_repo_membership_relpath(&canonical, &digest1);
    let key2 =
        crate::storage::repo_membership::canonical_repo_membership_relpath(&canonical, &digest2);

    let rec1 = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        canonical.clone(),
        digest1.clone(),
        None,
    );
    let rec2 = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        canonical.clone(),
        digest2.clone(),
        None,
    );

    driver.objects.lock().unwrap().insert(
        key1.clone(),
        (
            bytes::Bytes::from(serde_json::to_vec(&rec1).unwrap()),
            "etag-rec-1".to_string(),
        ),
    );
    driver.objects.lock().unwrap().insert(
        key2.clone(),
        (
            bytes::Bytes::from(serde_json::to_vec(&rec2).unwrap()),
            "etag-rec-2".to_string(),
        ),
    );

    // Simulate concurrent deletion of key1 during point fetch
    let driver_for_hook = driver.clone();
    let hook_key1 = key1.clone();
    driver.set_hook_before(move |method, k| {
        if method == "get_object" && k == hook_key1 {
            driver_for_hook.objects.lock().unwrap().remove(k);
        }
        None
    });

    // 1. First page with page_limit = 1 (covers key1)
    let res_p1 = storage.list_all_repo_blob_memberships_page(None, 1).await;
    assert!(res_p1.is_ok());
    let (records_p1, next_tok_p1) = res_p1.unwrap();
    // key1 disappeared, so records on this page is empty, but token advances to key1
    assert!(records_p1.is_empty());
    assert_eq!(next_tok_p1, Some(key1.clone()));

    // 2. Second page continuing from key1 with page_limit = 1
    let res_p2 = storage
        .list_all_repo_blob_memberships_page(next_tok_p1.as_deref(), 1)
        .await;
    assert!(res_p2.is_ok());
    let (records_p2, next_tok_p2) = res_p2.unwrap();
    assert_eq!(records_p2.len(), 1);
    assert_eq!(records_p2[0].digest, digest2);
    assert_eq!(next_tok_p2, None);

    // 3. Verify call log proves list_objects_v2 ran and get_object ran on both keys
    let log = driver.get_call_log();
    assert!(
        log.iter().any(|entry| entry.method == "list_objects_v2"),
        "list_objects_v2 must have executed"
    );
    assert!(
        log.iter()
            .any(|entry| entry.method == "get_object" && entry.key == key1),
        "get_object must have attempted to fetch key1"
    );
    assert!(
        log.iter()
            .any(|entry| entry.method == "get_object" && entry.key == key2),
        "get_object must have fetched key2"
    );
}

#[tokio::test]
async fn test_s3_migration_checkpoint_malformed_json_is_corrupt_data() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver.clone(),
    );

    let key = "meta/migration_checkpoint.json";
    let malformed_bytes = b"{{{ malformed migration checkpoint json";
    driver.objects.lock().unwrap().insert(
        key.to_string(),
        (
            bytes::Bytes::from_static(malformed_bytes),
            "etag-cp-1".to_string(),
        ),
    );

    let res = storage.get_migration_checkpoint().await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_parse_err = serde_json::from_slice::<
        crate::storage::repo_membership::MigrationCheckpointRecord,
    >(malformed_bytes)
    .unwrap_err();
    let expected_message = format!("corrupt s3 migration checkpoint: {expected_parse_err}");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_s3_delete_error_classification_uses_typed_metadata() {
    use crate::storage::ConditionalDeleteResult;
    let dummy_msg = "some-arbitrary-unrelated-error-payload-12345";

    // 1. Status 412 -> Ok(ConditionalDeleteResult::PreconditionFailed)
    let res_412 = classify_s3_delete_service_error(412, "OtherCode", dummy_msg.to_string());
    assert_eq!(
        res_412.unwrap(),
        ConditionalDeleteResult::PreconditionFailed {
            current_version: None
        }
    );

    // 2. Code PreconditionFailed at non-412 status -> Ok(ConditionalDeleteResult::PreconditionFailed)
    let res_code_prec =
        classify_s3_delete_service_error(400, "PreconditionFailed", dummy_msg.to_string());
    assert_eq!(
        res_code_prec.unwrap(),
        ConditionalDeleteResult::PreconditionFailed {
            current_version: None
        }
    );

    // 3. Code AtLeastOnePreconditionFailed at non-412 status -> Ok(ConditionalDeleteResult::PreconditionFailed)
    let res_code_atleast = classify_s3_delete_service_error(
        400,
        "AtLeastOnePreconditionFailed",
        dummy_msg.to_string(),
    );
    assert_eq!(
        res_code_atleast.unwrap(),
        ConditionalDeleteResult::PreconditionFailed {
            current_version: None
        }
    );

    // 3b. Code AtLeastOneConditionFailed at non-412 status -> Ok(ConditionalDeleteResult::PreconditionFailed)
    let res_code_atleast_cond =
        classify_s3_delete_service_error(400, "AtLeastOneConditionFailed", dummy_msg.to_string());
    assert_eq!(
        res_code_atleast_cond.unwrap(),
        ConditionalDeleteResult::PreconditionFailed {
            current_version: None
        }
    );

    // 4. Status 404 -> Ok(ConditionalDeleteResult::NotFound)
    let res_404 = classify_s3_delete_service_error(404, "OtherCode", dummy_msg.to_string());
    assert_eq!(res_404.unwrap(), ConditionalDeleteResult::NotFound);

    // 5. Code NoSuchKey at non-404 status -> Ok(ConditionalDeleteResult::NotFound)
    let res_code_no_key = classify_s3_delete_service_error(400, "NoSuchKey", dummy_msg.to_string());
    assert_eq!(res_code_no_key.unwrap(), ConditionalDeleteResult::NotFound);

    // 6. Code NotFound at non-404 status -> Ok(ConditionalDeleteResult::NotFound)
    let res_code_not_found =
        classify_s3_delete_service_error(400, "NotFound", dummy_msg.to_string());
    assert_eq!(
        res_code_not_found.unwrap(),
        ConditionalDeleteResult::NotFound
    );

    // 7. Status 403 -> PermissionDenied
    let res_403 = classify_s3_delete_service_error(403, "OtherCode", dummy_msg.to_string());
    assert!(res_403.is_err());
    let err_403 = res_403.unwrap_err();
    assert_eq!(
        err_403.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err_403.message(), Some(dummy_msg));
    assert_eq!(err_403.to_string(), format!("internal error: {dummy_msg}"));

    // 8. Code AccessDenied at non-403 status -> PermissionDenied
    let res_code_access =
        classify_s3_delete_service_error(400, "AccessDenied", dummy_msg.to_string());
    assert!(res_code_access.is_err());
    let err_code_access = res_code_access.unwrap_err();
    assert_eq!(
        err_code_access.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err_code_access.message(), Some(dummy_msg));
    assert_eq!(
        err_code_access.to_string(),
        format!("internal error: {dummy_msg}")
    );

    // 9. Ordinary status/code -> Backend
    let res_generic = classify_s3_delete_service_error(500, "InternalError", dummy_msg.to_string());
    assert!(res_generic.is_err());
    let err_generic = res_generic.unwrap_err();
    assert_eq!(
        err_generic.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(err_generic.message(), Some(dummy_msg));
    assert_eq!(
        err_generic.to_string(),
        format!("internal error: {dummy_msg}")
    );
}

#[tokio::test]
async fn test_s3_list_repo_blob_memberships_page_malformed_json_is_corrupt_data() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver.clone(),
    );

    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let canonical = CanonicalRepoName::parse("test-repo").unwrap();
    let key =
        crate::storage::repo_membership::canonical_repo_membership_relpath(&canonical, &digest);

    let malformed_bytes = b"{{{ malformed membership record json";
    driver.objects.lock().unwrap().insert(
        key.clone(),
        (
            bytes::Bytes::from_static(malformed_bytes),
            "etag-mem-malformed-1".to_string(),
        ),
    );

    let res = storage
        .list_repo_blob_memberships_page("test-repo", None, 10)
        .await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_parse_err = serde_json::from_slice::<
        crate::storage::repo_membership::RepoBlobMembershipRecord,
    >(malformed_bytes)
    .unwrap_err();
    let expected_message =
        format!("corrupt membership record at key '{key}': {expected_parse_err}");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_s3_list_all_repo_blob_memberships_page_malformed_json_is_corrupt_data() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver.clone(),
    );

    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let canonical = CanonicalRepoName::parse("test-repo").unwrap();
    let key =
        crate::storage::repo_membership::canonical_repo_membership_relpath(&canonical, &digest);

    let malformed_bytes = b"{{{ malformed all memberships record json";
    driver.objects.lock().unwrap().insert(
        key.clone(),
        (
            bytes::Bytes::from_static(malformed_bytes),
            "etag-mem-malformed-2".to_string(),
        ),
    );

    let res = storage.list_all_repo_blob_memberships_page(None, 10).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_parse_err = serde_json::from_slice::<
        crate::storage::repo_membership::RepoBlobMembershipRecord,
    >(malformed_bytes)
    .unwrap_err();
    let expected_message =
        format!("corrupt membership record at key '{key}': {expected_parse_err}");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData)
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_s3_is_storage_empty_repeated_continuation_token_is_backend() {
    struct CyclicPageDriver {
        inner: MockS3Driver,
    }

    #[async_trait]
    impl S3Driver for CyclicPageDriver {
        async fn get_bucket_versioning_state(&self, bucket: &str) -> S3BucketVersioningState {
            self.inner.get_bucket_versioning_state(bucket).await
        }
        async fn create_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
        ) -> Result<String, StorageError> {
            self.inner.create_multipart_upload(bucket, key).await
        }
        async fn upload_part(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
            part_number: i32,
            body: Bytes,
        ) -> Result<String, StorageError> {
            self.inner
                .upload_part(bucket, key, upload_id, part_number, body)
                .await
        }
        async fn complete_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
            parts: Vec<(i32, String)>,
        ) -> Result<(), StorageError> {
            self.inner
                .complete_multipart_upload(bucket, key, upload_id, parts)
                .await
        }
        async fn abort_multipart_upload(
            &self,
            bucket: &str,
            key: &str,
            upload_id: &str,
        ) -> Result<(), StorageError> {
            self.inner
                .abort_multipart_upload(bucket, key, upload_id)
                .await
        }
        async fn list_multipart_uploads(
            &self,
            bucket: &str,
            prefix: &str,
            key_marker: Option<&str>,
            upload_id_marker: Option<&str>,
        ) -> Result<S3MultipartListResult, StorageError> {
            self.inner
                .list_multipart_uploads(bucket, prefix, key_marker, upload_id_marker)
                .await
        }
        async fn get_object(
            &self,
            bucket: &str,
            key: &str,
        ) -> Result<Option<(Bytes, String)>, StorageError> {
            self.inner.get_object(bucket, key).await
        }
        async fn head_object(&self, bucket: &str, key: &str) -> Result<Option<u64>, StorageError> {
            self.inner.head_object(bucket, key).await
        }
        async fn put_object_conditional(
            &self,
            bucket: &str,
            key: &str,
            body: Bytes,
            if_match: Option<String>,
            if_none_match: Option<String>,
        ) -> Result<String, StorageError> {
            self.inner
                .put_object_conditional(bucket, key, body, if_match, if_none_match)
                .await
        }
        async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
            self.inner.delete_object(bucket, key).await
        }
        async fn delete_object_conditional(
            &self,
            bucket: &str,
            key: &str,
            if_match: Option<String>,
        ) -> Result<super::super::ConditionalDeleteResult, StorageError> {
            self.inner
                .delete_object_conditional(bucket, key, if_match)
                .await
        }
        async fn copy_object(
            &self,
            src_bucket: &str,
            src_key: &str,
            dst_bucket: &str,
            dst_key: &str,
        ) -> Result<(), StorageError> {
            self.inner
                .copy_object(src_bucket, src_key, dst_bucket, dst_key)
                .await
        }
        async fn list_objects_v2(
            &self,
            bucket: &str,
            prefix: &str,
        ) -> Result<Vec<S3ObjectSummary>, StorageError> {
            self.inner.list_objects_v2(bucket, prefix).await
        }
        async fn list_objects_v2_page(
            &self,
            _bucket: &str,
            _prefix: &str,
            _continuation_token: Option<&str>,
            _max_keys: i32,
        ) -> Result<S3ObjectsPage, StorageError> {
            Ok(S3ObjectsPage {
                objects: Vec::new(),
                next_continuation_token: Some("cyclic-token-abc".to_string()),
            })
        }
    }

    let driver = Arc::new(CyclicPageDriver {
        inner: MockS3Driver::new(1000),
    });
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver,
    );

    let res = storage.is_storage_empty().await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(
        err.message(),
        Some("repeated S3 continuation token detected during storage readiness check")
    );
    assert_eq!(
        err.to_string(),
        "internal error: repeated S3 continuation token detected during storage readiness check"
    );
}

#[test]
fn test_classify_s3_generic_service_error_uses_typed_metadata() {
    let dummy_msg = "test generic error message";

    // 1. Status 403 -> PermissionDenied
    let err_403 = classify_s3_generic_service_error(403, "OtherCode", dummy_msg.to_string());
    assert_eq!(
        err_403.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err_403.message(), Some(dummy_msg));
    assert_eq!(err_403.to_string(), format!("internal error: {dummy_msg}"));

    // 2. Code AccessDenied at non-403 status -> PermissionDenied
    let err_access_denied =
        classify_s3_generic_service_error(400, "AccessDenied", dummy_msg.to_string());
    assert_eq!(
        err_access_denied.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err_access_denied.message(), Some(dummy_msg));
    assert_eq!(
        err_access_denied.to_string(),
        format!("internal error: {dummy_msg}")
    );

    // 3. Status 500 / other code -> Backend
    let err_500 = classify_s3_generic_service_error(500, "InternalError", dummy_msg.to_string());
    assert_eq!(
        err_500.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(err_500.message(), Some(dummy_msg));
    assert_eq!(err_500.to_string(), format!("internal error: {dummy_msg}"));

    // 4. Status 503 -> Backend
    let err_503 = classify_s3_generic_service_error(503, "SlowDown", dummy_msg.to_string());
    assert_eq!(
        err_503.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(err_503.message(), Some(dummy_msg));
    assert_eq!(err_503.to_string(), format!("internal error: {dummy_msg}"));
}

#[test]
fn test_classify_s3_copy_service_error_uses_typed_metadata() {
    let dummy_msg = "test copy error message";

    // 1. Status 404 -> NotFound
    let err_404 = classify_s3_copy_service_error(404, "OtherCode", dummy_msg.to_string());
    assert!(matches!(err_404, StorageError::NotFound));
    assert_eq!(err_404.internal_kind(), None);
    assert_eq!(err_404.message(), None);
    assert_eq!(err_404.to_string(), "not found");

    // 2. Code NoSuchKey at non-404 status -> NotFound
    let err_no_such_key = classify_s3_copy_service_error(400, "NoSuchKey", dummy_msg.to_string());
    assert!(matches!(err_no_such_key, StorageError::NotFound));
    assert_eq!(err_no_such_key.internal_kind(), None);
    assert_eq!(err_no_such_key.message(), None);
    assert_eq!(err_no_such_key.to_string(), "not found");

    // 3. Code NotFound at non-404 status -> NotFound
    let err_not_found = classify_s3_copy_service_error(400, "NotFound", dummy_msg.to_string());
    assert!(matches!(err_not_found, StorageError::NotFound));
    assert_eq!(err_not_found.internal_kind(), None);
    assert_eq!(err_not_found.message(), None);
    assert_eq!(err_not_found.to_string(), "not found");

    // 4. Status 403 -> PermissionDenied
    let err_403 = classify_s3_copy_service_error(403, "OtherCode", dummy_msg.to_string());
    assert_eq!(
        err_403.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err_403.message(), Some(dummy_msg));
    assert_eq!(err_403.to_string(), format!("internal error: {dummy_msg}"));

    // 5. Code AccessDenied at non-403 status -> PermissionDenied
    let err_access_denied =
        classify_s3_copy_service_error(400, "AccessDenied", dummy_msg.to_string());
    assert_eq!(
        err_access_denied.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err_access_denied.message(), Some(dummy_msg));
    assert_eq!(
        err_access_denied.to_string(),
        format!("internal error: {dummy_msg}")
    );

    // 6. Status 412 -> Backend (copy_object sends no precondition headers)
    let err_412 = classify_s3_copy_service_error(412, "OtherCode", dummy_msg.to_string());
    assert_eq!(
        err_412.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(err_412.message(), Some(dummy_msg));
    assert_eq!(err_412.to_string(), format!("internal error: {dummy_msg}"));

    // 7. Code PreconditionFailed at non-412 status -> Backend (no precondition semantics for copy_object)
    let err_precondition =
        classify_s3_copy_service_error(400, "PreconditionFailed", dummy_msg.to_string());
    assert_eq!(
        err_precondition.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(err_precondition.message(), Some(dummy_msg));
    assert_eq!(
        err_precondition.to_string(),
        format!("internal error: {dummy_msg}")
    );

    // 8. Status 500 / other code -> Backend
    let err_500 = classify_s3_copy_service_error(500, "InternalError", dummy_msg.to_string());
    assert_eq!(
        err_500.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(err_500.message(), Some(dummy_msg));
    assert_eq!(err_500.to_string(), format!("internal error: {dummy_msg}"));
}

#[test]
fn test_map_sdk_err_service_error_uses_typed_metadata_and_full_message() {
    let err_meta = aws_sdk_s3::error::ErrorMetadata::builder()
        .code("AccessDenied")
        .message("User is not authorized")
        .build();
    let get_err = aws_sdk_s3::operation::get_object::GetObjectError::generic(err_meta);
    let raw_http = aws_sdk_s3::config::http::HttpResponse::new(
        403u16.try_into().unwrap(),
        aws_sdk_s3::primitives::SdkBody::empty(),
    );
    let sdk_err = aws_sdk_s3::error::SdkError::service_error(get_err, raw_http);
    let expected_message = sdk_err.to_string();

    let storage_err = map_sdk_err(sdk_err, classify_s3_generic_service_error);
    assert_eq!(
        storage_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::PermissionDenied)
    );
    assert_eq!(storage_err.message(), Some(expected_message.as_str()));
    assert_eq!(
        storage_err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[test]
fn test_map_sdk_err_service_error_404_maps_to_not_found() {
    let raw_http = aws_sdk_s3::config::http::HttpResponse::new(
        404u16.try_into().unwrap(),
        aws_sdk_s3::primitives::SdkBody::empty(),
    );
    let err_meta = aws_sdk_s3::error::ErrorMetadata::builder()
        .code("NoSuchKey")
        .message("The specified key does not exist.")
        .build();
    let copy_err = aws_sdk_s3::operation::copy_object::CopyObjectError::generic(err_meta);
    let sdk_err = aws_sdk_s3::error::SdkError::service_error(copy_err, raw_http);

    let storage_err = map_sdk_err(sdk_err, classify_s3_copy_service_error);
    assert!(matches!(storage_err, StorageError::NotFound));
    assert_eq!(storage_err.internal_kind(), None);
    assert_eq!(storage_err.message(), None);
    assert_eq!(storage_err.to_string(), "not found");
}

#[test]
fn test_map_sdk_err_service_error_500_maps_to_backend_and_preserves_full_message() {
    let raw_http = aws_sdk_s3::config::http::HttpResponse::new(
        500u16.try_into().unwrap(),
        aws_sdk_s3::primitives::SdkBody::empty(),
    );
    let err_meta = aws_sdk_s3::error::ErrorMetadata::builder()
        .code("InternalError")
        .message("We encountered an internal error. Please try again.")
        .build();
    let get_err = aws_sdk_s3::operation::get_object::GetObjectError::generic(err_meta);
    let sdk_err = aws_sdk_s3::error::SdkError::service_error(get_err, raw_http);
    let expected_message = sdk_err.to_string();

    let storage_err = map_sdk_err(sdk_err, classify_s3_generic_service_error);
    assert_eq!(
        storage_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(storage_err.message(), Some(expected_message.as_str()));
    assert_eq!(
        storage_err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[test]
fn test_map_sdk_err_transport_error_maps_to_backend_and_preserves_message() {
    let custom_err = "simulated network timeout during send";
    let sdk_err: aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError> =
        aws_sdk_s3::error::SdkError::construction_failure(custom_err);
    let expected_message = sdk_err.to_string();

    let storage_err = map_sdk_err(sdk_err, classify_s3_generic_service_error);
    assert_eq!(
        storage_err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert_eq!(storage_err.message(), Some(expected_message.as_str()));
    assert_eq!(
        storage_err.to_string(),
        format!("internal error: {expected_message}")
    );
}

// ==========================================
// STORAGE-PARITY: unconditional object-deletion failures must surface
// (`S3Driver::delete_object` classification + storage-boundary propagation).
// The filesystem backend propagates deletion failures (`delete_manifest`
// unlink errors, `delete_tag` errors); the S3 backend must not convert a
// failed DeleteObject into a false deletion success. Absent-object deletion
// stays idempotent success (native S3 answers 204; some S3-compatible
// backends answer 404/NoSuchKey).
// ==========================================

#[test]
fn test_classify_s3_unconditional_delete_error_taxonomy() {
    // Absent object: idempotent success in every spelled form.
    assert!(classify_s3_unconditional_delete_error(404, "", "gone".to_string()).is_ok());
    assert!(classify_s3_unconditional_delete_error(200, "NoSuchKey", "gone".to_string()).is_ok());
    assert!(classify_s3_unconditional_delete_error(200, "NotFound", "gone".to_string()).is_ok());

    // Permission failures classify as PermissionDenied.
    for (status, code) in [(403u16, ""), (200u16, "AccessDenied")] {
        let err = classify_s3_unconditional_delete_error(status, code, "denied".to_string())
            .expect_err("permission failure must surface");
        assert_eq!(
            err.internal_kind(),
            Some(crate::storage::StorageErrorKind::PermissionDenied),
            "({status}, {code}) must classify as PermissionDenied"
        );
    }

    // Everything else (throttling, internal errors, unexpected preconditions)
    // is a backend failure — never silent success.
    for (status, code) in [
        (500u16, ""),
        (503u16, "SlowDown"),
        (412u16, "PreconditionFailed"),
    ] {
        let err = classify_s3_unconditional_delete_error(status, code, "boom".to_string())
            .expect_err("service failure must surface");
        assert_eq!(
            err.internal_kind(),
            Some(crate::storage::StorageErrorKind::Backend),
            "({status}, {code}) must classify as Backend"
        );
    }
}

fn parity_manifest_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "size": 2,
            "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "size": 3,
            "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        }]
    }))
    .unwrap()
}

// A failed DeleteObject on the manifest's primary object must propagate out of
// `delete_manifest` as an error, leaving the manifest present — never a false
// deletion success (the lifecycle advances its journal and decrements
// BlobRefIndex accounting only on success, exactly as on the filesystem
// backend).
#[tokio::test]
async fn test_s3_delete_manifest_propagates_object_delete_failure() {
    let (storage, driver) = create_mock_storage();
    let hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let digest = Digest::parse(&format!("sha256:{hex}")).unwrap();
    let manifest_key = format!("repos/parity-repo/manifests/{hex}");
    driver.objects.lock().unwrap().insert(
        manifest_key.clone(),
        (Bytes::from(parity_manifest_json()), "\"m1\"".to_string()),
    );

    // Fail ONLY the DeleteObject of the manifest key; reads stay healthy.
    let failing_key = manifest_key.clone();
    driver.set_hook_before(move |method, key| {
        if method == "delete_object" && key == failing_key {
            Some(StorageError::backend("injected DeleteObject failure"))
        } else {
            None
        }
    });

    let err = storage
        .delete_manifest("parity-repo", &digest)
        .await
        .expect_err("failed object deletion must not report deletion success");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend),
        "propagates the backend classification, got {err:?}"
    );
    assert!(
        driver.objects.lock().unwrap().contains_key(&manifest_key),
        "manifest object survives the failed deletion"
    );

    // Negative control: once the fault clears, the same deletion succeeds and
    // the object is gone.
    driver.clear_hooks();
    storage
        .delete_manifest("parity-repo", &digest)
        .await
        .expect("deletion succeeds without the injected fault");
    assert!(
        !driver.objects.lock().unwrap().contains_key(&manifest_key),
        "manifest object removed on success"
    );
}

// `delete_tag` parity (Phase 3 converged): a failed DeleteObject surfaces;
// deleting an ABSENT tag is Err(NotFound) on BOTH backends (the retired
// S3-specific path returned idempotent success; production callers are
// best-effort journal recovery that ignores the result).
#[tokio::test]
async fn test_s3_delete_tag_propagates_failure_and_absent_is_not_found() {
    let (storage, driver) = create_mock_storage();
    let tag_key = "repos/parity-repo/tags/v1".to_string();
    driver.objects.lock().unwrap().insert(
        tag_key.clone(),
        (
            Bytes::from_static(
                b"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            ),
            "\"t1\"".to_string(),
        ),
    );

    let failing_key = tag_key.clone();
    driver.set_hook_before(move |method, key| {
        if method == "delete_object" && key == failing_key {
            Some(StorageError::backend("injected DeleteObject failure"))
        } else {
            None
        }
    });

    let err = storage
        .delete_tag("parity-repo", "v1")
        .await
        .expect_err("failed tag deletion must not report success");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert!(
        driver.objects.lock().unwrap().contains_key(&tag_key),
        "tag object survives the failed deletion"
    );

    driver.clear_hooks();
    storage
        .delete_tag("parity-repo", "v1")
        .await
        .expect("tag deletion succeeds without the fault");
    assert!(!driver.objects.lock().unwrap().contains_key(&tag_key));

    // Absent tag: Err(NotFound) — the converged cross-backend contract.
    let err_absent = storage
        .delete_tag("parity-repo", "v1")
        .await
        .expect_err("deleting an absent tag reports NotFound on both backends");
    assert!(matches!(err_absent, StorageError::NotFound));
}

// ==========================================
// STORAGE-PARITY-CLOSURE Part A: S3-LISTING-FAIL-CLOSED
// Shared `list_tags_page` contract (established from the contained
// filesystem implementation and its tests): valid tags listed sorted with
// strictly-after tokens; empty/malformed digest TEXT omitted; structural
// non-tag entries skipped; objects vanished between listing and read
// skipped; read failures propagate; INVALID UTF-8 in a registry-owned tag
// payload FAILS CLOSED (it must not silently disappear from a listing that
// feeds BlobRefIndex sync/rebuild and POLICY-B delete-safety proofs).
// ==========================================

#[tokio::test]
async fn test_s3_list_tags_page_invalid_utf8_payload_fails_closed() {
    let (storage, driver) = create_mock_storage();
    let valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    {
        let mut objs = driver.objects.lock().unwrap();
        objs.insert(
            "repos/parity-repo/tags/good".to_string(),
            (
                Bytes::from(format!("sha256:{valid_hex}\n")),
                "\"t1\"".to_string(),
            ),
        );
        objs.insert(
            "repos/parity-repo/tags/broken".to_string(),
            (
                Bytes::from_static(&[0xff, 0xfe, 0xfd]),
                "\"t2\"".to_string(),
            ),
        );
    }

    let err = storage
        .list_tags_page("parity-repo", None, 10)
        .await
        .expect_err("invalid UTF-8 tag payload must fail the listing closed");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::CorruptData),
        "corrupt registry-owned tag payload classifies as CorruptData, got {err:?}"
    );

    // Once the corrupt object is repaired, the listing succeeds again.
    driver.objects.lock().unwrap().insert(
        "repos/parity-repo/tags/broken".to_string(),
        (
            Bytes::from(format!("sha256:{valid_hex}\n")),
            "\"t3\"".to_string(),
        ),
    );
    let (page, next) = storage
        .list_tags_page("parity-repo", None, 10)
        .await
        .unwrap();
    assert_eq!(
        page.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["broken", "good"]
    );
    assert!(next.is_none());
}

#[tokio::test]
async fn test_s3_list_tags_page_shared_omission_and_pagination_contract() {
    let (storage, driver) = create_mock_storage();
    let valid_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    {
        let mut objs = driver.objects.lock().unwrap();
        // Valid tags (sorted order: a1, b2, c3).
        for name in ["a1", "b2", "c3"] {
            objs.insert(
                format!("repos/parity-repo/tags/{name}"),
                (
                    Bytes::from(format!("sha256:{valid_hex}\n")),
                    "\"e\"".to_string(),
                ),
            );
        }
        // Malformed digest TEXT (valid UTF-8): omitted on both backends.
        objs.insert(
            "repos/parity-repo/tags/malformed".to_string(),
            (Bytes::from_static(b"not-a-digest"), "\"e\"".to_string()),
        );
        // Empty payload: omitted on both backends.
        objs.insert(
            "repos/parity-repo/tags/empty".to_string(),
            (Bytes::from_static(b""), "\"e\"".to_string()),
        );
        // Structural non-tag entry (nested key beneath the prefix): skipped,
        // the analogue of the filesystem listing skipping subdirectories.
        objs.insert(
            "repos/parity-repo/tags/nested/entry".to_string(),
            (
                Bytes::from(format!("sha256:{valid_hex}\n")),
                "\"e\"".to_string(),
            ),
        );
        // Unrelated out-of-namespace object: never part of the listing.
        objs.insert(
            "unrelated/top-level-object".to_string(),
            (Bytes::from_static(b"noise"), "\"e\"".to_string()),
        );
    }

    // Page 1: strictly-after token semantics over the VALID tags only.
    let (page1, tok1) = storage
        .list_tags_page("parity-repo", None, 2)
        .await
        .unwrap();
    assert_eq!(
        page1.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["a1", "b2"]
    );
    let tok1 = tok1.expect("continuation token for remaining tag");
    assert_eq!(tok1, "b2");

    let (page2, tok2) = storage
        .list_tags_page("parity-repo", Some(&tok1), 2)
        .await
        .unwrap();
    assert_eq!(
        page2.iter().map(|(t, _)| t.as_str()).collect::<Vec<_>>(),
        vec!["c3"]
    );
    assert!(tok2.is_none(), "no token past the final page");

    // Absent repository: empty page, no token (parity with FS absent dir).
    let (empty_page, empty_tok) = storage
        .list_tags_page("absent-repo", None, 5)
        .await
        .unwrap();
    assert!(empty_page.is_empty());
    assert!(empty_tok.is_none());
}

// ==========================================
// STORAGE-PARITY-CLOSURE Part B: S3-MEMBERSHIP-UNLINK-PARITY
// Shared `unlink_repo_blob` contract (established from the FS
// implementation and the ledger consumer that gates reverse-index removal
// on the returned bool): present+removed -> Ok(true); absent -> Ok(false);
// repeated unlink -> true then false; deletion failure -> Err; and a record
// replaced inside the unlink window must never be deleted under the stale
// observation (ETag-conditional removal).
// ==========================================

fn parity_membership_record(
    repo: &str,
    digest: &Digest,
) -> crate::storage::repo_membership::RepoBlobMembershipRecord {
    crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
        crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap(),
        digest.clone(),
        Some("parity-upload".to_string()),
    )
}

#[tokio::test]
async fn test_s3_unlink_repo_blob_contract_present_absent_repeat() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
    let (storage, _driver) = create_mock_storage();
    let digest =
        Digest::parse("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap();

    // Absent record: Ok(false) — FS parity.
    assert!(
        !storage
            .unlink_repo_blob("parity/repo", &digest)
            .await
            .unwrap()
    );

    // Present record: removed -> Ok(true); repeat -> Ok(false).
    storage
        .link_repo_blob(&parity_membership_record("parity/repo", &digest))
        .await
        .unwrap();
    assert!(
        storage
            .get_repo_blob_membership("parity/repo", &digest)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .unlink_repo_blob("parity/repo", &digest)
            .await
            .unwrap()
    );
    assert!(
        storage
            .get_repo_blob_membership("parity/repo", &digest)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        !storage
            .unlink_repo_blob("parity/repo", &digest)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_s3_unlink_repo_blob_failure_propagates_and_replacement_not_deleted() {
    use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
    let (storage, driver) = create_mock_storage();
    let digest =
        Digest::parse("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap();
    storage
        .link_repo_blob(&parity_membership_record("parity/repo", &digest))
        .await
        .unwrap();
    let record_key = {
        let objs = driver.objects.lock().unwrap();
        objs.keys()
            .find(|k| k.contains("bbbb"))
            .expect("membership record key present")
            .clone()
    };

    // 1. Deletion failure propagates as Err (never a false `true`).
    let failing_key = record_key.clone();
    driver.set_hook_before(move |method, key| {
        if method == "delete_object_if_match" && key == failing_key {
            Some(StorageError::backend("injected membership delete failure"))
        } else {
            None
        }
    });
    let err = storage
        .unlink_repo_blob("parity/repo", &digest)
        .await
        .expect_err("failed membership deletion must surface");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Backend)
    );
    assert!(
        driver.objects.lock().unwrap().contains_key(&record_key),
        "record survives the failed deletion"
    );
    driver.clear_hooks();

    // 2. Deterministic replacement race: the record is REPLACED (new content,
    //    new ETag) inside the unlink window, between the observation read and
    //    the conditional delete. The stale observation must not delete the
    //    replacement: the unlink fails closed with a conflict and the
    //    replacement survives byte-identically. (Within the supported
    //    coordination model — every membership mutation serialized by the
    //    consistency coordinator under the exclusive deployment writer lock —
    //    this interleaving cannot occur; this proves the mechanical guarantee
    //    anyway.) Negative control: a naive unconditional delete would have
    //    removed the replacement here.
    let race_key = record_key.clone();
    let race_driver = driver.clone();
    driver.set_hook_before(move |method, key| {
        if method == "delete_object_if_match" && key == race_key {
            race_driver.objects.lock().unwrap().insert(
                race_key.clone(),
                (
                    Bytes::from_static(b"{\"replacement\":\"generation\"}"),
                    "\"replaced-etag\"".to_string(),
                ),
            );
        }
        None
    });
    let err = storage
        .unlink_repo_blob("parity/repo", &digest)
        .await
        .expect_err("replacement inside the unlink window must fail closed");
    assert_eq!(
        err.internal_kind(),
        Some(crate::storage::StorageErrorKind::Conflict),
        "stale-observation unlink classifies as Conflict, got {err:?}"
    );
    assert_eq!(
        driver.objects.lock().unwrap().get(&record_key).unwrap().0,
        Bytes::from_static(b"{\"replacement\":\"generation\"}"),
        "the replacement record is NOT deleted under the stale observation"
    );
    driver.clear_hooks();
}
