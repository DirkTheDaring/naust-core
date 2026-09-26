use super::*;

#[test]
fn test_storage_error_kind_display_formatting() {
    assert_eq!(StorageErrorKind::Io.to_string(), "io");
    assert_eq!(StorageErrorKind::Backend.to_string(), "backend");
    assert_eq!(
        StorageErrorKind::PermissionDenied.to_string(),
        "permission_denied"
    );
    assert_eq!(StorageErrorKind::CorruptData.to_string(), "corrupt_data");
    assert_eq!(StorageErrorKind::Serialization.to_string(), "serialization");
    assert_eq!(StorageErrorKind::Configuration.to_string(), "configuration");
    assert_eq!(StorageErrorKind::Conflict.to_string(), "conflict");
    assert_eq!(
        StorageErrorKind::InternalInvariant.to_string(),
        "internal_invariant"
    );
}

#[test]
fn test_storage_error_internal_display_preserves_message() {
    let err = StorageError::internal(StorageErrorKind::Io, "disk disconnected");
    assert_eq!(err.to_string(), "internal error: disk disconnected");

    let err2 = StorageError::backend("connection reset by peer");
    assert_eq!(err2.to_string(), "internal error: connection reset by peer");
}

#[test]
fn test_storage_error_constructors_and_accessors() {
    let io_err = StorageError::io("read failed");
    assert_eq!(io_err.internal_kind(), Some(StorageErrorKind::Io));
    assert_eq!(io_err.message(), Some("read failed"));

    let backend_err = StorageError::backend("503 slow down");
    assert_eq!(backend_err.internal_kind(), Some(StorageErrorKind::Backend));
    assert_eq!(backend_err.message(), Some("503 slow down"));

    let perm_err = StorageError::permission_denied("access denied 403");
    assert_eq!(
        perm_err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    assert_eq!(perm_err.message(), Some("access denied 403"));

    let corrupt_err = StorageError::corrupt_data("bad json");
    assert_eq!(
        corrupt_err.internal_kind(),
        Some(StorageErrorKind::CorruptData)
    );
    assert_eq!(corrupt_err.message(), Some("bad json"));

    let ser_err = StorageError::serialization("to_vec failed");
    assert_eq!(
        ser_err.internal_kind(),
        Some(StorageErrorKind::Serialization)
    );
    assert_eq!(ser_err.message(), Some("to_vec failed"));

    let config_err = StorageError::configuration("missing S3 bucket");
    assert_eq!(
        config_err.internal_kind(),
        Some(StorageErrorKind::Configuration)
    );
    assert_eq!(config_err.message(), Some("missing S3 bucket"));

    let conflict_err = StorageError::conflict("etag mismatch");
    assert_eq!(
        conflict_err.internal_kind(),
        Some(StorageErrorKind::Conflict)
    );
    assert_eq!(conflict_err.message(), Some("etag mismatch"));

    let inv_err = StorageError::internal_invariant("state transition unreachable");
    assert_eq!(
        inv_err.internal_kind(),
        Some(StorageErrorKind::InternalInvariant)
    );
    assert_eq!(inv_err.message(), Some("state transition unreachable"));
}

#[test]
fn test_dedicated_storage_error_variants_have_no_internal_kind() {
    let variants = vec![
        StorageError::NotFound,
        StorageError::DigestMismatch,
        StorageError::Unsupported,
        StorageError::TooLarge,
        StorageError::InsufficientStorage,
        StorageError::TagAlreadyExists,
        StorageError::ExclusiveWriterLocked("held by node-1".to_string()),
        StorageError::InvalidRepoName("bad/name".to_string()),
        StorageError::MigrationRequired("run backfill".to_string()),
    ];

    for v in variants {
        assert_eq!(v.internal_kind(), None);
    }
    assert_eq!(StorageError::NotFound.message(), None);
    assert_eq!(
        StorageError::ExclusiveWriterLocked("held by node-1".to_string()).message(),
        Some("held by node-1")
    );
}

#[test]
fn test_storage_error_kind_serde_round_trip() {
    let kinds = [
        StorageErrorKind::Io,
        StorageErrorKind::Backend,
        StorageErrorKind::PermissionDenied,
        StorageErrorKind::CorruptData,
        StorageErrorKind::Serialization,
        StorageErrorKind::Configuration,
        StorageErrorKind::Conflict,
        StorageErrorKind::InternalInvariant,
    ];

    for kind in kinds {
        let serialized = serde_json::to_string(&kind).expect("serialization succeeds");
        let deserialized: StorageErrorKind =
            serde_json::from_str(&serialized).expect("deserialization succeeds");
        assert_eq!(kind, deserialized);
    }
}

#[test]
fn test_storage_error_clone_and_debug() {
    let err = StorageError::internal(StorageErrorKind::Backend, "mock failure");
    let cloned = err.clone();
    assert_eq!(cloned.internal_kind(), Some(StorageErrorKind::Backend));
    assert_eq!(cloned.message(), Some("mock failure"));
    assert_eq!(err.internal_kind(), Some(StorageErrorKind::Backend));
    assert_eq!(err.message(), Some("mock failure"));
}

#[test]
fn test_production_boundary_s3_get_head_classifier_404_not_found() {
    let err1 = crate::storage::s3::classify_s3_get_head_service_error(
        404,
        "UnrelatedCode",
        "arbitrary-get-head-message-alpha".to_string(),
    );
    assert!(matches!(err1, StorageError::NotFound));
    assert_eq!(err1.internal_kind(), None);
    assert_eq!(err1.message(), None);
    assert_eq!(err1.to_string(), "not found");

    let err2 = crate::storage::s3::classify_s3_get_head_service_error(
        400,
        "NoSuchKey",
        "arbitrary-get-head-message-beta".to_string(),
    );
    assert!(matches!(err2, StorageError::NotFound));
    assert_eq!(err2.internal_kind(), None);
    assert_eq!(err2.message(), None);
    assert_eq!(err2.to_string(), "not found");

    let err3 = crate::storage::s3::classify_s3_get_head_service_error(
        400,
        "NotFound",
        "arbitrary-get-head-message-gamma".to_string(),
    );
    assert!(matches!(err3, StorageError::NotFound));
    assert_eq!(err3.internal_kind(), None);
    assert_eq!(err3.message(), None);
    assert_eq!(err3.to_string(), "not found");
}

#[test]
fn test_production_boundary_s3_get_head_classifier_403_access_denied() {
    let msg1 = "arbitrary-get-permission-msg-one";
    let err1 = crate::storage::s3::classify_s3_get_head_service_error(
        403,
        "UnrelatedCode",
        msg1.to_string(),
    );
    assert_eq!(
        err1.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err1.message(), Some(msg1));
    assert_eq!(err1.to_string(), format!("internal error: {msg1}"));

    let msg2 = "arbitrary-get-permission-msg-two";
    let err2 = crate::storage::s3::classify_s3_get_head_service_error(
        400,
        "AccessDenied",
        msg2.to_string(),
    );
    assert_eq!(
        err2.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err2.message(), Some(msg2));
    assert_eq!(err2.to_string(), format!("internal error: {msg2}"));
}

#[test]
fn test_production_boundary_s3_put_classifier_404_backend_and_412_conflict() {
    let msg_backend = "arbitrary-put-backend-fallback-message";
    let err_backend = crate::storage::s3::classify_s3_put_service_error(
        404,
        "NoSuchBucket",
        msg_backend.to_string(),
    );
    assert_eq!(err_backend.internal_kind(), Some(StorageErrorKind::Backend));
    assert_eq!(err_backend.message(), Some(msg_backend));
    assert_eq!(
        err_backend.to_string(),
        format!("internal error: {msg_backend}")
    );

    let msg_conf1 = "arbitrary-put-conflict-msg-alpha";
    let err_conf1 = crate::storage::s3::classify_s3_put_service_error(
        412,
        "UnrelatedCode",
        msg_conf1.to_string(),
    );
    assert_eq!(err_conf1.internal_kind(), Some(StorageErrorKind::Conflict));
    assert_eq!(err_conf1.message(), Some(msg_conf1));
    assert_eq!(
        err_conf1.to_string(),
        format!("internal error: {msg_conf1}")
    );

    let msg_conf2 = "arbitrary-put-conflict-msg-beta";
    let err_conf2 = crate::storage::s3::classify_s3_put_service_error(
        400,
        "PreconditionFailed",
        msg_conf2.to_string(),
    );
    assert_eq!(err_conf2.internal_kind(), Some(StorageErrorKind::Conflict));
    assert_eq!(err_conf2.message(), Some(msg_conf2));
    assert_eq!(
        err_conf2.to_string(),
        format!("internal error: {msg_conf2}")
    );

    let msg_conf3 = "arbitrary-put-conflict-msg-gamma";
    let err_conf3 = crate::storage::s3::classify_s3_put_service_error(
        400,
        "AtLeastOnePreconditionFailed",
        msg_conf3.to_string(),
    );
    assert_eq!(err_conf3.internal_kind(), Some(StorageErrorKind::Conflict));
    assert_eq!(err_conf3.message(), Some(msg_conf3));
    assert_eq!(
        err_conf3.to_string(),
        format!("internal error: {msg_conf3}")
    );

    let msg_conf4 = "arbitrary-put-conflict-msg-delta";
    let err_conf4 = crate::storage::s3::classify_s3_put_service_error(
        400,
        "AtLeastOneConditionFailed",
        msg_conf4.to_string(),
    );
    assert_eq!(err_conf4.internal_kind(), Some(StorageErrorKind::Conflict));
    assert_eq!(err_conf4.message(), Some(msg_conf4));
    assert_eq!(
        err_conf4.to_string(),
        format!("internal error: {msg_conf4}")
    );
}

#[test]
fn test_production_boundary_s3_put_classifier_403_access_denied() {
    let msg1 = "arbitrary-put-permission-msg-one";
    let err1 =
        crate::storage::s3::classify_s3_put_service_error(403, "UnrelatedCode", msg1.to_string());
    assert_eq!(
        err1.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err1.message(), Some(msg1));
    assert_eq!(err1.to_string(), format!("internal error: {msg1}"));

    let msg2 = "arbitrary-put-permission-msg-two";
    let err2 =
        crate::storage::s3::classify_s3_put_service_error(400, "AccessDenied", msg2.to_string());
    assert_eq!(
        err2.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
    assert_eq!(err2.message(), Some(msg2));
    assert_eq!(err2.to_string(), format!("internal error: {msg2}"));
}

#[test]
fn test_production_boundary_s3_classifier_500_and_503_backend() {
    let err_500 = crate::storage::s3::classify_s3_service_error(
        500,
        "InternalError",
        "We encountered an internal error. Please try again.".to_string(),
    );
    assert_eq!(err_500.internal_kind(), Some(StorageErrorKind::Backend));
    assert_eq!(
        err_500.message(),
        Some("We encountered an internal error. Please try again.")
    );
    assert_eq!(
        err_500.to_string(),
        "internal error: We encountered an internal error. Please try again."
    );

    let err_503 = crate::storage::s3::classify_s3_service_error(
        503,
        "SlowDown",
        "Please reduce your request rate.".to_string(),
    );
    assert_eq!(err_503.internal_kind(), Some(StorageErrorKind::Backend));
    assert_eq!(err_503.message(), Some("Please reduce your request rate."));
    assert_eq!(
        err_503.to_string(),
        "internal error: Please reduce your request rate."
    );
}

#[tokio::test]
async fn test_real_filesystem_io_boundary_on_uncreatable_root() {
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("existing_file");
    std::fs::write(&file_path, b"not a directory").unwrap();
    let invalid_root = file_path.join("sub_dir");

    let source_error = std::fs::create_dir_all(&invalid_root).unwrap_err();
    let expected_message = format!(
        "failed to create storage dir {}: {source_error}",
        invalid_root.display()
    );

    let res = crate::storage::fs::FsStorage::try_new(invalid_root.clone(), 1024 * 1024);
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::Io),
        "Real OS filesystem creation failure must be classified as StorageErrorKind::Io"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[tokio::test]
async fn test_real_filesystem_corrupt_manifest_json_boundary() {
    use crate::storage::Storage;
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = crate::storage::fs::FsStorage::new(temp.path().to_path_buf(), 100_000_000);

    let repo = "corrupt-manifest-repo";
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();

    let manifest_path = temp
        .path()
        .join("repos")
        .join(repo)
        .join("manifests")
        .join(digest.hex());

    tokio::fs::create_dir_all(manifest_path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&manifest_path, b"not valid json {{{")
        .await
        .unwrap();

    let res = Storage::get_manifest(&storage, repo, &digest).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::CorruptData),
        "Corrupted on-disk manifest JSON must be classified as StorageErrorKind::CorruptData"
    );
}

#[tokio::test]
async fn test_real_filesystem_corrupt_persisted_membership_json_boundary() {
    use crate::registry::CanonicalRepoName;
    use crate::storage::repo_membership::{
        RepoBlobMembershipRecord, RepositoryBlobMembershipStorage,
        canonical_repo_membership_relpath,
    };
    let temp = tempfile::tempdir().expect("tempdir");
    let storage = crate::storage::fs::FsStorage::new(temp.path().to_path_buf(), 100_000_000);

    let repo = "corrupt-membership-repo";
    let canonical = CanonicalRepoName::parse(repo).unwrap();
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();

    let malformed_bytes = b"{ malformed json [[[ ";
    let source_error =
        serde_json::from_slice::<RepoBlobMembershipRecord>(malformed_bytes).unwrap_err();
    let expected_message = format!("corrupt membership record: {source_error}");

    // Write malformed JSON directly to the exact canonical repository membership path on disk
    let record_path = temp
        .path()
        .join(canonical_repo_membership_relpath(&canonical, &digest));
    tokio::fs::create_dir_all(record_path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&record_path, malformed_bytes)
        .await
        .unwrap();

    // Invoking the real storage adapter set_membership_candidate method
    let res = storage
        .set_membership_candidate(repo, &digest, 1700000000)
        .await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::CorruptData),
        "Corrupted on-disk membership JSON must be classified as StorageErrorKind::CorruptData"
    );
    assert_eq!(err.message(), Some(expected_message.as_str()));
    assert_eq!(
        err.to_string(),
        format!("internal error: {expected_message}")
    );
}

#[test]
fn test_storage_error_serialization_constructor_and_infallibility_contract() {
    // Contract: Production domain entities (RepoBlobMembershipRecord, MigrationCheckpointRecord, UploadSessionDoc)
    // contain primitive string and numeric fields and are infallible under serde_json::to_vec except for heap exhaustion.
    // This test verifies the StorageError::serialization constructor mapping and display formatting.
    let err = StorageError::serialization("recursion depth limit exceeded");
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::Serialization),
        "Serialization constructor must classify as StorageErrorKind::Serialization"
    );
    assert_eq!(
        err.to_string(),
        "internal error: recursion depth limit exceeded"
    );
}

#[tokio::test]
async fn test_production_boundary_conflict_missing_conditional_version() {
    use crate::storage::GcStorage;
    use crate::storage::mutation_authority::RuntimeMutationAuthority;
    use crate::storage::s3::S3Storage;
    use crate::storage::s3::tests::MockS3Driver;

    // --- Part 1: Filesystem GC Permit & Conditional Delete Verification ---
    let temp = tempfile::tempdir().expect("tempdir");
    let fs_storage = Arc::new(crate::storage::fs::FsStorage::new(
        temp.path().to_path_buf(),
        100_000_000,
    ));
    let mut fs_authority = RuntimeMutationAuthority::acquire(fs_storage.clone(), "test-fs-permit")
        .await
        .expect("authority");
    let fs_permit = fs_authority.gc_mutation_permit();
    let digest =
        Digest::parse("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    let dummy_version = BlobObjectVersion("v1".to_string());

    // 1a. Missing conditional version on FS produces typed Conflict
    let expected_fs_conflict_msg =
        "conditional delete on filesystem storage requires expected version";
    let res_fs_conflict =
        GcStorage::delete_blob_conditional(&*fs_storage, &fs_permit, &digest, None).await;
    assert!(res_fs_conflict.is_err());
    let err_fs_conflict = res_fs_conflict.unwrap_err();
    assert_eq!(
        err_fs_conflict.internal_kind(),
        Some(StorageErrorKind::Conflict),
        "Missing required version precondition on FS must classify as StorageErrorKind::Conflict"
    );
    assert_eq!(err_fs_conflict.message(), Some(expected_fs_conflict_msg));
    assert_eq!(
        err_fs_conflict.to_string(),
        format!("internal error: {expected_fs_conflict_msg}")
    );

    // 1b. Invalidate FS authority to make fs_permit inactive
    let err_fs_d = {
        let guard = fs_authority.set_test_inactive_guard();
        assert!(!fs_permit.is_valid());

        // Inactive permit on quarantine_blob (FS)
        let res_fs_q =
            GcStorage::quarantine_blob(&*fs_storage, &fs_permit, &digest, &dummy_version).await;
        assert!(res_fs_q.is_err());
        let err_fs_q = res_fs_q.unwrap_err();
        assert_eq!(
            err_fs_q.internal_kind(),
            Some(StorageErrorKind::PermissionDenied),
            "Inactive permit on quarantine_blob must classify as PermissionDenied"
        );
        assert_eq!(
            err_fs_q.message(),
            Some("invalid or inactive GC mutation permit")
        );
        assert_eq!(
            err_fs_q.to_string(),
            "internal error: invalid or inactive GC mutation permit"
        );

        // Inactive permit on restore_quarantined_blob (FS)
        let res_fs_r = GcStorage::restore_quarantined_blob(&*fs_storage, &fs_permit, &digest).await;
        assert!(res_fs_r.is_err());
        let err_fs_r = res_fs_r.unwrap_err();
        assert_eq!(
            err_fs_r.internal_kind(),
            Some(StorageErrorKind::PermissionDenied),
            "Inactive permit on restore_quarantined_blob must classify as PermissionDenied"
        );
        assert_eq!(
            err_fs_r.message(),
            Some("invalid or inactive GC mutation permit")
        );
        assert_eq!(
            err_fs_r.to_string(),
            "internal error: invalid or inactive GC mutation permit"
        );

        // Inactive permit on delete_blob_conditional (FS)
        let res_fs_d = GcStorage::delete_blob_conditional(
            &*fs_storage,
            &fs_permit,
            &digest,
            Some(&dummy_version),
        )
        .await;
        assert!(res_fs_d.is_err());
        let err_fs_d = res_fs_d.unwrap_err();
        assert_eq!(
            err_fs_d.internal_kind(),
            Some(StorageErrorKind::PermissionDenied),
            "Inactive permit on delete_blob_conditional must classify as PermissionDenied"
        );
        assert_eq!(
            err_fs_d.message(),
            Some("invalid or inactive GC mutation permit")
        );
        assert_eq!(
            err_fs_d.to_string(),
            "internal error: invalid or inactive GC mutation permit"
        );

        drop(guard);
        err_fs_d
    };

    // Distinguish FS conflict vs permission_denied
    assert_ne!(err_fs_conflict.internal_kind(), err_fs_d.internal_kind());

    // Restore validity, drop permit, and explicitly release authority with backend lock cleanup
    assert!(fs_permit.is_valid());
    drop(fs_permit);
    assert!(fs_authority.release().await.is_ok());
    assert!(
        crate::storage::mutation_authority::inspect_deployment_writer_lock(fs_storage.as_ref())
            .await
            .expect("inspect")
            .is_none(),
        "FS deployment lock must be deleted on backend after explicit release"
    );

    // --- Part 2: S3 GC Permit & Conditional Delete Verification ---
    let driver = Arc::new(MockS3Driver::new(1000));
    let s3_storage = Arc::new(S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver.clone(),
    ));
    let mut s3_authority = RuntimeMutationAuthority::acquire(s3_storage.clone(), "test-s3-permit")
        .await
        .expect("authority");
    let s3_permit = s3_authority.gc_mutation_permit();

    // 2a. Missing conditional version on S3 produces typed Conflict
    let expected_s3_conflict_msg = "S3 conditional delete requires an explicit object version/ETag; unconditional delete is forbidden in GC";
    let res_s3_conflict =
        GcStorage::delete_blob_conditional(&*s3_storage, &s3_permit, &digest, None).await;
    assert!(res_s3_conflict.is_err());
    let err_s3_conflict = res_s3_conflict.unwrap_err();
    assert_eq!(
        err_s3_conflict.internal_kind(),
        Some(StorageErrorKind::Conflict),
        "Missing required version precondition on S3 must classify as StorageErrorKind::Conflict"
    );
    assert_eq!(err_s3_conflict.message(), Some(expected_s3_conflict_msg));
    assert_eq!(
        err_s3_conflict.to_string(),
        format!("internal error: {expected_s3_conflict_msg}")
    );

    // 2b. Invalidate S3 authority to make s3_permit inactive
    let err_s3_d = {
        let guard = s3_authority.set_test_inactive_guard();
        assert!(!s3_permit.is_valid());

        // Inactive permit on quarantine_blob (S3)
        let res_s3_q =
            GcStorage::quarantine_blob(&*s3_storage, &s3_permit, &digest, &dummy_version).await;
        assert!(res_s3_q.is_err());
        let err_s3_q = res_s3_q.unwrap_err();
        assert_eq!(
            err_s3_q.internal_kind(),
            Some(StorageErrorKind::PermissionDenied),
            "Inactive permit on S3 quarantine_blob must classify as PermissionDenied"
        );
        assert_eq!(
            err_s3_q.message(),
            Some("invalid or inactive GC mutation permit")
        );
        assert_eq!(
            err_s3_q.to_string(),
            "internal error: invalid or inactive GC mutation permit"
        );

        // Inactive permit on restore_quarantined_blob (S3)
        let res_s3_r = GcStorage::restore_quarantined_blob(&*s3_storage, &s3_permit, &digest).await;
        assert!(res_s3_r.is_err());
        let err_s3_r = res_s3_r.unwrap_err();
        assert_eq!(
            err_s3_r.internal_kind(),
            Some(StorageErrorKind::PermissionDenied),
            "Inactive permit on S3 restore_quarantined_blob must classify as PermissionDenied"
        );
        assert_eq!(
            err_s3_r.message(),
            Some("invalid or inactive GC mutation permit")
        );
        assert_eq!(
            err_s3_r.to_string(),
            "internal error: invalid or inactive GC mutation permit"
        );

        // Inactive permit on delete_blob_conditional (S3)
        let res_s3_d = GcStorage::delete_blob_conditional(
            &*s3_storage,
            &s3_permit,
            &digest,
            Some(&dummy_version),
        )
        .await;
        assert!(res_s3_d.is_err());
        let err_s3_d = res_s3_d.unwrap_err();
        assert_eq!(
            err_s3_d.internal_kind(),
            Some(StorageErrorKind::PermissionDenied),
            "Inactive permit on S3 delete_blob_conditional must classify as PermissionDenied"
        );
        assert_eq!(
            err_s3_d.message(),
            Some("invalid or inactive GC mutation permit")
        );
        assert_eq!(
            err_s3_d.to_string(),
            "internal error: invalid or inactive GC mutation permit"
        );

        drop(guard);
        err_s3_d
    };

    // Distinguish S3 conflict vs permission_denied
    assert_ne!(err_s3_conflict.internal_kind(), err_s3_d.internal_kind());

    // Restore validity, drop permit, and explicitly release authority with backend lock cleanup
    assert!(s3_permit.is_valid());
    drop(s3_permit);
    assert!(s3_authority.release().await.is_ok());
    assert!(
        crate::storage::mutation_authority::inspect_deployment_writer_lock(s3_storage.as_ref())
            .await
            .expect("inspect")
            .is_none(),
        "S3 deployment lock must be deleted on backend after explicit release"
    );
}

#[tokio::test]
async fn test_production_boundary_s3_versioning_preflight_distinguishes_all_states() {
    use crate::storage::GcStorage;
    use crate::storage::s3::tests::MockS3Driver;
    use crate::storage::s3::{S3BucketVersioningState, S3Storage};

    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver.clone(),
    );

    // 1. Unversioned -> Ok(())
    *driver.versioning_state.lock().unwrap() = S3BucketVersioningState::Unversioned;
    assert!(
        GcStorage::check_bucket_versioning_for_gc(&storage)
            .await
            .is_ok()
    );

    // 2. AccessDenied -> Err(PermissionDenied) [Fails closed]
    *driver.versioning_state.lock().unwrap() =
        S3BucketVersioningState::AccessDenied("403 Forbidden".to_string());
    let res = GcStorage::check_bucket_versioning_for_gc(&storage).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_msg =
        "S3 bucket versioning preflight check failed or permission denied: 403 Forbidden";
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::PermissionDenied),
        "AccessDenied on bucket versioning preflight must classify as PermissionDenied"
    );
    assert_eq!(err.message(), Some(expected_msg));
    assert_eq!(err.to_string(), format!("internal error: {expected_msg}"));

    // 3. BackendError -> Err(Backend) [Fails closed]
    *driver.versioning_state.lock().unwrap() =
        S3BucketVersioningState::BackendError("500 InternalServerError".to_string());
    let res = GcStorage::check_bucket_versioning_for_gc(&storage).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_msg =
        "S3 bucket versioning preflight check failed or permission denied: 500 InternalServerError";
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::Backend),
        "Backend/transport failure on versioning preflight must classify as Backend"
    );
    assert_eq!(err.message(), Some(expected_msg));
    assert_eq!(err.to_string(), format!("internal error: {expected_msg}"));

    // 4. Enabled -> Err(Configuration) [Fails closed]
    *driver.versioning_state.lock().unwrap() = S3BucketVersioningState::Enabled;
    let res = GcStorage::check_bucket_versioning_for_gc(&storage).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_msg = "S3 physical GC requires an unversioned bucket; bucket versioning is Enabled (delete would create delete markers rather than reclaim physical space)";
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::Configuration),
        "Enabled versioning must classify as Configuration error for physical GC"
    );
    assert_eq!(err.message(), Some(expected_msg));
    assert_eq!(err.to_string(), format!("internal error: {expected_msg}"));

    // 5. Suspended -> Err(Configuration) [Fails closed]
    *driver.versioning_state.lock().unwrap() = S3BucketVersioningState::Suspended;
    let res = GcStorage::check_bucket_versioning_for_gc(&storage).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    let expected_msg = "S3 physical GC requires an unversioned bucket; bucket versioning is Suspended (noncurrent versions exist and cannot be reclaimed without version-aware GC)";
    assert_eq!(
        err.internal_kind(),
        Some(StorageErrorKind::Configuration),
        "Suspended versioning must classify as Configuration error for physical GC"
    );
    assert_eq!(err.message(), Some(expected_msg));
    assert_eq!(err.to_string(), format!("internal error: {expected_msg}"));
}

#[test]
fn test_golden_display_all_preexisting_storage_error_variants() {
    assert_eq!(StorageError::NotFound.to_string(), "not found");
    assert_eq!(StorageError::DigestMismatch.to_string(), "digest mismatch");
    assert_eq!(StorageError::Unsupported.to_string(), "unsupported");
    assert_eq!(StorageError::TooLarge.to_string(), "too large");
    assert_eq!(
        StorageError::InsufficientStorage.to_string(),
        "insufficient storage"
    );
    assert_eq!(
        StorageError::TagAlreadyExists.to_string(),
        "tag already exists"
    );
    assert_eq!(
        StorageError::ExclusiveWriterLocked("node-42".to_string()).to_string(),
        "exclusive writer lock held by another deployment/instance: node-42"
    );
    assert_eq!(
        StorageError::InvalidRepoName("bad//repo".to_string()).to_string(),
        "invalid repository name: bad//repo"
    );
    assert_eq!(
        StorageError::MigrationRequired("v2 schema backfill".to_string()).to_string(),
        "migration required: v2 schema backfill"
    );
    assert_eq!(
        StorageError::internal(StorageErrorKind::Io, "disk disconnected").to_string(),
        "internal error: disk disconnected"
    );
    assert_eq!(
        StorageError::internal(StorageErrorKind::Backend, "connection reset").to_string(),
        "internal error: connection reset"
    );
    assert_eq!(
        StorageError::internal(StorageErrorKind::PermissionDenied, "access denied").to_string(),
        "internal error: access denied"
    );
    assert_eq!(
        StorageError::internal(StorageErrorKind::CorruptData, "malformed manifest").to_string(),
        "internal error: malformed manifest"
    );
    assert_eq!(
        StorageError::internal(StorageErrorKind::Serialization, "recursion limit").to_string(),
        "internal error: recursion limit"
    );
    assert_eq!(
        StorageError::internal(StorageErrorKind::Configuration, "missing bucket").to_string(),
        "internal error: missing bucket"
    );
    assert_eq!(
        StorageError::internal(StorageErrorKind::Conflict, "etag mismatch").to_string(),
        "internal error: etag mismatch"
    );
    assert_eq!(
        StorageError::internal(StorageErrorKind::InternalInvariant, "unreachable state")
            .to_string(),
        "internal error: unreachable state"
    );
}

#[tokio::test]
async fn test_production_boundary_lock_holder_conflict_vs_invalid_admin_auth_permission_denied() {
    use crate::storage::ClusterLockStore;
    use crate::storage::mutation_authority::{
        DEPLOYMENT_LOCK_FORMAT_VERSION, DeploymentWriterLockDoc,
        admin_clear_abandoned_deployment_writer_lock, force_unlock_deployment_writer,
    };
    use crate::storage::s3::S3Storage;
    use crate::storage::s3::tests::MockS3Driver;

    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100_000_000,
        driver.clone(),
    );

    // 1. Seed a stored lock document owned by 'node-2' with etag 'etag-123'
    let lock_doc = DeploymentWriterLockDoc {
        format_version: DEPLOYMENT_LOCK_FORMAT_VERSION,
        owner_id: "node-2".to_string(),
        owner_token: "token-node-2".to_string(),
        hostname: "host-2".to_string(),
        pid: 1234,
        command_mode: "serve".to_string(),
        acquired_unix_secs: 1000,
    };
    let lock_bytes = serde_json::to_vec(&lock_doc).unwrap();
    let lock_key = "meta/exclusive_writer.lock";
    driver.objects.lock().unwrap().insert(
        lock_key.to_string(),
        (bytes::Bytes::from(lock_bytes), "etag-123".to_string()),
    );

    // 1a. Competing writer / active lock holder -> Dedicated domain variant
    let locked_domain = StorageError::ExclusiveWriterLocked("node-2".to_string());
    assert!(matches!(
        locked_domain,
        StorageError::ExclusiveWriterLocked(_)
    ));
    assert_eq!(locked_domain.internal_kind(), None);
    assert_eq!(
        locked_domain.to_string(),
        "exclusive writer lock held by another deployment/instance: node-2"
    );

    // 1b. Invoke real production S3 admin_clear_deployment_writer_lock with expected_owner 'node-1'
    // This executes the production lock owner mismatch check in S3Storage::admin_clear_deployment_writer_lock
    let res_conflict =
        ClusterLockStore::admin_clear_deployment_writer_lock(&storage, "node-1", "etag-123").await;
    assert!(res_conflict.is_err());
    let err_conflict = res_conflict.unwrap_err();
    assert_eq!(
        err_conflict.internal_kind(),
        Some(StorageErrorKind::Conflict),
        "Lock owner mismatch in S3Storage must return typed StorageErrorKind::Conflict"
    );
    assert_eq!(
        err_conflict.message(),
        Some("lock owner mismatch: expected 'node-1', current is 'node-2'")
    );
    assert_eq!(
        err_conflict.to_string(),
        "internal error: lock owner mismatch: expected 'node-1', current is 'node-2'"
    );

    // Verify lock still exists in storage (not deleted due to conflict)
    assert!(
        driver.objects.lock().unwrap().contains_key(lock_key),
        "Lock object must survive on owner conflict"
    );

    // 2a. Invoke admin_clear_abandoned_deployment_writer_lock with invalid confirmation token
    let res_bad_conf = admin_clear_abandoned_deployment_writer_lock(
        &storage,
        "node-2",
        "etag-123",
        "INVALID-CONFIRMATION-TOKEN",
    )
    .await;
    assert!(res_bad_conf.is_err());
    let err_bad_conf = res_bad_conf.unwrap_err();
    assert_eq!(
        err_bad_conf.internal_kind(),
        Some(StorageErrorKind::PermissionDenied),
        "Invalid admin confirmation token must return typed StorageErrorKind::PermissionDenied"
    );
    assert_eq!(
        err_bad_conf.message(),
        Some(
            "destructive lock clearing requires exact confirmation token: 'CONFIRM-CLEAR-ABANDONED-WRITER'"
        )
    );
    assert_eq!(
        err_bad_conf.to_string(),
        "internal error: destructive lock clearing requires exact confirmation token: 'CONFIRM-CLEAR-ABANDONED-WRITER'"
    );

    // 2b. Invoke force_unlock_deployment_writer with invalid authorization token
    let res_bad_force = force_unlock_deployment_writer(&storage, "WRONG-TOKEN").await;
    assert!(res_bad_force.is_err());
    let err_bad_force = res_bad_force.unwrap_err();
    assert_eq!(
        err_bad_force.internal_kind(),
        Some(StorageErrorKind::PermissionDenied),
        "Invalid force unlock authorization must return typed StorageErrorKind::PermissionDenied"
    );
    assert_eq!(
        err_bad_force.message(),
        Some("confirmation token 'WRONG-TOKEN' did not match lock owner 'node-2'")
    );
    assert_eq!(
        err_bad_force.to_string(),
        "internal error: confirmation token 'WRONG-TOKEN' did not match lock owner 'node-2'"
    );

    // Verify lock still exists in storage (authorization failure did NOT execute downstream deletion)
    assert!(
        driver.objects.lock().unwrap().contains_key(lock_key),
        "Lock object must remain intact when authorization fails"
    );

    // 3. Confirm typed distinction between conflict and permission_denied without text parsing
    assert_ne!(err_conflict.internal_kind(), err_bad_conf.internal_kind());
    assert_ne!(err_conflict.internal_kind(), err_bad_force.internal_kind());
    assert_eq!(
        err_conflict.internal_kind(),
        Some(StorageErrorKind::Conflict)
    );
    assert_eq!(
        err_bad_conf.internal_kind(),
        Some(StorageErrorKind::PermissionDenied)
    );
}
