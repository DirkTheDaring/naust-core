use crate::manifest_refs::parse_manifest_refs;
use crate::registry::digest::Digest;
pub use crate::storage::repo_membership::{
    MigrationCheckpointRecord, MigrationPhase, MigrationStats, RepoBlobMembershipRecord,
};
use crate::storage::{BlobRefIndexStoragePort, BlobUploadCoordinatorStoragePort, StorageError};
use std::collections::{HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

const LEASE_DURATION_SECS: u64 = 60;

fn bound_utf8_diagnostic(err_msg: &mut String, max_bytes: usize) {
    if err_msg.len() > max_bytes {
        let mut boundary = max_bytes;
        while !err_msg.is_char_boundary(boundary) {
            boundary -= 1;
        }
        err_msg.truncate(boundary);
    }
}

/// Plan repository blob membership migration (dry-run). Performs ZERO writes.
pub async fn plan_membership_migration(
    storage: &(impl BlobRefIndexStoragePort + ?Sized),
) -> Result<MigrationStats, StorageError> {
    let mut stats = MigrationStats::default();
    let repos = storage.list_repositories().await?;
    stats.repositories_scanned = repos.len();

    for repo in &repos {
        let tags = match storage.list_tags(repo).await {
            Ok(tags) => tags,
            Err(StorageError::NotFound) => Vec::new(),
            Err(e) => return Err(e),
        };
        let mut visited_manifests: HashSet<Digest> = HashSet::new();
        for tag in tags {
            if let Ok(manifest_digest) = storage.resolve_tag(repo, &tag).await {
                let mut queue = VecDeque::new();
                if visited_manifests.insert(manifest_digest.clone()) {
                    queue.push_back(manifest_digest);
                }
                while let Some(current_digest) = queue.pop_front() {
                    stats.manifests_scanned += 1;
                    let (_meta, bytes) = storage.get_manifest(repo, &current_digest).await?;
                    let refs = parse_manifest_refs(&bytes).map_err(|e| {
                        StorageError::corrupt_data(format!(
                            "corrupt manifest {current_digest} in repo {repo}: {e}"
                        ))
                    })?;
                    for blob_d in refs.blob_references() {
                        match storage.get_repo_blob_membership(repo, blob_d).await? {
                            Some(_) => stats.memberships_already_present += 1,
                            None => stats.memberships_created += 1,
                        }
                    }
                    for child_manifest in refs.manifest_references() {
                        if visited_manifests.insert(child_manifest.clone()) {
                            queue.push_back(child_manifest.clone());
                        }
                    }
                }
            }
        }
    }

    Ok(stats)
}

/// Apply repository blob membership backfill from authoritative tagged manifests.
/// Resumes from previous checkpoint if interrupted.
pub async fn apply_membership_migration(
    storage: &(impl BlobUploadCoordinatorStoragePort + ?Sized),
) -> Result<MigrationStats, StorageError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let my_owner_id = uuid::Uuid::new_v4().to_string();

    let mut checkpoint = match storage.get_migration_checkpoint().await? {
        Some(existing) => {
            if existing.phase == MigrationPhase::Ready {
                return Ok(existing.stats);
            }
            // Check lease
            if let (Some(owner), Some(expiry)) =
                (&existing.owner_id, existing.lease_expiry_unix_secs)
            {
                if now < expiry && owner != &my_owner_id {
                    return Err(StorageError::conflict(format!(
                        "concurrent migrator {owner} holds active lease until {expiry}"
                    )));
                }
            }
            MigrationCheckpointRecord {
                schema_version: 1,
                phase: MigrationPhase::Applying,
                owner_id: Some(my_owner_id.clone()),
                lease_expiry_unix_secs: Some(now + LEASE_DURATION_SECS),
                source_continuation_token: existing.source_continuation_token,
                current_repository: None,
                current_cursor: None,
                stats: existing.stats,
                started_unix_secs: existing.started_unix_secs,
                last_updated_unix_secs: now,
                failure_info: None,
                verification_result: None,
            }
        }
        None => MigrationCheckpointRecord {
            schema_version: 1,
            phase: MigrationPhase::Applying,
            owner_id: Some(my_owner_id.clone()),
            lease_expiry_unix_secs: Some(now + LEASE_DURATION_SECS),
            source_continuation_token: None,
            current_repository: None,
            current_cursor: None,
            stats: MigrationStats::default(),
            started_unix_secs: now,
            last_updated_unix_secs: now,
            failure_info: None,
            verification_result: None,
        },
    };

    // Save initial Applying checkpoint
    storage.save_migration_checkpoint(&checkpoint).await?;

    let mut repos = storage.list_repositories().await?;
    repos.sort();
    checkpoint.stats.repositories_scanned = repos.len();

    for repo in &repos {
        // Skip already completed repositories based on deterministic sorted continuation cursor
        if let Some(ref last_completed) = checkpoint.source_continuation_token {
            if repo <= last_completed {
                continue;
            }
        }

        // Set current repository cursor
        let canonical_repo = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
        checkpoint.current_repository = Some(canonical_repo);
        let cur_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        checkpoint.last_updated_unix_secs = cur_time;
        checkpoint.lease_expiry_unix_secs = Some(cur_time + LEASE_DURATION_SECS);
        storage.save_migration_checkpoint(&checkpoint).await?;

        let tags = match storage.list_tags(repo).await {
            Ok(tags) => tags,
            Err(StorageError::NotFound) => Vec::new(),
            Err(e) => {
                checkpoint.phase = MigrationPhase::Failed;
                let mut err_msg = format!("tag listing failed for repo {repo}: {e}");
                bound_utf8_diagnostic(&mut err_msg, 512);
                checkpoint.failure_info = Some(err_msg);
                if let Err(save_err) = storage.save_migration_checkpoint(&checkpoint).await {
                    tracing::warn!(
                        repo = %repo,
                        listing_error = %e,
                        checkpoint_save_error = %save_err,
                        "failed to persist migration failure checkpoint; returning original listing error"
                    );
                }
                return Err(e);
            }
        };
        let mut visited_manifests: HashSet<Digest> = HashSet::new();
        for tag in tags {
            if let Ok(manifest_digest) = storage.resolve_tag(repo, &tag).await {
                let mut queue = VecDeque::new();
                if visited_manifests.insert(manifest_digest.clone()) {
                    queue.push_back(manifest_digest);
                }
                while let Some(current_digest) = queue.pop_front() {
                    checkpoint.stats.manifests_scanned += 1;
                    let (_meta, bytes) = match storage.get_manifest(repo, &current_digest).await {
                        Ok(res) => res,
                        Err(e) => {
                            checkpoint.phase = MigrationPhase::Failed;
                            let mut err_msg =
                                format!("failed reading manifest {current_digest} in {repo}: {e}");
                            bound_utf8_diagnostic(&mut err_msg, 512);
                            checkpoint.failure_info = Some(err_msg);
                            if let Err(save_err) =
                                storage.save_migration_checkpoint(&checkpoint).await
                            {
                                tracing::warn!(
                                    repo = %repo,
                                    manifest = %current_digest,
                                    read_error = %e,
                                    checkpoint_save_error = %save_err,
                                    "failed to persist migration failure checkpoint"
                                );
                            }
                            return Err(e);
                        }
                    };
                    let refs = match parse_manifest_refs(&bytes) {
                        Ok(r) => r,
                        Err(e) => {
                            checkpoint.phase = MigrationPhase::Failed;
                            let mut err_msg =
                                format!("corrupt manifest {current_digest} in {repo}: {e}");
                            bound_utf8_diagnostic(&mut err_msg, 512);
                            checkpoint.failure_info = Some(err_msg);
                            if let Err(save_err) =
                                storage.save_migration_checkpoint(&checkpoint).await
                            {
                                tracing::warn!(
                                    repo = %repo,
                                    manifest = %current_digest,
                                    parse_error = %e,
                                    checkpoint_save_error = %save_err,
                                    "failed to persist migration failure checkpoint"
                                );
                            }
                            return Err(StorageError::corrupt_data(format!(
                                "corrupt manifest {current_digest} in repo {repo}: {e}"
                            )));
                        }
                    };
                    for blob_d in refs.blob_references() {
                        match storage.get_repo_blob_membership(repo, blob_d).await? {
                            Some(_) => {
                                checkpoint.stats.memberships_already_present += 1;
                            }
                            None => {
                                let canonical_repo =
                                    crate::registry::canonical_name::CanonicalRepoName::parse(repo)
                                        .map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
                                let record = RepoBlobMembershipRecord::new_migration(
                                    canonical_repo,
                                    blob_d.clone(),
                                );
                                storage.link_repo_blob(&record).await?;
                                checkpoint.stats.memberships_created += 1;
                            }
                        }
                    }
                    for child_manifest in refs.manifest_references() {
                        if visited_manifests.insert(child_manifest.clone()) {
                            queue.push_back(child_manifest.clone());
                        }
                    }
                }
            }
        }

        // Advance cursor and clear current repository
        checkpoint.source_continuation_token = Some(repo.clone());
        checkpoint.current_repository = None;
        let cur_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        checkpoint.last_updated_unix_secs = cur_time;
        checkpoint.lease_expiry_unix_secs = Some(cur_time + LEASE_DURATION_SECS);
        storage.save_migration_checkpoint(&checkpoint).await?;
    }

    // Phase: Verifying
    checkpoint.phase = MigrationPhase::Verifying;
    storage.save_migration_checkpoint(&checkpoint).await?;

    // Verify all memberships exist and point to valid CAS objects before marking Ready!
    let is_valid = verify_membership_migration(storage).await?;
    if !is_valid {
        checkpoint.phase = MigrationPhase::Failed;
        checkpoint.failure_info = Some(
            "membership verification failed: unlinked or missing CAS blobs detected".to_string(),
        );
        checkpoint.verification_result = Some(false);
        storage.save_migration_checkpoint(&checkpoint).await?;
        return Err(StorageError::corrupt_data(
            "membership verification failed after apply; not all referenced blobs have durable records",
        ));
    }

    // Mark ready only after full verification passes
    storage.mark_membership_ready().await?;
    checkpoint.phase = MigrationPhase::Ready;
    checkpoint.verification_result = Some(true);
    checkpoint.owner_id = None;
    checkpoint.lease_expiry_unix_secs = None;
    checkpoint.current_repository = None;
    checkpoint.current_cursor = None;
    checkpoint.last_updated_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    storage.save_migration_checkpoint(&checkpoint).await?;

    Ok(checkpoint.stats)
}

/// Verify that all repository-referenced blobs have durable membership records and exist in CAS.
pub async fn verify_membership_migration(
    storage: &(impl BlobUploadCoordinatorStoragePort + ?Sized),
) -> Result<bool, StorageError> {
    let repos = storage.list_repositories().await?;
    for repo in &repos {
        let tags = match storage.list_tags(repo).await {
            Ok(tags) => tags,
            Err(StorageError::NotFound) => Vec::new(),
            Err(e) => return Err(e),
        };
        let mut visited_manifests: HashSet<Digest> = HashSet::new();
        for tag in tags {
            let manifest_digest = match storage.resolve_tag(repo, &tag).await {
                Ok(d) => d,
                Err(StorageError::NotFound) => continue,
                Err(e) => return Err(e),
            };
            let mut queue = VecDeque::new();
            if visited_manifests.insert(manifest_digest.clone()) {
                queue.push_back(manifest_digest);
            }
            while let Some(current_digest) = queue.pop_front() {
                let (_meta, bytes) = match storage.get_manifest(repo, &current_digest).await {
                    Ok(m) => m,
                    Err(StorageError::NotFound) => return Ok(false),
                    Err(e) => return Err(e),
                };
                let refs = match parse_manifest_refs(&bytes) {
                    Ok(r) => r,
                    Err(_) => return Ok(false),
                };
                for blob_d in refs.blob_references() {
                    let membership =
                        storage.get_repo_blob_membership(repo, blob_d).await?;
                    let Some(record) = membership else {
                        return Ok(false);
                    };
                    // Verify repository and digest match
                    if record.repo != *repo || record.digest != *blob_d {
                        return Ok(false);
                    }
                    // Verify CAS blob exists globally
                    if storage.head_blob(blob_d).await.is_err() {
                        return Ok(false);
                    }
                }
                for child_manifest in refs.manifest_references() {
                    if visited_manifests.insert(child_manifest.clone()) {
                        queue.push_back(child_manifest.clone());
                    }
                }
            }
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bound_utf8_diagnostic_multibyte_boundary() {
        let mut msg = String::from("prefix_");
        // Append 4-byte emoji 🦀 (0xF0 0x9F 0x90 0x80) repeatedly
        while msg.len() < 510 {
            msg.push('🦀');
        }
        // At len 511 (or close), push multibyte sequence crossing 512
        msg.push_str("AB🦀CD");
        assert!(msg.len() > 512);

        bound_utf8_diagnostic(&mut msg, 512);
        assert!(msg.len() <= 512);
        // Valid UTF-8 string guaranteed by &mut String, truncation lands on character boundary
        std::str::from_utf8(msg.as_bytes()).expect("must remain valid UTF-8");
    }

    #[test]
    fn test_bound_utf8_diagnostic_under_limit() {
        let mut msg = String::from("short error");
        bound_utf8_diagnostic(&mut msg, 512);
        assert_eq!(msg, "short error");
    }

    #[test]
    fn test_bound_utf8_diagnostic_exact_512() {
        let mut msg = "a".repeat(512);
        bound_utf8_diagnostic(&mut msg, 512);
        assert_eq!(msg.len(), 512);
    }

    #[test]
    fn test_bound_utf8_diagnostic_2byte_crossing() {
        // 'é' is 2 bytes: 0xC3 0xA9
        let mut msg = "a".repeat(511);
        msg.push('é'); // len is 513
        assert_eq!(msg.len(), 513);
        bound_utf8_diagnostic(&mut msg, 512);
        assert_eq!(msg.len(), 511);
        assert_eq!(msg, "a".repeat(511));
        std::str::from_utf8(msg.as_bytes()).expect("must remain valid UTF-8");
    }

    #[test]
    fn test_bound_utf8_diagnostic_3byte_crossing() {
        // '中' is 3 bytes: 0xE4 0xB8 0xAD
        let mut msg = "a".repeat(511);
        msg.push('中'); // len is 514
        assert_eq!(msg.len(), 514);
        bound_utf8_diagnostic(&mut msg, 512);
        assert_eq!(msg.len(), 511);
        assert_eq!(msg, "a".repeat(511));
        std::str::from_utf8(msg.as_bytes()).expect("must remain valid UTF-8");

        let mut msg2 = "a".repeat(510);
        msg2.push('中'); // len is 513
        bound_utf8_diagnostic(&mut msg2, 512);
        assert_eq!(msg2.len(), 510);
        assert_eq!(msg2, "a".repeat(510));
    }

    #[test]
    fn test_bound_utf8_diagnostic_empty_and_zero_bound() {
        let mut empty = String::new();
        bound_utf8_diagnostic(&mut empty, 512);
        assert_eq!(empty, "");

        let mut non_empty = String::from("hello");
        bound_utf8_diagnostic(&mut non_empty, 0);
        assert_eq!(non_empty, "");
    }

    fn test_sha256(data: &[u8]) -> Digest {
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(data);
        Digest::parse(&format!("sha256:{}", hex::encode(hash))).unwrap()
    }

    async fn write_test_blob(storage: &crate::storage::fs::FsStorage, data: &[u8]) -> Digest {
        use crate::storage::ports::BlobCasWriter;
        let digest = test_sha256(data);
        let up = storage.create_upload().await.unwrap();
        storage
            .append_upload(&up.uuid, bytes::Bytes::copy_from_slice(data))
            .await
            .unwrap();
        storage.finalize_upload(&up.uuid, &digest).await.unwrap();
        digest
    }

    #[tokio::test]
    async fn test_membership_migration_multiarch_manifest_list_traversal() {
        use crate::storage::fs::FsStorage;
        use crate::storage::ports::{ManifestStore, TagStore};
        use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path().to_path_buf(), 50 * 1024 * 1024);
        let repo = "multi-arch-repo";

        // 1. Create blobs for child manifests (config + layer for each arch)
        let config_amd64 = write_test_blob(&storage, b"cfg_amd64").await;
        let layer_amd64 = write_test_blob(&storage, b"layer_amd64").await;
        let config_arm64 = write_test_blob(&storage, b"cfg_arm64").await;
        let layer_arm64 = write_test_blob(&storage, b"layer_arm64").await;

        // 2. Create child manifests
        let manifest_amd64_bytes = bytes::Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":9}},"layers":[{{"digest":"{}","size":11}}]}}"#,
            config_amd64.as_str(),
            layer_amd64.as_str()
        ));
        let digest_amd64 = test_sha256(&manifest_amd64_bytes);
        storage
            .put_manifest(repo, &digest_amd64, manifest_amd64_bytes)
            .await
            .unwrap();

        let manifest_arm64_bytes = bytes::Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":9}},"layers":[{{"digest":"{}","size":11}}]}}"#,
            config_arm64.as_str(),
            layer_arm64.as_str()
        ));
        let digest_arm64 = test_sha256(&manifest_arm64_bytes);
        storage
            .put_manifest(repo, &digest_arm64, manifest_arm64_bytes)
            .await
            .unwrap();

        // 3. Create multi-arch OCI Image Index manifest
        let index_bytes = bytes::Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":100}},{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"{}","size":100}}]}}"#,
            digest_amd64.as_str(),
            digest_arm64.as_str()
        ));
        let digest_index = test_sha256(&index_bytes);
        storage
            .put_manifest(repo, &digest_index, index_bytes)
            .await
            .unwrap();

        // 4. Tag points ONLY to the top-level multi-arch index
        storage.set_tag(repo, "latest", &digest_index).await.unwrap();

        // Plan: dry-run should discover all 3 manifests and 4 blob memberships
        let plan_stats = plan_membership_migration(&storage).await.unwrap();
        assert_eq!(plan_stats.manifests_scanned, 3);
        assert_eq!(plan_stats.memberships_created, 4);
        assert_eq!(plan_stats.memberships_already_present, 0);

        // Apply: backfill memberships recursively
        let apply_stats = apply_membership_migration(&storage).await.unwrap();
        assert_eq!(apply_stats.manifests_scanned, 3);
        assert_eq!(apply_stats.memberships_created, 4);

        // Verify: verify_membership_migration should traverse all 3 manifests and verify all 4 blobs
        let verified = verify_membership_migration(&storage).await.unwrap();
        assert!(verified, "membership verification must pass for multi-arch manifest lists");

        // Verify all 4 blobs have durable memberships
        for blob in [&config_amd64, &layer_amd64, &config_arm64, &layer_arm64] {
            assert!(
                storage
                    .get_repo_blob_membership(repo, blob)
                    .await
                    .unwrap()
                    .is_some(),
                "blob {blob} must have repo membership"
            );
        }
    }

    #[tokio::test]
    async fn test_membership_migration_failure_checkpoint_persisted_on_corrupt_manifest() {
        use crate::storage::fs::FsStorage;
        use crate::storage::ports::{ManifestStore, TagStore};
        use crate::storage::repo_membership::RepositoryBlobMembershipStorage;

        let dir = tempfile::tempdir().unwrap();
        let storage = FsStorage::new(dir.path().to_path_buf(), 50 * 1024 * 1024);
        let repo = "corrupt-repo";

        let valid_manifest_bytes = bytes::Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":9}},"layers":[]}}"#,
            test_sha256(b"dummy").as_str()
        ));
        let digest = test_sha256(&valid_manifest_bytes);
        storage
            .put_manifest(repo, &digest, valid_manifest_bytes)
            .await
            .unwrap();
        storage.set_tag(repo, "latest", &digest).await.unwrap();

        // Corrupt manifest on disk to trigger parse_manifest_refs failure
        let manifest_path = dir
            .path()
            .join("repos")
            .join(repo)
            .join("manifests")
            .join(digest.hex());
        std::fs::write(
            &manifest_path,
            b"{\"schemaVersion\": 2, \"config\": \"invalid-config\"}",
        )
        .unwrap();

        let res = apply_membership_migration(&storage).await;
        assert!(res.is_err());

        // Checkpoint must be persisted with MigrationPhase::Failed (verified via .await)
        let checkpoint = storage
            .get_migration_checkpoint()
            .await
            .unwrap()
            .expect("failure checkpoint must be durably saved");
        assert_eq!(checkpoint.phase, MigrationPhase::Failed);
        assert!(checkpoint.failure_info.is_some());
        assert!(checkpoint
            .failure_info
            .unwrap()
            .contains("corrupt manifest"));

        let verified = verify_membership_migration(&storage).await.unwrap();
        assert!(
            !verified,
            "verify_membership_migration must fail when a manifest is corrupt"
        );
    }
}
