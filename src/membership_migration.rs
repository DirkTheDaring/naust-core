use crate::manifest_refs::parse_manifest_refs;
pub use crate::storage::repo_membership::{
    MigrationCheckpointRecord, MigrationPhase, MigrationStats, RepoBlobMembershipRecord,
};
use crate::storage::{BlobRefIndexStoragePort, BlobUploadCoordinatorStoragePort, StorageError};
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
        for tag in tags {
            if let Ok(manifest_digest) = storage.resolve_tag(repo, &tag).await {
                stats.manifests_scanned += 1;
                let (_meta, bytes) = storage.get_manifest(repo, &manifest_digest).await?;
                let refs = parse_manifest_refs(&bytes).map_err(|e| {
                    StorageError::corrupt_data(format!(
                        "corrupt manifest {manifest_digest} in repo {repo}: {e}"
                    ))
                })?;
                for blob_d in refs.blob_references() {
                    match storage.get_repo_blob_membership(repo, blob_d).await? {
                        Some(_) => stats.memberships_already_present += 1,
                        None => stats.memberships_created += 1,
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
        for tag in tags {
            if let Ok(manifest_digest) = storage.resolve_tag(repo, &tag).await {
                checkpoint.stats.manifests_scanned += 1;
                let (_meta, bytes) = storage.get_manifest(repo, &manifest_digest).await?;
                let refs = parse_manifest_refs(&bytes).map_err(|e| {
                    checkpoint.phase = MigrationPhase::Failed;
                    let mut err_msg = format!("corrupt manifest {manifest_digest} in {repo}: {e}");
                    err_msg.truncate(512);
                    checkpoint.failure_info = Some(err_msg);
                    let _ = storage.save_migration_checkpoint(&checkpoint);
                    StorageError::corrupt_data(format!(
                        "corrupt manifest {manifest_digest} in repo {repo}: {e}"
                    ))
                })?;
                for blob_d in refs.blob_references() {
                    match storage.get_repo_blob_membership(repo, blob_d).await? {
                        Some(_) => {
                            checkpoint.stats.memberships_already_present += 1;
                        }
                        None => {
                            let canonical_repo =
                                crate::registry::canonical_name::CanonicalRepoName::parse(&repo)
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
        for tag in tags {
            if let Ok(manifest_digest) = storage.resolve_tag(repo, &tag).await {
                if let Ok((_meta, bytes)) = storage.get_manifest(repo, &manifest_digest).await {
                    if let Ok(refs) = parse_manifest_refs(&bytes) {
                        for blob_d in refs.blob_references() {
                            let membership = storage.get_repo_blob_membership(repo, blob_d).await?;
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
}
