use crate::{manifest_refs::parse_manifest_refs, registry::digest::Digest, storage::StorageError};
use std::{
    collections::HashMap,
    collections::{HashSet, VecDeque},
    sync::Arc,
};

#[derive(Clone, Debug)]
pub struct BlobReference {
    pub repo: String,
    pub tag: Option<String>,
    pub manifest: String,
}

use crate::manifest_refs::ManifestRefs;
use crate::storage::BlobIndexStoragePort;

async fn scan_repo_for_blob(
    storage: &(impl BlobIndexStoragePort + ?Sized),
    repo: &str,
    root_manifest: Digest,
    root_tag: Option<String>,
    target: &Digest,
    refs_cache: &mut HashMap<Digest, Option<ManifestRefs>>,
) -> Result<Option<BlobReference>, StorageError> {
    let mut queue: VecDeque<Digest> = VecDeque::new();
    queue.push_back(root_manifest);

    let mut visited: HashSet<Digest> = HashSet::new();

    while let Some(digest) = queue.pop_front() {
        if !visited.insert(digest.clone()) {
            continue;
        }

        let refs = if let Some(v) = refs_cache.get(&digest) {
            match v.clone() {
                Some(r) => r,
                None => continue,
            }
        } else {
            let (_meta, bytes) = match storage.get_manifest(repo, &digest).await {
                Ok(v) => v,
                Err(StorageError::NotFound) => {
                    refs_cache.insert(digest.clone(), None);
                    continue;
                }
                Err(e) => return Err(e),
            };

            let parsed = match parse_manifest_refs(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    return Err(StorageError::corrupt_data(format!(
                        "unparsable manifest {}: {e}",
                        digest.as_str()
                    )));
                }
            };
            refs_cache.insert(digest.clone(), Some(parsed.clone()));
            parsed
        };

        if refs.blob_references().any(|d| d == target) {
            return Ok(Some(BlobReference {
                repo: repo.to_string(),
                tag: root_tag,
                manifest: digest.as_str(),
            }));
        }

        for child in refs.manifest_references() {
            queue.push_back(child.clone());
        }
    }

    Ok(None)
}

/// Returns the first known reference to `target` if found.
///
/// The algorithm is intentionally conservative:
/// - It walks all repositories and all tags.
/// - For each tag, it traverses the manifest graph (indexes -> manifests) and checks
///   config/layer/subject digests.
/// - If it cannot fetch a referenced manifest, it skips that node (treating the repo
///   as already inconsistent).
#[allow(dead_code)]
pub async fn find_blob_reference(
    storage: &(impl BlobIndexStoragePort + ?Sized),
    target: &Digest,
) -> Result<Option<BlobReference>, StorageError> {
    let repos = storage.list_repositories().await?;

    for repo in repos {
        let tags = match storage.list_tags(&repo).await {
            Ok(t) => t,
            Err(StorageError::NotFound) => continue,
            Err(e) => return Err(e),
        };

        // Many tags often point to the same digest. De-dup roots to avoid repeated manifest reads.
        let mut roots: HashMap<Digest, String> = HashMap::new();
        for tag in tags {
            let root = match storage.resolve_tag(&repo, &tag).await {
                Ok(d) => d,
                Err(StorageError::NotFound) => continue,
                Err(e) => return Err(e),
            };
            roots.entry(root).or_insert(tag);
        }

        let mut refs_cache: HashMap<Digest, Option<ManifestRefs>> = HashMap::new();
        for (root, tag) in roots {
            if let Some(r) =
                scan_repo_for_blob(storage, &repo, root, Some(tag), target, &mut refs_cache).await?
            {
                return Ok(Some(r));
            }
        }
    }

    Ok(None)
}

/// Returns the first known reference to `target` in the specified repository `repo`.
pub async fn find_repo_blob_reference(
    storage: &(impl BlobIndexStoragePort + ?Sized),
    repo: &str,
    target: &Digest,
) -> Result<Option<BlobReference>, StorageError> {
    let tags = match storage.list_tags(repo).await {
        Ok(t) => t,
        Err(StorageError::NotFound) => return Ok(None),
        Err(e) => return Err(e),
    };

    let mut roots: HashMap<Digest, String> = HashMap::new();
    for tag in tags {
        let root = match storage.resolve_tag(repo, &tag).await {
            Ok(d) => d,
            Err(StorageError::NotFound) => continue,
            Err(e) => return Err(e),
        };
        roots.entry(root).or_insert(tag);
    }

    let mut refs_cache: HashMap<Digest, Option<ManifestRefs>> = HashMap::new();
    for (root, tag) in roots {
        if let Some(r) =
            scan_repo_for_blob(storage, repo, root, Some(tag), target, &mut refs_cache).await?
        {
            return Ok(Some(r));
        }
    }

    Ok(None)
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlobDeleteResult {
    Success,
    NotFound,
    InUse { message: String },
}

pub(crate) fn map_ledger_error(
    err: crate::repository_membership_ledger::LedgerError,
) -> StorageError {
    let msg = err.to_string();
    match err {
        crate::repository_membership_ledger::LedgerError::Storage(se) => match se {
            StorageError::Internal { kind, .. } => StorageError::internal(kind, msg),
            other => other,
        },
        crate::repository_membership_ledger::LedgerError::RefIndex(e) => {
            match crate::upload_coordinator::map_ref_index_error(e) {
                StorageError::Internal { kind, .. } => StorageError::internal(kind, msg),
                other => other,
            }
        }
        crate::repository_membership_ledger::LedgerError::Corrupt(_) => {
            StorageError::corrupt_data(msg)
        }
        crate::repository_membership_ledger::LedgerError::IndexRequired(_) => {
            StorageError::configuration(msg)
        }
    }
}

pub struct BlobDeleteService {
    ledger: crate::repository_membership_ledger::RepositoryMembershipLedger,
    index_storage: Arc<dyn BlobIndexStoragePort>,
}

impl BlobDeleteService {
    pub fn new(
        index_storage: Arc<dyn BlobIndexStoragePort>,
        ledger: crate::repository_membership_ledger::RepositoryMembershipLedger,
    ) -> Self {
        Self {
            ledger,
            index_storage,
        }
    }

    pub fn ledger(&self) -> &crate::repository_membership_ledger::RepositoryMembershipLedger {
        &self.ledger
    }

    /// Safely handles a repository-scoped blob deletion request:
    /// 1. Acquires mutation guard from coordinator.
    /// 2. Verifies membership in the requested repository (returns NotFound if absent).
    /// 3. Verifies whether any manifest in the requested repository still references the blob (returns InUse if so).
    /// 4. Unlinks only the requested repository's membership record through the ledger under guard
    ///    (the ledger's index gate fails CLOSED on an unhealthy index — deletion never
    ///    triggers a rebuild itself; recovery runs via the documented auto-heal paths:
    ///    blob finalization, manifest/tag mutations, GC preflight, scheduled GC, startup).
    pub async fn delete_repo_blob(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<BlobDeleteResult, StorageError> {
        // 1. Acquire mutation guard for atomic reference validation and unlinking
        let guard = self.ledger.consistency().acquire_mutation().await;

        // 2. Verify membership exists in the requested repository
        let membership = self.ledger.get_membership(repo, digest).await?;
        if membership.is_none() {
            return Ok(BlobDeleteResult::NotFound);
        }

        // 3. Check if referenced by manifest in this repository
        if let Some(r) = find_repo_blob_reference(self.index_storage.as_ref(), repo, digest).await?
        {
            let mut msg = format!("blob is still referenced by manifest {}", r.manifest);
            if let Some(tag) = r.tag {
                msg = format!("{msg} (repo={}, tag={})", r.repo, tag);
            }
            return Ok(BlobDeleteResult::InUse { message: msg });
        }

        // 4. Unlink repository membership via ledger under guard
        match self.ledger.unlink_with_guard(&guard, repo, digest).await {
            Ok(true) => Ok(BlobDeleteResult::Success),
            Ok(false) => Ok(BlobDeleteResult::NotFound),
            Err(e) => Err(map_ledger_error(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_ref_index::RefIndexError;
    use crate::repository_membership_ledger::LedgerError;
    use crate::storage::fs::FsStorage;
    use crate::storage::{Storage, StorageErrorKind};
    use sha2::{Digest as _, Sha256, Sha512};
    use std::path::PathBuf;

    fn tmp_fs_root() -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("naust-delete-safety-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("create temp fs_root");
        p
    }

    #[test]
    fn test_delete_repo_blob_ledger_error_typed_mapping() {
        use std::path::PathBuf;

        // 1. LedgerError::Storage(Conflict) -> preserved directly
        let ledger_conflict = LedgerError::Storage(StorageError::conflict("tag lock contention"));
        let expected_conflict_msg = ledger_conflict.to_string();
        let mapped_conflict = map_ledger_error(ledger_conflict);
        assert!(matches!(
            mapped_conflict,
            StorageError::Internal {
                kind: StorageErrorKind::Conflict,
                ..
            }
        ));
        assert_eq!(
            mapped_conflict.internal_kind(),
            Some(StorageErrorKind::Conflict)
        );
        assert_eq!(
            mapped_conflict.message(),
            Some(expected_conflict_msg.as_str())
        );
        assert_eq!(
            mapped_conflict.to_string(),
            format!("internal error: {expected_conflict_msg}")
        );

        // 2. LedgerError::Storage(PermissionDenied) -> preserved directly
        let ledger_perm =
            LedgerError::Storage(StorageError::permission_denied("read-only storage mode"));
        let expected_perm_msg = ledger_perm.to_string();
        let mapped_perm = map_ledger_error(ledger_perm);
        assert!(matches!(
            mapped_perm,
            StorageError::Internal {
                kind: StorageErrorKind::PermissionDenied,
                ..
            }
        ));
        assert_eq!(
            mapped_perm.internal_kind(),
            Some(StorageErrorKind::PermissionDenied)
        );
        assert_eq!(mapped_perm.message(), Some(expected_perm_msg.as_str()));
        assert_eq!(
            mapped_perm.to_string(),
            format!("internal error: {expected_perm_msg}")
        );

        // 3. LedgerError::Storage(NotFound) -> preserved directly (dedicated variant)
        let ledger_nf = LedgerError::Storage(StorageError::NotFound);
        let mapped_nf = map_ledger_error(ledger_nf);
        assert!(matches!(mapped_nf, StorageError::NotFound));
        assert_eq!(mapped_nf.internal_kind(), None);
        assert_eq!(mapped_nf.message(), None);
        assert_eq!(mapped_nf.to_string(), "not found");

        // 4. LedgerError::RefIndex(RefIndexError::Sled(Io(PermissionDenied))) -> StorageErrorKind::PermissionDenied
        let sled_perm = sled::Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        let ledger_sled_perm = LedgerError::RefIndex(RefIndexError::Sled(sled_perm));
        let expected_sled_perm_msg = ledger_sled_perm.to_string();
        let mapped_sled_perm = map_ledger_error(ledger_sled_perm);
        assert!(matches!(
            mapped_sled_perm,
            StorageError::Internal {
                kind: StorageErrorKind::PermissionDenied,
                ..
            }
        ));
        assert_eq!(
            mapped_sled_perm.internal_kind(),
            Some(StorageErrorKind::PermissionDenied)
        );
        assert_eq!(
            mapped_sled_perm.message(),
            Some(expected_sled_perm_msg.as_str())
        );
        assert_eq!(
            mapped_sled_perm.to_string(),
            format!("internal error: {expected_sled_perm_msg}")
        );

        // 5. LedgerError::RefIndex(RefIndexError::Sled(Io(ordinary))) -> StorageErrorKind::Io
        let sled_io = sled::Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ));
        let ledger_sled_io = LedgerError::RefIndex(RefIndexError::Sled(sled_io));
        let expected_sled_io_msg = ledger_sled_io.to_string();
        let mapped_sled_io = map_ledger_error(ledger_sled_io);
        assert!(matches!(
            mapped_sled_io,
            StorageError::Internal {
                kind: StorageErrorKind::Io,
                ..
            }
        ));
        assert_eq!(mapped_sled_io.internal_kind(), Some(StorageErrorKind::Io));
        assert_eq!(
            mapped_sled_io.message(),
            Some(expected_sled_io_msg.as_str())
        );
        assert_eq!(
            mapped_sled_io.to_string(),
            format!("internal error: {expected_sled_io_msg}")
        );

        // 5b. LedgerError::RefIndex(RefIndexError::Storage(StorageError::backend(...))) -> StorageErrorKind::Backend
        let ledger_ref_backend = LedgerError::RefIndex(RefIndexError::Storage(
            StorageError::backend("s3 connection reset"),
        ));
        let expected_ref_backend_msg = ledger_ref_backend.to_string();
        let mapped_ref_backend = map_ledger_error(ledger_ref_backend);
        assert!(matches!(
            mapped_ref_backend,
            StorageError::Internal {
                kind: StorageErrorKind::Backend,
                ..
            }
        ));
        assert_eq!(
            mapped_ref_backend.internal_kind(),
            Some(StorageErrorKind::Backend)
        );
        assert_eq!(
            mapped_ref_backend.message(),
            Some(expected_ref_backend_msg.as_str())
        );
        assert_eq!(
            mapped_ref_backend.to_string(),
            format!("internal error: {expected_ref_backend_msg}")
        );

        // 6. LedgerError::RefIndex(RefIndexError::Sled(Io(ENOSPC))) -> dedicated StorageError::InsufficientStorage
        let sled_enospc = sled::Error::Io(std::io::Error::from_raw_os_error(libc::ENOSPC));
        let ledger_sled_enospc = LedgerError::RefIndex(RefIndexError::Sled(sled_enospc));
        let mapped_sled_enospc = map_ledger_error(ledger_sled_enospc);
        assert!(matches!(
            mapped_sled_enospc,
            StorageError::InsufficientStorage
        ));
        assert_eq!(mapped_sled_enospc.internal_kind(), None);
        assert_eq!(mapped_sled_enospc.message(), None);
        assert_eq!(mapped_sled_enospc.to_string(), "insufficient storage");

        // 7. LedgerError::RefIndex(RefIndexError::Sled(Corruption)) -> StorageErrorKind::CorruptData
        let sled_corr = sled::Error::Corruption { at: None, bt: () };
        let ledger_sled_corr = LedgerError::RefIndex(RefIndexError::Sled(sled_corr));
        let expected_sled_corr_msg = ledger_sled_corr.to_string();
        let mapped_sled_corr = map_ledger_error(ledger_sled_corr);
        assert!(matches!(
            mapped_sled_corr,
            StorageError::Internal {
                kind: StorageErrorKind::CorruptData,
                ..
            }
        ));
        assert_eq!(
            mapped_sled_corr.internal_kind(),
            Some(StorageErrorKind::CorruptData)
        );
        assert_eq!(
            mapped_sled_corr.message(),
            Some(expected_sled_corr_msg.as_str())
        );
        assert_eq!(
            mapped_sled_corr.to_string(),
            format!("internal error: {expected_sled_corr_msg}")
        );

        // 8. LedgerError::RefIndex(RefIndexError::Corrupt) -> StorageErrorKind::CorruptData
        let ledger_ref_corr =
            LedgerError::RefIndex(RefIndexError::Corrupt("bad index checksum".to_string()));
        let expected_ref_corr_msg = ledger_ref_corr.to_string();
        let mapped_ref_corr = map_ledger_error(ledger_ref_corr);
        assert!(matches!(
            mapped_ref_corr,
            StorageError::Internal {
                kind: StorageErrorKind::CorruptData,
                ..
            }
        ));
        assert_eq!(
            mapped_ref_corr.internal_kind(),
            Some(StorageErrorKind::CorruptData)
        );
        assert_eq!(
            mapped_ref_corr.message(),
            Some(expected_ref_corr_msg.as_str())
        );
        assert_eq!(
            mapped_ref_corr.to_string(),
            format!("internal error: {expected_ref_corr_msg}")
        );

        // 9. LedgerError::RefIndex(RefIndexError::NotFound) -> StorageError::NotFound
        let ledger_ref_nf =
            LedgerError::RefIndex(RefIndexError::NotFound(PathBuf::from("/missing/db")));
        let mapped_ref_nf = map_ledger_error(ledger_ref_nf);
        assert!(matches!(mapped_ref_nf, StorageError::NotFound));
        assert_eq!(mapped_ref_nf.internal_kind(), None);
        assert_eq!(mapped_ref_nf.message(), None);
        assert_eq!(mapped_ref_nf.to_string(), "not found");

        // 10. LedgerError::Corrupt -> StorageErrorKind::CorruptData
        let ledger_corr = LedgerError::Corrupt("invalid marker schema".to_string());
        let expected_ledger_corr_msg = ledger_corr.to_string();
        let mapped_ledger_corr = map_ledger_error(ledger_corr);
        assert!(matches!(
            mapped_ledger_corr,
            StorageError::Internal {
                kind: StorageErrorKind::CorruptData,
                ..
            }
        ));
        assert_eq!(
            mapped_ledger_corr.internal_kind(),
            Some(StorageErrorKind::CorruptData)
        );
        assert_eq!(
            mapped_ledger_corr.message(),
            Some(expected_ledger_corr_msg.as_str())
        );
        assert_eq!(
            mapped_ledger_corr.to_string(),
            format!("internal error: {expected_ledger_corr_msg}")
        );

        // 11. LedgerError::IndexRequired -> StorageErrorKind::Configuration
        let ledger_idx_req = LedgerError::IndexRequired("secondary index is mandatory".to_string());
        let expected_idx_req_msg = ledger_idx_req.to_string();
        let mapped_idx_req = map_ledger_error(ledger_idx_req);
        assert!(matches!(
            mapped_idx_req,
            StorageError::Internal {
                kind: StorageErrorKind::Configuration,
                ..
            }
        ));
        assert_eq!(
            mapped_idx_req.internal_kind(),
            Some(StorageErrorKind::Configuration)
        );
        assert_eq!(
            mapped_idx_req.message(),
            Some(expected_idx_req_msg.as_str())
        );
        assert_eq!(
            mapped_idx_req.to_string(),
            format!("internal error: {expected_idx_req_msg}")
        );
    }

    #[tokio::test]
    async fn test_find_blob_reference_with_sha512_manifest_root() {
        let root = tmp_fs_root();
        let storage = Arc::new(FsStorage::new(root.clone(), 1024 * 1024));

        let repo = "testrepo";
        let blob_bytes = b"sample layer data for deletion safety";
        let blob_hex = hex::encode(Sha256::digest(blob_bytes));
        let blob_digest = Digest::parse(&format!("sha256:{blob_hex}")).unwrap();

        // 1. Put blob into storage
        let upload = storage.create_upload().await.unwrap();
        storage
            .append_upload(&upload.uuid, bytes::Bytes::from_static(blob_bytes))
            .await
            .unwrap();
        storage
            .finalize_upload(&upload.uuid, &blob_digest)
            .await
            .unwrap();

        // 2. Create manifest referencing this blob
        let manifest_json = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 0
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": blob_digest.as_str(),
                    "size": blob_bytes.len()
                }
            ]
        });
        let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap();
        let manifest_hex = hex::encode(Sha512::digest(&manifest_bytes));
        let manifest_digest = Digest::parse(&format!("sha512:{manifest_hex}")).unwrap();

        storage
            .put_manifest(repo, &manifest_digest, bytes::Bytes::from(manifest_bytes))
            .await
            .unwrap();
        storage
            .set_tag(repo, "v1.0", &manifest_digest)
            .await
            .unwrap();

        // 3. Find reference to target blob
        let found = find_blob_reference(&storage, &blob_digest)
            .await
            .unwrap()
            .expect("should find reference in sha512 manifest root");

        assert_eq!(found.repo, repo);
        assert_eq!(found.tag.as_deref(), Some("v1.0"));
        assert_eq!(found.manifest, manifest_digest.as_str());

        let _ = std::fs::remove_dir_all(&root);
    }
}
