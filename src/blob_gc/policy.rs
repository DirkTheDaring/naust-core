use crate::blob_ref_index::BlobRefIndex;
use crate::manifest_refs::{ManifestParseError, parse_manifest_refs};
use crate::registry::digest::Digest;
use crate::storage;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum BlobGcPolicy {
    /// Consider a blob "in use" only if reachable from any tag root.
    TagRooted,
    /// Consider a blob "in use" if reachable from any stored manifest (tagged or untagged).
    ManifestRooted,
}

impl Default for BlobGcPolicy {
    fn default() -> Self {
        Self::ManifestRooted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeEligibility {
    Eligible,
    IneligibleAge,
    FutureTimestamp,
    MissingTimestamp,
}

/// Authoritative age/grace eligibility evaluation for GC candidates across all storage backends.
///
/// Invariants:
/// - Missing or unparseable timestamps (`last_modified == UNIX_EPOCH`) fail closed as `MissingTimestamp`.
/// - Future timestamps (`last_modified > now`) fail closed as `FutureTimestamp`.
/// - Elapsed age < `min_age` returns `IneligibleAge`.
/// - Elapsed age >= `min_age` returns `Eligible`.
/// - Zero grace (`min_age == 0`) with valid past timestamp returns `Eligible`.
pub fn check_candidate_age(
    last_modified: SystemTime,
    now: SystemTime,
    min_age: Duration,
) -> AgeEligibility {
    if last_modified == UNIX_EPOCH {
        return AgeEligibility::MissingTimestamp;
    }
    match now.duration_since(last_modified) {
        Ok(age) => {
            if age >= min_age {
                AgeEligibility::Eligible
            } else {
                AgeEligibility::IneligibleAge
            }
        }
        Err(_) => AgeEligibility::FutureTimestamp,
    }
}

/// Typed error model for policy evaluation, reachability traversal, and root set construction.
#[derive(Debug, thiserror::Error)]
pub enum GcPolicyError {
    #[error("reference index health check failed: {0}")]
    IndexHealth(#[from] crate::blob_ref_index::RefIndexError),

    #[error("repository enumeration failed: {0}")]
    ListRepositories(#[source] crate::storage::StorageError),

    #[error("manifest listing failed for repository '{repository}': {source}")]
    ListManifests {
        repository: String,
        #[source]
        source: crate::storage::StorageError,
    },

    #[error("failed to read manifest '{digest}' in repository '{repository}': {source}")]
    ReadManifest {
        repository: String,
        digest: String,
        #[source]
        source: crate::storage::StorageError,
    },

    #[error(
        "failed to parse manifest references for '{digest}' in repository '{repository}': {source}"
    )]
    ParseManifest {
        repository: String,
        digest: String,
        #[source]
        source: ManifestParseError,
    },

    #[error("contained manifest discovery failed: {0}")]
    ManifestDiscovery(#[source] crate::storage::StorageError),

    #[error("filesystem traversal failed for '{path}': {source}")]
    FsReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read manifest file '{path}': {source}")]
    FsReadManifest {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub struct PolicyContext {
    pub(crate) policy: BlobGcPolicy,
    pub(crate) idx: Arc<BlobRefIndex>,
    pub(crate) manifest_protected: Option<HashSet<String>>,
}

impl PolicyContext {
    pub async fn build(
        storage: &(impl storage::GcServiceStoragePort + ?Sized),
        idx: &BlobRefIndex,
        policy: BlobGcPolicy,
    ) -> Result<Self, GcPolicyError> {
        idx.check_health()?;

        let idx = Arc::new(idx.clone());

        let manifest_protected = match policy {
            BlobGcPolicy::TagRooted => None,
            BlobGcPolicy::ManifestRooted => Some(build_manifest_protected_set(storage).await?),
        };

        Ok(Self {
            policy,
            idx,
            manifest_protected,
        })
    }

    pub async fn is_referenced(
        &mut self,
        digest: &Digest,
    ) -> Result<bool, crate::blob_ref_index::RefIndexError> {
        let tag_reachable = self.idx.is_blob_referenced(digest)?;
        if tag_reachable {
            return Ok(true);
        }

        if self.policy == BlobGcPolicy::ManifestRooted {
            let Some(set) = self.manifest_protected.as_ref() else {
                return Ok(false);
            };
            return Ok(set.contains(&digest.as_str()));
        }

        Ok(false)
    }

    pub fn is_pinned(
        &self,
        digest: &Digest,
        now: SystemTime,
    ) -> Result<bool, crate::blob_ref_index::RefIndexError> {
        self.idx.is_blob_pinned(digest, now)
    }
}

pub async fn build_manifest_protected_set(
    storage: &(impl storage::GcServiceStoragePort + ?Sized),
) -> Result<HashSet<String>, GcPolicyError> {
    if let Some(set) = storage
        .discover_manifest_references()
        .await
        .map_err(GcPolicyError::ManifestDiscovery)?
    {
        return Ok(set.into_iter().map(|d| d.to_string()).collect());
    }

    let repos = storage
        .list_repositories()
        .await
        .map_err(GcPolicyError::ListRepositories)?;

    let mut protected = HashSet::new();
    for repo in repos {
        let mut cursor = None;
        loop {
            let (digests, next_cursor) = storage
                .list_manifest_digests_page(&repo, cursor.as_deref(), 100)
                .await
                .map_err(|source| GcPolicyError::ListManifests {
                    repository: repo.clone(),
                    source,
                })?;

            for digest in digests {
                protected.insert(digest.as_str().to_string());
                let (_meta, bytes) =
                    storage
                        .get_manifest(&repo, &digest)
                        .await
                        .map_err(|source| GcPolicyError::ReadManifest {
                            repository: repo.clone(),
                            digest: digest.to_string(),
                            source,
                        })?;
                let refs =
                    parse_manifest_refs(&bytes).map_err(|source| GcPolicyError::ParseManifest {
                        repository: repo.clone(),
                        digest: digest.to_string(),
                        source,
                    })?;
                for r in refs.all_references() {
                    protected.insert(r.as_str().to_string());
                }
            }

            if next_cursor.is_none() {
                break;
            }
            cursor = next_cursor;
        }
    }

    Ok(protected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_ref_index::BlobRefIndex;
    use std::sync::Arc;

    #[cfg(target_os = "linux")]
    use crate::storage::fs::FsStorage;
    #[cfg(target_os = "linux")]
    use crate::storage::ports::{GcServiceStoragePort, GcStoragePort, ManifestReader};
    #[cfg(target_os = "linux")]
    use naust_storage_fs::DirEnumerationLimits;

    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    struct PermissionsRestorationGuard {
        path: PathBuf,
        original_permissions: std::fs::Permissions,
        restored: bool,
    }

    #[cfg(unix)]
    impl PermissionsRestorationGuard {
        fn capture(path: PathBuf) -> std::io::Result<Self> {
            let original_permissions = std::fs::metadata(&path)?.permissions();
            Ok(Self {
                path,
                original_permissions,
                restored: false,
            })
        }

        fn restore(&mut self) -> std::io::Result<()> {
            if !self.restored {
                std::fs::set_permissions(&self.path, self.original_permissions.clone())?;
                self.restored = true;
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    impl Drop for PermissionsRestorationGuard {
        fn drop(&mut self) {
            if !self.restored {
                if let Err(e) =
                    std::fs::set_permissions(&self.path, self.original_permissions.clone())
                {
                    eprintln!(
                        "PermissionsRestorationGuard failed to restore permissions on {:?}: {}",
                        self.path, e
                    );
                } else {
                    self.restored = true;
                }
            }
        }
    }

    fn make_test_manifest_json(config_digest: &str, layer_digest: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 123,
                "digest": config_digest
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": 456,
                    "digest": layer_digest
                }
            ]
        }))
        .unwrap()
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_gc_manifest_discovery_branch_selection_fs_vs_storage_port() {
        let temp = tempfile::tempdir().unwrap();
        let fs_root = temp.path().to_path_buf();
        let manifests_dir = fs_root.join("repos").join("test-repo").join("manifests");
        tokio::fs::create_dir_all(&manifests_dir).await.unwrap();

        let hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let cfg_digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let layer_digest =
            "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        tokio::fs::write(
            manifests_dir.join(hex),
            make_test_manifest_json(cfg_digest, layer_digest),
        )
        .await
        .unwrap();

        let storage = Arc::new(FsStorage::new(fs_root.clone(), 50 * 1024 * 1024));

        // Case 1: fs storage with an existing repos/ tree — contained discovery succeeds.
        assert_eq!(storage.kind(), "fs");
        assert!(tokio::fs::metadata(fs_root.join("repos")).await.is_ok());
        let protected_fs = build_manifest_protected_set(storage.as_ref())
            .await
            .expect("fs bypass discovery should succeed");
        assert!(protected_fs.contains(&format!("sha256:{hex}")));
        assert!(protected_fs.contains(cfg_digest));
        assert!(protected_fs.contains(layer_digest));

        // Case 2: contained discovery reads the storage's pinned root, so an unrelated
        // (even non-existent) ambient path is irrelevant; the port still serves the set.
        let non_existent_root = temp.path().join("non_existent_root");
        assert!(
            tokio::fs::metadata(non_existent_root.join("repos"))
                .await
                .is_err()
        );
        // Falls back to storage.list_repositories()
        let protected_fallback = build_manifest_protected_set(storage.as_ref())
            .await
            .expect("fallback to storage port should succeed");
        assert!(protected_fallback.contains(&format!("sha256:{hex}")));
        assert!(protected_fallback.contains(cfg_digest));
        assert!(protected_fallback.contains(layer_digest));

        // Case 3: s3 storage — discovery is served entirely by the storage port.
        let (s3_storage, driver) = crate::storage::s3::tests::create_mock_storage();
        let s3_arc: Arc<dyn GcServiceStoragePort> = Arc::new(s3_storage);
        assert_eq!(s3_arc.kind(), "s3");
        assert!(tokio::fs::metadata(fs_root.join("repos")).await.is_ok());
        // Mock S3 driver currently has no repos in objects table -> returns empty
        let protected_s3 = build_manifest_protected_set(s3_arc.as_ref())
            .await
            .expect("s3 port path should succeed");
        assert!(protected_s3.is_empty());
        // Populate mock S3 repo and manifest
        let manifest_bytes = make_test_manifest_json(cfg_digest, layer_digest);
        let s3_manifest_key = format!("repos/s3-repo/manifests/{hex}");
        driver.objects.lock().unwrap().insert(
            s3_manifest_key,
            (bytes::Bytes::from(manifest_bytes), "\"etag\"".to_string()),
        );
        let protected_s3_populated = build_manifest_protected_set(s3_arc.as_ref())
            .await
            .expect("s3 port path with repo should succeed");
        assert!(protected_s3_populated.contains(&format!("sha256:{hex}")));
        assert!(protected_s3_populated.contains(cfg_digest));
        assert!(protected_s3_populated.contains(layer_digest));
    }

    #[tokio::test]
    async fn test_gc_manifest_discovery_missing_and_empty_repository_trees() {
        let temp = tempfile::tempdir().unwrap();
        let fs_root = temp.path();

        // 1. Missing repos directory completely
        let storage = FsStorage::new(fs_root.to_path_buf(), 10 * 1024 * 1024);
        let protected_missing = build_manifest_protected_set(&storage).await.unwrap();
        assert!(protected_missing.is_empty());

        // 2. Empty repos directory
        let repos = fs_root.join("repos");
        tokio::fs::create_dir_all(&repos).await.unwrap();
        let protected_empty_repos = build_manifest_protected_set(&storage).await.unwrap();
        assert!(protected_empty_repos.is_empty());

        // 3. Repo directory with no manifests/ directory
        tokio::fs::create_dir_all(repos.join("empty-repo"))
            .await
            .unwrap();
        let protected_no_manifests = build_manifest_protected_set(&storage).await.unwrap();
        assert!(protected_no_manifests.is_empty());

        // 4. manifests/ directory exists but is completely empty
        tokio::fs::create_dir_all(repos.join("empty-repo").join("manifests"))
            .await
            .unwrap();
        let protected_empty_manifests = build_manifest_protected_set(&storage).await.unwrap();
        assert!(protected_empty_manifests.is_empty());
    }

    #[tokio::test]
    async fn test_gc_manifest_discovery_sha256_and_sha512_protected() {
        let temp = tempfile::tempdir().unwrap();
        let fs_root = temp.path();
        let manifests_dir = fs_root.join("repos").join("dual-repo").join("manifests");
        tokio::fs::create_dir_all(&manifests_dir).await.unwrap();

        // Valid 64-character lowercase hex SHA-256 manifest
        let sha256_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let sha256_cfg = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let sha256_layer =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        tokio::fs::write(
            manifests_dir.join(sha256_hex),
            make_test_manifest_json(sha256_cfg, sha256_layer),
        )
        .await
        .unwrap();

        // Valid 128-character lowercase hex SHA-512 manifest
        let sha512_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let sha512_cfg = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let sha512_layer =
            "sha256:4444444444444444444444444444444444444444444444444444444444444444";
        tokio::fs::write(
            manifests_dir.join(sha512_hex),
            make_test_manifest_json(sha512_cfg, sha512_layer),
        )
        .await
        .unwrap();

        let storage = FsStorage::new(fs_root.to_path_buf(), 10 * 1024 * 1024);
        let protected = build_manifest_protected_set(&storage).await.unwrap();

        // Both SHA-256 and SHA-512 manifests and their referenced blobs MUST be protected
        assert!(protected.contains(&format!("sha256:{sha256_hex}")));
        assert!(protected.contains(sha256_cfg));
        assert!(protected.contains(sha256_layer));

        assert!(protected.contains(&format!("sha512:{sha512_hex}")));
        assert!(protected.contains(sha512_cfg));
        assert!(protected.contains(sha512_layer));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_gc_manifest_discovery_name_filtering() {
        let temp = tempfile::tempdir().unwrap();
        let manifests_dir = temp
            .path()
            .join("repos")
            .join("filter-repo")
            .join("manifests");
        tokio::fs::create_dir_all(&manifests_dir).await.unwrap();

        let dummy_content = make_test_manifest_json(
            "sha256:1234567890123456789012345678901234567890123456789012345678901234",
            "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        );

        // 1. Prefixed name (e.g. "sha256:<hex>") -> len == 71 != 64 -> skipped
        let prefixed = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        tokio::fs::write(manifests_dir.join(prefixed), &dummy_content)
            .await
            .unwrap();

        // 2. Uppercase hex (64 chars) -> passes is_ascii_hexdigit() -> accepted, but inserted as uppercase
        let uppercase = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        tokio::fs::write(manifests_dir.join(uppercase), &dummy_content)
            .await
            .unwrap();

        // 3. Temporary upload files -> skipped
        tokio::fs::write(
            manifests_dir
                .join(".tmp_upload_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            &dummy_content,
        )
        .await
        .unwrap();
        tokio::fs::write(
            manifests_dir
                .join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tmp"),
            &dummy_content,
        )
        .await
        .unwrap();

        // 4. Malformed hex (64 chars but non-hex 'zz') -> skipped
        let malformed = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccczz";
        tokio::fs::write(manifests_dir.join(malformed), &dummy_content)
            .await
            .unwrap();

        // 5. Non-UTF-8 filename -> skipped (to_str returns None)
        let non_utf8_name = std::ffi::OsStr::from_bytes(b"invalid\xff\xfe\xfdhexname");
        tokio::fs::write(manifests_dir.join(non_utf8_name), &dummy_content)
            .await
            .unwrap();
        let storage = Arc::new(FsStorage::new(temp.path().to_path_buf(), 50 * 1024 * 1024));
        let protected = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();

        assert!(!protected.contains(prefixed));
        assert!(!protected.contains(&format!("sha256:{prefixed}")));
        assert!(!protected.contains(&format!("sha256:{malformed}")));

        // Contained discovery enforces lowercase hex [0-9a-f] (D-08), skipping uppercase hex
        assert!(!protected.contains(&format!("sha256:{uppercase}")));
        assert!(!protected.contains(&format!("sha256:{}", uppercase.to_lowercase())));
    }

    #[tokio::test]
    async fn test_gc_manifest_discovery_nested_repository_paths() {
        let temp = tempfile::tempdir().unwrap();

        // Deeply nested repository: repos/org/dept/team/project/service/manifests
        let deep_manifests = temp
            .path()
            .join("repos")
            .join("org")
            .join("dept")
            .join("team")
            .join("project")
            .join("service")
            .join("manifests");
        tokio::fs::create_dir_all(&deep_manifests).await.unwrap();

        let hex_deep = "1234123412341234123412341234123412341234123412341234123412341234";
        let cfg_deep = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let layer_deep = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        tokio::fs::write(
            deep_manifests.join(hex_deep),
            make_test_manifest_json(cfg_deep, layer_deep),
        )
        .await
        .unwrap();

        // Root-adjacent repository: repos/manifests
        let root_adj_manifests = temp.path().join("repos").join("manifests");
        tokio::fs::create_dir_all(&root_adj_manifests)
            .await
            .unwrap();
        let hex_root_adj = "5678567856785678567856785678567856785678567856785678567856785678";
        let cfg_root_adj =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let layer_root_adj =
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        tokio::fs::write(
            root_adj_manifests.join(hex_root_adj),
            make_test_manifest_json(cfg_root_adj, layer_root_adj),
        )
        .await
        .unwrap();
        let storage = Arc::new(FsStorage::new(temp.path().to_path_buf(), 50 * 1024 * 1024));
        let protected = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();

        assert!(protected.contains(&format!("sha256:{hex_deep}")));
        assert!(protected.contains(cfg_deep));
        assert!(protected.contains(layer_deep));

        assert!(protected.contains(&format!("sha256:{hex_root_adj}")));
        assert!(protected.contains(cfg_root_adj));
        assert!(protected.contains(layer_root_adj));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_gc_manifest_discovery_symlink_entries_skipped() {
        let temp = tempfile::tempdir().unwrap();
        let repos = temp.path().join("repos");
        tokio::fs::create_dir_all(&repos).await.unwrap();

        // Create external directory outside repos
        let external = temp.path().join("external_repo");
        let ext_manifests = external.join("manifests");
        tokio::fs::create_dir_all(&ext_manifests).await.unwrap();

        let hex_target = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cfg_target = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let layer_target =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let manifest_content = make_test_manifest_json(cfg_target, layer_target);
        let real_manifest_path = ext_manifests.join(hex_target);
        tokio::fs::write(&real_manifest_path, &manifest_content)
            .await
            .unwrap();

        // 1. Symlink directory entry in repos/ pointing to external directory
        let symlink_repo = repos.join("symlink_repo");
        std::os::unix::fs::symlink(&external, &symlink_repo).unwrap();

        // 2. Symlink file entry in real repo manifests/ pointing to real manifest file
        let real_repo_manifests = repos.join("real_repo").join("manifests");
        tokio::fs::create_dir_all(&real_repo_manifests)
            .await
            .unwrap();
        let symlink_manifest_path = real_repo_manifests
            .join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        std::os::unix::fs::symlink(&real_manifest_path, &symlink_manifest_path).unwrap();
        let storage = Arc::new(FsStorage::new(temp.path().to_path_buf(), 50 * 1024 * 1024));
        let protected = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();

        // Symlink directory is skipped by contained traversal
        assert!(!protected.contains(&format!("sha256:{hex_target}")));
        // Symlink file is skipped by contained file open
        assert!(
            !protected.contains(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            )
        );
        assert!(!protected.contains(cfg_target));
        assert!(!protected.contains(layer_target));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_gc_manifest_discovery_symlinked_initial_root_traversed() {
        let temp = tempfile::tempdir().unwrap();

        // Create target directory with repo and manifest
        let real_data = temp.path().join("real_data");
        let real_manifests = real_data.join("repos").join("my-repo").join("manifests");
        tokio::fs::create_dir_all(&real_manifests).await.unwrap();

        let hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let cfg_d = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let layer_d = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
        tokio::fs::write(
            real_manifests.join(hex),
            make_test_manifest_json(cfg_d, layer_d),
        )
        .await
        .unwrap();

        // Create symlinked root pointing to real_data
        let link_root = temp.path().join("link_root");
        std::os::unix::fs::symlink(&real_data, &link_root).unwrap();

        // Initial root symlink is resolved at initialization; contained discovery then traverses real_data
        let storage = Arc::new(FsStorage::new(link_root.clone(), 50 * 1024 * 1024));
        let protected = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();
        assert!(protected.contains(&format!("sha256:{hex}")));
        assert!(protected.contains(cfg_d));
        assert!(protected.contains(layer_d));
    }

    #[tokio::test]
    async fn test_gc_manifest_discovery_entry_type_filtering() {
        let temp = tempfile::tempdir().unwrap();
        let repos = temp.path().join("repos");
        let manifests = repos.join("my-repo").join("manifests");
        tokio::fs::create_dir_all(&manifests).await.unwrap();

        // 1. Regular file directly under repos/ (not a directory) -> skipped
        tokio::fs::write(repos.join("README.txt"), b"documentation")
            .await
            .unwrap();

        // 2. Subdirectory inside manifests/ (not a regular file) -> skipped
        tokio::fs::create_dir_all(
            manifests.join("1111111111111111111111111111111111111111111111111111111111111111"),
        )
        .await
        .unwrap();

        // 3. Valid regular file manifest
        let hex = "2222222222222222222222222222222222222222222222222222222222222222";
        let cfg_d = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
        let layer_d = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
        tokio::fs::write(manifests.join(hex), make_test_manifest_json(cfg_d, layer_d))
            .await
            .unwrap();
        let storage = Arc::new(FsStorage::new(temp.path().to_path_buf(), 50 * 1024 * 1024));
        let protected = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();
        assert!(protected.contains(&format!("sha256:{hex}")));
        assert!(protected.contains(cfg_d));
        assert!(protected.contains(layer_d));
    }

    #[tokio::test]
    async fn test_gc_manifest_discovery_read_parse_errors_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let manifests = temp
            .path()
            .join("repos")
            .join("fail-repo")
            .join("manifests");
        tokio::fs::create_dir_all(&manifests).await.unwrap();
        let storage = Arc::new(FsStorage::new(temp.path().to_path_buf(), 50 * 1024 * 1024));

        // Case A: Corrupted JSON content -> GcPolicyError::ManifestDiscovery(corrupt_data)
        let corrupt_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        tokio::fs::write(manifests.join(corrupt_hex), b"{not-valid-json")
            .await
            .unwrap();

        let err = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap_err();
        assert!(
            matches!(err, GcPolicyError::ManifestDiscovery(ref e) if e.internal_kind() == Some(crate::storage::StorageErrorKind::CorruptData)),
            "corrupted manifest JSON must fail closed with ManifestDiscovery error; got: {err:?}"
        );

        // Remove corrupt file
        tokio::fs::remove_file(manifests.join(corrupt_hex))
            .await
            .unwrap();

        // Case B: Manifest with unparseable/invalid digest in descriptor -> GcPolicyError::ManifestDiscovery(corrupt_data)
        let invalid_desc_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let invalid_desc_json = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "config": { "digest": "sha256:invalid-hex" },
            "layers": []
        }))
        .unwrap();
        tokio::fs::write(manifests.join(invalid_desc_hex), &invalid_desc_json)
            .await
            .unwrap();

        let err = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap_err();
        assert!(
            matches!(err, GcPolicyError::ManifestDiscovery(ref e) if e.internal_kind() == Some(crate::storage::StorageErrorKind::CorruptData)),
            "invalid digest in manifest must fail closed with ManifestDiscovery error; got: {err:?}"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    #[ignore = "Requires effective unprivileged permissions; root/CAP_DAC_OVERRIDE bypasses mode 000"]
    async fn test_gc_manifest_discovery_unreadable_manifest_permission_denied_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let manifests = temp
            .path()
            .join("repos")
            .join("fail-repo")
            .join("manifests");
        tokio::fs::create_dir_all(&manifests).await.unwrap();

        let unreadable_hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let unreadable_path = manifests.join(unreadable_hex);
        tokio::fs::write(&unreadable_path, b"some content")
            .await
            .unwrap();

        let mut guard = PermissionsRestorationGuard::capture(unreadable_path.clone())
            .expect("must capture original file permissions");
        std::fs::set_permissions(&unreadable_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let storage = Arc::new(FsStorage::new(temp.path().to_path_buf(), 50 * 1024 * 1024));
        let read_res = build_manifest_protected_set(storage.as_ref()).await;
        let err = read_res.expect_err("unreadable manifest must fail closed");

        guard
            .restore()
            .expect("explicit permission restoration must succeed");

        match err {
            GcPolicyError::ManifestDiscovery(ref storage_err) => {
                assert!(
                    storage_err.to_string().contains("Permission")
                        || format!("{storage_err:?}").contains("PermissionDenied")
                        || format!("{storage_err:?}").contains("Os { code: 13"),
                    "underlying error must reflect permission denied, got: {storage_err:?}"
                );
            }
            other => panic!("expected ManifestDiscovery, got: {other:?}"),
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    #[ignore = "Requires effective unprivileged permissions; root/CAP_DAC_OVERRIDE bypasses mode 000"]
    async fn test_gc_manifest_discovery_unreadable_directory_permission_denied_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let unreadable_dir = temp.path().join("repos").join("unreadable_dir");
        tokio::fs::create_dir_all(&unreadable_dir).await.unwrap();

        let mut guard = PermissionsRestorationGuard::capture(unreadable_dir.clone())
            .expect("must capture original directory permissions");
        std::fs::set_permissions(&unreadable_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let storage = Arc::new(FsStorage::new(temp.path().to_path_buf(), 50 * 1024 * 1024));
        let res = build_manifest_protected_set(storage.as_ref()).await;
        let err = res.expect_err("unreadable directory must fail closed");

        guard
            .restore()
            .expect("explicit permission restoration must succeed");

        match err {
            GcPolicyError::ManifestDiscovery(ref storage_err) => {
                assert!(
                    storage_err.to_string().contains("Permission")
                        || format!("{storage_err:?}").contains("PermissionDenied")
                        || format!("{storage_err:?}").contains("Os { code: 13"),
                    "underlying error must reflect permission denied, got: {storage_err:?}"
                );
            }
            other => panic!("expected ManifestDiscovery, got: {other:?}"),
        }
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_gc_manifest_discovery_ignores_configured_manifest_listing_budgets() {
        let temp = tempfile::tempdir().unwrap();
        let fs_root = temp.path().to_path_buf();
        let manifests_dir = fs_root.join("repos").join("budget-repo").join("manifests");
        tokio::fs::create_dir_all(&manifests_dir).await.unwrap();

        // Write 5 distinct valid manifests with unique config and layer digests
        let mut digests = Vec::new();
        for i in 0..5 {
            let hex = format!("a{i:063x}");
            let cfg_d = format!("sha256:b{i:063x}");
            let layer_d = format!("sha256:c{i:063x}");
            tokio::fs::write(
                manifests_dir.join(&hex),
                make_test_manifest_json(&cfg_d, &layer_d),
            )
            .await
            .unwrap();
            digests.push(format!("sha256:{hex}"));
        }

        // Configure FsStorage with restrictive listing limit of max_entries = 1
        let storage = Arc::new(
            FsStorage::try_new_with_limits(
                fs_root.clone(),
                50 * 1024 * 1024,
                DirEnumerationLimits::new(1, 100_000),
            )
            .unwrap(),
        );

        // FsStorage listing streams manifests without artificial listing bounds
        let (page, _) = storage
            .list_manifest_digests_page("budget-repo", None, 10)
            .await
            .expect("manifest listing must succeed under unbounded streaming");
        assert_eq!(page.len(), 5);

        // Contained GC discovery uses independent GC limits (not public listing limits), discovering all 5 manifests
        let protected = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();
        for d in &digests {
            assert!(
                protected.contains(d),
                "GC discovery uses independent GC budgets rather than listing budgets"
            );
        }
        assert_eq!(
            protected.len(),
            15,
            "5 manifests * (1 manifest + 1 config + 1 layer) = 15 protected items"
        );
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_gc_manifest_discovery_pathname_divergence_from_pinned_storage() {
        let temp_a = tempfile::tempdir().unwrap();
        let temp_b = tempfile::tempdir().unwrap();

        let fs_root_a = temp_a.path().to_path_buf();
        let fs_root_b = temp_b.path().to_path_buf();

        // Repo A in fs_root_a
        let manifests_a = fs_root_a.join("repos").join("repo-a").join("manifests");
        tokio::fs::create_dir_all(&manifests_a).await.unwrap();
        let hex_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        tokio::fs::write(
            manifests_a.join(hex_a),
            make_test_manifest_json(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            ),
        )
        .await
        .unwrap();

        // Repo B in fs_root_b
        let manifests_b = fs_root_b.join("repos").join("repo-b").join("manifests");
        tokio::fs::create_dir_all(&manifests_b).await.unwrap();
        let hex_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        tokio::fs::write(
            manifests_b.join(hex_b),
            make_test_manifest_json(
                "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            ),
        )
        .await
        .unwrap();

        // Storage is initialized pointing to fs_root_a
        let storage = Arc::new(FsStorage::new(fs_root_a.clone(), 50 * 1024 * 1024));

        // Config points to distinct root fs_root_b

        // Contained discovery operates exclusively on storage's pinned root (fs_root_a),
        // completely eliminating divergence with fs_root.
        let protected = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();
        assert!(
            protected.contains(&format!("sha256:{hex_a}")),
            "contained discovery must read storage's pinned root (fs_root_a)"
        );
        assert!(
            !protected.contains(&format!("sha256:{hex_b}")),
            "contained discovery must not read fs_root (fs_root_b)"
        );

        // Even if repos in fs_root_b is deleted, discovery on storage still returns repo-a manifests
        tokio::fs::remove_dir_all(fs_root_b.join("repos"))
            .await
            .unwrap();
        let protected_after_removal = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();
        assert!(protected_after_removal.contains(&format!("sha256:{hex_a}")));
        assert!(!protected_after_removal.contains(&format!("sha256:{hex_b}")));
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn test_gc_manifest_discovery_policy_context_fails_closed_on_discovery_error() {
        let temp = tempfile::tempdir().unwrap();
        let fs_root = temp.path().to_path_buf();
        let storage = Arc::new(FsStorage::new(fs_root.clone(), 50 * 1024 * 1024));

        let idx_path = temp.path().join("ref-index");
        let idx = Arc::new(BlobRefIndex::open(idx_path).unwrap());
        idx.ensure_healthy_or_rebuild(storage.as_ref(), true, true)
            .await
            .unwrap();

        // Write corrupt manifest file after index is initialized
        let manifests_dir = fs_root.join("repos").join("fail-repo").join("manifests");
        tokio::fs::create_dir_all(&manifests_dir).await.unwrap();
        let hex = "1111111111111111111111111111111111111111111111111111111111111111";
        tokio::fs::write(manifests_dir.join(hex), b"invalid-manifest-bytes")
            .await
            .unwrap();

        // 1. ManifestRooted policy MUST fail closed when manifest discovery fails
        let res_manifest_rooted =
            PolicyContext::build(storage.as_ref(), &idx, BlobGcPolicy::ManifestRooted).await;
        let err = match res_manifest_rooted {
            Err(e) => e,
            Ok(_) => panic!("manifest rooted build should have failed"),
        };
        assert!(
            matches!(err, GcPolicyError::ManifestDiscovery(ref e) if e.internal_kind() == Some(crate::storage::StorageErrorKind::CorruptData)),
            "manifest rooted build must fail closed with ManifestDiscovery error; got: {err:?}"
        );

        // 2. TagRooted policy does not build manifest protected set, so it succeeds
        assert!(
            PolicyContext::build(storage.as_ref(), &idx, BlobGcPolicy::TagRooted)
                .await
                .is_ok()
        );
    }
}
