pub mod policy;
pub mod traverser;
pub mod validation;

pub use policy::{
    AgeEligibility, BlobGcPolicy, GcPolicyError, PolicyContext, build_manifest_protected_set,
    check_candidate_age,
};
pub use traverser::{CasBlobTraverser, GcPaginationError};
pub(crate) use validation::execute_guarded_gc_deletion;
pub use validation::{
    GcCandidateDeletionError, GcCandidateDeletionOutcome, GcProtectionReason, PreDeleteValidation,
};

use crate::blob_ref_index::BlobRefIndex;
use crate::registry::digest::Digest;
use crate::storage;
use crate::storage::mutation_authority::RuntimeMutationAuthority;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum BlobGcError {
    #[error("policy evaluation error: {0}")]
    Policy(#[from] policy::GcPolicyError),

    #[error("pagination error: {0}")]
    Pagination(#[from] traverser::GcPaginationError),

    #[error("reference index error: {0}")]
    RefIndex(#[from] crate::blob_ref_index::RefIndexError),

    #[error("mutation authority unavailable or inactive")]
    AuthorityUnavailable,

    #[error("mutation authority released")]
    AuthorityReleased,

    #[error("guarded deletion failed: {0}")]
    CandidateDeletion(#[from] validation::GcCandidateDeletionError),

    #[error("quarantine storage mutation failed for candidate {digest}: {source}")]
    QuarantineStorage {
        digest: Digest,
        #[source]
        source: crate::storage::StorageError,
    },

    #[error("restore storage mutation failed for candidate {digest}: {source}")]
    RestoreStorage {
        digest: Digest,
        #[source]
        source: crate::storage::StorageError,
    },

    #[error("storage version query failed for candidate {digest}: {source}")]
    QuarantineVersionQuery {
        digest: Digest,
        #[source]
        source: crate::storage::StorageError,
    },

    #[error("membership count query failed for candidate {digest}: {source}")]
    MembershipCountQuery {
        digest: Digest,
        #[source]
        source: crate::storage::StorageError,
    },

    #[error("bucket versioning check failed for GC: {0}")]
    BucketVersioning(#[source] crate::storage::StorageError),

    #[error("filesystem traversal failed at '{path}': {source}")]
    FsReadDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("filesystem metadata write failed at '{path}': {source}")]
    FsWriteMeta {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("filesystem metadata read failed at '{path}': {source}")]
    FsReadMeta {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Default, Clone)]
pub struct BlobGcStats {
    pub scanned_blobs: u64,
    pub scanned_bytes: u64,
    pub eligible_blobs: u64,
    pub eligible_bytes: u64,
    pub quarantined_blobs: u64,
    pub quarantined_bytes: u64,
    pub restored_blobs: u64,
    pub restored_bytes: u64,
    pub deleted_blobs: u64,
    pub deleted_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct BlobGcLimits {
    pub max_per_run: usize,
    pub max_bytes: u64,
    pub max_seconds: u64,
}

impl BlobGcLimits {
    pub fn unlimited(max_per_run: usize) -> Self {
        Self {
            max_per_run,
            max_bytes: u64::MAX,
            max_seconds: u64::MAX,
        }
    }
}

pub async fn blob_gc_plan(
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    policy: BlobGcPolicy,
    min_age: Duration,
    limits: BlobGcLimits,
) -> Result<BlobGcStats, BlobGcError> {
    let mut policy_ctx = PolicyContext::build(storage, idx, policy).await?;
    let mut stats = BlobGcStats::default();

    let t0 = Instant::now();
    let now = SystemTime::now();

    let mut traverser = CasBlobTraverser::new(storage, 100);

    while let Some(items) = traverser.next_batch().await? {
        for candidate in items {
            if t0.elapsed() > Duration::from_secs(limits.max_seconds) {
                return Ok(stats);
            }

            match check_candidate_age(candidate.last_modified, now, min_age) {
                AgeEligibility::Eligible => {}
                _ => continue,
            }

            if policy_ctx.is_pinned(&candidate.digest, now)? {
                continue;
            }

            stats.scanned_blobs += 1;
            stats.scanned_bytes = stats.scanned_bytes.saturating_add(candidate.size);

            if stats.eligible_blobs as usize >= limits.max_per_run {
                continue;
            }
            if policy_ctx.is_referenced(&candidate.digest).await? {
                continue;
            }

            let mem_count = storage
                .count_repo_blob_memberships(&candidate.digest)
                .await
                .map_err(|source| BlobGcError::MembershipCountQuery {
                    digest: candidate.digest.clone(),
                    source,
                })?;
            if mem_count > 0 {
                continue;
            }

            if stats.eligible_bytes >= limits.max_bytes {
                continue;
            }
            stats.eligible_blobs += 1;
            stats.eligible_bytes = stats.eligible_bytes.saturating_add(candidate.size);
        }

        if t0.elapsed() > Duration::from_secs(limits.max_seconds) {
            break;
        }
    }

    Ok(stats)
}

pub(crate) async fn blob_gc_quarantine(
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    consistency: &crate::consistency::ConsistencyCoordinator,
    mutation_authority: &Arc<Mutex<Option<RuntimeMutationAuthority>>>,
    policy: BlobGcPolicy,
    min_age: Duration,
    limits: BlobGcLimits,
) -> Result<BlobGcStats, BlobGcError> {
    let auth_guard = mutation_authority.lock().await;
    let Some(ref auth) = *auth_guard else {
        return Err(BlobGcError::AuthorityUnavailable);
    };
    if !auth.is_active() {
        return Err(BlobGcError::AuthorityReleased);
    }
    blob_gc_quarantine_with_authority(storage, idx, consistency, auth, policy, min_age, limits)
        .await
}

pub async fn blob_gc_quarantine_with_authority(
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    consistency: &crate::consistency::ConsistencyCoordinator,
    authority: &RuntimeMutationAuthority,
    policy: BlobGcPolicy,
    min_age: Duration,
    limits: BlobGcLimits,
) -> Result<BlobGcStats, BlobGcError> {
    if storage.gc_strategy() == storage::GcStorageStrategy::S3DirectConditional {
        return Ok(BlobGcStats::default());
    }

    if !authority.is_active() {
        return Err(BlobGcError::AuthorityReleased);
    }

    let mut policy_ctx = PolicyContext::build(storage, idx, policy).await?;
    let mut stats = BlobGcStats::default();

    let t0 = Instant::now();
    let now = SystemTime::now();

    let mut traverser = CasBlobTraverser::new(storage, 100);

    while let Some(items) = traverser.next_batch().await? {
        for candidate in items {
            if t0.elapsed() > Duration::from_secs(limits.max_seconds) {
                return Ok(stats);
            }
            if stats.quarantined_blobs as usize >= limits.max_per_run {
                return Ok(stats);
            }
            if stats.quarantined_bytes >= limits.max_bytes {
                return Ok(stats);
            }

            match check_candidate_age(candidate.last_modified, now, min_age) {
                AgeEligibility::Eligible => {}
                _ => continue,
            }

            stats.scanned_blobs += 1;
            stats.scanned_bytes = stats.scanned_bytes.saturating_add(candidate.size);

            if !authority.is_active() {
                return Err(BlobGcError::AuthorityReleased);
            }
            let permit = authority.gc_mutation_permit();

            let _reval_guard = consistency.acquire_gc_revalidation().await;

            if policy_ctx.is_pinned(&candidate.digest, now)? {
                drop(_reval_guard);
                continue;
            }

            if policy_ctx.is_referenced(&candidate.digest).await? {
                drop(_reval_guard);
                continue;
            }

            let q_res = storage
                .quarantine_blob(&permit, &candidate.digest, &candidate.version)
                .await;

            drop(_reval_guard);

            match q_res {
                Ok(storage::GcQuarantineResult::Quarantined { size }) => {
                    stats.quarantined_blobs += 1;
                    stats.quarantined_bytes = stats.quarantined_bytes.saturating_add(size);
                }
                Ok(storage::GcQuarantineResult::Skipped) => {}
                Ok(storage::GcQuarantineResult::PreconditionFailed { .. }) => {
                    tracing::warn!(
                        "blob {} version changed since candidate inspection, preserving object",
                        candidate.digest
                    );
                }
                Err(source) => {
                    return Err(BlobGcError::QuarantineStorage {
                        digest: candidate.digest,
                        source,
                    });
                }
            }
        }

        if stats.quarantined_blobs as usize >= limits.max_per_run
            || stats.quarantined_bytes >= limits.max_bytes
            || t0.elapsed() > Duration::from_secs(limits.max_seconds)
        {
            break;
        }
    }

    Ok(stats)
}

pub(crate) async fn blob_gc_delete(
    fs_root: &std::path::Path,
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    consistency: &crate::consistency::ConsistencyCoordinator,
    mutation_authority: &Arc<Mutex<Option<RuntimeMutationAuthority>>>,
    policy: BlobGcPolicy,
    quarantine_delay: Duration,
    limits: BlobGcLimits,
) -> Result<BlobGcStats, BlobGcError> {
    let auth_guard = mutation_authority.lock().await;
    let Some(ref auth) = *auth_guard else {
        return Err(BlobGcError::AuthorityUnavailable);
    };
    if !auth.is_active() {
        return Err(BlobGcError::AuthorityReleased);
    }
    blob_gc_delete_with_authority(
        fs_root,
        storage,
        idx,
        consistency,
        auth,
        policy,
        quarantine_delay,
        limits,
    )
    .await
}

pub async fn blob_gc_delete_with_authority(
    fs_root: &std::path::Path,
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    consistency: &crate::consistency::ConsistencyCoordinator,
    authority: &RuntimeMutationAuthority,
    policy: BlobGcPolicy,
    quarantine_delay: Duration,
    limits: BlobGcLimits,
) -> Result<BlobGcStats, BlobGcError> {
    if !authority.is_active() {
        return Err(BlobGcError::AuthorityReleased);
    }
    match storage.gc_strategy() {
        storage::GcStorageStrategy::FilesystemQuarantine => {
            blob_gc_delete_fs_with_authority(
                fs_root,
                storage,
                idx,
                consistency,
                authority,
                policy,
                quarantine_delay,
                limits,
            )
            .await
        }
        storage::GcStorageStrategy::S3DirectConditional => {
            blob_gc_delete_s3_with_authority(
                storage,
                idx,
                consistency,
                authority,
                policy,
                quarantine_delay,
                limits,
            )
            .await
        }
    }
}

async fn blob_gc_delete_fs_with_authority(
    fs_root: &std::path::Path,
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    consistency: &crate::consistency::ConsistencyCoordinator,
    authority: &RuntimeMutationAuthority,
    policy: BlobGcPolicy,
    quarantine_delay: Duration,
    limits: BlobGcLimits,
) -> Result<BlobGcStats, BlobGcError> {
    use naust_storage_fs::{DirEntryType, FileName, FsMutateError};

    let mut policy_ctx = PolicyContext::build(storage, idx, policy).await?;
    let mut stats = BlobGcStats::default();

    let t0 = Instant::now();
    let now = SystemTime::now();

    // Pathname used only for error reporting; all traversal below is
    // fd-relative beneath the sweep root pinned once per run.
    let root = fs_root.join("quarantine").join("blobs").join("sha256");

    // Pin the sweep root once (contained, non-creating). A missing storage
    // root preserves the prior empty-sweep contract.
    let sweep_root = match naust_storage_fs::FsMetadataReader::open(&fs_root)
        .map_err(|e| io::Error::other(e.to_string()))
        .and_then(|r| {
            r.open_contained_dir_sync("")
                .map_err(|e| io::Error::other(e.to_string()))
        }) {
        Ok(d) => d,
        Err(source) => {
            if !fs_root.exists() {
                return Ok(stats);
            }
            return Err(BlobGcError::FsReadDir { path: root, source });
        }
    };

    // Resolve quarantine/blobs/sha256 beneath the pinned sweep root without
    // creating anything; absence of any component is the empty sweep, exactly
    // like the prior ambient read_dir NotFound contract.
    let mut q_root = sweep_root.clone();
    for seg in ["quarantine", "blobs", "sha256"] {
        let name = match FileName::new(seg) {
            Ok(n) => n,
            Err(e) => {
                return Err(BlobGcError::FsReadDir {
                    path: root,
                    source: fs_mutate_to_io(e),
                });
            }
        };
        q_root = match q_root.open_subdir(&name).await {
            Ok(d) => d,
            Err(FsMutateError::NotFound) => return Ok(stats),
            Err(e) => {
                return Err(BlobGcError::FsReadDir {
                    path: root,
                    source: fs_mutate_to_io(e),
                });
            }
        };
    }

    let mut prefix_stream = q_root.stream().map_err(|e| BlobGcError::FsReadDir {
        path: root.clone(),
        source: fs_mutate_to_io(e),
    })?;

    while let Some(prefix_res) = prefix_stream.next_entry().await {
        let prefix_ent = prefix_res.map_err(|e| BlobGcError::FsReadDir {
            path: root.clone(),
            source: fs_dir_to_io(e),
        })?;

        if t0.elapsed() > Duration::from_secs(limits.max_seconds) {
            break;
        }
        if stats.deleted_blobs as usize >= limits.max_per_run {
            break;
        }
        if stats.deleted_bytes >= limits.max_bytes {
            break;
        }

        if prefix_ent.file_type() != DirEntryType::Directory {
            continue;
        }
        // Non-UTF-8 prefix names cannot form a contained component and are
        // skipped (previously such directories were traversed by raw path;
        // valid hex shard prefixes are always UTF-8).
        let Some(prefix_name) = prefix_ent.name().to_str() else {
            continue;
        };
        let Ok(prefix_file_name) = FileName::new(prefix_name) else {
            continue;
        };

        let prefix_path = root.join(prefix_name);
        let prefix_dir = match q_root.open_subdir(&prefix_file_name).await {
            Ok(d) => d,
            Err(FsMutateError::NotFound) => continue, // Benign race: shard directory removed concurrently
            Err(source) => {
                return Err(BlobGcError::FsReadDir {
                    path: prefix_path,
                    source: fs_mutate_to_io(source),
                });
            }
        };

        let mut entry_stream = prefix_dir.stream().map_err(|e| BlobGcError::FsReadDir {
            path: prefix_path.clone(),
            source: fs_mutate_to_io(e),
        })?;

        while let Some(ent_res) = entry_stream.next_entry().await {
            let ent = ent_res.map_err(|e| BlobGcError::FsReadDir {
                path: prefix_path.clone(),
                source: fs_dir_to_io(e),
            })?;

            if t0.elapsed() > Duration::from_secs(limits.max_seconds) {
                break;
            }
            if stats.deleted_blobs as usize >= limits.max_per_run {
                break;
            }
            if stats.deleted_bytes >= limits.max_bytes {
                break;
            }

            if ent.file_type() != DirEntryType::Regular {
                continue;
            }
            let Some(file_hex) = ent.name().to_str() else {
                continue;
            };
            if file_hex.len() != 64 || !file_hex.chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let Ok(leaf) = FileName::new(file_hex) else {
                continue;
            };

            let size = match prefix_dir.inspect(&leaf).await {
                Ok(Some(identity)) => identity.size,
                Ok(None) | Err(_) => continue,
            };

            let digest = match Digest::parse(&format!("sha256:{file_hex}")) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let q_at = match read_quarantine_time(&sweep_root, fs_root, &digest).await? {
                Some(t) => t,
                None => {
                    let _ = write_quarantine_time(&sweep_root, fs_root, &digest, now).await;
                    continue;
                }
            };

            match check_candidate_age(q_at, now, quarantine_delay) {
                AgeEligibility::Eligible => {}
                _ => continue,
            }

            if stats.deleted_bytes >= limits.max_bytes {
                continue;
            }

            if !authority.is_active() {
                return Err(BlobGcError::AuthorityReleased);
            }
            let permit = authority.gc_mutation_permit();

            let reval_guard = consistency.acquire_gc_revalidation().await;

            if policy_ctx.is_pinned(&digest, now)? {
                drop(reval_guard);
                continue;
            }

            if policy_ctx.is_referenced(&digest).await? {
                let rest_res = storage.restore_quarantined_blob(&permit, &digest).await;
                drop(reval_guard);
                match rest_res {
                    Ok(Some(size)) => {
                        stats.restored_blobs += 1;
                        stats.restored_bytes = stats.restored_bytes.saturating_add(size);
                    }
                    Ok(None) => {}
                    Err(source) => {
                        return Err(BlobGcError::RestoreStorage { digest, source });
                    }
                }
                continue;
            }

            let version = match storage.quarantined_blob_version(&digest).await {
                Ok(Some(v)) => v,
                Ok(None) => {
                    drop(reval_guard);
                    continue;
                }
                Err(source) => {
                    drop(reval_guard);
                    return Err(BlobGcError::QuarantineVersionQuery { digest, source });
                }
            };

            let candidate = storage::GcBlobCandidate {
                digest: digest.clone(),
                size,
                // The leaf mtime carried here previously is consumed by no
                // step of this sweep (revalidation keys on digest/version,
                // accounting on size; the FS age decision above uses the
                // quarantine timestamp). Carry that same quarantine
                // timestamp rather than re-opening the leaf ambiently.
                last_modified: q_at,
                version,
            };

            let del_outcome = execute_guarded_gc_deletion(
                storage,
                idx,
                &candidate,
                now,
                &mut policy_ctx,
                &permit,
                &reval_guard,
            )
            .await;

            drop(reval_guard);

            match del_outcome {
                Ok(GcCandidateDeletionOutcome::Deleted { size }) => {
                    stats.deleted_blobs += 1;
                    stats.deleted_bytes = stats.deleted_bytes.saturating_add(size);
                }
                Ok(GcCandidateDeletionOutcome::Protected(_)) => {
                    continue;
                }
                Ok(GcCandidateDeletionOutcome::NotFound) => {}
                Ok(GcCandidateDeletionOutcome::PreconditionFailed { .. }) => {
                    tracing::warn!(
                        "quarantined blob {} version changed concurrently, preserving object",
                        digest
                    );
                }
                Err(e) => return Err(BlobGcError::CandidateDeletion(e)),
            }
        }
    }

    Ok(stats)
}

async fn blob_gc_delete_s3_with_authority(
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    consistency: &crate::consistency::ConsistencyCoordinator,
    authority: &RuntimeMutationAuthority,
    policy: BlobGcPolicy,
    min_age: Duration,
    limits: BlobGcLimits,
) -> Result<BlobGcStats, BlobGcError> {
    storage
        .check_bucket_versioning_for_gc()
        .await
        .map_err(BlobGcError::BucketVersioning)?;

    let mut policy_ctx = PolicyContext::build(storage, idx, policy).await?;
    let mut stats = BlobGcStats::default();

    let t0 = Instant::now();
    let now = SystemTime::now();

    let mut traverser = CasBlobTraverser::new(storage, 100);

    while let Some(items) = traverser.next_batch().await? {
        for candidate in items {
            if t0.elapsed() > Duration::from_secs(limits.max_seconds) {
                return Ok(stats);
            }
            if stats.deleted_blobs as usize >= limits.max_per_run {
                return Ok(stats);
            }
            if stats.deleted_bytes >= limits.max_bytes {
                return Ok(stats);
            }

            match check_candidate_age(candidate.last_modified, now, min_age) {
                AgeEligibility::Eligible => {}
                _ => continue,
            }

            stats.scanned_blobs += 1;
            stats.scanned_bytes = stats.scanned_bytes.saturating_add(candidate.size);

            if !authority.is_active() {
                return Err(BlobGcError::AuthorityReleased);
            }
            let permit = authority.gc_mutation_permit();

            let reval_guard = consistency.acquire_gc_revalidation().await;

            if policy_ctx.is_pinned(&candidate.digest, now)? {
                drop(reval_guard);
                continue;
            }

            if policy_ctx.is_referenced(&candidate.digest).await? {
                drop(reval_guard);
                continue;
            }

            let del_outcome = execute_guarded_gc_deletion(
                storage,
                idx,
                &candidate,
                now,
                &mut policy_ctx,
                &permit,
                &reval_guard,
            )
            .await;

            drop(reval_guard);

            match del_outcome {
                Ok(GcCandidateDeletionOutcome::Deleted { size }) => {
                    stats.deleted_blobs += 1;
                    stats.deleted_bytes = stats.deleted_bytes.saturating_add(size);
                }
                Ok(GcCandidateDeletionOutcome::Protected(_reason)) => {
                    continue;
                }
                Ok(GcCandidateDeletionOutcome::NotFound) => {}
                Ok(GcCandidateDeletionOutcome::PreconditionFailed { .. }) => {
                    tracing::warn!(
                        "s3 blob {} version changed concurrently, preserving object",
                        candidate.digest
                    );
                }
                Err(e) => return Err(BlobGcError::CandidateDeletion(e)),
            }
        }

        if stats.deleted_blobs as usize >= limits.max_per_run
            || stats.deleted_bytes >= limits.max_bytes
            || t0.elapsed() > Duration::from_secs(limits.max_seconds)
        {
            break;
        }
    }

    Ok(stats)
}

fn quarantine_meta_path(fs_root: &std::path::Path, digest: &Digest) -> PathBuf {
    fs_root
        .join("quarantine")
        .join("meta")
        .join(digest.algorithm())
        .join(digest.prefix2())
        .join(format!("{}.ts", digest.hex()))
}

/// Map a contained-primitive error into the `std::io::Error` payload carried by
/// the frozen `BlobGcError::Fs*` variants (preserving the underlying error for
/// `Io`, the `NotFound` kind for absence, and a descriptive message otherwise).
fn fs_mutate_to_io(err: naust_storage_fs::FsMutateError) -> std::io::Error {
    match err {
        naust_storage_fs::FsMutateError::Io(e) => e,
        naust_storage_fs::FsMutateError::NotFound => {
            std::io::Error::new(std::io::ErrorKind::NotFound, "contained target not found")
        }
        other => std::io::Error::other(other.to_string()),
    }
}

fn fs_dir_to_io(err: naust_storage_fs::FsDirError) -> std::io::Error {
    match err {
        naust_storage_fs::FsDirError::Io { source } => source,
        other => std::io::Error::other(other.to_string()),
    }
}

async fn write_quarantine_time(
    root: &naust_storage_fs::ContainedDir,
    fs_root: &std::path::Path,
    digest: &Digest,
    at: SystemTime,
) -> Result<(), BlobGcError> {
    use naust_storage_fs::FileName;

    // Pathnames are used only in error reports; all directory creation and the
    // write resolve fd-relative beneath the pinned sweep root.
    let path = quarantine_meta_path(fs_root, digest);
    let parent = path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| path.clone());

    let mut dir = root.clone();
    for seg in ["quarantine", "meta", digest.algorithm(), digest.prefix2()] {
        let name = FileName::new(seg).map_err(|e| BlobGcError::FsWriteMeta {
            path: parent.clone(),
            source: fs_mutate_to_io(e),
        })?;
        dir = dir
            .ensure_subdir(&name)
            .await
            .map_err(|e| BlobGcError::FsWriteMeta {
                path: parent.clone(),
                source: fs_mutate_to_io(e),
            })?;
    }

    let secs = at
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let leaf =
        FileName::new(format!("{}.ts", digest.hex())).map_err(|e| BlobGcError::FsWriteMeta {
            path: path.clone(),
            source: fs_mutate_to_io(e),
        })?;
    dir.write_leaf_atomic(&leaf, format!("{secs}\n").into_bytes(), true)
        .await
        .map_err(|e| BlobGcError::FsWriteMeta {
            path,
            source: fs_mutate_to_io(e),
        })?;

    Ok(())
}

async fn read_quarantine_time(
    root: &naust_storage_fs::ContainedDir,
    fs_root: &std::path::Path,
    digest: &Digest,
) -> Result<Option<SystemTime>, BlobGcError> {
    use naust_storage_fs::{FileName, FsMutateError};

    // Narrow error-handling contract for this quarantine-age safety check
    // (the read resolves fd-relative beneath the pinned sweep root; the
    // pathname below is used only in error reports): only genuine absence may
    // report None — the sweep then initializes a new timestamp. Read failures
    // and corrupt/unrepresentable stored values must not be conflated with
    // absence, which previously overwrote the stored evidence with a fresh
    // timestamp and restarted the deletion clock.
    let path = quarantine_meta_path(fs_root, digest);

    let mut dir = root.clone();
    for seg in ["quarantine", "meta", digest.algorithm(), digest.prefix2()] {
        let name = FileName::new(seg).map_err(|e| BlobGcError::FsReadMeta {
            path: path.clone(),
            source: fs_mutate_to_io(e),
        })?;
        dir = match dir.open_subdir(&name).await {
            Ok(d) => d,
            Err(FsMutateError::NotFound) => return Ok(None),
            Err(e) => {
                return Err(BlobGcError::FsReadMeta {
                    path,
                    source: fs_mutate_to_io(e),
                });
            }
        };
    }

    let leaf =
        FileName::new(format!("{}.ts", digest.hex())).map_err(|e| BlobGcError::FsReadMeta {
            path: path.clone(),
            source: fs_mutate_to_io(e),
        })?;
    let bytes = match dir.read_leaf(&leaf, u64::MAX).await {
        Ok(b) => b,
        Err(FsMutateError::NotFound) => return Ok(None),
        Err(e) => {
            return Err(BlobGcError::FsReadMeta {
                path,
                source: fs_mutate_to_io(e),
            });
        }
    };
    let content = String::from_utf8(bytes).map_err(|e| BlobGcError::FsReadMeta {
        path: path.clone(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()),
    })?;
    let secs: u64 = content
        .trim()
        .parse()
        .map_err(|e| BlobGcError::FsReadMeta {
            path: path.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("corrupt quarantine timestamp: {e}"),
            ),
        })?;
    let ts = UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or_else(|| BlobGcError::FsReadMeta {
            path,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("quarantine timestamp {secs}s is not representable as a system time"),
            ),
        })?;
    Ok(Some(ts))
}

#[cfg(test)]
mod tests {
    use super::validation::revalidate_candidate_before_delete;
    use super::*;

    #[tokio::test]
    async fn test_read_quarantine_time_absence_vs_failure_and_checked_arithmetic() {
        let temp = tempfile::tempdir().unwrap();
        let fs_root = temp.path().to_path_buf();
        let digest = Digest::parse(&format!("sha256:{}", "ab".repeat(32))).unwrap();
        let path = quarantine_meta_path(&fs_root, &digest);

        // Pinned sweep root, as blob_gc_delete_fs_with_authority resolves it.
        let root = naust_storage_fs::FsMetadataReader::open(&fs_root)
            .unwrap()
            .open_contained_dir_sync("")
            .unwrap();

        // Genuine absence -> Ok(None) (the sweep may then initialize a fresh
        // timestamp; that write path is unchanged).
        assert!(
            read_quarantine_time(&root, &fs_root, &digest)
                .await
                .unwrap()
                .is_none()
        );

        // Valid stored value round-trips (write via the contained helper,
        // observed at the expected pathname).
        write_quarantine_time(
            &root,
            &fs_root,
            &digest,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "1700000000\n",
            "timestamp bytes at the expected pathname"
        );
        assert_eq!(
            read_quarantine_time(&root, &fs_root, &digest)
                .await
                .unwrap(),
            Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        );

        // Corrupt stored value -> Err (previously silently None, which
        // overwrote the stored evidence and restarted the deletion clock).
        std::fs::write(&path, "garbage").unwrap();
        assert!(matches!(
            read_quarantine_time(&root, &fs_root, &digest).await,
            Err(BlobGcError::FsReadMeta { .. })
        ));

        // Unrepresentable stored value -> Err via checked arithmetic
        // (previously an unchecked UNIX_EPOCH + Duration addition).
        std::fs::write(&path, format!("{}\n", u64::MAX)).unwrap();
        assert!(matches!(
            read_quarantine_time(&root, &fs_root, &digest).await,
            Err(BlobGcError::FsReadMeta { .. })
        ));

        // A symlinked quarantine/meta shard component fails closed (Err, not
        // None, and nothing is read through the link).
        let digest2 = Digest::parse(&format!("sha256:{}", "cd".repeat(32))).unwrap();
        let outside = temp.path().join("outside-meta");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(
            outside.join(format!("{}.ts", digest2.hex())),
            "1700000000\n",
        )
        .unwrap();
        let algo_dir = fs_root.join("quarantine").join("meta").join("sha256");
        std::os::unix::fs::symlink(&outside, algo_dir.join(digest2.prefix2())).unwrap();
        assert!(matches!(
            read_quarantine_time(&root, &fs_root, &digest2).await,
            Err(BlobGcError::FsReadMeta { .. })
        ));
    }
    use crate::storage::mutation_authority::RuntimeMutationAuthority;
    use sha2::Digest as Sha2Digest;

    #[test]
    fn test_candidate_age_boundary_matrix() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        let min_age = Duration::from_secs(3600);

        // 1. Missing timestamp -> MissingTimestamp (fails closed)
        assert_eq!(
            check_candidate_age(UNIX_EPOCH, now, min_age),
            AgeEligibility::MissingTimestamp
        );

        // 2. Future timestamp -> FutureTimestamp (fails closed)
        let future = now + Duration::from_secs(60);
        assert_eq!(
            check_candidate_age(future, now, min_age),
            AgeEligibility::FutureTimestamp
        );

        // 3. Below limit -> IneligibleAge (preserved)
        let below = now - Duration::from_secs(3599);
        assert_eq!(
            check_candidate_age(below, now, min_age),
            AgeEligibility::IneligibleAge
        );

        // 4. Exactly at limit -> Eligible
        let exact = now - Duration::from_secs(3600);
        assert_eq!(
            check_candidate_age(exact, now, min_age),
            AgeEligibility::Eligible
        );

        // 5. Above limit -> Eligible
        let above = now - Duration::from_secs(7200);
        assert_eq!(
            check_candidate_age(above, now, min_age),
            AgeEligibility::Eligible
        );

        // 6. Explicit zero grace -> Eligible for past timestamp, fails closed on future
        assert_eq!(
            check_candidate_age(now - Duration::from_secs(1), now, Duration::ZERO),
            AgeEligibility::Eligible
        );
        assert_eq!(
            check_candidate_age(future, now, Duration::ZERO),
            AgeEligibility::FutureTimestamp
        );
    }

    #[tokio::test]
    async fn test_build_manifest_protected_set_aborts_on_unparsable_manifest() {
        let temp = tempfile::TempDir::new().unwrap();
        let fs_root = temp.path();

        let manifests_dir = fs_root
            .join("repos")
            .join("library")
            .join("test")
            .join("manifests");
        tokio::fs::create_dir_all(&manifests_dir).await.unwrap();

        let valid_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let valid_manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": { "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222" },
            "layers": [{ "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333" }]
        });
        tokio::fs::write(
            manifests_dir.join(valid_hex),
            serde_json::to_vec(&valid_manifest).unwrap(),
        )
        .await
        .unwrap();

        let storage = Arc::new(crate::storage::fs::FsStorage::new(
            fs_root.to_path_buf(),
            50 * 1024 * 1024,
        ));

        let protected = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap();
        assert!(
            protected.contains(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            )
        );
        assert!(
            protected.contains(
                "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            )
        );

        let malformed_hex = "4444444444444444444444444444444444444444444444444444444444444444";
        let malformed_manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": { "digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555" },
            "layers": [{ "digest": "sha256:invalid-hex" }]
        });
        tokio::fs::write(
            manifests_dir.join(malformed_hex),
            serde_json::to_vec(&malformed_manifest).unwrap(),
        )
        .await
        .unwrap();

        let err = build_manifest_protected_set(storage.as_ref())
            .await
            .unwrap_err();
        assert!(
            matches!(err, GcPolicyError::ManifestDiscovery(ref e) if e.internal_kind() == Some(crate::storage::StorageErrorKind::CorruptData)),
            "malformed manifest descriptor must fail closed with ManifestDiscovery error; got: {err:?}"
        );
    }

    #[tokio::test]
    async fn test_revalidate_candidate_malformed_journal_fails_closed() {
        let (s3_storage, driver) = crate::storage::s3::tests::create_mock_storage();
        let storage: Arc<dyn storage::GcServiceStoragePort> = Arc::new(s3_storage);

        let temp = tempfile::TempDir::new().unwrap();
        let idx = Arc::new(BlobRefIndex::open(temp.path().join("index.sled")).unwrap());
        idx.ensure_healthy_or_rebuild(storage.as_ref(), true, true)
            .await
            .unwrap();

        let candidate_bytes = b"test blob for malformed journal check";
        let hash = sha2::Sha256::digest(candidate_bytes);
        let hex = hex::encode(hash);
        let digest = Digest::parse(&format!("sha256:{hex}")).unwrap();
        let key = format!("blobs/sha256/{}/{}", &hex[0..2], &hex);
        driver.objects.lock().unwrap().insert(
            key,
            (
                bytes::Bytes::from_static(candidate_bytes),
                "\"etag\"".to_string(),
            ),
        );

        // Write corrupt/unparseable json to repo lifecycle journal
        let journal_key = "repos/journal-repo/meta/lifecycle_journal.json".to_string();
        driver.objects.lock().unwrap().insert(
            journal_key,
            (
                bytes::Bytes::from_static(b"{invalid-json-content}"),
                "\"etag\"".to_string(),
            ),
        );

        let candidate = storage::GcBlobCandidate {
            digest,
            size: candidate_bytes.len() as u64,
            last_modified: UNIX_EPOCH + Duration::from_secs(100),
            version: storage::BlobObjectVersion("\"etag\"".to_string()),
        };

        let mut policy_ctx = PolicyContext::build(&storage, &idx, BlobGcPolicy::ManifestRooted)
            .await
            .unwrap();
        let coordinator = crate::consistency::ConsistencyCoordinator::new();
        let guard = coordinator.acquire_gc_revalidation().await;
        let err = revalidate_candidate_before_delete(
            &storage,
            &idx,
            &candidate,
            SystemTime::now(),
            &mut policy_ctx,
            &guard,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            GcCandidateDeletionError::LifecycleJournalCorrupt {
                ref repository,
                ..
            } if repository == "journal-repo"
        ));
    }

    /// Restored from the deleted sweep test (R1 correction): the plan and
    /// deletion behavior on the S3 mock — orphan eligible + deleted, pinned
    /// blob protected — must stay covered without the removed sweep wrapper.
    #[tokio::test]
    async fn test_blob_gc_plan_and_delete_s3() {
        let (s3_storage, driver) = crate::storage::s3::mock::create_mock_storage();
        let s3_arc = Arc::new(s3_storage);
        let storage: Arc<dyn storage::GcServiceStoragePort> = s3_arc.clone();

        let temp = tempfile::TempDir::new().unwrap();
        let idx = Arc::new(BlobRefIndex::open(temp.path().join("index.sled")).unwrap());
        idx.ensure_healthy_or_rebuild(storage.as_ref(), true, true)
            .await
            .unwrap();

        let fs_root = temp.path().to_path_buf();

        let cluster_lock: Arc<dyn storage::ClusterLockStore> = s3_arc.clone();
        let authority = RuntimeMutationAuthority::acquire(cluster_lock, "test-gc")
            .await
            .unwrap();

        let orphan_bytes = b"orphan payload for gc";
        let orphan_hash = sha2::Sha256::digest(orphan_bytes);
        let orphan_hex = hex::encode(orphan_hash);
        let orphan_key = format!("blobs/sha256/{}/{}", &orphan_hex[0..2], &orphan_hex);
        driver.objects.lock().unwrap().insert(
            orphan_key.clone(),
            (
                bytes::Bytes::from_static(orphan_bytes),
                "\"etag_orphan\"".to_string(),
            ),
        );

        let pinned_bytes = b"pinned payload in-flight";
        let pinned_hash = sha2::Sha256::digest(pinned_bytes);
        let pinned_hex = hex::encode(pinned_hash);
        let pinned_digest = Digest::parse(&format!("sha256:{pinned_hex}")).unwrap();
        let pinned_key = format!("blobs/sha256/{}/{}", &pinned_hex[0..2], &pinned_hex);
        driver.objects.lock().unwrap().insert(
            pinned_key.clone(),
            (
                bytes::Bytes::from_static(pinned_bytes),
                "\"etag_pinned\"".to_string(),
            ),
        );
        idx.pin_blob(
            &pinned_digest,
            SystemTime::now() + Duration::from_secs(3600),
            "op-1",
        )
        .unwrap();

        let coordinator = crate::consistency::ConsistencyCoordinator::new();
        let authority_arc = Arc::new(Mutex::new(Some(authority)));

        let stats = blob_gc_plan(
            &storage,
            &idx,
            BlobGcPolicy::ManifestRooted,
            Duration::from_secs(0),
            BlobGcLimits::unlimited(100),
        )
        .await
        .unwrap();

        assert_eq!(stats.eligible_blobs, 1);

        let delete_stats = blob_gc_delete(
            &fs_root,
            &storage,
            &idx,
            &coordinator,
            &authority_arc,
            BlobGcPolicy::ManifestRooted,
            Duration::from_secs(0),
            BlobGcLimits::unlimited(100),
        )
        .await
        .unwrap();

        assert_eq!(delete_stats.deleted_blobs, 1);
        assert!(!driver.objects.lock().unwrap().contains_key(&orphan_key));
        assert!(driver.objects.lock().unwrap().contains_key(&pinned_key));
    }
}
