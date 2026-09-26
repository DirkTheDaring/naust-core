use crate::{manifest_refs::parse_manifest_refs, registry::digest::Digest, storage::StorageError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// Schema v2: root reachability is derived from per-repository provenance.
//
// INVARIANT (root accounting): `repo_roots` holds one record per
// (repository, digest) describing that repository's LIVE contribution to root
// reachability: whether the repository stores a manifest with that digest
// (`manifest` flag) and how many of the repository's tags currently target it
// (`tag_refs`). A contribution is live iff `manifest || tag_refs > 0`.
// `root_counts[digest]` is the derived aggregation: the number of repositories
// with a live contribution for that digest (key absent when zero). Repository-
// scoped reconciliation (sync/rebuild) replaces exactly that repository's
// contribution and can never erase another repository's accounting; incremental
// lifecycle hooks (manifest publish/delete, tag create/retarget/delete) adjust
// the same per-repository records so that incremental accounting is equivalent
// to a clean rebuild of the same authoritative state.
const SCHEMA_VERSION: u32 = 2;

const META_SCHEMA_VERSION: &[u8] = b"schema_version";
const META_STATE: &[u8] = b"state";
const META_STATE_READY: &[u8] = b"ready";
const META_STATE_BUILDING: &[u8] = b"building";
const META_STATE_DIRTY: &[u8] = b"dirty";

#[derive(thiserror::Error, Debug)]
pub enum RefIndexError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("manifest parse error: {0}")]
    ManifestParse(#[from] crate::manifest_refs::ManifestParseError),

    #[error("ref-index corrupt: {0}")]
    Corrupt(String),

    #[error("ref-index discovery resource limit exceeded: {0}")]
    ResourceLimit(String),

    #[error("ref-index not found at {0}")]
    NotFound(PathBuf),
}

#[derive(Clone)]
pub struct BlobRefIndex {
    db: sled::Db,
    meta: sled::Tree,
    tag_to_root: sled::Tree,
    root_counts: sled::Tree,
    /// Per-repository root provenance: `repo \0 digest` -> (manifest flag, tag_refs).
    repo_roots: sled::Tree,
    rev_edges: sled::Tree,
    pins: sled::Tree,
    repo_memberships: sled::Tree,
    fail_mark_dirty: Arc<std::sync::atomic::AtomicBool>,
    fail_mark_ready: Arc<std::sync::atomic::AtomicBool>,
    /// Test-only discovery-limit override; production code never sets this
    /// (the setter is `cfg(test)`), so production always uses
    /// [`DiscoveryLimits::PRODUCTION`].
    test_discovery_limits: Arc<std::sync::Mutex<Option<DiscoveryLimits>>>,
    /// In-process rebuild serialization (shared across clones). `rebuild`
    /// destructively clears the live trees before repopulating, so two
    /// interleaved rebuilds could publish READY while one of them is still
    /// mid-scan — violating the pinned invariant that READY is only ever
    /// written by a rebuild that completed its own full scan ("never
    /// silently ready"). Cross-process exclusion is already provided by
    /// sled's directory lock plus the server's root lock; this gate closes
    /// the in-process request-path race (blob finalize / lifecycle recovery
    /// / GC preflight can all trigger `ensure_healthy_or_rebuild`
    /// concurrently).
    rebuild_gate: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone, Debug, Default)]
pub struct TagRootedRefreshStats {
    pub repos_scanned: u64,
    pub tags_scanned: u64,
    pub roots_ingested: u64,
    pub tags_updated: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PinRecord {
    until_unix_secs: u64,
    reason: String,
}

fn system_time_to_unix_secs(t: SystemTime) -> Option<u64> {
    t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn decode_pin_record(bytes: &[u8]) -> Option<PinRecord> {
    serde_json::from_slice(bytes).ok()
}

fn encode_pin_record(rec: &PinRecord) -> Result<Vec<u8>, RefIndexError> {
    serde_json::to_vec(rec).map_err(|e| RefIndexError::Corrupt(format!("invalid pin record: {e}")))
}

fn encode_repo_membership_key(digest: &Digest, repo: &str) -> Vec<u8> {
    let s = digest.as_str();
    let digest_bytes = s.as_bytes();
    let repo_bytes = repo.as_bytes();
    let mut key = Vec::with_capacity(2 + digest_bytes.len() + 4 + repo_bytes.len());
    key.extend_from_slice(&(digest_bytes.len() as u16).to_be_bytes());
    key.extend_from_slice(digest_bytes);
    key.extend_from_slice(&(repo_bytes.len() as u32).to_be_bytes());
    key.extend_from_slice(repo_bytes);
    key
}

fn encode_repo_membership_prefix(digest: &Digest) -> Vec<u8> {
    let s = digest.as_str();
    let digest_bytes = s.as_bytes();
    let mut prefix = Vec::with_capacity(2 + digest_bytes.len());
    prefix.extend_from_slice(&(digest_bytes.len() as u16).to_be_bytes());
    prefix.extend_from_slice(digest_bytes);
    prefix
}

#[derive(Debug, Default)]
struct DiscoveredRepoData {
    roots: Vec<Digest>,
    edges: Vec<(Vec<u8>, Vec<u8>)>,
    tags: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Finite ceilings for one repository discovery/traversal pass. All staged
/// discovery structures (roots, edges, tags), traversal state (visited nodes,
/// parsed-refs cache), and pagination streams are charged against ONE budget so
/// no single staged collection can bypass the aggregate ceiling. Limits are
/// count-based plus an aggregate staged-byte ceiling; exceeding any limit fails
/// the discovery deterministically BEFORE any committed index mutation (the
/// staged-sync invariant is unchanged). These are internal resource-safety
/// constants, not a protocol/API commitment.
#[derive(Debug, Clone, Copy)]
struct DiscoveryLimits {
    /// Maximum stored manifests enumerated per repository.
    max_manifests: usize,
    /// Maximum tag mappings enumerated per repository.
    max_tags: usize,
    /// Maximum staged reverse-DAG edges per repository discovery.
    max_edges: usize,
    /// Maximum manifest nodes traversed (cumulative across roots for a
    /// discovery pass; per call for incremental `ingest_root`). Also bounds the
    /// parsed-refs cache entry count.
    max_traversal_nodes: usize,
    /// Maximum pages consumed per pagination stream (manifests, tags, and the
    /// rebuild membership stream). Guards distinct-token/empty-page floods that
    /// the token-cycle detector cannot see.
    max_pages: usize,
    /// Aggregate ceiling on staged key/value payload bytes (roots + edges +
    /// tags). Count limits bound entries; this bounds combined memory pressure.
    max_staged_bytes: usize,
}

impl DiscoveryLimits {
    /// Production ceilings. Rationale: generous for legitimate registries
    /// (100k manifests/tags per repository, 1M reverse edges, 500k traversal
    /// nodes, 100k pages per stream) while capping staged payload memory at
    /// 64 MiB — a worst-case in-memory footprint on the order of a few hundred
    /// MiB including container overhead, instead of unbounded.
    const PRODUCTION: DiscoveryLimits = DiscoveryLimits {
        max_manifests: 100_000,
        max_tags: 100_000,
        max_edges: 1_000_000,
        max_traversal_nodes: 500_000,
        max_pages: 100_000,
        max_staged_bytes: 64 * 1024 * 1024,
    };
}

/// Consumed-resource state for one discovery pass, charged against
/// [`DiscoveryLimits`]. Every charge returns a deterministic
/// [`RefIndexError::ResourceLimit`] on exhaustion; nothing is truncated or
/// partially indexed.
struct DiscoveryBudget {
    limits: DiscoveryLimits,
    repo: String,
    manifests: usize,
    tags: usize,
    edges: usize,
    nodes: usize,
    staged_bytes: usize,
}

impl DiscoveryBudget {
    fn new(limits: DiscoveryLimits, repo: &str) -> Self {
        Self {
            limits,
            repo: repo.to_string(),
            manifests: 0,
            tags: 0,
            edges: 0,
            nodes: 0,
            staged_bytes: 0,
        }
    }

    fn exceeded(&self, what: &str, limit: usize) -> RefIndexError {
        RefIndexError::ResourceLimit(format!(
            "{what} limit of {limit} exceeded during discovery for repository '{}'",
            self.repo
        ))
    }

    fn charge_bytes(&mut self, bytes: usize) -> Result<(), RefIndexError> {
        self.staged_bytes = self.staged_bytes.saturating_add(bytes);
        if self.staged_bytes > self.limits.max_staged_bytes {
            return Err(self.exceeded("staged bytes", self.limits.max_staged_bytes));
        }
        Ok(())
    }

    fn charge_manifest(&mut self, staged_bytes: usize) -> Result<(), RefIndexError> {
        self.manifests += 1;
        if self.manifests > self.limits.max_manifests {
            return Err(self.exceeded("manifest", self.limits.max_manifests));
        }
        self.charge_bytes(staged_bytes)
    }

    fn charge_tag(&mut self, staged_bytes: usize) -> Result<(), RefIndexError> {
        self.tags += 1;
        if self.tags > self.limits.max_tags {
            return Err(self.exceeded("tag", self.limits.max_tags));
        }
        self.charge_bytes(staged_bytes)
    }

    fn charge_edge(&mut self, staged_bytes: usize) -> Result<(), RefIndexError> {
        self.edges += 1;
        if self.edges > self.limits.max_edges {
            return Err(self.exceeded("edge", self.limits.max_edges));
        }
        self.charge_bytes(staged_bytes)
    }

    fn charge_node(&mut self) -> Result<(), RefIndexError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_traversal_nodes {
            return Err(self.exceeded("traversal node", self.limits.max_traversal_nodes));
        }
        Ok(())
    }

    /// `pages` counts every fetched page across the CALLER-chosen stream; each
    /// stream uses its own counter by passing a dedicated counter reference.
    fn charge_page(&mut self, pages: &mut usize) -> Result<(), RefIndexError> {
        *pages += 1;
        if *pages > self.limits.max_pages {
            return Err(self.exceeded("pagination page", self.limits.max_pages));
        }
        Ok(())
    }
}

impl BlobRefIndex {
    pub fn open(path: PathBuf) -> Result<Self, RefIndexError> {
        let db = sled::open(path)?;
        let meta = db.open_tree("meta")?;
        let tag_to_root = db.open_tree("tag_to_root")?;
        let root_counts = db.open_tree("root_counts")?;
        let repo_roots = db.open_tree("repo_roots")?;
        let rev_edges = db.open_tree("rev_edges")?;
        let pins = db.open_tree("pins")?;
        let repo_memberships = db.open_tree("repo_memberships")?;

        Ok(Self {
            db,
            meta,
            tag_to_root,
            root_counts,
            repo_roots,
            rev_edges,
            pins,
            repo_memberships,
            fail_mark_dirty: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            fail_mark_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            test_discovery_limits: Arc::new(std::sync::Mutex::new(None)),
            rebuild_gate: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Open an existing index if it exists on disk, returning NotFound without creating files if absent.
    pub fn open_existing(path: &Path) -> Result<Self, RefIndexError> {
        if !path.exists() {
            return Err(RefIndexError::NotFound(path.to_path_buf()));
        }
        Self::open(path.to_path_buf())
    }

    /// Check health of an index on disk without creating files if absent.
    pub fn check_path_health(path: &Path) -> Result<(), RefIndexError> {
        if !path.exists() {
            return Err(RefIndexError::NotFound(path.to_path_buf()));
        }
        let idx = Self::open(path.to_path_buf())?;
        idx.check_health()
    }

    // Pin/lease store (for online blob GC safety): best-effort and conservative.
    // - The server owns the sled DB; external tools must not mutate it.
    // - Pinning should never break pushes; callers should treat errors as non-fatal.
    pub fn acquire_pin(
        &self,
        digest: &Digest,
        pin_id: &str,
        until: SystemTime,
        reason: &str,
    ) -> Result<(), RefIndexError> {
        let Some(until_secs) = system_time_to_unix_secs(until) else {
            // System time before UNIX_EPOCH (or otherwise invalid): skip pinning.
            return Ok(());
        };

        let key = format!("{}:{}", digest.as_str(), pin_id);

        if let Some(existing) = self.pins.get(key.as_bytes())? {
            if let Some(old) = decode_pin_record(&existing) {
                // Never shorten an existing pin.
                if old.until_unix_secs >= until_secs {
                    return Ok(());
                }
            }
        }

        let rec = PinRecord {
            until_unix_secs: until_secs,
            reason: reason.to_string(),
        };
        self.pins.insert(key.as_bytes(), encode_pin_record(&rec)?)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn release_pin(&self, digest: &Digest, pin_id: &str) -> Result<bool, RefIndexError> {
        let key = format!("{}:{}", digest.as_str(), pin_id);
        let removed = self.pins.remove(key.as_bytes())?.is_some();
        if removed {
            self.db.flush()?;
        }
        Ok(removed)
    }

    pub fn pin_blob(
        &self,
        digest: &Digest,
        until: SystemTime,
        reason: &str,
    ) -> Result<(), RefIndexError> {
        self.acquire_pin(digest, "default", until, reason)
    }

    pub fn unpin_blob(&self, digest: &Digest, pin_id: &str) -> Result<bool, RefIndexError> {
        self.release_pin(digest, pin_id)
    }

    pub fn is_blob_pinned(&self, digest: &Digest, now: SystemTime) -> Result<bool, RefIndexError> {
        let Some(now_secs) = system_time_to_unix_secs(now) else {
            // Clock backwards / invalid: conservative.
            return Ok(true);
        };

        // Check exact key (backward compatibility with legacy single-key pins)
        let exact_key = digest.as_str();
        if let Some(v) = self.pins.get(exact_key.as_bytes())? {
            if let Some(rec) = decode_pin_record(&v) {
                if rec.until_unix_secs > now_secs {
                    return Ok(true);
                }
            }
        }

        // Check all scoped pin leases starting with "digest:"
        let prefix = format!("{}:", digest.as_str());
        for item in self.pins.scan_prefix(prefix.as_bytes()) {
            let (_k, v) = item?;
            if let Some(rec) = decode_pin_record(&v) {
                if rec.until_unix_secs > now_secs {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    pub fn purge_expired_pins(&self, now: SystemTime) -> Result<u64, RefIndexError> {
        let Some(now_secs) = system_time_to_unix_secs(now) else {
            // If time is invalid, do not purge.
            return Ok(0);
        };

        let mut removed = 0u64;
        for item in self.pins.iter() {
            let (k, v) = item?;
            let Some(rec) = decode_pin_record(&v) else {
                continue;
            };
            if rec.until_unix_secs <= now_secs {
                let _ = self.pins.remove(k);
                removed = removed.saturating_add(1);
            }
        }

        if removed > 0 {
            self.db.flush()?;
        }
        Ok(removed)
    }

    pub fn record_membership(&self, digest: &Digest, repo: &str) -> Result<(), RefIndexError> {
        let key = encode_repo_membership_key(digest, repo);
        self.repo_memberships.insert(&key, &[1u8])?;
        Ok(())
    }

    pub fn remove_membership(&self, digest: &Digest, repo: &str) -> Result<bool, RefIndexError> {
        let key = encode_repo_membership_key(digest, repo);
        let removed = self.repo_memberships.remove(&key)?.is_some();
        Ok(removed)
    }

    pub fn has_any_repo_membership(&self, digest: &Digest) -> Result<bool, RefIndexError> {
        self.check_health()?;
        let prefix = encode_repo_membership_prefix(digest);
        let mut iter = self.repo_memberships.scan_prefix(&prefix);
        Ok(iter.next().is_some())
    }

    pub fn get_membership_count(&self, digest: &Digest) -> Result<usize, RefIndexError> {
        self.check_health()?;
        let prefix = encode_repo_membership_prefix(digest);
        let count = self.repo_memberships.scan_prefix(&prefix).count();
        Ok(count)
    }

    pub fn check_health(&self) -> Result<(), RefIndexError> {
        let v = self
            .meta
            .get(META_SCHEMA_VERSION)?
            .ok_or_else(|| RefIndexError::Corrupt("missing schema_version".to_string()))?;
        let schema = decode_u32(&v)
            .ok_or_else(|| RefIndexError::Corrupt("invalid schema_version".to_string()))?;
        if schema != SCHEMA_VERSION {
            return Err(RefIndexError::Corrupt(format!(
                "unsupported schema_version={schema} (expected {SCHEMA_VERSION})"
            )));
        }

        let state = self
            .meta
            .get(META_STATE)?
            .ok_or_else(|| RefIndexError::Corrupt("missing state".to_string()))?;
        if state.as_ref() == META_STATE_DIRTY {
            return Err(RefIndexError::Corrupt(
                "index marked dirty (rebuild required)".to_string(),
            ));
        }
        if state.as_ref() != META_STATE_READY {
            return Err(RefIndexError::Corrupt(
                "index not ready (previous rebuild incomplete?)".to_string(),
            ));
        }

        // Light-weight sanity check: ensure at least one root_count entry (if any)
        // decodes as u64.
        if let Some(res) = self.root_counts.iter().next() {
            let (_k, v) = res?;
            if decode_u64(&v).is_none() {
                return Err(RefIndexError::Corrupt(
                    "invalid root_counts entry".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn mark_dirty(&self) -> Result<(), RefIndexError> {
        if self
            .fail_mark_dirty
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(RefIndexError::Corrupt(
                "injected mark_dirty failure".to_string(),
            ));
        }
        self.meta.insert(META_STATE, META_STATE_DIRTY)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn set_fail_mark_dirty(&self, fail: bool) {
        self.fail_mark_dirty
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn set_fail_mark_ready(&self, fail: bool) {
        self.fail_mark_ready
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn mark_ready(&self) -> Result<(), RefIndexError> {
        if self
            .fail_mark_ready
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(RefIndexError::Corrupt(
                "injected mark_ready failure".to_string(),
            ));
        }
        self.meta.insert(META_STATE, META_STATE_READY)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn flush(&self) -> Result<(), RefIndexError> {
        self.db.flush()?;
        Ok(())
    }

    pub async fn ensure_healthy_or_rebuild(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
        auto_rebuild_on_corruption: bool,
        rebuild_on_start: bool,
    ) -> Result<(), RefIndexError> {
        if rebuild_on_start {
            return self.rebuild(storage).await;
        }

        match self.check_health() {
            Ok(()) => Ok(()),
            Err(RefIndexError::Corrupt(reason)) if auto_rebuild_on_corruption => {
                // Serialize with any in-flight rebuild and COALESCE waiters:
                // a rebuild that completed while this caller waited on the
                // gate already healed the index, so re-check before
                // rebuilding again (N concurrent healers perform one
                // rebuild, not N serial destructive rebuilds).
                let _gate = self.rebuild_gate.lock().await;
                match self.check_health() {
                    Ok(()) => Ok(()),
                    Err(RefIndexError::Corrupt(reason2)) => {
                        let _ = reason;
                        tracing::warn!(
                            reason = reason2,
                            "ref-index: corruption detected; rebuilding"
                        );
                        self.rebuild_locked(storage).await
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn effective_discovery_limits(&self) -> DiscoveryLimits {
        self.test_discovery_limits
            .lock()
            .ok()
            .and_then(|g| *g)
            .unwrap_or(DiscoveryLimits::PRODUCTION)
    }

    /// Test seam: override discovery limits for this index instance. Not
    /// compiled into production builds.
    #[cfg(test)]
    fn set_test_discovery_limits(&self, limits: Option<DiscoveryLimits>) {
        *self.test_discovery_limits.lock().unwrap() = limits;
    }

    pub fn is_blob_referenced(&self, digest: &Digest) -> Result<bool, RefIndexError> {
        // If the index isn't healthy, treat it as corrupt.
        self.check_health()?;

        let mut queue: VecDeque<String> = VecDeque::new();
        let mut visited: HashSet<String> = HashSet::new();

        let start = digest.as_str().to_string();
        queue.push_back(start);

        while let Some(cur) = queue.pop_front() {
            if !visited.insert(cur.clone()) {
                continue;
            }

            if self.root_counts.contains_key(cur.as_bytes())? {
                return Ok(true);
            }

            let Some(v) = self.rev_edges.get(cur.as_bytes())? else {
                continue;
            };

            let parents = decode_parent_list(&v)
                .ok_or_else(|| RefIndexError::Corrupt("invalid rev_edges entry".to_string()))?;

            for p in parents {
                if !visited.contains(&p) {
                    if self.root_counts.contains_key(p.as_bytes())? {
                        return Ok(true);
                    }
                    queue.push_back(p);
                }
            }
        }

        Ok(false)
    }

    pub async fn on_tag_mutation(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
        repo: &str,
        tag: &str,
        new_root: &Digest,
        mutation: &crate::storage::TagMutation,
    ) -> Result<(), RefIndexError> {
        match mutation {
            crate::storage::TagMutation::Unchanged => {
                self.ingest_root(storage, repo, new_root).await?;
                Ok(())
            }
            crate::storage::TagMutation::Created | crate::storage::TagMutation::Replaced { .. } => {
                // Accounting reconciles against the mapping the index itself
                // previously stored (not the caller-reported previous digest),
                // keeping per-repository tag_refs self-consistent.
                self.ingest_root(storage, repo, new_root).await?;
                self.set_tag_mapping_accounted(repo, tag, &new_root.as_str())?;
                self.db.flush()?;
                Ok(())
            }
        }
    }

    pub async fn on_tag_set(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
        repo: &str,
        tag: &str,
        new_root: &Digest,
        old_root: Option<Digest>,
    ) -> Result<(), RefIndexError> {
        // Ensure the manifest graph is present.
        self.ingest_root(storage, repo, new_root).await?;

        // Accounting reconciles against the mapping the index itself previously
        // stored; `old_root` remains accepted for API compatibility but the
        // stored mapping is authoritative for per-repository tag_refs.
        let _ = old_root;
        self.set_tag_mapping_accounted(repo, tag, &new_root.as_str())?;

        self.db.flush()?;
        Ok(())
    }

    pub async fn sync_repo_manifests_and_tags(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
        repo: &str,
    ) -> Result<(), RefIndexError> {
        // Phase 1: Read-only storage discovery (all-or-nothing; zero index mutations
        // on error), bounded by the discovery budget: any limit exhaustion fails
        // closed here, before Phase 2 touches committed state.
        let staged = Self::discover_repo_manifests_and_tags(
            storage,
            repo,
            self.effective_discovery_limits(),
        )
        .await?;

        // Phase 2: Index application (performs sled operations, no backend I/O).
        // Reconcile THIS repository's contribution against the staged discovery:
        // repository-scoped replacement that is idempotent for unchanged storage
        // state and can never erase another repository's accounting. Multi-tree
        // application remains non-transactional (as elsewhere in this index) and
        // is protected by the caller-side dirty/rebuild mechanism.
        // 1. Build the repository's NEW contribution map from staged state.
        let mut new_contribs: HashMap<String, (bool, u32)> = HashMap::new();
        for digest in &staged.roots {
            new_contribs
                .entry(digest.as_str().to_string())
                .or_insert((false, 0))
                .0 = true;
        }
        for (_tag_k, digest_bytes) in &staged.tags {
            if let Ok(s) = std::str::from_utf8(digest_bytes) {
                let entry = new_contribs.entry(s.to_string()).or_insert((false, 0));
                entry.1 = entry.1.saturating_add(1);
            }
        }

        // 2. Load the repository's OLD contribution map.
        let prefix = tag_prefix(repo);
        let mut old_contribs: HashMap<String, (bool, u32)> = HashMap::new();
        for item in self.repo_roots.scan_prefix(&prefix) {
            let (k, v) = item?;
            let digest_str = std::str::from_utf8(&k[prefix.len()..])
                .map_err(|_| RefIndexError::Corrupt("invalid repo_roots key".to_string()))?
                .to_string();
            old_contribs.insert(digest_str, decode_contribution(Some(&v)));
        }

        // 3. Apply the per-digest delta, adjusting derived global reachability
        // only on liveness transitions of THIS repository's contribution.
        let mut all_digests: HashSet<String> = old_contribs.keys().cloned().collect();
        all_digests.extend(new_contribs.keys().cloned());
        for digest_str in all_digests {
            let old = old_contribs.get(&digest_str).copied().unwrap_or((false, 0));
            let new = new_contribs.get(&digest_str).copied().unwrap_or((false, 0));
            let old_live = old.0 || old.1 > 0;
            let new_live = new.0 || new.1 > 0;
            let key = repo_root_key(repo, &digest_str);
            if new_live {
                self.repo_roots
                    .insert(&key, encode_contribution(new.0, new.1))?;
            } else {
                self.repo_roots.remove(&key)?;
            }
            if !old_live && new_live {
                self.inc_root_count(digest_str.as_bytes())?;
            } else if old_live && !new_live {
                self.dec_root_count(digest_str.as_bytes())?;
            }
        }

        // 4. Replace this repository's tags.
        let existing_tags: Vec<Vec<u8>> = self
            .tag_to_root
            .scan_prefix(&prefix)
            .filter_map(|r| r.ok())
            .map(|(k, _v)| k.to_vec())
            .collect();
        for k in existing_tags {
            let _ = self.tag_to_root.remove(k);
        }
        for (tag_k, digest_bytes) in staged.tags {
            self.tag_to_root.insert(tag_k, digest_bytes.as_slice())?;
        }

        // 5. Apply DAG edges for discovered manifests.
        for (child, parent) in staged.edges {
            self.add_parent(&child, &parent)?;
        }

        self.db.flush()?;
        Ok(())
    }

    async fn discover_repo_manifests_and_tags(
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
        repo: &str,
        limits: DiscoveryLimits,
    ) -> Result<DiscoveredRepoData, RefIndexError> {
        let mut budget = DiscoveryBudget::new(limits, repo);
        let mut roots: Vec<Digest> = Vec::new();
        let mut edges: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut tags: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

        // 1. Enumerate all stored manifests in this repo with token cycle detection.
        // Every staged structure, the traversal state, and the pagination streams
        // are charged against ONE bounded discovery budget; token-cycle detection
        // fires before the page budget can be consumed by a repeating token.
        let mut manifest_token: Option<String> = None;
        let mut seen_manifest_tokens: HashSet<String> = HashSet::new();
        let mut manifest_pages: usize = 0;

        loop {
            budget.charge_page(&mut manifest_pages)?;
            let (manifests, next_tok) = storage
                .list_manifest_digests_page(repo, manifest_token.as_deref(), 128)
                .await?;

            for digest in manifests {
                budget.charge_manifest(digest.as_str().len())?;
                roots.push(digest.clone());

                // Perform recursive DAG discovery for this root.
                // Traversal queue, visited set, and refs_cache are scoped per root, preserving
                // exact ingest_root semantics and key identity (digest.hex().to_string()).
                let mut queue: VecDeque<Digest> = VecDeque::new();
                queue.push_back(digest.clone());

                let mut visited: HashSet<String> = HashSet::new();
                let mut refs_cache: HashMap<String, Option<crate::manifest_refs::ManifestRefs>> =
                    HashMap::new();

                while let Some(cur_digest) = queue.pop_front() {
                    if !visited.insert(cur_digest.hex().to_string()) {
                        continue;
                    }
                    budget.charge_node()?;

                    let digest_hex = cur_digest.hex().to_string();
                    let refs = if let Some(v) = refs_cache.get(&digest_hex) {
                        match v.clone() {
                            Some(r) => r,
                            None => continue,
                        }
                    } else {
                        let (_meta, bytes) = match storage.get_manifest(repo, &cur_digest).await {
                            Ok(v) => v,
                            // Tolerated NotFound: preserve existing semantics where missing roots or
                            // child manifests are cached as absent and skipped without failing discovery.
                            Err(StorageError::NotFound) => {
                                refs_cache.insert(digest_hex, None);
                                continue;
                            }
                            Err(e) => return Err(e.into()),
                        };

                        let parsed = parse_manifest_refs(&bytes)?;
                        refs_cache.insert(digest_hex, Some(parsed.clone()));
                        parsed
                    };

                    // child blob -> parent manifest
                    for child_blob in refs.blob_references() {
                        let child = child_blob.as_str().as_bytes().to_vec();
                        let parent = cur_digest.as_str().as_bytes().to_vec();
                        budget.charge_edge(child.len() + parent.len())?;
                        edges.push((child, parent));
                    }

                    // child manifest -> parent manifest
                    // The parent edge to the child manifest is retained even if the child manifest
                    // is subsequently found to be missing from storage.
                    for child_manifest in refs.manifest_references() {
                        let child = child_manifest.as_str().as_bytes().to_vec();
                        let parent = cur_digest.as_str().as_bytes().to_vec();
                        budget.charge_edge(child.len() + parent.len())?;
                        edges.push((child, parent));
                        queue.push_back(child_manifest.clone());
                    }
                }
            }

            match next_tok {
                Some(tok) => {
                    if !seen_manifest_tokens.insert(tok.clone()) {
                        return Err(StorageError::backend(format!(
                            "pagination cycle detected on continuation token '{tok}' in repository '{repo}'"
                        ))
                        .into());
                    }
                    manifest_token = Some(tok);
                }
                None => break,
            }
        }

        // 2. Enumerate tags in this repo with independent token cycle detection
        let mut tag_token: Option<String> = None;
        let mut seen_tag_tokens: HashSet<String> = HashSet::new();
        let mut tag_pages: usize = 0;

        loop {
            budget.charge_page(&mut tag_pages)?;
            let (page_tags, next_tok) = storage
                .list_tags_page(repo, tag_token.as_deref(), 128)
                .await?;

            for (tag, digest) in page_tags {
                let key = tag_key(repo, &tag);
                let val = digest.as_str().as_bytes().to_vec();
                budget.charge_tag(key.len() + val.len())?;
                tags.push((key, val));
            }

            match next_tok {
                Some(tok) => {
                    if !seen_tag_tokens.insert(tok.clone()) {
                        return Err(StorageError::backend(format!(
                            "pagination cycle detected on continuation token '{tok}' in repository '{repo}'"
                        ))
                        .into());
                    }
                    tag_token = Some(tok);
                }
                None => break,
            }
        }

        Ok(DiscoveredRepoData { roots, edges, tags })
    }

    pub async fn sync_repo_tags(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
        repo: &str,
    ) -> Result<(), RefIndexError> {
        self.sync_repo_manifests_and_tags(storage, repo).await
    }

    pub async fn on_manifest_published(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
        repo: &str,
        digest: &Digest,
        tag: Option<&str>,
    ) -> Result<(), RefIndexError> {
        // Idempotent per-repository manifest contribution (re-publishing an
        // already-indexed manifest does not inflate accounting).
        self.contribution_set_manifest(repo, &digest.as_str(), true)?;
        self.ingest_root(storage, repo, digest).await?;
        if let Some(t) = tag {
            self.set_tag_mapping_accounted(repo, t, &digest.as_str())?;
        }
        self.db.flush()?;
        Ok(())
    }

    pub fn on_tag_deleted(&self, repo: &str, tag: &str) -> Result<(), RefIndexError> {
        // Removing the mapping releases this repository's tag contribution to
        // the previously targeted digest.
        if let Some(prev) = self.tag_to_root.remove(tag_key(repo, tag))? {
            if let Ok(prev_str) = std::str::from_utf8(&prev) {
                let prev_str = prev_str.to_string();
                self.contribution_adjust_tag_refs(repo, &prev_str, -1)?;
            }
        }
        self.db.flush()?;
        Ok(())
    }

    pub fn on_manifest_deleted(&self, repo: &str, digest: &Digest) -> Result<(), RefIndexError> {
        // Clear exactly THIS repository's contribution (manifest presence plus
        // the tag references removed below); other repositories' live
        // contributions to the same content-addressed digest are untouched.
        let digest_str = digest.as_str();
        let prefix = tag_prefix(repo);
        let digest_bytes = digest_str.as_bytes();
        let tags_to_remove: Vec<Vec<u8>> = self
            .tag_to_root
            .scan_prefix(prefix)
            .filter_map(|r| r.ok())
            .filter(|(_k, v)| v.as_ref() == digest_bytes)
            .map(|(k, _v)| k.to_vec())
            .collect();
        for k in tags_to_remove {
            let _ = self.tag_to_root.remove(k);
        }
        self.contribution_clear(repo, &digest_str)?;
        self.db.flush()?;
        Ok(())
    }

    pub async fn rebuild(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
    ) -> Result<(), RefIndexError> {
        let _gate = self.rebuild_gate.lock().await;
        self.rebuild_locked(storage).await
    }

    /// Rebuild body, callers hold `rebuild_gate` (rebuilds are destructive:
    /// the live trees are cleared before repopulation, so rebuilds must
    /// never interleave in-process).
    async fn rebuild_locked(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
    ) -> Result<(), RefIndexError> {
        self.meta
            .insert(META_SCHEMA_VERSION, encode_u32(SCHEMA_VERSION))?;
        self.meta.insert(META_STATE, META_STATE_BUILDING)?;
        self.db.flush()?;

        self.tag_to_root.clear()?;
        self.root_counts.clear()?;
        self.repo_roots.clear()?;
        self.rev_edges.clear()?;
        self.repo_memberships.clear()?;

        let repos = storage.list_repositories().await?;
        for repo in &repos {
            self.sync_repo_manifests_and_tags(storage, repo).await?;
        }

        // Global pagination over ALL repository blob memberships (ensures
        // membership-only repositories with zero tags/manifests are fully
        // indexed). Memory per page is bounded; the page budget guards
        // non-terminating/token-flooding streams (this stream has no
        // token-cycle detector).
        let mut membership_budget =
            DiscoveryBudget::new(self.effective_discovery_limits(), "<memberships>");
        let mut membership_pages: usize = 0;
        let mut token: Option<String> = None;
        loop {
            membership_budget.charge_page(&mut membership_pages)?;
            let (page, next_tok) = storage
                .list_all_repo_blob_memberships_page(token.as_deref(), 256)
                .await?;
            for rec in page {
                self.record_membership(&rec.digest, rec.repo.as_str())?;
            }
            match next_tok {
                Some(tok) => token = Some(tok),
                None => break,
            }
        }

        self.meta.insert(META_STATE, META_STATE_READY)?;
        self.db.flush()?;
        Ok(())
    }

    /// Best-effort, conservative refresh for tag-rooted GC.
    ///
    /// This ensures the current on-disk tag roots are represented in the index so
    /// `is_blob_referenced()` won't produce false negatives due to stale/missed updates.
    ///
    /// It is conservative under concurrent writes:
    /// - it ingests reachable manifests for current roots (adds edges)
    /// - it sets tag->root when it differs
    /// - it increments root refcounts for new roots
    /// - it never decrements counts or deletes old mappings (may over-retain, but is safe)
    pub async fn refresh_tag_rooted_conservative(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
    ) -> Result<TagRootedRefreshStats, RefIndexError> {
        self.check_health()?;

        let mut stats = TagRootedRefreshStats::default();
        let repos = storage.list_repositories().await?;
        for repo in repos {
            stats.repos_scanned += 1;
            let tags = match storage.list_tags(&repo).await {
                Ok(t) => t,
                Err(StorageError::NotFound) => continue,
                Err(e) => return Err(e.into()),
            };

            for tag in tags {
                stats.tags_scanned += 1;
                let root = match storage.resolve_tag(&repo, &tag).await {
                    Ok(d) => d,
                    Err(StorageError::NotFound) => continue,
                    Err(e) => return Err(e.into()),
                };

                self.ingest_root(storage, &repo, &root).await?;
                stats.roots_ingested += 1;

                let key = tag_key(&repo, &tag);
                let new_val = root.as_str().as_bytes().to_vec();

                let cur = self.tag_to_root.get(&key)?;
                let needs_update = cur.as_ref().map(|v| v.as_ref()) != Some(new_val.as_slice());
                if needs_update {
                    // Deliberately conservative (documented above): add the new
                    // target's tag contribution without decrementing the old
                    // target, so concurrent writes can only over-retain. The
                    // next repository sync/rebuild reconciles exactly.
                    self.tag_to_root.insert(&key, new_val)?;
                    self.contribution_adjust_tag_refs(repo.as_str(), &root.as_str(), 1)?;
                    stats.tags_updated += 1;
                }
            }
        }

        self.db.flush()?;
        Ok(stats)
    }

    async fn ingest_root(
        &self,
        storage: &(impl crate::storage::BlobRefIndexStoragePort + ?Sized),
        repo: &str,
        root: &Digest,
    ) -> Result<(), RefIndexError> {
        // Incremental traversal shares the discovery budget model: the visited
        // set and parsed-refs cache are bounded by the traversal-node ceiling
        // (edges here are written directly to sled, not staged in memory). A
        // limit failure surfaces to the lifecycle caller, whose existing
        // dirty/rebuild protection applies.
        let mut budget = DiscoveryBudget::new(self.effective_discovery_limits(), repo);
        let mut queue: VecDeque<Digest> = VecDeque::new();
        queue.push_back(root.clone());

        let mut visited: HashSet<String> = HashSet::new();

        // Per-repo cache to avoid repeated manifest reads/parses.
        let mut refs_cache: HashMap<String, Option<crate::manifest_refs::ManifestRefs>> =
            HashMap::new();

        while let Some(digest) = queue.pop_front() {
            if !visited.insert(digest.hex().to_string()) {
                continue;
            }
            budget.charge_node()?;

            let digest_hex = digest.hex().to_string();
            let refs = if let Some(v) = refs_cache.get(&digest_hex) {
                match v.clone() {
                    Some(r) => r,
                    None => continue,
                }
            } else {
                let (_meta, bytes) = match storage.get_manifest(repo, &digest).await {
                    Ok(v) => v,
                    Err(StorageError::NotFound) => {
                        refs_cache.insert(digest_hex, None);
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };

                let parsed = parse_manifest_refs(&bytes)?;
                refs_cache.insert(digest_hex, Some(parsed.clone()));
                parsed
            };

            // child blob -> parent manifest
            for child_blob in refs.blob_references() {
                self.add_parent(child_blob.as_str().as_bytes(), digest.as_str().as_bytes())?;
            }

            // child manifest -> parent manifest
            for child_manifest in refs.manifest_references() {
                self.add_parent(
                    child_manifest.as_str().as_bytes(),
                    digest.as_str().as_bytes(),
                )?;
                queue.push_back(child_manifest.clone());
            }
        }

        Ok(())
    }

    fn add_parent(&self, child_key: &[u8], parent: &[u8]) -> Result<(), RefIndexError> {
        self.rev_edges.update_and_fetch(child_key, |old| {
            let mut parents: Vec<Vec<u8>> = match old {
                Some(v) => decode_parent_list_bytes(v).unwrap_or_default(),
                None => Vec::new(),
            };

            if parents.iter().any(|p| p.as_slice() == parent) {
                return Some(encode_parent_list_bytes(&parents));
            }

            parents.push(parent.to_vec());
            Some(encode_parent_list_bytes(&parents))
        })?;
        Ok(())
    }

    /// Applies a pure transformation to this repository's contribution record
    /// for `digest_str` and adjusts the derived global `root_counts` entry only
    /// on liveness transitions of THIS repository's contribution. The record is
    /// removed when it becomes dead (`!manifest && tag_refs == 0`).
    fn contribution_apply(
        &self,
        repo: &str,
        digest_str: &str,
        f: impl Fn(bool, u32) -> (bool, u32),
    ) -> Result<(), RefIndexError> {
        let key = repo_root_key(repo, digest_str);
        let prev = self.repo_roots.fetch_and_update(&key, |old| {
            let (m, t) = decode_contribution(old);
            let (nm, nt) = f(m, t);
            if !nm && nt == 0 {
                None
            } else {
                Some(encode_contribution(nm, nt))
            }
        })?;
        let (old_m, old_t) = decode_contribution(prev.as_deref());
        let (new_m, new_t) = f(old_m, old_t);
        let old_live = old_m || old_t > 0;
        let new_live = new_m || new_t > 0;
        if !old_live && new_live {
            self.inc_root_count(digest_str.as_bytes())?;
        } else if old_live && !new_live {
            self.dec_root_count(digest_str.as_bytes())?;
        }
        Ok(())
    }

    /// Sets/clears the manifest-presence bit of this repository's contribution.
    fn contribution_set_manifest(
        &self,
        repo: &str,
        digest_str: &str,
        present: bool,
    ) -> Result<(), RefIndexError> {
        self.contribution_apply(repo, digest_str, move |_m, t| (present, t))
    }

    /// Adjusts the tag-reference count of this repository's contribution
    /// (saturating at zero).
    fn contribution_adjust_tag_refs(
        &self,
        repo: &str,
        digest_str: &str,
        delta: i64,
    ) -> Result<(), RefIndexError> {
        self.contribution_apply(repo, digest_str, move |m, t| {
            let next = (i64::from(t)).saturating_add(delta).max(0) as u32;
            (m, next)
        })
    }

    /// Removes this repository's ENTIRE contribution for `digest_str`
    /// (manifest presence and tag references).
    fn contribution_clear(&self, repo: &str, digest_str: &str) -> Result<(), RefIndexError> {
        self.contribution_apply(repo, digest_str, |_m, _t| (false, 0))
    }

    /// Inserts/replaces a tag mapping and reconciles per-repository tag
    /// contributions against the mapping the index PREVIOUSLY stored:
    /// retargets release the old target and add the new one; same-target
    /// writes change nothing; fresh mappings add the new target.
    fn set_tag_mapping_accounted(
        &self,
        repo: &str,
        tag: &str,
        new_root_str: &str,
    ) -> Result<(), RefIndexError> {
        let key = tag_key(repo, tag);
        let prev = self.tag_to_root.insert(&key, new_root_str.as_bytes())?;
        match prev {
            Some(prev_v) if prev_v.as_ref() == new_root_str.as_bytes() => Ok(()),
            Some(prev_v) => {
                if let Ok(prev_str) = std::str::from_utf8(&prev_v) {
                    let prev_str = prev_str.to_string();
                    self.contribution_adjust_tag_refs(repo, &prev_str, -1)?;
                }
                self.contribution_adjust_tag_refs(repo, new_root_str, 1)
            }
            None => self.contribution_adjust_tag_refs(repo, new_root_str, 1),
        }
    }

    /// Test seam: derived global reachability count for a digest.
    #[cfg(test)]
    pub(crate) fn debug_root_count(&self, digest: &Digest) -> Option<u64> {
        self.root_counts
            .get(digest.as_str().as_bytes())
            .ok()
            .flatten()
            .and_then(|v| decode_u64(&v))
    }

    /// Test seam: this repository's contribution record for a digest.
    #[cfg(test)]
    pub(crate) fn debug_contribution(&self, repo: &str, digest: &Digest) -> Option<(bool, u32)> {
        self.repo_roots
            .get(repo_root_key(repo, &digest.as_str()))
            .ok()
            .flatten()
            .map(|v| decode_contribution(Some(&v)))
    }

    fn inc_root_count(&self, root: &[u8]) -> Result<(), RefIndexError> {
        self.root_counts.update_and_fetch(root, |old| {
            let cur = old.and_then(|v| decode_u64(v)).unwrap_or(0);
            Some(encode_u64(cur.saturating_add(1)))
        })?;
        Ok(())
    }

    fn dec_root_count(&self, root: &[u8]) -> Result<(), RefIndexError> {
        let updated = self.root_counts.update_and_fetch(root, |old| {
            let cur = old.and_then(|v| decode_u64(v)).unwrap_or(0);
            let next = cur.saturating_sub(1);
            if next == 0 {
                None
            } else {
                Some(encode_u64(next))
            }
        })?;

        // If updated == None, key was removed.
        let _ = updated;
        Ok(())
    }
}

fn tag_key(repo: &str, tag: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(repo.len() + 1 + tag.len());
    k.extend_from_slice(repo.as_bytes());
    k.push(0);
    k.extend_from_slice(tag.as_bytes());
    k
}

fn tag_prefix(repo: &str) -> Vec<u8> {
    let mut p = Vec::with_capacity(repo.len() + 1);
    p.extend_from_slice(repo.as_bytes());
    p.push(0);
    p
}

/// Per-repository provenance key: `repo \0 digest` (same framing as tag keys;
/// digest strings never contain NUL).
fn repo_root_key(repo: &str, digest_str: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(repo.len() + 1 + digest_str.len());
    k.extend_from_slice(repo.as_bytes());
    k.push(0);
    k.extend_from_slice(digest_str.as_bytes());
    k
}

/// Contribution record: `[manifest u8][tag_refs u32 BE]`. Tolerant decode:
/// malformed records (never written by this schema) read as empty and are
/// overwritten on the next apply (the index is rebuildable by design).
fn encode_contribution(manifest: bool, tag_refs: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(5);
    v.push(u8::from(manifest));
    v.extend_from_slice(&tag_refs.to_be_bytes());
    v
}

fn decode_contribution(v: Option<&[u8]>) -> (bool, u32) {
    match v {
        Some(b) if b.len() == 5 => {
            let mut t = [0u8; 4];
            t.copy_from_slice(&b[1..5]);
            (b[0] != 0, u32::from_be_bytes(t))
        }
        _ => (false, 0),
    }
}

fn encode_u64(v: u64) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn decode_u64(v: &[u8]) -> Option<u64> {
    if v.len() != 8 {
        return None;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(v);
    Some(u64::from_be_bytes(a))
}

fn encode_u32(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

fn decode_u32(v: &[u8]) -> Option<u32> {
    if v.len() != 4 {
        return None;
    }
    let mut a = [0u8; 4];
    a.copy_from_slice(v);
    Some(u32::from_be_bytes(a))
}

fn encode_parent_list_bytes(parents: &[Vec<u8>]) -> Vec<u8> {
    // newline-separated utf8 digests (sha256:...)
    let mut out: Vec<u8> = Vec::new();
    for (i, p) in parents.iter().enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(p);
    }
    out
}

fn decode_parent_list_bytes(v: &[u8]) -> Option<Vec<Vec<u8>>> {
    if v.is_empty() {
        return Some(Vec::new());
    }
    Some(v.split(|b| *b == b'\n').map(|s| s.to_vec()).collect())
}

fn decode_parent_list(v: &[u8]) -> Option<Vec<String>> {
    if v.is_empty() {
        return Some(Vec::new());
    }
    let s = std::str::from_utf8(v).ok()?;
    Some(
        s.split('\n')
            .filter(|p| !p.is_empty())
            .map(|p| p.to_string())
            .collect(),
    )
}

// Keep clippy happy: used by signature clarity.
#[allow(dead_code)]
fn _path_exists(p: &Path) -> bool {
    p.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::collections::{HashMap, HashSet};
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};
    use tokio::io::AsyncRead;

    #[derive(Default)]
    struct MockStorage {
        repos: Mutex<HashSet<String>>,
        tags: Mutex<HashMap<String, HashMap<String, Digest>>>,
        manifests: Mutex<HashMap<(String, String), Bytes>>,
        manifest_pages:
            Mutex<HashMap<String, Vec<Result<(Vec<Digest>, Option<String>), StorageError>>>>,
        tag_pages: Mutex<
            HashMap<String, Vec<Result<(Vec<(String, Digest)>, Option<String>), StorageError>>>,
        >,
        manifest_faults: Mutex<HashMap<(String, String), StorageError>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self::default()
        }

        fn add_repo(&self, repo: &str) {
            self.repos.lock().unwrap().insert(repo.to_string());
        }

        fn set_tag_sync(&self, repo: &str, tag: &str, digest: &Digest) {
            self.add_repo(repo);
            self.tags
                .lock()
                .unwrap()
                .entry(repo.to_string())
                .or_default()
                .insert(tag.to_string(), digest.clone());
        }

        fn remove_tag(&self, repo: &str, tag: &str) {
            if let Some(m) = self.tags.lock().unwrap().get_mut(repo) {
                m.remove(tag);
            }
        }

        fn remove_manifest(&self, repo: &str, digest: &Digest) {
            self.manifests
                .lock()
                .unwrap()
                .remove(&(repo.to_string(), digest.as_str().to_string()));
        }

        fn put_manifest_bytes(&self, repo: &str, digest: &Digest, bytes: Bytes) {
            self.add_repo(repo);
            self.manifests
                .lock()
                .unwrap()
                .insert((repo.to_string(), digest.as_str().to_string()), bytes);
        }

        fn queue_manifest_page(
            &self,
            repo: &str,
            page: Result<(Vec<Digest>, Option<String>), StorageError>,
        ) {
            self.manifest_pages
                .lock()
                .unwrap()
                .entry(repo.to_string())
                .or_default()
                .push(page);
        }

        fn queue_tag_page(
            &self,
            repo: &str,
            page: Result<(Vec<(String, Digest)>, Option<String>), StorageError>,
        ) {
            self.tag_pages
                .lock()
                .unwrap()
                .entry(repo.to_string())
                .or_default()
                .push(page);
        }

        fn inject_manifest_fault(&self, repo: &str, digest: &Digest, err: StorageError) {
            self.manifest_faults
                .lock()
                .unwrap()
                .insert((repo.to_string(), digest.as_str().to_string()), err);
        }
    }

    #[async_trait]
    impl crate::storage::UploadSessionStorage for MockStorage {}

    #[async_trait]
    impl crate::storage::repo_membership::RepositoryBlobMembershipStorage for MockStorage {}

    #[async_trait]
    impl crate::storage::GcStorage for MockStorage {
        async fn discover_manifest_references(
            &self,
        ) -> Result<
            Option<std::collections::HashSet<crate::registry::digest::Digest>>,
            crate::storage::StorageError,
        > {
            Ok(None)
        }
    }

    #[async_trait]
    impl Storage for MockStorage {
        fn kind(&self) -> &'static str {
            "mock"
        }

        async fn list_repositories(&self) -> Result<Vec<String>, StorageError> {
            let mut v: Vec<String> = self.repos.lock().unwrap().iter().cloned().collect();
            v.sort();
            Ok(v)
        }

        async fn repo_timestamps(
            &self,
            _name: &str,
        ) -> Result<crate::storage::RepoTimestamps, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn is_storage_empty(&self) -> Result<bool, StorageError> {
            Ok(self.repos.lock().unwrap().is_empty())
        }

        async fn head_blob(
            &self,
            _digest: &Digest,
        ) -> Result<crate::storage::BlobMeta, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn open_blob(
            &self,
            _digest: &Digest,
        ) -> Result<(crate::storage::BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError>
        {
            Err(StorageError::Unsupported)
        }

        async fn resolve_tag(&self, name: &str, tag: &str) -> Result<Digest, StorageError> {
            self.tags
                .lock()
                .unwrap()
                .get(name)
                .and_then(|m| m.get(tag).cloned())
                .ok_or(StorageError::NotFound)
        }

        async fn list_tags(&self, name: &str) -> Result<Vec<String>, StorageError> {
            let mut v: Vec<String> = self
                .tags
                .lock()
                .unwrap()
                .get(name)
                .map(|m| m.keys().cloned().collect())
                .unwrap_or_default();
            v.sort();
            Ok(v)
        }

        async fn head_manifest(
            &self,
            _name: &str,
            _digest: &Digest,
        ) -> Result<crate::storage::ManifestMeta, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn get_manifest(
            &self,
            name: &str,
            digest: &Digest,
        ) -> Result<(crate::storage::ManifestMeta, Bytes), StorageError> {
            if let Some(err) = self
                .manifest_faults
                .lock()
                .unwrap()
                .remove(&(name.to_string(), digest.as_str().to_string()))
            {
                return Err(err);
            }
            let key = (name.to_string(), digest.as_str().to_string());
            let bytes = self
                .manifests
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .ok_or(StorageError::NotFound)?;
            let meta = crate::storage::ManifestMeta {
                size: bytes.len() as u64,
                media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            };
            Ok((meta, bytes))
        }

        async fn put_manifest(
            &self,
            _name: &str,
            _digest: &Digest,
            _bytes: Bytes,
        ) -> Result<crate::storage::ManifestMeta, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn set_tag(
            &self,
            _name: &str,
            _tag: &str,
            _digest: &Digest,
        ) -> Result<(), StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn mutate_tag(
            &self,
            _name: &str,
            _tag: &str,
            _digest: &Digest,
            _policy: crate::storage::TagMutationPolicy,
        ) -> Result<crate::storage::TagMutation, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn delete_tag(&self, _name: &str, _tag: &str) -> Result<(), StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn list_manifest_digests_page(
            &self,
            repo: &str,
            _continuation_token: Option<&str>,
            _page_limit: usize,
        ) -> Result<(Vec<Digest>, Option<String>), StorageError> {
            if let Some(queue) = self.manifest_pages.lock().unwrap().get_mut(repo) {
                if !queue.is_empty() {
                    return queue.remove(0);
                }
            }
            let mut res = Vec::new();
            for (r, d_str) in self.manifests.lock().unwrap().keys() {
                if r == repo {
                    if let Ok(d) = Digest::parse(d_str) {
                        res.push(d);
                    }
                }
            }
            Ok((res, None))
        }

        async fn list_tags_page(
            &self,
            repo: &str,
            _continuation_token: Option<&str>,
            _page_limit: usize,
        ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
            if let Some(queue) = self.tag_pages.lock().unwrap().get_mut(repo) {
                if !queue.is_empty() {
                    return queue.remove(0);
                }
            }
            let mut res = Vec::new();
            if let Some(tags_map) = self.tags.lock().unwrap().get(repo) {
                for (t, d) in tags_map {
                    res.push((t.clone(), d.clone()));
                }
            }
            Ok((res, None))
        }

        async fn list_referrers_page(
            &self,
            _repo: &str,
            _subject: &Digest,
            _continuation_token: Option<&str>,
            _page_limit: usize,
        ) -> Result<(Vec<crate::storage::ReferrerDescriptor>, Option<String>), StorageError>
        {
            Ok((Vec::new(), None))
        }

        async fn get_tag_with_version(
            &self,
            repo: &str,
            tag: &str,
        ) -> Result<Option<(Digest, String)>, StorageError> {
            match self.resolve_tag(repo, tag).await {
                Ok(d) => Ok(Some((d, "v1".to_string()))),
                Err(StorageError::NotFound) => Ok(None),
                Err(e) => Err(e),
            }
        }

        async fn delete_tag_conditional(
            &self,
            repo: &str,
            tag: &str,
            _expected_version: Option<&str>,
        ) -> Result<crate::storage::ConditionalDeleteResult, StorageError> {
            match self.resolve_tag(repo, tag).await {
                Ok(_) => {
                    self.remove_tag(repo, tag);
                    Ok(crate::storage::ConditionalDeleteResult::Deleted)
                }
                Err(StorageError::NotFound) => {
                    Ok(crate::storage::ConditionalDeleteResult::NotFound)
                }
                Err(e) => Err(e),
            }
        }

        async fn read_lifecycle_journal(&self, _repo: &str) -> Result<Option<Bytes>, StorageError> {
            Ok(None)
        }

        async fn write_lifecycle_journal(
            &self,
            _repo: &str,
            _data: Bytes,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn delete_lifecycle_journal(&self, _repo: &str) -> Result<(), StorageError> {
            Ok(())
        }

        async fn acquire_repo_lease(
            &self,
            _repo: &str,
            _owner_id: &str,
            _lease_id: &str,
            _ttl_secs: u64,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn renew_repo_lease(
            &self,
            _repo: &str,
            _owner_id: &str,
            _lease_id: &str,
            _ttl_secs: u64,
        ) -> Result<bool, StorageError> {
            Ok(true)
        }

        async fn release_repo_lease(
            &self,
            _repo: &str,
            _owner_id: &str,
            _lease_id: &str,
        ) -> Result<(), StorageError> {
            Ok(())
        }

        async fn create_upload(&self) -> Result<crate::storage::UploadMeta, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn upload_status(
            &self,
            _uuid: &str,
        ) -> Result<crate::storage::UploadMeta, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn append_upload(
            &self,
            _uuid: &str,
            _chunk: Bytes,
        ) -> Result<crate::storage::UploadMeta, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn finalize_upload(
            &self,
            _uuid: &str,
            _digest: &Digest,
        ) -> Result<crate::storage::BlobMeta, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn abort_upload(&self, _uuid: &str) -> Result<(), StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn list_referrers(
            &self,
            _name: &str,
            _subject: &Digest,
        ) -> Result<Vec<crate::storage::ReferrerDescriptor>, StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn add_referrer(
            &self,
            _name: &str,
            _subject: &Digest,
            _descriptor: crate::storage::ReferrerDescriptor,
        ) -> Result<(), StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn remove_referrer(
            &self,
            _name: &str,
            _subject: &Digest,
            _referrer: &Digest,
        ) -> Result<(), StorageError> {
            Err(StorageError::Unsupported)
        }

        async fn delete_manifest(&self, _name: &str, _digest: &Digest) -> Result<(), StorageError> {
            Err(StorageError::Unsupported)
        }
    }

    crate::impl_storage_ports!(MockStorage);
    crate::impl_gc_storage_port!(MockStorage);
    crate::impl_cache_eviction_port!(MockStorage);

    fn temp_index_path() -> PathBuf {
        let p = std::env::temp_dir().join(format!("naust-ref-index-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    fn d(ch: char) -> Digest {
        let hex: String = std::iter::repeat_n(ch, 64).collect();
        Digest::parse(&format!("sha256:{hex}")).expect("valid sha256")
    }

    fn bytes(s: String) -> Bytes {
        Bytes::from(s.into_bytes())
    }

    fn index_manifest(child: &Digest) -> Bytes {
        bytes(format!(
            "{{\"schemaVersion\":2,\"manifests\":[{{\"digest\":\"{}\"}}]}}",
            child.as_str()
        ))
    }

    fn image_manifest(config: &Digest, layer: &Digest) -> Bytes {
        bytes(format!(
            "{{\"schemaVersion\":2,\"config\":{{\"digest\":\"{}\"}},\"layers\":[{{\"digest\":\"{}\"}}]}}",
            config.as_str(),
            layer.as_str()
        ))
    }

    fn artifact_manifest(subject: &Digest, blob: &Digest) -> Bytes {
        bytes(format!(
            "{{\"schemaVersion\":2,\"subject\":{{\"digest\":\"{}\"}},\"blobs\":[{{\"digest\":\"{}\"}}]}}",
            subject.as_str(),
            blob.as_str()
        ))
    }

    #[tokio::test]
    async fn pins_are_conservative_and_purge_expired() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");

        let digest = d('e');

        let now = UNIX_EPOCH + Duration::from_secs(100);
        let until = UNIX_EPOCH + Duration::from_secs(110);

        idx.pin_blob(&digest, until, "finalize_upload")
            .expect("pin");

        assert!(idx.is_blob_pinned(&digest, now).expect("is_pinned"));
        assert!(
            !idx.is_blob_pinned(&digest, UNIX_EPOCH + Duration::from_secs(111))
                .expect("is_pinned")
        );

        let removed = idx
            .purge_expired_pins(UNIX_EPOCH + Duration::from_secs(111))
            .expect("purge");
        assert_eq!(removed, 1);

        assert!(
            !idx.is_blob_pinned(&digest, UNIX_EPOCH + Duration::from_secs(200))
                .expect("is_pinned")
        );

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn pin_does_not_shorten_existing_pin() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");

        let digest = d('f');

        idx.pin_blob(&digest, UNIX_EPOCH + Duration::from_secs(200), "first")
            .expect("pin");

        // Attempt to shorten to 150; should be ignored.
        idx.pin_blob(&digest, UNIX_EPOCH + Duration::from_secs(150), "shorten")
            .expect("pin");

        assert!(
            idx.is_blob_pinned(&digest, UNIX_EPOCH + Duration::from_secs(160))
                .expect("is_pinned")
        );

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn check_health_before_rebuild_is_corrupt() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");

        let err = idx.check_health().expect_err("should be corrupt");
        match err {
            RefIndexError::Corrupt(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn rebuild_then_check_health_ok_and_references_resolve() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");

        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let root = d('a');
        let cfg = d('b');
        let layer = d('c');

        mock.set_tag_sync(repo, "latest", &root);
        mock.put_manifest_bytes(repo, &root, image_manifest(&cfg, &layer));

        idx.rebuild(&storage).await.expect("rebuild");
        idx.check_health().expect("healthy");

        assert!(idx.is_blob_referenced(&layer).expect("lookup"));
        assert!(idx.is_blob_referenced(&cfg).expect("lookup"));
        assert!(!idx.is_blob_referenced(&d('d')).expect("lookup"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn index_manifest_to_child_manifest_traversal_works() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");

        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let root_index = d('a');
        let child = d('b');
        let layer = d('c');

        mock.set_tag_sync(repo, "v1", &root_index);
        mock.put_manifest_bytes(repo, &root_index, index_manifest(&child));
        mock.put_manifest_bytes(repo, &child, image_manifest(&d('d'), &layer));

        idx.rebuild(&storage).await.expect("rebuild");

        assert!(idx.is_blob_referenced(&layer).expect("lookup"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn artifact_subject_and_blobs_are_indexed() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let root = d('a');
        let subject = d('b');
        let blob = d('c');

        mock.set_tag_sync(repo, "artifact", &root);
        mock.put_manifest_bytes(repo, &root, artifact_manifest(&subject, &blob));

        idx.rebuild(&storage).await.expect("rebuild");
        assert!(idx.is_blob_referenced(&blob).expect("lookup"));
        assert!(idx.is_blob_referenced(&subject).expect("lookup"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn on_tag_set_is_idempotent_for_same_digest() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        // Bring index to a healthy state.
        idx.meta
            .insert(META_SCHEMA_VERSION, encode_u32(SCHEMA_VERSION))
            .expect("meta");
        idx.meta.insert(META_STATE, META_STATE_READY).expect("meta");

        let repo = "org/repo";
        let root = d('a');
        mock.put_manifest_bytes(repo, &root, image_manifest(&d('b'), &d('c')));

        idx.on_tag_set(&storage, repo, "latest", &root, None)
            .await
            .expect("set");
        idx.on_tag_set(&storage, repo, "latest", &root, None)
            .await
            .expect("set idempotent");

        let v = idx
            .root_counts
            .get(root.as_str().as_bytes())
            .expect("get")
            .expect("present");
        let n = decode_u64(&v).expect("decode");
        assert_eq!(n, 1, "refcount should not double on same tag->digest");

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn sync_repo_tags_updates_counts_and_removes_deleted_tags() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let r1 = d('a');
        let r2 = d('b');
        mock.set_tag_sync(repo, "t1", &r1);
        mock.set_tag_sync(repo, "t2", &r2);
        mock.put_manifest_bytes(repo, &r1, image_manifest(&d('c'), &d('d')));
        mock.put_manifest_bytes(repo, &r2, image_manifest(&d('e'), &d('f')));

        idx.rebuild(&storage).await.expect("rebuild");

        // 1. Removing tag t2 in storage removes tag alias from tag_to_root, but r2 is still a stored manifest and remains in root_counts.
        mock.remove_tag(repo, "t2");
        idx.sync_repo_tags(&storage, repo).await.expect("sync");

        assert!(
            idx.root_counts
                .contains_key(r1.as_str().as_bytes())
                .expect("contains")
        );
        assert!(
            idx.root_counts
                .contains_key(r2.as_str().as_bytes())
                .expect("contains")
        );
        assert!(
            idx.tag_to_root
                .get(tag_key(repo, "t2"))
                .expect("get")
                .is_none()
        );

        // 2. Removing manifest r2 from storage removes r2 from root_counts on rebuild/sync.
        mock.remove_manifest(repo, &r2);
        idx.rebuild(&storage).await.expect("rebuild");

        assert!(
            idx.root_counts
                .contains_key(r1.as_str().as_bytes())
                .expect("contains")
        );
        assert!(
            !idx.root_counts
                .contains_key(r2.as_str().as_bytes())
                .expect("contains")
        );

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn corruption_detection_and_auto_rebuild() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let root = d('a');
        mock.set_tag_sync(repo, "latest", &root);
        mock.put_manifest_bytes(repo, &root, image_manifest(&d('b'), &d('c')));

        // Simulate an incomplete prior rebuild.
        idx.meta
            .insert(META_SCHEMA_VERSION, encode_u32(SCHEMA_VERSION))
            .expect("meta");
        idx.meta
            .insert(META_STATE, META_STATE_BUILDING)
            .expect("meta");

        let err = idx
            .ensure_healthy_or_rebuild(&storage, false, false)
            .await
            .expect_err("should refuse when auto rebuild disabled");
        match err {
            RefIndexError::Corrupt(_) => {}
            other => panic!("unexpected: {other:?}"),
        }

        idx.ensure_healthy_or_rebuild(&storage, true, false)
            .await
            .expect("auto rebuild");
        idx.check_health().expect("healthy");

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn corrupted_rev_edges_entry_is_detected() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let root = d('a');
        let layer = d('b');
        mock.set_tag_sync(repo, "latest", &root);
        mock.put_manifest_bytes(repo, &root, image_manifest(&d('c'), &layer));

        idx.rebuild(&storage).await.expect("rebuild");

        // Corrupt the rev_edges value for the layer.
        idx.rev_edges
            .insert(layer.as_str().as_bytes(), b"\xff\xff\xff")
            .expect("corrupt");

        let err = idx
            .is_blob_referenced(&layer)
            .expect_err("should be corrupt");
        match err {
            RefIndexError::Corrupt(_) => {}
            other => panic!("unexpected: {other:?}"),
        }

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_pin_lifecycle_success_removes_pin() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let digest = d('e');
        let op_id = "op-12345";
        let now = SystemTime::now();
        let until = now + Duration::from_secs(3600);

        // 1. Acquire pin before publication
        idx.acquire_pin(&digest, op_id, until, "upload_finalizing")
            .unwrap();
        assert!(idx.is_blob_pinned(&digest, now).unwrap());

        // 2. Publication completes -> release pin
        let released = idx.release_pin(&digest, op_id).unwrap();
        assert!(released);
        assert!(!idx.is_blob_pinned(&digest, now).unwrap());

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_pin_lifecycle_failed_commit_retains_protection() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let digest = d('e');
        let op_id = "op-crash-test";
        let now = SystemTime::now();
        let until = now + Duration::from_secs(3600);

        // Acquire pin
        idx.acquire_pin(&digest, op_id, until, "upload_finalizing")
            .unwrap();

        // Simulate crash during commit: pin remains active and protected
        assert!(idx.is_blob_pinned(&digest, now).unwrap());
        assert!(
            idx.is_blob_pinned(&digest, now + Duration::from_secs(1800))
                .unwrap()
        );

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_pin_lifecycle_recovery_removes_pin() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let digest = d('e');
        let op_id = "op-recovered";
        let now = SystemTime::now();
        let until = now + Duration::from_secs(3600);

        idx.acquire_pin(&digest, op_id, until, "upload_finalizing")
            .unwrap();
        assert!(idx.is_blob_pinned(&digest, now).unwrap());

        // Recovery succeeds -> releases pin
        idx.release_pin(&digest, op_id).unwrap();
        assert!(!idx.is_blob_pinned(&digest, now).unwrap());

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_pin_lifecycle_expired_abandoned_pin_purged() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let digest = d('e');
        let op_id = "op-abandoned";
        let now = SystemTime::now();
        let until = now + Duration::from_secs(10);

        idx.acquire_pin(&digest, op_id, until, "upload_finalizing")
            .unwrap();
        assert!(idx.is_blob_pinned(&digest, now).unwrap());

        // Advance past expiration
        let future = now + Duration::from_secs(20);
        assert!(!idx.is_blob_pinned(&digest, future).unwrap());

        // Purge expired
        let purged = idx.purge_expired_pins(future).unwrap();
        assert_eq!(purged, 1);

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_pin_lifecycle_idempotent_cleanup() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let digest = d('e');
        let op_id = "op-idempotent";
        let now = SystemTime::now();
        let until = now + Duration::from_secs(100);

        idx.acquire_pin(&digest, op_id, until, "upload_finalizing")
            .unwrap();

        // First release returns true
        assert!(idx.release_pin(&digest, op_id).unwrap());
        // Second release returns false without error
        assert!(!idx.release_pin(&digest, op_id).unwrap());

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn test_pin_lifecycle_unreferenced_blob_becomes_gc_eligible() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        idx.meta
            .insert(META_SCHEMA_VERSION, encode_u32(SCHEMA_VERSION))
            .expect("meta");
        idx.meta.insert(META_STATE, META_STATE_READY).expect("meta");

        let digest = d('e');
        let op_id = "op-gc-eligible";
        let now = SystemTime::now();
        let until = now + Duration::from_secs(10);

        idx.acquire_pin(&digest, op_id, until, "upload_finalizing")
            .unwrap();

        // Release pin upon commit
        idx.release_pin(&digest, op_id).unwrap();

        // Not referenced by any manifest and not pinned -> GC eligible
        assert!(!idx.is_blob_pinned(&digest, now).unwrap());
        assert!(!idx.is_blob_referenced(&digest).unwrap());

        let _ = std::fs::remove_dir_all(path);
    }

    fn snapshot_tree(tree: &sled::Tree) -> Vec<(Vec<u8>, Vec<u8>)> {
        tree.iter()
            .map(|r| r.expect("iter"))
            .map(|(k, v)| (k.to_vec(), v.to_vec()))
            .collect()
    }

    #[tokio::test]
    async fn test_sync_repo_first_page_manifest_listing_failure_preserves_populated_index() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let other_repo = "org/other";
        let r1 = d('1');
        let r_other = d('9');

        mock.set_tag_sync(repo, "t1", &r1);
        mock.put_manifest_bytes(repo, &r1, image_manifest(&d('2'), &d('3')));

        mock.set_tag_sync(other_repo, "t_other", &r_other);
        mock.put_manifest_bytes(other_repo, &r_other, image_manifest(&d('4'), &d('5')));

        // Populate initial index
        idx.sync_repo_manifests_and_tags(&storage, other_repo)
            .await
            .expect("sync other");
        idx.sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect("sync repo");

        let tags_before = snapshot_tree(&idx.tag_to_root);
        let roots_before = snapshot_tree(&idx.root_counts);
        let edges_before = snapshot_tree(&idx.rev_edges);
        let meta_before = snapshot_tree(&idx.meta);

        // Inject first-page manifest listing error
        mock.queue_manifest_page(
            repo,
            Err(StorageError::backend("injected manifest page 1 failure")),
        );

        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("should fail");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("injected manifest page 1 failure"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // Verify byte-for-byte preservation across all trees
        assert_eq!(snapshot_tree(&idx.tag_to_root), tags_before);
        assert_eq!(snapshot_tree(&idx.root_counts), roots_before);
        assert_eq!(snapshot_tree(&idx.rev_edges), edges_before);
        assert_eq!(snapshot_tree(&idx.meta), meta_before);

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_later_page_manifest_listing_failure_preserves_index() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let r1 = d('1');
        let r2 = d('2');
        mock.put_manifest_bytes(repo, &r1, image_manifest(&d('3'), &d('4')));
        mock.put_manifest_bytes(repo, &r2, image_manifest(&d('5'), &d('6')));

        mock.queue_manifest_page(repo, Ok((vec![r1.clone()], Some("page2".to_string()))));
        mock.queue_manifest_page(
            repo,
            Err(StorageError::backend("injected manifest page 2 failure")),
        );

        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("should fail on page 2");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("injected manifest page 2 failure"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // r1 was on page 1, but must NOT have been incremented in root_counts
        assert!(
            !idx.root_counts
                .contains_key(r1.as_str().as_bytes())
                .unwrap()
        );
        assert!(
            !idx.root_counts
                .contains_key(r2.as_str().as_bytes())
                .unwrap()
        );
        assert_eq!(snapshot_tree(&idx.rev_edges), Vec::new());

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_root_and_recursive_child_read_and_parse_failures() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        // 1. Root read failure
        let repo1 = "org/repo1";
        let r1 = d('1');
        mock.put_manifest_bytes(repo1, &r1, image_manifest(&d('3'), &d('4')));
        mock.inject_manifest_fault(repo1, &r1, StorageError::backend("root read error"));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo1)
            .await
            .expect_err("root read fail");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("root read error"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            !idx.root_counts
                .contains_key(r1.as_str().as_bytes())
                .unwrap()
        );

        // 2. Root parse failure
        let repo2 = "org/repo2";
        let r2 = d('2');
        mock.put_manifest_bytes(repo2, &r2, bytes("invalid manifest json".to_string()));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo2)
            .await
            .expect_err("root parse fail");
        match err {
            RefIndexError::ManifestParse(_) => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            !idx.root_counts
                .contains_key(r2.as_str().as_bytes())
                .unwrap()
        );

        // 3. Recursive child read failure
        let repo3 = "org/repo3";
        let r3 = d('3');
        let child3 = d('c');
        mock.put_manifest_bytes(repo3, &r3, index_manifest(&child3));
        mock.inject_manifest_fault(repo3, &child3, StorageError::backend("child read error"));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo3)
            .await
            .expect_err("child read fail");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("child read error"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            !idx.root_counts
                .contains_key(r3.as_str().as_bytes())
                .unwrap()
        );
        assert_eq!(snapshot_tree(&idx.rev_edges), Vec::new());

        // 4. Recursive child parse failure
        let repo4 = "org/repo4";
        let r4 = d('4');
        let child4 = d('d');
        mock.put_manifest_bytes(repo4, &r4, index_manifest(&child4));
        mock.put_manifest_bytes(repo4, &child4, bytes("invalid child json".to_string()));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo4)
            .await
            .expect_err("child parse fail");
        match err {
            RefIndexError::ManifestParse(_) => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            !idx.root_counts
                .contains_key(r4.as_str().as_bytes())
                .unwrap()
        );
        assert_eq!(snapshot_tree(&idx.rev_edges), Vec::new());

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_first_and_later_tag_page_failures_preserve_index() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let r1 = d('1');
        mock.put_manifest_bytes(repo, &r1, image_manifest(&d('2'), &d('3')));

        // Case A: First tag page failure
        mock.queue_tag_page(repo, Err(StorageError::backend("tag page 1 failure")));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("tag page 1 fail");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("tag page 1 failure"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            !idx.root_counts
                .contains_key(r1.as_str().as_bytes())
                .unwrap()
        );
        assert_eq!(snapshot_tree(&idx.tag_to_root), Vec::new());

        // Case B: Later tag page failure
        mock.queue_tag_page(
            repo,
            Ok((
                vec![("t1".to_string(), r1.clone())],
                Some("page2".to_string()),
            )),
        );
        mock.queue_tag_page(repo, Err(StorageError::backend("tag page 2 failure")));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("tag page 2 fail");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("tag page 2 failure"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            !idx.root_counts
                .contains_key(r1.as_str().as_bytes())
                .unwrap()
        );
        assert_eq!(snapshot_tree(&idx.tag_to_root), Vec::new());

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_token_cycles_detected_in_both_pagination_streams() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let r1 = d('1');
        let r2 = d('2');
        let r3 = d('3');
        mock.put_manifest_bytes(repo, &r1, image_manifest(&d('a'), &d('b')));
        mock.put_manifest_bytes(repo, &r2, image_manifest(&d('c'), &d('d')));
        mock.put_manifest_bytes(repo, &r3, image_manifest(&d('e'), &d('f')));

        // 1. Manifest immediate cycle: tok_a -> tok_a
        mock.queue_manifest_page(repo, Ok((vec![r1.clone()], Some("tok_a".to_string()))));
        mock.queue_manifest_page(repo, Ok((vec![r2.clone()], Some("tok_a".to_string()))));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("immediate cycle");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("pagination cycle detected on continuation token 'tok_a' in repository 'org/repo'"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(snapshot_tree(&idx.root_counts), Vec::new());

        // 2. Manifest multi-token cycle: tok_1 -> tok_2 -> tok_1
        mock.queue_manifest_page(repo, Ok((vec![r1.clone()], Some("tok_1".to_string()))));
        mock.queue_manifest_page(repo, Ok((vec![r2.clone()], Some("tok_2".to_string()))));
        mock.queue_manifest_page(repo, Ok((vec![r3.clone()], Some("tok_1".to_string()))));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("multi cycle");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("pagination cycle detected on continuation token 'tok_1' in repository 'org/repo'"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(snapshot_tree(&idx.root_counts), Vec::new());

        // 3. Tag immediate cycle: tag_tok_a -> tag_tok_a
        mock.queue_tag_page(
            repo,
            Ok((
                vec![("t1".to_string(), r1.clone())],
                Some("tag_tok_a".to_string()),
            )),
        );
        mock.queue_tag_page(
            repo,
            Ok((
                vec![("t2".to_string(), r2.clone())],
                Some("tag_tok_a".to_string()),
            )),
        );
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("tag immediate cycle");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("pagination cycle detected on continuation token 'tag_tok_a' in repository 'org/repo'"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(snapshot_tree(&idx.tag_to_root), Vec::new());

        // 4. Tag multi-token cycle: tag_tok_1 -> tag_tok_2 -> tag_tok_1
        mock.queue_tag_page(
            repo,
            Ok((
                vec![("t1".to_string(), r1.clone())],
                Some("tag_tok_1".to_string()),
            )),
        );
        mock.queue_tag_page(
            repo,
            Ok((
                vec![("t2".to_string(), r2.clone())],
                Some("tag_tok_2".to_string()),
            )),
        );
        mock.queue_tag_page(
            repo,
            Ok((
                vec![("t3".to_string(), r3.clone())],
                Some("tag_tok_1".to_string()),
            )),
        );
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("tag multi cycle");
        match err {
            RefIndexError::Storage(err) => {
                assert!(err.to_string().contains("pagination cycle detected on continuation token 'tag_tok_1' in repository 'org/repo'"));
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(snapshot_tree(&idx.tag_to_root), Vec::new());

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_tolerates_missing_root_and_missing_child_retaining_parent_edges() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let missing_root = d('1');
        let parent_root = d('2');
        let missing_child = d('3');

        // missing_root is in manifest listing but get_manifest returns NotFound
        mock.queue_manifest_page(
            repo,
            Ok((vec![missing_root.clone(), parent_root.clone()], None)),
        );

        // parent_root references missing_child
        mock.put_manifest_bytes(repo, &parent_root, index_manifest(&missing_child));
        // missing_child is NOT put into manifests -> get_manifest returns NotFound

        idx.sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect("should tolerate NotFound roots and children");

        // Tolerated NotFound root is counted in root_counts matching existing line 510 behavior
        assert!(
            idx.root_counts
                .contains_key(missing_root.as_str().as_bytes())
                .unwrap()
        );
        assert!(
            idx.root_counts
                .contains_key(parent_root.as_str().as_bytes())
                .unwrap()
        );

        // The parent edge to missing_child is retained even though missing_child was absent
        let parents_raw = idx
            .rev_edges
            .get(missing_child.as_str().as_bytes())
            .unwrap()
            .expect("parent edge retained");
        let parents = decode_parent_list(&parents_raw).expect("decode");
        assert_eq!(parents, vec![parent_root.as_str().to_string()]);

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_successful_recursive_dag_and_tag_sync() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        idx.meta
            .insert(META_SCHEMA_VERSION, encode_u32(SCHEMA_VERSION))
            .expect("meta");
        idx.meta.insert(META_STATE, META_STATE_READY).expect("meta");

        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let root_index = d('a');
        let child_manifest = d('b');
        let config = d('c');
        let layer = d('d');

        mock.set_tag_sync(repo, "latest", &root_index);
        mock.put_manifest_bytes(repo, &root_index, index_manifest(&child_manifest));
        mock.put_manifest_bytes(repo, &child_manifest, image_manifest(&config, &layer));

        idx.sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect("successful sync");

        assert!(
            idx.root_counts
                .contains_key(root_index.as_str().as_bytes())
                .unwrap()
        );
        let tag_val = idx
            .tag_to_root
            .get(tag_key(repo, "latest"))
            .unwrap()
            .unwrap();
        assert_eq!(tag_val.as_ref(), root_index.as_str().as_bytes());

        // Reverse edges are navigable and blobs are reachable
        assert!(idx.is_blob_referenced(&layer).expect("layer reachable"));
        assert!(idx.is_blob_referenced(&config).expect("config reachable"));

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_repeated_success_is_idempotent() {
        // T1: repeated successful sync of unchanged storage state must not
        // inflate accounting (previously this test documented counts 1/2/3;
        // schema v2 per-repository provenance makes sync idempotent).
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let r1 = d('1');
        mock.set_tag_sync(repo, "t1", &r1);
        mock.put_manifest_bytes(repo, &r1, image_manifest(&d('2'), &d('3')));

        for run in 1..=3 {
            idx.sync_repo_manifests_and_tags(&storage, repo)
                .await
                .unwrap_or_else(|e| panic!("run {run}: {e}"));
            assert_eq!(
                idx.debug_root_count(&r1),
                Some(1),
                "run {run}: exactly one contributing repository"
            );
            assert_eq!(
                idx.debug_contribution(repo, &r1),
                Some((true, 1)),
                "run {run}: manifest presence + one tag reference"
            );
        }
        // Full logical accounting is byte-stable across repeated syncs.
        idx.sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect("run 4");
        let roots_a = snapshot_tree(&idx.root_counts);
        let contribs_a = snapshot_tree(&idx.repo_roots);
        idx.sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect("run 5");
        assert_eq!(snapshot_tree(&idx.root_counts), roots_a);
        assert_eq!(snapshot_tree(&idx.repo_roots), contribs_a);

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_failure_followed_by_success_matches_single_success_from_identical_state()
     {
        let path_a = temp_index_path();
        let path_b = temp_index_path();
        let idx_a = BlobRefIndex::open(path_a.clone()).expect("open a");
        let idx_b = BlobRefIndex::open(path_b.clone()).expect("open b");

        let mock_a = Arc::new(MockStorage::new());
        let mock_b = Arc::new(MockStorage::new());

        let repo = "org/repo";
        let r1 = d('1');
        let r2 = d('2');
        mock_a.set_tag_sync(repo, "v1", &r1);
        mock_a.put_manifest_bytes(repo, &r1, image_manifest(&d('3'), &d('4')));
        mock_a.put_manifest_bytes(repo, &r2, image_manifest(&d('5'), &d('6')));

        mock_b.set_tag_sync(repo, "v1", &r1);
        mock_b.put_manifest_bytes(repo, &r1, image_manifest(&d('3'), &d('4')));
        mock_b.put_manifest_bytes(repo, &r2, image_manifest(&d('5'), &d('6')));

        // Path A: clean single success
        idx_a
            .sync_repo_manifests_and_tags(&mock_a, repo)
            .await
            .expect("sync a");

        // Path B: failure on page 2, followed by clean success
        mock_b.queue_manifest_page(repo, Ok((vec![r1.clone()], Some("page2".to_string()))));
        mock_b.queue_manifest_page(repo, Err(StorageError::backend("transient page 2 error")));
        idx_b
            .sync_repo_manifests_and_tags(&mock_b, repo)
            .await
            .expect_err("expected failure");

        // Now run successful sync on path B
        idx_b
            .sync_repo_manifests_and_tags(&mock_b, repo)
            .await
            .expect("retry b success");

        // Compare all trees: identical state
        assert_eq!(
            snapshot_tree(&idx_a.tag_to_root),
            snapshot_tree(&idx_b.tag_to_root)
        );
        assert_eq!(
            snapshot_tree(&idx_a.root_counts),
            snapshot_tree(&idx_b.root_counts)
        );
        assert_eq!(
            snapshot_tree(&idx_a.rev_edges),
            snapshot_tree(&idx_b.rev_edges)
        );

        let _ = std::fs::remove_dir_all(path_a);
        let _ = std::fs::remove_dir_all(path_b);
    }

    /// Discovery port that fails repository listing deterministically
    /// (drives a genuine failed rebuild -> durable BUILDING).
    struct FailingDiscoveryPort;
    #[async_trait]
    impl crate::storage::RepositoryCatalogReader for FailingDiscoveryPort {
        async fn list_repositories(&self) -> Result<Vec<String>, StorageError> {
            Err(StorageError::backend("injected discovery failure"))
        }
        async fn repo_timestamps(
            &self,
            _n: &str,
        ) -> Result<crate::storage::RepoTimestamps, StorageError> {
            Err(StorageError::backend("unused"))
        }
    }
    #[async_trait]
    impl crate::storage::TagReader for FailingDiscoveryPort {
        async fn resolve_tag(&self, _n: &str, _t: &str) -> Result<Digest, StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn list_tags(&self, _n: &str) -> Result<Vec<String>, StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn list_tags_page(
            &self,
            _r: &str,
            _c: Option<&str>,
            _p: usize,
        ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn get_tag_with_version(
            &self,
            _r: &str,
            _t: &str,
        ) -> Result<Option<(Digest, String)>, StorageError> {
            Err(StorageError::backend("unused"))
        }
    }
    #[async_trait]
    impl crate::storage::ManifestReader for FailingDiscoveryPort {
        async fn head_manifest(
            &self,
            _n: &str,
            _d: &Digest,
        ) -> Result<crate::storage::ManifestMeta, StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn get_manifest(
            &self,
            _n: &str,
            _d: &Digest,
        ) -> Result<(crate::storage::ManifestMeta, Bytes), StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn list_manifest_digests_page(
            &self,
            _r: &str,
            _c: Option<&str>,
            _p: usize,
        ) -> Result<(Vec<Digest>, Option<String>), StorageError> {
            Err(StorageError::backend("unused"))
        }
    }
    impl crate::storage::repo_membership::RepositoryBlobMembershipStorage for FailingDiscoveryPort {}

    /// Discovery port whose FIRST repository listing signals `started` and
    /// then blocks until `release` — a deterministic mid-rebuild hold point.
    /// Subsequent listings return an empty catalog immediately. Counts every
    /// listing call.
    struct GatedStorage {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        started: Arc<tokio::sync::Semaphore>,
        release: Arc<tokio::sync::Semaphore>,
    }
    impl GatedStorage {
        fn new() -> Self {
            Self {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                started: Arc::new(tokio::sync::Semaphore::new(0)),
                release: Arc::new(tokio::sync::Semaphore::new(0)),
            }
        }
    }
    #[async_trait]
    impl crate::storage::RepositoryCatalogReader for GatedStorage {
        async fn list_repositories(&self) -> Result<Vec<String>, StorageError> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call == 0 {
                self.started.add_permits(1);
                let _p = self.release.acquire().await.expect("release semaphore");
            }
            Ok(Vec::new())
        }
        async fn repo_timestamps(
            &self,
            _n: &str,
        ) -> Result<crate::storage::RepoTimestamps, StorageError> {
            Err(StorageError::backend("unused"))
        }
    }
    #[async_trait]
    impl crate::storage::TagReader for GatedStorage {
        async fn resolve_tag(&self, _n: &str, _t: &str) -> Result<Digest, StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn list_tags(&self, _n: &str) -> Result<Vec<String>, StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn list_tags_page(
            &self,
            _r: &str,
            _c: Option<&str>,
            _p: usize,
        ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn get_tag_with_version(
            &self,
            _r: &str,
            _t: &str,
        ) -> Result<Option<(Digest, String)>, StorageError> {
            Err(StorageError::backend("unused"))
        }
    }
    #[async_trait]
    impl crate::storage::ManifestReader for GatedStorage {
        async fn head_manifest(
            &self,
            _n: &str,
            _d: &Digest,
        ) -> Result<crate::storage::ManifestMeta, StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn get_manifest(
            &self,
            _n: &str,
            _d: &Digest,
        ) -> Result<(crate::storage::ManifestMeta, Bytes), StorageError> {
            Err(StorageError::backend("unused"))
        }
        async fn list_manifest_digests_page(
            &self,
            _r: &str,
            _c: Option<&str>,
            _p: usize,
        ) -> Result<(Vec<Digest>, Option<String>), StorageError> {
            Err(StorageError::backend("unused"))
        }
    }
    impl crate::storage::repo_membership::RepositoryBlobMembershipStorage for GatedStorage {}

    /// Rebuild serialization + waiter coalescing (Recovery Step 1): rebuilds
    /// are destructive (trees cleared before repopulation), so two healers
    /// must never interleave, and a healer that waited out another's
    /// completed rebuild must NOT run a second destructive rebuild. On the
    /// pre-repair base the two `ensure_healthy_or_rebuild` calls rebuilt
    /// CONCURRENTLY (two listing calls; READY publishable mid-scan of the
    /// slower rebuild — "silently ready" while incomplete).
    #[tokio::test]
    async fn test_concurrent_ensure_serializes_and_coalesces_rebuilds() {
        let path = temp_index_path();
        let idx = Arc::new(BlobRefIndex::open(path.clone()).expect("open"));

        // Wedge: a genuinely failed rebuild leaves durable BUILDING.
        idx.rebuild(&FailingDiscoveryPort)
            .await
            .expect_err("injected discovery failure");
        assert!(idx.check_health().is_err(), "BUILDING after failed rebuild");

        let gated = Arc::new(GatedStorage::new());

        // Healer A enters the rebuild and blocks mid-scan (deterministic
        // hold inside its first listing call).
        let idx_a = Arc::clone(&idx);
        let gated_a = Arc::clone(&gated);
        let a = tokio::spawn(async move {
            idx_a
                .ensure_healthy_or_rebuild(gated_a.as_ref(), true, false)
                .await
        });
        let _s = gated.started.acquire().await.expect("A reached the hold");

        // Healer B arrives while A holds the rebuild gate.
        let idx_b = Arc::clone(&idx);
        let gated_b = Arc::clone(&gated);
        let b_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let b_done_flag = Arc::clone(&b_done);
        let b = tokio::spawn(async move {
            let r = idx_b
                .ensure_healthy_or_rebuild(gated_b.as_ref(), true, false)
                .await;
            b_done_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            r
        });

        // B must not complete while A is mid-rebuild (bounded cooperative
        // yields; the gate guarantees this — the assertion documents it).
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        assert!(
            !b_done.load(std::sync::atomic::Ordering::SeqCst),
            "a second healer must not complete while a rebuild is mid-scan"
        );

        // Release A; both healers finish; B coalesces (no second rebuild).
        gated.release.add_permits(1);
        a.await.unwrap().expect("healer A rebuild succeeds");
        b.await
            .unwrap()
            .expect("healer B coalesces onto A's result");

        assert_eq!(
            gated.calls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exactly ONE rebuild ran: the waiter re-checked health under the \
             gate and never issued a second destructive rebuild"
        );
        idx.check_health()
            .expect("healthy after coalesced recovery");

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_rebuild_failure_retains_building_state() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let repo = "org/repo";
        let r1 = d('1');
        mock.set_tag_sync(repo, "latest", &r1);
        mock.put_manifest_bytes(repo, &r1, image_manifest(&d('2'), &d('3')));

        // Initial rebuild succeeds -> READY
        idx.rebuild(&storage).await.expect("initial rebuild");
        idx.check_health().expect("healthy");

        // Second rebuild encounters discovery failure
        mock.queue_manifest_page(repo, Err(StorageError::backend("storage unavailable")));
        idx.rebuild(&storage).await.expect_err("rebuild fails");

        // State remains BUILDING; health check fails
        let state = idx.meta.get(META_STATE).unwrap().unwrap();
        assert_eq!(state.as_ref(), META_STATE_BUILDING);

        let err = idx.check_health().expect_err("should be corrupt/building");
        match err {
            RefIndexError::Corrupt(msg) => {
                assert!(msg.contains("index not ready (previous rebuild incomplete?)"));
            }
            other => panic!("unexpected: {other:?}"),
        }

        let _ = std::fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_sync_repo_real_fs_promoted_listing_failure_preserves_populated_index() {
        use crate::storage::fs::FsStorage;

        let index_dir = temp_index_path();
        let idx = BlobRefIndex::open(index_dir.clone()).expect("open index");
        idx.meta
            .insert(META_SCHEMA_VERSION, encode_u32(SCHEMA_VERSION))
            .expect("set schema");
        idx.meta
            .insert(META_STATE, META_STATE_READY)
            .expect("set state");

        let storage_dir = tempfile::tempdir().expect("create storage dir");
        let root = storage_dir.path().join("storage-root");
        // Distinctive limit of 1 entry to induce promoted-listing failure
        let storage = FsStorage::try_new_with_limits(
            root.clone(),
            1024 * 1024,
            storage_fs::DirEnumerationLimits::new(1, 100_000),
        )
        .expect("create fs storage");

        let unaffected_repo = "unaffected/repo";
        let target_repo = "target/repo";

        let r_unaff = d('a');
        let b_unaff = d('1');
        let m_unaff = image_manifest(&b_unaff, &d('2'));

        let r_target_1 = d('b');
        let b_target_1 = d('3');
        let m_target_1 = image_manifest(&b_target_1, &d('4'));

        // Write initial valid manifests and tags
        storage
            .put_manifest(unaffected_repo, &r_unaff, m_unaff)
            .await
            .expect("put unaffected manifest");
        storage
            .set_tag(unaffected_repo, "latest", &r_unaff)
            .await
            .expect("set unaffected tag");

        storage
            .put_manifest(target_repo, &r_target_1, m_target_1)
            .await
            .expect("put target manifest 1");
        storage
            .set_tag(target_repo, "v1", &r_target_1)
            .await
            .expect("set target tag 1");

        // Populate initial index for both repositories
        idx.sync_repo_manifests_and_tags(&storage, unaffected_repo)
            .await
            .expect("sync unaffected repo");
        idx.sync_repo_manifests_and_tags(&storage, target_repo)
            .await
            .expect("sync target repo");

        // Verify initial index is populated across roots, edges, and tags
        assert!(
            !snapshot_tree(&idx.tag_to_root).is_empty(),
            "tag_to_root must not be empty"
        );
        assert!(
            !snapshot_tree(&idx.root_counts).is_empty(),
            "root_counts must not be empty"
        );
        assert!(
            !snapshot_tree(&idx.rev_edges).is_empty(),
            "rev_edges must not be empty"
        );
        assert!(
            idx.is_blob_referenced(&b_unaff).expect("check b_unaff"),
            "unaffected blob must be referenced"
        );
        assert!(
            idx.is_blob_referenced(&b_target_1)
                .expect("check b_target_1"),
            "target blob must be referenced"
        );

        // Snapshot all sled trees before triggering failure
        let tags_before = snapshot_tree(&idx.tag_to_root);
        let roots_before = snapshot_tree(&idx.root_counts);
        let edges_before = snapshot_tree(&idx.rev_edges);
        let pins_before = snapshot_tree(&idx.pins);
        let memberships_before = snapshot_tree(&idx.repo_memberships);
        let meta_before = snapshot_tree(&idx.meta);

        // Add a second manifest to target_repo, exceeding the configured limit of 1 entry
        let r_target_2 = d('c');
        let b_target_2 = d('5');
        let m_target_2 = image_manifest(&b_target_2, &d('6'));
        storage
            .put_manifest(target_repo, &r_target_2, m_target_2)
            .await
            .expect("put target manifest 2");

        // Synchronizing target_repo encounters discovery budget exhaustion
        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_manifests: 1,
            ..DiscoveryLimits::PRODUCTION
        }));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, target_repo)
            .await
            .expect_err("sync must fail due to limit exceeded");

        match err {
            RefIndexError::ResourceLimit(_) => {}
            other => panic!("expected RefIndexError::ResourceLimit, got {other:?}"),
        }

        // Verify byte-for-byte preservation across all sled trees
        assert_eq!(
            snapshot_tree(&idx.tag_to_root),
            tags_before,
            "tag_to_root must be byte-for-byte preserved"
        );
        assert_eq!(
            snapshot_tree(&idx.root_counts),
            roots_before,
            "root_counts must be byte-for-byte preserved"
        );
        assert_eq!(
            snapshot_tree(&idx.rev_edges),
            edges_before,
            "rev_edges must be byte-for-byte preserved"
        );
        assert_eq!(
            snapshot_tree(&idx.pins),
            pins_before,
            "pins must be byte-for-byte preserved"
        );
        assert_eq!(
            snapshot_tree(&idx.repo_memberships),
            memberships_before,
            "repo_memberships must be byte-for-byte preserved"
        );
        assert_eq!(
            snapshot_tree(&idx.meta),
            meta_before,
            "meta must be byte-for-byte preserved"
        );

        // Verify unaffected repository data and target repository data remain referenced and index remains healthy
        assert!(idx.is_blob_referenced(&b_unaff).expect("check b_unaff"));
        assert!(
            idx.is_blob_referenced(&b_target_1)
                .expect("check b_target_1")
        );
        idx.check_health().expect("check_health must succeed");

        let _ = std::fs::remove_dir_all(index_dir);
    }

    // T2: cross-repository manifest survival through the PRODUCTION hooks —
    // deleting repository A's manifest must not erase repository B's live
    // contribution for the same content-addressed digest (previously
    // on_manifest_deleted removed the entire global key).
    #[tokio::test]
    async fn test_cross_repo_manifest_delete_preserves_other_repo_contribution() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let shared = d('7');
        let blob = d('8');
        mock.put_manifest_bytes("repo/a", &shared, image_manifest(&d('9'), &blob));
        mock.put_manifest_bytes("repo/b", &shared, image_manifest(&d('9'), &blob));

        idx.on_manifest_published(&storage, "repo/a", &shared, Some("va"))
            .await
            .expect("publish a");
        idx.on_manifest_published(&storage, "repo/b", &shared, None)
            .await
            .expect("publish b");
        // Bootstrap the meta state so is_blob_referenced's health check passes.
        idx.meta
            .insert(META_SCHEMA_VERSION, encode_u32(SCHEMA_VERSION))
            .unwrap();
        idx.mark_ready().unwrap();

        assert_eq!(
            idx.debug_root_count(&shared),
            Some(2),
            "two contributing repos"
        );
        assert!(idx.is_blob_referenced(&blob).expect("referenced via both"));

        // Re-publishing must be idempotent (no inflation).
        idx.on_manifest_published(&storage, "repo/a", &shared, Some("va"))
            .await
            .expect("republish a");
        assert_eq!(
            idx.debug_root_count(&shared),
            Some(2),
            "re-publish does not inflate"
        );

        // Delete A's manifest: B's contribution survives.
        idx.on_manifest_deleted("repo/a", &shared)
            .expect("delete a");
        assert_eq!(
            idx.debug_root_count(&shared),
            Some(1),
            "B still contributes"
        );
        assert_eq!(idx.debug_contribution("repo/a", &shared), None, "A cleared");
        assert!(
            idx.is_blob_referenced(&blob).expect("still referenced"),
            "digest remains reachable through repository B"
        );

        // Delete B's manifest: no contribution remains.
        idx.on_manifest_deleted("repo/b", &shared)
            .expect("delete b");
        assert_eq!(idx.debug_root_count(&shared), None, "no contributors left");
        assert!(
            !idx.is_blob_referenced(&blob).expect("unreferenced"),
            "digest unreachable once every contribution is gone"
        );

        let _ = std::fs::remove_dir_all(path);
    }

    // T3: per-repository reconciliation removes the stale contribution when the
    // repository's authoritative state changes, without touching another
    // repository's independent contribution to the removed digest.
    #[tokio::test]
    async fn test_sync_reconciliation_replaces_stale_contribution() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let root_a = d('a');
        let root_b = d('b');

        // Other repo independently contributes root_a.
        mock.put_manifest_bytes("other", &root_a, image_manifest(&d('c'), &d('d')));
        idx.sync_repo_manifests_and_tags(&storage, "other")
            .await
            .expect("sync other");

        // R contributes root_a initially.
        mock.put_manifest_bytes("r", &root_a, image_manifest(&d('c'), &d('d')));
        idx.sync_repo_manifests_and_tags(&storage, "r")
            .await
            .expect("sync r (a)");
        assert_eq!(idx.debug_root_count(&root_a), Some(2));

        // Authoritative state changes: R now contributes root_b instead.
        mock.remove_manifest("r", &root_a);
        mock.put_manifest_bytes("r", &root_b, image_manifest(&d('e'), &d('f')));
        idx.sync_repo_manifests_and_tags(&storage, "r")
            .await
            .expect("sync r (b)");

        assert_eq!(
            idx.debug_contribution("r", &root_a),
            None,
            "stale contribution removed"
        );
        assert_eq!(idx.debug_contribution("r", &root_b), Some((true, 0)));
        assert_eq!(
            idx.debug_root_count(&root_a),
            Some(1),
            "other repo's independent contribution intact"
        );
        assert_eq!(idx.debug_root_count(&root_b), Some(1));

        let _ = std::fs::remove_dir_all(path);
    }

    // T4: tag create / retarget / delete keep contributions balanced and
    // equivalent to rebuild semantics, including shared digests across repos.
    #[tokio::test]
    async fn test_tag_mutation_contribution_balance() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let m1 = d('1');
        let m2 = d('2');
        mock.put_manifest_bytes("r", &m1, image_manifest(&d('3'), &d('4')));
        mock.put_manifest_bytes("r", &m2, image_manifest(&d('5'), &d('6')));
        // Another repo also tags m1: its contribution must be unaffected.
        mock.put_manifest_bytes("s", &m1, image_manifest(&d('3'), &d('4')));
        idx.on_tag_set(&storage, "s", "keep", &m1, None)
            .await
            .expect("s tag");
        assert_eq!(idx.debug_contribution("s", &m1), Some((false, 1)));

        // Create.
        idx.on_tag_set(&storage, "r", "t", &m1, None)
            .await
            .expect("create");
        assert_eq!(idx.debug_contribution("r", &m1), Some((false, 1)));
        assert_eq!(idx.debug_root_count(&m1), Some(2));

        // Same-target re-set: no change.
        idx.on_tag_set(&storage, "r", "t", &m1, None)
            .await
            .expect("re-set");
        assert_eq!(idx.debug_contribution("r", &m1), Some((false, 1)));
        assert_eq!(idx.debug_root_count(&m1), Some(2));

        // Retarget t: m1 -> m2 (via the TagMutation hook).
        idx.on_tag_mutation(
            &storage,
            "r",
            "t",
            &m2,
            &crate::storage::TagMutation::Replaced {
                previous: m1.clone(),
            },
        )
        .await
        .expect("retarget");
        assert_eq!(
            idx.debug_contribution("r", &m1),
            None,
            "old target released"
        );
        assert_eq!(idx.debug_contribution("r", &m2), Some((false, 1)));
        assert_eq!(
            idx.debug_root_count(&m1),
            Some(1),
            "repo s still contributes m1"
        );
        assert_eq!(idx.debug_root_count(&m2), Some(1));

        // Delete.
        idx.on_tag_deleted("r", "t").expect("delete tag");
        assert_eq!(idx.debug_contribution("r", &m2), None);
        assert_eq!(idx.debug_root_count(&m2), None);
        assert_eq!(
            idx.debug_root_count(&m1),
            Some(1),
            "repo s untouched throughout"
        );

        let _ = std::fs::remove_dir_all(path);
    }

    // T6: schema bump — a v1 index is recognized as requiring rebuild by the
    // existing mechanism, the rebuild produces correct v2 accounting, and a
    // reopen uses the new schema normally.
    #[tokio::test]
    async fn test_schema_bump_forces_rebuild_and_reopen_is_healthy() {
        let path = temp_index_path();
        {
            let idx = BlobRefIndex::open(path.clone()).expect("open");
            // Simulate an old (v1) on-disk index: old schema marker + a stale
            // inflated global count with no provenance.
            idx.meta.insert(META_SCHEMA_VERSION, encode_u32(1)).unwrap();
            idx.meta.insert(META_STATE, META_STATE_READY).unwrap();
            idx.root_counts
                .insert(d('1').as_str().as_bytes(), encode_u64(3))
                .unwrap();
            idx.flush().unwrap();
        }

        let idx = BlobRefIndex::open(path.clone()).expect("reopen");
        let err = idx.check_health().expect_err("v1 schema must be rejected");
        assert!(matches!(err, RefIndexError::Corrupt(_)));

        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();
        let m1 = d('1');
        mock.set_tag_sync("r", "t", &m1);
        mock.put_manifest_bytes("r", &m1, image_manifest(&d('2'), &d('3')));

        idx.ensure_healthy_or_rebuild(&storage, true, false)
            .await
            .expect("auto-rebuild on schema mismatch");
        idx.check_health().expect("healthy after rebuild");
        assert_eq!(
            idx.debug_root_count(&m1),
            Some(1),
            "stale inflated count replaced"
        );
        assert_eq!(idx.debug_contribution("r", &m1), Some((true, 1)));

        // Reopen normally under the new schema. Sled releases its file lock
        // asynchronously after drop, so retry briefly and deterministically.
        drop(idx);
        let mut idx2 = None;
        for _ in 0..100 {
            match BlobRefIndex::open(path.clone()) {
                Ok(i) => {
                    idx2 = Some(i);
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        let idx2 = idx2.expect("reopen v2 within retry window");
        idx2.check_health().expect("v2 index healthy on reopen");

        let _ = std::fs::remove_dir_all(path);
    }

    // T7: rebuild equivalence — incremental lifecycle events over two repos
    // (shared digest, distinct digest, tag retarget + deletion) produce the
    // same logical accounting as a clean rebuild of the same state.
    #[tokio::test]
    async fn test_incremental_accounting_matches_clean_rebuild() {
        let inc_path = temp_index_path();
        let reb_path = temp_index_path();
        let inc = BlobRefIndex::open(inc_path.clone()).expect("open inc");
        let reb = BlobRefIndex::open(reb_path.clone()).expect("open reb");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let shared = d('1');
        let only_a = d('2');
        let retired = d('3');

        // Authoritative end state built alongside incremental events.
        mock.put_manifest_bytes("a", &shared, image_manifest(&d('4'), &d('5')));
        mock.put_manifest_bytes("b", &shared, image_manifest(&d('4'), &d('5')));
        mock.put_manifest_bytes("a", &only_a, image_manifest(&d('6'), &d('7')));
        mock.put_manifest_bytes("a", &retired, image_manifest(&d('8'), &d('9')));

        inc.on_manifest_published(&storage, "a", &shared, Some("s"))
            .await
            .unwrap();
        inc.on_manifest_published(&storage, "b", &shared, None)
            .await
            .unwrap();
        inc.on_manifest_published(&storage, "a", &only_a, None)
            .await
            .unwrap();
        inc.on_manifest_published(&storage, "a", &retired, Some("old"))
            .await
            .unwrap();
        mock.set_tag_sync("a", "s", &shared);
        mock.set_tag_sync("a", "old", &retired);

        // Retarget "old" from `retired` to `only_a`, then delete `retired`.
        inc.on_tag_mutation(
            &storage,
            "a",
            "old",
            &only_a,
            &crate::storage::TagMutation::Replaced {
                previous: retired.clone(),
            },
        )
        .await
        .unwrap();
        mock.set_tag_sync("a", "old", &only_a);
        inc.on_manifest_deleted("a", &retired).unwrap();
        mock.remove_manifest("a", &retired);
        mock.remove_tag("a", "nonexistent"); // no-op; keep mock coherent

        // Clean rebuild of the same authoritative end state.
        reb.rebuild(&storage).await.expect("rebuild");

        for digest in [&shared, &only_a, &retired] {
            assert_eq!(
                inc.debug_root_count(digest),
                reb.debug_root_count(digest),
                "global accounting must match rebuild for {digest:?}"
            );
            for repo in ["a", "b"] {
                assert_eq!(
                    inc.debug_contribution(repo, digest),
                    reb.debug_contribution(repo, digest),
                    "contribution must match rebuild for {repo}/{digest:?}"
                );
            }
        }

        let _ = std::fs::remove_dir_all(inc_path);
        let _ = std::fs::remove_dir_all(reb_path);
    }

    // T7b: repeated rebuild converges (byte-stable accounting trees).
    #[tokio::test]
    async fn test_repeated_rebuild_converges() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();
        mock.set_tag_sync("r", "t", &d('1'));
        mock.put_manifest_bytes("r", &d('1'), image_manifest(&d('2'), &d('3')));

        idx.rebuild(&storage).await.expect("rebuild 1");
        let roots = snapshot_tree(&idx.root_counts);
        let contribs = snapshot_tree(&idx.repo_roots);
        idx.rebuild(&storage).await.expect("rebuild 2");
        assert_eq!(snapshot_tree(&idx.root_counts), roots);
        assert_eq!(snapshot_tree(&idx.repo_roots), contribs);

        let _ = std::fs::remove_dir_all(path);
    }

    // T8: ordinary single-repository behavior is unweakened — publish makes
    // blobs referenced, delete makes them unreferenced.
    #[tokio::test]
    async fn test_single_repo_reference_lifecycle_regression() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let m = d('1');
        let blob = d('4');
        mock.put_manifest_bytes("solo", &m, image_manifest(&d('3'), &blob));
        idx.meta
            .insert(META_SCHEMA_VERSION, encode_u32(SCHEMA_VERSION))
            .unwrap();
        idx.mark_ready().unwrap();

        idx.on_manifest_published(&storage, "solo", &m, Some("v1"))
            .await
            .expect("publish");
        assert!(idx.is_blob_referenced(&blob).expect("referenced"));
        assert_eq!(idx.debug_contribution("solo", &m), Some((true, 1)));

        idx.on_tag_deleted("solo", "v1").expect("tag delete");
        assert!(
            idx.is_blob_referenced(&blob).expect("still referenced"),
            "stored manifest keeps the digest live after tag deletion"
        );
        assert_eq!(idx.debug_contribution("solo", &m), Some((true, 0)));

        idx.on_manifest_deleted("solo", &m)
            .expect("manifest delete");
        assert!(!idx.is_blob_referenced(&blob).expect("unreferenced"));
        assert_eq!(idx.debug_contribution("solo", &m), None);
        assert_eq!(idx.debug_root_count(&m), None);

        let _ = std::fs::remove_dir_all(path);
    }

    // ------------------------------------------------------------------
    // REFIDX-BOUNDS: bounded discovery/staging
    // ------------------------------------------------------------------

    fn limits_for_tests() -> DiscoveryLimits {
        // Generous in every dimension; individual tests tighten one knob.
        DiscoveryLimits {
            max_manifests: 1_000,
            max_tags: 1_000,
            max_edges: 10_000,
            max_traversal_nodes: 10_000,
            max_pages: 1_000,
            max_staged_bytes: 1024 * 1024,
        }
    }

    fn dn(i: u32) -> Digest {
        Digest::parse(&format!("sha256:{:064x}", 0x1000 + i)).unwrap()
    }

    fn assert_resource_limit(err: RefIndexError, what: &str) {
        match err {
            RefIndexError::ResourceLimit(msg) => {
                assert!(msg.contains(what), "expected {what:?} limit, got: {msg}")
            }
            other => panic!("expected ResourceLimit({what}), got {other:?}"),
        }
    }

    // T1 + T10: exceeding the manifest ceiling fails deterministically BEFORE
    // Phase 2 — previously committed accounting is byte-identical, and no
    // partial "successful" index is produced.
    #[tokio::test]
    async fn test_bounds_manifest_limit_fails_closed_preserving_committed_state() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();
        let repo = "org/repo";

        mock.put_manifest_bytes(repo, &dn(1), image_manifest(&dn(101), &dn(201)));
        mock.put_manifest_bytes(repo, &dn(2), image_manifest(&dn(102), &dn(202)));
        mock.set_tag_sync(repo, "keep", &dn(1));
        idx.sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect("initial sync under production limits");

        let tags_before = snapshot_tree(&idx.tag_to_root);
        let roots_before = snapshot_tree(&idx.root_counts);
        let contribs_before = snapshot_tree(&idx.repo_roots);
        let edges_before = snapshot_tree(&idx.rev_edges);

        // Third manifest + a budget that only admits two.
        mock.put_manifest_bytes(repo, &dn(3), image_manifest(&dn(103), &dn(203)));
        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_manifests: 2,
            ..limits_for_tests()
        }));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("manifest limit must fail the sync");
        assert_resource_limit(err, "manifest");

        assert_eq!(snapshot_tree(&idx.tag_to_root), tags_before);
        assert_eq!(snapshot_tree(&idx.root_counts), roots_before);
        assert_eq!(snapshot_tree(&idx.repo_roots), contribs_before);
        assert_eq!(snapshot_tree(&idx.rev_edges), edges_before);
        assert_eq!(
            idx.debug_contribution(repo, &dn(3)),
            None,
            "no partial indexing of the over-limit manifest"
        );

        idx.set_test_discovery_limits(None);
        let _ = std::fs::remove_dir_all(path);
    }

    // T2: tag ceiling fails closed before Phase 2 with committed tag mappings,
    // provenance, and derived counts unchanged.
    #[tokio::test]
    async fn test_bounds_tag_limit_fails_closed_preserving_committed_state() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();
        let repo = "org/repo";

        mock.put_manifest_bytes(repo, &dn(1), image_manifest(&dn(101), &dn(201)));
        mock.set_tag_sync(repo, "t1", &dn(1));
        mock.set_tag_sync(repo, "t2", &dn(1));
        idx.sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect("initial sync");

        let tags_before = snapshot_tree(&idx.tag_to_root);
        let roots_before = snapshot_tree(&idx.root_counts);
        let contribs_before = snapshot_tree(&idx.repo_roots);

        mock.set_tag_sync(repo, "t3", &dn(1));
        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_tags: 2,
            ..limits_for_tests()
        }));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("tag limit must fail the sync");
        assert_resource_limit(err, "tag");

        assert_eq!(snapshot_tree(&idx.tag_to_root), tags_before);
        assert_eq!(snapshot_tree(&idx.root_counts), roots_before);
        assert_eq!(snapshot_tree(&idx.repo_roots), contribs_before);

        idx.set_test_discovery_limits(None);
        let _ = std::fs::remove_dir_all(path);
    }

    // T3: staged-edge ceiling fails closed with no committed mutation.
    #[tokio::test]
    async fn test_bounds_edge_limit_fails_closed() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();
        let repo = "org/repo";

        // Two manifests x two blob refs each = 4 staged edges.
        mock.put_manifest_bytes(repo, &dn(1), image_manifest(&dn(101), &dn(201)));
        mock.put_manifest_bytes(repo, &dn(2), image_manifest(&dn(102), &dn(202)));
        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_edges: 3,
            ..limits_for_tests()
        }));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("edge limit must fail the sync");
        assert_resource_limit(err, "edge");
        assert_eq!(snapshot_tree(&idx.root_counts), Vec::new());
        assert_eq!(snapshot_tree(&idx.repo_roots), Vec::new());
        assert_eq!(snapshot_tree(&idx.rev_edges), Vec::new());

        idx.set_test_discovery_limits(None);
        let _ = std::fs::remove_dir_all(path);
    }

    // T4: the aggregate staged-byte budget fires even when every per-entry
    // count limit is far from exhausted.
    #[tokio::test]
    async fn test_bounds_aggregate_bytes_limit_fires() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();
        let repo = "org/repo";

        // Two manifests: counts are tiny, but staged digest+edge bytes exceed
        // a 200-byte aggregate ceiling (each digest string is 71 bytes).
        mock.put_manifest_bytes(repo, &dn(1), image_manifest(&dn(101), &dn(201)));
        mock.put_manifest_bytes(repo, &dn(2), image_manifest(&dn(102), &dn(202)));
        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_staged_bytes: 200,
            ..limits_for_tests()
        }));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("aggregate byte budget must fail the sync");
        assert_resource_limit(err, "staged bytes");

        idx.set_test_discovery_limits(None);
        let _ = std::fs::remove_dir_all(path);
    }

    // T5 + T6 + T7: exactly-at-limit input succeeds with correct
    // REFIDX-ACCOUNTING semantics (multi-repo shared digest), limit+1 fails,
    // and repeated bounded sync stays idempotent.
    #[tokio::test]
    async fn test_bounds_exact_boundary_and_idempotent_bounded_sync() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        let shared = dn(1);
        mock.put_manifest_bytes("a", &shared, image_manifest(&dn(101), &dn(201)));
        mock.put_manifest_bytes("a", &dn(2), image_manifest(&dn(102), &dn(202)));
        mock.put_manifest_bytes("b", &shared, image_manifest(&dn(101), &dn(201)));
        mock.set_tag_sync("a", "t1", &shared);
        mock.set_tag_sync("a", "t2", &dn(2));

        // Exactly at the manifest/tag limits for repo a.
        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_manifests: 2,
            max_tags: 2,
            ..limits_for_tests()
        }));
        idx.sync_repo_manifests_and_tags(&storage, "a")
            .await
            .expect("exactly-at-limit sync succeeds");
        idx.sync_repo_manifests_and_tags(&storage, "b")
            .await
            .expect("sync b");

        assert_eq!(idx.debug_contribution("a", &shared), Some((true, 1)));
        assert_eq!(idx.debug_contribution("b", &shared), Some((true, 0)));
        assert_eq!(idx.debug_root_count(&shared), Some(2));

        // Repeated bounded sync is idempotent (fresh budget per run).
        let roots = snapshot_tree(&idx.root_counts);
        let contribs = snapshot_tree(&idx.repo_roots);
        idx.sync_repo_manifests_and_tags(&storage, "a")
            .await
            .expect("repeat bounded sync");
        assert_eq!(snapshot_tree(&idx.root_counts), roots);
        assert_eq!(snapshot_tree(&idx.repo_roots), contribs);

        // limit + 1 fails.
        mock.put_manifest_bytes("a", &dn(3), image_manifest(&dn(103), &dn(203)));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, "a")
            .await
            .expect_err("limit+1 must fail");
        assert_resource_limit(err, "manifest");

        idx.set_test_discovery_limits(None);
        let _ = std::fs::remove_dir_all(path);
    }

    // T8: rebuild under sufficient limits completes healthy with correct
    // accounting; a rebuild limit failure leaves the documented recovery path
    // working (BUILDING state -> unhealthy -> auto-rebuild succeeds once the
    // pathological input is admitted or removed).
    #[tokio::test]
    async fn test_bounds_rebuild_success_and_limit_failure_recovery() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();

        mock.put_manifest_bytes("r", &dn(1), image_manifest(&dn(101), &dn(201)));
        mock.set_tag_sync("r", "t", &dn(1));

        idx.set_test_discovery_limits(Some(limits_for_tests()));
        idx.rebuild(&storage).await.expect("bounded rebuild");
        idx.check_health().expect("healthy after bounded rebuild");
        assert_eq!(idx.debug_contribution("r", &dn(1)), Some((true, 1)));

        // Force a rebuild limit failure.
        mock.put_manifest_bytes("r", &dn(2), image_manifest(&dn(102), &dn(202)));
        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_manifests: 1,
            ..limits_for_tests()
        }));
        let err = idx.rebuild(&storage).await.expect_err("rebuild over limit");
        assert_resource_limit(err, "manifest");
        assert!(
            idx.check_health().is_err(),
            "failed rebuild leaves the index unhealthy (BUILDING), never silently ready"
        );

        // Documented recovery: once limits admit the state, auto-rebuild heals.
        idx.set_test_discovery_limits(Some(limits_for_tests()));
        idx.ensure_healthy_or_rebuild(&storage, true, false)
            .await
            .expect("auto-rebuild recovery");
        idx.check_health().expect("healthy after recovery");
        assert_eq!(idx.debug_contribution("r", &dn(2)), Some((true, 0)));

        idx.set_test_discovery_limits(None);
        let _ = std::fs::remove_dir_all(path);
    }

    // T9: a repeating continuation token still reports a pagination CYCLE
    // (backend error), not resource exhaustion; a distinct-token empty-page
    // flood is caught by the page budget.
    #[tokio::test]
    async fn test_bounds_cycle_detection_precedes_page_budget() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();
        let repo = "org/repo";
        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_pages: 3,
            ..limits_for_tests()
        }));

        // Cycle: token repeats -> cycle error (not ResourceLimit).
        mock.queue_manifest_page(repo, Ok((vec![], Some("tok".to_string()))));
        mock.queue_manifest_page(repo, Ok((vec![], Some("tok".to_string()))));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("cycle must fail");
        match err {
            RefIndexError::Storage(se) => {
                assert!(se.to_string().contains("pagination cycle"), "got: {se}")
            }
            other => panic!("expected cycle backend error, got {other:?}"),
        }

        // Distinct-token empty-page flood -> page budget fires.
        for i in 0..4 {
            mock.queue_manifest_page(repo, Ok((vec![], Some(format!("tok{i}")))));
        }
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("page flood must fail");
        assert_resource_limit(err, "pagination page");

        idx.set_test_discovery_limits(None);
        let _ = std::fs::remove_dir_all(path);
    }

    // Traversal-node ceiling: a deep child-manifest chain exceeds the node
    // budget during staged discovery, failing closed with no mutation.
    #[tokio::test]
    async fn test_bounds_traversal_node_limit() {
        let path = temp_index_path();
        let idx = BlobRefIndex::open(path.clone()).expect("open");
        let mock = Arc::new(MockStorage::new());
        let storage = mock.clone();
        let repo = "org/repo";

        // Chain: m0 -> m1 -> m2 -> m3 (child manifest references).
        let chain: Vec<Digest> = (0..4).map(dn).collect();
        for i in 0..3 {
            mock.put_manifest_bytes(repo, &chain[i], index_manifest(&chain[i + 1]));
        }
        mock.put_manifest_bytes(repo, &chain[3], image_manifest(&dn(103), &dn(203)));
        // Only enumerate the chain head as a stored manifest page, so the
        // traversal (not enumeration) does the walking.
        mock.queue_manifest_page(repo, Ok((vec![chain[0].clone()], None)));

        idx.set_test_discovery_limits(Some(DiscoveryLimits {
            max_traversal_nodes: 2,
            ..limits_for_tests()
        }));
        let err = idx
            .sync_repo_manifests_and_tags(&storage, repo)
            .await
            .expect_err("node limit must fail");
        assert_resource_limit(err, "traversal node");
        assert_eq!(snapshot_tree(&idx.repo_roots), Vec::new());

        idx.set_test_discovery_limits(None);
        let _ = std::fs::remove_dir_all(path);
    }
}
