//! Proxy-cache eviction planning (remediation A3/R2, KI-02).
//!
//! Pure planning over materialized candidate rows: the composition root
//! enumerates blobs through `storage::ports::CacheEvictionPort`, attaches
//! last-access metadata from its own index, computes the protected set, and
//! hands everything here. Execution (physical deletes) goes back through the
//! port. Core never touches the proxy engine or its sled index.
//!
//! Budget semantics (deliberate change from the historical no-op walker,
//! which never deleted anything): `max_cache_bytes` bounds the TOTAL cached
//! bytes; only unprotected blobs are evictable, in LRU order
//! (never-accessed first, then oldest access, tie-broken by modification
//! time). If evicting every unprotected blob still leaves the cache over
//! budget, the plan reports the residual instead of touching protected
//! content.

use crate::registry::digest::Digest;
use crate::storage::BlobObjectVersion;
use std::collections::HashSet;
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct CacheBlobCandidate {
    pub digest: Digest,
    pub size: u64,
    pub last_modified: SystemTime,
    /// Unix seconds of the last recorded access, if the index knows one.
    pub last_access: Option<u64>,
    /// Enumerated object version; carried through so deletes stay conditional.
    pub version: BlobObjectVersion,
}

#[derive(Debug, Default)]
pub struct EvictionPlan {
    /// Blobs to evict, in eviction (LRU-first) order.
    pub evict: Vec<CacheBlobCandidate>,
    pub total_bytes: u64,
    pub evictable_bytes: u64,
    pub planned_freed_bytes: u64,
    /// Bytes that remain over budget even after evicting everything
    /// unprotected (0 when the plan reaches the budget).
    pub residual_over_budget: u64,
}

pub fn plan_evictions(
    candidates: Vec<CacheBlobCandidate>,
    protected_hex: &HashSet<String>,
    max_cache_bytes: u64,
) -> EvictionPlan {
    let total_bytes: u64 = candidates.iter().map(|c| c.size).sum();
    let mut evictable: Vec<CacheBlobCandidate> = candidates
        .into_iter()
        .filter(|c| !protected_hex.contains(c.digest.hex()))
        .collect();
    let evictable_bytes: u64 = evictable.iter().map(|c| c.size).sum();

    let mut plan = EvictionPlan {
        evict: Vec::new(),
        total_bytes,
        evictable_bytes,
        planned_freed_bytes: 0,
        residual_over_budget: 0,
    };
    if total_bytes <= max_cache_bytes {
        return plan;
    }

    // LRU order: never-accessed first (None < Some), then oldest access,
    // tie-broken by oldest modification time.
    evictable
        .sort_by(|a, b| (a.last_access, a.last_modified).cmp(&(b.last_access, b.last_modified)));

    let need = total_bytes - max_cache_bytes;
    for candidate in evictable {
        if plan.planned_freed_bytes >= need {
            break;
        }
        plan.planned_freed_bytes = plan.planned_freed_bytes.saturating_add(candidate.size);
        plan.evict.push(candidate);
    }
    plan.residual_over_budget = need.saturating_sub(plan.planned_freed_bytes);
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cand(hex_byte: u8, size: u64, access: Option<u64>, mtime_secs: u64) -> CacheBlobCandidate {
        let hex: String = format!("{:02x}", hex_byte).repeat(32);
        CacheBlobCandidate {
            digest: Digest::parse(&format!("sha256:{hex}")).unwrap(),
            size,
            last_modified: SystemTime::UNIX_EPOCH + Duration::from_secs(mtime_secs),
            last_access: access,
            version: BlobObjectVersion(format!("v{hex_byte}")),
        }
    }

    #[test]
    fn under_budget_evicts_nothing() {
        let plan = plan_evictions(vec![cand(1, 100, None, 1)], &HashSet::new(), 100);
        assert!(plan.evict.is_empty());
        assert_eq!(plan.total_bytes, 100);
        assert_eq!(plan.residual_over_budget, 0);
    }

    #[test]
    fn evicts_lru_first_until_budget_met() {
        // total 600, budget 300 -> need 300.
        let candidates = vec![
            cand(1, 200, Some(50), 1), // recently accessed
            cand(2, 200, None, 9),     // never accessed, newer mtime
            cand(3, 200, None, 2),     // never accessed, older mtime -> first
        ];
        let plan = plan_evictions(candidates, &HashSet::new(), 300);
        let order: Vec<&str> = plan.evict.iter().map(|c| c.version.0.as_str()).collect();
        // Never-accessed evicted before accessed; older mtime breaks the tie.
        assert_eq!(order, vec!["v3", "v2"]);
        assert_eq!(plan.planned_freed_bytes, 400);
        assert_eq!(plan.residual_over_budget, 0);
    }

    #[test]
    fn protected_blobs_count_toward_budget_but_are_never_evicted() {
        let protected: HashSet<String> = [cand(1, 0, None, 0).digest.hex().to_string()]
            .into_iter()
            .collect();
        // protected 500 + unprotected 100, budget 300 -> need 300, only 100 evictable.
        let candidates = vec![cand(1, 500, None, 1), cand(2, 100, None, 2)];
        let plan = plan_evictions(candidates, &protected, 300);
        assert_eq!(plan.evict.len(), 1);
        assert_eq!(plan.evict[0].version.0, "v2");
        assert_eq!(plan.planned_freed_bytes, 100);
        assert_eq!(plan.residual_over_budget, 200);
    }

    #[test]
    fn oldest_access_evicted_before_newer() {
        let candidates = vec![
            cand(1, 10, Some(100), 1),
            cand(2, 10, Some(5), 1),
            cand(3, 10, Some(60), 1),
        ];
        let plan = plan_evictions(candidates, &HashSet::new(), 0);
        let order: Vec<&str> = plan.evict.iter().map(|c| c.version.0.as_str()).collect();
        assert_eq!(order, vec!["v2", "v3", "v1"]);
    }
}
