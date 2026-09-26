//! Core-owned policy types (ADR-010 §2.3).
//!
//! These types parameterize core engines and backends. The server's `config`
//! module maps its parsed configuration into them at composition time and
//! re-exports the moved types for compatibility until the Phase 2 crate split.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Tag-freshness policy for proxy-cached tags (moved from `config`).
#[derive(Clone, Debug)]
pub enum TagPolicy {
    DigestOnly,
    TtlSeconds(u64),
    AlwaysRevalidate,
}

/// Proxy-cache eviction policy (moved from `config`).
#[derive(Clone, Debug)]
pub enum EvictionPolicy {
    Default,
    KeepTags(Vec<String>),
    // Keep the highest SemVer tag among *cached tags* (optionally filtered by regex).
    KeepLatestCachedSemver {
        tag_regex: Option<String>,
        allow_prerelease: bool,
    },
}

/// Disposition of legacy/unknown multipart uploads during S3 session cleanup
/// (moved from `config`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyMultipartCleanupPolicy {
    #[default]
    Disabled,
    CurrentFormatOnly,
    OperatorConfirmedAllUnknown,
}

/// Everything `GcService` needs from configuration.
///
/// Backend identity is deliberately absent: strategy-dependent behavior is
/// derived from the storage port's `gc_strategy()` capability, never from a
/// backend enum (ADR-010 §2.3).
#[derive(Clone, Debug)]
pub struct GcPolicy {
    pub enabled: bool,
    pub enable_delete: bool,
    pub default_min_age_secs: u64,
    pub default_quarantine_delay_secs: u64,
    pub default_max_blobs: usize,
    pub default_max_bytes: u64,
    pub default_max_seconds: u64,
    /// `ref_index.auto_rebuild_on_corruption` in server configuration.
    pub auto_rebuild_ref_index_on_corruption: bool,
    /// Filesystem root hosting the CAS and the `quarantine/` tree. Only read
    /// on the `FilesystemQuarantine` strategy path; ignored for direct-delete
    /// backends.
    pub fs_root: PathBuf,
}
