//! Registry-object primitives (ADR-010).
//!
//! Everything needed to implement an OCI registry on top of pluggable storage:
//! value types ([`registry`]), capability ports and two reference backends
//! ([`storage`]), domain engines (uploads, manifest lifecycle, membership,
//! GC, ref-index), and transport-neutral [`application`] services.
//! Deliberately free of HTTP, auth, and server configuration: composition
//! roots map their own config into [`policy`] types and, for pull-through
//! setups, implement [`upstream::UpstreamFetcher`].
//!
//! See `examples/minimal_registry.rs` for a complete registry composed
//! without any HTTP/auth/config stack.
//!
//! # Load-bearing contracts
//!
//! These invariants are what a consumer must preserve; they are enforced by
//! the engines, not by the caller, but composition mistakes can defeat them.
//!
//! **Blob upload finalization is a seven-step ordered sequence** (see the
//! `STEP` comments in [`upload_coordinator`]): begin-finalize session
//! validation → ref-index heal (**before** the pin gate — healing after
//! pinning can resurrect a stale index under an active pin) → pin lease
//! (fail-closed health check, TTL heartbeat) → dirty mark → CAS commit +
//! membership link under the [`consistency::MutationGuard`] → index update +
//! flush → pin release.
//!
//! **GC deletes a blob only when five axes ALL pass** (see
//! [`blob_gc::validation`]): no active pin lease → repository membership
//! count is zero → not policy-reachable (discovery fails closed) → no active
//! manifest-lifecycle journal record → older than the configured minimum
//! age. Strategy is a storage-port capability
//! (`gc_strategy()` on [`storage::ports::GcServiceStoragePort`]): filesystem
//! backends use two-phase quarantine + delayed delete, S3 uses direct
//! ETag-conditional deletion (fail-closed unless bucket versioning is fully
//! disabled).
//!
//! **Membership readiness gates startup**: with non-empty storage, refuse to
//! serve until the repository↔blob membership ledger reports `Ready`
//! ([`membership_migration`] provides the resumable backfill); empty storage
//! may be auto-marked ready.
//!
//! **One [`ConsistencyCoordinator`] per composition root**: every mutation
//! engine handed to a root must share that root's coordinator, or the
//! mutation/GC-revalidation exclusion breaks.
#![allow(clippy::all)]

pub mod application;
pub mod blob_delete_safety;
pub mod blob_gc;
pub mod blob_ref_index;
pub mod cache_eviction;
pub mod consistency;
pub use consistency::{ConsistencyCoordinator, GcRevalidationGuard, MutationGuard};
pub mod fs_root_lock;
pub mod gc_service;
pub mod manifest_lifecycle;
pub mod manifest_refs;
pub mod membership_migration;
pub mod policy;
pub mod registry;
pub mod repository_membership_ledger;
pub mod storage;
pub mod upload_coordinator;
pub mod upload_lifecycle;
pub mod upstream;

#[doc(hidden)]
pub mod test_support;

/// The primary surface for building a registry on top of this crate.
pub mod prelude {
    pub use crate::application::{
        BlobMutationService, BlobReadService, CatalogQueryService, ManifestMutationService,
        ManifestReadService, ProxyTarget, ReferrersQueryService, TagQueryService,
    };
    pub use crate::blob_ref_index::BlobRefIndex;
    pub use crate::consistency::ConsistencyCoordinator;
    pub use crate::gc_service::{GcBudgets, GcService};
    pub use crate::manifest_lifecycle::{ManifestLifecycleService, PublishManifestRequest};
    pub use crate::policy::{EvictionPolicy, GcPolicy, LegacyMultipartCleanupPolicy, TagPolicy};
    pub use crate::registry::canonical_name::CanonicalRepoName;
    pub use crate::registry::digest::Digest;
    pub use crate::storage::mutation_authority::RuntimeMutationAuthority;
    pub use crate::storage::{StorageError, StorageWiring};
    pub use crate::upload_coordinator::BlobUploadCoordinatorConfig;
    pub use crate::upstream::UpstreamFetcher;
}
