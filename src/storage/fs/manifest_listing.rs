//! Filesystem manifest-listing support: configured resource limits.
//!
//! The manifest LISTING MECHANICS that previously lived here (the contained
//! `list_manifest_digests_page_impl` seam) migrated to the backend-neutral
//! shared manifest domain (`crate::storage::manifest_domain`) over
//! `storage_core::ObjectStore` in the Phase 4 manifest-family cutover. What
//! remains is configuration only: the defaults/minimums wired by
//! `config.rs`, `gc_service.rs`, and the `FsStorage` constructors into the
//! manifest object store's enumeration budget.

use storage_fs::DirEnumerationLimits;

/// Default maximum number of manifest directory entries to enumerate during listing.
pub const DEFAULT_MANIFEST_LISTING_MAX_ENTRIES: usize = 10_000;

/// Default maximum cumulative bytes of entry filenames during manifest listing.
pub const DEFAULT_MANIFEST_LISTING_MAX_NAME_BYTES: usize = 1_500_000;

/// Minimum allowable value for `manifest_listing_max_entries`.
pub const MIN_MANIFEST_LISTING_ENTRIES: usize = 1;

/// Minimum allowable value for `manifest_listing_max_name_bytes` (accommodates a 128-byte SHA-512 filename).
pub const MIN_MANIFEST_LISTING_NAME_BYTES: usize = 128;

/// Approved default directory-enumeration limits for manifest listing.
pub fn default_manifest_dir_limits() -> DirEnumerationLimits {
    DirEnumerationLimits::new(
        DEFAULT_MANIFEST_LISTING_MAX_ENTRIES,
        DEFAULT_MANIFEST_LISTING_MAX_NAME_BYTES,
    )
}
