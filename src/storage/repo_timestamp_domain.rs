//! Shared registry repository-timestamp implementation over the
//! backend-neutral [`ObjectStore`] contract (STORAGE-LAYER-MIGRATION
//! Phase 8).
//!
//! This is the ONE registry implementation of `repo_timestamps` — a PURE
//! READ-DERIVED, ZERO-WRITE family: no timestamp object is ever stored,
//! written, or deleted. `last_tag_update` / `last_manifest_update` are the
//! MAXIMUM modification times of the DIRECT-CHILD objects of
//! `repos/<repo>/tags` and `repos/<repo>/manifests` — modification metadata
//! that arises implicitly from the migrated tag/manifest domain writes and
//! is exposed by the accepted [`ObjectStore::list_page`] contract
//! (`ListedObject::modified`; direct-child OBJECTS only, dot-prefixed keys
//! included, non-object entries excluded — exactly the frozen FS
//! regular-files-only/dotfiles-included rule). No clock exists in this
//! domain: the backend's own object-modification metadata is the source,
//! precision is whatever the adapter reports, and equal timestamps compare
//! with `>=` (the frozen max selection).
//!
//! # Preserved historical semantics
//! - repository grammar is the shared structural validation
//!   (`tag_domain::validate_path_component` + [`ObjectKey`] composition) →
//!   [`StorageError::InvalidRepoName`] before any backend access (the frozen
//!   FS rule; the retired S3 body interpolated raw names, whose empty-prefix
//!   `NotFound` produced the same caller-visible outcome — converged per the
//!   Phase 8 matrix);
//! - a present-but-empty namespace yields `None` for that field; an entry
//!   without a modification timestamp contributes nothing; results are never
//!   partial (any listing failure fails the whole call);
//! - reads are deliberately UNBOUNDED (the documented frozen baseline: "no
//!   approved production limit's scope covers these operations") — pages are
//!   drained holding only the running maximum;
//! - the ABSENT-REPOSITORY rule remains the accepted INTENTIONAL BACKEND
//!   DIFFERENCE (the Phase 3 repository-existence pattern): when BOTH
//!   namespaces yield zero rows, a backend WITH a repository-existence
//!   notion (FS) consults its contained probe — absent directory →
//!   [`StorageError::NotFound`], bare/emptied repository → `Ok` with `None`
//!   fields; a backend WITHOUT one (S3) treats zero rows as absence →
//!   `NotFound`, the frozen S3 rule.

use std::sync::Arc;
use std::time::SystemTime;

use naust_storage_core::ObjectKey;
use naust_storage_core::object_store::{ObjectStore, StoreError};

use crate::storage::tag_domain::TagRepoProbe;

use super::{RepoTimestamps, StorageError};

/// Internal page size for listing collection round trips.
const LIST_PAGE_SIZE: usize = 1000;

/// The absent-repository policy consulted only when BOTH namespaces yield
/// zero rows (see the module docs).
#[derive(Clone)]
pub(crate) enum RepoExistencePolicy {
    /// The backend has a real repository-existence notion (FS): consult the
    /// contained probe; `false` → `NotFound`, `true` → `Ok` with `None`
    /// fields (the frozen "bare repository" contract). Probe failures
    /// propagate.
    Probe(Arc<dyn TagRepoProbe>),
    /// The backend has no repository-existence notion (S3): zero rows in
    /// both namespaces IS absence (the frozen S3 rule).
    EmptyIsAbsent,
}

impl std::fmt::Debug for RepoExistencePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Probe(_) => f.write_str("Probe"),
            Self::EmptyIsAbsent => f.write_str("EmptyIsAbsent"),
        }
    }
}

fn namespace_key(repo: &str, namespace: &str) -> Result<ObjectKey, StorageError> {
    crate::storage::tag_domain::validate_path_component(repo, "repository name")?;
    let key_str = format!("repos/{repo}/{namespace}");
    ObjectKey::parse(&key_str).map_err(|e| StorageError::InvalidRepoName(e.to_string()))
}

/// ONE common translation of generic store failures into the registry error
/// taxonomy for timestamp derivation. Absence never reaches this function
/// (an absent prefix is an empty page in the [`ObjectStore`] contract).
fn translate_store_error(err: StoreError, what: &str) -> StorageError {
    match err {
        StoreError::TooLarge { limit } => StorageError::backend(format!(
            "{what}: payload exceeds the read ceiling of {limit} bytes"
        )),
        StoreError::PermissionDenied { message, .. } => {
            StorageError::permission_denied(format!("{what}: {message}"))
        }
        StoreError::Corrupt { message } => StorageError::corrupt_data(format!("{what}: {message}")),
        StoreError::InvalidInput { message } => {
            StorageError::internal_invariant(format!("{what}: {message}"))
        }
        StoreError::Backend { .. } => {
            if crate::storage::store_common::store_error_is_storage_full(&err) {
                return StorageError::InsufficientStorage;
            }
            let StoreError::Backend { message, .. } = err else {
                unreachable!()
            };
            StorageError::backend(format!("{what}: {message}"))
        }
    }
}

/// Drains one namespace, returning the maximum modification time of its
/// direct-child objects and the number of rows observed (content evidence
/// for the absent-repository decision). An absent prefix is an empty page in
/// the store contract → `(None, 0)`. Deliberately unbounded (frozen
/// baseline); only the running maximum is held.
async fn max_modified(
    store: &dyn ObjectStore,
    dir: &ObjectKey,
) -> Result<(Option<SystemTime>, usize), StorageError> {
    let page_size = std::num::NonZeroUsize::new(LIST_PAGE_SIZE).expect("nonzero page size");
    let mut max_time: Option<SystemTime> = None;
    let mut rows: usize = 0;
    let mut token = None;
    loop {
        let page = store
            .list_page(Some(dir), token.as_ref(), page_size)
            .await
            .map_err(|e| {
                translate_store_error(e, &format!("timestamp listing for {}", dir.as_str()))
            })?;
        rows = rows.saturating_add(page.objects.len());
        for row in page.objects {
            if let Some(modified) = row.modified {
                max_time = Some(match max_time {
                    Some(current) if current >= modified => current,
                    _ => modified,
                });
            }
        }
        match page.next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    Ok((max_time, rows))
}

/// Derives the repository timestamps (see the module docs for the frozen
/// contract and the absent-repository backend difference).
pub(crate) async fn repo_timestamps(
    store: &dyn ObjectStore,
    existence: &RepoExistencePolicy,
    repo: &str,
) -> Result<RepoTimestamps, StorageError> {
    let tags_dir = namespace_key(repo, "tags")?;
    let manifests_dir = namespace_key(repo, "manifests")?;

    let (last_tag_update, tag_rows) = max_modified(store, &tags_dir).await?;
    let (last_manifest_update, manifest_rows) = max_modified(store, &manifests_dir).await?;

    if tag_rows == 0 && manifest_rows == 0 {
        match existence {
            RepoExistencePolicy::EmptyIsAbsent => return Err(StorageError::NotFound),
            RepoExistencePolicy::Probe(probe) => {
                if !probe.repo_exists(repo).await? {
                    return Err(StorageError::NotFound);
                }
            }
        }
    }

    Ok(RepoTimestamps {
        last_tag_update,
        last_manifest_update,
    })
}

/// Transitional wiring container: the backend-neutral handle each storage
/// backend exposes for its migrated repository-timestamp derivation.
#[derive(Clone)]
pub(crate) struct RepoTimestampDomain {
    store: Arc<dyn ObjectStore>,
    existence: RepoExistencePolicy,
}

impl std::fmt::Debug for RepoTimestampDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoTimestampDomain")
            .field("existence", &self.existence)
            .finish()
    }
}

impl RepoTimestampDomain {
    pub(crate) fn new(store: Arc<dyn ObjectStore>, existence: RepoExistencePolicy) -> Self {
        Self { store, existence }
    }

    pub(crate) async fn repo_timestamps(&self, repo: &str) -> Result<RepoTimestamps, StorageError> {
        repo_timestamps(self.store.as_ref(), &self.existence, repo).await
    }
}

#[cfg(test)]
#[path = "repo_timestamp_domain_tests.rs"]
mod tests;
