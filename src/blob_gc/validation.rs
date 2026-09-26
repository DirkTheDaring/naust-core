use super::policy::PolicyContext;
use crate::blob_ref_index::BlobRefIndex;
use crate::manifest_lifecycle::LifecycleJournalRecord;
use crate::registry::digest::Digest;
use crate::storage;
use std::sync::Arc;
use std::time::SystemTime;

/// Specific category explaining why a GC blob candidate was protected from deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcProtectionReason {
    /// Blob is actively pinned by an in-flight or finalizing upload session.
    ActiveUploadPin,
    /// Blob has one or more active or pending repository memberships.
    RepositoryMembership { count: usize },
    /// Blob is reachable from an active manifest or tag root under configured policy.
    ManifestOrTagReachable,
    /// Blob is referenced as target or subject by an in-progress lifecycle journal record.
    ActiveLifecycleJournal { repository: String, op_id: String },
    /// Candidate age does not satisfy the minimum retention policy.
    PolicyAgeProtected,
}

impl std::fmt::Display for GcProtectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActiveUploadPin => write!(f, "active upload pin in ref-index"),
            Self::RepositoryMembership { count } => {
                write!(
                    f,
                    "blob has {count} active or pending repository memberships"
                )
            }
            Self::ManifestOrTagReachable => write!(f, "reachable from manifest or tag root"),
            Self::ActiveLifecycleJournal { repository, op_id } => {
                write!(
                    f,
                    "active lifecycle journal op {op_id} in repo '{repository}' references target blob"
                )
            }
            Self::PolicyAgeProtected => {
                write!(f, "candidate age does not satisfy minimum retention policy")
            }
        }
    }
}

/// Typed error model for failures occurring during authoritative GC candidate deletion.
#[derive(Debug, thiserror::Error)]
pub enum GcCandidateDeletionError {
    #[error("durable reference index health check failed: {0}")]
    IndexHealth(#[from] crate::blob_ref_index::RefIndexError),

    #[error("failed to query repository memberships for blob {digest}: {source}")]
    RepositoryMembershipQuery {
        digest: Digest,
        #[source]
        source: crate::storage::StorageError,
    },

    #[error("repository enumeration failed during lifecycle journal pre-delete check: {0}")]
    RepositoryEnumeration(#[source] crate::storage::StorageError),

    #[error("failed to read lifecycle journal for repository '{repository}': {source}")]
    LifecycleJournalRead {
        repository: String,
        #[source]
        source: crate::storage::StorageError,
    },

    #[error("corrupt lifecycle journal record in repository '{repository}': {source}")]
    LifecycleJournalCorrupt {
        repository: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("storage conditional deletion failed for blob {digest}: {source}")]
    StorageDelete {
        digest: Digest,
        #[source]
        source: crate::storage::StorageError,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreDeleteValidation {
    Eligible,
    Protected(GcProtectionReason),
}

/// Authoritative pre-delete candidate revalidation executed immediately before physical deletion.
///
/// Invariants:
/// - Fails closed if reference index is unhealthy.
/// - Protects candidate if pinned by active upload sessions.
/// - Protects candidate if repository memberships > 0.
/// - Protects candidate if reachable from tags/manifests under current policy.
/// - Protects candidate if referenced in any repository lifecycle journal WAL.
/// - Fails closed if any repository lifecycle journal is unreadable or malformed.
pub(crate) async fn revalidate_candidate_before_delete(
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    candidate: &storage::GcBlobCandidate,
    now: SystemTime,
    policy_ctx: &mut PolicyContext,
    _guard: &crate::consistency::GcRevalidationGuard,
) -> Result<PreDeleteValidation, GcCandidateDeletionError> {
    // 1. Ref-index health check
    idx.check_health()?;

    // 2. In-flight upload pins
    if policy_ctx.is_pinned(&candidate.digest, now)? {
        return Ok(PreDeleteValidation::Protected(
            GcProtectionReason::ActiveUploadPin,
        ));
    }

    // 3. Authoritative repository-membership count
    let mem_count = storage
        .count_repo_blob_memberships(&candidate.digest)
        .await
        .map_err(
            |source| GcCandidateDeletionError::RepositoryMembershipQuery {
                digest: candidate.digest.clone(),
                source,
            },
        )?;
    if mem_count > 0 {
        return Ok(PreDeleteValidation::Protected(
            GcProtectionReason::RepositoryMembership { count: mem_count },
        ));
    }

    // 4. Reachability from tags/manifests under current policy
    if policy_ctx.is_referenced(&candidate.digest).await? {
        return Ok(PreDeleteValidation::Protected(
            GcProtectionReason::ManifestOrTagReachable,
        ));
    }

    // 5. Active WAL Lifecycle Journals
    let repos = storage
        .list_repositories()
        .await
        .map_err(GcCandidateDeletionError::RepositoryEnumeration)?;

    for repo in repos {
        match storage.read_lifecycle_journal(&repo).await {
            Ok(Some(journal_bytes)) => {
                let rec: LifecycleJournalRecord =
                    serde_json::from_slice(&journal_bytes).map_err(|source| {
                        GcCandidateDeletionError::LifecycleJournalCorrupt {
                            repository: repo.clone(),
                            source,
                        }
                    })?;

                if rec.target_digest == candidate.digest
                    || rec.subject_digest.as_ref() == Some(&candidate.digest)
                {
                    return Ok(PreDeleteValidation::Protected(
                        GcProtectionReason::ActiveLifecycleJournal {
                            repository: repo.clone(),
                            op_id: rec.op_id,
                        },
                    ));
                }
            }
            Ok(None) => {}
            Err(e) => {
                return Err(GcCandidateDeletionError::LifecycleJournalRead {
                    repository: repo.clone(),
                    source: e,
                });
            }
        }
    }

    Ok(PreDeleteValidation::Eligible)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcCandidateDeletionOutcome {
    Deleted {
        size: u64,
    },
    Protected(GcProtectionReason),
    NotFound,
    PreconditionFailed {
        current_version: Option<storage::BlobObjectVersion>,
    },
}

/// Centralized execution helper for safe, guarded candidate deletion.
///
/// Invariants enforced:
/// - Fails closed if pre-delete candidate revalidation fails.
/// - Performs conditional physical mutation only when candidate is validated as Eligible.
/// - Classifies the final deletion outcome into structured types.
pub(crate) async fn execute_guarded_gc_deletion(
    storage: &Arc<dyn storage::GcServiceStoragePort>,
    idx: &BlobRefIndex,
    candidate: &storage::GcBlobCandidate,
    now: SystemTime,
    policy_ctx: &mut PolicyContext,
    permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
    reval_guard: &crate::consistency::GcRevalidationGuard,
) -> Result<GcCandidateDeletionOutcome, GcCandidateDeletionError> {
    // 1. Authoritative pre-delete revalidation
    match revalidate_candidate_before_delete(storage, idx, candidate, now, policy_ctx, reval_guard)
        .await?
    {
        PreDeleteValidation::Eligible => {}
        PreDeleteValidation::Protected(reason) => {
            return Ok(GcCandidateDeletionOutcome::Protected(reason));
        }
    }

    // 2. Conditional physical deletion against authoritative storage
    let del_res = storage
        .delete_blob_conditional(permit, &candidate.digest, Some(&candidate.version))
        .await;

    // 3. Outcome classification
    match del_res {
        Ok(storage::GcDeleteResult::Deleted) => Ok(GcCandidateDeletionOutcome::Deleted {
            size: candidate.size,
        }),
        Ok(storage::GcDeleteResult::NotFound) => Ok(GcCandidateDeletionOutcome::NotFound),
        Ok(storage::GcDeleteResult::PreconditionFailed { current_version }) => {
            Ok(GcCandidateDeletionOutcome::PreconditionFailed { current_version })
        }
        Err(source) => Err(GcCandidateDeletionError::StorageDelete {
            digest: candidate.digest.clone(),
            source,
        }),
    }
}
