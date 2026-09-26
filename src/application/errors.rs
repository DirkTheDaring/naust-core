use crate::manifest_lifecycle::{ManifestLifecycleError, UnverifiedReason};
use crate::manifest_refs::ManifestParseError;
use crate::registry::canonical_name::RepoNameError;
use crate::registry::digest::Digest;
use crate::repository_membership_ledger::LedgerError;
use crate::storage::StorageError;
use crate::storage::upload_session::{UploadOffsetPrecondition, UploadStreamError};
use crate::upload_coordinator::CoordinatorError;
use crate::upload_lifecycle::state::StateTokenError;

#[derive(Debug, thiserror::Error)]
pub enum BlobMutationError {
    #[error("repository name '{name}' is invalid: {source}")]
    InvalidRepoName {
        name: String,
        #[source]
        source: RepoNameError,
    },
    #[error("session not found")]
    SessionNotFound,
    #[error("state token error: {0}")]
    StateToken(#[from] StateTokenError),
    #[error("offset mismatch: expected {expected:?}, current {current}")]
    OffsetMismatch {
        expected: UploadOffsetPrecondition,
        current: u64,
    },
    #[error("content range invalid: {0}")]
    RangeInvalid(String),
    #[error("digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch { expected: Digest, computed: String },
    #[error("size invalid: {0}")]
    SizeInvalid(String),
    #[error("payload too large")]
    TooLarge,
    #[error("concurrent operation conflict")]
    Conflict,
    #[error("monolithic uploads are disallowed")]
    MonolithicDisallowed,
    #[error("invalid prepared handle")]
    InvalidPreparedHandle,
    #[error("blob in use: {0}")]
    BlobInUse(String),
    #[error("blob not found")]
    BlobNotFound,
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error("stream error: {0}")]
    Stream(#[from] UploadStreamError),
}

impl From<CoordinatorError> for BlobMutationError {
    fn from(err: CoordinatorError) -> Self {
        match err {
            CoordinatorError::InvalidRepoName(name) => {
                let source = match crate::registry::canonical_name::CanonicalRepoName::parse(&name)
                {
                    Ok(_) => RepoNameError::Empty,
                    Err(e) => e,
                };
                BlobMutationError::InvalidRepoName { name, source }
            }
            CoordinatorError::SessionNotFound => BlobMutationError::SessionNotFound,
            CoordinatorError::StateToken(e) => BlobMutationError::StateToken(e),
            CoordinatorError::OffsetMismatch { expected, current } => {
                BlobMutationError::OffsetMismatch { expected, current }
            }
            CoordinatorError::RangeInvalid(msg) => BlobMutationError::RangeInvalid(msg),
            CoordinatorError::DigestMismatch { expected, computed } => {
                BlobMutationError::DigestMismatch { expected, computed }
            }
            CoordinatorError::SizeInvalid(msg) => BlobMutationError::SizeInvalid(msg),
            CoordinatorError::TooLarge => BlobMutationError::TooLarge,
            CoordinatorError::Conflict => BlobMutationError::Conflict,
            CoordinatorError::MonolithicDisallowed => BlobMutationError::MonolithicDisallowed,
            CoordinatorError::InvalidPreparedHandle => BlobMutationError::InvalidPreparedHandle,
            CoordinatorError::Storage(e) => BlobMutationError::Storage(e),
            CoordinatorError::Stream(e) => BlobMutationError::Stream(e),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestMutationError {
    #[error("repository name '{name}' is invalid: {source}")]
    InvalidRepoName {
        name: String,
        #[source]
        source: RepoNameError,
    },
    #[error("manifest payload is empty")]
    EmptyPayload,
    #[error("manifest payload exceeds maximum allowed size")]
    PayloadTooLarge,
    #[error("manifest JSON is malformed or invalid: {0}")]
    InvalidManifest(#[from] ManifestParseError),
    #[error("manifest signature is unverified: {0}")]
    Unverified(#[from] UnverifiedReason),
    #[error("unsupported manifest media type: {0}")]
    UnsupportedMediaType(String),
    #[error("referenced blob not found in storage: {0}")]
    MissingBlob(String),
    #[error("referenced child manifest not found in storage: {0}")]
    MissingManifest(String),
    #[error("invalid tag name")]
    InvalidTag,
    #[error("tag already exists and overwrite is disallowed")]
    TagAlreadyExists,
    #[error("tag is immutable and cannot be deleted")]
    TagImmutable,
    #[error("tag not found")]
    TagNotFound,
    #[error("manifest not found")]
    ManifestNotFound,
    #[error("tag precondition failed")]
    TagPreconditionFailed,
    #[error("manifest digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch { expected: String, computed: String },
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("reference index error: {0}")]
    RefIndex(#[from] crate::blob_ref_index::RefIndexError),
    #[error(transparent)]
    Lifecycle(ManifestLifecycleError),
}

impl From<ManifestLifecycleError> for ManifestMutationError {
    fn from(err: ManifestLifecycleError) -> Self {
        match err {
            ManifestLifecycleError::InvalidRepoName => ManifestMutationError::InvalidRepoName {
                name: String::new(),
                source: RepoNameError::Empty,
            },
            ManifestLifecycleError::EmptyPayload => ManifestMutationError::EmptyPayload,
            ManifestLifecycleError::PayloadTooLarge => ManifestMutationError::PayloadTooLarge,
            ManifestLifecycleError::InvalidManifest(e) => ManifestMutationError::InvalidManifest(e),
            ManifestLifecycleError::Unverified(e) => ManifestMutationError::Unverified(e),
            ManifestLifecycleError::UnsupportedMediaType(mt) => {
                ManifestMutationError::UnsupportedMediaType(mt)
            }
            ManifestLifecycleError::MissingBlob(d) => ManifestMutationError::MissingBlob(d),
            ManifestLifecycleError::MissingManifest(d) => ManifestMutationError::MissingManifest(d),
            ManifestLifecycleError::InvalidTag => ManifestMutationError::InvalidTag,
            ManifestLifecycleError::TagAlreadyExists => ManifestMutationError::TagAlreadyExists,
            ManifestLifecycleError::TagNotFound => ManifestMutationError::TagNotFound,
            ManifestLifecycleError::ManifestNotFound => ManifestMutationError::ManifestNotFound,
            ManifestLifecycleError::TagPreconditionFailed => {
                ManifestMutationError::TagPreconditionFailed
            }
            ManifestLifecycleError::DigestMismatch { expected, computed } => {
                ManifestMutationError::DigestMismatch { expected, computed }
            }
            ManifestLifecycleError::Storage(e) => ManifestMutationError::Storage(e),
            ManifestLifecycleError::RefIndex(e) => ManifestMutationError::RefIndex(e),
            other @ (ManifestLifecycleError::CoordinationLeaseHeld
            | ManifestLifecycleError::LeaseLost(_)
            | ManifestLifecycleError::CorruptJournal(_)
            | ManifestLifecycleError::JournalSerialization(_)) => {
                ManifestMutationError::Lifecycle(other)
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlobReadError {
    #[error("repository name '{name}' is invalid: {source}")]
    InvalidRepoName {
        name: String,
        #[source]
        source: RepoNameError,
    },
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
    #[error("blob not found")]
    NotFound,
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("proxy error: {0}")]
    Proxy(#[source] crate::upstream::ProxyError),
    #[error("mutation error: {0}")]
    Mutation(#[source] BlobMutationError),
    #[error("storage error: {0}")]
    Storage(#[source] StorageError),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestReadError {
    #[error("repository name '{name}' is invalid: {source}")]
    InvalidRepoName {
        name: String,
        #[source]
        source: RepoNameError,
    },
    #[error("invalid tag '{0}'")]
    InvalidTag(String),
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
    #[error("manifest not found")]
    NotFound,
    #[error("tag not found")]
    TagNotFound,
    #[error("manifest payload too large")]
    TooLarge,
    #[error("manifest digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch { expected: String, computed: String },
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("proxy error: {0}")]
    Proxy(#[source] crate::upstream::ProxyError),
    #[error("mutation error: {0}")]
    Mutation(#[source] ManifestMutationError),
    #[error("storage error: {0}")]
    Storage(#[source] StorageError),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CatalogQueryError {
    #[error("storage error: {0}")]
    Storage(#[source] StorageError),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum TagQueryError {
    #[error("repository name '{name}' is invalid: {source}")]
    InvalidRepoName {
        name: String,
        #[source]
        source: RepoNameError,
    },
    #[error("repository not found")]
    NotFound,
    #[error("storage error: {0}")]
    Storage(#[source] StorageError),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ReferrersQueryError {
    #[error("repository name '{name}' is invalid: {source}")]
    InvalidRepoName {
        name: String,
        #[source]
        source: RepoNameError,
    },
    #[error("invalid subject digest: {0}")]
    InvalidDigest(String),
    #[error("storage error: {0}")]
    Storage(#[source] StorageError),
    #[error("internal error: {0}")]
    Internal(String),
}
