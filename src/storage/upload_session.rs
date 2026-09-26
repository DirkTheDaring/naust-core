use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::{BlobMeta, StorageError};
use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UploadSessionId {
    pub repo: CanonicalRepoName,
    pub uuid: String,
}

impl UploadSessionId {
    pub fn new(repo: CanonicalRepoName, uuid: impl Into<String>) -> Self {
        Self {
            repo,
            uuid: uuid.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadOffsetPrecondition {
    Exact(u64),
    CurrentForServerComposedMonolithicOperation,
}

#[derive(Debug, thiserror::Error)]
pub enum UploadStreamError {
    #[error("I/O error during upload stream: {0}")]
    Io(#[from] std::io::Error),
    #[error("upload idle timeout reached")]
    IdleTimeout,
    #[error("upload throughput fell below minimum transfer rate")]
    RateTooLow,
}

pub type UploadByteStream =
    Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, UploadStreamError>> + Send>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UploadSessionState {
    Active,
    Appending,
    Finalizing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadSessionStatus {
    pub session: UploadSessionId,
    pub state: UploadSessionState,
    pub committed_offset: u64,
    pub created_at: SystemTime,
    pub last_active_at: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadAppendResult {
    Committed { new_offset: u64 },
    OffsetMismatch { current_offset: u64 },
    Conflict,
}

#[derive(Clone, Debug)]
pub struct PreparedFinalize {
    pub session: UploadSessionId,
    pub operation_id: String,
    pub expected_digest: Digest,
    pub committed_offset: u64,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalizeOutcome {
    Published(BlobMeta),
    AlreadyFinalized(BlobMeta),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizedReceipt {
    pub repo: CanonicalRepoName,
    pub uuid: String,
    pub digest: String,
    pub size: u64,
    pub finalized_at_unix_secs: u64,
    pub format_version: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum UploadTransitionError {
    #[error("upload session not found")]
    NotFound,
    #[error("offset mismatch: expected {expected:?}, current is {current}")]
    OffsetMismatch {
        expected: UploadOffsetPrecondition,
        current: u64,
    },
    #[error("concurrent operation conflict")]
    Conflict,
    #[error("digest mismatch: expected {expected}, computed {computed}")]
    DigestMismatch { expected: Digest, computed: String },
    #[error("upload size limit exceeded")]
    TooLarge,
    #[error("invalid or foreign prepared finalization handle")]
    InvalidPreparedHandle,
    #[error("stream error: {0}")]
    Stream(#[from] UploadStreamError),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

#[async_trait]
pub trait UploadSessionStorage: Send + Sync {
    /// Creates a new upload session, allocating initial staging and lock resources.
    async fn create_session(&self, _repo: &str) -> Result<UploadSessionId, StorageError> {
        Err(StorageError::Unsupported)
    }

    /// Inspects the current authoritative session status.
    async fn session_status(
        &self,
        _session: &UploadSessionId,
    ) -> Result<UploadSessionStatus, UploadTransitionError> {
        Err(UploadTransitionError::Storage(StorageError::Unsupported))
    }

    /// Atomically appends streaming chunks under the session lock if and only if the session satisfies `expected_offset`.
    async fn append_if_offset(
        &self,
        _session: &UploadSessionId,
        _expected_offset: UploadOffsetPrecondition,
        _stream: UploadByteStream,
        _max_upload_bytes: u64,
    ) -> Result<UploadAppendResult, UploadTransitionError> {
        Err(UploadTransitionError::Storage(StorageError::Unsupported))
    }

    /// Prepares finalization under session lock: commits trailing bytes, computes digest, and persists Finalizing state.
    /// Does NOT make the final blob visible in the CAS store.
    async fn begin_finalize(
        &self,
        _session: &UploadSessionId,
        _expected_offset: UploadOffsetPrecondition,
        _trailing_stream: Option<UploadByteStream>,
        _expected_digest: &Digest,
        _max_upload_bytes: u64,
        _abort_on_digest_mismatch: bool,
    ) -> Result<PreparedFinalize, UploadTransitionError> {
        Err(UploadTransitionError::Storage(StorageError::Unsupported))
    }

    /// Commits a prepared finalization: atomically publishes the CAS blob and records the finalized receipt.
    async fn commit_finalize(
        &self,
        _prepared: &PreparedFinalize,
    ) -> Result<FinalizeOutcome, UploadTransitionError> {
        Err(UploadTransitionError::Storage(StorageError::Unsupported))
    }

    /// Aborts an upload session and cleans up temporary staging data.
    async fn abort_session(&self, _session: &UploadSessionId) -> Result<(), StorageError> {
        Err(StorageError::Unsupported)
    }

    /// Recovers an interrupted or expired session state.
    async fn recover_session(
        &self,
        _session: &UploadSessionId,
    ) -> Result<UploadSessionStatus, UploadTransitionError> {
        Err(UploadTransitionError::Storage(StorageError::Unsupported))
    }

    /// Fetches an existing finalized receipt if present.
    async fn get_finalized_receipt(
        &self,
        _session: &UploadSessionId,
    ) -> Result<Option<FinalizedReceipt>, StorageError> {
        Err(StorageError::Unsupported)
    }

    /// Reaps expired upload sessions and receipts based on max age and receipt TTL.
    async fn reap_expired_sessions(
        &self,
        _max_age_secs: u64,
        _receipt_ttl_secs: u64,
    ) -> Result<usize, StorageError> {
        Err(StorageError::Unsupported)
    }
}

#[async_trait]
impl<T: ?Sized + UploadSessionStorage + Send + Sync> UploadSessionStorage for std::sync::Arc<T> {
    async fn create_session(&self, repo: &str) -> Result<UploadSessionId, StorageError> {
        (**self).create_session(repo).await
    }

    async fn session_status(
        &self,
        session: &UploadSessionId,
    ) -> Result<UploadSessionStatus, UploadTransitionError> {
        (**self).session_status(session).await
    }

    async fn append_if_offset(
        &self,
        session: &UploadSessionId,
        expected_offset: UploadOffsetPrecondition,
        stream: UploadByteStream,
        max_upload_bytes: u64,
    ) -> Result<UploadAppendResult, UploadTransitionError> {
        (**self)
            .append_if_offset(session, expected_offset, stream, max_upload_bytes)
            .await
    }

    async fn begin_finalize(
        &self,
        session: &UploadSessionId,
        expected_offset: UploadOffsetPrecondition,
        trailing_stream: Option<UploadByteStream>,
        expected_digest: &Digest,
        max_upload_bytes: u64,
        abort_on_digest_mismatch: bool,
    ) -> Result<PreparedFinalize, UploadTransitionError> {
        (**self)
            .begin_finalize(
                session,
                expected_offset,
                trailing_stream,
                expected_digest,
                max_upload_bytes,
                abort_on_digest_mismatch,
            )
            .await
    }

    async fn commit_finalize(
        &self,
        prepared: &PreparedFinalize,
    ) -> Result<FinalizeOutcome, UploadTransitionError> {
        (**self).commit_finalize(prepared).await
    }

    async fn abort_session(&self, session: &UploadSessionId) -> Result<(), StorageError> {
        (**self).abort_session(session).await
    }

    async fn recover_session(
        &self,
        session: &UploadSessionId,
    ) -> Result<UploadSessionStatus, UploadTransitionError> {
        (**self).recover_session(session).await
    }

    async fn get_finalized_receipt(
        &self,
        session: &UploadSessionId,
    ) -> Result<Option<FinalizedReceipt>, StorageError> {
        (**self).get_finalized_receipt(session).await
    }

    async fn reap_expired_sessions(
        &self,
        max_age_secs: u64,
        receipt_ttl_secs: u64,
    ) -> Result<usize, StorageError> {
        (**self)
            .reap_expired_sessions(max_age_secs, receipt_ttl_secs)
            .await
    }
}
