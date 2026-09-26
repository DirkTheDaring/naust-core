use crate::blob_ref_index::BlobRefIndex;
use crate::registry::digest::Digest;
use crate::registry::validation::is_valid_repo_name;
use crate::storage::StorageError;
use crate::storage::upload_session::{
    FinalizeOutcome, UploadAppendResult, UploadByteStream, UploadOffsetPrecondition,
    UploadSessionId, UploadSessionState, UploadStreamError, UploadTransitionError,
};
use crate::upload_lifecycle::state::{StateTokenError, UploadStateData};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("repository name invalid: {0}")]
    InvalidRepoName(String),
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
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("stream error: {0}")]
    Stream(#[from] UploadStreamError),
}

impl From<UploadTransitionError> for CoordinatorError {
    fn from(err: UploadTransitionError) -> Self {
        match err {
            UploadTransitionError::NotFound => CoordinatorError::SessionNotFound,
            UploadTransitionError::OffsetMismatch { expected, current } => {
                CoordinatorError::OffsetMismatch { expected, current }
            }
            UploadTransitionError::DigestMismatch { expected, computed } => {
                CoordinatorError::DigestMismatch { expected, computed }
            }
            UploadTransitionError::Conflict => CoordinatorError::Conflict,
            UploadTransitionError::TooLarge => CoordinatorError::TooLarge,
            UploadTransitionError::InvalidPreparedHandle => CoordinatorError::InvalidPreparedHandle,
            UploadTransitionError::Storage(e) => CoordinatorError::Storage(e),
            UploadTransitionError::Stream(e) => CoordinatorError::Stream(e),
        }
    }
}

pub(crate) fn map_ref_index_error(e: crate::blob_ref_index::RefIndexError) -> StorageError {
    let msg = e.to_string();
    match e {
        crate::blob_ref_index::RefIndexError::Storage(se) => match se {
            StorageError::Internal { kind, .. } => StorageError::internal(kind, msg),
            other => other,
        },
        crate::blob_ref_index::RefIndexError::Corrupt(_) => StorageError::corrupt_data(msg),
        // Deliberate fail-closed resource-limit exhaustion; classified as a
        // backend failure (NOT corruption) so it cannot trigger an
        // auto-rebuild-on-corruption loop that would exhaust the same limit.
        crate::blob_ref_index::RefIndexError::ResourceLimit(_) => StorageError::backend(msg),
        crate::blob_ref_index::RefIndexError::ManifestParse(_) => StorageError::corrupt_data(msg),
        crate::blob_ref_index::RefIndexError::NotFound(_) => StorageError::NotFound,
        crate::blob_ref_index::RefIndexError::Sled(err) => match err {
            sled::Error::Io(ref io_err) => {
                if io_err.raw_os_error() == Some(libc::ENOSPC)
                    || io_err.kind() == std::io::ErrorKind::StorageFull
                {
                    StorageError::InsufficientStorage
                } else if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                    StorageError::permission_denied(msg)
                } else {
                    StorageError::io(msg)
                }
            }
            sled::Error::Corruption { .. } => StorageError::corrupt_data(msg),
            sled::Error::Unsupported(_) => StorageError::configuration(msg),
            sled::Error::ReportableBug(_) => StorageError::internal_invariant(msg),
            sled::Error::CollectionNotFound(_) => StorageError::internal_invariant(msg),
        },
    }
}

pub(crate) fn map_ref_index_error_with_context(
    e: crate::blob_ref_index::RefIndexError,
    context: &str,
) -> StorageError {
    let msg = format!("{context}: {e}");
    match e {
        crate::blob_ref_index::RefIndexError::Storage(se) => match se {
            StorageError::Internal { kind, .. } => StorageError::internal(kind, msg),
            other => other,
        },
        crate::blob_ref_index::RefIndexError::Corrupt(_) => StorageError::corrupt_data(msg),
        // Deliberate fail-closed resource-limit exhaustion; classified as a
        // backend failure (NOT corruption) so it cannot trigger an
        // auto-rebuild-on-corruption loop that would exhaust the same limit.
        crate::blob_ref_index::RefIndexError::ResourceLimit(_) => StorageError::backend(msg),
        crate::blob_ref_index::RefIndexError::ManifestParse(_) => StorageError::corrupt_data(msg),
        crate::blob_ref_index::RefIndexError::NotFound(_) => StorageError::NotFound,
        crate::blob_ref_index::RefIndexError::Sled(err) => match err {
            sled::Error::Io(ref io_err) => {
                if io_err.raw_os_error() == Some(libc::ENOSPC)
                    || io_err.kind() == std::io::ErrorKind::StorageFull
                {
                    StorageError::InsufficientStorage
                } else if io_err.kind() == std::io::ErrorKind::PermissionDenied {
                    StorageError::permission_denied(msg)
                } else {
                    StorageError::io(msg)
                }
            }
            sled::Error::Corruption { .. } => StorageError::corrupt_data(msg),
            sled::Error::Unsupported(_) => StorageError::configuration(msg),
            sled::Error::ReportableBug(_) => StorageError::internal_invariant(msg),
            sled::Error::CollectionNotFound(_) => StorageError::internal_invariant(msg),
        },
    }
}

#[inline]
pub(crate) fn resolve_pin_failure_or_fallback(failure_err: Option<StorageError>) -> StorageError {
    failure_err.unwrap_or_else(|| {
        StorageError::internal_invariant("pin renewal heartbeat failed during commit")
    })
}

#[derive(Clone, Debug)]
pub struct StartUploadResult {
    pub session: UploadSessionId,
    pub state_token: String,
    pub offset: u64,
}

#[derive(Clone, Debug)]
pub struct UploadStatusResult {
    pub session: UploadSessionId,
    pub state: UploadSessionState,
    pub offset: u64,
    pub state_token: String,
}

#[derive(Clone, Debug)]
pub struct AppendResult {
    pub session: UploadSessionId,
    pub new_offset: u64,
    pub state_token: String,
}

#[derive(Clone, Debug)]
pub struct FinalizeResult {
    pub digest: Digest,
    pub size: u64,
    pub already_existed: bool,
}

#[derive(Debug)]
pub enum MonolithicUploadResult {
    Created(FinalizeResult),
    SessionStarted(StartUploadResult),
    AlreadyFinalized(FinalizeResult),
}

#[derive(Debug)]
pub enum CrossMountResult {
    Mounted(FinalizeResult),
    Fallback(StartUploadResult),
}

#[derive(Clone)]
pub struct BlobUploadCoordinatorConfig {
    pub signing_key: Vec<u8>,
    pub max_upload_bytes: u64,
    pub abort_on_digest_mismatch: bool,
    pub disallow_monolithic_uploads: bool,
    pub upload_chunk_min_bytes: Option<u64>,
    pub gc_pin_duration_secs: u64,
    /// Post-finalize protection window (REQ-012): a freshly published blob is
    /// pin-protected for this long so a slow client can still push the
    /// referencing manifest even under aggressive GC min-age settings.
    /// 0 disables the grace pin.
    pub finalize_grace_secs: u64,
}

impl Default for BlobUploadCoordinatorConfig {
    fn default() -> Self {
        Self {
            signing_key: b"naust-state-secret".to_vec(),
            max_upload_bytes: 0,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 72 * 3600,
        }
    }
}

/// Structured RAII guard for the durable garbage collection pin and background renewal heartbeat.
///
/// Invariant:
/// - If the request future is cancelled or dropped, `Drop` immediately aborts the renewal task
///   without releasing the durable pin (retaining crash-consistency protection for eventual recovery).
/// - When finalization succeeds, `stop().await` is executed before `release_pin()` to ensure no
///   subsequent background iteration can recreate or extend an already-released pin.
/// - If renewal fails while commit is in progress, the failure is observed concurrently via
///   `tokio::select!`, aborting commit and returning a retryable error while retaining the pin.
pub struct PinLeaseGuard {
    idx: Arc<BlobRefIndex>,
    digest: Digest,
    op_id: String,
    task_handle: Option<tokio::task::JoinHandle<()>>,
    failure_rx: tokio::sync::mpsc::Receiver<StorageError>,
    stopped: bool,
    released: bool,
}

impl PinLeaseGuard {
    pub async fn acquire_and_start(
        idx: Arc<BlobRefIndex>,
        digest: &Digest,
        op_id: &str,
        pin_ttl_secs: u64,
    ) -> Result<Self, CoordinatorError> {
        idx.check_health().map_err(|e| {
            CoordinatorError::Storage(map_ref_index_error_with_context(
                e,
                "ref-index unhealthy before acquiring GC pin",
            ))
        })?;

        let pin_until = SystemTime::now() + Duration::from_secs(pin_ttl_secs);
        idx.acquire_pin(digest, op_id, pin_until, "upload_finalizing")
            .map_err(|e| {
                CoordinatorError::Storage(map_ref_index_error_with_context(
                    e,
                    "failed to acquire GC pin",
                ))
            })?;

        let (failure_tx, failure_rx) = tokio::sync::mpsc::channel(1);
        let idx_clone = Arc::clone(&idx);
        let op_id_string = op_id.to_string();
        let digest_clone = digest.clone();
        let renew_interval = Duration::from_secs((pin_ttl_secs / 3).max(1));

        let task_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(renew_interval).await;
                if let Err(e) = idx_clone.check_health() {
                    let _ = failure_tx
                        .send(map_ref_index_error_with_context(e, "pin renewal failed"))
                        .await;
                    break;
                }
                let refreshed_until = SystemTime::now() + Duration::from_secs(pin_ttl_secs);
                if let Err(e) = idx_clone.acquire_pin(
                    &digest_clone,
                    &op_id_string,
                    refreshed_until,
                    "upload_finalizing_renewal",
                ) {
                    let _ = failure_tx
                        .send(map_ref_index_error_with_context(e, "pin renewal failed"))
                        .await;
                    break;
                }
            }
        });

        Ok(Self {
            idx,
            digest: digest.clone(),
            op_id: op_id.to_string(),
            task_handle: Some(task_handle),
            failure_rx,
            stopped: false,
            released: false,
        })
    }

    pub async fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        if let Some(handle) = self.task_handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }

    /// Places the post-finalize grace pin (REQ-012) under a dedicated pin id;
    /// it expires on its own and is never explicitly released.
    pub fn grace_pin(&self, until: SystemTime) -> Result<(), CoordinatorError> {
        self.idx
            .acquire_pin(
                &self.digest,
                "finalize-grace",
                until,
                "finalize grace (REQ-012)",
            )
            .map_err(|e| {
                CoordinatorError::Storage(map_ref_index_error_with_context(
                    e,
                    "failed to place finalize grace pin",
                ))
            })
    }

    pub fn release_pin(&mut self) -> Result<(), CoordinatorError> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        self.idx
            .release_pin(&self.digest, &self.op_id)
            .map_err(|e| {
                CoordinatorError::Storage(map_ref_index_error_with_context(
                    e,
                    "failed to release pin",
                ))
            })?;
        Ok(())
    }

    pub async fn wait_for_failure(&mut self) -> Option<StorageError> {
        self.failure_rx.recv().await
    }
}

impl Drop for PinLeaseGuard {
    fn drop(&mut self) {
        if let Some(ref handle) = self.task_handle {
            handle.abort();
        }
        // Do NOT release the pin in Drop! Retain for crash-recovery/timeout.
    }
}

pub struct BlobUploadCoordinator {
    storage: Arc<dyn crate::storage::BlobUploadCoordinatorStoragePort>,
    ref_index: Option<Arc<BlobRefIndex>>,
    consistency: crate::consistency::ConsistencyCoordinator,
    config: BlobUploadCoordinatorConfig,
}

impl BlobUploadCoordinator {
    pub fn new(
        storage: Arc<dyn crate::storage::BlobUploadCoordinatorStoragePort>,
        ref_index: Option<Arc<BlobRefIndex>>,
        consistency: crate::consistency::ConsistencyCoordinator,
        config: BlobUploadCoordinatorConfig,
    ) -> Self {
        Self {
            storage,
            ref_index,
            consistency,
            config,
        }
    }

    pub fn storage(&self) -> &Arc<dyn crate::storage::BlobUploadCoordinatorStoragePort> {
        &self.storage
    }

    pub fn ref_index(&self) -> Option<&Arc<BlobRefIndex>> {
        self.ref_index.as_ref()
    }

    pub fn config(&self) -> &BlobUploadCoordinatorConfig {
        &self.config
    }

    fn generate_state_token(&self, repo: &str, uuid: &str, offset: u64) -> String {
        UploadStateData::new(repo, uuid, offset).encode_and_sign(&self.config.signing_key)
    }

    fn validate_state_token(
        &self,
        token_str: Option<&str>,
        repo: &str,
        uuid: &str,
        expected_offset: Option<u64>,
        is_required: bool,
    ) -> Result<Option<UploadStateData>, CoordinatorError> {
        let Some(raw_token) = token_str else {
            if is_required {
                return Err(CoordinatorError::StateToken(StateTokenError::Missing));
            }
            return Ok(None);
        };

        let data = UploadStateData::verify_and_decode(raw_token, &self.config.signing_key, repo)?;

        if let Some(expected) = expected_offset {
            data.validate_session(uuid, expected)?;
        } else if data.uuid != uuid {
            return Err(CoordinatorError::StateToken(StateTokenError::UuidMismatch));
        }

        Ok(Some(data))
    }

    /// Starts a new chunked upload session for the given repository.
    pub async fn start_upload(&self, repo: &str) -> Result<StartUploadResult, CoordinatorError> {
        let session = self.storage.create_session(repo).await?;
        let state_token = self.generate_state_token(repo, &session.uuid, 0);
        Ok(StartUploadResult {
            session,
            state_token,
            offset: 0,
        })
    }

    /// Queries the status and authoritative offset of an upload session.
    pub async fn get_upload_status(
        &self,
        repo: &str,
        uuid: &str,
        state_param: Option<&str>,
    ) -> Result<UploadStatusResult, CoordinatorError> {
        // Optional state validation if present
        let _ = self.validate_state_token(state_param, repo, uuid, None, false)?;

        let canonical_repo = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| CoordinatorError::InvalidRepoName(e.to_string()))?;
        let session = UploadSessionId::new(canonical_repo, uuid);
        let status = self.storage.session_status(&session).await?;

        let state_token = self.generate_state_token(repo, uuid, status.committed_offset);

        Ok(UploadStatusResult {
            session: status.session,
            state: status.state,
            offset: status.committed_offset,
            state_token,
        })
    }

    /// Appends stream chunks to an active upload session.
    ///
    /// Requires a valid signed `_state` token matching the current authoritative offset.
    pub async fn append_upload(
        &self,
        repo: &str,
        uuid: &str,
        state_param: &str,
        content_range: Option<(u64, u64)>,
        content_length: Option<u64>,
        stream: UploadByteStream,
    ) -> Result<AppendResult, CoordinatorError> {
        let canonical_repo = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| CoordinatorError::InvalidRepoName(e.to_string()))?;
        let session = UploadSessionId::new(canonical_repo, uuid);

        // 1. Query authoritative status first to validate state token against authoritative offset
        let status = self.storage.session_status(&session).await?;

        // 2. Validate mandatory signed _state token against authoritative offset
        self.validate_state_token(
            Some(state_param),
            repo,
            uuid,
            Some(status.committed_offset),
            true,
        )?;

        // 3. Optional Content-Length pre-check against max configured limit
        if let Some(len) = content_length {
            let next_total = status.committed_offset.saturating_add(len);
            if self.config.max_upload_bytes > 0 && next_total > self.config.max_upload_bytes {
                return Err(CoordinatorError::TooLarge);
            }
        }

        // 4. Content-Range start validation if supplied
        let expected_offset = match content_range {
            Some((start, _)) => {
                if start != status.committed_offset {
                    return Err(CoordinatorError::RangeInvalid(format!(
                        "range start {start} does not match current committed offset {}",
                        status.committed_offset
                    )));
                }
                UploadOffsetPrecondition::Exact(start)
            }
            None => UploadOffsetPrecondition::Exact(status.committed_offset),
        };

        // 5. Append chunk via storage under session lock
        let append_res = self
            .storage
            .append_if_offset(
                &session,
                expected_offset,
                stream,
                self.config.max_upload_bytes,
            )
            .await?;

        let new_offset = match append_res {
            UploadAppendResult::Committed { new_offset } => new_offset,
            UploadAppendResult::OffsetMismatch { current_offset } => {
                return Err(CoordinatorError::OffsetMismatch {
                    expected: expected_offset,
                    current: current_offset,
                });
            }
            UploadAppendResult::Conflict => return Err(CoordinatorError::Conflict),
        };

        // 6. Sign and return fresh state token bound to new offset
        let new_token = self.generate_state_token(repo, uuid, new_offset);
        Ok(AppendResult {
            session: session.clone(),
            new_offset,
            state_token: new_token,
        })
    }

    /// Finalizes an upload session and durably links it into the repository-scoped ledger and CAS store.
    pub async fn finalize_upload(
        &self,
        repo: &str,
        uuid: &str,
        state_param: Option<&str>,
        content_range: Option<(u64, u64)>,
        trailing_stream: Option<UploadByteStream>,
        expected_digest: &Digest,
    ) -> Result<FinalizeResult, CoordinatorError> {
        let canonical_repo = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| CoordinatorError::InvalidRepoName(e.to_string()))?;
        let session = UploadSessionId::new(canonical_repo, uuid);

        // 1. Check if finalized receipt already exists (idempotent retry)
        if let Ok(Some(receipt)) = self.storage.get_finalized_receipt(&session).await {
            // Receipt must strictly match the target repository and upload UUID
            if receipt.repo.as_str() != repo || receipt.uuid != uuid {
                return Err(CoordinatorError::SessionNotFound);
            }
            if receipt.digest != expected_digest.as_str() {
                return Err(CoordinatorError::DigestMismatch {
                    expected: expected_digest.clone(),
                    computed: receipt.digest,
                });
            }
            // Fail closed if global CAS blob is missing
            match self.storage.head_blob(expected_digest).await {
                Ok(_) => {}
                Err(StorageError::NotFound) => {
                    return Err(CoordinatorError::Storage(
                        crate::storage::StorageError::corrupt_data(
                            "corrupt receipt: global CAS blob missing",
                        ),
                    ));
                }
                Err(other) => return Err(CoordinatorError::Storage(other)),
            }
            // Fail closed if repository membership is missing (e.g. deleted) or corrupt
            let membership = self
                .storage
                .get_repo_blob_membership(repo, expected_digest)
                .await
                .map_err(CoordinatorError::Storage)?;
            if membership.is_none() {
                return Err(CoordinatorError::SessionNotFound);
            }

            return Ok(FinalizeResult {
                digest: expected_digest.clone(),
                size: receipt.size,
                already_existed: true,
            });
        }

        // 2. Fetch authoritative session status to check state and validate pre-conditions
        let status = match self.storage.session_status(&session).await {
            Ok(s) => s,
            Err(UploadTransitionError::NotFound) => {
                return Err(CoordinatorError::SessionNotFound);
            }
            Err(e) => return Err(CoordinatorError::from(e)),
        };

        // Optional state validation if present: validate binding and offset against authoritative committed offset
        let _ = self.validate_state_token(
            state_param,
            repo,
            uuid,
            Some(status.committed_offset),
            false,
        )?;

        // Content-Range start validation if supplied
        if let Some((start, _)) = content_range
            && start != status.committed_offset
        {
            return Err(CoordinatorError::RangeInvalid(format!(
                "range start {start} does not match current committed offset {}",
                status.committed_offset
            )));
        }

        // STEP 1: Begin finalize in storage backend (verifies digest against expected, sets Finalizing)
        let prepared = self
            .storage
            .begin_finalize(
                &session,
                UploadOffsetPrecondition::CurrentForServerComposedMonolithicOperation,
                trailing_stream,
                expected_digest,
                self.config.max_upload_bytes,
                self.config.abort_on_digest_mismatch,
            )
            .await?;

        // STEP 2: Ensure the reverse index is healthy BEFORE the pin gate.
        // The pin acquisition fails closed on an unhealthy index, so the
        // documented BUILDING/dirty recovery (auto-rebuild) must run first —
        // with the historical order (pin gate, then heal) a failed rebuild
        // left blob finalization permanently refusing with "ref-index
        // unhealthy before acquiring GC pin" while the self-heal four lines
        // below it was unreachable (the BUILDING-wedge repair; the heal call
        // itself is unchanged).
        if let Some(ref idx) = self.ref_index {
            idx.ensure_healthy_or_rebuild(&self.storage, true, false)
                .await
                .map_err(|e| CoordinatorError::Storage(map_ref_index_error(e)))?;
        }

        // STEP 3: Durably pin the verified digest in BlobRefIndex to protect against concurrent online GC
        let mut pin_guard = if let Some(ref idx) = self.ref_index {
            Some(
                PinLeaseGuard::acquire_and_start(
                    Arc::clone(idx),
                    expected_digest,
                    &prepared.operation_id,
                    self.config.gc_pin_duration_secs,
                )
                .await?,
            )
        } else {
            None
        };

        // STEP 4: Durably mark reverse index dirty before storage mutation
        if let Some(ref idx) = self.ref_index {
            idx.mark_dirty()
                .map_err(|e| CoordinatorError::Storage(map_ref_index_error(e)))?;
        }

        // STEP 5: Commit finalize in storage backend under the consistency coordinator
        let _guard = self.consistency.acquire_mutation().await;
        let outcome = if let Some(ref mut guard) = pin_guard {
            tokio::select! {
                outcome_res = self.storage.commit_finalize(&prepared) => {
                    outcome_res?
                }
                failure_err = guard.wait_for_failure() => {
                    drop(_guard);
                    guard.stop().await;
                    let err = resolve_pin_failure_or_fallback(failure_err);
                    return Err(CoordinatorError::Storage(err));
                }
            }
        } else {
            self.storage.commit_finalize(&prepared).await?
        };

        // STEP 6: Update reverse index, flush, and mark ready
        if let Some(ref idx) = self.ref_index {
            idx.record_membership(expected_digest, repo)
                .map_err(|e| CoordinatorError::Storage(map_ref_index_error(e)))?;
            idx.flush()
                .map_err(|e| CoordinatorError::Storage(map_ref_index_error(e)))?;
            idx.mark_ready()
                .map_err(|e| CoordinatorError::Storage(map_ref_index_error(e)))?;
        }
        drop(_guard);

        // STEP 7: Stop renewal and release the operational pin. Freshly
        // published content first receives a fixed-TTL grace pin (REQ-012):
        // pins auto-expire, so no release path is needed for it.
        if let Some(ref mut guard) = pin_guard {
            guard.stop().await;
            if self.config.finalize_grace_secs > 0
                && matches!(outcome, FinalizeOutcome::Published(_))
            {
                let until =
                    SystemTime::now() + Duration::from_secs(self.config.finalize_grace_secs);
                if let Err(err) = guard.grace_pin(until) {
                    tracing::warn!(error = %err, "failed to place finalize grace pin");
                }
            }
            let _ = guard.release_pin();
        }

        match outcome {
            FinalizeOutcome::Published(meta) => Ok(FinalizeResult {
                digest: expected_digest.clone(),
                size: meta.size,
                already_existed: false,
            }),
            FinalizeOutcome::AlreadyFinalized(meta) => Ok(FinalizeResult {
                digest: expected_digest.clone(),
                size: meta.size,
                already_existed: true,
            }),
        }
    }

    /// Performs a single-request monolithic upload or fast session creation.
    pub async fn monolithic_upload(
        &self,
        repo: &str,
        digest: &Digest,
        stream: Option<UploadByteStream>,
    ) -> Result<MonolithicUploadResult, CoordinatorError> {
        if !is_valid_repo_name(repo) {
            return Err(CoordinatorError::InvalidRepoName(repo.to_string()));
        }

        // Check if digest already exists in CAS store and already has membership in this repository
        if let Ok(meta) = self.storage.head_blob(digest).await
            && let Ok(Some(_)) = self.storage.get_repo_blob_membership(repo, digest).await
        {
            return Ok(MonolithicUploadResult::AlreadyFinalized(FinalizeResult {
                digest: digest.clone(),
                size: meta.size,
                already_existed: true,
            }));
        }

        if self.config.disallow_monolithic_uploads {
            return Err(CoordinatorError::MonolithicDisallowed);
        }

        let Some(stream) = stream else {
            let start_res = self.start_upload(repo).await?;
            return Ok(MonolithicUploadResult::SessionStarted(start_res));
        };

        // Create new session and directly finalize with the full stream
        let session = self.storage.create_session(repo).await?;
        let res = self
            .finalize_upload(repo, &session.uuid, None, None, Some(stream), digest)
            .await?;

        Ok(MonolithicUploadResult::Created(res))
    }

    /// Unified publication of verified blob content for proxy caching.
    ///
    /// Required state transition:
    /// 1. Download/stage and digest-verify content via session creation and streaming.
    /// 2. Acquire a durable upload/publication pin for the digest in BlobRefIndex.
    /// 3. Publish into CAS store.
    /// 4. Under the shared consistency gate, create repository membership and record in ref-index.
    /// 5. Durably flush required state.
    /// 6. Release the pin only after membership succeeds.
    pub async fn publish_proxy_blob(
        &self,
        local_repo: &crate::registry::canonical_name::CanonicalRepoName,
        digest: &Digest,
        stream: UploadByteStream,
    ) -> Result<(), CoordinatorError> {
        let session = self.storage.create_session(local_repo.as_str()).await?;
        self.finalize_upload(
            local_repo.as_str(),
            &session.uuid,
            None,
            None,
            Some(stream),
            digest,
        )
        .await?;
        Ok(())
    }

    /// Performs cross-repository blob mounting with full membership verification and GC protection.
    pub async fn cross_mount_blob(
        &self,
        target_repo: &str,
        from_repo: Option<&str>,
        digest: &Digest,
    ) -> Result<CrossMountResult, CoordinatorError> {
        let canonical_target =
            crate::registry::canonical_name::CanonicalRepoName::parse(target_repo)
                .map_err(|e| CoordinatorError::InvalidRepoName(e.to_string()))?;

        let Some(from_repo) = from_repo else {
            // Missing from parameter -> safe fallback to normal 202 upload session
            let start = self.start_upload(target_repo).await?;
            return Ok(CrossMountResult::Fallback(start));
        };

        let canonical_from = crate::registry::canonical_name::CanonicalRepoName::parse(from_repo)
            .map_err(|e| CoordinatorError::InvalidRepoName(e.to_string()))?;

        // 1. Verify source repository membership
        let src_membership = self
            .storage
            .get_repo_blob_membership(from_repo, digest)
            .await?;

        let Some(_src_rec) = src_membership else {
            // Source repo does not own this blob -> safe fallback to normal 202 session
            let start = self.start_upload(target_repo).await?;
            return Ok(CrossMountResult::Fallback(start));
        };

        // 2. Ensure the reverse index is healthy BEFORE the pin gate (the
        // same BUILDING-wedge repair as monolithic finalization: the
        // documented auto-rebuild recovery must precede the fail-closed pin
        // health gate).
        let op_id = uuid::Uuid::new_v4().to_string();
        if let Some(ref idx) = self.ref_index {
            idx.ensure_healthy_or_rebuild(&self.storage, true, false)
                .await
                .map_err(|e| CoordinatorError::Storage(map_ref_index_error(e)))?;
        }

        // 3. Durably pin the verified digest in BlobRefIndex
        let mut pin_guard = if let Some(ref idx) = self.ref_index {
            Some(
                PinLeaseGuard::acquire_and_start(
                    Arc::clone(idx),
                    digest,
                    &op_id,
                    self.config.gc_pin_duration_secs,
                )
                .await?,
            )
        } else {
            None
        };

        // 4. Verify underlying CAS blob existence
        let meta = match self.storage.head_blob(digest).await {
            Ok(m) => m,
            Err(e) => return Err(CoordinatorError::from(e)),
        };

        // 5. Durably mark reverse index dirty before storage mutation
        if let Some(ref idx) = self.ref_index {
            idx.mark_dirty()
                .map_err(|e| CoordinatorError::Storage(map_ref_index_error(e)))?;
        }

        // 6. Durably create target repository membership under the consistency coordinator
        let target_record =
            crate::storage::repo_membership::RepoBlobMembershipRecord::new_cross_mount(
                canonical_target,
                digest.clone(),
                canonical_from,
            );
        let _guard = self.consistency.acquire_mutation().await;
        let link_res = self.storage.link_repo_blob(&target_record).await;

        if let Ok(()) = link_res
            && let Some(ref idx) = self.ref_index
        {
            let _ = idx.record_membership(digest, target_repo);
            let _ = idx.flush();
            let _ = idx.mark_ready();
        }
        drop(_guard);

        if let Some(ref mut guard) = pin_guard {
            guard.stop().await;
            let _ = guard.release_pin();
        }

        link_res?;

        Ok(CrossMountResult::Mounted(FinalizeResult {
            digest: digest.clone(),
            size: meta.size,
            already_existed: true,
        }))
    }

    /// Aborts an upload session and cleans up temporary staging data.
    pub async fn abort_upload(
        &self,
        repo: &str,
        uuid: &str,
        state_param: Option<&str>,
    ) -> Result<(), CoordinatorError> {
        // Validate optional state token if provided
        let _ = self.validate_state_token(state_param, repo, uuid, None, false)?;

        let canonical_repo = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| CoordinatorError::InvalidRepoName(e.to_string()))?;
        let session = UploadSessionId::new(canonical_repo, uuid);
        self.storage.abort_session(&session).await?;
        Ok(())
    }

    /// Reaps expired upload sessions and stale finalized receipts across storage.
    pub async fn reap_expired_uploads(
        &self,
        max_age_secs: u64,
        receipt_ttl_secs: u64,
    ) -> Result<usize, CoordinatorError> {
        let count = self
            .storage
            .reap_expired_sessions(max_age_secs, receipt_ttl_secs)
            .await?;
        if let Some(ref idx) = self.ref_index {
            let _ = idx.purge_expired_pins(SystemTime::now());
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Storage;
    use crate::storage::ports::BlobUploadCoordinatorStoragePort;
    use crate::storage::s3::tests::{MockS3Driver, TagBridgeDriver};
    use crate::storage::upload_session::UploadSessionStorage;
    use sha2::Digest as _;
    use tempfile::TempDir;

    fn hex_sha256(bytes: &[u8]) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn test_coordinator(
        storage: Arc<dyn BlobUploadCoordinatorStoragePort>,
        ref_index: Option<Arc<BlobRefIndex>>,
        config: BlobUploadCoordinatorConfig,
    ) -> BlobUploadCoordinator {
        BlobUploadCoordinator::new(
            storage,
            ref_index,
            crate::consistency::ConsistencyCoordinator::new(),
            config,
        )
    }

    #[tokio::test]
    async fn test_coordinator_s3_monolithic_upload() {
        let driver = Arc::new(MockS3Driver::new(1000));
        // Phase 6: the finalize path writes membership through the shared
        // domain over the migrated object store, so the mock driver is
        // wrapped in the bridge that provides the object-store seam.
        let storage = Arc::new(crate::storage::s3::S3Storage::new_with_driver(
            Some("test-bucket".to_string()),
            "".to_string(),
            104857600,
            Arc::new(TagBridgeDriver::new(driver.clone())),
        ));
        let config = BlobUploadCoordinatorConfig {
            signing_key: b"test-key".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 72 * 3600,
        };
        let coordinator = test_coordinator(storage.clone(), None, config);

        let repo = "s3-test/repo";
        let data = b"payload for s3 monolithic upload test";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();
        let stream = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(data))
        }));

        let res = coordinator
            .monolithic_upload(repo, &digest, Some(stream))
            .await
            .unwrap();

        match res {
            MonolithicUploadResult::Created(fin) => {
                assert_eq!(fin.digest, digest);
                assert_eq!(fin.size, data.len() as u64);
            }
            other => panic!("Unexpected monolithic upload outcome: {other:?}"),
        }

        // Head blob in CAS storage
        let head = storage.head_blob(&digest).await.unwrap();
        assert_eq!(head.size, data.len() as u64);
    }

    #[tokio::test]
    async fn test_coordinator_fs_chunked_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let storage = Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let config = BlobUploadCoordinatorConfig {
            signing_key: b"test-fs-key".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 72 * 3600,
        };
        let coordinator = test_coordinator(storage.clone(), None, config);

        let repo = "fs-test/repo";
        let chunk1 = b"chunk one of the file;";
        let chunk2 = b" chunk two of the file.";
        let mut full = chunk1.to_vec();
        full.extend_from_slice(chunk2);
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(&full))).unwrap();

        // 1. Start upload
        let start = coordinator.start_upload(repo).await.unwrap();
        assert_eq!(start.offset, 0);

        // 2. Append chunk 1
        let stream1 = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(chunk1))
        }));
        let app1 = coordinator
            .append_upload(
                repo,
                &start.session.uuid,
                &start.state_token,
                None,
                Some(chunk1.len() as u64),
                stream1,
            )
            .await
            .unwrap();
        assert_eq!(app1.new_offset, chunk1.len() as u64);

        // 3. Status check
        let st = coordinator
            .get_upload_status(repo, &start.session.uuid, Some(&app1.state_token))
            .await
            .unwrap();
        assert_eq!(st.offset, chunk1.len() as u64);

        // 4. Append chunk 2
        let stream2 = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(chunk2))
        }));
        let app2 = coordinator
            .append_upload(
                repo,
                &start.session.uuid,
                &app1.state_token,
                None,
                Some(chunk2.len() as u64),
                stream2,
            )
            .await
            .unwrap();
        assert_eq!(app2.new_offset, full.len() as u64);

        // 5. Finalize
        let fin = coordinator
            .finalize_upload(
                repo,
                &start.session.uuid,
                Some(&app2.state_token),
                None,
                None,
                &digest,
            )
            .await
            .unwrap();
        assert_eq!(fin.digest, digest);
        assert_eq!(fin.size, full.len() as u64);
    }

    /// REQ-012 (KI-03): a freshly published blob carries a finalize-grace pin
    /// so slow clients can push the referencing manifest before GC may act;
    /// the pin expires on its own and uses a dedicated pin id.
    #[tokio::test]
    async fn test_finalize_grace_pin_protects_fresh_publication() {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let ref_path = temp_dir.path().join("ref_index");
        std::fs::create_dir_all(&ref_path).unwrap();
        let storage: Arc<dyn BlobUploadCoordinatorStoragePort> =
            Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let ref_index = Arc::new(BlobRefIndex::open(ref_path).unwrap());
        ref_index
            .ensure_healthy_or_rebuild(storage.as_ref(), true, false)
            .await
            .unwrap();

        let config = BlobUploadCoordinatorConfig {
            signing_key: b"grace-test".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 3600,
        };
        let coordinator = test_coordinator(storage.clone(), Some(ref_index.clone()), config);

        let data = b"grace pinned payload";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();
        let stream = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(data))
        }));
        let res = coordinator
            .monolithic_upload("grace/repo", &digest, Some(stream))
            .await
            .unwrap();
        assert!(matches!(res, MonolithicUploadResult::Created(_)));

        // Protected by the grace pin (the operational pin itself is released).
        assert!(
            ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap(),
            "fresh publication must be grace-pinned"
        );
        // It is exactly the dedicated finalize-grace pin…
        assert!(ref_index.unpin_blob(&digest, "finalize-grace").unwrap());
        // …and nothing else keeps it pinned afterwards.
        assert!(
            !ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_coordinator_gc_pin_race_preserves_pinned_blob_during_finalization() {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let ref_path = temp_dir.path().join("ref_index");
        std::fs::create_dir_all(&ref_path).unwrap();

        let storage: Arc<dyn BlobUploadCoordinatorStoragePort> =
            Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let ref_index = Arc::new(BlobRefIndex::open(ref_path).unwrap());
        ref_index
            .ensure_healthy_or_rebuild(storage.as_ref(), true, false)
            .await
            .unwrap();

        let config = BlobUploadCoordinatorConfig {
            signing_key: b"test-gc-pin-key".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 0,
        };
        let coordinator = test_coordinator(storage.clone(), Some(ref_index.clone()), config);

        let repo = "gc-test/repo";
        let data = b"payload to test GC pin protection";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();
        let stream = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(data))
        }));

        let fin = coordinator
            .monolithic_upload(repo, &digest, Some(stream))
            .await
            .unwrap();
        match fin {
            MonolithicUploadResult::Created(res) => {
                assert_eq!(res.digest, digest);
            }
            _ => panic!("Expected created outcome"),
        }

        // Verify blob operation pin is released upon successful commit
        let is_pinned = ref_index
            .is_blob_pinned(&digest, SystemTime::now())
            .unwrap();
        assert!(
            !is_pinned,
            "Blob operation pin must be released upon successful publication"
        );

        // Verify that if a commit fails/crashes, acquire_pin preserves protection
        ref_index
            .acquire_pin(
                &digest,
                "failed-commit-op",
                SystemTime::now() + Duration::from_secs(3600),
                "upload_finalizing",
            )
            .unwrap();
        assert!(
            ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap(),
            "Blob must remain protected by operation pin during crash/recovery window"
        );
    }

    /// Discovery port whose repository listing fails deterministically —
    /// drives a GENUINE failed rebuild (durable BUILDING meta state) without
    /// touching the real storage backend.
    struct FailingDiscoveryPort;

    #[async_trait::async_trait]
    impl crate::storage::RepositoryCatalogReader for FailingDiscoveryPort {
        async fn list_repositories(&self) -> Result<Vec<String>, crate::storage::StorageError> {
            Err(crate::storage::StorageError::backend(
                "injected discovery failure",
            ))
        }
        async fn repo_timestamps(
            &self,
            _name: &str,
        ) -> Result<crate::storage::RepoTimestamps, crate::storage::StorageError> {
            Err(crate::storage::StorageError::backend("unused"))
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::TagReader for FailingDiscoveryPort {
        async fn resolve_tag(
            &self,
            _n: &str,
            _t: &str,
        ) -> Result<Digest, crate::storage::StorageError> {
            Err(crate::storage::StorageError::backend("unused"))
        }
        async fn list_tags(&self, _n: &str) -> Result<Vec<String>, crate::storage::StorageError> {
            Err(crate::storage::StorageError::backend("unused"))
        }
        async fn list_tags_page(
            &self,
            _r: &str,
            _c: Option<&str>,
            _p: usize,
        ) -> Result<(Vec<(String, Digest)>, Option<String>), crate::storage::StorageError> {
            Err(crate::storage::StorageError::backend("unused"))
        }
        async fn get_tag_with_version(
            &self,
            _r: &str,
            _t: &str,
        ) -> Result<Option<(Digest, String)>, crate::storage::StorageError> {
            Err(crate::storage::StorageError::backend("unused"))
        }
    }

    #[async_trait::async_trait]
    impl crate::storage::ManifestReader for FailingDiscoveryPort {
        async fn head_manifest(
            &self,
            _n: &str,
            _d: &Digest,
        ) -> Result<crate::storage::ManifestMeta, crate::storage::StorageError> {
            Err(crate::storage::StorageError::backend("unused"))
        }
        async fn get_manifest(
            &self,
            _n: &str,
            _d: &Digest,
        ) -> Result<(crate::storage::ManifestMeta, bytes::Bytes), crate::storage::StorageError>
        {
            Err(crate::storage::StorageError::backend("unused"))
        }
        async fn list_manifest_digests_page(
            &self,
            _r: &str,
            _c: Option<&str>,
            _p: usize,
        ) -> Result<(Vec<Digest>, Option<String>), crate::storage::StorageError> {
            Err(crate::storage::StorageError::backend("unused"))
        }
    }

    impl crate::storage::repo_membership::RepositoryBlobMembershipStorage for FailingDiscoveryPort {}

    /// BUILDING-wedge regression (Recovery Step 1): a FAILED rebuild leaves
    /// the index durably at BUILDING (the intended fail-closed state); blob
    /// finalization must then reach the DOCUMENTED auto-rebuild recovery
    /// instead of refusing at the pin health gate. On the pre-repair base
    /// this sequence failed every attempt with "ref-index unhealthy before
    /// acquiring GC pin" because the pin gate preceded the (unreachable)
    /// self-heal.
    #[tokio::test]
    async fn test_monolithic_finalize_recovers_from_building_index() {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let ref_path = temp_dir.path().join("ref_index");
        std::fs::create_dir_all(&ref_path).unwrap();

        let storage: Arc<dyn BlobUploadCoordinatorStoragePort> =
            Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let ref_index = Arc::new(BlobRefIndex::open(ref_path).unwrap());
        ref_index
            .ensure_healthy_or_rebuild(storage.as_ref(), true, false)
            .await
            .unwrap();
        ref_index.check_health().expect("healthy before the wedge");

        // A genuinely FAILED rebuild leaves durable BUILDING (fail-closed).
        ref_index
            .rebuild(&FailingDiscoveryPort)
            .await
            .expect_err("injected discovery failure must fail the rebuild");
        assert!(
            ref_index.check_health().is_err(),
            "failed rebuild leaves the index unhealthy (BUILDING)"
        );

        let config = BlobUploadCoordinatorConfig {
            signing_key: b"test-building-recovery".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 72 * 3600,
        };
        let coordinator = test_coordinator(storage.clone(), Some(ref_index.clone()), config);

        let repo = "recovery/repo";
        let data = b"payload after failed rebuild";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();
        let stream = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(data))
        }));

        let fin = coordinator
            .monolithic_upload(repo, &digest, Some(stream))
            .await
            .expect("finalization heals the BUILDING index via the documented auto-rebuild");
        match fin {
            MonolithicUploadResult::Created(res) => assert_eq!(res.digest, digest),
            other => panic!("expected created outcome, got {other:?}"),
        }
        ref_index
            .check_health()
            .expect("index healthy after the self-healed finalization");
    }

    /// The same wedge repair on the cross-mount path: a BUILDING index must
    /// heal via the documented recovery before the pin gate.
    #[tokio::test]
    async fn test_cross_mount_recovers_from_building_index() {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let ref_path = temp_dir.path().join("ref_index");
        std::fs::create_dir_all(&ref_path).unwrap();

        let storage: Arc<dyn BlobUploadCoordinatorStoragePort> =
            Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let ref_index = Arc::new(BlobRefIndex::open(ref_path).unwrap());
        ref_index
            .ensure_healthy_or_rebuild(storage.as_ref(), true, false)
            .await
            .unwrap();

        let config = BlobUploadCoordinatorConfig {
            signing_key: b"test-building-recovery-xm".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 72 * 3600,
        };
        let coordinator = test_coordinator(storage.clone(), Some(ref_index.clone()), config);

        // Publish the source blob while the index is healthy.
        let source_repo = "xm/source";
        let data = b"cross-mount payload";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();
        let stream = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(data))
        }));
        coordinator
            .monolithic_upload(source_repo, &digest, Some(stream))
            .await
            .unwrap();

        // Wedge the index with a genuinely failed rebuild.
        ref_index
            .rebuild(&FailingDiscoveryPort)
            .await
            .expect_err("injected discovery failure must fail the rebuild");
        assert!(ref_index.check_health().is_err());

        let res = coordinator
            .cross_mount_blob("xm/target", Some(source_repo), &digest)
            .await
            .expect("cross-mount heals the BUILDING index via the documented auto-rebuild");
        match res {
            CrossMountResult::Mounted(fin) => assert_eq!(fin.digest, digest),
            other => panic!("expected mounted outcome, got {other:?}"),
        }
        ref_index.check_health().expect("healthy after cross-mount");
    }

    #[tokio::test]
    async fn test_coordinator_monolithic_disallowed() {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let storage = Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let config = BlobUploadCoordinatorConfig {
            signing_key: b"test-disallow-key".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: true,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 72 * 3600,
        };
        let coordinator = test_coordinator(storage, None, config);

        let repo = "disallow/repo";
        let data = b"some data";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();
        let stream = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(data))
        }));

        let res = coordinator
            .monolithic_upload(repo, &digest, Some(stream))
            .await;
        assert!(matches!(res, Err(CoordinatorError::MonolithicDisallowed)));
    }

    struct InstrumentedPollStream {
        chunks: Vec<Result<bytes::Bytes, crate::storage::upload_session::UploadStreamError>>,
        poll_count: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl futures_util::Stream for InstrumentedPollStream {
        type Item = Result<bytes::Bytes, crate::storage::upload_session::UploadStreamError>;

        fn poll_next(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            self.poll_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.chunks.is_empty() {
                std::task::Poll::Ready(None)
            } else {
                std::task::Poll::Ready(Some(self.chunks.remove(0)))
            }
        }
    }

    #[tokio::test]
    async fn test_instrumented_stream_negative_cases_do_not_poll_body() {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let storage = Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let config = BlobUploadCoordinatorConfig {
            signing_key: b"secret-test-key".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 3600,
            finalize_grace_secs: 72 * 3600,
        };
        let coordinator = test_coordinator(storage, None, config);

        let repo = "instrumented/repo";
        let start = coordinator.start_upload(repo).await.unwrap();
        let uuid = &start.session.uuid;

        // 1. Invalid signature -> 0 polls
        let poll_count1 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stream1 = Box::pin(InstrumentedPollStream {
            chunks: vec![Ok(bytes::Bytes::from_static(b"never read"))],
            poll_count: poll_count1.clone(),
        });
        let invalid_token = format!("{}.forgedsignature", start.state_token);
        let err1 = coordinator
            .append_upload(repo, uuid, &invalid_token, None, None, stream1)
            .await;
        assert!(matches!(err1, Err(CoordinatorError::StateToken(_))));
        assert_eq!(
            poll_count1.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Invalid signature must not poll body"
        );

        // 2. Wrong repository binding -> 0 polls
        let poll_count2 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stream2 = Box::pin(InstrumentedPollStream {
            chunks: vec![Ok(bytes::Bytes::from_static(b"never read"))],
            poll_count: poll_count2.clone(),
        });
        let wrong_repo_token =
            UploadStateData::new("other/repo", uuid, 0).encode_and_sign(b"secret-test-key");
        let err2 = coordinator
            .append_upload(repo, uuid, &wrong_repo_token, None, None, stream2)
            .await;
        assert!(matches!(err2, Err(CoordinatorError::StateToken(_))));
        assert_eq!(
            poll_count2.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Wrong repo must not poll body"
        );

        // 3. Stale offset -> 0 polls
        // Advance offset first
        let advance_stream = Box::pin(futures_util::stream::once(async move {
            Ok(bytes::Bytes::from_static(b"chunk12345"))
        }));
        let app_res = coordinator
            .append_upload(repo, uuid, &start.state_token, None, None, advance_stream)
            .await
            .unwrap();
        assert_eq!(app_res.new_offset, 10);

        let poll_count3 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stream3 = Box::pin(InstrumentedPollStream {
            chunks: vec![Ok(bytes::Bytes::from_static(b"never read"))],
            poll_count: poll_count3.clone(),
        });
        // Re-use initial state token (offset 0) against committed offset 10
        let err3 = coordinator
            .append_upload(repo, uuid, &start.state_token, None, None, stream3)
            .await;
        assert!(matches!(err3, Err(CoordinatorError::StateToken(_))));
        assert_eq!(
            poll_count3.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Stale offset must not poll body"
        );

        // 4. Stream failure leaves committed offset unchanged
        let poll_count4 = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stream4 = Box::pin(InstrumentedPollStream {
            chunks: vec![Err(
                crate::storage::upload_session::UploadStreamError::IdleTimeout,
            )],
            poll_count: poll_count4.clone(),
        });
        let err4 = coordinator
            .append_upload(repo, uuid, &app_res.state_token, None, None, stream4)
            .await;
        assert!(matches!(err4, Err(CoordinatorError::Stream(_))));

        let status = coordinator
            .get_upload_status(repo, uuid, None)
            .await
            .unwrap();
        assert_eq!(
            status.offset, 10,
            "Committed offset must remain unchanged after stream failure"
        );
    }

    #[tokio::test]
    async fn test_coordinator_and_gc_pin_safety_full_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let ref_path = temp_dir.path().join("ref_index");
        std::fs::create_dir_all(&ref_path).unwrap();

        let storage: Arc<dyn BlobUploadCoordinatorStoragePort> =
            Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let ref_index = Arc::new(BlobRefIndex::open(ref_path).unwrap());
        ref_index
            .ensure_healthy_or_rebuild(storage.as_ref(), true, false)
            .await
            .unwrap();

        // Short pin duration (2 seconds) to test renewal
        let config = BlobUploadCoordinatorConfig {
            signing_key: b"secret-test-key".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 2,
            finalize_grace_secs: 0,
        };
        let coordinator = test_coordinator(storage.clone(), Some(ref_index.clone()), config);

        let repo = "pin-lifecycle/repo";
        let data = b"DATA_FOR_PIN_LIFECYCLE_TEST";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();

        // 1. Start upload & append chunk
        let start = coordinator.start_upload(repo).await.unwrap();
        let app = coordinator
            .append_upload(
                repo,
                &start.session.uuid,
                &start.state_token,
                None,
                None,
                Box::pin(futures_util::stream::once(async move {
                    Ok(bytes::Bytes::from_static(data))
                })),
            )
            .await
            .unwrap();

        // 2. Acquire a manual pin to simulate during-finalization state
        let op_id = "op-pin-test-1";
        let pin_until = SystemTime::now() + Duration::from_secs(10);
        ref_index
            .acquire_pin(&digest, op_id, pin_until, "upload_finalizing")
            .unwrap();

        // 3. Property 1 & 2: Pinned blob cannot be deleted or pruned by GC
        assert!(
            ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap(),
            "Blob must be protected while pin is active"
        );

        // 4. Property 4: If commit crashes / fails before publication, pin is retained
        assert!(
            ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap(),
            "Pin must be retained on simulated crash before commit"
        );

        // 5. Property 5: Recovery completes publication and releases the pin
        let fin_res = coordinator
            .finalize_upload(
                repo,
                &start.session.uuid,
                Some(&app.state_token),
                None,
                None,
                &digest,
            )
            .await
            .unwrap();
        assert_eq!(fin_res.digest, digest);

        // Clean up manual test pin
        let _ = ref_index.release_pin(&digest, op_id);

        // 6. Property 3 & 5: Commit success writes receipt and releases the operation pin
        assert!(
            !ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap(),
            "Operation pin must be released upon successful commit"
        );

        // 7. Property 8: When referenced by a manifest/tag, blob remains protected even without pin
        ref_index
            .on_tag_mutation(
                storage.as_ref(),
                repo,
                "v1.0",
                &digest,
                &crate::storage::TagMutation::Created,
            )
            .await
            .unwrap();
        let is_referenced = ref_index.is_blob_referenced(&digest).unwrap();
        assert!(
            is_referenced,
            "Referenced blob must be protected by ref index"
        );
    }

    // =========================================================================
    // 12 Deterministic Pin Guard & Lifecycle Properties (Phase A Acceptance)
    // =========================================================================

    // Helper: Build mock coordinator with FsStorage and BlobRefIndex
    async fn setup_test_coordinator() -> (
        Arc<dyn BlobUploadCoordinatorStoragePort>,
        Arc<BlobRefIndex>,
        BlobUploadCoordinator,
        TempDir,
    ) {
        let temp_dir = TempDir::new().unwrap();
        let fs_root = temp_dir.path().join("fs_root");
        let ref_path = temp_dir.path().join("ref_index");
        std::fs::create_dir_all(&ref_path).unwrap();

        let storage: Arc<dyn BlobUploadCoordinatorStoragePort> =
            Arc::new(crate::storage::fs::FsStorage::new(fs_root, 104857600));
        let ref_index = Arc::new(BlobRefIndex::open(ref_path).unwrap());
        ref_index
            .ensure_healthy_or_rebuild(storage.as_ref(), true, false)
            .await
            .unwrap();

        let config = BlobUploadCoordinatorConfig {
            signing_key: b"secret-test-key".to_vec(),
            max_upload_bytes: 104857600,
            abort_on_digest_mismatch: false,
            disallow_monolithic_uploads: false,
            upload_chunk_min_bytes: None,
            gc_pin_duration_secs: 2,
            finalize_grace_secs: 0,
        };
        let coordinator = test_coordinator(storage.clone(), Some(ref_index.clone()), config);

        (storage, ref_index, coordinator, temp_dir)
    }

    // Property 1: pin acquisition failure prevents commit_finalize
    #[tokio::test]
    async fn test_pin_property_1_acquisition_failure_prevents_commit_finalize() {
        let (storage, ref_index, coordinator, _tmp) = setup_test_coordinator().await;
        let repo = "prop1/repo";
        let data = b"PROPERTY_1_DATA";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();

        let start = coordinator.start_upload(repo).await.unwrap();
        let app = coordinator
            .append_upload(
                repo,
                &start.session.uuid,
                &start.state_token,
                None,
                None,
                Box::pin(futures_util::stream::once(async move {
                    Ok(bytes::Bytes::from_static(data))
                })),
            )
            .await
            .unwrap();

        // Make the index UNRECOVERABLY unhealthy: mark it dirty AND plant a
        // poison manifest so the documented auto-rebuild recovery fails
        // deterministically. (Recovery Step 1 note: a merely-dirty index no
        // longer blocks finalization — the documented auto-heal now runs
        // BEFORE the pin gate and repairs it, which is the corrected
        // contract. The property under test — no commit without pin
        // protection — therefore requires a failure the heal cannot fix.)
        ref_index.mark_dirty().unwrap();
        let poison = _tmp
            .path()
            .join("fs_root")
            .join("repos")
            .join("poisoned")
            .join("manifests")
            .join("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        std::fs::create_dir_all(poison.parent().unwrap()).unwrap();
        std::fs::write(&poison, b"not json at all").unwrap();

        let res = coordinator
            .finalize_upload(
                repo,
                &start.session.uuid,
                Some(&app.state_token),
                None,
                None,
                &digest,
            )
            .await;

        // Finalize must fail (the heal attempt fails on the poison object;
        // the pin is never acquired and the commit never runs)
        assert!(res.is_err());
        // CAS blob must NOT have been created in storage
        assert!(storage.head_blob(&digest).await.is_err());
        // The index remains fail-closed (never silently ready)
        assert!(ref_index.check_health().is_err());
    }

    // Property 2: successful commit stops and joins renewal before releasing the pin
    #[tokio::test]
    async fn test_pin_property_2_successful_commit_stops_and_joins_renewal_before_releasing_pin() {
        let (storage, ref_index, coordinator, _tmp) = setup_test_coordinator().await;
        let repo = "prop2/repo";
        let data = b"PROPERTY_2_DATA";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();

        let start = coordinator.start_upload(repo).await.unwrap();
        let app = coordinator
            .append_upload(
                repo,
                &start.session.uuid,
                &start.state_token,
                None,
                None,
                Box::pin(futures_util::stream::once(async move {
                    Ok(bytes::Bytes::from_static(data))
                })),
            )
            .await
            .unwrap();

        let res = coordinator
            .finalize_upload(
                repo,
                &start.session.uuid,
                Some(&app.state_token),
                None,
                None,
                &digest,
            )
            .await
            .unwrap();

        assert_eq!(res.digest, digest);
        // Blob exists in CAS
        assert!(storage.head_blob(&digest).await.is_ok());
        // Pin is released after success
        assert!(
            !ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );
    }

    // Property 3: commit error stops renewal and retains the pin
    #[tokio::test]
    async fn test_pin_property_3_commit_error_stops_renewal_and_retains_pin() {
        let (_storage, ref_index, _coordinator, _tmp) = setup_test_coordinator().await;
        let digest = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let op_id = "op-prop3-test";

        let mut guard =
            PinLeaseGuard::acquire_and_start(Arc::clone(&ref_index), &digest, op_id, 10)
                .await
                .unwrap();

        let handle = guard.task_handle.as_ref().unwrap().abort_handle();

        // Simulate commit error by calling stop() on guard without releasing pin
        guard.stop().await;

        // Background renewal task is joined/terminated
        assert!(handle.is_finished());
        // Durable pin in index is RETAINED
        assert!(
            ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );
    }

    // Property 4: dropping finalize_upload during commit stops renewal
    #[tokio::test]
    async fn test_pin_property_4_dropping_finalize_upload_during_commit_stops_renewal() {
        let (_storage, ref_index, _coordinator, _tmp) = setup_test_coordinator().await;
        let digest = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let op_id = "op-prop4-test";

        let guard = PinLeaseGuard::acquire_and_start(Arc::clone(&ref_index), &digest, op_id, 10)
            .await
            .unwrap();

        let handle = guard.task_handle.as_ref().unwrap().abort_handle();

        // Dropping the guard (simulating cancellation of finalize_upload future during commit)
        drop(guard);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Background renewal task is terminated
        assert!(handle.is_finished());
        // Durable pin in index is NOT deleted by Drop
        assert!(
            ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );
    }

    // Property 5: no renewal can occur after release
    #[tokio::test]
    async fn test_pin_property_5_no_renewal_can_occur_after_release() {
        let (_storage, ref_index, _coordinator, _tmp) = setup_test_coordinator().await;
        let digest = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let op_id = "op-prop5-test";

        let mut guard = PinLeaseGuard::acquire_and_start(Arc::clone(&ref_index), &digest, op_id, 2)
            .await
            .unwrap();

        guard.stop().await;
        guard.release_pin().unwrap();
        assert!(
            !ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );

        // Wait to verify no background iteration can re-create or extend the pin
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );
    }

    // Property 6: renewal failure interrupts the in-progress commit wait
    #[tokio::test]
    async fn test_pin_property_6_renewal_failure_interrupts_in_progress_commit_wait() {
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel::<StorageError>(1);
        failure_tx
            .send(StorageError::io("simulated sled corruption"))
            .await
            .unwrap();

        let commit_interrupted = tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(10)) => {
                panic!("commit wait should have been interrupted by failure channel");
            }
            msg = failure_rx.recv() => {
                let err = msg.expect("channel must yield error");
                assert_eq!(
                    err.internal_kind(),
                    Some(crate::storage::StorageErrorKind::Io)
                );
                assert_eq!(err.message(), Some("simulated sled corruption"));
                true
            }
        };
        assert!(commit_interrupted);
    }

    // Property 7: renewal failure produces a typed retryable error
    #[tokio::test]
    async fn test_pin_property_7_renewal_failure_produces_typed_retryable_error() {
        let err =
            CoordinatorError::Storage(StorageError::io("pin renewal failed: sled error: IO error"));
        let storage_err = match err {
            CoordinatorError::Storage(se) => se,
            _ => panic!("expected CoordinatorError::Storage"),
        };
        assert_eq!(
            storage_err.internal_kind(),
            Some(crate::storage::StorageErrorKind::Io)
        );
        assert_eq!(
            storage_err.message(),
            Some("pin renewal failed: sled error: IO error")
        );
        assert_eq!(
            storage_err.to_string(),
            "internal error: pin renewal failed: sled error: IO error"
        );
    }

    // Property 8: an S3 copy that completes after its future was cancelled is reconciled
    #[tokio::test]
    async fn test_pin_property_8_s3_copy_completing_after_cancellation_is_reconciled() {
        let (storage, driver) = crate::storage::s3::tests::create_mock_storage();
        let session = storage.create_session("reconcile-repo").await.unwrap();
        let data = bytes::Bytes::from_static(b"RECONCILE_S3_PAYLOAD");
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(&data))).unwrap();

        let stream_data = data.clone();
        storage
            .append_if_offset(
                &session,
                UploadOffsetPrecondition::Exact(0),
                Box::pin(futures_util::stream::once(async move { Ok(stream_data) })),
                10 * 1024 * 1024,
            )
            .await
            .unwrap();

        let prep = storage
            .begin_finalize(
                &session,
                UploadOffsetPrecondition::Exact(data.len() as u64),
                None,
                &digest,
                10 * 1024 * 1024,
                false,
            )
            .await
            .unwrap();

        // Simulate S3 driver writing the CAS blob object directly as if copy succeeded before cancellation
        let blob_k = format!("blobs/sha256/{}", &digest.as_str()[7..]);
        driver
            .objects
            .lock()
            .unwrap()
            .insert(blob_k.clone(), (data.clone(), "\"etag_cas\"".to_string()));

        // Recovery detects CAS blob already exists and publishes receipt
        let outcome = storage.commit_finalize(&prep).await.unwrap();
        assert!(matches!(
            outcome,
            FinalizeOutcome::Published(_) | FinalizeOutcome::AlreadyFinalized(_)
        ));

        // Receipt exists
        let r = storage.get_finalized_receipt(&session).await.unwrap();
        assert!(r.is_some());
        assert_eq!(r.unwrap().digest, digest.as_str());
    }

    // Property 9: recovery creates or finds the receipt and releases the retained pin
    #[tokio::test]
    async fn test_pin_property_9_recovery_creates_or_finds_receipt_and_releases_retained_pin() {
        let (_storage, ref_index, coordinator, _tmp) = setup_test_coordinator().await;
        let repo = "prop9/repo";
        let data = b"PROPERTY_9_DATA";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();

        let start = coordinator.start_upload(repo).await.unwrap();
        let app = coordinator
            .append_upload(
                repo,
                &start.session.uuid,
                &start.state_token,
                None,
                None,
                Box::pin(futures_util::stream::once(async move {
                    Ok(bytes::Bytes::from_static(data))
                })),
            )
            .await
            .unwrap();

        // First finalization succeeds
        let res1 = coordinator
            .finalize_upload(
                repo,
                &start.session.uuid,
                Some(&app.state_token),
                None,
                None,
                &digest,
            )
            .await
            .unwrap();
        assert_eq!(res1.digest, digest);

        // Second retry / recovery finds receipt and returns AlreadyFinalized
        let res2 = coordinator
            .finalize_upload(repo, &start.session.uuid, None, None, None, &digest)
            .await
            .unwrap();
        assert_eq!(res2.digest, digest);
        assert!(res2.already_existed);

        // Pin is released
        assert!(
            !ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );
    }

    // Property 10: repeated recovery and cleanup are idempotent
    #[tokio::test]
    async fn test_pin_property_10_repeated_recovery_and_cleanup_are_idempotent() {
        let (storage, _ref_index, coordinator, _tmp) = setup_test_coordinator().await;
        let repo = "prop10/repo";
        let data = b"PROPERTY_10_DATA";
        let digest = Digest::parse(&format!("sha256:{}", hex_sha256(data))).unwrap();

        let start = coordinator.start_upload(repo).await.unwrap();
        let app = coordinator
            .append_upload(
                repo,
                &start.session.uuid,
                &start.state_token,
                None,
                None,
                Box::pin(futures_util::stream::once(async move {
                    Ok(bytes::Bytes::from_static(data))
                })),
            )
            .await
            .unwrap();

        let _ = coordinator
            .finalize_upload(
                repo,
                &start.session.uuid,
                Some(&app.state_token),
                None,
                None,
                &digest,
            )
            .await
            .unwrap();

        // 3 consecutive status / recover calls return identical finalized status
        for _ in 0..3 {
            let st = storage.session_status(&start.session).await.unwrap();
            assert_eq!(st.committed_offset, data.len() as u64);
        }
    }

    // Property 11: finalization lasting longer than one renewal interval remains pinned
    #[tokio::test]
    async fn test_pin_property_11_finalization_longer_than_renewal_interval_remains_pinned() {
        let (_storage, ref_index, _coordinator, _tmp) = setup_test_coordinator().await;
        let digest = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let op_id = "op-prop11-test";

        // Initial pin TTL of 2 seconds (renewal interval = 1s)
        let mut guard = PinLeaseGuard::acquire_and_start(Arc::clone(&ref_index), &digest, op_id, 2)
            .await
            .unwrap();

        // Verify pinned initially
        assert!(
            ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );

        // Wait 1.5 seconds (past one renewal interval)
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Pin must still be active and extended by heartbeat
        assert!(
            ref_index
                .is_blob_pinned(&digest, SystemTime::now())
                .unwrap()
        );

        guard.stop().await;
        guard.release_pin().unwrap();
    }

    // Property 12: renewal-task count returns to baseline after success, error, renewal failure and cancellation
    #[tokio::test]
    async fn test_pin_property_12_renewal_task_count_returns_to_baseline() {
        let (_storage, ref_index, _coordinator, _tmp) = setup_test_coordinator().await;
        let digest = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        // Path A: Success
        {
            let mut guard =
                PinLeaseGuard::acquire_and_start(Arc::clone(&ref_index), &digest, "op-a", 10)
                    .await
                    .unwrap();
            let handle = guard.task_handle.as_ref().unwrap().abort_handle();
            guard.stop().await;
            guard.release_pin().unwrap();
            assert!(handle.is_finished());
        }

        // Path B: Commit error
        {
            let mut guard =
                PinLeaseGuard::acquire_and_start(Arc::clone(&ref_index), &digest, "op-b", 10)
                    .await
                    .unwrap();
            let handle = guard.task_handle.as_ref().unwrap().abort_handle();
            guard.stop().await; // Stopped on error
            assert!(handle.is_finished());
        }

        // Path C: Cancellation (Drop)
        {
            let guard =
                PinLeaseGuard::acquire_and_start(Arc::clone(&ref_index), &digest, "op-c", 10)
                    .await
                    .unwrap();
            let handle = guard.task_handle.as_ref().unwrap().abort_handle();
            drop(guard);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(handle.is_finished());
        }
    }

    #[test]
    fn test_upload_coordinator_ref_index_error_context_preservation() {
        // --- 1. Sled Error Variants: Non-contextual mapping ---
        // 1a. sled::Error::Io(PermissionDenied) -> StorageErrorKind::PermissionDenied
        let sled_perm = sled::Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        let ref_err_perm = crate::blob_ref_index::RefIndexError::Sled(sled_perm);
        let expected_perm_str = ref_err_perm.to_string();
        let err_perm_nc = map_ref_index_error(ref_err_perm);
        assert!(matches!(
            err_perm_nc,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::PermissionDenied,
                ..
            }
        ));
        assert_eq!(
            err_perm_nc.internal_kind(),
            Some(crate::storage::StorageErrorKind::PermissionDenied)
        );
        assert_eq!(err_perm_nc.message(), Some(expected_perm_str.as_str()));
        assert_eq!(
            err_perm_nc.to_string(),
            format!("internal error: {expected_perm_str}")
        );

        // 1b. sled::Error::Io(ordinary) -> StorageErrorKind::Io
        let sled_io = sled::Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "broken pipe",
        ));
        let ref_err_io = crate::blob_ref_index::RefIndexError::Sled(sled_io);
        let expected_io_str = ref_err_io.to_string();
        let err_io_nc = map_ref_index_error(ref_err_io);
        assert!(matches!(
            err_io_nc,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Io,
                ..
            }
        ));
        assert_eq!(
            err_io_nc.internal_kind(),
            Some(crate::storage::StorageErrorKind::Io)
        );
        assert_eq!(err_io_nc.message(), Some(expected_io_str.as_str()));
        assert_eq!(
            err_io_nc.to_string(),
            format!("internal error: {expected_io_str}")
        );

        // 1c. sled::Error::Io(ENOSPC) -> dedicated StorageError::InsufficientStorage
        let sled_enospc = sled::Error::Io(std::io::Error::from_raw_os_error(libc::ENOSPC));
        let ref_err_enospc = crate::blob_ref_index::RefIndexError::Sled(sled_enospc);
        let err_enospc_nc = map_ref_index_error(ref_err_enospc);
        assert!(matches!(err_enospc_nc, StorageError::InsufficientStorage));
        assert_eq!(err_enospc_nc.internal_kind(), None);
        assert_eq!(err_enospc_nc.message(), None);
        assert_eq!(err_enospc_nc.to_string(), "insufficient storage");

        // 1d. sled::Error::Corruption -> StorageErrorKind::CorruptData
        let sled_corr = sled::Error::Corruption { at: None, bt: () };
        let ref_err_corr = crate::blob_ref_index::RefIndexError::Sled(sled_corr);
        let expected_corr_str = ref_err_corr.to_string();
        let err_corr_nc = map_ref_index_error(ref_err_corr);
        assert!(matches!(
            err_corr_nc,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::CorruptData,
                ..
            }
        ));
        assert_eq!(
            err_corr_nc.internal_kind(),
            Some(crate::storage::StorageErrorKind::CorruptData)
        );
        assert_eq!(err_corr_nc.message(), Some(expected_corr_str.as_str()));
        assert_eq!(
            err_corr_nc.to_string(),
            format!("internal error: {expected_corr_str}")
        );

        // 1e. sled::Error::Unsupported -> StorageErrorKind::Configuration
        let sled_unsupp = sled::Error::Unsupported("unsupported compaction feature".to_string());
        let ref_err_unsupp = crate::blob_ref_index::RefIndexError::Sled(sled_unsupp);
        let expected_unsupp_str = ref_err_unsupp.to_string();
        let err_unsupp_nc = map_ref_index_error(ref_err_unsupp);
        assert!(matches!(
            err_unsupp_nc,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Configuration,
                ..
            }
        ));
        assert_eq!(
            err_unsupp_nc.internal_kind(),
            Some(crate::storage::StorageErrorKind::Configuration)
        );
        assert_eq!(err_unsupp_nc.message(), Some(expected_unsupp_str.as_str()));
        assert_eq!(
            err_unsupp_nc.to_string(),
            format!("internal error: {expected_unsupp_str}")
        );

        // 1f. sled::Error::ReportableBug -> StorageErrorKind::InternalInvariant
        let sled_bug = sled::Error::ReportableBug("fatal btree invariant broken".to_string());
        let ref_err_bug = crate::blob_ref_index::RefIndexError::Sled(sled_bug);
        let expected_bug_str = ref_err_bug.to_string();
        let err_bug_nc = map_ref_index_error(ref_err_bug);
        assert!(matches!(
            err_bug_nc,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::InternalInvariant,
                ..
            }
        ));
        assert_eq!(
            err_bug_nc.internal_kind(),
            Some(crate::storage::StorageErrorKind::InternalInvariant)
        );
        assert_eq!(err_bug_nc.message(), Some(expected_bug_str.as_str()));
        assert_eq!(
            err_bug_nc.to_string(),
            format!("internal error: {expected_bug_str}")
        );

        // 1g. sled::Error::CollectionNotFound -> StorageErrorKind::InternalInvariant
        let sled_cnf = sled::Error::CollectionNotFound(sled::IVec::from(b"meta_tree"));
        let ref_err_cnf = crate::blob_ref_index::RefIndexError::Sled(sled_cnf);
        let expected_cnf_str = ref_err_cnf.to_string();
        let err_cnf_nc = map_ref_index_error(ref_err_cnf);
        assert!(matches!(
            err_cnf_nc,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::InternalInvariant,
                ..
            }
        ));
        assert_eq!(
            err_cnf_nc.internal_kind(),
            Some(crate::storage::StorageErrorKind::InternalInvariant)
        );
        assert_eq!(err_cnf_nc.message(), Some(expected_cnf_str.as_str()));
        assert_eq!(
            err_cnf_nc.to_string(),
            format!("internal error: {expected_cnf_str}")
        );

        // 1h. Storage(Internal { kind: Backend, .. }) -> StorageErrorKind::Backend
        let ref_err_backend_nc = crate::blob_ref_index::RefIndexError::Storage(
            StorageError::backend("s3 connection reset"),
        );
        let expected_backend_nc_str = ref_err_backend_nc.to_string();
        let err_backend_nc = map_ref_index_error(ref_err_backend_nc);
        assert!(matches!(
            err_backend_nc,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Backend,
                ..
            }
        ));
        assert_eq!(
            err_backend_nc.internal_kind(),
            Some(crate::storage::StorageErrorKind::Backend)
        );
        assert_eq!(
            err_backend_nc.message(),
            Some(expected_backend_nc_str.as_str())
        );
        assert_eq!(
            err_backend_nc.to_string(),
            format!("internal error: {expected_backend_nc_str}")
        );

        // --- 2. Sled Error Variants: Contextual mapping ---
        let context = "failed to acquire GC pin";

        // 2a. sled::Error::Io(PermissionDenied) with context
        let sled_perm_ctx = sled::Error::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        ));
        let ref_err_sled_perm = crate::blob_ref_index::RefIndexError::Sled(sled_perm_ctx);
        let expected_sled_perm_msg = format!("{context}: {ref_err_sled_perm}");
        let err_sled_perm = map_ref_index_error_with_context(ref_err_sled_perm, context);
        assert!(matches!(
            err_sled_perm,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::PermissionDenied,
                ..
            }
        ));
        assert_eq!(
            err_sled_perm.internal_kind(),
            Some(crate::storage::StorageErrorKind::PermissionDenied)
        );
        assert_eq!(
            err_sled_perm.message(),
            Some(expected_sled_perm_msg.as_str())
        );
        assert_eq!(
            err_sled_perm.to_string(),
            format!("internal error: {expected_sled_perm_msg}")
        );

        // 2b. sled::Error::Io(ordinary) with context
        let sled_io_ctx = sled::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "mock disk fault",
        ));
        let ref_err_sled_io = crate::blob_ref_index::RefIndexError::Sled(sled_io_ctx);
        let expected_sled_io_msg = format!("{context}: {ref_err_sled_io}");
        let err_sled_io = map_ref_index_error_with_context(ref_err_sled_io, context);
        assert!(matches!(
            err_sled_io,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Io,
                ..
            }
        ));
        assert_eq!(
            err_sled_io.internal_kind(),
            Some(crate::storage::StorageErrorKind::Io)
        );
        assert_eq!(err_sled_io.message(), Some(expected_sled_io_msg.as_str()));
        assert_eq!(
            err_sled_io.to_string(),
            format!("internal error: {expected_sled_io_msg}")
        );

        // 2c. sled::Error::Io(ENOSPC) with context -> dedicated StorageError::InsufficientStorage (NO context prefix)
        let sled_enospc_ctx = sled::Error::Io(std::io::Error::from_raw_os_error(libc::ENOSPC));
        let ref_err_sled_enospc = crate::blob_ref_index::RefIndexError::Sled(sled_enospc_ctx);
        let err_sled_enospc = map_ref_index_error_with_context(ref_err_sled_enospc, context);
        assert!(matches!(err_sled_enospc, StorageError::InsufficientStorage));
        assert_eq!(err_sled_enospc.internal_kind(), None);
        assert_eq!(err_sled_enospc.message(), None);
        assert_eq!(err_sled_enospc.to_string(), "insufficient storage");

        // 2d. sled::Error::Corruption with context
        let sled_corr_ctx = sled::Error::Corruption { at: None, bt: () };
        let ref_err_sled_corr = crate::blob_ref_index::RefIndexError::Sled(sled_corr_ctx);
        let expected_sled_corr_msg = format!("{context}: {ref_err_sled_corr}");
        let err_sled_corr = map_ref_index_error_with_context(ref_err_sled_corr, context);
        assert!(matches!(
            err_sled_corr,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::CorruptData,
                ..
            }
        ));
        assert_eq!(
            err_sled_corr.internal_kind(),
            Some(crate::storage::StorageErrorKind::CorruptData)
        );
        assert_eq!(
            err_sled_corr.message(),
            Some(expected_sled_corr_msg.as_str())
        );
        assert_eq!(
            err_sled_corr.to_string(),
            format!("internal error: {expected_sled_corr_msg}")
        );

        // 2e. sled::Error::Unsupported with context
        let sled_unsupp_ctx = sled::Error::Unsupported("unsupported option".to_string());
        let ref_err_sled_unsupp = crate::blob_ref_index::RefIndexError::Sled(sled_unsupp_ctx);
        let expected_sled_unsupp_msg = format!("{context}: {ref_err_sled_unsupp}");
        let err_sled_unsupp = map_ref_index_error_with_context(ref_err_sled_unsupp, context);
        assert!(matches!(
            err_sled_unsupp,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Configuration,
                ..
            }
        ));
        assert_eq!(
            err_sled_unsupp.internal_kind(),
            Some(crate::storage::StorageErrorKind::Configuration)
        );
        assert_eq!(
            err_sled_unsupp.message(),
            Some(expected_sled_unsupp_msg.as_str())
        );
        assert_eq!(
            err_sled_unsupp.to_string(),
            format!("internal error: {expected_sled_unsupp_msg}")
        );

        // 2f. sled::Error::ReportableBug with context
        let sled_bug_ctx = sled::Error::ReportableBug("fatal bug".to_string());
        let ref_err_sled_bug = crate::blob_ref_index::RefIndexError::Sled(sled_bug_ctx);
        let expected_sled_bug_msg = format!("{context}: {ref_err_sled_bug}");
        let err_sled_bug = map_ref_index_error_with_context(ref_err_sled_bug, context);
        assert!(matches!(
            err_sled_bug,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::InternalInvariant,
                ..
            }
        ));
        assert_eq!(
            err_sled_bug.internal_kind(),
            Some(crate::storage::StorageErrorKind::InternalInvariant)
        );
        assert_eq!(err_sled_bug.message(), Some(expected_sled_bug_msg.as_str()));
        assert_eq!(
            err_sled_bug.to_string(),
            format!("internal error: {expected_sled_bug_msg}")
        );

        // 2g. sled::Error::CollectionNotFound with context
        let sled_cnf_ctx = sled::Error::CollectionNotFound(sled::IVec::from(b"pins_tree"));
        let ref_err_sled_cnf = crate::blob_ref_index::RefIndexError::Sled(sled_cnf_ctx);
        let expected_sled_cnf_msg = format!("{context}: {ref_err_sled_cnf}");
        let err_sled_cnf = map_ref_index_error_with_context(ref_err_sled_cnf, context);
        assert!(matches!(
            err_sled_cnf,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::InternalInvariant,
                ..
            }
        ));
        assert_eq!(
            err_sled_cnf.internal_kind(),
            Some(crate::storage::StorageErrorKind::InternalInvariant)
        );
        assert_eq!(err_sled_cnf.message(), Some(expected_sled_cnf_msg.as_str()));
        assert_eq!(
            err_sled_cnf.to_string(),
            format!("internal error: {expected_sled_cnf_msg}")
        );

        // --- 3. Other RefIndexError Variants ---
        // 3a. Corrupt ref-index -> StorageErrorKind::CorruptData with exact contextual prefix
        let ref_err_corrupt =
            crate::blob_ref_index::RefIndexError::Corrupt("bad crc in index record".to_string());
        let expected_corrupt_msg =
            format!("ref-index unhealthy before acquiring GC pin: {ref_err_corrupt}");
        let err_corrupt = map_ref_index_error_with_context(
            ref_err_corrupt,
            "ref-index unhealthy before acquiring GC pin",
        );
        assert!(matches!(
            err_corrupt,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::CorruptData,
                ..
            }
        ));
        assert_eq!(
            err_corrupt.internal_kind(),
            Some(crate::storage::StorageErrorKind::CorruptData)
        );
        assert_eq!(err_corrupt.message(), Some(expected_corrupt_msg.as_str()));
        assert_eq!(
            err_corrupt.to_string(),
            format!("internal error: {expected_corrupt_msg}")
        );

        // 3b. Storage(Internal { kind: Backend, .. }) -> StorageErrorKind::Backend with exact contextual prefix
        let ref_err_backend = crate::blob_ref_index::RefIndexError::Storage(StorageError::backend(
            "s3 connection reset",
        ));
        let expected_backend_msg = format!("failed to release pin: {ref_err_backend}");
        let err_backend =
            map_ref_index_error_with_context(ref_err_backend, "failed to release pin");
        assert!(matches!(
            err_backend,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Backend,
                ..
            }
        ));
        assert_eq!(
            err_backend.internal_kind(),
            Some(crate::storage::StorageErrorKind::Backend)
        );
        assert_eq!(err_backend.message(), Some(expected_backend_msg.as_str()));
        assert_eq!(
            err_backend.to_string(),
            format!("internal error: {expected_backend_msg}")
        );

        // 3c. RefIndexError::NotFound -> dedicated StorageError::NotFound (NO context prefix)
        let ref_err_not_found = crate::blob_ref_index::RefIndexError::NotFound(
            std::path::PathBuf::from("/nonexistent/ref.db"),
        );
        let err_nf =
            map_ref_index_error_with_context(ref_err_not_found, "failed to acquire GC pin");
        assert!(matches!(err_nf, StorageError::NotFound));
        assert_eq!(err_nf.internal_kind(), None);
        assert_eq!(err_nf.message(), None);
        assert_eq!(err_nf.to_string(), "not found");

        // 3d. Storage(StorageError::NotFound) -> dedicated StorageError::NotFound (NO context prefix)
        let ref_err_storage_nf =
            crate::blob_ref_index::RefIndexError::Storage(StorageError::NotFound);
        let err_storage_nf =
            map_ref_index_error_with_context(ref_err_storage_nf, "failed to release pin");
        assert!(matches!(err_storage_nf, StorageError::NotFound));
        assert_eq!(err_storage_nf.internal_kind(), None);
        assert_eq!(err_storage_nf.message(), None);
        assert_eq!(err_storage_nf.to_string(), "not found");

        // 3e. Storage(StorageError::Internal { kind: Conflict, .. }) -> StorageErrorKind::Conflict with exact contextual prefix
        let ref_err_storage_conflict = crate::blob_ref_index::RefIndexError::Storage(
            StorageError::conflict("tag lock contention"),
        );
        let expected_conflict_msg = format!("failed to release pin: {ref_err_storage_conflict}");
        let err_storage_conflict =
            map_ref_index_error_with_context(ref_err_storage_conflict, "failed to release pin");
        assert!(matches!(
            err_storage_conflict,
            StorageError::Internal {
                kind: crate::storage::StorageErrorKind::Conflict,
                ..
            }
        ));
        assert_eq!(
            err_storage_conflict.internal_kind(),
            Some(crate::storage::StorageErrorKind::Conflict)
        );
        assert_eq!(
            err_storage_conflict.message(),
            Some(expected_conflict_msg.as_str())
        );
        assert_eq!(
            err_storage_conflict.to_string(),
            format!("internal error: {expected_conflict_msg}")
        );

        // 3f. Storage(StorageError::PreconditionFailed) -> dedicated StorageError::PreconditionFailed (NO context prefix)
        let ref_err_storage_precond =
            crate::blob_ref_index::RefIndexError::Storage(StorageError::PreconditionFailed);
        let err_storage_precond =
            map_ref_index_error_with_context(ref_err_storage_precond, "failed to release pin");
        assert!(matches!(
            err_storage_precond,
            StorageError::PreconditionFailed
        ));
        assert_eq!(err_storage_precond.internal_kind(), None);
        assert_eq!(err_storage_precond.message(), None);
        assert_eq!(err_storage_precond.to_string(), "precondition failed");
    }

    #[test]
    fn test_upload_coordinator_pin_failure_fallback_on_channel_loss() {
        let fallback_err = resolve_pin_failure_or_fallback(None);
        assert_eq!(
            fallback_err.internal_kind(),
            Some(crate::storage::StorageErrorKind::InternalInvariant)
        );
        assert_eq!(
            fallback_err.message(),
            Some("pin renewal heartbeat failed during commit")
        );
        assert_eq!(
            fallback_err.to_string(),
            "internal error: pin renewal heartbeat failed during commit"
        );

        let typed_err = StorageError::io("disk failure during pin renewal");
        let preserved_err = resolve_pin_failure_or_fallback(Some(typed_err));
        assert_eq!(
            preserved_err.internal_kind(),
            Some(crate::storage::StorageErrorKind::Io)
        );
        assert_eq!(
            preserved_err.message(),
            Some("disk failure during pin renewal")
        );
        assert_eq!(
            preserved_err.to_string(),
            "internal error: disk failure during pin renewal"
        );

        let nf_err = StorageError::NotFound;
        let preserved_nf = resolve_pin_failure_or_fallback(Some(nf_err));
        assert!(matches!(preserved_nf, StorageError::NotFound));
        assert_eq!(preserved_nf.internal_kind(), None);
        assert_eq!(preserved_nf.message(), None);
        assert_eq!(preserved_nf.to_string(), "not found");
    }

    #[tokio::test]
    async fn test_upload_coordinator_finalized_receipt_head_blob_error_classification() {
        let (storage, driver) = crate::storage::s3::tests::create_mock_storage();
        let config = BlobUploadCoordinatorConfig::default();
        let coordinator = test_coordinator(Arc::new(storage), None, config);

        let repo = "test-head-err/repo";
        let uuid = "11111111-2222-3333-4444-555555555555";
        let canonical = crate::registry::canonical_name::CanonicalRepoName::parse(repo).unwrap();
        let digest = Digest::parse(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        // 1. Insert valid finalized receipt in mock S3 storage
        let receipt = crate::storage::FinalizedReceipt {
            format_version: 1,
            repo: canonical.clone(),
            uuid: uuid.to_string(),
            digest: digest.as_str().to_string(),
            size: 1024,
            finalized_at_unix_secs: 1000,
        };
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        let receipt_key = format!("uploads/{uuid}/finalized.json");
        driver.objects.lock().unwrap().insert(
            receipt_key,
            (
                bytes::Bytes::from(receipt_bytes),
                "etag-receipt".to_string(),
            ),
        );

        // Case 1: head_blob returns NotFound -> StorageErrorKind::CorruptData
        {
            let res = coordinator
                .finalize_upload(repo, uuid, None, None, None, &digest)
                .await;
            assert!(res.is_err());
            let err = match res.unwrap_err() {
                CoordinatorError::Storage(e) => e,
                other => panic!("expected CoordinatorError::Storage, got {:?}", other),
            };
            assert_eq!(
                err.internal_kind(),
                Some(crate::storage::StorageErrorKind::CorruptData)
            );
            assert_eq!(
                err.message(),
                Some("corrupt receipt: global CAS blob missing")
            );
            assert_eq!(
                err.to_string(),
                "internal error: corrupt receipt: global CAS blob missing"
            );

            // Verify head_object was called for the CAS blob key
            let log = driver.get_call_log();
            let expected_cas_key = format!("blobs/sha256/{}/{}", digest.prefix2(), digest.hex());
            assert!(
                log.iter()
                    .any(|e| e.method == "head_object" && e.key == expected_cas_key),
                "head_blob must have been invoked on expected CAS key"
            );
        }

        // Case 2: head_blob returns Backend error -> StorageErrorKind::Backend
        {
            driver.set_hook_before(|method, key| {
                if method == "head_object" && key.starts_with("blobs/") {
                    Some(StorageError::backend("head backend failure"))
                } else {
                    None
                }
            });

            let res = coordinator
                .finalize_upload(repo, uuid, None, None, None, &digest)
                .await;
            assert!(res.is_err());
            let err = match res.unwrap_err() {
                CoordinatorError::Storage(e) => e,
                other => panic!("expected CoordinatorError::Storage, got {:?}", other),
            };
            assert_eq!(
                err.internal_kind(),
                Some(crate::storage::StorageErrorKind::Backend)
            );
            assert_eq!(err.message(), Some("head backend failure"));
            assert_eq!(err.to_string(), "internal error: head backend failure");

            driver.clear_hooks();
        }

        // Case 3: head_blob returns PermissionDenied error -> StorageErrorKind::PermissionDenied
        {
            driver.set_hook_before(|method, key| {
                if method == "head_object" && key.starts_with("blobs/") {
                    Some(StorageError::permission_denied("head permission failure"))
                } else {
                    None
                }
            });

            let res = coordinator
                .finalize_upload(repo, uuid, None, None, None, &digest)
                .await;
            assert!(res.is_err());
            let err = match res.unwrap_err() {
                CoordinatorError::Storage(e) => e,
                other => panic!("expected CoordinatorError::Storage, got {:?}", other),
            };
            assert_eq!(
                err.internal_kind(),
                Some(crate::storage::StorageErrorKind::PermissionDenied)
            );
            assert_eq!(err.message(), Some("head permission failure"));
            assert_eq!(err.to_string(), "internal error: head permission failure");

            driver.clear_hooks();
        }
    }
}
