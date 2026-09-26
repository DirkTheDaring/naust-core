use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::storage::{ClusterLockStore, StorageError};

pub const DEPLOYMENT_LOCK_FORMAT_VERSION: u32 = 1;

/// Structured diagnosis and ownership record for a deployment writer lock.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeploymentWriterLockDoc {
    pub format_version: u32,
    pub owner_token: String,
    pub owner_id: String,
    pub hostname: String,
    pub pid: u32,
    pub command_mode: String,
    pub acquired_unix_secs: u64,
}

impl DeploymentWriterLockDoc {
    pub fn new(command_mode: &str) -> Self {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "unknown-host".to_string());
        let pid = std::process::id();
        let owner_token = format!("{}-{}-{}", Uuid::new_v4(), pid, Uuid::new_v4());
        let owner_id = format!("{hostname}:{pid}:{command_mode}");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            format_version: DEPLOYMENT_LOCK_FORMAT_VERSION,
            owner_token,
            owner_id,
            hostname,
            pid,
            command_mode: command_mode.to_string(),
            acquired_unix_secs: now,
        }
    }
}

/// A runtime-owned mutation authority.
///
/// Properties:
/// 1. Must be acquired BEFORE constructing AppState, HTTP routers, workers, or supervisors.
/// 2. Owned by the top-level supervisor for the duration of the process.
/// 3. Cannot be accidentally released by cloning or dropping storage backends.
/// 4. Released conditionally on graceful shutdown with owner-token / ETag match.
/// 5. Never released unconditionally.
pub struct RuntimeMutationAuthority {
    storage: Arc<dyn ClusterLockStore>,
    doc: DeploymentWriterLockDoc,
    etag: Option<String>,
    released: bool,
    #[cfg(test)]
    test_force_inactive: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for RuntimeMutationAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeMutationAuthority")
            .field("doc", &self.doc)
            .field("etag", &self.etag)
            .field("released", &self.released)
            .finish()
    }
}

impl RuntimeMutationAuthority {
    /// Attempts to acquire the exclusive deployment mutation authority.
    pub async fn acquire(
        storage: Arc<dyn ClusterLockStore>,
        command_mode: &str,
    ) -> Result<Self, StorageError> {
        let doc = DeploymentWriterLockDoc::new(command_mode);
        let (acquired, etag) = storage.acquire_deployment_writer_lock(&doc).await?;
        if !acquired {
            return Err(StorageError::ExclusiveWriterLocked(format!(
                "failed to acquire deployment writer lock for mode '{command_mode}'"
            )));
        }

        Ok(Self {
            storage,
            doc,
            etag,
            released: false,
            #[cfg(test)]
            test_force_inactive: std::sync::atomic::AtomicBool::new(false),
        })
    }

    #[allow(dead_code)]
    pub fn doc(&self) -> &DeploymentWriterLockDoc {
        &self.doc
    }

    #[allow(dead_code)]
    pub fn owner_token(&self) -> &str {
        &self.doc.owner_token
    }

    #[allow(dead_code)]
    pub fn is_active(&self) -> bool {
        #[cfg(test)]
        if self
            .test_force_inactive
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return false;
        }
        !self.released
    }

    /// Mints a sealed `GcMutationPermit` for mutating GC operations.
    pub fn gc_mutation_permit(&self) -> GcMutationPermit<'_> {
        assert!(
            self.is_active(),
            "cannot mint GC permit from released or inactive authority"
        );
        GcMutationPermit { _authority: self }
    }

    /// Explicitly releases the deployment mutation lock upon clean shutdown.
    pub async fn release(&mut self) -> Result<(), StorageError> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        self.storage
            .release_deployment_writer_lock(&self.doc, self.etag.as_deref())
            .await?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn set_test_inactive_guard(&self) -> TestInactiveGuard<'_> {
        self.test_force_inactive
            .store(true, std::sync::atomic::Ordering::SeqCst);
        TestInactiveGuard { authority: self }
    }
}

#[cfg(test)]
pub(super) struct TestInactiveGuard<'a> {
    authority: &'a RuntimeMutationAuthority,
}

#[cfg(test)]
impl<'a> Drop for TestInactiveGuard<'a> {
    fn drop(&mut self) {
        self.authority
            .test_force_inactive
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for RuntimeMutationAuthority {
    fn drop(&mut self) {
        if !self.released {
            tracing::warn!(
                owner = %self.doc.owner_id,
                mode = %self.doc.command_mode,
                "RuntimeMutationAuthority dropped without explicit graceful release. Lock remains intact on storage."
            );
        }
    }
}

/// Administrative function to inspect the stored deployment writer lock metadata without acquiring or mutating it.
pub async fn inspect_deployment_writer_lock(
    storage: &(impl ClusterLockStore + ?Sized),
) -> Result<Option<(DeploymentWriterLockDoc, Option<String>)>, StorageError> {
    storage.inspect_deployment_writer_lock().await
}

/// Administrative function to conditionally clear an abandoned deployment lock.
///
/// SAFETY & OPERATOR CONTRACT:
/// 1. The human operator MUST establish out-of-band that the previous writer process is dead
///    and cannot resume execution or issue network writes.
/// 2. Requires the exact expected owner ID/token and the observed object version / ETag obtained
///    from `inspect_deployment_writer_lock`.
/// 3. Performs a conditional deletion (`If-Match: <expected_etag>`). If the lock was replaced,
///    modified, or acquired by a new writer concurrently, the operation fails closed with
///    `PreconditionFailed` and the newer lock survives intact.
pub async fn admin_clear_abandoned_deployment_writer_lock(
    storage: &(impl ClusterLockStore + ?Sized),
    expected_owner: &str,
    expected_etag: &str,
    confirmation: &str,
) -> Result<(), StorageError> {
    if confirmation != "CONFIRM-CLEAR-ABANDONED-WRITER" {
        return Err(StorageError::permission_denied(
            "destructive lock clearing requires exact confirmation token: 'CONFIRM-CLEAR-ABANDONED-WRITER'",
        ));
    }

    storage
        .admin_clear_deployment_writer_lock(expected_owner, expected_etag)
        .await
}

/// Deprecated / convenience alias forwarding to administrative clear with verification.
pub async fn force_unlock_deployment_writer(
    storage: &(impl ClusterLockStore + ?Sized),
    confirmation_token: &str,
) -> Result<(), StorageError> {
    let inspect = storage.inspect_deployment_writer_lock().await?;
    let (doc, etag) = match inspect {
        Some((d, Some(t))) => (d, t),
        Some((d, None)) => (d, "".to_string()),
        None => return Ok(()),
    };

    if confirmation_token != "FORCE"
        && confirmation_token != doc.owner_token
        && confirmation_token != doc.owner_id
    {
        return Err(StorageError::permission_denied(format!(
            "confirmation token '{confirmation_token}' did not match lock owner '{}'",
            doc.owner_id
        )));
    }

    storage
        .admin_clear_deployment_writer_lock(&doc.owner_id, &etag)
        .await
}

/// A sealed, non-forgeable permit required for mutating Garbage Collection operations
/// (quarantine, deletion, and candidate unlinking sweeps).
///
/// This permit can ONLY be minted by a live holder of `RuntimeMutationAuthority`
/// and statically cannot outlive the authority reference.
#[derive(Debug)]
pub struct GcMutationPermit<'a> {
    _authority: &'a RuntimeMutationAuthority,
}

impl<'a> GcMutationPermit<'a> {
    pub fn owner_id(&self) -> &str {
        &self._authority.doc.owner_id
    }

    pub fn is_valid(&self) -> bool {
        self._authority.is_active()
    }
}
