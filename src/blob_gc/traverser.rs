use crate::storage;
use std::collections::HashSet;

#[derive(Debug, thiserror::Error)]
pub enum GcPaginationError {
    #[error("storage error during CAS listing: {0}")]
    Storage(#[from] storage::StorageError),

    #[error("pagination repeated cursor detected: {0}")]
    RepeatedCursor(String),

    #[error("pagination cursor cycle detected: {0}")]
    CursorCycle(String),

    #[error("gc error: {0}")]
    Other(String),
}

/// Centralized pagination traversal over CAS objects.
///
/// Invariants enforced:
/// - If `page.items` is empty but `next_cursor` is `Some(...)`, traversal continues.
/// - `next_cursor = None` terminates traversal.
/// - If `next_cursor` equals the current cursor, fails immediately with `RepeatedCursor`.
/// - If `next_cursor` was previously observed in this traversal, fails immediately with `CursorCycle`.
/// - Failures fail closed and bubble up typed contextual errors.
pub struct CasBlobTraverser<'a> {
    storage: &'a dyn storage::GcStoragePort,
    page_limit: usize,
    cursor: Option<storage::GcCursor>,
    seen_cursors: HashSet<String>,
    done: bool,
}

impl<'a> CasBlobTraverser<'a> {
    pub fn new(storage: &'a (impl storage::GcStoragePort + 'a), page_limit: usize) -> Self {
        Self {
            storage,
            page_limit,
            cursor: None,
            seen_cursors: HashSet::new(),
            done: false,
        }
    }

    /// Fetches the next non-empty batch of CAS blob candidates, or None when CAS enumeration is exhausted.
    pub async fn next_batch(
        &mut self,
    ) -> Result<Option<Vec<storage::GcBlobCandidate>>, GcPaginationError> {
        if self.done {
            return Ok(None);
        }

        loop {
            let page = self
                .storage
                .list_cas_blobs_page(self.cursor.as_ref(), self.page_limit)
                .await?;

            let next_cursor = page.next_cursor;
            if let Some(ref next) = next_cursor {
                if let Some(ref curr) = self.cursor {
                    if next.0 == curr.0 {
                        self.done = true;
                        return Err(GcPaginationError::RepeatedCursor(next.0.clone()));
                    }
                }
                if !self.seen_cursors.insert(next.0.clone()) {
                    self.done = true;
                    return Err(GcPaginationError::CursorCycle(next.0.clone()));
                }
            } else {
                self.done = true;
            }

            self.cursor = next_cursor;

            if !page.items.is_empty() {
                return Ok(Some(page.items));
            }

            if self.done {
                return Ok(None);
            }
        }
    }
}
