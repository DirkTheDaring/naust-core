//! Registry-owned in-tree compatibility facade for storage operations.
//!
//! In Slice 1, this provides a minimal crate-private wiring seam around `StorageWiring`.

use std::sync::Arc;

use crate::storage::ports::{BlobCasReader, StorageWiring};

/// Crate-private compatibility facade wrapping `StorageWiring`.
#[derive(Clone)]
pub struct StorageWiringFacade {
    wiring: StorageWiring,
}

impl StorageWiringFacade {
    pub fn new(wiring: StorageWiring) -> Self {
        Self { wiring }
    }

    pub fn blob_reader(&self) -> Arc<dyn BlobCasReader> {
        self.wiring.blob_reader()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::digest::Digest;
    use crate::storage::fs::FsStorage;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_storage_wiring_facade_delegation() {
        let temp = TempDir::new().unwrap();
        let fs_root = temp.path().join("root");
        std::fs::create_dir_all(&fs_root).unwrap();

        let backend = Arc::new(FsStorage::new(fs_root, 10 * 1024 * 1024));
        let wiring = StorageWiring::from_backend(backend);
        let facade = StorageWiringFacade::new(wiring);

        let reader = facade.blob_reader();
        let digest = Digest::parse(
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        .unwrap();
        assert!(matches!(
            reader.head_blob(&digest).await,
            Err(crate::storage::StorageError::NotFound)
        ));
    }
}
