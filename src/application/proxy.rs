use crate::storage::ports::ProxyStoragePort;
use std::sync::Arc;

/// Transport-neutral target pointing to an upstream proxy and its cache storage.
#[derive(Clone)]
pub struct ProxyTarget {
    pub proxy: Arc<dyn crate::upstream::UpstreamFetcher>,
    pub cache_storage: Arc<dyn ProxyStoragePort>,
}

impl ProxyTarget {
    pub fn new(
        proxy: Arc<dyn crate::upstream::UpstreamFetcher>,
        cache_storage: Arc<dyn ProxyStoragePort>,
    ) -> Self {
        Self {
            proxy,
            cache_storage,
        }
    }
}
