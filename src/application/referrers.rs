use super::errors::ReferrersQueryError;
use super::proxy::ProxyTarget;
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::ReferrerDescriptor;
use crate::storage::ports::ReferrersReader;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct ReferrersQueryParams {
    pub artifact_type: Option<String>,
    pub last: Option<String>,
    pub n: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferrersPage {
    pub descriptors: Vec<ReferrerDescriptor>,
    pub has_more: bool,
    pub next_last: Option<String>,
}

pub struct ReferrersQueryService {
    referrers_reader: Arc<dyn ReferrersReader>,
}

impl ReferrersQueryService {
    pub fn new(referrers_reader: Arc<dyn ReferrersReader>) -> Self {
        Self { referrers_reader }
    }

    pub fn referrers_reader(&self) -> &Arc<dyn ReferrersReader> {
        &self.referrers_reader
    }

    pub async fn query_referrers(
        &self,
        repo: &str,
        subject: &Digest,
        params: ReferrersQueryParams,
        proxy_target: Option<&ProxyTarget>,
    ) -> Result<ReferrersPage, ReferrersQueryError> {
        CanonicalRepoName::parse(repo).map_err(|source| ReferrersQueryError::InvalidRepoName {
            name: repo.to_string(),
            source,
        })?;

        let reader: &dyn ReferrersReader = proxy_target
            .map(|t| t.cache_storage.as_referrers_reader())
            .unwrap_or(self.referrers_reader.as_ref());
        let mut entries = match reader.list_referrers(repo, subject).await {
            Ok(v) => v,
            Err(crate::storage::StorageError::NotFound) => Vec::new(),
            Err(e) => return Err(ReferrersQueryError::Storage(e)),
        };

        if let Some(ref filter) = params.artifact_type {
            entries.retain(|d| d.artifact_type.as_deref() == Some(filter.as_str()));
        }

        // Sort deterministically by digest for stable pagination.
        entries.sort_by(|a, b| a.digest.cmp(&b.digest));

        let start_idx = if let Some(ref last) = params.last {
            match entries.iter().position(|d| d.digest == *last) {
                Some(pos) => pos + 1,
                None => 0,
            }
        } else {
            0
        };

        let remaining = if start_idx < entries.len() {
            &entries[start_idx..]
        } else {
            &[]
        };

        let (descriptors, next_last, has_more) = match params.n {
            Some(0) => (Vec::new(), None, !remaining.is_empty()),
            Some(n) if n < remaining.len() => (
                remaining[..n].to_vec(),
                remaining.get(n.saturating_sub(1)).map(|d| d.digest.clone()),
                true,
            ),
            _ => (remaining.to_vec(), None, false),
        };

        Ok(ReferrersPage {
            descriptors,
            has_more,
            next_last,
        })
    }
}
