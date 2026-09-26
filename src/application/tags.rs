use super::errors::TagQueryError;
use super::proxy::ProxyTarget;
use crate::registry::canonical_name::CanonicalRepoName;
use crate::storage::ports::TagReader;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct TagQueryParams {
    pub n: Option<usize>,
    pub last: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagListPage {
    pub repo: String,
    pub tags: Vec<String>,
    pub total: usize,
    pub has_more: bool,
    pub next_last: Option<String>,
}

pub struct TagQueryService {
    tag_reader: Arc<dyn TagReader>,
}

impl TagQueryService {
    pub fn new(tag_reader: Arc<dyn TagReader>) -> Self {
        Self { tag_reader }
    }

    pub fn tag_reader(&self) -> &Arc<dyn TagReader> {
        &self.tag_reader
    }

    pub async fn query_tags(
        &self,
        repo: &str,
        params: TagQueryParams,
        proxy_target: Option<&ProxyTarget>,
    ) -> Result<TagListPage, TagQueryError> {
        CanonicalRepoName::parse(repo).map_err(|source| TagQueryError::InvalidRepoName {
            name: repo.to_string(),
            source,
        })?;

        let reader: &dyn TagReader = proxy_target
            .map(|t| t.cache_storage.as_tag_reader())
            .unwrap_or(self.tag_reader.as_ref());
        let mut all_tags = reader.list_tags(repo).await.map_err(|e| match e {
            crate::storage::StorageError::NotFound => TagQueryError::NotFound,
            other => TagQueryError::Storage(other),
        })?;
        all_tags.sort();
        let total = all_tags.len();

        let n = params.n.unwrap_or(usize::MAX);
        let start_idx = match params.last.as_deref() {
            Some(last) => all_tags
                .iter()
                .position(|t| t.as_str() > last)
                .unwrap_or(all_tags.len()),
            None => 0,
        };

        let end_idx = start_idx.saturating_add(n).min(total);
        let tags: Vec<String> = all_tags
            .into_iter()
            .skip(start_idx)
            .take(end_idx.saturating_sub(start_idx))
            .collect();

        let has_more = params.n.is_some() && !tags.is_empty() && tags.len() == n && end_idx < total;
        let next_last = if has_more { tags.last().cloned() } else { None };

        Ok(TagListPage {
            repo: repo.to_string(),
            tags,
            total,
            has_more,
            next_last,
        })
    }

    pub async fn list_tags(
        &self,
        repo: &str,
        proxy_target: Option<&ProxyTarget>,
    ) -> Result<Vec<String>, TagQueryError> {
        CanonicalRepoName::parse(repo).map_err(|source| TagQueryError::InvalidRepoName {
            name: repo.to_string(),
            source,
        })?;

        let reader: &dyn TagReader = proxy_target
            .map(|t| t.cache_storage.as_tag_reader())
            .unwrap_or(self.tag_reader.as_ref());
        reader.list_tags(repo).await.map_err(|e| match e {
            crate::storage::StorageError::NotFound => TagQueryError::NotFound,
            other => TagQueryError::Storage(other),
        })
    }

    pub async fn resolve_tag(
        &self,
        repo: &str,
        tag: &str,
        proxy_target: Option<&ProxyTarget>,
    ) -> Result<crate::registry::digest::Digest, TagQueryError> {
        CanonicalRepoName::parse(repo).map_err(|source| TagQueryError::InvalidRepoName {
            name: repo.to_string(),
            source,
        })?;

        let reader: &dyn TagReader = proxy_target
            .map(|t| t.cache_storage.as_tag_reader())
            .unwrap_or(self.tag_reader.as_ref());
        reader.resolve_tag(repo, tag).await.map_err(|e| match e {
            crate::storage::StorageError::NotFound => TagQueryError::NotFound,
            other => TagQueryError::Storage(other),
        })
    }
}
