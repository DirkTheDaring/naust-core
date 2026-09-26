use super::errors::CatalogQueryError;
use super::proxy::ProxyTarget;
use crate::storage::ports::{BlobCasReader, ManifestReader, RepositoryCatalogReader, TagReader};
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct CatalogQueryParams {
    pub n: Option<usize>,
    pub last: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogPage {
    pub repositories: Vec<String>,
    pub total: usize,
    pub has_more: bool,
    pub next_last: Option<String>,
}

fn platform_triplet(os: &str, arch: &str, variant: Option<&str>) -> String {
    match variant {
        Some(v) => format!("{os}/{arch}/{v}"),
        None => format!("{os}/{arch}"),
    }
}

pub struct CatalogQueryService {
    catalog_reader: Arc<dyn RepositoryCatalogReader>,
    tag_reader: Arc<dyn TagReader>,
    manifest_reader: Arc<dyn ManifestReader>,
    blob_reader: Arc<dyn BlobCasReader>,
}

impl CatalogQueryService {
    pub fn new(
        catalog_reader: Arc<dyn RepositoryCatalogReader>,
        tag_reader: Arc<dyn TagReader>,
        manifest_reader: Arc<dyn ManifestReader>,
        blob_reader: Arc<dyn BlobCasReader>,
    ) -> Self {
        Self {
            catalog_reader,
            tag_reader,
            manifest_reader,
            blob_reader,
        }
    }

    pub fn catalog_reader(&self) -> &Arc<dyn RepositoryCatalogReader> {
        &self.catalog_reader
    }

    pub fn tag_reader(&self) -> &Arc<dyn TagReader> {
        &self.tag_reader
    }

    pub fn manifest_reader(&self) -> &Arc<dyn ManifestReader> {
        &self.manifest_reader
    }

    pub fn blob_reader(&self) -> &Arc<dyn BlobCasReader> {
        &self.blob_reader
    }

    pub async fn query_catalog(
        &self,
        params: CatalogQueryParams,
        proxy_target: Option<&ProxyTarget>,
    ) -> Result<CatalogPage, CatalogQueryError> {
        let reader: &dyn RepositoryCatalogReader = proxy_target
            .map(|t| t.cache_storage.as_catalog_reader())
            .unwrap_or(self.catalog_reader.as_ref());
        let mut all = reader
            .list_repositories()
            .await
            .map_err(CatalogQueryError::Storage)?;
        all.sort();
        let total = all.len();

        let n = params.n.unwrap_or(usize::MAX);
        let start_idx = match params.last.as_deref() {
            Some(last) => all
                .iter()
                .position(|t| t.as_str() > last)
                .unwrap_or(all.len()),
            None => 0,
        };

        let end_idx = start_idx.saturating_add(n).min(total);
        let repositories: Vec<String> = all
            .into_iter()
            .skip(start_idx)
            .take(end_idx.saturating_sub(start_idx))
            .collect();

        let has_more = params.n.is_some()
            && !repositories.is_empty()
            && repositories.len() == n
            && end_idx < total;
        let next_last = if has_more {
            repositories.last().cloned()
        } else {
            None
        };

        Ok(CatalogPage {
            repositories,
            total,
            has_more,
            next_last,
        })
    }

    pub async fn list_repositories(
        &self,
        proxy_target: Option<&ProxyTarget>,
    ) -> Result<Vec<String>, CatalogQueryError> {
        let reader: &dyn RepositoryCatalogReader = proxy_target
            .map(|t| t.cache_storage.as_catalog_reader())
            .unwrap_or(self.catalog_reader.as_ref());
        reader
            .list_repositories()
            .await
            .map_err(CatalogQueryError::Storage)
    }

    pub async fn repo_timestamps(
        &self,
        repo: &str,
        proxy_target: Option<&ProxyTarget>,
    ) -> Result<crate::storage::RepoTimestamps, CatalogQueryError> {
        let reader: &dyn RepositoryCatalogReader = proxy_target
            .map(|t| t.cache_storage.as_catalog_reader())
            .unwrap_or(self.catalog_reader.as_ref());
        reader
            .repo_timestamps(repo)
            .await
            .map_err(CatalogQueryError::Storage)
    }

    pub async fn tag_platforms_for_repo(
        &self,
        repo: &str,
        tag: &str,
        proxy_target: Option<&ProxyTarget>,
    ) -> Result<serde_json::Value, CatalogQueryError> {
        let tag_reader: &dyn TagReader = proxy_target
            .map(|t| t.cache_storage.as_tag_reader())
            .unwrap_or(self.tag_reader.as_ref());
        let manifest_reader: &dyn ManifestReader = proxy_target
            .map(|t| t.cache_storage.as_manifest_reader())
            .unwrap_or(self.manifest_reader.as_ref());
        let blob_reader: &dyn BlobCasReader = proxy_target
            .map(|t| t.cache_storage.as_blob_reader())
            .unwrap_or(self.blob_reader.as_ref());

        let digest = tag_reader
            .resolve_tag(repo, tag)
            .await
            .map_err(CatalogQueryError::Storage)?;
        let (meta, bytes) = manifest_reader
            .get_manifest(repo, &digest)
            .await
            .map_err(CatalogQueryError::Storage)?;

        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

        let mut platforms: std::collections::HashSet<String> = std::collections::HashSet::new();
        let kind: &str;

        if let Some(manifests) = v.get("manifests").and_then(|m| m.as_array()) {
            kind = "index";
            for m in manifests {
                let p = m.get("platform");
                let Some(os) = p.and_then(|p| p.get("os")).and_then(|x| x.as_str()) else {
                    continue;
                };
                let Some(arch) = p
                    .and_then(|p| p.get("architecture"))
                    .and_then(|x| x.as_str())
                else {
                    continue;
                };
                let variant = p.and_then(|p| p.get("variant")).and_then(|x| x.as_str());
                platforms.insert(platform_triplet(os, arch, variant));
            }
        } else {
            kind = "manifest";
            if let Some(cfg_digest) = v
                .get("config")
                .and_then(|c| c.get("digest"))
                .and_then(|d| d.as_str())
            {
                if let Ok(cfg_d) = crate::registry::digest::Digest::parse(cfg_digest) {
                    if let Ok((b_meta, mut reader)) = blob_reader.open_blob(&cfg_d).await {
                        if (b_meta.size as usize) <= 1024 * 1024 {
                            use tokio::io::AsyncReadExt;
                            let mut buf = Vec::with_capacity(b_meta.size as usize);
                            let mut chunk = [0u8; 8192];
                            while buf.len() <= 1024 * 1024 {
                                let n = reader.read(&mut chunk).await.unwrap_or(0);
                                if n == 0 {
                                    break;
                                }
                                buf.extend_from_slice(&chunk[..n]);
                            }
                            if let Ok(cfg) = serde_json::from_slice::<serde_json::Value>(&buf) {
                                if let (Some(os), Some(arch)) = (
                                    cfg.get("os").and_then(|x| x.as_str()),
                                    cfg.get("architecture").and_then(|x| x.as_str()),
                                ) {
                                    let variant = cfg.get("variant").and_then(|x| x.as_str());
                                    platforms.insert(platform_triplet(os, arch, variant));
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut platforms: Vec<String> = platforms.into_iter().collect();
        platforms.sort();

        Ok(serde_json::json!({
            "tag": tag,
            "digest": digest.as_str(),
            "media_type": meta.media_type,
            "kind": kind,
            "platforms": platforms,
        }))
    }
}
