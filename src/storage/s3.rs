use super::upload_session::*;
use super::{
    BlobMeta, BlobObjectVersion, ConditionalDeleteResult, GcBlobCandidate, GcBlobPage, GcCursor,
    GcDeleteResult, GcQuarantineResult, GcStorage, GcStorageStrategy, ManifestMeta,
    ReferrerDescriptor, RepoTimestamps, Storage, StorageError, UploadMeta,
};
use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::repo_membership::RepositoryBlobMembershipStorage;
use async_trait::async_trait;
use aws_config::Region;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::BehaviorVersion;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use base64::Engine as _;
use bytes::Bytes;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncRead;
use tokio::sync::OnceCell;

#[derive(Debug, Clone)]
pub struct S3ObjectSummary {
    pub key: String,
    pub size: u64,
    pub last_modified_unix_secs: u64,
    pub e_tag: Option<String>,
}

#[derive(Debug, Clone)]
pub struct S3ObjectsPage {
    pub objects: Vec<S3ObjectSummary>,
    pub next_continuation_token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct S3MultipartUploadSummary {
    pub key: String,
    pub upload_id: String,
    pub initiated_at_unix_secs: u64,
}

#[derive(Debug, Clone, Default)]
pub struct S3MultipartListResult {
    pub uploads: Vec<S3MultipartUploadSummary>,
    pub next_key_marker: Option<String>,
    pub next_upload_id_marker: Option<String>,
    pub is_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S3BucketVersioningState {
    Unversioned,
    Enabled,
    Suspended,
    AccessDenied(String),
    BackendError(String),
}

#[async_trait]
pub trait S3Driver: Send + Sync + 'static {
    async fn get_bucket_versioning_state(&self, _bucket: &str) -> S3BucketVersioningState {
        S3BucketVersioningState::Unversioned
    }

    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, StorageError>;
    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<String, StorageError>;
    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> Result<(), StorageError>;
    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), StorageError>;
    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        key_marker: Option<&str>,
        upload_id_marker: Option<&str>,
    ) -> Result<S3MultipartListResult, StorageError>;

    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Bytes, String)>, StorageError>;

    /// Streams the inclusive byte span. The default refuses so a collecting
    /// `get_object` cannot be reused for a range. [`AwsS3Driver`] overrides it.
    async fn get_object_range(
        &self,
        _bucket: &str,
        _key: &str,
        _start: u64,
        _end_inclusive: u64,
    ) -> Result<Option<Pin<Box<dyn AsyncRead + Send>>>, StorageError> {
        Err(StorageError::Unsupported)
    }

    /// Streams the entire object without collecting it into memory.
    async fn get_object_stream(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(u64, Pin<Box<dyn AsyncRead + Send>>)>, StorageError> {
        let res = self.get_object(bucket, key).await?;
        match res {
            Some((bytes, _)) => {
                let size = bytes.len() as u64;
                let reader = std::io::Cursor::new(bytes);
                Ok(Some((size, Box::pin(reader))))
            }
            None => Ok(None),
        }
    }

    async fn head_object(&self, bucket: &str, key: &str) -> Result<Option<u64>, StorageError>;
    async fn put_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        body: Bytes,
        if_match: Option<String>,
        if_none_match: Option<String>,
    ) -> Result<String, StorageError>;
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), StorageError>;
    async fn delete_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        if_match: Option<String>,
    ) -> Result<super::ConditionalDeleteResult, StorageError>;

    /// Transitional wiring: the backend-neutral [`ObjectStore`] handle for
    /// the MIGRATED families (Phase 3 tags, Phase 4 manifests), rooted at
    /// the given bucket and configured key prefix. Defaulted so existing
    /// driver test doubles that never serve migrated-family traffic compile
    /// unchanged; the production [`AwsS3Driver`] overrides it.
    async fn object_store(
        &self,
        _bucket: &str,
        _prefix: &str,
    ) -> Result<Arc<dyn storage_core::object_store::ObjectStore>, StorageError> {
        Err(StorageError::configuration(
            "this S3 driver does not provide an object store",
        ))
    }

    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<(), StorageError>;
    async fn list_objects_v2(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<S3ObjectSummary>, StorageError>;
    async fn list_objects_v2_page(
        &self,
        bucket: &str,
        prefix: &str,
        continuation_token: Option<&str>,
        max_keys: i32,
    ) -> Result<S3ObjectsPage, StorageError>;

    fn now_unix_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

pub struct AwsS3Driver {
    endpoint: Option<String>,
    region: Option<String>,
    client: OnceCell<Client>,
}

impl AwsS3Driver {
    pub fn new(endpoint: Option<String>, region: Option<String>) -> Self {
        Self {
            endpoint,
            region,
            client: OnceCell::new(),
        }
    }

    async fn client(&self) -> Result<Client, StorageError> {
        let region_str = self
            .region
            .as_deref()
            .ok_or_else(|| StorageError::configuration("STORAGE_S3_REGION is required"))?;
        let c = self
            .client
            .get_or_try_init(|| async {
                let is_local = self
                    .endpoint
                    .as_deref()
                    .map(|ep| {
                        ep.contains("127.0.0.1")
                            || ep.contains("localhost")
                            || ep.contains("0.0.0.0")
                            || ep.contains("::1")
                    })
                    .unwrap_or(false);

                let loader = aws_config::defaults(BehaviorVersion::latest())
                    .region(Region::new(region_str.to_string()));
                let loader = if is_local && std::env::var("AWS_ACCESS_KEY_ID").is_err() {
                    loader.credentials_provider(aws_sdk_s3::config::Credentials::new(
                        "minioadmin",
                        "minioadmin",
                        None,
                        None,
                        "static",
                    ))
                } else {
                    loader
                };
                let shared = loader.load().await;

                let mut builder = aws_sdk_s3::config::Builder::from(&shared);
                if let Some(ep) = self.endpoint.as_deref() {
                    builder = builder.endpoint_url(ep);
                    if is_local {
                        builder = builder.force_path_style(true);
                    }
                }
                Ok::<_, StorageError>(Client::from_conf(builder.build()))
            })
            .await?;
        Ok(c.clone())
    }
}

pub(crate) fn validate_multipart_upload_id(
    upload_id: Option<&str>,
) -> Result<String, StorageError> {
    upload_id
        .map(|s| s.to_string())
        .ok_or_else(|| StorageError::backend("missing upload_id"))
}

pub(crate) fn track_continuation_token(
    seen_tokens: &mut HashSet<String>,
    token: &str,
) -> Result<(), StorageError> {
    if !seen_tokens.insert(token.to_string()) {
        return Err(StorageError::backend(
            "cyclic continuation token from S3 list_objects_v2",
        ));
    }
    Ok(())
}

#[async_trait]
impl S3Driver for AwsS3Driver {
    /// Builds the shared S3 ObjectStore over this driver's lazily
    /// constructed SDK client. The registry prefix is normalized exactly as
    /// `S3Storage::key` normalizes it (slash-trimmed), so
    /// migrated-family ObjectKeys (`repos/<repo>/tags/<tag>`,
    /// `repos/<repo>/manifests/<hex>`) map to byte-identical physical bucket
    /// keys.
    async fn object_store(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Arc<dyn storage_core::object_store::ObjectStore>, StorageError> {
        let client = self.client().await?;
        let s3_client = storage_s3::AwsS3Client::new(client, bucket);
        let trimmed = prefix.trim_matches('/');
        let prefix_opt = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        };
        let store =
            storage_s3::S3ObjectStore::new(Arc::new(s3_client), prefix_opt).map_err(|e| {
                StorageError::configuration(format!(
                    "configured S3 prefix is not usable as a tag store root: {e}"
                ))
            })?;
        Ok(Arc::new(store))
    }

    async fn get_bucket_versioning_state(&self, bucket: &str) -> S3BucketVersioningState {
        let client = match self.client().await {
            Ok(c) => c,
            Err(e) => return S3BucketVersioningState::BackendError(e.to_string()),
        };
        match client.get_bucket_versioning().bucket(bucket).send().await {
            Ok(resp) => match resp.status() {
                Some(aws_sdk_s3::types::BucketVersioningStatus::Enabled) => {
                    S3BucketVersioningState::Enabled
                }
                Some(aws_sdk_s3::types::BucketVersioningStatus::Suspended) => {
                    S3BucketVersioningState::Suspended
                }
                _ => S3BucketVersioningState::Unversioned,
            },
            Err(e) => match e {
                aws_sdk_s3::error::SdkError::ServiceError(se) => {
                    let status = se.raw().status().as_u16();
                    let code = se.err().meta().code().unwrap_or("");
                    if status == 403 || code == "AccessDenied" {
                        S3BucketVersioningState::AccessDenied(se.err().to_string())
                    } else {
                        S3BucketVersioningState::BackendError(se.err().to_string())
                    }
                }
                other => S3BucketVersioningState::BackendError(other.to_string()),
            },
        }
    }

    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, StorageError> {
        let client = self.client().await?;
        let resp = client
            .create_multipart_upload()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .map_err(|err| map_sdk_err(err, classify_s3_generic_service_error))?;
        validate_multipart_upload_id(resp.upload_id())
    }

    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<String, StorageError> {
        let client = self.client().await?;
        let resp = client
            .upload_part()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(ByteStream::from(body))
            .send()
            .await
            .map_err(|err| map_sdk_err(err, classify_s3_generic_service_error))?;
        Ok(resp.e_tag().unwrap_or("").trim_matches('"').to_string())
    }

    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> Result<(), StorageError> {
        let client = self.client().await?;
        let completed_parts: Vec<CompletedPart> = parts
            .into_iter()
            .map(|(num, etag)| {
                CompletedPart::builder()
                    .set_part_number(Some(num))
                    .set_e_tag(Some(etag))
                    .build()
            })
            .collect();
        let upload = CompletedMultipartUpload::builder()
            .set_parts(Some(completed_parts))
            .build();
        client
            .complete_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(upload)
            .send()
            .await
            .map_err(|err| map_sdk_err(err, classify_s3_generic_service_error))?;
        Ok(())
    }

    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), StorageError> {
        let client = self.client().await?;
        let _ = client
            .abort_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await;
        Ok(())
    }

    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        key_marker: Option<&str>,
        upload_id_marker: Option<&str>,
    ) -> Result<S3MultipartListResult, StorageError> {
        let client = self.client().await?;
        let mut req = client
            .list_multipart_uploads()
            .bucket(bucket)
            .prefix(prefix);
        if let Some(km) = key_marker {
            req = req.key_marker(km);
        }
        if let Some(uim) = upload_id_marker {
            req = req.upload_id_marker(uim);
        }
        let resp = req
            .send()
            .await
            .map_err(|err| map_sdk_err(err, classify_s3_generic_service_error))?;

        let uploads = resp
            .uploads()
            .iter()
            .map(|u| {
                let initiated = u
                    .initiated()
                    .and_then(|t| t.to_millis().ok())
                    .map(|ms| (ms / 1000) as u64)
                    .unwrap_or(0);
                S3MultipartUploadSummary {
                    key: u.key().unwrap_or("").to_string(),
                    upload_id: u.upload_id().unwrap_or("").to_string(),
                    initiated_at_unix_secs: initiated,
                }
            })
            .collect();

        Ok(S3MultipartListResult {
            uploads,
            next_key_marker: resp.next_key_marker().map(ToString::to_string),
            next_upload_id_marker: resp.next_upload_id_marker().map(ToString::to_string),
            is_truncated: resp.is_truncated().unwrap_or(false),
        })
    }

    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Bytes, String)>, StorageError> {
        let client = self.client().await?;
        let resp = match client.get_object().bucket(bucket).key(key).send().await {
            Ok(r) => r,
            Err(err) => {
                let s3_err = map_s3_err(err);
                if matches!(s3_err, StorageError::NotFound) {
                    return Ok(None);
                }
                return Err(s3_err);
            }
        };
        let etag = resp.e_tag().unwrap_or("").trim_matches('"').to_string();
        let bytes = resp
            .body
            .collect()
            .await
            .map_err(|e| StorageError::backend(e.to_string()))?
            .into_bytes();
        Ok(Some((bytes, etag)))
    }

    async fn get_object_range(
        &self,
        bucket: &str,
        key: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Option<Pin<Box<dyn AsyncRead + Send>>>, StorageError> {
        let client = self.client().await?;
        let range = format!("bytes={start}-{end_inclusive}");
        let resp = match client
            .get_object()
            .bucket(bucket)
            .key(key)
            .range(range)
            .send()
            .await
        {
            Ok(r) => r,
            Err(err) => {
                let s3_err = map_s3_err(err);
                if matches!(s3_err, StorageError::NotFound) {
                    return Ok(None);
                }
                return Err(s3_err);
            }
        };
        let length = end_inclusive.saturating_sub(start).saturating_add(1);
        let reader = tokio::io::AsyncReadExt::take(resp.body.into_async_read(), length);
        Ok(Some(Box::pin(reader)))
    }

    async fn get_object_stream(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(u64, Pin<Box<dyn AsyncRead + Send>>)>, StorageError> {
        let client = self.client().await?;
        let resp = match client.get_object().bucket(bucket).key(key).send().await {
            Ok(r) => r,
            Err(err) => {
                let s3_err = map_s3_err(err);
                if matches!(s3_err, StorageError::NotFound) {
                    return Ok(None);
                }
                return Err(s3_err);
            }
        };
        let size = resp.content_length().unwrap_or(0).max(0) as u64;
        let reader = resp.body.into_async_read();
        Ok(Some((size, Box::pin(reader))))
    }

    async fn head_object(&self, bucket: &str, key: &str) -> Result<Option<u64>, StorageError> {
        let client = self.client().await?;
        match client.head_object().bucket(bucket).key(key).send().await {
            Ok(resp) => Ok(Some(resp.content_length().unwrap_or(0) as u64)),
            Err(err) => {
                let s3_err = map_head_err(err);
                if matches!(s3_err, StorageError::NotFound) {
                    Ok(None)
                } else {
                    Err(s3_err)
                }
            }
        }
    }

    async fn put_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        body: Bytes,
        if_match: Option<String>,
        if_none_match: Option<String>,
    ) -> Result<String, StorageError> {
        let client = self.client().await?;
        let mut req = client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(body));

        if let Some(ref m) = if_match {
            req = req.if_match(format!("\"{}\"", m.trim_matches('"')));
        }
        if let Some(ref nm) = if_none_match {
            req = req.if_none_match(nm);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(err) => {
                let is_precondition_failed = match &err {
                    aws_sdk_s3::error::SdkError::ServiceError(se) => {
                        let status = se.raw().status().as_u16();
                        let code = se.err().meta().code().unwrap_or("");
                        is_s3_precondition_failure(status, code)
                    }
                    _ => false,
                };
                if is_precondition_failed {
                    return Err(StorageError::TagAlreadyExists);
                }
                let is_permission = match &err {
                    aws_sdk_s3::error::SdkError::ServiceError(se) => {
                        let status = se.raw().status().as_u16();
                        let code = se.err().meta().code().unwrap_or("");
                        status == 403 || code == "AccessDenied"
                    }
                    _ => false,
                };
                if is_permission {
                    return Err(StorageError::permission_denied(err.to_string()));
                }
                return Err(StorageError::backend(err.to_string()));
            }
        };
        Ok(resp.e_tag().unwrap_or("").trim_matches('"').to_string())
    }

    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        let client = self.client().await?;
        match client.delete_object().bucket(bucket).key(key).send().await {
            Ok(_) => Ok(()),
            Err(e) => match &e {
                aws_sdk_s3::error::SdkError::ServiceError(se) => {
                    let status = se.raw().status().as_u16();
                    let code = se.err().meta().code().unwrap_or("");
                    classify_s3_unconditional_delete_error(status, code, e.to_string())
                }
                _ => Err(StorageError::backend(e.to_string())),
            },
        }
    }

    async fn delete_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        if_match: Option<String>,
    ) -> Result<super::ConditionalDeleteResult, StorageError> {
        let current = self.get_object(bucket, key).await?;
        let current_etag = match current {
            Some((_, etag)) => etag,
            None => return Ok(super::ConditionalDeleteResult::NotFound),
        };

        if let Some(ref expected) = if_match {
            if current_etag.trim_matches('"') != expected.trim_matches('"') {
                return Ok(super::ConditionalDeleteResult::PreconditionFailed {
                    current_version: Some(current_etag),
                });
            }
        }

        let client = self.client().await?;
        let mut req = client.delete_object().bucket(bucket).key(key);
        if let Some(ref m) = if_match {
            req = req.if_match(format!("\"{}\"", m.trim_matches('"')));
        }
        match req.send().await {
            Ok(_) => Ok(super::ConditionalDeleteResult::Deleted),
            Err(e) => match &e {
                aws_sdk_s3::error::SdkError::ServiceError(se) => {
                    let status = se.raw().status().as_u16();
                    let code = se.err().meta().code().unwrap_or("");
                    if is_s3_precondition_failure(status, code) {
                        let latest = match self.get_object(bucket, key).await {
                            Ok(Some((_, etag))) => Some(etag),
                            _ => None,
                        };
                        Ok(super::ConditionalDeleteResult::PreconditionFailed {
                            current_version: latest,
                        })
                    } else {
                        classify_s3_delete_service_error(status, code, e.to_string())
                    }
                }
                _ => Err(StorageError::backend(e.to_string())),
            },
        }
    }

    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<(), StorageError> {
        let client = self.client().await?;
        client
            .copy_object()
            .bucket(dst_bucket)
            .key(dst_key)
            .copy_source(format!("{src_bucket}/{src_key}"))
            .send()
            .await
            .map_err(|e| map_sdk_err(e, classify_s3_copy_service_error))?;
        Ok(())
    }

    async fn list_objects_v2(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<S3ObjectSummary>, StorageError> {
        let client = self.client().await?;
        let mut token: Option<String> = None;
        let mut seen_tokens: HashSet<String> = HashSet::new();
        let mut out = Vec::new();

        loop {
            let mut req = client
                .list_objects_v2()
                .bucket(bucket)
                .prefix(prefix.to_string());
            if let Some(t) = token.as_deref() {
                req = req.continuation_token(t);
            }
            let resp = req
                .send()
                .await
                .map_err(|err| map_sdk_err(err, classify_s3_generic_service_error))?;

            for obj in resp.contents() {
                if let Some(k) = obj.key() {
                    let size = obj.size().unwrap_or(0) as u64;
                    let last_modified_unix_secs = obj
                        .last_modified()
                        .map(|dt| dt.secs().max(0) as u64)
                        .unwrap_or(0);
                    let e_tag = obj.e_tag().map(|et| et.trim_matches('"').to_string());
                    out.push(S3ObjectSummary {
                        key: k.to_string(),
                        size,
                        last_modified_unix_secs,
                        e_tag,
                    });
                }
            }

            if resp.is_truncated().unwrap_or(false) {
                if let Some(next) = resp.next_continuation_token() {
                    let next_str = next.to_string();
                    track_continuation_token(&mut seen_tokens, &next_str)?;
                    token = Some(next_str);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Ok(out)
    }

    async fn list_objects_v2_page(
        &self,
        bucket: &str,
        prefix: &str,
        continuation_token: Option<&str>,
        max_keys: i32,
    ) -> Result<S3ObjectsPage, StorageError> {
        let client = self.client().await?;
        let mut req = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(prefix.to_string())
            .max_keys(max_keys);
        if let Some(t) = continuation_token {
            req = req.continuation_token(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|err| map_sdk_err(err, classify_s3_generic_service_error))?;

        let mut objects = Vec::new();
        for obj in resp.contents() {
            if let Some(k) = obj.key() {
                let size = obj.size().unwrap_or(0) as u64;
                let last_modified_unix_secs = obj
                    .last_modified()
                    .map(|dt| dt.secs().max(0) as u64)
                    .unwrap_or(0);
                let e_tag = obj.e_tag().map(|et| et.trim_matches('"').to_string());
                objects.push(S3ObjectSummary {
                    key: k.to_string(),
                    size,
                    last_modified_unix_secs,
                    e_tag,
                });
            }
        }

        let next_continuation_token = if resp.is_truncated().unwrap_or(false) {
            resp.next_continuation_token().map(|s| s.to_string())
        } else {
            None
        };

        Ok(S3ObjectsPage {
            objects,
            next_continuation_token,
        })
    }
}

#[derive(Clone, Debug)]
pub struct S3SessionConfig {
    pub lease_duration_secs: u64,
    pub lease_renewal_interval_secs: u64,
    pub max_retry_attempts: u32,
    pub receipt_lifetime_secs: u64,
    pub upload_expiration_secs: u64,
    pub legacy_multipart_cleanup_policy: crate::policy::LegacyMultipartCleanupPolicy,
    pub part_size_bytes: usize,
}

impl Default for S3SessionConfig {
    fn default() -> Self {
        Self {
            lease_duration_secs: S3_LEASE_DURATION_SECS,
            lease_renewal_interval_secs: S3_LEASE_RENEWAL_INTERVAL_SECS,
            max_retry_attempts: S3_MAX_RETRY_ATTEMPTS,
            receipt_lifetime_secs: 72 * 3600,
            upload_expiration_secs: 24 * 3600,
            legacy_multipart_cleanup_policy: crate::policy::LegacyMultipartCleanupPolicy::Disabled,
            part_size_bytes: S3_PART_SIZE,
        }
    }
}

#[derive(Clone)]
pub struct S3Storage {
    bucket: Option<String>,
    prefix: String,
    max_upload_bytes: u64,
    pub session_config: S3SessionConfig,
    driver: Arc<dyn S3Driver>,
    /// Phase 5 referrer-family cutover: the historical in-process
    /// same-subject mutation serialization, now owned by the shared
    /// backend-neutral referrer domain. Shared via `Arc` across clones so
    /// every clone serializes against one shard set, exactly as the retired
    /// `Arc<Vec<Mutex<()>>>` did.
    referrer_locks: Arc<crate::storage::referrer_domain::ReferrerLockShards>,
    /// Migrated-family cutovers (Phase 3 tags, Phase 4 manifests): the
    /// lazily wired backend-neutral ObjectStore shared by both domains
    /// (lazy to preserve the historical first-use surfacing of
    /// bucket/region configuration errors).
    object_store: Arc<OnceCell<Arc<dyn storage_core::object_store::ObjectStore>>>,
}

impl std::fmt::Debug for S3Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Storage")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("max_upload_bytes", &self.max_upload_bytes)
            .field("session_config", &self.session_config)
            .finish()
    }
}

impl S3Storage {
    pub fn new(
        endpoint: Option<String>,
        region: Option<String>,
        bucket: Option<String>,
        prefix: String,
        max_upload_bytes: u64,
    ) -> Self {
        let driver = Arc::new(AwsS3Driver::new(endpoint, region));
        Self {
            bucket,
            prefix,
            max_upload_bytes,
            session_config: S3SessionConfig::default(),
            driver,
            referrer_locks: Arc::new(crate::storage::referrer_domain::ReferrerLockShards::new()),
            object_store: Arc::new(OnceCell::new()),
        }
    }

    #[allow(dead_code)]
    pub fn new_with_driver(
        bucket: Option<String>,
        prefix: String,
        max_upload_bytes: u64,
        driver: Arc<dyn S3Driver>,
    ) -> Self {
        Self {
            bucket,
            prefix,
            max_upload_bytes,
            session_config: S3SessionConfig::default(),
            driver,
            referrer_locks: Arc::new(crate::storage::referrer_domain::ReferrerLockShards::new()),
            object_store: Arc::new(OnceCell::new()),
        }
    }

    pub fn with_session_config(mut self, session_config: S3SessionConfig) -> Self {
        self.session_config = session_config;
        self
    }

    fn bucket(&self) -> Result<&str, StorageError> {
        self.bucket
            .as_deref()
            .ok_or_else(|| StorageError::configuration("STORAGE_S3_BUCKET is required"))
    }

    /// The backend-neutral ObjectStore shared by the migrated families,
    /// wired on first use (missing bucket/region keep surfacing as the
    /// historical per-request configuration errors).
    async fn migrated_object_store(
        &self,
    ) -> Result<Arc<dyn storage_core::object_store::ObjectStore>, StorageError> {
        self.object_store
            .get_or_try_init(|| async {
                let bucket = self.bucket()?;
                self.driver.object_store(bucket, &self.prefix).await
            })
            .await
            .cloned()
    }

    /// Shared tag domain over the migrated-family ObjectStore. S3 has no
    /// repository existence notion, so the probe always reports existence
    /// (absent repositories list as empty — the historical S3 contract),
    /// and the resource bounds are the shared defaults (S3 historically had
    /// none; bounded truthful failure is the accepted campaign policy).
    async fn tag_domain(&self) -> Result<crate::storage::tag_domain::TagDomain, StorageError> {
        let store = self.migrated_object_store().await?;
        Ok(crate::storage::tag_domain::TagDomain::new(
            store,
            crate::storage::tag_domain::TagDomainConfig {
                max_payload_bytes: crate::storage::tag_domain::DEFAULT_MAX_PAYLOAD_BYTES,
                max_listing_entries: crate::storage::tag_domain::DEFAULT_MAX_LISTING_ENTRIES,
            },
            Arc::new(crate::storage::tag_domain::AlwaysExistsRepoProbe),
        ))
    }

    /// Shared manifest domain over the migrated-family ObjectStore (Phase 4).
    /// The listing bound is the shared default (mirroring the accepted FS
    /// configured default; the retired S3 listing drained unboundedly).
    async fn manifest_domain(
        &self,
    ) -> Result<crate::storage::manifest_domain::ManifestDomain, StorageError> {
        let store = self.migrated_object_store().await?;
        Ok(crate::storage::manifest_domain::ManifestDomain::new(
            store,
            crate::storage::manifest_domain::ManifestDomainConfig {
                max_listing_entries: crate::storage::manifest_domain::DEFAULT_MAX_LISTING_ENTRIES,
            },
        ))
    }

    /// Shared referrer domain over the migrated-family ObjectStore (Phase 5).
    /// The lock shards live on `self` (shared across clones) so per-call
    /// domain construction preserves the historical instance-wide in-process
    /// same-subject serialization.
    async fn referrer_domain(
        &self,
    ) -> Result<crate::storage::referrer_domain::ReferrerDomain, StorageError> {
        let store = self.migrated_object_store().await?;
        Ok(crate::storage::referrer_domain::ReferrerDomain::new(
            store,
            Arc::clone(&self.referrer_locks),
        ))
    }

    /// Shared membership domain over the migrated-family ObjectStore
    /// (Phase 6, point operations only; the enumeration operations and the
    /// `meta/` readiness/checkpoint state remain on the retained raw-driver
    /// seams).
    async fn membership_domain(
        &self,
    ) -> Result<crate::storage::membership_domain::MembershipDomain, StorageError> {
        let store = self.migrated_object_store().await?;
        Ok(crate::storage::membership_domain::MembershipDomain::new(
            store,
        ))
    }

    /// Shared lifecycle-journal domain over the migrated-family ObjectStore
    /// (Phase 7).
    async fn journal_domain(
        &self,
    ) -> Result<crate::storage::journal_domain::JournalDomain, StorageError> {
        let store = self.migrated_object_store().await?;
        Ok(crate::storage::journal_domain::JournalDomain::new(store))
    }

    /// Shared repository-timestamp domain over the migrated-family
    /// ObjectStore (Phase 8). S3 has no repository-existence notion: zero
    /// rows in both namespaces IS absence (the frozen S3 rule).
    async fn repo_timestamp_domain(
        &self,
    ) -> Result<crate::storage::repo_timestamp_domain::RepoTimestampDomain, StorageError> {
        let store = self.migrated_object_store().await?;
        Ok(
            crate::storage::repo_timestamp_domain::RepoTimestampDomain::new(
                store,
                crate::storage::repo_timestamp_domain::RepoExistencePolicy::EmptyIsAbsent,
            ),
        )
    }

    fn key(&self, suffix: &str) -> String {
        let p = self.prefix.trim_matches('/');
        if p.is_empty() {
            suffix.trim_start_matches('/').to_string()
        } else {
            format!("{p}/{}", suffix.trim_start_matches('/'))
        }
    }
}

/// S3 repository key prefix codec: computes the S3 key prefix for a validated repository name.
pub(crate) fn s3_repo_prefix(root_prefix: &str, repo: &CanonicalRepoName) -> String {
    let prefix = root_prefix.trim_matches('/');
    if prefix.is_empty() {
        format!("repos/{}/", repo.as_str())
    } else {
        format!("{prefix}/repos/{}/", repo.as_str())
    }
}

impl S3Storage {
    fn blob_key2(&self, digest: &Digest) -> String {
        self.key(&format!(
            "blobs/{}/{}/{}",
            digest.algorithm(),
            digest.prefix2(),
            digest.hex()
        ))
    }

    /// Physical membership-record key composition, retained for TEST
    /// seeding only (production point operations moved to the shared
    /// membership domain in Phase 6; the deferred listing seams enumerate by
    /// prefix and GET listed keys verbatim).
    #[cfg(test)]
    fn repo_blob_key(&self, repo: &CanonicalRepoName, digest: &Digest) -> String {
        self.key(&crate::storage::repo_membership::canonical_repo_membership_relpath(repo, digest))
    }

    fn repo_blobs_prefix(&self, repo: &CanonicalRepoName) -> String {
        self.key(&crate::storage::repo_membership::canonical_repo_membership_prefix(repo))
    }

    fn all_memberships_prefix(&self) -> String {
        self.key(crate::storage::repo_membership::canonical_all_memberships_prefix())
    }

    fn upload_key(&self, base_uuid: &str) -> String {
        self.key(&format!("uploads/{base_uuid}.data"))
    }

    fn session_key(&self, uuid: &str) -> String {
        self.key(&format!("uploads/{uuid}/session.json"))
    }

    pub async fn check_bucket_versioning(&self) -> S3BucketVersioningState {
        match self.bucket() {
            Ok(b) => self.driver.get_bucket_versioning_state(b).await,
            Err(e) => S3BucketVersioningState::BackendError(e.to_string()),
        }
    }

    pub async fn reap_orphaned_multipart_uploads(
        &self,
        older_than_unix_secs: u64,
    ) -> Result<usize, StorageError> {
        let bucket = self.bucket()?;
        let staging_prefix = self.key("uploads/");
        let mut count = 0;
        let mut key_marker: Option<String> = None;
        let mut upload_id_marker: Option<String> = None;

        loop {
            let res = self
                .driver
                .list_multipart_uploads(
                    bucket,
                    &staging_prefix,
                    key_marker.as_deref(),
                    upload_id_marker.as_deref(),
                )
                .await?;

            for u in &res.uploads {
                // Safety restriction: Must strictly start with our staging prefix
                if !u.key.starts_with(&staging_prefix) {
                    continue;
                }

                // Check age cutoff
                if u.initiated_at_unix_secs >= older_than_unix_secs {
                    continue;
                }

                // Extract UUID: uploads/<uuid>/...
                let rel = u.key.strip_prefix(&staging_prefix).unwrap_or("");
                let uuid = rel.split('/').next().unwrap_or("");
                if uuid.is_empty() {
                    continue;
                }

                // Check session document state explicitly distinguishing Ok(Some), Ok(None), and Err
                match self.get_session_doc_with_etag(uuid).await {
                    Ok(Some((doc, _))) => {
                        let now = self.driver.now_unix_secs();
                        let is_active = match doc.state {
                            UploadSessionState::Active => {
                                now.saturating_sub(doc.last_active_at_unix_secs)
                                    < self.session_config.upload_expiration_secs
                            }
                            UploadSessionState::Appending | UploadSessionState::Finalizing => doc
                                .current_operation
                                .as_ref()
                                .map(|op| now <= op.lease_expires_at_unix_secs)
                                .unwrap_or(false),
                        };
                        if is_active {
                            continue;
                        }
                        // Non-active session documents will be handled by the authoritative session reaper
                        continue;
                    }
                    Ok(None) => {
                        // No session doc exists. Evaluate against explicit cleanup policy.
                        match self.session_config.legacy_multipart_cleanup_policy {
                            crate::policy::LegacyMultipartCleanupPolicy::Disabled => {
                                tracing::debug!(
                                    key = %u.key,
                                    upload_id = %u.upload_id,
                                    "orphan multipart upload found without session doc, but legacy cleanup policy is disabled; skipping abort"
                                );
                                continue;
                            }
                            crate::policy::LegacyMultipartCleanupPolicy::CurrentFormatOnly => {
                                tracing::debug!(
                                    key = %u.key,
                                    upload_id = %u.upload_id,
                                    "orphan multipart upload without session.json cannot be proven current format; skipping abort"
                                );
                                continue;
                            }
                            crate::policy::LegacyMultipartCleanupPolicy::OperatorConfirmedAllUnknown => {
                                // Operator explicitly confirmed all unknown uploads may be cleaned up.
                            }
                        }
                    }
                    Err(err) => {
                        // FAIL CLOSED: S3 read error or corrupt metadata must NEVER trigger an abort!
                        tracing::warn!(
                            error = %err,
                            key = %u.key,
                            uuid = %uuid,
                            "failed to fetch session doc during multipart reaper; failing closed (skipping abort)"
                        );
                        continue;
                    }
                }

                // Immediately revalidate before destructive abort
                match self.get_session_doc_with_etag(uuid).await {
                    Ok(None) => {
                        // Authoritative absence reconfirmed. Proceed with abort.
                        match self
                            .driver
                            .abort_multipart_upload(bucket, &u.key, &u.upload_id)
                            .await
                        {
                            Ok(_) => {
                                count += 1;
                            }
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    key = %u.key,
                                    upload_id = %u.upload_id,
                                    "failed to abort orphaned multipart upload"
                                );
                            }
                        }
                    }
                    Ok(Some(_)) => {
                        tracing::info!(
                            key = %u.key,
                            uuid = %uuid,
                            "session doc appeared during pre-abort revalidation; abort skipped"
                        );
                        continue;
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            key = %u.key,
                            uuid = %uuid,
                            "error during pre-abort revalidation; failing closed (abort skipped)"
                        );
                        continue;
                    }
                }
            }

            if !res.is_truncated {
                break;
            }
            key_marker = res.next_key_marker;
            upload_id_marker = res.next_upload_id_marker;
            if key_marker.is_none() && upload_id_marker.is_none() {
                break;
            }
        }

        Ok(count)
    }

    fn finalized_key(&self, uuid: &str) -> String {
        self.key(&format!("uploads/{uuid}/finalized.json"))
    }

    fn multipart_data_key(&self, uuid: &str) -> String {
        self.key(&format!("uploads/{uuid}/multipart.data"))
    }

    fn pending_buffer_key(&self, uuid: &str, op_id: &str) -> String {
        self.key(&format!("uploads/{uuid}/pending/{op_id}.bin"))
    }

    #[allow(dead_code)]
    fn encode_upload_token(base_uuid: &str, upload_id: &str) -> String {
        let upload_id_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(upload_id);
        format!("{base_uuid}~{upload_id_b64}")
    }

    fn decode_upload_token(token: &str) -> Result<(String, String), StorageError> {
        if let Some((base, b64)) = token.split_once('~') {
            let upload_id_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(b64.as_bytes())
                .map_err(|_| StorageError::NotFound)?;
            let upload_id =
                String::from_utf8(upload_id_bytes).map_err(|_| StorageError::NotFound)?;
            Ok((base.to_string(), upload_id))
        } else {
            Ok((token.to_string(), String::new()))
        }
    }

    async fn get_session_doc_with_etag(
        &self,
        uuid: &str,
    ) -> Result<Option<(S3SessionDoc, String)>, StorageError> {
        let bucket = self.bucket()?;
        let key = self.session_key(uuid);
        let res = self.driver.get_object(bucket, &key).await?;
        match res {
            None => Ok(None),
            Some((bytes, etag)) => {
                let doc: S3SessionDoc = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::corrupt_data(e.to_string()))?;
                Ok(Some((doc, etag)))
            }
        }
    }

    async fn put_session_doc_conditional(
        &self,
        uuid: &str,
        doc: &S3SessionDoc,
        expected_etag: Option<&str>,
    ) -> Result<String, StorageError> {
        let bucket = self.bucket()?;
        let key = self.session_key(uuid);
        let body =
            serde_json::to_vec(doc).map_err(|e| StorageError::serialization(e.to_string()))?;
        let if_match = expected_etag.map(|s| s.to_string());
        let if_none_match = if expected_etag.is_none() {
            Some("*".to_string())
        } else {
            None
        };
        self.driver
            .put_object_conditional(bucket, &key, Bytes::from(body), if_match, if_none_match)
            .await
    }
}

pub(crate) fn classify_s3_get_head_service_error(
    status: u16,
    code: &str,
    raw_message: String,
) -> StorageError {
    if status == 404 || code == "NoSuchKey" || code == "NotFound" {
        StorageError::NotFound
    } else if status == 403 || code == "AccessDenied" {
        StorageError::permission_denied(raw_message)
    } else {
        StorageError::backend(raw_message)
    }
}

fn is_s3_precondition_failure(status: u16, code: &str) -> bool {
    status == 412
        || code == "PreconditionFailed"
        || code == "AtLeastOneConditionFailed"
        || code == "AtLeastOnePreconditionFailed"
}

pub(crate) fn classify_s3_put_service_error(
    status: u16,
    code: &str,
    raw_message: String,
) -> StorageError {
    if status == 403 || code == "AccessDenied" {
        StorageError::permission_denied(raw_message)
    } else if is_s3_precondition_failure(status, code) {
        StorageError::conflict(raw_message)
    } else {
        StorageError::backend(raw_message)
    }
}

pub(crate) fn classify_s3_delete_service_error(
    status: u16,
    code: &str,
    raw_message: String,
) -> Result<super::ConditionalDeleteResult, StorageError> {
    if is_s3_precondition_failure(status, code) {
        Ok(super::ConditionalDeleteResult::PreconditionFailed {
            current_version: None,
        })
    } else if status == 404 || code == "NoSuchKey" || code == "NotFound" {
        Ok(super::ConditionalDeleteResult::NotFound)
    } else if status == 403 || code == "AccessDenied" {
        Err(StorageError::permission_denied(raw_message))
    } else {
        Err(StorageError::backend(raw_message))
    }
}

/// Classification for UNCONDITIONAL S3 object deletion outcomes
/// (`S3Driver::delete_object`). Deleting an absent object is idempotent
/// success (native S3 answers 204 for it; some S3-compatible backends answer
/// 404/NoSuchKey instead). Every other service failure must surface to the
/// caller: a swallowed deletion failure would let a caller-visible deletion
/// (e.g. `delete_manifest`'s primary object delete, `delete_tag`) report
/// success while the object survives — a false deletion success the
/// filesystem backend correctly refuses.
pub(crate) fn classify_s3_unconditional_delete_error(
    status: u16,
    code: &str,
    raw_message: String,
) -> Result<(), StorageError> {
    if status == 404 || code == "NoSuchKey" || code == "NotFound" {
        Ok(())
    } else if status == 403 || code == "AccessDenied" {
        Err(StorageError::permission_denied(raw_message))
    } else {
        Err(StorageError::backend(raw_message))
    }
}

#[allow(dead_code)]
pub(crate) fn classify_s3_service_error(
    status: u16,
    code: &str,
    raw_message: String,
) -> StorageError {
    classify_s3_get_head_service_error(status, code, raw_message)
}

pub(crate) fn classify_s3_generic_service_error(
    status: u16,
    code: &str,
    raw_message: String,
) -> StorageError {
    if status == 403 || code == "AccessDenied" {
        StorageError::permission_denied(raw_message)
    } else {
        StorageError::backend(raw_message)
    }
}

pub(crate) fn classify_s3_copy_service_error(
    status: u16,
    code: &str,
    raw_message: String,
) -> StorageError {
    if status == 404 || code == "NoSuchKey" || code == "NotFound" {
        StorageError::NotFound
    } else if status == 403 || code == "AccessDenied" {
        StorageError::permission_denied(raw_message)
    } else {
        StorageError::backend(raw_message)
    }
}

pub(crate) fn map_sdk_err<
    E: std::error::Error + aws_sdk_s3::error::ProvideErrorMetadata + 'static,
>(
    err: aws_sdk_s3::error::SdkError<E>,
    classifier: fn(u16, &str, String) -> StorageError,
) -> StorageError {
    match &err {
        aws_sdk_s3::error::SdkError::ServiceError(se) => {
            let status = se.raw().status().as_u16();
            let code = se.err().meta().code().unwrap_or("");
            classifier(status, code, err.to_string())
        }
        _ => StorageError::backend(err.to_string()),
    }
}

fn map_s3_err(
    err: aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>,
) -> StorageError {
    match err {
        aws_sdk_s3::error::SdkError::ServiceError(se) => {
            let status = se.raw().status().as_u16();
            let code = se.err().meta().code().unwrap_or("");
            classify_s3_get_head_service_error(status, code, se.err().to_string())
        }
        other => StorageError::backend(other.to_string()),
    }
}

fn map_head_err(
    err: aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::head_object::HeadObjectError>,
) -> StorageError {
    match err {
        aws_sdk_s3::error::SdkError::ServiceError(se) => {
            let status = se.raw().status().as_u16();
            let code = se.err().meta().code().unwrap_or("");
            classify_s3_get_head_service_error(status, code, se.err().to_string())
        }
        other => StorageError::backend(other.to_string()),
    }
}

#[allow(dead_code)]
fn map_put_err(
    err: aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::put_object::PutObjectError>,
) -> StorageError {
    match err {
        aws_sdk_s3::error::SdkError::ServiceError(se) => {
            let status = se.raw().status().as_u16();
            let code = se.err().meta().code().unwrap_or("");
            classify_s3_put_service_error(status, code, se.err().to_string())
        }
        other => StorageError::backend(other.to_string()),
    }
}

#[async_trait]
impl crate::storage::ports::CacheEvictionPort for S3Storage {
    async fn list_cache_blobs_page(
        &self,
        cursor: Option<&GcCursor>,
        limit: usize,
    ) -> Result<GcBlobPage, StorageError> {
        GcStorage::list_cas_blobs_page(self, cursor, limit).await
    }

    /// Version-conditional delete of a cached CAS object (cache prefixes only;
    /// see the trait docs for why this is deliberately permit-free).
    async fn evict_cache_blob(
        &self,
        digest: &Digest,
        version: Option<&BlobObjectVersion>,
    ) -> Result<GcDeleteResult, StorageError> {
        let Some(version) = version else {
            return Err(StorageError::conflict(
                "S3 cache eviction requires the enumerated object version/ETag; unconditional delete is forbidden",
            ));
        };
        let bucket = self.bucket()?;
        let key = self.blob_key2(digest);
        let res = self
            .driver
            .delete_object_conditional(bucket, &key, Some(version.0.clone()))
            .await?;
        match res {
            ConditionalDeleteResult::Deleted => Ok(GcDeleteResult::Deleted),
            ConditionalDeleteResult::NotFound => Ok(GcDeleteResult::NotFound),
            ConditionalDeleteResult::PreconditionFailed { current_version } => {
                Ok(GcDeleteResult::PreconditionFailed {
                    current_version: current_version.map(BlobObjectVersion),
                })
            }
        }
    }
}

#[async_trait]
impl GcStorage for S3Storage {
    async fn check_bucket_versioning_for_gc(&self) -> Result<(), StorageError> {
        match self.check_bucket_versioning().await {
            S3BucketVersioningState::Unversioned => Ok(()),
            S3BucketVersioningState::Enabled => Err(StorageError::configuration(
                "S3 physical GC requires an unversioned bucket; bucket versioning is Enabled (delete would create delete markers rather than reclaim physical space)",
            )),
            S3BucketVersioningState::Suspended => Err(StorageError::configuration(
                "S3 physical GC requires an unversioned bucket; bucket versioning is Suspended (noncurrent versions exist and cannot be reclaimed without version-aware GC)",
            )),
            S3BucketVersioningState::AccessDenied(err) => Err(StorageError::permission_denied(
                format!("S3 bucket versioning preflight check failed or permission denied: {err}"),
            )),
            S3BucketVersioningState::BackendError(err) => Err(StorageError::backend(format!(
                "S3 bucket versioning preflight check failed or permission denied: {err}"
            ))),
        }
    }

    async fn list_cas_blobs_page(
        &self,
        cursor: Option<&GcCursor>,
        limit: usize,
    ) -> Result<GcBlobPage, StorageError> {
        let max_limit = 1000;
        let limit = limit.min(max_limit).max(1);
        let bucket = self.bucket()?;
        let prefix = self.key("blobs/sha256/");

        let page = self
            .driver
            .list_objects_v2_page(bucket, &prefix, cursor.map(|c| c.0.as_str()), limit as i32)
            .await?;

        let mut items = Vec::new();
        for obj in page.objects {
            if obj.key == prefix || obj.key.ends_with('/') {
                continue;
            }
            let suffix = match obj.key.strip_prefix(&prefix) {
                Some(s) => s,
                None => {
                    return Err(StorageError::corrupt_data(format!(
                        "malformed object key not starting with CAS prefix: {}",
                        obj.key
                    )));
                }
            };
            let parts: Vec<&str> = suffix.split('/').collect();
            if parts.len() != 2 {
                return Err(StorageError::corrupt_data(format!(
                    "malformed CAS object key structure in S3 (expected 2 parts): {}",
                    obj.key
                )));
            }
            let (p2, hex) = (parts[0], parts[1]);
            if p2.len() != 2
                || hex.len() != 64
                || !hex
                    .to_ascii_lowercase()
                    .starts_with(&p2.to_ascii_lowercase())
                || !p2.chars().all(|c| c.is_ascii_hexdigit())
                || !hex.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(StorageError::corrupt_data(format!(
                    "malformed CAS object key hex/prefix in S3: {}",
                    obj.key
                )));
            }

            let digest = match Digest::parse(&format!("sha256:{}", hex.to_ascii_lowercase())) {
                Ok(d) => d,
                Err(e) => {
                    return Err(StorageError::corrupt_data(format!(
                        "unparsable digest from CAS object key {}: {e}",
                        obj.key
                    )));
                }
            };

            let last_modified = UNIX_EPOCH + Duration::from_secs(obj.last_modified_unix_secs);
            let version = BlobObjectVersion(
                obj.e_tag
                    .unwrap_or_else(|| format!("{}:{}", obj.last_modified_unix_secs, obj.size)),
            );

            items.push(GcBlobCandidate {
                digest,
                size: obj.size,
                last_modified,
                version,
            });
        }

        Ok(GcBlobPage {
            items,
            next_cursor: page.next_continuation_token.map(GcCursor),
        })
    }

    async fn quarantine_blob(
        &self,
        permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        _digest: &Digest,
        _version: &BlobObjectVersion,
    ) -> Result<GcQuarantineResult, StorageError> {
        if !permit.is_valid() {
            return Err(StorageError::permission_denied(
                "invalid or inactive GC mutation permit",
            ));
        }
        Ok(GcQuarantineResult::Skipped)
    }

    async fn restore_quarantined_blob(
        &self,
        permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        _digest: &Digest,
    ) -> Result<Option<u64>, StorageError> {
        if !permit.is_valid() {
            return Err(StorageError::permission_denied(
                "invalid or inactive GC mutation permit",
            ));
        }
        Ok(None)
    }

    async fn delete_blob_conditional(
        &self,
        permit: &crate::storage::mutation_authority::GcMutationPermit<'_>,
        digest: &Digest,
        version: Option<&BlobObjectVersion>,
    ) -> Result<GcDeleteResult, StorageError> {
        if !permit.is_valid() {
            return Err(StorageError::permission_denied(
                "invalid or inactive GC mutation permit",
            ));
        }
        let Some(version) = version else {
            return Err(StorageError::conflict(
                "S3 conditional delete requires an explicit object version/ETag; unconditional delete is forbidden in GC",
            ));
        };
        let bucket = self.bucket()?;
        let key = self.blob_key2(digest);
        let if_match = Some(version.0.clone());
        let res = self
            .driver
            .delete_object_conditional(bucket, &key, if_match)
            .await?;

        match res {
            ConditionalDeleteResult::Deleted => Ok(GcDeleteResult::Deleted),
            ConditionalDeleteResult::NotFound => Ok(GcDeleteResult::NotFound),
            ConditionalDeleteResult::PreconditionFailed { current_version } => {
                Ok(GcDeleteResult::PreconditionFailed {
                    current_version: current_version.map(BlobObjectVersion),
                })
            }
        }
    }

    fn gc_strategy(&self) -> GcStorageStrategy {
        GcStorageStrategy::S3DirectConditional
    }

    async fn discover_manifest_references(&self) -> Result<Option<HashSet<Digest>>, StorageError> {
        Ok(None)
    }
}

#[async_trait]
impl Storage for S3Storage {
    fn kind(&self) -> &'static str {
        "s3"
    }

    async fn list_repositories(&self) -> Result<Vec<String>, StorageError> {
        let bucket = self.bucket()?;
        let repos_prefix = self.key("repos/");
        let objects = self.driver.list_objects_v2(bucket, &repos_prefix).await?;

        let mut set: HashSet<String> = HashSet::new();
        for obj in objects {
            let Some(rest) = obj.key.strip_prefix(&repos_prefix) else {
                continue;
            };
            let repo = if let Some((repo, _)) = rest.split_once("/tags/") {
                Some(repo)
            } else if let Some((repo, _)) = rest.split_once("/manifests/") {
                Some(repo)
            } else if let Some((repo, _)) = rest.split_once("/referrers/") {
                Some(repo)
            } else if let Some((repo, _)) = rest.split_once("/meta/") {
                Some(repo)
            } else {
                None
            };
            if let Some(repo) = repo
                && !repo.is_empty()
            {
                set.insert(repo.to_string());
            }
        }

        let mem_prefix = self.all_memberships_prefix();
        let mem_objects = self.driver.list_objects_v2(bucket, &mem_prefix).await?;
        for obj in mem_objects {
            if let Some(rest) = obj.key.strip_prefix(&mem_prefix) {
                if let Some((repo_enc, _)) = rest.split_once('/') {
                    let canon =
                        crate::storage::repo_membership::decode_canonical_repo_key(repo_enc)
                            .map_err(|e| {
                                StorageError::corrupt_data(format!(
                                    "malformed repository membership key in S3: {e}"
                                ))
                            })?;
                    set.insert(canon.to_string());
                }
            }
        }

        let mut repos: Vec<String> = set.into_iter().collect();
        repos.sort();
        Ok(repos)
    }

    async fn repo_timestamps(&self, name: &str) -> Result<RepoTimestamps, StorageError> {
        // Phase 8: the shared derivation over the migrated object store's
        // direct-child listing metadata; zero rows in both namespaces is
        // absence (the frozen S3 rule — no repository-existence notion).
        self.repo_timestamp_domain()
            .await?
            .repo_timestamps(name)
            .await
    }

    async fn is_storage_empty(&self) -> Result<bool, StorageError> {
        let bucket = self.bucket()?;
        let prefix = self.key("");
        let lock_key = self.key("meta/exclusive_writer.lock");

        let mut continuation_token: Option<String> = None;
        let mut seen_tokens: HashSet<String> = HashSet::new();

        loop {
            let page = self
                .driver
                .list_objects_v2_page(bucket, &prefix, continuation_token.as_deref(), 10)
                .await?;

            let has_data_objects = page.objects.iter().any(|obj| obj.key != lock_key);

            if has_data_objects {
                return Ok(false);
            }

            if let Some(next_token) = page.next_continuation_token {
                if !seen_tokens.insert(next_token.clone()) {
                    return Err(StorageError::backend(
                        "repeated S3 continuation token detected during storage readiness check",
                    ));
                }
                continuation_token = Some(next_token);
            } else {
                break;
            }
        }

        let mpu = self
            .driver
            .list_multipart_uploads(bucket, &prefix, None, None)
            .await?;
        if !mpu.uploads.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }

    async fn head_blob(&self, digest: &Digest) -> Result<BlobMeta, StorageError> {
        let bucket = self.bucket()?;
        let key = self.blob_key2(digest);
        let res = self.driver.head_object(bucket, &key).await?;
        match res {
            Some(size) => Ok(BlobMeta { size }),
            None => Err(StorageError::NotFound),
        }
    }

    async fn open_blob(
        &self,
        digest: &Digest,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError> {
        let bucket = self.bucket()?;
        let key = self.blob_key2(digest);
        let res = self.driver.get_object_stream(bucket, &key).await?;
        match res {
            Some((size, reader)) => Ok((BlobMeta { size }, reader)),
            None => Err(StorageError::NotFound),
        }
    }

    async fn open_blob_range(
        &self,
        digest: &Digest,
        start: u64,
        end_inclusive: u64,
    ) -> Result<(BlobMeta, Pin<Box<dyn AsyncRead + Send>>), StorageError> {
        if start > end_inclusive {
            return Err(StorageError::backend("byte range exceeds object"));
        }
        let bucket = self.bucket()?;
        let key = self.blob_key2(digest);
        let size = self
            .driver
            .head_object(bucket, &key)
            .await?
            .ok_or(StorageError::NotFound)?;
        if end_inclusive >= size {
            return Err(StorageError::backend("byte range exceeds object"));
        }
        let reader = self
            .driver
            .get_object_range(bucket, &key, start, end_inclusive)
            .await?
            .ok_or(StorageError::NotFound)?;
        Ok((BlobMeta { size }, reader))
    }

    async fn resolve_tag(&self, name: &str, tag: &str) -> Result<Digest, StorageError> {
        self.tag_domain().await?.resolve_tag(name, tag).await
    }

    async fn list_tags(&self, name: &str) -> Result<Vec<String>, StorageError> {
        self.tag_domain().await?.list_tags(name).await
    }

    async fn head_manifest(
        &self,
        name: &str,
        digest: &Digest,
    ) -> Result<ManifestMeta, StorageError> {
        self.manifest_domain()
            .await?
            .head_manifest(name, digest)
            .await
    }

    async fn get_manifest(
        &self,
        name: &str,
        digest: &Digest,
    ) -> Result<(ManifestMeta, Bytes), StorageError> {
        self.manifest_domain()
            .await?
            .get_manifest(name, digest)
            .await
    }

    async fn put_manifest(
        &self,
        name: &str,
        digest: &Digest,
        bytes: Bytes,
    ) -> Result<ManifestMeta, StorageError> {
        // Phase 4: shared manifest domain over the migrated-family
        // ObjectStore — media type validated before the write; unconditional
        // durable publication (one acknowledged PUT).
        self.manifest_domain()
            .await?
            .put_manifest(name, digest, bytes)
            .await
    }

    async fn set_tag(&self, name: &str, tag: &str, digest: &Digest) -> Result<(), StorageError> {
        self.mutate_tag(name, tag, digest, super::TagMutationPolicy::Replace)
            .await?;
        Ok(())
    }

    async fn mutate_tag(
        &self,
        name: &str,
        tag: &str,
        digest: &Digest,
        policy: super::TagMutationPolicy,
    ) -> Result<super::TagMutation, StorageError> {
        // Phase 3: shared tag domain over the backend-neutral ObjectStore.
        // CreateOnly rides on the service-atomic If-None-Match publication;
        // the old read/CAS-retry loop (and its Conflict exhaustion error) is
        // retired (see the Phase 3 tag mutation design).
        self.tag_domain()
            .await?
            .mutate_tag(name, tag, digest, policy)
            .await
    }

    async fn delete_tag(&self, name: &str, tag: &str) -> Result<(), StorageError> {
        // Converged contract (Phase 3): absent -> NotFound, matching the
        // trait's filesystem behavior. (The retired S3-specific path treated
        // absence as idempotent success; production callers ignore the
        // result.) Backend delete failures keep the accepted classification.
        self.tag_domain().await?.delete_tag(name, tag).await
    }

    async fn list_manifest_digests_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<Digest>, Option<String>), StorageError> {
        self.manifest_domain()
            .await?
            .list_manifest_digests_page(repo, continuation_token, page_limit)
            .await
    }

    async fn list_tags_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<(String, Digest)>, Option<String>), StorageError> {
        self.tag_domain()
            .await?
            .list_tags_page(repo, continuation_token, page_limit)
            .await
    }

    async fn list_referrers_page(
        &self,
        repo: &str,
        subject: &Digest,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<(Vec<ReferrerDescriptor>, Option<String>), StorageError> {
        self.referrer_domain()
            .await?
            .list_referrers_page(repo, subject, continuation_token, page_limit)
            .await
    }

    async fn get_tag_with_version(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<Option<(Digest, String)>, StorageError> {
        // Phase 3: the returned version token is the registry's raw-byte
        // SHA-256 on every backend (the retired S3 path exposed the object
        // ETag). Tokens are never client-supplied; journal snapshots from a
        // pre-cutover run degrade to recovery's fresh-read sweep.
        self.tag_domain()
            .await?
            .get_tag_with_version(repo, tag)
            .await
    }

    async fn delete_tag_conditional(
        &self,
        repo: &str,
        tag: &str,
        expected_version: Option<&str>,
    ) -> Result<super::ConditionalDeleteResult, StorageError> {
        // Registry version precondition composed over read_with_version +
        // delete_if_version: the service-atomic If-Match delete replaces the
        // retired GET-then-conditional-DELETE driver path.
        self.tag_domain()
            .await?
            .delete_tag_conditional(repo, tag, expected_version)
            .await
    }

    async fn read_lifecycle_journal(&self, repo: &str) -> Result<Option<Bytes>, StorageError> {
        self.journal_domain()
            .await?
            .read_lifecycle_journal(repo)
            .await
    }

    async fn write_lifecycle_journal(&self, repo: &str, data: Bytes) -> Result<(), StorageError> {
        // Phase 7: the shared domain performs the frozen unconditional
        // durable publication at the identical prefixed key.
        self.journal_domain()
            .await?
            .write_lifecycle_journal(repo, data)
            .await
    }

    async fn delete_lifecycle_journal(&self, repo: &str) -> Result<(), StorageError> {
        // Phase 7: idempotent removal through the shared domain. The retired
        // body discarded EVERY delete error (`let _ =`) while all production
        // callers `?`-propagate; failures now surface truthfully, matching
        // the filesystem contract (semantic-matrix row R).
        self.journal_domain()
            .await?
            .delete_lifecycle_journal(repo)
            .await
    }

    async fn acquire_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
        ttl_secs: u64,
    ) -> Result<bool, StorageError> {
        let canonical = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
        let bucket = self.bucket()?;
        let key = self.key(&format!(
            "repos/{}/meta/repo_lease.json",
            canonical.as_str()
        ));
        let now = self.driver.now_unix_secs();

        #[derive(serde::Serialize, serde::Deserialize)]
        struct LeaseDoc {
            owner_id: String,
            lease_id: String,
            acquired_unix_secs: u64,
            expiry_unix_secs: u64,
        }

        let existing = self.driver.get_object(bucket, &key).await?;
        match existing {
            None => {
                let doc = LeaseDoc {
                    owner_id: owner_id.to_string(),
                    lease_id: lease_id.to_string(),
                    acquired_unix_secs: now,
                    expiry_unix_secs: now + ttl_secs,
                };
                let body = Bytes::from(serde_json::to_vec(&doc).unwrap());
                match self
                    .driver
                    .put_object_conditional(bucket, &key, body, None, Some("*".to_string()))
                    .await
                {
                    Ok(_) => Ok(true),
                    Err(StorageError::TagAlreadyExists) => Ok(false),
                    Err(e) => Err(e),
                }
            }
            Some((bytes, _etag)) => {
                if let Ok(parsed) = serde_json::from_slice::<LeaseDoc>(&bytes) {
                    if parsed.owner_id == owner_id && parsed.lease_id == lease_id {
                        return Ok(true);
                    }
                }
                // Under Option B (explicit single-writer / no automatic expiry takeover),
                // an active or unreleased lease held by another owner fails closed.
                Ok(false)
            }
        }
    }

    async fn renew_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
        ttl_secs: u64,
    ) -> Result<bool, StorageError> {
        let canonical = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
        let bucket = self.bucket()?;
        let key = self.key(&format!(
            "repos/{}/meta/repo_lease.json",
            canonical.as_str()
        ));
        let now = self.driver.now_unix_secs();

        #[derive(serde::Serialize, serde::Deserialize)]
        struct LeaseDoc {
            owner_id: String,
            lease_id: String,
            acquired_unix_secs: u64,
            expiry_unix_secs: u64,
        }

        let Some((bytes, etag)) = self.driver.get_object(bucket, &key).await? else {
            return Ok(false);
        };

        let Ok(parsed) = serde_json::from_slice::<LeaseDoc>(&bytes) else {
            return Ok(false);
        };

        if parsed.owner_id != owner_id || parsed.lease_id != lease_id {
            return Ok(false);
        }

        let doc = LeaseDoc {
            owner_id: owner_id.to_string(),
            lease_id: lease_id.to_string(),
            acquired_unix_secs: parsed.acquired_unix_secs,
            expiry_unix_secs: now + ttl_secs,
        };
        let body = Bytes::from(serde_json::to_vec(&doc).unwrap());
        match self
            .driver
            .put_object_conditional(bucket, &key, body, Some(etag), None)
            .await
        {
            Ok(_) => Ok(true),
            Err(StorageError::TagAlreadyExists) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn release_repo_lease(
        &self,
        repo: &str,
        owner_id: &str,
        lease_id: &str,
    ) -> Result<(), StorageError> {
        let canonical = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
        let bucket = self.bucket()?;
        let key = self.key(&format!(
            "repos/{}/meta/repo_lease.json",
            canonical.as_str()
        ));

        #[derive(serde::Serialize, serde::Deserialize)]
        struct LeaseDoc {
            owner_id: String,
            lease_id: String,
            acquired_unix_secs: u64,
            expiry_unix_secs: u64,
        }

        if let Some((bytes, etag)) = self.driver.get_object(bucket, &key).await? {
            if let Ok(parsed) = serde_json::from_slice::<LeaseDoc>(&bytes) {
                if parsed.owner_id == owner_id && parsed.lease_id == lease_id {
                    let _ = self
                        .driver
                        .delete_object_conditional(bucket, &key, Some(etag))
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn acquire_deployment_writer_lock(
        &self,
        doc: &super::mutation_authority::DeploymentWriterLockDoc,
    ) -> Result<(bool, Option<String>), StorageError> {
        let bucket = self.bucket()?;
        let key = self.key("meta/exclusive_writer.lock");

        if let Some((bytes, etag)) = self.driver.get_object(bucket, &key).await? {
            if let Ok(existing) =
                serde_json::from_slice::<super::mutation_authority::DeploymentWriterLockDoc>(&bytes)
            {
                if existing.owner_token == doc.owner_token {
                    return Ok((true, Some(etag)));
                }
                return Err(StorageError::ExclusiveWriterLocked(format!(
                    "held by {} on {} (pid {}) in mode '{}' acquired at {}",
                    existing.owner_id,
                    existing.hostname,
                    existing.pid,
                    existing.command_mode,
                    existing.acquired_unix_secs
                )));
            } else {
                let s = String::from_utf8_lossy(&bytes).to_string();
                return Err(StorageError::ExclusiveWriterLocked(s));
            }
        }

        let body = Bytes::from(serde_json::to_vec(doc).unwrap());
        match self
            .driver
            .put_object_conditional(bucket, &key, body, None, Some("*".to_string()))
            .await
        {
            Ok(_) => {
                let etag = self
                    .driver
                    .get_object(bucket, &key)
                    .await?
                    .map(|(_, tag)| tag);
                Ok((true, etag))
            }
            Err(StorageError::TagAlreadyExists) => {
                let current_owner = self
                    .driver
                    .get_object(bucket, &key)
                    .await?
                    .map(|(b, _)| {
                        if let Ok(d) = serde_json::from_slice::<
                            super::mutation_authority::DeploymentWriterLockDoc,
                        >(&b)
                        {
                            format!("{} ({})", d.owner_id, d.command_mode)
                        } else {
                            String::from_utf8_lossy(&b).to_string()
                        }
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                Err(StorageError::ExclusiveWriterLocked(current_owner))
            }
            Err(e) => Err(e),
        }
    }

    async fn release_deployment_writer_lock(
        &self,
        doc: &super::mutation_authority::DeploymentWriterLockDoc,
        expected_etag: Option<&str>,
    ) -> Result<bool, StorageError> {
        let bucket = self.bucket()?;
        let key = self.key("meta/exclusive_writer.lock");

        if let Some((bytes, etag)) = self.driver.get_object(bucket, &key).await? {
            if let Ok(existing) =
                serde_json::from_slice::<super::mutation_authority::DeploymentWriterLockDoc>(&bytes)
            {
                if existing.owner_token != doc.owner_token {
                    // Lock belongs to someone else; do not touch
                    return Ok(false);
                }
            }
            let version_to_delete = expected_etag.or(Some(&etag)).map(ToString::to_string);
            let del_res = self
                .driver
                .delete_object_conditional(bucket, &key, version_to_delete)
                .await?;
            return Ok(matches!(del_res, super::ConditionalDeleteResult::Deleted));
        }
        Ok(false)
    }

    async fn inspect_deployment_writer_lock(
        &self,
    ) -> Result<
        Option<(
            super::mutation_authority::DeploymentWriterLockDoc,
            Option<String>,
        )>,
        StorageError,
    > {
        let bucket = self.bucket()?;
        let key = self.key("meta/exclusive_writer.lock");

        if let Some((bytes, etag)) = self.driver.get_object(bucket, &key).await? {
            if let Ok(doc) =
                serde_json::from_slice::<super::mutation_authority::DeploymentWriterLockDoc>(&bytes)
            {
                return Ok(Some((doc, Some(etag))));
            }
        }
        Ok(None)
    }

    async fn admin_clear_deployment_writer_lock(
        &self,
        expected_owner: &str,
        expected_etag: &str,
    ) -> Result<(), StorageError> {
        let bucket = self.bucket()?;
        let key = self.key("meta/exclusive_writer.lock");

        let (bytes, current_etag) = match self.driver.get_object(bucket, &key).await? {
            Some(res) => res,
            None => return Err(StorageError::NotFound),
        };

        if !expected_etag.is_empty() && current_etag != expected_etag {
            return Err(StorageError::ExclusiveWriterLocked(format!(
                "lock etag mismatch: expected '{expected_etag}', current is '{current_etag}'"
            )));
        }

        if let Ok(doc) =
            serde_json::from_slice::<super::mutation_authority::DeploymentWriterLockDoc>(&bytes)
        {
            if !expected_owner.is_empty()
                && doc.owner_id != expected_owner
                && doc.owner_token != expected_owner
            {
                return Err(StorageError::conflict(format!(
                    "lock owner mismatch: expected '{expected_owner}', current is '{}'",
                    doc.owner_id
                )));
            }
        }

        let version = if expected_etag.is_empty() {
            Some(current_etag)
        } else {
            Some(expected_etag.to_string())
        };

        let res = self
            .driver
            .delete_object_conditional(bucket, &key, version)
            .await?;
        match res {
            super::ConditionalDeleteResult::Deleted => Ok(()),
            super::ConditionalDeleteResult::PreconditionFailed { current_version } => {
                Err(StorageError::ExclusiveWriterLocked(format!(
                    "lock changed concurrently to generation {:?}",
                    current_version
                )))
            }
            super::ConditionalDeleteResult::NotFound => Err(StorageError::NotFound),
        }
    }

    async fn create_upload(&self) -> Result<UploadMeta, StorageError> {
        let base_uuid = uuid::Uuid::new_v4().to_string();
        Ok(UploadMeta {
            uuid: base_uuid,
            offset: 0,
        })
    }

    async fn upload_status(&self, uuid: &str) -> Result<UploadMeta, StorageError> {
        let bucket = self.bucket()?;
        let (base_uuid, _) = Self::decode_upload_token(uuid)?;
        let key = self.upload_key(&base_uuid);
        let head = self.driver.head_object(bucket, &key).await?;
        let offset = head.unwrap_or(0);
        Ok(UploadMeta {
            uuid: uuid.to_string(),
            offset,
        })
    }

    async fn append_upload(&self, uuid: &str, chunk: Bytes) -> Result<UploadMeta, StorageError> {
        let bucket = self.bucket()?;
        let (base_uuid, _) = Self::decode_upload_token(uuid)?;
        let key = self.upload_key(&base_uuid);

        let mut current_bytes = match self.driver.get_object(bucket, &key).await? {
            Some((b, _)) => b.to_vec(),
            None => Vec::new(),
        };
        current_bytes.extend_from_slice(&chunk);
        let len = current_bytes.len() as u64;
        self.driver
            .put_object_conditional(bucket, &key, Bytes::from(current_bytes), None, None)
            .await?;

        Ok(UploadMeta {
            uuid: uuid.to_string(),
            offset: len,
        })
    }

    async fn finalize_upload(&self, uuid: &str, digest: &Digest) -> Result<BlobMeta, StorageError> {
        let bucket = self.bucket()?;
        let (base_uuid, _) = Self::decode_upload_token(uuid)?;
        let upload_key = self.upload_key(&base_uuid);

        if let Ok(meta) = self.head_blob(digest).await {
            let _ = self.driver.delete_object(bucket, &upload_key).await;
            return Ok(meta);
        }

        let dest_key = self.blob_key2(digest);
        self.driver
            .copy_object(bucket, &upload_key, bucket, &dest_key)
            .await?;
        let _ = self.driver.delete_object(bucket, &upload_key).await;

        let meta = self.head_blob(digest).await?;
        Ok(meta)
    }

    async fn abort_upload(&self, uuid: &str) -> Result<(), StorageError> {
        let bucket = self.bucket()?;
        let (base_uuid, upload_id) = Self::decode_upload_token(uuid)?;
        let key = self.upload_key(&base_uuid);

        let _ = self
            .driver
            .abort_multipart_upload(bucket, &key, &upload_id)
            .await;
        let _ = self.driver.delete_object(bucket, &key).await;
        Ok(())
    }

    async fn list_referrers(
        &self,
        name: &str,
        subject: &Digest,
    ) -> Result<Vec<ReferrerDescriptor>, StorageError> {
        self.referrer_domain()
            .await?
            .list_referrers(name, subject)
            .await
    }

    async fn add_referrer(
        &self,
        name: &str,
        subject: &Digest,
        descriptor: ReferrerDescriptor,
    ) -> Result<(), StorageError> {
        // Phase 5: the shared domain keeps the historical in-process shard
        // lock (same identity/scope, shared across clones via `self`) and
        // replaces the retired GET + unconditional PUT with replacement-safe
        // conditional read-modify-write — an external writer racing the
        // mutation can no longer be silently overwritten.
        self.referrer_domain()
            .await?
            .add_referrer(name, subject, descriptor)
            .await
    }

    async fn remove_referrer(
        &self,
        name: &str,
        subject: &Digest,
        referrer: &Digest,
    ) -> Result<(), StorageError> {
        // Same shared shard lock and conditional read-modify-write as
        // `add_referrer`; the empty-index removal is version-conditional
        // with the historical best-effort error treatment.
        self.referrer_domain()
            .await?
            .remove_referrer(name, subject, referrer)
            .await
    }

    async fn delete_manifest(&self, name: &str, digest: &Digest) -> Result<(), StorageError> {
        // Phase 4: frozen ordering — shared payload steps (pre-read ->
        // subject extraction -> payload delete) and the accepted Phase 3
        // replacement-safe tag cleanup run in the shared manifest domain;
        // the existing unmigrated-family referrer cleanup stays the final
        // best-effort step. Not a transaction; partial cleanup after the
        // payload delete remains possible, exactly as before.
        let maybe_subject = self
            .manifest_domain()
            .await?
            .delete_manifest(&self.tag_domain().await?, name, digest)
            .await?;
        if let Some(subject) = maybe_subject {
            let _ = self.remove_referrer(name, &subject, digest).await;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct S3SessionDoc {
    pub format_version: u32,
    pub repo: crate::registry::canonical_name::CanonicalRepoName,
    pub uuid: String,
    pub multipart_upload_id: String,
    pub state: UploadSessionState,
    pub committed_offset: u64,
    pub committed_parts: Vec<S3CommittedPart>,
    pub pending_buffer_key: Option<String>,
    pub pending_bytes: u64,
    pub created_at_unix_secs: u64,
    pub last_active_at_unix_secs: u64,
    pub current_operation: Option<S3CurrentOperation>,
    pub finalizing_info: Option<S3FinalizingInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct S3CommittedPart {
    pub part_number: i32,
    pub size: u64,
    pub etag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct S3CurrentOperation {
    pub operation_id: String,
    pub expected_offset: u64,
    pub target_part_number: i32,
    pub lease_expires_at_unix_secs: u64,
}

/// Default lease duration for active Appending and Finalizing upload operations.
pub const S3_LEASE_DURATION_SECS: u64 = 300;

/// Interval at which active upload stream workers renew their session lease.
pub const S3_LEASE_RENEWAL_INTERVAL_SECS: u64 = 60;

/// S3 multipart part size constraints.
pub const S3_MIN_PART_SIZE: usize = 5 * 1024 * 1024; // 5 MiB AWS S3 minimum
pub const S3_MAX_PART_SIZE: usize = 5 * 1024 * 1024 * 1024; // 5 GiB AWS S3 maximum
pub const DEFAULT_S3_PART_SIZE: usize = 64 * 1024 * 1024; // 64 MiB default for AI image compatibility (up to 640 GB)

/// S3 multipart standard minimum chunk size (5 MiB).
pub const S3_PART_SIZE: usize = S3_MIN_PART_SIZE;

/// Maximum number of CAS retry attempts under transient contention.
pub const S3_MAX_RETRY_ATTEMPTS: u32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct S3FinalizingInfo {
    pub operation_id: String,
    pub expected_digest: String,
    pub size: u64,
    pub finalizing_at_unix_secs: u64,
    #[serde(default)]
    pub multipart_completed: bool,
}

#[async_trait]
impl UploadSessionStorage for S3Storage {
    async fn create_session(&self, repo: &str) -> Result<UploadSessionId, StorageError> {
        let canonical_repo = crate::registry::canonical_name::CanonicalRepoName::parse(repo)
            .map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
        let bucket = self.bucket()?;
        let uuid = uuid::Uuid::new_v4().to_string();
        let data_key = self.multipart_data_key(&uuid);

        let multipart_upload_id = self
            .driver
            .create_multipart_upload(bucket, &data_key)
            .await?;
        let now = self.driver.now_unix_secs();

        let doc = S3SessionDoc {
            format_version: 1,
            repo: canonical_repo.clone(),
            uuid: uuid.clone(),
            multipart_upload_id,
            state: UploadSessionState::Active,
            committed_offset: 0,
            committed_parts: Vec::new(),
            pending_buffer_key: None,
            pending_bytes: 0,
            created_at_unix_secs: now,
            last_active_at_unix_secs: now,
            current_operation: None,
            finalizing_info: None,
        };

        self.put_session_doc_conditional(&uuid, &doc, None).await?;
        Ok(UploadSessionId::new(canonical_repo, uuid))
    }

    async fn session_status(
        &self,
        session: &UploadSessionId,
    ) -> Result<UploadSessionStatus, UploadTransitionError> {
        let (doc, _) = match self
            .get_session_doc_with_etag(&session.uuid)
            .await
            .map_err(UploadTransitionError::Storage)?
        {
            Some(pair) => pair,
            None => {
                if let Some(receipt) = self
                    .get_finalized_receipt(session)
                    .await
                    .map_err(UploadTransitionError::Storage)?
                {
                    return Ok(UploadSessionStatus {
                        session: session.clone(),
                        state: UploadSessionState::Finalizing,
                        committed_offset: receipt.size,
                        created_at: UNIX_EPOCH
                            + Duration::from_secs(receipt.finalized_at_unix_secs),
                        last_active_at: UNIX_EPOCH
                            + Duration::from_secs(receipt.finalized_at_unix_secs),
                    });
                }
                return Err(UploadTransitionError::NotFound);
            }
        };

        if doc.repo != session.repo || doc.uuid != session.uuid {
            return Err(UploadTransitionError::NotFound);
        }

        Ok(UploadSessionStatus {
            session: session.clone(),
            state: doc.state,
            committed_offset: doc.committed_offset,
            created_at: UNIX_EPOCH + Duration::from_secs(doc.created_at_unix_secs),
            last_active_at: UNIX_EPOCH + Duration::from_secs(doc.last_active_at_unix_secs),
        })
    }

    async fn append_if_offset(
        &self,
        session: &UploadSessionId,
        expected_offset: UploadOffsetPrecondition,
        mut stream: UploadByteStream,
        max_upload_bytes: u64,
    ) -> Result<UploadAppendResult, UploadTransitionError> {
        let bucket = self.bucket().map_err(UploadTransitionError::Storage)?;

        // 1. Acquire reservation lease on session.json with bounded retry on CAS contention
        let mut reserved_doc: S3SessionDoc;
        let mut reserved_etag: String;
        let operation_id = uuid::Uuid::new_v4().to_string();

        let mut attempts = 0;
        loop {
            attempts += 1;
            let (mut doc, etag) = match self
                .get_session_doc_with_etag(&session.uuid)
                .await
                .map_err(UploadTransitionError::Storage)?
            {
                Some(p) => p,
                None => return Err(UploadTransitionError::NotFound),
            };

            if doc.repo != session.repo || doc.uuid != session.uuid {
                return Err(UploadTransitionError::NotFound);
            }

            let now = self.driver.now_unix_secs();

            match doc.state {
                UploadSessionState::Active => {
                    match expected_offset {
                        UploadOffsetPrecondition::Exact(off) => {
                            if off != doc.committed_offset {
                                return Ok(UploadAppendResult::OffsetMismatch {
                                    current_offset: doc.committed_offset,
                                });
                            }
                        }
                        UploadOffsetPrecondition::CurrentForServerComposedMonolithicOperation => {}
                    }

                    let target_part_number = doc
                        .committed_parts
                        .iter()
                        .map(|p| p.part_number)
                        .max()
                        .unwrap_or(0)
                        .saturating_add(1);
                    doc.state = UploadSessionState::Appending;
                    doc.current_operation = Some(S3CurrentOperation {
                        operation_id: operation_id.clone(),
                        expected_offset: match expected_offset {
                            UploadOffsetPrecondition::Exact(off) => off,
                            UploadOffsetPrecondition::CurrentForServerComposedMonolithicOperation => {
                                doc.committed_offset
                            }
                        },
                        target_part_number,
                        lease_expires_at_unix_secs: now.saturating_add(self.session_config.lease_duration_secs),
                    });
                    doc.last_active_at_unix_secs = now;

                    match self
                        .put_session_doc_conditional(&session.uuid, &doc, Some(&etag))
                        .await
                    {
                        Ok(new_etag) => {
                            reserved_doc = doc;
                            reserved_etag = new_etag;
                            break;
                        }
                        Err(StorageError::TagAlreadyExists) => {
                            if attempts >= self.session_config.max_retry_attempts {
                                return Ok(UploadAppendResult::Conflict);
                            }
                            tokio::time::sleep(Duration::from_millis(10 * (1 << attempts))).await;
                            continue;
                        }
                        Err(err) => return Err(UploadTransitionError::Storage(err)),
                    }
                }
                UploadSessionState::Appending => {
                    let lease_expired = doc
                        .current_operation
                        .as_ref()
                        .map(|op| now > op.lease_expires_at_unix_secs)
                        .unwrap_or(true);
                    if lease_expired {
                        let _ = self.recover_session(session).await;
                        if attempts >= self.session_config.max_retry_attempts {
                            return Ok(UploadAppendResult::Conflict);
                        }
                        tokio::time::sleep(Duration::from_millis(10 * (1 << attempts))).await;
                        continue;
                    }
                    return Ok(UploadAppendResult::Conflict);
                }
                UploadSessionState::Finalizing => return Ok(UploadAppendResult::Conflict),
            }
        }

        // 2. Read existing pending bytes if any (strictly < part_size)
        let part_size = self
            .session_config
            .part_size_bytes
            .clamp(S3_MIN_PART_SIZE, S3_MAX_PART_SIZE);
        let mut buffer = Vec::with_capacity(part_size + 64 * 1024);
        if let Some(ref pending_key) = reserved_doc.pending_buffer_key
            && let Ok(Some((b, _))) = self.driver.get_object(bucket, pending_key).await
        {
            buffer.extend_from_slice(&b);
        }

        let limit = if max_upload_bytes > 0 {
            max_upload_bytes
        } else {
            self.max_upload_bytes
        };
        let initial_offset = reserved_doc.committed_offset;
        let mut incoming_written = 0u64;
        let mut parts_to_commit = reserved_doc.committed_parts.clone();
        let mut target_part_number = parts_to_commit
            .iter()
            .map(|p| p.part_number)
            .max()
            .unwrap_or(0)
            .saturating_add(1);

        let mut last_renewed_at = self.driver.now_unix_secs();
        let data_key = self.multipart_data_key(&session.uuid);

        // 3. Streaming loop: read chunk, buffer, upload full parts when full, renew lease
        while let Some(chunk_res) = stream.next().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(err) => return Err(UploadTransitionError::Stream(err)),
            };
            if chunk.is_empty() {
                continue;
            }
            let next_total = initial_offset
                .saturating_add(incoming_written)
                .saturating_add(chunk.len() as u64);
            if limit > 0 && next_total > limit {
                return Err(UploadTransitionError::TooLarge);
            }
            buffer.extend_from_slice(&chunk);
            incoming_written = incoming_written.saturating_add(chunk.len() as u64);

            let now = self.driver.now_unix_secs();
            // Check lease renewal interval
            if now.saturating_sub(last_renewed_at)
                >= self.session_config.lease_renewal_interval_secs
            {
                let (cur_doc, cur_etag) = match self
                    .get_session_doc_with_etag(&session.uuid)
                    .await
                    .map_err(UploadTransitionError::Storage)?
                {
                    Some(p) => p,
                    None => return Ok(UploadAppendResult::Conflict),
                };

                let same_owner = cur_doc
                    .current_operation
                    .as_ref()
                    .map(|op| op.operation_id == operation_id)
                    .unwrap_or(false);

                if !same_owner {
                    return Ok(UploadAppendResult::Conflict);
                }

                let mut renew_doc = cur_doc;
                if let Some(ref mut op) = renew_doc.current_operation {
                    op.lease_expires_at_unix_secs =
                        now.saturating_add(self.session_config.lease_duration_secs);
                    op.target_part_number = target_part_number;
                }
                renew_doc.last_active_at_unix_secs = now;

                match self
                    .put_session_doc_conditional(&session.uuid, &renew_doc, Some(&cur_etag))
                    .await
                {
                    Ok(new_etag) => {
                        reserved_etag = new_etag;
                        last_renewed_at = now;
                    }
                    Err(StorageError::TagAlreadyExists) => {
                        // Lost lease / 412
                        return Ok(UploadAppendResult::Conflict);
                    }
                    Err(err) => return Err(UploadTransitionError::Storage(err)),
                }
            }

            // Upload full parts as they accumulate
            while buffer.len() >= part_size {
                let part_bytes = Bytes::copy_from_slice(&buffer[..part_size]);
                let part_etag = self
                    .driver
                    .upload_part(
                        bucket,
                        &data_key,
                        &reserved_doc.multipart_upload_id,
                        target_part_number,
                        part_bytes,
                    )
                    .await
                    .map_err(UploadTransitionError::Storage)?;

                parts_to_commit.push(S3CommittedPart {
                    part_number: target_part_number,
                    size: part_size as u64,
                    etag: part_etag,
                });
                target_part_number += 1;
                buffer.drain(..part_size);
            }
        }

        let old_pending_key = reserved_doc.pending_buffer_key.clone();
        let mut new_pending_key = None;
        let new_pending_bytes = buffer.len() as u64;

        if new_pending_bytes > 0 {
            let key = self.pending_buffer_key(&session.uuid, &operation_id);
            self.driver
                .put_object_conditional(
                    bucket,
                    &key,
                    Bytes::from(buffer),
                    None,
                    Some("*".to_string()),
                )
                .await
                .map_err(UploadTransitionError::Storage)?;
            new_pending_key = Some(key);
        }

        let now = self.driver.now_unix_secs();
        reserved_doc.committed_offset = initial_offset.saturating_add(incoming_written);
        reserved_doc.committed_parts = parts_to_commit;
        reserved_doc.pending_buffer_key = new_pending_key.clone();
        reserved_doc.pending_bytes = new_pending_bytes;
        reserved_doc.state = UploadSessionState::Active;
        reserved_doc.current_operation = None;
        reserved_doc.last_active_at_unix_secs = now;

        match self
            .put_session_doc_conditional(&session.uuid, &reserved_doc, Some(&reserved_etag))
            .await
        {
            Ok(_) => {
                if let Some(old_key) = old_pending_key {
                    let _ = self.driver.delete_object(bucket, &old_key).await;
                }
                Ok(UploadAppendResult::Committed {
                    new_offset: reserved_doc.committed_offset,
                })
            }
            Err(StorageError::TagAlreadyExists) => {
                if let Some(ref new_key) = new_pending_key {
                    let _ = self.driver.delete_object(bucket, new_key).await;
                }
                Ok(UploadAppendResult::Conflict)
            }
            Err(err) => {
                if let Some(ref new_key) = new_pending_key {
                    let _ = self.driver.delete_object(bucket, new_key).await;
                }
                Err(UploadTransitionError::Storage(err))
            }
        }
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
        let bucket = self.bucket().map_err(UploadTransitionError::Storage)?;

        // If upload is already finalized, return immediately with idempotent prepared handle
        if let Some(receipt) = self
            .get_finalized_receipt(session)
            .await
            .map_err(UploadTransitionError::Storage)?
        {
            if receipt.digest == expected_digest.as_str() {
                return Ok(PreparedFinalize {
                    session: session.clone(),
                    operation_id: "already-finalized".to_string(),
                    expected_digest: expected_digest.clone(),
                    committed_offset: receipt.size,
                    size: receipt.size,
                });
            } else {
                return Err(UploadTransitionError::DigestMismatch {
                    expected: expected_digest.clone(),
                    computed: receipt.digest.clone(),
                });
            }
        }

        let had_trailing = trailing_stream.is_some();
        if let Some(stream) = trailing_stream {
            let append_res = self
                .append_if_offset(session, expected_offset, stream, max_upload_bytes)
                .await?;
            match append_res {
                UploadAppendResult::Committed { .. } => {}
                UploadAppendResult::OffsetMismatch { current_offset } => {
                    return Err(UploadTransitionError::OffsetMismatch {
                        expected: expected_offset,
                        current: current_offset,
                    });
                }
                UploadAppendResult::Conflict => return Err(UploadTransitionError::Conflict),
            }
        }

        let (mut doc, etag) = match self
            .get_session_doc_with_etag(&session.uuid)
            .await
            .map_err(UploadTransitionError::Storage)?
        {
            Some(p) => p,
            None => {
                if let Some(receipt) = self
                    .get_finalized_receipt(session)
                    .await
                    .map_err(UploadTransitionError::Storage)?
                {
                    if receipt.digest == expected_digest.as_str() {
                        return Ok(PreparedFinalize {
                            session: session.clone(),
                            operation_id: "already-finalized".to_string(),
                            expected_digest: expected_digest.clone(),
                            committed_offset: receipt.size,
                            size: receipt.size,
                        });
                    } else {
                        return Err(UploadTransitionError::DigestMismatch {
                            expected: expected_digest.clone(),
                            computed: receipt.digest.clone(),
                        });
                    }
                }
                return Err(UploadTransitionError::NotFound);
            }
        };

        if doc.repo != session.repo || doc.uuid != session.uuid {
            return Err(UploadTransitionError::NotFound);
        }

        if !had_trailing {
            match expected_offset {
                UploadOffsetPrecondition::Exact(off) => {
                    if off != doc.committed_offset {
                        return Err(UploadTransitionError::OffsetMismatch {
                            expected: expected_offset,
                            current: doc.committed_offset,
                        });
                    }
                }
                UploadOffsetPrecondition::CurrentForServerComposedMonolithicOperation => {}
            }
        }

        let data_key = self.multipart_data_key(&session.uuid);

        // Upload any remaining pending bytes as the final part (S3 allows the last part to be < 5 MiB)
        if let Some(ref pending_key) = doc.pending_buffer_key
            && let Ok(Some((bytes, _))) = self.driver.get_object(bucket, pending_key).await
            && !bytes.is_empty()
        {
            let final_part_num = doc
                .committed_parts
                .iter()
                .map(|p| p.part_number)
                .max()
                .unwrap_or(0)
                .saturating_add(1);

            let part_etag = self
                .driver
                .upload_part(
                    bucket,
                    &data_key,
                    &doc.multipart_upload_id,
                    final_part_num,
                    bytes.clone(),
                )
                .await
                .map_err(UploadTransitionError::Storage)?;

            doc.committed_parts.push(S3CommittedPart {
                part_number: final_part_num,
                size: bytes.len() as u64,
                etag: part_etag,
            });
        }
        if let Some(ref pending_key) = doc.pending_buffer_key {
            let _ = self.driver.delete_object(bucket, pending_key).await;
            doc.pending_buffer_key = None;
            doc.pending_bytes = 0;
        }

        let operation_id = uuid::Uuid::new_v4().to_string();
        let now = self.driver.now_unix_secs();

        // STEP 1: Persist Finalizing state via conditional CAS BEFORE completing multipart upload
        doc.state = UploadSessionState::Finalizing;
        doc.finalizing_info = Some(S3FinalizingInfo {
            operation_id: operation_id.clone(),
            expected_digest: expected_digest.as_str().to_string(),
            size: doc.committed_offset,
            finalizing_at_unix_secs: now,
            multipart_completed: false,
        });

        let mut finalizing_etag = self
            .put_session_doc_conditional(&session.uuid, &doc, Some(&etag))
            .await
            .map_err(UploadTransitionError::Storage)?;

        // STEP 2: Complete multipart upload
        let completed_parts: Vec<(i32, String)> = doc
            .committed_parts
            .iter()
            .map(|p| (p.part_number, p.etag.clone()))
            .collect();

        self.driver
            .complete_multipart_upload(bucket, &data_key, &doc.multipart_upload_id, completed_parts)
            .await
            .map_err(UploadTransitionError::Storage)?;

        // STEP 3: Record multipart completion in session metadata
        doc.finalizing_info.as_mut().unwrap().multipart_completed = true;
        if let Ok(updated_etag) = self
            .put_session_doc_conditional(&session.uuid, &doc, Some(&finalizing_etag))
            .await
        {
            finalizing_etag = updated_etag;
        }
        let _ = finalizing_etag;

        // STEP 4: Verify digest by streaming staged object (constant memory)
        let (_, mut reader) = match self.driver.get_object_stream(bucket, &data_key).await {
            Ok(Some(res)) => res,
            Ok(None) => return Err(UploadTransitionError::NotFound),
            Err(e) => return Err(UploadTransitionError::Storage(e)),
        };

        use tokio::io::AsyncReadExt as _;
        let mut chunk_buf = [0u8; 64 * 1024];
        let computed_hex = if expected_digest.algorithm() == "sha512" {
            let mut hasher = sha2::Sha512::new();
            loop {
                let n = reader
                    .read(&mut chunk_buf)
                    .await
                    .map_err(|e| UploadTransitionError::Storage(StorageError::io(e.to_string())))?;
                if n == 0 {
                    break;
                }
                hasher.update(&chunk_buf[..n]);
            }
            hex::encode(hasher.finalize())
        } else {
            let mut hasher = sha2::Sha256::new();
            loop {
                let n = reader
                    .read(&mut chunk_buf)
                    .await
                    .map_err(|e| UploadTransitionError::Storage(StorageError::io(e.to_string())))?;
                if n == 0 {
                    break;
                }
                hasher.update(&chunk_buf[..n]);
            }
            hex::encode(hasher.finalize())
        };

        if computed_hex != expected_digest.hex() {
            if abort_on_digest_mismatch {
                let _ = self.driver.delete_object(bucket, &data_key).await;
                let _ = self
                    .driver
                    .delete_object(bucket, &self.session_key(&session.uuid))
                    .await;
            }
            return Err(UploadTransitionError::DigestMismatch {
                expected: expected_digest.clone(),
                computed: computed_hex,
            });
        }

        Ok(PreparedFinalize {
            session: session.clone(),
            operation_id,
            expected_digest: expected_digest.clone(),
            committed_offset: doc.committed_offset,
            size: doc.committed_offset,
        })
    }

    async fn commit_finalize(
        &self,
        prepared: &PreparedFinalize,
    ) -> Result<FinalizeOutcome, UploadTransitionError> {
        let bucket = self.bucket().map_err(UploadTransitionError::Storage)?;

        // 1. Check receipt
        if let Some(receipt) = self
            .get_finalized_receipt(&prepared.session)
            .await
            .map_err(UploadTransitionError::Storage)?
            && receipt.digest == prepared.expected_digest.as_str()
        {
            return Ok(FinalizeOutcome::AlreadyFinalized(BlobMeta {
                size: receipt.size,
            }));
        }

        // 2. Validate session
        let (doc, _etag) = match self
            .get_session_doc_with_etag(&prepared.session.uuid)
            .await
            .map_err(UploadTransitionError::Storage)?
        {
            Some(p) => p,
            None => {
                // Check if blob exists in CAS store
                let dest_key = self.blob_key2(&prepared.expected_digest);
                if let Ok(Some(size)) = self.driver.head_object(bucket, &dest_key).await {
                    let receipt = FinalizedReceipt {
                        repo: prepared.session.repo.clone(),
                        uuid: prepared.session.uuid.clone(),
                        digest: prepared.expected_digest.as_str().to_string(),
                        size,
                        finalized_at_unix_secs: self.driver.now_unix_secs(),
                        format_version: 1,
                    };
                    let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
                    let _ = self
                        .driver
                        .put_object_conditional(
                            bucket,
                            &self.finalized_key(&prepared.session.uuid),
                            Bytes::from(receipt_bytes),
                            None,
                            None,
                        )
                        .await;
                    return Ok(FinalizeOutcome::AlreadyFinalized(BlobMeta { size }));
                }
                return Err(UploadTransitionError::NotFound);
            }
        };

        if doc.state != UploadSessionState::Finalizing {
            return Err(UploadTransitionError::InvalidPreparedHandle);
        }
        let Some(ref fin_info) = doc.finalizing_info else {
            return Err(UploadTransitionError::InvalidPreparedHandle);
        };
        if fin_info.operation_id != prepared.operation_id
            || fin_info.expected_digest != prepared.expected_digest.as_str()
        {
            return Err(UploadTransitionError::InvalidPreparedHandle);
        }

        // Copy into CAS destination
        let data_key = self.multipart_data_key(&prepared.session.uuid);
        let dest_key = self.blob_key2(&prepared.expected_digest);

        self.driver
            .copy_object(bucket, &data_key, bucket, &dest_key)
            .await
            .map_err(UploadTransitionError::Storage)?;

        // STEP 5: Durably create target repository membership BEFORE receipt
        let membership = crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
            prepared.session.repo.clone(),
            prepared.expected_digest.clone(),
            Some(prepared.session.uuid.clone()),
        );
        self.link_repo_blob(&membership)
            .await
            .map_err(UploadTransitionError::Storage)?;

        // Write finalized receipt
        let now = self.driver.now_unix_secs();
        let receipt = FinalizedReceipt {
            repo: prepared.session.repo.clone(),
            uuid: prepared.session.uuid.clone(),
            digest: prepared.expected_digest.as_str().to_string(),
            size: prepared.size,
            finalized_at_unix_secs: now,
            format_version: 1,
        };
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(|e| {
            UploadTransitionError::Storage(StorageError::serialization(e.to_string()))
        })?;
        self.driver
            .put_object_conditional(
                bucket,
                &self.finalized_key(&prepared.session.uuid),
                Bytes::from(receipt_bytes),
                None,
                None,
            )
            .await
            .map_err(UploadTransitionError::Storage)?;

        // Clean staging objects
        let _ = self.driver.delete_object(bucket, &data_key).await;
        let _ = self
            .driver
            .delete_object(bucket, &self.session_key(&prepared.session.uuid))
            .await;

        Ok(FinalizeOutcome::Published(BlobMeta {
            size: prepared.size,
        }))
    }

    async fn abort_session(&self, session: &UploadSessionId) -> Result<(), StorageError> {
        let bucket = self.bucket()?;

        if let Some((doc, _)) = self.get_session_doc_with_etag(&session.uuid).await? {
            let data_key = self.multipart_data_key(&session.uuid);
            let _ = self
                .driver
                .abort_multipart_upload(bucket, &data_key, &doc.multipart_upload_id)
                .await;
        }

        // Delete all objects under uploads/<uuid>/ (pending buffers, staging, session.json)
        let prefix = format!("uploads/{}/", session.uuid);
        if let Ok(objs) = self.driver.list_objects_v2(bucket, &prefix).await {
            for obj in objs {
                let _ = self.driver.delete_object(bucket, &obj.key).await;
            }
        }

        let _ = self
            .driver
            .delete_object(bucket, &self.session_key(&session.uuid))
            .await;
        Ok(())
    }

    async fn recover_session(
        &self,
        session: &UploadSessionId,
    ) -> Result<UploadSessionStatus, UploadTransitionError> {
        let bucket = self.bucket().map_err(UploadTransitionError::Storage)?;

        let (mut doc, _etag) = match self
            .get_session_doc_with_etag(&session.uuid)
            .await
            .map_err(UploadTransitionError::Storage)?
        {
            Some(p) => p,
            None => {
                if let Some(receipt) = self
                    .get_finalized_receipt(session)
                    .await
                    .map_err(UploadTransitionError::Storage)?
                {
                    return Ok(UploadSessionStatus {
                        session: session.clone(),
                        state: UploadSessionState::Finalizing,
                        committed_offset: receipt.size,
                        created_at: UNIX_EPOCH
                            + Duration::from_secs(receipt.finalized_at_unix_secs),
                        last_active_at: UNIX_EPOCH
                            + Duration::from_secs(receipt.finalized_at_unix_secs),
                    });
                }
                return Err(UploadTransitionError::NotFound);
            }
        };

        let now = self.driver.now_unix_secs();

        if doc.state == UploadSessionState::Finalizing
            && let Some(ref fin_info) = doc.finalizing_info
            && let Ok(digest) = Digest::parse(&fin_info.expected_digest)
        {
            let dest_key = self.blob_key2(&digest);
            if let Ok(Some(size)) = self.driver.head_object(bucket, &dest_key).await {
                let membership =
                    crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
                        session.repo.clone(),
                        digest.clone(),
                        Some(session.uuid.clone()),
                    );
                let _ = self.link_repo_blob(&membership).await;

                let receipt = FinalizedReceipt {
                    repo: session.repo.clone(),
                    uuid: session.uuid.clone(),
                    digest: fin_info.expected_digest.clone(),
                    size,
                    finalized_at_unix_secs: fin_info.finalizing_at_unix_secs,
                    format_version: 1,
                };
                let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
                let _ = self
                    .driver
                    .put_object_conditional(
                        bucket,
                        &self.finalized_key(&session.uuid),
                        Bytes::from(receipt_bytes),
                        None,
                        None,
                    )
                    .await;
                let _ = self
                    .driver
                    .delete_object(bucket, &self.multipart_data_key(&session.uuid))
                    .await;
                let _ = self
                    .driver
                    .delete_object(bucket, &self.session_key(&session.uuid))
                    .await;
            } else {
                // Staged object may still exist, or multipart upload may need completion
                let data_key = self.multipart_data_key(&session.uuid);
                let mut staging_size = self
                    .driver
                    .head_object(bucket, &data_key)
                    .await
                    .ok()
                    .flatten();

                if staging_size.is_none() && !doc.multipart_upload_id.is_empty() {
                    let completed_parts: Vec<(i32, String)> = doc
                        .committed_parts
                        .iter()
                        .map(|p| (p.part_number, p.etag.clone()))
                        .collect();
                    if self
                        .driver
                        .complete_multipart_upload(
                            bucket,
                            &data_key,
                            &doc.multipart_upload_id,
                            completed_parts,
                        )
                        .await
                        .is_ok()
                    {
                        staging_size = self
                            .driver
                            .head_object(bucket, &data_key)
                            .await
                            .ok()
                            .flatten();
                    }
                }

                if let Some(size) = staging_size {
                    let _ = self
                        .driver
                        .copy_object(bucket, &data_key, bucket, &dest_key)
                        .await;
                    let membership =
                        crate::storage::repo_membership::RepoBlobMembershipRecord::new_upload(
                            session.repo.clone(),
                            digest.clone(),
                            Some(session.uuid.clone()),
                        );
                    let _ = self.link_repo_blob(&membership).await;

                    let receipt = FinalizedReceipt {
                        repo: session.repo.clone(),
                        uuid: session.uuid.clone(),
                        digest: fin_info.expected_digest.clone(),
                        size,
                        finalized_at_unix_secs: fin_info.finalizing_at_unix_secs,
                        format_version: 1,
                    };
                    let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
                    let _ = self
                        .driver
                        .put_object_conditional(
                            bucket,
                            &self.finalized_key(&session.uuid),
                            Bytes::from(receipt_bytes),
                            None,
                            None,
                        )
                        .await;
                    let _ = self.driver.delete_object(bucket, &data_key).await;
                    let _ = self
                        .driver
                        .delete_object(bucket, &self.session_key(&session.uuid))
                        .await;
                } else {
                    return Err(UploadTransitionError::Storage(StorageError::corrupt_data(
                        "neither CAS blob nor staged object found for finalizing session",
                    )));
                }
            }
        } else if doc.state == UploadSessionState::Appending {
            let lease_expired = doc
                .current_operation
                .as_ref()
                .map(|op| now > op.lease_expires_at_unix_secs)
                .unwrap_or(true);
            if lease_expired {
                doc.state = UploadSessionState::Active;
                doc.current_operation = None;
                let bytes = serde_json::to_vec(&doc).map_err(|e| {
                    UploadTransitionError::Storage(StorageError::serialization(e.to_string()))
                })?;
                let _ = self
                    .driver
                    .put_object_conditional(
                        bucket,
                        &self.session_key(&session.uuid),
                        Bytes::from(bytes),
                        None,
                        None,
                    )
                    .await;
            }
        }

        self.session_status(session).await
    }

    async fn get_finalized_receipt(
        &self,
        session: &UploadSessionId,
    ) -> Result<Option<FinalizedReceipt>, StorageError> {
        let bucket = self.bucket()?;
        let key = self.finalized_key(&session.uuid);
        match self.driver.get_object(bucket, &key).await? {
            Some((bytes, _)) => {
                let receipt: FinalizedReceipt = serde_json::from_slice(&bytes)
                    .map_err(|e| StorageError::corrupt_data(e.to_string()))?;
                if receipt.repo == session.repo && receipt.uuid == session.uuid {
                    Ok(Some(receipt))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn reap_expired_sessions(
        &self,
        max_age_secs: u64,
        receipt_ttl_secs: u64,
    ) -> Result<usize, StorageError> {
        let bucket = self.bucket()?;
        let prefix = self.key("uploads/");
        let mut count = 0;

        let objects = self.driver.list_objects_v2(bucket, &prefix).await?;
        let now = self.driver.now_unix_secs();

        let effective_receipt_ttl = if receipt_ttl_secs > 0 {
            receipt_ttl_secs
        } else {
            self.session_config.receipt_lifetime_secs
        };

        for obj in &objects {
            let key = &obj.key;
            if key.ends_with("/session.json") {
                if let Ok(Some((bytes, _))) = self.driver.get_object(bucket, key).await
                    && let Ok(doc) = serde_json::from_slice::<S3SessionDoc>(&bytes)
                    && now.saturating_sub(doc.last_active_at_unix_secs) >= max_age_secs
                {
                    let session = UploadSessionId::new(doc.repo.clone(), &doc.uuid);
                    if doc.state == UploadSessionState::Finalizing {
                        let _ = self.recover_session(&session).await;
                        count += 1;
                    } else if doc.state == UploadSessionState::Appending {
                        let _ = self.recover_session(&session).await;
                        let _ = self.abort_session(&session).await;
                        count += 1;
                    } else {
                        let _ = self.abort_session(&session).await;
                        count += 1;
                    }
                }
            } else if key.ends_with("/finalized.json") {
                if let Ok(Some((bytes, _))) = self.driver.get_object(bucket, key).await
                    && let Ok(receipt) = serde_json::from_slice::<FinalizedReceipt>(&bytes)
                    && now.saturating_sub(receipt.finalized_at_unix_secs) >= effective_receipt_ttl
                {
                    let _ = self.driver.delete_object(bucket, key).await;
                    count += 1;
                }
            } else if key.contains("/pending/")
                && now.saturating_sub(obj.last_modified_unix_secs) >= max_age_secs
            {
                let _ = self.driver.delete_object(bucket, key).await;
                count += 1;
            }
        }

        let mp_cutoff = now.saturating_sub(max_age_secs);
        if let Ok(mp_count) = self.reap_orphaned_multipart_uploads(mp_cutoff).await {
            count += mp_count;
        }

        Ok(count)
    }
}

#[async_trait]
impl crate::storage::repo_membership::RepositoryBlobMembershipStorage for S3Storage {
    async fn get_repo_blob_membership(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<Option<crate::storage::repo_membership::RepoBlobMembershipRecord>, StorageError>
    {
        self.membership_domain()
            .await?
            .get_repo_blob_membership(repo, digest)
            .await
    }

    async fn link_repo_blob(
        &self,
        record: &crate::storage::repo_membership::RepoBlobMembershipRecord,
    ) -> Result<(), StorageError> {
        // Phase 6: the shared domain performs the frozen unconditional
        // durable publication at the identical physical key.
        self.membership_domain().await?.link_repo_blob(record).await
    }

    async fn set_membership_candidate(
        &self,
        repo: &str,
        digest: &Digest,
        since_unix_secs: u64,
    ) -> Result<bool, StorageError> {
        // Phase 6: the shared conditional transition preserves the pinned
        // precondition-loss -> Ok(false) contract (the retired ETag-guarded
        // read-modify-write), now version-conditional through the shared
        // ObjectStore.
        self.membership_domain()
            .await?
            .set_membership_candidate(repo, digest, since_unix_secs)
            .await
    }

    async fn clear_membership_candidate(
        &self,
        repo: &str,
        digest: &Digest,
    ) -> Result<bool, StorageError> {
        self.membership_domain()
            .await?
            .clear_membership_candidate(repo, digest)
            .await
    }

    async fn unlink_repo_blob(&self, repo: &str, digest: &Digest) -> Result<bool, StorageError> {
        // Phase 6: the parity-closure existence contract through the shared
        // domain — observation with a generation, then a conditional delete
        // of that observed generation. Ok(true) only when an existing record
        // was removed; a replacement racing the removal survives (Conflict).
        self.membership_domain()
            .await?
            .unlink_repo_blob(repo, digest)
            .await
    }

    async fn list_repo_blob_memberships_page(
        &self,
        repo: &str,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<
        (
            Vec<crate::storage::repo_membership::RepoBlobMembershipRecord>,
            Option<String>,
        ),
        StorageError,
    > {
        let bucket = self.bucket()?;
        let canonical = CanonicalRepoName::parse(repo)
            .map_err(|e| StorageError::InvalidRepoName(e.to_string()))?;
        let prefix = self.repo_blobs_prefix(&canonical);
        let objects = self.driver.list_objects_v2(bucket, &prefix).await?;

        let mut all_keys: Vec<String> = objects
            .into_iter()
            .map(|o| o.key)
            .filter(|k| k.starts_with(&prefix))
            .collect();
        all_keys.sort();

        let start_idx = if let Some(token) = continuation_token {
            match all_keys.binary_search_by(|k| k.as_str().cmp(token)) {
                Ok(idx) => idx + 1,
                Err(idx) => idx,
            }
        } else {
            0
        };

        let end_idx = (start_idx + page_limit).min(all_keys.len());
        let page_slice = &all_keys[start_idx..end_idx];

        let mut records = Vec::new();
        for key in page_slice {
            let (bytes, _etag) = match self.driver.get_object(bucket, key).await? {
                Some(res) => res,
                None => continue,
            };
            let rec = serde_json::from_slice::<
                crate::storage::repo_membership::RepoBlobMembershipRecord,
            >(&bytes)
            .map_err(|e| {
                StorageError::corrupt_data(format!("corrupt membership record at key '{key}': {e}"))
            })?;
            records.push(rec);
        }

        let next_token = if end_idx < all_keys.len() {
            page_slice.last().cloned()
        } else {
            None
        };

        Ok((records, next_token))
    }

    async fn list_all_repo_blob_memberships_page(
        &self,
        continuation_token: Option<&str>,
        page_limit: usize,
    ) -> Result<
        (
            Vec<crate::storage::repo_membership::RepoBlobMembershipRecord>,
            Option<String>,
        ),
        StorageError,
    > {
        let bucket = self.bucket()?;
        let prefix = self.all_memberships_prefix();
        let objects = self.driver.list_objects_v2(bucket, &prefix).await?;

        let mut all_keys: Vec<String> = objects
            .into_iter()
            .map(|o| o.key)
            .filter(|k| k.starts_with(&prefix))
            .collect();
        all_keys.sort();

        let start_idx = if let Some(token) = continuation_token {
            match all_keys.binary_search_by(|k| k.as_str().cmp(token)) {
                Ok(idx) => idx + 1,
                Err(idx) => idx,
            }
        } else {
            0
        };

        let end_idx = (start_idx + page_limit).min(all_keys.len());
        let page_slice = &all_keys[start_idx..end_idx];

        let mut records = Vec::new();
        for key in page_slice {
            let (bytes, _etag) = match self.driver.get_object(bucket, key).await? {
                Some(res) => res,
                None => continue,
            };
            let rec = serde_json::from_slice::<
                crate::storage::repo_membership::RepoBlobMembershipRecord,
            >(&bytes)
            .map_err(|e| {
                StorageError::corrupt_data(format!("corrupt membership record at key '{key}': {e}"))
            })?;
            records.push(rec);
        }

        let next_token = if end_idx < all_keys.len() {
            page_slice.last().cloned()
        } else {
            None
        };

        Ok((records, next_token))
    }

    async fn count_repo_blob_memberships(&self, digest: &Digest) -> Result<usize, StorageError> {
        let bucket = self.bucket()?;
        let prefix = self.all_memberships_prefix();
        let objects = self.driver.list_objects_v2(bucket, &prefix).await?;
        let suffix = format!("/{}/{}.json", digest.algorithm(), digest.hex());
        let mut count = 0;
        for obj in objects {
            if obj.key.ends_with(&suffix) {
                count += 1;
            }
        }
        Ok(count)
    }

    async fn is_membership_ready(&self) -> Result<bool, StorageError> {
        let checkpoint = self.get_migration_checkpoint().await?;
        let bucket = self.bucket()?;
        let key = self.key("meta/membership_ready.json");
        let ready_marker_exists = self.driver.head_object(bucket, &key).await?.is_some();
        match checkpoint {
            Some(cp) => Ok(
                cp.phase == crate::storage::repo_membership::MigrationPhase::Ready
                    && ready_marker_exists,
            ),
            None => Ok(ready_marker_exists),
        }
    }

    async fn mark_membership_ready(&self) -> Result<(), StorageError> {
        let bucket = self.bucket()?;
        let key = self.key("meta/membership_ready.json");
        let now = self.driver.now_unix_secs();
        let payload = serde_json::json!({
            "version": 1,
            "ready_at_unix_secs": now,
        });
        let bytes = serde_json::to_vec(&payload).unwrap();
        self.driver
            .put_object_conditional(bucket, &key, Bytes::from(bytes), None, None)
            .await?;

        let cp = self.get_migration_checkpoint().await?;
        let ready_cp = match cp {
            Some(mut c) => {
                c.phase = crate::storage::repo_membership::MigrationPhase::Ready;
                c.verification_result = Some(true);
                c.last_updated_unix_secs = now;
                c
            }
            None => crate::storage::repo_membership::MigrationCheckpointRecord {
                schema_version: 1,
                phase: crate::storage::repo_membership::MigrationPhase::Ready,
                owner_id: None,
                lease_expiry_unix_secs: None,
                source_continuation_token: None,
                current_repository: None,
                current_cursor: None,
                stats: crate::storage::repo_membership::MigrationStats::default(),
                started_unix_secs: now,
                last_updated_unix_secs: now,
                failure_info: None,
                verification_result: Some(true),
            },
        };
        self.save_migration_checkpoint(&ready_cp).await?;
        Ok(())
    }

    async fn get_migration_checkpoint(
        &self,
    ) -> Result<Option<crate::storage::repo_membership::MigrationCheckpointRecord>, StorageError>
    {
        let bucket = self.bucket()?;
        let key = self.key("meta/migration_checkpoint.json");
        if let Some((bytes, _etag)) = self.driver.get_object(bucket, &key).await? {
            let rec = serde_json::from_slice::<
                crate::storage::repo_membership::MigrationCheckpointRecord,
            >(&bytes)
            .map_err(|e| {
                StorageError::corrupt_data(format!("corrupt s3 migration checkpoint: {e}"))
            })?;
            return Ok(Some(rec));
        }
        Ok(None)
    }

    async fn save_migration_checkpoint(
        &self,
        checkpoint: &crate::storage::repo_membership::MigrationCheckpointRecord,
    ) -> Result<(), StorageError> {
        let bucket = self.bucket()?;
        let key = self.key("meta/migration_checkpoint.json");
        let bytes = serde_json::to_vec(checkpoint).map_err(|e| {
            StorageError::serialization(format!("serialize s3 migration checkpoint: {e}"))
        })?;
        self.driver
            .put_object_conditional(bucket, &key, Bytes::from(bytes), None, None)
            .await?;
        Ok(())
    }
}

#[cfg(any(test, feature = "test-mocks"))]
#[path = "s3/mock.rs"]
pub mod mock;

#[cfg(test)]
#[path = "s3/tests.rs"]
pub(crate) mod tests;
