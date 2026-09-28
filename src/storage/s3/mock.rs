//! Deterministic in-memory S3 mock driving the REAL S3Storage/S3ObjectStore
//! adapters without an endpoint. Available to core unit tests and, behind the
//! `test-mocks` feature, to downstream crates' test builds (ADR-010).

use super::*;
use crate::storage::ConditionalDeleteResult;
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub struct S3CallLogEntry {
    pub method: String,
    pub key: String,
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
    #[allow(dead_code)]
    pub body_len: usize,
}

type MockPartMap = HashMap<i32, (Bytes, String)>;
type MockMultipartStore = HashMap<String, (String, MockPartMap, u64)>;
type MockObjectStore = HashMap<String, (Bytes, String)>;
type MockHookFn = Arc<dyn Fn(&str, &str) -> Option<StorageError> + Send + Sync>;

pub struct MockS3Driver {
    pub objects: StdMutex<MockObjectStore>,
    pub multiparts: StdMutex<MockMultipartStore>,
    pub clock_secs: AtomicU64,
    pub etag_seq: AtomicU64,
    pub call_log: StdMutex<Vec<S3CallLogEntry>>,
    pub injected_412_keys: StdMutex<HashSet<String>>,
    pub versioning_state: StdMutex<S3BucketVersioningState>,
    pub hook_before_op: StdMutex<Option<MockHookFn>>,
    pub hook_after_op: StdMutex<Option<MockHookFn>>,
    /// Optional per-key modification times (unix seconds) surfaced through
    /// the bridge's listing `ObjectStat.modified` (Phase 8 repo-timestamp
    /// tests); keys without an entry list with `modified: None`.
    pub object_mtimes: StdMutex<HashMap<String, u64>>,
}

impl MockS3Driver {
    pub fn new(initial_time: u64) -> Self {
        Self {
            objects: StdMutex::new(HashMap::new()),
            multiparts: StdMutex::new(HashMap::new()),
            clock_secs: AtomicU64::new(initial_time),
            etag_seq: AtomicU64::new(1),
            call_log: StdMutex::new(Vec::new()),
            injected_412_keys: StdMutex::new(HashSet::new()),
            versioning_state: StdMutex::new(S3BucketVersioningState::Unversioned),
            hook_before_op: StdMutex::new(None),
            hook_after_op: StdMutex::new(None),
            object_mtimes: StdMutex::new(HashMap::new()),
        }
    }

    pub fn set_hook_before<F>(&self, f: F)
    where
        F: Fn(&str, &str) -> Option<StorageError> + Send + Sync + 'static,
    {
        *self.hook_before_op.lock().unwrap() = Some(Arc::new(f));
    }

    #[allow(dead_code)]
    pub fn set_hook_after<F>(&self, f: F)
    where
        F: Fn(&str, &str) -> Option<StorageError> + Send + Sync + 'static,
    {
        *self.hook_after_op.lock().unwrap() = Some(Arc::new(f));
    }

    pub fn clear_hooks(&self) {
        *self.hook_before_op.lock().unwrap() = None;
        *self.hook_after_op.lock().unwrap() = None;
    }

    pub fn advance_time(&self, secs: u64) {
        self.clock_secs.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn set_time(&self, secs: u64) {
        self.clock_secs.store(secs, Ordering::SeqCst);
    }

    pub fn inject_412_on_key(&self, key: &str) {
        self.injected_412_keys
            .lock()
            .unwrap()
            .insert(key.to_string());
    }

    pub fn clear_injected_412(&self) {
        self.injected_412_keys.lock().unwrap().clear();
    }

    pub fn get_call_log(&self) -> Vec<S3CallLogEntry> {
        self.call_log.lock().unwrap().clone()
    }

    fn check_before_hook(&self, method: &str, key: &str) -> Result<(), StorageError> {
        if let Some(ref hook) = *self.hook_before_op.lock().unwrap()
            && let Some(err) = hook(method, key)
        {
            return Err(err);
        }
        Ok(())
    }

    fn check_after_hook(&self, method: &str, key: &str) -> Result<(), StorageError> {
        if let Some(ref hook) = *self.hook_after_op.lock().unwrap()
            && let Some(err) = hook(method, key)
        {
            return Err(err);
        }
        Ok(())
    }
}

#[async_trait]
impl S3Driver for MockS3Driver {
    async fn get_bucket_versioning_state(&self, _bucket: &str) -> S3BucketVersioningState {
        self.versioning_state.lock().unwrap().clone()
    }

    async fn create_multipart_upload(
        &self,
        _bucket: &str,
        key: &str,
    ) -> Result<String, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "create_multipart_upload".to_string(),
            key: key.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("create_multipart_upload", key)?;

        let upload_id = uuid::Uuid::new_v4().to_string();
        let now = self.now_unix_secs();
        let mut mps = self.multiparts.lock().unwrap();
        mps.insert(upload_id.clone(), (key.to_string(), HashMap::new(), now));
        drop(mps);

        self.check_after_hook("create_multipart_upload", key)?;

        Ok(upload_id)
    }

    async fn upload_part(
        &self,
        _bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<String, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "upload_part".to_string(),
            key: key.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: body.len(),
        });
        drop(log);

        self.check_before_hook("upload_part", key)?;

        let mut mps = self.multiparts.lock().unwrap();
        let Some((_, parts, _)) = mps.get_mut(upload_id) else {
            return Err(StorageError::NotFound);
        };
        let etag = format!("\"etag_p{}_{}\"", part_number, body.len());
        parts.insert(part_number, (body, etag.clone()));
        drop(mps);

        self.check_after_hook("upload_part", key)?;

        Ok(etag)
    }

    async fn complete_multipart_upload(
        &self,
        _bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> Result<(), StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "complete_multipart_upload".to_string(),
            key: key.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("complete_multipart_upload", key)?;

        let mut mps = self.multiparts.lock().unwrap();
        let Some((_mp_key, stored_parts, _)) = mps.remove(upload_id) else {
            return Err(StorageError::NotFound);
        };
        let mut assembled = Vec::new();
        for (num, _) in parts {
            let Some((p_bytes, _)) = stored_parts.get(&num) else {
                return Err(StorageError::internal_invariant(format!(
                    "missing part {num}"
                )));
            };
            assembled.extend_from_slice(p_bytes);
        }
        let mut objs = self.objects.lock().unwrap();
        let etag = format!("\"mp_etag_{}\"", assembled.len());
        objs.insert(key.to_string(), (Bytes::from(assembled), etag));
        drop(objs);

        self.check_after_hook("complete_multipart_upload", key)?;

        Ok(())
    }

    async fn abort_multipart_upload(
        &self,
        _bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "abort_multipart_upload".to_string(),
            key: key.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("abort_multipart_upload", key)?;

        let mut mps = self.multiparts.lock().unwrap();
        mps.remove(upload_id);
        drop(mps);

        self.check_after_hook("abort_multipart_upload", key)?;

        Ok(())
    }

    async fn list_multipart_uploads(
        &self,
        _bucket: &str,
        prefix: &str,
        key_marker: Option<&str>,
        upload_id_marker: Option<&str>,
    ) -> Result<S3MultipartListResult, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "list_multipart_uploads".to_string(),
            key: prefix.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("list_multipart_uploads", prefix)?;

        let mps = self.multiparts.lock().unwrap();
        let mut items = Vec::new();
        for (uid, (k, _, initiated)) in mps.iter() {
            if k.starts_with(prefix) {
                items.push(S3MultipartUploadSummary {
                    key: k.clone(),
                    upload_id: uid.clone(),
                    initiated_at_unix_secs: *initiated,
                });
            }
        }
        items.sort_by(|a, b| a.key.cmp(&b.key).then(a.upload_id.cmp(&b.upload_id)));

        let mut start_idx = 0;
        if let Some(km) = key_marker {
            if let Some(pos) = items.iter().position(|u| {
                u.key.as_str() > km
                    || (u.key == km
                        && upload_id_marker
                            .map(|uim| u.upload_id.as_str() > uim)
                            .unwrap_or(false))
            }) {
                start_idx = pos;
            } else {
                start_idx = items.len();
            }
        }

        let slice = &items[start_idx..];
        Ok(S3MultipartListResult {
            uploads: slice.to_vec(),
            next_key_marker: None,
            next_upload_id_marker: None,
            is_truncated: false,
        })
    }

    async fn get_object(
        &self,
        _bucket: &str,
        key: &str,
    ) -> Result<Option<(Bytes, String)>, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "get_object".to_string(),
            key: key.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("get_object", key)?;

        let objs = self.objects.lock().unwrap();
        let res = objs.get(key).cloned();
        drop(objs);

        self.check_after_hook("get_object", key)?;

        Ok(res)
    }

    async fn get_object_range(
        &self,
        _bucket: &str,
        key: &str,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Option<std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>>, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "get_object_range".to_string(),
            key: key.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("get_object_range", key)?;
        let objs = self.objects.lock().unwrap();
        let res = objs.get(key).cloned();
        drop(objs);
        self.check_after_hook("get_object_range", key)?;

        let Some((bytes, _)) = res else {
            return Ok(None);
        };
        if start > end_inclusive || end_inclusive >= bytes.len() as u64 {
            return Err(StorageError::backend("byte range exceeds object"));
        }
        let start_idx = usize::try_from(start).unwrap_or(usize::MAX);
        let end_idx = usize::try_from(end_inclusive).unwrap_or(usize::MAX);
        let slice = bytes.slice(start_idx..=end_idx);
        Ok(Some(Box::pin(std::io::Cursor::new(slice))))
    }

    async fn head_object(&self, _bucket: &str, key: &str) -> Result<Option<u64>, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "head_object".to_string(),
            key: key.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("head_object", key)?;

        let objs = self.objects.lock().unwrap();
        let res = objs.get(key).map(|(b, _)| b.len() as u64);
        drop(objs);

        self.check_after_hook("head_object", key)?;

        Ok(res)
    }

    async fn put_object_conditional(
        &self,
        _bucket: &str,
        key: &str,
        body: Bytes,
        if_match: Option<String>,
        if_none_match: Option<String>,
    ) -> Result<String, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "put_object".to_string(),
            key: key.to_string(),
            if_match: if_match.clone(),
            if_none_match: if_none_match.clone(),
            body_len: body.len(),
        });
        drop(log);

        self.check_before_hook("put_object", key)?;

        if self.injected_412_keys.lock().unwrap().contains(key) {
            return Err(StorageError::TagAlreadyExists);
        }

        let mut objs = self.objects.lock().unwrap();
        let existing = objs.get(key);

        if matches!(if_none_match.as_deref(), Some("*")) && existing.is_some() {
            return Err(StorageError::TagAlreadyExists);
        }

        if let Some(ref m) = if_match {
            let m_clean = m.trim_matches('"');
            match existing {
                Some((_, cur_etag)) => {
                    if cur_etag.trim_matches('"') != m_clean {
                        return Err(StorageError::TagAlreadyExists);
                    }
                }
                None => return Err(StorageError::TagAlreadyExists),
            }
        }

        let seq = self.etag_seq.fetch_add(1, Ordering::SeqCst);
        let new_etag = format!("\"etag_{}_{}_{}\"", key.replace('/', "_"), body.len(), seq);
        objs.insert(key.to_string(), (body, new_etag.clone()));
        drop(objs);

        self.check_after_hook("put_object", key)?;

        Ok(new_etag.trim_matches('"').to_string())
    }

    async fn delete_object(&self, _bucket: &str, key: &str) -> Result<(), StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "delete_object".to_string(),
            key: key.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("delete_object", key)?;

        let mut objs = self.objects.lock().unwrap();
        objs.remove(key);
        drop(objs);

        self.check_after_hook("delete_object", key)?;

        Ok(())
    }

    async fn delete_object_conditional(
        &self,
        _bucket: &str,
        key: &str,
        if_match: Option<String>,
    ) -> Result<ConditionalDeleteResult, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "delete_object_conditional".to_string(),
            key: key.to_string(),
            if_match: if_match.clone(),
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("delete_object", key)?;

        let mut objs = self.objects.lock().unwrap();
        let Some((_bytes, existing_etag)) = objs.get(key) else {
            return Ok(ConditionalDeleteResult::NotFound);
        };

        if let Some(ref expected_etag) = if_match {
            let norm_expected = expected_etag.trim_matches('"');
            let norm_actual = existing_etag.trim_matches('"');
            if norm_expected != "*" && norm_expected != norm_actual {
                let current_etag = existing_etag.trim_matches('"').to_string();
                drop(objs);
                return Ok(ConditionalDeleteResult::PreconditionFailed {
                    current_version: Some(current_etag),
                });
            }
        }

        objs.remove(key);
        drop(objs);

        self.check_after_hook("delete_object", key)?;
        Ok(ConditionalDeleteResult::Deleted)
    }

    async fn copy_object(
        &self,
        _src_bucket: &str,
        src_key: &str,
        _dst_bucket: &str,
        dst_key: &str,
    ) -> Result<(), StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "copy_object".to_string(),
            key: format!("{src_key} -> {dst_key}"),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("copy_object", dst_key)?;

        let mut objs = self.objects.lock().unwrap();
        let Some((bytes, _)) = objs.get(src_key).cloned() else {
            return Err(StorageError::NotFound);
        };
        let new_etag = format!("\"copy_etag_{}\"", bytes.len());
        objs.insert(dst_key.to_string(), (bytes, new_etag));
        drop(objs);

        self.check_after_hook("copy_object", dst_key)?;

        Ok(())
    }

    async fn list_objects_v2(
        &self,
        _bucket: &str,
        prefix: &str,
    ) -> Result<Vec<S3ObjectSummary>, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "list_objects_v2".to_string(),
            key: prefix.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("list_objects_v2", prefix)?;

        let objs = self.objects.lock().unwrap();
        let clock = self.now_unix_secs();
        let mut out = Vec::new();
        for (k, (b, etag)) in objs.iter() {
            if k.starts_with(prefix) {
                out.push(S3ObjectSummary {
                    key: k.clone(),
                    size: b.len() as u64,
                    last_modified_unix_secs: clock,
                    e_tag: Some(etag.clone()),
                });
            }
        }
        drop(objs);

        self.check_after_hook("list_objects_v2", prefix)?;

        Ok(out)
    }

    async fn list_objects_v2_page(
        &self,
        _bucket: &str,
        prefix: &str,
        continuation_token: Option<&str>,
        max_keys: i32,
    ) -> Result<S3ObjectsPage, StorageError> {
        let mut log = self.call_log.lock().unwrap();
        log.push(S3CallLogEntry {
            method: "list_objects_v2_page".to_string(),
            key: prefix.to_string(),
            if_match: None,
            if_none_match: None,
            body_len: 0,
        });
        drop(log);

        self.check_before_hook("list_objects_v2_page", prefix)?;

        let objs = self.objects.lock().unwrap();
        let clock = self.now_unix_secs();
        let mut matched = Vec::new();
        for (k, (b, etag)) in objs.iter() {
            if k.starts_with(prefix) {
                if let Some(tok) = continuation_token {
                    if k.as_str() <= tok {
                        continue;
                    }
                }
                matched.push(S3ObjectSummary {
                    key: k.clone(),
                    size: b.len() as u64,
                    last_modified_unix_secs: clock,
                    e_tag: Some(etag.clone()),
                });
            }
        }
        drop(objs);

        matched.sort_by(|a, b| a.key.cmp(&b.key));
        let has_more = matched.len() as i32 > max_keys;
        if has_more {
            matched.truncate(max_keys as usize);
        }
        let next_continuation_token = if has_more {
            matched.last().map(|o| o.key.clone())
        } else {
            None
        };

        self.check_after_hook("list_objects_v2_page", prefix)?;

        Ok(S3ObjectsPage {
            objects: matched,
            next_continuation_token,
        })
    }

    fn now_unix_secs(&self) -> u64 {
        self.clock_secs.load(Ordering::SeqCst)
    }
}

fn make_test_stream(chunks: Vec<Bytes>) -> UploadByteStream {
    Box::pin(futures_util::stream::iter(chunks.into_iter().map(Ok)))
}

pub fn compute_sha256_digest(bytes: &[u8]) -> Digest {
    let hash = sha2::Sha256::digest(bytes);
    Digest::parse(&format!("sha256:{}", hex::encode(hash))).unwrap()
}

pub fn create_mock_storage() -> (S3Storage, Arc<MockS3Driver>) {
    let driver = Arc::new(MockS3Driver::new(1000));
    let storage = S3Storage::new_with_driver(
        Some("test-bucket".to_string()),
        "".to_string(),
        100 * 1024 * 1024,
        Arc::new(TagBridgeDriver::new(driver.clone())),
    );
    (storage, driver)
}

// ==========================================
// Phase 3 tag-family test bridge
// ==========================================

/// Exposes the [`MockS3Driver`]'s object map and injected-fault hooks
/// through the `storage-s3` [`naust_storage_s3::S3Client`] seam so the REAL
/// `S3ObjectStore` adapter serves the migrated tag family against the same
/// mock state the unmigrated families use. Hook method names stay the
/// legacy driver names ("get_object", "put_object", "delete_object",
/// "list_objects_v2") so existing fault closures keep working.
struct MockDriverTagClient(Arc<MockS3Driver>);

fn hook_to_api_error(err: StorageError) -> naust_storage_s3::S3ApiError {
    let msg = err.message().unwrap_or("injected fault").to_string();
    match err.internal_kind() {
        Some(crate::storage::StorageErrorKind::PermissionDenied) => {
            naust_storage_s3::S3ApiError::new(Some(403), Some("AccessDenied"), msg)
        }
        _ => naust_storage_s3::S3ApiError::new(Some(500), Some("InternalError"), msg),
    }
}

impl MockDriverTagClient {
    fn fire(&self, method: &str, key: &str) -> Result<(), naust_storage_s3::S3ApiError> {
        self.0
            .check_before_hook(method, key)
            .map_err(hook_to_api_error)
    }

    fn next_etag(&self) -> String {
        let n = self.0.etag_seq.fetch_add(1, Ordering::SeqCst);
        format!("\"tagmock-{n}\"")
    }
}

fn trimmed(e: &str) -> &str {
    e.trim_matches('"')
}

#[async_trait]
impl naust_storage_s3::S3Client for MockDriverTagClient {
    async fn head_object(
        &self,
        key: &str,
    ) -> Result<Option<naust_storage_s3::client::ObjectStat>, naust_storage_s3::S3ApiError> {
        self.fire("head_object", key)?;
        Ok(self.0.objects.lock().unwrap().get(key).map(|(b, e)| {
            naust_storage_s3::client::ObjectStat {
                size: b.len() as u64,
                modified: None,
                etag: e.clone(),
            }
        }))
    }

    async fn get_object(
        &self,
        key: &str,
        max_len: u64,
    ) -> Result<Option<naust_storage_s3::client::GetResult>, naust_storage_s3::S3ApiError> {
        self.fire("get_object", key)?;
        let objs = self.0.objects.lock().unwrap();
        let Some((bytes, etag)) = objs.get(key) else {
            return Ok(None);
        };
        if bytes.len() as u64 > max_len {
            return Err(naust_storage_s3::S3ApiError::new(
                None,
                Some(&naust_storage_s3::client::too_large_sentinel(max_len)),
                "object exceeds caller byte bound",
            ));
        }
        Ok(Some(naust_storage_s3::client::GetResult {
            stat: naust_storage_s3::client::ObjectStat {
                size: bytes.len() as u64,
                modified: None,
                etag: etag.clone(),
            },
            bytes: bytes.clone(),
        }))
    }

    async fn put_object(
        &self,
        key: &str,
        bytes: Bytes,
        precondition: naust_storage_s3::client::PutPrecondition,
    ) -> Result<String, naust_storage_s3::S3ApiError> {
        self.fire("put_object", key)?;
        // One lock across evaluate + apply: service-atomic conditionals.
        let mut objs = self.0.objects.lock().unwrap();
        match &precondition {
            naust_storage_s3::client::PutPrecondition::None => {}
            naust_storage_s3::client::PutPrecondition::IfNoneMatchAny => {
                if objs.contains_key(key) {
                    return Err(naust_storage_s3::S3ApiError::new(
                        Some(412),
                        Some("PreconditionFailed"),
                        "If-None-Match: * failed: object exists",
                    ));
                }
            }
            naust_storage_s3::client::PutPrecondition::IfMatch(expected) => match objs.get(key) {
                None => {
                    return Err(naust_storage_s3::S3ApiError::new(
                        Some(404),
                        Some("NoSuchKey"),
                        "If-Match on absent object",
                    ));
                }
                Some((_, cur)) if trimmed(cur) != trimmed(expected) => {
                    return Err(naust_storage_s3::S3ApiError::new(
                        Some(412),
                        Some("PreconditionFailed"),
                        "If-Match failed: stale etag",
                    ));
                }
                Some(_) => {}
            },
        }
        let etag = self.next_etag();
        objs.insert(key.to_string(), (bytes, etag.clone()));
        Ok(etag)
    }

    async fn delete_object(&self, key: &str) -> Result<(), naust_storage_s3::S3ApiError> {
        self.fire("delete_object", key)?;
        // Native S3: deleting an absent key is 204 success.
        self.0.objects.lock().unwrap().remove(key);
        Ok(())
    }

    async fn delete_object_if_match(
        &self,
        key: &str,
        etag: &str,
    ) -> Result<naust_storage_s3::client::RawConditionalDelete, naust_storage_s3::S3ApiError> {
        self.fire("delete_object_if_match", key)?;
        let mut objs = self.0.objects.lock().unwrap();
        match objs.get(key) {
            None => Ok(naust_storage_s3::client::RawConditionalDelete::NotFound),
            Some((_, cur)) if trimmed(cur) != trimmed(etag) => {
                Ok(naust_storage_s3::client::RawConditionalDelete::PreconditionFailed)
            }
            Some(_) => {
                objs.remove(key);
                Ok(naust_storage_s3::client::RawConditionalDelete::Deleted)
            }
        }
    }

    async fn list_direct_children(
        &self,
        dir_prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<naust_storage_s3::client::RawListPage, naust_storage_s3::S3ApiError> {
        self.fire("list_objects_v2", dir_prefix)?;
        let objs = self.0.objects.lock().unwrap();
        let mut keys: Vec<&String> = objs
            .keys()
            .filter(|k| {
                let Some(rest) = k.strip_prefix(dir_prefix) else {
                    return false;
                };
                // Delimiter mode: nested keys are common prefixes, not rows.
                !rest.is_empty() && !rest.contains('/')
            })
            .collect();
        keys.sort();
        let cap = max_keys.clamp(1, 1000);
        let mut out = Vec::new();
        let mut truncated = false;
        for key in keys {
            if let Some(sa) = start_after
                && key.as_str() <= sa
            {
                continue;
            }
            if out.len() == cap {
                truncated = true;
                break;
            }
            let (bytes, etag) = &objs[key.as_str()];
            let modified = self
                .0
                .object_mtimes
                .lock()
                .unwrap()
                .get(key.as_str())
                .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(*secs));
            out.push((
                key.clone(),
                naust_storage_s3::client::ObjectStat {
                    size: bytes.len() as u64,
                    modified,
                    etag: etag.clone(),
                },
            ));
        }
        Ok(naust_storage_s3::client::RawListPage {
            objects: out,
            truncated,
        })
    }
}

/// Delegating [`S3Driver`] wrapper adding the Phase 3 `tag_object_store`
/// seam over the shared mock state; every unmigrated-family method forwards
/// to the inner [`MockS3Driver`] unchanged.
pub struct TagBridgeDriver {
    inner: Arc<MockS3Driver>,
}

impl TagBridgeDriver {
    pub fn new(inner: Arc<MockS3Driver>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl S3Driver for TagBridgeDriver {
    async fn get_bucket_versioning_state(&self, bucket: &str) -> S3BucketVersioningState {
        self.inner.get_bucket_versioning_state(bucket).await
    }
    async fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<String, StorageError> {
        self.inner.create_multipart_upload(bucket, key).await
    }
    async fn upload_part(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: Bytes,
    ) -> Result<String, StorageError> {
        self.inner
            .upload_part(bucket, key, upload_id, part_number, body)
            .await
    }
    async fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, String)>,
    ) -> Result<(), StorageError> {
        self.inner
            .complete_multipart_upload(bucket, key, upload_id, parts)
            .await
    }
    async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> Result<(), StorageError> {
        self.inner
            .abort_multipart_upload(bucket, key, upload_id)
            .await
    }
    async fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        key_marker: Option<&str>,
        upload_id_marker: Option<&str>,
    ) -> Result<S3MultipartListResult, StorageError> {
        self.inner
            .list_multipart_uploads(bucket, prefix, key_marker, upload_id_marker)
            .await
    }
    async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<Option<(Bytes, String)>, StorageError> {
        self.inner.get_object(bucket, key).await
    }
    async fn head_object(&self, bucket: &str, key: &str) -> Result<Option<u64>, StorageError> {
        self.inner.head_object(bucket, key).await
    }
    async fn put_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        body: Bytes,
        if_match: Option<String>,
        if_none_match: Option<String>,
    ) -> Result<String, StorageError> {
        self.inner
            .put_object_conditional(bucket, key, body, if_match, if_none_match)
            .await
    }
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), StorageError> {
        self.inner.delete_object(bucket, key).await
    }
    async fn delete_object_conditional(
        &self,
        bucket: &str,
        key: &str,
        if_match: Option<String>,
    ) -> Result<crate::storage::ConditionalDeleteResult, StorageError> {
        self.inner
            .delete_object_conditional(bucket, key, if_match)
            .await
    }
    async fn object_store(
        &self,
        _bucket: &str,
        prefix: &str,
    ) -> Result<Arc<dyn naust_storage_core::object_store::ObjectStore>, StorageError> {
        let client = Arc::new(MockDriverTagClient(self.inner.clone()));
        let trimmed_prefix = prefix.trim_matches('/');
        let prefix_opt = if trimmed_prefix.is_empty() {
            None
        } else {
            Some(trimmed_prefix)
        };
        let store = naust_storage_s3::S3ObjectStore::new(client, prefix_opt)
            .map_err(|e| StorageError::configuration(e.to_string()))?;
        Ok(Arc::new(store))
    }
    async fn copy_object(
        &self,
        src_bucket: &str,
        src_key: &str,
        dst_bucket: &str,
        dst_key: &str,
    ) -> Result<(), StorageError> {
        self.inner
            .copy_object(src_bucket, src_key, dst_bucket, dst_key)
            .await
    }
    async fn list_objects_v2(
        &self,
        bucket: &str,
        prefix: &str,
    ) -> Result<Vec<S3ObjectSummary>, StorageError> {
        self.inner.list_objects_v2(bucket, prefix).await
    }
    async fn list_objects_v2_page(
        &self,
        bucket: &str,
        prefix: &str,
        continuation_token: Option<&str>,
        max_keys: i32,
    ) -> Result<S3ObjectsPage, StorageError> {
        self.inner
            .list_objects_v2_page(bucket, prefix, continuation_token, max_keys)
            .await
    }
    fn now_unix_secs(&self) -> u64 {
        self.inner.now_unix_secs()
    }
}
