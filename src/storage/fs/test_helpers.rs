//! Shared FS test helpers. Available to core unit tests and, behind the
//! `test-mocks` feature, to downstream crates' test builds (ADR-010).

use super::*;
use crate::registry::digest::Digest;
use crate::storage::upload_session::{
    PreparedFinalize, UploadByteStream, UploadOffsetPrecondition, UploadSessionId,
    UploadSessionStorage,
};
use bytes::Bytes;
use std::path::{Path, PathBuf};

pub fn tmp_fs_root() -> PathBuf {
    let p = std::env::temp_dir().join(format!("naust-fsstorage-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&p).expect("create temp fs_root");
    p
}

pub fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent dirs");
    }
    std::fs::write(path, bytes).expect("write file");
}

pub fn make_test_stream(chunks: Vec<Bytes>) -> UploadByteStream {
    let items: Vec<Result<Bytes, UploadStreamError>> = chunks.into_iter().map(Ok).collect();
    Box::pin(futures_util::stream::iter(items))
}

pub async fn prepare_finalizable_session(
    storage: &FsStorage,
    repo: &str,
    data: &[u8],
) -> (UploadSessionId, PreparedFinalize, Digest) {
    let session = storage.create_session(repo).await.unwrap();
    let stream = make_test_stream(vec![Bytes::copy_from_slice(data)]);
    storage
        .append_if_offset(
            &session,
            UploadOffsetPrecondition::Exact(0),
            stream,
            1024 * 1024,
        )
        .await
        .unwrap();

    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    let digest = Digest::parse(&format!("sha256:{}", hex::encode(hasher.finalize()))).unwrap();

    let prepared = storage
        .begin_finalize(
            &session,
            UploadOffsetPrecondition::Exact(data.len() as u64),
            None,
            &digest,
            1024 * 1024,
            true,
        )
        .await
        .unwrap();
    (session, prepared, digest)
}

/// ext4 immediately reuses freed inode numbers, so a remove-then-recreate at
/// the same path can yield the SAME identity and defeat swap-scenario staging
/// (btrfs, by contrast, never reuses inode numbers). Consume the just-freed
/// inode with a keeper entry created in `parent`; callers remove the keeper
/// once the real replacement exists.
pub fn occupy_freed_inode(parent: &Path) -> PathBuf {
    let keeper = parent.join(".inode-keeper");
    std::fs::write(&keeper, b"inode keeper").unwrap();
    keeper
}
