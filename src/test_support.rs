//! Narrow test-support interface for integration and golden tests.
//!
//! Internal storage codecs and addressing functions are `pub(crate)` within the crate,
//! but exposed here with `#[doc(hidden)]` to allow deterministic golden tests to verify
//! addressing stability without making backend addressing internals part of the public API.

use crate::registry::canonical_name::CanonicalRepoName;
use crate::registry::digest::Digest;
use crate::storage::StorageError;
use crate::storage::repo_membership::RepoKeyDecodeError;
use std::path::{Path, PathBuf};

pub fn fs_repo_dir(base_root: &Path, repo: &CanonicalRepoName) -> Result<PathBuf, StorageError> {
    crate::storage::fs::fs_repo_dir(base_root, repo)
}

pub fn s3_repo_prefix(root_prefix: &str, repo: &CanonicalRepoName) -> String {
    crate::storage::s3::s3_repo_prefix(root_prefix, repo)
}

pub fn encode_canonical_repo_key(repo: &CanonicalRepoName) -> String {
    crate::storage::repo_membership::encode_canonical_repo_key(repo)
}

pub fn decode_canonical_repo_key(encoded: &str) -> Result<CanonicalRepoName, RepoKeyDecodeError> {
    crate::storage::repo_membership::decode_canonical_repo_key(encoded)
}

pub fn canonical_repo_membership_relpath(repo: &CanonicalRepoName, digest: &Digest) -> String {
    crate::storage::repo_membership::canonical_repo_membership_relpath(repo, digest)
}

pub fn canonical_repo_membership_prefix(repo: &CanonicalRepoName) -> String {
    crate::storage::repo_membership::canonical_repo_membership_prefix(repo)
}

pub fn canonical_all_memberships_prefix() -> &'static str {
    crate::storage::repo_membership::canonical_all_memberships_prefix()
}

pub fn push_repository_allowed(
    allowlist: &[crate::registry::RepositoryAccessPattern],
    repo: &CanonicalRepoName,
) -> bool {
    crate::registry::access_pattern::push_repository_allowed(allowlist, repo)
}
