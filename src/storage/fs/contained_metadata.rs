//! Experimental Linux descriptor-relative metadata reader (O-05 characterization / exploration).
//!
//! Evaluates kernel-enforced descriptor-relative path resolution via Linux `openat2`
//! with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
//!
//! This module is compiled strictly for Linux under `test` and is not wired into production.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Minimal private error representation distinguishing causal failure modes.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ContainedMetadataError {
    #[error("invalid relative path: {0}")]
    InvalidInput(String),

    #[error("object not found: {0}")]
    NotFound(#[source] std::io::Error),

    #[error(
        "resolution rejected by kernel containment policy (raw OS error {raw_os_error}): {source}"
    )]
    ResolutionRejected {
        raw_os_error: i32,
        #[source]
        source: std::io::Error,
    },

    #[error("unsupported object type (mode: {mode:#o})")]
    UnsupportedObjectType { mode: u32 },

    #[error("openat2 syscall unsupported on this kernel: {0}")]
    SyscallUnsupported(#[source] std::io::Error),

    #[error("operating system error: {0}")]
    OsError(#[source] std::io::Error),
}

/// Classifies raw OS errors returned by `openat2` without classifying from rendered strings.
pub(crate) fn classify_openat2_error(err: std::io::Error) -> ContainedMetadataError {
    match err.raw_os_error() {
        Some(libc::ENOSYS) => ContainedMetadataError::SyscallUnsupported(err),
        Some(libc::ENOENT) => ContainedMetadataError::NotFound(err),
        Some(libc::EXDEV) | Some(libc::ELOOP) => ContainedMetadataError::ResolutionRejected {
            raw_os_error: err.raw_os_error().unwrap(),
            source: err,
        },
        _ => ContainedMetadataError::OsError(err),
    }
}

/// Validates relative hierarchical lookup input.
///
/// Rejects empty input, absolute paths, `.` and `..` segments, repeated separators,
/// trailing separators, and embedded NUL without silently normalizing them away.
pub(crate) fn validate_relative_path(path: &str) -> Result<(), ContainedMetadataError> {
    if path.is_empty() {
        return Err(ContainedMetadataError::InvalidInput(
            "path must not be empty".to_string(),
        ));
    }
    if path.starts_with('/') {
        return Err(ContainedMetadataError::InvalidInput(
            "absolute paths rejected".to_string(),
        ));
    }
    if path.ends_with('/') {
        return Err(ContainedMetadataError::InvalidInput(
            "trailing separators rejected".to_string(),
        ));
    }
    if path.contains('\0') {
        return Err(ContainedMetadataError::InvalidInput(
            "embedded NUL rejected".to_string(),
        ));
    }
    for segment in path.split('/') {
        if segment.is_empty() {
            return Err(ContainedMetadataError::InvalidInput(
                "empty segment or repeated separators rejected".to_string(),
            ));
        }
        if segment == "." {
            return Err(ContainedMetadataError::InvalidInput(
                "current directory '.' segment rejected".to_string(),
            ));
        }
        if segment == ".." {
            return Err(ContainedMetadataError::InvalidInput(
                "parent directory '..' segment rejected".to_string(),
            ));
        }
    }
    Ok(())
}

/// Validates the inspected descriptor's file type and size.
///
/// Only regular files (`S_IFREG`) are accepted. Any other object type (directories,
/// symlinks, FIFOs, sockets, character/block devices) is rejected at the application level
/// as `UnsupportedObjectType { mode }` without fabricating a causal OS error.
pub(crate) fn check_file_type_and_size(st: &libc::stat) -> Result<u64, ContainedMetadataError> {
    let mode_type = st.st_mode & libc::S_IFMT;
    if mode_type != libc::S_IFREG {
        return Err(ContainedMetadataError::UnsupportedObjectType {
            mode: st.st_mode as u32,
        });
    }

    // Checked size conversion from signed off_t to u64
    u64::try_from(st.st_size).map_err(|_| {
        ContainedMetadataError::OsError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "negative file size in metadata",
        ))
    })
}

/// An owned directory descriptor serving as a pinned root authority.
#[derive(Debug)]
pub(crate) struct PinnedRoot {
    fd: OwnedFd,
}

impl PinnedRoot {
    /// Opens an existing configured directory once and retains an owned descriptor.
    ///
    /// Does not create the directory. An initial symlink at the root may resolve during
    /// this call, after which the acquired descriptor becomes the sole pinned authority.
    pub(crate) fn open(path: &Path) -> Result<Self, ContainedMetadataError> {
        if path.as_os_str().is_empty() {
            return Err(ContainedMetadataError::InvalidInput(
                "root path must not be empty".to_string(),
            ));
        }
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            ContainedMetadataError::InvalidInput("root path contains embedded NUL".to_string())
        })?;

        let raw_fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_DIRECTORY | libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::ENOENT) => Err(ContainedMetadataError::NotFound(err)),
                _ => Err(ContainedMetadataError::OsError(err)),
            };
        }

        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(Self { fd })
    }

    /// Queries the byte size of a regular file relative to the pinned root.
    ///
    /// Resolves beneath the root using `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`,
    /// and `RESOLVE_NO_MAGICLINKS`. Enforces regular-file type and returns size as `u64`.
    pub(crate) fn metadata_size(&self, relative_path: &str) -> Result<u64, ContainedMetadataError> {
        validate_relative_path(relative_path)?;

        let c_rel = CString::new(relative_path).map_err(|_| {
            ContainedMetadataError::InvalidInput("relative path contains embedded NUL".to_string())
        })?;

        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
        how.mode = 0;
        how.resolve = (libc::RESOLVE_BENEATH
            | libc::RESOLVE_NO_SYMLINKS
            | libc::RESOLVE_NO_MAGICLINKS) as u64;

        let res = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                self.fd.as_raw_fd(),
                c_rel.as_ptr(),
                &how,
                std::mem::size_of::<libc::open_how>(),
            )
        };

        if res < 0 {
            let err = std::io::Error::last_os_error();
            return Err(classify_openat2_error(err));
        }

        // OwnedFd ensures target descriptor is closed reliably on any exit path
        let target_fd = unsafe { OwnedFd::from_raw_fd(res as i32) };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let stat_res = unsafe { libc::fstat(target_fd.as_raw_fd(), &mut st) };
        if stat_res != 0 {
            return Err(ContainedMetadataError::OsError(
                std::io::Error::last_os_error(),
            ));
        }

        check_file_type_and_size(&st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contained_metadata_empty_and_nonempty_and_sparse_files() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let pinned = PinnedRoot::open(&root_dir).expect("open root");

        // 1. Empty file
        let empty_path = root_dir.join("empty.bin");
        std::fs::write(&empty_path, b"").expect("write empty file");
        assert_eq!(pinned.metadata_size("empty.bin").unwrap(), 0);

        // 2. Nonempty file
        let nonempty_path = root_dir.join("nonempty.bin");
        let content = b"hello contained linux world";
        std::fs::write(&nonempty_path, content).expect("write nonempty file");
        assert_eq!(
            pinned.metadata_size("nonempty.bin").unwrap(),
            content.len() as u64
        );

        // 3. Sparse file above u32::MAX (8 GiB)
        let sparse_path = root_dir.join("sparse.bin");
        let sparse_file = std::fs::File::create(&sparse_path).expect("create sparse file");
        let expected_size: u64 = 8_589_934_592; // 8 GiB
        sparse_file
            .set_len(expected_size)
            .expect("set sparse length");
        assert_eq!(pinned.metadata_size("sparse.bin").unwrap(), expected_size);
    }

    #[test]
    fn test_contained_metadata_invalid_relative_inputs() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let pinned = PinnedRoot::open(&root_dir).expect("open root");

        let invalid_inputs = [
            "",
            "/absolute/path",
            "trailing/slash/",
            "repeated//slash",
            "curdir/./segment",
            "parent/../segment",
            "embedded\0null",
            ".",
            "..",
        ];

        for input in invalid_inputs {
            let res = pinned.metadata_size(input);
            assert!(
                matches!(res, Err(ContainedMetadataError::InvalidInput(_))),
                "input {input:?} must yield InvalidInput error, got {res:?}"
            );
        }
    }

    #[test]
    fn test_contained_metadata_missing_object_vs_rejected_symlink() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let pinned = PinnedRoot::open(&root_dir).expect("open root");

        // 1. Missing object yields NotFound
        let missing_res = pinned.metadata_size("does_not_exist.bin");
        assert!(
            matches!(missing_res, Err(ContainedMetadataError::NotFound(_))),
            "missing object must yield NotFound, got {missing_res:?}"
        );

        // 2. Symlink yields ResolutionRejected (not NotFound)
        let target = root_dir.join("real_file.bin");
        std::fs::write(&target, b"payload").expect("write target");
        let link = root_dir.join("symlink.bin");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let symlink_res = pinned.metadata_size("symlink.bin");
        assert!(
            matches!(
                symlink_res,
                Err(ContainedMetadataError::ResolutionRejected {
                    raw_os_error: libc::ELOOP,
                    ..
                })
            ),
            "symlink must yield ResolutionRejected with ELOOP, got {symlink_res:?}"
        );
    }

    #[test]
    fn test_contained_metadata_final_symlinks_rejected() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        let outside_dir = fixture.path().join("outside");
        std::fs::create_dir_all(&root_dir).expect("create root");
        std::fs::create_dir_all(&outside_dir).expect("create outside");
        let pinned = PinnedRoot::open(&root_dir).expect("open root");

        // Inside-root target
        let inside_target = root_dir.join("inside_target.bin");
        std::fs::write(&inside_target, b"inside").expect("write inside");
        let inside_link = root_dir.join("inside_link.bin");
        std::os::unix::fs::symlink(&inside_target, &inside_link).expect("create inside link");

        // Outside-root target
        let outside_target = outside_dir.join("outside_target.bin");
        std::fs::write(&outside_target, b"outside").expect("write outside");
        let outside_link = root_dir.join("outside_link.bin");
        std::os::unix::fs::symlink(&outside_target, &outside_link).expect("create outside link");

        // Dangling target
        let dangling_link = root_dir.join("dangling_link.bin");
        std::os::unix::fs::symlink(root_dir.join("missing.bin"), &dangling_link)
            .expect("create dangling link");

        for link_name in ["inside_link.bin", "outside_link.bin", "dangling_link.bin"] {
            let res = pinned.metadata_size(link_name);
            assert!(
                matches!(res, Err(ContainedMetadataError::ResolutionRejected { .. })),
                "final symlink {link_name} must be rejected, got {res:?}"
            );
        }
    }

    #[test]
    fn test_contained_metadata_intermediate_dir_symlink_rejected() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        let outside_dir = fixture.path().join("outside");
        std::fs::create_dir_all(&root_dir).expect("create root");
        std::fs::create_dir_all(&outside_dir).expect("create outside");
        let pinned = PinnedRoot::open(&root_dir).expect("open root");

        // Create target file outside root
        let outside_file = outside_dir.join("secret.bin");
        std::fs::write(&outside_file, b"secret content").expect("write outside file");

        // Intermediate symlink inside root pointing to outside dir
        let inter_link = root_dir.join("sub_link");
        std::os::unix::fs::symlink(&outside_dir, &inter_link)
            .expect("create intermediate dir symlink");

        let res = pinned.metadata_size("sub_link/secret.bin");
        assert!(
            matches!(res, Err(ContainedMetadataError::ResolutionRejected { .. })),
            "intermediate symlink must be rejected by kernel resolution policy, got {res:?}"
        );
    }

    #[test]
    fn test_contained_metadata_directory_and_fifo_rejected() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let root_dir = fixture.path().join("root");
        std::fs::create_dir_all(&root_dir).expect("create root");
        let pinned = PinnedRoot::open(&root_dir).expect("open root");

        // 1. Directory rejection
        let sub_dir = root_dir.join("a_directory");
        std::fs::create_dir_all(&sub_dir).expect("create dir");
        let dir_res = pinned.metadata_size("a_directory");
        match dir_res {
            Err(ContainedMetadataError::UnsupportedObjectType { mode }) => {
                assert_eq!(
                    mode & libc::S_IFMT,
                    libc::S_IFDIR,
                    "mode must indicate directory"
                );
            }
            other => panic!("directory must yield UnsupportedObjectType, got {other:?}"),
        }

        // 2. FIFO rejection without blocking
        let fifo_path = root_dir.join("test_fifo");
        let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        let mkfifo_res = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o644) };
        assert_eq!(
            mkfifo_res,
            0,
            "mkfifo failed: {}",
            std::io::Error::last_os_error()
        );

        let fifo_res = pinned.metadata_size("test_fifo");
        match fifo_res {
            Err(ContainedMetadataError::UnsupportedObjectType { mode }) => {
                assert_eq!(
                    mode & libc::S_IFMT,
                    libc::S_IFIFO,
                    "mode must indicate FIFO"
                );
            }
            other => panic!("FIFO must yield UnsupportedObjectType, got {other:?}"),
        }
    }

    #[test]
    fn test_contained_metadata_root_pinning() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let orig_root = fixture.path().join("storage_root");
        std::fs::create_dir_all(&orig_root).expect("create orig root");

        let original_file = orig_root.join("data.bin");
        let original_content = b"original root content";
        std::fs::write(&original_file, original_content).expect("write original file");

        // Pin the root descriptor
        let pinned = PinnedRoot::open(&orig_root).expect("open original root");

        // Rename the original directory
        let renamed_root = fixture.path().join("renamed_storage_root");
        std::fs::rename(&orig_root, &renamed_root).expect("rename root dir");

        // Create a new replacement directory at the original pathname with different file
        std::fs::create_dir_all(&orig_root).expect("create replacement root");
        let replacement_file = orig_root.join("data.bin");
        let replacement_content = b"attacker replacement data with distinct length";
        std::fs::write(&replacement_file, replacement_content).expect("write replacement file");

        // Lookup through pinned root must refer to the original pinned directory
        let size = pinned
            .metadata_size("data.bin")
            .expect("metadata query on pinned root");
        assert_eq!(
            size,
            original_content.len() as u64,
            "pinned root must inspect original directory, not new directory at old pathname"
        );
    }

    #[test]
    fn test_contained_metadata_configured_root_symlink_initialization() {
        let fixture = tempfile::tempdir().expect("create fixture");
        let real_dir = fixture.path().join("real_target_dir");
        let symlink_dir = fixture.path().join("symlink_root");
        std::fs::create_dir_all(&real_dir).expect("create real dir");

        let file_path = real_dir.join("file.bin");
        let content = b"resolved through root symlink";
        std::fs::write(&file_path, content).expect("write file");

        std::os::unix::fs::symlink(&real_dir, &symlink_dir).expect("create root symlink");

        // Initial open follows the configured root symlink and pins the target directory
        let pinned = PinnedRoot::open(&symlink_dir).expect("open via symlink");
        assert_eq!(
            pinned.metadata_size("file.bin").unwrap(),
            content.len() as u64
        );

        // Even if symlink_dir is removed, pinned root retains open descriptor authority
        std::fs::remove_file(&symlink_dir).expect("remove symlink");
        assert_eq!(
            pinned.metadata_size("file.bin").unwrap(),
            content.len() as u64
        );
    }

    #[test]
    fn test_contained_metadata_synthetic_error_classification() {
        // Synthetic evidence: verifies raw OS error classification for openat2
        // ENOSYS -> SyscallUnsupported
        let enosys = std::io::Error::from_raw_os_error(libc::ENOSYS);
        assert!(matches!(
            classify_openat2_error(enosys),
            ContainedMetadataError::SyscallUnsupported(_)
        ));

        // ENOENT -> NotFound
        let enoent = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert!(matches!(
            classify_openat2_error(enoent),
            ContainedMetadataError::NotFound(_)
        ));

        // EXDEV / ELOOP -> ResolutionRejected
        let exdev = std::io::Error::from_raw_os_error(libc::EXDEV);
        assert!(matches!(
            classify_openat2_error(exdev),
            ContainedMetadataError::ResolutionRejected {
                raw_os_error: libc::EXDEV,
                ..
            }
        ));

        let eloop = std::io::Error::from_raw_os_error(libc::ELOOP);
        assert!(matches!(
            classify_openat2_error(eloop),
            ContainedMetadataError::ResolutionRejected {
                raw_os_error: libc::ELOOP,
                ..
            }
        ));

        // EINVAL and EPERM must NOT be misclassified as SyscallUnsupported
        let einval = std::io::Error::from_raw_os_error(libc::EINVAL);
        assert!(matches!(
            classify_openat2_error(einval),
            ContainedMetadataError::OsError(_)
        ));

        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(matches!(
            classify_openat2_error(eperm),
            ContainedMetadataError::OsError(_)
        ));
    }

    #[test]
    fn test_contained_metadata_synthetic_descriptor_type_safeguard() {
        // Synthetic evidence: verifies application-level descriptor-type safeguard logic
        // if an opened descriptor were ever to reference a symlink or other non-regular file,
        // without altering production syscall flags or executing an actual symlink open.
        let mut symlink_stat: libc::stat = unsafe { std::mem::zeroed() };
        symlink_stat.st_mode = libc::S_IFLNK | 0o777;
        symlink_stat.st_size = 42;

        let res = check_file_type_and_size(&symlink_stat);
        match res {
            Err(ContainedMetadataError::UnsupportedObjectType { mode }) => {
                assert_eq!(
                    mode & libc::S_IFMT,
                    libc::S_IFLNK,
                    "synthetic symlink mode must be preserved in UnsupportedObjectType"
                );
            }
            other => {
                panic!("expected UnsupportedObjectType for synthetic symlink stat, got {other:?}")
            }
        }

        // Synthetic regular file stat
        let mut reg_stat: libc::stat = unsafe { std::mem::zeroed() };
        reg_stat.st_mode = libc::S_IFREG | 0o644;
        reg_stat.st_size = 1234;
        assert_eq!(check_file_type_and_size(&reg_stat).unwrap(), 1234);

        // Synthetic directory stat
        let mut dir_stat: libc::stat = unsafe { std::mem::zeroed() };
        dir_stat.st_mode = libc::S_IFDIR | 0o755;
        match check_file_type_and_size(&dir_stat) {
            Err(ContainedMetadataError::UnsupportedObjectType { mode }) => {
                assert_eq!(mode & libc::S_IFMT, libc::S_IFDIR);
            }
            other => panic!("expected UnsupportedObjectType for synthetic dir stat, got {other:?}"),
        }

        // Synthetic negative size check
        let mut neg_stat: libc::stat = unsafe { std::mem::zeroed() };
        neg_stat.st_mode = libc::S_IFREG | 0o644;
        neg_stat.st_size = -1;
        assert!(matches!(
            check_file_type_and_size(&neg_stat),
            Err(ContainedMetadataError::OsError(_))
        ));
    }
}
