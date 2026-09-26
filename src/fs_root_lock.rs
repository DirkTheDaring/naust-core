use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

pub struct FsRootLock {
    _file: File,
}

impl FsRootLock {
    pub fn try_acquire(fs_root: &Path) -> Result<Self, String> {
        let locks_dir = fs_root.join(".locks");
        std::fs::create_dir_all(&locks_dir)
            .map_err(|e| format!("failed to create {}: {e}", locks_dir.display()))?;

        let lock_path = locks_dir.join("naust.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| format!("failed to open {}: {e}", lock_path.display()))?;

        file.try_lock_exclusive()
            .map_err(|e| format!("failed to acquire lock {}: {e}", lock_path.display()))?;

        // Best-effort: write some debug context (PID). Ignore errors.
        let mut file_for_write = &file;
        let _ = file_for_write.set_len(0);
        let _ = file_for_write.write_all(format!("pid={}\n", std::process::id()).as_bytes());

        let _ = lock_path; // keep in scope for error strings above

        Ok(Self { _file: file })
    }
}
