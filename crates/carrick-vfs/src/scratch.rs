//! Shared, bounded admission for case-sensitive runtime scratch.

use std::path::{Path, PathBuf};

/// Validate exactly the configured home without consulting conventional mounts.
/// Directory creation, case checking and cleanup share the resolver deadline.
pub fn preflight_home(home: &Path) -> std::io::Result<()> {
    if home.as_os_str().is_empty() {
        return Err(std::io::Error::other(
            "CARRICK_HOME must name an internal case-sensitive directory",
        ));
    }
    checked_scratch_root(home.join("scratch"), true, probe_scratch_root)
        .host_path()
        .map(|_| ())
        .map_err(|error| std::io::Error::other(format!(
            "CARRICK_HOME={} failed scratch preflight: {error}; set CARRICK_HOME to an internal case-sensitive directory (probe deadline: 2 seconds)",
            home.display()
        )))
}

/// The selected scratch path and its case-sensitivity decision, checked once.
pub struct ScratchRoot {
    path: PathBuf,
    pub(crate) case_sensitive: bool,
}

impl ScratchRoot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Refuse host-backed Linux paths unless the selected root passed the probe.
    pub fn host_path(&self) -> std::io::Result<&Path> {
        if self.case_sensitive {
            Ok(&self.path)
        } else {
            Err(std::io::Error::other(format!(
                "scratch root {} is not usable as a case-sensitive filesystem",
                self.path.display()
            )))
        }
    }
}

pub(crate) fn checked_scratch_root(
    path: PathBuf,
    create: bool,
    probe: impl FnOnce(&Path, bool) -> bool + Send + 'static,
) -> ScratchRoot {
    let candidate = path.clone();
    let case_sensitive = bounded_probe(std::time::Duration::from_secs(2), move || {
        probe(&candidate, create)
    });
    ScratchRoot {
        path,
        case_sensitive,
    }
}

pub(crate) fn probe_scratch_root(path: &Path, create: bool) -> bool {
    (!create || std::fs::create_dir_all(path).is_ok()) && probe_case_sensitive_unbounded(path)
}

/// Probe with exclusive nonblocking creation. Existing files (including FIFOs,
/// devices and symlinks) are unusable and must never be opened or removed.
/// O_NONBLOCK prevents FIFO rendezvous; it does not bound filesystem device I/O.
/// The caller waits at most two seconds, including directory creation and cleanup.
/// A stalled filesystem worker is detached; the process-wide ScratchRoot cache
/// prevents repeated workers on subsequent backend construction. Gate hosts still
/// select an internal root with CARRICK_HOME to avoid touching cold storage.
fn bounded_probe(
    timeout: std::time::Duration,
    probe: impl FnOnce() -> bool + Send + 'static,
) -> bool {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let Ok(_worker) = std::thread::Builder::new()
        .name("scratch-case-probe".into())
        .spawn(move || {
            let _ = sender.send(probe());
        })
    else {
        return false;
    };
    receiver.recv_timeout(timeout).unwrap_or(false)
}

#[cfg(test)]
pub(crate) fn probe_case_sensitive(path: &Path) -> bool {
    let path = path.to_owned();
    bounded_probe(std::time::Duration::from_secs(2), move || {
        probe_case_sensitive_unbounded(&path)
    })
}

pub(crate) fn probe_case_sensitive_unbounded(path: &Path) -> bool {
    // A private namespace prevents simultaneous startups from treating each
    // other's live sentinel as an unusable filesystem.
    let Ok(directory) = tempfile::Builder::new()
        .prefix(".carrick-case-")
        .tempdir_in(path)
    else {
        return false;
    };
    probe_case_sensitive_in(directory.path())
}

pub(crate) fn probe_case_sensitive_in(path: &Path) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    let lower = path.join(".carrick-case-probe");
    let upper = path.join(".CARRICK-case-probe");
    let Ok(file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_EXCL)
        .open(&lower)
    else {
        return false;
    };
    let regular = file.metadata().is_ok_and(|metadata| metadata.is_file());
    let metadata_upper = std::fs::metadata(&upper);
    let _ = std::fs::remove_file(&lower);
    // On case-sensitive: upper doesn't exist → Err.
    // On case-insensitive: upper opens the same inode as lower → Ok.
    regular && matches!(metadata_upper, Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}
