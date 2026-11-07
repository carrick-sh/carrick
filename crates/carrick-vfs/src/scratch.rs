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

/// Admit the shared resolver's choice once before starting a gate's tests.
pub fn preflight_default() -> std::io::Result<()> {
    preflight_selected(crate::apfs::preferred_scratch_root())
}

pub(crate) fn preflight_selected(root: &ScratchRoot) -> std::io::Result<()> {
    root.host_path().map(|_| ()).map_err(|error| {
        std::io::Error::other(format!(
            "failed scratch preflight: {error}; set CARRICK_HOME to an internal case-sensitive directory"
        ))
    })
}

// The conventional APFS mount is a macOS-only default. On other hosts it is
// never automatically admitted; explicit configuration remains authoritative.
#[cfg(not(target_os = "macos"))]
pub(crate) fn internal_volume(_: &Path) -> bool {
    false
}

#[cfg(target_os = "macos")]
pub(crate) fn internal_volume(path: &Path) -> bool {
    use core_foundation_sys::{array::*, base::*, dictionary::*, number::*, url::*};
    let bytes = path.as_os_str().as_encoded_bytes();
    // SAFETY: all CF objects are checked for NULL, borrowed only while their
    // owner lives, and released according to the Create/Copy ownership rule.
    // These public keys describe the device bus and removable media, without
    // launching diskutil or enumerating APFS containers. See Apple's CFURL
    // Volume Property Keys documentation. This runs inside the probe deadline.
    unsafe {
        let url = CFURLCreateFromFileSystemRepresentation(
            std::ptr::null(),
            bytes.as_ptr(),
            bytes.len() as CFIndex,
            1,
        );
        if url.is_null() {
            return false;
        }
        let keys = [
            kCFURLVolumeIsInternalKey.cast(),
            kCFURLVolumeIsRemovableKey.cast(),
        ];
        let array = CFArrayCreate(std::ptr::null(), keys.as_ptr(), 2, &kCFTypeArrayCallBacks);
        if array.is_null() {
            CFRelease(url.cast());
            return false;
        }
        let properties = CFURLCopyResourcePropertiesForKeys(url, array, std::ptr::null_mut());
        let accepted = if properties.is_null() {
            false
        } else {
            let internal = CFDictionaryGetValue(properties, kCFURLVolumeIsInternalKey.cast());
            let removable = CFDictionaryGetValue(properties, kCFURLVolumeIsRemovableKey.cast());
            // CFBoolean values are singletons. Missing/unknown values reject
            // the candidate as well as an external bus (including USB).
            let result = internal == kCFBooleanTrue.cast() && removable == kCFBooleanFalse.cast();
            CFRelease(properties.cast());
            result
        };
        CFRelease(array.cast());
        CFRelease(url.cast());
        accepted
    }
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
/// prevents repeated workers on subsequent backend construction. Automatic conventional-volume admission requires internal storage; an explicit
/// CARRICK_HOME must also avoid cold storage.
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
