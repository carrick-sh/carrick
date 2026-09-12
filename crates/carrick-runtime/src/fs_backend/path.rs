//! Path and dentry normalization and inspection helpers.
//!
//! Sandboxed filesystem operations require relative, normalized paths with
//! leading slashes and `.`/`..` components resolved within the rootfs sandbox.
//! This module provides [`NormalizedRelPath`] and path resolution utilities
//! used across Carrick's filesystem backends.

use crate::linux_abi::LinuxErrno;
use std::path::{Component, Path, PathBuf};

/// Strip a leading `/` and collapse `.` / `..` so the backend's
/// internal keys match what `RootFs::normalize_rootfs_path` would
/// produce. Returns `None` for paths that would escape the rootfs
/// (`/../something`).
pub fn normalize(path: &str) -> Option<PathBuf> {
    // `path` arrives in the VFS layer's reversible escape form (see
    // `crate::pathcodec`): undecodable guest path bytes are carried as PUA
    // scalars so the `&str`-based layer can hold them. We KEEP that encoded form
    // as the on-disk host name — macOS APFS rejects a raw non-UTF-8 filename
    // with EILSEQ (errno 92), so a guest's opaque `b"\xff"` cannot be stored
    // byte-for-byte. The PUA escape is valid UTF-8 (APFS-storable) AND
    // reversible, so it's our durable host representation of an undecodable
    // name. The escape is decoded back to the raw guest bytes only at the
    // GUEST-facing read-back boundaries (getdents/readlink/getcwd), so the
    // guest still sees `b"\xff"` and a re-open by those bytes round-trips.
    // Valid-UTF-8 paths encode to themselves (fast path, allocation-free).
    normalize_raw(Path::new(path))
}

/// Component-normalize a path whose components are already in the host's
/// canonical on-disk form (the VFS escape encoding, or plain UTF-8). Used for a
/// path that must NOT be re-encoded (e.g. a symlink target read back from the
/// host, which is already in the encoded form).
pub fn normalize_raw(raw: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in raw.components() {
        match component {
            Component::Prefix(_) => return None,
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(name) => out.push(name),
        }
    }
    Some(out)
}

/// A path that is already normalized relative to the sandbox/rootfs root (no
/// leading `/`, no `.` or `..` components). Bypasses redundant re-normalization
/// passes and component splits when passed from the dentry layer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormalizedRelPath(PathBuf);

impl NormalizedRelPath {
    /// Construct from a path known to already be normalized and relative to root.
    pub fn from_normalized_relative(path: PathBuf) -> Self {
        Self(path)
    }

    /// Construct from an already-normalized string (e.g. from dentry cache),
    /// stripping a leading `/` if present without running component normalization.
    pub fn from_normalized_str(s: &str) -> Self {
        let stripped = s.strip_prefix('/').unwrap_or(s);
        let trimmed = stripped.trim_end_matches('/');
        Self(PathBuf::from(trimmed))
    }

    /// Construct by running `normalize()` if not already normalized.
    pub fn from_raw(s: &str) -> Option<Self> {
        normalize(s).map(Self)
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn parent(&self) -> Option<&Path> {
        self.0.parent()
    }

    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.0.file_name()
    }

    pub fn file_name_c(&self) -> Option<std::ffi::CString> {
        self.file_name().and_then(cstring_from_osstr)
    }
}

impl AsRef<Path> for NormalizedRelPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for NormalizedRelPath {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Build a NUL-terminated C path from a raw host `OsStr` *by its bytes* —
/// unlike `CString::new(os.to_str()?)`, this does not reject a legitimate
/// non-UTF-8 (undecodable) filename that Linux lets the guest create. Returns
/// `None` only if the bytes contain an interior NUL (impossible for a real
/// path component).
#[cfg(unix)]
pub(super) fn cstring_from_osstr(os: &std::ffi::OsStr) -> Option<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(os.as_bytes()).ok()
}

pub(super) fn io_error_to_linux_errno(error: std::io::Error) -> LinuxErrno {
    crate::host_to_linux_errno(error.raw_os_error().unwrap_or(libc::EIO))
}

pub(super) fn open_host_watch_fd(path: &Path) -> Result<i32, LinuxErrno> {
    let cpath = cstring_from_osstr(path.as_os_str()).ok_or(crate::linux_abi::LINUX_EINVAL)?;
    #[cfg(target_os = "macos")]
    let host_flags = libc::O_EVTONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
    #[cfg(not(target_os = "macos"))]
    let host_flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC;
    // SAFETY: `cpath` is NUL-terminated and points at a real host path.
    let fd = unsafe { libc::open(cpath.as_ptr(), host_flags) };
    if fd < 0 {
        let raw = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return Err(crate::host_to_linux_errno(raw));
    }
    Ok(fd)
}

pub(super) fn dup_host_watch_fd(fd: i32) -> Result<i32, LinuxErrno> {
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        let raw = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EMFILE);
        return Err(crate::host_to_linux_errno(raw));
    }
    Ok(dup)
}

pub(super) fn child_name(prefix: &Path, candidate: &Path) -> Option<String> {
    let stripped = candidate.strip_prefix(prefix).ok()?;
    let mut components = stripped.components();
    let first = components.next()?;
    if components.next().is_some() {
        return None;
    }
    let Component::Normal(name) = first else {
        return None;
    };
    // The on-disk name is already in the host's canonical form (the VFS escape
    // encoding for an undecodable name, else plain UTF-8) — both are valid
    // UTF-8. Carry it through unchanged; the guest-facing getdents decodes it.
    Some(name.to_string_lossy().into_owned())
}
