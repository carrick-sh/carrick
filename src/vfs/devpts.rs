//! `/dev/pts` mount + pseudo-terminal table. `/dev/ptmx` opens a real
//! macOS pty (posix_openpt); `/dev/pts/N` opens its slave. Master/slave
//! data I/O reuses the dispatcher's `HostPipe` open-description; this
//! module owns the index<->host-fd/slave-name mapping.

use std::collections::BTreeMap;
use std::ffi::CStr;

/// Tags a `HostPipe` open-description as a pty end so the ioctl handler
/// can synthesize `TIOCGPTN`/`TIOCSPTLCK` and passthrough termios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtyRole {
    pub index: u32,
    pub is_master: bool,
}

struct PtyEntry {
    host_slave_name: String,
    locked: bool,
    owner_pid: u32,
}

/// Maps a guest pts index to the macOS master fd + slave device name.
/// Shared (`Arc<Mutex<_>>`) between the `/dev/ptmx` handler, the
/// `/dev/pts` mount, and the dispatcher's close/ioctl paths.
pub struct PtyTable {
    next_index: u32,
    entries: BTreeMap<u32, PtyEntry>,
}

impl PtyTable {
    pub fn new() -> Self {
        Self {
            next_index: 0,
            entries: BTreeMap::new(),
        }
    }

    /// Record a freshly-opened pty's slave name and the pid that opened the
    /// master; returns the allocated index N.
    pub fn insert(&mut self, host_slave_name: String, owner_pid: u32) -> u32 {
        let n = self.next_index;
        self.next_index += 1;
        self.entries.insert(
            n,
            PtyEntry {
                host_slave_name,
                locked: true,
                owner_pid,
            },
        );
        n
    }

    pub fn slave_name(&self, n: u32) -> Option<String> {
        self.entries.get(&n).map(|e| e.host_slave_name.clone())
    }

    pub fn is_locked(&self, n: u32) -> bool {
        self.entries.get(&n).map(|e| e.locked).unwrap_or(false)
    }

    pub fn set_locked(&mut self, n: u32, locked: bool) {
        if let Some(e) = self.entries.get_mut(&n) {
            e.locked = locked;
        }
    }

    /// Live pts indices in ascending order (for `/dev/pts` readdir).
    pub fn live_indices(&self) -> Vec<u32> {
        self.entries.keys().copied().collect()
    }

    /// Drop an entry (master closed). Does not close the host fd — the
    /// dispatcher owns fd closing; this only updates the directory view.
    pub fn free(&mut self, n: u32) {
        self.entries.remove(&n);
    }

    /// Remove entry `n` only if `pid` opened it. A forked child that closes
    /// its inherited master must NOT remove the parent's entry (the per-process
    /// table is a fork copy); only the owning process's close frees it.
    pub fn free_if_owner(&mut self, n: u32, pid: u32) {
        if self.entries.get(&n).map(|e| e.owner_pid) == Some(pid) {
            self.entries.remove(&n);
        }
    }
}

impl Default for PtyTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Open a fresh macOS pty master: posix_openpt + grantpt + unlockpt,
/// then resolve the slave device name. `nonblock` adds O_NONBLOCK to
/// the master. Returns (master_fd, slave_name) or the raw macOS errno.
/// NOTE: `ptsname` is not thread-safe; callers serialize by holding the
/// PtyTable mutex across this call.
pub fn open_master(nonblock: bool) -> Result<(i32, String), i32> {
    let mut oflag = libc::O_RDWR | libc::O_NOCTTY;
    if nonblock {
        oflag |= libc::O_NONBLOCK;
    }
    // SAFETY: posix_openpt takes an int flag and returns an fd or -1.
    let master = unsafe { libc::posix_openpt(oflag) };
    if master < 0 {
        return Err(unsafe { *libc::__error() });
    }
    // SAFETY: master is a valid fd from posix_openpt.
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        let e = unsafe { *libc::__error() };
        unsafe { libc::close(master) };
        return Err(e);
    }
    // SAFETY: master is valid; ptsname returns a static C string or null.
    let name_ptr = unsafe { libc::ptsname(master) };
    if name_ptr.is_null() {
        let e = unsafe { *libc::__error() };
        unsafe { libc::close(master) };
        return Err(e);
    }
    // SAFETY: name_ptr is a valid NUL-terminated C string from ptsname.
    let slave_name = unsafe { CStr::from_ptr(name_ptr) }
        .to_string_lossy()
        .into_owned();
    Ok((master, slave_name))
}

// ── DevptsVfs ─────────────────────────────────────────────────────────────────

use super::{DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};
use crate::linux_abi::{LINUX_ENOENT, LINUX_ENOTDIR};
use parking_lot::Mutex;
use std::ffi::CString;
use std::sync::Arc;

/// VFS mount for `/dev/pts`. Serves directory metadata for `/dev/pts` itself
/// and `CharDevice` metadata + open for each live `/dev/pts/N` slave.
/// Shares its [`PtyTable`] with the `/dev` (DevVfs) mount so that a slave
/// opened here is the counterpart of a master opened via `/dev/ptmx`.
pub struct DevptsVfs {
    pty_table: Arc<Mutex<PtyTable>>,
}

impl DevptsVfs {
    pub fn new(pty_table: Arc<Mutex<PtyTable>>) -> Self {
        Self { pty_table }
    }

    fn parse_index(path: &str) -> Option<u32> {
        path.strip_prefix("/dev/pts/")?.parse().ok()
    }
}

impl Vfs for DevptsVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        if path == "/dev/pts" {
            return Ok(Metadata {
                kind: EntryKind::Directory,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        // /dev/pts/ptmx is the Linux devpts "clone" device — same semantics as
        // /dev/ptmx but mounted inside the pts filesystem.
        if path == "/dev/pts/ptmx" {
            return Ok(Metadata {
                kind: EntryKind::CharDevice,
                mode: 0o666,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        if let Some(n) = Self::parse_index(path)
            && self.pty_table.lock().slave_name(n).is_some()
        {
            return Ok(Metadata {
                kind: EntryKind::CharDevice,
                mode: 0o620,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        Err(LINUX_ENOENT)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        if path != "/dev/pts" {
            return Err(LINUX_ENOTDIR);
        }
        Ok(self
            .pty_table
            .lock()
            .live_indices()
            .into_iter()
            .map(|n| DirEnt {
                name: n.to_string(),
                kind: EntryKind::CharDevice,
            })
            .collect())
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        // /dev/pts/ptmx is the devpts-internal clone device for opening new pty
        // masters.  Redirect to open_master just like /dev/ptmx.
        if path == "/dev/pts/ptmx" {
            let mut table = self.pty_table.lock();
            let (master_fd, slave_name) =
                open_master(flags.nonblock).map_err(crate::dispatch::macos_to_linux_errno)?;
            let index = table.insert(slave_name, std::process::id());
            let status_flags = if flags.nonblock {
                crate::linux_abi::LINUX_O_NONBLOCK as u32
            } else {
                0
            };
            return Ok(VfsHandle::Pty {
                host_fd: master_fd,
                pts_index: index,
                is_master: true,
                status_flags,
            });
        }

        let n = Self::parse_index(path).ok_or(LINUX_ENOENT)?;
        let slave_name = self.pty_table.lock().slave_name(n).ok_or(LINUX_ENOENT)?;
        let mut oflag = if flags.read && flags.write {
            libc::O_RDWR
        } else if flags.write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
        oflag |= libc::O_NOCTTY;
        if flags.nonblock {
            oflag |= libc::O_NONBLOCK;
        }
        let cpath = CString::new(slave_name).map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        // SAFETY: cpath is a valid NUL-terminated path to a host slave pty device.
        let host_fd = unsafe { libc::open(cpath.as_ptr(), oflag) };
        if host_fd < 0 {
            return Err(super::dev::host_open_errno());
        }
        let status_flags = if flags.nonblock {
            crate::linux_abi::LINUX_O_NONBLOCK as u32
        } else {
            0
        };
        Ok(VfsHandle::Pty {
            host_fd,
            pts_index: n,
            is_master: false,
            status_flags,
        })
    }

    fn name(&self) -> &'static str {
        "devpts"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_master_returns_fd_and_slave_name() {
        let (master_fd, slave_name) = open_master(false).expect("posix_openpt");
        assert!(master_fd >= 0);
        assert!(slave_name.starts_with("/dev/"), "got {slave_name}");
        unsafe { libc::close(master_fd) };
    }

    #[test]
    fn alloc_lookup_free_roundtrip() {
        let mut t = PtyTable::new();
        let n0 = t.insert("/dev/ttys000".into(), 1234);
        let n1 = t.insert("/dev/ttys001".into(), 1234);
        assert_eq!(n0, 0);
        assert_eq!(n1, 1);
        assert_eq!(t.slave_name(0).as_deref(), Some("/dev/ttys000"));
        assert_eq!(t.slave_name(1).as_deref(), Some("/dev/ttys001"));
        assert_eq!(t.slave_name(2), None);
        assert_eq!(t.live_indices(), vec![0, 1]);
        assert!(t.is_locked(0));
        t.set_locked(0, false);
        assert!(!t.is_locked(0));
        t.free(0);
        assert_eq!(t.slave_name(0), None);
        assert_eq!(t.live_indices(), vec![1]);
        assert_eq!(t.insert("/dev/ttys002".into(), 1234), 2);
    }

    #[test]
    fn free_if_owner_only_frees_for_owning_pid() {
        let mut t = PtyTable::new();
        let n = t.insert("/dev/ttysX".into(), 100);
        t.free_if_owner(n, 999); // non-owner: no-op
        assert!(t.slave_name(n).is_some());
        t.free_if_owner(n, 100); // owner: frees
        assert!(t.slave_name(n).is_none());
    }

    #[test]
    fn devpts_lookup_and_readdir_track_live_ptys() {
        use crate::vfs::{OpenContext, OpenFlags, Vfs};
        use parking_lot::Mutex;
        use std::sync::Arc;

        let table = Arc::new(Mutex::new(PtyTable::new()));
        let dev = DevptsVfs::new(Arc::clone(&table));

        assert_eq!(
            dev.lookup("/dev/pts").unwrap().kind,
            crate::vfs::EntryKind::Directory
        );
        assert!(dev.lookup("/dev/pts/0").is_err());

        // Allocate a slave name out-of-band; use /dev/null as an openable stand-in.
        let n = table.lock().insert("/dev/null".into(), 1234);
        assert_eq!(n, 0);
        assert_eq!(
            dev.lookup("/dev/pts/0").unwrap().kind,
            crate::vfs::EntryKind::CharDevice
        );
        let names: Vec<String> = dev
            .readdir("/dev/pts")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(names.contains(&"0".to_string()));

        let h = dev
            .open(
                "/dev/pts/0",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            crate::vfs::VfsHandle::Pty {
                is_master,
                pts_index,
                host_fd,
                ..
            } => {
                assert!(!is_master);
                assert_eq!(pts_index, 0);
                unsafe { libc::close(host_fd) };
            }
            other => panic!("expected Pty handle, got {other:?}"),
        }
    }
}
