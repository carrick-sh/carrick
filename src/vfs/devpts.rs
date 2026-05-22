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
        Self { next_index: 0, entries: BTreeMap::new() }
    }

    /// Record a freshly-opened pty's slave device name; returns the
    /// allocated index N.
    pub fn insert(&mut self, host_slave_name: String) -> u32 {
        let n = self.next_index;
        self.next_index += 1;
        self.entries.insert(n, PtyEntry { host_slave_name, locked: true });
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
    let slave_name = unsafe { CStr::from_ptr(name_ptr) }.to_string_lossy().into_owned();
    Ok((master, slave_name))
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
        let n0 = t.insert("/dev/ttys000".into());
        let n1 = t.insert("/dev/ttys001".into());
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
        assert_eq!(t.insert("/dev/ttys002".into()), 2);
    }
}
