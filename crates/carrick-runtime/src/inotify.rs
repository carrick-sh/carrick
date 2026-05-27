//! inotify(7) emulation backed by Darwin kqueue `EVFILT_VNODE`.
//!
//! Linux inotify is watch-descriptor based (one fd, many path watches);
//! kqueue is fd-based (one kevent per open fd). [`InotifyState`] bridges the
//! two: each `inotify_add_watch` opens the target and registers an
//! `EVFILT_VNODE` filter, keyed by watch descriptor (`wd`). `read(2)` on the
//! inotify fd drains the kqueue and formats Linux `struct inotify_event`
//! records.
//!
//! Scope: this watches a single vnode per watch (files and "self" events:
//! IN_MODIFY/IN_ATTRIB/IN_DELETE_SELF/IN_MOVE_SELF). kqueue reports vnode
//! changes but not the *names* of directory entries that changed, so
//! directory-entry-level events (IN_CREATE/IN_DELETE with a filename) are a
//! documented follow-up — the same fidelity gap every kqueue-backed inotify
//! shim has.

use std::collections::HashMap;
use std::os::fd::RawFd;

use parking_lot::Mutex;

use crate::darwin_kqueue::{Kevent, Kqueue};

// Linux inotify event/mask bits (asm-generic, shared by aarch64).
pub(crate) const IN_ACCESS: u32 = 0x0000_0001;
pub(crate) const IN_MODIFY: u32 = 0x0000_0002;
pub(crate) const IN_ATTRIB: u32 = 0x0000_0004;
pub(crate) const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub(crate) const IN_MOVED_FROM: u32 = 0x0000_0040;
pub(crate) const IN_MOVED_TO: u32 = 0x0000_0080;
// IN_CREATE (0x100) is intentionally omitted: kqueue's EVFILT_VNODE reports a
// directory was written but not *which* entry changed, so file-creation events
// with a name are a follow-up (see module docs); we never synthesize IN_CREATE.
pub(crate) const IN_DELETE: u32 = 0x0000_0200;
pub(crate) const IN_DELETE_SELF: u32 = 0x0000_0400;
pub(crate) const IN_MOVE_SELF: u32 = 0x0000_0800;

// inotify_init1 / open flags carried in the `flags` argument.
pub(crate) const IN_CLOEXEC: u32 = 0o2_000_000;
pub(crate) const IN_NONBLOCK: u32 = 0o0_004_000;

/// Wire size of Linux `struct inotify_event { int wd; u32 mask; u32 cookie;
/// u32 len; char name[]; }`. Self-watches carry no name, so `len` is 0 and a
/// record is exactly the header.
pub(crate) const INOTIFY_EVENT_HEADER_SIZE: usize = 16;

const LINUX_EINVAL: i32 = 22;
const LINUX_ENOSPC: i32 = 28;

/// Map a Linux watch mask to the Darwin `EVFILT_VNODE` `NOTE_*` flags to
/// request. A mask with no recognized data-changing bit still watches the
/// common set so a broad `IN_ALL_EVENTS` watch behaves sensibly.
fn linux_mask_to_note(mask: u32) -> u32 {
    let mut note = 0;
    if mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_ACCESS) != 0 {
        note |= libc::NOTE_WRITE | libc::NOTE_EXTEND;
    }
    if mask & IN_ATTRIB != 0 {
        note |= libc::NOTE_ATTRIB;
    }
    if mask & (IN_DELETE_SELF | IN_DELETE) != 0 {
        note |= libc::NOTE_DELETE;
    }
    if mask & (IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO) != 0 {
        note |= libc::NOTE_RENAME;
    }
    if note == 0 {
        note = libc::NOTE_WRITE | libc::NOTE_EXTEND | libc::NOTE_ATTRIB | libc::NOTE_DELETE;
    }
    note
}

/// Translate the `NOTE_*` fflags of a fired vnode event back into a Linux
/// inotify event mask, restricted to the bits the watch actually requested.
fn note_to_linux_mask(fflags: u32, requested: u32) -> u32 {
    let mut mask = 0;
    if fflags & (libc::NOTE_WRITE | libc::NOTE_EXTEND) != 0 {
        mask |= IN_MODIFY;
    }
    if fflags & libc::NOTE_ATTRIB != 0 {
        mask |= IN_ATTRIB;
    }
    if fflags & libc::NOTE_DELETE != 0 {
        mask |= IN_DELETE_SELF;
    }
    if fflags & libc::NOTE_RENAME != 0 {
        mask |= IN_MOVE_SELF;
    }
    // Only surface bits the caller asked for, except the self-events Linux
    // always reports (delete/move of the watched object).
    mask & (requested | IN_DELETE_SELF | IN_MOVE_SELF)
}

#[derive(Debug)]
struct Watch {
    host_fd: RawFd,
    mask: u32,
}

#[derive(Debug)]
struct Inner {
    next_wd: i32,
    watches: HashMap<i32, Watch>,
    wd_by_fd: HashMap<RawFd, i32>,
    /// Encoded `inotify_event` records observed from the kqueue but not yet
    /// handed to the guest (a `read(2)` whose buffer was smaller than the
    /// available events keeps the rest here, like the kernel's event queue).
    pending: Vec<u8>,
}

/// One inotify instance: a kqueue plus its watch-descriptor table. Owns every
/// watched fd and closes them on `rm_watch`/drop.
#[derive(Debug)]
pub(crate) struct InotifyState {
    kqueue: Kqueue,
    inner: Mutex<Inner>,
}

impl InotifyState {
    pub(crate) fn new() -> Option<Self> {
        Kqueue::new_internal().map(|kqueue| Self {
            kqueue,
            inner: Mutex::new(Inner {
                next_wd: 1,
                watches: HashMap::new(),
                wd_by_fd: HashMap::new(),
                pending: Vec::new(),
            }),
        })
    }

    /// The backing kqueue's fd, so poll/epoll/blocking-read can wait on inotify
    /// readiness the same way they do for timerfd/pidfd.
    pub(crate) fn poll_fd(&self) -> RawFd {
        self.kqueue.raw_fd()
    }

    /// Register a watch on an already-open host fd, taking ownership of it.
    /// If `host_fd`'s vnode is already watched, updates the mask and returns the
    /// existing wd (matching inotify, which returns the same wd for a re-add).
    pub(crate) fn add_watch(&self, host_fd: RawFd, mask: u32) -> Result<i32, i32> {
        let note = linux_mask_to_note(mask);
        if self.kqueue.apply(&[Kevent::vnode(host_fd, note)]).is_err() {
            // Registration failed: we own the fd, so don't leak it.
            unsafe { libc::close(host_fd) };
            return Err(LINUX_ENOSPC);
        }
        let mut inner = self.inner.lock();
        if let Some(&wd) = inner.wd_by_fd.get(&host_fd) {
            if let Some(w) = inner.watches.get_mut(&wd) {
                w.mask = mask;
            }
            // The caller's duplicate fd is redundant; drop it.
            unsafe { libc::close(host_fd) };
            return Ok(wd);
        }
        let wd = inner.next_wd;
        inner.next_wd += 1;
        inner.watches.insert(wd, Watch { host_fd, mask });
        inner.wd_by_fd.insert(host_fd, wd);
        Ok(wd)
    }

    /// Remove a watch by descriptor; closes its fd. Unknown wd → EINVAL.
    pub(crate) fn rm_watch(&self, wd: i32) -> Result<(), i32> {
        let mut inner = self.inner.lock();
        let Some(watch) = inner.watches.remove(&wd) else {
            return Err(LINUX_EINVAL);
        };
        inner.wd_by_fd.remove(&watch.host_fd);
        let _ = self.kqueue.apply(&[Kevent::vnode_delete(watch.host_fd)]);
        unsafe { libc::close(watch.host_fd) };
        Ok(())
    }

    /// Read up to `max_bytes` of encoded Linux `inotify_event` records (header
    /// only — self-watches carry no name). First drains any newly-ready vnode
    /// changes from the kqueue, then returns whole records up to the caller's
    /// buffer size, keeping the remainder queued (`pending`) for the next read.
    /// An empty return means no events are ready (caller maps to EAGAIN / a
    /// wait on [`poll_fd`]). A non-empty queue with `max_bytes` too small for a
    /// single record is signalled by `Err(EINVAL)`, matching Linux.
    pub(crate) fn read_records(&self, max_bytes: usize) -> Result<Vec<u8>, i32> {
        let mut events = [Kevent::empty(); 32];
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let n = self.kqueue.wait(&[], &mut events, Some(&timeout)).unwrap_or(0);
        let mut inner = self.inner.lock();
        for ev in &events[..n] {
            let fd = ev.vnode_ident();
            let Some(&wd) = inner.wd_by_fd.get(&fd) else {
                continue;
            };
            let requested = inner.watches.get(&wd).map(|w| w.mask).unwrap_or(0);
            let mask = note_to_linux_mask(ev.fflags(), requested);
            if mask == 0 {
                continue;
            }
            inner.pending.extend_from_slice(&wd.to_ne_bytes());
            inner.pending.extend_from_slice(&mask.to_ne_bytes());
            inner.pending.extend_from_slice(&0u32.to_ne_bytes()); // cookie
            inner.pending.extend_from_slice(&0u32.to_ne_bytes()); // len (no name)
        }
        if inner.pending.is_empty() {
            return Ok(Vec::new());
        }
        if max_bytes < INOTIFY_EVENT_HEADER_SIZE {
            return Err(LINUX_EINVAL);
        }
        // Return whole records only, up to the buffer size.
        let take = (max_bytes.min(inner.pending.len()) / INOTIFY_EVENT_HEADER_SIZE)
            * INOTIFY_EVENT_HEADER_SIZE;
        Ok(inner.pending.drain(..take).collect())
    }
}

impl Drop for InotifyState {
    fn drop(&mut self) {
        let inner = self.inner.lock();
        for watch in inner.watches.values() {
            unsafe { libc::close(watch.host_fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn vnode_watch_reports_file_modification_as_in_modify() {
        let path =
            std::env::temp_dir().join(format!("carrick-inotify-{}.tmp", std::process::id()));
        std::fs::write(&path, b"seed").unwrap();
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // O_EVTONLY: an event-only descriptor, ideal for watching a vnode.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_EVTONLY) };
        assert!(fd >= 0, "open O_EVTONLY failed");

        let state = InotifyState::new().expect("kqueue");
        let wd = state.add_watch(fd, IN_MODIFY).expect("add_watch");

        // Modify the file through a *different* fd; the vnode event still fires.
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"-more").unwrap();
        f.flush().unwrap();
        drop(f);

        let bytes = state.read_records(4096).expect("read_records");
        assert!(
            bytes.len() >= INOTIFY_EVENT_HEADER_SIZE,
            "expected at least one inotify_event, got {} bytes",
            bytes.len()
        );
        let got_wd = i32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let mask = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(got_wd, wd);
        assert!(mask & IN_MODIFY != 0, "expected IN_MODIFY, got {mask:#x}");

        state.rm_watch(wd).expect("rm_watch");
        assert_eq!(state.rm_watch(wd), Err(LINUX_EINVAL), "double rm is EINVAL");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mask_translation_round_trips_common_events() {
        assert!(linux_mask_to_note(IN_MODIFY) & libc::NOTE_WRITE != 0);
        assert!(linux_mask_to_note(IN_ATTRIB) & libc::NOTE_ATTRIB != 0);
        assert_eq!(note_to_linux_mask(libc::NOTE_WRITE, IN_MODIFY), IN_MODIFY);
        assert_eq!(note_to_linux_mask(libc::NOTE_ATTRIB, IN_MODIFY), 0);
        // Self-delete is always surfaced even if not explicitly requested.
        assert_eq!(note_to_linux_mask(libc::NOTE_DELETE, IN_MODIFY), IN_DELETE_SELF);
    }
}
