//! inotify(7) emulation.
//!
//! On **Linux** the host kernel has the real thing: [`InotifyState`] keeps a
//! native `inotify` instance (`inotify_init1`), adds watches with
//! `inotify_add_watch` against the path the watched fd resolves to
//! (`/proc/self/fd/<fd>`), and `read(2)` returns the kernel's own
//! `struct inotify_event` records verbatim — basename CREATE/DELETE and all —
//! with only the watch descriptor remapped from the host's wd space to the
//! guest's. No directory snapshot/diff is needed; the kernel reports child
//! events natively.
//!
//! On **macOS** there is no inotify, so [`InotifyState`] bridges to Darwin
//! kqueue `EVFILT_VNODE` through the [`EventMultiplexer`](carrick_hal::event::EventMultiplexer):
//! Linux inotify is watch-descriptor based (one fd, many path watches) while
//! kqueue is fd-based (one kevent per open fd). Each `inotify_add_watch` opens
//! the target and registers an `EVFILT_VNODE` filter, keyed by watch descriptor
//! (`wd`); `read(2)` drains the kqueue and *formats* Linux `inotify_event`
//! records. Because kqueue only reports that a *directory's* vnode changed (not
//! which child), the macOS path pairs a host directory snapshot/diff with the
//! vnode write so children created or removed after registration still surface
//! Linux-style basename events. That dir-diff is macOS-only.

use std::collections::HashMap;
use std::os::fd::RawFd;

use parking_lot::Mutex;

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
use carrick_hal::event::{EventMultiplexer, PollEvent, VnodeEvents};
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
use std::collections::HashSet;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
use std::path::{Path, PathBuf};
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
use std::time::Duration;

// Linux inotify event/mask bits (asm-generic, shared by aarch64). Only the
// macOS emulation needs the individual event bits (to translate kqueue
// `NOTE_*` ↔ Linux mask); the native Linux backend passes the guest mask to the
// kernel verbatim, so they are macOS-gated to stay dead-code-clean off-macOS.
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_ACCESS: u32 = 0x0000_0001;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_MODIFY: u32 = 0x0000_0002;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_ATTRIB: u32 = 0x0000_0004;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_CLOSE_WRITE: u32 = 0x0000_0008;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_MOVED_FROM: u32 = 0x0000_0040;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_MOVED_TO: u32 = 0x0000_0080;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_CREATE: u32 = 0x0000_0100;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_DELETE: u32 = 0x0000_0200;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) const IN_DELETE_SELF: u32 = 0x0000_0400;
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
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

/// macOS analogue producing the [`VnodeEvents`] the [`EventMultiplexer`]
/// register API consumes. Requests the kqueue `NOTE_*` set corresponding to the
/// Linux watch mask; a mask with no recognized data-changing bit falls back to
/// the common set so a broad `IN_ALL_EVENTS` watch behaves sensibly.
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn linux_mask_to_vnode_events(mask: u32) -> VnodeEvents {
    let mut ev = VnodeEvents::default();
    if mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_ACCESS | IN_CREATE | IN_DELETE) != 0 {
        ev.write = true;
        ev.extend = true;
    }
    if mask & IN_ATTRIB != 0 {
        ev.attrib = true;
    }
    if mask & (IN_DELETE_SELF | IN_DELETE) != 0 {
        ev.delete = true;
    }
    if mask & (IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO) != 0 {
        ev.rename = true;
    }
    if !(ev.write || ev.extend || ev.attrib || ev.delete || ev.rename) {
        // Broad fallback: WRITE|EXTEND|ATTRIB|DELETE.
        ev.write = true;
        ev.extend = true;
        ev.attrib = true;
        ev.delete = true;
    }
    ev
}

/// Translate the `NOTE_*` fflags of a fired vnode event back into a Linux
/// inotify event mask, restricted to the bits the watch actually requested.
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn note_to_linux_mask(fflags: u32, requested: u32) -> u32 {
    let mut mask = 0;
    if fflags & (carrick_portable::NOTE_WRITE | carrick_portable::NOTE_EXTEND) != 0 {
        mask |= IN_MODIFY;
    }
    if fflags & carrick_portable::NOTE_ATTRIB != 0 {
        mask |= IN_ATTRIB;
    }
    if fflags & carrick_portable::NOTE_DELETE != 0 {
        mask |= IN_DELETE_SELF;
    }
    if fflags & carrick_portable::NOTE_RENAME != 0 {
        mask |= IN_MOVE_SELF;
    }
    // Only surface bits the caller asked for, except the self-events Linux
    // always reports (delete/move of the watched object).
    mask & (requested | IN_DELETE_SELF | IN_MOVE_SELF)
}

#[derive(Debug)]
struct Watch {
    host_fds: Vec<RawFd>,
    mask: u32,
}

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
#[derive(Clone, Debug)]
struct ScannedDir {
    path: PathBuf,
    entries: HashSet<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct WatchedFd {
    wd: i32,
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    name: Option<Vec<u8>>,
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    scan_dir: Option<ScannedDir>,
}

#[derive(Debug)]
struct Inner {
    next_wd: i32,
    watches: HashMap<i32, Watch>,
    wd_by_fd: HashMap<RawFd, WatchedFd>,
    /// Encoded `inotify_event` records observed but not yet handed to the guest
    /// (a `read(2)` whose buffer was smaller than the available events keeps the
    /// rest here, like the kernel's event queue). On Linux this only buffers a
    /// short-read remainder; on macOS it also holds synthesized records.
    pending: std::collections::VecDeque<Vec<u8>>,
    /// Linux only: native-inotify watch descriptor → guest wd. The kernel hands
    /// out its own wd from `inotify_add_watch`; the guest sees our `wd`, so a
    /// record read off the native fd is rewritten through this map.
    #[cfg(feature = "platform-linux")]
    native_wd_to_guest: HashMap<i32, i32>,
}

/// One inotify instance: a readiness backend plus its watch-descriptor table.
/// Owns every watched fd and closes them on `rm_watch`/drop.
///
/// On macOS the backend is a boxed [`EventMultiplexer`](carrick_hal::event::EventMultiplexer)
/// (kqueue-backed via `EVFILT_VNODE`); the watch register/drain go through the
/// trait. On Linux the backend is a native `inotify` fd read directly.
pub(crate) struct InotifyState {
    /// macOS readiness backend. `Mutex` because the trait's register/drain
    /// methods need `&mut` yet `InotifyState` is shared via `Arc` and exposes
    /// `&self` methods; the lock is only ever held for a non-blocking kqueue
    /// change or a zero-timeout drain.
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    mux: Mutex<Box<dyn EventMultiplexer>>,
    /// The native Linux inotify fd (`IN_NONBLOCK | IN_CLOEXEC`). Pollable
    /// directly; `read(2)` returns native `inotify_event` records.
    #[cfg(feature = "platform-linux")]
    inotify_fd: RawFd,
    /// Cached pollable fd — stable for the instance's life, read lock-free
    /// (`mux.poll_fd()` on macOS, the inotify fd on Linux).
    poll_fd: RawFd,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for InotifyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InotifyState")
            .field("poll_fd", &self.poll_fd())
            .finish_non_exhaustive()
    }
}

impl InotifyState {
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    pub(crate) fn new() -> Option<Self> {
        let mux = crate::event_mux::make_event_multiplexer().ok()?;
        let poll_fd = mux.poll_fd();
        Some(Self {
            mux: Mutex::new(mux),
            poll_fd,
            inner: Mutex::new(Inner {
                next_wd: 1,
                watches: HashMap::new(),
                wd_by_fd: HashMap::new(),
                pending: std::collections::VecDeque::new(),
            }),
        })
    }

    #[cfg(feature = "platform-linux")]
    pub(crate) fn new() -> Option<Self> {
        // SAFETY: inotify_init1 takes a flags int and returns an fd or -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        Some(Self {
            inotify_fd: fd,
            poll_fd: fd,
            inner: Mutex::new(Inner {
                next_wd: 1,
                watches: HashMap::new(),
                wd_by_fd: HashMap::new(),
                pending: std::collections::VecDeque::new(),
                native_wd_to_guest: HashMap::new(),
            }),
        })
    }

    /// The backing pollable fd (the kqueue fd on macOS, the inotify fd on
    /// Linux), so poll/epoll/blocking-read can wait on inotify readiness the
    /// same way they do for timerfd/pidfd.
    pub(crate) fn poll_fd(&self) -> RawFd {
        self.poll_fd
    }

    /// Register a watch on an already-open host fd, taking ownership of it.
    /// If `host_fd`'s vnode is already watched, updates the mask and returns the
    /// existing wd (matching inotify, which returns the same wd for a re-add).
    pub(crate) fn add_watch(&self, host_fd: RawFd, mask: u32) -> Result<i32, i32> {
        self.add_watch_fds(vec![crate::vfs::WatchFd::unnamed(host_fd)], mask)
    }

    #[cfg(feature = "platform-linux")]
    pub(crate) fn add_watch_fds(
        &self,
        watch_fds: Vec<crate::vfs::WatchFd>,
        mask: u32,
    ) -> Result<i32, i32> {
        if watch_fds.is_empty() {
            return Err(LINUX_EINVAL);
        }
        let host_fds: Vec<RawFd> = watch_fds.iter().map(|watch_fd| watch_fd.host_fd).collect();

        // Native inotify watches *paths*; resolve each watched fd to the path it
        // currently names (/proc/self/fd/<fd>) and add a kernel watch. The guest
        // mask is a Linux mask on a Linux host, so it passes through verbatim.
        let mut native_wds = Vec::with_capacity(host_fds.len());
        for &host_fd in &host_fds {
            match native_add_watch(self.inotify_fd, host_fd, mask) {
                Ok(native_wd) => native_wds.push(native_wd),
                Err(()) => {
                    // Failed to register: we own the fds, so don't leak them.
                    for host_fd in host_fds {
                        unsafe { libc::close(host_fd) };
                    }
                    return Err(LINUX_ENOSPC);
                }
            }
        }

        let mut inner = self.inner.lock();
        if watch_fds.len() == 1
            && let Some(existing) = inner.wd_by_fd.get(&watch_fds[0].host_fd).cloned()
        {
            let wd = existing.wd;
            if let Some(w) = inner.watches.get_mut(&wd) {
                w.mask = mask;
            }
            // Re-adding the same vnode reuses the kernel's wd; refresh the map.
            for native_wd in native_wds {
                inner.native_wd_to_guest.insert(native_wd, wd);
            }
            // The caller's duplicate fd is redundant; drop it.
            unsafe { libc::close(watch_fds[0].host_fd) };
            return Ok(wd);
        }
        let wd = inner.next_wd;
        inner.next_wd += 1;
        for (watch_fd, native_wd) in watch_fds.iter().zip(native_wds) {
            inner.wd_by_fd.insert(watch_fd.host_fd, WatchedFd { wd });
            inner.native_wd_to_guest.insert(native_wd, wd);
        }
        inner.watches.insert(wd, Watch { host_fds, mask });
        Ok(wd)
    }

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    pub(crate) fn add_watch_fds(
        &self,
        watch_fds: Vec<crate::vfs::WatchFd>,
        mask: u32,
    ) -> Result<i32, i32> {
        if watch_fds.is_empty() {
            return Err(LINUX_EINVAL);
        }
        let host_fds: Vec<RawFd> = watch_fds.iter().map(|watch_fd| watch_fd.host_fd).collect();

        // Register each watched vnode for the requested `NOTE_*` set. The token
        // is the host fd so `read_records` can map a fired event back to its wd.
        let registered = {
            let events = linux_mask_to_vnode_events(mask);
            let mut mux = self.mux.lock();
            host_fds.iter().try_for_each(|host_fd| {
                mux.register_vnode(*host_fd, *host_fd as u64, events)
                    .map_err(|_| ())
            })
        };
        if registered.is_err() {
            // Registration failed: we own the fds, so don't leak them.
            for host_fd in host_fds {
                unsafe { libc::close(host_fd) };
            }
            return Err(LINUX_ENOSPC);
        }
        let mut inner = self.inner.lock();
        if watch_fds.len() == 1
            && watch_fds[0].name.is_none()
            && let Some(existing) = inner.wd_by_fd.get(&watch_fds[0].host_fd).cloned()
        {
            let wd = existing.wd;
            if let Some(w) = inner.watches.get_mut(&wd) {
                w.mask = mask;
            }
            // The caller's duplicate fd is redundant; drop it.
            unsafe { libc::close(watch_fds[0].host_fd) };
            return Ok(wd);
        }
        let wd = inner.next_wd;
        inner.next_wd += 1;
        for watch_fd in &watch_fds {
            let scan_dir = watch_fd.scan_dir.as_ref().and_then(|path| {
                scan_dir_entries(path).ok().map(|entries| ScannedDir {
                    path: path.clone(),
                    entries,
                })
            });
            inner.wd_by_fd.insert(
                watch_fd.host_fd,
                WatchedFd {
                    wd,
                    name: watch_fd.name.clone(),
                    scan_dir,
                },
            );
        }
        inner.watches.insert(wd, Watch { host_fds, mask });
        Ok(wd)
    }

    /// Remove a watch by descriptor; closes its fd. Unknown wd → EINVAL.
    pub(crate) fn rm_watch(&self, wd: i32) -> Result<(), i32> {
        let mut inner = self.inner.lock();
        let Some(watch) = inner.watches.remove(&wd) else {
            return Err(LINUX_EINVAL);
        };
        for host_fd in watch.host_fds {
            inner.wd_by_fd.remove(&host_fd);
            #[cfg(any(
                feature = "platform-macos",
                feature = "platform-freebsd",
                feature = "platform-netbsd"
            ))]
            {
                let _ = self.mux.lock().deregister(host_fd);
            }
            #[cfg(feature = "platform-linux")]
            {
                // Drop the kernel watch(es) that map to this guest wd.
                let native: Vec<i32> = inner
                    .native_wd_to_guest
                    .iter()
                    .filter(|&(_, &g)| g == wd)
                    .map(|(&n, _)| n)
                    .collect();
                for native_wd in native {
                    inner.native_wd_to_guest.remove(&native_wd);
                    // SAFETY: inotify_rm_watch on our owned inotify fd + valid wd.
                    unsafe { libc::inotify_rm_watch(self.inotify_fd, native_wd) };
                }
            }
            unsafe { libc::close(host_fd) };
        }
        Ok(())
    }

    /// Read up to `max_bytes` of encoded Linux `inotify_event` records. First
    /// drains any newly-ready changes (the kqueue on macOS, the native inotify
    /// fd on Linux), then returns whole records up to the caller's buffer size,
    /// keeping the remainder queued (`pending`) for the next read.
    /// An empty return means no events are ready (caller maps to EAGAIN / a
    /// wait on [`Self::poll_fd`]). A non-empty queue with `max_bytes` too small
    /// for a single record is signalled by `Err(EINVAL)`, matching Linux.
    #[cfg(feature = "platform-linux")]
    pub(crate) fn read_records(&self, max_bytes: usize) -> Result<Vec<u8>, i32> {
        let mut inner = self.inner.lock();
        // Drain whatever the kernel has queued on the native inotify fd, rewrite
        // each record's wd from the host's space into the guest's, and enqueue
        // the (already Linux-formatted) records. The kernel reports basenames
        // for directory children natively — no dir-diff.
        let mut buf = [0u8; 8192];
        loop {
            // SAFETY: reading into a stack buffer from a nonblocking inotify fd.
            let n = unsafe {
                libc::read(
                    self.inotify_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let mut off = 0usize;
            while off + INOTIFY_EVENT_HEADER_SIZE <= n {
                // Header fields are at fixed little-endian offsets; read them by
                // copy to avoid an unaligned reference into `buf`.
                // Explicit byte indexing (no `unwrap()` — the no-panic gate): the
                // loop guard `off + INOTIFY_EVENT_HEADER_SIZE(16) <= n` proves
                // [off, off+16) is in-bounds.
                let native_wd =
                    i32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
                let len = u32::from_ne_bytes([
                    buf[off + 12],
                    buf[off + 13],
                    buf[off + 14],
                    buf[off + 15],
                ]) as usize;
                let record_end = off + INOTIFY_EVENT_HEADER_SIZE + len;
                if record_end > n {
                    break;
                }
                if let Some(&guest_wd) = inner.native_wd_to_guest.get(&native_wd) {
                    // Copy the record verbatim, overwriting only the wd field.
                    let mut record = buf[off..record_end].to_vec();
                    record[0..4].copy_from_slice(&guest_wd.to_ne_bytes());
                    inner.pending.push_back(record);
                }
                off = record_end;
            }
            if n < buf.len() {
                break;
            }
        }
        drain_pending(&mut inner, max_bytes)
    }

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    pub(crate) fn read_records(&self, max_bytes: usize) -> Result<Vec<u8>, i32> {
        // Non-blocking drain of newly-ready vnode changes, normalized to a list
        // of `(watched host fd, fired NOTE_* fflags)`.
        let fired: Vec<(RawFd, u32)> = {
            let mut out: Vec<PollEvent> = Vec::new();
            let _ = self.mux.lock().wait(&mut out, Some(Duration::ZERO));
            out.iter()
                .map(|ev| {
                    // The token is the watched host fd (set at register_vnode).
                    let fd = ev.token as RawFd;
                    let fflags = ev.vnode.map(|v| v.to_note()).unwrap_or(0);
                    (fd, fflags)
                })
                .collect()
        };
        let mut inner = self.inner.lock();
        for &(fd, fflags) in &fired {
            let Some(watched) = inner.wd_by_fd.get(&fd).cloned() else {
                continue;
            };
            let wd = watched.wd;
            let requested = inner.watches.get(&wd).map(|w| w.mask).unwrap_or(0);
            if let Some(scan_dir) = watched.scan_dir
                && let Some(records) =
                    Self::scan_directory_records(&mut inner, fd, wd, requested, scan_dir)
                && !records.is_empty()
            {
                inner.pending.extend(records);
                continue;
            }
            let mask = note_to_linux_mask(fflags, requested);
            if mask == 0 {
                continue;
            }
            inner
                .pending
                .push_back(encode_event(wd, mask, watched.name.as_deref()));
        }
        drain_pending(&mut inner, max_bytes)
    }

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    fn scan_directory_records(
        inner: &mut Inner,
        fd: RawFd,
        wd: i32,
        requested: u32,
        mut scan_dir: ScannedDir,
    ) -> Option<Vec<Vec<u8>>> {
        let current = scan_dir_entries(&scan_dir.path).ok()?;
        let mut records = Vec::new();
        let mut added: Vec<Vec<u8>> = current.difference(&scan_dir.entries).cloned().collect();
        let mut removed: Vec<Vec<u8>> = scan_dir.entries.difference(&current).cloned().collect();
        added.sort();
        removed.sort();

        let create_mask = requested & IN_CREATE;
        let delete_mask = requested & IN_DELETE;
        let fallback_mask = requested & IN_MODIFY;
        for name in added {
            let mask = if create_mask != 0 {
                create_mask
            } else {
                fallback_mask
            };
            if mask != 0 {
                records.push(encode_event(wd, mask, Some(&name)));
            }
        }
        for name in removed {
            let mask = if delete_mask != 0 {
                delete_mask
            } else {
                fallback_mask
            };
            if mask != 0 {
                records.push(encode_event(wd, mask, Some(&name)));
            }
        }

        scan_dir.entries = current;
        if let Some(watched) = inner.wd_by_fd.get_mut(&fd) {
            watched.scan_dir = Some(scan_dir);
        }
        Some(records)
    }
}

/// Pop whole `inotify_event` records from `inner.pending` up to `max_bytes`.
/// Empty queue → empty Vec (caller maps to EAGAIN); a buffer too small for the
/// first queued record → `Err(EINVAL)`, matching Linux.
fn drain_pending(inner: &mut Inner, max_bytes: usize) -> Result<Vec<u8>, i32> {
    if inner.pending.is_empty() {
        return Ok(Vec::new());
    }
    let first_len = inner
        .pending
        .front()
        .map(|record| record.len())
        .unwrap_or(INOTIFY_EVENT_HEADER_SIZE);
    if max_bytes < first_len {
        return Err(LINUX_EINVAL);
    }
    let mut out = Vec::new();
    while let Some(record) = inner.pending.front() {
        if out.len() + record.len() > max_bytes {
            break;
        }
        let Some(record) = inner.pending.pop_front() else {
            break;
        };
        out.extend_from_slice(&record);
    }
    Ok(out)
}

/// Native Linux `inotify_add_watch` against the path `host_fd` currently names.
/// Returns the kernel's watch descriptor, or `Err(())` on any failure.
#[cfg(feature = "platform-linux")]
fn native_add_watch(inotify_fd: RawFd, host_fd: RawFd, mask: u32) -> Result<i32, ()> {
    let link = format!("/proc/self/fd/{host_fd}");
    let clink = std::ffi::CString::new(link).map_err(|_| ())?;
    let mut buf = [0u8; libc::PATH_MAX as usize];
    // SAFETY: readlink writes at most buf.len() bytes; clink is NUL-terminated.
    let n = unsafe {
        libc::readlink(
            clink.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
        )
    };
    if n < 0 {
        return Err(());
    }
    let cpath = std::ffi::CString::new(&buf[..n as usize]).map_err(|_| ())?;
    // SAFETY: cpath is a valid NUL-terminated C string for the call; the guest
    // mask is a Linux mask on a Linux host, passed through verbatim.
    let wd = unsafe { libc::inotify_add_watch(inotify_fd, cpath.as_ptr(), mask) };
    if wd < 0 { Err(()) } else { Ok(wd) }
}

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn encode_event(wd: i32, mask: u32, name: Option<&[u8]>) -> Vec<u8> {
    let name_len = name.map(|name| align4(name.len() + 1)).unwrap_or(0);
    let mut record = Vec::with_capacity(INOTIFY_EVENT_HEADER_SIZE + name_len);
    record.extend_from_slice(&wd.to_ne_bytes());
    record.extend_from_slice(&mask.to_ne_bytes());
    record.extend_from_slice(&0u32.to_ne_bytes()); // cookie
    record.extend_from_slice(&(name_len as u32).to_ne_bytes());
    if let Some(name) = name {
        record.extend_from_slice(name);
        record.resize(INOTIFY_EVENT_HEADER_SIZE + name_len, 0);
    }
    record
}

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn align4(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn scan_dir_entries(path: &Path) -> std::io::Result<HashSet<Vec<u8>>> {
    let mut entries = HashSet::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        entries.insert(entry.file_name().as_bytes().to_vec());
    }
    Ok(entries)
}

impl Drop for InotifyState {
    fn drop(&mut self) {
        let inner = self.inner.lock();
        for watch in inner.watches.values() {
            for host_fd in &watch.host_fds {
                unsafe { libc::close(*host_fd) };
            }
        }
        // The native inotify fd is owned here on Linux; close it last so any
        // outstanding watches are torn down with it.
        #[cfg(feature = "platform-linux")]
        unsafe {
            libc::close(self.inotify_fd);
        }
    }
}

// kqueue-vnode semantics (O_EVTONLY, EVFILT_VNODE) — macOS-only, like the
// host-side inotify emulation itself.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn vnode_watch_reports_file_modification_as_in_modify() {
        let path = std::env::temp_dir().join(format!("carrick-inotify-{}.tmp", std::process::id()));
        std::fs::write(&path, b"seed").unwrap();
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // O_EVTONLY: an event-only descriptor, ideal for watching a vnode.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_EVTONLY) };
        assert!(fd >= 0, "open O_EVTONLY failed");

        let state = InotifyState::new().expect("kqueue");
        let wd = state.add_watch(fd, IN_MODIFY).expect("add_watch");

        // Modify the file through a *different* fd; the vnode event still fires.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
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
        assert!(linux_mask_to_vnode_events(IN_MODIFY).write);
        assert!(linux_mask_to_vnode_events(IN_ATTRIB).attrib);
        assert_eq!(
            note_to_linux_mask(carrick_portable::NOTE_WRITE, IN_MODIFY),
            IN_MODIFY
        );
        assert_eq!(
            note_to_linux_mask(carrick_portable::NOTE_ATTRIB, IN_MODIFY),
            0
        );
        // Self-delete is always surfaced even if not explicitly requested.
        assert_eq!(
            note_to_linux_mask(carrick_portable::NOTE_DELETE, IN_MODIFY),
            IN_DELETE_SELF
        );
    }
}

// Native Linux inotify smoke test — exercises the real kernel inotify backend
// (the non-macOS path) end to end.
#[cfg(all(test, feature = "platform-linux", target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn native_watch_reports_file_modification_as_in_modify() {
        let path =
            std::env::temp_dir().join(format!("carrick-inotify-l-{}.tmp", std::process::id()));
        std::fs::write(&path, b"seed").unwrap();
        let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0, "open failed");

        // The native backend passes the mask to the kernel verbatim; use the
        // host's own IN_MODIFY (the per-bit constants are macOS-gated).
        let in_modify = libc::IN_MODIFY;
        let state = InotifyState::new().expect("inotify_init1");
        let wd = state.add_watch(fd, in_modify).expect("add_watch");

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"-more").unwrap();
        f.flush().unwrap();
        drop(f);

        // Native inotify is asynchronous; retry briefly.
        let mut bytes = Vec::new();
        for _ in 0..50 {
            bytes = state.read_records(4096).expect("read_records");
            if !bytes.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            bytes.len() >= INOTIFY_EVENT_HEADER_SIZE,
            "expected at least one inotify_event, got {} bytes",
            bytes.len()
        );
        let got_wd = i32::from_ne_bytes(bytes[0..4].try_into().unwrap());
        let mask = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(got_wd, wd, "guest wd must be remapped from the native wd");
        assert!(mask & in_modify != 0, "expected IN_MODIFY, got {mask:#x}");

        state.rm_watch(wd).expect("rm_watch");
        assert_eq!(state.rm_watch(wd), Err(LINUX_EINVAL), "double rm is EINVAL");
        let _ = std::fs::remove_file(&path);
    }
}
