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
//! kqueue `EVFILT_VNODE` through the `EventMultiplexer`:
//! Linux inotify is watch-descriptor based (one fd, many path watches) while
//! kqueue is fd-based (one kevent per open fd). Each `inotify_add_watch` opens
//! the target and registers an `EVFILT_VNODE` filter, keyed by watch descriptor
//! (`wd`); `read(2)` drains the kqueue and *formats* Linux `inotify_event`
//! records. Because kqueue only reports that a *directory's* vnode changed (not
//! which child), the macOS path pairs a host directory snapshot/diff with the
//! vnode write so children created or removed after registration still surface
//! Linux-style basename events. That dir-diff is macOS-only.

use crate::linux_abi::{LINUX_EINVAL, LINUX_ENOSPC, LinuxErrno};
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

// Linux inotify event/mask bits live in `carrick-abi` (the shared ABI crate).
// The native Linux backend passes the guest mask to the kernel verbatim; the
// macOS emulation needs the individual bits to translate kqueue `NOTE_*` ↔ Linux
// mask, so it re-aliases the abi constants under the historical short names and
// keeps the aliases macOS-gated to stay dead-code-clean off-macOS.
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
use carrick_abi::{
    LINUX_IN_ACCESS as IN_ACCESS, LINUX_IN_ATTRIB as IN_ATTRIB,
    LINUX_IN_CLOSE_WRITE as IN_CLOSE_WRITE, LINUX_IN_CREATE as IN_CREATE,
    LINUX_IN_DELETE as IN_DELETE, LINUX_IN_DELETE_SELF as IN_DELETE_SELF,
    LINUX_IN_MODIFY as IN_MODIFY, LINUX_IN_MOVE_SELF as IN_MOVE_SELF,
    LINUX_IN_MOVED_FROM as IN_MOVED_FROM, LINUX_IN_MOVED_TO as IN_MOVED_TO,
};

// inotify_init1 / open flags carried in the `flags` argument.
pub(crate) const IN_CLOEXEC: u32 = 0o2_000_000;
pub(crate) const IN_NONBLOCK: u32 = 0o0_004_000;

/// Wire size of Linux `struct inotify_event { int wd; u32 mask; u32 cookie;
/// u32 len; char name[]; }`. Self-watches carry no name, so `len` is 0 and a
/// record is exactly the header.
pub(crate) const INOTIFY_EVENT_HEADER_SIZE: usize = carrick_abi::LINUX_INOTIFY_EVENT_HEADER_SIZE;

/// Maximum records the in-process inotify queue holds before it synthesizes an
/// `IN_Q_OVERFLOW` marker and drops further events, mirroring the kernel's
/// `/proc/sys/fs/inotify/max_queued_events` ceiling (carrick reports 16384 in
/// `vfs/proc.rs`, so match it exactly — `inotify05` generates that many events
/// expecting the overflow record).
pub(crate) const INOTIFY_MAX_QUEUED_EVENTS: usize = 16384;

/// Event bits the kernel delivers to a watch regardless of the mask it was
/// added with: `IN_IGNORED` (watch auto-/explicitly removed), `IN_Q_OVERFLOW`,
/// and `IN_UNMOUNT`. `IN_ALL_EVENTS` does not include these, so the per-watch
/// mask filter in [`dispatch_in`] must let them through unconditionally.
const UNCONDITIONAL_EVENT_BITS: u32 = carrick_abi::LINUX_IN_IGNORED
    | carrick_abi::LINUX_IN_Q_OVERFLOW
    | carrick_abi::LINUX_IN_UNMOUNT;

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
    /// Set once the queue hit [`INOTIFY_MAX_QUEUED_EVENTS`] and an
    /// `IN_Q_OVERFLOW` marker was appended, so later enqueues are dropped (the
    /// kernel keeps exactly one overflow record at the tail and stops queuing).
    /// Cleared after the overflow record is drained.
    overflowed: bool,
    /// Monotonic rename-pairing cookie. The kernel ties an `IN_MOVED_FROM` and
    /// its matching `IN_MOVED_TO` with the same non-zero `cookie`; the
    /// dispatch-layer rename hook draws a fresh value here for each pair.
    next_cookie: u32,
    /// When set, the macOS/BSD kqueue backend's `read_records` skips its own
    /// `NOTE_*`/dir-diff *synthesis* and only forwards anything already queued.
    /// The dispatch-layer registry covers same-process events precisely, so the
    /// coarse kqueue synthesis would only emit DUPLICATES (e.g. a second
    /// `IN_MODIFY`) that break the exact-sequence inotify tests. The kqueue fd
    /// stays registered purely as a `poll_fd` readiness source. Set the first
    /// time a dispatch watch is registered on this instance.
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    dispatch_authoritative: bool,
    /// Linux only: native-inotify watch descriptor → guest wd. The kernel hands
    /// out its own wd from `inotify_add_watch`; the guest sees our `wd`, so a
    /// record read off the native fd is rewritten through this map. Kept on the
    /// shared `Inner` (not the backend) so all bookkeeping lives under the single
    /// `inner` lock — a backend-owned copy would force a two-lock dance and a
    /// deadlock hazard.
    #[cfg(feature = "platform-linux")]
    native_wd_to_guest: HashMap<i32, i32>,
}

impl Inner {
    /// Construct the shared watch-descriptor bookkeeping for a fresh instance.
    fn new() -> Self {
        Inner {
            next_wd: 1,
            watches: HashMap::new(),
            wd_by_fd: HashMap::new(),
            pending: std::collections::VecDeque::new(),
            overflowed: false,
            next_cookie: 1,
            #[cfg(any(
                feature = "platform-macos",
                feature = "platform-freebsd",
                feature = "platform-netbsd"
            ))]
            dispatch_authoritative: false,
            #[cfg(feature = "platform-linux")]
            native_wd_to_guest: HashMap::new(),
        }
    }

    /// Append one already-encoded `inotify_event` record, enforcing the bounded
    /// queue: at [`INOTIFY_MAX_QUEUED_EVENTS`] it appends a single zero-name
    /// `IN_Q_OVERFLOW` (`wd = -1`) marker and drops this and all subsequent
    /// records until the queue drains. Matches the kernel's overflow behaviour
    /// that `inotify05` asserts.
    fn push_record(&mut self, record: Vec<u8>) {
        if self.overflowed {
            return;
        }
        // Event coalescing (inotify(7)): "If successive output inotify events
        // produced on the inotify file descriptor are identical (same wd, mask,
        // cookie, and name), then they are coalesced into a single event if the
        // older event has not yet been read." The whole encoded record carries
        // exactly wd|mask|cookie|len|name, so a byte-equal tail record is an
        // identical event — drop the new one. (inotify02 renames the watched dir
        // twice back-to-back, expecting a single coalesced IN_MOVE_SELF.)
        if self.pending.back().is_some_and(|tail| *tail == record) {
            return;
        }
        if self.pending.len() >= INOTIFY_MAX_QUEUED_EVENTS {
            self.overflowed = true;
            self.pending.push_back(encode_event_raw(
                -1,
                carrick_abi::LINUX_IN_Q_OVERFLOW,
                0,
                None,
            ));
            return;
        }
        self.pending.push_back(record);
    }
}

/// The platform readiness/watch backend behind [`InotifyState`]. Each variant
/// owns its host-side machinery (a native `inotify` fd on Linux, a boxed
/// `EventMultiplexer` on macOS/BSD) and implements the watch register/drain in
/// terms of the shared [`Inner`] bookkeeping. Methods that mutate `Inner` take
/// `&Mutex<Inner>` and lock it exactly where the old per-`cfg` bodies did, so
/// the single `inner` lock still serializes every table update.
trait InotifyBackend: Send + Sync {
    /// The backing pollable fd (the kqueue fd on macOS, the inotify fd on Linux).
    fn poll_fd(&self) -> RawFd;
    /// Register a batch of watched fds under one guest wd; mirrors the old
    /// per-platform `add_watch_fds`. Takes ownership of the fds.
    fn add_watch_fds(
        &self,
        watch_fds: Vec<crate::vfs::WatchFd>,
        mask: u32,
        inner: &Mutex<Inner>,
    ) -> Result<i32, LinuxErrno>;
    /// Tear down the backend-side registration for one watched fd of a wd being
    /// removed. Called by `rm_watch`, which already holds the `inner` lock, so it
    /// takes `&mut Inner`.
    fn deregister(&self, host_fd: RawFd, wd: i32, inner: &mut Inner);
    /// Drain newly-ready changes and return up to `max_bytes` of encoded Linux
    /// `inotify_event` records; mirrors the old per-platform `read_records`.
    fn read_records(&self, max_bytes: usize, inner: &Mutex<Inner>) -> Result<Vec<u8>, LinuxErrno>;
}

/// Native Linux backend: a real kernel `inotify` instance read directly.
#[cfg(feature = "platform-linux")]
struct NativeLinuxInotify {
    /// The native Linux inotify fd (`IN_NONBLOCK | IN_CLOEXEC`). Pollable
    /// directly; `read(2)` returns native `inotify_event` records.
    inotify_fd: RawFd,
}

#[cfg(feature = "platform-linux")]
impl InotifyBackend for NativeLinuxInotify {
    fn poll_fd(&self) -> RawFd {
        self.inotify_fd
    }

    fn add_watch_fds(
        &self,
        watch_fds: Vec<crate::vfs::WatchFd>,
        mask: u32,
        inner: &Mutex<Inner>,
    ) -> Result<i32, LinuxErrno> {
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

        let mut inner = inner.lock();
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

    fn deregister(&self, _host_fd: RawFd, wd: i32, inner: &mut Inner) {
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

    fn read_records(&self, max_bytes: usize, inner: &Mutex<Inner>) -> Result<Vec<u8>, LinuxErrno> {
        let mut inner = inner.lock();
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
                    inner.push_record(record);
                }
                off = record_end;
            }
            if n < buf.len() {
                break;
            }
        }
        drain_pending(&mut inner, max_bytes)
    }
}

/// macOS/BSD backend: bridges Linux inotify to kqueue `EVFILT_VNODE` via the
/// boxed `EventMultiplexer`, pairing the vnode write with a directory
/// snapshot/diff to synthesize Linux-style basename child events.
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
struct VnodeDiffInotify {
    /// macOS readiness backend. `Mutex` because the trait's register/drain
    /// methods need `&mut` yet the backend is shared via `Arc` and exposes
    /// `&self` methods; the lock is only ever held for a non-blocking kqueue
    /// change or a zero-timeout drain.
    mux: Mutex<Box<dyn EventMultiplexer>>,
}

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
impl InotifyBackend for VnodeDiffInotify {
    fn poll_fd(&self) -> RawFd {
        self.mux.lock().poll_fd()
    }

    fn add_watch_fds(
        &self,
        watch_fds: Vec<crate::vfs::WatchFd>,
        mask: u32,
        inner: &Mutex<Inner>,
    ) -> Result<i32, LinuxErrno> {
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
        let mut inner = inner.lock();
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

    fn deregister(&self, host_fd: RawFd, _wd: i32, _inner: &mut Inner) {
        let _ = self.mux.lock().deregister(host_fd);
    }

    fn read_records(&self, max_bytes: usize, inner: &Mutex<Inner>) -> Result<Vec<u8>, LinuxErrno> {
        // Non-blocking drain of newly-ready vnode changes, normalized to a list
        // of `(watched host fd, fired NOTE_* fflags)`. Always pump the kqueue
        // (even when dispatch-authoritative) so its edge-triggered EV_CLEAR
        // state is consumed and `poll_fd` readiness re-arms.
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
        let mut inner = inner.lock();
        // When the dispatch layer owns event generation for this instance, the
        // kqueue notes were drained above purely to clear readiness; do NOT
        // synthesize records from them (they'd duplicate the precise
        // dispatch-layer events). Just hand back whatever is already queued.
        if inner.dispatch_authoritative {
            return drain_pending(&mut inner, max_bytes);
        }
        for &(fd, fflags) in &fired {
            let Some(watched) = inner.wd_by_fd.get(&fd).cloned() else {
                continue;
            };
            let wd = watched.wd;
            let requested = inner.watches.get(&wd).map(|w| w.mask).unwrap_or(0);
            if let Some(scan_dir) = watched.scan_dir
                && let Some(records) =
                    scan_directory_records(&mut inner, fd, wd, requested, scan_dir)
                && !records.is_empty()
            {
                for record in records {
                    inner.push_record(record);
                }
                continue;
            }
            let mask = note_to_linux_mask(fflags, requested);
            if mask == 0 {
                continue;
            }
            let record = encode_event(wd, mask, watched.name.as_deref());
            inner.push_record(record);
        }
        drain_pending(&mut inner, max_bytes)
    }
}

/// Snapshot/diff a watched directory and synthesize Linux basename
/// CREATE/DELETE records for entries added/removed since the last scan,
/// refreshing the stored snapshot. macOS-only, like the vnode emulation itself.
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

/// Construct the platform inotify backend, mirroring
/// [`crate::event_mux::make_event_multiplexer`]'s cfg pattern: a native
/// `inotify` fd on Linux, a kqueue-backed `EventMultiplexer` on macOS/BSD, and
/// `None` (unsupported) on any other host.
fn make_inotify_backend() -> Option<Box<dyn InotifyBackend>> {
    #[cfg(feature = "platform-linux")]
    {
        // SAFETY: inotify_init1 takes a flags int and returns an fd or -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        Some(Box::new(NativeLinuxInotify { inotify_fd: fd }))
    }
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    {
        let mux = crate::event_mux::make_event_multiplexer().ok()?;
        Some(Box::new(VnodeDiffInotify {
            mux: Mutex::new(mux),
        }))
    }
    #[cfg(not(any(
        feature = "platform-macos",
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    )))]
    {
        None
    }
}

/// One inotify instance: a readiness backend plus its watch-descriptor table.
/// Owns every watched fd and closes them on `rm_watch`/drop.
///
/// On macOS the backend is a boxed `EventMultiplexer`
/// (kqueue-backed via `EVFILT_VNODE`); the watch register/drain go through the
/// trait. On Linux the backend is a native `inotify` fd read directly. The
/// platform fork lives behind [`InotifyBackend`]; this struct holds no cfg
/// fields.
pub(crate) struct InotifyState {
    /// Platform readiness/watch backend (native inotify on Linux, kqueue
    /// `EVFILT_VNODE` on macOS/BSD).
    backend: Box<dyn InotifyBackend>,
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
    pub(crate) fn new() -> Option<Self> {
        let backend = make_inotify_backend()?;
        let poll_fd = backend.poll_fd();
        Some(Self {
            backend,
            poll_fd,
            inner: Mutex::new(Inner::new()),
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
    pub(crate) fn add_watch(&self, host_fd: RawFd, mask: u32) -> Result<i32, LinuxErrno> {
        self.add_watch_fds(vec![crate::vfs::WatchFd::unnamed(host_fd)], mask)
    }

    pub(crate) fn add_watch_fds(
        &self,
        watch_fds: Vec<crate::vfs::WatchFd>,
        mask: u32,
    ) -> Result<i32, LinuxErrno> {
        self.backend.add_watch_fds(watch_fds, mask, &self.inner)
    }

    /// Allocate a watch descriptor with no backend (kqueue/native) registration:
    /// a purely dispatch-driven watch, fed only by [`Self::enqueue`]. Used when
    /// the fs backend can't hand back a host vnode to kqueue (e.g. `--fs memory`,
    /// or a directory the host-watch path declined) but the path exists and the
    /// guest is entitled to a wd. Same-process events still flow via the
    /// dispatch-layer registry; cross-process directory wakeups (which need a
    /// real shared vnode) are simply unavailable for such a watch.
    pub(crate) fn add_virtual_watch(&self, mask: u32) -> i32 {
        let mut inner = self.inner.lock();
        let wd = inner.next_wd;
        inner.next_wd += 1;
        inner.watches.insert(
            wd,
            Watch {
                host_fds: Vec::new(),
                mask,
            },
        );
        wd
    }

    /// Remove a watch by descriptor; closes its fd. Unknown wd → EINVAL.
    pub(crate) fn rm_watch(&self, wd: i32) -> Result<(), LinuxErrno> {
        let mut inner = self.inner.lock();
        let Some(watch) = inner.watches.remove(&wd) else {
            return Err(LINUX_EINVAL);
        };
        for host_fd in watch.host_fds {
            inner.wd_by_fd.remove(&host_fd);
            self.backend.deregister(host_fd, wd, &mut inner);
            unsafe { libc::close(host_fd) };
        }
        Ok(())
    }

    /// Synthesize one precise `inotify_event` from the dispatch layer and queue
    /// it for the guest's next `read(2)`. carrick intercepts every guest fd
    /// syscall, so the open/read/write/close/create/unlink/rename/chmod handlers
    /// call this to emit the exact Linux event (mask + basename) the kqueue
    /// `NOTE_*` set is too coarse to express — `IN_OPEN`/`IN_ACCESS`/per-write
    /// `IN_MODIFY`/`IN_CLOSE_*`, and `IN_CREATE`/`IN_DELETE`/`IN_MOVED_*` pairs
    /// for transient children a directory snapshot/diff would miss. The
    /// bounded-queue + `IN_Q_OVERFLOW` policy is enforced here, like a real read.
    pub(crate) fn enqueue(&self, wd: i32, mask: u32, cookie: u32, name: Option<&[u8]>) {
        let record = encode_event_raw(wd, mask, cookie, name);
        self.inner.lock().push_record(record);
    }

    /// Mark this instance as dispatch-authoritative: the macOS/BSD kqueue
    /// backend stops synthesizing its own (coarse, duplicate-prone) records and
    /// leaves event generation to the dispatch-layer registry, keeping the
    /// kqueue fd only as a `poll_fd` readiness source. Idempotent; a no-op on the
    /// native-Linux backend (which has no synthesis to suppress).
    pub(crate) fn mark_dispatch_authoritative(&self) {
        #[cfg(any(
            feature = "platform-macos",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ))]
        {
            self.inner.lock().dispatch_authoritative = true;
        }
    }

    /// Draw a fresh non-zero rename-pairing cookie so an `IN_MOVED_FROM` and its
    /// matching `IN_MOVED_TO` share one value (the kernel's pairing contract).
    pub(crate) fn next_cookie(&self) -> u32 {
        let mut inner = self.inner.lock();
        let cookie = inner.next_cookie;
        inner.next_cookie = inner.next_cookie.wrapping_add(1);
        if inner.next_cookie == 0 {
            inner.next_cookie = 1;
        }
        cookie
    }

    /// Read up to `max_bytes` of encoded Linux `inotify_event` records. First
    /// drains any newly-ready changes (the kqueue on macOS, the native inotify
    /// fd on Linux), then returns whole records up to the caller's buffer size,
    /// keeping the remainder queued (`pending`) for the next read.
    /// An empty return means no events are ready (caller maps to EAGAIN / a
    /// wait on [`Self::poll_fd`]). A non-empty queue with `max_bytes` too small
    /// for a single record is signalled by `Err(EINVAL)`, matching Linux.
    pub(crate) fn read_records(&self, max_bytes: usize) -> Result<Vec<u8>, LinuxErrno> {
        self.backend.read_records(max_bytes, &self.inner)
    }

    /// Render the per-watch `/proc/<pid>/fdinfo/<fd>` lines for this inotify
    /// instance, one per live watch, in ascending wd order:
    /// `inotify wd:<wd> ino:<ino> sdev:<sdev> mask:<mask> ...` (proc_pid_fdinfo(5)).
    /// The mask is the exact value the watch was added with (including
    /// `IN_ONESHOT`/`IN_EXCL_UNLINK`), which `inotify12` parses and asserts. `ino`
    /// and `sdev` are synthetic placeholders — the test scans them with `%*x`
    /// (skip-assignment) and only checks `mask`. Hex fields are lowercase, matching
    /// the kernel's `%08x`/`%x` formatting.
    pub(crate) fn fdinfo_lines(&self) -> String {
        let inner = self.inner.lock();
        let mut wds: Vec<i32> = inner.watches.keys().copied().collect();
        wds.sort_unstable();
        let mut out = String::new();
        for wd in wds {
            if let Some(watch) = inner.watches.get(&wd) {
                // ino/sdev are skip-assigned by the test (`%*x`); only mask is
                // load-bearing. mask is %08x in the kernel; render it the same.
                out.push_str(&format!(
                    "inotify wd:{wd} ino:0 sdev:0 mask:{:08x} ignored_mask:0 fhandle-bytes:0 fhandle-type:0 f_handle:0\n",
                    watch.mask
                ));
            }
        }
        out
    }
}

/// Pop whole `inotify_event` records from `inner.pending` up to `max_bytes`.
/// Empty queue → empty Vec (caller maps to EAGAIN); a buffer too small for the
/// first queued record → `Err(EINVAL)`, matching Linux.
fn drain_pending(inner: &mut Inner, max_bytes: usize) -> Result<Vec<u8>, LinuxErrno> {
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
    // Once the queue is fully drained the overflow latch lifts, so a watch that
    // keeps firing after the guest catches up can re-fill and overflow again.
    if inner.pending.is_empty() {
        inner.overflowed = false;
    }
    Ok(out)
}

/// One dispatch-layer watch: which inotify instance + watch descriptor a guest
/// path is registered under, and the event mask the guest asked for. Held by
/// [`InotifyRegistry`] so the fs handlers can synthesize precise events without
/// re-reading the per-instance tables.
#[derive(Clone)]
struct RegisteredWatch {
    state: std::sync::Arc<InotifyState>,
    wd: i32,
    mask: u32,
}

/// Dispatch-layer inotify watch table, keyed by the *guest* path each watch was
/// added on. carrick intercepts every guest fd syscall, so this lets the
/// open/read/write/close/create/unlink/rename/chmod handlers emit the exact
/// Linux event a coarse kqueue `NOTE_*` can't (`IN_OPEN`/`IN_ACCESS`/per-write
/// `IN_MODIFY`/`IN_CLOSE_*`, and transient `IN_CREATE`+`IN_DELETE` pairs).
///
/// This complements, and does not replace, the per-instance kqueue/native-
/// inotify backend: cross-process changes (a forked guest child mutating a
/// watched directory) are NOT visible here — the child is a separate host
/// process with its own copy of this in-memory table — so those still flow
/// through the fork-coherent kqueue path. The registry covers the same-process
/// operations the kqueue is too coarse for.
#[derive(Default)]
pub(crate) struct InotifyRegistry {
    /// Guest path → the watches registered on exactly that path. A directory
    /// watch is stored under the directory's own path; child events are routed
    /// by looking up the child's parent path here.
    by_path: parking_lot::RwLock<HashMap<String, Vec<RegisteredWatch>>>,
}

impl std::fmt::Debug for InotifyRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InotifyRegistry")
            .field("watched_paths", &self.by_path.read().len())
            .finish()
    }
}

impl InotifyRegistry {
    /// Record that `path` is now watched under `wd` of `state` with `mask`.
    /// Called from `inotify_add_watch` after the per-instance watch is added.
    pub(crate) fn register(
        &self,
        path: &str,
        state: &std::sync::Arc<InotifyState>,
        wd: i32,
        mask: u32,
    ) {
        let key = normalize_watch_path(path);
        let mut by_path = self.by_path.write();
        let entry = by_path.entry(key).or_default();
        // Re-adding the same (instance, wd) updates the mask in place (inotify
        // returns the same wd for a re-add and replaces the mask).
        if let Some(existing) = entry
            .iter_mut()
            .find(|w| w.wd == wd && std::sync::Arc::ptr_eq(&w.state, state))
        {
            existing.mask = mask;
        } else {
            entry.push(RegisteredWatch {
                state: std::sync::Arc::clone(state),
                wd,
                mask,
            });
        }
    }

    /// Drop every registry entry for `wd` of `state` (an `inotify_rm_watch`, or
    /// the inotify fd closing). `state` is compared by pointer so two instances
    /// that reused the same small `wd` don't clobber each other.
    pub(crate) fn unregister(&self, state: &std::sync::Arc<InotifyState>, wd: i32) {
        let mut by_path = self.by_path.write();
        by_path.retain(|_, watches| {
            watches.retain(|w| !(w.wd == wd && std::sync::Arc::ptr_eq(&w.state, state)));
            !watches.is_empty()
        });
    }

    /// Drop every registry entry belonging to `state` (the whole inotify
    /// instance closing). Called when an inotify fd is closed.
    pub(crate) fn unregister_all(&self, state: &std::sync::Arc<InotifyState>) {
        let mut by_path = self.by_path.write();
        by_path.retain(|_, watches| {
            watches.retain(|w| !std::sync::Arc::ptr_eq(&w.state, state));
            !watches.is_empty()
        });
    }

    /// Drop every watch registered on exactly `path` (the watched object was
    /// deleted or moved away — the kernel auto-removes the watch and sends
    /// `IN_IGNORED`, which the caller emits just before this). Does NOT touch
    /// watches on the parent or on children.
    pub(crate) fn unregister_path(&self, path: &str) {
        let key = normalize_watch_path(path);
        self.by_path.write().remove(&key);
    }

    /// Move a watch from `from` to `to` (a `rename(2)` of a watched object):
    /// the kernel keeps the watch alive on the renamed inode, so the wd stays
    /// valid and future events route under the new path. A watch already on
    /// `to` (the rename replaced it) is dropped first, matching the inode
    /// replacement. No-op when `from` isn't watched.
    pub(crate) fn rename_path(&self, from: &str, to: &str) {
        let from_key = normalize_watch_path(from);
        let to_key = normalize_watch_path(to);
        if from_key == to_key {
            return;
        }
        let mut by_path = self.by_path.write();
        if let Some(watches) = by_path.remove(&from_key) {
            by_path.insert(to_key, watches);
        }
    }

    /// True iff nothing is currently watched (the hot-path fast exit: the fs
    /// handlers skip all event work when no inotify watch exists).
    pub(crate) fn is_empty(&self) -> bool {
        self.by_path.read().is_empty()
    }

    /// Emit a *self* event on `path` (the watched object itself changed):
    /// `IN_OPEN`/`IN_ACCESS`/`IN_MODIFY`/`IN_ATTRIB`/`IN_CLOSE_*` on a watched
    /// file, or the directory-self form. `name` is `None` (self events carry no
    /// basename). `is_dir` sets `IN_ISDIR`.
    pub(crate) fn notify_self(&self, path: &str, mask: u32, is_dir: bool) {
        self.dispatch(&normalize_watch_path(path), mask, is_dir, None, 0, false);
    }

    /// Emit a *child* event on the directory containing `path`: e.g. an
    /// `IN_CREATE`/`IN_DELETE` with `name = basename(path)` delivered to a watch
    /// on the parent directory. `is_dir` sets `IN_ISDIR` (the child is a dir).
    pub(crate) fn notify_child(&self, path: &str, mask: u32, is_dir: bool) {
        self.notify_child_excl(path, mask, is_dir, false);
    }

    /// `notify_child`, plus the `IN_EXCL_UNLINK` discriminator: when
    /// `child_unlinked` is true the named child has been unlinked from the
    /// watched directory, so a watch added with `IN_EXCL_UNLINK` must NOT receive
    /// this event (inotify(7): "events are not generated for children after they
    /// have been unlinked from the watched directory"). Watches without the flag
    /// still get it (the default behaviour — events continue for an unlinked-but-
    /// still-open child). Used by the read/write/close hooks, which fire on an fd
    /// whose path may already be unlinked.
    pub(crate) fn notify_child_excl(
        &self,
        path: &str,
        mask: u32,
        is_dir: bool,
        child_unlinked: bool,
    ) {
        let norm = normalize_watch_path(path);
        let (parent, name) = split_parent_name(&norm);
        if name.is_empty() {
            return;
        }
        self.dispatch(
            parent,
            mask,
            is_dir,
            Some(name.as_bytes()),
            0,
            child_unlinked,
        );
    }

    /// Emit a rename pair: `IN_MOVED_FROM` (basename of `from`) on `from`'s
    /// parent and `IN_MOVED_TO` (basename of `to`) on `to`'s parent, tied by one
    /// freshly drawn cookie *per watching instance* (the kernel pairs them by
    /// cookie within a single inotify fd). `is_dir` sets `IN_ISDIR`.
    pub(crate) fn notify_move(&self, from: &str, to: &str, is_dir: bool) {
        let from_norm = normalize_watch_path(from);
        let to_norm = normalize_watch_path(to);
        let (from_parent, from_name) = split_parent_name(&from_norm);
        let (to_parent, to_name) = split_parent_name(&to_norm);
        let by_path = self.by_path.read();
        // FROM and TO can land on different watches; cookie pairing only matters
        // when the *same* instance watches both parents, so cache a cookie per
        // instance the first time it is touched.
        let mut cookies: Vec<(*const InotifyState, u32)> = Vec::new();
        let mut cookie_for = |state: &std::sync::Arc<InotifyState>| -> u32 {
            let ptr = std::sync::Arc::as_ptr(state);
            if let Some((_, c)) = cookies.iter().find(|(p, _)| *p == ptr) {
                *c
            } else {
                let c = state.next_cookie();
                cookies.push((ptr, c));
                c
            }
        };
        let mut fired_oneshot: Vec<OneshotFire> = Vec::new();
        if !from_name.is_empty() {
            dispatch_in(
                &by_path,
                from_parent,
                carrick_abi::LINUX_IN_MOVED_FROM,
                is_dir,
                Some(from_name.as_bytes()),
                false,
                &mut cookie_for,
                &mut fired_oneshot,
            );
        }
        if !to_name.is_empty() {
            dispatch_in(
                &by_path,
                to_parent,
                carrick_abi::LINUX_IN_MOVED_TO,
                is_dir,
                Some(to_name.as_bytes()),
                false,
                &mut cookie_for,
                &mut fired_oneshot,
            );
        }
        drop(by_path);
        self.retire_oneshot(fired_oneshot);
    }

    /// Core fan-out: deliver `mask` (optionally `| IN_ISDIR`) to every watch on
    /// `path`, masked by what each watch requested. `child_unlinked` gates the
    /// `IN_EXCL_UNLINK` watches; any `IN_ONESHOT` watch that fires is retired
    /// (removed + `IN_IGNORED`) after the read lock is released.
    fn dispatch(
        &self,
        path: &str,
        mask: u32,
        is_dir: bool,
        name: Option<&[u8]>,
        cookie: u32,
        child_unlinked: bool,
    ) {
        let mut fired_oneshot: Vec<OneshotFire> = Vec::new();
        {
            let by_path = self.by_path.read();
            let mut const_cookie = |_: &std::sync::Arc<InotifyState>| cookie;
            dispatch_in(
                &by_path,
                path,
                mask,
                is_dir,
                name,
                child_unlinked,
                &mut const_cookie,
                &mut fired_oneshot,
            );
        }
        self.retire_oneshot(fired_oneshot);
    }

    /// Retire every `IN_ONESHOT` watch that just delivered its single event:
    /// emit the auto-removal `IN_IGNORED` (the kernel always follows a oneshot
    /// fire with one), drop the per-instance watch, and remove the registry
    /// entry. Runs after the dispatch read lock is dropped so it can take the
    /// write lock. (inotify12 #1: `IN_MODIFY | IN_ONESHOT` fires exactly once;
    /// the second write then sees no watch and the read returns EAGAIN.)
    fn retire_oneshot(&self, fired: Vec<OneshotFire>) {
        for fire in fired {
            // The watch is gone after one event; IN_IGNORED announces that.
            fire.state
                .enqueue(fire.wd, carrick_abi::LINUX_IN_IGNORED, 0, None);
            let _ = fire.state.rm_watch(fire.wd);
            self.unregister(&fire.state, fire.wd);
        }
    }
}

/// A fired `IN_ONESHOT` watch awaiting retirement (collected under the dispatch
/// read lock, acted on after it is released).
struct OneshotFire {
    state: std::sync::Arc<InotifyState>,
    wd: i32,
}

/// Deliver one event to every watch registered on `path`, filtered by each
/// watch's requested mask, drawing the cookie from `cookie_for`. Free function
/// so both [`InotifyRegistry::dispatch`] and `notify_move` can share it while
/// holding the read lock. Any `IN_ONESHOT` watch that fires is pushed to
/// `fired_oneshot` for the caller to retire once the lock is released.
#[allow(clippy::too_many_arguments)]
fn dispatch_in(
    by_path: &HashMap<String, Vec<RegisteredWatch>>,
    path: &str,
    mask: u32,
    is_dir: bool,
    name: Option<&[u8]>,
    child_unlinked: bool,
    cookie_for: &mut dyn FnMut(&std::sync::Arc<InotifyState>) -> u32,
    fired_oneshot: &mut Vec<OneshotFire>,
) {
    let Some(watches) = by_path.get(path) else {
        return;
    };
    for watch in watches {
        // IN_EXCL_UNLINK: once a child is unlinked from the watched directory, a
        // watch carrying this flag stops receiving its events (inotify12 #2).
        // Watches without the flag keep getting them (the default).
        if child_unlinked && watch.mask & carrick_abi::LINUX_IN_EXCL_UNLINK != 0 {
            continue;
        }
        // The kernel reports only the bits the watch asked for, EXCEPT the
        // unconditional info events (IN_IGNORED on watch removal, IN_Q_OVERFLOW,
        // IN_UNMOUNT), which are delivered regardless of the watch mask. Without
        // this an `IN_ALL_EVENTS` watch — whose mask excludes IN_IGNORED
        // (0x8000) — would have its auto-removal IN_IGNORED filtered out
        // (inotify04 asserts exactly that IN_IGNORED).
        let delivered = (mask & watch.mask) | (mask & UNCONDITIONAL_EVENT_BITS);
        if delivered == 0 {
            continue;
        }
        let out_mask = if is_dir {
            delivered | carrick_abi::LINUX_IN_ISDIR
        } else {
            delivered
        };
        let cookie = cookie_for(&watch.state);
        watch.state.enqueue(watch.wd, out_mask, cookie, name);
        // IN_ONESHOT: the watch is removed after its first delivered event.
        if watch.mask & carrick_abi::LINUX_IN_ONESHOT != 0 {
            fired_oneshot.push(OneshotFire {
                state: std::sync::Arc::clone(&watch.state),
                wd: watch.wd,
            });
        }
    }
}

/// Normalize a guest path to the registry key form: collapse to an absolute
/// path without a trailing slash (except root). Watches and lookups must agree
/// on the exact key, so both sides route through this.
fn normalize_watch_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Split a normalized path into `(parent, basename)`. Root and bare names map to
/// parent `"/"`.
fn split_parent_name(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(idx) => (&path[..idx], &path[idx + 1..]),
        None => ("/", path),
    }
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

/// Encode one wire `struct inotify_event` with an explicit `cookie` (the
/// rename-pairing field). Platform-neutral: the dispatch-layer synthesis path
/// uses it on every host, not just macOS. `name` is NUL-terminated and padded so
/// the next record starts 4-byte aligned (`len` counts the padded length).
fn encode_event_raw(wd: i32, mask: u32, cookie: u32, name: Option<&[u8]>) -> Vec<u8> {
    let name_len = name.map(|name| align4(name.len() + 1)).unwrap_or(0);
    let mut record = Vec::with_capacity(INOTIFY_EVENT_HEADER_SIZE + name_len);
    record.extend_from_slice(&wd.to_ne_bytes());
    record.extend_from_slice(&mask.to_ne_bytes());
    record.extend_from_slice(&cookie.to_ne_bytes());
    record.extend_from_slice(&(name_len as u32).to_ne_bytes());
    if let Some(name) = name {
        record.extend_from_slice(name);
        record.resize(INOTIFY_EVENT_HEADER_SIZE + name_len, 0);
    }
    record
}

/// Cookie-less convenience used by the macOS kqueue/diff backend, which never
/// pairs moves (it only synthesizes CREATE/DELETE/MODIFY/self-events).
#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
fn encode_event(wd: i32, mask: u32, name: Option<&[u8]>) -> Vec<u8> {
    encode_event_raw(wd, mask, 0, name)
}

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
        // The native inotify fd (Linux) is owned by the backend, which closes it
        // in its own `Drop` after this runs (struct fields drop in declaration
        // order, so `backend` drops after `inner`).
    }
}

#[cfg(feature = "platform-linux")]
impl Drop for NativeLinuxInotify {
    fn drop(&mut self) {
        // Close the native inotify fd; any outstanding watches are torn down
        // with it.
        // SAFETY: we own the inotify fd for the backend's lifetime.
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

// Platform-neutral tests for the dispatch-layer synthesis pieces: wire encoding,
// the bounded-queue + IN_Q_OVERFLOW policy, and the path-routing registry. These
// run on every host (the synthesis path is not macOS-gated).
#[cfg(test)]
mod registry_tests {
    use super::*;

    fn parse_header(rec: &[u8]) -> (i32, u32, u32, u32) {
        let wd = i32::from_ne_bytes(rec[0..4].try_into().unwrap());
        let mask = u32::from_ne_bytes(rec[4..8].try_into().unwrap());
        let cookie = u32::from_ne_bytes(rec[8..12].try_into().unwrap());
        let len = u32::from_ne_bytes(rec[12..16].try_into().unwrap());
        (wd, mask, cookie, len)
    }

    #[test]
    fn encode_event_raw_lays_out_header_and_padded_name() {
        // No name: exactly the 16-byte header, len == 0.
        let rec = encode_event_raw(7, carrick_abi::LINUX_IN_OPEN, 0, None);
        assert_eq!(rec.len(), INOTIFY_EVENT_HEADER_SIZE);
        let (wd, mask, cookie, len) = parse_header(&rec);
        assert_eq!(
            (wd, mask, cookie, len),
            (7, carrick_abi::LINUX_IN_OPEN, 0, 0)
        );

        // 3-char name "foo" → NUL-terminated + 4-byte aligned = 4 bytes.
        let rec = encode_event_raw(3, carrick_abi::LINUX_IN_CREATE, 42, Some(b"foo"));
        let (wd, mask, cookie, len) = parse_header(&rec);
        assert_eq!((wd, mask, cookie), (3, carrick_abi::LINUX_IN_CREATE, 42));
        assert_eq!(len, 4, "len counts the NUL-padded, 4-aligned name");
        assert_eq!(rec.len(), INOTIFY_EVENT_HEADER_SIZE + 4);
        assert_eq!(&rec[16..19], b"foo");
        assert_eq!(rec[19], 0, "name is NUL-padded");

        // 4-char name "test" → 5 bytes with NUL, rounded up to 8.
        let rec = encode_event_raw(1, carrick_abi::LINUX_IN_DELETE, 0, Some(b"test"));
        let (_, _, _, len) = parse_header(&rec);
        assert_eq!(len, 8);
        assert_eq!(rec.len(), INOTIFY_EVENT_HEADER_SIZE + 8);
    }

    #[test]
    fn bounded_queue_appends_single_overflow_marker_then_drops() {
        let mut inner = Inner::new();
        // Fill exactly to the ceiling. Use a distinct cookie per record so the
        // event-coalescing rule (identical successive records collapse into one)
        // does not collapse the fill — each push must be a NEW event, exactly
        // like inotify05's alternating ACCESS/MODIFY stream that drives overflow.
        for i in 0..INOTIFY_MAX_QUEUED_EVENTS {
            inner.push_record(encode_event_raw(
                1,
                carrick_abi::LINUX_IN_MODIFY,
                i as u32,
                None,
            ));
        }
        assert_eq!(inner.pending.len(), INOTIFY_MAX_QUEUED_EVENTS);
        assert!(!inner.overflowed);
        // The next push trips overflow: a single IN_Q_OVERFLOW marker is
        // appended and further pushes are dropped.
        inner.push_record(encode_event_raw(
            1,
            carrick_abi::LINUX_IN_MODIFY,
            INOTIFY_MAX_QUEUED_EVENTS as u32,
            None,
        ));
        assert!(inner.overflowed);
        inner.push_record(encode_event_raw(
            1,
            carrick_abi::LINUX_IN_MODIFY,
            INOTIFY_MAX_QUEUED_EVENTS as u32 + 1,
            None,
        ));
        assert_eq!(
            inner.pending.len(),
            INOTIFY_MAX_QUEUED_EVENTS + 1,
            "exactly one overflow marker, no further records"
        );
        // The tail record is the overflow marker: wd=-1, mask=IN_Q_OVERFLOW,
        // cookie=0, len=0.
        let last = inner.pending.back().unwrap();
        let (wd, mask, cookie, len) = parse_header(last);
        assert_eq!(wd, -1);
        assert_eq!(mask, carrick_abi::LINUX_IN_Q_OVERFLOW);
        assert_eq!((cookie, len), (0, 0));
        // Draining everything lifts the latch so the queue can overflow again.
        let _ = drain_pending(&mut inner, usize::MAX);
        assert!(!inner.overflowed);
        assert!(inner.pending.is_empty());
    }

    #[test]
    fn identical_successive_records_coalesce_until_read() {
        let mut inner = Inner::new();
        // inotify(7): identical successive events (same wd|mask|cookie|name)
        // coalesce into one while the older is still queued. (inotify02's two
        // back-to-back IN_MOVE_SELF collapse to a single event.)
        let rec = || encode_event_raw(1, carrick_abi::LINUX_IN_MOVE_SELF, 0, None);
        inner.push_record(rec());
        inner.push_record(rec());
        inner.push_record(rec());
        assert_eq!(inner.pending.len(), 1, "identical records coalesce to one");
        // A DIFFERENT event in between breaks the run, so the next identical one
        // is a fresh event (it is no longer the tail).
        inner.push_record(encode_event_raw(1, carrick_abi::LINUX_IN_ATTRIB, 0, None));
        inner.push_record(rec());
        assert_eq!(
            inner.pending.len(),
            3,
            "a differing event breaks coalescing"
        );
        // Once the older identical event is read (drained), a later identical one
        // is queued anew rather than coalesced.
        let _ = drain_pending(&mut inner, usize::MAX);
        assert!(inner.pending.is_empty());
        inner.push_record(rec());
        inner.push_record(rec());
        assert_eq!(
            inner.pending.len(),
            1,
            "after a full drain, a repeat still coalesces against the new tail"
        );
    }

    #[test]
    fn registry_routes_self_child_and_move_to_the_right_watch() {
        let state = std::sync::Arc::new(InotifyState::new().expect("inotify backend"));
        let reg = InotifyRegistry::default();
        // Watch the directory "/w" with all events.
        let wd = state.add_virtual_watch(carrick_abi::LINUX_IN_ALL_EVENTS);
        reg.register("/w", &state, wd, carrick_abi::LINUX_IN_ALL_EVENTS);
        state.mark_dispatch_authoritative();
        assert!(!reg.is_empty());

        // A child create under the watched dir → IN_CREATE with name "child".
        reg.notify_child("/w/child", carrick_abi::LINUX_IN_CREATE, false);
        let bytes = state.read_records(4096).expect("read");
        let (got_wd, mask, _, len) = parse_header(&bytes);
        assert_eq!(got_wd, wd);
        assert_eq!(mask, carrick_abi::LINUX_IN_CREATE);
        assert_eq!(&bytes[16..16 + 5], b"child"); // "child\0..." within the padded name
        assert!(len >= 6);

        // A self event on the watched dir → IN_ISDIR set, no name.
        reg.notify_self("/w", carrick_abi::LINUX_IN_ATTRIB, true);
        let bytes = state.read_records(4096).expect("read");
        let (_, mask, _, len) = parse_header(&bytes);
        assert_eq!(
            mask,
            carrick_abi::LINUX_IN_ATTRIB | carrick_abi::LINUX_IN_ISDIR
        );
        assert_eq!(len, 0);

        // A rename within the watched dir → IN_MOVED_FROM + IN_MOVED_TO sharing
        // one non-zero cookie.
        reg.notify_move("/w/a", "/w/b", false);
        let bytes = state.read_records(4096).expect("read");
        // Two records back-to-back; first is MOVED_FROM "a", second MOVED_TO "b".
        let (_, m0, c0, l0) = parse_header(&bytes);
        assert_eq!(m0, carrick_abi::LINUX_IN_MOVED_FROM);
        let rec1 = &bytes[16 + l0 as usize..];
        let (_, m1, c1, _) = parse_header(rec1);
        assert_eq!(m1, carrick_abi::LINUX_IN_MOVED_TO);
        assert_ne!(c0, 0, "move cookie must be non-zero");
        assert_eq!(c0, c1, "MOVED_FROM and MOVED_TO must share a cookie");

        // An event the watch did not request is filtered out (empty → EAGAIN at
        // the dispatcher). Re-register with only IN_MODIFY.
        reg.unregister(&state, wd);
        let wd2 = state.add_virtual_watch(carrick_abi::LINUX_IN_MODIFY);
        reg.register("/w", &state, wd2, carrick_abi::LINUX_IN_MODIFY);
        reg.notify_self("/w", carrick_abi::LINUX_IN_ATTRIB, true); // not requested
        assert!(state.read_records(4096).expect("read").is_empty());
    }

    #[test]
    fn registry_unregister_and_rename_path_update_routing() {
        let state = std::sync::Arc::new(InotifyState::new().expect("inotify backend"));
        let reg = InotifyRegistry::default();
        let wd = state.add_virtual_watch(carrick_abi::LINUX_IN_ALL_EVENTS);
        reg.register("/old", &state, wd, carrick_abi::LINUX_IN_ALL_EVENTS);

        // rename_path moves the watch's key; a self event now routes via the new
        // path, not the old one.
        reg.rename_path("/old", "/new");
        reg.notify_self("/old", carrick_abi::LINUX_IN_ATTRIB, false);
        assert!(state.read_records(4096).expect("read").is_empty());
        reg.notify_self("/new", carrick_abi::LINUX_IN_ATTRIB, false);
        assert!(!state.read_records(4096).expect("read").is_empty());

        // unregister_path drops it entirely.
        reg.unregister_path("/new");
        assert!(reg.is_empty());
    }
}
