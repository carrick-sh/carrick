//! Native Linux [`EventMultiplexer`] backed by a single epoll set.
//!
//! One `epoll` instance services every event class the runtime needs, mirroring
//! the contract of the BSD sibling (`carrick_host_bsd::multiplexer::KqueueMultiplexer`)
//! kqueue-for-everything design:
//!
//!   * **IO readiness** — fds added directly with `EPOLLIN`/`EPOLLOUT`/`EPOLLPRI`
//!     (`EPOLLET` when edge-triggered). This is the kqueue `EVFILT_READ`/
//!     `EVFILT_WRITE`/`EVFILT_EXCEPT` analogue.
//!   * **User wakes** (`EVFILT_USER`) — an `eventfd` per ident, added `EPOLLIN`;
//!     `trigger_user` writes the counter, `wait` drains it and surfaces the ident
//!     with **no** IO readiness (a "re-check" wake, matching the BSD path).
//!   * **Timers** (`EVFILT_TIMER`) — a `timerfd` per token.
//!   * **Vnode/file events** (`EVFILT_VNODE`) — one lazily-created `inotify`
//!     instance; each watched fd is resolved to a path via `/proc/self/fd/<fd>`
//!     and added with the translated `IN_*` mask.
//!   * **Process exit** (`EVFILT_PROC` + `NOTE_EXITSTATUS`) — a `pidfd` per pid,
//!     readable on exit; `wait` PEEKs the status with
//!     `waitid(P_PIDFD, …, WEXITED|WNOWAIT|WNOHANG)` so the guest's own `wait4`
//!     can still reap the zombie.
//!
//! Every helper fd (`eventfd`/`timerfd`/`inotify`/`pidfd`) is owned by this
//! struct and closed on `Drop`; the epoll fd itself is closed last.
#![allow(clippy::useless_conversion)] // c_int<->i32 casts read clearer explicit.

use carrick_hal::error::OsError;
use carrick_hal::event::{
    EventMultiplexer, Interest, PollEvent, Readiness, TriggerMode, VnodeEvents,
};
use std::collections::HashMap;
use std::os::fd::RawFd;
use std::time::Duration;

/// Top bit of the 64-bit token space is reserved so a user-wake's `eventfd`
/// readiness can carry the caller's `ident` without colliding with a real
/// token. `wait` strips the flag and reports the bare ident.
const USER_TOKEN_FLAG: u64 = 1u64 << 63;

/// One epoll set servicing IO, timers, user-wakes, vnode and process-exit events.
pub struct EpollMultiplexer {
    epfd: RawFd,
    /// fds currently in the epoll set via [`register_io`](Self::register_io), so
    /// we know whether to `EPOLL_CTL_ADD` or `EPOLL_CTL_MOD`. Maps fd → token.
    io_fds: HashMap<RawFd, u64>,
    /// ident → owned eventfd (user wakes).
    user_eventfds: HashMap<u64, RawFd>,
    /// token → owned timerfd.
    timer_fds: HashMap<u64, RawFd>,
    /// token → owned pidfd (process-exit watches).
    pidfds: HashMap<u64, RawFd>,
    /// Lazily-created inotify instance (one for the whole multiplexer).
    inotify_fd: Option<RawFd>,
    /// inotify watch-descriptor → token.
    wd_to_token: HashMap<i32, u64>,
    /// watched fd → its inotify watch-descriptor (so `deregister(fd)` can drop it).
    fd_to_wd: HashMap<RawFd, i32>,
}

impl EpollMultiplexer {
    /// Create the epoll set (`epoll_create1(EPOLL_CLOEXEC)`).
    pub fn new() -> Result<Self, OsError> {
        // SAFETY: epoll_create1 is a plain syscall taking a flags int.
        let epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epfd < 0 {
            return Err(OsError::last("epoll_create1"));
        }
        Ok(Self {
            epfd,
            io_fds: HashMap::new(),
            user_eventfds: HashMap::new(),
            timer_fds: HashMap::new(),
            pidfds: HashMap::new(),
            inotify_fd: None,
            wd_to_token: HashMap::new(),
            fd_to_wd: HashMap::new(),
        })
    }

    /// `epoll_ctl(ADD)`, transparently retrying as `MOD` if the fd was already
    /// registered (`EEXIST`). `events`/`token` form the `epoll_event`.
    fn ctl_add_or_mod(&self, fd: RawFd, events: u32, token: u64) -> Result<(), OsError> {
        let mut ev = libc::epoll_event { events, u64: token };
        // SAFETY: &mut ev is a valid epoll_event for the duration of the call.
        let rc = unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) };
        if rc == 0 {
            return Ok(());
        }
        let err = OsError::last("epoll_ctl(ADD)");
        if err.errno == libc::EEXIST {
            // SAFETY: same as above; MOD updates the existing registration.
            let rc = unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_MOD, fd, &mut ev) };
            if rc == 0 {
                return Ok(());
            }
            return Err(OsError::last("epoll_ctl(MOD)"));
        }
        Err(err)
    }

    /// `epoll_ctl(DEL)`, ignoring `ENOENT`/`EBADF` (fd already gone).
    fn ctl_del(&self, fd: RawFd) {
        // SAFETY: DEL ignores the event pointer; null is permitted on modern
        // kernels and we never deref it.
        let _ =
            unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_DEL, fd, std::ptr::null_mut()) };
    }

    /// Lazily create the single inotify instance and add it to the epoll set.
    /// Its readiness is surfaced internally (token `0` is never returned from a
    /// raw inotify event; we translate watch-descriptors to caller tokens in
    /// `wait`). We register it under a sentinel token equal to the inotify fd's
    /// own value so the `wait` loop can recognise "this is the inotify fd".
    fn ensure_inotify(&mut self) -> Result<RawFd, OsError> {
        if let Some(fd) = self.inotify_fd {
            return Ok(fd);
        }
        // SAFETY: inotify_init1 takes a flags int.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(OsError::last("inotify_init1"));
        }
        // Register the inotify fd under a token that encodes its own fd value so
        // `wait` can detect "the inotify instance fired" and demux per-wd.
        if let Err(e) = self.ctl_add_or_mod(fd, libc::EPOLLIN as u32, inotify_self_token(fd)) {
            // SAFETY: fd was just created and is owned here.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        self.inotify_fd = Some(fd);
        Ok(fd)
    }
}

/// Reserved token used for the inotify instance's own epoll registration. We do
/// not collide with user tokens because we only ever *match* against this exact
/// value (it is never handed back to the caller) and the caller never observes
/// it. Encoded distinctly from real tokens by OR-ing the user flag plus the fd.
fn inotify_self_token(fd: RawFd) -> u64 {
    USER_TOKEN_FLAG | 0x4000_0000_0000_0000u64 | (fd as u64)
}

impl Drop for EpollMultiplexer {
    fn drop(&mut self) {
        for &fd in self.user_eventfds.values() {
            // SAFETY: fds owned by this struct; closed exactly once at drop.
            unsafe { libc::close(fd) };
        }
        for &fd in self.timer_fds.values() {
            unsafe { libc::close(fd) };
        }
        for &fd in self.pidfds.values() {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.inotify_fd {
            unsafe { libc::close(fd) };
        }
        // SAFETY: epoll fd owned by this struct.
        unsafe { libc::close(self.epfd) };
    }
}

/// `pidfd_open(2)` via raw syscall — libc 0.2.x does not export a wrapper.
fn pidfd_open(pid: i32) -> RawFd {
    // SAFETY: SYS_pidfd_open(pid, flags) returns an fd or -1; no pointers.
    unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0i32) as RawFd }
}

/// `VnodeEvents` → inotify `IN_*` mask. `extend`/`write` both map to `IN_MODIFY`
/// (inotify has no separate "file grew" event); `delete` covers both the watched
/// inode going away (`IN_DELETE_SELF`) and a child being deleted (`IN_DELETE`);
/// `link`/`rename` cover the inode moving (`IN_MOVE_SELF`) and directory entries
/// moving in/out (`IN_MOVED_FROM`/`IN_MOVED_TO`).
fn vnode_to_inotify_mask(mask: VnodeEvents) -> u32 {
    let mut m = 0u32;
    if mask.delete {
        m |= libc::IN_DELETE_SELF | libc::IN_DELETE;
    }
    if mask.write {
        m |= libc::IN_MODIFY;
    }
    if mask.extend {
        m |= libc::IN_MODIFY;
    }
    if mask.attrib {
        m |= libc::IN_ATTRIB;
    }
    if mask.link {
        m |= libc::IN_MOVE_SELF;
    }
    if mask.rename {
        m |= libc::IN_MOVE_SELF | libc::IN_MOVED_FROM | libc::IN_MOVED_TO;
    }
    // `revoke` has no inotify analogue; ignored.
    m
}

impl EventMultiplexer for EpollMultiplexer {
    fn register_io(
        &mut self,
        fd: RawFd,
        token: u64,
        interest: Interest,
        mode: TriggerMode,
    ) -> Result<(), OsError> {
        let mut events: u32 = 0;
        if interest.read {
            events |= libc::EPOLLIN as u32;
        }
        if interest.write {
            events |= libc::EPOLLOUT as u32;
        }
        if interest.oob {
            events |= libc::EPOLLPRI as u32;
        }
        if mode == TriggerMode::Edge {
            events |= libc::EPOLLET as u32;
        }
        self.ctl_add_or_mod(fd, events, token)?;
        self.io_fds.insert(fd, token);
        Ok(())
    }

    fn register_vnode(&mut self, fd: RawFd, token: u64, mask: VnodeEvents) -> Result<(), OsError> {
        let ino = self.ensure_inotify()?;
        // Resolve the fd to a path the way inotify needs (it watches *paths*,
        // not fds): readlink(/proc/self/fd/<fd>).
        let link = format!("/proc/self/fd/{fd}");
        let mut buf = [0u8; libc::PATH_MAX as usize];
        // SAFETY: readlink writes at most buf.len() bytes; link is NUL-terminated
        // by CString.
        let clink = std::ffi::CString::new(link).map_err(|_| OsError::from_raw(libc::EINVAL))?;
        let n = unsafe {
            libc::readlink(
                clink.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if n < 0 {
            return Err(OsError::last("readlink(/proc/self/fd)"));
        }
        let path = &buf[..n as usize];
        let cpath = std::ffi::CString::new(path).map_err(|_| OsError::from_raw(libc::EINVAL))?;
        let ino_mask = vnode_to_inotify_mask(mask);
        // SAFETY: cpath is a valid NUL-terminated C string for the call.
        let wd = unsafe { libc::inotify_add_watch(ino, cpath.as_ptr(), ino_mask) };
        if wd < 0 {
            return Err(OsError::last("inotify_add_watch"));
        }
        self.wd_to_token.insert(wd, token);
        self.fd_to_wd.insert(fd, wd);
        Ok(())
    }

    fn watch_process_exit(&mut self, pid: i32, token: u64) -> Result<(), OsError> {
        let pidfd = pidfd_open(pid);
        if pidfd < 0 {
            return Err(OsError::last("pidfd_open"));
        }
        if let Err(e) = self.ctl_add_or_mod(pidfd, libc::EPOLLIN as u32, token) {
            // SAFETY: pidfd just created and owned here.
            unsafe { libc::close(pidfd) };
            return Err(e);
        }
        // If a token was already watched, close the prior pidfd to avoid a leak.
        if let Some(old) = self.pidfds.insert(token, pidfd) {
            self.ctl_del(old);
            // SAFETY: old pidfd owned by this struct, replaced now.
            unsafe { libc::close(old) };
        }
        Ok(())
    }

    fn register_user(&mut self, ident: u64) -> Result<(), OsError> {
        // SAFETY: eventfd(initval, flags) takes scalars only.
        let efd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if efd < 0 {
            return Err(OsError::last("eventfd"));
        }
        let token = USER_TOKEN_FLAG | ident;
        if let Err(e) = self.ctl_add_or_mod(efd, libc::EPOLLIN as u32, token) {
            // SAFETY: efd just created and owned here.
            unsafe { libc::close(efd) };
            return Err(e);
        }
        if let Some(old) = self.user_eventfds.insert(ident, efd) {
            self.ctl_del(old);
            // SAFETY: old eventfd owned by this struct, replaced now.
            unsafe { libc::close(old) };
        }
        Ok(())
    }

    fn trigger_user(&self, ident: u64) -> Result<(), OsError> {
        let Some(&efd) = self.user_eventfds.get(&ident) else {
            return Err(OsError::from_raw(libc::ENOENT));
        };
        let one: u64 = 1;
        // SAFETY: writing 8 bytes of a u64 counter to an eventfd is the defined
        // wake primitive; the pointer/len are valid for `one`.
        let rc = unsafe {
            libc::write(
                efd,
                &one as *const u64 as *const libc::c_void,
                std::mem::size_of::<u64>(),
            )
        };
        if rc != std::mem::size_of::<u64>() as isize {
            return Err(OsError::last("write(eventfd)"));
        }
        Ok(())
    }

    fn register_timer(
        &mut self,
        token: u64,
        interval: Duration,
        oneshot: bool,
    ) -> Result<(), OsError> {
        // SAFETY: timerfd_create takes scalars only.
        let tfd = unsafe {
            libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            )
        };
        if tfd < 0 {
            return Err(OsError::last("timerfd_create"));
        }
        let dur = libc::timespec {
            tv_sec: interval.as_secs() as libc::time_t,
            tv_nsec: interval.subsec_nanos() as i64,
        };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let spec = libc::itimerspec {
            // 0 reload for a oneshot; periodic otherwise.
            it_interval: if oneshot { zero } else { dur },
            // First (and for oneshot, only) expiry after `interval`.
            it_value: dur,
        };
        // SAFETY: &spec valid for the call; null old_value is permitted.
        let rc = unsafe { libc::timerfd_settime(tfd, 0, &spec, std::ptr::null_mut()) };
        if rc < 0 {
            let e = OsError::last("timerfd_settime");
            // SAFETY: tfd just created and owned here.
            unsafe { libc::close(tfd) };
            return Err(e);
        }
        if let Err(e) = self.ctl_add_or_mod(tfd, libc::EPOLLIN as u32, token) {
            // SAFETY: tfd just created and owned here.
            unsafe { libc::close(tfd) };
            return Err(e);
        }
        if let Some(old) = self.timer_fds.insert(token, tfd) {
            self.ctl_del(old);
            // SAFETY: old timerfd owned by this struct, replaced now.
            unsafe { libc::close(old) };
        }
        Ok(())
    }

    fn deregister(&mut self, fd: RawFd) -> Result<(), OsError> {
        self.ctl_del(fd);
        self.io_fds.remove(&fd);
        // Drop any inotify watch keyed on this fd.
        if let Some(wd) = self.fd_to_wd.remove(&fd) {
            self.wd_to_token.remove(&wd);
            if let Some(ino) = self.inotify_fd {
                // SAFETY: inotify_rm_watch on an owned inotify fd + valid wd.
                unsafe { libc::inotify_rm_watch(ino, wd) };
            }
        }
        Ok(())
    }

    fn wait(
        &mut self,
        out: &mut Vec<PollEvent>,
        timeout: Option<Duration>,
    ) -> Result<usize, OsError> {
        out.clear();
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 128];
        let timeout_ms: libc::c_int = match timeout {
            None => -1,
            Some(d) => {
                let ms = d.as_millis();
                if ms > libc::c_int::MAX as u128 {
                    libc::c_int::MAX
                } else {
                    ms as libc::c_int
                }
            }
        };

        // SAFETY: events buffer is valid for `events.len()` entries; null sigmask.
        let n = unsafe {
            libc::epoll_pwait(
                self.epfd,
                events.as_mut_ptr(),
                events.len() as libc::c_int,
                timeout_ms,
                std::ptr::null(),
            )
        };
        if n < 0 {
            return Err(OsError::last("epoll_pwait"));
        }

        for ev in events.iter().take(n as usize) {
            let raw_token = ev.u64;
            let flags = ev.events as libc::c_int;

            // The inotify instance: demux its queued events into per-wd tokens.
            if self.inotify_fd == Some(inotify_self_fd(raw_token)) && is_inotify_self(raw_token) {
                self.drain_inotify(out);
                continue;
            }

            let is_user = raw_token & USER_TOKEN_FLAG != 0;

            // A user-wake (eventfd) is a "re-check" signal: drain the counter and
            // surface the bare ident with NO readiness (mirrors the BSD path's
            // EVFILT_USER, which carries no IO readiness).
            if is_user {
                let ident = raw_token & !USER_TOKEN_FLAG;
                if let Some(&efd) = self.user_eventfds.get(&ident) {
                    let mut buf = [0u8; 8];
                    // SAFETY: draining 8 bytes from a nonblocking eventfd.
                    unsafe {
                        libc::read(efd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
                    }
                }
                out.push(PollEvent {
                    token: ident,
                    readiness: Readiness::empty(),
                    readiness_count: 0,
                    error: None,
                    eof: false,
                    exit_status: None,
                    vnode: None,
                });
                continue;
            }

            // A timerfd: drain the expiration count so a level-triggered epoll
            // registration goes quiet after we report the fire (kqueue's
            // EVFILT_TIMER auto-clears; a timerfd stays EPOLLIN-readable until
            // read). A oneshot will not re-arm; a periodic re-fires on schedule.
            if let Some(&tfd) = self.timer_fds.get(&raw_token) {
                let mut expirations = [0u8; 8];
                // SAFETY: draining the 8-byte expiration counter from a
                // nonblocking timerfd.
                unsafe {
                    libc::read(
                        tfd,
                        expirations.as_mut_ptr() as *mut libc::c_void,
                        expirations.len(),
                    );
                }
                out.push(PollEvent {
                    token: raw_token,
                    readiness: Readiness::READ,
                    readiness_count: 0,
                    error: None,
                    eof: false,
                    exit_status: None,
                    vnode: None,
                });
                continue;
            }

            // A process-exit pidfd: PEEK the status (WNOWAIT leaves the zombie so
            // the guest's own wait4 still reaps it).
            if let Some(&pidfd) = self.pidfds.get(&raw_token) {
                let exit_status = peek_pidfd_exit(pidfd);
                out.push(PollEvent {
                    token: raw_token,
                    readiness: Readiness::READ,
                    readiness_count: 0,
                    error: None,
                    eof: true,
                    exit_status,
                    vnode: None,
                });
                continue;
            }

            // Plain IO / timerfd readiness.
            let mut readiness = Readiness::empty();
            if flags & libc::EPOLLIN != 0 {
                readiness.read = true;
            }
            if flags & libc::EPOLLOUT != 0 {
                readiness.write = true;
            }
            if flags & libc::EPOLLPRI != 0 {
                readiness.oob = true;
            }
            let eof = flags & libc::EPOLLHUP != 0;
            let error = if flags & libc::EPOLLERR != 0 {
                // epoll does not surface a specific errno; report a generic EPOLLERR.
                Some(libc::EPOLLERR)
            } else {
                None
            };

            out.push(PollEvent {
                token: raw_token,
                readiness,
                readiness_count: 0,
                error,
                eof,
                exit_status: None,
                vnode: None,
            });
        }

        Ok(out.len())
    }

    fn poll_fd(&self) -> RawFd {
        self.epfd
    }

    /// The raw eventfd backing the user-wake channel for `ident` (registered via
    /// [`register_user`](EventMultiplexer::register_user)), if any. The runtime's
    /// in-memory wake registry stores this fd so a process-wide readiness
    /// broadcast can pop a parked `epoll_pwait` by writing the eventfd directly
    /// (mirroring the BSD path's `kqueue::trigger_user`, which drives the
    /// EVFILT_USER channel from the kqueue fd alone).
    fn user_wake_fd(&self, ident: u64) -> Option<RawFd> {
        self.user_eventfds.get(&ident).copied()
    }
}

/// Pulse a user-wake `eventfd` (the channel registered by
/// [`EpollMultiplexer::register_user`]) by writing its 8-byte counter. Used by
/// the runtime's in-memory readiness broadcast to wake a thread blocked on the
/// owning epoll set's `poll_fd`. A failed/closed fd is ignored (best-effort
/// wake); the eventfd is `EFD_NONBLOCK` so a saturated counter never blocks.
pub fn trigger_user_eventfd(efd: RawFd) {
    let one: u64 = 1;
    // SAFETY: writing 8 bytes of a u64 counter to an eventfd is its defined wake
    // primitive; `one`'s pointer/len are valid for the call.
    unsafe {
        libc::write(
            efd,
            &one as *const u64 as *const libc::c_void,
            std::mem::size_of::<u64>(),
        );
    }
}

impl EpollMultiplexer {
    /// Read all queued inotify events and translate each watch-descriptor to its
    /// caller token, emitting one `PollEvent` (read-readiness) per token seen.
    fn drain_inotify(&mut self, out: &mut Vec<PollEvent>) {
        let Some(ino) = self.inotify_fd else {
            return;
        };
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: reading into a stack buffer from a nonblocking inotify fd.
            let n = unsafe { libc::read(ino, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n <= 0 {
                break;
            }
            let mut off = 0usize;
            let hdr = std::mem::size_of::<libc::inotify_event>();
            while off + hdr <= n as usize {
                // SAFETY: off+hdr <= n, so the header bytes are initialised; we
                // read it by value via a copy to avoid an unaligned reference.
                let ev: libc::inotify_event = unsafe {
                    std::ptr::read_unaligned(buf.as_ptr().add(off) as *const libc::inotify_event)
                };
                let wd = ev.wd;
                let len = ev.len as usize;
                if let Some(&token) = self.wd_to_token.get(&wd) {
                    out.push(PollEvent {
                        token,
                        readiness: Readiness::READ,
                        readiness_count: 0,
                        error: None,
                        eof: ev.mask & (libc::IN_IGNORED | libc::IN_DELETE_SELF) != 0,
                        exit_status: None,
                        vnode: None,
                    });
                }
                off += hdr + len;
            }
            // If the read filled the buffer there may be more; loop. A short read
            // (< buf.len) plus EAGAIN on the next read terminates the loop.
            if (n as usize) < buf.len() {
                break;
            }
        }
    }
}

/// Recover the inotify fd value encoded in its self-token (see
/// [`inotify_self_token`]).
fn inotify_self_fd(token: u64) -> RawFd {
    (token & 0x0000_0000_FFFF_FFFFu64) as RawFd
}

/// True if `token` is the encoded inotify self-token.
fn is_inotify_self(token: u64) -> bool {
    token & (USER_TOKEN_FLAG | 0x4000_0000_0000_0000u64)
        == (USER_TOKEN_FLAG | 0x4000_0000_0000_0000u64)
}

/// PEEK a pidfd's exit status without reaping (`WNOWAIT`). Returns the bare exit
/// code on normal exit (`CLD_EXITED`), or `128 + signal` for a signal death
/// (`CLD_KILLED`/`CLD_DUMPED`) — the shell convention — so the caller always
/// gets a meaningful small integer. `None` if the process is not yet waitable
/// (should not happen once the pidfd is EPOLLIN-readable) or `waitid` errors.
fn peek_pidfd_exit(pidfd: RawFd) -> Option<i32> {
    // SAFETY: zeroed siginfo_t is a valid initial state for waitid to fill.
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid(P_PIDFD, pidfd, &si, flags) — si is valid for the call;
    // WNOWAIT leaves the zombie so the guest can reap it with wait4.
    let rc = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd as libc::id_t,
            &mut si,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if rc != 0 {
        return None;
    }
    // WNOHANG with no waitable state leaves si_pid == 0.
    // SAFETY: reading the SIGCHLD union fields of a waitid-populated siginfo.
    let pid = unsafe { si.si_pid() };
    if pid == 0 {
        return None;
    }
    // SAFETY: same union read; valid after a successful waitid.
    let code = si.si_code;
    let status = unsafe { si.si_status() };
    match code {
        libc::CLD_EXITED => Some(status),
        libc::CLD_KILLED | libc::CLD_DUMPED => Some(128 + status),
        _ => Some(status),
    }
}

#[cfg(test)]
mod tests {
    //! Host-runnable unit tests exercising each event class against the REAL
    //! Linux primitives (epoll/eventfd/timerfd/inotify/pidfd). They run on any
    //! aarch64/x86_64 Linux host (the crate is `cfg(target_os = "linux")`), e.g.
    //! the lima L2 lane. No `/dev/kvm` or guest is required.
    use super::*;
    use std::time::Instant;

    /// Block in `wait` up to `budget`, retrying across spurious empty wakes,
    /// until `out` is non-empty or the budget elapses. Returns the events.
    fn wait_until(mux: &mut EpollMultiplexer, budget: Duration) -> Vec<PollEvent> {
        let deadline = Instant::now() + budget;
        let mut out = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let n = mux.wait(&mut out, Some(remaining)).unwrap_or(0);
            if n > 0 {
                return out;
            }
            if Instant::now() >= deadline {
                return out;
            }
        }
    }

    #[test]
    fn register_io_pipe_read_readiness() -> Result<(), OsError> {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 fills a 2-element fd array.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(rc, 0, "pipe2 failed");
        let (rd, wr) = (fds[0], fds[1]);

        let mut mux = EpollMultiplexer::new()?;
        let token = 0xABCD_u64;
        mux.register_io(rd, token, Interest::READ, TriggerMode::Level)?;

        // Write to the write-end → read-end becomes readable.
        let byte = [42u8];
        // SAFETY: writing 1 byte to the pipe write-end.
        let w = unsafe { libc::write(wr, byte.as_ptr() as *const libc::c_void, 1) };
        assert_eq!(w, 1, "write to pipe");

        let evs = wait_until(&mut mux, Duration::from_millis(500));
        assert_eq!(evs.len(), 1, "expected one ready event, got {evs:?}");
        assert_eq!(evs[0].token, token, "token mismatch");
        assert!(evs[0].readiness.read, "expected read-readiness");

        // SAFETY: closing fds owned by this test.
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        Ok(())
    }

    /// GROUNDING (empirical, not assumed): the `EpollMultiplexer` is carrick's
    /// epoll-emulation primitive on Linux. carrick's `epoll_pwait` mirrors the
    /// guest's `EPOLLET` onto this multiplexer (`TriggerMode::Edge`) and relies on
    /// the host edge to deliver EOF to the guest. This test OBSERVES, against the
    /// real kernel, how many times a peer-close HUP on a pipe read-end is reported
    /// across repeated non-blocking `wait()`s under Edge vs Level — i.e. whether a
    /// HUP edge fires exactly once (so a drain that fails to deliver it loses it
    /// forever — the Go-netpoller hang) or re-reports (level). The `assert`s
    /// codify what the kernel actually does so a regression is caught.
    fn hup_reports(mode: TriggerMode) -> usize {
        let mut fds = [0i32; 2];
        // SAFETY: pipe2 fills a 2-element fd array.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(rc, 0, "pipe2 failed");
        let (rd, wr) = (fds[0], fds[1]);
        let mut mux = EpollMultiplexer::new().expect("mux");
        mux.register_io(rd, 0xEE, Interest::READ, mode)
            .expect("register");
        // Peer closes the write-end: the read-end is now at permanent EOF (HUP).
        // SAFETY: closing the write-end this test owns.
        unsafe {
            libc::close(wr);
        }
        // Count how many of three back-to-back NON-BLOCKING drains report it.
        let mut reports = 0usize;
        for _ in 0..3 {
            let mut out = Vec::new();
            let n = mux.wait(&mut out, Some(Duration::ZERO)).unwrap_or(0);
            if n > 0 {
                reports += 1;
            }
        }
        // SAFETY: closing the read-end this test owns.
        unsafe {
            libc::close(rd);
        }
        reports
    }

    #[test]
    fn edge_hup_fires_once_level_re_reports() {
        let edge = hup_reports(TriggerMode::Edge);
        let level = hup_reports(TriggerMode::Level);
        eprintln!(
            "HUP-after-peer-close reports over 3 non-blocking drains: edge={edge} level={level}"
        );
        // The whole edge-loss bug class: an EDGE registration reports the EOF/HUP
        // exactly ONCE — if carrick's drain consumes that single report without
        // delivering it to the guest (a concurrency race), it is gone forever. A
        // LEVEL registration re-reports the persistent HUP on every drain, so a
        // dropped report self-heals. This is WHY the emulation must register the
        // multiplexer LEVEL-triggered and apply the guest's edge semantics in
        // software (matching illumos's bitmap-latch + level-wakeup model).
        assert_eq!(
            edge, 1,
            "EDGE HUP must fire exactly once (the lost-edge risk)"
        );
        assert_eq!(
            level, 3,
            "LEVEL HUP must re-report on every drain (self-healing)"
        );
    }

    #[test]
    fn register_user_and_trigger() -> Result<(), OsError> {
        let mut mux = EpollMultiplexer::new()?;
        let ident = 7u64;
        mux.register_user(ident)?;
        mux.trigger_user(ident)?;

        let evs = wait_until(&mut mux, Duration::from_millis(500));
        assert_eq!(evs.len(), 1, "expected one wake, got {evs:?}");
        assert_eq!(evs[0].token, ident, "ident token must be the bare ident");
        // A user-wake carries no IO readiness (re-check semantics).
        assert!(
            !evs[0].readiness.read && !evs[0].readiness.write && !evs[0].readiness.oob,
            "user wake must carry no readiness"
        );
        Ok(())
    }

    #[test]
    fn register_timer_oneshot_fires_once() -> Result<(), OsError> {
        let mut mux = EpollMultiplexer::new()?;
        let token = 0x7117_u64;
        mux.register_timer(token, Duration::from_millis(20), true)?;

        let evs = wait_until(&mut mux, Duration::from_millis(200));
        assert_eq!(evs.len(), 1, "timer should fire once, got {evs:?}");
        assert_eq!(evs[0].token, token, "timer token");
        assert!(evs[0].readiness.read, "timer readiness is read");

        // A oneshot must NOT fire again within a comparable window.
        let mut out = Vec::new();
        let n = mux
            .wait(&mut out, Some(Duration::from_millis(80)))
            .unwrap_or(0);
        assert_eq!(n, 0, "oneshot timer must not re-fire, got {out:?}");
        Ok(())
    }

    #[test]
    fn watch_process_exit_peeks_status_and_leaves_reapable() -> Result<(), OsError> {
        // SAFETY: fork creates a child; child immediately _exit(42)s.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: exit with code 42 right away.
            // SAFETY: _exit never returns; no allocation across the fork.
            unsafe { libc::_exit(42) };
        }

        let mut mux = EpollMultiplexer::new()?;
        let token = 0xDEAD_u64;
        mux.watch_process_exit(pid, token)?;

        let evs = wait_until(&mut mux, Duration::from_millis(1000));
        assert_eq!(evs.len(), 1, "expected exit event, got {evs:?}");
        assert_eq!(evs[0].token, token, "exit token");
        assert_eq!(
            evs[0].exit_status,
            Some(42),
            "peeked exit status must be 42"
        );

        // Prove WNOWAIT did NOT consume the zombie: the guest's own wait4 must
        // still reap it successfully.
        let mut wstatus = 0i32;
        // SAFETY: waitpid on our own child; wstatus is a valid out-param.
        let reaped = unsafe { libc::waitpid(pid, &mut wstatus, 0) };
        assert_eq!(reaped, pid, "waitpid must still reap the child (WNOWAIT)");
        assert!(libc::WIFEXITED(wstatus), "child exited normally");
        assert_eq!(libc::WEXITSTATUS(wstatus), 42, "reaped exit code is 42");
        Ok(())
    }

    #[test]
    fn register_vnode_reports_modify() -> Result<(), OsError> {
        // Create a temp file, write-watch it, then modify it.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("carrick-epoll-vnode-{}", std::process::id()));
        let cpath = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| OsError::from_raw(libc::EINVAL))?;
        // SAFETY: open creates/truncates the temp file; flags+mode are valid.
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
                0o600,
            )
        };
        assert!(fd >= 0, "open temp file");

        let mut mux = EpollMultiplexer::new()?;
        let token = 0xF11E_u64;
        let mask = VnodeEvents {
            write: true,
            extend: true,
            ..Default::default()
        };
        mux.register_vnode(fd, token, mask)?;

        // Modify the file → IN_MODIFY.
        let data = b"hello";
        // SAFETY: writing into the watched fd.
        let w = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        assert_eq!(w, data.len() as isize, "write to watched file");

        let evs = wait_until(&mut mux, Duration::from_millis(1000));
        assert!(
            evs.iter().any(|e| e.token == token && e.readiness.read),
            "expected a vnode event for the token, got {evs:?}"
        );

        // SAFETY: cleanup.
        unsafe {
            libc::close(fd);
            libc::unlink(cpath.as_ptr());
        }
        Ok(())
    }
}
