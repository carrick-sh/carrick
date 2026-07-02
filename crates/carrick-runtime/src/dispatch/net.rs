//! Networking and readiness syscalls: BSD sockets, AF_NETLINK synthesis, the
//! `epoll`→`kqueue` shim, and `select`/`poll`/`pselect`/`ppoll`.
//!
//! # Theory of operation
//!
//! Two very different Linux subsystems share this file because they share one
//! fact: macOS already has a real, native implementation underneath, so the job
//! is *translation*, not *emulation*.
//!
//! ## Sockets: native BSD, translated at the edges
//!
//! AF_INET / AF_INET6 / AF_UNIX sockets are backed by REAL host sockets — the
//! guest's `socket(2)` becomes a host `socket(2)`, `connect`/`send`/`recv` flow
//! to the Darwin kernel, and a Linux server under carrick is reachable from the
//! macOS host (the web-server demo). Darwin and Linux agree on the numeric
//! socket *types* (1=STREAM, 2=DGRAM, …) but NOT on much else, so the handlers
//! translate at three boundaries:
//!
//!   - **Address families** (`linux_to_host_af` / `host_to_linux_af` in the
//!     `support` submodule). The shapes that exist on both sides map 1:1; Linux-only
//!     families (AF_PACKET) are passed through so the host `socket()` returns
//!     EAFNOSUPPORT naturally rather than carrick faking an error.
//!   - **`struct sockaddr`** (`read_linux_sockaddr` parses guest → host;
//!     `host_to_linux_sockaddr` / `write_linux_sockaddr` go the other way).
//!     AF_INET/INET6 differ only in the leading `sa_family` byte/halfword;
//!     AF_UNIX is the hard case (below).
//!   - **Buffer sizing and option semantics**: macOS gives an AF_UNIX stream
//!     socket only an 8 KiB buffer where Linux gives 212992, which strands a
//!     guest writer that fills its socket buffer expecting a non-blocking-style
//!     completion (`widen_unix_stream_buffers`); SEQPACKET has no macOS AF_UNIX
//!     backing and is framed on top of a STREAM socket
//!     (`host_socktype_backing`).
//!
//! AF_UNIX carries its own emulation layer (path hashing + a process-global
//! registry, abstract namespace, autobind, SEQPACKET framing) so that Linux
//! AF_UNIX features macOS lacks still work; that machinery lives in the
//! `support` submodule and is documented there.
//!
//! ## AF_NETLINK: there is no host netlink, so synthesise it
//!
//! macOS has no AF_NETLINK. Returning EAFNOSUPPORT is not acceptable: glibc's
//! `__check_pf`/`getaddrinfo` opens an `NETLINK_ROUTE` socket on the way to
//! every name resolution, and `ip`/`ss` are pure rtnetlink clients. So a netlink
//! `socket()` returns a SYNTHETIC fd (`OpenDescription::Netlink`) with NO host
//! backing — a userspace in-memory recv queue plus a remembered `(pid, groups)`
//! binding. `sendto`/`write` of an rtnetlink dump request is parsed and answered
//! by `support::build_netlink_reply`, which emits properly framed
//! `NLM_F_MULTI` dumps terminated by `NLMSG_DONE`: RTM_GETLINK yields one
//! `lo`, RTM_GETADDR yields `127.0.0.1/8`, RTM_GETROUTE yields the connected
//! route, and everything unmodelled yields a bare `NLMSG_DONE` (an "empty"
//! dump) so the client sees a well-formed end-of-dump rather than a hang. This
//! is consistent with carrick presenting itself as a single-`lo`,
//! loopback-only host (matching `docker run --net host`'s view from the guest's
//! standpoint for the resolver's purposes).
//!
//! ## epoll → kqueue: the readiness model
//!
//! Linux `epoll` is emulated on Darwin `kqueue`. `epoll_create1` allocates a
//! real kqueue; the returned epoll fd's readiness IS that kqueue's fd, so a
//! thread blocks by waiting on the kqueue (see `io_wait`). Two readiness
//! sources coexist on one kqueue:
//!
//!   - **Host-backed fds** (sockets, host files, ptys) register an
//!     `EVFILT_READ`/`EVFILT_WRITE` knote — the kernel signals readiness.
//!   - **In-memory fds** (eventfd, pipes, timerfd, netlink) have no host kernel
//!     object the kqueue can watch, so their readiness is recomputed in
//!     userspace (`epoll_ready_events`) and a writer pokes the kqueue's
//!     `EVFILT_USER(0)` to force every blocked waiter to re-check
//!     (see [`super::epoll_shim`]). This is the fix for Go's `netpollBreak`
//!     lost-wakeup: an eventfd write must wake a poller blocked on the instance
//!     kqueue even though the eventfd is not a host fd.
//!
//! `fd_is_epollable` mirrors the kernel rule that an fd whose file has no
//! `->poll` op (a regular file, directory, or synthetic /proc node) is rejected
//! from `epoll_ctl(ADD)` with EPERM.
//!
//! `select`/`poll`/`pselect6`/`ppoll` share the same readiness machinery; the
//! `*p*` variants additionally swap the signal mask for the duration of the
//! wait (atomically, the way the kernel does), which is why they reach into the
//! signal subsystem.
//!
//! Methods are `impl` blocks on [`SyscallDispatcher`]; see [`super`] for the
//! dispatcher struct and the normalized dispatch table. Socket/netlink/fd-set
//! helper routines and the AF_UNIX registry live in the `support` submodule.
use super::*;

syscall_table! {
    /// Per-module syscall routing for the `net` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `net` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_net;
    19 => eventfd2,
    20 => epoll_create1,
    carrick_abi::CARRICK_PRIVATE_X86_EPOLL_CREATE => x86_epoll_create,
    21 => epoll_ctl,
    22 => epoll_pwait,
    // x86_64 poll(2): shares the ppoll handler, which branches on the
    // canonical number to read arg2 as an INT timeout_ms (not a *timespec).
    carrick_abi::CARRICK_PRIVATE_X86_POLL => ppoll,
    // x86_64 select(2): shares the pselect6 handler, which branches on the
    // canonical number to read the timeout as a *timeval (not *timespec).
    carrick_abi::CARRICK_PRIVATE_X86_SELECT => pselect6,
    72 => pselect6,
    73 => ppoll,
    198 => socket,
    199 => socketpair,
    200 => bind,
    201 => listen,
    202 => accept,
    203 => connect,
    204 => getsockname,
    205 => getpeername,
    206 => sendto,
    207 => recvfrom,
    208 => setsockopt,
    209 => getsockopt,
    210 => shutdown,
    211 => sendmsg,
    212 => recvmsg,
    242 => accept4,
    243 => sys_recvmmsg,
    269 => sys_sendmmsg,
}
mod support;
use support::*;
pub(super) use support::{drain_netlink_queue, set_host_nonblocking};

/// Resolve a host `connect` that reported SUCCESS (`rc==0` or `EISCONN`) into the
/// guest result, consulting `SO_ERROR` first. carrick makes the host socket
/// non-blocking before `connect` (so it never blocks the dispatcher under the
/// lock), so a "success" return does NOT prove the connection completed: an async
/// connect that FAILED (e.g. `ECONNREFUSED` to a non-listening port) is reported
/// by macOS as `EISCONN` on the POLLOUT re-dispatch, deferring the real error to
/// the first `recv`. A BLOCKING guest `connect(2)` must surface that error at
/// connect time — otherwise `socket.create_connection`'s address fallback
/// (IPv6 `::1` → IPv4 `127.0.0.1`) never triggers and CPython's network suites
/// (ftplib/httplib/imaplib/docxmlrpc) wrongly fail. `SO_ERROR` is the
/// authoritative async-connect result; a healthy socket reports 0.
/// Linux `connect()` treats INADDR_ANY (0.0.0.0) as the loopback (127.0.0.1), but
/// FreeBSD/macOS return ENETUNREACH for it. Rewrite an unspecified IPv4 connect target
/// to loopback so a guest connecting to `0.0.0.0:port` behaves like Linux (LTP
/// send01/recv01/sendto01/recvfrom01). `sin_addr` is at offset 4 in both the Linux and
/// BSD `sockaddr_in`. A no-op on a Linux host, where the kernel already does this.
#[cfg(not(target_os = "linux"))]
fn rewrite_unspecified_connect_loopback(family: i32, host_addr: &mut [u8]) {
    if family == libc::AF_INET && host_addr.len() >= 8 && host_addr[4..8] == [0, 0, 0, 0] {
        host_addr[4..8].copy_from_slice(&[127, 0, 0, 1]);
    }
}

#[cfg(target_os = "linux")]
fn rewrite_unspecified_connect_loopback(_family: i32, _host_addr: &mut [u8]) {}

// The transform only exists (and only matters) on a non-Linux host, where the
// kernel does NOT itself remap 0.0.0.0 → loopback; on Linux it is a no-op, so
// the test is compiled out there rather than asserting an intentional no-op.
#[cfg(all(test, not(target_os = "linux")))]
mod connect_loopback_tests {
    use super::*;

    /// A host `sockaddr_in` laid out as `[sa_family:u16][sin_port:u16 BE][sin_addr:4][pad:8]`.
    fn sockaddr_in(family: i32, addr: [u8; 4], port_be: [u8; 2]) -> Vec<u8> {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&(family as u16).to_ne_bytes());
        buf[2..4].copy_from_slice(&port_be);
        buf[4..8].copy_from_slice(&addr);
        buf
    }

    #[test]
    fn inaddr_any_rewrites_to_loopback_preserving_port() {
        // 0.0.0.0:8080 (port 0x1f90 big-endian) must become 127.0.0.1:8080.
        let mut buf = sockaddr_in(libc::AF_INET, [0, 0, 0, 0], [0x1f, 0x90]);
        rewrite_unspecified_connect_loopback(libc::AF_INET, &mut buf);
        assert_eq!(
            &buf[4..8],
            &[127, 0, 0, 1],
            "INADDR_ANY (0.0.0.0) must be rewritten to loopback"
        );
        assert_eq!(&buf[2..4], &[0x1f, 0x90], "the port must be preserved");
        // sa_family must be untouched.
        assert_eq!(
            u16::from_ne_bytes([buf[0], buf[1]]),
            libc::AF_INET as u16,
            "the address family must be preserved"
        );
    }

    #[test]
    fn real_ipv4_address_is_left_untouched() {
        let mut buf = sockaddr_in(libc::AF_INET, [10, 0, 0, 5], [0x00, 0x50]);
        rewrite_unspecified_connect_loopback(libc::AF_INET, &mut buf);
        assert_eq!(
            &buf[4..8],
            &[10, 0, 0, 5],
            "a non-unspecified address must NOT be rewritten"
        );
    }

    #[test]
    fn non_inet_family_is_untouched_even_when_address_is_zero() {
        // The loopback quirk is IPv4-only: an AF_INET6 (or any non-AF_INET)
        // sockaddr with a zeroed addr field must be left exactly as-is.
        let mut buf = sockaddr_in(libc::AF_INET6, [0, 0, 0, 0], [0x01, 0xbb]);
        rewrite_unspecified_connect_loopback(libc::AF_INET6, &mut buf);
        assert_eq!(
            &buf[4..8],
            &[0, 0, 0, 0],
            "IPv6 / other families must never be rewritten"
        );
    }

    #[test]
    fn buffer_shorter_than_sin_addr_is_a_noop_not_a_panic() {
        // A truncated buffer (< 8 bytes) must be left alone rather than panicking
        // on the [4..8] slice.
        let mut buf = vec![0u8; 4];
        rewrite_unspecified_connect_loopback(libc::AF_INET, &mut buf);
        assert_eq!(buf, vec![0u8; 4]);
    }
}

fn connect_success_or_pending_error(host_fd: i32) -> DispatchOutcome {
    let mut host_err: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            host_fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut host_err as *mut i32).cast(),
            &mut len,
        )
    };
    if rc == 0 && host_err != 0 {
        return DispatchOutcome::errno(crate::host_to_linux_errno(host_err));
    }
    DispatchOutcome::Returned { value: 0 }
}

fn guest_unix_pathname(memory: &impl GuestMemory, addr: u64, addrlen: u32) -> Option<String> {
    memory
        .read_bytes(addr, addrlen as usize)
        .ok()
        .and_then(|raw| {
            if raw.len() > 2 && raw[2] != 0 {
                let nul = raw[2..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| 2 + p)
                    .unwrap_or(raw.len());
                std::str::from_utf8(&raw[2..nul])
                    .ok()
                    .map(|s| s.to_string())
            } else {
                None
            }
        })
}

impl SyscallDispatcher {
    /// Whether `fd` is a pollable target for `epoll_ctl(ADD)`. The kernel
    /// returns EPERM when adding an fd whose file has no `->poll` op — regular
    /// files, directories, and synthetic /proc files. Pipes, sockets, eventfd,
    /// timerfd, epoll, netlink, and character devices (ptys) are all pollable.
    fn fd_is_epollable(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::File { .. }
            | OpenDescription::Directory { .. }
            | OpenDescription::SyntheticFile { .. } => false,
            OpenDescription::HostFile { metadata, .. } => {
                matches!(metadata.kind, crate::rootfs::RootFsEntryKind::CharDevice)
            }
            _ => true,
        }
    }

    fn epoll_effective_interest(
        &self,
        fd: i32,
        events: u32,
        _last_ready: u32,
        _write_backpressured: bool,
    ) -> carrick_hal::event::Interest {
        // Wire→typed seam: the guest event word is a raw u32; epoll ACCEPTS
        // unknown bits, so retain them rather than reject.
        let mut interest = epoll_interest_for(LinuxEpollEvents::from_bits_retain(events));
        // A one-way pipe/FIFO read end is never writable under Linux, so it must
        // never carry a write filter. FreeBSD's kqueue arms `EVFILT_WRITE` on a
        // pipe read end and fires it immediately (the read end is reported
        // "writable"); that spurious edge wakes a blocked edge-triggered
        // `epoll_wait` and pollutes the readiness latch with `EPOLLOUT`, masking
        // the real `EPOLLIN|EPOLLHUP` EOF. Suppressing write interest here keeps
        // the host registration faithful to Linux semantics on every host.
        if interest.write && self.host_fd_is_oneway_pipe_read_end(fd) {
            interest.write = false;
            interest.read = true;
        }
        interest
    }

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    fn rebind_epoll_host_registration(
        &self,
        kqueue: &Arc<EpollKqueue>,
        interest: &HashMap<i32, EpollInterest>,
        host_fd: HostFd,
    ) {
        let mut survivor: Option<(i32, u32)> = None;
        let mut union_events = 0u32;
        let mut union_interest = carrick_hal::event::Interest::default();
        for (&other, slot) in interest.iter() {
            if self.host_fd_for_poll(other) != Some(host_fd) {
                continue;
            }
            survivor.get_or_insert((other, slot.reg_gen));
            union_events |= slot.event.events;
            let effective = self.epoll_effective_interest(
                other,
                slot.event.events,
                slot.last_ready,
                slot.write_backpressured,
            );
            union_interest.read |= effective.read;
            union_interest.write |= effective.write;
            union_interest.oob |= effective.oob;
        }

        kqueue.with_mux(|mux| match survivor {
            Some((sfd, sgen)) => {
                let _ = mux.register_io(
                    host_fd.get(),
                    pack_epoll_udata(sfd, sgen),
                    union_interest,
                    epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(union_events)),
                );
            }
            None => {
                let _ = mux.deregister(host_fd.get());
            }
        });
    }

    fn epoll_ready_events(&self, fd: i32, requested_events: u32) -> u32 {
        let Some(open_file) = self.open_file(fd) else {
            return 0;
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::EventFd { state, .. }
                if state.counter_value() > 0 && requested_events & LINUX_EPOLLIN != 0 =>
            {
                LINUX_EPOLLIN
            }
            OpenDescription::PipeReader { pipe, .. } if requested_events & LINUX_EPOLLIN != 0 => {
                let pipe = pipe.lock();
                if !pipe.buffer.is_empty() || pipe.writers == 0 {
                    LINUX_EPOLLIN
                } else {
                    0
                }
            }
            OpenDescription::TimerFd { state, .. }
                if requested_events & LINUX_EPOLLIN != 0 && timerfd_ready_count(state) > 0 =>
            {
                LINUX_EPOLLIN
            }
            _ => {
                // For host-backed descriptions (HostPipe/HostSocket/HostFile/
                // stdio) the in-memory arms above don't apply: readiness lives
                // in the real kernel object. Mirror what poll()/ppoll() do —
                // map the guest fd to its host fd and do a non-blocking
                // libc::poll(timeout 0), then translate revents → epoll events.
                // A one-way pipe/FIFO read end is never writable under Linux;
                // FreeBSD's poll(2) wrongly reports POLLOUT on it (see
                // host_fd_is_oneway_pipe_read_end), so drop EPOLLOUT for it.
                let suppress_pollout = matches!(
                    &*open,
                    OpenDescription::HostPipe {
                        is_read_end: true,
                        bidirectional: false,
                        pty: None,
                        ..
                    }
                );
                drop(open);
                let Some(host_fd) = self.host_fd_for_poll(fd) else {
                    return 0;
                };
                let mut interest: i16 = 0;
                if requested_events & LINUX_EPOLLIN != 0 {
                    interest |= libc::POLLIN;
                }
                if requested_events & LINUX_EPOLLOUT != 0 && !suppress_pollout {
                    interest |= libc::POLLOUT;
                }
                if requested_events & LINUX_EPOLLPRI != 0 {
                    interest |= libc::POLLPRI;
                }
                let mut pfd = libc::pollfd {
                    fd: host_fd.get(),
                    events: interest,
                    revents: 0,
                };
                let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
                let mut ready = 0u32;
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LINUX_EPOLLIN;
                    }
                    // FreeBSD's poll(2) sets POLLOUT on a pipe read end even when
                    // it was not requested; a one-way read end is never writable
                    // on Linux, so never surface EPOLLOUT for it.
                    if pfd.revents & libc::POLLOUT != 0 && !suppress_pollout {
                        ready |= LINUX_EPOLLOUT;
                    }
                    if pfd.revents & libc::POLLPRI != 0 {
                        ready |= LINUX_EPOLLPRI;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LINUX_EPOLLHUP;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LINUX_EPOLLERR;
                    }
                }
                // macOS `poll(2)` does NOT surface TCP urgent/out-of-band data
                // through `POLLPRI` (it stays clear even with a pending urgent
                // byte), so the recompute above can never assert EPOLLPRI on
                // Darwin. The instance kqueue's `EVFILT_EXCEPT`/`NOTE_OOB` filter
                // detects the OOB edge correctly, but this level-readiness probe
                // (which the epoll_pwait re-poll trusts over the drained bits)
                // must answer EPOLLPRI the Darwin-native way too — otherwise the
                // edge is drained then dropped and EPOLLPRI is never delivered
                // (probe `epollpri`). Check it via a one-shot kqueue OOB probe
                // whenever the caller is interested in EPOLLPRI; `host_fd_has_oob`
                // is a no-op on hosts whose native poll already handled POLLPRI.
                if requested_events & LINUX_EPOLLPRI != 0
                    && ready & LINUX_EPOLLPRI == 0
                    && host_fd_has_oob(host_fd.get())
                {
                    ready |= LINUX_EPOLLPRI;
                }
                // macOS doesn't report a named-FIFO read-end ready when its last
                // writer closed — the kernel-decided beacon does (dispatch::
                // fifo_beacon). Check it REGARDLESS of the host poll result: a
                // read-end registered for EPOLLOUT (Go's netpoller watches both
                // directions) makes the host poll return rc>0 with a spurious
                // POLLOUT, which must NOT mask the EOF (POLLIN|HUP) Linux delivers.
                if crate::dispatch::fifo_beacon::read_end_at_eof(host_fd.get()) {
                    ready |= LINUX_EPOLLIN | LINUX_EPOLLHUP;
                }
                // Only report events the caller is watching, plus the
                // always-reported HUP/ERR conditions Linux delivers regardless.
                ready & (requested_events | LINUX_EPOLLHUP | LINUX_EPOLLERR)
            }
        }
    }

    fn host_read_avail_for_poll(&self, fd: i32) -> u64 {
        let Some(host_fd) = self.host_fd_for_poll(fd) else {
            return 0;
        };
        let mut avail: libc::c_int = 0;
        let rc = unsafe { libc::ioctl(host_fd.get(), libc::FIONREAD, &mut avail) };
        if rc == 0 && avail > 0 {
            avail as u64
        } else {
            0
        }
    }

    /// Consumption-based EPOLLET re-arm for the Linux lane's sampled epoll
    /// emulation: after the guest performs a read-family syscall on fd X,
    /// clear the read-side bits of `last_ready` for X in every epoll interest
    /// set watching X (write-side bits for write-family syscalls).
    ///
    /// The Linux-lane ET latch is a readiness DIFF between consecutive
    /// `epoll_pwait` samples (`raw & !last_ready`), so a drain + refill that
    /// both land BETWEEN two samples is indistinguishable from "asserted
    /// since the last delivery": the new edge is masked from delivery AND
    /// (per the ET park-set rule) excluded from the ppoll park — the waiter
    /// parks forever. Captured live in go-os TestSpliceFile/Basic-TCP: the
    /// writer's `write(1025)+close` lands between the reader's splice EAGAIN
    /// (drain) and its `epoll_pwait` re-park; the sample sees IN still
    /// asserted, masks it, and the netpoller M never wakes. macOS doesn't
    /// need this: kqueue's `EV_CLEAR` re-arms in-kernel on consumption.
    ///
    /// An I/O syscall on X is exactly the consumption signal the sampling
    /// can't see — the guest serviced the delivered edge, so the next
    /// asserted sample is a NEW edge and must be delivered. Clearing on
    /// every read (not only EAGAIN) can at worst re-deliver one spurious
    /// event, which epoll's contract permits (and ET consumers drain to
    /// EAGAIN by contract). HUP/ERR are cleared on both directions: poll(2)
    /// reports them regardless of the requested set, and a guest that just
    /// touched the fd must see a still-standing terminal condition again.
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    pub(crate) fn epoll_rearm_after_io(&self, request: &SyscallRequest, outcome: &DispatchOutcome) {
        const READ_CLEAR: u32 =
            LINUX_EPOLLIN | LINUX_EPOLLRDHUP | LINUX_EPOLLPRI | LINUX_EPOLLHUP | LINUX_EPOLLERR;
        const WRITE_CLEAR: u32 = LINUX_EPOLLOUT | LINUX_EPOLLHUP | LINUX_EPOLLERR;
        let positive = matches!(outcome, DispatchOutcome::Returned { value } if *value > 0);
        let zero = matches!(outcome, DispatchOutcome::Returned { value } if *value == 0);
        let eagain = matches!(outcome, DispatchOutcome::Errno { errno } if *errno == LINUX_EAGAIN);
        let read_consumed = positive || zero || eagain;
        let write_consumed = positive;
        let a = |i: usize| request.arg(i) as i32;
        let write_eagain_targets: [Option<i32>; 2] = if eagain {
            match request.number.raw() {
                64 | 66 | 68 | 70 | 287 | 206 | 211 | 269 => [Some(a(0)), None],
                71 => [Some(a(0)), None],
                76 | 285 => [Some(a(2)), None],
                77 => [Some(a(1)), None],
                _ => [None, None],
            }
        } else {
            [None, None]
        };
        // (fd, bits-to-clear) per direction the syscall consumed. aarch64 nrs.
        let targets: [Option<(i32, u32)>; 2] = match request.number.raw() {
            // read / readv / pread64 / preadv / preadv2, accept / accept4,
            // recvfrom / recvmsg / recvmmsg: consume the read side of arg0.
            63 | 65 | 67 | 69 | 286 | 202 | 242 | 207 | 212 | 243 if read_consumed => {
                [Some((a(0), READ_CLEAR)), None]
            }
            // write / writev / pwrite64 / pwritev / pwritev2, sendto /
            // sendmsg / sendmmsg: consume the write side of arg0.
            64 | 66 | 68 | 70 | 287 | 206 | 211 | 269 if write_consumed => {
                [Some((a(0), WRITE_CLEAR)), None]
            }
            // sendfile(out_fd, in_fd, ..): reads in_fd, writes out_fd.
            71 if positive => [Some((a(1), READ_CLEAR)), Some((a(0), WRITE_CLEAR))],
            71 if zero || eagain => [Some((a(1), READ_CLEAR)), None],
            // splice(fd_in, off_in, fd_out, ..) / copy_file_range: reads
            // arg0, writes arg2. tee(fd_in, fd_out, ..): reads arg0, writes
            // arg1.
            76 | 285 if positive => [Some((a(0), READ_CLEAR)), Some((a(2), WRITE_CLEAR))],
            76 | 285 if zero || eagain => [Some((a(0), READ_CLEAR)), None],
            77 if positive => [Some((a(0), READ_CLEAR)), Some((a(1), WRITE_CLEAR))],
            77 if zero || eagain => [Some((a(0), READ_CLEAR)), None],
            _ if write_eagain_targets.iter().any(Option::is_some) => [None, None],
            _ => return,
        };
        // Snapshot the registered epoll fds and DROP the set lock before
        // touching any description lock (epoll_ctl registers while holding no
        // description lock either, keeping the order acyclic).
        let epfds: Vec<i32> = self.io.epoll_fds.read().iter().copied().collect();
        for epfd in epfds {
            let stale = match self.open_file(epfd) {
                None => true,
                Some(open_file) => {
                    let mut open = open_file.description.write();
                    if let OpenDescription::Epoll {
                        interest, kqueue, ..
                    } = &mut *open
                    {
                        let mut snapshot_changed = false;
                        #[cfg(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        ))]
                        let mut host_rearms: Vec<i32> = Vec::new();
                        for (fd, clear) in targets.iter().flatten() {
                            if let Some(slot) = interest.get_mut(fd) {
                                let before = slot.last_ready;
                                slot.last_ready &= !clear;
                                if clear & READ_CLEAR != 0 {
                                    slot.last_read_avail = 0;
                                }
                                if clear & WRITE_CLEAR != 0 {
                                    slot.write_backpressured = false;
                                }
                                if before != slot.last_ready {
                                    snapshot_changed = true;
                                    #[cfg(any(
                                        feature = "platform-macos",
                                        feature = "platform-freebsd",
                                        feature = "platform-netbsd"
                                    ))]
                                    if let Some(host_fd) = self.host_fd_for_poll(*fd) {
                                        host_rearms.push(host_fd.get());
                                    }
                                }
                            }
                        }
                        for fd in write_eagain_targets.iter().flatten() {
                            if let Some(slot) = interest.get_mut(fd)
                                && slot.event.events & LINUX_EPOLLET != 0
                                && slot.event.events & LINUX_EPOLLOUT != 0
                            {
                                if !slot.write_backpressured {
                                    snapshot_changed = true;
                                    slot.write_backpressured = true;
                                }
                                #[cfg(any(
                                    feature = "platform-macos",
                                    feature = "platform-freebsd",
                                    feature = "platform-netbsd"
                                ))]
                                if let Some(host_fd) = self.host_fd_for_poll(*fd) {
                                    host_rearms.push(host_fd.get());
                                }
                            }
                        }
                        #[cfg(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        ))]
                        {
                            host_rearms.sort_unstable();
                            host_rearms.dedup();
                            for host_fd in host_rearms {
                                self.rebind_epoll_host_registration(
                                    kqueue,
                                    interest,
                                    HostFd(host_fd),
                                );
                            }
                        }
                        // A waiter parked before this consumption holds a park
                        // set whose ET exclusion was computed from the now-
                        // serviced edge (the fd may be parked with events==0 —
                        // deaf). Pop it so it re-samples and re-parks armed.
                        if snapshot_changed {
                            kqueue.wake_parked();
                        }
                        false
                    } else {
                        true
                    }
                }
            };
            // Lazy prune: the fd was closed or recycled as a non-epoll.
            if stale {
                self.io.epoll_fds.write().remove(&epfd);
            }
        }
    }

    fn read_optional_fd_set(
        &self,
        memory: &mut impl GuestMemory,
        address: u64,
        nfds: usize,
    ) -> Result<Result<Option<Vec<u8>>, LinuxErrno>, DispatchError> {
        if address == 0 {
            return Ok(Ok(None));
        }
        match read_fd_set(memory, address, nfds) {
            Ok(s) => Ok(Ok(Some(s))),
            Err(errno) => Ok(Err(errno)),
        }
    }

    /// Return the host fd backing a guest fd for ppoll's fast path.
    /// `Some(host_fd)` means we can hand this off to libc::poll.
    /// `None` means it's synthetic (epoll/eventfd/timerfd/in-memory pipe)
    /// and ppoll has to fall back to the per-fd readiness loop.
    pub(super) fn host_fd_for_poll(&self, fd: i32) -> Option<HostFd> {
        if fd < 0 {
            // Negative fd in a pollfd entry: libc::poll ignores it
            // (revents=0), which is the right semantic. Pass it through.
            return Some(HostFd(fd));
        }
        if let Some(open_file) = self.open_file(fd) {
            let open = open_file.description.read();
            return match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostSocket { host_fd, .. }
                | OpenDescription::HostFile { host_fd, .. } => Some(HostFd(*host_fd)),
                // eventfd is host-backed by a readiness pipe (read end readable
                // iff counter > 0), so epoll/poll/select watch it natively via
                // EVFILT_READ/POLLIN — no in-memory recompute or EVFILT_USER
                // broadcast needed (the robust path for Go's netpollBreak).
                OpenDescription::EventFd { state, .. } if state.read_fd >= 0 => {
                    Some(HostFd(state.read_fd))
                }
                // A pidfd is read-ready when its process exits; the backing
                // multiplexer's poll fd (the kqueue fd on macOS, the
                // pidfd-bearing epoll fd on Linux) is what poll/epoll watch.
                OpenDescription::Pidfd { kqueue, .. } => Some(HostFd(kqueue.poll_fd())),
                // inotify readiness is the backing kqueue's fd, so poll/epoll/
                // blocking-read wait on it natively.
                OpenDescription::Inotify { state, .. } => Some(HostFd(state.poll_fd())),
                _ => None,
            };
        }
        if is_stdio_fd(fd) {
            return Some(HostFd(fd));
        }
        // Unknown fd: do NOT pass the guest fd number through as a host fd
        // (host fds 3,4,5… belong to carrick itself — the cap-std rootfs dir,
        // the HVF device, etc., so polling them blocks on the wrong object).
        // Route to the synthetic readiness path instead.
        None
    }

    /// Is `fd` a one-way (non-bidirectional, non-pty) pipe/FIFO READ end?
    ///
    /// Such an fd is NEVER writable under Linux `poll(2)`/`epoll(7)`: a read end
    /// has no write side, so `POLLOUT`/`EPOLLOUT` is impossible there. Most hosts
    /// agree — macOS and Linux `poll()` leave `POLLOUT` clear on a pipe read end.
    /// **FreeBSD does not:** `poll(POLLIN|POLLOUT)` on a pipe read end returns
    /// `POLLOUT` (the kernel reports the read end "writable"), and kqueue's
    /// `EVFILT_WRITE` arms and fires on a read end with `data == buffer space`.
    /// That spurious writability both wakes a blocked edge-triggered `epoll_wait`
    /// early and latches `EPOLLOUT` into the readiness latch, masking the real
    /// EOF (`EPOLLIN|EPOLLHUP`) that arrives when the writer later closes — the
    /// `epolletblockedhup`/`epolletchildhup` failures on bhyve.
    ///
    /// Suppressing `POLLOUT`/`EPOLLOUT` for a one-way read end is correct on
    /// EVERY host (Linux/macOS already never assert it there), so this needs no
    /// `cfg`-split — it is a no-op everywhere except FreeBSD/NetBSD, where it
    /// removes the divergence.
    pub(super) fn host_fd_is_oneway_pipe_read_end(&self, fd: i32) -> bool {
        if fd < 0 {
            return false;
        }
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let open = open_file.description.read();
        matches!(
            &*open,
            OpenDescription::HostPipe {
                is_read_end: true,
                bidirectional: false,
                pty: None,
                ..
            }
        )
    }

    /// Remove `fd` from every epoll instance's interest set (and purge any
    /// readiness already queued for it). Linux auto-removes a closed fd from all
    /// epoll interest lists; carrick keys interest by guest fd NUMBER, so a
    /// `close(2)` that skips `EPOLL_CTL_DEL` would otherwise leak a stale entry —
    /// yielding a spurious `EEXIST` when the fd number is reused, and recompute
    /// against a dead epoll_data token. The kqueue knote keyed on the closing
    /// host fd is reclaimed by the kernel when that host fd closes; a dup that
    /// keeps the host fd alive within the SAME epoll is the rarer
    /// `EPOLL_CTL_DEL`-covered survivor-rebind case. MUST be called with NO
    /// `open_files` lock held — it takes a read lock to snapshot the instances.
    pub(in crate::dispatch) fn detach_fd_from_epolls(&self, fd: i32) {
        let descriptions: Vec<OpenDescriptionRef> = self
            .io
            .open_files
            .read()
            .values()
            .map(|of| of.description.clone())
            .collect();
        for description in descriptions {
            let mut guard = description.write();
            if let OpenDescription::Epoll {
                interest,
                pending_ready,
                kqueue,
                ..
            } = &mut *guard
                && interest.remove(&fd).is_some()
            {
                clear_pending_epoll_ready(pending_ready, fd);
                // A parked waiter still ppolls the closed fd's host fd (a
                // closed entry never wakes poll); pop it so it rebuilds.
                kqueue.wake_parked();
            }
        }
    }

    /// The guest's status flags (O_NONBLOCK etc.) for `fd`. carrick keeps the
    /// HOST fd non-blocking always and tracks the guest's intended blocking
    /// mode here; `blocking_io` consults this to decide EAGAIN vs a lockless
    /// wait. Bare stdio / unknown fds report 0 (blocking), the safe default.
    pub(super) fn fd_status_flags(&self, fd: i32) -> u64 {
        let Some(open_file) = self.open_file(fd) else {
            return 0;
        };
        open_file.description.read().status_flags()
    }

    /// THE single chokepoint for blocking-mode host I/O — every recv/send/
    /// accept/read/write on a host fd routes through here. `op` performs ONE
    /// NON-BLOCKING libc call (the host fd is always `O_NONBLOCK`) and, on
    /// success, returns the value to hand the guest (having already copied any
    /// data into guest memory). The classification is uniform:
    ///   * `Ok(n)`            → the syscall returns `n`.
    ///   * `Err(EAGAIN)`      → guest non-blocking fd: EAGAIN; guest blocking
    ///     fd: `WaitOnFds` (the runtime waits with the dispatcher lock
    ///     RELEASED, then re-dispatches).
    ///   * `Err(other)`       → that errno.
    ///
    /// INVARIANT: `host_fd` MUST be `O_NONBLOCK`. If it isn't, `op` could block
    /// inside libc while we hold the dispatcher lock and starve every sibling
    /// thread — the exact bug this design exists to prevent. We assert it
    /// loudly in debug/test builds and self-heal (force non-blocking) in
    /// release so a missed creation site can never silently reintroduce the
    /// starvation.
    fn blocking_io<F>(
        &self,
        host_fd: i32,
        dir: IoDir,
        nonblocking: bool,
        timeout: Option<std::time::Duration>,
        op: F,
    ) -> DispatchOutcome
    where
        F: FnOnce() -> Result<i64, LinuxErrno>,
    {
        match op() {
            Ok(n) => DispatchOutcome::Returned { value: n },
            Err(e) if e == LINUX_EAGAIN => {
                if nonblocking {
                    // Guest wants non-blocking (fd O_NONBLOCK or per-call
                    // MSG_DONTWAIT): report EAGAIN, don't wait.
                    DispatchOutcome::errno(LINUX_EAGAIN)
                } else {
                    // Blocking-mode: hand off to the runtime to wait on host-fd
                    // readiness with the dispatcher lock RELEASED (per-thread
                    // kqueue), then re-dispatch. `timeout` carries the per-fd
                    // SO_RCVTIMEO/SO_SNDTIMEO (None = block forever, signal-
                    // interruptible); on WaitResult::TimedOut the run-loops
                    // return on_timeout = -EAGAIN, matching the Linux SO_*TIMEO
                    // recv/send result.
                    DispatchOutcome::WaitOnFds {
                        fds: WaitFds::raw_one(host_fd, dir.events()),
                        timeout,
                        on_timeout: LINUX_EAGAIN.guest_retval(),
                        sig_mask: carrick_abi::WaitSigMask::NONE,
                    }
                }
            }
            Err(e) => DispatchOutcome::errno(e),
        }
    }

    /// Whether a host-I/O op on `fd` with these guest `msg_flags` should report
    /// EAGAIN (true) rather than block: the guest fd is O_NONBLOCK, or the call
    /// carries MSG_DONTWAIT.
    pub(super) fn io_is_nonblocking(&self, fd: i32, msg_flags: i32) -> bool {
        // from_bits_retain: send/recv IGNORE unknown msg_flags bits.
        self.fd_status_flags(fd) & LINUX_O_NONBLOCK != 0
            || LinuxMsgFlags::from_bits_retain(msg_flags).contains(LinuxMsgFlags::DONTWAIT)
    }

    /// True iff `fd` is an eventfd. An eventfd is always POLLOUT-ready (its
    /// counter isn't at max), but its host readiness pipe's READ end is never
    /// writable — so select/poll's all-host `libc::poll` fast path drops the
    /// requested POLLOUT (and worse, blocks waiting for it). When POLLOUT is
    /// requested we route the eventfd through `poll_ready_events` instead, which
    /// reports it writable. POLLIN-only stays on the native read_fd path so Go's
    /// epoll netpollBreak (EVFILT_READ on the readiness pipe) is unaffected.
    pub(super) fn fd_is_eventfd(&self, fd: i32) -> bool {
        self.open_file(fd)
            .is_some_and(|f| matches!(&*f.description.read(), OpenDescription::EventFd { .. }))
    }

    fn poll_ready_events(&self, fd: i32, requested_events: i16) -> i16 {
        if fd < 0 {
            return 0;
        }
        let Some(open_file) = self.open_file(fd) else {
            return if is_stdio_fd(fd) {
                // fd 1/2 are always writable (we either buffer or stream
                // straight to host write). For fd 0 we have to actually
                // poll the host because the guest's read(0,...) ultimately
                // calls libc::read(0,...); without a real readiness check,
                // ppoll would always return POLLOUT only and never POLLIN,
                // breaking interactive shells that ppoll(stdin) before
                // each prompt.
                let mut revents = requested_events & LINUX_POLLOUT;
                if fd == 0 && (requested_events & LINUX_POLLIN) != 0 {
                    let mut pfd = libc::pollfd {
                        fd: 0,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let n = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
                    if n > 0 {
                        if pfd.revents & libc::POLLIN != 0 {
                            revents |= LINUX_POLLIN;
                        }
                        if pfd.revents & libc::POLLHUP != 0 {
                            revents |= LINUX_POLLHUP;
                        }
                    }
                }
                revents
            } else {
                LINUX_POLLNVAL
            };
        };
        let open = open_file.description.read();
        let mut ready = 0;
        match &*open {
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    ready |= LINUX_POLLIN;
                }
            }
            // Regular files are always ready for read and write.
            OpenDescription::HostFile { .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::Directory { .. } => {}
            OpenDescription::EventFd { state, .. } => {
                let counter = state.counter_value();
                if requested_events & LINUX_POLLIN != 0 && counter > 0 {
                    ready |= LINUX_POLLIN;
                }
                // POLLOUT iff a write of 1 wouldn't overflow the counter — Linux
                // reports an eventfd unwritable once it reaches 0xFFFF…FFFE
                // (test_os EventfdTests.test_eventfd_select checks both states).
                if requested_events & LINUX_POLLOUT != 0 && counter < u64::MAX - 1 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::TimerFd { state, .. } => {
                if requested_events & LINUX_POLLIN != 0 && timerfd_ready_count(state) > 0 {
                    ready |= LINUX_POLLIN;
                }
            }
            OpenDescription::Epoll {
                interest,
                pending_ready,
                kqueue,
                ..
            } => {
                if requested_events & LINUX_POLLIN != 0 {
                    if !pending_ready.is_empty() {
                        ready |= LINUX_POLLIN;
                    } else {
                        let mut pfd = libc::pollfd {
                            fd: kqueue.poll_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                        if (rc > 0
                            && pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
                            || interest.iter().any(|(fd, interest)| {
                                self.host_fd_for_poll(*fd).is_none()
                                    && self.epoll_ready_events(*fd, interest.event.events) != 0
                            })
                        {
                            ready |= LINUX_POLLIN;
                        }
                    }
                }
            }
            // Pidfd readiness is the kqueue's job (host_fd_for_poll returns the
            // EVFILT_PROC kqueue fd), so there's no in-memory readiness here.
            OpenDescription::Pidfd { .. } => {}
            // Inotify readiness is likewise the backing kqueue's job
            // (host_fd_for_poll returns its fd); no in-memory readiness here.
            OpenDescription::Inotify { .. } => {}
            // signalfd readiness would track pending masked signals; delivery is
            // a tracked follow-up, so there is no in-memory readiness here.
            OpenDescription::SignalFd { .. } => {}
            OpenDescription::PipeReader { pipe, .. } => {
                if requested_events & LINUX_POLLIN != 0 {
                    let pipe = pipe.lock();
                    if !pipe.buffer.is_empty() {
                        ready |= LINUX_POLLIN;
                    }
                    if pipe.writers == 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
            OpenDescription::PipeWriter { pipe, .. } => {
                let pipe = pipe.lock();
                if pipe.readers == 0 {
                    ready |= LINUX_POLLERR;
                } else if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            OpenDescription::HostPipe {
                host_fd,
                is_read_end,
                bidirectional,
                pty,
                ..
            } => {
                // Poll the real host pipe fd so the guest's poll loop reflects
                // actual kernel readiness: a read end with buffered data is
                // POLLIN-ready, a write end with buffer space is POLLOUT-ready,
                // and a hung-up peer surfaces POLLHUP/POLLERR. Reporting
                // nothing here made poll/ppoll/pselect6 undercount ready fds
                // for pipe ends.
                // A one-way pipe/FIFO read end is never writable under Linux, but
                // FreeBSD's poll(2) reports POLLOUT on it — drop that spurious
                // writability so poll/ppoll/select agree with Linux (and with the
                // epoll path's host_fd_is_oneway_pipe_read_end suppression).
                let suppress_pollout = *is_read_end && !*bidirectional && pty.is_none();
                let mut pfd = libc::pollfd {
                    fd: *host_fd,
                    events: 0,
                    revents: 0,
                };
                if requested_events & LINUX_POLLIN != 0 {
                    pfd.events |= libc::POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 && !suppress_pollout {
                    pfd.events |= libc::POLLOUT;
                }
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LINUX_POLLIN;
                    }
                    if pfd.revents & libc::POLLOUT != 0 && !suppress_pollout {
                        ready |= LINUX_POLLOUT;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LINUX_POLLERR;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
                // macOS won't report a named-FIFO read-end ready when its last
                // writer closed; the kernel-decided beacon does (dispatch::
                // fifo_beacon). Surface the POLLIN|POLLHUP (read→EOF) Linux gives.
                if requested_events & LINUX_POLLIN != 0
                    && ready & LINUX_POLLIN == 0
                    && crate::dispatch::fifo_beacon::read_end_at_eof(*host_fd)
                {
                    ready |= LINUX_POLLIN | LINUX_POLLHUP;
                }
            }
            OpenDescription::HostSocket { host_fd, .. } => {
                // Poll the real host fd so the guest's poll loop reflects
                // actual kernel readiness for the socket.
                let mut pfd = libc::pollfd {
                    fd: *host_fd,
                    events: 0,
                    revents: 0,
                };
                if requested_events & LINUX_POLLIN != 0 {
                    pfd.events |= libc::POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    pfd.events |= libc::POLLOUT;
                }
                let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                if rc > 0 {
                    if pfd.revents & libc::POLLIN != 0 {
                        ready |= LINUX_POLLIN;
                    }
                    if pfd.revents & libc::POLLOUT != 0 {
                        ready |= LINUX_POLLOUT;
                    }
                    if pfd.revents & libc::POLLERR != 0 {
                        ready |= LINUX_POLLERR;
                    }
                    if pfd.revents & libc::POLLHUP != 0 {
                        ready |= LINUX_POLLHUP;
                    }
                }
            }
            OpenDescription::Netlink { recv_queue, .. } => {
                // A netlink socket is "readable" once a dump response has
                // been queued (by a prior sendto/sendmsg), and always
                // writable (the kernel never blocks rtnetlink requests).
                if requested_events & LINUX_POLLIN != 0 && !recv_queue.is_empty() {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 {
                    ready |= LINUX_POLLOUT;
                }
            }
            // A POSIX message queue is readable iff it holds at least one
            // message and writable iff it has room — read the backing file's
            // header (under its OFD lock) to decide. (mq_overview(7)/poll(2).)
            OpenDescription::Mqueue {
                host_fd, max_msg, ..
            } => {
                let (readable, writable) =
                    crate::dispatch::mqueue::poll_readiness(*host_fd, *max_msg);
                if requested_events & LINUX_POLLIN != 0 && readable {
                    ready |= LINUX_POLLIN;
                }
                if requested_events & LINUX_POLLOUT != 0 && writable {
                    ready |= LINUX_POLLOUT;
                }
            }
        }
        ready
    }

    /// Create a synthetic AF_NETLINK socket. Linux accepts SOCK_RAW and
    /// SOCK_DGRAM for netlink (they're equivalent there); other socket
    /// types are rejected with ESOCKTNOSUPPORT, matching the kernel.
    fn netlink_socket(&self, type_: i32, protocol: i32) -> DispatchOutcome {
        let socket_flags = LinuxSocketTypeFlags::from_bits_retain(type_);
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
        if base_type != LINUX_SOCK_RAW && base_type != LINUX_SOCK_DGRAM {
            return DispatchOutcome::errno(LINUX_ESOCKTNOSUPPORT);
        }
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        self.install_fd(
            OpenDescription::Netlink {
                protocol,
                sock_type: base_type,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::new(),
                base: OpenDescriptionBase::new(status_flags),
            },
            fd_flags,
        )
    }

    fn host_socket_install(&self, family: i32, type_: i32, protocol: i32) -> DispatchOutcome {
        // Strip the Linux-only SOCK_NONBLOCK / SOCK_CLOEXEC bits before
        // we hand the type to macOS, then set them on the resulting fd
        // by hand.
        let socket_flags = LinuxSocketTypeFlags::from_bits_retain(type_);
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
        let host_family = linux_to_host_af(family);
        let host_type = host_socktype_backing(family, base_type);
        // macOS has no UDPLITE protocol, so back IPPROTO_UDPLITE with a plain UDP
        // socket (proto 0 → UDP for SOCK_DGRAM). UDPLITE's datagram send/recv is
        // UDP-identical; only the checksum-coverage sockopts differ, accepted as
        // no-ops below. The guest is LINUX python, whose test_socket runs the
        // whole UDPLITE suite (native-macOS python skips it — IPPROTO_UDPLITE
        // undefined there); pass-through socket() returned EPROTONOSUPPORT and
        // ERRORed every UDPLITE test at setUp.
        let host_protocol = if protocol == LINUX_IPPROTO_UDPLITE {
            0
        } else {
            protocol
        };
        let host_fd = match (unsafe { libc::socket(host_family, host_type, host_protocol) })
            .host_syscall_errno()
        {
            Ok(value) => value,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        // The host fd is always nonblocking; Carrick preserves the guest's
        // blocking mode in Linux-visible status_flags and waits outside the
        // dispatcher lock when a blocking operation would block.
        set_host_nonblocking(host_fd);
        // Give AF_UNIX stream sockets the Linux-sized buffer (macOS defaults to
        // 8 KiB vs Linux's 212992) so a guest write expecting to complete up to the
        // socket buffer without a draining reader doesn't block forever (Go
        // splice/sendfile "Limited" copy hang). No-op for AF_INET / DGRAM.
        widen_unix_stream_buffers(host_fd, family, base_type);
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let open_file = OpenFile::with_host_fd(
            Arc::new(RwLock::new(OpenDescription::HostSocket {
                host_fd,
                family,
                type_: base_type,
                base: OpenDescriptionBase::new(status_flags),
            })),
            fd_flags,
            host_fd,
        );
        let linux_fd = match self.install_fd_at_or_above(3, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        DispatchOutcome::Returned {
            value: linux_fd as i64,
        }
    }

    /// Map a GUEST fd to its backing HOST fd for an `SCM_RIGHTS` send. Only
    /// real host-backed descriptions (pipe/socket/file) can be passed to a peer
    /// over the host AF_UNIX socket; anything else (eventfd, pidfd, in-memory
    /// File, …) has no single host fd to dup into the peer and is rejected with
    /// EBADF (the closest Linux errno for "can't pass this fd"). The forkserver
    /// only ever passes os.pipe() ends + inherited sockets, all host-backed.
    fn host_fd_for_scm(&self, guest_fd: i32) -> Option<i32> {
        let open_file = self.open_file(guest_fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostPipe { host_fd, .. }
            | OpenDescription::HostSocket { host_fd, .. }
            | OpenDescription::HostFile { host_fd, .. } => Some(*host_fd),
            _ => None,
        }
    }

    /// Install a HOST fd received via `SCM_RIGHTS` as a fresh GUEST fd, wrapping
    /// it in the right `OpenDescription` by `fstat`ing its type (socket → host
    /// socket, fifo → host pipe, else a host file). The received host fd is
    /// already a live kernel fd the macOS kernel handed us; we keep its blocking
    /// mode non-blocking to satisfy the dispatcher's wait invariants. Returns
    /// the new guest fd, or `None` on failure (the caller closes the host fd).
    fn install_received_host_fd(&self, host_fd: i32, cloexec: bool) -> Option<i32> {
        set_host_nonblocking(host_fd);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let kind = if unsafe { libc::fstat(host_fd, &mut st) } == 0 {
            st.st_mode & libc::S_IFMT
        } else {
            0
        };
        let description = if kind == libc::S_IFSOCK {
            // Recover the socket's domain/type so SO_TYPE/SO_DOMAIN report
            // faithfully; default to AF_UNIX/STREAM (the forkserver case).
            let mut so_type: i32 = libc::SOCK_STREAM;
            let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
            unsafe {
                libc::getsockopt(
                    host_fd,
                    libc::SOL_SOCKET,
                    libc::SO_TYPE,
                    (&mut so_type as *mut i32).cast(),
                    &mut len,
                );
            }
            // SOCK_STREAM/DGRAM/RAW/SEQPACKET are numerically identical on
            // macOS and Linux (1/2/3/5), so the host SO_TYPE value is already a
            // valid Linux socket type.
            OpenDescription::HostSocket {
                host_fd,
                family: libc::AF_UNIX,
                type_: so_type,
                base: OpenDescriptionBase::new(LINUX_O_RDWR),
            }
        } else if kind == libc::S_IFIFO {
            // A pipe end. Probe its direction so reads/writes route correctly;
            // a pipe read end rejects writes and vice versa. F_GETFL's access
            // mode is unreliable for pipe ends, so treat it as bidirectional-
            // safe: mark it not-a-read-end unless a write probe fails. The
            // forkserver passes both ends; CPython only uses each in one
            // direction, so a conservative bidirectional flag is safe.
            OpenDescription::HostPipe {
                host_fd,
                is_read_end: false,
                // A pipe end received over SCM_RIGHTS: its host inode (already
                // fstat'd above) is the same kernel-object identity in this
                // process, so it serves as a stable FASYNC join key.
                pipe_id: st.st_ino as u64,
                pty: None,
                bidirectional: true,
                write_kind: HostWriteKind::PipeLike,
                base: OpenDescriptionBase::new(0),
            }
        } else {
            // Regular file / chardev / anything else: a host file with a real fd.
            let metadata = RootFsMetadata {
                path: std::path::PathBuf::from("scm:[received]"),
                kind: if kind == libc::S_IFDIR {
                    RootFsEntryKind::Directory
                } else {
                    RootFsEntryKind::File
                },
                mode: (st.st_mode & 0o7777) as u32,
                size: st.st_size.max(0) as usize,
            };
            OpenDescription::HostFile {
                host_fd,
                metadata,
                writable: true,
                base: OpenDescriptionBase::new(0),
            }
        };
        // MSG_CMSG_CLOEXEC: install the received fd close-on-exec. (audit M3)
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let open_file =
            OpenFile::with_host_fd(Arc::new(RwLock::new(description)), fd_flags, host_fd);
        self.install_fd_at_or_above(3, open_file).ok()
    }

    /// Pull a (host_fd, family) pair out of the dispatcher's fd table.
    pub(in crate::dispatch) fn host_socket_lookup(
        &self,
        fd: i32,
    ) -> Result<(HostFd, i32), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostSocket {
                host_fd, family, ..
            } => Ok((HostFd(*host_fd), *family)),
            _ => Err(LINUX_ENOTSOCK),
        }
    }

    /// Read the per-description `connect_in_progress` flag for `fd` (false if the
    /// fd is missing or not a HostSocket). See `OpenDescriptionBase.connect_in_progress`.
    fn socket_connect_in_progress(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(&*of.description.read(), OpenDescription::HostSocket { base, .. } if base.connect_in_progress())
        })
    }

    /// Set/clear the per-description `connect_in_progress` flag for `fd`.
    fn set_socket_connect_in_progress(&self, fd: i32, on: bool) {
        if let Some(open_file) = self.open_file(fd)
            && let OpenDescription::HostSocket { base, .. } = &mut *open_file.description.write()
        {
            base.set_connect_in_progress(on);
        }
    }

    /// True iff `fd` is a HostSocket with SO_PASSCRED enabled (audit M2).
    fn socket_so_passcred(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(&*of.description.read(), OpenDescription::HostSocket { base, .. } if base.so_passcred())
        })
    }

    /// Peer `(pid, uid, gid)` for an AF_UNIX `host_fd`, from LOCAL_PEERCRED +
    /// LOCAL_PEERPID (best-effort; 0 where unavailable). Used to synthesize the
    /// SCM_CREDENTIALS ancillary message for SO_PASSCRED. (audit M2)
    fn peer_ucred(&self, host_fd: i32) -> (u32, u32, u32) {
        carrick_portable::peer_ucred(host_fd)
    }

    /// The GUEST-requested socket type for `fd` (e.g. SOCK_SEQPACKET), which can
    /// differ from the host backing — carrick backs a guest AF_UNIX SEQPACKET
    /// with a host SOCK_STREAM, so the host's SO_TYPE would mis-report it.
    pub(in crate::dispatch) fn socket_guest_type(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read();
        match &*open {
            OpenDescription::HostSocket { type_, .. } => Some(*type_),
            OpenDescription::Netlink { sock_type, .. } => Some(*sock_type),
            _ => None,
        }
    }

    /// True iff `fd` refers to a synthetic AF_NETLINK socket.
    fn fd_is_netlink(&self, fd: i32) -> bool {
        self.open_file(fd)
            .is_some_and(|of| matches!(&*of.description.read(), OpenDescription::Netlink { .. }))
    }

    /// Handle a netlink "send": parse the request and queue a synthetic
    /// rtnetlink dump reply (or a bare NLMSG_DONE for requests we don't
    /// specifically model). Returns the number of bytes "sent".
    fn netlink_send(&self, fd: i32, request: &[u8]) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let reply = {
            let open = open_file.description.read();
            let OpenDescription::Netlink { pid, .. } = &*open else {
                return DispatchOutcome::errno(LINUX_ENOTSOCK);
            };
            let dest_pid = if *pid != 0 { *pid } else { std::process::id() };
            build_netlink_reply(request, dest_pid)
        };
        if let OpenDescription::Netlink { recv_queue, .. } = &mut *open_file.description.write() {
            recv_queue.extend(reply);
        }
        DispatchOutcome::Returned {
            value: request.len() as i64,
        }
    }

    /// recvfrom path for netlink: drain queued reply bytes into guest memory.
    fn netlink_recv(
        &self,
        fd: i32,
        buf_addr: u64,
        len: usize,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let chunk = self.netlink_drain(fd, len);
        if !chunk.is_empty() && memory.write_bytes(buf_addr, &chunk).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::Returned {
            value: chunk.len() as i64,
        }
    }

    /// Pop up to `max` bytes from the netlink recv queue. Our synthetic
    /// reply is built as one contiguous dump, so a single drain that fits
    /// the caller's buffer returns the whole thing.
    fn netlink_drain(&self, fd: i32, max: usize) -> Vec<u8> {
        let Some(open_file) = self.open_file(fd) else {
            return Vec::new();
        };
        let mut open = open_file.description.write();
        let OpenDescription::Netlink { recv_queue, .. } = &mut *open else {
            return Vec::new();
        };
        let take = recv_queue.len().min(max);
        recv_queue.drain(..take).collect()
    }

    pub(in crate::dispatch) fn accept_common(
        &self,
        fd: Fd,
        addr: GuestPtr,
        addrlen: GuestPtr,
        memory: &mut impl GuestMemory,
        accept4_flags: i32,
    ) -> DispatchOutcome {
        let fd = fd.0;
        let addr_addr = addr.0;
        let addrlen_addr = addrlen.0;
        let (host_fd, family, type_) = {
            let Some(open_file) = self.open_file(fd) else {
                return DispatchOutcome::errno(LINUX_EBADF);
            };
            match &*open_file.description.read() {
                OpenDescription::HostSocket {
                    host_fd,
                    family,
                    type_,
                    ..
                } => (*host_fd, *family, *type_),
                _ => {
                    return DispatchOutcome::errno(LINUX_ENOTSOCK);
                }
            }
        };
        // accept(2) has no per-call non-blocking flag, but listen() already put
        // the host listen socket in non-blocking mode, so this never blocks.
        // Whether EAGAIN becomes a wait or an EAGAIN to the guest is decided by
        // the guest's listen-fd blocking intent. The accept + sockaddr writeback
        // run in the closure (no &self); the fd is installed AFTER (the
        // install needs &self, which blocking_io's &self closure can't hold).
        let nonblocking = self.io_is_nonblocking(fd, 0);
        // accept(2) has no SO_*TIMEO bound on Linux — no per-fd timeout.
        let outcome = self.blocking_io(host_fd, IoDir::Read, nonblocking, None, || {
            let mut sa_storage = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa_storage.len() as libc::socklen_t;
            let new_host = unsafe {
                libc::accept(
                    host_fd,
                    sa_storage.as_mut_ptr() as *mut _,
                    &mut sa_len as *mut _,
                )
            };
            let new_host = new_host.host_syscall_errno()?;
            if addr_addr != 0 && addrlen_addr != 0 {
                let used = (sa_len as usize).min(sa_storage.len());
                let linux_bytes = host_to_linux_sockaddr(&sa_storage[..used], family, false);
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    unsafe { libc::close(new_host) };
                    return Err(LINUX_EFAULT);
                }
            }
            Ok(new_host as i64)
        });
        let new_host = match outcome {
            DispatchOutcome::Returned { value } => value as i32,
            // WaitOnFds (block) or Errno — propagate; the runtime re-dispatches
            // accept on readiness.
            other => return other,
        };
        crate::event_ring::rec(crate::event_ring::ACCEPT, host_fd, new_host, 0);
        let socket_flags = LinuxSocketTypeFlags::from_bits_retain(accept4_flags);
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        // Keep the host socket non-blocking; Linux-visible blocking intent is
        // carried by status_flags and serviced by WaitOnFds.
        set_host_nonblocking(new_host);
        widen_unix_stream_buffers(new_host, family, type_);
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let open_file = OpenFile::with_host_fd(
            Arc::new(RwLock::new(OpenDescription::HostSocket {
                host_fd: new_host,
                family,
                type_,
                base: OpenDescriptionBase::new(status_flags),
            })),
            fd_flags,
            new_host,
        );
        let linux_fd = match self.install_fd_at_or_above(3, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        DispatchOutcome::Returned {
            value: linux_fd as i64,
        }
    }

    /// connect(2) core with always-wait-on-block semantics, for the io_uring
    /// CONNECT op (the synchronous `connect` handler keeps its own non-blocking
    /// branch). Returns Returned{0} on success/EISCONN, WaitOnFds (POLLOUT) while
    /// the connect is in progress, or Errno otherwise.
    pub(in crate::dispatch) fn connect_common(
        &self,
        fd: i32,
        addr_addr: u64,
        addrlen: u32,
        memory: &impl GuestMemory,
    ) -> DispatchOutcome {
        let (host_fd, family) = match self.host_socket_lookup(fd) {
            Ok(t) => t,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let mut host_addr = match read_linux_sockaddr(memory, addr_addr, addrlen, family) {
            Ok(bytes) => bytes,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        rewrite_unspecified_connect_loopback(family, &mut host_addr);
        set_host_nonblocking(host_fd.get());
        let rc = unsafe {
            libc::connect(
                host_fd.get(),
                host_addr.as_ptr() as *const _,
                host_addr.len() as u32,
            )
        };
        if rc == 0 {
            return connect_success_or_pending_error(host_fd.get());
        }
        let e = HostSyscallError::last().linux_errno();
        // See `fn connect` for why EISCONN is split on connect_in_progress.
        if e == LINUX_EISCONN {
            if self.socket_connect_in_progress(fd) {
                self.set_socket_connect_in_progress(fd, false);
                return connect_success_or_pending_error(host_fd.get());
            }
            return DispatchOutcome::errno(LINUX_EISCONN);
        }
        if e == LINUX_EINPROGRESS || e == LINUX_EALREADY || e == LINUX_EAGAIN {
            self.set_socket_connect_in_progress(fd, true);
            return DispatchOutcome::WaitOnFds {
                fds: WaitFds::raw_one(host_fd.get(), libc::POLLOUT),
                timeout: None,
                on_timeout: LINUX_EINPROGRESS.guest_retval(),
                sig_mask: carrick_abi::WaitSigMask::NONE,
            };
        }
        DispatchOutcome::errno(e)
    }

    /// `sendmmsg(sockfd, msgvec, vlen, flags)` — Linux's batched
    /// sendmsg. glibc's getaddrinfo uses sendmmsg for DNS queries even
    /// when only a single message is sent; without this handler the
    /// guest sees ENOSYS and bails with "Temporary failure resolving".
    /// Implemented as a loop over single sendmsgs, writing each entry's
    /// msg_len field with the bytes-sent on success.
    fn sendmmsg(
        &self,
        fd: Fd,
        msgvec: GuestPtr,
        vlen: u64,
        flags: u64,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = fd.0;
        let msgvec = msgvec.0;
        let vlen = vlen as u32;
        let flags = flags as i32;
        const MMSGHDR_SIZE: u64 = <LinuxMmsghdr as KernelAbi>::ABI_SIZE as u64;
        const MSG_LEN_OFFSET: u64 = <LinuxMsghdr as KernelAbi>::ABI_SIZE as u64;
        let mut sent: i32 = 0;
        for i in 0..vlen {
            let entry = match msgvec.checked_add(i as u64 * MMSGHDR_SIZE) {
                Some(a) => a,
                None => {
                    return DispatchOutcome::errno(LINUX_EFAULT);
                }
            };
            let outcome = match self.sendmsg_inner(fd, entry, flags, &*memory) {
                Ok(o) => o,
                Err(_) => {
                    return DispatchOutcome::errno(LINUX_EFAULT);
                }
            };
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let len_u32 = value as u32;
                    if memory
                        .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes())
                        .is_err()
                    {
                        return DispatchOutcome::errno(LINUX_EFAULT);
                    }
                    sent += 1;
                }
                DispatchOutcome::Errno { errno } => {
                    if sent > 0 {
                        // At least one message went out — Linux returns
                        // the count of successful sends, and the errno
                        // surfaces on the next call.
                        return DispatchOutcome::Returned { value: sent as i64 };
                    }
                    return DispatchOutcome::errno(errno);
                }
                other => return other,
            }
        }
        DispatchOutcome::Returned { value: sent as i64 }
    }

    /// `recvmmsg(sockfd, msgvec, vlen, flags, timeout)` — Linux's
    /// batched recvmsg. Same shape as sendmmsg: loop over entries,
    /// call single recvmsg for each, fill msg_len on success.
    ///
    /// LIMITATION: the `timeout` argument is currently NOT honored
    /// (bound `_timeout`). The first message takes the socket's normal
    /// blocking path (so the wait is bounded only by SO_RCVTIMEO, else
    /// it blocks until a datagram arrives or a signal interrupts);
    /// after the first datagram `received > 0` forces MSG_DONTWAIT so
    /// the rest drain without waiting. A faithful implementation would
    /// convert `timeout` to an absolute deadline once and check it
    /// AFTER each received datagram (Linux only consults the timeout
    /// between datagrams — it does NOT bound the wait for the first
    /// one), NOT as an up-front poll.
    fn recvmmsg(
        &self,
        fd: Fd,
        msgvec: GuestPtr,
        vlen: u64,
        flags: u64,
        timeout: GuestPtr,
        memory: &mut impl GuestMemory,
    ) -> DispatchOutcome {
        let fd = fd.0;
        let msgvec = msgvec.0;
        let vlen = vlen as u32;
        let flags = flags as i32;
        // Validate the optional timeout up front, exactly as pselect6/ppoll do: a
        // malformed struct timespec (negative tv_sec, or tv_nsec outside
        // [0, 1e9)) is rejected with EINVAL, a bad pointer with EFAULT, before any
        // receive. The full per-datagram deadline semantics are not yet emulated
        // (see the doc comment above); validating the argument is the
        // Linux-faithful, side-effect-free part we can do precisely.
        let timeout = timeout.0;
        if timeout != 0 {
            match read_kernel_struct::<LinuxTimespec>(&*memory, timeout) {
                Ok(ts) => {
                    // Copy out of the packed timespec before referencing (E0793).
                    let sec = ts.tv_sec;
                    let nsec = ts.tv_nsec;
                    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                        return DispatchOutcome::errno(LINUX_EINVAL);
                    }
                }
                Err(_) => return DispatchOutcome::errno(LINUX_EFAULT),
            }
        }
        const MMSGHDR_SIZE: u64 = <LinuxMmsghdr as KernelAbi>::ABI_SIZE as u64;
        const MSG_LEN_OFFSET: u64 = <LinuxMsghdr as KernelAbi>::ABI_SIZE as u64;
        let mut received: i32 = 0;
        for i in 0..vlen {
            let entry = match msgvec.checked_add(i as u64 * MMSGHDR_SIZE) {
                Some(a) => a,
                None => {
                    return DispatchOutcome::errno(LINUX_EFAULT);
                }
            };
            // After the first successful recvmsg, switch to non-blocking
            // so we drain whatever else is in the queue without waiting.
            let entry_flags = if received > 0 {
                flags | libc::MSG_DONTWAIT
            } else {
                flags
            };
            let outcome = match self.recvmsg_inner(fd, entry, entry_flags, &mut *memory) {
                Ok(o) => o,
                Err(_) => {
                    return DispatchOutcome::errno(LINUX_EFAULT);
                }
            };
            match outcome {
                DispatchOutcome::Returned { value } => {
                    let len_u32 = value as u32;
                    if memory
                        .write_bytes(entry + MSG_LEN_OFFSET, &len_u32.to_le_bytes())
                        .is_err()
                    {
                        return DispatchOutcome::errno(LINUX_EFAULT);
                    }
                    received += 1;
                }
                DispatchOutcome::Errno { errno } => {
                    if received > 0 {
                        return DispatchOutcome::Returned {
                            value: received as i64,
                        };
                    }
                    return DispatchOutcome::errno(errno);
                }
                other => return other,
            }
        }
        DispatchOutcome::Returned {
            value: received as i64,
        }
    }
}

#[cfg(test)]
mod recvmmsg_tests {
    use super::*;
    use crate::dispatch::LinearMemory;

    #[test]
    fn recvmmsg_rejects_malformed_timeout_with_einval() {
        // Linux validates the optional `timeout` struct timespec up front and
        // rejects a tv_nsec outside [0, 1e9) (or a negative tv_sec) with EINVAL,
        // just like nanosleep/ppoll/pselect6. carrick previously ignored the
        // argument entirely, so a malformed timeout slipped through to a normal
        // (EBADF/EFAULT) receive. The fd is irrelevant: validation must precede
        // any fd/msgvec use.
        let dispatcher = SyscallDispatcher::new();
        let base = 0x1000u64;
        let mut memory = LinearMemory::new(base, vec![0u8; 0x1000]);
        // struct timespec { tv_sec: 0, tv_nsec: 2_000_000_000 } — tv_nsec >= 1e9.
        let mut ts = [0u8; 16];
        ts[8..16].copy_from_slice(&2_000_000_000i64.to_le_bytes());
        memory.write_bytes(base, &ts).unwrap();

        let out = dispatcher.recvmmsg(
            Fd(-1),
            GuestPtr(base + 0x100),
            1,
            0,
            GuestPtr(base),
            &mut memory,
        );
        assert!(
            matches!(out, DispatchOutcome::Errno { errno } if errno == LINUX_EINVAL),
            "malformed recvmmsg timeout must yield EINVAL, got {out:?}"
        );
    }

    #[test]
    fn recvmmsg_null_timeout_is_not_validated() {
        // A NULL timeout pointer is the common case and must NOT be treated as a
        // malformed timespec — it simply means "no timeout".
        let dispatcher = SyscallDispatcher::new();
        let base = 0x1000u64;
        let mut memory = LinearMemory::new(base, vec![0u8; 0x1000]);
        let out = dispatcher.recvmmsg(Fd(-1), GuestPtr(base), 1, 0, GuestPtr(0), &mut memory);
        // fd is invalid, so this is some receive error — the point is it is NOT
        // the EINVAL we reserve for a malformed timeout.
        assert!(
            !matches!(out, DispatchOutcome::Errno { errno } if errno == LINUX_EINVAL),
            "NULL timeout must not be rejected as malformed, got {out:?}"
        );
    }
}

impl SyscallDispatcher {
    define_syscall! {

        fn eventfd2(this, cx, initial_value: u64, flags: u64) {

            // `from_bits` rejects exactly the historical
            // `& !(SEMAPHORE|NONBLOCK|CLOEXEC)` set: the type's full set IS
            // the supported set.
            let Some(efd_flags) = LinuxEfdFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let description = OpenDescription::EventFd {
                state: Arc::new(EventFdState::new(initial_value)),
                semaphore: efd_flags.contains(LinuxEfdFlags::SEMAPHORE),
                // EFD_NONBLOCK == O_NONBLOCK, so the isolated bit IS the
                // status-flag word the base expects.
                base: OpenDescriptionBase::new((efd_flags & LinuxEfdFlags::NONBLOCK).bits()),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))

        }

        fn epoll_create1(this, cx, flags: u64) {

            if flags & !LINUX_EPOLL_CLOEXEC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The readiness backend is an EventMultiplexer: kqueue-backed on
            // macOS, epoll-backed on Linux. The user-wake channel `register_user(0)`
            // is the in-memory wake: `notify_inmem_epoll`/`wake_parked` trigger it
            // when an eventfd/pipe/timerfd readiness changes or an interest is
            // re-armed, so a thread blocked on this instance's poll_fd re-checks.
            let epoll_kqueue = {
                let mut mux = match crate::event_mux::make_event_multiplexer() {
                    Ok(m) => m,
                    // The backing kqueue/epoll fd couldn't be allocated (fd table full).
                    Err(_) => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE)),
                };
                let _ = mux.register_user(0);
                crate::dispatch::EpollKqueue::new(mux)
            };
            let description = OpenDescription::Epoll {
                interest: HashMap::new(),
                base: OpenDescriptionBase::new(0),
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(epoll_kqueue),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(flags)))

        }

        fn x86_epoll_create(this, cx, size: u64) {

            // x86_64 legacy epoll_create(size): the size is ignored since 2.6.8
            // but the kernel still rejects size <= 0 with EINVAL (epoll-ltp /
            // epoll_create02). Validate, then create exactly as epoll_create1(0).
            if (size as i32) <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let epoll_kqueue = {
                let mut mux = match crate::event_mux::make_event_multiplexer() {
                    Ok(m) => m,
                    Err(_) => return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE)),
                };
                let _ = mux.register_user(0);
                crate::dispatch::EpollKqueue::new(mux)
            };
            let description = OpenDescription::Epoll {
                interest: HashMap::new(),
                base: OpenDescriptionBase::new(0),
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(epoll_kqueue),
            };
            Ok(this.install_fd(description, linux_fd_flags_from_open_flags(0)))

        }

        fn epoll_ctl(this, cx, epfd: Fd, op: u64, fd: Fd, event: GuestPtr) {

            let memory = &*cx.memory;
            let epfd = epfd.0;
            let operation = op;
            let fd = fd.0;
            let event_address = event.0;
            // A bad target fd is EBADF; a target equal to the epoll fd itself is
            // EINVAL (an epoll instance can't monitor itself). (LTP epoll_ctl02.)
            if !this.fd_is_valid(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if epfd == fd {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let Some(open_file) = this.open_file(epfd) else {
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            // The host fd backing this target (sockets/pipes/ptys); `None` for an
            // in-memory eventfd/pipe/timerfd, whose readiness is recomputed each
            // `epoll_wait` rather than registered on the kqueue. Computed before
            // taking the epoll write lock (it locks the *target* fd's description).
            let host_fd = this.host_fd_for_poll(fd);

            // Record this epoll instance for the consumption-based EPOLLET
            // re-arm ([`Self::epoll_rearm_after_io`]) BEFORE taking the
            // description lock (the re-arm path snapshots this set first, then
            // locks descriptions — registering here keeps the lock order
            // acyclic). A non-epoll epfd inserted on the error path below is
            // harmless: the re-arm prunes it lazily.
            this.io.epoll_fds.write().insert(epfd);

            let mut open = open_file.description.write();
            let OpenDescription::Epoll {
                interest,
                pending_ready,
                kqueue,
                ..
            } = &mut *open
            else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };

            match operation {
                LINUX_EPOLL_CTL_ADD => {
                    let event = read_epoll_event(memory, event_address, cx.guest_abi())?;
                    // The kernel rejects ADD of a target that has no ->poll support
                    // (regular files, directories) with EPERM. (LTP epoll_ctl02/05.)
                    if !this.fd_is_epollable(fd) {
                        return Ok(DispatchOutcome::errno(LINUX_EPERM));
                    }
                    if interest.contains_key(&fd) {
                        return Ok(DispatchOutcome::errno(LINUX_EEXIST));
                    }
                    // Generational handle: the multiplexer IDENT is the host fd
                    // (the kernel's stable key, auto-removed on close); the udata
                    // is `(guest_fd, reg_gen)`. Guest AND host fd numbers recycle
                    // rapidly under churn, so a drained event keyed by a bare fd is
                    // an ABA hazard — by delivery time the fd may name a different
                    // registration. `epoll_pwait` routes by the udata's guest fd
                    // and requires `reg_gen` to match the live interest, so a stale
                    // edge for a recycled fd is dropped, not mis-delivered.
                    // (epoll_et_pipe_eof_not_lost.)
                    let reg_gen = next_epoll_reg_gen();
                    if let Some(host_fd) = host_fd {
                        let ev_events = event.events;
                        let effective = this.epoll_effective_interest(fd, ev_events, 0, false);
                        kqueue.with_mux(|mux| {
                            let _ = mux.register_io(
                                host_fd.get(),
                                pack_epoll_udata(fd, reg_gen),
                                effective,
                                epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(
                                    ev_events,
                                )),
                            );
                        });
                        crate::event_ring::rec(
                            crate::event_ring::EPADD,
                            kqueue.poll_fd(),
                            host_fd.get(),
                            ev_events as i32,
                        );
                    }
                    interest.insert(
                        fd,
                        EpollInterest {
                            event,
                            last_ready: 0,
                            last_read_avail: 0,
                            write_backpressured: false,
                            reg_gen,
                        },
                    );
                    // A waiter parked on this instance's ppoll snapshot does
                    // not watch the just-added fd; pop it so it rebuilds.
                    kqueue.wake_parked();
                    crate::probes::epoll_ctl(epfd, operation, fd, event.events, event.data, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_EPOLL_CTL_MOD => {
                    let event = read_epoll_event(memory, event_address, cx.guest_abi())?;
                    let Some(slot) = interest.get_mut(&fd) else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    };
                    // `register_io` re-arms the filters present in the new mask and
                    // EV_DELETEs the ones no longer present in a single call, so the
                    // old "add new, then delete removed" sequence — which avoided a
                    // no-interest gap where a readiness edge could be lost — is now
                    // atomic per direction (no transient gap at all). MOD keeps the
                    // SAME registration, so it preserves `reg_gen` (the generational
                    // handle is unchanged — see EPOLL_CTL_ADD).
                    let reg_gen = slot.reg_gen;
                    if let Some(host_fd) = host_fd {
                        let effective = this.epoll_effective_interest(fd, event.events, 0, false);
                        kqueue.with_mux(|mux| {
                            let _ = mux.register_io(
                                host_fd.get(),
                                pack_epoll_udata(fd, reg_gen),
                                effective,
                                epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(
                                    event.events,
                                )),
                            );
                        });
                    }
                    clear_pending_epoll_ready(pending_ready, fd);
                    *slot = EpollInterest {
                        event,
                        last_ready: 0,
                        last_read_avail: 0,
                        write_backpressured: false,
                        reg_gen,
                    };
                    // Re-arm visible to a parked waiter: rebuild its park set.
                    kqueue.wake_parked();
                    crate::probes::epoll_ctl(epfd, operation, fd, event.events, event.data, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_EPOLL_CTL_DEL => {
                    if interest.remove(&fd).is_none() {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    }
                    if let Some(host_fd) = host_fd {
                        // Other guest fds in THIS epoll instance can be dups of the
                        // same socket/pipe, all sharing ONE host fd. The multiplexer
                        // registration (kqueue filter / epoll entry) is keyed by host
                        // fd, so an unconditional DELETE here would deafen those
                        // survivors — but Linux epoll interest is per-fd, so they
                        // must keep getting readiness. (This is the Go `net`
                        // TestFileListener hang: File() + FileListener dup the
                        // listener, then the intermediate dup is DEL'd, which used to
                        // rip out the shared registration.) Re-bind the registration
                        // to a surviving fd with the UNION of all survivors' masks,
                        // and only drop interest classes no survivor still wants.
                        // With no survivor, deregister as before. Native epoll is
                        // per-fd and auto-removes on close, but a *dup* keeps the host
                        // fd alive, so the host-fd-keyed registration must be rebound
                        // rather than dropped — identical to the kqueue case.
                        // With a survivor: re-arm the host registration to the
                        // UNION of all survivors' currently unlatched masks
                        // (register_io also clears interest classes no survivor still
                        // wants), re-using one surviving fd's generational handle.
                        // With none: drop the host registration entirely.
                        #[cfg(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        ))]
                        this.rebind_epoll_host_registration(kqueue, interest, host_fd);
                        #[cfg(not(any(
                            feature = "platform-macos",
                            feature = "platform-freebsd",
                            feature = "platform-netbsd"
                        )))]
                        {
                            let mut survivor: Option<(i32, u32)> = None;
                            let mut union_events: u32 = 0;
                            for (&other, slot) in interest.iter() {
                                if this.host_fd_for_poll(other) == Some(host_fd) {
                                    survivor.get_or_insert((other, slot.reg_gen));
                                    union_events |= slot.event.events;
                                }
                            }
                            kqueue.with_mux(|mux| match survivor {
                                Some((sfd, sgen)) => {
                                    let union_events =
                                        LinuxEpollEvents::from_bits_retain(union_events);
                                    let _ = mux.register_io(
                                        host_fd.get(),
                                        pack_epoll_udata(sfd, sgen),
                                        epoll_interest_for(union_events),
                                        epoll_host_trigger_mode(union_events),
                                    );
                                }
                                None => {
                                    let _ = mux.deregister(host_fd.get());
                                }
                            });
                        }
                    }
                    clear_pending_epoll_ready(pending_ready, fd);
                    // A parked waiter still ppolls the removed fd's host fd;
                    // pop it so it rebuilds without the dead entry.
                    kqueue.wake_parked();
                    crate::probes::epoll_ctl(epfd, operation, fd, 0, 0, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            }

        }

        fn epoll_pwait(this, cx, epfd: Fd, events: GuestPtr, maxevents: u64, timeout: u64, sigmask: GuestPtr, sigsetsize: u64) {

            let epfd = epfd.0;
            let events_address = events.0;
            let guest_abi = cx.guest_abi();
            // maxevents is a signed int; the kernel rejects <= 0 with EINVAL. A
            // negative value arrives as a huge u64, so check the signed form.
            // (LTP epoll_wait03.)
            let max_events_signed = maxevents as i32;
            let timeout_ms = timeout as i32;
            // epoll_pwait carries a sigmask (arg4) + sigsetsize (arg5); epoll_wait
            // passes a NULL mask. A non-NULL mask must have the right size and a
            // readable pointer, else EINVAL/EFAULT. (LTP epoll_pwait04.)
            let sigmask_ptr = sigmask.0;
            let memory = &mut *cx.memory;
            if max_events_signed <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let max_events = max_events_signed as usize;
            // The sigmask temporarily blocks signals for the duration of the wait;
            // capture it as a typed SigSet (converted at the guest sigset_t read)
            // to carry into WaitOnFds so a blocked signal doesn't interrupt the
            // wait (LTP epoll_pwait01).
            let block_signals: carrick_abi::SigSet = if sigmask_ptr != 0 {
                if sigsetsize != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                match memory.read_bytes(sigmask_ptr, crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize) {
                    Ok(bytes) => {
                        let mut le = [0u8; 8];
                        le.copy_from_slice(&bytes[..8]);
                        carrick_abi::SigSet::from_raw(u64::from_le_bytes(le))
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            } else {
                carrick_abi::SigSet::EMPTY
            };
            // epoll_pwait's sigmask (when present) REPLACES the thread's
            // persistent mask for the wait; epoll_wait (NULL mask) is a plain
            // additive wait.
            let sig_mask = if sigmask_ptr != 0 {
                carrick_abi::WaitSigMask::Replace(block_signals)
            } else {
                carrick_abi::WaitSigMask::NONE
            };

            let Some(open_file) = this.open_file(epfd) else {
                // A valid fd that simply isn't an epoll instance is EINVAL; only a
                // genuinely bad fd is EBADF. (LTP epoll_wait03.)
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            // Snapshot any already-queued ready events first. `ready` is
            // reassigned on the multiplexer path below (it collects the
            // drained-and-tagged events), so the `mut` is load-bearing.
            let mut ready = {
                let mut open = open_file.description.write();
                let OpenDescription::Epoll { pending_ready, .. } = &mut *open else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                drain_pending_epoll_ready(pending_ready, max_events)
            };
            if !ready.is_empty() {
                crate::probes::epoll_result(epfd, ready.len() as i32, 0, timeout_ms, 0);
                return write_epoll_events(memory, events_address, &ready, guest_abi);
            }

            // Multiplexer-backed readiness (kqueue on macOS, epoll on Linux). The
            // multiplexer is the authoritative readiness source for host-backed fds
            // (sockets/pipes/ptys/eventfds) — crucially, it monitors fds registered
            // by OTHER threads while this thread is blocked, fixing the
            // interest-snapshot race that lost a netpoller wakeup. If a drained host
            // event names a guest fd that is not in this snapshot, fall back to the
            // live map before dropping it; that covers the narrow concurrent ADD
            // race without putting a live lock lookup on every returned event.
            {
            let (interests, kq, kq_fd) = {
                let open = open_file.description.read();
                let OpenDescription::Epoll {
                    interest, kqueue, ..
                } = &*open
                else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                (
                    interest
                        .iter()
                        .map(|(fd, interest)| (*fd, interest.clone()))
                        .collect::<Vec<_>>(),
                    Arc::clone(kqueue),
                    kqueue.poll_fd(),
                )
            };
            let has_interests = !interests.is_empty();

            // guest_fd -> (accumulated epoll events, epoll_data); read+write filters
            // for the same fd merge into one returned event.
            let mut acc: HashMap<i32, (u32, u64)> = HashMap::new();
            let mut ready_updates: Vec<(i32, u32, u32, Option<u64>, bool)> = Vec::new();
            let mut host_ready_sampled = std::collections::HashSet::<i32>::new();
            const READ_READY_BITS: u32 =
                LINUX_EPOLLIN | LINUX_EPOLLRDHUP | LINUX_EPOLLHUP | LINUX_EPOLLERR;

            // (1) Drain the instance kqueue (non-blocking) for host-backed fds.
            // `kq_drained_all_filtered` tracks the corner case where the kqueue
            // had readiness events but the user's interest mask filters them
            // all out (e.g. `epoll_ctl(ADD, fd, events=0)` plus data on the
            // pipe — the read filter still fires because Linux must surface
            // EPOLLHUP/EPOLLERR, but no event bit matches). Without this flag
            // we'd return `WaitOnPollFds` and the runtime would re-poll the
            // already-readable kq_fd, re-dispatch, and tight-loop until the
            // harness deadline. Detect it once here and switch to an empty
            // `WaitOnFds` (signal-pipe-and-timeout-only) below.
            let mut kq_drained_all_filtered = false;
            {
                // Non-blocking drain of the multiplexer for host-backed fds.
                let mut poll_events: Vec<carrick_hal::event::PollEvent> = Vec::new();
                if kq
                    .with_mux(|mux| mux.wait(&mut poll_events, Some(Duration::ZERO)))
                    .is_ok()
                {
                    let acc_before = acc.len();
                    // Each drained event's udata is a GENERATIONAL handle
                    // `(guest_fd, reg_gen)` (the multiplexer IDENT stays the host
                    // fd). Guest AND host fd numbers recycle rapidly under churn, so
                    // routing by a bare fd is an ABA hazard; the gen lets us confirm
                    // the edge belongs to the CURRENT registration of guest_fd and
                    // drop a stale edge for a recycled fd (see below). For each valid
                    // edge we RE-POLL the live owner(s) rather than trust the drained
                    // bits, which stays correct even when the host fd was recycled
                    // mid-drain. bits==0 is an EVFILT_USER(0) in-memory wake or a
                    // filter with no translatable bits — in-memory readiness is
                    // recomputed in step (2), so it is skipped (and must NOT count
                    // toward `kq_drained_all_filtered`: it auto-resets, so polling
                    // kq_fd won't spin, whereas the all-filtered path parks on the
                    // signal pipe — the Node worker-teardown hang).
                    let mut filtered_ready_events = 0usize;
                    if !poll_events.is_empty() {
                        // Build the per-wait routing tables from the LIVE interest map
                        // (NOT the pre-drain snapshot): an fd ADDed by another thread
                        // AFTER the snapshot whose edge is already in THIS batch must
                        // still be routable — its single EV_CLEAR/EPOLLET edge is
                        // consumed and will not re-fire. `gfd_info` resolves a guest
                        // fd to its (host_fd, mask, data, reg_gen); `host_to_gfds` is
                        // the reverse index for dup fan-out (one host fd may back
                        // several guest fds — Linux wakes each pollDesc). Built once
                        // here, then the epoll lock is dropped before the per-fd
                        // re-poll so a concurrent epoll_ctl isn't blocked on syscalls.
                        // gfd_info: guest fd -> (host_fd, requested events,
                        // epoll_data, reg_gen, last_ready, last_read_avail,
                        // write_backpressured). host_to_gfds: host fd
                        // -> guest fds sharing it (dup fan-out). Types inferred
                        // from the inserts.
                        let (gfd_info, host_to_gfds) = {
                            let open = open_file.description.read();
                            // Per-guest-fd epoll interest snapshot: (host_fd,
                            // events, epoll data, reg_gen, last_ready,
                            // last_read_avail, write_backpressured).
                            type GfdInterest = (i32, u32, u64, u32, u32, u64, bool);
                            let mut info: HashMap<i32, GfdInterest> = HashMap::new();
                            let mut rev: HashMap<i32, Vec<i32>> = HashMap::new();
                            if let OpenDescription::Epoll { interest, .. } = &*open {
                                for (gfd, slot) in interest.iter() {
                                    if let Some(hfd) = this.host_fd_for_poll(*gfd) {
                                        info.insert(
                                            *gfd,
                                            (
                                                hfd.get(),
                                                slot.event.events,
                                                slot.event.data,
                                                slot.reg_gen,
                                                slot.last_ready,
                                                slot.last_read_avail,
                                                slot.write_backpressured,
                                            ),
                                        );
                                        rev.entry(hfd.get()).or_default().push(*gfd);
                                    }
                                }
                            }
                            (info, rev)
                        };
                        // Resolve each drained event through its generational handle.
                        // The udata is (guest_fd, gen); trust it only if the live
                        // interest for guest_fd carries the SAME gen — otherwise the
                        // fd was recycled (ABA) and this is a stale edge for a gone
                        // registration: drop it (the current owner, if any, gets its
                        // own edge) and probe so the race stays observable. A valid
                        // hit fans out to every guest fd currently sharing that host
                        // fd (dups). bits==0 is an EVFILT_USER(0) wake / untranslatable
                        // filter — in-memory readiness is recomputed in step (2).
                        let mut deliver: HashMap<i32, (u32, u64)> = HashMap::new();
                        for ev in &poll_events {
                            let edge_bits = pollevent_to_epoll(ev);
                            if edge_bits == 0 {
                                continue;
                            }
                            let edge_readiness_count = if ev.readiness_count > 0 {
                                ev.readiness_count as u64
                            } else {
                                0
                            };
                            let (guest_fd, generation) = unpack_epoll_udata(ev.token);
                            match gfd_info.get(&guest_fd) {
                                Some(&(hfd, _, _, reg_gen, _, _, _)) if reg_gen == generation => {
                                    if let Some(siblings) = host_to_gfds.get(&hfd) {
                                        for sibling in siblings {
                                            let entry = deliver.entry(*sibling).or_insert((0, 0));
                                            entry.0 |= edge_bits;
                                            entry.1 = entry.1.max(edge_readiness_count);
                                        }
                                    }
                                }
                                _ => {
                                    crate::probes::epoll_stale_edge(
                                        ev.token,
                                        guest_fd,
                                        generation,
                                    );
                                }
                            }
                        }
                        // Deliver each owner's CURRENT readiness. RE-POLLING (rather
                        // than trusting the drained bits) keeps delivery correct even
                        // when the host fd was recycled between the edge and now — the
                        // live poll(2) state is always the truth. illumos devpoll
                        // model: the edge only FLAGS the fd; we re-poll just the
                        // flagged owners (polling ALL registered fds was O(nfds) and
                        // too slow).
                        for (gfd, (edge_bits, edge_readiness_count)) in deliver {
                            if let Some(&(
                                _,
                                requested,
                                data,
                                reg_gen,
                                last_ready,
                                last_read_avail,
                                write_backpressured,
                            )) =
                                gfd_info.get(&gfd)
                            {
                                host_ready_sampled.insert(gfd);
                                let raw = this.epoll_ready_events(gfd, requested);
                                let read_avail = if raw & READ_READY_BITS != 0 {
                                    this.host_read_avail_for_poll(gfd)
                                } else {
                                    0
                                };
                                let observed_read_avail = if edge_readiness_count > 0 {
                                    edge_readiness_count
                                } else {
                                    read_avail
                                };
                                let clear_write_backpressure =
                                    write_backpressured && raw & LINUX_EPOLLOUT != 0;
                                let read_growth = if requested & LINUX_EPOLLET != 0
                                    && raw & READ_READY_BITS != 0
                                    && observed_read_avail > last_read_avail
                                {
                                    raw & READ_READY_BITS
                                } else {
                                    0
                                };
                                let mut ready_events = if requested & LINUX_EPOLLET != 0 {
                                    (raw & !last_ready) | read_growth
                                } else {
                                    raw
                                };
                                if clear_write_backpressure {
                                    ready_events |= raw & LINUX_EPOLLOUT;
                                }
                                let read_avail_update = if raw & READ_READY_BITS == 0 {
                                    Some(0)
                                } else if ready_events & READ_READY_BITS != 0 {
                                    Some(observed_read_avail)
                                } else {
                                    None
                                };
                                ready_updates.push((
                                    gfd,
                                    reg_gen,
                                    raw,
                                    read_avail_update,
                                    clear_write_backpressure,
                                ));
                                crate::probes::epoll_interest(
                                    epfd,
                                    gfd,
                                    requested,
                                    raw,
                                    last_ready,
                                    ready_events,
                                );
                                if ready_events != 0 {
                                    acc.entry(gfd).or_insert((0, data)).0 |= ready_events;
                                } else if requested & LINUX_EPOLLET != 0
                                    && raw != 0
                                    && raw & last_ready != 0
                                {
                                    #[cfg(any(
                                        feature = "platform-macos",
                                        feature = "platform-freebsd",
                                        feature = "platform-netbsd"
                                    ))]
                                    {
                                        // BSD host-fd registrations are kept
                                        // level-triggered and the guest ET
                                        // contract is enforced by last_ready.
                                        // A level event that is fully masked by
                                        // the software latch would make the
                                        // instance kqueue fd immediately
                                        // readable again, so park on the
                                        // signal/backstop path instead.
                                        filtered_ready_events += 1;
                                    }
                                    #[cfg(not(any(
                                        feature = "platform-macos",
                                        feature = "platform-freebsd",
                                        feature = "platform-netbsd"
                                    )))]
                                    {
                                        // Native epoll ET on Linux has no
                                        // persistent level event to spin on
                                        // here; a later edge will re-wake the
                                        // instance.
                                    }
                                } else if raw != 0 {
                                    filtered_ready_events += 1;
                                }
                            }
                        }
                    }
                    // A REAL, CURRENT host-fd readiness event fired but the interest
                    // masks let none through (the events=0-with-data case): polling
                    // kq_fd would see the same level readiness and spin, so park on
                    // the signal pipe instead. Stale (recycled-fd) edges are excluded
                    // from `translatable_events`: their host edge was consumed, so
                    // kq_fd won't spin and the kqueue-poll path stays reachable by the
                    // current owner's own later edge. A pure EVFILT_USER drain is
                    // likewise excluded — it auto-resets.
                    kq_drained_all_filtered =
                        filtered_ready_events > 0 && acc.len() == acc_before;
                }
            }

            // (2) Host-backed fds: the multiplexer edge says which owners are
            // worth re-polling, but the live host level is still the authority.
            // Re-sample any host-backed interest that was not already sampled
            // from a drained mux event so a missed/stale edge cannot park an
            // epoll waiter while the host fd is already readable/writable.
            for (fd, interest) in &interests {
                if host_ready_sampled.contains(fd) || this.host_fd_for_poll(*fd).is_none() {
                    continue;
                }
                host_ready_sampled.insert(*fd);
                let requested = interest.event.events;
                let raw_ready = this.epoll_ready_events(*fd, requested);
                let read_avail = if raw_ready & READ_READY_BITS != 0 {
                    this.host_read_avail_for_poll(*fd)
                } else {
                    0
                };
                let clear_write_backpressure =
                    interest.write_backpressured && raw_ready & LINUX_EPOLLOUT != 0;
                let read_growth = if requested & LINUX_EPOLLET != 0
                    && raw_ready & READ_READY_BITS != 0
                    && read_avail > interest.last_read_avail
                {
                    raw_ready & READ_READY_BITS
                } else {
                    0
                };
                let mut ready_events = if requested & LINUX_EPOLLET != 0 {
                    (raw_ready & !interest.last_ready) | read_growth
                } else {
                    raw_ready
                };
                if clear_write_backpressure {
                    ready_events |= raw_ready & LINUX_EPOLLOUT;
                }
                let read_avail_update = if raw_ready & READ_READY_BITS == 0 {
                    Some(0)
                } else if ready_events & READ_READY_BITS != 0 {
                    Some(read_avail)
                } else {
                    None
                };
                ready_updates.push((
                    *fd,
                    interest.reg_gen,
                    raw_ready,
                    read_avail_update,
                    clear_write_backpressure,
                ));
                crate::probes::epoll_interest(
                    epfd,
                    *fd,
                    requested,
                    raw_ready,
                    interest.last_ready,
                    ready_events,
                );
                if ready_events != 0 {
                    let entry = acc.entry(*fd).or_insert((0, interest.event.data));
                    entry.0 |= ready_events;
                }
            }

            // (3) In-memory fds (no host fd): recompute readiness.
            for (fd, interest) in &interests {
                if host_ready_sampled.contains(fd) {
                    continue;
                }
                // Host-fd fds are handled by the kqueue drain above — EXCEPT a
                // named-FIFO read-end whose writer has closed: macOS kqueue won't
                // report that (dispatch::fifo_beacon decides it via a kernel
                // beacon pipe), so recompute it here so the notify_inmem_epoll
                // wake on writer-close surfaces EOF instead of blocking forever.
                if let Some(hfd) = this.host_fd_for_poll(*fd)
                    && !crate::dispatch::fifo_beacon::read_end_at_eof(hfd.get()) {
                        continue;
                    }
                let requested = interest.event.events;
                let raw_ready = this.epoll_ready_events(*fd, requested);
                let ready_events = if requested & LINUX_EPOLLET != 0 {
                    raw_ready & !interest.last_ready
                } else {
                    raw_ready
                };
                ready_updates.push((*fd, interest.reg_gen, raw_ready, Some(0), false));
                crate::probes::epoll_interest(
                    epfd,
                    *fd,
                    requested,
                    raw_ready,
                    interest.last_ready,
                    ready_events,
                );
                if ready_events != 0 {
                    let entry = acc.entry(*fd).or_insert((0, interest.event.data));
                    entry.0 |= ready_events;
                }
            }

            // EPOLLONESHOT: every interest that just fired must be disarmed
            // until EPOLL_CTL_MOD re-arms it (Linux semantics — the fd never
            // appears in a subsequent epoll_wait without an explicit MOD).
            // Collect the fds-to-disarm before consuming `acc`.
            let oneshot_fds: Vec<i32> = acc
                .iter()
                .filter(|(fd, _)| {
                    interests
                        .iter()
                        .any(|(ifd, slot)| ifd == *fd && slot.event.events & LINUX_EPOLLONESHOT != 0)
                })
                .map(|(fd, _)| *fd)
                .collect();

            if !ready_updates.is_empty() || !oneshot_fds.is_empty() {
                let mut open = open_file.description.write();
                if let OpenDescription::Epoll {
                    interest, kqueue, ..
                } = &mut *open
                {
                    #[cfg(any(
                        feature = "platform-macos",
                        feature = "platform-freebsd",
                        feature = "platform-netbsd"
                    ))]
                    let mut host_rearms: Vec<i32> = Vec::new();
                    for (fd, reg_gen, raw, read_avail, clear_write_backpressure) in ready_updates {
                        if let Some(slot) = interest.get_mut(&fd) {
                            if slot.reg_gen != reg_gen {
                                continue;
                            }
                            let before = slot.last_ready;
                            slot.last_ready = raw;
                            if let Some(read_avail) = read_avail {
                                slot.last_read_avail = read_avail;
                            }
                            if clear_write_backpressure {
                                slot.write_backpressured = false;
                            }
                            #[cfg(any(
                                feature = "platform-macos",
                                feature = "platform-freebsd",
                                feature = "platform-netbsd"
                            ))]
                            if slot.event.events & LINUX_EPOLLET != 0
                                && before != raw
                                && let Some(host_fd) = this.host_fd_for_poll(fd)
                            {
                                host_rearms.push(host_fd.get());
                            }
                        }
                    }
                    #[cfg(any(
                        feature = "platform-macos",
                        feature = "platform-freebsd",
                        feature = "platform-netbsd"
                    ))]
                    {
                        host_rearms.sort_unstable();
                        host_rearms.dedup();
                        for host_fd in host_rearms {
                            this.rebind_epoll_host_registration(kqueue, interest, HostFd(host_fd));
                        }
                    }
                    for fd in &oneshot_fds {
                        if let Some(slot) = interest.get_mut(fd) {
                            // Clear the events mask so subsequent waits never
                            // surface this fd until EPOLL_CTL_MOD re-arms it.
                            slot.event.events = 0;
                        }
                    }
                }
            }
            // Also remove the host kqueue filter for each disarmed fd so the
            // level-triggered EVFILT_READ doesn't keep firing and tight-loop
            // the next epoll_wait (the same shape as the events=0 fix above,
            // applied to the freshly-disarmed ONESHOT slot).
            for fd in &oneshot_fds {
                if let Some(host_fd) = this.host_fd_for_poll(*fd) {
                    kq.with_mux(|mux| {
                        let _ = mux.deregister(host_fd.get());
                    });
                }
            }

            // Tag each ready event with its ORIGINATING guest fd (acc is keyed by
            // guest fd) so an overflow queued into pending_ready can be purged by
            // fd on EPOLL_CTL_DEL/MOD even when epoll_data != fd. Split the tail
            // (still fd-tagged) into pending_ready, THEN strip fds for the
            // guest-visible `ready`. (audit M3; probe epollstaledel)
            let mut ready_tagged: Vec<(i32, LinuxEpollEvent)> = acc
                .into_iter()
                .map(|(fd, (events, data))| {
                    (
                        fd,
                        LinuxEpollEvent {
                            events,
                            _pad: 0,
                            data,
                        },
                    )
                })
                .collect();
            if ready_tagged.len() > max_events {
                let overflow: Vec<(i32, LinuxEpollEvent)> = ready_tagged.split_off(max_events);
                let mut open = open_file.description.write();
                if let OpenDescription::Epoll { pending_ready, .. } = &mut *open {
                    pending_ready.extend(overflow);
                }
            }
            ready = ready_tagged.into_iter().map(|(_fd, event)| event).collect();

            crate::event_ring::rec(
                crate::event_ring::EPWAIT,
                kq_fd,
                ready.len() as i32,
                timeout_ms,
            );
            if ready.is_empty() && timeout_ms != 0 {
                let timeout = if timeout_ms < 0 {
                    None
                } else {
                    Some(Duration::from_millis(timeout_ms as u64))
                };
                if kq_drained_all_filtered {
                    // The instance kqueue is readable, but every drained event
                    // was masked by the guest interest or by the software ET
                    // latch. Polling kq_fd for POLLIN would wake immediately
                    // and spin; polling the same valid fd with an empty event
                    // mask uses the WaitOnPollFds backstop as an interruptible
                    // retry sleep while preserving the guest deadline.
                    crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 2);
                    return Ok(DispatchOutcome::WaitOnPollFds {
                        fds: WaitFds::raw_one(kq_fd, 0),
                        timeout,
                        on_timeout: 0,
                        sig_mask,
                    });
                }
                if !has_interests {
                    // epoll_pwait with an empty interest set must still honour
                    // timeout + signal interruption, not return 0 immediately.
                    // There is no instance-fd readiness to wait for.
                    crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 2);
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds: WaitFds::empty(),
                        timeout,
                        on_timeout: 0,
                        sig_mask,
                    });
                }
                crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 1);
                crate::probes::epoll_wait_fd(epfd, -1, kq_fd, libc::POLLIN as i32, timeout_ms);
                // Poll the instance kqueue fd for readability. This avoids nesting
                // the epoll kqueue inside the per-thread kqueue, and unlike calling
                // kevent() here it does not consume pending epoll events before the
                // re-dispatched epoll_pwait can copy them out.
                return Ok(DispatchOutcome::WaitOnPollFds {
                    fds: WaitFds::raw_one(kq_fd, libc::POLLIN),
                    timeout,
                    on_timeout: 0,
                    sig_mask,
                });
            }

            crate::probes::epoll_result(epfd, ready.len() as i32, 0, timeout_ms, 0);
            write_epoll_events(memory, events_address, &ready, guest_abi)
        }

        }

        fn pselect6(this, cx, nfds: u64, readfds: GuestPtr, writefds: GuestPtr, exceptfds: GuestPtr, timeout: GuestPtr, sigmask: GuestPtr) {

            // Linux rejects nfds < 0 with EINVAL BEFORE anything else. nfds is an
            // `int`: read the LOW 32 bits as signed. The guest may pass a negative
            // either sign-extended (0xFFFF..FFFF) or, on x86_64 where an int arg
            // leaves the upper register bits undefined, zero-extended (0xFFFFFFFF)
            // — `as i32` catches both, whereas `as i64` missed the zero-extended
            // form and fell through to an EFAULT on the bad fd_set pointer
            // (select03). Without this, pselect6(-1, ...) — LTP pselect02 case 2 —
            // also blocks the test child forever (watchdog SIGALRM → TBROK).
            if (nfds as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let nfds = GuestLen::try_from_arg(nfds)?.0;
            let readfds_addr = readfds.0;
            let writefds_addr = writefds.0;
            let exceptfds_addr = exceptfds.0;
            let timeout_addr = timeout.0;
            let sigmask_addr = sigmask.0;
            let request_number = cx.number();
            // x86_64 select(2) reaches this handler via CARRICK_PRIVATE_X86_SELECT:
            // its timeout (arg4) is a *timeval (tv_usec), not pselect6's *timespec
            // (tv_nsec), and it has no sigmask. pselect6(72) keeps the decode below.
            let is_select = request_number == carrick_abi::CARRICK_PRIVATE_X86_SELECT;
            let request_args = cx.raw_args();
            let memory = &mut *cx.memory;
            let reporter = cx.reporter;

            // Linux's pselect6 ABI for the 6th argument is NOT a bare sigset_t *
            // but a pointer to `struct { const sigset_t *ss; size_t ss_len; }`
            // (the kernel "sigset_argpack"). We read the pair, then if ss != 0
            // and ss_len == LINUX_RT_SIGSET_SIZE, read the actual 8-byte sigset
            // for the bitmask. NULL outer arg means "no mask change". This bit
            // mask gates the waiter via `block_signals`: a blocked signal stays
            // pending instead of EINTR-ing the wait (LTP pselect02 case).
            let block_signals: carrick_abi::SigSet = if sigmask_addr != 0 {
                match memory.read_bytes(sigmask_addr, 16) {
                    Ok(pack) => {
                        let ss_ptr = u64::from_le_bytes(pack[0..8].try_into().unwrap_or([0; 8]));
                        let ss_len = u64::from_le_bytes(pack[8..16].try_into().unwrap_or([0; 8]));
                        if ss_ptr != 0 && ss_len == crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                            match memory.read_bytes(ss_ptr, ss_len as usize) {
                                Ok(bytes) => carrick_abi::SigSet::from_raw(u64::from_le_bytes(
                                    bytes.try_into().unwrap_or([0; 8]),
                                )),
                                Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                            }
                        } else {
                            carrick_abi::SigSet::EMPTY
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            } else {
                carrick_abi::SigSet::EMPTY
            };
            // pselect6's sigmask (when the outer argpack pointer is non-NULL)
            // REPLACES the thread's persistent mask for the wait; select /
            // NULL-mask pselect6 is a plain additive wait.
            let sig_mask = if sigmask_addr != 0 {
                carrick_abi::WaitSigMask::Replace(block_signals)
            } else {
                carrick_abi::WaitSigMask::NONE
            };

            // Decode timespec → millis for libc::poll. NULL = block forever (-1).
            let timeout_ms: i32 = if timeout_addr == 0 {
                -1
            } else if is_select {
                // select(2): the timeout is a *timeval (tv_sec + tv_usec), not a
                // *timespec. Linux rejects sec<0 or usec out of [0,1e6) → EINVAL.
                match read_kernel_struct::<LinuxTimeval>(memory, timeout_addr) {
                    Ok(tv) => {
                        let sec = tv.tv_sec;
                        let usec = tv.tv_usec;
                        if sec < 0 || !(0..1_000_000).contains(&usec) {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let ms = sec.saturating_mul(1000).saturating_add(usec / 1000);
                        if ms <= 0 {
                            0
                        } else if ms > i32::MAX as i64 {
                            i32::MAX
                        } else {
                            ms as i32
                        }
                    }
                    _ => 0,
                }
            } else {
                match read_kernel_struct::<LinuxTimespec>(memory, timeout_addr) {
                    Ok(timespec) => {
                        let sec = timespec.tv_sec;
                        let nsec = timespec.tv_nsec;
                        // Linux rejects an invalid timespec with EINVAL (negative
                        // seconds/nanoseconds or nsec out of [0, 1e9)) — LTP
                        // pselect02 case 3. carrick previously clamped it to 0
                        // (returned "timed out" instead of erroring).
                        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
                        if ms <= 0 {
                            0
                        } else if ms > i32::MAX as i64 {
                            i32::MAX
                        } else {
                            ms as i32
                        }
                    }
                    // A bad timeout pointer: leave the existing behavior (a guest
                    // read of an unmapped VA already injects a fault upstream);
                    // only the value-validation above is new. (faulty-pointer
                    // EFAULT vs guest-SIGSEGV is select03's domain — left as-is.)
                    _ => 0,
                }
            };

            // Pull each fd_set into memory.
            let read_set = this.read_optional_fd_set(memory, readfds_addr, nfds)??;
            let write_set = this.read_optional_fd_set(memory, writefds_addr, nfds)??;
            let except_set = this.read_optional_fd_set(memory, exceptfds_addr, nfds)??;

            // Collect the union of the three sets into per-fd entries, and try to
            // map each guest fd to a real host fd. Then route exactly like ppoll:
            //   - all fds host-backed → one libc::poll (kernel blocks efficiently);
            //   - any fd synthetic (eventfd/timerfd/epoll/in-memory pipe) → the
            //     poll_ready_events readiness loop, which is correct for those.
            // The old code unwrap_or'd synthetic fds into the guest fd *number* and
            // polled that as a host fd — which blocks on carrick's own fds and
            // deadlocks. Each fd gets POLLIN/POLLOUT/POLLPRI per its set membership.
            let mut owners: Vec<(i32, i16)> = Vec::new(); // (fd, requested_mask)
            let mut events_list: Vec<i16> = Vec::new();
            let mut host_map: Vec<Option<i32>> = Vec::new();
            for fd in 0..nfds {
                let r = read_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                let w = write_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                let e = except_set.as_ref().is_some_and(|s| fd_set_contains(s, fd));
                if !(r || w || e) {
                    continue;
                }
                let fd_i32 = i32::try_from(fd).map_err(|_| DispatchError::LengthTooLarge(u64::MAX))?;
                if !this.fd_is_valid(fd_i32) {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                let mut events: i16 = 0;
                if r {
                    events |= libc::POLLIN;
                }
                if w {
                    events |= libc::POLLOUT;
                }
                if e {
                    events |= libc::POLLPRI;
                }
                let mut req_mask: i16 = 0;
                if r {
                    req_mask |= 0x01;
                }
                if w {
                    req_mask |= 0x02;
                }
                if e {
                    req_mask |= 0x04;
                }
                owners.push((fd_i32, req_mask));
                events_list.push(events);
                // An eventfd with POLLOUT requested must go the poll_ready_events
                // path (always-writable); its host read_fd would never report
                // POLLOUT and the all-host libc::poll would block forever.
                host_map.push(if w && this.fd_is_eventfd(fd_i32) {
                    None
                } else {
                    this.host_fd_for_poll(fd_i32).map(HostFd::get)
                });
            }

            // revents per entry, filled by whichever path runs.
            let mut revents: Vec<i16> = vec![0; owners.len()];
            let all_host: Option<Vec<i32>> = host_map.iter().copied().collect();

            if owners.is_empty() {
                // No fds in any set. The original raw `libc::nanosleep` here
                // never observed guest pending signals (the pump publishes via
                // the dispatcher-thread-invisible PENDING atomic, not a host
                // signal), so pselect(0, NULL, NULL, NULL, &ts, NULL) slept the
                // whole timeout instead of EINTR-ing on SIGALRM. Hand off to
                // the runtime's lockless waiter just like ppoll does: empty
                // fds + Some(timeout) parks on the signal pipe with the
                // timeout, returns Interrupted (EINTR) on a wake, TimedOut
                // (returned=0) on the deadline.
                let timeout = if timeout_ms < 0 {
                    None
                } else {
                    Some(std::time::Duration::from_millis(timeout_ms as u64))
                };
                let _ = reporter;
                let _ = request_number;
                let _ = request_args;
                return Ok(DispatchOutcome::WaitOnFds {
                    fds: WaitFds::empty(),
                    timeout,
                    on_timeout: 0,
                    sig_mask,
                });
            } else if let Some(host_fds) = all_host {
                let mut pollfds: Vec<libc::pollfd> = host_fds
                    .iter()
                    .zip(events_list.iter())
                    .map(|(hf, ev)| libc::pollfd {
                        fd: *hf,
                        events: *ev,
                        revents: 0,
                    })
                    .collect();
                // NON-BLOCKING probe (timeout 0). A blocking libc::poll here
                // would (a) tie up this vCPU thread without releasing it for
                // siblings, and (b) never wake on a guest signal — carrick
                // publishes pending signals via an atomic the dispatcher checks
                // between dispatches, not a host signal that interrupts poll —
                // so select could never return EINTR. Instead, if nothing is
                // ready and the caller wants to wait, hand off to the runtime's
                // signal-interruptible waiter via WaitOnFdsSelect (mirrors how
                // ppoll uses WaitOnFds).
                let n = unsafe {
                    libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 0)
                };
                if let Err(errno) = n.host_syscall_errno() {
                    return Ok(DispatchOutcome::errno(errno));
                }
                if n == 0 && timeout_ms != 0 {
                    // Nothing ready yet, caller wants to block. Leave the guest
                    // fd-sets UNTOUCHED (select's bitmaps are input==output): a
                    // Ready re-dispatch must re-read the original input, and an
                    // EINTR must leave them unmodified (Linux semantics). The
                    // runtime zeroes them only if the wait times out.
                    let timeout = if timeout_ms < 0 {
                        None
                    } else {
                        Some(std::time::Duration::from_millis(timeout_ms as u64))
                    };
                    let wait_fds: Vec<(i32, i16)> = host_fds
                        .iter()
                        .zip(events_list.iter())
                        .map(|(hf, ev)| (*hf, *ev))
                        .collect();
                    let mut clear_on_timeout: Vec<(u64, usize)> = Vec::new();
                    if let Some(s) = &read_set {
                        clear_on_timeout.push((readfds_addr, s.len()));
                    }
                    if let Some(s) = &write_set {
                        clear_on_timeout.push((writefds_addr, s.len()));
                    }
                    if let Some(s) = &except_set {
                        clear_on_timeout.push((exceptfds_addr, s.len()));
                    }
                    return Ok(DispatchOutcome::WaitOnFdsSelect {
                        fds: WaitFds::raw(wait_fds),
                        timeout,
                        sig_mask,
                        clear_on_timeout,
                    });
                }
                for (slot, p) in revents.iter_mut().zip(pollfds.iter()) {
                    *slot = p.revents;
                }
            } else {
                // Mixed/synthetic: per-fd readiness with nanosleep slicing.
                let mut deadline_attempts = 0u32;
                loop {
                    let mut any = false;
                    for (i, (fd, _)) in owners.iter().enumerate() {
                        let rev = this.poll_ready_events(*fd, events_list[i]);
                        revents[i] = rev;
                        if rev != 0 {
                            any = true;
                        }
                    }
                    if any || timeout_ms == 0 {
                        break;
                    }
                    const SLICE_MS: u32 = 10;
                    unsafe {
                        let ts = libc::timespec {
                            tv_sec: 0,
                            tv_nsec: (SLICE_MS as i64) * 1_000_000,
                        };
                        libc::nanosleep(&ts, std::ptr::null_mut());
                    }
                    deadline_attempts += 1;
                    if timeout_ms > 0 {
                        if deadline_attempts.saturating_mul(SLICE_MS) as i32 >= timeout_ms {
                            break;
                        }
                    } else if deadline_attempts > 6000 {
                        // Blocked ~60 s with no fd ever ready: almost certainly a
                        // missing readiness signal, not a real idle wait. Make it
                        // loud in `carrick trace` instead of silently returning 0.
                        reporter.record(CompatEvent::partial_syscall(
                            request_number,
                            "pselect6",
                            request_args,
                            "blocked ~60s with no fd ready (possible poll deadlock)",
                        ));
                        break;
                    }
                }
            }

            // Adapter so the writeback below reads `p.revents` uniformly.
            let pollfds: Vec<libc::pollfd> = owners
                .iter()
                .zip(revents.iter())
                .map(|((fd, _), rev)| libc::pollfd {
                    fd: *fd,
                    events: 0,
                    revents: *rev,
                })
                .collect();

            // Write back ready bits. Start with fully-cleared sets and only
            // set bits for fds that fired.
            let mut new_read = read_set.clone().map(|mut s| {
                s.fill(0);
                s
            });
            let mut new_write = write_set.clone().map(|mut s| {
                s.fill(0);
                s
            });
            let mut new_except = except_set.clone().map(|mut s| {
                s.fill(0);
                s
            });
            let mut ready = 0i64;
            for ((fd, req_mask), p) in owners.iter().zip(pollfds.iter()) {
                let fd_usize = *fd as usize;
                let revs = p.revents;
                // select(2) returns the TOTAL number of ready bits across all
                // three sets — an fd that is ready for both read AND write
                // (e.g. an O_RDWR FIFO/socket placed in readfds and writefds,
                // LTP select01) counts as 2, not 1. Count each set-bit, not the
                // fd once.
                if (req_mask & 0x01) != 0
                    && (revs & (libc::POLLIN | libc::POLLHUP)) != 0
                    && let Some(ref mut set) = new_read
                {
                    fd_set_set(set, fd_usize);
                    ready += 1;
                }
                // select(2) marks an fd write-ready when it is writable OR has a
                // pending error/hangup (so the app can collect the error via a
                // write/getsockopt). Linux reports POLLOUT|POLLERR|POLLHUP on a
                // failed async connect; macOS poll() reports ONLY POLLHUP for the
                // same socket (verified). Treat POLLERR/POLLHUP as write-ready so
                // asyncio's sock_connect surfaces ConnectionRefusedError instead
                // of hanging until the wait_for timeout.
                if (req_mask & 0x02) != 0
                    && (revs & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP)) != 0
                    && let Some(ref mut set) = new_write
                {
                    fd_set_set(set, fd_usize);
                    ready += 1;
                }
                if (req_mask & 0x04) != 0
                    && (revs & (libc::POLLPRI | libc::POLLERR)) != 0
                    && let Some(ref mut set) = new_except
                {
                    fd_set_set(set, fd_usize);
                    ready += 1;
                }
            }
            if let Some(s) = &new_read
                && memory.write_bytes(readfds_addr, s).is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if let Some(s) = &new_write
                && memory.write_bytes(writefds_addr, s).is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if let Some(s) = &new_except
                && memory.write_bytes(exceptfds_addr, s).is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: ready })

        }

        fn ppoll(this, cx, fds: GuestPtr, nfds: u64, timeout: GuestPtr, sigmask: GuestPtr, sigsetsize: u64) {

            let pollfds_address = fds.0;
            let nfds =
                usize::try_from(nfds).map_err(|_| DispatchError::LengthTooLarge(nfds))?;
            let timeout_address = timeout.0;
            // sigmask args read here (before the `memory` mutable borrow); the mask
            // VALUE is read from guest memory below once `memory` is bound.
            let sigmask_addr = sigmask.0;
            let request_number = cx.number();
            // x86_64 poll(2) reaches this handler via CARRICK_PRIVATE_X86_POLL:
            // arg2 (`timeout`) is an INT timeout_ms (not a *timespec) and there is
            // no sigmask. ppoll(73) keeps the *timespec + sigmask decode below.
            let is_poll = request_number == carrick_abi::CARRICK_PRIVATE_X86_POLL;
            let request_args = cx.raw_args();
            let memory = &mut *cx.memory;
            let reporter = cx.reporter;

            // Decode timeout. NULL pointer means block forever; non-NULL points
            // to a `struct timespec { i64 tv_sec; i64 tv_nsec; }`. We translate
            // to milliseconds for libc::poll (-1 = forever, 0 = immediate).
            let timeout_ms: i32 = if is_poll {
                // poll: arg2 IS the int timeout_ms (-1 = block forever, 0 = return
                // now, N = N ms). The raw register value is sign-correct in its
                // low 32 bits.
                timeout_address as i32
            } else if timeout_address == 0 {
                -1
            } else {
                match read_kernel_struct::<LinuxTimespec>(memory, timeout_address) {
                    Ok(timespec) => {
                        let sec = timespec.tv_sec;
                        let nsec = timespec.tv_nsec;
                        let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
                        if ms <= 0 {
                            0
                        } else if ms > i32::MAX as i64 {
                            i32::MAX
                        } else {
                            ms as i32
                        }
                    }
                    _ => 0,
                }
            };

            // ppoll(fds, nfds, timeout, sigmask, sigsetsize): capture the sigmask
            // as a typed SigSet (converted at the guest sigset_t read) so a blocked
            // signal doesn't interrupt the wait (it stays pending, delivered after
            // the syscall). Mirrors epoll_pwait. Read before the pollfd loop
            // (returns an owned Vec, so the `memory` borrow is released).
            let block_signals: carrick_abi::SigSet = if is_poll {
                // poll(2) has no sigmask argument.
                carrick_abi::SigSet::EMPTY
            } else if sigmask_addr != 0 {
                if sigsetsize != crate::linux_abi::LINUX_RT_SIGSET_SIZE {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                match memory.read_bytes(
                    sigmask_addr,
                    crate::linux_abi::LINUX_RT_SIGSET_SIZE as usize,
                ) {
                    Ok(bytes) => {
                        let mut le = [0u8; 8];
                        le.copy_from_slice(&bytes[..8]);
                        carrick_abi::SigSet::from_raw(u64::from_le_bytes(le))
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            } else {
                carrick_abi::SigSet::EMPTY
            };
            // ppoll's sigmask (when present) REPLACES the thread's persistent
            // mask for the wait; poll(2) / NULL-mask ppoll is a plain additive
            // wait.
            let sig_mask = if !is_poll && sigmask_addr != 0 {
                carrick_abi::WaitSigMask::Replace(block_signals)
            } else {
                carrick_abi::WaitSigMask::NONE
            };

            // Read all the pollfds up front so we can route them. Fast path:
            // every fd in the set maps to a host fd (stdio bare, HostPipe, or
            // HostSocket) → call libc::poll once with the requested timeout
            // and let the kernel block efficiently instead of pseudo-polling
            // in a 10 ms-slice loop.
            let pollfd_size = core::mem::size_of::<LinuxPollFd>();
            let mut fds: Vec<LinuxPollFd> = Vec::with_capacity(nfds);
            let mut addresses: Vec<u64> = Vec::with_capacity(nfds);
            for index in 0..nfds {
                let offset = index
                    .checked_mul(pollfd_size)
                    .and_then(|offset| u64::try_from(offset).ok())
                    .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                let address = pollfds_address.checked_add(offset).ok_or(LINUX_EFAULT);
                let address = match address {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                let pollfd = read_pollfd(memory, address)?;
                fds.push(pollfd);
                addresses.push(address);
            }
            // Map guest fds → host fds where possible. Fast path requires
            // every fd be host-backed (stdio bare, HostPipe, HostSocket).
            // An eventfd with POLLOUT requested goes the poll_ready_events path
            // (always-writable); its host read_fd never reports POLLOUT.
            let host_fds: Option<Vec<i32>> = fds
                .iter()
                .map(|p| {
                    if (p.events & LINUX_POLLOUT) != 0 && this.fd_is_eventfd(p.fd) {
                        None
                    } else {
                        this.host_fd_for_poll(p.fd).map(HostFd::get)
                    }
                })
                .collect();
            if let Some(host_fds) = host_fds {
                let mut sys_pollfds: Vec<libc::pollfd> = fds
                    .iter()
                    .zip(host_fds.iter())
                    .map(|(p, hf)| libc::pollfd {
                        fd: *hf,
                        events: p.events,
                        revents: 0,
                    })
                    .collect();
                // NON-BLOCKING probe (timeout 0): we must NEVER block here — this
                // runs while holding the dispatcher lock, and blocking would starve
                // every sibling thread (the GIL handoff, a server's workers). If
                // nothing is ready and the guest asked to wait, hand off to the
                // runtime via WaitOnFds, which waits with the lock RELEASED.
                let n = unsafe {
                    libc::poll(
                        sys_pollfds.as_mut_ptr(),
                        sys_pollfds.len() as libc::nfds_t,
                        0,
                    )
                };
                if let Err(errno) = n.host_syscall_errno() {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let mut ready = 0i64;
                for (i, p) in sys_pollfds.iter().enumerate() {
                    let mut pollfd = fds[i];
                    pollfd.revents = p.revents;
                    if pollfd.revents != 0 {
                        ready += 1;
                    }
                    // Always write back (zeroed revents on a not-ready probe) so a
                    // later timeout completion needs no further writes.
                    if write_kernel_struct_raw(memory, addresses[i], &pollfd).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
                if ready > 0 || timeout_ms == 0 {
                    return Ok(DispatchOutcome::Returned { value: ready });
                }
                let timeout = if timeout_ms < 0 {
                    None
                } else {
                    Some(std::time::Duration::from_millis(timeout_ms as u64))
                };
                let wait_fds: Vec<(i32, i16)> = sys_pollfds.iter().map(|p| (p.fd, p.events)).collect();
                // poll/ppoll: a timeout means "no fds ready" → return 0.
                return Ok(DispatchOutcome::WaitOnFds {
                    fds: WaitFds::raw(wait_fds),
                    timeout,
                    on_timeout: 0,
                    sig_mask,
                });
            }

            // Mixed / synthetic fds: fall back to the per-fd readiness check
            // loop. Slow because of nanosleep slicing but correct.
            let mut ready: i64;
            let mut deadline_attempts = 0u32;
            loop {
                ready = 0;
                for (index, pollfd) in fds.iter_mut().enumerate() {
                    pollfd.revents = this.poll_ready_events(pollfd.fd, pollfd.events);
                    if pollfd.revents != 0 {
                        ready += 1;
                    }
                    if write_kernel_struct_raw(memory, addresses[index], pollfd).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
                if ready > 0 || timeout_ms == 0 {
                    break;
                }
                const SLICE_MS: u32 = 10;
                unsafe {
                    let ts = libc::timespec {
                        tv_sec: 0,
                        tv_nsec: (SLICE_MS as i64) * 1_000_000,
                    };
                    libc::nanosleep(&ts, std::ptr::null_mut());
                }
                deadline_attempts += 1;
                if timeout_ms > 0 {
                    let elapsed_ms = deadline_attempts.saturating_mul(SLICE_MS);
                    if elapsed_ms as i32 >= timeout_ms {
                        break;
                    }
                } else if deadline_attempts > 6000 {
                    // ~60 s ceiling for "block forever" callers. Reaching it means
                    // no fd ever became ready — surface it loudly in carrick trace
                    // rather than silently returning 0 (a likely poll deadlock).
                    reporter.record(CompatEvent::partial_syscall(
                        request_number,
                        "ppoll",
                        request_args,
                        "blocked ~60s with no fd ready (possible poll deadlock)",
                    ));
                    break;
                }
            }

            Ok(DispatchOutcome::Returned { value: ready })

        }

        fn socket(this, cx, domain: u64, socket_type: u64, protocol: u64) {

            let family = domain as i32;
            let type_ = socket_type as i32;
            let protocol = protocol as i32;
            // AF_NETLINK has no macOS equivalent, so we can't back it with a
            // host socket. Model a synthetic netlink fd instead (see the
            // `OpenDescription::Netlink` docs) so glibc's __check_pf /
            // getaddrinfo and `ip`/`ss` get a valid fd rather than
            // EAFNOSUPPORT.
            if family == LINUX_AF_NETLINK {
                return Ok(this.netlink_socket(type_, protocol));
            }
            Ok(this.host_socket_install(family, type_, protocol))

        }

        fn socketpair(this, cx, domain: u64, socket_type: u64, protocol: u64, sv: GuestPtr) {

            let memory = &mut *cx.memory;
            let family = domain as i32;
            let type_ = socket_type as i32;
            let protocol = protocol as i32;
            let sv_addr = sv.0;
            let socket_flags = LinuxSocketTypeFlags::from_bits_retain(type_);
            let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
            let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
            let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
            let host_family = linux_to_host_af(family);
            let host_type = host_socktype_backing(family, base_type);

            let mut host_fds: [i32; 2] = [-1, -1];
            let rc =
                unsafe { libc::socketpair(host_family, host_type, protocol, host_fds.as_mut_ptr()) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            set_host_nonblocking(host_fds[0]);
            set_host_nonblocking(host_fds[1]);
            let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
            let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
            let first = OpenFile::with_host_fd(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    host_fd: host_fds[0],
                    family,
                    type_: base_type,
                    base: OpenDescriptionBase::new(status_flags),
                })),
                fd_flags,
                host_fds[0],
            );
            let second = OpenFile::with_host_fd(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    host_fd: host_fds[1],
                    family,
                    type_: base_type,
                    base: OpenDescriptionBase::new(status_flags),
                })),
                fd_flags,
                host_fds[1],
            );
            let (read_fd, write_fd) = match this.install_fd_pair_at_or_above(3, first, second) {
                Ok(pair) => pair,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                }
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, sv_addr, &pair).is_err() {
                let removed = {
                    let mut table = this.io.open_files.write();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn bind(this, cx, fd: Fd, addr: GuestPtr, addrlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0;
            let addr_addr = addr.0;
            let addrlen = addrlen as u32;
            // AF_NETLINK bind: read the (optional) sockaddr_nl to pick up the
            // requested pid/groups, then assign a pid (the guest's own pid
            // when the caller passed 0, i.e. "let the kernel choose").
            if let Some(open_file) = this.open_file(fd)
                && let OpenDescription::Netlink {
                    pid: nl_pid,
                    groups: nl_groups,
                    ..
                } = &mut *open_file.description.write()
            {
                let (req_pid, req_groups) = read_sockaddr_nl(memory, addr_addr, addrlen);
                *nl_pid = if req_pid != 0 {
                    req_pid
                } else {
                    std::process::id()
                };
                *nl_groups = req_groups;
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            // AF_UNIX autobind: a bind with only the family (addrlen == 2, empty
            // path) asks the kernel to assign a unique abstract name. macOS has
            // no autobind, so generate the name + a host node and bind there; a
            // later getsockname reverse-translates the host path → the abstract
            // name via the registry.
            if family == libc::AF_UNIX && addrlen <= 2 {
                let host_path = autobind_unix_host_path();
                let p = host_path.to_string_lossy();
                let pb = p.as_bytes();
                if pb.len() >= 104 {
                    return Ok(DispatchOutcome::errno(LINUX_ENAMETOOLONG));
                }
                let mut sa = vec![0u8; 2 + pb.len() + 1];
                set_host_sockaddr_header(&mut sa, libc::AF_UNIX);
                sa[2..2 + pb.len()].copy_from_slice(pb);
                // Remove a stale socket node left by a prior run (the generated
                // name is per-process; a leftover host file would be EADDRINUSE),
                // mirroring the pathname unlink-then-bind below.
                if let Ok(md) = std::fs::symlink_metadata(&*p) {
                    use std::os::unix::fs::FileTypeExt;
                    if md.file_type().is_socket() {
                        let _ = std::fs::remove_file(&*p);
                    }
                }
                let rc = unsafe {
                    libc::bind(
                        host_fd.get(),
                        sa.as_ptr() as *const libc::sockaddr,
                        sa.len() as u32,
                    )
                };
                return Ok(match rc.host_syscall_errno() {
                    Ok(_) => DispatchOutcome::Returned { value: 0 },
                    Err(errno) => DispatchOutcome::errno(errno),
                });
            }
            // AF_UNIX bind to a directory-like pathname (trailing '/', e.g. "//"
            // = "/") can't hold a socket node on Linux → EADDRINUSE. carrick maps
            // every path to a fresh hashed host node, so without this check it
            // would wrongly succeed (TestProtocolListenError).
            if family == libc::AF_UNIX
                && let Ok(raw) = memory.read_bytes(addr_addr, addrlen as usize)
                && raw.len() > 2
                && raw[2] != 0
            {
                let nul = raw[2..].iter().position(|&b| b == 0).map(|p| 2 + p).unwrap_or(raw.len());
                if raw[..nul].last() == Some(&b'/') {
                    return Ok(DispatchOutcome::errno(linux_errno::EADDRINUSE));
                }
            }
            // For an AF_UNIX PATHNAME socket, capture the GUEST sun_path now
            // (while we still hold the memory borrow) so that — after a
            // successful host bind — we can materialise a stat-able S_IFSOCK
            // node at that guest path in the overlay. Linux creates a real
            // socket node on bind; carrick binds the host socket at a HASHED
            // host path, so without this a stat/os.path.exists/chmod/unlink of
            // the guest path is ENOENT (multiprocessing forkserver chmods its
            // listener → crash). Abstract-namespace (leading NUL) and autobind
            // sockets have no fs node, so are excluded.
            let guest_unix_path: Option<String> = if family == libc::AF_UNIX {
                guest_unix_pathname(memory, addr_addr, addrlen)
            } else {
                None
            };
            let resolved_guest_unix_path = if let Some(gp) = &guest_unix_path {
                let resolved = this.resolve_at_path(LINUX_AT_FDCWD, gp)?;
                let parent = std::path::Path::new(&resolved)
                    .parent()
                    .and_then(|p| p.to_str())
                    .filter(|p| !p.is_empty())
                    .unwrap_or("/");
                match this.layered_metadata(parent) {
                    Ok(md) if md.kind == RootFsEntryKind::Directory => {}
                    Ok(_) => return Ok(DispatchOutcome::errno(LINUX_ENOTDIR)),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
                if this.layered_lstat(&resolved).is_ok() {
                    return Ok(DispatchOutcome::errno(linux_errno::EADDRINUSE));
                }
                Some(resolved)
            } else {
                None
            };
            let host_addr = read_linux_sockaddr(memory, addr_addr, addrlen, family)?;
            // AF_UNIX pathname sockets are bound at a stable host path (see
            // unix_socket_host_path). The guest's unlink only tombstones a VFS
            // overlay entry, so it can't clear a real host socket left by a
            // prior run — which would make bind() fail with EADDRINUSE. Mirror
            // Linux's unlink-then-bind by removing a stale *socket* node here
            // before binding (only if it is actually a socket, never a regular
            // file or directory, to stay safe).
            if family == libc::AF_UNIX && host_addr.len() > 2 && host_addr[2] != 0 {
                let path_end = host_addr[2..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| 2 + p)
                    .unwrap_or(host_addr.len());
                if let Ok(path) = std::str::from_utf8(&host_addr[2..path_end])
                    && let Ok(md) = std::fs::symlink_metadata(path)
                {
                    use std::os::unix::fs::FileTypeExt;
                    if md.file_type().is_socket() {
                        let _ = std::fs::remove_file(path);
                    }
                }
            }
            let rc = unsafe {
                libc::bind(
                    host_fd.get(),
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            if family == libc::AF_UNIX && host_addr.len() > 2 {
                let end = host_addr[2..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| 2 + i)
                    .unwrap_or(host_addr.len());
                crate::event_ring::rec(
                    crate::event_ring::BIND,
                    fd,
                    host_fd.get(),
                    crate::event_ring::path_hash(&host_addr[2..end]),
                );
                // Stamp the guest sun_path onto the just-created host node so a
                // DIFFERENT carrick process (whose per-process registry lacks
                // this bind) can reverse-translate it in getsockname/getpeername
                // instead of leaking the raw <hash>.sock host path.
                persist_unix_path_xattr(&host_addr[2..end]);
            }
            // Bind succeeded. Materialise the guest-facing S_IFSOCK node at the
            // resolved guest path. Linux applies the umask to 0o777 for the
            // socket node's permission bits (verified vs Docker: umask 022 →
            // 0o755). Best-effort: a failure here doesn't undo the host bind
            // (the socket still works), it only means stat won't see the node.
            if let Some(resolved) = resolved_guest_unix_path {
                let umask = this.cred_snapshot().umask & 0o777;
                let mode = 0o777 & !umask;
                if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                    let _ = m.vfs.create_socket(&m.full_path, mode);
                } else {
                    let _ = this.fs.rootfs_vfs.overlay.create_socket(&resolved, mode);
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn listen(this, cx, fd: Fd, backlog: u64) {

            let fd: Fd = fd;
            let backlog = backlog as i32;
            let (host_fd, _family) = this.host_socket_lookup(fd.0)?;
            let rc = unsafe { libc::listen(host_fd.get(), backlog) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            crate::event_ring::rec(crate::event_ring::LISTEN, host_fd.get(), 0, 0);
            // A listen socket exists only to accept(2); make the HOST socket
            // non-blocking so accept never blocks under the dispatcher lock — the
            // guest's blocking intent is emulated by blocking_io's WaitOnFds
            // hand-off (the one idiomatic, targeted non-blocking exception; data
            // sockets keep their native mode + per-call MSG_DONTWAIT).
            set_host_nonblocking(host_fd.get());
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn accept(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr) {

            Ok(this.accept_common(fd, addr, addrlen, &mut *cx.memory, 0))

        }

        fn accept4(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr, flags: u64) {

            let flags = flags as i32;
            Ok(this.accept_common(fd, addr, addrlen, &mut *cx.memory, flags))

        }

        fn connect(this, cx, fd: Fd, addr: GuestPtr, addrlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0;
            let addr_addr = addr.0;
            let addrlen = addrlen as u32;
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            let mut host_addr = read_linux_sockaddr(memory, addr_addr, addrlen, family)?;
            rewrite_unspecified_connect_loopback(family, &mut host_addr);
            // connect(AF_UNSPEC) is the UDP "disconnect" (dissolve the peer
            // association); Linux returns 0. macOS disconnects too but may then
            // report EAFNOSUPPORT/EINVAL — treat those as success below.
            let is_unspec_disconnect = addrlen >= 2
                && memory
                    .read_bytes(addr_addr, 2)
                    .ok()
                    .map(|b| u16::from_ne_bytes([b[0], b[1]]) as i32 == LINUX_AF_UNSPEC)
                    .unwrap_or(false);
            if family == libc::AF_UNIX
                && let Some(gp) = guest_unix_pathname(memory, addr_addr, addrlen)
            {
                let resolved = this.resolve_at_path(LINUX_AT_FDCWD, &gp)?;
                let parent = std::path::Path::new(&resolved)
                    .parent()
                    .and_then(|p| p.to_str())
                    .filter(|p| !p.is_empty())
                    .unwrap_or("/");
                match this.layered_metadata(parent) {
                    Ok(md) if md.kind == RootFsEntryKind::Directory => {}
                    Ok(_) => return Ok(DispatchOutcome::errno(LINUX_ENOTDIR)),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
                match this.layered_metadata(&resolved) {
                    Ok(md) if md.kind == RootFsEntryKind::Socket => {}
                    Ok(_) => return Ok(DispatchOutcome::errno(linux_errno::ECONNREFUSED)),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
            // connect(2) has no per-call non-blocking flag, so put the host socket
            // non-blocking — it then returns EINPROGRESS instead of blocking under
            // the dispatcher lock. recv/send use MSG_DONTWAIT + the guest's intended
            // mode (status_flags), so the host fd's real mode is immaterial.
            let nonblocking = this.io_is_nonblocking(fd, 0);
            set_host_nonblocking(host_fd.get());
            let rc = unsafe {
                libc::connect(
                    host_fd.get(),
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            };
            if family == libc::AF_UNIX && host_addr.len() > 2 {
                let end = host_addr[2..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| 2 + i)
                    .unwrap_or(host_addr.len());
                crate::event_ring::rec(
                    crate::event_ring::CONNECT,
                    host_fd.get(),
                    rc,
                    crate::event_ring::path_hash(&host_addr[2..end]),
                );
            }
            if rc == 0 {
                // A non-blocking host connect reporting success does not prove the
                // connection completed — consult SO_ERROR (see
                // connect_success_or_pending_error).
                return Ok(connect_success_or_pending_error(host_fd.get()));
            }
            let e = HostSyscallError::last().linux_errno();
            // EISCONN: macOS reports it BOTH when an async connect we deferred
            // completes (the POLLOUT re-dispatch) AND when the guest calls
            // connect() on an already-established socket. Only the former should
            // be folded to success: distinguish via the per-description
            // connect_in_progress flag (set when we first deferred this connect).
            //   - in-progress set ⇒ async completion: consult SO_ERROR so a FAILED
            //     async connect (macOS still says EISCONN) surfaces ECONNREFUSED
            //     etc. at connect time rather than deferring it to the first recv
            //     (which breaks blocking connect + the IPv6->IPv4 address fallback).
            //   - in-progress clear ⇒ a real re-connect of an established socket:
            //     surface EISCONN to the guest (Linux connect01 "already connected").
            if e == LINUX_EISCONN {
                if this.socket_connect_in_progress(fd) {
                    this.set_socket_connect_in_progress(fd, false);
                    return Ok(connect_success_or_pending_error(host_fd.get()));
                }
                return Ok(DispatchOutcome::errno(LINUX_EISCONN));
            }
            if e == LINUX_EINPROGRESS || e == LINUX_EALREADY || e == LINUX_EAGAIN {
                if nonblocking {
                    // Non-blocking guest: hand EINPROGRESS/EALREADY straight back.
                    return Ok(DispatchOutcome::errno(e));
                }
                // Blocking guest: wait (lock released) for the socket to become
                // writable, then re-dispatch — connect then returns EISCONN or the
                // real connect error. Mark the connect as deferred so the EISCONN
                // we expect on re-dispatch is recognised as async-completion above.
                this.set_socket_connect_in_progress(fd, true);
                return Ok(DispatchOutcome::WaitOnFds {
                    fds: WaitFds::raw_one(host_fd.get(), libc::POLLOUT),
                    timeout: None,
                    on_timeout: LINUX_EINPROGRESS.guest_retval(),
                    sig_mask: carrick_abi::WaitSigMask::NONE,
                });
            }
            if is_unspec_disconnect && (e == LINUX_EAFNOSUPPORT || e == LINUX_EINVAL) {
                // macOS already disassociated the UDP socket; Linux returns 0
                // for the AF_UNSPEC disconnect, so report success.
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            Ok(DispatchOutcome::errno(e))

        }

        fn getsockname(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0;
            let addr_addr = addr.0;
            let addrlen_addr = addrlen.0;
            // AF_NETLINK getsockname: hand back a sockaddr_nl carrying the
            // bound pid/groups (or pid=0 if the socket was never bound).
            if let Some(open_file) = this.open_file(fd)
                && let OpenDescription::Netlink { pid, groups, .. } = &*open_file.description.read()
            {
                let nl = sockaddr_nl_bytes(*pid, *groups);
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &nl).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            // getsockname needs both output pointers; a NULL addr or addrlen →
            // EFAULT (getsockname01), checked after the fd validation so a
            // bad/non-socket fd still surfaces EBADF/ENOTSOCK first.
            if addr_addr == 0 || addrlen_addr == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            // A negative input *addrlen → EINVAL (getsockname01); the kernel
            // reads addrlen first and rejects len < 0 before copying out. A bad
            // (unreadable) addrlen pointer surfaces EFAULT via the write below.
            if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
            let rc =
                unsafe { libc::getsockname(host_fd.get(), sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, false);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn getpeername(this, cx, fd: Fd, addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0;
            let addr_addr = addr.0;
            let addrlen_addr = addrlen.0;
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
            let rc =
                unsafe { libc::getpeername(host_fd.get(), sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            // Connected (the host call succeeded): a NULL addr/addrlen → EFAULT
            // and a negative input *addrlen → EINVAL (symmetric with
            // getsockname; checked after the host call so an unconnected
            // socket's ENOTCONN still wins). getpeername01.
            if addr_addr == 0 || addrlen_addr == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, false);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn sendto(this, cx, fd: Fd, buf: GuestPtr, len: u64, flags: u64, dest_addr: GuestPtr, addrlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0;
            let buf_addr = buf.0;
            let len = len as usize;
            let flags = flags as i32;
            let dest_addr = dest_addr.0;
            let dest_len = addrlen as u32;
            // AF_NETLINK send: treat the payload as an rtnetlink request and
            // queue a synthetic dump reply for the next recv.
            if this.fd_is_netlink(fd) {
                let bytes = match memory.read_bytes(buf_addr, len) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                return Ok(this.netlink_send(fd, &bytes));
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            // Zero-copy when the whole buffer is one contiguous mapped region
            // (send straight out of guest memory); otherwise snapshot it. The
            // pointer is resolved per dispatch — blocking_io's op is FnOnce and an
            // EAGAIN re-dispatches the whole handler, so it never outlives a
            // lock-releasing wait.
            let zc_ptr = memory.host_ptr_for_read(buf_addr, len);
            let send_copy: Option<Vec<u8>> = if zc_ptr.is_some() {
                None
            } else {
                match memory.read_bytes(buf_addr, len) {
                    Ok(b) => Some(b),
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            };
            let data_ptr: *const u8 = match (zc_ptr, &send_copy) {
                (Some(p), _) => p,
                (None, Some(b)) => b.as_ptr(),
                (None, None) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            // Read the destination sockaddr (if any) from guest memory up front,
            // then send with MSG_DONTWAIT through blocking_io: a full socket buffer
            // (EAGAIN) on a blocking fd waits for POLLOUT losslessly.
            let host_addr = if dest_addr == 0 {
                None
            } else {
                // Linux's move_addr_to_kernel rejects a negative addrlen with
                // EINVAL before touching the buffer (sendto01 "invalid to buffer
                // length", tolen = -1). read_linux_sockaddr reads addrlen as u32
                // and would instead fault on the huge length (EFAULT) — guard here.
                if (dest_len as i32) < 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                match read_linux_sockaddr(memory, dest_addr, dest_len, family) {
                    Ok(b) => Some(b),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };
            // A send on an unconnected STREAM socket: Linux returns EPIPE
            // (tcp_sendmsg with no peer), but macOS returns ENOTCONN. Remap only
            // for stream sockets so datagram ENOTCONN (a real Linux errno) is
            // untouched. (sendto01 "not connected TCP")
            let is_stream = this.socket_guest_type(fd) == Some(libc::SOCK_STREAM);
            let nonblocking = this.io_is_nonblocking(fd, flags);
            let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
            let send_to = this
                .open_file(fd)
                .and_then(|f| f.description.read().send_timeout());
            let outcome = this.blocking_io(host_fd.get(), IoDir::Write, nonblocking, send_to, || {
                let n = match &host_addr {
                    None => unsafe {
                        libc::sendto(
                            host_fd.get(),
                            data_ptr as *const _,
                            len,
                            host_flags,
                            std::ptr::null(),
                            0,
                        )
                    },
                    Some(a) => unsafe {
                        libc::sendto(
                            host_fd.get(),
                            data_ptr as *const _,
                            len,
                            host_flags,
                            a.as_ptr() as *const _,
                            a.len() as u32,
                        )
                    },
                };
                match n.host_syscall_errno().map(|value| value as i64) {
                    Err(LINUX_ENOTCONN) if is_stream => Err(LINUX_EPIPE),
                    other => other,
                }
            });
            Ok(outcome)

        }

        fn recvfrom(this, cx, fd: Fd, buf: GuestPtr, len: u64, flags: u64, src_addr: GuestPtr, addrlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0;
            let buf_addr = buf.0;
            let len = len as usize;
            let flags = flags as i32;
            let src_addr = src_addr.0;
            let src_len_addr = addrlen.0;
            // AF_NETLINK recv: drain the queued dump reply. The source address
            // (if requested) is the kernel: sockaddr_nl with pid=0.
            if this.fd_is_netlink(fd) {
                let drained = this.netlink_recv(fd, buf_addr, len, memory);
                if let DispatchOutcome::Returned { .. } = drained
                    && src_addr != 0
                    && src_len_addr != 0
                {
                    let nl = sockaddr_nl_bytes(0, 0);
                    let _ = write_linux_sockaddr(memory, src_addr, src_len_addr, &nl);
                }
                return Ok(drained);
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            // MSG_ERRQUEUE reads the socket's error queue. carrick keeps no
            // error queue, so it's always empty → EAGAIN (recv01/recvfrom01),
            // matching Linux when no error is queued. Checked after the socket
            // lookup so a bad/non-socket fd still surfaces EBADF/ENOTSOCK.
            // (from_bits_retain: recv IGNORES other unknown flag bits.)
            if LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::ERRQUEUE) {
                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
            }
            // When the caller wants the source address back, Linux's
            // move_addr_to_user reads the in/out length as a *signed* int and
            // returns EINVAL for a negative value (recvfrom01 "invalid socket
            // addr length", fromlen = -1). carrick's write_linux_sockaddr reads
            // it as u32, so it would never reject it — validate here.
            if src_addr != 0 && src_len_addr != 0 {
                match memory.read_bytes(src_len_addr, 4) {
                    Ok(b) => {
                        if i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            }
            // Native fd mode preserved; force this CALL non-blocking with
            // MSG_DONTWAIT and route through blocking_io: on EAGAIN a blocking-mode
            // guest fd waits losslessly (kqueue, lock released), a non-blocking one
            // gets EAGAIN. Never blocks under the dispatcher lock.
            let nonblocking = this.io_is_nonblocking(fd, flags);
            let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
            let len = len.min(crate::dispatch::MAX_RW_COUNT);
            // Zero-copy recv straight INTO guest memory when the destination is
            // one contiguous, guest-writable region; else recv into a bounce and
            // copy. host_ptr_for_write enforces guest-writability (a read-only
            // mapping returns None → checked write path → EFAULT).
            let zc_dst = memory.host_ptr_for_write(buf_addr, len);
            let zero_copy = zc_dst.is_some();
            let mut recv_copy: Option<Vec<u8>> = if zero_copy { None } else { Some(vec![0u8; len]) };
            let dst_ptr: *mut u8 = match (zc_dst, recv_copy.as_mut()) {
                (Some(p), _) => p,
                (None, Some(b)) => b.as_mut_ptr(),
                (None, None) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            let recv_to = this
                .open_file(fd)
                .and_then(|f| f.description.read().recv_timeout());
            let outcome = this.blocking_io(host_fd.get(), IoDir::Read, nonblocking, recv_to, || {
                let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
                let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
                let (n, used_addr) = if src_addr == 0 {
                    (
                        unsafe {
                            libc::recvfrom(
                                host_fd.get(),
                                dst_ptr as *mut _,
                                len,
                                host_flags,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            )
                        },
                        false,
                    )
                } else {
                    (
                        unsafe {
                            libc::recvfrom(
                                host_fd.get(),
                                dst_ptr as *mut _,
                                len,
                                host_flags,
                                sa.as_mut_ptr() as *mut _,
                                &mut sa_len as *mut _,
                            )
                        },
                        true,
                    )
                };
                let n = n.host_syscall_errno()?;
                // Copy path: flush the bounce into guest. Zero-copy: the kernel
                // already wrote straight into guest memory, nothing to copy.
                if !zero_copy
                    && n > 0
                    && let Some(b) = recv_copy.as_ref()
                    && memory.write_bytes(buf_addr, &b[..n as usize]).is_err()
                {
                    return Err(LINUX_EFAULT);
                }
                if used_addr && src_addr != 0 && src_len_addr != 0 {
                    let used = (sa_len as usize).min(sa.len());
                    let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, true);
                    if write_linux_sockaddr(memory, src_addr, src_len_addr, &linux_bytes).is_err() {
                        return Err(LINUX_EFAULT);
                    }
                }
                Ok(n as i64)
            });
            Ok(outcome)

        }

        fn setsockopt(this, cx, fd: Fd, level: u64, optname: u64, optval: GuestPtr, optlen: u64) {

            let memory = &*cx.memory;
            let fd = fd.0;
            let level = level as i32;
            let optname = optname as i32;
            let optval_addr = optval.0;
            let optlen = optlen as u32;
            // AF_NETLINK setsockopt: glibc/`ip` set SO_RCVBUF / SO_SNDBUF and
            // netlink-specific options (NETLINK_*). We don't model buffer
            // pressure, so just accept them.
            if this.fd_is_netlink(fd) {
                let _ = (level, optname, optval_addr, optlen);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // LTP setsockopt01: a closed fd is EBADF and a non-socket fd is
            // ENOTSOCK; host_socket_lookup collapses both to EINVAL. (netlink is
            // handled above.)
            match this.open_file(fd) {
                None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                Some(of) => {
                    if !matches!(&*of.description.read(), OpenDescription::HostSocket { .. }) {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                    }
                }
            }
            let (host_fd, _family) = this.host_socket_lookup(fd)?;
            // Record the GUEST-intended SO_REUSEPORT / SO_RCVBUF / SO_SNDBUF so
            // getsockopt reports what the guest set rather than carrick's
            // host-side widening (SO_REUSEADDR→SO_REUSEPORT for UDP; AF_UNIX
            // buffer widening). The value still passes through to the host
            // below. (audit M4, M5)
            if level == LINUX_SOL_SOCKET
                && (optname == LINUX_SO_REUSEPORT
                    || optname == LINUX_SO_RCVBUF
                    || optname == LINUX_SO_SNDBUF)
                && optlen >= 4
                && let Ok(b) = memory.read_bytes(optval_addr, 4)
            {
                let v = i32::from_ne_bytes([b[0], b[1], b[2], b[3]]);
                if let Some(open_file) = this.open_file(fd)
                    && let OpenDescription::HostSocket { base, .. } =
                        &mut *open_file.description.write()
                {
                    if optname == LINUX_SO_REUSEPORT {
                        base.set_so_reuseport(v != 0);
                    } else if optname == LINUX_SO_RCVBUF {
                        base.set_so_rcvbuf(v);
                    } else {
                        base.set_so_sndbuf(v);
                    }
                }
            }
            // SO_PASSCRED: store + accept. macOS has no equivalent (it would
            // ENOPROTOOPT through the host), and recvmsg synthesizes the
            // SCM_CREDENTIALS ancillary message from LOCAL_PEERCRED when it's
            // set, so handle it entirely carrick-side. (audit M2)
            if level == LINUX_SOL_SOCKET && optname == crate::linux_abi::LINUX_SO_PASSCRED {
                let on = optlen >= 4
                    && memory.read_bytes(optval_addr, 4).is_ok_and(|b| {
                        i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) != 0
                    });
                if let Some(open_file) = this.open_file(fd)
                    && let OpenDescription::HostSocket { base, .. } =
                        &mut *open_file.description.write()
                {
                    base.set_so_passcred(on);
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // SOL_UDPLITE (136): the checksum-coverage options on a UDPLITE
            // socket we back with plain UDP. macOS has neither the level nor the
            // options; accept UDPLITE_SEND_CSCOV(10)/RECV_CSCOV(11) as no-ops so
            // the Linux guest's UDPLITE tests proceed (partial-checksum BEHAVIOR
            // isn't emulated — macOS can't — but the option calls must succeed).
            if level == 136 {
                let _ = (optname, optval_addr, optlen);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // SO_RCVTIMEO/SO_SNDTIMEO: the host fd is ALWAYS O_NONBLOCK (the
            // blocking_io invariant), so a host-side timeval is dead. Store the
            // timeout per open-file-description and let blocking_io thread it
            // into the WaitOnFds. Intercept BEFORE the host passthrough.
            if level == LINUX_SOL_SOCKET
                && (optname == LINUX_SO_RCVTIMEO || optname == LINUX_SO_SNDTIMEO)
            {
                // aarch64 SO_RCVTIMEO/SO_SNDTIMEO use `struct __kernel_old_timeval`
                // = two i64 (tv_sec, tv_usec) = 16 bytes.
                let dur = if optval_addr == 0 || optlen < 16 {
                    None
                } else {
                    match memory.read_bytes(optval_addr, 16) {
                        Ok(b) => {
                            let sec = i64::from_ne_bytes([
                                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                            ]);
                            let usec = i64::from_ne_bytes([
                                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
                            ]);
                            // {0,0} disables the timeout (block forever).
                            if sec <= 0 && usec <= 0 {
                                None
                            } else {
                                Some(std::time::Duration::new(
                                    sec.max(0) as u64,
                                    (usec.max(0) as u32).saturating_mul(1000),
                                ))
                            }
                        }
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                    }
                };
                if let Some(open_file) = this.open_file(fd) {
                    let mut open = open_file.description.write();
                    if let OpenDescription::HostSocket { base, .. } = &mut *open {
                        if optname == LINUX_SO_RCVTIMEO {
                            base.set_recv_timeout(dur);
                        } else {
                            base.set_send_timeout(dur);
                        }
                    }
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // macOS BSD SO_REUSEADDR does NOT let two UDP sockets share a
            // wildcard addr/port the way Linux does — that needs SO_REUSEPORT on
            // macOS. libuv's UV_UDP_REUSEADDR sets ONLY SO_REUSEADDR (before
            // bind) and expects two 0.0.0.0:PORT UDP binds to both succeed
            // (udp_bind_reuseaddr, watcher_cross_stop). Widen REUSEADDR ->
            // REUSEPORT for datagram sockets so the macOS kernel matches Linux;
            // the existing passthrough below still sets host SO_REUSEADDR so a
            // later getsockopt reports the value the guest set.
            if level == LINUX_SOL_SOCKET
                && optname == LINUX_SO_REUSEADDR
                && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
            {
                let enable = optlen >= 4
                    && memory
                        .read_bytes(optval_addr, 4)
                        .ok()
                        .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) != 0)
                        .unwrap_or(false);
                if enable {
                    let one: i32 = 1;
                    unsafe {
                        libc::setsockopt(
                            host_fd.get(),
                            libc::SOL_SOCKET,
                            libc::SO_REUSEPORT,
                            &one as *const i32 as *const libc::c_void,
                            std::mem::size_of::<i32>() as u32,
                        );
                    }
                }
            }
            // Multicast GROUP MEMBERSHIP (join/leave, incl. source-specific) needs
            // a multicast-capable route + SSM that carrick can't reliably provide
            // on macOS, and the host test interface usually can't deliver it.
            // Report ENODEV ("no such device") — libuv maps it to UV_ENODEV and
            // the multicast tests RETURN_SKIP("No multicast support"), the honest
            // outcome for an unsupported feature. The non-membership knobs
            // (IP_MULTICAST_IF/TTL/LOOP) still pass through.
            {
                use crate::linux_abi as a;
                const IP_ADD_SOURCE_MEMBERSHIP: i32 = 39;
                const IP_DROP_SOURCE_MEMBERSHIP: i32 = 40;
                let ip_membership = level == a::LINUX_SOL_IP
                    && (optname == a::LINUX_IP_ADD_MEMBERSHIP
                        || optname == a::LINUX_IP_DROP_MEMBERSHIP
                        || optname == IP_ADD_SOURCE_MEMBERSHIP
                        || optname == IP_DROP_SOURCE_MEMBERSHIP);
                let ipv6_membership = level == a::LINUX_SOL_IPV6
                    && (optname == a::LINUX_IPV6_JOIN_GROUP
                        || optname == a::LINUX_IPV6_LEAVE_GROUP);
                if ip_membership || ipv6_membership {
                    return Ok(DispatchOutcome::errno(a::LINUX_ENODEV));
                }
                // Protocol-independent multicast source-filter API
                // (MCAST_JOIN_GROUP=42 .. MCAST_LEAVE_SOURCE_GROUP=47, RFC 3678).
                // The LTP networking framework sets MCAST_JOIN_GROUP during setup;
                // real Linux returns 0 (verified against the arm64 Docker oracle on
                // both TCP and UDP). macOS has no MCAST_* optnames, so
                // accept-and-ignore (no-op success) instead of the ENOPROTOOPT that
                // TBROK'd accept02/connect02 et al.
                let mcast_family = (level == a::LINUX_SOL_IP
                    || level == a::LINUX_SOL_IPV6)
                    && (42..=47).contains(&optname);
                if mcast_family {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
            }
            let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
                Some(t) => t,
                None => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOPROTOOPT));
                }
            };
            let bytes = if optval_addr == 0 || optlen == 0 {
                Vec::new()
            } else {
                match memory.read_bytes(optval_addr, optlen as usize) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            };
            let rc = unsafe {
                libc::setsockopt(
                    host_fd.get(),
                    host_level,
                    host_opt,
                    if bytes.is_empty() {
                        std::ptr::null()
                    } else {
                        bytes.as_ptr() as *const _
                    },
                    bytes.len() as u32,
                )
            };
            Ok(if let Err(errno) = rc.host_syscall_errno() {
                // Linux apps frequently set options that aren't supported on
                // macOS (eg IP_MTU_DISCOVER); swallow ENOPROTOOPT silently
                // when the equivalent option simply doesn't exist on macOS.
                DispatchOutcome::errno(errno)
            } else {
                DispatchOutcome::Returned { value: 0 }
            })

        }

        fn getsockopt(this, cx, fd: Fd, level: u64, optname: u64, optval: GuestPtr, optlen: GuestPtr) {

            let memory = &mut *cx.memory;
            let fd = fd.0;
            let level = level as i32;
            let optname = optname as i32;
            let optval_addr = optval.0;
            let optlen_addr = optlen.0;
            // AF_NETLINK getsockopt: answer SO_TYPE with the GUEST-requested type
            // (SOCK_RAW or SOCK_DGRAM — a SOCK_DGRAM netlink socket must not be
            // mislabeled SOCK_RAW); everything else returns 0. (audit M6)
            if this.fd_is_netlink(fd) {
                let val: i32 = if level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE {
                    this.socket_guest_type(fd).unwrap_or(LINUX_SOCK_RAW)
                } else {
                    0
                };
                let _ = memory.write_bytes(optval_addr, &val.to_ne_bytes());
                let _ = memory.write_bytes(optlen_addr, &4u32.to_ne_bytes());
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // LTP getsockopt01: closed fd -> EBADF, non-socket fd -> ENOTSOCK,
            // before the carrick-side SO_TYPE/SO_DOMAIN answers. (netlink above.)
            match this.open_file(fd) {
                None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                Some(of) => {
                    if !matches!(&*of.description.read(), OpenDescription::HostSocket { .. }) {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTSOCK));
                    }
                }
            }
            // SO_TYPE must report the GUEST-requested type, not the host backing:
            // a guest AF_UNIX SOCK_SEQPACKET is backed by a host SOCK_STREAM, but
            // Go derives the network ("unixpacket") from SO_TYPE, so the host's
            // STREAM answer would mislabel the socket.
            if level == LINUX_SOL_SOCKET && optname == LINUX_SO_TYPE
                && let Some(t) = this.socket_guest_type(fd) {
                    let _ = memory.write_bytes(optval_addr, &t.to_ne_bytes());
                    let _ = memory.write_bytes(optlen_addr, &4u32.to_ne_bytes());
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
            // SO_DOMAIN / SO_PROTOCOL are Linux-only getsockopt options with no
            // macOS equivalent (the generic host path would ENOPROTOOPT). Answer
            // from carrick's per-fd bookkeeping. CPython's
            // `socket.socket(fileno=fd)` queries SO_PROTOCOL to reconstruct an
            // inherited socket (the multiprocessing forkserver path); without
            // this it raised OSError(ENOPROTOOPT) and the forkserver child died.
            // SO_DOMAIN → the guest address family (stored as the Linux value at
            // socket() time). SO_PROTOCOL → 0 (the default/unspecified protocol,
            // exactly what Linux reports for AF_UNIX and a default AF_INET TCP/UDP
            // socket, which is what the forkserver reconstruct expects).
            if level == LINUX_SOL_SOCKET
                && (optname == crate::linux_abi::LINUX_SO_DOMAIN
                    || optname == crate::linux_abi::LINUX_SO_PROTOCOL)
            {
                let (_host_fd, family) = this.host_socket_lookup(fd)?;
                let val: i32 = if optname == crate::linux_abi::LINUX_SO_DOMAIN {
                    family
                } else {
                    0
                };
                // Honor the guest's optlen (it offers 4; clamp defensively).
                return write_sockopt_value(memory, optval_addr, optlen_addr, &val.to_ne_bytes());
            }
            // SO_REUSEPORT / SO_RCVBUF / SO_SNDBUF: report the GUEST-intended
            // value, not carrick's host-side widening. REUSEPORT defaults to 0
            // unless the guest set it (so a SO_REUSEADDR→REUSEPORT widening on a
            // UDP socket is invisible here); RCVBUF/SNDBUF report Linux's doubled
            // (2×) value of what was set, or the default when never set.
            // (audit M4, M5)
            if level == LINUX_SOL_SOCKET
                && (optname == LINUX_SO_REUSEPORT
                    || optname == LINUX_SO_RCVBUF
                    || optname == LINUX_SO_SNDBUF
                    || optname == crate::linux_abi::LINUX_SO_PASSCRED)
            {
                const LINUX_DEFAULT_SOCKBUF: i32 = 212_992;
                let Some(open_file) = this.open_file(fd) else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                let val: i32 = {
                    let open = open_file.description.read();
                    if let OpenDescription::HostSocket { base, .. } = &*open {
                        if optname == LINUX_SO_REUSEPORT {
                            i32::from(base.so_reuseport())
                        } else if optname == crate::linux_abi::LINUX_SO_PASSCRED {
                            i32::from(base.so_passcred())
                        } else if optname == LINUX_SO_RCVBUF {
                            base.so_rcvbuf()
                                .map_or(LINUX_DEFAULT_SOCKBUF, |v| v.saturating_mul(2))
                        } else {
                            base.so_sndbuf()
                                .map_or(LINUX_DEFAULT_SOCKBUF, |v| v.saturating_mul(2))
                        }
                    } else {
                        0
                    }
                };
                return write_sockopt_value(memory, optval_addr, optlen_addr, &val.to_ne_bytes());
            }
            // SO_RCVTIMEO/SO_SNDTIMEO readback: the set side stores these per
            // open-file-description and bypasses the (dead) host fd, so the
            // generic path below would read back {0,0}. Answer from the stored
            // Option<Duration> as a 16-byte two-i64 timeval. If the fd is not a
            // HostSocket, fall through to the generic path.
            if level == LINUX_SOL_SOCKET
                && (optname == LINUX_SO_RCVTIMEO || optname == LINUX_SO_SNDTIMEO)
            {
                let mut handled = false;
                let mut dur: Option<std::time::Duration> = None;
                if let Some(open_file) = this.open_file(fd)
                    && let OpenDescription::HostSocket { base, .. } = &*open_file.description.read() {
                        handled = true;
                        dur = if optname == LINUX_SO_RCVTIMEO {
                            base.recv_timeout()
                        } else {
                            base.send_timeout()
                        };
                    }
                if handled {
                    let tv_sec = dur.map(|d| d.as_secs() as i64).unwrap_or(0);
                    let tv_usec = dur.map(|d| d.subsec_micros() as i64).unwrap_or(0);
                    let mut tv_bytes = [0u8; 16];
                    tv_bytes[0..8].copy_from_slice(&tv_sec.to_ne_bytes());
                    tv_bytes[8..16].copy_from_slice(&tv_usec.to_ne_bytes());
                    return write_sockopt_value(memory, optval_addr, optlen_addr, &tv_bytes);
                }
            }
            // SO_PEERCRED: Linux returns `struct ucred { pid, uid, gid }`. macOS
            // has no single equivalent, so synthesize it from LOCAL_PEERCRED
            // (peer uid + primary gid via `xucred`) and LOCAL_PEERPID (peer pid).
            // Used by D-Bus / systemd peer authentication over AF_UNIX. Done here
            // because `linux_to_host_sockopt` has no Darwin opt to map it to.
            if level == LINUX_SOL_SOCKET && optname == crate::linux_abi::LINUX_SO_PEERCRED {
                let (host_fd, _family) = this.host_socket_lookup(fd)?;
                // Best-effort peer creds, resolved per host (Linux: SO_PEERCRED
                // -> ucred; Darwin: LOCAL_PEERCRED + LOCAL_PEERPID). Returns 0s
                // if the socket isn't connected, matching the guest's tolerance.
                let (pid, uid, gid) = carrick_portable::peer_ucred(host_fd.get());
                let mut ucred = [0u8; crate::linux_abi::LINUX_UCRED_SIZE];
                ucred[0..4].copy_from_slice(&pid.to_ne_bytes());
                ucred[4..8].copy_from_slice(&uid.to_ne_bytes());
                ucred[8..12].copy_from_slice(&gid.to_ne_bytes());
                // Honor the guest's optlen: write at most what it offered and
                // report the bytes actually written (Linux clamps to the buffer).
                return write_sockopt_value(memory, optval_addr, optlen_addr, &ucred);
            }
            let (host_fd, _family) = this.host_socket_lookup(fd)?;
            // SO_ERROR: the option VALUE is itself an errno (the pending socket
            // error, e.g. from an async connect). The host returns a Darwin
            // errno; the guest reads it as a Linux errno. Without translation a
            // refused connect surfaces as Darwin ECONNREFUSED=61, which Linux
            // reads as ENODATA — so asyncio's sock_connect never raises
            // ConnectionRefusedError. Translate the i32 value through the same
            // table the rest of the ABI uses. (getsockopt itself still
            // succeeds; only the value is mapped.)
            if level == LINUX_SOL_SOCKET && optname == LINUX_SO_ERROR {
                let mut host_err: i32 = 0;
                let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
                let rc = unsafe {
                    libc::getsockopt(
                        host_fd.get(),
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        (&mut host_err as *mut i32).cast(),
                        &mut len,
                    )
                };
                if let Err(errno) = rc.host_syscall_errno() {
                    return Ok(DispatchOutcome::errno(errno));
                }
                // 0 = "no pending error" (not an errno); non-zero is a HOST
                // errno translated to the Linux value and written RAW into the
                // guest's int optval — a wire boundary, hence `.get()`.
                let linux_err: i32 = if host_err == 0 {
                    0
                } else {
                    crate::host_to_linux_errno(host_err).get()
                };
                // Honor the guest's optlen (it may pass <4); clamp like Linux.
                return write_sockopt_value(
                    memory,
                    optval_addr,
                    optlen_addr,
                    &linux_err.to_ne_bytes(),
                );
            }
            let (host_level, host_opt) = match linux_to_host_sockopt(level, optname) {
                Some(t) => t,
                None => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOPROTOOPT));
                }
            };
            // Read the guest's reported optlen so we don't overflow.
            let optlen_bytes = match memory.read_bytes(optlen_addr, 4) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            };
            let mut optlen = u32::from_ne_bytes([
                optlen_bytes[0],
                optlen_bytes[1],
                optlen_bytes[2],
                optlen_bytes[3],
            ]);
            let cap = optlen.min(256) as usize;
            let mut buf = vec![0u8; cap];
            let rc = unsafe {
                libc::getsockopt(
                    host_fd.get(),
                    host_level,
                    host_opt,
                    buf.as_mut_ptr() as *mut _,
                    &mut optlen as *mut _,
                )
            };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            let used = (optlen as usize).min(buf.len());
            if optval_addr != 0 && used > 0 && memory.write_bytes(optval_addr, &buf[..used]).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            if memory
                .write_bytes(optlen_addr, &optlen.to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn shutdown(this, cx, fd: Fd, how: u64) {

            let fd: Fd = fd;
            let how = how as i32;
            let (host_fd, _family) = this.host_socket_lookup(fd.0)?;
            let rc = unsafe { libc::shutdown(host_fd.get(), how) };
            Ok(if let Err(errno) = rc.host_syscall_errno() {
                DispatchOutcome::errno(errno)
            } else {
                DispatchOutcome::Returned { value: 0 }
            })

        }

        fn sendmsg(this, cx, fd: Fd, msg: GuestPtr, flags: u64) {
            this.sendmsg_inner(fd.0, msg.0, flags as i32, &*cx.memory)
        }

        fn recvmsg(this, cx, fd: Fd, msg: GuestPtr, flags: u64) {
            this.recvmsg_inner(fd.0, msg.0, flags as i32, &mut *cx.memory)
        }

        fn sys_recvmmsg(this, cx, fd: Fd, mmsg: GuestPtr, vlen: u64, flags: u64, timeout: GuestPtr) {

            Ok(this.recvmmsg(fd, mmsg, vlen, flags, timeout, cx.memory))

        }

        fn sys_sendmmsg(this, cx, fd: Fd, mmsg: GuestPtr, vlen: u64, flags: u64) {

            Ok(this.sendmmsg(fd, mmsg, vlen, flags, cx.memory))

        }

    }
}

impl SyscallDispatcher {
    fn sendmsg_inner(
        &self,
        fd: i32,
        msg_addr: u64,
        flags: i32,
        memory: &impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let is_netlink = self.fd_is_netlink(fd);
        let (host_fd, family) = if is_netlink {
            (HostFd(-1), LINUX_AF_NETLINK)
        } else {
            self.host_socket_lookup(fd)?
        };
        let msg = read_linux_msghdr(memory, msg_addr)?;
        let iovecs = read_iovecs(memory, msg.iov, msg.iovlen as usize)?;
        // Pack iovecs into a single contiguous send. Simple and avoids
        // having to keep guest pointers alive across the FFI call.
        let mut data = Vec::new();
        for iov in iovecs {
            // An empty iovec contributes nothing — and its base is allowed to be
            // NULL (libuv sends a zero-length datagram as uv_buf_init(NULL, 0)).
            // read_bytes(NULL, 0) would otherwise fault, so skip it.
            if iov.iov_len == 0 {
                continue;
            }
            let chunk = match memory.read_bytes(iov.iov_base, iov.iov_len as usize) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            };
            data.extend_from_slice(&chunk);
        }
        // AF_NETLINK: parse the assembled request and queue a synthetic
        // dump reply, ignoring the destination sockaddr (always the kernel).
        if is_netlink {
            return Ok(self.netlink_send(fd, &data));
        }
        let host_addr = if msg.name == 0 || msg.namelen == 0 {
            None
        } else {
            match read_linux_sockaddr(memory, msg.name, msg.namelen, family) {
                Ok(b) => Some(b),
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
        };
        // SCM_RIGHTS ancillary data (passing fds over AF_UNIX). Read the guest's
        // Linux-layout control buffer, extract the guest fds, map each to its
        // backing host fd, and build a host-layout control buffer for the real
        // sendmsg. This is the multiprocessing forkserver's fd-handoff path.
        let mut host_control: Vec<u8> = Vec::new();
        if msg.control != 0 && msg.controllen > 0 {
            let raw = memory.read_bytes(msg.control, msg.controllen as usize)?;
            let guest_fds = parse_linux_scm_rights_fds(&raw);
            if !guest_fds.is_empty() {
                let mut host_fds = Vec::with_capacity(guest_fds.len());
                for gfd in &guest_fds {
                    match self.host_fd_for_scm(*gfd) {
                        Some(h) => host_fds.push(h),
                        // A passed fd with no backing host fd can't cross the
                        // socket → EBADF, matching Linux's rejection of an
                        // invalid fd in an SCM_RIGHTS array.
                        None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                    }
                }
                host_control = build_host_scm_rights(&host_fds);
            }
            // IPv6 ancillary cmsgs set on send (IPV6_HOPLIMIT/TCLASS): translate
            // the guest's Linux cmsg types → macOS and append a host-layout
            // record so the kernel applies them (CPython testSetHopLimit /
            // testSetTrafficClassAndHopLimit). recvmsg translates them back.
            let ipv6 = parse_guest_ipv6_cmsgs(&raw);
            if !ipv6.is_empty() {
                host_control.extend_from_slice(&build_host_ipv6_cmsgs(&ipv6));
            }
        }
        let nonblocking = self.io_is_nonblocking(fd, flags);
        let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
        let send_to = self
            .open_file(fd)
            .and_then(|f| f.description.read().send_timeout());
        let outcome = self.blocking_io(host_fd.get(), IoDir::Write, nonblocking, send_to, || {
            // Use a real sendmsg so the host control buffer (SCM_RIGHTS) is
            // delivered. A single iovec over the assembled `data` is fine —
            // the byte stream is identical to the guest's scattered iovecs.
            let mut hiov = libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            let mut hmsg: libc::msghdr = unsafe { std::mem::zeroed() };
            if let Some(a) = &host_addr {
                hmsg.msg_name = a.as_ptr() as *mut libc::c_void;
                hmsg.msg_namelen = a.len() as libc::socklen_t;
            }
            hmsg.msg_iov = &mut hiov as *mut _;
            hmsg.msg_iovlen = 1;
            if !host_control.is_empty() {
                hmsg.msg_control = host_control.as_ptr() as *mut libc::c_void;
                hmsg.msg_controllen = host_control.len() as _;
            }
            let n = unsafe { libc::sendmsg(host_fd.get(), &hmsg as *const _, host_flags) };
            n.host_syscall_errno().map(|value| value as i64)
        });
        Ok(outcome)
    }

    fn recvmsg_inner(
        &self,
        fd: i32,
        msg_addr: u64,
        flags: i32,
        memory: &mut impl GuestMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let is_netlink = self.fd_is_netlink(fd);
        let (host_fd, family) = if is_netlink {
            (HostFd(-1), LINUX_AF_NETLINK)
        } else {
            self.host_socket_lookup(fd)?
        };
        let msg = read_linux_msghdr(memory, msg_addr)?;
        // Linux caps the iovec array at UIO_MAXIOV (1024); a larger msg_iovlen is
        // EMSGSIZE, not the EINVAL that read_iovecs' length guard would raise
        // (recvmsg01 "invalid iovec count").
        if msg.iovlen as usize > 1024 {
            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMSGSIZE));
        }
        let iovecs = read_iovecs(memory, msg.iov, msg.iovlen as usize)?;
        // AF_NETLINK: drain the queued dump reply into the iovecs, fill in
        // the source sockaddr_nl (kernel; pid=0), and zero controllen/flags.
        if is_netlink {
            let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
            let chunk = self.netlink_drain(fd, total);
            let n = chunk.len();
            let mut remaining = n;
            let mut cursor = 0usize;
            for iov in &iovecs {
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(iov.iov_len as usize);
                if take > 0 {
                    if memory
                        .write_bytes(iov.iov_base, &chunk[cursor..cursor + take])
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    cursor += take;
                    remaining -= take;
                }
            }
            if msg.name != 0 && msg.namelen != 0 {
                let nl = sockaddr_nl_bytes(0, 0);
                let write_len = (nl.len() as u32).min(msg.namelen);
                if write_len > 0
                    && memory
                        .write_bytes(msg.name, &nl[..write_len as usize])
                        .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                let _ = memory.write_bytes(
                    msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                    &(nl.len() as u32).to_ne_bytes(),
                );
            }
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64,
                &0u64.to_ne_bytes(),
            );
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, flags) as u64,
                &0i32.to_ne_bytes(),
            );
            return Ok(DispatchOutcome::Returned { value: n as i64 });
        }
        let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
        let nonblocking = self.io_is_nonblocking(fd, flags);
        let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
        let recv_to = self
            .open_file(fd)
            .and_then(|f| f.description.read().recv_timeout());
        let want_control = msg.control != 0 && msg.controllen > 0;
        // SCM_RIGHTS host fds received this call, ferried out of the I/O closure
        // (which may run on a retry) so they're installed/written-back exactly
        // once after a successful recvmsg. Same for the guest msg_flags.
        let received_host_fds = std::cell::RefCell::new(Vec::<i32>::new());
        // IPv6 RFC 3542 ancillary cmsgs (hop-limit/tclass/pktinfo) the host
        // returned, as (linux_cmsg_type, data) — forwarded to the guest below.
        let received_ipv6_cmsgs = std::cell::RefCell::new(Vec::<(i32, Vec<u8>)>::new());
        let guest_msg_flags = std::cell::Cell::new(0i32);
        let outcome = self.blocking_io(host_fd.get(), IoDir::Read, nonblocking, recv_to, || {
            // A retry must not leak fds from a prior partial attempt.
            for stale in received_host_fds.borrow_mut().drain(..) {
                unsafe { libc::close(stale) };
            }
            let mut buf = vec![0u8; total];
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            // A host control buffer sized to hold the guest's requested
            // controllen (SCM_RIGHTS fd array). CMSG_SPACE for that many fds is
            // >= the Linux size, so this never under-provisions.
            let mut hcontrol: Vec<u8> = if want_control {
                let max_fds = (msg.controllen as usize / 4).max(1);
                vec![0u8; unsafe { libc::CMSG_SPACE((max_fds * 4) as u32) } as usize]
            } else {
                Vec::new()
            };
            // Use the host recvmsg (not recvfrom) so the kernel can report
            // MSG_TRUNC/MSG_CTRUNC/MSG_EOR in the returned msg_flags. macOS/XNU
            // sets MSG_TRUNC on truncated atomic (PR_ATOMIC) records exactly
            // like Linux, so translating those flags back is a faithful match.
            let mut hiov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut _,
                iov_len: buf.len(),
            };
            let mut hmsg: libc::msghdr = unsafe { std::mem::zeroed() };
            if msg.name != 0 {
                hmsg.msg_name = sa.as_mut_ptr() as *mut _;
                hmsg.msg_namelen = sa.len() as libc::socklen_t;
            }
            hmsg.msg_iov = &mut hiov as *mut _;
            hmsg.msg_iovlen = 1; // c_int on macOS
            if !hcontrol.is_empty() {
                hmsg.msg_control = hcontrol.as_mut_ptr() as *mut libc::c_void;
                hmsg.msg_controllen = hcontrol.len() as _;
            }
            // host_flags carries MSG_DONTWAIT and this runs inside blocking_io
            // (host_fd is O_NONBLOCK; EAGAIN -> WaitOnFds with the dispatcher lock
            // released), so this recvmsg never blocks under the lock.
            let n = unsafe { libc::recvmsg(host_fd.get(), &mut hmsg as *mut _, host_flags) };
            let n = n.host_syscall_errno()?;
            // Stash any received fds (host-layout cmsg) for installation after
            // the closure returns; the guest-facing rewrite happens below.
            if want_control && hmsg.msg_controllen as usize > 0 {
                let got = parse_host_scm_rights_fds(&hcontrol, hmsg.msg_controllen as usize);
                *received_host_fds.borrow_mut() = got;
                *received_ipv6_cmsgs.borrow_mut() =
                    parse_host_ipv6_cmsgs(&hcontrol, hmsg.msg_controllen as usize);
            }
            // Scatter the received bytes back into the guest's iovecs.
            let mut remaining = n as usize;
            let mut cursor = 0usize;
            for iov in &iovecs {
                if remaining == 0 {
                    break;
                }
                let chunk = remaining.min(iov.iov_len as usize);
                if chunk > 0 {
                    if memory
                        .write_bytes(iov.iov_base, &buf[cursor..cursor + chunk])
                        .is_err()
                    {
                        return Err(LINUX_EFAULT);
                    }
                    cursor += chunk;
                    remaining -= chunk;
                }
            }
            if msg.name != 0 && msg.namelen != 0 {
                let used = (hmsg.msg_namelen as usize).min(sa.len());
                let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, true);
                let write_len = (linux_bytes.len() as u32).min(msg.namelen);
                if write_len > 0
                    && memory
                        .write_bytes(msg.name, &linux_bytes[..write_len as usize])
                        .is_err()
                {
                    return Err(LINUX_EFAULT);
                }
                // namelen lives at offset 8 (after the 8-byte name pointer).
                if memory
                    .write_bytes(
                        msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                        &(linux_bytes.len() as u32).to_ne_bytes(),
                    )
                    .is_err()
                {
                    return Err(LINUX_EFAULT);
                }
            }
            // Remember the host msg_flags; the guest controllen + final flags
            // (incl. a possible MSG_CTRUNC) are written after fd install below.
            guest_msg_flags.set(host_to_linux_msg_flags(hmsg.msg_flags));
            Ok(n as i64)
        });
        // Install any received fds as fresh guest fds, then write the guest
        // (Linux-layout) control buffer + the controllen/flags fields. Done
        // OUTSIDE the I/O closure so it happens exactly once on success.
        let host_fds: Vec<i32> = received_host_fds.borrow_mut().drain(..).collect();
        if matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
            // from_bits_retain: recvmsg IGNORES unknown msg_flags bits.
            let cloexec =
                LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::CMSG_CLOEXEC);
            let mut guest_fds = Vec::with_capacity(host_fds.len());
            for hfd in host_fds {
                match self.install_received_host_fd(hfd, cloexec) {
                    Some(gfd) => guest_fds.push(gfd),
                    None => unsafe {
                        libc::close(hfd);
                    },
                }
            }
            let mut linux_flags = guest_msg_flags.get();
            let mut written_controllen = 0u64;
            if want_control {
                let (mut scm, scm_trunc) =
                    build_linux_scm_rights(&guest_fds, msg.controllen as usize);
                // SO_PASSCRED: append an SCM_CREDENTIALS record with the peer's
                // ucred after any SCM_RIGHTS, bounded by the remaining control
                // budget. (audit M2)
                let mut cred_trunc = false;
                if !is_netlink && self.socket_so_passcred(fd) {
                    let (pid, uid, gid) = self.peer_ucred(host_fd.get());
                    let remaining = (msg.controllen as usize).saturating_sub(scm.len());
                    let (creds, t) = build_linux_scm_creds(pid, uid, gid, remaining);
                    scm.extend_from_slice(&creds);
                    cred_trunc = t;
                }
                // Append the translated IPv6 ancillary cmsgs after the SCM
                // records, honoring the guest's controllen (overflow → MSG_CTRUNC).
                let ipv6 = received_ipv6_cmsgs.borrow();
                let (ctrl, ipv6_trunc) =
                    build_linux_ipv6_cmsgs(&scm, &ipv6, msg.controllen as usize);
                if !ctrl.is_empty() && memory.write_bytes(msg.control, &ctrl).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                written_controllen = ctrl.len() as u64;
                if scm_trunc || ipv6_trunc || cred_trunc {
                    linux_flags |= crate::linux_abi::LINUX_MSG_CTRUNC;
                }
            }
            // controllen at offset 40, flags at offset 48 in LinuxMsghdr.
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64,
                &written_controllen.to_ne_bytes(),
            );
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, flags) as u64,
                &linux_flags.to_ne_bytes(),
            );
        } else {
            // Error/would-block: nothing received, so close any stray fds and
            // leave the guest msghdr's controllen/flags zeroed.
            for hfd in host_fds {
                unsafe { libc::close(hfd) };
            }
        }
        Ok(outcome)
    }
}
