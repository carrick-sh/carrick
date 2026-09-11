//! Socket lifecycle, connection, and address management syscall handlers
//! (`socket`, `socketpair`, `bind`, `listen`, `accept`, `accept4`, `connect`,
//! `getsockname`, `getpeername`, `shutdown`).
//!
//! Owns socket creation, descriptor installation, address resolution and
//! rewriting (e.g. INADDR_ANY connect loopback redirection), connection state
//! transitions, SCM rights registration, error state caching, and synthetic
//! responses (ICMP echo, DNS gateway replies).

use std::sync::Arc;

use carrick_abi::{
    LINUX_AF_INET, LINUX_AF_INET6, LINUX_AF_PACKET, LINUX_AF_UNIX, LINUX_EBADF, LINUX_EINVAL,
    LINUX_ENOTCONN, LINUX_ENOTSOCK, LINUX_SOCK_DGRAM, LINUX_SOCK_RAW, LINUX_SOCK_STREAM,
    LinuxErrno, LinuxSocketTypeFlags,
};
use parking_lot::RwLock;

use super::support::*;
use super::*;
use crate::dispatch::net::{recverr, reuseport, scm_rights};
use crate::dispatch::{
    CurrentMmMemory, DispatchOutcome, Fd, GuestPtr, HostFd, OpenDescription, OpenFile, SyscallCtx,
};
use carrick_spec::PortProtocol;

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

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

fn guest_unix_pathname(memory: &impl CurrentMmMemory, addr: u64, addrlen: u32) -> Option<String> {
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

#[cfg(not(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd",
    target_os = "linux"
)))]
fn host_stream_socket_read_eof(host_fd: i32) -> bool {
    let mut byte = [0u8; 1];
    let rc = unsafe {
        // BLOCKING-IO-OK: MSG_DONTWAIT is passed
        libc::recv(
            host_fd,
            byte.as_mut_ptr().cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    rc == 0
}

#[cfg(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(in crate::dispatch) fn host_stream_socket_rdhup(host_fd: i32) -> bool {
    use carrick_host_bsd::Kqueue;
    use carrick_host_bsd::kqueue::Kevent;

    let Some(kq) = Kqueue::new_internal() else {
        return false;
    };
    let add = Kevent::read(
        host_fd,
        carrick_portable::EV_ADD | carrick_portable::EV_ENABLE | carrick_portable::EV_CLEAR,
    );
    if kq.apply(&[add]).is_err() {
        return false;
    }
    let mut out = [Kevent::empty(); 1];
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    matches!(
        kq.wait(&[], &mut out, Some(&zero)),
        Ok(n) if n >= 1
            && out[0].filter() == libc::EVFILT_READ
            && out[0].flags() & libc::EV_EOF != 0
    )
}

#[cfg(target_os = "linux")]
pub(in crate::dispatch) fn host_stream_socket_rdhup(host_fd: i32) -> bool {
    let mut pfd = libc::pollfd {
        fd: host_fd,
        events: libc::POLLRDHUP,
        revents: 0,
    };
    unsafe { libc::poll(&mut pfd, 1, 0) > 0 && pfd.revents & libc::POLLRDHUP != 0 }
}

#[cfg(not(any(
    feature = "platform-macos",
    feature = "platform-freebsd",
    feature = "platform-netbsd",
    target_os = "linux"
)))]
pub(in crate::dispatch) fn host_stream_socket_rdhup(host_fd: i32) -> bool {
    host_stream_socket_read_eof(host_fd)
}

pub(in crate::dispatch) fn host_stream_socket_is_connected(host_fd: i32) -> bool {
    if host_fd < 0 {
        return false;
    }
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len: libc::socklen_t = std::mem::size_of_val(&storage) as libc::socklen_t;
    let rc = unsafe {
        libc::getpeername(
            host_fd,
            &mut storage as *mut _ as *mut libc::sockaddr,
            &mut len,
        )
    };
    rc == 0
}

#[cfg(test)]
mod host_stream_socket_read_eof_tests {
    use super::host_stream_socket_rdhup;

    #[test]
    fn detects_peer_half_close_while_payload_remains_buffered() {
        let mut sockets = [-1; 2];
        // SAFETY: socketpair initializes both descriptors on success; every
        // descriptor is closed before returning from the test.
        unsafe {
            assert_eq!(
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()),
                0
            );
            assert_eq!(libc::write(sockets[0], b"payload".as_ptr().cast(), 7), 7);
            assert_eq!(libc::shutdown(sockets[0], libc::SHUT_WR), 0);

            assert!(
                host_stream_socket_rdhup(sockets[1]),
                "RDHUP must be visible before the queued payload is drained"
            );

            libc::close(sockets[0]);
            libc::close(sockets[1]);
        }
    }
}

fn decode_accept4_flags(flags: i32) -> Option<LinuxSocketTypeFlags> {
    LinuxSocketTypeFlags::from_bits(flags)
}

#[cfg(test)]
mod accept4_flag_tests {
    use super::*;

    #[test]
    fn rejects_unknown_flags_before_accept_side_effects() {
        assert_eq!(decode_accept4_flags(0), Some(LinuxSocketTypeFlags::empty()));
        assert_eq!(
            decode_accept4_flags(LinuxSocketTypeFlags::NONBLOCK.bits()),
            Some(LinuxSocketTypeFlags::NONBLOCK)
        );
        assert_eq!(
            decode_accept4_flags(LinuxSocketTypeFlags::CLOEXEC.bits()),
            Some(LinuxSocketTypeFlags::CLOEXEC)
        );
        assert_eq!(decode_accept4_flags(0x1234_5678), None);
        assert_eq!(decode_accept4_flags(-1), None);
    }

    #[test]
    fn detects_connected_stream_without_consuming_data() {
        let mut connected = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, connected.as_mut_ptr())
            },
            0
        );
        assert!(host_socket_is_connected(connected[0]));
        unsafe {
            libc::close(connected[0]);
            libc::close(connected[1]);
        }

        let unconnected = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(unconnected >= 0);
        assert!(!host_socket_is_connected(unconnected));
        unsafe { libc::close(unconnected) };
    }
}
impl<'a> NetView<'a> {
    pub(in crate::dispatch) fn host_socket_install(
        &self,
        family: i32,
        type_: i32,
        protocol: i32,
    ) -> DispatchOutcome {
        // Strip the Linux-only SOCK_NONBLOCK / SOCK_CLOEXEC bits before
        // we hand the type to macOS, then set them on the resulting fd
        // by hand.
        let socket_flags = LinuxSocketTypeFlags::from_bits_retain(type_);
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
        // Reject Linux-invalid (family,type,protocol) tuples with the canonical
        // errno before macOS gets a chance to report a divergent one. (socket01)
        if let Some(errno) = canonical_socket_errno(family, base_type, protocol) {
            return DispatchOutcome::errno(errno);
        }
        let host_family = match linux_to_host_af(family) {
            Ok(f) => f,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let host_type = host_socktype_backing(family, base_type);
        // macOS has no UDPLITE protocol, so back IPPROTO_UDPLITE with a plain UDP
        // socket (proto 0 → UDP for SOCK_DGRAM). UDPLITE's datagram send/recv is
        // UDP-identical; only the checksum-coverage sockopts differ, accepted as
        // no-ops below. The guest is LINUX python, whose test_socket runs the
        // whole UDPLITE suite (native-macOS python skips it — IPPROTO_UDPLITE
        // undefined there); pass-through socket() returned EPROTONOSUPPORT and
        // ERRORed every UDPLITE test at setUp.
        // macOS has no SCTP either. A guest SCTP SOCK_STREAM is a reliable,
        // ordered byte stream to ONE peer, which is what a TCP socket already
        // provides — the same substitution UDPLITE gets below, and the same shape
        // as backing a guest AF_UNIX SEQPACKET with a host SOCK_STREAM. The guest
        // protocol is recorded unchanged in the OpenDescription, so `SO_PROTOCOL`
        // still reports SCTP.
        //
        // Deliberately NOT extended to SOCK_SEQPACKET: that is message-oriented
        // and multi-streamed, and TCP cannot reconstruct its boundaries. It stays
        // EPROTONOSUPPORT rather than pretending.
        let host_protocol = if protocol == LINUX_IPPROTO_SCTP && base_type == LINUX_SOCK_STREAM
            || protocol == LINUX_IPPROTO_UDPLITE
            || cfg!(carrick_bsd)
                && matches!(family, LINUX_AF_INET | LINUX_AF_INET6)
                && base_type == LINUX_SOCK_RAW
        {
            0
        } else {
            protocol
        };
        let host_fd = match (unsafe { libc::socket(host_family, host_type, host_protocol) })
            .host_syscall_errno()
        {
            Ok(value) => value,
            // FreeBSD has no Linux-style datagram ICMP ping socket. Keep a real
            // nonblocking UDP fd as the poll/close carrier; loopback echo
            // request/reply semantics are synthesized at sendto/recvfrom below.
            Err(errno)
                if errno == linux_errno::EPROTONOSUPPORT
                    && family == LINUX_AF_INET
                    && base_type == LINUX_SOCK_DGRAM
                    && protocol == LINUX_IPPROTO_ICMP =>
            {
                match (unsafe { libc::socket(host_family, host_type, 0) }).host_syscall_errno() {
                    Ok(value) => value,
                    Err(errno) => return DispatchOutcome::errno(errno),
                }
            }
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        // The host fd is always nonblocking; Carrick preserves the guest's
        // blocking mode in Linux-visible status_flags and waits outside the
        // dispatcher lock when a blocking operation would block.
        set_host_nonblocking(host_fd);
        // Give stream sockets a Linux-sized host backing buffer so guest
        // non-blocking copy/splice loops do not churn on macOS' small defaults.
        if let Err(errno) = widen_stream_socket_buffers(host_fd, family, base_type) {
            unsafe { libc::close(host_fd) };
            return DispatchOutcome::errno(errno);
        }
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostSocket {
                host_fd: HostFdRef::new(host_fd),
                family,
                type_: base_type,
                protocol,
                base: OpenDescriptionBase::new(status_flags),
                mcast_memberships: Vec::new(),
                synthetic_recv: std::collections::VecDeque::new(),
            })),
            status_flags,
            fd_flags,
        );
        let linux_fd = match self.install_fd_at_or_above(3, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        DispatchOutcome::returned_i32(linux_fd)
    }

    /// Add GUEST fd `guest_fd` to an `SCM_RIGHTS` send. A host-backed
    /// description (pipe/socket/file) travels as its real host fd, which also
    /// reaches a non-guest peer on the host side of a bind-mounted socket.
    /// Everything carrick owns itself — guest pipes, eventfds, memfds, … — is
    /// parked in the carrier's rights vault and travels as a placeholder the
    /// receiving guest resolves back to the SAME description, exactly the
    /// dup semantics Linux gives a passed fd (see [`scm_rights`]). Only a
    /// closed/invalid guest fd is EBADF, as on Linux.
    /// Queue guest fd `guest_fd` for an `SCM_RIGHTS` send. Every guest fd
    /// crosses as its `FileDescription` (see [`scm_rights`]): the receiver
    /// installs the SAME description, exactly like `dup`, so status flags,
    /// the file offset, the path and writability all travel with it — a
    /// host-backed file re-wrapped from its raw host fd would arrive as a
    /// read-only stranger (`F_GETFL` 0, `mmap(PROT_WRITE, MAP_SHARED)`
    /// EACCES, the forkserver `Arena` failure). Bare stdio (no table entry)
    /// is materialized first, as `dup` does.
    pub(in crate::dispatch::net) fn add_scm_right(
        &self,
        rights: &mut scm_rights::InFlightRights,
        guest_fd: i32,
    ) -> Result<(), LinuxErrno> {
        let description = match self.open_file(guest_fd) {
            Some(open_file) => {
                if matches!(
                    open_file.description.read().as_deref(),
                    Some(OpenDescription::Closed { .. }) | None
                ) {
                    return Err(LINUX_EBADF);
                }
                open_file.description()
            }
            None if is_stdio_fd(guest_fd) && !self.stdio_is_closed(guest_fd) => {
                self.bare_stdio_description(guest_fd)?
            }
            None => return Err(LINUX_EBADF),
        };
        if !rights.push_parked(description) {
            return Err(crate::linux_abi::LINUX_EMFILE);
        }
        Ok(())
    }

    /// Install a HOST fd received via `SCM_RIGHTS` as a fresh GUEST fd, wrapping
    /// it in the right `OpenDescription` by `fstat`ing its type (socket → host
    /// socket, fifo → host pipe, else a host file). The received host fd is
    /// already a live kernel fd the macOS kernel handed us; we keep its blocking
    /// mode non-blocking to satisfy the dispatcher's wait invariants. Returns
    /// the new guest fd, or `None` on failure (the caller closes the host fd).
    pub(super) fn install_received_host_fd(&self, host_fd: i32, cloexec: bool) -> Option<i32> {
        set_host_nonblocking(host_fd);
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let kind = if unsafe { libc::fstat(host_fd, &mut st) } == 0 {
            st.st_mode & libc::S_IFMT
        } else {
            0
        };
        // MSG_CMSG_CLOEXEC: install the received fd close-on-exec. (audit M3)
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        // A placeholder for a description parked by the sending guest (the
        // way every guest fd crosses): install THAT description (shared, like
        // dup) and drop the placeholder — the guest never sees the pipe. What
        // follows only wraps fds a non-guest host peer sent.
        if kind == libc::S_IFIFO
            && let Some(description) = scm_rights::claim(scm_rights::PlaceholderKey::from_stat(&st))
        {
            unsafe {
                libc::close(host_fd);
            }
            let installed = self
                .install_fd_at_or_above(3, OpenFile::new(Arc::clone(&description), fd_flags))
                .ok();
            // The install took its own reference; the vault's is done.
            description.release_fd_ref();
            return installed;
        }
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
            let is_stream = so_type == LINUX_SOCK_STREAM || so_type == LINUX_SOCK_SEQPACKET;
            let mut base = OpenDescriptionBase::new(LINUX_O_RDWR);
            if is_stream && host_stream_socket_is_connected(host_fd) {
                base.set_connected(true);
            }
            OpenDescription::HostSocket {
                host_fd: HostFdRef::new(host_fd),
                family: libc::AF_UNIX,
                type_: so_type,
                protocol: 0,
                base,
                mcast_memberships: Vec::new(),
                synthetic_recv: std::collections::VecDeque::new(),
            }
        } else if kind == libc::S_IFIFO {
            // A pipe end. Probe its direction so reads/writes route correctly;
            // a pipe read end rejects writes and vice versa. F_GETFL's access
            // mode is unreliable for pipe ends, so treat it as bidirectional-
            // safe: mark it not-a-read-end unless a write probe fails. The
            // forkserver passes both ends; CPython only uses each in one
            // direction, so a conservative bidirectional flag is safe.
            OpenDescription::HostPipe {
                host_fd: HostFdRef::new(host_fd),
                is_read_end: false,
                // A pipe end received over SCM_RIGHTS: its host inode (already
                // fstat'd above) is the same kernel-object identity in this
                // process, so it serves as a stable FASYNC join key.
                pipe_id: st.st_ino as u64,
                pty: None,
                bidirectional: true,
                write_kind: HostWriteKind::PipeLike,
                base: OpenDescriptionBase::new(0),
                stdio_stream: None,
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
                host_fd: HostFdRef::new(host_fd),
                metadata,
                writable: true,
                base: OpenDescriptionBase::new(0),
            }
        };
        // On an install failure (EMFILE) the dropped OpenFile's description —
        // the fd's ONE owner — closes the received host fd; the caller must
        // not close it again.
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(description)),
            0,
            fd_flags,
        );
        self.install_fd_at_or_above(3, open_file).ok()
    }

    pub(in crate::dispatch) fn host_socket_lookup(
        &self,
        fd: i32,
    ) -> Result<(HostFd, i32), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let open = open_file.description.read().ok_or(LINUX_ENOTSOCK)?;
        match &*open {
            OpenDescription::HostSocket {
                host_fd, family, ..
            } => Ok((host_fd.view(), *family)),
            _ => Err(LINUX_ENOTSOCK),
        }
    }

    /// Read the per-description `connect_in_progress` flag for `fd` (false if the
    /// fd is missing or not a HostSocket). See `OpenDescriptionBase.connect_in_progress`.
    fn socket_connect_in_progress(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(of.description.read().as_deref(), Some(OpenDescription::HostSocket { base, .. }) if base.connect_in_progress())
        })
    }

    /// Update the per-description `connect_in_progress` and/or `connected` flags for `fd`.
    fn update_socket_connection_state(
        &self,
        fd: i32,
        connect_in_progress: Option<bool>,
        connected: Option<bool>,
    ) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
        {
            if let Some(on) = connect_in_progress {
                base.set_connect_in_progress(on);
            }
            if let Some(on) = connected {
                base.set_connected(on);
            }
        }
    }

    fn set_socket_pending_error(&self, fd: i32, errno: carrick_abi::LinuxErrno) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
        {
            base.set_pending_socket_error(errno.get());
        }
    }

    pub(super) fn take_socket_pending_error(&self, fd: i32) -> Option<carrick_abi::LinuxErrno> {
        let open_file = self.open_file(fd)?;
        let mut open = open_file.description.write()?;
        let OpenDescription::HostSocket { base, .. } = &mut *open else {
            return None;
        };
        base.take_pending_socket_error()
            .map(carrick_abi::LinuxErrno::new)
    }

    fn set_socket_error_after_send(&self, fd: i32, errno: carrick_abi::LinuxErrno) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
        {
            base.set_socket_error_after_send(errno.get());
        }
    }

    fn clear_socket_error_after_send(&self, fd: i32) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
        {
            base.clear_socket_error_after_send();
        }
    }

    fn reset_host_stream_socket_for_disconnect(&self, fd: i32) -> Result<(), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let mut open = open_file.description.write().ok_or(LINUX_ENOTSOCK)?;
        let OpenDescription::HostSocket {
            host_fd,
            family,
            type_,
            base,
            synthetic_recv,
            ..
        } = &mut *open
        else {
            return Err(LINUX_ENOTSOCK);
        };
        if *type_ != LINUX_SOCK_STREAM {
            return Err(LINUX_EINVAL);
        }
        let new_host = unsafe {
            libc::socket(
                linux_to_host_af(*family)?,
                host_socktype_backing(*family, *type_),
                0,
            )
        }
        .host_syscall_errno()?;
        set_host_nonblocking(new_host);
        if let Err(errno) = widen_stream_socket_buffers(new_host, *family, *type_) {
            unsafe { libc::close(new_host) };
            return Err(errno);
        }
        *host_fd = HostFdRef::new(new_host);
        synthetic_recv.clear();
        base.set_connect_in_progress(false);
        base.set_connected(false);
        base.clear_socket_error_after_send();
        let _ = base.take_pending_socket_error();
        Ok(())
    }

    pub(super) fn queue_socket_error_after_send(&self, fd: i32) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(mut open) = open_file.description.write()
            && let OpenDescription::HostSocket { base, .. } = &mut *open
            && let Some(errno) = base.socket_error_after_send()
        {
            base.set_pending_socket_error(errno);
        }
    }

    fn record_rewritten_connect_addresses(
        &self,
        family: i32,
        host_fd: i32,
        guest_peer: std::net::SocketAddr,
        host_peer: HostSocketAddr,
        protocol: PortProtocol,
    ) {
        let host_local = host_socket_addr(host_fd, family, false);
        let guest_local = self
            .network
            .provider
            .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd))
            .ok()
            .flatten()
            .or_else(|| {
                host_local.and_then(|local| {
                    (family == libc::AF_INET
                        && self.network.spec.mode == carrick_spec::NetworkMode::Bridge)
                        .then_some(GuestSocketAddr(std::net::SocketAddr::new(
                            if guest_peer.ip().is_loopback() {
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                            } else {
                                std::net::IpAddr::V4(self.network.spec.ipv4)
                            },
                            local.port(),
                        )))
                })
            });
        let _ = self.network.provider.record_socket_addresses(
            self.network.spec.namespace_id.as_ref(),
            crate::network::SocketKey::for_host_fd(host_fd),
            guest_local,
            host_local.map(HostSocketAddr).or(Some(host_peer)),
            Some(GuestSocketAddr(guest_peer)),
            protocol,
        );
    }

    fn prepare_rewritten_connect_source(
        &self,
        family: i32,
        host_fd: i32,
        guest_peer: std::net::SocketAddr,
        host_peer: HostSocketAddr,
        protocol: PortProtocol,
    ) -> Result<(), carrick_abi::LinuxErrno> {
        if family == libc::AF_INET
            && self.network.spec.mode == carrick_spec::NetworkMode::Bridge
            && self
                .network
                .provider
                .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd))
                .ok()
                .flatten()
                .is_none()
        {
            let needs_autobind = host_socket_addr(host_fd, family, false)
                .map(|addr| addr.port() == 0)
                .unwrap_or(true);
            if needs_autobind
                && let Some(host_local) = socket_addr_to_host_sockaddr(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    0,
                ))
            {
                let rc = unsafe {
                    libc::bind(
                        host_fd,
                        host_local.as_ptr() as *const _,
                        host_local.len() as u32,
                    )
                };
                rc.host_syscall_errno()?;
            }
        }
        self.record_rewritten_connect_addresses(family, host_fd, guest_peer, host_peer, protocol);
        Ok(())
    }

    /// True iff `fd` is a HostSocket with SO_PASSCRED enabled (audit M2).
    pub(super) fn socket_so_passcred(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(of.description.read().as_deref(), Some(OpenDescription::HostSocket { base, .. }) if base.so_passcred())
        })
    }

    /// Peer `(pid, uid, gid)` for an AF_UNIX `host_fd`, from LOCAL_PEERCRED +
    /// LOCAL_PEERPID (best-effort; 0 where unavailable). Used to synthesize the
    /// SCM_CREDENTIALS ancillary message for SO_PASSCRED. (audit M2)
    /// The `ucred` an `SO_PASSCRED` receiver sees, in GUEST terms.
    ///
    /// Never `carrick_portable::peer_ucred(host_fd)`. That reads the HOST's
    /// credentials and leaked them straight into the guest: measured against the
    /// Docker oracle, a socketpair peer reported `pid=97396 uid=501 gid=20` — the
    /// macOS pid and the Mac user's uid/gid — where Linux reports the guest's own
    /// `pid=1 uid=0 gid=0`. Under HVPatch a host pid is the CARRIER's, identical
    /// for every guest process, so it could never have been a valid answer either
    /// (`identity_pid`'s own doc names that trap).
    ///
    /// The peer of a `socketpair` — the shape `SO_PASSCRED` receivers
    /// overwhelmingly use, and the one Go's `TestSCMCredentials` exercises — is
    /// the same guest process. A cross-process AF_UNIX peer would need the
    /// endpoint registry to carry the connector's identity; until it does, this
    /// still answers in the guest's domain rather than leaking the host's.
    pub(super) fn peer_ucred(&self, fd: i32) -> (u32, u32, u32) {
        if let Some(open_file) = self.open_file(fd)
            && let Some(cred) = open_file.description.common().peer_cred()
        {
            return (cred.pid.0 as u32, cred.uid.raw(), cred.gid.raw());
        }
        (0, 0xFFFF_FFFF, 0xFFFF_FFFF)
    }

    pub(in crate::dispatch) fn record_unix_peer_cred(
        &self,
        fd: i32,
        cred: crate::dispatch::fd_table::SocketPeerCred,
    ) {
        if let Some(open_file) = self.open_file(fd) {
            open_file.description.common().set_peer_cred(Some(cred));
        }
    }

    /// The GUEST-requested socket type for `fd` (e.g. SOCK_SEQPACKET), which can
    /// differ from the host backing — carrick backs a guest AF_UNIX SEQPACKET
    /// with a host SOCK_STREAM, so the host's SO_TYPE would mis-report it.
    pub(in crate::dispatch) fn socket_guest_type(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::HostSocket { type_, .. } => Some(*type_),
            OpenDescription::Netlink { sock_type, .. } => Some(*sock_type),
            OpenDescription::Packet { socket, .. } => Some(socket.sock_type),
            _ => None,
        }
    }

    pub(super) fn socket_guest_domain_type_and_protocol(&self, fd: i32) -> Option<(i32, i32, i32)> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::HostSocket {
                family,
                type_,
                protocol,
                ..
            } => Some((*family, *type_, *protocol)),
            OpenDescription::Netlink {
                sock_type,
                protocol,
                ..
            } => Some((LINUX_AF_NETLINK, *sock_type, *protocol)),
            OpenDescription::Packet { socket, .. } => {
                Some((LINUX_AF_PACKET, socket.sock_type, socket.protocol as i32))
            }
            _ => None,
        }
    }

    pub(in crate::dispatch) fn socket_guest_protocol(&self, fd: i32) -> Option<i32> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::HostSocket { protocol, .. } => Some(*protocol),
            OpenDescription::Netlink { protocol, .. } => Some(*protocol),
            OpenDescription::Packet { socket, .. } => Some(socket.protocol as i32),
            _ => None,
        }
    }

    fn socket_reuseport(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(of.description.read().as_deref(), Some(OpenDescription::HostSocket { base, .. }) if base.so_reuseport())
        })
    }

    pub(super) fn socket_port_protocol(&self, fd: i32) -> Option<PortProtocol> {
        match self.socket_guest_type(fd)? {
            LINUX_SOCK_STREAM => Some(PortProtocol::Tcp),
            LINUX_SOCK_DGRAM => Some(PortProtocol::Udp),
            _ => None,
        }
    }

    pub(in crate::dispatch) fn maybe_queue_icmp_echo_reply(
        &self,
        fd: i32,
        request: &[u8],
        requested: std::net::SocketAddr,
    ) -> bool {
        if self.socket_guest_protocol(fd) != Some(LINUX_IPPROTO_ICMP)
            || self.socket_guest_type(fd) != Some(LINUX_SOCK_DGRAM)
            || !requested.ip().is_loopback()
            || request.len() < 8
            || request[0] != LINUX_ICMP_ECHO_REQUEST
            || request[1] != 0
        {
            return false;
        }
        let Some(source) = socket_addr_to_linux_sockaddr(requested) else {
            return false;
        };
        let mut response = request.to_vec();
        response[0] = LINUX_ICMP_ECHO_REPLY;
        response[2..4].fill(0);
        let checksum = internet_checksum(&response);
        response[2..4].copy_from_slice(&checksum.to_be_bytes());
        self.queue_synthetic_datagram(fd, response, source)
    }

    pub(in crate::dispatch) fn maybe_queue_dns_response(
        &self,
        fd: i32,
        request: &[u8],
        requested: std::net::SocketAddr,
    ) -> bool {
        if !self.is_dns_gateway_addr(requested) {
            return false;
        }
        let Some(source) = socket_addr_to_linux_sockaddr(requested) else {
            return false;
        };
        let Some(response) = crate::network::dns::build_a_response(request, |name| {
            match self.network.resolve_dns_name(name) {
                Ok(service_addrs) if service_addrs.is_empty() => {
                    crate::network::dns::resolve_host_a(name)
                }
                Ok(service_addrs) => service_addrs,
                Err(_) => Vec::new(),
            }
        }) else {
            return false;
        };
        self.queue_synthetic_datagram(fd, response, source)
    }

    /// Park a datagram carrick produced in-process on `fd`'s synthetic receive
    /// queue and publish the readiness change.
    ///
    /// The host kernel never sees these bytes, so nothing on an epoll
    /// instance's kqueue fires for them: a waiter already parked in
    /// `epoll_wait` must be pulsed through `notify_inmem_epoll`, after which
    /// its re-sample (`epoll_ready_events`) reports the queue as EPOLLIN. A
    /// `recvfrom`/`recvmsg` issued after the send needs no wake -- it drains
    /// this queue before touching the host fd (`synthetic_datagram_drain`).
    /// Every in-process datagram producer (ICMP echo, the DNS gateway) goes
    /// through here so none can forget the broadcast again.
    fn queue_synthetic_datagram(&self, fd: i32, payload: Vec<u8>, source: Vec<u8>) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        {
            let Some(mut open) = open_file.description.write() else {
                return false;
            };
            let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
                return false;
            };
            synthetic_recv.push_back((payload, source));
        }
        self.notify_inmem_epoll();
        true
    }

    pub(in crate::dispatch) fn synthetic_datagram_drain(
        &self,
        fd: i32,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let open_file = self.open_file(fd)?;
        let mut open = open_file.description.write()?;
        let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
            return None;
        };
        synthetic_recv.pop_front()
    }

    pub(in crate::dispatch) fn is_dns_gateway_addr(&self, addr: std::net::SocketAddr) -> bool {
        addr.port() == 53
            && matches!(addr.ip(), std::net::IpAddr::V4(ip) if ip == self.network.spec.gateway_v4)
    }

    pub(super) fn connected_guest_peer_addr(&self, fd: i32) -> Option<std::net::SocketAddr> {
        let (host_fd, _family) = self.host_socket_lookup(fd).ok()?;
        self.network
            .provider
            .guest_visible_peer_addr(crate::network::SocketKey::for_host_fd(host_fd.get()))
            .ok()
            .flatten()
            .map(|addr| addr.0)
    }

    pub(in crate::dispatch) fn accept_common(
        &self,
        fd: Fd,
        addr: GuestPtr,
        addrlen: GuestPtr,
        memory: &mut impl CurrentMmMemory,
        accept4_flags: i32,
    ) -> DispatchOutcome {
        let Some(socket_flags) = decode_accept4_flags(accept4_flags) else {
            return DispatchOutcome::errno(LINUX_EINVAL);
        };
        let fd = fd.0;
        let addr_addr = addr.0;
        let addrlen_addr = addrlen.0;
        let (host_fd, family, type_, protocol) = {
            let Some(open_file) = self.open_file(fd) else {
                return DispatchOutcome::errno(LINUX_EBADF);
            };
            if carrick_abi::LinuxOpenFlags::from_bits_truncate(
                open_file.description.common().status_flags(),
            )
            .contains(carrick_abi::LinuxOpenFlags::PATH)
            {
                return DispatchOutcome::errno(LINUX_EBADF);
            }
            match open_file.description.read().as_deref() {
                Some(OpenDescription::HostSocket {
                    host_fd,
                    family,
                    type_,
                    protocol,
                    ..
                }) => (host_fd.raw(), *family, *type_, *protocol),
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
        let accepted_source = std::cell::RefCell::new(None::<Vec<u8>>);
        // SO_REUSEPORT: Darwin parks EVERY incoming connection on the last
        // socket that bound the addr:port, so this member's own host socket is
        // very likely empty even when the group has work. Try it first (the
        // common, ungrouped case costs nothing), then take from the sibling
        // holding it. `siblings` is empty unless this fd is in a group with
        // more than one member, so an ordinary listener never leaves the
        // original path.
        let accept_targets: Vec<i32> = std::iter::once(host_fd)
            .chain(reuseport::steal_targets(host_fd))
            .collect();
        let outcome = self.blocking_io(fd, host_fd, IoDir::Read, nonblocking, None, || {
            let mut last = Err(LINUX_EAGAIN);
            for target in accept_targets {
                let mut sa_storage = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
                let mut sa_len: libc::socklen_t = sa_storage.len() as libc::socklen_t;
                let new_host = unsafe {
                    libc::accept(
                        target,
                        sa_storage.as_mut_ptr() as *mut _,
                        &mut sa_len as *mut _,
                    )
                };
                match new_host.host_syscall_errno() {
                    Ok(new_host) => {
                        if addr_addr != 0 && addrlen_addr != 0 {
                            let used = (sa_len as usize).min(sa_storage.len());
                            accepted_source
                                .borrow_mut()
                                .replace(sa_storage[..used].to_vec());
                        }
                        return Ok(new_host as i64);
                    }
                    // Only an empty queue is worth trying the next member for.
                    // Any other errno is this accept's real answer.
                    Err(e) if e == LINUX_EAGAIN => last = Err(e),
                    Err(e) => return Err(e),
                }
            }
            last
        });
        let new_host = match outcome {
            DispatchOutcome::Returned { value } => value as i32,
            // WaitOnFds (block) or Errno — propagate; the runtime re-dispatches
            // accept on readiness.
            other => return other,
        };
        // This member took the group's turn; hand it to the next one so two
        // symmetric workers alternate strictly rather than racing.
        reuseport::advance_turn(host_fd);
        crate::event_ring::rec(crate::event_ring::ACCEPT, host_fd, new_host, 0);
        let accepted_source = accepted_source.into_inner();
        let accept_protocol = (family == libc::AF_INET && type_ == libc::SOCK_STREAM)
            .then_some(carrick_spec::PortProtocol::Tcp);
        let listener_guest_local = self
            .network
            .provider
            .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd))
            .ok()
            .flatten();
        let accepted_host_source = host_socket_addr(new_host, family, true).or_else(|| {
            accepted_source
                .as_ref()
                .and_then(|host_source| host_sockaddr_to_socket_addr(host_source))
        });
        let guest_peer = accepted_host_source.and_then(|host_addr| {
            accept_protocol
                .zip(Some(host_addr))
                .and_then(|(protocol, host_addr)| {
                    self.network
                        .provider
                        .translate_recv_addr(HostSocketAddr(host_addr), protocol)
                        .ok()
                        .flatten()
                        .or_else(|| {
                            let listener_ip = listener_guest_local?.0.ip();
                            (self.network.spec.mode == carrick_spec::NetworkMode::Bridge
                                && host_addr.ip().is_loopback()
                                && matches!(listener_ip, std::net::IpAddr::V4(ip) if !ip.is_loopback()))
                            .then_some(GuestSocketAddr(std::net::SocketAddr::new(
                                listener_ip,
                                host_addr.port(),
                            )))
                        })
                })
        });
        if addr_addr != 0 && addrlen_addr != 0 {
            let linux_bytes = guest_peer
                .and_then(|addr| socket_addr_to_linux_sockaddr(addr.0))
                .or_else(|| accepted_host_source.and_then(socket_addr_to_linux_sockaddr))
                .or_else(|| {
                    accepted_source
                        .as_ref()
                        .map(|host_source| host_to_linux_sockaddr(host_source, family, false))
                })
                .or_else(|| {
                    (family == libc::AF_UNIX).then(|| (LINUX_AF_UNIX as u16).to_ne_bytes().to_vec())
                });
            let Some(linux_bytes) = linux_bytes else {
                crate::event_ring::rec(
                    crate::event_ring::ACCEPTERR,
                    host_fd,
                    new_host,
                    LINUX_EFAULT.get(),
                );
                unsafe { libc::close(new_host) };
                return DispatchOutcome::errno(LINUX_EFAULT);
            };
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                crate::event_ring::rec(
                    crate::event_ring::ACCEPTERR,
                    host_fd,
                    new_host,
                    LINUX_EFAULT.get(),
                );
                unsafe { libc::close(new_host) };
                return DispatchOutcome::errno(LINUX_EFAULT);
            }
        }
        let nonblock = socket_flags.contains(LinuxSocketTypeFlags::NONBLOCK);
        let cloexec = socket_flags.contains(LinuxSocketTypeFlags::CLOEXEC);
        // Keep the host socket non-blocking; Linux-visible blocking intent is
        // carried by status_flags and serviced by WaitOnFds.
        set_host_nonblocking(new_host);
        if let Err(errno) = widen_stream_socket_buffers(new_host, family, type_) {
            crate::event_ring::rec(crate::event_ring::ACCEPTERR, host_fd, new_host, errno.get());
            if family != LINUX_AF_UNIX {
                unsafe { libc::close(new_host) };
                return DispatchOutcome::errno(errno);
            }
            // Linux accept(2) does not fail because optional host-side buffer
            // tuning failed. AF_UNIX accepted sockets can reject the larger Darwin
            // buffer target intermittently; keep the connection and let normal
            // nonblocking backpressure handle any smaller host buffer.
        }
        let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
        let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
        let peer_cred = if family == LINUX_AF_UNIX {
            support::pop_pending_unix_client(host_fd)
        } else {
            None
        };
        let mut base = OpenDescriptionBase::new(status_flags);
        base.set_connected(true);
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::HostSocket {
                host_fd: HostFdRef::new(new_host),
                family,
                type_,
                protocol,
                base,
                mcast_memberships: Vec::new(),
                synthetic_recv: std::collections::VecDeque::new(),
            })),
            status_flags,
            fd_flags,
        );
        if peer_cred.is_some() {
            open_file.description.common().set_peer_cred(peer_cred);
        }
        let linux_fd = match self.install_fd_at_or_above(3, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                crate::event_ring::rec(
                    crate::event_ring::ACCEPTERR,
                    host_fd,
                    new_host,
                    linux_errno::EMFILE.get(),
                );
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        if let Some(protocol) = accept_protocol {
            let guest_local = self
                .network
                .provider
                .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd))
                .ok()
                .flatten();
            let host_local = host_socket_addr(new_host, family, false);
            let _ = self.network.provider.record_socket_addresses(
                self.network.spec.namespace_id.as_ref(),
                crate::network::SocketKey::for_host_fd(new_host),
                guest_local,
                host_local.map(HostSocketAddr),
                guest_peer,
                protocol,
            );
        }
        DispatchOutcome::returned_i32(linux_fd)
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
        memory: &impl CurrentMmMemory,
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
            let outcome = connect_success_or_pending_error(host_fd.get());
            if matches!(outcome, DispatchOutcome::Returned { value: 0 }) {
                self.update_socket_connection_state(fd, Some(false), Some(true));
            }
            return outcome;
        }
        let e = HostSyscallError::last().linux_errno();
        // See `fn connect` for why EISCONN is split on connect_in_progress.
        if e == LINUX_EISCONN {
            if self.socket_connect_in_progress(fd) {
                let outcome = connect_success_or_pending_error(host_fd.get());
                let connected = matches!(outcome, DispatchOutcome::Returned { value: 0 });
                self.update_socket_connection_state(fd, Some(false), Some(connected));
                return outcome;
            }
            return DispatchOutcome::errno(LINUX_EISCONN);
        }
        if e == LINUX_EINPROGRESS || e == LINUX_EALREADY || e == LINUX_EAGAIN {
            self.update_socket_connection_state(fd, Some(true), None);
            let files = self.captured_file_table();
            let fds = match WaitFds::raw_one(host_fd.get(), libc::POLLOUT)
                .with_guest_slots(&files, [fd])
            {
                Ok(fds) => fds,
                Err(errno) => return DispatchOutcome::errno(errno),
            };
            return DispatchOutcome::WaitOnFds {
                fds,
                timeout: None,
                sig_mask: carrick_abi::WaitSigMask::NONE,
                completion: FdWaitCompletion::Fd {
                    on_timeout: LINUX_EINPROGRESS.guest_retval(),
                },
            };
        }
        DispatchOutcome::errno(e)
    }
}

#[cfg(test)]
mod icmp_ping_tests {
    use super::*;

    #[test]
    fn loopback_echo_reply_is_queued_with_valid_checksum() {
        let dispatcher = SyscallDispatcher::new();
        let fd = match dispatcher.host_socket_install(
            LINUX_AF_INET,
            LINUX_SOCK_DGRAM,
            LINUX_IPPROTO_ICMP,
        ) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("ping socket creation failed: {other:?}"),
        };
        assert_eq!(
            dispatcher.socket_guest_protocol(fd),
            Some(LINUX_IPPROTO_ICMP)
        );

        let mut request = [0u8; 8];
        request[0] = LINUX_ICMP_ECHO_REQUEST;
        request[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        request[6..8].copy_from_slice(&1u16.to_be_bytes());
        let checksum = internet_checksum(&request);
        request[2..4].copy_from_slice(&checksum.to_be_bytes());
        let loopback = "127.0.0.1:0".parse().unwrap();
        assert!(dispatcher.maybe_queue_icmp_echo_reply(fd, &request, loopback));

        let (reply, source) = dispatcher.synthetic_datagram_drain(fd).unwrap();
        assert_eq!(reply[0], LINUX_ICMP_ECHO_REPLY);
        assert_eq!(reply[1], 0);
        assert_eq!(internet_checksum(&reply), 0);
        assert_eq!(source, socket_addr_to_linux_sockaddr(loopback).unwrap());
    }
}

impl<'a> NetView<'a> {
    define_syscall! {
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
            if family == LINUX_AF_PACKET {
                return Ok(this.packet_socket(cx.kernel, type_, protocol));
            }
            // Reject Linux-invalid (family,type,protocol) tuples with the
            // canonical errno first: protocol selection precedes the
            // capability check on Linux, so a raw socket naming no protocol
            // is EPROTONOSUPPORT for root and non-root alike (socket01).
            let base_type = type_ & !LinuxSocketTypeFlags::SUPPORTED_MASK;
            if let Some(errno) = canonical_socket_errno(family, base_type, protocol) {
                return Ok(DispatchOutcome::errno(errno));
            }
            // A packet-crafting socket needs CAP_NET_RAW (socket(2),
            // capabilities(7)). Docker's default set grants it, so container
            // root keeps working; a guest that has setuid'd away from root
            // has lost every capability and must get EPERM.
            if base_type == LINUX_SOCK_RAW
                && !super::creds::has_effective_capability(
                    cx.kernel,
                    crate::namespace::process::CAP_NET_RAW,
                )
            {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
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
            // Reject Linux-invalid (family,type,protocol) tuples with the
            // canonical errno before macOS gets a chance to report a divergent
            // one; a valid INET pair still falls through to socketpair(), which
            // answers EOPNOTSUPP. (socketpair01)
            if let Some(errno) = canonical_socket_errno(family, base_type, protocol) {
                return Ok(DispatchOutcome::errno(errno));
            }
            let host_family = match linux_to_host_af(family) {
                Ok(f) => f,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            let host_type = host_socktype_backing(family, base_type);

            let mut host_fds: [i32; 2] = [-1, -1];
            let rc =
                unsafe { libc::socketpair(host_family, host_type, protocol, host_fds.as_mut_ptr()) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            set_host_nonblocking(host_fds[0]);
            set_host_nonblocking(host_fds[1]);
            // Same Linux-sized backing every other stream-socket creation site
            // gets. macOS gives an AF_UNIX stream pair 8 KiB
            // (`net.local.stream.sendspace`) where Linux gives ~208 KiB, so a
            // guest that fills the pair before draining it — LTP `splice05`
            // pushes 64 KiB pipe→socket and only reads afterwards — blocked
            // forever on a peer buffer 1/26th the size it was written for.
            for host_fd in host_fds {
                if let Err(errno) = widen_stream_socket_buffers(host_fd, family, base_type) {
                    unsafe {
                        libc::close(host_fds[0]);
                        libc::close(host_fds[1]);
                    }
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            let status_flags = LINUX_O_RDWR | if nonblock { LINUX_O_NONBLOCK } else { 0 };
            let fd_flags = if cloexec { LINUX_FD_CLOEXEC } else { 0 };
            let my_cred = {
                let creds = this.cred_snapshot();
                crate::dispatch::fd_table::SocketPeerCred {
                    pid: crate::dispatch::abi_args::NsPid(this.identity_pid() as i32),
                    uid: creds.euid,
                    gid: creds.egid,
                }
            };
            let mut base_first = OpenDescriptionBase::new(status_flags);
            base_first.set_connected(true);
            let first = OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    host_fd: HostFdRef::new(host_fds[0]),
                    family,
                    type_: base_type,
                    protocol,
                    base: base_first,
                    mcast_memberships: Vec::new(),
                    synthetic_recv: std::collections::VecDeque::new(),
                })),
                status_flags,
                fd_flags,
            );
            first.description.common().set_peer_cred(Some(my_cred));
            let mut base_second = OpenDescriptionBase::new(status_flags);
            base_second.set_connected(true);
            let second = OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::HostSocket {
                    host_fd: HostFdRef::new(host_fds[1]),
                    family,
                    type_: base_type,
                    protocol,
                    base: base_second,
                    mcast_memberships: Vec::new(),
                    synthetic_recv: std::collections::VecDeque::new(),
                })),
                status_flags,
                fd_flags,
            );
            second.description.common().set_peer_cred(Some(my_cred));
            let (read_fd, write_fd) = match this.install_fd_pair_at_or_above(3, first, second) {
                Ok(pair) => pair,
                Err(_) => {
                    return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                }
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, sv_addr, &pair).is_err() {
                let removed = {
                    let files = this.captured_file_table();
                    let mut table = files.write_open_files();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                this.note_fd_closed(read_fd);
                this.note_fd_closed(write_fd);
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
                && let Some(mut open) = open_file.description.write()
            {
                match &mut *open {
                    OpenDescription::Netlink {
                        pid: nl_pid,
                        groups: nl_groups,
                        ..
                    } => {
                        let (req_pid, req_groups) = read_sockaddr_nl(memory, addr_addr, addrlen);
                        *nl_pid = if req_pid != 0 {
                            req_pid
                        } else {
                            std::process::id()
                        };
                        *nl_groups = req_groups;
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    OpenDescription::Packet { socket, .. } => {
                        let socket = Arc::clone(socket);
                        drop(open);
                        return Ok(socket.bind(memory, addr_addr, addrlen));
                    }
                    _ => {}
                }
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
            let mut host_addr = read_linux_sockaddr(memory, addr_addr, addrlen, family)?;
            let mut rewritten_bind: Option<(std::net::SocketAddr, PortProtocol)> = None;
            if family == LINUX_AF_INET
                && let Some(protocol) = this.socket_port_protocol(fd)
                && let Some(requested) = host_sockaddr_to_socket_addr(&host_addr)
            {
                match this.network.provider.materialize_bind(
                    this.network.spec.namespace_id.as_ref(),
                    GuestSocketAddr(requested),
                    protocol,
                ) {
                    Ok(BindTarget::Host(host)) => {
                        if let Some(mapped) = socket_addr_to_host_sockaddr(host.0) {
                            host_addr = mapped;
                            rewritten_bind = Some((requested, protocol));
                        }
                    }
                    Ok(BindTarget::Unchanged) => {}
                    Err(_) => return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EADDRNOTAVAIL)),
                }
            }
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
            // An error-queue socket needs host SO_REUSEPORT so its shadow can
            // share this addr:port (see `recverr`). Linux would refuse a SECOND
            // error-queue bind here, and Darwin no longer will once the flag is
            // set, so Carrick enforces that itself.
            if recverr::is_enabled(host_fd.get()) {
                if !recverr::reserve_bind(host_fd.get(), &host_addr) {
                    return Ok(DispatchOutcome::errno(linux_errno::EADDRINUSE));
                }
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
            let rc = unsafe {
                libc::bind(
                    host_fd.get(),
                    host_addr.as_ptr() as *const _,
                    host_addr.len() as u32,
                )
            };
            let mut bind_result = rc.host_syscall_errno();
            if let Err(errno) = bind_result
                && errno == linux_errno::EADDRINUSE
                && this.network.spec.mode == carrick_spec::NetworkMode::Bridge
                && family == LINUX_AF_INET
                && let Some(requested) = host_sockaddr_to_socket_addr(&host_addr)
                && matches!(
                    requested.ip(),
                    std::net::IpAddr::V4(ip)
                        if ip == std::net::Ipv4Addr::UNSPECIFIED || ip == this.network.spec.ipv4
                )
                && let Some(protocol) = this.socket_port_protocol(fd)
                && let Some(mapped) =
                    socket_addr_to_host_sockaddr(std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        0,
                    ))
            {
                host_addr = mapped;
                let retry = unsafe {
                    libc::bind(
                        host_fd.get(),
                        host_addr.as_ptr() as *const _,
                        host_addr.len() as u32,
                    )
                };
                bind_result = retry.host_syscall_errno();
                if bind_result.is_ok() {
                    rewritten_bind = Some((requested, protocol));
                }
            }
            if let Err(errno) = bind_result {
                return Ok(DispatchOutcome::errno(errno));
            }
            // An error-queue socket's shadow must exist before `epoll_ctl(ADD)`
            // registers it (see `recverr::create_shadow_at_bind`).
            if recverr::is_enabled(host_fd.get())
                && let Some(local) = host_sockaddr_bytes(host_fd.get())
            {
                recverr::create_shadow_at_bind(host_fd.get(), &local);
            }
            // SO_REUSEPORT: join this host addr:port's group. Darwin lets every
            // member bind but then delivers ALL traffic to the last binder, so
            // Carrick has to distribute — see `reuseport`. Keyed on the address
            // the HOST actually bound (read back, not the requested one, which
            // may carry port 0 or have been rewritten above).
            if this.socket_reuseport(fd)
                && let Some(socket_type) = this.socket_guest_type(fd)
                && let Some(bound) = host_sockaddr_bytes(host_fd.get())
            {
                reuseport::join(reuseport::GroupKey::new(socket_type, bound), host_fd.get());
            }
            if let Some((guest_local, protocol)) = rewritten_bind
                && let Some(host_local) = host_socket_addr(host_fd.get(), family, false)
            {
                let guest_local = if guest_local.port() == 0 {
                    std::net::SocketAddr::new(guest_local.ip(), host_local.port())
                } else {
                    guest_local
                };
                let _ = this.network.provider.record_socket_addresses(
                    this.network.spec.namespace_id.as_ref(),
                    crate::network::SocketKey::for_host_fd(host_fd.get()),
                    Some(GuestSocketAddr(guest_local)),
                    Some(HostSocketAddr(host_local)),
                    None,
                    protocol,
                );
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
                let creds = this.cred_snapshot();
                let my_cred = crate::dispatch::fd_table::SocketPeerCred {
                    pid: crate::dispatch::abi_args::NsPid(this.identity_pid() as i32),
                    uid: creds.euid,
                    gid: creds.egid,
                };
                support::register_unix_listener(&host_addr[2..end], host_fd.get(), my_cred);
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
                } else if this
                    .fs
                    .rootfs_vfs
                    .create_socket(&resolved, mode)
                    .is_ok()
                {
                    // Stamp the creator, exactly as `mknod(S_IFSOCK)` and
                    // `openat(O_CREAT)` do. Without this the node has no owner
                    // xattr, `get_owner` falls back to root, and a non-root
                    // guest cannot `chmod` the socket it just created — libuv's
                    // `pipe_set_chmod` saw EPERM and skipped, where Linux (whose
                    // socket inode is owned by the uid that bound it) runs.
                    this.stamp_new_node_owner(&resolved, mode);
                }
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn listen(this, cx, fd: Fd, backlog: u64) {

            let fd: Fd = fd;
            let backlog = backlog as i32;
            let (host_fd, _family) = this.host_socket_lookup(fd.0)?;
            if let Some(protocol) = this.socket_port_protocol(fd.0)
                && let Some(host_local) = host_socket_addr(host_fd.get(), libc::AF_INET, false)
                && let Err(errno) = this.network.provider.prepare_listen(
                    this.network.spec.namespace_id.as_ref(),
                    this
                        .network
                        .provider
                        .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(
                            host_fd.get(),
                        ))
                        .ok()
                        .flatten(),
                    Some(HostSocketAddr(host_local)),
                    protocol,
                    this.socket_reuseport(fd.0),
                )
            {
                return Ok(DispatchOutcome::errno(errno));
            }
            let rc = unsafe { libc::listen(host_fd.get(), backlog) };
            if let Err(errno) = rc.host_syscall_errno() {
                return Ok(DispatchOutcome::errno(errno));
            }
            if let Some(open_file) = this.open_file(fd.0)
                && let Some(mut open) = open_file.description.write()
                && let OpenDescription::HostSocket { base, .. } =
                    &mut *open
            {
                base.set_listening(true);
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
            // BSD requires privilege for a real INET raw socket. Such sockets
            // use an unprivileged datagram fd as their host carrier, so a raw
            // connect cannot be handed to the carrier (a raw sockaddr has no
            // transport port, and Darwin rejects UDP connect-to-port-zero).
            // Linux raw connect only establishes the default peer identity;
            // record that identity in the network namespace and leave payload
            // operations on the carrier. This is sufficient for the ordinary
            // bind/options/poll/name surface without claiming privileged raw
            // packet injection.
            if cfg!(carrick_bsd)
                && matches!(family, LINUX_AF_INET | LINUX_AF_INET6)
                && this.socket_guest_type(fd) == Some(LINUX_SOCK_RAW)
            {
                let Some(requested) = host_sockaddr_to_socket_addr(&host_addr) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                this.record_rewritten_connect_addresses(
                    family,
                    host_fd.get(),
                    requested,
                    HostSocketAddr(requested),
                    PortProtocol::Udp,
                );
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let mut rewritten_connect: Option<(
                std::net::SocketAddr,
                HostSocketAddr,
                PortProtocol,
            )> = None;
            let mut synthetic_error_after_send = false;
            if family == LINUX_AF_INET
                && let Some(protocol) = this.socket_port_protocol(fd)
                && let Some(requested) = host_sockaddr_to_socket_addr(&host_addr)
            {
                if protocol == PortProtocol::Udp
                    && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
                    && this.is_dns_gateway_addr(requested)
                {
                    let synthetic_host_peer = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                        requested.port(),
                    );
                    if let Some(mapped) = socket_addr_to_host_sockaddr(synthetic_host_peer) {
                        host_addr = mapped;
                        rewritten_connect =
                            Some((requested, HostSocketAddr(synthetic_host_peer), protocol));
                    }
                } else {
                match this.network.provider.resolve_connect(
                    this.network.spec.namespace_id.as_ref(),
                    GuestSocketAddr(requested),
                    protocol,
                ) {
                    Ok(ConnectTarget::Host(host)) => {
                        if let Some(mapped) = socket_addr_to_host_sockaddr(host.0) {
                            host_addr = mapped;
                            rewritten_connect = Some((requested, host, protocol));
                        }
                    }
                    Ok(ConnectTarget::Intercept(mock)) => {
                        let Some(open_file) = this.open_file(fd) else {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        };
                        let status_flags = open_file.description.common().status_flags();
                        let old_host_fd = {
                            let open = open_file.description.read();
                            if let Some(OpenDescription::HostSocket { host_fd, .. }) = open.as_deref() {
                                Some(host_fd.raw())
                            } else {
                                None
                            }
                        };
                        if let Some(hfd) = old_host_fd {
                            this.network.provider.forget_socket_addresses(crate::network::SocketKey::for_host_fd(hfd));
                        }
                        let local_port = 49152 + (fd as u16 % 16384);
                        let local_addr = match requested {
                            std::net::SocketAddr::V4(_) => std::net::SocketAddr::new(
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                local_port,
                            ),
                            std::net::SocketAddr::V6(_) => std::net::SocketAddr::new(
                                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                                local_port,
                            ),
                        };
                        let pure_sock = crate::dispatch::net::unix_pure::PureSocketInner::new_mock(
                            family,
                            LINUX_SOCK_STREAM,
                            LINUX_IPPROTO_TCP,
                            Some(local_addr),
                            Some(requested),
                            mock,
                            None,
                        );
                        if let Some(initial_bytes) = pure_sock.mock_on_connect() {
                            pure_sock.queue_mock_response(&initial_bytes);
                            this.notify_inmem_epoll();
                        }
                        if let Some(mut open) = open_file.description.write() {
                            *open = OpenDescription::InMemorySocket {
                                base: OpenDescriptionBase::new(status_flags),
                                socket: pure_sock,
                            };
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    Ok(ConnectTarget::Unchanged) => {
                    }
                    Ok(ConnectTarget::Denied(errno)) => {
                        if errno == carrick_abi::LINUX_ECONNREFUSED
                            && protocol == PortProtocol::Tcp
                            && this.socket_guest_type(fd) == Some(LINUX_SOCK_STREAM)
                            && this.io_is_nonblocking(fd, 0)
                        {
                            this.set_socket_pending_error(fd, carrick_abi::LINUX_ECONNREFUSED);
                            return Ok(DispatchOutcome::errno(LINUX_EINPROGRESS));
                        }
                        if errno == carrick_abi::LINUX_ECONNREFUSED
                            && protocol == PortProtocol::Udp
                            && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
                        {
                            let synthetic_host_peer = std::net::SocketAddr::new(
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                requested.port(),
                            );
                            if let Some(mapped) = socket_addr_to_host_sockaddr(synthetic_host_peer)
                            {
                                host_addr = mapped;
                                this.set_socket_error_after_send(
                                    fd,
                                    carrick_abi::LINUX_ECONNREFUSED,
                                );
                                synthetic_error_after_send = true;
                                rewritten_connect = Some((
                                    requested,
                                    HostSocketAddr(synthetic_host_peer),
                                    protocol,
                                ));
                            } else {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                        } else {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(carrick_abi::LINUX_ECONNREFUSED)),
                }
                }
            }
            // connect(AF_UNSPEC) is the UDP "disconnect" (dissolve the peer
            // association); Linux returns 0. macOS disconnects too but may then
            // report EAFNOSUPPORT/EINVAL — treat those as success below.
            let is_unspec_disconnect = addrlen >= 2
                && memory
                    .read_bytes(addr_addr, 2)
                    .ok()
                    .map(|b| u16::from_ne_bytes([b[0], b[1]]) as i32 == LINUX_AF_UNSPEC)
                    .unwrap_or(false);
            if is_unspec_disconnect && this.socket_guest_type(fd) == Some(LINUX_SOCK_STREAM) {
                match this.reset_host_stream_socket_for_disconnect(fd) {
                    Ok(()) => return Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
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
                    Err(errno) => {
                        tracing::debug!(
                            target: "carrick::unix",
                            guest_path = %gp,
                            resolved,
                            parent,
                            ?errno,
                            "AF_UNIX connect: parent directory lookup failed"
                        );
                        return Ok(DispatchOutcome::errno(errno));
                    }
                }
                match this.layered_metadata(&resolved) {
                    Ok(md) if md.kind == RootFsEntryKind::Socket => {}
                    Ok(md) => {
                        tracing::debug!(
                            target: "carrick::unix",
                            guest_path = %gp,
                            resolved,
                            kind = ?md.kind,
                            "AF_UNIX connect: path is not a socket node"
                        );
                        return Ok(DispatchOutcome::errno(linux_errno::ECONNREFUSED));
                    }
                    Err(errno) => {
                        tracing::debug!(
                            target: "carrick::unix",
                            guest_path = %gp,
                            resolved,
                            ?errno,
                            "AF_UNIX connect: socket node lookup failed"
                        );
                        return Ok(DispatchOutcome::errno(errno));
                    }
                }
            }
            // connect(2) has no per-call non-blocking flag, so put the host socket
            // non-blocking — it then returns EINPROGRESS instead of blocking under
            // the dispatcher lock. recv/send use MSG_DONTWAIT + the guest's intended
            // mode (status_flags), so the host fd's real mode is immaterial.
            let nonblocking = this.io_is_nonblocking(fd, 0);
            set_host_nonblocking(host_fd.get());
            if let Some((guest_peer, host_peer, protocol)) = rewritten_connect {
                if let Err(errno) = this.prepare_rewritten_connect_source(
                    family,
                    host_fd.get(),
                    guest_peer,
                    host_peer,
                    protocol,
                ) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                rewritten_connect = Some((guest_peer, host_peer, protocol));
            }
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
                let creds = this.cred_snapshot();
                let client_cred = crate::dispatch::fd_table::SocketPeerCred {
                    pid: crate::dispatch::abi_args::NsPid(this.identity_pid() as i32),
                    uid: creds.euid,
                    gid: creds.egid,
                };
                if let Some(server_cred) =
                    support::lookup_and_queue_unix_connect(&host_addr[2..end], client_cred)
                {
                    this.record_unix_peer_cred(fd, server_cred);
                }
            }
            if rc == 0 {
                if !synthetic_error_after_send {
                    this.clear_socket_error_after_send(fd);
                }
                // A non-blocking host connect reporting success does not prove the
                // connection completed — consult SO_ERROR (see
                // connect_success_or_pending_error).
                let outcome = connect_success_or_pending_error(host_fd.get());
                if matches!(outcome, DispatchOutcome::Returned { value: 0 }) {
                    this.update_socket_connection_state(fd, Some(false), Some(true));
                    if let Some((guest_peer, host_peer, protocol)) = rewritten_connect {
                        this.record_rewritten_connect_addresses(
                            family,
                            host_fd.get(),
                            guest_peer,
                            host_peer,
                            protocol,
                        );
                    }
                }
                return Ok(outcome);
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
                    let outcome = connect_success_or_pending_error(host_fd.get());
                    let connected = matches!(outcome, DispatchOutcome::Returned { value: 0 });
                    this.update_socket_connection_state(fd, Some(false), Some(connected));
                    if connected {
                        if let Some((guest_peer, host_peer, protocol)) = rewritten_connect {
                            this.record_rewritten_connect_addresses(
                                family,
                                host_fd.get(),
                                guest_peer,
                                host_peer,
                                protocol,
                            );
                        }
                    }
                    return Ok(outcome);
                }
                return Ok(DispatchOutcome::errno(LINUX_EISCONN));
            }
            if e == LINUX_EINPROGRESS || e == LINUX_EALREADY || e == LINUX_EAGAIN {
                if let Some((guest_peer, host_peer, protocol)) = rewritten_connect {
                    this.record_rewritten_connect_addresses(
                        family,
                        host_fd.get(),
                        guest_peer,
                        host_peer,
                        protocol,
                    );
                }
                this.update_socket_connection_state(fd, Some(true), None);
                if nonblocking {
                    // Non-blocking guest: hand EINPROGRESS/EALREADY straight back.
                    return Ok(DispatchOutcome::errno(e));
                }
                // Blocking guest: wait (lock released) for the socket to become
                // writable, then re-dispatch — connect then returns EISCONN or the
                // real connect error. Mark the connect as deferred so the EISCONN
                // we expect on re-dispatch is recognised as async-completion above.
                let files = this.captured_file_table();
                let fds = match WaitFds::raw_one(host_fd.get(), libc::POLLOUT)
                    .with_guest_slots(&files, [fd])
                {
                    Ok(fds) => fds,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                return Ok(DispatchOutcome::WaitOnFds {
                    fds,
                    timeout: None,
                    sig_mask: carrick_abi::WaitSigMask::NONE,
                    completion: FdWaitCompletion::Fd {
                        on_timeout: LINUX_EINPROGRESS.guest_retval(),
                    },
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
                && let Some(OpenDescription::Netlink { pid, groups, .. }) = open_file.description.read().as_deref()
            {
                let nl = sockaddr_nl_bytes(*pid, *groups);
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &nl).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if let Some(open_file) = this.open_file(fd)
                && let Some(open) = open_file.description.read()
            {
                match &*open {
                    OpenDescription::InMemorySocket { socket, .. } => {
                        if addr_addr == 0 || addrlen_addr == 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                            && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let local = socket.local_addr();
                        let linux_bytes = if let Some(local) = local {
                            socket_addr_to_linux_sockaddr(local).unwrap_or_default()
                        } else {
                            vec![0u8; 16]
                        };
                        if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    OpenDescription::Packet { socket, .. } => {
                        let socket = Arc::clone(socket);
                        drop(open);
                        return Ok(socket.getsockname(memory, addr_addr, addrlen_addr));
                    }
                    _ => {}
                }
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
            if let Ok(Some(guest_local)) = this
                .network
                .provider
                .guest_visible_local_addr(crate::network::SocketKey::for_host_fd(host_fd.get()))
                && let Some(linux_bytes) = socket_addr_to_linux_sockaddr(guest_local.0)
            {
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
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
            if let Some(open_file) = this.open_file(fd)
                && let Some(open) = open_file.description.read()
            {
                match &*open {
                    OpenDescription::InMemorySocket { socket, .. } => {
                        if addr_addr == 0 || addrlen_addr == 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                            && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let peer = socket.peer_addr();
                        let Some(peer) = peer else {
                            return Ok(DispatchOutcome::errno(LINUX_ENOTCONN));
                        };
                        let Some(linux_bytes) = socket_addr_to_linux_sockaddr(peer) else {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        };
                        if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    OpenDescription::Packet { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_ENOTCONN));
                    }
                    _ => {}
                }
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            if cfg!(carrick_bsd)
                && this.socket_guest_type(fd) == Some(LINUX_SOCK_RAW)
                && let Ok(Some(guest_peer)) = this
                    .network
                    .provider
                    .guest_visible_peer_addr(crate::network::SocketKey::for_host_fd(host_fd.get()))
            {
                if addr_addr == 0 || addrlen_addr == 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if let Ok(b) = memory.read_bytes(addrlen_addr, 4)
                    && i32::from_ne_bytes([b[0], b[1], b[2], b[3]]) < 0
                {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let Some(linux_bytes) = socket_addr_to_linux_sockaddr(guest_peer.0) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
            let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
            let rc =
                unsafe { libc::getpeername(host_fd.get(), sa.as_mut_ptr() as *mut _, &mut sa_len as *mut _) };
            if let Err(errno) = rc.host_syscall_errno() {
                // On Darwin, getpeername returns EINVAL when the peer has closed or
                // reset the connection. On Linux, getpeername returns ENOTCONN.
                let errno = if errno == LINUX_EINVAL {
                    LINUX_ENOTCONN
                } else {
                    errno
                };
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
            if let Ok(Some(guest_peer)) = this
                .network
                .provider
                .guest_visible_peer_addr(crate::network::SocketKey::for_host_fd(host_fd.get()))
                && let Some(linux_bytes) = socket_addr_to_linux_sockaddr(guest_peer.0)
            {
                if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let used = (sa_len as usize).min(sa.len());
            let linux_bytes = host_to_linux_sockaddr(&sa[..used], family, false);
            if write_linux_sockaddr(memory, addr_addr, addrlen_addr, &linux_bytes).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn shutdown(this, cx, fd: Fd, how: u64) {

            let fd: Fd = fd;
            let how = how as i32;
            if let Some(open_file) = this.open_file(fd.0)
                && let Some(open) = open_file.description.read()
                && let OpenDescription::InMemorySocket { socket, .. } = &*open
            {
                let socket = Arc::clone(socket);
                drop(open);
                match socket.shutdown(how) {
                    Ok(()) => {
                        this.notify_inmem_epoll();
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            }
            let (host_fd, _family) = this.host_socket_lookup(fd.0)?;
            let rc = unsafe { libc::shutdown(host_fd.get(), how) };
            Ok(if let Err(errno) = rc.host_syscall_errno() {
                DispatchOutcome::errno(errno)
            } else {
                DispatchOutcome::Returned { value: 0 }
            })

        }


    }
}
