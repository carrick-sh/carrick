//! Socket data transfer syscall handlers (`sendto`, `recvfrom`, `sendmsg`,
//! `recvmsg`, `sys_sendmmsg`, `sys_recvmmsg`).
//!
//! Handles connected and unconnected datagram/stream transmission, iovec
//! scattering and gathering, SCM_RIGHTS and SCM_CREDENTIALS ancillary data,
//! IPv6 control messages, corking (MSG_MORE), synthetic Netlink/ICMP/DNS
//! responses, error queues (MSG_ERRQUEUE), and Darwin/Linux flag translations.

use std::sync::Arc;

use carrick_abi::{KernelAbi, LinuxErrno, LinuxMsgFlags};

use super::support::*;
use super::*;
use crate::dispatch::net::{recverr, reuseport, scm_rights, sctp};
use crate::dispatch::{
    CurrentMmMemory, DispatchError, DispatchOutcome, Fd, GuestPtr, HostFd, SyscallCtx,
};
use crate::network::{ConnectTarget, GuestSocketAddr};
use carrick_spec::PortProtocol;

/// Everything a send path needs from the socket description, read once.
#[derive(Clone, Copy, Debug)]
struct SocketSendView {
    host_fd: HostFd,
    family: i32,
    cork_enabled: bool,
    has_pending_cork: bool,
}

fn linux_msg_trunc_recv_capacity(host_fd: i32, guest_len: usize, flags: i32) -> usize {
    if flags & LINUX_MSG_TRUNC == 0 {
        return guest_len;
    }
    host_socket_buffer_size(host_fd, libc::SO_RCVBUF)
        .ok()
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(guest_len)
        .max(guest_len)
        .min(crate::dispatch::MAX_RW_COUNT)
}

#[cfg(test)]
mod host_dgram_msg_trunc_tests {
    use super::{LINUX_MSG_TRUNC, linux_msg_trunc_recv_capacity};

    #[test]
    fn widens_the_host_receive_without_widening_the_guest_copy() {
        let mut sockets = [-1; 2];
        // SAFETY: socketpair initializes both descriptors on success; every
        // descriptor is closed before returning from the test.
        unsafe {
            assert_eq!(
                libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sockets.as_mut_ptr()),
                0
            );
            assert_eq!(
                libc::send(sockets[0], b"twelve-bytes".as_ptr().cast(), 12, 0),
                12
            );

            let capacity = linux_msg_trunc_recv_capacity(sockets[1], 4, LINUX_MSG_TRUNC);
            assert!(capacity >= 12, "host buffer must fit the queued datagram");
            let mut host = vec![0u8; capacity];
            let received = libc::recv(
                sockets[1],
                host.as_mut_ptr().cast(),
                host.len(),
                libc::MSG_TRUNC | libc::MSG_DONTWAIT,
            );
            assert_eq!(received, 12);
            assert_eq!(&host[..4], b"twel");

            libc::close(sockets[0]);
            libc::close(sockets[1]);
        }
    }
}

impl SyscallDispatcher {
    fn host_socket_send_view(&self, fd: i32) -> Result<SocketSendView, LinuxErrno> {
        let (host_fd, family) = self.host_socket_lookup(fd)?;
        let (cork_enabled, has_pending_cork) = self.open_file(fd).map_or((false, false), |of| {
            let cork = of.description.common().cork();
            (cork.enabled, !cork.buffer.is_empty())
        });
        Ok(SocketSendView {
            host_fd,
            family,
            cork_enabled,
            has_pending_cork,
        })
    }

    /// `sendmmsg(sockfd, msgvec, vlen, flags)` — Linux's batched
    /// sendmsg. glibc's getaddrinfo uses sendmmsg for DNS queries even
    /// when only a single message is sent; without this handler the
    /// guest sees ENOSYS and bails with "Temporary failure resolving".
    /// Implemented as a loop over single sendmsgs, writing each entry's
    /// msg_len field with the bytes-sent on success.
    fn sendmmsg(
        &self,
        context: &crate::kernel::KernelContext,
        fd: Fd,
        msgvec: GuestPtr,
        vlen: u64,
        flags: u64,
        memory: &mut impl CurrentMmMemory,
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
            let outcome = match self.sendmsg_inner(context, fd, entry, flags, &*memory) {
                Ok(o) => o,
                // Surface the REAL errno the single-message path carries (a bad
                // fd is EBADF, not the blanket EFAULT — sendmmsg02). The
                // `match outcome` below keeps the multi-message semantics: a
                // failure after >=1 success still returns the count.
                Err(DispatchError::Errno(errno)) => DispatchOutcome::Errno { errno },
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
                        return DispatchOutcome::returned_i32(sent);
                    }
                    return DispatchOutcome::errno(errno);
                }
                other => return other,
            }
        }
        DispatchOutcome::returned_i32(sent)
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
        memory: &mut impl CurrentMmMemory,
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
                // Surface the REAL errno the single-message path carries (a bad
                // fd is EBADF, not the blanket EFAULT — recvmmsg01). The
                // `match outcome` below keeps the multi-message semantics: a
                // failure after >=1 success still returns the count.
                Err(DispatchError::Errno(errno)) => DispatchOutcome::Errno { errno },
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
                        return DispatchOutcome::returned_i32(received);
                    }
                    return DispatchOutcome::errno(errno);
                }
                other => return other,
            }
        }
        DispatchOutcome::returned_i32(received)
    }

    define_syscall! {
        fn sendto(this, cx, fd: Fd, buf: GuestPtr, len: u64, flags: u64, dest_addr: GuestPtr, addrlen: u64) {
            let fd = fd.0;
            let buf_addr = buf.0;
            let len = len as usize;
            let flags = flags as i32;
            let dest_addr = dest_addr.0;
            let dest_len = addrlen as u32;
            // AF_NETLINK send: treat the payload as an rtnetlink request and
            // queue a synthetic dump reply for the next recv.
            if this.fd_is_netlink(fd) {
                let bytes = match cx.memory.read_bytes(buf_addr, len) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                return Ok(this.netlink_send(cx.kernel, fd, &bytes));
            }
            let memory = &*cx.memory;
            if let Some(open_file) = this.open_file(fd)
                && let Some(open) = open_file.description.read()
            {
                match &*open {
                    OpenDescription::Packet { socket, .. } => {
                        let socket = Arc::clone(socket);
                        drop(open);
                        let bytes = match cx.memory.read_bytes(buf_addr, len) {
                            Ok(b) => b,
                            Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                        };
                        return Ok(socket.sendto(&mut *cx.memory, &bytes, flags, dest_addr, dest_len as u64));
                    }
                    OpenDescription::InMemorySocket { socket, .. } => {
                        let socket = Arc::clone(socket);
                        drop(open);
                        let bytes = match memory.read_bytes(buf_addr, len) {
                            Ok(b) => b,
                            Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                        };
                        match socket.send_stream(&bytes, Vec::new()) {
                            Ok(written) => {
                                this.notify_inmem_epoll();
                                return Ok(DispatchOutcome::returned_len(written)?);
                            }
                            Err(LINUX_EPIPE) => {
                                let outcome = DispatchOutcome::errno(LINUX_EPIPE);
                                if (flags & LINUX_MSG_NOSIGNAL) == 0 {
                                    return Ok(this.raise_sigpipe_on_epipe(cx, outcome));
                                } else {
                                    return Ok(outcome);
                                }
                            }
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        }
                    }
                    _ => {}
                }
            }
            let send_view = this.host_socket_send_view(fd)?;
            let (host_fd, family) = (send_view.host_fd, send_view.family);
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
            let (guest_domain, guest_type, guest_protocol) =
                match this.socket_guest_domain_type_and_protocol(fd) {
                    Some(triple) => (Some(triple.0), Some(triple.1), Some(triple.2)),
                    None => (None, None, None),
                };
            let is_stream = guest_type == Some(libc::SOCK_STREAM);
            let is_sctp_stream = is_stream && guest_protocol == Some(LINUX_IPPROTO_SCTP);
            let is_unix_stream = is_stream && guest_domain == Some(libc::AF_UNIX);
            let is_connected_stream = is_stream
                && !is_unix_stream
                && !is_sctp_stream
                && host_socket_is_connected(host_fd.get());

            // Linux move_addr_to_kernel bound: sizeof(struct sockaddr_storage) = 128
            const LINUX_SOCKADDR_STORAGE_MAX: usize = 128;

            // Read the destination sockaddr (if any) from guest memory up front,
            // then send with MSG_DONTWAIT through blocking_io: a full socket buffer
            // (EAGAIN) on a blocking fd waits for POLLOUT losslessly.
            let mut host_addr = if dest_addr == 0 {
                None
            } else {
                // Linux's move_addr_to_kernel rejects a negative addrlen or
                // addrlen > sizeof(sockaddr_storage) (128) with EINVAL before
                // touching the buffer (sendto01 "invalid to buffer length",
                // tolen = -1).
                if (dest_len as i32) < 0 || dest_len as usize > LINUX_SOCKADDR_STORAGE_MAX {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if is_connected_stream {
                    // On connected TCP / non-UNIX stream sockets, Linux ignores
                    // dest_addr after move_addr_to_kernel validation, while Darwin
                    // sendto with an address would fail with EISCONN. Send implicitly.
                    if dest_len > 0 && memory.read_bytes(dest_addr, dest_len as usize).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    None
                } else if is_unix_stream && host_socket_is_connected(host_fd.get()) {
                    // Connected AF_UNIX stream returns EISCONN if dest_len > 0.
                    // A zero length means no effective destination.
                    if dest_len > 0 {
                        if memory.read_bytes(dest_addr, dest_len as usize).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        return Ok(DispatchOutcome::errno(LINUX_EISCONN));
                    }
                    None
                } else {
                    // UDP, unconnected sockets, etc. parse destination sockaddr.
                    match read_linux_sockaddr(memory, dest_addr, dest_len, family) {
                        Ok(b) => Some(b),
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    }
                }
            };
            if !is_connected_stream
                && family == LINUX_AF_INET
                && let Some(protocol) = this.socket_port_protocol(fd)
                && let Some(requested) = host_addr
                    .as_deref()
                    .and_then(host_sockaddr_to_socket_addr)
                    .or_else(|| this.connected_guest_peer_addr(fd))
            {
                if let Ok(bytes) = memory.read_bytes(buf_addr, len)
                    && this.maybe_queue_icmp_echo_reply(fd, &bytes, requested)
                {
                    return Ok(DispatchOutcome::returned_len(len)?);
                }
                if protocol == PortProtocol::Udp
                    && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
                    && let Ok(bytes) = memory.read_bytes(buf_addr, len)
                    && this.maybe_queue_dns_response(fd, &bytes, requested)
                {
                    return Ok(DispatchOutcome::returned_len(len)?);
                }
                match this.network.provider.resolve_connect(
                    this.network.spec.namespace_id.as_ref(),
                    GuestSocketAddr(requested),
                    protocol,
                ) {
                    Ok(ConnectTarget::Host(host)) => {
                        if let Some(mapped) = socket_addr_to_host_sockaddr(host.0) {
                            host_addr = Some(mapped);
                        }
                    }
                    Ok(ConnectTarget::Unchanged) => {}
                    Ok(ConnectTarget::Denied(errno))
                        if errno == carrick_abi::LINUX_ECONNREFUSED
                            && protocol == PortProtocol::Udp
                            && this.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM) =>
                    {
                        // The datagram is dropped (nothing listens on the
                        // bridge-local target), but Linux still reports the
                        // send as successful. For a CONNECTED socket the
                        // asynchronous ICMP unreachable must then surface as
                        // POLLERR + recv ECONNREFUSED — arm the pending error
                        // exactly like a delivered ICMP would (the connect
                        // path already staged error_after_send).
                        if dest_addr == 0 {
                            this.queue_socket_error_after_send(fd);
                        }
                        return Ok(DispatchOutcome::returned_len(len)?);
                    }
                    Ok(ConnectTarget::Intercept(_)) => {
                        return Ok(DispatchOutcome::errno(carrick_abi::LINUX_ECONNREFUSED))
                    }
                    Ok(ConnectTarget::Denied(errno)) => return Ok(DispatchOutcome::errno(errno)),
                    Err(_) => return Ok(DispatchOutcome::errno(carrick_abi::LINUX_ECONNREFUSED)),
                }
            }
            // On connected SCTP stream sockets (backed by host TCP), clear host_addr
            // after address validation / provider routing so Darwin sends implicitly.
            let mut host_addr = if is_sctp_stream && host_socket_is_connected(host_fd.get()) {
                None
            } else {
                host_addr
            };
            // MSG_MORE corks only the IP transports (UDP datagrams and TCP
            // streams). The native-arm64 Docker oracle for `socketcredmore`
            // shows an AF_UNIX SOCK_DGRAM send with MSG_MORE going out at once.
            let is_msg_more = carrick_abi::LinuxMsgFlags::from_bits_retain(flags)
                .contains(carrick_abi::LinuxMsgFlags::MORE)
                && matches!(send_view.family, LINUX_AF_INET | LINUX_AF_INET6);
            let (is_cork_enabled, has_pending_cork) =
                (send_view.cork_enabled, send_view.has_pending_cork);

            if is_cork_enabled || is_msg_more {
                let data = unsafe { std::slice::from_raw_parts(data_ptr, len) };
                if let Some(open_file) = this.open_file(fd) {
                    open_file
                        .description
                        .common()
                        .cork()
                        .stage(data, host_addr.as_deref());
                }
                return Ok(DispatchOutcome::returned_len(len)?);
            }

            let pending_cork_data = if has_pending_cork {
                this.open_file(fd).and_then(|open_file| {
                    open_file.description.common().cork().take()
                })
            } else {
                None
            };

            let (combined_buf, current_payload_len) = if let Some((mut buf, dest)) = pending_cork_data {
                if host_addr.is_none() {
                    host_addr = dest;
                }
                let cur = len;
                buf.extend_from_slice(unsafe { std::slice::from_raw_parts(data_ptr, len) });
                (Some(buf), cur)
            } else {
                (None, len)
            };

            let (data_ptr, len) = if let Some(ref buf) = combined_buf {
                (buf.as_ptr(), buf.len())
            } else {
                (data_ptr, len)
            };

            let nonblocking = this.io_is_nonblocking(fd, flags);
            let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
            let connected_send = dest_addr == 0;
            // Resolve the error-queue shadow BEFORE entering the I/O closure:
            // it needs this socket's own bound address, and the closure cannot
            // borrow `this`.
            let recverr_send_fd = match (&host_addr, recverr::is_enabled(host_fd.get())) {
                (Some(dest), true) => host_sockaddr_bytes(host_fd.get())
                    .and_then(|local| recverr::shadow_for_send(host_fd.get(), &local, dest)),
                _ => None,
            };
            let send_to = this
                .open_file(fd)
                .and_then(|f| f.description.read()?.send_timeout());
            let outcome = this.blocking_io(fd, host_fd.get(), IoDir::Write, nonblocking, send_to, || {
                // Re-stated locally (idempotent) so the non-blocking guarantee
                // is visible at every send site below: both the real socket and
                // the error-queue shadow are O_NONBLOCK, and MSG_DONTWAIT keeps
                // that true per call.
                let host_flags = host_flags | libc::MSG_DONTWAIT;
                // Publish the SCTP boundary BEFORE the host send: the peer can
                // read the bytes the instant it returns.
                let pending_sctp = if is_sctp_stream {
                    sctp::begin_send(host_fd.get(), len)
                } else {
                    None
                };
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
                    // An error-queue socket sends through its shadow (same
                    // local addr:port, connected to this destination), so Darwin
                    // reports the returning ICMP error — it reports nothing on
                    // an unconnected socket. The shadow is already connected, so
                    // the destination is implicit: Darwin answers EISCONN for a
                    // `sendto` that names an address on a connected socket.
                    // No shadow means send normally; losing the datagram would
                    // be far worse than losing the error report.
                    Some(a) => {
                        let host_flags = host_flags | libc::MSG_DONTWAIT;
                        match recverr_send_fd {
                            Some(shadow) => unsafe {
                                libc::sendto(
                                    shadow,
                                    data_ptr as *const _,
                                    len,
                                    host_flags,
                                    std::ptr::null(),
                                    0,
                                )
                            },
                            None => unsafe {
                                libc::sendto(
                                    host_fd.get(),
                                    data_ptr as *const _,
                                    len,
                                    host_flags,
                                    a.as_ptr() as *const _,
                                    a.len() as u32,
                                )
                            },
                        }
                    }
                };
                let result = match n.host_syscall_errno().map(|value| value as i64) {
                    Err(LINUX_ENOTCONN) if is_stream => Err(LINUX_EPIPE),
                    other => other,
                };
                if let Some(pending) = pending_sctp {
                    pending.settle(result.ok().map(|sent| sent.max(0) as usize));
                }
                result
            });
            if connected_send && matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
                this.queue_socket_error_after_send(fd);
            }
            Ok(this.settle_cork_send(
                fd,
                outcome,
                combined_buf.as_deref(),
                len - current_payload_len,
                nonblocking,
            ))
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
                let drained = this.netlink_recv(fd, buf_addr, len, flags, memory);
                if let DispatchOutcome::Returned { .. } = drained
                    && src_addr != 0
                    && src_len_addr != 0
                {
                    let nl = sockaddr_nl_bytes(0, 0);
                    let _ = write_linux_sockaddr(memory, src_addr, src_len_addr, &nl);
                }
                return Ok(drained);
            }
            if let Some(open_file) = this.open_file(fd)
                && let Some(open) = open_file.description.read()
            {
                match &*open {
                    OpenDescription::Packet { socket, .. } => {
                        let socket = Arc::clone(socket);
                        drop(open);
                        return Ok(socket.recvfrom(memory, buf_addr, len, flags, src_addr, src_len_addr));
                    }
                    OpenDescription::InMemorySocket { socket, .. } => {
                        let socket = Arc::clone(socket);
                        drop(open);
                        let mut target_buf = vec![0u8; len];
                        match socket.recv_stream(&mut target_buf, 0) {
                            Ok((read_len, _rights)) => {
                                if read_len > 0 {
                                    if memory.write_bytes(buf_addr, &target_buf[..read_len]).is_err() {
                                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                                    }
                                }
                                if let Some(peer) = socket.peer_addr() {
                                    if src_addr != 0 && src_len_addr != 0 {
                                        if let Some(sockaddr_bytes) = socket_addr_to_linux_sockaddr(peer) {
                                            let _ = write_linux_sockaddr(
                                                memory,
                                                src_addr,
                                                src_len_addr,
                                                &sockaddr_bytes,
                                            );
                                        }
                                    }
                                }
                                return Ok(DispatchOutcome::returned_len(read_len)?);
                            }
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        }
                    }
                    _ => {}
                }
            }
            let (host_fd, family) = this.host_socket_lookup(fd)?;
            if family == LINUX_AF_UNIX
                && LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::OOB)
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // MSG_ERRQUEUE reads the socket's error queue. carrick keeps no
            // error queue, so it's always empty → EAGAIN (recv01/recvfrom01),
            // matching Linux when no error is queued. Checked after the socket
            // lookup so a bad/non-socket fd still surfaces EBADF/ENOTSOCK.
            // (from_bits_retain: recv IGNORES other unknown flag bits.)
            if LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::ERRQUEUE) {
                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
            }
            if let Some((payload, source)) = this.synthetic_datagram_drain(fd) {
                let take = payload.len().min(len);
                if take > 0 && memory.write_bytes(buf_addr, &payload[..take]).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if src_addr != 0
                    && src_len_addr != 0
                    && write_linux_sockaddr(memory, src_addr, src_len_addr, &source).is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::returned_len(take)?);
            }
            // An error-queue socket's ICMP error goes ONLY to the queue — that
            // is what `IP_RECVERR` is FOR. The ordinary read must still answer
            // EAGAIN, which libuv reports as a zero-length receive.
            // `udp_send_unreachable` pins this: its `recv_cb` treats a NEGATIVE
            // nread carrying no `UV_UDP_LINUX_RECVERR` flag as
            // `ASSERT(0 && "unexpected error")`.
            recverr::poll_errors(host_fd.get());
            if let Some(errno) = this.take_socket_pending_error(fd) {
                return Ok(DispatchOutcome::errno(errno));
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
            let atomic_record = matches!(
                this.socket_guest_type(fd),
                Some(LINUX_SOCK_DGRAM) | Some(LINUX_SOCK_SEQPACKET)
            );
            let host_recv_len = if atomic_record {
                linux_msg_trunc_recv_capacity(host_fd.get(), len, flags)
            } else {
                len
            };
            // Zero-copy recv straight INTO guest memory when the destination is
            // one contiguous, guest-writable region; else recv into a bounce and
            // copy. host_ptr_for_write enforces guest-writability (a read-only
            // mapping returns None → checked write path → EFAULT).
            // Linux MSG_TRUNC on an atomic record returns the full record length
            // while copying at most `len`; Darwin returns only the host buffer
            // length. Widen that host-only bounce to SO_RCVBUF, then copy only
            // the guest-requested prefix. Stream reads never widen: doing so
            // would consume bytes the guest did not request.
            let zc_dst = (host_recv_len == len)
                .then(|| memory.host_ptr_for_write(buf_addr, len))
                .flatten();
            let zero_copy = zc_dst.is_some();
            let mut recv_copy: Option<Vec<u8>> = if zero_copy {
                None
            } else {
                Some(vec![0u8; host_recv_len])
            };
            let dst_ptr: *mut u8 = match (zc_dst, recv_copy.as_mut()) {
                (Some(p), _) => p,
                (None, Some(b)) => b.as_mut_ptr(),
                (None, None) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
            };
            let recv_to = this
                .open_file(fd)
                .and_then(|f| f.description.read()?.recv_timeout());
            let recv_protocol = this.socket_port_protocol(fd);
            let received_source = std::cell::RefCell::new(None::<Vec<u8>>);
            let recv_targets: Vec<i32> = std::iter::once(host_fd.get())
                .chain(reuseport::steal_targets(host_fd.get()))
                .collect();
            let outcome = this.blocking_io(fd, host_fd.get(), IoDir::Read, nonblocking, recv_to, || {
                let host_write_ranges = [(buf_addr, len)];
                let host_write = zero_copy.then(|| {
                    carrick_guest_mem::HostWriteGuard::new(memory, &host_write_ranges)
                });
                let mut sa = [0u8; LINUX_SOCKADDR_STORAGE_SIZE];
                let mut sa_len: libc::socklen_t = sa.len() as libc::socklen_t;
                let used_addr = src_addr != 0;
                // SO_REUSEPORT: Darwin delivers every datagram to the last
                // socket that bound the addr:port, so take from the sibling
                // holding the group's work when this member's own socket is
                // empty. `recv_targets` is just this fd unless it is in a
                // multi-member group.
                let mut n = -1isize;
                let mut last_errno = None;
                // Re-stated locally (idempotent) so the non-blocking guarantee
                // is visible at BOTH recvfrom call sites below rather than only
                // at the outer binding — the host fd is O_NONBLOCK and this
                // runs inside `blocking_io`, and MSG_DONTWAIT keeps that true
                // per call.
                let host_flags = host_flags | libc::MSG_DONTWAIT;
                for target in &recv_targets {
                    sa_len = sa.len() as libc::socklen_t;
                    let attempt = if used_addr {
                        unsafe {
                            libc::recvfrom(
                                *target,
                                dst_ptr as *mut _,
                                host_recv_len,
                                host_flags,
                                sa.as_mut_ptr() as *mut _,
                                &mut sa_len as *mut _,
                            )
                        }
                    } else {
                        unsafe {
                            libc::recvfrom(
                                *target,
                                dst_ptr as *mut _,
                                host_recv_len,
                                host_flags,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            )
                        }
                    };
                    match attempt.host_syscall_errno() {
                        Ok(_) => {
                            n = attempt;
                            last_errno = None;
                            break;
                        }
                        // Only an empty socket is worth trying the next member
                        // for; any other errno is this recv's real answer.
                        Err(e) if e == LINUX_EAGAIN => last_errno = Some(e),
                        Err(e) => {
                            last_errno = Some(e);
                            break;
                        }
                    }
                }
                let n = match last_errno {
                    Some(e) => {
                        drop(host_write);
                        return Err(e);
                    }
                    None => n,
                };
                // Close the odd-generation bracket before interpreting any
                // result or touching `memory` again. Drop also runs on unwind.
                drop(host_write);
                let n = n.host_syscall_errno()?;
                if !zero_copy
                    && n > 0
                    && let Some(b) = recv_copy.as_ref()
                    && memory
                        .write_bytes(buf_addr, &b[..(n as usize).min(len)])
                        .is_err()
                {
                    return Err(LINUX_EFAULT);
                }
                if used_addr && src_addr != 0 && src_len_addr != 0 {
                    let used = (sa_len as usize).min(sa.len());
                    received_source.borrow_mut().replace(sa[..used].to_vec());
                }
                Ok(n as i64)
            });
            if matches!(outcome, DispatchOutcome::Returned { .. }) {
                // This member took the group's turn; hand it to the next.
                reuseport::advance_turn(host_fd.get());
            }
            if matches!(outcome, DispatchOutcome::Returned { .. })
                && src_addr != 0
                && src_len_addr != 0
                && let Some(host_source) = received_source.into_inner()
            {
                let linux_bytes = if let Some(protocol) = recv_protocol
                    && let Some(host_addr) = host_sockaddr_to_socket_addr(&host_source)
                    && let Ok(Some(guest_addr)) =
                        this.network
                            .provider
                            .translate_recv_addr(HostSocketAddr(host_addr), protocol)
                    && let Some(guest_sockaddr) = socket_addr_to_linux_sockaddr(guest_addr.0)
                {
                    guest_sockaddr
                } else {
                    host_to_linux_sockaddr(&host_source, family, true)
                };
                if write_linux_sockaddr(memory, src_addr, src_len_addr, &linux_bytes).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
            }
            Ok(outcome)
        }

        fn sendmsg(this, cx, fd: Fd, msg: GuestPtr, flags: u64) {
            this.sendmsg_inner(cx.kernel, fd.0, msg.0, flags as i32, &*cx.memory)
        }

        fn recvmsg(this, cx, fd: Fd, msg: GuestPtr, flags: u64) {
            this.recvmsg_inner(fd.0, msg.0, flags as i32, &mut *cx.memory)
        }

        fn sys_recvmmsg(this, cx, fd: Fd, mmsg: GuestPtr, vlen: u64, flags: u64, timeout: GuestPtr) {
            Ok(this.recvmmsg(fd, mmsg, vlen, flags, timeout, cx.memory))
        }

        fn sys_sendmmsg(this, cx, fd: Fd, mmsg: GuestPtr, vlen: u64, flags: u64) {
            Ok(this.sendmmsg(cx.kernel, fd, mmsg, vlen, flags, cx.memory))
        }
    }

    fn sendmsg_inner(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        msg_addr: u64,
        flags: i32,
        memory: &impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let is_netlink = self.fd_is_netlink(fd);
        if let Some(open_file) = self.open_file(fd)
            && let Some(open) = open_file.description.read()
            && let OpenDescription::InMemorySocket { socket, .. } = &*open
        {
            let socket = Arc::clone(socket);
            drop(open);
            let msg = read_linux_msghdr(memory, msg_addr)?;
            let iovecs = read_iovecs(memory, msg.iov, msg.iovlen as usize)?;
            let mut data = Vec::new();
            for iov in iovecs {
                if iov.iov_len == 0 {
                    continue;
                }
                let chunk = match memory.read_bytes(iov.iov_base, iov.iov_len as usize) {
                    Ok(b) => b,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                data.extend_from_slice(&chunk);
            }
            match socket.send_stream(&data, Vec::new()) {
                Ok(written) => {
                    self.notify_inmem_epoll();
                    return Ok(DispatchOutcome::returned_len(written)?);
                }
                Err(LINUX_EPIPE) => {
                    return Ok(DispatchOutcome::errno(LINUX_EPIPE));
                }
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
        }
        let send_view = if is_netlink {
            None
        } else {
            Some(self.host_socket_send_view(fd)?)
        };
        let (host_fd, family) = send_view.map_or((HostFd(-1), LINUX_AF_NETLINK), |view| {
            (view.host_fd, view.family)
        });
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
            return Ok(self.netlink_send(context, fd, &data));
        }
        let mut host_addr = if msg.name == 0 || msg.namelen == 0 {
            None
        } else {
            match read_linux_sockaddr(memory, msg.name, msg.namelen, family) {
                Ok(b) => Some(b),
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
        };
        // MSG_MORE corks only the IP transports; see the sendto arm.
        let is_msg_more = carrick_abi::LinuxMsgFlags::from_bits_retain(flags)
            .contains(carrick_abi::LinuxMsgFlags::MORE)
            && matches!(family, LINUX_AF_INET | LINUX_AF_INET6);
        let (is_cork_enabled, has_pending_cork) = send_view.map_or((false, false), |view| {
            (view.cork_enabled, view.has_pending_cork)
        });

        if is_cork_enabled || is_msg_more {
            let data_len = data.len();
            if let Some(open_file) = self.open_file(fd) {
                open_file
                    .description
                    .common()
                    .cork()
                    .stage(&data, host_addr.as_deref());
            }
            return Ok(DispatchOutcome::returned_len(data_len)?);
        }

        let pending_cork_data = if has_pending_cork {
            self.open_file(fd)
                .and_then(|open_file| open_file.description.common().cork().take())
        } else {
            None
        };

        let current_payload_len = data.len();
        if let Some((mut buf, dest)) = pending_cork_data {
            if host_addr.is_none() {
                host_addr = dest;
            }
            buf.extend_from_slice(&data);
            data = buf;
        }
        if family == LINUX_AF_INET
            && self.socket_guest_type(fd) == Some(LINUX_SOCK_DGRAM)
            && let Some(requested) = host_addr
                .as_deref()
                .and_then(host_sockaddr_to_socket_addr)
                .or_else(|| self.connected_guest_peer_addr(fd))
        {
            if self.maybe_queue_icmp_echo_reply(fd, &data, requested)
                || self.socket_port_protocol(fd) == Some(PortProtocol::Udp)
                    && self.maybe_queue_dns_response(fd, &data, requested)
            {
                return Ok(DispatchOutcome::returned_len(data.len())?);
            }
        }
        // SCM_RIGHTS ancillary data (passing fds over AF_UNIX). Read the guest's
        // Linux-layout control buffer, extract the guest fds, map each to its
        // backing host fd, and build a host-layout control buffer for the real
        // sendmsg. This is the multiprocessing forkserver's fd-handoff path.
        let mut host_control: Vec<u8> = Vec::new();
        // Lives until the host sendmsg has settled: it owns the placeholder
        // fds named by `host_control` and un-parks them if the send fails.
        let mut rights = scm_rights::InFlightRights::new();
        if msg.control != 0 && msg.controllen > 0 {
            let raw = memory.read_bytes(msg.control, msg.controllen as usize)?;
            let guest_fds = parse_linux_scm_rights_fds(&raw);
            if !guest_fds.is_empty() {
                for gfd in &guest_fds {
                    if let Err(errno) = self.add_scm_right(&mut rights, *gfd) {
                        rights.abort();
                        return Ok(DispatchOutcome::errno(errno));
                    }
                }
                host_control = build_host_scm_rights(rights.host_fds());
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
        // A guest SCTP stream is backed by TCP, which carries no message
        // boundaries; record where each message ends so the receiver can report
        // MSG_EOR the way Linux does.
        let (guest_domain, guest_type, guest_protocol) =
            match self.socket_guest_domain_type_and_protocol(fd) {
                Some(triple) => (Some(triple.0), Some(triple.1), Some(triple.2)),
                None => (None, None, None),
            };
        let is_stream = guest_type == Some(libc::SOCK_STREAM);
        let is_sctp_stream = is_stream && guest_protocol == Some(LINUX_IPPROTO_SCTP);
        let is_unix_stream = is_stream && guest_domain == Some(libc::AF_UNIX);
        if is_unix_stream && host_addr.is_some() && host_socket_is_connected(host_fd.get()) {
            return Ok(DispatchOutcome::errno(LINUX_EISCONN));
        }
        let payload_len = data.len();
        let send_to = self
            .open_file(fd)
            .and_then(|f| f.description.read()?.send_timeout());
        // An error-queue socket sends through its shadow so Darwin will report
        // the returning ICMP error (it reports nothing on an unconnected
        // socket). Same bytes and same source address on the wire. libuv's
        // `uv_udp_send` lowers to sendmsg, not sendto, so this path needs the
        // routing just as much as `sendto` does.
        let recverr_send_fd = match (&host_addr, recverr::is_enabled(host_fd.get())) {
            (Some(dest), true) => host_sockaddr_bytes(host_fd.get())
                .and_then(|local| recverr::shadow_for_send(host_fd.get(), &local, dest)),
            _ => None,
        };
        let outcome = self.blocking_io(
            fd,
            host_fd.get(),
            IoDir::Write,
            nonblocking,
            send_to,
            || {
                // Use a real sendmsg so the host control buffer (SCM_RIGHTS) is
                // delivered. A single iovec over the assembled `data` is fine —
                // the byte stream is identical to the guest's scattered iovecs.
                let mut hiov = libc::iovec {
                    iov_base: data.as_ptr() as *mut libc::c_void,
                    iov_len: data.len(),
                };
                let mut hmsg: libc::msghdr = unsafe { std::mem::zeroed() };
                // The shadow is already CONNECTED to this destination, and Darwin
                // answers EISCONN for a send that names an address on a connected
                // socket — so address it implicitly there.
                // Similarly, connected TCP/stream sockets ignore dest_addr on Linux,
                // while Darwin answers EISCONN if named.
                if let Some(a) = &host_addr
                    && recverr_send_fd.is_none()
                    && !(is_stream && !is_unix_stream && host_socket_is_connected(host_fd.get()))
                {
                    hmsg.msg_name = a.as_ptr() as *mut libc::c_void;
                    hmsg.msg_namelen = a.len() as libc::socklen_t;
                }
                hmsg.msg_iov = &mut hiov as *mut _;
                hmsg.msg_iovlen = 1;
                if !host_control.is_empty() {
                    hmsg.msg_control = host_control.as_ptr() as *mut libc::c_void;
                    hmsg.msg_controllen = host_control.len() as _;
                }
                let send_fd = recverr_send_fd.unwrap_or_else(|| host_fd.get());
                // Re-stated locally (idempotent): both the real socket and the
                // error-queue shadow are O_NONBLOCK, and MSG_DONTWAIT keeps this
                // call non-blocking regardless.
                let host_flags = host_flags | libc::MSG_DONTWAIT;
                let pending_sctp = if is_sctp_stream {
                    sctp::begin_send(send_fd, payload_len)
                } else {
                    None
                };
                let n = unsafe { libc::sendmsg(send_fd, &hmsg as *const _, host_flags) };
                let result = n.host_syscall_errno().map(|value| value as i64);
                if let Some(pending) = pending_sctp {
                    pending.settle(result.ok().map(|sent| sent.max(0) as usize));
                }
                result
            },
        );
        // A delivered message holds its own dups of the placeholders; anything
        // else (errno, or a blocking hand-off that will retry WITHOUT this
        // control buffer) means the parked descriptions can never be claimed.
        if matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
            drop(rights);
        } else {
            rights.abort();
        }
        Ok(self.settle_cork_send(
            fd,
            outcome,
            Some(&data),
            data.len() - current_payload_len,
            nonblocking,
        ))
    }

    /// Translate the host's accepted byte count into the guest's `send`
    /// result when the host call carried `cork_len` previously corked bytes
    /// ahead of this call's payload.
    ///
    /// The host is the send-queue authority: it reports how many bytes it
    /// actually queued, and a stream socket with a small `SO_SNDBUF` accepts
    /// a partial write routinely. Reporting the full payload length in that
    /// case told the guest bytes were queued that never were — asyncio's
    /// sendfile fallback (`cpython-asyncio` `test_sendfile_*`) lost 4 KiB
    /// slices of a 1 MiB transfer that way. Linux semantics: the corked bytes
    /// belong to the kernel queue already, so this call's count is whatever
    /// the host accepted beyond them; if the host accepted none of this
    /// payload, the call did not make progress and a non-blocking sender
    /// sees `EAGAIN`. Unsent corked bytes go back to the front of the cork
    /// buffer so the next send or the close-time flush still delivers them
    /// in order.
    fn settle_cork_send(
        &self,
        fd: i32,
        outcome: DispatchOutcome,
        combined: Option<&[u8]>,
        cork_len: usize,
        nonblocking: bool,
    ) -> DispatchOutcome {
        let DispatchOutcome::Returned { value } = outcome else {
            if cork_len > 0
                && let Some(combined) = combined
            {
                self.restore_cork_prefix(fd, &combined[..cork_len]);
            }
            return outcome;
        };
        if value < 0 || cork_len == 0 {
            return outcome;
        }
        let sent = value as usize;
        if sent < cork_len {
            if let Some(combined) = combined {
                self.restore_cork_prefix(fd, &combined[sent..cork_len]);
            }
            return if nonblocking {
                DispatchOutcome::errno(LINUX_EAGAIN)
            } else {
                DispatchOutcome::Returned { value: 0 }
            };
        }
        let payload_sent = sent - cork_len;
        if payload_sent == 0 && nonblocking {
            return DispatchOutcome::errno(LINUX_EAGAIN);
        }
        DispatchOutcome::returned_len_or_errno(payload_sent)
    }

    /// Put not-yet-accepted corked bytes back ahead of anything corked since.
    fn restore_cork_prefix(&self, fd: i32, unsent: &[u8]) {
        if unsent.is_empty() {
            return;
        }
        if let Some(open_file) = self.open_file(fd) {
            open_file.description.common().cork().restore_prefix(unsent);
        }
    }

    /// Serve one `recvmsg(MSG_ERRQUEUE)` from this socket's modelled Linux
    /// error queue (see `dispatch::net::recverr`).
    ///
    /// Returns the entry as a `sock_extended_err` + `SO_EE_OFFENDER` cmsg with
    /// `MSG_ERRQUEUE` set in the returned `msg_flags` — libuv checks that flag
    /// before it will even look at the cmsgs. An empty queue is `EAGAIN`,
    /// exactly as a drained Linux queue is, which is what ends libuv's
    /// errqueue-drain loop.
    fn recvmsg_errqueue(
        &self,
        fd: i32,
        msg_addr: u64,
        msg: &LinuxMsghdr,
        memory: &mut impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let Ok((host_fd, _family)) = self.host_socket_lookup(fd) else {
            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
        };
        recverr::poll_errors(host_fd.get());
        let Some(entry) = recverr::pop(host_fd.get()) else {
            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
        };
        // The offending peer, in the guest's sockaddr layout, both as msg_name
        // and inside the cmsg (Linux puts it in both places).
        let offender = host_to_linux_sockaddr(
            &entry.offender,
            if entry.is_ipv6 {
                LINUX_AF_INET6
            } else {
                LINUX_AF_INET
            },
            true,
        );
        if msg.name != 0 && msg.namelen > 0 {
            let take = offender.len().min(msg.namelen as usize);
            if memory.write_bytes(msg.name, &offender[..take]).is_err() {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }
            let _ = memory.write_bytes(
                msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                &(offender.len() as u32).to_ne_bytes(),
            );
        }
        let mut linux_flags = crate::linux_abi::LINUX_MSG_ERRQUEUE;
        let cap = if msg.control != 0 {
            msg.controllen as usize
        } else {
            0
        };
        let (control, truncated) = build_linux_recverr(entry.errno, entry.is_ipv6, &offender, cap);
        if truncated {
            linux_flags |= crate::linux_abi::LINUX_MSG_CTRUNC;
        }
        if !control.is_empty() && memory.write_bytes(msg.control, &control).is_err() {
            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
        }
        let _ = memory.write_bytes(
            msg_addr + core::mem::offset_of!(LinuxMsghdr, controllen) as u64,
            &(control.len() as u64).to_ne_bytes(),
        );
        let _ = memory.write_bytes(
            msg_addr + core::mem::offset_of!(LinuxMsghdr, flags) as u64,
            &linux_flags.to_ne_bytes(),
        );
        // Linux returns the original datagram's payload here; libuv ignores it
        // and reads only the cmsg, so report zero bytes rather than inventing
        // a payload Carrick never captured.
        Ok(DispatchOutcome::Returned { value: 0 })
    }

    fn recvmsg_inner(
        &self,
        fd: i32,
        msg_addr: u64,
        flags: i32,
        memory: &mut impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let is_netlink = self.fd_is_netlink(fd);
        if let Some(open_file) = self.open_file(fd)
            && let Some(open) = open_file.description.read()
            && let OpenDescription::InMemorySocket { socket, .. } = &*open
        {
            let socket = Arc::clone(socket);
            drop(open);
            let msg = read_linux_msghdr(memory, msg_addr)?;
            if (msg.namelen as i32) < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if msg.iovlen as usize > 1024 {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMSGSIZE));
            }
            let iovecs = read_iovecs(memory, msg.iov, msg.iovlen as usize)?;
            let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
            let mut target_buf = vec![0u8; total];
            match socket.recv_stream(&mut target_buf, 0) {
                Ok((read_len, _rights)) => {
                    let mut remaining = read_len;
                    let mut cursor = 0usize;
                    for iov in &iovecs {
                        if remaining == 0 {
                            break;
                        }
                        let take = remaining.min(iov.iov_len as usize);
                        if take > 0 {
                            if memory
                                .write_bytes(iov.iov_base, &target_buf[cursor..cursor + take])
                                .is_err()
                            {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                            cursor += take;
                            remaining -= take;
                        }
                    }
                    if let Some(peer) = socket.peer_addr() {
                        if msg.name != 0 && msg.namelen != 0 {
                            if let Some(sockaddr_bytes) = socket_addr_to_linux_sockaddr(peer) {
                                let take = sockaddr_bytes.len().min(msg.namelen as usize);
                                if memory
                                    .write_bytes(msg.name, &sockaddr_bytes[..take])
                                    .is_err()
                                {
                                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                                }
                                let _ = memory.write_bytes(
                                    msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                                    &(sockaddr_bytes.len() as u32).to_ne_bytes(),
                                );
                            }
                        }
                    }
                    return Ok(DispatchOutcome::returned_len(read_len)?);
                }
                Err(LINUX_EAGAIN) => return Ok(DispatchOutcome::errno(LINUX_EAGAIN)),
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
        }
        let (host_fd, family) = if is_netlink {
            (HostFd(-1), LINUX_AF_NETLINK)
        } else {
            self.host_socket_lookup(fd)?
        };
        let msg = read_linux_msghdr(memory, msg_addr)?;
        // Linux validates the msghdr during copy-in before touching the flags: a
        // negative msg_namelen is EINVAL (recvmsg01 "invalid socket length",
        // which passes flags=-1 so its MSG_ERRQUEUE bit must NOT short-circuit
        // ahead of this check).
        if !is_netlink && (msg.namelen as i32) < 0 {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }
        // MSG_ERRQUEUE reads the socket's error queue. carrick keeps no error
        // queue, so it's always empty -> EAGAIN (recvmsg01), matching Linux when
        // no error is queued. Checked after msghdr validation so an invalid
        // msg_namelen still surfaces EINVAL. (from_bits_retain: recvmsg IGNORES
        // other unknown flag bits.) Mirrors the recvfrom MSG_ERRQUEUE path.
        if !is_netlink && LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::ERRQUEUE) {
            return self.recvmsg_errqueue(fd, msg_addr, &msg, memory);
        }
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
            if total == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            let chunk = self.netlink_drain(fd, total);
            if chunk.is_empty() {
                return Ok(self.empty_netlink_recv(fd, flags));
            }
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
            return Ok(DispatchOutcome::returned_len(n)?);
        }
        let total: usize = iovecs.iter().map(|iov| iov.iov_len as usize).sum();
        if let Some((payload, source)) = self.synthetic_datagram_drain(fd) {
            let n = payload.len().min(total);
            let mut remaining = n;
            let mut cursor = 0usize;
            for iov in &iovecs {
                if remaining == 0 {
                    break;
                }
                let take = remaining.min(iov.iov_len as usize);
                if take > 0 {
                    if memory
                        .write_bytes(iov.iov_base, &payload[cursor..cursor + take])
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    cursor += take;
                    remaining -= take;
                }
            }
            if msg.name != 0 && msg.namelen != 0 {
                let write_len = (source.len() as u32).min(msg.namelen);
                if write_len > 0
                    && memory
                        .write_bytes(msg.name, &source[..write_len as usize])
                        .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                let _ = memory.write_bytes(
                    msg_addr + core::mem::offset_of!(LinuxMsghdr, namelen) as u64,
                    &(source.len() as u32).to_ne_bytes(),
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
            return Ok(DispatchOutcome::returned_len(n)?);
        }
        let nonblocking = self.io_is_nonblocking(fd, flags);
        let host_flags = linux_to_host_msg_flags(flags) | libc::MSG_DONTWAIT;
        let recv_to = self
            .open_file(fd)
            .and_then(|f| f.description.read()?.recv_timeout());
        let want_control = msg.control != 0 && msg.controllen > 0;
        // SCM_RIGHTS host fds received this call, ferried out of the I/O closure
        // (which may run on a retry) so they're installed/written-back exactly
        // once after a successful recvmsg. Same for the guest msg_flags.
        let received_host_fds = std::cell::RefCell::new(Vec::<i32>::new());
        // IPv6 RFC 3542 ancillary cmsgs (hop-limit/tclass/pktinfo) the host
        // returned, as (linux_cmsg_type, data) — forwarded to the guest below.
        let received_ipv6_cmsgs = std::cell::RefCell::new(Vec::<(i32, Vec<u8>)>::new());
        // See the recvfrom path: with `IP_RECVERR` the error belongs to the
        // QUEUE, not to this read, which must still answer EAGAIN.
        if !is_netlink {
            recverr::poll_errors(host_fd.get());
        }
        let guest_msg_flags = std::cell::Cell::new(0i32);
        // SCTP never merges two messages into one recvmsg and reports MSG_EOR
        // when a read consumes the END of one. Its TCP backing has neither
        // property, so cap the read at the current boundary and answer EOR from
        // the recorded one.
        let (_, guest_type, guest_protocol) = match self.socket_guest_domain_type_and_protocol(fd) {
            Some(triple) => (Some(triple.0), Some(triple.1), Some(triple.2)),
            None => (None, None, None),
        };
        let is_sctp_stream = guest_protocol == Some(LINUX_IPPROTO_SCTP);
        let sctp_peek = flags & LinuxMsgFlags::PEEK.bits() != 0;
        let sctp_eor = std::cell::Cell::new(false);
        // macOS reports MSG_TRUNC for a ZERO-length datagram read into a
        // zero-length buffer, where nothing is truncated and Linux reports none;
        // the genuinely-truncated case agrees on both. Telling them apart needs to
        // know whether the datagram carried payload, and `FIONREAD` cannot say —
        // on macOS it answers 16 for an EMPTY unix datagram and 17 for a one-byte
        // one, i.e. it includes per-datagram accounting overhead, and subtracting
        // a hardcoded 16 would be exactly the sort of magic offset that rots.
        //
        // So read into a ONE-byte scratch and look at what comes back. Linux
        // CONSUMES a datagram read into a zero-length buffer either way, so
        // consuming it here matches, and "did any byte arrive" answers it
        // directly. Restricted to datagram-shaped sockets — on a stream, a byte
        // the guest did not ask for must stay queued.
        let datagram_shaped = matches!(
            guest_type,
            Some(t) if t == libc::SOCK_DGRAM || t == libc::SOCK_SEQPACKET
        );
        let zero_len_datagram_read = total == 0 && datagram_shaped && !is_netlink;
        let scratch_saw_payload = std::cell::Cell::new(false);
        let recvmsg_targets: Vec<i32> = std::iter::once(host_fd.get())
            .chain(reuseport::steal_targets(host_fd.get()))
            .collect();
        let outcome =
            self.blocking_io(fd, host_fd.get(), IoDir::Read, nonblocking, recv_to, || {
                // A retry must not leak fds from a prior partial attempt.
                for stale in received_host_fds.borrow_mut().drain(..) {
                    unsafe { libc::close(stale) };
                }
                let capped = if is_sctp_stream {
                    sctp::read_limit(host_fd.get(), total)
                } else {
                    total
                };
                // Darwin returns only the host-buffer length for an atomic
                // recvmsg(MSG_TRUNC). Widen the host-only buffer so the return
                // value retains the full record length, while the scatter below
                // still copies no more than the guest iovec capacity.
                let host_recv_len = if datagram_shaped && !zero_len_datagram_read {
                    linux_msg_trunc_recv_capacity(host_fd.get(), capped, flags)
                } else if zero_len_datagram_read {
                    1
                } else {
                    capped
                };
                let mut buf = vec![0u8; host_recv_len];
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
                // SO_REUSEPORT: Darwin delivers every datagram to the last socket
                // that bound the addr:port, so take from the sibling holding the
                // group's work when this member's own socket is empty. Without
                // this the member whose TURN it is can never drain the group and
                // the readiness gate silences the others — a deadlock, not just a
                // skew. `recvmsg_targets` is just this fd unless it is in a
                // multi-member group.
                let mut n = -1isize;
                let mut last_errno = None;
                for target in &recvmsg_targets {
                    if msg.name != 0 {
                        hmsg.msg_namelen = sa.len() as libc::socklen_t;
                    }
                    if want_control {
                        hmsg.msg_controllen = hcontrol.len() as _;
                    }
                    let attempt =
                        unsafe { libc::recvmsg(*target, &mut hmsg as *mut _, host_flags) };
                    match attempt.host_syscall_errno() {
                        Ok(_) => {
                            n = attempt;
                            last_errno = None;
                            break;
                        }
                        Err(e) if e == LINUX_EAGAIN => last_errno = Some(e),
                        Err(e) => {
                            last_errno = Some(e);
                            break;
                        }
                    }
                }
                if let Some(e) = last_errno {
                    return Err(e);
                }
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
                let n = if zero_len_datagram_read {
                    // The guest asked for no bytes; anything the scratch caught only
                    // tells us the datagram was non-empty.
                    scratch_saw_payload.set(n > 0);
                    0
                } else {
                    n
                };
                let mut translated_flags = host_to_linux_msg_flags(hmsg.msg_flags);
                if datagram_shaped && flags & LINUX_MSG_TRUNC != 0 && n as usize > total {
                    translated_flags |= LINUX_MSG_TRUNC;
                }
                guest_msg_flags.set(translated_flags);
                if is_sctp_stream {
                    sctp_eor.set(sctp::complete_read(host_fd.get(), n as usize, sctp_peek));
                }
                Ok(n as i64)
            });
        // Install any received fds as fresh guest fds, then write the guest
        // (Linux-layout) control buffer + the controllen/flags fields. Done
        // OUTSIDE the I/O closure so it happens exactly once on success.
        let host_fds: Vec<i32> = received_host_fds.borrow_mut().drain(..).collect();
        if matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
            // This member took the group's turn; hand it to the next.
            reuseport::advance_turn(host_fd.get());
        }
        if matches!(outcome, DispatchOutcome::Returned { value } if value >= 0) {
            // from_bits_retain: recvmsg IGNORES unknown msg_flags bits.
            let cloexec =
                LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::CMSG_CLOEXEC);
            let mut guest_fds = Vec::with_capacity(host_fds.len());
            for hfd in host_fds {
                // An install failure (None) already closed `hfd`: the
                // freshly-built description became the fd's ONE owner, and
                // dropping it ran the close. (Historically the owner's drop
                // AND an explicit close here both fired — a latent EMFILE
                // double-close.)
                if let Some(gfd) = self.install_received_host_fd(hfd, cloexec) {
                    guest_fds.push(gfd);
                }
            }
            let mut linux_flags = guest_msg_flags.get();
            // MSG_CMSG_CLOEXEC has no macOS equivalent, so the host never reports
            // it and the translated flags come back without it. Linux ECHOES the
            // caller's request in msg_flags — Go's `TestSCMCredentials` asserts
            // exactly that, and the Docker oracle returns 0x40000000 where carrick
            // returned 0x0. The close-on-exec itself was already applied to the
            // installed fd; only the echo was missing.
            if LinuxMsgFlags::from_bits_retain(flags).contains(LinuxMsgFlags::CMSG_CLOEXEC) {
                linux_flags |= LinuxMsgFlags::CMSG_CLOEXEC.bits();
            }
            // SCTP: this read consumed the end of a message, which Linux reports
            // as MSG_EOR. The TCP backing cannot say so on its own.
            if sctp_eor.get() {
                linux_flags |= LinuxMsgFlags::EOR.bits();
            }
            // MSG_TRUNC reports a truncated ATOMIC record, so Linux sets it only
            // on datagram/seqpacket sockets — a stream has no record to truncate
            // and simply leaves the rest queued. macOS sets it on a stream too
            // when the data does not fit.
            if guest_type == Some(libc::SOCK_STREAM) {
                linux_flags &= !LinuxMsgFlags::TRUNC.bits();
            }
            // A zero-length read of a datagram truncates it only if it carried
            // payload; the scratch read above answers that directly.
            if zero_len_datagram_read {
                if scratch_saw_payload.get() {
                    linux_flags |= LinuxMsgFlags::TRUNC.bits();
                } else {
                    linux_flags &= !LinuxMsgFlags::TRUNC.bits();
                }
            }
            let mut written_controllen = 0u64;
            if want_control {
                let (mut scm, scm_trunc) =
                    build_linux_scm_rights(&guest_fds, msg.controllen as usize);
                // SO_PASSCRED: append an SCM_CREDENTIALS record with the peer's
                // ucred after any SCM_RIGHTS, bounded by the remaining control
                // budget. (audit M2)
                let mut cred_trunc = false;
                if !is_netlink && self.socket_so_passcred(fd) {
                    let (pid, uid, gid) = self.peer_ucred(fd);
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
