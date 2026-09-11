//! Synthetic AF_NETLINK socket implementation and rtnetlink dump response synthesis.
//!
//! macOS has no native AF_NETLINK socket family. This module models in-memory
//! synthetic AF_NETLINK fds (`OpenDescription::Netlink`), handles sending/receiving
//! rtnetlink dump requests/replies, and provides asynchronous netlink message
//! delivery (used e.g. by POSIX mqueue `SIGEV_THREAD` notification).

use super::support::build_netlink_reply_for_snapshot;
use super::*;
use std::collections::VecDeque;
use std::sync::Arc;

impl SyscallDispatcher {
    /// Create a synthetic AF_NETLINK socket. Linux accepts SOCK_RAW and
    /// SOCK_DGRAM for netlink (they're equivalent there); other socket
    /// types are rejected with ESOCKTNOSUPPORT, matching the kernel.
    pub(in crate::dispatch) fn netlink_socket(&self, type_: i32, protocol: i32) -> DispatchOutcome {
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
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
                base: OpenDescriptionBase::new(status_flags),
            },
            fd_flags,
        )
    }

    /// True iff `fd` refers to a synthetic AF_NETLINK socket.
    pub(in crate::dispatch) fn fd_is_netlink(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(
                of.description.read().as_deref(),
                Some(OpenDescription::Netlink { .. })
            )
        })
    }

    /// Handle a netlink "send": parse the request and queue a synthetic
    /// rtnetlink dump reply (or a bare NLMSG_DONE for requests we don't
    /// specifically model). Returns the number of bytes "sent".
    pub(in crate::dispatch) fn netlink_send(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        request: &[u8],
    ) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let reply = {
            let Some(open) = open_file.description.read() else {
                return DispatchOutcome::errno(LINUX_ENOTSOCK);
            };
            let OpenDescription::Netlink { pid, .. } = &*open else {
                return DispatchOutcome::errno(LINUX_ENOTSOCK);
            };
            let dest_pid = if *pid != 0 { *pid } else { std::process::id() };
            // ONE encoder, over the namespace the CALLING task belongs to. The
            // mode used to select between two encoders over two different data
            // sources — the spec-built model for bridge, a fresh `getifaddrs(3)`
            // walk for host — which is why the guest's own surfaces disagreed
            // with each other, and why the accurate encoder was the one the
            // conformance lane never exercised.
            let net_ns = self.caller_net_ns(context);
            build_netlink_reply_for_snapshot(request, dest_pid, &net_ns.view())
        };
        if let Some(mut open) = open_file.description.write() {
            if let OpenDescription::Netlink {
                recv_queue,
                wait_queue,
                ..
            } = &mut *open
            {
                let was_empty = recv_queue.is_empty();
                recv_queue.extend(reply);
                if was_empty && !recv_queue.is_empty() {
                    let wq = Arc::clone(wait_queue);
                    drop(open);
                    wq.wake_all();
                    self.notify_inmem_epoll();
                    crate::host_signal::wake_all_waiters();
                }
            }
        }
        DispatchOutcome::returned_len_or_errno(request.len())
    }

    /// recvfrom path for netlink: drain queued reply bytes into guest memory,
    /// or block/EAGAIN while a blocking caller waits for a future kernel event.
    pub(in crate::dispatch) fn netlink_recv(
        &self,
        fd: i32,
        buf_addr: u64,
        len: usize,
        flags: i32,
        memory: &mut impl CurrentMmMemory,
    ) -> DispatchOutcome {
        if len == 0 {
            return DispatchOutcome::Returned { value: 0 };
        }
        let chunk = self.netlink_drain(fd, len);
        if chunk.is_empty() {
            return self.empty_netlink_recv(fd, flags);
        }
        if !chunk.is_empty() && memory.write_bytes(buf_addr, &chunk).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::returned_len_or_errno(chunk.len())
    }

    /// Pop up to `max` bytes from the netlink recv queue. Our synthetic
    /// reply is built as one contiguous dump, so a single drain that fits
    /// the caller's buffer returns the whole thing.
    pub(super) fn netlink_drain(&self, fd: i32, max: usize) -> Vec<u8> {
        let Some(open_file) = self.open_file(fd) else {
            return Vec::new();
        };
        let Some(mut open) = open_file.description.write() else {
            return Vec::new();
        };
        let OpenDescription::Netlink { recv_queue, .. } = &mut *open else {
            return Vec::new();
        };
        let take = recv_queue.len().min(max);
        recv_queue.drain(..take).collect()
    }

    pub(super) fn empty_netlink_recv(&self, fd: i32, flags: i32) -> DispatchOutcome {
        if self.io_is_nonblocking(fd, flags) {
            return DispatchOutcome::errno(LINUX_EAGAIN);
        }
        let files = self.captured_file_table();
        let fds = match WaitFds::raw_one(-1, 0).with_guest_slots(&files, [fd]) {
            Ok(fds) => fds,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        DispatchOutcome::WaitOnFds {
            // Synthetic netlink sockets have no host fd to poll. A negative
            // pollfd is ignored by poll(2); enqueue_netlink_message publishes
            // queue state before waking the registered dispatcher-aware waiter,
            // which then re-samples this queue without a periodic timer.
            fds,
            timeout: None,
            sig_mask: carrick_abi::WaitSigMask::NONE,
            completion: FdWaitCompletion::Poll { on_timeout: 0 },
        }
    }

    /// Queue an asynchronous kernel-to-userspace netlink message on a synthetic
    /// AF_NETLINK fd. POSIX mqueue `SIGEV_THREAD` uses this path: glibc registers
    /// a NETLINK_ROUTE socket with `mq_notify`, then its helper thread blocks in
    /// `recvfrom` waiting for the kernel's 32-byte notification record.
    pub(in crate::dispatch) fn enqueue_netlink_message(
        &self,
        fd: i32,
        bytes: &[u8],
    ) -> Result<(), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let Some(mut open) = open_file.description.write() else {
            return Err(LINUX_EBADF);
        };
        let OpenDescription::Netlink {
            recv_queue,
            wait_queue,
            ..
        } = &mut *open
        else {
            return Err(LINUX_EBADF);
        };
        let wq = Arc::clone(wait_queue);
        recv_queue.extend(bytes);
        drop(open);
        wq.wake_all();
        self.notify_inmem_epoll();
        // A thread may be blocked in recvfrom() directly rather than through
        // an epoll instance. The queue mutation above is durable; wake the
        // dispatcher-aware private waiter so it re-samples the synthetic fd.
        crate::host_signal::wake_all_waiters();
        Ok(())
    }
}
