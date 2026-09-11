//! Emulated Linux event polling backed by Darwin `kqueue` (`epoll_create1`,
//! `epoll_ctl`, `epoll_pwait`, `epoll_pwait2`).
//!
//! Maps Linux edge-triggered and level-triggered events, one-shot
//! disarming, EPOLLEXCLUSIVE, and EPOLLWAKEUP to kqueue filters, and
//! coordinates with the in-memory wake registry for synthetic
//! events.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use carrick_abi::{
    LINUX_EBADF, LINUX_EEXIST, LINUX_EINVAL, LINUX_ENOENT, LINUX_EPERM, LINUX_EPOLL_CLOEXEC,
    LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL, LINUX_EPOLL_CTL_MOD, LINUX_EPOLLERR, LINUX_EPOLLET,
    LINUX_EPOLLHUP, LINUX_EPOLLIN, LINUX_EPOLLONESHOT, LINUX_EPOLLOUT, LINUX_EPOLLPRI,
    LINUX_EPOLLRDHUP, LinuxEpollEvent, LinuxEpollEvents, LinuxTimespec,
};

use super::support::*;
use super::*;
use crate::dispatch::{
    CurrentMmMemory, DispatchError, DispatchOutcome, Fd, FdWaitCompletion, GuestPtr, HostFd,
    OpenDescription, OpenFile, SyscallCtx, SyscallRequest,
};

const EPOLL_REBIND_REASON_IO_REARM: u32 = 1;
const EPOLL_REBIND_REASON_CLOSE_DETACH: u32 = 2;

const EPOLL_REBIND_REASON_WAIT_SAMPLE: u32 = 3;
const EPOLL_REBIND_REASON_CTL_DEL: u32 = 4;

fn remove_epoll_interest(
    interest: &mut HashMap<i32, EpollInterest>,
    synthetic_interest_count: &mut usize,
    fd: i32,
) -> Option<EpollInterest> {
    let removed = interest.remove(&fd)?;
    if !removed.host_poll_source {
        *synthetic_interest_count = synthetic_interest_count.saturating_sub(1);
    }
    Some(removed)
}

fn merge_epoll_edge_sample(
    accumulated: &mut (u32, u64),
    edge_bits: u32,
    edge_readiness_count: u64,
) {
    accumulated.0 |= edge_bits;
    // Darwin reports one kqueue record per direction. EVFILT_WRITE's `data`
    // is socket send-buffer capacity (often ~8 MiB), not readable bytes. Do
    // not let that count poison EPOLLET's read-growth baseline when read and
    // write records for one bidirectional socket land in the same batch.
    if edge_bits & LINUX_EPOLLIN != 0 {
        accumulated.1 = accumulated.1.max(edge_readiness_count);
    }
}

fn epoll_wait_sample_needs_host_rebind(
    before: u32,
    raw: u32,
    read_avail_changed: bool,
    clear_write_backpressure: bool,
    edge_drained: bool,
    masked_ready: bool,
    masked_arrival_source: bool,
) -> bool {
    // BSD edge filters use EV_DISPATCH and therefore need an explicit rebind
    // after a delivered event. A masked event whose readiness snapshot did not
    // change is different: re-adding the filter can immediately reproduce the
    // same event when NOTE_LOWAT cannot express `last_read_avail + 1` (for
    // example, a stream socket already at its receive-buffer ceiling, or a
    // consumption path rebinds it through `epoll_rearm_after_io`. Listening
    // sockets are different: EVFILT_READ `data` is the pending-connection
    // count, and the filter must stay armed so NOTE_LOWAT can observe a later
    // arrival even when a redundant delivery did not change the current count.
    before != raw
        || read_avail_changed
        || clear_write_backpressure
        || (edge_drained && (!masked_ready || masked_arrival_source))
}

fn epoll_io_progress_needs_host_rebind(
    before_ready: u32,
    after_ready: u32,
    before_read_avail: u64,
    after_read_avail: u64,
) -> bool {
    before_ready != after_ready || before_read_avail != after_read_avail
}

fn epoll_ready_sample_is_current(
    sampled_reg_gen: u32,
    sampled_io_gen: u64,
    live_reg_gen: u32,
    live_io_gen: u64,
) -> bool {
    sampled_reg_gen == live_reg_gen && sampled_io_gen == live_io_gen
}

#[cfg(test)]
mod epoll_edge_sample_tests {
    use super::*;

    #[test]
    fn writable_capacity_does_not_poison_read_growth_baseline() {
        let mut accumulated = (LINUX_EPOLLIN, 35);

        merge_epoll_edge_sample(&mut accumulated, LINUX_EPOLLOUT, 8 * 1024 * 1024);

        assert_eq!(accumulated, (LINUX_EPOLLIN | LINUX_EPOLLOUT, 35));
    }

    #[test]
    fn unchanged_masked_edge_stays_disarmed_until_io_progress() {
        assert!(!epoll_wait_sample_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            false,
            false,
            true,
            true,
            false,
        ));
        assert!(!epoll_wait_sample_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            false,
            false,
            false,
            true,
            false,
        ));
        assert!(epoll_wait_sample_needs_host_rebind(
            0,
            LINUX_EPOLLIN,
            true,
            false,
            true,
            false,
            false,
        ));
        assert!(epoll_wait_sample_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            false,
            false,
            true,
            true,
            true,
        ));

        assert!(epoll_wait_sample_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            false,
            false,
            true,
            false,
            false,
        ));
    }

    #[test]
    fn partial_read_progress_rebinds_the_lower_growth_threshold() {
        assert!(epoll_io_progress_needs_host_rebind(
            LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            8 * 1024 * 1024,
            3 * 1024 * 1024,
        ));
    }

    #[test]
    fn readiness_sample_before_io_cannot_relatch_consumed_edge() {
        assert!(!epoll_ready_sample_is_current(7, 11, 7, 12));
    }
}

impl<'a> NetView<'a> {
    fn fd_is_epollable(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        if open_file
            .description
            .concrete_backing::<crate::dispatch::ioring::IoUringBacking>()
            .is_some()
        {
            return true;
        }
        let Some(open) = open_file.description.read() else {
            return false;
        };
        match &*open {
            OpenDescription::File { .. }
            | OpenDescription::InMemoryFile { .. }
            | OpenDescription::Directory { .. }
            | OpenDescription::SyntheticFile { .. } => false,
            OpenDescription::HostFile { metadata, .. } => {
                matches!(metadata.kind, crate::rootfs::RootFsEntryKind::CharDevice)
            }
            _ => true,
        }
    }

    pub(super) fn fd_supports_epoll_oob(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        matches!(
            open_file.description.read().as_deref(),
            Some(OpenDescription::HostSocket { .. })
        )
    }

    fn fd_supports_read_lowat(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        matches!(
            open_file.description.read().as_deref(),
            Some(OpenDescription::HostSocket { .. })
        )
    }

    fn fd_is_listening_socket(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        matches!(
            open_file.description.read().as_deref(),
            Some(OpenDescription::HostSocket { base, .. }) if base.listening()
        )
    }

    fn epoll_path_reaches_desc(
        &self,
        current_desc: &Arc<crate::kernel::FileDescription>,
        target_id: crate::kernel::FileDescriptionId,
        depth: usize,
        seen: &mut std::collections::BTreeSet<crate::kernel::FileDescriptionId>,
    ) -> bool {
        if current_desc.id() == target_id || depth >= 5 || !seen.insert(current_desc.id()) {
            return true;
        }
        let Some(children) = current_desc.epoll_targets() else {
            return false;
        };
        children
            .into_iter()
            .any(|child| self.epoll_path_reaches_desc(&child, target_id, depth + 1, seen))
    }

    fn epoll_add_would_loop_desc(
        &self,
        target_desc: &Arc<crate::kernel::FileDescription>,
        epoll_id: crate::kernel::FileDescriptionId,
    ) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        self.epoll_path_reaches_desc(target_desc, epoll_id, 0, &mut seen)
    }

    pub(in crate::dispatch) fn epoll_effective_interest(
        &self,
        fd: i32,
        events: u32,
        last_ready: u32,
        last_read_avail: u64,
        write_backpressured: bool,
    ) -> carrick_hal::event::Interest {
        // Wire→typed seam: the guest event word is a raw u32; epoll ACCEPTS
        // unknown bits, so retain them rather than reject.
        let mut interest = epoll_interest_for(LinuxEpollEvents::from_bits_retain(events));
        // Guest EPOLLET is enforced by the software `last_ready` latch. Once
        // EPOLLOUT or a terminal HUP/ERR edge has been delivered, keeping write
        // interest armed can wake an epoll waiter for host writability that the
        // Linux-facing sampler will keep masking. Drop the write filter until
        // either guest I/O consumes the edge or a write returns EAGAIN and
        // explicitly asks to watch for writability again. Keep read armed:
        // read-side ET uses FIONREAD growth to detect a new edge while data
        // remains buffered.
        if events & LINUX_EPOLLET != 0 {
            if interest.write
                && last_ready & (LINUX_EPOLLOUT | LINUX_EPOLLHUP | LINUX_EPOLLERR) != 0
                && !write_backpressured
            {
                interest.write = false;
            }
            if interest.read {
                if last_ready & (LINUX_EPOLLHUP | LINUX_EPOLLERR) != 0 {
                    interest.read = false;
                } else if last_ready & LINUX_EPOLLIN != 0 {
                    if last_read_avail > 0 && self.fd_supports_read_lowat(fd) {
                        interest.read_lowat = Some(last_read_avail.saturating_add(1));
                    } else {
                        interest.read = false;
                    }
                }
            }
        }
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
        if interest.oob && !self.fd_supports_epoll_oob(fd) {
            interest.oob = false;
        }
        // FreeBSD/NetBSD kqueue has no usable OOB filter — `register_io` with an
        // OOB interest returns ENOTSUP and would fail the whole `epoll_ctl(ADD)`.
        // Unlike macOS (whose `poll(2)` never surfaces `POLLPRI`, so the
        // EVFILT_EXCEPT/NOTE_OOB filter is the only OOB signal), FreeBSD/NetBSD
        // native `poll(2)` DOES report `POLLPRI`, so EPOLLPRI readiness is
        // computed by the `libc::poll(POLLPRI)` recompute in `epoll_ready_events`
        // — the kqueue OOB filter is both unsupported and unnecessary here. Drop
        // it from the host registration only; the guest's requested EPOLLPRI
        // interest is unaffected (readiness still keys off `event.events`).
        // (probe `epollpri`.)
        #[cfg(any(feature = "platform-freebsd", feature = "platform-netbsd"))]
        {
            interest.oob = false;
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
        reason: u32,
        excluded_survivor_fd: Option<i32>,
    ) {
        let mut survivor: Option<(i32, u32)> = None;
        let mut union_events = 0u32;
        let mut union_interest = carrick_hal::event::Interest::default();
        let mut read_lowat: Option<Option<u64>> = None;
        for (&other, slot) in interest.iter() {
            if self.host_fd_for_poll(other) != Some(host_fd) {
                continue;
            }
            if Some(other) != excluded_survivor_fd {
                survivor.get_or_insert((other, slot.reg_gen));
            }
            union_events |= slot.event.events;
            let effective = self.epoll_effective_interest(
                other,
                slot.event.events,
                slot.last_ready,
                slot.last_read_avail,
                slot.write_backpressured,
            );
            union_interest.read |= effective.read;
            union_interest.write |= effective.write;
            union_interest.oob |= effective.oob;
            if effective.read {
                read_lowat = match (read_lowat, effective.read_lowat) {
                    (None, lowat) => Some(lowat),
                    (Some(Some(current)), Some(next)) => Some(Some(current.min(next))),
                    (Some(_), None) => Some(None),
                    (current, Some(_)) => current,
                };
            }
        }
        union_interest.read_lowat = read_lowat.flatten();
        let (survivor_fd, survivor_gen) = survivor.unwrap_or((-1, 0));
        let effective_bits = u32::from(union_interest.read)
            | (u32::from(union_interest.write) << 1)
            | (u32::from(union_interest.oob) << 2);
        crate::probes::epoll_rebind(
            reason,
            host_fd.get(),
            survivor_fd,
            survivor_gen,
            union_events,
            effective_bits,
        );

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

    pub(super) fn epoll_ready_events(&self, fd: i32, requested_events: u32) -> u32 {
        let Some(open_file) = self.open_file(fd) else {
            return 0;
        };
        let interest = carrick_abi::LinuxEpollEvents::from_bits_retain(requested_events);
        open_file.description.readiness(interest, self).bits()
    }

    pub(super) fn host_read_avail_for_poll(&self, fd: i32) -> u64 {
        // Bytes carrick queued on a socket outside the host kernel
        // (`synthetic_recv`). Counted into the ET read-growth baseline so a
        // gateway reply is a visible arrival, exactly as `pipe.buffered_bytes()`
        // is for an in-memory pipe; FIONREAD on the host fd cannot see them.
        let mut synthetic_bytes = 0u64;
        if let Some(open_file) = self.open_file(fd) {
            let Some(open) = open_file.description.read() else {
                return 0;
            };
            match &*open {
                OpenDescription::PipeReader { pipe, .. } => return pipe.buffered_bytes() as u64,
                OpenDescription::InMemorySocket { socket, .. } => {
                    return socket.buffered_bytes() as u64;
                }
                OpenDescription::HostSocket { synthetic_recv, .. } => {
                    synthetic_bytes = synthetic_recv
                        .iter()
                        .map(|(payload, _source)| payload.len() as u64)
                        .sum();
                }
                _ => {}
            }
        }
        let Some(host_fd) = self.host_fd_for_poll(fd) else {
            return synthetic_bytes;
        };
        let mut avail: libc::c_int = 0;
        let rc = unsafe { libc::ioctl(host_fd.get(), libc::FIONREAD, &mut avail) };
        let host = if rc == 0 && avail > 0 {
            avail as u64
        } else {
            0
        };
        host.saturating_add(self.staged_splice_pipe_bytes(fd) as u64)
            .saturating_add(synthetic_bytes)
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
        let positive_value = match outcome {
            DispatchOutcome::Returned { value } if *value > 0 => Some(*value as u64),
            _ => None,
        };
        let zero = matches!(outcome, DispatchOutcome::Returned { value } if *value == 0);
        let eagain = matches!(outcome, DispatchOutcome::Errno { errno } if *errno == LINUX_EAGAIN);
        let read_consumed = positive || zero || eagain;
        let write_consumed = positive;
        let a = |i: usize| request.arg(i) as i32;
        let read_progress_bytes = if positive {
            match request.number.raw() {
                // read / readv / pread64 / preadv / preadv2, recvfrom /
                // recvmsg / recvmmsg: positive return is bytes consumed.
                63 | 65 | 67 | 69 | 286 | 207 | 212 | 243 => positive_value,
                // sendfile/splice/copy_file_range/tee: positive return is bytes
                // consumed from the read-side fd.
                71 | 76 | 285 | 77 => positive_value,
                // accept/accept4 consume listener readiness but return a new fd,
                // not a byte count; clear the read latch outright.
                202 | 242 => None,
                _ => None,
            }
        } else {
            None
        };
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
        let epfds: Vec<i32> = self
            .captured_file_table()
            .read_epoll_fds()
            .iter()
            .copied()
            .collect();
        for epfd in epfds {
            let stale = match self.open_file(epfd) {
                None => true,
                Some(open_file) => {
                    let Some(mut open) = open_file.description.write() else {
                        return;
                    };
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
                            let target_host_fd = self.host_fd_for_poll(*fd);
                            let target_description = self
                                .open_file(*fd)
                                .map(|file| Arc::clone(&file.description));
                            let matching_fds = interest
                                .keys()
                                .copied()
                                .filter(|candidate| {
                                    *candidate == *fd
                                        || target_host_fd.is_some()
                                            && self.host_fd_for_poll(*candidate) == target_host_fd
                                        || target_description.as_ref().is_some_and(|target| {
                                            self.open_file(*candidate).is_some_and(|candidate| {
                                                Arc::ptr_eq(&candidate.description, target)
                                            })
                                        })
                                })
                                .collect::<Vec<_>>();
                            for matching_fd in matching_fds {
                                let Some(slot) = interest.get_mut(&matching_fd) else {
                                    continue;
                                };
                                let before = slot.last_ready;
                                let before_read_avail = slot.last_read_avail;
                                slot.io_gen = slot.io_gen.wrapping_add(1);
                                crate::event_ring::rec(
                                    crate::event_ring::EPCMSUM,
                                    matching_fd,
                                    slot.io_gen as i32,
                                    *clear as i32,
                                );
                                if clear & READ_CLEAR != 0 {
                                    if let Some(bytes) = read_progress_bytes {
                                        slot.last_read_avail =
                                            slot.last_read_avail.saturating_sub(bytes);
                                        if slot.last_read_avail == 0 {
                                            slot.last_ready &= !READ_CLEAR;
                                        }
                                    } else {
                                        slot.last_ready &= !READ_CLEAR;
                                        slot.last_read_avail = 0;
                                    }
                                }
                                if clear & !READ_CLEAR != 0 {
                                    slot.last_ready &= !(clear & !READ_CLEAR);
                                }
                                if clear & WRITE_CLEAR != 0 {
                                    slot.write_backpressured = false;
                                }
                                if epoll_io_progress_needs_host_rebind(
                                    before,
                                    slot.last_ready,
                                    before_read_avail,
                                    slot.last_read_avail,
                                ) || slot.event.events & LINUX_EPOLLET != 0
                                {
                                    snapshot_changed = true;
                                    #[cfg(any(
                                        feature = "platform-macos",
                                        feature = "platform-freebsd",
                                        feature = "platform-netbsd"
                                    ))]
                                    if let Some(host_fd) = self.host_fd_for_poll(matching_fd) {
                                        host_rearms.push(host_fd.get());
                                    }
                                }
                            }
                        }
                        for fd in write_eagain_targets.iter().flatten() {
                            let target_host_fd = self.host_fd_for_poll(*fd);
                            let target_description = self
                                .open_file(*fd)
                                .map(|file| Arc::clone(&file.description));
                            let matching_fds = interest
                                .keys()
                                .copied()
                                .filter(|candidate| {
                                    *candidate == *fd
                                        || target_host_fd.is_some()
                                            && self.host_fd_for_poll(*candidate) == target_host_fd
                                        || target_description.as_ref().is_some_and(|target| {
                                            self.open_file(*candidate).is_some_and(|candidate| {
                                                Arc::ptr_eq(&candidate.description, target)
                                            })
                                        })
                                })
                                .collect::<Vec<_>>();
                            for matching_fd in matching_fds {
                                let Some(slot) = interest.get_mut(&matching_fd) else {
                                    continue;
                                };
                                if slot.event.events & LINUX_EPOLLET == 0
                                    || slot.event.events & LINUX_EPOLLOUT == 0
                                {
                                    continue;
                                }
                                if !slot.write_backpressured {
                                    snapshot_changed = true;
                                    slot.write_backpressured = true;
                                }
                                #[cfg(any(
                                    feature = "platform-macos",
                                    feature = "platform-freebsd",
                                    feature = "platform-netbsd"
                                ))]
                                if let Some(host_fd) = self.host_fd_for_poll(matching_fd) {
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
                                    EPOLL_REBIND_REASON_IO_REARM,
                                    None,
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
                self.captured_file_table().write_epoll_fds().remove(&epfd);
            }
        }
    }

    fn detach_description_from_all_epolls(
        &self,
        target: &Arc<crate::kernel::FileDescription>,
        detached_host_fd: Option<HostFd>,
    ) {
        for (owner, registration_fd) in target.take_epoll_owners() {
            let Some(mut guard) = owner.write() else {
                continue;
            };
            let OpenDescription::Epoll {
                interest,
                synthetic_interest_count,
                pending_ready,
                kqueue,
                ..
            } = &mut *guard
            else {
                continue;
            };
            let registered_target = interest
                .get(&registration_fd)
                .and_then(|slot| slot.target.as_ref());
            if !registered_target.is_some_and(|registered| Arc::ptr_eq(registered, target)) {
                continue;
            }
            let _ = remove_epoll_interest(interest, synthetic_interest_count, registration_fd);
            clear_pending_epoll_ready(pending_ready, registration_fd);
            if let Some(host_fd) = detached_host_fd {
                kqueue.with_mux(|mux| {
                    let _ = mux.deregister(host_fd.get());
                });
            }
            kqueue.wake_parked();
            drop(guard);
            if let Some(wq) = owner.wait_queue() {
                wq.wake_all();
            }
            crate::event_ring::rec(
                crate::event_ring::EPRETIRE,
                owner.id().raw() as i32,
                target.id().raw() as i32,
                0,
            );
        }
    }

    pub(in crate::dispatch) fn detach_fd_from_epolls(&self, fd: i32) {
        let detached_host_fd = self.host_fd_for_poll(fd);
        let (detached_description, owners, should_auto_detach) = {
            let files = self.captured_file_table();
            let table = files.read_open_files();
            let detached_description = table.get(&fd).map(|file| file.description.clone());
            let logical_refs = detached_description
                .as_ref()
                .map_or(1, |target| target.fd_ref_count());
            // Only the epoll instances registered on the closing description
            // can hold an entry for it, and the description records them at
            // EPOLL_CTL_ADD; a table-wide walk here made every non-final
            // alias close cost the size of the fd table. A bare inherited
            // stdio fd is registered without a table-backed description
            // (`target: None`, matched by number), so only that case still
            // scans the table's epoll descriptions; any other number absent
            // from the table can hold no registration at all.
            let owners: Vec<Arc<crate::kernel::FileDescription>> = match &detached_description {
                Some(target) => target.epoll_owners(),
                None if is_stdio_fd(fd) => table
                    .values()
                    .filter(|of| of.description.is_epoll())
                    .map(|of| of.description.clone())
                    .collect(),
                None => Vec::new(),
            };
            // Linux retains every registration for an open description until
            // its final fd slot closes, including registrations installed
            // through a dup alias whose numeric slot closed earlier.
            let should_auto_detach = logical_refs == 1;
            (detached_description, owners, should_auto_detach)
        };
        if should_auto_detach && let Some(target) = &detached_description {
            self.detach_description_from_all_epolls(target, detached_host_fd);
            return;
        }
        for description in owners {
            let Some(mut guard) = description.write() else {
                continue;
            };
            if let OpenDescription::Epoll {
                interest,
                synthetic_interest_count,
                pending_ready,
                kqueue,
                ..
            } = &mut *guard
            {
                let matching_fds = interest
                    .iter()
                    .filter_map(|(registered_fd, slot)| {
                        let matches = match (&slot.target, &detached_description) {
                            (Some(registered), Some(closing)) => Arc::ptr_eq(registered, closing),
                            (None, None) => *registered_fd == fd,
                            _ => false,
                        };
                        matches.then_some(*registered_fd)
                    })
                    .collect::<Vec<_>>();
                if matching_fds.is_empty() {
                    continue;
                }
                if should_auto_detach {
                    for registered_fd in matching_fds {
                        let _ = remove_epoll_interest(
                            interest,
                            synthetic_interest_count,
                            registered_fd,
                        );
                        clear_pending_epoll_ready(pending_ready, registered_fd);
                    }
                }
                if let Some(host_fd) = detached_host_fd {
                    // A non-final close after fork is local to the CHILD fd
                    // table, while the inherited epoll description (and its
                    // host multiplexer) is shared with the parent.  If this
                    // table has no other registration for the host fd, deleting
                    // the filter here deafens the parent's still-valid numeric
                    // registration.  Rebind only when this table can name a
                    // surviving registration; a final description close still
                    // deregisters as usual.
                    let has_local_registered_survivor = interest.keys().any(|other| {
                        *other != fd && self.host_fd_for_poll(*other) == Some(host_fd)
                    });
                    if !should_auto_detach && !has_local_registered_survivor {
                        continue;
                    }
                    #[cfg(any(
                        feature = "platform-macos",
                        feature = "platform-freebsd",
                        feature = "platform-netbsd"
                    ))]
                    self.rebind_epoll_host_registration(
                        kqueue,
                        interest,
                        host_fd,
                        EPOLL_REBIND_REASON_CLOSE_DETACH,
                        Some(fd),
                    );
                    #[cfg(not(any(
                        feature = "platform-macos",
                        feature = "platform-freebsd",
                        feature = "platform-netbsd"
                    )))]
                    {
                        let mut survivor: Option<(i32, u32)> = None;
                        let mut union_events: u32 = 0;
                        for (&other, slot) in interest.iter() {
                            if other != fd && self.host_fd_for_poll(other) == Some(host_fd) {
                                survivor.get_or_insert((other, slot.reg_gen));
                                union_events |= slot.event.events;
                            }
                        }
                        kqueue.with_mux(|mux| match survivor {
                            Some((sfd, sgen)) => {
                                let union_events = LinuxEpollEvents::from_bits_retain(union_events);
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
                // A parked waiter still ppolls the closed fd's host fd (a
                // closed entry never wakes poll); pop it so it rebuilds.
                kqueue.wake_parked();
            }
        }
    }

    // core stays byte-for-byte identical (one pre-existing unused destructure).
    #[allow(unused_variables)]
    #[allow(clippy::too_many_arguments)]
    fn epoll_pwait_wait_core<M: CurrentMmMemory>(
        &self,
        memory: &mut M,
        open_file: OpenFile,
        epfd: i32,
        events_address: u64,
        guest_abi: LinuxGuestAbi,
        max_events: usize,
        timeout_ms: i32,
        sig_mask: carrick_abi::WaitSigMask,
    ) -> Result<DispatchOutcome, DispatchError> {
        let this = self;
        // Snapshot any already-queued ready events first. `ready` is
        // reassigned on the multiplexer path below (it collects the
        // drained-and-tagged events), so the `mut` is load-bearing.
        let pending_ready = {
            let Some(mut open) = open_file.description.write() else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let OpenDescription::Epoll { pending_ready, .. } = &mut *open else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            drain_pending_epoll_ready(pending_ready, max_events)
        };
        let mut ready: Vec<LinuxEpollEvent> =
            pending_ready.iter().map(|(_fd, event)| *event).collect();
        if !ready.is_empty() {
            for (fd, event) in &pending_ready {
                crate::event_ring::rec(crate::event_ring::EPREADY, epfd, *fd, event.events as i32);
            }
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
                let Some(open) = open_file.description.read() else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
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
            let watched_guest_fds = interests.iter().map(|(fd, _)| *fd).collect::<Vec<_>>();

            // guest_fd -> (accumulated epoll events, epoll_data); read+write filters
            // for the same fd merge into one returned event.
            let mut acc: HashMap<i32, (u32, u64)> = HashMap::new();
            type ReadyUpdate = (i32, u32, u64, u32, Option<u64>, bool, bool, bool);
            let mut ready_updates: Vec<ReadyUpdate> = Vec::new();
            let mut host_ready_sampled = std::collections::HashSet::<i32>::new();
            const READ_READY_BITS: u32 =
                LINUX_EPOLLIN | LINUX_EPOLLRDHUP | LINUX_EPOLLHUP | LINUX_EPOLLERR;
            // (1) Drain the instance kqueue (non-blocking) for host-backed fds.
            // `kq_drained_all_filtered` tracks the corner case where the kqueue
            // had readiness events but the user's interest mask filters them
            // all out (e.g. `epoll_ctl(ADD, fd, events=0)` plus data on the
            // pipe). The poll-backed wait below uses an empty event mask and a
            // short retry slice: it avoids re-polling kq_fd as immediately
            // readable while still re-dispatching for a concurrent MOD/HUP and
            // preserving the guest deadline.
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
                        // epoll_data, reg_gen, io_gen, last_ready, last_read_avail,
                        // write_backpressured). host_to_gfds: host fd
                        // -> guest fds sharing it (dup fan-out). Types inferred
                        // from the inserts.
                        let (gfd_info, host_to_gfds) = {
                            let Some(open) = open_file.description.read() else {
                                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                            };
                            // Per-guest-fd epoll interest snapshot: (host_fd,
                            // events, epoll data, reg_gen, io_gen, last_ready,
                            // last_read_avail, write_backpressured).
                            type GfdInterest = (i32, u32, u64, u32, u64, u32, u64, bool);
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
                                                slot.io_gen,
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
                            crate::event_ring::rec(
                                crate::event_ring::EPEDGE,
                                guest_fd,
                                edge_bits as i32,
                                edge_readiness_count.min(i32::MAX as u64) as i32,
                            );
                            match gfd_info.get(&guest_fd) {
                                Some(&(hfd, _, _, reg_gen, _, _, _, _))
                                    if reg_gen == generation =>
                                {
                                    if let Some(siblings) = host_to_gfds.get(&hfd) {
                                        for sibling in siblings {
                                            let entry = deliver.entry(*sibling).or_insert((0, 0));
                                            merge_epoll_edge_sample(
                                                entry,
                                                edge_bits,
                                                edge_readiness_count,
                                            );
                                        }
                                    }
                                }
                                _ => {
                                    let live_generation =
                                        gfd_info.get(&guest_fd).map_or(-1, |entry| entry.3 as i32);
                                    crate::event_ring::rec(
                                        crate::event_ring::EPSTALE,
                                        guest_fd,
                                        generation as i32,
                                        live_generation,
                                    );
                                    crate::probes::epoll_stale_edge(ev.token, guest_fd, generation);
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
                                hfd,
                                requested,
                                data,
                                reg_gen,
                                io_gen,
                                last_ready,
                                last_read_avail,
                                write_backpressured,
                            )) = gfd_info.get(&gfd)
                            {
                                host_ready_sampled.insert(gfd);
                                let mut raw = this.epoll_ready_events(gfd, requested);
                                let terminal_edge = edge_bits
                                    & (LINUX_EPOLLRDHUP | LINUX_EPOLLHUP | LINUX_EPOLLERR);
                                raw |= terminal_edge;
                                if terminal_edge & LINUX_EPOLLRDHUP != 0 {
                                    raw |= LINUX_EPOLLIN;
                                }
                                let read_avail = if raw & READ_READY_BITS != 0 {
                                    this.host_read_avail_for_poll(gfd)
                                } else {
                                    0
                                };
                                let observed_read_avail = if read_avail > 0 {
                                    read_avail
                                } else {
                                    edge_readiness_count
                                };
                                let clear_write_backpressure =
                                    write_backpressured && raw & LINUX_EPOLLOUT != 0;
                                // Growth over the recorded baseline delivers a
                                // SECOND ET edge while the first is still
                                // unconsumed. It is not the mechanism that
                                // carries the ordinary "ready again after you
                                // drained" case — that is `raw & !last_ready`
                                // once consumption re-armed the latch
                                // (`epoll_rearm_after_io`). See
                                // `EpollInterest::last_read_avail` for what the
                                // count means per fd and why growth is a sound
                                // arrival predicate for a listener even though
                                // its accept-queue depth is non-monotone.
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
                                let edge_filtered_by_interest =
                                    edge_bits & (requested | LINUX_EPOLLHUP | LINUX_EPOLLERR) == 0;
                                let read_avail_update = if raw & READ_READY_BITS == 0 {
                                    Some(0)
                                } else {
                                    Some(observed_read_avail)
                                };
                                let masked_ready =
                                    ready_events == 0 && (raw != 0 || edge_filtered_by_interest);
                                ready_updates.push((
                                    gfd,
                                    reg_gen,
                                    io_gen,
                                    raw,
                                    read_avail_update,
                                    clear_write_backpressure,
                                    true,
                                    masked_ready,
                                ));
                                crate::probes::epoll_interest(
                                    epfd,
                                    gfd,
                                    requested,
                                    raw,
                                    last_ready,
                                    ready_events,
                                );
                                if masked_ready {
                                    crate::event_ring::rec(
                                        crate::event_ring::EPMASK,
                                        1,
                                        raw as i32,
                                        last_ready as i32,
                                    );
                                    crate::event_ring::rec(
                                        crate::event_ring::EPMASKFD,
                                        1,
                                        gfd,
                                        hfd,
                                    );
                                    crate::probes::epoll_masked(crate::probes::EpollMaskedProbe {
                                        origin: 1,
                                        fd: gfd,
                                        host_fd: hfd,
                                        requested,
                                        raw_ready: raw,
                                        last_ready,
                                        read_avail: observed_read_avail,
                                        last_read_avail,
                                    });
                                }
                                if ready_events != 0 {
                                    acc.entry(gfd).or_insert((0, data)).0 |= ready_events;
                                } else if requested & LINUX_EPOLLET == 0
                                    && (raw != 0 || edge_filtered_by_interest)
                                {
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
                    kq_drained_all_filtered = filtered_ready_events > 0 && acc.len() == acc_before;
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
                } else if read_avail == 0 {
                    // Readable, but FIONREAD reports no byte count. The case
                    // this floor EXISTS for is a LISTENER: its readiness count
                    // is the pending accept-queue depth, which lives in the
                    // multiplexer edge's `readiness_count` (>=1), not in
                    // FIONREAD. Recording 0 here would DESYNC this level
                    // re-sample from the edge path: if this path observes and
                    // reports the readiness first (its poll(2) can beat the
                    // not-yet-drained knote) and stores 0, the later drain of
                    // that SAME knote sees `count (1) > last_read_avail (0)`,
                    // reads it as growth, and spuriously redelivers the
                    // already-reported, still-unaccepted connection. Flooring
                    // the baseline at the readiness just reported keeps only a
                    // genuine depth increase (a NEW connection) re-arming the
                    // edge. A real byte count takes the branch below.
                    //
                    // The branch is NOT listener-only, so be precise about what
                    // it does to the other two fds that report readable with
                    // FIONREAD == 0 (for both, the edge path's count is 0 too,
                    // so there is no desync to fix and the floor is pure
                    // conservatism):
                    //   - an EOF/HUP read end: terminal. No later count can
                    //     ever exceed the floor because no more data can arrive,
                    //     and consumption (a read returning 0) resets the
                    //     baseline outright. Inert.
                    //   - a 0-length datagram: the one case where the floor can
                    //     defer an edge. A follow-up 1-byte datagram lands at
                    //     count 1, which no longer exceeds the floored baseline,
                    //     so it is not reported as growth while the 0-length
                    //     readiness is STILL UNCONSUMED (a recv of any size
                    //     resets the baseline and re-arms). Bounded to that
                    //     window, and only on the level-first ordering; fixing
                    //     it properly needs the multiplexer to report a count
                    //     FIONREAD cannot see (an arrival counter / queue depth)
                    //     rather than this path guessing one, so it is left
                    //     documented instead of special-cased here.
                    Some(interest.last_read_avail.max(1))
                } else {
                    Some(read_avail)
                };
                let masked_ready = ready_events == 0 && raw_ready != 0;
                ready_updates.push((
                    *fd,
                    interest.reg_gen,
                    interest.io_gen,
                    raw_ready,
                    read_avail_update,
                    clear_write_backpressure,
                    false,
                    masked_ready,
                ));
                crate::probes::epoll_interest(
                    epfd,
                    *fd,
                    requested,
                    raw_ready,
                    interest.last_ready,
                    ready_events,
                );
                if masked_ready {
                    crate::event_ring::rec(
                        crate::event_ring::EPMASK,
                        2,
                        raw_ready as i32,
                        interest.last_ready as i32,
                    );
                    let host_fd = this
                        .host_fd_for_poll(*fd)
                        .map_or(-1, |host_fd| host_fd.get());
                    crate::event_ring::rec(crate::event_ring::EPMASKFD, 2, *fd, host_fd);
                    crate::probes::epoll_masked(crate::probes::EpollMaskedProbe {
                        origin: 2,
                        fd: *fd,
                        host_fd,
                        requested,
                        raw_ready,
                        last_ready: interest.last_ready,
                        read_avail,
                        last_read_avail: interest.last_read_avail,
                    });
                }
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
                    && !crate::dispatch::fifo_beacon::read_end_at_eof(hfd.get())
                {
                    continue;
                }
                let requested = interest.event.events;
                let raw_ready = this.epoll_ready_events(*fd, requested);
                let read_avail = if raw_ready & READ_READY_BITS != 0 {
                    this.host_read_avail_for_poll(*fd)
                } else {
                    0
                };
                let read_growth = if requested & LINUX_EPOLLET != 0
                    && raw_ready & READ_READY_BITS != 0
                    && read_avail > interest.last_read_avail
                {
                    raw_ready & READ_READY_BITS
                } else {
                    0
                };
                let ready_events = if requested & LINUX_EPOLLET != 0 {
                    (raw_ready & !interest.last_ready) | read_growth
                } else {
                    raw_ready
                };
                let read_avail_update = if raw_ready & READ_READY_BITS == 0 {
                    Some(0)
                } else {
                    Some(read_avail)
                };
                ready_updates.push((
                    *fd,
                    interest.reg_gen,
                    interest.io_gen,
                    raw_ready,
                    read_avail_update,
                    false,
                    false,
                    false,
                ));
                crate::probes::epoll_interest(
                    epfd,
                    *fd,
                    requested,
                    raw_ready,
                    interest.last_ready,
                    ready_events,
                );
                if ready_events == 0 && raw_ready != 0 {
                    crate::event_ring::rec(
                        crate::event_ring::EPMASK,
                        3,
                        raw_ready as i32,
                        interest.last_ready as i32,
                    );
                    crate::event_ring::rec(crate::event_ring::EPMASKFD, 3, *fd, -1);
                    crate::probes::epoll_masked(crate::probes::EpollMaskedProbe {
                        origin: 3,
                        fd: *fd,
                        host_fd: -1,
                        requested,
                        raw_ready,
                        last_ready: interest.last_ready,
                        read_avail: 0,
                        last_read_avail: interest.last_read_avail,
                    });
                }
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
                    interests.iter().any(|(ifd, slot)| {
                        ifd == *fd && slot.event.events & LINUX_EPOLLONESHOT != 0
                    })
                })
                .map(|(fd, _)| *fd)
                .collect();

            if !ready_updates.is_empty() || !oneshot_fds.is_empty() {
                if let Some(mut open) = open_file.description.write() {
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
                        for (
                            fd,
                            reg_gen,
                            io_gen,
                            raw,
                            read_avail,
                            clear_write_backpressure,
                            edge_drained,
                            masked_ready,
                        ) in ready_updates
                        {
                            if let Some(slot) = interest.get_mut(&fd) {
                                if !epoll_ready_sample_is_current(
                                    reg_gen,
                                    io_gen,
                                    slot.reg_gen,
                                    slot.io_gen,
                                ) {
                                    continue;
                                }
                                let before = slot.last_ready;
                                let read_avail_changed = read_avail
                                    .is_some_and(|read_avail| read_avail != slot.last_read_avail);
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
                                    && epoll_wait_sample_needs_host_rebind(
                                        before,
                                        raw,
                                        read_avail_changed,
                                        clear_write_backpressure,
                                        edge_drained,
                                        masked_ready,
                                        this.fd_is_listening_socket(fd),
                                    )
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
                                this.rebind_epoll_host_registration(
                                    kqueue,
                                    interest,
                                    HostFd(host_fd),
                                    EPOLL_REBIND_REASON_WAIT_SAMPLE,
                                    None,
                                );
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
                if let Some(mut open) = open_file.description.write() {
                    if let OpenDescription::Epoll { pending_ready, .. } = &mut *open {
                        pending_ready.extend(overflow);
                    }
                }
            }
            for (fd, event) in &ready_tagged {
                crate::event_ring::rec(crate::event_ring::EPREADY, epfd, *fd, event.events as i32);
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
                    // was masked by the guest interest. Poll kq_fd with an
                    // empty event mask: the poll-backed wait uses a short
                    // backstop to re-dispatch without spinning, while still
                    // observing a concurrent epoll_ctl MOD or a later HUP/ERR.
                    crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 2);
                    crate::event_ring::rec(crate::event_ring::EPWFD, kq_fd, 0, timeout_ms);
                    let files = self.captured_file_table();
                    let fds = match WaitFds::raw_one(kq_fd, 0).with_redispatch_and_watched_slots(
                        &files,
                        [epfd],
                        watched_guest_fds.iter().copied(),
                    ) {
                        Ok(fds) => fds,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds,
                        timeout,
                        sig_mask,
                        completion: FdWaitCompletion::Poll { on_timeout: 0 },
                    });
                }
                if !has_interests {
                    // epoll_pwait with an empty interest set must still honour
                    // timeout + signal interruption, not return 0 immediately.
                    // Poll the instance's durable user-wake source as well: a
                    // concurrent epoll_ctl ADD can make the formerly-empty set
                    // ready and must force a registry recomputation.
                    crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 2);
                    crate::event_ring::rec(
                        crate::event_ring::EPWFD,
                        kq_fd,
                        libc::POLLIN as i32,
                        timeout_ms,
                    );
                    let files = self.captured_file_table();
                    let fds = match WaitFds::raw_one(kq_fd, libc::POLLIN)
                        .with_redispatch_and_watched_slots(
                            &files,
                            [epfd],
                            watched_guest_fds.iter().copied(),
                        ) {
                        Ok(fds) => fds,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds,
                        timeout,
                        sig_mask,
                        completion: FdWaitCompletion::Poll { on_timeout: 0 },
                    });
                }
                crate::probes::epoll_result(epfd, 0, 1, timeout_ms, 1);
                crate::probes::epoll_wait_fd(epfd, -1, kq_fd, libc::POLLIN as i32, timeout_ms);
                crate::event_ring::rec(
                    crate::event_ring::EPWFD,
                    kq_fd,
                    libc::POLLIN as i32,
                    timeout_ms,
                );
                // Poll the instance kqueue fd for readability. This avoids nesting
                // the epoll kqueue inside the per-thread kqueue, and unlike calling
                // kevent() here it does not consume pending epoll events before the
                // re-dispatched epoll_pwait can copy them out.
                let files = self.captured_file_table();
                let fds = match WaitFds::raw_one(kq_fd, libc::POLLIN)
                    .with_redispatch_and_watched_slots(
                        &files,
                        [epfd],
                        watched_guest_fds.iter().copied(),
                    ) {
                    Ok(fds) => fds,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                return Ok(DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    sig_mask,
                    completion: FdWaitCompletion::Poll { on_timeout: 0 },
                });
            }

            crate::probes::epoll_result(epfd, ready.len() as i32, 0, timeout_ms, 0);
            write_epoll_events(memory, events_address, &ready, guest_abi)
        }
    }
}

#[cfg(test)]
mod synthetic_datagram_readiness_tests {
    use super::*;

    /// A datagram carrick itself queued on a host-backed UDP socket (the bridge
    /// DNS gateway's answer, a loopback ICMP echo reply) lives in
    /// `synthetic_recv`, not in the host kernel, so the host `poll(2)` that
    /// `epoll_ready_events` trusts for sockets can never see it. Linux reports
    /// EPOLLIN for any queued datagram; so must the recompute `epoll_pwait`
    /// runs on every host-backed interest, and the ET read-growth baseline
    /// must count its bytes the way it counts an in-memory pipe's.
    #[test]
    fn queued_synthetic_datagram_is_epollin_ready() {
        let dispatcher = SyscallDispatcher::new();
        let fd = match dispatcher.host_socket_install(LINUX_AF_INET, LINUX_SOCK_DGRAM, 0) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("udp socket creation failed: {other:?}"),
        };
        // An unbound, unconnected UDP socket: the host kernel has nothing
        // queued, so any readiness below comes from the synthetic queue alone.
        assert_eq!(dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.host_read_avail_for_poll(fd), 0);

        let payload = b"\x12\x34\x81\x80reply".to_vec();
        let source = socket_addr_to_linux_sockaddr("172.31.0.1:53".parse().unwrap()).unwrap();
        {
            let open_file = dispatcher.open_file(fd).expect("udp socket open file");
            let mut open = open_file
                .description
                .write()
                .expect("udp socket open description");
            let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
                panic!("udp socket must be a HostSocket");
            };
            synthetic_recv.push_back((payload.clone(), source));
        }

        let ready = dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN);
        assert_eq!(
            ready & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "synthetic datagram must make the socket EPOLLIN-ready, got {ready:#x}"
        );
        assert_eq!(
            dispatcher.host_read_avail_for_poll(fd),
            payload.len() as u64,
            "the ET read-growth baseline must count synthetic bytes"
        );

        // Draining the queue takes the readiness with it.
        assert!(dispatcher.synthetic_datagram_drain(fd).is_some());
        assert_eq!(dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.host_read_avail_for_poll(fd), 0);
    }
}

#[cfg(test)]
pub(super) fn epoll_kqueue_for_wake_test(
    dispatcher: &SyscallDispatcher,
) -> crate::dispatch::EpollKqueue {
    let mut mux = crate::event_mux::make_event_multiplexer().expect("event multiplexer");
    mux.register_user(0).expect("register user wake");
    crate::dispatch::EpollKqueue::new(
        mux,
        Arc::clone(dispatcher.captured_file_table().epoll_wake_registry()),
    )
}

#[cfg(test)]
mod dns_gateway_wake_tests {
    use super::*;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn poll_fd_readable(fd: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
        rc == 1 && pfd.revents & libc::POLLIN != 0
    }

    /// The bridge DNS gateway answers a guest query in-process, straight into
    /// the socket's `synthetic_recv`. A thread already parked in `epoll_wait`
    /// on that socket sits on the instance kqueue, which only the host kernel
    /// or `notify_inmem_epoll` can pulse; the host never sees the reply, so
    /// the gateway must publish the wake itself (as the ICMP echo path does).
    #[test]
    fn dns_gateway_reply_wakes_parked_epoll_instance() {
        let network = crate::network::RuntimeNetwork::create(
            &carrick_spec::NetworkNamespaceSpec::bridge_default(
                Some("dns-epoll-wake".to_string()),
                Vec::new(),
                Vec::new(),
            ),
        )
        .expect("create bridge network");
        // Direct field assignment (net.rs is a child module of `dispatch`, so
        // the private field is visible) rather than
        // `SyscallDispatcher::with_network`: that constructor also publishes
        // the root net view process-wide and mounts `/etc/resolv.conf`,
        // neither of which this test needs and the former of which would leak
        // into sibling tests in the same process.
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.network = Arc::new(network);
        let gateway =
            std::net::SocketAddr::new(std::net::IpAddr::V4(dispatcher.network.spec.gateway_v4), 53);
        assert!(dispatcher.is_dns_gateway_addr(gateway));

        let fd = match dispatcher.host_socket_install(LINUX_AF_INET, LINUX_SOCK_DGRAM, 0) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("udp socket creation failed: {other:?}"),
        };

        // Exactly what `epoll_create1` builds (net.rs:4430-4439): a multiplexer
        // with its user-wake armed, registered in THIS dispatcher's wake
        // registry.
        let epoll = epoll_kqueue_for_wake_test(&dispatcher);
        assert!(
            !poll_fd_readable(epoll.poll_fd()),
            "a fresh epoll instance must be quiet"
        );

        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_ascii("localhost.").expect("name"),
            RecordType::A,
        ));
        let request = query.to_vec().expect("encode query");

        assert!(
            dispatcher.maybe_queue_dns_response(fd, &request, gateway),
            "the gateway must answer a query addressed to gateway_v4:53"
        );
        assert!(
            poll_fd_readable(epoll.poll_fd()),
            "DNS gateway reply must wake the epoll instance's poll fd"
        );

        let (reply, source) = dispatcher
            .synthetic_datagram_drain(fd)
            .expect("reply queued on the querying socket");
        assert_eq!(
            Message::from_vec(&reply).expect("parse reply").metadata.id,
            query.metadata.id
        );
        assert_eq!(source, socket_addr_to_linux_sockaddr(gateway).unwrap());
    }
}

#[cfg(test)]
mod epoll_interest_tests {
    use super::*;

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    #[test]
    fn et_write_latch_temporarily_disarms_host_write_filter() {
        let dispatcher = SyscallDispatcher::new();
        let events = LINUX_EPOLLET | LINUX_EPOLLIN | LINUX_EPOLLOUT;

        let fresh = dispatcher.epoll_effective_interest(12345, events, 0, 0, false);
        assert!(fresh.read);
        assert!(fresh.write);

        let latched = dispatcher.epoll_effective_interest(12345, events, LINUX_EPOLLOUT, 0, false);
        assert!(latched.read);
        assert!(!latched.write);

        let backpressured =
            dispatcher.epoll_effective_interest(12345, events, LINUX_EPOLLOUT, 0, true);
        assert!(backpressured.read);
        assert!(backpressured.write);

        let level = dispatcher.epoll_effective_interest(
            12345,
            LINUX_EPOLLIN | LINUX_EPOLLOUT,
            LINUX_EPOLLOUT,
            0,
            false,
        );
        assert!(level.read);
        assert!(level.write);
    }

    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    #[test]
    fn et_terminal_latch_disarms_host_filters() {
        let dispatcher = SyscallDispatcher::new();
        let events = LINUX_EPOLLET | LINUX_EPOLLIN | LINUX_EPOLLOUT;

        let hup_latched = dispatcher.epoll_effective_interest(
            12345,
            events,
            LINUX_EPOLLIN | LINUX_EPOLLHUP,
            0,
            false,
        );
        assert!(!hup_latched.read);
        assert!(!hup_latched.write);

        let err_latched =
            dispatcher.epoll_effective_interest(12345, events, LINUX_EPOLLERR, 0, false);
        assert!(!err_latched.read);
        assert!(!err_latched.write);

        let backpressured = dispatcher.epoll_effective_interest(
            12345,
            events,
            LINUX_EPOLLIN | LINUX_EPOLLHUP,
            0,
            true,
        );
        assert!(!backpressured.read);
        assert!(backpressured.write);

        let in_latched_zero =
            dispatcher.epoll_effective_interest(12345, events, LINUX_EPOLLIN, 0, false);
        assert!(!in_latched_zero.read);
        assert!(in_latched_zero.write);
    }
}

#[cfg(test)]
mod nested_epoll_readiness_tests {
    use super::*;
    use crate::dispatch::LinearMemory;

    fn create_epoll(
        dispatcher: &mut SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        mem: &mut LinearMemory,
        reporter: &CompatReporter,
    ) -> i32 {
        let req = SyscallRequest::new(20, SyscallArgs::from([0, 0, 0, 0, 0, 0]));
        match dispatcher.dispatch(kernel, req, mem, reporter).unwrap() {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("epoll_create1 failed: {other:?}"),
        }
    }

    fn create_eventfd(
        dispatcher: &mut SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        mem: &mut LinearMemory,
        reporter: &CompatReporter,
        init_val: u64,
    ) -> i32 {
        let req = SyscallRequest::new(19, SyscallArgs::from([init_val, 0, 0, 0, 0, 0]));
        match dispatcher.dispatch(kernel, req, mem, reporter).unwrap() {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("eventfd2 failed: {other:?}"),
        }
    }

    fn close_guest_fd(
        dispatcher: &mut SyscallDispatcher,
        kernel: &crate::kernel::KernelContext,
        mem: &mut LinearMemory,
        reporter: &CompatReporter,
        fd: i32,
    ) -> bool {
        let req = SyscallRequest::new(57, SyscallArgs::from([fd as u64, 0, 0, 0, 0, 0]));
        matches!(
            dispatcher.dispatch(kernel, req, mem, reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        )
    }

    fn write_guest_epoll_event(mem: &mut LinearMemory, address: u64, events: u32, data: u64) {
        let ev = LinuxEpollEvent {
            events,
            _pad: 0,
            data,
        };
        mem.write_bytes(address, zerocopy::IntoBytes::as_bytes(&ev))
            .unwrap();
    }

    fn read_guest_epoll_event(mem: &LinearMemory, address: u64) -> LinuxEpollEvent {
        read_kernel_struct(mem, address).unwrap()
    }

    #[test]
    fn empty_inner_epoll_has_no_false_in_on_poll_or_outer_epoll() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        // Create empty inner epoll
        let inner_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Create outer epoll
        let outer_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Register inner in outer
        let event_ptr = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr, LINUX_EPOLLIN, 42);

        let add_req = SyscallRequest::new(
            21,
            SyscallArgs::from([
                outer_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                inner_epfd as u64,
                event_ptr,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_req, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Authoritative readiness must NOT return POLLIN/EPOLLIN because inner epoll has no deliverable events!
        assert_eq!(
            dispatcher.poll_ready_events(inner_epfd, LINUX_POLLIN),
            0,
            "empty inner epoll must not report POLLIN under poll(2)"
        );
        assert_eq!(
            dispatcher.epoll_ready_events(inner_epfd, LINUX_EPOLLIN),
            0,
            "empty inner epoll must not report EPOLLIN under epoll"
        );
        assert_eq!(
            dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN),
            0,
            "outer epoll monitoring empty inner epoll must not report EPOLLIN"
        );
        assert_eq!(
            dispatcher.poll_ready_events(outer_epfd, LINUX_POLLIN),
            0,
            "outer epoll monitoring empty inner epoll must not report POLLIN"
        );
    }

    #[test]
    fn threaded_eventfd_nested_epoll_wake() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        // Create eventfd (initially 0)
        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);

        // Create inner epoll
        let inner_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Create outer epoll
        let outer_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Add efd to inner_epfd
        let event_ptr1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr1, LINUX_EPOLLIN, 101);
        let add_efd = SyscallRequest::new(
            21,
            SyscallArgs::from([
                inner_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                efd as u64,
                event_ptr1,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_efd, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Add inner_epfd to outer_epfd
        let event_ptr2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr2, LINUX_EPOLLIN, 202);
        let add_inner = SyscallRequest::new(
            21,
            SyscallArgs::from([
                outer_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                inner_epfd as u64,
                event_ptr2,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_inner, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Initially neither is ready
        assert_eq!(dispatcher.epoll_ready_events(inner_epfd, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN), 0);

        // Get outer epoll's wait_queue
        let outer_file = dispatcher.open_file(outer_epfd).unwrap();
        let outer_wq = outer_file.wait_queue().unwrap();
        let outer_kqueue_poll_fd = dispatcher
            .host_fd_for_poll(outer_epfd)
            .map(|h| h.get())
            .unwrap_or(-1);

        // Spawn a background waiter that waits for outer epoll wake_queue or kqueue poll_fd
        let (tx, rx) = std::sync::mpsc::channel();
        let outer_wq_clone = Arc::clone(&outer_wq);
        let waiter = std::thread::spawn(move || {
            let wait_set = crate::kernel::WaitSet::for_current_executor();
            let _enrollment = wait_set.enroll(&outer_wq_clone);
            let mut pfd = libc::pollfd {
                fd: outer_kqueue_poll_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            tx.send(()).unwrap();
            let outcome = wait_set.wait(&[], Some(std::time::Duration::from_secs(5)), || false);
            let kq_ready = if outer_kqueue_poll_fd >= 0 {
                unsafe { libc::poll(&mut pfd, 1, 0) }
            } else {
                0
            };
            (
                outcome == crate::kernel::WaitSetOutcome::Woken,
                kq_ready > 0 && pfd.revents & libc::POLLIN != 0,
            )
        });

        // Wait until waiter has enrolled
        rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Write to eventfd (0 -> 1)
        let write_buf = 0x1040u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        let write_req =
            SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0]));
        let write_outcome = dispatcher.dispatch(&kernel, write_req, &mut guest_mem, &reporter);
        assert!(matches!(
            write_outcome,
            Ok(DispatchOutcome::Returned { value: 8 })
        ));

        let (wq_woken, kq_woken) = waiter.join().expect("waiter thread joined");
        assert!(
            wq_woken,
            "registered wait queue must wake before deadline; late kqueue readiness={kq_woken}"
        );

        // After write, outer and inner are both ready
        assert_eq!(
            dispatcher.epoll_ready_events(inner_epfd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
    }

    #[test]
    fn nested_epoll_dup_close_reuse() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        // Create eventfd (initially 0)
        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);

        // Create inner epoll
        let inner_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Add efd to inner_epfd
        let event_ptr1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr1, LINUX_EPOLLIN, 101);
        let add_efd = SyscallRequest::new(
            21,
            SyscallArgs::from([
                inner_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                efd as u64,
                event_ptr1,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_efd, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Dup inner_epfd to alias_inner_fd
        let inner_open_file = dispatcher.open_file(inner_epfd).unwrap();
        let alias_inner_fd = dispatcher
            .install_fd_at_or_above(30, inner_open_file)
            .unwrap();

        // Create outer epoll
        let outer_epfd = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Add inner_epfd to outer_epfd
        let event_ptr2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, event_ptr2, LINUX_EPOLLIN, 202);
        let add_inner = SyscallRequest::new(
            21,
            SyscallArgs::from([
                outer_epfd as u64,
                LINUX_EPOLL_CTL_ADD,
                inner_epfd as u64,
                event_ptr2,
                0,
                0,
            ]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, add_inner, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Close original inner_epfd
        assert!(close_guest_fd(
            &mut dispatcher,
            &kernel,
            &mut guest_mem,
            &reporter,
            inner_epfd
        ));

        // Install a new Netlink socket (empty) into the exact slot inner_epfd
        let netlink_open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::Netlink {
                base: OpenDescriptionBase::new(0),
                protocol: 0,
                sock_type: LINUX_SOCK_DGRAM,
                pid: 0,
                groups: 0,
                recv_queue: VecDeque::new(),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            })),
            0,
            0,
        );
        let reused_fd = dispatcher
            .install_fd_at_or_above(inner_epfd, netlink_open_file)
            .unwrap();
        assert_eq!(reused_fd, inner_epfd);

        // Write to eventfd (0 -> 1)
        let write_buf = 0x1040u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        let write_req =
            SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0]));
        assert!(matches!(
            dispatcher.dispatch(&kernel, write_req, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 8 })
        ));

        // Outer epoll must report ready because it tracks the underlying Epoll description identity (referenced by alias_inner_fd)
        assert_eq!(
            dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "outer epoll must track stored description identity, not newly installed netlink at reused fd"
        );

        // Now close alias_inner_fd (the last handle to the inner epoll description)
        assert!(close_guest_fd(
            &mut dispatcher,
            &kernel,
            &mut guest_mem,
            &reporter,
            alias_inner_fd
        ));

        // Outer epoll must now evaluate to not ready because the target description is closed
        assert_eq!(
            dispatcher.epoll_ready_events(outer_epfd, LINUX_EPOLLIN),
            0,
            "outer epoll must not report ready after inner epoll description is closed"
        );
    }

    #[test]
    fn nested_epoll_et_and_oneshot() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x2000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        // EventFd 1 (for ET test)
        let efd1 = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);
        let inner1 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer1 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // Add efd1 to inner1
        let ep1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ep1, LINUX_EPOLLIN, 1);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([inner1 as u64, LINUX_EPOLL_CTL_ADD, efd1 as u64, ep1, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Add inner1 to outer1 with EPOLLET | EPOLLIN
        let ep2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, ep2, LINUX_EPOLLET | LINUX_EPOLLIN, 2);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer1 as u64, LINUX_EPOLL_CTL_ADD, inner1 as u64, ep2, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Write to efd1 (0 -> 1)
        let write_buf = 0x1040u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(64, SyscallArgs::from([efd1 as u64, write_buf, 8, 0, 0, 0])),
            &mut guest_mem,
            &reporter,
        );

        // Outer1 is ready
        assert_eq!(
            dispatcher.epoll_ready_events(outer1, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );

        // Consume outer1 readiness via epoll_pwait (syscall 22 on aarch64)
        let events_out = 0x1100u64;
        let wait_outcome = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                22,
                SyscallArgs::from([outer1 as u64, events_out, 10, 0, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );
        assert!(
            matches!(&wait_outcome, Ok(DispatchOutcome::Returned { value: 1 })),
            "outer ET epoll first delivery: {wait_outcome:?}"
        );

        // Verify delivered 16-byte event struct and user data payload
        let delivered_event = read_guest_epoll_event(&guest_mem, events_out);
        assert_eq!(
            { delivered_event.events } & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "delivered event mask must include EPOLLIN"
        );
        assert_eq!(
            { delivered_event.data },
            2,
            "delivered event data must match registered payload"
        );

        // Outer1 is now latched (ET suppresses repeat report without new readiness change)
        assert_eq!(
            dispatcher.epoll_ready_events(outer1, LINUX_EPOLLIN),
            0,
            "ET registration must be suppressed once latched"
        );

        // Test ONESHOT:
        let outer2 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let ep3 = 0x1060u64;
        write_guest_epoll_event(&mut guest_mem, ep3, LINUX_EPOLLONESHOT | LINUX_EPOLLIN, 3);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer2 as u64, LINUX_EPOLL_CTL_ADD, inner1 as u64, ep3, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Outer2 is ready
        assert_eq!(
            dispatcher.epoll_ready_events(outer2, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );

        // Consume outer2 readiness via epoll_pwait (disarms ONESHOT)
        let wait_outcome2 = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                22,
                SyscallArgs::from([outer2 as u64, events_out, 10, 0, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );
        assert!(matches!(
            wait_outcome2,
            Ok(DispatchOutcome::Returned { value: 1 })
        ));

        let delivered_event2 = read_guest_epoll_event(&guest_mem, events_out);
        assert_eq!({ delivered_event2.data }, 3);

        // Outer2 is now not ready (disarmed by delivery)
        assert_eq!(
            dispatcher.epoll_ready_events(outer2, LINUX_EPOLLIN),
            0,
            "disarmed ONESHOT registration must not report ready"
        );

        // Re-arm via MOD
        write_guest_epoll_event(&mut guest_mem, ep3, LINUX_EPOLLONESHOT | LINUX_EPOLLIN, 33);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer2 as u64, LINUX_EPOLL_CTL_MOD, inner1 as u64, ep3, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Outer2 is ready again
        assert_eq!(
            dispatcher.epoll_ready_events(outer2, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "re-armed ONESHOT registration must report ready"
        );
    }

    #[test]
    fn nested_epoll_drain_and_rearm() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);
        let inner = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        let ep1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ep1, LINUX_EPOLLIN, 10);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([inner as u64, LINUX_EPOLL_CTL_ADD, efd as u64, ep1, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        let ep2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, ep2, LINUX_EPOLLIN, 20);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer as u64, LINUX_EPOLL_CTL_ADD, inner as u64, ep2, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Initial: 0
        assert_eq!(dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN), 0);

        // Write 5 to eventfd
        let write_buf = 0x1040u64;
        guest_mem
            .write_bytes(write_buf, &5u64.to_le_bytes())
            .unwrap();
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0])),
            &mut guest_mem,
            &reporter,
        );

        // Both ready
        assert_eq!(
            dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );

        // Drain eventfd (read 8 bytes)
        let read_buf_addr = 0x1060u64;
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                63,
                SyscallArgs::from([efd as u64, read_buf_addr, 8, 0, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // After drain: both not ready
        assert_eq!(dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN), 0);

        // Write 1 to eventfd again
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0])),
            &mut guest_mem,
            &reporter,
        );

        // Both ready again
        assert_eq!(
            dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN) & LINUX_EPOLLIN,
            LINUX_EPOLLIN
        );
    }

    #[test]
    fn nested_epoll_active_wait_cancel_and_retirement() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let inner = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        let ep1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ep1, LINUX_EPOLLIN, 99);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([outer as u64, LINUX_EPOLL_CTL_ADD, inner as u64, ep1, 0, 0]),
            ),
            &mut guest_mem,
            &reporter,
        );

        let outer_file = dispatcher.open_file(outer).unwrap();
        let outer_wq = outer_file.wait_queue().unwrap();

        // Spawn a waiter on outer's wait queue
        let (tx, rx) = std::sync::mpsc::channel();
        let outer_wq_clone = Arc::clone(&outer_wq);
        let waiter = std::thread::spawn(move || {
            let wait_set = crate::kernel::WaitSet::for_current_executor();
            let _enrollment = wait_set.enroll(&outer_wq_clone);
            tx.send(()).unwrap();
            wait_set.wait(&[], Some(std::time::Duration::from_secs(5)), || false)
        });

        rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Delete inner from outer
        let del_req = SyscallRequest::new(
            21,
            SyscallArgs::from([outer as u64, LINUX_EPOLL_CTL_DEL, inner as u64, 0, 0, 0]),
        );
        assert!(matches!(
            dispatcher.dispatch(&kernel, del_req, &mut guest_mem, &reporter),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Waiter must be woken!
        let outcome = waiter.join().expect("waiter thread joined");
        assert_eq!(
            outcome,
            crate::kernel::WaitSetOutcome::Woken,
            "waiter must be woken when registration is deleted"
        );

        // Readiness on outer is 0
        assert_eq!(dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN), 0);
    }

    #[test]
    fn nested_epoll_3_levels_deep_wake() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x1000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);
        let ep1 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let ep2 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let ep3 = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        // ep1 watches efd
        let ev1 = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ev1, LINUX_EPOLLIN, 1);
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([ep1 as u64, LINUX_EPOLL_CTL_ADD, efd as u64, ev1, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            ),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // ep2 watches ep1
        let ev2 = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, ev2, LINUX_EPOLLIN, 2);
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([ep2 as u64, LINUX_EPOLL_CTL_ADD, ep1 as u64, ev2, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            ),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // ep3 watches ep2
        let ev3 = 0x1040u64;
        write_guest_epoll_event(&mut guest_mem, ev3, LINUX_EPOLLIN, 3);
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(
                    21,
                    SyscallArgs::from([ep3 as u64, LINUX_EPOLL_CTL_ADD, ep2 as u64, ev3, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            ),
            Ok(DispatchOutcome::Returned { value: 0 })
        ));

        // Background waiter on ep3
        let ep3_file = dispatcher.open_file(ep3).unwrap();
        let ep3_wq = ep3_file.wait_queue().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let wait_set = crate::kernel::WaitSet::for_current_executor();
            let _enrollment = wait_set.enroll(&ep3_wq);
            tx.send(()).unwrap();
            wait_set.wait(&[], Some(std::time::Duration::from_secs(5)), || false)
        });

        rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Write to eventfd (0 -> 1)
        let write_buf = 0x1060u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0])),
                &mut guest_mem,
                &reporter,
            ),
            Ok(DispatchOutcome::Returned { value: 8 })
        ));

        let outcome = waiter.join().expect("waiter thread joined");
        assert_eq!(
            outcome,
            crate::kernel::WaitSetOutcome::Woken,
            "waiter on 3-level deep epoll must wake on leaf write"
        );

        // All 3 levels must report ready
        assert_eq!(
            dispatcher.epoll_ready_events(ep1, LINUX_EPOLLIN),
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(ep2, LINUX_EPOLLIN),
            LINUX_EPOLLIN
        );
        assert_eq!(
            dispatcher.epoll_ready_events(ep3, LINUX_EPOLLIN),
            LINUX_EPOLLIN
        );
    }

    #[test]
    fn nested_epoll_ppoll_continuation_yield_and_wake() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x2000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let efd = create_eventfd(&mut dispatcher, &kernel, &mut guest_mem, &reporter, 0);
        let inner = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        let ev1_addr = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ev1_addr, LINUX_EPOLLIN, 111);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([
                    inner as u64,
                    LINUX_EPOLL_CTL_ADD,
                    efd as u64,
                    ev1_addr,
                    0,
                    0,
                ]),
            ),
            &mut guest_mem,
            &reporter,
        );

        let ev2_addr = 0x1020u64;
        write_guest_epoll_event(&mut guest_mem, ev2_addr, LINUX_EPOLLIN, 222);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([
                    outer as u64,
                    LINUX_EPOLL_CTL_ADD,
                    inner as u64,
                    ev2_addr,
                    0,
                    0,
                ]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Call ppoll on outer with timeout = 500ms
        let pollfds_addr = 0x1100u64;
        let pfd = LinuxPollFd {
            fd: outer,
            events: LINUX_POLLIN,
            revents: 0,
        };
        guest_mem
            .write_bytes(pollfds_addr, zerocopy::IntoBytes::as_bytes(&pfd))
            .unwrap();

        let timeout_addr = 0x1120u64;
        let timespec = LinuxTimespec {
            tv_sec: 0,
            tv_nsec: 500_000_000,
        };
        guest_mem
            .write_bytes(timeout_addr, zerocopy::IntoBytes::as_bytes(&timespec))
            .unwrap();

        // ppoll must return WaitOnPollFds continuation rather than blocking synchronously
        let ppoll_outcome = dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(
                    73,
                    SyscallArgs::from([pollfds_addr, 1, timeout_addr, 0, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            )
            .unwrap();

        match &ppoll_outcome {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                completion,
                ..
            } => {
                assert_eq!(*timeout, Some(std::time::Duration::from_millis(500)));
                match completion {
                    FdWaitCompletion::Fd { on_timeout } | FdWaitCompletion::Poll { on_timeout } => {
                        assert_eq!(*on_timeout, 0);
                    }
                    FdWaitCompletion::Select { .. } => {
                        panic!("unexpected Select completion for ppoll");
                    }
                }
                assert!(!fds.is_empty(), "WaitFds must contain host poll target");
            }
            other => panic!("expected WaitOnFds outcome, got {other:?}"),
        }

        // Write to eventfd (0 -> 1)
        let write_buf = 0x1140u64;
        guest_mem
            .write_bytes(write_buf, &1u64.to_le_bytes())
            .unwrap();
        assert!(matches!(
            dispatcher.dispatch(
                &kernel,
                SyscallRequest::new(64, SyscallArgs::from([efd as u64, write_buf, 8, 0, 0, 0])),
                &mut guest_mem,
                &reporter
            ),
            Ok(DispatchOutcome::Returned { value: 8 })
        ));

        // Re-dispatch ppoll -> now returns ready value = 1
        let ppoll_ready = dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(
                    73,
                    SyscallArgs::from([pollfds_addr, 1, timeout_addr, 0, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            )
            .unwrap();

        assert_eq!(ppoll_ready, DispatchOutcome::Returned { value: 1 });
        let out_pfd: LinuxPollFd = read_kernel_struct(&guest_mem, pollfds_addr).unwrap();
        assert_eq!(out_pfd.revents & LINUX_POLLIN, LINUX_POLLIN);
    }

    #[test]
    fn nested_epoll_negative_control_control_wake_no_false_readiness() {
        let mut dispatcher = SyscallDispatcher::new();
        let mut guest_mem = LinearMemory::new(0x1000, vec![0; 0x2000]);
        let kernel = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let inner = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);
        let outer = create_epoll(&mut dispatcher, &kernel, &mut guest_mem, &reporter);

        let ev_addr = 0x1000u64;
        write_guest_epoll_event(&mut guest_mem, ev_addr, LINUX_EPOLLIN, 555);
        let _ = dispatcher.dispatch(
            &kernel,
            SyscallRequest::new(
                21,
                SyscallArgs::from([
                    outer as u64,
                    LINUX_EPOLL_CTL_ADD,
                    inner as u64,
                    ev_addr,
                    0,
                    0,
                ]),
            ),
            &mut guest_mem,
            &reporter,
        );

        // Control wake pulse on inner and outer
        let inner_file = dispatcher.open_file(inner).unwrap();
        if let Some(wq) = inner_file.wait_queue() {
            wq.wake_all();
        }
        let outer_file = dispatcher.open_file(outer).unwrap();
        if let Some(wq) = outer_file.wait_queue() {
            wq.wake_all();
        }

        // Logical readiness MUST remain 0!
        assert_eq!(dispatcher.epoll_ready_events(inner, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.epoll_ready_events(outer, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.poll_ready_events(outer, LINUX_POLLIN), 0);

        // epoll_pwait with timeout 0 returns 0 (no false events delivered)
        let events_out = 0x1100u64;
        let wait_outcome = dispatcher
            .dispatch(
                &kernel,
                SyscallRequest::new(
                    22,
                    SyscallArgs::from([outer as u64, events_out, 10, 0, 0, 0]),
                ),
                &mut guest_mem,
                &reporter,
            )
            .unwrap();
        assert_eq!(wait_outcome, DispatchOutcome::Returned { value: 0 });
    }
}

impl<'a> NetView<'a> {
    define_syscall! {
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
                crate::dispatch::EpollKqueue::new(
                    mux,
                    Arc::clone(this.captured_file_table().epoll_wake_registry()),
                )
            };
            let description = OpenDescription::Epoll {
                interest: HashMap::new(),
                synthetic_interest_count: 0,
                base: OpenDescriptionBase::new(0),
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(epoll_kqueue),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
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
                crate::dispatch::EpollKqueue::new(
                    mux,
                    Arc::clone(this.captured_file_table().epoll_wake_registry()),
                )
            };
            let description = OpenDescription::Epoll {
                interest: HashMap::new(),
                synthetic_interest_count: 0,
                base: OpenDescriptionBase::new(0),
                pending_ready: VecDeque::new(),
                kqueue: Arc::new(epoll_kqueue),
                wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
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
            let epoll_description = Arc::clone(&open_file.description);
            let Some(target_file) = this.open_file(fd) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // Same-description alias check (LTP / Linux epoll_ctl EINVAL when target refers to this epoll instance)
            if epoll_description.id() == target_file.description.id() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The host fd backing this target (sockets/pipes/ptys); `None` for an
            // in-memory eventfd/pipe/timerfd, whose readiness is recomputed each
            // `epoll_wait` rather than registered on the kqueue. Computed before
            // taking the epoll write lock (it locks the *target* fd's description).
            let host_fd = this.host_fd_for_poll(fd);
            let target_description = Some(Arc::clone(&target_file.description));

            // Record this epoll instance for the consumption-based EPOLLET
            // re-arm ([`Self::epoll_rearm_after_io`]) BEFORE taking the
            // description lock (the re-arm path snapshots this set first, then
            // locks descriptions — registering here keeps the lock order
            // acyclic). A non-epoll epfd inserted on the error path below is
            // harmless: the re-arm prunes it lazily.
            this.captured_file_table().write_epoll_fds().insert(epfd);

            let Some(mut open) = open_file.description.write() else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let OpenDescription::Epoll {
                interest,
                synthetic_interest_count,
                pending_ready,
                kqueue,
                wait_queue,
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
                    if this.epoll_add_would_loop_desc(&target_file.description, epoll_description.id()) {
                        return Ok(DispatchOutcome::errno(carrick_abi::LINUX_ELOOP));
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
                        let effective = this.epoll_effective_interest(fd, ev_events, 0, 0, false);
                        let register = kqueue.with_mux(|mux| {
                            mux.register_io(
                                host_fd.get(),
                                pack_epoll_udata(fd, reg_gen),
                                effective,
                                epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(
                                    ev_events,
                                )),
                            )
                        });
                        // An error-queue socket's ICMP error lands on its
                        // SHADOW, which the guest knows nothing about. Register
                        // it under the SAME udata so an event there wakes this
                        // epoll and the level recompute reports the queued
                        // error. Without it the guest parks in epoll_wait with
                        // an error it is never told about — the error arrives
                        // asynchronously, after the send has already returned.
                        if let Some(shadow) = recverr::shadow_fd(host_fd.get()) {
                            let _ = kqueue.with_mux(|mux| {
                                mux.register_io(
                                    shadow,
                                    pack_epoll_udata(fd, reg_gen),
                                    effective,
                                    epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(
                                        ev_events,
                                    )),
                                )
                            });
                        }
                        if let Err(err) = register {
                            return Ok(DispatchOutcome::errno(crate::host_to_linux_errno(
                                err.errno,
                            )));
                        }
                        crate::event_ring::rec(
                            crate::event_ring::EPADD,
                            kqueue.poll_fd(),
                            host_fd.get(),
                            ev_events as i32,
                        );
                    }
                    let kqueue_weak = Arc::downgrade(kqueue);
                    let owner_wq_weak = Arc::downgrade(wait_queue);
                    let owner_id = epoll_description.id();
                    let callback_enrollment = if let Some(target) = &target_description
                        && let Some(target_wq) = target.wait_queue()
                    {
                        let target_id = target.id();
                        Some(Arc::new(target_wq.enroll_callback(move |depth: usize| {
                            if let Some(kqueue) = kqueue_weak.upgrade() {
                                kqueue.wake_parked();
                            }
                            if let Some(owner_wq) = owner_wq_weak.upgrade() {
                                owner_wq.wake_all_with_depth(depth);
                            }
                            crate::event_ring::rec(
                                crate::event_ring::EPWAKE,
                                owner_id.raw() as i32,
                                target_id.raw() as i32,
                                depth as i32,
                            );
                        })))
                    } else {
                        None
                    };
                    if let Some(target) = &target_description {
                        target.register_epoll_owner(&epoll_description, fd);
                        crate::event_ring::rec(
                            crate::event_ring::EPOWNER,
                            epoll_description.id().raw() as i32,
                            target.id().raw() as i32,
                            fd,
                        );
                    }
                    interest.insert(
                        fd,
                        EpollInterest {
                            target: target_description,
                            host_poll_source: host_fd.is_some(),
                            event,
                            last_ready: 0,
                            last_read_avail: 0,
                            write_backpressured: false,
                            io_gen: 0,
                            reg_gen,
                            _callback_enrollment: callback_enrollment,
                        },
                    );
                    if host_fd.is_none() {
                        *synthetic_interest_count += 1;
                    }
                    // A waiter parked on this instance's ppoll snapshot does
                    // not watch the just-added fd; pop it so it rebuilds.
                    kqueue.wake_parked();
                    drop(open);
                    if let Some(wq) = open_file.description.wait_queue() {
                        wq.wake_all();
                    }
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
                    let host_poll_source = slot.host_poll_source;
                    if let Some(host_fd) = host_fd {
                        let effective =
                            this.epoll_effective_interest(fd, event.events, 0, 0, false);
                        let register = kqueue.with_mux(|mux| {
                            mux.register_io(
                                host_fd.get(),
                                pack_epoll_udata(fd, reg_gen),
                                effective,
                                epoll_host_trigger_mode(LinuxEpollEvents::from_bits_retain(
                                    event.events,
                                )),
                            )
                        });
                        if let Err(err) = register {
                            return Ok(DispatchOutcome::errno(crate::host_to_linux_errno(
                                err.errno,
                            )));
                        }
                    }
                    clear_pending_epoll_ready(pending_ready, fd);
                    *slot = EpollInterest {
                        target: slot.target.clone(),
                        host_poll_source,
                        event,
                        last_ready: 0,
                        last_read_avail: 0,
                        write_backpressured: false,
                        io_gen: 0,
                        reg_gen,
                        _callback_enrollment: slot._callback_enrollment.clone(),
                    };
                    // Re-arm visible to a parked waiter: rebuild its park set.
                    kqueue.wake_parked();
                    drop(open);
                    if let Some(wq) = open_file.description.wait_queue() {
                        wq.wake_all();
                    }
                    crate::probes::epoll_ctl(epfd, operation, fd, event.events, event.data, 0);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                LINUX_EPOLL_CTL_DEL => {
                    let Some(removed) =
                        remove_epoll_interest(interest, synthetic_interest_count, fd)
                    else {
                        return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                    };
                    let removed_reg_gen = removed.reg_gen;
                    if let Some(target) = &removed.target {
                        target.unregister_epoll_owner(&epoll_description, fd);
                        crate::event_ring::rec(
                            crate::event_ring::EPRETIRE,
                            epoll_description.id().raw() as i32,
                            fd,
                            removed_reg_gen as i32,
                        );
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
                        this.rebind_epoll_host_registration(
                            kqueue,
                            interest,
                            host_fd,
                            EPOLL_REBIND_REASON_CTL_DEL,
                            None,
                        );
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
                    drop(open);
                    if let Some(wq) = open_file.description.wait_queue() {
                        wq.wake_all();
                    }
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
            let clock = Arc::clone(cx.kernel.task().container().clock());
            let timeout_ms = if timeout as i32 > 0 && clock.is_scaled() {
                let scaled =
                    clock.scale_timeout(std::time::Duration::from_millis(timeout as i32 as u64));
                i32::try_from(scaled.as_millis()).unwrap_or(i32::MAX)
            } else {
                timeout as i32
            };
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

            let files = this.captured_file_table();
            let open_file = files.read_open_files().get(&epfd).cloned();
            crate::probes::epoll_lookup(|| {
                let (slot_generation, file_description_id, lookup_kind) = match &open_file {
                    Some(open_file) => (
                        open_file.generation(),
                        open_file.description.id().raw(),
                        if open_file.description.is_epoll() { 0 } else { 1 },
                    ),
                    None => (0, 0, 2),
                };
                (
                    files.id().raw(),
                    epfd,
                    slot_generation,
                    file_description_id,
                    lookup_kind,
                )
            });
            let Some(open_file) = open_file else {
                // A valid fd that simply isn't an epoll instance is EINVAL; only a
                // genuinely bad fd is EBADF. (LTP epoll_wait03.)
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            this.epoll_pwait_wait_core(
                memory,
                open_file,
                epfd,
                events_address,
                guest_abi,
                max_events,
                timeout_ms,
                sig_mask,
            )

        }

        fn epoll_pwait2(this, cx, epfd: Fd, events: GuestPtr, maxevents: u64, timeout: GuestPtr, sigmask: GuestPtr, sigsetsize: u64) {
            let epfd = epfd.0;
            let events_address = events.0;
            let timeout_addr = timeout.0;
            let sigmask_ptr = sigmask.0;
            let guest_abi = cx.guest_abi();
            let memory = &mut *cx.memory;
            let max_events_signed = maxevents as i32;
            if max_events_signed <= 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let max_events = max_events_signed as usize;
            // epoll_pwait2 carries the SAME sigmask (arg4) + sigsetsize (arg5)
            // contract as epoll_pwait: a non-NULL mask must have the right size
            // and a readable pointer (else EINVAL/EFAULT), and it REPLACES the
            // thread mask for the wait so a blocked signal doesn't interrupt it.
            // Capture it as a typed SigSet exactly like epoll_pwait so both feed
            // the shared wait core identically (LTP epoll_pwait01).
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
            let sig_mask = if sigmask_ptr != 0 {
                carrick_abi::WaitSigMask::Replace(block_signals)
            } else {
                carrick_abi::WaitSigMask::NONE
            };
            // epoll_pwait2's timeout is a *timespec (nsec), unlike epoll_pwait's
            // millisecond int; decode it to the timeout_ms the shared wait core
            // consumes. NULL = block forever (-1). Invalid timespec -> EINVAL,
            // bad pointer -> EFAULT (LTP epoll_pwait04).
            let timeout_ms = if timeout_addr == 0 {
                -1
            } else {
                let timespec = match read_kernel_struct::<LinuxTimespec>(memory, timeout_addr) {
                    Ok(timespec) => timespec,
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                let sec = timespec.tv_sec;
                let nsec = timespec.tv_nsec;
                if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
                if ms <= 0 {
                    0
                } else {
                    let dur = std::time::Duration::from_millis(ms as u64);
                    let clock = Arc::clone(cx.kernel.task().container().clock());
                    let scaled = clock.scale_timeout(dur);
                    i32::try_from(scaled.as_millis()).unwrap_or(i32::MAX)
                }
            };
            let files = this.captured_file_table();
            let open_file = files.read_open_files().get(&epfd).cloned();
            crate::probes::epoll_lookup(|| {
                let (slot_generation, file_description_id, lookup_kind) = match &open_file {
                    Some(open_file) => (
                        open_file.generation(),
                        open_file.description.id().raw(),
                        if open_file.description.is_epoll() { 0 } else { 1 },
                    ),
                    None => (0, 0, 2),
                };
                (
                    files.id().raw(),
                    epfd,
                    slot_generation,
                    file_description_id,
                    lookup_kind,
                )
            });
            let Some(open_file) = open_file else {
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(epfd) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            // Delegate to the SHARED epoll_pwait wait core. epoll_pwait2 formerly
            // returned ENOSYS whenever a real wait/readiness sample was required,
            // diverging from epoll_pwait (LTP epoll_pwait01/02/03).
            this.epoll_pwait_wait_core(
                memory,
                open_file,
                epfd,
                events_address,
                guest_abi,
                max_events,
                timeout_ms,
                sig_mask,
            )
        }

    }
}
