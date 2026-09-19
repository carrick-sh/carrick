//! Scalar-write completion with no captured file-table authority.
use super::*;

/// Exact target chosen by the I/O handler, not a numeric descriptor to resolve
/// on return. The Arc preserves identity without keeping a table or endpoint
/// functionally live throughout the host operation.
pub(in crate::dispatch) struct WriteRearm {
    target: Option<Arc<crate::kernel::FileDescription>>,
}

impl WriteRearm {
    pub(in crate::dispatch) fn new(target: Option<Arc<crate::kernel::FileDescription>>) -> Self {
        // epoll_ctl requires a table-backed target. None deliberately records
        // that bare stdio needs no rearm, not permission for a later fd lookup.
        Self { target }
    }
    pub(in crate::dispatch) fn complete(self, outcome: &DispatchOutcome) {
        const WRITE_CLEAR: u32 = LINUX_EPOLLOUT | LINUX_EPOLLHUP | LINUX_EPOLLERR;
        let positive = matches!(outcome, DispatchOutcome::Returned { value } if *value > 0);
        let eagain = matches!(outcome, DispatchOutcome::Errno { errno } if *errno == LINUX_EAGAIN);
        if !positive && !eagain {
            return;
        }
        let Some(target) = self.target else { return };
        // Pin only for the short completion, never across the host wait. Drop
        // outside all epoll guards; final endpoint close can run callbacks.
        let Some(_endpoint) = target.retain_fd_lease() else {
            return;
        };
        // A newly added watch can deliver an edge before I/O completes too.
        for owner in target.epoll_owners() {
            let Some(mut open) = owner.write() else {
                continue;
            };
            let OpenDescription::Epoll {
                interest, kqueue, ..
            } = &mut *open
            else {
                continue;
            };
            let mut rebind = false;
            for (&fd, slot) in interest.iter_mut() {
                if !slot
                    .target
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &target))
                {
                    continue;
                }
                if positive {
                    let before = slot.last_ready;
                    slot.io_gen = slot.io_gen.wrapping_add(1);
                    slot.last_ready &= !WRITE_CLEAR;
                    slot.write_backpressured = false;
                    crate::event_ring::rec(
                        crate::event_ring::EPCMSUM,
                        fd,
                        slot.io_gen as i32,
                        WRITE_CLEAR as i32,
                    );
                    rebind |= before != slot.last_ready || slot.event.events & LINUX_EPOLLET != 0;
                } else if slot.event.events & (LINUX_EPOLLET | LINUX_EPOLLOUT)
                    == (LINUX_EPOLLET | LINUX_EPOLLOUT)
                {
                    slot.write_backpressured = true;
                    rebind = true;
                }
            }
            #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
            if rebind {
                if let Some(host_fd) = NetView::description_host_fd_for_poll(&target) {
                    rebind_owned(kqueue, interest, host_fd);
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
            let _ = (rebind, kqueue);
        }
    }
}

/// Recompute the current union so concurrent MOD/DEL is never overwritten by
/// a pre-wait mask. Every source is resolved from its exact retained target.
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
fn rebind_owned(kqueue: &Arc<EpollKqueue>, slots: &HashMap<i32, EpollInterest>, host_fd: HostFd) {
    let mut survivor = None;
    let mut union = carrick_hal::event::Interest::default();
    let mut events = 0;
    let mut level = false;
    for (&fd, slot) in slots {
        let Some(target) = slot.target.as_ref() else {
            continue;
        };
        if NetView::description_host_fd_for_poll(target) != Some(host_fd) {
            continue;
        }
        survivor.get_or_insert((fd, slot.reg_gen));
        events |= slot.event.events;
        level |= slot.event.events & LINUX_EPOLLET == 0;
        let effective = NetView::description_epoll_effective_interest(
            Some(target),
            slot.event.events,
            slot.last_ready,
            slot.write_backpressured,
        );
        union.read |= effective.read;
        union.write |= effective.write;
        union.oob |= effective.oob;
    }
    union.mode = if level {
        carrick_hal::event::TriggerMode::Level
    } else {
        carrick_hal::event::TriggerMode::Edge
    };
    let (fd, generation) = survivor.unwrap_or((-1, 0));
    crate::probes::epoll_rebind(
        EPOLL_REBIND_REASON_IO_REARM,
        host_fd.get(),
        fd,
        generation,
        events,
        u32::from(union.read) | (u32::from(union.write) << 1) | (u32::from(union.oob) << 2),
    );
    kqueue.with_mux(|mux| match survivor {
        Some((fd, generation)) => {
            let _ = mux.register_io(
                host_fd.get(),
                pack_epoll_udata(fd, generation),
                union,
                union.mode,
            );
        }
        None => {
            let _ = mux.deregister(host_fd.get());
        }
    });
}
