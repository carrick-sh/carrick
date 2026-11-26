//! The ring's one harvest of a zone epoll that may hold carrier sockets,
//! shared by a guest `epoll_pwait` (`super::epoll`) and a readiness set
//! (`super::readiness_set`).
//!
//! Once an epoll has hosted a carrier socket, the carrier's reactor takes
//! the same epoll lock on every host event. A ring harvest then probes the
//! lock once through the tracked release (`BoundedSpin(0)`): a carrier
//! holder is "not now", so the call enrols on the holder's release, parks,
//! and reruns the harvest once it is published. It never spins on a host
//! thread and never answers an errno for contention.

use super::{EL1_WAIT, IpcExecution, IpcRegion};
use carrick_el1_abi::ipc::epoll::{EpollHarvest, EpollItemRef, EpollReport};
use carrick_el1_abi::ipc::{IpcError, IpcObjectHandle, IpcOperation};
use carrick_sched_core::object_wait::ipc_release::{
    IpcLockIndex, IpcLockRelease, IpcLockReleaseVenue,
};
use carrick_sched_core::object_wait::{ObjectStateSnapshot, ObjectWaitKey};

pub(super) struct EpollLockRelease<'a, C: carrick_el1_abi::EntryContext> {
    index: IpcLockIndex,
    venue: IpcLockReleaseVenue<'a, C>,
}

impl<C: carrick_el1_abi::EntryContext> IpcLockRelease for EpollLockRelease<'_, C> {
    fn carrier(&self) -> core::num::NonZeroU64 {
        self.venue.carrier
    }

    fn released(&self, index: IpcLockIndex) {
        if self.index == index {
            self.venue.released(index);
        }
    }
}

pub(super) enum Harvest {
    Ready(EpollHarvest),
    WaitForRelease(IpcOperation, ObjectWaitKey, ObjectStateSnapshot),
    Refused,
}

pub(super) fn harvest<E: IpcExecution>(
    sched: &E,
    region: &IpcRegion<'_>,
    epoll: IpcObjectHandle,
    operation: IpcOperation,
    reports: &mut [EpollReport],
    taken: &mut [EpollItemRef],
) -> Harvest {
    use carrick_sched_core::refusal::{Attempt, ContentionSource, Refusal, ReleaseCause, Settled};
    let carrier = region.operation_slot_generation();
    let release = IpcLockIndex::object(epoll.index() as usize)
        .filter(|_| region.epoll_needs_host_release(epoll))
        .and_then(|index| {
            let source = sched.zone().ipc_lock_release_source(index, carrier).ok()?;
            Some((index, source))
        });
    let Some((index, source)) = release else {
        return region
            .epoll_harvest(epoll, reports, taken, &EL1_WAIT)
            .map_or(Harvest::Refused, Harvest::Ready);
    };
    let adapter = EpollLockRelease {
        index,
        venue: IpcLockReleaseVenue {
            zone: sched.zone(),
            carrier,
            waker: carrick_sched_core::Waker::El1 { slot: sched.slot() },
            deliver: crate::sched::object_wait::deliver_host_completion,
        },
    };
    let tracked = region
        .with_lock_release(&adapter)
        .unwrap_or_else(|_| invalid());
    match source.contend(|| {
        match tracked.lock_epoll(epoll, &carrick_sched_core::BoundedSpin(0)) {
            Ok(guard) => Ok(guard),
            Err(IpcError::Contended) if region.has_tracked_lock_holder(epoll) => {
                Err(Attempt::Contended(ReleaseCause::Object))
            }
            Err(IpcError::Contended) => {
                // The failed probe observed a racing release or a legacy
                // holder. A legacy holder owes no release publication.
                tracked
                    .lock_epoll(epoll, &EL1_WAIT)
                    .map_err(|error| Attempt::Settled(Settled::Guest(error)))
            }
            Err(error) => Err(Attempt::Settled(Settled::Guest(error))),
        }
    }) {
        Ok(guard) => tracked
            .epoll_harvest_locked(guard, reports, taken, &EL1_WAIT)
            .map_or(Harvest::Refused, Harvest::Ready),
        // SAFETY: the pinned syscall and the pre-probe revision are passed
        // directly to its scheduler park below. A raced park returns the
        // same operation for one immediate rerun. No guard crosses the park.
        Err(Refusal::Contended(ticket)) => unsafe {
            ticket.park_and_rerun(operation, |op, enrollment| {
                Harvest::WaitForRelease(
                    op,
                    enrollment.key(),
                    ObjectStateSnapshot::before_object_probe(enrollment.observed()),
                )
            })
        },
        Err(Refusal::Invariant(_)) => invalid(),
        Err(Refusal::Guest(_)) => Harvest::Refused,
    }
}

/// A broken custody invariant: fail the run.
fn invalid<T>() -> T {
    crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding)
}
