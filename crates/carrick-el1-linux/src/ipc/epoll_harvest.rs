//! The ring's one harvest of a zone epoll that may hold carrier sockets,
//! shared by a guest `epoll_pwait` (`super::epoll`) and a readiness set
//! (`super::readiness_set`).
//!
//! Once an epoll has hosted a carrier socket, the carrier's reactor takes
//! the same epoll lock on every host event. A ring harvest takes that lock,
//! first and at every relock between member reads, under one policy: a
//! carrier holder is "not now", so the harvest puts back everything it
//! took, the call enrols on the holder's release, parks, and reruns the
//! whole harvest once it is published. It never spins on a host thread and
//! never answers an errno for contention.

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
    // One policy for the first acquisition and every relock: a carrier
    // holder is "not now" (the harvest takes nothing and enrols on its
    // release); an EL1 holder is a short critical section, waited out.
    let not_now = CarrierNotNow { region, epoll };
    let attempt = |error| match error {
        IpcError::Contended => Attempt::Contended(ReleaseCause::Object),
        error => Attempt::Settled(Settled::Guest(error)),
    };
    match source.contend(|| {
        let guard = tracked.lock_epoll(epoll, &not_now).map_err(attempt)?;
        tracked
            .epoll_harvest_locked(guard, reports, taken, &EL1_WAIT, &not_now)
            .map_err(attempt)
    }) {
        Ok(harvest) => Harvest::Ready(harvest),
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

/// The epoll lock policy of a harvest that may meet the carrier: a
/// tracked (carrier) holder publishes its release, so contention with it is
/// refused at once; any other holder is an EL1 short critical section.
struct CarrierNotNow<'r, 'a> {
    region: &'r IpcRegion<'a>,
    epoll: IpcObjectHandle,
}

impl carrick_sched_core::LockWait for CarrierNotNow<'_, '_> {
    fn wait(&self, _attempt: u32) -> bool {
        if self.region.has_tracked_lock_holder(self.epoll) {
            return false;
        }
        core::hint::spin_loop();
        true
    }
}

/// A broken custody invariant: fail the run.
fn invalid<T>() -> T {
    crate::dispatch::invalid_completion(crate::dispatch::NativeInvariant::EntryBinding)
}
