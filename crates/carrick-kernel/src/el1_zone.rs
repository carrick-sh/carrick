//! The host venue of the in-guest scheduler zone (EL1 plan 1b).
//!
//! Guest EL1 serves the private futex operations of a zone process in the
//! guest and switches between its threads without a host exit; the host
//! serves the rest of that process's private futex operations (timed waits,
//! `futex_waitv`, requeue, and every wait EL1 forwarded) on the SAME queues,
//! through the same `carrick_sched_core` functions. One queue per process, two
//! venues. The ownership protocol of a parked thread is in
//! `carrick_sched_core`; this module is the host's side of it:
//!
//! - [`zone`]: the tables, when the carrier maps the EL1 region, schedules
//!   threads in the guest (it has the in-kernel GIC, [`enable`]) and the
//!   `CARRICK_EL1_FUTEX=0` bisection hatch is not set.
//! - [`claim`]: take a parked thread for a signal, a timeout, a control wake
//!   or a cancellation; a thread EL1 holds is reached by kicking its vCPU
//!   slot (its executor hands it back at that exit), never by writing it.
//! - [`wake`] / [`requeue`]: host wakes, whose woken records the runtime then
//!   hands back to their threads.

use std::sync::OnceLock;

use carrick_el1_abi::{
    Handback, HostClaim, LockWait, RecordRef, SlotId, Waker, ZoneTables, zone_tables,
};

/// The host waits for a bucket lock by spinning, then yielding. A holder is
/// either a host thread in a short critical section or a vCPU inside EL1,
/// which its executor always resumes to completion.
pub struct HostLockWait;

impl LockWait for HostLockWait {
    fn wait(&self, attempt: u32) -> bool {
        if attempt < 128 {
            std::hint::spin_loop();
        } else {
            std::thread::yield_now();
        }
        true
    }
}

fn hatch_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CARRICK_EL1_FUTEX").map_or(true, |value| value.trim() != "0")
    })
}

static GUEST_SCHEDULER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The carrier schedules threads in the guest: its VM has the interrupt
/// controller the in-guest scheduler needs (virtual timer and SGIs taken at
/// EL1). Without it (`CARRICK_HVF_GIC=0`, other backends) the zone is off,
/// exactly as with `CARRICK_EL1_FUTEX=0`: a woken thread could otherwise
/// wait behind a running one with nothing to preempt it.
pub fn enable(guest_interrupts: bool) {
    GUEST_SCHEDULER.store(guest_interrupts, std::sync::atomic::Ordering::Release);
}

/// The zone tables, if this carrier serves private futexes in the zone.
pub fn zone() -> Option<&'static ZoneTables> {
    if !hatch_enabled() || !GUEST_SCHEDULER.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    zone_tables()
}

/// How the host reaches a vCPU slot: mark pending host work and force its
/// vCPU out of the guest. Registered by the HVF carrier.
pub type SlotKicker = Box<dyn Fn(SlotId) + Send + Sync>;

static SLOT_KICKER: OnceLock<SlotKicker> = OnceLock::new();

/// Register the carrier's slot kicker (once per process).
pub fn register_slot_kicker(kicker: SlotKicker) {
    let _ = SLOT_KICKER.set(kicker);
}

/// Force the vCPU on `slot` to exit, so its executor takes back every thread
/// EL1 holds there.
pub fn kick_slot(slot: SlotId) {
    carrick_el1_abi::mark_pending_host_work(usize::from(slot.raw()));
    if let Some(kicker) = SLOT_KICKER.get() {
        kicker(slot);
    }
}

/// Claim `record` for `kind` (with `seq`, only that park). A thread EL1 holds
/// has its slot kicked; the caller then waits for the handback.
pub fn claim(record: RecordRef, seq: Option<u32>, kind: Handback) -> HostClaim {
    let Some(zone) = zone_tables() else {
        return HostClaim::Stale;
    };
    let outcome = zone.claim_for_host(record, seq, kind, &HostLockWait);
    if let HostClaim::El1Held { slot } = outcome {
        kick_slot(slot);
    }
    outcome
}

/// Whether the host owns `record` (a wake, a signal, a timeout or a
/// handback claimed it), so its thread may run.
pub fn is_host_owned(record: RecordRef) -> bool {
    zone_tables().is_some_and(|zone| {
        zone.live(record)
            .is_some_and(|rec| matches!(rec.claim(), carrick_el1_abi::Claim::Host { .. }))
    })
}

/// Retire a parked thread whose host continuation is gone: free a record
/// the host could claim, or flag one EL1 holds so its slot discards it.
pub fn cancel(record: RecordRef) {
    let Some(zone) = zone_tables() else {
        return;
    };
    match zone.claim_for_host(record, None, Handback::Cancelled, &HostLockWait) {
        HostClaim::Claimed | HostClaim::AlreadyHost => {
            if zone.live(record).is_some() {
                zone.free_record(record.id);
            }
        }
        HostClaim::El1Held { slot } => {
            if let Some(rec) = zone.live(record) {
                rec.request_cancel();
            }
            kick_slot(slot);
        }
        HostClaim::Deferred | HostClaim::Stale => {}
    }
}

/// What a host futex wake did: how many waiters it woke, and which of them
/// the runtime hands back to their threads (host-owned with
/// [`Handback::Woken`]). Where the guest schedules, the others are already
/// queued in the guest, never host-owned on the way.
#[derive(Debug, Default)]
pub struct ZoneWake {
    pub count: u32,
    pub handed: Vec<RecordRef>,
}

/// Host `FUTEX_WAKE(_BITSET)` on a zone process: wake up to `count` waiters
/// of `(mm, uaddr)` matching `bitset`.
pub fn wake(zone: &ZoneTables, mm: u64, uaddr: u64, bitset: u32, count: u32) -> ZoneWake {
    let mut wake = ZoneWake::default();
    let mut placements = Vec::new();
    let mut transfers = Vec::new();
    {
        let Some(guard) = zone.lock(ZoneTables::bucket_of(mm, uaddr), &HostLockWait) else {
            return wake;
        };
        wake.count = zone.wake_host(
            &guard,
            mm,
            uaddr,
            bitset,
            count,
            schedules_in_guest(),
            &mut |transfer| transfers.push(transfer),
            &mut |placement| placements.push(placement),
        );
    }
    for placement in placements {
        deliver_placement(Some(placement));
    }
    // A futex_waitv park is queued on other buckets too.
    wake.handed = transfers
        .into_iter()
        .filter_map(|transfer| transfer.finish(&HostLockWait))
        .collect();
    wake
}

/// Host `FUTEX_(CMP_)REQUEUE` on a zone process: under both bucket locks,
/// check `check` (the CMP value comparison; `Err` aborts with that errno),
/// wake up to `wake_count` waiters of `from`, then move up to
/// `requeue_count` of the rest to `to`. Returns the woken records and the
/// number moved.
pub fn requeue<E>(
    zone: &ZoneTables,
    mm: u64,
    from: u64,
    to: u64,
    wake_count: u32,
    requeue_count: u32,
    check: impl FnOnce() -> Result<(), E>,
) -> Result<(Vec<RecordRef>, u32), E> {
    let from_bucket = ZoneTables::bucket_of(mm, from);
    let to_bucket = ZoneTables::bucket_of(mm, to);
    let (first, second) = if from_bucket <= to_bucket {
        (from_bucket, to_bucket)
    } else {
        (to_bucket, from_bucket)
    };
    let mut woken = Vec::new();
    let mut transfers = Vec::new();
    let moved;
    {
        let Some(first_guard) = zone.lock(first, &HostLockWait) else {
            return Ok((woken, 0));
        };
        let second_guard = if second != first {
            zone.lock(second, &HostLockWait)
        } else {
            None
        };
        let (from_guard, to_guard) = match &second_guard {
            Some(second_guard) if from_bucket == first => (&first_guard, second_guard),
            Some(second_guard) => (second_guard, &first_guard),
            None => (&first_guard, &first_guard),
        };
        check()?;
        let mut remaining = wake_count;
        let mut batch = [const { carrick_el1_abi::WakeRecord::Empty }; 64];
        while remaining > 0 {
            let Ok(n) = zone.wake(
                from_guard,
                mm,
                from,
                u32::MAX,
                remaining,
                Waker::Host,
                &mut batch,
            ) else {
                break;
            };
            transfers.extend(
                batch
                    .iter_mut()
                    .take(n as usize)
                    .map(|entry| core::mem::replace(entry, carrick_el1_abi::WakeRecord::Empty)),
            );
            if (n as usize) < batch.len() {
                break;
            }
            remaining -= n;
        }
        moved = zone.requeue(from_guard, to_guard, mm, from, to, requeue_count);
    }
    woken.extend(
        transfers
            .iter_mut()
            .filter_map(|entry| entry.take_ready(&HostLockWait)),
    );
    Ok((woken, moved))
}

/// Whether the zone thread `record` is running or runnable in the guest
/// (`Some(true)`: queued, on a vCPU, or claimed by the host to run) or parked
/// there (`Some(false)`); `None` if the record is gone.
pub fn record_runs(record: RecordRef) -> Option<bool> {
    let rec = zone_tables()?.live(record)?;
    match rec.claim() {
        carrick_el1_abi::Claim::Parked { .. } | carrick_el1_abi::Claim::Transferring { .. } => {
            Some(false)
        }
        carrick_el1_abi::Claim::Queued { .. }
        | carrick_el1_abi::Claim::OnCpu { .. }
        | carrick_el1_abi::Claim::Host { .. } => Some(true),
        _ => None,
    }
}

/// Whether the thread `key`, which the host loaded on a vCPU, is parked in
/// EL1 there: its slot's home record is `Parked` (its vCPU runs another thread
/// or idles, and the host learns it at the next exit).
pub fn home_record_parked(key: crate::kernel::ThreadKey) -> bool {
    let Some(zone) = zone_tables() else {
        return false;
    };
    (0..carrick_el1_abi::ZONE_SLOTS)
        .filter_map(SlotId::from_index)
        .filter_map(|slot| zone.slot(slot).host_record())
        .any(|record| {
            let rec = zone.record(record);
            matches!(rec.claim(), carrick_el1_abi::Claim::Parked { .. })
                && thread_key_of(zone.record_ref(record)) == Some(key)
        })
}

/// The kernel thread a record names.
pub fn thread_key_of(record: RecordRef) -> Option<crate::kernel::ThreadKey> {
    let zone = zone_tables()?;
    let rec = zone.live(record)?;
    let identity = rec.identity();
    let tid = i32::try_from(identity.tid).ok()?;
    let serial = std::num::NonZeroU64::new(identity.serial)?;
    crate::kernel::ThreadKey::from_zone_identity(tid, serial)
}

/// Outcome of [`read_quiesced_parked_registers`].
///
/// Cold, rare (crash capture only): boxing `Found` would add an allocation
/// for every call solely to shrink the two empty variants.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum QuiescedParkedRegisters {
    /// `key` has no live EL1-parked record right now: it is running, is
    /// host-owned, or its record is gone. The caller's own crash-capture
    /// safe-point protocol owns the answer instead.
    NotParked,
    /// The exact architectural state EL1 saved for `key`, converted to the
    /// core-dump register-file shape.
    Found(carrick_hal::Aarch64CoreRegisters),
    /// A record matched `key`'s identity but changed while it was being
    /// read: refuse to attribute those bytes to `key` rather than publish an
    /// unauthenticated register file.
    Unauthenticated,
}

/// Read `key`'s EL1 save area for address space `mm`, converted to the
/// host's crash-capture register-file shape, if EL1 currently holds it
/// parked (queued on a futex wait queue or a vCPU run queue).
///
/// A thread parked in a syscall resumes directly at EL0 with no host trap
/// pending, exactly as the runtime's zone-residency loader (`materialize_zone`,
/// `carrick-runtime`) overlays it to run: there is no separate "live vCPU
/// state" for a thread EL1 is not currently running, so the same
/// `pc`/`pstate` pair fills every raw/live/resume field of the result,
/// mirroring that loader's field assignments.
///
/// # Safety
///
/// The caller must have already authenticated that no vCPU of address space
/// `mm` can be executing guest code right now (every one of its vCPUs
/// force-exited to the host and its execution-lease set drained) — the
/// crash-capture quiesce barrier does exactly this before it ever polls a
/// register-file quorum. See [`ZoneTables::read_parked_context`] for why that
/// authentication is what makes this read race-free.
pub unsafe fn read_quiesced_parked_registers(
    mm: u64,
    key: crate::kernel::ThreadKey,
) -> QuiescedParkedRegisters {
    // `zone()`, not the raw `zone_tables()`: a carrier with the futex zone or
    // guest scheduling hatched off never parks a thread in EL1 in the first
    // place, so its (still-mapped) records must not be consulted as if they
    // could be authoritative.
    let Some(zone) = zone() else {
        return QuiescedParkedRegisters::NotParked;
    };
    let Ok(tid) = u64::try_from(key.tid.raw()) else {
        return QuiescedParkedRegisters::NotParked;
    };
    // SAFETY: forwarded by the caller (see the doc comment above).
    match unsafe { zone.read_parked_context(mm, tid, key.serial.raw()) } {
        carrick_el1_abi::ParkedContextRead::NotParked => QuiescedParkedRegisters::NotParked,
        carrick_el1_abi::ParkedContextRead::Unauthenticated => {
            QuiescedParkedRegisters::Unauthenticated
        }
        carrick_el1_abi::ParkedContextRead::Found(ctx) => {
            QuiescedParkedRegisters::Found(carrick_hal::Aarch64CoreRegisters {
                gprs: ctx.x,
                sp_el0: ctx.sp_el0,
                resume_pc: ctx.pc,
                resume_pstate: ctx.pstate,
                pc: ctx.pc,
                pstate: ctx.pstate,
                elr_el1: ctx.pc,
                spsr_el1: ctx.pstate,
                tpidr_el0: ctx.tpidr_el0,
                vregs: ctx.v,
                fpsr: ctx.fpsr as u32,
                fpcr: ctx.fpcr as u32,
            })
        }
    }
}

/// Force `slot`'s vCPU out of the guest WITHOUT host work: a host placement
/// owes it a reschedule SGI (`ZoneTables::take_resched`), which its run loop
/// raises before the vCPU runs on.
pub fn resched_slot(slot: SlotId) {
    if let Some(kicker) = SLOT_KICKER.get() {
        kicker(slot);
    }
}

fn deliver_placement(placed: Option<carrick_el1_abi::HostPlacement>) -> bool {
    match placed {
        Some(placement) => {
            if placement.resched {
                resched_slot(placement.slot);
            }
            true
        }
        None => false,
    }
}

fn guest_scheduling_hatch_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("CARRICK_EL1_SCHED").map_or(true, |value| value.trim() != "0")
    })
}

/// Whether this carrier schedules its threads in the guest (EL1 plan 1d):
/// a runnable thread goes to an EL1 run queue, never to a host run queue,
/// and an executor with no thread waits in the guest. `CARRICK_EL1_SCHED=0`
/// (exact) is the bisection hatch: host run queues and condvar parks, with
/// the in-guest futex zone still on.
pub fn schedules_in_guest() -> bool {
    guest_scheduling_hatch_enabled() && zone().is_some()
}

/// Count a runnable thread an executor took from a host run queue.
pub fn count_host_queue_claim() {
    if let Some(zone) = zone() {
        zone.counters
            .host_queue_claims
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Count an executor parking on a host run-queue condvar for work.
pub fn count_host_executor_park() {
    if let Some(zone) = zone() {
        zone.counters
            .host_executor_parks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Queue, in the guest, a thread the host made runnable at `generation`
/// (a completed host wait, a first run, a control action): a service record
/// ([`Handback::Service`]) that EL1 orders with the rest of a vCPU's run
/// queue and that the vCPU's executor loads when EL1 reaches it. False: no
/// record could be allocated; the caller keeps the thread on the host.
pub fn place_service(
    thread: crate::kernel::ThreadKey,
    generation: crate::kernel::objects::ExecutionGeneration,
    affinity: u64,
) -> bool {
    let Some(zone) = zone() else {
        return false;
    };
    let identity = carrick_el1_abi::ThreadIdentity {
        tid: carrick_el1_abi::El1TaskId::from_linux_tid(thread.tid.raw()).raw(),
        serial: thread.serial.raw(),
        mm: 0,
        file_table: 0,
        generation: generation.raw(),
        affinity,
    };
    let Ok(record) = zone.alloc_host_runnable(identity) else {
        return false;
    };
    if deliver_placement(zone.place_from_host(record)) {
        return true;
    }
    zone.free_record(record);
    false
}

/// Take a service record the host could not place (host-owned): free it and
/// return the exact row it stood for. `None` for any other record.
pub fn take_unplaced_service(
    record: RecordRef,
) -> Option<(
    crate::kernel::ThreadKey,
    crate::kernel::objects::ExecutionGeneration,
)> {
    let zone = zone_tables()?;
    let rec = zone.live(record)?;
    if rec.handback() != Some(Handback::Service)
        || !matches!(rec.claim(), carrick_el1_abi::Claim::Host { .. })
    {
        return None;
    }
    let key = service_key(record);
    zone.free_record(record.id);
    key
}

/// The exact runnable generation a service record names.
pub fn service_key(
    record: RecordRef,
) -> Option<(
    crate::kernel::ThreadKey,
    crate::kernel::objects::ExecutionGeneration,
)> {
    let zone = zone_tables()?;
    let rec = zone.live(record)?;
    let key = thread_key_of(record)?;
    Some((
        key,
        crate::kernel::objects::ExecutionGeneration::from_raw(rec.identity().generation),
    ))
}

/// How the host hands a zone thread back to its host continuation (its zone
/// wait becomes ready and the scheduler makes it runnable). Registered by
/// the carrier with its scheduler.
pub type HandbackPublisher = Box<dyn Fn(RecordRef) + Send + Sync>;

static HANDBACK_PUBLISHER: parking_lot::RwLock<Option<HandbackPublisher>> =
    parking_lot::RwLock::new(None);

/// Register the handback publisher of the carrier's current scheduler. Each
/// start of the executor pool registers its own scheduler (a carrier may run
/// several containers in turn): a publisher of a retired scheduler would drop
/// every handback.
pub fn register_handback_publisher(publisher: HandbackPublisher) {
    *HANDBACK_PUBLISHER.write() = Some(publisher);
}

/// Hand host-owned zone threads back to their host continuations: each
/// zone wait becomes ready and the scheduler makes its thread runnable.
pub fn hand_back(records: &[RecordRef]) {
    for record in records {
        publish_handback(*record);
    }
}

fn publish_handback(record: RecordRef) {
    if let Some(zone) = zone_tables() {
        zone.counters
            .host_handbacks
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    if let Some(publisher) = HANDBACK_PUBLISHER.read().as_ref() {
        publisher(record);
    }
}

/// The executor of `slot`, stopped: hand every queued thread the host asked
/// for while EL1 held it to its host continuation (a signal, an exit or
/// exec drain acts on it there).
pub fn hand_back_wanted(slot: SlotId) {
    let Some(zone) = zone() else {
        return;
    };
    let mut wanted = Vec::new();
    zone.take_host_wanted(slot, &mut |record| wanted.push(record));
    for record in wanted {
        publish_handback(record);
    }
}

/// The executor of `slot` is about to park on a host run queue (the
/// `CARRICK_EL1_SCHED=0` hatch): nothing runs its vCPU while it waits, so
/// every thread queued there goes to its host continuation.
pub fn drain_to_host(slot: SlotId) {
    let Some(zone) = zone() else {
        return;
    };
    let mut handed = Vec::new();
    zone.drain_slot(slot, &mut |record, discard| {
        if discard {
            zone.free_record(record.id);
        } else {
            handed.push(record);
        }
    });
    for record in handed {
        publish_handback(record);
    }
}

/// Executor `driver` of `slot` entered a blocking inline host wait and lent
/// its guest CPU: its stopped vCPU may hold no thread another vCPU could run,
/// so what is queued there goes elsewhere, and no placement chooses the slot
/// until [`come_back_to_slot`] (`ZoneTables::step_away`). A service thread no
/// live slot will take stays, for this executor when it returns.
pub fn step_away_from_slot(slot: SlotId, driver: u64) {
    let Some(zone) = zone() else {
        return;
    };
    let mut records = Vec::new();
    let mut placements = Vec::new();
    if zone.step_away(
        slot,
        driver,
        &mut |record| records.push(record),
        &mut |placement| placements.push(placement),
    ) {
        settle_vacated(zone, Some(slot), records, placements, &mut publish_handback);
    }
}

/// Executor `driver` of `slot` is back from its blocking host wait.
pub fn come_back_to_slot(slot: SlotId, driver: u64) {
    if let Some(zone) = zone() {
        zone.step_back(slot, driver);
    }
}

/// Executor `driver` stopped driving `slot`: the mailbox lease the slot
/// follows moved on and it drives `now` instead, or (`now` `None`) it parks
/// with no guest CPU and drives nothing. If nobody took `slot` over, what is
/// queued there leaves; a service thread no live slot will take waits on
/// `now`, or goes back to its host continuation.
pub fn leave_slot(slot: SlotId, driver: u64, now: Option<SlotId>) {
    if let Some(zone) = zone() {
        leave_slot_in(zone, slot, driver, now);
    }
}

/// [`leave_slot`] on the tables `zone`.
pub fn leave_slot_in(zone: &ZoneTables, slot: SlotId, driver: u64, now: Option<SlotId>) {
    let mut records = Vec::new();
    let mut placements = Vec::new();
    if zone.leave_slot(
        slot,
        driver,
        &mut |record| records.push(record),
        &mut |placement| placements.push(placement),
    ) {
        settle_vacated(zone, now, records, placements, &mut publish_handback);
    }
}

/// Deliver what vacating a slot placed, and place or hand back what it took:
/// a service thread no live slot takes waits on `fallback`, if any. Preserve
/// the incarnation captured at evacuation: another host claimant can retire
/// and reuse the record before this deferred publication runs.
fn settle_vacated(
    zone: &ZoneTables,
    fallback: Option<SlotId>,
    records: Vec<RecordRef>,
    placements: Vec<carrick_el1_abi::HostPlacement>,
    publish: &mut impl FnMut(RecordRef),
) {
    for placement in placements {
        deliver_placement(Some(placement));
    }
    for record in records {
        let Some(rec) = zone.live(record) else {
            continue;
        };
        if rec.handback() == Some(Handback::Service) {
            // A service record stands for its thread's held host row, which
            // only the scheduler sees: placing it from host ownership is
            // invisible to any claimant.
            if deliver_placement(zone.place_from_host(record.id)) {
                continue;
            }
            if fallback.is_some_and(|fallback| zone.requeue_on(fallback, record.id)) {
                continue;
            }
            // No slot runs an executor that could take it (every one is
            // stopped in a host call, say): its thread's held row goes to a
            // host run queue (`Scheduler::publish_zone_handback`).
            publish(record);
        } else {
            publish(record);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use carrick_el1_abi::{Claim, ThreadIdentity};

    fn heap_zone() -> Box<ZoneTables> {
        let layout = std::alloc::Layout::new::<ZoneTables>();
        // SAFETY: all-zero is the valid empty zone state. Box owns this
        // aligned allocation and releases it after the test.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
            assert!(!ptr.is_null());
            Box::from_raw(ptr)
        }
    }

    fn identity(tid: u64) -> ThreadIdentity {
        ThreadIdentity {
            tid,
            serial: tid,
            mm: 7,
            file_table: 1,
            generation: 1,
            affinity: 0,
        }
    }

    /// Contract kernel.el1.deferred-handback-identity. The slot evacuation
    /// and its publication are separate phases: a control claimant can retire
    /// a host-owned record in between. Publication owes the original thread
    /// only, never a new waiter that reused the record number.
    #[test]
    fn deferred_slot_handback_does_not_wake_a_reused_record() {
        for count in [1, 8, 32] {
            let zone = heap_zone();
            let slot = SlotId::new(3);
            zone.drive(slot, 7);
            let mut original = Vec::new();
            for tid in 1..=count {
                let record = zone.alloc_record(identity(tid)).unwrap();
                let seq = zone.next_seq(record);
                zone.publish_park(record, seq);
                assert_eq!(
                    zone.claim_for_host(
                        zone.record_ref(record),
                        Some(seq),
                        Handback::Woken,
                        &HostLockWait,
                    ),
                    HostClaim::Claimed,
                );
                original.push(zone.record_ref(record));
                assert!(zone.requeue_on(slot, record));
            }
            let mut records = Vec::new();
            let mut placements = Vec::new();
            assert!(zone.leave_slot(
                slot,
                7,
                &mut |record| records.push(record),
                &mut |placement| placements.push(placement),
            ));
            assert_eq!(records.len(), count as usize);
            assert!(placements.is_empty());

            // The other owner completes each original host continuation,
            // frees its record, and a new thread parks in the same slot.
            let mut replacements = Vec::new();
            for old in original {
                assert!(matches!(
                    zone.live(old).unwrap().claim(),
                    Claim::Host { .. }
                ));
                assert_eq!(
                    zone.claim_for_host(old, None, Handback::Cancelled, &HostLockWait),
                    HostClaim::AlreadyHost,
                );
                zone.free_record(old.id);
                let record = zone
                    .alloc_record(identity(100 + u64::from(old.id.raw())))
                    .unwrap();
                assert_eq!(record, old.id);
                assert_ne!(zone.record_ref(record), old);
                let seq = zone.next_seq(record);
                zone.publish_park(record, seq);
                replacements.push((record, seq));
            }
            let mut published = Vec::new();
            settle_vacated(&zone, None, records, placements, &mut |record| {
                published.push(record);
            });
            assert!(
                published.is_empty(),
                "delayed handback targeted replacement: {published:?}"
            );
            for (record, seq) in replacements {
                assert_eq!(zone.record(record).claim(), Claim::Parked { seq });
            }
        }
    }

    #[test]
    fn deferred_slot_handback_preserves_live_records() {
        let zone = heap_zone();
        let slot = SlotId::new(3);
        zone.drive(slot, 7);
        let record = zone.alloc_host_runnable(identity(1)).unwrap();
        let expected = zone.record_ref(record);
        assert!(zone.requeue_on(slot, record));
        let mut records = Vec::new();
        let mut placements = Vec::new();
        assert!(zone.leave_slot(
            slot,
            7,
            &mut |record| records.push(record),
            &mut |placement| placements.push(placement),
        ));
        let mut published = Vec::new();
        settle_vacated(&zone, None, records, placements, &mut |record| {
            published.push(record);
        });
        assert_eq!(published, [expected]);
        assert!(matches!(
            zone.live(expected).unwrap().claim(),
            Claim::Host { .. }
        ));
    }
}
