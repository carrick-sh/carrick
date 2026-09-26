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
    Handback, HostClaim, LockWait, RecordId, RecordRef, SlotId, Waker, ZoneTables, zone_tables,
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
        HostClaim::Stale => {}
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
            &mut |record| wake.handed.push(zone.record_ref(record)),
            &mut |placement| placements.push(placement),
        );
    }
    for placement in placements {
        deliver_placement(Some(placement));
    }
    // A futex_waitv park is queued on other buckets too.
    for record in &wake.handed {
        zone.unlink_all(record.id, &HostLockWait);
    }
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
        let mut batch = [RecordId::PLACEHOLDER; 64];
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
            woken.extend(batch[..n as usize].iter().map(|id| zone.record_ref(*id)));
            if (n as usize) < batch.len() {
                break;
            }
            remaining -= n;
        }
        moved = zone.requeue(from_guard, to_guard, mm, from, to, requeue_count);
    }
    for record in &woken {
        zone.unlink_all(record.id, &HostLockWait);
    }
    Ok((woken, moved))
}

/// Whether the zone thread `record` is running or runnable in the guest
/// (`Some(true)`: queued, on a vCPU, or claimed by the host to run) or parked
/// there (`Some(false)`); `None` if the record is gone.
pub fn record_runs(record: RecordRef) -> Option<bool> {
    let rec = zone_tables()?.live(record)?;
    match rec.claim() {
        carrick_el1_abi::Claim::Parked { .. } => Some(false),
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
    zone.take_host_wanted(slot, &mut |record| wanted.push(zone.record_ref(record)));
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
            zone.free_record(record);
        } else {
            handed.push(zone.record_ref(record));
        }
    });
    for record in handed {
        publish_handback(record);
    }
}

/// The executor of `slot` is about to wait on the host with its vCPU stopped
/// (a spare): nothing may be queued on it, and what is goes elsewhere.
pub fn retire_slot(slot: SlotId) {
    let Some(zone) = zone() else {
        return;
    };
    let mut records = Vec::new();
    let mut placements = Vec::new();
    zone.retire_slot(slot, &mut |record| records.push(record), &mut |placement| {
        placements.push(placement)
    });
    for placement in placements {
        deliver_placement(Some(placement));
    }
    for record in records {
        if zone.record(record).handback() == Some(Handback::Service) {
            // A service record stands for its thread's held host row, which
            // only the scheduler sees: placing it from host ownership is
            // invisible to any claimant.
            if !deliver_placement(zone.place_from_host(record)) {
                // Every bound executor's slot is live and allows every CPU a
                // thread may name, so a service thread always has a slot; one
                // with none would strand its thread's held row.
                carrick_fatal::carrick_fatal!(
                    "el1_zone::retire_slot",
                    "no vCPU slot can take service record {record:?} from retired slot {slot:?}"
                );
            }
        } else {
            publish_handback(zone.record_ref(record));
        }
    }
}
