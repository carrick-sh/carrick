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
//! - [`zone`]: the tables, when the carrier maps the EL1 region and the
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

/// The zone tables, if this carrier serves private futexes in the zone.
pub fn zone() -> Option<&'static ZoneTables> {
    if !hatch_enabled() {
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

/// How long a woken thread may wait on a vCPU slot's run queue before the
/// guard forces that slot's vCPU out, handing the thread to the host
/// scheduler: at most two guard periods.
const RUN_QUEUE_GUARD_PERIOD: std::time::Duration = std::time::Duration::from_millis(2);

/// The vCPU slots the guard watches (one per syscall-mailbox slot).
const GUARD_SLOTS: usize = carrick_el1_abi::EL1_STACK_SLOTS as usize;

/// Start the carrier's run-queue guard (once per process). EL1 queues a
/// woken thread behind the thread that woke it, which normally blocks in a
/// served futex wait next (the handoff) or makes a syscall EL1 forwards
/// (whose exit hands the queued thread to the host). A waker that does
/// neither would hold it indefinitely: the guard sees a slot whose queue has
/// been non-empty since the same instant for a whole period and kicks it.
pub fn start_run_queue_guard() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let _ = std::thread::Builder::new()
            .name("carrick-el1-zone-guard".to_owned())
            .spawn(run_queue_guard);
    });
}

fn run_queue_guard() {
    let mut seen = [0_u64; GUARD_SLOTS];
    loop {
        let Some(zone) = zone() else {
            seen = [0; GUARD_SLOTS];
            std::thread::sleep(std::time::Duration::from_millis(100));
            continue;
        };
        for (index, last) in seen.iter_mut().enumerate() {
            let Some(slot) = SlotId::from_index(index) else {
                continue;
            };
            let s = zone.slot(slot);
            if s.queued() == 0 {
                *last = 0;
                continue;
            }
            let since = s.queued_since();
            if since != 0 && *last == since {
                kick_slot(slot);
            }
            *last = since;
        }
        std::thread::sleep(RUN_QUEUE_GUARD_PERIOD);
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

/// Host `FUTEX_WAKE(_BITSET)` on a zone process: wake up to `count` waiters
/// of `(mm, uaddr)` matching `bitset`. Returns the woken records, host-owned
/// with [`Handback::Woken`], for the runtime to hand back to their threads.
pub fn wake(zone: &ZoneTables, mm: u64, uaddr: u64, bitset: u32, count: u32) -> Vec<RecordRef> {
    let mut woken = Vec::new();
    {
        let Some(guard) = zone.lock(ZoneTables::bucket_of(mm, uaddr), &HostLockWait) else {
            return woken;
        };
        let mut remaining = count;
        let mut batch = [RecordId::PLACEHOLDER; 64];
        while remaining > 0 {
            let Ok(n) = zone.wake(
                &guard,
                mm,
                uaddr,
                bitset,
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
    }
    // A futex_waitv park is queued on other buckets too.
    for record in &woken {
        zone.unlink_all(record.id, &HostLockWait);
    }
    woken
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

/// The kernel thread a record names.
pub fn thread_key_of(record: RecordRef) -> Option<crate::kernel::ThreadKey> {
    let zone = zone_tables()?;
    let rec = zone.live(record)?;
    let identity = rec.identity();
    let tid = i32::try_from(identity.tid).ok()?;
    let serial = std::num::NonZeroU64::new(identity.serial)?;
    crate::kernel::ThreadKey::from_zone_identity(tid, serial)
}
