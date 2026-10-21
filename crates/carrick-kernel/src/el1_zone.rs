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

use std::sync::{Arc, OnceLock};

use carrick_el1_abi::{
    Handback, HostClaim, LockWait, RecordRef, SlotId, Waker, ZoneTables, zone_tables,
};

/// The host waits for a bucket lock by spinning, then yielding. A holder is
/// either a host thread in a short critical section or a vCPU inside EL1,
/// which its executor always resumes to completion.
pub struct HostLockWait;

/// Effects collected while an IPC object and its waiter queue are locked.
/// Storage is uninitialized until a waiter is affected: no population scan,
/// per-transfer heap allocation, or delivery while shared locks are held.
pub(crate) struct ObjectWakeDelivery {
    handed: [std::mem::MaybeUninit<RecordRef>; carrick_sched_core::ZONE_RECORDS],
    len: usize,
    slots: [u64; carrick_el1_abi::ZONE_SLOTS / 64],
}
impl ObjectWakeDelivery {
    pub(crate) fn new() -> Self {
        Self {
            handed: [const { std::mem::MaybeUninit::uninit() }; carrick_sched_core::ZONE_RECORDS],
            len: 0,
            slots: [0; carrick_el1_abi::ZONE_SLOTS / 64],
        }
    }
    pub(crate) fn collect(&mut self, wake: carrick_el1_abi::ipc::IpcWake) {
        let Some(zone) = zone() else {
            return;
        };
        // The object's own lanes, then the readable lane of every zone
        // epoll the change queued an item on.
        let lanes = [
            (wake.readers, carrick_el1_abi::ipc::pipe::WaitFor::Readable),
            (wake.writers, carrick_el1_abi::ipc::pipe::WaitFor::Writable),
        ]
        .into_iter()
        .filter(|(active, _)| *active)
        .map(|(_, direction)| (wake.object, direction))
        .chain(
            wake.epolls
                .iter()
                .map(|epoll| (epoll, carrick_el1_abi::ipc::pipe::WaitFor::Readable)),
        );
        for (object, direction) in lanes {
            let Some(key) = carrick_el1_abi::ipc::object_wait_key(object, direction) else {
                continue;
            };
            let Ok(queue) = zone.object_wait(key, &HostLockWait) else {
                continue;
            };
            let Self { handed, len, slots } = self;
            queue
                .notify_object_host(
                    &mut |record| {
                        let Some(slot) = handed.get_mut(*len) else {
                            carrick_fatal::carrick_fatal!(
                                "ipc::wake",
                                "duplicate object waiter delivery"
                            );
                        };
                        slot.write(record);
                        *len += 1;
                    },
                    &mut |placed| {
                        if placed.resched {
                            let index = usize::from(placed.slot.raw());
                            slots[index / 64] |= 1 << (index % 64);
                        }
                    },
                )
                .unwrap_or_else(|_| {
                    carrick_fatal::carrick_fatal!("ipc::wake", "object wake ownership failed")
                });
        }
    }
    pub(crate) fn deliver(self) {
        for record in &self.handed[..self.len] {
            // SAFETY: collect initialized precisely this prefix.
            publish_handback(unsafe { record.assume_init() });
        }
        for (word, mut bits) in self.slots.into_iter().enumerate() {
            while bits != 0 {
                let index = word * 64 + bits.trailing_zeros() as usize;
                bits &= bits - 1;
                if let Some(slot) = SlotId::from_index(index) {
                    resched_slot(slot);
                }
            }
        }
    }
}

/// Metadata readiness uses the same record-owned waits as IPC, with a
/// separately admitted queue and a typed token that IPC cannot construct.
#[derive(Debug)]
pub struct MetadataCompletionWake;

impl carrick_el1_abi::MetadataCompletionWake for MetadataCompletionWake {
    fn publish_and_wake(
        &self,
        mailbox: &carrick_el1_abi::MetadataGrantMailbox,
        generation: u64,
        response: [u64; 4],
    ) {
        let publish =
            || mailbox.publish_response(response[0], response[1], response[2], response[3]);
        let Some(zone) = zone() else {
            publish();
            return;
        };
        let Some(key) =
            carrick_sched_core::object_wait::ObjectWaitKey::metadata_request(generation)
        else {
            carrick_fatal::carrick_fatal!("metadata::wake", "zero metadata request incarnation");
        };
        let Ok(queue) = zone.object_wait(key, &HostLockWait) else {
            // No zone participant bound a queue (e.g. guest scheduling disabled).
            publish();
            return;
        };
        let mut delivery = ObjectWakeDelivery::new();
        publish();
        let ObjectWakeDelivery { handed, len, slots } = &mut delivery;
        queue
            .notify_object_host(
                &mut |record| {
                    let Some(target) = handed.get_mut(*len) else {
                        carrick_fatal::carrick_fatal!(
                            "metadata::wake",
                            "duplicate metadata waiter delivery"
                        );
                    };
                    target.write(record);
                    *len += 1;
                },
                &mut |placed| {
                    if placed.resched {
                        let index = usize::from(placed.slot.raw());
                        slots[index / 64] |= 1 << (index % 64);
                    }
                },
            )
            .unwrap_or_else(|_| {
                carrick_fatal::carrick_fatal!("metadata::wake", "metadata wake ownership failed")
            });
        drop(queue);
        delivery.deliver();
    }
}

fn complete_object_wake<C: carrick_el1_abi::EntryContext>(
    zone: &carrick_sched_core::ZoneTables<C>,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, C>,
) {
    let (waker, effects) = owned.deliver_handbacks(&mut publish_handback);
    let own = match waker {
        carrick_sched_core::Waker::El1 { slot } => Some(slot),
        carrick_sched_core::Waker::Host => None,
    };
    assert!(own.is_some() || (!effects.queued_own && !effects.misplaced));
    for slot in effects
        .sgi_slots()
        .chain(own.filter(|_| effects.queued_own))
    {
        zone.owe_resched(slot);
        resched_slot(slot);
    }
    if effects.misplaced
        && let Some(slot) = own
    {
        kick_slot(slot);
    }
}

impl LockWait for HostLockWait {
    fn complete_object_wake(
        &self,
        zone: &carrick_sched_core::ZoneTables,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_>,
    ) {
        complete_object_wake(zone, owned);
    }

    fn wait(&self, attempt: u32) -> bool {
        if attempt < 128 {
            std::hint::spin_loop();
        } else {
            std::thread::yield_now();
        }
        true
    }
}

impl LockWait<carrick_el1_abi::Aarch64ParkedContext> for HostLockWait {
    fn complete_object_wake(
        &self,
        zone: &ZoneTables,
        owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<
            '_,
            carrick_el1_abi::Aarch64ParkedContext,
        >,
    ) {
        complete_object_wake(zone, owned);
    }

    fn wait(&self, attempt: u32) -> bool {
        <Self as LockWait>::wait(self, attempt)
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

#[cfg(feature = "test-support")]
std::thread_local! {
    static TEST_ZONE: std::cell::Cell<Option<&'static ZoneTables>> = const { std::cell::Cell::new(None) };
}

/// Bind a VM-free fixture's real scheduler tables to host operations on this
/// thread. The scoped binding cannot affect parallel tests or escape unwind.
#[cfg(feature = "test-support")]
pub fn with_test_zone<T>(zone: &'static ZoneTables, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<&'static ZoneTables>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_ZONE.set(self.0);
        }
    }
    let _restore = Restore(TEST_ZONE.replace(Some(zone)));
    run()
}

/// The zone tables, if this carrier serves private futexes in the zone.
pub fn zone() -> Option<&'static ZoneTables> {
    #[cfg(feature = "test-support")]
    if let Some(zone) = TEST_ZONE.get() {
        return Some(zone);
    }
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

/// The executor of `slot` is leaving EL1: a timed park of another
/// executor's thread on this slot's timer would go unserved until the vCPU
/// returns. Claim it for the host (a control handback): its thread re-runs
/// the call with what is left of its deadline. A wake that won the record
/// first leaves nothing to claim.
pub fn hand_back_foreign_timer(slot: SlotId) {
    let Some(zone) = zone() else {
        return;
    };
    while let Some(foreign) = zone.take_foreign_timer(slot) {
        if let HostClaim::Claimed = claim(foreign.record, Some(foreign.seq), Handback::Control) {
            hand_back(&[foreign.record]);
        }
    }
}

/// Whether the host owns `record` (a wake, a signal, a timeout or a
/// handback claimed it), so its thread may run.
pub fn is_host_owned(record: RecordRef) -> bool {
    zone_tables().is_some_and(|zone| {
        zone.live(record).is_some_and(|rec| {
            matches!(
                rec.claim(),
                carrick_el1_abi::Claim::Host { .. } | carrick_el1_abi::Claim::FirstEntryHost { .. }
            )
        })
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

/// The one queue venue serving an address space's private futexes (#685).
///
/// Every waiter and every waker of one mm, host or EL1, must meet in the
/// same queue. The venue is therefore a function of the address space
/// alone, resolved from its [`MmId`](crate::kernel::MmId) here and nowhere
/// else: never from a per-job cache, which a job that has not refreshed it
/// (or a waker running on another thread's behalf) reads as "no zone"
/// while the mm's other threads park in the zone.
///
/// A carrier either serves private futexes in the zone for every address
/// space or for none: [`zone`] is decided once, by [`enable`] before any
/// executor starts, and never changes for a live carrier. So an mm's venue
/// is fixed for its whole life. The only constructors are
/// [`FutexQueueAuthority::of_mm`] and [`FutexQueueAuthority::of_context`];
/// a caller cannot pick a venue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexQueueAuthority(FutexQueueVenue);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FutexQueueVenue {
    /// The in-guest zone's queues, shared with EL1.
    Zone(ZoneFutexQueue),
    /// The carrier's host `FutexTable` (no zone on this carrier).
    Table,
}

impl FutexQueueAuthority {
    /// The venue of address space `mm`.
    pub fn of_mm(mm: crate::kernel::MmId) -> Self {
        Self(match zone() {
            Some(tables) => FutexQueueVenue::Zone(ZoneFutexQueue { tables, mm }),
            None => FutexQueueVenue::Table,
        })
    }

    /// The venue of the address space `context` runs in.
    pub fn of_context(context: &crate::kernel::KernelContext) -> Self {
        Self::of_mm(context.shared().mm_id())
    }

    /// The zone queue, when the zone serves this address space; `None`: the
    /// host `FutexTable` does.
    pub const fn zone(self) -> Option<ZoneFutexQueue> {
        match self.0 {
            FutexQueueVenue::Zone(queue) => Some(queue),
            FutexQueueVenue::Table => None,
        }
    }

    /// Wake the joiner of a cleared `CLONE_CHILD_CLEARTID` word in this
    /// address space's queue: the host half of a thread retirement whose
    /// in-zone exit did not wake (EL1's wake is all or nothing, so a
    /// declined in-zone exit woke nobody). The caller hands back
    /// `handed`.
    pub fn wake_child_tid(self, futex: &crate::thread::FutexTable, address: u64) -> ZoneWake {
        let wake = match self.0 {
            FutexQueueVenue::Zone(queue) => queue.wake(
                address,
                carrick_personality_linux::thread::CHILD_TID_WAKE_MASK,
                carrick_personality_linux::thread::CHILD_TID_WAKE_COUNT,
            ),
            FutexQueueVenue::Table => ZoneWake {
                count: futex.wake(
                    address,
                    carrick_personality_linux::thread::CHILD_TID_WAKE_COUNT,
                ),
                handed: Vec::new(),
            },
        };
        crate::event_ring::rec_futex_wake(address, wake.count);
        wake
    }
}

/// The zone queue of one address space: the zone tables and the mm whose
/// key (`MmId::raw`, the same key EL1 loads for the task) selects its
/// buckets. Built only by [`FutexQueueAuthority`].
#[derive(Clone, Copy)]
pub struct ZoneFutexQueue {
    tables: &'static ZoneTables,
    mm: crate::kernel::MmId,
}

impl ZoneFutexQueue {
    pub const fn tables(self) -> &'static ZoneTables {
        self.tables
    }

    pub const fn mm(self) -> crate::kernel::MmId {
        self.mm
    }

    /// The zone key of the address space (`ThreadIdentity::mm`, the bucket
    /// context): the ABI spelling of [`Self::mm`].
    pub const fn key(self) -> u64 {
        self.mm.raw()
    }

    /// Host `FUTEX_WAKE(_BITSET)` on this queue.
    pub fn wake(self, uaddr: u64, bitset: u32, count: u32) -> ZoneWake {
        wake(self.tables, self.key(), uaddr, bitset, count)
    }

    /// Host `FUTEX_(CMP_)REQUEUE` on this queue ([`requeue`]).
    pub fn requeue<E>(
        self,
        from: u64,
        to: u64,
        wake_count: u32,
        requeue_count: u32,
        check: impl FnOnce() -> Result<(), E>,
    ) -> Result<(Vec<RecordRef>, u32), E> {
        requeue(
            self.tables,
            self.key(),
            from,
            to,
            wake_count,
            requeue_count,
            check,
        )
    }
}

impl std::fmt::Debug for ZoneFutexQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneFutexQueue")
            .field("tables", &std::ptr::from_ref(self.tables))
            .field("mm", &self.mm)
            .finish()
    }
}

impl PartialEq for ZoneFutexQueue {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.tables, other.tables) && self.mm == other.mm
    }
}

impl Eq for ZoneFutexQueue {}

/// Wake every waiter of a lifecycle exit-wait channel (`exit_wait()` of a
/// task's lifecycle page): a carrier-internal rendezvous keyed by the ABI
/// entry mm, not a guest futex, so it does not go through
/// [`FutexQueueAuthority`]. Hands the woken back; `None` without a zone.
pub fn wake_exit_wait_channel(
    mm: carrick_el1_abi::EntryMmKey,
    address: std::num::NonZeroU64,
) -> Option<u32> {
    let zone = zone()?;
    let woken = wake(zone, mm.raw(), address.get(), u32::MAX, u32::MAX);
    hand_back(&woken.handed);
    Some(woken.count)
}

/// Host `FUTEX_WAKE(_BITSET)` on a zone process: wake up to `count` waiters
/// of `(mm, uaddr)` matching `bitset`. Guest futexes reach it only through
/// [`ZoneFutexQueue::wake`].
fn wake(zone: &ZoneTables, mm: u64, uaddr: u64, bitset: u32, count: u32) -> ZoneWake {
    let mut wake = ZoneWake::default();
    let mut placements = Vec::new();
    let mut transfers = Vec::new();
    {
        let Some(guard) = zone.lock(ZoneTables::bucket_of_with_context(mm, uaddr), &HostLockWait)
        else {
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
/// number moved. Guest futexes reach it only through
/// [`ZoneFutexQueue::requeue`].
fn requeue<E>(
    zone: &ZoneTables,
    mm: u64,
    from: u64,
    to: u64,
    wake_count: u32,
    requeue_count: u32,
    check: impl FnOnce() -> Result<(), E>,
) -> Result<(Vec<RecordRef>, u32), E> {
    let from_bucket = ZoneTables::bucket_of_with_context(mm, from);
    let to_bucket = ZoneTables::bucket_of_with_context(mm, to);
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

/// Route an actual kernel group stop through the existing zone ownership
/// protocol. Exact thread identities fence this from other tasks, including
/// tasks sharing an address space. One bounded census per stop; no polling.
pub(crate) fn claim_group_stop(threads: &[crate::kernel::ThreadKey]) {
    let Some(zone) = zone_tables() else {
        return;
    };
    let keys: std::collections::BTreeSet<_> = threads.iter().copied().collect();
    for index in 1..carrick_sched_core::ZONE_RECORDS {
        let Some(id) = u32::try_from(index)
            .ok()
            .and_then(carrick_el1_abi::RecordId::from_raw)
        else {
            continue;
        };
        let record = zone.record_ref(id);
        if thread_key_of(record).is_some_and(|key| keys.contains(&key)) {
            match claim(record, None, Handback::GroupStop) {
                HostClaim::Claimed | HostClaim::AlreadyHost => publish_handback(record),
                HostClaim::El1Held { .. } | HostClaim::Deferred | HostClaim::Stale => {}
            }
        }
    }
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
        | carrick_el1_abi::Claim::OnCpuRequested { .. }
        | carrick_el1_abi::Claim::Host { .. }
        | carrick_el1_abi::Claim::FirstEntryHost { .. } => Some(true),
        _ => None,
    }
}

/// Exact retained thread binding, independent of vCPU home/foreign scope.
/// One live-record lookup: no record or slot population scan.
pub fn thread_record_runs(record: RecordRef, key: crate::kernel::ThreadKey) -> Option<bool> {
    thread_record_runs_in(zone_tables()?, record, key)
}

fn thread_record_runs_in(
    zone: &ZoneTables,
    record: RecordRef,
    key: crate::kernel::ThreadKey,
) -> Option<bool> {
    let rec = zone.live(record)?;
    let identity = rec.identity();
    if identity.tid != carrick_el1_abi::El1TaskId::from_linux_tid(key.tid.raw()).raw()
        || identity.serial != key.serial.raw()
    {
        return None;
    }
    let claim = rec.claim();
    // The record may be retired/reused during the snapshot. Never project
    // another thread's claim through an old control-slot reference.
    zone.live(record)?;
    match claim {
        carrick_el1_abi::Claim::Parked { .. } | carrick_el1_abi::Claim::Transferring { .. } => {
            Some(false)
        }
        carrick_el1_abi::Claim::Queued { .. }
        | carrick_el1_abi::Claim::OnCpu { .. }
        | carrick_el1_abi::Claim::OnCpuRequested { .. }
        | carrick_el1_abi::Claim::Host { .. }
        | carrick_el1_abi::Claim::FirstEntryHost { .. } => Some(true),
        _ => None,
    }
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
            let ctx = ctx.native;
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

/// Complete the detached wake claims EL1 transferred at its exit boundary.
pub fn hand_back_completions() {
    if let Some(zone) = zone() {
        hand_back_completions_in(zone);
    }
}

/// Settle every deferred object-wait completion on `zone`'s carrier chain:
/// each `Transferring` record becomes host-owned and goes to its thread's
/// continuation, in the one owned `HostTransfer` publication. EL1 announces
/// that chain only with the venue's pending-host-work doorbell, so every
/// host boundary that consumes the doorbell settles the chain through here
/// (`el1_delegation::deliver_boundary_wakes`), exactly like the owed IPC
/// wakes the same doorbell stands for (#641).
pub(crate) fn hand_back_completions_in(zone: &ZoneTables) {
    zone.take_completion_handbacks(&HostLockWait, &mut publish_handback);
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
        lifecycle_page: 0,
        control_slot: 0,
    };
    let Ok(record) = zone.alloc_host_runnable(identity) else {
        return false;
    };
    #[cfg(all(feature = "test-support", feature = "deferred-capture-test-control"))]
    if deferred_capture_control::hold(zone, record) {
        return true;
    }
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
#[derive(Clone, Copy, Debug)]
pub enum HandbackEvent<'a> {
    /// Queue evacuation finished; deferred identity filtering has not begun.
    DeferredCaptured(&'a [RecordRef]),
    /// A host-owned record can be offered to its continuation.
    Ready(RecordRef),
}

pub type HandbackPublisher = Arc<dyn Fn(HandbackEvent<'_>) + Send + Sync>;

static HANDBACK_PUBLISHER: parking_lot::RwLock<Option<HandbackPublisher>> =
    parking_lot::RwLock::new(None);

/// Register the handback publisher of the carrier's current scheduler. Each
/// start of the executor pool registers its own scheduler (a carrier may run
/// several containers in turn): a publisher of a retired scheduler would drop
/// every handback.
pub fn register_handback_publisher(publisher: HandbackPublisher) {
    *HANDBACK_PUBLISHER.write() = Some(publisher);
}

/// Bind a VM-free fixture's scheduler handback publisher for the duration of
/// one serial test, restoring the process-global carrier publisher afterward.
#[cfg(any(test, feature = "test-support"))]
pub fn with_test_handback_publisher<T>(publisher: HandbackPublisher, run: impl FnOnce() -> T) -> T {
    struct Restore(Option<HandbackPublisher>);
    impl Drop for Restore {
        fn drop(&mut self) {
            *HANDBACK_PUBLISHER.write() = self.0.take();
        }
    }
    let _restore = Restore(HANDBACK_PUBLISHER.write().replace(publisher));
    run()
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
        publish_handback_in_zone(zone, record, &mut |record| {
            deliver_handback_event(HandbackEvent::Ready(record));
        });
    } else {
        deliver_handback_event(HandbackEvent::Ready(record));
    }
}

fn publish_handback_in_zone(
    zone: &ZoneTables,
    record: RecordRef,
    publish: &mut impl FnMut(RecordRef),
) {
    zone.counters
        .host_handbacks
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if route_first_entry_in_zone(zone, record) {
        return;
    }
    publish(record);
}

/// An uninitialized Born thread has reserved activation capacity, but no
/// continuation to wake. Keep its exact record on an executor service queue.
pub(crate) fn route_first_entry_handback(record: RecordRef) -> bool {
    zone_tables().is_some_and(|zone| route_first_entry_in_zone(zone, record))
}

fn route_first_entry_in_zone(zone: &ZoneTables, record: RecordRef) -> bool {
    let Some(custody) = zone.claim_first_entry_placement(record) else {
        return false;
    };
    let custody = match zone.place_first_entry(custody) {
        Ok(placement) => return deliver_placement(Some(placement)),
        Err(custody) => custody,
    };
    !zone.release_first_entry_placement(custody)
}

fn deliver_handback_event(event: HandbackEvent<'_>) {
    // An auditor may hold a deferred delivery while another execution lane
    // progresses. Never retain the registration lock across its callback.
    let publisher = HANDBACK_PUBLISHER.read().clone();
    if let Some(publisher) = publisher {
        publisher(event);
    }
}

fn capture_handbacks(records: &[RecordRef]) {
    if !records.is_empty() {
        deliver_handback_event(HandbackEvent::DeferredCaptured(records));
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
    #[cfg(all(feature = "test-support", feature = "deferred-capture-test-control"))]
    deferred_capture_control::release_at_step_away(zone, slot, driver);
    let mut records = Vec::new();
    let mut placements = Vec::new();
    if zone.step_away(
        slot,
        driver,
        &mut |record| records.push(record),
        &mut |placement| placements.push(placement),
    ) {
        settle_vacated(
            zone,
            Some(slot),
            records,
            placements,
            &mut publish_handback,
            &mut capture_handbacks,
        );
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
        settle_vacated(
            zone,
            now,
            records,
            placements,
            &mut publish_handback,
            &mut capture_handbacks,
        );
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
    captured: &mut impl FnMut(&[RecordRef]),
) {
    for placement in placements {
        deliver_placement(Some(placement));
    }
    // Deliver already-owed kicks before an observer can delay this batch.
    captured(&records);
    for record in records {
        let Some(rec) = zone.live(record) else {
            continue;
        };
        if rec.handback() == Some(Handback::Service) || rec.is_unadopted_birth() {
            // A Born thread has reserved first-entry capacity, but no host
            // continuation yet. Even a Resumed handback must reach an
            // executor for activation rather than publish a continuation wake.
            // A service record stands for its thread's held host row, which
            // only the scheduler sees: placing it from host ownership is
            // invisible to any claimant.
            if deliver_placement(zone.place_from_host(record.id)) {
                continue;
            }
            if deliver_placement(fallback.and_then(|fallback| zone.requeue_on(fallback, record.id)))
            {
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

/// Bounded observers for signed first-entry ownership witnesses. No observer
/// is installed by product code; callbacks run without the subscription lock.
#[cfg(any(test, feature = "test-support"))]
pub mod first_entry_test_control {
    use super::{HostClaim, RecordRef};
    use std::sync::Arc;

    #[derive(Clone, Copy, Debug)]
    pub enum Event {
        ClosingEntered(Option<RecordRef>),
        ClosingClaim(RecordRef, HostClaim),
        ClosingFinished,
        ExecutorTaken(RecordRef),
        Adopted(RecordRef),
        BeforeRetire(RecordRef),
        Retired(RecordRef),
        NextFatal,
    }

    type Observer = Arc<dyn Fn(Event) + Send + Sync>;
    static OBSERVER: parking_lot::RwLock<Option<Observer>> = parking_lot::RwLock::new(None);

    pub struct Subscription;
    impl Drop for Subscription {
        fn drop(&mut self) {
            *OBSERVER.write() = None;
        }
    }

    pub fn subscribe(observer: Observer) -> Subscription {
        let mut current = OBSERVER.write();
        assert!(
            current.is_none(),
            "one signed first-entry witness at a time"
        );
        *current = Some(observer);
        Subscription
    }

    pub fn emit(event: Event) {
        let observer = OBSERVER.read().clone();
        if let Some(observer) = observer {
            observer(event);
        }
    }

    pub fn closing_entered(
        context: &crate::kernel::KernelContext,
        closing_slot: Option<super::SlotId>,
    ) {
        if OBSERVER.read().is_none() {
            return;
        }
        let record = context.task().threads().into_iter().find_map(|thread| {
            if thread.execution_state().generation().is_some() {
                return None;
            }
            let record = thread.control_slot().zone_record()?;
            let live = super::zone_tables()?.live(record)?;
            // The Closing executor itself is paused. Select a real birth on
            // another driven lane, so its executor can reach the service take.
            (live.last_slot().is_some()
                && live.last_slot() != closing_slot
                && matches!(live.claim(), carrick_el1_abi::Claim::Parked { .. }))
            .then_some(record)
        });
        emit(Event::ClosingEntered(record));
    }

    /// The caller owns activation custody: no reuse or requeue can race the
    /// inspection. Refuse incomplete inspection rather than treating it as clear.
    pub fn links_clear(record: RecordRef) -> Option<bool> {
        struct Deadline(std::time::Instant);
        impl carrick_el1_abi::LockWait<carrick_el1_abi::Aarch64ParkedContext> for Deadline {
            fn wait(&self, _: u32) -> bool {
                std::thread::yield_now();
                self.0.elapsed() < std::time::Duration::from_secs(5)
            }
        }
        super::zone_tables()?
            .first_entry_links_clear_for_test(record, &Deadline(std::time::Instant::now()))
    }
}

/// Signed-witness control for the deferred-capture boundary (#695). Armed,
/// once any slot has stepped away (past the workload's first run), it holds
/// the next real service placement (host-owned, unqueued) and
/// queues it on the first slot that may run it just before that slot's
/// driver steps away, so the vacate captures exactly that record. It never
/// creates a record. A hold not released by its deadline goes to the host
/// run queue like any unplaced service record, and the outcome says so.
#[cfg(all(feature = "test-support", feature = "deferred-capture-test-control"))]
pub mod deferred_capture_control {
    use super::{RecordRef, SlotId, ZoneTables, publish_handback};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// How an armed hold ended.
    #[derive(
        ::core::clone::Clone,
        ::core::marker::Copy,
        ::core::fmt::Debug,
        ::core::cmp::Eq,
        ::core::cmp::PartialEq,
    )]
    pub enum HoldOutcome {
        /// No service placement happened while armed.
        NotHeld,
        /// Queued on `slot` immediately before its driver stepped away.
        ReleasedAtStepAway { record: RecordRef, slot: SlotId },
        /// The deadline (or disarm) passed first; handed to the host queue.
        Expired { record: RecordRef },
    }

    struct Hold {
        armed: bool,
        /// A slot stepped away since arming: the workload is past its first
        /// run, so a held thread cannot be the only one able to progress.
        stepped_away: bool,
        held: Option<RecordRef>,
        outcome: HoldOutcome,
        epoch: u64,
    }

    static HOLD: Mutex<Hold> = Mutex::new(Hold {
        armed: false,
        stepped_away: false,
        held: None,
        outcome: HoldOutcome::NotHeld,
        epoch: 0,
    });

    /// One armed hold. Dropping or finishing it disarms and releases any
    /// record still held, so a hold can never strand a thread.
    #[must_use = "finish the hold to read its outcome"]
    pub struct ArmedHold {
        epoch: u64,
        finished: bool,
    }

    /// Arm a hold of the next service placement for at most `deadline`.
    pub fn arm(deadline: Duration) -> ArmedHold {
        let epoch = {
            let mut hold = HOLD
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                !hold.armed && hold.held.is_none(),
                "one deferred-capture hold at a time"
            );
            hold.epoch = hold.epoch.wrapping_add(1);
            hold.armed = true;
            hold.stepped_away = false;
            hold.outcome = HoldOutcome::NotHeld;
            hold.epoch
        };
        let until = Instant::now() + deadline;
        let _expiry = std::thread::Builder::new()
            .name("deferred-capture-hold".into())
            .spawn(move || {
                std::thread::sleep(until.saturating_duration_since(Instant::now()));
                expire(epoch);
            });
        ArmedHold {
            epoch,
            finished: false,
        }
    }

    impl ArmedHold {
        /// Disarm and report how the hold ended.
        pub fn finish(mut self) -> HoldOutcome {
            self.finished = true;
            expire(self.epoch);
            let mut hold = HOLD
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            hold.armed = false;
            hold.outcome
        }
    }

    impl Drop for ArmedHold {
        fn drop(&mut self) {
            if !self.finished {
                expire(self.epoch);
                HOLD.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .armed = false;
            }
        }
    }

    pub(super) fn hold(zone: &ZoneTables, record: carrick_el1_abi::RecordId) -> bool {
        let mut hold = HOLD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !hold.armed
            || !hold.stepped_away
            || hold.held.is_some()
            || hold.outcome != HoldOutcome::NotHeld
        {
            return false;
        }
        hold.held = Some(zone.record_ref(record));
        true
    }

    pub(super) fn release_at_step_away(zone: &ZoneTables, slot: SlotId, driver: u64) {
        let mut hold = HOLD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if hold.armed {
            hold.stepped_away = true;
        }
        let Some(record) = hold.held else {
            return;
        };
        if zone.record_ref(record.id) != record {
            // Retired and reused meanwhile: nothing of this hold remains.
            hold.held = None;
            return;
        }
        if zone.slot(slot).driver() != Some(driver)
            || !zone.slot(slot).is_live()
            || !zone.record_allows_slot(record.id, slot)
            || !super::deliver_placement(zone.requeue_on(slot, record.id))
        {
            return;
        }
        hold.held = None;
        hold.outcome = HoldOutcome::ReleasedAtStepAway { record, slot };
    }

    fn expire(epoch: u64) {
        let record = {
            let mut hold = HOLD
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if hold.epoch != epoch {
                return;
            }
            let Some(record) = hold.held.take() else {
                return;
            };
            hold.outcome = HoldOutcome::Expired { record };
            record
        };
        // The ordinary path of a service record no slot took.
        publish_handback(record);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use carrick_el1_abi::{Claim, ThreadIdentity};

    #[test]
    fn foreign_parked_thread_projection_uses_exact_incarnation_not_vcpu_home() {
        let zone = heap_zone();
        let own = crate::kernel::ThreadKey::from_zone_identity(
            18,
            std::num::NonZeroU64::new(262).unwrap(),
        )
        .unwrap();
        let other = crate::kernel::ThreadKey::from_zone_identity(
            18,
            std::num::NonZeroU64::new(290).unwrap(),
        )
        .unwrap();
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: 18,
                serial: 262,
                mm: 7,
                ..ThreadIdentity::default()
            })
            .unwrap();
        let reference = zone.record_ref(record);
        let control = carrick_el1_abi::ThreadControlSlot::new();
        control.bind_zone_record(reference);
        zone.publish_park(record, zone.next_seq(record));
        assert_eq!(zone.record(record).home(), None);
        assert_eq!(
            thread_record_runs_in(&zone, control.zone_record().unwrap(), own),
            Some(false)
        );
        assert_eq!(thread_record_runs_in(&zone, reference, other), None);
        zone.free_record(record);
        let reused = zone
            .alloc_record(ThreadIdentity {
                tid: 18,
                serial: 290,
                mm: 22,
                ..ThreadIdentity::default()
            })
            .unwrap();
        assert_eq!(reused, record);
        zone.publish_park(reused, zone.next_seq(reused));
        assert_eq!(thread_record_runs_in(&zone, reference, own), None);
        assert_eq!(
            thread_record_runs_in(&zone, zone.record_ref(reused), other),
            Some(false)
        );
    }

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
            lifecycle_page: 0,
            control_slot: 0,
        }
    }

    #[test]
    fn serial_host_group_stop_claims_zone_wait_before_continue() {
        use crate::kernel::continuation::test_support::bootstrap;
        use carrick_sched_core::object_wait::{ObjectWaitKey, OperationToken};
        let (kernel, context) = bootstrap(153_900);
        let plan = crate::kernel::ClonePlan::from_flags(
            crate::linux_abi::LinuxCloneFlags::THREAD
                | crate::linux_abi::LinuxCloneFlags::SIGHAND
                | crate::linux_abi::LinuxCloneFlags::VM,
        )
        .unwrap();
        let sibling = kernel
            .clone_thread(
                &context,
                plan,
                crate::thread::ThreadId::synthetic_for_tests(153_901),
                None,
            )
            .unwrap();
        let layout =
            std::alloc::Layout::from_size_align(carrick_el1_abi::EL1_REGION_SIZE as usize, 64)
                .unwrap();
        // SAFETY: an aligned zeroed carrier region is a valid empty ABI image.
        let region = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!region.is_null());
        carrick_el1_abi::record_el1_region_host_ptr(region as usize);
        let zone = carrick_el1_abi::zone_tables().unwrap();
        let key = context.thread().key();
        let record = zone
            .alloc_record(ThreadIdentity {
                tid: key.tid.raw() as u64,
                serial: key.serial.raw(),
                mm: 7,
                file_table: 1,
                generation: 1,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        let lane = ObjectWaitKey::new(1, 1).unwrap();
        zone.bind_object_wait(lane, &HostLockWait).unwrap();
        let queue = zone.object_wait(lane, &HostLockWait).unwrap();
        queue
            .park(queue.snapshot(), record, OperationToken::new(1, 1).unwrap())
            .unwrap();
        drop(queue);
        let sibling_key = sibling.thread().key();
        let sibling_record = zone
            .alloc_record(ThreadIdentity {
                tid: sibling_key.tid.raw() as u64,
                serial: sibling_key.serial.raw(),
                mm: 7,
                file_table: 1,
                generation: 1,
                affinity: 0,
                lifecycle_page: 0,
                control_slot: 0,
            })
            .unwrap();
        let foreign_record = zone.alloc_record(identity(153_902)).unwrap();
        for (parked, token) in [(sibling_record, 2), (foreign_record, 3)] {
            let queue = zone.object_wait(lane, &HostLockWait).unwrap();
            queue
                .park(
                    queue.snapshot(),
                    parked,
                    OperationToken::new(token, 1).unwrap(),
                )
                .unwrap();
        }
        let stop =
            crate::kernel::LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).unwrap();
        let cont =
            crate::kernel::LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).unwrap();
        assert!(kernel.stop_task_for_job_control(context.task().key().id, stop, None));
        assert!(kernel.post_signal_to_task(context.task().key().id, cont, None));
        let claimed = matches!(zone.record(record).claim(), Claim::Host { .. });
        let reason = zone.record(record).handback();
        let sibling_claimed = matches!(zone.record(sibling_record).claim(), Claim::Host { .. });
        let foreign_parked = matches!(zone.record(foreign_record).claim(), Claim::Parked { .. });
        // Clear the process-global mapping before any assertion may unwind.
        carrick_el1_abi::record_el1_region_host_ptr(0);
        // SAFETY: the original aligned allocation is no longer published.
        unsafe {
            std::alloc::dealloc(region, layout);
        }
        assert!(
            claimed,
            "group stop must take the parked zone operation before SIGCONT"
        );
        assert_eq!(reason, Some(Handback::GroupStop));
        assert!(sibling_claimed, "every sibling joins the group stop");
        assert!(
            foreign_parked,
            "a distinct thread group sharing the MM is untouched"
        );
        let op = carrick_el1_abi::ipc::IpcOperation {
            kind: carrick_el1_abi::ipc::IpcOpKind::EpollWait,
            ..carrick_el1_abi::ipc::IpcOperation::EMPTY
        };
        assert_eq!(
            crate::kernel::continuation::ipc::interrupted(
                &op,
                crate::kernel::continuation::ipc::IpcCause::Stop,
                crate::kernel::continuation::ipc::CounterClock {
                    now: 1,
                    numer: 1,
                    denom: 1
                },
            ),
            crate::kernel::continuation::ipc::IpcHostOutcome::Complete {
                result: carrick_abi::LINUX_EINTR.guest_retval(),
                sigpipe: false,
            }
        );
    }

    /// Contract kernel.el1.deferred-handback-identity. The slot evacuation
    /// and its publication are separate phases: a control claimant can retire
    /// a host-owned record in between. Publication owes the original thread
    /// only, never a new waiter that reused the record number.
    #[test]
    fn deferred_slot_handback_does_not_wake_a_reused_record() {
        use carrick_conformance_contract::{
            Completeness, ContractId, ContractObservation, ContractRegistry, ExecutionLayer,
            SemanticAssertion, WorkMetric, WorkSnapshot, evaluate,
        };
        use sha2::{Digest, Sha256};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let registry = ContractRegistry::load(root).unwrap();
        let contract = registry
            .require("kernel.el1.deferred-handback-identity")
            .unwrap();
        let mut observations = Vec::new();
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
                assert!(zone.requeue_on(slot, record).is_some());
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
            settle_vacated(
                &zone,
                None,
                records,
                placements,
                &mut |record| {
                    published.push(record);
                },
                &mut |_| {},
            );
            assert!(
                published.is_empty(),
                "delayed handback targeted replacement: {published:?}"
            );
            for (record, seq) in replacements {
                assert_eq!(zone.record(record).claim(), Claim::Parked { seq });
            }
            // Count the actual publication callback in this one zone's
            // deferred delivery window, not a process-global counter delta.
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::WakePublications, published.len() as u64)
                .unwrap();
            observations.push(ContractObservation {
                contract_id: ContractId::new("kernel.el1.deferred-handback-identity").unwrap(),
                layer: ExecutionLayer::VmFree,
                implementation_revision: format!(
                    "sha256:{:x}",
                    Sha256::new()
                        .chain_update(include_bytes!("el1_zone.rs"))
                        .chain_update(include_bytes!("../../carrick-sched-core/src/lib.rs"))
                        .chain_update(include_bytes!("../../carrick-el1-abi/src/lib.rs"))
                        .finalize()
                ),
                fixture_identity: "unit:deferred_slot_handback_does_not_wake_a_reused_record"
                    .into(),
                scale: count,
                semantic_assertions: vec![SemanticAssertion::pass("replacement_remains_parked")],
                work: Some(work),
                timing: None,
                completeness: Completeness::Complete,
            });
        }
        evaluate(contract, &observations).unwrap();
        for observation in &observations {
            println!("{}", serde_json::to_string(observation).unwrap());
        }
        // The bound must reject even one extra publication at every scale.
        for index in 0..observations.len() {
            let mut extra = observations.clone();
            let mut work = WorkSnapshot::new();
            work.insert(WorkMetric::WakePublications, 1).unwrap();
            extra[index].work = Some(work);
            assert!(
                matches!(
                    evaluate(contract, &extra),
                    Err(
                        carrick_conformance_contract::ContractFailure::WorkBudgetExceeded {
                            metric: WorkMetric::WakePublications,
                            actual: 1,
                            maximum: 0,
                            ..
                        }
                    )
                ),
                "extra wake escaped the structural budget"
            );
        }
    }

    mod serial_host {
        use super::*;

        #[test]
        fn deferred_capture_does_not_hold_publisher_registration() {
            struct Restore(Option<HandbackPublisher>);
            impl Drop for Restore {
                fn drop(&mut self) {
                    *HANDBACK_PUBLISHER.write() = self.0.take();
                }
            }
            let _restore = Restore(HANDBACK_PUBLISHER.write().take());
            let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let callback_observed = Arc::clone(&observed);
            let record = RecordRef {
                id: carrick_el1_abi::RecordId::from_raw(1).unwrap(),
                incarnation: 7,
            };
            register_handback_publisher(Arc::new(move |event| {
                let HandbackEvent::DeferredCaptured(records) = event else {
                    panic!("expected deferred capture");
                };
                assert_eq!(records, &[record]);
                let registration = HANDBACK_PUBLISHER.try_write();
                assert!(
                    registration.is_some(),
                    "callback retained registration lock"
                );
                callback_observed.store(true, std::sync::atomic::Ordering::SeqCst);
            }));
            capture_handbacks(&[record]);
            assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
        }

        /// #641: EL1 defers an object-wait completion it cannot place (no
        /// slot in the guest) to the carrier boundary: the record is
        /// `Transferring` with `Handback::Resumed` on the completion chain,
        /// and the slot's pending-host-work doorbell is its only signal. An
        /// idle executor consumes that doorbell through `settle_el1_boundary`
        /// before it waits in the guest again. Consuming the doorbell must
        /// settle the chain it announces; otherwise every vCPU idles in WFI
        /// while the record's thread stays blocked on its host wait forever.
        #[test]
        fn idle_boundary_doorbell_settles_deferred_completion_handback() {
            deferred_completion_reaches_idle_boundary(
                carrick_el1_abi::LinuxTaskState::mark_pending_host_work,
                |_| {},
            );
        }

        /// #641 (second signed capture): binding a task to the slot between
        /// the deferral and the idle boundary must not erase the doorbell
        /// that announces the stranded completion.
        #[test]
        fn task_binding_keeps_deferred_completion_doorbell() {
            deferred_completion_reaches_idle_boundary(
                carrick_el1_abi::LinuxTaskState::mark_pending_host_work,
                bind_task,
            );
        }

        /// The same owed work announced through a served-with-work boundary
        /// (EL1 served the call and owes host wakes): rebinding the slot must
        /// move it to the doorbell, not erase it.
        #[test]
        fn task_binding_retires_served_boundary_into_doorbell() {
            deferred_completion_reaches_idle_boundary(
                carrick_el1_abi::LinuxTaskState::record_completed_with_work,
                bind_task,
            );
        }

        fn bind_task(slot: usize) {
            crate::el1_delegation::publish_current_task(
                slot,
                carrick_el1_abi::El1TaskId::from_linux_tid(2),
                carrick_el1_abi::SnapshotGeneration::from_raw(2_658),
                1,
                2,
                carrick_el1_abi::ContextGeneration::new(std::num::NonZeroU64::MIN),
            );
        }

        fn deferred_completion_reaches_idle_boundary(
            ring: fn(&carrick_el1_abi::LinuxTaskState),
            between: impl FnOnce(usize),
        ) {
            use carrick_sched_core::object_wait::{
                ObjectWaitKey, OperationToken, OwnedObjectWakeEffects,
            };
            use std::sync::Mutex;
            const SLOT: usize = 3;
            struct Restore(Option<HandbackPublisher>, usize);
            impl Drop for Restore {
                fn drop(&mut self) {
                    *HANDBACK_PUBLISHER.write() = self.0.take();
                    carrick_el1_abi::record_el1_region_host_ptr(self.1);
                }
            }
            let _restore = Restore(
                HANDBACK_PUBLISHER.write().take(),
                carrick_el1_abi::get_el1_region_host_ptr(),
            );
            let region = carrick_test_support::TestEl1Region::zeroed();
            carrick_el1_abi::record_el1_region_host_ptr(region.as_ptr() as usize);
            let task = {
                let at = region.as_ptr() as usize
                    + carrick_el1_abi::EL1_CURRENT_TASKS_OFFSET as usize
                    + SLOT * std::mem::size_of::<carrick_el1_abi::CurrentTask>();
                // SAFETY: inside the zeroed region; all-zero is an empty task.
                unsafe { &*(at as *const carrick_el1_abi::CurrentTask) }
            };
            let zone = zone_tables().unwrap();
            let ready = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&ready);
            register_handback_publisher(Arc::new(move |event| {
                if let HandbackEvent::Ready(record) = event {
                    seen.lock().unwrap().push(record);
                }
            }));
            // The guest venue (`deliver_completion`): defer what could not be
            // placed, then ring the venue slot's pending-host-work doorbell.
            let completion =
                |owned: OwnedObjectWakeEffects<'_, carrick_el1_abi::Aarch64ParkedContext>| {
                    let (_, _, deferred) = owned.defer_handbacks();
                    if deferred {
                        ring(&task.linux);
                    }
                };
            let key = ObjectWaitKey::new(3, 11).unwrap();
            zone.bind_object_wait_with_completion(key, &HostLockWait, &completion)
                .unwrap();
            let ticket = zone
                .admit_object_notification(key, &HostLockWait, &completion)
                .unwrap();
            let record = zone
                .alloc_record(ThreadIdentity {
                    tid: 2,
                    serial: 43,
                    mm: 2,
                    file_table: 1,
                    generation: 267,
                    affinity: 0,
                    lifecycle_page: 0,
                    control_slot: 0,
                })
                .unwrap();
            let reference = zone.record_ref(record);
            {
                let guard = zone
                    .object_wait_with_completion(key, &HostLockWait, &completion)
                    .unwrap();
                guard
                    .park(
                        guard.snapshot(),
                        record,
                        OperationToken::new(403, 11).unwrap(),
                    )
                    .unwrap();
            }
            ticket.publish(Waker::Host, &completion);
            // The captured #641 state: deferred, unplaced, doorbell rung.
            assert!(matches!(
                zone.record(record).claim(),
                Claim::Transferring { .. }
            ));
            assert_eq!(zone.record(record).handback(), Some(Handback::Resumed));
            assert!(task.linux.has_pending_host_work() || task.linux.served_boundary_pending());
            between(SLOT);
            // The idle executor's boundary consumes the doorbell.
            let (kernel, _context) = crate::kernel::continuation::test_support::bootstrap(164_100);
            let _ = crate::el1_delegation::settle_el1_boundary(SLOT, &kernel);
            assert!(!task.linux.has_pending_host_work());
            assert!(!task.linux.served_boundary_pending());
            assert!(
                matches!(zone.record(record).claim(), Claim::Host { .. }),
                "consumed doorbell left the deferred handback stranded: {:?}",
                zone.record(record).claim()
            );
            assert_eq!(ready.lock().unwrap().as_slice(), &[reference]);
            // SAFETY: the boundary published this exact Host record; the
            // test owns its operation now and returns it.
            assert_eq!(
                unsafe { zone.record(record).take_object_operation() }
                    .unwrap()
                    .index(),
                403
            );
            zone.free_record(record);
        }
    }

    /// #695: the step-away capture boundary reports exactly the host-owned
    /// records queued on the vacated slot, once, in one batch.
    #[test]
    fn step_away_captures_exactly_the_queued_service_record() {
        let zone = heap_zone();
        let slot = SlotId::new(3);
        zone.drive(slot, 7);
        let queued = zone.alloc_host_runnable(identity(1)).unwrap();
        let reference = zone.record_ref(queued);
        assert!(zone.requeue_on(slot, queued).is_some());
        let mut records = Vec::new();
        let mut placements = Vec::new();
        assert!(zone.step_away(
            slot,
            7,
            &mut |record| records.push(record),
            &mut |placement| placements.push(placement),
        ));
        let mut batches = Vec::new();
        settle_vacated(
            &zone,
            Some(slot),
            records,
            placements,
            &mut |_| {},
            &mut |captured| batches.push(captured.to_vec()),
        );
        assert_eq!(batches, [vec![reference]]);
    }

    #[cfg(all(feature = "test-support", feature = "deferred-capture-test-control"))]
    mod serial_host_deferred_capture_control {
        use super::*;
        use deferred_capture_control::{HoldOutcome, arm};
        use std::time::Duration;

        fn thread() -> crate::kernel::ThreadKey {
            crate::kernel::ThreadKey::from_zone_identity(42, std::num::NonZeroU64::new(43).unwrap())
                .unwrap()
        }

        fn captures(run: impl FnOnce()) -> Vec<Vec<RecordRef>> {
            struct Restore(Option<HandbackPublisher>);
            impl Drop for Restore {
                fn drop(&mut self) {
                    *HANDBACK_PUBLISHER.write() = self.0.take();
                }
            }
            let _restore = Restore(HANDBACK_PUBLISHER.write().take());
            let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
            let sink = Arc::clone(&seen);
            register_handback_publisher(Arc::new(move |event| {
                if let HandbackEvent::DeferredCaptured(records) = event {
                    sink.lock().unwrap().push(records.to_vec());
                }
            }));
            run();
            seen.lock().unwrap().clone()
        }

        #[test]
        fn hold_is_captured_exactly_once_at_the_next_step_away() {
            let zone: &'static ZoneTables = Box::leak(heap_zone());
            let slot = SlotId::new(0);
            zone.drive(slot, 7);
            let mut outcome = HoldOutcome::NotHeld;
            let batches = captures(|| {
                with_test_zone(zone, || {
                    let hold = arm(Duration::from_secs(10));
                    // Before any step-away the workload may still be in its
                    // first run: nothing is held.
                    step_away_from_slot(slot, 7);
                    zone.step_back(slot, 7);
                    assert!(place_service(
                        thread(),
                        crate::kernel::objects::ExecutionGeneration::from_raw(9),
                        1
                    ));
                    // Held: not queued where the guest could run it.
                    assert_eq!(zone.slot(slot).queued(), 0);
                    step_away_from_slot(slot, 7);
                    outcome = hold.finish();
                });
            });
            let HoldOutcome::ReleasedAtStepAway { record, slot: at } = outcome else {
                panic!("hold was not released at step-away: {outcome:?}");
            };
            assert_eq!(at, slot);
            assert_eq!(batches, [vec![record]]);
        }

        #[test]
        fn nothing_is_held_before_the_first_step_away() {
            let zone: &'static ZoneTables = Box::leak(heap_zone());
            let slot = SlotId::new(0);
            zone.drive(slot, 7);
            let mut outcome = HoldOutcome::NotHeld;
            let batches = captures(|| {
                with_test_zone(zone, || {
                    let hold = arm(Duration::from_secs(10));
                    assert!(place_service(
                        thread(),
                        crate::kernel::objects::ExecutionGeneration::from_raw(9),
                        1
                    ));
                    // Placed normally on the live slot, not held.
                    assert_eq!(zone.slot(slot).queued(), 1);
                    outcome = hold.finish();
                });
            });
            assert_eq!(outcome, HoldOutcome::NotHeld);
            assert!(batches.is_empty());
        }

        /// #695 signed 20x at 8f932d032: holding a pingpong thread stalls its
        /// partner. A step-away only on a slot the held record may not run on
        /// releases nothing, and the hold expires. An independent actor
        /// stepping away on the record's allowed CPU releases it.
        #[test]
        fn hold_needs_a_step_away_on_an_allowed_cpu() {
            let zone: &'static ZoneTables = Box::leak(heap_zone());
            let (allowed, other) = (SlotId::new(0), SlotId::new(1));
            zone.drive(allowed, 7);
            zone.drive(other, 8);
            zone.publish_slot(allowed, 0, Some(0), 0);
            zone.publish_slot(other, 0, Some(1), 0);
            let place = || {
                assert!(place_service(
                    thread(),
                    crate::kernel::objects::ExecutionGeneration::from_raw(9),
                    0b1
                ));
            };
            // Stall shape: only the partner's slot (another CPU) steps away.
            let mut stalled = HoldOutcome::NotHeld;
            let batches = captures(|| {
                with_test_zone(zone, || {
                    let hold = arm(Duration::from_secs(10));
                    step_away_from_slot(other, 8);
                    zone.step_back(other, 8);
                    place();
                    step_away_from_slot(other, 8);
                    zone.step_back(other, 8);
                    stalled = hold.finish();
                });
            });
            assert!(
                matches!(stalled, HoldOutcome::Expired { .. }),
                "{stalled:?}"
            );
            assert!(batches.is_empty(), "{batches:?}");
            // Fixed shape: an independent actor on the allowed CPU steps away.
            let mut released = HoldOutcome::NotHeld;
            let batches = captures(|| {
                with_test_zone(zone, || {
                    let hold = arm(Duration::from_secs(10));
                    step_away_from_slot(other, 8);
                    zone.step_back(other, 8);
                    place();
                    step_away_from_slot(allowed, 7);
                    released = hold.finish();
                });
            });
            let HoldOutcome::ReleasedAtStepAway { record, slot } = released else {
                panic!("independent actor did not release the hold: {released:?}");
            };
            assert_eq!(slot, allowed);
            assert_eq!(batches, [vec![record]]);
        }

        /// #695 signed 20x at 81de5b7c0: 4 runs resumed the held thread and
        /// it faulted on its own stack. The hold must not change what the
        /// record says or where production places it: released at a
        /// step-away, the captured record is placed by `settle_vacated`
        /// exactly as an unheld record queued on that slot is, with its
        /// identity (thread, generation, mm, affinity) unchanged, and the
        /// live slot's executor takes exactly that record.
        #[test]
        fn held_record_is_placed_like_a_production_record() {
            let generation = crate::kernel::objects::ExecutionGeneration::from_raw(9);
            let expected = carrick_el1_abi::ThreadIdentity {
                tid: carrick_el1_abi::El1TaskId::from_linux_tid(thread().tid.raw()).raw(),
                serial: thread().serial.raw(),
                mm: 0,
                file_table: 0,
                generation: generation.raw(),
                affinity: 0b11,
                lifecycle_page: 0,
                control_slot: 0,
            };
            // Where one vacated record ends up, and what it says there.
            let run = |held: bool| {
                let zone: &'static ZoneTables = Box::leak(heap_zone());
                let (away, live) = (SlotId::new(0), SlotId::new(1));
                zone.drive(away, 7);
                zone.drive(live, 8);
                zone.publish_slot(away, 0, Some(0), 0);
                zone.publish_slot(live, 0, Some(1), 0);
                let mut record = None;
                let batches = captures(|| {
                    with_test_zone(zone, || {
                        if held {
                            let hold = arm(Duration::from_secs(10));
                            step_away_from_slot(live, 8);
                            zone.step_back(live, 8);
                            assert!(place_service(thread(), generation, 0b11));
                            assert_eq!(zone.slot(away).queued() + zone.slot(live).queued(), 0);
                            step_away_from_slot(away, 7);
                            let HoldOutcome::ReleasedAtStepAway { record: held, slot } =
                                hold.finish()
                            else {
                                panic!("hold was not released at the step-away");
                            };
                            assert_eq!(slot, away);
                            record = Some(held);
                        } else {
                            // Production: the record is already queued on the
                            // slot whose driver steps away.
                            let id = zone.alloc_host_runnable(expected).unwrap();
                            assert!(zone.requeue_on(away, id).is_some());
                            record = Some(zone.record_ref(id));
                            step_away_from_slot(away, 7);
                        }
                    });
                });
                let record = record.unwrap();
                assert_eq!(batches, [vec![record]]);
                assert_eq!(zone.slot(away).queued(), 0);
                assert_eq!(zone.slot(live).queued(), 1);
                let rec = zone.live(record).expect("placed record is live");
                assert_eq!(rec.identity(), expected);
                assert_eq!(rec.handback(), Some(Handback::Service));
                // The live slot's executor takes exactly this record; its
                // identity names the thread's exact runnable generation.
                assert_eq!(zone.take_service_head(live), Some(record));
                assert_eq!(zone.live(record).map(|rec| rec.identity()), Some(expected));
            };
            run(false);
            run(true);
        }

        #[test]
        fn unreleased_hold_expires_to_the_host_queue() {
            let zone: &'static ZoneTables = Box::leak(heap_zone());
            let slot = SlotId::new(0);
            zone.drive(slot, 7);
            let mut outcome = HoldOutcome::NotHeld;
            let mut published = 0;
            let batches = captures(|| {
                with_test_zone(zone, || {
                    let hold = arm(Duration::from_secs(10));
                    // Before any step-away the workload may still be in its
                    // first run: nothing is held.
                    step_away_from_slot(slot, 7);
                    zone.step_back(slot, 7);
                    assert!(place_service(
                        thread(),
                        crate::kernel::objects::ExecutionGeneration::from_raw(9),
                        1
                    ));
                    outcome = hold.finish();
                    published = 1;
                });
            });
            assert!(
                matches!(outcome, HoldOutcome::Expired { .. }),
                "{outcome:?}"
            );
            assert!(batches.is_empty());
            assert_eq!(published, 1);
        }
    }

    #[test]
    fn deferred_capture_precedes_filter_and_releases_queue_authority() {
        let zone = heap_zone();
        let slot = SlotId::new(3);
        zone.drive(slot, 7);
        let old_id = zone.alloc_host_runnable(identity(1)).unwrap();
        let old = zone.record_ref(old_id);
        assert!(zone.requeue_on(slot, old_id).is_some());
        let mut records = Vec::new();
        let mut placements = Vec::new();
        assert!(zone.leave_slot(
            slot,
            7,
            &mut |record| records.push(record),
            &mut |placement| placements.push(placement),
        ));
        let mut captured = Vec::new();
        let mut published = Vec::new();
        let mut replacement = None;
        settle_vacated(
            &zone,
            None,
            records,
            placements,
            &mut |record| published.push(record),
            &mut |records| {
                struct RefuseWait;
                impl<C: carrick_el1_abi::EntryContext> LockWait<C> for RefuseWait {
                    fn wait(&self, _: u32) -> bool {
                        false
                    }
                }
                let queue = zone.slot_lock(slot, &RefuseWait);
                assert!(queue.is_some(), "capture retained queue authority");
                drop(queue);
                captured.extend_from_slice(records);
                assert_eq!(records, &[old]);
                // The core evacuation has returned; the hook can retire and
                // reuse this allocation before deferred filtering runs.
                zone.free_record(old.id);
                let next = zone.alloc_record(identity(2)).unwrap();
                assert_eq!(next, old.id);
                let seq = zone.next_seq(next);
                zone.publish_park(next, seq);
                replacement = Some((zone.record_ref(next), seq));
            },
        );
        assert_eq!(captured, [old]);
        assert!(published.is_empty());
        let (replacement, seq) = replacement.unwrap();
        assert_ne!(replacement, old);
        assert_eq!(
            zone.live(replacement).unwrap().claim(),
            Claim::Parked { seq }
        );
    }

    #[test]
    fn born_wake_handbacks_reach_first_entry_for_two_live_processes() {
        let zone = heap_zone();
        let mut published = Vec::new();
        for (cpu, mm) in [(0, 7), (1, 8)] {
            let slot = SlotId::new(cpu);
            zone.drive(slot, u64::from(cpu) + 1);
            zone.publish_slot(slot, 0, Some(u32::from(cpu)), 0);
            zone.enter_guest(slot);
            zone.enter_idle(slot, true);
            let id = zone
                .alloc_record(ThreadIdentity {
                    mm,
                    generation: 0,
                    affinity: 1 << cpu,
                    lifecycle_page: 0x1000 + mm * 4096,
                    control_slot: 0x2000 + mm * 4096,
                    ..identity(mm)
                })
                .unwrap();
            let record = zone.record_ref(id);
            zone.publish_park(id, zone.next_seq(id));
            zone.claim_for_host(record, None, Handback::Woken, &HostLockWait);
            publish_handback_in_zone(&zone, record, &mut |record| published.push(record));
            assert!(
                published.is_empty(),
                "a Born wake cannot target a nonexistent host continuation"
            );
            assert_eq!(zone.take_service_head(slot), Some(record));
            assert_eq!(zone.live(record).unwrap().handback(), Some(Handback::Woken));
        }
    }

    #[test]
    fn deferred_born_handbacks_reach_executors_for_two_live_processes() {
        let zone = heap_zone();
        let mut records = Vec::new();
        for (cpu, mm) in [(0, 7), (1, 8)] {
            let slot = SlotId::new(cpu);
            zone.drive(slot, u64::from(cpu) + 1);
            zone.publish_slot(slot, 0, Some(u32::from(cpu)), 0);
            zone.enter_guest(slot);
            zone.enter_idle(slot, true);
            let id = zone
                .alloc_record(ThreadIdentity {
                    mm,
                    generation: 0,
                    affinity: 1 << cpu,
                    lifecycle_page: 0x1000 + mm * 4096,
                    control_slot: 0x2000 + mm * 4096,
                    ..identity(mm)
                })
                .unwrap();
            let record = zone.record_ref(id);
            zone.publish_park(id, zone.next_seq(id));
            zone.claim_for_host(record, None, Handback::Resumed, &HostLockWait);
            records.push(record);
        }
        let mut published = Vec::new();
        settle_vacated(
            &zone,
            None,
            records.clone(),
            Vec::new(),
            &mut |record| published.push(record),
            &mut |_| {},
        );
        assert!(
            published.is_empty(),
            "a Born thread has no host continuation to wake"
        );
        for (cpu, record) in records.iter().enumerate() {
            let slot = SlotId::new(cpu as u8);
            assert_eq!(zone.take_service_head(slot), Some(*record));
        }
    }

    #[test]
    fn deferred_slot_handback_preserves_live_records() {
        let zone = heap_zone();
        let slot = SlotId::new(3);
        zone.drive(slot, 7);
        let record = zone.alloc_host_runnable(identity(1)).unwrap();
        let expected = zone.record_ref(record);
        assert!(zone.requeue_on(slot, record).is_some());
        let mut records = Vec::new();
        let mut placements = Vec::new();
        assert!(zone.leave_slot(
            slot,
            7,
            &mut |record| records.push(record),
            &mut |placement| placements.push(placement),
        ));
        let mut published = Vec::new();
        settle_vacated(
            &zone,
            None,
            records,
            placements,
            &mut |record| {
                published.push(record);
            },
            &mut |_| {},
        );
        assert_eq!(published, [expected]);
        assert!(matches!(
            zone.live(expected).unwrap().claim(),
            Claim::Host { .. }
        ));
    }
}
