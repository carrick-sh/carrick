//! The in-guest scheduler's shared objects (EL1 plan 1b): private futex wait
//! queues and the per-vCPU run queues through which guest EL1 hands a CPU
//! from one guest thread to another without a host exit.
//!
//! One implementation, two venues: guest EL1 (`carrick-el1`) and the host
//! runtime operate on the same [`ZoneTables`] in the shared EL1 region, under
//! the same bucket locks, through the functions here.
//!
//! # Ownership: one owner per parked thread
//!
//! A thread that waits on a private futex of a zone process is represented by
//! a [`ZoneRecord`]: its EL0 register context ([`ThreadCtx`]) and a single
//! 64-bit claim word ([`Claim`]). The claim word names the one owner of that
//! context at every instant, and every transfer is one compare-and-swap:
//!
//! - [`Claim::Parked`]: queued on one or more futex wait queues. Nobody runs
//!   it. Any waker (EL1 or host) may claim it, as may the host for a signal,
//!   a timeout or a teardown; exactly one CAS wins.
//! - [`Claim::Queued`] / [`Claim::OnCpu`]: an EL1 waker on vCPU slot `s`
//!   claimed it; it waits on, or runs from, `s`'s run queue. Only `s` may
//!   touch it: EL1 while `s`'s vCPU runs, the executor holding `s` while it is
//!   stopped at an exit. The host reaches it by kicking `s` (an exit), never
//!   by writing it.
//! - [`Claim::Host`]: the host claimed it (a wake, a signal, a timeout, a
//!   teardown, or `s`'s executor handing it back at an exit). The context is
//!   frozen until the host loads the thread and frees the record.
//!
//! The context is written only by the party that is about to publish
//! `Parked` (the thread's current runner) or that holds `Queued`/`OnCpu`,
//! and read only after a successful claim, so no two parties ever touch it at
//! once.

#![no_std]

#[cfg(test)]
extern crate std;

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Parked-thread records (index 0 is reserved as "none").
pub const ZONE_RECORDS: usize = 4096;
/// Futex wait-queue entries (index 0 is reserved as "none"). A plain wait
/// uses one; a `futex_waitv` uses one per futex.
pub const ZONE_ENTRIES: usize = 8192;
/// Futex hash buckets.
pub const ZONE_BUCKETS: usize = 1024;
/// vCPU slots (one per syscall-mailbox slot).
pub const ZONE_SLOTS: usize = 256;
/// Threads one vCPU slot may hold woken and waiting to run.
pub const ZONE_RUNQ_CAPACITY: usize = 8;

const NIL: u32 = 0;

/// A record index in `1..ZONE_RECORDS`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct RecordId(u32);

impl RecordId {
    /// Filler for result arrays; never read before the callee writes it.
    pub const PLACEHOLDER: Self = Self(1);

    /// A record id from its raw index; `None` for 0 or out of range.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        if raw == 0 || raw as usize >= ZONE_RECORDS {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    const fn index(self) -> usize {
        self.0 as usize
    }
}

/// A vCPU slot (the syscall-mailbox slot index).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct SlotId(u8);

impl SlotId {
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// A slot from a mailbox slot index; `None` beyond [`ZONE_SLOTS`].
    pub fn from_index(index: usize) -> Option<Self> {
        u8::try_from(index).ok().map(Self)
    }

    pub const fn raw(self) -> u8 {
        self.0
    }
}

/// Who owns a parked thread's context. See the crate docs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Claim {
    /// The record is not in use.
    Free,
    /// On futex wait queue(s), claimable by one CAS. `seq` names this park.
    Parked { seq: u32 },
    /// Claimed by EL1 on `slot` and waiting on its run queue.
    Queued { slot: SlotId, seq: u32 },
    /// Running on `slot` (EL1 switched it in); the record's context is stale.
    OnCpu { slot: SlotId, seq: u32 },
    /// Owned by the host; the context is frozen until the thread is loaded.
    Host { seq: u32 },
}

const STATE_FREE: u64 = 0;
const STATE_PARKED: u64 = 1;
const STATE_QUEUED: u64 = 2;
const STATE_ONCPU: u64 = 3;
const STATE_HOST: u64 = 4;

impl Claim {
    pub const fn encode(self) -> u64 {
        match self {
            Self::Free => STATE_FREE,
            Self::Parked { seq } => STATE_PARKED | ((seq as u64) << 16),
            Self::Queued { slot, seq } => {
                STATE_QUEUED | ((slot.0 as u64) << 8) | ((seq as u64) << 16)
            }
            Self::OnCpu { slot, seq } => {
                STATE_ONCPU | ((slot.0 as u64) << 8) | ((seq as u64) << 16)
            }
            Self::Host { seq } => STATE_HOST | ((seq as u64) << 16),
        }
    }

    pub const fn decode(word: u64) -> Self {
        let seq = (word >> 16) as u32;
        let slot = SlotId(((word >> 8) & 0xff) as u8);
        match word & 0xff {
            STATE_PARKED => Self::Parked { seq },
            STATE_QUEUED => Self::Queued { slot, seq },
            STATE_ONCPU => Self::OnCpu { slot, seq },
            STATE_HOST => Self::Host { seq },
            _ => Self::Free,
        }
    }

    /// The park this claim belongs to (0 for [`Claim::Free`]).
    pub const fn seq(self) -> u32 {
        match self {
            Self::Free => 0,
            Self::Parked { seq }
            | Self::Queued { seq, .. }
            | Self::OnCpu { seq, .. }
            | Self::Host { seq } => seq,
        }
    }
}

/// Why the host owns a record, set with the transition to [`Claim::Host`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Handback {
    /// Woken by a futex wake: apply [`ZoneRecord::result`] as the syscall's
    /// return value.
    Woken = 1,
    /// It ran in-guest after its wait and was stopped at an exit; its context
    /// is its current state, with nothing to apply.
    Resumed = 2,
    /// Its wait's deadline passed while it was parked.
    Timeout = 3,
    /// A signal interrupts its wait.
    Signal = 4,
    /// The host needs it runnable for a control action (exit or exec drain).
    Control = 5,
    /// Its host continuation was cancelled; the thread will not run again.
    Cancelled = 6,
}

impl Handback {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Woken),
            2 => Some(Self::Resumed),
            3 => Some(Self::Timeout),
            4 => Some(Self::Signal),
            5 => Some(Self::Control),
            6 => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// A guest thread's EL0 register context while it is parked in the zone:
/// what an in-guest switch saves and restores. FP/SIMD state is 16-byte
/// aligned for `stp q`/`ldp q` (`v` at offset 304, FPSR and FPCR after it).
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadCtx {
    /// X0..X30.
    pub x: [u64; 31],
    /// The EL0 resume PC (for a thread parked in a syscall, the instruction
    /// after its `svc`).
    pub pc: u64,
    /// The EL0 PSTATE paired with `pc`.
    pub pstate: u64,
    pub sp_el0: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub contextidr_el1: u64,
    _pad: u64,
    /// V0..V31.
    pub v: [u128; 32],
    /// Written by the EL1 FP/SIMD routine right after `v`: FPSR, then FPCR.
    pub fpsr: u64,
    pub fpcr: u64,
}

/// Byte offset of [`ThreadCtx::v`] (the FP/SIMD save area).
pub const THREAD_CTX_V_OFFSET: usize = core::mem::offset_of!(ThreadCtx, v);
/// Byte offset of [`ThreadCtx::fpsr`] (FPCR follows it).
pub const THREAD_CTX_FPSR_OFFSET: usize = core::mem::offset_of!(ThreadCtx, fpsr);
const _: () = assert!(THREAD_CTX_V_OFFSET.is_multiple_of(16));
const _: () = assert!(THREAD_CTX_FPSR_OFFSET + 8 == core::mem::offset_of!(ThreadCtx, fpcr));

impl ThreadCtx {
    pub const ZERO: Self = Self {
        x: [0; 31],
        pc: 0,
        pstate: 0,
        sp_el0: 0,
        tpidr_el0: 0,
        tpidrro_el0: 0,
        contextidr_el1: 0,
        _pad: 0,
        v: [0; 32],
        fpsr: 0,
        fpcr: 0,
    };
}

/// The identity a parked thread carries so the host can find its kernel
/// thread and EL1 can publish it as the running task after a switch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ThreadIdentity {
    /// The `El1TaskId` word (zero-extended Linux tid).
    pub tid: u64,
    /// The host's thread serial (with `tid`, the exact kernel thread).
    pub serial: u64,
    /// The zone key: the process's address-space id. Threads switch only
    /// among records of the same `mm`.
    pub mm: u64,
    /// The thread's file table (EL1's file zone reads it).
    pub file_table: u64,
    /// The host task generation published with the thread.
    pub generation: u64,
}

/// One parked thread. See the crate docs for the ownership protocol.
#[repr(C, align(64))]
pub struct ZoneRecord {
    claim: AtomicU64,
    /// Bumped on every allocation; with the index it names one use.
    incarnation: AtomicU64,
    tid: AtomicU64,
    serial: AtomicU64,
    mm: AtomicU64,
    file_table: AtomicU64,
    generation: AtomicU64,
    /// The syscall return value to apply when woken (0, or a waitv index).
    result: AtomicU64,
    handback: AtomicU32,
    /// First queue entry of the current park (entries chain via `sibling`).
    first_entry: AtomicU32,
    entry_count: AtomicU32,
    /// The last park's sequence number (the next park uses +1).
    last_seq: AtomicU32,
    /// The host retired the thread while EL1 held its record: whoever next
    /// owns the record discards it instead of running or handing it back.
    cancelled: AtomicU32,
    ctx: UnsafeCell<ThreadCtx>,
}

// SAFETY: the context is accessed only by the claim-word owner (crate docs);
// every other field is atomic.
unsafe impl Sync for ZoneRecord {}

impl ZoneRecord {
    pub fn claim(&self) -> Claim {
        Claim::decode(self.claim.load(Ordering::Acquire))
    }

    pub fn incarnation(&self) -> u64 {
        self.incarnation.load(Ordering::Acquire)
    }

    pub fn identity(&self) -> ThreadIdentity {
        ThreadIdentity {
            tid: self.tid.load(Ordering::Relaxed),
            serial: self.serial.load(Ordering::Relaxed),
            mm: self.mm.load(Ordering::Relaxed),
            file_table: self.file_table.load(Ordering::Relaxed),
            generation: self.generation.load(Ordering::Relaxed),
        }
    }

    pub fn result(&self) -> u64 {
        self.result.load(Ordering::Acquire)
    }

    pub fn handback(&self) -> Option<Handback> {
        Handback::from_raw(self.handback.load(Ordering::Acquire))
    }

    pub fn entry_count(&self) -> u32 {
        self.entry_count.load(Ordering::Acquire)
    }

    /// Whether the host retired the thread while EL1 held this record.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) != 0
    }

    /// The host retires the thread while EL1 holds the record (a claim
    /// returned [`HostClaim::El1Held`]); the slot's executor discards it.
    pub fn request_cancel(&self) {
        self.cancelled.store(1, Ordering::Release);
    }

    /// The context.
    ///
    /// # Safety
    ///
    /// The caller owns the record per the claim protocol: it is about to
    /// publish `Parked`, or holds `Queued`/`OnCpu` for its slot, or has
    /// claimed `Host`.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn ctx_mut(&self) -> &mut ThreadCtx {
        // SAFETY: exclusive access is the caller's contract.
        unsafe { &mut *self.ctx.get() }
    }

    fn set_identity(&self, id: ThreadIdentity) {
        self.tid.store(id.tid, Ordering::Relaxed);
        self.serial.store(id.serial, Ordering::Relaxed);
        self.mm.store(id.mm, Ordering::Relaxed);
        self.file_table.store(id.file_table, Ordering::Relaxed);
        self.generation.store(id.generation, Ordering::Relaxed);
    }

    fn cas(&self, current: Claim, next: Claim) -> bool {
        self.claim
            .compare_exchange(
                current.encode(),
                next.encode(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

/// One futex wait-queue entry: a record waiting on `(mm, uaddr)`.
#[repr(C, align(64))]
pub struct ZoneEntry {
    next: AtomicU32,
    prev: AtomicU32,
    record: AtomicU32,
    /// The next entry of the same record (a `futex_waitv` park).
    sibling: AtomicU32,
    bucket: AtomicU32,
    seq: AtomicU32,
    bitset: AtomicU32,
    /// The waitv index this entry reports when it wakes the record.
    index: AtomicU32,
    mm: AtomicU64,
    uaddr: AtomicU64,
}

/// A futex hash bucket: a lock and a doubly linked FIFO of entries.
#[repr(C, align(16))]
pub struct ZoneBucket {
    lock: AtomicU32,
    head: AtomicU32,
    tail: AtomicU32,
    len: AtomicU32,
}

/// Per-vCPU-slot scheduler state. Touched only by EL1 on that slot's vCPU
/// while it runs and by the executor holding the slot while it is stopped
/// (sequential ownership, no lock); other host threads read `len` and
/// `queued_since` only.
#[repr(C, align(64))]
pub struct ZoneSlot {
    /// The record EL1 switched in (0: the thread the host loaded is running).
    current: AtomicU32,
    len: AtomicU32,
    /// The record EL1 allocated when it parked the thread the host loaded on
    /// this slot (0: it has not parked since the host loaded it).
    host_record: AtomicU32,
    _pad: AtomicU32,
    /// CNTVCT when the run queue last became non-empty.
    queued_since: AtomicU64,
    runq: [AtomicU32; ZONE_RUNQ_CAPACITY],
}

impl ZoneSlot {
    /// The record EL1 switched in, if any.
    pub fn current(&self) -> Option<RecordId> {
        RecordId::from_raw(self.current.load(Ordering::Acquire))
    }

    /// Threads EL1 woke onto this slot that have not run yet.
    pub fn queued(&self) -> usize {
        self.len.load(Ordering::Acquire) as usize
    }

    /// CNTVCT when the run queue last became non-empty.
    pub fn queued_since(&self) -> u64 {
        self.queued_since.load(Ordering::Acquire)
    }

    /// The record of the host-loaded thread, if EL1 parked it.
    pub fn host_record(&self) -> Option<RecordId> {
        RecordId::from_raw(self.host_record.load(Ordering::Acquire))
    }
}

/// Zone event counters (carrier-wide, for tests and diagnostics).
#[repr(C)]
pub struct ZoneCounters {
    /// Threads parked by EL1 with a switch to another thread.
    pub el1_parks: AtomicU64,
    /// Threads parked by the host (forwarded or timed waits).
    pub host_parks: AtomicU64,
    /// In-guest switches to a woken thread.
    pub el1_switches: AtomicU64,
    /// Threads EL1 woke onto its run queue.
    pub el1_wakes: AtomicU64,
    /// Threads the host woke.
    pub host_wakes: AtomicU64,
    /// Host claims of parked records, by [`Handback`] (index = raw value).
    pub host_claims: [AtomicU64; 8],
    /// Handbacks at an executor exit: records run in-guest (`Resumed`).
    pub reconcile_resumed: AtomicU64,
    /// Handbacks at an executor exit: woken records that had not run yet.
    pub reconcile_woken: AtomicU64,
    /// Host claims refused because EL1 held the record (a slot kick follows).
    pub el1_held_refusals: AtomicU64,
    /// Record or entry allocation failures.
    pub exhausted: AtomicU64,
    /// Threads EL1 woke onto ANOTHER vCPU slot's run queue (a cross-vCPU
    /// handoff).
    pub el1_cross_wakes: AtomicU64,
    /// Wake SGIs EL1 sent to a vCPU parked in WFI.
    pub el1_sgis: AtomicU64,
    /// Running threads EL1 preempted at a virtual-timer tick.
    pub el1_preemptions: AtomicU64,
    /// Queued threads EL1 moved to an idle vCPU slot at a tick.
    pub el1_migrations: AtomicU64,
    /// Timed waits EL1 ended at their deadline (ETIMEDOUT).
    pub el1_timeouts: AtomicU64,
    /// Times a vCPU slot went idle in EL1 (nothing runnable).
    pub el1_idle_entries: AtomicU64,
    /// WFIs an idle vCPU executed.
    pub el1_wfi_entries: AtomicU64,
    /// Idle vCPUs that left the guest for host work (a kick).
    pub el1_idle_exits: AtomicU64,
    /// Woken threads EL1 could not place where they belong, queued on the
    /// waker's slot, which then exits so the host places them.
    pub el1_misplaced: AtomicU64,
}

/// The zone: every table, as one `repr(C)` object in the shared EL1 region.
/// All-zero bytes are a valid empty zone.
#[repr(C, align(64))]
pub struct ZoneTables {
    buckets: [ZoneBucket; ZONE_BUCKETS],
    slots: [ZoneSlot; ZONE_SLOTS],
    record_map: [AtomicU64; ZONE_RECORDS / 64],
    entry_map: [AtomicU64; ZONE_ENTRIES / 64],
    pub counters: ZoneCounters,
    entries: [ZoneEntry; ZONE_ENTRIES],
    records: [ZoneRecord; ZONE_RECORDS],
}

/// How a bucket lock waits: EL1 gives up after a bounded spin (and forwards
/// the syscall); the host keeps trying, yielding its CPU.
pub trait LockWait {
    /// Called after the `attempt`-th failed acquisition; false gives up.
    fn wait(&self, attempt: u32) -> bool;
}

/// Spin at most `0` times, then give up.
pub struct BoundedSpin(pub u32);

impl LockWait for BoundedSpin {
    fn wait(&self, attempt: u32) -> bool {
        core::hint::spin_loop();
        attempt < self.0
    }
}

/// A held bucket lock.
pub struct BucketGuard<'a> {
    zone: &'a ZoneTables,
    bucket: usize,
}

impl Drop for BucketGuard<'_> {
    fn drop(&mut self) {
        self.zone.buckets[self.bucket]
            .lock
            .store(0, Ordering::Release);
    }
}

impl BucketGuard<'_> {
    pub fn bucket(&self) -> usize {
        self.bucket
    }
}

/// A wake would need a feature the caller's venue does not serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WakeRefusal {
    /// A matching waiter parks on several futexes (`futex_waitv`).
    MultiEntry,
    /// More waiters would wake than the slot's run queue can hold.
    RunQueueFull,
}

/// Who performs a wake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Waker {
    /// EL1 on `slot`: woken threads go to its run queue.
    El1 { slot: SlotId },
    /// The host: woken threads become [`Claim::Host`] with
    /// [`Handback::Woken`], for the caller to hand back.
    Host,
}

/// The outcome of a host claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostClaim {
    /// The host now owns the record (and every queue entry was unlinked).
    Claimed,
    /// EL1 on `slot` holds it; kick the slot, and its executor hands it back.
    El1Held { slot: SlotId },
    /// Another party already made it host-owned.
    AlreadyHost,
    /// The park named by the caller is over (`seq` mismatch), or the record
    /// is free or reused.
    Stale,
}

/// What [`ZoneTables::drain_slot`] found on a slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotDrain {
    /// Records handed back as woken (the first `woken` of the caller's buffer).
    pub woken: usize,
    /// Records of retired threads, host-owned for the caller to free.
    pub discarded: usize,
    /// The record EL1 switched in, if any.
    pub current: Option<RecordId>,
    /// The record of the host-loaded thread, if EL1 parked it.
    pub host_record: Option<RecordId>,
}

/// The outcome of [`ZoneTables::handback_current`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurrentHandback {
    /// Host-owned with [`Handback::Resumed`]: publish it to its thread.
    HandedBack,
    /// Its thread was retired: host-owned, for the caller to free.
    Discard,
    /// It was not the slot's switched-in record (a protocol violation).
    Lost,
}

/// A record and the incarnation that names one use of it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RecordRef {
    pub id: RecordId,
    pub incarnation: u64,
}

/// Allocation of a table index failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exhausted;

fn mix(mm: u64, uaddr: u64) -> usize {
    let mut h = mm.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (uaddr >> 2);
    h ^= h >> 29;
    h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= h >> 32;
    (h as usize) % ZONE_BUCKETS
}

impl ZoneTables {
    /// The bucket that `(mm, uaddr)` hashes to.
    pub fn bucket_of(mm: u64, uaddr: u64) -> usize {
        mix(mm, uaddr)
    }

    pub fn record(&self, id: RecordId) -> &ZoneRecord {
        &self.records[id.index()]
    }

    pub fn slot(&self, slot: SlotId) -> &ZoneSlot {
        &self.slots[slot.0 as usize]
    }

    /// A record reference for its current incarnation.
    pub fn record_ref(&self, id: RecordId) -> RecordRef {
        RecordRef {
            id,
            incarnation: self.record(id).incarnation(),
        }
    }

    /// The record `r` names, if that incarnation is still live.
    pub fn live(&self, r: RecordRef) -> Option<&ZoneRecord> {
        let record = self.record(r.id);
        (record.incarnation() == r.incarnation && record.claim() != Claim::Free).then_some(record)
    }

    /// Take the lock of `bucket`, waiting per `wait`.
    pub fn lock(&self, bucket: usize, wait: &impl LockWait) -> Option<BucketGuard<'_>> {
        let lock = &self.buckets[bucket % ZONE_BUCKETS].lock;
        let mut attempt = 0;
        loop {
            if lock
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(BucketGuard {
                    zone: self,
                    bucket: bucket % ZONE_BUCKETS,
                });
            }
            attempt += 1;
            if !wait.wait(attempt) {
                return None;
            }
        }
    }

    fn alloc_bit(map: &[AtomicU64], limit: usize) -> Option<u32> {
        for (word_index, word) in map.iter().enumerate() {
            let mut current = word.load(Ordering::Relaxed);
            loop {
                // Index 0 is reserved.
                let reserved = if word_index == 0 { 1 } else { 0 };
                let free = !(current | reserved);
                if free == 0 {
                    break;
                }
                let bit = free.trailing_zeros();
                let index = word_index * 64 + bit as usize;
                if index >= limit {
                    break;
                }
                match word.compare_exchange_weak(
                    current,
                    current | (1 << bit),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return u32::try_from(index).ok(),
                    Err(observed) => current = observed,
                }
            }
        }
        None
    }

    fn free_bit(map: &[AtomicU64], index: u32) {
        let word = index as usize / 64;
        if let Some(word) = map.get(word) {
            word.fetch_and(!(1 << (index % 64)), Ordering::AcqRel);
        }
    }

    /// Allocate a record for `identity`. It starts [`Claim::Free`] with a
    /// fresh incarnation; the allocator owns it until it publishes a park.
    pub fn alloc_record(&self, identity: ThreadIdentity) -> Result<RecordId, Exhausted> {
        let Some(id) = Self::alloc_bit(&self.record_map, ZONE_RECORDS).and_then(RecordId::from_raw)
        else {
            self.counters.exhausted.fetch_add(1, Ordering::Relaxed);
            return Err(Exhausted);
        };
        let record = self.record(id);
        record.incarnation.fetch_add(1, Ordering::AcqRel);
        record.set_identity(identity);
        record.result.store(0, Ordering::Relaxed);
        record.handback.store(0, Ordering::Relaxed);
        record.first_entry.store(NIL, Ordering::Relaxed);
        record.entry_count.store(0, Ordering::Relaxed);
        record.cancelled.store(0, Ordering::Relaxed);
        record.claim.store(Claim::Free.encode(), Ordering::Release);
        Ok(id)
    }

    /// Free a record its owner is done with (the host after loading it, or a
    /// party that allocated it and never published a park).
    pub fn free_record(&self, id: RecordId) {
        let record = self.record(id);
        record.claim.store(Claim::Free.encode(), Ordering::Release);
        record.incarnation.fetch_add(1, Ordering::AcqRel);
        Self::free_bit(&self.record_map, id.raw());
    }

    fn entry(&self, id: u32) -> &ZoneEntry {
        &self.entries[id as usize]
    }

    fn link_tail(&self, guard: &BucketGuard<'_>, entry_id: u32) {
        let bucket = &self.buckets[guard.bucket];
        let entry = self.entry(entry_id);
        let tail = bucket.tail.load(Ordering::Relaxed);
        entry.prev.store(tail, Ordering::Relaxed);
        entry.next.store(NIL, Ordering::Relaxed);
        entry.bucket.store(guard.bucket as u32, Ordering::Relaxed);
        if tail == NIL {
            bucket.head.store(entry_id, Ordering::Relaxed);
        } else {
            self.entry(tail).next.store(entry_id, Ordering::Relaxed);
        }
        bucket.tail.store(entry_id, Ordering::Relaxed);
        bucket.len.fetch_add(1, Ordering::Relaxed);
    }

    fn unlink(&self, guard: &BucketGuard<'_>, entry_id: u32) {
        let bucket = &self.buckets[guard.bucket];
        let entry = self.entry(entry_id);
        let prev = entry.prev.load(Ordering::Relaxed);
        let next = entry.next.load(Ordering::Relaxed);
        if prev == NIL {
            bucket.head.store(next, Ordering::Relaxed);
        } else {
            self.entry(prev).next.store(next, Ordering::Relaxed);
        }
        if next == NIL {
            bucket.tail.store(prev, Ordering::Relaxed);
        } else {
            self.entry(next).prev.store(prev, Ordering::Relaxed);
        }
        entry.prev.store(NIL, Ordering::Relaxed);
        entry.next.store(NIL, Ordering::Relaxed);
        bucket.len.fetch_sub(1, Ordering::Relaxed);
    }

    /// Queue `record` on `(mm, uaddr)` in the bucket `guard` holds (which
    /// must be `bucket_of(mm, uaddr)`), as entry `index` of the park `seq`.
    /// The caller publishes the park ([`Self::publish_park`]) after every
    /// entry is queued, still holding the lock(s).
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue(
        &self,
        guard: &BucketGuard<'_>,
        record: RecordId,
        seq: u32,
        mm: u64,
        uaddr: u64,
        bitset: u32,
        index: u32,
    ) -> Result<(), Exhausted> {
        let Some(entry_id) = Self::alloc_bit(&self.entry_map, ZONE_ENTRIES) else {
            self.counters.exhausted.fetch_add(1, Ordering::Relaxed);
            return Err(Exhausted);
        };
        let entry = self.entry(entry_id);
        entry.record.store(record.raw(), Ordering::Relaxed);
        entry.seq.store(seq, Ordering::Relaxed);
        entry.mm.store(mm, Ordering::Relaxed);
        entry.uaddr.store(uaddr, Ordering::Relaxed);
        entry.bitset.store(bitset, Ordering::Relaxed);
        entry.index.store(index, Ordering::Relaxed);
        let rec = self.record(record);
        entry
            .sibling
            .store(rec.first_entry.load(Ordering::Relaxed), Ordering::Relaxed);
        rec.first_entry.store(entry_id, Ordering::Relaxed);
        rec.entry_count.fetch_add(1, Ordering::Relaxed);
        self.link_tail(guard, entry_id);
        Ok(())
    }

    /// The sequence number of `record`'s next park.
    pub fn next_seq(&self, record: RecordId) -> u32 {
        let seq = self
            .record(record)
            .last_seq
            .load(Ordering::Relaxed)
            .wrapping_add(1);
        if seq == 0 { 1 } else { seq }
    }

    /// Publish `record` as parked (claimable) under park `seq`. The caller
    /// wrote the context and queued every entry, and still holds the lock of
    /// every bucket it queued on.
    pub fn publish_park(&self, record: RecordId, seq: u32) {
        let rec = self.record(record);
        rec.last_seq.store(seq, Ordering::Relaxed);
        rec.handback.store(0, Ordering::Relaxed);
        rec.claim
            .store(Claim::Parked { seq }.encode(), Ordering::Release);
    }

    /// Wake up to `count` waiters on `(mm, uaddr)` whose bitset intersects
    /// `bitset`, in queue order, under the lock `guard` holds. Returns the
    /// number woken and writes the woken records to `woken`.
    ///
    /// An EL1 waker is refused as a whole (nothing changes) if a waiter it
    /// would wake parks on several futexes, or if its run queue cannot hold
    /// them; it then forwards the syscall. A host waker wakes a `futex_waitv`
    /// park too: it must call [`Self::unlink_all`] for each woken record
    /// after releasing `guard`.
    #[allow(clippy::too_many_arguments)]
    pub fn wake(
        &self,
        guard: &BucketGuard<'_>,
        mm: u64,
        uaddr: u64,
        bitset: u32,
        count: u32,
        waker: Waker,
        woken: &mut [RecordId],
    ) -> Result<u32, WakeRefusal> {
        // An EL1 wake is all or nothing: it must wake every eligible waiter
        // up to `count` or refuse (the host then serves it), never return a
        // short count because its run queue or `woken` is smaller. A host
        // wake takes a batch of at most `woken.len()` and the caller loops.
        let limit = match waker {
            Waker::El1 { .. } => (count as usize).min(woken.len() + 1),
            Waker::Host => (count as usize).min(woken.len()),
        };
        let bucket = &self.buckets[guard.bucket];
        // First pass: decide without changing anything.
        let mut planned = 0usize;
        let mut cursor = bucket.head.load(Ordering::Relaxed);
        while cursor != NIL && planned < limit {
            let entry = self.entry(cursor);
            let next = entry.next.load(Ordering::Relaxed);
            if let Some(record) = self.eligible(entry, mm, uaddr, bitset) {
                if matches!(waker, Waker::El1 { .. }) && self.record(record).entry_count() != 1 {
                    return Err(WakeRefusal::MultiEntry);
                }
                planned += 1;
            }
            cursor = next;
        }
        if let Waker::El1 { slot } = waker
            && (planned > woken.len() || self.slot(slot).queued() + planned > ZONE_RUNQ_CAPACITY)
        {
            return Err(WakeRefusal::RunQueueFull);
        }
        // Second pass: claim. A record the host claimed meanwhile (a signal
        // or a timeout needs no bucket lock) is skipped, not counted.
        let mut done = 0usize;
        let mut cursor = bucket.head.load(Ordering::Relaxed);
        while cursor != NIL && done < planned {
            let entry = self.entry(cursor);
            let next = entry.next.load(Ordering::Relaxed);
            if let Some(record) = self.eligible(entry, mm, uaddr, bitset) {
                let rec = self.record(record);
                let seq = entry.seq.load(Ordering::Relaxed);
                let next_claim = match waker {
                    Waker::El1 { slot } => Claim::Queued { slot, seq },
                    Waker::Host => Claim::Host { seq },
                };
                if rec.cas(Claim::Parked { seq }, next_claim) {
                    rec.result.store(
                        u64::from(entry.index.load(Ordering::Relaxed)),
                        Ordering::Relaxed,
                    );
                    self.unlink(guard, cursor);
                    self.drop_entry(rec, cursor);
                    match waker {
                        Waker::El1 { slot } => {
                            self.push_runq(slot, record);
                            self.counters.el1_wakes.fetch_add(1, Ordering::Relaxed);
                        }
                        Waker::Host => {
                            rec.handback
                                .store(Handback::Woken as u32, Ordering::Release);
                            self.counters.host_wakes.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    woken[done] = record;
                    done += 1;
                }
            }
            cursor = next;
        }
        Ok(done as u32)
    }

    /// The record `entry` wakes for `(mm, uaddr, bitset)`, if it is a live
    /// park.
    fn eligible(&self, entry: &ZoneEntry, mm: u64, uaddr: u64, bitset: u32) -> Option<RecordId> {
        if entry.mm.load(Ordering::Relaxed) != mm
            || entry.uaddr.load(Ordering::Relaxed) != uaddr
            || entry.bitset.load(Ordering::Relaxed) & bitset == 0
        {
            return None;
        }
        let record = RecordId::from_raw(entry.record.load(Ordering::Relaxed))?;
        match self.record(record).claim() {
            Claim::Parked { seq } if seq == entry.seq.load(Ordering::Relaxed) => Some(record),
            _ => None,
        }
    }

    /// Remove `entry_id` from `rec`'s sibling chain and free it. The entry is
    /// already unlinked from its bucket.
    fn drop_entry(&self, rec: &ZoneRecord, entry_id: u32) {
        let mut link = &rec.first_entry;
        loop {
            let current = link.load(Ordering::Relaxed);
            if current == NIL {
                break;
            }
            if current == entry_id {
                link.store(
                    self.entry(entry_id).sibling.load(Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                rec.entry_count.fetch_sub(1, Ordering::Relaxed);
                break;
            }
            link = &self.entry(current).sibling;
        }
        self.entry(entry_id).record.store(NIL, Ordering::Relaxed);
        Self::free_bit(&self.entry_map, entry_id);
    }

    /// Unlink and free every queue entry of `record`, taking each entry's
    /// bucket lock in turn (with no other bucket lock held). Only the
    /// record's owner calls this: the host after a claim, or a parker undoing
    /// a park it never published.
    pub fn unlink_all(&self, record: RecordId, wait: &impl LockWait) {
        let rec = self.record(record);
        loop {
            let entry_id = rec.first_entry.load(Ordering::Acquire);
            if entry_id == NIL {
                return;
            }
            let bucket = self.entry(entry_id).bucket.load(Ordering::Relaxed) as usize;
            let Some(guard) = self.lock(bucket, wait) else {
                continue;
            };
            // Requeue may have moved it between reading and locking.
            if self.entry(entry_id).bucket.load(Ordering::Relaxed) as usize == guard.bucket {
                self.unlink(&guard, entry_id);
                self.drop_entry(rec, entry_id);
            }
        }
    }

    /// Move up to `count` live waiters of `(mm, from)` to `(mm, to)`, under
    /// both buckets' locks (the same guard twice when they share a bucket).
    /// Returns the number moved. Host only (EL1 forwards requeue).
    pub fn requeue(
        &self,
        from_guard: &BucketGuard<'_>,
        to_guard: &BucketGuard<'_>,
        mm: u64,
        from: u64,
        to: u64,
        count: u32,
    ) -> u32 {
        let bucket = &self.buckets[from_guard.bucket];
        let mut moved = 0;
        let mut cursor = bucket.head.load(Ordering::Relaxed);
        while cursor != NIL && moved < count {
            let entry = self.entry(cursor);
            let next = entry.next.load(Ordering::Relaxed);
            if self.eligible(entry, mm, from, u32::MAX).is_some() {
                self.unlink(from_guard, cursor);
                entry.uaddr.store(to, Ordering::Relaxed);
                self.link_tail(to_guard, cursor);
                moved += 1;
            }
            cursor = next;
        }
        moved
    }

    fn push_runq(&self, slot: SlotId, record: RecordId) {
        let s = self.slot(slot);
        let len = s.len.load(Ordering::Relaxed) as usize;
        if len < ZONE_RUNQ_CAPACITY {
            s.runq[len].store(record.raw(), Ordering::Relaxed);
            s.len.store(len as u32 + 1, Ordering::Release);
        }
    }

    /// Record the CNTVCT at which `slot`'s run queue became non-empty (EL1
    /// calls this after a wake that queued threads on an empty queue).
    pub fn note_queued_since(&self, slot: SlotId, cntvct: u64) {
        self.slot(slot)
            .queued_since
            .store(cntvct, Ordering::Release);
    }

    /// The oldest woken record on `slot`'s run queue, if it is still queued
    /// there (only that slot changes it, so it stays switchable until the
    /// slot's next [`Self::switch_in`]).
    pub fn runnable_head(&self, slot: SlotId) -> Option<RecordId> {
        let s = self.slot(slot);
        if s.len.load(Ordering::Acquire) == 0 {
            return None;
        }
        let record = RecordId::from_raw(s.runq[0].load(Ordering::Relaxed))?;
        let rec = self.record(record);
        (matches!(rec.claim(), Claim::Queued { slot: owner, .. } if owner == slot)
            && !rec.is_cancelled())
        .then_some(record)
    }

    /// EL1: take the oldest woken record off `slot`'s run queue and make it
    /// the running thread (`OnCpu`). The caller loads its context.
    pub fn switch_in(&self, slot: SlotId) -> Option<RecordId> {
        let s = self.slot(slot);
        let len = s.len.load(Ordering::Relaxed) as usize;
        if len == 0 {
            return None;
        }
        let first = s.runq[0].load(Ordering::Relaxed);
        for i in 1..len {
            s.runq[i - 1].store(s.runq[i].load(Ordering::Relaxed), Ordering::Relaxed);
        }
        s.len.store(len as u32 - 1, Ordering::Release);
        let record = RecordId::from_raw(first)?;
        let rec = self.record(record);
        let Claim::Queued { slot: owner, seq } = rec.claim() else {
            return None;
        };
        if owner != slot || !rec.cas(Claim::Queued { slot, seq }, Claim::OnCpu { slot, seq }) {
            return None;
        }
        s.current.store(record.raw(), Ordering::Release);
        self.counters.el1_switches.fetch_add(1, Ordering::Relaxed);
        Some(record)
    }

    /// EL1: the record the running thread parks into. The host-loaded thread
    /// (no record switched in) gets a new one for `identity`; a switched-in
    /// thread parks back into its own.
    pub fn current_or_new(
        &self,
        slot: SlotId,
        identity: ThreadIdentity,
    ) -> Result<RecordId, Exhausted> {
        match self.slot(slot).current() {
            Some(record) => Ok(record),
            None => {
                let record = self.alloc_record(identity)?;
                self.slot(slot)
                    .host_record
                    .store(record.raw(), Ordering::Release);
                Ok(record)
            }
        }
    }

    /// EL1: the running thread on `slot` parked (its record is published);
    /// nothing is switched in until [`Self::switch_in`].
    pub fn clear_current(&self, slot: SlotId) {
        self.slot(slot).current.store(NIL, Ordering::Release);
    }

    /// The executor of `slot`, at an exit (vCPU stopped): take everything EL1
    /// did on the slot since it last ran it. Every woken record still queued
    /// becomes host-owned with [`Handback::Woken`] (written to `woken`), or,
    /// if the host retired its thread meanwhile, [`Handback::Cancelled`]
    /// (written to `discarded`, for the caller to free). The switched-in
    /// record, if any, is left for the caller, which captures its live state
    /// and calls [`Self::handback_current`], or, if it is the thread the
    /// executor loaded, [`Self::release_current`].
    pub fn drain_slot(
        &self,
        slot: SlotId,
        woken: &mut [RecordId],
        discarded: &mut [RecordId],
    ) -> SlotDrain {
        let s = self.slot(slot);
        let len = (s.len.load(Ordering::Acquire) as usize).min(ZONE_RUNQ_CAPACITY);
        let mut drain = SlotDrain {
            woken: 0,
            discarded: 0,
            current: s.current(),
            host_record: s.host_record(),
        };
        for i in 0..len {
            let Some(record) = RecordId::from_raw(s.runq[i].load(Ordering::Relaxed)) else {
                continue;
            };
            let rec = self.record(record);
            let Claim::Queued { slot: owner, seq } = rec.claim() else {
                continue;
            };
            if owner != slot || !rec.cas(Claim::Queued { slot, seq }, Claim::Host { seq }) {
                continue;
            }
            if rec.is_cancelled() {
                rec.handback
                    .store(Handback::Cancelled as u32, Ordering::Release);
                if drain.discarded < discarded.len() {
                    discarded[drain.discarded] = record;
                    drain.discarded += 1;
                }
                continue;
            }
            rec.handback
                .store(Handback::Woken as u32, Ordering::Release);
            self.counters
                .reconcile_woken
                .fetch_add(1, Ordering::Relaxed);
            if drain.woken < woken.len() {
                woken[drain.woken] = record;
                drain.woken += 1;
            }
        }
        s.len.store(0, Ordering::Release);
        drain
    }

    /// Hand the switched-in record of `slot` back to the host after the
    /// caller captured its live context into it.
    pub fn handback_current(&self, slot: SlotId, record: RecordId) -> CurrentHandback {
        let rec = self.record(record);
        let s = self.slot(slot);
        s.current.store(NIL, Ordering::Release);
        let Claim::OnCpu { slot: owner, seq } = rec.claim() else {
            return CurrentHandback::Lost;
        };
        if owner != slot || !rec.cas(Claim::OnCpu { slot, seq }, Claim::Host { seq }) {
            return CurrentHandback::Lost;
        }
        if rec.is_cancelled() {
            rec.handback
                .store(Handback::Cancelled as u32, Ordering::Release);
            return CurrentHandback::Discard;
        }
        rec.handback
            .store(Handback::Resumed as u32, Ordering::Release);
        self.counters
            .reconcile_resumed
            .fetch_add(1, Ordering::Relaxed);
        CurrentHandback::HandedBack
    }

    /// The switched-in record of `slot` is the thread the executor loaded:
    /// it is simply running again, so its record is done.
    pub fn release_current(&self, slot: SlotId, record: RecordId) {
        let s = self.slot(slot);
        s.current.store(NIL, Ordering::Release);
        if s.host_record.load(Ordering::Acquire) == record.raw() {
            s.host_record.store(NIL, Ordering::Release);
        }
        if matches!(self.record(record).claim(), Claim::OnCpu { slot: owner, .. } if owner == slot)
        {
            self.free_record(record);
        }
    }

    /// Reset `slot` when the host loads a thread on it (nothing switched in,
    /// nothing queued). Anything left is a protocol violation the caller
    /// reports.
    pub fn reset_slot(&self, slot: SlotId) -> bool {
        let s = self.slot(slot);
        let clean = s.current.load(Ordering::Acquire) == NIL && s.len.load(Ordering::Acquire) == 0;
        s.current.store(NIL, Ordering::Release);
        s.len.store(0, Ordering::Release);
        s.host_record.store(NIL, Ordering::Release);
        clean
    }

    /// The host takes `r` for `kind` (a signal, a timeout, a control wake or
    /// a cancellation). With `seq`, only that park may be claimed (a timeout
    /// belongs to the park that armed it). On success every queue entry is
    /// unlinked before this returns.
    pub fn claim_for_host(
        &self,
        r: RecordRef,
        seq: Option<u32>,
        kind: Handback,
        wait: &impl LockWait,
    ) -> HostClaim {
        let Some(rec) = self.live(r) else {
            return HostClaim::Stale;
        };
        loop {
            let claim = rec.claim();
            match claim {
                Claim::Parked { seq: current } => {
                    if seq.is_some_and(|wanted| wanted != current) {
                        return HostClaim::Stale;
                    }
                    if rec.cas(claim, Claim::Host { seq: current }) {
                        rec.handback.store(kind as u32, Ordering::Release);
                        self.unlink_all(r.id, wait);
                        if let Some(counter) = self.counters.host_claims.get(kind as usize) {
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        return HostClaim::Claimed;
                    }
                }
                Claim::Queued { slot, .. } | Claim::OnCpu { slot, .. } => {
                    self.counters
                        .el1_held_refusals
                        .fetch_add(1, Ordering::Relaxed);
                    return HostClaim::El1Held { slot };
                }
                Claim::Host { .. } => return HostClaim::AlreadyHost,
                Claim::Free => return HostClaim::Stale,
            }
            if rec.incarnation() != r.incarnation {
                return HostClaim::Stale;
            }
        }
    }
}

#[cfg(test)]
mod tests;
