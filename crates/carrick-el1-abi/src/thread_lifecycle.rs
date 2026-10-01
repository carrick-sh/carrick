//! Born-in-zone thread lifecycle ABI (stage L2 of
//! `docs/superpowers/plans/2026-09-30-el1-thread-lifecycle.md`).
//!
//! This module only defines the shared records; the kernel, runtime and EL1
//! personality consume it in later stages.
//!
//! * [`ThreadLifecyclePage`]: one per process, kernel-only (EL1-RW, no EL0
//!   mapping). A gate word, the live-thread count, the shared pending-signal
//!   summary and a fixed pool of [`PoolEntry`] identities with a typed atomic
//!   state machine. Placement is per process, so it is allocated by the
//!   owner of the process's EL1 metadata, not at a fixed region offset.
//! * [`ThreadControlSlot`]: one per thread, reached from the zone record. The
//!   blocked mask, the `sigaltstack` record and the robust-list head.
//!
//! # State machine
//!
//! ```text
//! Vacant/Reaped/Revoked --stock--> Reserved --claim--> Claimed --record_born--> Born
//! Reserved --revoke--> Revoked          Born --publish--> Published
//! Born|Published --exit_in_zone--> ExitedInZone --reap--> Reaped
//! ```
//!
//! Every transition is a compare-and-swap of the whole state word, which
//! packs a 56-bit generation above the 8-bit state. `stock` bumps the
//! generation, so a stale [`EntryRef`] (ABA) fails every transition. Payload
//! fields are relaxed atomics published by the release CAS that follows their
//! store and observed after the acquire CAS that precedes their load.
//!
//! # Dekker pairs (memory ordering)
//!
//! Two store-then-load pairs need a total order, because acquire/release
//! alone permits both sides to miss each other's store:
//!
//! 1. Signal delivery vs `rt_sigprocmask`: the sender does
//!    `pending |= bit; read blocked`, the masker does
//!    `blocked = new; read pending`. With all four operations `SeqCst`,
//!    either the sender sees the new mask (so it is unblocked and the sender
//!    delivers) or the masker sees the pending bit (so it serves with work).
//!    Both cannot miss. The API is [`PendingSummary::post_then_read_blocked`]
//!    and [`ThreadControlSlot::store_blocked_then_read_pending`]: the store
//!    and the load are one method, so a caller cannot reorder or weaken them.
//! 2. Clone claim vs fork gate: the claimer CASes `Reserved -> Claimed` then
//!    reads the gate; a forker stores `ForkClosing` then scans for `Claimed`.
//!    All `SeqCst`. A claimer that sees a closed gate backs out inside
//!    [`ThreadLifecyclePage::claim`], so the forker only ever waits on a
//!    window that cannot block.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

/// Protocol revision, folded into [`crate::EL1_ABI_LAYOUT_HASH`].
pub const THREAD_LIFECYCLE_PROTOCOL_VERSION: u64 = 2;

/// Pool entries per process: a task holds up to four identities ahead of use.
pub const THREAD_POOL_ENTRIES: usize = 8;

/// Bytes of one lifecycle page.
pub const THREAD_LIFECYCLE_PAGE_SIZE: usize = 4096;

/// Life stage of a pool entry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    /// Never stocked (initial).
    Vacant = 0,
    /// Being stocked by the kernel; identity fields are not yet valid.
    Stocking = 1,
    /// Identity issued, unclaimed.
    Reserved = 2,
    /// An EL1 clone owns it and is filling in the Born record.
    Claimed = 3,
    /// Child exists; the host has not yet observed it.
    Born = 4,
    /// The host settled the birth.
    Published = 5,
    /// The thread exited in the zone; the host has not yet folded the exit.
    ExitedInZone = 6,
    /// The host folded the exit; the identity is free to restock.
    Reaped = 7,
    /// Withdrawn before use.
    Revoked = 8,
}

impl EntryState {
    const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Stocking,
            2 => Self::Reserved,
            3 => Self::Claimed,
            4 => Self::Born,
            5 => Self::Published,
            6 => Self::ExitedInZone,
            7 => Self::Reaped,
            8 => Self::Revoked,
            _ => Self::Vacant,
        }
    }
}

const fn pack(generation: u64, state: EntryState) -> u64 {
    (generation << 8) | state as u64
}
const fn unpack(word: u64) -> (u64, EntryState) {
    (word >> 8, EntryState::from_raw(word as u8))
}

/// Why a transition was refused. `observed` is the state (or generation)
/// found instead; nothing was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    /// The entry was not in a state this transition starts from.
    WrongState(EntryState),
    /// The entry was recycled since the reference was taken (ABA).
    StaleGeneration,
    /// The gate was not open; the claim was backed out.
    GateClosed(GateState),
    /// The index is outside the pool.
    NoSuchEntry,
    /// No entry is `Reserved` ([`ThreadLifecyclePage::claim_any`]).
    PoolEmpty,
}

/// A reference to one incarnation of one entry. Copyable: it proves nothing
/// by itself, every transition re-validates the generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryRef {
    index: u32,
    generation: u64,
}
impl EntryRef {
    pub const fn index(self) -> usize {
        self.index as usize
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// One word for a [`ThreadControlSlot`]: never 0, since a stocked entry's
    /// generation is at least 1.
    const fn pack(self) -> u64 {
        (self.generation << 8) | self.index as u64
    }
    const fn unpack(word: u64) -> Option<Self> {
        if word == 0 {
            return None;
        }
        Some(Self {
            index: (word & 0xff) as u32,
            generation: word >> 8,
        })
    }
}

/// Proof of a successful claim. Not `Copy`/`Clone`: [`ThreadLifecyclePage::record_born`]
/// consumes it, so a claim is completed at most once.
#[derive(Debug, PartialEq, Eq)]
pub struct ClaimedEntry(EntryRef);
impl ClaimedEntry {
    pub const fn entry(&self) -> EntryRef {
        self.0
    }
}

/// The identity the kernel issues into an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryIdentity {
    /// Reserved namespace-independent tid.
    pub tid: u32,
    /// The visible (namespace) tid.
    pub visible_tid: u32,
    /// `ThreadKey` serial the child will carry.
    pub thread_serial: u64,
    /// RLIMIT_NPROC credit held for the owning uid.
    pub uid_credit: u64,
}

/// Written by the claimant between claim and `Born`. Creds, blocked mask and
/// affinity bind at claim (director ruling 2), so the mask is captured here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BornRecord {
    /// Caller's `TaskKey` (task id word).
    pub caller_task: u64,
    /// Caller's `ThreadKey` serial.
    pub caller_serial: u64,
    pub clone_flags: u64,
    /// `clear_child_tid` address (0 = none).
    pub clear_child_tid: u64,
    /// Blocked mask captured at claim.
    pub blocked: BlockedMask,
}

/// Signal blocked mask (bit `n-1` is signal `n`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct BlockedMask(pub u64);
/// Set of pending signals (bit `n-1` is signal `n`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct PendingSignals(pub u64);

/// A pool entry: state word plus payload.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct PoolEntry {
    state: AtomicU64,
    tid: AtomicU32,
    visible_tid: AtomicU32,
    thread_serial: AtomicU64,
    uid_credit: AtomicU64,
    caller_task: AtomicU64,
    caller_serial: AtomicU64,
    clone_flags: AtomicU64,
    clear_child_tid: AtomicU64,
    blocked: AtomicU64,
}

impl PoolEntry {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(pack(0, EntryState::Vacant)),
            tid: AtomicU32::new(0),
            visible_tid: AtomicU32::new(0),
            thread_serial: AtomicU64::new(0),
            uid_credit: AtomicU64::new(0),
            caller_task: AtomicU64::new(0),
            caller_serial: AtomicU64::new(0),
            clone_flags: AtomicU64::new(0),
            clear_child_tid: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
        }
    }
}

/// Fork/exec gate for EL1 lifecycle serving.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateState {
    Open = 0,
    /// A fork transaction is settling claims; new claims back out.
    ForkClosing = 1,
    /// Terminal for this page: exec, tracer, seccomp or opt-out. A new page
    /// is stocked for the next incarnation.
    Closed = 2,
}
impl GateState {
    const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Open,
            1 => Self::ForkClosing,
            _ => Self::Closed,
        }
    }
}

/// `try_exit` refusal: the last live thread never exits in the zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastThread;

/// The shared pending-signal summary of the process.
#[repr(transparent)]
#[derive(Debug)]
pub struct PendingSummary(AtomicU64);

impl PendingSummary {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
    /// Sender half of the Dekker pair: publish `bits`, then read the target's
    /// blocked mask. Returns the mask; a signal not in it must be delivered
    /// by the sender. Both operations are `SeqCst`.
    #[must_use]
    pub fn post_then_read_blocked(
        &self,
        bits: PendingSignals,
        target: &ThreadControlSlot,
    ) -> BlockedMask {
        self.0.fetch_or(bits.0, Ordering::SeqCst);
        BlockedMask(target.blocked.load(Ordering::SeqCst))
    }
    /// Consume `bits` (delivery). Monotone clear, `SeqCst`.
    pub fn clear(&self, bits: PendingSignals) {
        self.0.fetch_and(!bits.0, Ordering::SeqCst);
    }
    /// Observe the summary. Not the second half of a Dekker pair; use only
    /// where no mask store precedes it.
    pub fn load(&self) -> PendingSignals {
        PendingSignals(self.0.load(Ordering::SeqCst))
    }
}
impl Default for PendingSummary {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of a thread's `sigaltstack`. Size 0 is the disabled stack
/// (zeroed storage, and what `SS_DISABLE` stores): an enabled one is at least
/// `MINSIGSTKSZ` bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AltStack {
    pub sp: u64,
    pub size: u64,
    pub flags: u32,
}
impl AltStack {
    /// No alternate stack.
    pub const DISABLED: Self = Self {
        sp: 0,
        size: 0,
        flags: 0,
    };
    pub const fn is_disabled(&self) -> bool {
        self.size == 0
    }
}

/// Per-thread control state served at EL1. Single writer per field: the
/// owning thread writes `blocked` (`store_blocked_then_read_pending`) and the
/// altstack/robust record; other threads and the host only read (senders read
/// `blocked` through [`PendingSummary::post_then_read_blocked`]).
#[repr(C, align(64))]
#[derive(Debug)]
pub struct ThreadControlSlot {
    blocked: AtomicU64,
    /// Even = stable, odd = write in progress.
    alt_seq: AtomicU64,
    alt_sp: AtomicU64,
    alt_size: AtomicU64,
    alt_flags: AtomicU32,
    robust_len: AtomicU32,
    robust_head: AtomicU64,
    /// `clear_child_tid` (`CLONE_CHILD_CLEARTID`, `set_tid_address`); 0 = none.
    clear_child_tid: AtomicU64,
    /// The pool entry this thread was born into ([`EntryRef::pack`]); 0 for
    /// a thread that holds none (the leader).
    entry: AtomicU64,
}

impl ThreadControlSlot {
    pub const fn new() -> Self {
        Self {
            blocked: AtomicU64::new(0),
            alt_seq: AtomicU64::new(0),
            alt_sp: AtomicU64::new(0),
            alt_size: AtomicU64::new(0),
            alt_flags: AtomicU32::new(0),
            robust_len: AtomicU32::new(0),
            robust_head: AtomicU64::new(0),
            clear_child_tid: AtomicU64::new(0),
            entry: AtomicU64::new(0),
        }
    }

    /// Initialise the slot of a thread about to be born into `entry`, before
    /// it is visible (nothing else reads the slot of a thread not yet Born):
    /// the mask captured at claim, no alternate stack and no robust list
    /// (`clone(2)` with `CLONE_VM` clears both), its `clear_child_tid`.
    pub fn reset_for_birth(&self, blocked: BlockedMask, clear_child_tid: u64, entry: EntryRef) {
        self.blocked.store(blocked.0, Ordering::Relaxed);
        // Keep the sequence even: a stale odd value would wedge readers.
        let seq = self.alt_seq.load(Ordering::Relaxed);
        self.alt_seq
            .store(seq.wrapping_add(seq & 1), Ordering::Relaxed);
        self.alt_sp.store(0, Ordering::Relaxed);
        self.alt_size.store(0, Ordering::Relaxed);
        self.alt_flags.store(0, Ordering::Relaxed);
        self.robust_head.store(0, Ordering::Relaxed);
        self.robust_len.store(0, Ordering::Relaxed);
        self.clear_child_tid
            .store(clear_child_tid, Ordering::Relaxed);
        self.entry.store(entry.pack(), Ordering::Release);
    }

    /// The pool entry the thread holds, if any.
    pub fn entry(&self) -> Option<EntryRef> {
        EntryRef::unpack(self.entry.load(Ordering::Acquire))
    }

    /// The thread's `clear_child_tid` address (0 = none).
    pub fn clear_child_tid(&self) -> u64 {
        self.clear_child_tid.load(Ordering::Acquire)
    }

    /// Owner-written `clear_child_tid` (`set_tid_address(2)`).
    pub fn set_clear_child_tid(&self, address: u64) {
        self.clear_child_tid.store(address, Ordering::Release);
    }

    /// Masker half of the Dekker pair: install `new`, then read the shared
    /// pending summary. Returns `(old mask, pending)`. If any pending bit is
    /// not in `new`, the caller must serve with work. `SeqCst` on both.
    #[must_use]
    pub fn store_blocked_then_read_pending(
        &self,
        new: BlockedMask,
        pending: &PendingSummary,
    ) -> (BlockedMask, PendingSignals) {
        let old = self.blocked.swap(new.0, Ordering::SeqCst);
        (
            BlockedMask(old),
            PendingSignals(pending.0.load(Ordering::SeqCst)),
        )
    }

    /// Plain read of the mask (no ordering pair): the owner's own view, or
    /// diagnostics.
    pub fn blocked(&self) -> BlockedMask {
        BlockedMask(self.blocked.load(Ordering::Relaxed))
    }

    /// Seed the mask before the thread is visible (claim time). No pending
    /// read is needed because nothing can target a thread not yet Born.
    pub fn init_blocked(&self, mask: BlockedMask) {
        self.blocked.store(mask.0, Ordering::Release);
    }

    /// Seqlock write. Only the owning thread may call this; concurrent
    /// writers would corrupt the sequence.
    pub fn write_altstack(&self, value: AltStack) {
        let seq = self.alt_seq.load(Ordering::Relaxed);
        debug_assert!(seq & 1 == 0, "single writer: sequence must be even");
        self.alt_seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.alt_sp.store(value.sp, Ordering::Relaxed);
        self.alt_size.store(value.size, Ordering::Relaxed);
        self.alt_flags.store(value.flags, Ordering::Relaxed);
        self.alt_seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    /// Seqlock read: retries while a write is in flight or tore the read.
    pub fn read_altstack(&self) -> AltStack {
        loop {
            let before = self.alt_seq.load(Ordering::Acquire);
            if before & 1 == 1 {
                core::hint::spin_loop();
                continue;
            }
            let value = AltStack {
                sp: self.alt_sp.load(Ordering::Relaxed),
                size: self.alt_size.load(Ordering::Relaxed),
                flags: self.alt_flags.load(Ordering::Relaxed),
            };
            fence(Ordering::Acquire);
            if self.alt_seq.load(Ordering::Relaxed) == before {
                return value;
            }
            core::hint::spin_loop();
        }
    }

    /// Owner-written robust list registration `(head, len)`.
    pub fn set_robust_list(&self, head: u64, len: u32) {
        self.robust_head.store(head, Ordering::Relaxed);
        self.robust_len.store(len, Ordering::Release);
    }
    /// `(head, len)`; read by the owner or by the exit walker after the
    /// owner has stopped.
    pub fn robust_list(&self) -> (u64, u32) {
        let len = self.robust_len.load(Ordering::Acquire);
        (self.robust_head.load(Ordering::Relaxed), len)
    }
}
impl Default for ThreadControlSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// One per process; kernel-only.
#[repr(C, align(4096))]
#[derive(Debug)]
pub struct ThreadLifecyclePage {
    gate: AtomicU32,
    live: AtomicU32,
    pending: PendingSummary,
    entries: [PoolEntry; THREAD_POOL_ENTRIES],
    /// [`LifecycleHatches`] bits, fixed when the page is built.
    serving: AtomicU32,
}

const _: () = assert!(core::mem::size_of::<ThreadLifecyclePage>() == THREAD_LIFECYCLE_PAGE_SIZE);

/// Environment names of the EL1 lifecycle opt-out hatches.
pub const EL1_THREADS_HATCH_ENV: &str = "CARRICK_EL1_THREADS";
pub const EL1_SIGMASK_HATCH_ENV: &str = "CARRICK_EL1_SIGMASK";

/// Which EL1 lifecycle services a page allows. Both are on by default;
/// `CARRICK_EL1_THREADS=0` stops EL1 serving clone and exit,
/// `CARRICK_EL1_SIGMASK=0` stops it serving `rt_sigprocmask`,
/// `sigaltstack` and `set_robust_list`. The host reads each variable once
/// ([`Self::from_lookup`]) and builds every page with the result, so EL1 and
/// the host decide from the same bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleHatches {
    pub threads: bool,
    pub sigmask: bool,
}

const SERVING_THREADS: u32 = 1;
const SERVING_SIGMASK: u32 = 2;

impl LifecycleHatches {
    pub const ON: Self = Self {
        threads: true,
        sigmask: true,
    };

    /// Consult `lookup` once per hatch variable; exactly `0` (trimmed)
    /// disables that service, anything else (or unset) leaves it on.
    pub fn from_lookup<S: AsRef<str>>(mut lookup: impl FnMut(&str) -> Option<S>) -> Self {
        let mut on = |name: &str| lookup(name).is_none_or(|value| value.as_ref().trim() != "0");
        Self {
            threads: on(EL1_THREADS_HATCH_ENV),
            sigmask: on(EL1_SIGMASK_HATCH_ENV),
        }
    }

    const fn bits(self) -> u32 {
        (if self.threads { SERVING_THREADS } else { 0 })
            | (if self.sigmask { SERVING_SIGMASK } else { 0 })
    }
}
const _: () = assert!(core::mem::size_of::<ThreadControlSlot>() == 64);
const _: () = assert!(core::mem::size_of::<PoolEntry>() == 80);

impl ThreadLifecyclePage {
    /// A page with an open gate, one live thread (the leader), an empty
    /// pool and every service on.
    pub const fn new() -> Self {
        Self::with_hatches(LifecycleHatches::ON)
    }

    /// [`Self::new`] with the services `hatches` allows.
    pub const fn with_hatches(hatches: LifecycleHatches) -> Self {
        Self {
            gate: AtomicU32::new(GateState::Open as u32),
            live: AtomicU32::new(1),
            pending: PendingSummary::new(),
            entries: [const { PoolEntry::new() }; THREAD_POOL_ENTRIES],
            serving: AtomicU32::new(hatches.bits()),
        }
    }

    /// Whether EL1 may serve clone and exit (`CARRICK_EL1_THREADS`).
    pub fn serves_threads(&self) -> bool {
        self.serving.load(Ordering::Relaxed) & SERVING_THREADS != 0
    }

    /// Whether EL1 may serve the per-thread setup calls
    /// (`CARRICK_EL1_SIGMASK`).
    pub fn serves_sigmask(&self) -> bool {
        self.serving.load(Ordering::Relaxed) & SERVING_SIGMASK != 0
    }

    pub fn pending(&self) -> &PendingSummary {
        &self.pending
    }

    // ---- gate ----

    pub fn gate(&self) -> GateState {
        GateState::from_raw(self.gate.load(Ordering::SeqCst))
    }
    /// Fork begins: `Open -> ForkClosing`. New claims back out from here on.
    pub fn close_for_fork(&self) -> Result<(), GateState> {
        self.gate
            .compare_exchange(
                GateState::Open as u32,
                GateState::ForkClosing as u32,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(|_| ())
            .map_err(GateState::from_raw)
    }
    /// Fork committed: `ForkClosing -> Open`.
    pub fn reopen_after_fork(&self) -> Result<(), GateState> {
        self.gate
            .compare_exchange(
                GateState::ForkClosing as u32,
                GateState::Open as u32,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(|_| ())
            .map_err(GateState::from_raw)
    }
    /// Terminal close (exec, tracer, seccomp, opt-out), from any state.
    pub fn close(&self) {
        self.gate.store(GateState::Closed as u32, Ordering::SeqCst);
    }
    /// Entries currently `Claimed`: what a forker waits to drain after
    /// `close_for_fork`. `SeqCst` scan (second half of the claim/gate pair).
    pub fn claimed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| unpack(e.state.load(Ordering::SeqCst)).1 == EntryState::Claimed)
            .count()
    }

    // ---- live count ----

    pub fn live(&self) -> u32 {
        self.live.load(Ordering::SeqCst)
    }
    /// A thread was born: `n -> n+1`. Returns the new count, `None` on
    /// overflow.
    pub fn thread_born(&self) -> Option<u32> {
        self.live
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .ok()
            .map(|n| n + 1)
    }
    /// CAS `n > 1 -> n - 1`; refuses at 1 (the last thread exits on the
    /// host). Returns the new count.
    pub fn try_exit(&self) -> Result<u32, LastThread> {
        self.live
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n > 1 { Some(n - 1) } else { None }
            })
            .map(|n| n - 1)
            .map_err(|_| LastThread)
    }

    // ---- pool ----

    fn entry(&self, index: usize) -> Result<&PoolEntry, TransitionError> {
        self.entries.get(index).ok_or(TransitionError::NoSuchEntry)
    }

    /// Current state and generation of `index`.
    pub fn state(&self, index: usize) -> Option<(u64, EntryState)> {
        self.entries
            .get(index)
            .map(|e| unpack(e.state.load(Ordering::Acquire)))
    }

    fn transition(
        &self,
        r: EntryRef,
        from: &[EntryState],
        to: EntryState,
        order: Ordering,
    ) -> Result<(), TransitionError> {
        let e = self.entry(r.index())?;
        let cur = e.state.load(Ordering::Acquire);
        let (generation, state) = unpack(cur);
        if generation != r.generation {
            return Err(TransitionError::StaleGeneration);
        }
        if !from.contains(&state) {
            return Err(TransitionError::WrongState(state));
        }
        match e
            .state
            .compare_exchange(cur, pack(generation, to), order, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(now) => {
                let (g, s) = unpack(now);
                if g != r.generation {
                    Err(TransitionError::StaleGeneration)
                } else {
                    Err(TransitionError::WrongState(s))
                }
            }
        }
    }

    /// Kernel: issue `identity` into a `Vacant`, `Reaped` or `Revoked` entry,
    /// bumping the generation. Returns the reference to the new incarnation.
    pub fn stock(
        &self,
        index: usize,
        identity: EntryIdentity,
    ) -> Result<EntryRef, TransitionError> {
        let e = self.entry(index)?;
        let cur = e.state.load(Ordering::Acquire);
        let (generation, state) = unpack(cur);
        if !matches!(
            state,
            EntryState::Vacant | EntryState::Reaped | EntryState::Revoked
        ) {
            return Err(TransitionError::WrongState(state));
        }
        let next = generation + 1;
        e.state
            .compare_exchange(
                cur,
                pack(next, EntryState::Stocking),
                Ordering::Acquire,
                Ordering::Acquire,
            )
            .map_err(|now| TransitionError::WrongState(unpack(now).1))?;
        e.tid.store(identity.tid, Ordering::Relaxed);
        e.visible_tid.store(identity.visible_tid, Ordering::Relaxed);
        e.thread_serial
            .store(identity.thread_serial, Ordering::Relaxed);
        e.uid_credit.store(identity.uid_credit, Ordering::Relaxed);
        e.state
            .store(pack(next, EntryState::Reserved), Ordering::Release);
        Ok(EntryRef {
            index: index as u32,
            generation: next,
        })
    }

    /// EL1 clone: CAS `Reserved -> Claimed`, then check the gate (Dekker with
    /// [`Self::close_for_fork`]). A closed gate backs the claim out.
    pub fn claim(&self, r: EntryRef) -> Result<ClaimedEntry, TransitionError> {
        self.transition(
            r,
            &[EntryState::Reserved],
            EntryState::Claimed,
            Ordering::SeqCst,
        )?;
        let gate = GateState::from_raw(self.gate.load(Ordering::SeqCst));
        if gate != GateState::Open {
            // We own the entry (Claimed): only we can move it, so this
            // store cannot race another transition.
            let e = &self.entries[r.index()];
            e.state
                .store(pack(r.generation, EntryState::Reserved), Ordering::SeqCst);
            return Err(TransitionError::GateClosed(gate));
        }
        Ok(ClaimedEntry(r))
    }

    /// EL1 clone: claim the first `Reserved` entry ([`Self::claim`]).
    /// `GateClosed` as soon as the gate refuses a claim; `PoolEmpty` when no
    /// entry could be claimed (another claimant may have won each one).
    pub fn claim_any(&self) -> Result<ClaimedEntry, TransitionError> {
        for (index, e) in self.entries.iter().enumerate() {
            let (generation, state) = unpack(e.state.load(Ordering::Acquire));
            if state != EntryState::Reserved {
                continue;
            }
            let r = EntryRef {
                index: index as u32,
                generation,
            };
            match self.claim(r) {
                Ok(claimed) => return Ok(claimed),
                Err(closed @ TransitionError::GateClosed(_)) => return Err(closed),
                Err(_) => {}
            }
        }
        Err(TransitionError::PoolEmpty)
    }

    /// EL1 clone backs out after a successful claim (the child could not be
    /// created): `Claimed -> Reserved`, the identity unused and still issued.
    pub fn unclaim(&self, claim: ClaimedEntry) -> Result<EntryRef, TransitionError> {
        let r = claim.0;
        self.transition(
            r,
            &[EntryState::Claimed],
            EntryState::Reserved,
            Ordering::SeqCst,
        )?;
        Ok(r)
    }

    /// Kernel: withdraw an unused entry, `Reserved -> Revoked`. Loses to a
    /// concurrent claim.
    pub fn revoke(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::Reserved],
            EntryState::Revoked,
            Ordering::SeqCst,
        )
    }

    /// EL1 clone: record the Born payload and move `Claimed -> Born`.
    pub fn record_born(
        &self,
        claim: ClaimedEntry,
        record: BornRecord,
    ) -> Result<EntryRef, TransitionError> {
        let r = claim.0;
        let e = self.entry(r.index())?;
        e.caller_task.store(record.caller_task, Ordering::Relaxed);
        e.caller_serial
            .store(record.caller_serial, Ordering::Relaxed);
        e.clone_flags.store(record.clone_flags, Ordering::Relaxed);
        e.clear_child_tid
            .store(record.clear_child_tid, Ordering::Relaxed);
        e.blocked.store(record.blocked.0, Ordering::Relaxed);
        self.transition(
            r,
            &[EntryState::Claimed],
            EntryState::Born,
            Ordering::Release,
        )?;
        Ok(r)
    }

    /// Host settle: `Born -> Published`.
    pub fn publish(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::Born],
            EntryState::Published,
            Ordering::AcqRel,
        )
    }

    /// The thread exited in the zone: `Born | Published -> ExitedInZone`.
    pub fn exit_in_zone(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::Born, EntryState::Published],
            EntryState::ExitedInZone,
            Ordering::AcqRel,
        )
    }

    /// Host settle folded the exit: `ExitedInZone -> Reaped`.
    pub fn reap(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::ExitedInZone],
            EntryState::Reaped,
            Ordering::AcqRel,
        )
    }

    /// Identity of a reference, read after an acquire of its state. `None` if
    /// the reference is stale or the entry is not past `Stocking`.
    pub fn identity(&self, r: EntryRef) -> Option<EntryIdentity> {
        let e = self.entries.get(r.index())?;
        let (generation, state) = unpack(e.state.load(Ordering::Acquire));
        if generation != r.generation || matches!(state, EntryState::Vacant | EntryState::Stocking)
        {
            return None;
        }
        Some(EntryIdentity {
            tid: e.tid.load(Ordering::Relaxed),
            visible_tid: e.visible_tid.load(Ordering::Relaxed),
            thread_serial: e.thread_serial.load(Ordering::Relaxed),
            uid_credit: e.uid_credit.load(Ordering::Relaxed),
        })
    }

    /// Born record of a `Born`, `Published`, `ExitedInZone` or `Reaped`
    /// incarnation. `None` for any other state or a stale reference.
    pub fn born_record(&self, r: EntryRef) -> Option<BornRecord> {
        let e = self.entries.get(r.index())?;
        let (generation, state) = unpack(e.state.load(Ordering::Acquire));
        if generation != r.generation
            || !matches!(
                state,
                EntryState::Born
                    | EntryState::Published
                    | EntryState::ExitedInZone
                    | EntryState::Reaped
            )
        {
            return None;
        }
        Some(BornRecord {
            caller_task: e.caller_task.load(Ordering::Relaxed),
            caller_serial: e.caller_serial.load(Ordering::Relaxed),
            clone_flags: e.clone_flags.load(Ordering::Relaxed),
            clear_child_tid: e.clear_child_tid.load(Ordering::Relaxed),
            blocked: BlockedMask(e.blocked.load(Ordering::Relaxed)),
        })
    }
}
impl Default for ThreadLifecyclePage {
    fn default() -> Self {
        Self::new()
    }
}

/// Layout facts folded into [`crate::EL1_ABI_LAYOUT_HASH`].
pub const THREAD_LIFECYCLE_LAYOUT_FACTS: [u64; 15] = [
    THREAD_LIFECYCLE_PROTOCOL_VERSION,
    THREAD_POOL_ENTRIES as u64,
    core::mem::size_of::<ThreadLifecyclePage>() as u64,
    core::mem::align_of::<ThreadLifecyclePage>() as u64,
    core::mem::offset_of!(ThreadLifecyclePage, gate) as u64,
    core::mem::offset_of!(ThreadLifecyclePage, live) as u64,
    core::mem::offset_of!(ThreadLifecyclePage, pending) as u64,
    core::mem::offset_of!(ThreadLifecyclePage, entries) as u64,
    core::mem::size_of::<PoolEntry>() as u64,
    core::mem::size_of::<ThreadControlSlot>() as u64,
    core::mem::offset_of!(ThreadControlSlot, alt_seq) as u64,
    core::mem::offset_of!(ThreadControlSlot, robust_head) as u64,
    core::mem::offset_of!(ThreadControlSlot, clear_child_tid) as u64,
    core::mem::offset_of!(ThreadControlSlot, entry) as u64,
    core::mem::offset_of!(ThreadLifecyclePage, serving) as u64,
];

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;
    use std::vec::Vec;

    fn ident(n: u32) -> EntryIdentity {
        EntryIdentity {
            tid: n,
            visible_tid: n + 100,
            thread_serial: n as u64 + 1000,
            uid_credit: 1,
        }
    }
    fn born(mask: u64) -> BornRecord {
        BornRecord {
            caller_task: 7,
            caller_serial: 9,
            clone_flags: 0x3d0f00,
            clear_child_tid: 0x1000,
            blocked: BlockedMask(mask),
        }
    }
    fn st(p: &ThreadLifecyclePage, i: usize) -> EntryState {
        p.state(i).unwrap().1
    }

    #[test]
    fn legal_path_and_payload() {
        let p = ThreadLifecyclePage::new();
        assert_eq!(st(&p, 0), EntryState::Vacant);
        let r = p.stock(0, ident(5)).unwrap();
        assert_eq!(st(&p, 0), EntryState::Reserved);
        assert_eq!(p.identity(r), Some(ident(5)));
        assert!(p.born_record(r).is_none());
        let c = p.claim(r).unwrap();
        assert_eq!(st(&p, 0), EntryState::Claimed);
        assert_eq!(p.claimed_count(), 1);
        let r = p.record_born(c, born(0xff)).unwrap();
        assert_eq!(st(&p, 0), EntryState::Born);
        assert_eq!(p.born_record(r), Some(born(0xff)));
        p.publish(r).unwrap();
        p.exit_in_zone(r).unwrap();
        p.reap(r).unwrap();
        assert_eq!(st(&p, 0), EntryState::Reaped);
        // Restock bumps the generation; the old reference is dead.
        let r2 = p.stock(0, ident(6)).unwrap();
        assert_eq!(r2.generation(), r.generation() + 1);
        assert_eq!(p.claim(r), Err(TransitionError::StaleGeneration));
        assert!(p.identity(r).is_none());
    }

    #[test]
    fn born_may_exit_before_settle() {
        let p = ThreadLifecyclePage::new();
        let r = p.stock(1, ident(1)).unwrap();
        let r = p.record_born(p.claim(r).unwrap(), born(0)).unwrap();
        p.exit_in_zone(r).unwrap();
        p.reap(r).unwrap();
    }

    #[test]
    fn illegal_transitions_are_refused() {
        let p = ThreadLifecyclePage::new();
        let r = p.stock(0, ident(1)).unwrap();
        // From Reserved: only claim and revoke are legal.
        assert_eq!(
            p.publish(r),
            Err(TransitionError::WrongState(EntryState::Reserved))
        );
        assert_eq!(
            p.exit_in_zone(r),
            Err(TransitionError::WrongState(EntryState::Reserved))
        );
        assert_eq!(
            p.reap(r),
            Err(TransitionError::WrongState(EntryState::Reserved))
        );
        assert_eq!(
            p.stock(0, ident(2)),
            Err(TransitionError::WrongState(EntryState::Reserved))
        );
        let c = p.claim(r).unwrap();
        // Claimed: no second claim, no revoke, no publish.
        assert_eq!(
            p.claim(r),
            Err(TransitionError::WrongState(EntryState::Claimed))
        );
        assert_eq!(
            p.revoke(r),
            Err(TransitionError::WrongState(EntryState::Claimed))
        );
        assert_eq!(
            p.publish(r),
            Err(TransitionError::WrongState(EntryState::Claimed))
        );
        let r = p.record_born(c, born(0)).unwrap();
        // Born: cannot claim, revoke, reap.
        assert_eq!(
            p.claim(r),
            Err(TransitionError::WrongState(EntryState::Born))
        );
        assert_eq!(
            p.revoke(r),
            Err(TransitionError::WrongState(EntryState::Born))
        );
        assert_eq!(
            p.reap(r),
            Err(TransitionError::WrongState(EntryState::Born))
        );
        p.publish(r).unwrap();
        assert_eq!(
            p.publish(r),
            Err(TransitionError::WrongState(EntryState::Published))
        );
        assert_eq!(
            p.reap(r),
            Err(TransitionError::WrongState(EntryState::Published))
        );
        p.exit_in_zone(r).unwrap();
        assert_eq!(
            p.exit_in_zone(r),
            Err(TransitionError::WrongState(EntryState::ExitedInZone))
        );
        assert_eq!(
            p.publish(r),
            Err(TransitionError::WrongState(EntryState::ExitedInZone))
        );
        p.reap(r).unwrap();
        assert_eq!(
            p.reap(r),
            Err(TransitionError::WrongState(EntryState::Reaped))
        );
        // Revoked is terminal until restocked.
        let r = p.stock(0, ident(3)).unwrap();
        p.revoke(r).unwrap();
        assert_eq!(
            p.claim(r),
            Err(TransitionError::WrongState(EntryState::Revoked))
        );
        assert_eq!(
            p.revoke(r),
            Err(TransitionError::WrongState(EntryState::Revoked))
        );
        assert!(p.stock(0, ident(4)).is_ok());
        assert_eq!(
            p.claim(EntryRef {
                index: 99,
                generation: 1
            }),
            Err(TransitionError::NoSuchEntry)
        );
    }

    #[test]
    fn gate_backs_out_claims() {
        let p = ThreadLifecyclePage::new();
        let r = p.stock(0, ident(1)).unwrap();
        p.close_for_fork().unwrap();
        assert_eq!(p.close_for_fork(), Err(GateState::ForkClosing));
        assert_eq!(
            p.claim(r),
            Err(TransitionError::GateClosed(GateState::ForkClosing))
        );
        assert_eq!(st(&p, 0), EntryState::Reserved);
        assert_eq!(p.claimed_count(), 0);
        p.reopen_after_fork().unwrap();
        let c = p.claim(r).unwrap();
        p.close();
        assert_eq!(p.gate(), GateState::Closed);
        assert_eq!(p.reopen_after_fork(), Err(GateState::Closed));
        p.record_born(c, born(0)).unwrap();
    }

    #[test]
    fn claim_vs_revoke_has_one_winner() {
        for _ in 0..2000 {
            let p = Arc::new(ThreadLifecyclePage::new());
            let r = p.stock(0, ident(1)).unwrap();
            let gate = Arc::new(Barrier::new(2));
            let (p1, g1) = (p.clone(), gate.clone());
            let claimer = thread::spawn(move || {
                g1.wait();
                p1.claim(r).is_ok()
            });
            let (p2, g2) = (p.clone(), gate);
            let revoker = thread::spawn(move || {
                g2.wait();
                p2.revoke(r).is_ok()
            });
            let (c, v) = (claimer.join().unwrap(), revoker.join().unwrap());
            assert!(
                c ^ v,
                "exactly one of claim/revoke wins (claim={c}, revoke={v})"
            );
            assert_eq!(
                st(&p, 0),
                if c {
                    EntryState::Claimed
                } else {
                    EntryState::Revoked
                }
            );
        }
    }

    #[test]
    fn many_claimers_one_winner() {
        let p = Arc::new(ThreadLifecyclePage::new());
        let r = p.stock(0, ident(1)).unwrap();
        let gate = Arc::new(Barrier::new(8));
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let (p, g) = (p.clone(), gate.clone());
                thread::spawn(move || {
                    g.wait();
                    p.claim(r).is_ok()
                })
            })
            .collect();
        let winners = hs.into_iter().filter(|_| true).map(|h| h.join().unwrap());
        assert_eq!(winners.filter(|won| *won).count(), 1);
    }

    #[test]
    fn try_exit_refuses_at_one() {
        let p = ThreadLifecyclePage::new();
        assert_eq!(p.live(), 1);
        assert_eq!(p.try_exit(), Err(LastThread));
        assert_eq!(p.thread_born(), Some(2));
        assert_eq!(p.thread_born(), Some(3));
        assert_eq!(p.try_exit(), Ok(2));
        assert_eq!(p.try_exit(), Ok(1));
        assert_eq!(p.try_exit(), Err(LastThread));
        assert_eq!(p.live(), 1);
    }

    #[test]
    fn try_exit_concurrent_never_reaches_zero() {
        let p = Arc::new(ThreadLifecyclePage::new());
        for _ in 0..15 {
            p.thread_born().unwrap();
        }
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let p = p.clone();
                thread::spawn(move || (0..10).filter(|_| p.try_exit().is_ok()).count())
            })
            .collect();
        let ok: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(ok, 15);
        assert_eq!(p.live(), 1);
    }

    #[test]
    fn altstack_seqlock_never_tears() {
        let s = Arc::new(ThreadControlSlot::new());
        let stop = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let (s, stop) = (s.clone(), stop.clone());
                thread::spawn(move || {
                    let mut n = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let v = s.read_altstack();
                        assert_eq!(v.sp, v.size, "torn read");
                        assert_eq!(v.flags as u64, v.sp & 0xffff_ffff, "torn read");
                        n += 1;
                    }
                    n
                })
            })
            .collect();
        for i in 1..=200_000u64 {
            s.write_altstack(AltStack {
                sp: i,
                size: i,
                flags: i as u32,
            });
        }
        stop.store(true, Ordering::Relaxed);
        for r in readers {
            r.join().unwrap();
        }
        assert_eq!(s.read_altstack().sp, 200_000);
    }

    #[test]
    fn claim_any_takes_a_reserved_entry_and_unclaim_returns_it() {
        let p = ThreadLifecyclePage::new();
        assert_eq!(p.claim_any(), Err(TransitionError::PoolEmpty));
        let r0 = p.stock(0, ident(1)).unwrap();
        let r3 = p.stock(3, ident(4)).unwrap();
        let c = p.claim_any().unwrap();
        assert_eq!(c.entry(), r0);
        let c2 = p.claim_any().unwrap();
        assert_eq!(c2.entry(), r3);
        assert_eq!(p.claim_any(), Err(TransitionError::PoolEmpty));
        // Backing out keeps the identity issued, same incarnation.
        assert_eq!(p.unclaim(c), Ok(r0));
        assert_eq!(st(&p, 0), EntryState::Reserved);
        assert_eq!(p.identity(r0), Some(ident(1)));
        assert_eq!(p.claim_any().map(|c| c.entry()), Ok(r0));
        // A closed gate refuses without consuming anything.
        p.record_born(c2, born(0)).unwrap();
        let r5 = p.stock(5, ident(6)).unwrap();
        p.close_for_fork().unwrap();
        assert_eq!(
            p.claim_any(),
            Err(TransitionError::GateClosed(GateState::ForkClosing))
        );
        assert_eq!(p.state(5).unwrap().1, EntryState::Reserved);
        p.reopen_after_fork().unwrap();
        assert_eq!(p.claim_any().map(|c| c.entry()), Ok(r5));
    }

    #[test]
    fn birth_resets_the_slot_and_names_the_entry() {
        let p = ThreadLifecyclePage::new();
        let r = p.stock(2, ident(3)).unwrap();
        let s = ThreadControlSlot::new();
        assert_eq!(s.entry(), None);
        s.set_robust_list(0x5000, 24);
        s.write_altstack(AltStack {
            sp: 0x9000,
            size: 0x4000,
            flags: 0,
        });
        s.init_blocked(BlockedMask(0xff));
        s.reset_for_birth(BlockedMask(0x10), 0x7000, r);
        assert_eq!(s.entry(), Some(r));
        assert_eq!(s.blocked(), BlockedMask(0x10));
        assert_eq!(s.robust_list(), (0, 0));
        assert!(s.read_altstack().is_disabled());
        assert_eq!(s.clear_child_tid(), 0x7000);
        s.set_clear_child_tid(0);
        assert_eq!(s.clear_child_tid(), 0);
    }

    #[test]
    fn hatches_read_each_variable_once_and_only_zero_disables() {
        let mut seen = Vec::new();
        let h = LifecycleHatches::from_lookup(|name: &str| {
            seen.push(std::string::String::from(name));
            (name == EL1_SIGMASK_HATCH_ENV).then_some("0")
        });
        assert_eq!(
            h,
            LifecycleHatches {
                threads: true,
                sigmask: false
            }
        );
        assert_eq!(seen, [EL1_THREADS_HATCH_ENV, EL1_SIGMASK_HATCH_ENV]);
        let h = LifecycleHatches::from_lookup(|name: &str| {
            (name == EL1_THREADS_HATCH_ENV).then_some("1")
        });
        assert_eq!(h, LifecycleHatches::ON);
        let p = ThreadLifecyclePage::with_hatches(LifecycleHatches {
            threads: false,
            sigmask: true,
        });
        assert!(!p.serves_threads());
        assert!(p.serves_sigmask());
        assert!(ThreadLifecyclePage::new().serves_threads());
    }

    #[test]
    fn lifecycle_hatches_require_an_exact_zero() {
        for value in ["", "1", "false", "00", " 0", "0 ", "\t0\n"] {
            assert_eq!(
                LifecycleHatches::from_lookup(|_| Some(value)),
                LifecycleHatches::ON,
                "only the exact string 0 disables lifecycle serving: {value:?}"
            );
        }
        assert_eq!(
            LifecycleHatches::from_lookup(|_| Some("0")),
            LifecycleHatches {
                threads: false,
                sigmask: false
            }
        );
    }

    #[test]
    fn robust_list_roundtrip() {
        let s = ThreadControlSlot::new();
        assert_eq!(s.robust_list(), (0, 0));
        s.set_robust_list(0xdead_0000, 24);
        assert_eq!(s.robust_list(), (0xdead_0000, 24));
    }

    #[test]
    fn dekker_pair_loses_no_pending_observation() {
        const ROUNDS: usize = 50_000;
        const SIG: u64 = 1 << 9;
        let page = Arc::new(ThreadLifecyclePage::new());
        let slot = Arc::new(ThreadControlSlot::new());
        slot.init_blocked(BlockedMask(SIG));
        let start = Arc::new(Barrier::new(2));
        let end = Arc::new(Barrier::new(2));
        // Sender: post SIG, read the mask. Between rounds only the sender
        // resets state, while the masker waits at `start`.
        let sender = {
            let (page, slot, start, end) = (page.clone(), slot.clone(), start.clone(), end.clone());
            thread::spawn(move || {
                let mut saw_blocked = Vec::with_capacity(ROUNDS);
                for _ in 0..ROUNDS {
                    start.wait();
                    let blocked = page
                        .pending()
                        .post_then_read_blocked(PendingSignals(SIG), &slot);
                    saw_blocked.push(blocked.0 & SIG != 0);
                    end.wait();
                    page.pending().clear(PendingSignals(SIG));
                    slot.init_blocked(BlockedMask(SIG));
                }
                saw_blocked
            })
        };
        // Masker: unblock SIG, read pending.
        let masker = {
            let (page, slot, start, end) = (page.clone(), slot.clone(), start.clone(), end.clone());
            thread::spawn(move || {
                let mut saw_pending = Vec::with_capacity(ROUNDS);
                for _ in 0..ROUNDS {
                    start.wait();
                    let (_old, pend) =
                        slot.store_blocked_then_read_pending(BlockedMask(0), page.pending());
                    saw_pending.push(pend.0 & SIG != 0);
                    end.wait();
                }
                saw_pending
            })
        };
        let (sender, masker) = (sender.join().unwrap(), masker.join().unwrap());
        // A lost wakeup is: the sender saw SIG still blocked (so it leaves
        // the signal pending) AND the masker did not see it pending (so it
        // does not deliver). SeqCst on both sides forbids that.
        let lost = sender
            .iter()
            .zip(&masker)
            .filter(|(sender_saw_blocked, masker_saw_pending)| {
                **sender_saw_blocked && !**masker_saw_pending
            })
            .count();
        assert_eq!(lost, 0, "lost pending observations in {ROUNDS} rounds");
    }
}
