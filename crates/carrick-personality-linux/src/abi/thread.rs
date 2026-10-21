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
//! Born|Published --begin_exit--> ExitingBorn|ExitingPublished
//! ExitingBorn|ExitingPublished --commit--> ExitedInZone --reap--> Reaped
//! ExitingBorn --publish--> ExitingPublished (drop rolls back either exit state)
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

/// Protocol revision, folded into the image ABI layout hash.
pub const THREAD_LIFECYCLE_PROTOCOL_VERSION: u64 = 18;

pub use carrick_core::lifecycle::{ClaimedEntry, ExitAdmission, Lifecycle, MemberControlCustody};
pub use carrick_core_abi::lifecycle::*;

/// Pool entries per process: a task holds up to four identities ahead of use.
pub const THREAD_POOL_ENTRIES: usize = 8;

/// Why a lifecycle service leaves its unchanged syscall to the host.
#[repr(usize)]
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum LifecycleDecline {
    ExitDisabled,
    ExitGate,
    ExitNoEntry,
    ExitEntryState,
    ExitRobust,
    ExitPending,
    ExitNoCurrent,
    ExitNoMm,
    ExitHome,
    ExitClaim,
    ExitHostWork,
    ExitCancelled,
    ExitObjectOperation,
    ExitIdentity,
    ExitAdmission,
    ExitLast,
    ExitClearTidCopyout,
    ExitClearTidWake,
    ExitVenue,
    ExitScheduler,
    ExitDispatchHostWork,
    CloneDispatchHostWork,
    ClonePoolEmpty,
    ExitHostAdopted,
}

impl LifecycleDecline {
    pub const COUNT: usize = Self::ExitHostAdopted as usize + 1;
    pub const ALL: [Self; Self::COUNT] = [
        Self::ExitDisabled,
        Self::ExitGate,
        Self::ExitNoEntry,
        Self::ExitEntryState,
        Self::ExitRobust,
        Self::ExitPending,
        Self::ExitNoCurrent,
        Self::ExitNoMm,
        Self::ExitHome,
        Self::ExitClaim,
        Self::ExitHostWork,
        Self::ExitCancelled,
        Self::ExitObjectOperation,
        Self::ExitIdentity,
        Self::ExitAdmission,
        Self::ExitLast,
        Self::ExitClearTidCopyout,
        Self::ExitClearTidWake,
        Self::ExitVenue,
        Self::ExitScheduler,
        Self::ExitDispatchHostWork,
        Self::CloneDispatchHostWork,
        Self::ClonePoolEmpty,
        Self::ExitHostAdopted,
    ];
}

/// Bytes of one lifecycle page.
pub const THREAD_LIFECYCLE_PAGE_SIZE: usize = 4096;

/// The identity the kernel issues into an entry.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct EntryIdentity {
    /// Reserved namespace-independent tid.
    pub tid: u32,
    /// The visible (namespace) tid.
    pub visible_tid: u32,
    /// `ThreadKey` serial the child will carry.
    pub thread_serial: u64,
    /// Process incarnation this exact pool identity is born into.
    pub birth: carrick_core_abi::entry::BirthSerial,
    /// RLIMIT_NPROC credit held for the owning uid.
    pub uid_credit: u64,
}

/// Written by the claimant between claim and `Born`. Creds, blocked mask and
/// affinity bind at claim (director ruling 2), so the mask is captured here.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
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
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
#[repr(transparent)]
pub struct BlockedMask(pub u64);
/// Set of pending signals (bit `n-1` is signal `n`).
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
#[repr(transparent)]
pub struct PendingSignals(pub u64);

/// A pool entry: state word plus payload.
#[repr(C, align(16))]
#[derive(::core::fmt::Debug)]
pub struct PoolEntry {
    state: AtomicEntry,
    tid: AtomicU32,
    visible_tid: AtomicU32,
    thread_serial: AtomicU64,
    uid_credit: AtomicU64,
    caller_task: AtomicU64,
    caller_serial: AtomicU64,
    clone_flags: AtomicU64,
    clear_child_tid: AtomicU64,
    blocked: AtomicU64,
    birth: carrick_core_abi::entry::AtomicBirthSerial,
}

impl PoolEntry {
    const fn new() -> Self {
        Self {
            state: AtomicEntry::new(pack(0, EntryState::Vacant)),
            tid: AtomicU32::new(0),
            visible_tid: AtomicU32::new(0),
            thread_serial: AtomicU64::new(0),
            uid_credit: AtomicU64::new(0),
            caller_task: AtomicU64::new(0),
            caller_serial: AtomicU64::new(0),
            clone_flags: AtomicU64::new(0),
            clear_child_tid: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            birth: carrick_core_abi::entry::AtomicBirthSerial::new(),
        }
    }
}

/// The shared pending-signal summary of the process.
#[repr(transparent)]
#[derive(::core::fmt::Debug)]
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
    /// Publish the exact summary while the queue's owner holds its mutation lock.
    pub fn replace_from_locked_queue(&self, pending: PendingSignals) {
        self.0.store(pending.0, Ordering::SeqCst);
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

/// Read-only pending state, derived from the independently locked queues.
/// A reader cannot acquire either queue's publication authority through this view.
#[derive(::core::clone::Clone, ::core::marker::Copy)]
pub struct PendingRead<'a> {
    carrier: &'a PendingSummary,
    native: Option<&'a PendingSummary>,
}
impl PendingRead<'_> {
    pub fn load(&self) -> PendingSignals {
        PendingSignals(self.carrier.load().0 | self.native.map_or(0, |pending| pending.load().0))
    }
}
impl<'a> From<&'a PendingSummary> for PendingRead<'a> {
    fn from(carrier: &'a PendingSummary) -> Self {
        Self {
            carrier,
            native: None,
        }
    }
}

/// Native signal custody alone can publish the native queue's projection.
/// The retained exact incarnation excludes slot reset until this writer drops.
/// Admission is exclusive even across independently retained controls.
///
/// Moving the writer transfers custody; it cannot duplicate custody.
/// ```compile_fail,E0382
/// use carrick_personality_linux::abi::thread::NativePendingCustody;
/// fn duplicate(writer: NativePendingCustody<'_>) {
///     let first = writer;
///     let second = writer;
///     drop((first, second));
/// }
/// ```
/// Nor can a writer be cloned.
/// ```compile_fail,E0599
/// use carrick_personality_linux::abi::thread::NativePendingCustody;
/// fn duplicate(writer: NativePendingCustody<'_>) {
///     let second = writer.clone();
/// }
/// ```
pub struct NativePendingCustody<'a> {
    control: ::alloc::sync::Arc<MemberControlCustody<'a, ThreadControlSlot>>,
}
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct NativePendingAlreadyAdmitted;

impl<'a> NativePendingCustody<'a> {
    pub fn try_admit(
        control: ::alloc::sync::Arc<MemberControlCustody<'a, ThreadControlSlot>>,
    ) -> Result<Self, NativePendingAlreadyAdmitted> {
        control
            .control()
            .native_pending_writer
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| NativePendingAlreadyAdmitted)?;
        Ok(Self { control })
    }
    pub fn replace_from_locked_queue(&self, pending: PendingSignals) {
        self.control
            .control()
            .native_pending
            .replace_from_locked_queue(pending);
    }
}
impl Drop for NativePendingCustody<'_> {
    fn drop(&mut self) {
        let control = self.control.control();
        control
            .native_pending
            .replace_from_locked_queue(PendingSignals(0));
        control.native_pending_writer.store(0, Ordering::Release);
    }
}

/// Snapshot of a thread's `sigaltstack`. Size 0 is the disabled stack
/// (zeroed storage, and what `SS_DISABLE` stores): an enabled one is at least
/// `MINSIGSTKSZ` bytes.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
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

/// The protocol states of the shared `ThreadControlSlot::clear_child_tid`
/// word (#685). EL1 and the host read and write the word only through
/// [`ClearChildTidState::encode`] and [`ClearChildTidState::decode`].
///
/// Encoding: `0` is [`Self::None`]; a user address `a` is
/// [`Self::Pending`]; `a | CLEARED_IN_ZONE` is [`Self::ClearedInZone`]: an
/// in-zone exit already cleared and woke `a`, then declined the rest of the
/// exit, so no lane may clear or wake it again.
///
/// The tag is bit 63. No address a guest thread can clear has it: user
/// addresses lie below [`Self::USER_ADDRESS_LIMIT`] (2^48 covers the
/// AArch64 48-bit TTBR0 range carrick configures and the x86_64 4-level
/// lower half, 2^47; the hosts' `UserVaCeiling`s are checked against it in
/// carrick-kernel). An address at or above the limit is not a user address:
/// Linux's exit-time clear of it faults and wakes nobody, and carrick has no
/// tagged-address ABI (`PR_SET_TAGGED_ADDR_CTRL`), so it is stored as
/// [`Self::None`].
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub enum ClearChildTidState {
    None,
    Pending(carrick_guest_arch::UserVa),
    ClearedInZone(carrick_guest_arch::UserVa),
}

// No user address can carry the `ClearedInZone` tag.
const _: () = assert!(
    ClearChildTidState::USER_ADDRESS_LIMIT <= ClearChildTidState::CLEARED_IN_ZONE
        && ClearChildTidState::USER_ADDRESS_LIMIT.is_power_of_two()
);

impl ClearChildTidState {
    /// Exclusive bound of any user address either guest ISA can name.
    pub const USER_ADDRESS_LIMIT: u64 = 1 << 48;
    const CLEARED_IN_ZONE: u64 = 1 << 63;

    /// The state `set_tid_address(address)` (or `CLONE_CHILD_CLEARTID`)
    /// leaves.
    pub const fn for_user_address(address: u64) -> Self {
        if address == 0 || address >= Self::USER_ADDRESS_LIMIT {
            Self::None
        } else {
            Self::Pending(carrick_guest_arch::UserVa::new(address))
        }
    }

    pub const fn encode(self) -> u64 {
        match self {
            Self::None => 0,
            Self::Pending(address) => address.raw(),
            Self::ClearedInZone(address) => address.raw() | Self::CLEARED_IN_ZONE,
        }
    }

    pub const fn decode(word: u64) -> Self {
        let address = word & !Self::CLEARED_IN_ZONE;
        if address == 0 || address >= Self::USER_ADDRESS_LIMIT {
            Self::None
        } else if word & Self::CLEARED_IN_ZONE != 0 {
            Self::ClearedInZone(carrick_guest_arch::UserVa::new(address))
        } else {
            Self::Pending(carrick_guest_arch::UserVa::new(address))
        }
    }

    /// The address an exit must still clear and wake.
    pub const fn pending(self) -> Option<carrick_guest_arch::UserVa> {
        match self {
            Self::Pending(address) => Some(address),
            Self::None | Self::ClearedInZone(_) => None,
        }
    }
}

/// Per-thread control state served at EL1. Single writer per field: the
/// owning thread writes `blocked` (`store_blocked_then_read_pending`) and the
/// altstack/robust record; other threads and the host only read (senders read
/// `blocked` through [`PendingSummary::post_then_read_blocked`]).
#[repr(C, align(64))]
#[derive(::core::fmt::Debug)]
pub struct ThreadControlSlot {
    /// Namespace-visible identity, published before this incarnation is runnable.
    visible_tid: AtomicU32,
    blocked: AtomicU64,
    /// A forwarded temporary wait mask is restored by the native checkpoint.
    forwarded_saved_mask: AtomicU64,
    forwarded_mask_armed: AtomicU32,
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
    pending: PendingSummary,
    /// Owner-published exact zone record. Readers make one bounded attempt;
    /// an in-flight publication is absent, never a mixed incarnation.
    zone_seq: AtomicU64,
    zone_incarnation: AtomicU64,
    zone_id: AtomicU32,
    /// Exit request/receipt bits plus the core-owned exact member exit kind.
    /// The slot's `entry` is the generation key until exclusive reset.
    host_exit_requested: carrick_core::lifecycle::MemberControlAuthority,
    /// Host retirement's receipt, distinct from the birth identity below:
    /// task/birth first, thread last. A Closing owner only credits a
    /// complete receipt that acknowledges the identity it requested.
    retired_task: AtomicU64,
    retired_birth: carrick_core_abi::entry::AtomicBirthSerial,
    retired_thread: AtomicU64,
    /// The thread's exact birth identity, written once before the thread can
    /// run (task/birth first, thread last). Retirement never writes it.
    birth_task: AtomicU64,
    birth_serial: carrick_core_abi::entry::AtomicBirthSerial,
    birth_thread: AtomicU64,
    /// Signals whose current action (`SIG_IGN` or default-ignore) cannot
    /// interrupt a blocking wait on this thread.
    non_interrupting: AtomicU64,
    native_pending: PendingSummary,
    native_pending_writer: AtomicU32,
    /// The exact thread's sole affinity authority, shared by ring and host.
    affinity: carrick_core::affinity::AffinityAuthority,
    // Allocation aliases survive reset; the carrier pins both mappings before
    // publishing this control to EL1. Never dereference the other venue's VA.
    affinity_host_alias: AtomicU64,
    affinity_guest_alias: AtomicU64,
}

/// Quiescent initialization was attempted on a live execution authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AffinitySeedRefused;

impl ThreadControlSlot {
    pub fn affinity(&self) -> carrick_core::affinity::CpuAffinity {
        carrick_core::affinity::CpuAffinity::from_words(&[self.affinity.load()])
    }
    /// Seed exclusively retained pre-birth storage; live writes must use
    /// change_affinity so residency notification cannot be omitted.
    pub fn set_affinity(
        &self,
        mask: carrick_core::affinity::CpuAffinity,
    ) -> Result<(), AffinitySeedRefused> {
        self.affinity
            .initialize_quiescent(mask.words()[0])
            .then_some(())
            .ok_or(AffinitySeedRefused)
    }
    pub fn change_affinity(
        &self,
        mask: carrick_core::affinity::CpuAffinity,
        notifier: &mut impl carrick_core::affinity::AffinityNotifier,
    ) {
        self.affinity.change(mask.words()[0], notifier);
    }
    pub fn affinity_authority(&self) -> &carrick_core::affinity::AffinityAuthority {
        &self.affinity
    }
    pub fn initialize_affinity(&self, mask: carrick_core::affinity::CpuAffinity) {
        self.affinity.initialize(mask.words()[0]);
    }
    /// The carrier has mapped this host control allocation into EL1.
    /// # Safety
    /// `guest_control` must alias this retained control for the complete
    /// lifetime of every scheduler source published from it.
    pub unsafe fn publish_affinity_aliases(&self, guest_control: carrick_guest_arch::GuestVa) {
        let host = core::ptr::from_ref(&self.affinity).expose_provenance() as u64;
        let guest = guest_control.raw() + core::mem::offset_of!(Self, affinity) as u64;
        self.affinity_host_alias.store(host, Ordering::Relaxed);
        self.affinity_guest_alias.store(guest, Ordering::Release);
    }
    pub fn affinity_source(&self) -> carrick_sched_core::affinity_source::AffinitySource {
        let guest = self.affinity_guest_alias.load(Ordering::Acquire);
        let host = self.affinity_host_alias.load(Ordering::Relaxed);
        #[cfg(not(target_os = "none"))]
        let host = if host == 0 {
            core::ptr::from_ref(&self.affinity).expose_provenance() as u64
        } else {
            host
        };
        // SAFETY: every scheduler publication retains this exact control's
        // allocation until its record/slot is retired. The host-only form
        // cannot be offered to guest scheduling before mapping publication.
        unsafe { carrick_sched_core::affinity_source::AffinitySource::from_aliases(host, guest) }
    }

    pub fn recorded_exit_kind(
        &self,
        entry: Option<EntryRef>,
    ) -> carrick_core::lifecycle::MemberExitKind {
        carrick_core::lifecycle::recorded_member_exit_kind(self, entry)
    }

    pub const fn new() -> Self {
        Self {
            affinity: carrick_core::affinity::AffinityAuthority::new(),
            affinity_host_alias: AtomicU64::new(0),
            affinity_guest_alias: AtomicU64::new(0),
            visible_tid: AtomicU32::new(0),
            blocked: AtomicU64::new(0),
            forwarded_saved_mask: AtomicU64::new(0),
            forwarded_mask_armed: AtomicU32::new(0),
            alt_seq: AtomicU64::new(0),
            alt_sp: AtomicU64::new(0),
            alt_size: AtomicU64::new(0),
            alt_flags: AtomicU32::new(0),
            robust_len: AtomicU32::new(0),
            robust_head: AtomicU64::new(0),
            clear_child_tid: AtomicU64::new(0),
            entry: AtomicU64::new(0),
            pending: PendingSummary::new(),
            zone_seq: AtomicU64::new(0),
            zone_incarnation: AtomicU64::new(0),
            zone_id: AtomicU32::new(0),
            host_exit_requested: carrick_core::lifecycle::MemberControlAuthority::new(),
            retired_task: AtomicU64::new(0),
            retired_birth: carrick_core_abi::entry::AtomicBirthSerial::new(),
            retired_thread: AtomicU64::new(0),
            birth_task: AtomicU64::new(0),
            birth_serial: carrick_core_abi::entry::AtomicBirthSerial::new(),
            birth_thread: AtomicU64::new(0),
            non_interrupting: AtomicU64::new(0),
            native_pending: PendingSummary::new(),
            native_pending_writer: AtomicU32::new(0),
        }
    }

    /// Initialise the slot of a thread about to be born into `entry`, before
    /// it is visible (nothing else reads the slot of a thread not yet Born):
    /// the mask captured at claim, no alternate stack and no robust list
    /// (`clone(2)` with `CLONE_VM` clears both), its `clear_child_tid`.
    pub fn reset_for_birth(
        &self,
        blocked: BlockedMask,
        clear_child_tid: u64,
        entry: EntryRef,
    ) -> Result<(), TransitionError> {
        self.reset(blocked, clear_child_tid, Some(entry))
    }

    /// Initialise an exclusively retained host-born slot before publication.
    pub fn reset_for_host_birth(&self, blocked: BlockedMask) -> Result<(), TransitionError> {
        self.reset(blocked, 0, None)
    }
    /// Exclude graph retains while a returned lifecycle record is scrubbed.
    pub fn reserve_reset_for_reclaim(
        &self,
    ) -> Result<carrick_core::lifecycle::MemberReset<'_>, TransitionError> {
        self.host_exit_requested.reserve_reset()
    }
    #[cfg(feature = "host-test")]
    pub fn reserve_reset_for_test(
        &self,
    ) -> Result<carrick_core::lifecycle::MemberReset<'_>, TransitionError> {
        self.host_exit_requested.reserve_reset()
    }
    pub fn graph_referenced(&self) -> bool {
        self.host_exit_requested.custody().referenced()
    }
    pub fn native_signal_owner(&self) -> bool {
        self.host_exit_requested.custody().native_signal_owner()
    }
    pub fn graph_unregister_receipt(&self) -> bool {
        self.host_exit_requested.custody().unregister_receipt()
    }

    /// Publish once for this exclusively reserved slot incarnation. Repeated
    /// publication of the same identity is harmless; replacement is rejected.
    pub fn publish_visible_tid(&self, tid: u32) -> bool {
        tid != 0
            && self
                .visible_tid
                .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire)
                .map_or_else(|current| current == tid, |_| true)
    }

    /// Retire this predecessor incarnation after a committed exec. Its
    /// shared owner cannot authenticate the replacement control slot.
    pub fn retire_identity(&self) {
        self.visible_tid.store(0, Ordering::Release);
    }

    pub fn visible_tid(&self) -> Option<u32> {
        let tid = self.visible_tid.load(Ordering::Acquire);
        (tid != 0).then_some(tid)
    }

    pub fn pending(&self) -> PendingRead<'_> {
        PendingRead {
            carrier: &self.pending,
            native: Some(&self.native_pending),
        }
    }

    /// Carrier queue mutation never grants access to the native projection.
    pub fn carrier_pending(&self) -> &PendingSummary {
        &self.pending
    }

    fn reset(
        &self,
        blocked: BlockedMask,
        clear_child_tid: u64,
        entry: Option<EntryRef>,
    ) -> Result<(), TransitionError> {
        let _reset = self.host_exit_requested.reserve_reset()?;
        if entry.is_none() {
            self.visible_tid.store(0, Ordering::Relaxed);
        }
        self.zone_id.store(0, Ordering::Relaxed);
        self.retired_thread.store(0, Ordering::Relaxed);
        self.retired_task.store(0, Ordering::Relaxed);
        self.retired_birth.clear(Ordering::Relaxed);
        self.zone_incarnation.store(0, Ordering::Relaxed);
        self.zone_seq.store(0, Ordering::Relaxed);
        self.affinity.reset_exclusive();
        self.pending.clear(PendingSignals(u64::MAX));
        self.blocked.store(blocked.0, Ordering::Relaxed);
        self.birth_thread.store(0, Ordering::Relaxed);
        self.birth_task.store(0, Ordering::Relaxed);
        self.birth_serial.clear(Ordering::Relaxed);
        self.non_interrupting.store(0, Ordering::Relaxed);
        self.forwarded_saved_mask.store(0, Ordering::Relaxed);
        self.forwarded_mask_armed.store(0, Ordering::Relaxed);
        // Keep the sequence even: a stale odd value would wedge readers.
        let seq = self.alt_seq.load(Ordering::Relaxed);
        self.alt_seq
            .store(seq.wrapping_add(seq & 1), Ordering::Relaxed);
        self.alt_sp.store(0, Ordering::Relaxed);
        self.alt_size.store(0, Ordering::Relaxed);
        self.alt_flags.store(0, Ordering::Relaxed);
        self.robust_head.store(0, Ordering::Relaxed);
        self.robust_len.store(0, Ordering::Relaxed);
        self.clear_child_tid.store(
            ClearChildTidState::for_user_address(clear_child_tid).encode(),
            Ordering::Relaxed,
        );
        self.entry
            .store(entry.map_or(0, EntryRef::pack), Ordering::Release);
        Ok(())
    }

    /// The pool entry the thread holds, if any.
    pub fn entry(&self) -> Option<EntryRef> {
        EntryRef::unpack(self.entry.load(Ordering::Acquire))
    }

    /// The executing thread owns publication; host reset is exclusive before
    /// birth. This is a reference, not record custody: reuse is authenticated
    /// against the zone's live incarnation and exact thread identity.
    pub fn bind_zone_record(&self, record: carrick_sched_core::RecordRef) {
        self.zone_seq.fetch_add(1, Ordering::SeqCst);
        self.zone_incarnation
            .store(record.incarnation, Ordering::SeqCst);
        self.zone_id.store(record.id.raw(), Ordering::SeqCst);
        self.zone_seq.fetch_add(1, Ordering::SeqCst);
    }

    /// O(1), with no retry or population scan. A concurrent publication gives
    /// no projection; the kernel must still validate the returned reference.
    pub fn zone_record(&self) -> Option<carrick_sched_core::RecordRef> {
        let before = self.zone_seq.load(Ordering::SeqCst);
        if before & 1 != 0 {
            return None;
        }
        let id = self.zone_id.load(Ordering::SeqCst);
        let incarnation = self.zone_incarnation.load(Ordering::SeqCst);
        let after = self.zone_seq.load(Ordering::SeqCst);
        (before == after && incarnation != 0).then_some(carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(id)?,
            incarnation,
        })
    }

    /// The protocol state of the `clear_child_tid` word.
    pub fn clear_child_tid_state(&self) -> ClearChildTidState {
        ClearChildTidState::decode(self.clear_child_tid.load(Ordering::Acquire))
    }

    /// The thread's pending `clear_child_tid` address (0 = none, including
    /// a word an in-zone exit already cleared and woke).
    pub fn clear_child_tid(&self) -> u64 {
        self.clear_child_tid_state()
            .pending()
            .map_or(0, carrick_guest_arch::UserVa::raw)
    }

    /// Owner-written `clear_child_tid` (`set_tid_address(2)`).
    pub fn set_clear_child_tid(&self, address: u64) {
        self.clear_child_tid.store(
            ClearChildTidState::for_user_address(address).encode(),
            Ordering::Release,
        );
    }

    /// An in-zone exit cleared `address` and woke its joiner, then declined
    /// the rest of the exit to the host (#685): move the word from
    /// `Pending(address)` to `ClearedInZone(address)`, so neither a
    /// re-served exit nor the host lane clears and wakes it a second time.
    /// Only the owner writes this word while it runs, so a failed exchange
    /// means a newer `set_tid_address` replaced it: that address is still
    /// pending.
    pub fn mark_child_tid_cleared_in_zone(&self, address: u64) {
        let ClearChildTidState::Pending(pending) = ClearChildTidState::for_user_address(address)
        else {
            return;
        };
        let _ = self.clear_child_tid.compare_exchange(
            ClearChildTidState::Pending(pending).encode(),
            ClearChildTidState::ClearedInZone(pending).encode(),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Whether an in-zone exit already cleared and woke `address`.
    pub fn child_tid_cleared_in_zone_at(&self, address: u64) -> bool {
        matches!(
            self.clear_child_tid_state(),
            ClearChildTidState::ClearedInZone(cleared) if cleared.raw() == address
        )
    }

    /// Masker half of the Dekker pair: install `new`, then read the shared
    /// pending summary. Returns `(old mask, pending)`. If any pending bit is
    /// not in `new`, the caller must serve with work. `SeqCst` on both.
    #[must_use]
    pub fn store_blocked_then_read_pending<'a>(
        &self,
        new: BlockedMask,
        pending: impl Into<PendingRead<'a>>,
    ) -> (BlockedMask, PendingSignals) {
        let old = self.blocked.swap(new.0, Ordering::SeqCst);
        (BlockedMask(old), pending.into().load())
    }

    /// Plain read of the mask (no ordering pair): the owner's own view, or
    /// diagnostics.
    pub fn blocked(&self) -> BlockedMask {
        BlockedMask(self.blocked.load(Ordering::Relaxed))
    }

    /// Recipient selection after process-pending publication: the sender's
    /// second half of the mask/pending ordering pair.
    pub fn blocked_after_pending_publication(&self) -> BlockedMask {
        BlockedMask(self.blocked.load(Ordering::SeqCst))
    }

    /// Seed the mask before the thread is visible (claim time). No pending
    /// read is needed because nothing can target a thread not yet Born.
    pub fn init_blocked(&self, mask: BlockedMask) {
        self.blocked.store(mask.0, Ordering::Release);
    }

    /// Signals whose current sighand disposition cannot interrupt a blocking wait.
    pub fn non_interrupting(&self) -> BlockedMask {
        BlockedMask(self.non_interrupting.load(Ordering::Acquire))
    }

    /// Publish the sighand's current non-interrupting signal mask on this slot.
    pub fn set_non_interrupting(&self, mask: BlockedMask) {
        self.non_interrupting.store(mask.0, Ordering::Release);
    }

    /// The owning host continuation enters a temporary-mask wait. Publish
    /// the persistent mask before the temporary mask becomes visible to EL1.
    pub fn arm_forwarded_wait_mask(&self, temporary: BlockedMask, original: BlockedMask) {
        self.forwarded_saved_mask
            .store(original.0, Ordering::Relaxed);
        self.forwarded_mask_armed.store(1, Ordering::Release);
        let _ = self.store_blocked_then_read_pending(temporary, &self.pending);
    }

    pub fn forwarded_wait_mask_armed(&self) -> bool {
        self.forwarded_mask_armed.load(Ordering::Acquire) != 0
    }

    /// The native signal owner consumes the saved mask once, in the same
    /// selection path as an in-ring sigsuspend mask.
    pub fn take_forwarded_wait_mask(&self) -> Option<BlockedMask> {
        (self.forwarded_mask_armed.swap(0, Ordering::AcqRel) != 0)
            .then(|| BlockedMask(self.forwarded_saved_mask.load(Ordering::Acquire)))
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

    /// Record the exact birth identity of the host thread this slot serves:
    /// tid, owning process incarnation and thread serial. The host publishes
    /// it when it allocates the slot, before the thread can run, so every
    /// entry-less member owes a receipt for this identity.
    pub fn publish_host_birth_identity(
        &self,
        identity: carrick_core::terminal::ThreadBirthIdentity,
    ) {
        self.birth_task
            .store(identity.task().raw(), Ordering::Relaxed);
        self.birth_serial.store(identity.birth(), Ordering::Relaxed);
        self.birth_thread
            .store(identity.thread().raw(), Ordering::Release);
    }

    pub fn host_birth_identity(&self) -> Option<carrick_core::terminal::ThreadBirthIdentity> {
        let thread = self.birth_thread.load(Ordering::Acquire);
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::entry::EntryTaskKey::from_raw(
                self.birth_task.load(Ordering::Relaxed),
            ),
            self.birth_serial.load(Ordering::Relaxed)?,
            carrick_core_abi::entry::EntryThreadGeneration::from_raw(thread),
        )
    }

    /// Publish only after the host has retired the exact kernel thread and
    /// withdrawn its runtime membership. The control lease stays pinned.
    pub fn publish_host_retirement(
        &self,
        receipt: carrick_core::terminal::HostThreadRetirementReceipt,
    ) {
        let retired = receipt.retired();
        self.retired_task
            .store(retired.task().raw(), Ordering::Relaxed);
        self.retired_birth.store(retired.birth(), Ordering::Relaxed);
        self.retired_thread
            .store(retired.thread().raw(), Ordering::Release);
        self.host_exit_requested.publish_host_receipt();
    }

    pub fn host_retirement(&self) -> Option<carrick_core::terminal::HostThreadRetirementReceipt> {
        if !self.host_exit_requested.custody().host_receipt_published() {
            return None;
        }
        let thread = self.retired_thread.load(Ordering::Acquire);
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::entry::EntryTaskKey::from_raw(
                self.retired_task.load(Ordering::Relaxed),
            ),
            self.retired_birth.load(Ordering::Relaxed)?,
            carrick_core_abi::entry::EntryThreadGeneration::from_raw(thread),
        )
        .map(carrick_core::terminal::ThreadBirthIdentity::retirement)
    }

    /// The ring routed a declined raw exit to this exact host-owned slot.
    pub fn request_host_exit(&self) {
        self.host_exit_requested.request_host_exit();
    }

    pub fn host_exit_requested(&self) -> bool {
        self.host_exit_requested.custody().host_exit_requested()
    }
}
impl carrick_core::lifecycle::MemberControl for ThreadControlSlot {
    fn member_entry(&self) -> Option<EntryRef> {
        self.entry()
    }

    fn exit_custody(&self) -> &carrick_core::lifecycle::MemberExitCustody {
        self.host_exit_requested.custody()
    }

    fn host_retirement(&self) -> Option<carrick_core::terminal::HostThreadRetirementReceipt> {
        ThreadControlSlot::host_retirement(self)
    }
}
impl Default for ThreadControlSlot {
    fn default() -> Self {
        Self::new()
    }
}

/// A host-birth claim Closing could observe in `claimed_count` was put back.
/// The closing owner may have parked on that claim, and the rollback can make
/// its readiness true: the host venue owes its exit-channel wake and delivers
/// it after releasing its own locks. Only a rollback can mint one.
#[must_use = "a rolled-back host-birth claim owes the closing owner its exit wake"]
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct OwedExitWake(());

/// Why [`ThreadLifecyclePage::reserve_host_birth`] refused.
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub enum HostBirthRefusal {
    /// Every host-birth slot is in use; no claim was ever visible.
    Full,
    /// A slot was claimed, then the gate was found closed and the claim put
    /// back: the closing owner's exit wake is owed.
    Closed(OwedExitWake),
}

const CLOSING_VERDICT_WORDS: usize = 10;

/// Single-writer seqlock holding the Closing owner's last not-ready verdict.
#[repr(C)]
#[derive(::core::fmt::Debug)]
struct ClosingVerdictRecord {
    /// 0: never written; odd: a write is in progress.
    seq: AtomicU64,
    words: [AtomicU64; CLOSING_VERDICT_WORDS],
}

impl ClosingVerdictRecord {
    const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            words: [const { AtomicU64::new(0) }; CLOSING_VERDICT_WORDS],
        }
    }

    fn write(&self, verdict: &ClosingVerdict) {
        let start = self.seq.load(Ordering::Relaxed).wrapping_add(1) | 1;
        self.seq.store(start, Ordering::Relaxed);
        fence(Ordering::Release);
        for (word, value) in self.words.iter().zip(verdict.words) {
            word.store(value, Ordering::Relaxed);
        }
        self.seq.store(start.wrapping_add(1), Ordering::Release);
    }

    fn read(&self) -> ClosingVerdictRead {
        // Bounded: a census never waits on the owner.
        for _ in 0..4 {
            let before = self.seq.load(Ordering::Acquire);
            if before == 0 {
                return ClosingVerdictRead::Never;
            }
            if before & 1 != 0 {
                continue;
            }
            let mut words = [0; CLOSING_VERDICT_WORDS];
            for (value, word) in words.iter_mut().zip(&self.words) {
                *value = word.load(Ordering::Relaxed);
            }
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == before {
                return ClosingVerdictRead::Verdict(ClosingVerdict { words });
            }
        }
        ClosingVerdictRead::Torn
    }
}

/// A consistent copy of the owner's last verdict.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct ClosingVerdict {
    words: [u64; CLOSING_VERDICT_WORDS],
}

const VERDICT_SETTLE_BLOCKED: u64 = 0;
const VERDICT_POOL: u64 = 1;
const VERDICT_ADOPTED: u64 = 2;
const VERDICT_HOST_BORN: u64 = 3;
const VERDICT_MEMBER_SET: u64 = 4;

impl ClosingVerdict {
    fn encode(
        live: u32,
        claimed: usize,
        failure: Option<carrick_core::terminal::ReadinessFailure>,
    ) -> Self {
        use carrick_core::lifecycle::MemberExitKind;
        use carrick_core::terminal::ReadinessFailure;
        let kind_code = |kind: MemberExitKind| match kind {
            MemberExitKind::Active => 1,
            MemberExitKind::InZone => 2,
            MemberExitKind::HostRetiring => 3,
            MemberExitKind::Stale => 4,
        };
        let receipt = |receipt: Option<carrick_core::terminal::ThreadBirthIdentity>| {
            receipt.map_or([0; 3], |receipt| {
                [
                    receipt.task().raw(),
                    receipt.birth().raw(),
                    receipt.thread().raw(),
                ]
            })
        };
        let mut words = [0; CLOSING_VERDICT_WORDS];
        words[0] = u64::from(live) | (u64::try_from(claimed).unwrap_or(u64::MAX) << 32);
        let (code, member_kind, index, observed, expected, extra) = match failure {
            None => (VERDICT_SETTLE_BLOCKED, 0, 0, None, None, 0),
            Some(ReadinessFailure::Pool {
                entry,
                kind,
                observed,
                expected,
            }) => (
                VERDICT_POOL,
                kind_code(kind),
                u64::from(entry.index() as u32),
                observed,
                Some(expected),
                entry.generation(),
            ),
            Some(ReadinessFailure::Adopted {
                position,
                kind,
                observed,
                expected,
            }) => (
                VERDICT_ADOPTED,
                kind_code(kind),
                position as u64,
                observed,
                Some(expected),
                0,
            ),
            Some(ReadinessFailure::HostBorn { index, expected }) => {
                (VERDICT_HOST_BORN, 0, index as u64, None, Some(expected), 0)
            }
            Some(ReadinessFailure::MemberSet {
                observed_pool,
                observed_host,
                expected_pool,
                expected_host,
            }) => {
                let pack = |value: usize| (value as u64) & 0xffff;
                (
                    VERDICT_MEMBER_SET,
                    0,
                    0,
                    None,
                    None,
                    pack(observed_pool)
                        | (pack(observed_host) << 16)
                        | (pack(expected_pool) << 32)
                        | (pack(expected_host) << 48),
                )
            }
        };
        words[1] = code
            | (member_kind << 8)
            | ((index & 0xffff_ffff) << 16)
            | (u64::from(observed.is_some()) << 48);
        words[2..5].copy_from_slice(&receipt(observed.map(|receipt| receipt.retired())));
        words[5..8].copy_from_slice(&receipt(expected));
        words[8] = extra;
        Self { words }
    }
}

impl ::core::fmt::Display for ClosingVerdict {
    fn fmt(&self, out: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        let w = &self.words;
        let receipt = |base: usize| (w[base], w[base + 1], w[base + 2]);
        let kind = match (w[1] >> 8) & 0xff {
            1 => "Active",
            2 => "InZone",
            3 => "HostRetiring",
            4 => "Stale",
            _ => "-",
        };
        let index = (w[1] >> 16) & 0xffff_ffff;
        let observed = if (w[1] >> 48) & 1 != 0 {
            let (task, execution, thread) = receipt(2);
            ::alloc::format!("({task},{execution},{thread})")
        } else {
            ::alloc::string::String::from("None")
        };
        let (task, execution, thread) = receipt(5);
        ::core::write!(
            out,
            "owner_verdict live={} claimed={} ",
            w[0] & 0xffff_ffff,
            w[0] >> 32
        )?;
        match w[1] & 0xff {
            VERDICT_POOL => ::core::write!(
                out,
                "first=Pool index={index} generation={} exit_kind={kind} observed={observed} \
                 expected=({task},{execution},{thread})",
                w[8]
            ),
            VERDICT_ADOPTED => ::core::write!(
                out,
                "first=Adopted position={index} exit_kind={kind} observed={observed} \
                 expected=({task},{execution},{thread})"
            ),
            VERDICT_HOST_BORN => ::core::write!(
                out,
                "first=HostBorn index={index} expected=({task},{execution},{thread})"
            ),
            VERDICT_MEMBER_SET => ::core::write!(
                out,
                "first=MemberSet observed_pool={} observed_host={} expected_pool={} \
                 expected_host={}",
                w[8] & 0xffff,
                (w[8] >> 16) & 0xffff,
                (w[8] >> 32) & 0xffff,
                w[8] >> 48
            ),
            _ => ::core::write!(out, "receipts=complete can_settle=false"),
        }
    }
}

/// What a census read of the owner's verdict found.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub enum ClosingVerdictRead {
    Never,
    /// The owner rewrote it during every bounded attempt.
    Torn,
    Verdict(ClosingVerdict),
}

impl ::core::fmt::Display for ClosingVerdictRead {
    fn fmt(&self, out: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        match self {
            Self::Never => out.write_str("owner_verdict=none"),
            Self::Torn => out.write_str("owner_verdict=torn"),
            Self::Verdict(verdict) => verdict.fmt(out),
        }
    }
}

/// Census view of a Closing owner's readiness inputs
/// ([`ThreadLifecyclePage::closing_readiness`]).
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub struct ClosingReadiness {
    pub live: u32,
    pub claimed: usize,
    /// Host-birth claims and in-flight mutations within `claimed`.
    pub host_claimed: usize,
    /// Pool entries Claimed or Exiting within `claimed`.
    pub exiting: usize,
    /// The first member observation that is not a returned receipt.
    pub first: Option<ReadinessBlocker>,
}

impl ClosingReadiness {
    /// `TerminalCustody::can_settle`'s page inputs.
    pub fn can_settle(&self) -> bool {
        self.live == 0 && self.claimed == 0
    }
}

impl ::core::fmt::Display for ClosingReadiness {
    fn fmt(&self, out: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        ::core::write!(
            out,
            "readiness can_settle={} live={} claimed={} (host={} exiting={} fork={}) members=",
            self.can_settle(),
            self.live,
            self.claimed,
            self.host_claimed,
            self.exiting,
            self.claimed
                .saturating_sub(self.host_claimed)
                .saturating_sub(self.exiting),
        )?;
        match self.first {
            None => ::core::write!(out, "complete"),
            Some(ReadinessBlocker::Pool(blocker)) => ::core::write!(
                out,
                "blocked first=Pool index={} generation={} state={:?} exit_kind={:?} \
                 host_retirement={:?} expected_host={:?}",
                blocker.index,
                blocker.generation,
                blocker.state,
                blocker.kind,
                blocker.host_retirement,
                blocker.expected_host,
            ),
            Some(ReadinessBlocker::HostBorn {
                index,
                state,
                identity,
                returned_exact,
            }) => ::core::write!(
                out,
                "blocked first=HostBorn index={index} state={state} identity={identity:?} \
                 returned_exact={returned_exact}"
            ),
        }
    }
}

/// The first unreturned member receipt a Closing owner would wait for.
#[derive(::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug)]
pub enum ReadinessBlocker {
    /// A pool entry (`carrick_core::lifecycle::pool_readiness_census`).
    Pool(carrick_core::lifecycle::PoolReadinessBlocker),
    /// A host-born slot: 1 claimed, 2 live, 3 cancel requested.
    HostBorn {
        index: usize,
        state: u32,
        identity: Option<carrick_core::terminal::ThreadBirthIdentity>,
        returned_exact: bool,
    },
}

/// One per process; kernel-only.
#[repr(C, align(4096))]
#[derive(::core::fmt::Debug)]
pub struct ThreadLifecyclePage {
    gate: AtomicU32,
    live: AtomicU32,
    pending: PendingSummary,
    entries: [PoolEntry; THREAD_POOL_ENTRIES],
    /// [`LifecycleHatches`] bits, fixed when the page is built.
    serving: AtomicU32,
    ledger_host: AtomicU64,
    ledger_guest: AtomicU64,
    controls: [AtomicU64; THREAD_POOL_ENTRIES],
    exit_wait_mm: AtomicU64,
    exit_wait_address: AtomicU64,
    host_born: [HostBornMember; THREAD_POOL_ENTRIES],
    host_birth_mutations: AtomicU32,
    terminal: carrick_core::terminal::ProcessExitCustody,
    /// The Closing owner's last not-ready readiness verdict (census only).
    closing_verdict: ClosingVerdictRecord,
}

const _: () = assert!(core::mem::size_of::<ThreadLifecyclePage>() == THREAD_LIFECYCLE_PAGE_SIZE);

/// Shared-page identity for a member born on the host before EL1 can map its
/// control slab. States: vacant, publication claim, live, cancel requested,
/// and exact host receipt. EL1 never dereferences a host virtual address.
#[repr(C)]
#[derive(::core::fmt::Debug)]
struct HostBornMember {
    task: AtomicU64,
    birth: carrick_core_abi::entry::AtomicBirthSerial,
    thread: AtomicU64,
    state: AtomicU32,
}

impl HostBornMember {
    const fn new() -> Self {
        Self {
            task: AtomicU64::new(0),
            birth: carrick_core_abi::entry::AtomicBirthSerial::new(),
            thread: AtomicU64::new(0),
            state: AtomicU32::new(0),
        }
    }

    fn identity(&self) -> Option<carrick_core::terminal::ThreadBirthIdentity> {
        if self.state.load(Ordering::Acquire) < 2 {
            return None;
        }
        carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::entry::EntryTaskKey::from_raw(self.task.load(Ordering::Relaxed)),
            self.birth.load(Ordering::Relaxed)?,
            carrick_core_abi::entry::EntryThreadGeneration::from_raw(
                self.thread.load(Ordering::Relaxed),
            ),
        )
    }
}

const _: () = assert!(core::mem::size_of::<HostBornMember>() == 32);

/// Environment names of the EL1 lifecycle opt-out hatches.
pub const EL1_THREADS_HATCH_ENV: &str = "CARRICK_EL1_THREADS";
pub const EL1_SIGMASK_HATCH_ENV: &str = "CARRICK_EL1_SIGMASK";

/// Which EL1 lifecycle services a page allows. Both are on by default;
/// `CARRICK_EL1_THREADS=0` stops EL1 serving clone and exit,
/// `CARRICK_EL1_SIGMASK=0` stops it serving `rt_sigprocmask`,
/// `sigaltstack` and `set_robust_list`. The host reads each variable once
/// ([`Self::from_lookup`]) and builds every page with the result, so EL1 and
/// the host decide from the same bits.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
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

    /// Consult `lookup` once per hatch variable; exactly `0`
    /// disables that service, anything else (or unset) leaves it on.
    pub fn from_lookup<S: AsRef<str>>(mut lookup: impl FnMut(&str) -> Option<S>) -> Self {
        let mut on = |name: &str| lookup(name).is_none_or(|value| value.as_ref() != "0");
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
const _: () = assert!(core::mem::size_of::<ThreadControlSlot>() == 256);
const _: () = assert!(core::mem::size_of::<PoolEntry>() == 80);

/// Linux keeps the last thread's exit with the terminal runtime owner.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
pub struct LastThread;

impl ThreadLifecyclePage {
    pub fn try_exit(&self) -> Result<u32, LastThread> {
        self.release_live(1).map_err(|_| LastThread)
    }

    /// A page with an open gate, one live thread (the leader), an empty
    /// pool and every service on.
    pub const fn new() -> Self {
        Self::with_hatches(LifecycleHatches::ON)
    }

    /// Initialize an exclusively owned page without a page-sized temporary.
    ///
    /// # Safety
    ///
    /// `storage` must be aligned and writable for one complete page, with no
    /// observers or live custody referring to its previous contents.
    #[inline(never)]
    pub unsafe fn initialize_at(storage: *mut Self) {
        // Borrow the canonical constructor's immutable template. In particular,
        // `storage.write(Self::new())` can put multiple 4 KiB aligned copies on
        // a ring stack when copy elision changes between compiler drivers.
        // No reference to the template escapes and nobody mutates its atomics.
        static TEMPLATE: ThreadLifecyclePage = ThreadLifecyclePage::new();
        const { assert!(!core::mem::needs_drop::<ThreadLifecyclePage>()) };
        // SAFETY: the caller owns distinct storage; both pointers are aligned,
        // and the template has no owning fields requiring clone/drop semantics.
        unsafe { core::ptr::copy_nonoverlapping(&raw const TEMPLATE, storage, 1) };
    }

    /// [`Self::new`] with the services `hatches` allows.
    pub const fn with_hatches(hatches: LifecycleHatches) -> Self {
        Self {
            gate: AtomicU32::new(GateState::Open as u32),
            live: AtomicU32::new(1),
            pending: PendingSummary::new(),
            entries: [const { PoolEntry::new() }; THREAD_POOL_ENTRIES],
            serving: AtomicU32::new(hatches.bits()),
            ledger_host: AtomicU64::new(0),
            ledger_guest: AtomicU64::new(0),
            controls: [const { AtomicU64::new(0) }; THREAD_POOL_ENTRIES],
            exit_wait_mm: AtomicU64::new(0),
            exit_wait_address: AtomicU64::new(0),
            host_born: [const { HostBornMember::new() }; THREAD_POOL_ENTRIES],
            host_birth_mutations: AtomicU32::new(0),
            terminal: carrick_core::terminal::ProcessExitCustody::new(),
            closing_verdict: ClosingVerdictRecord::new(),
        }
    }

    /// Reserve one host-born member before its irreversible task publication.
    /// State one is an unpublished claim. Closing waits for every claim, so a
    /// claim backed out after the gate check is owed to the closing owner's
    /// exit channel ([`HostBirthRefusal::Closed`]).
    pub fn reserve_host_birth(&self) -> Result<usize, HostBirthRefusal> {
        for (index, slot) in self.host_born.iter().enumerate() {
            if slot
                .state
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                if self.gate() == GateState::Open {
                    return Ok(index);
                }
                slot.state.store(0, Ordering::SeqCst);
                return Err(HostBirthRefusal::Closed(OwedExitWake(())));
            }
        }
        Err(HostBirthRefusal::Full)
    }

    pub fn publish_host_birth(
        &self,
        index: usize,
        identity: carrick_core::terminal::ThreadBirthIdentity,
    ) -> bool {
        let Some(slot) = self.host_born.get(index) else {
            return false;
        };
        if slot.state.load(Ordering::SeqCst) != 1 {
            return false;
        }
        slot.task.store(identity.task().raw(), Ordering::Relaxed);
        slot.birth.store(identity.birth(), Ordering::Relaxed);
        slot.thread
            .store(identity.thread().raw(), Ordering::Relaxed);
        slot.state
            .compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Back out an unpublished host-birth claim. Closing may have parked on
    /// it, so a successful rollback returns the exit wake it owes.
    pub fn cancel_host_birth_claim(&self, index: usize) -> Option<OwedExitWake> {
        self.host_born
            .get(index)
            .is_some_and(|slot| {
                slot.state
                    .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            })
            .then_some(OwedExitWake(()))
    }

    pub fn host_birth_identity(
        &self,
        index: usize,
    ) -> Option<carrick_core::terminal::ThreadBirthIdentity> {
        self.host_born.get(index)?.identity()
    }

    pub fn host_birth_requested(
        &self,
        identity: carrick_core::terminal::ThreadBirthIdentity,
    ) -> bool {
        self.host_born.iter().any(|slot| {
            slot.identity() == Some(identity) && slot.state.load(Ordering::Acquire) == 3
        })
    }

    pub fn request_host_birth_cancel(&self, index: usize) -> bool {
        self.host_born.get(index).is_some_and(|slot| {
            slot.identity().is_some()
                && (slot
                    .state
                    .compare_exchange(2, 3, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                    || slot.state.load(Ordering::Acquire) == 3)
        })
    }

    pub fn publish_host_birth_receipt(
        &self,
        identity: carrick_core::terminal::ThreadBirthIdentity,
    ) -> bool {
        self.host_born.iter().any(|slot| {
            if slot.identity() != Some(identity) {
                return false;
            }
            let state = slot.state.load(Ordering::SeqCst);
            matches!(state, 2 | 3)
                && slot
                    .state
                    .compare_exchange(state, 4, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
        })
    }

    /// Publish one exact host retirement to the control slot and retained
    /// host-birth slot. The runtime calls this only after graph retirement.
    pub fn publish_exact_host_retirement(
        &self,
        control: &ThreadControlSlot,
        receipt: carrick_core::terminal::HostThreadRetirementReceipt,
    ) {
        control.publish_host_retirement(receipt);
        self.publish_host_birth_receipt(receipt.retired());
        self.release_completed_host_birth(receipt.retired());
    }

    /// Exercise the two publication boundaries through the production
    /// retirement sequence without changing its ordering.
    #[cfg(feature = "host-test")]
    pub fn publish_exact_host_retirement_with_hooks(
        &self,
        control: &ThreadControlSlot,
        receipt: carrick_core::terminal::HostThreadRetirementReceipt,
        after_receipt: impl FnOnce(),
        after_release_claim: impl FnOnce(),
    ) {
        control.publish_host_retirement(receipt);
        self.publish_host_birth_receipt(receipt.retired());
        after_receipt();
        self.release_host_birth_with_hook(receipt.retired(), 4, after_release_claim);
    }

    /// Retire the exact published entry and consume its reserved membership.
    pub fn retire_published_host_member(
        &self,
        entry: EntryRef,
        control: &ThreadControlSlot,
        membership: carrick_core::lifecycle::NonfinalExitMembership<'_>,
    ) -> Result<(), TransitionError> {
        carrick_core::lifecycle::retire_host_member(self, entry, control, membership)
    }

    /// What a Closing owner's readiness check would see, from page state and
    /// the member control slots the caller can reach (`pool`). Independent
    /// atomic observations for a census, not a coherent settlement proof:
    /// the owner's own outstanding set lives in its ring graph. Bounded by
    /// the pool and host-birth capacities; it never waits or mutates.
    pub fn closing_readiness(&self, pool: &[(EntryRef, &ThreadControlSlot)]) -> ClosingReadiness {
        let census = carrick_core::lifecycle::census(self);
        let host_claimed = self.host_birth_claimed_count();
        let (exiting, pool_blocker) = carrick_core::lifecycle::pool_readiness_census(
            self,
            |entry| {
                pool.iter()
                    .find(|(candidate, _)| *candidate == entry)
                    .map(|(_, control)| *control as &dyn carrick_core::lifecycle::MemberControl)
            },
            |entry| {
                self.identity(entry).and_then(|identity| {
                    carrick_core::terminal::ThreadBirthIdentity::from_parts(
                        carrick_core_abi::entry::EntryTaskKey::from_raw(u64::from(identity.tid)),
                        identity.birth,
                        carrick_core_abi::entry::EntryThreadGeneration::from_raw(
                            identity.thread_serial,
                        ),
                    )
                })
            },
        );
        let mut first = pool_blocker.map(ReadinessBlocker::Pool);
        if first.is_none() {
            for (index, slot) in self.host_born.iter().enumerate() {
                let state = slot.state.load(Ordering::Acquire);
                if matches!(state, 0 | 4) {
                    continue;
                }
                let identity = slot.identity();
                first = Some(ReadinessBlocker::HostBorn {
                    index,
                    state,
                    identity,
                    returned_exact: identity.is_some_and(|identity| {
                        self.host_birth_receipt_returned_exact(index, identity)
                    }),
                });
                break;
            }
        }
        ClosingReadiness {
            live: census.live,
            claimed: census.claimed,
            host_claimed,
            exiting,
            first,
        }
    }

    /// Record why the Closing owner is about to park instead of settling:
    /// the page inputs it saw and its first unreturned member observation
    /// (`None`: every receipt returned but `can_settle` was false). Written
    /// only on the owner's park path, under its process graph lock (the
    /// single writer), as a seqlock the census reads without waiting.
    pub fn record_closing_verdict(
        &self,
        failure: Option<carrick_core::terminal::ReadinessFailure>,
    ) {
        let census = carrick_core::lifecycle::census(self);
        self.closing_verdict.write(&ClosingVerdict::encode(
            census.live,
            census.claimed,
            failure,
        ));
    }

    /// The owner's last recorded verdict, if a consistent one is readable.
    pub fn closing_verdict(&self) -> ClosingVerdictRead {
        self.closing_verdict.read()
    }

    pub fn host_birth_receipt_returned(&self, index: usize) -> bool {
        self.host_born
            .get(index)
            .is_some_and(|slot| slot.state.load(Ordering::Acquire) == 4)
    }

    pub fn host_birth_claimed_count(&self) -> usize {
        self.host_birth_mutations.load(Ordering::SeqCst) as usize
            + self
                .host_born
                .iter()
                .filter(|slot| slot.state.load(Ordering::SeqCst) == 1)
                .count()
    }

    fn release_host_birth(
        &self,
        identity: carrick_core::terminal::ThreadBirthIdentity,
        expected: u32,
    ) -> bool {
        self.release_host_birth_with_hook(identity, expected, || {})
    }

    fn release_host_birth_with_hook(
        &self,
        identity: carrick_core::terminal::ThreadBirthIdentity,
        expected: u32,
        after_claim: impl FnOnce(),
    ) -> bool {
        self.host_birth_mutations.fetch_add(1, Ordering::SeqCst);
        after_claim();
        let released = self.host_born.iter().any(|slot| {
            if slot.identity() != Some(identity)
                || slot
                    .state
                    .compare_exchange(expected, 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_err()
            {
                return false;
            }
            if self.gate().is_terminal() {
                slot.state.store(expected, Ordering::SeqCst);
                return false;
            }
            // The non-Closed read is the release linearization point. Closing
            // sees the mutation claim until this vacancy is published.
            slot.state.store(0, Ordering::SeqCst);
            true
        });
        self.host_birth_mutations.fetch_sub(1, Ordering::SeqCst);
        released
    }

    /// Adoption and normal host completion consume their exact slot until
    /// Closed. Fork/exec gates block new births, not already-born adoption.
    /// Closing retains every slot until settlement.
    pub fn release_adopted_host_birth(
        &self,
        identity: carrick_core::terminal::ThreadBirthIdentity,
    ) -> bool {
        self.release_host_birth(identity, 2)
    }

    pub fn release_completed_host_birth(
        &self,
        identity: carrick_core::terminal::ThreadBirthIdentity,
    ) -> bool {
        self.release_host_birth(identity, 4)
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

    /// Bind the immutable host-side notification authority before publication.
    /// # Safety
    /// The page owner must retain this exact activity allocation for every
    /// access to the page, including accesses through carrier mappings.
    pub unsafe fn bind_host_activity(&self, activity: *const ThreadLedgerActivity) {
        self.ledger_host
            .store(activity.addr() as u64, Ordering::Release);
    }
    /// Bind a retained EL1-only mapping of the same activity authority.
    /// # Safety
    /// `address` must name the retained mapping of the host-bound activity
    /// and remain accessible in EL1 while any record names this page.
    pub unsafe fn bind_guest_activity(&self, address: u64) {
        self.ledger_guest.store(address, Ordering::Release);
    }
    pub fn guest_activity_address(&self) -> u64 {
        self.ledger_guest.load(Ordering::Acquire)
    }

    /// Publish the already-owned WaitChannel key before cancellation starts.
    /// The key publication and lookup join the live-count SeqCst order:
    /// the enrolling owner must observe settlement, or the settling member
    /// must observe this key. Acquire/release alone permits both to miss.
    /// The address is stored last so readers never observe a partial key.
    pub fn publish_exit_wait(&self, mm: carrick_core_abi::entry::EntryMmKey, address: u64) {
        self.exit_wait_mm.store(mm.raw(), Ordering::Relaxed);
        self.exit_wait_address.store(address, Ordering::SeqCst);
    }

    pub fn exit_wait(&self) -> Option<(carrick_core_abi::entry::EntryMmKey, u64)> {
        let address = self.exit_wait_address.load(Ordering::SeqCst);
        (address != 0).then(|| {
            (
                carrick_core_abi::entry::EntryMmKey::from_raw(
                    self.exit_wait_mm.load(Ordering::Relaxed),
                ),
                address,
            )
        })
    }

    pub fn clear_exit_wait(&self) {
        self.exit_wait_address.store(0, Ordering::SeqCst);
    }
    fn activity(&self) -> Option<&ThreadLedgerActivity> {
        #[cfg(target_os = "none")]
        let address = self.ledger_guest.load(Ordering::Acquire);
        #[cfg(not(target_os = "none"))]
        let address = self.ledger_host.load(Ordering::Acquire);
        if address == 0 {
            return None;
        }
        // SAFETY: the immutable owner binding pins this exact allocation;
        // each execution lane uses its own address domain.
        Some(unsafe { &*(address as *const ThreadLedgerActivity) })
    }

    /// Publish a control binding while owning its Reserved -> Stocking CAS.
    pub fn bind_control_address(
        &self,
        entry: EntryRef,
        address: u64,
    ) -> Result<(), TransitionError> {
        self.transition(
            entry,
            &[EntryState::Reserved],
            EntryState::Stocking,
            Ordering::AcqRel,
        )?;
        self.controls[entry.index()].store(address, Ordering::Relaxed);
        self.transition(
            entry,
            &[EntryState::Stocking],
            EntryState::Reserved,
            Ordering::Release,
        )
    }
    pub fn control_address(&self, entry: EntryRef) -> Option<u64> {
        self.identity(entry)?;
        Some(self.controls[entry.index()].load(Ordering::Acquire))
    }

    fn entry(&self, index: usize) -> Result<&PoolEntry, TransitionError> {
        self.entries.get(index).ok_or(TransitionError::NoSuchEntry)
    }

    /// Kernel: issue `identity` into a `Vacant`, `Reaped` or `Revoked` entry,
    /// bumping the generation. Returns the reference to the new incarnation.
    pub fn stock(
        &self,
        index: usize,
        identity: EntryIdentity,
    ) -> Result<EntryRef, TransitionError> {
        let e = self.entry(index)?;
        let reference = self.reserve_stock(index)?;
        let next = reference.generation();
        e.tid.store(identity.tid, Ordering::Relaxed);
        self.controls[index].store(0, Ordering::Relaxed);
        e.visible_tid.store(identity.visible_tid, Ordering::Relaxed);
        e.thread_serial
            .store(identity.thread_serial, Ordering::Relaxed);
        e.uid_credit.store(identity.uid_credit, Ordering::Relaxed);
        e.birth.store(identity.birth, Ordering::Relaxed);
        e.state
            .store(pack(next, EntryState::Reserved), Ordering::Release);
        Ok(reference)
    }

    /// EL1 clone: record the Born payload and move `Claimed -> Born`.
    pub fn record_born(
        &self,
        claim: ClaimedEntry,
        record: BornRecord,
    ) -> Result<EntryRef, carrick_core::lifecycle::BirthRefusal> {
        let r = claim.entry();
        let e = match self.entry(r.index()) {
            Ok(entry) => entry,
            Err(error) => return Err(carrick_core::lifecycle::BirthRefusal::new(error, claim)),
        };
        e.caller_task.store(record.caller_task, Ordering::Relaxed);
        e.caller_serial
            .store(record.caller_serial, Ordering::Relaxed);
        e.clone_flags.store(record.clone_flags, Ordering::Relaxed);
        e.clear_child_tid
            .store(record.clear_child_tid, Ordering::Relaxed);
        e.blocked.store(record.blocked.0, Ordering::Relaxed);
        self.complete_birth(claim)
    }

    /// Identity of a reference, read after an acquire of its state. `None` if
    /// the reference is stale or the entry is not past `Stocking`.
    pub fn identity(&self, r: EntryRef) -> Option<EntryIdentity> {
        let e = self.entries.get(r.index())?;
        let (generation, state) = unpack(e.state.load(Ordering::Acquire));
        if generation != r.generation()
            || matches!(state, EntryState::Vacant | EntryState::Stocking)
        {
            return None;
        }
        Some(EntryIdentity {
            tid: e.tid.load(Ordering::Relaxed),
            visible_tid: e.visible_tid.load(Ordering::Relaxed),
            thread_serial: e.thread_serial.load(Ordering::Relaxed),
            uid_credit: e.uid_credit.load(Ordering::Relaxed),
            birth: e.birth.load(Ordering::Relaxed)?,
        })
    }

    #[inline(never)]
    pub fn entry_ref_for_visible_tid(&self, visible_tid: u32) -> Option<EntryRef> {
        if visible_tid == 0 {
            return None;
        }
        for (index, entry) in self.entries.iter().enumerate() {
            let (generation, state) = unpack(entry.state.load(Ordering::Acquire));
            if matches!(state, EntryState::Vacant | EntryState::Stocking) {
                continue;
            }
            if entry.visible_tid.load(Ordering::Relaxed) == visible_tid {
                return Some(EntryRef::new(index as u32, generation));
            }
        }
        None
    }

    /// Born record of a `Born`, `Published`, `ExitedInZone` or `Reaped`
    /// incarnation. `None` for any other state or a stale reference.
    pub fn born_record(&self, r: EntryRef) -> Option<BornRecord> {
        let e = self.entries.get(r.index())?;
        let (generation, state) = unpack(e.state.load(Ordering::Acquire));
        if generation != r.generation()
            || !matches!(
                state,
                EntryState::Born
                    | EntryState::ExitingBorn
                    | EntryState::ExitingPublished
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
impl Lifecycle for ThreadLifecyclePage {
    fn terminal_notification(&self) -> Option<carrick_core::terminal::TerminalNotification> {
        let (mm, address) = self.exit_wait()?;
        Some(carrick_core::terminal::TerminalNotification {
            mm,
            address: core::num::NonZeroU64::new(address)?,
        })
    }
    fn process_exit_custody(&self) -> &carrick_core::terminal::ProcessExitCustody {
        &self.terminal
    }
    fn host_birth_receipt_returned_exact(
        &self,
        index: usize,
        identity: carrick_core::terminal::ThreadBirthIdentity,
    ) -> bool {
        self.host_birth_identity(index) == Some(identity) && self.host_birth_receipt_returned(index)
    }
    fn host_claimed_count(&self) -> usize {
        self.host_birth_claimed_count()
    }
    fn gate_word(&self) -> &AtomicU32 {
        &self.gate
    }
    fn live_word(&self) -> &AtomicU32 {
        &self.live
    }
    fn entry_count(&self) -> usize {
        self.entries.len()
    }
    fn entry_word(&self, index: usize) -> Option<&AtomicEntry> {
        self.entries.get(index).map(|entry| &entry.state)
    }
    fn activity(&self) -> Option<&ThreadLedgerActivity> {
        self.activity()
    }
}
impl Default for ThreadLifecyclePage {
    fn default() -> Self {
        Self::new()
    }
}

/// Layout facts folded into the image ABI layout hash.
pub const THREAD_LIFECYCLE_LAYOUT_FACTS: [u64; 46] = [
    THREAD_LIFECYCLE_PROTOCOL_VERSION,
    core::mem::offset_of!(PoolEntry, birth) as u64,
    core::mem::offset_of!(ThreadLifecyclePage, terminal) as u64,
    core::mem::size_of::<ThreadLedgerActivity>() as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, ledger_host) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, ledger_guest) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, controls) as u64,
    THREAD_POOL_ENTRIES as u64,
    core::mem::size_of::<ThreadLifecyclePage>() as u64,
    core::mem::align_of::<ThreadLifecyclePage>() as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, gate) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, live) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, pending) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, entries) as u64,
    core::mem::size_of::<PoolEntry>() as u64,
    core::mem::size_of::<ThreadControlSlot>() as u64,
    ::core::mem::offset_of!(ThreadControlSlot, visible_tid) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, alt_seq) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, robust_head) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, clear_child_tid) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, entry) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, pending) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, native_pending) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, native_pending_writer) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, zone_seq) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, zone_incarnation) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, zone_id) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, serving) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, retired_task) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, retired_birth) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, retired_thread) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, birth_task) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, birth_serial) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, birth_thread) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, exit_wait_mm) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, exit_wait_address) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, host_exit_requested) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, host_born) as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, host_birth_mutations) as u64,
    ::core::mem::size_of::<HostBornMember>() as u64,
    ::core::mem::offset_of!(ThreadLifecyclePage, closing_verdict) as u64,
    ::core::mem::size_of::<ClosingVerdictRecord>() as u64,
    ::core::mem::offset_of!(ThreadControlSlot, affinity) as u64,
    ::core::mem::size_of::<carrick_core::affinity::AffinityAuthority>() as u64,
    ::core::mem::offset_of!(ThreadControlSlot, affinity_host_alias) as u64,
    ::core::mem::offset_of!(ThreadControlSlot, affinity_guest_alias) as u64,
];

#[cfg(test)]
mod tests {
    #[test]
    fn closing_verdict_renders_the_owners_last_not_ready_observation() {
        use carrick_core::lifecycle::MemberExitKind;
        use carrick_core::terminal::{ReadinessFailure, ThreadBirthIdentity};
        use carrick_core_abi::entry::{EntryTaskKey, EntryThreadGeneration};
        use std::string::ToString;
        let page = super::ThreadLifecyclePage::new();
        assert_eq!(page.closing_verdict().to_string(), "owner_verdict=none");
        let receipt = |execution| {
            ThreadBirthIdentity::from_parts(
                EntryTaskKey::from_raw(2),
                carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(execution).unwrap(),
                ),
                EntryThreadGeneration::from_raw(43),
            )
            .unwrap()
        };
        page.record_closing_verdict(Some(ReadinessFailure::Adopted {
            position: 0,
            kind: MemberExitKind::HostRetiring,
            observed: Some(receipt(5).retirement()),
            expected: receipt(4263),
        }));
        assert_eq!(
            page.closing_verdict().to_string(),
            "owner_verdict live=1 claimed=0 first=Adopted position=0 exit_kind=HostRetiring \
             observed=(2,5,43) expected=(2,4263,43)"
        );
        assert!(page.release_live(0).is_ok());
        page.record_closing_verdict(Some(ReadinessFailure::MemberSet {
            observed_pool: 0,
            observed_host: 2,
            expected_pool: 0,
            expected_host: 1,
        }));
        assert_eq!(
            page.closing_verdict().to_string(),
            "owner_verdict live=0 claimed=0 first=MemberSet observed_pool=0 observed_host=2 \
             expected_pool=0 expected_host=1"
        );
        page.record_closing_verdict(None);
        assert_eq!(
            page.closing_verdict().to_string(),
            "owner_verdict live=0 claimed=0 receipts=complete can_settle=false"
        );
    }

    #[test]
    fn in_place_lifecycle_page_initializes_poisoned_aligned_storage() {
        use super::{EntryIdentity, Lifecycle, ThreadLifecyclePage};
        let mut storage = std::boxed::Box::<ThreadLifecyclePage>::new_uninit();
        // SAFETY: typed allocation preserves the page alignment, and no page
        // reference exists before the initializer has written its fields.
        let page = unsafe {
            storage
                .as_mut_ptr()
                .cast::<u8>()
                .write_bytes(0xa5, core::mem::size_of::<ThreadLifecyclePage>());
            ThreadLifecyclePage::initialize_at(storage.as_mut_ptr());
            storage.assume_init()
        };
        assert_eq!(
            std::format!("{page:?}"),
            std::format!("{:?}", ThreadLifecyclePage::new())
        );
        assert_eq!(page.live(), 1);
        assert!(page.serves_threads() && page.serves_sigmask());
        let entry = page
            .stock(
                0,
                EntryIdentity {
                    tid: 42,
                    visible_tid: 42,
                    thread_serial: 2,
                    birth: carrick_core_abi::entry::BirthSerial::of_task(
                        carrick_sched_core::process::TaskSerial::from_raw_u64(1).unwrap(),
                    ),
                    uid_credit: 0,
                },
            )
            .unwrap();
        let claim = page.claim(entry).unwrap();
        assert_eq!(page.claimed_count(), 1);
        page.unclaim(claim).unwrap();
        assert_eq!(page.claimed_count(), 0);
    }

    #[test]
    fn revoked_unpublished_control_publishes_its_release_receipt() {
        let page = super::ThreadLifecyclePage::new();
        let control = super::ThreadControlSlot::new();
        let entry = page
            .stock(
                0,
                super::EntryIdentity {
                    tid: 42,
                    visible_tid: 42,
                    thread_serial: 2,
                    birth: carrick_core_abi::entry::BirthSerial::of_task(
                        carrick_sched_core::process::TaskSerial::from_raw_u64(1).unwrap(),
                    ),
                    uid_credit: 0,
                },
            )
            .unwrap();
        assert!(!control.graph_unregister_receipt());
        carrick_core::lifecycle::revoke_unborn_control(&page, entry, &control).unwrap();
        assert!(control.graph_unregister_receipt());
    }

    #[test]
    fn rejected_recycled_control_retain_does_not_publish_unregister() {
        let slot = super::ThreadControlSlot::new();
        let old = super::EntryRef::new(0, 1);
        let replacement = super::EntryRef::new(0, 2);
        slot.reset_for_birth(super::BlockedMask(0), 0, old).unwrap();
        // The scan observed old before the host recycled this allocation.
        slot.reset_for_host_birth(super::BlockedMask(0)).unwrap();
        slot.reset_for_birth(super::BlockedMask(0), 0, replacement)
            .unwrap();
        let retained = carrick_core::lifecycle::MemberControlCustody::retain(&slot).unwrap();
        assert_ne!(retained.entry(), Some(old));
        drop(retained);
        assert!(
            !slot.graph_unregister_receipt(),
            "a rejected retain must not release the replacement host lease"
        );
    }

    #[test]
    fn graph_owned_control_rejects_reset_until_unregister() {
        let slot = super::ThreadControlSlot::new();
        let entry = super::EntryRef::new(0, 1);
        slot.reset_for_birth(super::BlockedMask(0), 0, entry)
            .unwrap();
        let custody = carrick_core::lifecycle::MemberControlCustody::retain(&slot).unwrap();
        custody.commit_registration();
        assert!(slot.reset_for_host_birth(super::BlockedMask(0)).is_err());
        assert!(
            slot.reset_for_birth(super::BlockedMask(0), 0, super::EntryRef::new(1, 2))
                .is_err()
        );
        assert_eq!(slot.entry(), Some(entry));
        assert!(!slot.graph_unregister_receipt());
        drop(custody);
        assert!(slot.graph_unregister_receipt());
        slot.reset_for_host_birth(super::BlockedMask(0)).unwrap();
        assert_eq!(slot.entry(), None);
        assert!(!slot.graph_unregister_receipt());
    }

    #[test]
    fn host_birth_capacity_refuses_without_leaking_a_claim() {
        let page = super::ThreadLifecyclePage::new();
        let mut slots = [0usize; super::THREAD_POOL_ENTRIES];
        for slot in &mut slots {
            *slot = page.reserve_host_birth().expect("capacity available");
        }
        assert_eq!(
            page.reserve_host_birth(),
            Err(super::HostBirthRefusal::Full)
        );
        assert_eq!(page.host_birth_claimed_count(), super::THREAD_POOL_ENTRIES);
        assert!(page.cancel_host_birth_claim(slots[0]).is_some());
        assert_eq!(page.reserve_host_birth(), Ok(slots[0]));
        assert_eq!(page.host_birth_claimed_count(), super::THREAD_POOL_ENTRIES);
    }

    #[test]
    fn host_birth_adoption_and_closing_have_one_slot_winner() {
        use super::Lifecycle;
        let first = carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::entry::EntryTaskKey::from_raw(41),
            carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(11).unwrap(),
            ),
            carrick_core_abi::entry::EntryThreadGeneration::from_raw(101),
        )
        .unwrap();
        let second = carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::entry::EntryTaskKey::from_raw(42),
            carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
            ),
            carrick_core_abi::entry::EntryThreadGeneration::from_raw(102),
        )
        .unwrap();
        let adopted = super::ThreadLifecyclePage::new();
        let slot = adopted.reserve_host_birth().unwrap();
        assert!(adopted.publish_host_birth(slot, first));
        assert!(adopted.release_adopted_host_birth(first));
        assert!(!adopted.release_adopted_host_birth(first));
        adopted.close();
        assert_eq!(adopted.host_birth_identity(slot), None);

        let cancelled = super::ThreadLifecyclePage::new();
        let slot = cancelled.reserve_host_birth().unwrap();
        assert!(cancelled.publish_host_birth(slot, second));
        cancelled.close();
        assert!(!cancelled.release_adopted_host_birth(second));
        assert_eq!(cancelled.host_birth_identity(slot), Some(second));
        assert!(cancelled.request_host_birth_cancel(slot));
        assert!(cancelled.host_birth_requested(second));
        assert!(!cancelled.publish_host_birth_receipt(first));
        assert!(!cancelled.host_birth_receipt_returned(slot));
        assert!(cancelled.publish_host_birth_receipt(second));
        assert!(cancelled.host_birth_receipt_returned(slot));
        assert_eq!(cancelled.host_birth_claimed_count(), 0);
    }

    #[test]
    fn host_retirement_publication_keeps_exact_control_and_slot_receipt() {
        use super::Lifecycle;
        let page = super::ThreadLifecyclePage::new();
        let control = super::ThreadControlSlot::new();
        let receipt = carrick_core::terminal::ThreadBirthIdentity::from_parts(
            carrick_core_abi::entry::EntryTaskKey::from_raw(42),
            carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(12).unwrap(),
            ),
            carrick_core_abi::entry::EntryThreadGeneration::from_raw(102),
        )
        .unwrap();
        let slot = page.reserve_host_birth().unwrap();
        assert!(page.publish_host_birth(slot, receipt));
        page.close();
        page.publish_exact_host_retirement(&control, receipt.retirement());
        assert_eq!(control.host_retirement(), Some(receipt.retirement()));
        assert!(page.host_birth_receipt_returned(slot));
        assert_eq!(page.host_birth_identity(slot), Some(receipt));
    }

    #[test]
    fn zone_record_binding_is_bounded_and_reset_with_its_control_incarnation() {
        let slot = super::ThreadControlSlot::new();
        let record = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(19).unwrap(),
            incarnation: 33,
        };
        assert_eq!(slot.zone_record(), None);
        slot.bind_zone_record(record);
        assert_eq!(slot.zone_record(), Some(record));
        slot.zone_seq.fetch_add(1, super::Ordering::SeqCst);
        assert_eq!(slot.zone_record(), None, "no retry on an in-flight writer");
        slot.reset_for_host_birth(super::BlockedMask(0)).unwrap();
        assert_eq!(
            slot.zone_record(),
            None,
            "reused control slot drops the old reference"
        );
    }
    #[test]
    fn carrier_queue_cleanup_cannot_clear_native_pending_custody() {
        let control = ThreadControlSlot::new();
        let custody = Arc::new(MemberControlCustody::retain(&control).unwrap());
        let native = NativePendingCustody::try_admit(custody.clone()).unwrap();
        native.replace_from_locked_queue(PendingSignals(0x100));
        let _ = control
            .carrier_pending()
            .post_then_read_blocked(PendingSignals(0x400), &control);
        assert_eq!(control.pending().load(), PendingSignals(0x500));
        control.carrier_pending().clear(PendingSignals(u64::MAX));
        assert_eq!(control.pending().load(), PendingSignals(0x100));
        native.replace_from_locked_queue(PendingSignals(0));
        assert_eq!(control.pending().load(), PendingSignals(0));
        drop(native);
        drop(custody);
        control.reset_for_host_birth(BlockedMask(0)).unwrap();
        assert_eq!(control.pending().load(), PendingSignals(0));
    }

    #[test]
    fn native_pending_writer_admission_is_exclusive_until_drop() {
        let control = ThreadControlSlot::new();
        let custody = Arc::new(MemberControlCustody::retain(&control).unwrap());
        let writer = NativePendingCustody::try_admit(custody.clone()).unwrap();
        writer.replace_from_locked_queue(PendingSignals(0x100));
        // A different retain must encounter the same slot's admission claim.
        let independent = Arc::new(MemberControlCustody::retain(&control).unwrap());
        assert_eq!(
            NativePendingCustody::try_admit(independent).err(),
            Some(NativePendingAlreadyAdmitted)
        );
        assert_eq!(control.pending().load(), PendingSignals(0x100));
        assert!(control.reset_for_host_birth(BlockedMask(0)).is_err());
        drop(writer);
        assert_eq!(control.pending().load(), PendingSignals(0));
        let successor = NativePendingCustody::try_admit(custody.clone()).unwrap();
        successor.replace_from_locked_queue(PendingSignals(0x400));
        assert_eq!(control.pending().load(), PendingSignals(0x400));
        drop(successor);
        drop(custody);
        control.reset_for_host_birth(BlockedMask(0)).unwrap();
        let next_birth = NativePendingCustody::try_admit(Arc::new(
            MemberControlCustody::retain(&control).unwrap(),
        ))
        .unwrap();
        assert_eq!(control.pending().load(), PendingSignals(0));
        drop(next_birth);
    }

    #[test]
    fn control_pending_is_owned_by_the_exact_thread_slot() {
        let first = ThreadControlSlot::new();
        let second = ThreadControlSlot::new();
        first.init_blocked(BlockedMask(0x400));
        let _ = first
            .carrier_pending()
            .post_then_read_blocked(PendingSignals(0x400), &first);
        assert_eq!(first.pending().load(), PendingSignals(0x400));
        assert_eq!(second.pending().load(), PendingSignals(0));
        assert_eq!(
            first
                .store_blocked_then_read_pending(BlockedMask(0), first.pending())
                .1,
            PendingSignals(0x400)
        );
        first.reset_for_host_birth(BlockedMask(0)).unwrap();
        assert_eq!(first.pending().load(), PendingSignals(0));
    }
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
            birth: carrick_core_abi::entry::BirthSerial::of_task(
                carrick_sched_core::process::TaskSerial::from_raw_u64(1).unwrap(),
            ),
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
        p.begin_exit(r).and_then(ExitAdmission::commit).unwrap();
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
        p.begin_exit(r).and_then(ExitAdmission::commit).unwrap();
        p.reap(r).unwrap();
    }

    #[test]
    fn closed_admission_refuses_exit_without_closing_a_peer() {
        let p = ThreadLifecyclePage::new();
        let peer = ThreadLifecyclePage::new();
        let r = p.stock(0, ident(1)).unwrap();
        let r = p.record_born(p.claim(r).unwrap(), born(0)).unwrap();
        p.close_for_fork().unwrap();
        assert_eq!(
            p.begin_exit(r).and_then(ExitAdmission::commit),
            Err(TransitionError::GateClosed(GateState::ForkClosing)),
            "closed admission let an exit cross conflicting host authority"
        );
        assert_eq!(st(&p, 0), EntryState::Born);
        assert_eq!(peer.gate(), GateState::Open);
    }

    #[test]
    fn exit_admission_drains_and_rolls_back_across_birth_publication() {
        let p = ThreadLifecyclePage::new();
        let peer = ThreadLifecyclePage::new();
        let r = p.stock(0, ident(1)).unwrap();
        let r = p.record_born(p.claim(r).unwrap(), born(0)).unwrap();
        let admission = p.begin_exit(r).unwrap();
        p.close_for_fork().unwrap();
        assert_eq!(p.claimed_count(), 1, "fork did not see the exit window");
        assert_eq!(peer.claimed_count(), 0);
        p.publish(r).unwrap();
        drop(admission);
        assert_eq!(p.claimed_count(), 0);
        assert_eq!(st(&p, 0), EntryState::Published);
        p.reopen_after_fork().unwrap();
        let admission = p.begin_exit(r).unwrap();
        p.close_for_fork().unwrap();
        admission.commit().unwrap();
        assert_eq!(p.claimed_count(), 0);
        assert_eq!(st(&p, 0), EntryState::ExitedInZone);
        assert_eq!(peer.gate(), GateState::Open);
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
            p.begin_exit(r).and_then(ExitAdmission::commit),
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
        p.begin_exit(r).and_then(ExitAdmission::commit).unwrap();
        assert_eq!(
            p.begin_exit(r).and_then(ExitAdmission::commit),
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
            p.claim(EntryRef::new(99, 1)),
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
    fn clear_child_tid_codec_round_trips_and_never_tags_a_user_address() {
        use carrick_guest_arch::UserVa;
        let limit = ClearChildTidState::USER_ADDRESS_LIMIT;
        for address in [4, 0x1004, 0x7fff_ffff_f000, limit - 4] {
            let pending = ClearChildTidState::for_user_address(address);
            assert_eq!(pending, ClearChildTidState::Pending(UserVa::new(address)));
            assert_eq!(pending.encode(), address, "a pending word is the address");
            assert_eq!(ClearChildTidState::decode(pending.encode()), pending);
            let cleared = ClearChildTidState::ClearedInZone(UserVa::new(address));
            assert_ne!(cleared.encode(), address);
            assert_eq!(ClearChildTidState::decode(cleared.encode()), cleared);
            assert_eq!(cleared.pending(), None);
        }
        for not_user in [0, limit, 1 << 63, u64::MAX] {
            assert_eq!(
                ClearChildTidState::for_user_address(not_user),
                ClearChildTidState::None
            );
        }
        assert_eq!(ClearChildTidState::decode(0), ClearChildTidState::None);
        assert_eq!(
            ClearChildTidState::decode(1 << 63),
            ClearChildTidState::None
        );

        let s = ThreadControlSlot::new();
        s.set_clear_child_tid(0x1004);
        assert_eq!(s.clear_child_tid(), 0x1004);
        s.mark_child_tid_cleared_in_zone(0x2000);
        assert!(
            !s.child_tid_cleared_in_zone_at(0x1004),
            "only the pending address"
        );
        s.mark_child_tid_cleared_in_zone(0x1004);
        assert_eq!(s.clear_child_tid(), 0);
        assert!(s.child_tid_cleared_in_zone_at(0x1004));
        s.set_clear_child_tid(1 << 63);
        assert_eq!(s.clear_child_tid_state(), ClearChildTidState::None);
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
    fn visible_tid_belongs_to_each_live_slot_and_survives_birth() {
        let first = ThreadControlSlot::new();
        let second = ThreadControlSlot::new();
        assert_eq!(first.visible_tid(), None);
        assert!(!first.publish_visible_tid(0));
        assert!(first.publish_visible_tid(41));
        assert!(second.publish_visible_tid(73));
        assert!(first.publish_visible_tid(41));
        assert!(!first.publish_visible_tid(73));
        let page = ThreadLifecyclePage::new();
        let entry = page.stock(0, ident(1)).unwrap();
        first.reset_for_birth(BlockedMask(0), 0, entry).unwrap();
        assert_eq!(first.visible_tid(), Some(41));
        assert_eq!(second.visible_tid(), Some(73));
        first.reset_for_host_birth(BlockedMask(0)).unwrap();
        assert_eq!(first.visible_tid(), None);
        assert_eq!(second.visible_tid(), Some(73));
        assert!(first.publish_visible_tid(91));
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
        s.reset_for_birth(BlockedMask(0x10), 0x7000, r).unwrap();
        assert_eq!(s.entry(), Some(r));
        assert_eq!(s.blocked(), BlockedMask(0x10));
        assert_eq!(s.robust_list(), (0, 0));
        assert!(s.read_altstack().is_disabled());
        assert_eq!(s.clear_child_tid(), 0x7000);
        s.set_clear_child_tid(0);
        assert_eq!(s.clear_child_tid(), 0);
        s.reset_for_host_birth(BlockedMask(0x20)).unwrap();
        assert_eq!(s.entry(), None);
        assert_eq!(s.blocked(), BlockedMask(0x20));
        assert_eq!(s.robust_list(), (0, 0));
        assert!(s.read_altstack().is_disabled());
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

// Literal wire layout captured from 3fd7862be on a 64-bit host.
// Keep these values fixed when moving the shared kernel implementation.
#[cfg(test)]
mod layout_manifest {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    macro_rules! field {
        ($record:ty, $field:ident, $ty:ty, $offset:literal, $size:literal, $align:literal) => {
            // Type-check the manifest's field type without constructing a record.
            let _ = |record: &$record| {
                let _: &$ty = &record.$field;
            };
            assert_eq!(
                (
                    offset_of!($record, $field),
                    size_of::<$ty>(),
                    align_of::<$ty>()
                ),
                ($offset, $size, $align),
                concat!(stringify!($record), "::", stringify!($field))
            );
        };
    }

    #[test]
    fn pool_entry() {
        assert_eq!((size_of::<PoolEntry>(), align_of::<PoolEntry>()), (80, 16));
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |PoolEntry {
                     state: _,
                     tid: _,
                     visible_tid: _,
                     thread_serial: _,
                     uid_credit: _,
                     caller_task: _,
                     caller_serial: _,
                     clone_flags: _,
                     clear_child_tid: _,
                     blocked: _,
                     birth: _,
                 }: PoolEntry| {};
        field!(PoolEntry, state, AtomicEntry, 0, 8, 8);
        field!(PoolEntry, tid, AtomicU32, 8, 4, 4);
        field!(PoolEntry, visible_tid, AtomicU32, 12, 4, 4);
        field!(PoolEntry, thread_serial, AtomicU64, 16, 8, 8);
        field!(PoolEntry, uid_credit, AtomicU64, 24, 8, 8);
        field!(PoolEntry, caller_task, AtomicU64, 32, 8, 8);
        field!(PoolEntry, caller_serial, AtomicU64, 40, 8, 8);
        field!(PoolEntry, clone_flags, AtomicU64, 48, 8, 8);
        field!(PoolEntry, clear_child_tid, AtomicU64, 56, 8, 8);
        field!(PoolEntry, blocked, AtomicU64, 64, 8, 8);
        field!(
            PoolEntry,
            birth,
            carrick_core_abi::entry::AtomicBirthSerial,
            72,
            8,
            8
        );
    }

    #[test]
    fn thread_control_slot() {
        assert_eq!(
            (
                size_of::<ThreadControlSlot>(),
                align_of::<ThreadControlSlot>()
            ),
            (256, 64)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |ThreadControlSlot {
                     visible_tid: _,
                     blocked: _,
                     forwarded_saved_mask: _,
                     forwarded_mask_armed: _,
                     alt_seq: _,
                     alt_sp: _,
                     alt_size: _,
                     alt_flags: _,
                     robust_len: _,
                     robust_head: _,
                     clear_child_tid: _,
                     entry: _,
                     pending: _,
                     zone_seq: _,
                     zone_incarnation: _,
                     zone_id: _,
                     host_exit_requested: _,
                     retired_task: _,
                     retired_birth: _,
                     retired_thread: _,
                     birth_task: _,
                     birth_serial: _,
                     birth_thread: _,
                     non_interrupting: _,
                     native_pending: _,
                     native_pending_writer: _,
                     affinity: _,
                     affinity_host_alias: _,
                     affinity_guest_alias: _,
                 }: ThreadControlSlot| {};
        field!(ThreadControlSlot, visible_tid, AtomicU32, 0, 4, 4);
        field!(ThreadControlSlot, blocked, AtomicU64, 8, 8, 8);
        field!(ThreadControlSlot, forwarded_saved_mask, AtomicU64, 16, 8, 8);
        field!(ThreadControlSlot, forwarded_mask_armed, AtomicU32, 24, 4, 4);
        field!(ThreadControlSlot, alt_seq, AtomicU64, 32, 8, 8);
        field!(ThreadControlSlot, alt_sp, AtomicU64, 40, 8, 8);
        field!(ThreadControlSlot, alt_size, AtomicU64, 48, 8, 8);
        field!(ThreadControlSlot, alt_flags, AtomicU32, 56, 4, 4);
        field!(ThreadControlSlot, robust_len, AtomicU32, 60, 4, 4);
        field!(ThreadControlSlot, robust_head, AtomicU64, 64, 8, 8);
        field!(ThreadControlSlot, clear_child_tid, AtomicU64, 72, 8, 8);
        field!(ThreadControlSlot, entry, AtomicU64, 80, 8, 8);
        field!(ThreadControlSlot, pending, PendingSummary, 88, 8, 8);
        field!(ThreadControlSlot, zone_seq, AtomicU64, 96, 8, 8);
        field!(ThreadControlSlot, zone_incarnation, AtomicU64, 104, 8, 8);
        field!(ThreadControlSlot, zone_id, AtomicU32, 112, 4, 4);
        field!(
            ThreadControlSlot,
            host_exit_requested,
            carrick_core::lifecycle::MemberControlAuthority,
            116,
            4,
            4
        );
        field!(ThreadControlSlot, retired_task, AtomicU64, 120, 8, 8);
        field!(
            ThreadControlSlot,
            retired_birth,
            carrick_core_abi::entry::AtomicBirthSerial,
            128,
            8,
            8
        );
        field!(ThreadControlSlot, retired_thread, AtomicU64, 136, 8, 8);
        field!(ThreadControlSlot, birth_task, AtomicU64, 144, 8, 8);
        field!(
            ThreadControlSlot,
            birth_serial,
            carrick_core_abi::entry::AtomicBirthSerial,
            152,
            8,
            8
        );
        field!(ThreadControlSlot, birth_thread, AtomicU64, 160, 8, 8);
        field!(ThreadControlSlot, non_interrupting, AtomicU64, 168, 8, 8);
        field!(ThreadControlSlot, native_pending, PendingSummary, 176, 8, 8);
        field!(
            ThreadControlSlot,
            native_pending_writer,
            AtomicU32,
            184,
            4,
            4
        );
        field!(
            ThreadControlSlot,
            affinity,
            carrick_core::affinity::AffinityAuthority,
            192,
            32,
            8
        );
        field!(ThreadControlSlot, affinity_host_alias, AtomicU64, 224, 8, 8);
        field!(
            ThreadControlSlot,
            affinity_guest_alias,
            AtomicU64,
            232,
            8,
            8
        );
    }

    #[test]
    fn native_signal_owner_requires_explicit_graph_admission() {
        let control = ThreadControlSlot::new();
        control.reset_for_host_birth(BlockedMask(0)).unwrap();
        let custody = carrick_core::lifecycle::MemberControlCustody::retain(&control).unwrap();
        custody.commit_registration();
        assert!(!control.native_signal_owner());
        custody.commit_native_signal_owner();
        assert!(control.native_signal_owner());
        drop(custody);
        control.reset_for_host_birth(BlockedMask(0)).unwrap();
        assert!(!control.native_signal_owner());
    }

    #[test]
    fn thread_lifecycle_page() {
        assert_eq!(
            (
                size_of::<ThreadLifecyclePage>(),
                align_of::<ThreadLifecyclePage>()
            ),
            (4096, 4096)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |ThreadLifecyclePage {
                     gate: _,
                     live: _,
                     pending: _,
                     entries: _,
                     serving: _,
                     ledger_host: _,
                     ledger_guest: _,
                     controls: _,
                     exit_wait_mm: _,
                     exit_wait_address: _,
                     host_born: _,
                     host_birth_mutations: _,
                     terminal: _,
                     closing_verdict: _,
                 }: ThreadLifecyclePage| {};
        field!(ThreadLifecyclePage, gate, AtomicU32, 0, 4, 4);
        field!(ThreadLifecyclePage, live, AtomicU32, 4, 4, 4);
        field!(ThreadLifecyclePage, pending, PendingSummary, 8, 8, 8);
        field!(
            ThreadLifecyclePage,
            entries,
            [PoolEntry; THREAD_POOL_ENTRIES],
            16,
            640,
            16
        );
        field!(ThreadLifecyclePage, serving, AtomicU32, 656, 4, 4);
        field!(ThreadLifecyclePage, ledger_host, AtomicU64, 664, 8, 8);
        field!(ThreadLifecyclePage, ledger_guest, AtomicU64, 672, 8, 8);
        field!(
            ThreadLifecyclePage,
            controls,
            [AtomicU64; THREAD_POOL_ENTRIES],
            680,
            64,
            8
        );
        field!(ThreadLifecyclePage, exit_wait_mm, AtomicU64, 744, 8, 8);
        field!(ThreadLifecyclePage, exit_wait_address, AtomicU64, 752, 8, 8);
        field!(
            ThreadLifecyclePage,
            host_born,
            [HostBornMember; THREAD_POOL_ENTRIES],
            760,
            256,
            8
        );
        field!(
            ThreadLifecyclePage,
            host_birth_mutations,
            AtomicU32,
            1016,
            4,
            4
        );
        field!(
            ThreadLifecyclePage,
            terminal,
            carrick_core::terminal::ProcessExitCustody,
            1020,
            8,
            4
        );
        field!(
            ThreadLifecyclePage,
            closing_verdict,
            ClosingVerdictRecord,
            1032,
            88,
            8
        );
    }
}

#[cfg(test)]
mod affinity_seed_tests {
    #![allow(clippy::unwrap_used)]
    extern crate std;
    #[test]
    fn quiescent_affinity_seed_refuses_live_residency_without_panicking() {
        let slot = super::ThreadControlSlot::new();
        slot.initialize_affinity(carrick_core::affinity::CpuAffinity::all(2));
        struct Quiet;
        impl carrick_core::affinity::AffinityNotifier for Quiet {
            fn notify(&mut self, _: carrick_core::affinity::AffinityNotification) {}
        }
        let token = slot.affinity_authority().bind(0, &mut Quiet).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            slot.set_affinity(carrick_core::affinity::CpuAffinity::single(1))
        }));
        assert!(
            result.is_ok(),
            "live storage misuse must return a typed refusal"
        );
        assert_eq!(result.unwrap(), Err(super::AffinitySeedRefused));
        assert_eq!(slot.affinity().words(), &[3]);
        assert!(slot.affinity_authority().unbind(token));
    }
}
