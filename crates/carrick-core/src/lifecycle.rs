//! Neutral exact-incarnation lifecycle transitions over retained storage.
pub use carrick_core_abi::lifecycle::*;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub mod stock;

/// Independent diagnostic observations, never a settlement or retirement proof.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct LifecycleCensus {
    pub gate: GateState,
    pub live: u32,
    pub claimed: usize,
}

/// Keep raw membership observations with their neutral owner. Consumers may
/// render this sample, but must retain the owned terminal protocol for decisions.
pub fn census(page: &impl Lifecycle) -> LifecycleCensus {
    LifecycleCensus {
        gate: page.gate(),
        live: page.live(),
        claimed: page.claimed_count(),
    }
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum ExpectedExitReceipt {
    Pool,
    Host,
    AlreadyExited,
}

/// Whether a page incarnation still requires a retained control reference
/// while preparing terminal custody. Recycled entries carry no such reference.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum PoolControlDisposition {
    Retain,
    Released,
}

/// The exit path recorded on one exact member's retained custody. A pool
/// entry word can be reaped or restocked while that member is unregistering.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum MemberExitKind {
    Active,
    InZone,
    HostRetiring,
    Stale,
}

/// Proof that host retirement publication is serialized by the registry write
/// lock. Safe host issuance belongs to the registry guard adapter.
///
/// ```compile_fail
/// use carrick_core::lifecycle::RegistryWriteHeld;
/// let proof = RegistryWriteHeld { _guard: core::marker::PhantomData };
/// ```
///
/// ```compile_fail
/// use carrick_core::lifecycle::RegistryWriteHeld;
/// let proof = RegistryWriteHeld::default();
/// ```
pub struct RegistryWriteHeld<'guard> {
    _guard: core::marker::PhantomData<&'guard mut ()>,
}
impl<'guard> RegistryWriteHeld<'guard> {
    /// # Safety
    /// The caller must hold the authoritative registry write guard for the
    /// token's entire lifetime. Only the host registry guard adapter may call
    /// this in production; passing an unlocked registry is unsound authority.
    pub unsafe fn from_write_guard<T: ?Sized>(_guard: &'guard T) -> Self {
        Self {
            _guard: core::marker::PhantomData,
        }
    }
}
#[cfg(any(test, feature = "host-test"))]
impl RegistryWriteHeld<'static> {
    /// VM-free fixtures with no host registry may exercise the neutral cells.
    pub fn for_test() -> Self {
        Self {
            _guard: core::marker::PhantomData,
        }
    }
}

const IN_ZONE_COMMITTED: u32 = 4;
const HOST_RETIRING: u32 = 8;

const GRAPH_REGISTERED: u32 = 16;
const NATIVE_SIGNAL_OWNER: u32 = 32;
const ZONE_TERMINAL: u32 = 64;
const ZONE_HOST_TERMINAL: u32 = 128;
const ABI_EXIT_PENDING: u32 = 256;
const MEMBERSHIP_CLAIMED: u32 = 512;
// Reserved for layer 2. No production path arms it while Busy is disabled.
const MEMBER_WAITER: u32 = 1024;
const GRAPH_REFERENCE: u32 = 2048;

#[derive(::core::clone::Clone, ::core::marker::Copy)]
pub(crate) enum NativeExitCompletion {
    Member,
    AbiExit,
}
const RESETTING: u32 = 1 << 31;
const REFERENCES: u32 = RESETTING - GRAPH_REFERENCE;

/// Exclusive live-unit reservation for one member. Both host graph cleanup
/// and native exit use this same admission before decrementing the page.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum MemberMembershipError {
    AlreadyTerminal,
    InFlight,
    Floor,
    InvalidMember,
}

struct MemberExitClaim<'a, W: crate::cancellation::CancellationWord> {
    word: &'a W,
    waiter: Option<&'a MemberReleaseWaiter>,
    committed: bool,
}
fn claim_member_exit<W: crate::cancellation::CancellationWord>(
    word: &W,
) -> Result<MemberExitClaim<'_, W>, MemberMembershipError> {
    let mut observed = word.load(Ordering::Acquire);
    loop {
        if observed & (ZONE_TERMINAL | IN_ZONE_COMMITTED) != 0 {
            return Err(MemberMembershipError::AlreadyTerminal);
        }
        if observed & (MEMBERSHIP_CLAIMED | HOST_RETIRING) != 0 {
            return Err(MemberMembershipError::InFlight);
        }
        if observed & RESETTING != 0 || observed & REFERENCES == REFERENCES {
            return Err(MemberMembershipError::InvalidMember);
        }
        match word.compare_exchange(
            observed,
            (observed | MEMBERSHIP_CLAIMED) + GRAPH_REFERENCE,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Ok(MemberExitClaim {
                    word,
                    waiter: None,
                    committed: false,
                });
            }
            Err(actual) => observed = actual,
        }
    }
}
/// One successful RMW both publishes release and consumes the waiter bit.
/// A separate load/clear could lose an arm or observe it twice. CAS retries
/// only atomic interference; no lock, callback or physical wake runs here.
fn finish_member_word<W: crate::cancellation::CancellationWord>(
    word: &W,
    set: u32,
    subtract: u32,
    order: Ordering,
) -> bool {
    let mut observed = word.load(Ordering::Acquire);
    loop {
        let clear_waiter =
            if subtract & REFERENCES == 0 || observed & REFERENCES <= subtract & REFERENCES {
                MEMBER_WAITER
            } else {
                0
            };
        let next = ((observed | set) & !clear_waiter) - subtract;
        match word.compare_exchange(observed, next, order, Ordering::Acquire) {
            Ok(previous) => return previous & clear_waiter != 0,
            Err(actual) => observed = actual,
        }
    }
}
impl<W: crate::cancellation::CancellationWord> Drop for MemberExitClaim<'_, W> {
    fn drop(&mut self) {
        if finish_member_word(
            self.word,
            0,
            GRAPH_REFERENCE
                + if self.committed {
                    0
                } else {
                    MEMBERSHIP_CLAIMED
                },
            Ordering::AcqRel,
        ) && let Some(waiter) = self.waiter
        {
            waiter.notify();
        }
    }
}

/// Shared ownership and exit provenance for one control incarnation. Only
/// core's admitted exit operations can publish its terminal provenance.
#[repr(transparent)]
#[derive(::core::fmt::Debug)]
pub struct MemberExitCustody {
    word: AtomicU32,
}
impl Default for MemberExitCustody {
    fn default() -> Self {
        Self::new()
    }
}
impl MemberExitCustody {
    pub const fn new() -> Self {
        Self {
            word: AtomicU32::new(0),
        }
    }
    #[cfg(test)]
    pub(crate) fn test_record(&self, word: u32) {
        self.word.store(word, Ordering::Release);
    }
    /// Irrevocable terminal custody is published before its record is freed.
    pub(crate) fn commit_zone_terminal(&self, completion: NativeExitCompletion) {
        let abi = match completion {
            NativeExitCompletion::Member => 0,
            NativeExitCompletion::AbiExit => ABI_EXIT_PENDING,
        };
        let _waiter = finish_member_word(&self.word, ZONE_TERMINAL | abi, 0, Ordering::AcqRel);
    }
    pub(crate) fn abi_exit_pending(&self) -> bool {
        self.word.load(Ordering::Acquire) & ABI_EXIT_PENDING != 0
    }
    pub(crate) fn zone_terminal(&self) -> bool {
        self.word.load(Ordering::Acquire) & ZONE_TERMINAL != 0
    }
    pub(crate) fn commit_host_zone_terminal(&self, _registry: &RegistryWriteHeld<'_>) {
        let _waiter = finish_member_word(
            &self.word,
            ZONE_TERMINAL | ZONE_HOST_TERMINAL | HOST_RETIRING,
            0,
            Ordering::AcqRel,
        );
    }
    pub(crate) fn native_zone_terminal(&self) -> bool {
        let word = self.word.load(Ordering::Acquire);
        word & (ZONE_TERMINAL | ZONE_HOST_TERMINAL) == ZONE_TERMINAL
    }
    pub fn referenced(&self) -> bool {
        self.word.load(Ordering::Acquire) & REFERENCES != 0
    }
    /// The native graph has accepted signal delivery for this exact member.
    /// This bit is distinct from generic graph registration and host receipts.
    pub fn native_signal_owner(&self) -> bool {
        self.word.load(Ordering::Acquire) & NATIVE_SIGNAL_OWNER != 0
    }
    pub fn unregister_receipt(&self) -> bool {
        self.word.load(Ordering::Acquire) & (GRAPH_REGISTERED | REFERENCES) == GRAPH_REGISTERED
    }
    pub fn host_exit_requested(&self) -> bool {
        self.word.load(Ordering::Acquire) & 1 != 0
    }
    pub fn host_receipt_published(&self) -> bool {
        self.word.load(Ordering::Acquire) & 2 != 0
    }
}
/// The storage owner alone holds mutation authority. Borrowed member views
/// expose custody observations, never the capability that resets or publishes.
#[repr(transparent)]
#[derive(::core::fmt::Debug, ::core::default::Default)]
pub struct MemberControlAuthority {
    custody: MemberExitCustody,
}
impl MemberControlAuthority {
    pub const fn new() -> Self {
        Self {
            custody: MemberExitCustody::new(),
        }
    }
    pub fn custody(&self) -> &MemberExitCustody {
        &self.custody
    }
    pub fn request_host_exit(&self) {
        self.custody.word.fetch_or(1, Ordering::Release);
    }
    pub fn publish_host_receipt(&self) {
        let _waiter = finish_member_word(
            &self.custody.word,
            2 | GRAPH_REGISTERED,
            0,
            Ordering::AcqRel,
        );
    }
    pub fn reserve_reset(&self) -> Result<MemberReset<'_>, TransitionError> {
        self.custody
            .word
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                (word & (REFERENCES | RESETTING) == 0).then_some(RESETTING)
            })
            .map_err(|_| TransitionError::StaleGeneration)?;
        Ok(MemberReset(&self.custody))
    }
}
/// Exclusive reset authority; retained graph references make it unavailable.
pub struct MemberReset<'a>(&'a MemberExitCustody);
impl Drop for MemberReset<'_> {
    fn drop(&mut self) {
        self.0.word.store(0, Ordering::Release);
    }
}

/// A retained source of progress for a control storage owner.
pub trait MemberControlRelease: Send + Sync {
    /// Publish progress after the final retained reference is returned. The
    /// observer owns its exact notification source; this is not a reuse proof.
    fn released(&self);
}

unsafe fn finish_member_release<R: MemberControlRelease>(ptr: *const (), notify: bool) {
    // SAFETY: `ptr` was produced by `Arc::into_raw` in `arm_member_release` and
    // claimed exclusively by atomic swap on `MemberReleaseWaiter::finish`.
    let release = unsafe { alloc::sync::Arc::from_raw(ptr.cast::<R>()) };
    if notify {
        release.released();
    }
}

/// Atomic waiter slot for a control storage owner's final-reference wake.
#[repr(C)]
#[derive(::core::fmt::Debug, ::core::default::Default)]
pub struct MemberReleaseWaiter {
    data: AtomicU64,
    finish: AtomicU64,
}
impl MemberReleaseWaiter {
    pub const fn new() -> Self {
        Self {
            data: AtomicU64::new(0),
            finish: AtomicU64::new(0),
        }
    }
    pub(crate) fn notify(&self) {
        self.take(true);
    }
    fn take(&self, notify: bool) {
        loop {
            match self.finish.load(Ordering::Acquire) {
                0 => return,
                1 => core::hint::spin_loop(),
                old_finish => {
                    if self
                        .finish
                        .compare_exchange(old_finish, 1, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        let old_data = self.data.swap(0, Ordering::Relaxed);
                        self.finish.store(0, Ordering::Release);
                        // SAFETY: `old_data` and `old_finish` were installed by `arm_member_release`.
                        unsafe {
                            let finish: unsafe fn(*const (), bool) =
                                core::mem::transmute(old_finish as usize);
                            finish(old_data as usize as *const (), notify);
                        }
                        return;
                    }
                }
            }
        }
    }
}

/// Arm `MEMBER_WAITER` on an occupied control so the final reference drop wakes `release` once.
/// Returns `false` when the control is already unreferenced or resetting.
pub fn arm_member_release<'a, R: MemberControlRelease + 'a>(
    member: &'a (impl MemberControl + ?Sized),
    release: alloc::sync::Arc<R>,
) -> bool {
    let Some(waiter) = member.release_waiter() else {
        return false;
    };
    let word = &member.exit_custody().word;
    let init = word.load(Ordering::Acquire);
    if init & RESETTING != 0 || init & REFERENCES == 0 {
        return false;
    }
    let raw_data = alloc::sync::Arc::into_raw(release) as usize as u64;
    let raw_finish = finish_member_release::<R> as *const () as usize as u64;
    let old = loop {
        match waiter.finish.load(Ordering::Acquire) {
            0 => {
                if waiter
                    .finish
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break None;
                }
            }
            1 => core::hint::spin_loop(),
            old_finish => {
                if word.load(Ordering::Acquire) & MEMBER_WAITER == 0 {
                    core::hint::spin_loop();
                    continue;
                }
                if waiter
                    .finish
                    .compare_exchange(old_finish, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let old_data = waiter.data.swap(0, Ordering::Relaxed);
                    break Some((old_data, old_finish));
                }
            }
        }
    };
    let mut observed = word.load(Ordering::Acquire);
    loop {
        if observed & RESETTING != 0 || observed & REFERENCES == 0 {
            waiter.finish.store(0, Ordering::Release);
            if let Some((old_data, old_finish)) = old {
                // SAFETY: `old_data` and `old_finish` were installed by a prior `arm_member_release`.
                unsafe {
                    let finish: unsafe fn(*const (), bool) =
                        core::mem::transmute(old_finish as usize);
                    finish(old_data as usize as *const (), true);
                }
            }
            // SAFETY: `raw_data` was produced by `Arc::into_raw` above and never published.
            unsafe {
                drop(alloc::sync::Arc::from_raw(raw_data as usize as *const R));
            }
            return false;
        }
        match word.compare_exchange(
            observed,
            observed | MEMBER_WAITER,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                waiter.data.store(raw_data, Ordering::Relaxed);
                waiter.finish.store(raw_finish, Ordering::Release);
                if let Some((old_data, old_finish)) = old {
                    // SAFETY: `old_data` and `old_finish` were installed by a prior `arm_member_release`.
                    unsafe {
                        let finish: unsafe fn(*const (), bool) =
                            core::mem::transmute(old_finish as usize);
                        finish(
                            old_data as usize as *const (),
                            observed & MEMBER_WAITER == 0,
                        );
                    }
                }
                return true;
            }
            Err(actual) => observed = actual,
        }
    }
}

/// An owned control reference that prevents allocation reuse. A committed
/// registration publishes its unregister receipt when every reference drops.
pub struct MemberControlCustody<'a, T: MemberControl + ?Sized> {
    control: &'a T,
}
impl<'a, T: MemberControl + ?Sized> MemberControlCustody<'a, T> {
    pub fn retain(control: &'a T) -> Result<Self, TransitionError> {
        control
            .exit_custody()
            .word
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                if word & RESETTING != 0 || word & REFERENCES == REFERENCES {
                    None
                } else {
                    Some(word + GRAPH_REFERENCE)
                }
            })
            .map_err(|_| TransitionError::StaleGeneration)?;
        Ok(Self { control })
    }
    /// Commit a retained reference into the graph or terminal receipt set.
    /// Speculative retains must drop without manufacturing an unregister receipt.
    pub fn commit_registration(&self) {
        self.control
            .exit_custody()
            .word
            .fetch_or(GRAPH_REGISTERED, Ordering::Release);
    }
    /// Publish only after the native registry can authenticate this member.
    pub fn commit_native_signal_owner(&self) {
        self.control
            .exit_custody()
            .word
            .fetch_or(NATIVE_SIGNAL_OWNER, Ordering::Release);
    }
    pub fn control(&self) -> &'a T {
        self.control
    }
}
impl<T: MemberControl + ?Sized> core::ops::Deref for MemberControlCustody<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.control
    }
}
impl<T: MemberControl + ?Sized> Drop for MemberControlCustody<'_, T> {
    fn drop(&mut self) {
        if finish_member_word(
            &self.control.exit_custody().word,
            0,
            GRAPH_REFERENCE,
            Ordering::AcqRel,
        ) && let Some(waiter) = self.control.release_waiter()
        {
            waiter.notify();
        }
    }
}

/// Exact member custody, reset exclusively before each birth. The entry
/// reference is the generation key; the flag word is member-owned storage.
pub trait MemberControl {
    fn member_entry(&self) -> Option<EntryRef>;
    fn exit_custody(&self) -> &MemberExitCustody;
    fn host_retirement(&self) -> Option<crate::terminal::HostThreadRetirementReceipt>;
    fn release_waiter(&self) -> Option<&MemberReleaseWaiter> {
        None
    }
}

pub(crate) fn reserve_member_exit<'a>(
    page: &'a impl Lifecycle,
    member: &'a dyn MemberControl,
) -> Result<NonfinalExitMembership<'a>, MemberMembershipError> {
    if member.host_retirement().is_some() {
        return Err(MemberMembershipError::AlreadyTerminal);
    }
    let mut claim = claim_member_exit(&member.exit_custody().word)?;
    claim.waiter = member.release_waiter();
    let mut membership = crate::terminal::reserve_thread_exit_membership(page)
        .map_err(|_| MemberMembershipError::Floor)?;
    membership.member = Some(claim);
    Ok(membership)
}

pub fn recorded_member_exit_kind(
    member: &dyn MemberControl,
    entry: Option<EntryRef>,
) -> MemberExitKind {
    if member.member_entry() != entry {
        return MemberExitKind::Stale;
    }
    let word = member.exit_custody().word.load(Ordering::Acquire);
    if word & HOST_RETIRING != 0 {
        MemberExitKind::HostRetiring
    } else if word & IN_ZONE_COMMITTED != 0 {
        MemberExitKind::InZone
    } else {
        MemberExitKind::Active
    }
}

/// The first pool member a Closing owner would still wait for, observed for a
/// census. Independent atomic reads; never a settlement proof.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct PoolReadinessBlocker {
    pub index: usize,
    pub generation: u64,
    pub state: EntryState,
    /// `None` when the caller reached no control for this entry.
    pub kind: Option<MemberExitKind>,
    pub host_retirement: Option<crate::terminal::HostThreadRetirementReceipt>,
    pub expected_host: Option<crate::terminal::ThreadBirthIdentity>,
}

/// Pool half of a Closing readiness census: entries in `claimed_count`
/// (Claimed or Exiting) and the first unreturned member receipt, with the
/// same returned rule as `TerminalCustody::observe_members`. Bounded by the
/// pool; never waits or mutates.
pub fn pool_readiness_census<'a>(
    page: &impl Lifecycle,
    controls: impl Fn(EntryRef) -> Option<&'a dyn MemberControl>,
    expected_host: impl Fn(EntryRef) -> Option<crate::terminal::ThreadBirthIdentity>,
) -> (usize, Option<PoolReadinessBlocker>) {
    let mut exiting = 0;
    let mut first = None;
    for index in 0..page.entry_count() {
        let Some((generation, state)) = page.state(index) else {
            continue;
        };
        if matches!(
            state,
            EntryState::Claimed | EntryState::ExitingBorn | EntryState::ExitingPublished
        ) {
            exiting += 1;
        }
        if first.is_some()
            || !matches!(
                state,
                EntryState::Claimed
                    | EntryState::Born
                    | EntryState::Published
                    | EntryState::ExitingBorn
                    | EntryState::ExitingPublished
            )
        {
            continue;
        }
        let entry = EntryRef::new(index as u32, generation);
        let control = controls(entry);
        let kind = control.map(|control| recorded_member_exit_kind(control, Some(entry)));
        let host_retirement = control.and_then(|control| control.host_retirement());
        let expected = expected_host(entry);
        let returned = match kind {
            Some(MemberExitKind::InZone) => true,
            Some(MemberExitKind::HostRetiring) => host_retirement
                .zip(expected)
                .is_some_and(|(receipt, expected)| receipt.acknowledges(expected)),
            _ => false,
        };
        if !returned {
            first = Some(PoolReadinessBlocker {
                index,
                generation,
                state,
                kind,
                host_retirement,
                expected_host: expected,
            });
        }
    }
    (exiting, first)
}

/// A revoked, never-published birth has no ring graph reference to retire.
/// Publish its release receipt at the successful revocation, not a later scan.
pub fn revoke_unborn_control(
    page: &dyn Lifecycle,
    entry: EntryRef,
    member: &dyn MemberControl,
) -> Result<(), TransitionError> {
    if member.member_entry().is_some_and(|actual| actual != entry) {
        return Err(TransitionError::StaleGeneration);
    }
    page.revoke(entry)?;
    member
        .exit_custody()
        .word
        .fetch_or(GRAPH_REGISTERED, Ordering::Release);
    Ok(())
}

pub fn retire_host_member(
    page: &dyn Lifecycle,
    entry: EntryRef,
    member: &dyn MemberControl,
    membership: NonfinalExitMembership<'_>,
    _registry: &RegistryWriteHeld<'_>,
) -> Result<(), TransitionError> {
    let _pin = MemberControlCustody::retain(member)?;
    if !core::ptr::addr_eq(page, membership.page) {
        return Err(TransitionError::StaleGeneration);
    }
    if member.member_entry() != Some(entry) {
        return Err(TransitionError::StaleGeneration);
    }
    let _waiter = finish_member_word(
        &member.exit_custody().word,
        HOST_RETIRING,
        0,
        Ordering::SeqCst,
    );
    if let Err(error) = page.retire_published(entry) {
        if member.member_entry() == Some(entry) {
            member
                .exit_custody()
                .word
                .fetch_and(!HOST_RETIRING, Ordering::SeqCst);
        }
        return Err(error);
    }
    membership.publish();
    Ok(())
}

/// Publish an exec/group-close cancellation for one exact pool member. The
/// caller has already reserved its nonfinal live unit; this operation binds
/// that unit to the member's in-zone receipt before making the entry reaped.
pub fn retire_cancelled_pool_member(
    page: &dyn Lifecycle,
    entry: EntryRef,
    member: &dyn MemberControl,
    membership: NonfinalExitMembership<'_>,
) -> Result<(), TransitionError> {
    let _pin = MemberControlCustody::retain(member)?;
    if !core::ptr::addr_eq(page, membership.page) || member.member_entry() != Some(entry) {
        return Err(TransitionError::StaleGeneration);
    }
    let _waiter = finish_member_word(
        &member.exit_custody().word,
        IN_ZONE_COMMITTED,
        0,
        Ordering::SeqCst,
    );
    if let Err(error) = page.retire_closing_caller(entry) {
        if member.member_entry() == Some(entry) {
            member
                .exit_custody()
                .word
                .fetch_and(!IN_ZONE_COMMITTED, Ordering::SeqCst);
        }
        return Err(error);
    }
    membership.publish();
    Ok(())
}

/// The exact page owns the storage and retains its ledger notification authority.
/// Linux payload initialization happens between reserve and release publication.
pub trait Lifecycle {
    fn terminal_notification(&self) -> Option<crate::terminal::TerminalNotification> {
        None
    }
    fn pool_control_disposition(&self, entry: EntryRef) -> PoolControlDisposition {
        if self
            .state(entry.index())
            .is_some_and(|(generation, state)| {
                generation == entry.generation()
                    && matches!(
                        state,
                        EntryState::Born
                            | EntryState::Published
                            | EntryState::ExitingBorn
                            | EntryState::ExitingPublished
                    )
            })
        {
            PoolControlDisposition::Retain
        } else {
            PoolControlDisposition::Released
        }
    }
    fn process_exit_custody(&self) -> &crate::terminal::ProcessExitCustody;
    fn host_birth_receipt_returned_exact(
        &self,
        index: usize,
        identity: crate::terminal::ThreadBirthIdentity,
    ) -> bool;
    fn gate_word(&self) -> &AtomicU32;
    fn live_word(&self) -> &AtomicU32;
    fn entry_count(&self) -> usize;
    fn entry_word(&self, index: usize) -> Option<&AtomicEntry>;
    fn activity(&self) -> Option<&ThreadLedgerActivity>;
    /// Host-born publications admitted before Closing but not yet visible.
    fn host_claimed_count(&self) -> usize {
        0
    }
    // ---- gate ----

    fn gate(&self) -> GateState {
        GateState::from_raw(self.gate_word().load(Ordering::SeqCst))
    }
    /// Fork begins: `Open -> ForkClosing`. New claims back out from here on.
    fn close_for_fork(&self) -> Result<(), GateState> {
        self.gate_word()
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
    fn reopen_after_fork(&self) -> Result<(), GateState> {
        self.gate_word()
            .compare_exchange(
                GateState::ForkClosing as u32,
                GateState::Open as u32,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(|_| ())
            .map_err(GateState::from_raw)
    }
    /// Reserve host authority while the post-exec image has no birth binding.
    fn close_awaiting_exec_binding(&self) -> Result<(), GateState> {
        self.transition_gate(GateState::AwaitingExecBinding, GateState::ForkClosing)
    }
    /// Release host authority without admitting births into an unbound image.
    fn await_exec_binding(&self) -> Result<(), GateState> {
        self.transition_gate(GateState::ForkClosing, GateState::AwaitingExecBinding)
    }
    /// Exec drain closed the predecessor as a process transition, rather than
    /// as fork quiescence. Preserve closed admission while the successor's
    /// authenticated binding is installed.
    fn await_exec_binding_after_close(&self) -> Result<(), GateState> {
        self.transition_gate(GateState::Closed, GateState::AwaitingExecBinding)
    }
    /// The new image's executable capacity is installed. This cannot release
    /// a fork's temporary close or a tracer's terminal close.
    fn reopen_after_exec_binding(&self) -> Result<(), GateState> {
        self.transition_gate(GateState::AwaitingExecBinding, GateState::Open)
    }
    fn transition_gate(&self, from: GateState, to: GateState) -> Result<(), GateState> {
        self.gate_word()
            .compare_exchange(from as u32, to as u32, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(GateState::from_raw)
    }
    /// Decline in-zone service without reviving a terminal process.
    fn decline_to_host(&self) {
        let _ = self
            .gate_word()
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |raw| {
                (!GateState::from_raw(raw).is_terminal()).then_some(GateState::HostOnly as u32)
            });
    }
    /// Terminal admission close, from any state.
    fn close(&self) {
        self.gate_word()
            .store(GateState::Closed as u32, Ordering::SeqCst);
    }
    /// Clone and exit admissions a host must drain after `close_for_fork`.
    /// `SeqCst` scan (second half of both claim/gate pairs).
    fn claimed_count(&self) -> usize {
        self.process_exit_custody().external_work()
            + self.host_claimed_count()
            + (0..self.entry_count())
                .filter(|&index| {
                    self.entry_word(index).is_some_and(|e| {
                        matches!(
                            unpack(e.load(Ordering::SeqCst)).1,
                            EntryState::Claimed
                                | EntryState::ExitingBorn
                                | EntryState::ExitingPublished
                        )
                    })
                })
                .count()
    }

    // ---- live count ----

    fn live(&self) -> u32 {
        self.live_word().load(Ordering::SeqCst)
    }
    /// A thread was born: `n -> n+1`. Returns the new count, `None` on
    /// overflow.
    fn thread_born(&self) -> Option<u32> {
        self.live_word()
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .ok()
            .map(|n| n + 1)
    }
    /// Release one live membership only above the caller-selected floor.
    /// Returns the new count; the owner never chooses terminal-exit policy.
    fn release_live(&self, minimum: u32) -> Result<u32, MembershipFloor> {
        self.live_word()
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                if n > minimum { Some(n - 1) } else { None }
            })
            .map(|n| n - 1)
            .map_err(|_| MembershipFloor)
    }

    /// Atomically reserve a nonfinal host exit before its graph publication.
    /// The page word, rather than a potentially lagging graph census, decides
    /// whether this member is last. Dropping an unpublished reservation puts
    /// its membership back.
    fn reserve_nonfinal_exit(&self) -> Result<NonfinalExitMembership<'_>, MembershipFloor>
    where
        Self: Sized,
    {
        self.release_live(1)?;
        Ok(NonfinalExitMembership {
            page: self,
            reserved: Some(ReservedLiveUnit::new()),
            member: None,
        })
    }

    /// A Closing process has already reserved its leader's terminal
    /// membership. Its cancelled host members may therefore take the page
    /// from one live member to zero without publishing process status.
    fn reserve_cancelled_member_exit(&self) -> Result<NonfinalExitMembership<'_>, MembershipFloor>
    where
        Self: Sized,
    {
        self.release_live(0)?;
        Ok(NonfinalExitMembership {
            page: self,
            reserved: Some(ReservedLiveUnit::new()),
            member: None,
        })
    }

    /// Reserve the Closing caller after closed admission and fallible member
    /// preparation. Dropping an unpublished reservation restores its unit.
    fn reserve_closing_caller_exit(&self) -> Result<NonfinalExitMembership<'_>, MembershipFloor>
    where
        Self: Sized,
    {
        self.release_live(0)?;
        Ok(NonfinalExitMembership {
            page: self,
            reserved: Some(ReservedLiveUnit::new()),
            member: None,
        })
    }

    /// Return a live unit taken by one exact exit reservation. The token is
    /// minted only after the same page subtracts that unit.
    fn restore_reserved(&self, _unit: ReservedLiveUnit) {
        let _ = self
            .live_word()
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                // A reserved unit was removed from this page before this
                // non-cloneable token existed, and concurrent births hold
                // distinct bounded pool or registry slots (far fewer than
                // u32::MAX), so this add cannot overflow. Saturate rather
                // than assume: a broken invariant must never become UB.
                Some(n.saturating_add(1))
            });
    }

    /// The caller of group exit has already released its live membership;
    /// its own entry is consumed by Closing rather than by CancelMembers.
    fn retire_closing_caller(&self, entry: EntryRef) -> Result<(), TransitionError> {
        if !self.gate().is_terminal() {
            return Err(TransitionError::GateClosed(self.gate()));
        }
        self.transition(
            entry,
            &[
                EntryState::Born,
                EntryState::Published,
                EntryState::ExitingBorn,
                EntryState::ExitingPublished,
            ],
            EntryState::Reaped,
            Ordering::AcqRel,
        )
    }

    fn state(&self, index: usize) -> Option<(u64, EntryState)> {
        self.entry_word(index)
            .map(|word| unpack(word.load(Ordering::Acquire)))
    }
    /// One exact member has one Closing receipt kind. A completed in-zone
    /// entry cannot acquire a host-retirement obligation while unregistering.
    fn expected_exit_receipt(
        &self,
        member: &dyn MemberControl,
        entry: Option<EntryRef>,
    ) -> ExpectedExitReceipt {
        match recorded_member_exit_kind(member, entry) {
            MemberExitKind::InZone => return ExpectedExitReceipt::AlreadyExited,
            MemberExitKind::HostRetiring | MemberExitKind::Stale => {
                return ExpectedExitReceipt::Host;
            }
            MemberExitKind::Active => {}
        }
        let Some(entry) = entry else {
            return ExpectedExitReceipt::Host;
        };
        match self.state(entry.index()) {
            Some((
                generation,
                EntryState::Born
                | EntryState::Published
                | EntryState::ExitingBorn
                | EntryState::ExitingPublished,
            )) if generation == entry.generation() => ExpectedExitReceipt::Pool,
            _ => ExpectedExitReceipt::Host,
        }
    }
    fn transition(
        &self,
        r: EntryRef,
        from: &[EntryState],
        to: EntryState,
        order: Ordering,
    ) -> Result<(), TransitionError> {
        let e = self
            .entry_word(r.index())
            .ok_or(TransitionError::NoSuchEntry)?;
        let cur = e.load(Ordering::Acquire);
        let (generation, state) = unpack(cur);
        if generation != r.generation() {
            return Err(TransitionError::StaleGeneration);
        }
        if !from.contains(&state) {
            return Err(TransitionError::WrongState(state));
        }
        match e.compare_exchange(cur, pack(generation, to), order, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(now) => {
                let (g, s) = unpack(now);
                if g != r.generation() {
                    Err(TransitionError::StaleGeneration)
                } else {
                    Err(TransitionError::WrongState(s))
                }
            }
        }
    }

    /// Reserve payload initialization in a `Vacant`, `Reaped` or `Revoked` entry,
    /// bumping the generation. Returns the reference to the new incarnation.
    fn reserve_stock(&self, index: usize) -> Result<EntryRef, TransitionError> {
        let e = self.entry_word(index).ok_or(TransitionError::NoSuchEntry)?;
        let cur = e.load(Ordering::Acquire);
        let (generation, state) = unpack(cur);
        if !matches!(
            state,
            EntryState::Vacant | EntryState::Reaped | EntryState::Revoked
        ) {
            return Err(TransitionError::WrongState(state));
        }
        let next = generation + 1;
        e.compare_exchange(
            cur,
            pack(next, EntryState::Stocking),
            Ordering::Acquire,
            Ordering::Acquire,
        )
        .map_err(|now| TransitionError::WrongState(unpack(now).1))?;
        Ok(EntryRef::new(index as u32, next))
    }

    /// EL1 clone: CAS `Reserved -> Claimed`, then check the gate (Dekker with
    /// [`Self::close_for_fork`]). A closed gate backs the claim out.
    fn claim(&self, r: EntryRef) -> Result<ClaimedEntry, TransitionError> {
        self.transition(
            r,
            &[EntryState::Reserved],
            EntryState::Claimed,
            Ordering::SeqCst,
        )?;
        let gate = GateState::from_raw(self.gate_word().load(Ordering::SeqCst));
        if gate != GateState::Open {
            // We own the entry (Claimed): only we can move it, so this
            // store cannot race another transition.
            let e = self
                .entry_word(r.index())
                .ok_or(TransitionError::NoSuchEntry)?;
            e.store(pack(r.generation(), EntryState::Reserved), Ordering::SeqCst);
            return Err(TransitionError::GateClosed(gate));
        }
        Ok(ClaimedEntry(r))
    }

    /// EL1 clone: claim the first `Reserved` entry ([`Self::claim`]).
    /// `GateClosed` as soon as the gate refuses a claim; `PoolEmpty` when no
    /// entry could be claimed (another claimant may have won each one).
    fn claim_any(&self) -> Result<ClaimedEntry, TransitionError> {
        for index in 0..self.entry_count() {
            let e = self.entry_word(index).ok_or(TransitionError::NoSuchEntry)?;
            let (generation, state) = unpack(e.load(Ordering::Acquire));
            if state != EntryState::Reserved {
                continue;
            }
            let r = EntryRef::new(index as u32, generation);
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
    fn unclaim(&self, claim: ClaimedEntry) -> Result<EntryRef, TransitionError> {
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
    fn revoke(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::Reserved],
            EntryState::Revoked,
            Ordering::SeqCst,
        )
    }

    /// EL1 clone: record the Born payload and move `Claimed -> Born`.
    fn complete_birth(&self, claim: ClaimedEntry) -> Result<EntryRef, BirthRefusal> {
        let r = claim.0;
        let activity = self.activity();
        if let Some(activity) = activity {
            activity.announce();
        }
        let result = self.transition(
            r,
            &[EntryState::Claimed],
            EntryState::Born,
            Ordering::Release,
        );
        if result.is_err()
            && let Some(activity) = activity
        {
            let _ = activity.complete(1);
        }
        match result {
            Ok(()) => Ok(r),
            Err(error) => Err(BirthRefusal::new(error, claim)),
        }
    }

    /// Host settle: `Born -> Published`.
    fn publish(&self, r: EntryRef) -> Result<(), TransitionError> {
        loop {
            let (generation, state) = self.state(r.index()).ok_or(TransitionError::NoSuchEntry)?;
            if generation != r.generation() {
                return Err(TransitionError::StaleGeneration);
            }
            let target = match state {
                EntryState::Born => EntryState::Published,
                EntryState::ExitingBorn => EntryState::ExitingPublished,
                _ => return Err(TransitionError::WrongState(state)),
            };
            match self.transition(r, &[state], target, Ordering::AcqRel) {
                Err(TransitionError::WrongState(_)) => continue,
                result => return result,
            }
        }
    }

    /// Claim exit admission before reading the gate (the Dekker peer of
    /// close and drain). A close either refuses us or observes our window.
    fn begin_exit(&self, r: EntryRef) -> Result<ExitAdmission<'_>, TransitionError>
    where
        Self: Sized,
    {
        loop {
            let (generation, state) = self.state(r.index()).ok_or(TransitionError::NoSuchEntry)?;
            if generation != r.generation() {
                return Err(TransitionError::StaleGeneration);
            }
            let target = match state {
                EntryState::Born => EntryState::ExitingBorn,
                EntryState::Published => EntryState::ExitingPublished,
                _ => return Err(TransitionError::WrongState(state)),
            };
            match self.transition(r, &[state], target, Ordering::SeqCst) {
                Err(TransitionError::WrongState(_)) => continue,
                Err(error) => return Err(error),
                Ok(()) => break,
            }
        }
        let admission = ExitAdmission {
            page: self,
            entry: r,
            committed: false,
            irrevocable: false,
        };
        let gate = self.gate();
        if gate != GateState::Open {
            return Err(TransitionError::GateClosed(gate));
        }
        Ok(admission)
    }

    /// Canonical host retirement of an adopted birth. The host owns execution
    /// and has already decremented the live census; no EL1 activity is owed.
    fn retire_published(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::Published],
            EntryState::Reaped,
            Ordering::AcqRel,
        )
    }

    /// Host settle folded the exit: `ExitedInZone -> Reaped`.
    fn reap(&self, r: EntryRef) -> Result<(), TransitionError> {
        self.transition(
            r,
            &[EntryState::ExitedInZone],
            EntryState::Reaped,
            Ordering::AcqRel,
        )
    }
}

#[must_use]
pub struct NonfinalExitMembership<'a> {
    page: &'a dyn Lifecycle,
    reserved: Option<ReservedLiveUnit>,
    member: Option<MemberExitClaim<'a, AtomicU32>>,
}

/// Proof that one live unit was removed from an exact page. Its constructor
/// stays private to the successful reservation paths above.
pub struct ReservedLiveUnit(());

impl ReservedLiveUnit {
    fn new() -> Self {
        Self(())
    }
}

impl NonfinalExitMembership<'_> {
    pub(crate) fn owns_member(&self, member: &dyn MemberControl) -> bool {
        self.member
            .as_ref()
            .is_some_and(|claim| core::ptr::eq(claim.word, &member.exit_custody().word))
    }
    pub(crate) fn rollback(&mut self) {
        if let Some(unit) = self.reserved.take() {
            self.page.restore_reserved(unit);
        }
        // A committed reservation has no refund and keeps terminal provenance.
        self.member.take();
    }
    /// The exact terminal owner crossed its irreversible publication point.
    /// Dropping this token can no longer restore a terminated member's unit.
    pub(crate) fn commit_irrevocable(&mut self) {
        self.reserved.take();
        if let Some(member) = self.member.as_mut() {
            member.committed = true;
        }
    }

    /// The graph's exact-thread retirement and ledger publication completed.
    pub fn publish(mut self) {
        self.commit_irrevocable();
    }
}

impl Drop for NonfinalExitMembership<'_> {
    fn drop(&mut self) {
        self.rollback();
    }
}
/// Non-cloneable ownership of the bounded EL1 exit window. Dropping an
/// unfinished exit restores membership, including a concurrent publication.
pub struct ExitAdmission<'a> {
    page: &'a dyn Lifecycle,
    entry: EntryRef,
    committed: bool,
    irrevocable: bool,
}

impl ExitAdmission<'_> {
    pub(crate) fn rollback(&mut self) {
        self.restore_admission();
        // The old token cannot later publish a newly admitted exit window.
        self.committed = true;
    }
    pub(crate) fn commit_irrevocable(&mut self) {
        self.irrevocable = true;
    }
    pub(crate) fn matches_membership(
        &self,
        entry: Option<EntryRef>,
        membership: &NonfinalExitMembership<'_>,
    ) -> bool {
        !self.committed
            && !self.irrevocable
            && entry == Some(self.entry)
            && core::ptr::addr_eq(self.page, membership.page)
    }
    /// Publish the member-owned exit kind before making the shared entry
    /// reappable. Closing may observe the marker during the admitted window,
    /// but claimed_count prevents settlement until this CAS completes.
    pub fn commit_with_member(self, member: &dyn MemberControl) -> Result<(), TransitionError> {
        if self.committed {
            return Err(TransitionError::StaleGeneration);
        }
        let _pin = MemberControlCustody::retain(member)?;
        if member.member_entry() != Some(self.entry) {
            return Err(TransitionError::StaleGeneration);
        }
        let _waiter = finish_member_word(
            &member.exit_custody().word,
            IN_ZONE_COMMITTED,
            0,
            Ordering::SeqCst,
        );
        let entry = self.entry;
        let result = self.commit();
        if result.is_err() && member.member_entry() == Some(entry) {
            member
                .exit_custody()
                .word
                .fetch_and(!IN_ZONE_COMMITTED, Ordering::SeqCst);
        }
        result
    }

    pub fn commit(mut self) -> Result<(), TransitionError> {
        if self.committed {
            return Err(TransitionError::StaleGeneration);
        }
        let activity = self.page.activity();
        if let Some(activity) = activity {
            activity.announce();
        }
        let result = self.page.transition(
            self.entry,
            &[EntryState::ExitingBorn, EntryState::ExitingPublished],
            EntryState::ExitedInZone,
            Ordering::SeqCst,
        );
        if result.is_err()
            && let Some(activity) = activity
        {
            let _ = activity.complete(1);
        }
        self.committed = result.is_ok();
        result
    }
}

impl ExitAdmission<'_> {
    fn restore_admission(&mut self) {
        if self.committed || self.irrevocable {
            return;
        }
        // Publication can race this rollback, so retry only that exact CAS
        // conflict; no guest wait or authority acquisition occurs here.
        loop {
            let Some((generation, state)) = self.page.state(self.entry.index()) else {
                return;
            };
            if generation != self.entry.generation() {
                return;
            }
            let restored = match state {
                EntryState::ExitingBorn => EntryState::Born,
                EntryState::ExitingPublished => EntryState::Published,
                _ => return,
            };
            if self
                .page
                .transition(self.entry, &[state], restored, Ordering::SeqCst)
                .is_ok()
            {
                return;
            }
        }
    }
}

impl Drop for ExitAdmission<'_> {
    fn drop(&mut self) {
        self.restore_admission();
    }
}

/// Proof of a successful claim. Not `Copy`/`Clone`: the owner birth publication
/// consumes it, so a claim is completed at most once.
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct ClaimedEntry(EntryRef);
impl ClaimedEntry {
    pub const fn entry(&self) -> EntryRef {
        self.0
    }
}

/// A refused Born transition returns custody of the claim to its caller.
#[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
pub struct BirthRefusal {
    error: TransitionError,
    claim: ClaimedEntry,
}
impl BirthRefusal {
    pub const fn new(error: TransitionError, claim: ClaimedEntry) -> Self {
        Self { error, claim }
    }
    pub fn into_parts(self) -> (TransitionError, ClaimedEntry) {
        (self.error, self.claim)
    }
}

#[cfg(test)]
mod membership_tests {
    use super::*;

    struct Page {
        terminal: crate::terminal::ProcessExitCustody,
        gate: AtomicU32,
        live: AtomicU32,
    }

    impl Lifecycle for Page {
        fn process_exit_custody(&self) -> &crate::terminal::ProcessExitCustody {
            &self.terminal
        }
        fn host_birth_receipt_returned_exact(
            &self,
            _: usize,
            _: crate::terminal::ThreadBirthIdentity,
        ) -> bool {
            false
        }

        fn gate_word(&self) -> &AtomicU32 {
            &self.gate
        }
        fn live_word(&self) -> &AtomicU32 {
            &self.live
        }
        fn entry_count(&self) -> usize {
            0
        }
        fn entry_word(&self, _: usize) -> Option<&AtomicEntry> {
            None
        }
        fn activity(&self) -> Option<&ThreadLedgerActivity> {
            None
        }
    }

    #[test]
    fn terminal_rmw_consumes_reserved_waiter_bit_before_claim_drop() {
        // Layer 1 allocates this bit but has no production arming operation.
        // Inject only in the fixture, while a genuine claim pins reset.
        let member = MemberControlAuthority::new();
        let mut claim = claim_member_exit(&member.custody.word).unwrap();
        member.custody.word.fetch_or(1024, Ordering::AcqRel);
        member
            .custody
            .commit_zone_terminal(NativeExitCompletion::Member);
        assert_eq!(
            member.custody.word.load(Ordering::Acquire) & 1024,
            0,
            "terminal RMW left the waiter bit armed"
        );
        claim.committed = true;
        drop(claim);
        assert!(!member.custody.referenced());
        assert!(member.reserve_reset().is_ok());
    }

    #[test]
    fn waiter_release_rmw_observes_one_winner_across_terminal_and_drop() {
        use crate::cancellation::CancellationWord;
        struct Counted {
            word: AtomicU32,
            observations: AtomicU32,
        }
        impl CancellationWord for Counted {
            fn load(&self, order: Ordering) -> u32 {
                self.word.load(order)
            }
            fn compare_exchange(
                &self,
                old: u32,
                new: u32,
                success: Ordering,
                failure: Ordering,
            ) -> Result<u32, u32> {
                let result = self.word.compare_exchange(old, new, success, failure);
                if result.is_ok() && old & MEMBER_WAITER != 0 && new & MEMBER_WAITER == 0 {
                    self.observations.fetch_add(1, Ordering::AcqRel);
                }
                result
            }
            fn fetch_sub(&self, n: u32, order: Ordering) -> u32 {
                self.word.fetch_sub(n, order)
            }
            fn fetch_or(&self, n: u32, order: Ordering) -> u32 {
                self.word.fetch_or(n, order)
            }
        }
        for terminal in [
            IN_ZONE_COMMITTED,
            2 | GRAPH_REGISTERED,
            HOST_RETIRING,
            ZONE_TERMINAL,
            ZONE_TERMINAL | ABI_EXIT_PENDING,
            ZONE_TERMINAL | ZONE_HOST_TERMINAL | HOST_RETIRING,
        ] {
            let word = Counted {
                word: AtomicU32::new(0),
                observations: AtomicU32::new(0),
            };
            let mut claim = claim_member_exit(&word).unwrap();
            claim.committed = true;
            word.word.fetch_or(MEMBER_WAITER, Ordering::AcqRel);
            std::thread::scope(|scope| {
                let terminal_owner =
                    scope.spawn(|| finish_member_word(&word, terminal, 0, Ordering::AcqRel));
                drop(claim);
                let _ = terminal_owner.join().unwrap();
            });
            assert_eq!(word.observations.load(Ordering::Acquire), 1);
            assert_eq!(
                word.word.load(Ordering::Acquire) & (REFERENCES | MEMBER_WAITER),
                0
            );
            assert!(
                !finish_member_word(&word, terminal, 0, Ordering::AcqRel),
                "a later commit observed the same waiter twice"
            );
        }
        let word = AtomicU32::new(0);
        let claim = claim_member_exit(&word).unwrap();
        word.fetch_or(MEMBER_WAITER, Ordering::AcqRel);
        drop(claim);
        assert_eq!(
            word.load(Ordering::Acquire),
            0,
            "rollback must clear claim, reference and waiter together"
        );
    }

    #[test]
    fn waiter_flag_does_not_alias_reference_exhaustion_or_reset() {
        assert_eq!(REFERENCES & MEMBER_WAITER, 0);
        assert_eq!(GRAPH_REFERENCE, MEMBER_WAITER << 1);
        let authority = MemberControlAuthority::new();
        authority
            .custody
            .word
            .store(REFERENCES | MEMBER_WAITER, Ordering::Release);
        assert!(matches!(
            claim_member_exit(&authority.custody.word),
            Err(MemberMembershipError::InvalidMember)
        ));
        struct View<'a>(&'a MemberExitCustody);
        impl MemberControl for View<'_> {
            fn member_entry(&self) -> Option<EntryRef> {
                None
            }
            fn exit_custody(&self) -> &MemberExitCustody {
                self.0
            }
            fn host_retirement(&self) -> Option<crate::terminal::HostThreadRetirementReceipt> {
                None
            }
        }
        assert!(MemberControlCustody::retain(&View(&authority.custody)).is_err());
        assert!(authority.reserve_reset().is_err());
        authority
            .custody
            .word
            .store(REFERENCES - GRAPH_REFERENCE, Ordering::Release);
        let claim = claim_member_exit(&authority.custody.word).unwrap();
        assert_eq!(
            authority.custody.word.load(Ordering::Acquire) & REFERENCES,
            REFERENCES
        );
        assert!(authority.reserve_reset().is_err());
        drop(claim);
        assert_eq!(
            authority.custody.word.load(Ordering::Acquire),
            REFERENCES - GRAPH_REFERENCE
        );
        authority.custody.word.store(0, Ordering::Release);
        let reset = authority.reserve_reset().unwrap();
        assert!(matches!(
            claim_member_exit(&authority.custody.word),
            Err(MemberMembershipError::InvalidMember)
        ));
        drop(reset);
        assert!(claim_member_exit(&authority.custody.word).is_ok());
    }

    #[test]
    fn unpublished_nonfinal_exit_restores_live_in_release() {
        let page = Page {
            terminal: crate::terminal::ProcessExitCustody::new(),
            gate: AtomicU32::new(GateState::Open as u32),
            live: AtomicU32::new(2),
        };
        drop(page.reserve_nonfinal_exit().unwrap());
        assert_eq!(page.live(), 2);
        let reserved = page.reserve_nonfinal_exit().unwrap();
        assert_eq!(page.thread_born(), Some(2));
        drop(reserved);
        assert_eq!(page.live(), 3);
        page.close();
        drop(page.reserve_cancelled_member_exit().unwrap());
        assert_eq!(page.live(), 3);
    }
    #[test]
    fn refused_host_page_transition_preserves_host_zone_provenance() {
        struct Member {
            custody: MemberExitCustody,
            entry: EntryRef,
        }
        impl MemberControl for Member {
            fn member_entry(&self) -> Option<EntryRef> {
                Some(self.entry)
            }
            fn exit_custody(&self) -> &MemberExitCustody {
                &self.custody
            }
            fn host_retirement(&self) -> Option<crate::terminal::HostThreadRetirementReceipt> {
                None
            }
        }
        let page = Page {
            terminal: crate::terminal::ProcessExitCustody::new(),
            gate: AtomicU32::new(GateState::Open as u32),
            live: AtomicU32::new(2),
        };
        let member = Member {
            custody: MemberExitCustody::new(),
            entry: EntryRef::new(0, 1),
        };
        let mut membership = page.reserve_nonfinal_exit().unwrap();
        member
            .custody
            .commit_host_zone_terminal(&RegistryWriteHeld::for_test());
        membership.commit_irrevocable();
        // The real page transition refuses its absent entry and rolls back
        // HOST_RETIRING. Its permanent provenance must still remain host-owned.
        assert_eq!(
            retire_host_member(
                &page,
                member.entry,
                &member,
                membership,
                &RegistryWriteHeld::for_test()
            ),
            Err(TransitionError::NoSuchEntry)
        );
        assert!(member.custody.zone_terminal());
        assert!(!member.custody.native_zone_terminal());
        assert_eq!(page.live(), 1);
    }
}

#[cfg(all(test, feature = "loom"))]
mod loom_models {
    use super::*;
    use crate::cancellation::{CancellationAuthority, CancellationWord, ProcessCancellation};
    use loom::sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32 as LoomWord},
    };
    use loom::thread;

    struct Word(LoomWord);
    impl CancellationWord for Word {
        fn load(&self, order: Ordering) -> u32 {
            self.0.load(order)
        }
        fn compare_exchange(
            &self,
            old: u32,
            new: u32,
            success: Ordering,
            failure: Ordering,
        ) -> Result<u32, u32> {
            self.0.compare_exchange(old, new, success, failure)
        }
        fn fetch_sub(&self, value: u32, order: Ordering) -> u32 {
            self.0.fetch_sub(value, order)
        }
        fn fetch_or(&self, value: u32, order: Ordering) -> u32 {
            self.0.fetch_or(value, order)
        }
    }

    #[test]
    fn concurrent_group_exit_and_direct_load_share_exact_member_admission() {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.max_branches = 10_000;
        model.check(|| {
            let cancellation = Arc::new(CancellationAuthority::with_word(Word(LoomWord::new(0))));
            let member = Arc::new(Word(LoomWord::new(0)));
            let live = Arc::new(LoomWord::new(2));
            let absent = Arc::new(AtomicBool::new(false));
            let retire =
                |member: &Word, live: &LoomWord, absent: &AtomicBool| match claim_member_exit(
                    member,
                ) {
                    Ok(mut claim) => {
                        assert!(live.fetch_sub(1, Ordering::AcqRel) > 0);
                        claim.committed = true;
                        member.fetch_or(ZONE_TERMINAL, Ordering::Release);
                        absent.store(true, Ordering::Release);
                    }
                    Err(
                        MemberMembershipError::AlreadyTerminal | MemberMembershipError::InFlight,
                    ) => {}
                    Err(error) => panic!("unexpected admission: {error:?}"),
                };
            let root_cancellation = cancellation.clone();
            let root_member = member.clone();
            let root_live = live.clone();
            let root_absent = absent.clone();
            let root = thread::spawn(move || {
                root_cancellation.publish(ProcessCancellation::GroupExit, thread::yield_now);
                // The close owner reserves its own distinct caller unit, then
                // races the sibling's exit to retire that same exact member.
                assert!(root_live.fetch_sub(1, Ordering::AcqRel) > 0);
                retire(&root_member, &root_live, &root_absent);
            });
            let sibling_member = member.clone();
            let sibling_live = live.clone();
            let sibling_absent = absent.clone();
            let sibling = thread::spawn(move || {
                cancellation.publish(ProcessCancellation::GroupExit, thread::yield_now);
                retire(&sibling_member, &sibling_live, &sibling_absent);
            });
            if absent.load(Ordering::Acquire) {
                assert_ne!(member.load(Ordering::Acquire) & ZONE_TERMINAL, 0);
            }
            root.join().unwrap();
            sibling.join().unwrap();
            assert_eq!(live.load(Ordering::Acquire), 0, "one unit per live member");
            assert_eq!(member.load(Ordering::Acquire) & REFERENCES, 0);
        });
    }
}
