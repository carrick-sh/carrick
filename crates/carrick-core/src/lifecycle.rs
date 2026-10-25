//! Neutral exact-incarnation lifecycle transitions over retained storage.
pub use carrick_core_abi::lifecycle::*;
use core::sync::atomic::{AtomicU32, Ordering};

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

const IN_ZONE_COMMITTED: u32 = 4;
const HOST_RETIRING: u32 = 8;

const GRAPH_REGISTERED: u32 = 16;
const NATIVE_SIGNAL_OWNER: u32 = 32;
const GRAPH_REFERENCE: u32 = 64;
const RESETTING: u32 = 1 << 31;
const REFERENCES: u32 = RESETTING - GRAPH_REFERENCE;

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
        self.custody
            .word
            .fetch_or(2 | GRAPH_REGISTERED, Ordering::Release);
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
        self.control
            .exit_custody()
            .word
            .fetch_sub(GRAPH_REFERENCE, Ordering::AcqRel);
    }
}

/// Exact member custody, reset exclusively before each birth. The entry
/// reference is the generation key; the flag word is member-owned storage.
pub trait MemberControl {
    fn member_entry(&self) -> Option<EntryRef>;
    fn exit_custody(&self) -> &MemberExitCustody;
    fn host_retirement(&self) -> Option<crate::terminal::HostThreadRetirementReceipt>;
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
) -> Result<(), TransitionError> {
    let _pin = MemberControlCustody::retain(member)?;
    if !core::ptr::addr_eq(page, membership.page) {
        return Err(TransitionError::StaleGeneration);
    }
    if member.member_entry() != Some(entry) {
        return Err(TransitionError::StaleGeneration);
    }
    member
        .exit_custody()
        .word
        .fetch_or(HOST_RETIRING, Ordering::SeqCst);
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
    member
        .exit_custody()
        .word
        .fetch_or(IN_ZONE_COMMITTED, Ordering::SeqCst);
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
    /// Exec drain owns the process-closing gate while retaining its caller as
    /// the successor. Unlike fork quiescence this transition is terminal for
    /// the predecessor image; a concurrent group exit may upgrade the owner,
    /// but no birth or service admission can reopen it.
    fn close_for_exec(&self) -> Result<(), GateState> {
        self.gate_word()
            .compare_exchange(
                GateState::Open as u32,
                GateState::Closed as u32,
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
    /// The graph's exact-thread retirement and ledger publication completed.
    pub fn publish(mut self) {
        self.reserved.take();
    }
}

impl Drop for NonfinalExitMembership<'_> {
    fn drop(&mut self) {
        if let Some(unit) = self.reserved.take() {
            self.page.restore_reserved(unit);
        }
    }
}
/// Non-cloneable ownership of the bounded EL1 exit window. Dropping an
/// unfinished exit restores membership, including a concurrent publication.
pub struct ExitAdmission<'a> {
    page: &'a dyn Lifecycle,
    entry: EntryRef,
    committed: bool,
}

impl ExitAdmission<'_> {
    /// Publish the member-owned exit kind before making the shared entry
    /// reappable. Closing may observe the marker during the admitted window,
    /// but claimed_count prevents settlement until this CAS completes.
    pub fn commit_with_member(self, member: &dyn MemberControl) -> Result<(), TransitionError> {
        let _pin = MemberControlCustody::retain(member)?;
        if member.member_entry() != Some(self.entry) {
            return Err(TransitionError::StaleGeneration);
        }
        member
            .exit_custody()
            .word
            .fetch_or(IN_ZONE_COMMITTED, Ordering::SeqCst);
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

impl Drop for ExitAdmission<'_> {
    fn drop(&mut self) {
        if self.committed {
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
}
