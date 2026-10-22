//! Exact, by-value thread terminal custody. The page live word chooses the
//! nonfinal member; lanes apply the resulting verdict.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::num::{NonZeroI32, NonZeroU64};

use carrick_core_abi::entry::{
    BirthSerial, EntryMmKey, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
};
use carrick_core_abi::lifecycle::EntryRef;
use carrick_guest_arch::{AddressContext, RootGpa};
use carrick_sched_core::process::{TaskId, TaskKey, TerminationStatus};

use crate::lifecycle::{
    Lifecycle, MemberControl, MemberExitKind, MembershipFloor, NonfinalExitMembership,
};

pub struct PoolMemberObservation<'a> {
    pub entry: EntryRef,
    /// The control slot retained by this member, even if its shared pool
    /// entry has since been reaped and reused. Host retirement must publish
    /// its typed receipt on this same slot.
    pub member: &'a dyn MemberControl,
    pub expected_host: ThreadBirthIdentity,
}

pub enum HostMemberObservation<'a> {
    /// An entry-less member owes the exact birth identity its slot records.
    Adopted {
        birth: ThreadBirthIdentity,
        member: &'a dyn MemberControl,
    },
    HostBorn {
        identity: ThreadBirthIdentity,
        index: usize,
    },
}

fn task_id_from_binding(binding: ExecutionBinding) -> Option<TaskId> {
    let raw = i32::try_from(binding.task.raw()).ok()?;
    if raw <= 0 {
        return None;
    }
    Some(TaskId::from_registry_allocation(NonZeroI32::new(raw)?))
}

pub struct Thread;

/// The neutral process terminal owner records the one physical-retirement
/// publication. An executor failure after normal publication reuses that
/// receipt; it cannot manufacture a second one from a later member snapshot.
#[derive(Debug, Default)]
pub enum ProcessPhysicalPublication<C> {
    #[default]
    Unpublished,
    Published(C),
}

#[derive(Debug)]
pub struct ProcessPhysicalPublicationOwner<'a, C>(&'a mut ProcessPhysicalPublication<C>);

impl<C> ProcessPhysicalPublicationOwner<'_, C> {
    pub fn publish(self, completion: C) {
        *self.0 = ProcessPhysicalPublication::Published(completion);
    }
}

#[cfg(test)]
mod process_physical_publication_tests {
    use super::ProcessPhysicalPublication;
    use alloc::vec;

    #[test]
    fn failure_after_normal_retirement_reuses_exact_receipt() {
        let mut owner = ProcessPhysicalPublication::default();
        owner
            .claim_owner()
            .expect("initial publication owner")
            .publish(vec![11_u32, 12]);
        assert!(owner.claim_owner().is_none());
        assert_eq!(owner.published(), Some(&vec![11, 12]));
        assert!(owner.publish(vec![13]).is_err());
        assert_eq!(owner.published(), Some(&vec![11, 12]));
    }
}

impl<C> ProcessPhysicalPublication<C> {
    pub fn claim_owner(&mut self) -> Option<ProcessPhysicalPublicationOwner<'_, C>> {
        matches!(self, Self::Unpublished).then_some(ProcessPhysicalPublicationOwner(self))
    }

    pub fn publish(&mut self, completion: C) -> Result<(), C> {
        let Some(owner) = self.claim_owner() else {
            return Err(completion);
        };
        owner.publish(completion);
        Ok(())
    }

    pub fn published(&self) -> Option<&C> {
        match self {
            Self::Unpublished => None,
            Self::Published(completion) => Some(completion),
        }
    }
}
/// One process incarnation owns exactly one terminal admission claim.
#[repr(C)]
#[derive(::core::fmt::Debug, ::core::default::Default)]
pub struct ProcessExitCustody {
    begun: core::sync::atomic::AtomicU32,
    external_work: core::sync::atomic::AtomicU32,
}
impl ProcessExitCustody {
    pub const fn new() -> Self {
        Self {
            begun: core::sync::atomic::AtomicU32::new(0),
            external_work: core::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Whether process custody has consumed the caller's live membership.
    /// Wait-key publication is notification plumbing and cannot choose the
    /// remaining members' retirement floor.
    pub fn caller_reserved(&self) -> bool {
        use core::sync::atomic::Ordering;
        loop {
            match self.begun.load(Ordering::Acquire) {
                0 => return false,
                2 => return true,
                // The process owner has claimed the close but has not yet
                // published its caller's membership reservation. A sibling
                // cannot choose a last-member floor until that completes.
                _ => core::hint::spin_loop(),
            }
        }
    }
}

impl ProcessExitCustody {
    pub(crate) fn external_work(&self) -> usize {
        self.external_work
            .load(core::sync::atomic::Ordering::SeqCst) as usize
    }
}

/// An admitted host fork publication, retained until publication or rollback
/// completes. It is an outstanding claim, never a parent thread membership.
struct ExternalWorkClaim<P: core::ops::Deref>(P)
where
    P::Target: Lifecycle;
impl<P: core::ops::Deref> ExternalWorkClaim<P>
where
    P::Target: Lifecycle,
{
    pub fn acquire(page: P) -> Result<Self, carrick_core_abi::lifecycle::GateState> {
        use carrick_core_abi::lifecycle::GateState;
        use core::sync::atomic::Ordering;
        page.process_exit_custody()
            .external_work
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            })
            .map_err(|_| GateState::ForkClosing)?;
        Ok(Self(page))
    }
    pub fn admitted(&self) -> bool {
        // Pair claim-before-gate with terminal close-before-claimed_count.
        // Either the fork observes Closed or Closing observes this claim.
        !self.0.gate().is_terminal()
    }
}
impl<P: core::ops::Deref> Drop for ExternalWorkClaim<P>
where
    P::Target: Lifecycle,
{
    fn drop(&mut self) {
        self.0
            .process_exit_custody()
            .external_work
            .fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
    }
}

/// An admitted host fork publication retained until publication or rollback.
/// It is outstanding work, never a parent thread membership.
pub struct ForkPublicationClaim<P: core::ops::Deref>(ExternalWorkClaim<P>)
where
    P::Target: Lifecycle;
impl<P: core::ops::Deref> ForkPublicationClaim<P>
where
    P::Target: Lifecycle,
{
    pub fn acquire(page: P) -> Result<Self, carrick_core_abi::lifecycle::GateState> {
        ExternalWorkClaim::acquire(page).map(Self)
    }
    pub fn admitted(&self) -> bool {
        self.0.admitted()
    }
}

/// Outstanding native service custody, distinct from a member or fork.
/// Abandonment leaves the claim outstanding; only an explicit acknowledgment
/// (including admission rollback) releases it and owes the terminal wake.
#[must_use]
pub struct NativeServiceClaim<P: core::ops::Deref>(P)
where
    P::Target: Lifecycle;
impl<P: core::ops::Deref> NativeServiceClaim<P>
where
    P::Target: Lifecycle,
{
    pub fn acquire(page: P) -> Result<Self, carrick_core_abi::lifecycle::GateState> {
        use core::sync::atomic::Ordering;
        page.process_exit_custody()
            .external_work
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_add(1)
            })
            .map_err(|_| carrick_core_abi::lifecycle::GateState::ForkClosing)?;
        Ok(Self(page))
    }
    pub fn admitted(&self) -> bool {
        !self.0.gate().is_terminal()
    }
    /// Claim release precedes sampling the wake published by closing. If
    /// close has not published yet, its later readiness check sees the release.
    pub fn acknowledge<R>(self, notify: impl FnOnce(Option<TerminalNotification>) -> R) -> R {
        self.0
            .process_exit_custody()
            .external_work
            .fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
        notify(self.0.terminal_notification())
    }
}

/// Closed birth admission, without a consumed caller membership or begun
/// terminal claim. Dropping this preparation never reopens the gate.
pub struct ProcessExitAdmission<'a, L: Lifecycle> {
    page: &'a L,
}

pub struct Process;
pub struct Live;
pub struct Exiting;
pub struct Terminal;
pub struct Closing;
pub struct Settled;

/// Raw task membership supplied by the graph that owns its registry. Core
/// decides whether an absent task makes a terminal retry already retired.
pub trait TaskMembership {
    fn contains_task(&self, task: TaskId) -> bool;
}

pub fn terminal_task_absent(graph: &impl TaskMembership, task: TaskId) -> bool {
    !graph.contains_task(task)
}

mod sealed {
    pub trait Sealed {}
}
pub trait TerminalKind: sealed::Sealed {
    type Identity: Copy;
    type LaneMarker;
}
impl sealed::Sealed for Thread {}
impl sealed::Sealed for Process {}
impl TerminalKind for Thread {
    type Identity = ThreadTerminalIdentity;
    type LaneMarker = *const ();
}
impl TerminalKind for Process {
    type Identity = ProcessTerminalIdentity;
    type LaneMarker = ();
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessTerminalIdentity {
    task: TaskKey,
    address: AddressContext<RootGpa>,
    status: TerminationStatus,
}

impl ProcessTerminalIdentity {
    pub(crate) fn from_exit(
        task: TaskKey,
        address: AddressContext<RootGpa>,
        status: TerminationStatus,
    ) -> Self {
        Self {
            task,
            address,
            status,
        }
    }

    pub fn task(self) -> TaskKey {
        self.task
    }
    pub fn address(self) -> AddressContext<RootGpa> {
        self.address
    }
    pub fn status(self) -> TerminationStatus {
        self.status
    }
}

/// A bounded description of the work the registry applies. Exact host
/// bindings live in a boxed list rather than on the EL1 stack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberSet {
    process: ProcessTerminalIdentity,
    pool: Box<[EntryRef]>,
    host: Box<[ThreadBirthIdentity]>,
}

impl MemberSet {
    pub(crate) fn new(
        process: ProcessTerminalIdentity,
        mut pool: Vec<EntryRef>,
        mut host: Vec<ThreadBirthIdentity>,
    ) -> Self {
        // One identity has one expected receipt, even if two registry views
        // named it during a handoff. The exact value remains authoritative.
        let mut seen_pool = Vec::new();
        pool.retain(|entry| {
            !seen_pool.contains(entry) && {
                seen_pool.push(*entry);
                true
            }
        });
        let mut seen_host = Vec::new();
        host.retain(|receipt| {
            !seen_host.contains(receipt) && {
                seen_host.push(*receipt);
                true
            }
        });
        Self {
            process,
            pool: pool.into_boxed_slice(),
            host: host.into_boxed_slice(),
        }
    }
    pub fn pool(&self) -> &[EntryRef] {
        &self.pool
    }
    pub fn host(&self) -> &[ThreadBirthIdentity] {
        &self.host
    }
    pub(crate) fn completed(
        &self,
        pool: &[EntryRef],
        host: &[ThreadBirthIdentity],
    ) -> Option<CompletedMemberReceipts> {
        if pool.len() != self.pool.len()
            || host.len() != self.host.len()
            || self
                .pool
                .iter()
                .any(|entry| pool.iter().filter(|got| *got == entry).count() != 1)
            || self
                .host
                .iter()
                .any(|receipt| host.iter().filter(|got| *got == receipt).count() != 1)
        {
            return None;
        }
        Some(CompletedMemberReceipts {
            process: self.process,
        })
    }
}

/// Core-minted proof that every exact member named by one verdict returned a
/// receipt. Callers cannot turn a census read or a boolean into this proof.
pub struct CompletedMemberReceipts {
    process: ProcessTerminalIdentity,
}

/// A thread's exact birth identity: tid, owning process incarnation and
/// thread serial, recorded once when the thread is born. A visible tid is
/// never sufficient (it is reused), and an execution binding is never one:
/// its snapshot generation moves on every settlement. There is deliberately
/// no constructor from an [`ExecutionBinding`]. Closing owes exactly one
/// [`HostThreadRetirementReceipt`] for each such identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadBirthIdentity {
    task: EntryTaskKey,
    birth: BirthSerial,
    thread: EntryThreadGeneration,
}

impl ThreadBirthIdentity {
    pub fn from_parts(
        task: EntryTaskKey,
        birth: BirthSerial,
        thread: EntryThreadGeneration,
    ) -> Option<Self> {
        (task.raw() != 0 && thread.raw() != 0).then_some(Self {
            task,
            birth,
            thread,
        })
    }

    /// The receipt the host publishes after it has retired exactly this
    /// thread. Only a retirement path mints one; it is never read back as a
    /// birth identity.
    pub fn retirement(self) -> HostThreadRetirementReceipt {
        HostThreadRetirementReceipt(self)
    }

    pub fn task(self) -> EntryTaskKey {
        self.task
    }
    pub fn birth(self) -> BirthSerial {
        self.birth
    }
    pub fn thread(self) -> EntryThreadGeneration {
        self.thread
    }
}

/// Host retirement's exact acknowledgement of one [`ThreadBirthIdentity`].
/// It lives in storage distinct from the birth identity, so a published
/// receipt can never stand in for the identity it is checked against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostThreadRetirementReceipt(ThreadBirthIdentity);

impl HostThreadRetirementReceipt {
    /// Whether this receipt retires exactly `identity`.
    pub fn acknowledges(self, identity: ThreadBirthIdentity) -> bool {
        self.0 == identity
    }
    /// The identity this receipt retired.
    pub fn retired(self) -> ThreadBirthIdentity {
        self.0
    }
}

/// A raw thread exit at the page's last live membership becomes a process
/// exit. The process owner then closes admission and fixes the group status.
pub fn raw_exit_is_process(page: &impl Lifecycle) -> bool {
    page.live() == 1
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadTerminalIdentity {
    binding: ExecutionBinding,
    entry: Option<NonZeroU64>,
    status: TerminationStatus,
}

impl ThreadTerminalIdentity {
    /// Bind one syscall exit to the exact task and page-entry incarnation.
    pub fn from_exit(
        binding: ExecutionBinding,
        entry: Option<EntryRef>,
        status: TerminationStatus,
    ) -> Option<Self> {
        task_id_from_binding(binding)?;
        let entry = match entry {
            Some(entry) => Some(NonZeroU64::new(entry.pack())?),
            None => None,
        };
        Some(Self {
            binding,
            entry,
            status,
        })
    }

    pub fn binding(&self) -> ExecutionBinding {
        self.binding
    }

    pub fn entry(&self) -> Option<EntryRef> {
        self.entry.and_then(|word| EntryRef::unpack(word.get()))
    }

    pub fn status(&self) -> TerminationStatus {
        self.status
    }
}

pub struct TerminalCustody<K: TerminalKind, P> {
    identity: K::Identity,
    phase: PhantomData<(K, P, K::LaneMarker)>,
}

// EL1/CPL0 terminal paths already have tight stack budgets. Phase changes
// consume this small value rather than moving an execution context by value.
const _: () = {
    assert!(core::mem::size_of::<TerminalCustody<Thread, Exiting>>() <= 64);
    assert!(core::mem::size_of::<TerminalCustody<Process, Closing>>() <= 64);
};

#[must_use]
pub struct TerminalNotification {
    pub mm: EntryMmKey,
    pub address: NonZeroU64,
}

impl TerminalNotification {
    /// Final membership progress owes the closing object's waiter a publication
    /// even if this member entered before the process owner was registered.
    /// The waiter still authenticates all exact retirement receipts.
    pub fn publish<C: carrick_core_abi::entry::EntryContext>(
        &self,
        zone: &carrick_sched_core::ZoneTables<C>,
        slot: carrick_sched_core::SlotId,
        wait: &impl carrick_sched_core::ShortLockWait,
    ) -> Result<carrick_sched_core::WakeEffects, carrick_sched_core::WakeRefusal> {
        let guard = zone.short_lock(
            carrick_sched_core::ZoneTables::<C>::bucket_of_with_context(
                self.mm.raw(),
                self.address.get(),
            ),
            wait,
        );
        let mut effects = carrick_sched_core::WakeEffects::default();
        zone.wake_placed(
            &guard,
            self.mm.raw(),
            self.address.get(),
            u32::MAX,
            u32::MAX,
            carrick_sched_core::Waker::El1 { slot },
            &mut [],
            &mut effects,
        )?;
        Ok(effects)
    }
}

/// The first member observation that kept a Closing owner from settling.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum ReadinessFailure {
    Pool {
        entry: EntryRef,
        kind: MemberExitKind,
        observed: Option<HostThreadRetirementReceipt>,
        expected: ThreadBirthIdentity,
    },
    /// `position` indexes the owner's host-member observations.
    Adopted {
        position: usize,
        kind: MemberExitKind,
        observed: Option<HostThreadRetirementReceipt>,
        expected: ThreadBirthIdentity,
    },
    HostBorn {
        index: usize,
        expected: ThreadBirthIdentity,
    },
    /// Every observation returned, but the returned set is not the exact
    /// expected member set (a missing or duplicated identity).
    MemberSet {
        observed_pool: usize,
        observed_host: usize,
        expected_pool: usize,
        expected_host: usize,
    },
}

#[must_use]
pub enum RetirementVerdict {
    RetireThreadOnHost {
        identity: ThreadTerminalIdentity,
    },
    RetireThread {
        identity: ThreadTerminalIdentity,
        requires_slot_absence: bool,
        notification: Option<TerminalNotification>,
    },
    CancelMembers {
        process: ProcessTerminalIdentity,
        members: MemberSet,
    },
}

impl TerminalCustody<Process, Live> {
    #[cfg(test)]
    pub(crate) fn admitted(identity: ProcessTerminalIdentity) -> Self {
        Self {
            identity,
            phase: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn close_gate(self, page: &impl Lifecycle) -> TerminalCustody<Process, Closing> {
        page.close();
        TerminalCustody {
            identity: self.identity,
            phase: PhantomData,
        }
    }

    pub fn close_admission<L: Lifecycle>(page: &L) -> ProcessExitAdmission<'_, L> {
        page.close();
        // Pair with Kernel::thread_spawned's publication-before-gate check.
        // Order the gate store before the Acquire host-born snapshot loads,
        // including targets where Acquire may compile to an RCpc load.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        ProcessExitAdmission { page }
    }

    pub fn begin_exit<L: Lifecycle>(
        admission: ProcessExitAdmission<'_, L>,
        task: TaskKey,
        address: AddressContext<RootGpa>,
        status: TerminationStatus,
    ) -> Result<TerminalCustody<Process, Closing>, MembershipFloor> {
        use core::sync::atomic::Ordering;
        let page = admission.page;
        let state = page.process_exit_custody();
        state
            .begun
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| MembershipFloor)?;
        let caller = match page.reserve_closing_caller_exit() {
            Ok(caller) => caller,
            Err(error) => {
                state.begun.store(0, Ordering::Release);
                return Err(error);
            }
        };
        caller.publish();
        state.begun.store(2, Ordering::Release);
        Ok(TerminalCustody {
            identity: ProcessTerminalIdentity::from_exit(task, address, status),
            phase: PhantomData,
        })
    }
}

impl TerminalCustody<Process, Closing> {
    pub fn cancel_members(
        &self,
        pool: Vec<EntryRef>,
        host: Vec<ThreadBirthIdentity>,
    ) -> RetirementVerdict {
        let members = MemberSet::new(self.identity, pool, host);
        RetirementVerdict::CancelMembers {
            process: self.identity,
            members,
        }
    }
    fn complete_members(
        &self,
        members: &MemberSet,
        pool: &[EntryRef],
        host: &[ThreadBirthIdentity],
    ) -> Option<CompletedMemberReceipts> {
        (members.process == self.identity)
            .then(|| members.completed(pool, host))
            .flatten()
    }
    pub fn observe_members(
        &self,
        page: &impl Lifecycle,
        members: &MemberSet,
        pool: &[PoolMemberObservation<'_>],
        host: &[HostMemberObservation<'_>],
    ) -> Option<CompletedMemberReceipts> {
        self.observe_members_verdict(page, members, pool, host).ok()
    }

    /// [`Self::observe_members`] that names the first member observation
    /// which is not a returned receipt. The one implementation: the boolean
    /// answer is this verdict's `Ok`.
    pub fn observe_members_verdict(
        &self,
        page: &impl Lifecycle,
        members: &MemberSet,
        pool: &[PoolMemberObservation<'_>],
        host: &[HostMemberObservation<'_>],
    ) -> Result<CompletedMemberReceipts, ReadinessFailure> {
        let mut completed_pool = Vec::with_capacity(pool.len());
        for observation in pool {
            let kind = crate::lifecycle::recorded_member_exit_kind(
                observation.member,
                Some(observation.entry),
            );
            let observed = observation.member.host_retirement();
            let returned = match kind {
                MemberExitKind::InZone => true,
                MemberExitKind::HostRetiring => {
                    observed.is_some_and(|receipt| receipt.acknowledges(observation.expected_host))
                }
                MemberExitKind::Active | MemberExitKind::Stale => false,
            };
            if !returned {
                return Err(ReadinessFailure::Pool {
                    entry: observation.entry,
                    kind,
                    observed,
                    expected: observation.expected_host,
                });
            }
            completed_pool.push(observation.entry);
        }
        let mut completed_host = Vec::with_capacity(host.len());
        for (index, observation) in host.iter().enumerate() {
            let identity = match observation {
                HostMemberObservation::Adopted { birth, member } => {
                    let kind =
                        crate::lifecycle::recorded_member_exit_kind(*member, member.member_entry());
                    let observed = member.host_retirement();
                    if kind == MemberExitKind::InZone
                        || !observed.is_some_and(|receipt| receipt.acknowledges(*birth))
                    {
                        return Err(ReadinessFailure::Adopted {
                            position: index,
                            kind,
                            observed,
                            expected: *birth,
                        });
                    }
                    *birth
                }
                HostMemberObservation::HostBorn { identity, index } => {
                    if !page.host_birth_receipt_returned_exact(*index, *identity) {
                        return Err(ReadinessFailure::HostBorn {
                            index: *index,
                            expected: *identity,
                        });
                    }
                    *identity
                }
            };
            completed_host.push(identity);
        }
        self.complete_members(members, &completed_pool, &completed_host)
            .ok_or(ReadinessFailure::MemberSet {
                observed_pool: completed_pool.len(),
                observed_host: completed_host.len(),
                expected_pool: members.pool.len(),
                expected_host: members.host.len(),
            })
    }
    pub fn can_settle(&self, page: &impl Lifecycle, receipts: &CompletedMemberReceipts) -> bool {
        self.identity == receipts.process && page.live() == 0 && page.claimed_count() == 0
    }

    pub fn settle(
        self,
        page: &impl Lifecycle,
        receipts: CompletedMemberReceipts,
    ) -> Result<TerminalCustody<Process, Settled>, Self> {
        if !self.can_settle(page, &receipts) {
            return Err(self);
        }
        Ok(TerminalCustody {
            identity: self.identity,
            phase: PhantomData,
        })
    }
}

impl TerminalCustody<Process, Settled> {
    pub fn identity(self) -> ProcessTerminalIdentity {
        self.identity
    }
}

impl TerminalCustody<Thread, Live> {
    pub fn admitted(identity: ThreadTerminalIdentity) -> Self {
        Self {
            identity,
            phase: PhantomData,
        }
    }

    pub fn begin(self) -> TerminalCustody<Thread, Exiting> {
        TerminalCustody {
            identity: self.identity,
            phase: PhantomData,
        }
    }
}

/// Reserve one exiting member using the neutral process owner's phase.
/// A host member and an in-zone member obey the same floor, including when
/// the root reserves its caller before publishing the exit wait channel.
pub fn reserve_thread_exit_membership(
    page: &impl Lifecycle,
) -> Result<NonfinalExitMembership<'_>, MembershipFloor> {
    reserve_thread_exit_membership_with(page, || {})
}

fn reserve_thread_exit_membership_with(
    page: &impl Lifecycle,
    after_phase_observation: impl FnOnce(),
) -> Result<NonfinalExitMembership<'_>, MembershipFloor> {
    let caller_reserved = page.process_exit_custody().caller_reserved();
    after_phase_observation();
    if caller_reserved {
        page.reserve_cancelled_member_exit()
    } else {
        match page.reserve_nonfinal_exit() {
            // The root may reserve its caller after our phase observation.
            Err(_) if page.process_exit_custody().caller_reserved() => {
                page.reserve_cancelled_member_exit()
            }
            result => result,
        }
    }
}

impl TerminalCustody<Thread, Exiting> {
    pub fn route_to_host(self) -> RetirementVerdict {
        RetirementVerdict::RetireThreadOnHost {
            identity: self.identity,
        }
    }

    pub fn reserve_nonfinal<'a>(
        self,
        page: &'a impl Lifecycle,
    ) -> Result<
        (
            TerminalCustody<Thread, Terminal>,
            NonfinalExitMembership<'a>,
        ),
        (Self, MembershipFloor),
    > {
        self.reserve_nonfinal_with(page, || {})
    }

    fn reserve_nonfinal_with<'a>(
        self,
        page: &'a impl Lifecycle,
        after_phase_observation: impl FnOnce(),
    ) -> Result<
        (
            TerminalCustody<Thread, Terminal>,
            NonfinalExitMembership<'a>,
        ),
        (Self, MembershipFloor),
    > {
        let membership = match reserve_thread_exit_membership_with(page, after_phase_observation) {
            Ok(membership) => membership,
            Err(error) => return Err((self, error)),
        };
        Ok((
            TerminalCustody {
                identity: self.identity,
                phase: PhantomData,
            },
            membership,
        ))
    }
}

impl TerminalCustody<Thread, Terminal> {
    pub fn into_verdict(self, page: &impl Lifecycle) -> RetirementVerdict {
        RetirementVerdict::RetireThread {
            identity: self.identity,
            requires_slot_absence: self.identity.entry.is_some(),
            notification: (page.live() == 0 && page.claimed_count() == 0)
                .then(|| page.terminal_notification())
                .flatten(),
        }
    }
}

// The EL1 caller may hold custody on its 16 KiB stack.
const _: () = assert!(core::mem::size_of::<TerminalCustody<Thread, Live>>() <= 64);
const _: () = assert!(core::mem::size_of::<TerminalCustody<Process, Closing>>() <= 64);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::AtomicEntry;
    use carrick_core_abi::entry::SnapshotGeneration;
    use carrick_sched_core::process::TaskSerial;
    use core::sync::atomic::AtomicU32;

    fn birth_receipt(task: u64, birth: u64, thread: u64) -> ThreadBirthIdentity {
        ThreadBirthIdentity::from_parts(
            EntryTaskKey::from_raw(task),
            BirthSerial::of_task(TaskSerial::from_raw_u64(birth).unwrap()),
            EntryThreadGeneration::from_raw(thread),
        )
        .unwrap()
    }

    struct Page {
        terminal: crate::terminal::ProcessExitCustody,
        gate: AtomicU32,
        live: AtomicU32,
    }
    impl Lifecycle for Page {
        fn process_exit_custody(&self) -> &crate::terminal::ProcessExitCustody {
            &self.terminal
        }
        fn host_birth_receipt_returned_exact(&self, _: usize, _: ThreadBirthIdentity) -> bool {
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
        fn activity(&self) -> Option<&crate::lifecycle::ThreadLedgerActivity> {
            None
        }
    }

    #[test]
    fn closing_rejects_caller_claim_without_member_receipts() {
        let page = Page {
            terminal: crate::terminal::ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(0),
        };
        let identity = ProcessTerminalIdentity::from_exit(
            TaskKey {
                id: TaskId::from_registry_allocation(NonZeroI32::new(41).unwrap()),
                serial: TaskSerial::from_raw_u64(11).unwrap(),
            },
            AddressContext {
                root: RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x10000)).unwrap(),
                mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::new(1).unwrap()),
                generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::new(1).unwrap()),
            },
            TerminationStatus::exited(0),
        );
        let entry = EntryRef::new(0, 1);
        let members = MemberSet::new(identity, alloc::vec![entry], Vec::new());
        let closing = TerminalCustody::<Process, Live>::admitted(identity).close_gate(&page);
        assert!(matches!(
            closing.cancel_members(alloc::vec![entry], Vec::new()),
            RetirementVerdict::CancelMembers { .. }
        ));
        assert!(members.completed(&[], &[]).is_none());
        let receipt = members.completed(&[entry], &[]).unwrap();
        assert!(closing.settle(&page, receipt).is_ok());
    }

    #[test]
    fn fork_publication_claims_are_exact_and_host_only_never_reopens_terminal() {
        use carrick_core_abi::lifecycle::GateState;
        let page = Page {
            terminal: ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(1),
        };
        let peer = Page {
            terminal: ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(1),
        };
        page.decline_to_host();
        assert_eq!(page.gate(), GateState::HostOnly);
        let first = ForkPublicationClaim::acquire(&page).unwrap();
        assert!(first.admitted());
        let second = ForkPublicationClaim::acquire(&page).unwrap();
        assert!(second.admitted());
        assert_eq!(page.claimed_count(), 2);
        assert_eq!(peer.claimed_count(), 0);
        let _exit = TerminalCustody::<Process, Live>::close_admission(&page);
        page.decline_to_host();
        assert_eq!(page.gate(), GateState::Closed);
        assert!(!first.admitted());
        drop(first);
        assert_eq!(page.claimed_count(), 1);
        drop(second);
        assert_eq!(page.claimed_count(), 0);
        assert_eq!(peer.gate(), GateState::Open);
    }

    #[test]
    fn native_service_ack_releases_claim_before_notifying_without_consuming_member() {
        let page = Page {
            terminal: ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(2),
        };
        let first = NativeServiceClaim::acquire(&page).unwrap();
        let second = NativeServiceClaim::acquire(&page).unwrap();
        assert!(first.admitted());
        assert_eq!(page.claimed_count(), 2);
        let _closing = TerminalCustody::<Process, Live>::close_admission(&page);
        assert!(!first.admitted());
        first.acknowledge(|_| {
            assert_eq!(page.claimed_count(), 1);
            assert_eq!(page.live(), 2);
        });
        second.acknowledge(|_| {
            assert_eq!(page.claimed_count(), 0);
            assert_eq!(page.live(), 2);
        });
        assert!(page.gate().is_terminal());
    }

    #[test]
    fn abandoned_exit_admission_keeps_gate_closed_without_consuming_membership() {
        use carrick_core_abi::lifecycle::GateState;
        use core::sync::atomic::Ordering;
        let page = Page {
            terminal: ProcessExitCustody::new(),
            gate: AtomicU32::new(GateState::ForkClosing as u32),
            live: AtomicU32::new(2),
        };
        {
            let _admission = TerminalCustody::<Process, Live>::close_admission(&page);
            assert_eq!(page.gate(), GateState::Closed);
        }
        assert_eq!(page.gate(), GateState::Closed);
        assert_eq!(page.live(), 2);
        assert_eq!(page.terminal.begun.load(Ordering::Acquire), 0);
    }

    #[test]
    fn second_process_close_cannot_consume_another_live_member() {
        let page = Page {
            terminal: crate::terminal::ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(2),
        };
        let task = TaskKey {
            id: TaskId::from_registry_allocation(NonZeroI32::new(41).unwrap()),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let address = AddressContext {
            root: RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x10000)).unwrap(),
            mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::new(1).unwrap()),
            generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::new(1).unwrap()),
        };
        let _first = TerminalCustody::<Process, Live>::begin_exit(
            TerminalCustody::<Process, Live>::close_admission(&page),
            task,
            address,
            TerminationStatus::exited(7),
        )
        .unwrap();
        assert!(
            TerminalCustody::<Process, Live>::begin_exit(
                TerminalCustody::<Process, Live>::close_admission(&page),
                task,
                address,
                TerminationStatus::exited(7),
            )
            .is_err()
        );
        assert_eq!(page.live(), 1);
    }

    #[test]
    fn closing_caller_and_last_sibling_both_return_live_membership() {
        let page = Page {
            terminal: ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(2),
        };
        let task = TaskKey {
            id: TaskId::from_registry_allocation(NonZeroI32::new(41).unwrap()),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let address = AddressContext {
            root: RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x10000)).unwrap(),
            mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::new(1).unwrap()),
            generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::new(1).unwrap()),
        };
        let closing = TerminalCustody::<Process, Live>::begin_exit(
            TerminalCustody::<Process, Live>::close_admission(&page),
            task,
            address,
            TerminationStatus::exited(0),
        )
        .unwrap();
        assert_eq!(page.live(), 1);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let identity = ThreadTerminalIdentity::from_exit(
                        ExecutionBinding {
                            task: EntryTaskKey::from_raw(41),
                            generation: SnapshotGeneration::from_raw(11),
                            mm: carrick_core_abi::entry::EntryMmKey::from_raw(5),
                            thread_generation: EntryThreadGeneration::from_raw(2),
                        },
                        None,
                        TerminationStatus::exited(0),
                    )
                    .unwrap();
                    let (_custody, unfinished) =
                        TerminalCustody::<Thread, Live>::admitted(identity)
                            .begin()
                            .reserve_nonfinal(&page)
                            .unwrap_or_else(|_| {
                                panic!("the only remaining sibling can retire after process close")
                            });
                    assert_eq!(page.live(), 0);
                    drop(unfinished);
                    assert_eq!(page.live(), 1, "abandoned sibling exit restores its unit");
                    let (_custody, sibling) = TerminalCustody::<Thread, Live>::admitted(identity)
                        .begin()
                        .reserve_nonfinal(&page)
                        .unwrap_or_else(|_| panic!("restored sibling exit must be admitted"));
                    sibling.publish();
                })
                .join()
                .unwrap();
        });
        assert_eq!(page.live(), 0);
        assert!(
            TerminalCustody::<Thread, Live>::admitted(
                ThreadTerminalIdentity::from_exit(
                    ExecutionBinding {
                        task: EntryTaskKey::from_raw(41),
                        generation: SnapshotGeneration::from_raw(11),
                        mm: carrick_core_abi::entry::EntryMmKey::from_raw(5),
                        thread_generation: EntryThreadGeneration::from_raw(3),
                    },
                    None,
                    TerminationStatus::exited(0),
                )
                .unwrap(),
            )
            .begin()
            .reserve_nonfinal(&page)
            .is_err(),
            "zero live units cannot be spent again"
        );
        let members = MemberSet::new(closing.identity, Vec::new(), Vec::new());
        let receipts = members.completed(&[], &[]).unwrap();
        assert!(closing.settle(&page, receipts).is_ok());
    }

    #[test]
    fn close_between_sibling_phase_check_and_live_reservation_keeps_its_unit() {
        let page = Page {
            terminal: ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(2),
        };
        let at_observation = std::sync::Barrier::new(2);
        let after_close = std::sync::Barrier::new(2);
        let task = TaskKey {
            id: TaskId::from_registry_allocation(NonZeroI32::new(41).unwrap()),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let address = AddressContext {
            root: RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x10000)).unwrap(),
            mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::new(1).unwrap()),
            generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::new(1).unwrap()),
        };
        let closing = std::thread::scope(|scope| {
            let sibling = scope.spawn(|| {
                let identity = ThreadTerminalIdentity::from_exit(
                    ExecutionBinding {
                        task: EntryTaskKey::from_raw(42),
                        generation: SnapshotGeneration::from_raw(11),
                        mm: carrick_core_abi::entry::EntryMmKey::from_raw(5),
                        thread_generation: EntryThreadGeneration::from_raw(2),
                    },
                    None,
                    TerminationStatus::exited(0),
                )
                .unwrap();
                let (_terminal, membership) = TerminalCustody::<Thread, Live>::admitted(identity)
                    .begin()
                    .reserve_nonfinal_with(&page, || {
                        at_observation.wait();
                        after_close.wait();
                    })
                    .unwrap_or_else(|_| panic!("closing sibling lost its last live unit"));
                membership.publish();
            });
            at_observation.wait();
            let closing = TerminalCustody::<Process, Live>::begin_exit(
                TerminalCustody::<Process, Live>::close_admission(&page),
                task,
                address,
                TerminationStatus::exited(0),
            )
            .unwrap();
            after_close.wait();
            sibling.join().unwrap();
            closing
        });
        assert_eq!(page.live(), 0);
        let members = MemberSet::new(closing.identity, Vec::new(), Vec::new());
        let receipts = members.completed(&[], &[]).unwrap();
        assert!(closing.settle(&page, receipts).is_ok());
    }

    #[test]
    fn closing_waits_for_late_born_and_exited_in_zone_publication() {
        use crate::lifecycle::{EntryState, MemberExitCustody, pack};

        struct OneEntryPage {
            terminal: ProcessExitCustody,
            gate: AtomicU32,
            live: AtomicU32,
            entry: AtomicEntry,
        }
        impl Lifecycle for OneEntryPage {
            fn process_exit_custody(&self) -> &ProcessExitCustody {
                &self.terminal
            }
            fn host_birth_receipt_returned_exact(&self, _: usize, _: ThreadBirthIdentity) -> bool {
                false
            }
            fn gate_word(&self) -> &AtomicU32 {
                &self.gate
            }
            fn live_word(&self) -> &AtomicU32 {
                &self.live
            }
            fn entry_count(&self) -> usize {
                1
            }
            fn entry_word(&self, index: usize) -> Option<&AtomicEntry> {
                (index == 0).then_some(&self.entry)
            }
            fn activity(&self) -> Option<&crate::lifecycle::ThreadLedgerActivity> {
                None
            }
        }
        struct Member {
            entry: EntryRef,
            exit: MemberExitCustody,
        }
        impl MemberControl for Member {
            fn member_entry(&self) -> Option<EntryRef> {
                Some(self.entry)
            }
            fn exit_custody(&self) -> &MemberExitCustody {
                &self.exit
            }
            fn host_retirement(&self) -> Option<HostThreadRetirementReceipt> {
                None
            }
        }

        let page = OneEntryPage {
            terminal: ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(1),
            entry: AtomicEntry::new(pack(0, EntryState::Vacant)),
        };
        let entry = page.reserve_stock(0).unwrap();
        page.transition(
            entry,
            &[EntryState::Stocking],
            EntryState::Reserved,
            core::sync::atomic::Ordering::Release,
        )
        .unwrap();
        let born = page.complete_birth(page.claim_any().unwrap()).unwrap();
        assert_eq!(born, entry);
        assert_eq!(page.thread_born(), Some(2));
        let admission = page.begin_exit(entry).unwrap();
        let member = Member {
            entry,
            exit: MemberExitCustody::new(),
        };
        let task = TaskKey {
            id: TaskId::from_registry_allocation(NonZeroI32::new(41).unwrap()),
            serial: TaskSerial::from_raw_u64(11).unwrap(),
        };
        let address = AddressContext {
            root: RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x10000)).unwrap(),
            mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::new(1).unwrap()),
            generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::new(1).unwrap()),
        };
        let closing = TerminalCustody::<Process, Live>::begin_exit(
            TerminalCustody::<Process, Live>::close_admission(&page),
            task,
            address,
            TerminationStatus::exited(0),
        )
        .unwrap();
        let members = MemberSet::new(closing.identity, alloc::vec![entry], Vec::new());
        let expected_host = birth_receipt(42, 11, 2);
        let observation = [PoolMemberObservation {
            entry,
            member: &member,
            expected_host,
        }];
        assert!(
            closing
                .observe_members(&page, &members, &observation, &[])
                .is_none()
        );
        page.publish(entry).unwrap(); // Born -> ExitingPublished after close
        let identity = ThreadTerminalIdentity::from_exit(
            ExecutionBinding {
                task: EntryTaskKey::from_raw(42),
                generation: SnapshotGeneration::from_raw(11),
                mm: carrick_core_abi::entry::EntryMmKey::from_raw(5),
                thread_generation: EntryThreadGeneration::from_raw(2),
            },
            Some(entry),
            TerminationStatus::exited(0),
        )
        .unwrap();
        let (_thread, membership) = TerminalCustody::<Thread, Live>::admitted(identity)
            .begin()
            .reserve_nonfinal(&page)
            .unwrap_or_else(|_| panic!("admitted exiting sibling must finish during close"));
        assert_eq!(page.claimed_count(), 1);
        admission.commit_with_member(&member).unwrap();
        membership.publish();
        assert_eq!(page.state(0).unwrap().1, EntryState::ExitedInZone);
        let receipts = closing
            .observe_members(&page, &members, &observation, &[])
            .expect("late in-zone exit supplies its exact receipt");
        assert!(closing.can_settle(&page, &receipts));
        page.reap(entry).unwrap();
        assert!(closing.settle(&page, receipts).is_ok());
    }

    #[test]
    fn completed_pool_proof_uses_member_exit_kind_after_entry_reuse() {
        struct Member {
            entry: EntryRef,
            exit: crate::lifecycle::MemberExitCustody,
            host: Option<ThreadBirthIdentity>,
        }
        impl MemberControl for Member {
            fn member_entry(&self) -> Option<EntryRef> {
                Some(self.entry)
            }
            fn exit_custody(&self) -> &crate::lifecycle::MemberExitCustody {
                &self.exit
            }
            fn host_retirement(&self) -> Option<HostThreadRetirementReceipt> {
                self.host.map(ThreadBirthIdentity::retirement)
            }
        }
        let page = Page {
            terminal: crate::terminal::ProcessExitCustody::new(),
            gate: AtomicU32::new(0),
            live: AtomicU32::new(0),
        };
        let identity = ProcessTerminalIdentity::from_exit(
            TaskKey {
                id: TaskId::from_registry_allocation(NonZeroI32::new(41).unwrap()),
                serial: TaskSerial::from_raw_u64(11).unwrap(),
            },
            AddressContext {
                root: RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x10000)).unwrap(),
                mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::new(1).unwrap()),
                generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::new(1).unwrap()),
            },
            TerminationStatus::exited(7),
        );
        let entry = EntryRef::new(0, 1);
        let members = MemberSet::new(identity, alloc::vec![entry], Vec::new());
        let custody = TerminalCustody::<Process, Live>::admitted(identity).close_gate(&page);
        let in_zone = Member {
            entry,
            exit: crate::lifecycle::MemberExitCustody::new(),
            host: None,
        };
        let receipt = birth_receipt(42, 12, 102);
        let observation = [PoolMemberObservation {
            entry,
            member: &in_zone,
            expected_host: receipt,
        }];
        assert!(
            custody
                .observe_members(&page, &members, &observation, &[])
                .is_none()
        );
        in_zone.exit.test_record(4);
        assert!(
            custody
                .observe_members(&page, &members, &observation, &[])
                .is_some()
        );

        let host = Member {
            entry,
            exit: crate::lifecycle::MemberExitCustody::new(),
            host: Some(receipt),
        };
        let observation = [PoolMemberObservation {
            entry,
            member: &host,
            expected_host: receipt,
        }];
        assert!(
            custody
                .observe_members(&page, &members, &observation, &[])
                .is_none()
        );
        host.exit.test_record(8);
        assert!(
            custody
                .observe_members(&page, &members, &observation, &[])
                .is_some()
        );
        let wrong_receipt = [PoolMemberObservation {
            entry,
            member: &host,
            expected_host: birth_receipt(42, 13, 102),
        }];
        assert!(
            custody
                .observe_members(&page, &members, &wrong_receipt, &[])
                .is_none()
        );
        let recycled = Member {
            entry: EntryRef::new(0, 2),
            exit: crate::lifecycle::MemberExitCustody::new(),
            host: Some(receipt),
        };
        recycled.exit.test_record(8);
        let wrong_generation = [PoolMemberObservation {
            entry,
            member: &recycled,
            expected_host: receipt,
        }];
        assert!(
            custody
                .observe_members(&page, &members, &wrong_generation, &[])
                .is_none()
        );
    }
}
