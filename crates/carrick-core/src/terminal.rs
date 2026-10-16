//! Exact, by-value thread terminal custody. The page live word chooses the
//! nonfinal member; lanes apply the resulting verdict.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::num::{NonZeroI32, NonZeroU64};

use carrick_core_abi::entry::{
    EntryGeneration, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
};
use carrick_core_abi::lifecycle::EntryRef;
use carrick_guest_arch::{AddressContext, RootGpa};
use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial, TerminationStatus};

use crate::lifecycle::{
    Lifecycle, MemberControl, MemberExitKind, MembershipFloor, NonfinalExitMembership,
};

pub struct PoolMemberObservation<'a> {
    pub entry: EntryRef,
    /// The control slot retained by this member, even if its shared pool
    /// entry has since been reaped and reused. Host retirement must publish
    /// its typed receipt on this same slot.
    pub member: &'a dyn MemberControl,
    pub expected_host: HostThreadRetirementReceipt,
}

pub enum HostMemberObservation<'a> {
    Adopted {
        binding: HostThreadRetirementReceipt,
        member: &'a dyn MemberControl,
    },
    HostBorn {
        identity: HostThreadRetirementReceipt,
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

#[cfg(test)]
mod process_physical_publication_tests {
    use super::ProcessPhysicalPublication;
    use alloc::vec;

    #[test]
    fn failure_after_normal_retirement_reuses_exact_receipt() {
        let mut owner = ProcessPhysicalPublication::default();
        assert!(owner.failure_needs_publication());
        assert!(owner.publish(vec![11_u32, 12]).is_ok());
        assert!(!owner.failure_needs_publication());
        assert_eq!(owner.published(), Some(&vec![11, 12]));
        assert!(owner.publish(vec![13]).is_err());
        assert_eq!(owner.published(), Some(&vec![11, 12]));
    }
}

impl<C> ProcessPhysicalPublication<C> {
    pub fn publish(&mut self, completion: C) -> Result<(), C> {
        if !matches!(self, Self::Unpublished) {
            return Err(completion);
        }
        *self = Self::Published(completion);
        Ok(())
    }

    pub fn published(&self) -> Option<&C> {
        match self {
            Self::Unpublished => None,
            Self::Published(completion) => Some(completion),
        }
    }

    pub fn failure_needs_publication(&self) -> bool {
        matches!(self, Self::Unpublished)
    }
}
/// One process incarnation owns exactly one terminal admission claim.
#[repr(C)]
#[derive(::core::fmt::Debug, ::core::default::Default)]
pub struct ProcessExitCustody {
    begun: core::sync::atomic::AtomicU32,
    fork_publications: core::sync::atomic::AtomicU32,
}
impl ProcessExitCustody {
    pub const fn new() -> Self {
        Self {
            begun: core::sync::atomic::AtomicU32::new(0),
            fork_publications: core::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl ProcessExitCustody {
    pub(crate) fn fork_publications(&self) -> usize {
        self.fork_publications
            .load(core::sync::atomic::Ordering::SeqCst) as usize
    }
}

/// An admitted host fork publication, retained until publication or rollback
/// completes. It is an outstanding claim, never a parent thread membership.
pub struct ForkPublicationClaim<P: core::ops::Deref>(P)
where
    P::Target: Lifecycle;
impl<P: core::ops::Deref> ForkPublicationClaim<P>
where
    P::Target: Lifecycle,
{
    pub fn acquire(page: P) -> Result<Self, carrick_core_abi::lifecycle::GateState> {
        use carrick_core_abi::lifecycle::GateState;
        use core::sync::atomic::Ordering;
        page.process_exit_custody()
            .fork_publications
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
impl<P: core::ops::Deref> Drop for ForkPublicationClaim<P>
where
    P::Target: Lifecycle,
{
    fn drop(&mut self) {
        self.0
            .process_exit_custody()
            .fork_publications
            .fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
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
    host: Box<[HostThreadRetirementReceipt]>,
}

impl MemberSet {
    pub(crate) fn new(
        process: ProcessTerminalIdentity,
        mut pool: Vec<EntryRef>,
        mut host: Vec<HostThreadRetirementReceipt>,
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
    pub fn host(&self) -> &[HostThreadRetirementReceipt] {
        &self.host
    }
    /// Move one exact expected host receipt with its retained execution
    /// binding. A duplicate or absent identity cannot mint a new proof.
    pub fn rehome_host(
        &mut self,
        old: HostThreadRetirementReceipt,
        new: HostThreadRetirementReceipt,
    ) -> bool {
        let Some(index) = self.host.iter().position(|receipt| *receipt == old) else {
            return false;
        };
        if old != new && self.host.contains(&new) {
            return false;
        }
        self.host[index] = new;
        true
    }
    pub(crate) fn completed(
        &self,
        pool: &[EntryRef],
        host: &[HostThreadRetirementReceipt],
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

/// Host retirement's exact acknowledgement of an adopted member. A visible
/// tid is never sufficient: its execution or thread generation may be reused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostThreadRetirementReceipt {
    task: EntryTaskKey,
    execution: EntryGeneration,
    thread: EntryThreadGeneration,
}

impl HostThreadRetirementReceipt {
    pub fn from_parts(
        task: EntryTaskKey,
        execution: EntryGeneration,
        thread: EntryThreadGeneration,
    ) -> Option<Self> {
        (task.raw() != 0 && execution.raw() != 0 && thread.raw() != 0).then_some(Self {
            task,
            execution,
            thread,
        })
    }

    pub fn from_binding(binding: ExecutionBinding) -> Self {
        Self {
            task: binding.task,
            execution: binding.generation,
            thread: binding.thread_generation,
        }
    }

    pub fn matches(self, binding: ExecutionBinding) -> bool {
        self == Self::from_binding(binding)
    }

    pub fn task(self) -> EntryTaskKey {
        self.task
    }
    pub fn execution(self) -> EntryGeneration {
        self.execution
    }
    pub fn thread(self) -> EntryThreadGeneration {
        self.thread
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

    pub fn task(&self) -> Option<TaskKey> {
        Some(TaskKey {
            id: task_id_from_binding(self.binding)?,
            serial: TaskSerial::from_raw_u64(self.binding.generation.raw())?,
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
pub enum RetirementVerdict {
    RetireThreadOnHost {
        identity: ThreadTerminalIdentity,
    },
    RetireThread {
        identity: ThreadTerminalIdentity,
        requires_slot_absence: bool,
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
        host: Vec<HostThreadRetirementReceipt>,
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
        host: &[HostThreadRetirementReceipt],
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
        let mut completed_pool = Vec::with_capacity(pool.len());
        for observation in pool {
            let kind = crate::lifecycle::recorded_member_exit_kind(
                observation.member,
                Some(observation.entry),
            );
            let returned = match kind {
                MemberExitKind::InZone => true,
                MemberExitKind::HostRetiring => {
                    observation.member.host_retirement() == Some(observation.expected_host)
                }
                MemberExitKind::Active | MemberExitKind::Stale => false,
            };
            if !returned {
                return None;
            }
            completed_pool.push(observation.entry);
        }
        let mut completed_host = Vec::with_capacity(host.len());
        for observation in host {
            let identity = match observation {
                HostMemberObservation::Adopted { binding, member }
                    if crate::lifecycle::recorded_member_exit_kind(
                        *member,
                        member.member_entry(),
                    ) != MemberExitKind::InZone
                        && member.host_retirement() == Some(*binding) =>
                {
                    *binding
                }
                HostMemberObservation::HostBorn { identity, index }
                    if page.host_birth_receipt_returned_exact(*index, *identity) =>
                {
                    *identity
                }
                _ => return None,
            };
            completed_host.push(identity);
        }
        self.complete_members(members, &completed_pool, &completed_host)
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
        let membership = match page.reserve_nonfinal_exit() {
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
    pub fn into_verdict(self) -> RetirementVerdict {
        RetirementVerdict::RetireThread {
            identity: self.identity,
            requires_slot_absence: self.identity.entry.is_some(),
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
    use core::sync::atomic::AtomicU32;

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
            _: HostThreadRetirementReceipt,
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
    fn rehomed_host_receipt_replaces_exact_pending_identity() {
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
        let old = HostThreadRetirementReceipt::from_binding(ExecutionBinding {
            task: EntryTaskKey::from_raw(42),
            generation: EntryGeneration::from_raw(1),
            mm: carrick_core_abi::entry::EntryMmKey::from_raw(5),
            thread_generation: EntryThreadGeneration::from_raw(2),
        });
        let new = HostThreadRetirementReceipt::from_binding(ExecutionBinding {
            task: EntryTaskKey::from_raw(42),
            generation: EntryGeneration::from_raw(2),
            mm: carrick_core_abi::entry::EntryMmKey::from_raw(5),
            thread_generation: EntryThreadGeneration::from_raw(2),
        });
        let mut members = MemberSet::new(identity, Vec::new(), alloc::vec![old]);
        assert!(members.rehome_host(old, new));
        assert!(members.completed(&[], &[old]).is_none());
        assert!(members.completed(&[], &[new]).is_some());
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
    fn completed_pool_proof_uses_member_exit_kind_after_entry_reuse() {
        struct Member {
            entry: EntryRef,
            exit: crate::lifecycle::MemberExitCustody,
            host: Option<HostThreadRetirementReceipt>,
        }
        impl MemberControl for Member {
            fn member_entry(&self) -> Option<EntryRef> {
                Some(self.entry)
            }
            fn exit_custody(&self) -> &crate::lifecycle::MemberExitCustody {
                &self.exit
            }
            fn host_retirement(&self) -> Option<HostThreadRetirementReceipt> {
                self.host
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
        let receipt = HostThreadRetirementReceipt::from_binding(ExecutionBinding {
            task: EntryTaskKey::from_raw(42),
            generation: EntryGeneration::from_raw(12),
            mm: carrick_core_abi::entry::EntryMmKey::from_raw(1),
            thread_generation: EntryThreadGeneration::from_raw(102),
        });
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
            expected_host: HostThreadRetirementReceipt::from_binding(ExecutionBinding {
                task: EntryTaskKey::from_raw(42),
                generation: EntryGeneration::from_raw(13),
                mm: carrick_core_abi::entry::EntryMmKey::from_raw(1),
                thread_generation: EntryThreadGeneration::from_raw(102),
            }),
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
