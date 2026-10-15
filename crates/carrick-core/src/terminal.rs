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

use crate::lifecycle::{Lifecycle, MembershipFloor, NonfinalExitMembership};

fn task_id_from_binding(binding: ExecutionBinding) -> Option<TaskId> {
    let raw = i32::try_from(binding.task.raw()).ok()?;
    if raw <= 0 {
        return None;
    }
    Some(TaskId::from_registry_allocation(NonZeroI32::new(raw)?))
}

pub struct Thread;
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
    pub(crate) fn admitted_exit(
        task: TaskKey,
        address: AddressContext<RootGpa>,
        status: TerminationStatus,
    ) -> Self {
        Self::admitted(ProcessTerminalIdentity::from_exit(task, address, status))
    }
    pub(crate) fn admitted(identity: ProcessTerminalIdentity) -> Self {
        Self {
            identity,
            phase: PhantomData,
        }
    }

    pub fn close_gate(self, page: &impl Lifecycle) -> TerminalCustody<Process, Closing> {
        page.close();
        TerminalCustody {
            identity: self.identity,
            phase: PhantomData,
        }
    }

    pub fn begin_exit(
        page: &impl Lifecycle,
        task: TaskKey,
        address: AddressContext<RootGpa>,
        status: TerminationStatus,
    ) -> Result<TerminalCustody<Process, Closing>, MembershipFloor> {
        page.release_live(0)?;
        Ok(Self::admitted_exit(task, address, status).close_gate(page))
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
    pub fn can_settle_observed(
        &self,
        page: &impl Lifecycle,
        members: &MemberSet,
        pool: &[EntryRef],
        host: &[HostThreadRetirementReceipt],
    ) -> bool {
        self.complete_members(members, pool, host)
            .is_some_and(|receipts| self.can_settle(page, &receipts))
    }

    pub fn settle_observed(
        self,
        page: &impl Lifecycle,
        members: &MemberSet,
        pool: &[EntryRef],
        host: &[HostThreadRetirementReceipt],
    ) -> Result<TerminalCustody<Process, Settled>, Self> {
        match self.complete_members(members, pool, host) {
            Some(receipts) => self.settle(page, receipts),
            None => Err(self),
        }
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
        gate: AtomicU32,
        live: AtomicU32,
    }
    impl Lifecycle for Page {
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
}
