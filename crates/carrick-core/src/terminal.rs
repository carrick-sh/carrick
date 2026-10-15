//! Exact, by-value thread terminal custody. The page live word chooses the
//! nonfinal member; lanes apply the resulting verdict.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::num::NonZeroU64;

use carrick_core_abi::entry::{
    EntryGeneration, EntryTaskKey, EntryThreadGeneration, ExecutionBinding,
};
use carrick_core_abi::lifecycle::EntryRef;
use carrick_guest_arch::{AddressContext, RootGpa};
use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial, TerminationStatus};

use crate::lifecycle::{Lifecycle, MembershipFloor, NonfinalExitMembership};

pub struct Thread;
pub struct Process;
pub struct Live;
pub struct Exiting;
pub struct Terminal;
pub struct Closing;
pub struct Settled;

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
    pub fn from_exit(
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
    pub fn new(
        process: ProcessTerminalIdentity,
        pool: Vec<EntryRef>,
        host: Vec<HostThreadRetirementReceipt>,
        capacity: usize,
    ) -> Option<Self> {
        if pool.len() + host.len() > capacity
            || pool
                .iter()
                .enumerate()
                .any(|(i, entry)| pool[..i].contains(entry))
            || host
                .iter()
                .enumerate()
                .any(|(i, receipt)| host[..i].contains(receipt))
        {
            return None;
        }
        Some(Self {
            process,
            pool: pool.into_boxed_slice(),
            host: host.into_boxed_slice(),
        })
    }
    pub fn pool(&self) -> &[EntryRef] {
        &self.pool
    }
    pub fn host(&self) -> &[HostThreadRetirementReceipt] {
        &self.host
    }
    pub fn completed(
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
        TaskId::from_abi_positive(i32::try_from(binding.task.raw()).ok()?).ok()?;
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
            id: TaskId::from_abi_positive(i32::try_from(self.binding.task.raw()).ok()?).ok()?,
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
    pub fn admitted(identity: ProcessTerminalIdentity) -> Self {
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
}

impl TerminalCustody<Process, Closing> {
    pub fn cancel_members(&self, members: MemberSet) -> Option<RetirementVerdict> {
        (self.identity == members.process).then_some(RetirementVerdict::CancelMembers {
            process: self.identity,
            members,
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
                id: TaskId::from_abi_positive(41).unwrap(),
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
        let members = MemberSet::new(identity, alloc::vec![entry], Vec::new(), 1).unwrap();
        let closing = TerminalCustody::<Process, Live>::admitted(identity).close_gate(&page);
        assert!(closing.cancel_members(members.clone()).is_some());
        assert!(members.completed(&[], &[]).is_none());
        let receipt = members.completed(&[entry], &[]).unwrap();
        assert!(closing.settle(&page, receipt).is_ok());
    }
}
