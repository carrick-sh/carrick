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
#[derive(Debug, Eq, PartialEq)]
pub struct MemberSet {
    pool_mask: u16,
    adopted: Box<[HostThreadRetirementReceipt]>,
}

impl MemberSet {
    pub fn new(
        pool_mask: u16,
        adopted: Vec<HostThreadRetirementReceipt>,
        capacity: usize,
    ) -> Option<Self> {
        if adopted.len() > capacity {
            return None;
        }
        Some(Self {
            pool_mask,
            adopted: adopted.into_boxed_slice(),
        })
    }
    pub fn pool_mask(self) -> u16 {
        self.pool_mask
    }
    pub fn adopted(&self) -> &[HostThreadRetirementReceipt] {
        &self.adopted
    }
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

    pub fn close(
        self,
        page: &impl Lifecycle,
        members: MemberSet,
    ) -> (TerminalCustody<Process, Closing>, RetirementVerdict) {
        page.close();
        (
            TerminalCustody {
                identity: self.identity,
                phase: PhantomData,
            },
            RetirementVerdict::CancelMembers {
                process: self.identity,
                members,
            },
        )
    }
}

impl TerminalCustody<Process, Closing> {
    pub fn settle(
        self,
        page: &impl Lifecycle,
        receipts_returned: bool,
    ) -> Result<TerminalCustody<Process, Settled>, Self> {
        if page.live() != 0 || page.claimed_count() != 0 || !receipts_returned {
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
