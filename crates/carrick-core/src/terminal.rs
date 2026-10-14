//! Exact, by-value thread terminal custody. The page live word chooses the
//! nonfinal member; lanes apply the resulting verdict.

use core::marker::PhantomData;
use core::num::NonZeroU64;

use carrick_core_abi::entry::ExecutionBinding;
use carrick_core_abi::lifecycle::EntryRef;
use carrick_sched_core::process::{TaskId, TaskKey, TaskSerial, TerminationStatus};

use crate::lifecycle::{Lifecycle, MembershipFloor, NonfinalExitMembership};

pub struct Thread;
pub struct Live;
pub struct Exiting;
pub struct Terminal;

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

pub struct TerminalCustody<K, P> {
    identity: ThreadTerminalIdentity,
    phase: PhantomData<(K, P, *const ())>,
}

#[must_use]
pub enum RetirementVerdict {
    RetireThread {
        identity: ThreadTerminalIdentity,
        requires_slot_absence: bool,
    },
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
