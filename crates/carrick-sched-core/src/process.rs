//! Shared process identity and exit receipts. These are the same domains
//! used by host kernel graph consumers and guest lifecycle owners.
use carrick_syscall_abi::LinuxWaitOptions;
use core::num::{NonZeroI32, NonZeroU64};
use core::time::Duration;

pub mod birth;
pub mod exit;
pub mod identity_allocator;
pub mod registry;
pub mod wait;

#[cfg(test)]
mod exit_tests;

macro_rules! linux_i32_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(NonZeroI32);

        impl $name {
            pub fn from_abi_positive(raw: i32) -> Result<Self, InvalidLinuxId> {
                let value = NonZeroI32::new(raw).ok_or(InvalidLinuxId::Zero)?;
                if raw < 0 {
                    return Err(InvalidLinuxId::Negative(raw));
                }
                Ok(Self(value))
            }

            pub const fn raw(self) -> i32 {
                self.0.get()
            }
        }
    };
}

macro_rules! serial_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            pub const fn from_registry_allocation(raw: NonZeroU64) -> Self {
                Self(raw)
            }

            pub const fn raw(self) -> u64 {
                self.0.get()
            }

            #[allow(dead_code)]
            pub const fn from_raw_u64(raw: u64) -> Option<Self> {
                match NonZeroU64::new(raw) {
                    Some(nz) => Some(Self(nz)),
                    None => None,
                }
            }
        }
    };
}

linux_i32_id!(TaskId);
linux_i32_id!(ProcessGroupId);
linux_i32_id!(SessionId);
serial_id!(TaskSerial);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct LinuxSignal(NonZeroI32);

impl LinuxSignal {
    pub fn for_signal_number(raw: i32) -> Result<Self, InvalidLinuxSignal> {
        let value = NonZeroI32::new(raw).ok_or(InvalidLinuxSignal::OutOfRange(raw))?;
        if !(1..=64).contains(&raw) {
            return Err(InvalidLinuxSignal::OutOfRange(raw));
        }
        Ok(Self(value))
    }

    pub const fn raw(self) -> i32 {
        self.0.get()
    }

    /// Whether this is a POSIX realtime signal (`SIGRTMIN..=SIGRTMAX`, 32..=64
    /// on Linux/aarch64).
    ///
    /// The distinction is not cosmetic: realtime signals QUEUE — every send is
    /// delivered, with its own siginfo, in send order — while a standard signal
    /// collapses to one pending bit no matter how many times it is sent. The
    /// pending queue picks `enqueue_realtime` vs `enqueue_standard` from this,
    /// so a wrong answer silently drops or duplicates deliveries.
    ///
    /// This is THE authority for the question; callers holding a raw signum go
    /// through [`Self::for_signal_number`] rather than re-testing the range.
    pub const fn is_realtime(self) -> bool {
        self.0.get() >= 32
    }

    /// `SIGCHLD` (17 on Linux/aarch64): the exit signal an ordinary `fork`
    /// child delivers, and the one `wait(2)` selects by default.
    pub const SIGCHLD: Self = Self(NonZeroI32::new(17).unwrap());
}

/// The signal a task delivers to its parent when it terminates -- the
/// `CSIGNAL` byte of `clone(2)` flags or `clone3(2)`'s `exit_signal`.
///
/// This is task state because Linux `wait(2)` partitions children on it: a
/// child whose exit signal is anything other than `SIGCHLD` -- a different
/// signal or none at all -- is a "clone child", visible only to a wait that
/// passes `__WCLONE` or `__WALL`. A plain `waitpid` on such a child is
/// `ECHILD`, not a reap (wait(2), "__WCLONE").
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChildExitSignal {
    /// Exit signal 0: the parent is not signalled at all.
    None,
    Signal(LinuxSignal),
}

impl ChildExitSignal {
    pub const SIGCHLD: Self = Self::Signal(LinuxSignal::SIGCHLD);

    /// The exit signal a clone request carries. The dispatch layer has
    /// already lowered an out-of-range `CSIGNAL` byte to 0, so anything
    /// other than a valid signal number means "no signal".
    pub fn for_clone_request(raw: u32) -> Self {
        i32::try_from(raw)
            .ok()
            .and_then(|raw| LinuxSignal::for_signal_number(raw).ok())
            .map_or(Self::None, Self::Signal)
    }

    /// Whether `wait(2)` treats this child as a "clone child".
    pub fn is_clone_child(self) -> bool {
        self != Self::SIGCHLD
    }

    /// The raw signal number, 0 for none -- the value `clone3`'s
    /// `exit_signal` field carries.
    pub fn raw(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Signal(signal) => signal.raw(),
        }
    }
}

impl TaskId {
    pub const fn from_registry_allocation(raw: NonZeroI32) -> Self {
        Self(raw)
    }

    pub fn for_root_bootstrap(raw: i32) -> Result<Self, InvalidLinuxId> {
        Self::from_abi_positive(raw)
    }
}

impl TaskId {
    pub const fn nonzero(self) -> NonZeroI32 {
        self.0
    }
}
impl ProcessGroupId {
    pub fn from_leader(leader: TaskId) -> Self {
        Self(leader.nonzero())
    }
}
impl SessionId {
    pub fn from_leader(leader: TaskId) -> Self {
        Self(leader.nonzero())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidLinuxId {
    Zero,
    Negative(i32),
}
impl core::fmt::Display for InvalidLinuxId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Zero => f.write_str("Linux identity zero is reserved"),
            Self::Negative(raw) => write!(f, "Linux identity {raw} is negative"),
        }
    }
}
impl core::error::Error for InvalidLinuxId {}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvalidLinuxSignal {
    OutOfRange(i32),
}
impl core::fmt::Display for InvalidLinuxSignal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self::OutOfRange(raw) = self;
        write!(f, "Linux signal number {raw} is outside 1..=64")
    }
}
impl core::error::Error for InvalidLinuxSignal {}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskKey {
    pub id: TaskId,
    pub serial: TaskSerial,
}

impl core::fmt::Display for TaskKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "task#{}:{}", self.id.raw(), self.serial.raw())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct LinuxWaitStatus(i32);

impl LinuxWaitStatus {
    pub const fn from_wait_encoding(raw: i32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaskRusage {
    pub user_time: Duration,
    pub system_time: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskLifecycle {
    Live,
    Exiting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskIdentity {
    pub process_group: ProcessGroupId,
    pub session: SessionId,
}

impl TaskIdentity {
    /// A fresh process group and session both led by `leader`.
    pub fn led_by(leader: TaskId) -> Self {
        Self {
            process_group: ProcessGroupId::from_leader(leader),
            session: SessionId::from_leader(leader),
        }
    }
}

/// Authoritative parent/child edges of one exact process incarnation.
/// Synchronization and topology reservations belong to the enclosing graph;
/// host and guest consumers store this record, never a mirrored edge index.
#[derive(Debug)]
pub struct ProcessRelations {
    parent: Option<TaskKey>,
    children: alloc::collections::BTreeSet<TaskKey>,
}
impl ProcessRelations {
    pub fn new(parent: Option<TaskKey>) -> Self {
        Self {
            parent,
            children: alloc::collections::BTreeSet::new(),
        }
    }
    pub const fn parent(&self) -> Option<TaskKey> {
        self.parent
    }
    pub fn reparent(&mut self, parent: Option<TaskKey>) {
        self.parent = parent;
    }
    pub fn add_child(&mut self, child: TaskKey) -> bool {
        self.children.insert(child)
    }
    pub fn remove_child(&mut self, child: TaskKey) -> bool {
        self.children.remove(&child)
    }
    pub fn children(&self) -> &alloc::collections::BTreeSet<TaskKey> {
        &self.children
    }
    pub fn publish_prepared_children(&mut self, children: alloc::collections::BTreeSet<TaskKey>) {
        self.children = children;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitMode {
    Observe,
    Consume,
}

/// Which children a `wait(2)` call can see, by the child's exit signal.
///
/// Linux partitions a parent's children into ordinary ones (exit signal
/// `SIGCHLD`) and "clone children" (any other exit signal, or none). A plain
/// wait sees only the former; `__WCLONE` selects only the latter and
/// `__WALL` both (wait(2)). The partition applies to real children in every
/// arm of the wait -- the zombie scan, job-control state changes, and the
/// `ECHILD`/block decision -- but not to ptrace tracees a tracer waits on
/// without being their parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitChildClass {
    /// The default: children whose exit signal is `SIGCHLD`.
    Sigchld,
    /// `__WCLONE`: only clone children.
    Clone,
    /// `__WALL`: every child regardless of exit signal.
    All,
}

impl WaitChildClass {
    pub fn from_wait_options(options: LinuxWaitOptions) -> Self {
        if options.contains(LinuxWaitOptions::WALL) {
            Self::All
        } else if options.contains(LinuxWaitOptions::WCLONE) {
            Self::Clone
        } else {
            Self::Sigchld
        }
    }

    pub fn admits(self, exit_signal: ChildExitSignal) -> bool {
        match self {
            Self::Sigchld => !exit_signal.is_clone_child(),
            Self::Clone => exit_signal.is_clone_child(),
            Self::All => true,
        }
    }
}

/// Which children one wait call may reap: the `pid` argument of
/// `wait4`/`waitid` lowered to a single typed selector, so a pid, an exact
/// generation and a process group can never be combined inconsistently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitTarget {
    Any,
    Pid(TaskId),
    Exact(TaskKey),
    ProcessGroup(ProcessGroupId),
}

impl WaitTarget {
    pub fn admits(self, child: TaskKey, process_group: ProcessGroupId) -> bool {
        match self {
            Self::Any => true,
            Self::Pid(target) => target == child.id,
            Self::Exact(target) => target == child,
            Self::ProcessGroup(group) => group == process_group,
        }
    }
}

/// Compact post-exit state. It contains no task-owned `Arc` and therefore
/// cannot retain mm, files, signals, or runner state after teardown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zombie<Container, Uid> {
    pub key: TaskKey,
    /// PID the parent saw in its container PID namespace at exit. The live
    /// namespace membership is released by a consuming wait, so the receipt
    /// must retain this value for wait4/waitid rendering after reap.
    pub namespace_pid: u32,
    pub container: Container,
    pub parent: Option<TaskKey>,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
    /// Historical process-group id in this container's PID namespace. Unlike
    /// the internal group key, this remains renderable after its leader PID
    /// mapping and the final live group record have both disappeared.
    pub namespace_process_group: u32,
    /// Historical session id in this container's PID namespace.
    pub namespace_session: u32,
    pub status: LinuxWaitStatus,
    /// The real uid this process held when it exited. Linux `waitid(2)` reports
    /// this value in `siginfo_t.si_uid`, so it must survive task teardown.
    pub ruid: Uid,
    /// The effective uid this process held when it exited. An unreaped process
    /// is still addressable by `sched_*`/`setpriority`/`process_vm_*`, and
    /// those calls apply the same ownership rule they apply to a live target,
    /// so the answer has to survive the task object.
    pub euid: Uid,
    pub rusage: TaskRusage,
    /// What this task had itself accumulated from reaping its own children.
    /// Kept separate for own-process diagnostics. Consuming waits return and
    /// charge the combined subtree total.
    pub children_rusage: TaskRusage,
    /// Which `wait(2)` class this zombie belongs to (`__WCLONE`/`__WALL`).
    pub exit_signal: ChildExitSignal,
    pub diagnostic_name: alloc::string::String,
}

impl<Container, Uid> Zombie<Container, Uid> {
    /// Everything a reaper must add to its own CHILDREN ledger for this child.
    pub fn total_charge_to_reaper(&self) -> TaskRusage {
        TaskRusage {
            user_time: self.rusage.user_time + self.children_rusage.user_time,
            system_time: self.rusage.system_time + self.children_rusage.system_time,
        }
    }
}

#[cfg(test)]
mod wait_tests;
