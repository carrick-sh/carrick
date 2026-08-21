//! Owned, generation-authenticated blocking syscall continuations.
//!
//! The Kernel owns a [`BlockedContinuation`] while its logical thread is
//! blocked.  [`CarrierWaitService`] owns only an exact registration referring
//! to that Kernel identity; callbacks publish durable readiness and ask the
//! scheduler to wake the exact thread, but never run guest code.

use std::collections::BTreeMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use carrick_abi::{SigBlockMask, SigSet, WaitSigMask};
use carrick_guest_mem::{GuestVa, SharedFutexLocation};
use parking_lot::{Condvar, Mutex};

use crate::dispatch::{
    BlockingHostWrite, BlockingRecordLock, DispatchOutcome, SyscallRequest, WaitFds,
};
use crate::kernel::objects::{ExecutionGeneration, ThreadKey};
use crate::kernel::{
    Kernel, KernelContext, MmId, Scheduler, Task, TaskKey, TaskRevision, VforkParentWait,
};
use crate::linux_abi::{LINUX_EAGAIN, LINUX_EINTR, LINUX_ETIMEDOUT, LinuxErrno};
use crate::thread::{FutexTable, FutexWait, FutexWaitOutcome};

static NEXT_CONTINUATION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_REGISTRATION_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_RESOURCE_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
struct FutexSource(Arc<FutexTable>);

impl std::fmt::Debug for FutexSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FutexSource")
    }
}

fn next_nonzero(source: &AtomicU64) -> u64 {
    let value = source.fetch_add(1, Ordering::Relaxed);
    if value == 0 || value == u64::MAX {
        std::process::abort();
    }
    value
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContinuationId(u64);

impl ContinuationId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationBackend {
    Hvpatch,
    HostProcessCompatibility,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartClass {
    Never,
    RestartSyscall,
    RestartNoHand,
    RestartNoIntr,
    RestartBlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallFrame {
    request: SyscallRequest,
}

impl SyscallFrame {
    pub const fn request(self) -> SyscallRequest {
        self.request
    }
}

#[derive(Debug)]
pub struct ContinuationCapture {
    kernel: Weak<Kernel>,
    task_ref: Weak<Task>,
    thread: ThreadKey,
    task: TaskKey,
    task_revision: TaskRevision,
    task_wake_generation: u64,
    mm: MmId,
    asid_generation: u64,
    persistent_signal_mask: SigSet,
    restore_after_signal: Option<SigSet>,
    execution: ExecutionGeneration,
    syscall: SyscallFrame,
    restart: RestartClass,
    backend: ContinuationBackend,
}

impl ContinuationCapture {
    pub fn from_lease(
        context: &KernelContext,
        lease: &crate::kernel::objects::ThreadExecutionLease,
        request: SyscallRequest,
        restart: RestartClass,
        backend: ContinuationBackend,
    ) -> Result<Self, ContinuationBuildError> {
        if !context.exact_thread_is_live()
            || lease.thread_key() != context.thread().key()
            || context.thread().execution_state().generation() != Some(lease.generation())
        {
            return Err(ContinuationBuildError::StaleExecutionAuthority);
        }
        let (mm, asid_generation) = lease
            .task_state_authority()
            .map_err(|_| ContinuationBuildError::StaleExecutionAuthority)?;
        if mm != context.shared().mm().id() {
            return Err(ContinuationBuildError::StaleExecutionAuthority);
        }
        let signal_authority = context.signal_authority();
        Ok(Self {
            kernel: Arc::downgrade(context.kernel()),
            task_ref: Arc::downgrade(context.task()),
            thread: context.thread().key(),
            task: context.task().key(),
            task_revision: context.revision(),
            task_wake_generation: context.task().wake_generation(),
            mm,
            asid_generation,
            persistent_signal_mask: signal_authority.blocked(),
            restore_after_signal: signal_authority.armed_restore_mask(),
            execution: lease.generation(),
            syscall: SyscallFrame { request },
            restart,
            backend,
        })
    }

    /// Compatibility constructor for callers that have not crossed the Task 2
    /// lease boundary. The HVPatch product path uses [`Self::from_lease`].
    pub fn new(
        context: &KernelContext,
        execution: ExecutionGeneration,
        request: SyscallRequest,
        restart: RestartClass,
        backend: ContinuationBackend,
    ) -> Result<Self, ContinuationBuildError> {
        if !context.exact_thread_is_live()
            || context.thread().execution_state().generation() != Some(execution)
        {
            return Err(ContinuationBuildError::StaleExecutionAuthority);
        }
        let (mm, asid_generation) = context
            .thread()
            .parked_task_state_authority(execution)
            .ok_or(ContinuationBuildError::StaleExecutionAuthority)?;
        if mm != context.shared().mm().id() {
            return Err(ContinuationBuildError::StaleExecutionAuthority);
        }
        let signal_authority = context.signal_authority();
        Ok(Self {
            kernel: Arc::downgrade(context.kernel()),
            task_ref: Arc::downgrade(context.task()),
            thread: context.thread().key(),
            task: context.task().key(),
            task_revision: context.revision(),
            task_wake_generation: context.task().wake_generation(),
            mm,
            asid_generation,
            persistent_signal_mask: signal_authority.blocked(),
            restore_after_signal: signal_authority.armed_restore_mask(),
            execution,
            syscall: SyscallFrame { request },
            restart,
            backend,
        })
    }
}

#[derive(Debug)]
pub struct ContinuationAuthority {
    kernel: Weak<Kernel>,
    task_ref: Weak<Task>,
    thread: ThreadKey,
    task: TaskKey,
    task_revision: TaskRevision,
    task_wake_generation: u64,
    execution: ExecutionGeneration,
    syscall: SyscallFrame,
    restart: RestartClass,
    mm: MmId,
    asid_generation: u64,
}

impl ContinuationAuthority {
    fn from_capture(capture: ContinuationCapture) -> Self {
        Self {
            kernel: capture.kernel,
            task_ref: capture.task_ref,
            thread: capture.thread,
            task: capture.task,
            task_revision: capture.task_revision,
            task_wake_generation: capture.task_wake_generation,
            execution: capture.execution,
            syscall: capture.syscall,
            restart: capture.restart,
            mm: capture.mm,
            asid_generation: capture.asid_generation,
        }
    }

    pub fn thread(&self) -> ThreadKey {
        self.thread
    }

    pub const fn task(&self) -> TaskKey {
        self.task
    }

    pub const fn task_revision(&self) -> TaskRevision {
        self.task_revision
    }

    pub const fn execution_generation(&self) -> ExecutionGeneration {
        self.execution
    }

    pub const fn mm(&self) -> MmId {
        self.mm
    }

    pub const fn asid_generation(&self) -> u64 {
        self.asid_generation
    }

    pub const fn syscall(&self) -> SyscallFrame {
        self.syscall
    }

    pub const fn restart_class(&self) -> RestartClass {
        self.restart
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestOutputRange {
    start: GuestVa,
    len: usize,
    mm: MmId,
    asid_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalMaskContinuationState {
    persistent: SigSet,
    temporary: Option<WaitSigMask>,
    restore_after_signal: Option<SigSet>,
}

impl SignalMaskContinuationState {
    pub const fn persistent(self) -> SigSet {
        self.persistent
    }

    pub const fn temporary(self) -> Option<WaitSigMask> {
        self.temporary
    }

    pub const fn restore_after_signal(self) -> Option<SigSet> {
        self.restore_after_signal
    }
}

impl GuestOutputRange {
    pub fn new(
        start: GuestVa,
        len: usize,
        mm: MmId,
        asid_generation: u64,
    ) -> Result<Self, ContinuationBuildError> {
        if len == 0 || start.raw().checked_add(len as u64).is_none() {
            return Err(ContinuationBuildError::InvalidGuestOutputRange);
        }
        Ok(Self {
            start,
            len,
            mm,
            asid_generation,
        })
    }

    pub const fn start(self) -> GuestVa {
        self.start
    }

    pub const fn len(self) -> usize {
        self.len
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub const fn mm(self) -> MmId {
        self.mm
    }

    pub const fn asid_generation(self) -> u64 {
        self.asid_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildSelector {
    Exact(TaskKey),
    AnyChildOf(TaskKey),
    HostPid(i32),
}

#[derive(Clone, Debug)]
struct OwnedFdRegistration {
    #[allow(dead_code)]
    fd: Arc<OwnedFd>,
    #[allow(dead_code)]
    events: i16,
    #[allow(dead_code)]
    generation: u64,
}

fn own_wait_fds(fds: &WaitFds) -> Result<Vec<OwnedFdRegistration>, ContinuationBuildError> {
    fds.iter()
        .map(|fd| {
            let owned = unsafe { libc::fcntl(fd.fd(), libc::F_DUPFD_CLOEXEC, 0) };
            if owned < 0 {
                return Err(ContinuationBuildError::FdPinFailed);
            }
            Ok(OwnedFdRegistration {
                fd: Arc::new(unsafe { OwnedFd::from_raw_fd(owned) }),
                events: fd.events(),
                generation: next_nonzero(&NEXT_RESOURCE_GENERATION),
            })
        })
        .collect()
}

#[derive(Debug)]
enum ContinuationDetail {
    Futex {
        wait: FutexWait,
        index: Option<i64>,
    },
    SharedFutex {
        location: SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        index: Option<i64>,
    },
    SharedWord {
        location: SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        sysv: Option<crate::dispatch::SysvWaitState>,
    },
    Fds {
        #[allow(dead_code)]
        registrations: Vec<OwnedFdRegistration>,
        on_timeout: i64,
        sig_mask: WaitSigMask,
    },
    Select {
        #[allow(dead_code)]
        registrations: Vec<OwnedFdRegistration>,
        sig_mask: WaitSigMask,
    },
    HostWrite(Arc<Mutex<BlockingHostWrite>>),
    RecordLock(Arc<BlockingRecordLock>),
    Process {
        selector: ChildSelector,
        sig_mask: WaitSigMask,
    },
    Signals {
        wait_set: SigSet,
        block_mask: SigBlockMask,
    },
    Sleep,
    Vfork {
        child: TaskKey,
        #[allow(dead_code)]
        wait: VforkParentWait,
    },
}

#[derive(Debug)]
struct CleanupState {
    settled: AtomicBool,
    #[cfg(test)]
    probe: Option<Arc<AtomicUsize>>,
}

impl CleanupState {
    fn new() -> Self {
        Self {
            settled: AtomicBool::new(false),
            #[cfg(test)]
            probe: None,
        }
    }

    fn settle(&self) -> usize {
        if self.settled.swap(true, Ordering::AcqRel) {
            return 0;
        }
        #[cfg(test)]
        if let Some(probe) = &self.probe {
            probe.fetch_add(1, Ordering::SeqCst);
        }
        1
    }
}

#[derive(Debug)]
struct RegistrationBinding {
    token: ContinuationWakeToken,
    service: Weak<CarrierWaitServiceInner>,
}

#[derive(Debug)]
pub struct ContinuationState {
    id: ContinuationId,
    authority: ContinuationAuthority,
    deadline: Option<Instant>,
    outputs: Vec<GuestOutputRange>,
    signal_masks: SignalMaskContinuationState,
    detail: ContinuationDetail,
    resource_generation: u64,
    private_futex: Option<FutexSource>,
    producer_completion: Arc<Mutex<Option<DispatchOutcome>>>,
    registration: Option<RegistrationBinding>,
    cleanup: CleanupState,
}

impl Drop for ContinuationState {
    fn drop(&mut self) {
        if let Some(binding) = self.registration.take()
            && let Some(service) = binding.service.upgrade()
        {
            service.finish_exact(binding.token);
        }
        let _ = self.cleanup.settle();
    }
}

#[derive(Debug)]
pub enum BlockedContinuation {
    FutexWait(ContinuationState),
    FutexWaitv(ContinuationState),
    SharedFutexWait(ContinuationState),
    SharedFutexWaitv(ContinuationState),
    WaitOnSharedWord(ContinuationState),
    WaitOnFds(ContinuationState),
    WaitOnFdsSelect(ContinuationState),
    WaitOnPollFds(ContinuationState),
    BlockingHostWrite(ContinuationState),
    BlockingRecordLock(ContinuationState),
    WaitOnProcExit(ContinuationState),
    WaitOnProcState(ContinuationState),
    WaitOnHvpatchChild(ContinuationState),
    WaitOnSignals(ContinuationState),
    WaitOnSleep(ContinuationState),
    VforkParent(ContinuationState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationFamily {
    FutexWait,
    FutexWaitv,
    SharedFutexWait,
    SharedFutexWaitv,
    WaitOnSharedWord,
    WaitOnFds,
    WaitOnFdsSelect,
    WaitOnPollFds,
    BlockingHostWrite,
    BlockingRecordLock,
    WaitOnProcExit,
    WaitOnProcState,
    WaitOnHvpatchChild,
    WaitOnSignals,
    WaitOnSleep,
    VforkParent,
}

pub const fn is_blocking_dispatch_outcome(outcome: &DispatchOutcome) -> bool {
    matches!(
        outcome,
        DispatchOutcome::FutexWait { .. }
            | DispatchOutcome::FutexWaitv { .. }
            | DispatchOutcome::SharedFutexWait { .. }
            | DispatchOutcome::SharedFutexWaitv { .. }
            | DispatchOutcome::WaitOnSharedWord { .. }
            | DispatchOutcome::WaitOnFds { .. }
            | DispatchOutcome::WaitOnFdsSelect { .. }
            | DispatchOutcome::WaitOnPollFds { .. }
            | DispatchOutcome::BlockingHostWrite(_)
            | DispatchOutcome::BlockingRecordLock(_)
            | DispatchOutcome::WaitOnProcExit { .. }
            | DispatchOutcome::WaitOnProcState { .. }
            | DispatchOutcome::WaitOnHvpatchChild { .. }
            | DispatchOutcome::WaitOnSignals { .. }
            | DispatchOutcome::WaitOnSleep { .. }
    )
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ContinuationBuildError {
    #[error("continuation execution authority is stale")]
    StaleExecutionAuthority,
    #[error("host-process wait is prohibited on HVPatch")]
    HostProcessWaitOnHvpatch,
    #[error("HVPatch child selector is stale or invalid")]
    StaleChildSelector,
    #[error("dispatch outcome is not blocking")]
    NonBlockingOutcome,
    #[error("failed to pin an exact fd description")]
    FdPinFailed,
    #[error("guest output range is empty or overflows")]
    InvalidGuestOutputRange,
}

impl BlockedContinuation {
    pub fn from_dispatch_outcome(
        outcome: DispatchOutcome,
        capture: ContinuationCapture,
    ) -> Result<Self, ContinuationBuildError> {
        let backend = capture.backend;
        let parent_task = capture.task;
        let persistent_signal_mask = capture.persistent_signal_mask;
        let restore_after_signal = capture.restore_after_signal;
        let kernel = capture.kernel.upgrade();
        let authority = ContinuationAuthority::from_capture(capture);
        let mm = authority.mm();
        let asid_generation = authority.asid_generation();
        let new_state = |deadline, outputs, temporary_signal_mask, detail| ContinuationState {
            id: ContinuationId(next_nonzero(&NEXT_CONTINUATION_ID)),
            authority,
            deadline,
            outputs,
            signal_masks: SignalMaskContinuationState {
                persistent: persistent_signal_mask,
                temporary: temporary_signal_mask,
                restore_after_signal,
            },
            detail,
            resource_generation: next_nonzero(&NEXT_RESOURCE_GENERATION),
            private_futex: None,
            producer_completion: Arc::new(Mutex::new(None)),
            registration: None,
            cleanup: CleanupState::new(),
        };
        let deadline = |duration: Option<Duration>| duration.map(|value| Instant::now() + value);
        Ok(match outcome {
            DispatchOutcome::FutexWait { wait, timeout } => Self::FutexWait(new_state(
                deadline(timeout),
                Vec::new(),
                None,
                ContinuationDetail::Futex { wait, index: None },
            )),
            DispatchOutcome::FutexWaitv {
                wait,
                timeout,
                index,
            } => Self::FutexWaitv(new_state(
                deadline(timeout),
                Vec::new(),
                None,
                ContinuationDetail::Futex {
                    wait,
                    index: Some(index),
                },
            )),
            DispatchOutcome::SharedFutexWait {
                location,
                waiter_key,
                value,
                timeout,
            } => Self::SharedFutexWait(new_state(
                deadline(timeout),
                Vec::new(),
                None,
                ContinuationDetail::SharedFutex {
                    location,
                    waiter_key,
                    value,
                    index: None,
                },
            )),
            DispatchOutcome::SharedFutexWaitv {
                location,
                waiter_key,
                value,
                timeout,
                index,
            } => Self::SharedFutexWaitv(new_state(
                deadline(timeout),
                Vec::new(),
                None,
                ContinuationDetail::SharedFutex {
                    location,
                    waiter_key,
                    value,
                    index: Some(index),
                },
            )),
            DispatchOutcome::WaitOnSharedWord {
                location,
                waiter_key,
                value,
                sysv,
            } => Self::WaitOnSharedWord(new_state(
                None,
                Vec::new(),
                None,
                ContinuationDetail::SharedWord {
                    location,
                    waiter_key,
                    value,
                    sysv,
                },
            )),
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            } => {
                let registrations = own_wait_fds(&fds)?;
                Self::WaitOnFds(new_state(
                    deadline(timeout),
                    Vec::new(),
                    Some(sig_mask),
                    ContinuationDetail::Fds {
                        registrations,
                        on_timeout,
                        sig_mask,
                    },
                ))
            }
            DispatchOutcome::WaitOnFdsSelect {
                fds,
                timeout,
                sig_mask,
                clear_on_timeout,
            } => {
                let registrations = own_wait_fds(&fds)?;
                let outputs = clear_on_timeout
                    .into_iter()
                    .map(|(address, len)| {
                        GuestOutputRange::new(GuestVa(address), len, mm, asid_generation)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Self::WaitOnFdsSelect(new_state(
                    deadline(timeout),
                    outputs,
                    Some(sig_mask),
                    ContinuationDetail::Select {
                        registrations,
                        sig_mask,
                    },
                ))
            }
            DispatchOutcome::WaitOnPollFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            } => {
                let registrations = own_wait_fds(&fds)?;
                Self::WaitOnPollFds(new_state(
                    deadline(timeout),
                    Vec::new(),
                    Some(sig_mask),
                    ContinuationDetail::Fds {
                        registrations,
                        on_timeout,
                        sig_mask,
                    },
                ))
            }
            DispatchOutcome::BlockingHostWrite(write) => Self::BlockingHostWrite(new_state(
                None,
                Vec::new(),
                Some(WaitSigMask::NONE),
                ContinuationDetail::HostWrite(Arc::new(Mutex::new(write))),
            )),
            DispatchOutcome::BlockingRecordLock(lock) => Self::BlockingRecordLock(new_state(
                None,
                Vec::new(),
                Some(WaitSigMask::NONE),
                ContinuationDetail::RecordLock(Arc::new(lock)),
            )),
            DispatchOutcome::WaitOnProcExit { pid, sig_mask } => {
                if backend == ContinuationBackend::Hvpatch {
                    return Err(ContinuationBuildError::HostProcessWaitOnHvpatch);
                }
                Self::WaitOnProcExit(new_state(
                    None,
                    Vec::new(),
                    Some(sig_mask),
                    ContinuationDetail::Process {
                        selector: ChildSelector::HostPid(pid),
                        sig_mask,
                    },
                ))
            }
            DispatchOutcome::WaitOnProcState { pid, sig_mask } => {
                if backend == ContinuationBackend::Hvpatch {
                    return Err(ContinuationBuildError::HostProcessWaitOnHvpatch);
                }
                Self::WaitOnProcState(new_state(
                    None,
                    Vec::new(),
                    Some(sig_mask),
                    ContinuationDetail::Process {
                        selector: ChildSelector::HostPid(pid),
                        sig_mask,
                    },
                ))
            }
            DispatchOutcome::WaitOnHvpatchChild { target, sig_mask } => {
                if backend != ContinuationBackend::Hvpatch {
                    return Err(ContinuationBuildError::StaleChildSelector);
                }
                let selector = match target {
                    None => ChildSelector::AnyChildOf(parent_task),
                    Some(pid) => {
                        let id = crate::kernel::TaskId::from_abi_positive(pid)
                            .map_err(|_| ContinuationBuildError::StaleChildSelector)?;
                        let identity = kernel
                            .as_ref()
                            .ok_or(ContinuationBuildError::StaleChildSelector)?
                            .task_identity(id)
                            .map_err(|_| ContinuationBuildError::StaleChildSelector)?;
                        if identity.parent != Some(parent_task) {
                            return Err(ContinuationBuildError::StaleChildSelector);
                        }
                        ChildSelector::Exact(identity.task)
                    }
                };
                Self::WaitOnHvpatchChild(new_state(
                    None,
                    Vec::new(),
                    Some(sig_mask),
                    ContinuationDetail::Process { selector, sig_mask },
                ))
            }
            DispatchOutcome::WaitOnSignals {
                wait_set,
                block_mask,
                timeout,
            } => Self::WaitOnSignals(new_state(
                deadline(timeout),
                Vec::new(),
                None,
                ContinuationDetail::Signals {
                    wait_set,
                    block_mask,
                },
            )),
            DispatchOutcome::WaitOnSleep {
                duration,
                remaining,
            } => {
                let outputs = remaining
                    .map(|pointer| {
                        GuestOutputRange::new(
                            GuestVa(pointer.0),
                            std::mem::size_of::<libc::timespec>(),
                            mm,
                            asid_generation,
                        )
                    })
                    .transpose()?
                    .into_iter()
                    .collect();
                Self::WaitOnSleep(new_state(
                    Some(Instant::now() + duration),
                    outputs,
                    None,
                    ContinuationDetail::Sleep,
                ))
            }
            DispatchOutcome::Returned { .. }
            | DispatchOutcome::SchedulerYield
            | DispatchOutcome::Errno { .. }
            | DispatchOutcome::Exit { .. }
            | DispatchOutcome::SignalDeath { .. }
            | DispatchOutcome::Fork { .. }
            | DispatchOutcome::Execve { .. }
            | DispatchOutcome::SetMemoryModel { .. }
            | DispatchOutcome::MapHostAlias { .. }
            | DispatchOutcome::SigReturn
            | DispatchOutcome::CloneThread { .. }
            | DispatchOutcome::ThreadExit { .. }
            | DispatchOutcome::SignalThread { .. }
            | DispatchOutcome::SharedFutexWake { .. }
            | DispatchOutcome::SharedFutexRequeue { .. } => {
                return Err(ContinuationBuildError::NonBlockingOutcome);
            }
        })
    }

    pub fn from_vfork_parent(
        capture: ContinuationCapture,
        child: TaskKey,
        wait: VforkParentWait,
    ) -> Result<Self, ContinuationBuildError> {
        let parent_task = capture.task;
        let persistent_signal_mask = capture.persistent_signal_mask;
        let restore_after_signal = capture.restore_after_signal;
        let kernel = capture
            .kernel
            .upgrade()
            .ok_or(ContinuationBuildError::StaleChildSelector)?;
        if capture.backend != ContinuationBackend::Hvpatch
            || !kernel.task_key_is_live(child)
            || kernel.task_parent_key(child).ok().flatten() != Some(parent_task)
        {
            return Err(ContinuationBuildError::StaleChildSelector);
        }
        let signal_masks = SignalMaskContinuationState {
            persistent: persistent_signal_mask,
            temporary: None,
            restore_after_signal,
        };
        Ok(Self::VforkParent(ContinuationState {
            id: ContinuationId(next_nonzero(&NEXT_CONTINUATION_ID)),
            authority: ContinuationAuthority::from_capture(capture),
            deadline: None,
            outputs: Vec::new(),
            signal_masks,
            detail: ContinuationDetail::Vfork { child, wait },
            resource_generation: next_nonzero(&NEXT_RESOURCE_GENERATION),
            private_futex: None,
            producer_completion: Arc::new(Mutex::new(None)),
            registration: None,
            cleanup: CleanupState::new(),
        }))
    }

    fn state(&self) -> &ContinuationState {
        match self {
            Self::FutexWait(state)
            | Self::FutexWaitv(state)
            | Self::SharedFutexWait(state)
            | Self::SharedFutexWaitv(state)
            | Self::WaitOnSharedWord(state)
            | Self::WaitOnFds(state)
            | Self::WaitOnFdsSelect(state)
            | Self::WaitOnPollFds(state)
            | Self::BlockingHostWrite(state)
            | Self::BlockingRecordLock(state)
            | Self::WaitOnProcExit(state)
            | Self::WaitOnProcState(state)
            | Self::WaitOnHvpatchChild(state)
            | Self::WaitOnSignals(state)
            | Self::WaitOnSleep(state)
            | Self::VforkParent(state) => state,
        }
    }

    fn state_mut(&mut self) -> &mut ContinuationState {
        match self {
            Self::FutexWait(state)
            | Self::FutexWaitv(state)
            | Self::SharedFutexWait(state)
            | Self::SharedFutexWaitv(state)
            | Self::WaitOnSharedWord(state)
            | Self::WaitOnFds(state)
            | Self::WaitOnFdsSelect(state)
            | Self::WaitOnPollFds(state)
            | Self::BlockingHostWrite(state)
            | Self::BlockingRecordLock(state)
            | Self::WaitOnProcExit(state)
            | Self::WaitOnProcState(state)
            | Self::WaitOnHvpatchChild(state)
            | Self::WaitOnSignals(state)
            | Self::WaitOnSleep(state)
            | Self::VforkParent(state) => state,
        }
    }

    pub const fn family(&self) -> ContinuationFamily {
        match self {
            Self::FutexWait(_) => ContinuationFamily::FutexWait,
            Self::FutexWaitv(_) => ContinuationFamily::FutexWaitv,
            Self::SharedFutexWait(_) => ContinuationFamily::SharedFutexWait,
            Self::SharedFutexWaitv(_) => ContinuationFamily::SharedFutexWaitv,
            Self::WaitOnSharedWord(_) => ContinuationFamily::WaitOnSharedWord,
            Self::WaitOnFds(_) => ContinuationFamily::WaitOnFds,
            Self::WaitOnFdsSelect(_) => ContinuationFamily::WaitOnFdsSelect,
            Self::WaitOnPollFds(_) => ContinuationFamily::WaitOnPollFds,
            Self::BlockingHostWrite(_) => ContinuationFamily::BlockingHostWrite,
            Self::BlockingRecordLock(_) => ContinuationFamily::BlockingRecordLock,
            Self::WaitOnProcExit(_) => ContinuationFamily::WaitOnProcExit,
            Self::WaitOnProcState(_) => ContinuationFamily::WaitOnProcState,
            Self::WaitOnHvpatchChild(_) => ContinuationFamily::WaitOnHvpatchChild,
            Self::WaitOnSignals(_) => ContinuationFamily::WaitOnSignals,
            Self::WaitOnSleep(_) => ContinuationFamily::WaitOnSleep,
            Self::VforkParent(_) => ContinuationFamily::VforkParent,
        }
    }

    pub fn id(&self) -> ContinuationId {
        self.state().id
    }

    pub fn authority(&self) -> &ContinuationAuthority {
        &self.state().authority
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.state().deadline
    }

    pub fn guest_outputs(&self) -> &[GuestOutputRange] {
        &self.state().outputs
    }

    pub fn signal_masks(&self) -> SignalMaskContinuationState {
        self.state().signal_masks
    }

    pub fn child_selector(&self) -> Option<ChildSelector> {
        match &self.state().detail {
            ContinuationDetail::Process { selector, .. } => Some(*selector),
            ContinuationDetail::Vfork { child, .. } => Some(ChildSelector::Exact(*child)),
            _ => None,
        }
    }

    pub fn vfork_child(&self) -> Option<TaskKey> {
        match &self.state().detail {
            ContinuationDetail::Vfork { child, .. } => Some(*child),
            _ => None,
        }
    }

    pub(crate) fn bind_product_futex(&mut self, futex: &Arc<FutexTable>) {
        self.state_mut().private_futex = Some(FutexSource(Arc::clone(futex)));
    }

    fn resource_fingerprint(&self) -> u64 {
        let state = self.state();
        let mut fingerprint = state.resource_generation
            ^ state
                .signal_masks
                .temporary
                .map_or(0, |mask| mask.block_mask().raw());
        fingerprint ^= state.signal_masks.persistent.raw()
            ^ state
                .signal_masks
                .restore_after_signal
                .map_or(0, SigSet::raw);
        match &state.detail {
            ContinuationDetail::Futex { wait, index } => {
                fingerprint ^= wait.addr ^ index.unwrap_or(0) as u64;
            }
            ContinuationDetail::SharedFutex {
                location,
                waiter_key,
                value,
                index,
            } => {
                fingerprint ^=
                    location.wait_addr().raw() as u64 ^ *waiter_key as u64 ^ u64::from(*value);
                fingerprint ^= index.unwrap_or(0) as u64;
            }
            ContinuationDetail::SharedWord {
                location,
                waiter_key,
                value,
                sysv,
            } => {
                fingerprint ^=
                    location.wait_addr().raw() as u64 ^ *waiter_key as u64 ^ u64::from(*value);
                fingerprint ^= sysv.as_ref().map_or(0, |state| {
                    state.blocked_id() as u64 ^ state.wait_word_fd() as u64
                });
            }
            ContinuationDetail::Fds {
                registrations,
                on_timeout,
                sig_mask,
            } => {
                fingerprint ^= *on_timeout as u64 ^ sig_mask.block_mask().raw();
                for registration in registrations {
                    fingerprint ^= registration.fd.as_raw_fd() as u64
                        ^ registration.events as u64
                        ^ registration.generation;
                }
            }
            ContinuationDetail::Select {
                registrations,
                sig_mask,
            } => {
                fingerprint ^= sig_mask.block_mask().raw();
                for registration in registrations {
                    fingerprint ^= registration.fd.as_raw_fd() as u64
                        ^ registration.events as u64
                        ^ registration.generation;
                }
            }
            ContinuationDetail::HostWrite(write) => {
                let write = write.lock();
                fingerprint ^= write.host_fd() as u64 ^ write.offset() as u64;
            }
            ContinuationDetail::RecordLock(lock) => {
                fingerprint ^= std::mem::size_of_val(lock) as u64;
            }
            ContinuationDetail::Process { selector, sig_mask } => {
                fingerprint ^= sig_mask.block_mask().raw();
                fingerprint ^= match selector {
                    ChildSelector::Exact(key) => key.serial.raw(),
                    ChildSelector::AnyChildOf(key) => key.serial.raw().rotate_left(7),
                    ChildSelector::HostPid(pid) => *pid as u64,
                };
            }
            ContinuationDetail::Signals {
                wait_set,
                block_mask,
            } => fingerprint ^= wait_set.raw() ^ block_mask.raw(),
            ContinuationDetail::Sleep => {}
            ContinuationDetail::Vfork { child, wait } => {
                fingerprint ^= child.serial.raw()
                    ^ wait.released_reason().map_or(0, |reason| match reason {
                        crate::kernel::VforkReleaseReason::Exec => 1,
                        crate::kernel::VforkReleaseReason::Exit => 2,
                    });
            }
        }
        fingerprint
    }

    pub(crate) fn attach_registration(
        &mut self,
        mut registration: ContinuationRegistration,
    ) -> Result<(), WaitServiceError> {
        let state = self.state();
        if !registration.enrolled
            || registration.token.continuation != state.id
            || registration.token.thread != state.authority.thread()
            || registration.token.thread_serial != state.authority.thread().serial.raw()
            || registration.token.execution != state.authority.execution_generation()
            || registration.token.execution_raw != state.authority.execution_generation().raw()
            || registration.token.mm_generation != state.authority.mm().raw()
            || registration.token.asid_generation != state.authority.asid_generation()
            || registration.token.resource_generation != state.resource_generation
        {
            return Err(WaitServiceError::StaleRegistration);
        }
        self.state_mut().registration = Some(RegistrationBinding {
            token: registration.token,
            service: registration.service.clone(),
        });
        registration.settled = true;
        Ok(())
    }

    pub fn authorize_resume(&self, resume: ResumeContext) -> Result<(), ContinuationResumeError> {
        let authority = self.authority();
        if resume.thread != authority.thread()
            || resume.execution != authority.execution_generation()
            || resume.task != authority.task()
        {
            return Err(ContinuationResumeError::StaleThread);
        }
        if resume.task_revision != authority.task_revision() {
            return Err(ContinuationResumeError::StaleTaskRevision);
        }
        if resume.mm != authority.mm() || resume.asid_generation != authority.asid_generation() {
            return Err(ContinuationResumeError::StaleAddressSpace);
        }
        let kernel = authority
            .kernel
            .upgrade()
            .ok_or(ContinuationResumeError::StaleThread)?;
        if !kernel.task_key_is_live(authority.task())
            || kernel
                .exact_thread_for_scheduler(authority.thread())
                .is_none()
        {
            return Err(ContinuationResumeError::StaleThread);
        }
        let current = kernel
            .context(authority.task().id, authority.thread().tid)
            .map_err(|_| ContinuationResumeError::StaleThread)?;
        if current.task().key() != authority.task()
            || current.thread().key() != authority.thread()
            || current.revision() != authority.task_revision()
        {
            return Err(ContinuationResumeError::StaleTaskRevision);
        }
        Ok(())
    }

    pub fn resume(
        mut self,
        event: ContinuationEvent,
        context: &KernelContext,
    ) -> Result<ContinuationResult, ContinuationResumeError> {
        self.authorize_resume(ResumeContext {
            thread: context.thread().key(),
            task: context.task().key(),
            task_revision: context.revision(),
            execution: self.authority().execution_generation(),
            mm: context.shared().mm().id(),
            asid_generation: self.authority().asid_generation(),
        })?;
        if let Some(binding) = self.state_mut().registration.take()
            && let Some(service) = binding.service.upgrade()
        {
            service.consume_ready_exact(binding.token)?;
        }
        if self.state().signal_masks.temporary.is_some() {
            context
                .signal_authority()
                .set_blocked(self.state().signal_masks.persistent);
        }
        let family = self.family();
        let restart_class = self.authority().restart_class();
        let producer_completion = self.state().producer_completion.lock().take();
        let outcome = match event {
            ContinuationEvent::Ready => match producer_completion {
                Some(DispatchOutcome::Returned { value }) => ContinuationCompletion::Return(value),
                Some(DispatchOutcome::Errno { errno }) => ContinuationCompletion::Errno(errno),
                Some(_) => ContinuationCompletion::Redispatch,
                None => match family {
                    ContinuationFamily::FutexWait => ContinuationCompletion::Return(0),
                    ContinuationFamily::FutexWaitv => {
                        let index = match &self.state().detail {
                            ContinuationDetail::Futex { index, .. }
                            | ContinuationDetail::SharedFutex { index, .. } => index.unwrap_or(0),
                            _ => 0,
                        };
                        ContinuationCompletion::Return(index)
                    }
                    ContinuationFamily::SharedFutexWait => ContinuationCompletion::Return(0),
                    ContinuationFamily::SharedFutexWaitv => {
                        let index = match &self.state().detail {
                            ContinuationDetail::SharedFutex { index, .. } => index.unwrap_or(0),
                            _ => 0,
                        };
                        ContinuationCompletion::Return(index)
                    }
                    ContinuationFamily::BlockingHostWrite => {
                        let offset = match &self.state().detail {
                            ContinuationDetail::HostWrite(write) => write.lock().offset() as i64,
                            _ => 0,
                        };
                        ContinuationCompletion::RedispatchWithPartial(offset)
                    }
                    ContinuationFamily::VforkParent => {
                        let child = self.vfork_child().map_or(0, |key| i64::from(key.id.raw()));
                        ContinuationCompletion::Return(child)
                    }
                    ContinuationFamily::WaitOnSharedWord => match &self.state().detail {
                        ContinuationDetail::SharedWord {
                            sysv: Some(sysv), ..
                        } => sysv.completion_after_wake().map_or(
                            ContinuationCompletion::Redispatch,
                            |outcome| match outcome {
                                DispatchOutcome::Errno { errno } => {
                                    ContinuationCompletion::Errno(errno)
                                }
                                _ => ContinuationCompletion::Redispatch,
                            },
                        ),
                        _ => ContinuationCompletion::Redispatch,
                    },
                    _ => ContinuationCompletion::Redispatch,
                },
            },
            ContinuationEvent::Timeout => match family {
                ContinuationFamily::FutexWait
                | ContinuationFamily::FutexWaitv
                | ContinuationFamily::SharedFutexWait
                | ContinuationFamily::SharedFutexWaitv => {
                    ContinuationCompletion::Errno(LINUX_ETIMEDOUT)
                }
                ContinuationFamily::WaitOnFds | ContinuationFamily::WaitOnPollFds => {
                    let value = match &self.state().detail {
                        ContinuationDetail::Fds { on_timeout, .. } => *on_timeout,
                        _ => 0,
                    };
                    ContinuationCompletion::Return(value)
                }
                ContinuationFamily::WaitOnSignals => ContinuationCompletion::Errno(LINUX_EAGAIN),
                ContinuationFamily::WaitOnFdsSelect | ContinuationFamily::WaitOnSleep => {
                    ContinuationCompletion::ReturnWithGuestWrites(0, self.guest_outputs().to_vec())
                }
                ContinuationFamily::BlockingHostWrite => {
                    let offset = match &self.state().detail {
                        ContinuationDetail::HostWrite(write) => write.lock().offset() as i64,
                        _ => 0,
                    };
                    ContinuationCompletion::Return(offset)
                }
                _ => ContinuationCompletion::Redispatch,
            },
            ContinuationEvent::Signal => {
                let signal_authority = context.signal_authority();
                let deliverable = signal_authority
                    .thread_pending()
                    .union(signal_authority.task_pending())
                    .difference(signal_authority.blocked());
                let action_requests_restart = deliverable
                    .lowest_signum()
                    .and_then(|signum| crate::kernel::LinuxSignal::for_signal_number(signum).ok())
                    .is_some_and(|signal| {
                        signal_authority.action(signal).sa_flags & carrick_abi::LINUX_SA_RESTART
                            != 0
                    });
                let restart = if family != ContinuationFamily::WaitOnSignals
                    && restart_class != RestartClass::Never
                    && action_requests_restart
                {
                    RestartDecision::Restart
                } else {
                    RestartDecision::NoRestart
                };
                let completion = if family == ContinuationFamily::BlockingHostWrite {
                    let offset = match &self.state().detail {
                        ContinuationDetail::HostWrite(write) => write.lock().offset() as i64,
                        _ => 0,
                    };
                    if offset != 0 {
                        ContinuationCompletion::Return(offset)
                    } else {
                        ContinuationCompletion::Errno(LINUX_EINTR)
                    }
                } else if family == ContinuationFamily::WaitOnSleep {
                    ContinuationCompletion::InterruptedSleep {
                        remaining: self.guest_outputs().first().copied().map(|range| {
                            (
                                range,
                                self.deadline().map_or(Duration::ZERO, |deadline| {
                                    deadline.saturating_duration_since(Instant::now())
                                }),
                            )
                        }),
                    }
                } else {
                    ContinuationCompletion::Errno(LINUX_EINTR)
                };
                self.state_mut().cleanup.settle();
                return Ok(ContinuationResult {
                    completion,
                    restart,
                });
            }
        };
        self.state_mut().cleanup.settle();
        Ok(ContinuationResult {
            completion: outcome,
            restart: RestartDecision::NoRestart,
        })
    }

    pub fn cancel(mut self, cause: CancellationCause) -> CancellationReceipt {
        let id = self.id();
        let cleanup_count = self.state_mut().cleanup.settle();
        CancellationReceipt {
            continuation: id,
            cause,
            cleanup_count,
        }
    }

    #[cfg(test)]
    fn install_cleanup_probe(&mut self, probe: Arc<AtomicUsize>) {
        self.state_mut().cleanup.probe = Some(probe);
    }

    #[cfg(test)]
    fn pinned_fds_for_test(&self) -> Vec<i32> {
        match &self.state().detail {
            ContinuationDetail::Fds { registrations, .. }
            | ContinuationDetail::Select { registrations, .. } => registrations
                .iter()
                .map(|registration| registration.fd.as_raw_fd())
                .collect(),
            _ => Vec::new(),
        }
    }
}

pub fn resume_continuation(
    lease: &mut crate::kernel::objects::ThreadExecutionLease,
    event: ContinuationEvent,
    context: &KernelContext,
) -> Result<ContinuationResult, ContinuationResumeError> {
    let continuation = lease
        .blocked_continuation()
        .ok_or(ContinuationResumeError::MissingContinuation)?;
    let original = continuation.authority().execution_generation().raw();
    let resumed = lease.generation().raw();
    let valid_successor = original
        .checked_add(1)
        .is_some_and(|first| resumed == first)
        || original
            .checked_add(2)
            .is_some_and(|second| resumed == second);
    if lease.thread_key() != continuation.authority().thread() || !valid_successor {
        return Err(ContinuationResumeError::StaleThread);
    }
    let (current_mm, current_asid) = lease
        .task_state_authority()
        .map_err(|_| ContinuationResumeError::StaleAddressSpace)?;
    if current_mm != continuation.authority().mm()
        || current_asid != continuation.authority().asid_generation()
    {
        return Err(ContinuationResumeError::StaleAddressSpace);
    }
    let continuation = lease
        .take_blocked_continuation()
        .ok_or(ContinuationResumeError::MissingContinuation)?;
    continuation.resume(event, context)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeContext {
    thread: ThreadKey,
    task: TaskKey,
    task_revision: TaskRevision,
    execution: ExecutionGeneration,
    mm: MmId,
    asid_generation: u64,
}

impl ResumeContext {
    #[cfg(test)]
    fn for_test(
        thread: ThreadKey,
        task: TaskKey,
        task_revision: TaskRevision,
        execution: ExecutionGeneration,
        mm: MmId,
        asid_generation: u64,
    ) -> Self {
        Self {
            thread,
            task,
            task_revision,
            execution,
            mm,
            asid_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationResumeError {
    StaleThread,
    StaleTaskRevision,
    StaleAddressSpace,
    MissingContinuation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartDecision {
    Restart,
    NoRestart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationEvent {
    Ready,
    Timeout,
    Signal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContinuationCompletion {
    Return(i64),
    Errno(LinuxErrno),
    Redispatch,
    RedispatchWithPartial(i64),
    ReturnWithGuestWrites(i64, Vec<GuestOutputRange>),
    ErrnoWithGuestWrites(LinuxErrno, Vec<GuestOutputRange>),
    InterruptedSleep {
        remaining: Option<(GuestOutputRange, Duration)>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationResult {
    pub completion: ContinuationCompletion,
    restart: RestartDecision,
}

impl ContinuationResult {
    pub const fn restart(&self) -> RestartDecision {
        self.restart
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationCause {
    Exec,
    ThreadExit,
    ProcessExit,
    Quiesce,
    ServiceShutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancellationReceipt {
    continuation: ContinuationId,
    cause: CancellationCause,
    cleanup_count: usize,
}

impl CancellationReceipt {
    pub const fn continuation(self) -> ContinuationId {
        self.continuation
    }

    pub const fn cause(self) -> CancellationCause {
        self.cause
    }

    pub const fn cleanup_count(self) -> usize {
        self.cleanup_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuationWakeToken {
    continuation: ContinuationId,
    thread: ThreadKey,
    thread_serial: u64,
    execution: ExecutionGeneration,
    execution_raw: u64,
    mm_generation: u64,
    asid_generation: u64,
    resource_generation: u64,
    registration_generation: u64,
}

impl ContinuationWakeToken {
    pub const fn continuation(self) -> ContinuationId {
        self.continuation
    }

    #[cfg(test)]
    fn with_thread_serial_offset_for_test(mut self, offset: u64) -> Self {
        self.thread_serial += offset;
        self
    }

    #[cfg(test)]
    fn with_execution_generation_offset_for_test(mut self, offset: u64) -> Self {
        self.execution_raw += offset;
        self
    }

    #[cfg(test)]
    fn with_resource_generation_offset_for_test(mut self, offset: u64) -> Self {
        self.resource_generation += offset;
        self
    }

    #[cfg(test)]
    fn with_mm_generation_offset_for_test(mut self, offset: u64) -> Self {
        self.mm_generation += offset;
        self
    }

    #[cfg(test)]
    fn with_asid_generation_offset_for_test(mut self, offset: u64) -> Self {
        self.asid_generation += offset;
        self
    }

    #[cfg(test)]
    fn with_registration_generation_offset_for_test(mut self, offset: u64) -> Self {
        self.registration_generation += offset;
        self
    }
}

#[derive(Debug)]
pub struct ContinuationRegistration {
    token: ContinuationWakeToken,
    service: Weak<CarrierWaitServiceInner>,
    enrolled: bool,
    settled: bool,
}

impl ContinuationRegistration {
    pub const fn wake_token(&self) -> ContinuationWakeToken {
        self.token
    }
}

impl Drop for ContinuationRegistration {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Some(service) = self.service.upgrade() {
            service.cancel_exact(self.token);
        }
        self.settled = true;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationState {
    Prepared,
    Enrolled,
    Ready,
    Cancelled,
    Consumed,
}

#[derive(Debug)]
enum ReadinessProbe {
    Futex {
        table: FutexSource,
        wait: FutexWait,
        deadline: Option<Instant>,
    },
    Fds {
        registrations: Vec<OwnedFdRegistration>,
        deadline: Option<Instant>,
    },
    SharedWord {
        location: SharedFutexLocation,
        value: u32,
        deadline: Option<Instant>,
    },
    HostWrite {
        write: Arc<Mutex<BlockingHostWrite>>,
        completion: Arc<Mutex<Option<DispatchOutcome>>>,
    },
    RecordLock {
        lock: Arc<BlockingRecordLock>,
        completion: Arc<Mutex<Option<DispatchOutcome>>>,
    },
    TaskWake {
        task: Weak<Task>,
        observed: u64,
        deadline: Option<Instant>,
    },
    Vfork {
        wait: VforkParentWait,
    },
    Timer {
        deadline: Instant,
    },
    Passive {
        deadline: Option<Instant>,
    },
}

impl ReadinessProbe {
    fn from_continuation(continuation: &BlockedContinuation) -> Self {
        let state = continuation.state();
        match &state.detail {
            ContinuationDetail::Fds { registrations, .. }
            | ContinuationDetail::Select { registrations, .. } => Self::Fds {
                registrations: registrations.clone(),
                deadline: state.deadline,
            },
            ContinuationDetail::SharedFutex {
                location, value, ..
            }
            | ContinuationDetail::SharedWord {
                location, value, ..
            } => Self::SharedWord {
                location: *location,
                value: *value,
                deadline: state.deadline,
            },
            ContinuationDetail::HostWrite(write) => Self::HostWrite {
                write: Arc::clone(write),
                completion: Arc::clone(&state.producer_completion),
            },
            ContinuationDetail::Process { .. } | ContinuationDetail::Signals { .. } => {
                let task = state.authority.task_ref.clone();
                let observed = state.authority.task_wake_generation;
                Self::TaskWake {
                    task,
                    observed,
                    deadline: state.deadline,
                }
            }
            ContinuationDetail::Vfork { wait, .. } => Self::Vfork { wait: wait.clone() },
            ContinuationDetail::Sleep => state
                .deadline
                .map_or(Self::Passive { deadline: None }, |deadline| Self::Timer {
                    deadline,
                }),
            ContinuationDetail::Futex { wait, .. } => state.private_futex.as_ref().map_or(
                Self::Passive {
                    deadline: state.deadline,
                },
                |table| Self::Futex {
                    table: table.clone(),
                    wait: *wait,
                    deadline: state.deadline,
                },
            ),
            ContinuationDetail::RecordLock(lock) => Self::RecordLock {
                lock: Arc::clone(lock),
                completion: Arc::clone(&state.producer_completion),
            },
        }
    }

    fn poll(&mut self) -> Option<ContinuationEvent> {
        let deadline_event = |deadline: Option<Instant>| {
            deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
                .then_some(ContinuationEvent::Timeout)
        };
        match self {
            Self::Futex {
                table,
                wait,
                deadline,
            } => {
                if let Some(event) = deadline_event(*deadline) {
                    return Some(event);
                }
                (table
                    .0
                    .wait_prepared(*wait, Some(Duration::ZERO), &|| false)
                    == FutexWaitOutcome::Woken)
                    .then_some(ContinuationEvent::Ready)
            }
            Self::Fds {
                registrations,
                deadline,
            } => {
                if let Some(event) = deadline_event(*deadline) {
                    return Some(event);
                }
                if registrations.is_empty() {
                    return None;
                }
                let mut pollfds = registrations
                    .iter()
                    .map(|registration| libc::pollfd {
                        fd: registration.fd.as_raw_fd(),
                        events: registration.events,
                        revents: 0,
                    })
                    .collect::<Vec<_>>();
                let ready =
                    unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 0) };
                (ready > 0).then_some(ContinuationEvent::Ready)
            }
            Self::SharedWord {
                location,
                value,
                deadline,
            } => {
                if let Some(event) = deadline_event(*deadline) {
                    return Some(event);
                }
                // SAFETY: the continuation pins the exact MM generation and
                // owns the wait token; cancellation precedes MM teardown.
                let current = unsafe {
                    (location.wait_addr().raw() as *const std::sync::atomic::AtomicU32)
                        .as_ref()
                        .map(|word| word.load(Ordering::Acquire))
                };
                current
                    .is_none_or(|current| current != *value)
                    .then_some(ContinuationEvent::Ready)
            }
            Self::HostWrite { write, completion } => {
                let mut write = write.lock();
                match crate::dispatch::drive_blocking_host_write(&mut write) {
                    crate::dispatch::BlockingHostWriteStep::Done(outcome) => {
                        *completion.lock() = Some(outcome);
                        Some(ContinuationEvent::Ready)
                    }
                    crate::dispatch::BlockingHostWriteStep::Wait => None,
                }
            }
            Self::RecordLock { lock, completion } => {
                match crate::dispatch::try_drive_blocking_record_lock(lock) {
                    crate::dispatch::BlockingRecordLockStep::Done(outcome) => {
                        *completion.lock() = Some(outcome);
                        Some(ContinuationEvent::Ready)
                    }
                    crate::dispatch::BlockingRecordLockStep::Wait => None,
                }
            }
            Self::TaskWake {
                task,
                observed,
                deadline,
            } => {
                if let Some(event) = deadline_event(*deadline) {
                    return Some(event);
                }
                let current = task
                    .upgrade()
                    .map_or(u64::MAX, |task| task.wake_generation());
                (current != *observed).then_some(ContinuationEvent::Ready)
            }
            Self::Vfork { wait } => wait
                .released_reason()
                .is_some()
                .then_some(ContinuationEvent::Ready),
            Self::Timer { deadline } => {
                (Instant::now() >= *deadline).then_some(ContinuationEvent::Timeout)
            }
            Self::Passive { deadline } => deadline_event(*deadline),
        }
    }
}

#[derive(Debug)]
struct RegistrationEntry {
    token: ContinuationWakeToken,
    state: RegistrationState,
    event: Option<ContinuationEvent>,
    probe: ReadinessProbe,
    interrupt: Option<(Weak<Task>, u64)>,
}

#[derive(Debug, Default)]
struct CarrierWaitState {
    entries: BTreeMap<ContinuationId, RegistrationEntry>,
    #[cfg(test)]
    last_prepared: Option<ContinuationWakeToken>,
}

#[derive(Debug)]
struct CarrierWaitServiceInner {
    scheduler: Arc<Scheduler>,
    state: Mutex<CarrierWaitState>,
    changed: Condvar,
    shutdown: AtomicBool,
    reactor: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl CarrierWaitServiceInner {
    fn cancel_exact(&self, token: ContinuationWakeToken) -> bool {
        let mut state = self.state.lock();
        let Some(entry) = state.entries.get_mut(&token.continuation) else {
            return false;
        };
        if entry.token != token
            || !matches!(
                entry.state,
                RegistrationState::Prepared | RegistrationState::Enrolled
            )
        {
            return false;
        }
        entry.state = RegistrationState::Cancelled;
        state.entries.remove(&token.continuation);
        self.changed.notify_all();
        true
    }

    fn consume_ready_exact(
        &self,
        token: ContinuationWakeToken,
    ) -> Result<(), ContinuationResumeError> {
        let mut state = self.state.lock();
        let entry = state
            .entries
            .get_mut(&token.continuation)
            .filter(|entry| entry.token == token)
            .ok_or(ContinuationResumeError::MissingContinuation)?;
        if entry.state != RegistrationState::Ready {
            return Err(ContinuationResumeError::MissingContinuation);
        }
        entry.state = RegistrationState::Consumed;
        state.entries.remove(&token.continuation);
        self.changed.notify_all();
        Ok(())
    }

    fn finish_exact(&self, token: ContinuationWakeToken) {
        let mut state = self.state.lock();
        if state
            .entries
            .get(&token.continuation)
            .is_some_and(|entry| entry.token == token)
        {
            state.entries.remove(&token.continuation);
            self.changed.notify_all();
        }
    }

    fn publish_event(
        &self,
        token: ContinuationWakeToken,
        event: ContinuationEvent,
    ) -> WakePublishReceipt {
        let won = {
            let mut state = self.state.lock();
            let Some(entry) = state.entries.get_mut(&token.continuation) else {
                return WakePublishReceipt::rejected();
            };
            if entry.token != token
                || !matches!(
                    entry.state,
                    RegistrationState::Prepared | RegistrationState::Enrolled
                )
            {
                return WakePublishReceipt::rejected();
            }
            entry.state = RegistrationState::Ready;
            entry.event = Some(event);
            self.changed.notify_all();
            true
        };
        let _ = self.scheduler.wake(token.thread);
        WakePublishReceipt {
            accepted: won,
            first: won,
        }
    }

    fn run_reactor(weak: Weak<Self>) {
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if inner.shutdown.load(Ordering::Acquire) {
                return;
            }
            let ready = {
                let mut state = inner.state.lock();
                let ready = state
                    .entries
                    .values_mut()
                    .filter(|entry| entry.state == RegistrationState::Enrolled)
                    .filter_map(|entry| {
                        let interrupted =
                            entry.interrupt.as_ref().is_some_and(|(task, observed)| {
                                task.upgrade()
                                    .is_none_or(|task| task.wake_generation() != *observed)
                            });
                        interrupted
                            .then_some(ContinuationEvent::Signal)
                            .or_else(|| entry.probe.poll())
                            .map(|event| (entry.token, event))
                    })
                    .collect::<Vec<_>>();
                if ready.is_empty() && !inner.shutdown.load(Ordering::Acquire) {
                    inner.changed.wait_for(&mut state, Duration::from_millis(2));
                }
                ready
            };
            for (token, event) in ready {
                inner.publish_event(token, event);
            }
        }
    }
}

impl Drop for CarrierWaitServiceInner {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.changed.notify_all();
        if let Some(handle) = self.reactor.get_mut().take()
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

#[derive(Clone, Debug)]
pub struct CarrierWaitService {
    inner: Arc<CarrierWaitServiceInner>,
}

impl CarrierWaitService {
    pub fn new(scheduler: Arc<Scheduler>) -> Self {
        let inner = Arc::new(CarrierWaitServiceInner {
            scheduler,
            state: Mutex::new(CarrierWaitState::default()),
            changed: Condvar::new(),
            shutdown: AtomicBool::new(false),
            reactor: Mutex::new(None),
        });
        let weak = Arc::downgrade(&inner);
        let handle = std::thread::Builder::new()
            .name("carrick-carrier-wait".to_owned())
            .spawn(move || CarrierWaitServiceInner::run_reactor(weak))
            .unwrap_or_else(|_| std::process::abort());
        *inner.reactor.lock() = Some(handle);
        Self { inner }
    }

    pub fn prepare_registration(
        &self,
        continuation: &BlockedContinuation,
    ) -> ContinuationRegistration {
        let authority = continuation.authority();
        let token = ContinuationWakeToken {
            continuation: continuation.id(),
            thread: authority.thread(),
            thread_serial: authority.thread().serial.raw(),
            execution: authority.execution_generation(),
            execution_raw: authority.execution_generation().raw(),
            mm_generation: authority.mm().raw(),
            asid_generation: authority.asid_generation(),
            resource_generation: continuation.state().resource_generation,
            registration_generation: next_nonzero(&NEXT_REGISTRATION_GENERATION),
        };
        let _resource_fingerprint = continuation.resource_fingerprint();
        let probe = ReadinessProbe::from_continuation(continuation);
        let interrupt = (!matches!(
            continuation.family(),
            ContinuationFamily::WaitOnProcExit
                | ContinuationFamily::WaitOnProcState
                | ContinuationFamily::WaitOnHvpatchChild
                | ContinuationFamily::WaitOnSignals
                | ContinuationFamily::VforkParent
        ))
        .then(|| {
            (
                continuation.authority().task_ref.clone(),
                continuation.authority().task_wake_generation,
            )
        });
        let mut state = self.inner.state.lock();
        let replaced = state.entries.insert(
            token.continuation,
            RegistrationEntry {
                token,
                state: RegistrationState::Prepared,
                event: None,
                probe,
                interrupt,
            },
        );
        if replaced.is_some() {
            std::process::abort();
        }
        #[cfg(test)]
        {
            state.last_prepared = Some(token);
        }
        ContinuationRegistration {
            token,
            service: Arc::downgrade(&self.inner),
            enrolled: false,
            settled: false,
        }
    }

    pub fn enroll(
        &self,
        registration: &mut ContinuationRegistration,
    ) -> Result<(), WaitServiceError> {
        if registration.enrolled
            || !Weak::ptr_eq(&registration.service, &Arc::downgrade(&self.inner))
        {
            return Err(WaitServiceError::StaleRegistration);
        }
        let mut state = self.inner.state.lock();
        let entry = state
            .entries
            .get_mut(&registration.token.continuation)
            .filter(|entry| entry.token == registration.token)
            .ok_or(WaitServiceError::StaleRegistration)?;
        if entry.state == RegistrationState::Prepared {
            entry.state = RegistrationState::Enrolled;
        }
        registration.enrolled = true;
        self.inner.changed.notify_all();
        Ok(())
    }

    /// Durable post-enrollment sample. The product path calls this before the
    /// destructive backend save; the shared reactor repeats the same probe
    /// afterward, closing both sides of the registration window.
    pub fn recheck_registration(
        &self,
        registration: &ContinuationRegistration,
    ) -> Result<Option<ContinuationEvent>, WaitServiceError> {
        let event = {
            let mut state = self.inner.state.lock();
            let entry = state
                .entries
                .get_mut(&registration.token.continuation)
                .filter(|entry| entry.token == registration.token)
                .ok_or(WaitServiceError::StaleRegistration)?;
            if !matches!(
                entry.state,
                RegistrationState::Enrolled | RegistrationState::Prepared
            ) {
                return Ok(entry.event);
            }
            let interrupted = entry.interrupt.as_ref().is_some_and(|(task, observed)| {
                task.upgrade()
                    .is_none_or(|task| task.wake_generation() != *observed)
            });
            interrupted
                .then_some(ContinuationEvent::Signal)
                .or_else(|| entry.probe.poll())
        };
        if let Some(event) = event {
            self.inner.publish_event(registration.token, event);
        }
        Ok(event)
    }

    pub fn publish_ready(&self, token: ContinuationWakeToken) -> WakePublishReceipt {
        self.inner.publish_event(token, ContinuationEvent::Ready)
    }

    pub fn wait_for_event(
        &self,
        token: ContinuationWakeToken,
        timeout: Duration,
    ) -> Result<ContinuationEvent, WaitServiceError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.inner.state.lock();
        loop {
            let entry = state
                .entries
                .get(&token.continuation)
                .filter(|entry| entry.token == token)
                .ok_or(WaitServiceError::StaleRegistration)?;
            if entry.state == RegistrationState::Ready {
                return entry.event.ok_or(WaitServiceError::StaleRegistration);
            }
            if matches!(
                entry.state,
                RegistrationState::Cancelled | RegistrationState::Consumed
            ) {
                return Err(WaitServiceError::StaleRegistration);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(WaitServiceError::TimedOut);
            }
            self.inner.changed.wait_for(&mut state, deadline - now);
        }
    }

    pub fn cancel_registration(
        &self,
        mut registration: ContinuationRegistration,
    ) -> Result<(), WaitServiceError> {
        let cancelled = self.inner.cancel_exact(registration.token);
        registration.settled = true;
        if cancelled {
            Ok(())
        } else {
            Err(WaitServiceError::StaleRegistration)
        }
    }

    pub const fn topology(&self) -> WaitServiceTopology {
        WaitServiceTopology {
            service_threads: 1,
            shared_reactors: 1,
        }
    }

    #[cfg(test)]
    fn last_prepared_token(&self) -> ContinuationWakeToken {
        self.inner
            .state
            .lock()
            .last_prepared
            .expect("prepared token")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitServiceTopology {
    service_threads: usize,
    shared_reactors: usize,
}

impl WaitServiceTopology {
    pub const fn service_threads(self) -> usize {
        self.service_threads
    }

    pub const fn shared_reactors(self) -> usize {
        self.shared_reactors
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WaitServiceError {
    #[error("wait-service registration is stale")]
    StaleRegistration,
    #[error("wait-service event did not arrive before the caller deadline")]
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WakePublishReceipt {
    accepted: bool,
    first: bool,
}

impl WakePublishReceipt {
    const fn rejected() -> Self {
        Self {
            accepted: false,
            first: false,
        }
    }

    pub const fn accepted(self) -> bool {
        self.accepted
    }

    pub const fn first_publication(self) -> bool {
        self.first
    }

    #[cfg(test)]
    fn assert_accepted(self) {
        assert!(self.accepted);
    }
}

#[derive(Debug)]
pub enum QuantumBoundary {
    OrdinarySyscall,
    Block(Box<BlockedContinuation>),
    Yield,
    Preempt,
    Quiesce,
    Exit,
    Fail,
}

pub trait TaskQuantumSource {
    fn next_boundary(&mut self) -> QuantumBoundary;
}

#[derive(Debug)]
pub enum QuantumExit {
    Runnable,
    Blocked(Box<BlockedContinuation>),
    Exited,
    Failed,
}

impl QuantumExit {
    pub const fn kind(&self) -> QuantumExitKind {
        match self {
            Self::Runnable => QuantumExitKind::Runnable,
            Self::Blocked(_) => QuantumExitKind::Blocked,
            Self::Exited => QuantumExitKind::Exited,
            Self::Failed => QuantumExitKind::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuantumExitKind {
    Runnable,
    Blocked,
    Exited,
    Failed,
}

pub fn run_task_quantum(source: &mut impl TaskQuantumSource) -> QuantumExit {
    loop {
        match source.next_boundary() {
            QuantumBoundary::OrdinarySyscall => {}
            QuantumBoundary::Block(continuation) => return QuantumExit::Blocked(continuation),
            QuantumBoundary::Yield | QuantumBoundary::Preempt | QuantumBoundary::Quiesce => {
                return QuantumExit::Runnable;
            }
            QuantumBoundary::Exit => return QuantumExit::Exited,
            QuantumBoundary::Fail => return QuantumExit::Failed,
        }
    }
}

/// Task-5-only adapter preserving the current welded runner until Task 6 wires
/// the real HVF executor backend.  It delegates all state decisions to the
/// Kernel/scheduler continuation APIs and owns no parallel task state machine.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransitionalDedicatedRunner;

impl TransitionalDedicatedRunner {
    pub const fn new() -> Self {
        Self
    }

    pub fn drive_quantum(&self, source: &mut impl TaskQuantumSource) -> QuantumExitKind {
        self.run_task_quantum(source).kind()
    }

    pub fn run_task_quantum(&self, source: &mut impl TaskQuantumSource) -> QuantumExit {
        run_task_quantum(source)
    }

    pub const fn is_task_5_only(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::RawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    use carrick_abi::{LinuxCloneFlags, SigBlockMask, SigSet, WaitSigMask};
    use carrick_guest_mem::{GuestVa, HostVa, SharedFutexLocation};
    use carrick_hal::ThreadId;
    use carrick_hal::threaded::{Aarch64TaskCpuStateV1, GuestCpuState};

    use super::*;
    use crate::compat::SyscallArgs;
    use crate::dispatch::{
        BlockingHostWrite, BlockingRecordLock, DispatchOutcome, SyscallRequest, WaitFds,
    };
    use crate::kernel::objects::{ExecutionGeneration, MigratableTaskState, ThreadExecutionState};
    use crate::kernel::{ClonePlan, Kernel, KernelContext, RootBootstrap, Scheduler};
    use crate::thread::FutexTable;

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "continuation test".to_owned(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    fn task_state(context: &KernelContext, marker: u64) -> MigratableTaskState {
        task_state_with_asid(context, marker, context.shared().mm().id().raw())
    }

    fn task_state_with_asid(
        context: &KernelContext,
        marker: u64,
        asid_generation: u64,
    ) -> MigratableTaskState {
        let mm = context.shared().mm().id();
        MigratableTaskState {
            cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
                gprs: std::array::from_fn(|index| marker + index as u64),
                pc: marker + 0x1000,
                pstate: marker + 0x2000,
                trap_pc: marker + 0x2100,
                trap_pstate: marker + 0x2200,
                sp_el0: marker + 0x3000,
                elr_el1: marker + 0x3100,
                spsr_el1: marker + 0x3200,
                ttbr0: marker + 0x4000,
                ttbr1: marker + 0x5000,
                tcr: marker + 0x6000,
                actlr_el1: marker + 0x7000,
                tpidr_el0: marker + 0x8000,
                tpidrro_el0: marker + 0x9000,
                contextidr_el1: marker + 0xa000,
                vregs: std::array::from_fn(|index| marker as u128 + index as u128),
                fpsr: marker as u32,
                fpcr: marker as u32 + 1,
                pending_resume_pc: Some(marker + 0xb000),
                last_syscall_nr: Some(marker),
                last_syscall_orig_x0: marker + 2,
                last_fault_esr: marker + 3,
                last_exit_class: marker,
                is_forked_child: false,
                syscall_continuation: None,
                mm_generation: mm.raw(),
                asid_generation,
            }),
            mm,
            asid_generation,
        }
    }

    fn publish(context: &KernelContext, marker: u64) -> ExecutionGeneration {
        context
            .thread()
            .publish_initial_task_state(task_state(context, marker))
            .expect("publish task state")
    }

    fn request(number: u64) -> SyscallRequest {
        SyscallRequest::new(
            number,
            SyscallArgs([0x1100, 0x2200, 0x3300, 0x4400, 0x5500, 0x6600]),
        )
    }

    fn capture(
        context: &KernelContext,
        generation: ExecutionGeneration,
        backend: ContinuationBackend,
    ) -> ContinuationCapture {
        ContinuationCapture::new(
            context,
            generation,
            request(73),
            RestartClass::RestartSyscall,
            backend,
        )
        .expect("capture exact continuation authority")
    }

    fn pipe_pair() -> [RawFd; 2] {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        fds
    }

    fn close_pair(fds: [RawFd; 2]) {
        for fd in fds {
            unsafe { libc::close(fd) };
        }
    }

    fn outcome_for(family: ContinuationFamily, tid: ThreadId) -> DispatchOutcome {
        match family {
            ContinuationFamily::FutexWait => DispatchOutcome::FutexWait {
                wait: FutexTable::new().prepare_wait(0x1000),
                timeout: Some(Duration::from_secs(2)),
            },
            ContinuationFamily::FutexWaitv => DispatchOutcome::FutexWaitv {
                wait: FutexTable::new().prepare_wait(0x2000),
                timeout: Some(Duration::from_secs(3)),
                index: 4,
            },
            ContinuationFamily::SharedFutexWait => DispatchOutcome::SharedFutexWait {
                location: SharedFutexLocation::Direct {
                    word: HostVa(0x3000),
                    waiter_key: 31,
                },
                waiter_key: 31,
                value: 7,
                timeout: Some(Duration::from_secs(4)),
            },
            ContinuationFamily::SharedFutexWaitv => DispatchOutcome::SharedFutexWaitv {
                location: SharedFutexLocation::Direct {
                    word: HostVa(0x4000),
                    waiter_key: 41,
                },
                waiter_key: 41,
                value: 8,
                timeout: Some(Duration::from_secs(5)),
                index: 9,
            },
            ContinuationFamily::WaitOnSharedWord => DispatchOutcome::WaitOnSharedWord {
                location: SharedFutexLocation::Direct {
                    word: HostVa(0x5000),
                    waiter_key: 51,
                },
                waiter_key: 51,
                value: 10,
                sysv: None,
            },
            ContinuationFamily::WaitOnFds => DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: Some(Duration::from_secs(6)),
                on_timeout: -11,
                sig_mask: WaitSigMask::NONE,
            },
            ContinuationFamily::WaitOnFdsSelect => DispatchOutcome::WaitOnFdsSelect {
                fds: WaitFds::empty(),
                timeout: Some(Duration::from_secs(7)),
                sig_mask: WaitSigMask::NONE,
                clear_on_timeout: vec![(0x7000, 16), (0x7100, 8)],
            },
            ContinuationFamily::WaitOnPollFds => DispatchOutcome::WaitOnPollFds {
                fds: WaitFds::empty(),
                timeout: Some(Duration::from_secs(8)),
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            ContinuationFamily::BlockingHostWrite => {
                let fds = pipe_pair();
                let write = BlockingHostWrite::for_tests(fds[1], vec![1, 2, 3, 4], 2, tid, true)
                    .expect("pinned partial write");
                close_pair(fds);
                DispatchOutcome::BlockingHostWrite(write)
            }
            ContinuationFamily::BlockingRecordLock => {
                let fds = pipe_pair();
                let lock = BlockingRecordLock::new(fds[0], libc::F_SETLKW, 0, 1, 1, 0)
                    .expect("pinned record lock");
                close_pair(fds);
                DispatchOutcome::BlockingRecordLock(lock)
            }
            ContinuationFamily::WaitOnProcExit => DispatchOutcome::WaitOnProcExit {
                pid: 9001,
                sig_mask: WaitSigMask::NONE,
            },
            ContinuationFamily::WaitOnProcState => DispatchOutcome::WaitOnProcState {
                pid: 9002,
                sig_mask: WaitSigMask::NONE,
            },
            ContinuationFamily::WaitOnHvpatchChild => DispatchOutcome::WaitOnHvpatchChild {
                target: None,
                sig_mask: WaitSigMask::NONE,
            },
            ContinuationFamily::WaitOnSignals => DispatchOutcome::WaitOnSignals {
                wait_set: SigSet::from_raw(0x55),
                block_mask: SigBlockMask::blocking_all_of(SigSet::from_raw(0xaa)),
                timeout: Some(Duration::from_secs(9)),
            },
            ContinuationFamily::WaitOnSleep => DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(10),
                remaining: Some(crate::dispatch::GuestPtr(0x9000)),
            },
            ContinuationFamily::VforkParent => {
                panic!("vfork continuation is constructed from the published Kernel relationship")
            }
        }
    }

    const DISPATCH_FAMILIES: [ContinuationFamily; 15] = [
        ContinuationFamily::FutexWait,
        ContinuationFamily::FutexWaitv,
        ContinuationFamily::SharedFutexWait,
        ContinuationFamily::SharedFutexWaitv,
        ContinuationFamily::WaitOnSharedWord,
        ContinuationFamily::WaitOnFds,
        ContinuationFamily::WaitOnFdsSelect,
        ContinuationFamily::WaitOnPollFds,
        ContinuationFamily::BlockingHostWrite,
        ContinuationFamily::BlockingRecordLock,
        ContinuationFamily::WaitOnProcExit,
        ContinuationFamily::WaitOnProcState,
        ContinuationFamily::WaitOnHvpatchChild,
        ContinuationFamily::WaitOnSignals,
        ContinuationFamily::WaitOnSleep,
    ];

    fn assert_send_static<T: Send + 'static>(_: &T) {}

    #[test]
    fn exhaustive_real_dispatch_shapes_become_owned_send_static_continuations() {
        let (kernel, context) = bootstrap(15_000);
        let generation = publish(&context, 0x100);
        let now = Instant::now();
        for family in DISPATCH_FAMILIES {
            let backend = if matches!(
                family,
                ContinuationFamily::WaitOnProcExit | ContinuationFamily::WaitOnProcState
            ) {
                ContinuationBackend::HostProcessCompatibility
            } else {
                ContinuationBackend::Hvpatch
            };
            let continuation = BlockedContinuation::from_dispatch_outcome(
                outcome_for(family, context.thread().registry_id()),
                capture(&context, generation, backend),
            )
            .expect("blocking outcome must convert");
            assert_eq!(continuation.family(), family);
            assert_send_static(&continuation);
            let authority = continuation.authority();
            assert_eq!(authority.thread(), context.thread().key());
            assert_eq!(authority.execution_generation(), generation);
            assert_eq!(authority.mm(), context.shared().mm().id());
            assert_eq!(
                authority.asid_generation(),
                context.shared().mm().id().raw()
            );
            assert_eq!(authority.syscall().request(), request(73));
            assert_eq!(authority.restart_class(), RestartClass::RestartSyscall);
            let masks = continuation.signal_masks();
            assert_eq!(masks.persistent(), SigSet::EMPTY);
            assert_eq!(masks.restore_after_signal(), None);
            assert_eq!(
                masks.temporary().is_some(),
                matches!(
                    family,
                    ContinuationFamily::WaitOnFds
                        | ContinuationFamily::WaitOnFdsSelect
                        | ContinuationFamily::WaitOnPollFds
                        | ContinuationFamily::BlockingHostWrite
                        | ContinuationFamily::BlockingRecordLock
                        | ContinuationFamily::WaitOnProcExit
                        | ContinuationFamily::WaitOnProcState
                        | ContinuationFamily::WaitOnHvpatchChild
                )
            );
            if let Some(deadline) = continuation.deadline() {
                assert!(deadline >= now, "deadline must be absolute monotonic time");
            }
            for range in continuation.guest_outputs() {
                assert_eq!(range.mm(), context.shared().mm().id());
                assert_eq!(range.asid_generation(), context.shared().mm().id().raw());
                assert!(range.len() != 0);
            }
        }
        drop(kernel);
    }

    #[test]
    fn vfork_parent_owns_exact_parent_child_relationship_and_release_token() {
        let (kernel, context) = bootstrap(15_010);
        let generation = publish(&context, 0x200);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM)
            .expect("vfork plan");
        let published = kernel
            .reserve_fork(&context, plan, "continuation vfork".to_owned(), None)
            .expect("reserve vfork")
            .prepare_reference(ThreadId::synthetic_for_tests(15_011))
            .expect("prepare vfork")
            .commit()
            .expect("publish vfork");
        let (child, wait) = published.into_parts().expect("start child");
        let wait = wait.expect("vfork parent wait");
        let current = context
            .task_binding()
            .capture(context.thread().key().tid)
            .expect("recapture parent after vfork publication");
        let continuation = BlockedContinuation::from_vfork_parent(
            capture(&current, generation, ContinuationBackend::Hvpatch),
            child.task().key(),
            wait.clone(),
        )
        .expect("owned vfork wait");
        assert_eq!(continuation.family(), ContinuationFamily::VforkParent);
        assert_eq!(continuation.vfork_child(), Some(child.task().key()));
        assert_send_static(&continuation);

        let probe = Arc::new(AtomicUsize::new(0));
        let make = || {
            let mut continuation = BlockedContinuation::from_vfork_parent(
                capture(&current, generation, ContinuationBackend::Hvpatch),
                child.task().key(),
                wait.clone(),
            )
            .expect("repeat owned vfork wait");
            continuation.install_cleanup_probe(Arc::clone(&probe));
            continuation
        };
        let ready = make()
            .resume(ContinuationEvent::Ready, &current)
            .expect("vfork release result");
        assert_eq!(
            ready.completion,
            ContinuationCompletion::Return(i64::from(child.task().key().id.raw()))
        );
        for cause in [
            CancellationCause::Exec,
            CancellationCause::ThreadExit,
            CancellationCause::ProcessExit,
            CancellationCause::Quiesce,
        ] {
            assert_eq!(make().cancel(cause).cleanup_count(), 1);
        }
        drop(make());
        assert_eq!(probe.load(Ordering::SeqCst), 6);
    }

    #[test]
    fn hvpatch_rejects_host_proc_wait_and_resolves_child_selectors_in_kernel_domain() {
        let (_kernel, context) = bootstrap(15_020);
        let generation = publish(&context, 0x300);
        let error = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnProcExit {
                pid: 22,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect_err("HvPatch may never infer a child from a Darwin pid");
        assert_eq!(error, ContinuationBuildError::HostProcessWaitOnHvpatch);

        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnHvpatchChild {
                target: None,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("kernel child selector");
        assert_eq!(
            continuation.child_selector(),
            Some(ChildSelector::AnyChildOf(context.task().key()))
        );
    }

    struct RaceFixture {
        scheduler: Arc<Scheduler>,
        service: Arc<CarrierWaitService>,
        context: KernelContext,
        executor: crate::kernel::ExecutorRegistration,
        running: crate::kernel::RunnableThread,
        continuation: BlockedContinuation,
        registration: ContinuationRegistration,
    }

    fn race_fixture(pid: i32) -> RaceFixture {
        let (kernel, context) = bootstrap(pid);
        let generation = publish(&context, pid as u64);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(30),
                remaining: Some(crate::dispatch::GuestPtr(0xa000)),
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("continuation");
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let executor = scheduler
            .register_executor(Arc::new(TestKick::default()))
            .expect("executor");
        scheduler
            .make_runnable(context.thread().key())
            .expect("queue root");
        let running = scheduler.take(&executor).expect("claim root");
        let service = Arc::new(CarrierWaitService::new(Arc::clone(&scheduler)));
        let registration = service.prepare_registration(&continuation);
        RaceFixture {
            scheduler,
            service,
            context,
            executor,
            running,
            continuation,
            registration,
        }
    }

    #[derive(Debug, Default)]
    struct TestKick {
        binding: parking_lot::Mutex<Option<crate::kernel::ExecutorBinding>>,
        kicks: AtomicUsize,
    }

    impl crate::kernel::ExecutorKick for TestKick {
        fn try_bind(&self, binding: crate::kernel::ExecutorBinding) -> bool {
            let mut current = self.binding.lock();
            if current.is_some() {
                return false;
            }
            *current = Some(binding);
            true
        }

        fn unbind(&self, binding: crate::kernel::ExecutorBinding) {
            let mut current = self.binding.lock();
            if *current == Some(binding) {
                *current = None;
            }
        }

        fn deliver_exact(&self, token: crate::kernel::ExecutorKickToken) -> bool {
            let current = self.binding.lock();
            if current.as_ref().is_none_or(|binding| {
                binding.executor() != token.executor()
                    || binding.executor_epoch() != token.executor_epoch()
                    || binding.thread() != token.thread()
                    || binding.generation() != token.generation()
            }) {
                return false;
            }
            self.kicks.fetch_add(1, Ordering::SeqCst);
            true
        }

        fn current_binding(&self) -> Option<crate::kernel::ExecutorBinding> {
            *self.binding.lock()
        }
    }

    fn publish_with_real_barrier(
        service: Arc<CarrierWaitService>,
        token: ContinuationWakeToken,
    ) -> thread::JoinHandle<WakePublishReceipt> {
        let barrier = Arc::new(Barrier::new(2));
        let child_barrier = Arc::clone(&barrier);
        let join = thread::spawn(move || {
            child_barrier.wait();
            service.publish_ready(token)
        });
        barrier.wait();
        join
    }

    #[test]
    fn event_before_enrollment_is_durable_and_settles_runnable_once() {
        let mut fixture = race_fixture(15_100);
        let receipt = publish_with_real_barrier(
            Arc::clone(&fixture.service),
            fixture.registration.wake_token(),
        )
        .join()
        .expect("publisher");
        assert!(receipt.first_publication());
        fixture
            .scheduler
            .begin_switch_out(&fixture.running)
            .expect("switch out");
        fixture
            .service
            .enroll(&mut fixture.registration)
            .expect("enroll after event");
        fixture
            .scheduler
            .settle_blocked_continuation(
                fixture.running,
                fixture.continuation,
                fixture.registration,
            )
            .expect("settle");
        assert!(matches!(
            fixture.context.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(fixture.scheduler.queued_len(), 1);
    }

    #[test]
    fn event_during_switching_out_save_is_durable_and_queues_once() {
        let mut fixture = race_fixture(15_110);
        fixture
            .scheduler
            .begin_switch_out(&fixture.running)
            .expect("switch out");
        fixture
            .service
            .enroll(&mut fixture.registration)
            .expect("enroll");
        let join = publish_with_real_barrier(
            Arc::clone(&fixture.service),
            fixture.registration.wake_token(),
        );
        join.join().expect("publisher");
        fixture
            .scheduler
            .settle_blocked_continuation(
                fixture.running,
                fixture.continuation,
                fixture.registration,
            )
            .expect("settle");
        assert!(matches!(
            fixture.context.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(fixture.scheduler.queued_len(), 1);
    }

    #[test]
    fn event_after_binding_clear_before_settlement_commit_queues_once() {
        let mut fixture = race_fixture(15_120);
        fixture
            .scheduler
            .begin_switch_out(&fixture.running)
            .expect("switch out");
        fixture
            .service
            .enroll(&mut fixture.registration)
            .expect("enroll");
        let at_clear = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        fixture
            .scheduler
            .install_continuation_settlement_barriers(Arc::clone(&at_clear), Arc::clone(&release));
        let scheduler = Arc::clone(&fixture.scheduler);
        let running = fixture.running;
        let continuation = fixture.continuation;
        let registration = fixture.registration;
        let settle = thread::spawn(move || {
            scheduler.settle_blocked_continuation(running, continuation, registration)
        });
        at_clear.wait();
        fixture
            .service
            .publish_ready(fixture.service.last_prepared_token())
            .assert_accepted();
        release.wait();
        settle.join().expect("settler").expect("settled");
        assert!(matches!(
            fixture.context.thread().execution_state(),
            ThreadExecutionState::Runnable { .. }
        ));
        assert_eq!(fixture.scheduler.queued_len(), 1);
    }

    #[test]
    fn event_after_destination_load_before_resume_kicks_exact_generation_once() {
        let mut fixture = race_fixture(15_130);
        fixture
            .scheduler
            .begin_switch_out(&fixture.running)
            .expect("switch out");
        fixture
            .service
            .enroll(&mut fixture.registration)
            .expect("enroll");
        let token = fixture.registration.wake_token();
        fixture
            .scheduler
            .settle_blocked_continuation(
                fixture.running,
                fixture.continuation,
                fixture.registration,
            )
            .expect("block");
        fixture.service.publish_ready(token).assert_accepted();
        let mut destination = fixture
            .scheduler
            .take(&fixture.executor)
            .expect("destination load");
        assert!(matches!(
            fixture.context.thread().execution_state(),
            ThreadExecutionState::Running {
                wake_pending: false,
                ..
            }
        ));
        let join = publish_with_real_barrier(Arc::clone(&fixture.service), token);
        let duplicate = join.join().expect("publisher");
        assert!(
            !duplicate.accepted(),
            "a consumed Ready registration must reject a stale duplicate without waking the successor"
        );
        assert!(matches!(
            fixture.context.thread().execution_state(),
            ThreadExecutionState::Running {
                wake_pending: false,
                ..
            }
        ));
        let continuation = destination
            .lease()
            .blocked_continuation()
            .expect("Kernel-owned continuation migrates in exact lease");
        assert_eq!(continuation.id(), token.continuation());
        let resumed = resume_continuation(
            destination.lease_mut(),
            ContinuationEvent::Timeout,
            &fixture.context,
        )
        .expect("consume exact continuation once");
        assert!(matches!(
            resumed.completion,
            ContinuationCompletion::ReturnWithGuestWrites(0, _)
        ));
        assert_eq!(
            resume_continuation(
                destination.lease_mut(),
                ContinuationEvent::Timeout,
                &fixture.context,
            ),
            Err(ContinuationResumeError::MissingContinuation)
        );
        fixture.scheduler.settle_exited(destination).expect("exit");
        assert_eq!(fixture.scheduler.queued_len(), 0);
    }

    #[test]
    fn timeout_signal_exec_exit_and_drop_cleanup_are_literal_for_every_family() {
        let (_kernel, context) = bootstrap(15_200);
        let generation = publish(&context, 0x400);
        for family in DISPATCH_FAMILIES {
            let backend = if matches!(
                family,
                ContinuationFamily::WaitOnProcExit | ContinuationFamily::WaitOnProcState
            ) {
                ContinuationBackend::HostProcessCompatibility
            } else {
                ContinuationBackend::Hvpatch
            };
            let probe = Arc::new(AtomicUsize::new(0));
            let make = || {
                let mut continuation = BlockedContinuation::from_dispatch_outcome(
                    outcome_for(family, context.thread().registry_id()),
                    capture(&context, generation, backend),
                )
                .expect("continuation");
                continuation.install_cleanup_probe(Arc::clone(&probe));
                continuation
            };

            let timeout = make()
                .resume(ContinuationEvent::Timeout, &context)
                .expect("timeout result");
            match (family, timeout.completion) {
                (
                    ContinuationFamily::FutexWait
                    | ContinuationFamily::FutexWaitv
                    | ContinuationFamily::SharedFutexWait
                    | ContinuationFamily::SharedFutexWaitv,
                    ContinuationCompletion::Errno(errno),
                ) => assert_eq!(errno, LINUX_ETIMEDOUT),
                (ContinuationFamily::WaitOnFds, ContinuationCompletion::Return(-11))
                | (ContinuationFamily::WaitOnPollFds, ContinuationCompletion::Return(0))
                | (ContinuationFamily::BlockingHostWrite, ContinuationCompletion::Return(2))
                | (
                    ContinuationFamily::WaitOnSharedWord
                    | ContinuationFamily::BlockingRecordLock
                    | ContinuationFamily::WaitOnProcExit
                    | ContinuationFamily::WaitOnProcState
                    | ContinuationFamily::WaitOnHvpatchChild,
                    ContinuationCompletion::Redispatch,
                ) => {}
                (ContinuationFamily::WaitOnSignals, ContinuationCompletion::Errno(errno)) => {
                    assert_eq!(errno, LINUX_EAGAIN)
                }
                (
                    ContinuationFamily::WaitOnFdsSelect,
                    ContinuationCompletion::ReturnWithGuestWrites(0, writes),
                ) => assert_eq!(writes.len(), 2),
                (
                    ContinuationFamily::WaitOnSleep,
                    ContinuationCompletion::ReturnWithGuestWrites(0, writes),
                ) => assert_eq!(writes.len(), 1),
                other => panic!("unexpected timeout result: {other:?}"),
            }
            let interrupted = make()
                .resume(ContinuationEvent::Signal, &context)
                .expect("signal result");
            match (&family, &interrupted.completion) {
                (ContinuationFamily::BlockingHostWrite, ContinuationCompletion::Return(2)) => {}
                (
                    ContinuationFamily::WaitOnSleep,
                    ContinuationCompletion::InterruptedSleep { remaining },
                ) => {
                    assert!(remaining.is_some());
                }
                (_, ContinuationCompletion::Errno(errno)) => assert_eq!(*errno, LINUX_EINTR),
                other => panic!("unexpected signal result: {other:?}"),
            }
            if matches!(family, ContinuationFamily::WaitOnSignals) {
                assert_eq!(interrupted.restart(), RestartDecision::NoRestart);
            }
            for cause in [
                CancellationCause::Exec,
                CancellationCause::ThreadExit,
                CancellationCause::ProcessExit,
            ] {
                let receipt = make().cancel(cause);
                assert_eq!(receipt.cause(), cause);
                assert_eq!(receipt.cleanup_count(), 1);
            }
            drop(make());
            assert_eq!(
                probe.load(Ordering::SeqCst),
                6,
                "{family:?} cleans once per terminal path"
            );
        }
    }

    #[test]
    fn select_and_sleep_guest_writes_revalidate_exact_mm_before_any_access() {
        let (_kernel, context) = bootstrap(15_210);
        let generation = publish(&context, 0x500);
        for (family, expected) in [
            (
                ContinuationFamily::WaitOnFdsSelect,
                vec![
                    GuestOutputRange::new(
                        GuestVa(0x7000),
                        16,
                        context.shared().mm().id(),
                        context.shared().mm().id().raw(),
                    )
                    .unwrap(),
                    GuestOutputRange::new(
                        GuestVa(0x7100),
                        8,
                        context.shared().mm().id(),
                        context.shared().mm().id().raw(),
                    )
                    .unwrap(),
                ],
            ),
            (
                ContinuationFamily::WaitOnSleep,
                vec![
                    GuestOutputRange::new(
                        GuestVa(0x9000),
                        std::mem::size_of::<libc::timespec>(),
                        context.shared().mm().id(),
                        context.shared().mm().id().raw(),
                    )
                    .unwrap(),
                ],
            ),
        ] {
            let continuation = BlockedContinuation::from_dispatch_outcome(
                outcome_for(family, context.thread().registry_id()),
                capture(&context, generation, ContinuationBackend::Hvpatch),
            )
            .unwrap();
            assert_eq!(continuation.guest_outputs(), expected);
            let wrong = ResumeContext::for_test(
                context.thread().key(),
                context.task().key(),
                context.revision(),
                generation,
                context.shared().mm().id(),
                context.shared().mm().id().raw() + 1,
            );
            assert_eq!(
                continuation.authorize_resume(wrong),
                Err(ContinuationResumeError::StaleAddressSpace)
            );
        }
    }

    #[test]
    fn stale_task_mm_fd_and_registration_generations_never_wake_successors() {
        let fixture = race_fixture(15_220);
        let token = fixture.registration.wake_token();
        assert!(
            !fixture
                .service
                .publish_ready(token.with_thread_serial_offset_for_test(1))
                .accepted()
        );
        assert!(
            !fixture
                .service
                .publish_ready(token.with_execution_generation_offset_for_test(1))
                .accepted()
        );
        assert!(
            !fixture
                .service
                .publish_ready(token.with_resource_generation_offset_for_test(1))
                .accepted()
        );
        assert!(
            !fixture
                .service
                .publish_ready(token.with_mm_generation_offset_for_test(1))
                .accepted()
        );
        assert!(
            !fixture
                .service
                .publish_ready(token.with_asid_generation_offset_for_test(1))
                .accepted()
        );
        assert!(
            !fixture
                .service
                .publish_ready(token.with_registration_generation_offset_for_test(1))
                .accepted()
        );
        assert_eq!(fixture.scheduler.queued_len(), 0);
        assert!(matches!(
            fixture.context.thread().execution_state(),
            ThreadExecutionState::Running {
                wake_pending: false,
                ..
            }
        ));
    }

    #[test]
    fn fd_wait_pins_exact_open_description_until_cleanup_and_rejects_reuse() {
        let (_kernel, context) = bootstrap(15_225);
        let generation = publish(&context, 0x551);
        let fds = pipe_pair();
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::raw(vec![(fds[0], libc::POLLIN)]),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("pin exact open description");
        let pinned = continuation.pinned_fds_for_test();
        assert_eq!(pinned.len(), 1);
        close_pair(fds);
        assert_ne!(unsafe { libc::fcntl(pinned[0], libc::F_GETFD) }, -1);
        drop(continuation);
        assert_eq!(unsafe { libc::fcntl(pinned[0], libc::F_GETFD) }, -1);
    }

    #[test]
    fn shared_wait_service_is_bounded_and_blocked_tasks_own_no_executor() {
        let mut fixture = race_fixture(15_230);
        let topology = fixture.service.topology();
        assert_eq!(topology.service_threads(), 1);
        assert_eq!(topology.shared_reactors(), 1);
        for _ in 0..256 {
            let continuation = BlockedContinuation::from_dispatch_outcome(
                DispatchOutcome::WaitOnSleep {
                    duration: Duration::from_secs(30),
                    remaining: None,
                },
                ContinuationCapture::from_lease(
                    &fixture.context,
                    fixture.running.lease(),
                    request(73),
                    RestartClass::RestartSyscall,
                    ContinuationBackend::Hvpatch,
                )
                .expect("running lease capture"),
            )
            .unwrap();
            let mut registration = fixture.service.prepare_registration(&continuation);
            fixture.service.enroll(&mut registration).unwrap();
            fixture.service.cancel_registration(registration).unwrap();
            drop(continuation);
        }
        assert_eq!(fixture.service.topology(), topology);
        fixture
            .scheduler
            .begin_switch_out(&fixture.running)
            .expect("switch out");
        fixture
            .service
            .enroll(&mut fixture.registration)
            .expect("enroll");
        fixture
            .scheduler
            .settle_blocked_continuation(
                fixture.running,
                fixture.continuation,
                fixture.registration,
            )
            .expect("block");
        assert!(matches!(
            fixture.context.thread().execution_state(),
            ThreadExecutionState::Blocked { .. }
        ));
        assert!(
            fixture
                .scheduler
                .binding_for_thread(fixture.context.thread().key())
                .is_none()
        );
    }

    #[test]
    fn shared_reactor_observes_real_fd_and_timer_readiness_without_private_waiters() {
        let (kernel, context) = bootstrap(15_231);
        let generation = publish(&context, 0x552);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let service = CarrierWaitService::new(Arc::clone(&scheduler));
        let fds = pipe_pair();
        let fd_continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::raw(vec![(fds[0], libc::POLLIN)]),
                timeout: Some(Duration::from_secs(1)),
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("fd continuation");
        let mut fd_registration = service.prepare_registration(&fd_continuation);
        service.enroll(&mut fd_registration).expect("enroll fd");
        let fd_token = fd_registration.wake_token();
        assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);
        assert_eq!(
            service
                .wait_for_event(fd_token, Duration::from_secs(1))
                .expect("fd event"),
            ContinuationEvent::Ready
        );
        assert!(service.cancel_registration(fd_registration).is_err());
        drop(fd_continuation);
        close_pair(fds);

        let timer = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_millis(5),
                remaining: None,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("timer continuation");
        let mut timer_registration = service.prepare_registration(&timer);
        service
            .enroll(&mut timer_registration)
            .expect("enroll timer");
        assert_eq!(
            service
                .wait_for_event(timer_registration.wake_token(), Duration::from_secs(1),)
                .expect("timer event"),
            ContinuationEvent::Timeout
        );
        assert_eq!(service.topology().service_threads(), 1);
        assert_eq!(service.topology().shared_reactors(), 1);
    }

    #[test]
    fn shared_reactor_rechecks_private_futex_and_shared_word_producer_state() {
        let (kernel, context) = bootstrap(15_232);
        let generation = publish(&context, 0x553);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let service = CarrierWaitService::new(scheduler);

        let futex = Arc::new(FutexTable::new());
        let wait = futex.prepare_wait(0xfeed);
        futex.wake(0xfeed, 1);
        let mut private = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::FutexWait {
                wait,
                timeout: Some(Duration::from_secs(1)),
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("private futex continuation");
        private.bind_product_futex(&futex);
        let mut registration = service.prepare_registration(&private);
        service.enroll(&mut registration).expect("enroll futex");
        assert_eq!(
            service
                .wait_for_event(registration.wake_token(), Duration::from_secs(1))
                .expect("event-before-registration generation recheck"),
            ContinuationEvent::Ready
        );
        drop(private);

        let word = std::sync::atomic::AtomicU32::new(7);
        let location = SharedFutexLocation::Direct {
            word: HostVa((&word as *const std::sync::atomic::AtomicU32) as usize),
            waiter_key: 0xbeef,
        };
        let shared = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSharedWord {
                location,
                waiter_key: 0xbeef,
                value: 7,
                sysv: None,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("shared-word continuation");
        let mut registration = service.prepare_registration(&shared);
        service
            .enroll(&mut registration)
            .expect("enroll shared word");
        word.store(8, Ordering::Release);
        assert_eq!(
            service
                .wait_for_event(registration.wake_token(), Duration::from_secs(1))
                .expect("shared word durable recheck"),
            ContinuationEvent::Ready
        );
    }

    #[test]
    fn shared_reactor_drives_write_record_signal_and_vfork_sources() {
        let (kernel, context) = bootstrap(15_233);
        let generation = publish(&context, 0x554);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let service = CarrierWaitService::new(scheduler);

        let pipe = pipe_pair();
        let write = BlockingHostWrite::for_tests(
            pipe[1],
            vec![1, 2, 3, 4],
            2,
            context.thread().registry_id(),
            false,
        )
        .expect("write state");
        let mut continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::BlockingHostWrite(write),
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("write continuation");
        let mut registration = service.prepare_registration(&continuation);
        service.enroll(&mut registration).expect("enroll write");
        assert_eq!(
            service
                .wait_for_event(registration.wake_token(), Duration::from_secs(1))
                .expect("write completion"),
            ContinuationEvent::Ready
        );
        continuation
            .attach_registration(registration)
            .expect("attach write registration");
        assert_eq!(
            continuation
                .resume(ContinuationEvent::Ready, &context)
                .expect("resume write")
                .completion,
            ContinuationCompletion::Return(4)
        );
        close_pair(pipe);

        let pipe = pipe_pair();
        let lock =
            BlockingRecordLock::new(pipe[0], libc::F_SETLKW, 0, 1, 1, 0).expect("record state");
        let lock_continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::BlockingRecordLock(lock),
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("record continuation");
        let mut registration = service.prepare_registration(&lock_continuation);
        service.enroll(&mut registration).expect("enroll record");
        assert_eq!(
            service
                .wait_for_event(registration.wake_token(), Duration::from_secs(1))
                .expect("record terminal result"),
            ContinuationEvent::Ready
        );
        drop(lock_continuation);
        close_pair(pipe);

        let signal_continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSignals {
                wait_set: SigSet::from_raw(1 << 9),
                block_mask: SigBlockMask::NONE,
                timeout: None,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("signal continuation");
        let mut registration = service.prepare_registration(&signal_continuation);
        service.enroll(&mut registration).expect("enroll signal");
        context.task().wake();
        assert_eq!(
            service
                .wait_for_event(registration.wake_token(), Duration::from_secs(1))
                .expect("task signal source"),
            ContinuationEvent::Ready
        );
        drop(signal_continuation);

        let plan = ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM)
            .expect("vfork plan");
        let published = kernel
            .reserve_fork(&context, plan, "reactor vfork".to_owned(), None)
            .expect("reserve")
            .prepare_reference(ThreadId::synthetic_for_tests(15_234))
            .expect("prepare")
            .commit()
            .expect("commit");
        let (child, wait) = published.into_parts().expect("child start");
        let wait = wait.expect("parent wait");
        let current = context
            .task_binding()
            .capture(context.thread().key().tid)
            .expect("current parent");
        let vfork = BlockedContinuation::from_vfork_parent(
            capture(&current, generation, ContinuationBackend::Hvpatch),
            child.task().key(),
            wait,
        )
        .expect("vfork continuation");
        let mut registration = service.prepare_registration(&vfork);
        service.enroll(&mut registration).expect("enroll vfork");
        kernel
            .exit_task(
                child.task().key().id,
                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("exit vfork child");
        assert_eq!(
            service
                .wait_for_event(registration.wake_token(), Duration::from_secs(1))
                .expect("vfork release source"),
            ContinuationEvent::Ready
        );
    }

    #[test]
    fn kernel_owned_continuation_does_not_form_a_thread_or_kernel_arc_cycle() {
        let mut fixture = race_fixture(15_235);
        let thread = Arc::downgrade(fixture.context.thread());
        fixture
            .scheduler
            .begin_switch_out(&fixture.running)
            .expect("switch out");
        fixture
            .service
            .enroll(&mut fixture.registration)
            .expect("enroll");
        fixture
            .scheduler
            .settle_blocked_continuation(
                fixture.running,
                fixture.continuation,
                fixture.registration,
            )
            .expect("block");
        drop(fixture.context);
        drop(fixture.service);
        drop(fixture.scheduler);
        assert!(
            thread.upgrade().is_none(),
            "Kernel Thread -> continuation -> KernelContext would be an unreclaimable cycle"
        );
    }

    #[test]
    fn readiness_cancellation_race_has_one_registration_winner_and_one_cleanup() {
        for pid in 15_300..15_364 {
            let fixture = race_fixture(pid);
            let token = fixture.registration.wake_token();
            let barrier = Arc::new(Barrier::new(3));
            let publish_service = Arc::clone(&fixture.service);
            let publish_barrier = Arc::clone(&barrier);
            let publish = thread::spawn(move || {
                publish_barrier.wait();
                publish_service.publish_ready(token)
            });
            let cancel_service = Arc::clone(&fixture.service);
            let cancel_barrier = Arc::clone(&barrier);
            let registration = fixture.registration;
            let cancel = thread::spawn(move || {
                cancel_barrier.wait();
                cancel_service.cancel_registration(registration)
            });
            barrier.wait();
            let ready = publish.join().expect("ready publisher");
            let cancelled = cancel.join().expect("canceller");
            assert_ne!(
                ready.accepted(),
                cancelled.is_ok(),
                "readiness and cancellation must have exactly one terminal winner"
            );
            if ready.accepted() {
                assert!(matches!(
                    fixture.context.thread().execution_state(),
                    ThreadExecutionState::Running {
                        wake_pending: true,
                        ..
                    }
                ));
            } else {
                assert!(matches!(
                    fixture.context.thread().execution_state(),
                    ThreadExecutionState::Running {
                        wake_pending: false,
                        ..
                    }
                ));
            }
            drop(fixture.continuation);
        }
    }

    #[test]
    fn duplicate_ready_and_cancel_after_ready_are_rejected_without_extra_wake() {
        let fixture = race_fixture(15_365);
        let token = fixture.registration.wake_token();
        let first = fixture.service.publish_ready(token);
        assert!(first.accepted());
        assert!(first.first_publication());
        let duplicate = fixture.service.publish_ready(token);
        assert!(!duplicate.accepted());
        assert!(!duplicate.first_publication());
        assert!(
            fixture
                .service
                .cancel_registration(fixture.registration)
                .is_err()
        );
        assert!(matches!(
            fixture.context.thread().execution_state(),
            ThreadExecutionState::Running {
                wake_pending: true,
                ..
            }
        ));
    }

    #[test]
    fn capture_uses_live_lease_mm_and_independent_asid_authority() {
        let (_kernel, context) = bootstrap(15_366);
        let mm = context.shared().mm().id();
        let independent_asid = mm.raw().checked_add(0x4000).expect("test asid");
        context
            .thread()
            .publish_initial_task_state(task_state_with_asid(&context, 0x701, independent_asid))
            .expect("publish independent ASID snapshot");
        let executor = crate::kernel::objects::ExecutorId::for_transitional_thread(
            context.thread().registry_id(),
        )
        .expect("executor");
        let lease = context.thread().claim_runnable(executor).expect("lease");
        let capture = ContinuationCapture::from_lease(
            &context,
            &lease,
            request(73),
            RestartClass::RestartSyscall,
            ContinuationBackend::Hvpatch,
        )
        .expect("lease-derived capture");
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(1),
                remaining: None,
            },
            capture,
        )
        .expect("continuation");
        assert_eq!(continuation.authority().mm(), mm);
        assert_eq!(continuation.authority().asid_generation(), independent_asid);
        assert_eq!(continuation.authority().task_revision(), context.revision());
        drop(lease);
    }

    #[test]
    fn same_task_same_mm_revision_drift_is_rejected_on_resume() {
        let (kernel, context) = bootstrap(15_367);
        let generation = publish(&context, 0x702);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(1),
                remaining: None,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("continuation");
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let published = kernel
            .reserve_fork(&context, plan, "revision drift child".to_owned(), None)
            .expect("reserve fork")
            .prepare_reference(ThreadId::synthetic_for_tests(15_368))
            .expect("prepare fork")
            .commit()
            .expect("commit fork");
        let (_child, no_vfork_wait) = published.into_parts().expect("start child");
        assert!(no_vfork_wait.is_none());
        let fresh = context
            .task_binding()
            .capture(context.thread().key().tid)
            .expect("fresh same-task context");
        assert_eq!(fresh.task().key(), context.task().key());
        assert_eq!(fresh.shared().mm().id(), context.shared().mm().id());
        assert_ne!(fresh.revision(), context.revision());
        assert_eq!(
            continuation.resume(ContinuationEvent::Ready, &fresh),
            Err(ContinuationResumeError::StaleTaskRevision)
        );
    }

    #[test]
    fn signal_restart_is_derived_from_captured_kernel_action_not_event_input() {
        let (_kernel, context) = bootstrap(15_369);
        let generation = publish(&context, 0x703);
        let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let mut action = carrick_abi::LinuxSigaction::empty();
        action.sa_handler = 0x1234;
        action.sa_flags = carrick_abi::LINUX_SA_RESTART;
        let authority = context.signal_authority();
        authority.install_action(signal, action);
        authority.enqueue_thread_standard(signal, None);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("restartable continuation");
        let result = continuation
            .resume(ContinuationEvent::Signal, &context)
            .expect("signal completion");
        assert_eq!(result.restart(), RestartDecision::Restart);
        assert_eq!(
            result.completion,
            ContinuationCompletion::Errno(LINUX_EINTR)
        );
    }

    #[test]
    fn quantum_and_transitional_adapter_keep_ordinary_syscalls_resident() {
        let (_kernel, context) = bootstrap(15_240);
        let generation = publish(&context, 0x600);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(1),
                remaining: None,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .unwrap();
        let mut source = TestQuantumSource::new(10_000, continuation);
        let exit = run_task_quantum(&mut source);
        assert!(matches!(exit, QuantumExit::Blocked(_)));
        assert_eq!(source.completed_syscalls(), 10_000);
        assert_eq!(source.snapshot_count(), 1, "only the real block snapshots");

        let adapter = TransitionalDedicatedRunner::new();
        assert!(adapter.is_task_5_only());
        assert_eq!(
            adapter.drive_quantum(&mut TestQuantumSource::yield_now()),
            QuantumExitKind::Runnable
        );
    }

    #[test]
    fn static_hvpatch_continuation_closure_forbids_host_blocking_authority() {
        let source = include_str!("continuation.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production continuation source");
        for prohibited in [
            "libc::wait",
            "libc::waitpid",
            "libc::kill",
            "libc::nanosleep",
            "ThreadWaiter",
            "make_readiness_pipe",
        ] {
            assert!(
                !source.contains(prohibited),
                "HVPatch continuation path retains prohibited host-blocking authority: {prohibited}"
            );
        }
        assert_eq!(DISPATCH_FAMILIES.len() + 1, 16);

        let loop_source = include_str!("mod.rs");
        let product = loop_source
            .split("fn suspend_hvpatch_continuation")
            .nth(1)
            .and_then(|tail| tail.split("fn service_threaded_syscall").next())
            .expect("real HVPatch continuation adapter body");
        for required in [
            "ContinuationCapture::from_lease",
            "runner.run_task_quantum",
            "prepare_registration",
            ".enroll(",
            "recheck_registration",
            "save_shared_wait_state",
            "settle_transitional_blocked_continuation",
            "Yield::Blocked",
            "wait_for_event",
            "take_transitional_lease",
            "resume_continuation",
        ] {
            assert!(
                product.contains(required),
                "missing product boundary: {required}"
            );
        }
        for prohibited in [
            "libc::wait",
            "libc::waitpid",
            "libc::kill",
            "libc::nanosleep",
            "ThreadWaiter",
            "kqueue",
            "vfork_release_fd",
        ] {
            assert!(
                !product.contains(prohibited),
                "product adapter retains {prohibited}"
            );
        }
        let dispatch = loop_source
            .split("fn service_threaded_syscall")
            .nth(1)
            .expect("dispatch service body");
        let escape = dispatch
            .find("continuation::is_blocking_dispatch_outcome(&outcome)")
            .expect("HVPatch blocking escape");
        let first_inline_wait = dispatch
            .find("DispatchOutcome::BlockingHostWrite")
            .expect("compatibility wait arm");
        assert!(
            escape < first_inline_wait,
            "HVPatch must escape before compatibility waits"
        );
        let quiesce = include_str!("quiesce.rs");
        let hvpatch_fork = quiesce
            .split("fn handle_in_process_fork")
            .nth(1)
            .expect("HVPatch fork body");
        assert!(hvpatch_fork.contains("HvpatchBlockInput::Vfork"));
        assert!(!hvpatch_fork.contains("wait.wait_for_release"));
    }

    struct TestQuantumSource {
        remaining: usize,
        completed: usize,
        snapshots: usize,
        continuation: Option<BlockedContinuation>,
        yield_only: bool,
    }

    impl TestQuantumSource {
        fn new(remaining: usize, continuation: BlockedContinuation) -> Self {
            Self {
                remaining,
                completed: 0,
                snapshots: 0,
                continuation: Some(continuation),
                yield_only: false,
            }
        }

        fn yield_now() -> Self {
            Self {
                remaining: 0,
                completed: 0,
                snapshots: 0,
                continuation: None,
                yield_only: true,
            }
        }

        fn completed_syscalls(&self) -> usize {
            self.completed
        }

        fn snapshot_count(&self) -> usize {
            self.snapshots
        }
    }

    impl TaskQuantumSource for TestQuantumSource {
        fn next_boundary(&mut self) -> QuantumBoundary {
            if self.yield_only {
                self.yield_only = false;
                self.snapshots += 1;
                return QuantumBoundary::Yield;
            }
            if self.remaining != 0 {
                self.remaining -= 1;
                self.completed += 1;
                return QuantumBoundary::OrdinarySyscall;
            }
            self.snapshots += 1;
            QuantumBoundary::Block(Box::new(
                self.continuation.take().expect("one terminal continuation"),
            ))
        }
    }
}
