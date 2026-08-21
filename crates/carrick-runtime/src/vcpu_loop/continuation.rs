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
use parking_lot::Mutex;

use crate::dispatch::{
    BlockingHostWrite, BlockingRecordLock, DispatchOutcome, SyscallRequest, WaitFds,
};
use crate::kernel::objects::{ExecutionGeneration, ThreadKey};
use crate::kernel::{
    Kernel, KernelContext, MmId, Scheduler, TaskKey, TaskRevision, VforkParentWait,
};
use crate::linux_abi::{LINUX_EAGAIN, LINUX_EINTR, LINUX_ETIMEDOUT, LinuxErrno};
use crate::thread::FutexWait;

static NEXT_CONTINUATION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_REGISTRATION_GENERATION: AtomicU64 = AtomicU64::new(1);
static NEXT_RESOURCE_GENERATION: AtomicU64 = AtomicU64::new(1);

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
    thread: ThreadKey,
    task: TaskKey,
    task_revision: TaskRevision,
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
        let mm = context.shared().mm().id();
        let signal_authority = context.signal_authority();
        Ok(Self {
            kernel: Arc::downgrade(context.kernel()),
            thread: context.thread().key(),
            task: context.task().key(),
            task_revision: context.revision(),
            mm,
            asid_generation: mm.raw(),
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
    thread: ThreadKey,
    task: TaskKey,
    task_revision: TaskRevision,
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
            thread: capture.thread,
            task: capture.task,
            task_revision: capture.task_revision,
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

#[derive(Debug)]
struct OwnedFdRegistration {
    #[allow(dead_code)]
    fd: OwnedFd,
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
                fd: unsafe { OwnedFd::from_raw_fd(owned) },
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
    HostWrite(BlockingHostWrite),
    RecordLock(BlockingRecordLock),
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
    registration: Option<RegistrationBinding>,
    cleanup: CleanupState,
}

impl Drop for ContinuationState {
    fn drop(&mut self) {
        if let Some(binding) = self.registration.take()
            && let Some(service) = binding.service.upgrade()
        {
            service.cancel_exact(binding.token);
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
                ContinuationDetail::HostWrite(write),
            )),
            DispatchOutcome::BlockingRecordLock(lock) => Self::BlockingRecordLock(new_state(
                None,
                Vec::new(),
                Some(WaitSigMask::NONE),
                ContinuationDetail::RecordLock(lock),
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
            execution: self.authority().execution_generation(),
            mm: context.shared().mm().id(),
            asid_generation: context.shared().mm().id().raw(),
        })?;
        let family = self.family();
        let restart_class = self.authority().restart_class();
        let outcome = match event {
            ContinuationEvent::Ready => match family {
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
                        ContinuationDetail::HostWrite(write) => write.offset() as i64,
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
                        ContinuationDetail::HostWrite(write) => write.offset() as i64,
                        _ => 0,
                    };
                    ContinuationCompletion::Return(offset)
                }
                _ => ContinuationCompletion::Redispatch,
            },
            ContinuationEvent::Signal { restart } => {
                let restart = if family == ContinuationFamily::WaitOnSignals
                    || restart_class == RestartClass::Never
                {
                    RestartDecision::NoRestart
                } else {
                    restart
                };
                let completion = if family == ContinuationFamily::BlockingHostWrite {
                    let offset = match &self.state().detail {
                        ContinuationDetail::HostWrite(write) => write.offset() as i64,
                        _ => 0,
                    };
                    if offset != 0 {
                        ContinuationCompletion::Return(offset)
                    } else {
                        ContinuationCompletion::Errno(LINUX_EINTR)
                    }
                } else if family == ContinuationFamily::WaitOnSleep {
                    ContinuationCompletion::ErrnoWithGuestWrites(
                        LINUX_EINTR,
                        self.guest_outputs().to_vec(),
                    )
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
    let continuation = lease
        .take_blocked_continuation()
        .ok_or(ContinuationResumeError::MissingContinuation)?;
    continuation.resume(event, context)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeContext {
    thread: ThreadKey,
    task: TaskKey,
    execution: ExecutionGeneration,
    mm: MmId,
    asid_generation: u64,
}

impl ResumeContext {
    #[cfg(test)]
    fn for_test(
        thread: ThreadKey,
        task: TaskKey,
        execution: ExecutionGeneration,
        mm: MmId,
        asid_generation: u64,
    ) -> Self {
        Self {
            thread,
            task,
            execution,
            mm,
            asid_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContinuationResumeError {
    StaleThread,
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
    Signal { restart: RestartDecision },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContinuationCompletion {
    Return(i64),
    Errno(LinuxErrno),
    Redispatch,
    RedispatchWithPartial(i64),
    ReturnWithGuestWrites(i64, Vec<GuestOutputRange>),
    ErrnoWithGuestWrites(LinuxErrno, Vec<GuestOutputRange>),
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
}

#[derive(Debug)]
struct RegistrationEntry {
    token: ContinuationWakeToken,
    state: RegistrationState,
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
}

impl CarrierWaitServiceInner {
    fn cancel_exact(&self, token: ContinuationWakeToken) -> bool {
        let mut state = self.state.lock();
        if state
            .entries
            .get(&token.continuation)
            .is_none_or(|entry| entry.token != token)
        {
            return false;
        }
        state.entries.remove(&token.continuation);
        true
    }
}

#[derive(Clone, Debug)]
pub struct CarrierWaitService {
    inner: Arc<CarrierWaitServiceInner>,
}

impl CarrierWaitService {
    pub fn new(scheduler: Arc<Scheduler>) -> Self {
        Self {
            inner: Arc::new(CarrierWaitServiceInner {
                scheduler,
                state: Mutex::new(CarrierWaitState::default()),
            }),
        }
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
        let mut state = self.inner.state.lock();
        let replaced = state.entries.insert(
            token.continuation,
            RegistrationEntry {
                token,
                state: RegistrationState::Prepared,
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
        Ok(())
    }

    pub fn publish_ready(&self, token: ContinuationWakeToken) -> WakePublishReceipt {
        let first = {
            let mut state = self.inner.state.lock();
            let Some(entry) = state.entries.get_mut(&token.continuation) else {
                return WakePublishReceipt::rejected();
            };
            if entry.token != token {
                return WakePublishReceipt::rejected();
            }
            let first = entry.state != RegistrationState::Ready;
            entry.state = RegistrationState::Ready;
            first
        };
        let accepted = self.inner.scheduler.wake(token.thread).is_ok();
        WakePublishReceipt { accepted, first }
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
            service_threads: 0,
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
        run_task_quantum(source).kind()
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
                asid_generation: mm.raw(),
            }),
            mm,
            asid_generation: mm.raw(),
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
        let continuation = BlockedContinuation::from_vfork_parent(
            capture(&context, generation, ContinuationBackend::Hvpatch),
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
                capture(&context, generation, ContinuationBackend::Hvpatch),
                child.task().key(),
                wait.clone(),
            )
            .expect("repeat owned vfork wait");
            continuation.install_cleanup_probe(Arc::clone(&probe));
            continuation
        };
        let ready = make()
            .resume(ContinuationEvent::Ready, &context)
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
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let executor = scheduler
            .register_executor(Arc::new(TestKick::default()))
            .expect("executor");
        scheduler
            .make_runnable(context.thread().key())
            .expect("queue root");
        let running = scheduler.take(&executor).expect("claim root");
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnSleep {
                duration: Duration::from_secs(30),
                remaining: Some(crate::dispatch::GuestPtr(0xa000)),
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("continuation");
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
        let join = publish_with_real_barrier(Arc::clone(&fixture.service), token);
        join.join().expect("publisher");
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
                .resume(
                    ContinuationEvent::Signal {
                        restart: RestartDecision::Restart,
                    },
                    &context,
                )
                .expect("signal result");
            match (&family, &interrupted.completion) {
                (ContinuationFamily::BlockingHostWrite, ContinuationCompletion::Return(2)) => {}
                (
                    ContinuationFamily::WaitOnSleep,
                    ContinuationCompletion::ErrnoWithGuestWrites(errno, writes),
                ) => {
                    assert_eq!(*errno, LINUX_EINTR);
                    assert_eq!(writes.len(), 1);
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
        assert_eq!(topology.service_threads(), 0);
        assert_eq!(topology.shared_reactors(), 1);
        for _ in 0..256 {
            let continuation = BlockedContinuation::from_dispatch_outcome(
                DispatchOutcome::WaitOnSleep {
                    duration: Duration::from_secs(30),
                    remaining: None,
                },
                capture(
                    &fixture.context,
                    fixture.running.generation(),
                    ContinuationBackend::Hvpatch,
                ),
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
            assert!(cancelled.is_ok());
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
            "std::thread::spawn",
            "Builder::spawn",
        ] {
            assert!(
                !source.contains(prohibited),
                "HVPatch continuation path retains prohibited host-blocking authority: {prohibited}"
            );
        }
        assert_eq!(DISPATCH_FAMILIES.len() + 1, 16);

        let loop_source = include_str!("mod.rs");
        assert!(
            loop_source.contains(
                "let _transitional_runner = continuation::TransitionalDedicatedRunner::new();"
            ),
            "Task 5 product path must remain explicitly marked until Task 7 removes the adapter"
        );
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
