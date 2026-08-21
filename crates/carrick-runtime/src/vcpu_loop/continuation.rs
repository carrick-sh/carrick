//! Owned, generation-authenticated blocking syscall continuations.
//!
//! The Kernel owns a [`BlockedContinuation`] while its logical thread is
//! blocked.  [`CarrierWaitService`] owns only an exact registration referring
//! to that Kernel identity; callbacks publish durable readiness and ask the
//! scheduler to wake the exact thread, but never run guest code.

use std::collections::BTreeMap;
use std::future::Future;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use carrick_abi::{SigBlockMask, SigSet, WaitSigMask};
use carrick_guest_mem::{GuestVa, SharedFutexLocation};
use parking_lot::Mutex;

use crate::dispatch::{
    BlockingHostWrite, BlockingRecordLock, DispatchOutcome, SyscallRequest, WaitFdAuthority,
    WaitFds,
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
static NEXT_RUNNER_JOB_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    static CURRENT_RUNNER_JOB: std::cell::Cell<Option<JobId>> = const { std::cell::Cell::new(None) };
    static CURRENT_RUNNER_WORKER: std::cell::RefCell<Option<Arc<TransitionalWorkerContext>>> = const { std::cell::RefCell::new(None) };
}

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

fn make_control_pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        std::process::abort();
    }
    for fd in fds {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0
            || fd_flags < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0
        {
            std::process::abort();
        }
    }
    (unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    })
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
    file_table: Arc<crate::kernel::objects::FileTable>,
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
            file_table: context.resources().files(),
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
            file_table: context.resources().files(),
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
    file_table: Arc<crate::kernel::objects::FileTable>,
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
            file_table: capture.file_table,
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
        generation: FutexWait,
        value: u32,
        index: Option<i64>,
    },
    SharedWord {
        location: SharedFutexLocation,
        waiter_key: usize,
        generation: FutexWait,
        value: u32,
        sysv: Option<crate::dispatch::SysvWaitState>,
    },
    Fds {
        #[allow(dead_code)]
        registrations: Vec<OwnedFdRegistration>,
        file_table: Arc<crate::kernel::objects::FileTable>,
        fd_authority: WaitFdAuthority,
        on_timeout: i64,
        sig_mask: WaitSigMask,
    },
    Select {
        #[allow(dead_code)]
        registrations: Vec<OwnedFdRegistration>,
        file_table: Arc<crate::kernel::objects::FileTable>,
        fd_authority: WaitFdAuthority,
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
            service.cancel_exact(binding.token, CancellationCause::ServiceShutdown);
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
        let file_table = Arc::clone(&authority.file_table);
        let exact_slot_authorities = |fds: &WaitFds| match fds.authority() {
            WaitFdAuthority::Empty if fds.is_empty() => Ok(WaitFdAuthority::Empty),
            WaitFdAuthority::Logical { strict, watched } if !strict.is_empty() => {
                Ok(WaitFdAuthority::Logical {
                    strict: strict.clone(),
                    watched: watched.clone(),
                })
            }
            WaitFdAuthority::Internal(authority) => Ok(WaitFdAuthority::Internal(*authority)),
            WaitFdAuthority::Empty | WaitFdAuthority::Missing | WaitFdAuthority::Logical { .. } => {
                Err(ContinuationBuildError::FdPinFailed)
            }
        };
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
                generation,
                value,
                timeout,
            } => Self::SharedFutexWait(new_state(
                deadline(timeout),
                Vec::new(),
                None,
                ContinuationDetail::SharedFutex {
                    location,
                    waiter_key,
                    generation,
                    value,
                    index: None,
                },
            )),
            DispatchOutcome::SharedFutexWaitv {
                location,
                waiter_key,
                generation,
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
                    generation,
                    value,
                    index: Some(index),
                },
            )),
            DispatchOutcome::WaitOnSharedWord {
                location,
                waiter_key,
                generation,
                value,
                sysv,
            } => Self::WaitOnSharedWord(new_state(
                None,
                Vec::new(),
                None,
                ContinuationDetail::SharedWord {
                    location,
                    waiter_key,
                    generation,
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
                let fd_authority = exact_slot_authorities(&fds)?;
                Self::WaitOnFds(new_state(
                    deadline(timeout),
                    Vec::new(),
                    Some(sig_mask),
                    ContinuationDetail::Fds {
                        registrations,
                        file_table: Arc::clone(&file_table),
                        fd_authority,
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
                let fd_authority = exact_slot_authorities(&fds)?;
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
                        file_table: Arc::clone(&file_table),
                        fd_authority,
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
                let fd_authority = exact_slot_authorities(&fds)?;
                Self::WaitOnPollFds(new_state(
                    deadline(timeout),
                    Vec::new(),
                    Some(sig_mask),
                    ContinuationDetail::Fds {
                        registrations,
                        file_table,
                        fd_authority,
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
                generation,
                value,
                index,
            } => {
                fingerprint ^=
                    location.wait_addr().raw() as u64 ^ *waiter_key as u64 ^ u64::from(*value);
                fingerprint ^= generation.generation();
                fingerprint ^= index.unwrap_or(0) as u64;
            }
            ContinuationDetail::SharedWord {
                location,
                waiter_key,
                generation,
                value,
                sysv,
            } => {
                fingerprint ^=
                    location.wait_addr().raw() as u64 ^ *waiter_key as u64 ^ u64::from(*value);
                fingerprint ^= generation.generation();
                fingerprint ^= sysv.as_ref().map_or(0, |state| {
                    state.blocked_id() as u64 ^ state.wait_word_fd() as u64
                });
            }
            ContinuationDetail::Fds {
                registrations,
                on_timeout,
                sig_mask,
                ..
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
                ..
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
            || current.shared().mm().id() != authority.mm()
        {
            return Err(ContinuationResumeError::StaleThread);
        }
        Ok(())
    }

    pub(crate) fn install_temporary_signal_mask(&self, context: &KernelContext) {
        let masks = self.state().signal_masks;
        let Some(temporary) = masks.temporary else {
            return;
        };
        let effective = match temporary {
            WaitSigMask::Additive(extra) => masks.persistent.union(extra),
            WaitSigMask::Replace(replacement) => replacement,
        };
        context.signal_authority().set_blocked(effective);
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
            asid_generation: self.authority().asid_generation(),
        })?;
        if let Some(binding) = self.state_mut().registration.take()
            && let Some(service) = binding.service.upgrade()
        {
            service.consume_ready_exact(binding.token)?;
        }
        let exact_file_slots_live = match &self.state().detail {
            ContinuationDetail::Fds {
                file_table,
                fd_authority,
                ..
            }
            | ContinuationDetail::Select {
                file_table,
                fd_authority,
                ..
            } => match fd_authority {
                WaitFdAuthority::Logical { strict, .. } => strict
                    .iter()
                    .all(|authority| file_table.validate_slot_authority(*authority)),
                WaitFdAuthority::Empty | WaitFdAuthority::Internal(_) => true,
                WaitFdAuthority::Missing => false,
            },
            _ => true,
        };
        if !exact_file_slots_live {
            let masks = self.state().signal_masks;
            if masks.temporary.is_some() {
                let authority = context.signal_authority();
                authority.set_blocked(masks.persistent);
                authority.arm_restore_mask(masks.restore_after_signal);
            }
            self.state_mut().cleanup.settle();
            return Err(ContinuationResumeError::StaleFileSlot);
        }
        let signal_masks = self.state().signal_masks;
        let family = self.family();
        let restart_class = self.authority().restart_class();
        let producer_completion = self.state().producer_completion.lock().take();
        let outcome = match event {
            ContinuationEvent::Ready => match producer_completion {
                Some(
                    outcome @ (DispatchOutcome::Returned { .. } | DispatchOutcome::Errno { .. }),
                ) if family == ContinuationFamily::BlockingHostWrite => {
                    let write = match &self.state().detail {
                        ContinuationDetail::HostWrite(write) => write.lock().clone(),
                        _ => unreachable!("blocking-write family without write state"),
                    };
                    ContinuationCompletion::BlockingWrite {
                        write,
                        outcome: match outcome {
                            DispatchOutcome::Returned { value } => {
                                BlockingWriteOutcome::Return(value)
                            }
                            DispatchOutcome::Errno { errno } => BlockingWriteOutcome::Errno(errno),
                            _ => unreachable!(),
                        },
                    }
                }
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
            event @ (ContinuationEvent::Signal | ContinuationEvent::ReservedSignal(_)) => {
                let reserved_signal = event.reserved_signal().cloned();
                let signal_authority = context.signal_authority();
                let effective_mask = match signal_masks.temporary {
                    Some(WaitSigMask::Additive(extra)) => signal_masks.persistent.union(extra),
                    Some(WaitSigMask::Replace(replacement)) => replacement,
                    None => signal_masks.persistent,
                };
                let deliverable = signal_authority
                    .thread_pending()
                    .union(signal_authority.task_pending())
                    .difference(effective_mask);
                let deliverable_action = reserved_signal
                    .as_ref()
                    .map(ReservedSignal::action)
                    .or_else(|| {
                        deliverable.lowest_signum().and_then(|signum| {
                            crate::kernel::LinuxSignal::for_signal_number(signum)
                                .ok()
                                .map(|signal| signal_authority.action(signal))
                        })
                    });
                let caught_handler = deliverable_action.is_some_and(|action| {
                    action.sa_handler != carrick_abi::LINUX_SIG_DFL
                        && action.sa_handler != carrick_abi::LINUX_SIG_IGN
                });
                let action_requests_restart = caught_handler
                    && deliverable_action
                        .is_some_and(|action| action.sa_flags & carrick_abi::LINUX_SA_RESTART != 0);
                let partial_write_progress = match &self.state().detail {
                    ContinuationDetail::HostWrite(write) => write.lock().offset() != 0,
                    _ => false,
                };
                let restart = if family != ContinuationFamily::WaitOnSignals
                    && !partial_write_progress
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
                if signal_masks.temporary.is_some() {
                    if caught_handler {
                        signal_authority.arm_restore_mask(Some(
                            signal_masks
                                .restore_after_signal
                                .unwrap_or(signal_masks.persistent),
                        ));
                    } else {
                        signal_authority.set_blocked(signal_masks.persistent);
                        signal_authority.arm_restore_mask(signal_masks.restore_after_signal);
                    }
                }
                self.state_mut().cleanup.settle();
                return Ok(ContinuationResult {
                    completion,
                    restart,
                    reserved_signal,
                });
            }
        };
        if signal_masks.temporary.is_some() {
            let authority = context.signal_authority();
            authority.set_blocked(signal_masks.persistent);
            authority.arm_restore_mask(signal_masks.restore_after_signal);
        }
        self.state_mut().cleanup.settle();
        Ok(ContinuationResult {
            completion: outcome,
            restart: RestartDecision::NoRestart,
            reserved_signal: None,
        })
    }

    pub fn cancel(mut self, cause: CancellationCause) -> CancellationReceipt {
        let id = self.id();
        if let Some(binding) = self.state_mut().registration.take()
            && let Some(service) = binding.service.upgrade()
        {
            service.cancel_exact(binding.token, cause);
        }
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
    StaleTaskRevision,
    StaleAddressSpace,
    MissingContinuation,
    StaleFileSlot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartDecision {
    Restart,
    NoRestart,
}

#[derive(Clone, Copy, Debug)]
enum ReservedSignalSource {
    Kernel(crate::kernel::objects::SignalDequeue),
    HostSlot { tid: i32 },
}

struct ReservedSignalInner {
    authority: crate::kernel::objects::SignalAuthority,
    signum: i32,
    siginfo: Option<crate::linux_abi::LinuxSiginfo>,
    job_control_generation: Option<crate::kernel::objects::JobControlStopInvalidationGeneration>,
    action_generation: u64,
    mask_generation: u64,
    action: carrick_abi::LinuxSigaction,
    effective_mask: SigSet,
    persistent_restore: SigSet,
    temporary: WaitSigMask,
    source: ReservedSignalSource,
    settlement: AtomicU8,
}

impl Drop for ReservedSignalInner {
    fn drop(&mut self) {
        if self.settlement.load(Ordering::Acquire) != 0 {
            return;
        }
        match self.source {
            ReservedSignalSource::Kernel(dequeued) => {
                self.authority.requeue_reserved(dequeued);
            }
            ReservedSignalSource::HostSlot { tid } => {
                crate::host_signal::publish_pending_for(tid, self.signum);
            }
        }
    }
}

#[derive(Clone)]
pub struct ReservedSignal(Arc<ReservedSignalInner>);

impl PartialEq for ReservedSignal {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ReservedSignal {}

impl std::fmt::Debug for ReservedSignal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReservedSignal")
            .field("signum", &self.signum())
            .field("action_generation", &self.action_generation())
            .finish_non_exhaustive()
    }
}

impl ReservedSignal {
    #[cfg(test)]
    pub(crate) fn kernel(
        authority: crate::kernel::objects::SignalAuthority,
        dequeued: crate::kernel::objects::SignalDequeue,
        action_generation: u64,
        action: carrick_abi::LinuxSigaction,
        persistent_restore: SigSet,
    ) -> Self {
        let mask_generation = authority.signal_state_generation();
        let effective_mask = authority.blocked();
        Self(Arc::new(ReservedSignalInner {
            authority,
            signum: dequeued.pending.signal.raw(),
            siginfo: dequeued.pending.siginfo,
            job_control_generation: dequeued.job_control_generation,
            action_generation,
            mask_generation,
            action,
            effective_mask,
            persistent_restore,
            temporary: WaitSigMask::NONE,
            source: ReservedSignalSource::Kernel(dequeued),
            settlement: AtomicU8::new(0),
        }))
    }

    fn from_kernel_reservation(
        authority: crate::kernel::objects::SignalAuthority,
        reservation: crate::kernel::objects::SignalWaitReservation,
    ) -> Self {
        let dequeue = reservation.dequeue();
        let source = match reservation.origin() {
            crate::kernel::objects::SignalReservationOrigin::Kernel => {
                ReservedSignalSource::Kernel(dequeue)
            }
            crate::kernel::objects::SignalReservationOrigin::HostSlot { tid } => {
                ReservedSignalSource::HostSlot { tid }
            }
        };
        Self(Arc::new(ReservedSignalInner {
            authority,
            signum: reservation.signum(),
            siginfo: dequeue.pending.siginfo,
            job_control_generation: dequeue.job_control_generation,
            action_generation: reservation.action_generation(),
            mask_generation: reservation.mask_generation(),
            action: reservation.action(),
            effective_mask: reservation.effective_mask(),
            persistent_restore: reservation.persistent_restore(),
            temporary: reservation.temporary(),
            source,
            settlement: AtomicU8::new(0),
        }))
    }

    pub fn signum(&self) -> i32 {
        self.0.signum
    }

    pub fn action(&self) -> carrick_abi::LinuxSigaction {
        self.0.action
    }

    pub fn action_generation(&self) -> u64 {
        self.0.action_generation
    }

    pub fn mask_generation(&self) -> u64 {
        self.0.mask_generation
    }

    pub fn siginfo(&self) -> Option<crate::linux_abi::LinuxSiginfo> {
        self.0.siginfo
    }

    pub fn persistent_restore(&self) -> SigSet {
        self.0.persistent_restore
    }

    pub fn effective_mask(&self) -> SigSet {
        self.0.effective_mask
    }

    pub fn temporary_mask(&self) -> WaitSigMask {
        self.0.temporary
    }

    pub(crate) fn job_control_generation(
        &self,
    ) -> Option<crate::kernel::objects::JobControlStopInvalidationGeneration> {
        self.0.job_control_generation
    }

    /// Transfer the exact dequeued instance to guest delivery. Only the first
    /// caller can consume it; cancellation/drop before this point requeues it.
    pub fn consume(&self) -> bool {
        self.0
            .settlement
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContinuationEvent {
    Ready,
    Timeout,
    Signal,
    ReservedSignal(ReservedSignal),
}

impl ContinuationEvent {
    pub fn reserved_signal(&self) -> Option<&ReservedSignal> {
        match self {
            Self::ReservedSignal(signal) => Some(signal),
            Self::Ready | Self::Timeout | Self::Signal => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContinuationCompletion {
    Return(i64),
    Errno(LinuxErrno),
    Redispatch,
    RedispatchWithPartial(i64),
    ReturnWithGuestWrites(i64, Vec<GuestOutputRange>),
    ErrnoWithGuestWrites(LinuxErrno, Vec<GuestOutputRange>),
    BlockingWrite {
        write: BlockingHostWrite,
        outcome: BlockingWriteOutcome,
    },
    InterruptedSleep {
        remaining: Option<(GuestOutputRange, Duration)>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockingWriteOutcome {
    Return(i64),
    Errno(LinuxErrno),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationResult {
    pub completion: ContinuationCompletion,
    restart: RestartDecision,
    reserved_signal: Option<ReservedSignal>,
}

impl ContinuationResult {
    pub const fn restart(&self) -> RestartDecision {
        self.restart
    }

    pub fn reserved_signal(&self) -> Option<&ReservedSignal> {
        self.reserved_signal.as_ref()
    }

    pub fn take_reserved_signal(&mut self) -> Option<ReservedSignal> {
        self.reserved_signal.take()
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
            service.cancel_exact(self.token, CancellationCause::ServiceShutdown);
        }
        self.settled = true;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistrationState {
    Prepared,
    Enrolled,
    Ready,
    Cancelled(CancellationCause),
    Consumed,
}

#[allow(dead_code)]
enum ProducerSubscription {
    Futex(carrick_thread::thread::FutexGenerationSubscription),
    Task(crate::kernel::objects::TaskWakeSubscription),
    Vfork(crate::kernel::core::VforkReleaseSubscription),
    FileSlot(crate::kernel::objects::FileSlotSubscription),
}

impl std::fmt::Debug for ProducerSubscription {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Futex(_) => formatter.write_str("FutexGenerationSubscription"),
            Self::Task(_) => formatter.write_str("TaskWakeSubscription"),
            Self::Vfork(_) => formatter.write_str("VforkReleaseSubscription"),
            Self::FileSlot(_) => formatter.write_str("FileSlotSubscription"),
        }
    }
}

#[derive(Clone, Debug)]
enum ReadinessProbe {
    Futex {
        table: FutexSource,
        wait: FutexWait,
        deadline: Option<Instant>,
    },
    Fds {
        registrations: Vec<OwnedFdRegistration>,
        file_table: Arc<crate::kernel::objects::FileTable>,
        fd_authority: WaitFdAuthority,
        deadline: Option<Instant>,
    },
    SharedWord {
        location: SharedFutexLocation,
        generation: FutexWait,
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

#[derive(Clone, Debug)]
struct SignalReadinessProbe {
    kernel: Weak<Kernel>,
    task_ref: Weak<Task>,
    observed_task_wake: u64,
    task: TaskKey,
    thread: ThreadKey,
    temporary: Option<WaitSigMask>,
    family: ContinuationFamily,
    wait_set: Option<SigSet>,
    signal_wait_block: Option<SigBlockMask>,
}

impl SignalReadinessProbe {
    fn from_continuation(continuation: &BlockedContinuation) -> Self {
        let state = continuation.state();
        let (wait_set, signal_wait_block) = match state.detail {
            ContinuationDetail::Signals {
                wait_set,
                block_mask,
            } => (Some(wait_set), Some(block_mask)),
            _ => (None, None),
        };
        Self {
            kernel: state.authority.kernel.clone(),
            task_ref: state.authority.task_ref.clone(),
            observed_task_wake: state.authority.task_wake_generation,
            task: state.authority.task,
            thread: state.authority.thread,
            temporary: state.signal_masks.temporary,
            family: continuation.family(),
            wait_set,
            signal_wait_block,
        }
    }

    fn event(&self) -> Option<ContinuationEvent> {
        if matches!(
            self.family,
            ContinuationFamily::WaitOnProcExit
                | ContinuationFamily::WaitOnProcState
                | ContinuationFamily::WaitOnHvpatchChild
        ) {
            return Some(ContinuationEvent::Ready);
        }
        let kernel = self.kernel.upgrade()?;
        let context = kernel.context(self.task.id, self.thread.tid).ok()?;
        if context.task().key() != self.task || context.thread().key() != self.thread {
            return None;
        }
        let authority = context.signal_authority();
        let host_signum = crate::host_signal::take_pending_for(self.thread.tid.raw());
        if let Some(wait_set) = self.wait_set {
            if host_signum != 0 && wait_set.contains(host_signum) {
                crate::host_signal::publish_pending_for(self.thread.tid.raw(), host_signum);
                return Some(ContinuationEvent::Ready);
            }
            if authority.has_pending_in(wait_set) {
                return Some(ContinuationEvent::Ready);
            }
            let blocked =
                SigSet::from_raw(self.signal_wait_block.unwrap_or(SigBlockMask::NONE).raw());
            let reservation = if host_signum == 0 {
                authority.reserve_deliverable_for_wait(WaitSigMask::Replace(blocked))
            } else {
                authority.reserve_deliverable_for_wait_with_host_slot(
                    WaitSigMask::Replace(blocked),
                    self.thread.tid.raw(),
                    host_signum,
                )
            };
            return reservation.map(|reservation| {
                ContinuationEvent::ReservedSignal(ReservedSignal::from_kernel_reservation(
                    authority,
                    reservation,
                ))
            });
        }
        let temporary = self.temporary.unwrap_or(WaitSigMask::NONE);
        let reservation = if host_signum == 0 {
            authority.reserve_deliverable_for_wait(temporary)
        } else {
            authority.reserve_deliverable_for_wait_with_host_slot(
                temporary,
                self.thread.tid.raw(),
                host_signum,
            )
        };
        reservation.map(|reservation| {
            ContinuationEvent::ReservedSignal(ReservedSignal::from_kernel_reservation(
                authority,
                reservation,
            ))
        })
    }
}

impl ReadinessProbe {
    fn from_continuation(continuation: &BlockedContinuation) -> Self {
        let state = continuation.state();
        match &state.detail {
            ContinuationDetail::Fds {
                registrations,
                file_table,
                fd_authority,
                ..
            }
            | ContinuationDetail::Select {
                registrations,
                file_table,
                fd_authority,
                ..
            } => Self::Fds {
                registrations: registrations.clone(),
                file_table: Arc::clone(file_table),
                fd_authority: fd_authority.clone(),
                deadline: state.deadline,
            },
            ContinuationDetail::SharedFutex {
                location,
                generation,
                value,
                ..
            }
            | ContinuationDetail::SharedWord {
                location,
                generation,
                value,
                ..
            } => Self::SharedWord {
                location: *location,
                generation: *generation,
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
                ..
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
                generation: _,
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
    deadline: Option<Instant>,
    task_waker: Option<Waker>,
    subscriptions: Vec<ProducerSubscription>,
    signal_readiness: SignalReadinessProbe,
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
    shutdown: AtomicBool,
    service_handles: AtomicU64,
    reactor: Mutex<Option<std::thread::JoinHandle<()>>>,
    control_read: OwnedFd,
    control_write: OwnedFd,
    reactor_poll_calls: AtomicU64,
    #[cfg(test)]
    reactor_poll_observer: Mutex<Option<Arc<std::sync::Barrier>>>,
}

impl CarrierWaitServiceInner {
    fn nudge_reactor(&self) {
        let byte = [1u8; 1];
        let _ = unsafe {
            libc::write(
                self.control_write.as_raw_fd(),
                byte.as_ptr().cast(),
                byte.len(),
            )
        };
    }
    fn attach_subscription(
        &self,
        token: ContinuationWakeToken,
        subscription: ProducerSubscription,
    ) {
        let mut state = self.state.lock();
        let Some(entry) = state
            .entries
            .get_mut(&token.continuation)
            .filter(|entry| entry.token == token)
        else {
            return;
        };
        if matches!(
            entry.state,
            RegistrationState::Prepared | RegistrationState::Enrolled
        ) {
            entry.subscriptions.push(subscription);
        }
    }

    fn publish_task_wake(&self, token: ContinuationWakeToken) {
        let probe = {
            let state = self.state.lock();
            let Some(entry) = state
                .entries
                .get(&token.continuation)
                .filter(|entry| entry.token == token)
            else {
                return;
            };
            if !matches!(
                entry.state,
                RegistrationState::Prepared | RegistrationState::Enrolled
            ) {
                return;
            }
            entry.signal_readiness.clone()
        };
        if let Some(event) = probe.event() {
            self.publish_event(token, event);
        }
    }

    fn cancel_exact(&self, token: ContinuationWakeToken, cause: CancellationCause) -> bool {
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
        entry.state = RegistrationState::Cancelled(cause);
        let task_waker = entry.task_waker.take();
        drop(state);
        self.nudge_reactor();
        if let Some(waker) = task_waker {
            waker.wake();
        }
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
        Ok(())
    }

    fn retire_terminal_exact(&self, token: ContinuationWakeToken) -> bool {
        let mut state = self.state.lock();
        let terminal = state.entries.get(&token.continuation).is_some_and(|entry| {
            entry.token == token
                && matches!(
                    entry.state,
                    RegistrationState::Ready
                        | RegistrationState::Cancelled(_)
                        | RegistrationState::Consumed
                )
        });
        if terminal {
            state.entries.remove(&token.continuation);
        }
        terminal
    }

    fn publish_event(
        &self,
        token: ContinuationWakeToken,
        event: ContinuationEvent,
    ) -> WakePublishReceipt {
        let (won, task_waker) = {
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
            let task_waker = entry.task_waker.take();
            (true, task_waker)
        };
        let _ = self.scheduler.wake(token.thread);
        self.nudge_reactor();
        if let Some(waker) = task_waker {
            waker.wake();
        }
        WakePublishReceipt {
            accepted: won,
            first: won,
        }
    }

    fn run_reactor(weak: Weak<Self>) {
        enum FdSource {
            Ready(ContinuationWakeToken),
            HostWrite(
                ContinuationWakeToken,
                Arc<Mutex<BlockingHostWrite>>,
                Arc<Mutex<Option<DispatchOutcome>>>,
            ),
        }
        loop {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            if inner.shutdown.load(Ordering::Acquire) {
                return;
            }
            let control_fd = inner.control_read.as_raw_fd();
            let (mut pollfds, sources, nearest_deadline) = {
                let state = inner.state.lock();
                let mut pollfds = vec![libc::pollfd {
                    fd: control_fd,
                    events: libc::POLLIN,
                    revents: 0,
                }];
                let mut sources = Vec::new();
                let mut nearest_deadline: Option<Instant> = None;
                for entry in state
                    .entries
                    .values()
                    .filter(|entry| entry.state == RegistrationState::Enrolled)
                {
                    if let Some(deadline) = entry.deadline {
                        nearest_deadline = Some(
                            nearest_deadline.map_or(deadline, |current| current.min(deadline)),
                        );
                    }
                    match &entry.probe {
                        ReadinessProbe::Fds { registrations, .. } => {
                            for registration in registrations {
                                pollfds.push(libc::pollfd {
                                    fd: registration.fd.as_raw_fd(),
                                    events: registration.events,
                                    revents: 0,
                                });
                                sources.push(FdSource::Ready(entry.token));
                            }
                        }
                        ReadinessProbe::HostWrite { write, completion } => {
                            pollfds.push(libc::pollfd {
                                fd: write.lock().host_fd(),
                                events: libc::POLLOUT,
                                revents: 0,
                            });
                            sources.push(FdSource::HostWrite(
                                entry.token,
                                Arc::clone(write),
                                Arc::clone(completion),
                            ));
                        }
                        ReadinessProbe::RecordLock { .. } => {
                            let retry = Instant::now() + Duration::from_millis(10);
                            nearest_deadline =
                                Some(nearest_deadline.map_or(retry, |current| current.min(retry)));
                        }
                        _ => {}
                    }
                }
                (pollfds, sources, nearest_deadline)
            };
            let timeout_ms = nearest_deadline.map_or(-1, |deadline| {
                let remaining = deadline.saturating_duration_since(Instant::now());
                i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX)
            });
            drop(inner);
            let result = unsafe {
                libc::poll(
                    pollfds.as_mut_ptr(),
                    pollfds.len() as libc::nfds_t,
                    timeout_ms,
                )
            };
            let Some(inner) = weak.upgrade() else {
                return;
            };
            inner.reactor_poll_calls.fetch_add(1, Ordering::Relaxed);
            #[cfg(test)]
            if let Some(observer) = inner.reactor_poll_observer.lock().take() {
                observer.wait();
            }
            if inner.shutdown.load(Ordering::Acquire) {
                return;
            }
            if result < 0 {
                continue;
            }
            if pollfds[0].revents != 0 {
                let mut bytes = [0u8; 256];
                loop {
                    let read =
                        unsafe { libc::read(control_fd, bytes.as_mut_ptr().cast(), bytes.len()) };
                    if read <= 0 {
                        break;
                    }
                }
            }
            for (pollfd, source) in pollfds.iter().skip(1).zip(sources) {
                if pollfd.revents == 0 {
                    continue;
                }
                match source {
                    FdSource::Ready(token) => {
                        inner.publish_event(token, ContinuationEvent::Ready);
                    }
                    FdSource::HostWrite(token, write, completion) => {
                        let mut write = write.lock();
                        if let crate::dispatch::BlockingHostWriteStep::Done(outcome) =
                            crate::dispatch::drive_blocking_host_write(&mut write)
                        {
                            *completion.lock() = Some(outcome);
                            inner.publish_event(token, ContinuationEvent::Ready);
                        }
                    }
                }
            }
            let now = Instant::now();
            let expired = {
                let state = inner.state.lock();
                state
                    .entries
                    .values()
                    .filter(|entry| {
                        entry.state == RegistrationState::Enrolled
                            && entry.deadline.is_some_and(|deadline| now >= deadline)
                    })
                    .map(|entry| entry.token)
                    .collect::<Vec<_>>()
            };
            for token in expired {
                inner.publish_event(token, ContinuationEvent::Timeout);
            }
            let record_locks = {
                let state = inner.state.lock();
                state
                    .entries
                    .values()
                    .filter_map(|entry| {
                        if entry.state != RegistrationState::Enrolled {
                            return None;
                        }
                        let ReadinessProbe::RecordLock { lock, completion } = &entry.probe else {
                            return None;
                        };
                        Some((entry.token, Arc::clone(lock), Arc::clone(completion)))
                    })
                    .collect::<Vec<_>>()
            };
            for (token, lock, completion) in record_locks {
                if let crate::dispatch::BlockingRecordLockStep::Done(outcome) =
                    crate::dispatch::try_drive_blocking_record_lock(&lock)
                {
                    *completion.lock() = Some(outcome);
                    inner.publish_event(token, ContinuationEvent::Ready);
                }
            }
        }
    }
}

impl Drop for CarrierWaitServiceInner {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.nudge_reactor();
        if let Some(handle) = self.reactor.get_mut().take()
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

#[derive(Debug)]
pub struct CarrierWaitService {
    inner: Arc<CarrierWaitServiceInner>,
}

impl Clone for CarrierWaitService {
    fn clone(&self) -> Self {
        self.inner.service_handles.fetch_add(1, Ordering::Relaxed);
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for CarrierWaitService {
    fn drop(&mut self) {
        if self.inner.service_handles.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let wakers = {
            let mut state = self.inner.state.lock();
            state
                .entries
                .values_mut()
                .filter_map(|entry| {
                    if matches!(
                        entry.state,
                        RegistrationState::Prepared | RegistrationState::Enrolled
                    ) {
                        entry.state =
                            RegistrationState::Cancelled(CancellationCause::ServiceShutdown);
                        entry.task_waker.take()
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        self.inner.shutdown.store(true, Ordering::Release);
        self.inner.nudge_reactor();
        for waker in wakers {
            waker.wake();
        }
        if let Some(handle) = self.inner.reactor.lock().take()
            && handle.thread().id() != std::thread::current().id()
        {
            let _ = handle.join();
        }
    }
}

impl CarrierWaitService {
    pub fn new(scheduler: Arc<Scheduler>) -> Self {
        let (control_read, control_write) = make_control_pipe();
        let inner = Arc::new(CarrierWaitServiceInner {
            scheduler,
            state: Mutex::new(CarrierWaitState::default()),
            shutdown: AtomicBool::new(false),
            service_handles: AtomicU64::new(1),
            reactor: Mutex::new(None),
            control_read,
            control_write,
            reactor_poll_calls: AtomicU64::new(0),
            #[cfg(test)]
            reactor_poll_observer: Mutex::new(None),
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
        let signal_readiness = SignalReadinessProbe::from_continuation(continuation);
        let mut state = self.inner.state.lock();
        let replaced = state.entries.insert(
            token.continuation,
            RegistrationEntry {
                token,
                state: RegistrationState::Prepared,
                event: None,
                probe,
                deadline: continuation.deadline(),
                task_waker: None,
                subscriptions: Vec::new(),
                signal_readiness,
            },
        );
        if replaced.is_some() {
            std::process::abort();
        }
        #[cfg(test)]
        {
            state.last_prepared = Some(token);
        }
        drop(state);
        self.inner.nudge_reactor();
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
        drop(state);
        self.install_producer_subscriptions(registration.token)?;
        self.inner.nudge_reactor();
        Ok(())
    }

    fn install_producer_subscriptions(
        &self,
        token: ContinuationWakeToken,
    ) -> Result<(), WaitServiceError> {
        let (probe, signal) = {
            let state = self.inner.state.lock();
            let entry = state
                .entries
                .get(&token.continuation)
                .filter(|entry| entry.token == token)
                .ok_or(WaitServiceError::StaleRegistration)?;
            (entry.probe.clone(), entry.signal_readiness.clone())
        };
        let weak = Arc::downgrade(&self.inner);
        let futex_source = match &probe {
            ReadinessProbe::Futex { table, wait, .. } => Some((table.0.clone(), *wait)),
            ReadinessProbe::SharedWord { generation, .. } => Some((
                Arc::clone(carrick_thread::platform_futex::carrier_shared_futex_table()),
                *generation,
            )),
            _ => None,
        };
        if let Some((table, wait)) = futex_source {
            let callback_weak = weak.clone();
            match table.subscribe_generation(
                wait,
                Arc::new(move |_| {
                    if let Some(inner) = callback_weak.upgrade() {
                        inner.publish_event(token, ContinuationEvent::Ready);
                    }
                }),
            ) {
                carrick_thread::thread::FutexGenerationEnrollment::Ready(_) => {
                    self.inner.publish_event(token, ContinuationEvent::Ready);
                }
                carrick_thread::thread::FutexGenerationEnrollment::Subscribed(subscription) => {
                    self.inner
                        .attach_subscription(token, ProducerSubscription::Futex(subscription));
                }
            }
        }
        if let Some(task) = signal.task_ref.upgrade() {
            let callback_weak = weak.clone();
            match task.subscribe_wake(
                signal.observed_task_wake,
                Arc::new(move |_| {
                    if let Some(inner) = callback_weak.upgrade() {
                        inner.publish_task_wake(token);
                    }
                }),
            ) {
                crate::kernel::objects::TaskWakeEnrollment::Ready(_) => {
                    self.inner.publish_task_wake(token);
                }
                crate::kernel::objects::TaskWakeEnrollment::Subscribed(subscription) => {
                    self.inner
                        .attach_subscription(token, ProducerSubscription::Task(subscription));
                }
            }
        }
        if let ReadinessProbe::Fds {
            file_table,
            fd_authority,
            ..
        } = &probe
            && let WaitFdAuthority::Logical { strict, watched } = fd_authority
        {
            for authority in strict.iter().chain(watched) {
                let callback_weak = weak.clone();
                let Some(subscription) = file_table.subscribe_slot_authority(
                    *authority,
                    Arc::new(move |_| {
                        if let Some(inner) = callback_weak.upgrade() {
                            inner.publish_event(token, ContinuationEvent::Ready);
                        }
                    }),
                ) else {
                    self.inner.publish_event(token, ContinuationEvent::Ready);
                    continue;
                };
                self.inner
                    .attach_subscription(token, ProducerSubscription::FileSlot(subscription));
            }
        }
        if let ReadinessProbe::Vfork { wait } = &probe {
            let wait = wait.clone();
            let callback_weak = weak;
            match wait.subscribe_release(Arc::new(move |_| {
                if let Some(inner) = callback_weak.upgrade() {
                    inner.publish_event(token, ContinuationEvent::Ready);
                }
            })) {
                crate::kernel::core::VforkReleaseEnrollment::Ready(_) => {
                    self.inner.publish_event(token, ContinuationEvent::Ready);
                }
                crate::kernel::core::VforkReleaseEnrollment::Subscribed(subscription) => {
                    self.inner
                        .attach_subscription(token, ProducerSubscription::Vfork(subscription));
                }
            }
        }
        if let ReadinessProbe::SharedWord {
            location, value, ..
        } = &probe
        {
            let current = unsafe {
                (location.wait_addr().raw() as *const std::sync::atomic::AtomicU32)
                    .as_ref()
                    .map(|word| word.load(Ordering::Acquire))
            };
            if current.is_none_or(|current| current != *value) {
                self.inner.publish_event(token, ContinuationEvent::Ready);
            }
        }
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
                return Ok(entry.event.clone());
            }
            entry
                .signal_readiness
                .event()
                .or_else(|| entry.probe.poll())
        };
        if let Some(event) = event.as_ref() {
            self.inner.publish_event(registration.token, event.clone());
        }
        Ok(event)
    }

    pub fn publish_ready(&self, token: ContinuationWakeToken) -> WakePublishReceipt {
        self.inner.publish_event(token, ContinuationEvent::Ready)
    }

    pub fn registration_timing(
        &self,
        token: ContinuationWakeToken,
    ) -> Result<RegistrationTiming, WaitServiceError> {
        let state = self.inner.state.lock();
        let entry = state
            .entries
            .get(&token.continuation)
            .filter(|entry| entry.token == token)
            .ok_or(WaitServiceError::StaleRegistration)?;
        Ok(RegistrationTiming {
            deadline: entry.deadline,
            has_periodic_probe: false,
        })
    }

    pub fn cancel_registration(
        &self,
        registration: ContinuationRegistration,
    ) -> Result<(), WaitServiceError> {
        self.cancel_registration_with_cause(registration, CancellationCause::ServiceShutdown)
    }

    pub fn cancel_registration_with_cause(
        &self,
        mut registration: ContinuationRegistration,
        cause: CancellationCause,
    ) -> Result<(), WaitServiceError> {
        let cancelled = self.inner.cancel_exact(registration.token, cause);
        registration.settled = true;
        if cancelled {
            Ok(())
        } else {
            Err(WaitServiceError::StaleRegistration)
        }
    }

    pub fn event(&self, token: ContinuationWakeToken) -> ContinuationEventFuture {
        ContinuationEventFuture {
            service: Arc::clone(&self.inner),
            token,
        }
    }

    pub(crate) async fn event_outside_quiesce(
        &self,
        token: ContinuationWakeToken,
        barrier: Option<Arc<carrick_thread::fork_quiesce::QuiesceBarrier>>,
    ) -> Result<ContinuationEvent, WaitServiceError> {
        let Some(barrier) = barrier else {
            return self.event(token).await;
        };
        enum Selected {
            Readiness(Result<ContinuationEvent, WaitServiceError>),
            Quiesce(carrick_thread::fork_quiesce::QuiesceEvent),
        }
        let mut readiness = Box::pin(self.event(token));
        let mut observed = barrier.publication_generation();
        let mut pending_readiness = None;
        loop {
            let mut quiesce_event = Box::pin(next_quiesce_event(&barrier, observed));
            let selected = std::future::poll_fn(|context| {
                if pending_readiness.is_none()
                    && let Poll::Ready(event) = readiness.as_mut().poll(context)
                {
                    return Poll::Ready(Selected::Readiness(event));
                }
                quiesce_event.as_mut().poll(context).map(Selected::Quiesce)
            })
            .await;
            match selected {
                Selected::Readiness(event) if !barrier.is_quiescing() => {
                    return event;
                }
                Selected::Readiness(event) => {
                    observed = barrier.publication_generation();
                    pending_readiness = Some(event);
                }
                Selected::Quiesce(event) => {
                    observed = event.generation;
                    if event.kind == carrick_thread::fork_quiesce::QuiesceEventKind::Released
                        && let Some(event) = pending_readiness.take()
                    {
                        return event;
                    }
                }
            }
        }
    }

    pub(crate) fn retire_terminal(&self, token: ContinuationWakeToken) -> bool {
        self.inner.retire_terminal_exact(token)
    }

    pub const fn topology(&self) -> WaitServiceTopology {
        WaitServiceTopology {
            service_threads: 1,
            shared_reactors: 1,
            record_lock_workers: 0,
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

    #[cfg(test)]
    fn reactor_poll_calls(&self) -> u64 {
        self.inner.reactor_poll_calls.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn nudge_reactor_for_test(&self) {
        self.inner.nudge_reactor();
    }

    #[cfg(test)]
    fn observe_next_reactor_poll(&self) -> Arc<std::sync::Barrier> {
        let observer = Arc::new(std::sync::Barrier::new(2));
        *self.inner.reactor_poll_observer.lock() = Some(Arc::clone(&observer));
        observer
    }
}

pub struct ContinuationEventFuture {
    service: Arc<CarrierWaitServiceInner>,
    token: ContinuationWakeToken,
}

struct QuiesceEventAwaitState {
    event: Mutex<Option<carrick_thread::fork_quiesce::QuiesceEvent>>,
    waker: Mutex<Option<Waker>>,
}

struct QuiesceEventFuture {
    state: Arc<QuiesceEventAwaitState>,
    _subscription: Option<carrick_thread::fork_quiesce::QuiesceSubscription>,
}

impl Future for QuiesceEventFuture {
    type Output = carrick_thread::fork_quiesce::QuiesceEvent;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(event) = self.state.event.lock().take() {
            return Poll::Ready(event);
        }
        *self.state.waker.lock() = Some(context.waker().clone());
        self.state
            .event
            .lock()
            .take()
            .map_or(Poll::Pending, Poll::Ready)
    }
}

fn next_quiesce_event(
    barrier: &Arc<carrick_thread::fork_quiesce::QuiesceBarrier>,
    observed_generation: u64,
) -> QuiesceEventFuture {
    let state = Arc::new(QuiesceEventAwaitState {
        event: Mutex::new(None),
        waker: Mutex::new(None),
    });
    let callback_state = Arc::clone(&state);
    let enrollment = barrier.subscribe_quiesce(
        observed_generation,
        Arc::new(move |event| {
            *callback_state.event.lock() = Some(event);
            if let Some(waker) = callback_state.waker.lock().take() {
                waker.wake();
            }
        }),
    );
    match enrollment {
        carrick_thread::fork_quiesce::QuiesceEnrollment::Ready(event) => {
            *state.event.lock() = Some(event);
            QuiesceEventFuture {
                state,
                _subscription: None,
            }
        }
        carrick_thread::fork_quiesce::QuiesceEnrollment::Subscribed(subscription) => {
            QuiesceEventFuture {
                state,
                _subscription: Some(subscription),
            }
        }
    }
}

impl Future for ContinuationEventFuture {
    type Output = Result<ContinuationEvent, WaitServiceError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.service.state.lock();
        let Some(entry) = state
            .entries
            .get_mut(&self.token.continuation)
            .filter(|entry| entry.token == self.token)
        else {
            return Poll::Ready(Err(WaitServiceError::StaleRegistration));
        };
        match entry.state {
            RegistrationState::Ready => Poll::Ready(
                entry
                    .event
                    .clone()
                    .ok_or(WaitServiceError::StaleRegistration),
            ),
            RegistrationState::Cancelled(cause) => {
                state.entries.remove(&self.token.continuation);
                Poll::Ready(Err(WaitServiceError::Cancelled(cause)))
            }
            RegistrationState::Consumed => Poll::Ready(Err(WaitServiceError::StaleRegistration)),
            RegistrationState::Prepared | RegistrationState::Enrolled => {
                entry.task_waker = Some(context.waker().clone());
                Poll::Pending
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitServiceTopology {
    service_threads: usize,
    shared_reactors: usize,
    record_lock_workers: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationTiming {
    deadline: Option<Instant>,
    has_periodic_probe: bool,
}

impl RegistrationTiming {
    pub const fn deadline(self) -> Option<Instant> {
        self.deadline
    }

    pub const fn has_periodic_probe(self) -> bool {
        self.has_periodic_probe
    }
}

impl WaitServiceTopology {
    pub const fn service_threads(self) -> usize {
        self.service_threads
    }

    pub const fn shared_reactors(self) -> usize {
        self.shared_reactors
    }

    pub const fn record_lock_workers(self) -> usize {
        self.record_lock_workers
    }

    pub const fn task_waiter_threads(self) -> usize {
        0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WaitServiceError {
    #[error("wait-service registration is stale")]
    StaleRegistration,
    #[error("wait-service event did not arrive before the caller deadline")]
    TimedOut,
    #[error("wait-service registration was cancelled: {0:?}")]
    Cancelled(CancellationCause),
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

pub async fn yield_runner_quantum() {
    struct YieldOnce(bool);
    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    YieldOnce(false).await;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuantumExit {
    Runnable,
    Blocked,
    Exited,
    Failed,
}

struct TransitionalWorkerKick {
    binding: Mutex<Option<crate::kernel::ExecutorBinding>>,
    hardware: Mutex<Option<Box<dyn carrick_hal::VcpuKickDyn>>>,
    pending: AtomicBool,
}

impl std::fmt::Debug for TransitionalWorkerKick {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransitionalWorkerKick")
            .field("binding", &*self.binding.lock())
            .field("hardware_published", &self.hardware.lock().is_some())
            .field("pending", &self.pending.load(Ordering::Acquire))
            .finish()
    }
}

impl crate::kernel::ExecutorKick for TransitionalWorkerKick {
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
            self.pending.store(false, Ordering::Release);
            self.hardware.lock().take();
        }
    }

    fn deliver_exact(&self, token: crate::kernel::ExecutorKickToken) -> bool {
        let current = self.binding.lock();
        let exact = current.is_some_and(|binding| {
            binding.executor() == token.executor()
                && binding.executor_epoch() == token.executor_epoch()
                && binding.thread() == token.thread()
                && binding.generation() == token.generation()
        });
        if !exact {
            return false;
        }
        self.pending.store(true, Ordering::Release);
        if let Some(hardware) = self.hardware.lock().as_ref() {
            hardware.kick();
        }
        true
    }

    fn current_binding(&self) -> Option<crate::kernel::ExecutorBinding> {
        *self.binding.lock()
    }
}

struct TransitionalWorkerContext {
    scheduler: Arc<Scheduler>,
    registration: crate::kernel::ExecutorRegistration,
    kick: Arc<TransitionalWorkerKick>,
}

impl TransitionalWorkerContext {
    fn register(scheduler: Arc<Scheduler>) -> Result<Arc<Self>, TransitionalRunnerError> {
        let kick = Arc::new(TransitionalWorkerKick {
            binding: Mutex::new(None),
            hardware: Mutex::new(None),
            pending: AtomicBool::new(false),
        });
        let registration = scheduler
            .register_executor(Arc::clone(&kick) as Arc<dyn crate::kernel::ExecutorKick>)
            .map_err(|_| TransitionalRunnerError::TaskFailed)?;
        Ok(Arc::new(Self {
            scheduler,
            registration,
            kick,
        }))
    }

    fn publish_hardware_kick(&self, kick: Box<dyn carrick_hal::VcpuKickDyn>) -> bool {
        let binding = self.kick.binding.lock();
        if binding.is_none() {
            return false;
        }
        *self.kick.hardware.lock() = Some(kick);
        if self.kick.pending.swap(false, Ordering::AcqRel)
            && let Some(kick) = self.kick.hardware.lock().as_ref()
        {
            kick.kick();
        }
        true
    }
}

impl Drop for TransitionalWorkerContext {
    fn drop(&mut self) {
        let _ = self.scheduler.unregister_executor(&self.registration);
    }
}

/// Task-5-only adapter preserving the current welded runner until Task 6 wires
/// the real HVF executor backend.  It delegates all state decisions to the
/// Kernel/scheduler continuation APIs and owns no parallel task state machine.
enum RunnerWork {
    Poll(Arc<RunnerTask>),
    Shutdown,
}

pub(crate) struct RunnerTask {
    future: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>>,
    sender: mpsc::Sender<RunnerWork>,
    queued: AtomicBool,
    completion: LogicalJobCompletion,
    scheduler: Arc<Mutex<Option<Arc<Scheduler>>>>,
}

impl RunnerTask {
    fn enqueue(self: &Arc<Self>) -> bool {
        if !self.queued.swap(true, Ordering::AcqRel) {
            if self
                .sender
                .send(RunnerWork::Poll(Arc::clone(self)))
                .is_err()
            {
                self.queued.store(false, Ordering::Release);
                return false;
            }
            if let Some(scheduler) = self.scheduler.lock().as_ref() {
                scheduler.request_preemption();
            }
        }
        true
    }

    fn poll(self: &Arc<Self>) -> QuantumExit {
        struct CurrentJobGuard;
        impl Drop for CurrentJobGuard {
            fn drop(&mut self) {
                CURRENT_RUNNER_JOB.with(|current| current.set(None));
            }
        }
        CURRENT_RUNNER_JOB.with(|current| {
            if current.replace(Some(self.completion.id())).is_some() {
                std::process::abort();
            }
        });
        let _current_job = CurrentJobGuard;
        self.queued.store(false, Ordering::Release);
        let waker = Waker::from(Arc::clone(self));
        let mut context = Context::from_waker(&waker);
        let mut slot = self.future.lock();
        let Some(future) = slot.as_mut() else {
            return QuantumExit::Exited;
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            future.as_mut().poll(&mut context)
        })) {
            Ok(Poll::Ready(())) => {
                *slot = None;
                self.completion.publish();
                QuantumExit::Exited
            }
            Ok(Poll::Pending) if self.queued.load(Ordering::Acquire) => QuantumExit::Runnable,
            Ok(Poll::Pending) => QuantumExit::Blocked,
            Err(_) => {
                *slot = None;
                self.completion.publish();
                QuantumExit::Failed
            }
        }
    }

    fn fail_boundary(self: &Arc<Self>) {
        let mut slot = self.future.lock();
        *slot = None;
        self.completion.publish();
    }
}

pub(crate) fn run_task_quantum(task: &Arc<RunnerTask>) -> QuantumExit {
    task.poll()
}

struct VcpuAdmissionWait {
    owner_alive: bool,
    lease: Option<carrick_hal::SlotLease>,
    waker: Option<Waker>,
}

struct VcpuAdmissionState {
    wait: Mutex<VcpuAdmissionWait>,
    scheduler: &'static dyn carrick_hal::VcpuScheduler,
}

struct VcpuAdmissionFuture {
    scheduler: &'static dyn carrick_hal::VcpuScheduler,
    tid: u64,
    preferred: Option<carrick_hal::SlotId>,
    ticket: Option<carrick_hal::vcpu_sched::AdmissionTicket>,
    state: Arc<VcpuAdmissionState>,
}

impl Future for VcpuAdmissionFuture {
    type Output = carrick_hal::SlotLease;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        {
            let mut wait = self.state.wait.lock();
            if let Some(lease) = wait.lease.take() {
                wait.owner_alive = false;
                return Poll::Ready(lease);
            }
            wait.waker = Some(context.waker().clone());
        }
        if self.ticket.is_none() {
            let state = Arc::clone(&self.state);
            match self.scheduler.acquire_or_subscribe(
                self.tid,
                self.preferred,
                Arc::new(move |lease| {
                    let mut wait = state.wait.lock();
                    if !wait.owner_alive {
                        drop(wait);
                        state.scheduler.release(lease, carrick_hal::Yield::Blocked);
                        return;
                    }
                    wait.lease = Some(lease);
                    if let Some(waker) = wait.waker.take() {
                        waker.wake();
                    }
                }),
            ) {
                carrick_hal::vcpu_sched::Admission::Granted(lease) => {
                    self.state.wait.lock().owner_alive = false;
                    return Poll::Ready(lease);
                }
                carrick_hal::vcpu_sched::Admission::Pending(ticket) => {
                    self.ticket = Some(ticket);
                }
            }
        }
        let mut wait = self.state.wait.lock();
        if let Some(lease) = wait.lease.take() {
            wait.owner_alive = false;
            Poll::Ready(lease)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for VcpuAdmissionFuture {
    fn drop(&mut self) {
        let lease = {
            let mut wait = self.state.wait.lock();
            wait.owner_alive = false;
            wait.waker = None;
            wait.lease.take()
        };
        if let Some(ticket) = self.ticket.take() {
            let _ = self.scheduler.cancel_admission(ticket);
        }
        if let Some(lease) = lease {
            self.scheduler.release(lease, carrick_hal::Yield::Blocked);
        }
    }
}

pub(crate) fn await_vcpu_admission(
    scheduler: &'static dyn carrick_hal::VcpuScheduler,
    tid: u64,
    preferred: Option<carrick_hal::SlotId>,
) -> impl Future<Output = carrick_hal::SlotLease> {
    VcpuAdmissionFuture {
        scheduler,
        tid,
        preferred,
        ticket: None,
        state: Arc::new(VcpuAdmissionState {
            wait: Mutex::new(VcpuAdmissionWait {
                owner_alive: true,
                lease: None,
                waker: None,
            }),
            scheduler,
        }),
    }
}

impl Wake for RunnerTask {
    fn wake(self: Arc<Self>) {
        let _ = self.enqueue();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let _ = self.enqueue();
    }
}

struct TransitionalRunnerPool {
    sender: mpsc::Sender<RunnerWork>,
    receiver: Arc<Mutex<mpsc::Receiver<RunnerWork>>>,
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    worker_count: usize,
    next_worker: AtomicUsize,
    scheduler: Arc<Mutex<Option<Arc<Scheduler>>>>,
    reject_next_submission: AtomicBool,
}

impl TransitionalRunnerPool {
    fn spawn_worker(self: &Arc<Self>) {
        let receiver = Arc::clone(&self.receiver);
        let weak = Arc::downgrade(self);
        let index = self.next_worker.fetch_add(1, Ordering::Relaxed);
        let worker = std::thread::Builder::new()
            .name(format!("carrick-transitional-{index}"))
            .spawn(move || {
                let boundary = crate::vcpu_loop::executor::WorkerBoundaryAudit::capture()
                    .unwrap_or_else(|_| std::process::abort());
                let mut worker_context: Option<Arc<TransitionalWorkerContext>> = None;
                loop {
                    let work = receiver.lock().recv();
                    match work {
                        Ok(RunnerWork::Poll(task)) => {
                            if worker_context.is_none()
                                && let Some(pool) = weak.upgrade()
                                && let Some(scheduler) = pool.scheduler.lock().clone()
                            {
                                worker_context =
                                    TransitionalWorkerContext::register(scheduler).ok();
                            }
                            if boundary.audit_runtime_owned().is_err() {
                                task.fail_boundary();
                                if let Some(pool) = weak.upgrade() {
                                    pool.spawn_worker();
                                }
                                return;
                            }
                            CURRENT_RUNNER_WORKER.with(|current| {
                                *current.borrow_mut() = worker_context.clone();
                            });
                            let exit =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    run_task_quantum(&task)
                                }));
                            CURRENT_RUNNER_WORKER.with(|current| current.borrow_mut().take());
                            if !matches!(
                                exit,
                                Ok(QuantumExit::Runnable
                                    | QuantumExit::Blocked
                                    | QuantumExit::Exited)
                            ) {
                                task.fail_boundary();
                                drop(worker_context.take());
                                if let Some(pool) = weak.upgrade() {
                                    pool.spawn_worker();
                                }
                                return;
                            }
                            if boundary.audit_runtime_owned().is_err() {
                                task.fail_boundary();
                                if let Some(pool) = weak.upgrade() {
                                    pool.spawn_worker();
                                }
                                return;
                            }
                        }
                        Ok(RunnerWork::Shutdown) | Err(_) => return,
                    }
                }
            })
            .unwrap_or_else(|_| std::process::abort());
        self.workers.lock().push(worker);
    }
}

impl std::fmt::Debug for TransitionalRunnerPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransitionalRunnerPool")
            .field("worker_count", &self.worker_count)
            .finish_non_exhaustive()
    }
}

impl Drop for TransitionalRunnerPool {
    fn drop(&mut self) {
        for _ in 0..self.worker_count {
            let _ = self.sender.send(RunnerWork::Shutdown);
        }
        for worker in self.workers.get_mut().drain(..) {
            if worker.thread().id() != std::thread::current().id() {
                let _ = worker.join();
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct TransitionalDedicatedRunner {
    pool: Arc<TransitionalRunnerPool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransitionalRunnerError {
    #[error("transitional runner requires at least one worker")]
    ZeroWorkers,
    #[error("transitional runner task panicked or the runner stopped")]
    TaskFailed,
}

pub struct LogicalTaskReceipt<T> {
    receiver: mpsc::Receiver<T>,
    completion: LogicalJobCompletion,
}

impl<T> LogicalTaskReceipt<T> {
    pub fn wait(self) -> Result<T, TransitionalRunnerError> {
        self.receiver
            .recv()
            .map_err(|_| TransitionalRunnerError::TaskFailed)
    }

    pub fn is_finished(&self) -> bool {
        self.completion.is_finished()
    }

    pub fn completion(&self) -> LogicalJobCompletion {
        self.completion.clone()
    }

    pub fn try_take(self) -> Result<T, TransitionalRunnerError> {
        self.receiver
            .try_recv()
            .map_err(|_| TransitionalRunnerError::TaskFailed)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct JobId(u64);

impl JobId {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

type JobCompletionCallback = Arc<dyn Fn(JobId) + Send + Sync + 'static>;

struct JobCompletionState {
    done: AtomicBool,
    next_listener: AtomicU64,
    listeners: Mutex<BTreeMap<u64, JobCompletionCallback>>,
}

#[derive(Clone)]
pub struct LogicalJobCompletion {
    id: JobId,
    state: Arc<JobCompletionState>,
}

impl std::fmt::Debug for LogicalJobCompletion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LogicalJobCompletion")
            .field("id", &self.id)
            .field("done", &self.is_finished())
            .finish()
    }
}

impl LogicalJobCompletion {
    pub(crate) fn pending() -> Self {
        Self {
            id: JobId(next_nonzero(&NEXT_RUNNER_JOB_ID)),
            state: Arc::new(JobCompletionState {
                done: AtomicBool::new(false),
                next_listener: AtomicU64::new(1),
                listeners: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    pub const fn id(&self) -> JobId {
        self.id
    }

    pub fn is_finished(&self) -> bool {
        self.state.done.load(Ordering::Acquire)
    }

    pub(crate) fn publish(&self) {
        if self.state.done.swap(true, Ordering::AcqRel) {
            return;
        }
        let callbacks = std::mem::take(&mut *self.state.listeners.lock())
            .into_values()
            .collect::<Vec<_>>();
        for callback in callbacks {
            callback(self.id);
        }
    }

    fn subscribe(&self, callback: JobCompletionCallback) -> Option<JobCompletionSubscription> {
        let mut listeners = self.state.listeners.lock();
        if self.is_finished() {
            return None;
        }
        let listener = next_nonzero(&self.state.next_listener);
        listeners.insert(listener, callback);
        Some(JobCompletionSubscription {
            completion: self.clone(),
            listener,
        })
    }
}

pub(crate) struct LogicalJobCompletionGuard(LogicalJobCompletion);

impl LogicalJobCompletionGuard {
    pub(crate) fn new(completion: LogicalJobCompletion) -> Self {
        Self(completion)
    }
}

impl Drop for LogicalJobCompletionGuard {
    fn drop(&mut self) {
        self.0.publish();
    }
}

struct JobCompletionSubscription {
    completion: LogicalJobCompletion,
    listener: u64,
}

impl Drop for JobCompletionSubscription {
    fn drop(&mut self) {
        self.completion
            .state
            .listeners
            .lock()
            .remove(&self.listener);
    }
}

struct ProcessDrainState {
    remaining: AtomicUsize,
    waker: Mutex<Option<Waker>>,
}

pub struct ProcessDrain {
    state: Arc<ProcessDrainState>,
    _subscriptions: Vec<JobCompletionSubscription>,
}

impl ProcessDrain {
    pub fn excluding(current: LogicalJobCompletion, jobs: Vec<LogicalJobCompletion>) -> Self {
        let pending = jobs
            .into_iter()
            .filter(|job| job.id() != current.id() && !job.is_finished())
            .collect::<Vec<_>>();
        let state = Arc::new(ProcessDrainState {
            remaining: AtomicUsize::new(pending.len()),
            waker: Mutex::new(None),
        });
        let mut subscriptions = Vec::with_capacity(pending.len());
        for job in pending {
            let callback_state = Arc::clone(&state);
            match job.subscribe(Arc::new(move |_| {
                let previous = callback_state.remaining.fetch_sub(1, Ordering::AcqRel);
                if previous == 0 {
                    std::process::abort();
                }
                if previous == 1
                    && let Some(waker) = callback_state.waker.lock().take()
                {
                    waker.wake();
                }
            })) {
                Some(subscription) => subscriptions.push(subscription),
                None => {
                    state.remaining.fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
        Self {
            state,
            _subscriptions: subscriptions,
        }
    }
}

impl Future for ProcessDrain {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.state.remaining.load(Ordering::Acquire) == 0 {
            return Poll::Ready(());
        }
        *self.state.waker.lock() = Some(context.waker().clone());
        if self.state.remaining.load(Ordering::Acquire) == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionalRunnerTopology {
    worker_threads: usize,
}

impl TransitionalRunnerTopology {
    pub const fn worker_threads(self) -> usize {
        self.worker_threads
    }

    pub const fn task_waiter_threads(self) -> usize {
        0
    }
}

impl TransitionalDedicatedRunner {
    pub fn new() -> Self {
        Self::with_worker_limit(1).unwrap_or_else(|_| std::process::abort())
    }

    pub fn with_worker_limit(worker_count: usize) -> Result<Self, TransitionalRunnerError> {
        if worker_count == 0 {
            return Err(TransitionalRunnerError::ZeroWorkers);
        }
        let (sender, receiver) = mpsc::channel();
        let pool = Arc::new(TransitionalRunnerPool {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            workers: Mutex::new(Vec::with_capacity(worker_count)),
            worker_count,
            next_worker: AtomicUsize::new(0),
            scheduler: Arc::new(Mutex::new(None)),
            reject_next_submission: AtomicBool::new(false),
        });
        for _ in 0..worker_count {
            pool.spawn_worker();
        }
        Ok(Self { pool })
    }

    pub fn spawn<F, T>(&self, future: F) -> LogicalTaskReceipt<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        match self.try_spawn(future) {
            Ok(receipt) => receipt,
            Err(_) => {
                let (sender, receiver) = mpsc::channel();
                drop(sender);
                let completion = LogicalJobCompletion::pending();
                completion.publish();
                LogicalTaskReceipt {
                    receiver,
                    completion,
                }
            }
        }
    }

    pub fn try_spawn<F, T>(
        &self,
        future: F,
    ) -> Result<LogicalTaskReceipt<T>, TransitionalRunnerError>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        if self
            .pool
            .reject_next_submission
            .swap(false, Ordering::AcqRel)
        {
            return Err(TransitionalRunnerError::TaskFailed);
        }
        let (sender, receiver) = mpsc::channel();
        let completion = LogicalJobCompletion::pending();
        let future = async move {
            let value = future.await;
            let _ = sender.send(value);
        };
        let task = Arc::new(RunnerTask {
            future: Mutex::new(Some(Box::pin(future))),
            sender: self.pool.sender.clone(),
            queued: AtomicBool::new(false),
            completion: completion.clone(),
            scheduler: Arc::clone(&self.pool.scheduler),
        });
        if !task.enqueue() {
            return Err(TransitionalRunnerError::TaskFailed);
        }
        Ok(LogicalTaskReceipt {
            receiver,
            completion,
        })
    }

    #[cfg(test)]
    pub(crate) fn reject_next_submission_for_test(&self) {
        self.pool
            .reject_next_submission
            .store(true, Ordering::Release);
    }

    pub fn topology(&self) -> TransitionalRunnerTopology {
        TransitionalRunnerTopology {
            worker_threads: self.pool.worker_count,
        }
    }

    pub(crate) fn attach_scheduler(&self, scheduler: Arc<Scheduler>) {
        let mut slot = self.pool.scheduler.lock();
        if let Some(installed) = slot.as_ref() {
            if !Arc::ptr_eq(installed, &scheduler) {
                std::process::abort();
            }
            return;
        }
        *slot = Some(scheduler);
    }

    #[cfg(test)]
    pub(crate) fn current_executor_id() -> Option<crate::kernel::objects::ExecutorId> {
        CURRENT_RUNNER_WORKER.with(|current| {
            current
                .borrow()
                .as_ref()
                .map(|worker| worker.registration.id())
        })
    }

    pub(crate) fn current_executor_registration() -> Option<crate::kernel::ExecutorRegistration> {
        CURRENT_RUNNER_WORKER.with(|current| {
            current
                .borrow()
                .as_ref()
                .map(|worker| worker.registration.clone())
        })
    }

    pub(crate) fn publish_current_hardware_kick(kick: Box<dyn carrick_hal::VcpuKickDyn>) -> bool {
        CURRENT_RUNNER_WORKER.with(|current| {
            let current = current.borrow();
            let Some(worker) = current.as_ref() else {
                return false;
            };
            worker.publish_hardware_kick(kick)
        })
    }

    pub fn current_job() -> Option<LogicalJobCompletion> {
        let id = CURRENT_RUNNER_JOB.with(std::cell::Cell::get)?;
        // The exact completion handle is owned by RunnerTask. A process drain
        // only needs the stable JobId for self-exclusion, so this detached
        // handle is already terminal and is never subscribed.
        Some(LogicalJobCompletion {
            id,
            state: Arc::new(JobCompletionState {
                done: AtomicBool::new(true),
                next_listener: AtomicU64::new(1),
                listeners: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    pub const fn is_task_5_only(&self) -> bool {
        true
    }
}

impl Default for TransitionalDedicatedRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::os::fd::RawFd;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::task::{Context, Poll, Waker};
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

    fn enqueue_root(
        scheduler: &Arc<Scheduler>,
        context: &KernelContext,
        generation: ExecutionGeneration,
    ) {
        scheduler
            .admit_root(context.thread().key(), generation)
            .expect("admit root")
            .publish(scheduler, Arc::clone(context.thread()))
            .expect("publish root");
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

    fn install_test_fd_authority(
        context: &KernelContext,
        guest_fd: i32,
    ) -> crate::kernel::objects::FileSlotAuthority {
        let files = context.resources().files();
        let number = crate::kernel::FileSlotNumber::for_open_fd(guest_fd).expect("test guest fd");
        let ids = crate::kernel::ObjectIdRegistry::new();
        files.install(
            number,
            Arc::new(crate::kernel::FileDescription::regular(
                ids.file_description_id().expect("test description"),
            )),
            false,
        );
        files
            .capture_slot_authority(number)
            .expect("test slot authority")
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
                generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                    .prepare_wait(31),
                value: 7,
                timeout: Some(Duration::from_secs(4)),
            },
            ContinuationFamily::SharedFutexWaitv => DispatchOutcome::SharedFutexWaitv {
                location: SharedFutexLocation::Direct {
                    word: HostVa(0x4000),
                    waiter_key: 41,
                },
                waiter_key: 41,
                generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                    .prepare_wait(41),
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
                generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                    .prepare_wait(51),
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

    fn await_event(
        service: &CarrierWaitService,
        token: ContinuationWakeToken,
    ) -> Result<ContinuationEvent, WaitServiceError> {
        let runner = TransitionalDedicatedRunner::new();
        let service = service.clone();
        runner
            .spawn(async move { service.event(token).await })
            .wait()
            .expect("shared runner")
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
        let authority = install_test_fd_authority(&context, 0);
        let fds = pipe_pair();
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::raw(vec![(fds[0], libc::POLLIN)])
                    .with_slot_authorities(vec![authority]),
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
    fn fd_wait_subscription_rejects_close_reuse_before_redispatch() {
        let (kernel, context) = bootstrap(15_226);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let service = CarrierWaitService::new(scheduler);
        let generation = publish(&context, 0x552);
        let files = context.resources().files();
        let number = crate::kernel::FileSlotNumber::for_open_fd(0).expect("stdin slot");
        let ids = crate::kernel::ObjectIdRegistry::new();
        files.install(
            number,
            Arc::new(crate::kernel::FileDescription::regular(
                ids.file_description_id().expect("original description"),
            )),
            false,
        );
        let authority = files
            .capture_slot_authority(number)
            .expect("exact stdin authority");
        let fds = pipe_pair();
        let mut continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::raw_one(fds[0], libc::POLLIN).with_slot_authorities(vec![authority]),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("fd-authorized continuation");
        let mut registration = service.prepare_registration(&continuation);
        service.enroll(&mut registration).expect("enroll fd slot");
        let token = registration.wake_token();
        continuation
            .attach_registration(registration)
            .expect("attach exact registration");

        let successor = Arc::new(crate::kernel::FileDescription::regular(
            ids.file_description_id().expect("successor description"),
        ));
        files.install(number, successor, false);
        assert_eq!(
            await_event(&service, token).expect("slot replacement readiness"),
            ContinuationEvent::Ready
        );
        assert_eq!(
            continuation.resume(ContinuationEvent::Ready, &context),
            Err(ContinuationResumeError::StaleFileSlot)
        );
        close_pair(fds);
    }

    #[test]
    fn epoll_strict_owner_and_watched_source_authority_have_distinct_resume_results() {
        let run_case = |pid: i32, replace_epfd: bool| {
            let (kernel, context) = bootstrap(pid);
            let generation = publish(&context, 0xa00);
            let files = context.resources().files();
            let epfd = install_test_fd_authority(&context, 40);
            let watched = install_test_fd_authority(&context, 41);
            let fds = WaitFds::empty()
                .with_redispatch_and_watched_slots(&files, [40], [41])
                .expect("split epoll authority");
            let continuation = BlockedContinuation::from_dispatch_outcome(
                DispatchOutcome::WaitOnFds {
                    fds,
                    timeout: None,
                    on_timeout: 0,
                    sig_mask: WaitSigMask::NONE,
                },
                capture(&context, generation, ContinuationBackend::Hvpatch),
            )
            .expect("epoll continuation");
            let scheduler = Arc::new(Scheduler::new(kernel));
            let service = CarrierWaitService::new(scheduler);
            let mut registration = service.prepare_registration(&continuation);
            service
                .enroll(&mut registration)
                .expect("enroll epoll wait");
            let replacement = if replace_epfd { epfd } else { watched };
            let number =
                crate::kernel::FileSlotNumber::for_open_fd(if replace_epfd { 40 } else { 41 })
                    .expect("replacement slot");
            let ids = crate::kernel::ObjectIdRegistry::new();
            files.install(
                number,
                Arc::new(crate::kernel::FileDescription::regular(
                    ids.file_description_id().expect("successor description"),
                )),
                false,
            );
            let event = await_event(&service, registration.wake_token())
                .expect("slot generation publication");
            assert_eq!(event, ContinuationEvent::Ready);
            assert!(!files.validate_slot_authority(replacement));
            continuation.resume(event, &context)
        };

        let watched = run_case(15_461, false).expect("watched change recomputes epoll");
        assert_eq!(watched.completion, ContinuationCompletion::Redispatch);
        assert_eq!(
            run_case(15_462, true),
            Err(ContinuationResumeError::StaleFileSlot),
            "strict epfd reuse is EBADF authority failure"
        );
    }

    #[test]
    fn hvpatch_fd_wait_without_explicit_slot_authority_fails_closed() {
        let (_kernel, context) = bootstrap(15_227);
        let generation = publish(&context, 0x554);
        let _fallback_would_have_matched = install_test_fd_authority(&context, 0);
        let fds = pipe_pair();
        let result = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::raw_one(fds[0], libc::POLLIN),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        );
        assert!(matches!(result, Err(ContinuationBuildError::FdPinFailed)));
        close_pair(fds);
    }

    #[test]
    fn shared_wait_service_is_bounded_and_blocked_tasks_own_no_executor() {
        let mut fixture = race_fixture(15_230);
        let topology = fixture.service.topology();
        assert_eq!(topology.service_threads(), 1);
        assert_eq!(topology.shared_reactors(), 1);
        assert_eq!(topology.record_lock_workers(), 0);
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
    fn cancelled_contended_record_locks_do_not_consume_shared_worker_capacity() {
        let (kernel, context) = bootstrap(15_231);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let service = CarrierWaitService::new(scheduler);
        assert_eq!(service.topology().record_lock_workers(), 0);
        let generation = publish(&context, 0x553);
        let contention = crate::dispatch::RecordLockContentionFixture::new();

        for serial in [2, 3] {
            let mut continuation = BlockedContinuation::from_dispatch_outcome(
                DispatchOutcome::BlockingRecordLock(
                    contention.waiter(ThreadId::synthetic_for_tests(15_231), serial),
                ),
                capture(&context, generation, ContinuationBackend::Hvpatch),
            )
            .expect("contended record-lock continuation");
            let mut registration = service.prepare_registration(&continuation);
            service
                .enroll(&mut registration)
                .expect("enroll contention");
            continuation
                .attach_registration(registration)
                .expect("attach contention");
            let receipt = continuation.cancel(CancellationCause::ThreadExit);
            assert_eq!(receipt.cleanup_count(), 1);
        }

        let mut successful = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::BlockingRecordLock(
                contention.waiter(ThreadId::synthetic_for_tests(15_231), 4),
            ),
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("third record-lock continuation");
        let mut registration = service.prepare_registration(&successful);
        service
            .enroll(&mut registration)
            .expect("enroll third lock");
        let token = registration.wake_token();
        successful
            .attach_registration(registration)
            .expect("attach third lock");
        contention.release_blocker();
        service.nudge_reactor_for_test();
        assert_eq!(
            await_event(&service, token).expect("third lock completes"),
            ContinuationEvent::Ready
        );
        assert_eq!(
            successful
                .resume(ContinuationEvent::Ready, &context)
                .expect("third lock resume")
                .completion,
            ContinuationCompletion::Return(0)
        );
    }

    #[test]
    fn shared_reactor_observes_real_fd_and_timer_readiness_without_private_waiters() {
        let (kernel, context) = bootstrap(15_231);
        let generation = publish(&context, 0x552);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let service = CarrierWaitService::new(Arc::clone(&scheduler));
        let authority = install_test_fd_authority(&context, 0);
        let fds = pipe_pair();
        let fd_continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::raw(vec![(fds[0], libc::POLLIN)])
                    .with_slot_authorities(vec![authority]),
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
            await_event(&service, fd_token).expect("fd event"),
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
            await_event(&service, timer_registration.wake_token()).expect("timer event"),
            ContinuationEvent::Timeout
        );
        assert_eq!(service.topology().service_threads(), 1);
        assert_eq!(service.topology().shared_reactors(), 1);
        assert_eq!(service.topology().record_lock_workers(), 0);
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
            await_event(&service, registration.wake_token())
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
                generation: carrick_thread::platform_futex::carrier_shared_futex_table()
                    .prepare_wait(0xbeef),
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
        carrick_thread::platform_futex::carrier_shared_futex_table().wake(0xbeef, 1);
        assert_eq!(
            await_event(&service, registration.wake_token()).expect("shared word durable recheck"),
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
            await_event(&service, registration.wake_token()).expect("write completion"),
            ContinuationEvent::Ready
        );
        continuation
            .attach_registration(registration)
            .expect("attach write registration");
        let completion = continuation
            .resume(ContinuationEvent::Ready, &context)
            .expect("resume write")
            .completion;
        assert!(matches!(
            completion,
            ContinuationCompletion::BlockingWrite {
                outcome: BlockingWriteOutcome::Return(4),
                ..
            }
        ));
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
            await_event(&service, registration.wake_token()).expect("record terminal result"),
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
        context.signal_authority().enqueue_thread_standard(
            crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1"),
            None,
        );
        context.task().wake();
        assert_eq!(
            await_event(&service, registration.wake_token()).expect("task signal source"),
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
        let mut vfork = BlockedContinuation::from_vfork_parent(
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
            await_event(&service, registration.wake_token()).expect("vfork release source"),
            ContinuationEvent::Ready
        );
        let fresh = context
            .task_binding()
            .capture(context.thread().key().tid)
            .expect("parent context after child exit");
        assert_ne!(fresh.revision(), context.revision());
        vfork
            .attach_registration(registration)
            .expect("attach released vfork registration");
        assert_eq!(
            vfork
                .resume(ContinuationEvent::Ready, &fresh)
                .expect("revision advance from child exit is legitimate")
                .completion,
            ContinuationCompletion::Return(i64::from(child.task().key().id.raw()))
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
            let barrier = Arc::new(Barrier::new(4));
            let publish_service = Arc::clone(&fixture.service);
            let publish_barrier = Arc::clone(&barrier);
            let publish = thread::spawn(move || {
                publish_barrier.wait();
                publish_service.publish_ready(token)
            });
            let timeout_service = Arc::clone(&fixture.service);
            let timeout_barrier = Arc::clone(&barrier);
            let timeout = thread::spawn(move || {
                timeout_barrier.wait();
                timeout_service
                    .inner
                    .publish_event(token, ContinuationEvent::Timeout)
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
            let timed_out = timeout.join().expect("timeout publisher");
            let cancelled = cancel.join().expect("canceller");
            assert_eq!(
                usize::from(ready.accepted())
                    + usize::from(timed_out.accepted())
                    + usize::from(cancelled.is_ok()),
                1,
                "readiness, timeout, and cancellation must have exactly one terminal winner"
            );
            if ready.accepted() || timed_out.accepted() {
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
    fn same_task_same_mm_revision_drift_reauthorizes_variant_resources() {
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
        assert!(
            continuation
                .resume(ContinuationEvent::Ready, &fresh)
                .is_ok()
        );
    }

    #[test]
    fn signal_restart_is_derived_from_captured_kernel_action_not_event_input() {
        let (_kernel, context) = bootstrap(15_369);
        let generation = publish(&context, 0x703);
        let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let persistent = SigSet::EMPTY.with(10);
        context.signal_authority().set_blocked(persistent);
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
                sig_mask: WaitSigMask::Replace(SigSet::EMPTY),
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("restartable continuation");
        continuation.install_temporary_signal_mask(&context);
        let result = continuation
            .resume(ContinuationEvent::Signal, &context)
            .expect("signal completion");
        assert_eq!(result.restart(), RestartDecision::Restart);
        assert_eq!(
            result.completion,
            ContinuationCompletion::Errno(LINUX_EINTR)
        );
        assert_eq!(context.signal_authority().blocked(), SigSet::EMPTY);
        assert_eq!(
            context.signal_authority().armed_restore_mask(),
            Some(persistent)
        );
    }

    #[test]
    fn reserved_signal_keeps_exact_action_when_opposite_restart_signal_arrives_before_resume() {
        let (_kernel, context) = bootstrap(15_369_2);
        let generation = publish(&context, 0x707);
        let first = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let second = crate::kernel::LinuxSignal::for_signal_number(12).expect("SIGUSR2");
        let mut restart = carrick_abi::LinuxSigaction::empty();
        restart.sa_handler = 0x1110;
        restart.sa_flags = carrick_abi::LINUX_SA_RESTART;
        let mut no_restart = carrick_abi::LinuxSigaction::empty();
        no_restart.sa_handler = 0x2220;
        context.signal_authority().install_action(first, restart);
        context
            .signal_authority()
            .install_action(second, no_restart);
        context
            .signal_authority()
            .enqueue_thread_standard(first, None);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("continuation");
        let event = SignalReadinessProbe::from_continuation(&continuation)
            .event()
            .expect("first signal readiness");
        assert_eq!(
            event.reserved_signal().expect("exact reservation").signum(),
            10
        );

        context
            .signal_authority()
            .enqueue_thread_standard(second, None);
        let result = continuation.resume(event, &context).expect("resume");
        assert_eq!(result.restart(), RestartDecision::Restart);
        let reserved = result.reserved_signal().expect("reserved delivery");
        assert_eq!(reserved.signum(), 10);
        assert_eq!(reserved.action(), restart);
        assert_ne!(reserved.action(), no_restart);
    }

    #[test]
    fn host_slot_signal_is_reserved_under_replace_mask_and_requeued_if_abandoned() {
        let (_kernel, context) = bootstrap(15_369_3);
        let generation = publish(&context, 0x708);
        let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let persistent = SigSet::EMPTY.with(10);
        context.signal_authority().set_blocked(persistent);
        let mut action = carrick_abi::LinuxSigaction::empty();
        action.sa_handler = 0x3330;
        context.signal_authority().install_action(signal, action);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::Replace(SigSet::EMPTY),
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("continuation");
        let tid = context.thread().key().tid.raw();
        crate::host_signal::publish_pending_for(tid, 10);
        let event = SignalReadinessProbe::from_continuation(&continuation)
            .event()
            .expect("host-slot readiness reservation");
        assert_eq!(event.reserved_signal().expect("reservation").signum(), 10);
        drop(event);
        assert_eq!(
            crate::host_signal::take_pending_for(tid),
            10,
            "abandoned exact reservation returns to its host slot"
        );
    }

    #[test]
    fn ignored_lower_signal_does_not_hide_next_exact_deliverable_reservation() {
        let (_kernel, context) = bootstrap(15_369_4);
        let generation = publish(&context, 0x709);
        let ignored = crate::kernel::LinuxSignal::for_signal_number(17).expect("SIGCHLD");
        let caught = crate::kernel::LinuxSignal::for_signal_number(18).expect("signal 18");
        let mut ignore_action = carrick_abi::LinuxSigaction::empty();
        ignore_action.sa_handler = carrick_abi::LINUX_SIG_IGN;
        let mut caught_action = carrick_abi::LinuxSigaction::empty();
        caught_action.sa_handler = 0x4440;
        let authority = context.signal_authority();
        authority.install_action(ignored, ignore_action);
        authority.install_action(caught, caught_action);
        authority.enqueue_thread_standard(ignored, None);
        authority.enqueue_thread_standard(caught, None);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("continuation");
        let event = SignalReadinessProbe::from_continuation(&continuation)
            .event()
            .expect("caught signal behind ignored SIGCHLD");
        assert_eq!(event.reserved_signal().expect("reservation").signum(), 18);
    }

    #[test]
    fn kernel_signal_reservation_is_atomic_across_two_waiters_and_two_instances() {
        let (_kernel, context) = bootstrap(15_369_5);
        let authority = context.signal_authority();
        for signum in [10, 12] {
            let signal = crate::kernel::LinuxSignal::for_signal_number(signum).expect("signal");
            let mut action = carrick_abi::LinuxSigaction::empty();
            action.sa_handler = 0x5000 + signum as u64;
            authority.install_action(signal, action);
            authority.enqueue_thread_standard(signal, None);
        }
        let barrier = Arc::new(Barrier::new(3));
        let mut waiters = Vec::new();
        for _ in 0..2 {
            let authority = authority.clone();
            let barrier = Arc::clone(&barrier);
            waiters.push(thread::spawn(move || {
                barrier.wait();
                authority
                    .reserve_deliverable_for_wait(WaitSigMask::NONE)
                    .expect("one exact reservation")
            }));
        }
        barrier.wait();
        let mut reserved = waiters
            .into_iter()
            .map(|waiter| waiter.join().expect("reservation waiter"))
            .collect::<Vec<_>>();
        reserved.sort_unstable_by_key(|reservation| reservation.signum());
        assert_eq!(
            reserved
                .iter()
                .map(|reservation| reservation.signum())
                .collect::<Vec<_>>(),
            vec![10, 12]
        );
        for reservation in reserved {
            let delivery = ReservedSignal::from_kernel_reservation(authority.clone(), reservation);
            assert!(delivery.consume(), "exact signal delivers once");
            assert!(!delivery.consume(), "duplicate delivery is rejected");
        }
        assert!(authority.thread_pending().is_empty());
    }

    #[test]
    fn kernel_signal_reservation_linearizes_disposition_and_mask_changes() {
        for (pid, initial_handler, replacement_handler) in [
            (15_369_6, 0x6000, carrick_abi::LINUX_SIG_IGN),
            (15_369_7, carrick_abi::LINUX_SIG_IGN, 0x7000),
        ] {
            let (_kernel, context) = bootstrap(pid);
            let authority = context.signal_authority();
            let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
            let mut initial = carrick_abi::LinuxSigaction::empty();
            initial.sa_handler = initial_handler;
            authority.install_action(signal, initial);
            authority.enqueue_thread_standard(signal, None);
            let barrier = Arc::new(Barrier::new(3));
            let reserve_authority = authority.clone();
            let reserve_barrier = Arc::clone(&barrier);
            let reserver = thread::spawn(move || {
                reserve_barrier.wait();
                reserve_authority.reserve_deliverable_for_wait(WaitSigMask::NONE)
            });
            let action_authority = authority.clone();
            let action_barrier = Arc::clone(&barrier);
            let changer = thread::spawn(move || {
                action_barrier.wait();
                let mut replacement = carrick_abi::LinuxSigaction::empty();
                replacement.sa_handler = replacement_handler;
                action_authority.install_action(signal, replacement);
            });
            barrier.wait();
            changer.join().expect("action changer");
            if let Some(reservation) = reserver.join().expect("reserver") {
                let handler = reservation.action().sa_handler;
                assert_ne!(handler, carrick_abi::LINUX_SIG_IGN);
                assert!(handler == initial_handler || handler == replacement_handler);
            }
            assert!(
                authority.thread_pending().is_empty(),
                "the transaction either reserves the caught instance or discards the ignored instance"
            );
        }

        let (_kernel, context) = bootstrap(15_369_8);
        let authority = context.signal_authority();
        let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let mut action = carrick_abi::LinuxSigaction::empty();
        action.sa_handler = 0x8000;
        authority.install_action(signal, action);
        authority.enqueue_thread_standard(signal, None);
        let barrier = Arc::new(Barrier::new(3));
        let reserve_authority = authority.clone();
        let reserve_barrier = Arc::clone(&barrier);
        let reserver = thread::spawn(move || {
            reserve_barrier.wait();
            reserve_authority.reserve_deliverable_for_wait(WaitSigMask::NONE)
        });
        let mask_authority = authority.clone();
        let mask_barrier = Arc::clone(&barrier);
        let masker = thread::spawn(move || {
            mask_barrier.wait();
            mask_authority.set_blocked(SigSet::EMPTY.with(10));
        });
        barrier.wait();
        masker.join().expect("mask changer");
        match reserver.join().expect("mask reserver") {
            Some(reservation) => {
                assert!(!reservation.effective_mask().contains(10));
                assert!(authority.thread_pending().is_empty());
            }
            None => {
                assert!(authority.thread_pending().contains(10));
                assert!(authority.blocked().contains(10));
            }
        }
    }

    #[test]
    fn partial_blocking_write_never_restarts_after_caught_sa_restart_signal() {
        let (_kernel, context) = bootstrap(15_369_1);
        let generation = publish(&context, 0x706);
        let signal = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let mut action = carrick_abi::LinuxSigaction::empty();
        action.sa_handler = 0x1234;
        action.sa_flags = carrick_abi::LINUX_SA_RESTART;
        context.signal_authority().install_action(signal, action);
        context
            .signal_authority()
            .enqueue_thread_standard(signal, None);
        let fds = pipe_pair();
        let write = BlockingHostWrite::for_tests(
            fds[1],
            vec![1, 2, 3, 4],
            2,
            ThreadId::synthetic_for_tests(15_369_1),
            false,
        )
        .expect("partial blocking write");
        close_pair(fds);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::BlockingHostWrite(write),
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("partial write continuation");
        let result = continuation
            .resume(ContinuationEvent::Signal, &context)
            .expect("partial signal result");
        assert_eq!(result.restart(), RestartDecision::NoRestart);
        assert_eq!(result.completion, ContinuationCompletion::Return(2));
    }

    #[test]
    fn signal_readiness_honors_replace_additive_ignore_and_live_restart_action() {
        let (kernel, context) = bootstrap(15_370);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let service = CarrierWaitService::new(scheduler);
        let usr1 = crate::kernel::LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let usr1_set = SigSet::from_raw(1 << 9);
        context.signal_authority().set_blocked(usr1_set);
        let generation = publish(&context, 0x704);

        let replacement = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::Replace(SigSet::EMPTY),
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("replacement-mask continuation");
        let mut replacement_registration = service.prepare_registration(&replacement);
        service
            .enroll(&mut replacement_registration)
            .expect("enroll replacement mask");
        context
            .signal_authority()
            .enqueue_thread_standard(usr1, None);
        context.task().wake();
        let event = await_event(&service, replacement_registration.wake_token())
            .expect("replacement mask unblocks SIGUSR1");
        assert_eq!(
            event.reserved_signal().expect("reserved SIGUSR1").signum(),
            10
        );
        let result = replacement
            .resume(event, &context)
            .expect("replacement resume");
        assert_eq!(result.restart(), RestartDecision::NoRestart);
        assert_eq!(context.signal_authority().blocked(), usr1_set);

        let (kernel, context) = bootstrap(15_371);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let service = CarrierWaitService::new(scheduler);
        let generation = publish(&context, 0x705);
        let additive = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::Additive(usr1_set),
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("additive-mask continuation");
        let mut additive_registration = service.prepare_registration(&additive);
        service
            .enroll(&mut additive_registration)
            .expect("enroll additive mask");
        context
            .signal_authority()
            .enqueue_thread_standard(usr1, None);
        context.task().wake();
        assert_eq!(
            service
                .inner
                .state
                .lock()
                .entries
                .get(&additive_registration.wake_token().continuation())
                .expect("additive registration")
                .state,
            RegistrationState::Enrolled
        );

        let chld = crate::kernel::LinuxSignal::for_signal_number(17).expect("SIGCHLD");
        let mut ignored = carrick_abi::LinuxSigaction::empty();
        ignored.sa_handler = carrick_abi::LINUX_SIG_IGN;
        context.signal_authority().install_action(chld, ignored);
        context
            .signal_authority()
            .enqueue_thread_standard(chld, None);
        context.task().wake();
        assert_eq!(
            service
                .inner
                .state
                .lock()
                .entries
                .get(&additive_registration.wake_token().continuation())
                .expect("ignored-signal registration")
                .state,
            RegistrationState::Enrolled
        );
        service
            .cancel_registration(additive_registration)
            .expect("cancel masked wait");
    }

    struct ManualGate {
        open: std::sync::atomic::AtomicBool,
        polled: Arc<AtomicUsize>,
        waker: parking_lot::Mutex<Option<Waker>>,
    }

    impl ManualGate {
        fn new(polled: Arc<AtomicUsize>) -> Arc<Self> {
            Arc::new(Self {
                open: std::sync::atomic::AtomicBool::new(false),
                polled,
                waker: parking_lot::Mutex::new(None),
            })
        }

        fn open(&self) {
            self.open.store(true, Ordering::Release);
            if let Some(waker) = self.waker.lock().take() {
                waker.wake();
            }
        }
    }

    impl Future for &ManualGate {
        type Output = ();

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
            if self.open.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            self.polled.fetch_add(1, Ordering::SeqCst);
            *self.waker.lock() = Some(context.waker().clone());
            Poll::Pending
        }
    }

    #[test]
    fn bounded_transitional_runner_releases_submitter_threads_across_256_blocked_jobs() {
        const JOBS: usize = 256;
        let runner = TransitionalDedicatedRunner::with_worker_limit(2).expect("runner");
        let polled = Arc::new(AtomicUsize::new(0));
        let gates = (0..JOBS)
            .map(|_| ManualGate::new(Arc::clone(&polled)))
            .collect::<Vec<_>>();
        let mut submitters = Vec::with_capacity(JOBS);
        for gate in &gates {
            let runner = runner.clone();
            let gate = Arc::clone(gate);
            submitters.push(thread::spawn(move || {
                let submitter = thread::current().id();
                let receipt = runner.spawn(async move {
                    gate.as_ref().await;
                    thread::current().id()
                });
                (submitter, receipt)
            }));
        }
        let submitted = submitters
            .into_iter()
            .map(|thread| thread.join().expect("submitter exits"))
            .collect::<Vec<_>>();
        while polled.load(Ordering::Acquire) < JOBS {
            thread::yield_now();
        }
        for gate in &gates {
            gate.open();
        }
        let mut workers = std::collections::HashSet::new();
        for (submitter, receipt) in submitted {
            let worker = receipt.wait().expect("logical job completion");
            assert_ne!(worker, submitter, "original task pthread must have exited");
            workers.insert(worker);
        }
        assert!(workers.len() <= 2);
        assert_eq!(runner.topology().worker_threads(), 2);
        assert_eq!(runner.topology().task_waiter_threads(), 0);
    }

    #[test]
    fn slot_starved_job_yields_the_only_runner_worker_until_exact_release() {
        let admission: &'static carrick_hal::vcpu_sched::HostCondvarScheduler = Box::leak(
            Box::new(carrick_hal::vcpu_sched::HostCondvarScheduler::new(1)),
        );
        let held = carrick_hal::VcpuScheduler::acquire(admission, 1);
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        let a = runner.spawn(async move {
            let lease = await_vcpu_admission(admission, 2, Some(held.slot)).await;
            carrick_hal::VcpuScheduler::release(admission, lease, carrick_hal::Yield::Exited);
            2usize
        });
        let b = runner.spawn(async { 1usize });

        assert_eq!(
            b.wait().expect("runnable job B"),
            1,
            "slot-starved A must not occupy the sole runner worker"
        );
        assert!(
            !a.is_finished(),
            "A remains suspended until its exact admission grant"
        );
        carrick_hal::VcpuScheduler::release(admission, held, carrick_hal::Yield::Blocked);
        assert_eq!(a.wait().expect("released job A"), 2);
    }

    #[test]
    fn rejected_initial_submission_drops_engine_guard_on_bootstrap_thread() {
        struct BootstrapProbe {
            cleanup: mpsc::Sender<std::thread::ThreadId>,
        }
        fn cleanup(probe: &mut BootstrapProbe) {
            probe
                .cleanup
                .send(std::thread::current().id())
                .expect("cleanup receipt");
        }
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("runner");
        runner.reject_next_submission_for_test();
        let bootstrap = std::thread::current().id();
        let (tx, rx) = mpsc::channel();
        let guarded =
            super::super::OwnerThreadEngine::for_test(BootstrapProbe { cleanup: tx }, cleanup);
        let result = runner.try_spawn(async move {
            drop(guarded);
        });
        assert!(matches!(result, Err(TransitionalRunnerError::TaskFailed)));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1))
                .expect("same-thread cleanup"),
            bootstrap
        );
    }

    #[test]
    fn failed_initial_submission_retires_exact_runnable_without_queue_row() {
        let (kernel, context) = bootstrap(15_460);
        let scheduler = Scheduler::new(kernel);
        let generation = publish(&context, 0x900);
        assert_eq!(scheduler.queued_len(), 0);
        context
            .thread()
            .fail_runnable_generation(
                generation,
                crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
            )
            .expect("exact bootstrap failure");
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed {
                generation: failed,
                reason: crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
            } if failed == generation
        ));
        assert_eq!(scheduler.queued_len(), 0);
    }

    #[test]
    fn indefinite_registration_has_no_synthetic_timeout_or_periodic_probe_deadline() {
        let (kernel, context) = bootstrap(15_370);
        let generation = publish(&context, 0x704);
        let continuation = BlockedContinuation::from_dispatch_outcome(
            DispatchOutcome::WaitOnFds {
                fds: WaitFds::empty(),
                timeout: None,
                on_timeout: 0,
                sig_mask: WaitSigMask::NONE,
            },
            capture(&context, generation, ContinuationBackend::Hvpatch),
        )
        .expect("indefinite continuation");
        let scheduler = Arc::new(Scheduler::new(kernel));
        let service = CarrierWaitService::new(scheduler);
        let mut registration = service.prepare_registration(&continuation);
        service
            .enroll(&mut registration)
            .expect("enroll indefinite");
        assert_eq!(continuation.deadline(), None);
        let state = service
            .registration_timing(registration.wake_token())
            .expect("registration timing");
        assert_eq!(state.deadline(), None);
        assert!(!state.has_periodic_probe());
    }

    #[test]
    fn idle_256_indefinite_waits_use_one_blocking_poll_without_probe_storm() {
        let (kernel, context) = bootstrap(15_371);
        let generation = publish(&context, 0x705);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let service = CarrierWaitService::new(scheduler);
        let mut owned = Vec::new();
        for _ in 0..256 {
            let continuation = BlockedContinuation::from_dispatch_outcome(
                DispatchOutcome::WaitOnFds {
                    fds: WaitFds::empty(),
                    timeout: None,
                    on_timeout: 0,
                    sig_mask: WaitSigMask::NONE,
                },
                capture(&context, generation, ContinuationBackend::Hvpatch),
            )
            .expect("indefinite continuation");
            let mut registration = service.prepare_registration(&continuation);
            service.enroll(&mut registration).expect("enroll");
            owned.push((continuation, registration));
        }
        let before = service.reactor_poll_calls();
        let observed = service.observe_next_reactor_poll();
        service.nudge_reactor_for_test();
        observed.wait();
        let after = service.reactor_poll_calls();
        assert!(
            after > before,
            "blocking reactor did not observe its control nudge"
        );
        for _ in 0..1024 {
            thread::yield_now();
        }
        assert!(service.reactor_poll_calls() <= after + 1);
        assert_eq!(service.topology().shared_reactors(), 1);
        assert_eq!(service.topology().task_waiter_threads(), 0);
        drop(owned);
    }

    #[test]
    fn quiesce_raise_defers_ready_job_until_release_without_occupying_shared_worker() {
        let fixture = race_fixture(15_372);
        let barrier = Arc::new(carrick_thread::fork_quiesce::QuiesceBarrier::new());
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        let service = Arc::clone(&fixture.service);
        let token = fixture.registration.wake_token();
        barrier.set_quiescing();
        let wait_barrier = Arc::clone(&barrier);
        let blocked = runner.spawn(async move {
            service
                .event_outside_quiesce(token, Some(wait_barrier))
                .await
        });
        fixture.service.publish_ready(token).assert_accepted();
        for _ in 0..128 {
            thread::yield_now();
        }
        assert!(
            !blocked.is_finished(),
            "ready task cannot claim during quiesce"
        );
        assert_eq!(
            runner
                .spawn(async { 7_u8 })
                .wait()
                .expect("worker remains free"),
            7
        );
        barrier.end_quiesce();
        assert_eq!(
            blocked
                .wait()
                .expect("logical task receipt")
                .expect("readiness after release"),
            ContinuationEvent::Ready
        );
    }

    #[test]
    fn wait_service_drop_finalizes_pending_job_with_typed_cancellation() {
        let fixture = race_fixture(15_373);
        let token = fixture.registration.wake_token();
        let future = fixture.service.event(token);
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        let receipt = runner.spawn(future);
        drop(fixture.registration);
        drop(fixture.service);
        assert_eq!(
            receipt.wait().expect("logical receipt"),
            Err(WaitServiceError::Cancelled(
                CancellationCause::ServiceShutdown
            ))
        );
    }

    #[test]
    fn one_worker_process_drain_excludes_current_job_and_yields_for_siblings() {
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        let gate = ManualGate::new(Arc::new(AtomicUsize::new(0)));
        let jobs = Arc::new(Mutex::new(Vec::new()));
        let owner_jobs = Arc::clone(&jobs);
        let owner_runner = runner.clone();
        let owner_gate = Arc::clone(&gate);
        let (done_tx, done_rx) = mpsc::channel();
        let owner = runner.spawn(async move {
            owner_gate.as_ref().await;
            let current = TransitionalDedicatedRunner::current_job()
                .expect("runner poll publishes exact current JobId");
            let mut sibling_receipts = Vec::new();
            for value in [11_u8, 22, 33] {
                let receipt = owner_runner.spawn(async move { value });
                owner_jobs.lock().push(receipt.completion());
                sibling_receipts.push(receipt);
            }
            let completions = std::mem::take(&mut *owner_jobs.lock());
            ProcessDrain::excluding(current, completions).await;
            let values = sibling_receipts
                .into_iter()
                .map(|receipt| receipt.wait().expect("completed sibling receipt"))
                .collect::<Vec<_>>();
            done_tx.send(values).expect("publish drain completion");
        });
        jobs.lock().push(owner.completion());
        drop(owner);
        gate.open();
        assert_eq!(
            done_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("exit owner must yield the sole worker, not synchronously join"),
            vec![11, 22, 33]
        );
    }

    #[test]
    fn dirty_transitional_worker_fails_exact_job_and_replacement_is_clean() {
        struct DirtyEngineProbe {
            cleanup_tx: mpsc::Sender<std::thread::ThreadId>,
        }
        fn cleanup(probe: &mut DirtyEngineProbe) {
            probe
                .cleanup_tx
                .send(std::thread::current().id())
                .expect("dirty cleanup receipt");
        }
        struct DirtyBoundary {
            _engine: super::super::OwnerThreadEngine<DirtyEngineProbe>,
        }
        impl Future for DirtyBoundary {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
                let dirty = crate::dispatch::lock_order::LockOrderGuard::acquire(
                    crate::dispatch::lock_order::LockLevel::Proc,
                );
                std::mem::forget(dirty);
                Poll::Pending
            }
        }

        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        let (cleanup_tx, cleanup_rx) = mpsc::channel();
        assert_eq!(
            runner
                .spawn(DirtyBoundary {
                    _engine: super::super::OwnerThreadEngine::for_test(
                        DirtyEngineProbe { cleanup_tx },
                        cleanup,
                    ),
                })
                .wait(),
            Err(TransitionalRunnerError::TaskFailed)
        );
        let dirty_worker = cleanup_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("dirty task cleanup");
        let (value, clean_worker) = runner
            .spawn(async { (73_u8, std::thread::current().id()) })
            .wait()
            .expect("clean replacement");
        assert_eq!(value, 73);
        assert_ne!(dirty_worker, clean_worker);
        assert_eq!(runner.topology().worker_threads(), 1);
    }

    #[test]
    fn one_worker_two_real_runner_jobs_both_advance_at_quantum_boundaries() {
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        let progress = Arc::new(Mutex::new(Vec::new()));
        let spawn_job = |id: u8| {
            let progress = Arc::clone(&progress);
            runner.spawn(async move {
                for quantum in 0..8_u8 {
                    progress.lock().push((id, quantum));
                    yield_runner_quantum().await;
                }
                id
            })
        };
        let first = spawn_job(1);
        let second = spawn_job(2);
        assert_eq!(first.wait().expect("first compute job"), 1);
        assert_eq!(second.wait().expect("second compute job"), 2);
        let progress = progress.lock();
        assert_eq!(progress.iter().filter(|(id, _)| *id == 1).count(), 8);
        assert_eq!(progress.iter().filter(|(id, _)| *id == 2).count(), 8);
        let first_second = progress
            .iter()
            .position(|(id, _)| *id == 2)
            .expect("second job advances");
        assert!(
            first_second < 8,
            "one job must not monopolize the only worker"
        );
    }

    #[test]
    fn executor_identity_is_owned_by_worker_not_logical_job() {
        let (kernel, _context) = bootstrap(15_453);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        runner.attach_scheduler(Arc::clone(&scheduler));
        let first = runner
            .spawn(async {
                TransitionalDedicatedRunner::current_executor_id()
                    .expect("worker executor while polling")
            })
            .wait()
            .expect("first job");
        let second = runner
            .spawn(async {
                TransitionalDedicatedRunner::current_executor_id()
                    .expect("same worker executor while polling")
            })
            .wait()
            .expect("second job");
        assert_eq!(first, second);
        assert_eq!(scheduler.registered_executor_count(), 1);
    }

    #[test]
    fn worker_exact_wake_uses_live_hardware_kick_and_unbinds_before_successor() {
        #[derive(Clone)]
        struct CountingKick(Arc<AtomicUsize>);
        impl carrick_hal::VcpuKickDyn for CountingKick {
            fn kick(&self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (kernel, context) = bootstrap(15_454);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let generation = publish(&context, 0x707);
        enqueue_root(&scheduler, &context, generation);
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        runner.attach_scheduler(Arc::clone(&scheduler));
        let kicks = Arc::new(AtomicUsize::new(0));
        let task_kicks = Arc::clone(&kicks);
        let task_scheduler = Arc::clone(&scheduler);
        let thread = Arc::clone(context.thread());
        runner
            .spawn(async move {
                let executor = TransitionalDedicatedRunner::current_executor_registration()
                    .expect("worker registration");
                let running = task_scheduler.take(&executor).expect("claim exact task");
                assert!(TransitionalDedicatedRunner::publish_current_hardware_kick(
                    Box::new(CountingKick(task_kicks))
                ));
                task_scheduler
                    .wake(thread.key())
                    .expect("exact running wake");
                task_scheduler
                    .settle_runnable_successor(running)
                    .expect("unbind predecessor");
            })
            .wait()
            .expect("worker job");
        assert_eq!(kicks.load(Ordering::SeqCst), 1);
        assert!(
            scheduler
                .binding_for_thread(context.thread().key())
                .is_none()
        );
        scheduler
            .wake(context.thread().key())
            .expect("successor already runnable");
        assert_eq!(kicks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn live_task_panic_cleans_up_on_owner_worker_and_retires_it() {
        struct PanicEngineProbe {
            cleanup_tx: mpsc::Sender<std::thread::ThreadId>,
        }
        fn cleanup(probe: &mut PanicEngineProbe) {
            probe
                .cleanup_tx
                .send(std::thread::current().id())
                .expect("cleanup receipt");
        }
        let runner = TransitionalDedicatedRunner::with_worker_limit(1).expect("one worker");
        let (cleanup_tx, cleanup_rx) = mpsc::channel();
        let panic_receipt = runner.spawn(async move {
            let _engine =
                super::super::OwnerThreadEngine::for_test(PanicEngineProbe { cleanup_tx }, cleanup);
            panic!("injected live engine panic");
        });
        assert_eq!(
            panic_receipt.wait(),
            Err(TransitionalRunnerError::TaskFailed)
        );
        let cleanup_thread = cleanup_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("owner cleanup ran");
        let successor_thread = runner
            .spawn(async { std::thread::current().id() })
            .wait()
            .expect("replacement worker");
        assert_ne!(cleanup_thread, successor_thread);
    }

    #[test]
    fn static_hvpatch_continuation_closure_forbids_host_blocking_authority() {
        let continuation_source = include_str!("continuation.rs")
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
            "wait_for_event",
            "Duration::from_millis(2)",
            "Duration::from_secs(24 * 60 * 60)",
        ] {
            assert!(
                !continuation_source.contains(prohibited),
                "HVPatch continuation path retains prohibited host-blocking authority: {prohibited}"
            );
        }
        assert_eq!(DISPATCH_FAMILIES.len() + 1, 16);
        assert!(continuation_source.contains("run_task_quantum(&task)"));
        assert!(!continuation_source.contains("TaskQuantumSource"));
        assert!(!continuation_source.contains("fallback_fd"));
        for required in [
            "TransitionalWorkerContext::register",
            "publish_current_hardware_kick",
            "scheduler.request_preemption()",
            "drop(worker_context.take())",
        ] {
            assert!(
                continuation_source.contains(required),
                "worker-owned executor path misses {required}"
            );
        }

        let loop_source = include_str!("mod.rs");
        let suspend = loop_source
            .split("fn suspend_hvpatch_continuation")
            .nth(1)
            .and_then(|tail| tail.split("fn service_threaded_syscall").next())
            .expect("real HVPatch continuation adapter body");
        for required in [
            "ContinuationCapture::from_lease",
            "prepare_registration",
            ".enroll(",
            "recheck_registration",
            "save_shared_wait_state",
            "settle_transitional_blocked_continuation",
            "Yield::Blocked",
            "event_outside_quiesce(token, self.process_fork_barrier.clone())",
            "take_transitional_lease",
            "resume_continuation",
        ] {
            assert!(
                suspend.contains(required),
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
            "acquire_timeout",
        ] {
            assert!(
                !suspend.contains(prohibited),
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
        let run_loop = loop_source
            .split("pub(crate) async fn run_vcpu_until_exit")
            .nth(1)
            .expect("real vCPU loop");
        let conversion = run_loop
            .find("suspend_hvpatch_continuation")
            .expect("product continuation conversion");
        let terminal_match = run_loop
            .find("match outcome")
            .expect("post-continuation syscall completion");
        assert!(conversion < terminal_match);
        let launch = loop_source
            .split("pub(crate) fn launch_vcpu_until_exit")
            .nth(1)
            .and_then(|tail| tail.split("pub(crate) async fn run_vcpu_until_exit").next())
            .expect("bounded launch adapter");
        let bootstrap_guard = launch
            .find("OwnerThreadEngine::new(engine)")
            .expect("immediate bootstrap owner guard");
        let runner_lookup = launch
            .find("kernel.transitional_runner()")
            .expect("runner lookup");
        assert!(bootstrap_guard < runner_lookup);
        for required in [
            "runner.try_spawn(future)",
            "prepared.fail_exact()",
            "prepared.scheduler.wake",
            "prepared.disarm()",
            "gate.open()",
        ] {
            assert!(
                launch.contains(required),
                "bootstrap handoff misses {required}"
            );
        }
        assert!(
            !launch.contains("future.as_mut().poll"),
            "bootstrap pthread must never poll the guest execution future"
        );
        assert!(launch.contains("prepare_initial_runner_handoff"));
        let quiesce = include_str!("quiesce.rs");
        let hvpatch_fork = quiesce
            .split("fn handle_in_process_fork")
            .nth(1)
            .expect("HVPatch fork body");
        assert!(hvpatch_fork.contains("HvpatchBlockInput::Vfork"));
        assert!(!hvpatch_fork.contains("wait.wait_for_release"));

        let threads = include_str!("threads.rs");
        let exec_drain = threads
            .split("if continuation::TransitionalDedicatedRunner::current_job().is_some()")
            .nth(2)
            .and_then(|tail| tail.split("let deadline =").next())
            .expect("shared-runner exec drain branch");
        for required in [
            "engine.save_guest_state()",
            "begin_switch_out",
            "settle_transitional_runnable",
            "Yield::Blocked",
            "drop(self.guest_execution.take())",
            "audit_executor_boundary()",
            "await_hvpatch_sibling_jobs().await",
            "await_vcpu_admission",
            ".rebind_to_slot",
            "take_transitional_lease",
        ] {
            assert!(
                exec_drain.contains(required),
                "exec drain misses {required}"
            );
        }
        for prohibited in [
            "std::thread::sleep",
            "handle.join()",
            ".wait()",
            "vcpu_sched::global().acquire(",
            "acquire_timeout",
        ] {
            assert!(
                !exec_drain.contains(prohibited),
                "shared-runner exec drain synchronously blocks on {prohibited}"
            );
        }

        let record_reactor = continuation_source
            .split("ReadinessProbe::RecordLock")
            .nth(2)
            .and_then(|tail| tail.split("impl Drop for CarrierWaitServiceInner").next())
            .expect("shared record-lock reactor path");
        assert!(record_reactor.contains("try_drive_blocking_record_lock"));
        for prohibited in [
            "crate::dispatch::drive_blocking_record_lock(",
            "F_SETLKW",
            "Condvar",
        ] {
            assert!(
                !record_reactor.contains(prohibited),
                "record-lock reactor retains blocking authority {prohibited}"
            );
        }

        let signal_source = include_str!("signal.rs");
        assert!(signal_source.contains("deliver_pending_signal_with_restart"));
        assert!(loop_source.contains("continuation.install_temporary_signal_mask(context)"));
        assert!(loop_source.contains("self.continuation_restart = Some(result.restart())"));
        assert!(loop_source.contains("ContinuationResumeError::StaleFileSlot"));
        assert!(loop_source.contains("OwnerThreadEngine::new(engine)"));
        assert!(loop_source.contains("engine.disarm()"));
        assert!(!loop_source.contains("TransitionalSchedulerKick"));
        assert!(!loop_source.contains("continuation_executor"));

        let net_source = include_str!("../dispatch/net.rs");
        assert!(
            net_source.matches("with_guest_slots(&files").count() >= 2,
            "pselect/ppoll must capture every exact guest fd slot at dispatch"
        );
        let io_uring_source = include_str!("../dispatch/ioring.rs");
        assert!(io_uring_source.contains("with_guest_slots(&files, [ring_fd, sqe.fd])"));
        let proc_source = include_str!("../dispatch/proc.rs");
        assert!(proc_source.contains("with_guest_slots(&files, [id as i32])"));
        let fs_source = include_str!("../dispatch/fs.rs");
        assert!(!fs_source.contains("WaitFdAuthority::Missing"));
        for required in [
            "captured_slot_authority(guest_fd)",
            "captured_slot_authority(fd)",
            "captured_slot_authority(fd.0)",
            "WaitFdAuthority::logical",
            "[in_fd.0, out_fd.0]",
            "complete_wait_fd_authority",
        ] {
            assert!(
                fs_source.contains(required),
                "fd producer misses {required}"
            );
        }
    }
}
