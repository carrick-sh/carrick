//! Owned, generation-authenticated blocking syscall continuations.
//!
//! The Kernel owns a [`BlockedContinuation`] while its logical thread is
//! blocked.  [`CarrierWaitService`] owns only an exact registration referring
//! to that Kernel identity; callbacks publish durable readiness and ask the
//! scheduler to wake the exact thread, but never run guest code.

use std::future::Future;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use carrick_abi::{SigBlockMask, SigSet, WaitSigMask};
use carrick_fatal::carrick_fatal;
use carrick_guest_mem::{GuestVa, SharedFutexLocation};
use parking_lot::Mutex;

use crate::dispatch::{
    BlockingHostWrite, BlockingRecordLock, DispatchOutcome, FdWaitCompletion, SyscallRequest,
    WaitFdAuthority, WaitFds,
};
use crate::kernel::objects::{ExecutionGeneration, ThreadKey};
use crate::kernel::{Kernel, KernelContext, MmId, Task, TaskKey, TaskRevision, VforkParentWait};
use crate::linux_abi::{LINUX_EAGAIN, LINUX_EINTR, LINUX_ETIMEDOUT, LinuxErrno};
use crate::thread::{FutexTable, FutexWait};

static NEXT_CONTINUATION_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_RESOURCE_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub(in crate::vcpu_loop) struct FutexSource(pub(in crate::vcpu_loop) Arc<FutexTable>);

impl std::fmt::Debug for FutexSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("FutexSource")
    }
}

pub(super) fn next_nonzero(source: &AtomicU64) -> u64 {
    let value = source.fetch_add(1, Ordering::Relaxed);
    if value == 0 || value == u64::MAX {
        carrick_fatal!(
            "vcpu_loop::continuation_identity",
            "atomic generation counter overflow: value={value}"
        );
    }
    value
}

pub mod quantum;
pub mod readiness;
pub mod wait_service;

pub(crate) use self::quantum::{
    ExecutorFailureSettlement, HvpatchTaskBinding, HvpatchTaskQuantum, PersistentQuantumJob,
};
pub use self::quantum::{JobId, LogicalJobCompletion, ProcessDrain, QuantumExit};
pub use self::readiness::{ContinuationWakeToken, ReservedSignal, ResumeContext, StaleThreadCause};
pub(in crate::vcpu_loop) use self::readiness::{ReadinessProbe, SignalReadinessProbe};
pub use self::wait_service::{
    CarrierWaitService, ContinuationEventFuture, WaitServiceError, WaitServiceTopology,
    WakePublishReceipt,
};
pub(in crate::vcpu_loop) use self::wait_service::{CarrierWaitServiceInner, RegistrationState};
#[cfg(test)]
pub(in crate::vcpu_loop) use self::wait_service::{CarrierWaitState, RegistrationOperationGate};

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
    task_event_generation: u64,
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
            task_event_generation: context.task().task_event_generation(),
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
            task_event_generation: context.task().task_event_generation(),
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
    pub(in crate::vcpu_loop) kernel: Weak<Kernel>,
    pub(in crate::vcpu_loop) task_ref: Weak<Task>,
    pub(in crate::vcpu_loop) file_table: Arc<crate::kernel::objects::FileTable>,
    pub(in crate::vcpu_loop) thread: ThreadKey,
    pub(in crate::vcpu_loop) task: TaskKey,
    pub(in crate::vcpu_loop) task_revision: TaskRevision,
    pub(in crate::vcpu_loop) task_wake_generation: u64,
    pub(in crate::vcpu_loop) task_event_generation: u64,
    pub(in crate::vcpu_loop) execution: ExecutionGeneration,
    pub(in crate::vcpu_loop) syscall: SyscallFrame,
    pub(in crate::vcpu_loop) restart: RestartClass,
    pub(in crate::vcpu_loop) mm: MmId,
    pub(in crate::vcpu_loop) asid_generation: u64,
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
            task_event_generation: capture.task_event_generation,
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

    fn namespace_task_id(&self, task: TaskKey) -> Option<i64> {
        let parent = self.task_ref.upgrade()?;
        if parent.key() != self.task {
            return None;
        }
        let raw = u32::try_from(task.id.raw()).ok()?;
        match parent.pid_ns_region() {
            Some(region) => region.host_to_ns(raw).map(i64::from),
            None => Some(i64::from(raw)),
        }
    }

    pub const fn task_revision(&self) -> TaskRevision {
        self.task_revision
    }

    pub const fn execution_generation(&self) -> ExecutionGeneration {
        self.execution
    }

    /// Re-stamp the authority onto the lease that held this continuation
    /// without consuming it. The kernel carries a parked continuation through
    /// any lease that re-parks before resuming it (an executor refused
    /// admission during a fork quiesce, an owner control quantum, an exec or
    /// exit drain); the authority must then name THAT lease, or every such
    /// re-park adds one generation to the succession `resume_continuation`
    /// checks and a blameless thread eventually fails `StaleThread`.
    pub(crate) const fn rebind_execution_generation(&mut self, generation: ExecutionGeneration) {
        self.execution = generation;
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

/// Pointer-free diagnostic view of one parked continuation. See
/// [`BlockedContinuation::diagnostic`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationDiagnostic {
    pub id: u64,
    pub family: &'static str,
    pub detail: String,
    pub deadline_ms_remaining: Option<i64>,
    pub registration: Option<ContinuationRegistrationDiagnostic>,
}

/// The wait-service side of a parked continuation: the registration the
/// producers publish into, as the service actually holds it right now.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationRegistrationDiagnostic {
    pub continuation: u64,
    pub thread_serial: u64,
    pub execution_generation: u64,
    pub registration_generation: u64,
    /// `false` once the owning [`CarrierWaitService`] has been dropped: no
    /// reactor exists to poll this registration's fds any more.
    pub service_alive: bool,
    /// `prepared` / `enrolled` / `ready` / `cancelled(<cause>)` / `consumed`,
    /// or `absent` / `token-mismatch` / `service-dropped` when the service
    /// holds no entry this continuation can be woken through.
    pub state: String,
    pub event: Option<&'static str>,
    pub probe: String,
    /// The signal/task-wake generations this registration was captured at and
    /// the producer task's current values. A child wait rides the task EVENT
    /// generation; `observed_event == current_event` on a parked wait whose
    /// child is already a zombie means no producer edge was ever published.
    pub signal_readiness: String,
    /// Host fds the reactor polls for this registration, with their `poll(2)`
    /// event mask. Empty for probes that are not fd-driven.
    pub poll_fds: Vec<DiagnosticPollFd>,
    pub subscriptions: usize,
    pub has_task_waker: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticPollFd {
    pub fd: i32,
    pub events: i16,
}

/// The guest side of an fd wait: the exact slots it is authorised against.
/// Rendered as `<fd>@<description>` so a snapshot reader can join straight to
/// the `file_slots` / `file_descriptions` tables and name the pipe, socket or
/// event set the thread is parked on. The host fds in `poll_fds` are private
/// dups and join to nothing.
fn fd_authority_diagnostic(authority: &WaitFdAuthority) -> String {
    let render = |slots: &[crate::kernel::objects::FileSlotAuthority]| {
        slots
            .iter()
            .map(|slot| format!("{}@{}", slot.number().raw(), slot.description().raw()))
            .collect::<Vec<_>>()
            .join(",")
    };
    match authority {
        WaitFdAuthority::Empty => "slots=empty".to_owned(),
        WaitFdAuthority::Missing => "slots=missing".to_owned(),
        WaitFdAuthority::Logical { strict, watched } => {
            format!("slots=[{}] watched=[{}]", render(strict), render(watched))
        }
        WaitFdAuthority::Internal(_) => "slots=internal".to_owned(),
    }
}

fn detail_diagnostic(detail: &ContinuationDetail) -> String {
    match detail {
        ContinuationDetail::Futex { wait, index } => {
            format!("futex addr={:#x} index={index:?}", wait.addr)
        }
        ContinuationDetail::SharedFutex {
            generation, value, ..
        } => format!("shared-futex addr={:#x} value={value}", generation.addr),
        ContinuationDetail::SharedWord {
            generation, value, ..
        } => format!("shared-word addr={:#x} value={value}", generation.addr),
        ContinuationDetail::Fds {
            registrations,
            on_timeout,
            fd_authority,
            ..
        } => format!(
            "fds n={} on_timeout={on_timeout} {}",
            registrations.len(),
            fd_authority_diagnostic(fd_authority)
        ),
        ContinuationDetail::Select {
            registrations,
            fd_authority,
            ..
        } => format!(
            "select n={} {}",
            registrations.len(),
            fd_authority_diagnostic(fd_authority)
        ),
        ContinuationDetail::HostWrite(_) => "host-write".to_owned(),
        ContinuationDetail::RecordLock(_) => "record-lock".to_owned(),
        ContinuationDetail::Process { selector, .. } => match selector {
            ChildSelector::Exact(task) => {
                format!("process exact={}.{}", task.id.raw(), task.serial.raw())
            }
            ChildSelector::AnyChildOf(task) => {
                format!(
                    "process any-child-of={}.{}",
                    task.id.raw(),
                    task.serial.raw()
                )
            }
            ChildSelector::HostPid(pid) => format!("process host-pid={pid}"),
        },
        ContinuationDetail::Signals { wait_set, .. } => {
            format!("signals wait_set={:#x}", wait_set.raw())
        }
        ContinuationDetail::Sleep => "sleep".to_owned(),
        ContinuationDetail::Vfork { child, .. } => {
            format!("vfork child={}.{}", child.id.raw(), child.serial.raw())
        }
    }
}

fn probe_diagnostic(probe: &ReadinessProbe) -> (String, Vec<DiagnosticPollFd>) {
    match probe {
        ReadinessProbe::Futex { wait, .. } => (format!("futex addr={:#x}", wait.addr), Vec::new()),
        ReadinessProbe::Fds { registrations, .. } => (
            format!("fds n={}", registrations.len()),
            registrations
                .iter()
                .map(|registration| DiagnosticPollFd {
                    fd: registration.fd.as_raw_fd(),
                    events: registration.events,
                })
                .collect(),
        ),
        ReadinessProbe::SharedWord { generation, .. } => (
            format!("shared-word addr={:#x}", generation.addr),
            Vec::new(),
        ),
        ReadinessProbe::HostWrite { host_fd, .. } => (
            format!("host-write fd={host_fd}"),
            vec![DiagnosticPollFd {
                fd: *host_fd,
                events: libc::POLLOUT,
            }],
        ),
        ReadinessProbe::RecordLock { .. } => ("record-lock".to_owned(), Vec::new()),
        ReadinessProbe::TaskWake { task, observed, .. } => (
            task.upgrade().map_or_else(
                || format!("task-wake observed={observed} task=dropped"),
                |task| {
                    format!(
                        "task-wake observed={observed} current={} events={}",
                        task.wake_generation(),
                        task.task_event_generation()
                    )
                },
            ),
            Vec::new(),
        ),
        ReadinessProbe::Vfork { .. } => ("vfork".to_owned(), Vec::new()),
        ReadinessProbe::Timer { .. } => ("timer".to_owned(), Vec::new()),
        ReadinessProbe::Passive { .. } => ("passive".to_owned(), Vec::new()),
    }
}

fn event_diagnostic(event: &ContinuationEvent) -> &'static str {
    match event {
        ContinuationEvent::Ready => "ready",
        ContinuationEvent::Timeout => "timeout",
        ContinuationEvent::Signal => "signal",
        ContinuationEvent::ReservedSignal(_) => "reserved-signal",
    }
}

fn registration_state_diagnostic(state: RegistrationState) -> String {
    match state {
        RegistrationState::Prepared => "prepared".to_owned(),
        RegistrationState::Enrolled => "enrolled".to_owned(),
        RegistrationState::Ready => "ready".to_owned(),
        RegistrationState::Consumed => "consumed".to_owned(),
        RegistrationState::Cancelled(cause) => format!("cancelled({cause:?})"),
    }
}

fn registration_diagnostic(binding: &RegistrationBinding) -> ContinuationRegistrationDiagnostic {
    let token = binding.token;
    let absent = |state: &str| ContinuationRegistrationDiagnostic {
        continuation: token.continuation.raw(),
        thread_serial: token.thread_serial,
        execution_generation: token.execution_raw,
        registration_generation: token.registration_generation,
        service_alive: true,
        state: state.to_owned(),
        event: None,
        probe: "none".to_owned(),
        signal_readiness: "unavailable".to_owned(),
        poll_fds: Vec::new(),
        subscriptions: 0,
        has_task_waker: false,
    };
    let Some(service) = binding.service.upgrade() else {
        let mut row = absent("service-dropped");
        row.service_alive = false;
        return row;
    };
    let state = service.state.lock();
    let Some(entry) = state.entries.get(&token.continuation) else {
        return absent("absent");
    };
    if entry.token != token {
        return absent("token-mismatch");
    }
    let (probe, poll_fds) = probe_diagnostic(&entry.probe);
    let signal_readiness = entry.signal_readiness.task_ref.upgrade().map_or_else(
        || {
            format!(
                "observed_wake={} observed_event={} task=dropped",
                entry.signal_readiness.observed_task_wake,
                entry.signal_readiness.observed_task_event
            )
        },
        |task| {
            format!(
                "observed_wake={} current_wake={} observed_event={} current_event={}",
                entry.signal_readiness.observed_task_wake,
                task.wake_generation(),
                entry.signal_readiness.observed_task_event,
                task.task_event_generation()
            )
        },
    );
    ContinuationRegistrationDiagnostic {
        signal_readiness,
        continuation: token.continuation.raw(),
        thread_serial: token.thread_serial,
        execution_generation: token.execution_raw,
        registration_generation: token.registration_generation,
        service_alive: true,
        state: registration_state_diagnostic(entry.state),
        event: entry.event.as_ref().map(event_diagnostic),
        probe,
        poll_fds,
        subscriptions: entry.subscriptions.len(),
        has_task_waker: entry.task_waker.is_some(),
    }
}

#[derive(Clone, Debug)]
pub(in crate::vcpu_loop) struct OwnedFdRegistration {
    #[allow(dead_code)]
    pub(in crate::vcpu_loop) fd: Arc<OwnedFd>,
    #[allow(dead_code)]
    pub(in crate::vcpu_loop) events: i16,
    #[allow(dead_code)]
    pub(in crate::vcpu_loop) generation: u64,
}

fn own_wait_fds(fds: &WaitFds) -> Result<Vec<OwnedFdRegistration>, ContinuationBuildError> {
    fds.iter()
        .filter(|fd| fd.fd() >= 0)
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
pub(in crate::vcpu_loop) enum ContinuationDetail {
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
        /// The parent's wake generation as of the child scan that concluded
        /// nothing was reapable. Both readiness probes enroll against THIS
        /// rather than against the generation the capture re-reads, because a
        /// child that exits between the scan and the capture publishes its
        /// edge in between. See
        /// [`ChildWaitPrecheck`](crate::kernel::ChildWaitPrecheck).
        precheck: crate::kernel::ChildWaitPrecheck,
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
    pub(in crate::vcpu_loop) id: ContinuationId,
    pub(in crate::vcpu_loop) authority: ContinuationAuthority,
    pub(in crate::vcpu_loop) deadline: Option<Instant>,
    pub(in crate::vcpu_loop) outputs: Vec<GuestOutputRange>,
    pub(in crate::vcpu_loop) signal_masks: SignalMaskContinuationState,
    pub(in crate::vcpu_loop) detail: ContinuationDetail,
    pub(in crate::vcpu_loop) resource_generation: u64,
    pub(in crate::vcpu_loop) private_futex: Option<FutexSource>,
    pub(in crate::vcpu_loop) producer_completion: Arc<Mutex<Option<DispatchOutcome>>>,
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

impl ContinuationFamily {
    /// Stable event-ring representation. Keep this explicit rather than
    /// depending on Rust's enum layout: cores and LLDB scripts outlive builds.
    pub(crate) const fn event_code(self) -> u8 {
        match self {
            Self::FutexWait => 1,
            Self::FutexWaitv => 2,
            Self::SharedFutexWait => 3,
            Self::SharedFutexWaitv => 4,
            Self::WaitOnSharedWord => 5,
            Self::WaitOnFds => 6,
            Self::WaitOnFdsSelect => 7,
            Self::WaitOnPollFds => 8,
            Self::BlockingHostWrite => 9,
            Self::BlockingRecordLock => 10,
            Self::WaitOnProcExit => 11,
            Self::WaitOnProcState => 12,
            Self::WaitOnHvpatchChild => 13,
            Self::WaitOnSignals => 14,
            Self::WaitOnSleep => 15,
            Self::VforkParent => 16,
        }
    }

    /// Stable snapshot spelling. Same rule as `event_code`: a wedge snapshot
    /// outlives the build that produced it, so the name is written out rather
    /// than derived from the Rust variant.
    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            Self::FutexWait => "futex-wait",
            Self::FutexWaitv => "futex-waitv",
            Self::SharedFutexWait => "shared-futex-wait",
            Self::SharedFutexWaitv => "shared-futex-waitv",
            Self::WaitOnSharedWord => "wait-on-shared-word",
            Self::WaitOnFds => "wait-on-fds",
            Self::WaitOnFdsSelect => "wait-on-fds-select",
            Self::WaitOnPollFds => "wait-on-poll-fds",
            Self::BlockingHostWrite => "blocking-host-write",
            Self::BlockingRecordLock => "blocking-record-lock",
            Self::WaitOnProcExit => "wait-on-proc-exit",
            Self::WaitOnProcState => "wait-on-proc-state",
            Self::WaitOnHvpatchChild => "wait-on-hvpatch-child",
            Self::WaitOnSignals => "wait-on-signals",
            Self::WaitOnSleep => "wait-on-sleep",
            Self::VforkParent => "vfork-parent",
        }
    }

    /// Whether a published task event is a producer edge for this wait.
    ///
    /// Synthetic logical descriptors have no host fd to poll, so their
    /// producers publish into the descriptor and signal readiness through the
    /// task-event generation. Other families have exact producer generations
    /// (futex/shared-word/vfork), timers, or signal state and must not turn an
    /// unrelated task event into successful completion.
    const fn accepts_task_event(self) -> bool {
        matches!(
            self,
            Self::WaitOnFds | Self::WaitOnFdsSelect | Self::WaitOnPollFds
        )
    }
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
                target,
                generation,
                value,
                timeout,
            } => Self::SharedFutexWait(new_state(
                deadline(timeout),
                Vec::new(),
                None,
                ContinuationDetail::SharedFutex {
                    location: target.location,
                    waiter_key: target.waiter_key,
                    generation,
                    value,
                    index: None,
                },
            )),
            DispatchOutcome::SharedFutexWaitv {
                target,
                generation,
                value,
                timeout,
                index,
            } => Self::SharedFutexWaitv(new_state(
                deadline(timeout),
                Vec::new(),
                None,
                ContinuationDetail::SharedFutex {
                    location: target.location,
                    waiter_key: target.waiter_key,
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
                sig_mask,
                completion,
            } => match completion {
                FdWaitCompletion::Fd { on_timeout } => {
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
                FdWaitCompletion::Select { clear_on_timeout } => {
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
                FdWaitCompletion::Poll { on_timeout } => {
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
            },
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
                        precheck: crate::kernel::ChildWaitPrecheck::unsampled(),
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
                        precheck: crate::kernel::ChildWaitPrecheck::unsampled(),
                    },
                ))
            }
            DispatchOutcome::WaitOnHvpatchChild {
                target,
                sig_mask,
                precheck,
            } => {
                if backend != ContinuationBackend::Hvpatch {
                    return Err(ContinuationBuildError::StaleChildSelector);
                }
                let selector = match target {
                    None => ChildSelector::AnyChildOf(parent_task),
                    Some(pid) => {
                        let id = crate::kernel::TaskId::from_abi_positive(pid)
                            .map_err(|_| ContinuationBuildError::StaleChildSelector)?;
                        let kernel = kernel
                            .as_ref()
                            .ok_or(ContinuationBuildError::StaleChildSelector)?;
                        // A child may finish exiting and transition from `state.tasks` to
                        // `state.zombies` in the race window between wait4 returning StillRunning
                        // and continuation enrollment; checking `zombie(id)` prevents a spurious
                        // StaleChildSelector error when building WaitOnHvpatchChild.
                        let (child_key, parent) = if let Ok(identity) = kernel.task_identity(id) {
                            (identity.task, identity.parent)
                        } else if let Some(zombie) = kernel.registry().zombie(id) {
                            (zombie.key, zombie.parent)
                        } else {
                            return Err(ContinuationBuildError::StaleChildSelector);
                        };
                        if parent != Some(parent_task) {
                            return Err(ContinuationBuildError::StaleChildSelector);
                        }
                        ChildSelector::Exact(child_key)
                    }
                };
                Self::WaitOnHvpatchChild(new_state(
                    None,
                    Vec::new(),
                    Some(sig_mask),
                    ContinuationDetail::Process {
                        selector,
                        sig_mask,
                        precheck,
                    },
                ))
            }
            DispatchOutcome::WaitOnSignals {
                wait_set,
                block_mask,
                timeout,
            } => Self::WaitOnSignals(new_state(
                deadline(timeout),
                Vec::new(),
                Some(WaitSigMask::Replace(SigSet::from_raw(block_mask.raw()))),
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

    pub(in crate::vcpu_loop) fn state(&self) -> &ContinuationState {
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

    /// Whether a generic scheduler wake is itself a completion edge.
    ///
    /// Families that resume with `Redispatch` re-run the syscall and re-check
    /// their own readiness, so a spurious `Ready` costs one extra dispatch.
    /// The families listed here instead resume with a *result* that asserts
    /// a producer fired: a vfork parent has exactly one producer (its child's
    /// exec/exit release gate) and a futex wait returns 0 only for a counted
    /// `FUTEX_WAKE`. Their exact producers — the futex table subscription,
    /// the task-wake/signal subscription and the reactor deadline — publish
    /// into the registration before calling `Scheduler::wake`, so retry,
    /// signal and task-event wakes must never manufacture readiness for them.
    /// `ltp-pause01` is the witness: a sibling child's exit posted SIGCHLD to
    /// the parent mid-switch-out, the settlement fabricated `Ready` for the
    /// parent's shared checkpoint `FUTEX_WAIT`, and the next child's
    /// `FUTEX_WAKE` counted 0 waiters forever.
    pub(crate) const fn accepts_generic_scheduler_wake(&self) -> bool {
        !matches!(
            self,
            Self::VforkParent(_)
                | Self::FutexWait(_)
                | Self::FutexWaitv(_)
                | Self::SharedFutexWait(_)
                | Self::SharedFutexWaitv(_)
        )
    }

    /// Whether the scheduler may queue this continuation for the current wake.
    /// Exact producers publish into the registration before calling
    /// `Scheduler::wake`, so an already-ready vfork release remains runnable
    /// even though unrelated generic wakes are rejected.
    pub(crate) fn accepts_scheduler_wake_now(&self) -> bool {
        self.accepts_generic_scheduler_wake() || self.ready_event().is_ok()
    }

    pub fn id(&self) -> ContinuationId {
        self.state().id
    }

    pub fn authority(&self) -> &ContinuationAuthority {
        &self.state().authority
    }

    /// The lease at `generation` held this continuation and settled without
    /// consuming it; the continuation now answers to that lease. See
    /// [`ContinuationAuthority::rebind_execution_generation`].
    pub(crate) fn carry_through_lease(&mut self, generation: ExecutionGeneration) {
        self.state_mut()
            .authority
            .rebind_execution_generation(generation);
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.state().deadline
    }

    /// Pointer-free diagnostic view of this parked continuation, for the
    /// kernel debug snapshot.
    ///
    /// `Blocked { reason: HostWait, continuation: Some(..) }` says a thread is
    /// parked; it does not say WHAT it is parked on, and a watchdog wedge
    /// snapshot is usually the only evidence a lost wake leaves behind. This
    /// names the family, the exact readiness probe with its polled host fds,
    /// and — decisively — whether the wait service still holds a live
    /// registration for it. A blocked thread whose registration reads
    /// `absent`, `token-mismatch`, `cancelled(..)` or `service-dropped` has no
    /// producer that can ever wake it; one that reads `ready` was woken and
    /// the *scheduler* dropped the edge. Those are different bugs and the
    /// snapshot must tell them apart without a live process to attach to.
    pub fn diagnostic(&self) -> ContinuationDiagnostic {
        let state = self.state();
        let now = Instant::now();
        ContinuationDiagnostic {
            id: state.id.raw(),
            family: self.family().wire_name(),
            detail: detail_diagnostic(&state.detail),
            deadline_ms_remaining: state.deadline.map(|deadline| {
                i64::try_from(deadline.saturating_duration_since(now).as_millis())
                    .unwrap_or(i64::MAX)
            }),
            // `None` here is the starkest form of the same defect: the
            // continuation carries no binding at all, so nothing anywhere can
            // publish an event for it.
            registration: state.registration.as_ref().map(registration_diagnostic),
        }
    }

    pub fn guest_outputs(&self) -> &[GuestOutputRange] {
        &self.state().outputs
    }

    pub fn signal_masks(&self) -> SignalMaskContinuationState {
        self.state().signal_masks
    }

    pub fn is_waiting_for_signal(&self, signal: crate::kernel::LinuxSignal) -> bool {
        match &self.state().detail {
            ContinuationDetail::Signals { wait_set, .. } => wait_set.contains(signal.raw()),
            _ => false,
        }
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
                fingerprint ^= generation.ticket();
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
                fingerprint ^= generation.ticket();
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
            ContinuationDetail::Process {
                selector, sig_mask, ..
            } => {
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
        use ContinuationResumeError::StaleThread;
        let authority = self.authority();
        if resume.thread != authority.thread()
            || resume.execution != authority.execution_generation()
            || resume.task != authority.task()
        {
            return Err(StaleThread(StaleThreadCause::ResumeIdentity {
                resume_thread: resume.thread,
                resume_execution: resume.execution.raw(),
                authority_thread: authority.thread(),
                authority_execution: authority.execution_generation().raw(),
            }));
        }
        if resume.mm != authority.mm() || resume.asid_generation != authority.asid_generation() {
            return Err(ContinuationResumeError::StaleAddressSpace);
        }
        let kernel = authority
            .kernel
            .upgrade()
            .ok_or(StaleThread(StaleThreadCause::KernelGone))?;
        if !kernel.task_key_is_live(authority.task()) {
            return Err(StaleThread(StaleThreadCause::TaskNotLive));
        }
        if kernel
            .exact_thread_for_scheduler(authority.thread())
            .is_none()
        {
            return Err(StaleThread(StaleThreadCause::ThreadNotSchedulable));
        }
        let current = kernel
            .context(authority.task().id, authority.thread().tid)
            .map_err(|_| StaleThread(StaleThreadCause::ContextUnavailable))?;
        if current.task().key() != authority.task()
            || current.thread().key() != authority.thread()
            || current.shared().mm().id() != authority.mm()
        {
            return Err(StaleThread(StaleThreadCause::ContextMismatch));
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
        let authority = context.signal_authority();
        authority.arm_restore_mask(Some(masks.restore_after_signal.unwrap_or(masks.persistent)));
        authority.set_blocked(effective);
    }

    pub(crate) fn publish_ready_event(&self, event: ContinuationEvent) -> bool {
        let Some(binding) = self.state().registration.as_ref() else {
            return false;
        };
        let Some(service) = binding.service.upgrade() else {
            return false;
        };
        let (won, task_waker) = {
            let mut state = service.state.lock();
            let Some(mut entry) = state.registration_mut(binding.token.continuation) else {
                return false;
            };
            if entry.token != binding.token
                || !matches!(
                    entry.state,
                    RegistrationState::Prepared | RegistrationState::Enrolled
                )
            {
                return false;
            }
            entry.state = RegistrationState::Ready;
            entry.event = Some(event);
            let task_waker = entry.task_waker.take();
            (true, task_waker)
        };
        service.nudge_reactor();
        if let Some(waker) = task_waker {
            waker.wake();
        }
        won
    }

    pub(crate) fn ready_event(&self) -> Result<ContinuationEvent, ContinuationResumeError> {
        let binding = self
            .state()
            .registration
            .as_ref()
            .ok_or(ContinuationResumeError::MissingContinuation)?;
        let service = binding
            .service
            .upgrade()
            .ok_or(ContinuationResumeError::MissingContinuation)?;
        let state = service.state.lock();
        let entry = state
            .entries
            .get(&binding.token.continuation)
            .filter(|entry| entry.token == binding.token && entry.state == RegistrationState::Ready)
            .ok_or(ContinuationResumeError::MissingContinuation)?;
        entry
            .event
            .clone()
            .ok_or(ContinuationResumeError::MissingContinuation)
    }

    pub fn resume(
        mut self,
        event: ContinuationEvent,
        context: &KernelContext,
    ) -> Result<ContinuationResult, ContinuationResumeError> {
        if event == ContinuationEvent::Ready
            && matches!(
                &self.state().detail,
                ContinuationDetail::Vfork { wait, .. } if wait.released_reason().is_none()
            )
        {
            return Err(ContinuationResumeError::PrematureVforkRelease);
        }
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
                        match self
                            .vfork_child()
                            .and_then(|key| self.authority().namespace_task_id(key))
                        {
                            Some(child) => ContinuationCompletion::Return(child),
                            None => ContinuationCompletion::Errno(carrick_abi::LINUX_ESRCH),
                        }
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
                    if let Some(reserved) = reserved_signal.as_ref() {
                        signal_authority.set_blocked(reserved.effective_mask());
                        signal_authority.arm_restore_mask(Some(reserved.persistent_restore()));
                    } else if caught_handler {
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
        return Err(ContinuationResumeError::StaleThread(
            StaleThreadCause::LeaseSuccession {
                lease_thread: lease.thread_key(),
                continuation_thread: continuation.authority().thread(),
                original_generation: original,
                resumed_generation: resumed,
            },
        ));
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
pub enum ContinuationResumeError {
    StaleThread(StaleThreadCause),
    StaleTaskRevision,
    StaleAddressSpace,
    MissingContinuation,
    StaleFileSlot,
    PrematureVforkRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartDecision {
    Restart,
    NoRestart,
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

#[cfg(test)]
mod tests;
