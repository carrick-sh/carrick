use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
#[cfg(test)]
use std::time::Duration;

use carrick_abi::{LinuxEpollEvents, LinuxSiginfo, NsGid, NsUid};
use parking_lot::{Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::FdCeilingAuthority;
use super::ids::{
    FileDescriptionId, FileSlotNumber, FileTableId, FsContextId, LinuxSignal, LinuxTid,
    ObjectIdError, ProcessGroupId, TaskId, TaskSerial, ThreadSerial,
};
use carrick_fatal::carrick_fatal;

pub mod credentials;
pub mod process;
pub mod session;
pub mod signal;
pub mod task;
pub mod thread;

pub use self::credentials::Credentials;

pub use self::process::{
    LinuxWaitStatus, Mm, PidfdTarget, TaskRusage, TaskShared, TaskSharedCloneError, Zombie,
};
pub use self::session::{ProcessGroup, Session};
pub use self::signal::{
    HandlerFrameState, PendingQueue, PendingSignal, Sighand, SignalAuthority, SignalDeliveryAction,
    SignalDequeue, SignalDisposition, SignalPendingOwner, SignalReservationOrigin,
    SignalWaitReservation, TaskPendingSignals, ThreadSignalState, evaluate_signal_delivery_action,
    is_default_ignore_signal, is_default_stop_signal,
};
pub use self::task::JobControlStopInvalidationGeneration;
pub(in crate::kernel) use self::task::PreparedThreadSet;
pub use self::task::{
    DumpableMode, ProcessKeyrings, RlimitSet, Task, TaskIdentity, TaskLifecycle,
    TaskParticipantError, TaskRef, TaskWakeEnrollment, TaskWakeSubscription, TaskWaker,
    ThreadResources,
};
pub(crate) use self::task::{PtraceMemoryAccessWitness, PtraceTextAccess, TaskJobControlEvent};
pub use self::task::{PtraceStopSettlement, PtraceSynchronousFault};
pub(in crate::kernel) use self::thread::ExecDrain;
pub use self::thread::{
    BlockedReason, ExecConsumedPredecessorAuthority, ExecutionFailure, ExecutionGeneration,
    ExecutorId, MigratableTaskState, RunnerDirective, TaskCpuSample, Thread, ThreadCpuSample,
    ThreadExecutionError, ThreadExecutionLease, ThreadExecutionSettlementResult,
    ThreadExecutionState, ThreadKey, ThreadRef, ThreadRunner,
};
pub(crate) use self::thread::{
    CrashSafePointParticipation, CrashSafePointParticipationError, ThreadSchedulerAction,
};
pub use self::thread::{OpenedStartGate, SchedulerControlQuantum};

impl Thread {
    /// Mint the exact generation owned by this live executor quantum.
    pub fn enter_crash_safe_point_participation(
        self: &Arc<Self>,
    ) -> Result<CrashSafePointParticipation, CrashSafePointParticipationError> {
        self.enter_crash_safe_point_participation_raw()
    }
}

static NEXT_FILE_SLOT_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_file_slot_generation() -> u64 {
    let generation = NEXT_FILE_SLOT_GENERATION.fetch_add(1, Ordering::Relaxed);
    if generation == 0 || generation == u64::MAX {
        carrick_fatal!(
            "kernel::file_slot_generation",
            "FileSlot generation atomic counter overflow or zero"
        );
    }
    generation
}

#[derive(Default)]
pub(super) struct ObjectRevision(AtomicU64);

impl ObjectRevision {
    const fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    pub(super) fn load(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn publish(&self) -> u64 {
        let prev = self.0.fetch_add(1, Ordering::Release);
        if prev == u64::MAX {
            carrick_fatal!(
                "kernel::object_revision",
                "ObjectRevision atomic counter overflow"
            );
        }
        prev + 1
    }
}

impl std::fmt::Debug for ObjectRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ObjectRevision")
            .field(&self.load())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TaskKey {
    pub id: TaskId,
    pub serial: TaskSerial,
}

impl std::fmt::Display for TaskKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "task#{}:{}", self.id.raw(), self.serial.raw())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileDescriptionBackingKind {
    Closed,
    File,
    Directory,
    SyntheticFile,
    SyntheticDevice,
    EventFd,
    TimerFd,
    Epoll,
    Pidfd,
    PipeReader,
    PipeWriter,
    HostPipe,
    HostFile,
    HostSocket,
    Inotify,
    Fanotify,
    SignalFd,
    Netlink,
    Mqueue,
    BpfMap,
    BpfProg,
    PerfEvent,
    IoUring,
    /// A new-mount-API filesystem context (`fsopen(2)`/`fspick(2)`).
    FsContext,
    /// Pure in-memory stream/dgram socket (mocked network or AF_UNIX).
    InMemorySocket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenDescriptionBackingSnapshot {
    pub kind: FileDescriptionBackingKind,
    pub offset: Option<u64>,
    pub host_fd: Option<i32>,
    pub path: Option<String>,
    pub pipe_id: Option<u64>,
    pub epoll_interests: Vec<FileDescriptionId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileDescriptionBackingSnapshot {
    Open(OpenDescriptionBackingSnapshot),
    IoUring(crate::dispatch::ioring::IoUringDescriptionSnapshot),
}

impl FileDescriptionBackingSnapshot {
    pub(crate) const fn kind(&self) -> FileDescriptionBackingKind {
        match self {
            Self::Open(snapshot) => snapshot.kind,
            Self::IoUring(_) => FileDescriptionBackingKind::IoUring,
        }
    }

    pub(crate) fn epoll_interests(&self) -> &[FileDescriptionId] {
        match self {
            Self::Open(snapshot) => &snapshot.epoll_interests,
            Self::IoUring(_) => &[],
        }
    }
}

/// Context provided to [`FileDescriptionBacking::readiness`] to resolve
/// external readiness state (such as staged splice pushback buffers and nested
/// synthetic epoll child interests) without coupling backings directly to the
/// full dispatcher.
pub trait ReadinessContext {
    fn staged_splice_bytes(&self, id: FileDescriptionId) -> usize;

    fn host_pipe_write_room(
        &self,
        pipe_capacity: i64,
        pipe_id: u64,
        is_read_end: bool,
        bidirectional: bool,
        host_fd: i32,
    ) -> Option<usize> {
        let _ = (pipe_capacity, pipe_id, is_read_end, bidirectional, host_fd);
        None
    }

    fn description_readiness(
        &self,
        description: &Arc<FileDescription>,
        interest: LinuxEpollEvents,
    ) -> LinuxEpollEvents;
}

#[allow(dead_code)]
pub struct NoReadinessContext;
impl ReadinessContext for NoReadinessContext {
    fn staged_splice_bytes(&self, _id: FileDescriptionId) -> usize {
        0
    }

    fn host_pipe_write_room(
        &self,
        _pipe_capacity: i64,
        _pipe_id: u64,
        _is_read_end: bool,
        _bidirectional: bool,
        _host_fd: i32,
    ) -> Option<usize> {
        None
    }

    fn description_readiness(
        &self,
        _description: &Arc<FileDescription>,
        _interest: LinuxEpollEvents,
    ) -> LinuxEpollEvents {
        LinuxEpollEvents::empty()
    }
}
#[allow(dead_code)]
pub(crate) const NO_READINESS_CONTEXT: &NoReadinessContext = &NoReadinessContext;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum PipeCapacityAccounting {
    InMemory,
    Host { queued_bytes: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PipeCapacityMutationError {
    NotPipe,
    Semantic(carrick_abi::LinuxErrno),
    AccountingMismatch,
}

/// Owned readiness facts sampled by a listening socket's backing authority.
#[derive(Clone, Copy, Debug)]
pub struct ListenerReadinessSample {
    pub(crate) ready: LinuxEpollEvents,
    pub(crate) host_ready: LinuxEpollEvents,
    pub(crate) inzone: Option<crate::network::inzone::ListenerReadinessSnapshot>,
}

pub trait FileDescriptionBacking: Any + Send + Sync {
    fn is_epoll(&self) -> bool;

    /// Snapshot the description identities registered by an epoll backing.
    /// `None` means this is not an epoll description. Callers receive owned
    /// identities so they never hold a backing lock while walking the graph.
    fn epoll_targets(&self) -> Option<Vec<Arc<FileDescription>>> {
        None
    }

    #[allow(dead_code)]
    fn is_closed(&self) -> bool {
        false
    }

    fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileDescriptionBackingSnapshot>;

    /// Level readiness for `interest`, in epoll's domain. This is the ONE
    /// readiness authority: `poll`/`ppoll` and `epoll_pwait` both translate to
    /// and from it rather than keeping separate state machines. A backing whose
    /// readiness lives in a real host object returns the host's answer; a
    /// synthetic backing answers from its own queues.
    fn readiness(
        &self,
        description_id: FileDescriptionId,
        interest: LinuxEpollEvents,
        cx: &dyn ReadinessContext,
    ) -> LinuxEpollEvents;

    /// Sample listener arrival facts without exposing its backing or guard.
    fn listener_readiness(&self, _interest: LinuxEpollEvents) -> Option<ListenerReadinessSample> {
        None
    }

    fn on_first_fd_ref(&self) {}

    fn on_last_fd_ref(&self) {}

    /// Release backing resources after both fd slots and mappings are gone.
    fn on_last_resource_ref(&self) {}

    fn set_pipe_capacity_from_authority(
        &self,
        capacity: i64,
        accounting: PipeCapacityAccounting,
    ) -> Result<i64, PipeCapacityMutationError> {
        let _ = (capacity, accounting);
        Err(PipeCapacityMutationError::NotPipe)
    }

    fn wait_queue(&self) -> Option<Arc<super::wait_set::WaitQueue>> {
        None
    }

    fn as_any(&self) -> &dyn Any;
}

/// Typed work that is coupled to the terminal functional lifetime of an open
/// file description.
///
/// Registration is serialized with `retain_fd_lease` and final reference
/// release.  Implementations must not retain the description itself: terminal
/// retirement must be able to drain this list without an ownership cycle.
pub trait FileDescriptionFinalizer: std::fmt::Debug + Send + Sync {
    /// A description-local key used to avoid retaining the same finalizer for
    /// every operation on one open-file description.
    fn key(&self) -> FileDescriptionFinalizerKey;

    /// Run exactly once when the description loses its final functional fd
    /// reference. This is called after the lifecycle lock is released.
    fn finalize(&self);
}

/// Opaque identity for one terminal description finalizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileDescriptionFinalizerKey {
    finalizer_type: std::any::TypeId,
    primary: usize,
    secondary: usize,
}

impl FileDescriptionFinalizerKey {
    pub(crate) fn typed<T: 'static>(primary: usize, secondary: usize) -> Self {
        Self {
            finalizer_type: std::any::TypeId::of::<T>(),
            primary,
            secondary,
        }
    }
}

struct OpaqueFileDescriptionBacking(Arc<dyn FileDescriptionBacking>);

impl OpaqueFileDescriptionBacking {
    fn new<T>(backing: Arc<T>) -> Self
    where
        T: FileDescriptionBacking,
    {
        Self(backing)
    }

    fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: FileDescriptionBacking,
    {
        self.0.as_any().downcast_ref()
    }
}

impl std::fmt::Debug for OpaqueFileDescriptionBacking {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpaqueFileDescriptionBacking")
    }
}

#[derive(Debug)]
enum FileDescriptionKind {
    Concrete(OpaqueFileDescriptionBacking),
    Regular,
    Epoll(Mutex<BTreeMap<FileDescriptionId, Weak<FileDescription>>>),
}

/// Open-file-description identity. Epoll edges are weak and stable-keyed so
/// descriptor graphs cannot create ownership cycles.
type FileDescriptionObservation = (
    u64,
    bool,
    Vec<FileDescriptionId>,
    Option<FileDescriptionBackingSnapshot>,
    Vec<(FileDescriptionId, i32)>,
    u64,
    usize,
);

/// The async-I/O owner set by `F_SETOWN`/`F_SETOWN_EX`: the SIGIO/SIGURG
/// target. `(0, 0)` — the `Default` — means no owner. `owner_type` is
/// `F_OWNER_TID`/`F_OWNER_PID`/`F_OWNER_PGRP`; `owner_pid` is the positive id.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AsyncIoOwner {
    pub(crate) owner_type: i32,
    pub(crate) owner_pid: i32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AsyncIoTarget {
    pub(crate) container_id: u64,
    pub(crate) target_id: i32,
    pub(crate) target_generation: u64,
    pub(crate) thread_id: i32,
    pub(crate) thread_generation: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CapturedAsyncIoOwner {
    pub(crate) visible: AsyncIoOwner,
    pub(crate) target: AsyncIoTarget,
}

impl CapturedAsyncIoOwner {
    pub(crate) fn capture(
        context: &crate::kernel::KernelContext,
        owner_type: i32,
        owner_pid: i32,
    ) -> Self {
        let visible = AsyncIoOwner {
            owner_type,
            owner_pid,
        };
        let Some(namespace_id) = u32::try_from(owner_pid).ok().filter(|id| *id != 0) else {
            return Self {
                visible,
                target: AsyncIoTarget::default(),
            };
        };
        let container_id = context.container().id().raw();
        let target = match owner_type {
            crate::linux_abi::LINUX_F_OWNER_PGRP => {
                crate::namespace::pid::ns_to_process_group_for(context, namespace_id)
                    .and_then(|id| context.kernel().registry().process_group(id))
                    .map(|group| AsyncIoTarget {
                        container_id,
                        target_id: group.id().raw(),
                        target_generation: group.generation(),
                        thread_id: 0,
                        thread_generation: 0,
                    })
            }
            crate::linux_abi::LINUX_F_OWNER_TID => {
                crate::namespace::pid::guest_tid_to_kernel_for(context, owner_pid)
                    .and_then(|id| LinuxTid::from_abi_positive(id).ok())
                    .and_then(|tid| context.kernel().live_keys_for_thread(None, tid))
                    .and_then(|(task, thread)| {
                        context
                            .kernel()
                            .registry()
                            .task(task.id)
                            .filter(|task| task.container().id().raw() == container_id)
                            .map(|_| AsyncIoTarget {
                                container_id,
                                target_id: task.id.raw(),
                                target_generation: task.serial.raw(),
                                thread_id: thread.tid.raw(),
                                thread_generation: thread.serial.raw(),
                            })
                    })
            }
            _ => crate::namespace::pid::ns_to_kernel_for(context, namespace_id)
                .and_then(|id| i32::try_from(id).ok())
                .and_then(|id| TaskId::from_abi_positive(id).ok())
                .and_then(|id| context.kernel().registry().task(id))
                .filter(|task| task.container().id().raw() == container_id)
                .map(|task| AsyncIoTarget {
                    container_id,
                    target_id: task.key().id.raw(),
                    target_generation: task.key().serial.raw(),
                    thread_id: 0,
                    thread_generation: 0,
                }),
        }
        .unwrap_or_default();
        Self { visible, target }
    }

    pub(crate) fn post_kernel_signal(
        self,
        kernel: &Arc<crate::kernel::Kernel>,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        let Some(target_id) = TaskId::from_abi_positive(self.target.target_id).ok() else {
            return false;
        };
        match self.visible.owner_type {
            crate::linux_abi::LINUX_F_OWNER_PGRP => {
                let Ok(group_id) = ProcessGroupId::from_abi_positive(self.target.target_id) else {
                    return false;
                };
                if kernel
                    .registry()
                    .process_group(group_id)
                    .is_none_or(|group| group.generation() != self.target.target_generation)
                {
                    return false;
                }
                let mut posted = false;
                for task in kernel.task_keys_in_process_group(group_id) {
                    let is_exact_target = kernel.registry().task(task.id).is_some_and(|current| {
                        current.key() == task
                            && current.container().id().raw() == self.target.container_id
                    });
                    if is_exact_target {
                        // Do not short-circuit: a process-group owner delivers
                        // to every live member, even after the first post.
                        posted |= kernel.post_signal_to_task_key(task, signal, siginfo);
                    }
                }
                posted
            }
            crate::linux_abi::LINUX_F_OWNER_TID => {
                let Some(task_serial) = TaskSerial::from_raw_u64(self.target.target_generation)
                else {
                    return false;
                };
                let Ok(tid) = LinuxTid::from_abi_positive(self.target.thread_id) else {
                    return false;
                };
                let Some(thread_serial) = ThreadSerial::from_raw_u64(self.target.thread_generation)
                else {
                    return false;
                };
                let task = TaskKey {
                    id: target_id,
                    serial: task_serial,
                };
                let thread = ThreadKey {
                    tid,
                    serial: thread_serial,
                };
                if kernel.registry().task(target_id).is_none_or(|current| {
                    current.key() != task
                        || current.container().id().raw() != self.target.container_id
                }) {
                    return false;
                }
                kernel.post_signal_to_thread_key(task, thread, signal, siginfo)
            }
            _ => {
                let Some(serial) = TaskSerial::from_raw_u64(self.target.target_generation) else {
                    return false;
                };
                let key = TaskKey {
                    id: target_id,
                    serial,
                };
                if kernel.registry().task(target_id).is_none_or(|task| {
                    task.key() != key || task.container().id().raw() != self.target.container_id
                }) {
                    return false;
                }
                kernel.post_signal_to_task_key(key, signal, siginfo)
            }
        }
    }
}

/// Open-file-description state that is generic across EVERY backing kind.
///
/// Linux keeps these on the description, so a `dup`, a `fork`, or a
/// `CLONE_FILES` sharer observes one value. Carrick used to keep a private copy
/// inside each of `OpenDescription`'s 25 variants (`OpenDescriptionBase`),
/// which cost two 25-arm matches to reach (`base`/`base_mut`), forced
/// `IoUringBacking` to carry a shadow `OpenDescription` purely to answer these
/// questions, and made the state unreachable — a process abort — once a
/// description drained to its `Closed` identity shell.
///
/// Reads take no description lock: every field is either an atomic or a short
/// `Mutex`, so the hot syscall prologue (`read(2)` asks seven of these
/// questions before a byte moves) does not serialize on the backing's `RwLock`.
/// Peer credentials recorded at connect/accept/socketpair time for an AF_UNIX socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketPeerCred {
    pub pid: crate::dispatch::NsPid,
    pub uid: NsUid,
    pub gid: NsGid,
}

/// A chunk of stream bytes associated with a sender's credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixStreamCred {
    pub bytes: usize,
    pub cred: SocketPeerCred,
}

/// A datagram message associated with a sender's credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixDgramCred {
    pub len: usize,
    pub cred: SocketPeerCred,
}

/// FIFO metadata ledger for a unidirectional flow.
#[derive(Debug, Default)]
pub struct UnixLedger {
    pub stream: VecDeque<UnixStreamCred>,
    pub dgram: VecDeque<UnixDgramCred>,
}

impl UnixLedger {
    pub fn push_stream(&mut self, bytes: usize, cred: SocketPeerCred) {
        if bytes == 0 {
            return;
        }
        if let Some(last) = self.stream.back_mut() {
            if last.cred == cred {
                last.bytes = last.bytes.saturating_add(bytes);
                return;
            }
        }
        self.stream.push_back(UnixStreamCred { bytes, cred });
    }

    pub fn push_dgram(&mut self, len: usize, cred: SocketPeerCred) {
        self.dgram.push_back(UnixDgramCred { len, cred });
    }

    pub fn peek_stream(&self) -> Option<UnixStreamCred> {
        self.stream.front().copied()
    }

    pub fn peek_dgram(&self) -> Option<UnixDgramCred> {
        self.dgram.front().copied()
    }

    pub fn consume_stream(&mut self, mut bytes: usize) {
        while bytes > 0 && !self.stream.is_empty() {
            if let Some(front) = self.stream.front_mut() {
                if front.bytes <= bytes {
                    bytes -= front.bytes;
                    self.stream.pop_front();
                } else {
                    front.bytes -= bytes;
                    bytes = 0;
                }
            }
        }
    }

    pub fn push_stream_bytes(&mut self, bytes: usize, cred: SocketPeerCred) {
        self.push_stream(bytes, cred);
    }

    pub fn peek_front_cred(&self, is_stream: bool) -> Option<UnixStreamCred> {
        if is_stream {
            self.peek_stream()
        } else {
            self.peek_dgram().map(|d| UnixStreamCred {
                bytes: d.len,
                cred: d.cred,
            })
        }
    }

    pub fn consume_bytes(&mut self, bytes: usize, is_stream: bool) {
        if is_stream {
            self.consume_stream(bytes);
        } else {
            self.consume_dgram();
        }
    }

    pub fn consume_dgram(&mut self) -> Option<UnixDgramCred> {
        self.dgram.pop_front()
    }
}

/// A unidirectional FIFO flow between a sender and a receiver over a UNIX socket.
#[derive(Debug, Default)]
pub struct UnixFlow {
    ledger: Mutex<UnixLedger>,
}

impl UnixFlow {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn lock_ledger(&self) -> MutexGuard<'_, UnixLedger> {
        self.ledger.lock()
    }
}

impl PartialEq for UnixFlow {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl Eq for UnixFlow {}

/// Paired bidirectional flows for a connected socket endpoint.
#[derive(Debug, Clone)]
pub struct SocketFlows {
    pub outbound: Arc<UnixFlow>,
    pub inbound: Arc<UnixFlow>,
}

impl SocketFlows {
    pub fn pair() -> (Self, Self) {
        let a_to_b = UnixFlow::new();
        let b_to_a = UnixFlow::new();
        (
            Self {
                outbound: Arc::clone(&a_to_b),
                inbound: Arc::clone(&b_to_a),
            },
            Self {
                outbound: b_to_a,
                inbound: a_to_b,
            },
        )
    }

    pub fn standalone() -> Self {
        Self {
            outbound: UnixFlow::new(),
            inbound: UnixFlow::new(),
        }
    }
}

/// Cork buffer and destination state for datagram coalescing (MSG_MORE / UDP_CORK / TCP_CORK).
#[derive(Debug, Default)]
pub struct SocketCork {
    pub enabled: bool,
    pub buffer: Vec<u8>,
    pub dest: Option<Vec<u8>>,
}

impl SocketCork {
    pub fn is_active(&self) -> bool {
        self.enabled || !self.buffer.is_empty()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn has_pending(&self) -> bool {
        !self.buffer.is_empty()
    }

    pub fn stage(&mut self, bytes: &[u8], dest: Option<&[u8]>) {
        self.buffer.extend_from_slice(bytes);
        if self.dest.is_none() {
            self.dest = dest.map(<[u8]>::to_vec);
        }
    }

    pub fn take(&mut self) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        if self.buffer.is_empty() {
            None
        } else {
            let buf = std::mem::take(&mut self.buffer);
            let dest = self.dest.take();
            Some((buf, dest))
        }
    }

    /// Put bytes the host did not accept back AHEAD of anything corked since,
    /// so a partial flush keeps the stream in order.
    pub fn restore_prefix(&mut self, unsent: &[u8]) {
        if unsent.is_empty() {
            return;
        }
        let mut restored = Vec::with_capacity(unsent.len() + self.buffer.len());
        restored.extend_from_slice(unsent);
        restored.append(&mut self.buffer);
        self.buffer = restored;
    }

    pub fn set_enabled(&mut self, enabled: bool) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        self.enabled = enabled;
        if !enabled && !self.buffer.is_empty() {
            let buf = std::mem::take(&mut self.buffer);
            let dest = self.dest.take();
            Some((buf, dest))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct DescriptionCommon {
    status_flags: AtomicU64,
    /// Number of Linux fd-table entries naming this description across every
    /// process namespace. Deliberately excludes transient Rust `Arc` clones
    /// held by in-flight syscalls: Linux removes an event-poll interest only after
    /// the last fd referring to the description closes, and `Arc::strong_count`
    /// cannot express that.
    fd_refs: AtomicUsize,
    /// `F_SETLEASE`/`F_GETLEASE`: `F_RDLCK`(0)/`F_WRLCK`(1)/`F_UNLCK`(2).
    lease: AtomicI32,
    /// `F_SETSIG`: the signal delivered on async I/O (0 = the default SIGIO).
    async_sig: AtomicI32,
    /// True for a `memfd_secret(2)` description.
    secretmem: AtomicBool,
    /// True if this open file description materialized a new file (`F_CREATED_QUERY`).
    created: AtomicBool,
    owner: Mutex<CapturedAsyncIoOwner>,
    /// `memfd_create(2)`/`F_ADD_SEALS` seal set. `None` = this description does
    /// not support sealing (`F_GET_SEALS`/`F_ADD_SEALS` → `EINVAL`).
    seals: Arc<Mutex<Option<u32>>>,
    splice_pushback: Mutex<crate::dispatch::SplicePushback>,
    peer_cred: Mutex<Option<SocketPeerCred>>,
    socket_flows: Mutex<Option<SocketFlows>>,
    cork: Mutex<SocketCork>,
    writeback_err: AtomicI32,
    /// Consecutive delegation windows recalled before paying off.
    delegation_strikes: AtomicU32,
    /// Forwarded delegation attempts still to be refused before retrying.
    delegation_backoff: AtomicU32,
}

impl DescriptionCommon {
    pub(crate) fn new(status_flags: u64) -> Self {
        Self {
            status_flags: AtomicU64::new(status_flags),
            fd_refs: AtomicUsize::new(0),
            lease: AtomicI32::new(crate::linux_abi::LINUX_F_UNLCK),
            async_sig: AtomicI32::new(0),
            secretmem: AtomicBool::new(false),
            created: AtomicBool::new(false),
            owner: Mutex::new(CapturedAsyncIoOwner::default()),
            seals: Arc::new(Mutex::new(None)),
            splice_pushback: Mutex::new(crate::dispatch::SplicePushback::default()),
            peer_cred: Mutex::new(None),
            socket_flows: Mutex::new(None),
            cork: Mutex::new(SocketCork::default()),
            writeback_err: AtomicI32::new(0),
            delegation_strikes: AtomicU32::new(0),
            delegation_backoff: AtomicU32::new(0),
        }
    }

    pub(crate) fn new_with_seals(status_flags: u64, seals: Arc<Mutex<Option<u32>>>) -> Self {
        Self {
            status_flags: AtomicU64::new(status_flags),
            fd_refs: AtomicUsize::new(0),
            lease: AtomicI32::new(crate::linux_abi::LINUX_F_UNLCK),
            async_sig: AtomicI32::new(0),
            secretmem: AtomicBool::new(false),
            created: AtomicBool::new(false),
            owner: Mutex::new(CapturedAsyncIoOwner::default()),
            seals,
            splice_pushback: Mutex::new(crate::dispatch::SplicePushback::default()),
            peer_cred: Mutex::new(None),
            socket_flows: Mutex::new(None),
            cork: Mutex::new(SocketCork::default()),
            writeback_err: AtomicI32::new(0),
            delegation_strikes: AtomicU32::new(0),
            delegation_backoff: AtomicU32::new(0),
        }
    }

    pub(crate) fn shared_seals(&self) -> Arc<Mutex<Option<u32>>> {
        Arc::clone(&self.seals)
    }

    pub(crate) fn status_flags(&self) -> u64 {
        self.status_flags.load(Ordering::Relaxed)
    }

    pub(crate) fn set_status_flags(&self, next: u64) {
        self.status_flags.store(next, Ordering::Relaxed);
    }

    pub(crate) fn fd_refs(&self) -> usize {
        self.fd_refs.load(Ordering::Relaxed)
    }

    pub(crate) fn retain_fd_ref(&self) -> usize {
        self.fd_refs.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Returns the count AFTER the release. Aborts on underflow: a negative
    /// logical fd-reference count means the close accounting has already lost
    /// track of an event-poll interest's lifetime, and continuing would leak or
    /// double-free a registration.
    pub(crate) fn release_fd_ref(&self) -> usize {
        let previous = self.fd_refs.fetch_sub(1, Ordering::Relaxed);
        if previous == 0 {
            carrick_fatal!(
                "kernel::file_description_refs",
                "logical fd reference count underflow"
            );
        }
        previous - 1
    }

    pub(crate) fn lease(&self) -> i32 {
        self.lease.load(Ordering::Relaxed)
    }

    pub(crate) fn set_lease(&self, lease: i32) {
        self.lease.store(lease, Ordering::Relaxed);
    }

    pub(crate) fn async_sig(&self) -> i32 {
        self.async_sig.load(Ordering::Relaxed)
    }

    pub(crate) fn set_async_sig(&self, sig: i32) {
        self.async_sig.store(sig, Ordering::Relaxed);
    }

    pub(crate) fn secretmem(&self) -> bool {
        self.secretmem.load(Ordering::Relaxed)
    }

    pub(crate) fn set_secretmem(&self, on: bool) {
        self.secretmem.store(on, Ordering::Relaxed);
    }

    pub(crate) fn created(&self) -> bool {
        self.created.load(Ordering::Relaxed)
    }

    pub(crate) fn set_created(&self, created: bool) {
        self.created.store(created, Ordering::Relaxed);
    }

    pub(crate) fn owner(&self) -> AsyncIoOwner {
        self.owner.lock().visible
    }

    #[cfg(test)]
    pub(crate) fn set_owner(&self, owner: AsyncIoOwner) {
        *self.owner.lock() = CapturedAsyncIoOwner {
            visible: owner,
            target: AsyncIoTarget::default(),
        };
    }

    pub(crate) fn captured_owner(&self) -> CapturedAsyncIoOwner {
        *self.owner.lock()
    }

    pub(crate) fn set_captured_owner(&self, owner: CapturedAsyncIoOwner) {
        *self.owner.lock() = owner;
    }

    pub(crate) fn seals(&self) -> Option<u32> {
        *self.seals.lock()
    }

    pub(crate) fn set_seals(&self, seals: Option<u32>) {
        *self.seals.lock() = seals;
    }

    pub(crate) fn splice_pushback(&self) -> &Mutex<crate::dispatch::SplicePushback> {
        &self.splice_pushback
    }

    pub(crate) fn clear_splice_pushback(&self) {
        *self.splice_pushback.lock() = crate::dispatch::SplicePushback::default();
    }

    pub(crate) fn peer_cred(&self) -> Option<SocketPeerCred> {
        *self.peer_cred.lock()
    }

    pub(crate) fn set_peer_cred(&self, cred: Option<SocketPeerCred>) {
        *self.peer_cred.lock() = cred;
    }

    pub(crate) fn socket_flows(&self) -> Option<SocketFlows> {
        self.socket_flows.lock().clone()
    }

    pub(crate) fn outbound_flow(&self) -> Option<Arc<UnixFlow>> {
        self.socket_flows().map(|f| f.outbound)
    }

    pub(crate) fn inbound_flow(&self) -> Option<Arc<UnixFlow>> {
        self.socket_flows().map(|f| f.inbound)
    }

    pub(crate) fn init_socket_flows(&self, flows: SocketFlows) {
        *self.socket_flows.lock() = Some(flows);
    }

    pub(crate) fn ensure_socket_flows(&self) -> SocketFlows {
        let mut guard = self.socket_flows.lock();
        if let Some(flows) = &*guard {
            flows.clone()
        } else {
            let flows = SocketFlows::standalone();
            *guard = Some(flows.clone());
            flows
        }
    }

    pub(crate) fn cork(&self) -> MutexGuard<'_, SocketCork> {
        self.cork.lock()
    }

    pub(crate) fn record_writeback_error(&self, err: carrick_abi::LinuxErrno) {
        let _ =
            self.writeback_err
                .compare_exchange(0, err.get(), Ordering::SeqCst, Ordering::SeqCst);
    }

    pub(crate) fn take_writeback_error(&self) -> Option<carrick_abi::LinuxErrno> {
        let err = self.writeback_err.swap(0, Ordering::SeqCst);
        if err != 0 {
            Some(carrick_abi::LinuxErrno::new(err))
        } else {
            None
        }
    }

    /// Record the end of an EL1 delegation window that served `served`
    /// operations. A window that paid for itself clears the backoff; one that
    /// did not doubles it (deterministic, counted in forwarded attempts).
    pub(crate) fn record_delegation_window(&self, served: u64) {
        if served >= crate::el1_delegation::DELEGATION_WINDOW_PAYOFF_OPS {
            self.delegation_strikes.store(0, Ordering::Relaxed);
            self.delegation_backoff.store(0, Ordering::Relaxed);
        } else {
            let strikes = self.delegation_strikes.fetch_add(1, Ordering::Relaxed) + 1;
            let backoff = crate::el1_delegation::DELEGATION_BACKOFF_BASE
                .saturating_mul(1u32 << strikes.min(16));
            self.delegation_backoff.store(backoff, Ordering::Relaxed);
        }
    }

    /// Whether a forwarded operation may try to delegate now; each refused
    /// attempt consumes one unit of backoff.
    pub(crate) fn admit_delegation(&self) -> bool {
        let mut remaining = self.delegation_backoff.load(Ordering::Relaxed);
        while remaining != 0 {
            match self.delegation_backoff.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return false,
                Err(current) => remaining = current,
            }
        }
        true
    }
}

#[derive(Debug, Default)]
struct DescriptionLifecycle {
    mapping_refs: usize,
    terminal_finalizers: Vec<Arc<dyn FileDescriptionFinalizer>>,
}

/// Keeps a mapped file's backing alive without retaining a logical fd slot.
/// Fragments and forked mappings may share this reference through an Arc.
#[derive(Debug)]
pub struct MappedFileReference {
    description: Arc<FileDescription>,
}

impl MappedFileReference {
    pub(crate) fn description(&self) -> &FileDescription {
        &self.description
    }
}

impl Drop for MappedFileReference {
    fn drop(&mut self) {
        let mut lifecycle = self.description.lifecycle_transition.lock();
        lifecycle.mapping_refs = lifecycle.mapping_refs.checked_sub(1).unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::file_description_refs",
                "mapped file reference count underflow"
            );
        });
        if lifecycle.mapping_refs == 0 && self.description.common.fd_refs() == 0 {
            if let FileDescriptionKind::Concrete(backing) = &self.description.kind {
                backing.0.on_last_resource_ref();
            }
        }
        self.description.revision.publish();
    }
}

#[derive(Debug)]
pub struct FileDescription {
    id: FileDescriptionId,
    kind: FileDescriptionKind,
    common: Arc<DescriptionCommon>,
    lifecycle_transition: Mutex<DescriptionLifecycle>,
    epoll_registrations: Mutex<BTreeMap<(FileDescriptionId, i32), Weak<FileDescription>>>,
    revision: ObjectRevision,
    delegation_handle: std::sync::atomic::AtomicU32,
    /// Counts this description against its host inode's EL1 ownership record
    /// (host regular files only; set once at construction).
    el1_registration: std::sync::OnceLock<crate::el1_delegation::InodeOpenRegistration>,
}

impl FileDescription {
    pub(crate) fn common(&self) -> &DescriptionCommon {
        &self.common
    }

    #[allow(dead_code)]
    pub(crate) fn common_arc(&self) -> Arc<DescriptionCommon> {
        Arc::clone(&self.common)
    }

    pub(crate) fn concrete_with_common<T>(
        backing: Arc<T>,
        common: Arc<DescriptionCommon>,
    ) -> Result<Self, ObjectIdError>
    where
        T: FileDescriptionBacking,
    {
        Ok(Self {
            id: super::ids::allocate_file_description_id()?,
            kind: FileDescriptionKind::Concrete(OpaqueFileDescriptionBacking::new(backing)),
            common,
            lifecycle_transition: Mutex::new(DescriptionLifecycle::default()),
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
            delegation_handle: std::sync::atomic::AtomicU32::new(0),
            el1_registration: std::sync::OnceLock::new(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn concrete_with_status_flags<T>(
        backing: Arc<T>,
        status_flags: u64,
    ) -> Result<Self, ObjectIdError>
    where
        T: FileDescriptionBacking,
    {
        Self::concrete_with_common(backing, Arc::new(DescriptionCommon::new(status_flags)))
    }

    #[allow(dead_code)]
    pub(crate) fn concrete_restored_with_common<T>(
        stable_id: u64,
        backing: Arc<T>,
        common: Arc<DescriptionCommon>,
    ) -> Result<Self, ObjectIdError>
    where
        T: FileDescriptionBacking,
    {
        Ok(Self {
            id: super::ids::restore_file_description_id(stable_id)?,
            kind: FileDescriptionKind::Concrete(OpaqueFileDescriptionBacking::new(backing)),
            common,
            lifecycle_transition: Mutex::new(DescriptionLifecycle::default()),
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
            delegation_handle: std::sync::atomic::AtomicU32::new(0),
            el1_registration: std::sync::OnceLock::new(),
        })
    }

    #[allow(dead_code)]
    pub(crate) fn concrete_restored_with_status_flags<T>(
        stable_id: u64,
        backing: Arc<T>,
        status_flags: u64,
    ) -> Result<Self, ObjectIdError>
    where
        T: FileDescriptionBacking,
    {
        Self::concrete_restored_with_common(
            stable_id,
            backing,
            Arc::new(DescriptionCommon::new(status_flags)),
        )
    }

    pub fn regular(id: FileDescriptionId) -> Self {
        Self {
            id,
            kind: FileDescriptionKind::Regular,
            common: Arc::new(DescriptionCommon::new(0)),
            lifecycle_transition: Mutex::new(DescriptionLifecycle::default()),
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
            delegation_handle: std::sync::atomic::AtomicU32::new(0),
            el1_registration: std::sync::OnceLock::new(),
        }
    }

    pub fn epoll(id: FileDescriptionId) -> Self {
        Self {
            id,
            kind: FileDescriptionKind::Epoll(Mutex::new(BTreeMap::new())),
            common: Arc::new(DescriptionCommon::new(0)),
            lifecycle_transition: Mutex::new(DescriptionLifecycle::default()),
            epoll_registrations: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
            delegation_handle: std::sync::atomic::AtomicU32::new(0),
            el1_registration: std::sync::OnceLock::new(),
        }
    }

    pub fn delegation_handle(&self) -> u32 {
        self.delegation_handle
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn set_delegation_handle(&self, handle: u32) {
        self.delegation_handle
            .store(handle, std::sync::atomic::Ordering::Release);
    }

    /// Attach the EL1 inode registration; first caller wins.
    pub(crate) fn set_el1_registration(
        &self,
        registration: crate::el1_delegation::InodeOpenRegistration,
    ) {
        let _ = self.el1_registration.set(registration);
    }

    /// The host inode identity this description is registered under, if any.
    pub(crate) fn el1_identity(&self) -> Option<carrick_vfs::InodeIdentity> {
        self.el1_registration.get().map(|r| r.identity())
    }

    pub(crate) fn has_active_mappings(&self) -> bool {
        self.lifecycle_transition.lock().mapping_refs > 0
    }

    pub const fn id(&self) -> FileDescriptionId {
        self.id
    }

    pub fn is_epoll(&self) -> bool {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.is_epoll(),
            FileDescriptionKind::Regular => false,
            FileDescriptionKind::Epoll(_) => true,
        }
    }

    pub(crate) fn epoll_targets(&self) -> Option<Vec<Arc<Self>>> {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.epoll_targets(),
            FileDescriptionKind::Regular => None,
            FileDescriptionKind::Epoll(interests) => Some(
                interests
                    .lock()
                    .values()
                    .filter_map(Weak::upgrade)
                    .collect(),
            ),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn is_closed(&self) -> bool {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.is_closed(),
            _ => false,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn readiness(
        &self,
        interest: LinuxEpollEvents,
        cx: &dyn ReadinessContext,
    ) -> LinuxEpollEvents {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.readiness(self.id, interest, cx),
            FileDescriptionKind::Regular => {
                interest & (LinuxEpollEvents::IN | LinuxEpollEvents::OUT)
            }
            FileDescriptionKind::Epoll(_) => LinuxEpollEvents::empty(),
        }
    }

    pub(crate) fn listener_readiness(
        &self,
        interest: LinuxEpollEvents,
    ) -> Option<ListenerReadinessSample> {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.listener_readiness(interest),
            FileDescriptionKind::Regular | FileDescriptionKind::Epoll(_) => None,
        }
    }

    pub(crate) fn wait_queue(&self) -> Option<Arc<super::wait_set::WaitQueue>> {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.wait_queue(),
            _ => None,
        }
    }

    pub(crate) fn register_epoll_owner(self: &Arc<Self>, owner: &Arc<Self>, registration_fd: i32) {
        self.epoll_registrations
            .lock()
            .insert((owner.id(), registration_fd), Arc::downgrade(owner));
        self.revision.publish();
    }

    pub(crate) fn unregister_epoll_owner(&self, owner: &Arc<Self>, registration_fd: i32) {
        if self
            .epoll_registrations
            .lock()
            .remove(&(owner.id(), registration_fd))
            .is_some()
        {
            self.revision.publish();
        }
    }

    /// The live epoll descriptions holding a registration whose target is
    /// this description, without disturbing the registry. A close that is
    /// not the description's final reference consults exactly these owners;
    /// no other epoll instance can hold a registration naming it.
    pub(crate) fn epoll_owners(&self) -> Vec<Arc<Self>> {
        let mut owners: Vec<Arc<Self>> = Vec::new();
        for owner in self.epoll_registrations.lock().values() {
            if let Some(owner) = owner.upgrade()
                && !owners.iter().any(|seen| Arc::ptr_eq(seen, &owner))
            {
                owners.push(owner);
            }
        }
        owners
    }

    pub(crate) fn take_epoll_owners(&self) -> Vec<(Arc<Self>, i32)> {
        let registrations = std::mem::take(&mut *self.epoll_registrations.lock());
        if !registrations.is_empty() {
            self.revision.publish();
        }
        registrations
            .into_iter()
            .filter_map(|((_, fd), owner)| owner.upgrade().map(|owner| (owner, fd)))
            .collect()
    }

    pub(crate) fn concrete_backing<T>(&self) -> Option<&T>
    where
        T: FileDescriptionBacking,
    {
        let FileDescriptionKind::Concrete(backing) = &self.kind else {
            return None;
        };
        backing.downcast_ref()
    }

    pub(crate) fn publish_mutation(&self) -> u64 {
        self.revision.publish()
    }

    pub(crate) fn set_pipe_capacity_from_authority(
        &self,
        capacity: i64,
        accounting: PipeCapacityAccounting,
    ) -> Result<u64, PipeCapacityMutationError> {
        let _guard = self.lifecycle_transition.lock();
        let FileDescriptionKind::Concrete(backing) = &self.kind else {
            return Err(PipeCapacityMutationError::NotPipe);
        };
        backing
            .0
            .set_pipe_capacity_from_authority(capacity, accounting)?;
        let revision = self.revision.publish();
        Ok(revision)
    }

    pub(crate) fn retain_fd_ref(&self) {
        crate::el1_delegation::recall_if_delegated(self);
        let _guard = self.lifecycle_transition.lock();
        let count = self.common.retain_fd_ref();
        if count == 1 {
            if let FileDescriptionKind::Concrete(backing) = &self.kind {
                backing.0.on_first_fd_ref();
            }
        }
        self.revision.publish();
    }

    /// Retain an exact live descriptor authority for asynchronous I/O.
    ///
    /// The check and increment share `lifecycle_transition` with final close:
    /// callers can therefore retain a live endpoint before acquiring an
    /// endpoint-specific lock, but can never resurrect a description after its
    /// final fd reference has published its close side effects.
    pub(crate) fn retain_fd_lease(self: &Arc<Self>) -> Option<FileDescriptionFdLease> {
        let _guard = self.lifecycle_transition.lock();
        if self.common.fd_refs() == 0 {
            return None;
        }
        self.common.retain_fd_ref();
        self.revision.publish();
        Some(FileDescriptionFdLease {
            description: Arc::clone(self),
        })
    }

    /// Attach final work to this exact live description.
    ///
    /// Callers must hold a `FileDescriptionFdLease` while registering and
    /// installing the associated state. A terminal description cannot accept a
    /// new finalizer, and repeated operations carrying the same description
    /// key retain one callback only.
    pub(crate) fn register_terminal_finalizer(
        &self,
        finalizer: Arc<dyn FileDescriptionFinalizer>,
    ) -> bool {
        let mut lifecycle = self.lifecycle_transition.lock();
        if self.common.fd_refs() == 0 {
            return false;
        }
        if lifecycle
            .terminal_finalizers
            .iter()
            .any(|current| current.key() == finalizer.key())
        {
            return true;
        }
        lifecycle.terminal_finalizers.push(finalizer);
        true
    }

    pub(crate) fn release_fd_ref(&self) {
        // Only the last fd reference ends an EL1 delegation: a transient
        // reference (a dup, an in-flight syscall's lease) coming and going is
        // not an ownership change. Recall runs outside `lifecycle_transition`,
        // which is ordered before the description guard.
        if self.common.fd_refs() <= 1 {
            crate::el1_delegation::recall_if_delegated(self);
        }
        let released_last;
        let terminal_finalizers = {
            let mut lifecycle = self.lifecycle_transition.lock();
            let count = self.common.release_fd_ref();
            released_last = count == 0;
            if count == 0 {
                if let FileDescriptionKind::Concrete(backing) = &self.kind {
                    backing.0.on_last_fd_ref();
                    if lifecycle.mapping_refs == 0 {
                        backing.0.on_last_resource_ref();
                    }
                }
                std::mem::take(&mut lifecycle.terminal_finalizers)
            } else {
                Vec::new()
            }
        };
        // Two releases that both saw another reference outstanding can reach
        // zero together; the description (and its host fd) is still alive, so
        // write the delegation back now.
        if released_last {
            crate::el1_delegation::recall_if_delegated(self);
        }
        // A finalizer may take subsystem state (for example logical-record
        // locks). Do not nest that under `lifecycle_transition`; the terminal
        // count has already made further lease admission impossible.
        for finalizer in terminal_finalizers {
            finalizer.finalize();
        }
        self.revision.publish();
    }

    /// Acquire while an fd still owns the backing, serialized with final close.
    /// A mapping and an EL1 delegation never coexist: the delegation is
    /// recalled first, and a mapped description is never delegated.
    pub(crate) fn retain_mapping(self: &Arc<Self>) -> Option<Arc<MappedFileReference>> {
        crate::el1_delegation::recall_if_delegated(self);
        let mut lifecycle = self.lifecycle_transition.lock();
        if self.common.fd_refs() == 0 {
            return None;
        }
        lifecycle.mapping_refs = lifecycle.mapping_refs.checked_add(1).unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::file_description_refs",
                "mapped file reference count overflow"
            );
        });
        self.revision.publish();
        Some(Arc::new(MappedFileReference {
            description: Arc::clone(self),
        }))
    }

    pub(crate) fn fd_ref_count(&self) -> usize {
        self.common.fd_refs()
    }

    pub(crate) fn clear_splice_pushback(&self) {
        self.common.clear_splice_pushback();
    }

    pub fn add_epoll_interest(
        self: &Arc<Self>,
        target: &Arc<Self>,
    ) -> Result<(), ObjectGraphError> {
        let FileDescriptionKind::Epoll(interests) = &self.kind else {
            return Err(ObjectGraphError::NotEpoll(self.id));
        };
        if self.id == target.id {
            return Err(ObjectGraphError::SelfEpollInterest(self.id));
        }
        if target.is_epoll() {
            return Err(ObjectGraphError::NestedEpollInterest(target.id));
        }
        let mut interests = interests.lock();
        interests.insert(target.id, Arc::downgrade(target));
        self.revision.publish();
        Ok(())
    }

    pub fn live_epoll_interest_count(&self) -> Result<usize, ObjectGraphError> {
        let FileDescriptionKind::Epoll(interests) = &self.kind else {
            return Err(ObjectGraphError::NotEpoll(self.id));
        };
        let mut interests = interests.lock();
        let before = interests.len();
        interests.retain(|_, target| target.strong_count() != 0);
        if interests.len() != before {
            self.revision.publish();
        }
        Ok(interests.len())
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileDescriptionObservation> {
        let owners = self.epoll_registrations.try_lock_until(deadline)?;
        let mut owners = owners
            .iter()
            .filter_map(|(&(owner, fd), weak)| (weak.strong_count() != 0).then_some((owner, fd)))
            .collect::<Vec<_>>();
        owners.sort_unstable();
        let status_flags = self.common.status_flags();
        let logical_fd_refs = self.common.fd_refs();
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => {
                let state = backing.0.snapshot_until(deadline)?;
                let is_epoll = state.kind() == FileDescriptionBackingKind::Epoll;
                let interests = state.epoll_interests().to_vec();
                Some((
                    self.revision.load(),
                    is_epoll,
                    interests,
                    Some(state),
                    owners,
                    status_flags,
                    logical_fd_refs,
                ))
            }
            FileDescriptionKind::Regular => Some((
                self.revision.load(),
                false,
                Vec::new(),
                None,
                owners,
                status_flags,
                logical_fd_refs,
            )),
            FileDescriptionKind::Epoll(interests) => {
                let interests = interests.try_lock_until(deadline)?;
                Some((
                    self.revision.load(),
                    true,
                    interests
                        .iter()
                        .filter_map(|(id, target)| (target.strong_count() != 0).then_some(*id))
                        .collect(),
                    None,
                    owners,
                    status_flags,
                    logical_fd_refs,
                ))
            }
        }
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }

    #[cfg(test)]
    pub(crate) fn revision_for_test(&self) -> u64 {
        self.revision()
    }

    #[cfg(test)]
    pub(crate) fn snapshot_for_test(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileDescriptionObservation> {
        self.snapshot_until(deadline)
    }
}

/// A functional descriptor reference retained for a syscall that may complete
/// after its numeric fd has been closed or reused.
#[derive(Debug)]
pub struct FileDescriptionFdLease {
    description: Arc<FileDescription>,
}

impl Clone for FileDescriptionFdLease {
    fn clone(&self) -> Self {
        // This lease itself keeps the description functionally live, so this
        // increment cannot resurrect a retired endpoint.
        self.description.retain_fd_ref();
        Self {
            description: Arc::clone(&self.description),
        }
    }
}

impl Drop for FileDescriptionFdLease {
    fn drop(&mut self) {
        self.description.release_fd_ref();
    }
}

impl FileDescriptionFdLease {
    /// The exact description whose functional lifetime this lease pins.
    /// Callers must not re-resolve the numeric fd after asynchronous admission.
    pub(crate) fn description(&self) -> &Arc<FileDescription> {
        &self.description
    }
}

#[derive(Clone, Debug)]
pub struct FileSlot {
    pub(crate) description: Arc<FileDescription>,
    pub(crate) fd_flags: u64,
    generation: u64,
}

impl FileSlot {
    pub(crate) fn new(description: Arc<FileDescription>, fd_flags: u64) -> Self {
        Self {
            description,
            fd_flags,
            generation: next_file_slot_generation(),
        }
    }

    pub fn description(&self) -> Arc<FileDescription> {
        Arc::clone(&self.description)
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub fn close_on_exec(&self) -> bool {
        carrick_abi::LinuxFdFlags::from_bits_truncate(self.fd_flags)
            .contains(carrick_abi::LinuxFdFlags::CLOEXEC)
    }

    #[allow(dead_code)]
    pub(crate) fn wait_queue(&self) -> Option<Arc<super::wait_set::WaitQueue>> {
        self.description.wait_queue()
    }
}

#[derive(Debug)]
pub struct FileSlotReservation {
    table: Arc<FileTable>,
    fd: i32,
    reservation_id: u64,
    committed: bool,
}

impl FileSlotReservation {
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    pub const fn reservation_id(&self) -> u64 {
        self.reservation_id
    }

    pub fn table(&self) -> &Arc<FileTable> {
        &self.table
    }

    pub fn commit(mut self, slot: FileSlot) -> Result<(), crate::linux_abi::LinuxErrno> {
        let res = self
            .table
            .commit_reserved_slot(self.fd, self.reservation_id, slot);
        if res.is_ok() {
            self.committed = true;
        }
        res
    }
}

impl Drop for FileSlotReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.table.cancel_reservation(self.fd, self.reservation_id);
        }
    }
}

#[derive(Debug)]
pub struct ExactSlotReservation {
    table: Arc<FileTable>,
    fd: i32,
    reservation_id: u64,
    committed: bool,
}

impl ExactSlotReservation {
    pub const fn fd(&self) -> i32 {
        self.fd
    }

    pub const fn reservation_id(&self) -> u64 {
        self.reservation_id
    }

    pub fn table(&self) -> &Arc<FileTable> {
        &self.table
    }

    pub fn commit(
        mut self,
        slot: FileSlot,
    ) -> Result<Option<FileSlot>, crate::linux_abi::LinuxErrno> {
        let res = self
            .table
            .commit_exact_replacement(self.fd, self.reservation_id, slot);
        if res.is_ok() {
            self.committed = true;
        }
        res
    }
}

impl Drop for ExactSlotReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.table.cancel_reservation(self.fd, self.reservation_id);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileSlotAuthority {
    table: FileTableId,
    number: FileSlotNumber,
    slot_generation: u64,
    description: FileDescriptionId,
}

impl FileSlotAuthority {
    pub const fn table(self) -> FileTableId {
        self.table
    }

    pub const fn number(self) -> FileSlotNumber {
        self.number
    }

    pub const fn slot_generation(self) -> u64 {
        self.slot_generation
    }

    pub const fn description(self) -> FileDescriptionId {
        self.description
    }
}

type FileSlotCallback = Arc<dyn Fn(FileSlotAuthority) + Send + Sync + 'static>;

#[derive(Default)]
struct FileSlotSubscriptions {
    listeners: Mutex<BTreeMap<u64, (FileSlotAuthority, FileSlotCallback)>>,
}

impl std::fmt::Debug for FileSlotSubscriptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileSlotSubscriptions")
            .field("listeners", &self.listeners.lock().len())
            .finish()
    }
}

impl FileSlotSubscriptions {
    /// Retire and notify every listener whose authority no longer resolves to
    /// its slot. Only the slot numbers in `changed` can have moved, so the
    /// listeners on every other number are provably still current and are
    /// not re-examined.
    fn publish_changes(&self, table: FileTableId, slots: &FileSlotMap, changed: &[i32]) {
        let callbacks = {
            let mut listeners = self.listeners.lock();
            let stale = listeners
                .iter()
                .filter_map(|(id, (authority, _))| {
                    if !changed.contains(&authority.number.raw()) {
                        return None;
                    }
                    let matches = authority.table == table
                        && slots.get(&authority.number.raw()).is_some_and(|slot| {
                            slot.generation == authority.slot_generation
                                && slot.description.id() == authority.description
                        });
                    (!matches).then_some(*id)
                })
                .collect::<Vec<_>>();
            stale
                .into_iter()
                .filter_map(|id| listeners.remove(&id))
                .collect::<Vec<_>>()
        };
        for (authority, callback) in callbacks {
            callback(authority);
        }
    }
}

pub struct FileSlotSubscription {
    subscriptions: Weak<FileSlotSubscriptions>,
    listener: u64,
}

impl Drop for FileSlotSubscription {
    fn drop(&mut self) {
        if let Some(subscriptions) = self.subscriptions.upgrade() {
            subscriptions.listeners.lock().remove(&self.listener);
        }
    }
}

pub(super) struct FileTableStateSnapshot {
    pub(super) revision: u64,
    pub(super) functional_refs_active: bool,
    pub(super) slots: Vec<(FileSlotNumber, FileSlot)>,
    pub(super) next_fd: i32,
    pub(super) stdio_cloexec: [bool; 3],
    pub(super) closed_stdio: [bool; 3],
    pub(super) fd_open_paths: Vec<(FileSlotNumber, String)>,
    pub(super) epoll_fds: Vec<FileSlotNumber>,
}

#[derive(Debug, Default)]
struct FileTableFunctionalState {
    accepting: bool,
    frozen: bool,
    active_uses: usize,
    active_mutations: usize,
}

#[derive(Debug)]
struct FileTableFunctionalGate {
    state: Mutex<FileTableFunctionalState>,
    changed: Condvar,
}

impl FileTableFunctionalGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(FileTableFunctionalState {
                accepting: true,
                ..FileTableFunctionalState::default()
            }),
            changed: Condvar::new(),
        }
    }

    fn acquire_use(self: &Arc<Self>) -> Option<FileTableFunctionalLease> {
        let mut state = self.state.lock();
        while state.accepting && state.frozen {
            self.changed.wait(&mut state);
        }
        if !state.accepting {
            return None;
        }
        state.active_uses = state.active_uses.checked_add(1)?;
        Some(FileTableFunctionalLease {
            gate: Arc::clone(self),
        })
    }

    fn acquire_mutation(self: &Arc<Self>) -> Option<FileTableMutationLease> {
        let mut state = self.state.lock();
        while state.accepting && state.frozen {
            self.changed.wait(&mut state);
        }
        if !state.accepting {
            return None;
        }
        state.active_mutations = state.active_mutations.checked_add(1)?;
        Some(FileTableMutationLease {
            gate: Arc::clone(self),
        })
    }

    fn freeze(self: &Arc<Self>) -> Option<FileTableExecFreeze> {
        let mut state = self.state.lock();
        while state.accepting && state.frozen {
            self.changed.wait(&mut state);
        }
        if !state.accepting {
            return None;
        }
        state.frozen = true;
        while state.active_uses != 0 || state.active_mutations != 0 {
            self.changed.wait(&mut state);
        }
        Some(FileTableExecFreeze {
            gate: Arc::clone(self),
            active: true,
        })
    }

    #[cfg(test)]
    fn is_frozen(&self) -> bool {
        self.state.lock().frozen
    }

    fn retire(&self) -> bool {
        let mut state = self.state.lock();
        if !state.accepting {
            return false;
        }
        state.accepting = false;
        self.changed.notify_all();
        while state.active_uses != 0 || state.active_mutations != 0 {
            self.changed.wait(&mut state);
        }
        true
    }
}

pub struct FileTableFunctionalLease {
    gate: Arc<FileTableFunctionalGate>,
}

impl Drop for FileTableFunctionalLease {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        state.active_uses = state.active_uses.checked_sub(1).unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::file_table_gate",
                "FileTable active functional lease count underflow"
            );
        });
        self.gate.changed.notify_all();
    }
}

struct FileTableMutationLease {
    gate: Arc<FileTableFunctionalGate>,
}

impl Drop for FileTableMutationLease {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        state.active_mutations = state.active_mutations.checked_sub(1).unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::file_table_gate",
                "FileTable active mutation lease count underflow"
            );
        });
        self.gate.changed.notify_all();
    }
}

pub(super) struct FileTableExecFreeze {
    gate: Arc<FileTableFunctionalGate>,
    active: bool,
}

impl Drop for FileTableExecFreeze {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.gate.state.lock();
        state.frozen = false;
        self.gate.changed.notify_all();
        self.active = false;
    }
}

/// Collision-free hashing for the signed 32-bit descriptor-number domain.
///
/// Guest code controls descriptor values, but each `i32` maps to a distinct
/// `u64`, so this avoids both collision attacks and the SipHash work that
/// otherwise dominated fd-fill workloads. Keep this private to the typed fd
/// table; arbitrary byte keys must continue using a keyed hasher.
#[derive(Default)]
pub struct FileSlotHasher(u64);

impl Hasher for FileSlotHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // `Hash for i32` calls `write_i32`; retain a deterministic fallback so
        // the Hasher contract remains total if that implementation changes.
        self.0 = bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
    }

    fn write_i32(&mut self, value: i32) {
        self.0 = u64::from(value as u32);
    }
}

pub type FileSlotMap = HashMap<i32, FileSlot, BuildHasherDefault<FileSlotHasher>>;

#[derive(Debug)]
pub struct FileTable {
    id: FileTableId,
    fd_ceiling: Arc<FdCeilingAuthority>,
    open_files: RwLock<FileSlotMap>,
    next_fd: Mutex<i32>,
    reserved_slots: Mutex<HashMap<i32, u64>>,
    next_reservation_id: AtomicU64,
    stdio_cloexec: Mutex<[bool; 3]>,
    closed_stdio: Mutex<[bool; 3]>,
    fd_open_paths: RwLock<HashMap<i32, String>>,
    epoll_fds: RwLock<BTreeSet<i32>>,
    epoll_wake_registry: crate::dispatch::EpollWakeRegistry,
    functional_gate: Arc<FileTableFunctionalGate>,
    functional_refs_active: AtomicBool,
    revision: ObjectRevision,
    slot_subscriptions: Arc<FileSlotSubscriptions>,
}

impl FileTable {
    pub fn new(id: FileTableId) -> Self {
        Self::with_fd_ceiling(id, Arc::new(FdCeilingAuthority::new()))
    }

    pub fn with_fd_ceiling(id: FileTableId, fd_ceiling: Arc<FdCeilingAuthority>) -> Self {
        Self {
            id,
            fd_ceiling,
            open_files: RwLock::new(FileSlotMap::default()),
            next_fd: Mutex::new(3),
            reserved_slots: Mutex::new(HashMap::new()),
            next_reservation_id: AtomicU64::new(0),
            stdio_cloexec: Mutex::new([false; 3]),
            closed_stdio: Mutex::new([false; 3]),
            fd_open_paths: RwLock::new(HashMap::new()),
            epoll_fds: RwLock::new(BTreeSet::new()),
            epoll_wake_registry: crate::dispatch::new_epoll_wake_registry(),
            functional_gate: Arc::new(FileTableFunctionalGate::new()),
            functional_refs_active: AtomicBool::new(true),
            revision: ObjectRevision::new(),
            slot_subscriptions: Arc::new(FileSlotSubscriptions::default()),
        }
    }

    pub(crate) fn for_fork_copy(id: FileTableId, parent: &Self) -> Self {
        let open_files = parent.open_files.read().clone();
        for slot in open_files.values() {
            crate::el1_delegation::recall_if_delegated(&slot.description);
            slot.description.retain_fd_ref();
        }
        let epoll_wake_registry = Arc::clone(&parent.epoll_wake_registry);
        let mut child_next_fd = 3;
        while open_files.contains_key(&child_next_fd) {
            let Some(next) = child_next_fd.checked_add(1) else {
                break;
            };
            child_next_fd = next;
        }
        let _ = *parent.next_fd.lock();
        let stdio_cloexec = *parent.stdio_cloexec.lock();
        let closed_stdio = *parent.closed_stdio.lock();
        let fd_open_paths = {
            let guard = parent.fd_open_paths.read();
            if guard.is_empty() {
                HashMap::new()
            } else {
                guard.clone()
            }
        };
        let epoll_fds = {
            let guard = parent.epoll_fds.read();
            if guard.is_empty() {
                BTreeSet::new()
            } else {
                guard.clone()
            }
        };
        Self {
            id,
            fd_ceiling: Arc::clone(&parent.fd_ceiling),
            open_files: RwLock::new(open_files),
            next_fd: Mutex::new(child_next_fd),
            reserved_slots: Mutex::new(HashMap::new()),
            next_reservation_id: AtomicU64::new(0),
            stdio_cloexec: Mutex::new(stdio_cloexec),
            closed_stdio: Mutex::new(closed_stdio),
            fd_open_paths: RwLock::new(fd_open_paths),
            epoll_fds: RwLock::new(epoll_fds),
            epoll_wake_registry,
            functional_gate: Arc::new(FileTableFunctionalGate::new()),
            functional_refs_active: AtomicBool::new(true),
            revision: ObjectRevision::new(),
            slot_subscriptions: Arc::new(FileSlotSubscriptions::default()),
        }
    }

    pub(super) fn for_external_exec(id: FileTableId, fd_ceiling: Arc<FdCeilingAuthority>) -> Self {
        Self::with_fd_ceiling(id, fd_ceiling)
    }

    fn for_exec(id: FileTableId, caller: &Self) -> Self {
        let open_files: FileSlotMap = caller
            .open_files
            .read()
            .iter()
            .filter_map(|(number, slot)| (!slot.close_on_exec()).then_some((*number, slot.clone())))
            .collect();
        for slot in open_files.values() {
            slot.description.retain_fd_ref();
        }
        let mut closed_stdio = *caller.closed_stdio.lock();
        for (closed, close_on_exec) in closed_stdio
            .iter_mut()
            .zip(caller.stdio_cloexec.lock().iter())
        {
            *closed |= *close_on_exec;
        }
        let epoll_wake_registry = Arc::clone(&caller.epoll_wake_registry);
        if let Some(maximum) = open_files.keys().max() {
            caller.fd_ceiling.publish(*maximum);
        }
        let mut next_fd = 3;
        while open_files.contains_key(&next_fd) {
            let Some(next) = next_fd.checked_add(1) else {
                break;
            };
            next_fd = next;
        }
        let _ = *caller.next_fd.lock();
        let fd_open_paths = caller
            .fd_open_paths
            .read()
            .iter()
            .filter_map(|(number, path)| {
                open_files
                    .contains_key(number)
                    .then_some((*number, path.clone()))
            })
            .collect();
        let epoll_fds = caller
            .epoll_fds
            .read()
            .iter()
            .filter_map(|number| open_files.contains_key(number).then_some(*number))
            .collect();
        Self {
            id,
            fd_ceiling: Arc::clone(&caller.fd_ceiling),
            open_files: RwLock::new(open_files),
            next_fd: Mutex::new(next_fd),
            reserved_slots: Mutex::new(HashMap::new()),
            next_reservation_id: AtomicU64::new(0),
            stdio_cloexec: Mutex::new([false; 3]),
            closed_stdio: Mutex::new(closed_stdio),
            fd_open_paths: RwLock::new(fd_open_paths),
            epoll_fds: RwLock::new(epoll_fds),
            epoll_wake_registry,
            functional_gate: Arc::new(FileTableFunctionalGate::new()),
            functional_refs_active: AtomicBool::new(true),
            revision: ObjectRevision::new(),
            slot_subscriptions: Arc::new(FileSlotSubscriptions::default()),
        }
    }

    pub const fn id(&self) -> FileTableId {
        self.id
    }

    pub fn reserve_exact_target(
        self: &Arc<Self>,
        fd: i32,
        limit: i32,
    ) -> Result<ExactSlotReservation, crate::linux_abi::LinuxErrno> {
        if !(0..limit).contains(&fd) {
            return Err(crate::linux_abi::LINUX_EBADF);
        }
        let _mutation = self
            .functional_gate
            .acquire_mutation()
            .ok_or(crate::linux_abi::LINUX_EBADF)?;
        let mut reserved = self.lock_reserved_slots();
        if reserved.contains_key(&fd) {
            return Err(crate::linux_abi::LINUX_EBUSY);
        }
        let reservation_id = self.next_reservation_id.fetch_add(1, Ordering::Relaxed) + 1;
        reserved.insert(fd, reservation_id);
        drop(reserved);

        Ok(ExactSlotReservation {
            table: Arc::clone(self),
            fd,
            reservation_id,
            committed: false,
        })
    }

    pub fn reserve_slot_at_or_above(
        self: &Arc<Self>,
        min_fd: i32,
        limit: i32,
    ) -> Result<FileSlotReservation, crate::linux_abi::LinuxErrno> {
        let _mutation = self
            .functional_gate
            .acquire_mutation()
            .ok_or(crate::linux_abi::LINUX_EBADF)?;
        let open_files = self.read_open_files();
        let mut next_fd = self.lock_next_fd();
        let mut reserved = self.lock_reserved_slots();
        let closed_stdio = self.lock_closed_stdio();

        let mut fd = None;

        // If min_fd < 3 and any stdio was closed, check closed stdio slots first
        if min_fd < 3 && (closed_stdio[0] || closed_stdio[1] || closed_stdio[2]) {
            for stdio in min_fd.max(0)..3 {
                if closed_stdio[stdio as usize]
                    && !open_files.contains_key(&stdio)
                    && !reserved.contains_key(&stdio)
                {
                    fd = Some(stdio);
                    break;
                }
            }
        }

        let fd = match fd {
            Some(stdio) => stdio,
            None => {
                let mut candidate = if min_fd < 3 {
                    *next_fd
                } else {
                    (*next_fd).max(min_fd)
                };

                loop {
                    if candidate >= limit {
                        return Err(crate::linux_abi::LINUX_EMFILE);
                    }

                    let reserved_stdio =
                        (0..3).contains(&candidate) && !closed_stdio[candidate as usize];
                    if !open_files.contains_key(&candidate)
                        && !reserved.contains_key(&candidate)
                        && !reserved_stdio
                    {
                        break candidate;
                    }

                    let Some(next) = candidate.checked_add(1) else {
                        return Err(crate::linux_abi::LINUX_EMFILE);
                    };
                    candidate = next;
                }
            }
        };

        if fd >= limit {
            return Err(crate::linux_abi::LINUX_EMFILE);
        }

        let reservation_id = self.next_reservation_id.fetch_add(1, Ordering::Relaxed) + 1;
        reserved.insert(fd, reservation_id);

        if fd >= 3 && fd == *next_fd {
            let mut candidate = fd.saturating_add(1);
            loop {
                let reserved_stdio =
                    (0..3).contains(&candidate) && !closed_stdio[candidate as usize];
                if !open_files.contains_key(&candidate)
                    && !reserved.contains_key(&candidate)
                    && !reserved_stdio
                {
                    break;
                }
                let Some(next) = candidate.checked_add(1) else {
                    break;
                };
                candidate = next;
            }
            *next_fd = candidate;
        }

        drop(closed_stdio);
        drop(reserved);
        drop(next_fd);
        drop(open_files);

        Ok(FileSlotReservation {
            table: Arc::clone(self),
            fd,
            reservation_id,
            committed: false,
        })
    }

    pub fn is_slot_reserved(&self, fd: i32) -> bool {
        self.lock_reserved_slots().contains_key(&fd)
    }

    pub(crate) fn cancel_reservation(&self, fd: i32, reservation_id: u64) -> bool {
        if fd >= 3 {
            if let Some(mut next_fd) = self.try_lock_next_fd() {
                let mut reserved = self.lock_reserved_slots();
                if reserved.get(&fd).copied() == Some(reservation_id) {
                    reserved.remove(&fd);
                    if fd < *next_fd {
                        *next_fd = fd;
                    }
                    return true;
                }
                return false;
            }
        }
        let mut reserved = self.lock_reserved_slots();
        if reserved.get(&fd).copied() == Some(reservation_id) {
            reserved.remove(&fd);
            true
        } else {
            false
        }
    }

    pub(crate) fn commit_reserved_slot(
        &self,
        fd: i32,
        reservation_id: u64,
        slot: FileSlot,
    ) -> Result<(), crate::linux_abi::LinuxErrno> {
        let _mutation = self
            .functional_gate
            .acquire_mutation()
            .ok_or(crate::linux_abi::LINUX_EBADF)?;
        let mut open_files = self.write_open_files();
        let mut next_fd = self.lock_next_fd();
        let mut reserved = self.lock_reserved_slots();

        if reserved.get(&fd).copied() != Some(reservation_id) {
            return Err(crate::linux_abi::LINUX_EBADF);
        }

        if open_files.contains_key(&fd) {
            return Err(crate::linux_abi::LINUX_EBUSY);
        }

        reserved.remove(&fd);
        open_files.insert(fd, slot);

        if (0..3).contains(&fd) {
            self.lock_closed_stdio()[fd as usize] = false;
        }

        if fd >= 3 && fd == *next_fd {
            let mut candidate = fd.saturating_add(1);
            let closed = self.lock_closed_stdio();
            loop {
                let reserved_stdio = (0..3).contains(&candidate) && !closed[candidate as usize];
                if !open_files.contains_key(&candidate)
                    && !reserved.contains_key(&candidate)
                    && !reserved_stdio
                {
                    break;
                }
                let Some(next) = candidate.checked_add(1) else {
                    break;
                };
                candidate = next;
            }
            *next_fd = candidate;
        }

        Ok(())
    }

    pub(crate) fn commit_exact_replacement(
        &self,
        fd: i32,
        reservation_id: u64,
        slot: FileSlot,
    ) -> Result<Option<FileSlot>, crate::linux_abi::LinuxErrno> {
        let _mutation = self
            .functional_gate
            .acquire_mutation()
            .ok_or(crate::linux_abi::LINUX_EBADF)?;
        let mut open_files = self.write_open_files();
        let mut next_fd = self.lock_next_fd();
        let mut reserved = self.lock_reserved_slots();

        if reserved.get(&fd).copied() != Some(reservation_id) {
            return Err(crate::linux_abi::LINUX_EBADF);
        }

        reserved.remove(&fd);
        let replaced = open_files.insert(fd, slot);

        if (0..3).contains(&fd) {
            self.lock_closed_stdio()[fd as usize] = false;
        }

        if fd >= 3 && fd == *next_fd {
            let mut candidate = fd.saturating_add(1);
            let closed = self.lock_closed_stdio();
            loop {
                let reserved_stdio = (0..3).contains(&candidate) && !closed[candidate as usize];
                if !open_files.contains_key(&candidate)
                    && !reserved.contains_key(&candidate)
                    && !reserved_stdio
                {
                    break;
                }
                let Some(next) = candidate.checked_add(1) else {
                    break;
                };
                candidate = next;
            }
            *next_fd = candidate;
        }

        Ok(replaced)
    }

    pub fn install(
        &self,
        number: FileSlotNumber,
        description: Arc<FileDescription>,
        close_on_exec: bool,
    ) -> Option<FileSlot> {
        let _mutation = self.mutation_lease();
        let mut open_files = self.open_files.write();
        self.fd_ceiling.publish(number.raw());
        let replaced = open_files.insert(
            number.raw(),
            FileSlot::new(
                description,
                u64::from(close_on_exec) * crate::linux_abi::LINUX_FD_CLOEXEC,
            ),
        );
        self.revision.publish();
        self.slot_subscriptions
            .publish_changes(self.id, &open_files, &[number.raw()]);
        replaced
    }

    pub fn capture_slot_authority(&self, number: FileSlotNumber) -> Option<FileSlotAuthority> {
        let slot = self.open_files.read().get(&number.raw()).cloned()?;
        Some(FileSlotAuthority {
            table: self.id,
            number,
            slot_generation: slot.generation,
            description: slot.description.id(),
        })
    }

    /// Snapshot one live slot and its authenticated identity under the same
    /// table read guard. The returned `FileSlot` is only a classification
    /// snapshot; asynchronous admission must use [`Self::retain_slot_lease`].
    pub(crate) fn capture_open_slot_authority(
        &self,
        number: FileSlotNumber,
    ) -> Option<(FileSlot, FileSlotAuthority)> {
        let slots = self.open_files.read();
        let slot = slots.get(&number.raw())?;
        Some((
            slot.clone(),
            FileSlotAuthority {
                table: self.id,
                number,
                slot_generation: slot.generation,
                description: slot.description.id(),
            },
        ))
    }

    pub fn is_bare_stdio_open(&self, raw: i32) -> bool {
        (0..3).contains(&raw) && !self.lock_closed_stdio()[raw as usize]
    }

    pub fn capture_slot_or_stdio_authority(
        &self,
        number: FileSlotNumber,
    ) -> Option<FileSlotAuthority> {
        if let Some(authority) = self.capture_slot_authority(number) {
            return Some(authority);
        }
        let raw = number.raw();
        if self.is_bare_stdio_open(raw) {
            let description = FileDescriptionId::from_raw_u64(u64::MAX - raw as u64)?;
            return Some(FileSlotAuthority {
                table: self.id,
                number,
                slot_generation: 0,
                description,
            });
        }
        None
    }

    pub fn validate_slot_authority(&self, authority: FileSlotAuthority) -> bool {
        if authority.table != self.id {
            return false;
        }
        if let Some(slot) = self.open_files.read().get(&authority.number.raw()) {
            return slot.generation == authority.slot_generation
                && slot.description.id() == authority.description;
        }
        let raw = authority.number.raw();
        if self.is_bare_stdio_open(raw) {
            let Some(expected_desc) = FileDescriptionId::from_raw_u64(u64::MAX - raw as u64) else {
                return false;
            };
            return authority.slot_generation == 0 && authority.description == expected_desc;
        }
        false
    }

    fn resolve_slot_from_guard(
        open_files: &FileSlotMap,
        authority: FileSlotAuthority,
    ) -> Option<Arc<FileDescription>> {
        let slot = open_files.get(&authority.number.raw())?;
        if slot.generation == authority.slot_generation
            && slot.description.id() == authority.description
        {
            Some(Arc::clone(&slot.description))
        } else {
            None
        }
    }

    pub fn resolve_slot_authority(
        &self,
        authority: FileSlotAuthority,
    ) -> Option<Arc<FileDescription>> {
        if authority.table != self.id {
            return None;
        }
        let open_files = self.open_files.read();
        Self::resolve_slot_from_guard(&open_files, authority)
    }

    /// Retain a functional I/O lease only if `authority` still names the same
    /// live slot. Holding the table read guard through the retain makes close
    /// or reuse linearize either wholly before admission (stale → `None`) or
    /// after the exact description has been pinned.
    pub(crate) fn retain_slot_lease(
        &self,
        authority: FileSlotAuthority,
    ) -> Option<FileDescriptionFdLease> {
        if authority.table != self.id {
            return None;
        }
        let open_files = self.open_files.read();
        let description = Self::resolve_slot_from_guard(&open_files, authority)?;
        description.retain_fd_lease()
    }

    #[cfg(test)]
    pub(crate) fn retain_slot_lease_with_hook<F>(
        &self,
        authority: FileSlotAuthority,
        on_guard_acquired: F,
    ) -> Option<FileDescriptionFdLease>
    where
        F: FnOnce(),
    {
        if authority.table != self.id {
            return None;
        }
        let open_files = self.open_files.read();
        on_guard_acquired();
        let description = Self::resolve_slot_from_guard(&open_files, authority)?;
        description.retain_fd_lease()
    }

    #[cfg(test)]
    pub(crate) fn resolve_slot_authority_with_hook<F>(
        &self,
        authority: FileSlotAuthority,
        on_guard_acquired: F,
    ) -> Option<Arc<FileDescription>>
    where
        F: FnOnce(),
    {
        if authority.table != self.id {
            return None;
        }
        let open_files = self.open_files.read();
        on_guard_acquired();
        Self::resolve_slot_from_guard(&open_files, authority)
    }

    pub fn subscribe_slot_authority(
        self: &Arc<Self>,
        authority: FileSlotAuthority,
        callback: FileSlotCallback,
    ) -> Option<FileSlotSubscription> {
        let open_files = self.open_files.read();
        if authority.table != self.id
            || open_files.get(&authority.number.raw()).is_none_or(|slot| {
                slot.generation != authority.slot_generation
                    || slot.description.id() != authority.description
            })
        {
            return None;
        }
        let listener = next_file_slot_generation();
        self.slot_subscriptions
            .listeners
            .lock()
            .insert(listener, (authority, callback));
        Some(FileSlotSubscription {
            subscriptions: Arc::downgrade(&self.slot_subscriptions),
            listener,
        })
    }

    pub fn slot(&self, number: FileSlotNumber) -> Option<FileSlot> {
        self.open_files.read().get(&number.raw()).cloned()
    }

    pub fn slot_count(&self) -> usize {
        self.open_files.read().len()
    }

    pub(crate) fn read_open_files(&self) -> RwLockReadGuard<'_, FileSlotMap> {
        self.open_files.read()
    }

    pub(crate) fn write_open_files(&self) -> FileTableWriteGuard<'_> {
        let mutation = self.mutation_lease();
        let guard = self.open_files.write();
        FileTableWriteGuard {
            guard,
            _mutation: mutation,
            fd_ceiling: &self.fd_ceiling,
            revision: &self.revision,
            table: self.id,
            subscriptions: &self.slot_subscriptions,
            touched: Vec::new(),
        }
    }

    fn try_lock_next_fd(&self) -> Option<FileTableMutexGuard<'_, i32>> {
        self.try_mutex_write(&self.next_fd)
    }

    pub(crate) fn lock_next_fd(&self) -> FileTableMutexGuard<'_, i32> {
        self.mutex_write(&self.next_fd)
    }

    pub(crate) fn lock_stdio_cloexec(&self) -> FileTableMutexGuard<'_, [bool; 3]> {
        self.mutex_write(&self.stdio_cloexec)
    }

    pub(crate) fn lock_closed_stdio(&self) -> FileTableMutexGuard<'_, [bool; 3]> {
        self.mutex_write(&self.closed_stdio)
    }

    pub(crate) fn lock_reserved_slots(&self) -> MutexGuard<'_, HashMap<i32, u64>> {
        self.reserved_slots.lock()
    }

    pub(crate) fn read_fd_open_paths(&self) -> RwLockReadGuard<'_, HashMap<i32, String>> {
        self.fd_open_paths.read()
    }

    pub(crate) fn write_fd_open_paths(&self) -> FileTableRwWriteGuard<'_, HashMap<i32, String>> {
        self.rw_write(&self.fd_open_paths)
    }

    pub(crate) fn record_fd_open_path(&self, fd: i32, path: String) {
        self.write_fd_open_paths().insert(fd, path);
    }

    pub(crate) fn rename_fd_open_paths(&self, resolved_old: &str, resolved_new: &str) {
        let mut fd_open_paths = self.write_fd_open_paths();
        for (_, open_path) in fd_open_paths.iter_mut() {
            if *open_path == resolved_old {
                *open_path = resolved_new.to_string();
            } else if open_path.starts_with(resolved_old)
                && open_path.as_bytes().get(resolved_old.len()) == Some(&b'/')
            {
                let rest = &open_path[resolved_old.len() + 1..];
                *open_path = format!("{resolved_new}/{rest}");
            }
        }
    }

    pub(crate) fn read_epoll_fds(&self) -> RwLockReadGuard<'_, BTreeSet<i32>> {
        self.epoll_fds.read()
    }

    pub(crate) fn write_epoll_fds(&self) -> FileTableRwWriteGuard<'_, BTreeSet<i32>> {
        self.rw_write(&self.epoll_fds)
    }

    pub(crate) fn epoll_wake_registry(&self) -> &crate::dispatch::EpollWakeRegistry {
        &self.epoll_wake_registry
    }

    /// Capture a registry-only capability for an asynchronous readiness wake.
    /// It intentionally does not retain this file table or any descriptor.
    pub(crate) fn epoll_wake_handle(&self) -> crate::dispatch::EpollWakeHandle {
        crate::dispatch::EpollWakeHandle::from_registry(&self.epoll_wake_registry)
    }

    pub(crate) fn functional_refs_active(&self) -> bool {
        self.functional_refs_active.load(Ordering::Acquire)
    }

    pub(crate) fn acquire_functional_lease(self: &Arc<Self>) -> Option<FileTableFunctionalLease> {
        self.functional_gate.acquire_use()
    }

    pub(super) fn freeze_for_exec(self: &Arc<Self>) -> Option<FileTableExecFreeze> {
        self.functional_gate.freeze()
    }

    #[cfg(test)]
    pub(crate) fn functional_gate_is_frozen(&self) -> bool {
        self.functional_gate.is_frozen()
    }

    pub(crate) fn drain_functional_refs(&self) -> Vec<(i32, FileSlot)> {
        self.functional_refs_active.store(false, Ordering::Release);
        if !self.functional_gate.retire() {
            return Vec::new();
        }
        let slots = self
            .open_files
            .read()
            .iter()
            .map(|(fd, slot)| (*fd, slot.clone()))
            .collect();
        self.revision.publish();
        slots
    }

    fn mutation_lease(&self) -> FileTableMutationLease {
        self.functional_gate.acquire_mutation().unwrap_or_else(|| {
            carrick_fatal!(
                "kernel::file_table_gate",
                "mutation reached a draining FileTable generation"
            );
        })
    }

    fn try_mutex_write<'a, T>(&'a self, lock: &'a Mutex<T>) -> Option<FileTableMutexGuard<'a, T>> {
        let mutation = self.functional_gate.acquire_mutation()?;
        Some(FileTableMutexGuard {
            guard: lock.lock(),
            _mutation: mutation,
            revision: &self.revision,
        })
    }

    fn mutex_write<'a, T>(&'a self, lock: &'a Mutex<T>) -> FileTableMutexGuard<'a, T> {
        let mutation = self.mutation_lease();
        FileTableMutexGuard {
            guard: lock.lock(),
            _mutation: mutation,
            revision: &self.revision,
        }
    }

    fn rw_write<'a, T>(&'a self, lock: &'a RwLock<T>) -> FileTableRwWriteGuard<'a, T> {
        let mutation = self.mutation_lease();
        FileTableRwWriteGuard {
            guard: lock.write(),
            _mutation: mutation,
            revision: &self.revision,
        }
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<FileTableStateSnapshot> {
        let revision = self.revision.load();
        let open_files = self.open_files.try_read_until(deadline)?;
        let next_fd = *self.next_fd.try_lock_until(deadline)?;
        let stdio_cloexec = *self.stdio_cloexec.try_lock_until(deadline)?;
        let closed_stdio = *self.closed_stdio.try_lock_until(deadline)?;
        let fd_open_paths = self.fd_open_paths.try_read_until(deadline)?;
        let epoll_fds = self.epoll_fds.try_read_until(deadline)?;

        let to_number = |fd| FileSlotNumber::for_open_fd(fd).ok();
        let mut slots = open_files
            .iter()
            .map(|(fd, slot)| Some((to_number(*fd)?, slot.clone())))
            .collect::<Option<Vec<_>>>()?;
        slots.sort_by_key(|(number, _)| *number);
        let mut paths = fd_open_paths
            .iter()
            .map(|(fd, path)| Some((to_number(*fd)?, path.clone())))
            .collect::<Option<Vec<_>>>()?;
        paths.sort_by_key(|(number, _)| *number);
        let sorted_numbers = |fds: Vec<i32>| {
            let mut numbers = fds.into_iter().map(to_number).collect::<Option<Vec<_>>>()?;
            numbers.sort_unstable();
            Some(numbers)
        };

        Some(FileTableStateSnapshot {
            revision,
            functional_refs_active: self.functional_refs_active(),
            slots,
            next_fd,
            stdio_cloexec,
            closed_stdio,
            fd_open_paths: paths,
            epoll_fds: sorted_numbers(epoll_fds.iter().copied().collect())?,
        })
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

impl Drop for FileTable {
    fn drop(&mut self) {
        if !self.functional_gate.retire() {
            return;
        }
        self.functional_refs_active.store(false, Ordering::Release);
        for slot in self.open_files.get_mut().values() {
            // Model-only descriptions and tests that install observational
            // slots directly carry no functional dispatch reference.
            if slot.description.fd_ref_count() != 0 {
                slot.description.release_fd_ref();
            }
        }
    }
}

/// Exclusive access to a table's slots. Mutation goes through the typed
/// `insert`/`remove`/`get_mut` methods so the guard knows exactly which slot
/// numbers moved: a `dup`/`open`/`close` costs the slots it touches, not the
/// size of the table. (The previous design snapshotted every slot on acquire
/// and re-walked every slot on release to discover changes, which made an
/// fd-fill loop quadratic — `dup` at 20k open fds cost ~1 ms, 6000x Linux.)
pub struct FileTableWriteGuard<'a> {
    guard: RwLockWriteGuard<'a, FileSlotMap>,
    _mutation: FileTableMutationLease,
    fd_ceiling: &'a FdCeilingAuthority,
    revision: &'a ObjectRevision,
    table: FileTableId,
    subscriptions: &'a FileSlotSubscriptions,
    /// Slot numbers this guard mutated. `None` marks an insert or a remove
    /// (the slot's identity is new or gone either way); `Some(id)` records the
    /// description a slot carried when it was first borrowed mutably, so an
    /// in-place description swap is detected on release while an fd-flag
    /// update keeps the slot's identity.
    touched: Vec<(i32, Option<FileDescriptionId>)>,
}

impl Deref for FileTableWriteGuard<'_> {
    type Target = FileSlotMap;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl FileTableWriteGuard<'_> {
    fn mark_replaced(&mut self, number: i32) {
        match self
            .touched
            .iter_mut()
            .find(|(touched, _)| *touched == number)
        {
            Some((_, before)) => *before = None,
            None => self.touched.push((number, None)),
        }
    }

    /// Install `slot` at `number`, returning the slot it displaced. The
    /// installed slot always receives a fresh generation: a number that is
    /// (re)populated is a new slot identity, whatever the caller built it from.
    pub(crate) fn insert(&mut self, number: i32, mut slot: FileSlot) -> Option<FileSlot> {
        slot.generation = next_file_slot_generation();
        self.mark_replaced(number);
        self.fd_ceiling.publish(number);
        self.guard.insert(number, slot)
    }

    pub(crate) fn remove(&mut self, number: &i32) -> Option<FileSlot> {
        let removed = self.guard.remove(number);
        if removed.is_some() {
            self.mark_replaced(*number);
        }
        removed
    }

    pub(crate) fn get_mut(&mut self, number: &i32) -> Option<&mut FileSlot> {
        let slot = self.guard.get_mut(number)?;
        if !self.touched.iter().any(|(touched, _)| touched == number) {
            self.touched.push((*number, Some(slot.description.id())));
        }
        Some(slot)
    }
}

impl Drop for FileTableWriteGuard<'_> {
    fn drop(&mut self) {
        let mut changed = Vec::with_capacity(self.touched.len());
        for (number, before) in self.touched.drain(..) {
            match before {
                None => changed.push(number),
                Some(before) => {
                    let Some(slot) = self.guard.get_mut(&number) else {
                        changed.push(number);
                        continue;
                    };
                    if slot.description.id() != before {
                        slot.generation = next_file_slot_generation();
                        changed.push(number);
                    }
                }
            }
        }
        self.revision.publish();
        if !changed.is_empty() {
            // EL1 must stop serving an fd number the moment it stops referring
            // to the object it was published for.
            crate::el1_delegation::fd_map_forget(self.table, &changed);
            self.subscriptions
                .publish_changes(self.table, &self.guard, &changed);
        }
    }
}

pub struct FileTableMutexGuard<'a, T> {
    guard: MutexGuard<'a, T>,
    _mutation: FileTableMutationLease,
    revision: &'a ObjectRevision,
}

impl<T> Deref for FileTableMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for FileTableMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for FileTableMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.revision.publish();
    }
}

pub struct FileTableRwWriteGuard<'a, T> {
    guard: RwLockWriteGuard<'a, T>,
    _mutation: FileTableMutationLease,
    revision: &'a ObjectRevision,
}

impl<T> Deref for FileTableRwWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for FileTableRwWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for FileTableRwWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.revision.publish();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FsContextState {
    cwd: String,
    chroot_root: Option<String>,
}

/// Authoritative Linux filesystem traversal context.
///
/// Mount tables and rootfs services remain runtime infrastructure. Only the
/// caller-visible `fs_struct` values live here, so `CLONE_FS` can share them
/// while fork and clones without `CLONE_FS` copy their exact values.
#[derive(Debug)]
pub struct FsContext {
    id: FsContextId,
    state: RwLock<FsContextState>,
    revision: ObjectRevision,
}

impl FsContext {
    pub fn new(id: FsContextId) -> Self {
        Self {
            id,
            state: RwLock::new(FsContextState {
                cwd: "/".to_owned(),
                chroot_root: None,
            }),
            revision: ObjectRevision::new(),
        }
    }

    fn for_fork_copy(id: FsContextId, parent: &Self) -> Self {
        Self {
            id,
            state: RwLock::new(parent.state.read().clone()),
            revision: ObjectRevision::new(),
        }
    }

    pub const fn id(&self) -> FsContextId {
        self.id
    }

    pub fn cwd(&self) -> String {
        self.state.read().cwd.clone()
    }

    pub fn with_cwd<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        let state = self.state.read();
        f(&state.cwd)
    }

    pub fn chroot_root(&self) -> Option<String> {
        self.state.read().chroot_root.clone()
    }

    pub fn with_chroot_root<R>(&self, f: impl FnOnce(Option<&str>) -> R) -> R {
        let state = self.state.read();
        f(state.chroot_root.as_deref())
    }

    pub fn set_cwd(&self, cwd: String) {
        let mut state = self.state.write();
        if state.cwd != cwd {
            state.cwd = cwd;
            self.revision.publish();
        }
    }

    pub fn set_chroot_root(&self, chroot_root: Option<String>) {
        let mut state = self.state.write();
        if state.chroot_root != chroot_root {
            state.chroot_root = chroot_root;
            self.revision.publish();
        }
    }

    pub(super) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, String, Option<String>)> {
        let state = self.state.try_read_until(deadline)?;
        Some((
            self.revision.load(),
            state.cwd.clone(),
            state.chroot_root.clone(),
        ))
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

/// One host thread's open claim on one logical guest thread's SYSTEM CPU.
///
/// The window is opened by [`Thread::open_system_charge_window`] at the
/// dispatch boundary and closed by [`close_system_charge_window`] when the
/// executor stops running that logical thread, so it spans a whole executor
/// residency rather than one syscall. That is the point: reading
/// `CLOCK_THREAD_CPUTIME_ID` costs a host `thread_selfusage` syscall on Darwin,
/// so bracketing every guest syscall spent exactly two host syscalls on every
/// guest syscall of every kind — to measure windows only microseconds long.
///
/// What the window contains has to be corrected for one measured fact: on
/// Apple's `Hypervisor.framework`, the time a vCPU thread spends inside
/// `hv_vcpu_run` DOES accrue to that host thread's `CLOCK_THREAD_CPUTIME_ID`.
/// (Measured 2026-09-08 with `scripts/dtrace/syscall-tax-reducer.rs` in `spin`
/// mode — a guest that only computes: charging the raw window put 11,673 µs of
/// system time on a thread that had issued no syscall at all, against 11,358 µs
/// of user time. The `guest_cpu` module's note that HVF guest execution does not
/// accrue is true of `proc_pid_rusage`, NOT of the per-thread clock.) Guest
/// execution is USER time, so it has to come back out of the window.
///
/// It cannot be subtracted directly, because the only free measure of guest
/// execution is the engine's run receipt, which is a WALL clock: on a loaded
/// host the guest-run wall exceeds the host-CPU delta and the subtraction
/// floors at zero, reporting a syscall-bound guest as having spent no system
/// time at all (observed at 1-minute load 23). The window therefore splits the
/// residency's REAL cpu — measured on the thread's own clock, so host
/// preemption is already excluded — in the ratio of the two wall spans it can
/// see for free: how much of the residency was inside guest runs, and how much
/// was carrick servicing them.
fn guest_run_clock_ns() -> u64 {
    carrick_host::clock::host_clock_uptime_ns()
}

#[derive(Clone, Debug)]
pub(super) struct SystemChargeWindow {
    /// The logical thread being charged. Identity, never a slot: `execve` can
    /// replace the thread object mid-residency.
    ///
    /// WEAK on purpose. A window is an observation about a thread, not an owner
    /// of one, and a strong reference here outlives every boundary the runtime
    /// audits: it kept retired `Thread`s alive past their sweep and shifted the
    /// id the next fork was handed (caught by
    /// `copied_file_table_owner_exit_purges_registration_despite_parent_description_ref`).
    /// Every use upgrades first, so a freed-and-recycled allocation can never be
    /// mistaken for the thread the window was opened on.
    pub(super) thread: std::sync::Weak<Thread>,
    /// Host thread CPU clock (`CLOCK_THREAD_CPUTIME_ID`) when the window
    /// opened. The one reading that costs a host syscall.
    pub(super) opened_at_host_cpu_ns: u64,
    /// Monotonic wall clock when the window opened.
    pub(super) opened_at_wall_ns: u64,
    /// The thread's accumulated guest-run wall time when the window opened;
    /// its growth is the part of the residency that was guest execution.
    pub(super) opened_at_user_ns: u64,
    /// How much of this window has already been committed. Cumulative rather
    /// than per-flush, so a flush can never charge an interval twice and a
    /// shrinking estimate cannot claw back time already reported to a guest.
    pub(super) charged_ns: u64,
}

impl SystemChargeWindow {
    /// The live thread this window charges, or `None` once it has been
    /// dropped — at which point nothing can report the time anyway.
    pub(super) fn live(&self) -> Option<ThreadRef> {
        self.thread.upgrade()
    }

    /// The service CPU this window has accrued but not yet committed, and the
    /// new cumulative total. Costs exactly one host syscall (the clock read);
    /// the wall and guest-run readings are free.
    pub(super) fn pending(&self, thread: &Thread) -> (u64, u64) {
        let residency_cpu_ns = carrick_host::guest_cpu::this_thread_cpu_ns()
            .saturating_sub(self.opened_at_host_cpu_ns);
        let residency_wall_ns = guest_run_clock_ns().saturating_sub(self.opened_at_wall_ns);
        let guest_wall_ns = thread
            .cpu_ns_including_active()
            .saturating_sub(self.opened_at_user_ns);
        let service_wall_ns = residency_wall_ns.saturating_sub(guest_wall_ns);
        let accrued_ns = if residency_wall_ns == 0 {
            0
        } else {
            u64::try_from(
                u128::from(residency_cpu_ns) * u128::from(service_wall_ns)
                    / u128::from(residency_wall_ns),
            )
            .unwrap_or(u64::MAX)
        };
        let uncommitted_ns = accrued_ns.saturating_sub(self.charged_ns);
        (uncommitted_ns, accrued_ns.max(self.charged_ns))
    }
}

thread_local! {
    /// This host thread's open charge window, if it is running a logical guest
    /// thread right now. See [`SystemChargeWindow`].
    pub(super) static SYSTEM_CHARGE_WINDOW: std::cell::RefCell<Option<SystemChargeWindow>> =
        const { std::cell::RefCell::new(None) };
}

/// Commit what this host thread has burned servicing the logical thread it was
/// running, and close the window.
///
/// The executor calls this when it stops running the loaded logical thread —
/// at a residency boundary, and again in the boundary audit so no error path
/// can leave a window open for a different logical thread to inherit.
pub fn close_system_charge_window() {
    let closed = SYSTEM_CHARGE_WINDOW.with(|window| window.borrow_mut().take());
    if let Some(window) = closed
        && let Some(thread) = window.live()
    {
        let (uncommitted_ns, _) = window.pending(&thread);
        thread.charge_system_ns(uncommitted_ns);
    }
}

/// Is this host thread free of any logical thread's charge window? Part of the
/// executor boundary audit: an executor about to load a different logical task
/// must not still be charging the previous one.
pub fn system_charge_window_is_closed() -> bool {
    SYSTEM_CHARGE_WINDOW.with(|window| window.borrow().is_none())
}

pub(super) static NEXT_PROCESS_GROUP_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObjectGraphError {
    #[error("first thread TID {tid:?} must match task leader {task:?}")]
    LeaderTidMismatch { task: TaskId, tid: LinuxTid },
    #[error("thread TID {0:?} is already attached")]
    DuplicateThread(LinuxTid),
    #[error("prepared thread belongs to a different task")]
    WrongThreadTask,
    #[error("thread {0:?} already has a bound backend runner")]
    RunnerAlreadyBound(ThreadKey),
    #[error("thread {0:?} is draining and cannot bind a backend runner")]
    RunnerDraining(ThreadKey),
    #[error("thread {0:?} no longer owns its backend runner gate")]
    RunnerOwnershipChanged(ThreadKey),
    #[error("thread {0:?} does not share this backend runner gate")]
    RunnerGateMismatch(ThreadKey),
    #[error("process-group claim does not match its typed ID")]
    ProcessGroupClaimMismatch,
    #[error("session claim does not match its typed ID")]
    SessionClaimMismatch,
    #[error("file description {0:?} is not an epoll instance")]
    NotEpoll(FileDescriptionId),
    #[error("epoll file description {0:?} cannot monitor itself")]
    SelfEpollInterest(FileDescriptionId),
    #[error("nested epoll target {0:?} is rejected by the K1 object model")]
    NestedEpollInterest(FileDescriptionId),
    #[error("host-fork target Mm already has ring allocations")]
    NonEmptyForkMm,
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    use crate::kernel::ids::ObjectIdRegistry;

    use super::*;

    #[derive(Debug, Default)]
    struct TestCeilingPublisher(AtomicU32);

    impl carrick_hal::FdCeilingPublisher for TestCeilingPublisher {
        fn raise(&self, maximum: u32) {
            self.0.fetch_max(maximum, Ordering::Release);
        }

        fn disable(&self) {}
    }

    #[derive(Debug)]
    struct PanickingCeilingPublisher(Arc<parking_lot::Mutex<Vec<&'static str>>>);

    impl carrick_hal::FdCeilingPublisher for PanickingCeilingPublisher {
        fn raise(&self, maximum: u32) {
            if maximum > 2 {
                self.0.lock().push("raise");
                panic!("publication intercept");
            }
        }

        fn disable(&self) {}
    }

    fn regular_description(ids: &ObjectIdRegistry) -> Arc<FileDescription> {
        Arc::new(FileDescription::regular(
            ids.file_description_id().expect("description ID"),
        ))
    }

    #[test]
    fn install_publishes_before_slot_visibility() {
        let ids = ObjectIdRegistry::new();
        let authority = Arc::new(FdCeilingAuthority::new());
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        authority.register(Arc::new(PanickingCeilingPublisher(Arc::clone(&events))));
        let table = FileTable::with_fd_ceiling(ids.file_table_id().expect("table ID"), authority);
        let fd = FileSlotNumber::for_open_fd(9).expect("fd");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            table.install(fd, regular_description(&ids), false);
        }));
        assert!(result.is_err());
        assert_eq!(&*events.lock(), &["raise"]);
        assert!(table.slot(fd).is_none());
    }

    #[test]
    fn write_guard_publishes_before_slot_visibility() {
        let ids = ObjectIdRegistry::new();
        let authority = Arc::new(FdCeilingAuthority::new());
        let events = Arc::new(parking_lot::Mutex::new(Vec::new()));
        authority.register(Arc::new(PanickingCeilingPublisher(Arc::clone(&events))));
        let table = FileTable::with_fd_ceiling(ids.file_table_id().expect("table ID"), authority);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            table
                .write_open_files()
                .insert(12, FileSlot::new(regular_description(&ids), 0));
        }));
        assert!(result.is_err());
        assert_eq!(&*events.lock(), &["raise"]);
        assert!(
            table
                .slot(FileSlotNumber::for_open_fd(12).expect("fd"))
                .is_none()
        );
    }

    #[test]
    fn copied_tables_share_ceiling_while_standalone_tables_are_isolated() {
        let ids = ObjectIdRegistry::new();
        let authority = Arc::new(FdCeilingAuthority::new());
        let publisher = Arc::new(TestCeilingPublisher::default());
        authority.register(publisher.clone());
        let parent =
            FileTable::with_fd_ceiling(ids.file_table_id().expect("parent table ID"), authority);
        let child = FileTable::for_fork_copy(ids.file_table_id().expect("child table ID"), &parent);
        child.install(
            FileSlotNumber::for_open_fd(47).expect("fd"),
            regular_description(&ids),
            false,
        );
        assert_eq!(publisher.0.load(Ordering::Acquire), 47);

        let standalone = FileTable::new(ids.file_table_id().expect("standalone table ID"));
        standalone.install(
            FileSlotNumber::for_open_fd(63).expect("fd"),
            regular_description(&ids),
            false,
        );
        assert_eq!(publisher.0.load(Ordering::Acquire), 47);
    }

    #[test]
    fn fork_exec_and_external_exec_tables_retain_the_carrier_authority() {
        let ids = ObjectIdRegistry::new();
        let authority = Arc::new(FdCeilingAuthority::new());
        let publisher = Arc::new(TestCeilingPublisher::default());
        authority.register(publisher.clone());
        let parent = FileTable::with_fd_ceiling(
            ids.file_table_id().expect("parent table ID"),
            Arc::clone(&authority),
        );
        let fork = FileTable::for_fork_copy(ids.file_table_id().expect("fork table ID"), &parent);
        let exec = FileTable::for_exec(ids.file_table_id().expect("exec table ID"), &fork);
        let external = FileTable::for_external_exec(
            ids.file_table_id().expect("external table ID"),
            authority,
        );

        for (table, fd) in [(&fork, 21), (&exec, 34), (&external, 55)] {
            table.install(
                FileSlotNumber::for_open_fd(fd).expect("fd"),
                regular_description(&ids),
                false,
            );
        }
        assert_eq!(publisher.0.load(Ordering::Acquire), 55);
    }

    #[test]
    fn concurrent_file_table_insertions_publish_the_largest_descriptor() {
        let ids = ObjectIdRegistry::new();
        let authority = Arc::new(FdCeilingAuthority::new());
        let publisher = Arc::new(TestCeilingPublisher::default());
        authority.register(publisher.clone());
        let table = Arc::new(FileTable::with_fd_ceiling(
            ids.file_table_id().expect("table ID"),
            authority,
        ));
        let threads = (3..35)
            .map(|fd| {
                let table = Arc::clone(&table);
                let description = regular_description(&ids);
                std::thread::spawn(move || {
                    table.install(
                        FileSlotNumber::for_open_fd(fd).expect("fd"),
                        description,
                        false,
                    );
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().expect("insertion thread");
        }
        assert_eq!(publisher.0.load(Ordering::Acquire), 34);
        assert_eq!(table.slot_count(), 32);
    }

    #[test]
    fn file_slot_hasher_preserves_the_i32_descriptor_domain() {
        for value in [i32::MIN, -1, 0, 1, 2, 3, 65_535, i32::MAX] {
            let mut hasher = FileSlotHasher::default();
            std::hash::Hasher::write_i32(&mut hasher, value);
            assert_eq!(hasher.finish(), u64::from(value as u32));
        }
    }
    #[test]
    fn epoll_rejects_self_and_nested_edges_and_uses_weak_targets() {
        let ids = ObjectIdRegistry::new();
        let epoll = Arc::new(FileDescription::epoll(
            ids.file_description_id().expect("epoll ID"),
        ));
        let nested = Arc::new(FileDescription::epoll(
            ids.file_description_id().expect("nested epoll ID"),
        ));
        let regular = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("regular ID"),
        ));

        assert_eq!(
            epoll.add_epoll_interest(&epoll),
            Err(ObjectGraphError::SelfEpollInterest(epoll.id()))
        );
        assert_eq!(
            epoll.add_epoll_interest(&nested),
            Err(ObjectGraphError::NestedEpollInterest(nested.id()))
        );
        epoll
            .add_epoll_interest(&regular)
            .expect("regular weak interest");
        assert_eq!(epoll.live_epoll_interest_count(), Ok(1));
        drop(regular);
        assert_eq!(epoll.live_epoll_interest_count(), Ok(0));
    }

    #[test]
    fn epoll_wake_handle_wakes_after_its_file_table_drops() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table ID")));
        let wake = table.epoll_wake_handle();
        let table_weak = Arc::downgrade(&table);

        let mut mux = crate::event_mux::make_event_multiplexer().expect("event multiplexer");
        mux.register_user(0).expect("register user wake");
        let epoll = crate::dispatch::EpollKqueue::new(mux, Arc::clone(table.epoll_wake_registry()));

        drop(table);
        assert!(
            table_weak.upgrade().is_none(),
            "wake handle must not retain FileTable"
        );

        wake.notify();
        let mut pollfd = libc::pollfd {
            fd: epoll.poll_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut pollfd, 1, 0) },
            1,
            "registry-only wake handle must wake the registered epoll instance"
        );
        assert_ne!(pollfd.revents & libc::POLLIN, 0);
    }

    #[test]
    fn fork_shares_description_pushback_cell() {
        let ids = ObjectIdRegistry::new();
        let parent = FileTable::new(ids.file_table_id().expect("parent table ID"));
        let description = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("description ID"),
        ));
        parent.install(
            FileSlotNumber::for_open_fd(3).expect("fd"),
            Arc::clone(&description),
            false,
        );

        let child = FileTable::for_fork_copy(ids.file_table_id().expect("child table ID"), &parent);
        let child_slot = child
            .slot(FileSlotNumber::for_open_fd(3).expect("fd"))
            .expect("child slot");
        assert!(Arc::ptr_eq(&description, &child_slot.description));
        assert!(std::ptr::eq(
            description.common().splice_pushback(),
            child_slot.description.common().splice_pushback()
        ));
    }

    #[test]
    fn fd_slot_authority_rejects_close_and_same_number_reuse_before_successor_access() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table ID")));
        let number = FileSlotNumber::for_open_fd(3).expect("fd");
        let original = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("original description"),
        ));
        table.install(number, original, false);
        let authority = table
            .capture_slot_authority(number)
            .expect("exact original slot authority");
        let callbacks = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&callbacks);
        let _subscription = table
            .subscribe_slot_authority(
                authority,
                Arc::new(move |_| {
                    observed.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .expect("subscribe original slot");

        let successor = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("successor description"),
        ));
        table.install(number, Arc::clone(&successor), false);
        assert_eq!(callbacks.load(Ordering::SeqCst), 1);
        assert!(!table.validate_slot_authority(authority));
        let replacement = table
            .capture_slot_authority(number)
            .expect("replacement authority");
        assert_eq!(replacement.description(), successor.id());
        assert_ne!(replacement.slot_generation(), authority.slot_generation());
    }

    #[test]
    fn file_table_retirement_waits_for_admitted_functional_use() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table ID")));
        let lease = table
            .acquire_functional_lease()
            .expect("active table lease");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let retiring = Arc::clone(&table);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("retirement started");
            let drained = retiring.drain_functional_refs();
            done_tx.send(drained).expect("retirement complete");
        });

        started_rx.recv().expect("retirement entered");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(25)).is_err(),
            "retirement completed while a functional lease was admitted"
        );
        drop(lease);
        assert!(done_rx.recv().expect("retirement released").is_empty());
        worker.join().expect("retirement worker");
        assert!(!table.functional_refs_active());
    }

    #[test]
    fn exec_freeze_blocks_table_mutation_until_publication_boundary() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table ID")));
        let freeze = table.freeze_for_exec().expect("exec freeze");
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let mutating = Arc::clone(&table);
        let worker = std::thread::spawn(move || {
            started_tx.send(()).expect("mutation started");
            *mutating.lock_next_fd() = 4096;
            done_tx.send(()).expect("mutation complete");
        });

        started_rx.recv().expect("mutation entered");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(25)).is_err(),
            "mutation crossed the exec freeze"
        );
        drop(freeze);
        done_rx.recv().expect("mutation released");
        worker.join().expect("mutation worker");
        assert_eq!(*table.lock_next_fd(), 4096);
    }

    #[test]
    fn resolve_slot_authority_returns_exact_arc_or_stale_across_lock_boundary_never_replacement() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let number = FileSlotNumber::for_open_fd(3).expect("fd 3");

        let desc1 = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("desc 1"),
        ));
        table.install(number, Arc::clone(&desc1), false);
        let token1 = table.capture_slot_authority(number).expect("token 1");

        // 1. Initial resolution returns exact original Arc.
        let resolved = table
            .resolve_slot_authority(token1)
            .expect("resolve token 1");
        assert!(Arc::ptr_eq(&resolved, &desc1));

        // 2. Lock boundary test: hold write lock, queue reader on thread, replace with desc2.
        let desc2 = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("desc 2"),
        ));

        // Acquire write guard FIRST, guaranteeing that the reader thread must block
        // on open_files.read() and cannot observe the pre-replacement slot.
        let mut write_guard = table.open_files.write();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();

        // Spawn reader thread that attempts resolution while write guard is held.
        let table_clone = Arc::clone(&table);
        let reader_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = table_clone.resolve_slot_authority(token1);
            done_tx.send(result).unwrap();
        });

        // Ensure the reader thread has started.
        started_rx.recv().unwrap();

        // Replace slot 3 under the held write lock.
        write_guard.insert(number.raw(), FileSlot::new(Arc::clone(&desc2), 0));
        // Release write guard, allowing the blocked reader thread to proceed.
        drop(write_guard);

        let result = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("reader completed");
        reader_thread.join().unwrap();

        // Reader must receive None (stale), never Some(desc2).
        assert!(
            result.is_none(),
            "stale token must resolve to None, not replacement Arc"
        );

        // Sequential resolution with stale token is also None.
        assert!(table.resolve_slot_authority(token1).is_none());

        // Fresh token for desc2 resolves to desc2.
        let token2 = table.capture_slot_authority(number).expect("token 2");
        let resolved2 = table
            .resolve_slot_authority(token2)
            .expect("resolve token 2");
        assert!(Arc::ptr_eq(&resolved2, &desc2));
    }

    #[test]
    fn slot_lease_rejects_stale_authority_after_reuse() {
        let ids = ObjectIdRegistry::new();
        let table = FileTable::new(ids.file_table_id().expect("table id"));
        let number = FileSlotNumber::for_open_fd(3).expect("fd 3");
        let original = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("original description"),
        ));
        // Model an alias held by another numeric fd: closing this slot alone
        // must not retire the original description.
        original.retain_fd_ref();
        table.install(number, Arc::clone(&original), false);
        let authority = table
            .capture_slot_authority(number)
            .expect("original authority");
        let replacement = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("replacement description"),
        ));
        table.install(number, replacement, false);

        assert!(table.resolve_slot_authority(authority).is_none());
        assert!(
            table.retain_slot_lease(authority).is_none(),
            "a stale authority must never retain the old alias or replacement"
        );
    }

    #[test]
    fn slot_lease_reader_wins_before_queued_reuse_and_pins_exact_description() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let number = FileSlotNumber::for_open_fd(3).expect("fd 3");
        let original = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("original description"),
        ));
        original.retain_fd_ref();
        table.install(number, Arc::clone(&original), false);
        let authority = table.capture_slot_authority(number).expect("authority");

        let (reader_holding_tx, reader_holding_rx) = std::sync::mpsc::channel();
        let (release_reader_tx, release_reader_rx) = std::sync::mpsc::channel();
        let (lease_tx, lease_rx) = std::sync::mpsc::channel();
        let reader_table = Arc::clone(&table);
        let reader = std::thread::spawn(move || {
            let lease = reader_table.retain_slot_lease_with_hook(authority, || {
                reader_holding_tx.send(()).expect("reader entered guard");
                release_reader_rx.recv().expect("release reader");
            });
            lease_tx.send(lease).expect("return lease");
        });
        reader_holding_rx.recv().expect("reader holds table guard");

        let replacement = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("replacement description"),
        ));
        let (writer_started_tx, writer_started_rx) = std::sync::mpsc::channel();
        let (writer_done_tx, writer_done_rx) = std::sync::mpsc::channel();
        let writer_table = Arc::clone(&table);
        let writer = std::thread::spawn(move || {
            writer_started_tx.send(()).expect("writer started");
            writer_table
                .write_open_files()
                .insert(number.raw(), FileSlot::new(replacement, 0));
            writer_done_tx.send(()).expect("writer done");
        });
        writer_started_rx.recv().expect("writer queued");
        assert!(
            writer_done_rx
                .recv_timeout(std::time::Duration::from_millis(20))
                .is_err(),
            "reuse must wait for exact lease admission"
        );

        release_reader_tx.send(()).expect("release reader");
        let lease = lease_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("reader returned")
            .expect("live original lease");
        assert!(Arc::ptr_eq(lease.description(), &original));
        reader.join().expect("reader joined");
        writer_done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("writer completed after reader");
        writer.join().expect("writer joined");
        assert!(table.retain_slot_lease(authority).is_none());
    }

    #[test]
    fn resolve_slot_authority_rejects_mismatched_table_id_or_generation() {
        let ids = ObjectIdRegistry::new();
        let table1 = Arc::new(FileTable::new(ids.file_table_id().expect("table 1")));
        let table2 = Arc::new(FileTable::new(ids.file_table_id().expect("table 2")));
        let number = FileSlotNumber::for_open_fd(3).expect("fd 3");

        let desc = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("desc 1"),
        ));
        table1.install(number, Arc::clone(&desc), false);
        let token1 = table1.capture_slot_authority(number).expect("token 1");

        // Resolving on table2 with table1's token returns None.
        assert!(table2.resolve_slot_authority(token1).is_none());
    }

    #[test]
    fn capture_slot_or_stdio_authority_authorizes_bare_stdio_slots() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table")));
        let stdin_slot = FileSlotNumber::for_open_fd(0).expect("stdin");
        let stdout_slot = FileSlotNumber::for_open_fd(1).expect("stdout");

        // Open bare stdio slot captures authority and validates.
        assert!(table.is_bare_stdio_open(0));
        let token = table
            .capture_slot_or_stdio_authority(stdin_slot)
            .expect("token for stdin");
        assert!(table.validate_slot_authority(token));

        // When stdio slot is marked closed, authority capture returns None.
        table.lock_closed_stdio()[0] = true;
        assert!(!table.is_bare_stdio_open(0));
        assert!(table.capture_slot_or_stdio_authority(stdin_slot).is_none());
        assert!(!table.validate_slot_authority(token));

        // Other stdio slot remains open and capturable.
        assert!(table.is_bare_stdio_open(1));
        let token_out = table
            .capture_slot_or_stdio_authority(stdout_slot)
            .expect("token for stdout");
        assert!(table.validate_slot_authority(token_out));
    }

    /// A write guard settles exactly the slots it mutated: an untouched slot
    /// keeps its generation and its listener, a flag-only `get_mut` keeps the
    /// slot's identity, and only a description swap, an insert, or a remove
    /// mints a generation and retires the listener on that number. The
    /// previous design re-walked every slot on release, so an fd-fill loop
    /// paid the table size per `dup`.
    #[test]
    fn write_guard_settles_only_touched_slots() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let numbers: Vec<FileSlotNumber> = (3..=5)
            .map(|fd| FileSlotNumber::for_open_fd(fd).expect("fd"))
            .collect();
        for number in &numbers {
            let desc = Arc::new(FileDescription::regular(
                ids.file_description_id().expect("desc"),
            ));
            table.install(*number, desc, false);
        }
        let before: Vec<u64> = numbers
            .iter()
            .map(|number| table.slot(*number).expect("slot").generation())
            .collect();
        let fired: Vec<Arc<AtomicUsize>> = (0..3).map(|_| Arc::new(AtomicUsize::new(0))).collect();
        let subscriptions: Vec<_> = numbers
            .iter()
            .zip(&fired)
            .map(|(number, fired)| {
                let authority = table.capture_slot_authority(*number).expect("authority");
                let fired = Arc::clone(fired);
                table
                    .subscribe_slot_authority(
                        authority,
                        Arc::new(move |_| {
                            fired.fetch_add(1, Ordering::SeqCst);
                        }),
                    )
                    .expect("subscription")
            })
            .collect();

        let swapped = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("swapped desc"),
        ));
        let inserted = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("inserted desc"),
        ));
        {
            let mut guard = table.write_open_files();
            guard.get_mut(&4).expect("fd 4").fd_flags = carrick_abi::LinuxFdFlags::CLOEXEC.bits();
            guard.get_mut(&5).expect("fd 5").description = Arc::clone(&swapped);
            assert!(guard.insert(6, FileSlot::new(inserted, 0)).is_none());
        }

        let after: Vec<u64> = numbers
            .iter()
            .map(|number| table.slot(*number).expect("slot").generation())
            .collect();
        assert_eq!(after[0], before[0], "untouched slot keeps its generation");
        assert_eq!(
            after[1], before[1],
            "flag-only mutation keeps the slot identity"
        );
        assert_ne!(
            after[2], before[2],
            "description swap mints a new generation"
        );
        assert_eq!(
            fired[0].load(Ordering::SeqCst),
            0,
            "untouched listener stays"
        );
        assert_eq!(
            fired[1].load(Ordering::SeqCst),
            0,
            "flag-only listener stays"
        );
        assert_eq!(
            fired[2].load(Ordering::SeqCst),
            1,
            "swapped listener retired"
        );
        assert!(
            table
                .slot(FileSlotNumber::for_open_fd(6).expect("fd 6"))
                .is_some()
        );

        {
            let mut guard = table.write_open_files();
            assert!(guard.remove(&3).is_some());
            assert!(guard.remove(&7).is_none());
        }
        assert_eq!(
            fired[0].load(Ordering::SeqCst),
            1,
            "removed listener retired"
        );
        assert_eq!(fired[1].load(Ordering::SeqCst), 0);
        drop(subscriptions);
    }

    #[test]
    fn resolve_slot_authority_resolver_wins_returns_exact_arc_before_queued_writer_replaces_slot() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let number = FileSlotNumber::for_open_fd(3).expect("fd 3");

        let desc1 = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("desc 1"),
        ));
        table.install(number, Arc::clone(&desc1), false);
        let token1 = table.capture_slot_authority(number).expect("token 1");

        let desc2 = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("desc 2"),
        ));

        let (resolver_holding_read_guard_tx, resolver_holding_read_guard_rx) =
            std::sync::mpsc::channel();
        let (writer_queued_tx, writer_queued_rx) = std::sync::mpsc::channel();
        let (resolver_done_tx, resolver_done_rx) = std::sync::mpsc::channel();

        // 1. Spawn reader thread that acquires read guard first.
        let table_reader = Arc::clone(&table);
        let reader_thread = std::thread::spawn(move || {
            let result = table_reader.resolve_slot_authority_with_hook(token1, || {
                // Signal that read guard is currently held.
                resolver_holding_read_guard_tx.send(()).unwrap();
                // Wait until writer has attempted/queued write acquisition.
                writer_queued_rx.recv().unwrap();
            });
            resolver_done_tx.send(result).unwrap();
        });

        // Ensure reader has acquired read guard.
        resolver_holding_read_guard_rx.recv().unwrap();

        // 2. Spawn writer thread that attempts to acquire write guard.
        let (writer_started_tx, writer_started_rx) = std::sync::mpsc::channel();
        let (writer_done_tx, writer_done_rx) = std::sync::mpsc::channel();
        let table_writer = Arc::clone(&table);
        let desc2_clone = Arc::clone(&desc2);
        let writer_thread = std::thread::spawn(move || {
            writer_started_tx.send(()).unwrap();
            // This write lock acquisition must block until the reader thread drops its read guard.
            let mut write_guard = table_writer.open_files.write();
            write_guard.insert(number.raw(), FileSlot::new(desc2_clone, 0));
            drop(write_guard);
            writer_done_tx.send(()).unwrap();
        });

        // Ensure writer thread has started and is attempting to acquire write lock.
        writer_started_rx.recv().unwrap();

        // 3. Release resolver hook so resolver clones and returns desc1 under its read guard.
        writer_queued_tx.send(()).unwrap();

        // Resolver finishes first and returns original Arc.
        let resolved = resolver_done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("resolver finished");
        reader_thread.join().unwrap();

        let resolved_desc = resolved.expect("resolver succeeded");
        assert!(Arc::ptr_eq(&resolved_desc, &desc1));

        // Writer unblocks and completes replacement.
        writer_done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("writer finished");
        writer_thread.join().unwrap();

        // Now sequential resolution of stale token1 returns None.
        assert!(table.resolve_slot_authority(token1).is_none());

        // Sequential resolution with fresh token returns desc2.
        let token2 = table.capture_slot_authority(number).expect("token 2");
        let resolved2 = table
            .resolve_slot_authority(token2)
            .expect("resolve token 2");
        assert!(Arc::ptr_eq(&resolved2, &desc2));
    }

    #[test]
    fn socket_cork_staging_taking_and_enabling() {
        let mut cork = SocketCork::default();
        assert!(!cork.is_active());
        assert!(!cork.is_enabled());
        assert!(!cork.has_pending());
        assert_eq!(cork.take(), None);

        // Stage bytes with destination
        cork.stage(b"hello ", Some(b"dest1"));
        assert!(cork.is_active());
        assert!(!cork.is_enabled());
        assert!(cork.has_pending());

        // Subsequent stage preserves existing destination
        cork.stage(b"world", Some(b"dest2"));
        assert_eq!(cork.dest.as_deref(), Some(&b"dest1"[..]));
        assert_eq!(&cork.buffer, b"hello world");

        // Take drains buffer and destination
        let taken = cork.take().expect("taken");
        assert_eq!(taken.0, b"hello world");
        assert_eq!(taken.1.as_deref(), Some(&b"dest1"[..]));
        assert!(!cork.is_active());
        assert_eq!(cork.take(), None);

        // Enabling and disabling with pending data flushes
        assert_eq!(cork.set_enabled(true), None);
        assert!(cork.is_active());
        assert!(cork.is_enabled());

        cork.stage(b"flushme", None);
        let flushed = cork.set_enabled(false).expect("flushed");
        assert_eq!(flushed.0, b"flushme");
        assert_eq!(flushed.1, None);
        assert!(!cork.is_active());
    }

    #[test]
    fn description_common_socket_cork_and_peer_cred_accessors() {
        let common = DescriptionCommon::new(0);
        assert_eq!(common.peer_cred(), None);

        let cred = SocketPeerCred {
            pid: crate::dispatch::NsPid(42),
            uid: NsUid::new(1000),
            gid: NsGid::new(1000),
        };
        common.set_peer_cred(Some(cred));
        assert_eq!(common.peer_cred(), Some(cred));

        assert!(!common.cork().is_active());
        common.cork().stage(b"data", None);
        assert!(common.cork().has_pending());
        let taken = common.cork().take().expect("taken");
        assert_eq!(taken.0, b"data");
    }

    fn dummy_file_slot() -> FileSlot {
        let ids = ObjectIdRegistry::new();
        let desc = Arc::new(FileDescription::regular(
            ids.file_description_id().expect("desc"),
        ));
        FileSlot::new(desc, 0)
    }

    #[test]
    fn sequential_reservations_allocate_contiguous_slots() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));

        let n = 100;
        let mut reservations = Vec::new();
        for _ in 0..n {
            let res = table.reserve_slot_at_or_above(0, 1024).expect("reserve");
            reservations.push(res);
        }

        for (i, res) in reservations.into_iter().enumerate() {
            assert_eq!(res.fd(), 3 + i as i32);
            assert!(res.commit(dummy_file_slot()).is_ok());
        }
    }

    #[test]
    fn low_limit_early_bound_check() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let limit = 5; // Slots available: 3, 4 (stdio 0, 1, 2 not closed)

        let r1 = table.reserve_slot_at_or_above(0, limit).expect("slot 3");
        assert_eq!(r1.fd(), 3);
        let r2 = table.reserve_slot_at_or_above(0, limit).expect("slot 4");
        assert_eq!(r2.fd(), 4);

        let err = table.reserve_slot_at_or_above(0, limit).unwrap_err();
        assert_eq!(err, crate::linux_abi::LINUX_EMFILE);
    }

    #[test]
    fn authenticated_commit_rejects_mismatched_reservation_id() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let res = table.reserve_slot_at_or_above(0, 1024).expect("slot 3");
        let fd = res.fd();

        // Attempting to commit directly with a wrong reservation_id must fail EBADF
        let err = table
            .commit_reserved_slot(fd, res.reservation_id() + 999, dummy_file_slot())
            .unwrap_err();
        assert_eq!(err, crate::linux_abi::LINUX_EBADF);

        // Committing with valid reservation succeeds
        assert!(res.commit(dummy_file_slot()).is_ok());
    }

    #[test]
    fn reservation_rollback_and_cursor_rewind_on_drop() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));

        {
            let res = table.reserve_slot_at_or_above(0, 1024).expect("slot 3");
            assert_eq!(res.fd(), 3);
            assert!(table.is_slot_reserved(3));
            // res is dropped without commit -> rollback
        }

        assert!(!table.is_slot_reserved(3));

        // Next reservation must reuse slot 3 due to cursor rewind
        let res2 = table
            .reserve_slot_at_or_above(0, 1024)
            .expect("slot 3 reuse");
        assert_eq!(res2.fd(), 3);
        assert!(res2.commit(dummy_file_slot()).is_ok());

        // Slot 3 is now occupied
        let res3 = table.reserve_slot_at_or_above(0, 1024).expect("slot 4");
        assert_eq!(res3.fd(), 4);
    }

    #[test]
    fn retired_table_rejects_reserved_slot_commits_and_releases_reservations() {
        let ids = ObjectIdRegistry::new();

        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let reservation = table.reserve_slot_at_or_above(0, 1024).expect("slot 3");
        assert!(table.drain_functional_refs().is_empty());
        assert!(matches!(
            reservation.commit(dummy_file_slot()),
            Err(crate::linux_abi::LINUX_EBADF)
        ));
        assert!(!table.is_slot_reserved(3));

        let exact_table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));
        let exact = exact_table
            .reserve_exact_target(3, 1024)
            .expect("exact slot 3");
        assert!(exact_table.drain_functional_refs().is_empty());
        assert!(matches!(
            exact.commit(dummy_file_slot()),
            Err(crate::linux_abi::LINUX_EBADF)
        ));
        assert!(!exact_table.is_slot_reserved(3));
    }

    #[test]
    fn admitted_slot_stability_after_lowering_rlimit() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));

        // Reserve slot 7 with limit 8
        let r3 = table.reserve_slot_at_or_above(0, 8).expect("reserve 3");
        let r4 = table.reserve_slot_at_or_above(0, 8).expect("reserve 4");
        let r5 = table.reserve_slot_at_or_above(0, 8).expect("reserve 5");
        let r6 = table.reserve_slot_at_or_above(0, 8).expect("reserve 6");
        let r7 = table.reserve_slot_at_or_above(0, 8).expect("reserve 7");
        assert_eq!(r7.fd(), 7);

        // Commit r7 succeeds even if limit is conceptually lowered (commit doesn't re-check limit)
        assert!(r7.commit(dummy_file_slot()).is_ok());

        // Clean up remaining reservations
        drop(r3);
        drop(r4);
        drop(r5);
        drop(r6);
    }

    #[test]
    fn exact_slot_reservation_linear_winner_and_isolation() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));

        // 1. Open reserves slot 3
        let open_res = table.reserve_slot_at_or_above(0, 1024).expect("reserve 3");
        assert_eq!(open_res.fd(), 3);

        // 2. Exact reservation on slot 3 must fail EBUSY while open reservation is live
        let err = table.reserve_exact_target(3, 1024).unwrap_err();
        assert_eq!(err, crate::linux_abi::LINUX_EBUSY);

        // 3. Drop open reservation -> slot 3 freed
        drop(open_res);
        assert!(!table.is_slot_reserved(3));

        // 4. Exact reservation on slot 3 now succeeds
        let exact_res = table
            .reserve_exact_target(3, 1024)
            .expect("exact reserve 3");
        assert_eq!(exact_res.fd(), 3);
        assert!(table.is_slot_reserved(3));

        // 5. Concurrent open allocation skips slot 3 and allocates slot 4
        let open_res2 = table.reserve_slot_at_or_above(0, 1024).expect("reserve 4");
        assert_eq!(open_res2.fd(), 4);

        // 6. Exact reservation commits replacement
        let slot1 = dummy_file_slot();
        let desc1 = slot1.description();
        let replaced = exact_res.commit(slot1).expect("commit exact");
        assert!(replaced.is_none());

        // 7. Subsequent exact reservation on occupied slot 3 replaces existing slot
        let exact_res2 = table
            .reserve_exact_target(3, 1024)
            .expect("exact reserve 3 again");
        let slot2 = dummy_file_slot();
        let desc2 = slot2.description();
        let replaced2 = exact_res2.commit(slot2).expect("commit replacement");
        let old_slot = replaced2.expect("replaced slot");
        assert!(Arc::ptr_eq(&old_slot.description(), &desc1));
        assert!(Arc::ptr_eq(
            &table.open_files.read().get(&3).unwrap().description(),
            &desc2
        ));

        drop(open_res2);
    }

    #[test]
    fn for_exec_closes_bare_stdio_with_cloexec() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));

        // Mark stdin (0) as close-on-exec on bare stdio
        table.stdio_cloexec.lock()[0] = true;

        // Perform for_exec
        let exec_table = Arc::new(FileTable::for_exec(
            ids.file_table_id().expect("exec table id"),
            &table,
        ));

        // Stdin (0) must now be recorded in closed_stdio
        assert!(exec_table.closed_stdio.lock()[0]);
        assert!(!exec_table.closed_stdio.lock()[1]);
        assert!(!exec_table.closed_stdio.lock()[2]);

        // A new open allocating from 0 must now allocate the closed stdin slot (0)
        let res = exec_table
            .reserve_slot_at_or_above(0, 1024)
            .expect("reserve 0");
        assert_eq!(res.fd(), 0);
    }

    #[test]
    fn cancellation_does_not_hold_reserved_slots_while_awaiting_next_fd() {
        let ids = ObjectIdRegistry::new();
        let table = Arc::new(FileTable::new(ids.file_table_id().expect("table id")));

        let res = table.reserve_slot_at_or_above(0, 1024).expect("slot 3");
        assert_eq!(res.fd(), 3);
        assert!(table.is_slot_reserved(3));

        // Thread 1 holds next_fd lock
        let next_fd_guard = table.next_fd.lock();

        // Spawn Thread 2 to cancel the reservation (drop uncommitted reservation)
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn({
            let _table = Arc::clone(&table);
            move || {
                tx.send(()).unwrap();
                drop(res); // triggers cancel_reservation
            }
        });

        rx.recv().unwrap();
        // Wait until cancellation reaches mutation admission and is blocked attempting next_fd
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut reached_admission = false;
        while std::time::Instant::now() < deadline {
            if table.functional_gate.state.lock().active_mutations == 1 {
                reached_admission = true;
                break;
            }
            std::thread::yield_now();
        }

        // Under correct lock ordering (next_fd -> reserved_slots), Thread 2 awaits next_fd
        // WITHOUT holding reserved_slots, so reserved_slots is free to acquire here.
        // Under inverted lock ordering (reserved_slots -> next_fd), Thread 2 holds reserved_slots
        // while blocked on next_fd, deadlocking any attempt to acquire reserved_slots.
        let acquired = if reached_admission {
            table
                .reserved_slots
                .try_lock_for(std::time::Duration::from_millis(100))
        } else {
            None
        };

        let is_unlocked = acquired.is_some();
        drop(acquired);
        drop(next_fd_guard);
        let join_res = t.join();

        assert!(
            reached_admission,
            "cancellation should have reached mutation admission within timeout"
        );
        assert!(
            is_unlocked,
            "cancel_reservation must acquire next_fd before reserved_slots to prevent lock inversion deadlock"
        );
        assert!(join_res.is_ok());
        assert!(!table.is_slot_reserved(3));
    }
}
