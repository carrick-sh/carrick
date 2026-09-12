use std::any::Any;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{BuildHasherDefault, Hasher};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwap;
use carrick_abi::keyring::{KeyRequestDefault, KeySerial};
use carrick_abi::{
    LINUX_RLIM_INFINITY, LinuxEpollEvents, LinuxResource, LinuxRlimit, LinuxSiginfo, NsGid, NsUid,
    SigSet,
};
use carrick_hal::ThreadId;
use parking_lot::{Condvar, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::linux_abi::LINUX_DEFAULT_UMASK;
use crate::namespace::process::{CapabilitySet, ProcessCredsNs};
use crate::namespace::user::UserNs;

use super::clone_plan::{CloneObjectMode, ClonePlan};
use super::container::Container;
use super::ids::{
    ChildExitSignal, CredentialsId, FileDescriptionId, FileSlotNumber, FileTableId, FsContextId,
    LinuxSignal, LinuxTid, MmId, ObjectIdError, ObjectIdRegistry, ProcessGroupId, SessionId,
    TaskId, TaskSerial, ThreadSerial,
};
use super::netns::{NetNs, NsProxy, UtsNs};
use carrick_fatal::carrick_fatal;

pub mod process;
pub mod session;
pub mod signal;
pub mod thread;

pub use self::process::{
    LinuxWaitStatus, Mm, PidfdTarget, TaskRusage, TaskShared, TaskSharedCloneError, Zombie,
};
pub use self::session::{ProcessGroup, Session};
pub use self::signal::{
    HandlerFrameState, PendingQueue, PendingSignal, Sighand, SignalAuthority, SignalDequeue,
    SignalDisposition, SignalPendingOwner, SignalReservationOrigin, SignalWaitReservation,
    TaskPendingSignals, ThreadSignalState,
};
pub(in crate::kernel) use self::thread::ExecDrain;
pub use self::thread::{
    BlockedReason, ExecutionFailure, ExecutionGeneration, ExecutorId, MigratableTaskState,
    RunnerDirective, TaskCpuSample, Thread, ThreadCpuSample, ThreadExecutionError,
    ThreadExecutionLease, ThreadExecutionSettlementResult, ThreadExecutionState, ThreadKey,
    ThreadRef, ThreadRunner,
};
pub(crate) use self::thread::{
    CrashSafePointParticipation, CrashSafePointParticipationError, OpenedStartGate,
    SchedulerControlQuantum, ThreadSchedulerAction,
};

impl Thread {
    /// Mint the exact generation owned by this live executor quantum.
    pub(crate) fn enter_crash_safe_point_participation(
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
pub(crate) trait ReadinessContext {
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
pub(crate) struct NoReadinessContext;
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
pub(crate) enum PipeCapacityAccounting {
    InMemory,
    Host { queued_bytes: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PipeCapacityMutationError {
    NotPipe,
    Semantic(carrick_abi::LinuxErrno),
    AccountingMismatch,
}

pub(crate) trait FileDescriptionBacking: Any + Send + Sync {
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

    fn timerfd_remaining_timeout(&self) -> Option<Duration> {
        None
    }

    fn as_any(&self) -> &dyn Any;
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
pub(crate) struct AsyncIoOwner {
    pub(crate) owner_type: i32,
    pub(crate) owner_pid: i32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AsyncIoTarget {
    pub(crate) container_id: u64,
    pub(crate) target_id: i32,
    pub(crate) target_generation: u64,
    pub(crate) thread_id: i32,
    pub(crate) thread_generation: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct CapturedAsyncIoOwner {
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
pub(crate) struct DescriptionCommon {
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
    owner: Mutex<CapturedAsyncIoOwner>,
    /// `memfd_create(2)`/`F_ADD_SEALS` seal set. `None` = this description does
    /// not support sealing (`F_GET_SEALS`/`F_ADD_SEALS` → `EINVAL`).
    seals: Arc<Mutex<Option<u32>>>,
    splice_pushback: Mutex<crate::dispatch::SplicePushback>,
    peer_cred: Mutex<Option<SocketPeerCred>>,
    cork: Mutex<SocketCork>,
}

impl DescriptionCommon {
    pub(crate) fn new(status_flags: u64) -> Self {
        Self {
            status_flags: AtomicU64::new(status_flags),
            fd_refs: AtomicUsize::new(0),
            lease: AtomicI32::new(crate::linux_abi::LINUX_F_UNLCK),
            async_sig: AtomicI32::new(0),
            secretmem: AtomicBool::new(false),
            owner: Mutex::new(CapturedAsyncIoOwner::default()),
            seals: Arc::new(Mutex::new(None)),
            splice_pushback: Mutex::new(crate::dispatch::SplicePushback::default()),
            peer_cred: Mutex::new(None),
            cork: Mutex::new(SocketCork::default()),
        }
    }

    pub(crate) fn new_with_seals(status_flags: u64, seals: Arc<Mutex<Option<u32>>>) -> Self {
        Self {
            status_flags: AtomicU64::new(status_flags),
            fd_refs: AtomicUsize::new(0),
            lease: AtomicI32::new(crate::linux_abi::LINUX_F_UNLCK),
            async_sig: AtomicI32::new(0),
            secretmem: AtomicBool::new(false),
            owner: Mutex::new(CapturedAsyncIoOwner::default()),
            seals,
            splice_pushback: Mutex::new(crate::dispatch::SplicePushback::default()),
            peer_cred: Mutex::new(None),
            cork: Mutex::new(SocketCork::default()),
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

    pub(crate) fn cork(&self) -> MutexGuard<'_, SocketCork> {
        self.cork.lock()
    }
}

#[derive(Debug, Default)]
struct DescriptionLifecycle {
    mapping_refs: usize,
}

/// Keeps a mapped file's backing alive without retaining a logical fd slot.
/// Fragments and forked mappings may share this reference through an Arc.
#[derive(Debug)]
pub(crate) struct MappedFileReference {
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
}

impl FileDescription {
    pub(crate) fn common(&self) -> &DescriptionCommon {
        &self.common
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
        }
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

    pub(crate) fn wait_queue(&self) -> Option<Arc<super::wait_set::WaitQueue>> {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.wait_queue(),
            _ => None,
        }
    }

    pub(crate) fn timerfd_remaining_timeout(&self) -> Option<Duration> {
        match &self.kind {
            FileDescriptionKind::Concrete(backing) => backing.0.timerfd_remaining_timeout(),
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
        let _guard = self.lifecycle_transition.lock();
        let count = self.common.retain_fd_ref();
        if count == 1 {
            if let FileDescriptionKind::Concrete(backing) = &self.kind {
                backing.0.on_first_fd_ref();
            }
        }
        self.revision.publish();
    }

    pub(crate) fn release_fd_ref(&self) {
        let lifecycle = self.lifecycle_transition.lock();
        let count = self.common.release_fd_ref();
        if count == 0 {
            if let FileDescriptionKind::Concrete(backing) = &self.kind {
                backing.0.on_last_fd_ref();
                if lifecycle.mapping_refs == 0 {
                    backing.0.on_last_resource_ref();
                }
            }
        }
        self.revision.publish();
    }

    /// Acquire while an fd still owns the backing, serialized with final close.
    pub(crate) fn retain_mapping(self: &Arc<Self>) -> Option<Arc<MappedFileReference>> {
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

    pub(crate) fn timerfd_remaining_timeout(&self) -> Option<Duration> {
        self.description.timerfd_remaining_timeout()
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

pub(crate) struct FileTableFunctionalLease {
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
pub(crate) struct FileSlotHasher(u64);

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

pub(crate) type FileSlotMap = HashMap<i32, FileSlot, BuildHasherDefault<FileSlotHasher>>;

#[derive(Debug)]
pub struct FileTable {
    id: FileTableId,
    open_files: RwLock<FileSlotMap>,
    next_fd: Mutex<i32>,
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
        Self {
            id,
            open_files: RwLock::new(FileSlotMap::default()),
            next_fd: Mutex::new(3),
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

    pub(super) fn for_fork_copy(id: FileTableId, parent: &Self) -> Self {
        let open_files = parent.open_files.read().clone();
        for slot in open_files.values() {
            slot.description.retain_fd_ref();
        }
        let epoll_wake_registry = Arc::clone(&parent.epoll_wake_registry);
        Self {
            id,
            open_files: RwLock::new(open_files),
            next_fd: Mutex::new(*parent.next_fd.lock()),
            stdio_cloexec: Mutex::new(*parent.stdio_cloexec.lock()),
            closed_stdio: Mutex::new(*parent.closed_stdio.lock()),
            fd_open_paths: RwLock::new(parent.fd_open_paths.read().clone()),
            epoll_fds: RwLock::new(parent.epoll_fds.read().clone()),
            epoll_wake_registry,
            functional_gate: Arc::new(FileTableFunctionalGate::new()),
            functional_refs_active: AtomicBool::new(true),
            revision: ObjectRevision::new(),
            slot_subscriptions: Arc::new(FileSlotSubscriptions::default()),
        }
    }

    pub(super) fn for_external_exec(id: FileTableId) -> Self {
        Self::new(id)
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
        let next_fd = *caller.next_fd.lock();
        let fd_open_paths = caller
            .fd_open_paths
            .read()
            .iter()
            .filter_map(|(fd, path)| open_files.contains_key(fd).then_some((*fd, path.clone())))
            .collect();
        let epoll_fds = caller
            .epoll_fds
            .read()
            .iter()
            .filter(|fd| open_files.contains_key(fd))
            .copied()
            .collect();
        Self {
            id,
            open_files: RwLock::new(open_files),
            next_fd: Mutex::new(next_fd),
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

    pub fn install(
        &self,
        number: FileSlotNumber,
        description: Arc<FileDescription>,
        close_on_exec: bool,
    ) -> Option<FileSlot> {
        let _mutation = self.mutation_lease();
        let mut open_files = self.open_files.write();
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
            revision: &self.revision,
            table: self.id,
            subscriptions: &self.slot_subscriptions,
            touched: Vec::new(),
        }
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

    pub(crate) fn read_fd_open_paths(&self) -> RwLockReadGuard<'_, HashMap<i32, String>> {
        self.fd_open_paths.read()
    }

    pub(crate) fn write_fd_open_paths(&self) -> FileTableRwWriteGuard<'_, HashMap<i32, String>> {
        self.rw_write(&self.fd_open_paths)
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
        if !self.functional_gate.retire() {
            return Vec::new();
        }
        self.functional_refs_active.store(false, Ordering::Release);
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
pub(crate) struct FileTableWriteGuard<'a> {
    guard: RwLockWriteGuard<'a, FileSlotMap>,
    _mutation: FileTableMutationLease,
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
            self.subscriptions
                .publish_changes(self.table, &self.guard, &changed);
        }
    }
}

pub(crate) struct FileTableMutexGuard<'a, T> {
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

pub(crate) struct FileTableRwWriteGuard<'a, T> {
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

    pub fn chroot_root(&self) -> Option<String> {
        self.state.read().chroot_root.clone()
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

/// Immutable Linux credential register file. A mutation publishes a fresh
/// Thread credentials. `clone` creates an independent copy; `set*uid`/`set*gid`
/// creates a new [`Credentials`] object and replaces only the calling thread's
/// `ThreadResources` association.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credentials {
    id: CredentialsId,
    pub(crate) ruid: NsUid,
    pub(crate) euid: NsUid,
    pub(crate) suid: NsUid,
    pub(crate) rgid: NsGid,
    pub(crate) egid: NsGid,
    pub(crate) sgid: NsGid,
    pub(crate) fsuid: NsUid,
    pub(crate) fsgid: NsGid,
    pub(crate) umask: u32,
    /// `None` preserves launch-time `/etc/group` fallback; `Some`, including an
    /// empty vector, is the complete set installed by `setgroups(2)`.
    supplementary_groups_override: Option<Vec<NsGid>>,
}

impl Credentials {
    pub const fn root(id: CredentialsId) -> Self {
        Self {
            id,
            ruid: NsUid::ROOT,
            euid: NsUid::ROOT,
            suid: NsUid::ROOT,
            rgid: NsGid::ROOT,
            egid: NsGid::ROOT,
            sgid: NsGid::ROOT,
            fsuid: NsUid::ROOT,
            fsgid: NsGid::ROOT,
            umask: LINUX_DEFAULT_UMASK,
            supplementary_groups_override: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub const fn from_values(
        id: CredentialsId,
        ruid: NsUid,
        euid: NsUid,
        suid: NsUid,
        rgid: NsGid,
        egid: NsGid,
        sgid: NsGid,
        fsuid: NsUid,
        fsgid: NsGid,
        umask: u32,
    ) -> Self {
        Self {
            id,
            ruid,
            euid,
            suid,
            rgid,
            egid,
            sgid,
            fsuid,
            fsgid,
            umask,
            supplementary_groups_override: None,
        }
    }

    pub(super) fn for_copy(id: CredentialsId, source: &Self) -> Self {
        let mut copy = source.clone();
        copy.id = id;
        copy
    }

    pub const fn id(&self) -> CredentialsId {
        self.id
    }
    pub const fn ruid(&self) -> NsUid {
        self.ruid
    }
    pub const fn euid(&self) -> NsUid {
        self.euid
    }
    pub const fn suid(&self) -> NsUid {
        self.suid
    }
    pub const fn rgid(&self) -> NsGid {
        self.rgid
    }
    pub const fn egid(&self) -> NsGid {
        self.egid
    }
    pub const fn sgid(&self) -> NsGid {
        self.sgid
    }
    pub const fn fsuid(&self) -> NsUid {
        self.fsuid
    }
    pub const fn fsgid(&self) -> NsGid {
        self.fsgid
    }
    pub const fn umask(&self) -> u32 {
        self.umask
    }
    pub fn supplementary_groups_override(&self) -> Option<&[NsGid]> {
        self.supplementary_groups_override.as_deref()
    }

    pub(crate) fn seed_identity(&mut self, uid: NsUid, gid: NsGid) {
        self.ruid = uid;
        self.euid = uid;
        self.suid = uid;
        self.fsuid = uid;
        self.rgid = gid;
        self.egid = gid;
        self.sgid = gid;
        self.fsgid = gid;
    }

    pub(crate) const fn is_privileged(&self) -> bool {
        self.euid.is_root()
    }
    pub(crate) fn set_uid_triple(&mut self, ruid: NsUid, euid: NsUid, suid: NsUid) {
        self.ruid = ruid;
        self.euid = euid;
        self.suid = suid;
        self.fsuid = euid;
    }
    pub(crate) fn set_gid_triple(&mut self, rgid: NsGid, egid: NsGid, sgid: NsGid) {
        self.rgid = rgid;
        self.egid = egid;
        self.sgid = sgid;
        self.fsgid = egid;
    }
    pub(crate) fn set_fsuid(&mut self, fsuid: NsUid) {
        self.fsuid = fsuid;
    }
    pub(crate) fn set_fsgid(&mut self, fsgid: NsGid) {
        self.fsgid = fsgid;
    }
    pub(crate) fn set_umask(&mut self, umask: u32) {
        self.umask = umask;
    }
    pub(crate) fn set_supplementary_groups(&mut self, groups: Vec<NsGid>) {
        self.supplementary_groups_override = Some(groups);
    }
    pub(crate) fn copy_values_from(&mut self, source: &Self) {
        self.ruid = source.ruid;
        self.euid = source.euid;
        self.suid = source.suid;
        self.rgid = source.rgid;
        self.egid = source.egid;
        self.sgid = source.sgid;
        self.fsuid = source.fsuid;
        self.fsgid = source.fsgid;
        self.umask = source.umask;
        self.supplementary_groups_override = source.supplementary_groups_override.clone();
    }
}

#[derive(Debug)]
pub struct ThreadResources {
    files: Arc<FileTable>,
    fs_context: Arc<FsContext>,
    credentials: Arc<Credentials>,
}

impl ThreadResources {
    pub fn new(
        files: Arc<FileTable>,
        fs_context: Arc<FsContext>,
        credentials: Arc<Credentials>,
    ) -> Self {
        Self {
            files,
            fs_context,
            credentials,
        }
    }

    pub fn for_clone(
        parent: &Self,
        plan: ClonePlan,
        ids: &ObjectIdRegistry,
    ) -> Result<Self, ObjectIdError> {
        let files = match plan.files() {
            CloneObjectMode::Share => Arc::clone(&parent.files),
            CloneObjectMode::Copy => Arc::new(FileTable::for_fork_copy(
                ids.file_table_id()?,
                &parent.files,
            )),
        };
        let fs_context = match plan.fs_context() {
            CloneObjectMode::Share => Arc::clone(&parent.fs_context),
            CloneObjectMode::Copy => Arc::new(FsContext::for_fork_copy(
                ids.fs_context_id()?,
                &parent.fs_context,
            )),
        };
        Ok(Self::new(
            files,
            fs_context,
            Arc::new(Credentials::for_copy(
                ids.credentials_id()?,
                &parent.credentials,
            )),
        ))
    }

    pub(super) fn for_exec(caller: &Self, ids: &ObjectIdRegistry) -> Result<Self, ObjectIdError> {
        Ok(Self::new(
            Arc::new(FileTable::for_exec(ids.file_table_id()?, &caller.files)),
            Arc::clone(&caller.fs_context),
            Arc::clone(&caller.credentials),
        ))
    }

    pub fn files(&self) -> Arc<FileTable> {
        Arc::clone(&self.files)
    }

    pub fn fs_context(&self) -> Arc<FsContext> {
        Arc::clone(&self.fs_context)
    }

    pub fn credentials(&self) -> Arc<Credentials> {
        Arc::clone(&self.credentials)
    }

    pub(super) fn with_files(&self, files: Arc<FileTable>) -> Self {
        Self::new(
            files,
            Arc::clone(&self.fs_context),
            Arc::clone(&self.credentials),
        )
    }

    pub(super) fn with_credentials(&self, credentials: Arc<Credentials>) -> Self {
        Self::new(
            Arc::clone(&self.files),
            Arc::clone(&self.fs_context),
            credentials,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskLifecycle {
    Live,
    Exiting,
}

pub type TaskRef = Arc<Task>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TaskParticipantError {
    #[error("thread {thread:?} is not a current member of task {task:?}")]
    UnknownThread { task: TaskKey, thread: ThreadKey },
}

fn saturating_fork_sibling_count_for_probe(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

#[derive(Debug)]
pub(crate) struct ForkBarrierParticipants {
    siblings: BTreeSet<ThreadKey>,
}

impl ForkBarrierParticipants {
    pub(crate) fn requires_quiesce(&self) -> bool {
        self.siblings.iter().next().is_some()
    }

    #[cfg(test)]
    pub(crate) fn contains_sibling(&self, key: ThreadKey) -> bool {
        self.siblings.contains(&key)
    }

    /// Exact durable sibling cardinality solely for the existing USDT probe.
    /// Fork admission and barrier control must use [`Self::requires_quiesce`].
    pub(crate) fn initial_sibling_count_for_probe(&self) -> u32 {
        saturating_fork_sibling_count_for_probe(self.siblings.len())
    }
}

#[derive(Debug)]
pub(crate) struct CrashBarrierParticipants {
    siblings: BTreeSet<ThreadKey>,
}

impl CrashBarrierParticipants {
    pub(crate) fn requires_quiesce(&self) -> bool {
        self.siblings.iter().next().is_some()
    }

    #[cfg(test)]
    pub(crate) fn contains_sibling(&self, key: ThreadKey) -> bool {
        self.siblings.contains(&key)
    }
}

#[derive(Debug)]
pub(super) struct ThreadExitParticipants {
    survivors: BTreeSet<ThreadKey>,
}

impl ThreadExitParticipants {
    pub(super) fn permits_nonfinal_exit(&self) -> bool {
        self.survivors.iter().next().is_some()
    }

    #[cfg(test)]
    pub(super) fn contains_survivor(&self, key: ThreadKey) -> bool {
        self.survivors.contains(&key)
    }
}

#[derive(Debug)]
pub(crate) struct CrashCaptureParticipants {
    members: BTreeMap<ThreadKey, ThreadRef>,
}

impl CrashCaptureParticipants {
    pub(crate) fn into_threads(self) -> impl Iterator<Item = ThreadRef> {
        self.members.into_values()
    }
}

#[derive(Debug)]
pub(crate) struct CoreNoteParticipants {
    members: BTreeSet<ThreadKey>,
}

impl CoreNoteParticipants {
    pub(crate) fn required_note_count_for_probe(&self) -> u64 {
        u64::try_from(self.members.len()).unwrap_or(u64::MAX)
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JobControlStopInvalidationGeneration(u64);

/// Non-forgeable authority for one exact settled ptrace stop.
///
/// A resume, detach, or later stop generation invalidates the witness even if
/// the same tracer establishes another settled stop before the consumer
/// reaches its commit point.
#[derive(Clone, Debug)]
pub(crate) struct PtraceMemoryAccessWitness {
    task: Arc<Task>,
    tracer: TaskKey,
    mm_id: MmId,
    stop_generation: u64,
}

/// Borrowed proof that one exact ptrace stop still authorizes text mutation of
/// its exact MM. The value exists only while the target lifecycle/job-control
/// locks are held by `with_revalidated_text` and is deliberately non-cloneable.
pub(crate) struct PtraceTextAccess<'witness> {
    mm_id: MmId,
    _witness: std::marker::PhantomData<&'witness mut ()>,
}

impl PtraceTextAccess<'_> {
    pub(crate) fn mm_id(&self) -> MmId {
        self.mm_id
    }
}

impl PtraceMemoryAccessWitness {
    pub(crate) fn mm_id(&self) -> MmId {
        self.mm_id
    }

    pub(crate) fn with_revalidated<T>(
        &self,
        operation: impl FnOnce() -> T,
    ) -> Result<T, carrick_abi::LinuxErrno> {
        self.task.with_ptrace_memory_access(self, operation)
    }

    pub(crate) fn with_revalidated_text<T>(
        &self,
        mm_id: MmId,
        operation: impl for<'witness> FnOnce(PtraceTextAccess<'witness>) -> T,
    ) -> Result<T, carrick_abi::LinuxErrno> {
        if mm_id != self.mm_id {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        self.task.with_ptrace_memory_access(self, || {
            operation(PtraceTextAccess {
                mm_id,
                _witness: std::marker::PhantomData,
            })
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum DefaultStopGeneration {
    #[default]
    None,
    Pending,
    Cancelled,
}

#[derive(Debug, Default)]
struct TaskJobControl {
    stopped_by: Option<LinuxSignal>,
    pending_stop: Option<LinuxSignal>,
    pending_stop_is_ptrace: bool,
    stopped_by_ptrace: bool,
    ptrace_tracer: Option<TaskKey>,
    ptrace_stop_settled: bool,
    ptrace_stop_generation: u64,
    ptrace_resume_command: Option<PtraceResumeCommand>,
    ptrace_resume_signal: Option<LinuxSignal>,
    ptrace_stopped_fault: Option<BoundPtraceSynchronousFault>,
    ptrace_resume_fault: Option<BoundPtraceSynchronousFault>,
    pending_continue: bool,
    stop_invalidation_generation: u64,
    default_stop_generation: DefaultStopGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PtraceResumeCommand {
    signal: Option<LinuxSignal>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundPtraceSynchronousFault {
    stop_generation: u64,
    fault: PtraceSynchronousFault,
}

fn clear_ptrace_transient_state(state: &mut TaskJobControl) {
    state.ptrace_stop_settled = false;
    state.ptrace_resume_command = None;
    state.ptrace_resume_signal = None;
    state.ptrace_stopped_fault = None;
    state.ptrace_resume_fault = None;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PtraceStopSettlement {
    NotPtraceStopped,
    Stopped,
    Resumed { signal: Option<LinuxSignal> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PtraceSynchronousFault {
    pub(crate) signal: LinuxSignal,
    pub(crate) si_code: i32,
    pub(crate) si_addr: u64,
    pub(crate) interrupted_pc: Option<u64>,
}

fn advance_job_control_stop_invalidation_generation(state: &mut TaskJobControl) {
    let Some(next) = state.stop_invalidation_generation.checked_add(1) else {
        carrick_fatal!(
            "kernel::job_control",
            "job-control stop invalidation generation exhausted"
        );
    };
    state.stop_invalidation_generation = next;
}

fn advance_ptrace_stop_generation(state: &mut TaskJobControl) {
    let Some(next) = state.ptrace_stop_generation.checked_add(1) else {
        carrick_fatal!(
            "kernel::ptrace_stop_authority",
            "ptrace stop generation exhausted"
        );
    };
    state.ptrace_stop_generation = next;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TaskJobControlEvent {
    Stopped(LinuxSignal),
    Continued,
}

/// How the kernel makes a task NOTICE something it has been handed.
///
/// Enqueuing a signal is only half of delivery. A task that reaches a syscall
/// or trap boundary polls its own pending queue and finds it; a task parked in
/// a host wait — a blocking read, a futex, `waitpid`, a kqueue — finds nothing,
/// because none of those vehicles watch the kernel's queues. Waking it is
/// unavoidably host-specific (on the kernel lane: unpark the futex table, poke
/// the wake pipes, force the vCPU out of `hv_vcpu_run`), so the kernel names
/// the CAPABILITY and each lane supplies it.
///
/// Waking is a hint, never a guarantee of consumption: the woken task re-reads
/// the authoritative queue and decides for itself. That makes a spurious wake
/// harmless and a missing implementation merely slow rather than wrong — a task
/// with no waker still notices at its next boundary.
pub trait TaskWaker: Send + Sync + std::fmt::Debug {
    /// Kick every vehicle this task may be parked on. Idempotent, and safe to
    /// call for a task that is running or already awake.
    fn wake_task(&self);
}

type TaskWakeCallback = Arc<dyn Fn(u64) + Send + Sync + 'static>;

struct TaskWakeListener {
    expected_generation: u64,
    callback: TaskWakeCallback,
}

impl std::fmt::Debug for TaskWakeListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskWakeListener")
            .field("expected_generation", &self.expected_generation)
            .finish_non_exhaustive()
    }
}

pub struct TaskWakeSubscription {
    listeners: Weak<Mutex<BTreeMap<u64, TaskWakeListener>>>,
    id: u64,
}

impl Drop for TaskWakeSubscription {
    fn drop(&mut self) {
        if let Some(listeners) = self.listeners.upgrade() {
            listeners.lock().remove(&self.id);
        }
    }
}

pub enum TaskWakeEnrollment {
    Ready(u64),
    Subscribed(TaskWakeSubscription),
}

/// A process's `PR_SET_DUMPABLE` attribute (prctl(2)): whether it can be
/// core-dumped and — the guest-visible half — whether it is `ptrace`-attachable
/// by a same-uid caller. `Disable` means only `CAP_SYS_PTRACE` may attach.
///
/// This is process state in the kernel graph, not a dispatcher cell, because
/// `attach_task_for_ptrace` has to read the TARGET's attribute, and the target
/// is another Linux process whose dispatcher the caller cannot see.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum DumpableMode {
    /// `SUID_DUMP_DISABLE`: not dumpable, not attachable without
    /// `CAP_SYS_PTRACE`.
    Disable = 0,
    /// `SUID_DUMP_USER` (the default): dumpable and attachable by a uid match.
    User = 1,
}

impl DumpableMode {
    /// The value a guest wrote through `prctl(PR_SET_DUMPABLE, arg2)`. Linux
    /// accepts only 0 and 1 (`SUID_DUMP_ROOT` is root-only via `/proc/sys` and
    /// rejected here with EINVAL, exactly as the oracle does).
    pub fn from_prctl(raw: u64) -> Option<Self> {
        match raw {
            0 => Some(Self::Disable),
            1 => Some(Self::User),
            _ => None,
        }
    }

    /// The value `prctl(PR_GET_DUMPABLE)` returns.
    pub fn to_prctl(self) -> i64 {
        i64::from(self as i32)
    }

    fn from_atomic(raw: i32) -> Self {
        if raw == Self::Disable as i32 {
            Self::Disable
        } else {
            Self::User
        }
    }
}

#[derive(Debug)]
pub struct Task {
    key: TaskKey,
    parent: Mutex<Option<TaskKey>>,
    children: Mutex<BTreeSet<TaskKey>>,
    /// Tasks this task traces (`PTRACE_TRACEME` children and `PTRACE_ATTACH`
    /// targets). A tracee's own `ptrace_tracer` stays authoritative; this set
    /// only lets the tracer's `wait` and exit find its tracees without a
    /// registry sweep, so an entry that no longer names this task as tracer
    /// is stale and ignored.
    ptrace_tracees: Mutex<BTreeSet<TaskKey>>,
    /// The signal this process delivers to its parent on termination (the
    /// clone `CSIGNAL` byte / `clone3` `exit_signal`; `SIGCHLD` for `fork`).
    /// Fixed at creation: it is what `wait(2)` partitions children on, so a
    /// parent's plain `waitpid` must keep ignoring a `clone(..|0)` child for
    /// the child's whole life, not only until it exits.
    exit_signal: ChildExitSignal,
    identity: Mutex<TaskIdentity>,
    lifecycle: Mutex<TaskLifecycle>,
    /// Process-directed signal permission uses the last published thread-group
    /// leader credential generation. Keep it after a non-final leader exit; a
    /// live task must not become ESRCH merely because only siblings remain.
    process_credentials: ArcSwap<Credentials>,
    /// Guest job-control state is task scoped. HVPatch cannot lower it to host
    /// SIGSTOP/SIGCONT because all guest tasks share one Darwin process.
    signal_generation: Mutex<()>,
    job_control: Mutex<TaskJobControl>,
    job_control_changed: Condvar,
    shared: ArcSwap<TaskShared>,
    threads: Mutex<BTreeMap<LinuxTid, (ThreadKey, ThreadRef)>>,
    cpu: TaskCpu,
    /// Lane-supplied wake vehicle, absent until the runtime publishes one (and
    /// on lanes that have none). Held here rather than in a side table so it
    /// cannot outlive the task or be looked up for a retired one.
    waker: Mutex<Option<Arc<dyn TaskWaker>>>,
    /// Durable counterpart to the lane wake hint. A vCPU can be between a
    /// syscall boundary and guest re-entry when the host kick fires; retaining
    /// the generation lets that same boundary reconcile the authoritative
    /// pending state before it enters guest code.
    wake_generation: AtomicU64,
    task_event_generation: AtomicU64,
    wake_listeners: Arc<Mutex<BTreeMap<u64, TaskWakeListener>>>,
    next_wake_listener: AtomicU64,
    has_run: AtomicBool,
    /// Linux's per-process OOM-killer bias, `/proc/<pid>/oom_score_adj`
    /// (proc(5)): inherited at fork, independent of the parent afterwards, and
    /// shared by every thread of the process.
    ///
    /// It is task state rather than a host-process global for the same reason
    /// [`TaskCpu`] is: under HVPatch all Linux processes are threads of ONE
    /// Darwin process, so a global would publish one guest process's write to
    /// every other one. LTP's `tst_test` setup writes -1000 to *another*
    /// process's file and reads it back (`tst_memutils.c:set_oom_score_adj`),
    /// which a shared cell cannot model.
    oom_score_adj: AtomicI32,
    /// `PR_SET_DUMPABLE` (prctl(2)): inherited across fork, reset to
    /// [`DumpableMode::User`] by exec (carrick has no set-uid exec, so the
    /// `suid_dumpable` exception never applies), and shared by every thread.
    /// Read by ptrace attach permission checks for the TARGET task.
    dumpable: AtomicI32,
    /// This process's nice value (`getpriority`/`setpriority`): range
    /// [-20, 19], default 0. Inherited across fork and preserved across exec.
    ///
    /// Per-TASK, not a runtime `static`: under HVPatch many logical Linux
    /// processes share one host carrier, so a global cell leaks one process's
    /// nice into every other. (Linux's own granularity is finer still — nice is
    /// really per-thread — see `nice()`.)
    nice: AtomicI32,
    /// This process's I/O priority, stored by `ioprio_set` and echoed by
    /// `ioprio_get`. Carrick has no real I/O scheduler, so this is a faithful
    /// value store, not a scheduling input. Default `IOPRIO_CLASS_BE(2)` level
    /// 4 = `(2 << 13) | 4`, what Linux reports for a process that never set one.
    ///
    /// Per-TASK for the same reason as [`Task::nice`]: it was a runtime-global
    /// `static IOPRIO_VALUE` in `dispatch/proc.rs`, which every logical Linux
    /// process in the carrier shared.
    ioprio: AtomicU32,
    /// This process's keyring pointers (`keyrings(7)`): the process keyring,
    /// the session keyring, and the `KEYCTL_SET_REQKEY_KEYRING` default.
    ///
    /// They are task state, not thread state, because Linux shares them across
    /// every thread of a process — and they are not a host-process global for
    /// the same reason [`Task::oom_score_adj`] is not: under HVPatch every
    /// Linux process is a thread of ONE Darwin process, so a global would let
    /// one guest's `KEYCTL_JOIN_SESSION_KEYRING` reassign every other guest's
    /// session keyring.
    keyrings: Mutex<ProcessKeyrings>,
    /// This process's five capability sets (`capabilities(7)`) and its
    /// user-namespace view (`user_namespaces(7)`) — the `uid_map`/`gid_map`/
    /// `setgroups` state behind `/proc/self/*`.
    ///
    /// Both are per-process attributes that a `fork` child inherits as a COPY
    /// and then owns: `PR_CAPBSET_DROP`, `capset`, `PR_CAP_AMBIENT_*` and a
    /// `uid_map` write change only the calling process. They live on the task
    /// for the same reason [`Task::oom_score_adj`] and [`Task::keyrings`] do —
    /// under HVPatch every Linux process is a thread of ONE Darwin process, so
    /// the `static` that used to hold them was a single cell shared by every
    /// guest process at once. That made one guest's capbset drop remove the
    /// capability from every other guest, irreversibly, and published one
    /// guest's `uid_map` in every other guest's `/proc/self/uid_map`.
    ///
    /// One mutex covers both because `unshare(CLONE_NEWUSER)` must replace the
    /// namespace and grant the full set as a single atomic step; splitting
    /// them would let a reader observe a fresh namespace with the old caps.
    creds_ns: Mutex<ProcessCredsNs>,
    /// This process's resource limits (`getrlimit(2)`, `prlimit(2)`).
    ///
    /// On the TASK because that is Linux's own scope — an rlimit lives in
    /// `signal_struct`, shared by every thread of a thread group — and because a
    /// peer must be able to WRITE it: `prlimit(pid, …)` sets ANOTHER process's
    /// limit. Held in the dispatcher's private `ProcState` instead, there was no
    /// path from any other task into the table at all, so `prlimit` silently
    /// wrote the CALLER's limits: the target saw nothing change and the caller's
    /// own soft NOFILE moved underneath it. Go's `TestPrlimitFileLimit` is
    /// exactly that shape.
    ///
    /// `ArcSwap` rather than a `Mutex` because the read path is hot and runs
    /// under other locks — `Nofile` is consulted inside fd allocation while the
    /// file table is held, and `Fsize` on every regular-file write — so a read
    /// must not be able to block on a writer.
    rlimits: ArcSwap<RlimitSet>,
    /// Serializes read-modify-write on [`Self::rlimits`]. `ArcSwap` gives atomic
    /// publication, not atomic update: `setrlimit` has to compare the new soft
    /// against the CURRENT hard, and two concurrent writers reading the same
    /// snapshot would each publish a set built from a stale one.
    rlimit_write: Mutex<()>,
    /// Which network and UTS namespaces this process belongs to — Linux's
    /// `nsproxy`.
    ///
    /// Both were previously answered from outside the kernel graph and were
    /// wrong in OPPOSITE directions, which is why they land together. The
    /// network view was a carrier-global `Arc<RuntimeNetwork>` on the
    /// dispatcher, so every guest process shared one and `unshare(CLONE_NEWNET)`
    /// had nowhere to write. The hostname was a `String` in the dispatcher's
    /// private `ProcState` that the fork path CLONED, so a parent's
    /// `sethostname` never reached its children — where Linux shares one
    /// `uts_namespace` across `fork` and the child does see the new name.
    ///
    /// `ArcSwap` for the same reason [`Self::rlimits`] uses it: reading a task's
    /// namespaces is on the guest's syscall path (every `/proc/net` read, every
    /// `uname`) while replacing them happens only at `unshare`. The proxy is
    /// swapped whole rather than field-by-field so `unshare(CLONE_NEWNET |
    /// CLONE_NEWUTS)` cannot be observed half-applied.
    nsproxy: ArcSwap<NsProxy>,
    /// Serializes read-modify-write on [`Self::nsproxy`] — an `unshare` builds
    /// the replacement from the CURRENT proxy, so two concurrent unsharers
    /// reading one snapshot would each drop the other's namespace.
    nsproxy_write: Mutex<()>,
}

/// A process's sixteen resource limits, indexed by [`LinuxResource`].
///
/// A dense array rather than a map of overrides: the previous shape stored
/// `Option<LinuxRlimit>` per slot and resolved "unset" to a default at every
/// read, which is why three different files answered "max processes" three
/// different ways. One table, one answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RlimitSet {
    limits: [LinuxRlimit; LinuxResource::COUNT],
}

impl RlimitSet {
    /// The limits a guest process starts with.
    ///
    /// These are carrick's answer for a container, and they are the SINGLE
    /// source: `getrlimit`, `/proc/<pid>/limits` and every enforcement site read
    /// this table, so they cannot disagree the way the frozen `/proc` literal
    /// disagreed with `getrlimit` on four resources.
    pub const fn carrick_defaults() -> Self {
        const INF: u64 = LINUX_RLIM_INFINITY;
        let unlimited = LinuxRlimit::new(INF, INF);
        let mut limits = [unlimited; LinuxResource::COUNT];
        // Docker's default container limits, which the conformance oracle runs
        // with; anything not listed is unlimited.
        limits[LinuxResource::Nofile.index()] = LinuxRlimit::new(1_048_576, 1_048_576);
        limits[LinuxResource::Nproc.index()] = LinuxRlimit::new(8_192, 8_192);
        limits[LinuxResource::Stack.index()] = LinuxRlimit::new(8 * 1024 * 1024, INF);
        limits[LinuxResource::Sigpending.index()] = LinuxRlimit::new(63_880, 63_880);
        limits[LinuxResource::Msgqueue.index()] = LinuxRlimit::new(819_200, 819_200);
        limits[LinuxResource::Nice.index()] = LinuxRlimit::new(0, 0);
        limits[LinuxResource::Rtprio.index()] = LinuxRlimit::new(0, 0);
        Self { limits }
    }

    pub const fn get(&self, resource: LinuxResource) -> LinuxRlimit {
        self.limits[resource.index()]
    }

    /// Returns the set with `resource` replaced — `RlimitSet` is `Copy`, so a
    /// writer publishes a whole new snapshot rather than mutating one readers
    /// may be holding.
    pub const fn with(mut self, resource: LinuxResource, limit: LinuxRlimit) -> Self {
        self.limits[resource.index()] = limit;
        self
    }
}

/// A process's keyring pointers. Serials rather than object references: the
/// keys themselves live in the VM-wide [`crate::keyring::KeyringService`], and
/// naming them by serial is what lets a `fork` child share the parent's session
/// keyring by simply copying the number.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessKeyrings {
    /// `KEY_SPEC_PROCESS_KEYRING`, materialised on demand.
    pub process: Option<KeySerial>,
    /// `KEY_SPEC_SESSION_KEYRING`. `None` means this process has never joined
    /// one, so its session keyring IS its user-session keyring — Linux's
    /// default, and the reason a fresh guest can still `add_key` to
    /// `KEY_SPEC_SESSION_KEYRING`.
    pub session: Option<KeySerial>,
    /// Where `request_key(2)` links a constructed key when the caller passes
    /// destination 0.
    pub request_key_default: KeyRequestDefault,
}

/// The two CPU ledgers Linux keeps for every process, owned by the kernel
/// rather than read back out of the host.
///
/// `times(2)` reports the process's own CPU in `tms_utime`/`tms_stime` and the
/// summed CPU of its *reaped* children in `tms_cutime`/`tms_cstime`;
/// `getrusage(2)` spells the same split `RUSAGE_SELF` versus
/// `RUSAGE_CHILDREN`. Sourcing either from the host process is wrong under
/// HVPatch by construction: all Linux processes are threads of one host
/// process, so a host per-process counter is the sum over every guest at once.
#[derive(Debug, Default)]
struct TaskCpu {
    /// CPU of this task's threads that have already exited. Live threads are
    /// totalled on demand from their `guest_cpu` slots; this is the part that
    /// would otherwise be lost when a slot is released.
    exited_threads_us: AtomicU64,
    /// SYSTEM CPU of this task's exited threads, the counterpart to
    /// `exited_threads_us`. Kept separate rather than summed because Linux
    /// reports the two independently and a caller that conflates them cannot
    /// be corrected later.
    exited_threads_system_us: AtomicU64,
    /// User CPU of reaped children, including the children's own reaped
    /// children — Linux folds a reaped child's `cutime` into its parent's.
    children_user_us: AtomicU64,
    children_system_us: AtomicU64,
}

impl Task {
    pub fn new(
        key: TaskKey,
        parent: Option<TaskKey>,
        identity: TaskIdentity,
        shared: Arc<TaskShared>,
        process_credentials: Arc<Credentials>,
        container: Arc<Container>,
        exit_signal: ChildExitSignal,
    ) -> Self {
        Self {
            key,
            parent: Mutex::new(parent),
            children: Mutex::new(BTreeSet::new()),
            ptrace_tracees: Mutex::new(BTreeSet::new()),
            exit_signal,
            identity: Mutex::new(identity),
            lifecycle: Mutex::new(TaskLifecycle::Live),
            process_credentials: ArcSwap::new(process_credentials),
            signal_generation: Mutex::new(()),
            job_control: Mutex::new(TaskJobControl::default()),
            job_control_changed: Condvar::new(),
            shared: ArcSwap::new(shared),
            threads: Mutex::new(BTreeMap::new()),
            cpu: TaskCpu::default(),
            waker: Mutex::new(None),
            wake_generation: AtomicU64::new(0),
            task_event_generation: AtomicU64::new(0),
            wake_listeners: Arc::new(Mutex::new(BTreeMap::new())),
            next_wake_listener: AtomicU64::new(1),
            has_run: AtomicBool::new(false),
            oom_score_adj: AtomicI32::new(0),
            dumpable: AtomicI32::new(DumpableMode::User as i32),
            nice: AtomicI32::new(0),
            ioprio: AtomicU32::new(Task::DEFAULT_IOPRIO),
            keyrings: Mutex::new(ProcessKeyrings::default()),
            creds_ns: Mutex::new(ProcessCredsNs::default()),
            rlimits: ArcSwap::new(Arc::new(RlimitSet::carrick_defaults())),
            rlimit_write: Mutex::new(()),
            nsproxy: ArcSwap::new(Arc::new(NsProxy::for_container(container))),
            nsproxy_write: Mutex::new(()),
        }
    }

    /// Mark this task as having run on an executor, returning `true` on first call.
    pub fn mark_first_run(&self) -> bool {
        !self.has_run.swap(true, Ordering::AcqRel)
    }

    /// The signal this process delivers to its parent when it terminates.
    pub fn exit_signal(&self) -> ChildExitSignal {
        self.exit_signal
    }

    /// What Linux reports for a process that never called `ioprio_set`:
    /// `IOPRIO_CLASS_BE` (2) at level 4, packed as `(class << 13) | level`.
    pub const DEFAULT_IOPRIO: u32 = (2 << 13) | 4;

    /// This process's packed I/O priority (`ioprio_get`).
    pub fn ioprio(&self) -> u32 {
        self.ioprio.load(Ordering::SeqCst)
    }

    /// Store this process's packed I/O priority (`ioprio_set`).
    pub fn set_ioprio(&self, value: u32) {
        self.ioprio.store(value, Ordering::SeqCst);
    }

    /// This process's nice value (default 0).
    pub fn nice(&self) -> i32 {
        self.nice.load(Ordering::Relaxed)
    }

    /// Set this process's nice value.
    pub fn set_nice(&self, value: i32) {
        self.nice.store(value, Ordering::Relaxed);
    }

    /// Copy every per-process attribute Linux inherits across `fork(2)` and
    /// leaves independent thereafter, from `parent` into this fresh child task.
    ///
    /// This exists as ONE named operation because there are TWO fork paths that
    /// mint a child `Task`, and they drifted: `ForkReservation::prepare` (the
    /// in-process path HVPatch uses) carried all four, while the host-fork
    /// adapter `reset_one_task_kernel_binding_for_current_process` — taken by
    /// backends whose `supports_in_process_fork()` is false — bootstrapped a
    /// brand-new root task and carried none of them. That difference was
    /// invisible while these values lived in process-global `static`s, because
    /// `libc::fork` copied the statics for free. Moving them onto `Task` makes
    /// the omission load-bearing, so the two paths must share this one call.
    pub fn inherit_fork_attributes_from(&self, parent: &Task) {
        // oom_score_adj is inherited across fork and independent thereafter
        // (`proc(5)`).
        self.set_oom_score_adj(parent.oom_score_adj());
        // The dumpable attribute is inherited across fork (prctl(2)).
        self.set_dumpable(parent.dumpable());
        // nice is inherited across fork (`fork(2)`: "the child's nice value is
        // the same as the parent's").
        self.set_nice(parent.nice());
        // I/O priority is likewise inherited across fork (`ioprio_set(2)`).
        self.set_ioprio(parent.ioprio());
        // The session and process keyrings and the `KEYCTL_SET_REQKEY_KEYRING`
        // default are inherited (`keyrings(7)`); the thread keyring is not, and
        // a fresh leader starts without one.
        self.inherit_keyrings_from(parent);
        // The five capability sets and the user-namespace view are inherited as
        // a COPY (`capabilities(7)`, `user_namespaces(7)`): the child starts
        // identical, and each side's later `PR_CAPBSET_DROP` / `capset` /
        // `uid_map` write is invisible to the other.
        self.inherit_creds_ns_from(parent);
        // Resource limits are inherited as a COPY (`fork(2)`), and each side
        // owns its own afterwards — the whole point of the defect this fixes is
        // that one process's `prlimit` must not move another's.
        self.rlimits.store(Arc::new(parent.rlimits()));
        // The network and UTS namespaces are inherited as a SHARE, not a copy
        // (`namespaces(7)`: `fork` without `CLONE_NEW*` leaves the child in
        // every one of its parent's namespaces). Cloning the `Arc`s is what
        // makes that true — a parent's `sethostname` or a new address on `eth0`
        // is visible to children that already exist.
        self.inherit_ns_from(parent);
    }

    /// This process's limit for one resource.
    ///
    /// `ArcSwap::load` is a hazard-pointer guard, not an allocation, so this is
    /// safe to call on the hot paths that need it — fd allocation holds the file
    /// table while asking for `Nofile`, and every regular-file write asks for
    /// `Fsize`.
    pub fn rlimit(&self, resource: LinuxResource) -> LinuxRlimit {
        self.rlimits.load().get(resource)
    }

    /// This process's whole limit set, for `/proc/<pid>/limits`.
    pub fn rlimits(&self) -> RlimitSet {
        **self.rlimits.load()
    }

    /// Replace one resource's limit under the write lock, letting `decide` see
    /// the CURRENT value.
    ///
    /// The closure is where `setrlimit`'s rules live (a soft above the hard is
    /// EINVAL; raising the hard needs CAP_SYS_RESOURCE), and it must run against
    /// the value it will replace — which is why this is a read-modify-write
    /// under a mutex rather than a bare `ArcSwap::store`.
    pub fn replace_rlimit<E>(
        &self,
        resource: LinuxResource,
        decide: impl FnOnce(LinuxRlimit) -> Result<LinuxRlimit, E>,
    ) -> Result<LinuxRlimit, E> {
        let _write = self.rlimit_write.lock();
        let current = self.rlimits.load();
        let old = current.get(resource);
        let new = decide(old)?;
        self.rlimits.store(Arc::new(current.with(resource, new)));
        Ok(old)
    }

    /// A snapshot of this process's capability sets and user-namespace view,
    /// for the `/proc` render context.
    pub fn creds_ns(&self) -> ProcessCredsNs {
        self.creds_ns.lock().clone()
    }

    /// This process's capability sets, by value.
    pub fn caps(&self) -> CapabilitySet {
        self.creds_ns.lock().caps
    }

    /// Mutate this process's capability sets under the task lock, so a
    /// read-modify-write (`capset`, `PR_CAPBSET_DROP`, `PR_CAP_AMBIENT_RAISE`)
    /// cannot race a sibling thread of the same process. All threads of a
    /// Linux process share one set, which is why this is task state and not
    /// thread state.
    pub fn with_caps<R>(&self, f: impl FnOnce(&mut CapabilitySet) -> R) -> R {
        f(&mut self.creds_ns.lock().caps)
    }

    /// This process's user namespace, by value.
    pub fn user_ns(&self) -> UserNs {
        self.creds_ns.lock().user.clone()
    }

    /// Mutate this process's user-namespace view under the task lock — the
    /// `/proc/self/{uid_map,gid_map,setgroups}` write path.
    pub fn with_user_ns<R>(&self, f: impl FnOnce(&mut UserNs) -> R) -> R {
        f(&mut self.creds_ns.lock().user)
    }

    /// `unshare(CLONE_NEWUSER)` (and the `clone(CLONE_NEWUSER)` child path):
    /// place this process in a fresh user namespace parented at its current
    /// one, and grant it a full capability set WITHIN that namespace
    /// (`user_namespaces(7)`; design §4.1, §4.6). Returns the new id.
    ///
    /// Namespace replacement and the capability grant happen under one lock so
    /// no reader sees the new namespace with the old caps.
    pub fn unshare_user_ns(&self) -> crate::namespace::NsId {
        let id = crate::namespace::process::alloc_ns_id();
        let mut guard = self.creds_ns.lock();
        let parent = guard.user.id;
        guard.user = UserNs::fresh(id, parent);
        guard.caps = CapabilitySet::full();
        id
    }

    /// Copy the parent's capability sets and user-namespace view into a fresh
    /// `fork` child.
    ///
    /// `capabilities(7)`: `fork` preserves all five sets verbatim — the child
    /// starts identical to the parent and diverges only through its own later
    /// `capset`/`PR_CAPBSET_DROP`/`PR_CAP_AMBIENT_*`. `user_namespaces(7)`: the
    /// child is a member of the parent's user namespace, seeing the same
    /// `uid_map`/`gid_map`. Both are COPIES, so a later change on either side
    /// is invisible to the other.
    ///
    /// There is no execve counterpart: `execve` does not build a new [`Task`],
    /// and Linux preserves the bounding, inheritable and ambient sets across an
    /// exec of an ordinary (non-setuid, no-file-capability) binary — which is
    /// every exec carrick models, since it implements neither file capabilities
    /// nor the set-user-ID bit. Preserving the whole struct is therefore the
    /// correct execve behaviour and needs no code.
    pub fn inherit_creds_ns_from(&self, parent: &Task) {
        *self.creds_ns.lock() = parent.creds_ns.lock().clone();
    }

    /// The network namespace this process belongs to. Every guest-facing
    /// network surface — rtnetlink, `/proc/net/*`, `/sys/class/net`, the `SIOC*`
    /// ioctls — renders from the view this namespace holds, so two processes in
    /// different namespaces get different answers and no surface can reach past
    /// it to the host's own interface list.
    pub fn net_ns(&self) -> Arc<NetNs> {
        Arc::clone(self.nsproxy.load().net())
    }

    /// The PID namespace region of this process's container, or `None` when
    /// the container shares the host pid namespace (`--pid host`). This is the
    /// ONLY path from a task to pid translation: `namespace::pid::region()`
    /// resolves the calling task through it, never through a static.
    pub fn pid_ns_region(&self) -> Option<Arc<crate::namespace::pid::NsSharedRegion>> {
        self.container().pid_region()
    }

    /// The UTS namespace this process belongs to — the nodename `uname(2)` and
    /// `/proc/sys/kernel/hostname` report.
    pub fn uts_ns(&self) -> Arc<UtsNs> {
        Arc::clone(self.nsproxy.load().uts())
    }

    /// The container this process belongs to, read through the task's
    /// `nsproxy` — never a static — so two containers in one carrier cannot
    /// alias. Inherited across `fork` as a share by
    /// [`Self::inherit_fork_attributes_from`] (its `inherit_ns_from` stores
    /// the parent's whole proxy `Arc`).
    pub fn container(&self) -> Arc<Container> {
        Arc::clone(self.nsproxy.load().container())
    }

    /// `unshare(CLONE_NEWUTS)`: put THIS process in a fresh UTS namespace
    /// carrying a COPY of the name it can currently see, leaving its parent and
    /// siblings in the one they share. Returns the new id.
    ///
    /// Copy on unshare, share on fork — the two directions this whole pair
    /// exists to keep apart. `namespaces(7)`: the new namespace is initialised
    /// from the caller's, and the two diverge from that point, so a later
    /// `sethostname` on either side is invisible to the other.
    ///
    /// Under the write lock because the replacement proxy is built from the
    /// CURRENT one: two concurrent unsharers reading a single snapshot would
    /// each discard the other's namespace.
    ///
    /// No guest syscall reaches this yet — `unshare(CLONE_NEWUTS)` is accepted
    /// and ignored and `sethostname` is unconditional EPERM, both in
    /// `dispatch/proc.rs`, which the process-identity batch moves onto this.
    pub fn unshare_uts_ns(&self) -> crate::namespace::NsId {
        let id = crate::namespace::process::alloc_ns_id();
        let _write = self.nsproxy_write.lock();
        let current = self.nsproxy.load();
        let fresh = Arc::new(UtsNs::new(id, current.uts().nodename()));
        self.nsproxy.store(Arc::new(current.entering_uts(fresh)));
        id
    }

    /// `unshare(CLONE_NEWNET)`: put THIS process in a fresh network namespace,
    /// leaving its parent and siblings in the one they share. Returns the new
    /// id.
    ///
    /// Unlike UTS, a new network namespace is NOT a copy — Linux gives it
    /// nothing but a loopback device, and every address, route and resolver the
    /// caller could see is gone. Carrick renders that loopback already
    /// configured (`127.0.0.1/8`, `::1/128`, up), where Linux leaves it down
    /// and address-less until something runs `ip link set lo up`; there is no
    /// guest path to configure a link yet, so a down loopback would be a
    /// namespace nothing could ever make usable.
    ///
    /// Same lock discipline and the same staging as [`Self::unshare_uts_ns`]:
    /// the guest-facing `unshare` still refuses `CLONE_NEWNET`, and must keep
    /// refusing until sockets are confined to a namespace as well — accepting
    /// the flag and then putting the guest's traffic on the host's wire would be
    /// worse than an honest EPERM.
    pub fn unshare_net_ns(&self) -> crate::namespace::NsId {
        let id = crate::namespace::process::alloc_ns_id();
        let fresh = Arc::new(NetNs::from_model(
            id,
            crate::network::model::LinuxNetworkModel::isolated(),
        ));
        let _write = self.nsproxy_write.lock();
        let current = self.nsproxy.load();
        self.nsproxy.store(Arc::new(current.entering_net(fresh)));
        id
    }

    /// Place a fresh `fork` child in every namespace its parent belongs to.
    ///
    /// `namespaces(7)`: a `fork` without `CLONE_NEW*` shares the parent's
    /// namespaces rather than copying their contents, so this clones POINTERS.
    /// The distinction is guest-visible and was the defect: the hostname lived
    /// in a struct the fork path cloned by value, so `sethostname` in a parent
    /// left every existing child reporting the old name from `uname(2)` — where
    /// Linux reports the new one.
    fn inherit_ns_from(&self, parent: &Task) {
        let _write = self.nsproxy_write.lock();
        self.nsproxy.store(parent.nsproxy.load_full());
    }

    /// This process's keyring pointers.
    pub fn keyrings(&self) -> ProcessKeyrings {
        *self.keyrings.lock()
    }

    /// Mutate this process's keyring pointers under the task lock, so a
    /// materialise-if-absent (`KEYCTL_GET_KEYRING_ID` with create) cannot race
    /// a sibling thread into two keyrings for one process.
    pub fn with_keyrings<R>(&self, f: impl FnOnce(&mut ProcessKeyrings) -> R) -> R {
        f(&mut self.keyrings.lock())
    }

    /// Copy the parent's keyring pointers into a fresh `fork` child.
    ///
    /// `keyrings(7)`: the session keyring is INHERITED — parent and child go on
    /// sharing one keyring object until one of them joins another — and so is
    /// the request-key default. The THREAD keyring is deliberately absent here:
    /// Linux does not pass it to a child, and neither does carrick (a fresh
    /// [`Thread`] starts with none).
    pub fn inherit_keyrings_from(&self, parent: &Task) {
        *self.keyrings.lock() = parent.keyrings();
    }

    /// This process's `/proc/<pid>/oom_score_adj` (default 0).
    pub fn oom_score_adj(&self) -> i32 {
        self.oom_score_adj.load(Ordering::Relaxed)
    }

    /// Set this process's `oom_score_adj`. The caller has already range-checked
    /// `value` against Linux's [-1000, 1000]; fork inheritance copies the
    /// parent's value into the child at creation.
    pub fn set_oom_score_adj(&self, value: i32) {
        self.oom_score_adj.store(value, Ordering::Relaxed);
    }

    /// This process's `PR_GET_DUMPABLE` attribute.
    pub fn dumpable(&self) -> DumpableMode {
        DumpableMode::from_atomic(self.dumpable.load(Ordering::Relaxed))
    }

    /// `prctl(PR_SET_DUMPABLE)`; fork inheritance copies the parent's value
    /// and exec resets it through [`Task::reset_dumpable_for_exec`].
    pub fn set_dumpable(&self, mode: DumpableMode) {
        self.dumpable.store(mode as i32, Ordering::Relaxed);
    }

    /// exec restores the default (prctl(2): "the dumpable attribute is reset
    /// to 1 across execve"). Carrick has no set-uid or unreadable-image exec
    /// that would instead apply `/proc/sys/fs/suid_dumpable`.
    pub(super) fn reset_dumpable_for_exec(&self) {
        self.set_dumpable(DumpableMode::User);
    }

    /// Publish the lane's wake vehicle for this task, replacing any previous
    /// one. The runtime calls this once the task has a vCPU and a futex table
    /// to kick.
    pub fn set_waker(&self, waker: Arc<dyn TaskWaker>) {
        *self.waker.lock() = Some(waker);
    }

    /// Kick every vehicle this task may be parked on, so it reaches a point
    /// where it re-reads the kernel's authoritative state.
    ///
    /// THE single door for waking a task. A no-op when no waker is published —
    /// the task then notices at its next syscall or trap boundary, which is
    /// slower but not wrong. Waking is always a hint: nothing is consumed here
    /// and the woken task decides for itself what it found, so a spurious call
    /// is harmless.
    pub fn wake(&self) -> bool {
        self.publish_wake(true)
    }

    pub(crate) fn publish_wake_subscriptions(&self) -> bool {
        self.publish_wake(false)
    }

    fn publish_wake(&self, wake_vehicle: bool) -> bool {
        let previous = self.wake_generation.fetch_add(1, Ordering::AcqRel);
        let generation = previous.wrapping_add(1);
        let callbacks = {
            let mut listeners = self.wake_listeners.lock();
            listeners
                .values_mut()
                .filter_map(|listener| {
                    (listener.expected_generation != generation).then(|| {
                        listener.expected_generation = generation;
                        Arc::clone(&listener.callback)
                    })
                })
                .collect::<Vec<_>>()
        };
        let published_to_subscription = !callbacks.is_empty();
        for callback in callbacks {
            callback(generation);
        }
        if wake_vehicle {
            let waker = self.waker.lock().clone();
            if let Some(waker) = waker {
                waker.wake_task();
            }
        }
        published_to_subscription
    }

    pub fn wake_generation(&self) -> u64 {
        self.wake_generation.load(Ordering::Acquire)
    }

    pub fn record_task_event(&self) -> u64 {
        self.task_event_generation.fetch_add(1, Ordering::AcqRel)
    }

    pub fn task_event_generation(&self) -> u64 {
        self.task_event_generation.load(Ordering::Acquire)
    }

    pub fn subscribe_wake(
        &self,
        expected_generation: u64,
        callback: TaskWakeCallback,
    ) -> TaskWakeEnrollment {
        let mut listeners = self.wake_listeners.lock();
        let current = self.wake_generation();
        if current != expected_generation {
            return TaskWakeEnrollment::Ready(current);
        }
        let id = self.next_wake_listener.fetch_add(1, Ordering::Relaxed);
        if id == 0 || id == u64::MAX {
            return TaskWakeEnrollment::Ready(current);
        }
        listeners.insert(
            id,
            TaskWakeListener {
                expected_generation,
                callback,
            },
        );
        TaskWakeEnrollment::Subscribed(TaskWakeSubscription {
            listeners: Arc::downgrade(&self.wake_listeners),
            id,
        })
    }

    /// This task's own CPU (µs): its live threads plus the threads it has
    /// already retired. This is `RUSAGE_SELF` / `times`' `tms_utime`, and it
    /// deliberately does NOT consult the host process — under HVPatch that
    /// would return every guest process's CPU summed together.
    pub fn self_cpu_us(&self) -> u64 {
        let live: u64 = self
            .threads
            .lock()
            .values()
            .map(|(_, thread)| thread.cpu_us())
            .fold(0_u64, u64::saturating_add);
        live.saturating_add(self.cpu.exited_threads_us.load(Ordering::Acquire))
    }

    /// This task's own user CPU (ns) including every guest run its threads are
    /// inside right now. This is what `RLIMIT_CPU` must be judged against: a
    /// thread that spins never traps, so its committed [`Self::self_cpu_us`]
    /// stops advancing exactly when the limit matters most.
    pub fn self_cpu_ns_including_active(&self) -> u64 {
        self.sample_cpu_including_active().cpu_ns
    }

    /// [`Self::self_cpu_ns_including_active`] together with the rate at which
    /// it can grow: how many of this task's threads are inside a guest run at
    /// this instant. A watcher sleeping until the task could have reached a CPU
    /// point must scale wall time by that, not by thread membership.
    pub fn sample_cpu_including_active(&self) -> TaskCpuSample {
        let (live, running_guest_threads) =
            self.threads
                .lock()
                .values()
                .fold((0_u64, 0_u64), |(cpu_ns, running), (_, thread)| {
                    let sample = thread.sample_cpu_including_active();
                    (
                        cpu_ns.saturating_add(sample.cpu_ns),
                        running.saturating_add(u64::from(sample.running_guest)),
                    )
                });
        TaskCpuSample {
            cpu_ns: live.saturating_add(
                self.cpu
                    .exited_threads_us
                    .load(Ordering::Acquire)
                    .saturating_mul(1000),
            ),
            running_guest_threads,
        }
    }

    /// This task's own SYSTEM CPU (µs): carrick's CPU spent servicing this
    /// task's syscalls, across its live threads plus the ones that have exited.
    /// The counterpart to [`Self::self_cpu_us`], which is user time.
    pub fn self_system_cpu_us(&self) -> u64 {
        let live: u64 = self
            .threads
            .lock()
            .values()
            .map(|(_, thread)| thread.system_cpu_us())
            .fold(0_u64, u64::saturating_add);
        live.saturating_add(self.cpu.exited_threads_system_us.load(Ordering::Acquire))
    }

    /// Fold a departing thread's CPU into the task before its slot is released,
    /// so a process's own history survives its threads. BOTH ledgers — a thread
    /// that exits after servicing syscalls has system time that would otherwise
    /// vanish with it.
    pub fn retain_exited_thread_cpu(&self, thread: &Thread) {
        self.cpu
            .exited_threads_us
            .fetch_add(thread.cpu_us(), Ordering::AcqRel);
        self.cpu
            .exited_threads_system_us
            .fetch_add(thread.system_cpu_us(), Ordering::AcqRel);
    }

    /// Charge a reaped child's CPU to this task's CHILDREN ledger. Linux
    /// credits the child's own time *and* the time the child had already
    /// accumulated from its own reaped children.
    pub fn charge_reaped_child(&self, rusage: TaskRusage) {
        self.cpu.children_user_us.fetch_add(
            u64::try_from(rusage.user_time.as_micros()).unwrap_or(u64::MAX),
            Ordering::AcqRel,
        );
        self.cpu.children_system_us.fetch_add(
            u64::try_from(rusage.system_time.as_micros()).unwrap_or(u64::MAX),
            Ordering::AcqRel,
        );
    }

    /// This task's CHILDREN ledger as (user µs, system µs).
    pub fn children_cpu_us(&self) -> (u64, u64) {
        (
            self.cpu.children_user_us.load(Ordering::Acquire),
            self.cpu.children_system_us.load(Ordering::Acquire),
        )
    }

    pub const fn key(&self) -> TaskKey {
        self.key
    }

    pub(super) fn parent(&self) -> Option<TaskKey> {
        *self.parent.lock()
    }

    pub(super) fn reparent(&self, parent: Option<TaskKey>) {
        *self.parent.lock() = parent;
    }

    pub(super) fn add_child(&self, child: TaskKey) -> bool {
        self.children.lock().insert(child)
    }

    pub(super) fn remove_child(&self, child: TaskKey) -> bool {
        self.children.lock().remove(&child)
    }

    pub(super) fn children(&self) -> Vec<TaskKey> {
        self.children.lock().iter().copied().collect()
    }

    pub(super) fn children_set(&self) -> BTreeSet<TaskKey> {
        self.children.lock().clone()
    }

    pub(super) fn publish_prepared_children(&self, children: BTreeSet<TaskKey>) {
        *self.children.lock() = children;
    }

    pub(super) fn ptrace_tracer(&self) -> Option<TaskKey> {
        self.job_control.lock().ptrace_tracer
    }

    pub(super) fn add_ptrace_tracee(&self, tracee: TaskKey) -> bool {
        self.ptrace_tracees.lock().insert(tracee)
    }

    pub(super) fn remove_ptrace_tracee(&self, tracee: TaskKey) -> bool {
        self.ptrace_tracees.lock().remove(&tracee)
    }

    pub(super) fn ptrace_tracees(&self) -> Vec<TaskKey> {
        self.ptrace_tracees.lock().iter().copied().collect()
    }

    pub(super) fn take_ptrace_tracees(&self) -> BTreeSet<TaskKey> {
        std::mem::take(&mut *self.ptrace_tracees.lock())
    }

    /// This task's process group — the value `getpgrp(2)` reports, and the
    /// membership key `killpg(2)` resolves against.
    pub fn process_group(&self) -> ProcessGroupId {
        self.identity.lock().process_group
    }

    pub fn session(&self) -> SessionId {
        self.identity.lock().session
    }

    /// Both group memberships read under one lock, so a child inherits a
    /// consistent (process group, session) pair even if `setsid(2)` races.
    pub fn identity(&self) -> TaskIdentity {
        *self.identity.lock()
    }

    /// Registry-transaction publication point. Callers must hold the kernel
    /// registry write lock before taking this one task leaf lock.
    pub(super) fn replace_identity(&self, process_group: ProcessGroupId, session: SessionId) {
        *self.identity.lock() = TaskIdentity {
            process_group,
            session,
        };
    }

    pub(super) fn lifecycle(&self) -> TaskLifecycle {
        *self.lifecycle.lock()
    }

    pub fn process_credentials(&self) -> Arc<Credentials> {
        self.process_credentials.load_full()
    }

    pub(super) fn replace_process_credentials(&self, credentials: Arc<Credentials>) {
        self.process_credentials.store(credentials);
    }

    pub(crate) fn is_job_control_stopped(&self) -> bool {
        self.job_control.lock().stopped_by.is_some()
    }

    pub(super) fn begin_ptrace_memory_access(
        self: &Arc<Self>,
        tracer: TaskKey,
    ) -> Result<PtraceMemoryAccessWitness, carrick_abi::LinuxErrno> {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        let job_control = self.job_control.lock();
        if job_control.ptrace_tracer != Some(tracer)
            || !job_control.stopped_by_ptrace
            || job_control.stopped_by.is_none()
            || !job_control.ptrace_stop_settled
            || job_control.ptrace_resume_command.is_some()
        {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        Ok(PtraceMemoryAccessWitness {
            task: Arc::clone(self),
            tracer,
            mm_id: self.shared().mm().id(),
            stop_generation: job_control.ptrace_stop_generation,
        })
    }

    pub(super) fn with_ptrace_memory_access<T>(
        &self,
        witness: &PtraceMemoryAccessWitness,
        operation: impl FnOnce() -> T,
    ) -> Result<T, carrick_abi::LinuxErrno> {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        let job_control = self.job_control.lock();
        if self.key() != witness.task.key()
            || job_control.ptrace_tracer != Some(witness.tracer)
            || !job_control.stopped_by_ptrace
            || job_control.stopped_by.is_none()
            || !job_control.ptrace_stop_settled
            || job_control.ptrace_resume_command.is_some()
            || job_control.ptrace_stop_generation != witness.stop_generation
        {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        let target_mm = self.shared().mm();
        if target_mm.id() != witness.mm_id {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        let result = operation();
        drop(job_control);
        drop(lifecycle);
        Ok(result)
    }

    pub(super) fn claim_ptrace_tracer(&self, tracer: TaskKey) -> bool {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        if state.ptrace_tracer.is_some() {
            return false;
        }
        state.ptrace_tracer = Some(tracer);
        true
    }

    pub(super) fn stop_for_ptrace(&self, signal: LinuxSignal) -> bool {
        self.stop_for_ptrace_inner(signal, None)
    }

    fn stop_for_ptrace_inner(
        &self,
        signal: LinuxSignal,
        fault: Option<PtraceSynchronousFault>,
    ) -> bool {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        if state.ptrace_tracer.is_none() {
            return false;
        }
        if state.stopped_by.is_some() {
            return state.stopped_by_ptrace;
        }
        advance_ptrace_stop_generation(&mut state);
        state.stopped_by = Some(signal);
        state.pending_stop = Some(signal);
        state.pending_stop_is_ptrace = true;
        state.stopped_by_ptrace = true;
        clear_ptrace_transient_state(&mut state);
        state.ptrace_stopped_fault = fault.map(|fault| BoundPtraceSynchronousFault {
            stop_generation: state.ptrace_stop_generation,
            fault,
        });
        true
    }

    pub(super) fn stop_for_ptrace_fault(&self, fault: PtraceSynchronousFault) -> bool {
        self.stop_for_ptrace_inner(fault.signal, Some(fault))
    }

    pub(super) fn take_ptrace_resume_fault(&self) -> Option<PtraceSynchronousFault> {
        let mut state = self.job_control.lock();
        let bound = state.ptrace_resume_fault.take()?;
        (bound.stop_generation == state.ptrace_stop_generation).then_some(bound.fault)
    }

    pub(super) fn resume_from_ptrace(&self, tracer: TaskKey, signal: Option<LinuxSignal>) -> bool {
        let signal_generation = self.lock_signal_generation();
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        {
            let state = self.job_control.lock();
            if state.ptrace_tracer != Some(tracer)
                || !state.stopped_by_ptrace
                || state.ptrace_resume_command.is_some()
            {
                return false;
            }
        }
        let resumed_fault = {
            let state = self.job_control.lock();
            state.ptrace_stopped_fault.filter(|bound| {
                bound.stop_generation == state.ptrace_stop_generation
                    && signal == Some(bound.fault.signal)
            })
        };
        if let Some(signal) = signal.filter(|_| resumed_fault.is_none()) {
            self.discard_opposing_job_control_signals(signal);
            self.record_job_control_signal_generation(signal);
            let pending = self.shared().pending_signals();
            if signal.is_realtime() {
                pending.enqueue_realtime(signal, None);
            } else {
                pending.enqueue_standard(signal, None);
            }
        }
        {
            let mut state = self.job_control.lock();
            state.ptrace_resume_signal = signal;
            state.ptrace_resume_fault = resumed_fault;
            state.ptrace_stopped_fault = None;
            if state.ptrace_stop_settled {
                state.stopped_by = None;
                state.stopped_by_ptrace = false;
                state.ptrace_stop_settled = false;
            } else {
                state.ptrace_resume_command = Some(PtraceResumeCommand { signal });
            }
        }
        drop(lifecycle);
        drop(signal_generation);
        self.job_control_changed.notify_all();
        true
    }

    pub(super) fn settle_ptrace_stop(&self) -> PtraceStopSettlement {
        let signal_generation = self.lock_signal_generation();
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return PtraceStopSettlement::NotPtraceStopped;
        }
        let mut state = self.job_control.lock();
        if !state.stopped_by_ptrace {
            return PtraceStopSettlement::NotPtraceStopped;
        }
        state.ptrace_stop_settled = true;
        let Some(command) = state.ptrace_resume_command.take() else {
            return PtraceStopSettlement::Stopped;
        };
        state.stopped_by = None;
        state.stopped_by_ptrace = false;
        state.ptrace_stop_settled = false;
        let settlement = PtraceStopSettlement::Resumed {
            signal: command.signal,
        };
        drop(state);
        drop(lifecycle);
        drop(signal_generation);
        self.job_control_changed.notify_all();
        settlement
    }

    pub(super) fn detach_from_ptrace(&self, tracer: TaskKey) -> bool {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        if state.ptrace_tracer != Some(tracer) {
            return false;
        }
        state.ptrace_tracer = None;
        clear_ptrace_transient_state(&mut state);
        let changed = state.stopped_by_ptrace;
        if changed {
            state.stopped_by = None;
            state.stopped_by_ptrace = false;
        }
        drop(state);
        drop(lifecycle);
        if changed {
            self.job_control_changed.notify_all();
        }
        true
    }

    pub(super) fn consume_ptrace_resume_signal(&self, signal: LinuxSignal) -> bool {
        let mut state = self.job_control.lock();
        if state.ptrace_resume_signal == Some(signal) {
            state.ptrace_resume_signal = None;
            true
        } else {
            false
        }
    }

    /// Serialize Linux job-control generation and delivery-state transitions
    /// for this task. The guard is deliberately task-local: distinct Linux
    /// processes in HVPatch remain independent even though they share one host
    /// carrier.
    pub(super) fn lock_signal_generation(&self) -> MutexGuard<'_, ()> {
        self.signal_generation.lock()
    }

    /// Apply Linux's task-wide job-control pending-set cancellation rule while
    /// the caller holds [`Self::lock_signal_generation`]. Both the shared
    /// process queue and every live thread queue participate regardless of
    /// whether the newly generated signal itself is process- or thread-directed.
    pub(super) fn discard_opposing_job_control_signals(&self, signal: LinuxSignal) {
        let signals = if signal.raw() == carrick_abi::LINUX_SIGCONT {
            SigSet::EMPTY
                .with(carrick_abi::LINUX_SIGSTOP)
                .with(carrick_abi::LINUX_SIGTSTP)
                .with(carrick_abi::LINUX_SIGTTIN)
                .with(carrick_abi::LINUX_SIGTTOU)
        } else if matches!(
            signal.raw(),
            carrick_abi::LINUX_SIGSTOP
                | carrick_abi::LINUX_SIGTSTP
                | carrick_abi::LINUX_SIGTTIN
                | carrick_abi::LINUX_SIGTTOU
        ) {
            SigSet::EMPTY.with(carrick_abi::LINUX_SIGCONT)
        } else {
            SigSet::EMPTY
        };
        if signals.is_empty() {
            return;
        }
        self.shared().pending_signals().discard(signals);
        for thread in self.threads() {
            thread.update_signal_state(|state| state.discard_pending(signals));
        }
    }

    /// Record generation ordering for the narrow dequeue-to-default-action
    /// window. A SIGCONT can race after a vCPU removes a stop signal from its
    /// pending queue but before that vCPU applies the default stop. Remembering
    /// the cancellation lets the later action fail closed instead of re-stopping
    /// a task after the continue.
    pub(super) fn record_job_control_signal_generation(&self, signal: LinuxSignal) {
        let mut state = self.job_control.lock();
        if matches!(
            signal.raw(),
            carrick_abi::LINUX_SIGSTOP
                | carrick_abi::LINUX_SIGTSTP
                | carrick_abi::LINUX_SIGTTIN
                | carrick_abi::LINUX_SIGTTOU
        ) {
            state.default_stop_generation = DefaultStopGeneration::Pending;
        } else if matches!(
            signal.raw(),
            carrick_abi::LINUX_SIGCONT | carrick_abi::LINUX_SIGKILL
        ) {
            advance_job_control_stop_invalidation_generation(&mut state);
            state.default_stop_generation = DefaultStopGeneration::Cancelled;
        }
    }

    /// Snapshot the exact stop-invalidation epoch in which a stop left a
    /// pending queue. SIGCONT and SIGKILL both advance this epoch: neither may
    /// allow an already-dequeued stop action to park the task afterward.
    /// The caller holds [`Self::lock_signal_generation`] across dequeue and this
    /// read, so neither invalidating signal can create an ABA window.
    pub(super) fn job_control_generation_for_dequeue(
        &self,
        signal: LinuxSignal,
    ) -> Option<JobControlStopInvalidationGeneration> {
        if !matches!(
            signal.raw(),
            carrick_abi::LINUX_SIGSTOP
                | carrick_abi::LINUX_SIGTSTP
                | carrick_abi::LINUX_SIGTTIN
                | carrick_abi::LINUX_SIGTTOU
        ) {
            return None;
        }
        let state = self.job_control.lock();
        match state.default_stop_generation {
            DefaultStopGeneration::Pending => Some(JobControlStopInvalidationGeneration(
                state.stop_invalidation_generation,
            )),
            DefaultStopGeneration::None | DefaultStopGeneration::Cancelled => None,
        }
    }

    /// Publish one default-stop transition and a waitable child-state event.
    /// Repeated stop signals while already stopped do not manufacture another
    /// WUNTRACED report.
    pub(super) fn stop_for_job_control(
        &self,
        signal: LinuxSignal,
        action_generation: Option<JobControlStopInvalidationGeneration>,
    ) -> bool {
        // Keep the lifecycle lock through publication. Otherwise exit could
        // clear job control between this check and the state write, leaving a
        // retired task stopped forever with nobody left to resume it.
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        match action_generation {
            Some(generation)
                if generation
                    != JobControlStopInvalidationGeneration(state.stop_invalidation_generation) =>
            {
                // Every dequeued stop action is tied to the invalidation epoch
                // in which it left pending state. A newer stop does not
                // invalidate it, but any intervening SIGCONT or SIGKILL does,
                // even if another stop has since made the aggregate state
                // Pending again.
                return true;
            }
            None if state.default_stop_generation == DefaultStopGeneration::Cancelled => {
                return true;
            }
            Some(_) | None => {}
        }
        if state.stopped_by.is_some() {
            return true;
        }
        state.stopped_by = Some(signal);
        state.pending_stop = Some(signal);
        state.pending_stop_is_ptrace = false;
        state.stopped_by_ptrace = false;
        clear_ptrace_transient_state(&mut state);
        true
    }

    fn resume_from_job_control(&self, publish_continued: bool) -> bool {
        let lifecycle = self.lifecycle.lock();
        if *lifecycle != TaskLifecycle::Live {
            return false;
        }
        let mut state = self.job_control.lock();
        let changed = state.stopped_by.take().is_some();
        if changed {
            state.stopped_by_ptrace = false;
            clear_ptrace_transient_state(&mut state);
            if publish_continued {
                state.pending_continue = true;
            }
        }
        drop(state);
        drop(lifecycle);
        if changed {
            self.job_control_changed.notify_all();
        }
        changed
    }

    /// Resume a stopped task and publish one waitable WCONTINUED transition.
    /// SIGCONT against an already-running task remains successful but creates no
    /// child-state event, matching Linux's state-change semantics.
    pub(super) fn continue_from_job_control(&self) -> bool {
        self.resume_from_job_control(true)
    }

    /// Release a stopped task so its vCPU can consume a fatal signal without
    /// manufacturing WCONTINUED. Linux reports the eventual signal death, not
    /// an intermediate continue transition caused only by SIGKILL delivery.
    pub(super) fn resume_from_job_control_for_fatal_signal(&self) -> bool {
        self.resume_from_job_control(false)
    }

    pub(super) fn waitable_job_control_event(
        &self,
        include_stopped: bool,
        include_continued: bool,
        consume: bool,
    ) -> Option<TaskJobControlEvent> {
        let mut state = self.job_control.lock();
        if (include_stopped || state.pending_stop_is_ptrace)
            && let Some(signal) = state.pending_stop
        {
            if consume {
                state.pending_stop = None;
                state.pending_stop_is_ptrace = false;
            }
            return Some(TaskJobControlEvent::Stopped(signal));
        }
        if include_continued && state.pending_continue {
            if consume {
                state.pending_continue = false;
            }
            return Some(TaskJobControlEvent::Continued);
        }
        None
    }

    pub(super) fn begin_exit(&self) -> bool {
        let generation = self.signal_generation.lock();
        {
            let mut lifecycle = self.lifecycle.lock();
            if *lifecycle == TaskLifecycle::Exiting {
                return false;
            }
            *lifecycle = TaskLifecycle::Exiting;
        }
        let mut job_control = self.job_control.lock();
        job_control.stopped_by = None;
        job_control.stopped_by_ptrace = false;
        job_control.ptrace_tracer = None;
        clear_ptrace_transient_state(&mut job_control);
        drop(job_control);
        drop(generation);
        self.job_control_changed.notify_all();
        true
    }

    pub(crate) fn shared(&self) -> Arc<TaskShared> {
        self.shared.load_full()
    }

    pub(super) fn replace_shared(&self, replacement: Arc<TaskShared>) -> Arc<TaskShared> {
        self.shared.swap(replacement)
    }

    pub(super) fn prepare_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
    ) -> ThreadRef {
        Thread::prepare(self, key, registry_id, resources)
    }

    pub(super) fn prepare_clone_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller_signal_state: ThreadSignalState,
        caller_affinity: carrick_hal::CpuAffinity,
    ) -> ThreadRef {
        Thread::prepare_clone(
            self,
            key,
            registry_id,
            resources,
            caller_signal_state,
            caller_affinity,
        )
    }

    pub(super) fn prepare_fork_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller_signal_state: ThreadSignalState,
        caller_affinity: carrick_hal::CpuAffinity,
    ) -> ThreadRef {
        Thread::prepare_fork(
            self,
            key,
            registry_id,
            resources,
            caller_signal_state,
            caller_affinity,
        )
    }

    pub(super) fn prepare_exec_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller: &ThreadRef,
    ) -> ThreadRef {
        Thread::prepare_exec(self, key, registry_id, resources, caller)
    }

    /// Publish a prepared thread. Kernel operations call this only while the
    /// registry write lock is held, after every other fallible preparation.
    pub(super) fn publish_thread(&self, thread: ThreadRef) -> Result<(), ObjectGraphError> {
        if thread.task_key() != self.key {
            return Err(ObjectGraphError::WrongThreadTask);
        }
        let key = thread.key();
        let mut threads = self.threads.lock();
        if threads.contains_key(&key.tid) {
            return Err(ObjectGraphError::DuplicateThread(key.tid));
        }
        if threads.is_empty() && key.tid != LinuxTid::for_task_leader(self.key.id) {
            return Err(ObjectGraphError::LeaderTidMismatch {
                task: self.key.id,
                tid: key.tid,
            });
        }
        threads.insert(key.tid, (key, thread));
        Ok(())
    }

    pub(super) fn attach_fork_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
        caller_signal_state: ThreadSignalState,
        caller_affinity: carrick_hal::CpuAffinity,
    ) -> Result<ThreadRef, ObjectGraphError> {
        let thread = self.prepare_fork_thread(
            key,
            registry_id,
            resources,
            caller_signal_state,
            caller_affinity,
        );
        self.publish_thread(Arc::clone(&thread))?;
        Ok(thread)
    }

    pub(super) fn attach_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
    ) -> Result<ThreadRef, ObjectGraphError> {
        let thread = self.prepare_thread(key, registry_id, resources);
        self.publish_thread(Arc::clone(&thread))?;
        Ok(thread)
    }

    pub(super) fn prepare_exec_thread_set(
        &self,
        replacement: ThreadRef,
    ) -> Result<PreparedThreadSet, ObjectGraphError> {
        if replacement.task_key != self.key {
            return Err(ObjectGraphError::WrongThreadTask);
        }
        let leader_tid = LinuxTid::for_task_leader(self.key.id);
        if replacement.key.tid != leader_tid {
            return Err(ObjectGraphError::LeaderTidMismatch {
                task: self.key.id,
                tid: replacement.key.tid,
            });
        }
        Ok(PreparedThreadSet {
            task_key: self.key,
            threads: BTreeMap::from([(leader_tid, (replacement.key, replacement))]),
        })
    }

    pub(super) fn publish_exec_thread_set(
        &self,
        prepared: PreparedThreadSet,
    ) -> BTreeMap<LinuxTid, (ThreadKey, ThreadRef)> {
        debug_assert_eq!(prepared.task_key, self.key);
        let mut threads = self.threads.lock();
        std::mem::replace(&mut *threads, prepared.threads)
    }

    pub(super) fn drain_exec_siblings(&self, caller: ThreadKey) -> ExecDrain {
        let gates = self
            .threads
            .lock()
            .values()
            .filter(|(key, _)| *key != caller)
            .map(|(_, thread)| thread.runner_gate())
            .collect();
        ExecDrain::new(gates)
    }

    pub(super) fn thread_keys(&self) -> Vec<ThreadKey> {
        self.threads.lock().values().map(|(key, _)| *key).collect()
    }

    pub(crate) fn thread(&self, tid: LinuxTid) -> Option<ThreadRef> {
        self.threads
            .lock()
            .get(&tid)
            .map(|(_, thread)| Arc::clone(thread))
    }

    pub(crate) fn thread_by_registry_id(&self, registry_id: ThreadId) -> Option<ThreadRef> {
        self.threads.lock().values().find_map(|(_, thread)| {
            (thread.registry_id() == registry_id).then(|| Arc::clone(thread))
        })
    }

    pub(crate) fn threads(&self) -> Vec<ThreadRef> {
        self.threads
            .lock()
            .values()
            .map(|(_, thread)| Arc::clone(thread))
            .collect()
    }

    pub(crate) fn fork_barrier_participants(
        &self,
        owner: ThreadKey,
    ) -> Result<ForkBarrierParticipants, TaskParticipantError> {
        let threads = self.threads.lock();
        if threads
            .get(&owner.tid)
            .is_none_or(|(published, _)| *published != owner)
        {
            return Err(TaskParticipantError::UnknownThread {
                task: self.key,
                thread: owner,
            });
        }
        Ok(ForkBarrierParticipants {
            siblings: threads
                .values()
                .map(|(key, _)| *key)
                .filter(|key| *key != owner)
                .collect(),
        })
    }

    pub(crate) fn crash_barrier_participants(
        &self,
        fatal_owner: ThreadKey,
    ) -> Result<CrashBarrierParticipants, TaskParticipantError> {
        let threads = self.threads.lock();
        if threads
            .get(&fatal_owner.tid)
            .is_none_or(|(published, _)| *published != fatal_owner)
        {
            return Err(TaskParticipantError::UnknownThread {
                task: self.key,
                thread: fatal_owner,
            });
        }
        Ok(CrashBarrierParticipants {
            siblings: threads
                .values()
                .map(|(key, _)| *key)
                .filter(|key| *key != fatal_owner)
                .collect(),
        })
    }

    pub(super) fn thread_exit_participants(
        &self,
        departing: ThreadKey,
    ) -> Result<ThreadExitParticipants, TaskParticipantError> {
        let threads = self.threads.lock();
        if threads
            .get(&departing.tid)
            .is_none_or(|(published, _)| *published != departing)
        {
            return Err(TaskParticipantError::UnknownThread {
                task: self.key,
                thread: departing,
            });
        }
        Ok(ThreadExitParticipants {
            survivors: threads
                .values()
                .map(|(key, _)| *key)
                .filter(|key| *key != departing)
                .collect(),
        })
    }

    pub(crate) fn crash_capture_participants(&self) -> CrashCaptureParticipants {
        CrashCaptureParticipants {
            members: self
                .threads
                .lock()
                .values()
                .map(|(key, thread)| (*key, Arc::clone(thread)))
                .collect(),
        }
    }

    pub(crate) fn core_note_participants(&self) -> CoreNoteParticipants {
        CoreNoteParticipants {
            members: self.threads.lock().values().map(|(key, _)| *key).collect(),
        }
    }

    pub(crate) fn accepts_unhandled_signal(&self, signal: super::ids::LinuxSignal) -> bool {
        let threads = self.threads.lock();
        for (_, thread) in threads.values() {
            if thread.accepts_unhandled_signal(signal) {
                return true;
            }
        }
        false
    }

    pub(super) fn retire_thread(&self, key: ThreadKey) -> Option<ThreadRef> {
        let mut threads = self.threads.lock();
        if threads
            .get(&key.tid)
            .is_none_or(|(published_key, _)| *published_key != key)
        {
            return None;
        }
        let retired = threads.remove(&key.tid).map(|(_, thread)| thread);
        // Retain the departing thread's CPU before it leaves the task's live
        // set: its `guest_cpu` slot is recycled by the next thread to claim
        // one, so a process that has retired threads would otherwise appear to
        // lose the CPU they burned.
        if let Some(thread) = retired.as_ref() {
            let _ = thread.cancel_kernel_owned_continuation(
                crate::vcpu_loop::continuation::CancellationCause::ThreadExit,
            );
            self.retain_exited_thread_cpu(thread);
            // A retired thread has left the graph and can never reach another
            // safe point. Say so at the source rather than leaving a fatal
            // sibling's quorum to infer it from a membership snapshot it took
            // before the retirement.
            thread.revoke_crash_safe_point_participation();
        }
        retired
    }

    #[cfg(test)]
    pub(super) fn thread_count_for_test(&self) -> usize {
        self.threads.lock().len()
    }

    pub(super) fn parent_until(&self, deadline: std::time::Instant) -> Option<Option<TaskKey>> {
        self.parent.try_lock_until(deadline).map(|parent| *parent)
    }

    pub(super) fn children_until(&self, deadline: std::time::Instant) -> Option<Vec<TaskKey>> {
        self.children
            .try_lock_until(deadline)
            .map(|children| children.iter().copied().collect())
    }

    pub(super) fn identity_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(ProcessGroupId, SessionId)> {
        self.identity
            .try_lock_until(deadline)
            .map(|identity| (identity.process_group, identity.session))
    }

    pub(super) fn lifecycle_until(&self, deadline: std::time::Instant) -> Option<TaskLifecycle> {
        self.lifecycle.try_lock_until(deadline).map(|state| *state)
    }

    pub(super) fn threads_until(&self, deadline: std::time::Instant) -> Option<Vec<ThreadRef>> {
        self.threads.try_lock_until(deadline).map(|threads| {
            threads
                .values()
                .map(|(_, thread)| Arc::clone(thread))
                .collect()
        })
    }
}

#[derive(Debug)]
pub(super) struct PreparedThreadSet {
    task_key: TaskKey,
    threads: BTreeMap<LinuxTid, (ThreadKey, ThreadRef)>,
}

impl PreparedThreadSet {
    pub(super) const fn task_key(&self) -> TaskKey {
        self.task_key
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
pub(crate) fn close_system_charge_window() {
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
pub(crate) fn system_charge_window_is_closed() -> bool {
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
    use std::sync::atomic::AtomicUsize;

    use carrick_abi::LinuxCloneFlags;

    use super::*;

    #[test]
    fn file_slot_hasher_preserves_the_i32_descriptor_domain() {
        for value in [i32::MIN, -1, 0, 1, 2, 3, 65_535, i32::MAX] {
            let mut hasher = FileSlotHasher::default();
            std::hash::Hasher::write_i32(&mut hasher, value);
            assert_eq!(hasher.finish(), u64::from(value as u32));
        }
    }
    use crate::kernel::ClonePlan;
    use crate::kernel::container::{LaunchContext, RunId};

    struct Fixture {
        ids: ObjectIdRegistry,
        task: TaskRef,
        leader: ThreadRef,
    }

    impl Fixture {
        fn new() -> Self {
            let ids = ObjectIdRegistry::new();
            let task_id = TaskId::for_root_bootstrap(100).expect("task ID");
            let key = TaskKey {
                id: task_id,
                serial: ids.task_serial().expect("task serial"),
            };
            let mm = Arc::new(Mm::new_reference(ids.mm_id().expect("mm ID")));
            let sighand = Arc::new(Sighand::new(ids.sighand_id().expect("sighand ID")));
            let shared = Arc::new(TaskShared::new(mm, sighand));
            let resources = Arc::new(ThreadResources::new(
                Arc::new(FileTable::new(ids.file_table_id().expect("files ID"))),
                Arc::new(FsContext::new(ids.fs_context_id().expect("fs ID"))),
                Arc::new(Credentials::root(
                    ids.credentials_id().expect("credentials ID"),
                )),
            ));
            let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
                "objects-fixture",
            ))));
            let task = Arc::new(Task::new(
                key,
                None,
                TaskIdentity::led_by(task_id),
                shared,
                resources.credentials(),
                container,
                ChildExitSignal::SIGCHLD,
            ));
            let leader = task
                .attach_thread(
                    ThreadKey {
                        tid: LinuxTid::for_task_leader(task_id),
                        serial: ids.thread_serial().expect("thread serial"),
                    },
                    ThreadId::synthetic_for_tests(100),
                    resources,
                )
                .expect("leader thread");
            Self { ids, task, leader }
        }
    }

    /// A limit belongs to ONE task, so writing another task's does not move
    /// this one's.
    ///
    /// This is the property the previous design could not have: rlimits lived in
    /// the dispatcher's private `ProcState`, reachable only by the thread running
    /// that process, so `prlimit(pid, …)` had nowhere to write except the
    /// CALLER's table. Go's `TestPrlimitFileLimit` observes both halves of that —
    /// the target unchanged AND the caller's own soft NOFILE moved underneath it.
    ///
    /// Deliberately written with TWO tasks: with one, every identity in the
    /// system coincides and the defect is invisible, which is why the four
    /// existing single-process rlimit probes all pass with the bug in place.
    #[test]
    fn an_rlimit_belongs_to_one_task_not_to_whoever_writes_it() {
        let parent = Fixture::new();
        let child = Fixture::new();

        let default_nofile = parent.task.rlimit(LinuxResource::Nofile);
        assert_eq!(child.task.rlimit(LinuxResource::Nofile), default_nofile);

        // Stand in for `prlimit(child_pid, RLIMIT_NOFILE, {42, …})`.
        let target = LinuxRlimit::new(42, default_nofile.rlim_max);
        let old = child
            .task
            .replace_rlimit(LinuxResource::Nofile, |_current| Ok::<_, ()>(target))
            .expect("replace");

        assert_eq!(
            old, default_nofile,
            "the OLD value is the target's, reported before the write"
        );
        assert_eq!(child.task.rlimit(LinuxResource::Nofile), target);
        assert_eq!(
            parent.task.rlimit(LinuxResource::Nofile),
            default_nofile,
            "writing the child's limit must not move the parent's"
        );
        // ...and only the named resource moved.
        assert_eq!(
            child.task.rlimit(LinuxResource::Fsize),
            parent.task.rlimit(LinuxResource::Fsize)
        );
    }

    /// `decide` sees the value it is replacing, which is what `setrlimit`'s
    /// rules need: a soft above the CURRENT hard is EINVAL.
    #[test]
    fn replace_rlimit_shows_the_writer_the_current_value() {
        let fixture = Fixture::new();
        let before = fixture.task.rlimit(LinuxResource::Nofile);

        let refused = fixture
            .task
            .replace_rlimit(LinuxResource::Nofile, |current| {
                assert_eq!(current, before, "the closure must see the live value");
                Err("soft above hard")
            });
        assert_eq!(refused, Err("soft above hard"));
        assert_eq!(
            fixture.task.rlimit(LinuxResource::Nofile),
            before,
            "a refused write publishes nothing"
        );
    }

    /// fork inherits limits as a COPY, and the two then diverge (`fork(2)`).
    #[test]
    fn fork_inherits_rlimits_as_a_copy() {
        let parent = Fixture::new();
        let lowered = LinuxRlimit::new(64, 4096);
        parent
            .task
            .replace_rlimit(LinuxResource::Nofile, |_| Ok::<_, ()>(lowered))
            .expect("parent lowers its own");

        let child = Fixture::new();
        child.task.inherit_fork_attributes_from(&parent.task);
        assert_eq!(
            child.task.rlimit(LinuxResource::Nofile),
            lowered,
            "inherited"
        );

        let raised = LinuxRlimit::new(128, 4096);
        child
            .task
            .replace_rlimit(LinuxResource::Nofile, |_| Ok::<_, ()>(raised))
            .expect("child changes its own");
        assert_eq!(child.task.rlimit(LinuxResource::Nofile), raised);
        assert_eq!(
            parent.task.rlimit(LinuxResource::Nofile),
            lowered,
            "the child owns its copy; the parent is untouched"
        );
    }

    /// A `fork` child SHARES its parent's UTS namespace, and `unshare` COPIES
    /// it. Both directions, because carrick had each one wrong.
    ///
    /// This is the exact opposite of the rlimit rule two tests above, and
    /// getting the two backwards is the whole hazard: `fork(2)` copies rlimits
    /// and shares namespaces (`namespaces(7)`). The hostname lived in a `String`
    /// the fork path CLONED, so a parent's `sethostname` never reached a child
    /// that already existed — where Linux shares one `uts_namespace` and the
    /// child does see the new name.
    ///
    /// TWO live tasks by construction. With one guest process the parent and
    /// the child are the same object, so copy and share are indistinguishable
    /// and this entire class is invisible — which is why the single-process
    /// `etchostnamefile` and `selfhostnameresolve` probes pass with the defect
    /// in place.
    ///
    /// The parent unshares FIRST so the whole test runs in a namespace of its
    /// own: the root one is carrier-wide, and renaming it here would be visible
    /// to every other test in this binary.
    #[test]
    fn fork_shares_the_uts_namespace_and_unshare_copies_it() {
        let parent = Fixture::new();
        let root = parent.task.uts_ns().id();
        parent.task.unshare_uts_ns();
        parent.task.uts_ns().set_nodename("before-fork");

        let child = Fixture::new();
        child.task.inherit_fork_attributes_from(&parent.task);
        assert_eq!(
            child.task.uts_ns().id(),
            parent.task.uts_ns().id(),
            "a fork child is IN its parent's UTS namespace, not holding a copy"
        );

        parent.task.uts_ns().set_nodename("renamed-after-fork");
        assert_eq!(
            child.task.uts_ns().nodename(),
            "renamed-after-fork",
            "a name set by the parent reaches a child that already exists"
        );

        // `unshare` is where a copy is correct: the new namespace starts from
        // the caller's name and the two diverge from there.
        let unshared = child.task.unshare_uts_ns();
        assert_ne!(unshared, parent.task.uts_ns().id());
        assert_eq!(child.task.uts_ns().nodename(), "renamed-after-fork");

        child.task.uts_ns().set_nodename("child-only");
        parent.task.uts_ns().set_nodename("parent-only");
        assert_eq!(child.task.uts_ns().nodename(), "child-only");
        assert_eq!(parent.task.uts_ns().nodename(), "parent-only");
        assert_ne!(
            root,
            parent.task.uts_ns().id(),
            "neither task disturbed the namespace it started in"
        );
    }

    /// Container membership is inherited across fork as a SHARE, exactly like
    /// the network and UTS namespaces: the child holds the parent's `Arc`.
    #[test]
    fn fork_child_inherits_parent_container() {
        let parent = Fixture::new();
        let child = Fixture::new();
        assert_ne!(
            child.task.container().id(),
            parent.task.container().id(),
            "two fresh fixtures are two containers"
        );

        child.task.inherit_fork_attributes_from(&parent.task);

        assert!(
            Arc::ptr_eq(&child.task.container(), &parent.task.container()),
            "a fork child is IN its parent's container, not holding a copy"
        );
    }

    /// The same pair of rules for the network namespace, where carrick was
    /// wrong in the OTHER direction: the view was one carrier-global
    /// `Arc<RuntimeNetwork>` on the dispatcher, so no two guest processes could
    /// ever hold different ones and `unshare(CLONE_NEWNET)` had nowhere to
    /// write at all.
    ///
    /// `unshare` here is a fresh namespace rather than a copy — Linux gives a
    /// new network namespace nothing but a loopback — which is why the two
    /// namespaces cannot share one inheritance helper.
    #[test]
    fn fork_shares_the_net_namespace_and_unshare_leaves_the_sibling_alone() {
        let parent = Fixture::new();
        let child = Fixture::new();
        child.task.inherit_fork_attributes_from(&parent.task);

        assert_eq!(
            child.task.net_ns().id(),
            parent.task.net_ns().id(),
            "a fork child is in its parent's network namespace"
        );
        assert!(
            Arc::ptr_eq(&child.task.net_ns(), &parent.task.net_ns()),
            "shared by pointer, so a republication reaches both"
        );

        let stayed = parent
            .task
            .net_ns()
            .view()
            .links
            .iter()
            .map(|link| link.name.clone())
            .collect::<Vec<_>>();

        child.task.unshare_net_ns();

        assert_ne!(child.task.net_ns().id(), parent.task.net_ns().id());
        assert_eq!(
            child
                .task
                .net_ns()
                .view()
                .links
                .iter()
                .map(|link| link.name.clone())
                .collect::<Vec<_>>(),
            ["lo"],
            "a fresh network namespace holds loopback and nothing else"
        );
        assert_eq!(
            parent
                .task
                .net_ns()
                .view()
                .links
                .iter()
                .map(|link| link.name.clone())
                .collect::<Vec<_>>(),
            stayed,
            "the namespace the parent stayed in is untouched by its child leaving"
        );
    }

    /// One table answers every reader, so `getrlimit` and `/proc/<pid>/limits`
    /// cannot disagree — they disagreed on four resources when `/proc` was a
    /// frozen literal.
    #[test]
    fn the_default_set_is_the_single_source_for_every_resource() {
        let fixture = Fixture::new();
        let set = fixture.task.rlimits();
        for resource in LinuxResource::ALL {
            assert_eq!(
                set.get(resource),
                fixture.task.rlimit(resource),
                "{resource:?} must read the same through both accessors"
            );
        }
        assert_eq!(
            set.get(LinuxResource::Core),
            LinuxRlimit::new(LINUX_RLIM_INFINITY, LINUX_RLIM_INFINITY)
        );
    }

    #[test]
    fn task_wake_generation_is_durable_without_a_lane_waker() {
        let fixture = Fixture::new();

        assert_eq!(fixture.task.wake_generation(), 0);
        fixture.task.wake();
        assert_eq!(fixture.task.wake_generation(), 1);
        fixture.task.wake();
        assert_eq!(fixture.task.wake_generation(), 2);
    }

    #[test]
    fn ptrace_transient_command_state_is_cleared_by_non_ptrace_transitions() {
        let stop_signal =
            LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGUSR2).expect("SIGUSR2");
        let kill_signal =
            LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGKILL).expect("SIGKILL");

        let stage_early_resume = || {
            let fixture = Fixture::new();
            let tracer = fixture.task.key();
            assert!(fixture.task.claim_ptrace_tracer(tracer));
            assert!(fixture.task.stop_for_ptrace(stop_signal));
            assert!(fixture.task.resume_from_ptrace(tracer, Some(kill_signal)));
            fixture
        };
        let assert_transient_clear = |task: &Task| {
            let state = task.job_control.lock();
            assert!(!state.ptrace_stop_settled);
            assert_eq!(state.ptrace_resume_command, None);
            assert_eq!(state.ptrace_resume_signal, None);
            assert_eq!(state.ptrace_stopped_fault, None);
            assert_eq!(state.ptrace_resume_fault, None);
        };

        let detached = stage_early_resume();
        assert!(detached.task.detach_from_ptrace(detached.task.key()));
        assert_transient_clear(&detached.task);

        let continued = stage_early_resume();
        assert!(continued.task.resume_from_job_control(false));
        assert_transient_clear(&continued.task);

        let exited = stage_early_resume();
        assert!(exited.task.begin_exit());
        assert_transient_clear(&exited.task);

        let ordinary_stop = Fixture::new();
        {
            let mut state = ordinary_stop.task.job_control.lock();
            state.ptrace_stop_settled = true;
            state.ptrace_resume_command = Some(PtraceResumeCommand {
                signal: Some(kill_signal),
            });
            state.ptrace_resume_signal = Some(kill_signal);
        }
        assert!(ordinary_stop.task.stop_for_job_control(stop_signal, None));
        assert_transient_clear(&ordinary_stop.task);
    }

    #[test]
    fn task_wake_subscription_publishes_before_lane_waker_and_unregisters_on_drop() {
        let fixture = Fixture::new();
        let order = Arc::new(Mutex::new(Vec::new()));
        let callback_order = Arc::clone(&order);
        let subscription = match fixture.task.subscribe_wake(
            fixture.task.wake_generation(),
            Arc::new(move |generation| callback_order.lock().push(("callback", generation))),
        ) {
            TaskWakeEnrollment::Subscribed(subscription) => subscription,
            TaskWakeEnrollment::Ready(_) => panic!("unchanged task is not ready"),
        };
        fixture.task.wake();
        assert_eq!(order.lock().as_slice(), &[("callback", 1)]);
        drop(subscription);
        fixture.task.wake();
        assert_eq!(order.lock().len(), 1);

        let stale = fixture.task.wake_generation();
        fixture.task.wake();
        assert!(matches!(
            fixture
                .task
                .subscribe_wake(stale, Arc::new(|_| panic!("stale callback"))),
            TaskWakeEnrollment::Ready(3)
        ));
    }

    #[test]
    fn legal_thread_clone_can_copy_files_and_fs_independently() {
        let fixture = Fixture::new();
        let flags = LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM;
        let plan = ClonePlan::from_flags(flags).expect("legal clone plan");
        let parent = fixture.leader.resources();
        parent.fs_context().set_cwd("/parent/cwd".to_owned());
        parent
            .fs_context()
            .set_chroot_root(Some("/parent/root".to_owned()));
        let child = ThreadResources::for_clone(&parent, plan, &fixture.ids).expect("resources");

        assert!(!Arc::ptr_eq(&parent.files(), &child.files()));
        assert!(!Arc::ptr_eq(&parent.fs_context(), &child.fs_context()));
        assert_eq!(child.fs_context().cwd(), "/parent/cwd");
        assert_eq!(
            child.fs_context().chroot_root().as_deref(),
            Some("/parent/root")
        );
        child.fs_context().set_cwd("/child/cwd".to_owned());
        assert_eq!(parent.fs_context().cwd(), "/parent/cwd");
        assert!(!Arc::ptr_eq(&parent.credentials(), &child.credentials()));
        assert_eq!(parent.credentials().ruid(), child.credentials().ruid());
    }

    #[test]
    fn clone_flags_control_each_shared_object_independently() {
        let fixture = Fixture::new();
        let flags = LinuxCloneFlags::VM
            | LinuxCloneFlags::SIGHAND
            | LinuxCloneFlags::FILES
            | LinuxCloneFlags::FS;
        let plan = ClonePlan::from_flags(flags).expect("legal clone plan");
        let parent_shared = fixture.task.shared();
        let child_shared = TaskShared::for_new_task_reference(&parent_shared, plan, &fixture.ids)
            .expect("shared resources");
        let parent_resources = fixture.leader.resources();
        parent_resources
            .fs_context()
            .set_cwd("/shared/cwd".to_owned());
        let child_resources = ThreadResources::for_clone(&parent_resources, plan, &fixture.ids)
            .expect("thread resources");

        assert!(Arc::ptr_eq(&parent_shared.mm(), &child_shared.mm()));
        assert!(Arc::ptr_eq(
            &parent_shared.sighand(),
            &child_shared.sighand()
        ));
        assert!(Arc::ptr_eq(
            &parent_resources.files(),
            &child_resources.files()
        ));
        assert!(Arc::ptr_eq(
            &parent_resources.fs_context(),
            &child_resources.fs_context()
        ));
        child_resources
            .fs_context()
            .set_cwd("/shared/updated".to_owned());
        assert_eq!(parent_resources.fs_context().cwd(), "/shared/updated");
    }

    #[test]
    fn task_owns_threads_without_a_strong_back_link_cycle() {
        let fixture = Fixture::new();
        let task = Arc::clone(&fixture.task);
        let weak_task = Arc::downgrade(&task);
        let leader = Arc::clone(&fixture.leader);
        drop(fixture);
        assert_eq!(task.thread_count_for_test(), 1);
        drop(task);

        assert!(weak_task.upgrade().is_none());
        assert!(leader.task().is_none());
    }

    #[test]
    fn fork_probe_sibling_count_saturates_at_u32_max() {
        let max = usize::try_from(u32::MAX).expect("u32 max fits usize");
        assert_eq!(saturating_fork_sibling_count_for_probe(max), u32::MAX);
        assert_eq!(
            saturating_fork_sibling_count_for_probe(max.saturating_add(1)),
            u32::MAX
        );
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
}
