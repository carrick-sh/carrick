//! Logical guest task structure, lifecycle state, and resources.
//!
//! Encapsulates task hierarchy, resource limits, process keyrings,
//! job control, ptrace stops, and thread coordination.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};

use arc_swap::ArcSwap;
use parking_lot::{Condvar, Mutex, MutexGuard};

use carrick_abi::keyring::{KeyRequestDefault, KeySerial};
use carrick_abi::{LINUX_RLIM_INFINITY, LinuxResource, LinuxRlimit, SigSet};
use carrick_fatal::carrick_fatal;
use carrick_hal::ThreadId;

use crate::kernel::clone_plan::{CloneObjectMode, ClonePlan};
use crate::kernel::container::Container;
use crate::kernel::ids::{
    ChildExitSignal, LinuxSignal, LinuxTid, MmId, ObjectIdError, ObjectIdRegistry, ProcessGroupId,
    SessionId, TaskId,
};
use crate::kernel::netns::{NetNs, NsProxy, UtsNs};
use crate::kernel::objects::process::{TaskRusage, TaskShared};
use crate::kernel::objects::signal::ThreadSignalState;
use crate::kernel::objects::thread::{ExecDrain, TaskCpuSample, Thread, ThreadKey, ThreadRef};
use crate::kernel::objects::{Credentials, FileTable, FsContext, ObjectGraphError, TaskKey};
use crate::namespace::process::{CapabilitySet, ProcessCredsNs};
use crate::namespace::user::UserNs;

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

    pub(in crate::kernel) fn for_exec(
        caller: &Self,
        ids: &ObjectIdRegistry,
    ) -> Result<Self, ObjectIdError> {
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

    pub(in crate::kernel) fn with_files(&self, files: Arc<FileTable>) -> Self {
        Self::new(
            files,
            Arc::clone(&self.fs_context),
            Arc::clone(&self.credentials),
        )
    }

    pub(in crate::kernel) fn with_credentials(&self, credentials: Arc<Credentials>) -> Self {
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
pub(crate) struct ThreadExitParticipants {
    survivors: BTreeSet<ThreadKey>,
}

impl ThreadExitParticipants {
    pub(crate) fn permits_nonfinal_exit(&self) -> bool {
        self.survivors.iter().next().is_some()
    }

    #[cfg(test)]
    pub(crate) fn contains_survivor(&self, key: ThreadKey) -> bool {
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
pub(crate) enum TaskJobControlEvent {
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
    pub(in crate::kernel) fn reset_dumpable_for_exec(&self) {
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

    pub(in crate::kernel) fn parent(&self) -> Option<TaskKey> {
        *self.parent.lock()
    }

    pub(in crate::kernel) fn reparent(&self, parent: Option<TaskKey>) {
        *self.parent.lock() = parent;
    }

    pub(in crate::kernel) fn add_child(&self, child: TaskKey) -> bool {
        self.children.lock().insert(child)
    }

    pub(in crate::kernel) fn remove_child(&self, child: TaskKey) -> bool {
        self.children.lock().remove(&child)
    }

    pub(in crate::kernel) fn children(&self) -> Vec<TaskKey> {
        self.children.lock().iter().copied().collect()
    }

    pub(in crate::kernel) fn children_set(&self) -> BTreeSet<TaskKey> {
        self.children.lock().clone()
    }

    pub(in crate::kernel) fn publish_prepared_children(&self, children: BTreeSet<TaskKey>) {
        *self.children.lock() = children;
    }

    pub(in crate::kernel) fn ptrace_tracer(&self) -> Option<TaskKey> {
        self.job_control.lock().ptrace_tracer
    }

    pub(in crate::kernel) fn add_ptrace_tracee(&self, tracee: TaskKey) -> bool {
        self.ptrace_tracees.lock().insert(tracee)
    }

    pub(in crate::kernel) fn remove_ptrace_tracee(&self, tracee: TaskKey) -> bool {
        self.ptrace_tracees.lock().remove(&tracee)
    }

    pub(in crate::kernel) fn ptrace_tracees(&self) -> Vec<TaskKey> {
        self.ptrace_tracees.lock().iter().copied().collect()
    }

    pub(in crate::kernel) fn take_ptrace_tracees(&self) -> BTreeSet<TaskKey> {
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
    pub(in crate::kernel) fn replace_identity(
        &self,
        process_group: ProcessGroupId,
        session: SessionId,
    ) {
        *self.identity.lock() = TaskIdentity {
            process_group,
            session,
        };
    }

    pub(in crate::kernel) fn lifecycle(&self) -> TaskLifecycle {
        *self.lifecycle.lock()
    }

    pub fn process_credentials(&self) -> Arc<Credentials> {
        self.process_credentials.load_full()
    }

    pub(in crate::kernel) fn replace_process_credentials(&self, credentials: Arc<Credentials>) {
        self.process_credentials.store(credentials);
    }

    pub(crate) fn is_job_control_stopped(&self) -> bool {
        self.job_control.lock().stopped_by.is_some()
    }

    pub(in crate::kernel) fn begin_ptrace_memory_access(
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

    pub(in crate::kernel) fn with_ptrace_memory_access<T>(
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

    pub(in crate::kernel) fn claim_ptrace_tracer(&self, tracer: TaskKey) -> bool {
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

    pub(in crate::kernel) fn stop_for_ptrace(&self, signal: LinuxSignal) -> bool {
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

    pub(in crate::kernel) fn stop_for_ptrace_fault(&self, fault: PtraceSynchronousFault) -> bool {
        self.stop_for_ptrace_inner(fault.signal, Some(fault))
    }

    pub(in crate::kernel) fn take_ptrace_resume_fault(&self) -> Option<PtraceSynchronousFault> {
        let mut state = self.job_control.lock();
        let bound = state.ptrace_resume_fault.take()?;
        (bound.stop_generation == state.ptrace_stop_generation).then_some(bound.fault)
    }

    pub(in crate::kernel) fn resume_from_ptrace(
        &self,
        tracer: TaskKey,
        signal: Option<LinuxSignal>,
    ) -> bool {
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

    pub(in crate::kernel) fn settle_ptrace_stop(&self) -> PtraceStopSettlement {
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

    pub(in crate::kernel) fn detach_from_ptrace(&self, tracer: TaskKey) -> bool {
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

    pub(in crate::kernel) fn consume_ptrace_resume_signal(&self, signal: LinuxSignal) -> bool {
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
    pub(in crate::kernel) fn lock_signal_generation(&self) -> MutexGuard<'_, ()> {
        self.signal_generation.lock()
    }

    /// Apply Linux's task-wide job-control pending-set cancellation rule while
    /// the caller holds [`Self::lock_signal_generation`]. Both the shared
    /// process queue and every live thread queue participate regardless of
    /// whether the newly generated signal itself is process- or thread-directed.
    pub(in crate::kernel) fn discard_opposing_job_control_signals(&self, signal: LinuxSignal) {
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
    pub(in crate::kernel) fn record_job_control_signal_generation(&self, signal: LinuxSignal) {
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
    pub(in crate::kernel) fn job_control_generation_for_dequeue(
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
    pub(in crate::kernel) fn stop_for_job_control(
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
    pub(in crate::kernel) fn continue_from_job_control(&self) -> bool {
        self.resume_from_job_control(true)
    }

    /// Release a stopped task so its vCPU can consume a fatal signal without
    /// manufacturing WCONTINUED. Linux reports the eventual signal death, not
    /// an intermediate continue transition caused only by SIGKILL delivery.
    pub(in crate::kernel) fn resume_from_job_control_for_fatal_signal(&self) -> bool {
        self.resume_from_job_control(false)
    }

    pub(in crate::kernel) fn waitable_job_control_event(
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

    pub(in crate::kernel) fn begin_exit(&self) -> bool {
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

    pub(in crate::kernel) fn replace_shared(
        &self,
        replacement: Arc<TaskShared>,
    ) -> Arc<TaskShared> {
        self.shared.swap(replacement)
    }

    pub(in crate::kernel) fn prepare_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
    ) -> ThreadRef {
        Thread::prepare(self, key, registry_id, resources)
    }

    pub(in crate::kernel) fn prepare_clone_thread(
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

    pub(in crate::kernel) fn prepare_fork_thread(
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

    pub(in crate::kernel) fn prepare_exec_thread(
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
    pub(in crate::kernel) fn publish_thread(
        &self,
        thread: ThreadRef,
    ) -> Result<(), ObjectGraphError> {
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

    pub(in crate::kernel) fn attach_fork_thread(
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

    pub(in crate::kernel) fn attach_thread(
        self: &Arc<Self>,
        key: ThreadKey,
        registry_id: ThreadId,
        resources: Arc<ThreadResources>,
    ) -> Result<ThreadRef, ObjectGraphError> {
        let thread = self.prepare_thread(key, registry_id, resources);
        self.publish_thread(Arc::clone(&thread))?;
        Ok(thread)
    }

    pub(in crate::kernel) fn prepare_exec_thread_set(
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

    pub(in crate::kernel) fn publish_exec_thread_set(
        &self,
        prepared: PreparedThreadSet,
    ) -> BTreeMap<LinuxTid, (ThreadKey, ThreadRef)> {
        debug_assert_eq!(prepared.task_key, self.key);
        let mut threads = self.threads.lock();
        std::mem::replace(&mut *threads, prepared.threads)
    }

    pub(in crate::kernel) fn drain_exec_siblings(&self, caller: ThreadKey) -> ExecDrain {
        let gates = self
            .threads
            .lock()
            .values()
            .filter(|(key, _)| *key != caller)
            .map(|(_, thread)| thread.runner_gate())
            .collect();
        ExecDrain::new(gates)
    }

    pub(in crate::kernel) fn thread_keys(&self) -> Vec<ThreadKey> {
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

    pub(in crate::kernel) fn thread_exit_participants(
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

    pub(crate) fn accepts_unhandled_signal(&self, signal: LinuxSignal) -> bool {
        let threads = self.threads.lock();
        for (_, thread) in threads.values() {
            if thread.accepts_unhandled_signal(signal) {
                return true;
            }
        }
        false
    }

    pub(in crate::kernel) fn retire_thread(&self, key: ThreadKey) -> Option<ThreadRef> {
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
    pub(in crate::kernel) fn thread_count_for_test(&self) -> usize {
        self.threads.lock().len()
    }

    pub(in crate::kernel) fn parent_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<Option<TaskKey>> {
        self.parent.try_lock_until(deadline).map(|parent| *parent)
    }

    pub(in crate::kernel) fn children_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<Vec<TaskKey>> {
        self.children
            .try_lock_until(deadline)
            .map(|children| children.iter().copied().collect())
    }

    pub(in crate::kernel) fn identity_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(ProcessGroupId, SessionId)> {
        self.identity
            .try_lock_until(deadline)
            .map(|identity| (identity.process_group, identity.session))
    }

    pub(in crate::kernel) fn lifecycle_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<TaskLifecycle> {
        self.lifecycle.try_lock_until(deadline).map(|state| *state)
    }

    pub(in crate::kernel) fn threads_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<Vec<ThreadRef>> {
        self.threads.try_lock_until(deadline).map(|threads| {
            threads
                .values()
                .map(|(_, thread)| Arc::clone(thread))
                .collect()
        })
    }
}

#[derive(Debug)]
pub(in crate::kernel) struct PreparedThreadSet {
    pub(in crate::kernel) task_key: TaskKey,
    pub(in crate::kernel) threads: BTreeMap<LinuxTid, (ThreadKey, ThreadRef)>,
}

impl PreparedThreadSet {
    pub(in crate::kernel) const fn task_key(&self) -> TaskKey {
        self.task_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::ClonePlan;
    use crate::kernel::container::{LaunchContext, RunId};
    use crate::kernel::objects::process::Mm;
    use crate::kernel::objects::signal::Sighand;
    use carrick_abi::LinuxCloneFlags;

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
}
