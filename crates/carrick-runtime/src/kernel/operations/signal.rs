//! Signal, process-directed event, job-control, and ptrace operations.
//!
//! Enforces POSIX and Linux signal delivery, thread-directed targeting,
//! credential authorization, process group routing, job control stops,
//! and ptrace attachment, memory access, and resumption.

use std::sync::{Arc, Weak};

use carrick_abi::LinuxSiginfo;

use super::session::exact_process_group_members;
use crate::kernel::container::ContainerId;
use crate::kernel::core::{Kernel, KernelContext, KernelDomain};
use crate::kernel::ids::{LinuxSignal, LinuxTid, ProcessGroupId, TaskId};
use crate::kernel::objects::{
    DumpableMode, PtraceStopSettlement, PtraceSynchronousFault, Task, TaskKey, TaskLifecycle,
    TaskRef, ThreadKey,
};

/// Result of resolving one Linux signal target against the authoritative
/// kernel identity, credential, session, and sighand graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalTargetAuthorization {
    Allowed,
    DropProtectedInit,
    Denied,
    Missing,
}

/// An authorization result bound to the exact task/thread objects that were
/// inspected. The allowed ticket's fields stay private so a bare numeric PID
/// cannot be substituted between policy and enqueue.
#[derive(Debug)]
pub(crate) enum ExactSignalTargetAuthorization {
    Allowed(AuthorizedSignalTarget),
    DropProtectedInit,
    Denied,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExactThreadSignalPost {
    Posted(Option<ThreadKey>),
    Missing,
    QueueFull,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CarrierControlSignalPost {
    Posted,
    AcceptedProtectedInit,
    Missing,
}

impl ExactThreadSignalPost {
    pub(crate) const fn is_posted(self) -> bool {
        matches!(self, Self::Posted(_))
    }
}

#[derive(Debug)]
pub(crate) struct AuthorizedSignalTarget {
    domain: Arc<KernelDomain>,
    task: Weak<Task>,
    thread: Option<Weak<crate::kernel::objects::Thread>>,
}

impl Kernel {
    /// Authorize a process- or thread-directed Linux signal without consulting
    /// host process identity. `target_thread == None` uses the task's retained
    /// leader credential authority; thread-directed calls name the exact target
    /// thread.
    pub fn authorize_signal_target(
        &self,
        caller: &KernelContext,
        target_task: TaskId,
        target_thread: Option<LinuxTid>,
        signal: Option<LinuxSignal>,
    ) -> SignalTargetAuthorization {
        let target = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target_task) else {
                return SignalTargetAuthorization::Missing;
            };
            let thread = match target_thread {
                Some(tid) => {
                    let Some(thread) = record.task.thread(tid) else {
                        return SignalTargetAuthorization::Missing;
                    };
                    Some(thread.key())
                }
                None => None,
            };
            (record.task.key(), thread)
        };
        match self.authorize_signal_target_exact(caller, target.0, target.1, signal) {
            ExactSignalTargetAuthorization::Allowed(_) => SignalTargetAuthorization::Allowed,
            ExactSignalTargetAuthorization::DropProtectedInit => {
                SignalTargetAuthorization::DropProtectedInit
            }
            ExactSignalTargetAuthorization::Denied => SignalTargetAuthorization::Denied,
            ExactSignalTargetAuthorization::Missing => SignalTargetAuthorization::Missing,
        }
    }

    /// Resolve signal policy to one unforgeable task/thread generation. The
    /// returned ticket weakly binds the exact objects inspected here; posting
    /// through it fails if that generation exits and can never follow a reused
    /// numeric PID/TID to a different process.
    pub(crate) fn authorize_signal_target_exact(
        &self,
        caller: &KernelContext,
        target_task: TaskKey,
        target_thread: Option<ThreadKey>,
        signal: Option<LinuxSignal>,
    ) -> ExactSignalTargetAuthorization {
        if !std::ptr::eq(self, caller.kernel().as_ref()) {
            return ExactSignalTargetAuthorization::Missing;
        }
        let (target, thread, target_credentials, target_session, target_sighand) = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target_task.id) else {
                return ExactSignalTargetAuthorization::Missing;
            };
            if record.task.key() != target_task || record.task.lifecycle() != TaskLifecycle::Live {
                return ExactSignalTargetAuthorization::Missing;
            }
            let (credentials, thread) = match target_thread {
                Some(key) => {
                    let Some(thread) = record.task.thread(key.tid) else {
                        return ExactSignalTargetAuthorization::Missing;
                    };
                    if thread.key() != key {
                        return ExactSignalTargetAuthorization::Missing;
                    }
                    (thread.resources().credentials(), Some(thread))
                }
                None => (record.task.process_credentials(), None),
            };
            (
                Arc::clone(&record.task),
                thread,
                credentials,
                record.task.session(),
                record.task.shared().sighand(),
            )
        };
        if target.container().id() != caller.container().id() {
            return ExactSignalTargetAuthorization::Missing;
        }
        let caller_credentials = caller.resources().credentials();
        let caller_is_privileged = caller_credentials.is_privileged();
        let uid_match = [caller_credentials.ruid(), caller_credentials.euid()]
            .into_iter()
            .any(|caller_uid| {
                caller_uid == target_credentials.ruid() || caller_uid == target_credentials.suid()
            });
        let same_session_sigcont = signal.is_some_and(|signal| {
            signal.raw() == carrick_abi::LINUX_SIGCONT && caller.task().session() == target_session
        });
        if !caller_is_privileged && !uid_match && !same_session_sigcont {
            return ExactSignalTargetAuthorization::Denied;
        }

        if target.container().pid_root() == Some(target_task)
            && signal.is_some_and(|signal| {
                (crate::namespace::pid::is_init_protected_default_signal(signal.raw())
                    || matches!(
                        signal.raw(),
                        carrick_abi::LINUX_SIGTSTP
                            | carrick_abi::LINUX_SIGTTIN
                            | carrick_abi::LINUX_SIGTTOU
                    ))
                    && target_sighand.disposition(signal)
                        == crate::kernel::objects::SignalDisposition::Default
                    && !target.accepts_unhandled_signal(signal)
            })
        {
            return ExactSignalTargetAuthorization::DropProtectedInit;
        }
        ExactSignalTargetAuthorization::Allowed(AuthorizedSignalTarget {
            domain: Arc::clone(self.domain()),
            task: Arc::downgrade(&target),
            thread: thread.as_ref().map(Arc::downgrade),
        })
    }

    /// Apply a default-stop action to one live Linux task without signaling
    /// the host carrier process. The target's vCPU threads and its parent wait
    /// vehicle are woken only after the task-scoped state is published.
    pub(crate) fn stop_task_for_job_control(
        &self,
        target: TaskId,
        signal: LinuxSignal,
        action_generation: Option<crate::kernel::objects::JobControlStopInvalidationGeneration>,
    ) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        let generation = task.lock_signal_generation();
        if !task.stop_for_job_control(signal, action_generation) {
            return false;
        }
        drop(generation);
        let parent = self.current_parent_task(&task);
        task.wake();
        if let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    /// Make the calling task a `PTRACE_TRACEME` tracee owned by its exact
    /// current parent generation. HVPatch tasks share one host process, so
    /// this relation must live in the guest task graph rather than Darwin's
    /// process-wide ptrace state.
    pub(crate) fn claim_ptrace_traceme(&self, context: &KernelContext) -> bool {
        if !context.kernel().task_key_is_live(context.task().key()) {
            return false;
        }
        let Some(tracer) = context.task().parent() else {
            return false;
        };
        if self.live_task_key(tracer.id) != Some(tracer) {
            return false;
        }
        self.bind_ptrace_tracer(context.task(), tracer)
    }

    /// Record `tracer` as `tracee`'s exact tracer on both ends. The tracee's
    /// `ptrace_tracer` is the authority; the tracer's tracee set is the index
    /// its `wait` and exit consult.
    fn bind_ptrace_tracer(&self, tracee: &Task, tracer: TaskKey) -> bool {
        let tracer_task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&tracer.id) else {
                return false;
            };
            if record.task.key() != tracer || record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        if !tracee.claim_ptrace_tracer(tracer) {
            return false;
        }
        tracer_task.add_ptrace_tracee(tracee.key());
        true
    }

    /// `PTRACE_ATTACH` — ptrace(2): make the caller the tracer of one live
    /// process it may signal, then send it `SIGSTOP` so it enters a ptrace
    /// signal-delivery stop the tracer can `wait` for. Attaching to a task in
    /// the caller's own thread group, an already-traced task, or a task the
    /// caller could not signal is `EPERM`; a missing task is `ESRCH`. Init is
    /// attachable: this `SIGSTOP` is ptrace-directed, so the namespace-init
    /// drop that protects init from an ordinary `kill(1, SIGSTOP)` does not
    /// apply.
    pub(crate) fn attach_task_for_ptrace(
        &self,
        context: &KernelContext,
        target: TaskId,
    ) -> Result<(), carrick_abi::LinuxErrno> {
        if !std::ptr::eq(self, context.kernel().as_ref()) {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        let tracer = context.task().key();
        let tracee = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return Err(carrick_abi::LINUX_ESRCH);
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return Err(carrick_abi::LINUX_ESRCH);
            }
            Arc::clone(&record.task)
        };
        if tracee.key() == tracer {
            return Err(carrick_abi::LINUX_EPERM);
        }
        // ptrace(2) "Ptrace access mode checking", `PTRACE_MODE_ATTACH_REALCREDS`:
        // the caller's REAL uid/gid must equal the target's real, effective and
        // saved ids, AND the target's dumpable attribute must be 1. Only
        // `CAP_SYS_PTRACE` overrides either — the Docker default set lacks it
        // even for root, so euid 0 is NOT a pass (probe `ptraceattach`).
        let may_ptrace = context
            .task()
            .caps()
            .has_effective(crate::namespace::process::CAP_SYS_PTRACE);
        if !may_ptrace {
            let caller = context.resources().credentials();
            let target = tracee.process_credentials();
            let ids_match = [target.ruid(), target.euid(), target.suid()]
                .into_iter()
                .all(|uid| uid == caller.ruid())
                && [target.rgid(), target.egid(), target.sgid()]
                    .into_iter()
                    .all(|gid| gid == caller.rgid());
            if !ids_match || tracee.dumpable() == DumpableMode::Disable {
                return Err(carrick_abi::LINUX_EPERM);
            }
        }
        if !self.bind_ptrace_tracer(&tracee, tracer) {
            return Err(carrick_abi::LINUX_EPERM);
        }
        let Ok(sigstop) = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP) else {
            return Err(carrick_abi::LINUX_EINVAL);
        };
        if !self.post_signal_to_task_key(tracee.key(), sigstop, None) {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        Ok(())
    }

    /// Resolve a tracee's exact tracer at the moment a ptrace stop has been
    /// published, so the tracer's wait vehicle can be woken. The registry lock
    /// is released before callers invoke the lane waker.
    fn current_tracer_task(&self, task: &Task) -> Option<TaskRef> {
        let state = self.registry().state.read();
        task.ptrace_tracer()
            .and_then(|key| state.tasks.get(&key.id).map(|record| (key, record)))
            .filter(|(key, record)| record.task.key() == *key)
            .map(|(_, record)| Arc::clone(&record.task))
    }

    /// Mint authority for one exact settled ptrace stop before any target-MM
    /// retention or transport work begins.
    pub(crate) fn begin_ptrace_memory_access(
        &self,
        tracer: TaskKey,
        target: TaskKey,
    ) -> Result<crate::kernel::objects::PtraceMemoryAccessWitness, carrick_abi::LinuxErrno> {
        let task = {
            let registry = self.registry().state.read();
            let Some(record) = registry.tasks.get(&target.id) else {
                return Err(carrick_abi::LINUX_ESRCH);
            };
            if record.task.key() != target {
                return Err(carrick_abi::LINUX_ESRCH);
            }
            Arc::clone(&record.task)
        };
        task.begin_ptrace_memory_access(tracer)
    }

    pub(crate) fn stop_task_for_ptrace(&self, target: TaskId, signal: LinuxSignal) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        if !task.stop_for_ptrace(signal) {
            return false;
        }
        let parent = self.current_parent_task(&task);
        let tracer = self.current_tracer_task(&task);
        task.wake();
        if let Some(parent) = parent {
            parent.wake();
        }
        if let Some(tracer) = tracer {
            tracer.wake();
        }
        true
    }

    pub(crate) fn stop_task_for_ptrace_fault(
        &self,
        target: TaskId,
        fault: PtraceSynchronousFault,
    ) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        if !task.stop_for_ptrace_fault(fault) {
            return false;
        }
        let parent = self.current_parent_task(&task);
        let tracer = self.current_tracer_task(&task);
        task.wake();
        if let Some(parent) = parent {
            parent.wake();
        }
        if let Some(tracer) = tracer {
            tracer.wake();
        }
        true
    }

    pub(crate) fn take_ptrace_resume_fault(
        &self,
        target: TaskId,
    ) -> Option<PtraceSynchronousFault> {
        self.registry()
            .state
            .read()
            .tasks
            .get(&target)
            .and_then(|record| record.task.take_ptrace_resume_fault())
    }

    pub(crate) fn resume_task_from_ptrace(
        &self,
        tracer: TaskKey,
        target: TaskId,
        signal: Option<LinuxSignal>,
    ) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        if !task.resume_from_ptrace(tracer, signal) {
            return false;
        }
        task.wake();
        true
    }

    pub(crate) fn settle_task_ptrace_stop(&self, target: TaskId) -> PtraceStopSettlement {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return PtraceStopSettlement::NotPtraceStopped;
            };
            Arc::clone(&record.task)
        };
        task.settle_ptrace_stop()
    }

    pub(crate) fn detach_task_from_ptrace(&self, tracer: TaskKey, target: TaskId) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        if !task.detach_from_ptrace(tracer) {
            return false;
        }
        if let Some(tracer_task) = self.live_task(tracer.id).filter(|t| t.key() == tracer) {
            tracer_task.remove_ptrace_tracee(task.key());
        }
        task.wake();
        true
    }

    pub(crate) fn consume_ptrace_resume_signal(&self, target: TaskId, signal: LinuxSignal) -> bool {
        self.registry()
            .state
            .read()
            .tasks
            .get(&target)
            .is_some_and(|record| record.task.consume_ptrace_resume_signal(signal))
    }

    /// Resume one stopped Linux task. Returning false means the task was live
    /// but already running (or absent); SIGCONT delivery itself may still
    /// succeed and may still invoke a caught handler.
    pub fn continue_task_from_job_control(&self, target: TaskId) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            Arc::clone(&record.task)
        };
        let generation = task.lock_signal_generation();
        if !task.continue_from_job_control() {
            return false;
        }
        drop(generation);
        let parent = self.current_parent_task(&task);
        task.wake();
        if let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    pub fn task_is_job_control_stopped(&self, target: TaskId) -> bool {
        self.registry()
            .state
            .read()
            .tasks
            .get(&target)
            .is_some_and(|record| record.task.is_job_control_stopped())
    }

    /// Every LIVE task in `group`, lowest id first.
    ///
    /// This is the authority a `killpg(2)` must use. The HOST's process groups
    /// describe carrick itself, not the guest — on the kernel lane every Linux
    /// process is a thread of one host process, so they are all in the same
    /// host group and a guest pgid means nothing to `libc::kill`. Worse, a
    /// guest pgid of 1 negates to `kill(-1, …)`, the host BROADCAST sentinel.
    ///
    /// Sorted so delivery order is deterministic; Linux does not specify one,
    /// but a differential oracle needs carrick's to be stable.
    pub fn tasks_in_process_group(&self, group: ProcessGroupId) -> Vec<TaskId> {
        self.task_keys_in_process_group(group)
            .into_iter()
            .map(|key| key.id)
            .collect()
    }

    pub(crate) fn task_keys_in_process_group(&self, group: ProcessGroupId) -> Vec<TaskKey> {
        let state = self.registry().state.read();
        let mut keys: Vec<TaskKey> = state
            .tasks
            .iter()
            .filter(|(_, record)| {
                record.task.lifecycle() == TaskLifecycle::Live
                    && record.task.process_group() == group
            })
            .map(|(_, record)| record.task.key())
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Resolve one namespace-visible process group and capture authorization
    /// tickets for its exact member generations.
    ///
    /// Name lookup and membership selection share one registry read lock. If
    /// the group disappears and its internal number is reused afterward, the
    /// captured `TaskKey`s still carry the old serials; authorization/posting
    /// can therefore only fail, never redirect to the replacement group.
    pub(crate) fn authorize_namespace_process_group_signal_targets_exact(
        &self,
        caller: &KernelContext,
        namespace_id: u32,
        signal: Option<LinuxSignal>,
    ) -> Option<Vec<ExactSignalTargetAuthorization>> {
        if !std::ptr::eq(self, caller.kernel().as_ref()) {
            return None;
        }
        let targets = {
            let state = self.registry().state.read();
            let container = caller.container().id();
            let group = *state
                .process_group_by_namespace
                .get(&(container, namespace_id))?;
            exact_process_group_members(&state, container, group)?
        };
        Some(
            targets
                .into_iter()
                .map(|target| self.authorize_signal_target_exact(caller, target, None, signal))
                .collect(),
        )
    }

    /// Capture the caller's current process-group members with the same exact
    /// generation guarantee as namespace-name lookup.
    pub(crate) fn authorize_current_process_group_signal_targets_exact(
        &self,
        caller: &KernelContext,
        signal: Option<LinuxSignal>,
    ) -> Option<Vec<ExactSignalTargetAuthorization>> {
        if !std::ptr::eq(self, caller.kernel().as_ref()) {
            return None;
        }
        let targets = {
            let state = self.registry().state.read();
            let caller_record = state.tasks.get(&caller.task().key().id)?;
            if caller_record.task.key() != caller.task().key()
                || caller_record.task.lifecycle() != TaskLifecycle::Live
            {
                return None;
            }
            let container = caller_record.task.container().id();
            exact_process_group_members(&state, container, caller_record.task.process_group())?
        };
        Some(
            targets
                .into_iter()
                .map(|target| self.authorize_signal_target_exact(caller, target, None, signal))
                .collect(),
        )
    }

    /// Every LIVE task a broadcast `kill(-1, …)` may target: all of them except
    /// the caller and init, lowest id first.
    ///
    /// Linux sends `kill(-1)` to every process the caller has permission to
    /// signal, excluding itself and pid 1. Excluding init is what stops a
    /// guest's own `kill(-1, SIGKILL)` from taking down the container's init
    /// along with everything else.
    pub fn tasks_for_broadcast(&self, caller: TaskId) -> Vec<TaskId> {
        self.task_keys_for_broadcast(caller)
            .into_iter()
            .map(|key| key.id)
            .collect()
    }

    pub(crate) fn task_keys_for_broadcast(&self, caller: TaskId) -> Vec<TaskKey> {
        let state = self.registry().state.read();
        let Some(caller_record) = state.tasks.get(&caller) else {
            return Vec::new();
        };
        let container_id = caller_record.task.container().id();
        let init = state.container_inits.get(&container_id).copied();
        let mut keys: Vec<TaskKey> = state
            .tasks
            .iter()
            .filter(|(id, record)| {
                **id != caller
                    && init.is_none_or(|init| init.id != **id)
                    && record.task.container().id() == container_id
                    && record.task.lifecycle() == TaskLifecycle::Live
            })
            .map(|(_, record)| record.task.key())
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Enqueue through an exact-generation authorization ticket. The ticket
    /// upgrades only the weak task/thread references selected by policy, so an
    /// exit/reap/PID-reuse race can only make this fail; it cannot redirect
    /// delivery to the new occupant of the same numeric id.
    pub(crate) fn post_signal_to_authorized_target(
        &self,
        target: &AuthorizedSignalTarget,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        self.post_signal_to_authorized_target_inner(target, signal, siginfo, false)
            .is_posted()
    }

    /// Deliver a host-operator signal to one exact Linux task generation.
    ///
    /// Host peer authentication happens at the carrier-control boundary, so
    /// this path deliberately does not borrow a guest caller's credentials. It
    /// still preserves Linux namespace-init protection and never follows a
    /// recycled numeric pid because the complete [`TaskKey`] is required.
    pub(crate) fn post_carrier_control_signal(
        &self,
        target: TaskKey,
        signal: LinuxSignal,
    ) -> CarrierControlSignalPost {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target.id) else {
                return CarrierControlSignalPost::Missing;
            };
            if record.task.key() != target || record.task.lifecycle() != TaskLifecycle::Live {
                return CarrierControlSignalPost::Missing;
            }
            Arc::clone(&record.task)
        };
        if task.container().pid_root() == Some(target)
            && crate::namespace::pid::is_init_protected_default_signal(signal.raw())
            && task.shared().sighand().disposition(signal)
                == crate::kernel::objects::SignalDisposition::Default
            && !task.accepts_unhandled_signal(signal)
        {
            return CarrierControlSignalPost::AcceptedProtectedInit;
        }
        if self.post_signal_to_task_key(target, signal, None) {
            CarrierControlSignalPost::Posted
        } else {
            CarrierControlSignalPost::Missing
        }
    }

    pub(crate) fn post_guest_thread_signal_to_authorized_target(
        &self,
        target: &AuthorizedSignalTarget,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> ExactThreadSignalPost {
        self.post_signal_to_authorized_target_inner(target, signal, siginfo, true)
    }

    fn post_signal_to_authorized_target_inner(
        &self,
        target: &AuthorizedSignalTarget,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
        enforce_thread_rt_limit: bool,
    ) -> ExactThreadSignalPost {
        if !Arc::ptr_eq(self.domain(), &target.domain) {
            return ExactThreadSignalPost::Missing;
        }
        let Some(task) = target.task.upgrade() else {
            return ExactThreadSignalPost::Missing;
        };
        let thread = match &target.thread {
            Some(thread) => {
                let Some(thread) = thread.upgrade() else {
                    return ExactThreadSignalPost::Missing;
                };
                Some(thread)
            }
            None => None,
        };
        let generation = task.lock_signal_generation();
        if task.lifecycle() != TaskLifecycle::Live {
            return ExactThreadSignalPost::Missing;
        }
        if let Some(thread) = &thread
            && task
                .thread(thread.key().tid)
                .is_none_or(|current| !Arc::ptr_eq(&current, thread))
        {
            return ExactThreadSignalPost::Missing;
        }
        if enforce_thread_rt_limit && signal.is_realtime() {
            if thread.is_none() {
                return ExactThreadSignalPost::Missing;
            }
            let limit = task.rlimit(carrick_abi::LinuxResource::Sigpending).rlim_cur;
            if limit != carrick_abi::LINUX_RLIM_INFINITY {
                let thread_pending = task
                    .threads()
                    .into_iter()
                    .map(|thread| {
                        u64::try_from(thread.signal_state().pending_count()).unwrap_or(u64::MAX)
                    })
                    .fold(0_u64, u64::saturating_add);
                let pending = thread_pending.saturating_add(
                    u64::try_from(task.shared().pending_signals().pending_count())
                        .unwrap_or(u64::MAX),
                );
                if pending >= limit {
                    return ExactThreadSignalPost::QueueFull;
                }
            }
        }
        task.discard_opposing_job_control_signals(signal);
        task.record_job_control_signal_generation(signal);
        if let Some(thread) = &thread {
            thread.update_signal_state(|pending| {
                if signal.is_realtime() {
                    pending.enqueue_realtime(signal, siginfo);
                } else {
                    pending.enqueue_standard(signal, siginfo);
                }
            });
        } else {
            let pending = task.shared().pending_signals();
            if signal.is_realtime() {
                pending.enqueue_realtime(signal, siginfo);
            } else {
                pending.enqueue_standard(signal, siginfo);
            }
        }
        let continued = if signal.raw() == carrick_abi::LINUX_SIGCONT {
            task.continue_from_job_control()
        } else if signal.raw() == carrick_abi::LINUX_SIGKILL {
            task.resume_from_job_control_for_fatal_signal();
            false
        } else {
            false
        };
        drop(generation);
        // WCONTINUED belongs to the parent CURRENT at publication, not the
        // parent observed when authorization began. Resolve the exact current
        // TaskKey after publishing the event, then release the registry lock
        // before calling the lane waker.
        let parent = if continued {
            self.current_parent_task(&task)
        } else {
            None
        };
        if std::env::var_os("CARRICK_SIG_DEBUG").is_some() {
            eprintln!(
                "SIGDBG post sig={} task={:?} thread={:?}",
                signal.raw(),
                task.key(),
                target.thread.as_ref().map(|_| "tid-directed")
            );
        }
        task.wake();
        if let Some(parent) = parent {
            parent.wake();
        }
        ExactThreadSignalPost::Posted(thread.as_ref().map(|thread| thread.key()))
    }

    /// Post `signal` into `target`'s process-directed pending queue and report
    /// whether a live task took it.
    ///
    /// This is the delivery half of kernel-internal cross-process signalling:
    /// on the kernel lane a Linux process is a THREAD of one host process, so
    /// there is no host pid to `kill(2)` and the signal has to land in the
    /// kernel's own queue — the same queue [`take_lowest_in`] drains, so a
    /// signal posted here is indistinguishable from one the task raised on
    /// itself.
    ///
    /// Returns `false` for an unknown or exiting task, which is a `kill(2)`
    /// `ESRCH` for a specific target and simply "not a member" for a group
    /// fan-out. The liveness test closes a real race: a task that has begun
    /// exiting still has a registry entry (it becomes a zombie only once
    /// reaped), and enqueuing onto it would strand the signal in a queue no
    /// one will drain.
    ///
    /// [`take_lowest_in`]: super::objects::TaskPendingSignals::take_lowest_in
    ///
    /// The signal is made pending and then the target is WOKEN through its
    /// lane-supplied [`TaskWaker`](super::objects::TaskWaker), because enqueuing
    /// alone reaches only a task that gets back to a syscall or trap boundary —
    /// one parked in a host wait watches pipes, futexes and kqueues, none of
    /// which observe the kernel's queues. A task with no waker published is not an error: it still notices
    /// at its next boundary, just not while parked.
    ///
    /// The wake happens strictly AFTER the enqueue and outside the registry
    /// lock. After, so the woken task cannot look, find an empty queue, and go
    /// back to sleep having consumed its wake; outside, so a waker that blocks
    /// or re-enters the kernel cannot deadlock against the registry.
    #[cfg(test)]
    pub fn post_signal_to_task(
        &self,
        target: TaskId,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        let target = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target) else {
                return false;
            };
            record.task.key()
        };
        self.post_signal_to_task_key(target, signal, siginfo)
    }

    /// Publish one process-directed signal to an exact live task generation.
    /// Runtime-owned asynchronous sources (HVPatch process-local timers) use
    /// this after their syscall context has returned, when no caller context is
    /// available to authorize a fresh pid lookup. A recycled numeric pid can
    /// never receive the late event because the complete [`TaskKey`] must
    /// still match under the registry lock.
    pub(crate) fn post_signal_to_task_key(
        &self,
        target: TaskKey,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        let (task, parent) = {
            let state = self.registry().state.read();
            let Some(record) = state
                .tasks
                .get(&target.id)
                .filter(|record| record.task.key() == target)
            else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            let parent = record
                .task
                .parent()
                .and_then(|key| state.tasks.get(&key.id).map(|record| (key, record)))
                .filter(|(key, record)| record.task.key() == *key)
                .map(|(_, record)| Arc::clone(&record.task));
            (Arc::clone(&record.task), parent)
        };
        let generation = task.lock_signal_generation();
        if task.lifecycle() != TaskLifecycle::Live {
            return false;
        }
        task.discard_opposing_job_control_signals(signal);
        task.record_job_control_signal_generation(signal);
        let pending = task.shared().pending_signals();
        if signal.is_realtime() {
            pending.enqueue_realtime(signal, siginfo);
        } else {
            pending.enqueue_standard(signal, siginfo);
        }
        // Queue before resume. A stopped task cannot consume the signal yet,
        // and once SIGCONT/SIGKILL releases it the pending action must already
        // be visible so delivery cannot race behind guest execution or exit.
        let continued = if signal.raw() == carrick_abi::LINUX_SIGCONT {
            task.continue_from_job_control()
        } else if signal.raw() == carrick_abi::LINUX_SIGKILL {
            task.resume_from_job_control_for_fatal_signal();
            false
        } else {
            false
        };
        drop(generation);
        let subscribed = task.wake();
        if std::env::var_os("CARRICK_SIG_DEBUG").is_some() {
            eprintln!(
                "SIGDBG post_signal_to_task_key sig={} task={:?} subscribed_wake={subscribed}",
                signal.raw(),
                task.key(),
            );
        }
        if continued && let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    /// Cancel exactly one container generation for carrier shutdown. Every
    /// live task in that container has its kernel-owned continuation cancelled
    /// before SIGKILL is queued and its lane waker is fired. Sibling container
    /// tasks are selected out while holding the topology read lock.
    pub(crate) fn request_container_shutdown(&self, container: ContainerId) -> usize {
        let tasks = {
            let state = self.registry().state.read();
            state
                .tasks
                .values()
                .filter(|record| {
                    record.task.container().id() == container
                        && record.task.lifecycle() == TaskLifecycle::Live
                })
                .map(|record| Arc::clone(&record.task))
                .collect::<Vec<_>>()
        };
        for task in &tasks {
            for thread in task.threads() {
                let _ = thread.cancel_kernel_owned_continuation(
                    crate::vcpu_loop::continuation::CancellationCause::ServiceShutdown,
                );
            }
        }
        let Ok(sigkill) = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGKILL) else {
            return 0;
        };
        tasks
            .into_iter()
            .filter(|task| self.post_signal_to_task_key(task.key(), sigkill, None))
            .count()
    }

    /// Publish one short kernel-owned event to an exact live task generation,
    /// then wake that same retained task after publication.
    ///
    /// The registry read lock stays held only while `publish` mutates its leaf
    /// object. That makes the live-generation check and publication atomic
    /// against task exit, reap and PID reuse; the callback must not re-enter
    /// Kernel topology. The wake happens after both publication and registry
    /// unlock, so a waker can safely re-enter and can never observe the event
    /// as absent after spending its wake.
    pub(crate) fn publish_task_event_and_wake(
        &self,
        target: TaskKey,
        publish: impl FnOnce() -> bool,
    ) -> bool {
        let task = {
            let state = self.registry().state.read();
            let Some(record) = state
                .tasks
                .get(&target.id)
                .filter(|record| record.task.key() == target)
            else {
                return false;
            };
            if record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            if !publish() {
                return false;
            }
            record.task.record_task_event();
            Arc::clone(&record.task)
        };
        task.wake();
        true
    }

    /// Post one thread-directed signal to an exact live task/thread generation.
    /// The pending queue is published before the task wake, matching the
    /// process-directed ordering in [`Self::post_signal_to_task_key`].
    pub(crate) fn post_signal_to_thread_key(
        &self,
        target_task: TaskKey,
        target_thread: ThreadKey,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        let (thread, task, parent) = {
            let state = self.registry().state.read();
            let Some(record) = state.tasks.get(&target_task.id) else {
                return false;
            };
            if record.task.key() != target_task || record.task.lifecycle() != TaskLifecycle::Live {
                return false;
            }
            let Some(thread) = record.task.thread(target_thread.tid) else {
                return false;
            };
            if thread.key() != target_thread {
                return false;
            }
            let parent = record
                .task
                .parent()
                .and_then(|key| state.tasks.get(&key.id).map(|record| (key, record)))
                .filter(|(key, record)| record.task.key() == *key)
                .map(|(_, record)| Arc::clone(&record.task));
            (thread, Arc::clone(&record.task), parent)
        };
        let generation = task.lock_signal_generation();
        if task.lifecycle() != TaskLifecycle::Live
            || task
                .thread(target_thread.tid)
                .is_none_or(|current| !Arc::ptr_eq(&current, &thread))
        {
            return false;
        }
        task.discard_opposing_job_control_signals(signal);
        task.record_job_control_signal_generation(signal);
        thread.update_signal_state(|pending| {
            if signal.is_realtime() {
                pending.enqueue_realtime(signal, siginfo);
            } else {
                pending.enqueue_standard(signal, siginfo);
            }
        });
        let continued = if signal.raw() == carrick_abi::LINUX_SIGCONT {
            task.continue_from_job_control()
        } else if signal.raw() == carrick_abi::LINUX_SIGKILL {
            task.resume_from_job_control_for_fatal_signal();
            false
        } else {
            false
        };
        drop(generation);
        task.wake();
        if continued && let Some(parent) = parent {
            parent.wake();
        }
        true
    }

    #[cfg(test)]
    pub fn post_signal_to_thread(
        &self,
        target_task: TaskId,
        target_tid: LinuxTid,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> bool {
        let target = {
            let state = self.registry().state.read();
            let record = match state.tasks.get(&target_task) {
                Some(record) => record,
                None => return false,
            };
            let thread = match record.task.thread(target_tid) {
                Some(thread) => thread,
                None => return false,
            };
            (record.task.key(), thread.key())
        };
        self.post_signal_to_thread_key(target.0, target.1, signal, siginfo)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use carrick_abi::{LinuxCloneFlags, LinuxSiginfo, SigSet};
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::clone_plan::ClonePlan;
    use crate::kernel::objects::{LinuxWaitStatus, PtraceSynchronousFault};
    use crate::kernel::operations::tests::{bootstrap, fork_child};
    use crate::kernel::operations::{WaitChildClass, WaitMode, WaitOutcome};

    #[test]
    fn authorized_signal_never_follows_a_reused_numeric_pid() {
        let (kernel, root) = bootstrap(78);
        let root_binding = root.task_binding();
        let root_tid = root.thread().key().tid;
        let child_a = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_078),
                "signal-child-a".to_string(),
                None,
            )
            .expect("child A");
        let child_a_key = child_a.task().key();
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let ticket =
            match kernel.authorize_signal_target_exact(&root, child_a_key, None, Some(sigusr1)) {
                ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
                other => panic!("child A should authorize before exit: {other:?}"),
            };

        kernel
            .exit_task_key_eventually(child_a_key, LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit child A");
        drop(child_a);
        assert!(matches!(
            kernel.wait_child(
                root.task().key().id,
                Some(child_a_key.id),
                WaitMode::Consume
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        kernel.ids().set_next_for_tests(child_a_key.id.raw());

        let fresh_root = root_binding.capture(root_tid).expect("fresh root context");
        let child_b = kernel
            .fork_task(
                &fresh_root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_079),
                "signal-child-b".to_string(),
                None,
            )
            .expect("child B");
        assert_eq!(child_b.task().key().id, child_a_key.id);
        assert_ne!(child_b.task().key(), child_a_key);

        assert!(
            !kernel.post_signal_to_authorized_target(&ticket, sigusr1, None),
            "the old-generation authorization ticket must fail closed",
        );
        assert!(
            !child_b
                .task()
                .shared()
                .pending_signals()
                .present()
                .contains(sigusr1.raw()),
            "the reused PID must not receive child A's authorized signal",
        );
    }

    #[test]
    fn authorized_group_selection_never_follows_a_reused_group_number() {
        let (kernel, root) = bootstrap(79);
        let root_binding = root.task_binding();
        let root_tid = root.thread().key().tid;
        let child_a = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_179),
                "group-signal-child-a".to_owned(),
                None,
            )
            .expect("child A");
        let child_a_key = child_a.task().key();
        let child_a_group = kernel
            .create_process_group(child_a_key.id, None)
            .expect("child A group");
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let selected = kernel
            .authorize_namespace_process_group_signal_targets_exact(
                &root,
                child_a_group.raw() as u32,
                Some(sigusr1),
            )
            .expect("child A group exists");
        let ticket = selected
            .into_iter()
            .find_map(|authorization| match authorization {
                ExactSignalTargetAuthorization::Allowed(ticket) => Some(ticket),
                _ => None,
            })
            .expect("child A is authorized");

        kernel
            .exit_task_key_eventually(child_a_key, LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit child A");
        drop(child_a);
        assert!(matches!(
            kernel.wait_child(
                root.task().key().id,
                Some(child_a_key.id),
                WaitMode::Consume
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        kernel.ids().set_next_for_tests(child_a_key.id.raw());

        let fresh_root = root_binding.capture(root_tid).expect("fresh root context");
        let child_b = kernel
            .fork_task(
                &fresh_root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_180),
                "group-signal-child-b".to_owned(),
                None,
            )
            .expect("child B");
        assert_eq!(child_b.task().key().id, child_a_key.id);
        assert_ne!(child_b.task().key(), child_a_key);
        assert_eq!(
            kernel
                .create_process_group(child_b.task().key().id, None)
                .expect("child B group"),
            child_a_group,
        );

        assert!(
            !kernel.post_signal_to_authorized_target(&ticket, sigusr1, None),
            "the exact old group member ticket must fail closed",
        );
        assert!(
            !child_b
                .task()
                .shared()
                .pending_signals()
                .present()
                .contains(sigusr1.raw()),
            "the reused group number must not redirect delivery to child B",
        );
    }

    #[test]
    fn carrier_control_honors_default_signal_protection_for_namespace_init() {
        let (kernel, root) = bootstrap(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
        let sigterm = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTERM).expect("SIGTERM");

        assert_eq!(
            kernel.post_carrier_control_signal(root.task().key(), sigterm),
            CarrierControlSignalPost::AcceptedProtectedInit,
        );
        assert!(
            !root
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGTERM),
            "a default-protected signal must not enter init's pending queue",
        );
    }

    #[test]
    fn carrier_control_signal_is_bound_to_the_exact_task_generation() {
        let (kernel, root) = bootstrap(8_101);
        let stale = root.task().key();
        let sigkill = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGKILL).expect("SIGKILL");

        kernel
            .exit_task_key_eventually(stale, LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit old root generation");

        assert_eq!(
            kernel.post_carrier_control_signal(stale, sigkill),
            CarrierControlSignalPost::Missing,
        );
    }

    #[test]
    fn exact_authorized_self_signals_preserve_process_and_thread_queue_ownership() {
        let (kernel, root) = bootstrap(80);
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let sigusr2 = LinuxSignal::for_signal_number(12).expect("SIGUSR2");
        // Every container root is namespace init now, even when its carrier
        // TaskId is not numerically 1. Linux permits init to receive these
        // default-lethal signals only after it installs a handler; this test
        // is about process-vs-thread queue ownership, not init immunity.
        let mut caught = carrick_abi::LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        root.shared().sighand().install_action(sigusr1, caught);
        root.shared().sighand().install_action(sigusr2, caught);
        let process_ticket = match kernel.authorize_signal_target_exact(
            &root,
            root.task().key(),
            None,
            Some(sigusr1),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("self process target must authorize: {other:?}"),
        };
        let thread_ticket = match kernel.authorize_signal_target_exact(
            &root,
            root.task().key(),
            Some(root.thread().key()),
            Some(sigusr2),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("self thread target must authorize: {other:?}"),
        };

        assert!(kernel.post_signal_to_authorized_target(&process_ticket, sigusr1, None));
        assert!(kernel.post_signal_to_authorized_target(&thread_ticket, sigusr2, None));
        assert!(
            root.task()
                .shared()
                .pending_signals()
                .present()
                .contains(sigusr1.raw())
        );
        let thread_pending = root.thread().signal_state().pending();
        assert!(thread_pending.contains(sigusr2.raw()));
        assert!(!thread_pending.contains(sigusr1.raw()));
    }

    #[test]
    fn exact_thread_signal_admission_has_one_realtime_queue_winner() {
        let (kernel, root) = bootstrap(81);
        root.task()
            .replace_rlimit(carrick_abi::LinuxResource::Sigpending, |_| {
                Ok::<_, ()>(carrick_abi::LinuxRlimit::new(1, 1))
            })
            .expect("one pending RT slot");
        let signal = LinuxSignal::for_signal_number(32).expect("SIGRTMIN");
        let ticket = || match kernel.authorize_signal_target_exact(
            &root,
            root.task().key(),
            Some(root.thread().key()),
            Some(signal),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("exact thread ticket: {other:?}"),
        };
        let first = ticket();
        let second = ticket();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let results = std::thread::scope(|scope| {
            let first_barrier = Arc::clone(&barrier);
            let first_kernel = Arc::clone(&kernel);
            let first = scope.spawn(move || {
                first_barrier.wait();
                first_kernel.post_guest_thread_signal_to_authorized_target(
                    &first,
                    signal,
                    Some(LinuxSiginfo::kill(32, carrick_abi::LINUX_SI_TKILL, 81, 0)),
                )
            });
            let second_barrier = Arc::clone(&barrier);
            let second_kernel = Arc::clone(&kernel);
            let second = scope.spawn(move || {
                second_barrier.wait();
                second_kernel.post_guest_thread_signal_to_authorized_target(
                    &second,
                    signal,
                    Some(LinuxSiginfo::kill(32, carrick_abi::LINUX_SI_TKILL, 81, 0)),
                )
            });
            barrier.wait();
            [
                first.join().expect("first post"),
                second.join().expect("second post"),
            ]
        });
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(**result, ExactThreadSignalPost::Posted(Some(_))))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == ExactThreadSignalPost::QueueFull)
                .count(),
            1
        );
        assert_eq!(root.thread().signal_state().pending_count(), 1);
    }

    /// `killpg` must resolve its members from the KERNEL, not the host. On the
    /// kernel lane every Linux process is a thread of one host process, so they
    /// share one host process group and a guest pgid means nothing to
    /// `libc::kill` — and a guest pgid of 1 negates to the host BROADCAST
    /// sentinel.
    #[test]
    fn process_group_membership_comes_from_the_kernel() {
        let (kernel, root) = bootstrap(7);
        let root_id = root.task().key().id;
        let group = root.task().process_group();

        // A lone root is its own group.
        assert_eq!(kernel.tasks_in_process_group(group), vec![root_id]);

        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "group child".to_owned(),
                None,
            )
            .expect("reserve fork");
        let child_id = reservation.child_id();
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(701))
            .expect("prepare fork");
        let wait = prepared.take_child_start_wait().expect("child wait");
        let waiter = std::thread::spawn(move || wait.wait());
        let published = prepared.commit().expect("publish fork");
        drop(published);
        waiter.join().expect("join child");

        // A fork inherits its parent's group, so both are members and the order
        // is deterministic.
        assert_eq!(
            kernel.tasks_in_process_group(group),
            vec![root_id, child_id],
            "a forked child inherits its parent's process group"
        );

        // Exiting removes it: a killpg must never target a zombie.
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
        assert_eq!(kernel.tasks_in_process_group(group), vec![root_id]);
    }

    #[test]
    fn signal_authorization_uses_kernel_credentials_sessions_and_init_sighand() {
        let (kernel, root) = bootstrap(1);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(703),
                "signal authorization child".to_owned(),
                None,
            )
            .expect("fork child");
        let root = kernel
            .update_credentials(&root, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(1000))
            })
            .expect("set caller credentials");
        let child = kernel
            .update_credentials(&child, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(2000), carrick_abi::NsGid::new(2000))
            })
            .expect("set target credentials");
        let child_id = child.task().key().id;
        let child_tid = child.thread().key().tid;
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, None, Some(sigusr1)),
            SignalTargetAuthorization::Denied,
            "process-directed delivery must compare authoritative kernel credentials",
        );
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, Some(child_tid), None),
            SignalTargetAuthorization::Denied,
            "thread-directed signal zero must enforce the target thread credentials",
        );
        assert_eq!(
            kernel.tasks_for_broadcast(root.task().key().id),
            vec![child_id]
        );
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, None, None),
            SignalTargetAuthorization::Denied,
            "broadcast signal zero must filter a member with forbidden credentials",
        );
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, Some(child_tid), Some(sigcont)),
            SignalTargetAuthorization::Allowed,
            "SIGCONT is permitted within the same authoritative guest session",
        );

        let (kernel, init) = bootstrap(1);
        let sender = kernel
            .fork_task(
                &init,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(704),
                "init signal sender".to_owned(),
                None,
            )
            .expect("fork sender");
        let init_id = init.task().key().id;
        let sigterm = LinuxSignal::for_signal_number(15).expect("SIGTERM");
        assert_eq!(
            kernel.authorize_signal_target(&sender, init_id, None, Some(sigterm)),
            SignalTargetAuthorization::DropProtectedInit,
            "an unhandled default-lethal signal to guest init is accepted but dropped",
        );
        for signum in [
            carrick_abi::LINUX_SIGTSTP,
            carrick_abi::LINUX_SIGTTIN,
            carrick_abi::LINUX_SIGTTOU,
        ] {
            let signal = LinuxSignal::for_signal_number(signum).expect("terminal stop signal");
            assert_eq!(
                kernel.authorize_signal_target(&sender, init_id, None, Some(signal)),
                SignalTargetAuthorization::DropProtectedInit,
                "default terminal-stop signal {signum} must not stop guest init",
            );
        }
        let mut caught = carrick_abi::LinuxSigaction::empty();
        caught.sa_handler = 0x4000;
        init.shared().sighand().install_action(sigterm, caught);
        assert_eq!(
            kernel.authorize_signal_target(&sender, init_id, None, Some(sigterm)),
            SignalTargetAuthorization::Allowed,
            "guest init may receive a signal for which it installed a handler",
        );
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        init.shared().sighand().install_action(sigtstp, caught);
        assert_eq!(
            kernel.authorize_signal_target(&sender, init_id, None, Some(sigtstp)),
            SignalTargetAuthorization::Allowed,
            "guest init may catch a terminal-stop signal",
        );
        for signum in [carrick_abi::LINUX_SIGKILL, carrick_abi::LINUX_SIGSTOP] {
            let signal = LinuxSignal::for_signal_number(signum).expect("uncatchable signal");
            assert_eq!(
                kernel.authorize_signal_target(&sender, init_id, None, Some(signal)),
                SignalTargetAuthorization::Allowed,
                "signal {signum} must not take default-action init immunity",
            );
        }
    }

    #[test]
    fn signal_target_enumeration_excludes_tasks_that_have_begun_exit() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "exiting signal target", 705);
        let group = root.task().process_group();
        {
            let state = kernel.registry().state.read();
            let child = &state.tasks.get(&child_id).expect("live child").task;
            assert!(child.begin_exit());
        }

        assert_eq!(
            kernel.tasks_in_process_group(group),
            vec![root.task().key().id]
        );
        assert!(kernel.tasks_for_broadcast(root.task().key().id).is_empty());
    }

    #[test]
    fn process_signal_authority_survives_leader_thread_exit() {
        let (kernel, root) = bootstrap(1);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(706),
                "leader-exit signal target".to_owned(),
                None,
            )
            .expect("fork target");
        let sibling = kernel
            .clone_thread(
                &child,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(707),
                None,
            )
            .expect("clone sibling");
        let child_id = child.task().key().id;
        let root = kernel
            .update_credentials(&root, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(2000), carrick_abi::NsGid::new(2000))
            })
            .expect("set non-root caller credentials");
        let child = kernel
            .update_credentials(&child, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(2000), carrick_abi::NsGid::new(2000))
            })
            .expect("set leader credentials");
        kernel
            .exit_thread(&child, None)
            .expect("retire non-final leader");

        assert!(sibling.exact_thread_is_live());
        assert!(
            kernel
                .tasks_in_process_group(sibling.task().process_group())
                .contains(&child_id),
            "group signal enumeration retains a task whose leader retired",
        );
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, None, None),
            SignalTargetAuthorization::Allowed,
            "positive/group signal-zero uses the retained task credential authority",
        );
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        assert_eq!(
            kernel.authorize_signal_target(&root, child_id, None, Some(sigusr1)),
            SignalTargetAuthorization::Allowed,
            "positive/group nonzero signals use the retained task credential authority",
        );
        assert!(kernel.post_signal_to_task(child_id, sigusr1, None));
        assert!(
            sibling
                .task()
                .shared()
                .pending_signals()
                .take_lowest_in(SigSet::EMPTY.with(sigusr1.raw()))
                .is_some()
        );
    }

    #[test]
    fn job_control_stop_and_continue_are_task_scoped_and_waitable() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "job-control child", 708);
        let child_ruid = carrick_abi::NsUid::new(4_242);
        let child_euid = carrick_abi::NsUid::new(6_242);
        let child = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let _child = kernel
            .update_credentials(&child, |credentials| {
                credentials.seed_identity(child_euid, carrick_abi::NsGid::new(6_242));
                credentials.set_uid_triple(child_ruid, child_euid, child_euid);
            })
            .expect("set distinct child real and effective credentials");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.task_is_job_control_stopped(child_id));
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root.task().key().id,
                    Some(child_id),
                    WaitChildClass::Sigchld,
                    true,
                    false,
                    WaitMode::Consume,
                )
                .expect("wait stopped child"),
            WaitOutcome::Stopped {
                task: child_id,
                signal: sigstop,
                ruid: child_ruid,
            }
        );

        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root.task().key().id,
                    Some(child_id),
                    WaitChildClass::Sigchld,
                    false,
                    true,
                    WaitMode::Consume,
                )
                .expect("wait continued child"),
            WaitOutcome::Continued {
                task: child_id,
                ruid: child_ruid,
            }
        );
    }

    #[test]
    fn ptrace_stop_is_plain_waitable_and_only_exact_tracer_can_resume() {
        let (kernel, root) = bootstrap(1);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_088),
                "ptrace child".to_owned(),
                None,
            )
            .expect("fork child");
        let child_id = child.task().key().id;
        let child_ruid = carrick_abi::NsUid::new(4_243);
        let child = kernel
            .update_credentials(&child, |credentials| {
                credentials.seed_identity(child_ruid, carrick_abi::NsGid::new(4_243));
            })
            .expect("set non-root ptrace child credentials");
        let signal = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGUSR1).expect("SIGUSR1");

        assert!(kernel.claim_ptrace_traceme(&child));
        assert!(kernel.stop_task_for_ptrace(child_id, signal));
        assert_eq!(
            kernel
                .wait_child(root.task().key().id, Some(child_id), WaitMode::Consume)
                .expect("plain wait sees ptrace stop"),
            WaitOutcome::Stopped {
                task: child_id,
                signal,
                ruid: child_ruid,
            }
        );
        assert!(!kernel.resume_task_from_ptrace(child.task().key(), child_id, None,));
        assert!(kernel.resume_task_from_ptrace(root.task().key(), child_id, Some(signal),));
        assert!(
            child
                .task()
                .shared()
                .pending_signals()
                .take_lowest_in(SigSet::EMPTY.with(signal.raw()))
                .is_some(),
            "ptrace signal injection is queued before the stopped task wakes",
        );
        assert!(kernel.consume_ptrace_resume_signal(child_id, signal));
        assert!(!kernel.consume_ptrace_resume_signal(child_id, signal));
        assert!(matches!(
            kernel
                .wait_child(root.task().key().id, Some(child_id), WaitMode::Observe)
                .expect("resumed child remains live"),
            WaitOutcome::StillRunning(_)
        ));
    }

    #[test]
    fn ptrace_attach_stops_a_non_child_and_tracer_exit_detaches_it() {
        let (kernel, root) = bootstrap(1);
        let tracer = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_094),
                "ptrace tracer".to_owned(),
                None,
            )
            .expect("fork tracer");
        let tracee = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_095),
                "ptrace tracee".to_owned(),
                None,
            )
            .expect("fork tracee");
        let tracer_id = tracer.task().key().id;
        let tracee_id = tracee.task().key().id;
        let tracer = kernel
            .update_credentials(&tracer, |credentials| {
                credentials.seed_identity(
                    carrick_abi::NsUid::new(5_001),
                    carrick_abi::NsGid::new(5_001),
                );
            })
            .expect("unprivileged tracer");
        let tracee = kernel
            .update_credentials(&tracee, |credentials| {
                credentials.seed_identity(
                    carrick_abi::NsUid::new(6_002),
                    carrick_abi::NsGid::new(6_002),
                );
            })
            .expect("foreign-uid tracee");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");

        assert_eq!(
            kernel.attach_task_for_ptrace(&tracer, tracer_id),
            Err(carrick_abi::LINUX_EPERM),
            "a task cannot attach to itself",
        );
        assert_eq!(
            kernel.attach_task_for_ptrace(
                &tracer,
                TaskId::from_abi_positive(999_999).expect("unused id")
            ),
            Err(carrick_abi::LINUX_ESRCH),
        );
        assert_eq!(
            kernel.attach_task_for_ptrace(&tracer, tracee_id),
            Err(carrick_abi::LINUX_EPERM),
            "an unprivileged tracer needs a uid match",
        );
        let tracee_ruid = carrick_abi::NsUid::new(5_001);
        let tracee = kernel
            .update_credentials(&tracee, |credentials| {
                credentials.seed_identity(tracee_ruid, carrick_abi::NsGid::new(5_001));
            })
            .expect("uid-matched tracee");
        assert_eq!(kernel.attach_task_for_ptrace(&tracer, tracee_id), Ok(()));
        assert_eq!(
            kernel.attach_task_for_ptrace(&root, tracee_id),
            Err(carrick_abi::LINUX_EPERM),
            "an already-traced task rejects a second tracer",
        );
        assert_eq!(tracee.task().ptrace_tracer(), Some(tracer.task().key()));
        assert!(
            tracee
                .task()
                .shared()
                .pending_signals()
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some(),
            "attach posts SIGSTOP to the tracee",
        );
        assert!(matches!(
            kernel
                .wait_child(tracer_id, Some(tracee_id), WaitMode::Observe)
                .expect("a live tracee is waitable by its tracer"),
            WaitOutcome::StillRunning(_)
        ));

        assert!(kernel.stop_task_for_ptrace(tracee_id, sigstop));
        assert_eq!(
            kernel
                .wait_child(tracer_id, Some(tracee_id), WaitMode::Consume)
                .expect("tracer wait sees the attach stop"),
            WaitOutcome::Stopped {
                task: tracee_id,
                signal: sigstop,
                ruid: tracee_ruid,
            }
        );
        assert!(tracee.task().is_job_control_stopped());

        kernel
            .exit_task(tracer_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("tracer exit");
        assert_eq!(tracee.task().ptrace_tracer(), None, "tracer exit detaches");
        assert!(
            !tracee.task().is_job_control_stopped(),
            "a detached ptrace-stopped tracee resumes",
        );
        assert!(matches!(
            kernel
                .wait_child(root.task().key().id, Some(tracee_id), WaitMode::Observe)
                .expect("resumed tracee remains live for its parent"),
            WaitOutcome::StillRunning(_)
        ));
    }

    #[test]
    fn ptrace_attach_denies_a_non_dumpable_target_without_cap_sys_ptrace() {
        // ptrace(2) `PTRACE_MODE_ATTACH_REALCREDS`: a uid match is not enough
        // when the target cleared `PR_SET_DUMPABLE`; only `CAP_SYS_PTRACE`
        // overrides that, and the Docker default set (root included) lacks it
        // (probe `ptraceattach`: `attach_nondumpable_eperm=true` in the oracle).
        let (kernel, root) = bootstrap(1);
        let tracer = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_096),
                "non-dumpable ptrace tracer".to_owned(),
                None,
            )
            .expect("fork tracer");
        let tracee = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_097),
                "non-dumpable ptrace tracee".to_owned(),
                None,
            )
            .expect("fork tracee");
        let tracee_id = tracee.task().key().id;
        assert_eq!(tracee.task().dumpable(), DumpableMode::User);
        assert!(
            !tracer
                .task()
                .caps()
                .has_effective(crate::namespace::process::CAP_SYS_PTRACE),
            "the Docker default capability set lacks CAP_SYS_PTRACE even for root",
        );

        tracee.task().set_dumpable(DumpableMode::Disable);
        assert_eq!(
            kernel.attach_task_for_ptrace(&tracer, tracee_id),
            Err(carrick_abi::LINUX_EPERM),
            "a root tracer without CAP_SYS_PTRACE cannot attach to a non-dumpable target",
        );
        assert_eq!(tracee.task().ptrace_tracer(), None);

        tracer.task().with_caps(|caps| {
            caps.effective |= 1u64 << crate::namespace::process::CAP_SYS_PTRACE;
        });
        assert_eq!(
            kernel.attach_task_for_ptrace(&tracer, tracee_id),
            Ok(()),
            "CAP_SYS_PTRACE overrides the dumpable check",
        );
        assert_eq!(tracee.task().ptrace_tracer(), Some(tracer.task().key()));
    }

    #[test]
    fn ptrace_resume_preserves_exact_synchronous_fault_provenance() {
        let (kernel, root) = bootstrap(1);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_091),
                "ptrace synchronous-fault child".to_owned(),
                None,
            )
            .expect("fork child");
        let child_id = child.task().key().id;
        let signal = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSEGV).expect("SIGSEGV");
        let fault = PtraceSynchronousFault {
            signal,
            si_code: 2,
            si_addr: 0xfeed_4000,
            interrupted_pc: Some(0x4000_1234),
        };

        assert!(kernel.claim_ptrace_traceme(&child));
        assert!(kernel.stop_task_for_ptrace_fault(child_id, fault));
        assert!(matches!(
            kernel
                .wait_child(root.task().key().id, Some(child_id), WaitMode::Consume)
                .expect("plain wait sees synchronous ptrace stop"),
            WaitOutcome::Stopped { signal: stopped, .. } if stopped == signal
        ));
        assert!(kernel.resume_task_from_ptrace(root.task().key(), child_id, Some(signal)));
        assert_eq!(
            kernel.take_ptrace_resume_fault(child_id),
            Some(fault),
            "the exact stop generation must retain synchronous code/address/PC through resume"
        );
    }

    #[test]
    fn ptrace_resume_before_tracee_settlement_keeps_the_stop_authoritative() {
        let (kernel, root) = bootstrap(1);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_089),
                "ptrace early-resume child".to_owned(),
                None,
            )
            .expect("fork child");
        let child_id = child.task().key().id;
        let stop_signal =
            LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGUSR2).expect("SIGUSR2");
        let kill_signal =
            LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGKILL).expect("SIGKILL");

        assert!(kernel.claim_ptrace_traceme(&child));
        assert!(kernel.stop_task_for_ptrace(child_id, stop_signal));
        assert!(matches!(
            kernel
                .wait_child(root.task().key().id, Some(child_id), WaitMode::Consume)
                .expect("plain wait sees ptrace stop"),
            WaitOutcome::Stopped { signal, .. } if signal == stop_signal
        ));
        assert!(kernel.resume_task_from_ptrace(root.task().key(), child_id, Some(kill_signal),));

        assert!(
            kernel.task_is_job_control_stopped(child_id),
            "a tracer command cannot erase the stop before the tracee settles its return edge"
        );
        assert_eq!(
            kernel.settle_task_ptrace_stop(child_id),
            PtraceStopSettlement::Resumed {
                signal: Some(kill_signal),
            },
            "settlement must hand the already-recorded tracer command to the tracee"
        );
        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert!(
            child
                .task()
                .shared()
                .pending_signals()
                .take_lowest_in(SigSet::EMPTY.with(kill_signal.raw()))
                .is_some(),
            "SIGKILL remains queued until the tracee services the resume command"
        );
    }

    #[test]
    fn sigcont_generation_discards_pending_stop_signals_task_wide() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "continued child", 719);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigtstp, None));
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));

        let child = {
            let state = kernel.registry().state.read();
            Arc::clone(&state.tasks.get(&child_id).expect("child task").task)
        };
        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert!(
            !pending_of(&kernel, child_id)
                .present()
                .contains(sigstop.raw())
        );
        assert!(
            pending_of(&kernel, child_id)
                .present()
                .contains(sigcont.raw())
        );
        let thread_pending = child
            .thread(child_tid)
            .expect("child leader")
            .signal_state();
        assert!(!thread_pending.pending().contains(sigtstp.raw()));
    }

    #[test]
    fn stop_generation_discards_pending_sigcont_task_wide() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "stopped child", 720);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigcont, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigstop, None));

        let child = {
            let state = kernel.registry().state.read();
            Arc::clone(&state.tasks.get(&child_id).expect("child task").task)
        };
        assert!(
            !pending_of(&kernel, child_id)
                .present()
                .contains(sigcont.raw())
        );
        let thread_pending = child
            .thread(child_tid)
            .expect("child leader")
            .signal_state();
        assert!(!thread_pending.pending().contains(sigcont.raw()));
        assert!(thread_pending.pending().contains(sigstop.raw()));
    }

    #[test]
    fn sigcont_cancels_a_stop_dequeued_before_its_default_action() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "dequeue race child", 721);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(
            pending_of(&kernel, child_id)
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some(),
            "model a vCPU that dequeued STOP before applying its default action",
        );
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "the later SIGCONT generation must cancel the stale default-stop action",
        );
    }

    #[test]
    fn sigcont_cancels_every_stop_dequeued_before_its_default_action() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "two dequeue race child", 722);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigtstp, None));
        let child = {
            let state = kernel.registry().state.read();
            Arc::clone(&state.tasks.get(&child_id).expect("child task").task)
        };
        assert!(
            pending_of(&kernel, child_id)
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some(),
            "model one vCPU dequeuing the process-directed STOP",
        );
        assert!(
            child
                .thread(child_tid)
                .expect("child leader")
                .update_signal_state(|state| {
                    state
                        .take_lowest_in(SigSet::EMPTY.with(sigtstp.raw()))
                        .is_some()
                }),
            "model another vCPU dequeuing the thread-directed TSTP",
        );

        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.stop_task_for_job_control(child_id, sigtstp, None));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "SIGCONT must invalidate every earlier dequeued default-stop action",
        );

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(
            pending_of(&kernel, child_id)
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some()
        );
        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(
            kernel.task_is_job_control_stopped(child_id),
            "a stop generated after SIGCONT must replace the cancellation generation",
        );
    }

    #[test]
    fn stale_stop_action_cannot_borrow_a_newer_stop_generation() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "epoch-bound stop child", 724);
        let child_context = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        let stale = child_context
            .signal_authority()
            .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()));
        assert!(
            stale.is_some(),
            "model default-stop A dequeued before its action",
        );
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(kernel.post_signal_to_task(child_id, sigtstp, None));

        assert!(kernel.stop_task_for_job_control(
            child_id,
            sigstop,
            stale.and_then(|dequeue| dequeue.job_control_generation),
        ));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "stale A must not run under the newer stop B generation",
        );

        let current = child_context
            .signal_authority()
            .take_lowest_in(SigSet::EMPTY.with(sigtstp.raw()))
            .expect("dequeue new stop B");
        assert!(kernel.stop_task_for_job_control(
            child_id,
            sigtstp,
            current.job_control_generation,
        ));
        assert!(
            kernel.task_is_job_control_stopped(child_id),
            "the new stop generation must still apply its own default action",
        );
    }

    #[test]
    fn newer_stop_without_sigcont_does_not_cancel_dequeued_stop() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "same continue epoch child", 725);
        let child_context = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let child_ruid = carrick_abi::NsUid::new(4_244);
        let child_context = kernel
            .update_credentials(&child_context, |credentials| {
                credentials.seed_identity(child_ruid, carrick_abi::NsGid::new(4_244));
            })
            .expect("set non-root child credentials");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        let first = child_context
            .signal_authority()
            .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
            .expect("dequeue first stop");
        assert!(kernel.post_signal_to_task(child_id, sigtstp, None));

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, first.job_control_generation,));
        assert_eq!(
            kernel
                .wait_child_with_job_control(
                    root.task().key().id,
                    Some(child_id),
                    WaitChildClass::Sigchld,
                    true,
                    false,
                    WaitMode::Consume,
                )
                .expect("wait first stop"),
            WaitOutcome::Stopped {
                task: child_id,
                signal: sigstop,
                ruid: child_ruid,
            },
            "only an intervening SIGCONT invalidates dequeued stop work",
        );
    }

    #[test]
    fn sigkill_invalidates_a_stop_dequeued_before_fatal_delivery() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "kill dequeue race child", 726);
        let child_context = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigkill = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGKILL).expect("SIGKILL");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        let stale = child_context
            .signal_authority()
            .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
            .expect("dequeue stop before fatal signal generation");
        let ticket = match kernel.authorize_signal_target_exact(
            &root,
            child_context.task().key(),
            None,
            Some(sigkill),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("SIGKILL must authorize: {other:?}"),
        };
        assert!(kernel.post_signal_to_authorized_target(&ticket, sigkill, None));

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, stale.job_control_generation,));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "fatal delivery must invalidate every earlier dequeued stop action",
        );
        assert!(
            pending_of(&kernel, child_id)
                .present()
                .contains(sigkill.raw()),
            "the fatal signal must remain queued for the resumed vCPU",
        );
    }

    #[test]
    fn sigkill_resumes_a_stopped_task_without_wcontinued() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "kill stopped child", 727);
        let child_context = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("child context");
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigkill = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGKILL).expect("SIGKILL");

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.task_is_job_control_stopped(child_id));
        let ticket = match kernel.authorize_signal_target_exact(
            &root,
            child_context.task().key(),
            None,
            Some(sigkill),
        ) {
            ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
            other => panic!("SIGKILL must authorize: {other:?}"),
        };
        assert!(kernel.post_signal_to_authorized_target(&ticket, sigkill, None));

        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert!(
            matches!(
                kernel
                    .wait_child_with_job_control(
                        root.task().key().id,
                        Some(child_id),
                        WaitChildClass::Sigchld,
                        false,
                        true,
                        WaitMode::Consume,
                    )
                    .expect("wait after fatal resume"),
                WaitOutcome::StillRunning(_)
            ),
            "SIGKILL must not manufacture a WCONTINUED transition",
        );
    }

    #[test]
    fn sigcont_cancels_a_second_dequeued_stop_after_the_first_stops_the_task() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "split dequeue race child", 723);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigtstp = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGTSTP).expect("SIGTSTP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");

        assert!(kernel.post_signal_to_task(child_id, sigstop, None));
        assert!(kernel.post_signal_to_thread(child_id, child_tid, sigtstp, None));
        let child = {
            let state = kernel.registry().state.read();
            Arc::clone(&state.tasks.get(&child_id).expect("child task").task)
        };
        assert!(
            pending_of(&kernel, child_id)
                .take_lowest_in(SigSet::EMPTY.with(sigstop.raw()))
                .is_some()
        );
        assert!(
            child
                .thread(child_tid)
                .expect("child leader")
                .update_signal_state(|state| state
                    .take_lowest_in(SigSet::EMPTY.with(sigtstp.raw()))
                    .is_some())
        );

        assert!(kernel.stop_task_for_job_control(child_id, sigstop, None));
        assert!(kernel.task_is_job_control_stopped(child_id));
        assert!(kernel.post_signal_to_task(child_id, sigcont, None));
        assert!(!kernel.task_is_job_control_stopped(child_id));
        assert!(kernel.stop_task_for_job_control(child_id, sigtstp, None));
        assert!(
            !kernel.task_is_job_control_stopped(child_id),
            "SIGCONT must invalidate another stop dequeued before the first group stop",
        );
    }

    /// The pending queue of `id`, read the way the task's own drain reads it.
    fn pending_of(
        kernel: &Arc<Kernel>,
        id: TaskId,
    ) -> Arc<crate::kernel::objects::TaskPendingSignals> {
        let state = kernel.registry().state.read();
        state
            .tasks
            .get(&id)
            .expect("task is registered")
            .task
            .shared()
            .pending_signals()
    }

    /// The delivery half. A signal posted to another task must land in THAT
    /// task's pending queue and nowhere else: posting into the sender's queue
    /// instead is the shape of bug where `killpg` appears to work — the call
    /// succeeds — while the intended target never sees the signal and the
    /// SENDER dies of it.
    #[test]
    fn a_posted_signal_lands_in_the_target_queue_only() {
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;
        let child_id = fork_child(&kernel, &root, "signal target", 711);

        let sigterm = LinuxSignal::for_signal_number(15).expect("SIGTERM");
        assert!(
            kernel.post_signal_to_task(child_id, sigterm, None),
            "a live task accepts the signal"
        );

        assert!(
            pending_of(&kernel, child_id).present().contains(15),
            "the signal is pending on the target"
        );
        assert!(
            !pending_of(&kernel, root_id).present().contains(15),
            "the sender must not have signalled itself"
        );

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
    }

    #[test]
    fn a_thread_directed_signal_requires_exact_task_membership_and_lands_on_that_thread() {
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;
        let child_id = fork_child(&kernel, &root, "thread signal target", 714);
        let child_tid = LinuxTid::for_task_leader(child_id);
        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");

        assert_eq!(kernel.live_task_for_thread(None, child_tid), Some(child_id));
        assert_eq!(
            kernel.live_task_for_thread(Some(root_id), child_tid),
            None,
            "tgkill must reject a tid from another thread group",
        );
        assert!(kernel.post_signal_to_thread(
            child_id,
            child_tid,
            sigusr1,
            Some(LinuxSiginfo::kill(10, carrick_abi::LINUX_SI_TKILL, 1, 0)),
        ));

        let child = {
            let state = kernel.registry().state.read();
            state.tasks.get(&child_id).unwrap().task.clone()
        };
        assert!(
            child
                .thread(child_tid)
                .unwrap()
                .signal_state()
                .pending()
                .contains(10),
            "thread-directed delivery must not fall into the task-wide queue",
        );
        assert!(!pending_of(&kernel, child_id).present().contains(10));

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
    }

    /// Standard signals collapse to a single pending bit however many times
    /// they are sent; realtime signals QUEUE, one delivery per send. The queue
    /// picks between the two off `LinuxSignal::is_realtime`, so getting it
    /// backwards silently drops realtime deliveries (or duplicates standard
    /// ones) with no error anywhere.
    #[test]
    fn realtime_signals_queue_and_standard_signals_collapse() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "queue target", 712);

        let sigusr1 = LinuxSignal::for_signal_number(10).expect("SIGUSR1");
        assert!(!sigusr1.is_realtime());
        for _ in 0..3 {
            assert!(kernel.post_signal_to_task(child_id, sigusr1, None));
        }
        assert_eq!(
            pending_of(&kernel, child_id).pending_count(),
            1,
            "three sends of a standard signal collapse to one pending delivery"
        );

        let sigrt = LinuxSignal::for_signal_number(34).expect("SIGRTMIN+2");
        assert!(sigrt.is_realtime());
        for _ in 0..3 {
            assert!(kernel.post_signal_to_task(child_id, sigrt, None));
        }
        assert_eq!(
            pending_of(&kernel, child_id).pending_count(),
            4,
            "each realtime send queues its own delivery, alongside the standard one"
        );

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
    }

    /// A task that is parked in a host wait must be WOKEN, and it must be woken
    /// only once the signal is already pending — otherwise it wakes, looks at
    /// an empty queue, and parks again having spent its wake. This waker
    /// records what the queue held at the moment it was kicked, which is the
    /// ordering the lost-wakeup bug would violate.
    #[derive(Debug)]
    struct RecordingWaker {
        wakes: AtomicUsize,
        /// The target's REAL queue, so the wake observes exactly what a woken
        /// guest would observe rather than anything the test staged.
        queue: Arc<crate::kernel::objects::TaskPendingSignals>,
        pending_when_woken: AtomicUsize,
    }

    impl crate::kernel::objects::TaskWaker for RecordingWaker {
        fn wake_task(&self) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            self.pending_when_woken
                .store(self.queue.pending_count(), Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct EventPublicationWaker {
        wakes: AtomicUsize,
        published: Arc<AtomicBool>,
        published_when_woken: AtomicBool,
    }

    impl crate::kernel::objects::TaskWaker for EventPublicationWaker {
        fn wake_task(&self) {
            self.published_when_woken
                .store(self.published.load(Ordering::SeqCst), Ordering::SeqCst);
            self.wakes.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A shared kernel object can outlive the task that registered it. Its
    /// final event publication therefore has to authenticate and publish in
    /// one transaction: checking liveness, dropping the registry lock, then
    /// mutating the shared object lets exit/reap/PID-reuse redirect the event.
    #[test]
    fn exact_task_event_publication_serializes_exit_and_wakes_after_publish() {
        let (kernel, root) = bootstrap(79);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_080),
                "async object target".to_owned(),
                None,
            )
            .expect("child");
        let target = child.task().key();
        let published = Arc::new(AtomicBool::new(false));
        let waker = Arc::new(EventPublicationWaker {
            wakes: AtomicUsize::new(0),
            published: Arc::clone(&published),
            published_when_woken: AtomicBool::new(false),
        });
        child
            .task()
            .set_waker(Arc::clone(&waker) as Arc<dyn crate::kernel::objects::TaskWaker>);

        let (publish_entered_tx, publish_entered_rx) = std::sync::mpsc::sync_channel(0);
        let (release_publish_tx, release_publish_rx) = std::sync::mpsc::sync_channel(0);
        let publishing_kernel = Arc::clone(&kernel);
        let publishing_flag = Arc::clone(&published);
        let publisher = std::thread::spawn(move || {
            publishing_kernel.publish_task_event_and_wake(target, || {
                publish_entered_tx.send(()).unwrap();
                release_publish_rx.recv().unwrap();
                publishing_flag.store(true, Ordering::SeqCst);
                true
            })
        });
        publish_entered_rx.recv().unwrap();

        let (exit_started_tx, exit_started_rx) = std::sync::mpsc::sync_channel(0);
        let (exit_done_tx, exit_done_rx) = std::sync::mpsc::sync_channel(0);
        let exiting_kernel = Arc::clone(&kernel);
        let exiter = std::thread::spawn(move || {
            exit_started_tx.send(()).unwrap();
            let result = exiting_kernel
                .exit_task_key_eventually(target, LinuxWaitStatus::from_wait_encoding(0));
            exit_done_tx.send(result).unwrap();
        });
        exit_started_rx.recv().unwrap();
        assert!(matches!(
            exit_done_rx.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        release_publish_tx.send(()).unwrap();
        assert!(publisher.join().unwrap());
        assert!(
            exit_done_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("exit completes after publication")
                .is_ok()
        );
        exiter.join().unwrap();
        assert!(published.load(Ordering::SeqCst));
        assert_eq!(waker.wakes.load(Ordering::SeqCst), 1);
        assert!(waker.published_when_woken.load(Ordering::SeqCst));
    }

    /// Delivery must WAKE the target, not merely enqueue. A guest parked in a
    /// blocking read or a futex watches host pipes and futexes; none of them
    /// observe the kernel's pending queue, so without this a `killpg` to a
    /// sleeping process is silently deferred until it happens to trap.
    #[test]
    fn delivery_wakes_the_target_after_the_signal_is_pending() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "parked target", 714);
        let waker = Arc::new(RecordingWaker {
            wakes: AtomicUsize::new(0),
            queue: pending_of(&kernel, child_id),
            pending_when_woken: AtomicUsize::new(0),
        });

        {
            let state = kernel.registry().state.read();
            let task = &state.tasks.get(&child_id).expect("child").task;
            task.set_waker(Arc::clone(&waker) as Arc<dyn crate::kernel::objects::TaskWaker>);
        }

        let pending = pending_of(&kernel, child_id);
        assert_eq!(waker.wakes.load(Ordering::SeqCst), 0);

        let sigterm = LinuxSignal::for_signal_number(15).expect("SIGTERM");
        assert!(kernel.post_signal_to_task(child_id, sigterm, None));

        assert_eq!(
            waker.wakes.load(Ordering::SeqCst),
            1,
            "the target is woken exactly once per delivery"
        );
        assert_eq!(
            pending.pending_count(),
            1,
            "and the signal is pending for it to find"
        );
        assert_eq!(
            waker.pending_when_woken.load(Ordering::SeqCst),
            1,
            "the signal was ALREADY pending when the wake fired — waking first \
             lets the target look, find nothing, and park again having spent \
             its wake"
        );

        // A task with NO waker is not an error: it still notices at its next
        // syscall boundary, so delivery reports success.
        let bare_id = fork_child(&kernel, &root, "unwoken target", 715);
        assert!(kernel.post_signal_to_task(bare_id, sigterm, None));
        assert!(pending_of(&kernel, bare_id).present().contains(15));

        for id in [child_id, bare_id] {
            kernel
                .exit_task(id, LinuxWaitStatus::from_wait_encoding(0), None)
                .expect("retire child");
        }
    }

    #[test]
    fn authorized_sigcont_wakes_the_parent_current_at_publication() {
        let (kernel, root) = bootstrap(1);
        let parent = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_150),
                "old signal parent".to_string(),
                None,
            )
            .expect("old parent");
        let target = kernel
            .fork_task(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(7_151),
                "reparented signal target".to_string(),
                None,
            )
            .expect("target");
        let parent_id = parent.task().key().id;
        let target_key = target.task().key();
        let sigstop = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGSTOP).expect("SIGSTOP");
        let sigcont = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGCONT).expect("SIGCONT");
        assert!(kernel.stop_task_for_job_control(target_key.id, sigstop, None));
        let ticket =
            match kernel.authorize_signal_target_exact(&root, target_key, None, Some(sigcont)) {
                ExactSignalTargetAuthorization::Allowed(ticket) => ticket,
                other => panic!("SIGCONT must authorize before reparenting: {other:?}"),
            };

        let root_waker = Arc::new(RecordingWaker {
            wakes: AtomicUsize::new(0),
            queue: root.shared().pending_signals(),
            pending_when_woken: AtomicUsize::new(0),
        });
        let old_parent_waker = Arc::new(RecordingWaker {
            wakes: AtomicUsize::new(0),
            queue: parent.shared().pending_signals(),
            pending_when_woken: AtomicUsize::new(0),
        });
        root.task()
            .set_waker(Arc::clone(&root_waker) as Arc<dyn crate::kernel::objects::TaskWaker>);
        parent
            .task()
            .set_waker(Arc::clone(&old_parent_waker) as Arc<dyn crate::kernel::objects::TaskWaker>);

        kernel
            .exit_task(parent_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("exit old parent");
        assert_eq!(target.task().parent(), Some(root.task().key()));
        let root_wakes_before = root_waker.wakes.load(Ordering::SeqCst);
        let old_parent_wakes_before = old_parent_waker.wakes.load(Ordering::SeqCst);

        assert!(kernel.post_signal_to_authorized_target(&ticket, sigcont, None));
        assert_eq!(
            root_waker.wakes.load(Ordering::SeqCst),
            root_wakes_before + 1,
            "WCONTINUED publication must wake the target's current parent",
        );
        assert_eq!(
            old_parent_waker.wakes.load(Ordering::SeqCst),
            old_parent_wakes_before,
            "a stale authorization-time parent must not receive the wait wake",
        );
    }

    /// An unknown or already-exiting task reports no delivery. For a specific
    /// target that is `kill(2)`'s ESRCH; for a group fan-out it is simply "not
    /// a member". Enqueuing onto an exiting task would strand the signal in a
    /// queue nobody will drain.
    #[test]
    fn posting_to_an_unknown_or_exiting_task_reports_no_delivery() {
        let (kernel, root) = bootstrap(1);
        let child_id = fork_child(&kernel, &root, "exiting target", 713);
        let sigterm = LinuxSignal::for_signal_number(15).expect("SIGTERM");

        let absent = TaskId::from_abi_positive(9_999).expect("unused id");
        assert!(
            !kernel.post_signal_to_task(absent, sigterm, None),
            "a task that does not exist takes no signal"
        );

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
        assert!(
            !kernel.post_signal_to_task(child_id, sigterm, None),
            "a retired task takes no signal"
        );
    }

    /// `kill(-1)` targets every process the caller may signal EXCEPT itself and
    /// init. Excluding init is what stops a guest's own broadcast from killing
    /// the container's init along with everything else.
    #[test]
    fn broadcast_excludes_the_caller_and_init() {
        // Bootstrap AT pid 1 so the root IS init, which is the shape the kernel
        // lane will have once its id space is seeded at 1.
        let (kernel, root) = bootstrap(1);
        let root_id = root.task().key().id;

        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "broadcast child".to_owned(),
                None,
            )
            .expect("reserve fork");
        let child_id = reservation.child_id();
        let mut prepared = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(702))
            .expect("prepare fork");
        let wait = prepared.take_child_start_wait().expect("child wait");
        let waiter = std::thread::spawn(move || wait.wait());
        let published = prepared.commit().expect("publish fork");
        drop(published);
        waiter.join().expect("join child");

        // From init: the child, and NOT init itself.
        assert_eq!(kernel.tasks_for_broadcast(root_id), vec![child_id]);
        // From the child: init is excluded as init, the child as the caller —
        // so a lone child broadcasting reaches nobody.
        assert!(kernel.tasks_for_broadcast(child_id).is_empty());

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("retire child");
    }
}
