//! Thread cloning, scheduler target lookup, and thread reservation operations.
//!
//! Governs TID reservation and publication, thread startup handshake,
//! thread-group joining, and active scheduler generation validation.

use std::collections::BTreeSet;
use std::sync::Arc;

use carrick_fatal::carrick_fatal;
use carrick_hal::ThreadId;

use super::{
    ChildStartRelease, ChildStartWait, KernelFailpoint, KernelOperationError, TaskSetReservation,
    check_failpoint, ensure_task_unreserved, next_revision,
};
use crate::kernel::clone_plan::{ClonePlan, CloneTaskMode};
use crate::kernel::core::{Kernel, KernelContext};
use crate::kernel::ids::{LinuxTid, MmId, TaskId};
use crate::kernel::objects::{
    TaskKey, TaskLifecycle, TaskRef, TaskShared, ThreadKey, ThreadRef, ThreadResources,
};
use crate::kernel::registry::ThreadReservation;

#[derive(Debug)]
pub struct StartedThreadClone {
    context: KernelContext,
}

impl StartedThreadClone {
    pub fn context(&self) -> &KernelContext {
        &self.context
    }

    pub fn into_context(self) -> KernelContext {
        self.context
    }
}

/// Registry-published thread whose backend start gate is still closed.
/// Dropping it fail-safe starts the thread because publication cannot roll back.
#[derive(Debug)]
#[must_use = "a published thread must be started or explicitly retired"]
pub struct PublishedThreadClone {
    started: Option<StartedThreadClone>,
    visible_tid: i32,
    start_wait: Option<ChildStartWait>,
    start_release: ChildStartRelease,
}

impl PublishedThreadClone {
    pub const fn visible_tid(&self) -> i32 {
        self.visible_tid
    }

    pub fn context(&self) -> Option<&KernelContext> {
        self.started.as_ref().map(StartedThreadClone::context)
    }

    pub fn start_thread(mut self) -> Result<StartedThreadClone, KernelOperationError> {
        if let Some(started) = self.started.as_ref() {
            started.context.thread().open_start_gate();
        }
        self.start_release.start();
        drop(self.start_wait.take());
        self.started
            .take()
            .ok_or(KernelOperationError::PublishedThreadCloneConsumed)
    }

    pub fn into_context(self) -> Result<KernelContext, KernelOperationError> {
        Ok(self.start_thread()?.into_context())
    }
}

impl Drop for PublishedThreadClone {
    fn drop(&mut self) {
        if let Some(started) = self.started.as_ref() {
            started.context.thread().open_start_gate();
        }
        self.start_release.start();
        drop(self.start_wait.take());
    }
}

#[derive(Debug)]
pub struct ThreadCloneReservation {
    kernel: Arc<Kernel>,
    task: TaskRef,
    caller: ThreadRef,
    shared: Arc<TaskShared>,
    parent_resources: Arc<ThreadResources>,
    plan: ClonePlan,
    tid: LinuxTid,
    reservation: ThreadReservation,
    pid_identity: Option<crate::namespace::pid::PreparedNamespaceIdentity>,
    failpoint: Option<KernelFailpoint>,
}

impl ThreadCloneReservation {
    pub const fn tid(&self) -> LinuxTid {
        self.tid
    }

    pub fn visible_tid(&self) -> i32 {
        self.pid_identity
            .as_ref()
            .map_or(self.tid.raw(), |identity| identity.visible_id() as i32)
    }

    pub fn prepare(
        self,
        registry_id: ThreadId,
    ) -> Result<PreparedThreadClone, KernelOperationError> {
        let resources = Arc::new(ThreadResources::for_clone(
            &self.parent_resources,
            self.plan,
            self.kernel.object_ids(),
        )?);
        let thread = self.task.prepare_clone_thread(
            ThreadKey {
                tid: self.tid,
                serial: self.kernel.object_ids().thread_serial()?,
            },
            registry_id,
            Arc::clone(&resources),
            self.caller.signal_state(),
            self.caller.affinity(),
        );
        check_failpoint(self.failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(self.failpoint, KernelFailpoint::AfterBackendPrepare)?;
        let (start_wait, start_release) = ChildStartWait::pair();
        Ok(PreparedThreadClone {
            reservation: self,
            thread,
            resources,
            publication: None,
            start_wait: Some(start_wait),
            start_release,
        })
    }
}

#[derive(Debug)]
pub struct PreparedThreadClone {
    reservation: ThreadCloneReservation,
    thread: ThreadRef,
    resources: Arc<ThreadResources>,
    publication: Option<TaskSetReservation>,
    start_wait: Option<ChildStartWait>,
    start_release: ChildStartRelease,
}

pub enum ThreadPublicationReservationAttempt {
    Reserved(PreparedThreadClone),
    Busy(PreparedThreadClone),
}

impl PreparedThreadClone {
    pub const fn tid(&self) -> LinuxTid {
        self.reservation.tid
    }

    pub fn visible_tid(&self) -> i32 {
        self.reservation.visible_tid()
    }

    pub(crate) fn prepared_execution_identity(
        &self,
    ) -> (
        TaskKey,
        ThreadKey,
        MmId,
        crate::kernel::objects::ExecutionGeneration,
    ) {
        (
            self.reservation.task.key(),
            self.thread.key(),
            self.reservation.shared.mm().id(),
            crate::kernel::objects::ExecutionGeneration::initial_for_prepared_publication(),
        )
    }

    pub fn take_child_start_wait(&mut self) -> Result<ChildStartWait, KernelOperationError> {
        self.start_wait
            .take()
            .ok_or(KernelOperationError::ChildStartWaitTaken)
    }

    /// Reserve the task's publication slot before backend materialization takes
    /// the HVPatch topology lock. This establishes one lock order:
    /// task operation → topology → registry publication.
    pub fn reserve_publication_eventually(mut self) -> Result<Self, KernelOperationError> {
        let kernel = Arc::clone(&self.reservation.kernel);
        let task = self.reservation.task.key();
        let task_id = task.id;
        let transaction = kernel.object_ids().transaction_id()?;
        loop {
            let observed = kernel.reservation_epoch();
            let mut state = kernel.registry().state.write();
            if state
                .tasks
                .get(&task_id)
                .is_none_or(|record| record.task.key() != task)
            {
                return Err(KernelOperationError::ParentExited);
            }
            if !self.reservation.task.container().accepts_new_tasks() {
                return Err(KernelOperationError::ParentExited);
            }
            match TaskSetReservation::acquired(&kernel, &mut state, vec![task_id], transaction) {
                Ok(publication) => {
                    drop(state);
                    self.publication = Some(publication);
                    return Ok(self);
                }
                Err(KernelOperationError::TaskBusy(_)) => {
                    drop(state);
                    kernel.wait_for_reservation_change(observed);
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn try_reserve_publication(
        mut self,
    ) -> Result<ThreadPublicationReservationAttempt, KernelOperationError> {
        let kernel = Arc::clone(&self.reservation.kernel);
        let task = self.reservation.task.key();
        let task_id = task.id;
        let transaction = kernel.object_ids().transaction_id()?;
        let mut state = kernel.registry().state.write();
        if state
            .tasks
            .get(&task_id)
            .is_none_or(|record| record.task.key() != task)
        {
            return Err(KernelOperationError::ParentExited);
        }
        if !self.reservation.task.container().accepts_new_tasks() {
            return Err(KernelOperationError::ParentExited);
        }
        match TaskSetReservation::acquired(&kernel, &mut state, vec![task_id], transaction) {
            Ok(publication) => {
                drop(state);
                self.publication = Some(publication);
                Ok(ThreadPublicationReservationAttempt::Reserved(self))
            }
            Err(KernelOperationError::TaskBusy(_)) => {
                drop(state);
                Ok(ThreadPublicationReservationAttempt::Busy(self))
            }
            Err(error) => Err(error),
        }
    }

    pub fn commit(self) -> Result<PublishedThreadClone, KernelOperationError> {
        let Self {
            reservation,
            thread,
            resources,
            mut publication,
            start_wait,
            start_release,
        } = self;
        let ThreadCloneReservation {
            kernel,
            task,
            caller,
            shared,
            parent_resources,
            plan: _,
            tid,
            reservation,
            pid_identity,
            failpoint,
        } = reservation;
        let visible_tid = pid_identity
            .as_ref()
            .map_or(tid.raw(), |identity| identity.visible_id() as i32);
        let published_and_pending = {
            let mut state = kernel.registry().state.write();
            if let Some(publication) = publication.as_ref() {
                publication.validate(&state)?;
            } else {
                ensure_task_unreserved(&state, task.key().id)?;
            }
            let Some(record) = state.tasks.get_mut(&task.key().id) else {
                return Err(KernelOperationError::ParentExited);
            };
            if record.task.key() != task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            let current_shared = task.shared();
            let current_caller = task
                .thread(caller.key().tid)
                .ok_or(KernelOperationError::StaleContext)?;
            if !Arc::ptr_eq(&current_shared, &shared)
                || current_caller.key() != caller.key()
                || !Arc::ptr_eq(&current_caller, &caller)
                || !Arc::ptr_eq(&current_caller.resources(), &parent_resources)
            {
                return Err(KernelOperationError::StaleContext);
            }
            let published_revision = next_revision(record.revision)?;
            check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;
            if pid_identity.is_some_and(|identity| !identity.commit()) {
                return Err(KernelOperationError::PidNamespaceMembership(task.key().id));
            }
            let claim = reservation.commit();
            // The task, key and unique numeric claim were validated while the
            // registry write lock was held. Publication has no recoverable
            // failure left after namespace membership commits; treating an
            // invariant violation as an ordinary error would leave a ghost
            // namespace member behind.
            task.publish_thread(Arc::clone(&thread))
                .unwrap_or_else(|_| {
                    carrick_fatal!(
                        "kernel::thread_publication",
                        "publish_thread failed in PreparedThreadClone::commit"
                    );
                });
            record.thread_claims.insert(tid, claim);
            record.revision = published_revision;
            kernel.observe_thread_publication(&thread, &resources, published_revision);
            let pending_publication = match publication.as_mut() {
                Some(publication) => Some(publication.commit(&mut state)?),
                None => None,
            };
            (published_revision, pending_publication)
        };
        let (published_revision, pending_publication) = published_and_pending;
        if let Some(pending) = pending_publication {
            pending.publish();
        }
        kernel
            .auditors()
            .fork_admitted(task.key(), task.key(), crate::observe::ForkKind::Thread);
        Ok(PublishedThreadClone {
            started: Some(StartedThreadClone {
                context: KernelContext::from_parts(
                    kernel,
                    task,
                    thread,
                    shared,
                    resources,
                    published_revision,
                ),
            }),
            visible_tid,
            start_wait,
            start_release,
        })
    }
}

impl Kernel {
    /// Resolve one live Linux tid to its owning task, optionally requiring an
    /// exact tgid. Kernel-lane `tkill` uses the global form; `tgkill` supplies
    /// the tgid so a live tid from a different thread group is still ESRCH.
    pub fn live_task_for_thread(
        &self,
        required_task: Option<TaskId>,
        tid: LinuxTid,
    ) -> Option<TaskId> {
        self.live_keys_for_thread(required_task, tid)
            .map(|(task, _)| task.id)
    }

    pub(crate) fn live_keys_for_thread(
        &self,
        required_task: Option<TaskId>,
        tid: LinuxTid,
    ) -> Option<(TaskKey, ThreadKey)> {
        let state = self.registry().state.read();
        if let Some(task_id) = required_task {
            let record = state.tasks.get(&task_id)?;
            let thread = record.task.thread(tid)?;
            return (record.task.lifecycle() == TaskLifecycle::Live)
                .then_some((record.task.key(), thread.key()));
        }
        state.tasks.values().find_map(|record| {
            let thread = record.task.thread(tid)?;
            (record.task.lifecycle() == TaskLifecycle::Live)
                .then_some((record.task.key(), thread.key()))
        })
    }

    /// Resolve one scheduler request to the exact live thread generation.
    /// Numeric TID lookup is never returned on its own: the caller-supplied
    /// serial must still match while the registry read lock is held.
    pub(crate) fn exact_thread_for_scheduler(
        &self,
        key: ThreadKey,
    ) -> Option<Arc<crate::kernel::objects::Thread>> {
        let state = self.registry().state.read();
        state.tasks.values().find_map(|record| {
            let thread = record.task.thread(key.tid)?;
            (thread.key() == key).then_some(thread)
        })
    }

    /// Hold one exact live, active scheduler generation stable through an
    /// authority commit. Exited, Failed, and Uninitialized records are not
    /// admission authority even when their generation matches exactly.
    pub(crate) fn with_live_active_scheduler_thread<R>(
        &self,
        key: ThreadKey,
        generation: crate::kernel::objects::ExecutionGeneration,
        commit: impl FnOnce() -> R,
    ) -> Option<R> {
        let state = self.registry().state.read();
        let thread = state.tasks.values().find_map(|record| {
            let thread = record.task.thread(key.tid)?;
            (thread.key() == key).then_some(thread)
        })?;
        thread.with_active_execution_generation(generation, commit)
    }

    /// Test-only: drop one task's registry record while a caller still holds
    /// an `Arc<Thread>` for it — exactly what a concurrent reap does to a
    /// scheduler transition that is already in flight, which is the shape
    /// behind the captured `lost exact transition ... kernel_view=thread
    /// absent from registry` carrier abort.
    #[cfg(test)]
    pub(crate) fn reap_task_record_for_test(&self, task: TaskId) -> bool {
        let mut state = self.registry().state.write();
        let Some(record) = state.tasks.remove(&task) else {
            return false;
        };
        // A real reap does not merely drop the live record: it RETIRES every
        // thread of the task into the graph, which is how the kernel keeps
        // proving that generation terminal after the record is gone
        // (`commit_task_exit`). A fixture that skips it describes a graph Linux
        // cannot produce -- a thread that is in no task, no zombie and no
        // retirement -- and the generation-observer classifier is required to
        // call exactly that shape a LOST transition rather than a reap.
        let crate::kernel::core::TaskRecord {
            task: retired_task,
            thread_claims,
            dead_leader,
            ..
        } = record;
        for (tid, claim) in thread_claims {
            if let Some(thread) = retired_task.thread(tid) {
                state
                    .retired_threads
                    .push(crate::kernel::core::RetiredThreadRecord {
                        _key: thread.key(),
                        _task: thread.task_key(),
                        thread: Arc::downgrade(&thread),
                        _claim: claim,
                    });
            }
        }
        if let Some(dead_leader) = dead_leader {
            state.retired_threads.push(dead_leader);
        }
        true
    }

    /// What the KERNEL GRAPH says about one exact scheduler thread, for the
    /// generation observer's rejection classifier.
    ///
    /// `target` is the thread object the caller already holds, so its typed
    /// `execution_state` is read directly; the registry is consulted only for
    /// the two terminal facts the object itself cannot carry -- the thread is
    /// RETIRED, or its task is a ZOMBIE. Registry ABSENCE is deliberately not
    /// one of them: it answers "is this key resolvable right now", which is a
    /// different question from "will this generation ever run again".
    pub(crate) fn scheduler_target_liveness(
        &self,
        key: ThreadKey,
        target: &crate::kernel::objects::Thread,
    ) -> crate::kernel::scheduler::SchedulerTargetLiveness {
        use crate::kernel::scheduler::SchedulerTargetLiveness as Liveness;
        if matches!(
            target.execution_state(),
            crate::kernel::objects::ThreadExecutionState::Exited { .. }
                | crate::kernel::objects::ThreadExecutionState::Failed { .. }
        ) {
            return Liveness::Terminal;
        }
        let state = self.registry().state.read();
        if state
            .retired_threads
            .iter()
            .any(|retired| retired._key == key)
        {
            return Liveness::Terminal;
        }
        if state
            .zombies
            .values()
            .any(|record| LinuxTid::for_task_leader(record.zombie.key.id) == key.tid)
        {
            return Liveness::Terminal;
        }
        Liveness::Reachable
    }

    /// Test-only: drop one task's registry record and record NOTHING else.
    ///
    /// The result is a thread that is in no live task, no zombie and no
    /// retirement: the kernel graph cannot prove that generation terminal, only
    /// that the key does not resolve right now. That is a different fact from a
    /// reap, and this helper exists so the two can be told apart.
    #[cfg(test)]
    pub(crate) fn drop_task_record_for_test(&self, task: TaskId) -> bool {
        self.registry().state.write().tasks.remove(&task).is_some()
    }

    /// Diagnostic projection of one scheduler thread's execution state for the
    /// generation-observer abort: whether the registry still holds the thread
    /// and which execution generation it considers active. Read-only; taken
    /// on the abort path only.
    pub(crate) fn scheduler_thread_execution_diagnostic(&self, key: ThreadKey) -> String {
        let state = self.registry().state.read();
        let Some(thread) = state.tasks.values().find_map(|record| {
            let thread = record.task.thread(key.tid)?;
            (thread.key() == key).then_some(thread)
        }) else {
            let same_tid = state
                .tasks
                .values()
                .filter_map(|record| record.task.thread(key.tid))
                .map(|thread| format!("{:?}", thread.key()))
                .collect::<Vec<_>>();
            return format!("thread absent from registry; same-tid threads={same_tid:?}");
        };
        thread.execution_state_diagnostic()
    }

    /// Revalidate an exact granting generation and prove that `target` is a
    /// current process descendant in the Kernel parent graph. Thread-group
    /// siblings are intentionally excluded: scheduler shutdown inheritance is
    /// process lineage, never same-task membership or numeric ancestry.
    pub(crate) fn with_live_scheduler_descendant<R>(
        &self,
        grant: ThreadKey,
        grant_generation: crate::kernel::objects::ExecutionGeneration,
        target: ThreadKey,
        target_generation: crate::kernel::objects::ExecutionGeneration,
        commit: impl FnOnce() -> R,
    ) -> Option<R> {
        let state = self.registry().state.read();
        let resolve = |key: ThreadKey| {
            state.tasks.values().find_map(|record| {
                let thread = record.task.thread(key.tid)?;
                (thread.key() == key).then_some((record.task.key(), thread))
            })
        };
        let (grant_task, grant_thread) = resolve(grant)?;
        let (target_task, target_thread) = resolve(target)?;
        if target_task == grant_task || target.tid != LinuxTid::for_task_leader(target_task.id) {
            return None;
        }

        let mut parent = state
            .tasks
            .get(&target_task.id)
            .filter(|record| record.task.key() == target_task)
            .and_then(|record| record.task.parent());
        let mut visited = BTreeSet::new();
        let mut is_descendant = false;
        while let Some(key) = parent {
            if !visited.insert(key) {
                return None;
            }
            if key == grant_task {
                is_descendant = true;
                break;
            }
            parent = state
                .tasks
                .get(&key.id)
                .filter(|record| record.task.key() == key)
                .and_then(|record| record.task.parent());
        }
        if !is_descendant {
            return None;
        }
        grant_thread
            .with_active_execution_generation(grant_generation, || {
                target_thread.with_active_execution_generation(target_generation, commit)
            })
            .flatten()
    }

    pub(crate) fn with_live_scheduler_same_task_sibling<R>(
        &self,
        grant: ThreadKey,
        grant_generation: crate::kernel::objects::ExecutionGeneration,
        target: ThreadKey,
        target_generation: crate::kernel::objects::ExecutionGeneration,
        commit: impl FnOnce() -> R,
    ) -> Option<R> {
        let state = self.registry().state.read();
        let resolve = |key: ThreadKey| {
            state.tasks.values().find_map(|record| {
                let thread = record.task.thread(key.tid)?;
                (thread.key() == key).then_some((record.task.key(), thread))
            })
        };
        let (grant_task, grant_thread) = resolve(grant)?;
        let (target_task, target_thread) = resolve(target)?;
        if grant_task != target_task
            || grant == target
            || target.tid == LinuxTid::for_task_leader(target_task.id)
        {
            return None;
        }
        grant_thread
            .with_active_execution_generation(grant_generation, || {
                target_thread.with_active_execution_generation(target_generation, commit)
            })
            .flatten()
    }

    pub(crate) fn with_live_scheduler_process_root<R>(
        &self,
        target: ThreadKey,
        target_generation: crate::kernel::objects::ExecutionGeneration,
        commit: impl FnOnce() -> R,
    ) -> Option<R> {
        let state = self.registry().state.read();
        let record = state.tasks.values().find(|record| {
            record.task.lifecycle() == TaskLifecycle::Live
                && record.task.parent().is_none()
                && target.tid == LinuxTid::for_task_leader(record.task.key().id)
                && record
                    .task
                    .thread(target.tid)
                    .is_some_and(|thread| thread.key() == target)
        })?;
        record
            .task
            .thread(target.tid)?
            .with_active_execution_generation(target_generation, commit)
    }

    pub(crate) fn with_live_scheduler_peer_root<R>(
        &self,
        grant: ThreadKey,
        grant_generation: crate::kernel::objects::ExecutionGeneration,
        target: ThreadKey,
        target_generation: crate::kernel::objects::ExecutionGeneration,
        commit: impl FnOnce() -> R,
    ) -> Option<R> {
        let state = self.registry().state.read();
        let resolve = |key: ThreadKey| {
            state.tasks.values().find_map(|record| {
                let thread = record.task.thread(key.tid)?;
                (thread.key() == key).then_some((record.task.key(), record.task.parent(), thread))
            })
        };
        let (grant_task, grant_parent, grant_thread) = resolve(grant)?;
        let (target_task, target_parent, target_thread) = resolve(target)?;
        if grant_task == target_task
            || grant_parent != target_parent
            || grant.tid != LinuxTid::for_task_leader(grant_task.id)
            || target.tid != LinuxTid::for_task_leader(target_task.id)
        {
            return None;
        }
        grant_thread
            .with_active_execution_generation(grant_generation, || {
                target_thread.with_active_execution_generation(target_generation, commit)
            })
            .flatten()
    }

    /// Reserve a Linux TID while keeping the thread undiscoverable. The
    /// execution adapter prepares its host registry/vCPU state from the typed
    /// TID, then supplies the distinct registry identity to `prepare`.
    pub fn reserve_thread_clone(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<ThreadCloneReservation, KernelOperationError> {
        self.sweep_retired_threads();
        if !Arc::ptr_eq(self, &parent.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        if plan.task() != CloneTaskMode::JoinThreadGroup {
            return Err(KernelOperationError::ExpectedThreadGroup);
        }
        {
            let state = self.registry().state.read();
            ensure_task_unreserved(&state, parent.task.key().id)?;
            let record = state
                .tasks
                .get(&parent.task.key().id)
                .ok_or(KernelOperationError::ParentExited)?;
            if record.task.key() != parent.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            if !record.task.container().accepts_new_tasks() {
                return Err(KernelOperationError::ParentExited);
            }
            let current_shared = record.task.shared();
            let current_caller = record
                .task
                .thread(parent.thread.key().tid)
                .ok_or(KernelOperationError::StaleContext)?;
            if !Arc::ptr_eq(&current_shared, &parent.shared)
                || current_caller.key() != parent.thread.key()
                || !Arc::ptr_eq(&current_caller, &parent.thread)
                || !Arc::ptr_eq(&current_caller.resources(), &parent.resources)
            {
                return Err(KernelOperationError::StaleContext);
            }
        }
        let (tid, reservation) = self.ids().reserve_thread()?;
        let pid_identity = match parent.task().pid_ns_region() {
            Some(region) => {
                let internal = u32::try_from(tid.raw()).map_err(|_| {
                    KernelOperationError::PidNamespaceMembership(parent.task().key().id)
                })?;
                let parent_id = u32::try_from(parent.task().key().id.raw()).map_err(|_| {
                    KernelOperationError::PidNamespaceMembership(parent.task().key().id)
                })?;
                Some(region.reserve_identity(internal, parent_id).ok_or(
                    KernelOperationError::PidNamespaceMembership(parent.task().key().id),
                )?)
            }
            None => None,
        };
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        Ok(ThreadCloneReservation {
            kernel: self.clone(),
            task: Arc::clone(&parent.task),
            caller: Arc::clone(&parent.thread),
            shared: Arc::clone(&parent.shared),
            parent_resources: Arc::clone(&parent.resources),
            plan,
            tid,
            reservation,
            pid_identity,
            failpoint,
        })
    }

    /// Reserve a thread identity after any overlapping task transaction
    /// completes. Callers must invoke this before taking backend topology locks.
    pub fn reserve_thread_clone_eventually(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
    ) -> Result<ThreadCloneReservation, KernelOperationError> {
        loop {
            let observed = self.reservation_epoch();
            match self.reserve_thread_clone(parent, plan, None) {
                Ok(reservation) => return Ok(reservation),
                Err(KernelOperationError::TaskBusy(_)) => {
                    self.wait_for_reservation_change(observed);
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn clone_thread(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
        registry_id: ThreadId,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<KernelContext, KernelOperationError> {
        self.reserve_thread_clone(parent, plan, failpoint)?
            .prepare(registry_id)?
            .commit()?
            .into_context()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::clone_plan::ClonePlan;
    use crate::kernel::objects::LinuxWaitStatus;
    use crate::kernel::operations::tests::bootstrap;
    use crate::kernel::operations::{ChildStartOutcome, WaitMode, WaitOutcome};
    use crate::kernel::{Credentials, FileTable, FsContext, Mm, Sighand};

    #[test]
    fn thread_clone_reservation_keeps_tid_private_until_commit() {
        let (kernel, root) = bootstrap(190);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let reservation = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve thread");
        let tid = reservation.tid();
        assert!(root.task.thread(tid).is_none());

        let registry_id = ThreadId::synthetic_for_tests(8_888);
        let prepared = reservation.prepare(registry_id).expect("prepare thread");
        assert_eq!(prepared.tid(), tid);
        assert!(root.task.thread(tid).is_none());
        let published = prepared.commit().expect("publish thread");

        assert_eq!(
            published
                .context()
                .expect("published thread context")
                .thread
                .key()
                .tid,
            tid
        );
        assert!(root.task.thread(tid).is_some());
        let child = published.start_thread().expect("start thread");
        assert_eq!(child.context().thread.registry_id(), registry_id);
    }

    #[test]
    fn concurrent_thread_preparations_publish_against_the_latest_revision() {
        let (kernel, root) = bootstrap(194);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve first thread")
            .prepare(ThreadId::synthetic_for_tests(8_894))
            .expect("prepare first thread");
        let second = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve concurrent thread")
            .prepare(ThreadId::synthetic_for_tests(8_895))
            .expect("prepare concurrent thread");
        let first_tid = first.tid();
        let second_tid = second.tid();

        let commit_barrier = Arc::new(std::sync::Barrier::new(3));
        let first_barrier = Arc::clone(&commit_barrier);
        let first_handle = std::thread::spawn(move || {
            first_barrier.wait();
            first
                .commit()
                .expect("publish first thread")
                .start_thread()
                .expect("start first thread")
                .context()
                .task()
                .key()
        });
        let second_barrier = Arc::clone(&commit_barrier);
        let second_handle = std::thread::spawn(move || {
            second_barrier.wait();
            second
                .commit()
                .expect("publish concurrent thread after revision advance")
                .start_thread()
                .expect("start concurrent thread")
                .context()
                .task()
                .key()
        });
        commit_barrier.wait();
        let first_task = first_handle.join().expect("first commit thread");
        let second_task = second_handle.join().expect("second commit thread");

        assert_ne!(first_tid, second_tid);
        assert_eq!(first_task, root.task().key());
        assert_eq!(second_task, root.task().key());
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn sibling_publication_does_not_stale_thread_exit() {
        let (kernel, root) = bootstrap(195);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_896), None)
            .expect("first thread");
        let _second = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_897), None)
            .expect("second thread advances task revision");

        kernel
            .exit_thread(&first, None)
            .expect("thread identity remains valid across sibling publication");

        assert!(root.task().thread(first.thread().key().tid).is_none());
        assert_eq!(root.task().thread_count_for_test(), 2);
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn thread_start_gate_opens_only_after_clone_publication() {
        let (kernel, root) = bootstrap(191);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let reservation = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve thread");
        let tid = reservation.tid();
        let mut prepared = reservation
            .prepare(ThreadId::synthetic_for_tests(8_889))
            .expect("prepare thread");
        let wait = prepared
            .take_child_start_wait()
            .expect("unique thread wait");
        assert!(matches!(
            prepared.take_child_start_wait(),
            Err(KernelOperationError::ChildStartWaitTaken)
        ));
        let (waiting_tx, waiting_rx) = std::sync::mpsc::sync_channel(1);
        let (outcome_tx, outcome_rx) = std::sync::mpsc::sync_channel(1);
        let waiter = std::thread::spawn(move || {
            waiting_tx.send(()).expect("report waiting");
            outcome_tx.send(wait.wait()).expect("report outcome");
        });
        waiting_rx.recv().expect("thread reached gate");
        assert!(root.task.thread(tid).is_none());

        let published = prepared.commit().expect("publish thread");
        assert!(root.task.thread(tid).is_some());
        assert!(matches!(
            outcome_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        let started = published.start_thread().expect("start thread");
        assert_eq!(started.context().thread.key().tid, tid);
        assert_eq!(
            outcome_rx.recv().expect("started outcome"),
            ChildStartOutcome::Started
        );
        waiter.join().expect("join thread waiter");
    }

    #[test]
    fn thread_clone_drop_cancels_before_publish_and_starts_after_publish() {
        let (kernel, root) = bootstrap(192);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let reservation = kernel
            .reserve_thread_clone(&root, plan, None)
            .expect("reserve cancelled thread");
        let cancelled_tid = reservation.tid();
        let mut prepared = reservation
            .prepare(ThreadId::synthetic_for_tests(8_890))
            .expect("prepare cancelled thread");
        let wait = prepared.take_child_start_wait().expect("cancel wait");
        let cancelled = std::thread::spawn(move || wait.wait());
        drop(prepared);
        assert_eq!(
            cancelled.join().expect("join cancelled thread"),
            ChildStartOutcome::Cancelled
        );
        assert!(root.task.thread(cancelled_tid).is_none());

        let refreshed = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refreshed root");
        let reservation = kernel
            .reserve_thread_clone(&refreshed, plan, None)
            .expect("reserve fail-safe thread");
        let started_tid = reservation.tid();
        let mut prepared = reservation
            .prepare(ThreadId::synthetic_for_tests(8_891))
            .expect("prepare fail-safe thread");
        let wait = prepared.take_child_start_wait().expect("fail-safe wait");
        let started = std::thread::spawn(move || wait.wait());
        let published = prepared.commit().expect("publish fail-safe thread");
        drop(published);
        assert_eq!(
            started.join().expect("join fail-safe thread"),
            ChildStartOutcome::Started
        );
        let started_context = kernel
            .context(root.task.key().id, started_tid)
            .expect("started thread context");
        kernel
            .exit_thread(&started_context, None)
            .expect("retire fail-safe thread");
    }

    #[test]
    fn thread_exit_unpublishes_before_draining_its_tid_claim() {
        let (kernel, root) = bootstrap(195);
        let root_counts = kernel.ids().counts();
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let child = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(9_195), None)
            .expect("thread clone");
        let tid = child.thread.key().tid;
        let live_counts = kernel.ids().counts();

        kernel.exit_thread(&child, None).expect("thread exit");
        assert!(root.task.thread(tid).is_none());
        assert!(kernel.context(root.task.key().id, tid).is_err());
        assert_eq!(kernel.sweep_retired_threads(), 0);
        assert_eq!(kernel.ids().counts(), live_counts);

        drop(child);
        assert_eq!(kernel.sweep_retired_threads(), 1);
        assert_eq!(kernel.ids().counts(), root_counts);
        let refreshed = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refresh root");
        assert!(matches!(
            kernel.exit_thread(&refreshed, None),
            Err(KernelOperationError::LastThreadRequiresTaskExit(id)) if id == root.thread.key().tid
        ));
    }

    #[test]
    fn dead_leader_claim_survives_task_exit_and_zombie_reap_until_context_drain() {
        let (kernel, root) = bootstrap(196);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_196),
                "child".to_string(),
                None,
            )
            .expect("child task");
        let child_id = child.task.key().id;
        let sibling = kernel
            .clone_thread(
                &child,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(9_197),
                None,
            )
            .expect("child sibling");
        let dead_leader = kernel
            .context(child_id, LinuxTid::for_task_leader(child_id))
            .expect("current child leader");
        kernel
            .exit_thread(&dead_leader, None)
            .expect("leader thread exit");
        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("task exit");

        drop(child);
        drop(sibling);
        assert_eq!(kernel.sweep_retired_threads(), 0);
        assert_eq!(kernel.registry().retired_thread_count(), 2);
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Consume),
            Ok(WaitOutcome::Exited(_))
        ));
        assert_eq!(kernel.ids().counts().thread_claims, 3);

        drop(dead_leader);
        assert_eq!(kernel.sweep_retired_threads(), 2);
        assert_eq!(kernel.ids().counts().thread_claims, 1);
    }

    #[test]
    fn sweep_retired_threads_for_process_sweeps_only_matching_process() {
        let (kernel, root) = bootstrap(198);
        let child1 = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_198),
                "child1".to_string(),
                None,
            )
            .expect("child1 task");
        let child1_id = child1.task.key().id;
        let thread1 = kernel
            .clone_thread(
                &child1,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(9_199),
                None,
            )
            .expect("child1 thread");
        let child2 = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_200),
                "child2".to_string(),
                None,
            )
            .expect("child2 task");
        let child2_id = child2.task.key().id;
        let thread2 = kernel
            .clone_thread(
                &child2,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(9_201),
                None,
            )
            .expect("child2 thread");

        kernel.exit_thread(&thread1, None).expect("exit thread 1");
        kernel.exit_thread(&thread2, None).expect("exit thread 2");
        drop(thread1);
        drop(thread2);

        assert_eq!(kernel.registry().retired_thread_count(), 2);

        // Sweeping child1 only reaps child1's retired thread.
        assert_eq!(kernel.sweep_retired_threads_for_process(Some(child1_id)), 1);
        assert_eq!(kernel.registry().retired_thread_count(), 1);

        // A second sweep of child1 takes the read-fast-path and returns 0 without writing.
        assert_eq!(kernel.sweep_retired_threads_for_process(Some(child1_id)), 0);
        assert_eq!(kernel.registry().retired_thread_count(), 1);

        // Sweeping child2 reaps child2's retired thread.
        assert_eq!(kernel.sweep_retired_threads_for_process(Some(child2_id)), 1);
        assert_eq!(kernel.registry().retired_thread_count(), 0);
    }

    #[test]
    fn every_thread_exit_failpoint_preserves_the_live_thread() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, root) = bootstrap(197);
            let plan = ClonePlan::from_flags(
                LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
            )
            .expect("thread plan");
            let child = kernel
                .clone_thread(&root, plan, ThreadId::synthetic_for_tests(9_197), None)
                .expect("thread clone");
            let tid = child.thread.key().tid;
            let counts = kernel.ids().counts();

            assert!(matches!(
                kernel.exit_thread(&child, Some(point)),
                Err(KernelOperationError::Injected(injected)) if injected == point
            ));
            assert!(child.task.thread(tid).is_some());
            assert_eq!(kernel.ids().counts(), counts);
            assert!(kernel.validate_invariants().is_ok());
        }
    }

    #[test]
    fn thread_clone_keeps_task_shared_but_can_copy_files_and_fs() {
        let (kernel, root) = bootstrap(200);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let child = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(201), None)
            .expect("thread clone");

        assert!(Arc::ptr_eq(&root.task, &child.task));
        assert!(Arc::ptr_eq(&root.shared, &child.shared));
        assert!(!Arc::ptr_eq(
            &root.resources.files(),
            &child.resources.files()
        ));
        assert!(!Arc::ptr_eq(
            &root.resources.fs_context(),
            &child.resources.fs_context()
        ));
        assert_eq!(root.task.thread_count_for_test(), 2);
    }

    #[test]
    fn context_capture_never_mixes_association_generations() {
        let (kernel, root) = bootstrap(250);
        let first_shared = Arc::clone(&root.shared);
        let first_resources = Arc::clone(&root.resources);
        let second_shared = Arc::new(TaskShared::new(
            Arc::new(Mm::new_reference(
                kernel.object_ids().mm_id().expect("second mm"),
            )),
            Arc::new(Sighand::new(
                kernel.object_ids().sighand_id().expect("second sighand"),
            )),
        ));
        let second_resources = Arc::new(ThreadResources::new(
            Arc::new(FileTable::new(
                kernel.object_ids().file_table_id().expect("second files"),
            )),
            Arc::new(FsContext::new(
                kernel.object_ids().fs_context_id().expect("second fs"),
            )),
            Arc::new(Credentials::root(
                kernel
                    .object_ids()
                    .credentials_id()
                    .expect("second credentials"),
            )),
        ));
        let task_id = root.task.key().id;
        let tid = root.thread.key().tid;
        let writer_kernel = Arc::clone(&kernel);
        let writer_first_shared = Arc::clone(&first_shared);
        let writer_first_resources = Arc::clone(&first_resources);
        let writer_second_shared = Arc::clone(&second_shared);
        let writer_second_resources = Arc::clone(&second_resources);
        let writer = std::thread::spawn(move || {
            for iteration in 0..2_000 {
                let (shared, resources) = if iteration % 2 == 0 {
                    (
                        Arc::clone(&writer_second_shared),
                        Arc::clone(&writer_second_resources),
                    )
                } else {
                    (
                        Arc::clone(&writer_first_shared),
                        Arc::clone(&writer_first_resources),
                    )
                };
                writer_kernel
                    .publish_task_associations(task_id, tid, shared, resources)
                    .expect("publish generation");
            }
        });

        for _ in 0..2_000 {
            let context = kernel.context(task_id, tid).expect("context");
            let first = Arc::ptr_eq(&context.shared, &first_shared)
                && Arc::ptr_eq(&context.resources, &first_resources);
            let second = Arc::ptr_eq(&context.shared, &second_shared)
                && Arc::ptr_eq(&context.resources, &second_resources);
            assert!(first || second, "context mixed association generations");
        }
        writer.join().expect("writer thread");
    }

    /// Two threads of one Linux process must both be able to fork.
    ///
    /// This replaces an earlier `stale_context_cannot_commit_a_fork`, which
    /// asserted the opposite: that a second fork from the same captured
    /// context is refused as `StaleContext`. That contract is not Linux's.
    /// Committing a child advances the PARENT's revision (it gains a child),
    /// so any sibling holding a context captured beforehand was refused and
    /// the guest received `EAGAIN`. The Go toolchain forks concurrently from
    /// several threads, which is why a cold `go build` under HVPatch failed
    /// with "fork/exec ...: resource temporarily unavailable".
    ///
    /// The invariant that check was really protecting — a context captured
    /// before the task was REPARENTED must not fork — is now enforced
    /// directly against the parent association and is covered by
    /// `exiting_parent_reparents_live_and_zombie_children_to_root`.
    #[test]
    fn sibling_publication_does_not_stale_a_fork_context() {
        let (kernel, root) = bootstrap(275);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let first = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(276),
                "first child".to_string(),
                None,
            )
            .expect("first fork");
        let second = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(277),
                "sibling child".to_string(),
                None,
            )
            .expect("a sibling fork must not be staled by the first child's publication");

        assert_ne!(first.task.key(), second.task.key());
        assert_eq!(first.task.parent(), Some(root.task.key()));
        assert_eq!(second.task.parent(), Some(root.task.key()));
        assert_eq!(kernel.registry().task_count(), 3);
    }

    #[test]
    fn sibling_publication_does_not_stale_a_thread_clone_context() {
        let (kernel, root) = bootstrap(285);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(286), None)
            .expect("first thread");
        drop(first);
        let second = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(287), None)
            .expect("sibling-only revision advance remains compatible");

        assert_eq!(second.task().key(), root.task().key());
        assert_eq!(root.task.thread_count_for_test(), 3);
    }

    #[test]
    fn operation_lifetime_reservations_allow_thread_prepare_but_serialize_publication() {
        let (kernel, root) = bootstrap(335);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");

        let prepared_fork = kernel
            .reserve_fork(&root, fork_plan, "prepared child".to_owned(), None)
            .expect("reserve fork")
            .prepare_reference(ThreadId::synthetic_for_tests(336))
            .expect("prepare fork backend");
        assert!(matches!(
            kernel.prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            ),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        drop(prepared_fork);

        let prepared_thread = kernel
            .reserve_thread_clone(&root, thread_plan, None)
            .expect("reserve thread")
            .prepare(ThreadId::synthetic_for_tests(337))
            .expect("prepare thread backend");
        let prepared_exit_while_thread_prepares = kernel
            .prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("thread preparation does not reserve the task");
        assert!(matches!(
            prepared_thread.commit(),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        drop(prepared_exit_while_thread_prepares);

        let prepared_exit = kernel
            .prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare exit");
        assert!(matches!(
            kernel.reserve_fork(&root, fork_plan, "blocked child".to_owned(), None),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        assert!(matches!(
            kernel.reserve_thread_clone(&root, thread_plan, None),
            Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
        ));
        drop(prepared_exit);

        let fork_after_drop = kernel
            .reserve_fork(&root, fork_plan, "unblocked child".to_owned(), None)
            .expect("exit drop unlocks fork");
        drop(fork_after_drop);
        let thread_after_drop = kernel
            .reserve_thread_clone(&root, thread_plan, None)
            .expect("fork drop unlocks thread");
        drop(thread_after_drop);
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn thread_reservation_waits_for_an_overlapping_task_transaction() {
        let (kernel, root) = bootstrap(336);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let prepared_fork = kernel
            .reserve_fork(&root, fork_plan, "prepared child".to_owned(), None)
            .expect("reserve fork")
            .prepare_reference(ThreadId::synthetic_for_tests(337))
            .expect("prepare fork backend");
        let waiter_kernel = Arc::clone(&kernel);
        let root_task = root.task().key().id;
        let root_tid = root.thread().key().tid;
        let waiter = std::thread::spawn(move || {
            let waiter_root = waiter_kernel
                .context(root_task, root_tid)
                .expect("capture reservation waiter context");
            waiter_kernel.reserve_thread_clone_eventually(&waiter_root, thread_plan)
        });
        kernel.wait_for_reservation_waiter_for_tests();
        drop(prepared_fork);
        let reservation = waiter
            .join()
            .expect("thread reservation waiter")
            .expect("reserve after transaction release");
        drop(reservation);
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn prepared_thread_publication_waits_for_an_overlapping_task_transaction() {
        let (kernel, root) = bootstrap(338);
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let prepared_thread = kernel
            .reserve_thread_clone(&root, thread_plan, None)
            .expect("reserve thread")
            .prepare(ThreadId::synthetic_for_tests(339))
            .expect("prepare thread backend");
        let prepared_exit = kernel
            .prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("reserve overlapping exit");

        let publisher =
            std::thread::spawn(move || prepared_thread.reserve_publication_eventually()?.commit());
        kernel.wait_for_reservation_waiter_for_tests();
        drop(prepared_exit);
        let published = publisher
            .join()
            .expect("thread publisher")
            .expect("publish after transaction release");
        assert_eq!(
            published
                .context()
                .expect("published thread context")
                .task()
                .thread_count_for_test(),
            2
        );
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn prepared_thread_publication_busy_is_nonblocking_and_exactly_woken() {
        let (kernel, root) = bootstrap(339);
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .unwrap();
        let prepared_thread = kernel
            .reserve_thread_clone(&root, thread_plan, None)
            .unwrap()
            .prepare(ThreadId::synthetic_for_tests(340))
            .unwrap();
        let prepared_exit = kernel
            .prepare_task_exit(
                root.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .unwrap();
        let observed = kernel.reservation_epoch();
        let prepared_thread = match prepared_thread.try_reserve_publication().unwrap() {
            ThreadPublicationReservationAttempt::Busy(prepared) => prepared,
            ThreadPublicationReservationAttempt::Reserved(_) => {
                panic!("overlapping task transaction was not observed")
            }
        };
        let wakes = Arc::new(AtomicUsize::new(0));
        let callback_wakes = Arc::clone(&wakes);
        let subscription = kernel
            .subscribe_reservation_change(
                observed,
                Arc::new(move || {
                    callback_wakes.fetch_add(1, Ordering::SeqCst);
                }),
            )
            .expect("unchanged reservation epoch enrolls exact wake");
        assert_eq!(wakes.load(Ordering::SeqCst), 0);
        drop(prepared_exit);
        assert_eq!(wakes.load(Ordering::SeqCst), 1);
        drop(subscription);
        let prepared_thread = match prepared_thread.try_reserve_publication().unwrap() {
            ThreadPublicationReservationAttempt::Reserved(prepared) => prepared,
            ThreadPublicationReservationAttempt::Busy(_) => {
                panic!("released task transaction remained busy")
            }
        };
        let published = prepared_thread.commit().unwrap();
        assert_eq!(
            published.context().unwrap().task().thread_count_for_test(),
            2
        );
    }
}
