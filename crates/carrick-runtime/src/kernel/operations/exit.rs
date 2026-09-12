//! Task exit, thread retirement, and file-table and MM I/O retirement operations.
//!
//! Governs the two-phase task exit protocol (`prepare_task_exit` -> `commit_task_exit`),
//! non-final thread retirement (`exit_thread`), child reparenting / subreaper adoption,
//! exit subscription notification, and unreferenced file table and MM I/O retirement.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use carrick_fatal::carrick_fatal;
use carrick_hal::KernelTransactionId;

use super::session::remove_group_member;
use super::{
    KernelFailpoint, KernelOperationError, TaskSetReservation, check_failpoint,
    ensure_task_unreserved, next_revision,
};
use crate::kernel::core::{
    FileCloseDisposition, FileCloseEvent, Kernel, KernelContext, RetiredThreadRecord,
    TaskExitSubscriber, TaskRecord, TaskRevision, VforkReleaseReason, ZombieRecord,
};
use crate::kernel::ids::{FileTableId, LinuxTid, TaskId};
use crate::kernel::objects::{
    FileTable, LinuxWaitStatus, Mm, TaskKey, TaskLifecycle, TaskParticipantError, Zombie,
};

/// Exit publication token whose fallible topology and revision checks have
/// completed. Dropping it leaves the task graph unchanged and releases every
/// affected identity reservation.
#[derive(Debug)]
pub struct PreparedTaskExit {
    pub(super) reservation: TaskSetReservation,
    pub(super) task: TaskKey,
    pub(super) task_revision: TaskRevision,
    pub(super) children: Vec<TaskKey>,
    pub(super) affected_revisions: BTreeMap<TaskId, (TaskRevision, TaskRevision)>,
    pub(super) adopter: Option<TaskKey>,
    pub(super) prepared_adopter_children: Option<BTreeSet<TaskKey>>,
    /// The container's pid-namespace init as of this transaction, when it is
    /// still LIVE (the exiting task itself counts: it is live until this exit
    /// commits). `None` means the init has already become a zombie, so nothing
    /// inside the namespace can adopt anyone any more and container retirement
    /// is the reaper of last resort. Recorded here rather than re-read at
    /// commit so the judgement comes from the same reserved snapshot that
    /// chose `adopter`.
    pub(super) namespace_init: Option<TaskKey>,
    pub(super) registry_zombie: Zombie,
    pub(super) result_zombie: Zombie,
}

impl PreparedTaskExit {
    pub const fn task(&self) -> TaskKey {
        self.task
    }

    pub const fn transaction(&self) -> KernelTransactionId {
        self.reservation.transaction
    }

    /// Who will consume the zombie this exit publishes.
    ///
    /// A parentless zombie is NOT by itself a defect: a container's
    /// pid-namespace init has no parent inside its namespace, and a task its
    /// init left behind when it exited has none either — `retire_container`
    /// reaps both. The defect is a parentless zombie published while the
    /// namespace init was still live and should have adopted it.
    pub(crate) fn zombie_reaper(&self) -> crate::observe::ZombieReaper {
        match self.result_zombie.parent {
            Some(parent) => crate::observe::ZombieReaper::Parent(parent),
            None => match self.namespace_init {
                Some(init) if init != self.task => crate::observe::ZombieReaper::Unreapable,
                _ => crate::observe::ZombieReaper::ContainerRetirement,
            },
        }
    }

    pub fn commit(self) -> Result<Zombie, KernelOperationError> {
        let kernel = Arc::clone(&self.reservation.kernel);
        kernel.commit_task_exit(self)
    }

    pub fn commit_notifying(
        self,
        notify_parent: impl FnOnce(Option<TaskKey>),
    ) -> Result<Zombie, KernelOperationError> {
        let kernel = Arc::clone(&self.reservation.kernel);
        kernel.commit_task_exit_notifying(self, notify_parent)
    }
}

impl Kernel {
    pub(crate) fn retire_mm_io_state_if_unreferenced(&self, target: &Arc<Mm>) {
        let live = self
            .registry()
            .state
            .read()
            .tasks
            .values()
            .any(|record| Arc::ptr_eq(&record.task.shared().mm(), target));
        if !live {
            target.clear_io_uring_mappings();
        }
    }

    /// Whether any registered thread outside `excluded` still holds `target`
    /// as its file table. The exclusion lets a process-terminal path retire
    /// its own table while its last thread is still registered — Linux
    /// `exit_files` runs before `exit_notify` — so that fd teardown never
    /// waits behind the exit publication or anything it serialises with.
    fn file_table_is_live_excluding(
        &self,
        target: &Arc<FileTable>,
        excluded: Option<TaskKey>,
    ) -> bool {
        let state = self.registry().state.read();
        state
            .tasks
            .values()
            .filter(|record| excluded.is_none_or(|excluded| record.task.key() != excluded))
            .any(|record| {
                record.task.thread_keys().into_iter().any(|thread_key| {
                    record
                        .task
                        .thread(thread_key.tid)
                        .is_some_and(|thread| Arc::ptr_eq(&thread.resources().files(), target))
                })
            })
    }

    /// Current FileTable generations of one exact live task. Exec/CLONE_FILES
    /// lifecycle glue uses this to authenticate a notification's owner-local
    /// alias after an old shared table changes concurrently with exec.
    pub(crate) fn task_file_tables_exact(&self, target: TaskKey) -> Vec<Arc<FileTable>> {
        let state = self.registry().state.read();
        let Some(task) = state
            .tasks
            .get(&target.id)
            .map(|record| &record.task)
            .filter(|task| task.key() == target && task.lifecycle() == TaskLifecycle::Live)
        else {
            return Vec::new();
        };
        let mut tables = Vec::new();
        for thread_key in task.thread_keys() {
            let Some(thread) = task.thread(thread_key.tid) else {
                continue;
            };
            let files = thread.resources().files();
            if !tables.iter().any(|observed| Arc::ptr_eq(observed, &files)) {
                tables.push(files);
            }
        }
        tables
    }

    pub(crate) fn retire_file_table_if_unreferenced(&self, target: &Arc<FileTable>) {
        self.retire_file_table_generation(target, None, None);
    }

    /// Retire `target` on behalf of `exiting`, whose last thread may still be
    /// registered: the process-terminal path closes the process's fds BEFORE
    /// it takes the retirement topology lock and publishes the exit, so the
    /// exiting task itself must not count as a live holder. Every other task
    /// sharing the table (`CLONE_FILES` without `CLONE_THREAD`) still keeps
    /// it alive. Idempotent: a second call finds the generation drained.
    pub(crate) fn retire_file_table_for_exiting_task(
        &self,
        target: &Arc<FileTable>,
        exiting: TaskKey,
    ) {
        self.retire_file_table_generation(target, None, Some(exiting));
    }

    pub(crate) fn retire_file_table_after_exec(
        &self,
        target: &Arc<FileTable>,
        successor: &Arc<FileTable>,
    ) {
        self.retire_file_table_generation(target, Some(successor), None);
    }

    pub(super) fn retire_file_table_generation(
        &self,
        target: &Arc<FileTable>,
        successor: Option<&Arc<FileTable>>,
        exiting: Option<TaskKey>,
    ) {
        if self.file_table_is_live_excluding(target, exiting) {
            return;
        }
        let events = target.drain_functional_refs();
        if events.is_empty() {
            return;
        }
        let successor_slots = successor.map(|table| table.read_open_files());
        self.pending_file_closes
            .lock()
            .extend(events.into_iter().map(|(fd, slot)| {
                let disposition = successor_slots
                    .as_ref()
                    .and_then(|slots| slots.get(&fd))
                    .filter(|survivor| Arc::ptr_eq(&survivor.description, &slot.description))
                    .map_or(FileCloseDisposition::Closed, |_| {
                        FileCloseDisposition::Transferred
                    });
                FileCloseEvent {
                    table: target.id(),
                    fd,
                    slot,
                    disposition,
                }
            }));
    }

    pub(crate) fn take_file_close_events(&self, table: FileTableId) -> Vec<FileCloseEvent> {
        let mut pending = self.pending_file_closes.lock();
        let mut selected = Vec::new();
        let mut index = 0;
        while index < pending.len() {
            if pending[index].table == table {
                selected.push(pending.swap_remove(index));
            } else {
                index += 1;
            }
        }
        selected
    }

    pub fn register_task_exit_subscriber<T>(
        &self,
        task_id: TaskId,
        subscriber: &Arc<T>,
    ) -> Option<TaskKey>
    where
        T: TaskExitSubscriber + 'static,
    {
        let state = self.registry().state.read();
        if let Some(record) = state.tasks.get(&task_id) {
            let task = record.task.key();
            self.exit_subscribers.register(task, subscriber);
            return Some(task);
        }
        let exited = state.zombies.get(&task_id).map(|record| record.zombie.key);
        drop(state);
        if exited.is_some() {
            subscriber.publish_exit();
        }
        exited
    }

    /// Retire one non-final thread from the authoritative task graph. The TID
    /// claim drains only after every captured context releases its thread Arc.
    pub fn exit_thread(
        self: &Arc<Self>,
        context: &KernelContext,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<TaskRevision, KernelOperationError> {
        self.sweep_retired_threads();
        if !Arc::ptr_eq(self, &context.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        let files = context.resources.files();
        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, context.task.key().id)?;
        let record = state
            .tasks
            .get(&context.task.key().id)
            .ok_or(KernelOperationError::ParentExited)?;
        if record.task.key() != context.task.key() {
            return Err(KernelOperationError::ParentExited);
        }
        let exit_participants = context
            .task
            .thread_exit_participants(context.thread.key())
            .map_err(|TaskParticipantError::UnknownThread { .. }| {
                KernelOperationError::UnknownThread(context.thread.key().tid)
            })?;
        if !exit_participants.permits_nonfinal_exit() {
            return Err(KernelOperationError::LastThreadRequiresTaskExit(
                context.thread.key().tid,
            ));
        }
        let tid = context.thread.key().tid;
        if context.task.thread(tid).is_none_or(|thread| {
            thread.key() != context.thread.key() || !Arc::ptr_eq(&thread, &context.thread)
        }) || !record.thread_claims.contains_key(&tid)
        {
            return Err(KernelOperationError::UnknownThread(tid));
        }
        let next = next_revision(record.revision)?;
        state
            .retired_threads
            .try_reserve_exact(1)
            .map_err(|_| KernelOperationError::RetiredThreadCapacity(1))?;
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

        let thread = context
            .task
            .retire_thread(context.thread.key())
            .ok_or(KernelOperationError::UnknownThread(tid))?;
        let record = state
            .tasks
            .get_mut(&context.task.key().id)
            .ok_or(KernelOperationError::ParentExited)?;
        let claim = record
            .thread_claims
            .remove(&tid)
            .ok_or(KernelOperationError::UnknownThread(tid))?;
        record.revision = next;
        if tid == LinuxTid::for_task_leader(context.task.key().id) {
            record.dead_leader = Some(RetiredThreadRecord {
                _key: thread.key(),
                _task: thread.task_key(),
                thread: Arc::downgrade(&thread),
                _claim: claim,
            });
        } else {
            state.retired_threads.push(RetiredThreadRecord {
                _key: thread.key(),
                _task: thread.task_key(),
                thread: Arc::downgrade(&thread),
                _claim: claim,
            });
        }
        drop(state);
        if tid != LinuxTid::for_task_leader(context.task.key().id)
            && let Some(region) = context.task.pid_ns_region()
        {
            let internal = u32::try_from(tid.raw()).unwrap_or_else(|_| {
                carrick_fatal!(
                    "kernel::thread_retirement",
                    "tid exceeds u32 in exit_thread"
                );
            });
            if !region.unregister_reaped(internal) {
                carrick_fatal!(
                    "kernel::thread_retirement",
                    "failed to unregister reaped thread in exit_thread"
                );
            }
        }
        self.retire_file_table_if_unreferenced(&files);
        Ok(next)
    }

    /// Reserve every task identity and revision touched by exit publication.
    /// The backend may stop the task's vCPUs after this succeeds, but irreversible
    /// address-space/ASID retirement follows `PreparedTaskExit::commit`: a rare
    /// allocator abort must never leave a discoverable task without its backend.
    /// Dropping the token restores mutator access without changing task lifecycle
    /// or graph membership.
    pub fn prepare_task_exit(
        self: &Arc<Self>,
        task_id: TaskId,
        status: LinuxWaitStatus,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedTaskExit, KernelOperationError> {
        let task = self
            .registry()
            .state
            .read()
            .tasks
            .get(&task_id)
            .map(|record| record.task.key())
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        self.prepare_task_exit_key(task, status, failpoint)
    }

    pub fn prepare_task_exit_key(
        self: &Arc<Self>,
        task_key: TaskKey,
        status: LinuxWaitStatus,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedTaskExit, KernelOperationError> {
        self.prepare_task_exit_key_for_adopter(task_key, status, None, failpoint)
    }

    /// Reserve an exit that reparents the task's children to one exact live
    /// ancestor instead of the run root. Linux child subreapers use this path:
    /// the dispatcher supplies the nearest inherited subreaper as a generation-
    /// authenticated [`TaskKey`], and the same topology transaction reserves it
    /// with the exiting task and every child.
    pub fn prepare_task_exit_key_with_adopter(
        self: &Arc<Self>,
        task_key: TaskKey,
        status: LinuxWaitStatus,
        adopter: TaskKey,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedTaskExit, KernelOperationError> {
        self.prepare_task_exit_key_for_adopter(task_key, status, Some(adopter), failpoint)
    }

    fn prepare_task_exit_key_for_adopter(
        self: &Arc<Self>,
        task_key: TaskKey,
        status: LinuxWaitStatus,
        explicit_adopter: Option<TaskKey>,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedTaskExit, KernelOperationError> {
        self.sweep_retired_threads();
        let task_id = task_key.id;
        let transaction = self.object_ids().transaction_id()?;
        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some(task_record) = state.tasks.get(&task_id) else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        if task_record.task.key() != task_key {
            return Err(KernelOperationError::StaleTaskGeneration(task_id));
        }
        if task_record.task.lifecycle() == TaskLifecycle::Exiting {
            return Err(KernelOperationError::AlreadyExiting(task_id));
        }
        if state.zombies.contains_key(&task_id) {
            return Err(KernelOperationError::ExitTopologyChanged(task_id));
        }

        let task = Arc::clone(&task_record.task);
        let task_revision = task_record.revision;
        let diagnostic_name = task_record.diagnostic_name.clone();
        // The run's root task is the reparenting authority only while that
        // exact generation is live. HVPatch process threads are joined by the
        // outer runtime after individual process finalizers, so root teardown
        // can race a descendant's final Kernel publication. Once root has
        // already become a zombie, the descendant is an orphan with no live
        // adopter; targeting the retired root would make terminal cleanup fail
        // closed after the guest process has already exited.
        let adopter = if let Some(adopter_key) = explicit_adopter {
            let adopter_record = state
                .tasks
                .get(&adopter_key.id)
                .ok_or(KernelOperationError::UnknownTask(adopter_key.id))?;
            if adopter_record.task.key() != adopter_key {
                return Err(KernelOperationError::StaleTaskGeneration(adopter_key.id));
            }
            if adopter_record.task.lifecycle() != TaskLifecycle::Live {
                return Err(KernelOperationError::UnknownTask(adopter_key.id));
            }

            // An adopter must already be in the exiting task's authoritative
            // ancestry. This rejects accidental child/self adoption, which
            // would introduce a cycle when the children are published below.
            let mut ancestor = task.parent();
            let mut authenticated = false;
            while let Some(ancestor_key) = ancestor {
                if ancestor_key == adopter_key {
                    authenticated = true;
                    break;
                }
                let ancestor_record = state
                    .tasks
                    .get(&ancestor_key.id)
                    .filter(|record| record.task.key() == ancestor_key)
                    .ok_or(KernelOperationError::ExitTopologyChanged(ancestor_key.id))?;
                ancestor = ancestor_record.task.parent();
            }
            if !authenticated {
                return Err(KernelOperationError::ExitTopologyChanged(adopter_key.id));
            }
            Some(adopter_key)
        } else {
            let init = state.container_inits.get(&task.container().id()).copied();
            init.filter(|init| *init != task_key).and_then(|init| {
                state.tasks.get(&init.id).and_then(|record| {
                    (record.task.key() == init && record.task.lifecycle() == TaskLifecycle::Live)
                        .then(|| record.task.key())
                })
            })
        };
        // The namespace's reparenting authority, independent of whether THIS
        // exit has anything to reparent. `adopter` below is additionally
        // filtered to "not self" and "has children", which makes it useless as
        // an answer to "could anything in this namespace still have adopted an
        // orphan?" — the question a zombie's reaper depends on.
        let namespace_init = state
            .container_inits
            .get(&task.container().id())
            .copied()
            .filter(|init| {
                *init == task_key
                    || state.tasks.get(&init.id).is_some_and(|record| {
                        record.task.key() == *init && record.task.lifecycle() == TaskLifecycle::Live
                    })
            });
        let mut children = task.children();
        children.sort_by_key(|child| child.serial);
        // The adopter is only a participant when there is something to
        // reparent. A childless exit changes no parent edge on it, so it is
        // neither reserved nor revision-bumped: otherwise every leaf exit in
        // the VM contends with the run root's own in-flight fork/exec
        // reservations, and a concurrent `reserve_fork` on root observes
        // `TaskBusy` for an exit that never touches it. The adopter above was
        // still validated so a stale explicit adopter fails closed.
        let adopter = adopter.filter(|_| !children.is_empty());

        let mut reserved_ids = BTreeSet::from([task_id]);
        let mut affected_revisions = BTreeMap::new();
        for child_key in &children {
            reserved_ids.insert(child_key.id);
            if let Some(child) = state.tasks.get(&child_key.id) {
                if child.task.key() != *child_key {
                    return Err(KernelOperationError::ExitTopologyChanged(child_key.id));
                }
                affected_revisions.insert(
                    child_key.id,
                    (child.revision, next_revision(child.revision)?),
                );
            } else if state
                .zombies
                .get(&child_key.id)
                .is_none_or(|child| child.zombie.key != *child_key)
            {
                return Err(KernelOperationError::ExitTopologyChanged(child_key.id));
            }
        }

        let prepared_adopter_children = if let Some(adopter_key) = adopter {
            reserved_ids.insert(adopter_key.id);
            let adopter_record = state
                .tasks
                .get(&adopter_key.id)
                .filter(|record| record.task.key() == adopter_key)
                .ok_or(KernelOperationError::ExitTopologyChanged(adopter_key.id))?;
            affected_revisions.insert(
                adopter_key.id,
                (
                    adopter_record.revision,
                    next_revision(adopter_record.revision)?,
                ),
            );
            let mut prepared = adopter_record.task.children_set();
            prepared.extend(children.iter().copied());
            Some(prepared)
        } else {
            None
        };

        let namespace_process_group = state
            .process_groups
            .get(&task.process_group())
            .filter(|group| group.container == task.container().id())
            .map(|group| group.namespace_id)
            .ok_or(KernelOperationError::ExitTopologyChanged(task_id))?;
        let namespace_session = state
            .sessions
            .get(&task.session())
            .filter(|session| session.container == task.container().id())
            .map(|session| session.namespace_id)
            .ok_or(KernelOperationError::ExitTopologyChanged(task_id))?;
        let registry_zombie = Zombie::from_task(
            &task,
            status,
            diagnostic_name,
            namespace_process_group,
            namespace_session,
        );
        let result_zombie = registry_zombie.clone();
        let task_ids: Vec<_> = reserved_ids.into_iter().collect();
        let reservation = TaskSetReservation::acquired(self, &mut state, task_ids, transaction)?;
        drop(state);
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;
        Ok(PreparedTaskExit {
            reservation,
            task: task_key,
            task_revision,
            children,
            affected_revisions,
            adopter,
            prepared_adopter_children,
            namespace_init,
            registry_zombie,
            result_zombie,
        })
    }

    /// Publish a prepared task exit after vCPU drain and before irreversible
    /// backend retirement. All expected operational failure is resolved by
    /// `prepare_task_exit`; errors here denote an internal breach of the
    /// reservation contract, not a guest-visible retry condition.
    pub(crate) fn commit_task_exit(
        &self,
        prepared: PreparedTaskExit,
    ) -> Result<Zombie, KernelOperationError> {
        self.commit_task_exit_notifying(prepared, |_| {})
    }

    pub(crate) fn commit_task_exit_notifying(
        &self,
        mut prepared: PreparedTaskExit,
        notify_parent: impl FnOnce(Option<TaskKey>),
    ) -> Result<Zombie, KernelOperationError> {
        // Read before the zombie is moved into the registry below: the auditor
        // is told who will consume it, and that judgement belongs to the same
        // reserved snapshot that chose the adopter.
        let zombie_reaper = prepared.zombie_reaper();
        let mut state = self.registry().state.write();
        prepared.reservation.validate(&state)?;
        let Some(exiting_record) = state.tasks.get(&prepared.task.id) else {
            return Err(KernelOperationError::ExitTopologyChanged(prepared.task.id));
        };
        if exiting_record.task.key() != prepared.task
            || exiting_record.revision != prepared.task_revision
            || exiting_record.task.lifecycle() != TaskLifecycle::Live
        {
            return Err(KernelOperationError::ExitTopologyChanged(prepared.task.id));
        }
        for (affected_id, (expected, _)) in &prepared.affected_revisions {
            let Some(affected) = state.tasks.get(affected_id) else {
                return Err(KernelOperationError::ExitTopologyChanged(*affected_id));
            };
            if affected.revision != *expected {
                return Err(KernelOperationError::ExitTopologyChanged(*affected_id));
            }
        }
        for child_key in &prepared.children {
            let live_matches = state
                .tasks
                .get(&child_key.id)
                .is_some_and(|record| record.task.key() == *child_key);
            let zombie_matches = state
                .zombies
                .get(&child_key.id)
                .is_some_and(|record| record.zombie.key == *child_key);
            if !live_matches && !zombie_matches {
                return Err(KernelOperationError::ExitTopologyChanged(child_key.id));
            }
        }
        // ptrace(2): a tracer's exit detaches every tracee it still owns, and
        // a detached stopped tracee resumes. Capture the tracer key before
        // `begin_exit` clears this task's own tracee-side record so the tracer
        // can drop its index entry and re-evaluate a wait on this task.
        let own_tracer = exiting_record.task.ptrace_tracer();
        if !exiting_record.task.begin_exit() {
            return Err(KernelOperationError::AlreadyExiting(prepared.task.id));
        }
        let mut released_tracees = Vec::new();
        for tracee_key in exiting_record.task.take_ptrace_tracees() {
            if let Some(tracee) = state
                .tasks
                .get(&tracee_key.id)
                .filter(|record| record.task.key() == tracee_key)
                .map(|record| Arc::clone(&record.task))
                && tracee.detach_from_ptrace(prepared.task)
            {
                released_tracees.push(tracee);
            }
        }
        let own_tracer = own_tracer.and_then(|key| {
            state
                .tasks
                .get(&key.id)
                .filter(|record| record.task.key() == key)
                .map(|record| Arc::clone(&record.task))
        });
        if let Some(tracer) = &own_tracer {
            tracer.remove_ptrace_tracee(prepared.task);
        }
        let mut exiting_threads = Vec::new();
        let mut exiting_file_tables = Vec::new();
        for thread_key in exiting_record.task.thread_keys() {
            if let Some(thread) = exiting_record.task.thread(thread_key.tid) {
                let files = thread.resources().files();
                if !exiting_file_tables
                    .iter()
                    .any(|observed| Arc::ptr_eq(observed, &files))
                {
                    exiting_file_tables.push(files);
                }
                exiting_threads.push(thread);
            }
        }

        let record = state
            .tasks
            .remove(&prepared.task.id)
            .ok_or(KernelOperationError::ExitTopologyChanged(prepared.task.id))?;
        let TaskRecord {
            task,
            revision: _,
            task_claim,
            thread_claims,
            dead_leader,
            vfork_release,
            has_execed: _,
            diagnostic_name: _,
        } = record;
        let leader_tid = LinuxTid::for_task_leader(task.key().id);
        let pid_region = task.pid_ns_region();
        let mut retired_secondary_namespace_tids = Vec::new();
        for (tid, claim) in thread_claims {
            if tid != leader_tid {
                retired_secondary_namespace_tids.push(u32::try_from(tid.raw()).unwrap_or_else(
                    |_| {
                        carrick_fatal!(
                            "kernel::task_exit_identity",
                            "secondary tid exceeds u32 in commit_task_exit_notifying"
                        );
                    },
                ));
            }
            if let Some(thread) = task.thread(tid) {
                state
                    .retired_threads
                    .push(super::core::RetiredThreadRecord {
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

        for child_key in &prepared.children {
            if let Some(child) = state.tasks.get(&child_key.id) {
                child.task.reparent(prepared.adopter);
            } else if let Some(child) = state.zombies.get_mut(&child_key.id) {
                child.zombie.parent = prepared.adopter;
            }
        }
        if let (Some(adopter_key), Some(children)) =
            (prepared.adopter, prepared.prepared_adopter_children.take())
            && let Some(adopter_record) = state.tasks.get(&adopter_key.id)
        {
            adopter_record.task.publish_prepared_children(children);
        }
        for (affected_id, (_, published)) in &prepared.affected_revisions {
            if let Some(affected) = state.tasks.get_mut(affected_id) {
                affected.revision = *published;
            }
        }

        let process_group = task.process_group();
        let session = task.session();
        remove_group_member(&mut state, process_group, session, prepared.task);
        state.zombies.insert(
            prepared.task.id,
            ZombieRecord {
                zombie: prepared.registry_zombie,
                _task_claim: task_claim,
            },
        );
        // Detach this exact task generation's watchers before the zombie can
        // be consumed and its numeric claim eventually reused. Callbacks stay
        // outside the registry lock, but a later generation can no longer be
        // mistaken for this exit.
        let subscribers = self.exit_subscribers.take(prepared.task);
        drop(state);
        let mut state = self.registry().state.write();
        let pending_publication = prepared.reservation.commit(&mut state)?;
        drop(state);
        pending_publication.publish();
        self.auditors().zombie_created(prepared.task, zombie_reaper);
        if self.registry().state.read().tasks.is_empty() {
            self.auditors().process_graph_empty(self.unpublished_jobs());
        }
        if let Some(region) = pid_region {
            for tid in retired_secondary_namespace_tids {
                if !region.unregister_reaped(tid) {
                    carrick_fatal!(
                        "kernel::task_exit_identity",
                        "failed to unregister reaped secondary thread"
                    );
                }
            }
        }
        // Cancellation can wake a host waiter, whose callback may re-enter the
        // registry. Never invoke it while holding the topology write lock.
        for thread in exiting_threads {
            let _ = thread.cancel_kernel_owned_continuation(
                crate::vcpu_loop::continuation::CancellationCause::ProcessExit,
            );
        }
        // Queue the parent's exit notification after the exit reservation is
        // committed. If notify_parent ran before commit, a parent that woke
        // immediately would see TaskBusy in wait_child_matching and park in
        // BlockedContinuation having already consumed this exit's wake edge,
        // wedging forever.
        notify_parent(prepared.result_zombie.parent);
        for tracee in released_tracees {
            tracee.wake();
        }
        if let Some(tracer) = own_tracer {
            tracer.wake();
        }
        for files in &exiting_file_tables {
            self.retire_file_table_if_unreferenced(files);
        }
        if let Some(release) = vfork_release {
            release.release(VforkReleaseReason::Exit);
        }
        for subscriber in subscribers
            .into_iter()
            .filter_map(|subscriber| subscriber.upgrade())
        {
            subscriber.publish_exit();
        }
        Ok(prepared.result_zombie)
    }

    /// Convenience path for model callers without an external backend teardown.
    pub fn exit_task(
        self: &Arc<Self>,
        task_id: TaskId,
        status: LinuxWaitStatus,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<Zombie, KernelOperationError> {
        self.prepare_task_exit(task_id, status, failpoint)?.commit()
    }

    /// Publish terminal state for one exact task generation, waiting on the
    /// Kernel's reservation-change event for transient fork/exec/exit overlap.
    /// Re-observation of the same exact zombie is idempotent; a reused numeric
    /// PID with another serial is never mutated.
    pub fn exit_task_key_eventually(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
    ) -> Result<Zombie, KernelOperationError> {
        self.exit_task_key_eventually_for_adopter(task, status, None)
    }

    /// Publish terminal state and reparent children to one exact live ancestor,
    /// waiting through overlapping topology reservations just like the default
    /// run-root adoption path.
    pub fn exit_task_key_eventually_with_adopter(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        adopter: TaskKey,
    ) -> Result<Zombie, KernelOperationError> {
        self.exit_task_key_eventually_for_adopter(task, status, Some(adopter))
    }

    fn exit_task_key_eventually_for_adopter(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        adopter: Option<TaskKey>,
    ) -> Result<Zombie, KernelOperationError> {
        self.exit_task_key_eventually_for_adopter_notifying(task, status, adopter, |_| {})
    }

    /// Publish terminal state while queueing the exact parent's notification
    /// after committing the exit reservation.
    pub fn exit_task_key_eventually_notifying(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        adopter: Option<TaskKey>,
        notify_parent: impl FnOnce(Option<TaskKey>),
    ) -> Result<Zombie, KernelOperationError> {
        self.exit_task_key_eventually_for_adopter_notifying(task, status, adopter, notify_parent)
    }

    fn exit_task_key_eventually_for_adopter_notifying(
        self: &Arc<Self>,
        task: TaskKey,
        status: LinuxWaitStatus,
        adopter: Option<TaskKey>,
        notify_parent: impl FnOnce(Option<TaskKey>),
    ) -> Result<Zombie, KernelOperationError> {
        let mut notify_parent = Some(notify_parent);
        loop {
            let observed = self.reservation_epoch();
            match self.prepare_task_exit_key_for_adopter(task, status, adopter, None) {
                Ok(prepared) => {
                    let Some(notify_parent) = notify_parent.take() else {
                        return Err(KernelOperationError::StaleReservation);
                    };
                    return prepared.commit_notifying(notify_parent);
                }
                Err(KernelOperationError::TaskBusy(_)) => {
                    self.wait_for_reservation_change(observed);
                }
                Err(KernelOperationError::UnknownTask(_)) => {
                    let state = self.registry().state.read();
                    if let Some(zombie) = state
                        .zombies
                        .get(&task.id)
                        .filter(|record| record.zombie.key == task)
                    {
                        return Ok(zombie.zombie.clone());
                    }
                    if state
                        .tasks
                        .get(&task.id)
                        .is_some_and(|record| record.task.key() != task)
                        || state
                            .zombies
                            .get(&task.id)
                            .is_some_and(|record| record.zombie.key != task)
                    {
                        return Err(KernelOperationError::StaleTaskGeneration(task.id));
                    }
                    return Err(KernelOperationError::UnknownTask(task.id));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::clone_plan::ClonePlan;
    use crate::kernel::objects::{LinuxWaitStatus, TaskParticipantError};
    use crate::kernel::operations::tests::{CountingExitSubscriber, bootstrap};
    use crate::kernel::operations::{WaitMode, WaitOutcome};

    fn clone_sibling(
        kernel: &Arc<Kernel>,
        leader: &KernelContext,
        registry_id: i32,
    ) -> KernelContext {
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread clone plan");
        kernel
            .clone_thread(
                leader,
                plan,
                ThreadId::synthetic_for_tests(registry_id),
                None,
            )
            .expect("clone sibling")
    }

    #[test]
    fn task_mints_distinct_fork_and_crash_sibling_witnesses() {
        let (kernel, leader) = bootstrap(19_410);
        let sibling = clone_sibling(&kernel, &leader, 19_411);
        let second_sibling = clone_sibling(&kernel, &leader, 19_412);

        let fork = leader
            .task()
            .fork_barrier_participants(leader.thread().key())
            .expect("exact fork owner");
        let crash = leader
            .task()
            .crash_barrier_participants(leader.thread().key())
            .expect("exact crash owner");

        assert!(fork.requires_quiesce());
        assert!(fork.contains_sibling(sibling.thread().key()));
        assert!(fork.contains_sibling(second_sibling.thread().key()));
        assert_eq!(fork.initial_sibling_count_for_probe(), 2);
        assert!(crash.requires_quiesce());
        assert!(crash.contains_sibling(sibling.thread().key()));
        assert!(crash.contains_sibling(second_sibling.thread().key()));
        assert_eq!(
            leader
                .task()
                .core_note_participants()
                .required_note_count_for_probe(),
            3
        );
    }

    #[test]
    fn task_participant_witness_rejects_a_stale_exact_owner() {
        let (kernel, leader) = bootstrap(19_420);
        let sibling = clone_sibling(&kernel, &leader, 19_421);
        kernel.exit_thread(&sibling, None).expect("retire sibling");

        assert!(matches!(
            leader
                .task()
                .fork_barrier_participants(sibling.thread().key()),
            Err(TaskParticipantError::UnknownThread { .. })
        ));
    }

    #[test]
    fn thread_exit_participants_require_an_exact_survivor() {
        let (kernel, leader) = bootstrap(19_430);
        let sibling = clone_sibling(&kernel, &leader, 19_431);
        let witness = leader
            .task()
            .thread_exit_participants(leader.thread().key())
            .expect("exact exit owner");

        assert!(witness.permits_nonfinal_exit());
        assert!(witness.contains_survivor(sibling.thread().key()));

        let (_sole_kernel, sole) = bootstrap(19_432);
        let sole_witness = sole
            .task()
            .thread_exit_participants(sole.thread().key())
            .expect("exact sole owner");
        assert!(!sole_witness.permits_nonfinal_exit());
    }

    #[test]
    fn task_exit_subscribers_observe_live_zombie_and_unknown_targets() {
        let (kernel, root) = bootstrap(75);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_075),
                "child".to_string(),
                None,
            )
            .expect("child");
        let child_id = child.task.key().id;
        let live = Arc::new(CountingExitSubscriber::default());
        assert!(kernel.task_is_live(child_id));
        assert!(kernel.task_exists(child_id));
        assert_eq!(
            kernel.register_task_exit_subscriber(child_id, &live),
            Some(child.task.key())
        );
        assert_eq!(live.0.load(Ordering::Acquire), 0);

        kernel
            .exit_task(child_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("child exit");
        assert!(!kernel.task_is_live(child_id));
        assert!(kernel.task_exists(child_id));
        assert_eq!(live.0.load(Ordering::Acquire), 1);

        let zombie = Arc::new(CountingExitSubscriber::default());
        assert_eq!(
            kernel.register_task_exit_subscriber(child_id, &zombie),
            Some(child.task.key())
        );
        assert_eq!(zombie.0.load(Ordering::Acquire), 1);
        let unknown = Arc::new(CountingExitSubscriber::default());
        let unknown_id = TaskId::for_root_bootstrap(9_999).expect("unknown task");
        assert_eq!(
            kernel.register_task_exit_subscriber(unknown_id, &unknown),
            None
        );
        assert_eq!(unknown.0.load(Ordering::Acquire), 0);
    }

    #[test]
    fn child_exit_receipt_uses_parent_committed_during_reservation_wait() {
        let (kernel, root) = bootstrap(77);
        let parent = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_078),
                "parent".to_string(),
                None,
            )
            .expect("parent");
        let child = kernel
            .fork_task(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_079),
                "child".to_string(),
                None,
            )
            .expect("child");
        let prepared_parent = kernel
            .prepare_task_exit_key(
                parent.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare parent exit");
        let exiting_kernel = Arc::clone(&kernel);
        let child_key = child.task().key();
        let child_exit = std::thread::spawn(move || {
            exiting_kernel
                .exit_task_key_eventually(child_key, LinuxWaitStatus::from_wait_encoding(0))
        });
        prepared_parent.commit().expect("commit parent exit");
        let zombie = child_exit
            .join()
            .expect("child exit thread")
            .expect("child exit");
        assert_eq!(zombie.parent, Some(root.task().key()));
        assert_ne!(zombie.parent, Some(parent.task().key()));
    }

    #[test]
    fn a_zombie_left_behind_by_its_namespace_init_names_container_retirement() {
        let (kernel, root) = bootstrap(501);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let probe = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(9_501),
                "probe".to_string(),
                None,
            )
            .expect("probe");
        let child = kernel
            .fork_task(
                &probe,
                fork_plan,
                ThreadId::synthetic_for_tests(9_502),
                "child".to_string(),
                None,
            )
            .expect("child");
        let grandchild = kernel
            .fork_task(
                &child,
                fork_plan,
                ThreadId::synthetic_for_tests(9_503),
                "grandchild".to_string(),
                None,
            )
            .expect("grandchild");

        // The child exits first: the grandchild reparents to the namespace
        // init, which is exactly what Linux does and what the probe expects.
        let child_zombie = kernel
            .exit_task_key_eventually(child.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("child exit");
        assert_eq!(child_zombie.parent, Some(probe.task().key()));
        assert_eq!(grandchild.task().parent(), Some(root.task().key()));

        // A live namespace init adopting an orphan is the reapable case.
        let prepared_probe = kernel
            .prepare_task_exit_key(
                probe.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare probe exit");
        assert_eq!(
            prepared_probe.zombie_reaper(),
            crate::observe::ZombieReaper::Parent(root.task().key())
        );
        prepared_probe.commit().expect("commit probe exit");

        // The namespace init itself has no parent, and nothing inside the
        // namespace could ever have adopted it.
        let prepared_init = kernel
            .prepare_task_exit_key(
                root.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare init exit");
        assert_eq!(
            prepared_init.zombie_reaper(),
            crate::observe::ZombieReaper::ContainerRetirement
        );
        prepared_init.commit().expect("commit init exit");

        // The grandchild outlived the init, so it is parentless too — and is
        // reaped by container retirement, not stranded.
        assert_eq!(grandchild.task().parent(), None);
        let prepared_grandchild = kernel
            .prepare_task_exit_key(
                grandchild.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare grandchild exit");
        assert_eq!(
            prepared_grandchild.zombie_reaper(),
            crate::observe::ZombieReaper::ContainerRetirement
        );
        let grandchild_zombie = prepared_grandchild
            .commit()
            .expect("commit grandchild exit");
        assert_eq!(grandchild_zombie.parent, None);
    }

    #[test]
    fn explicit_subreaper_adopts_orphans_at_exit_publication() {
        let (kernel, root) = bootstrap(78);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let subreaper = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(9_080),
                "subreaper".to_string(),
                None,
            )
            .expect("subreaper");
        let parent = kernel
            .fork_task(
                &subreaper,
                fork_plan,
                ThreadId::synthetic_for_tests(9_081),
                "parent".to_string(),
                None,
            )
            .expect("parent");
        let child = kernel
            .fork_task(
                &parent,
                fork_plan,
                ThreadId::synthetic_for_tests(9_082),
                "orphan".to_string(),
                None,
            )
            .expect("orphan");

        let zombie = kernel
            .exit_task_key_eventually_with_adopter(
                parent.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                subreaper.task().key(),
            )
            .expect("parent exit through exact subreaper");

        assert_eq!(zombie.parent, Some(subreaper.task().key()));
        assert_eq!(child.task().parent(), Some(subreaper.task().key()));
        assert_eq!(kernel.validate_invariants(), Ok(()));
    }

    #[test]
    fn exit_notification_runs_after_reservation_release() {
        let (kernel, root) = bootstrap(79);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_083),
                "signal-before-wait".to_string(),
                None,
            )
            .expect("child");
        let hook_epoch = std::sync::atomic::AtomicU64::new(0);

        kernel
            .exit_task_key_eventually_notifying(
                child.task().key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
                |parent| {
                    assert_eq!(parent, Some(root.task().key()));
                    hook_epoch.store(kernel.reservation_epoch(), Ordering::Release);
                },
            )
            .expect("child exit");

        assert_ne!(hook_epoch.load(Ordering::Acquire), 0);
        assert_eq!(
            kernel.reservation_epoch(),
            hook_epoch.load(Ordering::Acquire),
            "parent notification hook must run after the exit reservation is committed",
        );
    }

    #[test]
    fn root_exit_before_descendant_exit_allows_orphan_teardown() {
        let (kernel, root) = bootstrap(78);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_080),
                "root-orphan".to_string(),
                None,
            )
            .expect("child");

        let root_zombie = kernel
            .exit_task_key_eventually(root.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("root exit");
        assert_eq!(root_zombie.parent, None);
        assert_eq!(child.task().parent(), None);

        let child_zombie = kernel
            .exit_task_key_eventually(child.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("orphan exit after root");
        assert_eq!(child_zombie.parent, None);
    }

    #[test]
    fn childless_exit_does_not_reserve_the_root_adopter() {
        let (kernel, root) = bootstrap(339);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let leaf = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(3391),
                "leaf".to_string(),
                None,
            )
            .expect("leaf child");
        let middle = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(3392),
                "middle".to_string(),
                None,
            )
            .expect("middle child");
        let _grandchild = kernel
            .fork_task(
                &middle,
                plan,
                ThreadId::synthetic_for_tests(3393),
                "grandchild".to_string(),
                None,
            )
            .expect("grandchild");

        // Root is mid-fork: its task is reserved by the in-flight operation.
        let in_flight = kernel
            .reserve_fork(&root, plan, "in-flight root fork".to_string(), None)
            .expect("root fork reservation");

        let leaf_exit = kernel
            .prepare_task_exit_key(
                leaf.task.key(),
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("a childless exit needs no adopter and must not wait on root");
        drop(leaf_exit);

        assert!(
            matches!(
                kernel.prepare_task_exit_key(
                    middle.task.key(),
                    LinuxWaitStatus::from_wait_encoding(0),
                    None,
                ),
                Err(KernelOperationError::TaskBusy(id)) if id == root.task.key().id
            ),
            "an exit that reparents children still reserves the adopter"
        );
        drop(in_flight);
    }

    #[test]
    fn exact_generation_exit_waits_for_reservation_release_and_is_idempotent() {
        let (kernel, root) = bootstrap(336);
        let task = root.task().key();
        let prepared_fork = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
                "reservation holder".to_owned(),
                None,
            )
            .unwrap()
            .prepare_reference(ThreadId::synthetic_for_tests(337))
            .unwrap();

        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
        let exiting = Arc::clone(&kernel);
        let handle = std::thread::spawn(move || {
            let result = exiting
                .exit_task_key_eventually(task, LinuxWaitStatus::from_wait_encoding(17 << 8));
            done_tx.send(result).unwrap();
        });
        kernel.wait_for_reservation_waiter_for_tests();
        assert!(matches!(
            done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        drop(prepared_fork);
        let zombie = done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("reservation release wakes terminal retry")
            .expect("exact-generation exit succeeds");
        handle.join().unwrap();
        assert_eq!(zombie.key, task);
        assert_eq!(zombie.status.raw(), 17 << 8);

        let repeated = kernel
            .exit_task_key_eventually(task, LinuxWaitStatus::from_wait_encoding(99 << 8))
            .expect("exact zombie makes repeated cleanup idempotent");
        assert_eq!(repeated.key, task);
        assert_eq!(repeated.status.raw(), 17 << 8);
    }

    #[test]
    fn prepared_task_exit_reserves_affected_graph_and_drop_unlocks_it() {
        let (kernel, root) = bootstrap(340);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let parent = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(341),
                "parent".to_owned(),
                None,
            )
            .expect("parent");
        let live_child = kernel
            .fork_task(
                &parent,
                plan,
                ThreadId::synthetic_for_tests(342),
                "live child".to_owned(),
                None,
            )
            .expect("live child");
        let refreshed_parent = kernel
            .context(parent.task.key().id, parent.thread.key().tid)
            .expect("refreshed parent");
        let zombie_child = kernel
            .fork_task(
                &refreshed_parent,
                plan,
                ThreadId::synthetic_for_tests(343),
                "zombie child".to_owned(),
                None,
            )
            .expect("zombie child");
        kernel
            .exit_task(
                zombie_child.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("zombie child exit");

        let prepared = kernel
            .prepare_task_exit(
                parent.task.key().id,
                LinuxWaitStatus::from_wait_encoding(7 << 8),
                None,
            )
            .expect("prepare parent exit");
        assert_eq!(kernel.validate_invariants(), Ok(()));
        for reserved in [
            root.task.key().id,
            parent.task.key().id,
            live_child.task.key().id,
            zombie_child.task.key().id,
        ] {
            assert!(matches!(
                kernel.create_process_group(reserved, None),
                Err(KernelOperationError::TaskBusy(id)) if id == reserved
            ));
        }
        assert!(matches!(
            kernel.wait_child(
                parent.task.key().id,
                Some(zombie_child.task.key().id),
                WaitMode::Consume,
            ),
            Err(KernelOperationError::TaskBusy(id)) if id == parent.task.key().id
        ));

        drop(prepared);
        assert!(matches!(
            kernel.wait_child(
                parent.task.key().id,
                Some(zombie_child.task.key().id),
                WaitMode::Consume,
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        assert!(!matches!(
            kernel.create_process_group(live_child.task.key().id, None),
            Err(KernelOperationError::TaskBusy(_))
        ));
    }

    #[test]
    fn prepared_task_exit_publishes_reparenting_and_subscriber_once() {
        let (kernel, root) = bootstrap(345);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let parent = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(346),
                "parent".to_owned(),
                None,
            )
            .expect("parent");
        let child = kernel
            .fork_task(
                &parent,
                plan,
                ThreadId::synthetic_for_tests(347),
                "child".to_owned(),
                None,
            )
            .expect("child");
        let subscriber = Arc::new(CountingExitSubscriber::default());
        assert_eq!(
            kernel.register_task_exit_subscriber(parent.task.key().id, &subscriber),
            Some(parent.task.key())
        );

        let prepared = kernel
            .prepare_task_exit(
                parent.task.key().id,
                LinuxWaitStatus::from_wait_encoding(9 << 8),
                None,
            )
            .expect("prepare parent exit");
        assert!(kernel.task_is_live(parent.task.key().id));
        assert_eq!(subscriber.0.load(Ordering::Acquire), 0);
        let zombie = prepared.commit().expect("commit parent exit");

        assert_eq!(zombie.status, LinuxWaitStatus::from_wait_encoding(9 << 8));
        assert_eq!(subscriber.0.load(Ordering::Acquire), 1);
        assert!(!kernel.task_is_live(parent.task.key().id));
        assert_eq!(
            kernel
                .task_identity(child.task.key().id)
                .expect("reparented child")
                .parent,
            Some(root.task.key())
        );
        assert!(matches!(
            kernel.wait_child(
                root.task.key().id,
                Some(parent.task.key().id),
                WaitMode::Observe,
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        let after_exit = Arc::new(CountingExitSubscriber::default());
        assert_eq!(
            kernel.register_task_exit_subscriber(parent.task.key().id, &after_exit),
            Some(parent.task.key())
        );
        assert_eq!(after_exit.0.load(Ordering::Acquire), 1);
        assert_eq!(subscriber.0.load(Ordering::Acquire), 1);
    }

    #[test]
    fn exiting_parent_reparents_live_and_zombie_children_to_root() {
        let (kernel, root) = bootstrap(395);
        let parent = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(396),
                "parent".to_string(),
                None,
            )
            .expect("parent");
        let grandchild = kernel
            .fork_task(
                &parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(397),
                "grandchild".to_string(),
                None,
            )
            .expect("grandchild");
        let grandchild_id = grandchild.task.key().id;
        let refreshed_parent = kernel
            .context(parent.task.key().id, parent.thread.key().tid)
            .expect("refreshed parent");
        let live_grandchild = kernel
            .fork_task(
                &refreshed_parent,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(398),
                "live grandchild".to_string(),
                None,
            )
            .expect("live grandchild");
        let parent_id = parent.task.key().id;
        drop(grandchild);

        kernel
            .exit_task(grandchild_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("grandchild exit");
        kernel
            .exit_task(parent_id, LinuxWaitStatus::from_wait_encoding(0), None)
            .expect("parent exit");

        let zombie = kernel
            .registry()
            .zombie(grandchild_id)
            .expect("reparented zombie");
        assert_eq!(zombie.parent, Some(root.task.key()));
        assert_eq!(live_grandchild.task.parent(), Some(root.task.key()));
        let descendant = kernel
            .fork_task(
                &live_grandchild,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(399),
                "reparented descendant".to_string(),
                None,
            )
            .expect("ordinary fork does not inherit the caller's parent association");
        assert_eq!(descendant.task.parent(), Some(live_grandchild.task.key()));
        assert!(matches!(
            kernel.fork_task(
                &live_grandchild,
                ClonePlan::from_flags(LinuxCloneFlags::PARENT).expect("CLONE_PARENT plan"),
                ThreadId::synthetic_for_tests(400),
                "stale CLONE_PARENT descendant".to_string(),
                None,
            ),
            Err(KernelOperationError::StaleContext)
        ));
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(grandchild_id), WaitMode::Consume),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        assert!(!kernel.ids().is_reserved_number(grandchild_id.raw()));
    }
}
