use std::sync::Arc;

use carrick_hal::ThreadId;

use super::clone_plan::{ClonePlan, CloneTaskMode};
use super::core::{
    Kernel, KernelContext, KernelDomain, ProcessGroupRecord, RegistryState, SessionRecord,
    TaskRecord, TaskRevision, ZombieRecord,
};
use super::ids::{LinuxTid, ObjectIdError, ProcessGroupId, SessionId, TaskId};
use super::objects::{
    LinuxWaitStatus, ObjectGraphError, ProcessGroup, Session, Task, TaskKey, TaskRusage,
    TaskShared, TaskSharedCloneError, ThreadKey, ThreadResources, Zombie,
};
use super::registry::IdError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelFailpoint {
    AfterReserve,
    AfterObjects,
    AfterBackendPrepare,
    BeforePublish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitMode {
    Observe,
    Consume,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WaitOutcome {
    Exited(Zombie),
    StillRunning,
    NoChild,
}

/// Typed permission to prepare work against one exact task topology revision.
#[derive(Debug)]
pub struct TaskOperationReservation {
    domain: Arc<KernelDomain>,
    task: TaskKey,
    revision: TaskRevision,
}

impl TaskOperationReservation {
    pub const fn task(&self) -> TaskKey {
        self.task
    }

    pub const fn revision(&self) -> TaskRevision {
        self.revision
    }
}

impl Kernel {
    /// Prepare a new Linux task outside the registry lock, then publish every
    /// registry/backlink change under one write-lock commit.
    pub fn fork_task(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
        child_registry_id: ThreadId,
        diagnostic_name: String,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<KernelContext, KernelOperationError> {
        self.sweep_retired_threads();
        if !Arc::ptr_eq(self, &parent.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        if plan.task() != CloneTaskMode::NewTask {
            return Err(KernelOperationError::ExpectedNewTask);
        }

        let (child_id, task_reservation) = self.ids().reserve_task()?;
        let leader_claim = self.ids().claim_task_leader_thread(child_id)?;
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;

        let child_shared = Arc::new(TaskShared::for_new_task(
            &parent.shared,
            plan,
            self.object_ids(),
        )?);
        let child_resources = Arc::new(ThreadResources::for_clone(
            &parent.resources,
            plan,
            self.object_ids(),
        )?);
        let child_key = TaskKey {
            id: child_id,
            serial: self.object_ids().task_serial()?,
        };
        let child = Arc::new(Task::new(
            child_key,
            Some(parent.task.key()),
            parent.task.process_group(),
            parent.task.session(),
            Arc::clone(&child_shared),
        ));
        let leader_tid = LinuxTid::for_task_leader(child_id);
        let leader = child.attach_fork_thread(
            ThreadKey {
                tid: leader_tid,
                serial: self.object_ids().thread_serial()?,
            },
            child_registry_id,
            Arc::clone(&child_resources),
            parent.thread.signal_state(),
        )?;
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        {
            let mut state = self.registry().state.write();
            ensure_task_unreserved(&state, parent.task.key().id)?;
            let Some(parent_record) = state.tasks.get(&parent.task.key().id) else {
                return Err(KernelOperationError::ParentExited);
            };
            if parent_record.task.key() != parent.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            if parent_record.revision != parent.revision {
                return Err(KernelOperationError::StaleContext);
            }
            let next_parent_revision = next_revision(parent_record.revision)?;
            let process_group = child.process_group();
            let session = child.session();
            if !state.process_groups.contains_key(&process_group)
                || !state.sessions.contains_key(&session)
            {
                return Err(KernelOperationError::IdentityObjectMissing);
            }
            check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

            let task_claim = task_reservation.commit();
            parent.task.add_child(child_key);
            if let Some(group) = state.process_groups.get_mut(&process_group) {
                group.members.insert(child_key);
            }
            state.tasks.insert(
                child_id,
                TaskRecord {
                    task: Arc::clone(&child),
                    revision: TaskRevision::INITIAL,
                    task_claim,
                    thread_claims: std::collections::BTreeMap::from([(leader_tid, leader_claim)]),
                    diagnostic_name,
                },
            );
            if let Some(parent_record) = state.tasks.get_mut(&parent.task.key().id) {
                parent_record.revision = next_parent_revision;
            }
        }

        Ok(KernelContext::from_parts(
            self.clone(),
            child,
            leader,
            child_shared,
            child_resources,
            TaskRevision::INITIAL,
        ))
    }

    /// Prepare a thread and its independently selectable files/fs associations,
    /// then make the thread discoverable only at the registry commit point.
    pub fn clone_thread(
        self: &Arc<Self>,
        parent: &KernelContext,
        plan: ClonePlan,
        registry_id: ThreadId,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<KernelContext, KernelOperationError> {
        self.sweep_retired_threads();
        if !Arc::ptr_eq(self, &parent.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        if plan.task() != CloneTaskMode::JoinThreadGroup {
            return Err(KernelOperationError::ExpectedThreadGroup);
        }
        let published_revision = next_revision(parent.revision)?;

        let (tid, reservation) = self.ids().reserve_thread()?;
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        let resources = Arc::new(ThreadResources::for_clone(
            &parent.resources,
            plan,
            self.object_ids(),
        )?);
        let thread = parent.task.prepare_clone_thread(
            ThreadKey {
                tid,
                serial: self.object_ids().thread_serial()?,
            },
            registry_id,
            Arc::clone(&resources),
            parent.thread.signal_state(),
        );
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        {
            let mut state = self.registry().state.write();
            ensure_task_unreserved(&state, parent.task.key().id)?;
            let Some(record) = state.tasks.get_mut(&parent.task.key().id) else {
                return Err(KernelOperationError::ParentExited);
            };
            if record.task.key() != parent.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            if record.revision != parent.revision {
                return Err(KernelOperationError::StaleContext);
            }
            check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;
            let claim = reservation.commit();
            parent.task.publish_thread(Arc::clone(&thread))?;
            record.thread_claims.insert(tid, claim);
            record.revision = published_revision;
        }

        Ok(KernelContext::from_parts(
            self.clone(),
            Arc::clone(&parent.task),
            thread,
            Arc::clone(&parent.shared),
            resources,
            published_revision,
        ))
    }

    /// Test registry-locked association publication without invoking the exec
    /// backend stop/drain protocol.
    #[cfg(test)]
    pub(super) fn publish_task_associations(
        &self,
        task_id: TaskId,
        tid: LinuxTid,
        shared: Arc<TaskShared>,
        resources: Arc<ThreadResources>,
    ) -> Result<TaskRevision, KernelOperationError> {
        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let record = state
            .tasks
            .get_mut(&task_id)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        let thread = record
            .task
            .thread(tid)
            .ok_or(KernelOperationError::UnknownThread(tid))?;
        let revision = next_revision(record.revision)?;

        record.task.replace_shared(shared);
        thread.replace_resources(resources);
        record.revision = revision;
        Ok(revision)
    }

    pub fn reserve_task_operation(
        &self,
        task_id: TaskId,
    ) -> Result<TaskOperationReservation, KernelOperationError> {
        self.sweep_retired_threads();
        let state = self.registry().state.read();
        ensure_task_unreserved(&state, task_id)?;
        let record = state
            .tasks
            .get(&task_id)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        Ok(TaskOperationReservation {
            domain: Arc::clone(self.domain()),
            task: record.task.key(),
            revision: record.revision,
        })
    }

    pub fn join_process_group(
        &self,
        task_id: TaskId,
        target_group: ProcessGroupId,
    ) -> Result<(), KernelOperationError> {
        self.sweep_retired_threads();
        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some((task, revision)) = state
            .tasks
            .get(&task_id)
            .map(|record| (Arc::clone(&record.task), record.revision))
        else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        let old_group = task.process_group();
        let session = task.session();
        if old_group == target_group {
            return Ok(());
        }
        let Some(target) = state.process_groups.get(&target_group) else {
            return Err(KernelOperationError::UnknownProcessGroup(target_group));
        };
        if target.object.session() != session {
            return Err(KernelOperationError::CrossSessionProcessGroup);
        }
        let published_revision = next_revision(revision)?;

        remove_group_member(&mut state, old_group, session, task.key());
        if let Some(target) = state.process_groups.get_mut(&target_group) {
            target.members.insert(task.key());
        }
        task.replace_identity(target_group, session);
        if let Some(record) = state.tasks.get_mut(&task_id) {
            record.revision = published_revision;
        }
        Ok(())
    }

    pub fn create_process_group(
        &self,
        task_id: TaskId,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<ProcessGroupId, KernelOperationError> {
        let reservation = self.reserve_task_operation(task_id)?;
        self.create_process_group_reserved(reservation, failpoint)
    }

    pub fn create_process_group_reserved(
        &self,
        reservation: TaskOperationReservation,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<ProcessGroupId, KernelOperationError> {
        if !Arc::ptr_eq(&reservation.domain, self.domain()) {
            return Err(KernelOperationError::ForeignReservation);
        }
        let task_id = reservation.task.id;
        let task = {
            let state = self.registry().state.read();
            ensure_task_unreserved(&state, task_id)?;
            let record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::UnknownTask(task_id))?;
            if record.task.key() != reservation.task || record.revision != reservation.revision {
                return Err(KernelOperationError::StaleReservation);
            }
            Arc::clone(&record.task)
        };
        let session = task.session();
        let group_id = ProcessGroupId::from_leader(task_id);
        let claim = self.ids().claim_process_group(group_id)?;
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        let object = Arc::new(ProcessGroup::new(group_id, session, self.ids(), claim)?);
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some(current) = state
            .tasks
            .get(&task_id)
            .map(|record| Arc::clone(&record.task))
        else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        let current_revision = state
            .tasks
            .get(&task_id)
            .map(|record| record.revision)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        if current.key() != task.key()
            || current.key() != reservation.task
            || current.session() != session
            || current_revision != reservation.revision
        {
            return Err(KernelOperationError::TaskChangedBeforeCommit);
        }
        let published_revision = next_revision(current_revision)?;
        if state.process_groups.contains_key(&group_id) {
            return Err(KernelOperationError::ProcessGroupExists(group_id));
        }
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

        let old_group = current.process_group();
        state.process_groups.insert(
            group_id,
            ProcessGroupRecord {
                object,
                members: std::collections::BTreeSet::from([current.key()]),
            },
        );
        if let Some(session_record) = state.sessions.get_mut(&session) {
            session_record.process_groups.insert(group_id);
        }
        remove_group_member(&mut state, old_group, session, current.key());
        current.replace_identity(group_id, session);
        if let Some(record) = state.tasks.get_mut(&task_id) {
            record.revision = published_revision;
        }
        Ok(group_id)
    }

    pub fn create_session(
        &self,
        task_id: TaskId,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<SessionId, KernelOperationError> {
        let reservation = self.reserve_task_operation(task_id)?;
        self.create_session_reserved(reservation, failpoint)
    }

    pub fn create_session_reserved(
        &self,
        reservation: TaskOperationReservation,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<SessionId, KernelOperationError> {
        if !Arc::ptr_eq(&reservation.domain, self.domain()) {
            return Err(KernelOperationError::ForeignReservation);
        }
        let task_id = reservation.task.id;
        let task = {
            let state = self.registry().state.read();
            ensure_task_unreserved(&state, task_id)?;
            let record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::UnknownTask(task_id))?;
            if record.task.key() != reservation.task || record.revision != reservation.revision {
                return Err(KernelOperationError::StaleReservation);
            }
            Arc::clone(&record.task)
        };
        let old_group = task.process_group();
        let old_session = task.session();
        let group_id = ProcessGroupId::from_leader(task_id);
        let session_id = SessionId::from_leader(task_id);
        if old_group == group_id {
            return Err(KernelOperationError::AlreadyProcessGroupLeader);
        }
        let group_claim = self.ids().claim_process_group(group_id)?;
        let session_claim = self.ids().claim_session(session_id)?;
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        let group = Arc::new(ProcessGroup::new(
            group_id,
            session_id,
            self.ids(),
            group_claim,
        )?);
        let session = Arc::new(Session::new(session_id, self.ids(), session_claim)?);
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some(current) = state
            .tasks
            .get(&task_id)
            .map(|record| Arc::clone(&record.task))
        else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        let current_revision = state
            .tasks
            .get(&task_id)
            .map(|record| record.revision)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        if current.key() != task.key()
            || current.key() != reservation.task
            || current.process_group() != old_group
            || current.session() != old_session
            || current_revision != reservation.revision
        {
            return Err(KernelOperationError::TaskChangedBeforeCommit);
        }
        let published_revision = next_revision(current_revision)?;
        if state.process_groups.contains_key(&group_id) || state.sessions.contains_key(&session_id)
        {
            return Err(KernelOperationError::IdentityObjectExists);
        }
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

        remove_group_member(&mut state, old_group, old_session, current.key());
        state.process_groups.insert(
            group_id,
            ProcessGroupRecord {
                object: group,
                members: std::collections::BTreeSet::from([current.key()]),
            },
        );
        state.sessions.insert(
            session_id,
            SessionRecord {
                object: session,
                process_groups: std::collections::BTreeSet::from([group_id]),
            },
        );
        current.replace_identity(group_id, session_id);
        if let Some(record) = state.tasks.get_mut(&task_id) {
            record.revision = published_revision;
        }
        Ok(session_id)
    }

    /// Convert a live task into a compact zombie. The task's numeric claim is
    /// moved into the zombie record and is released only by consuming wait.
    pub fn exit_task(
        &self,
        task_id: TaskId,
        status: LinuxWaitStatus,
        rusage: TaskRusage,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<Zombie, KernelOperationError> {
        self.sweep_retired_threads();
        check_failpoint(failpoint, KernelFailpoint::AfterReserve)?;
        check_failpoint(failpoint, KernelFailpoint::AfterObjects)?;
        check_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;

        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, task_id)?;
        let Some((exiting_task, retired_thread_count)) = state
            .tasks
            .get(&task_id)
            .map(|record| (Arc::clone(&record.task), record.thread_claims.len()))
        else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        let task_key = exiting_task.key();
        let adopter = (task_key != state.root).then_some(state.root);
        let mut children = exiting_task.children();
        children.sort_by_key(|child| child.serial);
        for affected in children.iter().copied().chain(adopter) {
            if state.tasks.contains_key(&affected.id) {
                ensure_task_unreserved(&state, affected.id)?;
            }
        }
        state
            .retired_threads
            .try_reserve_exact(retired_thread_count)
            .map_err(|_| KernelOperationError::RetiredThreadCapacity(retired_thread_count))?;
        let mut revision_updates = std::collections::BTreeMap::new();
        for child_key in &children {
            if let Some(child) = state.tasks.get(&child_key.id) {
                revision_updates.insert(child_key.id, next_revision(child.revision)?);
            }
        }
        if let Some(adopter_key) = adopter {
            if let Some(adopter_record) = state.tasks.get(&adopter_key.id) {
                revision_updates.insert(adopter_key.id, next_revision(adopter_record.revision)?);
            }
        }
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;
        if !exiting_task.begin_exit() {
            return Err(KernelOperationError::AlreadyExiting(task_id));
        }
        let Some(record) = state.tasks.remove(&task_id) else {
            return Err(KernelOperationError::UnknownTask(task_id));
        };
        let TaskRecord {
            task,
            revision: _,
            task_claim,
            thread_claims,
            diagnostic_name,
        } = record;
        let zombie = Zombie::from_task(&task, status, rusage, diagnostic_name);
        for (tid, claim) in thread_claims {
            if let Some(thread) = task.thread(tid) {
                state
                    .retired_threads
                    .push(super::core::RetiredThreadRecord {
                        thread: Arc::downgrade(&thread),
                        _claim: claim,
                    });
            }
        }

        for child_key in children {
            if let Some(child) = state.tasks.get(&child_key.id) {
                child.task.reparent(adopter);
            } else if let Some(child) = state.zombies.get_mut(&child_key.id) {
                child.zombie.parent = adopter;
            }
            if let Some(adopter_key) = adopter {
                if let Some(adopter_record) = state.tasks.get(&adopter_key.id) {
                    adopter_record.task.add_child(child_key);
                }
            }
        }
        for (affected_id, revision) in revision_updates {
            if let Some(affected) = state.tasks.get_mut(&affected_id) {
                affected.revision = revision;
            }
        }

        let process_group = task.process_group();
        let session = task.session();
        let remove_group = if let Some(group) = state.process_groups.get_mut(&process_group) {
            group.members.remove(&task_key);
            group.members.is_empty()
        } else {
            false
        };
        if remove_group {
            state.process_groups.remove(&process_group);
            let remove_session = if let Some(session_record) = state.sessions.get_mut(&session) {
                session_record.process_groups.remove(&process_group);
                session_record.process_groups.is_empty()
            } else {
                false
            };
            if remove_session {
                state.sessions.remove(&session);
            }
        }

        state.zombies.insert(
            task_id,
            ZombieRecord {
                zombie: zombie.clone(),
                _task_claim: task_claim,
            },
        );
        Ok(zombie)
    }

    pub fn wait_child(
        &self,
        parent_id: TaskId,
        target: Option<TaskId>,
        mode: WaitMode,
    ) -> Result<WaitOutcome, KernelOperationError> {
        self.sweep_retired_threads();
        let mut state = self.registry().state.write();
        if mode == WaitMode::Consume {
            ensure_task_unreserved(&state, parent_id)?;
        }
        let Some(parent) = state.tasks.get(&parent_id).map(|record| record.task.key()) else {
            return Err(KernelOperationError::UnknownTask(parent_id));
        };
        let exited = state
            .zombies
            .iter()
            .find(|(id, record)| {
                record.zombie.parent == Some(parent) && target.is_none_or(|target| target == **id)
            })
            .map(|(id, record)| (*id, record.zombie.clone()));
        if let Some((id, zombie)) = exited {
            if mode == WaitMode::Consume {
                let parent_revision = state
                    .tasks
                    .get(&parent_id)
                    .map(|record| next_revision(record.revision))
                    .transpose()?
                    .ok_or(KernelOperationError::UnknownTask(parent_id))?;
                state.zombies.remove(&id);
                if let Some(parent_record) = state.tasks.get_mut(&parent_id) {
                    parent_record.task.remove_child(zombie.key);
                    parent_record.revision = parent_revision;
                }
            }
            return Ok(WaitOutcome::Exited(zombie));
        }

        let live_child = state.tasks.iter().any(|(id, record)| {
            record.task.parent() == Some(parent) && target.is_none_or(|target| target == *id)
        });
        Ok(if live_child {
            WaitOutcome::StillRunning
        } else {
            WaitOutcome::NoChild
        })
    }
}

fn next_revision(revision: TaskRevision) -> Result<TaskRevision, KernelOperationError> {
    revision
        .next()
        .ok_or(KernelOperationError::RevisionExhausted)
}

fn remove_group_member(
    state: &mut RegistryState,
    group_id: ProcessGroupId,
    session_id: SessionId,
    task: TaskKey,
) {
    let remove_group = if let Some(group) = state.process_groups.get_mut(&group_id) {
        group.members.remove(&task);
        group.members.is_empty()
    } else {
        false
    };
    if !remove_group {
        return;
    }
    state.process_groups.remove(&group_id);
    let remove_session = if let Some(session) = state.sessions.get_mut(&session_id) {
        session.process_groups.remove(&group_id);
        session.process_groups.is_empty()
    } else {
        false
    };
    if remove_session {
        state.sessions.remove(&session_id);
    }
}

fn ensure_task_unreserved(
    state: &RegistryState,
    task_id: TaskId,
) -> Result<(), KernelOperationError> {
    if state.reservations.contains_key(&task_id) {
        return Err(KernelOperationError::TaskBusy(task_id));
    }
    Ok(())
}

fn check_failpoint(
    selected: Option<KernelFailpoint>,
    point: KernelFailpoint,
) -> Result<(), KernelOperationError> {
    if selected == Some(point) {
        return Err(KernelOperationError::Injected(point));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum KernelOperationError {
    #[error(transparent)]
    Id(#[from] IdError),
    #[error(transparent)]
    ObjectId(#[from] ObjectIdError),
    #[error(transparent)]
    ObjectGraph(#[from] ObjectGraphError),
    #[error(transparent)]
    TaskSharedClone(#[from] TaskSharedCloneError),
    #[error("kernel context belongs to another Kernel")]
    ForeignContext,
    #[error("clone plan creates a thread, not a new task")]
    ExpectedNewTask,
    #[error("clone plan creates a task, not a thread-group member")]
    ExpectedThreadGroup,
    #[error("parent task exited before commit")]
    ParentExited,
    #[error("kernel context revision is stale")]
    StaleContext,
    #[error("kernel operation reservation is stale")]
    StaleReservation,
    #[error("kernel operation reservation belongs to another Kernel")]
    ForeignReservation,
    #[error("task revision space is exhausted")]
    RevisionExhausted,
    #[error("could not reserve {0} retired-thread records")]
    RetiredThreadCapacity(usize),
    #[error("task's process-group or session object disappeared before commit")]
    IdentityObjectMissing,
    #[error("kernel task {0:?} is not live")]
    UnknownTask(TaskId),
    #[error("kernel task {0:?} has a preparing operation")]
    TaskBusy(TaskId),
    #[error("kernel thread {0:?} is not live")]
    UnknownThread(LinuxTid),
    #[error("kernel task {0:?} is already exiting")]
    AlreadyExiting(TaskId),
    #[error("process group {0:?} does not exist")]
    UnknownProcessGroup(ProcessGroupId),
    #[error("process group {0:?} already exists")]
    ProcessGroupExists(ProcessGroupId),
    #[error("task and target process group belong to different sessions")]
    CrossSessionProcessGroup,
    #[error("task identity changed before the operation committed")]
    TaskChangedBeforeCommit,
    #[error("process-group or session identity already exists")]
    IdentityObjectExists,
    #[error("a process-group leader cannot create a session")]
    AlreadyProcessGroupLeader,
    #[error("injected kernel operation failure at {0:?}")]
    Injected(KernelFailpoint),
}

#[cfg(test)]
mod tests {
    use carrick_abi::{LinuxCloneFlags, SigSet};
    use proptest::prelude::*;

    use super::*;
    use crate::kernel::{
        Credentials, FileDescription, FileSlotNumber, FileTable, FsContext, LinuxSignal, Mm,
        ObjectIdRegistry, RootBootstrap, Sighand, SignalDisposition, ThreadSignalState,
    };

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let ids = ObjectIdRegistry::new();
        let input = RootBootstrap::from_observed_pid(
            pid,
            ThreadId::synthetic_for_tests(pid),
            Arc::new(TaskShared::new(
                Arc::new(Mm::new_reference(ids.mm_id().expect("mm"))),
                Arc::new(Sighand::new(ids.sighand_id().expect("sighand"))),
            )),
            Arc::new(ThreadResources::new(
                Arc::new(FileTable::new(ids.file_table_id().expect("files"))),
                Arc::new(FsContext::new(ids.fs_context_id().expect("fs"))),
                Arc::new(Credentials::new()),
            )),
            "root".to_string(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    #[test]
    fn fork_publishes_task_and_independently_selected_resources() {
        let (kernel, root) = bootstrap(100);
        let ignored = LinuxSignal::for_signal_number(2).expect("ignored signal");
        let caught = LinuxSignal::for_signal_number(3).expect("caught signal");
        root.shared
            .sighand()
            .set_disposition(ignored, SignalDisposition::Ignore);
        root.shared
            .sighand()
            .set_disposition(caught, SignalDisposition::Caught);
        let parent_signals =
            ThreadSignalState::new(SigSet::EMPTY.with(4), SigSet::EMPTY.with(5), true, 2);
        root.thread.replace_signal_state(parent_signals);
        let slot = FileSlotNumber::for_open_fd(3).expect("file slot");
        let description = Arc::new(FileDescription::regular(
            kernel
                .object_ids()
                .file_description_id()
                .expect("description"),
        ));
        assert!(
            root.resources
                .files()
                .install(slot, Arc::clone(&description), false)
                .is_none()
        );
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let child = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(101),
                "child".to_string(),
                None,
            )
            .expect("fork");

        assert_eq!(kernel.registry().task_count(), 2);
        assert_eq!(child.task.parent(), Some(root.task.key()));
        assert!(!Arc::ptr_eq(&root.shared.mm(), &child.shared.mm()));
        assert!(!Arc::ptr_eq(
            &root.resources.files(),
            &child.resources.files()
        ));
        assert_eq!(
            child.shared.sighand().disposition(ignored),
            SignalDisposition::Ignore
        );
        assert_eq!(
            child.shared.sighand().disposition(caught),
            SignalDisposition::Caught
        );
        let child_signals = child.thread.signal_state();
        assert_eq!(child_signals.blocked(), parent_signals.blocked());
        assert!(child_signals.pending().is_empty());
        assert!(child_signals.altstack_enabled());
        assert_eq!(child_signals.handler_frame_depth(), 2);
        let child_slot = child
            .resources
            .files()
            .slot(slot)
            .expect("fork copies file slot");
        assert!(Arc::ptr_eq(&child_slot.description(), &description));
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
        assert_eq!(root.task.live_thread_count(), 2);
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
            Arc::new(Credentials::new()),
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

    #[test]
    fn stale_context_cannot_commit_a_fork() {
        let (kernel, root) = bootstrap(275);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(276),
                "first child".to_string(),
                None,
            )
            .expect("first fork");
        drop(child);
        let result = kernel.fork_task(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
            ThreadId::synthetic_for_tests(277),
            "stale child".to_string(),
            None,
        );

        assert!(matches!(result, Err(KernelOperationError::StaleContext)));
        assert_eq!(kernel.registry().task_count(), 2);
    }

    #[test]
    fn stale_context_cannot_commit_a_thread_clone() {
        let (kernel, root) = bootstrap(285);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(286), None)
            .expect("first thread");
        drop(first);
        let result = kernel.clone_thread(&root, plan, ThreadId::synthetic_for_tests(287), None);

        assert!(matches!(result, Err(KernelOperationError::StaleContext)));
        assert_eq!(root.task.live_thread_count(), 2);
    }

    #[test]
    fn stale_identity_reservations_cannot_commit() {
        let (kernel, root) = bootstrap(290);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(291),
                "child".to_string(),
                None,
            )
            .expect("child");
        let group_reservation = kernel
            .reserve_task_operation(child.task.key().id)
            .expect("group reservation");
        let thread_plan = ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan");
        let first_thread = kernel
            .clone_thread(
                &child,
                thread_plan,
                ThreadId::synthetic_for_tests(292),
                None,
            )
            .expect("first thread");
        assert!(matches!(
            kernel.create_process_group_reserved(group_reservation, None),
            Err(KernelOperationError::StaleReservation)
        ));

        let session_reservation = kernel
            .reserve_task_operation(child.task.key().id)
            .expect("session reservation");
        let second_thread = kernel
            .clone_thread(
                &first_thread,
                thread_plan,
                ThreadId::synthetic_for_tests(293),
                None,
            )
            .expect("second thread");
        drop(second_thread);
        assert!(matches!(
            kernel.create_session_reserved(session_reservation, None),
            Err(KernelOperationError::StaleReservation)
        ));
    }

    #[test]
    fn reservation_cannot_cross_kernel_identity() {
        let (first, first_root) = bootstrap(295);
        let (second, second_root) = bootstrap(295);
        assert_eq!(first_root.task.key(), second_root.task.key());
        assert_eq!(first_root.revision, second_root.revision);
        let reservation = first
            .reserve_task_operation(first_root.task.key().id)
            .expect("reservation");

        assert!(matches!(
            second.create_process_group_reserved(reservation, None),
            Err(KernelOperationError::ForeignReservation)
        ));
    }

    #[test]
    fn every_prepare_failpoint_leaves_registry_unchanged() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, root) = bootstrap(300);
            let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
            let counts = kernel.ids().counts();
            let credentials = root.resources.credentials();
            let credential_refs = Arc::strong_count(&credentials);
            let result = kernel.fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(301),
                "child".to_string(),
                Some(point),
            );

            assert!(matches!(result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.registry().task_count(), 1);
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(Arc::strong_count(&credentials), credential_refs);
            assert_eq!(root.task.children(), Vec::<TaskKey>::new());
        }
    }

    #[test]
    fn every_thread_failpoint_restores_claims_and_resource_references() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, root) = bootstrap(325);
            let counts = kernel.ids().counts();
            let files = root.resources.files();
            let credentials = root.resources.credentials();
            let file_refs = Arc::strong_count(&files);
            let credential_refs = Arc::strong_count(&credentials);
            let result = kernel.clone_thread(
                &root,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD
                        | LinuxCloneFlags::SIGHAND
                        | LinuxCloneFlags::VM
                        | LinuxCloneFlags::FILES,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(326),
                Some(point),
            );

            assert!(matches!(result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(Arc::strong_count(&files), file_refs);
            assert_eq!(Arc::strong_count(&credentials), credential_refs);
            assert_eq!(root.task.live_thread_count(), 1);
        }
    }

    #[test]
    fn every_identity_and_exit_failpoint_restores_registry_state() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, root) = bootstrap(335);
            let child = kernel
                .fork_task(
                    &root,
                    ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                    ThreadId::synthetic_for_tests(336),
                    "child".to_string(),
                    None,
                )
                .expect("child");
            let child_id = child.task.key().id;
            let counts = kernel.ids().counts();
            let task_count = kernel.registry().task_count();
            let group_count = kernel.registry().process_group_count();
            let session_count = kernel.registry().session_count();
            let child_shared_refs = Arc::strong_count(&child.shared);
            let child_resource_refs = Arc::strong_count(&child.resources);

            let group_result = kernel.create_process_group(child_id, Some(point));
            assert!(matches!(group_result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(kernel.registry().process_group_count(), group_count);
            assert_eq!(child.task.process_group(), root.task.process_group());

            let session_result = kernel.create_session(child_id, Some(point));
            assert!(matches!(session_result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(kernel.registry().process_group_count(), group_count);
            assert_eq!(kernel.registry().session_count(), session_count);
            assert_eq!(child.task.session(), root.task.session());

            let exit_result = kernel.exit_task(
                child_id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                Some(point),
            );
            assert!(matches!(exit_result, Err(KernelOperationError::Injected(p)) if p == point));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(kernel.registry().task_count(), task_count);
            assert_eq!(kernel.registry().zombie_count(), 0);
            assert_eq!(Arc::strong_count(&child.shared), child_shared_refs);
            assert_eq!(Arc::strong_count(&child.resources), child_resource_refs);
        }
    }

    #[test]
    fn registry_serializes_process_group_membership_transitions() {
        let (kernel, root) = bootstrap(350);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let first = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(351),
                "first".to_string(),
                None,
            )
            .expect("first child");
        let refreshed_root = kernel
            .context(root.task.key().id, root.thread.key().tid)
            .expect("refreshed root context");
        let second = kernel
            .fork_task(
                &refreshed_root,
                fork_plan,
                ThreadId::synthetic_for_tests(352),
                "second".to_string(),
                None,
            )
            .expect("second child");
        let group = kernel
            .create_process_group(first.task.key().id, None)
            .expect("new process group");

        kernel
            .join_process_group(second.task.key().id, group)
            .expect("join group");

        assert_eq!(first.task.process_group(), group);
        assert_eq!(second.task.process_group(), group);
        assert_eq!(
            kernel.registry().process_group_members(group),
            vec![first.task.key(), second.task.key()]
        );
        assert_eq!(first.task.session(), root.task.session());
    }

    #[test]
    fn registry_publishes_new_session_and_group_together() {
        let (kernel, root) = bootstrap(375);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(376),
                "session child".to_string(),
                None,
            )
            .expect("child");
        let session = kernel
            .create_session(child.task.key().id, None)
            .expect("new session");
        let group = ProcessGroupId::from_leader(child.task.key().id);

        assert_eq!(child.task.session(), session);
        assert_eq!(child.task.process_group(), group);
        assert_eq!(
            kernel.registry().session_process_groups(session),
            vec![group]
        );
        assert_eq!(
            kernel.registry().process_group_members(group),
            vec![child.task.key()]
        );
    }

    #[test]
    fn identity_failpoint_does_not_publish_partial_group() {
        let (kernel, root) = bootstrap(390);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(391),
                "child".to_string(),
                None,
            )
            .expect("child");
        let original_group = child.task.process_group();
        let result =
            kernel.create_process_group(child.task.key().id, Some(KernelFailpoint::BeforePublish));

        assert!(matches!(
            result,
            Err(KernelOperationError::Injected(
                KernelFailpoint::BeforePublish
            ))
        ));
        assert_eq!(child.task.process_group(), original_group);
        assert!(
            kernel
                .registry()
                .process_group(ProcessGroupId::from_leader(child.task.key().id))
                .is_none()
        );
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
            .exit_task(
                grandchild_id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            )
            .expect("grandchild exit");
        kernel
            .exit_task(
                parent_id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            )
            .expect("parent exit");

        let zombie = kernel
            .registry()
            .zombie(grandchild_id)
            .expect("reparented zombie");
        assert_eq!(zombie.parent, Some(root.task.key()));
        assert_eq!(live_grandchild.task.parent(), Some(root.task.key()));
        assert!(matches!(
            kernel.fork_task(
                &live_grandchild,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(399),
                "stale descendant".to_string(),
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

    proptest! {
        #[test]
        fn bounded_operation_sequences_preserve_registry_invariants(
            actions in proptest::collection::vec(any::<u8>(), 1..80)
        ) {
            let (kernel, root) = bootstrap(500);
            let root_id = root.task.key().id;
            for (step, action) in actions.into_iter().enumerate() {
                let tasks = kernel.registry().task_ids();
                if tasks.is_empty() {
                    break;
                }
                let selected = tasks[usize::from(action) % tasks.len()];
                match action % 7 {
                    0 if tasks.len() < 12 => {
                        if let Ok(context) = kernel.context(
                            selected,
                            LinuxTid::for_task_leader(selected),
                        ) {
                            let _ = kernel.fork_task(
                                &context,
                                ClonePlan::from_flags(LinuxCloneFlags::empty())
                                    .expect("fork plan"),
                                ThreadId::synthetic_for_tests(1_000 + step as i32),
                                format!("task-{step}"),
                                None,
                            );
                        }
                    }
                    1 => {
                        if let Ok(context) = kernel.context(
                            selected,
                            LinuxTid::for_task_leader(selected),
                        ) {
                            let _ = kernel.clone_thread(
                                &context,
                                ClonePlan::from_flags(
                                    LinuxCloneFlags::THREAD
                                        | LinuxCloneFlags::SIGHAND
                                        | LinuxCloneFlags::VM,
                                )
                                .expect("thread plan"),
                                ThreadId::synthetic_for_tests(2_000 + step as i32),
                                None,
                            );
                        }
                    }
                    2 if selected != root_id => {
                        let _ = kernel.exit_task(
                            selected,
                            LinuxWaitStatus::from_wait_encoding(0),
                            TaskRusage::default(),
                            None,
                        );
                    }
                    3 => {
                        let _ = kernel.wait_child(root_id, None, WaitMode::Consume);
                    }
                    4 => {
                        let _ = kernel.create_process_group(selected, None);
                    }
                    5 if selected != root_id => {
                        let _ = kernel.create_session(selected, None);
                    }
                    6 => {
                        let groups = kernel.registry().process_group_ids();
                        if let Some(group) = groups.get(usize::from(action) % groups.len().max(1)) {
                            let _ = kernel.join_process_group(selected, *group);
                        }
                    }
                    _ => {}
                }
                prop_assert_eq!(kernel.validate_invariants(), Ok(()));
            }
        }
    }

    #[test]
    fn zombie_holds_numeric_claim_until_consuming_wait() {
        let (kernel, root) = bootstrap(400);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(401),
                "child".to_string(),
                None,
            )
            .expect("fork");
        let child_id = child.task.key().id;
        drop(child);

        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Observe),
            Ok(WaitOutcome::StillRunning)
        ));
        kernel
            .exit_task(
                child_id,
                LinuxWaitStatus::from_wait_encoding(7 << 8),
                TaskRusage::default(),
                None,
            )
            .expect("exit");
        assert!(kernel.ids().is_reserved_number(child_id.raw()));
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Observe),
            Ok(WaitOutcome::Exited(_))
        ));
        assert!(kernel.ids().is_reserved_number(child_id.raw()));
        assert!(matches!(
            kernel.wait_child(root.task.key().id, Some(child_id), WaitMode::Consume),
            Ok(WaitOutcome::Exited(_))
        ));
        kernel.sweep_retired_threads();
        assert!(!kernel.ids().is_reserved_number(child_id.raw()));
        assert_eq!(kernel.registry().zombie_count(), 0);
    }
}
