//! Session, process group, and controlling terminal operations.
//!
//! Enforces POSIX session and process group invariants, controlling terminal
//! acquisition, foreground process group tracking, and group signal routing.

use std::sync::Arc;

use carrick_fatal::carrick_fatal;

use super::{
    KernelFailpoint, KernelOperationError, TaskOperationReservation, check_failpoint,
    ensure_task_unreserved, namespace_visible_task_id, next_revision,
};
use crate::kernel::core::{
    Kernel, KernelContext, ProcessGroupRecord, RegistryState, SessionRecord,
};
use crate::kernel::ids::{LinuxSignal, ProcessGroupId, SessionId, TaskId};
use crate::kernel::objects::{ProcessGroup, Session, TaskKey, TaskLifecycle};
use crate::kernel::registry::IdError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TtyControlError {
    NotControlling,
    Permission,
}

impl Kernel {
    pub(crate) fn initialize_launch_controlling_tty(&self, caller: &KernelContext) {
        let container = caller.container().id();
        let state = self.registry().state.read();
        let session = state
            .sessions
            .get(&caller.task().session())
            .filter(|record| record.container == container)
            .map(|record| Arc::clone(&record.object))
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "kernel::tty_identity",
                    "session not found in initialize_launch_controlling_tty"
                );
            });
        let foreground = state
            .process_groups
            .get(&caller.task().process_group())
            .filter(|record| record.container == container)
            .map(|record| Arc::clone(&record.object))
            .unwrap_or_else(|| {
                carrick_fatal!(
                    "kernel::tty_identity",
                    "process group not found in initialize_launch_controlling_tty"
                );
            });
        let mut ttys = self.controlling_ttys.lock();
        ttys.entry(container)
            .or_insert(crate::kernel::core::ControllingTtyState {
                session,
                foreground,
            });
        drop(ttys);
        drop(state);
        crate::kernel::tty::acknowledge_ready(self, container);
    }

    pub(crate) fn tty_acquire(
        &self,
        caller: &KernelContext,
        force: bool,
    ) -> Result<(), TtyControlError> {
        let container = caller.container().id();
        let session = caller.task().session();
        if session.raw() != caller.task().key().id.raw() {
            return Err(TtyControlError::Permission);
        }
        let state = self.registry().state.read();
        let Some(session_object) = state
            .sessions
            .get(&session)
            .filter(|record| record.container == container)
            .map(|record| Arc::clone(&record.object))
        else {
            return Err(TtyControlError::Permission);
        };
        let Some(foreground) = state
            .process_groups
            .get(&caller.task().process_group())
            .filter(|record| record.container == container)
            .map(|record| Arc::clone(&record.object))
        else {
            return Err(TtyControlError::Permission);
        };
        let mut ttys = self.controlling_ttys.lock();
        match ttys.get(&container) {
            Some(current) if current.session.id() == session => Ok(()),
            Some(_) if !force || !caller.resources().credentials().is_privileged() => {
                if crate::kernel::tty::session_controlling_tty(session).is_some() {
                    Ok(())
                } else {
                    Err(TtyControlError::Permission)
                }
            }
            _ => {
                ttys.insert(
                    container,
                    crate::kernel::core::ControllingTtyState {
                        session: session_object,
                        foreground,
                    },
                );
                Ok(())
            }
        }
    }

    pub(crate) fn tty_foreground_process_group(
        &self,
        caller: &KernelContext,
    ) -> Result<ProcessGroupId, TtyControlError> {
        let session = caller.task().session();
        if let Some(fg) = crate::kernel::tty::session_foreground_process_group(session) {
            return Ok(fg);
        }
        let ttys = self.controlling_ttys.lock();
        let tty = ttys
            .get(&caller.container().id())
            .ok_or(TtyControlError::NotControlling)?;
        if tty.session.id() != session {
            return Err(TtyControlError::NotControlling);
        }
        Ok(tty.foreground.id())
    }

    pub(crate) fn tty_session(&self, caller: &KernelContext) -> Result<SessionId, TtyControlError> {
        let session = caller.task().session();
        if crate::kernel::tty::session_controlling_tty(session).is_some() {
            return Ok(session);
        }
        let ttys = self.controlling_ttys.lock();
        let tty = ttys
            .get(&caller.container().id())
            .ok_or(TtyControlError::NotControlling)?;
        if tty.session.id() != session {
            return Err(TtyControlError::NotControlling);
        }
        Ok(tty.session.id())
    }

    pub(crate) fn tty_set_foreground_process_group(
        &self,
        caller: &KernelContext,
        foreground: ProcessGroupId,
    ) -> Result<(), TtyControlError> {
        let container = caller.container().id();
        let session = caller.task().session();
        let state = self.registry().state.read();
        let Some(group) = state.process_groups.get(&foreground) else {
            return Err(TtyControlError::Permission);
        };
        if group.container != container || group.object.session() != session {
            return Err(TtyControlError::Permission);
        }
        let foreground_obj = Arc::clone(&group.object);
        drop(state);

        let mut updated = false;
        if let Some(tty_key) = crate::kernel::tty::session_controlling_tty(session) {
            if crate::kernel::tty::set_foreground_process_group(tty_key, session, foreground)
                .is_ok()
            {
                updated = true;
            }
        }

        let mut ttys = self.controlling_ttys.lock();
        if let Some(tty) = ttys.get_mut(&container) {
            if tty.session.id() == session {
                tty.foreground = foreground_obj;
                updated = true;
            }
        }
        if updated {
            Ok(())
        } else {
            Err(TtyControlError::NotControlling)
        }
    }

    pub(crate) fn tty_detach(&self, caller: &KernelContext) -> Result<(), TtyControlError> {
        let container = caller.container().id();
        let session = caller.task().session();
        if let Some(tty_key) = crate::kernel::tty::session_controlling_tty(session) {
            crate::kernel::tty::detach_if_session(tty_key, session);
        }
        let mut ttys = self.controlling_ttys.lock();
        if let Some(current) = ttys.get(&container) {
            if current.session.id() == session {
                ttys.remove(&container);
            }
        }
        Ok(())
    }

    pub(crate) fn tty_caller_is_background(&self, caller: &KernelContext) -> bool {
        self.tty_foreground_process_group(caller)
            .is_ok_and(|foreground| foreground != caller.task().process_group())
    }

    pub(crate) fn caller_process_group_is_orphaned(&self, caller: &KernelContext) -> bool {
        let container = caller.container().id();
        let session = caller.task().session();
        let group_id = caller.task().process_group();
        let state = self.registry().state.read();
        let Some(group) = state.process_groups.get(&group_id) else {
            return true;
        };
        if group.container != container {
            return true;
        }
        for member_key in &group.members {
            let Some(member_record) = state.tasks.get(&member_key.id) else {
                continue;
            };
            if member_record.task.key() != *member_key
                || member_record.task.lifecycle() != TaskLifecycle::Live
                || member_record.task.container().id() != container
            {
                continue;
            }
            let Some(parent_key) = member_record.task.parent() else {
                continue;
            };
            let Some(parent_record) = state.tasks.get(&parent_key.id) else {
                continue;
            };
            if parent_record.task.key() != parent_key
                || parent_record.task.lifecycle() != TaskLifecycle::Live
                || parent_record.task.container().id() != container
            {
                continue;
            }
            if parent_record.task.session() == session
                && parent_record.task.process_group() != group_id
            {
                return false;
            }
        }
        true
    }

    pub(crate) fn post_signal_to_process_group(
        &self,
        container: crate::kernel::container::ContainerId,
        group_id: ProcessGroupId,
        signal: LinuxSignal,
    ) -> usize {
        let state = self.registry().state.read();
        let mut tasks = state
            .process_groups
            .get(&group_id)
            .filter(|record| record.container == container)
            .into_iter()
            .flat_map(|record| record.members.iter())
            .filter_map(|task| {
                state.tasks.get(&task.id).and_then(|record| {
                    (record.task.key() == *task
                        && record.task.lifecycle() == TaskLifecycle::Live
                        && record.task.container().id() == container)
                        .then_some(*task)
                })
            })
            .collect::<Vec<_>>();
        drop(state);
        tasks.sort_unstable();
        tasks.dedup();
        tasks
            .into_iter()
            .filter(|task| self.post_signal_to_task_key(*task, signal, None))
            .count()
    }

    pub(crate) fn post_signal_to_tty_foreground(
        &self,
        container: crate::kernel::container::ContainerId,
        signal: LinuxSignal,
    ) -> usize {
        let Some(group) = self
            .controlling_ttys
            .lock()
            .get(&container)
            .map(|tty| tty.foreground.id())
        else {
            return 0;
        };
        self.post_signal_to_process_group(container, group, signal)
    }

    pub fn set_process_group(
        &self,
        caller_id: TaskId,
        target_id: Option<TaskId>,
        requested_group: Option<ProcessGroupId>,
    ) -> Result<(), KernelOperationError> {
        self.sweep_retired_threads();
        let target_id = target_id.unwrap_or(caller_id);
        let target_group =
            requested_group.unwrap_or_else(|| ProcessGroupId::from_leader(target_id));

        let prospective_claim = if target_group == ProcessGroupId::from_leader(target_id) {
            match self.ids().claim_process_group(target_group) {
                Ok(claim) => Some(claim),
                Err(IdError::UnknownNamespaceId(_)) => {
                    return Err(KernelOperationError::UnknownTask(target_id));
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };

        let mut state = self.registry().state.write();
        ensure_task_unreserved(&state, target_id)?;
        let caller = state
            .tasks
            .get(&caller_id)
            .map(|record| Arc::clone(&record.task))
            .ok_or(KernelOperationError::UnknownTask(caller_id))?;
        let (target, target_revision, target_has_execed) = state
            .tasks
            .get(&target_id)
            .map(|record| (Arc::clone(&record.task), record.revision, record.has_execed))
            .ok_or(KernelOperationError::UnknownTask(target_id))?;
        if target_id != caller_id {
            if target.parent().map(|parent| parent.id) != Some(caller_id) {
                return Err(KernelOperationError::UnknownTask(target_id));
            }
            if target_has_execed {
                return Err(KernelOperationError::ChildExeced(target_id));
            }
        }
        if target.session() != caller.session()
            || SessionId::from_leader(target_id) == target.session()
        {
            return Err(KernelOperationError::IdentityPermission);
        }
        if target.process_group() == target_group {
            return Ok(());
        }

        let group_exists = match state.process_groups.get(&target_group) {
            Some(group) if group.object.session() == caller.session() => true,
            Some(_) => return Err(KernelOperationError::IdentityPermission),
            None => false,
        };
        if !group_exists && target_group != ProcessGroupId::from_leader(target_id) {
            return Err(KernelOperationError::IdentityPermission);
        }
        let target_namespace_id = if group_exists {
            None
        } else {
            Some(namespace_visible_task_id(&target)?)
        };

        let published_revision = next_revision(target_revision)?;
        if !group_exists {
            let Some(namespace_id) = target_namespace_id else {
                carrick_fatal!(
                    "kernel::process_group_identity",
                    "missing target_namespace_id in set_process_group"
                );
            };
            if !state.sessions.contains_key(&caller.session()) {
                return Err(KernelOperationError::IdentityObjectMissing);
            }
            let claim = prospective_claim.ok_or(KernelOperationError::IdentityPermission)?;
            let object = Arc::new(ProcessGroup::new(
                target_group,
                caller.session(),
                self.ids(),
                claim,
            )?);
            state
                .sessions
                .get_mut(&caller.session())
                .ok_or(KernelOperationError::IdentityObjectMissing)?
                .process_groups
                .insert(target_group);
            state.publish_process_group(
                target_group,
                ProcessGroupRecord {
                    object,
                    members: std::collections::BTreeSet::new(),
                    container: target.container().id(),
                    namespace_id,
                },
            );
        }

        let old_group = target.process_group();
        let session = target.session();
        remove_group_member(&mut state, old_group, session, target.key());
        let group = state
            .process_groups
            .get_mut(&target_group)
            .ok_or(KernelOperationError::IdentityObjectMissing)?;
        group.members.insert(target.key());
        target.replace_identity(target_group, session);
        if let Some(record) = state.tasks.get_mut(&target_id) {
            record.revision = published_revision;
        }
        Ok(())
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
        let namespace_id = namespace_visible_task_id(&task)?;
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
        state.publish_process_group(
            group_id,
            ProcessGroupRecord {
                object,
                members: std::collections::BTreeSet::from([current.key()]),
                container: current.container().id(),
                namespace_id,
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
        let namespace_id = namespace_visible_task_id(&task)?;
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
        // setsid(2): "EPERM — The process group ID of any process equals the
        // PID of the calling process." The leader check above only sees the
        // caller's OWN membership; a group it created and then left keeps
        // its id while any member survives, and that number is the caller's
        // pid. A surviving session by that number is the same refusal.
        if state.process_groups.contains_key(&group_id) || state.sessions.contains_key(&session_id)
        {
            return Err(KernelOperationError::IdentityInUseByCallerPid);
        }
        check_failpoint(failpoint, KernelFailpoint::BeforePublish)?;

        remove_group_member(&mut state, old_group, old_session, current.key());
        state.publish_process_group(
            group_id,
            ProcessGroupRecord {
                object: group,
                members: std::collections::BTreeSet::from([current.key()]),
                container: current.container().id(),
                namespace_id,
            },
        );
        state.publish_session(
            session_id,
            SessionRecord {
                object: session,
                process_groups: std::collections::BTreeSet::from([group_id]),
                container: current.container().id(),
                namespace_id,
            },
        );
        current.replace_identity(group_id, session_id);
        if let Some(record) = state.tasks.get_mut(&task_id) {
            record.revision = published_revision;
        }
        Ok(session_id)
    }
}

pub(super) fn exact_process_group_members(
    state: &RegistryState,
    container: crate::kernel::container::ContainerId,
    group_id: ProcessGroupId,
) -> Option<Vec<TaskKey>> {
    let group = state.process_groups.get(&group_id)?;
    if group.container != container {
        return None;
    }
    Some(
        group
            .members
            .iter()
            .filter_map(|key| {
                let record = state.tasks.get(&key.id)?;
                (record.task.key() == *key
                    && record.task.lifecycle() == TaskLifecycle::Live
                    && record.task.container().id() == container
                    && record.task.process_group() == group_id)
                    .then_some(*key)
            })
            .collect(),
    )
}

pub(super) fn remove_group_member(
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
    state.remove_process_group(group_id);
    let remove_session = if let Some(session) = state.sessions.get_mut(&session_id) {
        session.process_groups.remove(&group_id);
        session.process_groups.is_empty()
    } else {
        false
    };
    if remove_session {
        state.remove_session(session_id);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::kernel::ids::LinuxSignal;
    use crate::kernel::objects::LinuxWaitStatus;
    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::clone_plan::ClonePlan;
    use crate::kernel::operations::tests::bootstrap;
    use crate::kernel::operations::{ProcessState, WaitMode, WaitOutcome};

    #[test]
    fn controlling_tty_uses_kernel_session_and_foreground_group() {
        let (kernel, root) = bootstrap(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
        kernel.initialize_launch_controlling_tty(&root);
        assert_eq!(
            kernel.tty_foreground_process_group(&root),
            Ok(root.task().process_group())
        );
        assert_eq!(kernel.tty_session(&root), Ok(root.task().session()));
        assert!(!kernel.tty_caller_is_background(&root));
        kernel.tty_detach(&root).expect("detach controlling tty");
        assert_eq!(
            kernel.tty_foreground_process_group(&root),
            Err(TtyControlError::NotControlling)
        );
        assert_eq!(
            kernel.tty_session(&root),
            Err(TtyControlError::NotControlling),
            "ordinary tty queries must not implicitly reacquire after TIOCNOTTY",
        );
    }

    #[test]
    fn non_session_leader_cannot_acquire_controlling_tty() {
        let (kernel, root) = bootstrap(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_011),
                "non-session-leader".to_string(),
                None,
            )
            .expect("fork child");

        assert_ne!(child.task().key().id.raw(), child.task().session().raw());
        assert_eq!(
            kernel.tty_acquire(&child, false),
            Err(TtyControlError::Permission),
        );
    }

    #[test]
    fn relay_signal_posts_to_exact_kernel_foreground_group() {
        let (kernel, root) = bootstrap(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
        kernel.initialize_launch_controlling_tty(&root);
        let winch = LinuxSignal::for_signal_number(carrick_abi::LINUX_SIGWINCH).expect("WINCH");
        assert_eq!(
            kernel.post_signal_to_tty_foreground(root.container().id(), winch),
            1
        );
        assert!(
            root.shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGWINCH)
        );
    }

    #[test]
    fn relay_signal_waits_for_controlling_foreground_group_then_flushes() {
        let (kernel, root) = bootstrap(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
        crate::kernel::tty::prepare();
        crate::kernel::tty::route_foreground_signal(carrick_abi::LINUX_SIGQUIT);
        crate::kernel::tty::install(&kernel);
        for signum in [
            carrick_abi::LINUX_SIGINT,
            carrick_abi::LINUX_SIGTSTP,
            carrick_abi::LINUX_SIGWINCH,
        ] {
            crate::kernel::tty::route_foreground_signal(signum);
        }
        assert!(
            !root
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGINT),
            "relay delivery must not guess before controlling-tty initialization",
        );

        kernel.initialize_launch_controlling_tty(&root);
        let present = root.shared().pending_signals().present();
        for signum in [
            carrick_abi::LINUX_SIGINT,
            carrick_abi::LINUX_SIGQUIT,
            carrick_abi::LINUX_SIGTSTP,
            carrick_abi::LINUX_SIGWINCH,
        ] {
            assert!(
                present.contains(signum),
                "the acknowledged foreground route must flush early signal {signum}",
            );
        }
    }

    #[test]
    fn two_containers_keep_independent_tty_state_and_relay_routes_exactly() {
        use crate::kernel::{Container, LaunchContext, RunId};

        let (kernel, alpha) = bootstrap(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
        let beta_container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "tty-beta",
        ))));
        let beta = kernel
            .prepare_container_root(
                ThreadId::synthetic_for_tests(9_012),
                None,
                "tty-beta-init".to_owned(),
                beta_container,
                None,
            )
            .expect("prepare beta root")
            .commit()
            .expect("publish beta root");

        crate::kernel::tty::prepare();
        crate::kernel::tty::install(&kernel);
        kernel.initialize_launch_controlling_tty(&alpha);
        crate::kernel::tty::route_foreground_signal(carrick_abi::LINUX_SIGINT);

        kernel.initialize_launch_controlling_tty(&beta);
        crate::kernel::tty::route_foreground_signal(carrick_abi::LINUX_SIGWINCH);

        assert_eq!(
            kernel.tty_foreground_process_group(&alpha),
            Ok(alpha.task().process_group()),
        );
        assert_eq!(kernel.tty_session(&alpha), Ok(alpha.task().session()));
        assert_eq!(
            kernel.tty_foreground_process_group(&beta),
            Ok(beta.task().process_group()),
        );
        assert_eq!(kernel.tty_session(&beta), Ok(beta.task().session()));

        let alpha_pending = alpha.shared().pending_signals().present();
        let beta_pending = beta.shared().pending_signals().present();
        assert!(alpha_pending.contains(carrick_abi::LINUX_SIGINT));
        assert!(!alpha_pending.contains(carrick_abi::LINUX_SIGWINCH));
        assert!(!beta_pending.contains(carrick_abi::LINUX_SIGINT));
        assert!(beta_pending.contains(carrick_abi::LINUX_SIGWINCH));
    }

    #[test]
    fn retiring_container_revokes_only_its_controlling_tty() {
        use crate::kernel::{Container, LaunchContext, RunId};

        let (kernel, alpha) = bootstrap(carrick_abi::LINUX_BOOTSTRAP_PID as i32);
        let beta_container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
            "retired-tty-beta",
        ))));
        let beta_id = beta_container.id();
        let beta = kernel
            .prepare_container_root(
                ThreadId::synthetic_for_tests(9_013),
                None,
                "retired-tty-beta-init".to_owned(),
                beta_container,
                None,
            )
            .expect("prepare beta root")
            .commit()
            .expect("publish beta root");

        kernel.initialize_launch_controlling_tty(&alpha);
        kernel.initialize_launch_controlling_tty(&beta);
        kernel
            .retire_container_root(beta_id, None)
            .expect("retire beta root");

        assert_eq!(
            kernel.tty_session(&beta),
            Err(TtyControlError::NotControlling),
        );
        assert_eq!(kernel.tty_session(&alpha), Ok(alpha.task().session()));
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

    /// `setsid(2)`: "EPERM — The process group ID of any process equals the
    /// PID of the calling process." LTP `setsid01` builds exactly that shape:
    /// a process makes itself a group leader, forks a child that STAYS in
    /// that group, moves itself back into its parent's group, then calls
    /// `setsid`. The caller is no longer a leader, so the leader check does
    /// not fire; the still-populated group whose id is the caller's pid is
    /// what must refuse, and it must refuse with EPERM, not EINVAL.
    #[test]
    fn setsid_refuses_with_eperm_while_a_group_named_by_the_caller_pid_survives() {
        let (kernel, root) = bootstrap(360);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let leader = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(361),
                "leader".to_string(),
                None,
            )
            .expect("leader child");
        let leader_id = leader.task.key().id;
        let own_group = kernel
            .create_process_group(leader_id, None)
            .expect("leader makes its own group");
        let refreshed_leader = kernel
            .context(leader_id, leader.thread.key().tid)
            .expect("refreshed leader context");
        let member = kernel
            .fork_task(
                &refreshed_leader,
                fork_plan,
                ThreadId::synthetic_for_tests(362),
                "member".to_string(),
                None,
            )
            .expect("member child");
        assert_eq!(member.task.process_group(), own_group);

        // `setpgid(0, getppid())`: the leader leaves, the member stays.
        kernel
            .set_process_group(leader_id, None, Some(root.task.process_group()))
            .expect("leader rejoins the parent's group");
        assert_eq!(
            kernel.registry().process_group_members(own_group),
            vec![member.task.key()]
        );

        let error = kernel
            .create_session(leader_id, None)
            .expect_err("a group named by the caller's pid still has a member");
        assert_eq!(
            crate::hvpatch::identity_operation_errno(error),
            crate::linux_abi::LINUX_EPERM
        );
        // Nothing moved: the caller keeps its identity and the group its member.
        assert_eq!(
            kernel.registry().process_group_members(own_group),
            vec![member.task.key()]
        );
        assert_eq!(
            kernel
                .registry()
                .process_group_members(root.task.process_group()),
            vec![root.task.key(), leader.task.key()]
        );
    }

    /// Two live processes must describe THEMSELVES, and an exited one must stay
    /// describable until it is reaped.
    ///
    /// Both halves are invisible with a single task. With one process the pid,
    /// the process group and the session are the same number, so "the answer is
    /// wrong" and "the answer is right" produce identical output — which is
    /// exactly how a constant standing where a per-process function belongs
    /// survived. The second child exists so the two groups can disagree, and
    /// the exit exists because `getpgid` on an unreaped child returned ESRCH
    /// while `Zombie::process_group` sat there unread.
    #[test]
    fn process_identity_answers_per_process_and_survives_exit() {
        let (kernel, root) = bootstrap(370);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let first = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(371),
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
                ThreadId::synthetic_for_tests(372),
                "second".to_string(),
                None,
            )
            .expect("second child");
        kernel
            .set_process_group(root.task.key().id, Some(first.task.key().id), None)
            .expect("give the first child its own group");

        let first_identity = kernel
            .process_identity(first.task.key().id)
            .expect("first child identity");
        let second_identity = kernel
            .process_identity(second.task.key().id)
            .expect("second child identity");

        // Relations, never absolute numbers: each child names ITSELF, both name
        // the same parent, and only the child that called setpgid left the
        // inherited group.
        assert_ne!(first_identity.pid, second_identity.pid);
        assert_eq!(first_identity.parent, Some(root.task.key().id));
        assert_eq!(second_identity.parent, Some(root.task.key().id));
        assert_eq!(
            first_identity.process_group,
            ProcessGroupId::from_leader(first.task.key().id)
        );
        assert_eq!(
            second_identity.process_group,
            kernel
                .process_identity(root.task.key().id)
                .expect("root identity")
                .process_group
        );
        assert_ne!(first_identity.process_group, second_identity.process_group);
        assert_eq!(first_identity.session, second_identity.session);
        assert_eq!(first_identity.state, ProcessState::Live);
        assert_eq!(second_identity.state, ProcessState::Live);

        kernel
            .prepare_task_exit(
                first.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .expect("prepare first child exit")
            .commit()
            .expect("commit first child exit");

        let zombie_identity = kernel
            .process_identity(first.task.key().id)
            .expect("an unreaped child is still addressable");
        assert_eq!(zombie_identity.state, ProcessState::Zombie);
        assert_eq!(zombie_identity.process_group, first_identity.process_group);
        assert_eq!(zombie_identity.session, first_identity.session);
        assert_eq!(zombie_identity.parent, first_identity.parent);
        // The live sibling is untouched by its sibling's exit.
        assert_eq!(
            kernel.process_identity(second.task.key().id),
            Some(second_identity)
        );

        assert!(matches!(
            kernel.wait_child(
                root.task.key().id,
                Some(first.task.key().id),
                WaitMode::Consume,
            ),
            Ok(WaitOutcome::Exited(_))
        ));
        assert_eq!(kernel.process_identity(first.task.key().id), None);
    }

    #[test]
    fn set_process_group_enforces_parent_session_and_group_policy_atomically() {
        let (kernel, root) = bootstrap(360);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let first = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(361),
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
                ThreadId::synthetic_for_tests(362),
                "second".to_string(),
                None,
            )
            .expect("second child");
        let first_group = ProcessGroupId::from_leader(first.task.key().id);

        kernel
            .set_process_group(root.task.key().id, Some(first.task.key().id), None)
            .expect("create child's group");
        kernel
            .set_process_group(
                root.task.key().id,
                Some(second.task.key().id),
                Some(first_group),
            )
            .expect("join sibling's group");
        assert_eq!(first.task.process_group(), first_group);
        assert_eq!(second.task.process_group(), first_group);
        assert_eq!(
            kernel.registry().process_group_members(first_group),
            vec![first.task.key(), second.task.key()]
        );

        let first_context = kernel
            .context(first.task.key().id, first.thread.key().tid)
            .expect("first child context");
        let grandchild = kernel
            .fork_task(
                &first_context,
                fork_plan,
                ThreadId::synthetic_for_tests(363),
                "grandchild".to_string(),
                None,
            )
            .expect("grandchild");
        assert!(matches!(
            kernel.set_process_group(
                root.task.key().id,
                Some(grandchild.task.key().id),
                None,
            ),
            Err(KernelOperationError::UnknownTask(task_id)) if task_id == grandchild.task.key().id
        ));
        assert!(matches!(
            kernel.set_process_group(
                root.task.key().id,
                Some(second.task.key().id),
                Some(ProcessGroupId::from_leader(grandchild.task.key().id)),
            ),
            Err(KernelOperationError::IdentityPermission)
        ));
        assert!(matches!(
            kernel.set_process_group(root.task.key().id, None, None),
            Err(KernelOperationError::IdentityPermission)
        ));
    }

    #[test]
    fn parent_cannot_change_process_group_after_child_exec() {
        let (kernel, root) = bootstrap(370);
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(371),
                "child".to_string(),
                None,
            )
            .expect("child");
        let prepared = kernel.prepare_exec(&child, None).expect("prepare exec");
        kernel.commit_exec(prepared, None).expect("commit exec");

        assert!(matches!(
            kernel.set_process_group(root.task.key().id, Some(child.task.key().id), None),
            Err(KernelOperationError::ChildExeced(task_id)) if task_id == child.task.key().id
        ));
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
}
