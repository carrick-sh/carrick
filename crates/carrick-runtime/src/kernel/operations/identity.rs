//! Task and process identity, credentials, and umask operations.
//!
//! Governs live and zombie process identity lookup, parentage tracking,
//! credential updates (COW), and umask synchronization across `CLONE_FS` peers.

use std::sync::Arc;

use carrick_fatal::carrick_fatal;

use super::{KernelOperationError, ensure_task_unreserved};
use crate::kernel::core::{Kernel, KernelContext};
use crate::kernel::ids::{LinuxTid, MmId, ProcessGroupId, SessionId, TaskId};
use crate::kernel::objects::{Credentials, Task, TaskKey, TaskLifecycle, TaskRef};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Observable identity of one exact task generation.
///
/// Keys, not bare numbers. A Linux TGID is reused within a run and an ASID is
/// recycled on exit, so `(pid, asid)` cannot distinguish two generations that
/// share a number — the ambiguity K1's observability contract forbids. The
/// `TaskSerial` inside each key is never reused by one Kernel, so a consumer
/// joining lifecycle records can always tell "the same task again" from "a
/// different task wearing the same pid".
pub struct TaskIdentity {
    pub task: TaskKey,
    pub parent: Option<TaskKey>,
    pub mm: MmId,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
}

/// Whether a Linux process is still running or has exited and is waiting to be
/// reaped. Both are addressable: `wait(2)` is what removes a process from the
/// table, not `_exit(2)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessState {
    Live,
    Zombie,
}

/// Everything a guest-visible "who is that process?" question needs:
/// `getpgid`, `getsid`, `getppid`, and `/proc/<pid>/stat` fields 4-6.
///
/// Distinct from [`TaskIdentity`], which describes one exact LIVE task
/// generation for the fork/exit machinery. The two differ on the case that
/// matters here: Linux keeps an exited-but-unreaped child fully addressable, so
/// `getpgid(child)` after the child `_exit`s reports the child's group where a
/// live-only lookup reports ESRCH.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    pub pid: TaskId,
    pub parent: Option<TaskId>,
    pub process_group: ProcessGroupId,
    pub session: SessionId,
    pub namespace_process_group: u32,
    pub namespace_session: u32,
    pub state: ProcessState,
}

impl Kernel {
    pub fn task_identity(&self, task_id: TaskId) -> Result<TaskIdentity, KernelOperationError> {
        let state = self.registry().state.read();
        let record = state
            .tasks
            .get(&task_id)
            .ok_or(KernelOperationError::UnknownTask(task_id))?;
        Ok(TaskIdentity {
            task: record.task.key(),
            parent: record.task.parent(),
            mm: record.task.shared().mm().id(),
            process_group: record.task.process_group(),
            session: record.task.session(),
        })
    }

    /// Resolve one guest pid to the identity tuple every guest-visible "who is
    /// that process?" answer is built from — live or unreaped zombie.
    ///
    /// This is deliberately the ONE accessor for that question. `getpgid`,
    /// `getsid` and `/proc/<pid>/stat` each used to reach for their own lookup,
    /// which is how they came to disagree about the same process; sharing this
    /// makes disagreement unrepresentable.
    ///
    /// The zombie arm is the behaviour change. [`Zombie`] has carried
    /// `process_group` and `session` since it was introduced and nothing ever
    /// read them, so a guest that had not yet reaped a child and asked
    /// `getpgid(child)` got ESRCH — Linux answers with the group the child was
    /// in, because `wait(2)`, not `_exit(2)`, is what removes a process from
    /// the table. Job-control shells rely on that: they look up a stopped or
    /// exited member's group before reaping it.
    pub(crate) fn process_identity(&self, task_id: TaskId) -> Option<ProcessIdentity> {
        let state = self.registry().state.read();
        if let Some(record) = state.tasks.get(&task_id) {
            let container = record.task.container().id();
            let process_group = record.task.process_group();
            let session = record.task.session();
            let namespace_process_group = state
                .process_groups
                .get(&process_group)
                .filter(|group| group.container == container)
                .map(|group| group.namespace_id)?;
            let namespace_session = state
                .sessions
                .get(&session)
                .filter(|session| session.container == container)
                .map(|session| session.namespace_id)?;
            return Some(ProcessIdentity {
                pid: task_id,
                parent: record.task.parent().map(|parent| parent.id),
                process_group,
                session,
                namespace_process_group,
                namespace_session,
                state: ProcessState::Live,
            });
        }
        state.zombies.get(&task_id).map(|record| ProcessIdentity {
            pid: task_id,
            parent: record.zombie.parent.map(|parent| parent.id),
            process_group: record.zombie.process_group,
            session: record.zombie.session,
            namespace_process_group: record.zombie.namespace_process_group,
            namespace_session: record.zombie.namespace_session,
            state: ProcessState::Zombie,
        })
    }

    /// Resolve the authoritative current parent of one exact task generation.
    /// Runtime notification routing uses this immediately before exit
    /// publication so CLONE_PARENT and orphan reparenting cannot target a stale
    /// creator captured at fork time.
    pub fn task_parent_key(&self, task: TaskKey) -> Result<Option<TaskKey>, KernelOperationError> {
        let state = self.registry().state.read();
        let record = state
            .tasks
            .get(&task.id)
            .ok_or(KernelOperationError::UnknownTask(task.id))?;
        if record.task.key() != task {
            return Err(KernelOperationError::StaleTaskGeneration(task.id));
        }
        Ok(record.task.parent())
    }

    pub fn task_is_live(&self, task_id: TaskId) -> bool {
        self.registry().state.read().tasks.contains_key(&task_id)
    }

    /// Resolve a task id to the LIVE task itself, for the callers that must
    /// read or write another process's per-task state rather than just test a
    /// property of it.
    ///
    /// This answers "which task is it", which is what `prlimit(pid, …)` needs
    /// — Linux lets one process
    /// write another's limits, so there has to be a path from the caller to the
    /// target's state. There was none: rlimits lived in the dispatcher's private
    /// `ProcState`, so the write landed on whoever called.
    pub(crate) fn live_task(&self, task_id: TaskId) -> Option<TaskRef> {
        let state = self.registry().state.read();
        state.tasks.get(&task_id).and_then(|record| {
            (record.task.lifecycle() == TaskLifecycle::Live).then(|| Arc::clone(&record.task))
        })
    }

    pub(crate) fn live_task_key(&self, task_id: TaskId) -> Option<TaskKey> {
        let state = self.registry().state.read();
        state.tasks.get(&task_id).and_then(|record| {
            (record.task.lifecycle() == TaskLifecycle::Live).then(|| record.task.key())
        })
    }

    /// Resolve a task's exact parent at the moment a waitable state change has
    /// already been published. The registry lock is released before callers
    /// invoke the lane waker.
    pub(crate) fn current_parent_task(&self, task: &Task) -> Option<TaskRef> {
        let state = self.registry().state.read();
        task.parent()
            .and_then(|key| state.tasks.get(&key.id).map(|record| (key, record)))
            .filter(|(key, record)| record.task.key() == *key)
            .map(|(_, record)| Arc::clone(&record.task))
    }

    pub fn task_key_is_live(&self, task: TaskKey) -> bool {
        self.registry()
            .state
            .read()
            .tasks
            .get(&task.id)
            .is_some_and(|record| record.task.key() == task)
    }

    pub fn task_exists(&self, task_id: TaskId) -> bool {
        let state = self.registry().state.read();
        state.tasks.contains_key(&task_id) || state.zombies.contains_key(&task_id)
    }

    /// Publish an immutable credential COW for exactly the calling thread.
    ///
    /// The captured resource bundle is validated under the registry write lock,
    /// then replaced with one `ArcSwap` publication. Sibling threads retain
    /// their prior credentials and in-flight syscalls retain their captured
    /// coherent bundle.
    pub fn update_credentials(
        self: &Arc<Self>,
        context: &KernelContext,
        update: impl FnOnce(&mut Credentials),
    ) -> Result<KernelContext, KernelOperationError> {
        if !Arc::ptr_eq(self, &context.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        let task_id = context.task.key().id;
        let mut update = Some(update);
        loop {
            let observed = self.reservation_epoch();
            let state = self.registry().state.write();
            if let Err(KernelOperationError::TaskBusy(_)) = ensure_task_unreserved(&state, task_id)
            {
                drop(state);
                self.wait_for_reservation_change(observed);
                continue;
            }
            ensure_task_unreserved(&state, task_id)?;
            let record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::ParentExited)?;
            if record.task.key() != context.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            let thread = record.task.thread(context.thread.key().tid).ok_or(
                KernelOperationError::UnknownThread(context.thread.key().tid),
            )?;
            if thread.key() != context.thread.key()
                || !Arc::ptr_eq(&thread, &context.thread)
                || !Arc::ptr_eq(&thread.resources(), &context.resources)
            {
                return Err(KernelOperationError::StaleContext);
            }

            let mut credentials = Credentials::for_copy(
                self.object_ids().credentials_id()?,
                &context.resources.credentials(),
            );
            update.take().ok_or(KernelOperationError::StaleContext)?(&mut credentials);
            let resources = Arc::new(context.resources.with_credentials(Arc::new(credentials)));
            // `TaskRevision` protects task topology and shared process state.
            // A thread-local credential COW changes neither; the exact
            // `ThreadResources` pointer and stable credential identity are the
            // publication generation for this association.
            let revision = record.revision;
            let task = Arc::clone(&record.task);
            thread.replace_resources(Arc::clone(&resources));
            if thread.key().tid == LinuxTid::for_task_leader(task_id) {
                task.replace_process_credentials(resources.credentials());
            }
            self.observe_thread_publication(&thread, &resources, revision);
            return Ok(KernelContext::from_parts(
                self.clone(),
                task,
                thread,
                Arc::clone(&context.shared),
                resources,
                revision,
            ));
        }
    }

    /// Publish one Linux umask change across every live thread that shares the
    /// caller's exact `FsContext`. Umask remains a typed `Credentials` value,
    /// but `CLONE_FS` defines its sharing domain; each affected thread receives
    /// a fresh credential register file preserving that thread's independent
    /// uid/gid state.
    pub fn update_fs_umask(
        self: &Arc<Self>,
        context: &KernelContext,
        umask: u32,
    ) -> Result<(KernelContext, u32), KernelOperationError> {
        if !Arc::ptr_eq(self, &context.kernel) {
            return Err(KernelOperationError::ForeignContext);
        }
        let task_id = context.task.key().id;
        loop {
            let observed = self.reservation_epoch();
            let state = self.registry().state.write();
            match ensure_task_unreserved(&state, task_id) {
                Ok(()) => {}
                Err(KernelOperationError::TaskBusy(_)) => {
                    drop(state);
                    self.wait_for_reservation_change(observed);
                    continue;
                }
                Err(error) => return Err(error),
            }
            let caller_record = state
                .tasks
                .get(&task_id)
                .ok_or(KernelOperationError::ParentExited)?;
            if caller_record.task.key() != context.task.key() {
                return Err(KernelOperationError::ParentExited);
            }
            let caller_thread = caller_record.task.thread(context.thread.key().tid).ok_or(
                KernelOperationError::UnknownThread(context.thread.key().tid),
            )?;
            if caller_thread.key() != context.thread.key()
                || !Arc::ptr_eq(&caller_thread, &context.thread)
            {
                return Err(KernelOperationError::StaleContext);
            }

            // A concurrent CLONE_FS peer may have published a newer resource
            // generation after syscall entry. Retry from that authoritative
            // generation while the registry is locked, but only while the
            // exact caller still belongs to the captured FS domain. Copying
            // each thread's current credentials below preserves unrelated
            // concurrent credential changes rather than overwriting them.
            let fs_context = context.resources.fs_context();
            let caller_resources = caller_thread.resources();
            if !Arc::ptr_eq(&caller_resources.fs_context(), &fs_context) {
                return Err(KernelOperationError::StaleContext);
            }
            let previous_umask = caller_resources.credentials().umask();
            let mut affected = Vec::new();
            for record in state.tasks.values() {
                if record.task.lifecycle() != TaskLifecycle::Live {
                    continue;
                }
                for thread in record.task.threads() {
                    let resources = thread.resources();
                    if Arc::ptr_eq(&resources.fs_context(), &fs_context) {
                        affected.push((
                            record.task.key().id,
                            record.revision,
                            Arc::clone(&record.task),
                            thread,
                            resources,
                        ));
                    }
                }
            }

            if let Some(busy) = affected.iter().find_map(|(affected_task, ..)| {
                ensure_task_unreserved(&state, *affected_task).err()
            }) {
                if matches!(busy, KernelOperationError::TaskBusy(_)) {
                    drop(state);
                    self.wait_for_reservation_change(observed);
                    continue;
                }
                return Err(busy);
            }

            let mut prepared = Vec::with_capacity(affected.len());
            for (_, revision, task, thread, resources) in affected {
                let mut credentials = Credentials::for_copy(
                    self.object_ids().credentials_id()?,
                    &resources.credentials(),
                );
                credentials.set_umask(umask);
                let replacement = Arc::new(resources.with_credentials(Arc::new(credentials)));
                prepared.push((revision, task, thread, replacement));
            }

            if !prepared
                .iter()
                .any(|(_, _, thread, _)| thread.key() == context.thread.key())
            {
                return Err(KernelOperationError::StaleContext);
            }
            let mut caller_publication = None;
            for (revision, task, thread, replacement) in prepared {
                thread.replace_resources(Arc::clone(&replacement));
                self.observe_thread_publication(&thread, &replacement, revision);
                if thread.key() == context.thread.key() {
                    caller_publication = Some((revision, task, thread, replacement));
                }
            }
            let Some((revision, task, thread, resources)) = caller_publication else {
                tracing::error!("umask publication lost its already-validated caller");
                carrick_fatal!(
                    "kernel::fs_context_publication",
                    "umask publication lost its already-validated caller"
                );
            };
            return Ok((
                KernelContext::from_parts(
                    self.clone(),
                    task,
                    thread,
                    Arc::clone(&context.shared),
                    resources,
                    revision,
                ),
                previous_umask,
            ));
        }
    }
}

/// Namespace-visible pid for a live task, used when that task creates a
/// process-group or session whose name must outlive the task's own PID slot.
pub(in crate::kernel) fn namespace_visible_task_id(
    task: &TaskRef,
) -> Result<u32, KernelOperationError> {
    let internal = u32::try_from(task.key().id.raw())
        .map_err(|_| KernelOperationError::PidNamespaceMembership(task.key().id))?;
    match task.pid_ns_region() {
        Some(region) => region
            .host_to_ns(internal)
            .ok_or(KernelOperationError::PidNamespaceMembership(task.key().id)),
        None => Ok(internal),
    }
}

#[cfg(test)]
mod tests {
    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;

    use crate::kernel::clone_plan::ClonePlan;
    use crate::kernel::operations::tests::bootstrap;

    #[test]
    fn umask_updates_every_live_clone_fs_peer_without_sharing_identity() {
        let (kernel, root) = bootstrap(79);
        let shared = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::FS).expect("CLONE_FS plan"),
                ThreadId::synthetic_for_tests(9_081),
                "shared-fs".to_string(),
                None,
            )
            .expect("shared-FS child");
        let root_after_shared_fork = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("root after shared-FS fork");
        let private = kernel
            .fork_task(
                &root_after_shared_fork,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(9_082),
                "private-fs".to_string(),
                None,
            )
            .expect("private-FS child");
        let shared = kernel
            .update_credentials(&shared, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(1001), carrick_abi::NsGid::new(2001));
            })
            .expect("independent child identity");
        let root_context = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("fresh root context");
        let (_, previous) = kernel
            .update_fs_umask(&root_context, 0o077)
            .expect("publish shared umask");
        assert_eq!(previous, 0o022);
        // The exact syscall-entry context is now a stale resource generation.
        // A serialized CLONE_FS peer update must retry against the current
        // authoritative generation and return that generation's previous mask.
        let (_, previous) = kernel
            .update_fs_umask(&root_context, 0o027)
            .expect("retry stale shared-FS generation");
        assert_eq!(previous, 0o077);

        let root_after = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("root after umask");
        let shared_after = shared
            .task_binding()
            .capture(shared.thread().key().tid)
            .expect("shared peer after umask");
        let private_after = private
            .task_binding()
            .capture(private.thread().key().tid)
            .expect("private peer after umask");
        assert_eq!(root_after.resources().credentials().umask(), 0o027);
        assert_eq!(shared_after.resources().credentials().umask(), 0o027);
        assert_eq!(
            shared_after.resources().credentials().euid(),
            carrick_abi::NsUid::new(1001)
        );
        assert_eq!(private_after.resources().credentials().umask(), 0o022);
    }
}

#[cfg(test)]
mod credential_authority_tests {
    use super::*;
    use crate::kernel::{ClonePlan, Kernel, RootBootstrap};
    use carrick_abi::LinuxCloneFlags;
    use carrick_hal::ThreadId;
    use std::sync::Arc;

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        Kernel::bootstrap_root(
            RootBootstrap::for_reference_model(
                pid,
                ThreadId::synthetic_for_tests(pid),
                "credential-authority-test".to_owned(),
            )
            .expect("bootstrap input"),
        )
        .expect("bootstrap")
    }

    #[test]
    fn sibling_thread_credential_cow_diverges_only_calling_thread() {
        let (kernel, root) = bootstrap(8_100);
        let root = kernel
            .update_credentials(&root, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(1000))
            })
            .expect("seed root credentials");
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::VM
                | LinuxCloneFlags::SIGHAND
                | LinuxCloneFlags::THREAD
                | LinuxCloneFlags::FILES
                | LinuxCloneFlags::FS,
        )
        .expect("thread clone plan");
        let sibling = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_101), None)
            .expect("clone thread");
        assert_ne!(
            root.resources().credentials().id(),
            sibling.resources().credentials().id()
        );

        let sibling = kernel
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(2000));
                credentials.set_supplementary_groups(vec![
                    carrick_abi::NsGid::new(7),
                    carrick_abi::NsGid::new(11),
                ]);
            })
            .expect("publish sibling credentials");
        assert_eq!(
            root.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(1000)
        );
        assert_eq!(
            root.resources()
                .credentials()
                .supplementary_groups_override(),
            None
        );
        assert_eq!(
            sibling.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(2000)
        );
        assert_eq!(
            sibling
                .resources()
                .credentials()
                .supplementary_groups_override(),
            Some([carrick_abi::NsGid::new(7), carrick_abi::NsGid::new(11)].as_slice())
        );
        let fresh_root = kernel
            .context(root.task().key().id, root.thread().key().tid)
            .expect("fresh root context");
        assert_eq!(
            fresh_root.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(1000)
        );
    }

    #[test]
    fn fork_copies_values_with_distinct_credential_identity() {
        let (kernel, root) = bootstrap(8_200);
        let root = kernel
            .update_credentials(&root, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(123), carrick_abi::NsGid::new(456));
                credentials.set_fsuid(carrick_abi::NsUid::new(321));
                credentials.set_fsgid(carrick_abi::NsGid::new(654));
                credentials.set_umask(0o077);
                credentials.set_supplementary_groups(vec![
                    carrick_abi::NsGid::new(2),
                    carrick_abi::NsGid::new(4),
                    carrick_abi::NsGid::new(8),
                ]);
            })
            .expect("seed parent credentials");
        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(8_201),
                "credential-child".to_owned(),
                None,
            )
            .expect("fork task");
        let parent = root.resources().credentials();
        let child = child.resources().credentials();
        assert_ne!(parent.id(), child.id());
        assert_eq!(
            parent.supplementary_groups_override(),
            child.supplementary_groups_override()
        );
        assert_eq!(
            child.supplementary_groups_override(),
            Some(
                [
                    carrick_abi::NsGid::new(2),
                    carrick_abi::NsGid::new(4),
                    carrick_abi::NsGid::new(8)
                ]
                .as_slice()
            )
        );
        assert_eq!(
            (
                parent.ruid(),
                parent.egid(),
                parent.fsuid(),
                parent.fsgid(),
                parent.umask()
            ),
            (
                child.ruid(),
                child.egid(),
                child.fsuid(),
                child.fsgid(),
                child.umask()
            )
        );
    }

    #[test]
    fn fork_from_nonleader_copies_the_callers_divergent_credentials() {
        let (kernel, root) = bootstrap(8_250);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::VM
                | LinuxCloneFlags::SIGHAND
                | LinuxCloneFlags::THREAD
                | LinuxCloneFlags::FILES
                | LinuxCloneFlags::FS,
        )
        .expect("thread clone plan");
        let sibling = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_251), None)
            .expect("clone sibling");
        let sibling = kernel
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(9250));
                credentials.set_supplementary_groups(vec![
                    carrick_abi::NsGid::new(25),
                    carrick_abi::NsGid::new(26),
                ]);
            })
            .expect("diverge sibling credentials");

        let child = kernel
            .fork_task(
                &sibling,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(8_252),
                "nonleader-credential-child".to_owned(),
                None,
            )
            .expect("fork from sibling");

        assert_eq!(
            root.resources().credentials().fsuid(),
            carrick_abi::NsUid::ROOT
        );
        assert_eq!(
            child.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(9250)
        );
        assert_eq!(
            child
                .resources()
                .credentials()
                .supplementary_groups_override(),
            Some([carrick_abi::NsGid::new(25), carrick_abi::NsGid::new(26)].as_slice())
        );
    }

    #[test]
    fn sibling_credential_publication_does_not_stale_exact_fork_caller() {
        let (kernel, root) = bootstrap(8_275);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::VM
                | LinuxCloneFlags::SIGHAND
                | LinuxCloneFlags::THREAD
                | LinuxCloneFlags::FILES
                | LinuxCloneFlags::FS,
        )
        .expect("thread clone plan");
        let sibling = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_276), None)
            .expect("clone sibling");
        let root = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("refresh root after thread clone");
        kernel
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(9275));
            })
            .expect("diverge sibling credentials");

        let child = kernel
            .fork_task(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                ThreadId::synthetic_for_tests(8_277),
                "exact-root-credential-child".to_owned(),
                None,
            )
            .expect("fork exact root after sibling publication");

        assert_eq!(
            child.resources().credentials().fsuid(),
            carrick_abi::NsUid::ROOT
        );
    }

    #[test]
    fn exec_retains_callers_credential_object() {
        let (kernel, root) = bootstrap(8_300);
        let root = kernel
            .update_credentials(&root, |credentials| {
                credentials.seed_identity(carrick_abi::NsUid::new(77), carrick_abi::NsGid::new(88));
                credentials.set_supplementary_groups(Vec::new());
            })
            .expect("seed credentials");
        let before = root.resources().credentials();
        let committed = kernel
            .commit_exec(
                kernel.prepare_exec(&root, None).expect("prepare exec"),
                None,
            )
            .expect("commit exec");
        let after = committed.resources().credentials();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(
            (after.ruid(), after.rgid()),
            (carrick_abi::NsUid::new(77), carrick_abi::NsGid::new(88))
        );
        assert_eq!(after.supplementary_groups_override(), Some([].as_slice()));
    }

    #[test]
    fn replaced_callers_resources_reject_stale_exec_context() {
        let (kernel, root) = bootstrap(8_315);
        kernel
            .update_credentials(&root, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(9315));
            })
            .expect("replace caller credentials");

        assert!(matches!(
            kernel.prepare_exec(&root, None),
            Err(crate::kernel::ExecError::ForeignContext)
        ));
    }

    #[test]
    fn sibling_credential_publication_does_not_stale_exact_exec_caller() {
        let (kernel, root) = bootstrap(8_325);
        let plan = ClonePlan::from_flags(
            LinuxCloneFlags::VM
                | LinuxCloneFlags::SIGHAND
                | LinuxCloneFlags::THREAD
                | LinuxCloneFlags::FILES
                | LinuxCloneFlags::FS,
        )
        .expect("thread clone plan");
        let sibling = kernel
            .clone_thread(&root, plan, ThreadId::synthetic_for_tests(8_326), None)
            .expect("clone sibling");
        let root = root
            .task_binding()
            .capture(root.thread().key().tid)
            .expect("refresh root after thread clone");
        kernel
            .update_credentials(&sibling, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(9325));
            })
            .expect("diverge sibling credentials");

        let prepared = kernel
            .prepare_exec(&root, None)
            .expect("prepare exec from exact root after sibling publication");
        let exec = kernel.commit_exec(prepared, None).expect("commit exec");

        assert_eq!(
            exec.resources().credentials().fsuid(),
            carrick_abi::NsUid::ROOT
        );
    }

    #[test]
    fn credential_publication_waits_for_task_reservation_without_recapture() {
        let (kernel, root) = bootstrap(8_350);
        let reservation = kernel
            .reserve_fork(
                &root,
                ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan"),
                "credential-reservation-child".to_owned(),
                None,
            )
            .expect("hold task reservation");
        let exact = root.retain_exact();
        let updating = Arc::clone(&kernel);
        let (sent, received) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = updating.update_credentials(&exact, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(8350));
            });
            sent.send(result).unwrap();
        });

        assert!(matches!(
            received.recv_timeout(std::time::Duration::from_millis(20)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        drop(reservation);
        let updated = received
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("credential publication wakes")
            .expect("credential publication succeeds");
        worker.join().unwrap();
        assert_eq!(
            updated.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(8350)
        );
    }

    #[test]
    fn stale_context_cannot_publish_credentials() {
        let (kernel, original) = bootstrap(8_400);
        let current = kernel
            .update_credentials(&original, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(42))
            })
            .expect("publish current credentials");

        assert!(matches!(
            kernel.update_credentials(&original, |credentials| {
                credentials.set_fsuid(carrick_abi::NsUid::new(99))
            }),
            Err(KernelOperationError::StaleContext)
        ));
        assert_eq!(
            current.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(42)
        );
        let fresh = kernel
            .context(current.task().key().id, current.thread().key().tid)
            .expect("fresh context");
        assert_eq!(
            fresh.resources().credentials().fsuid(),
            carrick_abi::NsUid::new(42)
        );
    }
}
