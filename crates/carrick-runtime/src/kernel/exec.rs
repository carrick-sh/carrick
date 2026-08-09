use std::sync::Arc;

use carrick_hal::KernelTransactionId;

use super::core::{Kernel, KernelContext, RetiredThreadRecord, TaskRevision};
use super::ids::LinuxTid;
use super::objects::{
    ExecDrain, ObjectGraphError, PreparedThreadSet, TaskKey, TaskShared, ThreadKey, ThreadRef,
    ThreadResources,
};
use super::operations::KernelFailpoint;

struct ExecReservation {
    kernel: Arc<Kernel>,
    task: TaskKey,
    transaction: KernelTransactionId,
    active: bool,
}

impl ExecReservation {
    fn commit(&mut self) {
        self.active = false;
    }
}

impl Drop for ExecReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.kernel.registry().state.write();
        if state.reservations.get(&self.task.id) == Some(&self.transaction) {
            state.reservations.remove(&self.task.id);
        }
    }
}

struct ExecOperationGuard {
    reservation: Option<ExecReservation>,
    drain: Option<ExecDrain>,
}

impl ExecOperationGuard {
    fn terminate_siblings(&mut self) {
        if let Some(drain) = self.drain.take() {
            drain.terminate_and_wait();
        }
    }

    fn commit_reservation(&mut self) {
        if let Some(mut reservation) = self.reservation.take() {
            reservation.commit();
        }
    }

    fn transaction(&self) -> Option<KernelTransactionId> {
        self.reservation
            .as_ref()
            .map(|reservation| reservation.transaction)
    }
}

impl Drop for ExecOperationGuard {
    fn drop(&mut self) {
        // Rollback order is load-bearing: runners resume and acknowledge that
        // they left the park before another task mutator may acquire the ID.
        if let Some(drain) = self.drain.take() {
            drain.resume_and_wait();
        }
        drop(self.reservation.take());
    }
}

/// Fully prepared exec replacement. Dropping it resumes stopped siblings and
/// releases the operation reservation without changing the published graph.
pub struct PreparedExec {
    guard: ExecOperationGuard,
    task: TaskKey,
    caller: ThreadKey,
    revision: TaskRevision,
    shared: Arc<TaskShared>,
    resources: Arc<ThreadResources>,
    old_caller: ThreadRef,
    replacement: ThreadRef,
    thread_set: PreparedThreadSet,
}

impl std::fmt::Debug for PreparedExec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedExec")
            .field("task", &self.task)
            .field("caller", &self.caller)
            .field("revision", &self.revision)
            .field("transaction", &self.guard.transaction())
            .finish_non_exhaustive()
    }
}

impl Kernel {
    pub fn prepare_exec(
        self: &Arc<Self>,
        context: &KernelContext,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<PreparedExec, ExecError> {
        self.sweep_retired_threads();
        if !Arc::ptr_eq(self, &context.kernel) {
            return Err(ExecError::ForeignContext);
        }
        let transaction = self.object_ids().transaction_id()?;
        {
            let mut state = self.registry().state.write();
            let record = state
                .tasks
                .get(&context.task.key().id)
                .ok_or(ExecError::TaskExited)?;
            let caller = record
                .task
                .thread(context.thread.key().tid)
                .ok_or(ExecError::CallerExited)?;
            if !Arc::ptr_eq(&record.task, &context.task)
                || !Arc::ptr_eq(&caller, &context.thread)
                || record.revision != context.revision
            {
                return Err(ExecError::ForeignContext);
            }
            if state.reservations.contains_key(&context.task.key().id) {
                return Err(ExecError::TaskBusy);
            }
            state
                .reservations
                .insert(context.task.key().id, transaction);
        }
        let reservation = ExecReservation {
            kernel: self.clone(),
            task: context.task.key(),
            transaction,
            active: true,
        };
        let mut guard = ExecOperationGuard {
            reservation: Some(reservation),
            drain: None,
        };
        check_exec_failpoint(failpoint, KernelFailpoint::AfterReserve)?;

        // Only the validated caller supplies exec survivors. K1 gives the new
        // image, staged file table, and caught-handler reset fresh identities;
        // fs context, credentials, and pending signals retain caller identity.
        let shared = Arc::new(TaskShared::for_exec(&context.shared, self.object_ids())?);
        let resources = Arc::new(ThreadResources::for_exec(
            &context.resources,
            self.object_ids(),
        )?);
        let leader_tid = LinuxTid::for_task_leader(context.task.key().id);
        let replacement = context.task.prepare_exec_thread(
            ThreadKey {
                tid: leader_tid,
                serial: self.object_ids().thread_serial()?,
            },
            context.thread.registry_id(),
            Arc::clone(&resources),
            &context.thread,
        );
        let thread_set = context
            .task
            .prepare_exec_thread_set(Arc::clone(&replacement))?;
        check_exec_failpoint(failpoint, KernelFailpoint::AfterObjects)?;

        guard.drain = Some(context.task.drain_exec_siblings(context.thread.key()));
        check_exec_failpoint(failpoint, KernelFailpoint::AfterBackendPrepare)?;
        Ok(PreparedExec {
            guard,
            task: context.task.key(),
            caller: context.thread.key(),
            revision: context.revision,
            shared,
            resources,
            old_caller: Arc::clone(&context.thread),
            replacement,
            thread_set,
        })
    }

    pub fn commit_exec(
        self: &Arc<Self>,
        mut prepared: PreparedExec,
        failpoint: Option<KernelFailpoint>,
    ) -> Result<KernelContext, ExecError> {
        let Some(reservation) = prepared.guard.reservation.as_ref() else {
            return Err(ExecError::ReservationLost);
        };
        if !Arc::ptr_eq(&reservation.kernel, self) {
            return Err(ExecError::ForeignPreparation);
        }
        let transaction = reservation.transaction;
        let leader_tid = LinuxTid::for_task_leader(prepared.task.id);
        let (task, revision) = {
            let mut state = self.registry().state.write();
            if state.reservations.get(&prepared.task.id) != Some(&transaction) {
                return Err(ExecError::ReservationLost);
            }
            let record = state
                .tasks
                .get(&prepared.task.id)
                .ok_or(ExecError::TaskExited)?;
            if record.task.key() != prepared.task || record.revision != prepared.revision {
                return Err(ExecError::StalePreparation);
            }
            let caller = record
                .task
                .thread(prepared.caller.tid)
                .ok_or(ExecError::CallerExited)?;
            if caller.key() != prepared.caller {
                return Err(ExecError::CallerExited);
            }
            if prepared.thread_set.task_key() != prepared.task {
                return Err(ExecError::WrongTask);
            }
            if !record.thread_claims.contains_key(&leader_tid) {
                return Err(ExecError::LeaderClaimMissing);
            }
            let retired_count = record.thread_claims.len().saturating_sub(1);
            let revision = record.revision.next().ok_or(ExecError::RevisionExhausted)?;
            let task = Arc::clone(&record.task);
            state
                .retired_threads
                .try_reserve_exact(retired_count)
                .map_err(|_| ExecError::RetiredThreadCapacity(retired_count))?;
            check_exec_failpoint(failpoint, KernelFailpoint::BeforePublish)?;
            (task, revision)
        };

        // This is the only blocking part of commit and happens with no kernel
        // object lock held. Publication below is then an infallible transition.
        prepared.guard.terminate_siblings();

        let mut state = self.registry().state.write();
        debug_assert_eq!(
            state.reservations.get(&prepared.task.id),
            Some(&transaction)
        );
        let super::core::RegistryState {
            tasks,
            retired_threads,
            reservations,
            ..
        } = &mut *state;
        let Some(record) = tasks.get_mut(&prepared.task.id) else {
            return Err(ExecError::InvariantLostAfterDrain);
        };
        debug_assert_eq!(record.task.key(), prepared.task);
        debug_assert_eq!(record.revision, prepared.revision);

        prepared
            .old_caller
            .transfer_runner_to(&prepared.replacement);
        let old_threads = record.task.publish_exec_thread_set(prepared.thread_set);
        record.task.replace_shared(Arc::clone(&prepared.shared));
        for (tid, (_, thread)) in &old_threads {
            if *tid == leader_tid {
                continue;
            }
            if let Some(claim) = record.thread_claims.remove(tid) {
                retired_threads.push(RetiredThreadRecord {
                    thread: Arc::downgrade(thread),
                    _claim: claim,
                });
            }
        }
        record.revision = revision;
        reservations.remove(&prepared.task.id);
        prepared.guard.commit_reservation();
        drop(state);
        drop(old_threads);

        Ok(KernelContext::from_parts(
            self.clone(),
            task,
            prepared.replacement,
            prepared.shared,
            prepared.resources,
            revision,
        ))
    }

    /// Release retired thread IDs after runner/context references drain. Every
    /// allocating or lifecycle operation calls this automatically.
    pub fn sweep_retired_threads(&self) -> usize {
        let mut state = self.registry().state.write();
        let before = state.retired_threads.len();
        state
            .retired_threads
            .retain(|retired| retired.thread.strong_count() != 0);
        before - state.retired_threads.len()
    }
}

fn check_exec_failpoint(
    selected: Option<KernelFailpoint>,
    point: KernelFailpoint,
) -> Result<(), ExecError> {
    if selected == Some(point) {
        return Err(ExecError::Injected(point));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error(transparent)]
    ObjectId(#[from] super::ids::ObjectIdError),
    #[error(transparent)]
    ObjectGraph(#[from] ObjectGraphError),
    #[error("kernel context is foreign or internally inconsistent")]
    ForeignContext,
    #[error("prepared exec belongs to another Kernel")]
    ForeignPreparation,
    #[error("task has another preparing operation")]
    TaskBusy,
    #[error("exec operation reservation was lost")]
    ReservationLost,
    #[error("task exited before exec commit")]
    TaskExited,
    #[error("exec reservation invariant was lost after sibling drain")]
    InvariantLostAfterDrain,
    #[error("exec caller exited before commit")]
    CallerExited,
    #[error("prepared exec targets another task")]
    WrongTask,
    #[error("prepared exec revision is stale")]
    StalePreparation,
    #[error("thread-group leader claim is missing")]
    LeaderClaimMissing,
    #[error("task revision space is exhausted")]
    RevisionExhausted,
    #[error("could not reserve {0} retired-thread records")]
    RetiredThreadCapacity(usize),
    #[error("injected exec failure at {0:?}")]
    Injected(KernelFailpoint),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use carrick_abi::{LinuxCloneFlags, SigSet};
    use carrick_hal::ThreadId;

    use super::*;
    use crate::kernel::{
        ClonePlan, Credentials, FileDescription, FileSlotNumber, FileTable, FsContext, LinuxSignal,
        LinuxWaitStatus, Mm, ObjectIdRegistry, RootBootstrap, Sighand, SignalDisposition,
        TaskRusage,
    };

    fn associations(ids: &ObjectIdRegistry) -> (Arc<TaskShared>, Arc<ThreadResources>) {
        (
            Arc::new(TaskShared::new(
                Arc::new(Mm::new_reference(ids.mm_id().expect("mm"))),
                Arc::new(Sighand::new(ids.sighand_id().expect("sighand"))),
            )),
            Arc::new(ThreadResources::new(
                Arc::new(FileTable::new(ids.file_table_id().expect("files"))),
                Arc::new(FsContext::new(ids.fs_context_id().expect("fs"))),
                Arc::new(Credentials::new()),
            )),
        )
    }

    fn spawn_active_runner(
        thread_ref: &ThreadRef,
        progress: Arc<AtomicUsize>,
        quit: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        let runner = thread_ref.bind_runner().expect("bind runner");
        thread::spawn(move || {
            loop {
                match runner.checkpoint() {
                    super::super::objects::RunnerDirective::Terminate => break,
                    super::super::objects::RunnerDirective::Continue
                    | super::super::objects::RunnerDirective::Resumed => {
                        progress.fetch_add(1, Ordering::Release);
                        if quit.load(Ordering::Acquire) {
                            break;
                        }
                        thread::yield_now();
                    }
                }
            }
        })
    }

    fn wait_for_progress(progress: &AtomicUsize, baseline: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while progress.load(Ordering::Acquire) == baseline {
            assert!(Instant::now() < deadline, "runner did not make progress");
            thread::yield_now();
        }
    }

    fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
        let ids = ObjectIdRegistry::new();
        let (shared, resources) = associations(&ids);
        let input = RootBootstrap::from_observed_pid(
            pid,
            ThreadId::synthetic_for_tests(pid),
            shared,
            resources,
            "root".to_string(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    #[test]
    fn nonleader_exec_replaces_thread_group_and_drains_old_objects() {
        let (kernel, leader) = bootstrap(600);
        let sibling = kernel
            .clone_thread(
                &leader,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(601),
                None,
            )
            .expect("sibling");
        let ignored = LinuxSignal::for_signal_number(2).expect("ignored signal");
        let caught = LinuxSignal::for_signal_number(3).expect("caught signal");
        leader
            .shared
            .sighand()
            .set_disposition(ignored, SignalDisposition::Ignore);
        leader
            .shared
            .sighand()
            .set_disposition(caught, SignalDisposition::Caught);
        let caller_signal_state = super::super::objects::ThreadSignalState::new(
            SigSet::EMPTY.with(4),
            SigSet::EMPTY.with(5),
            true,
            2,
        );
        sibling.thread.replace_signal_state(caller_signal_state);
        let surviving_description = Arc::new(FileDescription::regular(
            kernel
                .object_ids()
                .file_description_id()
                .expect("surviving description"),
        ));
        let cloexec_description = Arc::new(FileDescription::regular(
            kernel
                .object_ids()
                .file_description_id()
                .expect("CLOEXEC description"),
        ));
        let surviving_slot = FileSlotNumber::for_open_fd(3).expect("surviving slot");
        let cloexec_slot = FileSlotNumber::for_open_fd(4).expect("CLOEXEC slot");
        let caller_files = sibling.resources.files();
        let old_caller = Arc::downgrade(&sibling.thread);
        let mut caller_runner = sibling.thread.bind_runner().expect("caller runner");
        assert!(
            caller_files
                .install(surviving_slot, Arc::clone(&surviving_description), false,)
                .is_none()
        );
        assert!(
            caller_files
                .install(cloexec_slot, Arc::clone(&cloexec_description), true)
                .is_none()
        );
        drop(caller_files);
        let sibling_tid = sibling.thread.key().tid;
        let old_mm_id = leader.shared.mm().id();
        let old_sighand_id = leader.shared.sighand().id();
        let old_mm = Arc::downgrade(&leader.shared.mm());
        let old_files = Arc::downgrade(&sibling.resources.files());
        let caller_fs = sibling.resources.fs_context();
        let caller_credentials = sibling.resources.credentials();
        let pending = sibling.shared.pending_signals();
        let progress = Arc::new(AtomicUsize::new(0));
        let quit = Arc::new(AtomicBool::new(false));
        let runner = spawn_active_runner(&leader.thread, Arc::clone(&progress), quit);
        wait_for_progress(&progress, 0);
        let prepared = kernel.prepare_exec(&sibling, None).expect("prepare exec");
        let committed = kernel.commit_exec(prepared, None).expect("commit exec");
        runner.join().expect("old leader terminated");
        assert!(matches!(
            leader.thread.bind_runner(),
            Err(ObjectGraphError::RunnerDraining(_))
        ));
        assert!(matches!(
            sibling.thread.bind_runner(),
            Err(ObjectGraphError::RunnerOwnershipChanged(_))
        ));
        assert!(matches!(
            committed.thread.bind_runner(),
            Err(ObjectGraphError::RunnerAlreadyBound(_))
        ));

        assert_eq!(
            committed.thread.key().tid,
            LinuxTid::for_task_leader(committed.task.key().id)
        );
        assert_eq!(committed.task.live_thread_count(), 1);
        assert_ne!(committed.shared.mm().id(), old_mm_id);
        assert_ne!(committed.shared.sighand().id(), old_sighand_id);
        assert_eq!(
            committed.shared.sighand().disposition(ignored),
            SignalDisposition::Ignore
        );
        assert_eq!(
            committed.shared.sighand().disposition(caught),
            SignalDisposition::Default
        );
        let committed_signals = committed.thread.signal_state();
        assert_eq!(committed_signals.blocked(), caller_signal_state.blocked());
        assert_eq!(committed_signals.pending(), caller_signal_state.pending());
        assert!(!committed_signals.altstack_enabled());
        assert_eq!(committed_signals.handler_frame_depth(), 0);
        assert!(progress.load(Ordering::Acquire) != 0);
        assert!(Arc::ptr_eq(&committed.resources.fs_context(), &caller_fs));
        assert!(Arc::ptr_eq(
            &committed.resources.credentials(),
            &caller_credentials
        ));
        assert!(Arc::ptr_eq(&committed.shared.pending_signals(), &pending));
        assert_ne!(
            committed.resources.files().id(),
            old_files.upgrade().expect("old files").id()
        );
        let survivor = committed
            .resources
            .files()
            .slot(surviving_slot)
            .expect("surviving slot retained");
        assert!(Arc::ptr_eq(&survivor.description(), &surviving_description));
        assert!(!survivor.close_on_exec());
        assert!(committed.resources.files().slot(cloexec_slot).is_none());
        assert_eq!(committed.resources.files().slot_count(), 1);
        assert!(matches!(
            kernel.context(committed.task.key().id, sibling_tid),
            Err(super::super::core::KernelError::UnknownThread(_))
        ));
        assert_eq!(kernel.registry().retired_thread_count(), 1);
        assert!(old_mm.upgrade().is_some());
        assert!(old_files.upgrade().is_some());

        drop(leader);
        assert!(old_mm.upgrade().is_some());
        drop(sibling);
        assert!(old_caller.upgrade().is_some());
        assert!(old_mm.upgrade().is_none());
        assert!(old_files.upgrade().is_some());
        assert_eq!(kernel.sweep_retired_threads(), 0);
        caller_runner
            .adopt_thread(&committed.thread)
            .expect("caller runner adopts exec replacement");
        assert_eq!(caller_runner.key(), committed.thread.key());
        assert!(old_caller.upgrade().is_none());
        assert!(old_mm.upgrade().is_none());
        assert!(old_files.upgrade().is_none());
        kernel
            .reserve_task_operation(committed.task.key().id)
            .expect("next operation sweeps retired claims");
        assert_eq!(kernel.registry().retired_thread_count(), 0);
        drop(caller_runner);
        drop(
            committed
                .thread
                .bind_runner()
                .expect("replacement owns gate"),
        );
    }

    #[test]
    fn every_exec_failpoint_preserves_published_generation() {
        for point in [
            KernelFailpoint::AfterReserve,
            KernelFailpoint::AfterObjects,
            KernelFailpoint::AfterBackendPrepare,
            KernelFailpoint::BeforePublish,
        ] {
            let (kernel, context) = bootstrap(620);
            let old_shared = Arc::clone(&context.shared);
            let old_resources = Arc::clone(&context.resources);
            let counts = kernel.ids().counts();
            let revision = context.revision;
            let result = kernel.prepare_exec(&context, Some(point));
            if point == KernelFailpoint::BeforePublish {
                let prepared = result.expect("prepare before publish failpoint");
                assert!(matches!(
                    kernel.commit_exec(prepared, Some(point)),
                    Err(ExecError::Injected(p)) if p == point
                ));
            } else {
                assert!(matches!(result, Err(ExecError::Injected(p)) if p == point));
            }

            let current = kernel
                .context(context.task.key().id, context.thread.key().tid)
                .expect("unchanged context");
            assert_eq!(current.revision, revision);
            assert!(Arc::ptr_eq(&current.shared, &old_shared));
            assert!(Arc::ptr_eq(&current.resources, &old_resources));
            assert_eq!(kernel.ids().counts(), counts);
            assert_eq!(current.task.live_thread_count(), 1);
            assert_eq!(kernel.registry().retired_thread_count(), 0);
        }
    }

    #[test]
    fn reservations_block_mutation_and_foreign_preparations_fail_closed() {
        let (kernel, context) = bootstrap(640);
        let prepared = kernel.prepare_exec(&context, None).expect("preparation");
        assert!(matches!(
            kernel.clone_thread(
                &context,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(641),
                None,
            ),
            Err(super::super::operations::KernelOperationError::TaskBusy(_))
        ));
        drop(prepared);

        let foreign = kernel
            .prepare_exec(&context, None)
            .expect("foreign preparation");
        let (other, _) = bootstrap(640);
        assert!(matches!(
            other.commit_exec(foreign, None),
            Err(ExecError::ForeignPreparation)
        ));
    }

    #[test]
    fn exit_cannot_reparent_an_exec_reserved_child() {
        let (kernel, root) = bootstrap(650);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let parent = kernel
            .fork_task(
                &root,
                plan,
                ThreadId::synthetic_for_tests(651),
                "parent".to_string(),
                None,
            )
            .expect("parent");
        let child = kernel
            .fork_task(
                &parent,
                plan,
                ThreadId::synthetic_for_tests(652),
                "child".to_string(),
                None,
            )
            .expect("child");
        let prepared = kernel.prepare_exec(&child, None).expect("child exec");

        assert!(matches!(
            kernel.exit_task(
                parent.task.key().id,
                LinuxWaitStatus::from_wait_encoding(0),
                TaskRusage::default(),
                None,
            ),
            Err(super::super::operations::KernelOperationError::TaskBusy(id))
                if id == child.task.key().id
        ));
        drop(prepared);
        kernel.validate_invariants().expect("rollback invariants");
    }

    #[test]
    fn dropped_preparation_resumes_active_sibling_before_releasing_reservation() {
        let (kernel, leader) = bootstrap(660);
        let sibling = kernel
            .clone_thread(
                &leader,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .expect("thread plan"),
                ThreadId::synthetic_for_tests(661),
                None,
            )
            .expect("sibling");
        let leader = kernel
            .context(leader.task.key().id, leader.thread.key().tid)
            .expect("refreshed leader");
        let progress = Arc::new(AtomicUsize::new(0));
        let quit = Arc::new(AtomicBool::new(false));
        let runner = spawn_active_runner(&sibling.thread, Arc::clone(&progress), Arc::clone(&quit));
        wait_for_progress(&progress, 0);

        let prepared = kernel.prepare_exec(&leader, None).expect("prepare");
        assert!(matches!(
            kernel.reserve_task_operation(leader.task.key().id),
            Err(super::super::operations::KernelOperationError::TaskBusy(_))
        ));
        let parked_progress = progress.load(Ordering::Acquire);
        drop(prepared);
        wait_for_progress(&progress, parked_progress);
        kernel
            .reserve_task_operation(leader.task.key().id)
            .expect("reservation released after runner resumed");

        quit.store(true, Ordering::Release);
        runner.join().expect("resumed runner exits normally");
    }
}
