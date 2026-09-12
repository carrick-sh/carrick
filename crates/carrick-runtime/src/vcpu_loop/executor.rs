//! Persistent owner-thread executor pool used to prove the HVPatch M:N
//! lifecycle before a real HVF backend is wired to it.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, mpsc};

use crate::kernel::objects::{
    BlockedReason, ExecutionFailure, ExecutionGeneration, ExecutorId, ThreadKey,
};
use crate::kernel::{ExecutorKick, Scheduler, SettlementDisposition};
#[cfg(test)]
use crate::trap::TrapError;
use carrick_fatal::carrick_fatal;

pub mod binding;
pub use binding::*;

pub mod settlement;
pub use settlement::*;

pub mod backend;
pub use backend::*;

pub mod pool;
pub use pool::*;

pub(crate) fn probe_executor_lifecycle(
    executor: ExecutorId,
    phase: crate::probes::HvpatchExecutorLifecyclePhase,
    thread: Option<ThreadKey>,
    generation: Option<ExecutionGeneration>,
    asid_generation: u64,
) {
    crate::probes::hvpatch_executor_lifecycle(
        executor.raw_for_probe(),
        phase,
        thread.map_or(0, |key| key.serial.raw()),
        generation.map_or(0, ExecutionGeneration::raw),
        asid_generation,
    );
}

pub(crate) fn executor_worker<F, R>(
    slot: WorkerSlot,
    scheduler: Arc<Scheduler>,
    factory: Arc<F>,
    resolver: Arc<R>,
    receipts: Arc<ReceiptLog>,
    control: Arc<PoolControl>,
    channels: WorkerChannels,
) -> WorkerOutcome
where
    F: PersistentExecutorFactory,
    R: TaskBindingResolver<
        <<F as PersistentExecutorFactory>::Executor as PersistentExecutor>::TaskBinding,
    >,
{
    let WorkerSlot { index, is_spare } = slot;
    let WorkerChannels { commands, startup } = channels;
    if !matches!(commands.recv(), Ok(WorkerCommand::Initialize)) {
        return WorkerOutcome {
            executor: None,
            failure: None,
            retired: false,
        };
    }
    let kick = Arc::new(WorkerKick::new(Arc::clone(&receipts)));
    let registration = match scheduler.register_executor_bound(
        Arc::clone(&kick) as Arc<dyn ExecutorKick>,
        None,
        is_spare,
    ) {
        Ok(registration) => registration,
        Err(error) => {
            let _ = startup.send(StartupStatus {
                index,
                error: Some(error.to_string()),
                executor: None,
                kick: None,
            });
            return WorkerOutcome {
                executor: None,
                failure: Some(error.to_string()),
                retired: true,
            };
        }
    };
    let executor_id = registration.id();
    let mut backend = match catch_unwind(AssertUnwindSafe(|| factory.create(executor_id))) {
        Ok(Ok(backend)) => backend,
        Ok(Err(error)) => {
            let _ = scheduler.unregister_executor(&registration);
            let _ = startup.send(StartupStatus {
                index,
                error: Some(error.to_string()),
                executor: Some(executor_id),
                kick: None,
            });
            return WorkerOutcome {
                executor: Some(executor_id),
                failure: Some(error.to_string()),
                retired: true,
            };
        }
        Err(_) => {
            let _ = scheduler.unregister_executor(&registration);
            let message = "executor factory panicked".to_owned();
            let _ = startup.send(StartupStatus {
                index,
                error: Some(message.clone()),
                executor: Some(executor_id),
                kick: None,
            });
            return WorkerOutcome {
                executor: Some(executor_id),
                failure: Some(message),
                retired: true,
            };
        }
    };
    let mut startup_sent = false;
    let lifecycle = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
        receipts.record(executor_id, ExecutorPoolEvent::Created);
        probe_executor_lifecycle(
            executor_id,
            crate::probes::HvpatchExecutorLifecyclePhase::Create,
            None,
            None,
            0,
        );
        let hardware = backend.hardware_kick().map_err(|error| error.to_string())?;
        if !kick.publish_hardware(hardware) {
            return Err("backend failed to publish exact created hardware kick".to_owned());
        }
        let boundary = WorkerBoundaryAudit::capture()
            .and_then(|boundary| {
                boundary.audit_clean(&mut backend, &kick)?;
                Ok(boundary)
            })
            .map_err(|error| error.to_string())?;
        receipts.record(executor_id, ExecutorPoolEvent::AuditPassed);
        startup
            .send(StartupStatus {
                index,
                error: None,
                executor: Some(executor_id),
                kick: Some(Arc::clone(&kick)),
            })
            .map_err(|error| format!("startup status publication failed: {error}"))?;
        startup_sent = true;
        match commands.recv() {
            Ok(WorkerCommand::Run) => run_executor_loop(
                &scheduler,
                &resolver,
                &mut backend,
                WorkerRuntime {
                    registration: &registration,
                    kick: &kick,
                    boundary: &boundary,
                    receipts: &receipts,
                    control: &control,
                },
                &commands,
            ),
            Ok(WorkerCommand::Stop) | Err(_) => Ok(()),
            Ok(WorkerCommand::Initialize | WorkerCommand::InvalidateAsid { .. }) => {
                Err("executor received duplicate initialize".to_owned())
            }
        }
    }));
    let mut retired = false;
    let mut failure = match lifecycle {
        Ok(Ok(())) => None,
        Ok(Err(error)) => {
            retired = true;
            // An executor dying mid-run shrinks the pool for the rest of the
            // carrier's life and its cause was previously visible ONLY at
            // pool shutdown (inside the join) — a wedge that never reaches
            // shutdown showed nothing (the vforkexecthread hunt found a dead
            // executor purely from waiters=9 in the scheduler table). Name
            // the death when it happens.
            tracing::error!(index, %error, "executor worker died");
            Some(error)
        }
        Err(_) => {
            retired = true;
            tracing::error!(index, "executor worker panicked outside containment");
            Some("executor post-create lifecycle panicked; exact lease failed closed".to_owned())
        }
    };
    if !startup_sent {
        let message = failure
            .clone()
            .unwrap_or_else(|| "executor stopped before startup publication".to_owned());
        let _ = startup.send(StartupStatus {
            index,
            error: Some(message),
            executor: Some(executor_id),
            kick: None,
        });
    }
    if startup_sent
        && failure.is_some()
        && control.retire_failed_worker()
        && let Err(drain_error) =
            terminal_drain(&scheduler, resolver.as_ref(), &registration, &receipts)
    {
        if let Some(existing) = &mut failure {
            existing.push_str("; ");
            existing.push_str(&drain_error);
        } else {
            failure = Some(drain_error);
        }
    }
    if let Some(destroy_error) =
        destroy_and_unregister(backend, &scheduler, &registration, &kick, &receipts)
    {
        retired = true;
        if let Some(existing) = &mut failure {
            existing.push_str("; ");
            existing.push_str(&destroy_error);
        } else {
            failure = Some(destroy_error);
        }
    }
    WorkerOutcome {
        executor: Some(executor_id),
        failure,
        retired,
    }
}

fn run_executor_loop<F, R>(
    scheduler: &Arc<Scheduler>,
    resolver: &Arc<R>,
    backend: &mut F,
    runtime: WorkerRuntime<'_>,
    commands: &mpsc::Receiver<WorkerCommand>,
) -> Result<(), String>
where
    F: PersistentExecutor,
    R: TaskBindingResolver<F::TaskBinding>,
{
    let WorkerRuntime {
        registration,
        kick,
        boundary,
        receipts,
        control,
    } = runtime;
    // A Stop consumed while an ASID acknowledgement wait was servicing this
    // executor's own command channel is honored HERE, after the terminal that
    // consumed it has fully settled.
    let mut deferred_stop = false;
    loop {
        if deferred_stop {
            return Ok(());
        }
        if service_owner_thread_commands(backend, registration.id(), commands, boundary, receipts)?
        {
            return Ok(());
        }
        let mut running = match scheduler.take(registration) {
            Ok(running) => running,
            Err(crate::kernel::RunQueueError::ControlPoked) => continue,
            Err(crate::kernel::RunQueueError::Closed) => return Ok(()),
            Err(error) => return Err(error.to_string()),
        };
        let executor_id = running.executor();
        let guest_cpu = running.guest_cpu();
        let mut thread = running.thread_key();
        let mut generation = running.generation();
        receipts.record(
            executor_id,
            ExecutorPoolEvent::Claimed { thread, generation },
        );
        let kernel_task = running.thread().task();
        let event_ring_identity = kernel_task
            .as_ref()
            .and_then(|task| process_leader_event_identity(task.key().id.raw(), thread.tid.raw()));
        if let Some((pid, tid)) = event_ring_identity {
            crate::event_ring::rec_hvpatch_executor_claim(pid, tid, executor_id.raw_for_probe());
        }
        if let Some(task) = kernel_task.as_ref() {
            scheduler
                .kernel()
                .auditors()
                .executor_claimed(executor_id, guest_cpu, task.key());
            // A scheduler claim is evidence even when the claimed snapshot is
            // malformed. Preserve the non-reused task/thread/generation join
            // and use zero only for the authority field that could not be
            // validated; the subsequent load path still fails closed.
            let asid_generation = executor_claim_probe_asid_generation(
                running
                    .lease()
                    .task_state_authority()
                    .ok()
                    .map(|(_, asid_generation)| asid_generation),
            );
            crate::probes::hvpatch_executor_claim(
                task.key().serial.raw(),
                thread.serial.raw(),
                executor_id.raw_for_probe(),
                generation.raw(),
                asid_generation,
            );
        }
        if let Err(error) = boundary.audit_runtime(backend) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let mut binding = match resolver.resolve(thread, generation) {
            Ok(binding) => binding,
            Err(error) => {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(error.to_string(), settlement));
            }
        };
        let mut submission_authority = resolver.take_submission_authority(thread, generation);
        let task = RunnableTask {
            thread,
            generation,
            lease: running.lease(),
            binding: Arc::clone(&binding),
        };
        let mut asid_generation = match task.validate_for_load() {
            Ok(state) => state.asid_generation,
            Err(error) => {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(error.to_string(), settlement));
            }
        };
        if let Err(error) = backend.load(&task) {
            // A load refused because the address space is retiring is not this
            // executor's failure: another thread in the group called `execve`
            // (or the process exited), and Linux terminates every other thread
            // at that point -- this one is already dead, it just had a claim in
            // flight. Settling it and taking the next task is the whole
            // correction. Killing the worker here is what turned an ordinary
            // exec-from-a-thread race into a carrier abort: the dying worker
            // dropped an MM authority whose inventory was published but not yet
            // exactly retired, and that Drop aborts the process.
            if task.binding().address_space_is_retiring() {
                let _settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::AddressSpaceRetired,
                    receipts,
                );
                continue;
            }
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        if let Err(error) = audit_backend_hardware(backend, kick) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        receipts.record(
            executor_id,
            ExecutorPoolEvent::Loaded { thread, generation },
        );
        if let Some((pid, tid)) = event_ring_identity {
            crate::event_ring::rec_hvpatch_executor_load(pid, tid, executor_id.raw_for_probe());
        }
        probe_executor_lifecycle(
            executor_id,
            crate::probes::HvpatchExecutorLifecyclePhase::Load,
            Some(thread),
            Some(generation),
            asid_generation,
        );
        if let Some(task) = kernel_task.as_ref() {
            if task.mark_first_run() {
                scheduler
                    .kernel()
                    .auditors()
                    .child_first_run(task.key(), executor_id, guest_cpu);
            }
        }

        let mut pending_exec_retirement = None;
        let mut pending_exec_cleanup = false;
        let exit = loop {
            let lease = running.take_lease();
            #[cfg(test)]
            let publish_test_descendant = |child, child_generation| {
                let parent = submission_authority.as_ref().ok_or_else(|| {
                    TrapError::Hypervisor(
                        "test descendant publication has no resolver authority".to_owned(),
                    )
                })?;
                resolver.publish_test_descendant(scheduler, parent, child, child_generation)
            };
            let mut submission = ExecutorSubmissionContext {
                scheduler,
                #[cfg(test)]
                publish_test_descendant: &publish_test_descendant,
                current: submission_authority.as_ref(),
                lease: Some(lease),
                exec_replacement: None,
            };
            let attempted = catch_unwind(AssertUnwindSafe(|| {
                backend.run_until_boundary(&kick.need_resched, &mut submission)
            }));
            let exec_replacement = submission.exec_replacement.take();
            let lease = match submission.take_execution_lease() {
                Ok(lease) => lease,
                Err(error) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(error.to_string(), settlement));
                }
            };
            if let Some(replacement) = exec_replacement {
                let PendingExecReplacement {
                    transition,
                    replacement_mm,
                    retired_mm,
                } = replacement;
                let predecessor_thread = thread;
                let predecessor_generation = generation;
                let successor_generation = lease.generation();
                let authority = submission_authority.take();
                let replacement_record =
                    scheduler.retarget_running_exec(&mut running, transition, lease, |committed| {
                        backend.validate_loaded_hardware_identity()?;
                        let identity = TaskLoadIdentity {
                            abi: binding.load_identity().abi,
                            version: binding.load_identity().version,
                            mm: committed.successor_mm,
                            asid_generation: committed.successor_asid_generation,
                        };
                        let replacement_record = resolver.replace_exec(
                            scheduler,
                            ExecBindingTransition {
                                predecessor_thread,
                                predecessor_generation,
                                successor_thread: committed.successor_thread,
                                successor_generation,
                                identity,
                                replacement_mm: Some(Arc::clone(&replacement_mm)),
                                authority,
                            },
                        )?;
                        binding.mark_exec_transferred()?;
                        if backend
                            .retarget_loaded_task(Arc::clone(&replacement_record.binding))
                            .is_err()
                        {
                            // The combined record now names the replacement;
                            // allowing the old Arc to receive saved state would
                            // split immutable MM/ASID identity.
                            carrick_fatal!(
                                "vcpu_loop::executor_exec_transfer",
                                "backend task retarget failed during exec transfer: executor_id={:?}",
                                executor_id
                            );
                        }
                        Ok(replacement_record)
                    });
                let replacement_record = match replacement_record {
                    Ok(replacement) => replacement,
                    Err(error) => {
                        // Kernel exec has already published the replacement
                        // image/thread. Returning through predecessor failure
                        // cleanup would orphan the active successor and its
                        // authority. This is a split-authority invariant loss,
                        // so fail-stop the carrier rather than resume either
                        // image.
                        carrick_fatal!(
                            "vcpu_loop::executor_exec_transfer",
                            "worker-owned exec retarget failed after kernel published successor image: executor_id={:?}, error={error}",
                            executor_id
                        );
                    }
                };
                binding = replacement_record.binding;
                pending_exec_retirement = retired_mm;
                pending_exec_cleanup = true;
                submission_authority = replacement_record.authority;
                thread = running.thread_key();
                generation = successor_generation;
                asid_generation = binding.load_identity().asid_generation;
            } else if let Err((error, lease)) = running.restore_lease(lease) {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                drop(lease);
                return Err(with_settlement_error(error.to_string(), settlement));
            }
            let cpu = backend.take_cpu_receipt();
            running.thread().charge_user_ns(cpu.user_ns);
            running.thread().charge_system_ns(cpu.system_ns);
            let exit = match attempted {
                Ok(Ok(exit)) => exit,
                Ok(Err(error)) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(error.to_string(), settlement));
                }
                Err(_) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        "backend run panicked after publishing its exact CPU receipt".to_owned(),
                        settlement,
                    ));
                }
            };
            if matches!(exit, ExecutorExit::Syscall) {
                scheduler.note_syscall_boundary(&running);
                receipts.record(
                    executor_id,
                    ExecutorPoolEvent::OrdinarySyscall { thread, generation },
                );
                if scheduler.need_resched() {
                    break ExecutorExit::Preempted;
                }
                continue;
            }
            break exit;
        };
        // The residency is over: commit the system CPU this host thread burned
        // servicing the loaded logical thread before anything downstream can
        // observe that thread's accounting. A thread that exited here is about
        // to be retired and folded into its task's ledger, and its parent's
        // `wait4` rusage must not miss the residency that ran it.
        crate::kernel::close_system_charge_window();
        let post_run_event_identity = running.thread().task().as_ref().and_then(|task| {
            process_leader_event_identity(task.key().id.raw(), running.thread_key().tid.raw())
        });
        if let Some((pid, tid)) = post_run_event_identity {
            crate::event_ring::rec_hvpatch_executor_boundary(
                pid,
                tid,
                executor_boundary_event_code(&exit),
            );
        }
        if matches!(exit, ExecutorExit::InvalidState) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(
                "backend returned invalid executor state".to_owned(),
                settlement,
            ));
        }
        if let Err(error) = scheduler.begin_switch_out(&running) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotSaveFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let lease = running.take_lease();
        let saved = match backend.save(lease) {
            Ok(saved) => saved,
            Err(error) => {
                let (source, lease) = error.into_parts();
                if let Err((restore_error, lease)) =
                    scheduler.restore_saved_lease(&mut running, lease)
                {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotSaveFailed,
                        receipts,
                    );
                    drop(lease);
                    return Err(with_settlement_error(
                        format!("{source}; lease restore failed: {restore_error}"),
                        settlement,
                    ));
                }
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotSaveFailed,
                    receipts,
                );
                return Err(with_settlement_error(source.to_string(), settlement));
            }
        };
        receipts.record(executor_id, ExecutorPoolEvent::Saved { thread, generation });
        probe_executor_lifecycle(
            executor_id,
            crate::probes::HvpatchExecutorLifecyclePhase::Save,
            Some(thread),
            Some(generation),
            asid_generation,
        );
        if let Err((error, lease)) = scheduler.restore_saved_lease(&mut running, saved.into_lease())
        {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            drop(lease);
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        if let Err(error) = boundary.audit_runtime(backend) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        if let Err(error) = audit_backend_hardware(backend, kick) {
            let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                resolver.as_ref(),
                scheduler,
                running,
                ExecutionFailure::SnapshotRestoreFailed,
                receipts,
            );
            return Err(with_settlement_error(error.to_string(), settlement));
        }
        let terminal_retirement = binding.take_address_space_retirement();
        if terminal_retirement.is_some() && pending_exec_cleanup {
            carrick_fatal!(
                "hvpatch::mm_retirement",
                "conflicting address space retirement state encountered during exec cleanup: executor_id={:?}",
                executor_id
            );
        }
        let exec_cleanup_ran = pending_exec_retirement.is_some() || pending_exec_cleanup;
        if let Some(mut retirement) = pending_exec_retirement.take() {
            match control.invalidate_after_exec(
                &retirement,
                executor_id,
                backend,
                boundary,
                receipts,
                commands,
            ) {
                Ok(stop_seen) => deferred_stop |= stop_seen,
                Err(error) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        format!("exec predecessor ASID retirement failed: {error}"),
                        settlement,
                    ));
                }
            }
            let root_ticket = match retirement.take_root_retirement_ticket() {
                Ok(ticket) => ticket,
                Err(error) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        format!("exec predecessor root retirement ticket failed: {error}"),
                        settlement,
                    ));
                }
            };
            let root_receipt = match binding.retire_detached_exec_predecessor(root_ticket) {
                Ok(receipt) => receipt,
                Err(error) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        format!("exec detached predecessor cleanup failed: {error}"),
                        settlement,
                    ));
                }
            };
            if let Err(error) = retirement.complete(root_receipt) {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    format!("exec predecessor ASID/root release failed: {error}"),
                    settlement,
                ));
            }
            pending_exec_cleanup = false;
        }
        if pending_exec_cleanup {
            match binding.retire_detached_exec_predecessor(None) {
                Ok(None) => {}
                Ok(Some(_)) => {
                    carrick_fatal!(
                        "vcpu_loop::executor_boundary",
                        "kick handle remains bound after settlement transaction: executor_id={:?}",
                        executor_id
                    );
                }
                Err(error) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        format!("shared-MM exec detached predecessor cleanup failed: {error}"),
                        settlement,
                    ));
                }
            }
        }
        if exec_cleanup_ran {
            // Exec cleanup may drop the last foreign-MM registration after the
            // post-save audit above. Run the named idle maintenance boundary
            // now, while no topology guard or task binding is loaded, so an
            // all-idle executor pool cannot strand its retry request forever.
            if let Err(error) = boundary.audit_runtime(backend) {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    format!("post-exec-cleanup executor audit failed: {error}"),
                    settlement,
                ));
            }
        }
        if let Some(mut retirement) = terminal_retirement {
            if let Some(stage1) = retirement.retirement() {
                match control.invalidate_after_exec(
                    stage1,
                    executor_id,
                    backend,
                    boundary,
                    receipts,
                    commands,
                ) {
                    Ok(stop_seen) => deferred_stop |= stop_seen,
                    Err(error) => {
                        let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                            resolver.as_ref(),
                            scheduler,
                            running,
                            ExecutionFailure::SnapshotRestoreFailed,
                            receipts,
                        );
                        return Err(with_settlement_error(
                            format!("terminal ASID retirement failed: {error}"),
                            settlement,
                        ));
                    }
                }
            }
            let (_topology, stop_seen) = match acquire_process_retire_topology_lock_servicing(
                retirement.guest_pid(),
                retirement.guest_tid().raw(),
                backend,
                executor_id,
                commands,
                boundary,
                receipts,
            ) {
                Ok(acquired) => acquired,
                Err(error) => {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        format!("terminal topology acquisition failed: {error}"),
                        settlement,
                    ));
                }
            };
            deferred_stop |= stop_seen;
            let root_ticket = match retirement.take_root_retirement_ticket() {
                Ok(ticket) => ticket,
                Err(error) => {
                    drop(_topology);
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        format!("terminal root retirement ticket failed: {error}"),
                        settlement,
                    ));
                }
            };
            let cleanup = if retirement.retirement().is_some() {
                binding.retire_detached_address_space(root_ticket)
            } else {
                binding.retire_detached_shared_mm_edge().map(|()| None)
            };
            let root_receipt = match cleanup {
                Ok(receipt) => receipt,
                Err(error) => {
                    drop(_topology);
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(
                        format!("terminal detached address-space cleanup failed: {error}"),
                        settlement,
                    ));
                }
            };
            if let Err(error) = retirement.complete(root_receipt) {
                drop(_topology);
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    format!("terminal ASID/root release failed: {error}"),
                    settlement,
                ));
            }
            drop(_topology);
            // `retirement.complete()` can drop the terminal registration while
            // the topology guard is held. Backend maintenance is forbidden in
            // Drop and under that guard, so service its custody-local request
            // immediately after releasing topology authority.
            if let Err(error) = boundary.audit_runtime(backend) {
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    format!("post-terminal-cleanup executor audit failed: {error}"),
                    settlement,
                ));
            }
        }
        if let Some(authority) = submission_authority.take() {
            if let Err(authority) = resolver.restore_submission_authority(authority) {
                drop(authority);
                // The only error return in this quantum tail that dropped
                // `running` without settling it. `RunnableThread::drop` runs
                // `finish_claim` and nothing else, so the thread stayed in
                // whatever state `begin_switch_out` published, its job kept no
                // publisher, and the claim count went back to zero with no
                // record anywhere -- the exact stranded shape the round-7
                // `claim-dropped-unsettled` probe was added to name. Settle it
                // the way every sibling error path in this function does.
                let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                    resolver.as_ref(),
                    scheduler,
                    running,
                    ExecutionFailure::SnapshotRestoreFailed,
                    receipts,
                );
                return Err(with_settlement_error(
                    "combined task resolver rejected worker-held authority restoration".to_owned(),
                    settlement,
                ));
            }
        }
        let settlement_thread = Arc::clone(running.thread());
        // A settlement whose target was reaped in flight leaves this thread
        // with no successor and no other publisher, so its process job is
        // published HERE. Recorded by the arms below and acted on once, after
        // the settlement succeeds.
        let mut reaped_settlement = false;
        let settlement = match exit {
            ExecutorExit::Blocked(reason) => {
                drop(submission_authority);
                scheduler
                    .settle_blocked(running, reason)
                    .map(|disposition| {
                        reaped_settlement = disposition == SettlementDisposition::TargetReaped;
                        ExecutorPoolEvent::SettledBlocked { thread, generation }
                    })
            }
            ExecutorExit::BlockedContinuation {
                continuation,
                vfork_activation,
            } => {
                let mut registration = control.wait_service.prepare_registration(&continuation);
                if let Err(error) = control.wait_service.enroll(&mut registration) {
                    let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                        resolver.as_ref(),
                        scheduler,
                        running,
                        ExecutionFailure::SnapshotRestoreFailed,
                        receipts,
                    );
                    return Err(with_settlement_error(error.to_string(), settlement));
                }
                if let Some(activation) = vfork_activation {
                    if let Err(error) = activation.activate() {
                        let settlement = fail_running_and_retire::<F::TaskBinding, _>(
                            resolver.as_ref(),
                            scheduler,
                            running,
                            ExecutionFailure::SnapshotRestoreFailed,
                            receipts,
                        );
                        return Err(with_settlement_error(error.to_string(), settlement));
                    }
                }
                drop(submission_authority);
                scheduler
                    .settle_blocked_continuation(running, *continuation, registration)
                    .map(|disposition| {
                        reaped_settlement = disposition == SettlementDisposition::TargetReaped;
                        ExecutorPoolEvent::SettledBlocked { thread, generation }
                    })
            }
            ExecutorExit::Yielded | ExecutorExit::Preempted => {
                let disposition = scheduler
                    .settle_runnable_successor(running)
                    .map_err(|error| error.to_string())?;
                reaped_settlement = disposition == SettlementDisposition::TargetReaped;
                Ok(ExecutorPoolEvent::SettledRunnable { thread, generation })
            }
            ExecutorExit::Quiesced => {
                drop(submission_authority);
                scheduler
                    .settle_blocked(running, BlockedReason::HostWait)
                    .map(|disposition| {
                        reaped_settlement = disposition == SettlementDisposition::TargetReaped;
                        ExecutorPoolEvent::SettledBlocked { thread, generation }
                    })
            }
            ExecutorExit::Exited => {
                drop(submission_authority);
                let settled = scheduler
                    .settle_exited(running)
                    .map(|()| ExecutorPoolEvent::SettledExited { thread, generation });
                if settled.is_ok() {
                    resolver.retire(thread, generation);
                }
                settled
            }
            ExecutorExit::Syscall | ExecutorExit::InvalidState => unreachable!(),
        };
        // A guest `sched_yield` (or a preemption tick) requeued this task at
        // the TAIL of its own guest CPU, which is the fairness mechanism; the
        // executor then loops and claims whatever is now at the head. Any
        // OTHER boundary is not a fairness event, and yielding the host core
        // there hands it to any equal-priority competitor on the machine —
        // measured as a 1.3x wall and 1.3x CPU-seconds penalty for a
        // single-threaded row under three default-QoS hogs. Fairness between
        // guest CPUs is the run queue and the tick, never `sched_yield`.
        let yielded_or_preempted =
            matches!(settlement, Ok(ExecutorPoolEvent::SettledRunnable { .. }));
        match settlement {
            Ok(event) => {
                if reaped_settlement {
                    // The kernel graph says this thread is terminal: it will
                    // never be claimed again, so the job it owns publishes now
                    // or never. Round 4 withheld the successor AND the result,
                    // and `go_types` then wedged with the guest already at
                    // PASS, eighteen executors parked in `take_row` and main
                    // in `wait_process_jobs`.
                    // The binding record itself was already retired by
                    // `SchedulerGenerationObserver::retire_reaped`, which owns
                    // that half; what was missing is the RESULT.
                    binding.after_reaped_settlement();
                }
                if let Some((pid, tid)) = post_run_event_identity {
                    crate::event_ring::rec_hvpatch_executor_settlement(
                        pid,
                        tid,
                        thread_settlement_event_code(settlement_thread.execution_state()),
                    );
                }
                if matches!(event, ExecutorPoolEvent::SettledExited { .. }) {
                    binding.after_terminal_settlement();
                    let task_key = settlement_thread.task_key();
                    let (status, owner) =
                        if let Some(zombie) = scheduler.kernel().registry().zombie(task_key.id) {
                            (
                                zombie.status,
                                crate::observe::ExitOwner::from(zombie.parent),
                            )
                        } else {
                            (
                                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
                                crate::observe::ExitOwner::Nobody,
                            )
                        };
                    scheduler
                        .kernel()
                        .auditors()
                        .exit_settled(task_key, status, owner);
                }
                receipts.record(executor_id, event);
                probe_executor_lifecycle(
                    executor_id,
                    crate::probes::HvpatchExecutorLifecyclePhase::Switch,
                    Some(thread),
                    Some(generation),
                    asid_generation,
                );
            }
            Err(error) => return Err(error.to_string()),
        }
        // All fallible owner/backend checks ran while `running` still carried
        // the predecessor claim. Settlement then unbound the exact kick in the
        // same scheduler transaction. A bound kick here is an internal
        // invariant violation after successor publication; fail-stop instead
        // of retrospectively failing a predecessor that no longer exists.
        if kick.current_binding().is_some() {
            carrick_fatal!(
                "vcpu_loop::executor_boundary",
                "executor kick remains bound after terminal settlement: executor_id={:?}",
                executor_id
            );
        }
        receipts.record(executor_id, ExecutorPoolEvent::AuditPassed);
        if yielded_or_preempted {
            std::thread::yield_now();
        }
    }
}

const fn executor_claim_probe_asid_generation(validated: Option<u64>) -> u64 {
    match validated {
        Some(asid_generation) => asid_generation,
        None => 0,
    }
}

const fn process_leader_event_identity(task_pid: i32, tid: i32) -> Option<(i32, i32)> {
    if task_pid == tid {
        Some((task_pid, tid))
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests;
