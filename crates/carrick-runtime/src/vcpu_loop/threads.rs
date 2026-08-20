//! THREAD concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

enum SharedWordWaitRaw {
    Retval(i64),
    ExecReplacedThread,
}

/// One cross-process (`MAP_SHARED`) futex wait target. The three values always
/// travel together — the shared word's location, the waiter-table key, and the
/// value the guest expects to still be there — so they cross the wait API as
/// one named thing rather than three positional arguments.
#[derive(Clone, Copy)]
pub(super) struct SharedWordWait {
    pub(super) location: carrick_guest_mem::SharedFutexLocation,
    pub(super) waiter_key: usize,
    pub(super) value: u32,
}

pub(super) enum CloneThreadSpawn {
    Started(crate::kernel::LinuxTid),
    Errno(crate::linux_abi::LinuxErrno),
}

enum SiblingStartFailure {
    Cancelled,
    Materialization(String),
}

fn guest_host_thread_name(process_pid: Option<i32>, tid: ThreadId) -> String {
    process_pid.map_or_else(
        || format!("guest-tid-{tid}"),
        |pid| format!("guest-pid-{pid}-tid-{tid}"),
    )
}

fn has_dispatch_signal_for_futex_wait(
    dispatcher: &SyscallDispatcher,
    context: Option<&crate::kernel::KernelContext>,
    tid: ThreadId,
) -> bool {
    context.is_some_and(|context| {
        dispatcher.has_deliverable_dispatch_pending_for_wait(
            context,
            tid,
            carrick_abi::WaitSigMask::NONE,
        )
    })
}

/// The ONE interrupt vocabulary shared by BOTH futex-wait implementations —
/// the private `parking_lot` table and the cross-process `__ulock` word.
///
/// They used to disagree: the shared path omitted the kernel-graph term, and
/// on HVPatch that store is the ONLY place a guest signal lands
/// (`post_signal_to_authorized_target` records into the kernel graph and never
/// writes `host_signal`'s per-tid words). A thread parked on a `MAP_SHARED`
/// futex was therefore deaf to every `tgkill` / `pidfd_send_signal` /
/// `rt_sigqueueinfo` until an unrelated `FUTEX_WAKE` happened to arrive.
///
/// No new wake vehicle is needed to make the term effective: a shared wait is
/// sliced at `SHARED_FUTEX_MAX_SLICE_NS` (20 ms) and re-evaluates this
/// predicate at every slice boundary — that slice cap exists precisely because
/// a vCPU kick cannot interrupt a thread inside the host wait primitive.
fn futex_wait_is_interrupted(
    dispatcher: &SyscallDispatcher,
    context: Option<&crate::kernel::KernelContext>,
    registry: &ThreadRegistry,
    tid: ThreadId,
    fork_quiescing: bool,
) -> bool {
    crate::host_signal::has_pending_for(tid.raw())
        || has_dispatch_signal_for_futex_wait(dispatcher, context, tid)
        || fork_quiescing
        || crate::fork_quiesce::exec_replacing_other_thread(tid)
        || !registry.is_live(tid)
}

/// How long a clone child waits per attempt for its vCPU slot. Long enough
/// that a FIFO place is actually held rather than surrendered and retaken at
/// the back of the queue; short enough to notice `exit_group` cancellation
/// promptly.
const CLONE_CHILD_SLOT_WAIT_SLICE: Duration = Duration::from_millis(250);

fn acquire_vcpu_lease_while_live<A, R>(
    registry: &ThreadRegistry,
    tid: ThreadId,
    mut acquire: A,
    mut on_retry: R,
) -> Option<carrick_hal::vcpu_sched::SlotLease>
where
    A: FnMut() -> Option<carrick_hal::vcpu_sched::SlotLease>,
    R: FnMut(),
{
    loop {
        if thread_should_finish_for_exec_replacement(registry, tid) {
            return None;
        }
        if let Some(lease) = acquire() {
            return Some(lease);
        }
        // Process teardown can remove this thread while the bounded scheduler
        // wait is in progress. Re-check before retrying: otherwise a reclaimed
        // sibling with no vCPU lease can wait forever while its process owner
        // waits for the sibling's JoinHandle before retiring the mm root slot.
        if thread_should_finish_for_exec_replacement(registry, tid) {
            return None;
        }
        on_retry();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hvpatch_host_thread_name_carries_process_and_thread_identity() {
        let tid = ThreadId::synthetic_for_tests(456);
        assert_eq!(
            guest_host_thread_name(Some(123), tid),
            "guest-pid-123-tid-456"
        );
        assert_eq!(guest_host_thread_name(None, tid), "guest-tid-456");
    }

    #[test]
    fn reclaimed_vcpu_reacquire_stops_when_teardown_removes_thread() {
        let owner = ThreadId::synthetic_for_tests(1000);
        let registry = ThreadRegistry::new(owner);
        let sibling = registry.register_child(0);
        let mut attempts = 0;

        let lease = acquire_vcpu_lease_while_live(
            &registry,
            sibling,
            || {
                attempts += 1;
                registry.remove_all_except(owner);
                None
            },
            || panic!("a removed thread must not retry vCPU acquisition"),
        );

        assert!(lease.is_none());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn futex_wait_observes_thread_signal_in_dispatch_kernel_state() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.exact_signal_context_for_test();
        let tid = context.thread().registry_id();

        assert!(!has_dispatch_signal_for_futex_wait(
            &dispatcher,
            Some(&context),
            tid
        ));

        // HVPatch routes thread-directed signals through the shared kernel
        // task state, not host_signal's thread-local slot. A parked futex
        // waiter must observe that queue after its task waker unparks it.
        dispatcher.mark_signal_pending(&context, tid, 33);
        assert!(has_dispatch_signal_for_futex_wait(
            &dispatcher,
            Some(&context),
            tid
        ));
    }

    /// The cross-process (`MAP_SHARED`, `__ulock`) futex wait must use the SAME
    /// interrupt vocabulary as the private one. It did not: it omitted the
    /// kernel-graph term, which on HVPatch is the only place a guest signal is
    /// recorded, so a thread parked on a shared futex was deaf to every signal.
    /// Both paths now call this one predicate, so they cannot drift again.
    #[test]
    fn futex_wait_interrupt_vocabulary_sees_a_kernel_graph_signal() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.exact_signal_context_for_test();
        let tid = context.thread().registry_id();
        let registry = ThreadRegistry::new(tid);

        assert!(
            !futex_wait_is_interrupted(&dispatcher, Some(&context), &registry, tid, false),
            "an idle waiter is not interrupted"
        );
        assert!(
            futex_wait_is_interrupted(&dispatcher, Some(&context), &registry, tid, true),
            "a fork quiesce always interrupts"
        );

        dispatcher.mark_signal_pending(&context, tid, 33);
        assert!(
            futex_wait_is_interrupted(&dispatcher, Some(&context), &registry, tid, false),
            "a signal posted into the kernel graph must interrupt the wait"
        );
    }
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    /// Publish this thread's live vCPU into the kicker: the fresh kick handle
    /// AND the thread's lifetime in-guest flag, in one entry.
    ///
    /// This is the ONLY production caller of
    /// [`carrick_hal::VcpuRegistry::register`]. Every rebind path (blocking-wait
    /// reclaim, fork park, post-fork rebuild) funnels through here, so a
    /// re-registration cannot restore one facet and silently drop the other.
    pub(super) fn register_vcpu(&self, engine: &E) {
        let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
        self.kicker.register(self.this_tid, handle, &self.in_guest);
        self.registry
            .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
    }

    pub(super) fn complete_futex_wait(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        self.complete_futex_wait_with_value(kernel, engine, wait, timeout, 0)
    }

    pub(super) fn complete_futex_waitv(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
        index: i64,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        self.complete_futex_wait_with_value(kernel, engine, wait, timeout, index)
    }

    fn complete_futex_wait_with_value(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
        woken_value: i64,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        use crate::thread::FutexWaitOutcome;

        let retval: i64 = loop {
            let wait_trace = trace_hvpatch_wait_begin(kernel, self.this_tid, 7, &[], engine);
            // M:N reclaim-on-block: free this thread's vCPU slot for the duration of
            // the blocking wait so another guest thread can run on it, restoring this
            // thread's state into a (possibly different) slot on wake. Reclaim every
            // genuine futex block on reclaiming backends: tests and real runtimes
            // commonly spawn a set of waiters and then poll until all are asleep, so
            // early waiters must not keep scarce HVF slots merely because capacity
            // was still spare at the instant they parked.
            let reclaim_now = engine.reclaims();
            let snapshot = if reclaim_now {
                self.begin_reclaim_snapshot_save()?;
                let cpu = engine.save_guest_state().map_err(|error| {
                    self.fail_snapshot_boundary(
                        crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
                    );
                    RuntimeError::Trap(error)
                })?;
                let st = self.current_migratable_binding(cpu).inspect_err(|_error| {
                    self.fail_snapshot_boundary(
                        crate::kernel::objects::ExecutionFailure::SnapshotGenerationMismatch,
                    );
                })?;
                self.settle_reclaim_snapshot(&st)?;
                let old_slot = carrick_hal::vcpu_sched::current_slot();
                if let Some(l) = carrick_hal::vcpu_sched::take_current_lease() {
                    carrick_hal::vcpu_sched::global()
                        .release(l, carrick_hal::vcpu_sched::Yield::Blocked);
                }
                // A backend whose reclaim DESTROYS the vCPU (HVF) leaves a dead-id
                // kick handle (raw hv_vcpu_destroy doesn't drop applevisor's
                // liveness Weak, so is_valid() lies). Unregister it before the
                // no-vCPU wait — a parked thread is woken by the futex predicate,
                // not the kicker — and re-register the recreated vCPU after rebind.
                if engine.reclaim_refreshes_kicker() {
                    self.kicker.unregister(self.this_tid);
                }
                Some(old_slot)
            } else {
                None
            };
            // Genuine guest block (FUTEX_WAIT): publish Blocked so a sibling's
            // /proc/<pid>/stat reads `S`. `Running` is re-published when the vCPU
            // resumes guest code after the wake (run_vcpu_until_exit top).
            self.publish_thread_run_state(crate::run_state::RunState::Blocked, 'S');
            crate::event_ring::rec_futex_wait(wait.addr, self.this_tid.raw());
            let raw = self
                .futex
                .wait_prepared_for_thread(wait, timeout, self.this_tid, &|| {
                    futex_wait_is_interrupted(
                        &kernel.dispatcher,
                        self.service_kernel_context.as_ref(),
                        &self.registry,
                        self.this_tid,
                        self.fork_is_quiescing(),
                    )
                });
            crate::event_ring::rec_futex_end(
                wait.addr,
                match raw {
                    FutexWaitOutcome::Woken => 0,
                    FutexWaitOutcome::Interrupted => 1,
                    FutexWaitOutcome::TimedOut => 2,
                },
            );
            trace_hvpatch_wait_end(
                kernel,
                self.this_tid,
                7,
                match raw {
                    FutexWaitOutcome::Woken => 2,
                    FutexWaitOutcome::Interrupted => 4,
                    FutexWaitOutcome::TimedOut => 3,
                },
                0,
                wait_trace,
            );
            self.publish_thread_run_state(crate::run_state::RunState::Running, 'R');
            if thread_should_finish_for_exec_replacement(&self.registry, self.this_tid) {
                return Ok(BlockingWaitCompletion::ExecReplacedThread);
            }
            if let Some(old_slot) = snapshot {
                // Prefer the thread's OWN just-released slot (reuse its clean vCPU,
                // no re-bind) over reclaiming another thread's — esp. an exited one.
                //
                // BOUNDED acquire + quiesce parking: fork-parked siblings KEEP
                // their slot leases, so an unbounded wait here while a fork
                // quiesce drains deadlocks the forker against us — it waits for
                // OUR kicker entry to park while we wait for THEIR slots
                // (observed live under go-build: the 10 s quiesce-drain abort
                // with the stranded sibling in `acquire_preferring`). We hold no
                // slot while waiting, so on quiesce we drop out of the kicker
                // (letting the drain complete), park at the fork barrier, and
                // resume waiting once the fork is done.
                let mut kicker_dropped = engine.reclaim_refreshes_kicker();
                let new = acquire_vcpu_lease_while_live(
                    &self.registry,
                    self.this_tid,
                    || {
                        carrick_hal::vcpu_sched::global().acquire_timeout(
                            self.this_tid.raw() as u64,
                            old_slot,
                            Duration::from_millis(50),
                        )
                    },
                    || {
                        if self.fork_is_quiescing() {
                            if !kicker_dropped {
                                self.kicker.unregister(self.this_tid);
                                kicker_dropped = true;
                            }
                            // Parked while waiting for a vCPU lease: there is
                            // no readable register file here and this thread
                            // will not resume before the barrier drops, so it
                            // must withdraw rather than silently owe a fatal
                            // sibling a note it can never write.
                            self.withdraw_from_crash_capture();
                            self.park_if_fork_quiescing();
                        }
                    },
                );
                let Some(new) = new else {
                    return Ok(BlockingWaitCompletion::ExecReplacedThread);
                };
                carrick_hal::vcpu_sched::set_current_lease(new);
                let (cpu, execution_lease) = self.claim_reclaim_snapshot()?;
                if engine.reclaim_refreshes_kicker() {
                    // HVF recreates the vCPU: do it under the topology lock so
                    // vcpu_create can't race a concurrent fork's hv_vm_destroy/
                    // create, then re-register the fresh vCPU's kick handle.
                    let _topo = crate::fork_quiesce::acquire_topology_lock(
                        carrick_observability::probes::HvpatchTopologyOperation::VcpuRebind,
                        kernel
                            .hvpatch_process
                            .as_ref()
                            .map_or(0, crate::hvpatch::ProcessContext::pid),
                        self.this_tid.raw(),
                    );
                    let restore_result = engine.rebind_to_slot(new.slot, &cpu);
                    self.complete_reclaim_restore(execution_lease, restore_result)?;
                    self.register_vcpu(engine);
                } else {
                    // If a fork quiesce began while (or right after) we
                    // acquired, park FIRST — slot-less threads must not
                    // re-bind mid-freeze: the re-bind drives vm_run (the
                    // fresh-slot MSR blob / XRSTOR stub) and writes guest RAM,
                    // which must not overlap the forker's stop-the-world RAM
                    // snapshot. Unregister before parking so the forker's
                    // drain (kicker count → 1) can complete.
                    if self.fork_is_quiescing() {
                        if !kicker_dropped {
                            self.kicker.unregister(self.this_tid);
                            kicker_dropped = true;
                        }
                        // Slot-less and mid-rebind: no readable register file,
                        // and no resume before the barrier drops.
                        self.withdraw_from_crash_capture();
                        self.park_if_fork_quiescing();
                    }
                    // Re-register BEFORE the re-bind so a quiesce that starts
                    // mid-re-bind waits for us to reach the run-loop-top park
                    // (the pre-reclaim drain contract); a kick landing during
                    // the stub drive is handled (Kicked → re-run).
                    if kicker_dropped {
                        self.register_vcpu(engine);
                    }
                    let restore_result = engine.rebind_to_slot(new.slot, &cpu);
                    self.complete_reclaim_restore(execution_lease, restore_result)?;
                }
                let prev = old_slot.unwrap_or(new.slot);
                crate::probes::mn_reclaim(
                    self.this_tid.raw(),
                    prev,
                    new.slot,
                    if new.slot == prev { 1 } else { 2 },
                );
            } else if engine.reclaims() {
                // A reclaiming backend that PARKED (uncontended — kept its vCPU).
                let slot = carrick_hal::vcpu_sched::current_slot().unwrap_or(0);
                crate::probes::mn_reclaim(self.this_tid.raw(), slot, slot, 0);
            }
            let outcome = match raw {
                FutexWaitOutcome::Woken => woken_value,
                FutexWaitOutcome::TimedOut => crate::linux_abi::LINUX_ETIMEDOUT.guest_retval(),
                FutexWaitOutcome::Interrupted if self.fork_is_quiescing() => {
                    self.release_and_park_vcpu_for_fork(engine)?;
                    continue;
                }
                FutexWaitOutcome::Interrupted => crate::linux_abi::LINUX_EINTR.guest_retval(),
            };
            break outcome;
        };
        self.complete_returned(engine, retval)
            .map(BlockingWaitCompletion::Retval)
    }

    pub(super) fn complete_shared_futex_wait(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        wait: SharedWordWait,
        timeout: Option<Duration>,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        self.complete_shared_futex_wait_with_value(kernel, engine, wait, timeout, 0)
    }

    pub(super) fn complete_shared_futex_waitv(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        wait: SharedWordWait,
        timeout: Option<Duration>,
        index: i64,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        self.complete_shared_futex_wait_with_value(kernel, engine, wait, timeout, index)
    }

    fn wait_on_shared_word_retval(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        wait: SharedWordWait,
        timeout: Option<Duration>,
    ) -> Result<SharedWordWaitRaw, RuntimeError> {
        let SharedWordWait {
            location,
            waiter_key,
            value,
        } = wait;
        // Exactly the vocabulary the PRIVATE futex wait uses — see
        // `futex_wait_is_interrupted`.
        let interrupted = || {
            futex_wait_is_interrupted(
                &kernel.dispatcher,
                self.service_kernel_context.as_ref(),
                &self.registry,
                self.this_tid,
                self.fork_is_quiescing(),
            )
        };
        let retval = loop {
            // Shared park/resume pair (mod.rs): reclaim this thread's vCPU —
            // and, for a single-threaded process, the whole VM — for the
            // duration of the shared-word wait. ReleaseSafe: the wake is the
            // cross-process futex mirror / __ulock predicate, the ORIGINAL
            // (E4) VM-released wait shape, proven vCPU-less.
            let reclaim = self
                .park_vcpu_for_blocking_wait(engine, crate::thread::VcpuParkClass::ReleaseSafe)?;

            let publish_wait_enrolled = || {
                self.publish_thread_run_state(crate::run_state::RunState::Blocked, 'S');
            };
            if std::env::var_os("CARRICK_SIG_DEBUG").is_some() {
                let addr = location.wait_addr().raw();
                let current = unsafe {
                    (*(addr as *const std::sync::atomic::AtomicU32))
                        .load(std::sync::atomic::Ordering::SeqCst)
                };
                eprintln!(
                    "SIGDBG shared_wait enter tid={} key={:#x} addr={addr:#x} expect={value} current={current}",
                    self.this_tid.raw(),
                    waiter_key
                );
            }
            let retval = self.platform_futex.shared_wait(
                location,
                value,
                // Park under THIS thread's token so a thread-directed signal
                // can wake exactly this shared waiter, instead of the old
                // path's 20 ms interrupt polling.
                self.this_tid,
                timeout,
                &interrupted,
                &publish_wait_enrolled,
            );
            if std::env::var_os("CARRICK_SIG_DEBUG").is_some() {
                let addr = location.wait_addr().raw();
                let current = unsafe {
                    (*(addr as *const std::sync::atomic::AtomicU32))
                        .load(std::sync::atomic::Ordering::SeqCst)
                };
                eprintln!(
                    "SIGDBG shared_wait exit tid={} retval={retval} addr={addr:#x} current={current}",
                    self.this_tid.raw()
                );
            }
            self.publish_thread_run_state(crate::run_state::RunState::Running, 'R');
            if thread_should_finish_for_exec_replacement(&self.registry, self.this_tid) {
                return Ok(SharedWordWaitRaw::ExecReplacedThread);
            }
            self.resume_vcpu_after_blocking_wait(engine, reclaim)?;
            if retval == crate::linux_abi::LINUX_EINTR.guest_retval() && self.fork_is_quiescing() {
                self.release_and_park_vcpu_for_fork(engine)?;
                continue;
            }
            break retval;
        };
        if location.is_mirror() {
            let current = unsafe {
                (*(location.wait_addr().raw() as *const std::sync::atomic::AtomicU32))
                    .load(std::sync::atomic::Ordering::SeqCst)
            };
            let _ = engine.write_bytes(waiter_key as u64, &current.to_ne_bytes());
        }
        Ok(SharedWordWaitRaw::Retval(retval))
    }

    pub(super) fn wait_on_shared_word(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        wait: SharedWordWait,
    ) -> Result<SharedWordWaitCompletion, RuntimeError> {
        match self.wait_on_shared_word_retval(kernel, engine, wait, None)? {
            SharedWordWaitRaw::ExecReplacedThread => {
                Ok(SharedWordWaitCompletion::ExecReplacedThread)
            }
            SharedWordWaitRaw::Retval(retval)
                if retval == crate::linux_abi::LINUX_EINTR.guest_retval() =>
            {
                Ok(SharedWordWaitCompletion::Interrupted)
            }
            SharedWordWaitRaw::Retval(_) => Ok(SharedWordWaitCompletion::Changed),
        }
    }

    fn complete_shared_futex_wait_with_value(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        wait: SharedWordWait,
        timeout: Option<Duration>,
        woken_value: i64,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        let retval = match self.wait_on_shared_word_retval(kernel, engine, wait, timeout)? {
            SharedWordWaitRaw::Retval(retval) => retval,
            SharedWordWaitRaw::ExecReplacedThread => {
                return Ok(BlockingWaitCompletion::ExecReplacedThread);
            }
        };
        let retval = if retval == 0 { woken_value } else { retval };
        self.complete_returned(engine, retval)
            .map(BlockingWaitCompletion::Retval)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_clone_thread(
        &self,
        kernel: &Kernel,
        parent_context: &crate::kernel::KernelContext,
        engine: &mut E,
        stack: u64,
        tls: Option<u64>,
        flags: u64,
        parent_tid_addr: u64,
        child_tid_addr: u64,
        clear_child_tid_addr: u64,
    ) -> Result<CloneThreadSpawn, RuntimeError> {
        let Some(clone_permit) = kernel.try_enroll_thread_clone() else {
            crate::probes::mn_clone_outcome(
                self.this_tid.raw(),
                carrick_observability::probes::HvpatchCloneThreadPhase::AdmissionClosed,
                crate::linux_abi::LINUX_EAGAIN.get(),
            );
            return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN));
        };
        if kernel.process_exiting() || clone_permit.is_cancelled() {
            crate::probes::mn_clone_outcome(
                self.this_tid.raw(),
                carrick_observability::probes::HvpatchCloneThreadPhase::AdmissionCancelled,
                crate::linux_abi::LINUX_EAGAIN.get(),
            );
            return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN));
        }
        let read_tid_output = |address: u64| -> Option<Option<Vec<u8>>> {
            if address == 0 {
                Some(None)
            } else {
                engine
                    .read_bytes(address, std::mem::size_of::<i32>())
                    .ok()
                    .map(Some)
            }
        };
        let Some(parent_tid_original) = read_tid_output(parent_tid_addr) else {
            return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EFAULT));
        };
        let Some(child_tid_original) = read_tid_output(child_tid_addr) else {
            return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EFAULT));
        };
        let (linux_tid, tid, prepared_thread) =
            if let Some(process) = kernel.hvpatch_process.as_ref() {
                let plan = match crate::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::from_bits_retain(flags),
                ) {
                    Ok(plan) => plan,
                    Err(_) => return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EINVAL)),
                };
                let reservation = process
                    .kernel_graph()
                    .reserve_thread_clone_eventually(parent_context, plan)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "reserve authoritative hvpatch thread: {error}"
                        ))
                    })?;
                let linux_tid = reservation.tid();
                let tid = ThreadId::from_guest_supplied_tid(linux_tid.raw());
                let prepared = reservation.prepare(tid).map_err(|error| {
                    RuntimeError::Configuration(format!(
                        "prepare authoritative hvpatch thread: {error}"
                    ))
                })?;
                (linux_tid, tid, Some(prepared))
            } else {
                let tid = self.registry.register_child(clear_child_tid_addr);
                let linux_tid = match kernel
                    .dispatcher
                    .register_one_task_thread(parent_context, tid)
                {
                    Ok(linux_tid) => linux_tid,
                    Err(error) => {
                        self.registry.exit(tid);
                        return Err(RuntimeError::Configuration(format!(
                            "register one-task adapter thread: {error}"
                        )));
                    }
                };
                (linux_tid, tid, None)
            };
        crate::probes::mn_clone_outcome(
            tid.raw(),
            carrick_observability::probes::HvpatchCloneThreadPhase::Reserved,
            0,
        );
        let spec = match engine.build_sibling_spec(carrick_hal::GuestEntryRegs {
            return_value: 0,
            stack: Some(stack),
            tls,
        }) {
            Ok(spec) => spec,
            Err(error) => {
                if prepared_thread.is_none() {
                    self.registry.exit(tid);
                    let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
                }
                return Err(RuntimeError::Trap(error));
            }
        };
        // Reserve Kernel publication before the child can take the HVPatch
        // topology lock. Fork/exec take their task reservation before topology
        // too, so this ordering cannot form reservation ↔ topology cycles.
        let prepared_thread = match prepared_thread {
            Some(prepared) => Some(prepared.reserve_publication_eventually().map_err(|error| {
                RuntimeError::Configuration(format!(
                    "reserve authoritative hvpatch thread publication: {error}"
                ))
            })?),
            None => None,
        };
        let child_kernel = Arc::clone(kernel);
        let child_registry = Arc::clone(&self.registry);
        let child_futex = Arc::clone(&self.futex);
        let child_platform_futex = Arc::clone(&self.platform_futex);
        let child_platform_futex_factory = Arc::clone(&self.platform_futex_factory);
        let child_threads = Arc::clone(&self.threads);
        let child_kicker = Arc::clone(&self.kicker);
        // Cleanup handles kept past the move into run_vcpu_until_exit: if the
        // sibling loop returns Err, its normal thread-exit cleanup never ran, so
        // we MUST still drop it from the registry + kicker here. Otherwise it
        // lingers as a phantom live thread.
        let cleanup_registry = Arc::clone(&self.registry);
        let cleanup_kicker = Arc::clone(&self.kicker);
        let cleanup_kernel = Arc::clone(kernel);
        let max_traps = self.max_traps;
        let trace = self.trace;
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let (start_tx, start_rx) = std::sync::mpsc::sync_channel(1);
        let host_thread_name = guest_host_thread_name(
            child_kernel
                .hvpatch_process
                .as_ref()
                .map(crate::hvpatch::ProcessContext::pid),
            tid,
        );
        // Reclaim this caller's vCPU BEFORE spawning, not after. The child
        // materializer starts queueing for a slot the instant the host thread
        // runs, so releasing afterwards leaves a window in which the parent
        // still owns a slot while its own child competes for one -- and with
        // several parents cloning at once that window is the whole deadlock:
        // every parent holds a slot, every child waits for one, and the
        // parent's `ready` gate expires into `std::process::abort()`.
        //
        // Keep the caller reclaimed through publication/start: the child
        // materializer holds the topology lock until `start_tx`, so resuming the
        // parent first would exchange the slot deadlock for a topology deadlock.
        let parent_reclaim =
            self.park_vcpu_for_blocking_wait(engine, crate::thread::VcpuParkClass::ReleaseSafe)?;
        let handle = std::thread::Builder::new()
            .name(host_thread_name)
            .spawn(move || {
                crate::probes::mn_clone_outcome(
                    tid.raw(),
                    carrick_observability::probes::HvpatchCloneThreadPhase::HostThreadStarted,
                    0,
                );
                if trace {
                    eprintln!("[sibling tid#{tid}] thread started, building vCPU");
                }
                // Wait (if necessary) for room under the HVF concurrent-vCPU cap
                // BEFORE taking the topology lock. carrick binds one vCPU per
                // guest thread for its whole lifetime; HVF caps concurrent vCPUs
                // (64 on this host), so a guest with more live threads than the
                // cap (CPython test_queue.test_many_threads spawns 100) would
                // otherwise hit HV_NO_RESOURCES here. Done OUTSIDE the topology
                // lock so a fork in flight isn't stalled behind a full gate.
                E::wait_for_vcpu_slot();
                // M:N admission: borrow a vCPU slot from the scheduler (blocks if
                // the backend's N-slot pool is full; a Noop no-op on HVF/KVM). The
                // lease names the vCPU id the backend reads via `current_slot()`; an
                // RAII guard frees it on EVERY exit path (including the early
                // `!is_live` return below) except a full-process `_exit`, where
                // process death frees it anyway.
                // Admission itself must be cancellable. A clone can be queued
                // here when another thread begins exit_group; an unbounded
                // acquire leaves its JoinHandle live past the mm root-slot
                // teardown deadline even though it never created a vCPU.
                let lease = loop {
                    if child_kernel.process_exiting()
                        || child_kernel.clone_admission_cancelled()
                    {
                        crate::probes::mn_clone_outcome(
                            tid.raw(),
                            carrick_observability::probes::HvpatchCloneThreadPhase::ChildCancelledBeforeSlot,
                            crate::linux_abi::LINUX_EAGAIN.get(),
                        );
                        let _ = ready_tx.send(Err(SiblingStartFailure::Cancelled));
                        return;
                    }
                    // Wait in long slices, not short ones. Admission is FIFO,
                    // and every `acquire_timeout` call takes a FRESH place in
                    // line -- so a child that re-enters the queue every few
                    // milliseconds keeps sending itself to the back and can
                    // starve indefinitely behind threads that wait properly.
                    // Measured 2026-08-18 on `TestConcurrentExec` with a 10 ms
                    // slice: 23 children passed the HVF vCPU gate, only 17 ever
                    // got a scheduler slot, and the 6 that never did are exactly
                    // the ones whose parents' start gate expired into
                    // `std::process::abort()`. The slice only bounds how quickly
                    // cancellation is noticed, and the parent's gate is 10 s.
                    if let Some(lease) = carrick_hal::vcpu_sched::global().acquire_timeout(
                        tid.raw() as u64,
                        None,
                        CLONE_CHILD_SLOT_WAIT_SLICE,
                    ) {
                        break lease;
                    }
                };
                carrick_hal::vcpu_sched::set_current_lease(lease);
                // Covers every pre-loop exit (the process-exiting recheck and a
                // materialization error). run_vcpu_until_exit installs its own
                // guard; whichever guard sees the lease first releases it and
                // the other becomes a no-op.
                let _pre_loop_lease_guard = VcpuLeaseGuard;
                crate::probes::mn_admit(
                    tid.raw(),
                    lease.slot,
                    carrick_hal::vcpu_sched::global()
                        .budget()
                        .min(u32::MAX as usize) as u32,
                );
                crate::probes::mn_clone_outcome(
                    tid.raw(),
                    carrick_observability::probes::HvpatchCloneThreadPhase::Admitted,
                    0,
                );
                // `run_vcpu_until_exit` owns lease release for every guest
                // thread kind, including hvpatch process leaders which can
                // acquire their first lease only after a blocking wait.
                // Build the vCPU + register it in the kicker UNDER the topology
                // lock, so this is atomic w.r.t. a fork's VM teardown.
                let topo = crate::fork_quiesce::acquire_topology_lock(
                    carrick_observability::probes::HvpatchTopologyOperation::SiblingMaterialize,
                    child_kernel
                        .hvpatch_process
                        .as_ref()
                        .map_or(0, crate::hvpatch::ProcessContext::pid),
                    tid.raw(),
                );
                if child_kernel.process_exiting()
                    || child_kernel.clone_admission_cancelled()
                {
                    crate::probes::mn_clone_outcome(
                        tid.raw(),
                        carrick_observability::probes::HvpatchCloneThreadPhase::ChildCancelledBeforeMaterialize,
                        crate::linux_abi::LINUX_EAGAIN.get(),
                    );
                    drop(topo);
                    let _ = ready_tx.send(Err(SiblingStartFailure::Cancelled));
                    return;
                }
                match E::materialize_sibling(spec) {
                    Ok(mut child_engine) => {
                        crate::probes::mn_clone_outcome(
                            tid.raw(),
                            carrick_observability::probes::HvpatchCloneThreadPhase::Materialized,
                            0,
                        );
                        // Release the topology lock BEFORE the start handshake.
                        //
                        // `start_rx.recv()` is a blocking wait on the parent,
                        // and the parent does real work between observing
                        // `ready` and sending `start` — it installs the child's
                        // pidfd and publishes the child. Holding the process-
                        // wide topology lock across that wait deadlocks the
                        // whole VM: any thread that needs the lock to make
                        // progress blocks, the parent can then never reach its
                        // `start` send, and the child never releases. That is
                        // the "sibling materialization start gate timed out"
                        // abort, and it is why raising the 10 s bound to 120 s
                        // produced 121 s aborts instead of passes.
                        //
                        // It is also the general rule this tree already states:
                        // object-lock guards are never held across a blocking
                        // wait, thread creation, or a callback into another
                        // subsystem.
                        drop(topo);
                        if ready_tx.send(Ok(())).is_err() || start_rx.recv() != Ok(true) {
                            let topo = crate::fork_quiesce::acquire_topology_lock(
                                carrick_observability::probes::HvpatchTopologyOperation::SiblingMaterialize,
                                child_kernel
                                    .hvpatch_process
                                    .as_ref()
                                    .map_or(0, crate::hvpatch::ProcessContext::pid),
                                tid.raw(),
                            );
                            child_engine.destroy_vcpu_on_thread_exit();
                            drop(topo);
                            return;
                        }
                        // Re-acquire for the kicker registration, which must
                        // still be atomic with respect to a fork's VM teardown.
                        // Re-check liveness under the retaken lock: the world
                        // can have changed while we were waiting, and
                        // registering a vCPU into a torn-down VM is exactly
                        // what the lock exists to prevent.
                        let topo = crate::fork_quiesce::acquire_topology_lock(
                            carrick_observability::probes::HvpatchTopologyOperation::SiblingMaterialize,
                            child_kernel
                                .hvpatch_process
                                .as_ref()
                                .map_or(0, crate::hvpatch::ProcessContext::pid),
                            tid.raw(),
                        );
                        if child_kernel.process_exiting()
                            || child_kernel.clone_admission_cancelled()
                        {
                            crate::probes::mn_clone_outcome(
                                tid.raw(),
                                carrick_observability::probes::HvpatchCloneThreadPhase::ChildCancelledAfterMaterialize,
                                crate::linux_abi::LINUX_EAGAIN.get(),
                            );
                            child_engine.destroy_vcpu_on_thread_exit();
                            drop(topo);
                            return;
                        }
                        // The sibling's lifetime in-guest flag: created ONCE
                        // here, published with this bootstrap registration so
                        // the sibling is kickable before its loop starts, then
                        // moved into `run_vcpu_until_exit` so the loop stores
                        // into the very cell the kicker holds.
                        let sibling_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
                        let handle: Box<dyn carrick_hal::VcpuKickDyn> =
                            Box::new(child_engine.kick_handle());
                        child_kicker.register(tid, handle, &sibling_in_guest);
                        drop(topo);
                        if trace {
                            let pc = child_engine.program_counter().unwrap_or(0);
                            eprintln!("[sibling tid#{tid}] vCPU built, pc={pc:#x}, entering loop");
                        }
                        let r = run_vcpu_until_exit(
                            Arc::clone(&child_kernel),
                            child_engine,
                            child_registry,
                            child_futex,
                            child_platform_futex,
                            child_platform_futex_factory,
                            linux_tid,
                            tid,
                            child_threads,
                            child_kicker,
                            sibling_in_guest,
                            max_traps,
                        );
                        match r {
                            Ok(VcpuLoopOutcome::ProcessExit(result)) => {
                                tracing::trace!(
                                    tid = tid.raw(),
                                    exit_code = result.exit_code,
                                    "sibling reached process exit publication"
                                );
                                if child_kernel.dispatcher.execution_backend()
                                    == crate::page_profile::ExecutionBackend::HvPatch
                                {
                                    // The vCPU loop's terminal owner already ran
                                    // the unified child/root process finalizer.
                                    return;
                                }
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                                let _ = std::io::Write::flush(&mut std::io::stderr());
                                let _ = unsafe {
                                    libc::write(
                                        1,
                                        result.stdout.as_ptr() as *const _,
                                        result.stdout.len(),
                                    )
                                };
                                let _ = unsafe {
                                    libc::write(
                                        2,
                                        result.stderr.as_ptr() as *const _,
                                        result.stderr.len(),
                                    )
                                };
                                unsafe { libc::_exit(result.exit_code) };
                            }
                            Ok(VcpuLoopOutcome::TrapLimit(_)) | Ok(VcpuLoopOutcome::ThreadDone) => {
                            }
                            Err(e) => {
                                tracing::error!(tid = tid.raw(), error = %e, "thread sibling vCPU loop failed");
                                if child_kernel.dispatcher.execution_backend()
                                    == crate::page_profile::ExecutionBackend::HvPatch
                                {
                                    // Unified HVPatch terminal cleanup owns the
                                    // registry, Kernel task, and backend state.
                                    return;
                                }
                                // Exit-cleanup gate (see handle_thread_exit).
                                let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
                                cleanup_registry.exit(tid);
                                cleanup_kicker.unregister(tid);
                                crate::host_signal::forget_thread(tid.raw());
                                let _ = cleanup_kernel
                                    .dispatcher
                                    .exit_one_task_thread(linux_tid);
                            }
                        }
                    }
                    Err(error) => {
                        crate::probes::mn_clone_outcome(
                            tid.raw(),
                            carrick_observability::probes::HvpatchCloneThreadPhase::MaterializationFailed,
                            0,
                        );
                        drop(topo);
                        let _ = ready_tx
                            .send(Err(SiblingStartFailure::Materialization(error.to_string())));
                    }
                }
            })
            .map_err(|error| {
                crate::probes::mn_clone_outcome(
                    tid.raw(),
                    carrick_observability::probes::HvpatchCloneThreadPhase::HostThreadSpawnFailed,
                    error.raw_os_error().unwrap_or(0),
                );
                RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "spawn guest thread failed: {error}"
                )))
            });
        let handle = match handle {
            Ok(handle) => handle,
            Err(error) => {
                if prepared_thread.is_none() {
                    self.registry.exit(tid);
                    let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
                }
                return Err(error);
            }
        };
        // Classified 2026-08-13: this is a real deadlock/lost wakeup, NOT a time
        // assumption, so the bound is a backstop and must not be "fixed" by
        // raising it. Measured on the cold go-build fixture: a successful run
        // completes the whole build in 3-4 SECONDS, while a wedged
        // materialization waits the entire budget and never receives `ready` —
        // raising this to 120s produced 121s aborts, not passes.
        let ready_deadline = Instant::now() + Duration::from_secs(10);
        let ready = loop {
            match ready_rx.recv_timeout(Duration::from_millis(1)) {
                Ok(Ok(())) => break Ok(true),
                Ok(Err(SiblingStartFailure::Cancelled)) => break Ok(false),
                Ok(Err(SiblingStartFailure::Materialization(error))) => {
                    break Err(RuntimeError::Trap(TrapError::Hypervisor(error)));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() >= ready_deadline {
                        tracing::error!(
                            linux_tid = linux_tid.raw(),
                            backend_tid = tid.raw(),
                            process_exiting = kernel.process_exiting(),
                            clone_cancelled = clone_permit.is_cancelled(),
                            "sibling materialization start gate timed out"
                        );
                        std::process::abort();
                    }
                    // A process fork owns the topology lock before draining
                    // sibling vCPUs. A concurrent clone materializer can wait
                    // on that lock while this caller waits for `ready`.
                    if self.fork_is_quiescing() {
                        if parent_reclaim.is_some() {
                            // This vCPU is already reclaimed for the blocking
                            // wait, so there is nothing to publish from.
                            self.withdraw_from_crash_capture();
                            self.park_if_fork_quiescing();
                        } else {
                            self.release_and_park_vcpu_for_fork(engine)?;
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(RuntimeError::Trap(TrapError::Hypervisor(
                        "sibling materialization channel disconnected".to_owned(),
                    )));
                }
            }
        };
        match ready {
            Err(error) => {
                let _ = start_tx.send(false);
                let _ = handle.join();
                if prepared_thread.is_none() {
                    self.registry.exit(tid);
                    let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
                }
                self.resume_vcpu_after_blocking_wait(engine, parent_reclaim)?;
                return Err(error);
            }
            Ok(false) => {
                crate::probes::mn_clone_outcome(
                    tid.raw(),
                    carrick_observability::probes::HvpatchCloneThreadPhase::StartCancelled,
                    crate::linux_abi::LINUX_EAGAIN.get(),
                );
                let _ = start_tx.send(false);
                let _ = handle.join();
                if prepared_thread.is_none() {
                    self.registry.exit(tid);
                    let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
                }
                self.resume_vcpu_after_blocking_wait(engine, parent_reclaim)?;
                return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EAGAIN));
            }
            Ok(true) => {}
        }

        let restore_tid_outputs = |engine: &mut E| {
            if let Some(bytes) = parent_tid_original.as_ref() {
                let _ = engine.write_bytes(parent_tid_addr, bytes);
            }
            if let Some(bytes) = child_tid_original.as_ref() {
                let _ = engine.write_bytes(child_tid_addr, bytes);
            }
        };
        let tid_bytes = linux_tid.raw().to_le_bytes();
        let publish_tid_output = |engine: &mut E,
                                  output: carrick_observability::probes::HvpatchCloneTidOutput,
                                  address: u64| {
            if address == 0 {
                return true;
            }
            let result = engine.write_bytes(address, &tid_bytes);
            let result_kind = match &result {
                Ok(()) => carrick_observability::probes::HvpatchCloneTidWriteResult::Success,
                Err(carrick_guest_mem::MemoryError::OutOfBounds { .. }) => {
                    carrick_observability::probes::HvpatchCloneTidWriteResult::OutOfBounds
                }
                Err(carrick_guest_mem::MemoryError::Unsupported) => {
                    carrick_observability::probes::HvpatchCloneTidWriteResult::Unsupported
                }
                Err(carrick_guest_mem::MemoryError::HostMap(detail))
                    if detail.starts_with("HVPatch sparse mmap backing:") =>
                {
                    carrick_observability::probes::HvpatchCloneTidWriteResult::SparseBacking
                }
                Err(carrick_guest_mem::MemoryError::HostMap(detail))
                    if detail.starts_with("HVPatch frame COW:") =>
                {
                    carrick_observability::probes::HvpatchCloneTidWriteResult::FrameCow
                }
                Err(carrick_guest_mem::MemoryError::HostMap(_)) => {
                    carrick_observability::probes::HvpatchCloneTidWriteResult::HostMap
                }
            };
            crate::probes::mn_clone_tid_output(tid.raw(), output, address, result_kind);
            result.is_ok()
        };
        let tid_outputs_published = publish_tid_output(
            engine,
            carrick_observability::probes::HvpatchCloneTidOutput::Parent,
            parent_tid_addr,
        ) && publish_tid_output(
            engine,
            carrick_observability::probes::HvpatchCloneTidOutput::Child,
            child_tid_addr,
        );
        if !tid_outputs_published {
            restore_tid_outputs(engine);
            let _ = start_tx.send(false);
            let _ = handle.join();
            if prepared_thread.is_none() {
                self.registry.exit(tid);
                let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
            }
            self.resume_vcpu_after_blocking_wait(engine, parent_reclaim)?;
            return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EFAULT));
        }

        if let Some(prepared) = prepared_thread {
            let published = match prepared.commit() {
                Ok(published) => published,
                Err(error) => {
                    restore_tid_outputs(engine);
                    let _ = start_tx.send(false);
                    let _ = handle.join();
                    self.resume_vcpu_after_blocking_wait(engine, parent_reclaim)?;
                    return Err(RuntimeError::Configuration(format!(
                        "publish authoritative hvpatch thread: {error}"
                    )));
                }
            };
            if let Err(error) = published.into_context() {
                tracing::error!(
                    tid = tid.raw(),
                    %error,
                    "authoritative thread start gate failed after publication"
                );
                std::process::abort();
            }
            self.registry
                .register_child_with_tid(tid, clear_child_tid_addr);
        }
        // Make the host child visible to every exit/exec census before opening
        // its start gate. Once Kernel publication and runtime registration are
        // authoritative, a vanished receiver is an internal invariant breach,
        // not a guest-visible clone failure.
        self.threads.lock().push(handle);
        if start_tx.send(true).is_err() {
            tracing::error!(
                tid = tid.raw(),
                "sibling start gate disappeared after publication"
            );
            std::process::abort();
        }
        // Publication, registry state, handle visibility, and child start are
        // now complete. Release admission before reacquiring the parent's vCPU:
        // the child can itself become terminal and must not wait on a permit
        // whose owner is queued behind that child's scheduler slot.
        drop(clone_permit);
        crate::probes::mn_clone_outcome(
            tid.raw(),
            carrick_observability::probes::HvpatchCloneThreadPhase::ChildPublished,
            0,
        );
        self.resume_vcpu_after_blocking_wait(engine, parent_reclaim)?;
        crate::probes::mn_clone_outcome(
            tid.raw(),
            carrick_observability::probes::HvpatchCloneThreadPhase::Started,
            0,
        );
        Ok(CloneThreadSpawn::Started(linux_tid))
    }

    /// Stop every sibling vCPU belonging to this Linux process before its
    /// mm's stage-1 root and final global frames are unmapped. The old
    /// `VCPU_LIVE == 1` exec drain is
    /// process-global and therefore cannot distinguish unrelated processes in
    /// a shared VM; this path instead uses the process-private registry,
    /// kicker, and sibling JoinHandles.
    pub(super) fn terminate_siblings_for_process_exit(
        &self,
        kernel: &Kernel,
    ) -> Result<(), RuntimeError> {
        kernel.begin_process_exit();
        let current_host_thread = std::thread::current().id();
        // Give an attached debugger a bounded window to capture a stranded
        // sibling when fault diagnostics are explicitly enabled. Production
        // behavior retains the five-second fail-closed deadline.
        let teardown_timeout = if std::env::var_os("CARRICK_FAULT_DEBUG").is_some() {
            std::time::Duration::from_secs(30)
        } else {
            std::time::Duration::from_secs(5)
        };
        let teardown_started = std::time::Instant::now();
        let deadline = std::time::Instant::now() + teardown_timeout;
        let mut debugger_window_announced = false;

        loop {
            // Registry removal is the durable stop predicate used by guest-loop
            // tops and every blocking-wait completion path. Keep the owner's
            // entry until all siblings have finished so none can report itself
            // as the final process thread and retire the bank concurrently.
            let _ = self.registry.remove_all_except(self.this_tid);
            self.kicker.kick_all_except(self.this_tid);
            self.futex.notify_signal_pending();
            self.platform_futex.notify_signal_pending();
            kernel.signal_arrival.wake_all_waiters();

            let unfinished = self
                .threads
                .lock()
                .iter()
                .filter(|handle| handle.thread().id() != current_host_thread)
                .filter(|handle| !handle.is_finished())
                .count();
            let guest_executors = kernel.guest_executor_count();
            if unfinished == 0 && guest_executors <= 1 {
                break;
            }
            if !debugger_window_announced
                && teardown_timeout > std::time::Duration::from_secs(5)
                && teardown_started.elapsed() >= std::time::Duration::from_secs(5)
            {
                let unfinished_names: Vec<_> = self
                    .threads
                    .lock()
                    .iter()
                    .filter(|handle| handle.thread().id() != current_host_thread)
                    .filter(|handle| !handle.is_finished())
                    .map(|handle| handle.thread().name().unwrap_or("<unnamed>").to_owned())
                    .collect();
                eprintln!(
                    "[FAULTDBG teardown pid={}] unfinished={unfinished_names:?}; debugger window open",
                    kernel
                        .hvpatch_process
                        .as_ref()
                        .map_or(0, crate::hvpatch::ProcessContext::pid)
                );
                debugger_window_announced = true;
            }
            if std::time::Instant::now() >= deadline {
                return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "hvpatch process thread-group teardown timed out: pid={} unfinished={} guest_executors={} kicker={}",
                    kernel
                        .hvpatch_process
                        .as_ref()
                        .map_or(0, crate::hvpatch::ProcessContext::pid),
                    unfinished,
                    guest_executors,
                    self.kicker.count()
                ))));
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }

        let handles = std::mem::take(&mut *self.threads.lock());
        for handle in handles {
            // A non-leader thread may itself initiate fatal termination. Its
            // JoinHandle lives in this vector, but a thread cannot join itself;
            // dropping that one handle is correct because this stack is already
            // performing its terminal cleanup.
            if handle.thread().id() == current_host_thread {
                continue;
            }
            if handle.join().is_err() {
                return Err(RuntimeError::Trap(TrapError::Hypervisor(
                    "hvpatch sibling panicked during process exit".to_owned(),
                )));
            }
        }
        Ok(())
    }

    pub(super) fn settle_execution_lease_on_loop_departure(&self) {
        if let (Some(thread), Some(lease)) = (
            self.kernel_thread.as_ref(),
            self.execution_lease.lock().take(),
        ) && let Err((error, lease)) = thread.exit_from_executor(lease)
        {
            tracing::error!(%error, "settle exact execution lease on thread exit failed");
            let _ = thread.fail_from_executor(
                lease,
                crate::kernel::objects::ExecutionFailure::SnapshotGenerationMismatch,
            );
        }
    }

    pub(super) fn handle_thread_exit(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        code: i32,
        traps: usize,
    ) -> VcpuLoopOutcome {
        self.settle_execution_lease_on_loop_departure();
        // Exit-cleanup gate: the moment `kicker.unregister` below runs, a
        // concurrent fork's quiesce stops counting this thread — but the
        // cleanup that follows (`host_signal::forget_thread`) takes a
        // process-global mutex. If
        // `libc::fork` lands while one is held, the CHILD inherits it locked
        // forever (the deterministic go-os_exec TestConcurrentExec wedge: the
        // vfork child deadlocked in inherited signal-state cleanup). The guard is
        // a non-blocking atomic count; `handle_fork` waits for it to drain
        // (bounded) after the quiesce and before forking.
        let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 1);
        if let Some(addr) = self.registry.clear_child_tid(self.this_tid)
            && addr != 0
        {
            let _ = engine.write_bytes(addr, &0i32.to_le_bytes());
            let woken = self.futex.wake(addr, 1);
            crate::event_ring::rec_futex_wake(addr, woken);
        }
        let mut last = self.registry.exit(self.this_tid);
        if !last {
            if let Some(process) = kernel.hvpatch_process.as_ref() {
                match process.exit_thread(self.linux_tid) {
                    Ok(crate::hvpatch::ProcessThreadExit::Retired(retired)) => {
                        kernel.dispatcher.close_draining_file_table(
                            process.kernel_graph(),
                            &retired.files(),
                            Some(retired.owner()),
                            None,
                        );
                    }
                    Ok(crate::hvpatch::ProcessThreadExit::AlreadyRetired) => {}
                    Ok(crate::hvpatch::ProcessThreadExit::LastThread) => {
                        // Concurrent sibling retirement made this the final
                        // authoritative thread after the runtime-registry check.
                        // Escalate to the one process-terminal owner.
                        last = true;
                    }
                    Err(error) => {
                        tracing::error!(
                            pid = process.pid(),
                            tid = self.this_tid.raw(),
                            %error,
                            "retire authoritative hvpatch thread failed; terminating process"
                        );
                        last = true;
                    }
                }
            } else if let Err(error) = kernel.dispatcher.exit_one_task_thread(self.linux_tid) {
                tracing::error!(
                    tid = self.this_tid.raw(),
                    %error,
                    "retire one-task adapter thread failed"
                );
            }
        }
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 2);
        crate::run_state::clear_guest_tid(self.this_tid.raw());
        self.kicker.unregister(self.this_tid);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 3);
        crate::host_signal::forget_thread(self.this_tid.raw());
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 4);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 5);
        if last {
            let result = assemble_run_result(kernel, code, None, traps, false);
            VcpuLoopOutcome::ProcessExit(Box::new(result))
        } else {
            // A sibling thread is going away but the process lives on: destroy
            // its vCPU now (the no-op Drop won't), else it leaks live and a
            // later fork's hv_vm_destroy hits HV_BUSY on the dead thread's vCPU.
            engine.destroy_vcpu_on_thread_exit();
            trace_hvpatch_thread_teardown(kernel, self.this_tid, 6);
            VcpuLoopOutcome::ThreadDone
        }
    }

    pub(super) fn terminate_siblings_for_exec(
        &self,
        kernel: &Kernel,
        _engine: &mut E,
    ) -> Result<(), RuntimeError> {
        // Linux execve replaces the whole thread group. Carrick's execve path
        // tears down the old guest address space — HVF destroys/recreates the
        // process-wide VM; KVM deletes every memslot and munmaps the old
        // `GuestRam` in place (`execve_into`) — so every sibling vCPU must be
        // gone before `execve_into` runs. The drain below is therefore live on
        // BOTH backends: a just-kicked sibling can still be mid-dispatch
        // holding raw host pointers into the old RAM (use-after-free) or
        // mid-`map_host_alias` (slot-allocator vs `reset_slot_counter` race)
        // until its engine drops and `VCPU_LIVE` falls to 1 (measured without
        // the drain: 60/60 multithreaded-execv iterations EFAULT'd sibling
        // KVM_RUNs after the slot teardown). Forward progress is the kick
        // protocol: the kick forces the vCPU out of the guest (hv_vcpus_exit /
        // signal→KVM_RUN EINTR), blocked waits wake via
        // `exec_replacing_other_thread` predicates, and the loop top observes
        // the flag and exits — the wait stays BOUNDED (5s) against pathology
        // either way. (Non-linux scaffolding (bhyve): inert always-0
        // VCPU_LIVE → no wait, unchanged until it implements the contract.)
        let topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::ExecSiblingGate,
            kernel
                .hvpatch_process
                .as_ref()
                .map_or(0, crate::hvpatch::ProcessContext::pid),
            self.this_tid.raw(),
        );

        if kernel.hvpatch_process.is_some() {
            // In one shared VM, exec replaces only THIS Linux process's thread
            // group. The legacy global exec marker + VCPU_LIVE drain makes one
            // compiler process terminate unrelated compiler processes. Remove
            // this process's sibling registry entries first (the durable stop
            // predicate used by every wait/reclaim path), then drain only its
            // JoinHandles and live-vCPU counter. The topology lock still
            // serializes the shared VM's stage-2 mutation across processes.
            // A not-yet-materialized clone may need this lock once admission
            // succeeds so it can observe the registry removal and retire.
            // Actual exec stage-2 mutation is serialized separately around
            // `engine.execve_into` after this drain.
            drop(topology);
            let current_host_thread = std::thread::current().id();
            let _ = self.registry.remove_all_except(self.this_tid);
            self.kicker.kick_all_except(self.this_tid);
            self.futex.notify_signal_pending();
            self.platform_futex.notify_signal_pending();
            kernel.signal_arrival.wake_all_waiters();

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let unfinished = self
                    .threads
                    .lock()
                    .iter()
                    .filter(|handle| handle.thread().id() != current_host_thread)
                    .filter(|handle| !handle.is_finished())
                    .count();
                if unfinished == 0 && kernel.guest_executor_count() <= 1 {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                        "hvpatch exec thread-group teardown timed out: pid={} unfinished={} guest_executors={} kicker={}",
                        kernel
                            .hvpatch_process
                            .as_ref()
                            .map_or(0, crate::hvpatch::ProcessContext::pid),
                        unfinished,
                        kernel.guest_executor_count(),
                        self.kicker.count()
                    ))));
                }
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }

            let handles = std::mem::take(&mut *self.threads.lock());
            for handle in handles {
                if handle.thread().id() == current_host_thread {
                    continue;
                }
                if handle.join().is_err() {
                    return Err(RuntimeError::Trap(TrapError::Hypervisor(
                        "hvpatch sibling panicked during exec".to_owned(),
                    )));
                }
            }
            return Ok(());
        }

        kernel.begin_exec_replacement(self.this_tid);
        self.kicker.kick_all_except(self.this_tid);
        self.platform_futex.notify_signal_pending();
        kernel.signal_arrival.wake_all_waiters();

        {
            use std::sync::atomic::Ordering::SeqCst;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::trap::VCPU_LIVE.load(SeqCst) > 1 {
                if std::time::Instant::now() >= deadline {
                    kernel.end_exec_replacement();
                    return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                        "execve thread-group teardown timed out: vcpu_live={} kicker={}",
                        crate::trap::VCPU_LIVE.load(SeqCst),
                        self.kicker.count()
                    ))));
                }
                self.kicker.kick_all_except(self.this_tid);
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        }

        let removed = self.registry.remove_all_except(self.this_tid);
        for tid in removed {
            self.kicker.unregister(tid);
            crate::host_signal::forget_thread(tid.raw());
        }
        kernel.end_exec_replacement();
        Ok(())
    }
}
