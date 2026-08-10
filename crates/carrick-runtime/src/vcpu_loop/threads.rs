//! THREAD concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

enum SharedWordWaitRaw {
    Retval(i64),
    ExecReplacedThread,
}

pub(super) enum CloneThreadSpawn {
    Started(ThreadId),
    Errno(crate::linux_abi::LinuxErrno),
}

fn guest_host_thread_name(process_pid: Option<i32>, tid: ThreadId) -> String {
    process_pid.map_or_else(
        || format!("guest-tid-{tid}"),
        |pid| format!("guest-pid-{pid}-tid-{tid}"),
    )
}

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
        // waits for the sibling's JoinHandle before retiring the process bank.
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
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn register_vcpu(&self, engine: &E) {
        let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
        self.kicker.register(self.this_tid, handle);
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
                let st = engine.save_guest_state();
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
                Some((st, old_slot))
            } else {
                None
            };
            // Genuine guest block (FUTEX_WAIT): publish Blocked so a sibling's
            // /proc/<pid>/stat reads `S`. `Running` is re-published when the vCPU
            // resumes guest code after the wake (run_vcpu_until_exit top).
            crate::run_state::publish(crate::run_state::RunState::Blocked);
            crate::thread::set_current_thread_state(self.this_tid, 'S');
            crate::run_state::publish_guest_tid(
                self.this_tid.raw(),
                crate::run_state::RunState::Blocked,
            );
            crate::event_ring::rec_futex_wait(wait.addr, self.this_tid.raw());
            let raw = self
                .futex
                .wait_prepared_for_thread(wait, timeout, self.this_tid, &|| {
                    crate::host_signal::has_pending_for(self.this_tid.raw())
                        || self.fork_is_quiescing()
                        || crate::fork_quiesce::exec_replacing_other_thread(self.this_tid)
                        || !self.registry.is_live(self.this_tid)
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
            crate::thread::set_current_thread_state(self.this_tid, 'R');
            crate::run_state::publish_guest_tid(
                self.this_tid.raw(),
                crate::run_state::RunState::Running,
            );
            if thread_should_finish_for_exec_replacement(&self.registry, self.this_tid) {
                return Ok(BlockingWaitCompletion::ExecReplacedThread);
            }
            if let Some((st, old_slot)) = snapshot {
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
                            self.park_if_fork_quiescing();
                        }
                    },
                );
                let Some(new) = new else {
                    return Ok(BlockingWaitCompletion::ExecReplacedThread);
                };
                carrick_hal::vcpu_sched::set_current_lease(new);
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
                    engine
                        .rebind_to_slot(new.slot, &st)
                        .map_err(RuntimeError::Trap)?;
                    let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
                    self.kicker.register(self.this_tid, handle);
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
                        self.park_if_fork_quiescing();
                    }
                    // Re-register BEFORE the re-bind so a quiesce that starts
                    // mid-re-bind waits for us to reach the run-loop-top park
                    // (the pre-reclaim drain contract); a kick landing during
                    // the stub drive is handled (Kicked → re-run).
                    if kicker_dropped {
                        self.register_vcpu(engine);
                    }
                    engine
                        .rebind_to_slot(new.slot, &st)
                        .map_err(RuntimeError::Trap)?;
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
        engine: &mut E,
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        self.complete_shared_futex_wait_with_value(engine, location, waiter_key, value, timeout, 0)
    }

    pub(super) fn complete_shared_futex_waitv(
        &self,
        engine: &mut E,
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
        index: i64,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        self.complete_shared_futex_wait_with_value(
            engine, location, waiter_key, value, timeout, index,
        )
    }

    fn wait_on_shared_word_retval(
        &self,
        engine: &mut E,
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
    ) -> Result<SharedWordWaitRaw, RuntimeError> {
        let interrupted = || {
            crate::host_signal::has_pending_for(self.this_tid.raw())
                || self.fork_is_quiescing()
                || crate::fork_quiesce::exec_replacing_other_thread(self.this_tid)
                || !self.registry.is_live(self.this_tid)
        };
        let retval = loop {
            // Shared park/resume pair (mod.rs): reclaim this thread's vCPU —
            // and, for a single-threaded process, the whole VM — for the
            // duration of the shared-word wait. ReleaseSafe: the wake is the
            // cross-process futex mirror / __ulock predicate, the ORIGINAL
            // (E4) VM-released wait shape, proven vCPU-less.
            let reclaim =
                self.park_vcpu_for_blocking_wait(engine, crate::thread::VcpuParkClass::ReleaseSafe);

            let publish_wait_enrolled = || {
                crate::run_state::publish(crate::run_state::RunState::Blocked);
                crate::thread::set_current_thread_state(self.this_tid, 'S');
                crate::run_state::publish_guest_tid(
                    self.this_tid.raw(),
                    crate::run_state::RunState::Blocked,
                );
            };
            let retval = self.platform_futex.shared_wait(
                location,
                waiter_key,
                value,
                timeout,
                &interrupted,
                &publish_wait_enrolled,
            );
            crate::thread::set_current_thread_state(self.this_tid, 'R');
            crate::run_state::publish_guest_tid(
                self.this_tid.raw(),
                crate::run_state::RunState::Running,
            );
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
        engine: &mut E,
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        value: u32,
    ) -> Result<SharedWordWaitCompletion, RuntimeError> {
        match self.wait_on_shared_word_retval(engine, location, waiter_key, value, None)? {
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
        engine: &mut E,
        location: carrick_guest_mem::SharedFutexLocation,
        waiter_key: usize,
        value: u32,
        timeout: Option<Duration>,
        woken_value: i64,
    ) -> Result<BlockingWaitCompletion, RuntimeError> {
        let retval =
            match self.wait_on_shared_word_retval(engine, location, waiter_key, value, timeout)? {
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
        engine: &mut E,
        stack: u64,
        tls: Option<u64>,
        flags: u64,
        parent_tid_addr: u64,
        child_tid_addr: u64,
        clear_child_tid_addr: u64,
    ) -> Result<CloneThreadSpawn, RuntimeError> {
        if kernel.process_exiting() {
            return Err(RuntimeError::Trap(TrapError::Hypervisor(
                "clone raced process exit".to_owned(),
            )));
        }
        let (linux_tid, tid, prepared_thread) =
            if let Some(process) = kernel.hvpatch_process.as_ref() {
                let plan = match crate::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::from_bits_retain(flags),
                ) {
                    Ok(plan) => plan,
                    Err(_) => return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EINVAL)),
                };
                let parent = process
                    .context_for_linux_tid(self.linux_tid)
                    .map_err(|error| {
                        RuntimeError::Configuration(format!(
                            "capture authoritative hvpatch thread parent: {error}"
                        ))
                    })?;
                let reservation = process
                    .kernel_graph()
                    .reserve_thread_clone(&parent, plan, None)
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
                let linux_tid = match kernel.dispatcher.register_one_task_thread(tid) {
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
        let tid_bytes = tid.raw().to_le_bytes();
        if (parent_tid_addr != 0 && engine.write_bytes(parent_tid_addr, &tid_bytes).is_err())
            || (child_tid_addr != 0 && engine.write_bytes(child_tid_addr, &tid_bytes).is_err())
        {
            if prepared_thread.is_none() {
                self.registry.exit(tid);
                let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
            }
            return Ok(CloneThreadSpawn::Errno(crate::linux_abi::LINUX_EFAULT));
        }

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
        let handle = std::thread::Builder::new()
            .name(host_thread_name)
            .spawn(move || {
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
                // acquire leaves its JoinHandle live past the process-bank
                // teardown deadline even though it never created a vCPU.
                let lease = loop {
                    if child_kernel.process_exiting() {
                        let _ = ready_tx.send(Err("process exited before sibling admission".to_owned()));
                        return;
                    }
                    if let Some(lease) = carrick_hal::vcpu_sched::global().acquire_timeout(
                        tid.raw() as u64,
                        None,
                        Duration::from_millis(10),
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
                if child_kernel.process_exiting() {
                    drop(topo);
                    let _ = ready_tx.send(Err("process exited before sibling materialization".to_owned()));
                    return;
                }
                match E::materialize_sibling(spec) {
                    Ok(child_engine) => {
                        if ready_tx.send(Ok(())).is_err() || start_rx.recv() != Ok(true) {
                            drop(topo);
                            return;
                        }
                        let handle: Box<dyn carrick_hal::VcpuKickDyn> =
                            Box::new(child_engine.kick_handle());
                        child_kicker.register(tid, handle);
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
                            max_traps,
                        );
                        match r {
                            Ok(VcpuLoopOutcome::ProcessExit(result)) => {
                                tracing::trace!(
                                    tid = tid.raw(),
                                    exit_code = result.exit_code,
                                    "hvpatch sibling reached process exit publication"
                                );
                                if child_kernel.dispatcher.execution_backend()
                                    == crate::page_profile::ExecutionBackend::HvPatch
                                {
                                    if let Some(process) = child_kernel
                                        .hvpatch_process
                                        .as_ref()
                                        .filter(|process| process.is_child())
                                    {
                                        // An in-process Linux child has no outer
                                        // CLI owner for its private dispatcher.
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
                                        if let Err(error) =
                                            process.publish_exit_code(result.exit_code, tid)
                                        {
                                            tracing::error!(
                                                pid = process.pid(),
                                                %error,
                                                "publish sibling-initiated hvpatch child exit failed"
                                            );
                                        }
                                    }
                                    // A root result is emitted exactly once by
                                    // the main CLI owner after the completion
                                    // barrier; never write it from this worker.
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
                                if let Some(process) = child_kernel
                                    .hvpatch_process
                                    .as_ref()
                                    .filter(|process| process.is_child())
                                    && let Err(error) = process.publish_exit_code(127, tid)
                                {
                                    tracing::error!(
                                        pid = process.pid(),
                                        %error,
                                        "publish failed sibling-initiated hvpatch child exit failed"
                                    );
                                }
                                // Exit-cleanup gate (see handle_thread_exit).
                                let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
                                cleanup_registry.exit(tid);
                                cleanup_kicker.unregister(tid);
                                crate::host_signal::forget_thread(tid.raw());
                                cleanup_kernel.dispatcher.forget_thread_signal_state(tid);
                                if cleanup_kernel.hvpatch_process.is_none() {
                                    let _ = cleanup_kernel
                                        .dispatcher
                                        .exit_one_task_thread(linux_tid);
                                }
                            }
                        }
                    }
                    Err(error) => {
                        drop(topo);
                        let _ = ready_tx.send(Err(error.to_string()));
                    }
                }
            })
            .map_err(|error| {
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
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = start_tx.send(false);
                let _ = handle.join();
                if prepared_thread.is_none() {
                    self.registry.exit(tid);
                    let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
                }
                return Err(RuntimeError::Trap(TrapError::Hypervisor(error)));
            }
            Err(error) => {
                let _ = start_tx.send(false);
                let _ = handle.join();
                if prepared_thread.is_none() {
                    self.registry.exit(tid);
                    let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
                }
                return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "sibling materialization channel failed: {error}"
                ))));
            }
        }
        if let Some(prepared) = prepared_thread {
            let published = match prepared.commit() {
                Ok(published) => published,
                Err(error) => {
                    let _ = start_tx.send(false);
                    let _ = handle.join();
                    return Err(RuntimeError::Configuration(format!(
                        "publish authoritative hvpatch thread: {error}"
                    )));
                }
            };
            published.into_context().map_err(|error| {
                RuntimeError::Configuration(format!("start authoritative hvpatch thread: {error}"))
            })?;
            self.registry
                .register_child_with_tid(tid, clear_child_tid_addr);
        }
        kernel
            .dispatcher
            .inherit_thread_signal_mask(self.this_tid, tid);
        if start_tx.send(true).is_err() {
            self.registry.exit(tid);
            if let Some(process) = kernel.hvpatch_process.as_ref() {
                let _ = process.exit_thread(linux_tid);
            } else {
                let _ = kernel.dispatcher.exit_one_task_thread(linux_tid);
            }
            let _ = handle.join();
            return Err(RuntimeError::Configuration(
                "sibling start gate disappeared after publication".to_owned(),
            ));
        }
        self.threads.lock().push(handle);
        Ok(CloneThreadSpawn::Started(tid))
    }

    /// Stop every sibling vCPU belonging to this Linux process before its
    /// process bank is unmapped.  The old `VCPU_LIVE == 1` exec drain is
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
            let process_vcpu_live = kernel.process_vcpu_live();
            if unfinished == 0 && process_vcpu_live <= 1 {
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
                    "hvpatch process thread-group teardown timed out: pid={} unfinished={} process_vcpu_live={} kicker={}",
                    kernel
                        .hvpatch_process
                        .as_ref()
                        .map_or(0, crate::hvpatch::ProcessContext::pid),
                    unfinished,
                    process_vcpu_live,
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

    pub(super) fn handle_thread_exit(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        code: i32,
        traps: usize,
    ) -> VcpuLoopOutcome {
        // Exit-cleanup gate: the moment `kicker.unregister` below runs, a
        // concurrent fork's quiesce stops counting this thread — but the
        // cleanup that follows (host_signal::forget_thread, the dispatcher's
        // forget_thread_signal_state) takes process-global mutexes. If
        // `libc::fork` lands while one is held, the CHILD inherits it locked
        // forever (the deterministic go-os_exec TestConcurrentExec wedge: the
        // vfork child deadlocked in migrate_thread_signal_state). The guard is
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
        let last = self.registry.exit(self.this_tid);
        if !last {
            if let Some(process) = kernel.hvpatch_process.as_ref() {
                if let Err(error) = process.exit_thread(self.linux_tid) {
                    tracing::error!(
                        pid = process.pid(),
                        tid = self.this_tid.raw(),
                        %error,
                        "retire authoritative hvpatch thread failed"
                    );
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
        kernel.dispatcher.forget_thread_signal_state(self.this_tid);
        trace_hvpatch_thread_teardown(kernel, self.this_tid, 5);
        if last {
            let result = assemble_run_result(kernel, code, traps, false);
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
                if unfinished == 0 && kernel.process_vcpu_live() <= 1 {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                        "hvpatch exec thread-group teardown timed out: pid={} unfinished={} process_vcpu_live={} kicker={}",
                        kernel
                            .hvpatch_process
                            .as_ref()
                            .map_or(0, crate::hvpatch::ProcessContext::pid),
                        unfinished,
                        kernel.process_vcpu_live(),
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
            kernel.dispatcher.forget_thread_signal_state(tid);
        }
        kernel.end_exec_replacement();
        Ok(())
    }
}
