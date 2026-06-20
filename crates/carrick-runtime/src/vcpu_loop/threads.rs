//! THREAD concern of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

use super::*;

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
        engine: &mut E,
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
    ) -> Result<i64, RuntimeError> {
        use crate::thread::FutexWaitOutcome;

        let retval: i64 = loop {
            // M:N reclaim-on-block: free this thread's vCPU slot for the duration of
            // the blocking wait so another guest thread can run on it, restoring this
            // thread's state into a (possibly different) slot on wake. Only when the
            // backend reclaims (bhyve); a no-op on HVF/KVM (Phase 1 lifetime-bind).
            let snapshot = if engine.reclaims() && carrick_hal::vcpu_sched::global().has_waiters() {
                let st = engine.save_guest_state();
                let old_slot = carrick_hal::vcpu_sched::current_slot();
                if let Some(l) = carrick_hal::vcpu_sched::take_current_lease() {
                    carrick_hal::vcpu_sched::global()
                        .release(l, carrick_hal::vcpu_sched::Yield::Blocked);
                }
                Some((st, old_slot))
            } else {
                None
            };
            let raw = self
                .futex
                .wait_prepared_for_thread(wait, timeout, self.this_tid, &|| {
                    crate::host_signal::has_pending_for(self.this_tid)
                        || crate::fork_quiesce::is_quiescing()
                        || crate::fork_quiesce::exec_replacing_other_thread(self.this_tid)
                });
            if let Some((st, old_slot)) = snapshot {
                // Prefer the thread's OWN just-released slot (reuse its clean vCPU,
                // no re-bind) over reclaiming another thread's — esp. an exited one.
                let new = match old_slot {
                    Some(p) => carrick_hal::vcpu_sched::global()
                        .acquire_preferring(self.this_tid as u64, p),
                    None => carrick_hal::vcpu_sched::global().acquire(self.this_tid as u64),
                };
                carrick_hal::vcpu_sched::set_current_lease(new);
                engine
                    .rebind_to_slot(new.slot, &st)
                    .map_err(RuntimeError::Trap)?;
            }
            let outcome = match raw {
                FutexWaitOutcome::Woken => 0,
                FutexWaitOutcome::TimedOut => -(crate::linux_abi::LINUX_ETIMEDOUT as i64),
                FutexWaitOutcome::Interrupted if crate::fork_quiesce::is_quiescing() => {
                    self.release_and_park_vcpu_for_fork(engine)?;
                    continue;
                }
                FutexWaitOutcome::Interrupted => -(crate::linux_abi::LINUX_EINTR as i64),
            };
            break outcome;
        };
        self.complete_returned(engine, retval)
    }

    pub(super) fn complete_shared_futex_wait(
        &self,
        engine: &mut E,
        host_addr: usize,
        value: u32,
        timeout: Option<Duration>,
    ) -> Result<i64, RuntimeError> {
        let interrupted = || {
            crate::host_signal::has_pending_for(self.this_tid)
                || crate::fork_quiesce::is_quiescing()
                || crate::fork_quiesce::exec_replacing_other_thread(self.this_tid)
        };
        let retval = loop {
            let retval = self
                .platform_futex
                .shared_wait(host_addr, value, timeout, &interrupted);
            if retval == -(crate::linux_abi::LINUX_EINTR as i64)
                && crate::fork_quiesce::is_quiescing()
            {
                self.release_and_park_vcpu_for_fork(engine)?;
                continue;
            }
            break retval;
        };
        self.complete_returned(engine, retval)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_clone_thread(
        &self,
        kernel: &Kernel,
        engine: &mut E,
        stack: u64,
        tls: u64,
        parent_tid_addr: u64,
        child_tid_addr: u64,
    ) -> Result<ThreadId, RuntimeError> {
        let clear_addr = if child_tid_addr != 0 {
            child_tid_addr
        } else {
            0
        };
        let tid = self.registry.register_child(clear_addr);
        let tid_bytes = tid.to_le_bytes();
        if parent_tid_addr != 0 {
            let _ = engine.write_bytes(parent_tid_addr, &tid_bytes);
        }
        if child_tid_addr != 0 {
            let _ = engine.write_bytes(child_tid_addr, &tid_bytes);
        }

        let spec = engine.build_sibling_spec(carrick_hal::GuestEntryRegs {
            return_value: 0,
            stack: Some(stack),
            tls: Some(tls),
        })?;
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
        let handle = std::thread::Builder::new()
            .name(format!("guest-tid-{tid}"))
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
                let lease = carrick_hal::vcpu_sched::global().acquire(tid as u64);
                carrick_hal::vcpu_sched::set_current_lease(lease);
                struct SlotGuard;
                impl Drop for SlotGuard {
                    fn drop(&mut self) {
                        if let Some(l) = carrick_hal::vcpu_sched::take_current_lease() {
                            carrick_hal::vcpu_sched::global()
                                .release(l, carrick_hal::vcpu_sched::Yield::Exited);
                        }
                    }
                }
                let _slot_guard = SlotGuard;
                // Build the vCPU + register it in the kicker UNDER the topology
                // lock, so this is atomic w.r.t. a fork's VM teardown.
                let topo = crate::fork_quiesce::topology_lock()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !child_registry.is_live(tid) {
                    // Exit-cleanup gate (see handle_thread_exit): taken BEFORE
                    // dropping the topology lock so a fork can never land
                    // mid-cleanup with one of these global mutexes held.
                    let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
                    drop(topo);
                    child_kicker.unregister(tid);
                    crate::host_signal::forget_thread(tid);
                    child_kernel.dispatcher.forget_thread_signal_state(tid);
                    return;
                }
                match E::materialize_sibling(spec) {
                    Ok(child_engine) => {
                        let handle: Box<dyn carrick_hal::VcpuKickDyn> =
                            Box::new(child_engine.kick_handle());
                        child_kicker.register(tid, handle);
                        drop(topo);
                        if trace {
                            let pc = child_engine.program_counter().unwrap_or(0);
                            eprintln!("[sibling tid#{tid}] vCPU built, pc={pc:#x}, entering loop");
                        }
                        let r = run_vcpu_until_exit(
                            child_kernel,
                            child_engine,
                            child_registry,
                            child_futex,
                            child_platform_futex,
                            child_platform_futex_factory,
                            tid,
                            child_threads,
                            child_kicker,
                            max_traps,
                        );
                        match r {
                            Ok(VcpuLoopOutcome::ProcessExit(result)) => {
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
                                tracing::error!(tid, error = %e, "thread sibling vCPU loop failed");
                                // Exit-cleanup gate (see handle_thread_exit).
                                let _cleanup_gate = crate::fork_quiesce::begin_exit_cleanup();
                                cleanup_registry.exit(tid);
                                cleanup_kicker.unregister(tid);
                                crate::host_signal::forget_thread(tid);
                                cleanup_kernel.dispatcher.forget_thread_signal_state(tid);
                            }
                        }
                    }
                    Err(e) => {
                        drop(topo);
                        tracing::error!(tid, error = %e, "thread sibling vCPU failed to start");
                        child_registry.exit(tid);
                    }
                }
            })
            .map_err(|e| {
                RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "spawn guest thread failed: {e}"
                )))
            })?;
        self.threads.lock().push(handle);
        Ok(tid)
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
        if let Some(addr) = self.registry.clear_child_tid(self.this_tid)
            && addr != 0
        {
            let _ = engine.write_bytes(addr, &0i32.to_le_bytes());
            self.futex.wake(addr, 1);
        }
        let last = self.registry.exit(self.this_tid);
        self.kicker.unregister(self.this_tid);
        crate::host_signal::forget_thread(self.this_tid);
        kernel.dispatcher.forget_thread_signal_state(self.this_tid);
        if last {
            let result = assemble_run_result(kernel, code, traps, false);
            VcpuLoopOutcome::ProcessExit(Box::new(result))
        } else {
            // A sibling thread is going away but the process lives on: destroy
            // its vCPU now (the no-op Drop won't), else it leaks live and a
            // later fork's hv_vm_destroy hits HV_BUSY on the dead thread's vCPU.
            engine.destroy_vcpu_on_thread_exit();
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
        let _topology = crate::fork_quiesce::topology_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
            crate::host_signal::forget_thread(tid);
            kernel.dispatcher.forget_thread_signal_state(tid);
        }
        kernel.end_exec_replacement();
        Ok(())
    }
}
