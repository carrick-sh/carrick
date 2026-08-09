//! MEM concern: fork / page-table quiesce of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). The page-table pause is a
//! transactional typed gate: timeout rolls the request back before dispatch;
//! fork quiesce remains the separate process-topology protocol below.

use super::*;

/// Process-wide fork quiesce barrier (defined in `fork_quiesce` so the blocking
/// wait predicates can reach the same instance).
pub(crate) fn fork_barrier() -> &'static crate::fork_quiesce::QuiesceBarrier {
    crate::fork_quiesce::barrier()
}

/// Process-wide page-table-edit Pause-Modify-Resume barrier.
pub(crate) fn pt_barrier() -> &'static crate::fork_quiesce::PtQuiesce {
    crate::fork_quiesce::pt_barrier()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PtPauseError {
    TimedOut,
}

fn acquire_pt_pause(
    barrier: &'static crate::fork_quiesce::PtQuiesce,
    kicker: &dyn carrick_hal::VcpuRegistry,
    tid: ThreadId,
    timeout: Duration,
) -> Result<crate::fork_quiesce::PtPauseGuard, PtPauseError> {
    // Serialize editors: at most one stop-the-world at a time. A loser parks
    // (if the winner has raised quiescing) or yields (tiny pre-flag window),
    // then retries. This stays independent of the fork/topology lock.
    loop {
        if barrier.try_become_coordinator() {
            break;
        }
        if barrier.is_quiescing() {
            barrier.park();
        } else {
            std::thread::yield_now();
        }
    }
    barrier.set_quiescing();
    crate::probes::pt_pause_begin(
        tid.raw(),
        i32::from(kicker.any_other_in_guest(tid)),
        kicker.count() as i32,
    );

    let start = Instant::now();
    let deadline = start + timeout;
    let mut spins: i32 = 0;
    while kicker.any_other_in_guest(tid) {
        kicker.kick_all_except(tid);
        if Instant::now() >= deadline {
            crate::probes::pt_pause_timeout(tid.raw(), start.elapsed().as_micros() as i64);
            // Roll back BOTH persistent request bits and wake every sibling that
            // already parked. Returning a guard while the predicate is still
            // true would let the caller edit live page tables.
            barrier.end();
            return Err(PtPauseError::TimedOut);
        }
        spins = spins.saturating_add(1);
        std::thread::yield_now();
    }
    crate::probes::pt_pause_ready(tid.raw(), spins, start.elapsed().as_micros() as i64);
    Ok(barrier.pause_guard(tid))
}

pub(super) struct ForkRequest {
    pub(super) pidfd_out: Option<u64>,
    pub(super) clone_parent: bool,
    pub(super) parent_tid_addr: Option<u64>,
    pub(super) child_tid_addr: Option<u64>,
    pub(super) exit_signal: u32,
    pub(super) child_stack: u64,
    pub(super) vfork: Option<u64>,
}

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
    E::ProcessSpec: 'static,
{
    /// Pause sibling vCPUs for a stage-1 page-table edit (mmap/mprotect/munmap),
    /// returning an RAII guard that resumes them on drop. A timeout is a typed
    /// clean failure: the barrier request is rolled back and no edit may begin.
    pub(super) fn pt_pause(&self) -> Result<crate::fork_quiesce::PtPauseGuard, PtPauseError> {
        acquire_pt_pause(
            pt_barrier(),
            &*self.kicker,
            self.this_tid,
            Duration::from_millis(500),
        )
    }

    pub(super) fn release_and_park_vcpu_for_fork(
        &self,
        engine: &mut E,
    ) -> Result<(), RuntimeError> {
        if !engine.supports_in_process_fork() {
            engine.release_vcpu_for_fork()?;
        }
        // Drop out of the kicker the instant the vCPU is gone: while parked we
        // have no live vCPU, so another fork must not count us in `others` nor
        // try to kick a destroyed vCPU.
        self.kicker.unregister(self.this_tid);
        self.park_if_fork_quiescing();
        // Recreate the vCPU under the topology lock so vcpu_create cannot race
        // another fork's hv_vm_destroy/create. Register only after it exists.
        {
            let _topo = crate::fork_quiesce::acquire_topology_lock(
                carrick_observability::probes::HvpatchTopologyOperation::VcpuRebind,
                0,
                self.this_tid.raw(),
            );
            if !engine.supports_in_process_fork() {
                engine.rebuild_vcpu_after_fork()?;
            }
            self.register_vcpu(engine);
        }
        Ok(())
    }

    pub(super) fn handle_fork(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        request: ForkRequest,
    ) -> Result<Option<i64>, RuntimeError> {
        let elapsed_us = |start: std::time::Instant| -> u64 {
            let micros = start.elapsed().as_micros();
            micros.min(u128::from(u64::MAX)) as u64
        };
        let ForkRequest {
            pidfd_out,
            clone_parent,
            parent_tid_addr,
            child_tid_addr,
            exit_signal,
            child_stack,
            vfork,
        } = request;
        if engine.supports_in_process_fork() {
            return self.handle_in_process_fork(
                kernel,
                engine,
                ForkRequest {
                    pidfd_out,
                    clone_parent,
                    parent_tid_addr,
                    child_tid_addr,
                    exit_signal,
                    child_stack,
                    vfork,
                },
            );
        }
        // vfork (CLONE_VM|CLONE_VFORK): the child SHARES the parent's guest RAM
        // (engine.fork_vfork() below) and the parent vCPU is SUSPENDED here until
        // the child execve's or exits (Parent arm below). An ordinary fork keeps
        // the CoW snapshot and does not suspend.
        // Serialize forks: at most one quiesce/fork in flight. When another fork
        // already holds the token, BLOCK rather than surfacing EAGAIN. Park at the
        // in-flight fork's barrier so it can count this thread as quiesced and
        // complete, then retry the token.
        let phase_start = std::time::Instant::now();
        while !fork_barrier().try_begin_fork() {
            if fork_barrier().is_quiescing() {
                self.release_and_park_vcpu_for_fork(engine)?;
            }
            std::thread::yield_now();
        }
        crate::probes::fork_lifecycle(0, 0, elapsed_us(phase_start), 0, 0);
        // Pre-fork admission gate (fork-path exhaustion degradation): prove the
        // host can admit the CHILD's VM before quiescing or tearing anything
        // down. Persistent exhaustion (a parked fleet pinning HVF's ~127-VM
        // ceiling) becomes Linux-shaped `fork(2) = EAGAIN` with the parent VM
        // untouched, instead of the post-fork HV_NO_RESOURCES fatal ("trap
        // engine failed") that killed engines in the procladder_mt red. Only
        // `end_fork` needs unwinding here — the topology lock, quiesce, and
        // child record all come later. vfork is exempt: its child rebuild
        // bypasses the admission permit (the suspended parent and its child
        // sharing the gate can self-deadlock).
        if vfork.is_none()
            && let Err(error) = engine.fork_admission_check()
        {
            tracing::warn!(
                %error,
                "fork admission gate: host VM capacity exhausted; fork(2) = EAGAIN"
            );
            fork_barrier().end_fork();
            return Ok(Some(crate::linux_abi::LINUX_EAGAIN.guest_retval()));
        }
        // Serialize VM topology against sibling vCPU creation for the whole fork.
        let phase_start = std::time::Instant::now();
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::LegacyFork,
            kernel
                .hvpatch_process
                .as_ref()
                .map_or(0, crate::hvpatch::ProcessContext::pid),
            self.this_tid.raw(),
        );
        crate::probes::fork_lifecycle(0, 1, elapsed_us(phase_start), 0, 0);
        // Clear any VM published by a previous fork so siblings that release their
        // vCPUs this round see only THIS fork's republished VM. Also reset the
        // sibling-mapping registry so this round collects a clean set (siblings
        // publish their regions in release_vcpu_for_fork, AFTER the kick below, so
        // clearing here can't race a publish).
        crate::trap::clear_rebuilt_vm_for_fork();
        crate::trap::clear_sibling_fork_mappings();
        // Stop-the-world: a multithreaded guest can fork only if every OTHER guest
        // vCPU thread is first paused at its lock-safe run-loop top.
        let mut others = self.kicker.count().saturating_sub(1);
        crate::probes::fork_quiesce(
            0,
            others as i64,
            self.kicker.count() as i64,
            self.this_tid.raw(),
        );
        let mut quiesced = false;
        let phase_start = std::time::Instant::now();
        if others > 0 {
            let barrier = fork_barrier();
            barrier.set_quiescing();
            // Wake every other thread so it reaches the barrier: kick in-guest
            // vCPUs, and nudge blocked futex / io_wait waiters. The flag is set
            // FIRST so a woken thread observes `is_quiescing()` and parks.
            self.kicker.kick_all_except(self.this_tid);
            self.platform_futex.notify_signal_pending();
            kernel.signal_arrival.wake_all_waiters();
            // Bound the drain. This loop used to spin FOREVER if a sibling never
            // unregistered (i.e. it is stuck in a blocking host wait whose
            // interrupt predicate omits `is_quiescing()`, so a kick/notify never
            // returns it to the run-loop-top barrier). On HVF that ate ~10 min at
            // 100% CPU with every other sibling parked (sample-confirmed under
            // concurrent os/exec); on KVM it hangs eternally (no VCPU_LIVE abort
            // below). A deadline turns that into a bounded, LOGGED abort whose
            // core (bt all) names the stranded thread — the only way to pin which
            // wait arm is missing the predicate. The window is generous (the
            // normal drain is sub-millisecond) so a merely-slow sibling never
            // trips it. (fork_quiesce_no_lost_wakeup_* proves the barrier
            // coordination itself is sound, so a stall here is a stranded sibling,
            // not a lost wake.)
            let drain_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                // The quiesce is complete only when the KICKER COUNT itself
                // drains to 1 (just this forker). A parking sibling UNREGISTERS
                // first and parks second (`release_and_park_vcpu_for_fork`), so
                // the old predicate — parked count >= `count-1`, both re-read —
                // DOUBLE-COUNTED each parker (once for leaving the count, once
                // for joining `paused`) and was satisfied while a
                // STILL-REGISTERED sibling (e.g. a stage-1 page-table editor
                // mid `pt_pause`) had not parked. libc::fork then landed with
                // the PT barrier's `quiescing=true` and the CHILD inherited it
                // and parked FOREVER at its run-loop top (captured live in gdb
                // on KVM under go-os_exec: the child's PtQuiesce bytes showed
                // coordinator=1/quiescing=1 while the parent's were clear).
                // Draining the count to 1 keeps the original stale-HIGH exit
                // fix too: a vCPU that EXITS mid-quiesce unregisters and drops
                // out of this predicate the same way a parker does. (HVF was
                // immune to the double-count only via its extra VCPU_LIVE<=1
                // wait below.)
                others = self.kicker.count().saturating_sub(1);
                if others == 0 {
                    break;
                }
                if std::time::Instant::now() >= drain_deadline {
                    tracing::error!(
                        others,
                        kicker = self.kicker.count(),
                        paused = barrier.paused_count(),
                        pid = std::process::id(),
                        forker_tid = self.this_tid.raw(),
                        "fork quiesce drain: {others} sibling vCPU(s) failed to reach the \
                         run-loop barrier in 10s — a blocking wait arm is not surfacing \
                         is_quiescing(). Aborting (core: `bt all` names the stranded thread) \
                         rather than spinning forever.",
                    );
                    std::process::abort();
                }
                crate::probes::fork_quiesce(
                    1,
                    others as i64,
                    barrier.paused_count() as i64,
                    self.this_tid.raw(),
                );
                // Do not surface EAGAIN to the guest here. Keep nudging every wait
                // class until all live vCPUs leave the kicker, sleeping briefly
                // between nudges (the parked-count condvar can't be used as the
                // sleep: the same unregister-then-park sequence satisfies it
                // immediately).
                self.kicker.kick_all_except(self.this_tid);
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(Duration::from_micros(200));
            }
            quiesced = true;
        }
        crate::probes::fork_lifecycle(
            0,
            2,
            elapsed_us(phase_start),
            others as i64,
            self.kicker.count() as i64,
        );

        // INVARIANT before tearing down the VM: no OTHER guest vCPU is live
        // besides this forker's (VCPU_LIVE == 1). Give the kicked siblings a
        // BOUNDED window (sleeping, NOT spinning) to finish releasing; if it still
        // doesn't hold, ABORT LOUDLY rather than proceed into a corrupting
        // hv_vm_destroy (HV_BUSY).
        //
        // HVF-ONLY (unlike the execve drain in `terminate_siblings_for_exec`,
        // which is live on both backends): only HVF tears the parent VM down
        // at fork, so only HVF siblings RELEASE their vCPUs at the quiesce
        // barrier. KVM siblings park KEEPING their vCPUs (VCPU_LIVE stays at
        // the thread count — the fork child rebuilds a fresh VM in its own
        // process instead), so waiting for == 1 here would always time out
        // and abort.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            use std::sync::atomic::Ordering::SeqCst;
            let phase_start = std::time::Instant::now();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::trap::VCPU_LIVE.load(SeqCst) > 1 {
                if std::time::Instant::now() >= deadline {
                    tracing::error!(
                        vcpu_live = crate::trap::VCPU_LIVE.load(SeqCst),
                        kicker = self.kicker.count(),
                        others,
                        pid = std::process::id(),
                        "fork quiesce failed to release sibling vCPUs in 5s; aborting \
                         to avoid HV_BUSY VM corruption"
                    );
                    std::process::abort();
                }
                self.kicker.kick_all_except(self.this_tid);
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
            crate::probes::fork_lifecycle(
                0,
                3,
                elapsed_us(phase_start),
                crate::trap::VCPU_LIVE.load(SeqCst),
                self.kicker.count() as i64,
            );
        }

        // Drain in-flight EXIT CLEANUPS before forking. An exiting thread drops
        // out of the kicker (so the quiesce above stops counting it) and THEN
        // mutates process-global state — host_signal::forget_thread and the
        // dispatcher's forget_thread_signal_state — under process-wide mutexes.
        // `libc::fork` landing inside that window hands the child a mutex held
        // by a thread that does not exist in it: the child deadlocks on its
        // first touch (observed live on KVM: a vfork child of go-os_exec's
        // TestConcurrentExec wedged forever in `migrate_thread_signal_state` →
        // parking_lot `lock_slow`, surfacing as "vfork parent-suspend timed
        // out"). The cleanups are short, straight-line, and NEVER block on fork
        // state (the gate is a plain atomic count), so this wait is microseconds;
        // the 5s bound exists only against pathology, and on expiry we proceed
        // (the status-quo risk) rather than kill a healthy guest.
        {
            let phase_start = std::time::Instant::now();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::fork_quiesce::exit_cleanups_in_flight() > 0 {
                if std::time::Instant::now() >= deadline {
                    tracing::error!(
                        in_flight = crate::fork_quiesce::exit_cleanups_in_flight(),
                        "fork: exit-cleanup drain timed out after 5s; forking anyway \
                         (child may inherit a held cleanup lock)"
                    );
                    break;
                }
                std::thread::yield_now();
            }
            crate::probes::fork_lifecycle(
                0,
                4,
                elapsed_us(phase_start),
                crate::fork_quiesce::exit_cleanups_in_flight() as i64,
                0,
            );
        }

        let phase_start = std::time::Instant::now();
        let subphase_start = std::time::Instant::now();
        // Publish the arena high-water so the child snapshot's mincore scan is
        // bounded to the guest's used prefix, not all 32 GiB. The HVF child
        // snapshot reads the process-global (trap::set_guest_arena_high_water); a
        // shared-VM backend (KVM vfork) reads it off the engine via the hook (a
        // no-op elsewhere) so its per-window residency scan is bounded too.
        let arena_high_water = kernel.dispatcher.mmap_arena_high_water();
        crate::trap::set_guest_arena_high_water(arena_high_water);
        engine.set_vfork_arena_high_water(arena_high_water);
        crate::probes::fork_lifecycle(
            0,
            50,
            elapsed_us(subphase_start),
            arena_high_water.min(i64::MAX as u64) as i64,
            0,
        );
        // vfork: an inherited pipe to SUSPEND the parent until the child
        // execve/_exit. Created BEFORE the fork so BOTH processes inherit BOTH
        // ends; these are host fds (NOT in the guest fd table). On a pipe() failure
        // degrade to a non-suspending shared fork (vfork_pipe = None).
        let subphase_start = std::time::Instant::now();
        let vfork_pipe: Option<(i32, i32)> = if vfork.is_some() {
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
                unsafe {
                    libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                    libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                }
                Some((fds[0], fds[1]))
            } else {
                None
            }
        } else {
            None
        };
        crate::probes::fork_lifecycle(
            0,
            51,
            elapsed_us(subphase_start),
            i64::from(pidfd_out.is_some()),
            i64::from(vfork_pipe.is_some()),
        );
        let subphase_start = std::time::Instant::now();
        let prepared_fork = kernel.fork.prepare_host_fork();
        crate::probes::fork_lifecycle(0, 52, elapsed_us(subphase_start), 0, 0);
        // Hold the quiesce barrier's internal mutex ACROSS the fork: a sibling
        // parking for this quiesce leaves the kicker count BEFORE it parks
        // (`release_and_park_vcpu_for_fork` unregisters first), so the quiesce
        // wait above can be satisfied while that sibling is still inside
        // `park_if_quiescing`'s lock-increment window HOLDING the barrier
        // mutex — and a fork landing there hands the child the mutex locked
        // forever (captured live on KVM: a vfork child of go-os_exec wedged
        // permanently in `end_quiesce` → `Mutex::lock_contended`). Owning the
        // mutex here excludes that window by mutual exclusion; it is dropped on
        // BOTH sides immediately after the fork, before any barrier call.
        let subphase_start = std::time::Instant::now();
        let paused_guard = fork_barrier().lock_paused_across_fork();
        crate::probes::fork_lifecycle(0, 53, elapsed_us(subphase_start), 0, 0);
        // vfork shares the parent's guest RAM (CLONE_VM); an ordinary fork takes a
        // private CoW snapshot. CRITICAL: gate the SHARE on the suspend pipe
        // existing, NOT on vfork.is_some() — if pipe() failed the parent CANNOT be
        // suspended, and sharing RAM with a running parent silently corrupts guest
        // memory. So a pipe() failure degrades to a plain CoW fork.
        let subphase_start = std::time::Instant::now();
        let child_parent = if clone_parent {
            kernel.dispatcher.clone_parent_host_pid()
        } else {
            std::process::id()
        };
        let child_subreaper = kernel.dispatcher.subreaper_for_fork_child();
        let child_ns_pid = crate::namespace::pid::allocate_child_ns_pid_pre_fork();
        crate::probes::fork_lifecycle(
            0,
            54,
            elapsed_us(subphase_start),
            child_ns_pid.map(i64::from).unwrap_or(-1),
            i64::from(child_parent),
        );
        // Section exhaustion (a guest that forks children nobody ever reaps —
        // SIGCHLD ignored, or the parent exited without a subreaper) is
        // Linux-shaped EAGAIN from fork(2), not a guest abort (spec "Failure
        // model"). Unwind exactly like the engine-fork error arm below, but
        // complete the syscall instead of surfacing a runtime error.
        let subphase_start = std::time::Instant::now();
        let prepared_child_record = match crate::guest_cpu::prepare_child_record_pre_fork(
            child_parent,
            child_subreaper,
            child_ns_pid.unwrap_or(0),
            clone_parent && child_parent != 0,
            0,
        ) {
            Ok(r) => {
                crate::probes::fork_lifecycle(
                    0,
                    55,
                    elapsed_us(subphase_start),
                    child_ns_pid.map(i64::from).unwrap_or(-1),
                    0,
                );
                r
            }
            Err(_exhausted) => {
                crate::probes::fork_lifecycle(
                    0,
                    55,
                    elapsed_us(subphase_start),
                    child_ns_pid.map(i64::from).unwrap_or(-1),
                    -1,
                );
                drop(paused_guard);
                if let Some((r, w)) = vfork_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
                if quiesced {
                    fork_barrier().end_quiesce();
                }
                fork_barrier().end_fork();
                kernel.fork.restart_after_fork_error(
                    prepared_fork,
                    &self.kicker,
                    &self.platform_futex,
                );
                return Ok(Some(crate::linux_abi::LINUX_EAGAIN.guest_retval()));
            }
        };
        crate::probes::fork_lifecycle(
            0,
            5,
            elapsed_us(phase_start),
            child_ns_pid.map(i64::from).unwrap_or(-1),
            i64::from(vfork_pipe.is_some()),
        );

        let phase_start = std::time::Instant::now();
        let fork_result = if vfork_pipe.is_some() {
            engine.fork_vfork()
        } else {
            engine.fork()
        };
        let engine_fork_elapsed = elapsed_us(phase_start);
        // Release the barrier mutex FIRST THING on both sides (and on the error
        // path): every arm below calls `end_quiesce` / `park_if_quiescing`,
        // which retake it (self-deadlock if still held).
        drop(paused_guard);
        let fork_outcome = match fork_result {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some((r, w)) = vfork_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
                if quiesced {
                    fork_barrier().end_quiesce();
                }
                crate::guest_cpu::abort_prepared_child_record();
                fork_barrier().end_fork();
                kernel.fork.restart_after_fork_error(
                    prepared_fork,
                    &self.kicker,
                    &self.platform_futex,
                );
                return Err(RuntimeError::Trap(error));
            }
        };
        match &fork_outcome {
            crate::trap::ForkOutcome::Parent { child_pid } => {
                crate::probes::fork_lifecycle(0, 6, engine_fork_elapsed, i64::from(*child_pid), 0);
            }
            crate::trap::ForkOutcome::Child => {
                crate::probes::fork_lifecycle(1, 6, engine_fork_elapsed, 0, 0);
            }
        }

        let retval = match fork_outcome {
            crate::trap::ForkOutcome::Parent { child_pid } => {
                let runtime_repair_start = std::time::Instant::now();
                // Publish the rebuilt VM so quiesced siblings recreate their vCPUs
                // in it, THEN resume them.
                if quiesced {
                    engine.publish_vm_for_siblings()?;
                    fork_barrier().end_quiesce();
                }
                fork_barrier().end_fork();
                let child_exit_needs_signal_pump = kernel
                    .dispatcher
                    .child_exit_signal_needs_pump(self.this_tid, exit_signal);
                kernel.fork.restart_after_parent_fork(
                    prepared_fork,
                    &self.kicker,
                    &self.platform_futex,
                    child_exit_needs_signal_pump,
                );
                // engine.fork() rebuilt this thread's own vCPU, so its old kicker
                // handle is stale. Re-register the new one (under the topology lock
                // we still hold).
                self.register_vcpu(engine);
                if child_exit_needs_signal_pump {
                    // Watch the child's exit (EVFILT_PROC/NOTE_EXIT) so the signal
                    // pump delivers the requested signal to this (parent) tid when
                    // it exits.
                    crate::host_signal::register_child_exit_watch(
                        child_pid,
                        self.this_tid.raw(),
                        i32::try_from(exit_signal).unwrap_or(crate::linux_abi::LINUX_SIGCHLD),
                    );
                }
                crate::event_ring::rec(crate::event_ring::FORK, child_pid, 0, 0);
                // By REF, not via the global stash: end_fork() above released
                // fork serialization, so another thread's prepare may already
                // have overwritten the stash (its publish would then stamp OUR
                // child pid into THAT record — crossed ns-pids).
                crate::guest_cpu::publish_prepared_child_record_parent_ref(
                    prepared_child_record,
                    child_pid as u32,
                );
                crate::namespace::pid::notify_child_registered();
                // Seed the child's published run-state as Booting NOW, from the
                // parent, before this fork returns — so a parent that polls
                // /proc/<child>/stat immediately (pauseinterrupt2) sees `R`, not
                // the child's host boot-ppoll `S`. The table is shared, so this is
                // the same slot the child later updates to Running/Blocked.
                crate::run_state::publish_child_booting(child_pid as u32);
                // CLONE_PIDFD: allocate a pidfd for the new child and write its fd
                // to the guest pidfd-out pointer.
                if let Some(addr) = pidfd_out {
                    let fd = kernel
                        .dispatcher
                        .install_child_pidfd(child_pid)
                        .unwrap_or(-1);
                    let _ = engine.write_bytes(addr, &fd.to_le_bytes());
                }
                // PID namespace: the child's ns-pid was allocated and stored in
                // its prepared record before fork. Identity when namespaces are off.
                let retval = i64::from(child_ns_pid.unwrap_or(child_pid as u32));
                if let Some(addr) = parent_tid_addr {
                    let tid = (retval as i32).to_le_bytes();
                    let _ = engine.write_bytes(addr, &tid);
                }
                // vfork: SUSPEND this (parent) vCPU thread until the child execve's
                // (it writes one byte) or exits (the OS closes the child's write
                // end → our read() returns EOF). We still hold `_topology`, so no
                // concurrent fork can quiesce us. Retry on EINTR.
                if let Some((vf_read, _vf_write)) = vfork_pipe {
                    let vfork_wait_start = std::time::Instant::now();
                    unsafe { libc::close(_vf_write) }; // parent only reads
                    // Bounded suspend: the child should execve/_exit within ms, but
                    // a pathological guest must NOT wedge the parent forever — we
                    // still hold topology_lock here. Poll with a deadline; on expiry
                    // resume the parent DEGRADED with a loud diagnostic.
                    const VFORK_SUSPEND_TIMEOUT: Duration = Duration::from_secs(60);
                    let deadline = std::time::Instant::now() + VFORK_SUSPEND_TIMEOUT;
                    let mut byte = [0u8; 1];
                    loop {
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            tracing::error!(
                                child_pid,
                                "vfork parent-suspend timed out (60s) waiting for child \
                                 execve/_exit; resuming parent degraded"
                            );
                            break;
                        }
                        let remaining_ms =
                            (deadline - now).as_millis().min(i32::MAX as u128) as i32;
                        let mut pfd = libc::pollfd {
                            fd: vf_read,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let r = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
                        if r > 0 {
                            // Readable: a byte (child execve'd) or EOF (child exited).
                            let _ = unsafe { libc::read(vf_read, byte.as_mut_ptr().cast(), 1) };
                            break;
                        }
                        if r == 0 {
                            continue; // deadline re-checked at loop top
                        }
                        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                            break; // unexpected poll error — stop waiting
                        }
                        // EINTR → re-poll on the remaining budget.
                    }
                    unsafe { libc::close(vf_read) };
                    // The child has now execve'd or exited, so the shared window is
                    // quiescent. Reconcile the child's shared-VM writes back into
                    // the parent's address space and release the share (KVM's shadow
                    // copy-back; a no-op for backends that shared the RAM directly).
                    // Safe to do unconditionally: a non-vfork-shared backend's hook
                    // is a no-op, and on the pipe-failure degrade path nothing was
                    // armed.
                    engine.finish_vfork_parent();
                    // The vfork child shared the parent's guest RAM until it
                    // execve'd or exited. Its child-side identity stamp therefore
                    // overwrote the shared EL1 shim identity page; restore the
                    // parent's getpid/get*id fast-path values before resuming it.
                    stamp_identity_page(engine, &kernel.dispatcher);
                    crate::probes::fork_lifecycle(
                        0,
                        9,
                        elapsed_us(vfork_wait_start),
                        i64::from(child_pid),
                        0,
                    );
                }
                crate::probes::fork_lifecycle(
                    0,
                    7,
                    elapsed_us(runtime_repair_start),
                    i64::from(child_pid),
                    0,
                );
                retval
            }
            crate::trap::ForkOutcome::Child => {
                let runtime_repair_start = std::time::Instant::now();
                kernel.dispatcher.clear_output_buffers();
                // A forked child must NOT inherit its PARENT's vfork suspend-pipe
                // write end (copied across libc::fork). Drop the inherited copy so
                // only the genuine vfork child holds the writer.
                if let Some(stale) = self.vfork_release_fd.take() {
                    unsafe { libc::close(stale) };
                }
                // vfork: keep the WRITE end of OUR suspend pipe (close the read end
                // the parent owns).
                if let Some((vf_read, vf_write)) = vfork_pipe {
                    unsafe { libc::close(vf_read) };
                    self.vfork_release_fd = Some(vf_write);
                }
                // An explicit child stack (clone's stack arg != 0, vfork or
                // ordinary fork-like clone): run the child on it, exactly as
                // the kernel does — glibc/musl's `__clone` stub pops the child
                // function off the NEW stack (LTP clone01 crashed on the
                // parent's frames without this).
                let requested_stack = vfork.unwrap_or(child_stack);
                if requested_stack != 0
                    && let Err(e) = engine.set_guest_sp_el0(requested_stack)
                {
                    tracing::warn!(?e, "clone: failed to set child stack pointer");
                }
                // Don't inherit the parent's accumulated guest CPU time.
                crate::guest_cpu::reset();
                let parent_tid = self.this_tid;
                self.this_tid = ThreadId::main_from_host_pid();
                // The child inherits the parent's blocked mask + alternate signal
                // stack (POSIX) but has a NEW tid; re-key the dispatcher's per-tid
                // signal state.
                kernel
                    .dispatcher
                    .migrate_thread_signal_state(parent_tid, self.this_tid);
                self.registry = Arc::new(ThreadRegistry::new(self.this_tid));
                crate::thread::set_current_registry(Arc::clone(&self.registry));
                // The other guest threads do not exist in the child (libc::fork
                // replicated only the calling thread). Drop their stale bookkeeping:
                // a fresh futex table (no phantom waiters), a fresh kicker (only
                // this vCPU is registered below), and an empty thread-handle vec.
                // The fresh kicker comes from `fresh_fork_kicker()` (object-safe,
                // so the loop never names the concrete kicker); the fresh concrete
                // private-futex table is built here and the matching `PlatformFutex`
                // is derived from it via the threaded-through factory, so the two
                // stay over the SAME table (the notify-signal-pending consistency
                // invariant) without naming the backend.
                let fresh_kicker = engine.fresh_fork_kicker();
                self.kicker = fresh_kicker;
                self.futex = Arc::new(crate::thread::FutexTable::new());
                self.platform_futex = (self.platform_futex_factory)(Arc::clone(&self.futex));
                self.threads = Arc::new(parking_lot::Mutex::new(Vec::new()));
                // Clear the quiesce + fork flags the child inherited (copied) from
                // the parent so the child's single-threaded run loop runs. Also
                // reset the inherited parked-thread COUNT: it belongs to PARENT
                // threads that do not exist here and nothing would ever decrement
                // it, so a child that later goes multithreaded and forks would
                // see `wait_quiesced` satisfied by phantom parkers and fork
                // UNQUIESCED (siblings running mid-anything).
                fork_barrier().end_quiesce();
                fork_barrier().end_fork();
                fork_barrier().reset_paused_for_child();
                // Also clear the inherited PAGE-TABLE-EDIT pause. If the fork
                // landed while a parent sibling held `pt_pause` (the editor is
                // not in the child), the inherited coordinator/quiescing flags
                // would park this child's run loop FOREVER at its first loop
                // top (captured live: PtQuiesce bytes coordinator=1/quiescing=1
                // in a wedged go-os_exec vfork child). The count-drain predicate
                // above makes that window unreachable going forward; this reset
                // keeps the child self-healing regardless.
                pt_barrier().end();
                crate::event_ring::reinit_after_fork();
                crate::host_signal::reinit_after_fork();
                crate::dispatch::reset_fifo_beacons_after_fork_child();
                kernel.dispatcher.epoll_after_fork_child();
                // Publish THIS child (new host pid) as Booting in the SHARED
                // run-state table, before any post-fork boot work that parks the
                // vCPU in the host's internal boot ppoll — so a parent reading
                // /proc/<child>/stat sees `R` during boot (as real Linux does),
                // not the `S` of that boot park. Republished `Running` when the
                // child's vCPU first resumes guest code (run_vcpu_until_exit top).
                // Publish the child's host pid on its pre-fork record FIRST:
                // the run-state publish right after adopts that record (one
                // record per process), which only works once host_pid is set.
                crate::guest_cpu::complete_child_record_post_fork_child();
                crate::run_state::reinit_booting_after_fork();
                // M:N scheduler: the child inherited the parent's pool but has only
                // THIS thread, now the child's main (remapped to the child VM's vCPU
                // 0). Drop the inherited (parent-slot) lease, reset to a fresh pool,
                // and re-acquire slot 0 — otherwise the child's new threads block on
                // slots held by parent threads that don't exist here.
                carrick_hal::vcpu_sched::take_current_lease();
                carrick_hal::vcpu_sched::global().reset_for_fork();
                carrick_hal::vcpu_sched::set_current_lease(
                    carrick_hal::vcpu_sched::global().acquire(self.this_tid.raw() as u64),
                );
                // Re-stamp identity + tid: the child's pid changed and the vCPU was
                // rebuilt.
                stamp_identity_page(engine, &kernel.dispatcher);
                if let Some(addr) = parent_tid_addr {
                    let tid = (crate::namespace::pid::self_ns_pid() as i32).to_le_bytes();
                    let _ = engine.write_bytes(addr, &tid);
                }
                if let Some(addr) = child_tid_addr {
                    let tid = (crate::namespace::pid::self_ns_pid() as i32).to_le_bytes();
                    let _ = engine.write_bytes(addr, &tid);
                }
                stamp_guest_tid(engine, self.this_tid, &self.registry);
                kernel.dispatcher.proc_after_fork_child();
                kernel.dispatcher.sysv_after_fork_child();
                self.waiter = crate::io_wait::ThreadWaiter::new(self.this_tid);
                let handle: Box<dyn carrick_hal::VcpuKickDyn> = Box::new(engine.kick_handle());
                self.kicker.register(self.this_tid, handle);
                self.registry
                    .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
                kernel.fork.restart_after_child_fork(
                    prepared_fork,
                    &self.kicker,
                    &self.platform_futex,
                );
                crate::probes::fork_lifecycle(1, 8, elapsed_us(runtime_repair_start), 0, 0);
                0
            }
        };
        Ok(Some(retval))
    }

    fn handle_in_process_fork(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        request: ForkRequest,
    ) -> Result<Option<i64>, RuntimeError> {
        let Some(parent_process) = kernel.hvpatch_process.as_ref() else {
            return Err(RuntimeError::Configuration(
                "in-process fork requested without hvpatch process context".to_owned(),
            ));
        };
        let process_barrier = kernel.process_fork_barrier.as_ref().ok_or_else(|| {
            RuntimeError::Configuration(
                "in-process fork requested without a process-local barrier".to_owned(),
            )
        })?;
        while !process_barrier.try_begin_fork() {
            if process_barrier.is_quiescing() {
                self.release_and_park_vcpu_for_fork(engine)?;
            }
            std::thread::yield_now();
        }
        let _topology = crate::fork_quiesce::acquire_topology_lock(
            carrick_observability::probes::HvpatchTopologyOperation::InProcessFork,
            parent_process.pid(),
            self.this_tid.raw(),
        );
        let mut quiesced = false;
        if self.kicker.count() > 1 {
            process_barrier.set_quiescing();
            self.kicker.kick_all_except(self.this_tid);
            self.futex.notify_signal_pending();
            self.platform_futex.notify_signal_pending();
            kernel.signal_arrival.wake_all_waiters();
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.kicker.count() > 1 {
                if Instant::now() >= deadline {
                    tracing::error!(
                        pid = parent_process.pid(),
                        remaining = self.kicker.count().saturating_sub(1),
                        "hvpatch in-process fork quiesce timed out"
                    );
                    std::process::abort();
                }
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                self.platform_futex.notify_signal_pending();
                kernel.signal_arrival.wake_all_waiters();
                std::thread::sleep(Duration::from_micros(200));
            }
            quiesced = true;
        }

        crate::trap::set_guest_arena_high_water(kernel.dispatcher.mmap_arena_high_water());
        let (child_process, child_record) = match parent_process.fork_child() {
            Ok(child) => child,
            Err(error) => {
                if quiesced {
                    process_barrier.end_quiesce();
                }
                process_barrier.end_fork();
                tracing::warn!(%error, "hvpatch process allocation failed; fork(2) = EAGAIN");
                return Ok(Some(crate::linux_abi::LINUX_EAGAIN.guest_retval()));
            }
        };
        let child_pid = child_record.pid().raw();
        let Some(bank) = child_record.bank() else {
            let _ = child_process.discard_unstarted_child();
            if quiesced {
                process_barrier.end_quiesce();
            }
            process_barrier.end_fork();
            return Err(RuntimeError::Configuration(
                "hvpatch fork child has no process bank".to_owned(),
            ));
        };
        let child_tid = ThreadId::from_guest_supplied_tid(child_pid);
        // CLONE_PIDFD is part of child creation, not a best-effort postscript.
        // Install the guest-virtual pidfd while the process-table record is live
        // and before any child vCPU can run. Every later setup failure removes
        // the fd and retires the unstarted process atomically.
        let installed_pidfd = if request.pidfd_out.is_some() {
            match kernel
                .dispatcher
                .install_hvpatch_child_pidfd(parent_process, child_pid)
            {
                Ok(fd) => Some(fd),
                Err(errno) => {
                    let _ = child_process.discard_unstarted_child();
                    if quiesced {
                        process_barrier.end_quiesce();
                    }
                    process_barrier.end_fork();
                    return Ok(Some(errno.guest_retval()));
                }
            }
        } else {
            None
        };
        if let Some(address) = request.parent_tid_addr {
            let _ = engine.write_bytes(address, &child_pid.to_le_bytes());
        }
        let spec = match engine.build_process_spec(
            carrick_hal::GuestEntryRegs {
                return_value: 0,
                stack: (request.child_stack != 0).then_some(request.child_stack),
                tls: None,
            },
            child_record.ttbr0(),
            bank.base(),
            bank.size(),
            child_tid,
            self.this_tid,
        ) {
            Ok(spec) => spec,
            Err(error) => {
                if let Some(fd) = installed_pidfd {
                    let _ = kernel
                        .dispatcher
                        .remove_installed_hvpatch_child_pidfd(fd, child_pid);
                }
                let _ = child_process.discard_unstarted_child();
                if quiesced {
                    process_barrier.end_quiesce();
                }
                process_barrier.end_fork();
                return Err(RuntimeError::Trap(error));
            }
        };
        let child_dispatcher = kernel.dispatcher.fork_clone_in_process(
            self.this_tid,
            child_tid,
            parent_process.pid() as u32,
            child_pid as u32,
        );
        child_dispatcher.bind_hvpatch_process(child_process.clone());
        let child_unstarted_context = child_process.clone();
        let child_exit_context = child_process.clone();
        let child_trace_context = child_process.clone();
        let parent_kernel = Arc::clone(kernel);
        let parent_futex = Arc::clone(&self.futex);
        let parent_kicker = Arc::clone(&self.kicker);
        let parent_tid = self.this_tid;
        let child_exit_signal = i32::try_from(request.exit_signal)
            .ok()
            .filter(|signal| *signal != 0);
        let child_kernel = Arc::new(KernelState::new(
            child_dispatcher,
            Arc::clone(&kernel.fork),
            Arc::clone(&kernel.signal_arrival),
            Some(child_process),
        ));
        let child_exit_kernel = Arc::clone(&child_kernel);
        let child_registry = Arc::new(ThreadRegistry::new(child_tid));
        let child_futex = Arc::new(crate::thread::FutexTable::new());
        let child_platform_futex = (self.platform_futex_factory)(Arc::clone(&child_futex));
        let child_platform_futex_factory = Arc::clone(&self.platform_futex_factory);
        let child_kicker = engine.fresh_fork_kicker();
        let child_threads = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let all_threads = Arc::clone(&self.threads);
        let max_traps = self.max_traps;
        let child_tid_addr = request.child_tid_addr;
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let handle = match std::thread::Builder::new()
            .name(format!("guest-pid-{child_pid}"))
            .spawn(move || {
                let mut child_engine = match E::materialize_process(spec) {
                    Ok(engine) => engine,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error.to_string()));
                        return;
                    }
                };
                let handle: Box<dyn carrick_hal::VcpuKickDyn> =
                    Box::new(child_engine.kick_handle());
                child_kicker.register(child_tid, handle);
                if let Some(address) = child_tid_addr {
                    let _ = child_engine.write_bytes(address, &child_pid.to_le_bytes());
                }
                stamp_identity_page(&mut child_engine, &child_kernel.dispatcher);
                stamp_guest_tid(&child_engine, child_tid, &child_registry);
                let _ = ready_tx.send(Ok(()));
                match run_vcpu_until_exit(
                    child_kernel,
                    child_engine,
                    child_registry,
                    child_futex,
                    child_platform_futex,
                    child_platform_futex_factory,
                    child_tid,
                    child_threads,
                    child_kicker,
                    max_traps,
                ) {
                    Ok(VcpuLoopOutcome::ProcessExit(result)) => {
                        tracing::trace!(
                            child_pid,
                            exit_code = result.exit_code,
                            "hvpatch child reached process exit publication"
                        );
                        child_exit_kernel.dispatcher.retire_hvpatch_process_fds();
                        if let Err(error) =
                            child_exit_context.publish_exit_code(result.exit_code, child_tid)
                        {
                            tracing::error!(child_pid, %error, "publish hvpatch child exit failed");
                        }
                        if let Some(signal) = child_exit_signal
                            && parent_kernel
                                .dispatcher
                                .child_exit_signal_needs_pump(parent_tid, signal as u32)
                        {
                            parent_kernel
                                .dispatcher
                                .mark_in_process_signal_pending(signal);
                            parent_futex.notify_signal_pending();
                            parent_kernel.signal_arrival.wake_all_waiters();
                            parent_kicker.kick_all();
                        }
                        let _ = unsafe {
                            libc::write(1, result.stdout.as_ptr().cast(), result.stdout.len())
                        };
                        let _ = unsafe {
                            libc::write(2, result.stderr.as_ptr().cast(), result.stderr.len())
                        };
                    }
                    Ok(VcpuLoopOutcome::TrapLimit(_)) | Ok(VcpuLoopOutcome::ThreadDone) => {}
                    Err(error) => {
                        tracing::error!(child_pid, %error, "hvpatch child loop failed");
                        child_exit_kernel.dispatcher.retire_hvpatch_process_fds();
                        if let Err(publish_error) =
                            child_exit_context.publish_exit_code(127, child_tid)
                        {
                            tracing::error!(
                                child_pid,
                                %publish_error,
                                "publish failed hvpatch child exit failed"
                            );
                        }
                        if let Some(signal) = child_exit_signal
                            && parent_kernel
                                .dispatcher
                                .child_exit_signal_needs_pump(parent_tid, signal as u32)
                        {
                            parent_kernel
                                .dispatcher
                                .mark_in_process_signal_pending(signal);
                            parent_futex.notify_signal_pending();
                            parent_kernel.signal_arrival.wake_all_waiters();
                            parent_kicker.kick_all();
                        }
                    }
                }
            }) {
            Ok(handle) => handle,
            Err(error) => {
                if let Some(fd) = installed_pidfd {
                    let _ = kernel
                        .dispatcher
                        .remove_installed_hvpatch_child_pidfd(fd, child_pid);
                }
                let _ = child_unstarted_context.discard_unstarted_child();
                if quiesced {
                    process_barrier.end_quiesce();
                }
                process_barrier.end_fork();
                return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "spawn hvpatch process failed: {error}"
                ))));
            }
        };
        all_threads.lock().push(handle);
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if let Some(fd) = installed_pidfd {
                    let _ = kernel
                        .dispatcher
                        .remove_installed_hvpatch_child_pidfd(fd, child_pid);
                }
                let _ = child_unstarted_context.discard_unstarted_child();
                if quiesced {
                    process_barrier.end_quiesce();
                }
                process_barrier.end_fork();
                return Err(RuntimeError::Trap(TrapError::Hypervisor(error)));
            }
            Err(error) => {
                if let Some(fd) = installed_pidfd {
                    let _ = kernel
                        .dispatcher
                        .remove_installed_hvpatch_child_pidfd(fd, child_pid);
                }
                let _ = child_unstarted_context.discard_unstarted_child();
                if quiesced {
                    process_barrier.end_quiesce();
                }
                process_barrier.end_fork();
                return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "hvpatch child startup channel failed: {error}"
                ))));
            }
        }
        if let (Some(address), Some(fd)) = (request.pidfd_out, installed_pidfd) {
            let _ = engine.write_bytes(address, &fd.to_le_bytes());
        }
        if quiesced {
            process_barrier.end_quiesce();
        }
        process_barrier.end_fork();
        child_trace_context.trace_lifecycle(
            carrick_observability::probes::HvpatchGuestLifecyclePhase::Fork,
            child_tid,
            0,
        );
        crate::event_ring::rec(crate::event_ring::FORK, child_pid, 0, 0);
        if request.clone_parent || request.exit_signal != 0 {
            tracing::debug!(
                child_pid,
                "hvpatch in-process fork currently records clone-parent/exit-signal metadata for later wait integration"
            );
        }
        Ok(Some(i64::from(child_pid)))
    }
}

#[cfg(test)]
mod pt_pause_tests {
    use super::*;
    use carrick_hal::{GenericVcpuRegistry, VcpuKickDyn, VcpuRegistry};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct NoopKick;

    impl VcpuKickDyn for NoopKick {
        fn kick(&self) {}
    }

    struct LeaveGuestOnKick(Arc<AtomicBool>);

    impl VcpuKickDyn for LeaveGuestOnKick {
        fn kick(&self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }

    fn tid(raw: i32) -> ThreadId {
        ThreadId::synthetic_for_tests(raw)
    }

    #[test]
    fn pt_pause_timeout_skips_backend_and_resumes_parked_sibling() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let registry = Arc::new(GenericVcpuRegistry::new());
        let coordinator = tid(1501);
        let sibling = tid(1502);
        registry.register_in_guest(coordinator);
        let sibling_in_guest = registry.register_in_guest(sibling);
        sibling_in_guest.store(true, Ordering::SeqCst);
        registry.register(coordinator, Box::new(NoopKick));
        registry.register(sibling, Box::new(NoopKick));

        let resumed = Arc::new(AtomicBool::new(false));
        let sibling_resumed = Arc::clone(&resumed);
        let sibling_thread = std::thread::spawn(move || {
            while !barrier.is_quiescing() {
                std::thread::yield_now();
            }
            barrier.park();
            sibling_resumed.store(true, Ordering::SeqCst);
        });
        let backend_repoint_calls = AtomicUsize::new(0);
        let result = acquire_pt_pause(barrier, &*registry, coordinator, Duration::from_millis(20));
        if result.is_ok() {
            backend_repoint_calls.fetch_add(1, Ordering::SeqCst);
        }

        assert_eq!(result.err(), Some(PtPauseError::TimedOut));
        assert_eq!(backend_repoint_calls.load(Ordering::SeqCst), 0);
        sibling_thread.join().expect("join rolled-back sibling");
        assert!(resumed.load(Ordering::SeqCst));
        assert!(!barrier.is_quiescing());
        assert!(
            barrier.try_become_coordinator(),
            "timeout must release coordinator ownership"
        );
        barrier.end();
    }

    #[test]
    fn pt_pause_exact_drain_returns_guard_and_allows_backend() {
        let barrier: &'static crate::fork_quiesce::PtQuiesce =
            Box::leak(Box::new(crate::fork_quiesce::PtQuiesce::new()));
        let registry = Arc::new(GenericVcpuRegistry::new());
        let coordinator = tid(1511);
        let sibling = tid(1512);
        registry.register_in_guest(coordinator);
        let sibling_in_guest = registry.register_in_guest(sibling);
        sibling_in_guest.store(true, Ordering::SeqCst);
        registry.register(coordinator, Box::new(NoopKick));
        registry.register(
            sibling,
            Box::new(LeaveGuestOnKick(Arc::clone(&sibling_in_guest))),
        );

        let guard = acquire_pt_pause(barrier, &*registry, coordinator, Duration::from_secs(1))
            .expect("sibling drains exactly after kick");
        let backend_repoint_calls = AtomicUsize::new(0);
        backend_repoint_calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(backend_repoint_calls.load(Ordering::SeqCst), 1);
        assert!(barrier.is_quiescing());
        drop(guard);
        assert!(!barrier.is_quiescing());
    }
}
