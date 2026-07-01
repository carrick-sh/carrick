//! MEM concern: fork / page-table quiesce of the vCPU run loop.
//!
//! Split out of `vcpu_loop/mod.rs` (Task A2). Pure relocation — no logic
//! changes; only `mod`/`use`/visibility wiring differs.

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

impl<E: ThreadedEngine + 'static> ThreadRuntimeState<E>
where
    E::SiblingSpec: 'static,
{
    /// Pause sibling vCPUs for a stage-1 page-table edit (mmap/mprotect/munmap),
    /// returning an RAII guard that resumes them on drop.
    pub(super) fn pt_pause(&self) -> crate::fork_quiesce::PtPauseGuard {
        let b = pt_barrier();
        // Serialize editors: at most one stop-the-world at a time. A loser parks
        // (if the winner has raised quiescing) or yields (tiny pre-flag window),
        // then retries.
        loop {
            if b.try_become_coordinator() {
                break;
            }
            if b.is_quiescing() {
                b.park();
            } else {
                std::thread::yield_now();
            }
        }
        b.set_quiescing();
        let tid = self.this_tid;
        crate::probes::pt_pause_begin(
            tid,
            i32::from(self.kicker.any_other_in_guest(self.this_tid)),
            self.kicker.count() as i32,
        );
        // Force in-guest siblings out so they reach the run-loop-top park, then
        // wait until none is walking the tables. Re-kick each spin in case a
        // vCPU was between runs when the first kick landed.
        let start = std::time::Instant::now();
        let deadline = start + std::time::Duration::from_millis(500);
        let mut spins: i32 = 0;
        while self.kicker.any_other_in_guest(self.this_tid) {
            self.kicker.kick_all_except(self.this_tid);
            if std::time::Instant::now() >= deadline {
                crate::probes::pt_pause_timeout(tid, start.elapsed().as_micros() as i64);
                break;
            }
            spins = spins.saturating_add(1);
            std::thread::yield_now();
        }
        crate::probes::pt_pause_ready(tid, spins, start.elapsed().as_micros() as i64);
        b.pause_guard(tid)
    }

    pub(super) fn release_and_park_vcpu_for_fork(
        &self,
        engine: &mut E,
    ) -> Result<(), RuntimeError> {
        engine.release_vcpu_for_fork()?;
        // Drop out of the kicker the instant the vCPU is gone: while parked we
        // have no live vCPU, so another fork must not count us in `others` nor
        // try to kick a destroyed vCPU.
        self.kicker.unregister(self.this_tid);
        fork_barrier().park_if_quiescing();
        // Recreate the vCPU under the topology lock so vcpu_create cannot race
        // another fork's hv_vm_destroy/create. Register only after it exists.
        {
            let _topo = crate::fork_quiesce::topology_lock()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            engine.rebuild_vcpu_after_fork()?;
            self.register_vcpu(engine);
        }
        Ok(())
    }

    pub(super) fn handle_fork(
        &mut self,
        kernel: &Kernel,
        engine: &mut E,
        pidfd_out: Option<u64>,
        exit_signal: u32,
        child_stack: u64,
        vfork: Option<u64>,
    ) -> Result<Option<i64>, RuntimeError> {
        // vfork (CLONE_VM|CLONE_VFORK): the child SHARES the parent's guest RAM
        // (engine.fork_vfork() below) and the parent vCPU is SUSPENDED here until
        // the child execve's or exits (Parent arm below). An ordinary fork keeps
        // the CoW snapshot and does not suspend.
        // Serialize forks: at most one quiesce/fork in flight. When another fork
        // already holds the token, BLOCK rather than surfacing EAGAIN. Park at the
        // in-flight fork's barrier so it can count this thread as quiesced and
        // complete, then retry the token.
        while !fork_barrier().try_begin_fork() {
            if fork_barrier().is_quiescing() {
                self.release_and_park_vcpu_for_fork(engine)?;
            }
            std::thread::yield_now();
        }
        // Serialize VM topology against sibling vCPU creation for the whole fork.
        let _topology = crate::fork_quiesce::topology_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        crate::probes::fork_quiesce(0, others as i64, self.kicker.count() as i64, self.this_tid);
        let mut quiesced = false;
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
                        forker_tid = self.this_tid,
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
                    self.this_tid,
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
        }

        // Publish the arena high-water so the child snapshot's mincore scan is
        // bounded to the guest's used prefix, not all 32 GiB. The HVF child
        // snapshot reads the process-global (trap::set_guest_arena_high_water); a
        // shared-VM backend (KVM vfork) reads it off the engine via the hook (a
        // no-op elsewhere) so its per-window residency scan is bounded too.
        let arena_high_water = kernel.dispatcher.mmap_arena_high_water();
        crate::trap::set_guest_arena_high_water(arena_high_water);
        engine.set_vfork_arena_high_water(arena_high_water);
        // vfork: an inherited pipe to SUSPEND the parent until the child
        // execve/_exit. Created BEFORE the fork so BOTH processes inherit BOTH
        // ends; these are host fds (NOT in the guest fd table). On a pipe() failure
        // degrade to a non-suspending shared fork (vfork_pipe = None).
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
        let prepared_fork = kernel.fork.prepare_host_fork();
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
        let paused_guard = fork_barrier().lock_paused_across_fork();
        // vfork shares the parent's guest RAM (CLONE_VM); an ordinary fork takes a
        // private CoW snapshot. CRITICAL: gate the SHARE on the suspend pipe
        // existing, NOT on vfork.is_some() — if pipe() failed the parent CANNOT be
        // suspended, and sharing RAM with a running parent silently corrupts guest
        // memory. So a pipe() failure degrades to a plain CoW fork.
        let fork_result = if vfork_pipe.is_some() {
            engine.fork_vfork()
        } else {
            engine.fork()
        };
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
                fork_barrier().end_fork();
                kernel.fork.restart_after_fork_error(
                    prepared_fork,
                    &self.kicker,
                    &self.platform_futex,
                );
                return Err(RuntimeError::Trap(error));
            }
        };

        let retval = match fork_outcome {
            crate::trap::ForkOutcome::Parent { child_pid } => {
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
                        self.this_tid,
                        i32::try_from(exit_signal).unwrap_or(crate::linux_abi::LINUX_SIGCHLD),
                    );
                }
                crate::event_ring::rec(crate::event_ring::FORK, child_pid, 0, 0);
                crate::guest_cpu::register_child(child_pid as u32);
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
                // PID namespace: allocate the child's ns-pid + record the mapping,
                // and return the ns-pid as the fork retval. Identity when off.
                let retval = i64::from(crate::namespace::pid::register_child(
                    child_pid as u32,
                    std::process::id(),
                ));
                // vfork: SUSPEND this (parent) vCPU thread until the child execve's
                // (it writes one byte) or exits (the OS closes the child's write
                // end → our read() returns EOF). We still hold `_topology`, so no
                // concurrent fork can quiesce us. Retry on EINTR.
                if let Some((vf_read, _vf_write)) = vfork_pipe {
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
                }
                retval
            }
            crate::trap::ForkOutcome::Child => {
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
                self.this_tid = std::process::id() as ThreadId;
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
                // Publish THIS child (new host pid) as Booting in the SHARED
                // run-state table, before any post-fork boot work that parks the
                // vCPU in the host's internal boot ppoll — so a parent reading
                // /proc/<child>/stat sees `R` during boot (as real Linux does),
                // not the `S` of that boot park. Republished `Running` when the
                // child's vCPU first resumes guest code (run_vcpu_until_exit top).
                crate::run_state::reinit_booting_after_fork();
                // M:N scheduler: the child inherited the parent's pool but has only
                // THIS thread, now the child's main (remapped to the child VM's vCPU
                // 0). Drop the inherited (parent-slot) lease, reset to a fresh pool,
                // and re-acquire slot 0 — otherwise the child's new threads block on
                // slots held by parent threads that don't exist here.
                carrick_hal::vcpu_sched::take_current_lease();
                carrick_hal::vcpu_sched::global().reset_for_fork();
                carrick_hal::vcpu_sched::set_current_lease(
                    carrick_hal::vcpu_sched::global().acquire(self.this_tid as u64),
                );
                // PID namespace: block until the parent registered our ns-pid
                // before any guest code runs. No-op when ns off.
                crate::namespace::pid::await_self_registration();
                // Re-stamp identity + tid: the child's pid changed and the vCPU was
                // rebuilt.
                stamp_identity_page(engine, &kernel.dispatcher);
                stamp_guest_tid(engine, self.this_tid, &self.registry);
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
                0
            }
        };
        Ok(Some(retval))
    }
}
