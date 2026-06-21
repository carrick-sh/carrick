//! Cross-thread vCPU "kick": force a guest thread out of `hv_vcpu_run` so the
//! trap loop can deliver a pending signal promptly, even when the target is
//! spinning in guest userspace (not parked in a host syscall, where the
//! [`crate::io_wait`] self-pipe would wake it).
//!
//! This is the macOS-native realisation of the "interrupt a running vCPU"
//! primitive — Apple's `hv_vcpus_exit(ids, count)` forces the named vCPUs to
//! return from `hv_vcpu_run` with `ExitReason::CANCELED`. It ONLY affects a
//! vCPU that is currently executing the guest; a vCPU sitting in a host syscall
//! (e.g. `kevent`) is unaffected, which is exactly why blocking I/O waits watch
//! the self-pipe instead. The two mechanisms compose: the pipe covers parked
//! threads, the kick covers in-guest threads.
//!
//! Each guest thread publishes a [`VcpuKickHandle`] (a `Send`/`Sync` weak
//! reference to its vCPU) into the shared [`VcpuKicker`] when it starts running
//! and removes it on exit. A signalling thread (running a `tgkill` syscall, or
//! the process-directed signal pump) looks the target up and kicks it.

// The registry bookkeeping (the two maps + SeqCst handshake) now lives in
// carrick_hal::GenericVcpuRegistry (aliased as `VcpuKicker` below); only the
// VcpuKickHandle kick mechanism stays here, so the HashMap/Mutex/ThreadId the
// old struct used are no longer needed.

// ---------------------------------------------------------------------------
// carrick-hal trait impls: VcpuKick + VcpuRegistry
// ---------------------------------------------------------------------------
// These are forwarding impls only.  No behaviour is changed: every method
// delegates to the existing VcpuKickHandle / VcpuKicker methods verbatim.
// The AtomicBool orderings are preserved exactly (SeqCst throughout).
// ---------------------------------------------------------------------------

impl carrick_hal::VcpuKick for VcpuKickHandle {
    #[inline]
    fn kick(&self) {
        // Delegate to the existing kick path: build a one-element id slice and
        // call kick_ids, which calls hv_vcpus_exit.  On non-HVF targets
        // valid_id always returns None, so kick_ids is a no-op — same as
        // today.
        let ids: Vec<u64> = std::iter::once(self).filter_map(valid_id).collect();
        kick_ids(&ids);
    }
}

/// A `Send`/`Sync` handle to a guest thread's vCPU, usable from any thread to
/// kick it. Wraps `applevisor::vcpu::VcpuHandle` (which holds a `Weak` to the vCPU's
/// liveness guard, so a kick after the vCPU is destroyed is a safe no-op) on
/// macOS; an inert placeholder elsewhere.
#[derive(Clone)]
pub struct VcpuKickHandle {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    inner: applevisor::vcpu::VcpuHandle,
}

impl VcpuKickHandle {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn new(inner: applevisor::vcpu::VcpuHandle) -> Self {
        Self { inner }
    }

    /// Placeholder constructor for platforms without HVF; the threaded vCPU
    /// path never actually runs there.
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn placeholder() -> Self {
        Self {}
    }
}

/// The HVF vCPU-kick registry. The bookkeeping (the two maps + the SeqCst Dekker
/// handshake) is the platform-neutral [`carrick_hal::GenericVcpuRegistry`],
/// shared with KVM/bhyve; the only HVF-specific piece is [`VcpuKickHandle`] (the
/// `hv_vcpus_exit` kick mechanism). The old bulk-kick fast path (collecting
/// `raw_vcpu_id`s for ONE `hv_vcpus_exit(ids)`) is dropped: a per-handle kick is
/// behavior-equivalent (each `VcpuKickHandle::kick` issues `hv_vcpus_exit([id])`,
/// forcing the same vCPUs out, at the same infrequent quiesce points), so no
/// duplicated registry logic remains.
pub type VcpuKicker = carrick_hal::GenericVcpuRegistry;

/// Extract the live vCPU id from a handle, or `None` if the vCPU is gone.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn valid_id(h: &VcpuKickHandle) -> Option<u64> {
    h.inner.is_valid().then(|| h.inner.id())
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn valid_id(_h: &VcpuKickHandle) -> Option<u64> {
    None
}

/// Force the given vCPU ids out of `hv_vcpu_run`. Errors (e.g. a vCPU destroyed
/// in the race window) are ignored — a stale id yields `HV_BAD_ARGUMENT`, never
/// UB, and the worst case is a missed kick the next syscall boundary catches.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn kick_ids(ids: &[u64]) {
    if ids.is_empty() {
        return;
    }
    // SAFETY: `ids` is a valid slice of `hv_vcpu_t` (u64); `hv_vcpus_exit`
    // reads `count` ids and returns a status we deliberately ignore.
    unsafe {
        applevisor_sys::hv_vcpus_exit(ids.as_ptr(), ids.len() as u32);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn kick_ids(_ids: &[u64]) {}

/// Handle for the process-directed signal pump thread. Dropping or stopping it
/// asks the pump to exit and joins the host thread, which gives the runtime a
/// fork point with no pump thread alive.
pub struct SignalPump {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set true by the pump thread (via an exit guard) when its loop ends, so
    /// `stop_inner` can wait on the EXIT — not merely send one wake — and so it
    /// can give up and detach rather than `join()` forever.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    exited: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    handle: Option<std::thread::JoinHandle<()>>,
}

impl SignalPump {
    pub fn stop(mut self) {
        self.stop_inner();
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn stop_inner(&mut self) {
        use std::sync::atomic::Ordering;
        self.running.store(false, Ordering::SeqCst);
        let Some(handle) = self.handle.take() else {
            return;
        };
        // Wake the pump and wait for it to OBSERVE `running == false` and exit.
        //
        // A single wake is NOT enough: a freshly respawned pump (e.g. in a
        // forkserver worker that immediately forks server B) can still be
        // setting up its kqueue/pipe when stop runs, so one wake races and is
        // lost, the pump parks in `kevent` forever, and a plain `join()` hangs —
        // wedging the whole host fork (the CPython forkserver-from-forkserver
        // `test_parent_process` deadlock). So: wake via BOTH the pipe and the
        // EVFILT_USER NOTE_TRIGGER, retry on a short cadence until the pump's
        // exit guard fires, and if it still hasn't exited within a generous
        // bound (truly wedged), DETACH instead of joining forever. A leaked
        // daemon blocked in `kevent` is harmless — the next pump's
        // `pump_install_pipe` closes its pipe, which EOF-wakes it to exit.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            crate::host_signal::wake_signal_pump_all();
            if self.exited.load(Ordering::SeqCst) {
                let _ = handle.join();
                return;
            }
            if std::time::Instant::now() >= deadline {
                drop(handle); // detach (does NOT join) — never hang the fork
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn stop_inner(&mut self) {}
}

impl Drop for SignalPump {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Spawn a daemon thread that, whenever a signal is published, forces every
/// registered vCPU out of `hv_vcpu_run`. This delivers a *process-directed*
/// signal (host SIGINT, a cross-process kill) promptly to threads spinning in
/// guest userspace — the case the waiter self-pipe alone can't cover, since a
/// thread in-guest isn't parked in `kevent`. Threads parked in a blocking
/// syscall are still woken by their separate waiter pipe directly; this only
/// adds the in-guest kick. The thread runs until the process exits (no join —
/// it holds only an `Arc` clone of the kicker).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn spawn_signal_pump(
    kicker: std::sync::Arc<dyn carrick_hal::VcpuRegistry>,
    futex: std::sync::Arc<dyn carrick_hal::PlatformFutex>,
) -> SignalPump {
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let exited = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_running = std::sync::Arc::clone(&running);
    let thread_exited = std::sync::Arc::clone(&exited);
    let handle = std::thread::Builder::new()
        .name("carrick-signal-pump".to_owned())
        .spawn(move || {
            // Mark the pump EXITED on every return path (incl. the early
            // kqueue/pipe-setup bail-outs below), so `stop_inner` waits on the
            // real exit and never joins a thread that already left.
            struct ExitGuard(std::sync::Arc<std::sync::atomic::AtomicBool>);
            impl Drop for ExitGuard {
                fn drop(&mut self) {
                    self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let _exit_guard = ExitGuard(thread_exited);
            let Some(kq) = crate::darwin_kqueue::Kqueue::new_internal() else {
                return;
            };
            let kq_fd = kq.raw_fd();
            // Create the wake pipe HERE, after the kqueue is allocated, so the
            // pipe's read fd can never be the kqueue fd (the bug that wedged
            // pump.stop(): the pump armed EVFILT_READ on its own kqueue, so wake
            // bytes were lost). pump_install_pipe also closes any stale/inherited
            // pump pipe via replace_pipe.
            let Some(pipe) = crate::host_signal::pump_install_pipe() else {
                return;
            };
            // Two wake sources, both edge-triggered (EV_CLEAR), and we block
            // with NO timeout so the process genuinely sleeps when idle (a
            // poll would keep it SRUN and confound /proc/<pid>/stat):
            //
            //  * EVFILT_READ on the dedicated pump pipe — woken by a signal
            //    published from a HOST signal handler (async-signal-safe pipe
            //    write), e.g. SIGINT or a cross-process kill. This pipe is not
            //    watched or drained by blocking-I/O waiters.
            //  * EVFILT_USER (ident 0) — woken by `notify_pump` (NOTE_TRIGGER)
            //    from a normal thread, e.g. an interval-timer firing SIGALRM
            //    thousands of times into a guest busy-waiting in userspace.
            //    NOTE_TRIGGER re-fires reliably with EV_CLEAR, so this needs no
            //    pipe drain and no poll. (kevent isn't async-signal-safe, which
            //    is why the handler path uses the pipe instead.)
            let changes = [
                crate::darwin_kqueue::Kevent::read(pipe, libc::EV_ADD | libc::EV_CLEAR),
                crate::darwin_kqueue::Kevent::user(0, libc::EV_ADD | libc::EV_CLEAR),
            ];
            let _ = kq.apply(&changes);
            // Publish the kq so `notify_pump` can NOTE_TRIGGER our EVFILT_USER.
            crate::host_signal::set_pump_kqueue(kq_fd);
            // Arm EVFILT_PROC/NOTE_EXIT for any guest child forked before the
            // pump learned its kqueue, so a fast-exiting child still yields
            // SIGCHLD. New children are armed directly by register_child_exit_watch.
            crate::host_signal::rearm_child_watches(kq_fd);
            // Per-`which` EVFILT_TIMER ident this pump has registered, so the
            // reconcile below registers each new arm exactly once. A timer must
            // be EV_ADDed FROM THIS pump thread (the one calling kevent): a timer
            // registered by the dispatcher thread while the pump is blocked in
            // kevent() is not monitored by that wait. `setitimer` arms the neutral
            // slot + wakes the pump (EVFILT_USER), and the reconcile here does the
            // actual kqueue registration. Idents are fresh per arm (see
            // itimer::next_ident), so a changed live_ident == a new arm.
            let mut registered_timer_ident = [0usize; crate::itimer::ITIMER_COUNT];
            let mut out = [crate::darwin_kqueue::Kevent::empty()];
            while thread_running.load(std::sync::atomic::Ordering::SeqCst) {
                // Reconcile registered timers with the armed slots BEFORE waiting,
                // so a just-armed (or re-armed) timer is registered in this
                // thread's kevent context and fires into the wait below. The
                // kevent carries the arm's generation in `udata` so a stale late
                // fire from a superseded arm can be rejected on delivery.
                for (which, registered) in registered_timer_ident.iter_mut().enumerate() {
                    let target = if crate::itimer::is_armed(which) {
                        crate::itimer::live_ident(which)
                    } else {
                        0
                    };
                    if target != *registered {
                        if target != 0
                            && let Some(arm) = crate::itimer::current_arm(which)
                        {
                            let _ = kq.apply(&[crate::darwin_kqueue::Kevent::timer(
                                arm.ident,
                                arm.flags,
                                arm.delay_ns,
                            )
                            .with_udata_u64(arm.generation)]);
                        }
                        *registered = target;
                    }
                }
                let n = match kq.wait(&[], &mut out, None) {
                    Ok(n) => n,
                    Err(errno) => {
                        if errno == libc::EINTR {
                            continue;
                        }
                        break;
                    }
                };
                for event in out.iter().take(n) {
                    if event.is_read() {
                        crate::host_signal::drain_pump_pipe();
                        continue;
                    }
                    if let Some(child_pid) = event.proc_exit_ident() {
                        // A watched guest child exited (NOTE_EXIT) or was already
                        // gone (EV_ERROR on EVFILT_PROC) — either way deliver
                        // SIGCHLD to the forking parent tid. publish_pending_for
                        // marks SIGCHLD (linux signum 17) pending and wakes the
                        // parent's waiter/vCPU; the runtime's delivery cycle then
                        // applies the guest's SIGCHLD disposition (drop on
                        // SIG_IGN / default-ignore, else inject the handler). The
                        // child's exit status is NOT consumed here, so the
                        // guest's wait4 still reaps it via host waitpid.
                        if let Some((parent_tid, exit_signal)) =
                            crate::host_signal::take_child_exit_parent(child_pid)
                        {
                            // A 0 exit_signal (e.g. clone(0)) means the guest
                            // asked for NO exit notification; publishing a
                            // default-ignore SIGCHLD anyway would wrongly
                            // satisfy a sigtimedwait({SIGCHLD}). The wait4/waitid
                            // wake does not depend on this publish (wait_proc_exit
                            // owns its own EVFILT_PROC + 50ms re-poll), so
                            // suppressing it is hang-free and more faithful.
                            if exit_signal != 0 {
                                crate::host_signal::publish_pending_for(parent_tid, exit_signal);
                            }
                        }
                        continue;
                    }
                    if let Some(ident) = event.timer_ident() {
                        if let Some(which) = crate::itimer::which_for_ident(ident) {
                            // Invariant check: the fire's `udata` carries the arm
                            // generation it was registered with. If it no longer
                            // matches the slot's live generation, this is a stale
                            // late fire from a superseded arm (disarmed, or
                            // re-armed onto a fresh ident) — drop it and delete the
                            // dead knote. Guards against an extra/duplicate signal.
                            if !crate::itimer::is_armed(which)
                                || event.udata_u64() != crate::itimer::generation(which)
                            {
                                let _ = kq.apply(&[crate::darwin_kqueue::Kevent::timer(
                                    ident,
                                    libc::EV_DELETE,
                                    0,
                                )]);
                                continue;
                            }
                            let cpu_timer = crate::itimer::is_cpu_timer(which);
                            if cpu_timer
                                && let Some(crate::itimer::CpuTimerDecision::Wait { delay_ns }) =
                                    crate::itimer::cpu_timer_decision(which)
                            {
                                let _ = kq.apply(&[crate::darwin_kqueue::Kevent::timer(
                                    ident,
                                    libc::EV_ADD | libc::EV_ONESHOT,
                                    i64::try_from(delay_ns.max(1)).unwrap_or(i64::MAX),
                                )
                                .with_udata_u64(crate::itimer::generation(which))]);
                                continue;
                            }
                            let signum = crate::itimer::signum_for(which);
                            crate::probes::itimer_fire(signum, 0);
                            crate::host_signal::publish_process_signal(signum);
                            if cpu_timer {
                                let interval = crate::itimer::interval_ns(which);
                                if interval > 0 {
                                    let delay_ns =
                                        crate::itimer::cpu_timer_recheck_delay_ns(interval);
                                    let _ = kq.apply(&[crate::darwin_kqueue::Kevent::timer(
                                        ident,
                                        libc::EV_ADD | libc::EV_ONESHOT,
                                        i64::try_from(delay_ns).unwrap_or(i64::MAX),
                                    )
                                    .with_udata_u64(crate::itimer::generation(which))]);
                                } else {
                                    crate::itimer::complete_fire(which);
                                }
                                continue;
                            }
                            // A two-phase timer (it_value != it_interval) is armed
                            // as a one-shot for it_value; on that first fire we arm
                            // the periodic timer exactly once. take_needs_periodic
                            // clears the flag so later periodic fires don't re-arm
                            // (which would reset the period and accumulate drift).
                            // Pure-periodic and one-shot timers never re-arm here.
                            if crate::itimer::take_needs_periodic(which) {
                                let interval = crate::itimer::interval_ns(which);
                                if interval > 0 {
                                    let _ = kq.apply(&[crate::darwin_kqueue::Kevent::timer(
                                        ident,
                                        libc::EV_ADD,
                                        interval as i64,
                                    )
                                    .with_udata_u64(crate::itimer::generation(which))]);
                                }
                            } else {
                                crate::itimer::complete_fire(which);
                            }
                        }
                        continue;
                    }
                }
                if !thread_running.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
                let pending_threads = crate::host_signal::pending_thread_tids();
                if crate::host_signal::has_process_pending() {
                    // A process-directed signal can be delivered by any guest
                    // thread, so every in-guest vCPU and futex waiter must
                    // re-check pending at its next safe point.
                    kicker.kick_all();
                    futex.notify_signal_pending();
                }
                for tid in pending_threads {
                    // A thread-directed signal belongs to one guest tid. Wake
                    // only that vCPU / futex waiter; siblings stay parked.
                    kicker.kick(tid);
                    futex.notify_signal_pending_for(tid);
                }
            }
            crate::host_signal::clear_pump_kqueue(kq_fd);
        })
        .ok();
    SignalPump {
        running,
        exited,
        handle,
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn spawn_signal_pump(
    _kicker: std::sync::Arc<dyn carrick_hal::VcpuRegistry>,
    _futex: std::sync::Arc<dyn carrick_hal::PlatformFutex>,
) -> SignalPump {
    SignalPump {}
}

#[cfg(test)]
mod tests {
    use super::*;
    // VcpuKicker is now the shared GenericVcpuRegistry; its register/kick/… are
    // VcpuRegistry trait methods, so bring the trait into scope.
    use carrick_hal::VcpuRegistry;

    // On non-macOS, handles carry no live id, so kicks are no-ops; we still
    // exercise the registry bookkeeping (register/unregister) here. On macOS
    // these run too — kick_ids with an empty set is a no-op.
    #[test]
    fn register_unregister_is_consistent() {
        let kicker = VcpuKicker::new();
        // Unknown tid: kick is a harmless no-op.
        kicker.kick(42);
        kicker.unregister(42);
        // kick_all on an empty registry does nothing.
        kicker.kick_all();
        kicker.kick_all_except(1);
    }

    #[test]
    fn signal_pump_handle_stops_without_live_vcpus() {
        let _g = crate::host_signal::pump_state_test_guard();
        crate::host_signal::install_default_handlers();
        let registry: std::sync::Arc<dyn carrick_hal::VcpuRegistry> =
            std::sync::Arc::new(VcpuKicker::new());
        let futex: std::sync::Arc<dyn carrick_hal::PlatformFutex> = std::sync::Arc::new(
            crate::threaded_impl::hvf_futex(std::sync::Arc::new(crate::thread::FutexTable::new())),
        );
        let pump = spawn_signal_pump(registry, futex);
        pump.stop();
    }

    /// `SignalPump::stop` must be BOUNDED even when the pump can no longer be
    /// woken. The CPython forkserver-from-forkserver `test_parent_process`
    /// deadlock was exactly this: a worker forking server B called
    /// `prepare_host_fork -> stop()`, whose single pipe-wake raced and was lost,
    /// so `join()` blocked forever and wedged the whole host fork. With BOTH wake
    /// channels severed, stop must still return (by detaching) rather than hang.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn signal_pump_stop_is_bounded_when_wake_is_lost() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let _g = crate::host_signal::pump_state_test_guard();
        crate::host_signal::install_default_handlers();
        let registry: std::sync::Arc<dyn carrick_hal::VcpuRegistry> =
            std::sync::Arc::new(VcpuKicker::new());
        let futex: std::sync::Arc<dyn carrick_hal::PlatformFutex> = std::sync::Arc::new(
            crate::threaded_impl::hvf_futex(std::sync::Arc::new(crate::thread::FutexTable::new())),
        );
        let pump = spawn_signal_pump(registry, futex);
        // Let the pump finish setting up and park in kevent().
        std::thread::sleep(std::time::Duration::from_millis(150));
        // Sever BOTH wake channels so the pump can never observe the stop flag.
        crate::host_signal::debug_break_pump_wake();
        // Run stop() on a helper thread; the main thread enforces a deadline, so
        // a hang fails the test cleanly instead of wedging the test binary.
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let done2 = std::sync::Arc::clone(&done);
        let h = std::thread::spawn(move || {
            pump.stop();
            done2.store(true, Ordering::SeqCst);
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        while !done.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "SignalPump::stop hung when the pump could not be woken \
                 (the forkserver-from-forkserver deadlock)"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let _ = h.join();
        // `debug_break_pump_wake` severed the global pump pipe (PUMP_PIPE_WRITE)
        // and kqueue (both set to -1). Reinstall a fresh pump pipe so the NEXT
        // test (held off until now by the shared lock) sees a usable pump pipe
        // rather than a -1 write fd. PUMP_KQUEUE is left at -1, which is the
        // benign "no pump registered" sentinel every pump-assertion test resets
        // it to anyway.
        let _ = crate::host_signal::pump_install_pipe();
    }
}
