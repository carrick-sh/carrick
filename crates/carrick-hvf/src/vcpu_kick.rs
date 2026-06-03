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

use parking_lot::Mutex;
use std::collections::HashMap;

use crate::thread::ThreadId;

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

/// Process-wide registry mapping each live guest tid to a handle that can kick
/// its vCPU. Shared across all guest threads behind an `Arc`.
#[derive(Default)]
pub struct VcpuKicker {
    handles: Mutex<HashMap<ThreadId, VcpuKickHandle>>,
    /// Per-vCPU "currently inside hv_vcpu_run (walking guest memory)" flag. The
    /// page-table-edit Pause-Modify-Resume coordinator waits until every OTHER
    /// vCPU has this false (out of guest) before editing the shared stage-1
    /// tables — siblings blocked in host syscalls have it false and need no
    /// wake, which avoids the spurious-signal/blocking-wait deadlock.
    in_guest: Mutex<HashMap<ThreadId, std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}

impl VcpuKicker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (and return) this thread's in-guest flag. The vcpu loop sets it
    /// true immediately before `hv_vcpu_run` and false immediately after.
    pub fn register_in_guest(
        &self,
        tid: ThreadId,
    ) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[allow(clippy::expect_used)]
        self.in_guest
            .lock()
            .insert(tid, std::sync::Arc::clone(&flag));
        flag
    }

    /// True if any OTHER registered vCPU is currently in-guest.
    pub fn any_other_in_guest(&self, except: ThreadId) -> bool {
        #[allow(clippy::expect_used)]
        self.in_guest
            .lock()
            .iter()
            .any(|(tid, f)| *tid != except && f.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// Record this thread's vCPU handle so siblings can kick it. Called once
    /// when a vCPU thread begins running, on its owning thread.
    pub fn register(&self, tid: ThreadId, handle: VcpuKickHandle) {
        #[allow(clippy::expect_used)]
        self.handles.lock().insert(tid, handle);
    }

    /// Number of threads with a registered (live) vCPU. The fork quiesce uses
    /// this — not the thread registry's `live_count` — to decide how many
    /// siblings it must wait for: only threads with an actual vCPU need to
    /// release it, and a thread that has a tid but hasn't built its vCPU yet
    /// must NOT be awaited (it would never reach the barrier).
    pub fn count(&self) -> usize {
        #[allow(clippy::expect_used)]
        self.handles.lock().len()
    }

    /// Drop a thread's handle when it exits (so a kick can't target a dead vCPU
    /// and a recycled tid starts clean).
    pub fn unregister(&self, tid: ThreadId) {
        #[allow(clippy::expect_used)]
        self.handles.lock().remove(&tid);
        #[allow(clippy::expect_used)]
        self.in_guest.lock().remove(&tid);
    }

    /// Force `tid`'s vCPU out of `hv_vcpu_run` if it is currently in-guest.
    /// No-op if the tid is unknown or its vCPU is gone.
    pub fn kick(&self, tid: ThreadId) {
        #[allow(clippy::expect_used)]
        let ids: Vec<u64> = {
            let map = self.handles.lock();
            map.get(&tid).into_iter().filter_map(valid_id).collect()
        };
        kick_ids(&ids);
    }

    /// Kick every registered vCPU except `except` (the caller). Used by the
    /// process-directed signal pump: a signal with no specific thread target is
    /// deliverable by any thread, so we nudge all in-guest threads to re-check
    /// pending at their next safe point.
    pub fn kick_all_except(&self, except: ThreadId) {
        #[allow(clippy::expect_used)]
        let ids: Vec<u64> = {
            let map = self.handles.lock();
            map.iter()
                .filter(|(tid, _)| **tid != except)
                .filter_map(|(_, h)| valid_id(h))
                .collect()
        };
        kick_ids(&ids);
    }

    /// Kick every registered vCPU (including the caller's, if registered).
    pub fn kick_all(&self) {
        #[allow(clippy::expect_used)]
        let ids: Vec<u64> = {
            let map = self.handles.lock();
            map.values().filter_map(valid_id).collect()
        };
        kick_ids(&ids);
    }
}

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
    kicker: std::sync::Arc<VcpuKicker>,
    futex: std::sync::Arc<crate::thread::FutexTable>,
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
            // A freshly forked process can run `setitimer` before this pump
            // thread publishes its kqueue. Replay any already-armed timers so
            // their pending SIGALRM/SIGVTALRM/SIGPROF delivery is not lost.
            for arm in crate::itimer::current_arms() {
                let _ = kq.apply(&[crate::darwin_kqueue::Kevent::timer(
                    arm.ident,
                    arm.flags,
                    arm.delay_ns,
                )]);
            }
            let mut out = [crate::darwin_kqueue::Kevent::empty()];
            while thread_running.load(std::sync::atomic::Ordering::SeqCst) {
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
                            if !crate::itimer::is_armed(which) {
                                // Stale fire: the timer was disarmed (or a disarm
                                // raced a one-time periodic re-arm and resurrected
                                // it). Delete the kevent and drop the signal — this
                                // self-heals a resurrected periodic timer.
                                let _ = kq.apply(&[crate::darwin_kqueue::Kevent::timer(
                                    ident,
                                    libc::EV_DELETE,
                                    0,
                                )]);
                                continue;
                            }
                            let signum = crate::itimer::signum_for(which);
                            crate::probes::itimer_fire(signum, 0);
                            crate::host_signal::publish_process_signal(signum);
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
                                    )]);
                                }
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
    _kicker: std::sync::Arc<VcpuKicker>,
    _futex: std::sync::Arc<crate::thread::FutexTable>,
) -> SignalPump {
    SignalPump {}
}

#[cfg(test)]
mod tests {
    use super::*;

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
        crate::host_signal::install_default_handlers();
        let pump = spawn_signal_pump(
            std::sync::Arc::new(VcpuKicker::new()),
            std::sync::Arc::new(crate::thread::FutexTable::new()),
        );
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
        crate::host_signal::install_default_handlers();
        let pump = spawn_signal_pump(
            std::sync::Arc::new(VcpuKicker::new()),
            std::sync::Arc::new(crate::thread::FutexTable::new()),
        );
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
    }
}
