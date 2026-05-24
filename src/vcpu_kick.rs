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

use std::collections::HashMap;
use std::sync::Mutex;

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
}

impl VcpuKicker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record this thread's vCPU handle so siblings can kick it. Called once
    /// when a vCPU thread begins running, on its owning thread.
    pub fn register(&self, tid: ThreadId, handle: VcpuKickHandle) {
        #[allow(clippy::expect_used)]
        self.handles
            .lock()
            .expect("VcpuKicker poisoned")
            .insert(tid, handle);
    }

    /// Drop a thread's handle when it exits (so a kick can't target a dead vCPU
    /// and a recycled tid starts clean).
    pub fn unregister(&self, tid: ThreadId) {
        #[allow(clippy::expect_used)]
        self.handles
            .lock()
            .expect("VcpuKicker poisoned")
            .remove(&tid);
    }

    /// Force `tid`'s vCPU out of `hv_vcpu_run` if it is currently in-guest.
    /// No-op if the tid is unknown or its vCPU is gone.
    pub fn kick(&self, tid: ThreadId) {
        #[allow(clippy::expect_used)]
        let ids: Vec<u64> = {
            let map = self.handles.lock().expect("VcpuKicker poisoned");
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
            let map = self.handles.lock().expect("VcpuKicker poisoned");
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
            let map = self.handles.lock().expect("VcpuKicker poisoned");
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
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    handle: Option<std::thread::JoinHandle<()>>,
}

impl SignalPump {
    pub fn stop(mut self) {
        self.stop_inner();
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn stop_inner(&mut self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
        crate::host_signal::wake_signal_pump_pipe();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
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
    let pipe = crate::host_signal::pump_pipe_read_fd();
    if pipe < 0 {
        return SignalPump {
            running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            handle: None,
        };
    }
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let thread_running = std::sync::Arc::clone(&running);
    let handle = std::thread::Builder::new()
        .name("carrick-signal-pump".to_owned())
        .spawn(move || {
            let Some(kq) = crate::darwin_kqueue::Kqueue::new_internal() else {
                return;
            };
            let kq_fd = kq.raw_fd();
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
    SignalPump { running, handle }
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
}
