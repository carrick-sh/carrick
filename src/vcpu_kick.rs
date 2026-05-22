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

/// Spawn a daemon thread that, whenever a signal is published (the
/// `host_signal` self-pipe becomes readable), forces every registered vCPU out
/// of `hv_vcpu_run`. This delivers a *process-directed* signal (host SIGINT, a
/// cross-process kill) promptly to threads spinning in guest userspace — the
/// case the self-pipe alone can't cover, since a thread in-guest isn't parked
/// in `kevent`. Threads parked in a blocking syscall are still woken by the
/// pipe directly; this only adds the in-guest kick. The thread runs until the
/// process exits (no join — it holds only an `Arc` clone of the kicker).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn spawn_signal_pump(kicker: std::sync::Arc<VcpuKicker>) {
    let pipe = crate::host_signal::pending_pipe_read_fd();
    if pipe < 0 {
        return;
    }
    let _ = std::thread::Builder::new()
        .name("carrick-signal-pump".to_owned())
        .spawn(move || {
            let kq = unsafe { libc::kqueue() };
            if kq < 0 {
                return;
            }
            // Edge-triggered watch on the self-pipe: fire once per "became
            // readable" transition. We deliberately do NOT drain it — the
            // parked-thread waiters own that (level-triggered), and EV_CLEAR
            // re-arms on the next write.
            let change = libc::kevent {
                ident: pipe as usize,
                filter: libc::EVFILT_READ,
                flags: libc::EV_ADD | libc::EV_CLEAR,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            unsafe {
                libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null());
            }
            let mut out = [libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            }];
            loop {
                let n = unsafe {
                    libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 1, std::ptr::null())
                };
                if n < 0 {
                    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    if e == libc::EINTR {
                        continue;
                    }
                    break;
                }
                // A signal was published. Kick every in-guest vCPU so it
                // re-checks pending at its next safe point. A vCPU in a host
                // syscall (kevent) is unaffected (already woken by the pipe);
                // one spinning in the guest exits with CANCELED and delivers.
                kicker.kick_all();
            }
            unsafe { libc::close(kq) };
        });
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn spawn_signal_pump(_kicker: std::sync::Arc<VcpuKicker>) {}

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
}
