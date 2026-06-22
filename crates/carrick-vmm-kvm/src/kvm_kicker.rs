//! Cross-thread vCPU "kick" for the KVM backend: force a guest thread out of
//! `KVM_RUN` so the trap loop can deliver a pending signal promptly, even when
//! the target is spinning in guest userspace (not parked in a host syscall).
//!
//! This is the Linux/KVM realisation of the "interrupt a running vCPU"
//! primitive. HVF has Apple's `hv_vcpus_exit(ids, count)`; KVM has no such
//! direct call, so we use the kernel's documented mechanism: a signal delivered
//! to the vCPU thread makes the in-progress `KVM_RUN` ioctl return `-EINTR`
//! (which `crate::kvm::KvmVcpu::run` maps to [`carrick_hal::VcpuExit::Kicked`]).
//! The signal is [`kick_signal`] (`SIGRTMIN`), and its handler does nothing —
//! its ONLY job is to interrupt `KVM_RUN`, so it must be installed WITHOUT
//! `SA_RESTART` (or the kernel would silently restart the ioctl and the kick
//! would be lost).
//!
//! Each guest thread publishes a [`KvmKickHandle`] (carrying its `pthread_t`)
//! into the shared [`KvmKicker`] when it starts running and removes it on exit.
//! A signalling thread looks the target up and `pthread_kill`s it. The in-guest
//! flag bookkeeping mirrors the HVF `crate::trap_engine`-driven path exactly:
//! the Dekker handshake with the fork / page-table coordinators is SeqCst on
//! both sides.

use std::sync::Once;

/// The signal carrick uses to force a vCPU out of `KVM_RUN`.
///
/// `SIGRTMIN` (computed at RUNTIME — glibc reserves the first few real-time
/// signals for its own threading internals, so `SIGRTMIN` is NOT the raw
/// `__SIGRTMIN`/34 macro; never hardcode it). A real-time signal is chosen so
/// it never collides with a signal carrick routes to the guest (the runtime
/// maps guest signals through its own `host_signal` layer; it never installs a
/// disposition for `SIGRTMIN`).
#[inline]
pub fn kick_signal() -> i32 {
    libc::SIGRTMIN()
}

/// Empty signal handler. Its ONLY purpose is to interrupt an in-progress
/// `KVM_RUN` (delivering ANY caught signal makes the ioctl return `EINTR` when
/// the handler is installed without `SA_RESTART`). It does no work.
extern "C" fn kvm_kick_noop(_signum: libc::c_int) {}

static KICK_HANDLER_INSTALLED: Once = Once::new();

/// Install the process-wide [`kick_signal`] handler ONCE (idempotent). The
/// handler is empty and installed with `sa_flags = 0` — crucially WITHOUT
/// `SA_RESTART`, so a delivered kick makes the target vCPU thread's `KVM_RUN`
/// return `EINTR` (-> [`carrick_hal::VcpuExit::Kicked`]) instead of being
/// transparently restarted by the kernel.
///
/// Safe to call from any thread at any time; only the first call installs.
pub fn install_kvm_kick_handler() {
    KICK_HANDLER_INSTALLED.call_once(|| {
        // SAFETY: a zeroed `sigaction` is the documented "no flags, empty mask"
        // form; we set the handler fn, an empty mask, and sa_flags = 0 (NO
        // SA_RESTART). `kvm_kick_noop` is a valid `extern "C"` handler.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = kvm_kick_noop as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = 0; // NO SA_RESTART — KVM_RUN must return EINTR.
            libc::sigaction(kick_signal(), &action, std::ptr::null_mut());
        }
    });
}

/// A `Send`/`Sync` handle to a guest thread's vCPU, usable from any thread to
/// kick it. Holds the target's `pthread_t` so a `pthread_kill(tid, SIGRTMIN)`
/// forces it out of `KVM_RUN`. Cloneable (the registry stores it object-safe and
/// the engine hands a fresh clone out per [`carrick_hal::ThreadedEngine::kick_handle`]).
#[derive(Clone)]
pub struct KvmKickHandle {
    /// The owning vCPU thread's pthread id (the kick target).
    tid: libc::pthread_t,
}

impl KvmKickHandle {
    /// Build a handle for the CURRENT thread (call on the owning vCPU thread).
    pub fn for_current_thread() -> Self {
        // Install the SIGRTMIN kick-signal handler here (idempotent `Once`): a
        // thread becomes a kick TARGET only once it has registered a handle, so
        // installing on handle creation guarantees the handler is live process-
        // wide before any kick can be issued. (The shared `GenericVcpuRegistry`
        // used as `KvmKicker` has no constructor hook, and the fork coordinator
        // also installs it defensively — both are idempotent.)
        install_kvm_kick_handler();
        // SAFETY: `pthread_self` is always safe and returns this thread's id.
        let tid = unsafe { libc::pthread_self() };
        Self { tid }
    }
}

impl carrick_hal::VcpuKick for KvmKickHandle {
    fn kick(&self) {
        // SAFETY: `pthread_kill` with a live pthread id + a valid signal. A kick
        // to a thread that has already exited returns ESRCH, which we ignore (a
        // missed kick is caught at the next syscall boundary, never UB).
        unsafe {
            libc::pthread_kill(self.tid, kick_signal());
        }
    }
}

/// The KVM vCPU-kick registry. The bookkeeping (the two maps + the SeqCst Dekker
/// handshake) is the platform-neutral [`carrick_hal::GenericVcpuRegistry`],
/// shared with HVF/bhyve; the only KVM-specific piece is [`KvmKickHandle`] (the
/// `pthread_kill` kick mechanism) + the SIGRTMIN handler install, which now
/// happens in [`KvmKickHandle::for_current_thread`] (the registry has no
/// constructor hook). So this is a plain alias — no duplicated registry logic.
pub type KvmKicker = carrick_hal::GenericVcpuRegistry;

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::*;
    use carrick_hal::{VcpuKick, VcpuRegistry};

    /// A pure-data stand-in for a real `KvmKickHandle`: it records nothing and
    /// kicks nothing, so the registry bookkeeping tests run on ANY host (no
    /// pthread_kill, no /dev/kvm). The `in_guest` flag the registry tracks is
    /// the load-bearing state under test, not the handle.
    #[derive(Clone)]
    struct InertHandle;
    impl VcpuKick for InertHandle {
        fn kick(&self) {}
    }

    fn boxed() -> Box<dyn carrick_hal::VcpuKickDyn> {
        Box::new(InertHandle)
    }

    /// register / unregister / count bookkeeping: `count` reflects the number of
    /// registered handles, and unregister removes both maps' entries.
    #[test]
    fn register_unregister_count() {
        let k = KvmKicker::new();
        assert_eq!(k.count(), 0, "fresh kicker is empty");

        k.register(10, boxed());
        k.register(11, boxed());
        assert_eq!(k.count(), 2, "two handles registered");

        // Kicking an unknown tid, kick_all, kick_all_except are harmless no-ops
        // on inert handles (no pthread_kill fires).
        k.kick(999);
        k.kick_all();
        k.kick_all_except(10);

        k.unregister(10);
        assert_eq!(k.count(), 1, "one handle after unregister");
        k.unregister(11);
        assert_eq!(k.count(), 0, "empty after unregistering both");
        // Unregistering an absent tid is a no-op.
        k.unregister(11);
        assert_eq!(k.count(), 0);
    }

    /// `set_in_guest` + `any_other_in_guest` SeqCst bookkeeping (the Dekker
    /// handshake state) — pure HashMap/AtomicBool, no pthread/KVM.
    #[test]
    fn set_in_guest_any_other_in_guest() {
        let k = KvmKicker::new();
        // Two threads register their in-guest flags.
        let _f1 = k.register_in_guest(1);
        let _f2 = k.register_in_guest(2);

        // Nobody in guest yet.
        assert!(!k.any_other_in_guest(1), "no other thread in guest");
        assert!(!k.any_other_in_guest(2));

        // Thread 2 enters the guest.
        k.set_in_guest(2, true);
        assert!(
            k.any_other_in_guest(1),
            "thread 1 must observe thread 2 in guest"
        );
        // Thread 2 asking "any OTHER" excludes itself -> still false.
        assert!(
            !k.any_other_in_guest(2),
            "the in-guest thread excludes itself"
        );

        // Thread 2 leaves the guest.
        k.set_in_guest(2, false);
        assert!(!k.any_other_in_guest(1), "thread 2 left the guest");

        // set_in_guest for an UNREGISTERED tid is a no-op (no panic, no insert).
        k.set_in_guest(999, true);
        assert!(!k.any_other_in_guest(1));
    }

    /// The handle returned by `register_in_guest` is the SAME `Arc<AtomicBool>`
    /// the registry mutates — so a `set_in_guest(true)` is observable through the
    /// handle the run loop kept (the Dekker handshake relies on this aliasing).
    #[test]
    fn register_in_guest_returns_shared_flag() {
        let k = KvmKicker::new();
        let flag = k.register_in_guest(7);
        assert!(!flag.load(Ordering::SeqCst));
        k.set_in_guest(7, true);
        assert!(
            flag.load(Ordering::SeqCst),
            "the returned flag must alias the registry's flag"
        );
    }
}
