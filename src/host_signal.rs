//! Host-side signal capture for guest delivery.
//!
//! The Carrick host process catches a small set of UNIX signals
//! (currently just `SIGINT`) and translates them into pending guest
//! signal numbers that the runtime drains between vCPU iterations.
//! When the guest has a handler registered for the translated signum,
//! the runtime synthesises a guest signal frame; otherwise the default
//! action (terminate with `128 + signum`) is taken.
//!
//! The shared state is intentionally minimal:
//!
//! * A single `AtomicI32` (`PENDING`) carries the *most recent* host
//!   signal we observed. `0` means "no signal pending"; any positive
//!   value is the Linux signum the guest should see.
//! * `install_default_handlers()` registers our handler once via
//!   `libc::sigaction`. Re-installation is a no-op so test runners that
//!   spin up multiple runtime instances inside the same process don't
//!   stomp on each other.
//!
//! We deliberately do NOT serialise signals through the host kernel's
//! pending mask; the goal of v0 is "Ctrl-C breaks a long-running
//! command", not "perfectly faithful POSIX signal queueing". One slot
//! is enough for that.

use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};

use crate::linux_abi::LINUX_SIGINT;

/// "No signal pending" sentinel. Chosen as `0` because Linux's
/// `kill(pid, 0)` is documented as the null-signal probe; no real
/// delivery ever uses signum 0.
pub const NO_PENDING_SIGNAL: i32 = 0;

static PENDING: AtomicI32 = AtomicI32::new(NO_PENDING_SIGNAL);

/// 0 = handlers not installed yet, 1 = installed. Used to make
/// `install_default_handlers` idempotent across test setups.
static INSTALLED: AtomicU8 = AtomicU8::new(0);

/// Async-signal-safe handler. The only thing we do here is publish the
/// observed signum into `PENDING`. The runtime drains it between vCPU
/// iterations.
extern "C" fn handle_sigint(_signum: libc::c_int) {
    // Store the LINUX signum, not the host one; on Darwin and Linux
    // SIGINT happens to share the value 2, but we route everything
    // through the Linux numbering on the guest side so the dispatcher's
    // signal_handlers table lookup matches.
    PENDING.store(LINUX_SIGINT, Ordering::SeqCst);
}

/// Install the host SIGINT handler. Subsequent calls are no-ops. Safe
/// to call from anywhere; the runtime calls it once per `run_*`
/// invocation.
pub fn install_default_handlers() {
    if INSTALLED
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    // SAFETY: zero-initialised `sigaction` is the documented Linux/Darwin
    // "no flags, empty mask" form. We immediately fill `sa_sigaction`
    // with our handler before calling into libc.
    unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = handle_sigint as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        // Restart syscalls where possible so the host-side `vcpu.run`
        // syscall isn't permanently broken by a SIGINT. Without
        // SA_RESTART, applevisor's wrapper would observe EINTR and
        // surface a hypervisor error; with it set, the kernel returns
        // to the same vcpu_run call and we then notice PENDING when
        // the run completes via the normal HVC trap path.
        action.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

/// Drain whatever signal is currently pending. Returns `0` if none.
/// Atomic so the runtime can call this from any thread that's about to
/// re-enter `vcpu.run`.
pub fn take_pending() -> i32 {
    PENDING.swap(NO_PENDING_SIGNAL, Ordering::SeqCst)
}

/// Set a pending guest signum from inside the guest itself (e.g. from
/// `kill(self, SIGINT)`). Lets the runtime's signal-injection path
/// service synthetic raises the same way it services host SIGINT.
pub fn raise_for_self(signum: i32) {
    PENDING.store(signum, Ordering::SeqCst);
}
