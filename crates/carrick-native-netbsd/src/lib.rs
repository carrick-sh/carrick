//! `carrick-native-netbsd` — the NetBSD/amd64 host layer for the native
//! (DSR) backend.
//!
//! Task 1 of the NetBSD native-lane plan lands the dual-mapped W^X JIT backend
//! here (`jit`), built on the Task-0 grounding
//! (docs/superpowers/specs/2026-07-25-netbsd-primitives-grounding.md): NetBSD
//! has no `SHM_ANON`, so the anonymous backing object is a uniquely-named
//! `shm_open` that is `shm_unlink`ed immediately, then mapped twice (RX + RW).
//! Task 2 adds the guest-fault shim (`fault`) that turns SIGSEGV/SIGBUS/SIGFPE/
//! SIGILL inside the code cache into typed gateway `Signal` exits (reading the
//! NetBSD `mcontext_t.__gregs[_REG_*]` array) plus the RCX-recovery kick. The
//! cross-process futex (`futex`/`waiter_key`) joins in Task 3.
//!
//! The whole crate is NetBSD-only by construction (same `#![cfg]` pattern as
//! `carrick-native-freebsd`); other targets compile it to nothing, so the
//! module doc above uses a plain code span rather than an intra-doc link that
//! `cargo doc` could not resolve off-NetBSD.

#![cfg(target_os = "netbsd")]

pub mod fault;
pub mod futex;
pub mod jit;

pub use fault::NATIVE_EXIT_KICK_SIGNAL;
pub use jit::NetbsdHostJit;

// The run loop uses the exit kick as a signal PAIR (`NATIVE_EXIT_KICK_SIGNAL`
// and `+1`). NetBSD's `SIGRTMIN=33`/`SIGRTMAX=63` (Task-2 box probe) makes both
// 33 and 34 valid, free real-time signals (libpthread reserves no leading RT
// signals, unlike glibc), so the pair does not collide with a runtime handler.
const _: () = assert!(
    NATIVE_EXIT_KICK_SIGNAL == 33 && NATIVE_EXIT_KICK_SIGNAL + 1 == 34,
    "the exit-kick signal pair (33, 34) must be free real-time signals"
);

/// The process-wide host-JIT instance handed to the runtime's lane wiring
/// (mirrors `carrick-native-freebsd::active_host_jit`).
pub fn active_host_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
    static JIT: NetbsdHostJit = NetbsdHostJit;
    &JIT
}

/// The NetBSD half of a native lane (`carrick_dsr::lane::NativeHost`): hands
/// the lane wiring this crate's JIT authority. Mirrors `FreebsdHost`.
///
/// Unlike FreeBSD, NetBSD needs neither seam override (Task-0 grounding):
/// there is no `MAP_EXCL` (so `exclusive_fixed_map_flag` keeps the default 0,
/// overlap protection staying in `NativeMappingTransaction`), and the kernel
/// keys shared futexes by their backing object, so `shared_futex_waiter_key`
/// keeps the default `None` (finalized in Task 3) rather than a
/// `kern.proc.vmmap`-style derivation.
pub struct NetbsdHost;

impl carrick_dsr::lane::NativeHost for NetbsdHost {
    const NAME: &'static str = "netbsd";

    fn active_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
        active_host_jit()
    }

    fn become_guest_reaper() {
        // Graceful degradation (run-path review F3): NetBSD has no
        // `procctl(PROC_REAP_ACQUIRE)` subreaper primitive. Without it a guest
        // double-forked orphan reparents to HOST init instead of this process,
        // so the guest's `wait4(-1)` of that grandchild returns ECHILD and the
        // run loop's getppid-reports-guest-init subreaper bookkeeping goes
        // stale. This is a precisely-scoped, red-listed capability gap (a NetBSD
        // reap mechanism is the follow-on), not a crash — hence a no-op rather
        // than an error.
    }

    fn vdso_tsc_calibration() -> Option<(u64, u64, u64)> {
        // NetBSD lacks the FreeBSD `machdep.tsc_freq` /
        // `kern.timecounter.{invariant,smp}_tsc` sysctls the x86 vDSO
        // calibration reads, so return `None`: the vDSO's built-in
        // Linux-syscall fallback then supplies coherent host-clock semantics.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::NativeHost;

    #[test]
    fn netbsd_host_name_and_jit_are_wired() {
        assert_eq!(NetbsdHost::NAME, "netbsd");
        NetbsdHost::active_jit().supported().expect("supported");
    }
}
