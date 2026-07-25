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
//!
//! ## Which of this crate is amd64-welded, and which is not
//!
//! NetBSD/aarch64 is a real host (the aarch64 BSD native-lane campaign), so
//! the crate-level gate is `target_os` and the arch axis is applied
//! per-module — the `carrick-native-darwin` pattern:
//!
//! * `fault` is **amd64-only**: it indexes the register file as
//!   `mcontext_t.__gregs[_REG_RIP/_REG_RSP/_REG_R15/_REG_RCX]`, and those
//!   `_REG_*` constants exist only in libc's NetBSD **x86_64** module. The
//!   array itself differs in both element type and length on aarch64
//!   (`[greg_t; 32]` vs `[c___greg_t; 26]`), so an aarch64 shim is a port,
//!   not a cfg.
//! * `fsbase` is **amd64-only**: a `naked_asm!` `sysarch(2)` leaf in x86
//!   mnemonics, serving `carrick-dsr-x86`'s FSGSBASE gateway seam. AArch64
//!   has no FS base at all (TLS is `TPIDR_EL0`), so there is nothing to port.
//! * `futex` and `jit`'s mapping machinery are **arch-neutral**
//!   (`__futex(2)`, `shm_open` + `mmap`) and stay compiled on every NetBSD
//!   arch on purpose — whether they behave on arm64 (notably: whether PaX
//!   MPROTECT permits the RX/RW dual map) is exactly what the aarch64 lane
//!   needs to learn, so gating them out would hide the answer.
//! * `platform_futex` is **arch-neutral**: it is the `PlatformFutex` adapter
//!   over `futex` that the aarch64 run loop consumes, written so the x86 lane
//!   can adopt it when the two run loops merge.
//! * The one genuinely arch-shaped thing inside `jit` is `flush_icache`,
//!   whose x86 no-op is WRONG on aarch64's non-coherent I-cache. `jit` has a
//!   real `__clear_cache` body for aarch64 and fails closed on any other
//!   non-x86 arch.

#![cfg(target_os = "netbsd")]

#[cfg(target_arch = "x86_64")]
pub mod fault;
#[cfg(target_arch = "x86_64")]
pub mod fsbase;
pub mod futex;
pub mod jit;
pub mod platform_futex;

pub use jit::NetbsdHostJit;

/// NetBSD's kick signal: SIGRTMIN. The libc crate does not expose `SIGRTMIN`
/// on this target (Task-2 box probe: `SIGRTMIN=33`, `SIGRTMAX=63`, `NSIG=64`),
/// so it is named here as a constant — the same shape as the FreeBSD lane's
/// hardcoded 65. NetBSD's libpthread does not reserve leading real-time
/// signals for internal use (a glibc-ism), so SIGRTMIN is a free,
/// non-colliding kick channel the run loop delivers per-thread via
/// `pthread_kill(thread, SIGRTMIN)`.
///
/// Lives at the crate root, not in `fault`, because the value is a NetBSD
/// **OS** fact rather than an amd64 one: `fault` is amd64-gated, and the
/// constant (and the compile-time pair assertion below) must stay available
/// on every NetBSD arch. `carrick-runtime` already consumes it by this
/// crate-root path.
pub const NATIVE_EXIT_KICK_SIGNAL: libc::c_int = 33;

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
        if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
            // amd64: coherent I-cache, the no-op flush is correct. aarch64:
            // `flush_icache` does real `__clear_cache` maintenance, proven by
            // `jit::tests::republished_code_is_not_stale_after_flush_icache`.
            NetbsdHost::active_jit().supported().expect("supported");
        } else {
            // Not a weakened assertion: on an arch whose I-cache is not
            // coherent, a lane whose `flush_icache` has no cache-maintenance
            // body MUST refuse before anything maps code.
            assert!(
                NetbsdHost::active_jit().supported().is_err(),
                "a NetBSD arch with no I-cache flush must fail closed"
            );
        }
    }
}
