//! `carrick-native-freebsd` — the FreeBSD/amd64 host layer for the native
//! (DSR) backend.
//!
//! Two rungs of the seams design
//! (docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md)
//! live here: the dual-mapped W^X JIT backend (M0.7) and the guest-fault
//! shim (`fault`) that turns SIGSEGV/SIGBUS/SIGFPE/SIGILL inside the code
//! cache into typed gateway `Signal` exits. The SIGPIPE kick plumbing lands
//! with the runtime thread loop.
//!
//! `fault` (like every other item below) only exists when this crate's whole
//! body is compiled in on `target_os = "freebsd"`; the module doc above uses
//! a plain code span rather than an intra-doc link so `cargo doc` does not
//! try (and fail) to resolve it on other hosts, where the `#![cfg]` below
//! leaves this crate empty.
//!
//! The whole crate is FreeBSD-only by construction; other targets compile it
//! to nothing (same `#![cfg]` pattern as `carrick-host-bsd`).
//!
//! ## Which of this crate is amd64-welded, and which is not
//!
//! FreeBSD/aarch64 is a real host (the aarch64 BSD native-lane campaign), so
//! the crate-level gate is `target_os` and the arch axis is applied
//! per-module — the `carrick-native-darwin` pattern:
//!
//! * `fault` is **amd64-only**: it reads the named amd64 `mcontext_t` fields
//!   `mc_rip`/`mc_r15`/`mc_rcx`, which do not exist on FreeBSD/aarch64 (whose
//!   `mcontext_t` is `mc_gpregs: gpregs { gp_x, gp_lr, gp_sp, gp_elr,
//!   gp_spsr }`). An aarch64 fault shim is its own port, not a cfg.
//! * `tsc` is **amd64-only**: `std::arch::x86_64::_rdtsc` plus the
//!   `machdep.tsc_freq` / `kern.timecounter.*_tsc` sysctls, and it exists to
//!   calibrate the **x86** vDSO, which an aarch64 guest does not have.
//! * `futex`, `waiter_key` and `jit`'s mapping machinery are **arch-neutral**
//!   (`_umtx_op`, `sysctl(KERN_PROC_VMMAP)`, `shm_open(SHM_ANON)` + `mmap`)
//!   and stay compiled on every FreeBSD arch on purpose — whether they behave
//!   on arm64 is exactly what the aarch64 lane needs to learn, so gating them
//!   out would hide the answer rather than produce it.
//! * The one genuinely arch-shaped thing inside `jit` is `flush_icache`,
//!   whose x86 no-op is WRONG on aarch64's non-coherent I-cache. See `jit`
//!   for how that is made fail-closed rather than silently stale.

#![cfg(target_os = "freebsd")]

#[cfg(target_arch = "x86_64")]
pub mod fault;
pub mod futex;
pub mod jit;
#[cfg(target_arch = "x86_64")]
pub mod tsc;
mod waiter_key;

pub use jit::FreebsdHostJit;

/// FreeBSD's kick signal: `SIGRTMIN` = 65. The run loop uses it as a signal
/// PAIR (this value and `+1`), delivered per-thread with `pthread_kill`.
///
/// Lives at the crate root, not in `fault`, because the value is a FreeBSD
/// **OS** fact rather than an amd64 one: `fault` is amd64-gated, and the
/// constant must stay available on every FreeBSD arch (the aarch64 lane needs
/// it to resolve its host-signal glue). This mirrors
/// `carrick_native_netbsd::NATIVE_EXIT_KICK_SIGNAL` exactly; `carrick-runtime`
/// consumes both by this crate-root path.
pub const NATIVE_EXIT_KICK_SIGNAL: libc::c_int = 65;

// The exit kick is used as a PAIR. FreeBSD's `SIGRTMIN`=65 / `SIGRTMAX`=126
// makes both 65 and 66 valid, free real-time signals (libthr reserves no
// leading RT signals, unlike glibc), so the pair collides with no runtime
// handler.
const _: () = assert!(
    NATIVE_EXIT_KICK_SIGNAL == 65 && NATIVE_EXIT_KICK_SIGNAL + 1 == 66,
    "the exit-kick signal pair (65, 66) must be free real-time signals"
);

/// The process-wide host-JIT instance handed to
/// `carrick_dsr_aarch64::translator::install_host_jit`-style installers by
/// the runtime's lane wiring (M0.8).
pub fn active_host_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
    static JIT: FreebsdHostJit = FreebsdHostJit;
    &JIT
}

/// The FreeBSD half of a native lane (`carrick_dsr::lane::NativeHost`):
/// hands the lane wiring this crate's JIT authority. Mirrors
/// `carrick-native-darwin`'s `DarwinHost`.
pub struct FreebsdHost;

impl carrick_dsr::lane::NativeHost for FreebsdHost {
    const NAME: &'static str = "freebsd";

    fn active_jit() -> &'static dyn carrick_dsr::host::NativeHostJit {
        active_host_jit()
    }

    fn shared_futex_waiter_key(host_addr: usize) -> Option<usize> {
        waiter_key::shared_waiter_key(host_addr)
    }

    fn exclusive_fixed_map_flag() -> i32 {
        libc::MAP_EXCL
    }

    fn become_guest_reaper() {
        // Act as the guest's PID-namespace init: become a FreeBSD reaper so an
        // orphaned guest grandchild (its middle parent exited) REPARENTS to this
        // process instead of host init, letting the guest's wait4(-1) reap it —
        // pid_namespaces(7) "pid 1 reaps orphans" (`pidnsorphanreap`), and the
        // reparent target for PR_SET_CHILD_SUBREAPER (`childsubreaper`).
        // Idempotent: a second acquire returns EBUSY, ignored.
        // SAFETY: procctl with a valid cmd + NULL data.
        unsafe {
            libc::procctl(
                libc::P_PID,
                0,
                libc::PROC_REAP_ACQUIRE,
                std::ptr::null_mut(),
            );
        }
    }

    // amd64 only. On any other FreeBSD arch the trait's default `None` is the
    // correct answer — there is no TSC to calibrate and no x86 vDSO to feed —
    // so the override is simply absent rather than stubbed.
    #[cfg(target_arch = "x86_64")]
    fn vdso_tsc_calibration() -> Option<(u64, u64, u64)> {
        tsc::calibrate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr::lane::NativeHost;

    #[test]
    fn freebsd_host_name_and_jit_are_wired() {
        assert_eq!(FreebsdHost::NAME, "freebsd");
        if cfg!(target_arch = "x86_64") {
            FreebsdHost::active_jit().supported().expect("supported");
        } else {
            // Not a weakened assertion: on an arch whose I-cache is not
            // coherent, a lane whose `flush_icache` has no cache-maintenance
            // body MUST refuse before anything maps code.
            assert!(
                FreebsdHost::active_jit().supported().is_err(),
                "non-amd64 FreeBSD must fail closed: no aarch64 I-cache flush yet"
            );
        }
    }
}
