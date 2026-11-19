//! AArch64 EL0 system-register trap decoding.

pub const AARCH64_GUEST_COUNTER_HZ: u64 = 1_000_000_000;

/// Read the host's raw ARM generic-timer virtual count and frequency at EL0.
///
/// Keep this pair for diagnostics and oracles that intentionally compare the
/// raw, suspend-including counter with Darwin uptime. Frequency-only production
/// paths use [`host_counter_frequency`] so they never execute `CNTVCT_EL0`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn host_counter() -> (u64, u64) {
    let (cntvct, cntfrq): (u64, u64);
    // SAFETY: cntvct_el0/cntfrq_el0 are unprivileged reads on aarch64 macOS.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) cntvct, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) cntfrq, options(nomem, nostack));
    }
    (cntvct, cntfrq)
}

/// Read only the host ARM generic-timer frequency at EL0.
///
/// Capability and scale planning must not sample `CNTVCT_EL0`: that counter
/// includes host suspend on Apple Silicon and is not the Darwin uptime source
/// exposed to native guests. macOS permits the frequency read at EL0.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn host_counter_frequency() -> u64 {
    let cntfrq: u64;
    // SAFETY: cntfrq_el0 is an unprivileged read on aarch64 macOS.
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) cntfrq, options(nomem, nostack));
    }
    cntfrq
}

/// Read the host's CTR_EL0 (cache type) and DCZID_EL0 (DC ZVA block id) at EL0.
/// Both are unprivileged reads on aarch64 macOS (Darwin sets SCTLR_EL1.UCT/DZE),
/// so the emulate fallback returns the SAME real cache geometry the guest gets
/// natively once carrick sets SCTLR_EL1.UCT/DZE — both paths agree.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub fn host_ctr_dczid() -> (u64, u64) {
    let (ctr, dczid): (u64, u64);
    // SAFETY: ctr_el0/dczid_el0 are unprivileged reads on aarch64 macOS.
    unsafe {
        core::arch::asm!("mrs {}, ctr_el0", out(reg) ctr, options(nomem, nostack));
        core::arch::asm!("mrs {}, dczid_el0", out(reg) dczid, options(nomem, nostack));
    }
    (ctr, dczid)
}

/// Off-target (host unit tests on non-aarch64): a plausible CTR_EL0 (64-byte
/// i/d lines: IminLine=DminLine=4) + DCZID_EL0 (DZP=0, BS=4 → 64-byte block).
/// HVF never runs off-target, so this only satisfies the type checker.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn host_ctr_dczid() -> (u64, u64) {
    (0x8444_4004, 0x4)
}

// The host uptime clock moved to `carrick_host::clock` (per-OS clock id) so
// the native (DSR) backend synthesises guest counters from the same source on
// every host OS. Re-exported here for the existing HVF trap call sites.
pub use carrick_host::clock::host_clock_uptime_ns;

pub fn guest_counter_ticks() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}
