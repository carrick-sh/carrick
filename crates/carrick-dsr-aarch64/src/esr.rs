//! AArch64 `ESR_EL1` debug-class decoding.
//!
//! Moved verbatim from `carrick-runtime/src/vcpu_loop/signal.rs` with the
//! DSR translator extraction: the translator's fault-exit dispatch
//! (`translator::finish_exit_profiled`) needs it, and it is a pure
//! AArch64 architectural fact (no OS, no runtime state), so the ISA crate is
//! its home. The runtime's `vcpu_loop::signal` re-exports it so the HVF trap
//! lowering keeps its `el0_debug_signal` path unchanged.

/// Map an EL0 synchronous *debug* exception `ESR_EL1` to the Linux
/// `(SIGTRAP, si_code)` the kernel would deliver, or `None` if it isn't a debug
/// class (leaving it to `el0_fault_signal`).
pub fn el0_debug_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGTRAP: i32 = 5;
    const TRAP_BRKPT: i32 = 1; // software breakpoint (BRK)
    const TRAP_TRACE: i32 = 2; // process trace trap (single-step)
    const TRAP_HWBKPT: i32 = 4; // hardware breakpoint/watchpoint
    let ec = (esr >> 26) & 0x3f;
    match ec {
        0x3c => Some((SIGTRAP, TRAP_BRKPT)),         // BRK (AArch64)
        0x32 | 0x33 => Some((SIGTRAP, TRAP_TRACE)),  // software step
        0x30 | 0x31 => Some((SIGTRAP, TRAP_HWBKPT)), // HW breakpoint
        0x34 | 0x35 => Some((SIGTRAP, TRAP_HWBKPT)), // watchpoint
        _ => None,
    }
}
