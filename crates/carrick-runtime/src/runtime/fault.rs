//! EL0 synchronous-fault translation split out of runtime.rs (WS-F3): map an
//! `ESR_EL1` to the Linux (signum, si_code) the kernel would deliver
//! (el0_fault_signal / el0_debug_signal) and inject it into the guest
//! (deliver_fault_signal). Free functions reached via `use super::*`.
use super::*;

/// Map an EL0 synchronous-fault `ESR_EL1` to the Linux `(signum, si_code)` the
/// kernel would deliver, or `None` for a class we don't translate (kept fatal).
/// ESR EC: 0x20/0x21 = instruction abort, 0x24/0x25 = data abort. DFSC (low 6
/// bits): 0b0001LL translation fault → SEGV_MAPERR; 0b0011LL permission fault →
/// SEGV_ACCERR; 0b100001 alignment → SIGBUS/BUS_ADRALN.
pub(super) fn el0_fault_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGSEGV: i32 = 11;
    const SIGBUS: i32 = 7;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    const BUS_ADRALN: i32 = 1;
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    let segv_code = if (0x0c..=0x0f).contains(&dfsc) {
        SEGV_ACCERR
    } else {
        SEGV_MAPERR
    };
    match ec {
        0x20 | 0x21 => Some((SIGSEGV, segv_code)), // instruction abort
        0x24 | 0x25 => {
            if dfsc == 0x21 {
                Some((SIGBUS, BUS_ADRALN)) // alignment fault
            } else {
                Some((SIGSEGV, segv_code))
            }
        }
        _ => None,
    }
}

/// Map an EL0 synchronous *debug* exception `ESR_EL1` to the Linux
/// `(SIGTRAP, si_code)` the kernel would deliver, or `None` if it isn't a debug
/// class (leaving it to `el0_fault_signal`). These are distinct from
/// instruction/data aborts: a guest `BRK #imm` (Go's debug-call protocol),
/// software single-step, and HW breakpoints/watchpoints all surface SIGTRAP, not
/// SIGSEGV. ESR EC (bits 31:26): 0x3c = `BRK` (AArch64), 0x30/0x31 = HW
/// breakpoint, 0x32/0x33 = software step, 0x34/0x35 = watchpoint. si_addr for a
/// debug SIGTRAP is the PC (the BRK address), not FAR — see `deliver_fault_signal`.
pub(super) fn el0_debug_signal(esr: u64) -> Option<(i32, i32)> {
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

/// Deliver a synchronous guest EL0 fault as a Linux signal (SIGSEGV/SIGBUS with
/// `si_addr` = faulting address), exactly as the kernel does — so Go's
/// nil-deref→sigpanic→recover idiom (and any guest SIGSEGV handler) works
/// instead of carrick killing the guest. Returns `Some(outcome)` to terminate
/// (no handler, signal blocked, or untranslatable fault — Linux forces the
/// default action), `None` to resume into the injected handler. `elr` is the
/// faulting instruction's PC (resumed unless the handler advances it).
pub(super) fn deliver_fault_signal(
    kernel: &Kernel,
    engine: &mut HvfTrapEngine,
    this_tid: ThreadId,
    esr: u64,
    elr: u64,
    far: u64,
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    let dispatcher = &kernel.dispatcher;
    let terminate = |signum: i32| -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        if engine.is_forked_child() || kernel.dispatcher.is_forked_guest_process() {
            let out = dispatcher.stdout();
            let err = dispatcher.stderr();
            forked_child_die_by_signal(signum, &out, &err);
        }
        let result = assemble_run_result(kernel, 128 + signum, traps, false);
        Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))))
    };

    // Classify the synchronous exception. A debug class (BRK/step/HW) is a
    // SIGTRAP whose si_addr is the *PC* (the BRK instruction itself — ELR_EL1
    // for a BRK is the BRK's own address, not the next instruction); an
    // instruction/data abort is SIGSEGV/SIGBUS whose si_addr is the faulting
    // address (FAR). Anything else is untranslatable → fatal SIGSEGV (still
    // visible, but with proper exit semantics).
    let (signum, si_code, si_addr) = if let Some((signum, si_code)) = el0_debug_signal(esr) {
        (signum, si_code, elr)
    } else if let Some((signum, si_code)) = el0_fault_signal(esr) {
        (signum, si_code, far)
    } else {
        return terminate(11);
    };
    crate::probes::signal_deliver(this_tid, signum);

    // A synchronous fault with the signal blocked, or no handler installed,
    // forces the default action (terminate) on Linux.
    let action = dispatcher.registered_signal_handler(signum);
    if dispatcher.signal_blocked(this_tid, signum) || action.is_none() {
        return terminate(signum);
    }
    // INVARIANT: the `action.is_none()` arm above returned, so this is `Some`.
    #[allow(clippy::unwrap_used)]
    let action = action.unwrap();
    let restorer = if action.sa_flags & crate::linux_abi::LINUX_SA_RESTORER != 0 {
        action.sa_restorer
    } else {
        0
    };
    let altstack = if action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0 {
        dispatcher.signal_altstack(this_tid)
    } else {
        None
    };
    let saved_sigmask = dispatcher.enter_signal_handler(this_tid, signum, action);
    // The fault trapped via the EL1 HVC trampoline (like a syscall): ELR_EL1
    // already holds the faulting EL0 instruction (neither aborts nor BRK advance
    // it), and there's a pending eret to EL0. So use the syscall-boundary form
    // (`interrupted_pc=None`): inject sets the handler via ELR_EL1 and snapshots
    // saved_pc=ELR_EL1=the faulting instruction (re-run on return unless the
    // handler advances it — e.g. Go's sigpanic, or its debug-call handler doing
    // `set_pc(pc+4)` to step past the BRK). For a BRK this makes `sigpc` point at
    // the BRK so Go reads `*(*uint32)(sigpc) == 0xd4200000`.
    engine.inject_signal(
        signum,
        action.sa_handler,
        restorer,
        None,
        None,
        altstack,
        saved_sigmask,
        Some((si_code, si_addr)),
    )?;
    Ok(None)
}
