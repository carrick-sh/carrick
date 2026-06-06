//! The runtime↔engine trap contract.
//!
//! `SyscallTrap` is the single trait the runtime loop drives: run the vCPU
//! until a syscall trap, complete/inject/restore around guest syscalls and
//! signals, and fork/execve the guest address space. It references no
//! hypervisor-specific types in its signatures, so it lives here in
//! `carrick-hal` and is implemented per-backend (`HvfTrapEngine` on macOS,
//! `KvmTrapEngine` on Linux, and the runtime's `SplitView` test adapter).
//! `set_memory_model` and `map_host_alias` carry portable defaults so non-HVF
//! backends inherit sane behavior.

use carrick_abi::LinuxSiginfo;
use carrick_guest_mem::Aarch64SyscallFrame;
use carrick_mem::memory::AddressSpace;
use thiserror::Error;

/// The trap-engine contract the runtime loop drives: run the vCPU until a
/// syscall trap, complete/inject/restore around guest syscalls and signals,
/// and fork/execve the guest address space. Implemented by `HvfTrapEngine`
/// (macOS), `KvmTrapEngine` (Linux), and the runtime's `SplitView` adapter.
pub trait SyscallTrap {
    /// Run the vCPU until it traps. `Ok(Some(frame))` is a guest syscall;
    /// `Ok(None)` means the vCPU was forced out of the guest by a cross-thread
    /// kick (`hv_vcpus_exit` / KVM signal-kick) with no syscall pending — the
    /// loop should run signal delivery and resume. `Err` is a real fault.
    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError>;
    /// The guest PC the vCPU is currently parked at. Used as the resume address
    /// when injecting a signal on a non-syscall (kick) exit, where `ELR_EL1`
    /// does not hold a meaningful return address.
    fn current_pc(&self) -> Result<u64, TrapError>;
    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError>;
    /// Real host fork. Returns the child pid in the parent, 0 in the child.
    /// After this returns, the trap engine in the child holds a freshly rebuilt
    /// vCPU context pointing at the same guest memory; the runtime then writes
    /// the appropriate retval into the guest's x0 via `complete_syscall`.
    fn fork(&mut self) -> Result<ForkOutcome, TrapError>;
    /// `execve(2)` — tear down the current guest address space and
    /// re-initialise this engine with `new_image`. Does NOT advance past a
    /// syscall (execve has no successful return); the next `next_syscall`
    /// resumes at the new image's entry point.
    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError>;
    fn is_forked_child(&self) -> bool {
        false
    }
    /// Inject a guest signal frame for `signum`. Writes a `CarrickSigframe` to
    /// SP_EL0, points the guest's x30 at `sa_restorer`, sets x0 to `signum`,
    /// and redirects the vCPU's next resumed PC to the user handler. The
    /// pre-signal register state is preserved in the frame and recovered by
    /// `restore_from_sigframe` on `rt_sigreturn`.
    ///
    /// `pending_syscall_retval` is the retval the dispatcher computed for the
    /// syscall that was just trapped. `interrupted_pc` is `Some(pc)` when
    /// injecting on a non-syscall kick exit. `altstack` is `Some((ss_sp,
    /// ss_size))` when the handler was registered `SA_ONSTACK`. See the macOS
    /// `HvfTrapEngine` impl for the full per-field contract.
    #[allow(clippy::too_many_arguments)]
    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
        queued_siginfo: Option<LinuxSiginfo>,
        restart_syscall: bool,
    ) -> Result<(), TrapError>;
    /// The Linux syscall number of the most recently dispatched `svc`, used to
    /// decide whether an interrupted syscall is in the SA_RESTART-restartable
    /// set. `None` before the first syscall / on traps with no vCPU.
    fn last_syscall_nr(&self) -> Option<u64> {
        None
    }
    /// Restore vCPU state from the `CarrickSigframe` at SP_EL0. Called when the
    /// guest invokes `rt_sigreturn(2)`. Does NOT advance PC past the syscall the
    /// way `complete_syscall` does — the restored PC IS the next PC.
    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError>;
    /// Toggle the vCPU's memory-ordering model (`prctl(PR_SET_MEM_MODEL, …)`).
    /// `tso == true` enables hardware x86_64 Total Store Ordering on this vCPU
    /// (`ACTLR_EL1.EnTSO`), required for Rosetta-translated guests; `false`
    /// restores AArch64's default weakly-ordered model. The default
    /// implementation is a no-op (non-HVF / test traps have no vCPU register).
    fn set_memory_model(&mut self, tso: bool) -> Result<(), TrapError> {
        let _ = tso;
        Ok(())
    }
    /// Back a dynamic high-VA mmap (`DispatchOutcome::MapHostAlias`): map host
    /// memory at `ipa` and build the VA→IPA stage-1 path. Default error for
    /// non-HVF/test traps (they never emit the outcome).
    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        let _ = (va, ipa, len, payload, file);
        Err(TrapError::UnsupportedPlatform)
    }
}

#[derive(Debug, Error)]
pub enum TrapError {
    #[error("syscall trapping is not available on this platform")]
    UnsupportedPlatform,
    #[error("hypervisor operation failed: {0}")]
    Hypervisor(String),
    /// The signal frame could not be written to the guest's user stack. Linux
    /// `force_sigsegv()`s: the whole guest thread-group dies by SIGSEGV (exit
    /// 139). Signal-delivery callers map this to a term_signal=SIGSEGV
    /// termination instead of propagating a fatal carrick error.
    #[error("signal frame could not be delivered to the guest stack")]
    SignalDeliveryFault,
    #[error("guest mapping size {0} does not fit this host")]
    MappingTooLarge(u64),
    #[error("guest mapping at 0x{guest_start:x} with size {mapped_size} overflows")]
    MappingOverflow { guest_start: u64, mapped_size: u64 },
    #[error("hypervisor exited for an unexpected reason: {reason}")]
    UnexpectedExit { reason: String },
    #[error(
        "guest exception is not an AArch64 SVC trap: syndrome=0x{syndrome:x}, virtual_address=0x{virtual_address:x}, physical_address=0x{physical_address:x}"
    )]
    UnexpectedException {
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    },
    #[error("fork(2) failed: {0}")]
    ForkFailed(String),
    #[error(
        "guest-memory map(host=0x{host_addr:x}, guest=0x{guest_start:x}, size={size}) failed in child: 0x{code:x}"
    )]
    ChildMapFailed {
        host_addr: u64,
        guest_start: u64,
        size: usize,
        code: u32,
    },
    /// An EL0 sync exception other than `svc #0` reached the EL1 vector
    /// trampoline (e.g. instruction abort at PC=0, data abort, undef). Surfaces
    /// the original syndrome/ELR/FAR so the runtime can map it to a Linux signal.
    #[error(
        "EL0 fault not handled by trap path: esr=0x{syndrome:x} elr=0x{elr:x} far=0x{far:x} x16=0x{x16:x} x17=0x{x17:x} x29=0x{x29:x} x30=0x{x30:x} sp=0x{sp:x}"
    )]
    EL0Fault {
        syndrome: u64,
        elr: u64,
        far: u64,
        x16: u64,
        x17: u64,
        x29: u64,
        x30: u64,
        sp: u64,
        from_el0_direct: bool,
    },
}

/// Outcome of `SyscallTrap::fork`. The parent learns the child's PID; the child
/// returns and continues executing with a freshly-rebuilt VM that points at the
/// same host buffers.
#[derive(Debug)]
pub enum ForkOutcome {
    Parent { child_pid: i32 },
    Child,
}
