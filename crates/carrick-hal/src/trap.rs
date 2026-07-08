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

use carrick_abi::{CanonicalNr, LinuxSiginfo, NativeNr};
use carrick_guest_mem::{Gpa, GuestVa};
use carrick_mem::memory::AddressSpace;
use thiserror::Error;

use crate::error::OsError;

/// An ISA-neutral decoded syscall: the Linux syscall number plus its six
/// argument registers, already extracted from the per-ISA register frame by the
/// backend's [`crate::GuestArch::decode_syscall`]. `SyscallTrap::next_syscall`
/// returns this (not a raw aarch64 frame) so the runtime loop is ISA-agnostic —
/// the runtime maps it onto its own `SyscallRequest`. The backend keeps reading
/// the raw registers into its `GuestArch::Frame` as before; only the decode
/// moved into the backend (Phase 1, Task 3 of the x86_64 guest-ISA seam).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSyscall {
    /// The CANONICAL (asm-generic/aarch64) syscall number the dispatcher
    /// switches on. Typed [`CanonicalNr`] so it cannot be swapped with
    /// [`native_number`](Self::native_number) at a constructor.
    pub number: CanonicalNr,
    pub args: [u64; 6],
    /// The guest Linux UAPI struct-layout family for this syscall, stamped by
    /// the concrete backend's `GuestArch` at decode time. Carried as DATA (not
    /// inferred at the loop boundary) because `SyscallTrap::next_syscall` is
    /// type-erased over the ISA — a runtime loop generic over `R: SyscallTrap`
    /// (the no-threads / combined Linux loops) has no `Arch` to consult, so the
    /// abi must travel with the decoded syscall. `SyscallRequest::from_raw`
    /// reads it, so a call site cannot forget the guest ABI and mis-marshal
    /// epoll/stat/sigset layouts on the x86 path.
    pub guest_abi: carrick_abi::LinuxGuestAbi,
    /// The guest's *architecture-native* syscall number — what the guest
    /// actually put in its syscall register (`x8` on aarch64, `rax` on x86_64),
    /// BEFORE carrick normalizes it to the canonical aarch64 number in
    /// [`number`](Self::number). For aarch64 guests this equals `number`; for
    /// x86_64 guests it is the x86_64 UAPI number (`write == 1`, not the
    /// canonical `64`), and survives fork/vfork/poll/select desugaring.
    ///
    /// Carried because seccomp(2) filters compare `seccomp_data.nr` against the
    /// guest ISA's native numbering: an x86_64 Docker/libseccomp profile gates
    /// on `arch == AUDIT_ARCH_X86_64` then switches on x86_64 numbers, so the
    /// dispatcher must hand the filter the native number, not the canonical one.
    pub native_number: NativeNr,
}

/// A register/V-reg access through [`crate::RegAccess`] failed mid-sigframe
/// build/restore. The shared builder reports it as a hypervisor error so it can
/// use `?` on `RegAccess` calls (which return [`OsError`]) directly.
impl From<OsError> for TrapError {
    fn from(e: OsError) -> Self {
        TrapError::Hypervisor(format!("sigframe register access: {e}"))
    }
}

/// The trap-engine contract the runtime loop drives: run the vCPU until a
/// syscall trap, complete/inject/restore around guest syscalls and signals,
/// and fork/execve the guest address space. Implemented by `HvfTrapEngine`
/// (macOS), `KvmTrapEngine` (Linux), and the runtime's `SplitView` adapter.
pub trait SyscallTrap {
    /// Run the vCPU until it traps. `Ok(Some(raw))` is a guest syscall, already
    /// decoded to an ISA-neutral [`RawSyscall`] by the backend's
    /// [`crate::GuestArch::decode_syscall`]; `Ok(None)` means the vCPU was forced
    /// out of the guest by a cross-thread kick (`hv_vcpus_exit` / KVM
    /// signal-kick) with no syscall pending — the loop should run signal
    /// delivery and resume. `Err` is a real fault.
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError>;
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
    /// Pre-fork admission gate: verify the host has VM/vCPU capacity for the
    /// CHILD this fork is about to create, BEFORE any VM teardown or
    /// `libc::fork`, so persistent exhaustion (HVF's ~127-VM hard ceiling)
    /// surfaces here — with the parent VM still intact — as
    /// [`TrapError::HostResourceExhausted`], which the runtime's fork arms
    /// degrade to a guest `fork(2) = EAGAIN`. A post-fork rebuild failure
    /// cannot be degraded (the child already exists and the parent VM is
    /// gone), so this gate is the only sound EAGAIN point. Default: no gate
    /// (backends without a hard creation ceiling).
    fn fork_admission_check(&self) -> Result<(), TrapError> {
        Ok(())
    }
    /// `execve(2)` — tear down the current guest address space and
    /// re-initialise this engine with `new_image`. Does NOT advance past a
    /// syscall (execve has no successful return); the next `next_syscall`
    /// resumes at the new image's entry point.
    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError>;
    fn is_forked_child(&self) -> bool {
        false
    }
    /// Called immediately before a forked child process `_exit`s (which skips
    /// every `Drop`). Backends whose VM is NOT released by fd-close must tear it
    /// down here. KVM/HVF: no-op — the VM is fd-lifetime-bound, so closing the
    /// inherited descriptor (or letting the kernel reap it at `_exit`) frees it.
    /// bhyve: the VM is a NAME-bound `/dev/vmm/<name>` node that persists until
    /// `vm_destroy`, so a forked child that `_exit`s without this would LEAK its
    /// node — the bhyve engine overrides this to `vm_destroy` the child VM.
    fn process_exit_cleanup(&mut self) {}
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
    /// memory at `ipa` and build the VA→IPA stage-1 path.
    ///
    /// The dispatcher only emits `DispatchOutcome::MapHostAlias` for engines that
    /// can back a high-VA alias, so reaching this default is a carrick coverage
    /// bug — an engine received an outcome it cannot service — never a recoverable
    /// runtime condition. Fail LOUD at the call site (with the offending
    /// va/ipa/len) instead of returning a soft error that would propagate far
    /// away and surface as a generic "unsupported platform" at process exit,
    /// masking the real cause. An engine that wants this outcome MUST override
    /// the hook (HVF and KVM do).
    fn map_host_alias(
        &mut self,
        va: GuestVa,
        ipa: Gpa,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        let _ = (payload, file);
        let (va, ipa) = (va.raw(), ipa.raw());
        // A genuine, immediate abort (SIGABRT) — the codebase's deterministic
        // failure mechanism (see the panic-backstop note in the workspace
        // Cargo.toml). NOT a `panic!`/`unimplemented!` (both are workspace-denied
        // clippy lints) and NOT a soft `Err`: returning one would propagate far
        // away and surface as a generic "unsupported platform" at process exit,
        // masking the real cause. Aborting here names the offending va/ipa/len at
        // the exact call site.
        eprintln!(
            "carrick: FATAL: SyscallTrap::map_host_alias reached the trait default \
             (va={va:#x} ipa={ipa:#x} len={len:#x}) — this engine emitted a MapHostAlias \
             outcome it cannot service. Implement map_host_alias for this platform."
        );
        std::process::abort()
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
    /// The host ran out of VM/vCPU capacity and stayed exhausted past the
    /// bounded admission wait (HVF's ~127-VM hard ceiling / the ~120-permit
    /// soft budget). Fork-shaped callers degrade this to a guest
    /// `fork(2) = EAGAIN` (via the pre-fork [`SyscallTrap::fork_admission_check`]
    /// gate) instead of a fatal engine abort; other creation paths surface it
    /// as a bounded, loud error instead of parking forever.
    #[error("host VM/vCPU capacity exhausted: {what}")]
    HostResourceExhausted { what: String },
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
    ///
    /// This variant is **aarch64-internal**: the aarch64 engines (HVF, KVM
    /// aarch64) raise it carrying raw `ESR_EL1`, and the runtime loop *lowers* it
    /// to the ISA-neutral [`TrapError::GuestFault`] at the loop boundary (it
    /// resolves the raw ESR to the `(signum, si_code, fault_addr)` triple,
    /// covering both abort and debug classes). x86 backends never raise it; they
    /// emit `GuestFault` directly.
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
    /// carrick's guest took a SYNCHRONOUS exception while the CPU was at EL1.
    /// The guest itself only ever runs at EL0, and carrick's EL1 trampoline is
    /// just `hvc`/`eret`/shim code — so this is always carrick state corruption
    /// (a guest resume that left PSTATE at EL1, e.g. a signal handler entered
    /// with SPSR_EL1=EL1h whose PXN instruction fetch then aborts). The
    /// current-EL synchronous vector slots trap it via `hvc #3` so it FAILS LOUD
    /// here, instead of the guest spinning forever on a bare-`eret` that
    /// re-enters the faulting instruction at 100 % CPU. The raw EL1 fault
    /// registers (ESR/ELR/FAR/SPSR) pin the cause for post-mortem.
    #[error(
        "guest executed at EL1 (carrick state corruption): esr_el1=0x{esr_el1:x} elr_el1=0x{elr_el1:x} far_el1=0x{far_el1:x} spsr_el1=0x{spsr_el1:x}"
    )]
    GuestAtEl1 {
        esr_el1: u64,
        elr_el1: u64,
        far_el1: u64,
        spsr_el1: u64,
    },
    /// An ISA-neutral synchronous guest fault, carrying the **already-resolved**
    /// Linux signal triple (NOT a raw architectural syndrome). The runtime's
    /// fault arm delivers `signum`/`si_code` to the guest with `si_addr =
    /// fault_addr`.
    ///
    /// - aarch64 lowers [`TrapError::EL0Fault`] to this at the loop boundary
    ///   (resolving `ESR_EL1` → SIGSEGV/SIGBUS/SIGTRAP + `si_code`, and
    ///   `fault_addr` from `FAR_EL1`/`ELR_EL1`).
    /// - x86 backends emit it directly, filling `fault_addr` from **CR2** for the
    ///   SIGSEGV `si_addr`.
    #[error("guest fault: signum={signum} si_code={si_code} fault_addr=0x{fault_addr:x}")]
    GuestFault {
        signum: i32,
        si_code: i32,
        fault_addr: u64,
    },
}

impl TrapError {
    /// Build a [`TrapError::EL0Fault`] from the fault info + the EL0 GP-register
    /// snapshot captured at an aarch64 guest fault. The two aarch64 backends read
    /// these off their own vCPU API (HVF applevisor `Reg`/`SysReg`, KVM
    /// `carrick_hal::Reg`) then call this — single-sourcing the 9-field `EL0Fault`
    /// variant shape so a new fault field is added in ONE place, not in every
    /// backend's struct literal. (F7: the shared aarch64 fault-construction seam,
    /// the `Aarch64EngineCore` symmetry to `carrick_x86`.)
    #[allow(clippy::too_many_arguments)]
    pub fn el0_fault(
        syndrome: u64,
        elr: u64,
        far: u64,
        x16: u64,
        x17: u64,
        x29: u64,
        x30: u64,
        sp: u64,
        from_el0_direct: bool,
    ) -> Self {
        TrapError::EL0Fault {
            syndrome,
            elr,
            far,
            x16,
            x17,
            x29,
            x30,
            sp,
            from_el0_direct,
        }
    }
}

/// Outcome of `SyscallTrap::fork`. The parent learns the child's PID; the child
/// returns and continues executing with a freshly-rebuilt VM that points at the
/// same host buffers.
#[derive(Debug)]
pub enum ForkOutcome {
    Parent { child_pid: i32 },
    Child,
}
