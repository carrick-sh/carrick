//! `BhyveTrapEngine` — the bhyve x86_64 `SyscallTrap` + `GuestMemory` impl.
//!
//! This is the structural analogue of `KvmTrapEngine` in `carrick-linux`, but
//! over the bhyve INOUT vehicle instead of KVM's MMIO sentinel.  A ring-3
//! `SYSCALL` instruction enters the LSTAR stub (`out %al, $0xC5` + `sysretq`),
//! which surfaces as `VM_EXITCODE_INOUT` on port `SYSCALL_DOORBELL_PORT`.
//!
//! # Resume discipline (Experiment 1, T3)
//!
//! bhyve auto-advances the vCPU past a completed INOUT: `vmm.c:1172` records
//! `nextrip = rip + inst_length` at exit time and the next `vm_run` resumes
//! there.  `complete_syscall` therefore reuses `complete_inout` (a no-op) after
//! writing RAX — the analogue of the `SENTINEL_STR_WIDTH` must-not-double-
//! advance discipline in the KVM path.
//!
//! # Syscall number contract
//!
//! `next_syscall` returns **canonical** (aarch64/asm-generic) numbers for
//! `SyscallRemap::Direct` entries — the runtime loop dispatches on these.
//! For `SyscallRemap::Native` (e.g. `arch_prctl`) and `SyscallRemap::Unknown`
//! the raw x86_64 number is returned untranslated; the M1 test loop answers
//! -ENOSYS for unknowns and the plan states `arch_prctl` servicing is M2.

#![cfg(target_arch = "x86_64")]

use carrick_guest_mem::{GuestMemory, MemoryError, X8664SyscallFrame};
use carrick_hal::{
    OsError, RawSyscall, SyscallTrap, TrapError,
    guest_arch::{GuestArch, SyscallRemap, SyscallTable as _},
    x8664_arch::{X8664GuestArch, X8664SyscallTable},
};
use carrick_mem::memory::AddressSpace;

use crate::guest_setup_x86::{BhyveGuestRam, BroughtUpX86, SYSCALL_DOORBELL_PORT, complete_inout};
use crate::vmm::{BhyveVcpu, BhyveVm};
use crate::vmm_x86::{
    VM_REG_GUEST_CS, VM_REG_GUEST_R8, VM_REG_GUEST_R9, VM_REG_GUEST_R10, VM_REG_GUEST_RAX,
    VM_REG_GUEST_RCX, VM_REG_GUEST_RDI, VM_REG_GUEST_RDX, VM_REG_GUEST_RIP, VM_REG_GUEST_RSI,
    X86Exit,
};

/// Pending INOUT state: the vCPU is parked on the `OUT 0xC5` instruction.
/// `complete_syscall` applies the resume discipline once (writing RAX then
/// calling `complete_inout`).
struct PendingInout {
    rip: u64,
    inst_length: u8,
}

/// The bhyve x86_64 syscall trap engine.
///
/// Drives a single vCPU over the INOUT doorbell vehicle.  Phase 2 M1:
/// single-threaded, no fork/execve/signals (those return typed errors).
pub struct BhyveTrapEngine {
    vm: BhyveVm,
    vcpu: BhyveVcpu,
    ram: BhyveGuestRam,
    /// Set when `next_syscall` dequeues an INOUT; cleared by `complete_syscall`.
    pending_inout: Option<PendingInout>,
}

impl BhyveTrapEngine {
    /// Create a trap engine from a fully-brought-up M1 VM.
    pub fn new(bux: BroughtUpX86) -> Self {
        Self {
            vm: bux.vm,
            vcpu: bux.vcpu,
            ram: bux.ram,
            pending_inout: None,
        }
    }

    /// Resolve a guest VA to a host pointer through the `BhyveGuestRam` window
    /// table and the cached `vm_map_gpa` host pointer.
    ///
    /// Returns `(host_ptr, available_bytes_in_window)` or `None` if the VA
    /// does not fall inside any window.
    fn va_to_host(&self, va: u64, len: usize) -> Option<(*mut u8, usize)> {
        for w in &self.ram.windows {
            let w_end = w.va + w.len as u64;
            if va >= w.va && va < w_end {
                let offset = (va - w.va) as usize;
                let avail = w.len.saturating_sub(offset);
                if avail < len {
                    return None; // access straddles window end
                }
                // Resolve through the cached vm_map_gpa pointer.
                let host = self.vm.map_gpa(w.gpa + offset as u64, len)?;
                return Some((host, avail));
            }
        }
        None
    }

    /// Consume the VM (called after the guest exits cleanly).
    pub fn destroy(self) -> Result<(), OsError> {
        self.vm.destroy()
    }
}

impl GuestMemory for BhyveTrapEngine {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let (host, _avail) = self
            .va_to_host(address, length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let mut out = vec![0u8; length];
        // SAFETY: `va_to_host` verified [host, host+length) is within a live
        // vm_map_gpa window; the destination slice is disjoint.
        unsafe { std::ptr::copy_nonoverlapping(host, out.as_mut_ptr(), length) };
        Ok(out)
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let (host, _avail) = self
            .va_to_host(address, length)
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        // SAFETY: `va_to_host` verified [host, host+length) is within a live
        // vm_map_gpa window; the source slice is disjoint.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, length) };
        Ok(())
    }
}

impl SyscallTrap for BhyveTrapEngine {
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        // The LSTAR stub is two instructions: `out %al, $0xC5` (2 bytes) then
        // `sysretq` (3 bytes).  The vCPU parks on the `out` and never reaches
        // `sysretq` (the host resumes PAST the `out` via auto-advance).  Loop
        // to handle `Bogus` re-entries; everything else returns immediately.
        loop {
            match self
                .vcpu
                .run_x86()
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?
            {
                X86Exit::Inout {
                    port: SYSCALL_DOORBELL_PORT,
                    is_in: false,
                    inst_length,
                    rip,
                    ..
                } => {
                    // Batched read: one ioctl for the full syscall register set.
                    // Register order matches the x86_64 syscall ABI
                    // (syscall(2) man7.org): number=RAX, args=RDI,RSI,RDX,R10,R8,R9.
                    // RCX and R11 are the hardware SYSCALL clobbers (RIP/RFLAGS);
                    // they carry no arguments, but we read RCX for diagnostics.
                    let ids = [
                        VM_REG_GUEST_RAX,
                        VM_REG_GUEST_RDI,
                        VM_REG_GUEST_RSI,
                        VM_REG_GUEST_RDX,
                        VM_REG_GUEST_R10,
                        VM_REG_GUEST_R8,
                        VM_REG_GUEST_R9,
                        VM_REG_GUEST_RCX, // the saved RIP (SYSCALL clobber)
                    ];
                    let vals = self
                        .vcpu
                        .get_register_set(&ids)
                        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

                    let frame = X8664SyscallFrame {
                        rax: vals[0],
                        rdi: vals[1],
                        rsi: vals[2],
                        rdx: vals[3],
                        r10: vals[4],
                        r8: vals[5],
                        r9: vals[6],
                    };

                    // Stash the pending INOUT so `complete_syscall` can resume.
                    self.pending_inout = Some(PendingInout { rip, inst_length });

                    // Decode through the GuestArch trait (ISA-neutral number +
                    // args); then remap x86_64 number → canonical.
                    let (x86_number, args) = X8664GuestArch::decode_syscall(&frame);

                    let canonical = match X8664SyscallTable::remap(x86_number) {
                        // Direct: dispatch on the canonical (aarch64/asm-generic)
                        // number — the runtime loop contract.
                        SyscallRemap::Direct(c) => c,
                        // Native (e.g. arch_prctl=158) or Unknown: pass the raw
                        // x86_64 number; the M1 test loop's default arm answers
                        // -ENOSYS and logs the x86_64 name for diagnostics.
                        SyscallRemap::Native | SyscallRemap::Unknown => x86_number,
                    };

                    return Ok(Some(RawSyscall {
                        number: canonical,
                        args,
                    }));
                }

                // Spurious: VT-x re-schedules or the VM is idle — re-enter.
                X86Exit::Bogus => continue,

                // A real `hlt` is the only CLEAN stop (M0 ends this way).
                X86Exit::Hlt => return Ok(None),

                // SUSPENDED is NOT clean — on bhyve it is the empty-IDT
                // fatal-fault funnel (VM_SUSPEND_TRIPLEFAULT=4): a #GP/#PF/#UD
                // with no IDT handler triple-faults and suspends the VM. Report
                // `how` + the RIP/CS where it died so the WRMSR→iretq→ring-3→
                // SYSCALL chain can be debugged (CS low 2 bits = the CPL).
                X86Exit::Suspended { how } => {
                    let rip = self.vcpu.get_reg_raw(VM_REG_GUEST_RIP).unwrap_or(u64::MAX);
                    let cs = self.vcpu.get_reg_raw(VM_REG_GUEST_CS).unwrap_or(u64::MAX);
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve: VM_EXITCODE_SUSPENDED how={how} (4=TRIPLEFAULT) \
                         rip={rip:#x} cs={cs:#x} (cpl={}); the guest faulted with \
                         the empty IDT before reaching a syscall doorbell",
                        cs & 3
                    )));
                }

                // Nested-page fault: the PML4 mapping is wrong or the guest
                // accessed an unmapped VA.  Fatal with a diagnostic.
                X86Exit::Paging {
                    gpa,
                    fault_type,
                    rip,
                } => {
                    // Attempt a PML4 walk for the faulting GPA (best-effort).
                    let walk_msg = {
                        use carrick_mem::pml4::walk_descriptors;
                        let pml4_gpa = crate::guest_setup_x86::X86_PML4_GPA;
                        // Read the PML4 table bytes through the window map.
                        let pml4_size = crate::guest_setup_x86::X86_PML4_CAPACITY;
                        match self
                            .read_bytes(carrick_mem::memory::LINUX_PAGE_TABLES_BASE, pml4_size)
                        {
                            Ok(bytes) => {
                                let walk = walk_descriptors(&bytes, pml4_gpa, gpa);
                                format!(
                                    "PML4 walk for gpa={gpa:#x}: \
                                     L0={:#x} L1={:#x} L2={:#x} L3={:#x}",
                                    walk[0], walk[1], walk[2], walk[3]
                                )
                            }
                            Err(e) => format!("PML4 walk failed: {e}"),
                        }
                    };
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve: VM_EXITCODE_PAGING: gpa={gpa:#x} fault_type={fault_type} \
                         rip={rip:#x}; {walk_msg}"
                    )));
                }

                // Any other exit (RDMSR, WRMSR, VMINSN, …): loud fatal error so
                // a libc surprise is a 5-minute triage, not a silent hang.
                X86Exit::Inout {
                    port, is_in, rip, ..
                } => {
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve: unexpected INOUT on port={port:#x} is_in={is_in} rip={rip:#x} \
                         (only port {SYSCALL_DOORBELL_PORT:#x} is handled)"
                    )));
                }
                X86Exit::Other { code, rip } => {
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve: unhandled exit code={code} rip={rip:#x}"
                    )));
                }
            }
        }
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.vcpu
            .get_reg_raw(VM_REG_GUEST_RIP)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        // Write the syscall return value into RAX (the x86_64 syscall return
        // register, syscall(2) man7.org "Architecture calling conventions").
        self.vcpu
            .set_reg_raw(VM_REG_GUEST_RAX, return_value as u64)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Apply the resume discipline: bhyve auto-advances past a completed
        // INOUT (Experiment 1, T3), so `complete_inout` is a deliberate no-op.
        // The `PendingInout` is consumed here — exactly once per syscall.
        if let Some(p) = self.pending_inout.take() {
            complete_inout(&mut self.vcpu, p.rip, p.inst_length)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        }
        Ok(())
    }

    fn fork(&mut self) -> Result<carrick_hal::ForkOutcome, TrapError> {
        Err(TrapError::Hypervisor(
            "bhyve x86_64: fork is not implemented in Phase 2 (M3; spec N1)".into(),
        ))
    }

    fn execve_into(&mut self, _new_image: &AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "bhyve x86_64: execve is not implemented in Phase 2 (M3; spec N1)".into(),
        ))
    }

    fn inject_signal(
        &mut self,
        _signum: i32,
        _handler: u64,
        _sa_restorer: u64,
        _pending_syscall_retval: Option<i64>,
        _interrupted_pc: Option<u64>,
        _altstack: Option<(u64, u64)>,
        _saved_sigmask: u64,
        _fault_siginfo: Option<(i32, u64)>,
        _queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
        _restart_syscall: bool,
    ) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "bhyve x86_64: inject_signal is not implemented in Phase 2 (M3; spec N2)".into(),
        ))
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        Err(TrapError::Hypervisor(
            "bhyve x86_64: restore_from_sigframe is not implemented in Phase 2 (M3; spec N2)"
                .into(),
        ))
    }
}

// Re-export for the live test (avoids a direct dep on carrick-hal in the test
// binary — the test uses BhyveTrapEngine as a concrete type).
pub use carrick_hal::{RawSyscall as BhyveRawSyscall, TrapError as BhyveTrapError};
