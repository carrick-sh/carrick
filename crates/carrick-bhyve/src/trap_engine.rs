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
    OsError, RawSyscall, Reg, RegAccess, SysReg, SyscallTrap, TrapError,
    guest_arch::{GuestArch, SyscallRemap, SyscallTable as _},
    x8664_arch::{X8664GuestArch, X8664SyscallTable},
};
use carrick_mem::memory::AddressSpace;

use crate::guest_setup_x86::{BhyveGuestRam, BroughtUpX86, SYSCALL_DOORBELL_PORT, complete_inout};
use crate::vmm::{BhyveVcpu, BhyveVm};
use crate::vmm_x86::{
    VM_REG_GUEST_CS, VM_REG_GUEST_R8, VM_REG_GUEST_R9, VM_REG_GUEST_R10, VM_REG_GUEST_R11,
    VM_REG_GUEST_R12, VM_REG_GUEST_R13, VM_REG_GUEST_R14, VM_REG_GUEST_R15, VM_REG_GUEST_RAX,
    VM_REG_GUEST_RBP, VM_REG_GUEST_RBX, VM_REG_GUEST_RCX, VM_REG_GUEST_RDI, VM_REG_GUEST_RDX,
    VM_REG_GUEST_RFLAGS, VM_REG_GUEST_RIP, VM_REG_GUEST_RSI, VM_REG_GUEST_RSP, X86Exit,
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

    /// Set a raw guest register by ID (delegates to the inner vcpu).
    pub fn set_reg_raw(&mut self, id: std::ffi::c_int, val: u64) -> Result<(), OsError> {
        self.vcpu.set_reg_raw(id, val)
    }

    /// Get a raw guest register by ID.
    pub fn get_reg_raw(&self, id: std::ffi::c_int) -> Result<u64, OsError> {
        self.vcpu.get_reg_raw(id)
    }

    /// Set the FS segment base address (arch_prctl ARCH_SET_FS).
    ///
    /// `vm_set_register(VM_REG_GUEST_FS_BASE)` returns EINVAL — the base is
    /// part of the segment descriptor's hidden state in VT-x (Intel SDM vol. 3
    /// §21.3.1.2); it must be written via `vm_set_desc`.  We read the current
    /// limit and access-rights with `vm_get_desc` and rewrite only the base so
    /// the selector and type stay coherent.  This is the TPIDR_EL0 analogue on
    /// x86_64 (musl uses `ARCH_SET_FS` to install the TLS pointer).
    pub fn set_fs_base(&mut self, addr: u64) -> Result<(), OsError> {
        use crate::vmm_x86::VM_REG_GUEST_FS;
        let (_, limit, access) = self.vcpu.get_desc(VM_REG_GUEST_FS)?;
        self.vcpu.set_desc(VM_REG_GUEST_FS, addr, limit, access)
    }

    /// Get the FS segment base address.
    pub fn get_fs_base(&self) -> Result<u64, OsError> {
        use crate::vmm_x86::VM_REG_GUEST_FS;
        let (base, _, _) = self.vcpu.get_desc(VM_REG_GUEST_FS)?;
        Ok(base)
    }

    /// Set the GS segment base address (arch_prctl ARCH_SET_GS).
    /// Same rationale as [`set_fs_base`].
    pub fn set_gs_base(&mut self, addr: u64) -> Result<(), OsError> {
        use crate::vmm_x86::VM_REG_GUEST_GS;
        let (_, limit, access) = self.vcpu.get_desc(VM_REG_GUEST_GS)?;
        self.vcpu.set_desc(VM_REG_GUEST_GS, addr, limit, access)
    }

    /// Get the GS segment base address.
    pub fn get_gs_base(&self) -> Result<u64, OsError> {
        use crate::vmm_x86::VM_REG_GUEST_GS;
        let (base, _, _) = self.vcpu.get_desc(VM_REG_GUEST_GS)?;
        Ok(base)
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

// ─── arch_prctl FS/GS base (the carrick-hal shared policy calls these) ───────
//
// The bhyve mechanism is vm_get/set_desc on the FS/GS segment descriptor
// (vm_set_register(FS_BASE) returns EINVAL — the base is VT-x hidden state);
// the arch_prctl POLICY is shared with KVM in carrick_hal::x8664_arch.
impl carrick_hal::x8664_arch::SegmentBaseRegs for BhyveTrapEngine {
    fn seg_set_fs_base(&mut self, addr: u64) -> Result<(), TrapError> {
        self.set_fs_base(addr)
            .map_err(|e| TrapError::Hypervisor(format!("vm_set_desc(FS.base): {e}")))
    }

    fn seg_get_fs_base(&self) -> Result<u64, TrapError> {
        self.get_fs_base()
            .map_err(|e| TrapError::Hypervisor(format!("vm_get_desc(FS.base): {e}")))
    }

    fn seg_set_gs_base(&mut self, addr: u64) -> Result<(), TrapError> {
        self.set_gs_base(addr)
            .map_err(|e| TrapError::Hypervisor(format!("vm_set_desc(GS.base): {e}")))
    }

    fn seg_get_gs_base(&self) -> Result<u64, TrapError> {
        self.get_gs_base()
            .map_err(|e| TrapError::Hypervisor(format!("vm_get_desc(GS.base): {e}")))
    }
}

// ─── RegAccess (x86_64 via vm_get/set_register + FS/GS via vm_get/set_desc) ───
//
// Map the ISA-neutral `Reg`/`SysReg` onto bhyve's amd64 `vm_reg_name` ordinals.
// GPRs go through `vm_get/set_register`; FS/GS base reuse the SegmentBaseRegs
// `vm_get/set_desc` path (the base is VT-x hidden state — `vm_set_register` on
// it returns EINVAL). The aarch64 `Reg`/`SysReg` variants never reach this x86
// engine (→ a loud error, mirroring the KVM-x86 RegAccess). FP/SIMD is the one
// gap: FreeBSD 15.1 libvmmapi exposes no FP/XSAVE getter, so the vreg/fp methods
// error — a documented blocker for bhyve signal frames + clone/fork FP snapshot
// (the GPR-driven dispatcher + threading foundation never call them).

/// Map an ISA-neutral [`Reg`] to its bhyve amd64 `vm_reg_name` ordinal.
fn reg_to_vmreg(r: Reg) -> Result<std::ffi::c_int, OsError> {
    Ok(match r {
        Reg::Rax => VM_REG_GUEST_RAX,
        Reg::Rbx => VM_REG_GUEST_RBX,
        Reg::Rcx => VM_REG_GUEST_RCX,
        Reg::Rdx => VM_REG_GUEST_RDX,
        Reg::Rsi => VM_REG_GUEST_RSI,
        Reg::Rdi => VM_REG_GUEST_RDI,
        Reg::Rbp => VM_REG_GUEST_RBP,
        Reg::Rsp => VM_REG_GUEST_RSP,
        Reg::R8 => VM_REG_GUEST_R8,
        Reg::R9 => VM_REG_GUEST_R9,
        Reg::R10 => VM_REG_GUEST_R10,
        Reg::R11 => VM_REG_GUEST_R11,
        Reg::R12 => VM_REG_GUEST_R12,
        Reg::R13 => VM_REG_GUEST_R13,
        Reg::R14 => VM_REG_GUEST_R14,
        Reg::R15 => VM_REG_GUEST_R15,
        Reg::Rip => VM_REG_GUEST_RIP,
        Reg::Rflags => VM_REG_GUEST_RFLAGS,
        other => {
            return Err(OsError::new(format!(
                "bhyve RegAccess: {other:?} is an aarch64 register view on the x86 engine"
            )));
        }
    })
}

impl RegAccess for BhyveTrapEngine {
    fn get_reg(&self, r: Reg) -> Result<u64, OsError> {
        self.vcpu.get_reg_raw(reg_to_vmreg(r)?)
    }

    fn set_reg(&mut self, r: Reg, v: u64) -> Result<(), OsError> {
        self.vcpu.set_reg_raw(reg_to_vmreg(r)?, v)
    }

    fn get_sys_reg(&self, r: SysReg) -> Result<u64, OsError> {
        match r {
            SysReg::FsBase => self.get_fs_base(),
            SysReg::GsBase => self.get_gs_base(),
            other => Err(OsError::new(format!(
                "bhyve RegAccess: SysReg {other:?} unsupported (aarch64 view on the x86 engine)"
            ))),
        }
    }

    fn set_sys_reg(&mut self, r: SysReg, v: u64) -> Result<(), OsError> {
        match r {
            SysReg::FsBase => self.set_fs_base(v),
            SysReg::GsBase => self.set_gs_base(v),
            other => Err(OsError::new(format!(
                "bhyve RegAccess: SysReg {other:?} unsupported (aarch64 view on the x86 engine)"
            ))),
        }
    }

    // FP/SIMD gap: no libvmmapi FP/XSAVE getter on FreeBSD 15.1. Inert until the
    // bhyve signal-frame / FP-snapshot work adds the FFI (or a kernel getter).
    fn get_vreg(&self, _n: u32) -> Result<u128, OsError> {
        Err(OsError::new(
            "bhyve RegAccess: FP/SIMD (XMM) not exposed by libvmmapi".to_string(),
        ))
    }

    fn set_vreg(&mut self, _n: u32, _v: u128) -> Result<(), OsError> {
        Err(OsError::new(
            "bhyve RegAccess: FP/SIMD (XMM) not exposed by libvmmapi".to_string(),
        ))
    }

    fn get_fpcr(&self) -> Result<u64, OsError> {
        Err(OsError::new(
            "bhyve RegAccess: MXCSR not exposed by libvmmapi".to_string(),
        ))
    }

    fn set_fpcr(&mut self, _v: u64) -> Result<(), OsError> {
        Err(OsError::new(
            "bhyve RegAccess: MXCSR not exposed by libvmmapi".to_string(),
        ))
    }

    fn get_fpsr(&self) -> Result<u64, OsError> {
        Err(OsError::new(
            "bhyve RegAccess: x87 status not exposed by libvmmapi".to_string(),
        ))
    }

    fn set_fpsr(&mut self, _v: u64) -> Result<(), OsError> {
        Err(OsError::new(
            "bhyve RegAccess: x87 status not exposed by libvmmapi".to_string(),
        ))
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

                    // arch_prctl(SET/GET FS/GS) is serviced engine-side via the
                    // SHARED carrick-hal policy (FS/GS base = VT-x hidden state set
                    // by vm_set_desc, which the ISA-neutral dispatcher cannot do;
                    // raw x86 158 would also misroute to canonical getgroups=158).
                    // The pending INOUT was stashed above, so complete_syscall
                    // resumes past the doorbell; then re-enter the guest. Identical
                    // to the KVM lane.
                    if x86_number == carrick_hal::x8664_arch::ARCH_PRCTL_X86_NR {
                        let ret =
                            carrick_hal::x8664_arch::service_arch_prctl(self, args[0], args[1])?;
                        self.complete_syscall(ret)?;
                        continue;
                    }

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
