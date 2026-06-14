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

use std::sync::Arc;

use carrick_guest_mem::{GuestMemory, MemoryError, X8664SyscallFrame};
use carrick_hal::{OsError, RawSyscall, Reg, RegAccess, SysReg, SyscallTrap, TrapError};
use carrick_mem::memory::AddressSpace;

use crate::guest_setup_x86::{BhyveGuestRam, BroughtUpX86, SYSCALL_DOORBELL_PORT, complete_inout};
use crate::vmm::{BhyveVcpu, BhyveVm};
use crate::vmm_x86::{
    VM_REG_GUEST_CS, VM_REG_GUEST_R8, VM_REG_GUEST_R9, VM_REG_GUEST_R10, VM_REG_GUEST_R11,
    VM_REG_GUEST_R12, VM_REG_GUEST_R13, VM_REG_GUEST_R14, VM_REG_GUEST_R15, VM_REG_GUEST_RAX,
    VM_REG_GUEST_RBP, VM_REG_GUEST_RBX, VM_REG_GUEST_RCX, VM_REG_GUEST_RDI, VM_REG_GUEST_RDX,
    VM_REG_GUEST_RFLAGS, VM_REG_GUEST_RIP, VM_REG_GUEST_RSI, VM_REG_GUEST_RSP, X86Exit,
};

// The canonical clone number + the x86-64 clone arg-swap now live in
// carrick_hal::x8664_arch (defined once, shared with the KVM-x86 lane via
// X8664GuestArch::normalize_syscall).
//
// NOTE (SP1.1): `minherit(INHERIT_COPY)` was evaluated as a way to drop the
// pre-fork heap freeze in `fork()` (let the child copy from a COW-frozen
// inherited mapping). It is NOT used: the spikes proved it freezes only
// USERSPACE writes through the vm_map_gpa pointer, while bhyve's in-kernel vCPU
// writes guest RAM through the wired physical mapping and BYPASS the COW PTE —
// so the resumed parent vCPU still tears the child's image. See the negative
// result documented at the `frozen_ram` site and the `minherit_cow_*` tests.

/// Pending INOUT state: the vCPU is parked on the `OUT 0xC5` instruction.
/// `complete_syscall` applies the resume discipline once (writing RAX then
/// calling `complete_inout`).
#[derive(Debug)]
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
    /// Shared into the `BhyveKickHandle`: `kick()` raises it before the
    /// `pthread_kill`; `next_syscall` clears it on a requested-kick BOGUS exit.
    /// A kick surfaces as `VM_EXITCODE_BOGUS` (thread AST → astpending), NOT
    /// `EINTR`, so this flag is how the engine distinguishes our kick from a
    /// spurious VT-x BOGUS re-entry.
    kick_pending: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set `true` on the child side of a guest `fork(2)` — steers the exit path
    /// (the loop `_exit`s the child, skipping Drops, and calls
    /// `process_exit_cleanup` to destroy the name-bound child VM first). Mirrors
    /// `KvmX86TrapEngine::is_forked_child`.
    is_forked_child: bool,
    /// Set `true` when `self.vm` is a BORROWED view of a VM owned elsewhere — a
    /// vfork child sharing the parent's VM (SP2). A borrowed VM must NOT be torn
    /// down by this engine: `process_exit_cleanup` skips `vm_destroy` when set
    /// (the parent owns the node and resumes on it), and `execve_into`
    /// `mem::forget`s the old borrowed VM on detach instead of destroying it.
    /// Default `false`: `new`/`materialize_sibling`/the fork child all own their
    /// VM. Cleared back to `false` in `execve_into` (the fresh VM is owned).
    vm_borrowed: bool,
}

// SAFETY: BhyveTrapEngine owns one vCPU + one VM-context view + a guest-RAM
// window map, all driven from EXACTLY ONE thread at a time. The generic loop
// moves the engine into its owning thread; sibling vCPUs (Tier 2) are
// constructed on their own threads via materialize_sibling (the raw vmctx/vcpu
// pointers are never dereferenced from two threads at once). Sync is NOT
// implemented (the engine is never shared by reference across threads).
unsafe impl Send for BhyveTrapEngine {}

impl BhyveTrapEngine {
    /// Create a trap engine from a fully-brought-up M1 VM.
    pub fn new(bux: BroughtUpX86) -> Self {
        Self {
            vm: bux.vm,
            vcpu: bux.vcpu,
            ram: bux.ram,
            pending_inout: None,
            kick_pending: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            is_forked_child: false,
            // The main process VM is owned (created by bring_up_x86_elf).
            vm_borrowed: false,
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

                    // Normalize the raw x86-64 syscall via the shared ISA seam:
                    // fork/vfork→clone desugar + clone(220) tls↔child_tid arg-swap
                    // + arch_prctl dispatch all live in carrick_hal::x8664_arch
                    // (one definition shared with the KVM-x86 lane). arch_prctl
                    // (SET/GET FS/GS) is serviced engine-side (FS/GS base = VT-x
                    // hidden state set by vm_set_desc, which the ISA-neutral
                    // dispatcher cannot do; raw x86 158 would also misroute to
                    // canonical getgroups=158). The pending INOUT was stashed
                    // above, so complete_syscall resumes past the doorbell; then
                    // re-enter the guest. Identical to the KVM lane.
                    match carrick_hal::x8664_arch::X8664GuestArch::normalize_syscall(&frame) {
                        carrick_hal::x8664_arch::SyscallNorm::ArchPrctl { code, addr } => {
                            let ret =
                                carrick_hal::x8664_arch::service_arch_prctl(self, code, addr)?;
                            self.complete_syscall(ret)?;
                            continue;
                        }
                        carrick_hal::x8664_arch::SyscallNorm::Plain(raw) => return Ok(Some(raw)),
                    }
                }

                // A kick (pthread_kill → astpending) surfaces as VM_EXITCODE_BOGUS, not
                // EINTR. If WE requested a kick, return to the generic loop so it re-checks
                // pending (signals/futex/quiesce); a spurious VT-x BOGUS just re-enters.
                X86Exit::Bogus => {
                    if self
                        .kick_pending
                        .swap(false, std::sync::atomic::Ordering::SeqCst)
                    {
                        return Ok(None);
                    }
                    continue;
                }

                // A cross-thread kick forced this vCPU out of the guest with no
                // syscall pending. Return Ok(None): the generic loop re-checks
                // signals/futex/quiesce at the interrupted PC, then re-enters.
                // (EINTR path kept as belt-and-suspenders; clear the flag too.)
                X86Exit::Kicked => {
                    self.kick_pending
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                    return Ok(None);
                }

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

    fn is_forked_child(&self) -> bool {
        self.is_forked_child
    }

    fn process_exit_cleanup(&mut self) {
        // bhyve VMs persist as /dev/vmm/<name> until vm_destroy (NOT released by
        // fd-close, unlike KVM). A forked child _exits (skipping Drop), so destroy
        // its VM here to avoid leaking the node. Only meaningful in a forked child
        // (the main process exits via Drop). Safe: this engine is the sole holder
        // of the freshly-created child VM.
        //
        // SP2: a vfork child sharing the parent's VM (vm_borrowed) must NOT
        // destroy it on `_exit` — the parent owns the node and resumes on it
        // after the vfork window. `destroy_in_place` already honors the borrowed
        // handle's `owns=false`, but guard here too so the intent is explicit and
        // a borrowed engine never even calls into the teardown.
        if self.vm_borrowed {
            return;
        }
        self.vm.destroy_in_place();
    }

    fn fork(&mut self) -> Result<carrick_hal::ForkOutcome, TrapError> {
        use crate::guest_setup_x86::{
            PROT_RWX, VM_SEGID_SYSMEM, X86_MEM_SIZE, program_x86_vcpu_longmode_entry,
            snapshot_x86_bhyve,
        };
        use crate::vmm::BhyveVm;

        // Snapshot the parent vCPU BEFORE forking (suspended at the fork doorbell
        // trap — atomic). The parent snapshot: fork inherits everything, so we do
        // NOT seed a new stack/tls (unlike clone-thread). child RIP = parent RCX
        // (the SYSCALL-saved return RIP), child RSP = parent RSP, rax=0.
        //
        // RAX is zeroed in the snapshot HERE (not only via the blob's clear_rax)
        // to mirror the sibling path (`seed_entry_snapshot_bhyve` sets
        // gpr[RAX]=0). At fork-trap time RAX holds the raw x86 fork number (57),
        // and program_x86_vcpu_longmode_entry inherits all 15 GPRs verbatim
        // (including RAX) into the child vCPU before the ring-0 blob runs. Relying
        // solely on the blob's `xor eax,eax` left the child seeing RAX=57 (≠ 0) —
        // it took fork()'s PARENT branch and re-ran wait4 on a bogus pid. Zeroing
        // the snapshot RAX makes the child see fork() → 0 robustly.
        let mut snap =
            snapshot_x86_bhyve(&self.vcpu).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        snap.gpr[crate::guest_setup_x86::GPR_IDX_RAX] = 0;
        let ram = self.ram.clone();

        // Freeze the parent's ENTIRE guest RAM into a private heap buffer BEFORE
        // libc::fork — while the parent vCPU is suspended at the fork doorbell
        // (atomic, no guest writes in flight). The child copies from THIS frozen
        // buffer, NOT from `self.vm.map_gpa` (the parent's LIVE kernel RAM).
        //
        // Why this is mandatory on bhyve (and not on KVM): KVM guest RAM is
        // MAP_PRIVATE|MAP_ANONYMOUS, so libc::fork's copy-on-write hands the child
        // a frozen snapshot of the parent's address space for free. bhyve guest
        // RAM is KERNEL-OWNED (vm_setup_memory) and is NOT copy-on-write across
        // libc::fork — the inherited vmctx aliases the parent's SAME live kernel
        // pages. After libc::fork the parent process resumes its vCPU and runs the
        // post-fork guest code CONCURRENTLY with the child's copy, mutating its
        // stack/heap mid-copy. The child then copied a TORN, already-advanced
        // image: e.g. the musl `syscall()` wrapper's saved return address on the
        // stack had been overwritten by the parent's subsequent calls, so the
        // child's `ret` jumped to the parent's later code (a clean `_exit(0)`)
        // instead of resuming at the post-fork branch — the child silently
        // skipped its own fork-child logic. Snapshotting before the fork closes
        // the race: the child's image is exactly the parent's state at fork time.
        //
        // NEGATIVE RESULT (SP1.1, verified 2026-06-14 on FreeBSD 15.1-RC3): the
        // tempting optimization — `minherit(parent_map_gpa, X86_MEM_SIZE,
        // INHERIT_COPY)` before fork so the child inherits a frozen COW view and
        // copies from its OWN mapping (dropping this heap freeze) — does NOT work
        // for the real guest write path. minherit(INHERIT_COPY) sets COW only on
        // the USERSPACE vm_map entry: a host-side write through the `vm_map_gpa`
        // pointer is frozen for the child (the spikes `minherit_cow_frozen_*` in
        // tests/live_vcpu.rs PASS — child sees the pre-fork sentinel even after a
        // child VM is built). But bhyve's in-kernel vCPU writes guest RAM through
        // the WIRED physical mapping, which BYPASSES the userspace COW PTE, so the
        // resumed parent vCPU's post-fork writes mutate the same physical pages the
        // child's inherited mapping still aliases — COW never breaks for them. With
        // the heap freeze replaced by minherit, BOTH fork acceptance tests
        // (`fork_wait4_runs_to_zero`, `fork_raw_runs_to_zero`) FAILED
        // deterministically (3/3) with a torn child image (`child exit code \0`,
        // garbage wait4 pid) — the original bug. The explicit pre-fork heap freeze
        // is therefore required; the spikes are kept as committed regressions that
        // document the (userspace-only) scope of the COW.
        let frozen_ram: Vec<u8> = {
            let src = self.vm.map_gpa(0, X86_MEM_SIZE).ok_or_else(|| {
                TrapError::Hypervisor("fork: parent map_gpa(0, X86_MEM_SIZE) NULL".to_string())
            })?;
            let mut buf = vec![0u8; X86_MEM_SIZE];
            // SAFETY: `src` spans the full X86_MEM_SIZE-byte parent sysmem segment;
            // the parent vCPU is suspended at the doorbell so no concurrent guest
            // write races this read. `buf` is a fresh, disjoint allocation.
            unsafe { std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), X86_MEM_SIZE) };
            buf
        };

        // The generic loop has quiesced sibling vCPUs (fork barrier); this is the
        // only active thread.
        // SAFETY: libc::fork in a quiesced single-active-thread state.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(TrapError::ForkFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        if pid > 0 {
            // PARENT: live VM untouched; report child pid (loop writes it to RAX).
            return Ok(carrick_hal::ForkOutcome::Parent { child_pid: pid });
        }

        // CHILD. The child inherited the parent's vmctx (self.vm aliases the
        // parent's live kernel RAM — NOT a usable copy source; see the SP1.1
        // negative result above). Build a fresh, uniquely-named VM and copy from
        // the PRE-FORK `frozen_ram` buffer. The child's RAM layout MUST match the
        // parent's so the copy lands at the right GPAs: bring_up_x86_elf sized the
        // parent's sysmem at X86_MEM_SIZE (64 MiB)
        // (total_size().max(X86_MEM_SIZE).min(X86_MEM_SIZE)), so the child uses
        // the same size — NOT ram.total_size() (the bump cursor, which is smaller
        // than the parent's actual segment and would truncate the high windows).
        let mut child_vm = BhyveVm::create().map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        child_vm
            .setup_memory(X86_MEM_SIZE)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        child_vm
            .mmap_memseg(0, VM_SEGID_SYSMEM, X86_MEM_SIZE, PROT_RWX)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Eager full-RAM copy: write the ENTIRE [0, X86_MEM_SIZE) lowmem segment
        // from the PRE-FORK frozen buffer (NOT the parent's now-concurrently-live
        // RAM — see `frozen_ram` above). bhyve maps the whole sysmem segment
        // contiguously at GPA 0, so `vm_map_gpa(0, X86_MEM_SIZE)` resolves a
        // single host pointer spanning all of guest RAM. A full-segment copy is
        // strictly more correct than iterating `ram.windows`: it captures every
        // window PLUS any guest memory the parent dirtied that is not tracked by
        // a window descriptor (e.g. a `brk`/`mmap` region whose VA→GPA window was
        // not registered, or pages between windows). bhyve guest RAM is
        // kernel-owned and NOT COW (unlike KVM), so the copy is mandatory.
        // (A child triple-faulting at rip=0x0 traced to exactly this: the
        // per-window copy left part of the child's stack/heap zeroed, so a `ret`
        // landed on a NULL return address.)
        let dst = child_vm.map_gpa(0, X86_MEM_SIZE).ok_or_else(|| {
            TrapError::Hypervisor("fork: child map_gpa(0, X86_MEM_SIZE) NULL".to_string())
        })?;
        // SAFETY: `frozen_ram` is X86_MEM_SIZE bytes; `dst` is the full
        // X86_MEM_SIZE-byte child sysmem segment; the regions are disjoint
        // (private heap buffer vs the child VM's mapping).
        unsafe { std::ptr::copy_nonoverlapping(frozen_ram.as_ptr(), dst, X86_MEM_SIZE) };
        let _ = &ram; // retained below for self.ram = ram (the child's window view)

        // Program child vCPU 0 for long-mode entry at the post-fork resume.
        let mut child_vcpu = child_vm
            .add_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        program_x86_vcpu_longmode_entry(&mut child_vcpu, &child_vm, &snap, 0)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Swap in the child VM. CRITICAL: the OLD self.vm is the inherited parent
        // alias — its Drop would vm_destroy the PARENT's live kernel VM from the
        // child. mem::forget it (the Arc leaks in this child process, which is
        // correct — the parent's VM stays alive for the still-running parent).
        // Safe to forget the source mapping now: the copy above is complete.
        let inherited_parent = std::mem::replace(&mut self.vm, child_vm);
        std::mem::forget(inherited_parent);
        self.vcpu = child_vcpu; // the old parent vcpu handle has no Drop — harmless
        self.ram = ram;
        self.pending_inout = None; // the fresh child vCPU never hit a doorbell
        self.kick_pending = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.is_forked_child = true;
        // SP1 fork OWNS its freshly-created child VM (child_vm above): its
        // process_exit_cleanup destroys the name-bound node on _exit.
        self.vm_borrowed = false;
        Ok(carrick_hal::ForkOutcome::Child)
    }

    // NOTE: bhyve INTENTIONALLY does NOT override `fork_vfork`; it uses the trait
    // DEFAULT `fork_vfork() → self.fork()` (the fork-COPY above). vfork is thus a
    // fresh, OWNED child VM eagerly copied from the parent — NOT a shared parent
    // VM. True cross-process CLONE_VM (two processes on ONE bhyve VM) was proven
    // EMPIRICALLY infeasible: a borrowed-VM child leaves the parent's `active_cpus`
    // bit permanently set, the suspend rendezvous can't be satisfied, and `vm_run`
    // returns EINVAL. The fork-copy + the generic loop's vfork-pipe parent-suspend
    // (the parent waits until the child execve's/_exit's) is correct for every
    // conforming vfork user (POSIX: the child may only exec/_exit) and matches the
    // KVM x86 lane. See the vfork design-correction section of
    // docs/superpowers/specs/2026-06-14-bhyve-process-model-2-vfork-execve-design.md.
    // Acceptance: the `vfork_exit_runs_to_zero` + `vfork_exec_runs_to_zero` live
    // tests in crates/carrick-runtime/tests/live_bhyve_x86.rs.

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        use crate::guest_setup_x86::bring_up_x86_elf;

        // execve replaces the guest image. Unlike the aarch64 KVM reference
        // (in-place memslot remap on the LIVE VM), bhyve REBUILDS a fresh owned
        // VM from `new_image` and swaps it in — mirroring the HVF lane and the
        // SP1 fork child path. `new_image` was already fully staged by the loop's
        // `load_execve_image`: ELF segments loaded + argv/envp/auxv on the
        // initial stack (with_linux_initial_stack). Extract the entry RIP and the
        // initial RSP exactly as `build_x86_engine` does for the bare run-elf
        // path (the same two accessors).
        let entry_rip = new_image.entry();
        let initial_rsp = new_image.initial_stack_pointer().ok_or_else(|| {
            TrapError::Hypervisor(
                "bhyve execve_into: new_image has no initial stack pointer \
                 (with_linux_initial_stack not applied?)"
                    .to_string(),
            )
        })?;

        // Build the fresh OWNED VM FIRST, so any image/bring-up error surfaces
        // BEFORE we tear down the current image (Linux execve semantics: on
        // failure the caller keeps running its old image). bring_up_x86_elf does
        // the whole job: fresh BhyveVm::create + setup_memory + PML4/GDT/LSTAR/
        // init-blob + the vCPU programmed at the new entry via the ring-0 iretq.
        let bux = bring_up_x86_elf(new_image, entry_rip, initial_rsp)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;

        // Swap in the fresh VM/vCPU/RAM. The fresh VM is already built, so
        // tearing down the OLD one now is safe (nothing references it).
        //
        // Robust-by-construction (Part A): the OLD VM's teardown is gated on its
        // INNER's `owns` flag — a vfork child's borrowed `old_vm` is a distinct
        // `owns == false` inner, so `destroy_in_place` (and a plain drop) are
        // structural no-ops and CANNOT touch the parent's node. A normal process
        // execve's `old_vm` is an owning inner, so `destroy_in_place` runs
        // `vm_destroy` and reclaims the /dev/vmm node. We therefore call
        // `destroy_in_place` unconditionally and let the inner decide — no
        // `vm_borrowed`-keyed `mem::forget` is needed any longer (the borrowed
        // inner is the backstop). `self.vm_borrowed` is asserted here only as a
        // cross-check on the structural verdict.
        let mut old_vm = std::mem::replace(&mut self.vm, bux.vm);
        debug_assert_eq!(
            self.vm_borrowed,
            !old_vm.owns(),
            "execve_into: engine vm_borrowed must match the old VM's inner ownership"
        );
        old_vm.destroy_in_place();
        self.vcpu = bux.vcpu;
        self.ram = bux.ram;
        // The fresh VM from bring_up_x86_elf is OWNED (BhyveVm::create → owns).
        self.vm_borrowed = false;
        // The fresh vCPU never hit a doorbell; start a fresh kick-pending.
        self.pending_inout = None;
        self.kick_pending = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        // Do NOT advance PC: bring_up_x86_elf programmed the new entry (the
        // ring-0 init blob iretqs to entry_rip), so the next `next_syscall`
        // resumes at the new image. Mirrors the aarch64 reference (no PC bump).
        //
        // PRESERVE is_forked_child across execve (matching the aarch64
        // reference, trap_engine.rs ~:959): a vfork child that execve's is still
        // a child process for the loop's exit routing. The flag is a plain field
        // untouched by the swap above — left unchanged deliberately.
        Ok(())
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

/// Send payload for sibling vCPU materialization (clone CLONE_THREAD). Carries
/// the SHARED VM (so the sibling runs in the SAME address space / CR3 / PML4 /
/// guest RAM as the parent), the seeded per-thread register snapshot, and a
/// shared view of the parent's guest RAM. No page tables (x86 shares the parent
/// PML4 via the snapshot's CR3) and no FP (D4: no libvmmapi FP getter; a fresh
/// vCPU gets its own zeroed FP).
pub struct BhyveSiblingSpec {
    vm: crate::vmm::BhyveSharedVm,
    snapshot: crate::guest_setup_x86::X8664BhyveSnapshot,
    /// A clone of the parent's `BhyveGuestRam` window/bump bookkeeping. It owns
    /// no host mappings and has no Drop (the VM owns the kernel RAM via
    /// `vm_destroy`); the materialized sibling re-resolves the SAME GPAs through
    /// the shared ctx, so a plain clone is the correct shared view (see the
    /// `BhyveGuestRam` Clone note).
    ram: crate::guest_setup_x86::BhyveGuestRam,
}

// SAFETY: BhyveSharedVm is already Send+Sync; the snapshot is plain data; the
// RAM payload holds host-window descriptors into the shared guest mapping that
// the materialized engine touches single-threaded. The spec crosses to the new
// thread exactly once.
unsafe impl Send for BhyveSiblingSpec {}

// ─── ThreadedEngine (Tier 2 — real sibling vCPUs on the shared VM) ───────────
//
// Puts bhyve on the canonical run_vcpu_until_exit loop. clone(CLONE_THREAD)
// spawns a sibling vCPU on the SAME VM (shared ctx/CR3/PML4/RAM via
// BhyveSharedVm) — build/materialize_sibling below. fork/execve_into/
// inject_signal/restore_from_sigframe keep their SyscallTrap stubs (M3).
// Mirrors KvmX86TrapEngine's X8664SiblingSpec (bhyve shares RAM instead of
// rebuilding it, has no page-table Arc, and skips FP — D4).
impl carrick_hal::ThreadedEngine for BhyveTrapEngine {
    type Arch = carrick_hal::x8664_arch::X8664GuestArch;
    type KickHandle = crate::bhyve_kicker::BhyveKickHandle;
    type SiblingSpec = BhyveSiblingSpec;

    fn kick_handle(&self) -> Self::KickHandle {
        crate::bhyve_kicker::BhyveKickHandle::for_current_thread(std::sync::Arc::clone(
            &self.kick_pending,
        ))
    }

    fn wait_for_vcpu_slot() {
        // No admission cap (bhyve activates vCPUs eagerly; no HVF-style limit).
    }

    fn build_sibling_spec(
        &self,
        entry: carrick_hal::GuestEntryRegs,
    ) -> Result<Self::SiblingSpec, TrapError> {
        use crate::guest_setup_x86::{seed_entry_snapshot_bhyve, snapshot_x86_bhyve};
        // The parent is suspended at the trapped clone, parked on the LSTAR
        // doorbell `out %al, $0xC5` (2 bytes), with the pending INOUT recorded.
        // The sibling is a FRESH vCPU that never hit the doorbell, so it must be
        // seeded with RIP PAST the `out` (at the following `sysretq`, the
        // 3-byte tail of `entry_trampoline_bytes`), so it `sysretq`s straight
        // into the child's post-clone userspace with RAX=0. Compute that resume
        // RIP from the pending INOUT (robust to the actual trap site):
        //   resume_rip = pending.rip + pending.inst_length  (= rip-after-`out`).
        // Cross-check: this equals the KVM lane's X86_SYSRET_RESUME analogue,
        // LINUX_EL0_TRAMPOLINE_BASE + 2 (the LSTAR VA + the 2-byte `out`); the
        // pending-INOUT form is preferred because it does not assume the trap
        // site, but they agree (inst_length of `out %al,$imm8` is 2).
        let pending = self.pending_inout.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("bhyve build_sibling_spec: no pending doorbell".to_string())
        })?;
        let resume_rip = pending.rip + pending.inst_length as u64;
        // Parent is suspended at the trapped clone → atomic snapshot.
        let parent =
            snapshot_x86_bhyve(&self.vcpu).map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let snapshot = seed_entry_snapshot_bhyve(&parent, entry, resume_rip);
        Ok(BhyveSiblingSpec {
            vm: self.vm.shared_handle(),
            snapshot,
            // Clone the parent's RAM bookkeeping: it owns nothing and has no
            // Drop, and the sibling re-resolves the SAME GPAs through the shared
            // ctx — so a plain clone is the correct shared view.
            ram: self.ram.clone(),
        })
    }

    fn materialize_sibling(spec: Self::SiblingSpec) -> Result<Self, TrapError>
    where
        Self: Sized,
    {
        use crate::guest_setup_x86::program_x86_vcpu_longmode_entry;
        // New vCPU on the SAME VM (shared ctx/CR3/PML4/RAM). add_sibling_vcpu
        // draws a DISTINCT vcpu id from the shared allocator; it must be called
        // BEFORE from_shared consumes spec.vm. We capture the id to carve a
        // per-sibling ring-0 MSR-blob + scratch-stack slot from the post-boot-
        // free init-blob page.
        let (mut vcpu, id) = spec
            .vm
            .add_sibling_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Build a non-owning BhyveVm view of the shared ctx (its own Arc clone,
        // keeping the VM alive while this sibling runs) — needed to write the
        // per-sibling blob into guest RAM via vm_map_gpa.
        let vm = crate::vmm::BhyveVm::from_shared(spec.vm);
        // A fresh sibling from add_sibling_vcpu → vcpu_reset starts in REAL
        // MODE. program_x86_vcpu_longmode_entry replicates the parent's long-mode
        // bring-up (descriptors/GDTR/TR/CR/EFER over the SHARED PML4+GDT),
        // installs the SYSCALL MSRs via a ring-0 WRMSR blob, and iretqs the vCPU
        // into the child's post-clone ring-3 context (RCX, child stack, rax=0).
        // FP is skipped (D4): the snapshot carries no FP; the fresh vCPU's FP is
        // its own (zeroed) state — acceptable for a new thread.
        program_x86_vcpu_longmode_entry(&mut vcpu, &vm, &spec.snapshot, id)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        Ok(Self {
            vm,
            vcpu,
            ram: spec.ram,
            pending_inout: None,
            // Fresh kick-pending for THIS sibling vCPU (its own kick handle).
            kick_pending: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            is_forked_child: false,
            // A sibling holds an owning Arc clone of the shared VM (from_shared);
            // teardown is refcounted via Drop. Not borrowed.
            vm_borrowed: false,
        })
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        self.current_pc()
    }

    fn set_guest_sp_el0(&self, sp: u64) -> Result<(), TrapError> {
        // x86 "SP_EL0" analogue is RSP. The trait hands us &self; use the shared
        // single-reg writer (the engine is single-threaded).
        self.vcpu
            .set_reg_raw_shared(crate::vmm_x86::VM_REG_GUEST_RSP, sp)
            .map_err(|e| TrapError::Hypervisor(format!("set RSP: {e}")))
    }

    fn set_guest_thread_id(&self, _tid: u64) -> Result<(), TrapError> {
        // No in-guest gettid fast path on bhyve (no syscall shim); the dispatcher
        // services gettid. Mirrors the KVM/HVF no-shim path.
        Ok(())
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        Arc::new(crate::bhyve_kicker::BhyveKicker::new())
    }
}

// Re-export for the live test (avoids a direct dep on carrick-hal in the test
// binary — the test uses BhyveTrapEngine as a concrete type).
pub use carrick_hal::{RawSyscall as BhyveRawSyscall, TrapError as BhyveTrapError};
