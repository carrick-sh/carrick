//! The FreeBSD/bhyve x86_64 backend on the shared `carrick-x86` scaffold
//! (portability Stage 4 — the bhyve half).
//!
//! `BhyveVmm` (+ `impl X86Vcpu for BhyveX86Vcpu`) is the thin per-VMM trait pair
//! the generic [`carrick_x86::X86EngineCore`] is parameterized over — mirroring
//! `carrick-vmm-kvm`'s `kvm_x86_engine` and `carrick-vmm-nvmm`'s `nvmm_x86_engine`,
//! not a backend-local trap engine. The trap loop, register
//! walk, guest-memory access, snapshot triple, long-mode bring-up, sigframe
//! glue, and run-elf loop all now live ONCE in `carrick-x86`; this module
//! supplies only the bhyve-specific marshalling and the three quirk seams.
//!
//! ## bhyve answers the three quirk seams with the awkward quadrant (the doctrine)
//!
//!   - `set_syscall_msrs` → [`MsrInstall::NeedsRing0Blob`] (FreeBSD 15.1
//!     libvmmapi has NO MSR ioctl — LSTAR/STAR/SFMASK can only be installed by a
//!     guest ring-0 `WRMSR`). On the bring-up path the shared
//!     `program_longmode_entry` returns this and the caller runs the ring-0
//!     [`carrick_x86::msr_init_blob`]. On the fork/sibling RESTORE path
//!     `set_syscall_msrs` is the LAST call the shared `restore`/`seed` make, so
//!     it is the hook that programs the per-vCPU ring-0 blob + `iretq`-to-RCX
//!     entry (the body of the old `program_x86_vcpu_longmode_entry`).
//!   - `get_fp` → drives the guest-side FXSAVE ring-3 stub
//!     ([`carrick_x86::run_fp_stub`]) and returns `Some(fxsave)` (CPL-0) or
//!     `Some([0; 512])` (CPL-3 async, where `fxsave` would `#UD`). It NEVER
//!     returns `None`: the engine's sigframe `RegAccess` reads
//!     `get_fp()?.ok_or(EIO)?`, so a `None` would break `build_sigframe`.
//!   - `fork_ram_strategy` → [`ForkRamStrategy::EagerCopy`] (kernel-owned,
//!     non-COW guest RAM): `freeze_ram` snapshots the whole segment pre-fork and
//!     `rebuild_child_vm` creates a fresh named child VM + restores the frozen
//!     RAM, then swaps the engine's vCPU to the child's fresh vCPU.
//!
//! ## How the engine's `engine.vcpu` follows a fork's fresh vCPU (the §2.5b seam)
//!
//! `X86EngineCore<V>` holds `vm: V` and `vcpu: V::Vcpu` as SEPARATE fields, and
//! the shared `fork_x86` re-seeds the EXISTING `engine.vcpu` via `restore` after
//! the child rebuilds its VM. But bhyve's EagerCopy fork needs a DIFFERENT vCPU
//! object on a DIFFERENT `/dev/vmm` node. So `BhyveX86Vcpu` and `BhyveVmm` share
//! one `VcpuHandle` (an `Arc`): the raw `*mut Vcpu` lives in an `AtomicPtr`
//! there, and `rebuild_child_vm` (which runs in the forked child with `&mut
//! self.vm`) swaps the pointer + the child's `BhyveSharedVm`/`id` INSIDE the
//! shared handle. Because `engine.vcpu` shares the same `Arc<VcpuHandle>`, its
//! subsequent `restore`/run transparently drive the child's fresh vCPU. This is
//! a trait-only solution (no `carrick-x86` change): the swap is interior to the
//! handle the two engine fields share.

#![cfg(target_arch = "x86_64")]

use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex};

use carrick_abi::LinuxProtFlags;
use carrick_guest_mem::MemoryError;
use carrick_hal::GuestVmBackend;
use carrick_hal::OsError;
use carrick_hal::TrapError;
use carrick_mem::memory::AddressSpace;
use carrick_mem::pml4::Pml4Manager;
use carrick_x86::{
    BringupLayout, ForkRamStrategy, MsrInstall, WindowPlan, X86EngineCore, X86Exit, X86Reg, X86Seg,
    X86Vcpu, X86Vmm,
};

use crate::bhyve_kicker::{BhyveKickHandle, BhyveKicker};
use crate::guest_setup_x86::{
    ACCESS_RING3_CS64, ACCESS_RING3_SS, BhyveGuestRam, BroughtUpX86, CommitOutcome,
    FAULT_DOORBELL_PORT, FP_STUB_DOORBELL_PORT, FaultScratchRecord, PROT_RWX,
    SYSCALL_DOORBELL_PORT, USER_CS64_SEL, USER_SS_SEL, VM_SEGID_SYSMEM, X86_FP_SCRATCH_GPA,
    X86_FP_STUB_GPA, X86_GDT_GPA, X86_MEM_SIZE, X86_PML4_CAPACITY, X86_PML4_GPA, bring_up_x86_elf,
    fault_scratch_gpa, fault_scratch_record_from_bytes, fault_stack_frame_len,
    fault_user_context_from_bytes, program_x86_vcpu_longmode_entry, snapshot_x86_bhyve,
};
use crate::vmm::{BhyveSharedVm, BhyveVcpu, BhyveVm, Vcpu};
use crate::vmm_x86::{
    BhyveVmExit as NativeExit, VM_CAP_HALT_EXIT, VM_REG_GUEST_CR0, VM_REG_GUEST_CR2,
    VM_REG_GUEST_CR3, VM_REG_GUEST_CR4, VM_REG_GUEST_CS, VM_REG_GUEST_DS, VM_REG_GUEST_EFER,
    VM_REG_GUEST_ES, VM_REG_GUEST_FS, VM_REG_GUEST_GS, VM_REG_GUEST_R8, VM_REG_GUEST_R9,
    VM_REG_GUEST_R10, VM_REG_GUEST_R11, VM_REG_GUEST_R12, VM_REG_GUEST_R13, VM_REG_GUEST_R14,
    VM_REG_GUEST_R15, VM_REG_GUEST_RAX, VM_REG_GUEST_RBP, VM_REG_GUEST_RBX, VM_REG_GUEST_RCX,
    VM_REG_GUEST_RDI, VM_REG_GUEST_RDX, VM_REG_GUEST_RFLAGS, VM_REG_GUEST_RIP, VM_REG_GUEST_RSI,
    VM_REG_GUEST_RSP, VM_REG_GUEST_SS,
};
use crate::vmm_x86::{VM_REG_GUEST_GDTR, VM_REG_GUEST_IDTR};

/// The bhyve x86 kernel-window GPA layout (the §2.5a/`BringupLayout` per-backend
/// choice). bhyve folds the trampoline/GDT/PML4 into its single contiguous
/// lowmem segment at the fixed GPAs the bring-up has always used.
pub const BHYVE_X86_LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
    gdt_base: X86_GDT_GPA,
    pml4_base: X86_PML4_GPA,
};

/// The per-thread CPU registers captured/restored across an M:N reclaim re-bind:
/// the 16 GPRs + RIP + RFLAGS. Process-wide control regs (CR0/3/4, EFER, CS) are
/// NOT included — identical across the process's threads, they persist on the
/// recycled vCPU (which `reopen_vcpu` does NOT reset). FS/GS base (TLS) is saved
/// separately via the segment descriptor. (FP/AVX is a follow-up increment.)
const SNAPSHOT_REGS: [c_int; 18] = [
    VM_REG_GUEST_RAX,
    VM_REG_GUEST_RBX,
    VM_REG_GUEST_RCX,
    VM_REG_GUEST_RDX,
    VM_REG_GUEST_RSI,
    VM_REG_GUEST_RDI,
    VM_REG_GUEST_RBP,
    VM_REG_GUEST_RSP,
    VM_REG_GUEST_R8,
    VM_REG_GUEST_R9,
    VM_REG_GUEST_R10,
    VM_REG_GUEST_R11,
    VM_REG_GUEST_R12,
    VM_REG_GUEST_R13,
    VM_REG_GUEST_R14,
    VM_REG_GUEST_R15,
    VM_REG_GUEST_RIP,
    VM_REG_GUEST_RFLAGS,
];

// ─── VcpuHandle: the shared, swappable per-vCPU runtime state ─────────────────

/// The mutable runtime identity of a bhyve vCPU, shared (via `Arc`) between the
/// engine's `vcpu: BhyveX86Vcpu` field and its `vm: BhyveVmm` field so a fork's
/// `rebuild_child_vm` can swap the live vCPU underneath BOTH at once (§2.5b).
///
/// The raw `*mut Vcpu` is an `AtomicPtr` (read lock-free on every register
/// access). The `BhyveSharedVm`/`id`/FP-GPAs are only consulted on the rare
/// blob-write / FP-stub / fork paths, behind a `Mutex`.
struct VcpuHandle {
    /// The live libvmmapi vCPU handle. Swapped by `rebuild_child_vm` (fork) to
    /// the child VM's fresh vCPU; read by every register access.
    vcpu: AtomicPtr<Vcpu>,
    /// The VM (shared ctx) this vCPU belongs to — used to `vm_map_gpa` the
    /// per-vCPU ring-0 MSR blob (`set_syscall_msrs` restore hook) and the FP
    /// scratch page. Swapped to the child VM on fork.
    slot: Mutex<VcpuSlot>,
    /// Set by `kick()` before the `pthread_kill`; cleared by `run()` on a
    /// requested-kick BOGUS exit (the BhyveKickHandle ↔ run() contract).
    kick_pending: Arc<AtomicBool>,
    /// `false` until this vCPU has trapped at a real syscall doorbell at least
    /// once — i.e. it is past the ring-0 init blob and genuinely running ring-3
    /// guest code. The FP stub (`get_fp`/`set_fp`) requires a fully-running
    /// long-mode vCPU, so it is gated on this: a fork-child / clone-sibling vCPU
    /// re-seeded by `restore` is NOT yet runnable when `restore` calls `set_fp`
    /// (it still has to run its blob iretq), and a freshly-`vcpu_reset` vCPU does
    /// not reliably read back its CS DPL — so a CPL check alone would mis-fire and
    /// drive the FXRSTOR stub on an unprogrammed vCPU. Cleared on fork/execve
    /// re-seed; set in `run()` on the first SYSCALL doorbell.
    started: AtomicBool,
    /// Set `true` by the `set_syscall_msrs` restore hook (fork child / clone
    /// sibling), which programs the vCPU's RIP to the ring-0 MSR-init blob entry.
    /// The shared engine's `complete_syscall` (called by the run loop AFTER fork
    /// to write the child's `fork()` → 0 return value) unconditionally re-points
    /// RIP at `pending_resume_pc` (the SYSRETQ trampoline) — correct for a `Cow`
    /// backend whose child inherits live MSRs, but FATAL for bhyve: it would
    /// override the blob entry, so the un-installed (zero) STAR makes the first
    /// SYSRET load CS=0x13 → triple-fault. This flag makes the NEXT `set_gpr(Rip,
    /// _)` a no-op (consuming the flag), so `complete_syscall`'s RIP override is
    /// skipped and the child runs its ring-0 blob (which installs the MSRs then
    /// iretqs to the post-fork RIP). One-shot: it protects exactly that single
    /// spurious RIP write.
    fork_entry_pending: AtomicBool,
}

/// The mutex-guarded part of [`VcpuHandle`] (consulted only off the hot path).
struct VcpuSlot {
    /// The VM whose guest RAM the ring-0 blob + FP scratch live in.
    vm: BhyveSharedVm,
    /// This vCPU's id → per-vCPU ring-0 blob slot (`X86_INIT_BLOB_GPA + id*256`)
    /// and FP scratch slot (`X86_FP_SCRATCH_GPA + id*0x1000`).
    id: c_int,
}

impl VcpuHandle {
    fn raw(&self) -> *mut Vcpu {
        self.vcpu.load(Ordering::SeqCst)
    }

    /// Lock the slot, recovering the guard if a prior panic poisoned it (no
    /// `unwrap`/`expect`: the workspace lints deny them, and a poisoned slot is
    /// still consistent data — only the vCPU pointer/id, swapped atomically).
    fn slot(&self) -> std::sync::MutexGuard<'_, VcpuSlot> {
        self.slot.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A `BhyveVcpu` view over the current raw handle (for the inherent
    /// register/desc/run helpers in `vmm`/`vmm_x86`, which take a `BhyveVcpu`).
    fn as_bhyve(&self) -> BhyveVcpu {
        BhyveVcpu { vcpu: self.raw() }
    }
}

// SAFETY: the raw vCPU handle is a kernel object usable from the one thread that
// owns this engine at a time; the engine is `Send` but never `Sync` (the same
// vCPU is never driven from two threads concurrently). The atomic/mutex make the
// fork-time swap well-defined.
unsafe impl Send for VcpuHandle {}
unsafe impl Sync for VcpuHandle {}

// ─── BhyveX86Vcpu (the X86Vmm::Vcpu) ─────────────────────────────────────────

/// The per-vCPU register/run surface the generic engine drives. A thin `Arc`
/// over `VcpuHandle` (so the engine's `vm` and `vcpu` fields can share, and
/// swap, one live vCPU on fork).
///
/// `Clone` clones the `Arc` only — all clones drive the SAME underlying vCPU.
/// This is how `get_fp(&self)` obtains a `&mut Self` for the FXSAVE stub
/// ([`carrick_x86::run_fp_stub`] takes `&mut C`) WITHOUT an `&self`→`&mut self`
/// cast: a fresh owned clone drives the same vCPU (all mutation is through the
/// raw `*mut Vcpu` behind the shared handle, never through `Self`'s fields).
#[derive(Clone)]
pub struct BhyveX86Vcpu {
    h: Arc<VcpuHandle>,
}

impl BhyveX86Vcpu {
    fn reg_err(e: OsError) -> TrapError {
        TrapError::Hypervisor(e.to_string())
    }

    /// Read a raw amd64 `vm_reg_name` ordinal through the (current) live vCPU.
    fn get_raw(&self, id: c_int) -> Result<u64, TrapError> {
        self.h.as_bhyve().get_reg_raw(id).map_err(Self::reg_err)
    }

    /// Write a raw amd64 `vm_reg_name` ordinal through the (current) live vCPU.
    fn set_raw(&self, id: c_int, v: u64) -> Result<(), TrapError> {
        // `set_reg_raw` is `&mut self` on BhyveVcpu; the handle is single-thread
        // owned, so a fresh BhyveVcpu view is safe to mutate.
        let mut v_cpu = self.h.as_bhyve();
        v_cpu.set_reg_raw(id, v).map_err(Self::reg_err)
    }

    fn set_desc(&self, reg: c_int, base: u64, limit: u32, access: u32) -> Result<(), TrapError> {
        let mut v_cpu = self.h.as_bhyve();
        v_cpu
            .set_desc(reg, base, limit, access)
            .map_err(Self::reg_err)
    }

    fn get_desc(&self, reg: c_int) -> Result<(u64, u32, u32), TrapError> {
        self.h.as_bhyve().get_desc(reg).map_err(Self::reg_err)
    }

    /// Reload the ring-3 user segment selectors + hidden descriptors on the live
    /// vCPU, reproducing the state a `sysretq`/`iretq` to user space would latch
    /// (CS=0x23/DPL3/L, SS/DS/ES=0x1B/DPL3, base=0, 4 GiB flat). Called from the
    /// fault-doorbell path: taking a guest #PF through the IDT gate latched the
    /// ring-0 kernel CS into the live VMCS, so a fault that resumes in ring-3
    /// (demand-commit re-run or a delivered signal) must restore the user segments
    /// first. The shared `restore_user_after_fault`→`program_user_segments` does
    /// this for KVM/NVMM, but bhyve's `X86Vcpu::set_segment` is an intentional
    /// no-op (the fork/clone iretq-blocker), so the fault path restores them here
    /// — base/limit/AR via `set_desc`, the selector via `set_reg_raw`. FS/GS are
    /// NOT touched (their TLS base is independent guest state). This is the same
    /// descriptor encoding `program_x86_vcpu_longmode_entry`'s iretq frame produces.
    fn restore_ring3_segments(&self) -> Result<(), TrapError> {
        self.set_desc(VM_REG_GUEST_CS, 0, 0xFFFF_FFFF, ACCESS_RING3_CS64)?;
        self.set_raw(VM_REG_GUEST_CS, USER_CS64_SEL)?;
        for reg in [VM_REG_GUEST_SS, VM_REG_GUEST_DS, VM_REG_GUEST_ES] {
            self.set_desc(reg, 0, 0xFFFF_FFFF, ACCESS_RING3_SS)?;
            self.set_raw(reg, USER_SS_SEL)?;
        }
        Ok(())
    }

    fn set_cap(&self, cap: c_int, val: c_int) -> Result<(), TrapError> {
        let mut v_cpu = self.h.as_bhyve();
        v_cpu.set_capability(cap, val).map_err(Self::reg_err)
    }

    /// Write `bytes` into guest physical memory at `gpa` via the (current) VM.
    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        let slot = self.h.slot();
        let vm = BhyveVm::from_shared(slot.vm.clone());
        let host = vm.map_gpa(gpa, bytes.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!("bhyve-x86: write_gpa 0x{gpa:x} unmapped"))
        })?;
        // SAFETY: map_gpa proved [host, host+len) is a live guest-RAM window.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len()) };
        Ok(())
    }

    /// Read `len` bytes of guest physical memory at `gpa` via the (current) VM.
    fn read_gpa(&self, gpa: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        let slot = self.h.slot();
        let vm = BhyveVm::from_shared(slot.vm.clone());
        let host = vm.map_gpa(gpa, len).ok_or_else(|| {
            TrapError::Hypervisor(format!("bhyve-x86: read_gpa 0x{gpa:x} unmapped"))
        })?;
        let mut out = vec![0u8; len];
        // SAFETY: map_gpa proved [host, host+len) is a live guest-RAM window.
        unsafe { std::ptr::copy_nonoverlapping(host, out.as_mut_ptr(), len) };
        Ok(out)
    }

    /// Walk the guest's 4-level page tables to translate a guest VA → GPA.
    /// A fault frame is at the guest RSP, which is GPA-identity only for a
    /// ring-3 fault landing on the low RSP0 fault stack; a ring-0 stub fault
    /// leaves RSP on the (non-identity, window-mapped) user/goroutine stack,
    /// where `read_gpa`'s direct mapping is wrong. Handles 2 MiB / 1 GiB pages.
    fn translate_va(&self, va: u64) -> Result<u64, TrapError> {
        const PTE_ADDR: u64 = 0x000F_FFFF_FFFF_F000;
        let rd = |table_gpa: u64, idx: usize| -> Result<u64, TrapError> {
            let b = self.read_gpa(table_gpa + (idx as u64) * 8, 8)?;
            let octet: [u8; 8] = b.try_into().map_err(|_| {
                TrapError::Hypervisor(format!(
                    "translate_va: short read for PTE at gpa 0x{:x}",
                    table_gpa + (idx as u64) * 8
                ))
            })?;
            Ok(u64::from_le_bytes(octet))
        };
        let e4 = rd(X86_PML4_GPA, ((va >> 39) & 0x1FF) as usize)?;
        let nx = |lvl: &str| TrapError::Hypervisor(format!("translate_va 0x{va:x}: {lvl} absent"));
        if e4 & 1 == 0 {
            return Err(nx("PML4E"));
        }
        let e3 = rd(e4 & PTE_ADDR, ((va >> 30) & 0x1FF) as usize)?;
        if e3 & 1 == 0 {
            return Err(nx("PDPTE"));
        }
        if e3 & (1 << 7) != 0 {
            return Ok((e3 & 0x000F_FFFF_C000_0000) + (va & 0x3FFF_FFFF)); // 1 GiB page
        }
        let e2 = rd(e3 & PTE_ADDR, ((va >> 21) & 0x1FF) as usize)?;
        if e2 & 1 == 0 {
            return Err(nx("PDE"));
        }
        if e2 & (1 << 7) != 0 {
            return Ok((e2 & 0x000F_FFFF_FFE0_0000) + (va & 0x1F_FFFF)); // 2 MiB page
        }
        let e1 = rd(e2 & PTE_ADDR, ((va >> 12) & 0x1FF) as usize)?;
        if e1 & 1 == 0 {
            return Err(nx("PTE"));
        }
        Ok((e1 & PTE_ADDR) + (va & 0xFFF))
    }

    /// Read `len` bytes at a guest VA, translating page-by-page (a fault frame
    /// can straddle a page boundary).
    fn read_va(&self, va: u64, len: usize) -> Result<Vec<u8>, TrapError> {
        let mut out = vec![0u8; len];
        let mut off = 0usize;
        while off < len {
            let cur = va + off as u64;
            let gpa = self.translate_va(cur)?;
            let n = ((0x1000 - (cur & 0xFFF)) as usize).min(len - off);
            let chunk = self.read_gpa(gpa, n)?;
            out[off..off + n].copy_from_slice(&chunk);
            off += n;
        }
        Ok(out)
    }

    fn fp_scratch_gpa(&self) -> u64 {
        let id = self.h.slot().id;
        X86_FP_SCRATCH_GPA + (id as u64) * 0x1000
    }
}

/// Map an `X86Reg` to its bhyve amd64 `vm_reg_name` ordinal.
fn x86reg_to_vmreg(reg: X86Reg) -> c_int {
    match reg {
        X86Reg::Rax => VM_REG_GUEST_RAX,
        X86Reg::Rbx => VM_REG_GUEST_RBX,
        X86Reg::Rcx => VM_REG_GUEST_RCX,
        X86Reg::Rdx => VM_REG_GUEST_RDX,
        X86Reg::Rsi => VM_REG_GUEST_RSI,
        X86Reg::Rdi => VM_REG_GUEST_RDI,
        X86Reg::Rbp => VM_REG_GUEST_RBP,
        X86Reg::Rsp => VM_REG_GUEST_RSP,
        X86Reg::R8 => VM_REG_GUEST_R8,
        X86Reg::R9 => VM_REG_GUEST_R9,
        X86Reg::R10 => VM_REG_GUEST_R10,
        X86Reg::R11 => VM_REG_GUEST_R11,
        X86Reg::R12 => VM_REG_GUEST_R12,
        X86Reg::R13 => VM_REG_GUEST_R13,
        X86Reg::R14 => VM_REG_GUEST_R14,
        X86Reg::R15 => VM_REG_GUEST_R15,
        X86Reg::Rip => VM_REG_GUEST_RIP,
        X86Reg::Rflags => VM_REG_GUEST_RFLAGS,
        X86Reg::Cr0 => VM_REG_GUEST_CR0,
        X86Reg::Cr2 => VM_REG_GUEST_CR2,
        X86Reg::Cr3 => VM_REG_GUEST_CR3,
        X86Reg::Cr4 => VM_REG_GUEST_CR4,
        X86Reg::Efer => VM_REG_GUEST_EFER,
    }
}

impl X86Vcpu for BhyveX86Vcpu {
    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        self.get_raw(x86reg_to_vmreg(reg))
    }

    fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError> {
        // Suppress the ONE spurious RIP override that the shared
        // `complete_syscall` issues right after a fork/clone-restore: it would
        // re-point RIP at the SYSRETQ trampoline, clobbering the ring-0 MSR-blob
        // entry `set_syscall_msrs` just programmed (→ STAR=0 → CS=0x13 triple
        // fault). The flag is one-shot and protects exactly this write; every
        // other RIP write (including the engine's own resume on later syscalls)
        // proceeds normally.
        if reg == X86Reg::Rip && self.h.fork_entry_pending.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        self.set_raw(x86reg_to_vmreg(reg), v)
    }

    fn get_gprs(&self, regs: &[X86Reg], out: &mut [u64]) -> Result<(), TrapError> {
        // One `VM_GET_REGISTER_SET` ioctl for the whole slice (the shared
        // `complete_sysret` fetches RCX+R11 together) instead of one
        // `vm_get_register` per register.
        let ids: Vec<c_int> = regs.iter().map(|&r| x86reg_to_vmreg(r)).collect();
        let vals = self
            .h
            .as_bhyve()
            .get_register_set(&ids)
            .map_err(Self::reg_err)?;
        for (slot, v) in out.iter_mut().zip(vals) {
            *slot = v;
        }
        Ok(())
    }

    fn set_gprs(&mut self, writes: &[(X86Reg, u64)]) -> Result<(), TrapError> {
        // One `VM_SET_REGISTER_SET` ioctl for the slice (the shared
        // `complete_sysret` writes RAX+RIP together). Preserve the one-shot
        // fork-entry RIP suppression from `set_gpr`: if a RIP write is pending
        // suppression, drop it from the batch so it cannot clobber the ring-0
        // MSR-blob entry after a fork/clone-restore.
        let suppress_rip = writes.iter().any(|(r, _)| *r == X86Reg::Rip)
            && self.h.fork_entry_pending.swap(false, Ordering::SeqCst);
        let mut ids: Vec<c_int> = Vec::with_capacity(writes.len());
        let mut vals: Vec<u64> = Vec::with_capacity(writes.len());
        for (r, v) in writes {
            if *r == X86Reg::Rip && suppress_rip {
                continue;
            }
            ids.push(x86reg_to_vmreg(*r));
            vals.push(*v);
        }
        if ids.is_empty() {
            return Ok(());
        }
        self.h
            .as_bhyve()
            .set_register_set(&ids, &vals)
            .map_err(Self::reg_err)
    }

    fn set_segment(
        &mut self,
        _seg: X86Seg,
        _base: u64,
        _limit: u32,
        _ar: u32,
    ) -> Result<(), TrapError> {
        // INTENTIONAL NO-OP on bhyve. The ONLY caller of `set_segment` is the
        // shared `restore` (fork child / clone sibling) — bhyve's `bring_up` uses
        // `bring_up_x86_elf` directly, not the shared `program_longmode_entry`. On
        // a fresh `vcpu_reset` (real-mode) child, programming the segments to a
        // DPL-3 ring-3 CS here (what `restore` does, correct for KVM/NVMM direct
        // ring-3 entry) and THEN re-programming them to ring-0 for the MSR-blob
        // iretq entry leaves a hidden VMCS inconsistency vmm.ko does not reconcile
        // (the documented M1 iretq blocker): the iretq then does an INTRA-priv
        // return (RSP not popped, CS=0x13) → triple-fault deep in libc. So bhyve
        // does NOT let `restore` touch the segments: the segment + GDTR/IDTR/TR/
        // LDTR state is programmed EXACTLY ONCE, in `set_syscall_msrs` (the LAST
        // `restore` call) via the proven `program_x86_vcpu_longmode_entry` — the
        // same single-shot bring-up the old engine used. The snapshot that hook
        // builds reads GPRs / FS-GS bases / control regs (which `restore`'s
        // `set_gpr`/`set_fs_base` DO set), never the segment selectors, so the
        // no-op here loses nothing.
        Ok(())
    }

    /// Restore ring-3 user segments on the LIVE vCPU (fault/signal RESUME paths).
    /// The shared default goes through `set_segment`, which is the no-op above, so
    /// bhyve OVERRIDES it to program the selectors + hidden descriptors directly
    /// (`vm_set_register`/`vm_set_desc`). This is the legitimate counterpart to the
    /// fork/clone `set_segment` no-op: the fork/clone iretq bring-up must NOT touch
    /// the live segments, but a synchronous-fault/`rt_sigreturn` resume MUST, or
    /// the resumed user code runs supervisor (and the next fault, saved CS=ring-0,
    /// trips the ring-0 fault guard → fatal). Without this, a Rust binary whose std
    /// SIGSEGV handler returns into a still-faulting instruction (mmap NX violation,
    /// unmapped mremap tail) re-runs that instruction in ring-0 instead of taking
    /// the clean default-disposition SIGSEGV.
    fn restore_user_segments(&mut self) -> Result<(), TrapError> {
        self.restore_ring3_segments()
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        // FS.base is VT-x hidden descriptor state: read via vm_get_desc (the
        // base field), NOT vm_get_register (which returns EINVAL on the base).
        Ok(self.get_desc(VM_REG_GUEST_FS)?.0)
    }

    fn set_fs_base(&mut self, v: u64) -> Result<(), TrapError> {
        let (_, limit, access) = self.get_desc(VM_REG_GUEST_FS)?;
        self.set_desc(VM_REG_GUEST_FS, v, limit, access)
    }

    fn get_gs_base(&self) -> Result<u64, TrapError> {
        Ok(self.get_desc(VM_REG_GUEST_GS)?.0)
    }

    fn set_gs_base(&mut self, v: u64) -> Result<(), TrapError> {
        let (_, limit, access) = self.get_desc(VM_REG_GUEST_GS)?;
        self.set_desc(VM_REG_GUEST_GS, v, limit, access)
    }

    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError> {
        // bhyve has NO MSR ioctl. For bhyve, `set_syscall_msrs` is ONLY ever
        // reached via the shared `restore`/`seed_entry` (fork child / clone
        // sibling) — the initial `bring_up` uses `bring_up_x86_elf` directly and
        // never calls the shared `program_longmode_entry`. So this ALWAYS runs the
        // restore path: it is the LAST call `restore` makes (after every GPR /
        // segment / CR / base is on the vCPU), so it transplants the restored
        // ring-3 state into a ring-0 MSR-blob `iretq` entry — the body of the old
        // `program_x86_vcpu_longmode_entry`.
        //
        // (Earlier a CS-DPL-3 guard tried to distinguish bring-up from restore,
        // but a freshly `vcpu_reset` child does NOT reliably read back CS DPL=3
        // after `restore`'s `set_segment`, so the guard wrongly skipped the blob —
        // leaving STAR=0 → the next SYSRET loaded CS=0x13 → a deep-libc
        // triple-fault. There is no bring-up caller to disambiguate from, so the
        // guard is removed.)
        // Snapshot the just-`restore`d vCPU state and hand it to the PROVEN
        // `program_x86_vcpu_longmode_entry` — the EXACT function the old engine's
        // fork/sibling used. It reads `snap.gpr[RCX]` (the post-SYSCALL return RIP
        // `restore` carried verbatim), `snap.rsp`, the FS/GS bases, CR0/CR3/CR4/
        // EFER and the 15 GPRs, then writes the per-vCPU ring-0 WRMSR blob and
        // overrides the segments/RIP/RSP for the ring-0 blob entry that iretqs to
        // ring-3 at RCX with rax=0. Re-using the verified function (rather than a
        // hand-rolled inline copy) eliminates any subtle divergence in the
        // long-mode descriptor / iretq-frame sequence. The `lstar`/`star`/`sfmask`
        // restore passes here equal `bootstrap_sysregs()` (the same values the
        // function bakes into the blob), so the blob is byte-identical.
        let _ = (lstar, star, sfmask);
        let id = self.h.slot().id;
        let vm = BhyveVm::from_shared(self.h.slot().vm.clone());
        let snap = snapshot_x86_bhyve(&self.h.as_bhyve()).map_err(Self::reg_err)?;
        let mut bvcpu = self.h.as_bhyve();
        program_x86_vcpu_longmode_entry(&mut bvcpu, &vm, &snap, id).map_err(Self::reg_err)?;
        // The vCPU is now programmed to enter at the ring-0 MSR-init blob. Arm the
        // one-shot RIP-override suppressor so the shared `complete_syscall`'s
        // post-fork `set_gpr(Rip, pending_resume_pc)` does NOT clobber the blob
        // entry (see `set_gpr`).
        self.h.fork_entry_pending.store(true, Ordering::SeqCst);
        let _ = snap; // (snapshot consumed by program_x86_vcpu_longmode_entry)
        Ok(MsrInstall::NeedsRing0Blob)
    }

    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
        // The FP stub needs a fully-running long-mode vCPU. A fork-child / clone
        // sibling re-seeded by `restore` has not run its init blob yet (and a
        // fresh `vcpu_reset` vCPU does not reliably read back its CS DPL), so the
        // stub would mis-fire there; return a placeholder FP image until the vCPU
        // has trapped at a real syscall (the `started` gate). The engine's
        // sigframe reader needs `Some` either way (a `None` would EIO
        // build_sigframe).
        //
        // The placeholder is MASKED (MXCSR=0x1F80, FCW=0x037F), NOT zeroed:
        // `set_fp` restores it verbatim on rt_sigreturn, and a zeroed MXCSR=0
        // leaves every SIMD exception UNMASKED → a maskable SSE exception in the
        // guest (the Go compiler trips one) then raises #XF (vector 19).
        // `go version` is lighter and never trips one, which is why it passed
        // with the old all-zero image.
        let masked = {
            let mut fx = [0u8; 512];
            fx[0..2].copy_from_slice(&0x037Fu16.to_le_bytes()); // FCW
            fx[24..28].copy_from_slice(&0x1F80u32.to_le_bytes()); // MXCSR
            fx[28..32].copy_from_slice(&0x0000_FFFFu32.to_le_bytes()); // MXCSR_MASK
            fx
        };
        if !self.h.started.load(Ordering::SeqCst) {
            return Ok(Some(masked));
        }
        // SP4.1 CPL gate: `fxsave` can only run at CPL 0 (at ring 3 it #UDs and
        // enters the fault path). The syscall-boundary path (raise/intra-proc
        // signals + rt_sigreturn) enters via SYSCALL → the LSTAR stub leaves the
        // vCPU in ring 0, so the stub runs. An async (cross-thread kick) signal
        // parks the vCPU at an arbitrary ring-3 PC; there we cannot fxsave, so
        // return a CLEAN (zeroed) FP image.
        let cpl0 = (self.get_raw(VM_REG_GUEST_CS)? & 3) == 0;
        if !cpl0 {
            // Async ring-3 signal: capture the LIVE FP WITHOUT leaving ring 3.
            // The FP stub + scratch are user-mapped, so the guest runs them at
            // CPL 3; the only obstacle is the stub's OUT doorbell, which #GPs at
            // ring 3 unless CPL <= IOPL — so raise IOPL to 3 for the stub run and
            // restore it after. No CPL/segment switch, hence no VT-x guest-state
            // inconsistency (unlike the reverted CS/SS-switch attempt). Falls back
            // to the masked placeholder if the stub run fails, so signal delivery
            // never EIOs.
            let saved_rflags = self.get_raw(VM_REG_GUEST_RFLAGS)?;
            self.set_raw(VM_REG_GUEST_RFLAGS, saved_rflags | 0x3000)?; // IOPL = 3
            let mut me = self.clone();
            let r = carrick_x86::run_fp_stub(&mut me, X86_FP_STUB_GPA, self.fp_scratch_gpa());
            self.set_raw(VM_REG_GUEST_RFLAGS, saved_rflags)?;
            if r.is_err() {
                return Ok(Some(masked));
            }
            let blob = self.read_gpa(self.fp_scratch_gpa(), 512)?;
            let mut fx = [0u8; 512];
            fx.copy_from_slice(&blob);
            return Ok(Some(fx));
        }
        // Drive the guest-side FXSAVE stub. `run_fp_stub` takes `&mut C`, but all
        // mutation is through the raw `*mut Vcpu` behind the shared handle, not
        // through `Self`'s fields — so a fresh OWNED clone (Arc-clone of the same
        // handle) drives the SAME vCPU with no `&self`→`&mut` cast. The engine is
        // single-threaded per vCPU, so there is no concurrent driver. The stub is
        // non-destructive and restores the four touched regs.
        let mut me = self.clone();
        carrick_x86::run_fp_stub(&mut me, X86_FP_STUB_GPA, self.fp_scratch_gpa())?;
        let blob = self.read_gpa(self.fp_scratch_gpa(), 512)?;
        let mut fx = [0u8; 512];
        fx.copy_from_slice(&blob);
        Ok(Some(fx))
    }

    fn set_fp(&mut self, fx: &[u8; 512]) -> Result<bool, TrapError> {
        // Inverse of get_fp, with the same `started` + CPL gates. Critically this
        // makes `restore`'s `set_fp` (fork/clone, on a not-yet-runnable child) a
        // no-op — driving the FXRSTOR stub there would fault the unprogrammed
        // vCPU. The engine ignores the bool on the sigframe path.
        if !self.h.started.load(Ordering::SeqCst) {
            return Ok(true);
        }
        let cpl0 = (self.get_raw(VM_REG_GUEST_CS)? & 3) == 0;
        if !cpl0 {
            return Ok(true);
        }
        let scratch = self.fp_scratch_gpa();
        self.write_gpa(scratch, fx)?;
        carrick_x86::run_fp_stub(self, X86_FP_STUB_GPA + 8, scratch)?;
        Ok(true)
    }

    fn get_xsave(&self) -> Result<Option<[u8; carrick_x86::XSAVE_LEN]>, TrapError> {
        // Like get_fp, but drives the XSAVE stub (+16) to capture the full
        // 832-byte XSAVE area INCLUDING the AVX YMM_Hi component, so a signal's
        // FP save/restore preserves YMM upper halves. get_fp's 512-byte FXSAVE
        // path drops them (ymmtest: a handler that clobbers YMM0 then returns ->
        // YMM_BAD on bhyve, YMM_OK on Docker). The engine reads YMM via
        // get_ymm_hi -> get_xsave for the sigframe + fork/clone snapshot.
        let placeholder = {
            let mut fx = [0u8; 512];
            fx[0..2].copy_from_slice(&0x037Fu16.to_le_bytes()); // FCW
            fx[24..28].copy_from_slice(&0x1F80u32.to_le_bytes()); // MXCSR
            fx[28..32].copy_from_slice(&0x0000_FFFFu32.to_le_bytes()); // MXCSR_MASK
            carrick_x86::fxsave_to_xsave(fx)
        };
        if !self.h.started.load(Ordering::SeqCst) {
            return Ok(Some(placeholder));
        }
        let cpl0 = (self.get_raw(VM_REG_GUEST_CS)? & 3) == 0;
        if !cpl0 {
            // Async ring-3 signal: raise IOPL=3 so the stub's OUT doorbell fires
            // at CPL 3 (the stub + scratch are user-mapped); restore IOPL after.
            let saved_rflags = self.get_raw(VM_REG_GUEST_RFLAGS)?;
            self.set_raw(VM_REG_GUEST_RFLAGS, saved_rflags | 0x3000)?;
            let mut me = self.clone();
            let r = carrick_x86::run_fp_stub(&mut me, X86_FP_STUB_GPA + 16, self.fp_scratch_gpa());
            self.set_raw(VM_REG_GUEST_RFLAGS, saved_rflags)?;
            if r.is_err() {
                return Ok(Some(placeholder));
            }
        } else {
            let mut me = self.clone();
            carrick_x86::run_fp_stub(&mut me, X86_FP_STUB_GPA + 16, self.fp_scratch_gpa())?;
        }
        let blob = self.read_gpa(self.fp_scratch_gpa(), carrick_x86::XSAVE_LEN)?;
        let mut xs = [0u8; carrick_x86::XSAVE_LEN];
        xs.copy_from_slice(&blob);
        Ok(Some(xs))
    }

    fn set_xsave(&mut self, xs: &[u8; carrick_x86::XSAVE_LEN]) -> Result<bool, TrapError> {
        // Inverse of get_xsave: drive the XRSTOR stub (+32) with the full XSAVE
        // area so YMM upper halves are restored on rt_sigreturn / clone. Same
        // started + CPL gates as set_fp (rt_sigreturn enters at CPL 0 via SYSCALL).
        if !self.h.started.load(Ordering::SeqCst) {
            return Ok(true);
        }
        let cpl0 = (self.get_raw(VM_REG_GUEST_CS)? & 3) == 0;
        if !cpl0 {
            return Ok(true);
        }
        let scratch = self.fp_scratch_gpa();
        self.write_gpa(scratch, xs)?;
        carrick_x86::run_fp_stub(self, X86_FP_STUB_GPA + 32, scratch)?;
        Ok(true)
    }

    fn run(&mut self) -> Result<X86Exit, TrapError> {
        // `run_x86` takes `&mut BhyveVcpu`; build a transient view over the live
        // raw handle and decode its native exit into the shared `X86Exit`. Loop
        // (not recurse) to re-run on a spurious un-requested BOGUS — an unbounded
        // recursion could blow the stack on a wedged guest.
        loop {
            let mut v_cpu = self.h.as_bhyve();
            match v_cpu.run_x86().map_err(Self::reg_err)? {
                // SYSCALL doorbell: OUT 0xC5. bhyve carries rip + inst_length
                // SEPARATELY; the engine owns the pending state, so we compute
                // resume_pc = rip + inst_length HERE (= the sysretq after the `out`).
                NativeExit::Inout {
                    port: SYSCALL_DOORBELL_PORT,
                    is_in: false,
                    inst_length,
                    rip,
                    ..
                } => {
                    // The vCPU has reached a real ring-3 syscall (past its init
                    // blob): the FP stub is now safe to drive (gates get_fp/set_fp).
                    self.h.started.store(true, Ordering::SeqCst);
                    let ids = [
                        VM_REG_GUEST_RAX,
                        VM_REG_GUEST_RDI,
                        VM_REG_GUEST_RSI,
                        VM_REG_GUEST_RDX,
                        VM_REG_GUEST_R10,
                        VM_REG_GUEST_R8,
                        VM_REG_GUEST_R9,
                    ];
                    let vals = v_cpu.get_register_set(&ids).map_err(Self::reg_err)?;
                    let frame = carrick_guest_mem::X8664SyscallFrame {
                        rax: vals[0],
                        rdi: vals[1],
                        rsi: vals[2],
                        rdx: vals[3],
                        r10: vals[4],
                        r8: vals[5],
                        r9: vals[6],
                    };
                    return Ok(X86Exit::Syscall {
                        frame,
                        resume_pc: rip + inst_length as u64,
                    });
                }
                // FP-stub completion doorbell (OUT 0xC6): run_fp_stub consumes this.
                NativeExit::Inout {
                    port: FP_STUB_DOORBELL_PORT,
                    is_in: false,
                    ..
                } => return Ok(X86Exit::FpDoorbell),
                // SP4.3 synchronous-fault doorbell (OUT 0xC7): the guest IDT
                // stub stored vector/error-code in the per-vCPU scratch page,
                // and CR2 carries the faulting linear address for #PF.
                NativeExit::Inout {
                    port: FAULT_DOORBELL_PORT,
                    is_in: false,
                    ..
                } => {
                    let id = self.h.slot().id;
                    let scratch_gpa = fault_scratch_gpa(id).map_err(Self::reg_err)?;
                    let scratch =
                        self.read_gpa(scratch_gpa, std::mem::size_of::<FaultScratchRecord>())?;
                    let record =
                        fault_scratch_record_from_bytes(&scratch).map_err(Self::reg_err)?;
                    let ring0_rsp = self.get_raw(VM_REG_GUEST_RSP)?;
                    let frame_len =
                        fault_stack_frame_len(record.vector()).map_err(Self::reg_err)?;
                    // The frame VA is GPA-identity only on the low RSP0 fault
                    // stack (ring-3 fault); a ring-0 stub fault leaves RSP on the
                    // window-mapped user stack, so translate VA→GPA.
                    let frame = self.read_va(ring0_rsp, frame_len)?;
                    let context = fault_user_context_from_bytes(record.vector(), &frame)
                        .map_err(Self::reg_err)?;
                    let cr2 = self.get_raw(VM_REG_GUEST_CR2)?;
                    // Restore the ring-3 user segments on the live vCPU. Taking the
                    // #PF through the guest IDT gate latched CS=KERN_CS64_SEL (ring-0)
                    // into the live VMCS; whether this fault is DEMAND-COMMITTED (the
                    // engine re-runs the faulting instruction) or DELIVERED as a
                    // signal, the vCPU must resume in ring-3 at `context.rip`. The
                    // shared `restore_user_after_fault` calls `program_user_segments`
                    // for exactly this — but bhyve's `set_segment` is an intentional
                    // no-op (the fork/clone iretq-blocker), so the live ring-3 CS/SS
                    // would otherwise stay at the ring-0 selector the IDT gate left.
                    // Without this, the FIRST demand fault re-runs the guest in ring-0;
                    // it only "recovers" because the NEXT SYSCALL's `sysretq` reloads
                    // ring-3 — so two back-to-back demand faults with no intervening
                    // syscall (glibc ld.so's relocation loop touching consecutive
                    // fresh arena pages) leave the second running supervisor, and the
                    // shared ring-0 fault guard then kills the guest (vector=14 cs=0x8).
                    // Only restore when the FAULTING context was ring-3 — a genuine
                    // ring-0 fault must keep its CS so the guard still fires.
                    if context.cs & 3 == 3 {
                        self.restore_ring3_segments()?;
                    }
                    // Hand the assembled fault frame to the SHARED classifier
                    // (exactly like KVM/NVMM). It enforces the ring-0 fault guard —
                    // a fault whose saved CS is ring-0 (inside the LSTAR stub /
                    // kernel window) is a hard engine error, never a deliverable
                    // guest signal with a bogus user RIP/RSP — and single-sources
                    // the vector→kind and fault-address tables. Reading the live
                    // ring-0 fault frame off the stack (`read_va`, above) is the
                    // ONLY genuinely bhyve-specific step; everything past "I have
                    // vector + error + rip + rsp + cr2" is identical across
                    // backends, so it must not fork here.
                    let doorbell = carrick_x86::FaultDoorbellRecord {
                        vector: u8::try_from(record.vector()).map_err(|_| {
                            TrapError::Hypervisor(format!(
                                "bhyve: fault vector does not fit in u8: {}",
                                record.vector()
                            ))
                        })?,
                        error_code: context.error_code,
                        rip: context.rip,
                        cs: context.cs,
                        rsp: context.rsp,
                        rflags: context.rflags,
                        saved_rax: context.saved_rax,
                        cr2,
                    };
                    return carrick_x86::fault_exit_from_record(self, doorbell, "bhyve-x86");
                }
                // A requested kick surfaces as BOGUS (astpending), not EINTR. If WE
                // raised the kick, surface Kicked so the loop re-checks pending;
                // a spurious VT-x BOGUS just re-runs the guest.
                NativeExit::Bogus => {
                    if self.h.kick_pending.swap(false, Ordering::SeqCst) {
                        return Ok(X86Exit::Kicked);
                    }
                    // Spurious BOGUS with no pending kick: re-run the guest.
                    continue;
                }
                // A cross-thread kick that returned EINTR.
                NativeExit::Kicked => {
                    self.h.kick_pending.store(false, Ordering::SeqCst);
                    self.h.started.store(false, Ordering::SeqCst);
                    return Ok(X86Exit::Kicked);
                }
                NativeExit::Hlt => return Ok(X86Exit::Halt),
                NativeExit::Suspended { how } => {
                    let rip = self.get_raw(VM_REG_GUEST_RIP).unwrap_or(u64::MAX);
                    let cs = self.get_raw(VM_REG_GUEST_CS).unwrap_or(u64::MAX);
                    // A SUSPENDED/TRIPLEFAULT exit is fatal and opaque; dump the
                    // ring-0 state (CR/segment/GDTR/IDTR) so the next ring-0
                    // bring-up regression is diagnosable from a single run — this
                    // is how the fork-blob ring-0 RSP triple fault was root-caused.
                    let cr0 = self.get_raw(VM_REG_GUEST_CR0).unwrap_or(u64::MAX);
                    let cr3 = self.get_raw(VM_REG_GUEST_CR3).unwrap_or(u64::MAX);
                    let cr4 = self.get_raw(VM_REG_GUEST_CR4).unwrap_or(u64::MAX);
                    let efer = self.get_raw(VM_REG_GUEST_EFER).unwrap_or(u64::MAX);
                    let ss = self.get_raw(VM_REG_GUEST_SS).unwrap_or(u64::MAX);
                    let rsp = self.get_raw(VM_REG_GUEST_RSP).unwrap_or(u64::MAX);
                    let rflags = self.get_raw(VM_REG_GUEST_RFLAGS).unwrap_or(u64::MAX);
                    let (csb, csl, csa) =
                        self.get_desc(VM_REG_GUEST_CS).unwrap_or((u64::MAX, 0, 0));
                    let (gsb, _, _) = self.get_desc(VM_REG_GUEST_GS).unwrap_or((u64::MAX, 0, 0));
                    let (gdtb, gdtl, _) =
                        self.get_desc(VM_REG_GUEST_GDTR).unwrap_or((u64::MAX, 0, 0));
                    let (idtb, idtl, _) =
                        self.get_desc(VM_REG_GUEST_IDTR).unwrap_or((u64::MAX, 0, 0));
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve-x86: TRIPLEFAULT how={how} rip={rip:#x} cs={cs:#x} cpl={} \
                     cr0={cr0:#x} cr3={cr3:#x} cr4={cr4:#x} efer={efer:#x} ss={ss:#x} \
                     rsp={rsp:#x} rflags={rflags:#x} cs[b={csb:#x} l={csl:#x} ar={csa:#x}] \
                     gdtr[b={gdtb:#x} l={gdtl:#x}] idtr[b={idtb:#x} l={idtl:#x}] gs.base={gsb:#x}",
                        cs & 3
                    )));
                }
                NativeExit::Paging {
                    gpa,
                    fault_type,
                    rip,
                } => {
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve-x86: VM_EXITCODE_PAGING gpa={gpa:#x} fault_type={fault_type} rip={rip:#x}"
                    )));
                }
                NativeExit::Inout {
                    port, is_in, rip, ..
                } => {
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve-x86: unexpected INOUT port={port:#x} is_in={is_in} rip={rip:#x}"
                    )));
                }
                NativeExit::Other { code, rip } => {
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve-x86: unhandled exit code={code} rip={rip:#x}"
                    )));
                }
            }
        }
    }

    fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
        self.set_cap(VM_CAP_HALT_EXIT, 1)
    }
}

// ─── BhyveVmm (the X86Vmm) ───────────────────────────────────────────────────

/// The bhyve `X86Vmm`: an owned `BhyveVm` plus the `BhyveGuestRam` window table
/// and a shared handle to the live vCPU (so a fork's `rebuild_child_vm` can swap
/// the vCPU underneath the engine's separate `vcpu` field).
pub struct BhyveVmm {
    vm: BhyveVm,
    ram: BhyveGuestRam,
    /// The shared vCPU handle the engine's `vcpu: BhyveX86Vcpu` field also holds.
    h: Arc<VcpuHandle>,
    /// `true` while `self.vm` is a BORROWED view of a VM owned elsewhere (a vfork
    /// child sharing the parent's VM). Carried verbatim from the old engine's
    /// `vm_borrowed`; `process_exit_cleanup` must NOT destroy a borrowed VM.
    vm_borrowed: bool,
    /// Serializes the live-PML4 copy-edit-copy across sibling vCPUs. The guest
    /// page tables are shared (one CR3, in the shared sysmem); two vCPUs editing
    /// different leaves concurrently would each write back a whole-table image
    /// and drop the other's edit (a lost leaf → an unbreakable #PF loop). Shared
    /// via the sibling builder so all vCPUs take the SAME lock.
    pml4_lock: Arc<std::sync::Mutex<()>>,
}

// SAFETY: BhyveVmm owns the VM ctx + a single-thread-driven vCPU handle; the run
// loop moves it into its owning thread (sibling vCPUs hold distinct handles).
unsafe impl Send for BhyveVmm {}

/// The `Send` sibling-spawn payload (clone(CLONE_THREAD)): the shared VM handle +
/// the parent's RAM bookkeeping. The engine carries the seeded snapshot.
pub struct BhyveSiblingBuilder {
    vm: BhyveSharedVm,
    ram: BhyveGuestRam,
    kick_pending: Arc<AtomicBool>,
    pml4_lock: Arc<std::sync::Mutex<()>>,
}

// SAFETY: BhyveSharedVm is Send+Sync; the RAM payload is plain bookkeeping the
// materialized engine touches single-threaded.
unsafe impl Send for BhyveSiblingBuilder {}

impl BhyveVmm {
    /// Read the live guest PML4 into a scratch buffer, let `edit` mutate it via a
    /// `Pml4Manager`, write it back, and reload CR3 (the single-vCPU TLB flush) —
    /// the copy-edit-copy idiom shared by the demand-paging commit (and a future
    /// refactor of `protect_range` / `map_host_alias`). `edit` returns whether it
    /// changed the tables (no change ⇒ skip the write-back + CR3 reload).
    fn with_live_pml4<F>(&mut self, edit: F) -> Result<(), MemoryError>
    where
        F: FnOnce(&mut Pml4Manager) -> Result<bool, MemoryError>,
    {
        // Serialize the whole copy-edit-copy across sibling vCPUs: the PML4 is
        // shared (one CR3), so a concurrent edit of a different leaf would write
        // back a stale whole-table image and drop this edit (a lost leaf → an
        // unbreakable #PF loop).
        let _pml4 = self.pml4_lock.lock().unwrap_or_else(|e| e.into_inner());
        let host = self
            .vm
            .map_gpa(X86_PML4_GPA, X86_PML4_CAPACITY)
            .ok_or_else(|| {
                MemoryError::HostMap(format!(
                    "bhyve-x86: PML4 map_gpa 0x{X86_PML4_GPA:x} unmapped"
                ))
            })?;
        let mut tables = vec![0u8; X86_PML4_CAPACITY];
        // SAFETY: map_gpa proved the live PML4 window is mapped.
        unsafe { std::ptr::copy_nonoverlapping(host, tables.as_mut_ptr(), tables.len()) };
        let mut mgr = Pml4Manager::new(tables, X86_PML4_GPA);
        if !edit(&mut mgr)? {
            return Ok(());
        }
        // SAFETY: both windows are X86_PML4_CAPACITY bytes.
        unsafe { std::ptr::copy_nonoverlapping(mgr.bytes().as_ptr(), host, X86_PML4_CAPACITY) };
        self.h
            .as_bhyve()
            .set_reg_raw_shared(VM_REG_GUEST_CR3, X86_PML4_GPA)
            .map_err(|e| MemoryError::HostMap(format!("bhyve-x86: reload CR3: {e}")))
    }

    /// Back a lazily-reserved VA range NOW: allocate a compact GPA span,
    /// zero-fill it (Linux anon), map the leaves in the live PML4, and drop the
    /// reservation. Used by `demand_commit` (one page, on a guest #PF) and
    /// `host_ptr_mut` (a whole range, when carrick itself must WRITE into a
    /// reserved region — file-backed mmap content, stack/auxv).
    ///
    /// CRITICAL: only ALREADY-UNCOMMITTED pages are (re)backed; pages a window
    /// already covers are left untouched. Re-committing a live page would
    /// allocate a FRESH zeroed GPA over it — destroying its contents. The biting
    /// case: `host_ptr_mut` is driven by `write_bytes`, which probes the WHOLE
    /// remaining length; a guest buffer that was demand-faulted page-by-page is
    /// backed by 1-page windows that `resolve` cannot span, so `host_ptr` returns
    /// `None` for the multi-page probe and we land here even though the pages ARE
    /// committed. Blindly re-committing the span then zeroed the page holding the
    /// musl mallocng group header (`base->meta`) that `free()`/`get_meta` reads —
    /// the bhyve `read()`-into-a-touched-buffer heap corruption (`spliceunixpoll`,
    /// `go-net_http`). Committing only the genuine holes keeps live data intact;
    /// `write_bytes`' own per-run chunking then writes each page to its real GPA.
    fn commit_range(&mut self, va: u64, len: usize) -> Result<(), MemoryError> {
        let start = va & !0xFFF;
        let end = va.wrapping_add(len as u64).wrapping_add(0xFFF) & !0xFFF;
        let mut page = start;
        while page < end {
            // Preserve any page a window already backs (its live contents).
            if self.ram.resolve(page, 1).is_some() {
                page += 0x1000;
                continue;
            }
            // Coalesce a contiguous run of uncommitted pages into ONE window +
            // one PML4 edit (the original whole-span behaviour, scoped to holes).
            let mut run_end = page + 0x1000;
            while run_end < end && self.ram.resolve(run_end, 1).is_none() {
                run_end += 0x1000;
            }
            let span = (run_end - page) as usize;
            let gpa = self
                .ram
                .add_bump(page, span, true, true, false)
                .map_err(|e| MemoryError::HostMap(format!("bhyve commit_range: GPA alloc: {e}")))?;
            let host = self.vm.map_gpa(gpa, span).ok_or_else(|| {
                MemoryError::HostMap(format!("bhyve commit_range: map_gpa 0x{gpa:x} unmapped"))
            })?;
            // SAFETY: `host` is live sysmem of `span` bytes — zero the new anon pages.
            unsafe { std::ptr::write_bytes(host, 0, span) };
            // exec=true: this is the SYSCALL-access backing path (carrick reading/
            // writing guest mem), coalescing runs that may span reservations of
            // mixed prot — it maps RWX so carrick can always touch the page. The
            // GUEST's own execution permission (W^X / NX) is set independently by
            // the `#PF` `demand_commit` path, which honours the reservation's exec.
            self.with_live_pml4(|mgr| {
                mgr.map_aliased(page, gpa, span as u64, true, true)
                    .map_err(|_| MemoryError::OutOfBounds {
                        address: page,
                        length: span,
                    })?;
                Ok(true)
            })?;
            self.ram.drop_reservation(page, span);
            page = run_end;
        }
        Ok(())
    }

    /// Flush every registered writable file-backed shm alias's live sysmem back
    /// to its backing FILE. Called at the fork barrier (`freeze_ram`, parent vCPU
    /// suspended) so a forked child that re-`shmat`s the same segment reads the
    /// parent's stores via map_host_alias's file→sysmem copy. Best-effort: a
    /// transient `map_gpa`/`pwrite` failure is skipped (the worst case is the
    /// pre-fix stale-file behaviour for that one alias, never a crash). The write
    /// is bounded by the file's real size, so it never grows the file.
    fn flush_shm_aliases(&self) {
        for (gpa, fd, offset, write_len) in self.ram.shm_aliases_for_flush() {
            if write_len == 0 {
                continue;
            }
            let Some(host) = self.vm.map_gpa(gpa, write_len) else {
                continue;
            };
            // SAFETY: map_gpa proved `[gpa, gpa+write_len)` is live sysmem; we read
            // it into the kernel via pwrite. The parent vCPU is suspended, so the
            // bytes are a consistent snapshot.
            let n = unsafe { libc::pwrite(fd, host as *const libc::c_void, write_len, offset) };
            // A short/failed write only leaves the file as stale as before the fix
            // for this alias — never fatal; nothing to recover.
            let _ = n;
        }
    }
}

impl GuestVmBackend for BhyveVmm {
    fn write_gpa(&self, gpa: u64, bytes: &[u8]) -> Result<(), TrapError> {
        let host = self.vm.map_gpa(gpa, bytes.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!("bhyve-x86: write_gpa 0x{gpa:x} unmapped"))
        })?;
        // SAFETY: map_gpa proved [host, host+len) is a live guest-RAM window.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len()) };
        Ok(())
    }

    fn host_ptr(&self, gpa: u64, len: usize) -> Option<*mut u8> {
        // The engine's GuestMemory passes a guest VA; resolve VA→GPA through the
        // shared window table, then the contiguous segment via map_gpa.
        let target_gpa = self.ram.resolve(gpa, len)?;
        self.vm.map_gpa(target_gpa, len)
    }

    fn host_ptr_mut(&mut self, gpa: u64, len: usize) -> Option<*mut u8> {
        // A carrick-side WRITE into a lazily-reserved arena range — the
        // file-backed mmap content copy, stack/auxv staging — must materialize
        // the backing NOW. (A guest store faults page-by-page through
        // `demand_commit`; a host-side write goes straight to the host pointer,
        // so there is no #PF to drive the commit.) Commit the range, then
        // resolve. Best-effort: a wild/oversized VA fails `commit_range`
        // (plan_gpa/map_gpa overflow) and falls through to `None` — same as the
        // pre-demand-paging behavior. Eager/committed VAs short-circuit (the
        // first `host_ptr` hits).
        if self.host_ptr(gpa, len).is_none() {
            let _ = self.commit_range(gpa, len);
        }
        self.host_ptr(gpa, len)
    }

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        // bhyve guest RAM is kernel-owned and NOT copy-on-write across libc::fork
        // (the inherited vmctx aliases the parent's live kernel pages). The whole
        // segment must be eagerly copied into a fresh child VM (§2.5b).
        ForkRamStrategy::EagerCopy
    }

    fn wait_for_vcpu_slot() {
        // Admission is enforced by the carrick-hal VcpuScheduler (installed at
        // startup with `vcpu_budget()`), which the shared thread-spawn path calls
        // — so this backend hook stays a no-op.
    }

    fn vcpu_budget() -> usize {
        // hw.vmm.maxcpu is the bhyve hard cap on concurrently-active vCPUs; a guest
        // thread beyond it would EINVAL `vm_activate_cpu`. The scheduler bounds the
        // live set to this N (recycling ids) so that never happens.
        let mut val: i32 = 0;
        let mut len = std::mem::size_of::<i32>();
        let name = c"hw.vmm.maxcpu";
        let rc = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                &mut val as *mut _ as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 && val > 0 { val as usize } else { 8 }
    }

    fn reclaims(&self) -> bool {
        // bhyve has the lowest vCPU cap; it reclaims so >N guest threads can run.
        true
    }

    fn process_exit_cleanup(&mut self) {
        // Push this process's writable file-backed `MAP_SHARED` alias stores back
        // to their backing files BEFORE the VM node is torn down. bhyve can't share
        // guest physical RAM across the fork, so the shared inode is the only
        // cross-process medium: a forked child's stores live in its private sysmem
        // and must reach the file here so the parent — which re-reads the file when
        // it reaps this child (`refresh_shared_after_wait`) — sees them. Cheap and
        // safe: the process is exiting (no concurrent guest write to these pages),
        // the write is bounded by file size, and a read-only alias is skipped (no
        // dirty data). Done for a borrowed (vfork-shared) VM too — the writes are
        // owed regardless of who destroys the node.
        self.flush_shm_aliases();
        // Tear down the bhyve VM node on a forked-child `_exit` (which skips
        // Drop). A vfork-shared (borrowed) VM must NOT be destroyed — the parent
        // owns the node and resumes on it (§2.5c). Carried verbatim from the old
        // engine. The generic engine's `process_exit_cleanup` delegates here.
        if self.vm_borrowed {
            return;
        }
        self.vm.destroy_in_place();
    }
}

/// Number of slots in the fork-coherent futex mirror (open-addressed by futex-word VA).
const FUTEX_MIRROR_SLOTS: usize = 8192;

/// One fork-coherent futex-mirror slot: the guest futex-word VA (the open-addressing
/// key; 0 = empty), the cross-process mirror of that word's value, and a parked-waiter
/// count. The waiter count exists because FreeBSD `_umtx_op(UMTX_OP_WAKE)` returns 0 on
/// success — NOT the number of waiters woken, which Linux `FUTEX_WAKE` returns and which
/// `tst_checkpoint_wake` loops on. The umtx wait/wake path (carrick-host) bumps/reads it
/// at `value`+4 so a shared WAKE can report a Linux-faithful woken count. LAYOUT IS
/// LOAD-BEARING: `value` at offset 8, `waiters` at offset 12 (== the wake addr + 4).
#[repr(C, align(16))]
struct FutexMirrorSlot {
    key: std::sync::atomic::AtomicU64,
    value: std::sync::atomic::AtomicU32,
    waiters: std::sync::atomic::AtomicU32,
}

/// Fork-coherent "futex mirror" for the bhyve cross-process futex. bhyve cannot share
/// guest sysmem across a fork (the vmmapi memseg model can't back a guest segment with
/// a host fd from userspace — see `map_host_alias`), so each forked process holds a
/// PRIVATE copy of every guest MAP_SHARED word; a cross-process futex keyed on the
/// per-VM word never rendezvouses. This ONE host `MAP_SHARED|MAP_ANON` slot array,
/// allocated before the guest's first fork (so every child inherits the SAME physical
/// pages), holds the shared word the umtx waits/wakes on, open-addressed by the
/// futex-word VA — which is stable across the fork (the child inherits the page tables)
/// and so resolves to the same slot in parent and child. (Indexing by GPA would need a
/// per-VA→GPA translation the engine doesn't expose here; the VA is the natural key.)
static SHARED_FUTEX_MIRROR: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Base of the futex-mirror slot array; `None` if the mmap failed.
fn shared_futex_mirror_base() -> Option<usize> {
    let base = *SHARED_FUTEX_MIRROR.get_or_init(|| {
        let len = FUTEX_MIRROR_SLOTS * std::mem::size_of::<FutexMirrorSlot>();
        // SAFETY: a fresh anonymous shared mapping; a null hint lets the kernel place it.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED { 0 } else { p as usize }
    });
    (base != 0).then_some(base)
}

/// Resolve a guest futex-word VA to the host address of its fork-coherent mirror word,
/// claiming an open-addressed slot on first sight. `None` if the mmap failed or the
/// table is full (in which case the cross-process futex degrades to the old behaviour).
fn shared_futex_mirror_slot(key: u64) -> Option<usize> {
    use std::sync::atomic::Ordering::{AcqRel, Acquire};
    let base = shared_futex_mirror_base()?;
    let slots = base as *const FutexMirrorSlot;
    let mut idx = ((key >> 2) as usize) % FUTEX_MIRROR_SLOTS;
    for _ in 0..FUTEX_MIRROR_SLOTS {
        // SAFETY: idx < FUTEX_MIRROR_SLOTS and `base` is a live array of that many slots.
        let slot = unsafe { &*slots.add(idx) };
        let cur = slot.key.load(Acquire);
        if cur == key {
            return Some(&slot.value as *const _ as usize);
        }
        if cur == 0 {
            match slot.key.compare_exchange(0, key, AcqRel, Acquire) {
                Ok(_) => return Some(&slot.value as *const _ as usize),
                // Lost the race to a peer claiming the SAME key — still ours to use.
                Err(actual) if actual == key => {
                    return Some(&slot.value as *const _ as usize);
                }
                // Claimed by a different key — keep probing.
                Err(_) => {}
            }
        }
        idx = (idx + 1) % FUTEX_MIRROR_SLOTS;
    }
    None
}

impl X86Vmm for BhyveVmm {
    type Vcpu = BhyveX86Vcpu;
    type KickHandle = BhyveKickHandle;
    type SiblingBuilder = BhyveSiblingBuilder;

    fn setup_memory(&mut self, _plan: &WindowPlan) -> Result<(), TrapError> {
        // bhyve realizes the plan as ONE contiguous lowmem segment (§2.5a). The
        // segment + the window table are built by `bring_up`; this hook is a
        // no-op (the BhyveVmm `bring_up` produces returns is already mapped). The
        // fork-coherent futex mirror is allocated in `freeze_ram` (the guaranteed
        // pre-fork hook), not here.
        Ok(())
    }

    fn shared_futex_host_addr(&self, key: u64, _len: usize) -> Option<usize> {
        // Cross-process futex coherence on bhyve: the per-VM guest word is NOT shared
        // across the fork (vmmapi limitation, see SHARED_FUTEX_MIRROR). `key` is the
        // futex-word VA (syscall_buffer_gpa is identity on bhyve) — stable across the
        // fork — so resolve it to its fork-coherent mirror slot. The dispatch syncs the
        // per-VM guest word <-> the mirror at the WAIT/WAKE boundaries (proc.rs).
        shared_futex_mirror_slot(key)
    }

    /// bhyve's `shared_futex_host_addr` returns a SEPARATE mirror slot (the per-VM
    /// guest word is not fork-shared), so a `FUTEX_WAKE` MUST publish the waker's
    /// word into that mirror for a cross-process waiter to observe it. (On
    /// HVF/KVM this is false and the publish is skipped — host_addr IS the guest
    /// word, so republishing would race and revert a concurrent peer update.)
    fn shared_futex_uses_mirror(&self) -> bool {
        true
    }

    fn is_guest_reserved(&self, va: u64) -> bool {
        // A reserved (lazily anon-backed) VA the guest has not touched has no
        // window yet; the engine's read path treats it as kernel zero-fill
        // instead of EFAULT (see X86Vmm::is_guest_reserved).
        self.ram.find_reservation(va)
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        // Demand-paged anon arena: a protection request for a VA the bhyve
        // backend has NOT eagerly GPA-backed (no window covers it) is a fresh
        // anon-mmap reservation — record it and return WITHOUT a GPA/leaf. The
        // #PF path (`demand_commit`) backs one page on first touch, re-running
        // the faulting instruction. Only VAs already backed by a window (the
        // eager kernel/ELF/stack regions, or an already-committed page) take the
        // real page-table edit. The reservation REMEMBERS the requested protection
        // (PROT_WRITE → an RW leaf, !PROT_WRITE → a present-but-read-only leaf so a
        // store re-faults SEGV_ACCERR; !PROT_EXEC → an NX leaf so a fetch faults).
        //
        // A range can be PARTIALLY backed: e.g. mremap-MOVE copies `old_size` bytes
        // to a fresh destination (which commits only those pages via `write_bytes`/
        // `commit_range`), then `protect_range`s the FULL `new_size`. The leading
        // copied pages are backed (need a PML4 edit) while the grown tail is not
        // (needs a reservation). The old all-or-nothing decision keyed on page 0
        // alone took the edit branch and `set_rw` failed on the first uncommitted
        // tail page → spurious ENOMEM (the bhyve mremap-grow gap). So split the
        // range into maximal backed / unbacked runs and handle each correctly.
        let flags = LinuxProtFlags::from_bits_truncate(prot);
        let writable = flags.contains(LinuxProtFlags::WRITE);
        let exec = flags.contains(LinuxProtFlags::EXEC);

        let start = address & !0xFFF;
        let end = address.wrapping_add(len as u64).wrapping_add(0xFFF) & !0xFFF;
        if end <= start {
            return Ok(());
        }

        let mut page = start;
        while page < end {
            let backed = self.host_ptr(page, 1).is_some();
            // Extend a maximal run of pages with the SAME backing state.
            let mut run_end = page + 0x1000;
            while run_end < end && (self.host_ptr(run_end, 1).is_some() == backed) {
                run_end += 0x1000;
            }
            let run_len = (run_end - page) as usize;
            if backed {
                // Edit the live PML4 leaves for the already-committed run (the
                // shared locked copy-edit-copy + CR3 reload).
                self.with_live_pml4(|mgr| {
                    let changed = if flags.is_empty() {
                        mgr.set_prot_none(page, run_len)
                    } else if flags.contains(LinuxProtFlags::WRITE) {
                        mgr.set_rw(page, run_len, exec)
                    } else {
                        mgr.set_readonly(page, run_len, exec)
                    }
                    .map_err(|_| MemoryError::OutOfBounds {
                        address: page,
                        length: run_len,
                    })?;
                    Ok(changed)
                })?;
            } else {
                // Defer to the demand-commit path: record the reservation so the
                // first touch commits the leaf with this protection.
                self.ram.reserve(page, run_len, writable, exec);
            }
            page = run_end;
        }
        Ok(())
    }

    fn demand_commit(&mut self, fault_addr: u64) -> Result<bool, MemoryError> {
        let page = fault_addr & !0xFFF;
        // ATOMIC across sibling vCPUs (shared ram, one lock): AlreadyMapped means
        // another thread already committed this page — just re-run; NotReserved
        // is a genuine fault → SIGSEGV; Committed(gpa) means WE won and must zero
        // + map the leaf. This is what stops two Go threads committing one page
        // to divergent GPAs (the "bad sweepgen" heap corruption).
        match self
            .ram
            .commit_if_absent(page, 4096)
            .map_err(|e| MemoryError::HostMap(format!("bhyve demand_commit: {e}")))?
        {
            CommitOutcome::AlreadyMapped => Ok(true),
            CommitOutcome::NotReserved => Ok(false),
            CommitOutcome::Committed {
                gpa,
                writable,
                exec,
            } => {
                let host = self.vm.map_gpa(gpa, 4096).ok_or_else(|| {
                    MemoryError::HostMap(format!("bhyve demand_commit: map_gpa 0x{gpa:x} unmapped"))
                })?;
                // SAFETY: live sysmem of 4096 bytes — Linux anon zero-fill.
                unsafe { std::ptr::write_bytes(host, 0, 4096) };
                // Map the leaf with the reservation's protection. A read-only
                // (PROT_READ) reservation commits a PRESENT but read-only leaf, so
                // the guest WRITE that demand-faulted this page re-faults with
                // PFEC.P=1 (not-present bit clear) — the shared engine then skips
                // demand_commit and delivers SIGSEGV/SEGV_ACCERR. A non-exec
                // (no PROT_EXEC) reservation commits an NX leaf, so a guest
                // instruction FETCH re-faults (PFEC.P=1, I/D set) → SEGV_ACCERR
                // (W^X). A writable+exec reservation commits RWX (the common
                // anon-arena case).
                self.with_live_pml4(|mgr| {
                    mgr.map_aliased(page, gpa, 4096, writable, exec)
                        .map_err(|_| MemoryError::OutOfBounds {
                            address: page,
                            length: 4096,
                        })?;
                    Ok(true)
                })?;
                Ok(true)
            }
        }
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        // Drop any lazy reservation first, so a freed-but-never-faulted range is
        // not resurrected by the default `protect_range(0)` → reserve path. A
        // committed page (a window covers it) still gets its present bits cleared.
        self.ram.drop_reservation(address, len);
        let result = if self.host_ptr(address, 1).is_some() {
            // Clear the live PML4 leaves WHILE the window still resolves the VA→GPA
            // (protect_range needs host_ptr to find the committed page).
            self.protect_range(address, len, 0)
        } else {
            Ok(())
        };
        // THEN prune the window, so a later mmap that reuses this VA re-commits a
        // FRESH GPA instead of resolving this now-dead one. Leaving the window
        // behind diverges host_ptr (syscall copies) from the guest's live leaf and
        // mis-targets zero_backing — the bhyve large-alloc heap corruption. Done
        // after protect_range so the leaf-clear above can still resolve the VA.
        self.ram.remove_windows(address, len);
        result
    }

    fn map_host_alias(
        &mut self,
        va: u64,
        _ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        // bhyve IGNORES the dispatcher's `ipa` (it bumps its own GPA in the single
        // sysmem segment, which is already kernel-backed and host-visible via
        // map_gpa). The alias content is COPIED into that backing RAM: an anon
        // payload directly, or a file's current bytes via a transient host mmap.
        //
        // LIMITATION: this copy gives NO MAP_SHARED write-back — a guest's writes
        // to a file-backed alias stay in sysmem, never reach the host file, and are
        // not coherent across a COW fork. The vmmapi memseg model can't back a
        // guest segment with a host fd from userspace, so durable/shared-aperture
        // coherence on bhyve is a known follow-up. Enough for a guest that READS
        // its initial aperture content (the common startup case).
        let writable = match file {
            Some((_, _, prot)) => prot & libc::PROT_WRITE != 0,
            None => true,
        };
        let gpa = self
            .ram
            .add_bump(va, len as usize, true, writable, false)
            .map_err(|e| TrapError::Hypervisor(format!("bhyve map_host_alias: GPA alloc: {e}")))?;
        let host = self.vm.map_gpa(gpa, len as usize).ok_or_else(|| {
            TrapError::Hypervisor(format!("bhyve map_host_alias: map_gpa 0x{gpa:x} unmapped"))
        })?;
        match file {
            Some((fd, offset, _prot)) => {
                // The dispatcher's alias `len` is page-aligned to the alias-IPA
                // arena granularity (`HVF_PAGE_SIZE` = 16 KiB), but the backing
                // file (e.g. a SysV-shm segment ftruncated to its requested size)
                // is only its own length — which on x86 (4 KiB host pages) can be
                // SMALLER than `len`. mmap'ing `len` over a short file is fine, but
                // HOST-READING past the file's last page faults SIGBUS (the
                // "object-specific hardware error" — what crashed the `sysvshm` /
                // `shmrdonly` probes). So bound the copy to the bytes the file
                // actually backs; the sysmem tail `[copy_len, len)` is the fresh
                // bump GPA's kernel-zeroed RAM, matching Linux's zero-fill of a
                // segment's partial last page. (KVM never hits this: it registers
                // the mmap as a guest memslot WITHOUT host-reading it, so an
                // out-of-bounds touch would fault inside the guest, not the host.)
                let file_size = {
                    let mut st: libc::stat = unsafe { core::mem::zeroed() };
                    if unsafe { libc::fstat(fd, &mut st) } != 0 {
                        return Err(TrapError::Hypervisor(format!(
                            "bhyve map_host_alias: fstat fd={fd}: {}",
                            std::io::Error::last_os_error()
                        )));
                    }
                    st.st_size.max(0) as u64
                };
                let copy_len = file_size.saturating_sub(offset.max(0) as u64).min(len) as usize;
                // mmap the file's current content read-only in the host, copy the
                // file-backed prefix into the backing RAM, then drop the transient
                // host view. Map only the backed pages so the mapping itself never
                // straddles EOF.
                if copy_len > 0 {
                    let src = unsafe {
                        libc::mmap(
                            std::ptr::null_mut(),
                            copy_len,
                            libc::PROT_READ,
                            libc::MAP_SHARED,
                            fd,
                            offset,
                        )
                    };
                    if src == libc::MAP_FAILED {
                        return Err(TrapError::Hypervisor(format!(
                            "bhyve map_host_alias: mmap file fd={fd} off={offset} \
                             copy_len=0x{copy_len:x}: {}",
                            std::io::Error::last_os_error()
                        )));
                    }
                    // SAFETY: `src` is a `copy_len`-byte PROT_READ mapping wholly
                    // within the file; `host` is live sysmem of `len` >= copy_len;
                    // the regions don't overlap.
                    unsafe { std::ptr::copy_nonoverlapping(src as *const u8, host, copy_len) };
                    // SAFETY: drop the transient host view of the file.
                    unsafe { libc::munmap(src, copy_len) };
                }
                // SysV-shm cross-process coherence: bhyve cannot back the guest
                // segment with the host fd, so a guest store lands in private
                // sysmem, invisible to a forked child that re-attaches the same
                // file. For a WRITABLE alias, retain the fd and register the alias
                // so `freeze_ram` flushes this GPA back to the file at the fork
                // barrier — the child's re-`shmat` then reads the parent's stores
                // (matching KVM/HVF, whose MAP_SHARED file alias is coherent for
                // free). A READ-ONLY alias has no dirty data to push back, so just
                // close its fd. (The dispatcher transferred fd ownership to us;
                // KVM closes it after mmap — bhyve previously LEAKED it here.)
                if writable {
                    self.ram.register_shm_alias(
                        va,
                        gpa,
                        len as usize,
                        fd,
                        offset,
                        file_size as usize,
                    );
                } else {
                    // SAFETY: we own `fd`; nothing to flush for a read-only alias.
                    unsafe { libc::close(fd) };
                }
            }
            None => {
                let n = payload.len().min(len as usize);
                // SAFETY: `host` is live sysmem of `len`; n ≤ len.
                unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), host, n) };
            }
        }
        // Install the VA→GPA path in the live PML4 (the same copy-edit-copy +
        // CR3 reload as `protect_range`; map_aliased uses bounded 2 MiB block
        // leaves for large spans).
        let host = self
            .vm
            .map_gpa(X86_PML4_GPA, X86_PML4_CAPACITY)
            .ok_or_else(|| {
                TrapError::Hypervisor(format!(
                    "bhyve map_host_alias: PML4 map_gpa 0x{X86_PML4_GPA:x} unmapped"
                ))
            })?;
        let mut tables = vec![0u8; X86_PML4_CAPACITY];
        // SAFETY: map_gpa proved the live PML4 window is mapped.
        unsafe { std::ptr::copy_nonoverlapping(host, tables.as_mut_ptr(), tables.len()) };
        let mut mgr = Pml4Manager::new(tables, X86_PML4_GPA);
        // exec=true: a MAP_SHARED file/anon host alias maps executable (the
        // historical alias behaviour; shared-object text needs to execute).
        mgr.map_aliased(va, gpa, len, writable, true).map_err(|_| {
            TrapError::Hypervisor(format!(
                "bhyve map_host_alias: map_aliased va=0x{va:x} gpa=0x{gpa:x} len=0x{len:x}"
            ))
        })?;
        // SAFETY: both windows are X86_PML4_CAPACITY bytes.
        unsafe { std::ptr::copy_nonoverlapping(mgr.bytes().as_ptr(), host, X86_PML4_CAPACITY) };
        self.h
            .as_bhyve()
            .set_reg_raw_shared(VM_REG_GUEST_CR3, X86_PML4_GPA)
            .map_err(|e| TrapError::Hypervisor(format!("bhyve map_host_alias: reload CR3: {e}")))?;
        Ok(())
    }

    fn repoint_private(
        &mut self,
        va: u64,
        overlay_va: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        // Guest `mmap(MAP_FIXED|MAP_PRIVATE|MAP_ANON)` over a shared-aperture VA.
        // The dispatcher already carved an overlay slot (`overlay_va`, in the
        // per-process private overlay aperture) and asks the backend to make `va`
        // resolve there so the guest's "private" stores stay private. On bhyve the
        // overlay aperture is demand-paged (capped to 1 page at bring-up — see
        // guest_setup_x86.rs `M2_MISC_CAP`), so there is no pre-allocated overlay
        // GPA the KVM path's identity `host_ptr(overlay_gpa)` relies on. Instead
        // allocate a FRESH private bhyve GPA, seed it with `content`, and repoint
        // `va`'s live PML4 leaf at that GPA. The new GPA is keyed in the window
        // table at `overlay_va` so a later access through the overlay VA (and the
        // re-MAP_FIXED free path) resolves consistently; the leaf for `va` is what
        // the guest's own EL0 access and carrick's syscall-buffer translation
        // (`needs_stage1_translation`) both target.
        let span = (len + 0xFFF) & !0xFFF;
        if span == 0 {
            return Ok(());
        }
        // Reuse an existing overlay-VA window if a prior repoint already backed it
        // (the dispatcher frees the old overlay slot on re-MAP_FIXED, but the bhyve
        // GPA window persists; resolve it so we seed/repoint in place rather than
        // leaking a fresh GPA each time).
        let gpa = match self.ram.resolve(overlay_va, span) {
            Some(gpa) => gpa,
            None => self
                .ram
                .add_bump(overlay_va, span, true, true, false)
                .map_err(|e| {
                    MemoryError::HostMap(format!("bhyve repoint_private: GPA alloc: {e}"))
                })?,
        };
        let host = self.vm.map_gpa(gpa, span).ok_or_else(|| {
            MemoryError::HostMap(format!("bhyve repoint_private: map_gpa 0x{gpa:x} unmapped"))
        })?;
        // Seed: zero the whole slot (Linux anon zero-fill), then copy `content`
        // (the dispatcher passes zeros for an anon MAP_FIXED, but honour any seed).
        // SAFETY: `host` is live sysmem of `span` bytes (>= len).
        unsafe { std::ptr::write_bytes(host, 0, span) };
        if !content.is_empty() {
            let n = content.len().min(span);
            // SAFETY: `host` spans `span` >= n bytes; `content[..n]` is a distinct
            // valid source slice.
            unsafe { std::ptr::copy_nonoverlapping(content.as_ptr(), host, n) };
        }
        // Repoint the live PML4 leaf for `va` at the fresh private GPA (4 KiB
        // precise; the engine reloads CR3 after this returns).
        self.with_live_pml4(|mgr| {
            mgr.map_aliased(va & !0xFFF, gpa, span as u64, true, true)
                .map_err(|_| MemoryError::OutOfBounds {
                    address: va,
                    length: span,
                })?;
            Ok(true)
        })
    }

    fn back_fixed_anon(&mut self, va: u64, len: usize, writable: bool) -> Result<(), MemoryError> {
        // Back a `MAP_FIXED|MAP_PRIVATE|MAP_ANON` at a VA the PML4 does not yet map
        // (outside the eager arena/image). bhyve demand-pages the anon mmap arena,
        // so a fresh in-arena MAP_FIXED is already serviced by a reservation (see
        // `protect_range`); this only fires for a genuinely-unbacked, NON-reserved
        // VA. Allocate an identity-keyed private GPA, zero it, and install the leaf
        // so the guest's own access hits real backing instead of faulting.
        let span = (len + 0xFFF) & !0xFFF;
        if span == 0 {
            return Ok(());
        }
        let base = va & !0xFFF;
        let gpa = self
            .ram
            .add_bump(base, span, true, writable, false)
            .map_err(|e| MemoryError::HostMap(format!("bhyve back_fixed_anon: GPA alloc: {e}")))?;
        let host = self.vm.map_gpa(gpa, span).ok_or_else(|| {
            MemoryError::HostMap(format!("bhyve back_fixed_anon: map_gpa 0x{gpa:x} unmapped"))
        })?;
        // SAFETY: `host` is live sysmem of `span` bytes — Linux anon zero-fill.
        unsafe { std::ptr::write_bytes(host, 0, span) };
        self.with_live_pml4(|mgr| {
            // exec=true: the caller's `protect_range`/`set_rw` re-applies the prot
            // (incl. NX); the leaf itself stays executable here.
            mgr.map_aliased(base, gpa, span as u64, writable, true)
                .map_err(|_| MemoryError::OutOfBounds {
                    address: base,
                    length: span,
                })?;
            Ok(true)
        })
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        // The engine only calls add_vcpu on a freshly-constructed VMM; bhyve's
        // `bring_up` already created vCPU 0 and stored it in the shared handle, so
        // hand back a view over it. (A second add_vcpu is never issued on the x86
        // path — siblings go through materialize_sibling.)
        Ok(BhyveX86Vcpu {
            h: Arc::clone(&self.h),
        })
    }

    fn freeze_ram(&self) -> Result<Vec<u8>, TrapError> {
        // Allocate the fork-coherent futex mirror NOW — in the PARENT, immediately
        // before `libc::fork` — so every child inherits the SAME MAP_SHARED pages. A
        // lazy first-touch alloc would run post-fork and hand parent and child SEPARATE
        // mirrors (the bug: identical key → different host addrs). Idempotent OnceLock.
        let _ = shared_futex_mirror_base();
        // Snapshot the parent's LIVE high-water [0, total_size()) — NOT the full
        // 512 MiB pool — into a private heap buffer BEFORE libc::fork, while the
        // parent vCPU is suspended at the trap (atomic). The child copies from THIS
        // buffer, not the parent's now-concurrently-live kernel RAM.
        //
        // Why a copy (not COW): FreeBSD cannot COW bhyve guest sysmem. The memseg
        // is a plain OBJT_SWAP object with no shadow infrastructure (sys/dev/vmm/
        // vmm_mem.c), and it is dual-mapped into the host AND the hypervisor's
        // separate guest vmspace; marking it COW makes the two views diverge to
        // different physical pages -> virtio crash / guest FS corruption (Elena
        // Mihailescu, freebsd-amd64@, 2018-07-30, bhyve live-migration). illumos
        // bhyve confirms independently (wired VMM-reservoir, no shadow). So bhyve
        // MUST copy where KVM (mmap MAP_PRIVATE COW) and HVF (clonefile/mach COW)
        // get laziness free from the OS — but only the LIVE range.
        //
        // Why total_size() is the correct bound: it is the monotonic bump cursor
        // (guest_setup_x86.rs). Every committed GPA — bring-up artifacts, demand_
        // commit #PF pages, commit_range host writes — is allocated below it, and
        // abandoned munmap spans are never reclaimed, so it is a true high-water.
        // [total_size(), X86_MEM_SIZE) is reserved-but-never-touched (demand-zero)
        // and is byte-identical to the child's freshly kernel-zeroed segment.
        // Copying the whole pool forced ~512 MiB resident PER FORK regardless of
        // the guest's working set; this bounds it to the live footprint.
        // SysV-shm cross-process coherence: flush each writable file-backed alias's
        // live sysmem back to its backing FILE before the child forks, so the
        // child's re-`shmat` (which re-reads the file in map_host_alias) sees the
        // parent's stores. This is the fork barrier — the parent vCPU is suspended,
        // so the sysmem read is a consistent snapshot. KVM/HVF don't need this (their
        // alias IS a MAP_SHARED file mapping, coherent for free); bhyve copies
        // file→sysmem, so the file is stale until we push the dirty bytes back here.
        self.flush_shm_aliases();

        let live = self.ram.total_size().min(X86_MEM_SIZE);
        debug_assert!(live <= X86_MEM_SIZE);
        let src = self.vm.map_gpa(0, live.max(1)).ok_or_else(|| {
            TrapError::Hypervisor("bhyve-x86: freeze_ram map_gpa(0, live) NULL".into())
        })?;
        let mut buf = vec![0u8; live];
        // SAFETY: src spans `live` parent sysmem bytes; the parent vCPU is
        // suspended (no concurrent guest write); buf is fresh + disjoint.
        unsafe { std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), live) };
        Ok(buf)
    }

    fn rebuild_child_vm(&mut self, frozen: &[u8]) -> Result<(), TrapError> {
        // CHILD side of a guest fork(2). The child inherited the parent's vmctx
        // (self.vm aliases the parent's live kernel RAM — NOT a usable copy
        // source). Build a fresh, uniquely-named child VM, copy the PRE-FORK
        // frozen RAM into it, re-write the kernel artifacts, create vCPU 0, and
        // SWAP it into the shared handle so the engine's separate `vcpu` field
        // (which shares this Arc) drives the child's fresh vCPU after restore.
        let map_err = |e: OsError| TrapError::Hypervisor(e.to_string());

        let mut child_vm = BhyveVm::create().map_err(map_err)?;
        child_vm.setup_memory(X86_MEM_SIZE).map_err(map_err)?;
        child_vm
            .mmap_memseg(0, VM_SEGID_SYSMEM, X86_MEM_SIZE, PROT_RWX)
            .map_err(map_err)?;

        // Copy ONLY the live high-water captured in `frozen` (frozen.len() =
        // the parent's [0, total_size())). The child segment is the FULL 512 MiB
        // (reserved-lazy + kernel-zeroed by setup_memory above), so the untouched
        // tail [live, X86_MEM_SIZE) stays demand-zero — byte-identical to the
        // parent's never-touched tail — and the GPA plan can still place pages up
        // to the cap. This bounds per-fork resident RAM from ~512 MiB to the live
        // working set (the kernel-owned sysmem is non-COW; see freeze_ram).
        let live = frozen.len();
        let dst = child_vm.map_gpa(0, live.max(1)).ok_or_else(|| {
            TrapError::Hypervisor("bhyve-x86: child map_gpa(0, live) NULL".into())
        })?;
        // SAFETY: frozen is `live` bytes; dst is the first `live` bytes of the
        // child sysmem; disjoint (private buffer vs the child VM mapping).
        unsafe { std::ptr::copy_nonoverlapping(frozen.as_ptr(), dst, live) };

        // Create vCPU 0 on the child VM.
        let child_vcpu = child_vm.add_vcpu().map_err(map_err)?;

        // Swap the child VM into the shared handle's slot (the per-vCPU blob +
        // FP scratch now resolve through the child's ctx) and publish the fresh
        // raw vCPU pointer the engine will `restore` onto.
        let shared = child_vm.shared_handle();
        {
            let mut slot = self.h.slot();
            slot.vm = shared;
            slot.id = 0; // the child's vCPU 0
        }
        self.h.vcpu.store(child_vcpu.vcpu, Ordering::SeqCst);
        self.h.kick_pending.store(false, Ordering::SeqCst);
        self.h.started.store(false, Ordering::SeqCst);

        // Swap the child VM into self. CRITICAL: the OLD self.vm is the inherited
        // parent alias — its Drop would vm_destroy the PARENT's live kernel VM
        // from the child. mem::forget it (the Arc leaks in this child process,
        // which is correct: the parent's VM stays alive for the parent).
        let inherited_parent = std::mem::replace(&mut self.vm, child_vm);
        std::mem::forget(inherited_parent);
        // The fork child OWNS its fresh child VM; its process_exit_cleanup
        // destroys the name-bound node on _exit.
        self.vm_borrowed = false;
        Ok(())
    }

    fn kick_handle(&self) -> Self::KickHandle {
        BhyveKickHandle::for_current_thread(Arc::clone(&self.h.kick_pending))
    }

    fn save_guest_state(&self) -> Vec<u8> {
        // Captured at a ring-0 (LSTAR-stub) syscall block point — the per-thread
        // GPRs/RSP/RIP/RFLAGS + FS/GS base + FP/AVX. See SNAPSHOT_REGS.
        //
        // FAIL LOUD: any failed read makes save return an EMPTY buffer, which
        // `rebind_to_slot` rejects (returns Err) rather than restoring zeroed FS/GS
        // base or silently-dropped SSE/AVX into the reclaimed thread — that is a
        // silent data-corruption bug (Go &c. use SSE). The old code
        // `.unwrap_or_default()` / `.ok().flatten()` swallowed every error and, for
        // FP, conflated a genuine failure with the legitimate "no FP yet" case.
        let vc = self.h.as_bhyve();
        let build = || -> Result<Vec<u8>, TrapError> {
            let vals = vc
                .get_register_set(&SNAPSHOT_REGS)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
            let (fb, fl, fa) = vc
                .get_desc(VM_REG_GUEST_FS)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
            let (gb, gl, ga) = vc
                .get_desc(VM_REG_GUEST_GS)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
            // FP/AVX via the FXSAVE/XSAVE stub (valid at the ring-0 syscall
            // boundary, `started`+CPL-0). `Ok(None)` is the LEGIT "the vCPU has not
            // reached a real syscall yet" case (nothing to preserve); only `Err` is
            // a genuine failure that must abort the reclaim.
            let xsave = BhyveX86Vcpu {
                h: Arc::clone(&self.h),
            }
            .get_xsave()?;
            let mut buf = Vec::with_capacity(SNAPSHOT_REGS.len() * 8 + 33 + carrick_x86::XSAVE_LEN);
            for v in &vals {
                buf.extend_from_slice(&v.to_le_bytes());
            }
            buf.extend_from_slice(&fb.to_le_bytes());
            buf.extend_from_slice(&gb.to_le_bytes());
            for x in [fl, fa, gl, ga] {
                buf.extend_from_slice(&x.to_le_bytes());
            }
            match xsave {
                Some(xs) => {
                    buf.push(1);
                    buf.extend_from_slice(&xs);
                }
                None => buf.push(0),
            }
            Ok(buf)
        };
        // Err -> empty buffer -> rebind_to_slot returns a clean TrapError instead
        // of restoring corruption.
        build().unwrap_or_default()
    }

    fn rebind_to_slot(&mut self, slot: carrick_hal::SlotId, state: &[u8]) -> Result<(), TrapError> {
        let id = slot as c_int;
        let cur = self.h.slot().id;
        // Re-open the recycled (already-activated, long-mode) vCPU and swap it in —
        // only if the slot actually changed (re-binding to the SAME id is a no-op
        // for the handle; the saved state is restored below regardless).
        if id != cur {
            let vm = self.h.slot().vm.clone();
            let vcpu = vm
                .reopen_vcpu(id)
                .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
            self.h.vcpu.store(vcpu.vcpu, Ordering::SeqCst);
            let mut s = self.h.slot();
            s.id = id;
        }
        // A reclaim snapshot that failed to capture is returned EMPTY (or short)
        // by `save_guest_state`; refuse to restore zeroed/garbage state rather than
        // silently corrupt the reclaimed thread. Minimum valid length = the
        // SNAPSHOT_REGS GPRs + FS/GS base (16) + the four 4-byte desc limit/access
        // words (16) + the 1-byte FP-present flag.
        let min_len = SNAPSHOT_REGS.len() * 8 + 33;
        if state.len() < min_len {
            return Err(TrapError::Hypervisor(
                "bhyve reclaim: guest-state snapshot was incomplete (a register/FP \
                 read failed at save); refusing to restore zeroed state"
                    .to_owned(),
            ));
        }
        // Restore the saved per-thread state into the freed vCPU.
        let n = SNAPSHOT_REGS.len();
        let mut vals = Vec::with_capacity(n);
        for i in 0..n {
            let mut b = [0u8; 8];
            b.copy_from_slice(&state[i * 8..i * 8 + 8]);
            vals.push(u64::from_le_bytes(b));
        }
        let rd_u64 = |off: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&state[off..off + 8]);
            u64::from_le_bytes(b)
        };
        let rd_u32 = |off: usize| {
            let mut b = [0u8; 4];
            b.copy_from_slice(&state[off..off + 4]);
            u32::from_le_bytes(b)
        };
        let base = n * 8;
        let fb = rd_u64(base);
        let gb = rd_u64(base + 8);
        let fl = rd_u32(base + 16);
        let fa = rd_u32(base + 20);
        let gl = rd_u32(base + 24);
        let ga = rd_u32(base + 28);
        let mut vc = self.h.as_bhyve();
        vc.set_register_set(&SNAPSHOT_REGS, &vals)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        vc.set_desc(VM_REG_GUEST_FS, fb, fl, fa)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        vc.set_desc(VM_REG_GUEST_GS, gb, gl, ga)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        // Restore FP/AVX if it was captured (the flag byte follows the descriptors).
        let fp_off = base + 32;
        if state.get(fp_off) == Some(&1) && state.len() >= fp_off + 1 + carrick_x86::XSAVE_LEN {
            let mut xs = [0u8; carrick_x86::XSAVE_LEN];
            xs.copy_from_slice(&state[fp_off + 1..fp_off + 1 + carrick_x86::XSAVE_LEN]);
            // Propagate a failed FP/AVX restore: dropping it silently leaves the
            // reclaimed thread with stale SSE/AVX (the save-side bug's twin).
            BhyveX86Vcpu {
                h: Arc::clone(&self.h),
            }
            .set_xsave(&xs)
            .map_err(|e| {
                TrapError::Hypervisor(format!("bhyve reclaim: FP/AVX restore failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn build_sibling_builder(&self) -> Result<Self::SiblingBuilder, TrapError> {
        Ok(BhyveSiblingBuilder {
            vm: self.vm.shared_handle(),
            ram: self.ram.clone(),
            kick_pending: Arc::new(AtomicBool::new(false)),
            pml4_lock: self.pml4_lock.clone(),
        })
    }

    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError> {
        let map_err = |e: OsError| TrapError::Hypervisor(e.to_string());
        // New vCPU on the SHARED VM (shared ctx/CR3/PML4/RAM). add_sibling_vcpu
        // draws a DISTINCT id from the shared allocator.
        let (sibling, id) = builder.vm.add_sibling_vcpu().map_err(map_err)?;
        let vm = BhyveVm::from_shared(builder.vm.clone());
        // Seed the sibling's FP scratch with a MASKED FXSAVE image (FCW=0x037F,
        // MXCSR=0x1F80). A new vCPU's scratch is zeroed sysmem, so the FP stub's
        // first fxrstor would load MXCSR=0 — all SIMD exceptions UNMASKED — and a
        // maskable SSE exception in the guest (Go's compiler trips one; the
        // lighter `go version` does not) then raises #XF (vector 19). Linux clone
        // inherits the parent's FP state; a masked default suffices here (a new Go
        // M starts with fresh FP regs, and what matters for #XF is the MXCSR mask).
        if let Some(host) = vm.map_gpa(X86_FP_SCRATCH_GPA + (id as u64) * 0x1000, 512) {
            // SAFETY: map_gpa proved 512 live sysmem bytes for this vCPU's slot;
            // offsets 0/24/28 are the FXSAVE FCW / MXCSR / MXCSR_MASK fields.
            unsafe {
                std::ptr::write_bytes(host, 0, 512);
                std::ptr::write_unaligned(host as *mut u16, 0x037F);
                std::ptr::write_unaligned(host.add(24) as *mut u32, 0x1F80);
                std::ptr::write_unaligned(host.add(28) as *mut u32, 0x0000_FFFF);
            }
        }
        let h = Arc::new(VcpuHandle {
            vcpu: AtomicPtr::new(sibling.vcpu),
            slot: Mutex::new(VcpuSlot { vm: builder.vm, id }),
            kick_pending: builder.kick_pending,
            started: AtomicBool::new(false),
            fork_entry_pending: AtomicBool::new(false),
        });
        let vcpu = BhyveX86Vcpu { h: Arc::clone(&h) };
        let vmm = BhyveVmm {
            vm,
            ram: builder.ram,
            h,
            vm_borrowed: false,
            pml4_lock: builder.pml4_lock,
        };
        Ok((vmm, vcpu))
    }

    fn set_guest_sp(&self, _vcpu: &Self::Vcpu, sp: u64) -> Result<(), TrapError> {
        // x86 "SP_EL0" analogue is RSP. The engine hands us &self; use the
        // shared single-reg writer (single-threaded engine).
        self.h
            .as_bhyve()
            .set_reg_raw_shared(VM_REG_GUEST_RSP, sp)
            .map_err(|e| TrapError::Hypervisor(format!("bhyve-x86: set RSP: {e}")))
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        Arc::new(BhyveKicker::new())
    }

    fn refresh_shared_after_wait(&mut self) {
        // The parent just reaped a child (`wait4`/`waitid`). The child flushed its
        // writable file-backed `MAP_SHARED` aliases to their files on exit
        // (`process_exit_cleanup`); re-read those files INTO this (parent's) sysmem
        // so a subsequent guest load of a shared page sees the child's stores.
        // bhyve copies file→private sysmem (it can't back a guest segment with a
        // host fd), so without this re-read the parent reads its own stale private
        // copy. A `waitpid` return is a process-exit happens-before barrier, so the
        // file read is a consistent snapshot. KVM/HVF need nothing (their alias IS
        // a host `MAP_SHARED` of the file). Best-effort: a transient map_gpa/pread
        // failure leaves that one alias as stale as before — never fatal.
        for (gpa, fd, offset, read_len) in self.ram.shm_aliases_for_refresh() {
            if read_len == 0 {
                continue;
            }
            let Some(host) = self.vm.map_gpa(gpa, read_len) else {
                continue;
            };
            // SAFETY: map_gpa proved `[gpa, gpa+read_len)` is live sysmem; we read
            // the file into it via pread. The reaped child has exited, so the file
            // holds its final stores.
            let n = unsafe { libc::pread(fd, host as *mut libc::c_void, read_len, offset) };
            let _ = n;
        }
    }

    fn execve_rebuild(
        &mut self,
        _vcpu: &mut Self::Vcpu,
        new_image: &AddressSpace,
    ) -> Result<(), TrapError> {
        // Replace the live image (execve). Build a fresh OWNED VM FIRST (so a
        // bring-up error leaves the old image running — Linux semantics), swap it
        // in, tear down the old VM, and re-point the shared vCPU handle at the
        // fresh vCPU so the engine's separate `vcpu` field follows. Mirrors the
        // old engine's execve_into. The generic engine's `execve_into` calls this
        // then clears the pending-syscall state.
        let map_err = |e: OsError| TrapError::Hypervisor(e.to_string());
        let entry_rip = new_image.entry();
        let initial_rsp = new_image.initial_stack_pointer().ok_or_else(|| {
            TrapError::Hypervisor("bhyve-x86 execve: new_image has no initial stack pointer".into())
        })?;
        let bux = bring_up_x86_elf(new_image, entry_rip, initial_rsp).map_err(map_err)?;

        // Swap in the fresh VM/RAM and publish the fresh vCPU into the shared
        // handle (the engine's vcpu field follows). The OLD VM's teardown is
        // gated on its inner `owns` flag (a vfork child's borrowed old VM is a
        // no-op), so destroy_in_place is unconditional + structurally safe.
        let shared = bux.vm.shared_handle();
        let mut old_vm = std::mem::replace(&mut self.vm, bux.vm);
        old_vm.destroy_in_place();
        self.ram = bux.ram;
        {
            let mut slot = self.h.slot();
            slot.vm = shared;
            slot.id = 0;
        }
        self.h.vcpu.store(bux.vcpu.vcpu, Ordering::SeqCst);
        self.h.kick_pending.store(false, Ordering::SeqCst);
        self.h.started.store(false, Ordering::SeqCst);
        // The fresh VM from bring_up_x86_elf is OWNED.
        self.vm_borrowed = false;
        Ok(())
    }
}

// ─── bring_up ────────────────────────────────────────────────────────────────

/// Bring up a bhyve x86 guest for `image` and wrap it in the generic
/// [`X86EngineCore`]. Uses the existing `bring_up_x86_elf` (the live production
/// bring-up — one contiguous lowmem segment, kernel artifacts, the ring-0 MSR
/// init blob, the vCPU programmed at the new entry via the ring-0 iretq) and
/// adapts its `BroughtUpX86` into the `BhyveVmm`/`BhyveX86Vcpu` shared-handle
/// pair the shared engine drives.
///
/// The long-mode programming for the BOOT vCPU is bhyve's existing ring-0 blob
/// path (not the shared `program_longmode_entry` direct ring-3 entry, which VT-x
/// rejects on bhyve). The shared `program_longmode_entry` IS used on the
/// fork-child / clone-sibling restore path via `set_syscall_msrs`'s blob hook.
pub fn bring_up(image: &AddressSpace) -> Result<X86EngineCore<BhyveVmm>, TrapError> {
    let entry_rip = image.entry();
    let initial_rsp = image.initial_stack_pointer().ok_or_else(|| {
        TrapError::Hypervisor("bhyve-x86 bring_up: image has no initial stack pointer".into())
    })?;
    let bux = bring_up_x86_elf(image, entry_rip, initial_rsp)
        .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
    Ok(engine_from_brought_up(bux))
}

/// Wrap a `BroughtUpX86` (from `bring_up_x86_elf`) into the shared engine.
pub fn engine_from_brought_up(bux: BroughtUpX86) -> X86EngineCore<BhyveVmm> {
    let h = Arc::new(VcpuHandle {
        vcpu: AtomicPtr::new(bux.vcpu.vcpu),
        slot: Mutex::new(VcpuSlot {
            vm: bux.vm.shared_handle(),
            id: 0,
        }),
        kick_pending: Arc::new(AtomicBool::new(false)),
        started: AtomicBool::new(false),
        fork_entry_pending: AtomicBool::new(false),
    });
    let vcpu = BhyveX86Vcpu { h: Arc::clone(&h) };
    let vmm = BhyveVmm {
        vm: bux.vm,
        ram: bux.ram,
        h,
        vm_borrowed: false,
        pml4_lock: Arc::new(std::sync::Mutex::new(())),
    };
    X86EngineCore::from_parts(vmm, vcpu, BHYVE_X86_LAYOUT)
}
