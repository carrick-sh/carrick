//! The FreeBSD/bhyve x86_64 backend on the shared `carrick-x86` scaffold
//! (portability Stage 4 — the bhyve half).
//!
//! `BhyveVmm` (+ `impl X86Vcpu for BhyveX86Vcpu`) is the thin per-VMM trait pair
//! the generic [`carrick_x86::X86EngineCore`] is parameterized over — mirroring
//! `carrick-vmm-kvm`'s `kvm_x86_engine` and `carrick-vmm-nvmm`'s `nvmm_x86_engine`,
//! NOT a copy of the old hand-rolled `BhyveTrapEngine`. The trap loop, register
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
//! one [`VcpuHandle`] (an `Arc`): the raw `*mut Vcpu` lives in an `AtomicPtr`
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

use carrick_hal::OsError;
use carrick_hal::TrapError;
use carrick_mem::memory::AddressSpace;
use carrick_x86::{
    BringupLayout, ForkRamStrategy, MsrInstall, WindowPlan, X86EngineCore, X86Exit, X86Reg, X86Seg,
    X86Vcpu, X86Vmm,
};

use crate::bhyve_kicker::{BhyveKickHandle, BhyveKicker};
use crate::guest_setup_x86::{
    BhyveGuestRam, BroughtUpX86, FP_STUB_DOORBELL_PORT, PROT_RWX, SYSCALL_DOORBELL_PORT,
    VM_SEGID_SYSMEM, X86_FP_SCRATCH_GPA, X86_FP_STUB_GPA, X86_GDT_GPA, X86_MEM_SIZE, X86_PML4_GPA,
    bring_up_x86_elf, program_x86_vcpu_longmode_entry, snapshot_x86_bhyve,
};
use crate::vmm::{BhyveSharedVm, BhyveVcpu, BhyveVm, Vcpu};
use crate::vmm_x86::{
    VM_CAP_HALT_EXIT, VM_REG_GUEST_CR0, VM_REG_GUEST_CR2, VM_REG_GUEST_CR3, VM_REG_GUEST_CR4,
    VM_REG_GUEST_CS, VM_REG_GUEST_EFER, VM_REG_GUEST_FS, VM_REG_GUEST_GS, VM_REG_GUEST_R8,
    VM_REG_GUEST_R9, VM_REG_GUEST_R10, VM_REG_GUEST_R11, VM_REG_GUEST_R12, VM_REG_GUEST_R13,
    VM_REG_GUEST_R14, VM_REG_GUEST_R15, VM_REG_GUEST_RAX, VM_REG_GUEST_RBP, VM_REG_GUEST_RBX,
    VM_REG_GUEST_RCX, VM_REG_GUEST_RDI, VM_REG_GUEST_RDX, VM_REG_GUEST_RFLAGS, VM_REG_GUEST_RIP,
    VM_REG_GUEST_RSI, VM_REG_GUEST_RSP, X86Exit as NativeExit,
};

/// The bhyve x86 kernel-window GPA layout (the §2.5a/`BringupLayout` per-backend
/// choice). bhyve folds the trampoline/GDT/PML4 into its single contiguous
/// lowmem segment at the fixed GPAs the bring-up has always used.
pub const BHYVE_X86_LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE,
    gdt_base: X86_GDT_GPA,
    pml4_base: X86_PML4_GPA,
};

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
/// over [`VcpuHandle`] (so the engine's `vm` and `vcpu` fields can share, and
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
        // stub would mis-fire there; return a clean (zeroed) FP image until the
        // vCPU has trapped at a real syscall (the `started` gate). The engine's
        // sigframe reader needs `Some` either way (a `None` would EIO
        // build_sigframe).
        if !self.h.started.load(Ordering::SeqCst) {
            return Ok(Some([0u8; 512]));
        }
        // SP4.1 CPL gate: `fxsave` can only run at CPL 0 (at ring 3 it #UDs the
        // empty IDT → triple fault). The syscall-boundary path (raise/intra-proc
        // signals + rt_sigreturn) enters via SYSCALL → the LSTAR stub leaves the
        // vCPU in ring 0, so the stub runs. An async (cross-thread kick) signal
        // parks the vCPU at an arbitrary ring-3 PC; there we cannot fxsave, so
        // return a CLEAN (zeroed) FP image.
        let cpl0 = (self.get_raw(VM_REG_GUEST_CS)? & 3) == 0;
        if !cpl0 {
            return Ok(Some([0u8; 512]));
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
                    return Err(TrapError::Hypervisor(format!(
                        "bhyve-x86: VM_EXITCODE_SUSPENDED how={how} (4=TRIPLEFAULT) \
                     rip={rip:#x} cs={cs:#x} (cpl={}); the guest faulted with the \
                     empty IDT before reaching a syscall doorbell",
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
}

// SAFETY: BhyveSharedVm is Send+Sync; the RAM payload is plain bookkeeping the
// materialized engine touches single-threaded.
unsafe impl Send for BhyveSiblingBuilder {}

impl X86Vmm for BhyveVmm {
    type Vcpu = BhyveX86Vcpu;
    type KickHandle = BhyveKickHandle;
    type SiblingBuilder = BhyveSiblingBuilder;

    fn setup_memory(&mut self, _plan: &WindowPlan) -> Result<(), TrapError> {
        // bhyve realizes the plan as ONE contiguous lowmem segment (§2.5a). The
        // segment + the window table are built by `bring_up`; this hook is a
        // no-op (the BhyveVmm `bring_up` produces returns is already mapped).
        Ok(())
    }

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
        // window table, then the contiguous segment via map_gpa.
        for w in &self.ram.windows {
            let w_end = w.va + w.len as u64;
            if gpa >= w.va && gpa < w_end {
                let offset = (gpa - w.va) as usize;
                if w.len.saturating_sub(offset) < len {
                    return None; // straddles the window end
                }
                return self.vm.map_gpa(w.gpa + offset as u64, len);
            }
        }
        None
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

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        // bhyve guest RAM is kernel-owned and NOT copy-on-write across libc::fork
        // (the inherited vmctx aliases the parent's live kernel pages). The whole
        // segment must be eagerly copied into a fresh child VM (§2.5b).
        ForkRamStrategy::EagerCopy
    }

    fn freeze_ram(&self) -> Result<Vec<u8>, TrapError> {
        // Snapshot the parent's ENTIRE [0, X86_MEM_SIZE) sysmem into a private
        // heap buffer BEFORE libc::fork, while the parent vCPU is suspended at the
        // trap (atomic). The child copies from THIS buffer, not the parent's now-
        // concurrently-live kernel RAM (the minherit-COW route was proven not to
        // work for bhyve's in-kernel vCPU writes — see the old fork's negative
        // result). bhyve maps the whole sysmem contiguously at GPA 0.
        let src = self.vm.map_gpa(0, X86_MEM_SIZE).ok_or_else(|| {
            TrapError::Hypervisor("bhyve-x86: freeze_ram map_gpa(0, X86_MEM_SIZE) NULL".into())
        })?;
        let mut buf = vec![0u8; X86_MEM_SIZE];
        // SAFETY: src spans the full X86_MEM_SIZE parent sysmem; the parent vCPU
        // is suspended (no concurrent guest write); buf is fresh + disjoint.
        unsafe { std::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), X86_MEM_SIZE) };
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

        // Eager full-RAM copy from the frozen buffer (kernel-owned, non-COW RAM).
        let dst = child_vm.map_gpa(0, X86_MEM_SIZE).ok_or_else(|| {
            TrapError::Hypervisor("bhyve-x86: child map_gpa(0, X86_MEM_SIZE) NULL".into())
        })?;
        // SAFETY: frozen is X86_MEM_SIZE bytes; dst is the full child sysmem; the
        // regions are disjoint (private buffer vs the child VM mapping).
        unsafe { std::ptr::copy_nonoverlapping(frozen.as_ptr(), dst, X86_MEM_SIZE) };

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

    fn wait_for_vcpu_slot() {
        // No admission cap (bhyve activates vCPUs eagerly; no HVF-style limit).
    }

    fn build_sibling_builder(&self) -> Result<Self::SiblingBuilder, TrapError> {
        Ok(BhyveSiblingBuilder {
            vm: self.vm.shared_handle(),
            ram: self.ram.clone(),
            kick_pending: Arc::new(AtomicBool::new(false)),
        })
    }

    fn materialize_sibling(builder: Self::SiblingBuilder) -> Result<(Self, Self::Vcpu), TrapError> {
        let map_err = |e: OsError| TrapError::Hypervisor(e.to_string());
        // New vCPU on the SHARED VM (shared ctx/CR3/PML4/RAM). add_sibling_vcpu
        // draws a DISTINCT id from the shared allocator.
        let (sibling, id) = builder.vm.add_sibling_vcpu().map_err(map_err)?;
        let vm = BhyveVm::from_shared(builder.vm.clone());
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

    fn process_exit_cleanup(&mut self) {
        // Tear down the bhyve VM node on a forked-child `_exit` (which skips
        // Drop). A vfork-shared (borrowed) VM must NOT be destroyed — the parent
        // owns the node and resumes on it (§2.5c). Carried verbatim from the old
        // engine. The generic engine's `process_exit_cleanup` delegates here.
        if self.vm_borrowed {
            return;
        }
        self.vm.destroy_in_place();
    }

    fn execve_rebuild(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
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
    };
    X86EngineCore::from_parts(vmm, vcpu, BHYVE_X86_LAYOUT)
}

// Keep the FP-stub byte emitter referenced (parity assertion: the carrick-x86
// copy and the bhyve copy must agree; the bhyve copy is still written into guest
// RAM by bring_up_x86_elf's write_fp_stub).
#[cfg(test)]
mod tests {
    #[test]
    fn fp_stub_bytes_agree_with_carrick_x86() {
        assert_eq!(
            crate::guest_setup_x86::fp_stub_bytes(),
            carrick_x86::fp_stub_bytes()
        );
    }
}
