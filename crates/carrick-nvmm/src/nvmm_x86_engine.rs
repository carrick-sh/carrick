//! The NVMM x86_64 backend on the shared `carrick-x86` scaffold (portability S5).
//!
//! `NvmmVmm` (+ `impl X86Vcpu for NvmmVcpu`) is the thin per-VMM trait pair the
//! generic [`carrick_x86::X86EngineCore`] is parameterized over — mirroring
//! `carrick-linux`'s `kvm_x86_engine`, NOT copied from carrick-bhyve. The trap
//! loop, register walk, guest-memory access, snapshot triple, long-mode
//! bring-up, and run-elf loop all live ONCE in `carrick-x86`; this supplies only
//! the NVMM-specific marshalling.
//!
//! NVMM answers the three quirk seams with its BEST mechanism (the doctrine):
//!   - `set_syscall_msrs` → [`MsrInstall::Direct`] (`setstate(STATE_MSRS)` writes
//!     EFER/STAR/LSTAR/SFMASK directly — NO ring-0 WRMSR blob).
//!   - `get_fp` → `Some` (`getstate(STATE_FPU)` ↔ `struct fxsave fpu`, native —
//!     NO FXSAVE stub).
//!   - `fork_ram_strategy` → `Cow` (userspace-HVA RAM → host `libc::fork` is COW
//!     — NEVER freezes RAM / rebuilds the child VM).
//!
//! The IO doorbell exit returns `io.npc` (the next-PC; the kernel does NOT
//! advance RIP — proven in M0), so `run()` fills `resume_pc = exit.io.npc`.

use std::sync::Arc;

use carrick_hal::TrapError;
use carrick_mem::memory::AddressSpace;
use carrick_x86::{
    BringupLayout, ForkRamStrategy, MsrInstall, WindowPlan, WindowRegion, X86EngineCore, X86Exit,
    X86Reg, X86Seg, X86Vcpu, X86Vmm,
};

use crate::nvmm::{
    self, NVMM_PROT_EXEC, NVMM_PROT_READ, NVMM_PROT_WRITE, NVMM_VCPU_EXIT_HALTED,
    NVMM_VCPU_EXIT_IO, NVMM_VCPU_EXIT_NONE, NVMM_X64_CR_CR0, NVMM_X64_CR_CR2, NVMM_X64_CR_CR3,
    NVMM_X64_CR_CR4, NVMM_X64_GPR_R8, NVMM_X64_GPR_R9, NVMM_X64_GPR_R10, NVMM_X64_GPR_R11,
    NVMM_X64_GPR_R12, NVMM_X64_GPR_R13, NVMM_X64_GPR_R14, NVMM_X64_GPR_R15, NVMM_X64_GPR_RAX,
    NVMM_X64_GPR_RBP, NVMM_X64_GPR_RBX, NVMM_X64_GPR_RCX, NVMM_X64_GPR_RDI, NVMM_X64_GPR_RDX,
    NVMM_X64_GPR_RFLAGS, NVMM_X64_GPR_RIP, NVMM_X64_GPR_RSI, NVMM_X64_GPR_RSP, NVMM_X64_MSR_EFER,
    NVMM_X64_MSR_LSTAR, NVMM_X64_MSR_SFMASK, NVMM_X64_MSR_STAR, NVMM_X64_SEG_CS, NVMM_X64_SEG_DS,
    NVMM_X64_SEG_ES, NVMM_X64_SEG_FS, NVMM_X64_SEG_GDT, NVMM_X64_SEG_GS, NVMM_X64_SEG_IDT,
    NVMM_X64_SEG_LDT, NVMM_X64_SEG_SS, NVMM_X64_SEG_TR, NVMM_X64_STATE_CRS, NVMM_X64_STATE_FPU,
    NVMM_X64_STATE_GPRS, NVMM_X64_STATE_MSRS, NVMM_X64_STATE_SEGS, NvmmMachine, NvmmVcpu,
    NvmmX64StateSeg,
};
use crate::nvmm_kicker::{NvmmKickHandle, NvmmKicker};

/// The NVMM x86 kernel-window GPA layout (trampoline/GDT/PML4). Placed at 256
/// MiB — identity-mapped (VA==GPA, compact, under NVMM's `max_ram`) and ABOVE the
/// static binary's low load addresses (a non-PIE ET_EXEC loads at ~2 MiB), so it
/// never collides with an image region (mirrors KVM's `X86_KERNEL_WINDOW_BASE`).
pub const NVMM_X86_LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: 0x1000_0000,
    gdt_base: 0x1000_1000,
    pml4_base: 0x1000_2000,
};

/// Per-region cap so a multi-GiB arena is never fully `mmap`'d (matches the KVM
/// and `carrick-x86` 64 MiB cap).
const MAX_WINDOW_LEN: u64 = 64 * 1024 * 1024;

fn map_err(e: nvmm::NvmmError) -> TrapError {
    TrapError::Hypervisor(e.to_string())
}

// ─── NvmmVmm ─────────────────────────────────────────────────────────────────

/// One mapped guest-RAM region. NVMM's `max_ram` ceiling (128 GiB on VM 201) is
/// far below carrick's guest VA layout (heap 256 GiB, mmap 384 GiB, stack ~1
/// TiB), and `nvmm_gpa_map` ABORTS on an out-of-ceiling GPA, so — exactly like
/// bhyve — we assign each region a COMPACT low GPA from a bump cursor and let the
/// PML4 decouple the guest VA from it. The engine queries guest memory by VA
/// (`GuestMemory::read_bytes(va)`), so we record + resolve by `va` and only use
/// `gpa` for `gpa_map`. (Kernel-window regions are identity: `va == gpa`.)
struct Region {
    va: u64,
    hva: *mut u8,
    len: usize,
}

/// The NVMM `X86Vmm`: an `NvmmMachine` plus the VA-keyed host-HVA region table
/// the engine reads/writes guest memory through (NVMM is the N-mapping model —
/// `hva_map` + `gpa_map` per region — not bhyve's single segment).
pub struct NvmmVmm {
    mach: NvmmMachine,
    regions: Vec<Region>,
}

impl NvmmVmm {
    /// Find the host pointer for guest-VA `[va, va+len)` within a region.
    fn resolve(&self, va: u64, len: usize) -> Option<*mut u8> {
        for r in &self.regions {
            if va >= r.va && va + len as u64 <= r.va + r.len as u64 {
                // SAFETY: bounds proven above; offset stays within the region.
                return Some(unsafe { r.hva.add((va - r.va) as usize) });
            }
        }
        None
    }
}

impl X86Vmm for NvmmVmm {
    type Vcpu = NvmmVcpu;
    type KickHandle = NvmmKickHandle;
    type SiblingBuilder = ();

    /// Realize the plan as N compact-GPA regions. The plan's `gpa` is the
    /// (already compact) GPA the PML4 maps `va` to; `hva_map`+`gpa_map` backs it
    /// and we record `va → hva` for the engine's by-VA accesses.
    fn setup_memory(&mut self, plan: &WindowPlan) -> Result<(), TrapError> {
        for r in &plan.regions {
            let len = (r.len as usize)
                .next_multiple_of(0x1000)
                .min(MAX_WINDOW_LEN as usize);
            if len == 0 || self.resolve(r.va, len).is_some() {
                continue;
            }
            let mut prot = 0;
            if r.read {
                prot |= NVMM_PROT_READ;
            }
            if r.write {
                prot |= NVMM_PROT_WRITE;
            }
            if r.exec {
                prot |= NVMM_PROT_EXEC;
            }
            // hva_map + gpa_map a fresh anonymous host region at the compact GPA.
            let hva = self.mach.map_guest_ram(r.gpa, len, prot).map_err(map_err)?;
            self.regions.push(Region { va: r.va, hva, len });
        }
        Ok(())
    }

    fn write_gpa(&self, va: u64, bytes: &[u8]) -> Result<(), TrapError> {
        // Called with a guest VA (image region start) or an identity-mapped
        // kernel-window GPA (== its VA). Resolve uniformly by VA.
        let host = self.resolve(va, bytes.len()).ok_or_else(|| {
            TrapError::Hypervisor(format!("nvmm-x86: write_gpa va 0x{va:x} unmapped"))
        })?;
        // SAFETY: resolve proved [host, host+len) is within a live region.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len()) };
        Ok(())
    }

    fn host_ptr(&self, va: u64, len: usize) -> Option<*mut u8> {
        self.resolve(va, len)
    }

    fn add_vcpu(&mut self) -> Result<Self::Vcpu, TrapError> {
        self.mach.create_vcpu(0).map_err(map_err)
    }

    fn fork_ram_strategy(&self) -> ForkRamStrategy {
        // Userspace-HVA RAM (MAP_PRIVATE|MAP_ANON) → host libc::fork is COW.
        ForkRamStrategy::Cow
    }

    fn kick_handle(&self) -> Self::KickHandle {
        NvmmKickHandle::for_current_thread()
    }

    fn build_sibling_builder(&self) -> Result<Self::SiblingBuilder, TrapError> {
        // M2: sibling vCPUs on the shared NVMM machine (clone(CLONE_THREAD)).
        Err(TrapError::Hypervisor(
            "nvmm-x86: sibling vCPUs are M2 (not in M1 hello)".into(),
        ))
    }

    fn materialize_sibling(_builder: ()) -> Result<(Self, Self::Vcpu), TrapError> {
        Err(TrapError::Hypervisor(
            "nvmm-x86: sibling vCPUs are M2 (not in M1 hello)".into(),
        ))
    }

    fn set_guest_sp(&self, _vcpu: &Self::Vcpu, _sp: u64) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "nvmm-x86: set_guest_sp is M2 (vfork; not in M1 hello)".into(),
        ))
    }

    fn fresh_fork_kicker(&self) -> Arc<dyn carrick_hal::VcpuRegistry> {
        Arc::new(NvmmKicker::new())
    }
}

// SAFETY: NvmmVmm holds the libnvmm machine handle + raw HVA pointers valid in
// every thread of the process (threads share the address space). Mirrors the
// KVM/bhyve backends' `Send` over their VM handle.
unsafe impl Send for NvmmVmm {}

// ─── impl X86Vcpu for NvmmVcpu ───────────────────────────────────────────────

/// Pack an `X86Seg` (long-mode `base`/`limit`/packed-`ar`) into an
/// `NvmmX64StateSeg`.
///
/// The shared `carrick_x86::seg_ar` emits the **VMX** access-rights layout
/// (Intel SDM vol.3 §24.4.1): type[0:3], s[4], dpl[5:6], p[7], avl[12], l[13],
/// db[14], g[15]. NVMM's `attrib` is a **contiguous bitfield** (confirmed on-box
/// + grounding doc): type[0:3], s[4], dpl[5:6], p[7], avl[8], l[9], def[10],
/// g[11]. The low byte (type/s/dpl/p) is identical; the high flags move, so we
/// repack avl/l/db(def)/g into NVMM's positions. (Getting this wrong leaves CS
/// without its 64-bit `l` bit → the guest never runs long-mode ring-3 → spin.)
fn seg_to_nvmm(selector: u16, base: u64, limit: u32, ar: u32) -> NvmmX64StateSeg {
    let bit = |n: u32| (ar >> n) & 1;
    let attrib = (ar & 0xFF) as u16            // type/s/dpl/p (identical low byte)
        | (bit(12) << 8) as u16                // AVL: VMX 12 → NVMM 8
        | (bit(13) << 9) as u16                // L  : VMX 13 → NVMM 9
        | (bit(14) << 10) as u16               // D/B (def): VMX 14 → NVMM 10
        | (bit(15) << 11) as u16; // G  : VMX 15 → NVMM 11
    NvmmX64StateSeg {
        selector,
        attrib,
        limit,
        base,
    }
}

/// Where an [`X86Reg`] lives in `NvmmX64State`: a `(sub-area flag, array,
/// index)` tuple. CR0..4 → `crs[]`, EFER → `msrs[]`, everything else → `gprs[]`.
/// The arrays are all `[u64]`, so get/set is one uniform indexed access.
enum RegLoc {
    Cr(usize),
    Efer,
    Gpr(usize),
}

fn reg_loc(reg: X86Reg) -> RegLoc {
    use X86Reg::*;
    match reg {
        Cr0 => RegLoc::Cr(NVMM_X64_CR_CR0),
        Cr2 => RegLoc::Cr(NVMM_X64_CR_CR2),
        Cr3 => RegLoc::Cr(NVMM_X64_CR_CR3),
        Cr4 => RegLoc::Cr(NVMM_X64_CR_CR4),
        Efer => RegLoc::Efer,
        Rax => RegLoc::Gpr(NVMM_X64_GPR_RAX),
        Rbx => RegLoc::Gpr(NVMM_X64_GPR_RBX),
        Rcx => RegLoc::Gpr(NVMM_X64_GPR_RCX),
        Rdx => RegLoc::Gpr(NVMM_X64_GPR_RDX),
        Rsi => RegLoc::Gpr(NVMM_X64_GPR_RSI),
        Rdi => RegLoc::Gpr(NVMM_X64_GPR_RDI),
        Rbp => RegLoc::Gpr(NVMM_X64_GPR_RBP),
        Rsp => RegLoc::Gpr(NVMM_X64_GPR_RSP),
        R8 => RegLoc::Gpr(NVMM_X64_GPR_R8),
        R9 => RegLoc::Gpr(NVMM_X64_GPR_R9),
        R10 => RegLoc::Gpr(NVMM_X64_GPR_R10),
        R11 => RegLoc::Gpr(NVMM_X64_GPR_R11),
        R12 => RegLoc::Gpr(NVMM_X64_GPR_R12),
        R13 => RegLoc::Gpr(NVMM_X64_GPR_R13),
        R14 => RegLoc::Gpr(NVMM_X64_GPR_R14),
        R15 => RegLoc::Gpr(NVMM_X64_GPR_R15),
        Rip => RegLoc::Gpr(NVMM_X64_GPR_RIP),
        Rflags => RegLoc::Gpr(NVMM_X64_GPR_RFLAGS),
    }
}

/// The `NvmmX64State.segs[]` index for an [`X86Seg`].
fn seg_index(seg: X86Seg) -> usize {
    match seg {
        X86Seg::Cs => NVMM_X64_SEG_CS,
        X86Seg::Ds => NVMM_X64_SEG_DS,
        X86Seg::Es => NVMM_X64_SEG_ES,
        X86Seg::Fs => NVMM_X64_SEG_FS,
        X86Seg::Gs => NVMM_X64_SEG_GS,
        X86Seg::Ss => NVMM_X64_SEG_SS,
        X86Seg::Tr => NVMM_X64_SEG_TR,
        X86Seg::Ldtr => NVMM_X64_SEG_LDT,
        X86Seg::Gdtr => NVMM_X64_SEG_GDT,
        X86Seg::Idtr => NVMM_X64_SEG_IDT,
    }
}

impl NvmmVcpu {
    /// Read-modify-write the `segs[idx].base` field (FS/GS base programming).
    fn set_seg_base(&mut self, idx: usize, v: u64) -> Result<(), TrapError> {
        let mut st = self.get_state(NVMM_X64_STATE_SEGS).map_err(map_err)?;
        st.segs[idx].base = v;
        self.set_state(&st, NVMM_X64_STATE_SEGS).map_err(map_err)
    }
}

impl X86Vcpu for NvmmVcpu {
    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        // get_state is `&self` (FFI-handle pattern). One fetch of all three
        // sub-areas; pick the field per `reg_loc`.
        let st = self
            .get_state(NVMM_X64_STATE_CRS | NVMM_X64_STATE_MSRS | NVMM_X64_STATE_GPRS)
            .map_err(map_err)?;
        Ok(match reg_loc(reg) {
            RegLoc::Cr(i) => st.crs[i],
            RegLoc::Efer => st.msrs[NVMM_X64_MSR_EFER],
            RegLoc::Gpr(i) => st.gprs[i],
        })
    }

    fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError> {
        // Get-then-set only the touched sub-area (NVMM setstate pushes just the
        // requested flags).
        let flag = match reg_loc(reg) {
            RegLoc::Cr(_) => NVMM_X64_STATE_CRS,
            RegLoc::Efer => NVMM_X64_STATE_MSRS,
            RegLoc::Gpr(_) => NVMM_X64_STATE_GPRS,
        };
        let mut st = self.get_state(flag).map_err(map_err)?;
        match reg_loc(reg) {
            RegLoc::Cr(i) => st.crs[i] = v,
            RegLoc::Efer => st.msrs[NVMM_X64_MSR_EFER] = v,
            RegLoc::Gpr(i) => st.gprs[i] = v,
        }
        self.set_state(&st, flag).map_err(map_err)
    }

    fn set_segment(
        &mut self,
        seg: X86Seg,
        base: u64,
        limit: u32,
        ar: u32,
    ) -> Result<(), TrapError> {
        let mut st = self.get_state(NVMM_X64_STATE_SEGS).map_err(map_err)?;
        // Selector is cosmetic in long mode (hidden base/limit/ar drive it);
        // keep CS=0x23, SS/DS/ES=0x1B self-describing, others 0.
        let sel = match seg {
            X86Seg::Cs => 0x23,
            X86Seg::Ss | X86Seg::Ds | X86Seg::Es => 0x1B,
            _ => 0,
        };
        st.segs[seg_index(seg)] = seg_to_nvmm(sel, base, limit, ar);
        self.set_state(&st, NVMM_X64_STATE_SEGS).map_err(map_err)
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        Ok(self.get_state(NVMM_X64_STATE_SEGS).map_err(map_err)?.segs[NVMM_X64_SEG_FS].base)
    }

    fn set_fs_base(&mut self, v: u64) -> Result<(), TrapError> {
        self.set_seg_base(NVMM_X64_SEG_FS, v)
    }

    fn get_gs_base(&self) -> Result<u64, TrapError> {
        Ok(self.get_state(NVMM_X64_STATE_SEGS).map_err(map_err)?.segs[NVMM_X64_SEG_GS].base)
    }

    fn set_gs_base(&mut self, v: u64) -> Result<(), TrapError> {
        self.set_seg_base(NVMM_X64_SEG_GS, v)
    }

    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError> {
        // Direct MSR install: setstate(STATE_MSRS) writes STAR/LSTAR/SFMASK
        // (EFER is set separately). NO ring-0 WRMSR blob.
        let mut st = self.get_state(NVMM_X64_STATE_MSRS).map_err(map_err)?;
        st.msrs[NVMM_X64_MSR_STAR] = star;
        st.msrs[NVMM_X64_MSR_LSTAR] = lstar;
        st.msrs[NVMM_X64_MSR_SFMASK] = sfmask;
        self.set_state(&st, NVMM_X64_STATE_MSRS).map_err(map_err)?;
        Ok(MsrInstall::Direct)
    }

    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
        // Native FP: getstate(STATE_FPU) ↔ struct fxsave (512 bytes). NO stub.
        let st = self.get_state(NVMM_X64_STATE_FPU).map_err(map_err)?;
        Ok(Some(st.fpu.bytes))
    }

    fn set_fp(&mut self, fx: &[u8; 512]) -> Result<bool, TrapError> {
        let mut st = self.get_state(NVMM_X64_STATE_FPU).map_err(map_err)?;
        st.fpu.bytes = *fx;
        self.set_state(&st, NVMM_X64_STATE_FPU).map_err(map_err)?;
        Ok(true)
    }

    fn run(&mut self) -> Result<X86Exit, TrapError> {
        // Bound the consecutive host-internal (NONE) re-entries so a wedged guest
        // surfaces as an error instead of spinning the (nested) host forever.
        let mut spurious = 0u32;
        loop {
            let exit = self.run_until_exit().map_err(map_err)?;
            match exit.reason {
                NVMM_VCPU_EXIT_NONE => {
                    spurious += 1;
                    if spurious > 1_000_000 {
                        return Err(TrapError::Hypervisor(
                            "nvmm-x86: >1e6 consecutive NONE exits (wedged guest?)".into(),
                        ));
                    }
                    continue; // host-internal exit; resume
                }
                NVMM_VCPU_EXIT_IO => {
                    let io = exit.io();
                    if io.port != carrick_hal::SYSCALL_DOORBELL_PORT {
                        return Err(TrapError::Hypervisor(format!(
                            "nvmm-x86: unexpected OUT to port 0x{:04X}",
                            io.port
                        )));
                    }
                    // The IO exit hands back io.npc (the next-PC; the kernel does
                    // NOT advance RIP — proven in M0). Resume there directly.
                    let st = self.get_state(NVMM_X64_STATE_GPRS).map_err(map_err)?;
                    let frame = carrick_guest_mem::X8664SyscallFrame {
                        rax: st.gprs[NVMM_X64_GPR_RAX],
                        rdi: st.gprs[NVMM_X64_GPR_RDI],
                        rsi: st.gprs[NVMM_X64_GPR_RSI],
                        rdx: st.gprs[NVMM_X64_GPR_RDX],
                        r10: st.gprs[NVMM_X64_GPR_R10],
                        r8: st.gprs[NVMM_X64_GPR_R8],
                        r9: st.gprs[NVMM_X64_GPR_R9],
                    };
                    return Ok(X86Exit::Syscall {
                        frame,
                        resume_pc: io.npc,
                    });
                }
                NVMM_VCPU_EXIT_HALTED => return Ok(X86Exit::Halt),
                other => {
                    // Enrich with RIP (and the raw union head) so a long-mode /
                    // ring-3-entry fault is diagnosable (spec risk #2).
                    let rip = self
                        .get_state(NVMM_X64_STATE_GPRS)
                        .map(|s| s.gprs[NVMM_X64_GPR_RIP])
                        .unwrap_or(0);
                    return Err(TrapError::Hypervisor(format!(
                        "nvmm-x86: unexpected exit reason 0x{other:x} at rip=0x{rip:x} \
                         u={:02x?}",
                        exit.u
                    )));
                }
            }
        }
    }

    fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
        // NVMM exits on HLT (NVMM_VCPU_EXIT_HALTED) by default.
        Ok(())
    }
}

/// Where the compact-GPA bump cursor for high VAs starts (512 MiB) — above the
/// kernel window (256 MiB base + its PML4 1.75 MiB capacity) AND above the static
/// image's low load region, so compact runtime GPAs never collide with either.
const COMPACT_GPA_BASE: u64 = 0x2000_0000;

/// Rewrite the shared (identity GPA=VA) [`WindowPlan`] into one with COMPACT
/// GPAs for NVMM: kernel-window regions (trampoline/GDT/PML4, already low) stay
/// identity; every other region (high image/heap/mmap/stack VAs) is reassigned a
/// GPA from a bump cursor so it fits under NVMM's `max_ram` ceiling. The `va`
/// field is preserved, so `build_pml4` maps each guest VA → its compact GPA.
fn compact_plan(plan: &WindowPlan, layout: BringupLayout) -> WindowPlan {
    let mut cursor = COMPACT_GPA_BASE;
    let mut regions = Vec::with_capacity(plan.regions.len());
    for r in &plan.regions {
        let len = (r.len.next_multiple_of(0x1000)).min(MAX_WINDOW_LEN);
        let is_kernel = r.gpa == layout.trampoline_base
            || r.gpa == layout.gdt_base
            || r.gpa == layout.pml4_base;
        let gpa = if is_kernel {
            r.gpa // identity (already compact + low)
        } else {
            let g = cursor;
            cursor += len;
            g
        };
        regions.push(WindowRegion { gpa, len, ..*r });
    }
    WindowPlan { regions }
}

// ─── bring_up ────────────────────────────────────────────────────────────────

/// Bring up an NVMM x86 guest for `image` and wrap it in the generic
/// [`X86EngineCore`]. Assigns compact GPAs (NVMM's `max_ram` ceiling +
/// abort-on-overflow `gpa_map`), mmap+hva_map+gpa_map's every region, writes the
/// ELF bytes + the trampoline/GDT/PML4 images, creates the vCPU, and programs
/// long mode via the shared [`carrick_x86::program_longmode_entry`].
pub fn bring_up(image: &AddressSpace) -> Result<X86EngineCore<NvmmVmm>, TrapError> {
    nvmm::init().map_err(map_err)?;
    let mach = NvmmMachine::create().map_err(map_err)?;
    let mut vmm = NvmmVmm {
        mach,
        regions: Vec::new(),
    };

    // 1. Shared region walk (identity), then remap to compact GPAs + map them.
    let plan = compact_plan(
        &carrick_x86::plan_windows(image, NVMM_X86_LAYOUT)?,
        NVMM_X86_LAYOUT,
    );
    vmm.setup_memory(&plan)?;

    // 2. Copy each ELF/runtime region's bytes into the mapped guest RAM (by VA).
    for region in image.regions() {
        if region.end <= carrick_mem::memory::LINUX_NULL_GUARD_END {
            continue;
        }
        let bytes = region.bytes();
        if !bytes.is_empty() {
            vmm.write_gpa(region.start, bytes)?;
        }
    }

    // 3. Write the bring-up byte images (trampoline + GDT + PML4). The PML4 maps
    //    each guest VA → its compact GPA; CR3 = the (compact, low) pml4_base.
    let pml4_bytes = carrick_x86::build_pml4(&plan, NVMM_X86_LAYOUT)?;
    carrick_x86::write_bringup_images(&vmm, NVMM_X86_LAYOUT, &pml4_bytes)?;

    // 4. Create the vCPU and program long mode (CR/EFER/segs/GDTR/MSRs).
    let mut vcpu = vmm.add_vcpu()?;
    let rsp = image
        .initial_stack_pointer()
        .unwrap_or(carrick_mem::memory::LINUX_STACK_TOP);
    // NVMM is MsrInstall::Direct — the SYSCALL MSRs are live; no ring-0 blob.
    let _install =
        carrick_x86::program_longmode_entry(&mut vcpu, NVMM_X86_LAYOUT, image.entry(), rsp)?;

    // 5. Ring-3 entry. `program_longmode_entry` programs a DIRECT ring-3 entry
    //    (CS DPL3 + RIP=user entry). NVMM/VT-x will NOT vm-enter directly into a
    //    ring-3 CS via setstate (spec risk #2 — confirmed on VM 201: every state
    //    field is correct, yet the first nvmm_vcpu_run never reaches the doorbell).
    //    So override to enter in ring-0 at a 1-instruction `iretq` stub that pops
    //    a pre-built ring-3 frame — the canonical CPL0→CPL3 transition VT-x always
    //    accepts. (bhyve needed an analogous ring-0 init blob for VT-x reasons.)
    install_iretq_ring3_entry(&vmm, &mut vcpu, image.entry(), rsp)?;

    Ok(X86EngineCore::from_parts(vmm, vcpu, NVMM_X86_LAYOUT))
}

/// Offsets within the (exec, supervisor) trampoline page reused for the ring-3
/// entry stub: the `iretq` instruction and the 5-qword `iretq` frame. Both are
/// host-written at bring-up (so the page's guest RO/exec perms don't matter), and
/// the guest only fetches the stub + pops the frame.
const IRETQ_STUB_OFF: u64 = 0x100;
const IRETQ_FRAME_OFF: u64 = 0x800;

/// Program a ring-0 → ring-3 `iretq` entry (the spec-risk-#2 fallback). Writes a
/// one-byte-opcode `iretq` stub + a ring-3 `iretq` frame into the trampoline
/// page, then overrides CS=ring-0/RIP=stub/RSP=frame so the first `nvmm_vcpu_run`
/// vm-enters in ring-0 and `iretq`s into the user entry.
fn install_iretq_ring3_entry(
    vmm: &NvmmVmm,
    vcpu: &mut NvmmVcpu,
    user_entry: u64,
    user_rsp: u64,
) -> Result<(), TrapError> {
    let stub_gpa = NVMM_X86_LAYOUT.trampoline_base + IRETQ_STUB_OFF;
    let frame_gpa = NVMM_X86_LAYOUT.trampoline_base + IRETQ_FRAME_OFF;

    // `iretq` = 48 CF. Pops RIP, CS, RFLAGS, RSP, SS (low→high).
    vmm.write_gpa(stub_gpa, &[0x48, 0xCF])?;
    // Ring-3 iretq frame: user CS=0x23 (GDT[4] uCS64), user SS=0x1B (GDT[3] uSS),
    // RFLAGS=0x2 (reserved bit only).
    let mut frame = [0u8; 40];
    frame[0..8].copy_from_slice(&user_entry.to_le_bytes());
    frame[8..16].copy_from_slice(&0x23u64.to_le_bytes());
    frame[16..24].copy_from_slice(&0x2u64.to_le_bytes());
    frame[24..32].copy_from_slice(&user_rsp.to_le_bytes());
    frame[32..40].copy_from_slice(&0x1Bu64.to_le_bytes());
    vmm.write_gpa(frame_gpa, &frame)?;

    // Enter in ring-0: CS=GDT[1] kCS64 sel 0x08 (DPL0, L=1, exec/read, g=1),
    // SS=GDT[2] kSS sel 0x10, at the stub, RSP = the frame. The VMX-packed
    // access-rights (the shared `seg_ar` layout): ring-0 CS64 type=0xB|S|P|L|G,
    // ring-0 SS type=3|S|P|D/B|G. The selector must be the ring-0 (RPL0)
    // selector, so write the segs directly (the generic set_segment hardcodes the
    // ring-3 selectors).
    let cs0_ar = 0xB | (1 << 4) | (1 << 7) | (1 << 13) | (1 << 15);
    let ss0_ar = 0x3 | (1 << 4) | (1 << 7) | (1 << 14) | (1 << 15);
    let mut st = vcpu.get_state(NVMM_X64_STATE_SEGS).map_err(map_err)?;
    st.segs[NVMM_X64_SEG_CS] = seg_to_nvmm(0x08, 0, 0xFFFF_FFFF, cs0_ar);
    st.segs[NVMM_X64_SEG_SS] = seg_to_nvmm(0x10, 0, 0xFFFF_FFFF, ss0_ar);
    vcpu.set_state(&st, NVMM_X64_STATE_SEGS).map_err(map_err)?;
    vcpu.set_gpr(X86Reg::Rip, stub_gpa)?;
    vcpu.set_gpr(X86Reg::Rsp, frame_gpa)?;
    Ok(())
}
