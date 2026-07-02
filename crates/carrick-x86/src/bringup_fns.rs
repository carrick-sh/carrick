//! The `X86Vcpu`/`X86Vmm`-generic x86 guest bring-up free functions (design §2.2).
//!
//! These are the Axis-2 *pure functions* the spec hoists out of the per-VMM
//! copies (`carrick-vmm-kvm/src/{guest_setup_x86,trap_engine_x86,run_elf_x86}.rs`
//! and bhyve's analogues): the window plan, the long-mode programming sequence,
//! the snapshot/restore/seed triple, and the M2 run-elf service loop. Each is
//! generic over the thin [`crate::X86Vcpu`]/[`crate::X86Vmm`] trait pair, so a backend that
//! implements the pair gets all of this for free.
//!
//! ## Why a [`BringupLayout`]
//!
//! The CR/EFER/segment/MSR *values* are ISA constants (from
//! [`carrick_hal::x8664_arch::X8664BootSysregs`]). The GPAs the kernel-only
//! structures (LSTAR trampoline, GDT, PML4 root = CR3, fault tables) live at are a genuine
//! per-backend choice: KVM places them in a low 256 MiB window (the host
//! 36-bit physical-address ceiling caps CR3 there), bhyve folds them into its
//! single contiguous lowmem segment at different offsets. So the layout GPAs
//! are passed in — the *sequence* (which registers/segments/MSRs to program,
//! in what order, with which validation-safe grouping) is shared.

use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_hal::{GuestEntryRegs, TrapError};
use carrick_mem::memory::{AddressSpace, LINUX_NULL_GUARD_END};
use carrick_mem::pml4::{Pml4MapSpec, pml4_tables};

use crate::vmm::{MsrInstall, WindowPlan, WindowRegion, X86Reg, X86Seg, X86Vcpu};

// ─── Segment access-rights (VMX/long-mode packed encoding) ───────────────────
//
// The shared bring-up programs each segment as `(base, limit, ar)` where `ar`
// is the standard packed access-rights word. The backend's `set_segment`
// unpacks it into its native descriptor struct (KVM `kvm_segment`, bhyve
// `seg_desc`, NVMM `NvmmX64StateSeg`). Bit layout (Intel SDM vol. 3 §24.4.1
// "Guest Register State" / VMX segment access-rights):
//   bits  3:0  = type
//   bit   4    = S   (1 = code/data, 0 = system)
//   bits  6:5  = DPL
//   bit   7    = P   (present)
//   bit  12    = AVL
//   bit  13    = L   (64-bit code segment)
//   bit  14    = D/B
//   bit  15    = G   (granularity)
//   bit  16    = unusable (1 = segment is not usable)

/// Pack a long-mode segment access-rights word. Eight by-position fields mirror
/// the descriptor bit layout (Intel SDM vol. 3 §24.4.1); a struct would obscure
/// the encoding.
#[allow(clippy::too_many_arguments)]
const fn seg_ar(
    type_: u32,
    s: u32,
    dpl: u32,
    present: u32,
    l: u32,
    db: u32,
    g: u32,
    unusable: u32,
) -> u32 {
    (type_ & 0xF)
        | (s << 4)
        | (dpl << 5)
        | (present << 7)
        | (l << 13)
        | (db << 14)
        | (g << 15)
        | (unusable << 16)
}

/// Code segment type nibble: 0xB = execute/read/ACCESSED. The accessed bit MUST
/// be set; KVM validates segment access-rights on entry and rejects an unset
/// accessed bit with EINVAL on some kernels (same lesson as the bhyve M1 VT-x
/// accessed-bit blocker). Source: Intel SDM vol. 3 §3.4.5.1.
const CODE_SEG_TYPE: u32 = 11;
/// Data segment type nibble: 0x3 = read/write/ACCESSED.
const DATA_SEG_TYPE: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LongModeSegmentState {
    pub cs_ar: u32,
    pub data_ar: u32,
    pub kernel_cs_ar: u32,
    pub kernel_data_ar: u32,
    pub tr_ar: u32,
    pub ldtr_ar: u32,
    pub gdt_limit: u32,
}

pub fn long_mode_segment_state() -> LongModeSegmentState {
    LongModeSegmentState {
        // User CS64: GDT[4] sel 0x23, DPL3, L=1, exec/read/accessed.
        cs_ar: seg_ar(
            CODE_SEG_TYPE,
            1,
            3,
            1,
            /*l*/ 1,
            /*db*/ 0,
            /*g*/ 1,
            0,
        ),
        // User SS/DS/ES/FS/GS: GDT[3] sel 0x1B, DPL3, data/write/accessed, db=1.
        data_ar: seg_ar(
            DATA_SEG_TYPE,
            1,
            3,
            1,
            /*l*/ 0,
            /*db*/ 1,
            /*g*/ 1,
            0,
        ),
        // Kernel CS64/SS used while parked in the LSTAR stub before SYSRETQ.
        kernel_cs_ar: seg_ar(
            CODE_SEG_TYPE,
            1,
            0,
            1,
            /*l*/ 1,
            /*db*/ 0,
            /*g*/ 1,
            0,
        ),
        kernel_data_ar: seg_ar(
            DATA_SEG_TYPE,
            1,
            0,
            1,
            /*l*/ 0,
            /*db*/ 1,
            /*g*/ 1,
            0,
        ),
        // TR: minimal valid 32-bit busy TSS (type 11, system, DPL0, present, g=1).
        tr_ar: seg_ar(11, /*s*/ 0, 0, 1, 0, 0, 1, 0),
        // LDTR: unusable.
        ldtr_ar: seg_ar(0, 0, 0, 0, 0, 0, 0, /*unusable*/ 1),
        gdt_limit: (X8664GuestArch::bootstrap_sysregs().gdt.len() as u32) * 8 - 1,
    }
}

/// Where the kernel-only bring-up structures (LSTAR trampoline, GDT, PML4 root)
/// live in guest-physical space, and the resulting CR3. Per-backend (§ module
/// doc): the *values* programmed are ISA constants; only these GPAs vary.
#[derive(Debug, Clone, Copy)]
pub struct BringupLayout {
    /// GPA of the LSTAR trampoline (`out %al, $DOORBELL` + `sysretq`) = LSTAR MSR.
    pub trampoline_base: u64,
    /// GPA of the 5-entry boot GDT.
    pub gdt_base: u64,
    /// GPA of the PML4 root (= CR3 value). Must be a valid host physical address
    /// (KVM: below the host's 36-bit ceiling).
    pub pml4_base: u64,
}

// ─── plan_windows ────────────────────────────────────────────────────────────

/// Walk an image's regions into the shared [`WindowPlan`] (the §2.5a union the
/// backend realizes as N slots (KVM) or one contiguous segment (bhyve)). Image-
/// based, no vCPU. User regions cover the full address-space extent; the
/// kernel-only structures (trampoline/GDT/PML4/fault tables) are appended as supervisor-only
/// regions at the `layout` GPAs.
pub fn plan_windows(image: &AddressSpace, layout: BringupLayout) -> Result<WindowPlan, TrapError> {
    let mut regions: Vec<WindowRegion> = Vec::new();

    for region in image.regions() {
        // Skip the null guard.
        if region.end <= LINUX_NULL_GUARD_END {
            continue;
        }
        let raw_len = region.end.saturating_sub(region.start);
        if raw_len == 0 {
            continue;
        }
        // Identity GPA = VA for every image region.
        regions.push(WindowRegion {
            va: region.start,
            gpa: region.start,
            len: raw_len,
            read: region.perms.read,
            write: region.perms.write,
            exec: region.perms.execute,
            user: true,
            shared: region.shared,
        });
    }

    // Kernel window: trampoline (exec, RO), GDT (RO), PML4 (RW), and
    // exception-doorbell tables — supervisor-only.
    regions.push(WindowRegion {
        va: layout.trampoline_base,
        gpa: layout.trampoline_base,
        len: 0x1000,
        read: true,
        write: false,
        exec: true,
        user: false,
        shared: false,
    });
    regions.push(WindowRegion {
        va: layout.gdt_base,
        gpa: layout.gdt_base,
        len: 0x1000,
        read: true,
        write: false,
        exec: false,
        user: false,
        shared: false,
    });
    regions.push(WindowRegion {
        va: layout.pml4_base,
        gpa: layout.pml4_base,
        len: crate::vmm::X86_PML4_CAPACITY,
        read: true,
        write: true,
        exec: false,
        user: false,
        shared: false,
    });
    crate::fault::add_fault_windows(&mut regions, layout);

    // Carry the images' read-only page spans so `build_pml4` can re-apply the
    // per-segment write protection the merged regions escalated away. Clamp
    // below the null guard (those pages were skipped above).
    let ro_spans = image
        .ro_spans()
        .iter()
        .filter_map(|span| {
            let end = span.start.checked_add(span.len)?;
            let start = span.start.max(LINUX_NULL_GUARD_END);
            (end > start).then_some(carrick_mem::elf::RoSpan {
                start,
                len: end - start,
                exec: span.exec,
            })
        })
        .collect();

    Ok(WindowPlan { regions, ro_spans })
}

/// Build the x86-64 4-level page-table image (CR3 = `layout.pml4_base`) for the
/// plan. All mappings are identity (VA == GPA). The kernel-only regions are
/// supervisor-only; user regions carry per-REGION W/X bits, then the images'
/// read-only page spans (`plan.ro_spans`) are re-applied over the built tables
/// so `.text`/`.rodata` leaves lose R/W (a guest store #PFs with PFEC.P=1 →
/// SEGV_ACCERR) — the merged regions escalated writability away.
pub fn build_pml4(plan: &WindowPlan, layout: BringupLayout) -> Result<Vec<u8>, TrapError> {
    let mut maps: Vec<Pml4MapSpec> = Vec::with_capacity(plan.regions.len());
    for r in &plan.regions {
        let va = r.va & !0xFFF; // page-align down
        let gpa = r.gpa & !0xFFF;
        let aligned_len = ((r.va + r.len + 0xFFF) & !0xFFF) - va;
        if aligned_len == 0 {
            continue;
        }
        maps.push(Pml4MapSpec {
            va,
            gpa,
            len: aligned_len,
            user: r.user,
            write: r.write,
            exec: r.exec,
        });
    }
    let bytes = pml4_tables(
        &maps,
        layout.pml4_base,
        crate::vmm::X86_PML4_CAPACITY as usize,
    )
    .map_err(|e| TrapError::Hypervisor(format!("carrick-x86: pml4_tables: {e:?}")))?;
    if plan.ro_spans.is_empty() {
        return Ok(bytes);
    }
    // Same editor the runtime `protect_range` path uses, so a later guest
    // `mprotect` composes with these edits (2 MiB leaves split on demand; the
    // sequential table allocator is re-discovered by `Pml4Manager::new`).
    let mut mgr = carrick_mem::pml4::Pml4Manager::new(bytes, layout.pml4_base);
    for span in &plan.ro_spans {
        let Ok(len) = usize::try_from(span.len) else {
            continue;
        };
        // Best-effort per span: a span the plan's windows do not map
        // (BadAddress) is skipped — protection is an upgrade and must never
        // block bring-up; a skipped span degrades to the historical
        // (writable) behaviour.
        let _ = mgr.set_readonly(span.start, len, span.exec);
    }
    Ok(mgr.into_bytes())
}

// ─── program_longmode_entry ──────────────────────────────────────────────────

/// The ONE long-mode programming sequence (design §2.2). Programs the control
/// registers, the long-mode user/system segments, the GDT/IDT/TR/LDTR
/// descriptors, the entry GPRs (RIP/RSP/RFLAGS), and the SYSCALL MSRs — branching
/// once on [`MsrInstall`] (the bhyve `NeedsRing0Blob` seam) instead of every
/// backend re-deciding.
///
/// `entry_rip`/`rsp` are the ring-3 entry point and initial user stack. After
/// this the vCPU enters ring 3 on the first `run()` (KVM/NVMM `Direct`), or the
/// caller runs the ring-0 [`crate::bringup::msr_init_blob`] once (bhyve
/// `NeedsRing0Blob`).
pub fn program_longmode_entry<C: X86Vcpu>(
    vcpu: &mut C,
    layout: BringupLayout,
    entry_rip: u64,
    rsp: u64,
) -> Result<MsrInstall, TrapError> {
    let boot = X8664GuestArch::bootstrap_sysregs();

    // ── Control registers + EFER ──────────────────────────────────────────────
    vcpu.set_gpr(X86Reg::Cr0, boot.cr0)?;
    vcpu.set_gpr(X86Reg::Cr2, 0)?;
    vcpu.set_gpr(X86Reg::Cr3, layout.pml4_base)?;
    vcpu.set_gpr(X86Reg::Cr4, boot.cr4)?;
    vcpu.set_gpr(X86Reg::Efer, boot.efer)?;

    // ── Long-mode segments (must match CR0/EFER long-mode state) ──────────────
    //
    let segs = long_mode_segment_state();
    vcpu.set_segment(X86Seg::Cs, 0, 0xFFFF_FFFF, segs.cs_ar)?;
    vcpu.set_segment(X86Seg::Ss, 0, 0xFFFF_FFFF, segs.data_ar)?;
    vcpu.set_segment(X86Seg::Ds, 0, 0xFFFF_FFFF, segs.data_ar)?;
    vcpu.set_segment(X86Seg::Es, 0, 0xFFFF_FFFF, segs.data_ar)?;
    // FS/GS: base only is significant in 64-bit mode; arch_prctl sets the base.
    vcpu.set_segment(X86Seg::Fs, 0, 0xFFFF_FFFF, segs.data_ar)?;
    vcpu.set_segment(X86Seg::Gs, 0, 0xFFFF_FFFF, segs.data_ar)?;
    vcpu.set_segment(X86Seg::Tr, 0, 0xFFFF_FFFF, segs.tr_ar)?;
    vcpu.set_segment(X86Seg::Ldtr, 0, 0, segs.ldtr_ar)?;

    // GDT / fault IDT + TSS. Slot 0 is the initial vCPU; backends with sibling
    // vCPUs reprogram IDTR/TR to that vCPU's private slot on restore.
    vcpu.set_segment(X86Seg::Gdtr, layout.gdt_base, segs.gdt_limit, 0)?;
    crate::fault::program_fault_segments(vcpu, layout, 0)?;

    // ── Entry GPRs ────────────────────────────────────────────────────────────
    vcpu.set_gpr(X86Reg::Rip, entry_rip)?;
    vcpu.set_gpr(X86Reg::Rsp, rsp)?;
    vcpu.set_gpr(X86Reg::Rflags, boot.rflags)?;
    // Zero every other GPR, matching the Linux ELF loader (`ELF_PLAT_INIT`),
    // which clears them at exec so no kernel/bringup state leaks to the guest.
    // RDX is the load-bearing one: the System V x86-64 ABI defines it at process
    // entry as `rtld_fini` (0 = none). glibc's `__libc_start_main` registers RDX
    // via `__cxa_atexit` and CALLS it during exit teardown — so leftover init-blob
    // garbage in RDX makes a STATIC binary jump to a bogus address at exit and
    // SIGSEGV (a dynamic binary is unharmed: ld.so overwrites RDX before _start).
    for r in [
        X86Reg::Rax,
        X86Reg::Rbx,
        X86Reg::Rcx,
        X86Reg::Rdx,
        X86Reg::Rsi,
        X86Reg::Rdi,
        X86Reg::Rbp,
        X86Reg::R8,
        X86Reg::R9,
        X86Reg::R10,
        X86Reg::R11,
        X86Reg::R12,
        X86Reg::R13,
        X86Reg::R14,
        X86Reg::R15,
    ] {
        vcpu.set_gpr(r, 0)?;
    }

    // ── SYSCALL MSRs (LSTAR = trampoline GPA) ─────────────────────────────────
    vcpu.set_syscall_msrs(layout.trampoline_base, boot.star, boot.sfmask)
}

pub fn program_user_segments<C: X86Vcpu>(vcpu: &mut C) -> Result<(), TrapError> {
    let segs = long_mode_segment_state();
    vcpu.set_segment(X86Seg::Cs, 0, 0xFFFF_FFFF, segs.cs_ar)?;
    vcpu.set_segment(X86Seg::Ss, 0, 0xFFFF_FFFF, segs.data_ar)?;
    vcpu.set_segment(X86Seg::Ds, 0, 0xFFFF_FFFF, segs.data_ar)?;
    vcpu.set_segment(X86Seg::Es, 0, 0xFFFF_FFFF, segs.data_ar)
}

/// Write the bring-up byte images (LSTAR trampoline, GDT, PML4, fault tables)
/// into guest RAM via the [`crate::X86Vmm`] memory surface. Call before
/// `add_vcpu`/the first run so the trampoline and exception stubs are present.
/// `pml4_bytes` is from [`build_pml4`].
pub fn write_bringup_images<V: crate::X86Vmm>(
    vm: &V,
    layout: BringupLayout,
    pml4_bytes: &[u8],
) -> Result<(), TrapError> {
    vm.write_gpa(
        layout.trampoline_base,
        &X8664GuestArch::entry_trampoline_bytes(),
    )?;
    let boot = X8664GuestArch::bootstrap_sysregs();
    let gdt_bytes: Vec<u8> = boot.gdt.iter().flat_map(|e| e.to_le_bytes()).collect();
    vm.write_gpa(layout.gdt_base, &gdt_bytes)?;
    vm.write_gpa(layout.pml4_base, pml4_bytes)?;
    crate::fault::write_fault_tables(vm, layout)?;
    Ok(())
}

// ─── snapshot / restore / seed_entry ─────────────────────────────────────────

/// Full dynamic register state of an x86_64 vCPU, captured at a syscall trap so
/// a forked child (fresh VM) or a clone sibling (fresh vCPU on the same VM) can
/// resume inside the same trapped syscall. The ISA-neutral counterpart of the
/// per-backend snapshot structs (KVM `X8664VcpuSnapshot`, bhyve's analogue) —
/// it reads through the [`X86Vcpu`] trait, so it is backend-agnostic. All POD
/// (`Send`).
#[derive(Clone, Debug)]
pub struct X86VcpuSnapshot {
    /// `Rax..R15` (16 GPRs, in [`X86Reg`] order), `Rip`, `Rsp`, `Rflags`.
    pub gprs: [u64; 16],
    pub rip: u64,
    pub rsp: u64,
    pub rflags: u64,
    /// Control registers (carried so the child re-establishes long mode).
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    /// FS/GS/KERNEL_GS base.
    pub fs_base: u64,
    pub gs_base: u64,
    /// The full XSAVE area ([`crate::vmm::XSAVE_LEN`] — FXSAVE + AVX YMM_Hi) iff
    /// the backend has a native FP getter (`get_xsave() == Some`); `None` for a
    /// no-FP-getter backend (the FP state rides the ring-3 stub on restore
    /// instead). Carrying the full XSAVE (not the 512-byte FXSAVE) preserves a
    /// guest's AVX YMM upper halves across fork/clone/execve.
    pub xsave: Option<[u8; crate::vmm::XSAVE_LEN]>,
}

/// The 16 GPRs in canonical order (matches [`X86VcpuSnapshot::gprs`]).
const GPR_ORDER: [X86Reg; 16] = [
    X86Reg::Rax,
    X86Reg::Rbx,
    X86Reg::Rcx,
    X86Reg::Rdx,
    X86Reg::Rsi,
    X86Reg::Rdi,
    X86Reg::Rbp,
    X86Reg::Rsp,
    X86Reg::R8,
    X86Reg::R9,
    X86Reg::R10,
    X86Reg::R11,
    X86Reg::R12,
    X86Reg::R13,
    X86Reg::R14,
    X86Reg::R15,
];
const GPR_RAX: usize = 0;
const GPR_RCX: usize = 2;
const GPR_RSP: usize = 7;
const GPR_R11: usize = 11;
const RFLAGS_RESERVED_BIT: u64 = 0x2;

/// Capture the vCPU's full dynamic state at a syscall trap.
pub fn snapshot<C: X86Vcpu>(c: &C) -> Result<X86VcpuSnapshot, TrapError> {
    let mut gprs = [0u64; 16];
    for (slot, reg) in gprs.iter_mut().zip(GPR_ORDER) {
        *slot = c.get_gpr(reg)?;
    }
    Ok(X86VcpuSnapshot {
        gprs,
        rip: c.get_gpr(X86Reg::Rip)?,
        rsp: c.get_gpr(X86Reg::Rsp)?,
        rflags: c.get_gpr(X86Reg::Rflags)?,
        cr0: c.get_gpr(X86Reg::Cr0)?,
        cr3: c.get_gpr(X86Reg::Cr3)?,
        cr4: c.get_gpr(X86Reg::Cr4)?,
        efer: c.get_gpr(X86Reg::Efer)?,
        fs_base: c.get_fs_base()?,
        gs_base: c.get_gs_base()?,
        xsave: c.get_xsave()?,
    })
}

/// Program a freshly-created vCPU from `s`, then re-apply the static SYSCALL MSRs
/// (a fresh vCPU is at reset state with LSTAR/STAR/SFMASK = 0, which the snapshot
/// segment/GPR writes do NOT carry; without re-applying them the guest's next
/// SYSCALL jumps to RIP 0 and triple-faults).
///
/// Order: control regs + segments establish long mode, then GPRs, then bases,
/// then FP, then MSRs.
pub fn restore<C: X86Vcpu>(
    c: &mut C,
    layout: BringupLayout,
    s: &X86VcpuSnapshot,
) -> Result<(), TrapError> {
    // Control registers + EFER (re-establish long mode).
    c.set_gpr(X86Reg::Cr0, s.cr0)?;
    c.set_gpr(X86Reg::Cr3, s.cr3)?;
    c.set_gpr(X86Reg::Cr4, s.cr4)?;
    c.set_gpr(X86Reg::Efer, s.efer)?;

    // Long-mode segments (same encoding as program_longmode_entry).
    let segs = long_mode_segment_state();
    c.set_segment(X86Seg::Cs, 0, 0xFFFF_FFFF, segs.cs_ar)?;
    c.set_segment(X86Seg::Ss, 0, 0xFFFF_FFFF, segs.data_ar)?;
    c.set_segment(X86Seg::Ds, 0, 0xFFFF_FFFF, segs.data_ar)?;
    c.set_segment(X86Seg::Es, 0, 0xFFFF_FFFF, segs.data_ar)?;
    c.set_segment(X86Seg::Fs, 0, 0xFFFF_FFFF, segs.data_ar)?;
    c.set_segment(X86Seg::Gs, 0, 0xFFFF_FFFF, segs.data_ar)?;
    c.set_segment(X86Seg::Ldtr, 0, 0, segs.ldtr_ar)?;
    c.set_segment(X86Seg::Gdtr, layout.gdt_base, segs.gdt_limit, 0)?;
    crate::fault::program_fault_segments(c, layout, 0)?;

    // GPRs.
    for (val, reg) in s.gprs.iter().zip(GPR_ORDER) {
        c.set_gpr(reg, *val)?;
    }
    c.set_gpr(X86Reg::Rip, s.rip)?;
    c.set_gpr(X86Reg::Rsp, s.rsp)?;
    c.set_gpr(X86Reg::Rflags, s.rflags)?;

    // FS/GS bases.
    c.set_fs_base(s.fs_base)?;
    c.set_gs_base(s.gs_base)?;

    // FP state (full XSAVE incl AVX YMM_Hi), iff the backend has a native FP
    // setter and we captured an area.
    if let Some(xs) = &s.xsave {
        let _ = c.set_xsave(xs)?;
    }

    // Re-apply the static SYSCALL config (LSTAR = trampoline GPA).
    let boot = X8664GuestArch::bootstrap_sysregs();
    c.set_syscall_msrs(layout.trampoline_base, boot.star, boot.sfmask)?;
    Ok(())
}

/// Seed a freshly-built vCPU's register file from the ISA-neutral
/// [`GuestEntryRegs`], for BOTH a `clone(CLONE_THREAD)` sibling and a `fork(2)`
/// child. Starts from the parent snapshot (same CR3/segments/long-mode → same
/// address space) and applies the user-visible clone/fork return state:
///   - `rax = entry.return_value`     — clone()/fork() return value (0 for child).
///   - `rsp = entry.stack` (if `Some`) — new user stack; `None` inherits (fork).
///   - `fs_base = entry.tls` (if `Some`) — TLS base; `None` inherits (fork).
///   - `rip = parent.rcx`             — the user RIP saved by SYSCALL.
///   - `rflags = parent.r11`          — the user RFLAGS saved by SYSCALL.
///
/// FP is carried verbatim (correct for fork; harmless for a new thread).
pub fn seed_entry(parent: &X86VcpuSnapshot, entry: GuestEntryRegs) -> X86VcpuSnapshot {
    let mut snap = parent.clone();
    snap.gprs[GPR_RAX] = entry.return_value;
    if let Some(stack) = entry.stack {
        snap.rsp = stack;
        snap.gprs[GPR_RSP] = stack;
    }
    if let Some(tls) = entry.tls {
        snap.fs_base = tls;
    }
    snap.rip = parent.gprs[GPR_RCX];
    snap.rflags = parent.gprs[GPR_R11] | RFLAGS_RESERVED_BIT;
    snap
}

// ─── run_elf_service_loop ────────────────────────────────────────────────────

// The M2 startup syscall service set is shared by every x86 backend's MVP
// run-elf path. Canonical (asm-generic) syscall numbers, post-`normalize_syscall`.
const SYS_READ: u64 = 63;
const SYS_WRITE: u64 = 64;
const SYS_CLOSE: u64 = 57;
const SYS_WRITEV: u64 = 66;
const SYS_EXIT: u64 = 93;
const SYS_EXIT_GROUP: u64 = 94;
const SYS_BRK: u64 = 214;
const SYS_MMAP: u64 = 222;
const SYS_MUNMAP: u64 = 215;
const SYS_MPROTECT: u64 = 226;
const SYS_SET_TID_ADDRESS: u64 = 96;
const SYS_RT_SIGPROCMASK: u64 = 135;
const SYS_RT_SIGACTION: u64 = 134;
const SYS_SIGALTSTACK: u64 = 132;
const SYS_PPOLL: u64 = 73;
const SYS_TKILL: u64 = 130;

const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED: u64 = 0x10;
const SIGABRT: u64 = 6;

const NEG_ENOSYS: i64 = -38;
const NEG_EINVAL: i64 = -22;
const NEG_ENOMEM: i64 = -12;

const M2_HEAP_CAP: u64 = 8 * 1024 * 1024; // 8 MiB
const M2_MMAP_CAP: u64 = 64 * 1024 * 1024; // 64 MiB

/// Load a static x86_64 ELF and prepare its guest image — the image-prep idiom
/// every x86 run-elf path (KVM/bhyve/NVMM) repeated verbatim (NVMM did it twice
/// in one file): map the ELF, materialize the shared x86_64 vDSO/vvar, and build
/// the Linux initial stack (argc/argv/envp/auxv) with `argv = [path]` and an
/// empty environment. Returns a diagnostic string on failure.
pub fn load_x86_elf_image(
    path: &std::path::Path,
) -> Result<carrick_mem::memory::AddressSpace, String> {
    use carrick_hal::x8664_arch::X8664GuestArch;
    carrick_mem::memory::AddressSpace::load_elf_for(path, X8664GuestArch::elf_machine())
        .map_err(|e| format!("load_elf_x86: {e}"))?
        .with_vdso_bytes(X8664GuestArch::vdso_bytes())
        .map_err(|e| format!("with_vdso_bytes: {e}"))?
        .with_linux_initial_stack(
            [path.as_os_str().as_encoded_bytes()],
            std::iter::empty::<&[u8]>(),
        )
        .map_err(|e| format!("with_linux_initial_stack: {e}"))
}

/// The shared M2 run-elf service loop (design §2.2). Drives `engine` through the
/// startup syscall set a static-musl `hello` exercises, returning the guest's
/// exit code. Backend-agnostic: it needs only `SyscallTrap` (next/complete) and
/// `GuestMemory` (read/write the guest buffers).
pub fn run_elf_service_loop<E>(engine: &mut E) -> Result<i32, TrapError>
where
    E: carrick_hal::SyscallTrap + carrick_guest_mem::GuestMemory,
{
    let mut current_brk: u64 = carrick_mem::memory::LINUX_HEAP_BASE;
    let heap_limit: u64 = carrick_mem::memory::LINUX_HEAP_BASE + M2_HEAP_CAP;
    let mut mmap_cursor: u64 = carrick_mem::memory::LINUX_MMAP_BASE;
    let mmap_limit: u64 = carrick_mem::memory::LINUX_MMAP_BASE + M2_MMAP_CAP;

    loop {
        let raw = match engine.next_syscall()? {
            Some(r) => r,
            None => return Ok(0),
        };
        let canonical = raw.number.raw();
        let args = raw.args;

        let ret: i64 = match canonical {
            SYS_WRITE => match engine.read_bytes(args[1], args[2] as usize) {
                Ok(buf) => host_write(args[0] as i32, &buf),
                Err(e) => {
                    eprintln!("carrick-x86 write: guest read error: {e}");
                    NEG_EINVAL
                }
            },
            SYS_WRITEV => sys_writev(engine, args[0], args[1], args[2])?,
            SYS_READ => sys_read(engine, args[0], args[1], args[2])?,
            SYS_CLOSE => 0,
            SYS_BRK => {
                let requested = args[0];
                if requested == 0
                    || (requested >= carrick_mem::memory::LINUX_HEAP_BASE
                        && requested <= heap_limit)
                {
                    if requested != 0 {
                        current_brk = requested;
                    }
                    current_brk as i64
                } else {
                    current_brk as i64
                }
            }
            SYS_MMAP => {
                let length = args[1];
                let flags = args[3];
                let is_anon = flags & MAP_ANONYMOUS != 0;
                let is_private = flags & MAP_PRIVATE != 0;
                let is_fixed = flags & MAP_FIXED != 0;
                if is_fixed || !is_anon || !is_private || length == 0 {
                    NEG_ENOSYS
                } else {
                    let aligned = (length + 0xFFF) & !0xFFF;
                    let va = mmap_cursor;
                    let next = va.saturating_add(aligned);
                    if next > mmap_limit {
                        NEG_ENOMEM
                    } else {
                        mmap_cursor = next;
                        va as i64
                    }
                }
            }
            SYS_MUNMAP => 0,
            SYS_MPROTECT => 0,
            SYS_RT_SIGACTION => {
                let oact = args[2];
                if oact != 0 {
                    let _ = engine.write_bytes(oact, &[0u8; 32]);
                }
                0
            }
            SYS_RT_SIGPROCMASK => {
                let oldset = args[2];
                if oldset != 0 {
                    let _ = engine.write_bytes(oldset, &[0u8; 8]);
                }
                0
            }
            SYS_SET_TID_ADDRESS => {
                // SAFETY: getpid(2) is always safe.
                let tid = unsafe { libc::getpid() };
                i64::from(tid)
            }
            SYS_SIGALTSTACK => 0,
            SYS_PPOLL => 0,
            SYS_TKILL => {
                let sig = args[1];
                if sig == SIGABRT {
                    eprintln!("carrick-x86: guest called tkill(SIGABRT) → exit(134)");
                    return Ok(134);
                }
                0
            }
            SYS_EXIT | SYS_EXIT_GROUP => {
                return Ok(args[0] as i32);
            }
            other => {
                use carrick_hal::guest_arch::SyscallTable as _;
                use carrick_hal::x8664_arch::X8664SyscallTable;
                let name = X8664SyscallTable::name(other).unwrap_or("<unknown>");
                eprintln!(
                    "carrick-x86 run-elf: unhandled canonical={other} x86_name={name} \
                     args={:x?} → -ENOSYS",
                    &args
                );
                NEG_ENOSYS
            }
        };

        engine.complete_syscall(ret)?;
    }
}

/// `writev(fd, iov, iovcnt)` — walk the guest `struct iovec[]` (16 B each on
/// LP64) and write each buffer.
fn sys_writev<E>(engine: &E, fd: u64, iov_va: u64, iovcnt: u64) -> Result<i64, TrapError>
where
    E: carrick_guest_mem::GuestMemory,
{
    const IOVEC_SIZE: u64 = 16;
    let mut total: i64 = 0;
    for i in 0..iovcnt as usize {
        let ent = engine
            .read_bytes(iov_va + (i as u64) * IOVEC_SIZE, IOVEC_SIZE as usize)
            .map_err(|e| TrapError::Hypervisor(format!("writev iov[{i}]: {e}")))?;
        let base = u64::from_le_bytes(
            ent[0..8]
                .try_into()
                .map_err(|_| TrapError::Hypervisor("writev: iov_base".into()))?,
        );
        let len = u64::from_le_bytes(
            ent[8..16]
                .try_into()
                .map_err(|_| TrapError::Hypervisor("writev: iov_len".into()))?,
        ) as usize;
        if len == 0 {
            continue;
        }
        let buf = engine
            .read_bytes(base, len)
            .map_err(|e| TrapError::Hypervisor(format!("writev buf[{i}]: {e}")))?;
        let n = host_write(fd as i32, &buf);
        if n < 0 {
            return Ok(n);
        }
        total += n;
    }
    Ok(total)
}

/// `read(fd, buf, count)` — host `read(2)`, copy result into the guest buffer.
fn sys_read<E>(engine: &mut E, fd: u64, buf_va: u64, count: u64) -> Result<i64, TrapError>
where
    E: carrick_guest_mem::GuestMemory,
{
    let mut buf = vec![0u8; count as usize];
    // SAFETY: `buf` is a valid host allocation; `read(2)` on a host fd.
    let n = unsafe { libc::read(fd as i32, buf.as_mut_ptr().cast(), count as usize) };
    if n < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        return Ok(-i64::from(e));
    }
    engine
        .write_bytes(buf_va, &buf[..n as usize])
        .map_err(|e| TrapError::Hypervisor(format!("read: guest write: {e}")))?;
    Ok(n as i64)
}

/// Host `write(2)` helper — returns bytes written (>= 0) or `-errno`.
fn host_write(fd: i32, buf: &[u8]) -> i64 {
    // SAFETY: `buf` is a host-owned slice; `write(2)` on a host fd.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        -i64::from(e)
    } else {
        n as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_mem::memory::{
        LINUX_HEAP_BASE, LINUX_MMAP_BASE, LINUX_SHARED_FILE_BASE, mmap_arena_size,
    };

    fn test_layout() -> BringupLayout {
        BringupLayout {
            trampoline_base: 0x1000_0000,
            gdt_base: 0x1000_1000,
            pml4_base: 0x1000_2000,
        }
    }

    fn synthetic_x86_elf() -> Vec<u8> {
        const ET_EXEC: u16 = 2;
        const PT_LOAD: u32 = 1;
        const PF_X: u32 = 1;
        const PF_R: u32 = 4;

        let mut elf = vec![0u8; 0x1004];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&X8664GuestArch::elf_machine().to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());

        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        elf[ph + 8..ph + 16].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[ph + 32..ph + 40].copy_from_slice(&4u64.to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[0x1000] = 0xc3; // ret
        elf
    }

    fn synthetic_x86_image() -> AddressSpace {
        let elf = synthetic_x86_elf();
        AddressSpace::load_elf_bytes_with_reader_for(&elf, &|_| None, X8664GuestArch::elf_machine())
            .expect("synthetic x86 ELF should load")
    }

    #[test]
    fn plan_windows_covers_full_runtime_mmap_arena() {
        let image = synthetic_x86_image();
        let plan = plan_windows(&image, test_layout()).expect("window plan");
        let mmap = plan
            .regions
            .iter()
            .find(|region| region.va == LINUX_MMAP_BASE)
            .expect("mmap arena region");

        assert_eq!(mmap.gpa, LINUX_MMAP_BASE);
        assert_eq!(mmap.len, mmap_arena_size());
        assert!(
            mmap.len > 64 * 1024 * 1024,
            "generic x86 plan must not carry the old MVP 64 MiB cap"
        );
    }

    #[test]
    fn plan_windows_preserves_shared_aperture_backing() {
        let image = synthetic_x86_image();
        let plan = plan_windows(&image, test_layout()).expect("window plan");
        let shared = plan
            .regions
            .iter()
            .find(|region| region.va == LINUX_SHARED_FILE_BASE)
            .expect("shared aperture region");
        let heap = plan
            .regions
            .iter()
            .find(|region| region.va == LINUX_HEAP_BASE)
            .expect("heap region");

        assert!(shared.shared, "shared aperture must stay marked shared");
        assert!(!heap.shared, "ordinary private regions must stay private");
    }

    #[test]
    fn build_pml4_translates_full_runtime_mmap_arena() {
        let image = synthetic_x86_image();
        let layout = test_layout();
        let plan = plan_windows(&image, layout).expect("window plan");
        let bytes = build_pml4(&plan, layout).expect("build PML4");
        let mgr = carrick_mem::pml4::Pml4Manager::new(bytes, layout.pml4_base);
        let arena_end = LINUX_MMAP_BASE + mmap_arena_size();

        assert_eq!(mgr.translate(LINUX_MMAP_BASE), Some(LINUX_MMAP_BASE));
        assert_eq!(
            mgr.translate(arena_end - 1),
            Some(arena_end - 1),
            "last byte of the mmap arena must be mapped"
        );
        assert_eq!(mgr.translate(arena_end), None);
    }

    #[test]
    fn build_pml4_applies_image_ro_spans_to_leaves() {
        use carrick_mem::pml4::{PML4_NX, PML4_P, PML4_RW, walk_descriptors};

        // The synthetic image's single LOAD is R+X at 0x400000: plan_windows
        // must carry that page as an ro_span, and build_pml4 must clear R/W on
        // its leaf (keeping it present + executable) while the merged region's
        // OTHER pages keep the escalated writable mapping — a guest store to
        // its own .text/.rodata #PFs (PFEC.P=1 → SEGV_ACCERR) as on Linux.
        let image = synthetic_x86_image();
        let layout = test_layout();
        let plan = plan_windows(&image, layout).expect("window plan");
        assert!(
            plan.ro_spans
                .iter()
                .any(|s| s.start == 0x400000 && s.len == 0x1000 && s.exec),
            "plan carries the image's read-only span: {:?}",
            plan.ro_spans
        );

        let bytes = build_pml4(&plan, layout).expect("build PML4");
        let ro_leaf = walk_descriptors(&bytes, layout.pml4_base, 0x400000)[3];
        assert_ne!(ro_leaf & PML4_P, 0, "RO leaf stays present");
        assert_eq!(ro_leaf & PML4_RW, 0, "RO leaf loses R/W");
        assert_eq!(ro_leaf & PML4_NX, 0, "exec span keeps the leaf executable");

        // The heap window (writable region, no span) keeps R/W.
        let heap_walk = walk_descriptors(&bytes, layout.pml4_base, LINUX_HEAP_BASE);
        let heap_leaf = if heap_walk[3] != 0 {
            heap_walk[3]
        } else {
            heap_walk[2] // 2 MiB PS leaf
        };
        assert_ne!(heap_leaf & PML4_RW, 0, "heap leaf stays writable");
    }

    #[test]
    fn seg_ar_packs_user_cs() {
        // type=0xB, S=1, DPL=3, P=1, L=1, G=1 → 0x0000_A0FB
        let ar = seg_ar(CODE_SEG_TYPE, 1, 3, 1, 1, 0, 1, 0);
        assert_eq!(ar & 0xF, 0xB, "type");
        assert_ne!(ar & (1 << 4), 0, "S");
        assert_eq!((ar >> 5) & 0x3, 3, "DPL");
        assert_ne!(ar & (1 << 7), 0, "P");
        assert_ne!(ar & (1 << 13), 0, "L");
        assert_ne!(ar & (1 << 15), 0, "G");
    }

    #[test]
    fn seed_entry_sibling_applies_thread_deltas() {
        let mut parent = X86VcpuSnapshot {
            gprs: [0; 16],
            rip: 0x1000,
            rsp: 0x1111,
            rflags: 0x2,
            cr0: 0,
            cr3: 0,
            cr4: 0,
            efer: 0,
            fs_base: 0x2222,
            gs_base: 0,
            xsave: None,
        };
        parent.gprs[0] = 0xdead; // Rax
        parent.gprs[2] = 0x4000_1234; // Rcx: user RIP saved by SYSCALL
        parent.gprs[11] = 0x246; // R11: user RFLAGS saved by SYSCALL
        let child = seed_entry(
            &parent,
            GuestEntryRegs {
                return_value: 0,
                stack: Some(0xCAFE_0000),
                tls: Some(0xBEEF_0000),
            },
        );
        assert_eq!(child.gprs[0], 0, "child clone() returns 0");
        assert_eq!(child.rsp, 0xCAFE_0000, "rsp = child stack");
        assert_eq!(child.gprs[7], 0xCAFE_0000, "Rsp GPR = child stack");
        assert_eq!(child.fs_base, 0xBEEF_0000, "fs_base = tls");
        assert_eq!(child.rip, 0x4000_1234, "rip = saved user RCX");
        assert_eq!(child.rflags, 0x246, "rflags = saved user R11");
    }

    #[test]
    fn seed_entry_fork_child_inherits_stack_and_tls() {
        let mut parent = X86VcpuSnapshot {
            gprs: [0; 16],
            rip: 0x1000,
            rsp: 0x1111,
            rflags: 0x2,
            cr0: 0,
            cr3: 0,
            cr4: 0,
            efer: 0,
            fs_base: 0x2222,
            gs_base: 0,
            xsave: None,
        };
        parent.gprs[0] = 0xdead;
        parent.gprs[2] = 0x4000_5678;
        parent.gprs[7] = 0x1111;
        parent.gprs[11] = 0x244;
        let child = seed_entry(&parent, GuestEntryRegs::default());
        assert_eq!(child.gprs[0], 0);
        assert_eq!(child.rip, 0x4000_5678);
        assert_eq!(child.rflags, 0x246);
        assert_eq!(child.rsp, 0x1111, "fork child inherits parent rsp");
        assert_eq!(child.fs_base, 0x2222, "fork child inherits parent fs_base");
    }

    /// Minimal `X86Vcpu` that just records `set_gpr` calls — enough to assert
    /// what `program_longmode_entry` programs into the entry registers. The
    /// methods it does not touch are never called here.
    #[derive(Default)]
    struct RecordingVcpu {
        gprs: Vec<(X86Reg, u64)>,
    }
    impl RecordingVcpu {
        fn last(&self, r: X86Reg) -> Option<u64> {
            self.gprs
                .iter()
                .rev()
                .find(|(x, _)| *x == r)
                .map(|(_, v)| *v)
        }
    }
    impl X86Vcpu for RecordingVcpu {
        fn get_gpr(&self, _r: X86Reg) -> Result<u64, TrapError> {
            Ok(0)
        }
        fn set_gpr(&mut self, r: X86Reg, v: u64) -> Result<(), TrapError> {
            self.gprs.push((r, v));
            Ok(())
        }
        fn set_segment(&mut self, _s: X86Seg, _b: u64, _l: u32, _a: u32) -> Result<(), TrapError> {
            Ok(())
        }
        fn get_fs_base(&self) -> Result<u64, TrapError> {
            Ok(0)
        }
        fn set_fs_base(&mut self, _v: u64) -> Result<(), TrapError> {
            Ok(())
        }
        fn get_gs_base(&self) -> Result<u64, TrapError> {
            Ok(0)
        }
        fn set_gs_base(&mut self, _v: u64) -> Result<(), TrapError> {
            Ok(())
        }
        fn set_syscall_msrs(&mut self, _l: u64, _s: u64, _m: u64) -> Result<MsrInstall, TrapError> {
            Ok(MsrInstall::Direct)
        }
        fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
            Ok(None)
        }
        fn set_fp(&mut self, _fx: &[u8; 512]) -> Result<bool, TrapError> {
            Ok(true)
        }
        fn run(&mut self) -> Result<crate::vmm::X86Exit, TrapError> {
            Err(TrapError::Hypervisor(
                "RecordingVcpu::run unused".to_owned(),
            ))
        }
        fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
            Ok(())
        }
    }

    /// Regression guard for the static-binary exit-139 bug: the initial x86 entry
    /// must ZERO the GPRs (Linux `ELF_PLAT_INIT`). RDX especially — the SysV ABI
    /// defines it at entry as `rtld_fini`, which glibc registers via `__cxa_atexit`
    /// and CALLS during exit teardown, so leftover garbage there makes a static
    /// binary jump to a bogus address at exit and SIGSEGV.
    #[test]
    fn program_longmode_entry_zeroes_entry_gprs() {
        let mut v = RecordingVcpu::default();
        let entry_rip = 0x4000_1234u64;
        let rsp = 0x7fff_ffff_e000u64;
        program_longmode_entry(&mut v, test_layout(), entry_rip, rsp)
            .expect("program_longmode_entry");
        // RSP / RIP keep their values; only the scratch GPRs are zeroed.
        assert_eq!(
            v.last(X86Reg::Rsp),
            Some(rsp),
            "RSP must keep the user stack"
        );
        assert_eq!(
            v.last(X86Reg::Rip),
            Some(entry_rip),
            "RIP must be the entry"
        );
        for r in [
            X86Reg::Rax,
            X86Reg::Rbx,
            X86Reg::Rcx,
            X86Reg::Rdx,
            X86Reg::Rsi,
            X86Reg::Rdi,
            X86Reg::Rbp,
            X86Reg::R8,
            X86Reg::R9,
            X86Reg::R10,
            X86Reg::R11,
            X86Reg::R12,
            X86Reg::R13,
            X86Reg::R14,
            X86Reg::R15,
        ] {
            assert_eq!(
                v.last(r),
                Some(0),
                "entry GPR {r:?} must be zeroed (rtld_fini/RDX is the load-bearing one)"
            );
        }
    }
}
