//! VM-free SDM privileged-instruction and CPL0 `SoftMachine` boot witnesses (`carrick-sh/carrick#668`).

#![cfg(target_arch = "x86_64")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};

use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_softcpu_x86::{
    Cpl0CpuidView, CpuidRegs, DEFAULT_IA32_APIC_BASE, DEFAULT_IA32_PAT, DescriptorTablePtr,
    EFER_LMA, EFER_LME, EFER_NXE, EFER_SCE, ExtentRecord, ExtentTable, FrameGpa, GuestCpuidView,
    Level0CpuidView, LinearPlacement, MSR_IA32_APIC_BASE, MSR_IA32_CSTAR, MSR_IA32_EFER,
    MSR_IA32_FMASK, MSR_IA32_FS_BASE, MSR_IA32_GS_BASE, MSR_IA32_KERNEL_GS_BASE, MSR_IA32_LSTAR,
    MSR_IA32_MISC_ENABLE, MSR_IA32_PAT, MSR_IA32_STAR, MSR_IA32_TSC_DEADLINE, MmioHoles,
    MsrCapabilities, MsrError, MsrFile, MsrIndex, OwnerGeneration, PF_ERR_PRESENT, PF_ERR_USER,
    PF_ERR_WRITE, RootGpa, SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK, SOFT_TLB_PAGE_SIZE,
    SoftAccessKind, SoftCpu, SoftCpuContext, SoftCpuExit, SoftMachine, SoftMachineExit,
    SoftMmuMemory, SoftSegment, X86Exception, reg, translate_va,
};
use carrick_x86::cpl0_entry::{CONTROL_PORT, CpuBinding};
use carrick_x86::{
    BringupLayout, FAULT_DOORBELL_PORT, FaultDoorbellRecord, GuestSegment, LongModeSegments,
    WindowPlan, WindowRegion, X86_FAULT_RECORD_U32_WORDS, add_fault_windows, build_pml4,
    check_vmx_guest_segments, fault_idt_base, fault_slot_gpa, fault_tss_base,
    write_fault_tables_with,
};

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_NX: u64 = 1 << 63;
const PTE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const NON_CANON: u64 = 0x0000_8000_0000_0000;
const CODE_VA: u64 = 0xffff_8000_0010_0000;
const USER_CODE_VA: u64 = 0x0000_0000_0040_0000;
const DATA_VA: u64 = 0xffff_8000_0020_0000;
const STACK_VA: u64 = 0xffff_8000_0030_0000;

#[derive(Clone, Copy)]
struct Perms(u8);
impl Perms {
    const fn new(r: bool, w: bool, x: bool, u: bool) -> Self {
        Self((r as u8) | ((w as u8) << 1) | ((x as u8) << 2) | ((u as u8) << 3))
    }
    const USER_RW: Self = Self::new(true, true, false, true);
    const USER_RX: Self = Self::new(true, false, true, true);
    const KERNEL_RW: Self = Self::new(true, true, false, false);
    const KERNEL_RX: Self = Self::new(true, false, true, false);
}

struct Cpl0TestMemory {
    _backing: Vec<AtomicU64>,
    placement: LinearPlacement,
    extents: ExtentTable,
    next_gpa: u64,
}

impl Cpl0TestMemory {
    const POOL_BYTES: u64 = 32 * 1024 * 1024;
    const GEN: OwnerGeneration = OwnerGeneration::FIRST;
    const ROOT_GPA: u64 = 0;

    fn new() -> Self {
        let words = ((Self::POOL_BYTES + SOFT_TLB_PAGE_SIZE) as usize) / 8;
        let mut backing = Vec::with_capacity(words);
        backing.resize_with(words, || AtomicU64::new(0));
        let aligned = (backing.as_ptr() as usize + (SOFT_TLB_OFFSET_MASK as usize))
            & !(SOFT_TLB_OFFSET_MASK as usize);
        // SAFETY: `backing` owns `POOL_BYTES` initialized bytes starting at `aligned`
        // without resizing while each test runs a single vCPU serially.
        let placement =
            unsafe { LinearPlacement::new(aligned, Self::POOL_BYTES, MmioHoles::empty()) }.unwrap();
        let mut extents = ExtentTable::new().unwrap();
        let rec = ExtentRecord::new(FrameGpa::new(0), Self::POOL_BYTES, Self::GEN);
        assert!(extents.install(rec));
        let root = RootGpa::page_aligned(FrameGpa::new(Self::ROOT_GPA)).unwrap();
        extents.set_root_generation(root, Self::GEN);
        Self {
            _backing: backing,
            placement,
            extents,
            next_gpa: SOFT_TLB_PAGE_SIZE,
        }
    }

    fn register_root(&mut self, root_gpa: u64) {
        let root = RootGpa::page_aligned(FrameGpa::new(root_gpa)).unwrap();
        self.extents.set_root_generation(root, Self::GEN);
    }

    fn alloc_frame(&mut self) -> FrameGpa {
        let gpa = self.next_gpa;
        self.next_gpa += SOFT_TLB_PAGE_SIZE;
        assert!(self.next_gpa <= Self::POOL_BYTES, "test pool exhausted");
        FrameGpa::new(gpa)
    }

    fn word_ref(&self, gpa: u64) -> &AtomicU64 {
        let addr = self.placement.base_host_addr() + (gpa as usize);
        // SAFETY: `gpa` is 8-byte aligned inside `[0, POOL_BYTES)`.
        unsafe { &*(addr as *const AtomicU64) }
    }

    fn write_gpa(&mut self, gpa: u64, src: &[u8]) {
        assert!((gpa as usize) + src.len() <= Self::POOL_BYTES as usize);
        let dst = (self.placement.base_host_addr() + gpa as usize) as *mut u8;
        // SAFETY: `[gpa, gpa + src.len())` lies inside `[0, POOL_BYTES)`.
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
    }

    fn read_gpa(&self, gpa: u64, len: usize) -> Vec<u8> {
        assert!((gpa as usize) + len <= Self::POOL_BYTES as usize);
        let src = (self.placement.base_host_addr() + gpa as usize) as *const u8;
        let mut out = vec![0u8; len];
        // SAFETY: `[gpa, gpa + len)` lies inside `[0, POOL_BYTES)`.
        unsafe { std::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), len) };
        out
    }

    fn read_u64(&self, gpa: u64) -> u64 {
        u64::from_le_bytes(self.read_gpa(gpa, 8).try_into().unwrap())
    }

    fn read_u32(&self, gpa: u64) -> u32 {
        u32::from_le_bytes(self.read_gpa(gpa, 4).try_into().unwrap())
    }

    fn ensure_child_in_root(&mut self, table_gpa: u64, idx: usize) -> u64 {
        let slot = table_gpa + (idx as u64) * 8;
        let cur = self.word_ref(slot).load(Ordering::Relaxed);
        if (cur & PTE_PRESENT) != 0 {
            return cur & PTE_ADDR_MASK;
        }
        let child = self.alloc_frame().raw();
        self.word_ref(slot)
            .store(child | PTE_PRESENT | PTE_WRITABLE | PTE_USER, Ordering::Relaxed);
        child
    }

    fn map_at_root(&mut self, root_gpa: u64, va: u64, frame: FrameGpa, p: Perms) {
        let va_page = va & SOFT_TLB_PAGE_MASK;
        let mut tbl = root_gpa;
        for shift in [39, 30, 21] {
            tbl = self.ensure_child_in_root(tbl, ((va_page >> shift) & 0x1ff) as usize);
        }
        let w = if (p.0 & 2) != 0 { PTE_WRITABLE } else { 0 };
        let u = if (p.0 & 8) != 0 { PTE_USER } else { 0 };
        let nx = if (p.0 & 4) == 0 { PTE_NX } else { 0 };
        let pte = (frame.raw() & PTE_ADDR_MASK) | PTE_PRESENT | w | u | nx;
        self.word_ref(tbl + ((va_page >> 12) & 0x1ff) * 8)
            .store(pte, Ordering::Relaxed);
    }

    fn map_page(&mut self, va: u64, p: Perms) -> FrameGpa {
        let f = self.alloc_frame();
        self.map_at_root(Self::ROOT_GPA, va, f, p);
        f
    }
}

// SAFETY: `Cpl0TestMemory` pairs `placement` with its single private `extents` domain.
unsafe impl SoftMmuMemory for Cpl0TestMemory {
    fn placement(&self) -> &LinearPlacement {
        &self.placement
    }
    fn extents(&self) -> &ExtentTable {
        &self.extents
    }
    fn extents_mut(&mut self) -> &mut ExtentTable {
        &mut self.extents
    }
}

fn gp(rip: u64, code: u32) -> X86Exception {
    X86Exception::general_protection(rip, code)
}
fn ud(rip: u64) -> X86Exception {
    X86Exception::invalid_opcode(rip)
}
fn ss(rip: u64, code: u32) -> X86Exception {
    X86Exception::stack_segment_fault(rip, code)
}
fn np(rip: u64, code: u32) -> X86Exception {
    X86Exception::segment_not_present(rip, code)
}
fn pf(rip: u64, code: u32, cr2: u64) -> X86Exception {
    X86Exception::page_fault(rip, code, cr2)
}

fn setup_cpl0_cpu(
    code: &[u8],
    cpuid: Box<dyn GuestCpuidView>,
) -> (SoftCpu, Cpl0TestMemory, FrameGpa) {
    let mut mem = Cpl0TestMemory::new();
    let code_frame = mem.map_page(CODE_VA, Perms::KERNEL_RX);
    mem.write_gpa(code_frame.raw(), code);
    let data_frame = mem.map_page(DATA_VA, Perms::KERNEL_RW);
    let _stack = mem.map_page(STACK_VA, Perms::KERNEL_RW);
    let mut cpu = SoftCpu::with_cpuid_view(mem.extents(), cpuid).unwrap();
    enter_cpl0(cpu.context_mut(), CODE_VA);
    cpu.context_mut().gpr[reg::RSP] = STACK_VA + 0x800;
    (cpu, mem, data_frame)
}

fn enter_cpl0(ctx: &mut SoftCpuContext, rip: u64) {
    ctx.set_cpl(0);
    ctx.cs = SoftSegment::kernel_code64(0x08);
    ctx.ss = SoftSegment::kernel_data(0x10);
    ctx.rip = rip;
}

fn enter_cpl3(ctx: &mut SoftCpuContext, rip: u64) {
    ctx.set_cpl(3);
    ctx.cs = SoftSegment::user_code64(0x23);
    ctx.ss = SoftSegment::user_data(0x1b);
    ctx.rip = rip;
}

fn step_ok(cpu: &mut SoftCpu, mem: &mut Cpl0TestMemory, next_rip: u64) {
    let exit = cpu.step_block(mem).unwrap();
    assert_eq!(exit, SoftCpuExit::Continue { next_rip });
}

fn step_exc(cpu: &mut SoftCpu, mem: &mut Cpl0TestMemory, exc: X86Exception) {
    assert_eq!(cpu.step_block(mem).unwrap(), SoftCpuExit::Exception(exc));
}

fn step_rax_ok(cpu: &mut SoftCpu, mem: &mut Cpl0TestMemory, rip: u64, rax: u64, next_rip: u64) {
    cpu.context_mut().rip = rip;
    cpu.context_mut().gpr[reg::RAX] = rax;
    step_ok(cpu, mem, next_rip);
}

fn step_rax_gp(cpu: &mut SoftCpu, mem: &mut Cpl0TestMemory, rip: u64, rax: u64, err: u32) {
    cpu.context_mut().rip = rip;
    cpu.context_mut().gpr[reg::RAX] = rax;
    step_exc(cpu, mem, gp(rip, err));
}

fn read_ok(cpu: &mut SoftCpu, mem: &mut Cpl0TestMemory, va: u64) {
    let _ = translate_va(cpu.context_mut(), mem, va, SoftAccessKind::Read).unwrap();
}

fn assert_cpl3_exc(insn: &[u8], rcx: u64, exc: X86Exception) {
    let (mut cpu, mut mem, _) = setup_cpl0_cpu(insn, Box::new(Cpl0CpuidView::default()));
    let user_code = mem.map_page(USER_CODE_VA, Perms::USER_RX);
    mem.write_gpa(user_code.raw(), insn);
    enter_cpl3(cpu.context_mut(), USER_CODE_VA);
    cpu.context_mut().gpr[reg::RCX] = rcx;
    step_exc(&mut cpu, &mut mem, exc);
}

fn to_vmx_seg(s: SoftSegment) -> GuestSegment {
    GuestSegment {
        base: s.base,
        limit: s.limit,
        ar: s.ar,
        selector: s.selector,
    }
}

fn assert_vmx_valid(ctx: &SoftCpuContext) {
    let segs = LongModeSegments {
        cs: to_vmx_seg(ctx.cs),
        ss: to_vmx_seg(ctx.ss),
        ds: to_vmx_seg(ctx.ds),
        es: to_vmx_seg(ctx.es),
        fs: to_vmx_seg(ctx.fs),
        gs: to_vmx_seg(ctx.gs),
        tr: to_vmx_seg(ctx.tr),
        ldtr: to_vmx_seg(ctx.ldtr),
        cr0: ctx.cr0,
        cr4: ctx.cr4,
        efer: ctx.efer,
        rflags: ctx.rflags,
    };
    assert_eq!(check_vmx_guest_segments(&segs, false), Ok(()));
}

#[test]
fn msr_file_and_rdmsr_wrmsr_enforce_sdm_semantics_and_gp_ud_paths() {
    let mut msrs = MsrFile::new();
    let caps = MsrCapabilities::default();
    let cr0_pg = 0x8005_0033u64;
    let err_gp = Err(MsrError::GeneralProtection);

    assert_eq!(
        msrs.read(MSR_IA32_APIC_BASE, caps),
        Ok(DEFAULT_IA32_APIC_BASE)
    );
    assert_eq!(msrs.read(MSR_IA32_PAT, caps), Ok(DEFAULT_IA32_PAT));
    assert_eq!(msrs.read(MSR_IA32_TSC_DEADLINE, caps), err_gp);
    assert_eq!(msrs.read(MsrIndex::new(0xdead_beef), caps), err_gp);

    for idx in [
        MSR_IA32_LSTAR,
        MSR_IA32_CSTAR,
        MSR_IA32_FS_BASE,
        MSR_IA32_GS_BASE,
        MSR_IA32_KERNEL_GS_BASE,
    ] {
        let before = msrs.clone();
        assert_eq!(msrs.write(idx, NON_CANON, cr0_pg, caps), err_gp);
        assert_eq!(msrs, before);
    }
    let bad_msrs = [
        (MSR_IA32_FMASK, 1u64 << 32),
        (MSR_IA32_PAT, 0x0007_0406_0007_0402),
        (MSR_IA32_PAT, 0x0007_0406_0007_0408),
        (MSR_IA32_APIC_BASE, DEFAULT_IA32_APIC_BASE | 1),
        (MSR_IA32_APIC_BASE, DEFAULT_IA32_APIC_BASE | (1 << 9)),
        (MSR_IA32_APIC_BASE, DEFAULT_IA32_APIC_BASE | (1 << 10)),
        (MSR_IA32_APIC_BASE, (1u64 << 48) | 0x900),
        (MSR_IA32_MISC_ENABLE, 1u64 << 39),
        (MSR_IA32_EFER, EFER_SCE | EFER_NXE),
        (MSR_IA32_EFER, 1u64 << 63),
        (MsrIndex::new(0x9999), 0),
    ];
    for (idx, bad) in bad_msrs {
        let before = msrs.clone();
        assert_eq!(msrs.write(idx, bad, cr0_pg, caps), err_gp);
        assert_eq!(msrs, before);
    }

    let eff = msrs
        .write(MSR_IA32_EFER, EFER_SCE | EFER_LME, cr0_pg, caps)
        .unwrap();
    assert!(eff.flush_tlb && msrs.efer == (EFER_SCE | EFER_LME | EFER_LMA));
    let eff_pat = msrs
        .write(MSR_IA32_PAT, 0x0000_0104_0506_0700, cr0_pg, caps)
        .unwrap();
    assert!(eff_pat.flush_tlb);

    for insn in [&[0xF0, 0x0F, 0x30][..], &[0xF0, 0x0F, 0x32][..]] {
        assert_cpl3_exc(insn, 0, ud(USER_CODE_VA));
    }
    for insn in [&[0x0F, 0x30][..], &[0x0F, 0x32][..]] {
        assert_cpl3_exc(insn, u64::from(MSR_IA32_STAR.raw()), gp(USER_CODE_VA, 0));
    }

    let (mut cpu, mut mem, _) = setup_cpl0_cpu(
        &[0x0F, 0x30, 0x0F, 0x32],
        Box::new(Cpl0CpuidView::default()),
    );
    read_ok(&mut cpu, &mut mem, DATA_VA);
    read_ok(&mut cpu, &mut mem, DATA_VA);
    assert_eq!(cpu.context().tlb_stats().hits, 1);

    let ctx = cpu.context_mut();
    ctx.gpr[reg::RCX] = 0xffff_ffff_0000_0000 | u64::from(MSR_IA32_TSC_DEADLINE.raw());
    ctx.gpr[reg::RAX] = 0xaaaa_bbbb_89ab_cdef;
    ctx.gpr[reg::RDX] = 0xcccc_dddd_0123_4567;
    step_ok(&mut cpu, &mut mem, CODE_VA + 2);
    cpu.context_mut().gpr[reg::RAX] = u64::MAX;
    cpu.context_mut().gpr[reg::RDX] = u64::MAX;
    step_ok(&mut cpu, &mut mem, CODE_VA + 4);
    assert_eq!(cpu.context().gpr[reg::RAX], 0x89ab_cdef);
    assert_eq!(cpu.context().gpr[reg::RDX], 0x0123_4567);

    cpu.context_mut().gpr[reg::RCX] = u64::from(MSR_IA32_LSTAR.raw());
    cpu.context_mut().gpr[reg::RDX] = 0x0000_8000;
    step_rax_gp(&mut cpu, &mut mem, CODE_VA, 0, 0);
    assert_eq!(cpu.context().msrs.lstar, 0);

    cpu.context_mut().rip = CODE_VA;
    cpu.context_mut().gpr[reg::RCX] = u64::from(MSR_IA32_PAT.raw());
    cpu.context_mut().gpr[reg::RAX] = 0x0007_0400;
    cpu.context_mut().gpr[reg::RDX] = 0x0007_0406;
    step_ok(&mut cpu, &mut mem, CODE_VA + 2);
    cpu.context_mut().reset_tlb_stats();
    read_ok(&mut cpu, &mut mem, DATA_VA);
    assert_eq!(cpu.context().tlb_stats().misses, 1);
}

#[test]
fn mov_cr_and_mov_dr_enforce_sdm_semantics_tlb_flushes_and_fault_ordering() {
    let ud_ops: [&[u8]; 8] = [
        &[0x0F, 0x20, 0xC8],
        &[0x0F, 0x22, 0xE8],
        &[0x0F, 0x20, 0xF0],
        &[0x0F, 0x22, 0xF8],
        &[0x44, 0x0F, 0x20, 0xC8],
        &[0xF0, 0x0F, 0x20, 0xC0],
        &[0x44, 0x0F, 0x21, 0xC0],
        &[0xF0, 0x0F, 0x23, 0xC0],
    ];
    for bytes in ud_ops {
        assert_cpl3_exc(bytes, 0, ud(USER_CODE_VA));
    }
    let gp_ops: [&[u8]; 5] = [
        &[0x0F, 0x20, 0xC0],
        &[0x0F, 0x22, 0xD0],
        &[0x0F, 0x20, 0xD8],
        &[0x0F, 0x22, 0xE0],
        &[0x44, 0x0F, 0x20, 0xC0],
    ];
    for bytes in gp_ops {
        assert_cpl3_exc(bytes, 0, gp(USER_CODE_VA, 0));
    }

    let (mut cpu, mut mem, _) = setup_cpl0_cpu(
        &[0x0F, 0x22, 0xC0, 0x0F, 0x20, 0xC0],
        Box::new(Cpl0CpuidView::new(0, 0)),
    );
    for bad_cr0 in [
        0x8005_0033 | (1u64 << 32),
        0x8005_0032,
        0x8005_0033 | (1u64 << 29),
        0x0005_0033,
    ] {
        step_rax_gp(&mut cpu, &mut mem, CODE_VA, bad_cr0, 0);
    }
    cpu.context_mut().rip = CODE_VA;
    cpu.context_mut().gpr[reg::RAX] = (0x8001_0033 & !(1 << 4)) | (1 << 6);
    step_ok(&mut cpu, &mut mem, CODE_VA + 3);
    cpu.context_mut().gpr[reg::RAX] = 0;
    step_ok(&mut cpu, &mut mem, CODE_VA + 6);
    assert_eq!(cpu.context().gpr[reg::RAX], 0x8001_0033);

    let mut view = Cpl0CpuidView::default();
    view.max_phy_addr = 40;
    let code = [
        0x0F, 0x22, 0xD0, 0x0F, 0x20, 0xD0, 0x44, 0x0F, 0x22, 0xC0, 0x44, 0x0F, 0x20, 0xC0, 0x0F,
        0x22, 0xE0, 0x0F, 0x22, 0xD8, 0x0F, 0x20, 0xD8, 0x0F, 0x31,
    ];
    let (mut cpu, mut mem, _) = setup_cpl0_cpu(&code, Box::new(view));
    cpu.context_mut().gpr[reg::RAX] = 0xdead_beef_cafe_babe;
    step_ok(&mut cpu, &mut mem, CODE_VA + 3);
    cpu.context_mut().gpr[reg::RAX] = 0;
    step_ok(&mut cpu, &mut mem, CODE_VA + 6);
    assert_eq!(cpu.context().gpr[reg::RAX], 0xdead_beef_cafe_babe);

    step_rax_gp(&mut cpu, &mut mem, CODE_VA + 6, 16, 0);
    cpu.context_mut().gpr[reg::RAX] = 12;
    step_ok(&mut cpu, &mut mem, CODE_VA + 10);
    cpu.context_mut().gpr[reg::RAX] = 0;
    step_ok(&mut cpu, &mut mem, CODE_VA + 14);
    assert_eq!(cpu.context().gpr[reg::RAX], 12);

    for bad_cr4 in [0x0034_06d0u64, 0x0034_16f0u64, 1u64 << 22] {
        step_rax_gp(&mut cpu, &mut mem, CODE_VA + 14, bad_cr4, 0);
    }
    cpu.context_mut().cr3 = 1;
    step_rax_gp(&mut cpu, &mut mem, CODE_VA + 14, 0x0036_06f0, 0);
    cpu.context_mut().cr3 = 0;
    cpu.context_mut().rip = CODE_VA + 14;
    cpu.context_mut().gpr[reg::RAX] = 0x0036_06f4;
    step_ok(&mut cpu, &mut mem, CODE_VA + 17);

    step_rax_gp(&mut cpu, &mut mem, CODE_VA + 17, 1u64 << 40, 0);
    read_ok(&mut cpu, &mut mem, DATA_VA);
    cpu.context_mut().rip = CODE_VA + 17;
    cpu.context_mut().gpr[reg::RAX] = (1u64 << 63) | 0x0007;
    step_ok(&mut cpu, &mut mem, CODE_VA + 20);
    step_ok(&mut cpu, &mut mem, CODE_VA + 23);
    assert_eq!(cpu.context().gpr[reg::RAX], 0x0007);
    cpu.context_mut().reset_tlb_stats();
    read_ok(&mut cpu, &mut mem, DATA_VA);
    assert_eq!(cpu.context().tlb_stats().hits, 1);

    step_ok(&mut cpu, &mut mem, CODE_VA + 25);
    let user_rdtsc = mem.map_page(USER_CODE_VA, Perms::USER_RX);
    mem.write_gpa(user_rdtsc.raw(), &[0x0F, 0x31]);
    enter_cpl3(cpu.context_mut(), USER_CODE_VA);
    step_exc(&mut cpu, &mut mem, gp(USER_CODE_VA, 0));

    let dr_code = [
        0x0F, 0x23, 0xE0, 0x0F, 0x21, 0xF0, 0x0F, 0x23, 0xF8, 0x0F, 0x23, 0xC0,
    ];
    let (mut cpu, mut mem, _) = setup_cpl0_cpu(&dr_code, Box::new(Cpl0CpuidView::default()));
    let user_dr4 = mem.map_page(USER_CODE_VA, Perms::USER_RX);
    mem.write_gpa(user_dr4.raw(), &[0x0F, 0x21, 0xE0]);
    cpu.context_mut().cr4 |= 1 << 3;
    enter_cpl3(cpu.context_mut(), USER_CODE_VA);
    step_exc(&mut cpu, &mut mem, ud(USER_CODE_VA));
    cpu.context_mut().cr4 &= !(1 << 3);
    cpu.context_mut().rip = USER_CODE_VA;
    step_exc(&mut cpu, &mut mem, gp(USER_CODE_VA, 0));

    enter_cpl0(cpu.context_mut(), CODE_VA);
    step_rax_gp(&mut cpu, &mut mem, CODE_VA, 1u64 << 32, 0);
    cpu.context_mut().rip = CODE_VA;
    cpu.context_mut().gpr[reg::RAX] = 0x0000_0005;
    step_ok(&mut cpu, &mut mem, CODE_VA + 3);
    step_ok(&mut cpu, &mut mem, CODE_VA + 6);
    assert_eq!(cpu.context().gpr[reg::RAX], 0xffff_0ff5);

    cpu.context_mut().gpr[reg::RAX] = 1 << 13;
    step_ok(&mut cpu, &mut mem, CODE_VA + 9);
    cpu.context_mut().gpr[reg::RAX] = 0x1234_5678;
    step_exc(&mut cpu, &mut mem, X86Exception::debug(CODE_VA + 9));
    assert_ne!(cpu.context().dr[6] & (1 << 13), 0);
    assert_eq!(cpu.context().dr[7] & (1 << 13), 0);
    assert_eq!(cpu.context().dr[0], 0);
}

fn tss64(base: u64, limit: u32, typ: u8, s: bool, p: bool, rsvd: u8) -> [u8; 16] {
    let low = u64::from(limit & 0xffff)
        | ((base & 0xffff) << 16)
        | (((base >> 16) & 0xff) << 32)
        | (u64::from(typ & 0xf) << 40)
        | (u64::from(s) << 44)
        | (u64::from(p) << 47)
        | (u64::from((limit >> 16) & 0xf) << 48)
        | (((base >> 24) & 0xff) << 56);
    let high = (base >> 32) | (u64::from(rsvd) << 40);
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&low.to_le_bytes());
    out[8..16].copy_from_slice(&high.to_le_bytes());
    out
}

fn write_dt_ptr(mem: &mut Cpl0TestMemory, gpa: u64, limit: u16, base: u64) {
    let mut ptr = [0u8; 10];
    ptr[0..2].copy_from_slice(&limit.to_le_bytes());
    ptr[2..10].copy_from_slice(&base.to_le_bytes());
    mem.write_gpa(gpa, &ptr);
}

#[test]
fn lgdt_lidt_ltr_and_swapgs_enforce_descriptor_and_gs_semantics() {
    let code = [
        0x66, 0x0F, 0x01, 0x17, 0x0F, 0x01, 0x1F, 0x0F, 0x00, 0xD8, 0x48, 0x0F, 0x00, 0xC8, 0x0F,
        0x01, 0xF8, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
    ];
    let (mut cpu, mut mem, data_frame) = setup_cpl0_cpu(&code, Box::new(Cpl0CpuidView::default()));

    write_dt_ptr(&mut mem, data_frame.raw(), 0x3f, NON_CANON);
    cpu.context_mut().gpr[reg::RDI] = DATA_VA;
    step_exc(&mut cpu, &mut mem, gp(CODE_VA, 0));
    assert_eq!(cpu.context().gdtr, DescriptorTablePtr::new(0, 0));

    cpu.context_mut().rip = CODE_VA + 4;
    cpu.context_mut().gpr[reg::RDI] = 0x1234_5000;
    step_exc(&mut cpu, &mut mem, pf(CODE_VA + 4, 0, 0x1234_5000));

    let (gdt_va, idt_va) = (DATA_VA + 0x100, DATA_VA + 0x200);
    write_dt_ptr(&mut mem, data_frame.raw(), 0x37, gdt_va);
    write_dt_ptr(&mut mem, data_frame.raw() + 0x20, 0x0fff, idt_va);
    cpu.context_mut().rip = CODE_VA;
    cpu.context_mut().gpr[reg::RDI] = DATA_VA;
    step_ok(&mut cpu, &mut mem, CODE_VA + 4);
    assert_eq!(cpu.context().gdtr, DescriptorTablePtr::new(0x37, gdt_va));
    cpu.context_mut().gpr[reg::RDI] = DATA_VA + 0x20;
    step_ok(&mut cpu, &mut mem, CODE_VA + 7);
    assert_eq!(cpu.context().idtr, DescriptorTablePtr::new(0x0fff, idt_va));

    for (sel, err) in [(0u16, 0u32), (3, 0), (4, 4), (0x1c, 0x1c), (0x30, 0x30)] {
        step_rax_gp(&mut cpu, &mut mem, CODE_VA + 7, u64::from(sel), err);
    }

    let (desc_off, tss_base, gp28) = (0x128u64, DATA_VA + 0x400, gp(CODE_VA + 7, 0x28));
    let bad_tss_cases = [
        (tss64(tss_base, 0x67, 0x9, true, true, 0), gp28),
        (tss64(tss_base, 0x67, 0xb, false, true, 0), gp28),
        (tss64(tss_base, 0x67, 0x9, false, true, 1), gp28),
        (tss64(NON_CANON, 0x67, 0x9, false, true, 0), gp28),
        (tss64(tss_base, 0x66, 0x9, false, true, 0), gp28),
        (
            tss64(tss_base, 0x67, 0x9, false, false, 0),
            np(CODE_VA + 7, 0x28),
        ),
    ];
    for (desc, exc) in bad_tss_cases {
        mem.write_gpa(data_frame.raw() + desc_off, &desc);
        cpu.context_mut().rip = CODE_VA + 7;
        cpu.context_mut().gpr[reg::RAX] = 0x28;
        step_exc(&mut cpu, &mut mem, exc);
        assert_eq!(mem.read_gpa(data_frame.raw() + desc_off, 16), desc);
    }

    let valid_tss = tss64(tss_base, 0x67, 0x9, false, true, 0);
    mem.write_gpa(data_frame.raw() + desc_off, &valid_tss);
    cpu.context_mut().rip = CODE_VA + 7;
    cpu.context_mut().gpr[reg::RAX] = 0x28;
    step_ok(&mut cpu, &mut mem, CODE_VA + 10);
    assert_eq!(
        cpu.context().tr,
        SoftSegment::tss64_busy(0x28, tss_base, 0x67)
    );
    let updated = u64::from_le_bytes(
        mem.read_gpa(data_frame.raw() + desc_off, 8)
            .try_into()
            .unwrap(),
    );
    assert_eq!((updated >> 40) & 0xf, 0xb);

    step_ok(&mut cpu, &mut mem, CODE_VA + 14);
    assert_eq!(cpu.context().gpr[reg::RAX], 0x28);
    step_rax_gp(&mut cpu, &mut mem, CODE_VA + 7, 0x28, 0x28);

    let (gs_user_va, gs_kern_va) = (DATA_VA + 0x500, DATA_VA + 0x600);
    mem.write_gpa(
        data_frame.raw() + 0x500,
        &0x1111_2222_3333_4444u64.to_le_bytes(),
    );
    mem.write_gpa(
        data_frame.raw() + 0x600,
        &0xaaaa_bbbb_cccc_ddddu64.to_le_bytes(),
    );
    cpu.context_mut().gs_base = gs_user_va;
    cpu.context_mut().kernel_gs_base = gs_kern_va;
    cpu.context_mut().rip = CODE_VA + 14;
    step_ok(&mut cpu, &mut mem, CODE_VA + 17);
    assert_eq!(cpu.context().msrs.gs_base, gs_kern_va);
    assert_eq!(cpu.context().msrs.kernel_gs_base, gs_user_va);
    step_ok(&mut cpu, &mut mem, CODE_VA + 26);
    assert_eq!(cpu.context().gpr[reg::RAX], 0xaaaa_bbbb_cccc_dddd);
}

#[test]
fn sysret_and_iretq_enforce_privilege_transitions_and_fault_paths() {
    let code = [0x48, 0x0F, 0x07, 0x0F, 0x07, 0x48, 0xCF];
    let (mut cpu, mut mem, data_frame) = setup_cpl0_cpu(&code, Box::new(Cpl0CpuidView::default()));
    let user_page = mem.map_page(USER_CODE_VA, Perms::USER_RX);
    mem.write_gpa(user_page.raw(), &[0x90, 0x48, 0xCF]);

    let boot = X8664GuestArch::bootstrap_sysregs();
    let mut gdt_words = boot.gdt.to_vec();
    gdt_words.extend_from_slice(&[
        0x0000_9b00_0000_0000,
        0x0020_1b00_0000_0000,
        0x0000_7300_0000_0000,
    ]);
    let gdt_bytes: Vec<u8> = gdt_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    mem.write_gpa(data_frame.raw(), &gdt_bytes);
    cpu.context_mut().gdtr = DescriptorTablePtr::new((gdt_bytes.len() - 1) as u16, DATA_VA);
    cpu.context_mut().msrs.star = boot.star;

    cpu.context_mut().efer &= !EFER_SCE;
    enter_cpl3(cpu.context_mut(), USER_CODE_VA + 1);
    mem.write_gpa(user_page.raw() + 1, &[0x48, 0x0F, 0x07]);
    step_exc(&mut cpu, &mut mem, ud(USER_CODE_VA + 1));
    cpu.context_mut().efer |= EFER_SCE;
    cpu.context_mut().rip = USER_CODE_VA + 1;
    step_exc(&mut cpu, &mut mem, gp(USER_CODE_VA + 1, 0));
    mem.write_gpa(user_page.raw(), &[0x90, 0x48, 0xCF]);

    enter_cpl0(cpu.context_mut(), CODE_VA);
    cpu.context_mut().gpr[reg::RCX] = NON_CANON;
    step_exc(&mut cpu, &mut mem, gp(CODE_VA, 0));
    assert_eq!(cpu.context().cpl, 0);
    cpu.context_mut().rip = CODE_VA + 3;
    cpu.context_mut().gpr[reg::RCX] = USER_CODE_VA;
    step_exc(&mut cpu, &mut mem, gp(CODE_VA + 3, 0));

    cpu.context_mut().rip = CODE_VA;
    cpu.context_mut().gpr[reg::RCX] = USER_CODE_VA;
    cpu.context_mut().gpr[reg::R11] = 0x202 | (1 << 16) | (1 << 17);
    step_ok(&mut cpu, &mut mem, USER_CODE_VA);
    assert_eq!(cpu.context().cpl, 3);
    assert_eq!(
        (cpu.context().cs.selector, cpu.context().ss.selector),
        (0x23, 0x1b)
    );
    assert_eq!(cpu.context().rflags, 0x202);
    assert_vmx_valid(cpu.context());

    let user_stack_va = 0x0000_0000_0050_0000;
    let user_stack_frame = mem.map_page(user_stack_va, Perms::USER_RW);
    let put_frame = |m: &mut Cpl0TestMemory, gpa: u64, words: [u64; 5]| {
        let bytes: Vec<u8> = words.into_iter().flat_map(u64::to_le_bytes).collect();
        m.write_gpa(gpa, &bytes);
    };
    let esc_frame = [CODE_VA, 0x08, 0x202, STACK_VA + 0x800, 0x10];
    put_frame(&mut mem, user_stack_frame.raw() + 0x100, esc_frame);
    cpu.context_mut().gpr[reg::RSP] = user_stack_va + 0x100;
    cpu.context_mut().rip = USER_CODE_VA + 1;
    step_exc(&mut cpu, &mut mem, gp(USER_CODE_VA + 1, 0x08));

    enter_cpl0(cpu.context_mut(), CODE_VA + 5);
    cpu.context_mut().rflags = 0x202 | (1 << 14);
    cpu.context_mut().gpr[reg::RSP] = NON_CANON;
    step_exc(&mut cpu, &mut mem, gp(CODE_VA + 5, 0));
    cpu.context_mut().rflags = 0x202;
    cpu.context_mut().rip = CODE_VA + 5;
    step_exc(&mut cpu, &mut mem, ss(CODE_VA + 5, 0));

    let (iret_frame_va, ustk, ip) = (DATA_VA + 0x800, user_stack_va + 0x200, CODE_VA + 5);
    let iret_faults = [
        ([USER_CODE_VA, 0, 0x202, ustk, 0x1b], gp(ip, 0)),
        ([CODE_VA, 0x28, 0x202, STACK_VA + 0x400, 0x10], gp(ip, 0x28)),
        ([CODE_VA, 0x30, 0x202, STACK_VA + 0x400, 0x10], np(ip, 0x30)),
        ([NON_CANON, 0x23, 0x202, ustk, 0x1b], gp(ip, 0)),
        ([USER_CODE_VA, 0x23, 0x202, ustk, 0], gp(ip, 0)),
        ([USER_CODE_VA, 0x23, 0x202, ustk, 0x3b], ss(ip, 0x38)),
        ([USER_CODE_VA, 0x23, 0x202, NON_CANON, 0x1b], ss(ip, 0)),
    ];
    for (words, exc) in iret_faults {
        put_frame(&mut mem, data_frame.raw() + 0x800, words);
        cpu.context_mut().gpr[reg::RSP] = iret_frame_va;
        cpu.context_mut().rip = ip;
        step_exc(&mut cpu, &mut mem, exc);
    }

    let k_frame = [ip, 0x08, 0x202, DATA_VA + 0x840, 0];
    let u_frame = [USER_CODE_VA, 0x23, 0x246, user_stack_va + 0x300, 0x1b];
    put_frame(&mut mem, data_frame.raw() + 0x800, k_frame);
    put_frame(&mut mem, data_frame.raw() + 0x840, u_frame);
    cpu.context_mut().ds = SoftSegment::kernel_data(0x10);
    cpu.context_mut().es = SoftSegment::kernel_data(0x10);
    cpu.context_mut().gpr[reg::RSP] = iret_frame_va;
    cpu.context_mut().rip = ip;
    step_ok(&mut cpu, &mut mem, ip);
    assert_eq!(cpu.context().cpl, 0);
    assert!(cpu.context().ss.is_unusable());
    assert_vmx_valid(cpu.context());

    step_ok(&mut cpu, &mut mem, USER_CODE_VA);
    assert_eq!(cpu.context().cpl, 3);
    assert!(cpu.context().ds.is_unusable() && cpu.context().es.is_unusable());
    assert_vmx_valid(cpu.context());
}

struct CustomCpuidView;
impl GuestCpuidView for CustomCpuidView {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidRegs {
        CpuidRegs::new(
            0xaa00_0000 | leaf,
            0xbb00_0000 | subleaf,
            0xcc00_1234,
            0xdd00_5678,
        )
    }
}

#[test]
fn hlt_invlpg_and_cpuid_view_enforce_sdm_contracts() {
    let (mut cpu, mut mem, _) = setup_cpl0_cpu(&[0x0F, 0xA2], Box::new(CustomCpuidView));
    let user_cpuid = mem.map_page(USER_CODE_VA, Perms::USER_RX);
    mem.write_gpa(user_cpuid.raw(), &[0x0F, 0xA2, 0xF4, 0x0F, 0x01, 0x3F]);
    for (cpl, start_rip) in [(3u8, USER_CODE_VA), (0u8, CODE_VA)] {
        if cpl == 0 {
            enter_cpl0(cpu.context_mut(), start_rip);
        } else {
            enter_cpl3(cpu.context_mut(), start_rip);
        }
        let ctx = cpu.context_mut();
        ctx.gpr[reg::RAX] = 0xffff_ffff_0000_0007;
        ctx.gpr[reg::RBX] = u64::MAX;
        ctx.gpr[reg::RCX] = 0xffff_ffff_0000_0002;
        ctx.gpr[reg::RDX] = u64::MAX;
        step_ok(&mut cpu, &mut mem, start_rip + 2);
        let g = &cpu.context().gpr;
        assert_eq!(g[reg::RAX], 0xaa00_0007);
        assert_eq!(g[reg::RBX], 0xbb00_0002);
        assert_eq!(g[reg::RCX], 0xcc00_1234);
        assert_eq!(g[reg::RDX], 0xdd00_5678);
    }

    enter_cpl3(cpu.context_mut(), USER_CODE_VA + 2);
    step_exc(&mut cpu, &mut mem, gp(USER_CODE_VA + 2, 0));
    assert!(!cpu.context().halted);
    cpu.context_mut().rip = USER_CODE_VA + 3;
    step_exc(&mut cpu, &mut mem, gp(USER_CODE_VA + 3, 0));

    let code = [
        0x0F, 0x22, 0xE0, 0x0F, 0xA2, 0x0F, 0x01, 0x3F, 0x48, 0x8B, 0x07, 0xF4,
    ];
    let (mut cpu, mut mem, data_frame) = setup_cpl0_cpu(&code, Box::new(Level0CpuidView));
    let bad_sys: [&[u8]; 4] = [
        &[0xF0, 0xF4],
        &[0xF0, 0x0F, 0x01, 0x3F],
        &[0xF0, 0x0F, 0xA2],
        &[0x0F, 0x01, 0xFA],
    ];
    for bad in bad_sys {
        let f = mem.map_page(DATA_VA + 0x3000, Perms::KERNEL_RX);
        mem.write_gpa(f.raw(), bad);
        cpu.context_mut().flush_tlb();
        cpu.context_mut().rip = DATA_VA + 0x3000;
        step_exc(&mut cpu, &mut mem, ud(DATA_VA + 0x3000));
    }

    cpu.context_mut().rip = CODE_VA;
    cpu.context_mut().gpr[reg::RAX] = 0x0030_06f0;
    step_ok(&mut cpu, &mut mem, CODE_VA + 3);
    cpu.context_mut().gpr[reg::RAX] = 1;
    cpu.context_mut().gpr[reg::RCX] = 0;
    step_ok(&mut cpu, &mut mem, CODE_VA + 5);
    assert_eq!(cpu.context().gpr[reg::RCX] & (1 << 27), 0);

    cpu.context_mut().rip = CODE_VA;
    cpu.context_mut().gpr[reg::RAX] = 0x0034_06f0;
    step_ok(&mut cpu, &mut mem, CODE_VA + 3);
    cpu.context_mut().gpr[reg::RAX] = 1;
    step_ok(&mut cpu, &mut mem, CODE_VA + 5);
    assert_ne!(cpu.context().gpr[reg::RCX] & (1 << 27), 0);

    for addr in [NON_CANON, 0x7777_0000] {
        cpu.context_mut().rip = CODE_VA + 5;
        cpu.context_mut().gpr[reg::RDI] = addr;
        step_ok(&mut cpu, &mut mem, CODE_VA + 8);
    }

    let sibling_va = DATA_VA + 0x1000;
    let sibling_frame = mem.map_page(sibling_va, Perms::KERNEL_RW);
    mem.write_gpa(data_frame.raw(), &0x1111_1111_1111_1111u64.to_le_bytes());
    mem.write_gpa(sibling_frame.raw(), &0x2222_2222_2222_2222u64.to_le_bytes());
    read_ok(&mut cpu, &mut mem, DATA_VA);
    read_ok(&mut cpu, &mut mem, sibling_va);

    let replacement = mem.alloc_frame();
    mem.write_gpa(replacement.raw(), &0x9999_8888_7777_6666u64.to_le_bytes());
    mem.map_at_root(
        Cpl0TestMemory::ROOT_GPA,
        DATA_VA,
        replacement,
        Perms::KERNEL_RW,
    );

    let mut machine = SoftMachine::from_parts(cpu, mem);
    machine.context_mut().rip = CODE_VA + 5;
    machine.context_mut().gpr[reg::RDI] = DATA_VA;
    assert_eq!(
        machine.run(8).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA + 11,
            next_rip: CODE_VA + 12
        }
    );
    assert!(machine.context().halted);
    assert_eq!(machine.context().gpr[reg::RAX], 0x9999_8888_7777_6666);
    machine.context_mut().reset_tlb_stats();
    let (mut cpu, mut mem) = machine.into_parts();
    read_ok(&mut cpu, &mut mem, sibling_va);
    assert_eq!(cpu.context().tlb_stats().hits, 1);
}

fn push_msr_write(buf: &mut Vec<u8>, msr: MsrIndex, val: u64) {
    buf.push(0xB9);
    buf.extend_from_slice(&msr.raw().to_le_bytes());
    buf.push(0xB8);
    buf.extend_from_slice(&(val as u32).to_le_bytes());
    buf.push(0xBA);
    buf.extend_from_slice(&((val >> 32) as u32).to_le_bytes());
    buf.extend_from_slice(&[0x0F, 0x30]);
}

fn push_mov_rax_imm64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&[0x48, 0xB8]);
    buf.extend_from_slice(&val.to_le_bytes());
}

fn win_region(va: u64, len: u64, write: bool, exec: bool, user: bool) -> WindowRegion {
    WindowRegion {
        va,
        gpa: va,
        len,
        read: true,
        write,
        exec,
        user,
        shared: false,
    }
}

fn expect_port(m: &mut SoftMachine<Cpl0TestMemory>, expected: u32) {
    match m.run(64).unwrap() {
        SoftMachineExit::IoOut {
            port: CONTROL_PORT,
            size: 4,
            value,
            ..
        } => assert_eq!(value, expected),
        other => panic!("unexpected exit {other:?}"),
    }
}

#[test]
fn cpl0_fixture_boot_sequence_on_softmachine_matches_kvm_state() {
    let layout = BringupLayout {
        trampoline_base: 0x004f_0000,
        gdt_base: 0x0050_0000,
        pml4_base: 0x0060_0000,
    };
    let boot = X8664GuestArch::bootstrap_sysregs();
    let (boot_code_va, boot_data_va, kern_stack_va, binding_va) =
        (0x4e_0000, 0x4e_1000, 0x4e_2000, 0x4e_3000);
    let (user_code_va, user_data_va, user_tls_va, user_stack_va) =
        (0x01_0000, 0x01_1000, 0x01_2000, 0x01_3000);

    let pml4_cap = carrick_x86::X86_PML4_CAPACITY;
    let mut regions = vec![
        win_region(user_code_va, 0x1000, false, true, true),
        win_region(user_data_va, 0x3000, true, false, true),
        win_region(boot_code_va, 0x1000, false, true, false),
        win_region(boot_data_va, 0x3000, true, false, false),
        win_region(layout.trampoline_base, 0x1000, false, true, false),
        win_region(layout.gdt_base, 0x1000, true, false, false),
        win_region(layout.pml4_base, pml4_cap, true, false, false),
    ];
    add_fault_windows(&mut regions, layout);
    let plan = WindowPlan {
        regions,
        ro_spans: Vec::new(),
    };
    let pml4_bytes = build_pml4(&plan, layout).unwrap();

    let mut mem = Cpl0TestMemory::new();
    mem.register_root(layout.pml4_base);
    mem.write_gpa(layout.pml4_base, &pml4_bytes);
    write_fault_tables_with(layout, |gpa, bytes| {
        mem.write_gpa(gpa, bytes);
        Ok(())
    })
    .unwrap();

    let idt_gpa = fault_slot_gpa(fault_idt_base(layout), 0).unwrap();
    let tss_gpa = fault_slot_gpa(fault_tss_base(layout), 0).unwrap();
    let mut gdt_img: Vec<u8> = boot.gdt.iter().flat_map(|e| e.to_le_bytes()).collect();
    gdt_img.extend_from_slice(&tss64(tss_gpa, 0x67, 0x9, false, true, 0));
    mem.write_gpa(layout.gdt_base, &gdt_img);
    write_dt_ptr(
        &mut mem,
        boot_data_va,
        (gdt_img.len() - 1) as u16,
        layout.gdt_base,
    );
    write_dt_ptr(&mut mem, boot_data_va + 16, 0x0fff, idt_gpa);

    let kstack_top = kern_stack_va + 0xf00;
    mem.write_gpa(binding_va, &kstack_top.to_le_bytes());
    mem.write_gpa(binding_va + 16, &binding_va.to_le_bytes());
    assert_eq!(std::mem::offset_of!(CpuBinding, kernel_stack), 0);
    assert_eq!(std::mem::offset_of!(CpuBinding, user_stack), 8);
    assert_eq!(std::mem::offset_of!(CpuBinding, self_address), 16);
    mem.write_gpa(user_tls_va, &0x0000_0000_cafe_1234u64.to_le_bytes());
    mem.write_gpa(user_data_va, &0x0000_0000_55aa_77ccu64.to_le_bytes());

    let cp = CONTROL_PORT as u8;
    let lstar = [
        0x0F, 0x01, 0xF8, 0x65, 0x48, 0x89, 0x24, 0x25, 0x08, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B,
        0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x48, 0x81, 0xEC, 0x80, 0x02, 0x00, 0x00, 0x48, 0x83,
        0xE4, 0xC0, 0x51, 0x41, 0x53, 0x56, 0x48, 0x8D, 0x5C, 0x24, 0x18, 0xB8, 0x07, 0x00, 0x00,
        0x00, 0x31, 0xD2, 0x48, 0x0F, 0xAE, 0x23, 0x0F, 0x01, 0xCB, 0x8B, 0x07, 0x0F, 0x01, 0xCA,
        0xE7, cp, 0xB8, 0x07, 0x00, 0x00, 0x00, 0x31, 0xD2, 0x48, 0x0F, 0xAE, 0x2B, 0x5E, 0x41,
        0x5B, 0x59, 0x48, 0x85, 0xF6, 0x75, 0x0F, 0x65, 0x48, 0x8B, 0x24, 0x25, 0x08, 0x00, 0x00,
        0x00, 0x0F, 0x01, 0xF8, 0x48, 0x0F, 0x07, 0x6A, 0x1B, 0x65, 0xFF, 0x34, 0x25, 0x08, 0x00,
        0x00, 0x00, 0x41, 0x53, 0x6A, 0x23, 0x51, 0x0F, 0x01, 0xF8, 0x48, 0xCF,
    ];
    let hlt_va = layout.trampoline_base + 0x200;
    mem.write_gpa(layout.trampoline_base, &lstar);
    mem.write_gpa(hlt_va, &[0xF4]);

    let fault_va = 0x0000_0000_dead_0000u64;
    let mut user_prog = vec![0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0xBF];
    user_prog.extend_from_slice(&user_data_va.to_le_bytes());
    let mid = [
        0x03, 0x07, 0x89, 0x47, 0x08, 0x48, 0x83, 0xC7, 0x08, 0x31, 0xF6, 0x0F, 0x05, 0xBE, 0x01,
        0x00, 0x00, 0x00, 0x0F, 0x05, 0xB8, 0x42, 0x00, 0x00, 0x00, 0x48, 0xBA,
    ];
    user_prog.extend_from_slice(&mid);
    user_prog.extend_from_slice(&fault_va.to_le_bytes());
    let fault_insn_rip = user_code_va + user_prog.len() as u64;
    user_prog.extend_from_slice(&[0x48, 0x8B, 0x0A]);
    mem.write_gpa(user_code_va, &user_prog);

    let target_cr4 = boot.cr4 | (1 << 20) | (1 << 21);
    let mut cpl0_boot = vec![0xB8, 0x15, 0, 0, 0, 0x31, 0xC9, 0x0F, 0xA2];
    push_mov_rax_imm64(&mut cpl0_boot, boot_data_va + 0x100);
    cpl0_boot.extend_from_slice(&[0x89, 0x08]);
    for (op2, val) in [
        (0xD8u8, layout.pml4_base),
        (0xC0, boot.cr0),
        (0xE0, target_cr4),
    ] {
        push_mov_rax_imm64(&mut cpl0_boot, val);
        cpl0_boot.extend_from_slice(&[0x0F, 0x22, op2]);
    }
    push_mov_rax_imm64(&mut cpl0_boot, boot_data_va);
    cpl0_boot.extend_from_slice(&[
        0x0F, 0x01, 0x10, 0x0F, 0x01, 0x58, 0x10, 0xB8, 0x28, 0, 0, 0, 0x0F, 0x00, 0xD8,
    ]);
    for (msr, val) in [
        (MSR_IA32_EFER, boot.efer),
        (MSR_IA32_STAR, boot.star),
        (MSR_IA32_LSTAR, layout.trampoline_base),
        (MSR_IA32_FMASK, boot.sfmask),
        (MSR_IA32_FS_BASE, user_tls_va),
        (MSR_IA32_GS_BASE, 0),
        (MSR_IA32_KERNEL_GS_BASE, binding_va),
    ] {
        push_msr_write(&mut cpl0_boot, msr, val);
    }
    cpl0_boot.push(0xB9);
    cpl0_boot.extend_from_slice(&MSR_IA32_LSTAR.raw().to_le_bytes());
    cpl0_boot.extend_from_slice(&[0x0F, 0x32, 0x49, 0x89, 0xC7]);
    push_mov_rax_imm64(&mut cpl0_boot, user_code_va);
    cpl0_boot.extend_from_slice(&[0x0F, 0x01, 0x38, 0xB8, 0xB0, 0x07, 0, 0, 0xE7, cp]);

    let user_rsp_top = user_stack_va + 0xf00;
    cpl0_boot.extend_from_slice(&[0x6A, 0x1B]);
    push_mov_rax_imm64(&mut cpl0_boot, user_rsp_top);
    cpl0_boot.extend_from_slice(&[0x50, 0x68, 0x02, 0x02, 0x00, 0x00, 0x6A, 0x23]);
    push_mov_rax_imm64(&mut cpl0_boot, user_code_va);
    cpl0_boot.extend_from_slice(&[0x50, 0x31, 0xC0, 0x48, 0xCF]);
    mem.write_gpa(boot_code_va, &cpl0_boot);

    let mut machine =
        SoftMachine::new(mem, Box::new(Cpl0CpuidView::new(0, 2_000_000_000))).unwrap();
    {
        let ctx = machine.context_mut();
        enter_cpl0(ctx, boot_code_va);
        ctx.cr0 = 0x8000_0011;
        ctx.cr3 = layout.pml4_base;
        ctx.cr4 = 0x20;
        ctx.tr = SoftSegment::unusable();
        ctx.gpr[reg::RSP] = kstack_top;
    }

    expect_port(&mut machine, 0x07b0);
    {
        let ctx = machine.context();
        assert_eq!(ctx.cpl, 0);
        assert_eq!(
            (ctx.cr0, ctx.cr3, ctx.cr4, ctx.efer),
            (boot.cr0, layout.pml4_base, target_cr4, boot.efer)
        );
        assert_eq!(
            (ctx.msrs.star, ctx.msrs.lstar, ctx.msrs.fmask),
            (boot.star, layout.trampoline_base, boot.sfmask)
        );
        assert_eq!(
            (ctx.fs_base, ctx.gs_base, ctx.kernel_gs_base),
            (user_tls_va, 0, binding_va)
        );
        assert_eq!(ctx.gpr[reg::R15], layout.trampoline_base);
        assert_eq!(ctx.gdtr, DescriptorTablePtr::new(55, layout.gdt_base));
        assert_eq!(ctx.idtr, DescriptorTablePtr::new(0x0fff, idt_gpa));
        assert_eq!(ctx.tr, SoftSegment::tss64_busy(0x28, tss_gpa, 0x67));
        assert_vmx_valid(ctx);
        let hz = u32::from_le_bytes(
            machine
                .mem()
                .read_gpa(boot_data_va + 0x100, 4)
                .try_into()
                .unwrap(),
        );
        assert_eq!(hz, 2_000_000_000);
    }

    let expected_sum = 0xcafe_1234u32.wrapping_add(0x55aa_77cc);
    expect_port(&mut machine, expected_sum);
    assert_eq!(
        (machine.context().cpl, machine.context().gs_base),
        (0, binding_va)
    );
    assert_vmx_valid(machine.context());
    expect_port(&mut machine, expected_sum);

    let mut doorbell_words = Vec::with_capacity(X86_FAULT_RECORD_U32_WORDS);
    while doorbell_words.len() < X86_FAULT_RECORD_U32_WORDS {
        match machine.run(64).unwrap() {
            SoftMachineExit::IoOut {
                port: FAULT_DOORBELL_PORT,
                size: 4,
                value,
                ..
            } => doorbell_words.push(value),
            other => panic!("expected FAULT_DOORBELL_PORT word, got {other:?}"),
        }
    }
    let rec = FaultDoorbellRecord::from_u32_words(&doorbell_words).unwrap();
    assert_eq!(
        (rec.vector, rec.error_code, rec.rip, rec.cs),
        (14, u64::from(PF_ERR_USER), fault_insn_rip, 0x23)
    );
    assert_eq!(
        (rec.rsp, rec.saved_rax, rec.cr2),
        (user_rsp_top, 0x42, fault_va)
    );
    assert_eq!(
        (machine.context().cpl, machine.context().cr2),
        (0, fault_va)
    );
    assert_eq!(u64::from(PF_ERR_PRESENT | PF_ERR_WRITE), 3);
    assert_vmx_valid(machine.context());

    machine.context_mut().rip = hlt_va;
    assert_eq!(
        machine.run(8).unwrap(),
        SoftMachineExit::Hlt {
            rip: hlt_va,
            next_rip: hlt_va + 1
        }
    );
    assert!(machine.context().halted);
    assert_vmx_valid(machine.context());
}
