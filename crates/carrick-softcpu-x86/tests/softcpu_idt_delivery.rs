//! VM-free 64-bit IDT exception/interrupt delivery and CPL0 fixture fault-handling tests (`#669`).

#![cfg(target_arch = "x86_64")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};

use carrick_hal::guest_arch::GuestArch as _;
use carrick_hal::x8664_arch::X8664GuestArch;
use carrick_softcpu_x86::{
    Cpl0CpuidView, DescriptorTablePtr, ExtentRecord, ExtentTable, FrameGpa, InvalidInterruptVector,
    LinearPlacement, MSR_IA32_EFER, MSR_IA32_FMASK, MSR_IA32_KERNEL_GS_BASE, MSR_IA32_LSTAR,
    MSR_IA32_STAR, MmioHoles, MsrCapabilities, OwnerGeneration, PF_ERR_INSTR, PF_ERR_PRESENT,
    PF_ERR_USER, PF_ERR_WRITE, RootGpa, SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK,
    SOFT_TLB_PAGE_SIZE, SoftCpuContext, SoftMachine, SoftMachineExit, SoftMmuMemory, SoftSegment,
    X86ExceptionVector, reg,
};
use carrick_x86::{
    BringupLayout, FAULT_DOORBELL_PORT, FaultDoorbellRecord, GuestSegment, LongModeSegments,
    X86_FAULT_RECORD_U32_WORDS, check_vmx_guest_segments, fault_idt_base, fault_slot_gpa,
    fault_stack_base, fault_tss_base, write_fault_tables_with,
};

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_NX: u64 = 1 << 63;
const PTE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const NON_CANON: u64 = 0x0000_8000_0000_0000;

const CODE_VA: u64 = 0xffff_8000_0010_0000;
const HANDLER_BASE_VA: u64 = 0xffff_8000_0014_0000;
const USER_CODE_VA: u64 = 0x0000_0000_0040_0000;
const USER_DATA_VA: u64 = 0x0000_0000_0050_0000;
const USER_STACK_VA: u64 = 0x0000_0000_0060_0000;
const DATA_VA: u64 = 0xffff_8000_0020_0000;
const STACK_VA: u64 = 0xffff_8000_0030_0000;
const RSP0_VA: u64 = 0xffff_8000_0032_0000;
const IST1_VA: u64 = 0xffff_8000_0034_0000;
const IST2_VA: u64 = 0xffff_8000_0036_0000;
const GDT_VA: u64 = 0xffff_8000_0040_0000;
const IDT_VA: u64 = 0xffff_8000_0041_0000;
const TSS_VA: u64 = 0xffff_8000_0042_0000;

const RFLAGS_TF: u64 = 1 << 8;
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_RF: u64 = 1 << 16;
const RFLAGS_AC: u64 = 1 << 18;
const CR0_AM: u64 = 1 << 18;
const CR4_SMAP: u64 = 1 << 21;

#[derive(Clone, Copy)]
struct Perms(u8);
impl Perms {
    const fn new(r: bool, w: bool, x: bool, u: bool) -> Self {
        Self((r as u8) | ((w as u8) << 1) | ((x as u8) << 2) | ((u as u8) << 3))
    }
    const USER_RW: Self = Self::new(true, true, false, true);
    const USER_RO: Self = Self::new(true, false, false, true);
    const USER_RX: Self = Self::new(true, false, true, true);
    const KERNEL_RW: Self = Self::new(true, true, false, false);
    const KERNEL_RX: Self = Self::new(true, false, true, false);
}

struct IdtTestRig {
    machine: SoftMachine<TestMemory>,
    gdt_frame: FrameGpa,
    idt_frame: FrameGpa,
    tss_frame: FrameGpa,
    data_frame: FrameGpa,
    rsp0_frame: FrameGpa,
    ist1_frame: FrameGpa,
    ist2_frame: FrameGpa,
}

struct TestMemory {
    _backing: Vec<AtomicU64>,
    placement: LinearPlacement,
    extents: ExtentTable,
    next_gpa: u64,
}

impl TestMemory {
    const POOL_BYTES: u64 = 32 * 1024 * 1024;
    const GEN: OwnerGeneration = OwnerGeneration::FIRST;
    const ROOT_GPA: u64 = 0;

    fn new() -> Self {
        let words = ((Self::POOL_BYTES + SOFT_TLB_PAGE_SIZE) as usize) / 8;
        let mut backing = Vec::with_capacity(words);
        backing.resize_with(words, || AtomicU64::new(0));
        let aligned = (backing.as_ptr() as usize + (SOFT_TLB_OFFSET_MASK as usize))
            & !(SOFT_TLB_OFFSET_MASK as usize);
        // SAFETY: `backing` owns `POOL_BYTES` initialized bytes starting at `aligned`.
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

    fn ensure_child(&mut self, table_gpa: u64, idx: usize) -> u64 {
        let slot = table_gpa + (idx as u64) * 8;
        let cur = self.word_ref(slot).load(Ordering::Relaxed);
        if (cur & PTE_PRESENT) != 0 {
            return cur & PTE_ADDR_MASK;
        }
        let child = self.alloc_frame().raw();
        self.word_ref(slot).store(
            child | PTE_PRESENT | PTE_WRITABLE | PTE_USER,
            Ordering::Relaxed,
        );
        child
    }

    fn map_frame(&mut self, va: u64, frame: FrameGpa, p: Perms) {
        let va_page = va & SOFT_TLB_PAGE_MASK;
        let mut tbl = Self::ROOT_GPA;
        for shift in [39, 30, 21] {
            tbl = self.ensure_child(tbl, ((va_page >> shift) & 0x1ff) as usize);
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
        self.map_frame(va, f, p);
        f
    }

    fn unmap_page(&mut self, va: u64) {
        let va_page = va & SOFT_TLB_PAGE_MASK;
        let mut tbl = Self::ROOT_GPA;
        for shift in [39, 30, 21] {
            tbl = self.ensure_child(tbl, ((va_page >> shift) & 0x1ff) as usize);
        }
        self.word_ref(tbl + ((va_page >> 12) & 0x1ff) * 8)
            .store(0, Ordering::Relaxed);
    }
}

// SAFETY: `TestMemory` pairs `placement` with its single private `extents` domain.
unsafe impl SoftMmuMemory for TestMemory {
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

fn encode_idt_gate(handler_va: u64, cs_sel: u16, ist: u8, gate_type: u8, dpl: u8, p: bool) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0..2].copy_from_slice(&(handler_va as u16).to_le_bytes());
    g[2..4].copy_from_slice(&cs_sel.to_le_bytes());
    g[4] = ist & 0x7;
    g[5] = (gate_type & 0x1f) | ((dpl & 3) << 5) | if p { 0x80 } else { 0 };
    g[6..8].copy_from_slice(&((handler_va >> 16) as u16).to_le_bytes());
    g[8..12].copy_from_slice(&((handler_va >> 32) as u32).to_le_bytes());
    g
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
        efer: ctx.efer(),
        rflags: ctx.rflags,
    };
    assert_eq!(check_vmx_guest_segments(&segs, false), Ok(()));
}

impl IdtTestRig {
    fn new() -> Self {
        let mut mem = TestMemory::new();
        let _code = mem.map_page(CODE_VA, Perms::KERNEL_RX);
        let _handlers = mem.map_page(HANDLER_BASE_VA, Perms::KERNEL_RX);
        let _user_code = mem.map_page(USER_CODE_VA, Perms::USER_RX);
        let _user_data = mem.map_page(USER_DATA_VA, Perms::USER_RW);
        let _user_stack = mem.map_page(USER_STACK_VA, Perms::USER_RW);
        let data_frame = mem.map_page(DATA_VA, Perms::KERNEL_RW);
        let _stack = mem.map_page(STACK_VA, Perms::KERNEL_RW);
        let rsp0_frame = mem.map_page(RSP0_VA, Perms::KERNEL_RW);
        let ist1_frame = mem.map_page(IST1_VA, Perms::KERNEL_RW);
        let ist2_frame = mem.map_page(IST2_VA, Perms::KERNEL_RW);
        let gdt_frame = mem.map_page(GDT_VA, Perms::KERNEL_RW);
        let idt_frame = mem.map_page(IDT_VA, Perms::KERNEL_RW);
        let tss_frame = mem.map_page(TSS_VA, Perms::KERNEL_RW);

        // Give `rsp0_frame` its own extent so physical-retirement test 4d can retire it cleanly.
        let pool = mem
            .extents_mut()
            .remove(FrameGpa::new(0), None)
            .unwrap()
            .unwrap();
        let completion = pool.pending.try_complete().unwrap();
        mem.extents_mut().reclaim(&completion);
        for (base, len) in [
            (0, rsp0_frame.raw()),
            (rsp0_frame.raw(), SOFT_TLB_PAGE_SIZE),
            (
                rsp0_frame.raw() + SOFT_TLB_PAGE_SIZE,
                TestMemory::POOL_BYTES - rsp0_frame.raw() - SOFT_TLB_PAGE_SIZE,
            ),
        ] {
            assert!(mem.extents_mut().install(ExtentRecord::new(
                FrameGpa::new(base),
                len,
                TestMemory::GEN,
            )));
        }

        // GDT layout:
        // 0x00: null
        // 0x08: kernel code64 (DPL=0, L=1)
        // 0x10: kernel data   (DPL=0)
        // 0x18: ring1 code64  (DPL=1, L=1)
        // 0x20: user data     (DPL=3)
        // 0x28: user code64   (DPL=3, L=1)
        // 0x30..0x40: TSS64 busy at TSS_VA
        let gdt_words: [u64; 6] = [
            0,
            0x00af_9b00_0000_ffff,
            0x00cf_9300_0000_ffff,
            0x00af_bb00_0000_ffff,
            0x00cf_f300_0000_ffff,
            0x00af_fb00_0000_ffff,
        ];
        for (i, w) in gdt_words.iter().enumerate() {
            mem.write_gpa(gdt_frame.raw() + (i as u64) * 8, &w.to_le_bytes());
        }
        let tss_low = 0x67u64
            | ((TSS_VA & 0xffff) << 16)
            | (((TSS_VA >> 16) & 0xff) << 32)
            | (0x8bu64 << 40)
            | (((TSS_VA >> 24) & 0xff) << 56);
        let tss_high = TSS_VA >> 32;
        mem.write_gpa(gdt_frame.raw() + 0x30, &tss_low.to_le_bytes());
        mem.write_gpa(gdt_frame.raw() + 0x38, &tss_high.to_le_bytes());

        // TSS64: RSP0 at +4 (deliberately +0xff8 so 16-byte alignment down to +0xff0 is tested),
        // IST1 at +36, IST2 at +44.
        mem.write_gpa(tss_frame.raw() + 4, &(RSP0_VA + 0xff8).to_le_bytes());
        mem.write_gpa(tss_frame.raw() + 36, &(IST1_VA + 0xff0).to_le_bytes());
        mem.write_gpa(tss_frame.raw() + 44, &(IST2_VA + 0xff0).to_le_bytes());

        let mut machine = SoftMachine::new(mem, Box::new(Cpl0CpuidView::default())).unwrap();
        {
            let ctx = machine.context_mut();
            ctx.gdtr = DescriptorTablePtr::new(0x3f, GDT_VA);
            ctx.idtr = DescriptorTablePtr::new(0xfff, IDT_VA);
            ctx.tr = SoftSegment::tss64_busy(0x30, TSS_VA, 0x67);
            ctx.set_cpl(0);
            ctx.cs = SoftSegment::kernel_code64(0x08);
            ctx.ss = SoftSegment::kernel_data(0x10);
            ctx.gpr[reg::RSP] = STACK_VA + 0xff0;
        }

        let mut rig = Self {
            machine,
            gdt_frame,
            idt_frame,
            tss_frame,
            data_frame,
            rsp0_frame,
            ist1_frame,
            ist2_frame,
        };
        // Default: every vector 0..256 writes its vector to port 0xe0 and halts:
        // mov al, <vec>; out 0xe0, al; hlt (5 bytes per stub inside HANDLER_BASE_VA).
        for vec in 0..=255u8 {
            let stub_va = HANDLER_BASE_VA + u64::from(vec) * 16;
            let stub_gpa = rig.translate_kernel_page_gpa(HANDLER_BASE_VA) + u64::from(vec) * 16;
            rig.machine
                .mem_mut()
                .write_gpa(stub_gpa, &[0xb0, vec, 0xe6, 0xe0, 0xf4]);
            rig.set_gate(vec, stub_va, 0x08, 0, 0x0e, 0, true);
        }
        rig
    }

    fn translate_kernel_page_gpa(&self, page_va: u64) -> u64 {
        let mut tbl = TestMemory::ROOT_GPA;
        for shift in [39, 30, 21] {
            let slot = tbl + (((page_va >> shift) & 0x1ff) * 8);
            tbl = self.machine.mem().read_u64(slot) & PTE_ADDR_MASK;
        }
        let leaf = self
            .machine
            .mem()
            .read_u64(tbl + (((page_va >> 12) & 0x1ff) * 8));
        leaf & PTE_ADDR_MASK
    }

    fn set_gate(&mut self, vec: u8, handler_va: u64, cs: u16, ist: u8, typ: u8, dpl: u8, p: bool) {
        let gate = encode_idt_gate(handler_va, cs, ist, typ, dpl, p);
        self.machine
            .mem_mut()
            .write_gpa(self.idt_frame.raw() + u64::from(vec) * 16, &gate);
    }

    fn write_user_code(&mut self, bytes: &[u8]) {
        let gpa = self.translate_kernel_page_gpa(USER_CODE_VA);
        self.machine.mem_mut().write_gpa(gpa, bytes);
        self.machine.context_mut().flush_tlb();
    }

    fn write_kernel_code(&mut self, bytes: &[u8]) {
        let gpa = self.translate_kernel_page_gpa(CODE_VA);
        self.machine.mem_mut().write_gpa(gpa, bytes);
        self.machine.context_mut().flush_tlb();
    }

    fn write_handler(&mut self, vec: u8, bytes: &[u8]) -> u64 {
        let stub_va = HANDLER_BASE_VA + u64::from(vec) * 16;
        assert!(bytes.len() <= 16);
        let stub_gpa = self.translate_kernel_page_gpa(HANDLER_BASE_VA) + u64::from(vec) * 16;
        self.machine.mem_mut().write_gpa(stub_gpa, bytes);
        self.machine.context_mut().flush_tlb();
        stub_va
    }

    fn enter_cpl3(&mut self, rip: u64, rflags: u64) {
        let ctx = self.machine.context_mut();
        ctx.set_cpl(3);
        ctx.cs = SoftSegment::user_code64(0x2b);
        ctx.ss = SoftSegment::user_data(0x23);
        ctx.gpr[reg::RSP] = USER_STACK_VA + 0xff0;
        ctx.rflags = rflags | 0x2;
        ctx.halted = false;
        ctx.rip = rip;
    }

    fn enter_cpl0(&mut self, rip: u64, rflags: u64) {
        let ctx = self.machine.context_mut();
        ctx.set_cpl(0);
        ctx.cs = SoftSegment::kernel_code64(0x08);
        ctx.ss = SoftSegment::kernel_data(0x10);
        ctx.gpr[reg::RSP] = STACK_VA + 0xff0;
        ctx.rflags = rflags | 0x2;
        ctx.halted = false;
        ctx.rip = rip;
    }

    fn run_to_vec_port(&mut self) -> u8 {
        match self.machine.run(64).unwrap() {
            SoftMachineExit::IoOut {
                port: 0xe0,
                size: 1,
                value,
                ..
            } => value as u8,
            other => panic!("expected vector port 0xe0 exit, got {other:?}"),
        }
    }
}

#[test]
fn idt_vectors_de_db_ud_gp_pf_ac_match_sdm_frames_error_codes_cr2_and_stack_switch() {
    let mut rig = IdtTestRig::new();

    // 1. #DE (vector 0): CPL3 `xor edx, edx; xor ecx, ecx; mov eax, 1; div ecx` -> 40-byte frame on aligned RSP0.
    // 31 d2 31 c9 b8 01 00 00 00 f7 f1 (div ecx is at +9, 2 bytes).
    rig.write_user_code(&[0x31, 0xd2, 0x31, 0xc9, 0xb8, 1, 0, 0, 0, 0xf7, 0xf1]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 0);
    {
        let ctx = rig.machine.context();
        assert_eq!(ctx.cpl, 0);
        // TSS.RSP0 was RSP0_VA + 0xff8 -> aligned down to +0xff0, minus 40 bytes = +0xfc8.
        assert_eq!(ctx.gpr[reg::RSP], RSP0_VA + 0xfc8);
        assert!(ctx.ss.is_unusable());
        assert_eq!(ctx.ss.selector, 0);
        assert_vmx_valid(ctx);
    }
    let rsp0_gpa = rig.rsp0_frame.raw();
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc8), USER_CODE_VA + 9); // RIP = faulting DIV
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfd0), 0x2b); // CS
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfd8) & RFLAGS_IF, RFLAGS_IF);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfe0), USER_STACK_VA + 0xff0);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfe8), 0x23); // SS

    // 2a. #DB (vector 1) single-step TF=1: sets DR6.BS (bit 14), clears DR7.GD (bit 13), clears TF in handler.
    rig.write_user_code(&[0x90, 0x90]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_TF);
    rig.machine.context_mut().dr[6] = 0xffff_0ff3; // pre-existing B0|B1 should be cleared
    rig.machine.context_mut().dr[7] = 0x0000_2400; // GD bit set
    assert_eq!(rig.run_to_vec_port(), 1);
    assert_eq!(rig.machine.context().dr[6], 0xffff_0ff0 | (1 << 14));
    assert_eq!(rig.machine.context().dr[7] & (1 << 13), 0);
    assert_eq!(rig.machine.context().rflags & RFLAGS_TF, 0);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc8), USER_CODE_VA + 1);
    assert_ne!(rig.machine.mem().read_u64(rsp0_gpa + 0xfd8) & RFLAGS_TF, 0);

    // 2b. POPFQ clearing TF (1 -> 0) must NOT fire a trailing single-step #DB!
    // User stack has new RFLAGS = 0x202 (TF=0); code: `popfq (9d); mov eax, 0x77 (b8 77 00 00 00); ud2 (0f 0b)`
    let user_stack_gpa = rig.translate_kernel_page_gpa(USER_STACK_VA);
    rig.machine
        .mem_mut()
        .write_gpa(user_stack_gpa + 0xff0, &0x202u64.to_le_bytes());
    rig.write_user_code(&[0x9d, 0xb8, 0x77, 0, 0, 0, 0x0f, 0x0b]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_TF);
    // Must hit #UD (6) at +6 with EAX=0x77, NEVER #DB (1)!
    assert_eq!(rig.run_to_vec_port(), 6);
    assert_eq!(rig.machine.context().gpr[reg::RAX], 0x77);

    // 2c. POPFQ setting TF (0 -> 1) delays #DB until AFTER the NEXT instruction retires!
    rig.machine
        .mem_mut()
        .write_gpa(user_stack_gpa + 0xff0, &(0x202u64 | RFLAGS_TF).to_le_bytes());
    // `popfq (9d); mov eax, 0x42 (b8 42 00 00 00); mov ebx, 0x99 (bb 99 00 00 00)`
    rig.write_user_code(&[0x9d, 0xb8, 0x42, 0, 0, 0, 0xbb, 0x99, 0, 0, 0]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 1);
    assert_eq!(rig.machine.context().gpr[reg::RAX], 0x42);
    assert_eq!(rig.machine.context().gpr[reg::RBX], 0);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc8), USER_CODE_VA + 6);

    // 2d. REP MOVSB with TF=1 traps after a single iteration (`RCX` decrements 3 -> 2).
    let user_data_gpa = rig.translate_kernel_page_gpa(USER_DATA_VA);
    rig.machine
        .mem_mut()
        .write_gpa(user_data_gpa, &[0xaa, 0xbb, 0xcc]);
    rig.write_user_code(&[0xf3, 0xa4, 0x90]); // rep movsb; nop
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_TF);
    rig.machine.context_mut().gpr[reg::RSI] = USER_DATA_VA;
    rig.machine.context_mut().gpr[reg::RDI] = USER_DATA_VA + 0x100;
    rig.machine.context_mut().gpr[reg::RCX] = 3;
    assert_eq!(rig.run_to_vec_port(), 1);
    assert_eq!(rig.machine.context().gpr[reg::RCX], 2);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc8), USER_CODE_VA);

    // 2e. DR0 hardware execution breakpoint + IRETQ with RFLAGS.RF=1 resuming past DR0 once!
    // Handler 1 sets RF (bit 16) in `[rsp + 16]` and executes `iretq`:
    // `or qword ptr [rsp + 16], 0x10000` (48 81 4c 24 10 00 00 01 00); `inc r12` (49 ff c4); `iretq` (48 cf) = 14 bytes!
    rig.write_handler(
        1,
        &[
            0x48, 0x81, 0x4c, 0x24, 0x10, 0x00, 0x00, 0x01, 0x00, 0x49, 0xff, 0xc4, 0x48, 0xcf,
        ],
    );
    // User code: `mov eax, 0x55` (b8 55 00 00 00, at +0); `ud2` (0f 0b, at +5).
    rig.write_user_code(&[0xb8, 0x55, 0, 0, 0, 0x0f, 0x0b]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = 0;
    rig.machine.context_mut().gpr[reg::R12] = 0;
    rig.machine.context_mut().dr[0] = USER_CODE_VA;
    rig.machine.context_mut().dr[6] = 0xffff_0ff0;
    rig.machine.context_mut().dr[7] = 0x0000_0401; // L0=1, R/W0=00 (execute), LEN0=00
    assert_eq!(rig.run_to_vec_port(), 6);
    assert_eq!(
        rig.machine.context().gpr[reg::R12],
        1,
        "DR0 fired once, then RF=1 suppressed re-fire on resume"
    );
    assert_eq!(rig.machine.context().gpr[reg::RAX], 0x55);
    assert_eq!(rig.machine.context().dr[6] & 0xf, 1);
    assert_eq!(rig.machine.context().rflags & RFLAGS_RF, 0, "RF cleared after 1 retired insn");
    rig.machine.context_mut().dr[7] = 0x0000_0400;
    rig.write_handler(1, &[0xb0, 1, 0xe6, 0xe0, 0xf4]);

    // 2f. ICEBP / INT1 (`0xf1`) at CPL3 bypasses DPL=0 on gate 1 and uses EXT=0 on gate faults.
    rig.write_user_code(&[0xf1, 0x90]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 1);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc8), USER_CODE_VA + 1);
    // Mark gate 1 not-present: ICEBP must raise #NP (11) with EXT=0 -> (1 << 3) | 2 = 0x0a and fault_va = USER_CODE_VA.
    rig.set_gate(1, HANDLER_BASE_VA + 16, 0x08, 0, 0x0e, 0, false);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 11);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc0), 0x0a); // EXT=0!
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc8), USER_CODE_VA);
    rig.set_gate(1, HANDLER_BASE_VA + 16, 0x08, 0, 0x0e, 0, true);

    // 3. #GP (vector 13): privileged CLI at CPL3 (error_code = 0), INT 0x80 at DPL=0 (IDT=1, EXT=0),
    // and exception gate referencing out-of-limit CS=0x48 (EXT=1 -> 0x49).
    rig.write_user_code(&[0xfa]); // cli
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc0), 0);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc8), USER_CODE_VA);

    rig.write_user_code(&[0xcd, 0x80]); // int 0x80 (gate 0x80 has DPL=0)
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc0), (0x80 << 3) | 0x2);

    rig.set_gate(6, HANDLER_BASE_VA + 6 * 16, 0x48, 0, 0x0e, 0, true);
    rig.write_user_code(&[0x0f, 0x0b]); // ud2 -> benign #UD -> CS selector 0x48 out of GDT limit -> #GP(0x49)
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc0), 0x48 | 1);
    rig.set_gate(6, HANDLER_BASE_VA + 6 * 16, 0x08, 0, 0x0e, 0, true);

    // 4a. #PF (vector 14): write to read-only user page & execute on NX user page.
    let ro_va = 0x0000_0000_0070_0000;
    rig.machine.mem_mut().map_page(ro_va, Perms::USER_RO);
    // `mov byte ptr [rax], 1` (c6 00 01)
    rig.write_user_code(&[0xc6, 0x00, 0x01]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = ro_va + 0x34;
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, ro_va + 0x34);
    assert_eq!(
        rig.machine.mem().read_u64(rsp0_gpa + 0xfc0) as u32,
        PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER
    );

    rig.enter_cpl3(USER_DATA_VA + 0x10, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, USER_DATA_VA + 0x10);
    assert_eq!(
        rig.machine.mem().read_u64(rsp0_gpa + 0xfc0) as u32,
        PF_ERR_PRESENT | PF_ERR_USER | PF_ERR_INSTR
    );

    // 4b. #PF during CPL0 STAC with CR4.SMAP=1 MUST clear RFLAGS.AC on IDT entry while saving AC=1 on stack!
    rig.machine.context_mut().cr4 |= CR4_SMAP;
    rig.machine.context_mut().sync_tlb_tag_bits();
    // `stac (0f 01 cb); mov rax, [rdi] (48 8b 07)` at CODE_VA, with RDI = unmapped user VA 0x7_0000.
    rig.write_kernel_code(&[0x0f, 0x01, 0xcb, 0x48, 0x8b, 0x07]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RDI] = 0x7_0000;
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, 0x7_0000);
    assert_eq!(
        rig.machine.context().rflags & RFLAGS_AC,
        0,
        "IDT gate entry must clear RFLAGS.AC so CPL0 handler runs with SMAP protection engaged"
    );
    let stack_gpa = rig.translate_kernel_page_gpa(STACK_VA);
    // Same-privilege CPL0 stack: STACK_VA + 0xff0 - 48 = +0xfc0; saved RFLAGS is at +0xfd8.
    assert_ne!(
        rig.machine.mem().read_u64(stack_gpa + 0xfd8) & RFLAGS_AC,
        0,
        "pushed RFLAGS on stack must preserve caller AC=1 for IRETQ"
    );
    rig.machine.context_mut().cr4 &= !CR4_SMAP;
    rig.machine.context_mut().sync_tlb_tag_bits();

    // 4c. Same-privilege CPL3 -> CPL3 trap gate (`target_cs = 0x2b`, `DPL = 3`) on a supervisor-only stack
    // must push with `Cpl::Ring3` and fault with `PF_ERR_USER | PF_ERR_WRITE | PF_ERR_PRESENT`!
    rig.set_gate(0x81, USER_CODE_VA + 0x100, 0x2b, 0, 0x0f, 3, true);
    rig.write_user_code(&[0xcd, 0x81]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RSP] = DATA_VA + 0x800; // supervisor-only page!
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(
        rig.machine.mem().read_u64(rsp0_gpa + 0xfc0) as u32,
        PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER
    );

    // 4d. Physical-retirement witness (`softmmu.x86.physical-retirement`):
    // Warm RSP0_VA in SoftTlb, retire/remap RSP0_VA to a fresh frame while parked (without manual flush_tlb!),
    // then trigger CPL3 #UD -> IDT frame push must land in the new frame and never the retired frame!
    rig.write_user_code(&[0x0f, 0x0b]); // ud2 at USER_CODE_VA
    rig.write_kernel_code(&[0x48, 0xc7, 0x07, 0x11, 0, 0, 0, 0xf4]); // mov qword ptr [rdi], 0x11; hlt
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RDI] = RSP0_VA + 0xfc8;
    assert!(matches!(
        rig.machine.run(8).unwrap(),
        SoftMachineExit::Hlt { .. }
    ));
    let new_rsp0_frame = rig.machine.mem_mut().alloc_frame();
    rig.machine
        .mem_mut()
        .map_frame(RSP0_VA, new_rsp0_frame, Perms::KERNEL_RW);
    let retirement = rig
        .machine
        .mem_mut()
        .extents_mut()
        .remove(rig.rsp0_frame, None)
        .unwrap()
        .unwrap();
    let completion = retirement.pending.try_complete().unwrap();
    rig.machine.mem_mut().extents_mut().reclaim(&completion);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 6);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc8), 0x11);
    assert_eq!(
        rig.machine.mem().read_u64(new_rsp0_frame.raw() + 0xfc8),
        USER_CODE_VA
    );
    rig.rsp0_frame = new_rsp0_frame;
    let rsp0_gpa = rig.rsp0_frame.raw();

    // 5. #AC (vector 17): CPL3 + CR0.AM=1 + RFLAGS.AC=1 unaligned GPR load -> #AC(0);
    // unmapped page -> #PF takes priority; CPL0 -> no #AC; 16-byte legacy MOVUPS/MOVDQU -> NO #AC!
    rig.machine.context_mut().cr0 |= CR0_AM;
    // `mov rax, [rdi]` (48 8b 07)
    rig.write_user_code(&[0x48, 0x8b, 0x07]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_AC);
    rig.machine.context_mut().gpr[reg::RDI] = USER_DATA_VA + 3;
    assert_eq!(rig.run_to_vec_port(), 17);
    assert_eq!(rig.machine.mem().read_u64(rsp0_gpa + 0xfc0), 0);

    // Unmapped unaligned VA -> #PF (14) wins over #AC (17)!
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_AC);
    rig.machine.context_mut().gpr[reg::RDI] = 0x7_0003;
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, 0x7_0003);

    // CPL0 with CR0.AM=1 + RFLAGS.AC=1 -> NO #AC!
    rig.write_kernel_code(&[0x48, 0x8b, 0x07, 0xf4]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF | RFLAGS_AC);
    rig.machine.context_mut().gpr[reg::RDI] = DATA_VA + 3;
    assert!(matches!(
        rig.machine.run(8).unwrap(),
        SoftMachineExit::Hlt { .. }
    ));

    // Legacy 128-bit unaligned SIMD (`movups xmm0, [rdi + 1]`; `movdqu [rdi + 19], xmm0`; `ud2`) at CPL3
    // with CR0.AM=1 + RFLAGS.AC=1 must NOT raise #AC (must reach #UD 6)!
    rig.write_user_code(&[
        0x0f, 0x10, 0x47, 0x01, // movups xmm0, [rdi + 1]
        0xf3, 0x0f, 0x7f, 0x47, 0x13, // movdqu [rdi + 19], xmm0
        0x0f, 0x0b, // ud2
    ]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_AC);
    rig.machine.context_mut().gpr[reg::RDI] = USER_DATA_VA;
    assert_eq!(rig.run_to_vec_port(), 6);
}

#[test]
fn idt_double_fault_escalation_ist_and_triple_fault_match_sdm_table_6_5() {
    let mut rig = IdtTestRig::new();
    // Route #DF (vector 8) through IST1.
    rig.set_gate(8, HANDLER_BASE_VA + 8 * 16, 0x08, 1, 0x0e, 0, true);

    // 1. Contributory (#DE, 0) + Contributory (#NP on gate 0) -> escalates to #DF(0) on IST1!
    rig.set_gate(0, HANDLER_BASE_VA, 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0x31, 0xd2, 0x31, 0xc9, 0xf7, 0xf1]); // div ecx
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 8);
    assert_eq!(rig.machine.context().gpr[reg::RSP], IST1_VA + 0xff0 - 48);
    assert_eq!(rig.machine.mem().read_u64(rig.ist1_frame.raw() + 0xfc0), 0);
    rig.set_gate(0, HANDLER_BASE_VA, 0x08, 0, 0x0e, 0, true);

    // 2. PageFault (#PF, 14) + Contributory (#NP on gate 14) -> escalates to #DF(0), preserving CR2!
    rig.set_gate(14, HANDLER_BASE_VA + 14 * 16, 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0x48, 0x8b, 0x07]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RDI] = 0x9_9000;
    assert_eq!(rig.run_to_vec_port(), 8);
    assert_eq!(rig.machine.context().cr2, 0x9_9000);
    rig.set_gate(14, HANDLER_BASE_VA + 14 * 16, 0x08, 0, 0x0e, 0, true);

    // 3. PageFault (#PF, 14) + PageFault (unmapped RSP0) -> escalates to #DF(0) on IST1!
    rig.machine.mem_mut().unmap_page(RSP0_VA);
    rig.machine.context_mut().flush_tlb();
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RDI] = 0x9_a000;
    assert_eq!(rig.run_to_vec_port(), 8);
    assert_eq!(rig.machine.context().cr2, RSP0_VA + 0xfc0);

    // 4. Contributory (#GP, 13) + PageFault (unmapped RSP0) -> delivered SERIALLY to #PF (on IST2), NOT #DF!
    rig.set_gate(14, HANDLER_BASE_VA + 14 * 16, 0x08, 2, 0x0e, 0, true);
    rig.write_user_code(&[0xfa]); // cli -> #GP
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().gpr[reg::RSP], IST2_VA + 0xff0 - 48);
    rig.machine
        .mem_mut()
        .map_frame(RSP0_VA, rig.rsp0_frame, Perms::KERNEL_RW);
    rig.set_gate(14, HANDLER_BASE_VA + 14 * 16, 0x08, 0, 0x0e, 0, true);

    // 5. Benign (#UD, 6) + Contributory (#NP on gate 6) -> delivered SERIALLY to #NP (11), NOT #DF!
    rig.set_gate(6, HANDLER_BASE_VA + 6 * 16, 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0x0f, 0x0b]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 11);
    rig.set_gate(6, HANDLER_BASE_VA + 6 * 16, 0x08, 0, 0x0e, 0, true);

    // 6. ExternalInterrupt (0x40) + Contributory (#NP on gate 0x40) -> delivered SERIALLY to #NP(0x203), NOT #DF!
    rig.set_gate(0x40, HANDLER_BASE_VA + 0x40 * 16, 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0x90]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.inject_interrupt(0x40).unwrap();
    assert_eq!(rig.run_to_vec_port(), 11);
    assert_eq!(
        rig.machine.mem().read_u64(rig.rsp0_frame.raw() + 0xfc0),
        (0x40 << 3) | 0x2 | 1
    );

    // 7. Same-privilege CPL0 -> CPL0 via IST2 AND CPL3 -> Ring1 (`CS = 0x18`) via IST2:
    // Both MUST load NULL SS with `selector = new_cpl` and `SS.DPL = new_cpl` (`check_vmx_guest_segments` passes)!
    rig.set_gate(6, HANDLER_BASE_VA + 6 * 16, 0x08, 2, 0x0e, 0, true);
    rig.write_kernel_code(&[0x0f, 0x0b]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 6);
    assert_eq!(rig.machine.context().gpr[reg::RSP], IST2_VA + 0xff0 - 40);
    assert!(rig.machine.context().ss.is_unusable());
    assert_eq!(rig.machine.context().ss.selector, 0);
    assert_vmx_valid(rig.machine.context());
    // Saved SS on IST2 stack was old CPL0 SS (0x10):
    assert_eq!(rig.machine.mem().read_u64(rig.ist2_frame.raw() + 0xfe8), 0x10);

    // Inter-privilege CPL3 -> Ring1 (`CS = 0x19` / `0x18`, DPL = 1): NULL SS must have selector=1, DPL=1!
    rig.set_gate(6, HANDLER_BASE_VA + 6 * 16, 0x18, 2, 0x0e, 0, true);
    rig.write_user_code(&[0x0f, 0x0b]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    // At Ring 1, `out` raises #GP(0), so put `nop` at handler 6 and step once to inspect Ring 1 segment state!
    rig.write_handler(6, &[0x90]);
    assert_eq!(rig.machine.step().unwrap(), None); // executes UD2 and delivers gate 6 -> Ring 1!
    assert_eq!(rig.machine.context().cpl, 1);
    assert_eq!(rig.machine.context().ss.selector, 1);
    assert_eq!(rig.machine.context().ss.dpl(), 1);
    assert_vmx_valid(rig.machine.context());
    rig.write_handler(6, &[0xb0, 6, 0xe6, 0xe0, 0xf4]);
    rig.set_gate(6, HANDLER_BASE_VA + 6 * 16, 0x08, 0, 0x0e, 0, true);

    // 8. #DF + secondary fault (non-canonical IST1 in TSS) -> TripleFault!
    rig.machine
        .mem_mut()
        .write_gpa(rig.tss_frame.raw() + 36, &NON_CANON.to_le_bytes());
    rig.set_gate(0, HANDLER_BASE_VA, 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0x31, 0xd2, 0x31, 0xc9, 0xf7, 0xf1]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    match rig.machine.run(8).unwrap() {
        SoftMachineExit::TripleFault { last_exception } => {
            assert_eq!(last_exception.vector, X86ExceptionVector::StackSegmentFault);
            assert_eq!(last_exception.error_code, Some(1));
        }
        other => panic!("expected TripleFault, got {other:?}"),
    }
}

#[test]
fn external_interrupt_delivery_enforces_if_cr8_priority_sti_shadow_trap_vs_intr_gate_and_hlt_wake() {
    let mut rig = IdtTestRig::new();

    // 1. Vectors 0..31 are architectural exceptions and must be rejected.
    for bad in [0u8, 1, 14, 31] {
        assert_eq!(
            rig.machine.inject_interrupt(bad),
            Err(InvalidInterruptVector(bad))
        );
    }

    // 2. Simultaneous pending interrupts deliver highest vector first: 0xe1 > 0x80 > 0x30.
    // Handlers 0xe1, 0x80, 0x30 record their vector into `[DATA_VA + r13]` and `inc r13; iretq`:
    for vec in [0x30u8, 0x80, 0xe1] {
        // mov byte ptr [r14 + r13], <vec> (43 c6 04 2e <vec>); inc r13 (49 ff c5); iretq (48 cf) = 11 bytes!
        rig.write_handler(
            vec,
            &[0x43, 0xc6, 0x04, 0x2e, vec, 0x49, 0xff, 0xc5, 0x48, 0xcf],
        );
    }
    rig.write_user_code(&[0x90, 0x0f, 0x0b]); // nop; ud2
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::R14] = DATA_VA;
    rig.machine.context_mut().gpr[reg::R13] = 0;
    // Allow CPL0 handler access to DATA_VA (supervisor RW, already mapped).
    rig.machine.inject_interrupt(0x30).unwrap();
    rig.machine.inject_interrupt(0xe1).unwrap();
    rig.machine.inject_interrupt(0x80).unwrap();
    assert!(rig.machine.is_interrupt_pending(0x30));
    assert!(rig.machine.is_interrupt_pending(0x80));
    assert!(rig.machine.is_interrupt_pending(0xe1));
    assert_eq!(rig.machine.deliverable_interrupt(), Some(0xe1));
    assert_eq!(rig.run_to_vec_port(), 6); // runs all 3 IRQs in priority order, then NOP, then UD2!
    assert_eq!(
        rig.machine.mem().read_gpa(rig.data_frame.raw(), 3),
        vec![0xe1, 0x80, 0x30]
    );

    // 3. CR8 (TPR) masking: CR8 = 8 masks 0x80 (class 8 <= 8) and 0x30 (class 3 <= 8), admits 0x90 (class 9 > 8).
    rig.write_handler(
        0x90,
        &[0x43, 0xc6, 0x04, 0x2e, 0x90, 0x49, 0xff, 0xc5, 0x48, 0xcf],
    );
    // CPL0 code: `nop (90); mov eax, 2 (b8 02 00 00 00); mov cr8, rax (44 0f 22 c0); nop (90); hlt (f4)`
    rig.write_kernel_code(&[0x90, 0xb8, 2, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0, 0x90, 0xf4]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().cr8 = 8;
    rig.machine.context_mut().gpr[reg::R14] = DATA_VA + 0x10;
    rig.machine.context_mut().gpr[reg::R13] = 0;
    rig.machine.inject_interrupt(0x30).unwrap();
    rig.machine.inject_interrupt(0x80).unwrap();
    rig.machine.inject_interrupt(0x90).unwrap();
    // Step 1 delivers 0x90 immediately before `nop`!
    assert_eq!(rig.machine.step().unwrap(), None);
    assert_eq!(rig.machine.context().rip, HANDLER_BASE_VA + 0x90 * 16);
    assert!(rig.machine.is_interrupt_pending(0x80));
    assert!(rig.machine.is_interrupt_pending(0x30));
    assert_eq!(rig.machine.deliverable_interrupt(), None);
    // Run to HLT: `mov cr8, 2` unmasks 0x80 then 0x30!
    assert!(matches!(
        rig.machine.run(32).unwrap(),
        SoftMachineExit::Hlt { .. }
    ));
    assert_eq!(
        rig.machine.mem().read_gpa(rig.data_frame.raw() + 0x10, 3),
        vec![0x90, 0x80, 0x30]
    );
    rig.machine.context_mut().cr8 = 0;

    // 4. STI 1-instruction interrupt shadow:
    // 4a. `sti (fb); cli (fa); hlt (f4)` with IF=0 and pending 0x30 -> STI shadows 1 insn (`cli`),
    // `cli` clears IF=0 before IRQ can fire, and `hlt` stays halted with 0x30 still pending!
    rig.write_kernel_code(&[0xfb, 0xfa, 0xf4, 0xb8, 0x99, 0, 0, 0]);
    rig.enter_cpl0(CODE_VA, 0); // IF=0
    rig.machine.context_mut().gpr[reg::RAX] = 0;
    rig.machine.context_mut().gpr[reg::R13] = 0;
    rig.machine.inject_interrupt(0x30).unwrap();
    assert!(matches!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt { .. }
    ));
    assert!(
        rig.machine.is_interrupt_pending(0x30),
        "STI; CLI must keep pending interrupt masked across the 1-instruction STI shadow"
    );
    // Stepping a halted CPU with IF=0 MUST remain halted and NEVER execute `mov eax, 0x99` past HLT!
    assert!(matches!(
        rig.machine.step().unwrap(),
        Some(SoftMachineExit::Hlt { .. })
    ));
    assert_eq!(rig.machine.context().gpr[reg::RAX], 0);
    // Clear pending 0x30 by enabling IF and letting it deliver:
    rig.enter_cpl0(CODE_VA + 2, RFLAGS_IF); // `hlt` with IF=1 wakes immediately on pending 0x30!
    rig.machine.context_mut().gpr[reg::R14] = DATA_VA + 0x20;
    assert_eq!(rig.machine.step().unwrap(), None);
    assert!(!rig.machine.is_interrupt_pending(0x30));

    // 4b. `sti (fb); add eax, 1 (83 c0 01); add eax, 10 (83 c0 0a); hlt (f4)` with IF=0:
    // Pending 0x50 (handler outputs 0x50 to port 0xe0) must fire AFTER `add eax, 1` (`RAX == 1`), NOT before!
    rig.write_kernel_code(&[0xfb, 0x83, 0xc0, 0x01, 0x83, 0xc0, 0x0a, 0xf4]);
    rig.enter_cpl0(CODE_VA, 0);
    rig.machine.context_mut().gpr[reg::RAX] = 0;
    rig.machine.inject_interrupt(0x50).unwrap();
    assert_eq!(rig.run_to_vec_port(), 0x50);
    assert_eq!(
        rig.machine.context().gpr[reg::RAX],
        1,
        "STI shadow must retire exactly one instruction before delivering IRQ"
    );

    // 4c. `sti` when IF is ALREADY 1 creates NO shadow: pending 0x50 after `sti` delivers before `add eax, 1`!
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = 0;
    assert_eq!(rig.machine.step().unwrap(), None); // executes `sti` (IF was already 1 -> no shadow!)
    rig.machine.inject_interrupt(0x50).unwrap();
    assert_eq!(rig.run_to_vec_port(), 0x50);
    assert_eq!(rig.machine.context().gpr[reg::RAX], 0);

    // 4d. `sti (fb); hlt (f4); mov eax, 0x77 (b8 77 00 00 00); cli (fa); hlt (f4)` with IF=0 and ALREADY-pending 0x30
    // (`park_until_interrupt` pattern): `hlt` clears the STI shadow and wakes atomically without spurious halt!
    rig.write_kernel_code(&[0xfb, 0xf4, 0xb8, 0x77, 0, 0, 0, 0xfa, 0xf4]);
    rig.enter_cpl0(CODE_VA, 0);
    rig.machine.context_mut().gpr[reg::RAX] = 0;
    rig.machine.context_mut().gpr[reg::R14] = DATA_VA + 0x30;
    rig.machine.context_mut().gpr[reg::R13] = 0;
    rig.machine.inject_interrupt(0x30).unwrap();
    assert!(matches!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt { .. }
    ));
    assert_eq!(rig.machine.context().gpr[reg::RAX], 0x77);
    assert_eq!(rig.machine.context().gpr[reg::R13], 1);

    // 5. Trap Gate (`0x0f`) vs Interrupt Gate (`0x0e`):
    // Gate 0x60 = Trap Gate (`0x0f`, keeps IF=1); Gate 0x61 = Interrupt Gate (`0x0e`, clears IF=0).
    rig.set_gate(0x60, HANDLER_BASE_VA + 0x60 * 16, 0x08, 0, 0x0f, 0, true);
    rig.write_handler(0x60, &[0x90, 0x48, 0xcf]); // nop; iretq
    rig.write_kernel_code(&[0x90, 0xf4]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.inject_interrupt(0x60).unwrap();
    assert_eq!(rig.machine.step().unwrap(), None); // enters trap gate 0x60 with IF still 1!
    assert_ne!(rig.machine.context().rflags & RFLAGS_IF, 0);
    // Injecting 0x50 while inside Trap Gate 0x60 preempts 0x60 immediately!
    rig.machine.inject_interrupt(0x50).unwrap();
    assert_eq!(rig.run_to_vec_port(), 0x50);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn cpl0_fixture_image_fault_handling_and_native_irqs_match_kvm() {
    use std::num::NonZeroU64;
    use std::sync::atomic::{AtomicU32, Ordering};

    use carrick_core::terminal::ThreadBirthIdentity;
    use carrick_core_abi::{BirthSerial, EntryTaskKey, EntryThreadGeneration, X86_CPL0_RESERVATIONS_OFFSET, X86_CPL0_ZONE_OFFSET};
    use carrick_el1::memory::reservations::{X86Cpl0Reservations, X86Cpl0Zone};
    use carrick_el1_abi::{
        BlockedMask, Counters, CurrentTask, EL1_BOOTSTRAP_METADATA_SIZE,
        EL1_FRAME_GRANT_RESIDENCY_OFFSET, EL1_MM_PORTAL_OFFSET, EL1_REGION_SIZE,
        EL1_SIGNAL_INGRESS_OFFSET, El1TaskId, FileRegionBinding, FileRegionId,
        FrameGrantResidencyTable, MmPortalSlots, SharedSignalIngressQueue, SnapshotGeneration,
        ThreadControlSlot, ThreadLifecyclePage, X86_CPL0_BOOTSTRAP_METADATA_BASE,
        X86_CPL0_DIRECT_VA, X86_CPL0_DYNAMIC_METADATA_BASE, X86_CPL0_KERNEL_STACK_TOP_RESERVE,
        X86_CPL0_REGION_BASE, X86_CPL0_SUPERVISOR_IMAGE_BASE, X86_CPL0_SUPERVISOR_IMAGE_GPA,
        X86_CPL0_SUPERVISOR_IMAGE_SIZE, x86_cpl0_kernel_stack_end_gpa, x86_cpl0_kernel_stack_guards,
    };
    use carrick_guest_arch::{GuestLen, KernelVa};
    use carrick_mem::pml4::{Pml4MapSpec, pml4_tables, punch_holes};
    use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
    use carrick_mmu_core::x86::copy_window::{COW_COPY_TABLE_PAGES, provision_cow_copy_window};
    use carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords;
    use carrick_sched_core::process::TaskSerial;
    use carrick_x86::cpl0_entry::{
        CONTROL_PORT, CpuBinding, DIRECT_VA, FATAL_PORT, NativeFrame, OBSERVE_NATIVE,
        OBSERVE_SHARED_COW_FAULT, OBSERVE_SHARED_PREPARED_FAULT, PublishedApicIds, ShootdownTable,
    };
    use carrick_x86::interrupts::{
        IRQ_HEADER_GPA, IRQ_HEADER_MAGIC, KICK_VECTOR, LAPIC_BASE, LAPIC_VA, PAGE_FAULT_VECTOR,
        RESCHED_VECTOR, SHOOTDOWN_VECTOR, TIMER_VECTOR, interrupt_gate,
    };
    use goblin::elf::{Elf, program_header::PT_LOAD};

    // Verify both embedded CPL0 images built cleanly from current workspace sources.
    let prod_bytes = std::fs::read(env!("CARRICK_X86_CPL0_IMAGE")).unwrap();
    let prod_elf = Elf::parse(&prod_bytes).unwrap();
    assert!(prod_elf.entry >= X86_CPL0_SUPERVISOR_IMAGE_BASE);

    let fixture_bytes = std::fs::read(env!("CARRICK_X86_CPL0_FIXTURE_IMAGE")).unwrap();
    let fixture_elf = Elf::parse(&fixture_bytes).unwrap();

    const META_GPA: u64 = 0xc0_0000;
    const META_LEN: u64 = 0x10_0000;
    const ALLOCATOR_GPA: u64 = 0x200_0000;
    const KERNEL_REGION_GPA: u64 = 0x1_0000_0000;
    const PLACEMENT_SIZE: u64 = KERNEL_REGION_GPA + EL1_REGION_SIZE;
    const GDT_BASE: u64 = 0x50_0000;
    const PML4_BASE: u64 = 0x60_0000;
    const IST_STACK_BASE: u64 = 0xf0_0000;
    const USER_CODE: u64 = 0x1_0000;
    const COUNTERS_OFFSET: u64 = 0x1_0000;
    const BINDING_OFFSET: u64 = 0x8000;
    const TASK_OFFSET: u64 = 0x9000;
    const CONTROL_OFFSET: u64 = 0xa000;
    const ROUTES_OFFSET: u64 = 0xd000;
    const SHOOTDOWN_OFFSET: u64 = 0xe000;

    const LAYOUT: BringupLayout = BringupLayout {
        trampoline_base: X86_CPL0_SUPERVISOR_IMAGE_GPA,
        gdt_base: GDT_BASE,
        pml4_base: PML4_BASE,
    };

    struct FixtureArena {
        ptr: *mut u8,
        len: usize,
        placement: LinearPlacement,
        extents: ExtentTable,
    }

    impl Drop for FixtureArena {
        fn drop(&mut self) {
            // SAFETY: `self.ptr` and `self.len` came from `libc::mmap` in `FixtureArena::new`.
            unsafe {
                let _ = libc::munmap(self.ptr.cast(), self.len);
            }
        }
    }

    impl FixtureArena {
        fn new() -> Self {
            let len = PLACEMENT_SIZE as usize;
            // SAFETY: anonymous private MAP_NORESERVE reservation backs only touched pages.
            let raw = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                    -1,
                    0,
                )
            };
            assert_ne!(raw, libc::MAP_FAILED, "fixture mmap reservation");
            let ptr = raw.cast::<u8>();
            // SAFETY: `[ptr, ptr + PLACEMENT_SIZE)` is page-aligned and owned until `Drop`.
            let placement =
                unsafe { LinearPlacement::new(ptr as usize, PLACEMENT_SIZE, MmioHoles::empty()) }
                    .unwrap();
            let mut extents = ExtentTable::new().unwrap();
            let g = OwnerGeneration::FIRST;
            assert!(extents.install(ExtentRecord::new(FrameGpa::new(0), 0x200_0000, g)));
            assert!(extents.install(ExtentRecord::new(
                FrameGpa::new(ALLOCATOR_GPA),
                EL1_BOOTSTRAP_METADATA_SIZE,
                g
            )));
            assert!(extents.install(ExtentRecord::new(FrameGpa::new(LAPIC_BASE), 4096, g)));
            assert!(extents.install(ExtentRecord::new(
                FrameGpa::new(KERNEL_REGION_GPA),
                EL1_REGION_SIZE,
                g
            )));
            extents.set_root_generation(
                RootGpa::page_aligned(FrameGpa::new(PML4_BASE)).unwrap(),
                g,
            );
            Self {
                ptr,
                len,
                placement,
                extents,
            }
        }

        fn host_ptr(&self, gpa: u64, size: usize) -> *mut u8 {
            assert!((gpa as usize).checked_add(size).unwrap() <= self.len);
            // SAFETY: bounds checked within `[0, self.len)`.
            unsafe { self.ptr.add(gpa as usize) }
        }

        fn write_gpa(&mut self, gpa: u64, src: &[u8]) {
            let dst = self.host_ptr(gpa, src.len());
            // SAFETY: non-overlapping slice -> arena copy within bounds.
            unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) };
        }

        fn read_gpa(&self, gpa: u64, len: usize) -> Vec<u8> {
            let src = self.host_ptr(gpa, len) as *const u8;
            let mut out = vec![0u8; len];
            // SAFETY: non-overlapping arena -> Vec copy within bounds.
            unsafe { std::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), len) };
            out
        }

        fn read_u64(&self, gpa: u64) -> u64 {
            u64::from_le_bytes(self.read_gpa(gpa, 8).try_into().unwrap())
        }

        fn read_u32(&self, gpa: u64) -> u32 {
            u32::from_le_bytes(self.read_gpa(gpa, 4).try_into().unwrap())
        }
    }

    // SAFETY: `FixtureArena` pairs `placement` with its single private `extents` domain.
    unsafe impl SoftMmuMemory for FixtureArena {
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

    struct ArenaWords<'a>(&'a FixtureArena);
    impl LiveDescriptorWords for ArenaWords<'_> {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            if (pa & 7) != 0 || pa + 8 > PLACEMENT_SIZE {
                return Err(DescriptorRefusal::WrongBacking);
            }
            // SAFETY: 8-byte aligned within `FixtureArena`.
            let atom = unsafe { &*(self.0.host_ptr(pa, 8) as *const AtomicU64) };
            Ok(atom.load(Ordering::Acquire))
        }
        fn compare_exchange(
            &self,
            pa: u64,
            current: u64,
            new: u64,
        ) -> Result<bool, DescriptorRefusal> {
            if (pa & 7) != 0 || pa + 8 > PLACEMENT_SIZE {
                return Err(DescriptorRefusal::WrongBacking);
            }
            // SAFETY: 8-byte aligned within `FixtureArena`.
            let atom = unsafe { &*(self.0.host_ptr(pa, 8) as *const AtomicU64) };
            Ok(atom
                .compare_exchange(current, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok())
        }
        fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
            if (pa & 7) != 0 || pa + 8 > PLACEMENT_SIZE {
                return Err(DescriptorRefusal::WrongBacking);
            }
            // SAFETY: 8-byte aligned within `FixtureArena`.
            let atom = unsafe { &*(self.0.host_ptr(pa, 8) as *const AtomicU64) };
            atom.store(value, Ordering::Release);
            Ok(())
        }
        fn publish_barrier(&self) {
            std::sync::atomic::fence(Ordering::SeqCst);
        }
        fn invalidate_range(&self, _va: u64, _len: u64) {}
    }

    let boot_fixture = |program: &[u8], hardware_interrupts: bool, smap: bool| -> SoftMachine<FixtureArena> {
        let mut ram = FixtureArena::new();
        let mut maps = Vec::new();
        for ph in fixture_elf.program_headers.iter().filter(|ph| ph.p_type == PT_LOAD && ph.p_memsz > 0) {
            let va_start = ph.p_vaddr;
            let file_off = ph.p_offset as usize;
            let filesz = ph.p_filesz as usize;
            let gpa_off = X86_CPL0_SUPERVISOR_IMAGE_GPA + (va_start - X86_CPL0_SUPERVISOR_IMAGE_BASE);
            if filesz > 0 {
                ram.write_gpa(gpa_off, &fixture_bytes[file_off..file_off + filesz]);
            }
            let va = va_start & !0xfff;
            let end = va_start + ph.p_memsz;
            maps.push(Pml4MapSpec {
                va,
                gpa: X86_CPL0_SUPERVISOR_IMAGE_GPA + (va - X86_CPL0_SUPERVISOR_IMAGE_BASE),
                len: ((end + 0xfff) & !0xfff) - va,
                user: false,
                write: (ph.p_flags & 0x2) != 0,
                exec: (ph.p_flags & 0x1) != 0,
            });
        }

        let stub_start = carrick_x86::fault_stub_base(LAYOUT);
        let stub_end = fault_tss_base(LAYOUT);
        for (start, end, write, exec) in [
            (
                X86_CPL0_SUPERVISOR_IMAGE_GPA + X86_CPL0_SUPERVISOR_IMAGE_SIZE,
                stub_start,
                true,
                false,
            ),
            (stub_start, stub_end, false, true),
            (stub_end, META_GPA, true, false),
        ] {
            maps.push(Pml4MapSpec {
                va: DIRECT_VA + start,
                gpa: start,
                len: end - start,
                user: false,
                write,
                exec,
            });
        }
        maps.push(Pml4MapSpec {
            va: DIRECT_VA + META_GPA,
            gpa: META_GPA,
            len: if hardware_interrupts { 0x140_0000 } else { 0x40_0000 },
            user: false,
            write: true,
            exec: false,
        });
        maps.push(Pml4MapSpec {
            va: X86_CPL0_DYNAMIC_METADATA_BASE,
            gpa: META_GPA,
            len: META_LEN,
            user: false,
            write: true,
            exec: false,
        });
        maps.push(Pml4MapSpec {
            va: X86_CPL0_BOOTSTRAP_METADATA_BASE,
            gpa: ALLOCATOR_GPA,
            len: EL1_BOOTSTRAP_METADATA_SIZE,
            user: false,
            write: true,
            exec: false,
        });
        maps.push(Pml4MapSpec {
            va: X86_CPL0_REGION_BASE,
            gpa: KERNEL_REGION_GPA,
            len: EL1_REGION_SIZE,
            user: false,
            write: true,
            exec: false,
        });
        ram.write_gpa(USER_CODE, program);
        maps.push(Pml4MapSpec {
            va: USER_CODE,
            gpa: USER_CODE,
            len: 4096,
            user: true,
            write: false,
            exec: true,
        });
        maps.push(Pml4MapSpec {
            va: 0x3_0000,
            gpa: 0x3_0000,
            len: 8192,
            user: true,
            write: true,
            exec: false,
        });
        if hardware_interrupts {
            maps.push(Pml4MapSpec {
                va: carrick_x86::cpl0_lifecycle::LIFECYCLE_ZONE,
                gpa: 0x100_0000,
                len: 0x100_0000,
                user: false,
                write: true,
                exec: false,
            });
            maps.push(Pml4MapSpec {
                va: LAPIC_VA,
                gpa: LAPIC_BASE,
                len: 4096,
                user: false,
                write: true,
                exec: false,
            });
        }

        let table_capacity =
            (carrick_x86::X86_PML4_CAPACITY as usize) - COW_COPY_TABLE_PAGES * 4096;
        let guards: Vec<(u64, u64)> = x86_cpl0_kernel_stack_guards().collect();
        let tables =
            pml4_tables(&punch_holes(&maps, &guards), PML4_BASE, table_capacity).unwrap();
        ram.write_gpa(PML4_BASE, &tables);

        let boot = X8664GuestArch::bootstrap_sysregs();
        let gdt: Vec<u8> = boot.gdt.iter().flat_map(|w| w.to_le_bytes()).collect();
        ram.write_gpa(GDT_BASE, &gdt);
        write_fault_tables_with(LAYOUT, |gpa, bytes| {
            ram.write_gpa(gpa, bytes);
            Ok(())
        })
        .unwrap();

        let tss = fault_slot_gpa(fault_tss_base(LAYOUT), 0).unwrap();
        let fault_stack = fault_slot_gpa(fault_stack_base(LAYOUT), 0).unwrap();
        ram.write_gpa(tss + 4, &(DIRECT_VA + fault_stack + 4096).to_le_bytes());
        ram.write_gpa(tss + 36, &(DIRECT_VA + IST_STACK_BASE + 4096).to_le_bytes());
        let idt = fault_slot_gpa(fault_idt_base(LAYOUT), 0).unwrap();
        ram.write_gpa(idt + 8 * 16 + 4, &[1]); // #DF uses IST1
        for vector in 0..256_u64 {
            let gate_gpa = idt + vector * 16;
            let gate = ram.read_gpa(gate_gpa, 16);
            if gate[5] & 0x80 == 0 {
                continue;
            }
            let low = u16::from_le_bytes([gate[0], gate[1]]) as u64;
            let mid = u16::from_le_bytes([gate[6], gate[7]]) as u64;
            let high = u32::from_le_bytes([gate[8], gate[9], gate[10], gate[11]]) as u64;
            let entry = DIRECT_VA + low + (mid << 16) + (high << 32);
            ram.write_gpa(gate_gpa, &(entry as u16).to_le_bytes());
            ram.write_gpa(gate_gpa + 6, &((entry >> 16) as u16).to_le_bytes());
            ram.write_gpa(gate_gpa + 8, &((entry >> 32) as u32).to_le_bytes());
        }

        if hardware_interrupts {
            let header = ram.read_gpa(IRQ_HEADER_GPA, 48);
            let mut words = [0_u64; 6];
            for (word, bytes) in words.iter_mut().zip(header.chunks_exact(8)) {
                *word = u64::from_le_bytes(bytes.try_into().unwrap());
            }
            assert_eq!(words[0], IRQ_HEADER_MAGIC);
            for (vector, entry) in [
                TIMER_VECTOR,
                KICK_VECTOR,
                RESCHED_VECTOR,
                SHOOTDOWN_VECTOR,
                PAGE_FAULT_VECTOR,
            ]
            .into_iter()
            .zip(words[1..].iter().copied())
            {
                ram.write_gpa(idt + u64::from(vector) * 16, &interrupt_gate(entry));
            }
        }

        let file_binding = FileRegionBinding::new(
            FileRegionId::from_carrier(NonZeroU64::MIN),
            KernelVa::new(X86_CPL0_REGION_BASE),
            FrameGpa::new(KERNEL_REGION_GPA),
            GuestLen::new(EL1_REGION_SIZE),
        )
        .unwrap();

        // SAFETY: exclusive zeroed `FixtureArena` before SoftMachine runs.
        unsafe {
            let page = ram
                .host_ptr(META_GPA, size_of::<ThreadLifecyclePage>())
                .cast::<ThreadLifecyclePage>();
            page.write(ThreadLifecyclePage::new());
            ram.host_ptr(META_GPA + COUNTERS_OFFSET, size_of::<Counters>())
                .cast::<Counters>()
                .write(Counters::new());
            ram.host_ptr(META_GPA + ROUTES_OFFSET, size_of::<PublishedApicIds>())
                .cast::<PublishedApicIds>()
                .write(PublishedApicIds::new());
            let shootdown = ram
                .host_ptr(META_GPA + SHOOTDOWN_OFFSET, size_of::<ShootdownTable>())
                .cast::<ShootdownTable>();
            shootdown.write(ShootdownTable::new());

            let slot = ram
                .host_ptr(META_GPA + CONTROL_OFFSET, size_of::<ThreadControlSlot>())
                .cast::<ThreadControlSlot>();
            slot.write(ThreadControlSlot::new());
            (*slot).reset_for_host_birth(BlockedMask(0)).unwrap();
            assert!((*slot).publish_visible_tid(41));
            let birth = ThreadBirthIdentity::from_parts(
                EntryTaskKey::from_raw(41),
                BirthSerial::of_task(TaskSerial::from_raw_u64(11).unwrap()),
                EntryThreadGeneration::from_raw(101),
            )
            .unwrap();
            (*slot).publish_host_birth_identity(birth);

            let task = ram
                .host_ptr(META_GPA + TASK_OFFSET, size_of::<CurrentTask>())
                .cast::<CurrentTask>();
            task.write(CurrentTask::new());
            (*task).set(El1TaskId::from_linux_tid(41), SnapshotGeneration::from_raw(11), 5);
            (*task).mm.thread_generation.store(101, Ordering::Release);
            (*task).mm.key.store(201, Ordering::Release);
            (*shootdown).members[0].publish(PML4_BASE, 201, 1);
            (*task).publish_lifecycle(
                X86_CPL0_DYNAMIC_METADATA_BASE,
                X86_CPL0_DYNAMIC_METADATA_BASE + CONTROL_OFFSET,
            );

            ram.host_ptr(META_GPA + BINDING_OFFSET, size_of::<CpuBinding>())
                .cast::<CpuBinding>()
                .write(CpuBinding {
                    kernel_stack: DIRECT_VA + x86_cpl0_kernel_stack_end_gpa(0)
                        - X86_CPL0_KERNEL_STACK_TOP_RESERVE,
                    user_stack: 0,
                    self_address: X86_CPL0_DYNAMIC_METADATA_BASE + BINDING_OFFSET,
                    task_address: X86_CPL0_DYNAMIC_METADATA_BASE + TASK_OFFSET,
                    counters_address: X86_CPL0_DYNAMIC_METADATA_BASE + COUNTERS_OFFSET,
                    entry_kick: AtomicU32::new(0),
                    return_kick: AtomicU32::new(0),
                    entries: AtomicU64::new(0),
                    publications: AtomicU64::new(0),
                    completions: AtomicU64::new(0),
                    captured_stack: AtomicU64::new(0),
                    scheduler_witness: AtomicU64::new(0),
                    cpu_slot: 0,
                    tsc_hz: AtomicU64::new(0),
                    wake_routes_address: X86_CPL0_DYNAMIC_METADATA_BASE + ROUTES_OFFSET,
                    apic_timer_hz: AtomicU64::new(0),
                    pending_irqs: AtomicU32::new(0),
                    shootdown_table_address: X86_CPL0_DYNAMIC_METADATA_BASE + SHOOTDOWN_OFFSET,
                    fault_active: AtomicU64::new(0),
                    fault_frame: AtomicU64::new(0),
                    fault_address: AtomicU64::new(0),
                    fault_reason: AtomicU64::new(0),
                    mm_owner_generation: AtomicU64::new(1),
                    last_seen_generation: AtomicU64::new(0),
                    stdio_table_admitted: AtomicU64::new(0),
                    file_region: file_binding,
                });

            // `X86Cpl0Reservations` and `X86Cpl0Zone` are zero-valid ABI records in `FixtureArena`.
            let _ = ram
                .host_ptr(
                    META_GPA + X86_CPL0_RESERVATIONS_OFFSET,
                    size_of::<X86Cpl0Reservations>(),
                )
                .cast::<X86Cpl0Reservations>();
            let _ = ram
                .host_ptr(META_GPA + X86_CPL0_ZONE_OFFSET, size_of::<X86Cpl0Zone>())
                .cast::<X86Cpl0Zone>();

            if hardware_interrupts {
                let lifecycle_zone = &*(ram
                    .host_ptr(0x100_0000, size_of::<carrick_sched_core::ZoneTables>())
                    .cast::<carrick_sched_core::ZoneTables>());
                let space = lifecycle_zone
                    .spaces
                    .publish_closed(201, PML4_BASE, 0)
                    .unwrap();
                lifecycle_zone.spaces.open(space);
                let slot0 = carrick_sched_core::SlotId::new(0);
                lifecycle_zone.drive(slot0, 1);
                lifecycle_zone.publish_slot_with_affinity(
                    slot0,
                    201,
                    Some(0),
                    carrick_sched_core::AffinitySource::UNBOUND,
                );
                lifecycle_zone.enter_guest(slot0);
                lifecycle_zone.install_space(slot0, 201).unwrap();
            }

            FrameGrantResidencyTable::init_in_place(
                ram.host_ptr(
                    KERNEL_REGION_GPA + EL1_FRAME_GRANT_RESIDENCY_OFFSET,
                    size_of::<FrameGrantResidencyTable>(),
                )
                .cast::<FrameGrantResidencyTable>(),
            );
            SharedSignalIngressQueue::initialize_at(
                ram.host_ptr(
                    KERNEL_REGION_GPA + EL1_SIGNAL_INGRESS_OFFSET,
                    size_of::<SharedSignalIngressQueue>(),
                )
                .cast::<SharedSignalIngressQueue>(),
            );
            ram.host_ptr(
                KERNEL_REGION_GPA + EL1_MM_PORTAL_OFFSET,
                size_of::<MmPortalSlots>(),
            )
            .cast::<MmPortalSlots>()
            .write(MmPortalSlots::new());
        }

        let root = RootGpa::page_aligned(FrameGpa::new(PML4_BASE)).unwrap();
        let mut grants = [root; COW_COPY_TABLE_PAGES];
        for (i, g) in grants.iter_mut().enumerate() {
            let pa = PML4_BASE + (table_capacity as u64) + (i as u64) * 4096;
            *g = RootGpa::page_aligned(FrameGpa::new(pa)).unwrap();
        }
        provision_cow_copy_window(&ArenaWords(&ram), root, grants).unwrap();

        let mut machine = SoftMachine::new(ram, Box::new(Cpl0CpuidView::default())).unwrap();
        {
            let ctx = machine.context_mut();
            let caps = MsrCapabilities::default();
            ctx.cr0 = boot.cr0;
            ctx.cr3 = PML4_BASE;
            ctx.cr4 = boot.cr4 | (1 << 18) | (1 << 20) | if smap { CR4_SMAP } else { 0 };
            ctx.write_msr(MSR_IA32_EFER, boot.efer, caps).unwrap();
            ctx.write_msr(MSR_IA32_STAR, boot.star, caps).unwrap();
            ctx.write_msr(MSR_IA32_LSTAR, fixture_elf.entry, caps).unwrap();
            ctx.write_msr(
                MSR_IA32_FMASK,
                boot.sfmask | (1 << 10) | (1 << 8) | (1 << 18),
                caps,
            )
            .unwrap();
            ctx.write_msr(
                MSR_IA32_KERNEL_GS_BASE,
                X86_CPL0_DYNAMIC_METADATA_BASE + BINDING_OFFSET,
                caps,
            )
            .unwrap();
            ctx.gdtr = DescriptorTablePtr::new(
                (boot.gdt.len() * 8 - 1) as u16,
                X86_CPL0_DIRECT_VA + GDT_BASE,
            );
            ctx.idtr = DescriptorTablePtr::new(0xfff, X86_CPL0_DIRECT_VA + idt);
            ctx.tr = SoftSegment::tss64_busy(0x30, X86_CPL0_DIRECT_VA + tss, 0x67);
            ctx.set_cpl(3);
            ctx.cs = SoftSegment::user_code64(0x2b);
            ctx.ss = SoftSegment::user_data(0x23);
            ctx.rip = USER_CODE;
            ctx.gpr[reg::RSP] = 0x3_1ff0;
            ctx.rflags = boot.rflags | if hardware_interrupts { RFLAGS_IF } else { 0 };
            ctx.sync_tlb_tag_bits();
        }
        machine
    };

    let observe = |machine: &mut SoftMachine<FixtureArena>| -> i64 {
        match machine.run(200_000).unwrap() {
            SoftMachineExit::IoOut { port, .. } if port == CONTROL_PORT => {
                let frame_va = machine.context().gpr[reg::RAX];
                let frame_gpa = frame_va - DIRECT_VA;
                let raw = machine.mem().read_gpa(frame_gpa, size_of::<NativeFrame>());
                // SAFETY: `NativeFrame` is `#[repr(C)] Copy` and `raw` has exact size.
                let frame: NativeFrame =
                    unsafe { std::ptr::read_unaligned(raw.as_ptr().cast::<NativeFrame>()) };
                frame.rdi as i64
            }
            SoftMachineExit::IoOut { port, value, .. } if port == FATAL_PORT => {
                panic!("CPL0 fixture hit FATAL_PORT with value {value:#x}")
            }
            other => panic!("expected CONTROL_PORT observation, got {other:?}"),
        }
    };

    let read_fault_doorbell = |machine: &mut SoftMachine<FixtureArena>| -> FaultDoorbellRecord {
        let mut words = [0u32; X86_FAULT_RECORD_U32_WORDS];
        for word in &mut words {
            match machine.run(100_000).unwrap() {
                SoftMachineExit::IoOut {
                    port: FAULT_DOORBELL_PORT,
                    size: 4,
                    value,
                    ..
                } => *word = value,
                other => panic!("expected FAULT_DOORBELL_PORT outl, got {other:?}"),
            }
        }
        FaultDoorbellRecord::from_u32_words(&words).unwrap()
    };

    let read_user_leaf = |machine: &SoftMachine<FixtureArena>, va: u64| -> u64 {
        let mut tbl = PML4_BASE;
        for shift in [39, 30, 21] {
            tbl = machine.mem().read_u64(tbl + (((va >> shift) & 0x1ff) * 8)) & PTE_ADDR_MASK;
        }
        machine.mem().read_u64(tbl + (((va >> 12) & 0x1ff) * 8))
    };

    // --- Sub-case A: KVM `user_access_program(0)` across all 35 rounds with SMAP=false AND SMAP=true ---
    // Modes 6 & 7 bypass preflight and trigger live CPL0 STAC #PF -> `carrick_x86_page_fault_fixup`!
    let mapped = 0x3_1000_u64;
    let unmapped_edge = mapped + 0xff8;
    let calls: &[(u64, u64, i64)] = &[
        (mapped, 2, 0),
        (mapped, 0, 0x51ab_cdef_1234_5678),
        (mapped, 1, 0x51ab_cdef_1234_5678),
        (mapped, 8, 0x51ab_cdef_1234_5678),
        (mapped, 9, 0),
        (mapped, 0, 0x6ace_b00c_1234_5678),
        (mapped, 10, 0),
        (mapped, 14, 0),
        (mapped, 12, 0),
        (mapped, 13, 0),
        (mapped, 3, 0x1234_5678),
        (mapped, 4, 16),
        (mapped, 5, 16),
        (USER_CODE, 4, 16),
        (USER_CODE, 5, 0),
        (0xffff_ffff_8000_0000, 4, 0),
        (0xffff_ffff_8000_0000, 0, -14),
        (0xffff_ffff_8000_0000, 1, -14),
        (0xffff_ffff_8000_0000, 2, -14),
        (0x0000_7fff_ffff_fffc, 0, -14),
        (0x0000_7fff_ffff_fffc, 4, 0),
        (u64::MAX - 3, 1, -14),
        (u64::MAX - 3, 8, -14),
        (unmapped_edge, 4, 8),
        (unmapped_edge, 5, 8),
        (unmapped_edge + 4, 1, -14),
        (unmapped_edge + 4, 2, -14),
        (0x7_0000, 0, -14),
        (0x7_0000, 11, 0),
        (0x7_0000, 1, -14),
        (0x7_0000, 2, -14),
        (0x7_0000, 6, -14),
        (0x7_0000, 7, -14),
        (0x7_0000, 4, 0),
        (0x7_0000, 5, 0),
    ];
    let mut uaccess_prog = Vec::new();
    for &(address, mode, _) in calls {
        uaccess_prog.extend_from_slice(&[0x48, 0xbf]);
        uaccess_prog.extend_from_slice(&address.to_le_bytes());
        uaccess_prog.extend_from_slice(&[0x48, 0xbe]);
        uaccess_prog.extend_from_slice(&mode.to_le_bytes());
        uaccess_prog.extend_from_slice(&[0x48, 0xb8]);
        uaccess_prog.extend_from_slice(&0xffff_ffff_ffff_ff10_u64.to_le_bytes());
        uaccess_prog.extend_from_slice(&[0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48, 0xb8]);
        uaccess_prog.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
        uaccess_prog.extend_from_slice(&[0x0f, 0x05]);
    }
    uaccess_prog.extend_from_slice(&[0x0f, 0x0b]);

    for smap in [false, true] {
        let mut machine = boot_fixture(&uaccess_prog, false, smap);
        for (round, &(_, mode, expected)) in calls.iter().enumerate() {
            assert_eq!(
                observe(&mut machine),
                expected,
                "user_access_program smap={smap} round={round} mode={mode}"
            );
        }
    }

    // --- Sub-case B: In-guest prepared page fault & COW fault (`OBSERVE_SHARED_PREPARED_FAULT` & `OBSERVE_SHARED_COW_FAULT`) ---
    for (syscall_no, fault_va, expected_gpa, check_cow_cleared) in [
        (OBSERVE_SHARED_PREPARED_FAULT, 0x3_3000_u64, 0x9_1000_u64, false),
        (OBSERVE_SHARED_COW_FAULT, 0x3_4000_u64, 0xd1_5000_u64, true),
    ] {
        let mut prog = vec![0x48, 0xb8];
        prog.extend_from_slice(&syscall_no.to_le_bytes());
        prog.extend_from_slice(&[0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48, 0xb8]);
        prog.extend_from_slice(&OBSERVE_NATIVE.to_le_bytes());
        prog.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        let mut machine = boot_fixture(&prog, true, true);
        assert_eq!(observe(&mut machine), 1);
        let leaf = read_user_leaf(&machine, fault_va);
        assert_ne!(leaf & 1, 0);
        assert_ne!(leaf & 4, 0);
        if check_cow_cleared {
            assert_ne!(leaf & 2, 0);
            assert_eq!(leaf & (1 << 10), 0);
        } else {
            assert_eq!(leaf & (1 << 9), 0);
        }
        assert_eq!(leaf & PTE_ADDR_MASK, expected_gpa);
    }

    // --- Sub-case C: Live CPL3 hardware faults (#PF via `carrick_x86_user_page_fault`, #DE, #DB, #UD, #GP, #AC, and CPL0 #DF) ---
    // C1: Unresolved CPL3 #PF at 0x7_0000 routed through `carrick_x86_user_page_fault` (from IRQ_HEADER_GPA) ->
    // records `fault_address = 0x7_0000`, `fault_reason != 0`, and emits `FaultDoorbellRecord`!
    {
        let mut machine = boot_fixture(&[0x48, 0x8b, 0x04, 0x25, 0x00, 0x00, 0x07, 0x00], true, true);
        let rec = read_fault_doorbell(&mut machine);
        assert_eq!(rec.vector, 14);
        assert_eq!(rec.cr2, 0x7_0000);
        assert_eq!(rec.error_code, u64::from(PF_ERR_USER));
        assert_eq!(rec.cs, 0x2b);
        assert_eq!(rec.rsp, 0x3_1ff0);
        let binding_gpa = META_GPA + BINDING_OFFSET;
        // `fault_address` and `fault_reason` were published by `carrick_x86_unresolved_user_page_fault`:
        // SAFETY: stopped machine, aligned `CpuBinding` in `FixtureArena`.
        let binding = unsafe { &*(machine.mem().host_ptr(binding_gpa, size_of::<CpuBinding>()) as *const CpuBinding) };
        assert_eq!(binding.fault_address.load(Ordering::Acquire), 0x7_0000);
        assert_ne!(binding.fault_reason.load(Ordering::Acquire), 0);
    }

    // C2: CPL3 #DE (0), #DB (1), #UD (6), #GP (13), #AC (17) through `write_fault_tables_with` stubs!
    for (expected_vec, extra_rflags, set_am, prog) in [
        (0u8, 0u64, false, &[0x31, 0xd2, 0x31, 0xc9, 0xf7, 0xf1][..]), // #DE: div ecx
        (1, RFLAGS_TF, false, &[0x90][..]),                            // #DB: single-step nop
        (6, 0, false, &[0x0f, 0x0b][..]),                              // #UD: ud2
        (13, 0, false, &[0xfa][..]),                                   // #GP: cli at CPL3
        (17, RFLAGS_AC, true, &[0x48, 0x8b, 0x04, 0x25, 0x03, 0x00, 0x03, 0x00][..]), // #AC: unaligned [0x3_0003]
    ] {
        let mut machine = boot_fixture(prog, true, true);
        machine.context_mut().rflags |= extra_rflags;
        if set_am {
            machine.context_mut().cr0 |= CR0_AM;
        }
        let rec = read_fault_doorbell(&mut machine);
        assert_eq!(rec.vector, expected_vec, "CPL3 fault doorbell vector");
        assert_eq!(rec.cs, 0x2b);
        assert_eq!(rec.rsp, 0x3_1ff0);
    }

    // C3: CPL0 #DF (8) switches onto TSS.IST1 (`DIRECT_VA + IST_STACK_BASE + 4096`)!
    {
        let mut machine = boot_fixture(&[0x31, 0xd2, 0x31, 0xc9, 0xf7, 0xf1], false, true);
        let idt_gpa = fault_slot_gpa(fault_idt_base(LAYOUT), 0).unwrap();
        // Clear P bit on gate 0 (#DE) -> Contributory (#DE) + Contributory (#NP) -> #DF (8) on IST1!
        let mut gate0 = machine.mem().read_gpa(idt_gpa, 16);
        gate0[5] &= !0x80;
        machine.mem_mut().write_gpa(idt_gpa, &gate0);
        let rec = read_fault_doorbell(&mut machine);
        assert_eq!(rec.vector, 8);
        assert_eq!(rec.error_code, 0);
        assert_eq!(
            machine.context().gpr[reg::RSP],
            DIRECT_VA + IST_STACK_BASE + 4096 - 48
        );
    }

    // --- Sub-case D: All 4 native CPL0 external IRQ vectors (`0xe0..=0xe3`) delivered from CPL3 ---
    {
        // CPL3 loop: `inc r15 (49 ff c7); jmp -3 (eb fb)`
        let mut machine = boot_fixture(&[0x49, 0xff, 0xc7, 0xeb, 0xfb], true, true);
        let binding_gpa = META_GPA + BINDING_OFFSET;
        for (vec, expected_bit) in [
            (TIMER_VECTOR, 1u32),
            (KICK_VECTOR, 2u32),
            (RESCHED_VECTOR, 4u32),
            (SHOOTDOWN_VECTOR, 8u32),
        ] {
            // Set LAPIC ISR bit for `vec` (`LAPIC_BASE + 0x100 + (vec / 32) * 0x10`) and non-zero EOI sentinel:
            let isr_off = LAPIC_BASE + 0x100 + u64::from(vec / 32) * 0x10;
            let isr_bit = 1u32 << (vec % 32);
            machine.mem_mut().write_gpa(isr_off, &isr_bit.to_le_bytes());
            machine
                .mem_mut()
                .write_gpa(LAPIC_BASE + 0xb0, &0xffff_ffff_u32.to_le_bytes());

            machine.inject_interrupt(vec).unwrap();
            // Step until the CPL0 IRQ handler executes XSAVE64 -> capture_irq -> EOI -> XRSTOR64 -> IRETQ back to CPL3!
            let mut returned_to_cpl3 = false;
            for _ in 0..512 {
                assert_eq!(machine.step().unwrap(), None);
                if machine.context().cpl == 3 {
                    returned_to_cpl3 = true;
                    break;
                }
            }
            assert!(returned_to_cpl3, "IRQ {vec:#x} must return to CPL3 via IRETQ");
            assert_eq!(
                machine.mem().read_u32(LAPIC_BASE + 0xb0),
                0,
                "CPL0 IRQ handler must write 0 to LAPIC EOI"
            );
            machine.mem_mut().write_gpa(isr_off, &0u32.to_le_bytes());

            // SAFETY: stopped machine, aligned `CpuBinding` in `FixtureArena`.
            let binding = unsafe {
                &*(machine.mem().host_ptr(binding_gpa, size_of::<CpuBinding>()) as *const CpuBinding)
            };
            assert_ne!(
                binding.pending_irqs.load(Ordering::Acquire) & expected_bit,
                0,
                "CPL0 IRQ {vec:#x} must record bit {expected_bit:#x} in CpuBinding.pending_irqs"
            );
        }
        // Verify CPL3 loop continues advancing `r15` cleanly after all 4 IRQs!
        let before = machine.context().gpr[reg::R15];
        assert_eq!(machine.step().unwrap(), None);
        assert!(machine.context().gpr[reg::R15] > before);
    }
}
