//! VM-free 64-bit IDT exception delivery tests (`#669`, slice 1).

#![cfg(target_arch = "x86_64")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};

use carrick_softcpu_x86::{
    Cpl0CpuidView, DescriptorTablePtr, ExtentRecord, ExtentTable, FrameGpa, LinearPlacement,
    MmioHoles, OwnerGeneration, PF_ERR_INSTR, PF_ERR_PRESENT, PF_ERR_RSVD, PF_ERR_USER,
    PF_ERR_WRITE, RootGpa, SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK, SOFT_TLB_PAGE_SIZE,
    SoftAccessKind, SoftCpuContext, SoftMachine, SoftMachineExit, SoftMmuMemory, SoftSegment,
    X86Exception, X86ExceptionVector, reg, translate_va,
};
use carrick_x86::{GuestSegment, LongModeSegments, check_vmx_guest_segments};

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_RSVD_BIT51: u64 = 1 << 51;
const PTE_NX: u64 = 1 << 63;
const PTE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
const NON_CANON: u64 = 0x0001_0000_0000_1000;

const CODE_VA: u64 = 0xffff_8000_0010_0000;
const HANDLER_BASE_VA: u64 = 0xffff_8000_0014_0000;
const USER_CODE_VA: u64 = 0x0000_0000_0040_0000;
const USER_DATA_VA: u64 = 0x0000_0000_0050_0000;
const USER_STACK_VA: u64 = 0x0000_0000_0060_0000;
const DATA_VA: u64 = 0xffff_8000_0020_0000;
const STACK_VA: u64 = 0xffff_8000_0030_0000;
const RSP0_VA: u64 = 0xffff_8000_0032_0000;
const RSP1_VA: u64 = 0xffff_8000_0033_0000;
const IST1_VA: u64 = 0xffff_8000_0034_0000;
const IST2_VA: u64 = 0xffff_8000_0036_0000;
const IST7_VA: u64 = 0xffff_8000_0038_0000;
const GDT_VA: u64 = 0xffff_8000_0040_0000;
const IDT_VA: u64 = 0xffff_8000_0041_0000;
const TSS_VA: u64 = 0xffff_8000_0042_0000;

const RFLAGS_TF: u64 = 1 << 8;
const RFLAGS_IF: u64 = 1 << 9;
const RFLAGS_NT: u64 = 1 << 14;
const RFLAGS_RF: u64 = 1 << 16;
const RFLAGS_AC: u64 = 1 << 18;
const CR0_TS: u64 = 1 << 3;
const CR0_AM: u64 = 1 << 18;

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
    stack_frame: FrameGpa,
    rsp0_frame: FrameGpa,
    rsp1_frame: FrameGpa,
    ist1_frame: FrameGpa,
    ist2_frame: FrameGpa,
    ist7_frame: FrameGpa,
}

struct TestMemory {
    _backing: Vec<AtomicU64>,
    placement: LinearPlacement,
    extents: ExtentTable,
    next_gpa: u64,
}

impl TestMemory {
    const POOL_BYTES: u64 = 16 * 1024 * 1024;
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

    fn leaf_slot_gpa(&mut self, va: u64) -> u64 {
        let va_page = va & SOFT_TLB_PAGE_MASK;
        let mut tbl = Self::ROOT_GPA;
        for shift in [39, 30, 21] {
            tbl = self.ensure_child(tbl, ((va_page >> shift) & 0x1ff) as usize);
        }
        tbl + ((va_page >> 12) & 0x1ff) * 8
    }

    fn map_frame(&mut self, va: u64, frame: FrameGpa, p: Perms) {
        let w = if (p.0 & 2) != 0 { PTE_WRITABLE } else { 0 };
        let u = if (p.0 & 8) != 0 { PTE_USER } else { 0 };
        let nx = if (p.0 & 4) == 0 { PTE_NX } else { 0 };
        let pte = (frame.raw() & PTE_ADDR_MASK) | PTE_PRESENT | w | u | nx;
        let slot = self.leaf_slot_gpa(va);
        self.word_ref(slot).store(pte, Ordering::Relaxed);
    }

    fn write_raw_pte(&mut self, va: u64, pte: u64) {
        let slot = self.leaf_slot_gpa(va);
        self.word_ref(slot).store(pte, Ordering::Relaxed);
    }

    fn map_page(&mut self, va: u64, p: Perms) -> FrameGpa {
        let f = self.alloc_frame();
        self.map_frame(va, f, p);
        f
    }

    fn unmap_page(&mut self, va: u64) {
        let slot = self.leaf_slot_gpa(va);
        self.word_ref(slot).store(0, Ordering::Relaxed);
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

fn encode_idt_gate(
    handler_va: u64,
    cs_sel: u16,
    ist: u8,
    gate_type: u8,
    dpl: u8,
    p: bool,
) -> [u8; 16] {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame40 {
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame48 {
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

impl IdtTestRig {
    fn new() -> Self {
        let mut mem = TestMemory::new();
        let _code = mem.map_page(CODE_VA, Perms::KERNEL_RX);
        let _handlers = mem.map_page(HANDLER_BASE_VA, Perms::KERNEL_RX);
        let _user_code = mem.map_page(USER_CODE_VA, Perms::USER_RX);
        let _user_data = mem.map_page(USER_DATA_VA, Perms::USER_RW);
        let _user_stack = mem.map_page(USER_STACK_VA, Perms::USER_RW);
        let _data_frame = mem.map_page(DATA_VA, Perms::KERNEL_RW);
        let stack_frame = mem.map_page(STACK_VA, Perms::KERNEL_RW);
        let rsp0_frame = mem.map_page(RSP0_VA, Perms::KERNEL_RW);
        let rsp1_frame = mem.map_page(RSP1_VA, Perms::KERNEL_RW);
        let ist1_frame = mem.map_page(IST1_VA, Perms::KERNEL_RW);
        let ist2_frame = mem.map_page(IST2_VA, Perms::KERNEL_RW);
        let ist7_frame = mem.map_page(IST7_VA, Perms::KERNEL_RW);
        let gdt_frame = mem.map_page(GDT_VA, Perms::KERNEL_RW);
        let idt_frame = mem.map_page(IDT_VA, Perms::KERNEL_RW);
        let tss_frame = mem.map_page(TSS_VA, Perms::KERNEL_RW);

        // Give `rsp0_frame` its own extent so physical-retirement tests can retire it cleanly.
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

        // TSS64:
        // +4:  RSP0 = RSP0_VA + 0xff8 (unaligned -> aligned down to +0xff0)
        // +12: RSP1 = RSP1_VA + 0xff8 (unaligned -> aligned down to +0xff0)
        // +36: IST1 = IST1_VA + 0xff8 (unaligned -> aligned down to +0xff0)
        // +44: IST2 = IST2_VA + 0xff0
        // +84: IST7 = IST7_VA + 0xff8 (unaligned -> aligned down to +0xff0)
        mem.write_gpa(tss_frame.raw() + 4, &(RSP0_VA + 0xff8).to_le_bytes());
        mem.write_gpa(tss_frame.raw() + 12, &(RSP1_VA + 0xff8).to_le_bytes());
        mem.write_gpa(tss_frame.raw() + 36, &(IST1_VA + 0xff8).to_le_bytes());
        mem.write_gpa(tss_frame.raw() + 44, &(IST2_VA + 0xff0).to_le_bytes());
        mem.write_gpa(tss_frame.raw() + 84, &(IST7_VA + 0xff8).to_le_bytes());

        let cpuid = Cpl0CpuidView {
            max_phy_addr: 48,
            ..Default::default()
        };
        let mut machine = SoftMachine::new(mem, Box::new(cpuid)).unwrap();
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
            stack_frame,
            rsp0_frame,
            rsp1_frame,
            ist1_frame,
            ist2_frame,
            ist7_frame,
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

    fn stub_va(vec: u8) -> u64 {
        HANDLER_BASE_VA + u64::from(vec) * 16
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

    #[allow(clippy::too_many_arguments)]
    fn set_gate(&mut self, vec: u8, handler_va: u64, cs: u16, ist: u8, typ: u8, dpl: u8, p: bool) {
        let gate = encode_idt_gate(handler_va, cs, ist, typ, dpl, p);
        self.machine
            .mem_mut()
            .write_gpa(self.idt_frame.raw() + u64::from(vec) * 16, &gate);
    }

    fn write_raw_gate(&mut self, vec: u8, raw: &[u8; 16]) {
        self.machine
            .mem_mut()
            .write_gpa(self.idt_frame.raw() + u64::from(vec) * 16, raw);
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
        let stub_va = Self::stub_va(vec);
        assert!(bytes.len() <= 16);
        let stub_gpa = self.translate_kernel_page_gpa(HANDLER_BASE_VA) + u64::from(vec) * 16;
        self.machine.mem_mut().write_gpa(stub_gpa, bytes);
        self.machine.context_mut().flush_tlb();
        stub_va
    }

    fn enter_cpl3_rsp(&mut self, rip: u64, rsp: u64, rflags: u64) {
        let ctx = self.machine.context_mut();
        ctx.set_cpl(3);
        ctx.cs = SoftSegment::user_code64(0x2b);
        ctx.ss = SoftSegment::user_data(0x23);
        ctx.gpr[reg::RSP] = rsp;
        ctx.rflags = rflags | 0x2;
        ctx.halted = false;
        ctx.rip = rip;
    }

    fn enter_cpl3(&mut self, rip: u64, rflags: u64) {
        self.enter_cpl3_rsp(rip, USER_STACK_VA + 0xff0, rflags);
    }

    fn enter_cpl0_rsp(&mut self, rip: u64, rsp: u64, rflags: u64) {
        let ctx = self.machine.context_mut();
        ctx.set_cpl(0);
        ctx.cs = SoftSegment::kernel_code64(0x08);
        ctx.ss = SoftSegment::kernel_data(0x10);
        ctx.gpr[reg::RSP] = rsp;
        ctx.rflags = rflags | 0x2;
        ctx.halted = false;
        ctx.rip = rip;
    }

    fn enter_cpl0(&mut self, rip: u64, rflags: u64) {
        self.enter_cpl0_rsp(rip, STACK_VA + 0xff0, rflags);
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

    fn read_frame40(&self, frame_gpa: FrameGpa, offset: u64) -> Frame40 {
        let base = frame_gpa.raw() + offset;
        Frame40 {
            rip: self.machine.mem().read_u64(base),
            cs: self.machine.mem().read_u64(base + 8),
            rflags: self.machine.mem().read_u64(base + 16),
            rsp: self.machine.mem().read_u64(base + 24),
            ss: self.machine.mem().read_u64(base + 32),
        }
    }

    fn read_frame48(&self, frame_gpa: FrameGpa, offset: u64) -> Frame48 {
        let base = frame_gpa.raw() + offset;
        Frame48 {
            error_code: self.machine.mem().read_u64(base),
            rip: self.machine.mem().read_u64(base + 8),
            cs: self.machine.mem().read_u64(base + 16),
            rflags: self.machine.mem().read_u64(base + 24),
            rsp: self.machine.mem().read_u64(base + 32),
            ss: self.machine.mem().read_u64(base + 40),
        }
    }
}

#[test]
fn idt_gate_types_present_and_dpl_checks_match_sdm() {
    let mut rig = IdtTestRig::new();

    // 1. 64-bit Interrupt Gate (0x0e) clears RFLAGS.IF; 64-bit Trap Gate (0x0f) preserves RFLAGS.IF.
    rig.set_gate(0x80, IdtTestRig::stub_va(0x80), 0x08, 0, 0x0e, 3, true);
    rig.set_gate(0x81, IdtTestRig::stub_va(0x81), 0x08, 0, 0x0f, 3, true);

    rig.write_user_code(&[0xcd, 0x80]); // int 0x80
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_NT);
    assert_eq!(rig.run_to_vec_port(), 0x80);
    assert_eq!(rig.machine.context().rflags & (RFLAGS_IF | RFLAGS_NT), 0);
    let intr_frame = rig.read_frame40(rig.rsp0_frame, 0xfc8);
    assert_eq!(intr_frame.rip, USER_CODE_VA + 2);
    assert_eq!(
        intr_frame.rflags & (RFLAGS_IF | RFLAGS_NT),
        RFLAGS_IF | RFLAGS_NT
    );

    rig.write_user_code(&[0xcd, 0x81]); // int 0x81
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_NT);
    assert_eq!(rig.run_to_vec_port(), 0x81);
    assert_eq!(
        rig.machine.context().rflags & (RFLAGS_IF | RFLAGS_NT),
        RFLAGS_IF
    );
    let trap_frame = rig.read_frame40(rig.rsp0_frame, 0xfc8);
    assert_eq!(trap_frame.rip, USER_CODE_VA + 2);
    assert_eq!(
        trap_frame.rflags & (RFLAGS_IF | RFLAGS_NT),
        RFLAGS_IF | RFLAGS_NT
    );

    // Trap gate with IF=0 on entry keeps IF=0 (never sets IF).
    rig.enter_cpl0(CODE_VA, 0);
    rig.write_kernel_code(&[0xcd, 0x81]);
    assert_eq!(rig.run_to_vec_port(), 0x81);
    assert_eq!(rig.machine.context().rflags & RFLAGS_IF, 0);

    // 2. Invalid gate types (0x0c call gate, 0x05 task gate, S=1 0x1e) and non-zero upper bits [12:8] -> #GP.
    for bad_type in [0x0cu8, 0x05u8, 0x1eu8] {
        rig.set_gate(0x82, IdtTestRig::stub_va(0x82), 0x08, 0, bad_type, 3, true);
        rig.write_user_code(&[0xcd, 0x82]);
        rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
        assert_eq!(rig.run_to_vec_port(), 13);
        let f = rig.read_frame48(rig.rsp0_frame, 0xfc0);
        // Software INT -> EXT=0, IDT=1 -> (0x82 << 3) | 0x2.
        assert_eq!(f.error_code, (0x82u64 << 3) | 0x2);
        assert_eq!(f.rip, USER_CODE_VA);
    }

    let mut bad_upper = encode_idt_gate(IdtTestRig::stub_va(0x82), 0x08, 0, 0x0e, 3, true);
    bad_upper[13] = 0x01; // reserved bit 8 in upper dword [12:8]
    rig.write_raw_gate(0x82, &bad_upper);
    rig.write_user_code(&[0xcd, 0x82]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0).error_code,
        (0x82u64 << 3) | 0x2
    );

    // Restore valid 0x82 gate.
    rig.set_gate(0x82, IdtTestRig::stub_va(0x82), 0x08, 0, 0x0e, 3, true);

    // 3. IDTR limit refusal -> #GP((vec << 3) | 0x2 | ext).
    rig.machine.context_mut().idtr.limit = 0x80 * 16 - 1;
    rig.write_user_code(&[0xcd, 0x80]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0).error_code,
        (0x80u64 << 3) | 0x2
    );
    rig.machine.context_mut().idtr.limit = 0xfff;

    // 4. DPL checks for software INT n / INT3 vs hardware exceptions / ICEBP, and P=0 (#NP) ordering:
    // 4a. Software INT 0x83 at CPL3 with DPL=0 AND P=0 -> DPL check fires FIRST (#GP, EXT=0), NOT #NP!
    rig.set_gate(0x83, IdtTestRig::stub_va(0x83), 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0xcd, 0x83]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    let dpl_gp = rig.read_frame48(rig.rsp0_frame, 0xfc0);
    assert_eq!(dpl_gp.error_code, (0x83u64 << 3) | 0x2);
    assert_eq!(dpl_gp.rip, USER_CODE_VA);

    // 4b. Software INT 0x83 at CPL3 with DPL=3 AND P=0 -> passes DPL, raises #NP with EXT=0.
    rig.set_gate(0x83, IdtTestRig::stub_va(0x83), 0x08, 0, 0x0e, 3, false);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 11);
    let sw_np = rig.read_frame48(rig.rsp0_frame, 0xfc0);
    assert_eq!(sw_np.error_code, (0x83u64 << 3) | 0x2);
    assert_eq!(sw_np.rip, USER_CODE_VA);

    // 4c. INT3 (0xCC, vector 3) at CPL3: DPL=0 -> #GP((3 << 3) | 2), DPL=3 -> #BP with RIP = va + 1.
    rig.set_gate(3, IdtTestRig::stub_va(3), 0x08, 0, 0x0f, 0, true);
    rig.write_user_code(&[0xcc]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    let int3_gp = rig.read_frame48(rig.rsp0_frame, 0xfc0);
    assert_eq!(int3_gp.error_code, (3u64 << 3) | 0x2);
    assert_eq!(int3_gp.rip, USER_CODE_VA);

    rig.set_gate(3, IdtTestRig::stub_va(3), 0x08, 0, 0x0f, 3, true);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 3);
    assert_eq!(
        rig.read_frame40(rig.rsp0_frame, 0xfc8).rip,
        USER_CODE_VA + 1
    );

    // 4d. Hardware exception (#UD at CPL3) bypasses DPL=0; if gate has P=0, raises #NP with EXT=1!
    rig.set_gate(6, IdtTestRig::stub_va(6), 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0x0f, 0x0b]); // ud2
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 11);
    let hw_np = rig.read_frame48(rig.rsp0_frame, 0xfc0);
    assert_eq!(hw_np.error_code, (6u64 << 3) | 0x2 | 0x1);
    assert_eq!(hw_np.rip, USER_CODE_VA);
    rig.set_gate(6, IdtTestRig::stub_va(6), 0x08, 0, 0x0e, 0, true);

    // 4e. Software `INT 13` / `INT 14` with DPL=3 pushes NO error code (40-byte frame), unlike hardware #GP/#PF!
    rig.set_gate(13, IdtTestRig::stub_va(13), 0x08, 0, 0x0e, 3, true);
    rig.write_user_code(&[0xcd, 13]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc8); // 0xff0 - 40
    assert_eq!(
        rig.read_frame40(rig.rsp0_frame, 0xfc8).rip,
        USER_CODE_VA + 2
    );
    rig.set_gate(13, IdtTestRig::stub_va(13), 0x08, 0, 0x0e, 0, true);
}

#[test]
fn idt_ist_rsp0_stack_switch_alignment_and_frame_layout_match_sdm() {
    let mut rig = IdtTestRig::new();

    // 1. CPL3 -> CPL0 (IST=0): switches to TSS.RSP0 (+0xff8 -> aligned to +0xff0), pushes SS:RSP,
    // loads VMX-valid NULL SS (selector=0, DPL=0), and IRETQ restores unaligned user RSP (+0xff8).
    rig.write_handler(0x80, &[0xb0, 0x80, 0xe6, 0xe0, 0x48, 0xcf]); // mov al, 0x80; out 0xe0, al; iretq
    rig.set_gate(0x80, IdtTestRig::stub_va(0x80), 0x08, 0, 0x0e, 3, true);
    rig.write_user_code(&[0xcd, 0x80, 0xb0, 0x55, 0xe6, 0xe0]); // int 0x80; mov al, 0x55; out 0xe0, al (CPL3 OUT -> #GP)
    rig.enter_cpl3_rsp(USER_CODE_VA, USER_STACK_VA + 0xff8, RFLAGS_IF);
    rig.machine.context_mut().reset_tlb_stats();
    assert_eq!(rig.run_to_vec_port(), 0x80);
    // Zero implicit SoftTlb flushes across IDT gate entry (`page_table_invalidations <= 1` contract).
    assert_eq!(rig.machine.context().tlb_stats().full_flushes, 0);
    {
        let ctx = rig.machine.context();
        assert_eq!(ctx.cpl, 0);
        assert_eq!(ctx.gpr[reg::RSP], RSP0_VA + 0xfc8);
        assert!(ctx.ss.is_unusable());
        assert_eq!(ctx.ss.selector, 0);
        assert_vmx_valid(ctx);
    }
    assert_eq!(
        rig.read_frame40(rig.rsp0_frame, 0xfc8),
        Frame40 {
            rip: USER_CODE_VA + 2,
            cs: 0x2b,
            rflags: RFLAGS_IF | 0x2,
            rsp: USER_STACK_VA + 0xff8,
            ss: 0x23,
        }
    );
    // Step IRETQ -> returns to CPL3 with unaligned RSP = USER_STACK_VA + 0xff8, then faults on `out` (#GP).
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0).rsp,
        USER_STACK_VA + 0xff8
    );

    // 2. CPL0 -> CPL0 same-privilege (IST=0): aligns current RSP (+0xff8 -> +0xff0) and STILL pushes SS:RSP!
    rig.write_handler(0x81, &[0xb0, 0x81, 0xe6, 0xe0, 0x48, 0xcf]); // mov al, 0x81; out 0xe0, al; iretq
    rig.set_gate(0x81, IdtTestRig::stub_va(0x81), 0x08, 0, 0x0e, 0, true);
    rig.write_kernel_code(&[0xcd, 0x81, 0xf4]); // int 0x81; hlt
    rig.enter_cpl0_rsp(CODE_VA, STACK_VA + 0xff8, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 0x81);
    {
        let ctx = rig.machine.context();
        assert_eq!(ctx.cpl, 0);
        assert_eq!(ctx.gpr[reg::RSP], STACK_VA + 0xfc8);
        // Same-privilege IST=0 preserves kernel SS selector 0x10.
        assert_eq!(ctx.ss.selector, 0x10);
        assert!(!ctx.ss.is_unusable());
        assert_vmx_valid(ctx);
    }
    assert_eq!(
        rig.read_frame40(rig.stack_frame, 0xfc8),
        Frame40 {
            rip: CODE_VA + 2,
            cs: 0x08,
            rflags: RFLAGS_IF | 0x2,
            rsp: STACK_VA + 0xff8,
            ss: 0x10,
        }
    );
    // Continue across IRETQ -> HLT at CODE_VA + 2 with unaligned RSP restored!
    assert_eq!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA + 2,
            next_rip: CODE_VA + 3,
        }
    );
    assert_eq!(rig.machine.context().gpr[reg::RSP], STACK_VA + 0xff8);
    assert_eq!(rig.machine.context().rflags & RFLAGS_IF, RFLAGS_IF);

    // 3. IST selection from TSS:
    // 3a. CPL0 -> CPL0 with IST=7 switches to TSS.IST7 (+0xff8 -> +0xff0) and loads NULL SS!
    rig.write_handler(0x82, &[0xb0, 0x82, 0xe6, 0xe0, 0x48, 0xcf]);
    rig.set_gate(0x82, IdtTestRig::stub_va(0x82), 0x08, 7, 0x0e, 0, true);
    rig.write_kernel_code(&[0xcd, 0x82, 0xf4]);
    rig.enter_cpl0_rsp(CODE_VA, STACK_VA + 0xf08, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 0x82);
    {
        let ctx = rig.machine.context();
        assert_eq!(ctx.gpr[reg::RSP], IST7_VA + 0xfc8);
        assert!(ctx.ss.is_unusable());
        assert_eq!(ctx.ss.selector, 0);
        assert_vmx_valid(ctx);
    }
    assert_eq!(
        rig.read_frame40(rig.ist7_frame, 0xfc8).rsp,
        STACK_VA + 0xf08
    );
    assert_eq!(rig.read_frame40(rig.ist7_frame, 0xfc8).ss, 0x10);
    assert_eq!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA + 2,
            next_rip: CODE_VA + 3,
        }
    );
    assert_eq!(rig.machine.context().gpr[reg::RSP], STACK_VA + 0xf08);

    // 3b. CPL3 -> CPL0 with IST=2 overrides TSS.RSP0 and uses TSS.IST2!
    rig.set_gate(0x83, IdtTestRig::stub_va(0x83), 0x08, 2, 0x0e, 3, true);
    rig.write_user_code(&[0xcd, 0x83]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 0x83);
    assert_eq!(rig.machine.context().gpr[reg::RSP], IST2_VA + 0xfc8);
    assert_eq!(
        rig.read_frame40(rig.ist2_frame, 0xfc8).rsp,
        USER_STACK_VA + 0xff0
    );

    // 3c. CPL3 -> Ring 1 (target CS = 0x18, DPL=1, IST=0): selects TSS.RSP1 (+12) and loads NULL SS with RPL=DPL=1!
    let ring1_va = 0x0000_0000_0070_0000u64;
    let ring1_frame = rig.machine.mem_mut().map_page(ring1_va, Perms::KERNEL_RX);
    // Ring 1 handler executes `iretq` back to CPL3, where `ud2` fires to CPL0!
    rig.machine
        .mem_mut()
        .write_gpa(ring1_frame.raw(), &[0x48, 0xcf]);
    rig.set_gate(0x84, ring1_va, 0x18, 0, 0x0e, 3, true);
    rig.write_user_code(&[0xcd, 0x84, 0x0f, 0x0b]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.machine.step().unwrap(), None); // enters Ring 1 handler
    {
        let ctx = rig.machine.context();
        assert_eq!(ctx.cpl, 1);
        assert_eq!(ctx.cs.selector, 0x19);
        assert_eq!(ctx.ss.selector, 1);
        assert!(ctx.ss.is_unusable());
        assert_vmx_valid(ctx);
        assert_eq!(ctx.gpr[reg::RSP], RSP1_VA + 0xfc8);
    }
    assert_eq!(
        rig.read_frame40(rig.rsp1_frame, 0xfc8).rip,
        USER_CODE_VA + 2
    );
    assert_eq!(rig.run_to_vec_port(), 6); // IRETQ -> CPL3 -> ud2 -> Ring 0 #UD!

    // 4. Target-CPL stack push rights: CPL3 -> CPL3 gate (target CS = 0x28, DPL=3) with user RSP on a
    // supervisor-only page raises #PF with U/S = 1 (`PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER`)!
    let sup_only_stack = 0x0000_0000_0071_0000u64;
    rig.machine
        .mem_mut()
        .map_page(sup_only_stack, Perms::KERNEL_RW);
    rig.set_gate(0x85, USER_CODE_VA + 0x40, 0x2b, 0, 0x0f, 3, true);
    rig.write_user_code(&[0xcd, 0x85]);
    rig.enter_cpl3_rsp(USER_CODE_VA, sup_only_stack + 0xff0, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, sup_only_stack + 0xfc8);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0).error_code,
        u64::from(PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER)
    );

    // 5. Invalid/short TSS -> #TS(tr_sel | ext); non-canonical RSP0 -> #SS(ext).
    rig.machine.context_mut().tr.limit = 4; // too small for RSP0 (+4..+11)
    rig.write_user_code(&[0x0f, 0x0b]); // ud2 -> CPL3->0 tries RSP0 -> #TS -> #TS needs IST!
    // Put #TS (vector 10) on same-privilege? No, from CPL3 any CPL0 handler needs TSS!
    // Test from CPL0 with IST=1 where TR.limit < 43 -> #TS(0x30 | 1) delivered on IST=0 CPL0 stack!
    rig.set_gate(6, IdtTestRig::stub_va(6), 0x08, 1, 0x0e, 0, true);
    rig.machine.context_mut().tr.limit = 0x20; // < 36 + 7, so IST1 fails with #TS!
    rig.write_kernel_code(&[0x0f, 0x0b]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 10);
    let ts_frame = rig.read_frame48(rig.stack_frame, 0xfc0);
    assert_eq!(ts_frame.error_code, 0x30 | 1);
    assert_eq!(ts_frame.rip, CODE_VA);
    rig.machine.context_mut().tr.limit = 0x67;

    // Non-canonical IST1 -> #SS(1) delivered on IST=0 CPL0 stack.
    rig.machine
        .mem_mut()
        .write_gpa(rig.tss_frame.raw() + 36, &NON_CANON.to_le_bytes());
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 12);
    let ss_frame = rig.read_frame48(rig.stack_frame, 0xfc0);
    assert_eq!(ss_frame.error_code, 1);
    assert_eq!(ss_frame.rip, CODE_VA);
    rig.machine
        .mem_mut()
        .write_gpa(rig.tss_frame.raw() + 36, &(IST1_VA + 0xff8).to_le_bytes());
    rig.set_gate(6, IdtTestRig::stub_va(6), 0x08, 0, 0x0e, 0, true);

    // 6. Physical-retirement witness (`softmmu.x86.physical-retirement`):
    // Warm SoftTlb on `rsp0_frame`, retire `rsp0_frame` and install `rsp0_frame_b` while parked,
    // then trigger CPL3 #UD -> IDT stack push must retire debt and write only to `rsp0_frame_b`.
    {
        let (cpu, mem) = rig.machine.into_parts();
        let mut cpu = cpu;
        let mut mem = mem;
        cpu.context_mut().set_cpl(0);
        let _ = translate_va(
            cpu.context_mut(),
            &mut mem,
            RSP0_VA + 0xfc8,
            SoftAccessKind::Write,
        )
        .unwrap();
        mem.write_gpa(rig.rsp0_frame.raw() + 0xfc8, &[0xaa; 40]);

        let rsp0_frame_b = mem.alloc_frame();
        mem.map_frame(RSP0_VA, rsp0_frame_b, Perms::KERNEL_RW);
        let removed = mem
            .extents_mut()
            .remove(rig.rsp0_frame, None)
            .unwrap()
            .unwrap();
        let completion = removed.pending.try_complete().unwrap();
        mem.extents_mut().reclaim(&completion);

        rig.machine = SoftMachine::from_parts(cpu, mem);
        rig.write_user_code(&[0x0f, 0x0b]);
        rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
        assert_eq!(rig.run_to_vec_port(), 6);
        assert_eq!(
            rig.machine.mem().read_gpa(rig.rsp0_frame.raw() + 0xfc8, 40),
            vec![0xaa; 40]
        );
        assert_eq!(rig.read_frame40(rsp0_frame_b, 0xfc8).rip, USER_CODE_VA);
    }
}

#[test]
fn idt_error_code_presence_and_pf_cr2_bits_match_sdm() {
    // 1. Static SDM Table 6-1 classification check across all named vectors in Item 3:
    for v in [
        X86ExceptionVector::DoubleFault,
        X86ExceptionVector::InvalidTss,
        X86ExceptionVector::SegmentNotPresent,
        X86ExceptionVector::StackSegmentFault,
        X86ExceptionVector::GeneralProtection,
        X86ExceptionVector::PageFault,
        X86ExceptionVector::AlignmentCheck,
    ] {
        assert!(v.has_error_code(), "{v:?} must push an error code");
    }
    for v in [
        X86ExceptionVector::DivideError,
        X86ExceptionVector::Debug,
        X86ExceptionVector::Breakpoint,
        X86ExceptionVector::Overflow,
        X86ExceptionVector::InvalidOpcode,
        X86ExceptionVector::DeviceNotAvailable,
    ] {
        assert!(!v.has_error_code(), "{v:?} must not push an error code");
    }
    assert_eq!(X86Exception::overflow(CODE_VA).error_code, None);

    let mut rig = IdtTestRig::new();

    // 2. #NM (vector 7, no error code, 40-byte frame) via CR0.TS = 1 + FXSAVE64 / MOVAPS + CLTS recovery:
    // Handler 7: `clts; mov byte ptr [rip+...], 1; iretq` -> use port 0xe0 first to inspect 40-byte frame!
    rig.machine.context_mut().cr0 |= CR0_TS;
    // CPL3 `movaps xmm0, xmm1` (`0f 28 c1`) with CR0.TS=1 -> #NM (vector 7), 40-byte frame!
    rig.write_user_code(&[0x0f, 0x28, 0xc1]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 7);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc8); // 40-byte frame (no error code)
    assert_eq!(rig.read_frame40(rig.rsp0_frame, 0xfc8).rip, USER_CODE_VA);

    // Install lazy-FPU #NM handler (`clts; iretq` = `0f 06 48 cf`) and verify `fxsave64` + `movaps` complete!
    rig.write_handler(7, &[0x0f, 0x06, 0x48, 0xcf]);
    rig.machine.context_mut().cr0 |= CR0_TS;
    rig.machine
        .context_mut()
        .write_xmm(1, 0xdead_beef_cafe_babe_u128);
    // CPL0: `fxsave64 [rax]; movaps xmm0, xmm1; hlt`
    rig.write_kernel_code(&[0x48, 0x0f, 0xae, 0x00, 0x0f, 0x28, 0xc1, 0xf4]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = DATA_VA;
    assert_eq!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA + 7,
            next_rip: CODE_VA + 8,
        }
    );
    assert_eq!(rig.machine.context().cr0 & CR0_TS, 0);
    assert_eq!(
        rig.machine.context().read_xmm(0),
        0xdead_beef_cafe_babe_u128
    );
    // Restore default stub for vector 7.
    rig.write_handler(7, &[0xb0, 7, 0xe6, 0xe0, 0xf4]);

    // 3. #BP (vector 3, INT3) and #OF (vector 4, INT 4; 0xCE INTO is #UD in 64-bit mode) -> 40-byte frame (no error code):
    rig.set_gate(3, IdtTestRig::stub_va(3), 0x08, 0, 0x0e, 3, true);
    rig.set_gate(4, IdtTestRig::stub_va(4), 0x08, 0, 0x0e, 3, true);
    rig.write_user_code(&[0xcc]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 3);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc8);

    rig.write_user_code(&[0xcd, 0x04]); // int 4
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 4);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc8);

    rig.write_user_code(&[0xce]); // legacy INTO -> #UD (vector 6, 40-byte frame) in 64-bit mode
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 6);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc8);

    // 4. #SS (vector 12, 48-byte frame with selector error code) via IRETQ loading not-present SS:
    // GDT entry at 0x20: mark not-present (clear bit 47).
    let np_user_ss = 0x00cf_7300_0000_ffffu64;
    rig.machine
        .mem_mut()
        .write_gpa(rig.gdt_frame.raw() + 0x20, &np_user_ss.to_le_bytes());
    let iret_frame_off = 0xe00u64;
    for (i, w) in [
        USER_CODE_VA,
        0x2b,
        RFLAGS_IF | 0x2,
        USER_STACK_VA + 0xff0,
        0x23,
    ]
    .into_iter()
    .enumerate()
    {
        rig.machine.mem_mut().write_gpa(
            rig.stack_frame.raw() + iret_frame_off + (i as u64) * 8,
            &w.to_le_bytes(),
        );
    }
    rig.write_kernel_code(&[0x48, 0xcf]); // iretq
    rig.enter_cpl0_rsp(CODE_VA, STACK_VA + iret_frame_off, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 12);
    let ss_f = rig.read_frame48(rig.stack_frame, iret_frame_off - 48);
    assert_eq!(ss_f.error_code, 0x20);
    assert_eq!(ss_f.rip, CODE_VA);
    // Restore GDT 0x20.
    rig.machine.mem_mut().write_gpa(
        rig.gdt_frame.raw() + 0x20,
        &0x00cf_f300_0000_ffffu64.to_le_bytes(),
    );

    // 5. #PF CR2 and all five error-code bits: P (0x1), W/R (0x2), U/S (0x4), RSVD (0x8), I/D (0x10):
    let pf_va = 0x0000_0000_0090_0000u64;

    // 5a. Not-present supervisor read -> ec == 0, CR2 == pf_va + 0x34.
    rig.write_kernel_code(&[0x48, 0x8b, 0x00]); // mov rax, [rax]
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = pf_va + 0x34;
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, pf_va + 0x34);
    assert_eq!(rig.read_frame48(rig.stack_frame, 0xfc0).error_code, 0);

    // 5b. Not-present user write -> ec == W/R | U/S (0x6), CR2 == pf_va + 0x78.
    rig.write_user_code(&[0x48, 0x89, 0x08]); // mov [rax], rcx
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = pf_va + 0x78;
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, pf_va + 0x78);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0).error_code,
        u64::from(PF_ERR_WRITE | PF_ERR_USER)
    );

    // 5c. Present read-only user write -> ec == P | W/R | U/S (0x7).
    let pf_frame = rig.machine.mem_mut().map_page(pf_va, Perms::USER_RO);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = pf_va + 0x10;
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, pf_va + 0x10);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0).error_code,
        u64::from(PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER)
    );

    // 5d. Reserved PTE bit set (bit 51 with max_phy_addr=48) -> ec == P | U/S | RSVD (0xd).
    rig.machine.mem_mut().write_raw_pte(
        pf_va,
        (pf_frame.raw() & PTE_ADDR_MASK) | PTE_PRESENT | PTE_USER | PTE_RSVD_BIT51,
    );
    rig.machine.context_mut().flush_tlb();
    rig.write_user_code(&[0x48, 0x8b, 0x00]); // mov rax, [rax]
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = pf_va + 0x20;
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, pf_va + 0x20);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0).error_code,
        u64::from(PF_ERR_PRESENT | PF_ERR_USER | PF_ERR_RSVD)
    );

    // 5e. NX instruction fetch at CPL3 -> ec == P | U/S | I/D (0x15), CR2 == pf_va.
    rig.machine
        .mem_mut()
        .map_frame(pf_va, pf_frame, Perms::USER_RW); // NX = 1
    rig.machine.context_mut().flush_tlb();
    rig.enter_cpl3(pf_va, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, pf_va);
    let nx_f = rig.read_frame48(rig.rsp0_frame, 0xfc0);
    assert_eq!(
        nx_f.error_code,
        u64::from(PF_ERR_PRESENT | PF_ERR_USER | PF_ERR_INSTR)
    );
    assert_eq!(nx_f.rip, pf_va);
}

#[test]
fn idt_vector_de_delivers_frame_rsp0_ist_and_iretq_resume() {
    let mut rig = IdtTestRig::new();

    // 1. CPL3 `DIV ECX` by zero -> RSP0 (aligned from +0xff8 to +0xff0), 40-byte frame, no error code.
    rig.write_user_code(&[0x31, 0xd2, 0x31, 0xc9, 0xb8, 1, 0, 0, 0, 0xf7, 0xf1]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 0);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc8);
    assert_eq!(
        rig.read_frame40(rig.rsp0_frame, 0xfc8),
        Frame40 {
            rip: USER_CODE_VA + 9,
            cs: 0x2b,
            rflags: RFLAGS_IF | (1 << 6) | (1 << 2) | 0x2,
            rsp: USER_STACK_VA + 0xff0,
            ss: 0x23,
        }
    );

    // 2. CPL0 `IDIV` overflow (`i64::MIN / -1`) with IST=1 -> IST1 stack, handler sets RCX=1 and IRETQs!
    // Handler 0: `mov ecx, 1; iretq` (`b9 01 00 00 00 48 cf`) -> re-executes `idiv rcx` cleanly (`i64::MIN / 1`)!
    rig.write_handler(0, &[0xb9, 1, 0, 0, 0, 0x48, 0xcf]);
    rig.set_gate(0, IdtTestRig::stub_va(0), 0x08, 1, 0x0e, 0, true);
    // `cqo; idiv rcx; hlt` = `48 99 48 f7 f9 f4`
    rig.write_kernel_code(&[0x48, 0x99, 0x48, 0xf7, 0xf9, 0xf4]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = i64::MIN as u64;
    rig.machine.context_mut().gpr[reg::RCX] = (-1i64) as u64;
    // Step 1: `cqo; idiv rcx` faults on `idiv rcx` (at CODE_VA + 2) -> enters IST1 handler.
    assert_eq!(rig.machine.step().unwrap(), None);
    assert_eq!(rig.machine.context().rip, IdtTestRig::stub_va(0));
    assert_eq!(rig.machine.context().gpr[reg::RSP], IST1_VA + 0xfc8);
    assert_eq!(rig.read_frame40(rig.ist1_frame, 0xfc8).rip, CODE_VA + 2);
    // Resume through handler IRETQ -> `idiv rcx` succeeds -> HLT!
    assert_eq!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA + 5,
            next_rip: CODE_VA + 6,
        }
    );
    assert_eq!(rig.machine.context().gpr[reg::RAX], i64::MIN as u64);
    assert_eq!(rig.machine.context().gpr[reg::RDX], 0);
}

#[test]
fn idt_vector_db_delivers_tf_dr0_rf_and_icebp_through_idt() {
    let mut rig = IdtTestRig::new();

    // 1. TF=1 single-step at CPL3: retires `inc ebx` (`ff c3`) then delivers #DB (vector 1, 40-byte frame on RSP0)
    // with DR6.BS=1, DR7.GD=0, live TF=0, and stacked TF=1.
    rig.machine.context_mut().dr[7] = 0x0000_2400; // GD=1
    rig.write_user_code(&[0xff, 0xc3, 0x90]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_TF);
    rig.machine.context_mut().gpr[reg::RBX] = 41;
    assert_eq!(rig.run_to_vec_port(), 1);
    {
        let ctx = rig.machine.context();
        assert_eq!(ctx.gpr[reg::RBX], 42);
        assert_eq!(ctx.gpr[reg::RSP], RSP0_VA + 0xfc8);
        assert_eq!(ctx.dr[6] & (1 << 14), 1 << 14);
        assert_eq!(ctx.dr[7] & (1 << 13), 0);
        assert_eq!(ctx.rflags & RFLAGS_TF, 0);
    }
    let tf_frame = rig.read_frame40(rig.rsp0_frame, 0xfc8);
    assert_eq!(tf_frame.rip, USER_CODE_VA + 2);
    assert_eq!(tf_frame.rflags & RFLAGS_TF, RFLAGS_TF);

    // 2. SDM Vol. 3A §18.3.1.4: POPFQ clearing TF (1 -> 0) is itself single-stepped (since TF was 1 at
    // instruction start), pushing TF=0 in stacked RFLAGS, and subsequent instructions do NOT trap!
    // Handler 1: `inc r12; iretq` (`49 ff c4 48 cf`) on IST=1.
    rig.write_handler(1, &[0x49, 0xff, 0xc4, 0x48, 0xcf]);
    rig.set_gate(1, IdtTestRig::stub_va(1), 0x08, 1, 0x0e, 0, true);
    // Kernel stack holds 0x202 (TF=0, IF=1); code: `popfq; nop; hlt` (`9d 90 f4`).
    rig.machine
        .mem_mut()
        .write_gpa(rig.stack_frame.raw() + 0xff0, &0x202u64.to_le_bytes());
    rig.write_kernel_code(&[0x9d, 0x90, 0xf4]);
    rig.enter_cpl0_rsp(CODE_VA, STACK_VA + 0xff0, RFLAGS_IF | RFLAGS_TF);
    rig.machine.context_mut().gpr[reg::R12] = 0;
    assert_eq!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA + 2,
            next_rip: CODE_VA + 3,
        }
    );
    // Fired once after POPFQ (`CODE_VA + 1`), and zero times on `nop`!
    assert_eq!(rig.machine.context().gpr[reg::R12], 1);
    assert_eq!(rig.read_frame40(rig.ist1_frame, 0xfc8).rip, CODE_VA + 1);
    assert_eq!(
        rig.read_frame40(rig.ist1_frame, 0xfc8).rflags & RFLAGS_TF,
        0
    );

    // 3. DR0 hardware execution breakpoint (pre-fetch fault) + RFLAGS.RF suppression on IRETQ:
    // Handler 1 sets `RF=1` (`1 << 16`) in stacked RFLAGS (`[rsp + 16]`), increments R12, and IRETQs:
    // `49 ff c4` (`inc r12`), `48 81 4c 24 10 00 00 01 00` (`or qword ptr [rsp+16], 0x10000`), `48 cf` (`iretq`) = 14 bytes!
    rig.write_handler(
        1,
        &[
            0x49, 0xff, 0xc4, 0x48, 0x81, 0x4c, 0x24, 0x10, 0x00, 0x00, 0x01, 0x00, 0x48, 0xcf,
        ],
    );
    // Code: `inc eax; hlt` (`ff c0 f4`) with DR0 = CODE_VA, DR7 = G0 (0x2).
    rig.write_kernel_code(&[0xff, 0xc0, 0xf4]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = 10;
    rig.machine.context_mut().gpr[reg::R12] = 0;
    rig.machine.context_mut().dr[0] = CODE_VA;
    rig.machine.context_mut().dr[6] = 0xffff_0ff0;
    rig.machine.context_mut().dr[7] = 0x0000_0402;
    assert_eq!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA + 2,
            next_rip: CODE_VA + 3,
        }
    );
    // DR0 fired once before `inc eax` (DR6.B0=1), handler set RF=1 & IRETQ'd, `inc eax` ran once and cleared RF!
    assert_eq!(rig.machine.context().gpr[reg::R12], 1);
    assert_eq!(rig.machine.context().gpr[reg::RAX], 11);
    assert_eq!(rig.machine.context().dr[6] & 0xf, 0x1);
    assert_eq!(rig.machine.context().rflags & RFLAGS_RF, 0);
    rig.machine.context_mut().dr[7] = 0x0000_0400;

    // 4. ICEBP / INT1 (`0xF1`) at CPL3: bypasses gate DPL=0, sets DR6.BS=1, saves RIP = va + 1,
    // and sets EXT=0 if gate is not present!
    rig.write_handler(1, &[0xb0, 1, 0xe6, 0xe0, 0xf4]);
    rig.set_gate(1, IdtTestRig::stub_va(1), 0x08, 0, 0x0e, 0, true);
    rig.write_user_code(&[0xf1]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 1);
    assert_eq!(
        rig.read_frame40(rig.rsp0_frame, 0xfc8).rip,
        USER_CODE_VA + 1
    );
    assert_eq!(rig.machine.context().dr[6] & (1 << 14), 1 << 14);

    // With gate 1 P=0, ICEBP raises #NP with EXT=0 (`(1 << 3) | 0x2`, NOT `| 0x1`) and RIP = USER_CODE_VA!
    rig.set_gate(1, IdtTestRig::stub_va(1), 0x08, 0, 0x0e, 0, false);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 11);
    let icebp_np = rig.read_frame48(rig.rsp0_frame, 0xfc0);
    assert_eq!(icebp_np.error_code, (1u64 << 3) | 0x2);
    assert_eq!(icebp_np.rip, USER_CODE_VA);
}

#[test]
fn idt_vector_ud_delivers_frame_rsp0_ist_and_iretq_resume() {
    let mut rig = IdtTestRig::new();

    // 1. CPL3 `UD2` (`0f 0b`) -> RSP0 40-byte frame (no error code), RIP = USER_CODE_VA.
    rig.write_user_code(&[0x0f, 0x0b]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 6);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc8);
    assert_eq!(
        rig.read_frame40(rig.rsp0_frame, 0xfc8),
        Frame40 {
            rip: USER_CODE_VA,
            cs: 0x2b,
            rflags: RFLAGS_IF | 0x2,
            rsp: USER_STACK_VA + 0xff0,
            ss: 0x23,
        }
    );

    // 2. CPL0 `LOCK NOP` (`f0 90`) on IST=2 -> handler advances stacked RIP by 2 (`add qword ptr [rsp], 2; iretq`) and resumes!
    rig.write_handler(6, &[0x48, 0x83, 0x04, 0x24, 0x02, 0x48, 0xcf]);
    rig.set_gate(6, IdtTestRig::stub_va(6), 0x08, 2, 0x0e, 0, true);
    rig.write_kernel_code(&[0xf0, 0x90, 0xb8, 0x77, 0, 0, 0, 0xf4]); // lock nop; mov eax, 0x77; hlt
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    assert_eq!(rig.machine.step().unwrap(), None);
    assert_eq!(rig.machine.context().gpr[reg::RSP], IST2_VA + 0xfc8);
    assert_eq!(rig.read_frame40(rig.ist2_frame, 0xfc8).rip, CODE_VA);
    assert_eq!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA + 7,
            next_rip: CODE_VA + 8,
        }
    );
    assert_eq!(rig.machine.context().gpr[reg::RAX], 0x77);
}

#[test]
fn idt_vector_gp_delivers_zero_and_selector_error_codes_rsp0_and_ist() {
    let mut rig = IdtTestRig::new();

    // 1. CPL3 privileged instruction (`cli`, `fa`) -> RSP0 48-byte frame with error_code == 0.
    rig.write_user_code(&[0xfa]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc0);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0),
        Frame48 {
            error_code: 0,
            rip: USER_CODE_VA,
            cs: 0x2b,
            rflags: RFLAGS_IF | 0x2,
            rsp: USER_STACK_VA + 0xff0,
            ss: 0x23,
        }
    );

    // 2. CPL3 unaligned 128-bit `movaps xmm0, [rax]` (`0f 28 00`) -> #GP(0) on RSP0.
    rig.write_user_code(&[0x0f, 0x28, 0x00]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = USER_DATA_VA + 8;
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(rig.read_frame48(rig.rsp0_frame, 0xfc0).error_code, 0);

    // 3. CPL0 `ltr ax` (`0f 00 d8`) with code-segment selector 0x08 on IST=1 -> #GP(0x08) 48-byte frame on IST1!
    rig.set_gate(13, IdtTestRig::stub_va(13), 0x08, 1, 0x0e, 0, true);
    rig.write_kernel_code(&[0x0f, 0x00, 0xd8]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = 0x08;
    assert_eq!(rig.run_to_vec_port(), 13);
    assert_eq!(rig.machine.context().gpr[reg::RSP], IST1_VA + 0xfc0);
    let ltr_gp = rig.read_frame48(rig.ist1_frame, 0xfc0);
    assert_eq!(ltr_gp.error_code, 0x08);
    assert_eq!(ltr_gp.rip, CODE_VA);
}

#[test]
fn idt_vector_pf_delivers_cr2_all_five_error_bits_rsp0_ist_and_pte_fixup() {
    let mut rig = IdtTestRig::new();
    let fault_page = 0x0000_0000_00a0_0000u64;
    let backing = rig.machine.mem_mut().map_page(fault_page, Perms::USER_RO);
    rig.machine.mem_mut().write_gpa(
        backing.raw() + 0x28,
        &0x1122_3344_5566_7788u64.to_le_bytes(),
    );

    // 1. CPL3 write to read-only user page -> #PF on RSP0 (48-byte frame), then IST=1 check:
    rig.write_user_code(&[0x48, 0xc7, 0x00, 0xaa, 0xbb, 0x00, 0x00]); // mov qword ptr [rax], 0xbbaa
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = fault_page + 0x28;
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, fault_page + 0x28);
    assert_eq!(rig.machine.context().gpr[reg::RSP], RSP0_VA + 0xfc0);
    assert_eq!(
        rig.read_frame48(rig.rsp0_frame, 0xfc0),
        Frame48 {
            error_code: u64::from(PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER),
            rip: USER_CODE_VA,
            cs: 0x2b,
            rflags: RFLAGS_IF | 0x2,
            rsp: USER_STACK_VA + 0xff0,
            ss: 0x23,
        }
    );

    // 2. Real in-guest CPL0 #PF recovery on IST=1:
    // Map `pte_alias_va` in kernel space pointing at the PT page holding `fault_page`'s leaf PTE!
    let pte_slot_gpa = rig.machine.mem_mut().leaf_slot_gpa(fault_page);
    let pt_frame = FrameGpa::new(pte_slot_gpa & PTE_ADDR_MASK);
    let pte_alias_va = 0xffff_8000_0050_0000u64;
    rig.machine
        .mem_mut()
        .map_frame(pte_alias_va, pt_frame, Perms::KERNEL_RW);
    let pte_va = pte_alias_va + (pte_slot_gpa & SOFT_TLB_OFFSET_MASK);

    // Write #PF handler at CODE_VA + 0x200:
    // `or qword ptr [r13 + 0], 2` -> `49 83 4d 00 02` (sets PTE_WRITABLE)
    // `mov r14, cr2`              -> `49 0f 20 d6`
    // `invlpg [r14]`              -> `41 0f 01 3e`
    // `add rsp, 8`                -> `48 83 c4 08` (pop #PF error code!)
    // `iretq`                     -> `48 cf`
    let fixup_handler = [
        0x49, 0x83, 0x4d, 0x00, 0x02, 0x49, 0x0f, 0x20, 0xd6, 0x41, 0x0f, 0x01, 0x3e, 0x48, 0x83,
        0xc4, 0x08, 0x48, 0xcf,
    ];
    let handler_va = CODE_VA + 0x200;
    let code_gpa = rig.translate_kernel_page_gpa(CODE_VA);
    rig.machine
        .mem_mut()
        .write_gpa(code_gpa + 0x200, &fixup_handler);
    rig.set_gate(14, handler_va, 0x08, 1, 0x0e, 0, true);

    // User code: `mov qword ptr [rax], 0x5a5a; int 0x80` (with 0x80 DPL=3 halting stub).
    rig.set_gate(0x80, IdtTestRig::stub_va(0x80), 0x08, 0, 0x0e, 3, true);
    rig.write_user_code(&[0x48, 0xc7, 0x00, 0x5a, 0x5a, 0x00, 0x00, 0xcd, 0x80]);
    // Warm read TLB first so `invlpg` must evict the stale RO entry!
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    {
        let (mut cpu, mut mem) = rig.machine.into_parts();
        let _ = translate_va(
            cpu.context_mut(),
            &mut mem,
            fault_page + 0x28,
            SoftAccessKind::Read,
        )
        .unwrap();
        rig.machine = SoftMachine::from_parts(cpu, mem);
    }
    rig.machine.context_mut().reset_tlb_stats();
    rig.machine.context_mut().gpr[reg::RAX] = fault_page + 0x28;
    rig.machine.context_mut().gpr[reg::R13] = pte_va;

    assert_eq!(rig.run_to_vec_port(), 0x80);
    // Structural budget witness: zero full flushes, exactly 1 targeted `invlpg` eviction!
    let stats = rig.machine.context().tlb_stats();
    assert_eq!(stats.full_flushes, 0);
    assert_eq!(stats.va_evictions, 1);
    assert_eq!(rig.machine.mem().read_u64(backing.raw() + 0x28), 0x5a5a);
    assert_eq!(rig.machine.context().gpr[reg::R14], fault_page + 0x28);
}

#[test]
fn idt_vector_ac_delivers_zero_error_code_clears_ac_and_exempts_movups() {
    let mut rig = IdtTestRig::new();
    rig.machine.context_mut().cr0 |= CR0_AM;
    rig.machine.context_mut().set_smap_enabled(true);

    // 1. Legacy 128-bit unaligned `movups xmm0, [rax]` (`0f 10 00`) at CPL3 with CR0.AM=1, RFLAGS.AC=1
    // does NOT raise #AC; subsequent unaligned 8-byte `mov rcx, [rax]` (`48 8b 08`) DOES raise #AC(0)!
    rig.write_user_code(&[0x0f, 0x10, 0x00, 0x48, 0x8b, 0x08]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF | RFLAGS_AC);
    rig.machine.context_mut().gpr[reg::RAX] = USER_DATA_VA + 3;
    assert_eq!(rig.run_to_vec_port(), 17);
    {
        let ctx = rig.machine.context();
        // Gate entry clears live RFLAGS.AC (preventing leaked SMAP bypass in CPL0)!
        assert_eq!(ctx.rflags & RFLAGS_AC, 0);
        assert!(!ctx.ac());
        assert_eq!(ctx.gpr[reg::RSP], RSP0_VA + 0xfc0);
    }
    let ac_rsp0 = rig.read_frame48(rig.rsp0_frame, 0xfc0);
    assert_eq!(ac_rsp0.error_code, 0);
    assert_eq!(ac_rsp0.rip, USER_CODE_VA + 3); // faulted on `mov rcx, [rax]`, NOT `movups`!
    assert_eq!(ac_rsp0.rflags & RFLAGS_AC, RFLAGS_AC); // stacked RFLAGS preserves user AC=1

    // 2. #AC with IST=2 selects IST2 stack and pushes 48-byte frame with error_code == 0.
    rig.set_gate(17, IdtTestRig::stub_va(17), 0x08, 2, 0x0e, 0, true);
    rig.enter_cpl3(USER_CODE_VA + 3, RFLAGS_IF | RFLAGS_AC);
    rig.machine.context_mut().gpr[reg::RAX] = USER_DATA_VA + 1;
    assert_eq!(rig.run_to_vec_port(), 17);
    assert_eq!(rig.machine.context().gpr[reg::RSP], IST2_VA + 0xfc0);
    assert_eq!(rig.read_frame48(rig.ist2_frame, 0xfc0).error_code, 0);
}

#[test]
fn idt_pf_then_pf_escalates_to_double_fault_and_table_6_5_classes() {
    let mut rig = IdtTestRig::new();
    // Put #DF (vector 8) on IST=1 so it always has a valid dedicated stack!
    rig.set_gate(8, IdtTestRig::stub_va(8), 0x08, 1, 0x0e, 0, true);

    let fault_va1 = 0x0000_0000_00b0_0000u64;

    // 1a. #PF-then-#PF -> #DF(0) via unmapped #PF handler stack (`RSP0` unmapped when CPL3 #PF occurs):
    rig.machine.mem_mut().unmap_page(RSP0_VA);
    rig.machine.context_mut().flush_tlb();
    rig.write_user_code(&[0x48, 0x8b, 0x00]); // mov rax, [rax]
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = fault_va1 + 0x44;
    assert_eq!(rig.run_to_vec_port(), 8);
    {
        let ctx = rig.machine.context();
        assert_eq!(ctx.gpr[reg::RSP], IST1_VA + 0xfc0); // 48-byte #DF frame on IST1
        // Secondary #PF occurred while pushing the 48-byte #PF frame onto RSP0_VA + 0xfc0 -> CR2 updated!
        assert_eq!(ctx.cr2, RSP0_VA + 0xfc0);
    }
    assert_eq!(
        rig.read_frame48(rig.ist1_frame, 0xfc0),
        Frame48 {
            error_code: 0, // #DF always pushes error code 0
            rip: USER_CODE_VA,
            cs: 0x2b,
            rflags: RFLAGS_IF | 0x2,
            rsp: USER_STACK_VA + 0xff0,
            ss: 0x23,
        }
    );
    // Restore RSP0 mapping.
    rig.machine
        .mem_mut()
        .map_frame(RSP0_VA, rig.rsp0_frame, Perms::KERNEL_RW);
    rig.machine.context_mut().flush_tlb();

    // 1b. #PF-then-#PF -> #DF(0) via second page of IDT unmapped for vector 14:
    // Place IDTR.base at `IDT_SPLIT_VA - 14 * 16` where `IDT_SPLIT_VA - 0x1000` is mapped (holds vector 8 #DF!)
    // and `IDT_SPLIT_VA` is unmapped (holds vector 14 #PF!).
    let idt_low_va = 0xffff_8000_0045_0000u64;
    let idt_high_va = idt_low_va + SOFT_TLB_PAGE_SIZE;
    let idt_low_frame = rig.machine.mem_mut().map_page(idt_low_va, Perms::KERNEL_RW);
    rig.machine.mem_mut().unmap_page(idt_high_va);
    let split_idtr_base = idt_high_va - 14 * 16;
    let df_gate = encode_idt_gate(IdtTestRig::stub_va(8), 0x08, 1, 0x0e, 0, true);
    rig.machine.mem_mut().write_gpa(
        idt_low_frame.raw() + (split_idtr_base + 8 * 16 - idt_low_va),
        &df_gate,
    );
    rig.machine.context_mut().idtr = DescriptorTablePtr::new(0xfff, split_idtr_base);
    rig.machine.context_mut().flush_tlb();

    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = fault_va1;
    assert_eq!(rig.run_to_vec_port(), 8);
    assert_eq!(rig.machine.context().cr2, idt_high_va);
    assert_eq!(rig.read_frame48(rig.ist1_frame, 0xfc0).error_code, 0);

    // Restore standard IDT.
    rig.machine.context_mut().idtr = DescriptorTablePtr::new(0xfff, IDT_VA);
    rig.machine.context_mut().flush_tlb();

    // 2. #PF + Contributory (#NP on vector 14 gate) -> #DF(0), preserving first #PF's CR2!
    rig.set_gate(14, IdtTestRig::stub_va(14), 0x08, 0, 0x0e, 0, false);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = fault_va1 + 0x99;
    assert_eq!(rig.run_to_vec_port(), 8);
    assert_eq!(rig.machine.context().cr2, fault_va1 + 0x99);
    assert_eq!(rig.read_frame48(rig.ist1_frame, 0xfc0).error_code, 0);
    rig.set_gate(14, IdtTestRig::stub_va(14), 0x08, 0, 0x0e, 0, true);

    // 3. Contributory (#DE) + Contributory (#NP on vector 0 gate) -> #DF(0).
    rig.set_gate(0, IdtTestRig::stub_va(0), 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0x31, 0xd2, 0x31, 0xc9, 0xf7, 0xf1]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 8);
    assert_eq!(rig.read_frame48(rig.ist1_frame, 0xfc0).error_code, 0);
    rig.set_gate(0, IdtTestRig::stub_va(0), 0x08, 0, 0x0e, 0, true);

    // 4. Contributory (#DE on unmapped IST2) + #PF -> Table 6-5 delivers #PF serially (NOT #DF)!
    rig.machine.mem_mut().unmap_page(IST2_VA);
    rig.machine.context_mut().flush_tlb();
    rig.set_gate(0, IdtTestRig::stub_va(0), 0x08, 2, 0x0e, 0, true);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 14);
    assert_eq!(rig.machine.context().cr2, IST2_VA + 0xfc8);
    rig.machine
        .mem_mut()
        .map_frame(IST2_VA, rig.ist2_frame, Perms::KERNEL_RW);
    rig.set_gate(0, IdtTestRig::stub_va(0), 0x08, 0, 0x0e, 0, true);

    // 5. Benign (#UD) + Contributory (#NP on vector 6 gate) -> delivers #NP serially (NOT #DF)!
    rig.set_gate(6, IdtTestRig::stub_va(6), 0x08, 0, 0x0e, 0, false);
    rig.write_user_code(&[0x0f, 0x0b]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    assert_eq!(rig.run_to_vec_port(), 11);
    rig.set_gate(6, IdtTestRig::stub_va(6), 0x08, 0, 0x0e, 0, true);

    // 6. #DF + any secondary fault (#NP on vector 8 gate) -> SoftMachineExit::TripleFault!
    rig.set_gate(14, IdtTestRig::stub_va(14), 0x08, 0, 0x0e, 0, false); // #PF -> #NP -> #DF
    rig.set_gate(8, IdtTestRig::stub_va(8), 0x08, 1, 0x0e, 0, false); // #DF -> #NP -> TripleFault
    rig.write_user_code(&[0x48, 0x8b, 0x00]);
    rig.enter_cpl3(USER_CODE_VA, RFLAGS_IF);
    rig.machine.context_mut().gpr[reg::RAX] = fault_va1;
    assert_eq!(
        rig.machine.run(16).unwrap(),
        SoftMachineExit::TripleFault {
            last_exception: X86Exception::segment_not_present(USER_CODE_VA, (8 << 3) | 0x2 | 0x1),
        }
    );
}

#[test]
fn native_block_transitions_keep_guest_system_rflags_context_owned() {
    // A CPL3 host `POPF` can never load IOPL (and Rosetta also drops NT), so guest IOPL/NT must
    // survive native-body gateway transitions from the context, not from host flags.
    let mut rig = IdtTestRig::new();
    rig.set_gate(0x81, IdtTestRig::stub_va(0x81), 0x08, 0, 0x0f, 0, true);
    // add eax, 1 (native body); pushfq; pop rbx (emulated helpers); int 0x81.
    rig.write_kernel_code(&[0x05, 0x01, 0x00, 0x00, 0x00, 0x9c, 0x5b, 0xcd, 0x81]);
    rig.enter_cpl0(CODE_VA, RFLAGS_IF | RFLAGS_NT | (3 << 12));
    rig.machine.context_mut().gpr[reg::RAX] = 0xffff_ffff;
    assert_eq!(rig.run_to_vec_port(), 0x81);
    let ctx = rig.machine.context();
    // `add` result flags (ZF, CF) come from the native body; IOPL/NT/IF from the context.
    let pushed = ctx.gpr[reg::RBX];
    assert_eq!(
        pushed & (0x3000 | RFLAGS_NT | RFLAGS_IF),
        0x3000 | RFLAGS_NT | RFLAGS_IF
    );
    assert_eq!(pushed & 0x41, 0x41);
    let frame = rig.read_frame40(rig.stack_frame, 0xfc8);
    assert_eq!(frame.rip, CODE_VA + 9);
    assert_eq!(frame.rflags & (0x3000 | RFLAGS_NT), 0x3000 | RFLAGS_NT);
    // Trap-gate entry clears live NT but keeps IOPL and IF.
    assert_eq!(
        ctx.rflags & (0x3000 | RFLAGS_NT | RFLAGS_IF),
        0x3000 | RFLAGS_IF
    );
}
