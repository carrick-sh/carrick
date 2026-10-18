//! Comprehensive Level 0 test suite for `carrick-softcpu-x86`.

#![cfg(target_arch = "x86_64")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_softcpu_x86::{
    ExtentRecord, ExtentTable, FrameGpa, JitCodeBuffer, LinearPlacement, MmioHoles,
    OwnerGeneration, PF_ERR_USER, PF_ERR_WRITE, RootGpa, SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK,
    SOFT_TLB_PAGE_SIZE, SensitiveOp, SoftCpu, SoftCpuExit, SoftMmuMemory, X86Exception,
    X86ExceptionVector, reg,
};

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_RSVD: u64 = 1 << 51;
const PTE_NX: u64 = 1 << 63;
const PTE_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PagePerms(u8);

impl PagePerms {
    const fn new(r: bool, w: bool, x: bool, u: bool) -> Self {
        Self((r as u8) | ((w as u8) << 1) | ((x as u8) << 2) | ((u as u8) << 3))
    }
    const USER_RW: Self = Self::new(true, true, false, true);
    const USER_RX: Self = Self::new(true, false, true, true);
    const KERNEL_RX: Self = Self::new(true, false, true, false);
}

/// Test-only 4-level x86_64 page-table fixture implementing [`SoftMmuMemory`].
struct TestSoftMmuMemory {
    _backing: Vec<AtomicU64>,
    placement: LinearPlacement,
    extents: ExtentTable,
    next_frame_gpa: u64,
    va_to_frame: BTreeMap<u64, FrameGpa>,
}

impl TestSoftMmuMemory {
    const POOL_BYTES: u64 = 16 * 1024 * 1024;
    const GEN: OwnerGeneration = OwnerGeneration::new(1);

    fn root() -> RootGpa {
        RootGpa::page_aligned(FrameGpa::new(0)).expect("aligned root")
    }

    fn new() -> Self {
        let words = ((Self::POOL_BYTES + SOFT_TLB_PAGE_SIZE) as usize) / 8;
        let mut backing = Vec::with_capacity(words);
        backing.resize_with(words, || AtomicU64::new(0));
        let aligned = (backing.as_ptr() as usize + (SOFT_TLB_OFFSET_MASK as usize))
            & !(SOFT_TLB_OFFSET_MASK as usize);
        let placement = LinearPlacement::new(aligned, Self::POOL_BYTES, MmioHoles::empty())
            .expect("valid placement");
        let mut extents = ExtentTable::new();
        let rec = ExtentRecord::new(FrameGpa::new(0), Self::POOL_BYTES, Self::GEN);
        assert!(extents.install(rec));
        extents.set_root_generation(Self::root(), Self::GEN);
        Self {
            _backing: backing,
            placement,
            extents,
            next_frame_gpa: SOFT_TLB_PAGE_SIZE,
            va_to_frame: BTreeMap::new(),
        }
    }

    fn alloc_frame(&mut self) -> FrameGpa {
        let gpa = self.next_frame_gpa;
        self.next_frame_gpa = self.next_frame_gpa.wrapping_add(SOFT_TLB_PAGE_SIZE);
        assert!(self.next_frame_gpa <= Self::POOL_BYTES, "test pool OOM");
        FrameGpa::new(gpa)
    }

    fn word_ref(&self, gpa: u64) -> &AtomicU64 {
        let addr = self.placement.base_host_addr() + (gpa as usize);
        // SAFETY: `gpa` is 8-byte aligned and within `[0, POOL_BYTES)`.
        unsafe { &*(addr as *const AtomicU64) }
    }

    fn ensure_table_child(&mut self, table_gpa: u64, index: usize) -> u64 {
        let slot_gpa = table_gpa + (index as u64) * 8;
        let cur = self.word_ref(slot_gpa).load(Ordering::Relaxed);
        if (cur & PTE_PRESENT) != 0 {
            return cur & PTE_ADDR_MASK;
        }
        let child = self.alloc_frame().raw();
        let entry = child | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        self.word_ref(slot_gpa).store(entry, Ordering::Relaxed);
        child
    }

    fn leaf_pte(frame_gpa: FrameGpa, p: PagePerms) -> u64 {
        if (p.0 & 1) == 0 {
            return 0;
        }
        let mut pte = (frame_gpa.raw() & PTE_ADDR_MASK) | PTE_PRESENT;
        if (p.0 & 2) != 0 {
            pte |= PTE_WRITABLE;
        }
        if (p.0 & 8) != 0 {
            pte |= PTE_USER;
        }
        if (p.0 & 16) != 0 {
            pte |= PTE_RSVD;
        }
        if (p.0 & 4) == 0 {
            pte |= PTE_NX;
        }
        pte
    }

    fn install_leaf_pte(&mut self, va: u64, frame_gpa: FrameGpa, perms: PagePerms) {
        let va_page = va & SOFT_TLB_PAGE_MASK;
        let mut tbl = Self::root().address().raw();
        for shift in [39, 30, 21] {
            tbl = self.ensure_table_child(tbl, ((va_page >> shift) & 0x1ff) as usize);
        }
        let pte_gpa = tbl + ((va_page >> 12) & 0x1ff) * 8;
        self.word_ref(pte_gpa)
            .store(Self::leaf_pte(frame_gpa, perms), Ordering::Relaxed);
        self.va_to_frame.insert(va_page, frame_gpa);
    }

    fn frame_for_va(&self, va: u64) -> Option<FrameGpa> {
        self.va_to_frame.get(&(va & SOFT_TLB_PAGE_MASK)).copied()
    }

    fn map_range(&mut self, va_start: u64, len: usize, perms: PagePerms) {
        let mut page = va_start & SOFT_TLB_PAGE_MASK;
        let end = (va_start + len as u64 + SOFT_TLB_OFFSET_MASK) & SOFT_TLB_PAGE_MASK;
        while len > 0 && page < end {
            let f = self
                .va_to_frame
                .get(&page)
                .copied()
                .unwrap_or_else(|| self.alloc_frame());
            self.install_leaf_pte(page, f, perms);
            page = page.wrapping_add(SOFT_TLB_PAGE_SIZE);
        }
    }

    fn set_page_perms(&mut self, va: u64, perms: PagePerms) -> bool {
        let Some(frame_gpa) = self.frame_for_va(va) else {
            return false;
        };
        self.install_leaf_pte(va, frame_gpa, perms);
        true
    }

    fn host_byte_ptr(&self, va: u64) -> Option<*mut u8> {
        let frame_gpa = self.frame_for_va(va)?;
        let off = (frame_gpa.raw() as usize) + ((va & 0xfff) as usize);
        Some((self.placement.base_host_addr() + off) as *mut u8)
    }

    fn write_direct(&mut self, va: u64, data: &[u8]) -> bool {
        for (i, &b) in data.iter().enumerate() {
            let Some(dst) = self.host_byte_ptr(va.wrapping_add(i as u64)) else {
                return false;
            };
            // SAFETY: `dst` lies within `_backing`.
            unsafe { *dst = b };
        }
        true
    }

    fn read_direct(&self, va: u64, len: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let src = self.host_byte_ptr(va.wrapping_add(i as u64))?.cast_const();
            // SAFETY: `src` lies within `_backing`.
            out.push(unsafe { *src });
        }
        Some(out)
    }
}

impl SoftMmuMemory for TestSoftMmuMemory {
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

const fn pf(rip: u64, err: u32, cr2: u64) -> SoftCpuExit {
    SoftCpuExit::Exception(X86Exception::page_fault(rip, err, cr2))
}
const fn gp(rip: u64) -> SoftCpuExit {
    SoftCpuExit::Exception(X86Exception::general_protection(rip, 0))
}
const fn de(rip: u64) -> SoftCpuExit {
    SoftCpuExit::Exception(X86Exception::divide_error(rip))
}
const fn ud(rip: u64) -> SoftCpuExit {
    SoftCpuExit::Exception(X86Exception::invalid_opcode(rip))
}
const fn sys(rip: u64, next_rip: u64) -> SoftCpuExit {
    SoftCpuExit::Syscall { rip, next_rip }
}

fn setup_snippet(code: &[u8]) -> (SoftCpu, TestSoftMmuMemory, u64) {
    let (code_va, stack_va) = (0x0040_0000u64, 0x0080_0000u64);
    let mut mem = TestSoftMmuMemory::new();
    mem.map_range(code_va, 4096, PagePerms::USER_RX);
    mem.write_direct(code_va, code);
    mem.map_range(stack_va, 8192, PagePerms::USER_RW);
    let mut cpu = SoftCpu::new().expect("SoftCpu");
    cpu.ctx.rip = code_va;
    cpu.ctx.gpr[reg::RSP] = stack_va + 4096;
    (cpu, mem, code_va)
}

fn step_ok(cpu: &mut SoftCpu, mem: &mut TestSoftMmuMemory, exp: SoftCpuExit) {
    assert_eq!(cpu.step_block(mem).unwrap(), exp);
}

#[test]
fn invalid_opcode_witnesses_ud2_and_bad_encodings() {
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0xB8, 42, 0, 0, 0, 0x0F, 0x0B]);
    step_ok(&mut cpu, &mut mem, ud(code_va + 5));
    assert_eq!((cpu.ctx.gpr[reg::RAX], cpu.ctx.rip), (42, code_va + 5));
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x06]);
    step_ok(&mut cpu, &mut mem, ud(code_va));
}

#[test]
fn general_protection_witnesses_privileged_at_cpl3_and_sensitive_at_cpl0() {
    let cases: &[(&[u8], SensitiveOp)] = &[
        (&[0xFA], SensitiveOp::Cli),
        (&[0xFB], SensitiveOp::Sti),
        (&[0xF4], SensitiveOp::Hlt),
        (&[0x0F, 0x01, 0xF8], SensitiveOp::Swapgs),
        (&[0x48, 0xCF], SensitiveOp::Iretq),
        (&[0x48, 0x0F, 0x07], SensitiveOp::Sysret),
        (&[0x0F, 0x30], SensitiveOp::Wrmsr),
        (&[0x0F, 0x32], SensitiveOp::Rdmsr),
        (
            &[0x0F, 0x20, 0xD8],
            SensitiveOp::MovFromCr {
                cr: 3,
                gpr: reg::RAX,
            },
        ),
        (
            &[0x0F, 0x22, 0xD8],
            SensitiveOp::MovToCr {
                cr: 3,
                gpr: reg::RAX,
            },
        ),
        (&[0x0F, 0x01, 0xD1], SensitiveOp::Xsetbv),
        (&[0x0F, 0x01, 0xCA], SensitiveOp::Clac),
        (&[0x0F, 0x01, 0xCB], SensitiveOp::Stac),
        (
            &[0xE6, 0x80],
            SensitiveOp::OutImm {
                port: 0x80,
                size: 1,
            },
        ),
        (&[0xEE], SensitiveOp::OutDx { size: 1 }),
        (
            &[0xE4, 0x80],
            SensitiveOp::InImm {
                port: 0x80,
                size: 1,
            },
        ),
        (&[0xEC], SensitiveOp::InDx { size: 1 }),
        (&[0x0F, 0x01, 0x3F], SensitiveOp::Invlpg),
        (&[0x0F, 0x01, 0x17], SensitiveOp::Lgdt),
        (&[0x0F, 0x01, 0x1F], SensitiveOp::Lidt),
        (&[0x0F, 0x00, 0xD8], SensitiveOp::Ltr),
    ];

    for &(bytes, op) in cases {
        let (mut cpu, mut mem, code_va) = setup_snippet(bytes);
        step_ok(&mut cpu, &mut mem, gp(code_va));
        mem.set_page_perms(code_va, PagePerms::KERNEL_RX);
        cpu.ctx.set_cpl(0);
        cpu.ctx.tlb.flush_all();
        cpu.ctx.rip = code_va;
        let next_rip = code_va + bytes.len() as u64;
        step_ok(
            &mut cpu,
            &mut mem,
            SoftCpuExit::Sensitive {
                rip: code_va,
                next_rip,
                op,
            },
        );
    }
}

#[test]
fn general_protection_witnesses_non_canonical_and_unaligned_sse() {
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x48, 0x8B, 0x07, 0x0F, 0x05]);
    cpu.ctx.gpr[reg::RDI] = 0x0001_0000_0000_0000;
    step_ok(&mut cpu, &mut mem, gp(code_va));

    cpu.ctx.rip = 0x0002_0000_0000_0000;
    step_ok(&mut cpu, &mut mem, gp(0x0002_0000_0000_0000));

    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x0F, 0x28, 0x07, 0x0F, 0x05]);
    let data_va = 0x0090_0000u64;
    mem.map_range(data_va, 4096, PagePerms::USER_RW);
    mem.write_direct(data_va + 4, &[0x11u8; 16]);
    cpu.ctx.gpr[reg::RDI] = data_va + 4;
    step_ok(&mut cpu, &mut mem, gp(code_va));

    mem.write_direct(code_va, &[0x0F, 0x10, 0x07, 0x0F, 0x05]);
    cpu.ctx.rip = code_va;
    step_ok(&mut cpu, &mut mem, sys(code_va + 3, code_va + 5));
    assert_eq!(cpu.ctx.read_xmm(0), u128::from_le_bytes([0x11u8; 16]));
}

#[test]
fn divide_error_witnesses_div_idiv_zero_overflow_and_fault_priority() {
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x48, 0xF7, 0xF1, 0x0F, 0x05]);
    cpu.ctx.gpr[reg::RAX] = 100;
    step_ok(&mut cpu, &mut mem, de(code_va));
    assert_eq!(
        X86Exception::divide_error(code_va).vector,
        X86ExceptionVector::DivideError
    );

    cpu.ctx.rip = code_va;
    (
        cpu.ctx.gpr[reg::RDX],
        cpu.ctx.gpr[reg::RAX],
        cpu.ctx.gpr[reg::RCX],
    ) = (1, 0, 1);
    step_ok(&mut cpu, &mut mem, de(code_va));

    mem.write_direct(code_va, &[0x48, 0xF7, 0xF9, 0x0F, 0x05]);
    cpu.ctx.rip = code_va;
    (
        cpu.ctx.gpr[reg::RAX],
        cpu.ctx.gpr[reg::RDX],
        cpu.ctx.gpr[reg::RCX],
    ) = (i64::MIN as u64, u64::MAX, (-1i64) as u64);
    step_ok(&mut cpu, &mut mem, de(code_va));

    cpu.ctx.rip = code_va;
    (
        cpu.ctx.gpr[reg::RAX],
        cpu.ctx.gpr[reg::RDX],
        cpu.ctx.gpr[reg::RCX],
    ) = ((-100i64) as u64, u64::MAX, 7);
    step_ok(&mut cpu, &mut mem, sys(code_va + 3, code_va + 5));
    assert_eq!(
        (cpu.ctx.gpr[reg::RAX] as i64, cpu.ctx.gpr[reg::RDX] as i64),
        (-14, -2)
    );

    mem.write_direct(code_va, &[0x48, 0xF7, 0x37, 0x0F, 0x05]);
    cpu.ctx.rip = code_va;
    cpu.ctx.gpr[reg::RDI] = 0x0000_5555_beef_0000;
    step_ok(
        &mut cpu,
        &mut mem,
        pf(code_va, PF_ERR_USER, 0x0000_5555_beef_0000),
    );
}

#[test]
fn implicit_masked_store_cannot_write_a_host_address() {
    let mut host_bytes = [0x55u8; 16];
    let (mut cpu, mut mem, va) = setup_snippet(&[0x66, 0x0f, 0xf7, 0xc1, 0x0f, 0x05]);
    cpu.ctx.gpr[reg::RDI] = host_bytes.as_mut_ptr() as u64;
    cpu.ctx.write_xmm(0, u128::MAX);
    cpu.ctx.write_xmm(1, u128::MAX);
    let result = cpu.step_block(&mut mem).unwrap();
    assert_eq!(host_bytes, [0x55; 16], "guest store escaped soft memory");
    assert_eq!(
        result,
        pf(va, PF_ERR_WRITE | PF_ERR_USER, cpu.ctx.gpr[reg::RDI])
    );
}

#[test]
fn ignored_legacy_segment_prefixes_execute_in_long_mode() {
    for prefix in [0x26, 0x2e, 0x36, 0x3e] {
        let (mut cpu, mut mem, va) = setup_snippet(&[prefix, 0x66, 0x90, 0x0f, 0x05]);
        step_ok(&mut cpu, &mut mem, sys(va + 3, va + 5));
    }
    let (mut cpu, mut mem, va) =
        setup_snippet(&[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0, 0x0f, 0x05]);
    step_ok(&mut cpu, &mut mem, sys(va + 10, va + 12));
    for marker in [0xfa, 0xfb] {
        let (mut cpu, mut mem, va) = setup_snippet(&[0xf3, 0x0f, 0x1e, marker, 0x0f, 0x05]);
        step_ok(&mut cpu, &mut mem, sys(va + 4, va + 6));
    }
    let (mut cpu, mut mem, va) = setup_snippet(&[0x3e, 0xff, 0xe0]);
    cpu.ctx.gpr[reg::RAX] = va + 3;
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Continue { next_rip: va + 3 },
    );
    let (mut cpu, mut mem, va) = setup_snippet(&[0x2e, 0x74, 0]);
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Continue { next_rip: va + 3 },
    );
}

#[test]
fn unsupported_ymm_state_is_neither_advertised_nor_executed() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0x0f, 0xa2]);
    cpu.ctx.gpr[reg::RAX] = 1;
    cpu.step_block(&mut mem).unwrap();
    assert_eq!(
        cpu.ctx.gpr[reg::RCX] & ((1 << 28) | (1 << 12) | (1 << 29)),
        0
    );
    assert_eq!(cpu.ctx.xcr0, 3);
    // A block end must never make unpreserved YMM upper halves observable.
    mem.write_direct(va, &[0xc5, 0xfc, 0x57, 0xc0, 0xeb, 0]); // vxorps ymm0,ymm0,ymm0
    cpu.ctx.rip = va;
    assert_eq!(cpu.step_block(&mut mem).unwrap(), ud(va));
}

#[test]
fn gateway_returns_with_host_df_and_fp_controls_restored() {
    // Capture DF in a native wrapper immediately after the translated exit,
    // then restore host DF/FP controls before Rust even on the broken gateway.
    use carrick_softcpu_x86::{
        context::softcpu_enter_translated, emit_block, plan_block_from_memory,
    };
    let (mut cpu, mut mem, va) = setup_snippet(&[0xfd, 0x0f, 0x05]); // std
    let planned = plan_block_from_memory(va, 64, 4096, &mut cpu.ctx, &mut mem).unwrap();
    let mut block_jit = JitCodeBuffer::new(4096).unwrap();
    cpu.ctx.entry_exec_addr = block_jit
        .publish(&emit_block(&planned).unwrap().code)
        .unwrap();
    cpu.ctx.fxsave.0[..2].copy_from_slice(&0x027fu16.to_le_bytes());
    cpu.ctx.fxsave.0[24..28].copy_from_slice(&0x5f80u32.to_le_bytes());
    let mut snapshots = [0u8; 16];
    let mut wrapper = vec![
        0x53, 0x48, 0x89, 0xf3, 0x0f, 0xae, 0x1b, 0xd9, 0x7b, 4, 0x48, 0xb8,
    ];
    wrapper
        .extend_from_slice(&(softcpu_enter_translated as *const () as usize as u64).to_le_bytes());
    wrapper.extend_from_slice(&[
        0xff, 0xd0, 0x9c, 0x58, 0xfc, 0x0f, 0xae, 0x5b, 8, 0xd9, 0x7b, 12, 0x0f, 0xae, 0x13, 0xd9,
        0x6b, 4, 0x5b, 0xc3,
    ]);
    let mut wrapper_jit = JitCodeBuffer::new(4096).unwrap();
    let entry = wrapper_jit.publish(&wrapper).unwrap();
    let run: unsafe extern "sysv64" fn(*mut carrick_softcpu_x86::SoftCpuContext, *mut u8) -> u64 =
        unsafe { std::mem::transmute(entry as usize) };
    let flags = unsafe { run(&mut *cpu.ctx, snapshots.as_mut_ptr()) };
    assert_eq!(
        &snapshots[..6],
        &snapshots[8..14],
        "guest MXCSR/FCW reached host ABI"
    );
    assert_eq!(flags & (1 << 10), 0, "guest DF reached the host ABI");
    assert_ne!(cpu.ctx.rflags & (1 << 10), 0, "guest DF was lost");
    assert_eq!(&cpu.ctx.fxsave.0[..2], &0x027fu16.to_le_bytes());
    assert_eq!(&cpu.ctx.fxsave.0[24..28], &0x5f80u32.to_le_bytes());
}

#[test]
fn complete_f3_instruction_at_page_end_does_not_fetch_next_page() {
    for bytes in [&[0xf3, 0x90][..], &[0xf3, 0xc3], &[0xf3, 0xa4]] {
        let (mut cpu, mut mem, va) = setup_snippet(&[]);
        let ip = va + 4096 - bytes.len() as u64;
        mem.write_direct(ip, bytes);
        let planned =
            carrick_softcpu_x86::plan_block_from_memory(ip, 1, 4096, &mut cpu.ctx, &mut mem);
        assert!(
            planned.is_ok(),
            "complete F3 encoding spuriously fetched: {bytes:x?}: {planned:?}"
        );
    }
}

#[test]
fn oversized_and_unknown_memory_images_never_enter_native_memory_path() {
    for bytes in [&[0xdd, 0x37][..], &[0xdd, 0x27], &[0xd9, 0x27]] {
        // fnsave/frstor/fldenv
        let decoded = carrick_softcpu_x86::classify(bytes, 0x400000).unwrap();
        assert_ne!(
            decoded.class,
            carrick_softcpu_x86::InsnClass::Body,
            "unbounded legacy state image admitted"
        );
        let (mut cpu, mut mem, va) = setup_snippet(bytes);
        step_ok(&mut cpu, &mut mem, ud(va));
    }
}

#[test]
fn crossing_conditional_write_preserves_untouched_bounce_bytes() {
    use carrick_softcpu_x86::context::{
        pack_slow_path_meta, softcpu_commit_bounce, softcpu_mem_slow_path, translate_for_mem,
    };
    let (mut cpu, mut mem, _) = setup_snippet(&[]);
    let addr = 0x2000_0ff8;
    mem.map_range(0x2000_0000, 8192, PagePerms::USER_RW);
    mem.write_direct(addr, &[0x55; 16]);
    cpu.ctx.bounce_buf.fill(0xcc);
    cpu.ctx.active_mem_ptr = Some(std::ptr::NonNull::from(&mut mem).cast());
    cpu.ctx.active_translate_fn = Some(translate_for_mem::<TestSoftMmuMemory>);
    let ptr = softcpu_mem_slow_path(&mut cpu.ctx, addr, pack_slow_path_meta(0, 16, 1, false));
    assert_ne!(ptr, 0);
    // Model a CondWrite instruction updating only selected lanes.
    cpu.ctx.bounce_buf[0] = 0xaa;
    cpu.ctx.bounce_buf[15] = 0xaa;
    softcpu_commit_bounce(&mut cpu.ctx);
    let mut expected = [0x55; 16];
    expected[0] = 0xaa;
    expected[15] = 0xaa;
    assert_eq!(mem.read_direct(addr, 16).unwrap(), expected);
    cpu.ctx.active_mem_ptr = None;
    cpu.ctx.active_translate_fn = None;
}

#[test]
fn native_admission_denies_unimplemented_host_features() {
    use carrick_softcpu_x86::{InsnClass, classify};
    let cases: &[&[u8]] = &[
        &[0x0f, 0xc7, 0x2f],                   // xsaves
        &[0x0f, 0xc7, 0x1f],                   // xrstors
        &[0x0f, 0x01, 0xc8],                   // monitor
        &[0x0f, 0x01, 0xc9],                   // mwait
        &[0x66, 0x0f, 0x38, 0x82, 0x07],       // invpcid
        &[0x0f, 0x01, 0xc1],                   // vmcall
        &[0xf3, 0x0f, 0xc7, 0xf8],             // rdpid
        &[0xc5, 0xf9, 0xf7, 0xc1],             // vmaskmovdqu
        &[0x0f, 0x01, 0xfc],                   // clzero
        &[0x66, 0x0f, 0x38, 0xf8, 0x07],       // movdir64b
        &[0xf2, 0x0f, 0x38, 0xf8, 0x07],       // enqcmd
        &[0xf3, 0x0f, 0x38, 0xf8, 0x07],       // enqcmds
        &[0xf3, 0x0f, 0xae, 0xf0],             // umonitor
        &[0xc4, 0xe2, 0x7d, 0x92, 0x04, 0x87], // vgatherdps
        &[0xc5, 0xf8, 0x28, 0x07],             // vmovaps
        &[0x48, 0x0f, 0xc7, 0x0f],             // cmpxchg16b (CX16 is not exposed)
    ];
    for bytes in cases {
        assert_eq!(
            classify(bytes, 0x400000).unwrap().class,
            InsnClass::InvalidOpcode,
            "{bytes:x?}"
        );
        let (mut cpu, mut mem, va) = setup_snippet(bytes);
        cpu.ctx.gpr[reg::RDI] = 1; // dangerous if admitted natively
        step_ok(&mut cpu, &mut mem, ud(va));
    }
    let (mut cpu, mut mem, va) = setup_snippet(&[0x0f, 0x33]); // rdpmc requires a privileged exit
    step_ok(&mut cpu, &mut mem, gp(va));
}

#[test]
fn breakpoints_and_software_interrupts_have_typed_exits() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0xcc, 0xcd, 0x80]);
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Exception(X86Exception::new(
            X86ExceptionVector::Breakpoint,
            va + 1,
            None,
            None,
        )),
    );
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::SoftwareInterrupt {
            vector: 0x80,
            rip: va + 1,
            next_rip: va + 3,
        },
    );
}

#[test]
fn guest_rsp_values_survive_native_ops_memory_helpers_and_exits() {
    // mov rsp,1; mov rax,rsp; add rsp,7; mov [rsp],rax
    let (mut cpu, mut mem, va) = setup_snippet(&[
        0xbc, 1, 0, 0, 0, 0x48, 0x89, 0xe0, 0x48, 0x83, 0xc4, 7, 0x48, 0x89, 0x04, 0x24,
    ]);
    step_ok(
        &mut cpu,
        &mut mem,
        pf(va + 12, PF_ERR_USER | PF_ERR_WRITE, 8),
    );
    assert_eq!(cpu.ctx.gpr[reg::RSP], 8);
    assert_eq!(cpu.ctx.gpr[reg::RAX], 1);
}

#[test]
fn rip_relative_word_lea_preserves_upper_destination_bits() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0x66, 0x44, 0x8d, 0x3d, 1, 0, 0, 0, 0x0f, 0x05]);
    cpu.ctx.gpr[reg::R15] = 0x1234_5678_9abc_ffff;
    step_ok(&mut cpu, &mut mem, sys(va + 8, va + 10));
    assert_eq!(
        cpu.ctx.gpr[reg::R15],
        0x1234_5678_9abc_0000 | ((va + 9) & 0xffff)
    );
}

#[test]
fn masked_store_crosses_pages_without_changing_disabled_bytes() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0x66, 0x0f, 0xf7, 0xc1, 0x0f, 0x05]);
    let addr = 0x2000_0ff8;
    mem.map_range(0x2000_0000, 8192, PagePerms::USER_RW);
    mem.write_direct(addr, &[0x55; 16]);
    cpu.ctx.gpr[reg::RDI] = addr;
    cpu.ctx.write_xmm(0, u128::MAX);
    cpu.ctx.write_xmm(1, 0x80 | (0x80 << 120));
    step_ok(&mut cpu, &mut mem, sys(va + 4, va + 6));
    let mut expected = [0x55; 16];
    expected[0] = 0xff;
    expected[15] = 0xff;
    assert_eq!(mem.read_direct(addr, 16).unwrap(), expected);
}

#[test]
#[cfg(target_os = "linux")]
fn published_blocks_and_gateways_are_rx_and_never_writable() {
    fn permissions(addr: u64) -> String {
        std::fs::read_to_string("/proc/self/maps")
            .unwrap()
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                let (start, end) = fields.next()?.split_once('-')?;
                let start = u64::from_str_radix(start, 16).ok()?;
                let end = u64::from_str_radix(end, 16).ok()?;
                let perms = fields.next()?;
                (start <= addr && addr < end).then(|| perms.to_owned())
            })
            .unwrap()
    }
    let mut jit = JitCodeBuffer::new(4096).unwrap();
    for _ in 0..2 {
        let addr = jit.publish(&[0xc3]).unwrap();
        assert_eq!(permissions(addr), "r-xp");
    }
    let cpu = SoftCpu::new().unwrap();
    for addr in [
        cpu.ctx.slow_path_fn,
        cpu.ctx.bounce_commit_fn,
        cpu.ctx.complex_step_fn,
        cpu.ctx.exit_trampoline_fn,
    ] {
        assert_eq!(permissions(addr), "r-xp");
    }
}

#[test]
fn scalar_cmpsd_never_uses_unchecked_native_copy() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0xf2, 0x0f, 0xc2, 0xc1, 0, 0x0f, 0x05]);
    let planned =
        carrick_softcpu_x86::plan_block_from_memory(va, 64, 4096, &mut cpu.ctx, &mut mem).unwrap();
    let emitted = carrick_softcpu_x86::emit_block(&planned).unwrap();
    let native_comparison =
        iced_x86::Decoder::new(64, &emitted.code, iced_x86::DecoderOptions::NONE)
            .into_iter()
            .any(|i| i.mnemonic() == iced_x86::Mnemonic::Cmpsd && !i.is_string_instruction());
    assert!(
        !native_comparison,
        "scalar SSE CMPSD escaped the checked helper"
    );
}

#[test]
fn descriptor_queries_exit_without_host_state() {
    for bytes in [&[0x0f, 0x02, 0xc0][..], &[0x0f, 0x03, 0xc0]] {
        let decoded = carrick_softcpu_x86::classify(bytes, 0x400000).unwrap();
        assert!(matches!(
            decoded.class,
            carrick_softcpu_x86::InsnClass::Sensitive(_)
        ));
        let (mut cpu, mut mem, va) = setup_snippet(bytes);
        cpu.ctx.gpr[reg::RAX] = 0x33;
        let flags = cpu.ctx.rflags;
        assert!(
            matches!(cpu.step_block(&mut mem).unwrap(),SoftCpuExit::Sensitive { rip,next_rip,.. } if rip==va && next_rip==va+3)
        );
        assert_eq!(cpu.ctx.gpr[reg::RAX], 0x33);
        assert_eq!(cpu.ctx.rflags, flags);
    }
}
