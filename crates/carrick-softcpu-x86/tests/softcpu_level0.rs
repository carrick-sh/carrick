//! Comprehensive Level 0 test suite for `carrick-softcpu-x86`.

#![cfg(target_arch = "x86_64")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_softcpu_x86::{
    ExtentRecord, ExtentTable, FrameGpa, JitCodeBuffer, LinearPlacement, MmioHoles,
    OwnerGeneration, PF_ERR_INSTR, PF_ERR_PRESENT, PF_ERR_USER, PF_ERR_WRITE, RootGpa,
    SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK, SOFT_TLB_PAGE_SIZE, SensitiveOp, SoftAccessKind,
    SoftCpu, SoftCpuExit, SoftMmuMemory, X86Exception, X86ExceptionVector, read_guest_bytes, reg,
    translate_with_frame,
};
use goblin::elf::Elf;
use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};

const LINUX_SYS_WRITE: u64 = 1;
const LINUX_SYS_GETPID: u64 = 39;
const LINUX_SYS_EXIT_GROUP: u64 = 231;

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
    const USER_RO: Self = Self::new(true, false, false, true);
    const USER_RWX: Self = Self::new(true, true, true, true);
    const KERNEL_RW: Self = Self::new(true, true, false, false);
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

    fn map_alias(&mut self, va: u64, frame_gpa: FrameGpa, perms: PagePerms) {
        self.install_leaf_pte(va, frame_gpa, perms);
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

struct ElfRunResult {
    exception: Option<X86Exception>,
    exit_code: i32,
    stdout: Vec<u8>,
}

/// Load a static or static-pie x86_64 Linux ELF into `TestSoftMmuMemory` and run it to `exit_group`.
fn run_static_elf_fixture(elf_bytes: &[u8]) -> ElfRunResult {
    let elf = Elf::parse(elf_bytes).expect("parse ELF fixture");
    assert!(elf.is_64, "fixture must be 64-bit x86_64 ELF");
    let mut mem = TestSoftMmuMemory::new();
    let bias: u64 = if elf.header.e_type == goblin::elf::header::ET_DYN {
        0x0000_0040_0000_0000
    } else {
        0
    };
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 {
            continue;
        }
        let seg_va = ph.p_vaddr.wrapping_add(bias);
        let perms = PagePerms::new(
            true,
            (ph.p_flags & PF_W) != 0,
            (ph.p_flags & PF_X) != 0,
            true,
        );
        mem.map_range(seg_va, ph.p_memsz as usize, perms);
        let file_slice = &elf_bytes[ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize];
        assert!(mem.write_direct(seg_va, file_slice));
    }

    let (stack_base, stack_size, aux_scratch) =
        (0x7fff_fff0_0000u64, 65536usize, 0x7fff_ffef_0000u64);
    mem.map_range(stack_base, stack_size, PagePerms::USER_RW);
    mem.map_range(aux_scratch, 4096, PagePerms::USER_RW);
    assert!(mem.write_direct(aux_scratch, b"fixture\0"));
    assert!(mem.write_direct(aux_scratch + 16, &[0x42u8; 16]));

    let words: [u64; 10] = [1, aux_scratch, 0, 0, 6, 4096, 25, aux_scratch + 16, 0, 0];
    let rsp = (stack_base + stack_size as u64 - (words.len() * 8) as u64) & !0xf;
    for (i, w) in words.iter().enumerate() {
        assert!(mem.write_direct(rsp + (i * 8) as u64, &w.to_le_bytes()));
    }

    let mut cpu = SoftCpu::new().expect("create SoftCpu");
    cpu.context_mut().rip = elf.entry.wrapping_add(bias);
    cpu.context_mut().gpr[reg::RSP] = rsp;

    let mut stdout = Vec::new();
    for _step in 0..200_000 {
        match cpu.step_block(&mut mem).expect("step block") {
            SoftCpuExit::Continue { .. } => {}
            SoftCpuExit::Syscall { next_rip, .. } => match cpu.context_mut().gpr[reg::RAX] {
                LINUX_SYS_WRITE => {
                    let (buf_va, len) = (
                        cpu.context_mut().gpr[reg::RSI],
                        cpu.context_mut().gpr[reg::RDX] as usize,
                    );
                    let mut data = vec![0u8; len];
                    read_guest_bytes(
                        cpu.context_mut(),
                        &mut mem,
                        buf_va,
                        &mut data,
                        SoftAccessKind::Read,
                    )
                    .expect("read guest write buffer");
                    stdout.extend_from_slice(&data);
                    cpu.context_mut().gpr[reg::RAX] = len as u64;
                    cpu.context_mut().rip = next_rip;
                }
                LINUX_SYS_GETPID => {
                    cpu.context_mut().gpr[reg::RAX] = 1234;
                    cpu.context_mut().rip = next_rip;
                }
                LINUX_SYS_EXIT_GROUP => {
                    return ElfRunResult {
                        exception: None,
                        exit_code: cpu.context_mut().gpr[reg::RDI] as i32,
                        stdout,
                    };
                }
                other => panic!(
                    "unexpected syscall {other} at rip=0x{:x}",
                    cpu.context_mut().rip
                ),
            },
            SoftCpuExit::Exception(exc) => {
                return ElfRunResult {
                    exception: Some(exc),
                    exit_code: -1,
                    stdout,
                };
            }
            other => panic!("unexpected exit {other:?}"),
        }
    }
    panic!("fixture did not exit within step budget");
}

#[test]
fn retired_fixtures_run_over_soft_memory() {
    let res = run_static_elf_fixture(include_bytes!("fixtures/tinyguest-x86_64-linux"));
    assert_eq!(
        (res.stdout.as_slice(), res.exit_code),
        (&b"native-elf ok\n"[..], 21)
    );
    let res = run_static_elf_fixture(include_bytes!("fixtures/pkru-virtual-x86_64-linux"));
    assert_eq!(
        res.exception.unwrap().vector,
        X86ExceptionVector::InvalidOpcode
    );

    for f in [
        include_bytes!("fixtures/rdssp-disabled-x86_64-linux").as_slice(),
        include_bytes!("fixtures/call-ret-loop-x86_64-linux").as_slice(),
        include_bytes!("fixtures/xstate-chain-boundary-x86_64-linux").as_slice(),
    ] {
        assert_eq!(run_static_elf_fixture(f).exit_code, 37);
    }
}

fn setup_snippet(code: &[u8]) -> (SoftCpu, TestSoftMmuMemory, u64) {
    let (code_va, stack_va) = (0x0040_0000u64, 0x0080_0000u64);
    let mut mem = TestSoftMmuMemory::new();
    mem.map_range(code_va, 4096, PagePerms::USER_RX);
    mem.write_direct(code_va, code);
    mem.map_range(stack_va, 8192, PagePerms::USER_RW);
    let mut cpu = SoftCpu::new().expect("SoftCpu");
    cpu.context_mut().rip = code_va;
    cpu.context_mut().gpr[reg::RSP] = stack_va + 4096;
    (cpu, mem, code_va)
}

fn step_ok(cpu: &mut SoftCpu, mem: &mut TestSoftMmuMemory, exp: SoftCpuExit) {
    assert_eq!(cpu.step_block(mem).unwrap(), exp);
}

#[test]
fn page_fault_witnesses_read_write_ro_nx_smap_and_straddle_fetch() {
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x48, 0x8B, 0x07, 0x0F, 0x05]);
    cpu.context_mut().gpr[reg::RDI] = 0xdead_0000;
    cpu.context_mut().gpr[reg::RAX] = 0x1234_5678;
    step_ok(&mut cpu, &mut mem, pf(code_va, PF_ERR_USER, 0xdead_0000));
    assert_eq!(cpu.context_mut().gpr[reg::RAX], 0x1234_5678);

    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x48, 0x89, 0x07, 0x0F, 0x05]);
    let ro_va = 0x0090_0000u64;
    mem.map_range(ro_va, 4096, PagePerms::USER_RO);
    cpu.context_mut().gpr[reg::RDI] = ro_va + 8;
    let pwu = PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER;
    step_ok(&mut cpu, &mut mem, pf(code_va, pwu, ro_va + 8));

    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x48, 0x8B, 0x07, 0x0F, 0x05]);
    let sup_va = 0x00a0_0000u64;
    mem.map_range(sup_va, 4096, PagePerms::KERNEL_RW);
    cpu.context_mut().gpr[reg::RDI] = sup_va;
    step_ok(
        &mut cpu,
        &mut mem,
        pf(code_va, PF_ERR_PRESENT | PF_ERR_USER, sup_va),
    );

    let nx_va = 0x00b0_0000u64;
    mem.map_range(nx_va, 4096, PagePerms::USER_RW);
    mem.write_direct(nx_va, &[0x90, 0x0F, 0x05]);
    cpu.context_mut().rip = nx_va;
    let pui = PF_ERR_PRESENT | PF_ERR_USER | PF_ERR_INSTR;
    step_ok(&mut cpu, &mut mem, pf(nx_va, pui, nx_va));

    let straddle_rip = code_va + 0xFFA;
    mem.write_direct(straddle_rip, &[0x48, 0xB8, 1, 2, 3, 4]);
    cpu.context_mut().rip = straddle_rip;
    let ui = PF_ERR_USER | PF_ERR_INSTR;
    step_ok(&mut cpu, &mut mem, pf(straddle_rip, ui, code_va + 0x1000));

    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x48, 0x8B, 0x07, 0x0F, 0x05]);
    mem.set_page_perms(code_va, PagePerms::KERNEL_RX);
    cpu.context_mut().set_smap_enabled(true);
    let user_data = 0x00c0_0000u64;
    mem.map_range(user_data, 4096, PagePerms::USER_RW);
    mem.write_direct(user_data, &0xCAFE_BABE_1234_5678u64.to_le_bytes());
    cpu.context_mut().set_cpl(0);
    cpu.context_mut().tlb.flush_all();
    cpu.context_mut().gpr[reg::RDI] = user_data;
    step_ok(&mut cpu, &mut mem, pf(code_va, PF_ERR_PRESENT, user_data));
    cpu.context_mut().rflags |= 1 << 18;
    cpu.context_mut().sync_tlb_tag_bits();
    step_ok(&mut cpu, &mut mem, sys(code_va + 3, code_va + 5));
    assert_eq!(cpu.context_mut().gpr[reg::RAX], 0xCAFE_BABE_1234_5678);
}

#[test]
fn invalid_opcode_witnesses_ud2_and_bad_encodings() {
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0xB8, 42, 0, 0, 0, 0x0F, 0x0B]);
    step_ok(&mut cpu, &mut mem, ud(code_va + 5));
    assert_eq!(
        (cpu.context_mut().gpr[reg::RAX], cpu.context_mut().rip),
        (42, code_va + 5)
    );
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
        cpu.context_mut().set_cpl(0);
        cpu.context_mut().tlb.flush_all();
        cpu.context_mut().rip = code_va;
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
    cpu.context_mut().gpr[reg::RDI] = 0x0001_0000_0000_0000;
    step_ok(&mut cpu, &mut mem, gp(code_va));

    cpu.context_mut().rip = 0x0002_0000_0000_0000;
    step_ok(&mut cpu, &mut mem, gp(0x0002_0000_0000_0000));

    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x0F, 0x28, 0x07, 0x0F, 0x05]);
    let data_va = 0x0090_0000u64;
    mem.map_range(data_va, 4096, PagePerms::USER_RW);
    mem.write_direct(data_va + 4, &[0x11u8; 16]);
    cpu.context_mut().gpr[reg::RDI] = data_va + 4;
    step_ok(&mut cpu, &mut mem, gp(code_va));

    mem.write_direct(code_va, &[0x0F, 0x10, 0x07, 0x0F, 0x05]);
    cpu.context_mut().rip = code_va;
    step_ok(&mut cpu, &mut mem, sys(code_va + 3, code_va + 5));
    assert_eq!(
        cpu.context_mut().read_xmm(0),
        u128::from_le_bytes([0x11u8; 16])
    );
}

#[test]
fn divide_error_witnesses_div_idiv_zero_overflow_and_fault_priority() {
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x48, 0xF7, 0xF1, 0x0F, 0x05]);
    cpu.context_mut().gpr[reg::RAX] = 100;
    step_ok(&mut cpu, &mut mem, de(code_va));
    assert_eq!(
        X86Exception::divide_error(code_va).vector,
        X86ExceptionVector::DivideError
    );

    cpu.context_mut().rip = code_va;
    (
        cpu.context_mut().gpr[reg::RDX],
        cpu.context_mut().gpr[reg::RAX],
        cpu.context_mut().gpr[reg::RCX],
    ) = (1, 0, 1);
    step_ok(&mut cpu, &mut mem, de(code_va));

    mem.write_direct(code_va, &[0x48, 0xF7, 0xF9, 0x0F, 0x05]);
    cpu.context_mut().rip = code_va;
    (
        cpu.context_mut().gpr[reg::RAX],
        cpu.context_mut().gpr[reg::RDX],
        cpu.context_mut().gpr[reg::RCX],
    ) = (i64::MIN as u64, u64::MAX, (-1i64) as u64);
    step_ok(&mut cpu, &mut mem, de(code_va));

    cpu.context_mut().rip = code_va;
    (
        cpu.context_mut().gpr[reg::RAX],
        cpu.context_mut().gpr[reg::RDX],
        cpu.context_mut().gpr[reg::RCX],
    ) = ((-100i64) as u64, u64::MAX, 7);
    step_ok(&mut cpu, &mut mem, sys(code_va + 3, code_va + 5));
    assert_eq!(
        (
            cpu.context_mut().gpr[reg::RAX] as i64,
            cpu.context_mut().gpr[reg::RDX] as i64
        ),
        (-14, -2)
    );

    mem.write_direct(code_va, &[0x48, 0xF7, 0x37, 0x0F, 0x05]);
    cpu.context_mut().rip = code_va;
    cpu.context_mut().gpr[reg::RDI] = 0x0000_5555_beef_0000;
    step_ok(
        &mut cpu,
        &mut mem,
        pf(code_va, PF_ERR_USER, 0x0000_5555_beef_0000),
    );
}

#[test]
fn page_crossing_bounce_buffer_handles_read_write_rmw_and_second_page_fault_atomicity() {
    let code = &[
        0x48, 0x8B, 0x07, 0x48, 0x01, 0x1F, 0x48, 0x89, 0x06, 0x0F, 0x05,
    ];
    let (mut cpu, mut mem, code_va) = setup_snippet(code);
    let base_va = 0x1000_0000u64;
    mem.map_range(base_va, 3 * 4096, PagePerms::USER_RW);

    let (straddle_a, straddle_b, init_val) =
        (base_va + 0xFFD, base_va + 0x1FF9, 0x0102_0304_0506_0708u64);
    mem.write_direct(straddle_a, &init_val.to_le_bytes());
    (
        cpu.context_mut().gpr[reg::RDI],
        cpu.context_mut().gpr[reg::RSI],
        cpu.context_mut().gpr[reg::RBX],
    ) = (straddle_a, straddle_b, 0x1000_0000_0000_0001);

    step_ok(&mut cpu, &mut mem, sys(code_va + 9, code_va + 11));
    assert_eq!(cpu.context_mut().gpr[reg::RAX], init_val);

    let updated_a = u64::from_le_bytes(mem.read_direct(straddle_a, 8).unwrap().try_into().unwrap());
    assert_eq!(updated_a, init_val.wrapping_add(0x1000_0000_0000_0001));
    let written_b = u64::from_le_bytes(mem.read_direct(straddle_b, 8).unwrap().try_into().unwrap());
    assert_eq!(written_b, init_val);

    mem.set_page_perms(base_va + 0x1000, PagePerms::USER_RO);
    cpu.context_mut().tlb.flush_all();
    let before_bytes = mem.read_direct(straddle_a, 8).unwrap();

    mem.write_direct(code_va, &[0x48, 0x89, 0x1F, 0x0F, 0x05]);
    cpu.context_mut().rip = code_va;
    (
        cpu.context_mut().gpr[reg::RDI],
        cpu.context_mut().gpr[reg::RBX],
    ) = (straddle_a, u64::MAX);

    let pwu = PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER;
    step_ok(&mut cpu, &mut mem, pf(code_va, pwu, base_va + 0x1000));
    assert_eq!(before_bytes, mem.read_direct(straddle_a, 8).unwrap());
}

#[test]
fn virtualized_r14_r15_and_fs_gs_bases_work_transparently() {
    let code = &[
        0x4F, 0x8D, 0x74, 0xBE, 0x10, 0x4D, 0x8B, 0x3E, 0x64, 0x4C, 0x03, 0x3C, 0x25, 0x08, 0x00,
        0x00, 0x00, 0x65, 0x4C, 0x03, 0x3C, 0x25, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x05,
    ];
    let (mut cpu, mut mem, code_va) = setup_snippet(code);
    let (data_va, tls_va) = (0x2000_0000u64, 0x3000_0000u64);
    mem.map_range(data_va, 4096, PagePerms::USER_RW);
    mem.map_range(tls_va, 4096, PagePerms::USER_RW);

    (
        cpu.context_mut().gpr[reg::R14],
        cpu.context_mut().gpr[reg::R15],
    ) = (data_va, 0x20);
    let target_addr = data_va + 0x20 * 4 + 0x10;
    mem.write_direct(target_addr, &1000u64.to_le_bytes());
    (cpu.context_mut().fs_base, cpu.context_mut().gs_base) = (tls_va + 0x100, tls_va + 0x200);
    mem.write_direct(tls_va + 0x108, &200u64.to_le_bytes());
    mem.write_direct(tls_va + 0x210, &34u64.to_le_bytes());

    step_ok(&mut cpu, &mut mem, sys(code_va + 26, code_va + 28));
    assert_eq!(
        (
            cpu.context_mut().gpr[reg::R14],
            cpu.context_mut().gpr[reg::R15]
        ),
        (target_addr, 1234)
    );
}

#[test]
fn cflow_call_and_ret_fault_atomicity_preserves_rsp_and_rip() {
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0xE8, 0x10, 0x00, 0x00, 0x00, 0x0F, 0x05]);
    let unmapped_sp = 0x0000_7000_0000_0000u64;
    cpu.context_mut().gpr[reg::RSP] = unmapped_sp;
    let wu = PF_ERR_WRITE | PF_ERR_USER;
    step_ok(&mut cpu, &mut mem, pf(code_va, wu, unmapped_sp - 8));
    assert_eq!(
        (cpu.context_mut().rip, cpu.context_mut().gpr[reg::RSP]),
        (code_va, unmapped_sp)
    );

    let (data_va, ro_stack_va) = (0x2000_0000u64, 0x3000_0000u64);
    mem.map_range(data_va, 4096, PagePerms::USER_RW);
    mem.map_range(ro_stack_va, 4096, PagePerms::USER_RO);
    mem.write_direct(data_va, &(code_va + 0x100).to_le_bytes());
    mem.write_direct(code_va, &[0xFF, 0x17, 0x0F, 0x05]);
    cpu.context_mut().rip = code_va;
    cpu.context_mut().gpr[reg::RDI] = data_va;
    cpu.context_mut().gpr[reg::RSP] = ro_stack_va + 0x100;
    let pwu = PF_ERR_PRESENT | PF_ERR_WRITE | PF_ERR_USER;
    step_ok(&mut cpu, &mut mem, pf(code_va, pwu, ro_stack_va + 0xF8));
    assert_eq!(
        (cpu.context_mut().rip, cpu.context_mut().gpr[reg::RSP]),
        (code_va, ro_stack_va + 0x100)
    );

    mem.write_direct(code_va, &[0xC3, 0x0F, 0x05]);
    cpu.context_mut().rip = code_va;
    cpu.context_mut().gpr[reg::RSP] = unmapped_sp;
    step_ok(&mut cpu, &mut mem, pf(code_va, PF_ERR_USER, unmapped_sp));
    assert_eq!(
        (cpu.context_mut().rip, cpu.context_mut().gpr[reg::RSP]),
        (code_va, unmapped_sp)
    );
}

#[test]
fn string_instructions_rep_movsb_stosb_cmpsb_work_across_pages() {
    let code = &[
        0xFC, 0xF3, 0xA4, 0x0F, 0x05, 0xF3, 0xAA, 0x0F, 0x05, 0xF3, 0xA6, 0x0F, 0x05,
    ];
    let (mut cpu, mut mem, code_va) = setup_snippet(code);
    let (src_va, dst_va) = (0x2000_0000u64, 0x3000_0000u64);
    mem.map_range(src_va, 8192, PagePerms::USER_RW);
    mem.map_range(dst_va, 8192, PagePerms::USER_RW);

    let pattern: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    mem.write_direct(src_va + 0xFF0, &pattern);
    cpu.context_mut().gpr[reg::RSI] = src_va + 0xFF0;
    cpu.context_mut().gpr[reg::RDI] = dst_va + 0xFF0;
    cpu.context_mut().gpr[reg::RCX] = 32;

    step_ok(&mut cpu, &mut mem, sys(code_va + 3, code_va + 5));
    let g = &cpu.context_mut().gpr;
    assert_eq!(
        (g[reg::RCX], g[reg::RSI], g[reg::RDI]),
        (0, src_va + 0x1010, dst_va + 0x1010)
    );
    assert_eq!(mem.read_direct(dst_va + 0xFF0, 32).unwrap(), pattern);

    cpu.context_mut().rip = code_va + 5;
    cpu.context_mut().gpr[reg::RDI] = dst_va + 0xFF8;
    cpu.context_mut().gpr[reg::RAX] = 0x5A;
    cpu.context_mut().gpr[reg::RCX] = 16;
    step_ok(&mut cpu, &mut mem, sys(code_va + 7, code_va + 9));
    assert_eq!(
        (
            cpu.context_mut().gpr[reg::RCX],
            mem.read_direct(dst_va + 0xFF8, 16).unwrap()
        ),
        (0, vec![0x5Au8; 16])
    );

    cpu.context_mut().rip = code_va + 9;
    cpu.context_mut().gpr[reg::RSI] = src_va + 0xFF0;
    cpu.context_mut().gpr[reg::RDI] = dst_va + 0xFF0;
    cpu.context_mut().gpr[reg::RCX] = 32;
    step_ok(&mut cpu, &mut mem, sys(code_va + 11, code_va + 13));
    assert_eq!(
        (
            cpu.context_mut().gpr[reg::RCX],
            cpu.context_mut().rflags & (1 << 6)
        ),
        (23, 0)
    );
}

#[test]
fn alias_writes_advance_code_frame_generation() {
    let (mut cpu, mut mem, code_va) = setup_snippet(&[0x48, 0x89, 0x07, 0x0F, 0x05]);
    let (code2_va, alias_va) = (0x2000_0000u64, 0x5000_3000u64);
    mem.map_range(code2_va, 4096, PagePerms::USER_RWX);
    let shared_frame = mem.frame_for_va(code2_va).unwrap();
    mem.map_alias(alias_va, shared_frame, PagePerms::USER_RW);
    mem.write_direct(code2_va, &[0x90, 0x0F, 0x05]);

    let (_, auth_frame) =
        translate_with_frame(cpu.context_mut(), &mut mem, code2_va, SoftAccessKind::Read)
            .expect("resolve shared frame");

    cpu.context_mut().gpr[reg::RDI] = alias_va + 0x100;
    cpu.context_mut().gpr[reg::RAX] = 11;
    step_ok(&mut cpu, &mut mem, sys(code_va + 3, code_va + 5));
    assert_eq!(mem.extents().code_generation(auth_frame), 0);

    cpu.context_mut().rip = code2_va;
    step_ok(&mut cpu, &mut mem, sys(code2_va + 1, code2_va + 3));
    assert_eq!(mem.extents().code_generation(auth_frame), 1);

    cpu.context_mut().rip = code_va;
    cpu.context_mut().gpr[reg::RDI] = alias_va + 0x100;
    cpu.context_mut().gpr[reg::RAX] = 22;
    step_ok(&mut cpu, &mut mem, sys(code_va + 3, code_va + 5));
    assert_eq!(mem.extents().code_generation(auth_frame), 2);
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
struct NativeDiffState {
    gpr: [u64; 16],
    rflags: u64,
    host_rsp_save: u64,
}

const NATIVE_DIFF_PROLOGUE: &[u8; 88] = b"\
\x55\x53\x41\x54\x41\x55\x41\x56\x41\x57\x57\x48\x89\xA7\x88\x00\x00\x00\xFF\xB7\x80\x00\x00\x00\x9D\x48\x8B\x07\x48\x8B\x4F\x08\x48\x8B\x57\x10\x48\x8B\x5F\x18\x48\x8B\x67\x20\x48\x8B\x6F\x28\x48\x8B\x77\x30\x4C\x8B\x47\x40\x4C\x8B\x4F\x48\x4C\x8B\x57\x50\x4C\x8B\x5F\x58\x4C\x8B\x67\x60\x4C\x8B\x6F\x68\x4C\x8B\x77\x70\x4C\x8B\x7F\x78\x48\x8B\x7F\x38";

const NATIVE_DIFF_EPILOGUE_TAIL: &[u8; 84] = b"\
\x48\x89\x4F\x08\x48\x89\x57\x10\x48\x89\x5F\x18\x48\x89\x67\x20\x48\x89\x6F\x28\x48\x89\x77\x30\x4C\x89\x47\x40\x4C\x89\x4F\x48\x4C\x89\x57\x50\x4C\x89\x5F\x58\x4C\x89\x67\x60\x4C\x89\x6F\x68\x4C\x89\x77\x70\x4C\x89\x7F\x78\x48\x8B\xA7\x88\x00\x00\x00\x9C\x58\x48\x89\x87\x80\x00\x00\x00\x5F\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x5B\x5D\xC3";

struct Xorshift64(u64);

impl Xorshift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn gen_random_block(rng: &mut Xorshift64) -> Vec<u8> {
    const REGS: [u8; 14] = [0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let num_insns = 8 + (rng.next() as usize % 16);
    let mut out = Vec::new();
    for _ in 0..num_insns {
        let pick = (rng.next() % 12) as u8;
        let dst = REGS[(rng.next() as usize) % REGS.len()];
        let src = REGS[(rng.next() as usize) % REGS.len()];
        let rex_w = if (rng.next() & 1) != 0 { 0x48 } else { 0x40 };
        let rex_r = if dst >= 8 { 0x04 } else { 0 };
        let rex_b = if src >= 8 { 0x01 } else { 0 };
        let (rex, modrm_rr) = (rex_w | rex_r | rex_b, 0xC0 | ((dst & 7) << 3) | (src & 7));

        match pick {
            0..=4 => {
                const OPS: [u8; 8] = [0x03, 0x2B, 0x33, 0x0B, 0x23, 0x3B, 0x13, 0x1B];
                if rex != 0x40 {
                    out.push(rex);
                }
                out.extend_from_slice(&[OPS[(rng.next() as usize) % OPS.len()], modrm_rr]);
            }
            5 => {
                if rex != 0x40 {
                    out.push(rex);
                }
                out.extend_from_slice(&[0x0F, 0xAF, modrm_rr]);
            }
            6 => {
                const SUBOPS: [u8; 5] = [4, 5, 7, 0, 1];
                let sub = SUBOPS[(rng.next() as usize) % SUBOPS.len()];
                let r_b = rex_w | if dst >= 8 { 0x01 } else { 0 };
                if r_b != 0x40 {
                    out.push(r_b);
                }
                let imm = (rng.next() as u8) & 31;
                out.extend_from_slice(&[0xC1, 0xC0 | (sub << 3) | (dst & 7), imm]);
            }
            7 => {
                let disp = (rng.next() % 120) as u8;
                out.extend_from_slice(&[0x48 | rex_r, 0x8B, 0x45 | ((dst & 7) << 3), disp]);
            }
            8 => {
                let (disp, r) = ((rng.next() % 120) as u8, 0x48 | ((src >> 3) * 4));
                out.extend_from_slice(&[r, 0x89, 0x45 | ((src & 7) << 3), disp]);
            }
            9 => {
                let (disp, r) = ((rng.next() % 120) as u8, 0x48 | ((src >> 3) * 4));
                let op = if (rng.next() & 1) == 0 { 0x01 } else { 0x31 };
                out.extend_from_slice(&[r, op, 0x45 | ((src & 7) << 3), disp]);
            }
            10 if src != 4 && src != 12 && dst != 4 => {
                let r = 0x48 | rex_r | rex_b | ((dst >> 3) * 2);
                let (sib, disp) = (0x80 | ((dst & 7) << 3) | (src & 7), (rng.next() % 64) as u8);
                out.extend_from_slice(&[r, 0x8D, 0x44 | ((dst & 7) << 3), sib, disp]);
            }
            _ => {
                if src >= 8 {
                    out.push(0x41);
                }
                out.push(0x50 + (src & 7));
                if dst >= 8 {
                    out.push(0x41);
                }
                out.push(0x58 + (dst & 7));
            }
        }
    }
    out
}

#[test]
fn differential_property_tests_match_native_host_x86_64_cpu() {
    let mut rng = Xorshift64(0x853c_49e6_748f_ea9b);
    let mut native_jit = JitCodeBuffer::new(64 * 1024).expect("native diff JIT");
    let mut cpu = SoftCpu::new().expect("SoftCpu");
    const ARITH_FLAGS: u64 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);

    for trial in 0..200 {
        let body = gen_random_block(&mut rng);
        let mut guest_code = body.clone();
        guest_code.extend_from_slice(&[0x0F, 0x05]);

        let (code_va, data_va, stack_va) = (0x0040_0000u64, 0x2000_0000u64, 0x3000_0000u64);
        let mut mem = TestSoftMmuMemory::new();
        mem.map_range(code_va, 4096, PagePerms::USER_RX);
        mem.write_direct(code_va, &guest_code);
        mem.map_range(data_va, 8192, PagePerms::USER_RW);
        mem.map_range(stack_va, 8192, PagePerms::USER_RW);

        let host_data: Vec<u8> = (0..8192).map(|_| rng.next() as u8).collect();
        let host_stack: Vec<u8> = (0..8192).map(|_| rng.next() as u8).collect();
        mem.write_direct(data_va, &host_data);
        mem.write_direct(stack_va, &host_stack);

        let mut init_gprs = [0u64; 16];
        init_gprs.iter_mut().for_each(|g| *g = rng.next());
        let (rbp_offset, rsp_offset) = (0xFE0u64, 4096u64);
        let init_flags = 0x202 | (rng.next() & ARITH_FLAGS);

        cpu.context_mut().tlb.flush_all();
        cpu.context_mut().gpr = init_gprs;
        (
            cpu.context_mut().gpr[reg::RBP],
            cpu.context_mut().gpr[reg::RSP],
        ) = (data_va + rbp_offset, stack_va + rsp_offset);
        (cpu.context_mut().rip, cpu.context_mut().rflags) = (code_va, init_flags);

        let end_va = code_va + body.len() as u64;
        step_ok(&mut cpu, &mut mem, sys(end_va, end_va + 2));

        let (mut host_data_mut, mut host_stack_mut) = (host_data, host_stack);
        let mut native_state = NativeDiffState {
            gpr: init_gprs,
            rflags: init_flags,
            host_rsp_save: 0,
        };
        native_state.gpr[reg::RBP] = (host_data_mut.as_mut_ptr() as u64) + rbp_offset;
        native_state.gpr[reg::RSP] = (host_stack_mut.as_mut_ptr() as u64) + rsp_offset;
        let sb = ((&raw mut native_state) as usize as u64).to_le_bytes();

        let mut native_code = Vec::with_capacity(200 + body.len());
        for s in [
            &NATIVE_DIFF_PROLOGUE[..],
            &body,
            &[0x48, 0xA3],
            &sb,
            &[0x48, 0x89, 0xF8, 0x48, 0xBF],
            &sb,
            &[0x48, 0x89, 0x47, 0x38],
            &NATIVE_DIFF_EPILOGUE_TAIL[..],
        ] {
            native_code.extend_from_slice(s);
        }

        let native_exec = native_jit.publish(&native_code).unwrap();
        unsafe {
            let run_fn: unsafe extern "sysv64" fn(*mut NativeDiffState) =
                std::mem::transmute(native_exec as usize);
            run_fn(&raw mut native_state);
        }

        let (d_base, s_base) = (
            host_data_mut.as_ptr() as u64,
            host_stack_mut.as_ptr() as u64,
        );
        for r in 0..16 {
            let (soft_v, nat_v) = match r {
                reg::RBP => (
                    cpu.context_mut().gpr[r] - data_va,
                    native_state.gpr[r] - d_base,
                ),
                reg::RSP => (
                    cpu.context_mut().gpr[r] - stack_va,
                    native_state.gpr[r] - s_base,
                ),
                _ => (cpu.context_mut().gpr[r], native_state.gpr[r]),
            };
            assert_eq!(soft_v, nat_v, "trial {trial}: GPR {r} mismatch");
        }
        assert_eq!(
            cpu.context_mut().rflags & ARITH_FLAGS,
            native_state.rflags & ARITH_FLAGS
        );
        assert_eq!(mem.read_direct(data_va, 8192).unwrap(), host_data_mut);
        assert_eq!(mem.read_direct(stack_va, 8192).unwrap(), host_stack_mut);
    }
}

// Review regressions: safe to run against the pre-fix translator as well.
#[test]
fn implicit_masked_store_cannot_write_a_host_address() {
    let mut host_bytes = [0x55u8; 16];
    let (mut cpu, mut mem, va) = setup_snippet(&[0x66, 0x0f, 0xf7, 0xc1, 0x0f, 0x05]);
    cpu.context_mut().gpr[reg::RDI] = host_bytes.as_mut_ptr() as u64;
    cpu.context_mut().write_xmm(0, u128::MAX);
    cpu.context_mut().write_xmm(1, u128::MAX);
    let result = cpu.step_block(&mut mem).unwrap();
    assert_eq!(host_bytes, [0x55; 16], "guest store escaped soft memory");
    assert_eq!(
        result,
        pf(
            va,
            PF_ERR_WRITE | PF_ERR_USER,
            cpu.context_mut().gpr[reg::RDI]
        )
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
    cpu.context_mut().gpr[reg::RAX] = va + 3;
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
    cpu.context_mut().gpr[reg::RAX] = 1;
    cpu.step_block(&mut mem).unwrap();
    assert_eq!(
        cpu.context_mut().gpr[reg::RCX] & ((1 << 28) | (1 << 12) | (1 << 29)),
        0
    );
    assert_eq!(cpu.context_mut().xcr0, 3);
    // A block end must never make unpreserved YMM upper halves observable.
    mem.write_direct(va, &[0xc5, 0xfc, 0x57, 0xc0, 0xeb, 0]); // vxorps ymm0,ymm0,ymm0
    cpu.context_mut().rip = va;
    assert_eq!(cpu.step_block(&mut mem).unwrap(), ud(va));
}

#[test]
fn complete_f3_instruction_at_page_end_does_not_fetch_next_page() {
    for bytes in [&[0xf3, 0x90][..], &[0xf3, 0xc3], &[0xf3, 0xa4]] {
        let (mut cpu, mut mem, va) = setup_snippet(&[]);
        let ip = va + 4096 - bytes.len() as u64;
        mem.write_direct(ip, bytes);
        let planned =
            carrick_softcpu_x86::plan_block_from_memory(ip, 1, 4096, cpu.context_mut(), &mut mem);
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
        cpu.context_mut().gpr[reg::RDI] = 0x2000_0ff0;
        mem.map_range(0x2000_0000, 4096, PagePerms::USER_RW);
        let write = bytes[1] == 0x37;
        step_ok(
            &mut cpu,
            &mut mem,
            pf(
                va,
                PF_ERR_USER | if write { PF_ERR_WRITE } else { 0 },
                0x2000_1000,
            ),
        );
    }
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
        cpu.context_mut().gpr[reg::RDI] = 1; // dangerous if admitted natively
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
    assert_eq!(cpu.context_mut().gpr[reg::RSP], 8);
    assert_eq!(cpu.context_mut().gpr[reg::RAX], 1);
}

#[test]
fn rip_relative_word_lea_preserves_upper_destination_bits() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0x66, 0x44, 0x8d, 0x3d, 1, 0, 0, 0, 0x0f, 0x05]);
    cpu.context_mut().gpr[reg::R15] = 0x1234_5678_9abc_ffff;
    step_ok(&mut cpu, &mut mem, sys(va + 8, va + 10));
    assert_eq!(
        cpu.context_mut().gpr[reg::R15],
        0x1234_5678_9abc_0000 | ((va + 9) & 0xffff)
    );
}

#[test]
fn masked_store_crosses_pages_without_changing_disabled_bytes() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0x66, 0x0f, 0xf7, 0xc1, 0x0f, 0x05]);
    let addr = 0x2000_0ff8;
    mem.map_range(0x2000_0000, 8192, PagePerms::USER_RW);
    mem.write_direct(addr, &[0x55; 16]);
    cpu.context_mut().gpr[reg::RDI] = addr;
    cpu.context_mut().write_xmm(0, u128::MAX);
    cpu.context_mut().write_xmm(1, 0x80 | (0x80 << 120));
    step_ok(&mut cpu, &mut mem, sys(va + 4, va + 6));
    let mut expected = [0x55; 16];
    expected[0] = 0xff;
    expected[15] = 0xff;
    assert_eq!(mem.read_direct(addr, 16).unwrap(), expected);
}

#[test]
fn sse_exceptions_and_reserved_mxcsr_bits_are_guest_faults() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0xf3, 0x0f, 0x5e, 0xc1, 0x0f, 0x05]); // divss xmm0,xmm1
    cpu.context_mut().write_xmm(0, 1.0f32.to_bits() as u128);
    cpu.context_mut().write_xmm(1, 0);
    cpu.context_mut().fxsave.0[24..28].copy_from_slice(&0x1d80u32.to_le_bytes()); // unmask zero divide
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Exception(X86Exception::new(
            X86ExceptionVector::SimdFloatingPoint,
            va,
            None,
            None,
        )),
    );
    assert_eq!(cpu.context_mut().read_xmm(0), 1.0f32.to_bits() as u128);
    assert_ne!(cpu.context_mut().fxsave.0[24] & 4, 0);
    cpu.context_mut().fxsave.0[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
    cpu.context_mut().rip = va;
    step_ok(&mut cpu, &mut mem, sys(va + 4, va + 6));
    assert_eq!(
        cpu.context_mut().read_xmm(0) as u32,
        f32::INFINITY.to_bits()
    );
    let (mut cpu, mut mem, va) = setup_snippet(&[0x0f, 0xae, 0x17]); // ldmxcsr [rdi]
    mem.map_range(0x2000_0000, 4096, PagePerms::USER_RW);
    mem.write_direct(0x2000_0000, &0x8000_1f80u32.to_le_bytes());
    cpu.context_mut().gpr[reg::RDI] = 0x2000_0000;
    step_ok(&mut cpu, &mut mem, gp(va));
}

#[test]
fn xsave_masks_and_compacted_headers_control_restore() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0x0f, 0xae, 0x27]); // xsave [rdi]
    let addr = 0x2000_0000;
    mem.map_range(addr, 4096, PagePerms::USER_RW);
    let mut image = [0x55u8; 576];
    image[512..].fill(0);
    mem.write_direct(addr, &image);
    cpu.context_mut().gpr[reg::RDI] = addr;
    cpu.context_mut().gpr[reg::RAX] = 2;
    cpu.context_mut().write_xmm(0, 0x1234);
    cpu.step_block(&mut mem).unwrap();
    let saved = mem.read_direct(addr, 576).unwrap();
    assert_eq!(&saved[..24], &[0x55; 24]);
    assert_eq!(&saved[32..160], &[0x55; 128]);
    assert_eq!(&saved[160..176], &0x1234u128.to_le_bytes());
    assert_eq!(&saved[512..520], &2u64.to_le_bytes());
    mem.write_direct(va, &[0x0f, 0xc7, 0x27]); // xsavec
    cpu.context_mut().rip = va;
    cpu.context_mut().gpr[reg::RAX] = 2;
    cpu.step_block(&mut mem).unwrap();
    assert_eq!(
        &mem.read_direct(addr + 520, 8).unwrap(),
        &((1u64 << 63) | 2).to_le_bytes()
    );
    mem.write_direct(va, &[0x0f, 0xae, 0x2f]); // xrstor
    mem.write_direct(addr + 520, &1u64.to_le_bytes()); // reserved standard XCOMP_BV
    cpu.context_mut().rip = va;
    step_ok(&mut cpu, &mut mem, gp(va));
}

#[test]
fn legacy_x87_images_cross_pages_with_full_span_and_atomic_faults() {
    let addr = 0x2000_0fe0;
    let (mut cpu, mut mem, va) = setup_snippet(&[0xdd, 0x37]); // fnsave (108 bytes)
    mem.map_range(0x2000_0000, 8192, PagePerms::USER_RW);
    cpu.context_mut().gpr[reg::RDI] = addr;
    cpu.context_mut().fxsave.0[..2].copy_from_slice(&0x027fu16.to_le_bytes());
    cpu.step_block(&mut mem).unwrap();
    assert_eq!(&mem.read_direct(addr, 2).unwrap(), &0x027fu16.to_le_bytes());
    assert_eq!(
        &mem.read_direct(addr + 8, 2).unwrap(),
        &0xffffu16.to_le_bytes()
    );
    assert_eq!(&cpu.context_mut().fxsave.0[..2], &0x037fu16.to_le_bytes());
    mem.write_direct(va, &[0xdd, 0x27]); // frstor
    cpu.context_mut().rip = va;
    cpu.step_block(&mut mem).unwrap();
    assert_eq!(&cpu.context_mut().fxsave.0[..2], &0x027fu16.to_le_bytes());
    mem.set_page_perms(0x2000_1000, PagePerms::USER_RO);
    cpu.context_mut().tlb.flush_all();
    mem.write_direct(va, &[0xdd, 0x37]);
    cpu.context_mut().rip = va;
    let before = mem.read_direct(addr, 108).unwrap();
    step_ok(
        &mut cpu,
        &mut mem,
        pf(va, PF_ERR_USER | PF_ERR_WRITE | PF_ERR_PRESENT, 0x2000_1000),
    );
    assert_eq!(mem.read_direct(addr, 108).unwrap(), before);
    assert_eq!(&cpu.context_mut().fxsave.0[..2], &0x027fu16.to_le_bytes());
}

#[test]
fn legacy_save_image_matches_native_x87_formats() {
    use carrick_softcpu_x86::FxsaveArea;
    #[repr(C, align(16))]
    struct NativeX87 {
        guest: FxsaveArea,
        host: FxsaveArea,
        image: [u8; 108],
    }
    let mut run = NativeX87 {
        guest: FxsaveArea::default(),
        host: FxsaveArea::default(),
        image: [0; 108],
    };
    run.guest.0[..2].copy_from_slice(&0x027fu16.to_le_bytes());
    run.guest.0[2..4].copy_from_slice(&0x1800u16.to_le_bytes());
    run.guest.0[4] = 0b1010_0110;
    for i in 0..8 {
        let off = 32 + i * 16;
        let (significand, exponent) = match i % 3 {
            0 => (0u64, 0u16),
            1 => (1u64 << 63, 0x3fff),
            _ => (1u64 << 63, 0x7fff),
        };
        run.guest.0[off..off + 8].copy_from_slice(&significand.to_le_bytes());
        run.guest.0[off + 8..off + 10].copy_from_slice(&exponent.to_le_bytes());
    }
    let (mut cpu, mut mem, _) = setup_snippet(&[0xdd, 0x37]);
    cpu.context_mut().fxsave = run.guest.clone();
    cpu.context_mut().gpr[reg::RDI] = 0x2000_0000;
    mem.map_range(0x2000_0000, 4096, PagePerms::USER_RW);
    cpu.step_block(&mut mem).unwrap();
    let code = [
        0x48, 0x0f, 0xae, 0x87, 0, 2, 0, 0, 0x48, 0x0f, 0xae, 0x0f, 0xdd, 0xb7, 0, 4, 0, 0, 0x48,
        0x0f, 0xae, 0x8f, 0, 2, 0, 0, 0xc3,
    ];
    let mut jit = JitCodeBuffer::new(4096).unwrap();
    let entry = jit.publish(&code).unwrap();
    let execute: unsafe extern "sysv64" fn(*mut NativeX87) =
        unsafe { std::mem::transmute(entry as usize) };
    unsafe {
        execute(&mut run);
    }
    assert_eq!(mem.read_direct(0x2000_0000, 108).unwrap(), run.image);
}

#[test]
fn scalar_cmpsd_never_uses_unchecked_native_copy() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0xf2, 0x0f, 0xc2, 0xc1, 0, 0x0f, 0x05]);
    let planned =
        carrick_softcpu_x86::plan_block_from_memory(va, 64, 4096, cpu.context_mut(), &mut mem)
            .unwrap();
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
fn scalar_cmpsd_reports_guest_invalid_operation() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0xf2, 0x0f, 0xc2, 0xc1, 0, 0x0f, 0x05]);
    cpu.context_mut().write_xmm(0, 0x7ff0_0000_0000_0001);
    cpu.context_mut().write_xmm(1, 1.0f64.to_bits() as u128);
    cpu.context_mut().fxsave.0[24..28].copy_from_slice(&0x1f00u32.to_le_bytes());
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Exception(X86Exception::new(
            X86ExceptionVector::SimdFloatingPoint,
            va,
            None,
            None,
        )),
    );
    assert_eq!(cpu.context_mut().read_xmm(0), 0x7ff0_0000_0000_0001);
}

#[test]
fn fxsave_preserves_software_tail() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0x48, 0x0f, 0xae, 0x07]);
    let addr = 0x2000_0000;
    mem.map_range(addr, 4096, PagePerms::USER_RW);
    mem.write_direct(addr, &[0x55; 512]);
    cpu.context_mut().gpr[reg::RDI] = addr;
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Continue { next_rip: va + 4 },
    );
    assert_eq!(mem.read_direct(addr + 464, 48).unwrap(), [0x55; 48]);
}

#[test]
fn fxsave_pointer_width_follows_rex_w() {
    let (mut cpu, mut mem, va) = setup_snippet(&[0x0f, 0xae, 0x0f]); // fxrstor, REX.W=0
    let addr = 0x2000_0000;
    mem.map_range(addr, 4096, PagePerms::USER_RW);
    let mut image = carrick_softcpu_x86::FxsaveArea::default().0;
    image[8..12].copy_from_slice(&0x89ab_cdefu32.to_le_bytes());
    image[12..14].copy_from_slice(&0x23u16.to_le_bytes());
    image[16..20].copy_from_slice(&0x7654_3210u32.to_le_bytes());
    image[20..22].copy_from_slice(&0x2bu16.to_le_bytes());
    mem.write_direct(addr, &image);
    cpu.context_mut().gpr[reg::RDI] = addr;
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Continue { next_rip: va + 3 },
    );
    cpu.context_mut().gpr[reg::RDI] = addr + 1024;
    mem.write_direct(va, &[0x48, 0x0f, 0xae, 0x07]); // fxsave64
    cpu.context_mut().rip = va;
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Continue { next_rip: va + 4 },
    );
    assert_eq!(
        mem.read_direct(addr + 1032, 8).unwrap(),
        0x89ab_cdefu64.to_le_bytes()
    );
    assert_eq!(
        mem.read_direct(addr + 1040, 8).unwrap(),
        0x7654_3210u64.to_le_bytes()
    );
    mem.write_direct(va, &[0x0f, 0xae, 0x07]); // fxsave, REX.W=0
    cpu.context_mut().rip = va;
    step_ok(
        &mut cpu,
        &mut mem,
        SoftCpuExit::Continue { next_rip: va + 3 },
    );
    assert_eq!(
        mem.read_direct(addr + 1036, 2).unwrap(),
        0x23u16.to_le_bytes()
    );
    assert_eq!(
        mem.read_direct(addr + 1044, 2).unwrap(),
        0x2bu16.to_le_bytes()
    );
}

#[test]
fn sse_helper_validates_memory_before_arithmetic() {
    let bytes = &[0xf3, 0x0f, 0x58, 0x07, 0x0f, 0x05]; // addss xmm0,[rdi]
    for present in [true, false] {
        let (mut cpu, mut mem, va) = setup_snippet(bytes);
        let addr = 0x2000_0ffe;
        mem.map_range(
            0x2000_0000,
            if present { 8192 } else { 4096 },
            PagePerms::USER_RW,
        );
        if present {
            mem.write_direct(addr, &2.0f32.to_bits().to_le_bytes());
        }
        cpu.context_mut().gpr[reg::RDI] = addr;
        cpu.context_mut().write_xmm(0, 1.0f32.to_bits() as u128);
        if present {
            step_ok(&mut cpu, &mut mem, sys(va + 4, va + 6));
            assert_eq!(cpu.context_mut().read_xmm(0), 3.0f32.to_bits() as u128);
        } else {
            step_ok(&mut cpu, &mut mem, pf(va, PF_ERR_USER, 0x2000_1000));
            assert_eq!(cpu.context_mut().read_xmm(0), 1.0f32.to_bits() as u128);
        }
    }
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
        cpu.context_mut().gpr[reg::RAX] = 0x33;
        let flags = cpu.context_mut().rflags;
        assert!(
            matches!(cpu.step_block(&mut mem).unwrap(),SoftCpuExit::Sensitive { rip,next_rip,.. } if rip==va && next_rip==va+3)
        );
        assert_eq!(cpu.context_mut().gpr[reg::RAX], 0x33);
        assert_eq!(cpu.context_mut().rflags, flags);
    }
}
#[test]
fn unsupported_implicit_address_forms_refuse_before_mutation() {
    let cases: &[&[u8]] = &[
        &[0x67, 0xf3, 0xa4], // address-size MOVSB
        &[0x64, 0xa4],
        &[0x65, 0xac], // FS MOVSB, GS LODSB
        &[0x67, 0xd7],
        &[0x64, 0xd7],
        &[0x65, 0xd7], // XLAT
        &[0x0f, 0xa0],
        &[0x0f, 0xa8], // PUSH FS/GS
        &[0x0f, 0xa1],
        &[0x0f, 0xa9], // POP FS/GS
    ];
    for &bytes in cases {
        let (mut cpu, mut mem, va) = setup_snippet(&[bytes, &[0x0f, 0x05]].concat());
        let data = cpu.context().gpr[reg::RSP];
        mem.write_direct(data, &[0x55; 16]);
        let ctx = cpu.context_mut();
        ctx.gpr[reg::RCX] = 1;
        ctx.gpr[reg::RSI] = data;
        ctx.gpr[reg::RDI] = data + 8;
        ctx.gpr[reg::RBX] = data;
        ctx.fs_base = 4096;
        ctx.gs_base = 8192;
        let before = (ctx.gpr, ctx.rflags, ctx.fs_base, ctx.gs_base);
        step_ok(&mut cpu, &mut mem, ud(va));
        let ctx = cpu.context();
        assert_eq!((ctx.gpr, ctx.rflags, ctx.fs_base, ctx.gs_base), before);
        assert_eq!(mem.read_direct(data, 16).unwrap(), [0x55; 16]);
    }
}

#[test]
fn unavailable_features_raise_ud_and_cpuid_matches_the_layer() {
    for bytes in [
        &[0x0f, 0x01, 0xf9][..],
        &[0x0f, 0x01, 0xee],
        &[0x0f, 0x01, 0xef],
    ] {
        let (mut cpu, mut mem, va) = setup_snippet(bytes);
        step_ok(&mut cpu, &mut mem, ud(va));
    }
    let (mut cpu, mut mem, _) = setup_snippet(&[0x0f, 0xa2]);
    cpu.context_mut().gpr[reg::RAX] = 1;
    cpu.step_block(&mut mem).unwrap();
    assert_eq!(cpu.context().gpr[reg::RDX] & ((1 << 24) | 1), 1 << 24);
    assert_eq!(
        cpu.context().gpr[reg::RCX] & ((1 << 26) | (1 << 27)),
        (1 << 26) | (1 << 27)
    );    assert_eq!(
        cpu.context().cr4 & ((1 << 9) | (1 << 18)),
        (1 << 9) | (1 << 18)
    );
    // EM must remain clear for SSE data operations; x87 is absent independently.
    assert_eq!(cpu.context().cr0 & (1 << 2), 0);
    let (mut cpu, mut mem, va) = setup_snippet(&[0xd8, 0xc1]); // x87 arithmetic remains absent
    step_ok(&mut cpu, &mut mem, ud(va));
}

#[test]
fn exact_denormal_results_fault_when_underflow_is_unmasked() {
    for (prefix, left, right) in [
        (
            &[0xf3][..],
            f32::MIN_POSITIVE.to_bits() as u128,
            0.5f32.to_bits() as u128,
        ),
        (
            &[0xf2][..],
            f64::MIN_POSITIVE.to_bits() as u128,
            0.5f64.to_bits() as u128,
        ),
        (
            &[][..],
            u128::from_le_bytes(
                f32::MIN_POSITIVE
                    .to_bits()
                    .to_le_bytes()
                    .repeat(4)
                    .try_into()
                    .unwrap(),
            ),
            u128::from_le_bytes(0.5f32.to_bits().to_le_bytes().repeat(4).try_into().unwrap()),
        ),
        (
            &[0x66][..],
            u128::from_le_bytes(
                f64::MIN_POSITIVE
                    .to_bits()
                    .to_le_bytes()
                    .repeat(2)
                    .try_into()
                    .unwrap(),
            ),
            u128::from_le_bytes(0.5f64.to_bits().to_le_bytes().repeat(2).try_into().unwrap()),
        ),
    ] {
        for ftz in [0, 1 << 15] {
            let code = [prefix, &[0x0f, 0x59, 0xc1, 0x0f, 0x05]].concat(); // mulss/sd/ps/pd
            let (mut cpu, mut mem, va) = setup_snippet(&code);
            cpu.context_mut().write_xmm(0, left);
            cpu.context_mut().write_xmm(1, right);
            cpu.context_mut().fxsave.0[24..28].copy_from_slice(&(0x1780u32 | ftz).to_le_bytes());
            step_ok(
                &mut cpu,
                &mut mem,
                SoftCpuExit::Exception(X86Exception::new(
                    X86ExceptionVector::SimdFloatingPoint,
                    va,
                    None,
                    None,
                )),
            );
            assert_eq!(cpu.context().read_xmm(0), left);
            assert_eq!(
                cpu.context().fxsave.0[24] & 0x30,
                0x10,
                "exact tiny result sets UE, not PE"
            );
        }
    }
    // A selected denormal input and an untouched scalar upper lane are not arithmetic underflow.
    for bytes in [&[0xf3, 0x0f, 0x5d, 0xc1][..], &[0xf3, 0x0f, 0x59, 0xc1]] {
        let (mut cpu, mut mem, va) = setup_snippet(&[bytes, &[0x0f, 0x05]].concat());
        let a = if bytes[2] == 0x5d {
            1
        } else {
            1.0f32.to_bits()
        };
        cpu.context_mut().write_xmm(0, (1u128 << 32) | a as u128);
        cpu.context_mut().write_xmm(1, 1.0f32.to_bits() as u128);
        cpu.context_mut().fxsave.0[24..28].copy_from_slice(&0x1780u32.to_le_bytes());
        step_ok(&mut cpu, &mut mem, sys(va + 4, va + 6));
        assert_eq!(cpu.context().fxsave.0[24] & 0x10, 0);
    }
}

#[test]
fn xrstor_standard_and_compacted_reserved_ranges_follow_the_sdm() {
    for rex in [&[][..], &[0x48][..]] {
        for compact in [false, true] {
            for byte in [528, 535, 536, 575] {
                let code = [rex, &[0x0f, 0xae, 0x2f]].concat(); // xrstor/64 [rdi]
                let (mut cpu, mut mem, va) = setup_snippet(&code);
                let addr = 0x2000_0000;
                mem.map_range(addr, 4096, PagePerms::USER_RW);
                let mut image = [0u8; 576];
                if compact {
                    image[520..528].copy_from_slice(&(1u64 << 63).to_le_bytes());
                }
                image[byte] = 1;
                mem.write_direct(addr, &image);
                cpu.context_mut().gpr[reg::RDI] = addr;
                let expected = if compact || byte < 536 {
                    gp(va)
                } else {
                    SoftCpuExit::Continue {
                        next_rip: va + code.len() as u64,
                    }
                };
                step_ok(&mut cpu, &mut mem, expected);
            }
        }
    }
}

#[test]
fn xsave_header_faults_are_write_faults() {
    for bytes in [
        &[0x0f, 0xae, 0x27][..],
        &[0x0f, 0xae, 0x37],
        &[0x0f, 0xc7, 0x27],
    ] {
        for present in [false, true] {
            let (mut cpu, mut mem, va) = setup_snippet(bytes); // xsave/opt/c [rdi]
            let base = 0x2000_0000;
            mem.map_range(base, 4096, PagePerms::USER_RW);
            if present {
                mem.map_range(base + 4096, 4096, PagePerms::USER_RO);
            }
            cpu.context_mut().gpr[reg::RDI] = base + 4096 - 512;
            step_ok(
                &mut cpu,
                &mut mem,
                pf(
                    va,
                    PF_ERR_USER | PF_ERR_WRITE | if present { PF_ERR_PRESENT } else { 0 },
                    base + 4096,
                ),
            );
        }
    }
}
