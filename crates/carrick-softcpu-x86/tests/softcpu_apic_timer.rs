//! Local xAPIC (`ID`, `TPR`/`CR8`, `PPR`, `EOI`, `SVR`, `IRR`/`ISR`, `ESR`, `ICR`, `LVT` timer),
//! `IA32_TSC_DEADLINE` timer, and two-vCPU wake/IPI equivalence tests (`carrick-sh/carrick#670`).

#![cfg(target_arch = "x86_64")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use carrick_softcpu_x86::{
    ApicCluster, Cpl0CpuidView, DescriptorTablePtr, ExtentRecord, ExtentTable, FrameGpa,
    LAPIC_DEFAULT_PHYS_BASE, LAPIC_DFR_OFFSET, LAPIC_ESR_ILLEGAL_REG_ADDRESS, LAPIC_ESR_OFFSET,
    LAPIC_ESR_RECEIVE_ILLEGAL_VECTOR, LAPIC_ESR_SEND_ILLEGAL_VECTOR, LAPIC_ICR_DELIVERY_FIXED,
    LAPIC_ICR_DEST_MODE_LOGICAL, LAPIC_ICR_HIGH_OFFSET, LAPIC_ICR_LEVEL_ASSERT,
    LAPIC_ICR_LOW_OFFSET, LAPIC_ICR_SHORTHAND_ALL_EXCLUDING_SELF,
    LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF, LAPIC_ICR_SHORTHAND_NONE, LAPIC_ICR_SHORTHAND_SELF,
    LAPIC_LDR_OFFSET, LAPIC_LVT_MASKED, LAPIC_LVT_TIMER_MODE_ONESHOT,
    LAPIC_LVT_TIMER_MODE_PERIODIC, LAPIC_LVT_TIMER_MODE_TSC_DEADLINE, LAPIC_LVT_TIMER_OFFSET,
    LAPIC_MMIO_SIZE, LAPIC_SVR_ENABLE, LAPIC_SVR_OFFSET, LAPIC_TIMER_CCR_OFFSET,
    LAPIC_TIMER_DCR_OFFSET, LAPIC_TIMER_ICR_OFFSET, LAPIC_TPR_OFFSET, LAPIC_VERSION_DEFAULT,
    LinearPlacement, LocalApic, MSR_IA32_APIC_BASE, MSR_IA32_TSC, MSR_IA32_TSC_DEADLINE,
    ManualTscClock, MmioHoles, OwnerGeneration, PF_ERR_WRITE, RootGpa, SOFT_TLB_PAGE_MASK,
    SOFT_TLB_PAGE_SIZE, SoftCpuContext, SoftMachine, SoftMachineExit, SoftMmuMemory, SoftSegment,
    X86Exception, reg,
};

const GEN: OwnerGeneration = OwnerGeneration::FIRST;
const PML4_GPA: u64 = 0x1000;
const PDPT_LOW_GPA: u64 = 0x2000;
const PD_LOW_GPA: u64 = 0x3000;
const PT_LOW_GPA: u64 = 0x4000;
const PDPT_HIGH_GPA: u64 = 0x5000;
const PD_HIGH_GPA: u64 = 0x6000;
const PT_HIGH_GPA: u64 = 0x7000;
const PD_MMIO_GPA: u64 = 0x8000;
const PT_MMIO_GPA: u64 = 0x9000;
const FIRST_FREE_GPA: u64 = 0x1_0000;

const CODE_VA: u64 = 0xffff_8000_0001_0000;
const DATA_VA: u64 = 0xffff_8000_0002_0000;
const STACK_VA: u64 = 0xffff_8000_0003_0000;
const ISR_VA: u64 = 0xffff_8000_0004_0000;

const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_U: u64 = 1 << 2;
const PTE_NX: u64 = 1 << 63;

#[derive(Clone, Copy)]
struct Perms {
    writable: bool,
    executable: bool,
    user: bool,
}

impl Perms {
    const KERNEL_RX: Self = Self {
        writable: false,
        executable: true,
        user: false,
    };
    const KERNEL_RW: Self = Self {
        writable: true,
        executable: false,
        user: false,
    };
}

struct ApicTestMemory {
    _backing: Vec<std::sync::atomic::AtomicU64>,
    placement: LinearPlacement,
    extents: ExtentTable,
    mmio: MmioHoles,
    next_gpa: u64,
}

impl ApicTestMemory {
    fn new() -> Self {
        let len = 512 * 4096;
        let backing: Vec<std::sync::atomic::AtomicU64> = (0..(len + 4096) / 8)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect();
        let base = (backing.as_ptr() as usize + 4095) & !4095;
        let mut extents = ExtentTable::new().unwrap();
        assert!(extents.install(ExtentRecord::new(FrameGpa::new(0), len as u64, GEN)));
        extents.set_root_generation(RootGpa::page_aligned(FrameGpa::new(PML4_GPA)).unwrap(), GEN);
        let mmio = MmioHoles::x86_default();
        // SAFETY: aligned, initialized AtomicU64 allocation remains owned by this fixture.
        let placement = unsafe { LinearPlacement::new(base, len as u64, mmio) }.unwrap();
        let mut mem = Self {
            _backing: backing,
            placement,
            extents,
            mmio,
            next_gpa: FIRST_FREE_GPA,
        };
        let branch = PTE_P | PTE_W | PTE_U;
        mem.write_u64(PML4_GPA, PDPT_LOW_GPA | branch);
        mem.write_u64(PDPT_LOW_GPA, PD_LOW_GPA | branch);
        mem.write_u64(PD_LOW_GPA, PT_LOW_GPA | branch);
        mem.write_u64(PML4_GPA + 256 * 8, PDPT_HIGH_GPA | branch);
        mem.write_u64(PDPT_HIGH_GPA, PD_HIGH_GPA | branch);
        mem.write_u64(PD_HIGH_GPA, PT_HIGH_GPA | branch);

        // Map PDPT_LOW entry 3 (`0xc000_0000..0x1_0000_0000`) -> PD_MMIO -> PT_MMIO so
        // identity-mapped local xAPIC MMIO (`0xfee0_0000`) and relocated pages (`0xfee0_4000`)
        // walk cleanly through the 4-level page tables.
        mem.write_u64(PDPT_LOW_GPA + 3 * 8, PD_MMIO_GPA | branch);
        let pd_idx = ((LAPIC_DEFAULT_PHYS_BASE >> 21) & 0x1ff) * 8;
        mem.write_u64(PD_MMIO_GPA + pd_idx, PT_MMIO_GPA | branch);
        mem.map_mmio_identity_page(LAPIC_DEFAULT_PHYS_BASE);
        mem
    }

    fn map_mmio_identity_page(&mut self, phys_page: u64) {
        self.mmio = self.mmio.with_hole(phys_page, LAPIC_MMIO_SIZE).unwrap();
        // SAFETY: same live allocation and bounds, with one additional excluded MMIO page.
        self.placement = unsafe {
            LinearPlacement::new(
                self.placement.base_host_addr(),
                self.placement.span_bytes(),
                self.mmio,
            )
        }
        .unwrap();
        let pt_idx = ((phys_page >> 12) & 0x1ff) * 8;
        self.write_u64(
            PT_MMIO_GPA + pt_idx,
            (phys_page & SOFT_TLB_PAGE_MASK) | PTE_P | PTE_W | PTE_NX,
        );
    }

    fn alloc_frame(&mut self) -> FrameGpa {
        let gpa = self.next_gpa;
        self.next_gpa += SOFT_TLB_PAGE_SIZE;
        FrameGpa::new(gpa)
    }

    fn map_page(&mut self, va: u64, perms: Perms) -> FrameGpa {
        let frame = self.alloc_frame();
        self.map_va_to_frame(va, frame, perms);
        frame
    }

    fn map_va_to_frame(&mut self, va: u64, frame: FrameGpa, perms: Perms) {
        let idx = ((va >> 12) & 0x1ff) * 8;
        let mut pte = (frame.raw() & SOFT_TLB_PAGE_MASK) | PTE_P;
        if perms.writable {
            pte |= PTE_W;
        }
        if perms.user {
            pte |= PTE_U;
        }
        if !perms.executable {
            pte |= PTE_NX;
        }
        let pt_base = if (va >> 47) == 0 {
            PT_LOW_GPA
        } else {
            PT_HIGH_GPA
        };
        self.write_u64(pt_base + idx, pte);
    }

    fn write_u64(&mut self, gpa: u64, val: u64) {
        assert_eq!(gpa % 8, 0);
        // SAFETY: aligned initialized word in the fixture's private allocation.
        let word = unsafe {
            &*((self.placement.base_host_addr() + gpa as usize)
                as *const std::sync::atomic::AtomicU64)
        };
        word.store(val.to_le(), std::sync::atomic::Ordering::Relaxed);
    }
    fn read_u64(&self, gpa: u64) -> u64 {
        u64::from_le_bytes(self.read_bytes(gpa, 8).try_into().unwrap())
    }
    fn read_u32(&self, gpa: u64) -> u32 {
        u32::from_le_bytes(self.read_bytes(gpa, 4).try_into().unwrap())
    }
    fn read_bytes(&self, gpa: u64, len: usize) -> &[u8] {
        assert!(gpa as usize + len <= self.placement.span_bytes() as usize);
        // SAFETY: CPU is parked and the fixture exclusively owns the allocation.
        unsafe {
            std::slice::from_raw_parts(
                (self.placement.base_host_addr() + gpa as usize) as *const u8,
                len,
            )
        }
    }
    fn write_gpa(&mut self, gpa: u64, bytes: &[u8]) {
        assert!(gpa as usize + bytes.len() <= self.placement.span_bytes() as usize);
        // SAFETY: CPU is parked and the fixture exclusively owns the allocation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (self.placement.base_host_addr() + gpa as usize) as *mut u8,
                bytes.len(),
            );
        }
    }
}

// SAFETY: placement points into the stable owned allocation; descriptor words are aligned atomics.
unsafe impl SoftMmuMemory for ApicTestMemory {
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

use apic_fixture::idt_gate64;

fn enter_cpl0(ctx: &mut SoftCpuContext, rip: u64) {
    ctx.halted = false;
    ctx.set_cpl(0);
    ctx.cs = SoftSegment::kernel_code64(0x08);
    ctx.ss = SoftSegment::kernel_data(0x10);
    ctx.rip = rip;
}

fn setup_apic_machine(
    apic_id: u8,
    code: &[u8],
) -> (SoftMachine<ApicTestMemory>, FrameGpa, FrameGpa) {
    let mut mem = ApicTestMemory::new();
    let code_frame = mem.map_page(CODE_VA, Perms::KERNEL_RX);
    mem.write_gpa(code_frame.raw(), code);
    let data_frame = mem.map_page(DATA_VA, Perms::KERNEL_RW);
    let _stack_frame = mem.map_page(STACK_VA, Perms::KERNEL_RW);
    let isr_frame = mem.map_page(ISR_VA, Perms::KERNEL_RX);

    // GDT at DATA_VA: 0x00 null, 0x08 64-bit DPL0 code, 0x10 DPL0 data.
    let gdt = [0u64, 0x00af_9b00_0000_ffff, 0x00cf_9300_0000_ffff];
    let gdt_bytes: Vec<u8> = gdt.iter().flat_map(|w| w.to_le_bytes()).collect();
    mem.write_gpa(data_frame.raw(), &gdt_bytes);

    let cpuid = Box::new(Cpl0CpuidView::with_tsc_deadline(apic_id, 1_000_000_000));
    let mut machine = SoftMachine::new(mem, cpuid).expect("SoftMachine::new");
    let ctx = machine.context_mut();
    ctx.cr3 = PML4_GPA;
    ctx.gdtr = DescriptorTablePtr::new((gdt_bytes.len() - 1) as u16, DATA_VA);
    ctx.idtr = DescriptorTablePtr::new(0x0fff, DATA_VA + 0x100);
    ctx.gpr[reg::RSP] = STACK_VA + 0x800;
    enter_cpl0(ctx, CODE_VA);
    (machine, data_frame, isr_frame)
}

#[test]
fn local_apic_registers_tpr_cr8_ppr_eoi_esr_and_apic_base_relocation() {
    // Guest CPL0 sequence:
    // 1. Read LAPIC_ID ([rsi + 0x20]) -> r8d, LAPIC_VERSION ([rsi + 0x30]) -> r9d.
    // 2. Write SVR = 0x1ff ([rsi + 0xf0]).
    // 3. mov rax, 9; mov cr8, rax; read LAPIC_TPR ([rsi + 0x80]) -> r10d; read LAPIC_PPR ([rsi + 0xa0]) -> r11d.
    // 4. Write LAPIC_TPR = 0x5a ([rsi + 0x80]); mov r12, cr8.
    // 5. Read unimplemented LAPIC offset [rsi + 0x40] -> triggers ESR_ILLEGAL_REG_ADDRESS;
    // 6. HLT.
    let code = [
        0x44, 0x8B, 0x46, 0x20, // mov r8d, [rsi + 0x20]
        0x44, 0x8B, 0x4E, 0x30, // mov r9d, [rsi + 0x30]
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00,
        0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9
        0x44, 0x0F, 0x22, 0xC0, // mov cr8, rax
        0x44, 0x8B, 0x96, 0x80, 0x00, 0x00, 0x00, // mov r10d, [rsi + 0x80]
        0x44, 0x8B, 0x9E, 0xA0, 0x00, 0x00, 0x00, // mov r11d, [rsi + 0xa0]
        0xC7, 0x86, 0x80, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0x80], 0x5a
        0x45, 0x0F, 0x20, 0xC4, // mov r12, cr8
        0x8B, 0x46, 0x40, // mov eax, [rsi + 0x40] (illegal register offset)
        0xC7, 0x86, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0x280], 0
        0x44, 0x8B, 0xAE, 0x80, 0x02, 0x00, 0x00, // mov r13d, [rsi + 0x280]
        0xF4, // hlt
    ];
    let (mut machine, _, _) = setup_apic_machine(3, &code);
    machine.context_mut().gpr[reg::RSI] = LAPIC_DEFAULT_PHYS_BASE;

    let exit = machine.run(16).unwrap();
    assert!(matches!(exit, SoftMachineExit::Hlt { .. }));
    let ctx = machine.context();
    assert_eq!(
        ctx.gpr[reg::R8] as u32,
        3 << 24,
        "LAPIC_ID must report 3 << 24"
    );
    assert_eq!(ctx.gpr[reg::R9] as u32, LAPIC_VERSION_DEFAULT);
    assert_eq!(
        ctx.gpr[reg::R10] as u32,
        0x90,
        "MOV CR8=9 must set TPR=0x90"
    );
    assert_eq!(ctx.gpr[reg::R11] as u32, 0x90, "PPR must reflect TPR=0x90");
    assert_eq!(
        ctx.gpr[reg::R12],
        0x05,
        "MMIO write TPR=0x5a must update CR8 to 5"
    );
    assert_eq!(
        ctx.lapic().tpr(),
        0x5a,
        "TPR sub-priority bits [3:0] must be preserved"
    );
    assert_eq!(
        ctx.gpr[reg::R13] as u32,
        LAPIC_ESR_ILLEGAL_REG_ADDRESS,
        "illegal register read followed by ESR write must latch ESR[7]"
    );

    // Sending an IPI with vector < 16 sets LAPIC_ESR_SEND_ILLEGAL_VECTOR; injecting < 16 sets RECEIVE_ILLEGAL_VECTOR.
    let lapic = machine.context_mut().lapic_mut();
    let mut dummy_deadline = 0u64;
    lapic.write_reg32(
        LAPIC_ICR_LOW_OFFSET,
        LAPIC_ICR_SHORTHAND_SELF | LAPIC_ICR_DELIVERY_FIXED | 0x0f,
        0,
        &mut dummy_deadline,
    );
    lapic.inject_interrupt(0x07);
    lapic.write_reg32(LAPIC_ESR_OFFSET, 0, 0, &mut dummy_deadline);
    assert_eq!(
        lapic.read_reg32(LAPIC_ESR_OFFSET, 0),
        LAPIC_ESR_SEND_ILLEGAL_VECTOR | LAPIC_ESR_RECEIVE_ILLEGAL_VECTOR
    );

    // Relocate IA32_APIC_BASE to 0xfee0_4000 and verify MMIO moves to the new base.
    let relocated_base = 0xfee0_4000u64;
    machine.mem_mut().map_mmio_identity_page(relocated_base);
    let relocate_code = [
        0x0F, 0x30, // wrmsr (IA32_APIC_BASE = 0xfee0_4900)
        0x44, 0x8B, 0x46, 0x20, // mov r8d, [rsi + 0x20] (at relocated base)
        0xF4, // hlt
    ];
    let code_gpa = Pml4Lookup::code_gpa(&machine);
    machine.mem_mut().write_gpa(code_gpa, &relocate_code);
    let ctx = machine.context_mut();
    enter_cpl0(ctx, CODE_VA);
    ctx.gpr[reg::RCX] = u64::from(MSR_IA32_APIC_BASE.raw());
    let new_apic_base = relocated_base | 0x900;
    ctx.gpr[reg::RAX] = new_apic_base & 0xffff_ffff;
    ctx.gpr[reg::RDX] = new_apic_base >> 32;
    ctx.gpr[reg::RSI] = relocated_base;
    ctx.gpr[reg::R8] = 0;
    assert!(matches!(
        machine.run(8).unwrap(),
        SoftMachineExit::Hlt { .. }
    ));
    assert_eq!(machine.context().gpr[reg::R8] as u32, 3 << 24);

    // Clearing IA32_APIC_BASE.EN (bit 11 = 0) disables local APIC MMIO interception, so writing to
    // the unbacked MMIO hole raises #PF(PF_ERR_WRITE).
    let disable_code = [
        0x0F, 0x30, // wrmsr (IA32_APIC_BASE with EN=0)
        0xC7, 0x86, 0x80, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0x80], 0x10 -> #PF
        0xF4,
    ];
    machine.mem_mut().write_gpa(code_gpa, &disable_code);
    let ctx = machine.context_mut();
    enter_cpl0(ctx, CODE_VA);
    ctx.gpr[reg::RCX] = u64::from(MSR_IA32_APIC_BASE.raw());
    ctx.gpr[reg::RAX] = relocated_base | 0x100; // BSP=1, EN=0
    ctx.gpr[reg::RDX] = 0;
    ctx.gpr[reg::RSI] = relocated_base;
    let (mut cpu, mut mem) = machine.into_parts();
    let _ = cpu.step_block(&mut mem).unwrap(); // wrmsr
    let pf_exit = cpu.step_block(&mut mem).unwrap();
    assert_eq!(
        pf_exit,
        carrick_softcpu_x86::SoftCpuExit::Exception(X86Exception::page_fault(
            CODE_VA + 2,
            PF_ERR_WRITE,
            relocated_base + u64::from(LAPIC_TPR_OFFSET),
        ))
    );
}

struct Pml4Lookup;
impl Pml4Lookup {
    fn code_gpa(machine: &SoftMachine<ApicTestMemory>) -> u64 {
        let idx = ((CODE_VA >> 12) & 0x1ff) * 8;
        machine.mem().read_u64(PT_HIGH_GPA + idx) & SOFT_TLB_PAGE_MASK
    }
}

#[test]
fn interrupt_priority_sti_shadow_and_nested_preemption_with_eoi() {
    // Main code at CODE_VA:
    let main_code = [
        0xFA, // cli
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00,
        0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0xFB, // sti
        0x49, 0xC7, 0xC4, 0x11, 0x11, 0x00, 0x00, // mov r12, 0x1111
        0x49, 0xC7, 0xC5, 0x22, 0x22, 0x00, 0x00, // mov r13, 0x2222
        0xF4, // hlt
    ];

    // ISR for vector 0x40 at ISR_VA + 0x00:
    let isr_40 = [
        0x4C, 0x89, 0x27, // mov [rdi], r12
        0x4C, 0x89, 0x6F, 0x08, // mov [rdi + 8], r13
        0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, // mov eax, [rsi + 0xa0] (PPR)
        0x89, 0x47, 0x10, // mov [rdi + 16], eax
        0xFB, // sti
        0x90, // nop (shadowed by sti)
        0x90, // nop (preemption window for vector 0x60)
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0xb0], 0 (EOI)
        0xFF, 0x47, 0x18, // inc dword ptr [rdi + 24]
        0x48, 0xCF, // iretq
    ];

    // ISR for vector 0x60 (higher priority) at ISR_VA + 0x100:
    let isr_60 = [
        0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, // mov eax, [rsi + 0xa0]
        0x89, 0x47, 0x20, // mov [rdi + 32], eax
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0xb0], 0 (EOI)
        0xFF, 0x47, 0x24, // inc dword ptr [rdi + 36]
        0x48, 0xCF, // iretq
    ];

    // ISR for vector 0x30 (lower priority) at ISR_VA + 0x200:
    let isr_30 = [
        0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, // mov eax, [rsi + 0xa0]
        0x89, 0x47, 0x28, // mov [rdi + 40], eax
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0xb0], 0 (EOI)
        0xFF, 0x47, 0x2C, // inc dword ptr [rdi + 44]
        0x48, 0xCF, // iretq
    ];

    let (mut machine, data_frame, isr_frame) = setup_apic_machine(0, &main_code);
    machine.mem_mut().write_gpa(isr_frame.raw(), &isr_40);
    machine
        .mem_mut()
        .write_gpa(isr_frame.raw() + 0x100, &isr_60);
    machine
        .mem_mut()
        .write_gpa(isr_frame.raw() + 0x200, &isr_30);

    let idt_gpa = data_frame.raw() + 0x100;
    machine.mem_mut().write_gpa(
        idt_gpa + 0x30 * 16,
        &idt_gate64(ISR_VA + 0x200, 0x08, 0, 0, true, false),
    );
    machine.mem_mut().write_gpa(
        idt_gpa + 0x40 * 16,
        &idt_gate64(ISR_VA, 0x08, 0, 0, true, false),
    );
    machine.mem_mut().write_gpa(
        idt_gpa + 0x60 * 16,
        &idt_gate64(ISR_VA + 0x100, 0x08, 0, 0, true, false),
    );

    let scratch_va = DATA_VA + 0x800;
    let scratch_gpa = data_frame.raw() + 0x800;
    let ctx = machine.context_mut();
    ctx.gpr[reg::RSI] = LAPIC_DEFAULT_PHYS_BASE;
    ctx.gpr[reg::RDI] = scratch_va;
    ctx.gpr[reg::R12] = 0;
    ctx.gpr[reg::R13] = 0;

    // Queue both 0x30 and 0x40 before execution begins, and set CR8=4 initially to verify TPR masking.
    machine.context_mut().set_cr8(4);

    // Step 1: `cli`
    assert_eq!(machine.step().unwrap(), None);
    // Step 2: `mov [SVR], 0x1ff` + `sti` (ends at `sti`, arming 1-instruction shadow)
    assert_eq!(machine.step().unwrap(), None);
    assert!(machine.context().interrupt_shadow);
    machine.inject_interrupt(0x30);
    machine.inject_interrupt(0x40);
    // Because CR8 == 4 (TPR == 0x40), neither 0x40 nor 0x30 is deliverable!
    assert!(!machine.context().has_deliverable_apic_interrupt());

    // Lower CR8 to 2 (`TPR = 0x20`) while still inside the 1-instruction `STI` shadow:
    machine.context_mut().set_cr8(2);
    assert!(machine.context().has_deliverable_apic_interrupt());

    // Step 3: Because `interrupt_shadow` is active, `mov r12, 0x1111` (and ONLY `mov r12, 0x1111`)
    // executes before any interrupt is delivered!
    assert_eq!(machine.step().unwrap(), None);
    assert_eq!(machine.context().gpr[reg::R12], 0x1111);
    assert_eq!(machine.context().gpr[reg::R13], 0);
    assert!(!machine.context().interrupt_shadow);

    // Step 4: Now `0x40` (higher priority than `0x30`) is delivered into `isr_40`!
    // It executes up to `sti` inside `isr_40`.
    assert_eq!(machine.step().unwrap(), None);
    // Verify `isr_40` observed R12 == 0x1111, R13 == 0, and PPR == 0x40!
    assert_eq!(machine.mem().read_u64(scratch_gpa), 0x1111);
    assert_eq!(machine.mem().read_u64(scratch_gpa + 8), 0);
    assert_eq!(machine.mem().read_u32(scratch_gpa + 16), 0x40);
    // And `0x30` is still pending in IRR because PPR == 0x40 > 0x30!
    assert!(machine.context().lapic().irr_bit(0x30));
    assert!(machine.context().lapic().isr_bit(0x40));

    // Step 5: Executes the single shadowed `nop` after `sti` inside `isr_40`.
    // `0x30` still cannot preempt `0x40`.
    assert_eq!(machine.step().unwrap(), None);
    assert_eq!(machine.context().rip, ISR_VA + 18);

    // Now inject higher-priority vector `0x60` while `isr_40` is running with `IF == 1`!
    machine.inject_interrupt(0x60);

    // Run to completion: `0x60` preempts `0x40`, runs `isr_60` (PPR == 0x60, EOI, IRETQ),
    // returns to `isr_40` which finishes (EOI, IRETQ), then `0x30` is delivered (`isr_30`:
    // PPR == 0x30, EOI, IRETQ), and finally `mov r13, 0x2222; hlt` runs!
    let exit = machine.run(32).unwrap();
    assert!(matches!(exit, SoftMachineExit::Hlt { .. }));

    assert_eq!(machine.context().gpr[reg::R13], 0x2222);
    assert_eq!(
        machine.mem().read_u32(scratch_gpa + 32),
        0x60,
        "isr_60 must see PPR == 0x60"
    );
    assert_eq!(
        machine.mem().read_u32(scratch_gpa + 36),
        1,
        "isr_60 must run once"
    );
    assert_eq!(
        machine.mem().read_u32(scratch_gpa + 24),
        1,
        "isr_40 must complete once"
    );
    assert_eq!(
        machine.mem().read_u32(scratch_gpa + 40),
        0x30,
        "isr_30 must see PPR == 0x30"
    );
    assert_eq!(
        machine.mem().read_u32(scratch_gpa + 44),
        1,
        "isr_30 must run once"
    );
    assert_eq!(
        machine.context().lapic().ppr(),
        0x20,
        "after all EOIs, PPR must return to TPR (0x20)"
    );
}

#[test]
fn tsc_deadline_and_initial_count_timers_with_injectable_clock_and_bounded_hlt() {
    // Guest code at CODE_VA:
    let code = [
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00,
        0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0xC7, 0x86, 0x20, 0x03, 0x00, 0x00, 0xEF, 0x00, 0x04,
        0x00, // mov dword ptr [rsi + 0x320], 0x400ef
        0xB9, 0xE0, 0x06, 0x00, 0x00, // mov ecx, 0x6e0
        0xB8, 0x10, 0x27, 0x00, 0x00, // mov eax, 10_000
        0x31, 0xD2, // xor edx, edx
        0x0F, 0x30, // wrmsr
        0xFB, // sti
        0xF4, // hlt (woken by TSC-deadline timer!)
        0x49, 0xC7, 0xC6, 0xEF, 0xBE, 0xAD, 0xDE, // mov r14, 0xffffffffdeadbeef
        0xF4, // final hlt
    ];

    // Timer ISR for vector 0xef at ISR_VA:
    let timer_isr = [
        0xB9, 0xE0, 0x06, 0x00, 0x00, // mov ecx, 0x6e0
        0x0F, 0x32, // rdmsr
        0x48, 0xC1, 0xE2, 0x20, // shl rdx, 32
        0x48, 0x09, 0xD0, // or rax, rdx
        0x48, 0x89, 0x07, // mov [rdi], rax
        0xFF, 0x47, 0x08, // inc dword ptr [rdi + 8]
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // mov dword ptr [rsi + 0xb0], 0
        0x48, 0xCF, // iretq
    ];

    let (mut machine, data_frame, isr_frame) = setup_apic_machine(0, &code);
    machine.mem_mut().write_gpa(isr_frame.raw(), &timer_isr);
    let idt_gpa = data_frame.raw() + 0x100;
    machine.mem_mut().write_gpa(
        idt_gpa + 0xef * 16,
        &idt_gate64(ISR_VA, 0x08, 0, 0, true, false),
    );

    let clock = Arc::new(ManualTscClock::new(1_000));
    machine.set_clock(Arc::clone(&clock) as Arc<dyn carrick_softcpu_x86::TscClock>);
    machine.set_hlt_wait_timeout(Some(Duration::from_millis(500)));

    let scratch_va = DATA_VA + 0x800;
    let scratch_gpa = data_frame.raw() + 0x800;
    machine
        .mem_mut()
        .write_u64(scratch_gpa, 0xffff_ffff_ffff_ffff);
    machine.context_mut().gpr[reg::RSI] = LAPIC_DEFAULT_PHYS_BASE;
    machine.context_mut().gpr[reg::RDI] = scratch_va;

    // Unit-check disarming semantics before running the full HLT wakeup:
    {
        let ctx = machine.context_mut();
        ctx.lapic_mmio_write(LAPIC_SVR_OFFSET, &(LAPIC_SVR_ENABLE | 0xff).to_le_bytes());
        ctx.lapic_mmio_write(
            LAPIC_LVT_TIMER_OFFSET,
            &(LAPIC_LVT_TIMER_MODE_TSC_DEADLINE | LAPIC_LVT_MASKED | 0xef).to_le_bytes(),
        );
        let caps = carrick_softcpu_x86::MsrCapabilities::from_cpuid(
            &Cpl0CpuidView::with_tsc_deadline(0, 1_000_000_000),
        );
        ctx.write_msr(MSR_IA32_TSC_DEADLINE, 4_000, caps).unwrap();
        assert_eq!(ctx.msrs().read(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 4_000);
        // Advancing to 3_999 does not expire:
        clock.set(3_999);
        assert!(!ctx.poll_apic_timer());
        assert_eq!(ctx.msrs().read(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 4_000);
        // Advancing to 4_000 while LVT_TIMER is masked expires and disarms MSR to 0 without setting IRR:
        clock.set(4_000);
        assert!(ctx.poll_apic_timer());
        assert_eq!(ctx.msrs().read(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 0);
        assert!(!ctx.lapic().irr_bit(0xef));
        // Switching LVT_TIMER mode away from TSC_DEADLINE disarms IA32_TSC_DEADLINE:
        ctx.write_msr(MSR_IA32_TSC_DEADLINE, 8_000, caps).unwrap();
        ctx.lapic_mmio_write(
            LAPIC_LVT_TIMER_OFFSET,
            &(LAPIC_LVT_TIMER_MODE_ONESHOT | 0xef).to_le_bytes(),
        );
        assert_eq!(ctx.msrs().read(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 0);
    }

    // Now test bounded HLT wakeup driven by advancing ManualTscClock from a peer thread:
    clock.set(2_000);
    let clock_clone = Arc::clone(&clock);
    let advancer = thread::spawn(move || {
        assert!(clock_clone.wait_for_enrolments(1, Duration::from_secs(5)));
        clock_clone.set(10_000);
    });

    // The first `hlt` wakes when `clock_clone.set(10_000)` fires the TSC-deadline timer, runs
    // `timer_isr`, IRETQs to `mov r14, 0xffffffffdeadbeef`, and stops at the second `hlt`
    // (where we clear `hlt_wait_timeout` after the first wake or let the second `hlt` time out).
    machine.set_hlt_wait_timeout(Some(Duration::from_millis(250)));
    let exit = machine.run(32).unwrap();
    advancer.join().unwrap();

    assert!(matches!(exit, SoftMachineExit::Hlt { .. }));
    assert_eq!(
        machine.mem().read_u64(scratch_gpa),
        0,
        "IA32_TSC_DEADLINE must be disarmed (0) when read inside the timer ISR"
    );
    assert_eq!(
        machine.mem().read_u32(scratch_gpa + 8),
        1,
        "TSC-deadline timer ISR must fire exactly once"
    );
    assert_eq!(
        machine.context().gpr[reg::R14],
        0xffff_ffff_dead_beef,
        "IRETQ from timer ISR must resume at the instruction following HLT"
    );

    // Also verify OneShot and Periodic initial-count timer modes on LocalApic:
    let mut lapic = LocalApic::new(0);
    let mut deadline_msr = 0u64;
    lapic.write_reg32(
        LAPIC_SVR_OFFSET,
        LAPIC_SVR_ENABLE | 0xff,
        1_000,
        &mut deadline_msr,
    );
    // Divide by 16 (`DCR = 0b0011`), OneShot vector `0x55`, initial count `100` -> 1600 TSC ticks.
    lapic.write_reg32(LAPIC_TIMER_DCR_OFFSET, 0b0011, 1_000, &mut deadline_msr);
    lapic.write_reg32(
        LAPIC_LVT_TIMER_OFFSET,
        LAPIC_LVT_TIMER_MODE_ONESHOT | 0x55,
        1_000,
        &mut deadline_msr,
    );
    lapic.write_reg32(LAPIC_TIMER_ICR_OFFSET, 100, 1_000, &mut deadline_msr);
    assert_eq!(lapic.read_reg32(LAPIC_TIMER_CCR_OFFSET, 1_800), 50);
    assert!(!lapic.poll_timer(true, 2_599, &mut deadline_msr));
    assert!(lapic.poll_timer(true, 2_600, &mut deadline_msr));
    assert_eq!(lapic.read_reg32(LAPIC_TIMER_CCR_OFFSET, 2_600), 0);
    assert_eq!(lapic.accept_interrupt(true), Some(0x55));
    lapic.eoi();
    // OneShot does not re-fire:
    assert!(!lapic.poll_timer(true, 5_000, &mut deadline_msr));

    // Periodic mode reloads automatically every `100 * 16 = 1600` TSC ticks:
    lapic.write_reg32(
        LAPIC_LVT_TIMER_OFFSET,
        LAPIC_LVT_TIMER_MODE_PERIODIC | 0x56,
        5_000,
        &mut deadline_msr,
    );
    lapic.write_reg32(LAPIC_TIMER_ICR_OFFSET, 100, 5_000, &mut deadline_msr);
    assert!(lapic.poll_timer(true, 6_600, &mut deadline_msr));
    assert_eq!(lapic.accept_interrupt(true), Some(0x56));
    lapic.eoi();
    assert!(!lapic.poll_timer(true, 8_199, &mut deadline_msr));
    assert!(lapic.poll_timer(true, 8_200, &mut deadline_msr));
    assert_eq!(lapic.accept_interrupt(true), Some(0x56));
    lapic.eoi();
}

#[test]
fn icr_ipi_modes_self_broadcast_physical_and_logical_across_apic_cluster() {
    let cluster = Arc::new(ApicCluster::new());
    let mut apic0 = LocalApic::new(0);
    let mut apic1 = LocalApic::new(1);
    let mut apic2 = LocalApic::new(2);
    apic0.attach_cluster(Arc::clone(&cluster));
    apic1.attach_cluster(Arc::clone(&cluster));
    apic2.attach_cluster(Arc::clone(&cluster));

    let mut d = 0u64;
    for apic in [&mut apic0, &mut apic1, &mut apic2] {
        apic.write_reg32(LAPIC_SVR_OFFSET, LAPIC_SVR_ENABLE | 0xff, 0, &mut d);
    }

    // 1. Self IPI (`0x31`) from APIC 0:
    apic0.write_reg32(
        LAPIC_ICR_LOW_OFFSET,
        LAPIC_ICR_SHORTHAND_SELF | LAPIC_ICR_DELIVERY_FIXED | 0x31,
        0,
        &mut d,
    );
    assert!(apic0.irr_bit(0x31));
    assert!(!apic1.irr_bit(0x31));
    assert!(!apic2.irr_bit(0x31));
    assert_eq!(apic0.accept_interrupt(true), Some(0x31));
    apic0.eoi();

    // 2. Broadcast excluding self (`0x32`) from APIC 0:
    apic0.write_reg32(
        LAPIC_ICR_LOW_OFFSET,
        LAPIC_ICR_SHORTHAND_ALL_EXCLUDING_SELF | LAPIC_ICR_DELIVERY_FIXED | 0x32,
        0,
        &mut d,
    );
    assert!(!apic0.irr_bit(0x32));
    assert_eq!(apic1.accept_interrupt(true), Some(0x32));
    assert_eq!(apic2.accept_interrupt(true), Some(0x32));
    apic1.eoi();
    apic2.eoi();

    // 3. Broadcast including self (`0x33`) from APIC 1:
    apic1.write_reg32(
        LAPIC_ICR_LOW_OFFSET,
        LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF | LAPIC_ICR_DELIVERY_FIXED | 0x33,
        0,
        &mut d,
    );
    for apic in [&mut apic0, &mut apic1, &mut apic2] {
        assert_eq!(apic.accept_interrupt(true), Some(0x33));
        apic.eoi();
    }

    // 4. Physical destination (`APIC ID 2`, vector `0x34`) from APIC 0:
    apic0.write_reg32(LAPIC_ICR_HIGH_OFFSET, 2 << 24, 0, &mut d);
    apic0.write_reg32(
        LAPIC_ICR_LOW_OFFSET,
        LAPIC_ICR_SHORTHAND_NONE | LAPIC_ICR_DELIVERY_FIXED | LAPIC_ICR_LEVEL_ASSERT | 0x34,
        0,
        &mut d,
    );
    assert!(!apic0.irr_bit(0x34));
    assert!(!apic1.irr_bit(0x34));
    assert_eq!(apic2.accept_interrupt(true), Some(0x34));
    apic2.eoi();

    // 5. Logical flat mode (`DFR = 0xffff_ffff`, `LDR = (1 << id) << 24`):
    for (id, apic) in [&mut apic0, &mut apic1, &mut apic2].into_iter().enumerate() {
        apic.write_reg32(LAPIC_DFR_OFFSET, 0xffff_ffff, 0, &mut d);
        apic.write_reg32(LAPIC_LDR_OFFSET, (1u32 << id) << 24, 0, &mut d);
    }
    apic0.write_reg32(LAPIC_ICR_HIGH_OFFSET, 0b0110 << 24, 0, &mut d);
    apic0.write_reg32(
        LAPIC_ICR_LOW_OFFSET,
        LAPIC_ICR_DEST_MODE_LOGICAL | LAPIC_ICR_DELIVERY_FIXED | 0x35,
        0,
        &mut d,
    );
    assert!(!apic0.irr_bit(0x35));
    assert_eq!(apic1.accept_interrupt(true), Some(0x35));
    assert_eq!(apic2.accept_interrupt(true), Some(0x35));
    apic1.eoi();
    apic2.eoi();

    // 6. Logical cluster mode (`DFR = 0x0fff_ffff`, `LDR[31:28] = cluster`, `LDR[27:24] = mask`):
    apic1.write_reg32(LAPIC_DFR_OFFSET, 0x0fff_ffff, 0, &mut d);
    apic2.write_reg32(LAPIC_DFR_OFFSET, 0x0fff_ffff, 0, &mut d);
    apic1.write_reg32(LAPIC_LDR_OFFSET, 0x11 << 24, 0, &mut d); // cluster 1, member 0b0001
    apic2.write_reg32(LAPIC_LDR_OFFSET, 0x22 << 24, 0, &mut d); // cluster 2, member 0b0010
    apic0.write_reg32(LAPIC_ICR_HIGH_OFFSET, 0x22 << 24, 0, &mut d);
    apic0.write_reg32(
        LAPIC_ICR_LOW_OFFSET,
        LAPIC_ICR_DEST_MODE_LOGICAL | LAPIC_ICR_DELIVERY_FIXED | 0x36,
        0,
        &mut d,
    );
    assert!(!apic1.irr_bit(0x36));
    assert_eq!(apic2.accept_interrupt(true), Some(0x36));
    apic2.eoi();
}

// ============================================================================
// Two-vCPU wake/IPI fixture: SoftMachine vs /dev/kvm equivalence
// ============================================================================

#[path = "support/apic_fixture.rs"]
mod apic_fixture;

#[test]
fn two_vcpu_wake_and_ipi_fixture_on_softmachine() {
    assert_eq!(
        apic_fixture::run_two_vcpu_fixture_on_softmachine(),
        apic_fixture::expected_outcome()
    );
}

#[test]
fn hlt_deadline_wait_uses_clock_domain_after_guest_tsc_write() {
    #[derive(Debug)]
    struct RecordingClock(std::sync::Mutex<Option<u64>>);
    impl carrick_softcpu_x86::TscClock for RecordingClock {
        fn now_tsc(&self, _hz: u64) -> u64 {
            1_000
        }
        fn wait_until(
            &self,
            deadline: Option<u64>,
            _hz: u64,
            _node: &carrick_softcpu_x86::ApicNode,
            _bound: Duration,
        ) -> bool {
            *self.0.lock().unwrap() = deadline;
            false
        }
    }
    let (mut machine, _, _) = setup_apic_machine(0, &[0xf4]);
    let clock = Arc::new(RecordingClock(std::sync::Mutex::new(None)));
    machine.set_clock(clock.clone());
    machine.set_hlt_wait_timeout(Some(Duration::from_millis(1)));
    let ctx = machine.context_mut();
    ctx.lapic_mmio_write(LAPIC_SVR_OFFSET, &0x1ffu32.to_le_bytes());
    ctx.lapic_mmio_write(
        LAPIC_LVT_TIMER_OFFSET,
        &(LAPIC_LVT_TIMER_MODE_TSC_DEADLINE | 0xef).to_le_bytes(),
    );
    let caps = carrick_softcpu_x86::MsrCapabilities::from_cpuid(&Cpl0CpuidView::with_tsc_deadline(
        0,
        1_000_000_000,
    ));
    ctx.write_msr(MSR_IA32_TSC, 5_000, caps).unwrap();
    ctx.write_msr(MSR_IA32_TSC_DEADLINE, 6_000, caps).unwrap();
    assert!(matches!(
        machine.run(1).unwrap(),
        SoftMachineExit::Hlt { .. }
    ));
    assert_eq!(*clock.0.lock().unwrap(), Some(2_000));
}

#[test]
fn periodic_timer_coalesces_missed_periods_without_catchup_deliveries() {
    for missed in [1u64, 1_000, 1_000_000_000] {
        let mut apic = LocalApic::new(0);
        let mut deadline = 0;
        apic.write_reg32(LAPIC_SVR_OFFSET, 0x1ff, 0, &mut deadline);
        apic.write_reg32(LAPIC_TIMER_DCR_OFFSET, 0b1011, 0, &mut deadline);
        apic.write_reg32(
            LAPIC_LVT_TIMER_OFFSET,
            LAPIC_LVT_TIMER_MODE_PERIODIC | 0x55,
            0,
            &mut deadline,
        );
        apic.write_reg32(LAPIC_TIMER_ICR_OFFSET, 10, 0, &mut deadline);
        let now = 10 * missed + 3;
        assert!(apic.poll_timer(true, now, &mut deadline));
        assert_eq!(apic.timer_fire_count(), 1);
        assert_eq!(apic.accept_interrupt(true), Some(0x55));
        apic.eoi();
        assert_eq!(apic.accept_interrupt(true), None);
        assert!(!apic.poll_timer(true, now, &mut deadline));
        assert_eq!(
            apic.next_timer_deadline_tsc(true, deadline),
            Some((missed + 1) * 10)
        );
    }
}

#[test]
fn repeated_hlt_steps_stay_parked_until_an_interrupt_is_delivered() {
    let (mut machine, _, _) = setup_apic_machine(0, &[0x66, 0xf4, 0x49, 0xff, 0xc4, 0xf4]);
    assert!(
        machine.context().msrs().clock().is_some(),
        "default HLT and RDTSC share a clock"
    );
    assert_eq!(
        machine.run(1).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA,
            next_rip: CODE_VA + 2,
        }
    );
    assert_eq!(
        machine.run(1).unwrap(),
        SoftMachineExit::Hlt {
            rip: CODE_VA,
            next_rip: CODE_VA + 2,
        }
    );
    assert_eq!(
        machine.context().gpr[reg::R12],
        0,
        "HLT must not retire its successor without a wake"
    );
}

#[test]
fn hlt_with_if_clear_does_not_resume_for_a_maskable_ipi() {
    let (mut machine, _, _) = setup_apic_machine(0, &[0xfa, 0xf4, 0x49, 0xff, 0xc4, 0xf4]);
    machine
        .context_mut()
        .lapic_mmio_write(LAPIC_SVR_OFFSET, &0x1ffu32.to_le_bytes());
    assert_eq!(machine.step().unwrap(), None); // CLI retires before the IPI arrives.
    machine.inject_interrupt(0x41);
    assert!(matches!(
        machine.run(8).unwrap(),
        SoftMachineExit::Hlt { .. }
    ));
    assert_eq!(machine.context().gpr[reg::R12], 0);
    assert!(machine.context().lapic().irr_bit(0x41));
}

#[test]
fn lowest_priority_ipi_selects_one_enabled_destination() {
    let cluster = Arc::new(ApicCluster::new());
    let mut first = LocalApic::new(0);
    let mut second = LocalApic::new(1);
    first.attach_cluster(cluster.clone());
    second.attach_cluster(cluster);
    let mut deadline = 0;
    for apic in [&mut first, &mut second] {
        apic.write_reg32(LAPIC_SVR_OFFSET, 0x1ff, 0, &mut deadline);
    }
    first.set_tpr(0x80);
    second.set_tpr(0x20);
    first.write_reg32(
        LAPIC_ICR_LOW_OFFSET,
        LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF
            | carrick_softcpu_x86::LAPIC_ICR_DELIVERY_LOWEST_PRIORITY
            | 0x51,
        0,
        &mut deadline,
    );
    assert!(
        !first.irr_bit(0x51),
        "lowest-priority delivery must not broadcast"
    );
    assert!(second.irr_bit(0x51));
}

fn assert_wide_apic_gp(code: &[u8]) {
    assert_wide_apic_gp_at(code, LAPIC_DEFAULT_PHYS_BASE);
}

fn assert_wide_apic_gp_at(code: &[u8], address: u64) {
    let (mut machine, _, _) = setup_apic_machine(0, code);
    machine.context_mut().gpr[reg::RSI] = address;
    machine.context_mut().cr4 |= 1 << 9; // OSFXSR for SSE/FXRSTOR.
    let (mut cpu, mut mem) = machine.into_parts();
    assert_eq!(
        cpu.step_block(&mut mem).unwrap(),
        carrick_softcpu_x86::SoftCpuExit::Exception(X86Exception::general_protection(CODE_VA, 0)),
    );
}

#[test]
fn wide_apic_lidt_is_gp() {
    assert_wide_apic_gp(&[0x0f, 0x01, 0x1e]);
}

#[test]
fn wide_apic_fxrstor_is_gp() {
    assert_wide_apic_gp(&[0x0f, 0xae, 0x0e]);
}

#[test]
fn wide_apic_frstor_is_gp() {
    assert_wide_apic_gp(&[0xdd, 0x26]);
}

#[test]
fn wide_apic_sse_load_is_gp() {
    assert_wide_apic_gp(&[0x0f, 0x10, 0x06]); // movups xmm0, [rsi]
}

#[test]
fn wide_apic_fp_operand_is_gp() {
    assert_wide_apic_gp(&[0x0f, 0x58, 0x06]); // addps xmm0, [rsi]
}

#[test]
fn wide_apic_idt_gate_is_gp() {
    let (mut machine, _, _) = setup_apic_machine(0, &[0xcd, 0x20]);
    machine.context_mut().idtr = DescriptorTablePtr::new(0xfff, LAPIC_DEFAULT_PHYS_BASE);
    // All three deliveries encounter the APIC page: INT, #GP, then #DF.
    assert_eq!(
        machine.run(1).unwrap(),
        SoftMachineExit::TripleFault {
            last_exception: X86Exception::general_protection(CODE_VA, 0),
        },
    );
}

#[test]
fn deadline_written_at_reset_is_ignored() {
    let (mut machine, _, _) = setup_apic_machine(0, &[0x0f, 0x30]); // wrmsr
    let clock = Arc::new(ManualTscClock::new(1_000));
    machine.set_clock(clock.clone());
    let ctx = machine.context_mut();
    ctx.gpr[reg::RCX] = u64::from(MSR_IA32_TSC_DEADLINE.raw());
    ctx.gpr[reg::RAX] = 2_000;
    let (mut cpu, mut mem) = machine.into_parts();
    cpu.step_block(&mut mem).unwrap();
    let ctx = cpu.context_mut();
    let caps = carrick_softcpu_x86::MsrCapabilities::from_cpuid(&Cpl0CpuidView::with_tsc_deadline(
        0,
        1_000_000_000,
    ));
    assert_eq!(ctx.msrs().read(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 0);
    ctx.lapic_mmio_write(LAPIC_SVR_OFFSET, &0x1ffu32.to_le_bytes());
    ctx.lapic_mmio_write(
        LAPIC_LVT_TIMER_OFFSET,
        &(LAPIC_LVT_TIMER_MODE_TSC_DEADLINE | 0xef).to_le_bytes(),
    );
    clock.set(3_000);
    assert!(!ctx.poll_apic_timer());
    assert!(!ctx.lapic().irr_bit(0xef));
}

#[test]
fn deadline_passed_before_enrolment_returns_without_parking() {
    use carrick_softcpu_x86::TscClock;
    let clock = ManualTscClock::new(10_000);
    let lapic = LocalApic::new(0);
    assert!(clock.wait_until(
        Some(10_000),
        1_000_000_000,
        &lapic.node(),
        Duration::from_secs(1)
    ));
    assert!(!clock.wait_for_enrolments(1, Duration::ZERO));
}

#[test]
fn wide_apic_sse_page_crossing_is_gp() {
    assert_wide_apic_gp_at(&[0x0f, 0x10, 0x06], LAPIC_DEFAULT_PHYS_BASE + 0xff8);
}
