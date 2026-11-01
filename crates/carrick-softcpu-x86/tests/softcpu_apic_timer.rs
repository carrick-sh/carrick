//! Local xAPIC (`ID`, `TPR`/`CR8`, `PPR`, `EOI`, `SVR`, `IRR`/`ISR`, `ESR`, `ICR`, `LVT` timer),
//! `IA32_TSC_DEADLINE` timer, and two-vCPU wake/IPI equivalence tests (`carrick-sh/carrick#670`).

#![cfg(target_arch = "x86_64")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use carrick_softcpu_x86::{
    Access, ApicCluster, AuthenticatedDescriptorWords, AuthenticatedGpa, Cpl0CpuidView,
    DescriptorRefusal, DescriptorTablePtr, ExtentRecord, ExtentTable, FrameGpa, HostVa,
    LAPIC_DEFAULT_PHYS_BASE, LAPIC_DFR_OFFSET, LAPIC_EOI_OFFSET, LAPIC_ESR_ILLEGAL_REG_ADDRESS,
    LAPIC_ESR_OFFSET, LAPIC_ESR_RECEIVE_ILLEGAL_VECTOR, LAPIC_ESR_SEND_ILLEGAL_VECTOR,
    LAPIC_ICR_DELIVERY_FIXED, LAPIC_ICR_DEST_MODE_LOGICAL, LAPIC_ICR_HIGH_OFFSET,
    LAPIC_ICR_LEVEL_ASSERT, LAPIC_ICR_LOW_OFFSET, LAPIC_ICR_SHORTHAND_ALL_EXCLUDING_SELF,
    LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF, LAPIC_ICR_SHORTHAND_NONE, LAPIC_ICR_SHORTHAND_SELF,
    LAPIC_ID_OFFSET, LAPIC_IRR_BASE_OFFSET, LAPIC_ISR_BASE_OFFSET, LAPIC_LDR_OFFSET,
    LAPIC_LVT_ERROR_OFFSET, LAPIC_LVT_MASKED, LAPIC_LVT_TIMER_MODE_ONESHOT,
    LAPIC_LVT_TIMER_MODE_PERIODIC, LAPIC_LVT_TIMER_MODE_TSC_DEADLINE, LAPIC_LVT_TIMER_OFFSET,
    LAPIC_MMIO_SIZE, LAPIC_PPR_OFFSET, LAPIC_SVR_ENABLE, LAPIC_SVR_OFFSET, LAPIC_TIMER_CCR_OFFSET,
    LAPIC_TIMER_DCR_OFFSET, LAPIC_TIMER_ICR_OFFSET, LAPIC_TPR_OFFSET, LAPIC_VERSION_DEFAULT,
    LAPIC_VERSION_OFFSET, LinearPlacement, LiveDescriptorWords, LocalApic, LookupAdmission,
    MSR_IA32_APIC_BASE, MSR_IA32_TSC, MSR_IA32_TSC_DEADLINE, ManualTscClock, MmioHoles,
    OwnerGeneration, PF_ERR_WRITE, RootGpa, SOFT_TLB_PAGE_MASK, SOFT_TLB_PAGE_SIZE, SoftCpuContext,
    SoftMmuMemory, SoftSegment, SoftMachine, SoftMachineExit, Stage1Gpa, X86Exception, reg,
};

const GEN: OwnerGeneration = OwnerGeneration::new(1);
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
    backing: Vec<u8>,
    extents: Arc<ExtentTable>,
    roots: Vec<RootGpa>,
    mmio: MmioHoles,
    next_gpa: u64,
}

impl ApicTestMemory {
    fn new() -> Self {
        let len = 512 * 4096;
        let mut backing = vec![0u8; len];
        let extents = Arc::new(ExtentTable::new().expect("extent table"));
        let base_host = HostVa::new(backing.as_mut_ptr() as usize);
        for page in 0..512u64 {
            let gpa = page * 4096;
            extents
                .insert(ExtentRecord {
                    base_gpa: FrameGpa::new(gpa),
                    byte_len: 4096,
                    host_base: HostVa::new(base_host.raw() + gpa as usize),
                    generation: GEN,
                    allowed: Access {
                        read: true,
                        write: true,
                        execute: true,
                    },
                })
                .expect("insert extent");
        }
        let mut mmio = MmioHoles::new();
        mmio.insert(LAPIC_DEFAULT_PHYS_BASE, LAPIC_MMIO_SIZE);
        let mut mem = Self {
            backing,
            extents,
            roots: vec![RootGpa::page_aligned(FrameGpa::new(PML4_GPA)).unwrap()],
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
        self.mmio.insert(phys_page, LAPIC_MMIO_SIZE);
        let pt_idx = ((phys_page >> 12) & 0x1ff) * 8;
        self.write_u64(PT_MMIO_GPA + pt_idx, (phys_page & SOFT_TLB_PAGE_MASK) | PTE_P | PTE_W | PTE_NX);
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
        let off = gpa as usize;
        self.backing[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }

    fn read_u64(&self, gpa: u64) -> u64 {
        let off = gpa as usize;
        u64::from_le_bytes(self.backing[off..off + 8].try_into().unwrap())
    }

    fn read_u32(&self, gpa: u64) -> u32 {
        let off = gpa as usize;
        u32::from_le_bytes(self.backing[off..off + 4].try_into().unwrap())
    }

    fn write_gpa(&mut self, gpa: u64, bytes: &[u8]) {
        let off = gpa as usize;
        self.backing[off..off + bytes.len()].copy_from_slice(bytes);
    }
}

impl SoftMmuMemory for ApicTestMemory {
    fn extents(&self) -> &ExtentTable {
        &self.extents
    }
    fn generation(&self) -> OwnerGeneration {
        GEN
    }
    fn mmio_holes(&self) -> &MmioHoles {
        &self.mmio
    }
    fn is_registered_root(&self, root: RootGpa) -> bool {
        self.roots.contains(&root)
    }
    fn read_descriptor_words(
        &self,
        _admission: LookupAdmission<'_>,
        table_gpa: AuthenticatedGpa,
        index: usize,
    ) -> Result<AuthenticatedDescriptorWords, DescriptorRefusal> {
        let offset = (table_gpa.raw() as usize)
            .checked_add(index.checked_mul(8).ok_or(DescriptorRefusal::OutOfBounds)?)
            .ok_or(DescriptorRefusal::OutOfBounds)?;
        let bytes: [u8; 8] = self
            .backing
            .get(offset..offset + 8)
            .ok_or(DescriptorRefusal::OutOfBounds)?
            .try_into()
            .map_err(|_| DescriptorRefusal::OutOfBounds)?;
        Ok(LiveDescriptorWords::from_Single(u64::from_le_bytes(bytes))
            .authenticate(table_gpa.generation()))
    }
    fn compare_exchange_descriptor_low(
        &mut self,
        _admission: LookupAdmission<'_>,
        table_gpa: AuthenticatedGpa,
        index: usize,
        expected_low: u64,
        desired_low: u64,
    ) -> Result<u64, DescriptorRefusal> {
        let offset = (table_gpa.raw() as usize)
            .checked_add(index.checked_mul(8).ok_or(DescriptorRefusal::OutOfBounds)?)
            .ok_or(DescriptorRefusal::OutOfBounds)?;
        let observed = u64::from_le_bytes(
            self.backing
                .get(offset..offset + 8)
                .ok_or(DescriptorRefusal::OutOfBounds)?
                .try_into()
                .map_err(|_| DescriptorRefusal::OutOfBounds)?,
        );
        if observed == expected_low {
            self.backing[offset..offset + 8].copy_from_slice(&desired_low.to_le_bytes());
        }
        Ok(observed)
    }
    fn stage1_to_frame(&self, s1: Stage1Gpa, _placement: LinearPlacement) -> Option<FrameGpa> {
        Some(FrameGpa::new(s1.raw()))
    }
}

fn idt_gate64(handler: u64, selector: u16, ist: u8, dpl: u8, present: bool, trap_gate: bool) -> [u8; 16] {
    let mut gate = [0u8; 16];
    gate[0..2].copy_from_slice(&(handler as u16).to_le_bytes());
    gate[2..4].copy_from_slice(&selector.to_le_bytes());
    gate[4] = ist & 0x7;
    let gate_type = if trap_gate { 0x0f } else { 0x0e };
    gate[5] = gate_type | ((dpl & 3) << 5) | if present { 0x80 } else { 0 };
    gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
    gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
    gate
}

fn enter_cpl0(ctx: &mut SoftCpuContext, rip: u64) {
    ctx.set_cpl(0);
    ctx.cs = SoftSegment::kernel_code64(0x08);
    ctx.ss = SoftSegment::kernel_data(0x10);
    ctx.rip = rip;
}

fn setup_apic_machine(apic_id: u8, code: &[u8]) -> (SoftMachine<ApicTestMemory>, FrameGpa, FrameGpa) {
    let mut mem = ApicTestMemory::new();
    let code_frame = mem.map_page(CODE_VA, Perms::KERNEL_RX);
    mem.write_gpa(code_frame.raw(), code);
    let data_frame = mem.map_page(DATA_VA, Perms::KERNEL_RW);
    let stack_frame = mem.map_page(STACK_VA, Perms::KERNEL_RW);
    let isr_frame = mem.map_page(ISR_VA, Perms::KERNEL_RX);

    // GDT at DATA_VA: 0x00 null, 0x08 64-bit DPL0 code, 0x10 DPL0 data.
    let gdt = [
        0u64,
        0x00af_9b00_0000_ffff,
        0x00cf_9300_0000_ffff,
    ];
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
    //    write 0 to LAPIC_ESR ([rsi + 0x280]); read LAPIC_ESR ([rsi + 0x280]) -> r13d.
    // 6. HLT.
    let code = [
        0x44, 0x8B, 0x46, 0x20, // mov r8d, [rsi + 0x20]
        0x44, 0x8B, 0x4E, 0x30, // mov r9d, [rsi + 0x30]
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9
        0x44, 0x0F, 0x22, 0xC0, // mov cr8, rax
        0x44, 0x8B, 0x96, 0x80, 0x00, 0x00, 0x00, // mov r10d, [rsi + 0x80]
        0x44, 0x8B, 0x9E, 0xA0, 0x00, 0x00, 0x00, // mov r11d, [rsi + 0xa0]
        0xC7, 0x86, 0x80, 0x00, 0x00, 0x00, 0x5A, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0x80], 0x5a
        0x44, 0x0F, 0x20, 0xC4, // mov r12, cr8
        0x8B, 0x46, 0x40, // mov eax, [rsi + 0x40] (illegal register offset)
        0xC7, 0x86, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0x280], 0
        0x44, 0x8B, 0xAE, 0x80, 0x02, 0x00, 0x00, // mov r13d, [rsi + 0x280]
        0xF4, // hlt
    ];
    let (mut machine, _, _) = setup_apic_machine(3, &code);
    machine.context_mut().gpr[reg::RSI] = LAPIC_DEFAULT_PHYS_BASE;

    let exit = machine.run(16).unwrap();
    assert!(matches!(exit, SoftMachineExit::Hlt { .. }));
    let ctx = machine.context();
    assert_eq!(ctx.gpr[reg::R8] as u32, 3 << 24, "LAPIC_ID must report 3 << 24");
    assert_eq!(ctx.gpr[reg::R9] as u32, LAPIC_VERSION_DEFAULT);
    assert_eq!(ctx.gpr[reg::R10] as u32, 0x90, "MOV CR8=9 must set TPR=0x90");
    assert_eq!(ctx.gpr[reg::R11] as u32, 0x90, "PPR must reflect TPR=0x90");
    assert_eq!(ctx.gpr[reg::R12], 0x05, "MMIO write TPR=0x5a must update CR8 to 5");
    assert_eq!(ctx.lapic().tpr(), 0x5a, "TPR sub-priority bits [3:0] must be preserved");
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
    assert!(matches!(machine.run(8).unwrap(), SoftMachineExit::Hlt { .. }));
    assert_eq!(machine.context().gpr[reg::R8] as u32, 3 << 24);

    // Clearing IA32_APIC_BASE.EN (bit 11 = 0) disables local APIC MMIO interception, so writing to
    // the unbacked MMIO hole raises #PF(PF_ERR_WRITE).
    let disable_code = [
        0x0F, 0x30, // wrmsr (IA32_APIC_BASE with EN=0)
        0xC7, 0x46, 0x80, 0x10, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0x80], 0x10 -> #PF
        0xF4,
    ];
    machine.mem_mut().write_gpa(code_gpa, &disable_code);
    let ctx = machine.context_mut();
    enter_cpl0(ctx, CODE_VA);
    ctx.gpr[reg::RCX] = u64::from(MSR_IA32_APIC_BASE.raw());
    ctx.gpr[reg::RAX] = relocated_base | 0x100; // BSP=1, EN=0
    ctx.gpr[reg::RDX] = 0;
    ctx.gpr[reg::RSI] = relocated_base;
    let _ = machine.cpu_mut().step_block(machine.mem_mut()).unwrap(); // wrmsr
    let pf_exit = machine.cpu_mut().step_block(machine.mem_mut()).unwrap();
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
    //   cli
    //   mov dword ptr [rsi + 0xf0], 0x1ff   ; SVR enable
    //   sti                                  ; arms 1-insn STI shadow
    //   mov r12, 0x1111                      ; executes inside STI shadow BEFORE pending interrupt!
    //   mov r13, 0x2222                      ; executes AFTER ISR returns!
    //   hlt
    let main_code = [
        0xFA, // cli
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0xFB, // sti
        0x49, 0xC7, 0xC4, 0x11, 0x11, 0x00, 0x00, // mov r12, 0x1111
        0x49, 0xC7, 0xC5, 0x22, 0x22, 0x00, 0x00, // mov r13, 0x2222
        0xF4, // hlt
    ];

    // ISR for vector 0x40 at ISR_VA + 0x00:
    //    Records r12 and r13 at entry into [rdi + 0] and [rdi + 8],
    //   records PPR ([rsi + 0xa0]) into [rdi + 16],
    //   enables interrupts (`sti`) and executes a `nop` (so higher-priority 0x60 can preempt while 0x30 cannot!),
    //   writes EOI ([rsi + 0xb0] = 0),
    //   increments [rdi + 24] (0x40 completion counter),
    //   iretq.
    let isr_40 = [
        0x4C, 0x89, 0x27, // mov [rdi], r12
        0x4C, 0x89, 0x6F, 0x08, // mov [rdi + 8], r13
        0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, // mov eax, [rsi + 0xa0] (PPR)
        0x89, 0x47, 0x10, // mov [rdi + 16], eax
        0xFB, // sti
        0x90, // nop (shadowed by sti)
        0x90, // nop (preemption window for vector 0x60)
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0xb0], 0 (EOI)
        0xFF, 0x47, 0x18, // inc dword ptr [rdi + 24]
        0x48, 0xCF, // iretq
    ];

    // ISR for vector 0x60 (higher priority) at ISR_VA + 0x100:
    //   Reads PPR ([rsi + 0xa0]) -> [rdi + 32],
    //   writes EOI ([rsi + 0xb0] = 0),
    //   increments [rdi + 36],
    //   iretq.
    let isr_60 = [
        0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, // mov eax, [rsi + 0xa0]
        0x89, 0x47, 0x20, // mov [rdi + 32], eax
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0xb0], 0 (EOI)
        0xFF, 0x47, 0x24, // inc dword ptr [rdi + 36]
        0x48, 0xCF, // iretq
    ];

    // ISR for vector 0x30 (lower priority) at ISR_VA + 0x200:
    //   Reads PPR ([rsi + 0xa0]) -> [rdi + 40],
    //   writes EOI ([rsi + 0xb0] = 0),
    //   increments [rdi + 44],
    //   iretq.
    let isr_30 = [
        0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, // mov eax, [rsi + 0xa0]
        0x89, 0x47, 0x28, // mov [rdi + 40], eax
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0xb0], 0 (EOI)
        0xFF, 0x47, 0x2C, // inc dword ptr [rdi + 44]
        0x48, 0xCF, // iretq
    ];

    let (mut machine, data_frame, isr_frame) = setup_apic_machine(0, &main_code);
    machine.mem_mut().write_gpa(isr_frame.raw(), &isr_40);
    machine.mem_mut().write_gpa(isr_frame.raw() + 0x100, &isr_60);
    machine.mem_mut().write_gpa(isr_frame.raw() + 0x200, &isr_30);

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
    machine.inject_interrupt(0x30);
    machine.inject_interrupt(0x40);

    // Step 1: `cli`
    assert_eq!(machine.step().unwrap(), None);
    // Step 2: `mov [SVR], 0x1ff` + `sti` (ends at `sti`, arming 1-instruction shadow)
    assert_eq!(machine.step().unwrap(), None);
    assert!(machine.context().interrupt_shadow);
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
    assert_eq!(machine.mem().read_u32(scratch_gpa + 32), 0x60, "isr_60 must see PPR == 0x60");
    assert_eq!(machine.mem().read_u32(scratch_gpa + 36), 1, "isr_60 must run once");
    assert_eq!(machine.mem().read_u32(scratch_gpa + 24), 1, "isr_40 must complete once");
    assert_eq!(machine.mem().read_u32(scratch_gpa + 40), 0x30, "isr_30 must see PPR == 0x30");
    assert_eq!(machine.mem().read_u32(scratch_gpa + 44), 1, "isr_30 must run once");
    assert_eq!(machine.context().lapic().ppr(), 0x20, "after all EOIs, PPR must return to TPR (0x20)");
}

#[test]
fn tsc_deadline_and_initial_count_timers_with_injectable_clock_and_bounded_hlt() {
    // Guest code at CODE_VA:
    //   mov dword ptr [rsi + 0xf0], 0x1ff             ; SVR software enable
    //   mov dword ptr [rsi + 0x320], 0x0004_00ef      ; LVT_TIMER = TSC-Deadline mode (0b10 << 17) | vector 0xef
    //   mov ecx, 0x6e0                                ; MSR_IA32_TSC_DEADLINE
    //   mov eax, 10_000
    //   xor edx, edx
    //   wrmsr                                         ; arm deadline = 10_000
    //   sti
    //   hlt                                           ; wait for timer expiry
    //   mov r14, 0xdead_beef                          ; reached after timer ISR IRETQ
    //   hlt
    let code = [
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0xC7, 0x86, 0x20, 0x03, 0x00, 0x00, 0xEF, 0x00, 0x04, 0x00, // mov dword ptr [rsi + 0x320], 0x400ef
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
    //   mov ecx, 0x6e0
    //   rdmsr                        ; IA32_TSC_DEADLINE must read 0 after firing!
    //   shl rdx, 32
    //   or rax, rdx
    //   mov [rdi], rax               ; store post-expiry IA32_TSC_DEADLINE value
    //   inc dword ptr [rdi + 8]      ; increment timer ISR counter
    //   mov dword ptr [rsi + 0xb0], 0 ; EOI
    //   iretq
    let timer_isr = [
        0xB9, 0xE0, 0x06, 0x00, 0x00, // mov ecx, 0x6e0
        0x0F, 0x32, // rdmsr
        0x48, 0xC1, 0xE2, 0x20, // shl rdx, 32
        0x48, 0x09, 0xD0, // or rax, rdx
        0x48, 0x89, 0x07, // mov [rdi], rax
        0xFF, 0x47, 0x08, // inc dword ptr [rdi + 8]
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0xb0], 0
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
    machine.mem_mut().write_u64(scratch_gpa, 0xffff_ffff_ffff_ffff);
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
        let caps = ctx.msr_capabilities();
        ctx.write_msr(MSR_IA32_TSC_DEADLINE, 4_000, caps).unwrap();
        assert_eq!(ctx.read_msr(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 4_000);
        // Advancing to 3_999 does not expire:
        clock.set(3_999);
        assert!(!ctx.poll_apic_timer());
        assert_eq!(ctx.read_msr(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 4_000);
        // Advancing to 4_000 while LVT_TIMER is masked expires and disarms MSR to 0 without setting IRR:
        clock.set(4_000);
        assert!(ctx.poll_apic_timer());
        assert_eq!(ctx.read_msr(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 0);
        assert!(!ctx.lapic().irr_bit(0xef));
        // Switching LVT_TIMER mode away from TSC_DEADLINE disarms IA32_TSC_DEADLINE:
        ctx.write_msr(MSR_IA32_TSC_DEADLINE, 8_000, caps).unwrap();
        ctx.lapic_mmio_write(
            LAPIC_LVT_TIMER_OFFSET,
            &(LAPIC_LVT_TIMER_MODE_ONESHOT | 0xef).to_le_bytes(),
        );
        assert_eq!(ctx.read_msr(MSR_IA32_TSC_DEADLINE, caps).unwrap(), 0);
    }

    // Now test bounded HLT wakeup driven by advancing ManualTscClock from a peer thread:
    clock.set(2_000);
    let clock_Clone = Arc::clone(&clock);
    let advancer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        clock_Clone.set(10_000);
    });

    // The first `hlt` wakes when `clock_Clone.set(10_000)` fires the TSC-deadline timer, runs
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
    lapic.write_reg32(LAPIC_SVR_OFFSET, LAPIC_SVR_ENABLE | 0xff, 1_000, &mut deadline_msr);
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

const TWO_VCPU_RAM_SIZE: usize = 0x4_0000; // 256 KiB identity-mapped RAM
const TWO_VCPU_PML4_GPA: u64 = 0x1000;
const TWO_VCPU_PDPT_GPA: u64 = 0x2000;
const TWO_VCPU_PD0_GPA: u64 = 0x3000;
const TWO_VCPU_PT0_GPA: u64 = 0x4000;
const TWO_VCPU_PD3_GPA: u64 = 0x5000;
const TWO_VCPU_PT_LAPIC_GPA: u64 = 0x6000;
const TWO_VCPU_GDT_GPA: u64 = 0x7000;
const TWO_VCPU_IDT0_GPA: u64 = 0x8000;
const TWO_VCPU_IDT1_GPA: u64 = 0x9000;
const TWO_VCPU_BSP_CODE_GPA: u64 = 0xa000;
const TWO_VCPU_AP_CODE_GPA: u64 = 0xb000;
const TWO_VCPU_BSP_ISR_GPA: u64 = 0xc000;
const TWO_VCPU_AP_ISR_GPA: u64 = 0xd000;
const TWO_VCPU_BSP_STACK_GPA: u64 = 0xe000;
const TWO_VCPU_AP_STACK_GPA: u64 = 0xf000;
const TWO_VCPU_SHARED_GPA: u64 = 0x1_0000;

const IPI_PING_VEC: u8 = 0x41;
const IPI_PONG_VEC: u8 = 0x42;
const EXIT_PORT: u16 = 0xf4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TwoVcpuFixtureOutcome {
    bsp_apic_id: u32,
    ap_apic_id: u32,
    ap_ready: u32,
    ap_ipi_count: u32,
    ap_isr_during: u32,
    ap_isr_after_eoi: u32,
    bsp_ipi_count: u32,
    bsp_isr_during: u32,
    bsp_isr_after_eoi: u32,
    ap_done: u32,
    bsp_done: u32,
    bsp_exit_port_val: u32,
    ap_exit_port_val: u32,
}

fn build_two_vcpu_guest_image() -> Vec<u8> {
    let mut ram = vec![0u8; TWO_VCPU_RAM_SIZE];
    let put_u64 = |buf: &mut [u8], gpa: u64, val: u64| {
        let off = gpa as usize;
        buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
    };
    let put_bytes = |buf: &mut [u8], gpa: u64, bytes: &[u8]| {
        let off = gpa as usize;
        buf[off..off + bytes.len()].copy_from_slice(bytes);
    };

    // 4-level identity-mapped page tables:
    // - 0x0000_0000..0x0004_0000 (64 x 4 KiB pages) RWX
    // - 0xfee0_0000..0xfee0_1000 (local xAPIC MMIO page) RW + NX
    let branch = PTE_P | PTE_W | PTE_U;
    put_u64(&mut ram, TWO_VCPU_PML4_GPA, TWO_VCPU_PDPT_GPA | branch);
    put_u64(&mut ram, TWO_VCPU_PDPT_GPA, TWO_VCPU_PD0_GPA | branch);
    put_u64(&mut ram, TWO_VCPU_PD0_GPA, TWO_VCPU_PT0_GPA | branch);
    for page in 0..64u64 {
        let gpa = page * 4096;
        put_u64(&mut ram, TWO_VCPU_PT0_GPA + page * 8, gpa | PTE_P | PTE_W);
    }
    put_u64(&mut ram, TWO_VCPU_PDPT_GPA + 3 * 8, TWO_VCPU_PD3_GPA | branch);
    let pd_lapic_idx = ((LAPIC_DEFAULT_PHYS_BASE >> 21) & 0x1ff) * 8;
    put_u64(
        &mut ram,
        TWO_VCPU_PD3_GPA + pd_lapic_idx,
        TWO_VCPU_PT_LAPIC_GPA | branch,
    );
    let pt_lapic_idx = ((LAPIC_DEFAULT_PHYS_BASE >> 12) & 0x1ff) * 8;
    put_u64(
        &mut ram,
        TWO_VCPU_PT_LAPIC_GPA + pt_lapic_idx,
        LAPIC_DEFAULT_PHYS_BASE | PTE_P | PTE_W | PTE_NX,
    );

    // GDT at TWO_VCPU_GDT_GPA: 0x00 null, 0x08 64-bit kernel code, 0x10 kernel data.
    put_u64(&mut ram, TWO_VCPU_GDT_GPA, 0);
    put_u64(&mut ram, TWO_VCPU_GDT_GPA + 8, 0x00af_9b00_0000_ffff);
    put_u64(&mut ram, TWO_VCPU_GDT_GPA + 16, 0x00cf_9300_0000_ffff);

    // IDT0 (BSP): vector 0x42 (`IPI_PONG_VEC`) -> TWO_VCPU_BSP_ISR_GPA
    put_bytes(
        &mut ram,
        TWO_VCPU_IDT0_GPA + u64::from(IPI_PONG_VEC) * 16,
        &idt_gate64(TWO_VCPU_BSP_ISR_GPA, 0x08, 0, 0, true, false),
    );
    // IDT1 (AP): vector 0x41 (`IPI_PING_VEC`) -> TWO_VCPU_AP_ISR_GPA
    put_bytes(
        &mut ram,
        TWO_VCPU_IDT1_GPA + u64::from(IPI_PING_VEC) * 16,
        &idt_gate64(TWO_VCPU_AP_ISR_GPA, 0x08, 0, 0, true, false),
    );

    // Shared memory layout at TWO_VCPU_SHARED_GPA (`rdi` points here on both vCPUs;
    // `rsi` points to `LAPIC_DEFAULT_PHYS_BASE = 0xfee0_0000` on both vCPUs):
    //   [rdi + 0x00]: bsp_apic_id
    //   [rdi + 0x04]: ap_apic_id
    //   [rdi + 0x08]: ap_ready
    //   [rdi + 0x0c]: ap_ipi_count
    //   [rdi + 0x10]: ap_isr_during (word 2 of LAPIC_ISR at offset 0x120: bit 9 = 1 << 9)
    //   [rdi + 0x14]: ap_isr_after_eoi
    //   [rdi + 0x18]: bsp_ipi_count
    //   [rdi + 0x1c]: bsp_isr_during (word 2 of LAPIC_ISR at offset 0x120: bit 10 = 1 << 10)
    //   [rdi + 0x20]: bsp_isr_after_eoi
    //   [rdi + 0x24]: ap_done
    //   [rdi + 0x28]: bsp_done

    // AP (vCPU 1) code at TWO_VCPU_AP_CODE_GPA:
    //   cli
    //   mov dword ptr [rsi + 0xf0], 0x1ff          ; SVR software enable
    //   mov eax, [rsi + 0x20]                      ; read LAPIC_ID
    //   shr eax, 24
    //   mov [rdi + 0x04], eax                      ; store ap_apic_id
    //   mov dword ptr [rdi + 0x08], 1              ; ap_ready = 1
    //   sti                                        ; 1-instruction shadow covers hlt
    //   hlt                                        ; wait for BSP's ping IPI (0x41)
    //   mov dword ptr [rdi + 0x24], 1              ; ap_done = 1
    //   mov al, 0x41
    //   out 0xf4, al
    //   hlt
    let ap_code = [
        0xFA, // cli
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0x8B, 0x46, 0x20, // mov eax, [rsi + 0x20]
        0xC1, 0xE8, 0x18, // shr eax, 24
        0x89, 0x47, 0x04, // mov [rdi + 0x04], eax
        0xC7, 0x47, 0x08, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rdi + 0x08], 1
        0xFB, // sti
        0xF4, // hlt
        0xC7, 0x47, 0x24, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rdi + 0x24], 1
        0xB0, 0x41, // mov al, 0x41
        0xE6, 0xF4, // out 0xf4, al
        0xF4, // hlt
    ];
    put_bytes(&mut ram, TWO_VCPU_AP_CODE_GPA, &ap_code);

    // AP ISR (vector 0x41) at TWO_VCPU_AP_ISR_GPA:
    //   inc dword ptr [rdi + 0x0c]                 ; ap_ipi_count += 1
    //   mov eax, [rsi + 0x120]                     ; LAPIC_ISR word 2 (vectors 0x40..0x5f)
    //   mov [rdi + 0x10], eax                      ; ap_isr_during
    //   mov dword ptr [rsi + 0xb0], 0              ; EOI
    //   mov eax, [rsi + 0x120]                     ; LAPIC_ISR word 2 after EOI
    //   mov [rdi + 0x14], eax                      ; ap_isr_after_eoi
    //   mov dword ptr [rsi + 0x310], 0             ; ICR_HIGH = dest APIC ID 0
    //   mov dword ptr [rsi + 0x300], 0x0000_4042   ; ICR_LOW = Fixed | Assert | 0x42 (pong IPI to BSP)
    //   iretq
    let ap_isr = [
        0xFF, 0x47, 0x0C, // inc dword ptr [rdi + 0x0c]
        0x8B, 0x86, 0x20, 0x01, 0x00, 0x00, // mov eax, [rsi + 0x120]
        0x89, 0x47, 0x10, // mov [rdi + 0x10], eax
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0xb0], 0
        0x8B, 0x86, 0x20, 0x01, 0x00, 0x00, // mov eax, [rsi + 0x120]
        0x89, 0x47, 0x14, // mov [rdi + 0x14], eax
        0xC7, 0x86, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0x310], 0
        0xC7, 0x86, 0x00, 0x03, 0x00, 0x00, 0x42, 0x40, 0x00, 0x00, // mov dword ptr [rsi + 0x300], 0x4042
        0x48, 0xCF, // iretq
    ];
    put_bytes(&mut ram, TWO_VCPU_AP_ISR_GPA, &ap_isr);

    // BSP (vCPU 0) code at TWO_VCPU_BSP_CODE_GPA:
    //   cli
    //   mov dword ptr [rsi + 0xf0], 0x1ff          ; SVR software enable
    //   mov eax, [rsi + 0x20]                      ; read LAPIC_ID
    //   shr eax, 24
    //   mov [rdi + 0x00], eax                      ; store bsp_apic_id
    // wait_ap_ready:
    //   cmp dword ptr [rdi + 0x08], 1
    //   je send_ping
    //   pause
    //   jmp short wait_ap_ready
    // send_ping:
    //   mov dword ptr [rsi + 0x310], 0x0100_0000   ; ICR_HIGH = dest APIC ID 1
    //   mov dword ptr [rsi + 0x300], 0x0000_4041   ; ICR_LOW = Fixed | Assert | 0x41 (ping IPI to AP)
    //   sti                                        ; 1-instruction shadow covers hlt
    //   hlt                                        ; wait for AP's pong IPI (0x42)
    // wait_ap_done:
    //   cmp dword ptr [rdi + 0x24], 1
    //   je finish_bsp
    //   pause
    //   jmp short wait_ap_done
    // finish_bsp:
    //   mov dword ptr [rdi + 0x28], 1              ; bsp_done = 1
    //   mov al, 0x42
    //   out 0xf4, al
    //   hlt
    let bsp_code = [
        0xFA, // cli
        0xC7, 0x86, 0xF0, 0x00, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x00, // mov dword ptr [rsi + 0xf0], 0x1ff
        0x8B, 0x46, 0x20, // mov eax, [rsi + 0x20]
        0xC1, 0xE8, 0x18, // shr eax, 24
        0x89, 0x07, // mov [rdi], eax
        // wait_ap_ready:
        0x83, 0x7F, 0x08, 0x01, // cmp dword ptr [rdi + 0x08], 1
        0x74, 0x04, // je +4 (send_ping)
        0xF3, 0x90, // pause
        0xEB, 0xF6, // jmp wait_ap_ready
        // send_ping:
        0xC7, 0x86, 0x10, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // mov dword ptr [rsi + 0x310], 1 << 24
        0xC7, 0x86, 0x00, 0x03, 0x00, 0x00, 0x41, 0x40, 0x00, 0x00, // mov dword ptr [rsi + 0x300], 0x4041
        0xFB, // sti
        0xF4, // hlt
        // wait_ap_done:
        0x83, 0x7F, 0x24, 0x01, // cmp dword ptr [rdi + 0x24], 1
        0x74, 0x04, // je +4 (finish_bsp)
        0xF3, 0x90, // pause
        0xEB, 0xF6, // jmp wait_ap_done
        // finish_bsp:
        0xC7, 0x47, 0x28, 0x01, 0x00, 0x00, 0x00, // mov dword ptr [rdi + 0x28], 1
        0xB0, 0x42, // mov al, 0x42
        0xE6, 0xF4, // out 0xf4, al
        0xF4, // hlt
    ];
    put_bytes(&mut ram, TWO_VCPU_BSP_CODE_GPA, &bsp_code);

    // BSP ISR (vector 0x42) at TWO_VCPU_BSP_ISR_GPA:
    //   inc dword ptr [rdi + 0x18]                 ; bsp_ipi_count += 1
    //   mov eax, [rsi + 0x120]                     ; LAPIC_ISR word 2
    //   mov [rdi + 0x1c], eax                      ; bsp_isr_during
    //   mov dword ptr [rsi + 0xb0], 0              ; EOI
    //   mov eax, [rsi + 0x120]                     ; LAPIC_ISR word 2 after EOI
    //   mov [rdi + 0x20], eax                      ; bsp_isr_after_eoi
    //   iretq
    let bsp_isr = [
        0xFF, 0x47, 0x18, // inc dword ptr [rdi + 0x18]
        0x8B, 0x86, 0x20, 0x01, 0x00, 0x00, // mov eax, [rsi + 0x120]
        0x89, 0x47, 0x1C, // mov [rdi + 0x1c], eax
        0xC7, 0x86, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov dword ptr [rsi + 0xb0], 0
        0x8B, 0x86, 0x20, 0x01, 0x00, 0x00, // mov eax, [rsi + 0x120]
        0x89, 0x47, 0x20, // mov [rdi + 0x20], eax
        0x48, 0xCF, // iretq
    ];
    put_bytes(&mut ram, TWO_VCPU_BSP_ISR_GPA, &bsp_isr);

    ram
}

fn decode_shared_outcome(
    ram: &[u8],
    bsp_exit_port_val: u32,
    ap_exit_port_val: u32,
) -> TwoVcpuFixtureOutcome {
    let rd = |off: usize| -> u32 {
        let base = TWO_VCPU_SHARED_GPA as usize + off;
        u32::from_le_bytes(ram[base..base + 4].try_into().unwrap())
    };
    TwoVcpuFixtureOutcome {
        bsp_apic_id: rd(0x00),
        ap_apic_id: rd(0x04),
        ap_ready: rd(0x08),
        ap_ipi_count: rd(0x0c),
        ap_isr_during: rd(0x10),
        ap_isr_after_eoi: rd(0x14),
        bsp_ipi_count: rd(0x18),
        bsp_isr_during: rd(0x1c),
        bsp_isr_after_eoi: rd(0x20),
        ap_done: rd(0x24),
        bsp_done: rd(0x28),
        bsp_exit_port_val,
        ap_exit_port_val,
    }
}

/// Shared guest memory handle allowing two `SoftMachine` instances on separate host threads
/// to share the same underlying guest RAM and `ExtentTable`.
#[derive(Clone)]
struct SharedTwoVcpuSoftMemory {
    backing_ptr: usize,
    backing_len: usize,
    extents: Arc<ExtentTable>,
    mmio: MmioHoles,
}

impl SharedTwoVcpuSoftMemory {
    fn from_boxed_slice(backing: &mut [u8]) -> Self {
        let extents = Arc::new(ExtentTable::new().expect("extent table"));
        let base_host = HostVa::new(backing.as_mut_ptr() as usize);
        let pages = backing.len() / 4096;
        for page in 0..pages {
            let gpa = (page * 4096) as u64;
            extents
                .insert(ExtentRecord {
                    base_gpa: FrameGpa::new(gpa),
                    byte_len: 4096,
                    host_base: HostVa::new(base_host.raw() + gpa as usize),
                    generation: GEN,
                    allowed: Access {
                        read: true,
                        write: true,
                        execute: true,
                    },
                })
                .expect("insert shared extent");
        }
        let mut mmio = MmioHoles::new();
        mmio.insert(LAPIC_DEFAULT_PHYS_BASE, LAPIC_MMIO_SIZE);
        Self {
            backing_ptr: backing.as_mut_ptr() as usize,
            backing_len: backing.len(),
            extents,
            mmio,
        }
    }
}

impl SoftMmuMemory for SharedTwoVcpuSoftMemory {
    fn extents(&self) -> &ExtentTable {
        &self.extents
    }
    fn generation(&self) -> OwnerGeneration {
        GEN
    }
    fn mmio_holes(&self) -> &MmioHoles {
        &self.mmio
    }
    fn is_registered_root(&self, root: RootGpa) -> bool {
        root.raw() == TWO_VCPU_PML4_GPA
    }
    fn read_descriptor_words(
        &self,
        _admission: LookupAdmission<'_>,
        table_gpa: AuthenticatedGpa,
        index: usize,
    ) -> Result<AuthenticatedDescriptorWords, DescriptorRefusal> {
        let offset = (table_gpa.raw() as usize)
            .checked_add(index.checked_mul(8).ok_or(DescriptorRefusal::OutOfBounds)?)
            .ok_or(DescriptorRefusal::OutOfBounds)?;
        if offset + 8 > self.backing_len {
            return Err(DescriptorRefusal::OutOfBounds);
        }
        // SAFETY: `backing_ptr..backing_ptr + backing_len` is live for the duration of both vCPU threads.
        let word = unsafe {
            let ptr = (self.backing_ptr + offset) as *const u64;
            ptr.read_unaligned().to_le()
        };
        Ok(LiveDescriptorWords::from_Single(word).authenticate(table_gpa.generation()))
    }
    fn compare_exchange_descriptor_low(
        &mut self,
        _admission: LookupAdmission<'_>,
        table_gpa: AuthenticatedGpa,
        index: usize,
        expected_low: u64,
        desired_low: u64,
    ) -> Result<u64, DescriptorRefusal> {
        let offset = (table_gpa.raw() as usize)
            .checked_add(index.checked_mul(8).ok_or(DescriptorRefusal::OutOfBounds)?)
            .ok_or(DescriptorRefusal::OutOfBounds)?;
        if offset + 8 > self.backing_len {
            return Err(DescriptorRefusal::OutOfBounds);
        }
        // SAFETY: 8-byte aligned page-table descriptor atomic compare-exchange.
        let atom = unsafe {
            &*((self.backing_ptr + offset) as *const std::sync::atomic::AtomicU64)
        };
        match atom.compare_exchange(
            expected_low,
            desired_low,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(prev) | Err(prev) => Ok(prev),
        }
    }
    fn stage1_to_frame(&self, s1: Stage1Gpa, _placement: LinearPlacement) -> Option<FrameGpa> {
        Some(FrameGpa::new(s1.raw()))
    }
}

fn run_two_vcpu_fixture_on_softmachine() -> TwoVcpuFixtureOutcome {
    let mut backing = build_two_vcpu_guest_image().into_boxed_slice();
    let shared_mem0 = SharedTwoVcpuSoftMemory::from_boxed_slice(&mut backing);
    let shared_mem1 = shared_mem0.clone();
    let cluster = Arc::new(ApicCluster::new());

    let configure_vcpu = |mem: SharedTwoVcpuSoftMemory,
                          apic_id: u8,
                          code_gpa: u64,
                          idt_gpa: u64,
                          stack_gpa: u64,
                          cluster: Arc<ApicCluster>|
     -> SoftMachine<SharedTwoVcpuSoftMemory> {
        let cpuid = Box::new(Cpl0CpuidView::with_tsc_deadline(apic_id, 1_000_000_000));
        let mut machine = SoftMachine::new(mem, cpuid).expect("SoftMachine::new");
        machine.attach_apic_cluster(cluster);
        machine.set_hlt_wait_timeout(Some(Duration::from_secs(2)));
        let ctx = machine.context_mut();
        ctx.cr3 = TWO_VCPU_PML4_GPA;
        ctx.gdtr = DescriptorTablePtr::new(23, TWO_VCPU_GDT_GPA);
        ctx.idtr = DescriptorTablePtr::new(0x0fff, idt_gpa);
        ctx.gpr[reg::RSP] = stack_gpa + 0x800;
        ctx.gpr[reg::RSI] = LAPIC_DEFAULT_PHYS_BASE;
        ctx.gpr[reg::RDI] = TWO_VCPU_SHARED_GPA;
        enter_cpl0(ctx, code_gpa);
        machine
    };

    let cluster1 = Arc::clone(&cluster);
    let ap_handle = thread::spawn(move || {
        let mut ap = configure_vcpu(
            shared_mem1,
            1,
            TWO_VCPU_AP_CODE_GPA,
            TWO_VCPU_IDT1_GPA,
            TWO_VCPU_AP_STACK_GPA,
            cluster1,
        );
        match ap.run(10_000).expect("AP run") {
            SoftMachineExit::IoOut {
                port: EXIT_PORT,
                value,
                ..
            } => value,
            other => panic!("unexpected AP exit on SoftMachine: {other:?}"),
        }
    });

    let bsp_handle = thread::spawn(move || {
        let mut bsp = configure_vcpu(
            shared_mem0,
            0,
            TWO_VCPU_BSP_CODE_GPA,
            TWO_VCPU_IDT0_GPA,
            TWO_VCPU_BSP_STACK_GPA,
            cluster,
        );
        match bsp.run(100_000).expect("BSP run") {
            SoftMachineExit::IoOut {
                port: EXIT_PORT,
                value,
                ..
            } => value,
            other => panic!("unexpected BSP exit on SoftMachine: {other:?}"),
        }
    });

    let ap_port_val = ap_handle.join().expect("AP thread join");
    let bsp_port_val = bsp_handle.join().expect("BSP thread join");
    decode_shared_outcome(&backing, bsp_port_val, ap_port_val)
}

#[cfg(target_os = "linux")]
mod kvm_oracle {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const KVM_CREATE_VM: libc::c_ulong = 0xae01;
    const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = 0xae04;
    const KVM_CREATE_VCPU: libc::c_ulong = 0xae41;
    const KVM_SET_USER_MEMORY_REGION: libc::c_ulong = 0x4020_ae46;
    const KVM_SET_TSS_ADDR: libc::c_ulong = 0xae47;
    const KVM_CREATE_IRQCHIP: libc::c_ulong = 0xae60;
    const KVM_RUN: libc::c_ulong = 0xae80;
    const KVM_SET_REGS: libc::c_ulong = 0x4090_ae82;
    const KVM_GET_SREGS: libc::c_ulong = 0x8138_ae83;
    const KVM_SET_SREGS: libc::c_ulong = 0x4138_ae84;

    const KVM_EXIT_IO: u32 = 2;
    const KVM_EXIT_INTR: u32 = 10;

    #[repr(C)]
    #[derive(Default)]
    struct KvmUserspaceMemoryRegion {
        slot: u32,
        flags: u32,
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct KvmRegs {
        rax: u64,
        rbx: u64,
        rcx: u64,
        rdx: u64,
        rsi: u64,
        rdi: u64,
        rsp: u64,
        rbp: u64,
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rip: u64,
        rflags: u64,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct KvmSegment {
        base: u64,
        limit: u32,
        selector: u16,
        type_: u8,
        present: u8,
        dpl: u8,
        db: u8,
        s: u8,
        l: u8,
        g: u8,
        avl: u8,
        unusable: u8,
        padding: u8,
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct KvmDtable {
        base: u64,
        limit: u16,
        padding: [u16; 3],
    }

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct KvmSregs {
        cs: KvmSegment,
        ds: KvmSegment,
        es: KvmSegment,
        fs: KvmSegment,
        gs: KvmSegment,
        ss: KvmSegment,
        tr: KvmSegment,
        ldt: KvmSegment,
        gdt: KvmDtable,
        idt: KvmDtable,
        cr0: u64,
        cr2: u64,
        cr3: u64,
        cr4: u64,
        cr8: u64,
        efer: u64,
        apic_base: u64,
        interrupt_bitmap: [u64; 4],
    }

    #[repr(C)]
    struct KvmRunIo {
        direction: u8,
        size: u8,
        port: u16,
        count: u32,
        data_offset: u64,
    }

    pub(super) fn run_two_vcpu_fixture_on_kvm() -> Option<TwoVcpuFixtureOutcome> {
        let kvm_file = match OpenOptions::new().read(true).write(true).open("/dev/kvm") {
            Ok(f) => f,
            Err(_) => {
                assert!(
                    std::env::var_os("CARRICK_REQUIRE_KVM").is_none_or(|v| v != "1"),
                    "CARRICK_REQUIRE_KVM=1 but /dev/kvm could not be opened"
                );
                return None;
            }
        };

        // SAFETY: standard KVM ioctls on fresh file descriptors.
        unsafe {
            let mmap_size = libc::ioctl(kvm_file.as_raw_fd(), KVM_GET_VCPU_MMAP_SIZE, 0);
            assert!(mmap_size >= 4096, "KVM_GET_VCPU_MMAP_SIZE failed");

            let vm_raw = libc::ioctl(kvm_file.as_raw_fd(), KVM_CREATE_VM, 0);
            assert!(vm_raw >= 0, "KVM_CREATE_VM failed");
            let vm_fd = OwnedFd::from_raw_fd(vm_raw);

            let _ = libc::ioctl(vm_fd.as_raw_fd(), KVM_SET_TSS_ADDR, 0xfffb_d000usize);
            assert_eq!(
                libc::ioctl(vm_fd.as_raw_fd(), KVM_CREATE_IRQCHIP, 0),
                0,
                "KVM_CREATE_IRQCHIP failed"
            );

            // Allocate page-aligned guest RAM via mmap so KVM_SET_USER_MEMORY_REGION accepts it.
            let ram_ptr = libc::mmap(
                std::ptr::null_mut(),
                TWO_VCPU_RAM_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(ram_ptr, libc::MAP_FAILED, "mmap guest RAM failed");
            let initial_image = build_two_vcpu_guest_image();
            std::ptr::copy_nonoverlapping(
                initial_image.as_ptr(),
                ram_ptr.cast::<u8>(),
                TWO_VCPU_RAM_SIZE,
            );

            let region = KvmUserspaceMemoryRegion {
                slot: 0,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: TWO_VCPU_RAM_SIZE as u64,
                userspace_addr: ram_ptr as u64,
            };
            assert_eq!(
                libc::ioctl(vm_fd.as_raw_fd(), KVM_SET_USER_MEMORY_REGION, &region),
                0,
                "KVM_SET_USER_MEMORY_REGION failed"
            );

            let vcpu0_raw = libc::ioctl(vm_fd.as_raw_fd(), KVM_CREATE_VCPU, 0usize);
            assert!(vcpu0_raw >= 0, "KVM_CREATE_VCPU(0) failed");
            let vcpu0_fd = OwnedFd::from_raw_fd(vcpu0_raw);

            let vcpu1_raw = libc::ioctl(vm_fd.as_raw_fd(), KVM_CREATE_VCPU, 1usize);
            assert!(vcpu1_raw >= 0, "KVM_CREATE_VCPU(1) failed");
            let vcpu1_fd = OwnedFd::from_raw_fd(vcpu1_raw);

            let setup_kvm_vcpu = |vcpu_fd: &OwnedFd, rip: u64, rsp: u64, idt_base: u64| {
                let mut sregs = KvmSregs::default();
                assert_eq!(
                    libc::ioctl(vcpu_fd.as_raw_fd(), KVM_GET_SREGS, &mut sregs),
                    0,
                    "KVM_GET_SREGS failed"
                );
                sregs.cr0 = 0x8005_0033;
                sregs.cr3 = TWO_VCPU_PML4_GPA;
                sregs.cr4 = 0x0000_0020; // PAE
                sregs.efer = 0x0000_0d01; // SCE | LME | LMA | NXE
                sregs.cs = KvmSegment {
                    base: 0,
                    limit: 0xffff_ffff,
                    selector: 0x08,
                    type_: 11,
                    present: 1,
                    dpl: 0,
                    db: 0,
                    s: 1,
                    l: 1,
                    g: 1,
                    avl: 0,
                    unusable: 0,
                    padding: 0,
                };
                let data_seg = KvmSegment {
                    base: 0,
                    limit: 0xffff_ffff,
                    selector: 0x10,
                    type_: 3,
                    present: 1,
                    dpl: 0,
                    db: 1,
                    s: 1,
                    l: 0,
                    g: 1,
                    avl: 0,
                    unusable: 0,
                    padding: 0,
                };
                sregs.ss = data_seg;
                sregs.ds = data_seg;
                sregs.es = data_seg;
                sregs.gdt = KvmDtable {
                    base: TWO_VCPU_GDT_GPA,
                    limit: 23,
                    padding: [0; 3],
                };
                sregs.idt = KvmDtable {
                    base: idt_base,
                    limit: 0x0fff,
                    padding: [0; 3],
                };
                assert_eq!(
                    libc::ioctl(vcpu_fd.as_raw_fd(), KVM_SET_SREGS, &sregs),
                    0,
                    "KVM_SET_SREGS failed"
                );

                let regs = KvmRegs {
                    rip,
                    rsp,
                    rsi: LAPIC_DEFAULT_PHYS_BASE,
                    rdi: TWO_VCPU_SHARED_GPA,
                    rflags: 0x2,
                    ..KvmRegs::default()
                };
                assert_eq!(
                    libc::ioctl(vcpu_fd.as_raw_fd(), KVM_SET_REGS, &regs),
                    0,
                    "KVM_SET_REGS failed"
                );
            };

            setup_kvm_vcpu(
                &vcpu0_fd,
                TWO_VCPU_BSP_CODE_GPA,
                TWO_VCPU_BSP_STACK_GPA + 0x800,
                TWO_VCPU_IDT0_GPA,
            );
            setup_kvm_vcpu(
                &vcpu1_fd,
                TWO_VCPU_AP_CODE_GPA,
                TWO_VCPU_AP_STACK_GPA + 0x800,
                TWO_VCPU_IDT1_GPA,
            );

            let run_kvm_vcpu = move |vcpu_fd: OwnedFd, mmap_len: usize| -> u32 {
                let run_ptr = libc::mmap(
                    std::ptr::null_mut(),
                    mmap_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    vcpu_fd.as_raw_fd(),
                    0,
                );
                assert_ne!(run_ptr, libc::MAP_FAILED, "mmap kvm_run failed");
                let port_val = loop {
                    let rc = libc::ioctl(vcpu_fd.as_raw_fd(), KVM_RUN, 0);
                    if rc < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EINTR)
                            || err.raw_os_error() == Some(libc::EAGAIN)
                        {
                            continue;
                        }
                        panic!("KVM_RUN failed: {err}");
                    }
                    let exit_reason = *(run_ptr.cast::<u8>().add(8).cast::<u32>());
                    if exit_reason == KVM_EXIT_INTR {
                        continue;
                    }
                    assert_eq!(
                        exit_reason, KVM_EXIT_IO,
                        "expected KVM_EXIT_IO on exit port, got exit_reason={exit_reason}"
                    );
                    let io = &*(run_ptr.cast::<u8>().add(32).cast::<KvmRunIo>());
                    assert_eq!(io.port, EXIT_PORT);
                    let val = *(run_ptr.cast::<u8>().add(io.data_offset as usize));
                    break u32::from(val);
                };
                let _ = libc::munmap(run_ptr, mmap_len);
                port_val
            };

            let mmap_len = mmap_size as usize;
            let ap_thread = thread::spawn(move || run_kvm_vcpu(vcpu1_fd, mmap_len));
            let bsp_thread = thread::spawn(move || run_kvm_vcpu(vcpu0_fd, mmap_len));

            let ap_port_val = ap_thread.join().expect("KVM AP thread join");
            let bsp_port_val = bsp_thread.join().expect("KVM BSP thread join");

            let ram_slice = std::slice::from_raw_parts(ram_ptr.cast::<u8>(), TWO_VCPU_RAM_SIZE);
            let outcome = decode_shared_outcome(ram_slice, bsp_port_val, ap_port_val);
            let _ = libc::munmap(ram_ptr, TWO_VCPU_RAM_SIZE);
            Some(outcome)
        }
    }
}

#[test]
fn two_vcpu_wake_and_ipi_fixture_behaves_identically_on_softmachine_and_kvm() {
    let soft_outcome = run_two_vcpu_fixture_on_softmachine();
    let expected = TwoVcpuFixtureOutcome {
        bsp_apic_id: 0,
        ap_apic_id: 1,
        ap_ready: 1,
        ap_ipi_count: 1,
        ap_isr_during: 1 << (IPI_PING_VEC - 0x40),
        ap_isr_after_eoi: 0,
        bsp_ipi_count: 1,
        bsp_isr_during: 1 << (IPI_PONG_VEC - 0x40),
        bsp_isr_after_eoi: 0,
        ap_done: 1,
        bsp_done: 1,
        bsp_exit_port_val: u32::from(IPI_PONG_VEC),
        ap_exit_port_val: u32::from(IPI_PING_VEC),
    };
    assert_eq!(
        soft_outcome, expected,
        "SoftMachine two-vCPU wake/IPI fixture must match architectural expectation"
    );

    #[cfg(target_os = "linux")]
    if let Some(kvm_outcome) = kvm_oracle::run_two_vcpu_fixture_on_kvm() {
        assert_eq!(
            soft_outcome, kvm_outcome,
            "SoftMachine and /dev/kvm must produce identical state on the two-vCPU wake/IPI fixture"
        );
    }
}
