//! Stage-1 translation in the copy-through engine's exit handlers and block
//! fetch (#2480): known answers from the Arm ARM DDI0487G.a D5 (translation,
//! permissions, PAN/UAO/LDTR), D13.2.37 (ESR_EL1 ISS) and D1.10 (exception
//! entry), against hand-built tables and the production carrick-mem tables.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use carrick_softcpu_aarch64::dispatch::{ExecuteBlock, Stop, run};
use carrick_softcpu_aarch64::exception::Syndrome;
use carrick_softcpu_aarch64::handler::{
    Event, ExclusiveMonitor, GuestMemory, MemoryFault, Outcome, execute,
};
use carrick_softcpu_aarch64::mmu::Stage1Error;
use carrick_softcpu_aarch64::state::*;
use carrick_softcpu_aarch64::translate::{BlockLimits, GuestInstruction, TranslatedBlock};
use carrick_softcpu_aarch64::{Gpr, OperandRegister};
use std::collections::BTreeMap;

const PAGE: u64 = 4096;

/// Page-granular guest physical memory.
#[derive(Default)]
struct Physical(BTreeMap<u64, Box<[u8; PAGE as usize]>>);

impl Physical {
    fn back(&mut self, pa: u64) {
        self.0
            .entry(pa & !(PAGE - 1))
            .or_insert_with(|| Box::new([0; PAGE as usize]));
    }
    fn put(&mut self, pa: u64, v: u64) {
        self.write(VirtualAddress(pa), &v.to_le_bytes()).unwrap();
    }
    fn get(&mut self, pa: u64) -> u64 {
        let mut b = [0; 8];
        self.read(VirtualAddress(pa), &mut b).unwrap();
        u64::from_le_bytes(b)
    }
    fn byte(&mut self, a: u64) -> Result<&mut u8, MemoryFault> {
        self.0
            .get_mut(&(a & !(PAGE - 1)))
            .map(|p| &mut p[(a % PAGE) as usize])
            .ok_or(MemoryFault {
                address: VirtualAddress(a),
            })
    }
}

impl GuestMemory for Physical {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = *self.byte(address.0 + i as u64)?;
        }
        Ok(())
    }
    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
        for i in 0..bytes.len() as u64 {
            self.byte(address.0 + i)?;
        }
        for (i, b) in bytes.iter().enumerate() {
            *self.byte(address.0 + i as u64)? = *b;
        }
        Ok(())
    }
}

// D5.3 encodings.
const TABLE: u64 = 0b11;
const LEAF_PAGE: u64 = 0b11;
const AF: u64 = 1 << 10;
const AP_EL1_RW: u64 = 0b00 << 6;
const AP_ALL_RW: u64 = 0b01 << 6;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
/// T0SZ=T1SZ=16, TG1=4K, IPS=40 bits, TBI0/TBI1 (the bootstrap fields).
const TCR: u64 = 16 | (16 << 16) | (0b10 << 30) | (0b010 << 32) | (1 << 37) | (1 << 38);

const ROOT_A: u64 = 0x10_0000;
const ROOT_B: u64 = 0x20_0000;
/// Code, kernel data and user data pages (VAs) and their nonidentity outputs.
const CODE: u64 = 0x40_0000;
const KDATA: u64 = 0x40_1000;
const UDATA: u64 = 0x40_2000;
const HOLE: u64 = 0x40_3000;
const CODE_PA: u64 = 0x80_0000;
const KDATA_PA: u64 = 0x80_5000;
const UDATA_PA: u64 = 0x80_9000;
const VBAR: u64 = CODE + 0x800;

fn x(n: u8) -> OperandRegister {
    OperandRegister::Gpr(Gpr::new(n).unwrap())
}

/// Tables under `root` (L0..L3 in the four pages from `root`) mapping
/// CODE/KDATA/UDATA to `offset` plus their outputs; HOLE is unmapped.
fn map(memory: &mut Physical, root: u64, offset: u64) {
    for t in 0..4 {
        memory.back(root + t * PAGE);
    }
    let (l1, l2, l3) = (root + PAGE, root + 2 * PAGE, root + 3 * PAGE);
    memory.put(root, l1 | TABLE);
    memory.put(l1, l2 | TABLE);
    memory.put(l2 + 2 * 8, l3 | TABLE); // VA bits 29:21 = 2
    let leaf = |va: u64| l3 + ((va >> 12) & 511) * 8;
    memory.put(
        leaf(CODE),
        (CODE_PA + offset) | LEAF_PAGE | AF | AP_EL1_RW | UXN,
    );
    memory.put(
        leaf(KDATA),
        (KDATA_PA + offset) | LEAF_PAGE | AF | AP_EL1_RW | UXN,
    );
    memory.put(
        leaf(UDATA),
        (UDATA_PA + offset) | LEAF_PAGE | AF | AP_ALL_RW | PXN,
    );
    for pa in [CODE_PA, KDATA_PA, UDATA_PA] {
        memory.back(pa + offset);
    }
}

struct Rig {
    cpu: CpuState,
    monitor: ExclusiveMonitor,
    memory: Physical,
}

impl Rig {
    fn el1() -> Self {
        let mut memory = Physical::default();
        map(&mut memory, ROOT_A, 0);
        map(&mut memory, ROOT_B, 0x10_0000);
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.el1.vbar = VirtualAddress(VBAR);
        cpu.el1.tcr = SystemValue(TCR);
        cpu.named.ttbr0 = SystemValue(ROOT_A);
        cpu.el1.sctlr = Sctlr(1);
        cpu.pc = ProgramCounter(CODE);
        Self {
            cpu,
            monitor: ExclusiveMonitor::default(),
            memory,
        }
    }
    fn el0() -> Self {
        let mut r = Self::el1();
        r.cpu.pstate.el = ExceptionLevel::El0;
        r.cpu.pstate.sp = StackSelect::El0;
        r
    }
    fn set(&mut self, n: u8, v: u64) {
        self.cpu.write_operand(x(n), RegisterValue(v));
    }
    fn get(&self, n: u8) -> u64 {
        self.cpu.read_operand(x(n)).0
    }
    fn run(&mut self, word: u32) -> Outcome {
        let i = GuestInstruction::decode(self.cpu.pc, word);
        execute(&mut self.cpu, &mut self.monitor, &mut self.memory, &i)
    }
    fn assert_abort(&self, vector: u64, esr: u64, far: u64) {
        assert_eq!(self.cpu.pc.0, VBAR + vector, "vector");
        assert_eq!(
            self.cpu.el1.esr,
            Syndrome(esr),
            "ESR {:#x}",
            self.cpu.el1.esr.0
        );
        assert_eq!(self.cpu.el1.far, VirtualAddress(far), "FAR");
        assert_eq!(
            self.cpu.el1.elr,
            ProgramCounter(CODE),
            "ELR is the faulting PC"
        );
        assert_eq!(self.cpu.pstate.el, ExceptionLevel::El1);
    }
}

const LDR_X1_X0: u32 = 0xf940_0001;
const STR_X1_X0: u32 = 0xf900_0001;
const LDTR_X1_X0: u32 = 0xf840_0801;
const STTR_X1_X0: u32 = 0xf800_0801;
const STUR_X1_X0: u32 = 0xf800_0001;

#[test]
fn translated_loads_and_stores_reach_the_stage1_output() {
    let mut r = Rig::el1();
    r.memory.put(KDATA_PA + 0x18, 0x1122_3344_5566_7788);
    r.set(0, KDATA + 0x18);
    assert_eq!(r.run(LDR_X1_X0), Outcome::Continue);
    assert_eq!((r.get(1), r.cpu.pc.0), (0x1122_3344_5566_7788, CODE + 4));
    r.cpu.pc = ProgramCounter(CODE);
    r.set(1, 0xabcd);
    r.set(0, KDATA + 0x20);
    assert_eq!(r.run(STR_X1_X0), Outcome::Continue);
    assert_eq!(r.memory.get(KDATA_PA + 0x20), 0xabcd);
    // A tagged pointer (TBI0) reaches the same output.
    r.cpu.pc = ProgramCounter(CODE);
    r.set(0, (KDATA + 0x18) | (0x5a << 56));
    assert_eq!(r.run(LDR_X1_X0), Outcome::Continue);
    assert_eq!(r.get(1), 0x1122_3344_5566_7788);
}

#[test]
fn ttbr0_write_switches_the_root_for_the_next_access() {
    let mut r = Rig::el1();
    r.memory.put(KDATA_PA + 8, 1);
    r.memory.put(KDATA_PA + 0x10_0000 + 8, 2);
    r.set(0, KDATA + 8);
    r.run(LDR_X1_X0);
    assert_eq!(r.get(1), 1);
    r.cpu.pc = ProgramCounter(CODE);
    r.set(2, ROOT_B | (5 << 48));
    assert_eq!(r.run(0xd518_2002), Outcome::Continue); // msr ttbr0_el1, x2
    r.cpu.pc = ProgramCounter(CODE);
    r.run(LDR_X1_X0);
    assert_eq!(r.get(1), 2, "the second root's output");
}

#[test]
fn ldtr_at_el1_is_checked_as_el0_and_aborts_at_the_current_el() {
    // EL1 LDTR from a kernel-only page: permission fault, L3, EC 0x25.
    let mut r = Rig::el1();
    r.set(0, KDATA + 0x40);
    assert_eq!(r.run(LDTR_X1_X0), Outcome::Fault);
    r.assert_abort(0x200, 0x9600_000f, KDATA + 0x40);
    // STTR: the same with WnR.
    let mut r = Rig::el1();
    r.set(0, KDATA + 0x48);
    assert_eq!(r.run(STTR_X1_X0), Outcome::Fault);
    r.assert_abort(0x200, 0x9600_004f, KDATA + 0x48);
    // From a user page with PAN set, LDTR succeeds; an ordinary LDR faults.
    let mut r = Rig::el1();
    r.cpu.pstate.pan = true;
    r.memory.put(UDATA_PA, 0x77);
    r.set(0, UDATA);
    assert_eq!(r.run(LDTR_X1_X0), Outcome::Continue);
    assert_eq!((r.get(1), r.cpu.pc.0), (0x77, CODE + 4));
    r.cpu.pc = ProgramCounter(CODE);
    assert_eq!(r.run(LDR_X1_X0), Outcome::Fault);
    r.assert_abort(0x200, 0x9600_000f, UDATA);
    // UAO=1: LDTR is an ordinary EL1 access, PAN included.
    let mut r = Rig::el1();
    r.cpu.pstate.pan = true;
    r.cpu.pstate.uao = true;
    r.set(0, UDATA);
    assert_eq!(r.run(LDTR_X1_X0), Outcome::Fault);
    r.assert_abort(0x200, 0x9600_000f, UDATA);
}

#[test]
fn el0_faults_are_lower_el_data_aborts_with_exact_syndromes() {
    // EL0 store to a kernel page: permission L3, write, EC 0x24.
    let mut r = Rig::el0();
    r.set(0, KDATA);
    assert_eq!(r.run(STR_X1_X0), Outcome::Fault);
    r.assert_abort(0x400, 0x9200_004f, KDATA);
    // EL0 load from the unmapped page: translation L3.
    let mut r = Rig::el0();
    r.set(0, HOLE + 8);
    assert_eq!(r.run(LDR_X1_X0), Outcome::Fault);
    r.assert_abort(0x400, 0x9200_0007, HOLE + 8);
    // EL0 load from a user page succeeds.
    let mut r = Rig::el0();
    r.memory.put(UDATA_PA + 0x10, 9);
    r.set(0, UDATA + 0x10);
    assert_eq!(r.run(LDR_X1_X0), Outcome::Continue);
    assert_eq!(r.get(1), 9);
}

#[test]
fn a_crossing_store_faulting_on_its_second_page_writes_nothing() {
    // STUR of 8 bytes at UDATA_end - 4: the second page (HOLE) is unmapped.
    let mut r = Rig::el1();
    r.memory.put(UDATA_PA + PAGE - 8, 0x0101_0101_0101_0101);
    r.set(0, UDATA + PAGE - 4);
    r.set(1, u64::MAX);
    assert_eq!(r.run(STUR_X1_X0), Outcome::Fault);
    // FAR is the lowest address touched in the faulting page.
    r.assert_abort(0x200, 0x9600_0047, HOLE);
    assert_eq!(r.memory.get(UDATA_PA + PAGE - 8), 0x0101_0101_0101_0101);
}

#[test]
fn msr_sctlr_m_retires_under_an_admitted_tcr() {
    let mut r = Rig::el1();
    r.cpu.el1.sctlr = Sctlr(0);
    r.set(3, 1);
    assert_eq!(r.run(0xd518_1003), Outcome::Continue); // msr sctlr_el1, x3
    assert_eq!(r.cpu.el1.sctlr, Sctlr(1));
    // A 64 KiB TG0 is not admitted: the write stops unretired.
    let mut r = Rig::el1();
    r.cpu.el1.sctlr = Sctlr(0);
    r.cpu.el1.tcr = SystemValue(TCR | (0b01 << 14));
    r.set(3, 1);
    assert_eq!(
        r.run(0xd518_1003),
        Outcome::Event(Event::MmuEnable {
            value: SystemValue(1)
        })
    );
    // Translation already on under an unadmitted TCR: a provider stop.
    let mut r = Rig::el1();
    r.cpu.el1.tcr = SystemValue(TCR | (1 << 39));
    r.set(0, KDATA);
    assert!(matches!(
        r.run(LDR_X1_X0),
        Outcome::Event(Event::Translation(Stage1Error::Regime(_)))
    ));
    assert_eq!(r.cpu.pc.0, CODE, "not retired");
}

/// Never runs a block: the tests below stop before execution.
struct NoBlocks;
impl ExecuteBlock for NoBlocks {
    type Error = ();
    type Code = ();
    fn prepare(&mut self, _: &TranslatedBlock) -> Result<(), ()> {
        panic!("no block may be prepared")
    }
    fn execute(&mut self, _: &TranslatedBlock, _: &(), _: &mut CpuState) -> Result<usize, ()> {
        panic!("no block may run")
    }
}

#[test]
fn fetch_from_an_unmapped_page_takes_an_instruction_abort() {
    let mut r = Rig::el1();
    r.cpu.pc = ProgramCounter(HOLE);
    let report = run(
        &mut r.cpu,
        &mut r.monitor,
        &mut r.memory,
        &mut NoBlocks,
        BlockLimits::default(),
        1,
    );
    assert_eq!(report.stop, Stop::Budget);
    assert_eq!(report.blocks, 1, "the abort spent one budget step");
    assert_eq!(report.work.stage1_walks, 1);
    assert_eq!(report.work.executed_blocks, 0);
    assert_eq!(report.work.retired_instructions, 0);
    assert_eq!(r.cpu.pc.0, VBAR + 0x200);
    // Instruction abort, current EL: EC 0x21, IFSC translation L3.
    assert_eq!(r.cpu.el1.esr, Syndrome(0x8600_0007));
    assert_eq!(
        (r.cpu.el1.far, r.cpu.el1.elr),
        (VirtualAddress(HOLE), ProgramCounter(HOLE))
    );
    // EL0 fetch from a PXN user page is fine for EL0 but UXN kernel code is
    // not: a lower-EL instruction abort, permission L3 (EC 0x20).
    let mut r = Rig::el0();
    r.cpu.pc = ProgramCounter(CODE);
    run(
        &mut r.cpu,
        &mut r.monitor,
        &mut r.memory,
        &mut NoBlocks,
        BlockLimits::default(),
        1,
    );
    assert_eq!(r.cpu.el1.esr, Syndrome(0x8200_000f));
    assert_eq!(r.cpu.pc.0, VBAR + 0x400);
}

/// Every block in the fixture ends at a real handler or an unconditional
/// continuation. Only the host instruction launch is substituted.
struct SingleExit;
impl ExecuteBlock for SingleExit {
    type Error = ();
    type Code = ();

    fn prepare(&mut self, block: &TranslatedBlock) -> Result<(), ()> {
        assert_eq!(block.exits().len(), 1);
        Ok(())
    }

    fn execute(&mut self, _: &TranslatedBlock, _: &(), _: &mut CpuState) -> Result<usize, ()> {
        Ok(0)
    }
}

#[test]
fn tlbi_invalidates_a_loaded_translation_before_the_next_load() {
    let mut r = Rig::el1();
    let l3 = ROOT_A + 3 * PAGE;
    // Give the guest a writable alias for the descriptor page. KDATA is
    // index 1, so [x2] is the live KDATA descriptor.
    r.memory
        .put(l3 + 3 * 8, l3 | LEAF_PAGE | AF | AP_EL1_RW | UXN);
    r.memory.put(KDATA_PA, 0xfeed);
    r.set(0, KDATA);
    r.set(2, HOLE + 8);
    let code = [
        LDR_X1_X0,
        0xf900_005f, // str xzr, [x2] (invalidate KDATA descriptor)
        0xd503_3a9f, // dsb ishst
        0xd508_871f, // tlbi vmalle1
        0xd503_3b9f, // dsb ish
        0xd503_3fdf, // isb
        0xf940_0004, // ldr x4, [x0] (must fault)
        0xd400_0042, // hvc #2 (only reached with a stale hit)
    ];
    for (index, word) in code.into_iter().enumerate() {
        r.memory
            .write(
                VirtualAddress(CODE_PA + 4 * index as u64),
                &word.to_le_bytes(),
            )
            .unwrap();
    }
    r.memory
        .write(
            VirtualAddress(CODE_PA + 0xa00),
            &0xd400_0062_u32.to_le_bytes(),
        )
        .unwrap(); // HVC #3 at the current-EL SPx abort vector
    let report = run(
        &mut r.cpu,
        &mut r.monitor,
        &mut r.memory,
        &mut SingleExit,
        BlockLimits::default(),
        16,
    );
    assert!(matches!(
        report.stop,
        Stop::Event {
            event: Event::ProviderExit(_),
            ..
        }
    ));
    assert_eq!(r.get(1), 0xfeed);
    assert_eq!(r.get(4), 0);
    assert_eq!(r.cpu.el1.esr, Syndrome(0x9600_0007));
    assert_eq!(r.cpu.el1.far, VirtualAddress(KDATA));
    assert_eq!(r.cpu.el1.elr, ProgramCounter(CODE + 24));
    assert_eq!(report.pc, ProgramCounter(VBAR + 0x204));
}

mod production {
    use super::*;
    use carrick_mem::arch_sysregs::{SCTLR_EL1_BOOTSTRAP, TCR_EL1_BOOTSTRAP};
    use carrick_mem::memory::{
        LINUX_KERNEL_REGION_BASE, LINUX_NULL_GUARD_END, LINUX_PAGE_TABLES_BASE,
        stage1_identity_page_tables,
    };

    /// The production boot tables at their physical base, the bootstrap
    /// TCR/SCTLR and both TTBRs on the table base, as the HAL programs them.
    fn production() -> Rig {
        let mut r = Rig::el1();
        let tables = stage1_identity_page_tables();
        for (i, chunk) in tables.chunks(PAGE as usize).enumerate() {
            let pa = LINUX_PAGE_TABLES_BASE + i as u64 * PAGE;
            r.memory.back(pa);
            r.memory.write(VirtualAddress(pa), chunk).unwrap();
        }
        r.cpu.el1.tcr = SystemValue(TCR_EL1_BOOTSTRAP);
        r.cpu.el1.sctlr = Sctlr(SCTLR_EL1_BOOTSTRAP);
        r.cpu.named.ttbr0 = SystemValue(LINUX_PAGE_TABLES_BASE);
        r.cpu.named.ttbr1 = SystemValue(LINUX_PAGE_TABLES_BASE);
        r
    }

    #[test]
    fn production_tables_drive_ldtr_pan_and_kernel_accesses() {
        let user = LINUX_NULL_GUARD_END + 0x100;
        let kernel = LINUX_KERNEL_REGION_BASE + 0x1F_F000;
        // Identity: back the physical pages the accesses reach.
        let mut r = production();
        r.memory.back(user);
        r.memory.back(kernel);
        r.memory.put(user, 0x5150);
        r.cpu.pstate.pan = true;
        r.set(0, user);
        assert_eq!(r.run(LDTR_X1_X0), Outcome::Continue);
        assert_eq!(r.get(1), 0x5150, "HardwareUserWord-style LDTR under PAN");
        r.cpu.pc = ProgramCounter(CODE);
        r.set(0, kernel);
        r.set(1, 0xfeed);
        assert_eq!(r.run(STR_X1_X0), Outcome::Continue);
        assert_eq!(r.memory.get(kernel), 0xfeed);
        // PAN denies the ordinary load from the user page: permission, L3.
        r.cpu.pc = ProgramCounter(CODE);
        r.set(0, user);
        assert_eq!(r.run(LDR_X1_X0), Outcome::Fault);
        assert_eq!(r.cpu.el1.esr, Syndrome(0x9600_000f));
        assert_eq!(r.cpu.el1.far, VirtualAddress(user));
        // The null guard: an EL1 LDTR (user copy) of address 0 takes a
        // translation fault at L3.
        let mut r = production();
        r.set(0, 0);
        assert_eq!(r.run(LDTR_X1_X0), Outcome::Fault);
        assert_eq!(r.cpu.el1.esr, Syndrome(0x9600_0007));
        assert_eq!(r.cpu.el1.far, VirtualAddress(0));
        // An LDTR into the kernel block is checked as EL0: permission, L2.
        let mut r = production();
        r.set(0, kernel);
        assert_eq!(r.run(LDTR_X1_X0), Outcome::Fault);
        assert_eq!(r.cpu.el1.esr, Syndrome(0x9600_000e));
    }
}

#[test]
fn el0_dc_zva_zeros_one_translated_block_with_store_faults() {
    // Arm ARM DC ZVA and ESR_EL1.ISS: DC ZVA is a data store (CM=0).
    let mut r = Rig::el0();
    r.cpu.el1.mair = SystemValue(0xff);
    r.cpu.el1.sctlr.0 |= 1 << 14; // DZE
    for offset in (0..80).step_by(8) {
        r.memory.put(UDATA_PA + offset, u64::MAX);
    }
    r.set(3, UDATA + 31);
    assert_eq!(r.run(0xd50b_7423), Outcome::Continue);
    assert_eq!(r.cpu.pc.0, CODE + 4);
    for offset in (0..64).step_by(8) {
        assert_eq!(r.memory.get(UDATA_PA + offset), 0);
    }
    assert_eq!(r.memory.get(UDATA_PA + 64), u64::MAX);

    r.cpu.pc = ProgramCounter(CODE);
    r.set(3, KDATA + 31); // EL0 write permission is denied
    assert_eq!(r.run(0xd50b_7423), Outcome::Fault);
    r.assert_abort(0x400, 0x9200_004f, KDATA + 31);

    let mut r = Rig::el0();
    r.set(3, HOLE + 31);
    assert_eq!(r.run(0xd50b_7423), Outcome::Fault);
    assert_eq!(r.cpu.el1.esr, Syndrome(0x6212_dc68)); // DZE trap before translation
    assert_eq!(r.cpu.el1.elr, ProgramCounter(CODE));
}

#[test]
fn el0_ic_ivau_traps_or_translates_with_cache_maintenance_syndrome() {
    // DDI0487G.a IC IVAU, SCTLR_EL1.UCI and ESR_EL1.ISS.CM.
    let mut r = Rig::el0();
    r.set(3, HOLE + 31);
    assert_eq!(r.run(0xd50b_7523), Outcome::Fault);
    assert_eq!(r.cpu.el1.esr, Syndrome(0x6212_dc6a)); // UCI trap before translation
    assert_eq!(r.cpu.el1.elr, ProgramCounter(CODE));

    let mut r = Rig::el0();
    r.cpu.el1.sctlr.0 |= 1 << 26; // UCI
    r.set(3, UDATA + 31);
    assert!(matches!(r.run(0xd50b_7523), Outcome::Event(Event::Ic(_))));
    assert_eq!(r.cpu.pc.0, CODE + 4);

    r.cpu.pc = ProgramCounter(CODE);
    r.set(3, HOLE + 31);
    assert_eq!(r.run(0xd50b_7523), Outcome::Fault);
    r.assert_abort(0x400, 0x9200_0147, HOLE + 31);
}

#[test]
fn el0_q_store_crossing_a_stage1_hole_writes_neither_half() {
    use carrick_softcpu_aarch64::VectorRegister;
    let mut r = Rig::el0();
    let address = HOLE - 8;
    let q31 = VectorRegister::new(31).unwrap();
    r.cpu.write_vector(q31, u128::MAX);
    r.memory.put(UDATA_PA + PAGE - 8, 0x1020_3040_5060_7080);
    r.set(0, address);
    assert_eq!(r.run(0x3c81_0c1f), Outcome::Fault); // str q31, [x0, #16]!
    r.assert_abort(0x400, 0x9200_0047, address + 16);
    assert_eq!(r.get(0), address);

    let mut r = Rig::el0();
    r.cpu.write_vector(q31, u128::MAX);
    r.memory.put(UDATA_PA + PAGE - 8, 0x1020_3040_5060_7080);
    r.set(0, address);
    assert_eq!(r.run(0x3d80_001f), Outcome::Fault); // str q31, [x0]
    r.assert_abort(0x400, 0x9200_0047, HOLE);
    assert_eq!(r.memory.get(UDATA_PA + PAGE - 8), 0x1020_3040_5060_7080);
}

#[test]
fn el0_dc_zva_to_device_memory_raises_alignment_before_writing() {
    let mut r = Rig::el0();
    r.cpu.el1.sctlr.0 |= 1 << 14; // DZE
    r.cpu.el1.mair = SystemValue(0); // AttrIndx=0 selects Device-nGnRnE
    r.memory.put(UDATA_PA, u64::MAX);
    r.set(3, UDATA + 31);
    assert_eq!(r.run(0xd50b_7423), Outcome::Fault);
    r.assert_abort(0x400, 0x9200_0061, UDATA + 31);
    assert_eq!(r.memory.get(UDATA_PA), u64::MAX);
}

#[test]
fn el1_at_populates_par_el1_with_stage1_attributes_and_faults() {
    // DDI0487G.a C6.2.21 AT, C5.3 AT S1E*, D5.4.2 PAN, D13.2.103 PAR_EL1.
    let mut r = Rig::el1();
    r.cpu.pstate.pan = true;
    r.cpu.el1.mair = SystemValue(0x00_44_ff);
    let l3 = ROOT_A + 3 * PAGE;
    // UDATA: AttrIndx=0 (0xff Normal WB), SH=0b11 (Inner Shareable), EL0 RW.
    r.memory.put(
        l3 + ((UDATA >> 12) & 511) * 8,
        UDATA_PA | LEAF_PAGE | AF | AP_ALL_RW | (0b11 << 8) | PXN,
    );
    // KDATA: AttrIndx=1 (0x44 Normal NC -> effective Outer Shareable 0b10), EL1 RO.
    r.memory.put(
        l3 + ((KDATA >> 12) & 511) * 8,
        KDATA_PA | LEAF_PAGE | AF | (0b10 << 6) | (1 << 2) | UXN,
    );

    // 1. Production HardwareValidator form (`at s1e0r, x12` = 0xd508_784c):
    // succeeds on EL0-accessible UDATA even with PSTATE.PAN=1, stripping
    // page offset bits [11:0] and preserving ATTR=0xff, PA[47:12], RES1[11], SH=0b11.
    r.set(12, UDATA + 0xcf0);
    assert_eq!(r.run(0xd508_784c), Outcome::Continue);
    assert_eq!(r.cpu.pc.0, CODE + 4);
    assert_eq!(
        r.cpu.named.par.0,
        (0xff << 56) | UDATA_PA | (1 << 11) | (0b11 << 7)
    );

    // 2. `at s1e1r, x12` (0xd508_780c) ignores PSTATE.PAN, whereas
    // `at s1e1rp, x12` (0xd508_790c) enforces PSTATE.PAN and reports an L3
    // permission fault (FST=0x0f, F=1) in PAR_EL1 without taking an abort or
    // touching ESR_EL1 / FAR_EL1.
    r.cpu.pc = ProgramCounter(CODE);
    r.cpu.el1.esr = Syndrome(0x5600_0000);
    r.cpu.el1.far = VirtualAddress(0xaa55);
    assert_eq!(r.run(0xd508_780c), Outcome::Continue);
    assert_eq!(
        r.cpu.named.par.0,
        (0xff << 56) | UDATA_PA | (1 << 11) | (0b11 << 7)
    );
    r.cpu.pc = ProgramCounter(CODE);
    assert_eq!(r.run(0xd508_790c), Outcome::Continue);
    assert_eq!(r.cpu.pc.0, CODE + 4);
    assert_eq!(r.cpu.named.par.0, (1 << 11) | (0x0f << 1) | 1);
    assert_eq!(r.cpu.el1.esr, Syndrome(0x5600_0000));
    assert_eq!(r.cpu.el1.far, VirtualAddress(0xaa55));

    // 3. `at s1e1r` vs `at s1e1w` and `at s1e0r` on EL1-RO KDATA:
    // EL1 read reports ATTR=0x44 and forced SH=0b10; EL1 write and EL0 read
    // both record FST=0x0f (permission L3) in PAR_EL1.
    r.cpu.pc = ProgramCounter(CODE);
    r.set(12, KDATA + 0x28);
    assert_eq!(r.run(0xd508_780c), Outcome::Continue);
    assert_eq!(
        r.cpu.named.par.0,
        (0x44 << 56) | KDATA_PA | (1 << 11) | (0b10 << 7)
    );
    for denied in [0xd508_782c, 0xd508_784c, 0xd508_786c] {
        r.cpu.pc = ProgramCounter(CODE);
        assert_eq!(r.run(denied), Outcome::Continue);
        assert_eq!(r.cpu.named.par.0, (1 << 11) | (0x0f << 1) | 1);
    }

    // 4. Unmapped HOLE (under mapped l2[2] -> l3) reports L3 translation
    // fault (FST=0x07), and Rt=31 (`at s1e0r, xzr` = 0xd508_785f) translates
    // VA=0 (unmapped l2[0], L2 translation fault FST=0x06) rather than SP_EL1.
    r.cpu.sp_el1 = StackPointer(UDATA);
    r.cpu.pc = ProgramCounter(CODE);
    r.set(12, HOLE + 8);
    assert_eq!(r.run(0xd508_784c), Outcome::Continue);
    assert_eq!(r.cpu.named.par.0, (1 << 11) | (0x07 << 1) | 1);
    r.cpu.pc = ProgramCounter(CODE);
    assert_eq!(r.run(0xd508_785f), Outcome::Continue);
    assert_eq!(r.cpu.named.par.0, (1 << 11) | (0x06 << 1) | 1);

    // 5. Missing descriptor backing is a provider stop, not a guest PAR_EL1 fault.
    r.cpu.named.ttbr0 = SystemValue(0xf0_0000);
    r.cpu.named.par = SystemValue(0x1234);
    r.cpu.pc = ProgramCounter(CODE);
    assert!(matches!(
        r.run(0xd508_784c),
        Outcome::Event(Event::Translation(Stage1Error::Descriptor(_)))
    ));
    assert_eq!((r.cpu.pc.0, r.cpu.named.par.0), (CODE, 0x1234));
}
