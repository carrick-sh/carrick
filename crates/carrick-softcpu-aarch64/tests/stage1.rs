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
use carrick_softcpu_aarch64::translate::{
    BlockFrame, BlockLimits, GuestInstruction, TranslatedBlock,
};
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
    assert_eq!(r.run(LDTR_X1_X0), Outcome::Continue);
    r.assert_abort(0x200, 0x9600_000f, KDATA + 0x40);
    // STTR: the same with WnR.
    let mut r = Rig::el1();
    r.set(0, KDATA + 0x48);
    assert_eq!(r.run(STTR_X1_X0), Outcome::Continue);
    r.assert_abort(0x200, 0x9600_004f, KDATA + 0x48);
    // From a user page with PAN set, LDTR succeeds; an ordinary LDR faults.
    let mut r = Rig::el1();
    r.cpu.pstate.pan = true;
    r.memory.put(UDATA_PA, 0x77);
    r.set(0, UDATA);
    assert_eq!(r.run(LDTR_X1_X0), Outcome::Continue);
    assert_eq!((r.get(1), r.cpu.pc.0), (0x77, CODE + 4));
    r.cpu.pc = ProgramCounter(CODE);
    assert_eq!(r.run(LDR_X1_X0), Outcome::Continue);
    r.assert_abort(0x200, 0x9600_000f, UDATA);
    // UAO=1: LDTR is an ordinary EL1 access, PAN included.
    let mut r = Rig::el1();
    r.cpu.pstate.pan = true;
    r.cpu.pstate.uao = true;
    r.set(0, UDATA);
    assert_eq!(r.run(LDTR_X1_X0), Outcome::Continue);
    r.assert_abort(0x200, 0x9600_000f, UDATA);
}

#[test]
fn el0_faults_are_lower_el_data_aborts_with_exact_syndromes() {
    // EL0 store to a kernel page: permission L3, write, EC 0x24.
    let mut r = Rig::el0();
    r.set(0, KDATA);
    assert_eq!(r.run(STR_X1_X0), Outcome::Continue);
    r.assert_abort(0x400, 0x9200_004f, KDATA);
    // EL0 load from the unmapped page: translation L3.
    let mut r = Rig::el0();
    r.set(0, HOLE + 8);
    assert_eq!(r.run(LDR_X1_X0), Outcome::Continue);
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
    assert_eq!(r.run(STUR_X1_X0), Outcome::Continue);
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
    fn execute(&mut self, _: &TranslatedBlock, _: &mut BlockFrame) -> Result<usize, ()> {
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
        assert_eq!(r.run(LDR_X1_X0), Outcome::Continue);
        assert_eq!(r.cpu.el1.esr, Syndrome(0x9600_000f));
        assert_eq!(r.cpu.el1.far, VirtualAddress(user));
        // The null guard: an EL1 LDTR (user copy) of address 0 takes a
        // translation fault at L3.
        let mut r = production();
        r.set(0, 0);
        assert_eq!(r.run(LDTR_X1_X0), Outcome::Continue);
        assert_eq!(r.cpu.el1.esr, Syndrome(0x9600_0007));
        assert_eq!(r.cpu.el1.far, VirtualAddress(0));
        // An LDTR into the kernel block is checked as EL0: permission, L2.
        let mut r = production();
        r.set(0, kernel);
        assert_eq!(r.run(LDTR_X1_X0), Outcome::Continue);
        assert_eq!(r.cpu.el1.esr, Syndrome(0x9600_000e));
    }
}
