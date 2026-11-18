//! Exit-handler known answers, derived from the Arm ARM DDI0487G.a
//! instruction pseudocode (C6.2) and exception entry/return (D1.10/D1.11).
// Test helpers outside #[test] fns fail loudly on malformed fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use carrick_softcpu_aarch64::exception::Syndrome;
use carrick_softcpu_aarch64::handler::{
    Event, ExclusiveMonitor, GuestMemory, MemoryFault, Outcome, execute,
};
use carrick_softcpu_aarch64::state::*;
use carrick_softcpu_aarch64::translate::GuestInstruction;
use carrick_softcpu_aarch64::{Gpr, Hint, OperandRegister, TlbiOperation};
use std::collections::BTreeMap;

const PC: u64 = 0x2d04_0000_1000;
const VBAR: u64 = 0x2d04_0000_8000;

/// Flat byte-addressed guest memory over [0x10000, 0x20000) plus the code page.
#[derive(Default)]
struct Flat(BTreeMap<u64, u8>);

impl Flat {
    fn mapped(a: u64) -> bool {
        (0x10000..0x20000).contains(&a) || (PC..PC + 0x100).contains(&a)
    }
    fn put(&mut self, a: u64, v: u64) {
        for (i, b) in v.to_le_bytes().iter().enumerate() {
            self.0.insert(a + i as u64, *b);
        }
    }
    fn get(&self, a: u64) -> u64 {
        u64::from_le_bytes(core::array::from_fn(|i| {
            self.0.get(&(a + i as u64)).copied().unwrap_or(0)
        }))
    }
}

impl GuestMemory for Flat {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        for (i, b) in bytes.iter_mut().enumerate() {
            let a = address.0 + i as u64;
            if !Self::mapped(a) {
                return Err(MemoryFault {
                    address: VirtualAddress(a),
                });
            }
            *b = self.0.get(&a).copied().unwrap_or(0);
        }
        Ok(())
    }
    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
        if let Some(a) = (address.0..address.0 + bytes.len() as u64).find(|a| !Self::mapped(*a)) {
            return Err(MemoryFault {
                address: VirtualAddress(a),
            });
        }
        for (i, b) in bytes.iter().enumerate() {
            self.0.insert(address.0 + i as u64, *b);
        }
        Ok(())
    }
}

fn x(n: u8) -> OperandRegister {
    OperandRegister::Gpr(Gpr::new(n).unwrap())
}

struct Rig {
    cpu: CpuState,
    monitor: ExclusiveMonitor,
    memory: Flat,
}

impl Rig {
    fn el1() -> Self {
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.el1.vbar = VirtualAddress(VBAR);
        cpu.pc = ProgramCounter(PC);
        Self {
            cpu,
            monitor: ExclusiveMonitor::default(),
            memory: Flat::default(),
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
    fn pc(&self) -> u64 {
        self.cpu.pc.0
    }
}

#[test]
fn mrs_reads_into_rt_and_advances() {
    let mut r = Rig::el1();
    r.cpu.el1.sctlr = Sctlr(0x30d0_0800);
    assert_eq!(r.run(0xd5381003), Outcome::Continue); // mrs x3, sctlr_el1
    assert_eq!((r.get(3), r.pc()), (0x30d0_0800, PC + 4));
}

#[test]
fn production_sysreg_roundtrips_obey_register_widths() {
    // MSR encodings for the read/write registers in the typed ELF and vector
    // census, with inputs and readback derived from DDI0487G.a C5.2/D13.2.
    for (msr, input, expected) in [
        (0xd5182000, 0x0000_1234_5678_9000, 0x0000_1234_5678_9000), // TTBR0_EL1
        (0xd5184100, 0x1234_8000, 0x1234_8000),                     // SP_EL0
        (0xd518d020, 0x1234_abcd_9876_5432, 0x9876_5432),           // CONTEXTIDR_EL1
        (0xd51bd040, 0x1234_abcd_0000_8000, 0x1234_abcd_0000_8000), // TPIDR_EL0
        (0xd51bd060, 0x1234_abcd_0000_9000, 0x1234_abcd_0000_9000), // TPIDRRO_EL0
        (0xd51b4220, 0xffff_ffff_ffff_fe7f, 0x240),                 // DAIF
        (0xd51b4400, 0xffff_ffff_0440_6000, 0x0440_0000),           // FPCR
        (0xd51b4420, 0xffff_ffff_ffff_ffff, 0x0800_009f),           // FPSR
        (0xd5184020, 0x1234_abcd_0000_3100, 0x1234_abcd_0000_3100), // ELR_EL1
        (0xd5184000, 0xffff_ffff_a000_0145, 0xa000_0145),           // SPSR_EL1
        (0xd5185200, 0xffff_ffff_9200_004f, 0x9200_004f),           // ESR_EL1
        (0xd5186000, 0x1234_abcd_0000_2210, 0x1234_abcd_0000_2210), // FAR_EL1
        (0xd518d080, 0x1234_abcd_0000_9000, 0x1234_abcd_0000_9000), // TPIDR_EL1
    ] {
        let mut r = Rig::el1();
        r.set(0, input);
        r.set(1, !expected);
        assert_eq!(r.run(msr), Outcome::Continue, "MSR {msr:#x}");
        assert_eq!(r.pc(), PC + 4, "MSR {msr:#x}");
        let mrs = msr | (1 << 21) | 1; // MRS to X1
        assert_eq!(r.run(mrs), Outcome::Continue, "MRS {mrs:#x}");
        assert_eq!(r.pc(), PC + 8, "MRS {mrs:#x}");
        assert_eq!(r.get(1), expected, "MRS {mrs:#x}");
    }
}

#[test]
fn production_sysreg_reads_use_virtual_cpu_state() {
    let mut r = Rig::el1();
    r.cpu.named.mpidr = SystemValue(0x1234_12ab_4503_0201);
    r.cpu.named.par = SystemValue(0x8123);
    r.cpu.named.cntfrq = SystemValue(0xffff_ffff_017d_7840);
    r.cpu.named.cntvct = SystemValue(0x2345_6789_abcd_ef00);
    r.cpu.named.icciar1 = SystemValue(0x3ff);

    for (mrs, expected) in [
        (0xd53800a1, 0x0000_00ab_c103_0201), // MPIDR_EL1
        (0xd5387401, 0x8123),                // PAR_EL1
        (0xd53be001, 25_000_000),            // CNTFRQ_EL0
        (0xd53be041, 0x2345_6789_abcd_ef00), // CNTVCT_EL0
        (0xd538cc01, 0x3ff),                 // ICC_IAR1_EL1
    ] {
        let pc = r.pc();
        assert_eq!(r.run(mrs), Outcome::Continue, "MRS {mrs:#x}");
        assert_eq!(r.pc(), pc + 4, "MRS {mrs:#x}");
        assert_eq!(r.get(1), expected, "MRS {mrs:#x}");
    }
}

#[test]
fn production_sysreg_writes_update_their_owned_slots() {
    let mut r = Rig::el1();
    r.cpu.named.cntvctl = SystemValue(4); // provider's read-only ISTATUS
    for (msr, input) in [
        (0xd5182020, 0x1234_abcd_8000),      // TTBR1_EL1
        (0xd51be320, 0xffff_ffff_ffff_fffb), // CNTV_CTL_EL0
        (0xd51be340, 0x1_2345_6789),         // CNTV_CVAL_EL0
        (0xd518cc20, 0x29),                  // ICC_EOIR1_EL1
        (0xd518cba0, 0x100_0001),            // ICC_SGI1R_EL1
    ] {
        let pc = r.pc();
        r.set(0, input);
        assert_eq!(r.run(msr), Outcome::Continue, "MSR {msr:#x}");
        assert_eq!(r.pc(), pc + 4, "MSR {msr:#x}");
    }
    assert_eq!(r.cpu.named.ttbr1.0, 0x1234_abcd_8000);
    assert_eq!(r.cpu.named.cntvctl.0, 7);
    assert_eq!(r.cpu.named.cntvcval.0, 0x1_2345_6789);
    assert_eq!(r.cpu.named.icceoir1.0, 0x29);
    assert_eq!(r.cpu.named.iccsgi1r.0, 0x100_0001);
}

#[test]
fn msr_at_el0_to_an_el1_register_is_undefined() {
    let mut r = Rig::el0();
    r.set(3, 5);
    assert_eq!(r.run(0xd5181003), Outcome::Continue); // msr sctlr_el1, x3
    assert_eq!(r.pc(), VBAR + 0x400);
    assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
    assert_eq!(r.cpu.el1.esr, Syndrome(0x0200_0000));
    assert_eq!(r.cpu.el1.sctlr, Sctlr(0));
}

#[test]
fn msr_sctlr_setting_m_stops_without_retiring() {
    let mut r = Rig::el1();
    r.set(3, 0x30d0_0801);
    assert_eq!(
        r.run(0xd5181003),
        Outcome::Event(Event::MmuEnable {
            value: SystemValue(0x30d0_0801)
        })
    );
    assert_eq!((r.pc(), r.cpu.el1.sctlr), (PC, Sctlr(0)));
    // Clearing M (or writing without M) retires normally.
    r.set(3, 0x30d0_0800);
    assert_eq!(r.run(0xd5181003), Outcome::Continue);
    assert_eq!((r.pc(), r.cpu.el1.sctlr), (PC + 4, Sctlr(0x30d0_0800)));
}

#[test]
fn svc_from_el0_saves_next_pc_and_enters_lower_el_vector() {
    let mut r = Rig::el0();
    r.cpu.pstate.nzcv = 0b1010;
    assert_eq!(r.run(0xd40000a1), Outcome::Continue); // svc #5
    assert_eq!(r.pc(), VBAR + 0x400);
    assert_eq!(r.cpu.el1.elr, ProgramCounter(PC + 4));
    assert_eq!(r.cpu.el1.esr, Syndrome((0x15 << 26) | (1 << 25) | 5));
    assert_eq!(r.cpu.el1.spsr, SavedPstate(0xa000_0000));
    assert_eq!(r.cpu.pstate.el, ExceptionLevel::El1);
}

#[test]
fn hvc_at_el1_is_a_provider_exit_after_the_instruction() {
    let mut r = Rig::el1();
    let saved = r.cpu.el1.clone();
    let Outcome::Event(Event::ProviderExit(exit)) = r.run(0xd4000022) else {
        panic!("hvc #1 must exit to the provider");
    };
    assert_eq!(exit.immediate.value(), 1);
    assert_eq!((r.pc(), r.cpu.el1.clone()), (PC + 4, saved));
}

#[test]
fn brk_and_smc_take_exceptions_at_the_faulting_pc() {
    let mut r = Rig::el1();
    assert_eq!(r.run(0xd42000e0), Outcome::Continue); // brk #7
    assert_eq!(r.pc(), VBAR + 0x200);
    assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
    assert_eq!(r.cpu.el1.esr, Syndrome((0x3c << 26) | (1 << 25) | 7));
    let mut r = Rig::el1();
    r.run(0xd4000003); // smc #0: no EL3
    assert_eq!(r.cpu.el1.esr, Syndrome(0x0200_0000));
    assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
}

#[test]
fn eret_restores_el0_and_clears_the_monitor() {
    let mut r = Rig::el1();
    r.cpu.el1.elr = ProgramCounter(0x4000);
    r.cpu.el1.spsr = SavedPstate(0x6000_0000);
    r.set(0, 0x10000);
    r.run(0xc85f7c01); // ldxr x1, [x0]
    r.cpu.pc = ProgramCounter(PC);
    assert!(r.monitor.is_open());
    assert_eq!(r.run(0xd69f03e0), Outcome::Continue);
    assert_eq!(r.pc(), 0x4000);
    assert_eq!(
        (r.cpu.pstate.el, r.cpu.pstate.nzcv),
        (ExceptionLevel::El0, 0b0110)
    );
    assert!(!r.monitor.is_open());
}

#[test]
fn illegal_eret_restores_uao_from_spsr_el1() {
    for uao in [true, false] {
        let mut r = Rig::el1();
        r.cpu.pstate.uao = !uao;
        r.cpu.el1.elr = ProgramCounter(0x4000);
        // EL2h is illegal when returning from EL1. NZCV=0xb, PAN=1, DAIF=6.
        r.cpu.el1.spsr = SavedPstate(0xb040_0189 | (u64::from(uao) << 23));
        assert_eq!(r.run(0xd69f_03e0), Outcome::Continue); // eret
        assert_eq!(r.pc(), 0x4000);
        assert_eq!(
            r.cpu.pstate,
            Pstate {
                el: ExceptionLevel::El1,
                sp: StackSelect::El1,
                nzcv: 0xb,
                daif: InterruptMasks(6),
                pan: true,
                uao,
                il: true,
            }
        );
    }
}

#[test]
fn indirect_branches_read_rn_before_linking() {
    let mut r = Rig::el1();
    r.set(30, 0x5000);
    assert_eq!(r.run(0xd63f03c0), Outcome::Continue); // blr x30
    assert_eq!((r.pc(), r.get(30)), (0x5000, PC + 4));
    r.set(2, 0x6000);
    r.run(0xd61f0040); // br x2
    assert_eq!((r.pc(), r.get(30)), (0x6000, PC + 4));
    r.run(0xd65f03c0); // ret
    assert_eq!(r.pc(), PC + 4);
}

#[test]
fn loads_zero_and_sign_extend() {
    let mut r = Rig::el1();
    r.memory.put(0x10008, 0x8877_6655_4433_2211);
    r.memory.put(0x10010, 0xf0);
    r.set(0, 0x10000);
    r.run(0xf9400401); // ldr x1, [x0, #8]
    assert_eq!((r.get(1), r.pc()), (0x8877_6655_4433_2211, PC + 4));
    r.set(0, 0x10010);
    r.run(0x39c00001); // ldrsb w1, [x0]
    assert_eq!(r.get(1), 0xffff_fff0);
    r.run(0x39800001); // ldrsb x1, [x0]
    assert_eq!(r.get(1), 0xffff_ffff_ffff_fff0);
    r.run(0x39400001); // ldrb w1, [x0]
    assert_eq!(r.get(1), 0xf0);
}

#[test]
fn pre_and_post_index_write_back_the_base() {
    let mut r = Rig::el1();
    r.memory.put(0x10010, 11);
    r.memory.put(0x10000, 22);
    r.set(0, 0x10000);
    r.run(0xf8410c01); // ldr x1, [x0, #16]!
    assert_eq!((r.get(1), r.get(0)), (11, 0x10010));
    r.set(0, 0x10000);
    r.run(0xf8410401); // ldr x1, [x0], #16
    assert_eq!((r.get(1), r.get(0)), (22, 0x10010));
}

#[test]
fn stores_truncate_to_the_access_size() {
    let mut r = Rig::el1();
    r.memory.put(0x10000, u64::MAX);
    r.set(0, 0x10000);
    r.set(1, 0x1122_3344_5566_7788);
    r.run(0xb9000001); // str w1, [x0]
    assert_eq!(r.memory.get(0x10000), 0xffff_ffff_5566_7788);
}

#[test]
fn register_offset_scales_and_extends() {
    let mut r = Rig::el1();
    r.memory.put(0x10000 + 3 * 8, 99);
    r.set(0, 0x10000);
    r.set(2, 0xffff_ffff_0000_0003);
    r.run(0xf8625801); // ldr x1, [x0, w2, uxtw #3]
    assert_eq!(r.get(1), 99);
}

#[test]
fn pairs_use_consecutive_slots() {
    let mut r = Rig::el1();
    r.set(0, 0x10000);
    r.set(1, 7);
    r.set(2, 9);
    r.run(0xa9010801); // stp x1, x2, [x0, #16]
    assert_eq!((r.memory.get(0x10010), r.memory.get(0x10018)), (7, 9));
    r.run(0xa9411003); // ldp x3, x4, [x0, #16]
    assert_eq!((r.get(3), r.get(4)), (7, 9));
    // stp x29, x30, [sp, #-16]! through the banked EL1 SP.
    r.cpu.sp_el1 = StackPointer(0x10100);
    r.set(29, 1);
    r.set(30, 2);
    r.run(0xa9bf7bfd);
    assert_eq!(r.cpu.sp_el1, StackPointer(0x100f0));
    assert_eq!((r.memory.get(0x100f0), r.memory.get(0x100f8)), (1, 2));
}

#[test]
fn literal_loads_are_pc_relative() {
    let mut r = Rig::el1();
    r.memory.put(PC + 8, 0xabcd);
    r.run(0x58000041); // ldr x1, #8
    assert_eq!(r.get(1), 0xabcd);
}

#[test]
fn exclusive_pairs_succeed_once_and_clrex_breaks_them() {
    let mut r = Rig::el1();
    r.set(0, 0x10000);
    r.set(1, 0);
    r.run(0xc85f7c01); // ldxr x1, [x0]
    r.set(1, 42);
    r.run(0xc8027c01); // stxr w2, x1, [x0]
    assert_eq!((r.get(2), r.memory.get(0x10000)), (0, 42));
    r.set(1, 43);
    r.run(0xc8027c01); // a second stxr has no reservation
    assert_eq!((r.get(2), r.memory.get(0x10000)), (1, 42));
    r.run(0xc85f7c01);
    r.run(0xd503305f); // clrex
    r.run(0xc8027c01);
    assert_eq!((r.get(2), r.memory.get(0x10000)), (1, 42));
}

#[test]
fn ldadd_returns_the_old_value() {
    let mut r = Rig::el1();
    r.memory.put(0x10000, 40);
    r.set(0, 0x10000);
    r.set(1, 2);
    r.run(0xf8210002); // ldadd x1, x2, [x0]
    assert_eq!((r.get(2), r.memory.get(0x10000)), (40, 42));
}

#[test]
fn unmapped_access_stops_with_no_state_change() {
    let mut r = Rig::el1();
    r.set(0, 0x9000_0000);
    r.set(1, 5);
    let before = r.cpu.clone();
    assert_eq!(
        r.run(0xf8410c01), // ldr x1, [x0, #16]!
        Outcome::Event(Event::MemoryFault(MemoryFault {
            address: VirtualAddress(0x9000_0010)
        }))
    );
    assert_eq!(r.cpu, before);
}

#[test]
fn daif_immediates_set_clear_and_trap_at_el0() {
    let mut r = Rig::el1();
    r.run(0xd50343df); // msr daifset, #3
    assert_eq!(r.cpu.pstate.daif, InterruptMasks(3));
    r.run(0xd50342ff); // msr daifclr, #2
    assert_eq!(r.cpu.pstate.daif, InterruptMasks(1));
    let mut r = Rig::el0();
    r.run(0xd50342ff);
    assert_eq!(r.pc(), VBAR + 0x400);
    // EC=0x18, IL, op2=7, op1=3, CRn=4, Rt=31, CRm=2, direction write.
    let iss = (7 << 17) | (3 << 14) | (4 << 10) | (31 << 5) | (2 << 1);
    assert_eq!(r.cpu.el1.esr, Syndrome((0x18 << 26) | (1 << 25) | iss));
}

#[test]
fn tlbi_is_an_event_at_el1_and_undefined_at_el0() {
    let mut r = Rig::el1();
    assert_eq!(
        r.run(0xd508871f),
        Outcome::Event(Event::Tlbi(TlbiOperation::Vmalle1))
    );
    assert_eq!(r.pc(), PC + 4);
    let mut r = Rig::el0();
    assert_eq!(r.run(0xd508871f), Outcome::Continue);
    assert_eq!(r.cpu.el1.esr, Syndrome(0x0200_0000));
}

#[test]
fn waits_are_events_after_the_instruction() {
    let mut r = Rig::el1();
    assert_eq!(r.run(0xd503207f), Outcome::Event(Event::Hint(Hint::Wfi)));
    assert_eq!(r.pc(), PC + 4);
}

#[test]
fn el0_waits_trap_under_their_own_sctlr_control() {
    // DDI0487G.a WFxTrap and ConditionSyndrome: EC=1, IL=1,
    // CV=1, COND=AL, TI=0 for WFI and 1 for WFE.
    for (word, hint, enable, other_enable, esr) in [
        (0xd503207f, Hint::Wfi, 1 << 16, 1 << 18, 0x07e0_0000),
        (0xd503205f, Hint::Wfe, 1 << 18, 1 << 16, 0x07e0_0001),
    ] {
        let mut r = Rig::el0();
        r.cpu.el1.sctlr = Sctlr(other_enable);
        r.cpu.pstate.nzcv = 0xa;
        assert_eq!(r.run(word), Outcome::Continue);
        assert_eq!(r.pc(), VBAR + 0x400);
        assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
        assert_eq!(r.cpu.el1.esr, Syndrome(esr));
        assert_eq!(r.cpu.el1.spsr, SavedPstate(0xa000_0000));

        let mut r = Rig::el0();
        r.cpu.el1.sctlr = Sctlr(enable);
        assert_eq!(r.run(word), Outcome::Event(Event::Hint(hint)));
        assert_eq!(r.pc(), PC + 4);

        let mut r = Rig::el1();
        assert_eq!(r.run(word), Outcome::Event(Event::Hint(hint)));
        assert_eq!(r.pc(), PC + 4);
    }
}

#[test]
fn wfe_consumes_a_pending_local_event_before_checking_the_trap() {
    for (word, hint) in [(0xd503209f, Hint::Sev), (0xd50320bf, Hint::Sevl)] {
        let mut r = Rig::el0();
        assert_eq!(r.run(word), Outcome::Event(Event::Hint(hint)));
        assert_eq!(r.run(0xd503205f), Outcome::Continue); // WFE consumes the event
        assert_eq!(r.pc(), PC + 8);
        assert_eq!(r.run(0xd503205f), Outcome::Continue); // WFE traps
        assert_eq!(r.pc(), VBAR + 0x400);
        assert_eq!(r.cpu.el1.elr, ProgramCounter(PC + 8));
        assert_eq!(r.cpu.el1.esr, Syndrome(0x07e0_0001));
    }
}

#[test]
fn higher_el_tlbi_and_at_are_undefined_at_el1() {
    for word in [
        0xd50c_871f, // tlbi alle2
        0xd50e_871f, // tlbi alle3
        0xd50c_7800, // at s1e2r, x0
        0xd50c_7880, // at s12e1r, x0
        0xd50c_78e0, // at s12e0w, x0
        0xd50e_7800, // at s1e3r, x0
    ] {
        let mut r = Rig::el1();
        assert_eq!(r.run(word), Outcome::Continue, "{word:#010x}");
        assert_eq!(r.pc(), VBAR + 0x200);
        assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
        assert_eq!(r.cpu.el1.esr, Syndrome(0x0200_0000));
    }
}

#[test]
fn el1_ic_iallu_retires_and_el0_ic_iallu_is_undefined() {
    for (word, expected) in [
        (0xd508_711f, carrick_softcpu_aarch64::IcOperation::Ialluis),
        (0xd508_751f, carrick_softcpu_aarch64::IcOperation::Iallu),
    ] {
        let mut r = Rig::el1();
        assert_eq!(r.run(word), Outcome::Event(Event::Ic(expected)));
        assert_eq!(r.pc(), PC + 4);

        let mut r = Rig::el0();
        assert_eq!(r.run(word), Outcome::Continue);
        assert_eq!(r.pc(), VBAR + 0x400);
        assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
        assert_eq!(r.cpu.el1.esr, Syndrome(0x0200_0000));
    }
}

#[test]
fn el1_at_requires_a_walk_and_el0_at_is_undefined() {
    for word in [
        0xd508_7800, // at s1e1r, x0
        0xd508_7820, // at s1e1w, x0
        0xd508_7840, // at s1e0r, x0
        0xd508_7860, // at s1e0w, x0
        0xd508_7900, // at s1e1rp, x0
        0xd508_7920, // at s1e1wp, x0
    ] {
        let mut r = Rig::el1();
        assert_eq!(r.run(word), Outcome::Event(Event::AddressTranslate));
        assert_eq!(r.pc(), PC);

        let mut r = Rig::el0();
        assert_eq!(r.run(word), Outcome::Continue);
        assert_eq!(r.pc(), VBAR + 0x400);
        assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
        assert_eq!(r.cpu.el1.esr, Syndrome(0x0200_0000));
    }
}

#[test]
fn strict_scalar_and_pair_alignment_fault_before_memory_or_writeback() {
    for (word, offset, write) in [
        (0xf940_0020, 0, false), // ldr x0, [x1]
        (0xf800_8c20, 8, true),  // str x0, [x1, #8]!
        (0xa940_0820, 0, false), // ldp x0, x2, [x1]
    ] {
        let mut r = Rig::el1();
        r.cpu.el1.sctlr = Sctlr(1 << 1); // A, with M clear
        r.set(0, 42);
        r.set(1, 0x10001);
        r.set(2, 43);
        assert_eq!(r.run(word), Outcome::Continue);
        assert_eq!(r.pc(), VBAR + 0x200);
        assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
        assert_eq!(r.cpu.el1.far, VirtualAddress(0x10001 + offset));
        assert_eq!(
            r.cpu.el1.esr,
            Syndrome(0x9600_0021 | (u64::from(write) << 6))
        );
        assert_eq!((r.get(0), r.get(1), r.get(2)), (42, 0x10001, 43));
        assert!(r.memory.0.is_empty());
    }

    // Ordinary pair accesses check element alignment, including when A=1.
    let mut r = Rig::el1();
    r.cpu.el1.sctlr = Sctlr(1 << 1);
    r.set(1, 0x10008);
    r.memory.put(0x10008, 17);
    r.memory.put(0x10010, 19);
    assert_eq!(r.run(0xa940_0820), Outcome::Continue);
    assert_eq!((r.pc(), r.get(0), r.get(2)), (PC + 4, 17, 19));

    // The flat RAM model permits an ordinary unaligned load with A clear.
    r.cpu.el1.sctlr = Sctlr(0);
    r.set(1, 0x10001);
    r.memory.put(0x10001, 23);
    assert_eq!(r.run(0xf940_0020), Outcome::Continue);
    assert_eq!((r.pc(), r.get(0)), (PC + 8, 23));
}

#[test]
fn exclusive_ordered_and_lse_accesses_fault_with_alignment_check_disabled() {
    for (word, address, write) in [
        (0xc85f_7c20, 0x10001, false), // ldxr x0, [x1]
        (0xc803_7c20, 0x10001, true),  // stxr w3, x0, [x1]
        (0xc87f_0820, 0x10008, false), // ldxp x0, x2, [x1]
        (0xc823_0820, 0x10008, true),  // stxp w3, x0, x2, [x1]
        (0xc8df_fc20, 0x10001, false), // ldar x0, [x1]
        (0xc89f_fc20, 0x10001, true),  // stlr x0, [x1]
        (0xf822_0020, 0x10001, false), // ldadd x2, x0, [x1]: alignment check is a read
    ] {
        let mut r = Rig::el0();
        r.set(0, 42);
        r.set(1, address);
        r.set(2, 43);
        r.set(3, 44);
        assert_eq!(r.run(word), Outcome::Continue, "{word:#010x}");
        assert_eq!(r.pc(), VBAR + 0x400, "{word:#010x}");
        assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
        assert_eq!(r.cpu.el1.far, VirtualAddress(address));
        assert_eq!(
            r.cpu.el1.esr,
            Syndrome(0x9200_0021 | (u64::from(write) << 6))
        );
        assert_eq!((r.get(0), r.get(2), r.get(3)), (42, 43, 44));
        assert!(r.memory.0.is_empty());
        assert!(!r.monitor.is_open());
    }
}

#[test]
fn spsel_immediates_switch_the_active_stack_at_el1_only() {
    let mut r = Rig::el1();
    r.cpu.sp_el0 = StackPointer(0x10000);
    r.cpu.sp_el1 = StackPointer(0x11000);
    assert_eq!(r.run(0xd500_40bf), Outcome::Continue); // msr spsel, #0
    assert_eq!((r.pc(), r.cpu.sp()), (PC + 4, StackPointer(0x10000)));
    assert_eq!(r.run(0xd500_41bf), Outcome::Continue); // msr spsel, #1
    assert_eq!((r.pc(), r.cpu.sp()), (PC + 8, StackPointer(0x11000)));
    assert_el0_undefined(0xd500_41bf);
}

#[test]
fn pan_immediates_set_and_clear_at_el1_only() {
    let mut r = Rig::el1();
    assert_eq!(r.run(0xd500_419f), Outcome::Continue); // msr pan, #1
    assert_eq!((r.pc(), r.cpu.pstate.pan), (PC + 4, true));
    assert_eq!(r.run(0xd500_409f), Outcome::Continue); // msr pan, #0
    assert_eq!((r.pc(), r.cpu.pstate.pan), (PC + 8, false));
    assert_el0_undefined(0xd500_419f);
}

#[test]
fn uao_immediates_set_and_clear_at_el1_only() {
    let mut r = Rig::el1();
    assert_eq!(r.run(0xd500_417f), Outcome::Continue); // msr uao, #1
    assert_eq!((r.pc(), r.cpu.pstate.uao), (PC + 4, true));
    assert_eq!(r.run(0xd500_407f), Outcome::Continue); // msr uao, #0
    assert_eq!((r.pc(), r.cpu.pstate.uao), (PC + 8, false));
    assert_el0_undefined(0xd500_417f);
}

#[test]
fn uma_allows_daif_immediates_at_el0() {
    let mut r = Rig::el0();
    r.cpu.el1.sctlr = Sctlr(1 << 9); // UMA
    assert_eq!(r.run(0xd503_43df), Outcome::Continue); // msr daifset, #3
    assert_eq!((r.pc(), r.cpu.pstate.daif), (PC + 4, InterruptMasks(3)));
    assert_eq!(r.run(0xd503_42ff), Outcome::Continue); // msr daifclr, #2
    assert_eq!((r.pc(), r.cpu.pstate.daif), (PC + 8, InterruptMasks(1)));
}

fn assert_el0_undefined(word: u32) {
    let mut r = Rig::el0();
    assert_eq!(r.run(word), Outcome::Continue);
    assert_eq!(r.pc(), VBAR + 0x400);
    assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
    assert_eq!(r.cpu.el1.esr, Syndrome(0x0200_0000));
}

#[test]
fn eret_and_hvc_are_undefined_at_el0() {
    assert_el0_undefined(0xd69f_03e0); // eret
    assert_el0_undefined(0xd400_0022); // hvc #1
}

#[test]
fn sp_el0_sysreg_access_requires_the_el1_stack_bank() {
    const MSR: u32 = 0xd518_4101; // msr sp_el0, x1
    const MRS: u32 = 0xd538_4102; // mrs x2, sp_el0

    let mut r = Rig::el1();
    r.cpu.sp_el1 = StackPointer(0x11000);
    r.set(1, 0x10000);
    assert_eq!(r.run(MSR), Outcome::Continue);
    assert_eq!(r.run(MRS), Outcome::Continue);
    assert_eq!((r.pc(), r.get(2), r.cpu.sp().0), (PC + 8, 0x10000, 0x11000));

    for word in [MSR, MRS] {
        let mut r = Rig::el1();
        r.cpu.pstate.sp = StackSelect::El0;
        r.cpu.sp_el0 = StackPointer(0x10000);
        r.set(1, 0x11000);
        assert_eq!(r.run(word), Outcome::Continue);
        assert_eq!(r.pc(), VBAR); // current EL with SP_EL0
        assert_eq!(r.cpu.el1.elr, ProgramCounter(PC));
        assert_eq!(r.cpu.el1.esr, Syndrome(0x0200_0000));
        assert_eq!((r.cpu.sp_el0.0, r.get(2)), (0x10000, 0));
        assert_el0_undefined(word);
    }
}

#[test]
fn vbar_el1_write_discards_res0_bits() {
    let mut r = Rig::el1();
    r.set(1, VBAR | 0x7ff);
    assert_eq!(r.run(0xd518_c001), Outcome::Continue); // msr vbar_el1, x1
    assert_eq!(r.cpu.el1.vbar, VirtualAddress(VBAR));
    assert_eq!(r.run(0xd538_c002), Outcome::Continue); // mrs x2, vbar_el1
    assert_eq!((r.pc(), r.get(2)), (PC + 8, VBAR));
}
