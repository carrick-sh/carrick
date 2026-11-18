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
