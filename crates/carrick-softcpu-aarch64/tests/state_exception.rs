//! Known answers: DDI0487G.a D1 exception entry/return and D13.2 ESR_EL1;
//! A2's three worked scalar stage-1 fault examples.
use carrick_softcpu_aarch64::{exception::*, state::*};

#[test]
fn scalar_abort_known_answers() {
    for (el, access, fault, expected) in [
        (
            ExceptionLevel::El1,
            Access::Read,
            FaultStatus::Permission(LeafLevel::L3),
            0x9600_000f,
        ),
        (
            ExceptionLevel::El0,
            Access::Write,
            FaultStatus::Permission(LeafLevel::L3),
            0x9200_004f,
        ),
        (
            ExceptionLevel::El0,
            Access::Fetch,
            FaultStatus::Translation(TableLevel::L2),
            0x8200_0006,
        ),
    ] {
        let mut cpu = CpuState::default();
        cpu.pstate.el = el;
        cpu.pc = ProgramCounter(0x1234);
        cpu.el1.vbar = VirtualAddress(0x8000);
        take_exception(
            &mut cpu,
            Exception::Abort {
                access,
                status: fault,
                address: VirtualAddress(0xab00_0000_1000),
            },
        );
        assert_eq!(cpu.el1.esr, Syndrome(expected));
        assert_eq!(cpu.el1.far, VirtualAddress(0xab00_0000_1000));
        assert_eq!(cpu.el1.elr, ProgramCounter(0x1234));
    }
}

#[test]
fn vectors_banking_and_return() {
    for (el, sp, offset) in [
        (ExceptionLevel::El0, StackSelect::El0, 0x400),
        (ExceptionLevel::El1, StackSelect::El0, 0),
        (ExceptionLevel::El1, StackSelect::El1, 0x200),
    ] {
        for (event, extra) in [
            (Exception::Svc(9), 0),
            (Exception::Irq, 0x80),
            (Exception::Fiq, 0x100),
            (Exception::SError, 0x180),
        ] {
            let mut cpu = CpuState::default();
            cpu.pstate.el = el;
            cpu.pstate.sp = sp;
            cpu.pstate.uao = true;
            cpu.pc = ProgramCounter(0x1000);
            cpu.el1.vbar = VirtualAddress(0x8000);
            cpu.sp_el0 = StackPointer(0x2000);
            cpu.sp_el1 = StackPointer(0x3000);
            let saved = cpu.pstate;
            take_exception(&mut cpu, event);
            assert_eq!(cpu.pc, ProgramCounter(0x8000 + offset + extra));
            assert_eq!(cpu.sp(), StackPointer(0x3000));
            assert_eq!(cpu.pstate.daif, InterruptMasks::ALL);
            assert!(cpu.pstate.pan);
            assert!(!cpu.pstate.uao);
            eret(&mut cpu).unwrap();
            assert_eq!(cpu.pstate, saved);
            assert_eq!(
                cpu.pc,
                ProgramCounter(if matches!(event, Exception::Svc(_)) {
                    0x1004
                } else {
                    0x1000
                })
            );
        }
    }
}

#[test]
fn hvc_preserves_saved_exception_and_illegal_return_sets_il() {
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.el1.esr = Syndrome(0x9600_000f);
    let saved = cpu.el1.clone();
    assert_eq!(
        take_exception(&mut cpu, Exception::Hvc(3)),
        ExceptionOutcome::ProviderExit(ProviderExit { immediate: 3 })
    );
    assert_eq!(cpu.el1, saved);
    cpu.el1.spsr = SavedPstate(0x8); // unimplemented EL2
    cpu.el1.elr = ProgramCounter(0x9000);
    eret(&mut cpu).unwrap();
    assert!(cpu.pstate.il);
    assert_eq!(cpu.pstate.el, ExceptionLevel::El1);
    assert_eq!(cpu.pc, ProgramCounter(0x9000));
}
