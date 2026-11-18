//! Known answers: DDI0487G.a D1 exception entry/return and D13.2 ESR_EL1;
//! A2's scalar stage-1 examples plus an EL1 instruction permission abort.
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
        (
            ExceptionLevel::El1,
            Access::Fetch,
            FaultStatus::Permission(LeafLevel::L2),
            0x8600_000e,
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
            (
                Exception::Svc(carrick_softcpu_aarch64::Immediate16::new(9)),
                0,
            ),
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
        take_exception(
            &mut cpu,
            Exception::Hvc(carrick_softcpu_aarch64::Immediate16::new(3))
        ),
        ExceptionOutcome::ProviderExit(ProviderExit {
            immediate: carrick_softcpu_aarch64::Immediate16::new(3)
        })
    );
    assert_eq!(cpu.el1, saved);
    cpu.el1.spsr = SavedPstate(0x8); // unimplemented EL2
    cpu.el1.elr = ProgramCounter(0x9000);
    eret(&mut cpu).unwrap();
    assert!(cpu.pstate.il);
    assert_eq!(cpu.pstate.el, ExceptionLevel::El1);
    assert_eq!(cpu.pc, ProgramCounter(0x9000));
}

#[test]
fn illegal_return_restores_unconditional_fields() {
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    cpu.el1.spsr = SavedPstate(0xa040_0148); // NZCV, PAN, DAIF, illegal EL2
    eret(&mut cpu).unwrap();
    assert_eq!(cpu.pstate.daif, InterruptMasks(5));
    assert!(cpu.pstate.pan);
    assert_eq!(cpu.pstate.nzcv, 10);
    assert_eq!(cpu.pstate.sp, StackSelect::El1);
}

fn sys(fields: (u8, u8, u8, u8, u8)) -> carrick_softcpu_aarch64::SystemRegister {
    let (op0, op1, crn, crm, op2) = fields;
    carrick_softcpu_aarch64::SystemRegister {
        op0,
        op1,
        crn,
        crm,
        op2,
    }
}
#[test]
fn el0_privileged_register_is_undefined_not_a_system_trap() {
    let cpu = CpuState::default();
    let error = cpu
        .mrs(
            sys((3, 0, 4, 0, 1)),
            carrick_softcpu_aarch64::OperandRegister::Zr,
        )
        .unwrap_err();
    assert_eq!(error.syndrome, Syndrome(0x0200_0000));
}

#[test]
fn system_register_roundtrips_and_access_syndromes() {
    use carrick_softcpu_aarch64::{Instruction, OperandRegister, decode_instruction};
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.pstate.sp = StackSelect::El1;
    // D13/C5 register encodings, independent of the name lookup implementation.
    for fields in [
        (3, 0, 2, 0, 0),
        (3, 0, 2, 0, 1),
        (3, 0, 13, 0, 1),
        (3, 3, 13, 0, 2),
        (3, 3, 13, 0, 3),
        (3, 3, 4, 4, 0),
        (3, 3, 4, 4, 1),
        (3, 0, 7, 4, 0),
        (3, 3, 14, 3, 1),
        (3, 3, 14, 3, 2),
        (3, 0, 4, 0, 1),
        (3, 0, 4, 0, 0),
        (3, 0, 5, 2, 0),
        (3, 0, 6, 0, 0),
        (3, 0, 13, 0, 4),
        (3, 0, 2, 0, 2),
        (3, 0, 10, 2, 0),
    ] {
        cpu.msr(sys(fields), OperandRegister::Zr, SystemValue(0x1234))
            .unwrap();
        assert_eq!(
            cpu.mrs(sys(fields), OperandRegister::Zr).unwrap(),
            SystemValue(0x1234)
        );
    }
    for n in 0..31 {
        // MRS Xt, TPIDR_EL0 obtains an existing typed GPR operand.
        let Instruction::SystemAccess(a) = decode_instruction(0xd53bd040 | n) else {
            panic!("MRS")
        };
        cpu.write_operand(a.rt, RegisterValue(0x100 + u64::from(n)));
        assert_eq!(cpu.read_operand(a.rt), RegisterValue(0x100 + u64::from(n)));
    }
    cpu.write_operand(OperandRegister::Zr, RegisterValue(9));
    assert_eq!(cpu.read_operand(OperandRegister::Zr), RegisterValue(0));
    cpu.pstate.el = ExceptionLevel::El0;
    let trap = cpu
        .mrs(sys((3, 3, 4, 2, 1)), OperandRegister::Zr)
        .unwrap_err();
    assert_eq!(trap.syndrome, Syndrome(0x6232_d3e5)); // EC/IL, op0/op2/op1/CRn/Rt/CRm/read
    assert!(
        cpu.mrs(sys((3, 0, 15, 15, 7)), OperandRegister::Zr)
            .is_err()
    );
    assert!(
        cpu.msr(sys((3, 3, 13, 0, 3)), OperandRegister::Zr, SystemValue(0))
            .is_err()
    );
    assert!(eret(&mut cpu).is_err());
}

#[test]
fn pan_span_and_saved_status_known_answers() {
    for span in [false, true] {
        for pan in [false, true] {
            let mut cpu = CpuState::default();
            cpu.pstate = Pstate {
                el: ExceptionLevel::El1,
                sp: StackSelect::El0,
                nzcv: 10,
                daif: InterruptMasks(5),
                pan,
                uao: true,
                il: true,
            };
            cpu.el1.sctlr = Sctlr((u64::from(span) << 23) | (1 << 57));
            assert!(cpu.el1.sctlr.epan());
            take_exception(&mut cpu, Exception::Brk(0x1234));
            assert_eq!(
                cpu.el1.spsr,
                SavedPstate(0xa090_0144 | (u64::from(pan) << 22))
            );
            assert_eq!(cpu.el1.esr, Syndrome(0xf200_1234));
            assert_eq!(cpu.pstate.pan, !span || pan);
            assert!(!cpu.pstate.il);
        }
    }
    for mode in 0..32 {
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.el1.spsr = SavedPstate(mode);
        eret(&mut cpu).unwrap();
        assert_eq!(cpu.pstate.il, ![0, 4, 5].contains(&mode));
    }
}

/// Optional real-vector smoke: generate raw spans through carrick_mem::memory
/// (the CLI census's production builders), never a committed word inventory.
#[test]
fn generated_vectors_drive_state_transitions() {
    use carrick_softcpu_aarch64::{
        ExceptionKind, Instruction, SystemDirection, decode_instruction,
    };
    let Some(path) = std::env::var_os("CARRICK_A64_LOADER_SPANS") else {
        return;
    };
    let bytes = std::fs::read(path).unwrap();
    assert!(!bytes.is_empty());
    assert_eq!(bytes.len() % 4, 0);
    let mut seen = [0; 5];
    for word in bytes.chunks_exact(4) {
        let decoded = decode_instruction(u32::from_le_bytes(word.try_into().unwrap()));
        let mut cpu = CpuState::default();
        cpu.pstate.el = ExceptionLevel::El1;
        cpu.pstate.sp = StackSelect::El1;
        cpu.el1.vbar = VirtualAddress(0x8000);
        match decoded {
            Instruction::Eret => {
                cpu.el1.elr = ProgramCounter(0x1000);
                eret(&mut cpu).unwrap();
                assert_eq!(cpu.pc, ProgramCounter(0x1000));
                seen[0] += 1;
            }
            Instruction::ExceptionGeneration(e) if e.kind == ExceptionKind::Hvc => {
                let saved = cpu.el1.clone();
                assert!(matches!(
                    take_exception(
                        &mut cpu,
                        Exception::Hvc(carrick_softcpu_aarch64::Immediate16::new(e.immediate))
                    ),
                    ExceptionOutcome::ProviderExit(_)
                ));
                assert_eq!(cpu.el1, saved);
                seen[1] += 1;
            }
            Instruction::ExceptionGeneration(e) if e.kind == ExceptionKind::Svc => {
                cpu.pstate.el = ExceptionLevel::El0;
                take_exception(
                    &mut cpu,
                    Exception::Svc(carrick_softcpu_aarch64::Immediate16::new(e.immediate)),
                );
                assert_eq!(cpu.pc, ProgramCounter(0x8400));
                seen[2] += 1;
            }
            Instruction::SystemAccess(a) => match a.direction {
                SystemDirection::Read => {
                    cpu.mrs(a.encoding, a.rt).unwrap();
                    seen[3] += 1;
                }
                SystemDirection::Write => {
                    cpu.msr(a.encoding, a.rt, SystemValue(0)).unwrap();
                    seen[4] += 1;
                }
            },
            _ => (),
        }
    }
    assert!(
        seen[0] > 0 && seen[1] > 0 && seen[3] > 0 && seen[4] > 0,
        "{seen:?}"
    );
    // Loader vectors do not necessarily contain SVC, which originates in EL0.
    // SVC itself is exercised by the default known-answer vector matrix.
}

#[test]
fn hvc_at_el0_is_undefined_and_cannot_exit_provider() {
    let mut cpu = CpuState::default();
    cpu.pc = ProgramCounter(0x1000);
    assert_eq!(
        take_exception(
            &mut cpu,
            Exception::Hvc(carrick_softcpu_aarch64::Immediate16::new(1))
        ),
        ExceptionOutcome::Entered
    );
    assert_eq!(cpu.el1.esr, Syndrome(0x0200_0000));
    assert_eq!(cpu.el1.elr, ProgramCounter(0x1000));
}

#[test]
fn irq_preserves_syndrome_and_access_trap_enters_restart_vector() {
    use carrick_softcpu_aarch64::OperandRegister;
    let mut cpu = CpuState::default();
    cpu.pc = ProgramCounter(0x1000);
    cpu.el1.esr = Syndrome(0x1234);
    cpu.el1.far = VirtualAddress(0x5678);
    let error = cpu
        .mrs(sys((3, 3, 4, 2, 1)), OperandRegister::Zr)
        .unwrap_err();
    take_exception(&mut cpu, Exception::Irq);
    assert_eq!(cpu.el1.esr, Syndrome(0x1234));
    assert_eq!(cpu.el1.far, VirtualAddress(0x5678));
    eret(&mut cpu).unwrap();
    take_exception(&mut cpu, Exception::SystemAccess(error));
    assert_eq!(cpu.el1.esr, Syndrome(0x6232_d3e5));
    assert_eq!(cpu.el1.elr, ProgramCounter(0x1000));
}

#[test]
fn decoded_svc_enters_real_vector_group_then_decoded_eret_restores() {
    use carrick_softcpu_aarch64::{ExceptionKind, Instruction, decode_instruction};
    // C4.1.3 / C6 SVC immediate encoding, generated across its full field.
    for immediate in [0u16, 1, 0x1234, 0xffff] {
        let word = 0xd400_0001 | (u32::from(immediate) << 5);
        let Instruction::ExceptionGeneration(e) = decode_instruction(word) else {
            panic!("SVC")
        };
        assert_eq!(e.kind, ExceptionKind::Svc);
        let mut cpu = CpuState::default();
        cpu.pc = ProgramCounter(0x1000);
        cpu.el1.vbar = VirtualAddress(0x8000);
        take_exception(
            &mut cpu,
            Exception::Svc(carrick_softcpu_aarch64::Immediate16::new(e.immediate)),
        );
        assert_eq!(cpu.pc, ProgramCounter(0x8400));
        assert_eq!(cpu.el1.esr, Syndrome(0x5600_0000 | u64::from(immediate)));
        assert_eq!(decode_instruction(0xd69f_03e0), Instruction::Eret);
        eret(&mut cpu).unwrap();
        assert_eq!(cpu.pc, ProgramCounter(0x1004));
        assert_eq!(cpu.pstate.el, ExceptionLevel::El0);
    }
}

/// The legacy table is a production census input: lower-EL SVC -> HVC ->
/// ERET can run entirely through these state transitions. Other vector variants
/// contain memory/arithmetic instructions that belong to the A3 translator.
#[test]
fn svc_roundtrip_through_generated_production_vector_table() {
    use carrick_softcpu_aarch64::{ExceptionKind, Instruction, decode_instruction};
    let Some(path) = std::env::var_os("CARRICK_A64_VECTOR_TABLE") else {
        return;
    };
    let table = std::fs::read(path).unwrap();
    let mut cpu = CpuState::default();
    cpu.pc = ProgramCounter(0x1000);
    cpu.el1.vbar = VirtualAddress(0x8000);
    let Instruction::ExceptionGeneration(svc) = decode_instruction(0xd400_0001) else {
        panic!("SVC")
    };
    take_exception(
        &mut cpu,
        Exception::Svc(carrick_softcpu_aarch64::Immediate16::new(svc.immediate)),
    );
    let offset = usize::try_from(cpu.pc.0 - cpu.el1.vbar.0).unwrap();
    assert_eq!(offset, 0x400);
    let word = |offset| u32::from_le_bytes(table[offset..offset + 4].try_into().unwrap());
    let Instruction::ExceptionGeneration(hvc) = decode_instruction(word(offset)) else {
        panic!("production HVC")
    };
    assert_eq!(hvc.kind, ExceptionKind::Hvc);
    let saved = cpu.el1.clone();
    assert!(matches!(
        take_exception(
            &mut cpu,
            Exception::Hvc(carrick_softcpu_aarch64::Immediate16::new(hvc.immediate))
        ),
        ExceptionOutcome::ProviderExit(_)
    ));
    assert_eq!(cpu.el1, saved);
    // A3 resumes after the provider boundary; no host HVC is executed.
    cpu.pc = ProgramCounter(cpu.pc.0 + 4);
    assert_eq!(decode_instruction(word(offset + 4)), Instruction::Eret);
    eret(&mut cpu).unwrap();
    assert_eq!(cpu.pc, ProgramCounter(0x1004));
    assert_eq!(cpu.pstate.el, ExceptionLevel::El0);
}

/// D13.2.116 UMA is bit 9, independent of neighbouring controls.
#[test]
fn el0_daif_access_obeys_uma_bit_nine() {
    use carrick_softcpu_aarch64::OperandRegister;
    for control in [0, 1 << 8, 1 << 9, 1 << 10, !0u64 ^ (1 << 9)] {
        let mut cpu = CpuState::default();
        cpu.el1.sctlr = Sctlr(control);
        cpu.pstate.daif = InterruptMasks(5);
        let read = cpu.mrs(sys((3, 3, 4, 2, 1)), OperandRegister::Zr);
        let write = cpu.msr(
            sys((3, 3, 4, 2, 1)),
            OperandRegister::Zr,
            SystemValue(10 << 6),
        );
        if control & (1 << 9) != 0 {
            assert_eq!(read.unwrap(), SystemValue(5 << 6));
            write.unwrap();
            assert_eq!(cpu.pstate.daif, InterruptMasks(10));
        } else {
            assert_eq!(read.unwrap_err().syndrome, Syndrome(0x6232_d3e5));
            assert_eq!(write.unwrap_err().syndrome, Syndrome(0x6232_d3e4));
            assert_eq!(cpu.pstate.daif, InterruptMasks(5));
        }
    }
}

/// C5.2 SP_EL0 access is UNDEFINED while it is the active stack pointer.
#[test]
fn sp_el0_access_is_undefined_at_el1_using_sp_zero() {
    use carrick_softcpu_aarch64::OperandRegister;
    let mut cpu = CpuState::default();
    cpu.pstate.el = ExceptionLevel::El1;
    cpu.sp_el0 = StackPointer(0x1230);
    let register = sys((3, 0, 4, 1, 0));
    assert_eq!(
        cpu.mrs(register, OperandRegister::Zr).unwrap_err().syndrome,
        Syndrome(0x0200_0000)
    );
    assert_eq!(
        cpu.msr(register, OperandRegister::Zr, SystemValue(0x4560))
            .unwrap_err()
            .syndrome,
        Syndrome(0x0200_0000)
    );
    assert_eq!(cpu.sp_el0, StackPointer(0x1230));
    cpu.pstate.sp = StackSelect::El1;
    assert_eq!(
        cpu.mrs(register, OperandRegister::Zr).unwrap(),
        SystemValue(0x1230)
    );
    cpu.msr(register, OperandRegister::Zr, SystemValue(0x4560))
        .unwrap();
    assert_eq!(cpu.sp_el0, StackPointer(0x4560));
}

/// D13.2.140 VBAR_EL1[10:0] is RES0, including on reads of provider state.
#[test]
fn vbar_low_bits_are_res0() {
    use carrick_softcpu_aarch64::OperandRegister;
    for base in [0x8000, 0xffff_0000_1234_5800] {
        for low in 0..=0x7ff {
            let mut cpu = CpuState::default();
            cpu.pstate.el = ExceptionLevel::El1;
            cpu.pstate.sp = StackSelect::El1;
            cpu.msr(
                sys((3, 0, 12, 0, 0)),
                OperandRegister::Zr,
                SystemValue(base | low),
            )
            .unwrap();
            assert_eq!(
                cpu.mrs(sys((3, 0, 12, 0, 0)), OperandRegister::Zr).unwrap(),
                SystemValue(base)
            );
            // Public raw state can also be supplied by a provider.
            cpu.el1.vbar = VirtualAddress(base | low);
            assert_eq!(
                cpu.mrs(sys((3, 0, 12, 0, 0)), OperandRegister::Zr).unwrap(),
                SystemValue(base)
            );
            take_exception(&mut cpu, Exception::Irq);
            assert_eq!(cpu.pc, ProgramCounter(base + 0x280));
        }
    }
}

/// EL0+SP=1 cannot be produced by architectural transitions. Public raw
/// PSTATE fields can express it: banking and saving must still select EL0.
#[test]
fn raw_el0_sp_one_uses_the_el0_bank_and_saved_mode() {
    let mut cpu = CpuState::default();
    cpu.pstate.sp = StackSelect::El1;
    cpu.sp_el0 = StackPointer(0x1000);
    cpu.sp_el1 = StackPointer(0x2000);
    assert_eq!(cpu.sp(), StackPointer(0x1000));
    cpu.set_sp(StackPointer(0x3000));
    assert_eq!(cpu.sp_el0, StackPointer(0x3000));
    assert_eq!(cpu.sp_el1, StackPointer(0x2000));
    assert_eq!(cpu.pstate.save().0 & 31, 0);
}

#[test]
fn alignment_abort_is_data_only_and_preserves_fault_address() {
    for (el, access, expected) in [
        (ExceptionLevel::El0, DataAccess::Read, 0x9200_0021),
        (ExceptionLevel::El0, DataAccess::Write, 0x9200_0061),
        (ExceptionLevel::El1, DataAccess::Read, 0x9600_0021),
        (ExceptionLevel::El1, DataAccess::Write, 0x9600_0061),
    ] {
        let mut cpu = CpuState::default();
        cpu.pstate.el = el;
        take_exception(
            &mut cpu,
            Exception::Alignment {
                access,
                address: VirtualAddress(0x123),
            },
        );
        assert_eq!(cpu.el1.esr, Syndrome(expected));
        assert_eq!(cpu.el1.far, VirtualAddress(0x123));
    }
}
