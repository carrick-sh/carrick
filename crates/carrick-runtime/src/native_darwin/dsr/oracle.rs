use carrick_guest_mem::GuestVa;

use super::super::NativeUcontextSnapshot;
use super::block::{BlockPlan, PlannedExit, PlannedInst};
use super::cache::TranslationCache;
use super::emit::{EmittedBlock, emit_block};
use super::gateway::enter_translated;
use super::types::{
    CodeGeneration, DirectExit, DirectKind, DsrError, IndirectExit, IndirectKind, InstAction,
    NativeDsrExit, PcRelativeInst, PcRelativeKind,
};

fn legacy_brk_round_trip(
    entry: super::types::CacheVa,
    snapshot: &mut NativeUcontextSnapshot,
) -> Result<(), DsrError> {
    let mut seeded = *snapshot;
    seeded.pc = entry.host().raw() as u64;
    if unsafe { super::super::carrick_native_seed_ucontext(&seeded) } != 0 {
        return Err(DsrError::Gateway("seed brk comparison context".to_string()));
    }
    if unsafe { super::super::carrick_native_resume_detached_context() } != 1 {
        return Err(DsrError::Gateway(
            "enter brk comparison context".to_string(),
        ));
    }
    *snapshot =
        super::super::snapshot_ucontext().map_err(|error| DsrError::Gateway(error.to_string()))?;
    Ok(())
}

fn median(samples: &mut [f64]) -> f64 {
    samples.sort_by(f64::total_cmp);
    samples[samples.len() / 2]
}

fn seeded_snapshot(stack_pointer: u64) -> NativeUcontextSnapshot {
    let mut snapshot = NativeUcontextSnapshot {
        sp: stack_pointer,
        pstate: 0x6000_0000,
        fpsr: 0x0800_0000,
        fpcr: 0x0040_0000,
        ..NativeUcontextSnapshot::default()
    };
    for (index, register) in snapshot.x.iter_mut().enumerate() {
        *register = 0x1100_0000_0000_0000 | index as u64;
    }
    for (index, vector) in snapshot.v.iter_mut().enumerate() {
        *vector = (0x2200_0000_0000_0000_0000_0000_0000_0000_u128 | index as u128).to_le_bytes();
    }
    snapshot
}

fn run_full_state_oracle() -> Result<(), DsrError> {
    let mut stack = vec![0_u8; 16 * 1024];
    let stack_pointer = stack.as_mut_ptr() as u64 + stack.len() as u64;
    let mut snapshot = seeded_snapshot(stack_pointer);
    let expected = snapshot;
    let plan = BlockPlan {
        start: GuestVa(0x4000),
        end: GuestVa(0x4008),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: InstAction::Copy(0x9100_0400), // add x0, x0, #1
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x4004),
            resume: GuestVa(0x4008),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024)?;
    let emitted = emit_block(&mut cache, &plan)?;
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x4008),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)?;
    if snapshot.x[0] != expected.x[0] + 1
        || snapshot.x[1..] != expected.x[1..]
        || snapshot.sp != expected.sp
        || snapshot.pstate != expected.pstate
        || snapshot.v != expected.v
        || snapshot.fpsr != expected.fpsr
        || snapshot.fpcr != expected.fpcr
        || !matches!(
            exit,
            NativeDsrExit::Syscall {
                resume: GuestVa(0x4008)
            }
        )
    {
        let changed_registers = snapshot
            .x
            .iter()
            .zip(expected.x.iter())
            .enumerate()
            .filter_map(|(index, (observed, expected))| {
                (index != 0 && observed != expected)
                    .then_some(format!("x{index}=0x{observed:x}/0x{expected:x}"))
            })
            .collect::<Vec<_>>();
        return Err(DsrError::Gateway(format!(
            "full-state oracle mismatch: regs={changed_registers:?} sp={:x}/{:x} pstate={:x}/{:x} vectors={} fpsr={:x}/{:x} fpcr={:x}/{:x} exit={exit:?}",
            snapshot.sp,
            expected.sp,
            snapshot.pstate,
            expected.pstate,
            snapshot.v == expected.v,
            snapshot.fpsr,
            expected.fpsr,
            snapshot.fpcr,
            expected.fpcr,
        )));
    }
    Ok(())
}

#[test]
fn dsr_gateway_preserves_full_state_around_enumerated_change() {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        let result = run_full_state_oracle();
        if let Err(error) = &result {
            eprintln!("DSR gateway oracle child: {error}");
        }
        unsafe { libc::_exit(i32::from(result.is_err())) };
    }

    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn dsr_pc_relative_adr_materializes_guest_target() {
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let target = GuestVa(0x1234_5678_9abc_def0);
    let plan = BlockPlan {
        start: GuestVa(0x4000),
        end: GuestVa(0x4008),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: InstAction::PcRelative(PcRelativeInst {
                kind: PcRelativeKind::Adr,
                target,
                destination: Some(bad64::Reg::X0),
                word: 0x1000_0000,
            }),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x4004),
            resume: GuestVa(0x4008),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate PC-relative cache");
    let emitted = emit_block(&mut cache, &plan).expect("emit ADR relocation");
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x4008),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute ADR relocation");
    assert_eq!(snapshot.x[0], target.raw());
}

#[test]
fn dsr_pc_relative_literal_load_reads_guest_address() {
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let value = 0x8877_6655_4433_2211_u64;
    let target = GuestVa((&value as *const u64) as u64);
    let plan = BlockPlan {
        start: GuestVa(0x5000),
        end: GuestVa(0x5008),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: GuestVa(0x5000),
            action: InstAction::PcRelative(PcRelativeInst {
                kind: PcRelativeKind::LiteralLoad,
                target,
                destination: Some(bad64::Reg::X0),
                word: 0x5800_0000,
            }),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x5004),
            resume: GuestVa(0x5008),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate literal-load cache");
    let emitted = emit_block(&mut cache, &plan).expect("emit literal-load relocation");
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x5008),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("execute literal-load relocation");
    assert_eq!(snapshot.x[0], value);
}

#[test]
fn dsr_pc_relative_literals_cover_integer_simd_prefetch_and_virtual_x18() {
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let expected_x17 = snapshot.x[17];
    let word_value = 0xfedc_ba98_u32;
    let signed_value = -123_456_i32;
    let x18_value = 0x8877_6655_4433_2211_u64;
    let ignored_value = 0xdead_beef_cafe_babe_u64;
    let s_value = 0x1122_3344_u32;
    let d_value = 0x0123_4567_89ab_cdef_u64;
    let q_value = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdef_u128;
    let cases = [
        (0x1800_0000, (&word_value as *const u32) as u64), // ldr w0, literal
        (0x9800_0001, (&signed_value as *const i32) as u64), // ldrsw x1, literal
        (0x5800_0012, (&x18_value as *const u64) as u64),  // ldr x18, literal
        (0x5800_001f, (&ignored_value as *const u64) as u64), // ldr xzr, literal
        (0x1800_001f, (&word_value as *const u32) as u64), // ldr wzr, literal
        (0x1c00_0002, (&s_value as *const u32) as u64),    // ldr s2, literal
        (0x5c00_0003, (&d_value as *const u64) as u64),    // ldr d3, literal
        (0x9c00_0004, (&q_value as *const u128) as u64),   // ldr q4, literal
        (0xd800_0000, (&ignored_value as *const u64) as u64), // prfm literal
    ];
    let instructions = cases
        .into_iter()
        .enumerate()
        .map(|(index, (word, target))| PlannedInst {
            guest: GuestVa(0x6000 + index as u64 * 4),
            action: super::decode::classify(word, GuestVa(0x6000 + index as u64 * 4))
                .and_then(|action| match action {
                    InstAction::PcRelative(mut relative) => {
                        relative.target = GuestVa(target);
                        Ok(InstAction::PcRelative(relative))
                    }
                    _ => Err(DsrError::BlockPolicy(format!(
                        "literal test word 0x{word:08x} did not classify as PC-relative"
                    ))),
                })
                .expect("classify literal test instruction"),
        })
        .collect::<Vec<_>>();
    let exit_pc = GuestVa(0x6000 + instructions.len() as u64 * 4);
    let plan = BlockPlan {
        start: GuestVa(0x6000),
        end: GuestVa(exit_pc.raw() + 4),
        generation: CodeGeneration::INITIAL,
        instructions,
        exit: PlannedExit::Syscall {
            guest: exit_pc,
            resume: GuestVa(exit_pc.raw() + 4),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate literal matrix cache");
    let emitted = emit_block(&mut cache, &plan).expect("emit literal relocation matrix");
    for offset in (0..emitted.len()).step_by(4) {
        let address = emitted.entry().host().raw() + offset;
        let word = unsafe { std::ptr::read_unaligned(address as *const u32) };
        bad64::decode(word, address as u64).expect("decode emitted literal lowering");
    }
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(exit_pc.raw() + 4),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("execute literal relocation matrix");

    assert_eq!(snapshot.x[0], u64::from(word_value));
    assert_eq!(snapshot.x[1], signed_value as i64 as u64);
    assert_eq!(snapshot.x[17], expected_x17);
    assert_eq!(snapshot.x[18], x18_value);
    assert_eq!(&snapshot.v[2][..4], &s_value.to_le_bytes());
    assert_eq!(snapshot.v[2][4..], [0; 12]);
    assert_eq!(&snapshot.v[3][..8], &d_value.to_le_bytes());
    assert_eq!(snapshot.v[3][8..], [0; 8]);
    assert_eq!(snapshot.v[4], q_value.to_le_bytes());
}

#[test]
fn dsr_pc_relative_adrp_writes_virtual_guest_x18_without_clobbering_x17() {
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let expected_x17 = snapshot.x[17];
    let target = GuestVa(0xffff_1234_5678_9000);
    let plan = BlockPlan {
        start: GuestVa(0x7000),
        end: GuestVa(0x7008),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: GuestVa(0x7000),
            action: InstAction::PcRelative(PcRelativeInst {
                kind: PcRelativeKind::Adrp,
                target,
                destination: Some(bad64::Reg::X18),
                word: 0x9000_0012,
            }),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x7004),
            resume: GuestVa(0x7008),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate ADRP cache");
    let emitted = emit_block(&mut cache, &plan).expect("emit ADRP relocation");
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x7008),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute ADRP relocation");
    assert_eq!(snapshot.x[17], expected_x17);
    assert_eq!(snapshot.x[18], target.raw());
}

#[test]
fn dsr_direct_flow_unresolved_branch_reports_guest_target() {
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let target = GuestVa(0x9000);
    let plan = BlockPlan {
        start: GuestVa(0x8000),
        end: GuestVa(0x8004),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Direct {
            guest: GuestVa(0x8000),
            word: 0x1400_0400,
            exit: DirectExit {
                kind: DirectKind::Branch,
                target,
                resume: GuestVa(0x8004),
                condition: None,
                register: None,
                bit: None,
            },
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate direct-flow cache");
    let emitted = emit_block(&mut cache, &plan).expect("emit unresolved direct branch");
    let mut exit = NativeDsrExit::ResolveDirect {
        source: GuestVa(0x8000),
        target,
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("execute unresolved direct branch");
    assert_eq!(
        exit,
        NativeDsrExit::ResolveDirect {
            source: GuestVa(0x8000),
            target,
        }
    );
}

fn patch_direct_target(
    cache: &mut TranslationCache,
    source: &EmittedBlock,
    guest_target: GuestVa,
    target: &EmittedBlock,
) {
    let link = source
        .direct_links()
        .iter()
        .find(|link| link.target == guest_target)
        .expect("find direct link target");
    cache
        .patch_direct_branch(
            super::cache::LinkSite {
                source: source.entry(),
                slot: link.slot,
            },
            target.entry(),
        )
        .expect("patch direct link");
}

fn syscall_plan(start: GuestVa, word: u32) -> BlockPlan {
    BlockPlan {
        start,
        end: GuestVa(start.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: start,
            action: InstAction::Copy(word),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(start.raw() + 4),
            resume: GuestVa(start.raw() + 8),
        },
    }
}

#[test]
fn dsr_direct_flow_linked_branch_stays_in_translated_code_and_preserves_x17() {
    let mut cache = TranslationCache::new(32 * 1024).expect("allocate linked-flow cache");
    let source_plan = BlockPlan {
        start: GuestVa(0xa000),
        end: GuestVa(0xa008),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: GuestVa(0xa000),
            action: InstAction::Copy(0x9100_0631), // add x17, x17, #1
        }],
        exit: PlannedExit::Direct {
            guest: GuestVa(0xa004),
            word: 0x1400_03ff,
            exit: DirectExit {
                kind: DirectKind::Branch,
                target: GuestVa(0xb000),
                resume: GuestVa(0xa008),
                condition: None,
                register: None,
                bit: None,
            },
        },
    };
    let source = emit_block(&mut cache, &source_plan).expect("emit linked source");
    let target = emit_block(&mut cache, &syscall_plan(GuestVa(0xb000), 0x9100_0400))
        .expect("emit linked target"); // add x0, x0, #1
    patch_direct_target(&mut cache, &source, GuestVa(0xb000), &target);

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let expected_x0 = snapshot.x[0] + 1;
    let expected_x17 = snapshot.x[17] + 1;
    let mut exit = NativeDsrExit::ResolveDirect {
        source: GuestVa(0xa004),
        target: GuestVa(0xb000),
    };
    enter_translated(source.entry(), &mut snapshot, &mut exit).expect("execute linked branch");
    assert_eq!(snapshot.x[0], expected_x0);
    assert_eq!(snapshot.x[17], expected_x17);
    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(0xb008)
        }
    );
}

#[test]
fn dsr_direct_flow_conditional_edges_select_taken_and_fallthrough_links() {
    let mut cache = TranslationCache::new(64 * 1024).expect("allocate conditional-flow cache");
    let source_plan = BlockPlan {
        start: GuestVa(0xc000),
        end: GuestVa(0xc004),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Direct {
            guest: GuestVa(0xc000),
            word: 0xb400_0800, // cbz x0, 0xc100
            exit: DirectExit {
                kind: DirectKind::CompareZero { nonzero: false },
                target: GuestVa(0xc100),
                resume: GuestVa(0xc004),
                condition: None,
                register: Some(bad64::Reg::X0),
                bit: None,
            },
        },
    };
    let source = emit_block(&mut cache, &source_plan).expect("emit conditional source");
    let fallthrough = emit_block(&mut cache, &syscall_plan(GuestVa(0xc004), 0x9100_0821))
        .expect("emit fallthrough target"); // add x1, x1, #2
    let taken = emit_block(&mut cache, &syscall_plan(GuestVa(0xc100), 0x9100_0421))
        .expect("emit taken target"); // add x1, x1, #1
    patch_direct_target(&mut cache, &source, GuestVa(0xc004), &fallthrough);
    patch_direct_target(&mut cache, &source, GuestVa(0xc100), &taken);

    for (x0, increment, resume) in [(0, 1, 0xc108), (7, 2, 0xc00c)] {
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.x[0] = x0;
        let expected_x1 = snapshot.x[1] + increment;
        let mut exit = NativeDsrExit::ResolveDirect {
            source: GuestVa(0xc000),
            target: GuestVa(0xc100),
        };
        enter_translated(source.entry(), &mut snapshot, &mut exit)
            .expect("execute linked conditional branch");
        assert_eq!(snapshot.x[1], expected_x1);
        assert_eq!(
            exit,
            NativeDsrExit::Syscall {
                resume: GuestVa(resume)
            }
        );
    }
}

#[test]
fn dsr_direct_flow_linked_call_observes_guest_lr() {
    let mut cache = TranslationCache::new(32 * 1024).expect("allocate call-flow cache");
    let call_plan = BlockPlan {
        start: GuestVa(0xd000),
        end: GuestVa(0xd004),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Direct {
            guest: GuestVa(0xd000),
            word: 0x9400_0400,
            exit: DirectExit {
                kind: DirectKind::Call,
                target: GuestVa(0xe000),
                resume: GuestVa(0xd004),
                condition: None,
                register: None,
                bit: None,
            },
        },
    };
    let call = emit_block(&mut cache, &call_plan).expect("emit linked call");
    let nested_plan = BlockPlan {
        start: GuestVa(0xe000),
        end: GuestVa(0xe004),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Direct {
            guest: GuestVa(0xe000),
            word: 0x9400_0040,
            exit: DirectExit {
                kind: DirectKind::Call,
                target: GuestVa(0xe100),
                resume: GuestVa(0xe004),
                condition: None,
                register: None,
                bit: None,
            },
        },
    };
    let nested = emit_block(&mut cache, &nested_plan).expect("emit nested call");
    let callee = emit_block(&mut cache, &syscall_plan(GuestVa(0xe100), 0x9100_03c0))
        .expect("emit final callee"); // add x0, x30, #0
    patch_direct_target(&mut cache, &call, GuestVa(0xe000), &nested);
    patch_direct_target(&mut cache, &nested, GuestVa(0xe100), &callee);
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut exit = NativeDsrExit::ResolveDirect {
        source: GuestVa(0xd000),
        target: GuestVa(0xe000),
    };
    enter_translated(call.entry(), &mut snapshot, &mut exit).expect("execute linked call");
    assert_eq!(snapshot.x[30], 0xe004);
    assert_eq!(snapshot.x[0], 0xe004);
}

#[test]
fn dsr_direct_flow_condition_codes_and_virtual_x18_bits_choose_guest_edges() {
    let cases = [
        (0x5400_0040, 0_u64), // b.eq +8; seeded NZCV has Z set
        (0x3600_0052, 0_u64), // tbz w18, #0, +8
        (0x3700_0052, 1_u64), // tbnz w18, #0, +8
    ];
    for (word, guest_x18) in cases {
        let start = GuestVa(0x12_000);
        let action = super::decode::classify(word, start).expect("classify conditional edge");
        let InstAction::Direct(exit) = action else {
            panic!("conditional word did not classify as direct: 0x{word:08x}");
        };
        let plan = BlockPlan {
            start,
            end: GuestVa(start.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Direct {
                guest: start,
                word,
                exit,
            },
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate condition cache");
        let emitted = emit_block(&mut cache, &plan).expect("emit condition edge");
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.x[18] = guest_x18;
        let expected_x17 = snapshot.x[17];
        let mut observed = NativeDsrExit::ResolveDirect {
            source: start,
            target: exit.target,
        };
        enter_translated(emitted.entry(), &mut snapshot, &mut observed)
            .expect("execute conditional edge");
        assert_eq!(snapshot.x[17], expected_x17);
        assert_eq!(
            observed,
            NativeDsrExit::ResolveDirect {
                source: start,
                target: GuestVa(start.raw() + 8),
            }
        );
    }
}

#[test]
fn dsr_direct_flow_linked_backward_loop_reaches_fallthrough() {
    let mut cache = TranslationCache::new(32 * 1024).expect("allocate loop-flow cache");
    let loop_plan = BlockPlan {
        start: GuestVa(0xf000),
        end: GuestVa(0xf008),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: GuestVa(0xf000),
            action: InstAction::Copy(0xf100_0400), // subs x0, x0, #1
        }],
        exit: PlannedExit::Direct {
            guest: GuestVa(0xf004),
            word: 0xb5ff_ffe0, // cbnz x0, 0xf000
            exit: DirectExit {
                kind: DirectKind::CompareZero { nonzero: true },
                target: GuestVa(0xf000),
                resume: GuestVa(0xf008),
                condition: None,
                register: Some(bad64::Reg::X0),
                bit: None,
            },
        },
    };
    let loop_block = emit_block(&mut cache, &loop_plan).expect("emit linked loop");
    let done = emit_block(&mut cache, &syscall_plan(GuestVa(0xf008), 0xd503_201f))
        .expect("emit loop fallthrough");
    patch_direct_target(&mut cache, &loop_block, GuestVa(0xf000), &loop_block);
    patch_direct_target(&mut cache, &loop_block, GuestVa(0xf008), &done);
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = 4;
    let mut exit = NativeDsrExit::ResolveDirect {
        source: GuestVa(0xf004),
        target: GuestVa(0xf000),
    };
    enter_translated(loop_block.entry(), &mut snapshot, &mut exit)
        .expect("execute linked backward loop");
    assert_eq!(snapshot.x[0], 0);
    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(0xf010)
        }
    );
}

#[test]
fn dsr_indirect_flow_unresolved_return_reports_guest_register_target() {
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate indirect-flow cache");
    let plan = BlockPlan {
        start: GuestVa(0x13_000),
        end: GuestVa(0x13_004),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Indirect {
            guest: GuestVa(0x13_000),
            word: 0xd65f_03c0,
            exit: IndirectExit {
                kind: IndirectKind::Return,
                register: bad64::Reg::X30,
                resume: GuestVa(0x13_004),
            },
        },
    };
    let emitted = emit_block(&mut cache, &plan).expect("emit unresolved return");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[30] = 0x14_000;
    let mut exit = NativeDsrExit::ResolveIndirect {
        source: GuestVa(0x13_000),
        target: GuestVa(0x14_000),
        link: None,
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute unresolved return");
    assert_eq!(
        exit,
        NativeDsrExit::ResolveIndirect {
            source: GuestVa(0x13_000),
            target: GuestVa(0x14_000),
            link: None,
        }
    );
}

#[test]
fn dsr_indirect_flow_blr_sets_guest_link_and_alternates_targets() {
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate BLR cache");
    let plan = BlockPlan {
        start: GuestVa(0x15_000),
        end: GuestVa(0x15_004),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Indirect {
            guest: GuestVa(0x15_000),
            word: 0xd63f_00a0, // blr x5
            exit: IndirectExit {
                kind: IndirectKind::Call,
                register: bad64::Reg::X5,
                resume: GuestVa(0x15_004),
            },
        },
    };
    let emitted = emit_block(&mut cache, &plan).expect("emit BLR");
    for target in [GuestVa(0x16_000), GuestVa(0x17_000), GuestVa(0x16_000)] {
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.x[5] = target.raw();
        let mut exit = NativeDsrExit::ResolveIndirect {
            source: GuestVa(0x15_000),
            target,
            link: Some(GuestVa(0x15_004)),
        };
        enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute BLR");
        assert_eq!(snapshot.x[30], 0x15_004);
        assert_eq!(
            exit,
            NativeDsrExit::ResolveIndirect {
                source: GuestVa(0x15_000),
                target,
                link: Some(GuestVa(0x15_004)),
            }
        );
    }
}

#[test]
fn dsr_indirect_flow_branch_reads_virtual_guest_x18() {
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate x18 branch cache");
    let plan = BlockPlan {
        start: GuestVa(0x18_000),
        end: GuestVa(0x18_004),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Indirect {
            guest: GuestVa(0x18_000),
            word: 0xd61f_0240, // br x18
            exit: IndirectExit {
                kind: IndirectKind::Branch,
                register: bad64::Reg::X18,
                resume: GuestVa(0x18_004),
            },
        },
    };
    let emitted = emit_block(&mut cache, &plan).expect("emit virtual x18 branch");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[18] = 0x19_000;
    let expected_x17 = snapshot.x[17];
    let mut exit = NativeDsrExit::ResolveIndirect {
        source: GuestVa(0x18_000),
        target: GuestVa(0x19_000),
        link: None,
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("execute virtual x18 branch");
    assert_eq!(snapshot.x[17], expected_x17);
    assert_eq!(snapshot.x[18], 0x19_000);
    assert_eq!(
        exit,
        NativeDsrExit::ResolveIndirect {
            source: GuestVa(0x18_000),
            target: GuestVa(0x19_000),
            link: None,
        }
    );
}

#[test]
#[ignore = "explicit 30-sample Task 5 performance feasibility gate"]
fn dsr_gateway_perf_feasibility_30_samples() {
    const SAMPLES: usize = 30;
    const TRANSITIONS_PER_SAMPLE: usize = 200;

    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );
    let mut stack = vec![0_u8; 16 * 1024];
    let stack_pointer = stack.as_mut_ptr() as u64 + stack.len() as u64;
    let initial = seeded_snapshot(stack_pointer);
    let plan = BlockPlan {
        start: GuestVa(0x4000),
        end: GuestVa(0x4004),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x4000),
            resume: GuestVa(0x4004),
        },
    };
    let mut dsr_cache = TranslationCache::new(16 * 1024).expect("allocate DSR perf cache");
    let emitted = emit_block(&mut dsr_cache, &plan).expect("emit DSR perf block");
    let mut brk_cache = TranslationCache::new(16 * 1024).expect("allocate brk perf cache");
    let mut writer = brk_cache.begin_write(4).expect("begin brk perf write");
    writer
        .write_words(&[super::super::BRK_NATIVE_SYSCALL])
        .expect("write brk perf instruction");
    let brk = writer.publish().expect("publish brk perf instruction");

    for _ in 0..20 {
        let mut dsr_snapshot = initial;
        let mut exit = NativeDsrExit::Syscall {
            resume: GuestVa(0x4004),
        };
        enter_translated(emitted.entry(), &mut dsr_snapshot, &mut exit).expect("warm DSR gateway");
        let mut brk_snapshot = initial;
        legacy_brk_round_trip(brk.entry(), &mut brk_snapshot).expect("warm brk gateway");
    }

    let mut dsr_samples = Vec::with_capacity(SAMPLES);
    let mut brk_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = std::time::Instant::now();
        for _ in 0..TRANSITIONS_PER_SAMPLE {
            let mut snapshot = initial;
            let mut exit = NativeDsrExit::Syscall {
                resume: GuestVa(0x4004),
            };
            enter_translated(emitted.entry(), &mut snapshot, &mut exit)
                .expect("measure DSR gateway");
        }
        dsr_samples.push(start.elapsed().as_nanos() as f64 / TRANSITIONS_PER_SAMPLE as f64);

        let start = std::time::Instant::now();
        for _ in 0..TRANSITIONS_PER_SAMPLE {
            let mut snapshot = initial;
            legacy_brk_round_trip(brk.entry(), &mut snapshot).expect("measure brk gateway");
        }
        brk_samples.push(start.elapsed().as_nanos() as f64 / TRANSITIONS_PER_SAMPLE as f64);
    }

    let dsr_p50_ns = median(&mut dsr_samples);
    let brk_p50_ns = median(&mut brk_samples);
    eprintln!(
        "dsr_gateway_perf samples={SAMPLES} transitions_per_sample={TRANSITIONS_PER_SAMPLE} dsr_p50_ns={dsr_p50_ns:.1} brk_p50_ns={brk_p50_ns:.1} ratio={:.3}",
        dsr_p50_ns / brk_p50_ns
    );
    assert!(
        dsr_p50_ns < brk_p50_ns,
        "exception-free DSR gateway did not beat brk: dsr={dsr_p50_ns:.1}ns brk={brk_p50_ns:.1}ns"
    );
}
