use carrick_guest_mem::GuestVa;

use super::super::NativeUcontextSnapshot;
use super::block::{BlockPlan, PlannedExit, PlannedInst};
use super::cache::TranslationCache;
use super::emit::{EmittedBlock, GenerationGuard, emit_block, emit_block_with_generation};
use super::gateway::{IndirectTargetCache, enter_translated, enter_translated_with_cache};
use super::types::{
    CodeGeneration, DirectExit, DirectKind, DsrError, IndirectExit, IndirectKind, InstAction,
    NativeDsrExit, PcRelativeInst, PcRelativeKind, SensitiveExit, SensitiveKind,
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
            },
            "conditional word 0x{word:08x}"
        );
    }
}

#[test]
fn dsr_guarded_link_after_virtual_x18_condition_preserves_guest_x17() {
    use std::sync::atomic::AtomicU64;

    let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
    let source_guest = GuestVa(0x12_100);
    let target_guest = GuestVa(source_guest.raw() + 8);
    let word = 0x3700_0052; // tbnz w18, #0, +8
    let InstAction::Direct(exit) =
        super::decode::classify(word, source_guest).expect("classify virtual-x18 edge")
    else {
        panic!("virtual-x18 condition did not classify as direct");
    };
    let source_plan = BlockPlan {
        start: source_guest,
        end: GuestVa(source_guest.raw() + 4),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Direct {
            guest: source_guest,
            word,
            exit,
        },
    };
    let target_plan = BlockPlan {
        start: target_guest,
        end: GuestVa(target_guest.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: target_guest,
            action: InstAction::Copy(0xaa11_03e0), // mov x0, x17
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(target_guest.raw() + 4),
            resume: GuestVa(target_guest.raw() + 8),
        },
    };
    let mut cache = TranslationCache::new(32 * 1024).expect("allocate virtual-edge cache");
    let source = super::emit::emit_block_with_generation(
        &mut cache,
        &source_plan,
        super::emit::GenerationGuard::new(&generation, CodeGeneration::INITIAL),
    )
    .expect("emit guarded virtual edge");
    let target = super::emit::emit_block_with_generation(
        &mut cache,
        &target_plan,
        super::emit::GenerationGuard::new(&generation, CodeGeneration::INITIAL),
    )
    .expect("emit guarded virtual target");
    patch_direct_target(&mut cache, &source, target_guest, &target);

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[18] = 1;
    snapshot.x[17] = 0x1717_1717_1717_1717;
    let expected_x17 = snapshot.x[17];
    let mut observed = NativeDsrExit::Syscall {
        resume: GuestVa(target_guest.raw() + 8),
    };
    enter_translated(source.entry(), &mut snapshot, &mut observed)
        .expect("execute linked virtual-x18 condition");
    assert_eq!(snapshot.x[0], expected_x17);
    assert_eq!(snapshot.x[17], expected_x17);
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
fn dsr_indirect_flow_cache_hit_stays_in_translated_code() {
    let source_guest = GuestVa(0x18_100);
    let target_guest = GuestVa(0x18_200);
    let target_generation = CodeGeneration::claimed(2);
    let generation = std::sync::atomic::AtomicU64::new(target_generation.get());
    let mut code = TranslationCache::new(16 * 1024).expect("allocate indirect cache-hit code");
    // Production blocks carry a generation guard.  That guard must observe
    // the original guest x17 after an inline-cache hit, not the x17 scratch
    // used to hold the indirect target.
    let target = super::emit::emit_block_with_generation(
        &mut code,
        &BlockPlan {
            start: target_guest,
            end: GuestVa(target_guest.raw() + 4),
            generation: target_generation,
            instructions: Vec::new(),
            exit: PlannedExit::Syscall {
                guest: target_guest,
                resume: GuestVa(target_guest.raw() + 4),
            },
        },
        super::emit::GenerationGuard::new(&generation, target_generation),
    )
    .expect("emit indirect cache-hit target");
    let source = emit_block(
        &mut code,
        &BlockPlan {
            start: source_guest,
            end: GuestVa(source_guest.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Indirect {
                guest: source_guest,
                word: 0xd61f_0000, // br x0
                exit: IndirectExit {
                    kind: IndirectKind::Branch,
                    register: bad64::Reg::X0,
                    resume: GuestVa(source_guest.raw() + 4),
                },
            },
        },
    )
    .expect("emit indirect cache-hit source");
    let indirect = IndirectTargetCache::new();
    indirect.publish(target_guest, target_generation, target.entry());

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = target_guest.raw();
    snapshot.pstate = 0x8000_0000;
    let expected_x15 = snapshot.x[15];
    let expected_x16 = snapshot.x[16];
    let expected_x17 = snapshot.x[17];
    let expected_pstate = snapshot.pstate;
    let mut exit = NativeDsrExit::ResolveIndirect {
        source: source_guest,
        target: target_guest,
        link: None,
    };
    enter_translated_with_cache(source.entry(), &mut snapshot, &mut exit, &indirect)
        .expect("execute cached indirect branch");

    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target_guest.raw() + 4)
        }
    );
    assert_eq!(snapshot.x[15], expected_x15);
    assert_eq!(snapshot.x[16], expected_x16);
    assert_eq!(snapshot.x[17], expected_x17);
    assert_eq!(snapshot.pstate, expected_pstate);

    generation.store(3, std::sync::atomic::Ordering::Release);
    let mut stale_snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    stale_snapshot.x[0] = target_guest.raw();
    let mut stale_exit = NativeDsrExit::ResolveIndirect {
        source: source_guest,
        target: target_guest,
        link: None,
    };
    enter_translated_with_cache(
        source.entry(),
        &mut stale_snapshot,
        &mut stale_exit,
        &indirect,
    )
    .expect("execute stale cached indirect target");
    assert_eq!(
        stale_exit,
        NativeDsrExit::ResolveDirect {
            source: target_guest,
            target: target_guest,
        }
    );
}

#[test]
fn dsr_indirect_flow_cached_blr_sets_guest_link_register() {
    let source_guest = GuestVa(0x18_300);
    let target_guest = GuestVa(0x18_400);
    let resume_guest = GuestVa(source_guest.raw() + 4);
    let mut code = TranslationCache::new(16 * 1024).expect("allocate cached BLR code");
    let target = emit_block(
        &mut code,
        &BlockPlan {
            start: target_guest,
            end: GuestVa(target_guest.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Syscall {
                guest: target_guest,
                resume: GuestVa(target_guest.raw() + 4),
            },
        },
    )
    .expect("emit cached BLR target");
    let source = emit_block(
        &mut code,
        &BlockPlan {
            start: source_guest,
            end: resume_guest,
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Indirect {
                guest: source_guest,
                word: 0xd63f_0000, // blr x0
                exit: IndirectExit {
                    kind: IndirectKind::Call,
                    register: bad64::Reg::X0,
                    resume: resume_guest,
                },
            },
        },
    )
    .expect("emit cached BLR source");
    let indirect = IndirectTargetCache::new();
    indirect.publish(target_guest, CodeGeneration::INITIAL, target.entry());
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = target_guest.raw();
    let mut exit = NativeDsrExit::ResolveIndirect {
        source: source_guest,
        target: target_guest,
        link: Some(resume_guest),
    };

    enter_translated_with_cache(source.entry(), &mut snapshot, &mut exit, &indirect)
        .expect("execute cached BLR");

    assert_eq!(snapshot.x[30], resume_guest.raw());
    assert!(matches!(exit, NativeDsrExit::Syscall { .. }));
}

#[test]
fn dsr_sensitive_flow_reports_guest_pc_and_resume() {
    use std::sync::atomic::AtomicU64;

    let mut cache = TranslationCache::new(16 * 1024).expect("allocate sensitive cache");
    let generation = CodeGeneration::claimed(1);
    let current_generation = AtomicU64::new(generation.get());
    let plan = BlockPlan {
        start: GuestVa(0x1a_000),
        end: GuestVa(0x1a_004),
        generation,
        instructions: Vec::new(),
        exit: PlannedExit::Sensitive {
            guest: GuestVa(0x1a_000),
            word: 0xd53b_d040,
            exit: SensitiveExit {
                kind: SensitiveKind::ReadTpidr,
                register: Some(bad64::Reg::X0),
                resume: GuestVa(0x1a_004),
            },
        },
    };
    let emitted = emit_block_with_generation(
        &mut cache,
        &plan,
        GenerationGuard::new(&current_generation, generation),
    )
    .expect("emit sensitive exit");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut exit = NativeDsrExit::Sensitive {
        guest_pc: GuestVa(0x1a_000),
        resume: GuestVa(0x1a_004),
        generation: CodeGeneration::INITIAL,
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute sensitive exit");
    assert_eq!(
        exit,
        NativeDsrExit::Sensitive {
            guest_pc: GuestVa(0x1a_000),
            resume: GuestVa(0x1a_004),
            generation,
        }
    );
}

#[test]
fn dsr_virtual_x18_rewrites_destination_and_distinct_x17_operand() {
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate x18 rewrite cache");
    let plan = BlockPlan {
        start: GuestVa(0x1b_000),
        end: GuestVa(0x1b_00c),
        generation: CodeGeneration::INITIAL,
        instructions: vec![
            PlannedInst {
                guest: GuestVa(0x1b_000),
                action: super::decode::classify(0x9278_0032, GuestVa(0x1b_000))
                    .expect("classify x18 AND"),
            },
            PlannedInst {
                guest: GuestVa(0x1b_004),
                action: super::decode::classify(0x8b11_0252, GuestVa(0x1b_004))
                    .expect("classify x18 plus x17"),
            },
        ],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x1b_008),
            resume: GuestVa(0x1b_00c),
        },
    };
    let emitted = emit_block(&mut cache, &plan).expect("emit x18 rewrites");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[1] = 0x123;
    let expected_x17 = snapshot.x[17];
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x1b_00c),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute x18 rewrites");
    assert_eq!(snapshot.x[18], 0x100_u64.wrapping_add(expected_x17));
    assert_eq!(snapshot.x[17], expected_x17);
}

#[test]
fn dsr_virtual_x18_madd_then_aliasing_loads_preserve_computed_address() {
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate x18 alias cache");
    let plan = BlockPlan {
        start: GuestVa(0x1b_080),
        end: GuestVa(0x1b_090),
        generation: CodeGeneration::INITIAL,
        instructions: vec![
            PlannedInst {
                guest: GuestVa(0x1b_080),
                action: super::decode::classify(0x9b0b_2612, GuestVa(0x1b_080))
                    .expect("classify madd x18, x16, x11, x9"),
            },
            PlannedInst {
                guest: GuestVa(0x1b_084),
                action: super::decode::classify(0xb940_0251, GuestVa(0x1b_084))
                    .expect("classify ldr w17, [x18]"),
            },
            PlannedInst {
                guest: GuestVa(0x1b_088),
                action: super::decode::classify(0x7940_0e52, GuestVa(0x1b_088))
                    .expect("classify ldrh w18, [x18, #6]"),
            },
        ],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x1b_08c),
            resume: GuestVa(0x1b_090),
        },
    };
    let generation = std::sync::atomic::AtomicU64::new(CodeGeneration::INITIAL.get());
    let emitted = super::emit::emit_block_with_generation(
        &mut cache,
        &plan,
        super::emit::GenerationGuard::new(&generation, CodeGeneration::INITIAL),
    )
    .expect("emit guarded x18 aliasing loads");
    let mut record = [0_u8; 16];
    record[..4].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    record[6..8].copy_from_slice(&0x9abc_u16.to_le_bytes());
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[9] = record.as_ptr() as u64;
    snapshot.x[11] = 24;
    snapshot.x[16] = 0;
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x1b_090),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("execute x18 aliasing loads");
    assert_eq!(snapshot.x[17], 0x1234_5678);
    assert_eq!(snapshot.x[18], 0x9abc);
}

#[test]
fn dsr_virtual_x28_rewrites_destination_and_distinct_x17_operand() {
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate x28 rewrite cache");
    let plan = BlockPlan {
        start: GuestVa(0x1b_100),
        end: GuestVa(0x1b_10c),
        generation: CodeGeneration::INITIAL,
        instructions: vec![
            PlannedInst {
                guest: GuestVa(0x1b_100),
                action: super::decode::classify(0x9100_043c, GuestVa(0x1b_100))
                    .expect("classify add x28, x1, #1"),
            },
            PlannedInst {
                guest: GuestVa(0x1b_104),
                action: super::decode::classify(0x8b11_039c, GuestVa(0x1b_104))
                    .expect("classify x28 plus x17"),
            },
        ],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x1b_108),
            resume: GuestVa(0x1b_10c),
        },
    };
    let emitted = emit_block(&mut cache, &plan).expect("emit x28 rewrites");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[1] = 0x123;
    let expected_x17 = snapshot.x[17];
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x1b_10c),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute x28 rewrites");
    assert_eq!(snapshot.x[28], 0x124_u64.wrapping_add(expected_x17));
    assert_eq!(snapshot.x[17], expected_x17);
}

#[test]
fn dsr_dual_virtual_read_only_store_uses_guest_x18_and_x28() {
    let guest = GuestVa(0x1b_180);
    let plan = BlockPlan {
        start: guest,
        end: GuestVa(guest.raw() + 12),
        generation: CodeGeneration::INITIAL,
        instructions: vec![
            PlannedInst {
                guest,
                action: super::decode::classify(0xa900_4b82, guest)
                    .expect("classify stp x2, x18, [x28]"),
            },
            PlannedInst {
                guest: GuestVa(guest.raw() + 4),
                action: super::decode::classify(0xa90b_4b91, GuestVa(guest.raw() + 4))
                    .expect("classify stp x17, x18, [x28, #176]"),
            },
        ],
        exit: PlannedExit::Syscall {
            guest: GuestVa(guest.raw() + 8),
            resume: GuestVa(guest.raw() + 12),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate dual rewrite cache");
    let emitted = emit_block(&mut cache, &plan).expect("emit dual virtual store");
    let mut stored = [0_u64; 24];
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[2] = 0x2222_2222_2222_2222;
    snapshot.x[18] = 0x1818_1818_1818_1818;
    snapshot.x[28] = stored.as_mut_ptr() as u64;
    let expected_x15_x17 = [snapshot.x[15], snapshot.x[16], snapshot.x[17]];
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest.raw() + 12),
    };

    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("execute dual virtual store");

    assert_eq!(&stored[..2], &[snapshot.x[2], snapshot.x[18]]);
    assert_eq!(&stored[22..], &[snapshot.x[17], snapshot.x[18]]);
    assert_eq!(
        [snapshot.x[15], snapshot.x[16], snapshot.x[17]],
        expected_x15_x17
    );
    assert_eq!(snapshot.x[28], stored.as_mut_ptr() as u64);
}

#[test]
fn dsr_dual_virtual_add_commits_guest_x18_from_guest_x28() {
    let guest = GuestVa(0x1b_1c0);
    let plan = BlockPlan {
        start: guest,
        end: GuestVa(guest.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest,
            action: super::decode::classify(0x910a_6392, guest)
                .expect("classify add x18, x28, #0x298"),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(guest.raw() + 4),
            resume: GuestVa(guest.raw() + 8),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate dual add cache");
    let emitted = emit_block(&mut cache, &plan).expect("emit dual virtual add");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[28] = 0x8000;
    let expected_x15_x17 = [snapshot.x[15], snapshot.x[16], snapshot.x[17]];
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest.raw() + 8),
    };

    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute dual virtual add");

    assert_eq!(snapshot.x[18], 0x8298);
    assert_eq!(snapshot.x[28], 0x8000);
    assert_eq!(
        [snapshot.x[15], snapshot.x[16], snapshot.x[17]],
        expected_x15_x17
    );
}

#[test]
fn dsr_dual_virtual_load_commits_guest_x18_and_ordinary_destination() {
    let guest = GuestVa(0x1b_200);
    let plan = BlockPlan {
        start: guest,
        end: GuestVa(guest.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest,
            action: super::decode::classify(0xa94d_cb8f, guest)
                .expect("classify ldp x15, x18, [x28, #216]"),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(guest.raw() + 4),
            resume: GuestVa(guest.raw() + 8),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate dual load cache");
    let emitted = emit_block(&mut cache, &plan).expect("emit dual virtual load");
    let mut source = [0_u64; 29];
    source[27] = 0x1515_1515_1515_1515;
    source[28] = 0x1818_1818_1818_1818;
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[28] = source.as_ptr() as u64;
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest.raw() + 8),
    };

    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute dual virtual load");

    assert_eq!(snapshot.x[15], source[27]);
    assert_eq!(snapshot.x[18], source[28]);
    assert_eq!(snapshot.x[28], source.as_ptr() as u64);
}

#[test]
fn dsr_generation_guard_rejects_stale_block_before_guest_instruction() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
    let guest = GuestVa(0x1b_200);
    let plan = BlockPlan {
        start: guest,
        end: GuestVa(guest.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest,
            action: InstAction::Copy(0x9100_0400), // add x0, x0, #1
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(guest.raw() + 4),
            resume: GuestVa(guest.raw() + 8),
        },
    };
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate generation guard cache");
    let emitted = super::emit::emit_block_with_generation(
        &mut cache,
        &plan,
        super::emit::GenerationGuard::new(&generation, CodeGeneration::INITIAL),
    )
    .expect("emit guarded block");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let original_x0 = snapshot.x[0];
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest.raw() + 8),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute current block");
    assert_eq!(snapshot.x[0], original_x0 + 1);

    generation.store(1, Ordering::Release);
    snapshot.x[0] = original_x0;
    snapshot.pc = guest.raw();
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("reject stale block");
    assert_eq!(
        snapshot.x[0], original_x0,
        "stale guest instruction executed"
    );
    assert_eq!(
        exit,
        NativeDsrExit::ResolveDirect {
            source: guest,
            target: guest,
        }
    );
}

#[test]
fn dsr_vdso_x18_rewrites_match_native_execution() {
    let words = [
        0x2941_0c12,
        0x2a12_03fb,
        0x0b1b_024c,
        0x3940_0a12,
        0x5310_3e52,
        0x2a10_6250,
        0x3840_4dd2,
        0x2a0d_224d,
        0x3940_0152,
        0xaa0e_224e,
        0x3940_09d2,
        0x5310_3e52,
        0x2a0e_624e,
        0x3940_0552,
        0x3900_0572,
        0xaa08_03f2,
        0xcb08_0251,
        0x8b12_0012,
        0x3900_0249,
        0x9100_2243,
        0x3900_164a,
        0x3900_0e4b,
        0x3900_0a4c,
        0x3900_064d,
        0x3800_4e4e,
        0x3900_0e4f,
        0x3900_0a50,
        0xaa03_03f2,
    ];
    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );

    for (index, word) in words.into_iter().enumerate() {
        let guest = GuestVa(0x1b_100 + index as u64 * 0x10);
        let action = super::decode::classify(word, guest).expect("classify vDSO x18 word");
        assert!(matches!(action, InstAction::VirtualizedX18 { .. }));
        let mut memory = [0_u8; 512];
        for (offset, byte) in memory.iter_mut().enumerate() {
            *byte = offset as u8;
        }
        let pristine = memory;
        let base = unsafe { memory.as_mut_ptr().add(128) } as u64;
        let mut stack = vec![0_u8; 16 * 1024];
        let mut initial = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        for register in &mut initial.x {
            *register = base;
        }
        initial.x[8] = 1;
        initial.x[17] = base;
        initial.x[18] = base;

        let mut native_cache = TranslationCache::new(16 * 1024).expect("allocate native oracle");
        let mut writer = native_cache
            .begin_write(8)
            .expect("begin native oracle write");
        writer
            .write_words(&[word, super::super::BRK_NATIVE_SYSCALL])
            .expect("write native oracle words");
        let native = writer.publish().expect("publish native oracle");
        let mut expected = initial;
        legacy_brk_round_trip(native.entry(), &mut expected).unwrap_or_else(|error| {
            panic!("native vDSO x18 oracle failed for 0x{word:08x}: {error}")
        });
        let expected_memory = memory;

        memory.copy_from_slice(&pristine);
        let mut dsr_cache = TranslationCache::new(16 * 1024).expect("allocate DSR oracle");
        let emitted = emit_block(
            &mut dsr_cache,
            &BlockPlan {
                start: guest,
                end: GuestVa(guest.raw() + 8),
                generation: CodeGeneration::INITIAL,
                instructions: vec![PlannedInst { guest, action }],
                exit: PlannedExit::Syscall {
                    guest: GuestVa(guest.raw() + 4),
                    resume: GuestVa(guest.raw() + 8),
                },
            },
        )
        .expect("emit DSR vDSO x18 oracle");
        let mut observed = initial;
        let mut exit = NativeDsrExit::Syscall {
            resume: GuestVa(guest.raw() + 8),
        };
        enter_translated(emitted.entry(), &mut observed, &mut exit)
            .expect("execute DSR vDSO x18 oracle");

        assert_eq!(
            observed.x, expected.x,
            "GPR mismatch for vDSO word 0x{word:08x}"
        );
        assert_eq!(
            observed.pstate, expected.pstate,
            "NZCV mismatch for vDSO word 0x{word:08x}"
        );
        assert_eq!(
            memory, expected_memory,
            "memory mismatch for vDSO word 0x{word:08x}"
        );
    }
}

#[test]
fn dsr_signal_fault_reconstructs_copied_instruction_pc() {
    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate fault cache");
    let plan = BlockPlan {
        start: GuestVa(0x1c_000),
        end: GuestVa(0x1c_008),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: GuestVa(0x1c_000),
            action: InstAction::Copy(0xf940_0000), // ldr x0, [x0]
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x1c_004),
            resume: GuestVa(0x1c_008),
        },
    };
    let emitted = emit_block(&mut cache, &plan).expect("emit faulting block");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = 1;
    let mut exit = NativeDsrExit::Fault {
        guest_pc: GuestVa(0),
        signal: 0,
        code: 0,
        address: GuestVa(0),
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
        physical_x18: 0,
        gateway_phase: 0,
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("capture DSR fault");
    let NativeDsrExit::Fault {
        guest_pc,
        signal,
        address,
        ..
    } = exit
    else {
        panic!("expected fault exit, got {exit:?}");
    };
    assert!(signal == libc::SIGSEGV || signal == libc::SIGBUS);
    assert_eq!(address, GuestVa(1));
    assert_ne!(snapshot.esr, 0, "fault ESR must survive DSR signal exit");
    let offset = u32::try_from(guest_pc.raw() - emitted.entry().host().raw() as u64)
        .expect("fault cache offset");
    assert_eq!(
        emitted
            .map()
            .guest_for_cache(super::types::CacheOffset::published(offset)),
        Some(GuestVa(0x1c_000))
    );
}

#[test]
fn dsr_signal_fault_recovers_context_when_physical_x28_is_zero() {
    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );
    let guest = GuestVa(0x1c_100);
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate x28 recovery cache");
    let emitted = emit_block(
        &mut cache,
        &BlockPlan {
            start: guest,
            end: GuestVa(guest.raw() + 8),
            generation: CodeGeneration::INITIAL,
            // Deliberately bypass classification to model a corrupted
            // physical-x28 invariant immediately before a gateway exit.
            instructions: vec![PlannedInst {
                guest,
                action: InstAction::Copy(0xaa1f_03fc), // mov x28, xzr
            }],
            exit: PlannedExit::Syscall {
                guest: GuestVa(guest.raw() + 4),
                resume: GuestVa(guest.raw() + 8),
            },
        },
    )
    .expect("emit physical x18 corruption oracle");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let expected_virtual_x28 = snapshot.x[28];
    let mut exit = NativeDsrExit::Fault {
        guest_pc: GuestVa(0),
        signal: 0,
        code: 0,
        address: GuestVa(0),
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
        physical_x18: 0,
        gateway_phase: 0,
    };

    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("recover signal gateway context through the host-stack handoff");

    assert!(
        matches!(
            exit,
            NativeDsrExit::Fault {
                signal: libc::SIGSEGV,
                address: GuestVa(136),
                ..
            }
        ),
        "unexpected x28 recovery exit: {exit:?}"
    );
    assert_eq!(snapshot.x[28], expected_virtual_x28);
}

#[test]
fn dsr_concurrency_kick_exits_guarded_linked_loop_without_corrupting_guest_state() {
    use std::sync::atomic::AtomicU64;

    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );
    let guest = GuestVa(0x1c_200);
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate kick cache");
    let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
    let emitted = super::emit::emit_block_with_generation(
        &mut cache,
        &BlockPlan {
            start: guest,
            end: GuestVa(guest.raw() + 12),
            generation: CodeGeneration::INITIAL,
            instructions: vec![
                PlannedInst {
                    guest,
                    action: InstAction::Copy(0x9100_0400), // add x0, x0, #1
                },
                PlannedInst {
                    guest: GuestVa(guest.raw() + 4),
                    action: InstAction::Copy(0xc89f_fc20), // stlr x0, [x1]
                },
            ],
            exit: PlannedExit::Direct {
                guest: GuestVa(guest.raw() + 8),
                word: 0x1400_0000,
                exit: DirectExit {
                    kind: DirectKind::Branch,
                    target: guest,
                    resume: GuestVa(guest.raw() + 12),
                    condition: None,
                    register: None,
                    bit: None,
                },
            },
        },
        super::emit::GenerationGuard::new(&generation, CodeGeneration::INITIAL),
    )
    .expect("emit kick loop");
    let link = emitted.direct_links()[0];
    cache
        .patch_direct_branch(
            super::cache::LinkSite {
                source: emitted.entry(),
                slot: link.slot,
            },
            emitted.entry(),
        )
        .expect("link kick loop");
    let target = unsafe { libc::pthread_self() };
    let mut signal_set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    let mut old_set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    assert_eq!(unsafe { libc::sigemptyset(signal_set.as_mut_ptr()) }, 0);
    let mut signal_set = unsafe { signal_set.assume_init() };
    assert_eq!(
        unsafe { libc::sigaddset(&mut signal_set, libc::SIGPIPE) },
        0
    );
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &signal_set, old_set.as_mut_ptr()) },
        0
    );
    let old_set = unsafe { old_set.assume_init() };
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let sender_counter = std::sync::Arc::clone(&counter);
    let sender = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let requested_at = loop {
            let observed = sender_counter.load(std::sync::atomic::Ordering::Acquire);
            if observed != 0 {
                break observed;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "translated loop did not publish its instruction counter"
            );
            std::hint::spin_loop();
        };
        assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGPIPE) }, 0);
        requested_at
    });
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = 0;
    snapshot.x[1] = std::sync::Arc::as_ptr(&counter) as u64;
    snapshot.x[16] = 0x1616_1616_1616_1616;
    snapshot.x[17] = 0x1717_1717_1717_1717;
    snapshot.pstate = 0xa000_0000;
    let expected_x16 = snapshot.x[16];
    let expected_x17 = snapshot.x[17];
    let expected_pstate = snapshot.pstate;
    let mut exit = NativeDsrExit::Kick {
        resume: guest,
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
    };

    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("exit stale SIGPIPE through DSR gateway");
    let requested_at = sender.join().expect("join SIGPIPE sender");
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_set, std::ptr::null_mut()) },
        0
    );

    assert!(
        matches!(exit, NativeDsrExit::Kick { .. }),
        "unexpected stale SIGPIPE exit: {exit:?}"
    );
    let NativeDsrExit::Kick {
        resume,
        rewrite_scratch,
        rewrite_context_scratch,
        generation_pstate_scratch,
        indirect_x15_scratch,
        indirect_x30_scratch,
    } = exit
    else {
        unreachable!("matched kick above")
    };
    let offset = u32::try_from(resume.raw() - emitted.entry().host().raw() as u64)
        .expect("kick cache offset");
    if let Some(recovery) = emitted
        .recovery()
        .iter()
        .find(|entry| entry.cache == super::types::CacheOffset::published(offset))
        .map(|entry| entry.action)
    {
        super::recover_rewrite_state(
            &mut snapshot,
            recovery,
            rewrite_scratch,
            rewrite_context_scratch,
            generation_pstate_scratch,
            indirect_x15_scratch,
            indirect_x30_scratch,
        )
        .expect("recover interrupted generation guard");
    }
    assert_eq!(snapshot.x[16], expected_x16);
    assert_eq!(snapshot.x[17], expected_x17);
    assert_eq!(snapshot.pstate, expected_pstate);
    let instruction_delta = snapshot.x[0].saturating_sub(requested_at);
    let instructions_per_iteration = u64::from(link.slot.get() / 4 + 1);
    let observed_instruction_bound = instruction_delta
        .saturating_add(1)
        .saturating_mul(instructions_per_iteration);
    eprintln!(
        "DSR kick exited within {observed_instruction_bound} translated instruction(s) \
         after the request ({instruction_delta} complete loop iterations)"
    );
    assert!(
        observed_instruction_bound <= 100_000,
        "kick required more than 100000 translated instructions from request to exit: \
         observed upper bound {observed_instruction_bound}"
    );
}

#[test]
fn dsr_pending_kick_during_gateway_entry_keeps_guest_pc() {
    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );
    let guest = GuestVa(0x1c_300);
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate entry-kick cache");
    let emitted = emit_block(
        &mut cache,
        &BlockPlan {
            start: guest,
            end: GuestVa(guest.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Syscall {
                guest,
                resume: GuestVa(guest.raw() + 4),
            },
        },
    )
    .expect("emit entry-kick block");
    let state = super::super::NativeKickState::new().expect("create entry-kick state");
    state.bind_current().expect("bind entry-kick state");

    let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut kick);
        libc::sigaddset(&mut kick, libc::SIGPIPE);
    }
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &kick, &mut original) },
        0
    );
    assert!(state.request());
    assert_eq!(
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGPIPE) },
        0
    );

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.pc = guest.raw();
    let mut exit = NativeDsrExit::Syscall { resume: guest };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("exit pending kick at DSR entry");

    state.unbind_current();
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) },
        0
    );
    assert!(
        matches!(exit, NativeDsrExit::KickAtEntry { resume } if resume == guest),
        "entry kick must preserve the guest resume PC, got {exit:?}"
    );
}

#[test]
fn dsr_phase_zero_host_kick_keeps_original_guest_snapshot() {
    unsafe extern "C" {
        fn carrick_native_dsr_test_phase_zero_host_kick_once();
    }

    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );
    let guest = GuestVa(0x1c_380);
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate host-kick cache");
    let emitted = emit_block(
        &mut cache,
        &BlockPlan {
            start: guest,
            end: GuestVa(guest.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Syscall {
                guest,
                resume: GuestVa(guest.raw() + 4),
            },
        },
    )
    .expect("emit host-kick block");
    let indirect = IndirectTargetCache::new();
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.pc = guest.raw();
    let expected = snapshot;
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest.raw() + 4),
    };

    unsafe { carrick_native_dsr_test_phase_zero_host_kick_once() };
    super::gateway::enter_translated_with_cache_range(
        emitted.entry(),
        &mut snapshot,
        &mut exit,
        &indirect,
        emitted.entry().host().raw(),
        emitted.entry().host().raw() + emitted.len(),
    )
    .expect("classify phase-zero host kick");

    assert_eq!(
        exit,
        NativeDsrExit::KickAtEntry { resume: guest },
        "host kick must resume the original guest PC"
    );
    assert_eq!(snapshot.x, expected.x);
    assert_eq!(snapshot.sp, expected.sp);
    assert_eq!(snapshot.pc, expected.pc);
}

#[test]
fn dsr_signal_fault_recovers_scratch_in_expanded_x18_load() {
    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate x18 fault cache");
    let guest_pc = GuestVa(0x1d_000);
    let plan = BlockPlan {
        start: guest_pc,
        end: GuestVa(guest_pc.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: guest_pc,
            action: super::decode::classify(0xf940_0012, guest_pc).expect("classify ldr x18, [x0]"),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(guest_pc.raw() + 4),
            resume: GuestVa(guest_pc.raw() + 8),
        },
    };
    let emitted = emit_block(&mut cache, &plan).expect("emit expanded x18 load");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = 1;
    let original_x18 = snapshot.x[18];
    let original = snapshot;
    let mut exit = NativeDsrExit::Fault {
        guest_pc: GuestVa(0),
        signal: 0,
        code: 0,
        address: GuestVa(0),
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
        physical_x18: 0,
        gateway_phase: 0,
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("capture expanded x18 fault");
    let NativeDsrExit::Fault {
        guest_pc: cache_pc,
        rewrite_scratch,
        rewrite_context_scratch,
        ..
    } = exit
    else {
        panic!("expected expanded fault exit, got {exit:?}");
    };
    assert!(
        cache_pc.raw() >= emitted.entry().host().raw() as u64,
        "expanded fault reported non-cache PC 0x{:x} before entry 0x{:x}",
        cache_pc.raw(),
        emitted.entry().host().raw()
    );
    let offset = super::types::CacheOffset::published(
        u32::try_from(cache_pc.raw() - emitted.entry().host().raw() as u64)
            .expect("expanded fault offset"),
    );
    let recovery = emitted
        .recovery()
        .iter()
        .find(|entry| entry.cache == offset)
        .expect("expanded instruction recovery")
        .action;
    super::recover_rewrite_state(
        &mut snapshot,
        recovery,
        rewrite_scratch,
        rewrite_context_scratch,
        original.pstate,
        original.x[15],
        original.x[30],
    )
    .expect("recover expanded x18 scratch");
    assert_eq!(snapshot.x[18], original_x18);
    for index in 0..31 {
        if index != 0 {
            assert_eq!(snapshot.x[index], original.x[index], "x{index}");
        }
    }
}

#[test]
fn dsr_signal_fault_preserves_destination_in_expanded_literal_load() {
    assert_eq!(
        unsafe { super::super::carrick_native_install_trap_handler() },
        0
    );
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate literal fault cache");
    let guest_pc = GuestVa(0x1e_000);
    let plan = BlockPlan {
        start: guest_pc,
        end: GuestVa(guest_pc.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: guest_pc,
            action: InstAction::PcRelative(PcRelativeInst {
                kind: PcRelativeKind::LiteralLoad,
                target: GuestVa(1),
                destination: Some(bad64::Reg::X0),
                word: 0x5800_0000,
            }),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(guest_pc.raw() + 4),
            resume: GuestVa(guest_pc.raw() + 8),
        },
    };
    let emitted = emit_block(&mut cache, &plan).expect("emit expanded literal fault");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let original = snapshot;
    let mut exit = NativeDsrExit::Fault {
        guest_pc: GuestVa(0),
        signal: 0,
        code: 0,
        address: GuestVa(0),
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
        physical_x18: 0,
        gateway_phase: 0,
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("capture expanded literal fault");
    let NativeDsrExit::Fault {
        guest_pc: cache_pc,
        rewrite_scratch,
        rewrite_context_scratch,
        ..
    } = exit
    else {
        panic!("expected literal fault exit, got {exit:?}");
    };
    let offset = super::types::CacheOffset::published(
        u32::try_from(cache_pc.raw() - emitted.entry().host().raw() as u64)
            .expect("literal fault offset"),
    );
    let recovery = emitted
        .recovery()
        .iter()
        .find(|entry| entry.cache == offset)
        .expect("literal instruction recovery")
        .action;
    super::recover_rewrite_state(
        &mut snapshot,
        recovery,
        rewrite_scratch,
        rewrite_context_scratch,
        original.pstate,
        original.x[15],
        original.x[30],
    )
    .expect("recover literal scratch");
    assert_eq!(snapshot.x, original.x);
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
