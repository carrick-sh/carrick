// This whole module is the `#[cfg(test)]` live-execution oracle (see the
// `mod oracle;` gate in `dsr/mod.rs`): fixture/harness code that legitimately
// fails fast on a broken test setup, same rationale as the live VMM
// integration tests (e.g. `tests/live_bhyve_x86.rs`).
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use carrick_dsr_aarch64::direct_binding::DirectBindingExitMetadata;
use carrick_guest_mem::protections::MemoryProtections;
use carrick_guest_mem::{GuestVa, HostVa};

use super::super::NativeUcontextSnapshot;
use super::block::{BlockPlan, PlannedExit, PlannedInst};
use super::cache::TranslationCache;
use super::emit::{
    EmittedBlock, GenerationGuard, emit_block, emit_block_direct, emit_block_with_generation_direct,
};
use super::gateway::{IndirectTargetCache, enter_translated, enter_translated_with_cache};
use super::types::{
    CodeGeneration, CounterDestination, CounterRead, DirectExit, DirectKind, DsrError,
    IndirectExit, IndirectKind, InstAction, MemoryAccess, MemoryBase, MemoryClass,
    MemoryVirtualization, MemoryWriteback, NativeDsrExit, PcRelativeInst, PcRelativeKind,
    SensitiveExit, SensitiveKind,
};

static SIGNAL_ORACLE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn install_signal_handlers_for_oracle() -> std::sync::MutexGuard<'static, ()> {
    let guard = SIGNAL_ORACLE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        unsafe { super::super::carrick_native_install_dsr_signal_handlers() },
        0
    );
    guard
}

struct BiasedTranslatorFixture {
    memory: super::super::NativeMappedMemory,
    translator: super::ThreadTranslator,
    guest_code: GuestVa,
    guest_data: GuestVa,
    data_host: HostVa,
    host_bias: crate::native_darwin::address::NativeHostBias,
    _mapping: crate::native_darwin::address::OwnedHostMapping,
}

fn biased_translator_fixture(words: &[u32], guest_code: GuestVa) -> BiasedTranslatorFixture {
    const BIAS: u64 = 0x80_0000_0000;
    const PAGE_SIZE: u64 = 16 * 1024;
    const MAPPING_LEN: usize = 2 * PAGE_SIZE as usize;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, PAGE_SIZE)
        .expect("construct live biased host bias");
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + guest_code.raw()) as usize),
        MAPPING_LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map live biased fixture");
    let code = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    unsafe {
        std::ptr::copy_nonoverlapping(
            code.as_ptr(),
            mapping.range().start.raw() as *mut u8,
            code.len(),
        );
    }
    let guest_data = GuestVa(guest_code.raw() + PAGE_SIZE);
    let data_host = HostVa(mapping.range().start.raw() + PAGE_SIZE as usize);
    let process =
        Arc::new(super::test_process_translator(64 * 1024).expect("create live translator"));
    let memory = super::super::NativeMappedMemory {
        address_mode: crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
        owned_host_ranges: Arc::new(vec![mapping.range()]),
        regions: vec![
            super::super::NativeMappedRegion {
                start: guest_code.raw(),
                end: guest_code.raw() + PAGE_SIZE,
                host_protects: false,
                shared_futex: false,
                guest_writable: false,
                default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                shared_key_base: 0,
                shared_key_offset: 0,
            },
            super::super::NativeMappedRegion {
                start: guest_data.raw(),
                end: guest_data.raw() + PAGE_SIZE,
                host_protects: false,
                shared_futex: false,
                guest_writable: true,
                default_prot: crate::linux_abi::LINUX_PROT_READ
                    | crate::linux_abi::LINUX_PROT_WRITE,
                shared_key_base: 0,
                shared_key_offset: 0,
            },
        ],
        protections: MemoryProtections::default(),
        native_page_protections: BTreeMap::new(),
        native_write_exec_writable_pages: BTreeSet::new(),
        linux4k_page_protections: BTreeMap::new(),
        exclusive_sequences: parking_lot::Mutex::new(BTreeMap::new()),
        host_access_lifts: parking_lot::Mutex::new(std::collections::HashMap::new()),
        host_page_size: PAGE_SIZE,
        linux_page_size: PAGE_SIZE,
        dsr_generations: super::cache::PageGenerationTable::new(PAGE_SIZE)
            .expect("create live generation table"),
        dsr_translator: Some(Arc::clone(&process)),
    };
    BiasedTranslatorFixture {
        memory,
        translator: super::ThreadTranslator::for_process(process, 0),
        guest_code,
        guest_data,
        data_host,
        host_bias,
        _mapping: mapping,
    }
}

#[test]
fn biased_live_signal_gateway_recovers_pre_and_post_operation_faults() {
    let _signal_oracle = install_signal_handlers_for_oracle();

    {
        let mut fixture =
            biased_translator_fixture(&[0xf940_0020, 0xd400_0001], GuestVa(0x20_0000_0000));
        let invalid_guest = GuestVa(0x10_0000);
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.pc = fixture.guest_code.raw();
        snapshot.x[1] = invalid_guest.raw();
        let original = snapshot;
        let prepared = fixture
            .translator
            .prepare_entry::<false>(&fixture.memory, &snapshot)
            .expect("prepare live biased pre-operation fault");
        let prepared_exit = fixture
            .translator
            .enter_prepared::<false>(prepared, &mut snapshot)
            .expect("enter live biased pre-operation fault");
        let exit = fixture
            .translator
            .finish_exit(&fixture.memory, &mut snapshot, prepared, prepared_exit)
            .expect("finish live biased pre-operation fault");
        assert!(matches!(
            exit,
            super::ThreadExit::Fault {
                kind: super::ThreadFault::Host { signal, .. },
                address: super::ThreadFaultAddress::Host(address),
            } if matches!(signal, libc::SIGSEGV | libc::SIGBUS)
                && address == HostVa((fixture.host_bias.get() + invalid_guest.raw()) as usize)
        ));
        assert_eq!(snapshot.pc, fixture.guest_code.raw());
        assert_eq!(snapshot.x[1], original.x[1]);
        assert_eq!(snapshot.x[16], original.x[16]);
        assert_eq!(snapshot.x[17], original.x[17]);
    }

    {
        let mut fixture =
            biased_translator_fixture(&[0xf840_8420, 0xd400_0001], GuestVa(0x20_0001_0000));
        let loaded = 0x1122_3344_5566_7788_u64;
        unsafe { *(fixture.data_host.raw() as *mut u64) = loaded };
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.pc = fixture.guest_code.raw();
        snapshot.x[1] = fixture.guest_data.raw();
        snapshot.x[27] = 1;
        let original_x16 = snapshot.x[16];
        let original_x17 = snapshot.x[17];
        let prepared = fixture
            .translator
            .prepare_entry::<false>(&fixture.memory, &snapshot)
            .expect("prepare live biased post-operation fault");
        fixture
            .translator
            .patch_first_completed_recovery_for_test(
                fixture.guest_code,
                0xf940_0369, // ldr x9, [x27] with x27=1
            )
            .expect("patch completed cleanup instruction");
        let prepared_exit = fixture
            .translator
            .enter_prepared::<false>(prepared, &mut snapshot)
            .expect("enter live biased post-operation fault");
        let exit = fixture
            .translator
            .finish_exit(&fixture.memory, &mut snapshot, prepared, prepared_exit)
            .expect("finish live biased post-operation fault");
        assert!(matches!(
            exit,
            super::ThreadExit::Fault {
                kind: super::ThreadFault::Host { signal, .. },
                address: super::ThreadFaultAddress::Host(HostVa(1)),
            } if matches!(signal, libc::SIGSEGV | libc::SIGBUS)
        ));
        assert_eq!(snapshot.pc, fixture.guest_code.raw() + 4);
        assert_eq!(snapshot.x[0], loaded);
        assert_eq!(snapshot.x[1], fixture.guest_data.raw() + 8);
        assert_eq!(snapshot.x[16], original_x16);
        assert_eq!(snapshot.x[17], original_x17);
    }
}

#[test]
fn biased_wrapped_negative_literal_fault_reports_guest_address() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    const MIN_LITERAL_DISPLACEMENT: u64 = 1024 * 1024;
    let guest_code = GuestVa(0x4000);
    let wrapped_target = GuestVa(guest_code.raw().wrapping_sub(MIN_LITERAL_DISPLACEMENT));
    let mut fixture = biased_translator_fixture(
        &[
            0x5880_0000, // ldr x0, #-1 MiB
            0xd400_0001, // svc #0
        ],
        guest_code,
    );
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.pc = guest_code.raw();
    let original_x0 = snapshot.x[0];
    let prepared = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare wrapped negative biased literal");
    let prepared_exit = fixture
        .translator
        .enter_prepared::<false>(prepared, &mut snapshot)
        .expect("enter wrapped negative biased literal");
    let exit = fixture
        .translator
        .finish_exit(&fixture.memory, &mut snapshot, prepared, prepared_exit)
        .expect("finish wrapped negative biased literal");
    assert!(matches!(
        exit,
        super::ThreadExit::Fault {
            kind: super::ThreadFault::Host { signal, .. },
            address: super::ThreadFaultAddress::Guest(address),
        } if matches!(signal, libc::SIGSEGV | libc::SIGBUS) && address == wrapped_target
    ));
    assert_eq!(snapshot.pc, guest_code.raw());
    assert_eq!(snapshot.fault_address, wrapped_target.raw());
    assert_eq!(snapshot.x[0], original_x0);
}

#[derive(Clone, Copy, Debug)]
enum BiasedRecoveryMatrixShape {
    ScalarPre,
    ScalarPost,
    Literal,
    VirtualX18,
    VirtualX28,
    X16X17Collision,
}

impl BiasedRecoveryMatrixShape {
    fn words(self) -> Vec<u32> {
        match self {
            Self::ScalarPre => vec![0xf81f_8c20, 0xd400_0001],
            Self::ScalarPost => vec![0xf840_8420, 0xd400_0001],
            Self::Literal => vec![0x5800_0040, 0xd400_0001, 0x5566_7788, 0x1122_3344],
            Self::VirtualX18 => vec![0xf940_0240, 0xd400_0001],
            Self::VirtualX28 => vec![0xf940_0380, 0xd400_0001],
            Self::X16X17Collision => vec![0xf940_0211, 0xd400_0001],
        }
    }

    fn configure(self, fixture: &BiasedTranslatorFixture, snapshot: &mut NativeUcontextSnapshot) {
        const VALUE: u64 = 0x1122_3344_5566_7788;
        const INITIAL: u64 = 0xaabb_ccdd_eeff_0011;
        unsafe { *(fixture.data_host.raw() as *mut u64) = INITIAL };
        match self {
            Self::ScalarPre => {
                snapshot.x[0] = VALUE;
                snapshot.x[1] = fixture.guest_data.raw() + 8;
            }
            Self::ScalarPost => {
                unsafe { *(fixture.data_host.raw() as *mut u64) = VALUE };
                snapshot.x[1] = fixture.guest_data.raw();
            }
            Self::Literal => {}
            Self::VirtualX18 => {
                unsafe { *(fixture.data_host.raw() as *mut u64) = VALUE };
                snapshot.x[18] = fixture.guest_data.raw();
            }
            Self::VirtualX28 => {
                unsafe { *(fixture.data_host.raw() as *mut u64) = VALUE };
                snapshot.x[28] = fixture.guest_data.raw();
            }
            Self::X16X17Collision => {
                unsafe { *(fixture.data_host.raw() as *mut u64) = VALUE };
                snapshot.x[16] = fixture.guest_data.raw();
            }
        }
        snapshot.x[27] = 1;
    }
}

#[test]
fn biased_recovery_matrix_routes_every_offset_through_finish_exit() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let shapes = [
        BiasedRecoveryMatrixShape::ScalarPre,
        BiasedRecoveryMatrixShape::ScalarPost,
        BiasedRecoveryMatrixShape::Literal,
        BiasedRecoveryMatrixShape::VirtualX18,
        BiasedRecoveryMatrixShape::VirtualX28,
        BiasedRecoveryMatrixShape::X16X17Collision,
    ];
    for (shape_index, shape) in shapes.into_iter().enumerate() {
        let guest_code = GuestVa(0x20_0010_0000 + shape_index as u64 * 0x10_0000);
        let expected = {
            let mut fixture = biased_translator_fixture(&shape.words(), guest_code);
            let mut stack = vec![0_u8; 16 * 1024];
            let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
            snapshot.pc = guest_code.raw();
            shape.configure(&fixture, &mut snapshot);
            let original = snapshot;
            let prepared = fixture
                .translator
                .prepare_entry::<false>(&fixture.memory, &snapshot)
                .expect("prepare matrix expected execution");
            let exit = fixture
                .translator
                .enter_prepared::<false>(prepared, &mut snapshot)
                .expect("enter matrix expected execution");
            assert!(matches!(
                fixture
                    .translator
                    .finish_exit(&fixture.memory, &mut snapshot, prepared, exit)
                    .expect("finish matrix expected execution"),
                super::ThreadExit::Syscall { .. }
            ));
            (original, snapshot)
        };

        let recovery_count = {
            let mut fixture = biased_translator_fixture(&shape.words(), guest_code);
            let mut stack = vec![0_u8; 16 * 1024];
            let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
            snapshot.pc = guest_code.raw();
            shape.configure(&fixture, &mut snapshot);
            fixture
                .translator
                .prepare_entry::<false>(&fixture.memory, &snapshot)
                .expect("prepare matrix recovery count");
            fixture
                .translator
                .recovery_points_for_test(guest_code)
                .len()
        };
        assert!(recovery_count > 0, "shape={shape:?}");

        let mut skipped_invalid_publication = false;
        let mut skipped_invalid_tag = false;
        for point_index in 0..recovery_count {
            let mut fixture = biased_translator_fixture(&shape.words(), guest_code);
            let mut stack = vec![0_u8; 16 * 1024];
            let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
            snapshot.pc = guest_code.raw();
            shape.configure(&fixture, &mut snapshot);
            let original_sp = snapshot.sp;
            let prepared = fixture
                .translator
                .prepare_entry::<false>(&fixture.memory, &snapshot)
                .expect("prepare matrix recovery point");
            let (cache_pc, action) = fixture
                .translator
                .recovery_points_for_test(guest_code)
                .get(point_index)
                .copied()
                .expect("matrix recovery point");
            let original_word =
                unsafe { std::ptr::read_unaligned(cache_pc.host().raw() as *const u32) };
            fixture
                .translator
                .patch_recovery_word_for_test(cache_pc, 0xf940_0369)
                .expect("patch matrix recovery point");
            let fault = fixture
                .translator
                .enter_prepared::<false>(prepared, &mut snapshot)
                .expect("enter matrix recovery fault");
            let fault_exit = fault.exit;
            let fault_snapshot = snapshot;
            let super::types::NativeDsrExit::Fault {
                guest_pc: resume,
                rewrite_scratch,
                rewrite_context_scratch,
                generation_pstate_scratch,
                indirect_x15_scratch,
                indirect_x30_scratch,
                ..
            } = fault_exit
            else {
                assert!(
                    matches!(fault_exit, super::types::NativeDsrExit::Syscall { .. }),
                    "shape={shape:?} point={point_index} expected fault or an audited skipped invalid-path instruction, got {fault_exit:?}"
                );
                let publication_store = 0xf900_0000 | ((1200 / 8) << 10) | (28 << 5);
                if original_word & !0x1f == publication_store {
                    skipped_invalid_publication = true;
                } else if original_word & !0x3ff == 0xb251_0000 {
                    skipped_invalid_tag = true;
                } else {
                    panic!(
                        "shape={shape:?} point={point_index} unexpectedly skipped word 0x{original_word:08x}"
                    );
                }
                continue;
            };
            let kick = super::PreparedExit {
                exit: super::types::NativeDsrExit::Kick {
                    resume,
                    rewrite_scratch,
                    rewrite_context_scratch,
                    generation_pstate_scratch,
                    indirect_x15_scratch,
                    indirect_x30_scratch,
                },
            };
            let completed = action.instruction_complete();
            let expected_snapshot = if completed { expected.1 } else { expected.0 };

            let mut recovered_fault = fault_snapshot;
            let fault_result = fixture
                .translator
                .finish_exit(
                    &fixture.memory,
                    &mut recovered_fault,
                    prepared,
                    super::PreparedExit { exit: fault_exit },
                )
                .expect("finish matrix fault");
            assert!(matches!(
                fault_result,
                super::ThreadExit::Fault {
                    address: super::ThreadFaultAddress::Host(HostVa(1)),
                    ..
                }
            ));

            let mut recovered_kick = fault_snapshot;
            assert!(matches!(
                fixture
                    .translator
                    .finish_exit(&fixture.memory, &mut recovered_kick, prepared, kick)
                    .expect("finish matrix kick"),
                super::ThreadExit::Kick
            ));
            for (kind, recovered) in [("fault", recovered_fault), ("kick", recovered_kick)] {
                assert_eq!(
                    recovered.pc,
                    guest_code.raw() + if completed { 4 } else { 0 },
                    "shape={shape:?} point={point_index} kind={kind} PC"
                );
                assert_eq!(
                    recovered.x, expected_snapshot.x,
                    "shape={shape:?} point={point_index} kind={kind} registers"
                );
                assert_eq!(
                    recovered.sp, original_sp,
                    "shape={shape:?} point={point_index} kind={kind} SP"
                );
            }
            let observed_data = unsafe { *(fixture.data_host.raw() as *const u64) };
            if matches!(shape, BiasedRecoveryMatrixShape::ScalarPre) {
                assert_eq!(
                    observed_data,
                    if completed {
                        0x1122_3344_5566_7788
                    } else {
                        0xaabb_ccdd_eeff_0011
                    },
                    "shape={shape:?} point={point_index} store completion"
                );
            }
        }
        let has_checked_nonliteral_address = !matches!(shape, BiasedRecoveryMatrixShape::Literal);
        assert_eq!(
            skipped_invalid_publication, has_checked_nonliteral_address,
            "shape={shape:?} invalid-address publication path"
        );
        assert_eq!(
            skipped_invalid_tag, has_checked_nonliteral_address,
            "shape={shape:?} invalid-host tagging path"
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn biased_memory_families_access_guest_data() {
    const BIAS: u64 = 0x80_0000_0000;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, 16 * 1024)
        .expect("construct host bias");
    let mode = super::emit::EmitAddressMode::Biased { host_bias };
    const GUEST: u64 = 0x4_0000_0000;
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + GUEST) as usize),
        16 * 1024,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map biased oracle data");
    let words =
        unsafe { std::slice::from_raw_parts_mut(mapping.range().start.raw() as *mut u64, 2) };
    words.copy_from_slice(&[0x1122_3344_5566_7788_u64, 0x99aa_bbcc_ddee_ff00]);
    let guest = GUEST;
    let fixtures = [
        (0xf940_0020, MemoryClass::Scalar),
        (0xa940_0440, MemoryClass::Pair),
        (0x3dc0_0020, MemoryClass::Simd),
        (0xf8e0_0041, MemoryClass::Atomic),
    ];
    for (word, class) in fixtures {
        let base_register = if class == MemoryClass::Pair || class == MemoryClass::Atomic {
            bad64::Reg::X2
        } else {
            bad64::Reg::X1
        };
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4008),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: InstAction::Memory(MemoryAccess {
                    word,
                    op: bad64::decode(word, 0x4000).expect("decode fixture").op(),
                    base: MemoryBase::Register(base_register),
                    effective_address: super::types::MemoryEffectiveAddress::Base,
                    writeback: MemoryWriteback::None,
                    class,
                    virtualization: MemoryVirtualization::None,
                }),
            }],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008),
            },
        };
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate biased cache");
        let emitted = emit_block(&mut cache, &plan, mode).expect("emit biased fixture");
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.x[1] = guest;
        snapshot.x[2] = guest;
        snapshot.x[0] = 1;
        snapshot.pstate = 0x6000_0000;
        let expected_x16 = snapshot.x[16];
        let expected_x17 = snapshot.x[17];
        let expected_pstate = snapshot.pstate;
        let mut exit = NativeDsrExit::Syscall {
            resume: GuestVa(0x4008),
        };
        super::gateway::enter_translated_in_mode(
            emitted.entry(),
            &mut snapshot,
            &mut exit,
            crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
        )
        .expect("execute biased fixture");
        assert_eq!(snapshot.x[16], expected_x16, "word=0x{word:08x}");
        assert_eq!(snapshot.x[17], expected_x17, "word=0x{word:08x}");
        assert_eq!(snapshot.pstate, expected_pstate, "word=0x{word:08x}");
        match class {
            MemoryClass::Pair => {
                assert_eq!(snapshot.x[0], words[0]);
                assert_eq!(snapshot.x[1], words[1]);
            }
            MemoryClass::Simd => assert_eq!(snapshot.v[0], unsafe {
                std::ptr::read_unaligned(words.as_ptr().cast::<[u8; 16]>())
            }),
            MemoryClass::Atomic => {
                assert_eq!(snapshot.x[1], 0x1122_3344_5566_7788);
                assert_eq!(words[0], 0x1122_3344_5566_7789);
                words[0] = 0x1122_3344_5566_7788;
            }
            _ => assert_eq!(snapshot.x[0], words[0]),
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn biased_memory_preserves_nzcv_for_the_following_conditional_instruction() {
    const BIAS: u64 = 0x80_0000_0000;
    const GUEST: u64 = 0xb_0000_0000;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, 16 * 1024)
        .expect("construct host bias");
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + GUEST) as usize),
        16 * 1024,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map NZCV oracle data");
    unsafe { *(mapping.range().start.raw() as *mut u64) = 0x1122_3344_5566_7788 };
    let words = [
        0xf940_0020, // ldr x0, [x1]
        0x9a84_0062, // csel x2, x3, x4, eq
    ];
    let plan = BlockPlan {
        start: GuestVa(0x5000),
        end: GuestVa(0x500c),
        generation: CodeGeneration::INITIAL,
        instructions: words
            .into_iter()
            .enumerate()
            .map(|(index, word)| PlannedInst {
                guest: GuestVa(0x5000 + index as u64 * 4),
                action: super::decode::classify(word, GuestVa(0x5000 + index as u64 * 4))
                    .expect("classify NZCV oracle word"),
            })
            .collect(),
        exit: PlannedExit::Syscall {
            guest: GuestVa(0x5008),
            resume: GuestVa(0x500c),
        },
    };
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate NZCV oracle cache");
    let emitted = emit_block(
        &mut cache,
        &plan,
        super::emit::EmitAddressMode::Biased { host_bias },
    )
    .expect("emit NZCV oracle");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[1] = GUEST;
    snapshot.x[3] = 0x1111;
    snapshot.x[4] = 0x2222;
    snapshot.pstate = 0x4000_0000; // Z=1: EQ must select x3.
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x500c),
    };
    super::gateway::enter_translated_in_mode(
        emitted.entry(),
        &mut snapshot,
        &mut exit,
        crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
    )
    .expect("execute NZCV oracle");
    assert_eq!(snapshot.x[0], 0x1122_3344_5566_7788);
    assert_eq!(snapshot.x[2], 0x1111, "CSEL observed clobbered guest NZCV");
    assert_eq!(snapshot.pstate, 0x4000_0000);
}

#[cfg(target_arch = "aarch64")]
fn run_biased_single_memory(
    word: u32,
    guest_pc: GuestVa,
    host_bias: crate::native_darwin::address::NativeHostBias,
    snapshot: &mut NativeUcontextSnapshot,
) {
    let plan = BlockPlan {
        start: guest_pc,
        end: GuestVa(guest_pc.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: guest_pc,
            action: super::decode::classify(word, guest_pc).expect("classify biased memory"),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(guest_pc.raw() + 4),
            resume: GuestVa(guest_pc.raw() + 8),
        },
    };
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate single-memory cache");
    let emitted = emit_block(
        &mut cache,
        &plan,
        super::emit::EmitAddressMode::Biased { host_bias },
    )
    .expect("emit single biased memory");
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest_pc.raw() + 8),
    };
    super::gateway::enter_translated_in_mode(
        emitted.entry(),
        snapshot,
        &mut exit,
        crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
    )
    .expect("execute single biased memory");
}

#[cfg(target_arch = "aarch64")]
#[test]
fn biased_pre_post_writeback_stays_in_guest_coordinates() {
    const BIAS: u64 = 0x80_0000_0000;
    const GUEST: u64 = 0x7_0000_0000;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, 16 * 1024)
        .expect("construct host bias");
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + GUEST) as usize),
        16 * 1024,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map writeback data");
    let words =
        unsafe { std::slice::from_raw_parts_mut(mapping.range().start.raw() as *mut u64, 2) };
    words.copy_from_slice(&[11, 22]);
    let mut stack = vec![0_u8; 16 * 1024];

    let mut pre = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    pre.x[0] = 77;
    pre.x[1] = GUEST + 8;
    run_biased_single_memory(0xf81f_8c20, GuestVa(0xa000), host_bias, &mut pre);
    assert_eq!(pre.x[1], GUEST);
    assert_eq!(words[0], 77);

    let mut post = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    post.x[1] = GUEST;
    run_biased_single_memory(0xf840_8420, GuestVa(0xb000), host_bias, &mut post);
    assert_eq!(post.x[0], 77);
    assert_eq!(post.x[1], GUEST + 8);

    let mut virtual_overlap = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    virtual_overlap.x[18] = GUEST;
    run_biased_single_memory(
        0xf800_8652, // str x18, [x18], #8 (constrained overlap fixture)
        GuestVa(0xc000),
        host_bias,
        &mut virtual_overlap,
    );
    assert_eq!(words[0], GUEST);
    assert_eq!(virtual_overlap.x[18], GUEST + 8);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn biased_simd_pair_preindex_preserves_register_files_and_writeback() {
    const BIAS: u64 = 0x80_0000_0000;
    const GUEST: u64 = 0x7_0001_0000;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, 16 * 1024)
        .expect("construct host bias");
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + GUEST) as usize),
        16 * 1024,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map SIMD pair data");
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(mapping.range().start.raw() as *mut u8, 16 * 1024)
    };
    for (index, byte) in bytes[32..64].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(3).wrapping_add(1);
    }

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[1] = GUEST;
    run_biased_single_memory(
        0xadc1_0821, // ldp q1, q2, [x1, #32]!
        GuestVa(0xc000),
        host_bias,
        &mut snapshot,
    );

    assert_eq!(snapshot.x[1], GUEST + 32);
    assert_eq!(snapshot.v[1], bytes[32..48]);
    assert_eq!(snapshot.v[2], bytes[48..64]);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn biased_simd_structure_post_index_matches_memequal_load() {
    const BIAS: u64 = 0x80_0000_0000;
    const GUEST: u64 = 0xa_0001_0000;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, 16 * 1024)
        .expect("construct host bias");
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + GUEST) as usize),
        16 * 1024,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map memequal data");
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(mapping.range().start.raw() as *mut u8, 16 * 1024)
    };
    for (index, byte) in bytes[..64].iter_mut().enumerate() {
        *byte = index as u8;
    }

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = GUEST;
    run_biased_single_memory(0x4cdf_2c00, GuestVa(0xd000), host_bias, &mut snapshot);

    assert_eq!(snapshot.x[0], GUEST + 64);
    for (index, vector) in snapshot.v[..4].iter().enumerate() {
        assert_eq!(*vector, bytes[index * 16..(index + 1) * 16]);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn biased_memequal_vector_sequence_compares_equal_blocks() {
    const BIAS: u64 = 0x80_0000_0000;
    const GUEST: u64 = 0xa_0002_0000;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, 16 * 1024)
        .expect("construct host bias");
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + GUEST) as usize),
        16 * 1024,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map paired memequal data");
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(mapping.range().start.raw() as *mut u8, 16 * 1024)
    };
    for (index, byte) in bytes[..64].iter_mut().enumerate() {
        *byte = index as u8;
    }
    let (first, second) = bytes[..128].split_at_mut(64);
    second.copy_from_slice(first);

    let words = [
        0x4cdf_2c00,
        0x4cdf_2c24,
        0x6ee0_8c88,
        0x6ee1_8ca9,
        0x6ee2_8cca,
        0x6ee3_8ceb,
        0x4e28_1d28,
        0x4e28_1d48,
        0x4e28_1d68,
        0x4e08_3d04,
        0x4e18_3d05,
    ];
    let start = GuestVa(0xd100);
    let instructions = words
        .into_iter()
        .enumerate()
        .map(|(index, word)| {
            let guest = GuestVa(start.raw() + index as u64 * 4);
            PlannedInst {
                guest,
                action: super::decode::classify(word, guest).expect("classify memequal word"),
            }
        })
        .collect();
    let syscall = GuestVa(start.raw() + words.len() as u64 * 4);
    let plan = BlockPlan {
        start,
        end: GuestVa(syscall.raw() + 4),
        generation: CodeGeneration::INITIAL,
        instructions,
        exit: PlannedExit::Syscall {
            guest: syscall,
            resume: GuestVa(syscall.raw() + 4),
        },
    };
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate memequal cache");
    let emitted = emit_block(
        &mut cache,
        &plan,
        super::emit::EmitAddressMode::Biased { host_bias },
    )
    .expect("emit memequal vector sequence");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = GUEST;
    snapshot.x[1] = GUEST + 64;
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(syscall.raw() + 4),
    };
    super::gateway::enter_translated_in_mode(
        emitted.entry(),
        &mut snapshot,
        &mut exit,
        crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
    )
    .expect("execute memequal vector sequence");

    assert_eq!(snapshot.x[0], GUEST + 64);
    assert_eq!(snapshot.x[1], GUEST + 128);
    assert_eq!(snapshot.x[4], u64::MAX);
    assert_eq!(snapshot.x[5], u64::MAX);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn biased_literal_load_commits_virtual_x18() {
    const BIAS: u64 = 0x80_0000_0000;
    const GUEST: u64 = 0x8_0000_0000;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, 16 * 1024)
        .expect("construct host bias");
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + GUEST) as usize),
        16 * 1024,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map literal data");
    unsafe { *(mapping.range().start.raw() as *mut u64) = 0xfeed_face_cafe_beef };
    let word = 0x5800_0052;
    let plan = BlockPlan {
        start: GuestVa(0xd000),
        end: GuestVa(0xd008),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest: GuestVa(0xd000),
            action: InstAction::Memory(MemoryAccess {
                word,
                op: bad64::Op::LDR,
                base: MemoryBase::Literal(GuestVa(GUEST)),
                effective_address: super::types::MemoryEffectiveAddress::Base,
                writeback: MemoryWriteback::None,
                class: MemoryClass::Literal,
                virtualization: MemoryVirtualization::None,
            }),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(0xd004),
            resume: GuestVa(0xd008),
        },
    };
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate literal cache");
    let emitted = emit_block(
        &mut cache,
        &plan,
        super::emit::EmitAddressMode::Biased { host_bias },
    )
    .expect("emit biased literal");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0xd008),
    };
    super::gateway::enter_translated_in_mode(
        emitted.entry(),
        &mut snapshot,
        &mut exit,
        crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
    )
    .expect("execute biased literal");
    assert_eq!(snapshot.x[18], 0xfeed_face_cafe_beef);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn biased_x16_x17_and_store_families_execute_architecturally() {
    const BIAS: u64 = 0x80_0000_0000;
    const GUEST: u64 = 0x9_0000_0000;
    const VALUE: u64 = 0x1234_5678_9abc_def0;
    let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, 16 * 1024)
        .expect("construct host bias");
    let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
        HostVa((BIAS + GUEST) as usize),
        16 * 1024,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_ANON | libc::MAP_PRIVATE,
    )
    .expect("map operand-family data");
    let words =
        unsafe { std::slice::from_raw_parts_mut(mapping.range().start.raw() as *mut u64, 4) };
    let mut stack = vec![0_u8; 16 * 1024];

    type Configure = fn(&mut NativeUcontextSnapshot);
    type Verify = fn(&NativeUcontextSnapshot, &[u64]);
    let fixtures: [(u32, Configure, Verify); 4] = [
        (
            0xf940_0030,
            |snapshot: &mut NativeUcontextSnapshot| snapshot.x[1] = GUEST,
            |snapshot: &NativeUcontextSnapshot, words: &[u64]| assert_eq!(snapshot.x[16], words[0]),
        ),
        (
            0xf900_0031,
            |snapshot: &mut NativeUcontextSnapshot| {
                snapshot.x[1] = GUEST;
                snapshot.x[17] = VALUE;
            },
            |snapshot: &NativeUcontextSnapshot, words: &[u64]| {
                assert_eq!(words[0], VALUE);
                assert_eq!(snapshot.x[17], VALUE);
            },
        ),
        (
            0xf940_0200,
            |snapshot: &mut NativeUcontextSnapshot| snapshot.x[16] = GUEST,
            |snapshot: &NativeUcontextSnapshot, words: &[u64]| {
                assert_eq!(snapshot.x[0], words[0]);
                assert_eq!(snapshot.x[16], GUEST);
            },
        ),
        (
            0xf940_0220,
            |snapshot: &mut NativeUcontextSnapshot| snapshot.x[17] = GUEST,
            |snapshot: &NativeUcontextSnapshot, words: &[u64]| {
                assert_eq!(snapshot.x[0], words[0]);
                assert_eq!(snapshot.x[17], GUEST);
            },
        ),
    ];
    for (word, configure, verify) in fixtures {
        words.fill(0);
        words[0] = VALUE;
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        configure(&mut snapshot);
        run_biased_single_memory(word, GuestVa(0xe000), host_bias, &mut snapshot);
        verify(&snapshot, words);
    }

    words.fill(0);
    let mut pair = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    pair.x[0] = 11;
    pair.x[1] = 22;
    pair.x[2] = GUEST;
    run_biased_single_memory(0xa900_0440, GuestVa(0xe100), host_bias, &mut pair);
    assert_eq!(&words[..2], &[11, 22]);

    words.fill(0);
    let mut simd = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    simd.x[1] = GUEST;
    simd.v[0] = [0xa5; 16];
    run_biased_single_memory(0x3d80_0020, GuestVa(0xe200), host_bias, &mut simd);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), 16) },
        &[0xa5; 16]
    );

    words[0] = VALUE;
    let mut register_offset = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    register_offset.x[1] = GUEST;
    register_offset.x[2] = 0;
    run_biased_single_memory(
        0xf862_6820,
        GuestVa(0xe300),
        host_bias,
        &mut register_offset,
    );
    assert_eq!(register_offset.x[0], VALUE);
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

fn virtual_counter_plan(guest: GuestVa, destination: CounterDestination) -> BlockPlan {
    BlockPlan {
        start: guest,
        end: GuestVa(guest.raw() + 8),
        generation: CodeGeneration::INITIAL,
        instructions: vec![PlannedInst {
            guest,
            action: InstAction::CounterRead(CounterRead { destination }),
        }],
        exit: PlannedExit::Syscall {
            guest: GuestVa(guest.raw() + 4),
            resume: GuestVa(guest.raw() + 8),
        },
    }
}

fn counter_ticks_to_ns(ticks: u64, frequency: u64) -> u64 {
    u64::try_from((u128::from(ticks) * 1_000_000_000) / u128::from(frequency))
        .expect("counter nanoseconds fit u64")
}

#[test]
fn dsr_virtual_counter_tracks_suspend_excluding_uptime() {
    let guest = GuestVa(0x19_000);
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate counter cache");
    let emitted = emit_block_direct(
        &mut cache,
        &virtual_counter_plan(guest, CounterDestination::Gpr(2)),
    )
    .expect("emit virtual counter");
    assert_eq!(
        emitted.map().entries().len(),
        emitted.len() / std::mem::size_of::<u32>(),
        "every emitted word must have a guest-PC mapping"
    );
    let exit_offset = emitted
        .map()
        .entries()
        .iter()
        .find(|entry| entry.guest == GuestVa(guest.raw() + 4))
        .expect("counter block exit mapping")
        .cache;
    assert!(
        emitted
            .map()
            .entries()
            .iter()
            .filter(|entry| entry.cache.get() < exit_offset.get())
            .all(|entry| entry.guest == guest),
        "every inline counter word must map to the counter PC"
    );
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest.raw() + 8),
    };

    let before = crate::trap::host_clock_uptime_ns();
    enter_translated(emitted.entry(), &mut snapshot, &mut exit).expect("execute counter");
    let after = crate::trap::host_clock_uptime_ns();
    let (raw_counter, frequency) = crate::trap::host_counter();
    let observed = counter_ticks_to_ns(snapshot.x[2], frequency);
    // SAFETY: Darwin maps the fixed commpage timebase field read-only in every
    // process; this extra read is failure diagnostics, not the oracle value.
    let live_offset =
        unsafe { (super::counter::COMMPAGE_TIMEBASE_ADDRESS as *const u64).read_volatile() };
    let mach_ticks = super::counter::mach_absolute_time_ticks();

    assert!(
        before.saturating_sub(1_000) <= observed,
        "counter precedes uptime: before={before} observed={observed} after={after} ticks={} raw={raw_counter} freq={frequency} offset=0x{live_offset:x} mach={mach_ticks}",
        snapshot.x[2],
    );
    assert!(
        observed <= after.saturating_add(1_000),
        "counter exceeds uptime: before={before} observed={observed} after={after} ticks={}",
        snapshot.x[2]
    );
    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(guest.raw() + 8)
        }
    );
}

#[test]
fn dsr_virtual_counter_preserves_destination_matrix() {
    let destinations = [
        CounterDestination::Gpr(2),
        CounterDestination::Gpr(15),
        CounterDestination::Gpr(16),
        CounterDestination::Gpr(17),
        CounterDestination::Gpr(18),
        CounterDestination::Gpr(28),
        CounterDestination::Discard,
    ];
    let frequency = crate::trap::host_counter_frequency();

    for (case, destination) in destinations.into_iter().enumerate() {
        let guest = GuestVa(0x19_100 + (case as u64 * 0x100));
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate matrix cache");
        let emitted = emit_block_direct(&mut cache, &virtual_counter_plan(guest, destination))
            .expect("emit matrix counter");
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.pstate = 0xa000_0000;
        let expected = snapshot;
        let mut exit = NativeDsrExit::Syscall {
            resume: GuestVa(guest.raw() + 8),
        };

        let before = crate::trap::host_clock_uptime_ns();
        enter_translated(emitted.entry(), &mut snapshot, &mut exit)
            .expect("execute matrix counter");
        let after = crate::trap::host_clock_uptime_ns();

        for register in 0..31 {
            let is_destination = destination == CounterDestination::Gpr(register as u8);
            if is_destination {
                let observed = counter_ticks_to_ns(snapshot.x[register], frequency);
                assert!(
                    before.saturating_sub(1_000) <= observed,
                    "x{register} counter precedes uptime: before={before} observed={observed} after={after}"
                );
                assert!(
                    observed <= after.saturating_add(1_000),
                    "x{register} counter exceeds uptime: before={before} observed={observed} after={after}"
                );
            } else {
                assert_eq!(
                    snapshot.x[register], expected.x[register],
                    "x{register} changed for {destination:?}"
                );
            }
        }
        assert_eq!(
            snapshot.pstate, expected.pstate,
            "NZCV changed for {destination:?}"
        );
        assert_eq!(
            exit,
            NativeDsrExit::Syscall {
                resume: GuestVa(guest.raw() + 8)
            }
        );
    }
}

#[test]
fn dsr_virtual_counter_kicks_retry_before_and_preserve_after_commit() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let guest = GuestVa(0x20_0020_0000);
    let words = [0xd53b_e04f, 0xd400_0001]; // mrs x15, cntvct_el0; svc #0

    for completed in [false, true] {
        let mut fixture = biased_translator_fixture(&words, guest);
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.pc = guest.raw();
        snapshot.x[27] = 1;
        let original = snapshot;
        let prepared = fixture
            .translator
            .prepare_entry::<false>(&fixture.memory, &snapshot)
            .expect("prepare counter kick");
        let (cache_pc, _action) = fixture
            .translator
            .recovery_points_for_test(guest)
            .into_iter()
            .find(|(_, action)| action.instruction_complete() == completed)
            .expect("counter recovery phase");
        fixture
            .translator
            .patch_recovery_word_for_test(cache_pc, 0xf940_0369) // ldr x9, [x27], x27=1
            .expect("patch counter recovery point");
        let before = crate::trap::host_clock_uptime_ns();
        let fault = fixture
            .translator
            .enter_prepared::<false>(prepared, &mut snapshot)
            .expect("capture counter recovery state");
        let after = crate::trap::host_clock_uptime_ns();
        let committed_value = completed.then_some(snapshot.x[15]);
        if let Some(committed_value) = committed_value {
            let observed =
                counter_ticks_to_ns(committed_value, crate::trap::host_counter_frequency());
            assert!(before.saturating_sub(1_000) <= observed);
            assert!(observed <= after.saturating_add(1_000));
        }
        let NativeDsrExit::Fault {
            guest_pc: resume,
            rewrite_scratch,
            rewrite_context_scratch,
            generation_pstate_scratch,
            indirect_x15_scratch,
            indirect_x30_scratch,
            ..
        } = fault.exit
        else {
            panic!("expected patched counter fault, got {:?}", fault.exit);
        };
        let kick = super::PreparedExit {
            exit: NativeDsrExit::Kick {
                resume,
                rewrite_scratch,
                rewrite_context_scratch,
                generation_pstate_scratch,
                indirect_x15_scratch,
                indirect_x30_scratch,
            },
        };

        assert!(matches!(
            fixture
                .translator
                .finish_exit(&fixture.memory, &mut snapshot, prepared, kick)
                .expect("finish counter kick"),
            super::ThreadExit::Kick
        ));
        assert_eq!(snapshot.pc, guest.raw() + if completed { 4 } else { 0 });
        for register in 0..31 {
            if completed && register == 15 {
                assert_eq!(
                    snapshot.x[register],
                    committed_value.expect("committed x15 value")
                );
            } else {
                assert_eq!(
                    snapshot.x[register], original.x[register],
                    "completed={completed} x{register} sentinel"
                );
            }
        }
        assert_eq!(snapshot.pstate, original.pstate);
    }
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )?;
    let emitted = emit_block_direct(&mut cache, &plan)?;
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate PC-relative cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit ADR relocation");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate literal-load cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit literal-load relocation");
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
                    InstAction::Memory(mut memory)
                        if memory.class == super::types::MemoryClass::Literal =>
                    {
                        memory.base = super::types::MemoryBase::Literal(GuestVa(target));
                        Ok(InstAction::Memory(memory))
                    }
                    _ => Err(DsrError::BlockPolicy(format!(
                        "literal test word 0x{word:08x} did not classify as memory"
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate literal matrix cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit literal relocation matrix");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate ADRP cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit ADRP relocation");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate direct-flow cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit unresolved direct branch");
    let mut exit = NativeDsrExit::ResolveDirect {
        source: GuestVa(0x8000),
        target,
        binding: DirectBindingExitMetadata::Absent,
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("execute unresolved direct branch");
    assert_eq!(
        exit,
        NativeDsrExit::ResolveDirect {
            source: GuestVa(0x8000),
            target,
            binding: DirectBindingExitMetadata::Absent,
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
    let site = super::cache::LinkSite {
        source: source.entry(),
        slot: link.slot,
    };
    let word =
        super::encode_aarch64_direct_branch(site, target.entry()).expect("encode direct link");
    cache
        .patch_code_word(site, word)
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
    let mut cache = TranslationCache::new(
        32 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate linked-flow cache");
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
    let source = emit_block_direct(&mut cache, &source_plan).expect("emit linked source");
    let target = emit_block_direct(&mut cache, &syscall_plan(GuestVa(0xb000), 0x9100_0400))
        .expect("emit linked target"); // add x0, x0, #1
    patch_direct_target(&mut cache, &source, GuestVa(0xb000), &target);

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let expected_x0 = snapshot.x[0] + 1;
    let expected_x17 = snapshot.x[17] + 1;
    let mut exit = NativeDsrExit::ResolveDirect {
        source: GuestVa(0xa004),
        target: GuestVa(0xb000),
        binding: DirectBindingExitMetadata::Absent,
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
    let mut cache = TranslationCache::new(
        64 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate conditional-flow cache");
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
    let source = emit_block_direct(&mut cache, &source_plan).expect("emit conditional source");
    let fallthrough = emit_block_direct(&mut cache, &syscall_plan(GuestVa(0xc004), 0x9100_0821))
        .expect("emit fallthrough target"); // add x1, x1, #2
    let taken = emit_block_direct(&mut cache, &syscall_plan(GuestVa(0xc100), 0x9100_0421))
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
            binding: DirectBindingExitMetadata::Absent,
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
    let mut cache = TranslationCache::new(
        32 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate call-flow cache");
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
    let call = emit_block_direct(&mut cache, &call_plan).expect("emit linked call");
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
    let nested = emit_block_direct(&mut cache, &nested_plan).expect("emit nested call");
    let callee = emit_block_direct(&mut cache, &syscall_plan(GuestVa(0xe100), 0x9100_03c0))
        .expect("emit final callee"); // add x0, x30, #0
    patch_direct_target(&mut cache, &call, GuestVa(0xe000), &nested);
    patch_direct_target(&mut cache, &nested, GuestVa(0xe100), &callee);
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut exit = NativeDsrExit::ResolveDirect {
        source: GuestVa(0xd000),
        target: GuestVa(0xe000),
        binding: DirectBindingExitMetadata::Absent,
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
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate condition cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit condition edge");
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.x[18] = guest_x18;
        let expected_x17 = snapshot.x[17];
        let mut observed = NativeDsrExit::ResolveDirect {
            source: start,
            target: exit.target,
            binding: DirectBindingExitMetadata::Absent,
        };
        enter_translated(emitted.entry(), &mut snapshot, &mut observed)
            .expect("execute conditional edge");
        assert_eq!(snapshot.x[17], expected_x17);
        assert_eq!(
            observed,
            NativeDsrExit::ResolveDirect {
                source: start,
                target: GuestVa(start.raw() + 8),
                binding: DirectBindingExitMetadata::Absent,
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
    let mut cache = TranslationCache::new(
        32 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate virtual-edge cache");
    let source = super::emit::emit_block_with_generation_direct(
        &mut cache,
        &source_plan,
        super::emit::GenerationGuard::new(&generation, CodeGeneration::INITIAL),
    )
    .expect("emit guarded virtual edge");
    let target = super::emit::emit_block_with_generation_direct(
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
    let mut cache = TranslationCache::new(
        32 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate loop-flow cache");
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
    let loop_block = emit_block_direct(&mut cache, &loop_plan).expect("emit linked loop");
    let done = emit_block_direct(&mut cache, &syscall_plan(GuestVa(0xf008), 0xd503_201f))
        .expect("emit loop fallthrough");
    patch_direct_target(&mut cache, &loop_block, GuestVa(0xf000), &loop_block);
    patch_direct_target(&mut cache, &loop_block, GuestVa(0xf008), &done);
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = 4;
    let mut exit = NativeDsrExit::ResolveDirect {
        source: GuestVa(0xf004),
        target: GuestVa(0xf000),
        binding: DirectBindingExitMetadata::Absent,
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate indirect-flow cache");
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
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit unresolved return");
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
fn portable_direct_block_exits_through_context_gateway() {
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate portable direct cache");
    let guest = GuestVa(0x13_800);
    let target = GuestVa(guest.raw() + 4);
    let plan = BlockPlan {
        start: guest,
        end: target,
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Direct {
            guest,
            word: 0x1400_0001,
            exit: DirectExit {
                kind: DirectKind::Branch,
                target,
                resume: target,
                condition: None,
                register: None,
                bit: None,
            },
        },
    };
    let host_bias = crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
        .expect("construct portable direct bias");
    let artifact = super::emit::record_portable_block_artifact(
        &plan,
        0,
        super::emit::EmitAddressMode::Biased { host_bias },
        vec![0x1400_0001],
    )
    .expect("record portable direct block");
    let words = artifact
        .template
        .materialize_immutable_words(Some(host_bias.get()))
        .expect("materialize portable direct words");
    let emitted = cache
        .publish_words(&words)
        .expect("publish portable direct words");
    let generation = std::sync::atomic::AtomicU64::new(CodeGeneration::INITIAL.get());
    let bindings = [super::gateway::GenerationBinding::new(
        &generation,
        CodeGeneration::INITIAL,
    )];
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut exit = NativeDsrExit::ResolveDirect {
        source: guest,
        target,
        binding: DirectBindingExitMetadata::Absent,
    };
    super::gateway::enter_translated_with_generation_bindings(
        emitted.entry(),
        &mut snapshot,
        &mut exit,
        &bindings,
    )
    .expect("execute portable direct block");
    assert_eq!(
        exit,
        NativeDsrExit::ResolveDirect {
            source: guest,
            target,
            binding: DirectBindingExitMetadata::Absent,
        }
    );
}

fn assert_portable_direct_block_chains_through_published_target_authority(
    kind: DirectKind,
    word: u32,
) {
    let mut cache = TranslationCache::new(
        32 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate portable direct chaining cache");
    let guest = GuestVa(0x13_a00);
    let resume = GuestVa(guest.raw() + 4);
    let target = GuestVa(guest.raw() + 8);
    let source_plan = BlockPlan {
        start: guest,
        end: resume,
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Direct {
            guest,
            word,
            exit: DirectExit {
                kind,
                target,
                resume,
                condition: None,
                register: None,
                bit: None,
            },
        },
    };
    let target_plan = BlockPlan {
        start: target,
        end: GuestVa(target.raw() + 4),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Syscall {
            guest: target,
            resume: GuestVa(target.raw() + 4),
        },
    };
    let host_bias = crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
        .expect("construct portable direct chaining bias");
    let source_artifact = super::emit::record_portable_block_artifact(
        &source_plan,
        0,
        super::emit::EmitAddressMode::Biased { host_bias },
        vec![word],
    )
    .expect("record portable direct source");
    let target_artifact = super::emit::record_portable_block_artifact(
        &target_plan,
        1,
        super::emit::EmitAddressMode::Biased { host_bias },
        vec![0xd400_0001],
    )
    .expect("record portable direct target");
    let source_words = source_artifact
        .template
        .materialize_immutable_words(Some(host_bias.get()))
        .expect("materialize portable direct source");
    let target_words = target_artifact
        .template
        .materialize_immutable_words(Some(host_bias.get()))
        .expect("materialize portable direct target");
    let source = cache
        .publish_words(&source_words)
        .expect("publish portable direct source");
    let target_block = cache
        .publish_words(&target_words)
        .expect("publish portable direct target");
    let generations = [
        std::sync::atomic::AtomicU64::new(CodeGeneration::INITIAL.get()),
        std::sync::atomic::AtomicU64::new(CodeGeneration::INITIAL.get()),
    ];
    let bindings = [
        super::gateway::GenerationBinding::new(&generations[0], CodeGeneration::INITIAL),
        super::gateway::GenerationBinding::new(&generations[1], CodeGeneration::INITIAL),
    ];
    let range = cache.host_range();
    let authority =
        super::gateway::TargetCacheAuthority::new(range.start, range.end, bindings.as_ptr());
    let mut indirect = IndirectTargetCache::new();
    indirect.publish(
        target,
        CodeGeneration::INITIAL,
        target_block.entry(),
        &authority,
    );
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut exit = NativeDsrExit::ResolveDirect {
        source: guest,
        target,
        binding: DirectBindingExitMetadata::Absent,
    };

    super::gateway::enter_translated_with_cache_range_and_generation_bindings(
        source.entry(),
        &mut snapshot,
        &mut exit,
        &indirect,
        range.start,
        range.end,
        crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
        &bindings,
    )
    .expect("execute portable direct cache hit");

    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target.raw() + 4),
        }
    );
    if kind == DirectKind::Call {
        assert_eq!(snapshot.x[30], resume.raw());
    }
}

fn direct_binding_reentry_after_partial_authority_install(store_words: &[u32]) {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let mut partial_cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate partial-authority cache");
    let mut partial_words = store_words.to_vec();
    partial_words.push(0xf940_0369); // ldr x9, [x27], with x27=1
    let partial = partial_cache
        .publish_words(&partial_words)
        .expect("publish partial-authority sequence");

    let source_generation = std::sync::atomic::AtomicU64::new(CodeGeneration::INITIAL.get());
    let source_bindings = [super::gateway::GenerationBinding::new(
        &source_generation,
        CodeGeneration::INITIAL,
    )];
    let target_generation = std::sync::atomic::AtomicU64::new(7);
    let target_bindings = [super::gateway::GenerationBinding::new(
        &target_generation,
        CodeGeneration::claimed(7),
    )];
    let source_range = partial_cache.host_range();
    let target_range = (
        source_range.start.saturating_add(0x100_000),
        source_range.end.saturating_add(0x200_000),
    );
    let partial_descriptor = 0xfeed_0000_dead_0000_u64;
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[15] = target_range.0 as u64;
    snapshot.x[13] = partial_descriptor;
    snapshot.x[17] = target_bindings.as_ptr() as usize as u64;
    snapshot.x[30] = target_range.1 as u64;
    snapshot.x[27] = 1;
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(0x4000),
    };
    super::gateway::enter_translated_with_cache_range_and_generation_bindings(
        partial.entry(),
        &mut snapshot,
        &mut exit,
        &IndirectTargetCache::new(),
        source_range.start,
        source_range.end,
        crate::native_darwin::address::NativeAddressMode::Direct,
        &source_bindings,
    )
    .expect("interrupt partial authority installation");
    assert!(
        matches!(exit, NativeDsrExit::Fault { .. }),
        "partial authority sequence must fault after its requested store: {exit:?}"
    );

    let mut verifier_cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate authority verifier");
    let verifier_words = [
        0xf942_4f80, // ldr x0, [x28, #1176] -- cache_start
        0xf942_5381, // ldr x1, [x28, #1184] -- cache_end
        0xf942_7b82, // ldr x2, [x28, #1264] -- generation_bindings
        0xf942_8b83, // ldr x3, [x28, #1296] -- direct_binding_target
        0xf942_1b84, // ldr x4, [x28, #1072] -- entry
        0xd288_0011, // mov x17, #0x4000
        0xf2a0_0011,
        0xf2c0_0011,
        0xf2e0_0011,
        0xf902_1f91, // str x17, [x28, #1080] -- exit target
        0x5280_0031, // mov w17, #1 -- syscall exit
        0xb904_4b91, // str w17, [x28, #1096]
        0xf942_6391, // ldr x17, [x28, #1216] -- syscall gateway
        0xd61f_0220, // br x17
    ];
    let verifier = verifier_cache
        .publish_words(&verifier_words)
        .expect("publish authority verifier");
    let verifier_range = verifier_cache.host_range();
    let mut reentry_snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut reentry_exit = exit;
    super::gateway::enter_translated_with_cache_range_and_generation_bindings(
        verifier.entry(),
        &mut reentry_snapshot,
        &mut reentry_exit,
        &IndirectTargetCache::new(),
        verifier_range.start,
        verifier_range.end,
        crate::native_darwin::address::NativeAddressMode::Direct,
        &source_bindings,
    )
    .expect("re-enter after partial authority installation");

    assert_eq!(
        reentry_exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(0x4000),
        }
    );
    assert_eq!(reentry_snapshot.x[0], verifier_range.start as u64);
    assert_eq!(reentry_snapshot.x[1], verifier_range.end as u64);
    assert_eq!(
        reentry_snapshot.x[2],
        source_bindings.as_ptr() as usize as u64
    );
    assert_eq!(
        reentry_snapshot.x[3], 0,
        "a fresh source authority must clear the partial target descriptor"
    );
    assert_eq!(reentry_snapshot.x[4], verifier.entry().host().raw() as u64);
    assert_ne!(reentry_snapshot.x[0], target_range.0 as u64);
    assert_ne!(reentry_snapshot.x[1], target_range.1 as u64);
    assert_ne!(
        reentry_snapshot.x[2],
        target_bindings.as_ptr() as usize as u64
    );
    assert_ne!(reentry_snapshot.x[3], partial_descriptor);
}

#[test]
fn direct_binding_reentry_after_cache_range_store_discards_partial_target() {
    direct_binding_reentry_after_partial_authority_install(&[
        0x9112_638e, // add x14, x28, #1176
        0xa900_79cf, // stp x15, x30, [x14]
    ]);
}

#[test]
fn direct_binding_reentry_after_generation_store_discards_partial_target() {
    direct_binding_reentry_after_partial_authority_install(&[
        0xf902_7b91, // target generation bindings
    ]);
}

#[test]
fn direct_binding_reentry_after_descriptor_store_discards_partial_target() {
    direct_binding_reentry_after_partial_authority_install(&[
        0xf902_8b8d, // target descriptor pointer from x13
    ]);
}

#[test]
fn portable_direct_branch_chains_through_published_target_authority() {
    assert_portable_direct_block_chains_through_published_target_authority(
        DirectKind::Branch,
        0x1400_0002,
    );
}

#[test]
fn portable_direct_call_chains_through_published_target_authority() {
    assert_portable_direct_block_chains_through_published_target_authority(
        DirectKind::Call,
        0x9400_0002,
    );
}

#[test]
fn portable_direct_cache_hit_switches_cross_unit_authority_tuple() {
    let mut source_cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate direct source cache");
    let mut target_cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate direct target cache");
    let source_guest = GuestVa(0x13_c00);
    let target_guest = GuestVa(source_guest.raw() + 8);
    let host_bias = crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
        .expect("construct cross-unit direct bias");
    let source = super::emit::record_portable_block_artifact(
        &BlockPlan {
            start: source_guest,
            end: GuestVa(source_guest.raw() + 4),
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Direct {
                guest: source_guest,
                word: 0x1400_0002,
                exit: DirectExit {
                    kind: DirectKind::Branch,
                    target: target_guest,
                    resume: GuestVa(source_guest.raw() + 4),
                    condition: None,
                    register: None,
                    bit: None,
                },
            },
        },
        0,
        super::emit::EmitAddressMode::Biased { host_bias },
        vec![0x1400_0002],
    )
    .expect("record cross-unit direct source");
    let target = super::emit::record_portable_block_artifact(
        &BlockPlan {
            start: target_guest,
            end: GuestVa(target_guest.raw() + 4),
            generation: CodeGeneration::claimed(1),
            instructions: Vec::new(),
            exit: PlannedExit::Syscall {
                guest: target_guest,
                resume: GuestVa(target_guest.raw() + 4),
            },
        },
        1,
        super::emit::EmitAddressMode::Biased { host_bias },
        vec![0xd400_0001],
    )
    .expect("record cross-unit direct target");
    let source = source_cache
        .publish_words(
            &source
                .template
                .materialize_immutable_words(Some(host_bias.get()))
                .expect("materialize cross-unit direct source"),
        )
        .expect("publish cross-unit direct source");
    let target = target_cache
        .publish_words(
            &target
                .template
                .materialize_immutable_words(Some(host_bias.get()))
                .expect("materialize cross-unit direct target"),
        )
        .expect("publish cross-unit direct target");
    let source_generation = std::sync::atomic::AtomicU64::new(CodeGeneration::INITIAL.get());
    let target_generation = std::sync::atomic::AtomicU64::new(CodeGeneration::claimed(1).get());
    let source_bindings = [
        super::gateway::GenerationBinding::new(&source_generation, CodeGeneration::INITIAL),
        super::gateway::GenerationBinding::new(&target_generation, CodeGeneration::claimed(2)),
    ];
    let target_bindings = [
        super::gateway::GenerationBinding::new(&source_generation, CodeGeneration::claimed(2)),
        super::gateway::GenerationBinding::new(&target_generation, CodeGeneration::claimed(1)),
    ];
    let source_range = source_cache.host_range();
    let target_range = target_cache.host_range();
    assert_ne!(
        source_range, target_range,
        "source and target must use distinct caches"
    );
    assert_ne!(
        source_bindings.as_ptr(),
        target_bindings.as_ptr(),
        "source and target must use distinct generation-binding tables"
    );
    let target_authority = super::gateway::TargetCacheAuthority::new(
        target_range.start,
        target_range.end,
        target_bindings.as_ptr(),
    );
    let mut indirect = IndirectTargetCache::new();
    indirect.publish(
        target_guest,
        CodeGeneration::claimed(1),
        target.entry(),
        &target_authority,
    );
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let mut exit = NativeDsrExit::ResolveDirect {
        source: source_guest,
        target: target_guest,
        binding: DirectBindingExitMetadata::Absent,
    };

    super::gateway::enter_translated_with_cache_range_and_generation_bindings(
        source.entry(),
        &mut snapshot,
        &mut exit,
        &indirect,
        source_range.start,
        source_range.end,
        crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
        &source_bindings,
    )
    .expect("execute cross-unit direct cache hit");

    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target_guest.raw() + 4),
        },
        "the direct cache hit must install the target range and binding table before entry"
    );
}

#[test]
fn dsr_indirect_flow_blr_sets_guest_link_and_alternates_targets() {
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate BLR cache");
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
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit BLR");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate x18 branch cache");
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
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit virtual x18 branch");
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
fn dsr_indirect_cache_keeps_old_index_aliases_hot() {
    let source_guest = GuestVa(0x41_000);
    let first = GuestVa(0x42_000);
    let second = GuestVa(0x48_000);
    assert_eq!(
        (first.raw() >> 2) & 1023,
        (second.raw() >> 2) & 1023,
        "fixture must collide under the old page-offset index",
    );

    let target_plan = |target: GuestVa| BlockPlan {
        start: target,
        end: GuestVa(target.raw() + 4),
        generation: CodeGeneration::INITIAL,
        instructions: Vec::new(),
        exit: PlannedExit::Syscall {
            guest: target,
            resume: GuestVa(target.raw() + 4),
        },
    };
    let mut code = TranslationCache::new(
        32 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate alias oracle");
    let first_block =
        emit_block_direct(&mut code, &target_plan(first)).expect("emit first alias target");
    let second_block =
        emit_block_direct(&mut code, &target_plan(second)).expect("emit second alias target");
    let source = emit_block_direct(
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
    .expect("emit alias source");
    let range = code.host_range();
    let authority =
        super::gateway::TargetCacheAuthority::new(range.start, range.end, std::ptr::null());
    let mut indirect = IndirectTargetCache::new();
    indirect.publish(
        first,
        CodeGeneration::INITIAL,
        first_block.entry(),
        &authority,
    );
    indirect.publish(
        second,
        CodeGeneration::INITIAL,
        second_block.entry(),
        &authority,
    );

    let mut stack = vec![0_u8; 16 * 1024];
    for target in [first, second] {
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.x[0] = target.raw();
        let mut exit = NativeDsrExit::ResolveIndirect {
            source: source_guest,
            target,
            link: None,
        };
        enter_translated_with_cache(source.entry(), &mut snapshot, &mut exit, &indirect)
            .expect("execute cached alias target");
        assert_eq!(
            exit,
            NativeDsrExit::Syscall {
                resume: GuestVa(target.raw() + 4),
            },
            "both stable targets must remain cached",
        );
    }
}

#[test]
fn dsr_indirect_flow_cache_hit_stays_in_translated_code() {
    let source_guest = GuestVa(0x18_100);
    let target_guest = GuestVa(0x18_200);
    let target_generation = CodeGeneration::claimed(2);
    let generation = std::sync::atomic::AtomicU64::new(target_generation.get());
    let mut code = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate indirect cache-hit code");
    // Production blocks carry a generation guard.  That guard must observe
    // the original guest x17 after an inline-cache hit, not the x17 scratch
    // used to hold the indirect target.
    let target = super::emit::emit_block_with_generation_direct(
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
    let source = emit_block_direct(
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
    let range = code.host_range();
    let authority =
        super::gateway::TargetCacheAuthority::new(range.start, range.end, std::ptr::null());
    let mut indirect = IndirectTargetCache::new();
    indirect.publish(target_guest, target_generation, target.entry(), &authority);

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
            binding: DirectBindingExitMetadata::Absent,
        }
    );
}

#[test]
fn dsr_indirect_cache_installs_target_outside_active_translation_unit() {
    let source_guest = GuestVa(0x18_240);
    let target_guest = GuestVa(0x18_280);
    let mut source_code = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate indirect source unit");
    let source = emit_block_direct(
        &mut source_code,
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
    .expect("emit indirect source");
    let mut target_code = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate separate indirect target unit");
    let target = emit_block_direct(
        &mut target_code,
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
    .expect("emit separate indirect target");
    let target_range = target_code.host_range();
    let authority = super::gateway::TargetCacheAuthority::new(
        target_range.start,
        target_range.end,
        std::ptr::null(),
    );
    let mut indirect = IndirectTargetCache::new();
    indirect.publish(
        target_guest,
        CodeGeneration::INITIAL,
        target.entry(),
        &authority,
    );

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = target_guest.raw();
    let expected = NativeDsrExit::ResolveIndirect {
        source: source_guest,
        target: target_guest,
        link: None,
    };
    let mut exit = expected;
    let active_range = source_code.host_range();
    super::gateway::enter_translated_with_cache_range(
        source.entry(),
        &mut snapshot,
        &mut exit,
        &indirect,
        active_range.start,
        active_range.end,
        crate::native_darwin::address::NativeAddressMode::Direct,
    )
    .expect("execute source with an out-of-unit cached target");

    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target_guest.raw() + 4),
        },
        "a cached target must install its own unit authority"
    );

    indirect.publish(
        target_guest,
        CodeGeneration::INITIAL,
        target.entry(),
        &authority,
    );
    snapshot.pc = source_guest.raw();
    snapshot.x[0] = target_guest.raw();
    exit = expected;
    super::gateway::enter_translated_with_cache_range(
        source.entry(),
        &mut snapshot,
        &mut exit,
        &indirect,
        active_range.start,
        active_range.end,
        crate::native_darwin::address::NativeAddressMode::Direct,
    )
    .expect("execute source after republishing cross-unit target");
    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target_guest.raw() + 4),
        },
        "republishing preserves the target unit authority"
    );

    snapshot.pc = source_guest.raw();
    snapshot.x[0] = target_guest.raw();
    exit = expected;
    super::gateway::enter_translated_with_trusted_private_cache(
        source.entry(),
        &mut snapshot,
        &mut exit,
        &indirect,
        crate::native_darwin::address::NativeAddressMode::Direct,
    )
    .expect("execute source with a private-only target cache");
    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target_guest.raw() + 4),
        },
        "a private-only cache may chain without redundant range checks"
    );
}

#[test]
fn dsr_indirect_flow_cached_blr_sets_guest_link_register() {
    let source_guest = GuestVa(0x18_300);
    let target_guest = GuestVa(0x18_400);
    let resume_guest = GuestVa(source_guest.raw() + 4);
    let mut code = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate cached BLR code");
    let target = emit_block_direct(
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
    let source = emit_block_direct(
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
    let range = code.host_range();
    let authority =
        super::gateway::TargetCacheAuthority::new(range.start, range.end, std::ptr::null());
    let mut indirect = IndirectTargetCache::new();
    indirect.publish(
        target_guest,
        CodeGeneration::INITIAL,
        target.entry(),
        &authority,
    );
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

    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate sensitive cache");
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
            fusion: None,
        },
    };
    let emitted = emit_block_with_generation_direct(
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate x18 rewrite cache");
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
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit x18 rewrites");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate x18 alias cache");
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
    let emitted = super::emit::emit_block_with_generation_direct(
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate x28 rewrite cache");
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
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit x28 rewrites");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate dual rewrite cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit dual virtual store");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate dual add cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit dual virtual add");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate dual load cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit dual virtual load");
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate generation guard cache");
    let emitted = super::emit::emit_block_with_generation_direct(
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
            binding: DirectBindingExitMetadata::Absent,
        }
    );
}

#[test]
fn binding_generation_guard_contains_no_process_pointer() {
    use std::sync::atomic::AtomicU64;

    let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
    let process_pointer = (&generation as *const AtomicU64 as usize as u64).to_le_bytes();
    let adversarial_pointer = 0x1234_5678_9abc_def0_u64.to_le_bytes();
    let guest = GuestVa(0x1b_300);
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate binding generation guard cache");
    let emitted = super::emit::emit_block_with_generation_direct(
        &mut cache,
        &plan,
        GenerationGuard::binding(3, CodeGeneration::INITIAL),
    )
    .expect("emit binding generation guard");
    let bytes = unsafe {
        std::slice::from_raw_parts(emitted.entry().host().raw() as *const u8, emitted.len())
    };
    let words = bytes
        .chunks_exact(std::mem::size_of::<u32>())
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("complete emitted word")))
        .collect::<Vec<_>>();
    let materialized_values = words
        .windows(4)
        .filter_map(|words| {
            let register = words[0] & 0x1f;
            let immediate_mask = (0xffff << 5) | 0x1f;
            let expected_bases = [
                0xd280_0000,
                0xf280_0000 | (1 << 21),
                0xf280_0000 | (2 << 21),
                0xf280_0000 | (3 << 21),
            ];
            if words
                .iter()
                .zip(expected_bases)
                .any(|(word, base)| word & 0x1f != register || word & !immediate_mask != base)
            {
                return None;
            }
            Some(
                words
                    .iter()
                    .enumerate()
                    .fold(0_u64, |value, (halfword, word)| {
                        value | (u64::from((word >> 5) & 0xffff) << (halfword * 16))
                    }),
            )
        })
        .collect::<Vec<_>>();

    assert!(
        !materialized_values.contains(&u64::from_le_bytes(process_pointer)),
        "immutable binding guard embedded a process pointer"
    );
    assert!(
        !materialized_values.contains(&u64::from_le_bytes(adversarial_pointer)),
        "immutable binding guard embedded the adversarial process pointer"
    );
    let operations = words
        .iter()
        .enumerate()
        .map(|(index, word)| {
            bad64::decode(*word, guest.raw() + (index as u64 * 4))
                .expect("decode binding generation guard")
                .op()
        })
        .collect::<Vec<_>>();
    assert!(
        operations.windows(4).any(|window| {
            window
                == [
                    bad64::Op::ADD,
                    bad64::Op::LDP,
                    bad64::Op::LDAR,
                    bad64::Op::CMP,
                ]
        }),
        "binding guard must index the process table then atomically compare its binding"
    );
}

#[test]
fn binding_generation_guard_exits_stale_after_atomic_changes() {
    use std::sync::atomic::{AtomicU64, Ordering};

    let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
    let bindings = [super::gateway::GenerationBinding::new(
        &generation,
        CodeGeneration::INITIAL,
    )];
    let guest = GuestVa(0x1b_400);
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
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate binding generation guard cache");
    let emitted = super::emit::emit_block_with_generation_direct(
        &mut cache,
        &plan,
        GenerationGuard::binding(0, CodeGeneration::INITIAL),
    )
    .expect("emit binding generation guard");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let original_x0 = snapshot.x[0];
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest.raw() + 8),
    };
    super::gateway::enter_translated_with_generation_bindings(
        emitted.entry(),
        &mut snapshot,
        &mut exit,
        &bindings,
    )
    .expect("execute current binding guard");
    assert_eq!(snapshot.x[0], original_x0 + 1);

    generation.fetch_add(2, Ordering::Release);
    snapshot.x[0] = original_x0;
    snapshot.pc = guest.raw();
    super::gateway::enter_translated_with_generation_bindings(
        emitted.entry(),
        &mut snapshot,
        &mut exit,
        &bindings,
    )
    .expect("reject stale binding guard");
    assert_eq!(
        snapshot.x[0], original_x0,
        "stale binding guest instruction executed"
    );
    assert_eq!(
        exit,
        NativeDsrExit::ResolveDirect {
            source: guest,
            target: guest,
            binding: DirectBindingExitMetadata::Absent,
        }
    );
}

#[test]
fn published_shared_block_prevents_second_process_translation() {
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, DirectBindingLayout, ExecutableIdentity, GuestCodeLen, ImageFileLen,
        ImageFileOffset, NativePageProfileIdentity, PortableBlockRecord, PublishOutcome,
        SharedExecutableSegment, SharedImageConfig, SharedLoadedTranslationUnit, SourceFingerprint,
        TRANSLATION_UNIT_BASE_EXPORT, TRANSLATION_UNIT_SCHEMA_V2, TranslationUnitKey,
        TranslationUnitManifest, TranslationUnitStore, UnitMissReason,
    };

    #[derive(Clone)]
    struct FixtureStore {
        unit: SharedLoadedTranslationUnit,
    }

    impl TranslationUnitStore for FixtureStore {
        fn load(
            &self,
            _key: &TranslationUnitKey,
            _source_words: &[u32],
        ) -> Result<Option<SharedLoadedTranslationUnit>, UnitMissReason> {
            Ok(Some(self.unit.clone()))
        }

        fn publish(
            &self,
            _pending: &carrick_dsr_aarch64::shared_cache::PendingTranslationUnit,
        ) -> Result<PublishOutcome, UnitMissReason> {
            Ok(PublishOutcome::Existing)
        }
    }

    let words = [0x9100_0400, 0xd400_0001]; // add x0,x0,#1 ; svc #0
    let guest = GuestVa(0x20_0000_0000);
    let mut fixture = biased_translator_fixture(&words, guest);
    let generation = fixture
        .memory
        .dsr_generation_observation(guest)
        .expect("observe fixture generation")
        .expected();
    let plan = super::block::plan_block(&fixture.memory, guest, generation, 256)
        .expect("plan fixture block");
    let cache = std::sync::Arc::new(parking_lot::Mutex::new(
        TranslationCache::new(
            64 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate shared fixture cache"),
    ));
    let (emitted, record) = super::emit::emit_block_recording_artifact(
        &mut cache.lock(),
        &plan,
        GenerationGuard::binding(0, CodeGeneration::INITIAL),
        super::emit::EmitAddressMode::Biased {
            host_bias: fixture.host_bias,
        },
        words.to_vec(),
    )
    .expect("emit portable shared fixture");
    let base = emitted.entry().host().raw();
    let code_len = emitted.len();
    drop(emitted);
    let source_fingerprint = SourceFingerprint::from_words(&words);
    let key = TranslationUnitKey::for_segment(
        ExecutableIdentity::Digest([0x11; 32]),
        ImageFileOffset::new(0),
        ImageFileLen::new(8).expect("nonzero file length"),
        guest,
        GuestCodeLen::new(16 * 1024).expect("nonzero guest length"),
        source_fingerprint,
        NativePageProfileIdentity::Native16k,
        AddressModeIdentity::biased(fixture.host_bias),
    );
    let manifest = TranslationUnitManifest {
        schema: TRANSLATION_UNIT_SCHEMA_V2,
        key: key.clone(),
        dylib_sha256: [0x22; 32],
        base_export: TRANSLATION_UNIT_BASE_EXPORT.to_owned(),
        code_len: code_len as u64,
        blocks: vec![PortableBlockRecord {
            guest_start: guest,
            generation_binding: 0,
            entry_offset: 0,
            code_len: code_len as u32,
            requires_sensitive_metadata: false,
            template: record.template,
        }],
        binding_layout: DirectBindingLayout::Disabled,
        binding_export: String::new(),
        binding_data_len: 0,
        cell_size: 0,
        bindings: Vec::new(),
        binding_relocations: Vec::new(),
    };
    let lease: Arc<dyn Send + Sync> = cache;
    let store = Arc::new(FixtureStore {
        unit: SharedLoadedTranslationUnit::new(manifest, base, lease),
    });
    fixture
        .translator
        .process
        .configure_shared_image(
            SharedImageConfig {
                executable: ExecutableIdentity::Digest([0x11; 32]),
                page_profile: NativePageProfileIdentity::Native16k,
                address_mode: AddressModeIdentity::biased(fixture.host_bias),
                segments: vec![SharedExecutableSegment {
                    file_offset: ImageFileOffset::new(0),
                    file_len: ImageFileLen::new(8).expect("nonzero file length"),
                    guest_start: guest,
                    guest_len: GuestCodeLen::new(16 * 1024).expect("nonzero guest length"),
                    source_words: words.to_vec().into(),
                }],
            },
            store,
        )
        .expect("configure shared fixture");

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.pc = guest.raw();
    let original_x0 = snapshot.x[0];
    let prepared = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare shared entry");
    let exit = fixture
        .translator
        .enter_prepared::<false>(prepared, &mut snapshot)
        .expect("execute shared entry");
    assert_eq!(snapshot.x[0], original_x0 + 1);
    assert!(matches!(exit.exit, NativeDsrExit::Syscall { .. }));
    let stats = fixture.translator.resolver_stats();
    assert_eq!(stats.shared_unit_hits, 1);
    assert_eq!(stats.shared_translations_avoided, 1);
    assert_eq!(stats.translations, 0);

    fixture
        .memory
        .note_dsr_code_mutation(guest.raw(), 4)
        .expect("advance executable-page generation");
    snapshot.pc = guest.raw();
    snapshot.x[0] = original_x0;
    let changed = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare changed source through JIT");
    assert_ne!(
        changed.entry, prepared.entry,
        "changed generation reused the immutable entry"
    );
    assert_eq!(
        fixture.translator.resolver_stats().translations,
        1,
        "changed generation must fall back to ordinary JIT translation"
    );
}

#[test]
fn shared_to_private_indirect_cache_hit_installs_target_authority() {
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, DirectBindingLayout, ExecutableIdentity, GuestCodeLen, ImageFileLen,
        ImageFileOffset, NativePageProfileIdentity, PendingTranslationUnit, PortableBlockCandidate,
        PublishOutcome, SharedExecutableSegment, SharedImageConfig, SharedLoadedTranslationUnit,
        SourceFingerprint, TRANSLATION_UNIT_BASE_EXPORT, TRANSLATION_UNIT_SCHEMA_V2,
        TranslationUnitKey, TranslationUnitManifest, TranslationUnitStore, UnitMissReason,
    };

    struct FixtureStore(SharedLoadedTranslationUnit);
    impl TranslationUnitStore for FixtureStore {
        fn load(
            &self,
            _key: &TranslationUnitKey,
            _source_words: &[u32],
        ) -> Result<Option<SharedLoadedTranslationUnit>, UnitMissReason> {
            Ok(Some(self.0.clone()))
        }

        fn publish(
            &self,
            _pending: &PendingTranslationUnit,
        ) -> Result<PublishOutcome, UnitMissReason> {
            Ok(PublishOutcome::Existing)
        }
    }

    let words = [0xd61f_0020, 0xd400_0001]; // br x1 ; svc #0
    let guest = GuestVa(0x20_0000_0000);
    let mut fixture = biased_translator_fixture(&words, guest);
    let generation = fixture
        .memory
        .dsr_generation_observation(guest)
        .expect("observe indirect fixture generation")
        .expected();
    let first_plan = super::block::plan_block(&fixture.memory, guest, generation, 256)
        .expect("plan indirect source");
    let target = GuestVa(guest.raw() + 4);
    let first = super::emit::record_portable_block_artifact(
        &first_plan,
        0,
        super::emit::EmitAddressMode::Biased {
            host_bias: fixture.host_bias,
        },
        vec![words[0]],
    )
    .expect("record portable indirect source");
    let key = TranslationUnitKey::for_segment(
        ExecutableIdentity::Digest([0x77; 32]),
        ImageFileOffset::new(0),
        ImageFileLen::new(4).expect("nonzero file length"),
        guest,
        GuestCodeLen::new(4).expect("nonzero guest length"),
        SourceFingerprint::from_words(&words[..1]),
        NativePageProfileIdentity::Native16k,
        AddressModeIdentity::biased(fixture.host_bias),
    );
    let pending = PendingTranslationUnit::pack(
        key.clone(),
        vec![PortableBlockCandidate {
            guest_start: guest,
            generation_binding: 0,
            requires_sensitive_metadata: false,
            template: first.template,
        }],
        DirectBindingLayout::Disabled,
    )
    .expect("pack indirect fixture unit");
    let code_words = pending
        .code
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        .collect::<Vec<_>>();
    let cache = Arc::new(parking_lot::Mutex::new(
        TranslationCache::new(
            64 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate indirect fixture cache"),
    ));
    let emitted = cache
        .lock()
        .publish_words(&code_words)
        .expect("publish indirect fixture unit");
    let manifest = TranslationUnitManifest {
        schema: TRANSLATION_UNIT_SCHEMA_V2,
        key: key.clone(),
        dylib_sha256: [0x88; 32],
        base_export: TRANSLATION_UNIT_BASE_EXPORT.to_owned(),
        code_len: pending.code.len() as u64,
        blocks: pending.blocks,
        binding_layout: pending.binding_layout,
        binding_export: pending.binding_export,
        binding_data_len: pending.binding_data_len,
        cell_size: pending.cell_size,
        bindings: pending.bindings,
        binding_relocations: pending.binding_relocations,
    };
    let base = emitted.entry().host().raw();
    let lease: Arc<dyn Send + Sync> = cache;
    fixture
        .translator
        .process
        .configure_shared_image(
            SharedImageConfig {
                executable: ExecutableIdentity::Digest([0x77; 32]),
                page_profile: NativePageProfileIdentity::Native16k,
                address_mode: AddressModeIdentity::biased(fixture.host_bias),
                segments: vec![SharedExecutableSegment {
                    file_offset: ImageFileOffset::new(0),
                    file_len: ImageFileLen::new(4).expect("nonzero file length"),
                    guest_start: guest,
                    guest_len: GuestCodeLen::new(4).expect("nonzero guest length"),
                    source_words: words[..1].to_vec().into(),
                }],
            },
            Arc::new(FixtureStore(SharedLoadedTranslationUnit::new(
                manifest, base, lease,
            ))),
        )
        .expect("configure indirect fixture");

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.pc = guest.raw();
    snapshot.x[1] = target.raw();
    let prepared = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare shared indirect source");
    let exit = fixture
        .translator
        .enter_prepared::<false>(prepared, &mut snapshot)
        .expect("execute shared indirect miss");
    assert!(matches!(
        exit.exit,
        NativeDsrExit::ResolveIndirect {
            target: resolved,
            ..
        } if resolved == target
    ));
    assert!(matches!(
        fixture
            .translator
            .finish_exit(&fixture.memory, &mut snapshot, prepared, exit)
            .expect("resolve shared indirect target"),
        super::ThreadExit::Continue
    ));

    snapshot.pc = guest.raw();
    let prepared = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare shared indirect cache hit");
    let exit = fixture
        .translator
        .enter_prepared::<false>(prepared, &mut snapshot)
        .expect("execute shared indirect cache hit");
    assert_eq!(
        exit.exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target.raw() + 4)
        }
    );
}

#[test]
fn indirect_authority_switch_jittered_sigpipe_never_becomes_entry_kick() {
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, DirectBindingLayout, ExecutableIdentity, GuestCodeLen, ImageFileLen,
        ImageFileOffset, NativePageProfileIdentity, PendingTranslationUnit, PortableBlockCandidate,
        PublishOutcome, SharedExecutableSegment, SharedImageConfig, SharedLoadedTranslationUnit,
        SourceFingerprint, TRANSLATION_UNIT_BASE_EXPORT, TRANSLATION_UNIT_SCHEMA_V2,
        TranslationUnitKey, TranslationUnitManifest, TranslationUnitStore, UnitMissReason,
    };

    struct FixtureStore(SharedLoadedTranslationUnit);
    impl TranslationUnitStore for FixtureStore {
        fn load(
            &self,
            _key: &TranslationUnitKey,
            _source_words: &[u32],
        ) -> Result<Option<SharedLoadedTranslationUnit>, UnitMissReason> {
            Ok(Some(self.0.clone()))
        }

        fn publish(
            &self,
            _pending: &PendingTranslationUnit,
        ) -> Result<PublishOutcome, UnitMissReason> {
            Ok(PublishOutcome::Existing)
        }
    }

    let _signal_oracle = install_signal_handlers_for_oracle();
    let words = [0xd61f_0020, 0xd61f_0040]; // br x1 ; br x2
    let source = GuestVa(0x20_0000_0000);
    let target = GuestVa(source.raw() + 4);
    let mut fixture = biased_translator_fixture(&words, source);
    let generation = fixture
        .memory
        .dsr_generation_observation(source)
        .expect("observe indirect authority-switch generation")
        .expected();
    let source_plan = super::block::plan_block(&fixture.memory, source, generation, 256)
        .expect("plan shared indirect source");
    let artifact = super::emit::record_portable_block_artifact(
        &source_plan,
        0,
        super::emit::EmitAddressMode::Biased {
            host_bias: fixture.host_bias,
        },
        vec![words[0]],
    )
    .expect("record shared indirect source");
    let key = TranslationUnitKey::for_segment(
        ExecutableIdentity::Digest([0x79; 32]),
        ImageFileOffset::new(0),
        ImageFileLen::new(4).expect("nonzero file length"),
        source,
        GuestCodeLen::new(4).expect("nonzero guest length"),
        SourceFingerprint::from_words(&words[..1]),
        NativePageProfileIdentity::Native16k,
        AddressModeIdentity::biased(fixture.host_bias),
    );
    let pending = PendingTranslationUnit::pack(
        key.clone(),
        vec![PortableBlockCandidate {
            guest_start: source,
            generation_binding: 0,
            requires_sensitive_metadata: false,
            template: artifact.template,
        }],
        DirectBindingLayout::Disabled,
    )
    .expect("pack shared indirect source");
    let code_words = pending
        .code
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        .collect::<Vec<_>>();
    let cache = Arc::new(parking_lot::Mutex::new(
        TranslationCache::new(
            64 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate shared indirect source cache"),
    ));
    let emitted = cache
        .lock()
        .publish_words(&code_words)
        .expect("publish shared indirect source");
    let manifest = TranslationUnitManifest {
        schema: TRANSLATION_UNIT_SCHEMA_V2,
        key: key.clone(),
        dylib_sha256: [0x89; 32],
        base_export: TRANSLATION_UNIT_BASE_EXPORT.to_owned(),
        code_len: pending.code.len() as u64,
        blocks: pending.blocks,
        binding_layout: pending.binding_layout,
        binding_export: pending.binding_export,
        binding_data_len: pending.binding_data_len,
        cell_size: pending.cell_size,
        bindings: pending.bindings,
        binding_relocations: pending.binding_relocations,
    };
    let base = emitted.entry().host().raw();
    let lease: Arc<dyn Send + Sync> = cache;
    fixture
        .translator
        .process
        .configure_shared_image(
            SharedImageConfig {
                executable: ExecutableIdentity::Digest([0x79; 32]),
                page_profile: NativePageProfileIdentity::Native16k,
                address_mode: AddressModeIdentity::biased(fixture.host_bias),
                segments: vec![SharedExecutableSegment {
                    file_offset: ImageFileOffset::new(0),
                    file_len: ImageFileLen::new(4).expect("nonzero file length"),
                    guest_start: source,
                    guest_len: GuestCodeLen::new(4).expect("nonzero guest length"),
                    source_words: words[..1].to_vec().into(),
                }],
            },
            Arc::new(FixtureStore(SharedLoadedTranslationUnit::new(
                manifest, base, lease,
            ))),
        )
        .expect("configure shared indirect source");

    let mut stack = vec![0_u8; 16 * 1024];
    let mut warm = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    warm.pc = source.raw();
    warm.x[1] = target.raw();
    warm.x[2] = source.raw();
    let source_prepared = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &warm)
        .expect("prepare shared indirect source miss");
    let source_exit = fixture
        .translator
        .enter_prepared::<false>(source_prepared, &mut warm)
        .expect("execute shared indirect source miss");
    assert!(matches!(
        source_exit.exit,
        NativeDsrExit::ResolveIndirect {
            source: observed_source,
            target: observed_target,
            ..
        } if observed_source == source && observed_target == target
    ));
    assert!(matches!(
        fixture
            .translator
            .finish_exit(&fixture.memory, &mut warm, source_prepared, source_exit,)
            .expect("publish private indirect target"),
        super::ThreadExit::Continue
    ));

    warm.pc = target.raw();
    let target_prepared = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &warm)
        .expect("prepare private indirect target miss");
    let target_exit = fixture
        .translator
        .enter_prepared::<false>(target_prepared, &mut warm)
        .expect("execute private indirect target miss");
    assert!(matches!(
        target_exit.exit,
        NativeDsrExit::ResolveIndirect {
            source: observed_source,
            target: observed_target,
            ..
        } if observed_source == target && observed_target == source
    ));
    assert!(matches!(
        fixture
            .translator
            .finish_exit(&fixture.memory, &mut warm, target_prepared, target_exit,)
            .expect("publish shared indirect source target"),
        super::ThreadExit::Continue
    ));

    let target_thread = unsafe { libc::pthread_self() };
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
    let (request_tx, request_rx) = std::sync::mpsc::channel::<usize>();
    let (delivered_tx, delivered_rx) = std::sync::mpsc::channel::<()>();
    let sender = std::thread::spawn(move || {
        while let Ok(signal_index) = request_rx.recv() {
            std::thread::sleep(std::time::Duration::from_millis(1));
            for _ in 0..(signal_index.wrapping_mul(911) % 4096) {
                std::hint::spin_loop();
            }
            assert_eq!(
                unsafe { libc::pthread_kill(target_thread, libc::SIGPIPE) },
                0
            );
            if delivered_tx.send(()).is_err() {
                break;
            }
        }
    });

    const SIGNAL_BOUND: usize = 64;
    for signal_index in 0..SIGNAL_BOUND {
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.pc = source.raw();
        snapshot.x[1] = target.raw();
        snapshot.x[2] = source.raw();
        snapshot.x[15] = 0x1515_1515_1515_1515;
        snapshot.x[16] = 0x1616_1616_1616_1616;
        snapshot.x[17] = 0x1717_1717_1717_1717;
        snapshot.x[30] = 0x3030_3030_3030_3030;
        snapshot.pstate = 0xa000_0000;
        let expected = snapshot;
        let prepared = fixture
            .translator
            .prepare_entry::<false>(&fixture.memory, &snapshot)
            .expect("prepare hot indirect authority-switch loop");
        request_tx
            .send(signal_index)
            .expect("request bounded indirect SIGPIPE");
        let entered = fixture
            .translator
            .enter_prepared::<false>(prepared, &mut snapshot)
            .expect("enter hot indirect authority-switch loop");
        delivered_rx
            .recv()
            .expect("observe bounded indirect SIGPIPE delivery");
        assert!(
            matches!(entered.exit, NativeDsrExit::Kick { .. }),
            "catalogued indirect authority switch became an entry kick: {:?}",
            entered.exit
        );
        assert!(matches!(
            fixture
                .translator
                .finish_exit(&fixture.memory, &mut snapshot, prepared, entered)
                .expect("recover indirect authority-switch kick"),
            super::ThreadExit::Kick
        ));
        assert!(
            snapshot.pc == source.raw() || snapshot.pc == target.raw(),
            "indirect recovery resumed outside an edge owner: 0x{:x}",
            snapshot.pc
        );
        assert_eq!(snapshot.x[15], expected.x[15]);
        assert_eq!(snapshot.x[16], expected.x[16]);
        assert_eq!(snapshot.x[17], expected.x[17]);
        assert_eq!(snapshot.x[30], expected.x[30]);
        assert_eq!(snapshot.pstate, expected.pstate);
    }

    drop(request_tx);
    sender.join().expect("join bounded indirect SIGPIPE sender");
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_set, std::ptr::null_mut()) },
        0
    );
}

struct DirectBindingLiveFixture {
    fixture: BiasedTranslatorFixture,
    source: GuestVa,
    target: GuestVa,
    source_cell: Option<carrick_dsr_aarch64::direct_binding::DirectBindingCellRef>,
    target_cell: Option<carrick_dsr_aarch64::direct_binding::DirectBindingCellRef>,
    _source_loaded: Option<carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit>,
    _target_loaded: Option<carrick_dsr_aarch64::shared_cache::SharedLoadedTranslationUnit>,
    _cache_session: carrick_native_darwin::aot_cache::ContainerCacheSession,
    stack: Vec<u8>,
}

impl DirectBindingLiveFixture {
    fn traverse(&mut self, guest: GuestVa) -> NativeDsrExit {
        let mut snapshot =
            seeded_snapshot(self.stack.as_mut_ptr() as u64 + self.stack.len() as u64);
        snapshot.pc = guest.raw();
        let prepared = self
            .fixture
            .translator
            .prepare_entry::<false>(&self.fixture.memory, &snapshot)
            .expect("prepare live direct-binding source");
        let entered = self
            .fixture
            .translator
            .enter_prepared::<false>(prepared, &mut snapshot)
            .expect("enter live direct-binding source");
        let observed = entered.exit;
        if matches!(observed, NativeDsrExit::ResolveDirect { .. }) {
            assert!(matches!(
                self.fixture
                    .translator
                    .finish_exit(&self.fixture.memory, &mut snapshot, prepared, entered)
                    .expect("finish live direct-binding miss"),
                super::ThreadExit::Continue
            ));
        }
        observed
    }

    fn traverse_source(&mut self) -> NativeDsrExit {
        self.traverse(self.source)
    }
}

fn direct_binding_live_fixture(
    source_shared: bool,
    target_shared: bool,
    cyclic: bool,
) -> DirectBindingLiveFixture {
    use carrick_dsr_aarch64::direct_binding::DirectBindingCellRef;
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, DirectBindingLayout, ExecutableIdentity, GuestCodeLen, ImageFileLen,
        ImageFileOffset, NativePageProfileIdentity, PendingTranslationUnit, PortableBlockCandidate,
        PublishOutcome, SharedExecutableSegment, SharedImageConfig, SourceFingerprint,
        TranslationUnitKey, TranslationUnitStore,
    };

    const PAGE_SIZE: u64 = 16 * 1024;
    let source_word = 0x1400_1000; // b +16 KiB
    let target_word = if cyclic {
        0x17ff_f000 // b -16 KiB
    } else {
        0xd400_0001 // svc #0
    };
    let source = GuestVa(0x20_0000_0000);
    let target = GuestVa(source.raw() + PAGE_SIZE);
    let mut fixture = biased_translator_fixture(&[source_word], source);
    fixture.memory.regions[1].guest_writable = false;
    fixture.memory.regions[1].default_prot =
        crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC;
    // SAFETY: `data_host` owns the second live writable fixture page.
    unsafe { (fixture.data_host.raw() as *mut u32).write(target_word) };
    fixture.translator.process.enable_direct_bindings_for_test();

    let source_generation = fixture
        .memory
        .dsr_generation_observation(source)
        .expect("observe live source generation")
        .expected();
    let target_generation = fixture
        .memory
        .dsr_generation_observation(target)
        .expect("observe live target generation")
        .expected();
    let source_plan = super::block::plan_block(&fixture.memory, source, source_generation, 256)
        .expect("plan live direct-binding source");
    let target_plan = super::block::plan_block(&fixture.memory, target, target_generation, 256)
        .expect("plan live direct-binding target");
    let source_artifact = super::emit::record_portable_block_artifact(
        &source_plan,
        0,
        super::emit::EmitAddressMode::Biased {
            host_bias: fixture.host_bias,
        },
        vec![source_word],
    )
    .expect("record live direct-binding source");
    let target_artifact = super::emit::record_portable_block_artifact(
        &target_plan,
        0,
        super::emit::EmitAddressMode::Biased {
            host_bias: fixture.host_bias,
        },
        vec![target_word],
    )
    .expect("record live direct-binding target");
    let executable = ExecutableIdentity::Digest([0xd1; 32]);
    let source_key = TranslationUnitKey::for_segment(
        executable.clone(),
        ImageFileOffset::new(0),
        ImageFileLen::new(4).expect("source file length"),
        source,
        GuestCodeLen::new(4).expect("source guest length"),
        SourceFingerprint::from_words(&[source_word]),
        NativePageProfileIdentity::Native16k,
        AddressModeIdentity::biased(fixture.host_bias),
    );
    let target_key = TranslationUnitKey::for_segment(
        executable.clone(),
        ImageFileOffset::new(4),
        ImageFileLen::new(4).expect("target file length"),
        target,
        GuestCodeLen::new(4).expect("target guest length"),
        SourceFingerprint::from_words(&[target_word]),
        NativePageProfileIdentity::Native16k,
        AddressModeIdentity::biased(fixture.host_bias),
    );
    let source_pending = PendingTranslationUnit::pack(
        source_key.clone(),
        vec![PortableBlockCandidate {
            guest_start: source,
            generation_binding: 0,
            requires_sensitive_metadata: false,
            template: source_artifact.template,
        }],
        DirectBindingLayout::SidecarV1,
    )
    .expect("pack live direct-binding source");
    let target_pending = PendingTranslationUnit::pack(
        target_key,
        vec![PortableBlockCandidate {
            guest_start: target,
            generation_binding: 0,
            requires_sensitive_metadata: false,
            template: target_artifact.template,
        }],
        if cyclic {
            DirectBindingLayout::SidecarV1
        } else {
            DirectBindingLayout::Disabled
        },
    )
    .expect("pack live direct-binding target");
    assert_eq!(source_pending.bindings.len(), 1);

    let cache_session = carrick_native_darwin::aot_cache::begin_container_cache()
        .expect("begin live sidecar cache");
    let store = Arc::new(carrick_native_darwin::aot_cache::ActiveContainerUnitStore);
    if source_shared {
        assert_eq!(
            store
                .publish(&source_pending)
                .expect("publish live direct-binding source"),
            PublishOutcome::Winner
        );
    }
    if target_shared {
        assert_eq!(
            store
                .publish(&target_pending)
                .expect("publish live direct-binding target"),
            PublishOutcome::Winner
        );
    }
    let source_loaded = if source_shared {
        Some(
            store
                .load(&source_key, &[source_word])
                .expect("load live direct-binding source")
                .expect("published live direct-binding source"),
        )
    } else {
        None
    };
    let source_cell = source_loaded
        .as_ref()
        .and_then(|loaded| loaded.binding_base)
        .map(|address| {
            // SAFETY: `_source_loaded` pins the writable mapped sidecar cell for
            // the lifetime of this fixture and all copied adapters.
            unsafe {
                DirectBindingCellRef::from_mapped_address(address)
                    .expect("adapt live direct-binding cell")
            }
        });
    let target_loaded = if target_shared && cyclic {
        Some(
            store
                .load(
                    &TranslationUnitKey::for_segment(
                        executable.clone(),
                        ImageFileOffset::new(4),
                        ImageFileLen::new(4).expect("target file length"),
                        target,
                        GuestCodeLen::new(4).expect("target guest length"),
                        SourceFingerprint::from_words(&[target_word]),
                        NativePageProfileIdentity::Native16k,
                        AddressModeIdentity::biased(fixture.host_bias),
                    ),
                    &[target_word],
                )
                .expect("load live cyclic target")
                .expect("published live cyclic target"),
        )
    } else {
        None
    };
    let target_cell = target_loaded
        .as_ref()
        .and_then(|loaded| loaded.binding_base)
        .map(|address| {
            // SAFETY: `_target_loaded` pins this mapped writable cell.
            unsafe {
                DirectBindingCellRef::from_mapped_address(address)
                    .expect("adapt live cyclic target cell")
            }
        });
    if let Some(cell) = source_cell {
        assert!(cell.load_acquire().is_null());
    }
    fixture
        .translator
        .process
        .configure_shared_image(
            SharedImageConfig {
                executable,
                page_profile: NativePageProfileIdentity::Native16k,
                address_mode: AddressModeIdentity::biased(fixture.host_bias),
                segments: vec![
                    SharedExecutableSegment {
                        file_offset: ImageFileOffset::new(0),
                        file_len: ImageFileLen::new(4).expect("source file length"),
                        guest_start: source,
                        guest_len: GuestCodeLen::new(4).expect("source guest length"),
                        source_words: vec![source_word].into(),
                    },
                    SharedExecutableSegment {
                        file_offset: ImageFileOffset::new(4),
                        file_len: ImageFileLen::new(4).expect("target file length"),
                        guest_start: target,
                        guest_len: GuestCodeLen::new(4).expect("target guest length"),
                        source_words: vec![target_word].into(),
                    },
                ],
            },
            store,
        )
        .expect("configure live direct-binding image");

    DirectBindingLiveFixture {
        fixture,
        source,
        target,
        source_cell,
        target_cell,
        _source_loaded: source_loaded,
        _target_loaded: target_loaded,
        _cache_session: cache_session,
        stack: vec![0_u8; 16 * 1024],
    }
}

#[test]
fn direct_binding_private_to_shared_switch_executes() {
    let mut fixture = direct_binding_live_fixture(false, true, false);
    assert!(matches!(
        fixture.traverse_source(),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Absent,
        } if source == fixture.source && target == fixture.target
    ));
    assert_eq!(
        fixture.traverse_source(),
        NativeDsrExit::Syscall {
            resume: GuestVa(fixture.target.raw() + 4),
        },
        "the private source's cached direct edge must install the shared target authority"
    );
}

#[test]
fn direct_binding_shared_to_shared_switch_executes() {
    let mut fixture = direct_binding_live_fixture(true, true, false);
    assert!(matches!(
        fixture.traverse_source(),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if source == fixture.source && target == fixture.target
    ));
    assert!(
        !fixture
            .source_cell
            .expect("shared source cell")
            .load_acquire()
            .is_null()
    );
    assert_eq!(
        fixture.traverse_source(),
        NativeDsrExit::Syscall {
            resume: GuestVa(fixture.target.raw() + 4),
        },
        "the sidecar hit must install the target shared unit's authority"
    );
}

#[test]
fn direct_binding_first_miss_then_hit_bypasses_gateway() {
    let mut fixture = direct_binding_live_fixture(true, false, false);
    let cell = fixture.source_cell.expect("shared source cell");
    assert!(cell.load_acquire().is_null());
    assert!(matches!(
        fixture.traverse_source(),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if source == fixture.source && target == fixture.target
    ));
    assert!(!cell.load_acquire().is_null());
    assert_eq!(
        fixture.traverse_source(),
        NativeDsrExit::Syscall {
            resume: GuestVa(fixture.target.raw() + 4),
        },
        "the second traversal must bypass the direct resolver gateway"
    );
}

fn direct_binding_recovery_for_cache_pc(
    fixture: &DirectBindingLiveFixture,
    cache_pc: GuestVa,
) -> Option<(super::emit::DirectBindingRecoveryPhase, usize)> {
    let cache_pc = usize::try_from(cache_pc.raw()).ok()?;
    let state = fixture.fixture.translator.process.state.read();
    state.published.iter().find_map(|block| {
        let offset = cache_pc.checked_sub(block.entry.host().raw())?;
        if offset >= block.len {
            return None;
        }
        let offset = u32::try_from(offset).ok()?;
        let sidecar_start = block
            .recovery
            .iter()
            .filter_map(|entry| {
                matches!(
                    entry.action,
                    super::emit::RecoveryAction::RestoreDirectBinding { .. }
                )
                .then_some(entry.cache.get())
            })
            .min()?;
        block
            .recovery
            .iter()
            .find(|entry| entry.cache.get() == offset)
            .and_then(|entry| match entry.action {
                super::emit::RecoveryAction::RestoreDirectBinding { phase, .. } => {
                    Some((phase, usize::try_from((offset - sidecar_start) / 4).ok()?))
                }
                _ => None,
            })
    })
}

fn direct_binding_phase_index(phase: super::emit::DirectBindingRecoveryPhase) -> usize {
    match phase {
        super::emit::DirectBindingRecoveryPhase::ScratchCapture => 0,
        super::emit::DirectBindingRecoveryPhase::CellAddress => 1,
        super::emit::DirectBindingRecoveryPhase::TargetAcquire => 2,
        super::emit::DirectBindingRecoveryPhase::AuthorityValidate => 3,
        super::emit::DirectBindingRecoveryPhase::AuthorityInstall => 4,
        super::emit::DirectBindingRecoveryPhase::ArchitecturalRestore => 5,
        super::emit::DirectBindingRecoveryPhase::FinalBranch => 6,
        super::emit::DirectBindingRecoveryPhase::MissExit => 7,
    }
}

#[derive(Clone, Copy, Debug)]
struct DirectBindingSigpipeRequest {
    iteration: usize,
}

#[derive(Clone, Copy, Debug)]
struct DirectBindingSigpipeCompletion {
    iteration: usize,
}

#[derive(Debug)]
enum DirectBindingSigpipeOutcome {
    Completed {
        kill_status: libc::c_int,
        completion_iteration: usize,
    },
    TimedOut {
        evidence: String,
    },
}

#[derive(Debug)]
struct DirectBindingSigpipeResult {
    iteration: usize,
    requested: bool,
    requested_generation: u64,
    acknowledged_generation: u64,
    outcome: DirectBindingSigpipeOutcome,
}

struct BoundNativeKickState<'a>(&'a super::super::NativeKickState);

impl Drop for BoundNativeKickState<'_> {
    fn drop(&mut self) {
        self.0.unbind_current();
    }
}

struct RestoreSignalMask(Option<libc::sigset_t>);

impl RestoreSignalMask {
    fn restore(&mut self) -> libc::c_int {
        let Some(original) = self.0.take() else {
            return 0;
        };
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) }
    }
}

impl Drop for RestoreSignalMask {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

fn capture_direct_binding_jitter_thread(
    mach_thread: mach2::mach_types::thread_act_t,
) -> Result<(u64, u64), String> {
    let suspended = SuspendedMachThread::suspend(mach_thread)?;
    let mut state = mach2::structs::arm_thread_state64_t::new();
    let mut count = mach2::structs::arm_thread_state64_t::count();
    let status = unsafe {
        mach2::thread_act::thread_get_state(
            mach_thread,
            mach2::thread_status::ARM_THREAD_STATE64,
            std::ptr::from_mut(&mut state).cast(),
            &mut count,
        )
    };
    suspended.resume()?;
    if status != mach2::kern_return::KERN_SUCCESS {
        return Err(format!("thread_get_state failed: {status}"));
    }
    Ok((state.__pc, state.__x[28]))
}

fn direct_binding_sigpipe_sample(
    fixture: &mut DirectBindingLiveFixture,
    request: &std::sync::mpsc::Sender<DirectBindingSigpipeRequest>,
    completion: &std::sync::mpsc::Sender<DirectBindingSigpipeCompletion>,
    result: &std::sync::mpsc::Receiver<DirectBindingSigpipeResult>,
    signal_index: usize,
) -> Option<(super::emit::DirectBindingRecoveryPhase, usize)> {
    let mut snapshot =
        seeded_snapshot(fixture.stack.as_mut_ptr() as u64 + fixture.stack.len() as u64);
    snapshot.pc = fixture.source.raw();
    snapshot.x[15] = 0x1515_1515_1515_1515;
    snapshot.x[16] = 0x1616_1616_1616_1616;
    snapshot.x[17] = 0x1717_1717_1717_1717;
    snapshot.x[30] = 0x3030_3030_3030_3030;
    snapshot.pstate = 0xa000_0000;
    let expected = snapshot;
    let prepared = fixture
        .fixture
        .translator
        .prepare_entry::<false>(&fixture.fixture.memory, &snapshot)
        .expect("prepare jittered sidecar entry");
    request
        .send(DirectBindingSigpipeRequest {
            iteration: signal_index,
        })
        .expect("request bounded SIGPIPE");
    let entered = fixture
        .fixture
        .translator
        .enter_prepared::<false>(prepared, &mut snapshot)
        .map_err(|error| format!("enter jittered sidecar loop: {error}"));
    completion
        .send(DirectBindingSigpipeCompletion {
            iteration: signal_index,
        })
        .expect("publish jittered sidecar completion");
    let sender_result = result
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("observe bounded SIGPIPE sender result");
    let entered = entered.expect("enter jittered sidecar loop");
    let (phase, unexpected_exit) = match entered.exit {
        NativeDsrExit::Kick { resume, .. } => {
            (direct_binding_recovery_for_cache_pc(fixture, resume), None)
        }
        NativeDsrExit::KickAtEntry { .. } => (None, None),
        other => (None, Some(other)),
    };
    let finished = fixture.fixture.translator.finish_exit(
        &fixture.fixture.memory,
        &mut snapshot,
        prepared,
        entered,
    );
    let timeout_evidence = match &sender_result.outcome {
        DirectBindingSigpipeOutcome::TimedOut { evidence } => Some(evidence.as_str()),
        DirectBindingSigpipeOutcome::Completed { .. } => None,
    };
    assert!(
        timeout_evidence.is_none(),
        "iteration {signal_index} timed out after its requested kick; \
         sender={timeout_evidence:?}; finish_exit={finished:?}"
    );
    if let DirectBindingSigpipeOutcome::Completed {
        kill_status,
        completion_iteration,
    } = sender_result.outcome
    {
        assert_eq!(sender_result.iteration, signal_index);
        assert_eq!(completion_iteration, signal_index);
        assert!(
            sender_result.requested,
            "kick request must be newly pending"
        );
        assert_eq!(kill_status, 0, "pthread_kill(SIGPIPE)");
        assert_eq!(
            sender_result.requested_generation, sender_result.acknowledged_generation,
            "iteration {signal_index} completed without acknowledging its requested kick"
        );
    }
    assert!(
        unexpected_exit.is_none(),
        "jittered sidecar must exit through a kick: {unexpected_exit:?}"
    );
    assert!(matches!(
        finished.expect("finish jittered sidecar kick"),
        super::ThreadExit::Kick
    ));
    assert!(
        matches!(snapshot.pc, pc if pc == fixture.source.raw() || pc == fixture.target.raw()),
        "recovery must resume at a guest edge owner, not inside the sidecar: 0x{:x}",
        snapshot.pc
    );
    assert_eq!(snapshot.x[15], expected.x[15]);
    assert_eq!(snapshot.x[16], expected.x[16]);
    assert_eq!(
        snapshot.x[17], expected.x[17],
        "jittered recovery x17 mismatch for sampled phase {phase:?}"
    );
    assert_eq!(snapshot.x[30], expected.x[30]);
    // A requested kick delivered in the host window can surface Darwin's
    // host-only PSTATE.D mask; the guest architectural contract is exact NZCV.
    assert_eq!(
        snapshot.pstate & 0xf000_0000,
        expected.pstate & 0xf000_0000,
        "iteration {signal_index} phase {phase:?}"
    );
    phase
}

#[test]
fn direct_binding_jittered_sigpipe_stress_preserves_state() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let mut fixture = direct_binding_live_fixture(true, true, true);
    assert!(matches!(
        fixture.traverse(fixture.source),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if source == fixture.source && target == fixture.target
    ));
    assert!(matches!(
        fixture.traverse(fixture.target),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if source == fixture.target && target == fixture.source
    ));
    let source_cell = fixture.source_cell.expect("cyclic source cell");
    let target_cell = fixture.target_cell.expect("cyclic target cell");
    assert!(!source_cell.load_acquire().is_null());
    assert!(!target_cell.load_acquire().is_null());

    let kick_state =
        Arc::new(super::super::NativeKickState::new().expect("create jitter kick state"));
    kick_state
        .bind_current()
        .expect("bind jitter kick state to target");
    let kick_binding = BoundNativeKickState(&kick_state);
    let target_thread = unsafe { libc::pthread_self() };
    let target_mach_thread = unsafe { libc::pthread_mach_thread_np(target_thread) };
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
    let mut signal_mask = RestoreSignalMask(Some(old_set));
    let (request_tx, request_rx) = std::sync::mpsc::channel::<DirectBindingSigpipeRequest>();
    let (completion_tx, completion_rx) =
        std::sync::mpsc::channel::<DirectBindingSigpipeCompletion>();
    let (result_tx, result_rx) = std::sync::mpsc::channel::<DirectBindingSigpipeResult>();
    let (sender_done_tx, sender_done_rx) = std::sync::mpsc::channel::<()>();
    let sender_kick_state = Arc::clone(&kick_state);
    let sender = std::thread::spawn(move || {
        while let Ok(request) = request_rx.recv() {
            let jitter = request.iteration.wrapping_mul(997);
            std::thread::sleep(std::time::Duration::from_micros(25 + (jitter % 476) as u64));
            for _ in 0..(jitter % 65_536) {
                std::hint::spin_loop();
            }

            let requested = sender_kick_state.request();
            let requested_generation = sender_kick_state.requested_generation();
            let kill_status = unsafe { libc::pthread_kill(target_thread, libc::SIGPIPE) };
            let completion = completion_rx.recv_timeout(std::time::Duration::from_secs(1));
            let outcome = match completion {
                Ok(completion) => DirectBindingSigpipeOutcome::Completed {
                    kill_status,
                    completion_iteration: completion.iteration,
                },
                Err(wait) => {
                    let (pc, x28, capture_error) =
                        match capture_direct_binding_jitter_thread(target_mach_thread) {
                            Ok((pc, x28)) => (Some(pc), Some(x28), None),
                            Err(error) => (None, None, Some(error)),
                        };
                    let requested_at_timeout = sender_kick_state.requested_generation();
                    let acknowledged_at_timeout = sender_kick_state.acknowledged_generation();
                    let rescue_requested = if requested_at_timeout == acknowledged_at_timeout {
                        sender_kick_state.request()
                    } else {
                        false
                    };
                    let rescue_generation = sender_kick_state.requested_generation();
                    let rescue_kill_status =
                        unsafe { libc::pthread_kill(target_thread, libc::SIGPIPE) };
                    let completion_after_rescue =
                        match completion_rx.recv_timeout(std::time::Duration::from_secs(1)) {
                            Ok(completion) => Ok(completion.iteration),
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                Err("timed out after rescue")
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                Err("completion channel disconnected after rescue")
                            }
                        };
                    let wait_error = match wait {
                        std::sync::mpsc::RecvTimeoutError::Timeout => "timed out before rescue",
                        std::sync::mpsc::RecvTimeoutError::Disconnected => {
                            "completion channel disconnected before rescue"
                        }
                    };
                    let final_requested = sender_kick_state.requested_generation();
                    let final_acknowledged = sender_kick_state.acknowledged_generation();
                    DirectBindingSigpipeOutcome::TimedOut {
                        evidence: format!(
                            "first_kill={kill_status} wait={wait_error} pc={pc:#x?} \
                             x28={x28:#x?} capture_error={capture_error:?} \
                             timeout_req={requested_at_timeout} \
                             timeout_ack={acknowledged_at_timeout} \
                             rescue_requested={rescue_requested} \
                             rescue_generation={rescue_generation} \
                             rescue_kill={rescue_kill_status} \
                             completion_after_rescue={completion_after_rescue:?} \
                             final_req={final_requested} final_ack={final_acknowledged}"
                        ),
                    }
                }
            };
            let sender_result = DirectBindingSigpipeResult {
                iteration: request.iteration,
                requested,
                requested_generation,
                acknowledged_generation: sender_kick_state.acknowledged_generation(),
                outcome,
            };
            if result_tx.send(sender_result).is_err() {
                break;
            }
        }
        let _ = sender_done_tx.send(());
    });

    const SIGNAL_BOUND: usize = 10_000;
    let mut covered = [false; 8];
    let mut recovered_words = [0_u32; 64];
    for signal_index in 0..SIGNAL_BOUND {
        if let Some((phase, word)) = direct_binding_sigpipe_sample(
            &mut fixture,
            &request_tx,
            &completion_tx,
            &result_rx,
            signal_index,
        ) {
            covered[direct_binding_phase_index(phase)] = true;
            recovered_words[word] = recovered_words[word].saturating_add(1);
        }
    }

    drop(request_tx);
    sender_done_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("bounded SIGPIPE sender shutdown");
    drop(sender);
    drop(kick_binding);
    assert_eq!(signal_mask.restore(), 0);
    eprintln!(
        "direct-binding jitter coverage: covered={covered:?} \
         recovered_words={recovered_words:?} signals={SIGNAL_BOUND}"
    );
}

struct SuspendedMachThread {
    port: mach2::mach_types::thread_act_t,
    active: bool,
}

impl SuspendedMachThread {
    fn suspend(port: mach2::mach_types::thread_act_t) -> Result<Self, String> {
        let status = unsafe { mach2::thread_act::thread_suspend(port) };
        if status != mach2::kern_return::KERN_SUCCESS {
            return Err(format!("thread_suspend failed: {status}"));
        }
        Ok(Self { port, active: true })
    }

    fn resume(mut self) -> Result<(), String> {
        let status = unsafe { mach2::thread_act::thread_resume(self.port) };
        self.active = false;
        if status != mach2::kern_return::KERN_SUCCESS {
            return Err(format!("thread_resume failed: {status}"));
        }
        Ok(())
    }
}

impl Drop for SuspendedMachThread {
    fn drop(&mut self) {
        if self.active {
            let _ = unsafe { mach2::thread_act::thread_resume(self.port) };
        }
    }
}

fn direct_binding_sidecar_start(fixture: &DirectBindingLiveFixture, guest: GuestVa) -> usize {
    let state = fixture.fixture.translator.process.state.read();
    let block = state
        .published
        .iter()
        .find(|block| {
            state
                .blocks
                .get(&(guest, CodeGeneration::INITIAL))
                .is_some_and(|entry| *entry == block.entry)
        })
        .expect("published direct-binding block");
    let recovery_start = block
        .recovery
        .iter()
        .filter_map(|entry| {
            matches!(
                entry.action,
                super::emit::RecoveryAction::RestoreDirectBinding { .. }
            )
            .then_some(entry.cache.get())
        })
        .min()
        .expect("direct-binding recovery start");
    block
        .entry
        .host()
        .raw()
        .checked_add(recovery_start as usize)
        .expect("direct-binding sidecar address")
}

fn cmp_nzcv(lhs: u64, rhs: u64) -> u32 {
    let result = lhs.wrapping_sub(rhs);
    let negative = u32::from(result >> 63 != 0) << 31;
    let zero = u32::from(result == 0) << 30;
    let carry = u32::from(lhs >= rhs) << 29;
    let overflow = u32::from(((lhs ^ rhs) & (lhs ^ result)) >> 63 != 0) << 28;
    negative | zero | carry | overflow
}

#[derive(Clone, Copy, Debug)]
enum ForcedDirectBindingSite {
    ScratchCapture,
    CellAddress,
    TargetAcquire,
    AuthorityValidate,
    AuthorityInstall,
    ArchitecturalRestore,
    FinalBranch,
    MissExit,
    BlockEntry,
}

impl ForcedDirectBindingSite {
    const fn phase_and_word(self) -> Option<(super::emit::DirectBindingRecoveryPhase, usize)> {
        use super::emit::DirectBindingRecoveryPhase;

        match self {
            Self::ScratchCapture => Some((DirectBindingRecoveryPhase::ScratchCapture, 0)),
            Self::CellAddress => Some((DirectBindingRecoveryPhase::CellAddress, 5)),
            Self::TargetAcquire => Some((DirectBindingRecoveryPhase::TargetAcquire, 10)),
            Self::AuthorityValidate => Some((DirectBindingRecoveryPhase::AuthorityValidate, 14)),
            Self::AuthorityInstall => Some((DirectBindingRecoveryPhase::AuthorityInstall, 20)),
            Self::ArchitecturalRestore => {
                Some((DirectBindingRecoveryPhase::ArchitecturalRestore, 25))
            }
            Self::FinalBranch => Some((DirectBindingRecoveryPhase::FinalBranch, 26)),
            Self::MissExit => Some((DirectBindingRecoveryPhase::MissExit, 27)),
            Self::BlockEntry => None,
        }
    }

    const fn retains_captured_nzcv_in_physical_x16(self) -> bool {
        // Word 3 captures NZCV in physical x16 and word 4 only stores it.
        // These forced pre-instruction sites have not overwritten x16 since.
        matches!(
            self,
            Self::CellAddress | Self::TargetAcquire | Self::MissExit
        )
    }
}

fn direct_binding_cell_addresses(fixture: &DirectBindingLiveFixture) -> [usize; 2] {
    [
        fixture
            ._source_loaded
            .as_ref()
            .and_then(|loaded| loaded.binding_base)
            .expect("source binding cell")
            .get(),
        fixture
            ._target_loaded
            .as_ref()
            .and_then(|loaded| loaded.binding_base)
            .expect("target binding cell")
            .get(),
    ]
}

fn force_direct_binding_sigpipe(
    pthread: libc::pthread_t,
    mach_thread: mach2::mach_types::thread_act_t,
    sidecar_starts: [usize; 2],
    binding_cells: [usize; 2],
    site: ForcedDirectBindingSite,
    remove_catalog: bool,
) -> Result<usize, String> {
    const VALIDATE_WORD: usize = 14;
    const ENTRY_OFFSET: usize = 1072;
    const SAVED_NZCV_OFFSET: usize = 936;
    const SAVED_X16_OFFSET: usize = 1120;
    const SAVED_X17_OFFSET: usize = 1128;
    const SAVED_X15_OFFSET: usize = 1160;
    const SAVED_X30_OFFSET: usize = 1168;
    const GENERATION_BINDINGS_OFFSET: usize = 1264;
    const CACHE_START_OFFSET: usize = 1176;
    const CACHE_END_OFFSET: usize = 1184;
    const DIRECT_BINDING_TARGET_OFFSET: usize = 1296;
    const EXECUTABLE_RANGE_CATALOG_OFFSET: usize = 1304;

    let fail_with_live_kick = |error: String| {
        let _ = unsafe { libc::pthread_kill(pthread, libc::SIGPIPE) };
        Err(error)
    };
    for attempt in 0_usize..100_000 {
        let suspended = match SuspendedMachThread::suspend(mach_thread) {
            Ok(suspended) => suspended,
            Err(error) => return fail_with_live_kick(error),
        };
        let mut state = mach2::structs::arm_thread_state64_t::new();
        let mut count = mach2::structs::arm_thread_state64_t::count();
        let get_status = unsafe {
            mach2::thread_act::thread_get_state(
                mach_thread,
                mach2::thread_status::ARM_THREAD_STATE64,
                std::ptr::from_mut(&mut state).cast(),
                &mut count,
            )
        };
        if get_status != mach2::kern_return::KERN_SUCCESS {
            suspended.resume()?;
            return fail_with_live_kick(format!("thread_get_state failed: {get_status}"));
        }
        let Some((sidecar_index, sidecar_start)) = sidecar_starts
            .into_iter()
            .enumerate()
            .find(|(_, start)| state.__pc as usize == start + VALIDATE_WORD * 4)
        else {
            suspended.resume()?;
            if attempt.is_multiple_of(256) {
                std::thread::yield_now();
            }
            continue;
        };

        let descriptor =
            state.__x[17] as *const carrick_dsr_aarch64::direct_binding::DirectBindingTargetPrefix;
        let Some(prefix) = (unsafe { descriptor.as_ref() }) else {
            suspended.resume()?;
            return fail_with_live_kick(
                "word 14 did not retain a live direct-binding descriptor".to_string(),
            );
        };
        if state.__x[15] != prefix.cache_start
            || state.__lr != prefix.cache_end
            || state.__x[16] != prefix.target_cache_pc
            || state.__x[16] < state.__x[15]
            || state.__x[16] >= state.__lr
        {
            suspended.resume()?;
            return fail_with_live_kick(
                "word 14 register state did not match validated target authority".to_string(),
            );
        }

        let context = state.__x[28] as usize;
        if context == 0 {
            suspended.resume()?;
            return fail_with_live_kick("word 14 lost the live DSR context".to_string());
        }
        let context_u64 = |offset: usize| unsafe {
            (context.checked_add(offset).expect("context field") as *const u64).read()
        };
        let write_context_u64 = |offset: usize, value: u64| unsafe {
            (context.checked_add(offset).expect("context field") as *mut u64).write(value);
        };
        let saved_x15 = context_u64(SAVED_X15_OFFSET);
        let saved_x16 = context_u64(SAVED_X16_OFFSET);
        let saved_x17 = context_u64(SAVED_X17_OFFSET);
        let saved_x30 = context_u64(SAVED_X30_OFFSET);
        let saved_nzcv = context_u64(SAVED_NZCV_OFFSET);
        let binding_cell = binding_cells[sidecar_index] as u64;

        let restore_original_registers = |state: &mut mach2::structs::arm_thread_state64_t| {
            state.__x[15] = saved_x15;
            state.__x[16] = saved_x16;
            state.__x[17] = saved_x17;
            state.__lr = saved_x30;
            state.__cpsr = saved_nzcv as u32;
        };
        let emulate_authority_install = |state: &mut mach2::structs::arm_thread_state64_t| {
            // Emulate words 14 through 19 from the live validated state:
            // the two authority checks, generation-pointer install, and
            // target cache-range install.
            state.__cpsr = (state.__cpsr & 0x0fff_ffff) | cmp_nzcv(state.__x[16], state.__lr);
            state.__x[17] = prefix.generation_bindings;
            write_context_u64(GENERATION_BINDINGS_OFFSET, state.__x[17]);
            state.__x[17] = context
                .checked_add(CACHE_START_OFFSET)
                .expect("context cache range") as u64;
            write_context_u64(CACHE_START_OFFSET, state.__x[15]);
            write_context_u64(CACHE_END_OFFSET, state.__lr);
        };

        let forced_pc = match site {
            ForcedDirectBindingSite::ScratchCapture => {
                restore_original_registers(&mut state);
                write_context_u64(DIRECT_BINDING_TARGET_OFFSET, 0);
                sidecar_start
            }
            ForcedDirectBindingSite::CellAddress => {
                restore_original_registers(&mut state);
                state.__x[16] = saved_nzcv;
                write_context_u64(DIRECT_BINDING_TARGET_OFFSET, 0);
                sidecar_start
                    .checked_add(5 * 4)
                    .expect("cell-address recovery PC")
            }
            ForcedDirectBindingSite::TargetAcquire => {
                restore_original_registers(&mut state);
                state.__x[16] = saved_nzcv;
                state.__x[15] = binding_cell;
                state.__x[17] = descriptor as usize as u64;
                write_context_u64(DIRECT_BINDING_TARGET_OFFSET, state.__x[17]);
                sidecar_start
                    .checked_add(10 * 4)
                    .expect("target-acquire recovery PC")
            }
            ForcedDirectBindingSite::AuthorityValidate => sidecar_start
                .checked_add(VALIDATE_WORD * 4)
                .expect("authority-validation recovery PC"),
            ForcedDirectBindingSite::AuthorityInstall => {
                emulate_authority_install(&mut state);
                sidecar_start
                    .checked_add(20 * 4)
                    .expect("authority-install recovery PC")
            }
            ForcedDirectBindingSite::ArchitecturalRestore
            | ForcedDirectBindingSite::FinalBranch
            | ForcedDirectBindingSite::BlockEntry => {
                emulate_authority_install(&mut state);
                // Word 20 commits the target cache PC. Words 21 through 24
                // then restore NZCV, x15, x30, and x16.
                write_context_u64(ENTRY_OFFSET, prefix.target_cache_pc);
                restore_original_registers(&mut state);
                state.__x[17] = context
                    .checked_add(CACHE_START_OFFSET)
                    .expect("context cache range") as u64;
                match site {
                    ForcedDirectBindingSite::ArchitecturalRestore => sidecar_start
                        .checked_add(25 * 4)
                        .expect("architectural-restore recovery PC"),
                    ForcedDirectBindingSite::FinalBranch => {
                        state.__x[17] = prefix.target_cache_pc;
                        sidecar_start
                            .checked_add(26 * 4)
                            .expect("final-branch recovery PC")
                    }
                    ForcedDirectBindingSite::BlockEntry => {
                        state.__x[17] = prefix.target_cache_pc;
                        usize::try_from(prefix.target_cache_pc)
                            .map_err(|_| "target block entry does not fit usize".to_string())?
                    }
                    _ => unreachable!("outer match restricts authority-restored sites"),
                }
            }
            ForcedDirectBindingSite::MissExit => {
                restore_original_registers(&mut state);
                state.__x[16] = saved_nzcv;
                state.__x[15] = binding_cell;
                state.__x[17] = 0;
                write_context_u64(DIRECT_BINDING_TARGET_OFFSET, 0);
                sidecar_start
                    .checked_add(27 * 4)
                    .expect("miss-exit recovery PC")
            }
        };
        if site.retains_captured_nzcv_in_physical_x16() && state.__x[16] != saved_nzcv {
            suspended.resume()?;
            return fail_with_live_kick(format!(
                "{site:?} forced pre-instruction x16 was 0x{:x}, expected captured NZCV 0x{saved_nzcv:x}",
                state.__x[16]
            ));
        }
        if remove_catalog {
            unsafe {
                (context
                    .checked_add(EXECUTABLE_RANGE_CATALOG_OFFSET)
                    .expect("context executable catalog") as *mut usize)
                    .write(0);
            }
        }
        state.__pc = forced_pc as u64;
        let set_status = unsafe {
            mach2::thread_act::thread_set_state(
                mach_thread,
                mach2::thread_status::ARM_THREAD_STATE64,
                std::ptr::from_mut(&mut state).cast(),
                count,
            )
        };
        if set_status != mach2::kern_return::KERN_SUCCESS {
            suspended.resume()?;
            return fail_with_live_kick(format!("thread_set_state failed: {set_status}"));
        }
        let kill_status = unsafe { libc::pthread_kill(pthread, libc::SIGPIPE) };
        suspended.resume()?;
        if kill_status != 0 {
            return Err(format!("pthread_kill(SIGPIPE) failed: {kill_status}"));
        }
        return Ok(forced_pc);
    }
    fail_with_live_kick("could not suspend the live sidecar at word 14".to_string())
}

#[test]
fn direct_binding_forced_sigpipe_recovers_every_phase_and_block_entry() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let mut fixture = direct_binding_live_fixture(true, true, true);
    assert!(matches!(
        fixture.traverse(fixture.source),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if source == fixture.source && target == fixture.target
    ));
    assert!(matches!(
        fixture.traverse(fixture.target),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if source == fixture.target && target == fixture.source
    ));
    let sidecar_starts = [
        direct_binding_sidecar_start(&fixture, fixture.source),
        direct_binding_sidecar_start(&fixture, fixture.target),
    ];
    let binding_cells = direct_binding_cell_addresses(&fixture);
    let pthread = unsafe { libc::pthread_self() };
    let mach_thread = unsafe { libc::pthread_mach_thread_np(pthread) };
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

    let sites = [
        ForcedDirectBindingSite::ScratchCapture,
        ForcedDirectBindingSite::CellAddress,
        ForcedDirectBindingSite::TargetAcquire,
        ForcedDirectBindingSite::AuthorityValidate,
        ForcedDirectBindingSite::AuthorityInstall,
        ForcedDirectBindingSite::ArchitecturalRestore,
        ForcedDirectBindingSite::FinalBranch,
        ForcedDirectBindingSite::MissExit,
        ForcedDirectBindingSite::BlockEntry,
    ];
    let mut covered = [false; 8];
    for site in sites {
        let mut snapshot =
            seeded_snapshot(fixture.stack.as_mut_ptr() as u64 + fixture.stack.len() as u64);
        snapshot.pc = fixture.source.raw();
        snapshot.x[15] = 0x1515_1515_1515_1515;
        snapshot.x[16] = 0x1616_1616_1616_1616;
        snapshot.x[17] = 0x1717_1717_1717_1717;
        snapshot.x[30] = 0x3030_3030_3030_3030;
        snapshot.pstate = 0xa000_0000;
        let expected = snapshot;
        let prepared = fixture
            .fixture
            .translator
            .prepare_entry::<false>(&fixture.fixture.memory, &snapshot)
            .expect("prepare forced sidecar entry");
        let sender = std::thread::spawn(move || {
            force_direct_binding_sigpipe(
                pthread,
                mach_thread,
                sidecar_starts,
                binding_cells,
                site,
                false,
            )
        });
        let entered = fixture
            .fixture
            .translator
            .enter_prepared::<false>(prepared, &mut snapshot)
            .expect("enter forced sidecar loop");
        let forced_pc = sender
            .join()
            .expect("join forced sidecar sender")
            .unwrap_or_else(|error| panic!("force live {site:?} SIGPIPE: {error}"));
        let NativeDsrExit::Kick { resume, .. } = entered.exit else {
            panic!(
                "forced {site:?} source PC must be an ordinary kick: {:?}",
                entered.exit
            );
        };
        assert_eq!(resume.raw(), forced_pc as u64, "{site:?}: interrupted PC");
        if let Some((phase, word)) = site.phase_and_word() {
            assert_eq!(
                direct_binding_recovery_for_cache_pc(&fixture, resume),
                Some((phase, word)),
                "{site:?}: typed recovery point"
            );
            covered[direct_binding_phase_index(phase)] = true;
        } else {
            assert_eq!(
                direct_binding_recovery_for_cache_pc(&fixture, resume),
                None,
                "block entry is outside the direct-binding sidecar"
            );
        }
        assert!(matches!(
            fixture
                .fixture
                .translator
                .finish_exit(&fixture.fixture.memory, &mut snapshot, prepared, entered)
                .expect("finish forced sidecar kick"),
            super::ThreadExit::Kick
        ));
        assert!(
            snapshot.pc == fixture.source.raw() || snapshot.pc == fixture.target.raw(),
            "{site:?}: recovery resumed outside an edge owner: 0x{:x}",
            snapshot.pc
        );
        assert_eq!(snapshot.x[15], expected.x[15], "{site:?}: x15");
        assert_eq!(snapshot.x[16], expected.x[16], "{site:?}: x16");
        assert_eq!(snapshot.x[17], expected.x[17], "{site:?}: x17");
        assert_eq!(snapshot.x[30], expected.x[30], "{site:?}: x30");
        assert_eq!(snapshot.pstate, expected.pstate, "{site:?}: NZCV");
    }
    assert_eq!(
        covered, [true; 8],
        "every direct-binding recovery phase must be forced"
    );

    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_set, std::ptr::null_mut()) },
        0
    );
}

#[test]
fn direct_binding_forced_word20_sigpipe_discriminates_catalog() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let mut fixture = direct_binding_live_fixture(true, true, true);
    assert!(matches!(
        fixture.traverse(fixture.source),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if source == fixture.source && target == fixture.target
    ));
    assert!(matches!(
        fixture.traverse(fixture.target),
        NativeDsrExit::ResolveDirect {
            source,
            target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if source == fixture.target && target == fixture.source
    ));
    let sidecar_starts = [
        direct_binding_sidecar_start(&fixture, fixture.source),
        direct_binding_sidecar_start(&fixture, fixture.target),
    ];
    let binding_cells = direct_binding_cell_addresses(&fixture);
    let pthread = unsafe { libc::pthread_self() };
    let mach_thread = unsafe { libc::pthread_mach_thread_np(pthread) };
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

    for remove_catalog in [true, false] {
        let mut snapshot =
            seeded_snapshot(fixture.stack.as_mut_ptr() as u64 + fixture.stack.len() as u64);
        snapshot.pc = fixture.source.raw();
        snapshot.x[15] = 0x1515_1515_1515_1515;
        snapshot.x[16] = 0x1616_1616_1616_1616;
        snapshot.x[17] = 0x1717_1717_1717_1717;
        snapshot.x[30] = 0x3030_3030_3030_3030;
        snapshot.pstate = 0xa000_0000;
        let expected = snapshot;
        let prepared = fixture
            .fixture
            .translator
            .prepare_entry::<false>(&fixture.fixture.memory, &snapshot)
            .expect("prepare forced word-20 sidecar entry");
        let sender = std::thread::spawn(move || {
            force_direct_binding_sigpipe(
                pthread,
                mach_thread,
                sidecar_starts,
                binding_cells,
                ForcedDirectBindingSite::AuthorityInstall,
                remove_catalog,
            )
        });
        let entered = fixture
            .fixture
            .translator
            .enter_prepared::<false>(prepared, &mut snapshot)
            .expect("enter forced word-20 sidecar loop");
        let forced_pc = sender
            .join()
            .expect("join forced word-20 sender")
            .expect("force live word-20 SIGPIPE");

        if remove_catalog {
            assert!(
                matches!(entered.exit, NativeDsrExit::KickAtEntry { .. }),
                "removing source range from the catalog must reproduce the classification red: {:?}",
                entered.exit
            );
            eprintln!(
                "forced direct-binding word 20 pc=0x{forced_pc:x} \
                 catalog=absent exit=KickAtEntry"
            );
        } else {
            let NativeDsrExit::Kick { resume, .. } = entered.exit else {
                panic!(
                    "catalogued word-20 source PC must be an ordinary kick: {:?}",
                    entered.exit
                );
            };
            assert_eq!(resume.raw(), forced_pc as u64);
            assert_eq!(
                direct_binding_recovery_for_cache_pc(&fixture, resume),
                Some((
                    super::emit::DirectBindingRecoveryPhase::AuthorityInstall,
                    20,
                ))
            );
            eprintln!(
                "forced direct-binding word 20 pc=0x{forced_pc:x} \
                 catalog=present exit=Kick phase=AuthorityInstall"
            );
        }
        assert!(matches!(
            fixture
                .fixture
                .translator
                .finish_exit(&fixture.fixture.memory, &mut snapshot, prepared, entered)
                .expect("finish forced word-20 sidecar kick"),
            super::ThreadExit::Kick
        ));
        assert!(
            snapshot.pc == fixture.source.raw() || snapshot.pc == fixture.target.raw(),
            "forced recovery resumed outside an edge owner: 0x{:x}",
            snapshot.pc
        );
        assert_eq!(snapshot.x[15], expected.x[15]);
        assert_eq!(snapshot.x[16], expected.x[16]);
        assert_eq!(snapshot.x[17], expected.x[17]);
        assert_eq!(snapshot.x[30], expected.x[30]);
        assert_eq!(snapshot.pstate, expected.pstate);
    }

    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_set, std::ptr::null_mut()) },
        0
    );
}

#[test]
fn direct_binding_generation_change_clears_and_rebinds() {
    use carrick_dsr_aarch64::direct_binding::DirectBindingCellRef;
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, DirectBindingLayout, ExecutableIdentity, GuestCodeLen, ImageFileLen,
        ImageFileOffset, NativePageProfileIdentity, PendingTranslationUnit, PortableBlockCandidate,
        SharedExecutableSegment, SharedImageConfig, SourceFingerprint, TranslationUnitKey,
        TranslationUnitStore,
    };

    const PAGE_SIZE: u64 = 16 * 1024;
    let source_word = 0x1400_1000; // b +16 KiB
    let source = GuestVa(0x20_0000_0000);
    let target = GuestVa(source.raw() + PAGE_SIZE);
    let mut fixture = biased_translator_fixture(&[source_word], source);
    fixture.memory.regions[1].guest_writable = false;
    fixture.memory.regions[1].default_prot =
        crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC;
    // SAFETY: `data_host` owns the second live writable fixture page.
    unsafe { (fixture.data_host.raw() as *mut u32).write(0xd400_0001) };
    fixture.translator.process.enable_direct_bindings_for_test();

    let source_generation = fixture
        .memory
        .dsr_generation_observation(source)
        .expect("observe source generation")
        .expected();
    let source_plan = super::block::plan_block(&fixture.memory, source, source_generation, 256)
        .expect("plan direct source");
    let source_artifact = super::emit::record_portable_block_artifact(
        &source_plan,
        0,
        super::emit::EmitAddressMode::Biased {
            host_bias: fixture.host_bias,
        },
        vec![source_word],
    )
    .expect("record direct source");
    let executable = ExecutableIdentity::Digest([0xa5; 32]);
    let key = TranslationUnitKey::for_segment(
        executable.clone(),
        ImageFileOffset::new(0),
        ImageFileLen::new(4).expect("source file length"),
        source,
        GuestCodeLen::new(4).expect("source guest length"),
        SourceFingerprint::from_words(&[source_word]),
        NativePageProfileIdentity::Native16k,
        AddressModeIdentity::biased(fixture.host_bias),
    );
    let pending = PendingTranslationUnit::pack(
        key.clone(),
        vec![PortableBlockCandidate {
            guest_start: source,
            generation_binding: 0,
            requires_sensitive_metadata: false,
            template: source_artifact.template,
        }],
        DirectBindingLayout::SidecarV1,
    )
    .expect("pack direct-binding sidecar");
    assert_eq!(pending.bindings.len(), 1);

    let _cache_session =
        carrick_native_darwin::aot_cache::begin_container_cache().expect("begin container cache");
    let store = Arc::new(carrick_native_darwin::aot_cache::ActiveContainerUnitStore);
    assert_eq!(
        store.publish(&pending).expect("publish sidecar unit"),
        carrick_dsr_aarch64::shared_cache::PublishOutcome::Winner,
    );
    let loaded = store
        .load(&key, &[source_word])
        .expect("load sidecar unit")
        .expect("published sidecar unit");
    let binding_base = loaded.binding_base.expect("SidecarV1 binding base");
    // SAFETY: `loaded` pins the dylib and its writable binding cell until the
    // final traversal and all acquired loads below have completed.
    let cell = unsafe {
        DirectBindingCellRef::from_mapped_address(binding_base).expect("loaded sidecar cell")
    };
    assert!(cell.load_acquire().is_null());

    fixture
        .translator
        .process
        .configure_shared_image(
            SharedImageConfig {
                executable,
                page_profile: NativePageProfileIdentity::Native16k,
                address_mode: AddressModeIdentity::biased(fixture.host_bias),
                segments: vec![SharedExecutableSegment {
                    file_offset: ImageFileOffset::new(0),
                    file_len: ImageFileLen::new(4).expect("source file length"),
                    guest_start: source,
                    guest_len: GuestCodeLen::new(4).expect("source guest length"),
                    source_words: vec![source_word].into(),
                }],
            },
            store,
        )
        .expect("configure sidecar source");

    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.pc = source.raw();
    let prepared_source = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("load shared direct source");
    let first_miss = fixture
        .translator
        .enter_prepared::<false>(prepared_source, &mut snapshot)
        .expect("execute first sidecar miss");
    assert!(matches!(
        first_miss.exit,
        NativeDsrExit::ResolveDirect {
            source: resolved_source,
            target: resolved_target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if resolved_source == source && resolved_target == target
    ));
    assert!(matches!(
        fixture
            .translator
            .finish_exit(&fixture.memory, &mut snapshot, prepared_source, first_miss)
            .expect("resolve generation-one target"),
        super::ThreadExit::Continue
    ));
    let generation_one_target = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare generation-one target");
    assert_eq!(generation_one_target.generation, CodeGeneration::INITIAL);
    assert!(!cell.load_acquire().is_null());

    snapshot.pc = source.raw();
    let prepared_source = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare generation-one sidecar hit");
    let first_hit = fixture
        .translator
        .enter_prepared::<false>(prepared_source, &mut snapshot)
        .expect("execute generation-one sidecar hit");
    assert_eq!(
        first_hit.exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target.raw() + 4),
        }
    );

    let generation_two = fixture
        .memory
        .note_dsr_code_mutation(target.raw(), 4)
        .expect("mutate target generation")
        .expect("nonempty mutation");
    snapshot.pc = target.raw();
    let stale_guard = fixture
        .translator
        .enter_prepared::<false>(generation_one_target, &mut snapshot)
        .expect("execute emitted generation-one guard");
    assert!(matches!(
        stale_guard.exit,
        NativeDsrExit::ResolveDirect {
            source: stale_source,
            target: stale_target,
            binding: DirectBindingExitMetadata::Absent,
        } if stale_source == target && stale_target == target
    ));

    snapshot.pc = target.raw();
    let generation_two_target = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("translate stale target through production cache path");
    assert_eq!(generation_two_target.generation, generation_two);
    assert!(
        cell.load_acquire().is_null(),
        "stale target translation must invalidate its incoming sidecar cell"
    );

    snapshot.pc = source.raw();
    let prepared_source = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare source after target invalidation");
    let rebind_miss = fixture
        .translator
        .enter_prepared::<false>(prepared_source, &mut snapshot)
        .expect("execute real rebound resolver path");
    assert!(matches!(
        rebind_miss.exit,
        NativeDsrExit::ResolveDirect {
            source: resolved_source,
            target: resolved_target,
            binding: DirectBindingExitMetadata::Mapped(_),
        } if resolved_source == source && resolved_target == target
    ));
    assert!(matches!(
        fixture
            .translator
            .finish_exit(&fixture.memory, &mut snapshot, prepared_source, rebind_miss)
            .expect("resolve generation-two target"),
        super::ThreadExit::Continue
    ));
    let rebound = cell.load_acquire();
    assert!(!rebound.is_null());
    // SAFETY: the process registry retains the descriptor, and `loaded` pins
    // the cell through this acquired read.
    let rebound = unsafe { &*rebound };
    assert_eq!(rebound.target_generation(), generation_two);

    snapshot.pc = source.raw();
    let prepared_source = fixture
        .translator
        .prepare_entry::<false>(&fixture.memory, &snapshot)
        .expect("prepare rebound sidecar hit");
    let final_hit = fixture
        .translator
        .enter_prepared::<false>(prepared_source, &mut snapshot)
        .expect("execute rebound sidecar cell hit");
    assert_eq!(
        final_hit.exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(target.raw() + 4),
        },
        "the traversal after rebind must bypass the resolver"
    );
    assert!(!cell.load_acquire().is_null());
}

#[test]
fn translated_block_is_published_on_retirement_and_reused() {
    use carrick_dsr_aarch64::shared_cache::{
        AddressModeIdentity, ExecutableIdentity, GuestCodeLen, ImageFileLen, ImageFileOffset,
        NativePageProfileIdentity, PendingTranslationUnit, PublishOutcome, SharedExecutableSegment,
        SharedImageConfig, SharedLoadedTranslationUnit, TRANSLATION_UNIT_BASE_EXPORT,
        TRANSLATION_UNIT_SCHEMA_V2, TranslationUnitKey, TranslationUnitManifest,
        TranslationUnitStore, UnitMissReason,
    };

    #[derive(Default)]
    struct RetirementStore {
        loaded: std::sync::Mutex<Option<SharedLoadedTranslationUnit>>,
    }

    impl TranslationUnitStore for RetirementStore {
        fn load(
            &self,
            key: &TranslationUnitKey,
            source_words: &[u32],
        ) -> Result<Option<SharedLoadedTranslationUnit>, UnitMissReason> {
            let loaded = self.loaded.lock().expect("lock retirement fixture");
            let Some(unit) = loaded.as_ref() else {
                return Ok(None);
            };
            if &unit.manifest.key != key {
                return Err(UnitMissReason::ImageIdentity);
            }
            unit.manifest.validate_source(source_words)?;
            Ok(Some(unit.clone()))
        }

        fn publish(
            &self,
            pending: &PendingTranslationUnit,
        ) -> Result<PublishOutcome, UnitMissReason> {
            let mut loaded = self.loaded.lock().expect("lock retirement fixture");
            if loaded.is_some() {
                return Ok(PublishOutcome::Existing);
            }
            let words = pending
                .code
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
                .collect::<Vec<_>>();
            let cache = Arc::new(parking_lot::Mutex::new(
                TranslationCache::new(
                    64 * 1024,
                    crate::native_darwin::darwin_jit::active_host_jit(),
                )
                .expect("allocate retirement fixture cache"),
            ));
            let emitted = cache
                .lock()
                .publish_words(&words)
                .expect("publish retirement fixture words");
            let base = emitted.entry().host().raw();
            let manifest = TranslationUnitManifest {
                schema: TRANSLATION_UNIT_SCHEMA_V2,
                key: pending.key.clone(),
                dylib_sha256: [0x33; 32],
                base_export: TRANSLATION_UNIT_BASE_EXPORT.to_owned(),
                code_len: pending.code.len() as u64,
                blocks: pending.blocks.clone(),
                binding_layout: pending.binding_layout,
                binding_export: pending.binding_export.clone(),
                binding_data_len: pending.binding_data_len,
                cell_size: pending.cell_size,
                bindings: pending.bindings.clone(),
                binding_relocations: pending.binding_relocations.clone(),
            };
            let lease: Arc<dyn Send + Sync> = cache;
            *loaded = Some(SharedLoadedTranslationUnit::new(manifest, base, lease));
            Ok(PublishOutcome::Winner)
        }
    }

    fn configure(fixture: &BiasedTranslatorFixture, store: Arc<RetirementStore>, words: &[u32]) {
        fixture
            .translator
            .process
            .configure_shared_image(
                SharedImageConfig {
                    executable: ExecutableIdentity::Digest([0x66; 32]),
                    page_profile: NativePageProfileIdentity::Native16k,
                    address_mode: AddressModeIdentity::biased(fixture.host_bias),
                    segments: vec![SharedExecutableSegment {
                        file_offset: ImageFileOffset::new(0),
                        file_len: ImageFileLen::new(16 * 1024).expect("nonzero file length"),
                        guest_start: fixture.guest_code,
                        guest_len: GuestCodeLen::new(16 * 1024).expect("nonzero guest length"),
                        source_words: words.to_vec().into(),
                    }],
                },
                store,
            )
            .expect("configure retirement fixture");
    }

    let words = [0xf940_0020, 0xd400_0001]; // ldr x0,[x1] ; svc #0
    let guest = GuestVa(0x20_0000_0000);
    let store = Arc::new(RetirementStore::default());
    {
        let mut first = biased_translator_fixture(&words, guest);
        configure(&first, Arc::clone(&store), &words);
        let expected = 0x1234_5678_9abc_def0_u64;
        unsafe { std::ptr::write_unaligned(first.data_host.raw() as *mut u64, expected) };
        let mut stack = vec![0_u8; 16 * 1024];
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.pc = guest.raw();
        snapshot.x[1] = first.guest_data.raw();
        let prepared = first
            .translator
            .prepare_entry::<false>(&first.memory, &snapshot)
            .expect("translate first-process block");
        let exit = first
            .translator
            .enter_prepared::<false>(prepared, &mut snapshot)
            .expect("execute first-process block");
        assert_eq!(snapshot.x[0], expected);
        assert!(matches!(exit.exit, NativeDsrExit::Syscall { .. }));
        assert_eq!(first.translator.resolver_stats().translations, 1);
        assert_eq!(
            first
                .translator
                .process
                .publish_shared_candidates(&first.memory)
                .expect("publish first-process candidates"),
            vec![PublishOutcome::Winner]
        );
    }

    let mut second = biased_translator_fixture(&words, guest);
    configure(&second, Arc::clone(&store), &words);
    let expected = 0x0fed_cba9_8765_4321_u64;
    unsafe { std::ptr::write_unaligned(second.data_host.raw() as *mut u64, expected) };
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.pc = guest.raw();
    snapshot.x[1] = second.guest_data.raw();
    let prepared = second
        .translator
        .prepare_entry::<false>(&second.memory, &snapshot)
        .expect("load second-process shared block");
    let exit = second
        .translator
        .enter_prepared::<false>(prepared, &mut snapshot)
        .expect("execute second-process shared block");
    assert_eq!(snapshot.x[0], expected);
    assert!(matches!(exit.exit, NativeDsrExit::Syscall { .. }));
    assert_eq!(second.translator.resolver_stats().shared_unit_hits, 1);
    assert_eq!(second.translator.resolver_stats().translations, 0);
}

#[test]
fn dsr_signal_fault_reconstructs_copied_instruction_pc() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate fault cache");
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
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit faulting block");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = 1;
    let mut exit = NativeDsrExit::Fault {
        guest_pc: GuestVa(0),
        signal: 0,
        code: 0,
        address: HostVa(0),
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
        physical_x18: 0,
        gateway_phase: 0,
        biased_guest_fault_address: 0,
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
    assert_eq!(address, HostVa(1));
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
    let _signal_oracle = install_signal_handlers_for_oracle();
    let guest = GuestVa(0x1c_100);
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate x28 recovery cache");
    let emitted = emit_block_direct(
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
        address: HostVa(0),
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
        physical_x18: 0,
        gateway_phase: 0,
        biased_guest_fault_address: 0,
    };

    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("recover signal gateway context through the host-stack handoff");

    assert!(
        matches!(
            exit,
            NativeDsrExit::Fault {
                signal: libc::SIGSEGV,
                address: HostVa(136),
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

    let _signal_oracle = install_signal_handlers_for_oracle();
    let guest = GuestVa(0x1c_200);
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate kick cache");
    let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
    let emitted = super::emit::emit_block_with_generation_direct(
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
    let site = super::cache::LinkSite {
        source: emitted.entry(),
        slot: link.slot,
    };
    let word =
        super::encode_aarch64_direct_branch(site, emitted.entry()).expect("encode kick loop link");
    cache.patch_code_word(site, word).expect("link kick loop");
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

/// What one `live_biased_exclusive_kick_sweep` run observed: which emitted
/// words a real asynchronous kick was actually taken at, and how often each
/// scratch GPR was genuinely clobbered at the landing point.
#[derive(Debug)]
struct FusedRegionKickSweep {
    landings: BTreeSet<usize>,
    emitted_words: usize,
    spill_index: usize,
    load_index: usize,
    store_index: usize,
    retry_index: usize,
    in_region_kicks: u64,
    entry_kicks: u64,
    stale_entry_kicks: u64,
    clobbered_address: u64,
    clobbered_bias: u64,
}

impl FusedRegionKickSweep {
    /// (a) A region SETUP word, after both spills -- i.e. inside the clobber
    /// window, not merely inside the block.
    fn covered_setup(&self) -> bool {
        self.landings
            .iter()
            .any(|index| *index > self.spill_index + 1 && *index < self.load_index)
    }

    /// (b) One of the region's body `Copy` words.
    fn covered_body(&self) -> bool {
        self.landings
            .iter()
            .any(|index| *index > self.load_index && *index < self.store_index)
    }

    /// (c) The rewritten exclusive store.
    fn covered_store(&self) -> bool {
        self.landings.contains(&self.store_index)
    }

    /// (d) The relocated retry branch itself.
    fn covered_retry_branch(&self) -> bool {
        self.landings.contains(&self.retry_index)
    }

    /// The retry EDGE (`b region_top`), which only executes when the store
    /// actually failed. Reported, never required: reaching it depends on
    /// winning a race against the monitor contender.
    fn covered_retry_edge(&self) -> bool {
        self.landings.contains(&(self.retry_index + 2))
    }

    fn covered_all(&self) -> bool {
        self.covered_setup()
            && self.covered_body()
            && self.covered_store()
            && self.covered_retry_branch()
            && self.covered_retry_edge()
            && self.clobbered_address > 0
            && self.clobbered_bias > 0
    }
}

/// Drive real `pthread_kill(SIGPIPE)` kicks INTO a fused biased exclusive
/// region and check obligation (R) plus resume legality at every landing.
///
/// The region is the production one end to end: `block::plan_block` reads the
/// guest words through a live biased `NativeMappedMemory` and must return a
/// `FusedBiased` `ExclusiveRegion`, and the production emitter lowers it. The
/// only test-side edit to the emitted code is re-pointing the region's success
/// direct link at the block entry, so the loop keeps re-executing natively
/// instead of leaving through the gateway -- which is what gives the
/// asynchronous signal a translated region to land in.
///
/// The landing WORD is not controllable: the C handler
/// (`carrick_native_dsr_signal_handler`) captures whatever `__pc` the kernel
/// interrupted. So this drives many kicks with a jittered arming threshold,
/// asserts the invariant at EVERY landing, and returns the set of words it
/// actually reached. `body_len` shifts that set: which words the core reports
/// as the interrupted PC is microarchitectural, so the caller sweeps several
/// body widths and takes the union.
#[allow(
    clippy::panic,
    reason = "oracle helper: fails fast on a broken fixture exactly like its test caller"
)]
fn live_biased_exclusive_kick_sweep(
    guest_code: GuestVa,
    body_len: usize,
    max_kicks: u64,
) -> FusedRegionKickSweep {
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    // Assembled with `clang -c -arch arm64`:
    //   ldaxr w0, [x1] / .rept N: add w0, w0, #1 / stlxr w3, w0, [x1]
    //   / cbnz w3, -(N+2)*4
    // -- the canonical RMW retry loop, plus a trailing svc so the planner has
    // a well-formed instruction after the region.
    const LDAXR_W0_X1: u32 = 0x885f_fc20;
    const ADD_W0_W0_1: u32 = 0x1100_0400;
    const STLXR_W3_W0_X1: u32 = 0x8803_fc20;
    const SVC_0: u32 = 0xd400_0001;
    // Distinctive guest values for the two clobbered scratch GPRs.
    const GUEST_ADDRESS_SCRATCH: u64 = 0x5a5a_a5a5_0000_0011;
    const GUEST_BIAS_SCRATCH: u64 = 0x5a5a_a5a5_0000_0010;

    let retry_displacement = -(i32::try_from(body_len).expect("body length fits i32") + 2);
    let cbnz_back = 0x3500_0000 | ((retry_displacement as u32 & 0x7_ffff) << 5) | 3;
    let mut guest_words = vec![LDAXR_W0_X1];
    guest_words.extend(std::iter::repeat_n(ADD_W0_W0_1, body_len));
    guest_words.extend([STLXR_W3_W0_X1, cbnz_back, SVC_0]);
    let fixture = biased_translator_fixture(&guest_words, guest_code);

    // 1. The production planner must FUSE this region in biased mode.
    let plan = super::block::plan_block(&fixture.memory, guest_code, CodeGeneration::INITIAL, 256)
        .expect("plan the live biased exclusive region");
    let PlannedExit::ExclusiveRegion {
        exit: region,
        fusion,
        ..
    } = plan.exit
    else {
        panic!("biased planning must fuse this region, got {:?}", plan.exit);
    };
    assert_eq!(
        fusion.disposition,
        super::types::ExclusiveFusionDisposition::FusedBiased,
        "the live kick oracle must exercise the FUSED biased lowering"
    );
    let scratch = fusion
        .biased_scratch
        .expect("a fused biased region carries its scratch plan");
    let address_register = scratch.address.index();
    let bias_register = scratch.bias.index();
    assert_ne!(address_register, bias_register);
    let address_index = usize::try_from(address_register).expect("address scratch index");
    let bias_index = usize::try_from(bias_register).expect("bias scratch index");
    let start = region.start.raw();
    let end = region.end.raw();
    assert_eq!(start, guest_code.raw());
    assert_eq!(end, guest_code.raw() + (body_len as u64 + 3) * 4);

    // 2. Emit it with the production emitter, then turn the region into a
    //    native self-loop by re-pointing its success direct link at the entry.
    let mut cache = TranslationCache::new(
        64 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate fused-region kick cache");
    let emitted = emit_block(
        &mut cache,
        &plan,
        super::emit::EmitAddressMode::Biased {
            host_bias: fixture.host_bias,
        },
    )
    .expect("emit the fused biased exclusive region");
    assert_eq!(
        emitted.direct_links().len(),
        1,
        "an early-exit-free region leaves through exactly one direct link"
    );
    let link = emitted.direct_links()[0];
    let site = super::cache::LinkSite {
        source: emitted.entry(),
        slot: link.slot,
    };
    let self_link = super::encode_aarch64_direct_branch(site, emitted.entry())
        .expect("encode the region self-link");
    cache
        .patch_code_word(site, self_link)
        .expect("re-point the region exit at its own entry");

    // 3. Pin the emitted layout, so the per-word resume expectations below are
    //    an independent statement about the lowering rather than a restatement
    //    of the PC map they are checking.
    let words = (0..emitted.len() / 4)
        .map(|index| unsafe {
            std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
        })
        .collect::<Vec<_>>();
    let save_address = 0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | address_register;
    let save_bias = 0xf900_0000 | ((1128 / 8) << 10) | (28 << 5) | bias_register;
    let restore_address = 0xf940_0000 | ((1120 / 8) << 10) | (28 << 5) | address_register;
    let restore_bias = 0xf940_0000 | ((1128 / 8) << 10) | (28 << 5) | bias_register;
    let rewritten_load = (LDAXR_W0_X1 & !(0x1f << 5)) | (address_register << 5);
    let rewritten_store = (STLXR_W3_W0_X1 & !(0x1f << 5)) | (address_register << 5);
    let spill_index = words
        .iter()
        .position(|word| *word == save_address)
        .expect("region prologue spills the address scratch");
    assert_eq!(
        words[spill_index + 1],
        save_bias,
        "region prologue spills the bias scratch"
    );
    let load_index = words
        .iter()
        .position(|word| *word == rewritten_load)
        .expect("rewritten exclusive load");
    assert!(load_index > spill_index + 1, "the spills precede the load");
    let store_index = load_index + body_len + 1;
    let retry_index = store_index + 1;
    for (index, word) in words
        .iter()
        .enumerate()
        .take(store_index)
        .skip(load_index + 1)
    {
        assert_eq!(*word, ADD_W0_W0_1, "body copy at word {index}");
    }
    assert_eq!(words[store_index], rewritten_store, "rewritten store");
    assert_eq!(
        words[retry_index] & 0xff00_0000,
        0x3500_0000,
        "relocated retry CBNZ"
    );
    assert_eq!(
        words[retry_index + 1] & 0xfc00_0000,
        0x1400_0000,
        "b success_restore"
    );
    assert_eq!(
        words[retry_index + 2] & 0xfc00_0000,
        0x1400_0000,
        "b region_top (the retry edge)"
    );
    assert_eq!(words[retry_index + 3], restore_address, "success restore");
    assert_eq!(words[retry_index + 4], restore_bias, "success restore");
    assert_eq!(words[retry_index + 6], restore_address, "slow restore");
    assert_eq!(words[retry_index + 7], restore_bias, "slow restore");

    // Resume legality, per emitted word, derived from that layout alone.
    let expected_resume = |index: usize| -> Vec<u64> {
        let Some(step) = index.checked_sub(load_index) else {
            // Prologue and address validation: the region has not started, so
            // all of these resume at the exclusive load.
            return vec![start];
        };
        let step = step as u64;
        let body = body_len as u64;
        if step <= body + 2 {
            // The load, every body copy, the store and the retry branch each
            // resume at their OWN guest PC. Restarting the region from the
            // load would re-apply the body's non-re-derivable `add`.
            vec![start + 4 * step]
        } else if step == body + 3 {
            // Fallthrough into the success restore.
            vec![end]
        } else if step == body + 4 {
            // The retry EDGE is an iteration boundary: back to the load.
            vec![start]
        } else if step <= body + 7 {
            // Success restore (two loads) plus its tail branch.
            vec![end]
        } else if step <= body + 10 {
            // Slow restore (two loads) plus its tail branch.
            vec![start]
        } else {
            // Exit tails: the success tail maps to the region end, the
            // sensitive fallback tail to the load.
            vec![start, end]
        }
    };

    // 4. Live kicks. SIGPIPE must be deliverable on this thread.
    let mut unblock: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::sigemptyset(&mut unblock) }, 0);
    assert_eq!(unsafe { libc::sigaddset(&mut unblock, libc::SIGPIPE) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblock, &mut original) },
        0
    );

    let counter_address = fixture.data_host.raw();
    let stop = Arc::new(AtomicBool::new(false));
    let armed = Arc::new(AtomicU64::new(0));
    let delivered = Arc::new(AtomicU64::new(0));

    // Stop and join the helper threads even when an assertion unwinds: they
    // touch `fixture`'s guest mapping, which the unwind is about to unmap.
    struct SweepThreads {
        stop: Arc<AtomicBool>,
        armed: Arc<AtomicU64>,
        joins: Vec<std::thread::JoinHandle<()>>,
    }
    impl Drop for SweepThreads {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.armed.store(0, Ordering::Release);
            for join in self.joins.drain(..) {
                drop(join.join());
            }
        }
    }

    // A contender that clears this thread's exclusive monitor WITHOUT
    // disturbing the counter, so the guest's STXR sometimes fails and the
    // retry edge actually executes.
    let contender_stop = Arc::clone(&stop);
    let contender = std::thread::spawn(move || {
        let cell = unsafe { &*(counter_address as *const AtomicU32) };
        while !contender_stop.load(Ordering::Relaxed) {
            cell.fetch_add(0, Ordering::SeqCst);
            for _ in 0..32 {
                std::hint::spin_loop();
            }
        }
    });

    let target = unsafe { libc::pthread_self() };
    let sender_stop = Arc::clone(&stop);
    let sender_armed = Arc::clone(&armed);
    let sender_delivered = Arc::clone(&delivered);
    let sender = std::thread::spawn(move || {
        let cell = unsafe { &*(counter_address as *const AtomicU32) };
        while !sender_stop.load(Ordering::Acquire) {
            let request = sender_armed.load(Ordering::Acquire);
            if request == 0 {
                std::hint::spin_loop();
                continue;
            }
            // Let the translated loop run a jittered number of iterations so
            // the interrupt lands at a different word each time.
            let threshold = (request & 0xffff_ffff) as u32;
            let deadline = Instant::now() + Duration::from_millis(200);
            while cell.load(Ordering::Relaxed) < threshold
                && Instant::now() < deadline
                && sender_armed.load(Ordering::Acquire) == request
            {
                std::hint::spin_loop();
            }
            // The counter is published by the region's own STXR, so kicking
            // the instant the threshold is observed phase-locks the interrupt
            // to a fixed offset after a successful store (measured: whole runs
            // of emitted words were never reported). Smear the phase with a
            // per-request jitter so the landing point sweeps the loop.
            let jitter = (request >> 32).wrapping_mul(2_654_435_761) % 1_021;
            for _ in 0..jitter {
                std::hint::spin_loop();
            }
            // One kick, then a SLOW retry. A SIGPIPE delivered outside
            // translated execution is dropped by the handler, so a single shot
            // is not a liveness guarantee -- but a fast retry lands a second
            // signal in the gateway's exit window and overwrites the first
            // kick's published exit, so retry only after the entry has had
            // ample time to return.
            while sender_armed.load(Ordering::Acquire) == request {
                assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGPIPE) }, 0);
                sender_delivered.fetch_add(1, Ordering::Relaxed);
                let retry_at = Instant::now() + Duration::from_millis(50);
                while sender_armed.load(Ordering::Acquire) == request && Instant::now() < retry_at {
                    std::hint::spin_loop();
                }
            }
        }
    });

    let _threads = SweepThreads {
        stop: Arc::clone(&stop),
        armed: Arc::clone(&armed),
        joins: vec![sender, contender],
    };

    let indirect = IndirectTargetCache::new();
    let cache_start = emitted.entry().host().raw();
    let cache_end = cache_start + emitted.len();
    let mut stack = vec![0_u8; 64 * 1024];
    let mut sweep = FusedRegionKickSweep {
        landings: BTreeSet::new(),
        emitted_words: words.len(),
        spill_index,
        load_index,
        store_index,
        retry_index,
        in_region_kicks: 0,
        entry_kicks: 0,
        stale_entry_kicks: 0,
        clobbered_address: 0,
        clobbered_bias: 0,
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut iteration = 0_u64;
    while !sweep.covered_all() && iteration < max_kicks && Instant::now() < deadline {
        iteration += 1;

        let cell = unsafe { &*(counter_address as *const AtomicU32) };
        cell.store(0, Ordering::SeqCst);
        let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
        snapshot.pc = guest_code.raw();
        snapshot.x[1] = fixture.guest_data.raw();
        snapshot.x[address_index] = GUEST_ADDRESS_SCRATCH;
        snapshot.x[bias_index] = GUEST_BIAS_SCRATCH;
        snapshot.pstate = 0xa000_0000;
        let expected_pstate = snapshot.pstate;
        let mut exit = NativeDsrExit::Kick {
            resume: guest_code,
            rewrite_scratch: 0,
            rewrite_context_scratch: 0,
            generation_pstate_scratch: 0,
            indirect_x15_scratch: 0,
            indirect_x30_scratch: 0,
        };

        armed.store(
            (iteration << 32) | (1 + (iteration * 37) % 3_000),
            Ordering::Release,
        );
        super::gateway::enter_translated_with_cache_range(
            emitted.entry(),
            &mut snapshot,
            &mut exit,
            &indirect,
            cache_start,
            cache_end,
            crate::native_darwin::address::NativeAddressMode::Biased {
                host_bias: fixture.host_bias,
            },
        )
        .expect("execute the fused biased region under a live kick");
        armed.store(0, Ordering::Release);

        match exit {
            NativeDsrExit::Kick {
                resume,
                rewrite_scratch,
                rewrite_context_scratch,
                generation_pstate_scratch,
                indirect_x15_scratch,
                indirect_x30_scratch,
            } => {
                sweep.in_region_kicks += 1;
                let raw = resume.raw();
                assert!(
                    raw >= cache_start as u64 && raw < cache_end as u64,
                    "kick resume 0x{raw:x} is outside the published block"
                );
                let offset =
                    u32::try_from(raw - cache_start as u64).expect("kick cache offset fits u32");
                assert_eq!(offset % 4, 0, "kick landed off an instruction boundary");
                let index = offset as usize / 4;
                let cache_offset = super::types::CacheOffset::published(offset);
                let guest_pc = emitted
                    .map()
                    .guest_for_cache(cache_offset)
                    .expect("the landing word maps to a guest PC");
                let recovery = emitted
                    .recovery()
                    .iter()
                    .find(|entry| entry.cache == cache_offset)
                    .map(|entry| entry.action);
                let raw_address = snapshot.x[address_index];
                let raw_bias = snapshot.x[bias_index];
                if let Some(action) = recovery {
                    super::recover_rewrite_state(
                        &mut snapshot,
                        action,
                        rewrite_scratch,
                        rewrite_context_scratch,
                        generation_pstate_scratch,
                        indirect_x15_scratch,
                        indirect_x30_scratch,
                    )
                    .expect("recover the interrupted fused exclusive region");
                }
                snapshot.pc =
                    super::recovery_resume_pc(guest_pc, recovery).expect("region resume PC");

                // Obligation (R): both clobbered guest GPRs are back.
                assert_eq!(
                    snapshot.x[address_index],
                    GUEST_ADDRESS_SCRATCH,
                    "address scratch x{address_register} not restored at word {index} \
                     (body_len={body_len}, guest PC 0x{:x}, recovery {recovery:?})",
                    guest_pc.raw()
                );
                assert_eq!(
                    snapshot.x[bias_index],
                    GUEST_BIAS_SCRATCH,
                    "bias scratch x{bias_register} not restored at word {index} \
                     (body_len={body_len}, guest PC 0x{:x}, recovery {recovery:?})",
                    guest_pc.raw()
                );
                // Obligation (N): nothing the lowering emits writes NZCV.
                assert_eq!(
                    snapshot.pstate, expected_pstate,
                    "PSTATE mutated by the fused region at word {index} (body_len={body_len})"
                );
                let legal = expected_resume(index);
                assert!(
                    legal.contains(&snapshot.pc),
                    "word {index} (body_len={body_len}, guest PC 0x{:x}) resumed at 0x{:x}, \
                     expected one of {legal:x?}",
                    guest_pc.raw(),
                    snapshot.pc
                );
                if raw_address != GUEST_ADDRESS_SCRATCH {
                    sweep.clobbered_address += 1;
                }
                if raw_bias != GUEST_BIAS_SCRATCH {
                    sweep.clobbered_bias += 1;
                }
                sweep.landings.insert(index);
            }
            NativeDsrExit::KickAtEntry { resume } => {
                // The kick became deliverable outside translated code; the
                // handler must hand back the untouched guest snapshot. A
                // retried SIGPIPE that lands in the gateway's exit window
                // republishes the FIRST kick's captured host PC (a harness
                // artifact of kicking a thread that has no one-shot
                // `NativeKickState` bound); count those separately rather than
                // asserting on a snapshot the handler already replaced.
                sweep.entry_kicks += 1;
                if resume == guest_code {
                    assert_eq!(snapshot.x[address_index], GUEST_ADDRESS_SCRATCH);
                    assert_eq!(snapshot.x[bias_index], GUEST_BIAS_SCRATCH);
                } else {
                    sweep.stale_entry_kicks += 1;
                }
            }
            other => panic!("fused region must only leave through a kick, got {other:?}"),
        }
    }

    drop(_threads);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) },
        0
    );

    eprintln!(
        "body_len={body_len}: {iteration} entries, {} in-region kicks, {} at entry \
         ({} stale), {} SIGPIPEs; {} distinct landing words of {} emitted \
         (setup={}, body={}, store={}, retry_branch={}, retry_edge={}); \
         clobbered before recovery: address={}, bias={}; landings={:?}",
        sweep.in_region_kicks,
        sweep.entry_kicks,
        sweep.stale_entry_kicks,
        delivered.load(Ordering::Relaxed),
        sweep.landings.len(),
        sweep.emitted_words,
        sweep.covered_setup(),
        sweep.covered_body(),
        sweep.covered_store(),
        sweep.covered_retry_branch(),
        sweep.covered_retry_edge(),
        sweep.clobbered_address,
        sweep.clobbered_bias,
        sweep.landings,
    );
    sweep
}

/// A LIVE asynchronous interrupt landing INSIDE a fused biased exclusive
/// region -- the case `ExclusiveFusionPolicy::BiasedDisabled` existed to
/// avoid, and therefore the case that has to hold for that gate's removal to
/// be sound. Nothing else in the suite delivers a real asynchronous signal
/// into a fused region.
///
/// Obligation (R) -- "the two clobbered guest GPRs can be rolled back" -- is
/// checked in the only form that can fail: after production recovery runs,
/// both scratch registers must equal the guest values that were live at entry,
/// and the run is required to have observed landings where each of them was
/// genuinely clobbered beforehand, otherwise the assertion would be vacuous.
/// Resume legality is checked per word against the lowering's structure.
///
/// Landing on a SPECIFIC word is NOT controllable in this harness: the C
/// handler captures whatever `__pc` the kernel interrupted, and which words the
/// core reports is microarchitectural (with a one-instruction body the ALU word
/// between the pair was never reported in 8000 kicks, while with a 16-word body
/// the store never was). So the test sweeps several body widths and requires
/// the UNION of their landings to cover a setup word, a body copy word, the
/// store and the retry branch.
#[test]
fn dsr_live_kick_inside_fused_biased_exclusive_region_restores_both_scratch_gprs() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    // Which emitted words the core reports as the interrupted PC is
    // microarchitectural and shifts with the body width, so sweep widths until
    // their UNION covers every required word. `4` reaches all of them on its
    // own most runs; the rest are the fallback.
    let mut sweeps: Vec<FusedRegionKickSweep> = Vec::new();
    for (index, body_len) in [4_usize, 2, 16, 1].into_iter().enumerate() {
        sweeps.push(live_biased_exclusive_kick_sweep(
            GuestVa(0x21_0000_0000 + (index as u64) * 0x10_0000),
            body_len,
            40_000,
        ));
        if sweeps.iter().any(FusedRegionKickSweep::covered_setup)
            && sweeps.iter().any(FusedRegionKickSweep::covered_body)
            && sweeps.iter().any(FusedRegionKickSweep::covered_store)
            && sweeps
                .iter()
                .any(FusedRegionKickSweep::covered_retry_branch)
        {
            break;
        }
    }

    let in_region_kicks: u64 = sweeps.iter().map(|sweep| sweep.in_region_kicks).sum();
    let clobbered_address: u64 = sweeps.iter().map(|sweep| sweep.clobbered_address).sum();
    let clobbered_bias: u64 = sweeps.iter().map(|sweep| sweep.clobbered_bias).sum();
    let distinct_landings: usize = sweeps.iter().map(|sweep| sweep.landings.len()).sum();
    let covered_setup = sweeps.iter().any(FusedRegionKickSweep::covered_setup);
    let covered_body = sweeps.iter().any(FusedRegionKickSweep::covered_body);
    let covered_store = sweeps.iter().any(FusedRegionKickSweep::covered_store);
    let covered_retry_branch = sweeps
        .iter()
        .any(FusedRegionKickSweep::covered_retry_branch);
    let covered_retry_edge = sweeps.iter().any(FusedRegionKickSweep::covered_retry_edge);

    eprintln!(
        "live biased fused-exclusive kick union: {in_region_kicks} in-region kicks over \
         {} sweeps, {distinct_landings} distinct landing words; setup={covered_setup}, \
         body={covered_body}, store={covered_store}, retry_branch={covered_retry_branch}, \
         retry_edge={covered_retry_edge}",
        sweeps.len(),
    );

    assert!(in_region_kicks > 0, "no kick landed inside a fused region");
    // Without a landing where each register was genuinely clobbered, the
    // restore assertions inside the sweep would hold vacuously.
    assert!(
        clobbered_address > 0 && clobbered_bias > 0,
        "no landing found either scratch register clobbered: address={clobbered_address}, \
         bias={clobbered_bias}"
    );
    assert!(covered_setup, "(a) no kick landed on a region setup word");
    assert!(
        covered_body,
        "(b) no kick landed on a region body copy word"
    );
    assert!(covered_store, "(c) no kick landed on the exclusive store");
    assert!(
        covered_retry_branch,
        "(d) no kick landed on the retry branch"
    );
    // The retry EDGE additionally needs the store to have FAILED, which
    // depends on winning a race against the monitor contender, so it is
    // reported rather than required.
    eprintln!("retry edge (`b region_top`) landing observed: {covered_retry_edge}");
}
#[test]
fn dsr_pending_kick_during_gateway_entry_keeps_guest_pc() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let guest = GuestVa(0x1c_300);
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate entry-kick cache");
    let emitted = emit_block_direct(
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
fn dsr_host_window_kick_is_deferred_to_next_gateway_entry() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let guest = GuestVa(0x1c_340);
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate host-window cache");
    let emitted = emit_block_direct(
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
    .expect("emit host-window block");
    let state = super::super::NativeKickState::new().expect("create host-window state");
    state.bind_current().expect("bind host-window state");

    let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut kick);
        libc::sigaddset(&mut kick, libc::SIGPIPE);
    }
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &kick, &mut original) },
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
    let expected = snapshot;
    let mut exit = NativeDsrExit::Syscall {
        resume: GuestVa(guest.raw() + 4),
    };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("consume deferred host-window kick");

    state.unbind_current();
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) },
        0
    );
    assert_eq!(exit, NativeDsrExit::KickAtEntry { resume: guest });
    assert_eq!(snapshot.x, expected.x);
    assert_eq!(snapshot.sp, expected.sp);
    assert_eq!(snapshot.pc, expected.pc);
}

#[test]
fn dsr_reinstall_clears_inherited_host_window_kick() {
    let _signal_oracle = install_signal_handlers_for_oracle();
    let state = super::super::NativeKickState::new().expect("create reinstall state");
    state.bind_current().expect("bind reinstall state");
    let mut kick: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut original: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut kick);
        libc::sigaddset(&mut kick, libc::SIGPIPE);
    }
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &kick, &mut original) },
        0
    );
    assert!(state.request());
    assert_eq!(
        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGPIPE) },
        0
    );

    // `prepare_kick_target` re-installs the handler in a real fork child. The
    // child must not inherit a kick that was directed at the parent thread.
    assert_eq!(
        unsafe { super::super::carrick_native_install_dsr_signal_handlers() },
        0
    );
    let guest = GuestVa(0x1c_360);
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate reinstall cache");
    let emitted = emit_block_direct(
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
    .expect("emit reinstall block");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.pc = guest.raw();
    let mut exit = NativeDsrExit::Syscall { resume: guest };
    enter_translated(emitted.entry(), &mut snapshot, &mut exit)
        .expect("enter after handler reinstall");

    state.unbind_current();
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &original, std::ptr::null_mut()) },
        0
    );
    assert_eq!(
        exit,
        NativeDsrExit::Syscall {
            resume: GuestVa(guest.raw() + 4)
        }
    );
}

#[test]
fn dsr_phase_zero_host_kick_keeps_original_guest_snapshot() {
    unsafe extern "C" {
        fn carrick_native_dsr_test_phase_zero_host_kick_once();
    }

    let _signal_oracle = install_signal_handlers_for_oracle();
    let guest = GuestVa(0x1c_380);
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate host-kick cache");
    let emitted = emit_block_direct(
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
        crate::native_darwin::address::NativeAddressMode::Direct,
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
    let _signal_oracle = install_signal_handlers_for_oracle();
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate x18 fault cache");
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
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit expanded x18 load");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    snapshot.x[0] = 1;
    let original_x18 = snapshot.x[18];
    let original = snapshot;
    let mut exit = NativeDsrExit::Fault {
        guest_pc: GuestVa(0),
        signal: 0,
        code: 0,
        address: HostVa(0),
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
        physical_x18: 0,
        gateway_phase: 0,
        biased_guest_fault_address: 0,
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
    let _signal_oracle = install_signal_handlers_for_oracle();
    let mut cache = TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )
    .expect("allocate literal fault cache");
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
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit expanded literal fault");
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = seeded_snapshot(stack.as_mut_ptr() as u64 + stack.len() as u64);
    let original = snapshot;
    let mut exit = NativeDsrExit::Fault {
        guest_pc: GuestVa(0),
        signal: 0,
        code: 0,
        address: HostVa(0),
        rewrite_scratch: 0,
        rewrite_context_scratch: 0,
        generation_pstate_scratch: 0,
        indirect_x15_scratch: 0,
        indirect_x30_scratch: 0,
        physical_x18: 0,
        gateway_phase: 0,
        biased_guest_fault_address: 0,
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
