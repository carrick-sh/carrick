use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

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
        Arc::new(super::ProcessTranslator::new(64 * 1024).expect("create live translator"));
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
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate biased cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate NZCV oracle cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate single-memory cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate memequal cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate literal cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate counter cache");
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
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate matrix cache");
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
    let mut cache = TranslationCache::new(16 * 1024)?;
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate PC-relative cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate literal-load cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate literal matrix cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate ADRP cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate direct-flow cache");
    let emitted = emit_block_direct(&mut cache, &plan).expect("emit unresolved direct branch");
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
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit condition edge");
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
    let mut code = TranslationCache::new(32 * 1024).expect("allocate alias oracle");
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
    let indirect = IndirectTargetCache::new();
    indirect.publish(first, CodeGeneration::INITIAL, first_block.entry());
    indirect.publish(second, CodeGeneration::INITIAL, second_block.entry());

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
    let mut code = TranslationCache::new(16 * 1024).expect("allocate indirect cache-hit code");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate dual rewrite cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate dual add cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate dual load cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate generation guard cache");
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
        }
    );
}

#[test]
fn dsr_signal_fault_reconstructs_copied_instruction_pc() {
    let _signal_oracle = install_signal_handlers_for_oracle();
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate x28 recovery cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate kick cache");
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
    let _signal_oracle = install_signal_handlers_for_oracle();
    let guest = GuestVa(0x1c_300);
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate entry-kick cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate host-window cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate reinstall cache");
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
    let mut cache = TranslationCache::new(16 * 1024).expect("allocate host-kick cache");
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
