//! Shim: the AArch64 DSR emitter moved verbatim to
//! `carrick_dsr_aarch64::emit` as part of the staged native-backend
//! extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `super::emit::*` call paths resolve unchanged.
//!
//! The emitter's test suite stays HERE (not in the arch crate) because
//! nearly every test publishes into a live `TranslationCache` through the
//! Darwin host JIT (`darwin_jit::active_host_jit`) and several execute the
//! published code through the assembled gateway -- both still runtime-owned
//! until the host-seam slice (M0.6). The pure assembler-shape test moved
//! with the emitter; `copy_plan` is duplicated on both sides.

// `allow(unused_imports)`: the runtime LIB no longer names `dsr::emit::*`
// since the translator orchestration moved to the arch crate; the re-export
// stays for the oracle and the emitter test suite below.
#[allow(unused_imports)]
pub(in crate::native_darwin) use carrick_dsr_aarch64::emit::*;

#[cfg(test)]
mod tests {
    use super::super::block::{BlockLimit, BlockPlan, PlannedExit, PlannedInst};
    use super::super::cache::TranslationCache;
    use super::super::types::{
        CacheOffset, CodeGeneration, CounterDestination, CounterRead, DirectExit, DirectKind,
        DsrError, IndirectExit, IndirectKind, InstAction, MemoryAccess, MemoryBase, MemoryClass,
        MemoryWriteback, PcRelativeInst, PcRelativeKind, SensitiveExit, SensitiveKind,
    };
    use super::*;
    // These were ambient through the emitter's own file-level imports before
    // the extraction; the shim's glob re-export only carries the emitter's
    // PUB items, so the test module imports them directly.
    use carrick_guest_mem::GuestVa;
    use dynasmrt::{DynasmApi, VecAssembler, aarch64::Aarch64Relocation};

    #[derive(Clone, Copy)]
    struct EmissionComponentSummary {
        p50_us: f64,
        p95_us: f64,
        min_us: f64,
    }

    fn format_emission_component(name: &str, summary: EmissionComponentSummary) -> String {
        format!(
            "{name}_p50_us={:.3}\n{name}_p95_us={:.3}\n{name}_min_us={:.3}",
            summary.p50_us, summary.p95_us, summary.min_us
        )
    }

    #[cfg(target_arch = "aarch64")]
    fn read_counter() -> u64 {
        let value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {value}, cntvct_el0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    #[cfg(target_arch = "aarch64")]
    fn counter_frequency() -> u64 {
        let value: u64;
        unsafe {
            core::arch::asm!(
                "mrs {value}, cntfrq_el0",
                value = out(reg) value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    #[cfg(target_arch = "aarch64")]
    fn measure_emission_component(
        samples: usize,
        batch: usize,
        logical_operations: usize,
        mut operation: impl FnMut(),
    ) -> EmissionComponentSummary {
        for _ in 0..128 {
            operation();
        }
        let mut ticks = Vec::with_capacity(samples);
        for _ in 0..samples {
            let start = read_counter();
            for _ in 0..batch {
                operation();
            }
            ticks.push(read_counter().wrapping_sub(start));
        }
        ticks.sort_unstable();
        let frequency = counter_frequency() as f64;
        let divisor = (batch * logical_operations) as f64;
        let to_us = |value: u64| value as f64 * 1_000_000.0 / frequency / divisor;
        let rank = |percentile: f64| {
            let index = (((ticks.len() as f64) * percentile).ceil() as usize)
                .saturating_sub(1)
                .min(ticks.len() - 1);
            to_us(ticks[index])
        };
        EmissionComponentSummary {
            p50_us: rank(0.50),
            p95_us: rank(0.95),
            min_us: to_us(ticks[0]),
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn assert_valid_component(summary: EmissionComponentSummary) {
        assert!(summary.p50_us.is_finite() && summary.p50_us > 0.0);
        assert!(summary.p95_us.is_finite() && summary.p95_us > 0.0);
        assert!(summary.min_us.is_finite() && summary.min_us > 0.0);
    }

    #[test]
    fn emission_component_output_has_stable_machine_keys() {
        let summary = EmissionComponentSummary {
            p50_us: 0.101,
            p95_us: 0.202,
            min_us: 0.050,
        };
        assert_eq!(
            format_emission_component("dynasm_default", summary),
            "dynasm_default_p50_us=0.101\ndynasm_default_p95_us=0.202\ndynasm_default_min_us=0.050"
        );
    }

    fn copy_plan() -> BlockPlan {
        BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x400c),
            generation: CodeGeneration::INITIAL,
            instructions: vec![
                PlannedInst {
                    guest: GuestVa(0x4000),
                    action: InstAction::Copy(0xd503_201f),
                },
                PlannedInst {
                    guest: GuestVa(0x4004),
                    action: InstAction::Copy(0x9100_0400),
                },
            ],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4008),
                resume: GuestVa(0x400c),
            },
        }
    }

    // `dsr_virtual_counter_mode_one_emits_inline_machine_code` moved to the arch
    // crate's `emit::tests` (pure assembler shape; no JIT cache needed).

    #[test]
    fn recorded_emission_normalizes_process_bindings_and_replays_metadata() {
        let plan = copy_plan();
        let source_words = vec![0xd503_201f, 0x9100_0400, 0xd400_0001];
        let first_generation = AtomicU64::new(1);
        let second_generation = AtomicU64::new(9);
        let first_bias = carrick_dsr::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
            .expect("first bias");
        let second_bias = carrick_dsr::address::NativeHostBias::new(0x90_0000_0000, 16 * 1024)
            .expect("second bias");
        let mut first_cache = TranslationCache::new(
            64 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("first cache");
        let (first, first_artifact) = emit_block_recording_artifact(
            &mut first_cache,
            &plan,
            GenerationGuard::new(&first_generation, CodeGeneration::claimed(1)),
            EmitAddressMode::Biased {
                host_bias: first_bias,
            },
            source_words.clone(),
        )
        .expect("record first emission");
        let mut second_cache = TranslationCache::new(
            64 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("second cache");
        let (second, second_artifact) = emit_block_recording_artifact(
            &mut second_cache,
            &plan,
            GenerationGuard::new(&second_generation, CodeGeneration::claimed(9)),
            EmitAddressMode::Biased {
                host_bias: second_bias,
            },
            source_words,
        )
        .expect("record second emission");

        assert_eq!(first_artifact.template, second_artifact.template);
        assert_ne!(first_artifact.bindings, second_artifact.bindings);
        let mut replay_cache = TranslationCache::new(
            64 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("replay cache");
        let replay = super::super::artifact_spike::replay_artifact(
            &mut replay_cache,
            &first_artifact.template,
            &second_artifact.bindings,
        )
        .expect("replay first template with second bindings");
        assert_eq!(second.map().entries(), replay.map().entries());
        assert_eq!(second.recovery(), replay.recovery());
        assert_eq!(second.direct_links(), replay.direct_links());
        assert_ne!(first.entry(), replay.entry());
    }

    fn emitted_words_for_all_gateway_exits() -> Vec<Vec<u32>> {
        let syscall = copy_plan();

        let mut direct = copy_plan();
        direct.exit = PlannedExit::Direct {
            guest: GuestVa(0x4008),
            word: 0x1400_0002,
            exit: DirectExit {
                kind: DirectKind::Branch,
                target: GuestVa(0x4010),
                resume: GuestVa(0x400c),
                condition: None,
                register: None,
                bit: None,
            },
        };

        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd61f_0000,
            exit: IndirectExit {
                kind: IndirectKind::Branch,
                register: bad64::Reg::X0,
                resume: GuestVa(0x400c),
            },
        };

        let mut sensitive = copy_plan();
        sensitive.exit = PlannedExit::Sensitive {
            guest: GuestVa(0x4008),
            word: 0xd53b_d040,
            exit: SensitiveExit {
                kind: SensitiveKind::ReadTpidr,
                register: Some(bad64::Reg::X0),
                resume: GuestVa(0x400c),
            },
            fusion: None,
        };

        let mut continuation = copy_plan();
        continuation.instructions.truncate(1);
        continuation.end = GuestVa(0x4004);
        continuation.exit = PlannedExit::Continue {
            target: GuestVa(0x4004),
            limit: BlockLimit::InstructionLimit,
        };

        let mut unsupported = copy_plan();
        unsupported.exit = PlannedExit::Unsupported {
            guest: GuestVa(0x4008),
            word: 0,
            op: bad64::Op::UDF,
        };

        let mut cache = TranslationCache::new(
            128 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate exit emission cache");
        [
            syscall,
            direct,
            indirect,
            sensitive,
            continuation,
            unsupported,
        ]
        .into_iter()
        .map(|plan| {
            let emitted = emit_block_direct(&mut cache, &plan).expect("emit gateway exit");
            (0..emitted.len() / 4)
                .map(|index| unsafe {
                    std::ptr::read_unaligned(
                        (emitted.entry().host().raw() + index * 4) as *const u32,
                    )
                })
                .collect()
        })
        .collect()
    }

    #[test]
    fn carrick_owned_emitted_blocks_contain_no_brk_transport() {
        for words in emitted_words_for_all_gateway_exits() {
            assert!(words.iter().all(|word| word & 0xffe0_001f != 0xd420_0000));
        }
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    #[ignore = "explicit opt-in native DSR emission component benchmark"]
    fn dsr_emission_component_benchmark() {
        const WORDS: [u32; 64] = [0xd503_201f; 64];
        let bytes = WORDS
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();

        let bad64_decode = measure_emission_component(20_000, 16, 1, || {
            std::hint::black_box(
                bad64::decode(std::hint::black_box(0xf940_0280), 0x4000)
                    .expect("decode benchmark word"),
            );
        });
        let dynasm_default = measure_emission_component(4_000, 16, 1, || {
            let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
            for word in WORDS {
                assembler.push_u32(word);
            }
            std::hint::black_box(assembler.finalize().expect("finalize default assembler"));
        });
        let dynasm_reserved = measure_emission_component(4_000, 16, 1, || {
            let mut assembler = VecAssembler::<Aarch64Relocation>::new_with_capacity(
                0,
                WORDS.len() * 4,
                0,
                0,
                2,
                0,
                4,
            );
            for word in WORDS {
                assembler.push_u32(word);
            }
            std::hint::black_box(assembler.finalize().expect("finalize reserved assembler"));
        });
        let reshape_words = measure_emission_component(20_000, 16, 1, || {
            std::hint::black_box(
                bytes
                    .chunks_exact(4)
                    .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                    .collect::<Vec<_>>(),
            );
        });
        let copy_bytes = measure_emission_component(20_000, 16, 1, || {
            let mut destination = [0_u8; WORDS.len() * 4];
            destination.copy_from_slice(&bytes);
            std::hint::black_box(destination);
        });

        let measure_jit_window = |logical_blocks: usize| {
            let mut cache = TranslationCache::new(
                32 * 1024 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate emission benchmark cache");
            let words = WORDS.repeat(logical_blocks);
            measure_emission_component(2_000, 1, logical_blocks, || {
                let mut writer = cache
                    .begin_write(words.len() * std::mem::size_of::<u32>())
                    .expect("begin benchmark cache write");
                writer.write_words(&words).expect("write benchmark words");
                std::hint::black_box(writer.publish().expect("publish benchmark words"));
            })
        };
        let jit_window_1 = measure_jit_window(1);
        let jit_window_4 = measure_jit_window(4);
        let jit_window_16 = measure_jit_window(16);

        let generation = std::sync::atomic::AtomicU64::new(CodeGeneration::INITIAL.get());
        let plan = copy_plan();
        let mut cache = TranslationCache::new(
            32 * 1024 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate full emission benchmark cache");
        let full_guarded_emit = measure_emission_component(4_000, 1, 1, || {
            std::hint::black_box(
                emit_block_with_generation_direct(
                    &mut cache,
                    &plan,
                    GenerationGuard::new(&generation, CodeGeneration::INITIAL),
                )
                .expect("emit guarded benchmark block"),
            );
        });

        for (name, summary) in [
            ("bad64_decode", bad64_decode),
            ("dynasm_default", dynasm_default),
            ("dynasm_reserved", dynasm_reserved),
            ("reshape_words", reshape_words),
            ("copy_bytes", copy_bytes),
            ("jit_window_1", jit_window_1),
            ("jit_window_4", jit_window_4),
            ("jit_window_16", jit_window_16),
            ("full_guarded_emit", full_guarded_emit),
        ] {
            assert_valid_component(summary);
            println!("{}", format_emission_component(name, summary));
        }
        println!("pure_samples=20000");
        println!("dynasm_samples=4000");
        println!("jit_samples=2000");
        println!("full_emit_samples=4000");
    }

    #[test]
    fn dsr_emit_copy_only_block_decodes_back_with_exact_maps() {
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &copy_plan()).expect("emit copy-only block");
        assert_eq!(emitted.len(), 72);
        let original_words = [0xd503_201f, 0x9100_0400];
        let entry_word =
            unsafe { std::ptr::read_unaligned(emitted.entry().host().raw() as *const u32) };
        assert_eq!(
            bad64::decode(entry_word, emitted.entry().host().raw() as u64)
                .expect("decode entry marker")
                .op(),
            bad64::Op::STR
        );
        for (index, original_word) in original_words.into_iter().enumerate() {
            let offset = (index + 2) * 4;
            let pointer = (emitted.entry().host().raw() + offset) as *const u32;
            let word = unsafe { std::ptr::read_unaligned(pointer) };
            let decoded = bad64::decode(word, emitted.entry().host().raw() as u64 + offset as u64)
                .expect("decode emitted instruction");
            let original = bad64::decode(original_word, 0x4000 + index as u64 * 4)
                .expect("decode original instruction");
            assert_eq!(decoded.op(), original.op());
            assert_eq!(decoded.operands(), original.operands());
        }

        assert_eq!(
            emitted.map().cache_for_guest(GuestVa(0x4000)),
            Some(CacheOffset::published(0))
        );
        assert_eq!(
            emitted.map().guest_for_cache(CacheOffset::published(4)),
            Some(GuestVa(0x4000))
        );
        assert_eq!(
            emitted.map().cache_for_guest(GuestVa(0x4004)),
            Some(CacheOffset::published(12))
        );
        for entry in emitted.map().entries() {
            assert_eq!(entry.cache.get() % 4, 0);
            assert_eq!(
                emitted.map().guest_for_cache(entry.cache),
                Some(entry.guest)
            );
        }
    }

    #[test]
    fn dsr_direct_memory_action_emits_the_original_word() {
        let word = 0xf940_0020;
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4008),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: InstAction::Memory(MemoryAccess {
                    word,
                    op: bad64::Op::LDR,
                    base: MemoryBase::Register(bad64::Reg::X1),
                    effective_address: super::super::types::MemoryEffectiveAddress::Base,
                    writeback: MemoryWriteback::None,
                    class: MemoryClass::Scalar,
                    virtualization: super::super::types::MemoryVirtualization::None,
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
        .expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit direct memory block");
        let pointer = (emitted.entry().host().raw() + 8) as *const u32;
        assert_eq!(unsafe { std::ptr::read_unaligned(pointer) }, word);
    }

    #[test]
    fn direct_memory_emission_is_word_identical() {
        let word = 0xf940_0020;
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify direct memory"),
        }];
        plan.end = GuestVa(0x4008);
        plan.exit = PlannedExit::Syscall {
            guest: GuestVa(0x4004),
            resume: GuestVa(0x4008),
        };
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Direct)
            .expect("emit direct memory block");
        let words = (0..emitted.len() / 4).map(|index| unsafe {
            std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
        });
        assert!(words.into_iter().any(|emitted_word| emitted_word == word));
    }

    #[test]
    fn biased_in_range_memory_skips_fault_address_publication_store() {
        let word = 0xf940_0020; // ldr x0, [x1]
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify biased memory"),
        }];
        plan.end = GuestVa(0x4008);
        plan.exit = PlannedExit::Syscall {
            guest: GuestVa(0x4004),
            resume: GuestVa(0x4008),
        };
        let host_bias = carrick_dsr::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
            .expect("valid bias");
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("emit biased memory block");
        let words: Vec<u32> = (0..emitted.len() / 4)
            .map(|index| unsafe {
                std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
            })
            .collect();
        let store_masked = 0xf900_0000 | ((1200 / 8) << 10) | (28 << 5);
        let store = words
            .iter()
            .position(|word| word & !0x1f == store_masked)
            .expect("biased invalid path publishes exact guest fault address");
        assert_eq!(
            words.get(store.wrapping_sub(1)).copied(),
            Some(0xb400_0052),
            "cbz must skip the publication store for every in-range access"
        );
    }

    #[test]
    fn biased_dc_zva_lowers_inline_and_links_to_its_resume_pc() {
        let guest = GuestVa(0x4000);
        let resume = GuestVa(0x4004);
        let word = 0xd50b_7420; // dc zva, x0
        let plan = BlockPlan {
            start: guest,
            end: resume,
            generation: CodeGeneration::INITIAL,
            instructions: Vec::new(),
            exit: PlannedExit::Sensitive {
                guest,
                word,
                exit: SensitiveExit {
                    kind: SensitiveKind::DcZva,
                    register: Some(bad64::Reg::X0),
                    resume,
                },
                fusion: None,
            },
        };
        let host_bias = carrick_dsr::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
            .expect("valid bias");
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("emit inline biased dc zva");
        let words = (0..emitted.len() / 4).map(|index| unsafe {
            std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
        });

        assert!(
            emitted
                .direct_links()
                .iter()
                .any(|link| link.target == resume),
            "inline dc zva must stay in the translated chain"
        );
        assert!(
            words
                .into_iter()
                .any(|emitted_word| emitted_word & !0x1f == word & !0x1f),
            "inline lowering must execute a host dc zva"
        );
        assert!(emitted.recovery().iter().any(|entry| {
            matches!(
                entry.action,
                RecoveryAction::RecoverBiasedMemory(recovery)
                    if recovery.instruction_complete
            )
        }));
    }

    #[test]
    fn direct_memory_emission_matches_full_copy_block_bytes() {
        let word = 0xf940_0020;
        let mut memory = copy_plan();
        memory.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify direct memory"),
        }];
        memory.exit = PlannedExit::Syscall {
            guest: GuestVa(0x4004),
            resume: GuestVa(0x4008),
        };
        let mut copy = memory.clone();
        copy.instructions[0].action = InstAction::Copy(word);
        let mut memory_cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate direct memory cache");
        let mut copy_cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate direct copy cache");
        let memory_emitted = emit_block(&mut memory_cache, &memory, EmitAddressMode::Direct)
            .expect("emit typed direct memory");
        let copy_emitted = emit_block(&mut copy_cache, &copy, EmitAddressMode::Direct)
            .expect("emit copied direct memory");
        assert_eq!(memory_emitted.len(), copy_emitted.len());
        let memory_bytes = unsafe {
            std::slice::from_raw_parts(
                memory_emitted.entry().host().raw() as *const u8,
                memory_emitted.len(),
            )
        };
        let copy_bytes = unsafe {
            std::slice::from_raw_parts(
                copy_emitted.entry().host().raw() as *const u8,
                copy_emitted.len(),
            )
        };
        assert_eq!(memory_bytes, copy_bytes);
    }

    #[test]
    fn biased_memory_rejects_unsupported_families() {
        let word = 0x8598_5f6f;
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify unsupported SVE memory"),
        }];
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        assert!(matches!(
            emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias },),
            Err(DsrError::UnsupportedBlockAction { .. })
        ));
    }

    #[test]
    fn biased_memory_scratch_selection_handles_x16_x17_operands() {
        for word in [
            0xf940_0030, // ldr x16, [x1]
            0xf900_0031, // str x17, [x1]
            0xf940_0200, // ldr x0, [x16]
            0xf940_0220, // ldr x0, [x17]
        ] {
            let mut plan = copy_plan();
            plan.instructions = vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: super::super::decode::classify(word, GuestVa(0x4000))
                    .expect("classify x16/x17 memory fixture"),
            }];
            let host_bias =
                crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                    .expect("construct host bias");
            let mut cache = TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate translation cache");
            emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
                .unwrap_or_else(|error| panic!("0x{word:08x} did not lower: {error}"));
        }
    }

    #[test]
    fn biased_constrained_writeback_load_overlap_fails_closed() {
        for word in [
            0xf840_8421, // ldr x1, [x1], #8
            0xa8c1_0821, // ldp x1, x2, [x1], #16
        ] {
            let mut plan = copy_plan();
            plan.instructions = vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: super::super::decode::classify(word, GuestVa(0x4000))
                    .expect("classify constrained writeback load"),
            }];
            let host_bias =
                crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                    .expect("construct host bias");
            let mut cache = TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate overlap cache");
            assert!(matches!(
                emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias },),
                Err(DsrError::UnsupportedBlockAction { .. })
            ));
        }
    }

    #[test]
    fn biased_simd_pair_writeback_does_not_alias_gpr_base_by_register_number() {
        let word = 0xadc1_0821; // ldp q1, q2, [x1, #32]!
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify Go cgo SIMD pair load"),
        }];
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate SIMD pair cache");
        emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("SIMD pair destination numbering must not overlap its GPR base");
    }

    #[test]
    fn biased_simd_post_index_does_not_alias_gpr_base_by_register_number() {
        let word = 0x4cdf_2c00; // ld1 {v0.2d-v3.2d}, [x0], #64
        let action = super::super::decode::classify(word, GuestVa(0x4000))
            .expect("classify Go SIMD post-index load");
        assert!(matches!(
            action,
            InstAction::Memory(memory) if memory.writeback == MemoryWriteback::PostIndex
        ));
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action,
        }];
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate SIMD cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("SIMD destination numbering must not overlap its GPR base");
        assert!(emitted.recovery().iter().any(|entry| {
            matches!(
                entry.action,
                RecoveryAction::RecoverBiasedMemory(recovery) if recovery.commit_base
            )
        }));
    }

    #[test]
    fn biased_recovery_offsets_transition_once_from_retry_to_resume() {
        let word = 0xf81f_8c20; // str x0, [x1, #-8]!
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4008),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: super::super::decode::classify(word, GuestVa(0x4000))
                    .expect("classify writeback store"),
            }],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008),
            },
        };
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate recovery cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("emit writeback recovery matrix");
        let actions = emitted
            .recovery()
            .iter()
            .filter_map(|entry| match entry.action {
                RecoveryAction::RecoverBiasedMemory(recovery) => Some(recovery),
                _ => None,
            })
            .collect::<Vec<_>>();
        let first_complete = actions
            .iter()
            .position(|action| action.instruction_complete)
            .expect("post-memory recovery exists");
        assert!(first_complete > 0);
        assert!(
            actions[..first_complete]
                .iter()
                .all(|action| !action.instruction_complete && !action.commit_base)
        );
        assert!(
            actions[first_complete..]
                .iter()
                .all(|action| action.instruction_complete)
        );
        assert!(actions.iter().any(|action| {
            action.commit_base && action.base_coordinate == BiasedBaseCoordinate::Host
        }));
        assert!(actions.iter().any(|action| {
            action.commit_base && action.base_coordinate == BiasedBaseCoordinate::Guest
        }));
        assert!(!actions.last().expect("last recovery").commit_base);
    }

    #[test]
    fn biased_dual_virtual_cleanup_does_not_recommit_restored_scratch() {
        let word = 0xf940_0392; // ldr x18, [x28]
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify dual virtual load"),
        }];
        let host_bias =
            crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias");
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate dual cache");
        let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })
            .expect("emit dual virtual load");
        let final_actions = emitted
            .recovery()
            .iter()
            .filter_map(|entry| match entry.action {
                RecoveryAction::RecoverBiasedMemory(recovery) => Some(recovery),
                _ => None,
            })
            .rev()
            .take(4)
            .collect::<Vec<_>>();
        assert_eq!(final_actions.len(), 4);
        assert!(final_actions.iter().all(|action| {
            action.instruction_complete
                && action.virtual_x18_scratch.is_none()
                && action.virtual_x28_scratch.is_none()
        }));
    }

    #[test]
    fn dual_virtual_move_commits_x28_snapshot() {
        let word = 0xaa12_03fc; // mov x28, x18
        let mut plan = copy_plan();
        plan.instructions = vec![PlannedInst {
            guest: GuestVa(0x4000),
            action: super::super::decode::classify(word, GuestVa(0x4000))
                .expect("classify dual virtual move"),
        }];
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate dual cache");
        let emitted =
            emit_block(&mut cache, &plan, EmitAddressMode::Direct).expect("emit dual virtual move");
        assert!(emitted.recovery().iter().any(|entry| {
            matches!(
                entry.action,
                RecoveryAction::CommitDualVirtualAndRestore {
                    virtual_register: 28,
                    ..
                }
            )
        }));
    }

    #[test]
    fn dsr_direct_unsupported_memory_action_emits_the_original_word() {
        let word = 0x8598_5f6f;
        let action = super::super::decode::classify(word, GuestVa(0x4000))
            .expect("classify direct SVE memory");
        assert!(matches!(
            action,
            InstAction::Memory(memory) if memory.class == MemoryClass::Unsupported
        ));
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4008),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action,
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
        .expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit direct SVE memory block");
        let pointer = (emitted.entry().host().raw() + 8) as *const u32;
        assert_eq!(unsafe { std::ptr::read_unaligned(pointer) }, word);
    }

    #[test]
    fn dsr_direct_unsupported_memory_keeps_virtual_index_rewrite() {
        let word = 0xa452_48af;
        let action = super::super::decode::classify(word, GuestVa(0x4000))
            .expect("classify direct SVE x18-index memory");
        assert!(matches!(
            action,
            InstAction::Memory(memory)
                if memory.class == MemoryClass::Unsupported
                    && memory.virtualization
                        == super::super::types::MemoryVirtualization::X18
        ));
        let plan = BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x4008),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest: GuestVa(0x4000),
                action,
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
        .expect("allocate translation cache");
        emit_block_direct(&mut cache, &plan).expect("emit direct SVE x18-index memory block");
    }

    #[test]
    fn dsr_generation_guard_has_recovery_for_every_interruptible_instruction() {
        use std::sync::atomic::AtomicU64;

        let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block_with_generation_direct(
            &mut cache,
            &copy_plan(),
            GenerationGuard::new(&generation, CodeGeneration::INITIAL),
        )
        .expect("emit guarded block");
        let words = (0..emitted.len() / 4)
            .map(|index| unsafe {
                std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
            })
            .collect::<Vec<_>>();
        let first_guest = words
            .iter()
            .position(|word| *word == 0xd503_201f)
            .expect("first copied guest instruction");
        for index in 0..first_guest {
            let offset = CacheOffset::published((index * 4) as u32);
            assert!(
                emitted.recovery().iter().any(|entry| entry.cache == offset),
                "generation-guard instruction at cache offset {} has no recovery metadata",
                offset.get()
            );
        }
    }

    #[test]
    fn dsr_emit_relocates_pc_relative_address_subset() {
        let mut plan = copy_plan();
        plan.instructions[0].action = InstAction::PcRelative(PcRelativeInst {
            kind: PcRelativeKind::Adr,
            target: GuestVa(0x5000),
            destination: Some(bad64::Reg::X0),
            word: 0x1000_8000,
        });
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit relocated ADR");
        assert!(emitted.len() > 36);
    }

    #[test]
    fn dsr_emit_direct_link_and_indirect_resolver_exit() {
        let mut direct = copy_plan();
        direct.exit = PlannedExit::Direct {
            guest: GuestVa(0x4008),
            word: 0x1400_0002,
            exit: DirectExit {
                kind: DirectKind::Branch,
                target: GuestVa(0x4010),
                resume: GuestVa(0x400c),
                condition: None,
                register: None,
                bit: None,
            },
        };
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &direct).expect("emit direct link");
        assert_eq!(emitted.direct_links().len(), 1);
        assert_eq!(emitted.direct_links()[0].target, GuestVa(0x4010));

        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd61f_0000,
            exit: IndirectExit {
                kind: IndirectKind::Branch,
                register: bad64::Reg::X0,
                resume: GuestVa(0x400c),
            },
        };
        let emitted =
            emit_block_direct(&mut cache, &indirect).expect("emit indirect resolver exit");
        assert!(emitted.direct_links().is_empty());
    }

    #[test]
    fn dsr_return_publishes_guest_lr_without_physical_x18_staging() {
        let mut plan = copy_plan();
        plan.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd65f_03c0,
            exit: IndirectExit {
                kind: IndirectKind::Return,
                register: bad64::Reg::X30,
                resume: GuestVa(0x400c),
            },
        };
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate return cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit return resolver");
        let words = (0..emitted.len() / 4)
            .map(|index| unsafe {
                std::ptr::read_unaligned((emitted.entry().host().raw() + index * 4) as *const u32)
            })
            .collect::<Vec<_>>();
        let direct_lr_store = 0xf900_0000 | ((1080 / 8) << 10) | (28 << 5) | 30; // str x30, [x28, #1080]

        assert!(
            words.contains(&direct_lr_store),
            "return resolver must publish guest x30 directly"
        );
        assert!(
            !words.contains(&0xaa1e_03f2),
            "return resolver must not stage guest x30 through physical x18"
        );
    }

    #[test]
    fn dsr_every_emitted_instruction_has_a_guest_pc_mapping() {
        let mut plans = vec![copy_plan()];
        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd63f_0000,
            exit: IndirectExit {
                kind: IndirectKind::Call,
                register: bad64::Reg::X0,
                resume: GuestVa(0x400c),
            },
        };
        plans.push(indirect);

        let mut cache = TranslationCache::new(
            32 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        for plan in plans {
            let emitted = emit_block_direct(&mut cache, &plan).expect("emit mapped block");
            for offset in (0..emitted.len()).step_by(4) {
                let offset = CacheOffset::published(offset as u32);
                assert!(
                    emitted.map().guest_for_cache(offset).is_some(),
                    "emitted instruction at cache offset {} has no guest PC mapping",
                    offset.get()
                );
            }
        }
    }

    #[test]
    fn dsr_indirect_resolver_recovery_is_contiguous_after_scratch_mutation() {
        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd65f_03c0,
            exit: IndirectExit {
                kind: IndirectKind::Return,
                register: bad64::Reg::X30,
                resume: GuestVa(0x400c),
            },
        };
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &indirect).expect("emit indirect resolver");
        let resolver = emitted
            .recovery()
            .iter()
            .filter(|entry| {
                matches!(
                    entry.action,
                    RecoveryAction::RestoreIndirectRegisters
                        | RecoveryAction::RestoreIndirectResolver
                )
            })
            .collect::<Vec<_>>();
        assert!(
            matches!(
                resolver.first().map(|entry| entry.action),
                Some(RecoveryAction::RestoreIndirectRegisters)
            ),
            "resolver must publish its partial recovery point first"
        );
        assert!(
            resolver
                .iter()
                .skip(1)
                .all(|entry| entry.action == RecoveryAction::RestoreIndirectResolver),
            "every instruction after the scratch snapshot must have full recovery"
        );
        assert!(
            resolver
                .windows(2)
                .all(|pair| pair[1].cache.get() == pair[0].cache.get() + 4),
            "resolver recovery metadata must cover every instruction without gaps"
        );
        assert!(
            emitted
                .recovery()
                .iter()
                .any(|entry| entry.action == RecoveryAction::RestoreGuestX17),
            "internal x17 edges need a target-entry recovery point"
        );
    }

    #[test]
    fn dsr_emit_continue_exit_is_a_lazy_direct_link() {
        let mut plan = copy_plan();
        plan.instructions.truncate(1);
        plan.end = GuestVa(0x4004);
        plan.exit = PlannedExit::Continue {
            target: GuestVa(0x4004),
            limit: BlockLimit::InstructionLimit,
        };
        let mut cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let emitted = emit_block_direct(&mut cache, &plan).expect("emit bounded block");
        assert_eq!(emitted.direct_links().len(), 1);
        assert_eq!(emitted.direct_links()[0].target, GuestVa(0x4004));
        assert_eq!(
            emitted.map().guest_for_cache(CacheOffset::published(12)),
            Some(GuestVa(0x4004))
        );
    }

    mod exclusive_region_emission {
        use super::super::super::types::{
            BiasedExclusiveScratch, DsrScratchGpr, ExclusiveFusionDisposition, ExclusiveFusionSite,
            ExclusiveRegionExit,
        };
        use super::*;

        // ldaxr w0, [x1] / cmp w0, w2 / stlxr w3, w4, [x1] -- verified encodings
        // shared with the block planner's fusion tests.
        const LDAXR_W0_X1: u32 = 0x885f_fc20;
        const CMP_W0_W2: u32 = 0x6b02_001f;
        const STLXR_W3_W4_X1: u32 = 0x8803_fc24;
        const CLREX: u32 = 0xd503_3f5f;

        struct TestEmittedBlock {
            _cache: TranslationCache,
            emitted: EmittedBlock,
        }

        impl std::ops::Deref for TestEmittedBlock {
            type Target = EmittedBlock;

            fn deref(&self) -> &Self::Target {
                &self.emitted
            }
        }

        fn encode_b_cond(pc: GuestVa, target: GuestVa, cond: u32) -> u32 {
            let offset = (target.raw() as i64 - pc.raw() as i64) / 4;
            let imm19 = (offset as u32) & 0x7_ffff;
            0x5400_0000 | (imm19 << 5) | cond
        }

        fn encode_cbnz_w(pc: GuestVa, target: GuestVa, rt: u32) -> u32 {
            let offset = (target.raw() as i64 - pc.raw() as i64) / 4;
            let imm19 = (offset as u32) & 0x7_ffff;
            0x3500_0000 | (imm19 << 5) | rt
        }

        fn with_base_register(word: u32, register: u32) -> u32 {
            (word & !(0x1f << 5)) | (register << 5)
        }

        /// Build the `ExclusiveRegion` `BlockPlan` the planner would produce for
        /// the straight-line region `words` (load .. store) with the given retry
        /// and optional early-exit encodings.
        fn region_plan(
            start: GuestVa,
            words: &[u32],
            retry_word: u32,
            early_exit_word: Option<u32>,
        ) -> BlockPlan {
            let mut instructions = Vec::new();
            for (index, &word) in words.iter().enumerate() {
                let guest = GuestVa(start.raw() + (index as u64) * 4);
                let action = if let Some((_, memory)) =
                    super::super::super::decode::classify_exclusive(word, guest)
                        .expect("classify region exclusive")
                {
                    InstAction::Memory(memory)
                } else {
                    super::super::super::decode::classify(word, guest)
                        .expect("classify region body")
                };
                instructions.push(PlannedInst { guest, action });
            }
            let store_guest = GuestVa(start.raw() + ((words.len() - 1) as u64) * 4);
            let retry_pc = GuestVa(store_guest.raw() + 4);
            let end = GuestVa(retry_pc.raw() + 4);
            BlockPlan {
                start,
                end,
                generation: CodeGeneration::INITIAL,
                instructions,
                exit: PlannedExit::ExclusiveRegion {
                    guest: start,
                    word: words[0],
                    exit: ExclusiveRegionExit {
                        start,
                        end,
                        retry_edge: start,
                        load_word: words[0],
                        store_word: *words.last().unwrap(),
                        retry_word,
                        early_exit_word,
                        fallback: SensitiveExit {
                            kind: SensitiveKind::Exclusive(words[0]),
                            register: None,
                            resume: GuestVa(start.raw() + 4),
                        },
                    },
                    fusion: ExclusiveFusionSite {
                        guest: start,
                        word: words[0],
                        disposition: ExclusiveFusionDisposition::FusedDirect,
                        biased_scratch: None,
                    },
                },
            }
        }

        fn emitted_words(emitted: &EmittedBlock) -> Vec<u32> {
            (0..emitted.len() / 4)
                .map(|index| unsafe {
                    std::ptr::read_unaligned(
                        (emitted.entry().host().raw() + index * 4) as *const u32,
                    )
                })
                .collect()
        }

        fn emit_test_biased_cas() -> Result<TestEmittedBlock, DsrError> {
            let start = GuestVa(0x4000);
            let branch = encode_b_cond(GuestVa(0x4008), GuestVa(0x4014), 1);
            let retry = encode_cbnz_w(GuestVa(0x4010), start, 3);
            let mut plan = region_plan(
                start,
                &[LDAXR_W0_X1, CMP_W0_W2, branch, STLXR_W3_W4_X1],
                retry,
                Some(branch),
            );
            let scratch = BiasedExclusiveScratch {
                address: DsrScratchGpr::new(17).expect("x17 scratch"),
                bias: DsrScratchGpr::new(16).expect("x16 scratch"),
            };
            let PlannedExit::ExclusiveRegion { fusion, .. } = &mut plan.exit else {
                panic!("test plan must be an exclusive region");
            };
            fusion.disposition = ExclusiveFusionDisposition::FusedBiased;
            fusion.biased_scratch = Some(scratch);

            let host_bias =
                crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                    .expect("construct test host bias");
            let mut cache = TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate cache");
            let emitted = emit_block(&mut cache, &plan, EmitAddressMode::Biased { host_bias })?;
            Ok(TestEmittedBlock {
                _cache: cache,
                emitted,
            })
        }

        fn word_touches_memory(word: u32, pc: u64) -> bool {
            bad64::decode(word, pc).is_ok_and(|inst| {
                inst.operands().iter().any(|operand| {
                    matches!(
                        operand,
                        bad64::Operand::MemReg(_)
                            | bad64::Operand::MemOffset { .. }
                            | bad64::Operand::MemPreIdx { .. }
                            | bad64::Operand::MemPostIdxImm { .. }
                            | bad64::Operand::MemPostIdxReg(_)
                            | bad64::Operand::MemExt { .. }
                    )
                })
            })
        }

        #[test]
        fn biased_region_rewrites_only_the_exclusive_base_and_keeps_pair_clean() {
            let emitted = emit_test_biased_cas().expect("emit biased CAS");
            let words = emitted_words(&emitted);
            let rewritten_load = with_base_register(LDAXR_W0_X1, 17);
            let rewritten_store = with_base_register(STLXR_W3_W4_X1, 17);
            let load = words
                .iter()
                .position(|word| *word == rewritten_load)
                .expect("rewritten load");
            let store = words
                .iter()
                .position(|word| *word == rewritten_store)
                .expect("rewritten store");
            assert!(!words.contains(&LDAXR_W0_X1));
            assert!(!words.contains(&STLXR_W3_W4_X1));
            for (offset, word) in words[load + 1..store].iter().copied().enumerate() {
                let pc = emitted.entry().host().raw() as u64 + ((load + 1 + offset) * 4) as u64;
                assert!(
                    !word_touches_memory(word, pc),
                    "memory word 0x{word:08x} inside pair"
                );
            }
        }

        #[test]
        fn biased_region_recovery_covers_every_post_spill_instruction() {
            let emitted = emit_test_biased_cas().expect("emit biased CAS");
            let words = emitted_words(&emitted);
            let save_address = 0xf900_0000 | ((1120 / 8) << 10) | (28 << 5) | 17;
            let save_bias = 0xf900_0000 | ((1128 / 8) << 10) | (28 << 5) | 16;
            let first_spill = words
                .iter()
                .position(|word| *word == save_address)
                .expect("address scratch spill");
            assert_eq!(words[first_spill + 1], save_bias);
            assert!(emitted.recovery().iter().any(|entry| {
                entry.cache.get() == ((first_spill + 1) * 4) as u32
                    && entry.action == RecoveryAction::Noop
            }));
            let offsets = emitted
                .recovery()
                .iter()
                .filter(|entry| matches!(entry.action, RecoveryAction::RecoverBiasedExclusive(_)))
                .map(|entry| entry.cache.get())
                .collect::<Vec<_>>();
            assert!(
                offsets.len() > 4,
                "prelude, pair, retry, and restores need recovery"
            );
            assert_eq!(offsets[0], ((first_spill + 2) * 4) as u32);
            assert!(offsets.windows(2).all(|pair| pair[1] == pair[0] + 4));
            assert!(offsets.iter().all(|offset| {
                emitted
                    .recovery()
                    .iter()
                    .find(|entry| entry.cache.get() == *offset)
                    .is_some_and(|entry| !entry.action.instruction_complete())
            }));

            let rewritten_load = with_base_register(LDAXR_W0_X1, 17);
            let rewritten_store = with_base_register(STLXR_W3_W4_X1, 17);
            let load = words
                .iter()
                .position(|word| *word == rewritten_load)
                .expect("rewritten load");
            let store = words
                .iter()
                .position(|word| *word == rewritten_store)
                .expect("rewritten store");
            for (index, expected_guest) in [(load, GuestVa(0x4000)), (store, GuestVa(0x400c))] {
                let offset = CacheOffset::published((index * 4) as u32);
                assert_eq!(emitted.map().guest_for_cache(offset), Some(expected_guest));
                assert!(emitted.recovery().iter().any(|entry| {
                    entry.cache == offset
                        && matches!(
                            entry.action,
                            RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
                                resume: BiasedExclusiveResume::Exact,
                                ..
                            })
                        )
                }));
            }
            let retry = words[store + 1..]
                .iter()
                .enumerate()
                .find_map(|(offset, word)| {
                    let index = store + 1 + offset;
                    bad64::decode(
                        *word,
                        emitted.entry().host().raw() as u64 + (index * 4) as u64,
                    )
                    .ok()
                    .filter(|instruction| instruction.op() == bad64::Op::CBNZ)
                    .map(|_| index)
                })
                .expect("rewritten retry branch");
            let retry_offset = CacheOffset::published((retry * 4) as u32);
            assert_eq!(
                emitted.map().guest_for_cache(retry_offset),
                Some(GuestVa(0x4010))
            );
            assert!(emitted.recovery().iter().any(|entry| {
                entry.cache == retry_offset
                    && matches!(
                        entry.action,
                        RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
                            resume: BiasedExclusiveResume::Retry,
                            ..
                        })
                    )
            }));
        }

        #[test]
        fn biased_exclusive_emitted_map_resumes_each_guest_instruction_exactly() {
            let emitted = emit_test_biased_cas().expect("emit biased CAS");
            let words = emitted_words(&emitted);
            let rewritten_load = with_base_register(LDAXR_W0_X1, 17);
            let rewritten_store = with_base_register(STLXR_W3_W4_X1, 17);
            let load = words
                .iter()
                .position(|word| *word == rewritten_load)
                .expect("rewritten load");
            let store = words
                .iter()
                .position(|word| *word == rewritten_store)
                .expect("rewritten store");
            let pre_load = emitted
                .recovery()
                .iter()
                .find(|entry| {
                    entry.cache.get() < (load * 4) as u32
                        && matches!(entry.action, RecoveryAction::RecoverBiasedExclusive(_))
                })
                .expect("pre-load recovery entry");
            let between_pair = emitted
                .recovery()
                .iter()
                .find(|entry| {
                    entry.cache.get() > (load * 4) as u32
                        && entry.cache.get() < (store * 4) as u32
                        && matches!(entry.action, RecoveryAction::RecoverBiasedExclusive(_))
                })
                .expect("between-pair recovery entry");
            let post_store = emitted
                .recovery()
                .iter()
                .find(|entry| {
                    entry.cache.get() > (store * 4) as u32
                        && matches!(
                            entry.action,
                            RecoveryAction::RecoverBiasedExclusive(BiasedExclusiveRecovery {
                                resume: BiasedExclusiveResume::Retry,
                                ..
                            })
                        )
                })
                .expect("post-store recovery entry");

            assert_eq!(
                emitted.map().guest_for_cache(pre_load.cache),
                Some(GuestVa(0x4000))
            );
            assert_eq!(
                emitted.map().guest_for_cache(between_pair.cache),
                Some(GuestVa(0x4004))
            );
            assert!(!pre_load.action.instruction_complete());
            assert!(!between_pair.action.instruction_complete());
            assert_eq!(
                emitted.map().guest_for_cache(post_store.cache),
                Some(GuestVa(0x4010))
            );
            assert!(!post_store.action.instruction_complete());
        }

        #[test]
        fn biased_exclusive_recovery_preserves_captured_state_at_every_boundary() {
            let emitted = emit_test_biased_cas().expect("emit biased CAS");
            let recoveries = emitted
                .recovery()
                .iter()
                .filter(|entry| matches!(entry.action, RecoveryAction::RecoverBiasedExclusive(_)))
                .collect::<Vec<_>>();
            assert!(
                !recoveries.is_empty(),
                "biased region must publish recovery metadata"
            );

            for entry in recoveries {
                let mut snapshot = crate::native_darwin::NativeUcontextSnapshot::default();
                for (index, value) in snapshot.x.iter_mut().enumerate() {
                    *value = 0x1000 + index as u64;
                }
                snapshot.pstate = 0xa000_0000;
                let before = snapshot.x;
                let before_pstate = snapshot.pstate;

                super::super::super::recover_rewrite_state(
                    &mut snapshot,
                    entry.action,
                    0x1717,
                    0x1616,
                    0,
                    0,
                    0,
                )
                .expect("recover biased exclusive boundary");

                for (index, original) in before.into_iter().enumerate() {
                    let expected = match index {
                        17 => 0x1717,
                        16 => 0x1616,
                        _ => original,
                    };
                    assert_eq!(
                        snapshot.x[index],
                        expected,
                        "cache offset {} changed guest x{index}",
                        entry.cache.get()
                    );
                }
                assert_eq!(snapshot.pstate, before_pstate);
                let guest = emitted
                    .map()
                    .guest_for_cache(entry.cache)
                    .expect("recovery boundary must have a guest PC");
                assert_eq!(
                    super::super::super::recovery_resume_pc(guest, Some(entry.action))
                        .expect("recover mapped guest PC"),
                    guest.raw()
                );
            }
        }

        #[test]
        fn biased_region_slow_stub_restores_scratches_before_sensitive_exit() {
            let emitted = emit_test_biased_cas().expect("emit biased CAS");
            let words = emitted_words(&emitted);
            let base = emitted.entry().host().raw() as u64;
            let lsr_address = 0xd340_fc00 | (BIASED_FAST_ADDRESS_BITS << 16) | (17 << 5) | 16;
            let validation = words
                .iter()
                .position(|word| *word == lsr_address)
                .expect("address aperture validation");
            let slow_branch = validation + 2;
            let slow_pc = base + (slow_branch * 4) as u64;
            let InstAction::Direct(slow) =
                super::super::super::decode::classify(words[slow_branch], GuestVa(slow_pc))
                    .expect("decode slow branch")
            else {
                panic!("invalid-address edge must branch to its restore stub");
            };
            let slow_restore =
                usize::try_from((slow.target.raw() - base) / 4).expect("slow restore index");
            let restore_address = 0xf940_0000 | ((1120 / 8) << 10) | (28 << 5) | 17;
            let restore_bias = 0xf940_0000 | ((1128 / 8) << 10) | (28 << 5) | 16;
            assert_eq!(
                &words[slow_restore..slow_restore + 2],
                &[restore_address, restore_bias]
            );

            let tail_branch = slow_restore + 2;
            let tail_pc = base + (tail_branch * 4) as u64;
            let InstAction::Direct(tail) =
                super::super::super::decode::classify(words[tail_branch], GuestVa(tail_pc))
                    .expect("decode slow-tail branch")
            else {
                panic!("restored slow edge must branch to the sensitive tail");
            };
            let slow_tail =
                usize::try_from((tail.target.raw() - base) / 4).expect("slow tail index");
            let status_six = 0x5280_0000 | (6 << 5) | 17;
            let status = words[slow_tail..]
                .iter()
                .position(|word| *word == status_six)
                .map(|offset| slow_tail + offset)
                .expect("status-6 sensitive exit");
            let target_store = 0xf900_0000 | ((1080 / 8) << 10) | (28 << 5) | 17;
            let target = words[slow_tail..status]
                .iter()
                .position(|word| *word == target_store)
                .map(|offset| slow_tail + offset)
                .expect("sensitive exit target store");
            let target_value = [
                0xd280_0000 | (0x4004 << 5) | 17,
                0xf280_0000 | (1 << 21) | 17,
                0xf280_0000 | (2 << 21) | 17,
                0xf280_0000 | (3 << 21) | 17,
            ];
            assert_eq!(
                &words[target - target_value.len()..target],
                &target_value,
                "slow sensitive exit target must use the published fallback resume PC"
            );
            let source_store = 0xf900_0000 | ((1088 / 8) << 10) | (28 << 5) | 17;
            let source = words[..status]
                .iter()
                .rposition(|word| *word == source_store)
                .expect("sensitive exit source store");
            let source_value = [
                0xd280_0000 | (0x4000 << 5) | 17,
                0xf280_0000 | (1 << 21) | 17,
                0xf280_0000 | (2 << 21) | 17,
                0xf280_0000 | (3 << 21) | 17,
            ];
            assert_eq!(
                &words[source - source_value.len()..source],
                &source_value,
                "slow sensitive exit source must be the original load PC"
            );
        }

        /// (a) A minimal fused region (`ldxr; stxr; cbnz`) emits the exclusive
        /// load and store verbatim and ADJACENT -- proving no block prologue or
        /// context store lands between them (Hazard A).
        #[test]
        fn emits_load_and_store_verbatim_and_adjacent() {
            let start = GuestVa(0x4000);
            let store_pc = GuestVa(0x4004);
            let retry_pc = GuestVa(0x4008);
            let retry = encode_cbnz_w(retry_pc, start, 3);
            let plan = region_plan(start, &[LDAXR_W0_X1, STLXR_W3_W4_X1], retry, None);

            let mut cache = TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate cache");
            let emitted =
                emit_block_direct(&mut cache, &plan).expect("emit fused minimal exclusive region");
            let words = emitted_words(&emitted);

            let load_index = words
                .iter()
                .position(|&word| word == LDAXR_W0_X1)
                .expect("emitted stream must contain the exclusive load verbatim");
            assert_eq!(
                words[load_index + 1],
                STLXR_W3_W4_X1,
                "the exclusive store must immediately follow the load (no instruction between)"
            );
            let _ = store_pc;
            assert!(
                !words.contains(&CLREX),
                "a region with no early-exit edge has no non-completing exit, so no CLREX"
            );
        }

        /// (b) The canonical CAS region emits exactly one CLREX -- on the
        /// compare-failure early-exit edge (Hazard B) -- and NOTHING that
        /// touches memory sits between the exclusive load and store.
        #[test]
        fn emits_clrex_on_the_compare_failure_edge_only() {
            let start = GuestVa(0x4000);
            let branch_pc = GuestVa(0x4008);
            let store_pc = GuestVa(0x400c);
            let retry_pc = GuestVa(0x4010);
            let out_pc = GuestVa(0x4014);
            let branch = encode_b_cond(branch_pc, out_pc, 1);
            let retry = encode_cbnz_w(retry_pc, start, 3);
            let plan = region_plan(
                start,
                &[LDAXR_W0_X1, CMP_W0_W2, branch, STLXR_W3_W4_X1],
                retry,
                Some(branch),
            );

            let mut cache = TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate cache");
            let emitted =
                emit_block_direct(&mut cache, &plan).expect("emit fused canonical CAS region");
            let words = emitted_words(&emitted);

            assert_eq!(
                words.iter().filter(|&&word| word == CLREX).count(),
                1,
                "exactly one CLREX, on the single non-completing (compare-failure) edge"
            );

            let load_index = words
                .iter()
                .position(|&word| word == LDAXR_W0_X1)
                .expect("emitted stream must contain the exclusive load verbatim");
            let store_index = words
                .iter()
                .position(|&word| word == STLXR_W3_W4_X1)
                .expect("emitted stream must contain the exclusive store verbatim");
            assert!(store_index > load_index);
            for (offset, &word) in words[load_index + 1..store_index].iter().enumerate() {
                let pc =
                    emitted.entry().host().raw() as u64 + ((load_index + 1 + offset) * 4) as u64;
                assert!(
                    !word_touches_memory(word, pc),
                    "no memory access may sit between LDXR and STXR (Hazard A): 0x{word:08x}"
                );
            }
            let _ = store_pc;

            // Both exit edges leave to guest VAs via the direct-link resolver.
            let targets: std::collections::BTreeSet<_> = emitted
                .direct_links()
                .iter()
                .map(|link| link.target)
                .collect();
            assert!(
                targets.contains(&out_pc),
                "an exit edge resolves to `end`/`out`"
            );
        }

        /// Every emitted word must be a valid AArch64 instruction, and the two
        /// re-encoded region branches (the compare-failure and retry edges) must
        /// stay the same op family and branch to their block-local trampoline
        /// (taken -> PC+8), never to the original guest displacement.
        #[test]
        fn re_encoded_region_branches_decode_and_target_their_trampolines() {
            let start = GuestVa(0x4000);
            let branch = encode_b_cond(GuestVa(0x4008), GuestVa(0x4014), 1);
            let retry = encode_cbnz_w(GuestVa(0x4010), start, 3);
            let plan = region_plan(
                start,
                &[LDAXR_W0_X1, CMP_W0_W2, branch, STLXR_W3_W4_X1],
                retry,
                Some(branch),
            );

            let mut cache = TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate cache");
            let emitted = emit_block_direct(&mut cache, &plan).expect("emit fused CAS region");
            let base = emitted.entry().host().raw() as u64;
            let words = emitted_words(&emitted);

            for (index, &word) in words.iter().enumerate() {
                let pc = base + (index * 4) as u64;
                assert!(
                    bad64::decode(word, pc).is_ok(),
                    "emitted word 0x{word:08x} at +{} must decode",
                    index * 4
                );
            }

            // Re-encoded branch decodes to the same op and, when taken, jumps to
            // its own PC+8 trampoline (not the original guest displacement).
            let relocated_target = |word: u32, pc: u64| -> Option<GuestVa> {
                match super::super::super::decode::classify(word, GuestVa(pc)) {
                    Ok(InstAction::Direct(direct)) => Some(direct.target),
                    _ => None,
                }
            };
            let assert_branch_targets_trampoline = |op: bad64::Op| {
                let (pc, word) = words
                    .iter()
                    .enumerate()
                    .find_map(|(index, &word)| {
                        let pc = base + (index * 4) as u64;
                        bad64::decode(word, pc)
                            .ok()
                            .filter(|inst| inst.op() == op)
                            .map(|_| (pc, word))
                    })
                    .unwrap_or_else(|| panic!("re-encoded {op:?} branch must be present"));
                assert_eq!(
                    relocated_target(word, pc),
                    Some(GuestVa(pc + 8)),
                    "re-encoded {op:?} branch must target its +8 trampoline"
                );
            };
            // The compare-failure edge (b.ne) and the retry edge (cbnz).
            assert_branch_targets_trampoline(bad64::Op::B_NE);
            assert_branch_targets_trampoline(bad64::Op::CBNZ);
        }

        /// (d) The biased path never fuses; if an exclusive `Memory` action ever
        /// reaches biased emission the `:1442` tripwire must still fire.
        #[test]
        fn biased_exclusive_memory_tripwire_still_fires() {
            let word = LDAXR_W0_X1;
            let (_, memory) =
                super::super::super::decode::classify_exclusive(word, GuestVa(0x4000))
                    .expect("classify exclusive")
                    .expect("exclusive load");
            let mut plan = copy_plan();
            plan.instructions = vec![PlannedInst {
                guest: GuestVa(0x4000),
                action: InstAction::Memory(memory),
            }];
            plan.end = GuestVa(0x4008);
            plan.exit = PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008),
            };
            let bias =
                crate::native_darwin::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                    .expect("construct test host bias");
            let mut cache = TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate cache");
            let result = emit_block(
                &mut cache,
                &plan,
                EmitAddressMode::Biased { host_bias: bias },
            );
            match result {
                Err(DsrError::UnsupportedBlockAction { .. }) => {}
                Err(other) => {
                    panic!("biased exclusive emission failed with the wrong error: {other:?}")
                }
                Ok(_) => panic!("biased exclusive emission must trip the :1442 tripwire"),
            }
        }
    }
}
