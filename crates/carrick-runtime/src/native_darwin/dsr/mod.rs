//! Shim: the DSR translator orchestration (`ProcessTranslator` /
//! `ThreadTranslator`, `ThreadExit` dispatch, resolver stats, the sibling
//! profile registry, `encode_aarch64_direct_branch`) moved verbatim to
//! `carrick_dsr_aarch64::translator` as the extraction-completing slice of
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md;
//! re-exported so existing `dsr::*` call paths resolve unchanged.
//!
//! What stays here: the still-runtime-resident live-execution ORACLE
//! (`oracle`, `#[cfg(test)]`), the shim submodules below (each already a
//! re-export of its extracted home), the Darwin counter-fallback wrapper,
//! and the JIT-entangled test suite (it drives the Darwin host JIT and the
//! runtime thread loop, neither of which links from the arch crate before
//! the host-seam slice M0.6).

pub(crate) mod artifact_spike;
pub(super) mod block;
pub(super) mod cache;
pub(super) mod counter;
pub(super) mod decode;
pub(super) mod emit;
pub(super) mod gateway;
// The live-execution oracle installs the Darwin C-shim trap handlers, reads
// the Mach counter, and runs translated AArch64 through the assembled
// gateway — Darwin/AArch64-only by construction until the host-seam slice
// (M0.6) gives other hosts a real shim.
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod oracle;
pub(super) mod profile;
pub(super) mod types;

#[allow(unused_imports)]
pub(in crate::native_darwin) use carrick_dsr_aarch64::translator::*;

#[cfg(target_os = "macos")]
pub(super) fn fallback_counter_ticks() -> Option<u64> {
    counter::fallback_counter_ticks()
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(super) fn host_counter_plan_is_inline_for_test() -> bool {
    matches!(
        counter::host_counter_plan(),
        counter::HostCounterPlan::Inline { .. }
    )
}

/// Install the runtime's Darwin host JIT into the arch crate's seam before a
/// test constructs a translator/cache through the moved code (production
/// installs happen in `install_native_probe_sink` at every backend entry).
/// Idempotent, first-install-wins.
#[cfg(test)]
pub(super) fn install_test_host_jit() {
    carrick_dsr_aarch64::translator::install_host_jit(
        crate::native_darwin::darwin_jit::active_host_jit(),
    );
}

/// [`ProcessTranslator::new`] with the host JIT seam pre-installed — the
/// shape every pre-extraction test used (`new` reached the Darwin JIT as a
/// process-global; the seam keeps that contract once installed).
#[cfg(test)]
pub(super) fn test_process_translator(
    capacity: usize,
) -> Result<ProcessTranslator, types::DsrError> {
    install_test_host_jit();
    ProcessTranslator::new(capacity)
}

/// [`ThreadTranslator::new`] with the host JIT seam pre-installed (see
/// [`test_process_translator`]).
#[cfg(test)]
pub(super) fn test_thread_translator(capacity: usize) -> Result<ThreadTranslator, types::DsrError> {
    install_test_host_jit();
    ThreadTranslator::new(capacity)
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(super) fn execute_virtual_counter_for_test() -> Result<u64, types::DsrError> {
    let guest = carrick_guest_mem::GuestVa(0x19_000);
    let plan = block::BlockPlan {
        start: guest,
        end: carrick_guest_mem::GuestVa(guest.raw() + 8),
        generation: types::CodeGeneration::INITIAL,
        instructions: vec![block::PlannedInst {
            guest,
            action: types::InstAction::CounterRead(types::CounterRead {
                destination: types::CounterDestination::Gpr(2),
            }),
        }],
        exit: block::PlannedExit::Syscall {
            guest: carrick_guest_mem::GuestVa(guest.raw() + 4),
            resume: carrick_guest_mem::GuestVa(guest.raw() + 8),
        },
        extensions: Vec::new(),
    };
    let mut cache = cache::TranslationCache::new(
        16 * 1024,
        crate::native_darwin::darwin_jit::active_host_jit(),
    )?;
    let emitted = emit::emit_block_direct(&mut cache, &plan)?;
    let mut stack = vec![0_u8; 16 * 1024];
    let mut snapshot = super::NativeUcontextSnapshot {
        sp: stack.as_mut_ptr() as u64 + stack.len() as u64,
        ..super::NativeUcontextSnapshot::default()
    };
    let mut exit = types::NativeDsrExit::Syscall {
        resume: carrick_guest_mem::GuestVa(guest.raw() + 8),
    };
    gateway::enter_translated(emitted.entry(), &mut snapshot, &mut exit)?;
    Ok(snapshot.x[2])
}

// `recovery_resume_pc` / `recover_rewrite_state` live in
// `carrick_dsr_aarch64::emit` with the emitter whose `RecoveryAction`s they
// interpret; imported so `super::recover_rewrite_state` call paths (the
// oracle and the tests below) resolve unchanged.
#[allow(unused_imports)]
pub(super) use carrick_dsr_aarch64::emit::{recover_rewrite_state, recovery_resume_pc};

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::decode::classify;
    use super::types::{
        CounterDestination, CounterRead, DirectKind, IndirectKind, InstAction, MemoryBase,
        MemoryClass, MemoryVirtualization, MemoryWriteback, PcRelativeKind, SensitiveKind,
    };
    use carrick_guest_mem::{GuestMemory, GuestVa};
    use proptest::prelude::*;

    const PC: GuestVa = GuestVa(0x1000);

    fn fork_test(test: impl FnOnce() + std::panic::UnwindSafe) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let passed = std::panic::catch_unwind(test).is_ok();
            unsafe { libc::_exit(i32::from(!passed)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    fn biased_recovery_fixture(
        base: super::emit::BiasedBase,
        coordinate: super::emit::BiasedBaseCoordinate,
        complete: bool,
    ) -> super::emit::RecoveryAction {
        super::emit::RecoveryAction::RecoverBiasedMemory(super::emit::BiasedMemoryRecovery {
            scratch_registers: [9, 10, 0, 0],
            scratch_count: 2,
            base_scratch: 9,
            base,
            base_coordinate: coordinate,
            commit_base: true,
            virtual_x18_scratch: None,
            virtual_x28_scratch: None,
            virtual_reserved_scratch: None,
            host_bias: super::super::address::NativeHostBias::new(0x80_0000_0000, 16 * 1024)
                .expect("construct host bias"),
            instruction_complete: complete,
        })
    }

    #[test]
    fn biased_recovery_resume_and_wrapping_writeback_are_architectural() {
        let retry = biased_recovery_fixture(
            super::emit::BiasedBase::Register(0),
            super::emit::BiasedBaseCoordinate::Host,
            false,
        );
        let completed = biased_recovery_fixture(
            super::emit::BiasedBase::Register(0),
            super::emit::BiasedBaseCoordinate::Host,
            true,
        );
        assert_eq!(
            super::recovery_resume_pc(PC, Some(retry)).unwrap(),
            PC.raw()
        );
        assert_eq!(
            super::recovery_resume_pc(PC, Some(completed)).unwrap(),
            PC.raw() + 4
        );

        let mut snapshot = super::super::NativeUcontextSnapshot::default();
        snapshot.x[9] = 3;
        super::recover_rewrite_state(&mut snapshot, completed, 0xaa, 0xbb, 0, 0, 0, 0)
            .expect("recover wrapped writeback");
        assert_eq!(snapshot.x[0], 3_u64.wrapping_sub(0x80_0000_0000));
        assert_eq!(snapshot.x[9], 0xaa);
        assert_eq!(snapshot.x[10], 0xbb);
    }

    #[test]
    fn biased_exclusive_recovery_restores_both_scratch_registers() {
        let action = super::emit::RecoveryAction::RecoverBiasedExclusive(
            super::emit::BiasedExclusiveRecovery {
                scratch: super::types::BiasedExclusiveScratch {
                    address: super::types::DsrScratchGpr::new(17).expect("x17 scratch"),
                    bias: super::types::DsrScratchGpr::new(16).expect("x16 scratch"),
                },
                resume: super::emit::BiasedExclusiveResume::Load,
            },
        );
        assert!(!action.instruction_complete());
        assert_eq!(
            super::recovery_resume_pc(PC, Some(action)).expect("resume exclusive load"),
            PC.raw()
        );

        let mut snapshot = super::super::NativeUcontextSnapshot::default();
        snapshot.x[17] = 0xaaaa;
        snapshot.x[16] = 0xbbbb;
        super::recover_rewrite_state(&mut snapshot, action, 0x1717, 0x1616, 0, 0, 0, 0)
            .expect("recover biased exclusive scratch state");
        assert_eq!(snapshot.x[17], 0x1717);
        assert_eq!(snapshot.x[16], 0x1616);
    }

    #[test]
    fn biased_exclusive_retry_recovery_is_not_instruction_complete() {
        let action = super::emit::RecoveryAction::RecoverBiasedExclusive(
            super::emit::BiasedExclusiveRecovery {
                scratch: super::types::BiasedExclusiveScratch {
                    address: super::types::DsrScratchGpr::new(17).expect("x17 scratch"),
                    bias: super::types::DsrScratchGpr::new(16).expect("x16 scratch"),
                },
                resume: super::emit::BiasedExclusiveResume::Retry,
            },
        );
        assert!(!action.instruction_complete());
        assert_eq!(
            super::recovery_resume_pc(GuestVa(0x4010), Some(action)).expect("resume guest retry"),
            0x4010
        );
    }

    #[test]
    fn biased_recovery_commits_register_sp_and_virtual_bases_last() {
        let bias = 0x80_0000_0000;
        let guest = 0x1234_5000;
        for base in [
            super::emit::BiasedBase::Register(16),
            super::emit::BiasedBase::StackPointer,
            super::emit::BiasedBase::VirtualX18,
            super::emit::BiasedBase::VirtualX28,
            super::emit::BiasedBase::VirtualReserved,
        ] {
            let action =
                biased_recovery_fixture(base, super::emit::BiasedBaseCoordinate::Host, true);
            let mut snapshot = super::super::NativeUcontextSnapshot::default();
            snapshot.x[9] = bias + guest;
            super::recover_rewrite_state(&mut snapshot, action, 0xaa, 0xbb, 0, 0, 0, 0)
                .expect("recover biased base");
            match base {
                super::emit::BiasedBase::Register(16) => assert_eq!(snapshot.x[16], guest),
                super::emit::BiasedBase::StackPointer => assert_eq!(snapshot.sp, guest),
                super::emit::BiasedBase::VirtualX18 => assert_eq!(snapshot.x[18], guest),
                super::emit::BiasedBase::VirtualX28 => assert_eq!(snapshot.x[28], guest),
                super::emit::BiasedBase::VirtualReserved => assert_eq!(
                    snapshot.x[carrick_dsr_aarch64::gateway::RESERVED_SCRATCH as usize],
                    guest
                ),
                super::emit::BiasedBase::Register(_) | super::emit::BiasedBase::None => {
                    panic!("unexpected recovery base")
                }
            }
            assert_eq!(snapshot.x[9], 0xaa);
            assert_eq!(snapshot.x[10], 0xbb);
        }
    }

    fn mapped_dsr_test_memory(
        words: &[u32],
    ) -> Result<(super::super::NativeMappedMemory, GuestVa), String> {
        super::install_test_host_jit();
        let page_size = 16 * 1024_u64;
        let layout = super::super::MemoryLayout {
            heap_base: super::super::NATIVE_DARWIN_HEAP_BASE,
            heap_size: page_size,
            mmap_base: super::super::NATIVE_DARWIN_MMAP_BASE,
            mmap_size: page_size,
        };
        let image = super::super::AddressSpace::from_regions(0, Vec::new())
            .map_err(|error| error.to_string())?;
        let mut memory = super::super::NativeMappedMemory::map_with_translator(
            &image, layout, page_size, page_size, None, None,
        )
        .map_err(|error| error.to_string())?;
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        memory
            .write_bytes_raw(layout.mmap_base, &code)
            .map_err(|error| error.to_string())?;
        memory
            .protect_range(
                layout.mmap_base,
                page_size as usize,
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
            )
            .map_err(|error| error.to_string())?;
        Ok((memory, GuestVa(layout.mmap_base)))
    }

    #[test]
    fn dsr_translation_result_distinguishes_publish_and_index_hit() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let result = (|| -> Result<(), String> {
                let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001])?;
                let process =
                    super::test_process_translator(16 * 1024).map_err(|error| error.to_string())?;
                let mut state = process.state.write();
                let first = state
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;
                let second = state
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;
                if first.outcome != super::TranslationOutcome::Translated
                    || second.outcome != super::TranslationOutcome::BlockIndexHit
                    || first.entry != second.entry
                {
                    return Err(format!(
                        "unexpected outcomes: first={first:?} second={second:?}"
                    ));
                }
                drop(state);
                let (used_bytes, block_count, generation_count) = process.lifecycle_snapshot();
                if used_bytes == 0 || block_count != 1 || generation_count != 1 {
                    return Err(format!(
                        "unexpected lifecycle snapshot: used={used_bytes} blocks={block_count} generations={generation_count}"
                    ));
                }
                if first.cache_used_bytes != used_bytes {
                    return Err(format!(
                        "unexpected cache used bytes: result={} snapshot={used_bytes}",
                        first.cache_used_bytes,
                    ));
                }
                Ok(())
            })();
            if let Err(error) = &result {
                super::super::child_write_stderr(format!("{error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    /// Read-mostly RwLock fast path: a warm cache hit must resolve through a
    /// SHARED `&ProcessState` (`state.read()`), never `&mut`, so concurrent
    /// translations can proceed fully in parallel. `cached_block` is the
    /// read-only accessor the fast path uses.
    #[test]
    fn read_fast_path_hits_warm_cache_without_mut_access() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let result = (|| -> Result<(), String> {
                let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001])?;
                let process =
                    super::test_process_translator(16 * 1024).map_err(|error| error.to_string())?;
                // Populate the block via the write path, exactly as the real
                // miss path does.
                let translated = process
                    .state
                    .write()
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;

                let observation = memory
                    .dsr_generation_observation(guest)
                    .map_err(|error| error.to_string())?;
                // Read-only lookup: only `&ProcessState` (`.read()`) is held
                // here -- this would not compile against a `&mut self`
                // accessor, and it must be able to run concurrently with any
                // other reader.
                let hit = process
                    .state
                    .read()
                    .cached_block(guest, observation.expected());
                if hit != Some(translated.entry) {
                    return Err(format!(
                        "expected read fast path to hit the inserted block {:?}, got {hit:?}",
                        translated.entry
                    ));
                }
                Ok(())
            })();
            if let Err(error) = &result {
                super::super::child_write_stderr(format!("{error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    /// The cache key embeds the generation, so a stale (pre-mutation) block
    /// must never be returned by the read fast path once the guest page has
    /// been modified: `cached_block` is queried with the CURRENT generation,
    /// which the old block's key does not match.
    #[test]
    fn read_fast_path_never_returns_a_stale_generation_block() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let result = (|| -> Result<(), String> {
                let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001])?;
                let process =
                    super::test_process_translator(16 * 1024).map_err(|error| error.to_string())?;
                let first = process
                    .state
                    .write()
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;

                // Mutate the guest code: bumps the page's generation, so
                // `first`'s block is now keyed by a STALE generation.
                let new_generation = memory
                    .note_dsr_code_mutation(guest.raw(), 4)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "expected a DSR generation".to_string())?;
                if new_generation == first.generation {
                    return Err("code mutation did not change the generation".to_string());
                }

                // The read fast path, queried with the CURRENT generation,
                // must miss -- the old block's key is (guest, OLD
                // generation), which can never match. It must fall through
                // to the write path, which performs the actual invalidation.
                let hit = process.state.read().cached_block(guest, new_generation);
                if hit.is_some() {
                    return Err(format!(
                        "read fast path returned a stale-generation hit: {hit:?}"
                    ));
                }

                // The write path re-translates cleanly at the new generation.
                let second = process
                    .state
                    .write()
                    .translate(0, &memory, guest)
                    .map_err(|error| error.to_string())?;
                if second.generation != new_generation {
                    return Err(format!(
                        "expected re-translation at the new generation {new_generation:?}, got {:?}",
                        second.generation
                    ));
                }
                Ok(())
            })();
            if let Err(error) = &result {
                super::super::child_write_stderr(format!("{error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn repeated_prepare_keeps_valid_last_entry_hot() {
        fork_test(|| {
            let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001]).expect("map test memory");
            let snapshot = super::super::NativeUcontextSnapshot {
                pc: guest.raw(),
                ..Default::default()
            };
            let mut translator =
                super::test_thread_translator(16 * 1024).expect("create translator");
            let first = translator
                .prepare_entry::<false>(&memory, &snapshot)
                .expect("prepare first entry");
            let before = translator.profile_snapshot();
            let second = translator
                .prepare_entry::<false>(&memory, &snapshot)
                .expect("prepare repeated entry");
            let after = translator.profile_snapshot();
            assert_eq!(first.entry, second.entry);
            assert_eq!(after.one_entry_hits - before.one_entry_hits, 1);
        });
    }

    #[test]
    fn generation_change_discards_last_prepared_entry() {
        fork_test(|| {
            let (memory, guest) = mapped_dsr_test_memory(&[0xd400_0001]).expect("map test memory");
            let snapshot = super::super::NativeUcontextSnapshot {
                pc: guest.raw(),
                ..Default::default()
            };
            let mut translator =
                super::test_thread_translator(16 * 1024).expect("create translator");
            let first = translator
                .prepare_entry::<false>(&memory, &snapshot)
                .expect("prepare first entry");
            let changed = memory
                .note_dsr_code_mutation(guest.raw(), 4)
                .expect("record code mutation")
                .expect("DSR generation");
            let before = translator.profile_snapshot();
            let second = translator
                .prepare_entry::<false>(&memory, &snapshot)
                .expect("prepare after mutation");
            let after = translator.profile_snapshot();
            assert_eq!(second.generation, changed);
            assert_ne!(first.generation, second.generation);
            assert_eq!(after.one_entry_hits, before.one_entry_hits);
            assert_ne!(first.entry, second.entry);
        });
    }

    #[test]
    fn thread_translator_stores_the_guest_tid() {
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create translator"),
        );
        process
            .activate_translated_range_catalog()
            .expect("activate catalog");
        let mut translator = super::ThreadTranslator::for_process(process, 37);
        assert_eq!(translator.tid, 37);
        translator.after_fork_child(73).expect("fork repair");
        assert_eq!(translator.tid, 73);
    }

    #[test]
    fn fork_child_reset_does_not_mix_parent_profile_identity() {
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create translator"),
        );
        process
            .activate_translated_range_catalog()
            .expect("activate catalog");
        process.state.write().stats.translations = 9;
        let mut translator = super::ThreadTranslator::for_process(process, 42);
        translator.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        translator
            .budget
            .record_exit(super::profile::ExitClass::Syscall)
            .expect("record parent exit");

        translator.after_fork_child(73).expect("fork repair");

        let record = translator
            .budget
            .complete_record()
            .expect("fresh child profile");
        assert_eq!(record.pid, unsafe { libc::getpid() });
        assert_eq!(record.tid, 73);
        assert_eq!(record.gateway_entries, 0);
        assert_eq!(translator.profile_snapshot().translations, 0);
        translator.budget = super::profile::ThreadBudget::disabled_for_test(0, 0);
    }

    #[test]
    fn dsr_indirect_resolver_stats_start_at_zero() {
        let translator = super::test_thread_translator(16 * 1024).expect("create translator");
        assert_eq!(translator.resolver_stats(), super::ResolverStats::default());
        let profile = translator.profile_snapshot();
        assert_eq!(profile.gateway_entries, 0);
        assert_eq!(profile.syscall_exits, 0);
        assert_eq!(profile.cache_lookups, 0);
        assert_eq!(profile.cache_used_bytes, 0);
        assert_eq!(profile.cache_capacity_bytes, 16 * 1024);
        assert_eq!(profile.translation_decode_ns, 0);
        assert_eq!(profile.translation_plan_ns, 0);
        assert_eq!(profile.translation_emit_ns, 0);
        assert_eq!(profile.translation_publication_ns, 0);
    }

    #[test]
    fn exclusive_fusion_sites_deduplicate_across_generations() {
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create translator"),
        );
        let site = super::types::ExclusiveFusionSite {
            guest: PC,
            word: 0x885f_7c20,
            disposition: super::types::ExclusiveFusionDisposition::EligibleBackendDisabled,
            biased_scratch: None,
        };
        {
            let mut state = process.state.write();
            state.profiling = true;
            for generation in [
                super::types::CodeGeneration::INITIAL,
                super::types::CodeGeneration::claimed(1),
            ] {
                state.record_exclusive_fusion_site(site);
                state.sensitive.insert(
                    (site.guest, generation),
                    super::SensitiveMetadata {
                        exit: super::types::SensitiveExit {
                            kind: super::types::SensitiveKind::Exclusive(site.word),
                            register: None,
                            resume: GuestVa(site.guest.raw() + 4),
                        },
                        fusion: Some(site),
                    },
                );
            }
        }
        let mut translator = super::ThreadTranslator::for_process(process, 0);
        translator.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        let snapshot = translator.profile_snapshot();
        assert_eq!(
            snapshot.exclusive_fusion_sites
                [super::profile::ExclusiveFusionClass::EligibleBackendDisabled.index()],
            1
        );
        translator.budget = super::profile::ThreadBudget::disabled_for_test(0, 0);
    }

    #[test]
    fn exec_handoff_starts_a_new_fusion_site_epoch() {
        let old = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create old translator"),
        );
        let next = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create next translator"),
        );
        let site = |guest, word| super::types::ExclusiveFusionSite {
            guest: GuestVa(guest),
            word,
            disposition: super::types::ExclusiveFusionDisposition::EligibleBackendDisabled,
            biased_scratch: None,
        };
        {
            let mut state = old.state.write();
            state.profiling = true;
            state.record_exclusive_fusion_site(site(0x1000, 0x885f_7c20));
        }
        next.state.write().profiling = true;
        let mut thread = super::ThreadTranslator::for_process(old, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);

        thread
            .reset_for_exec_with_sink(next, |_| {})
            .expect("reset translator for exec");
        thread
            .process
            .state
            .write()
            .record_exclusive_fusion_site(site(0x2000, 0x885f_7c41));
        let frames = thread.take_profile_frames().expect("post-exec frames");

        assert!(
            frames.iter().any(|frame| {
                frame.contains("|frame=core|") && frame.ends_with("|exec_epoch=1")
            })
        );
        assert!(frames.iter().any(|frame| {
            frame.contains("|frame=fusion-sites-a|")
                && frame.contains("|fusion_eligible_backend_disabled=1|")
        }));
    }

    #[test]
    fn failed_self_reexec_restart_preserves_image_epoch_and_catalog() {
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create translator"),
        );
        {
            let mut state = process.state.write();
            state.profiling = true;
            state.record_exclusive_fusion_site(super::types::ExclusiveFusionSite {
                guest: GuestVa(0x1000),
                word: 0x885f_7c20,
                disposition: super::types::ExclusiveFusionDisposition::EligibleBackendDisabled,
                biased_scratch: None,
            });
        }
        let mut thread = super::ThreadTranslator::for_process(process, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        let before = thread.take_profile_frames().expect("pre-attempt frames");

        thread.start_next_profile_era_same_image();

        let after = thread.take_profile_frames().expect("rollback frames");
        assert_eq!(
            protocol_value(&after, "exec_epoch"),
            protocol_value(&before, "exec_epoch"),
            "a failed self-reexec did not replace the image"
        );
        assert!(
            protocol_value(&after, "era") > protocol_value(&before, "era"),
            "rollback must still start a distinct thread profiling era"
        );
        assert!(after.iter().any(|frame| {
            frame.contains("|frame=fusion-sites-a|")
                && frame.contains("|fusion_eligible_backend_disabled=1|")
        }));
    }

    #[test]
    fn large_pre_exec_catalog_is_not_carried_into_replacement_translator() {
        let old = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create old translator"),
        );
        let next = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create next translator"),
        );
        {
            let mut state = old.state.write();
            state.profiling = true;
            for index in 0..4096_u64 {
                state.record_exclusive_fusion_site(super::types::ExclusiveFusionSite {
                    guest: GuestVa(0x1000 + index * 4),
                    word: 0x885f_7c20,
                    disposition: super::types::ExclusiveFusionDisposition::EligibleBackendDisabled,
                    biased_scratch: None,
                });
            }
        }
        next.state.write().profiling = true;
        let mut thread = super::ThreadTranslator::for_process(old, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);

        thread
            .reset_for_exec_with_sink(std::sync::Arc::clone(&next), |_| {})
            .expect("reset translator for exec");

        assert_eq!(
            next.state.read().exclusive_fusion_site_counts()
                [super::profile::ExclusiveFusionClass::EligibleBackendDisabled.index()],
            0
        );
        thread.budget = super::profile::ThreadBudget::disabled_for_test(0, 0);
    }

    #[test]
    fn dsr_exec_switch_keeps_retiring_translator_metadata_alive() {
        let old = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create old translator"),
        );
        let key = (PC, super::types::CodeGeneration::INITIAL);
        let entry = super::types::CacheVa::published(carrick_guest_mem::HostVa(0x1000));
        old.state.write().blocks.insert(key, entry);
        let mut thread = super::ThreadTranslator::for_process(std::sync::Arc::clone(&old), 0);
        let next = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create next translator"),
        );

        thread
            .reset_for_exec(next)
            .expect("reset translator for exec");

        assert_eq!(
            old.state.read().blocks.get(&key),
            Some(&entry),
            "pre-exec threads must retain old PC metadata until their Arc retires"
        );
    }

    fn protocol_value(frames: &[String], key: &str) -> u64 {
        frames
            .iter()
            .flat_map(|frame| frame.split('|'))
            .find_map(|field| field.strip_prefix(&format!("{key}=")))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("missing protocol field {key}"))
    }

    #[test]
    fn exec_finalizes_coherent_pre_and_post_eras() {
        let old = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create old translator"),
        );
        old.state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 3);
        old.state
            .write()
            .stats
            .add(super::ResolverStat::TranslationNs, 11);
        let mut thread = super::ThreadTranslator::for_process(old, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        thread
            .budget
            .record_exit(super::profile::ExitClass::Syscall)
            .expect("record pre-exec exit");
        thread.nested_translation_ns = 17;
        let next = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create next translator"),
        );
        next.state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 5);
        let mut pre_exec = Vec::new();

        thread
            .reset_for_exec_with_sink(next, |frames| pre_exec.extend_from_slice(frames))
            .expect("reset translator for exec");

        assert_eq!(protocol_value(&pre_exec, "era"), 0);
        assert_eq!(protocol_value(&pre_exec, "gateway_entries"), 1);
        assert_eq!(protocol_value(&pre_exec, "translations"), 3);
        assert_eq!(protocol_value(&pre_exec, "nested_translation_ns"), 11);
        assert_eq!(protocol_value(&pre_exec, "translate_phase_nested_ns"), 17);
        let post_exec = thread.take_profile_frames().expect("post-exec era");
        assert!(protocol_value(&post_exec, "era") > 0);
        assert_eq!(protocol_value(&post_exec, "gateway_entries"), 0);
        assert_eq!(protocol_value(&post_exec, "translations"), 5);
        assert_eq!(protocol_value(&post_exec, "nested_translation_ns"), 0);
        assert_eq!(protocol_value(&post_exec, "translate_phase_nested_ns"), 0);
    }

    #[test]
    fn post_exec_seeded_era_thread_cpu_excludes_the_installed_baseline() {
        // Models runtime re-entry after a PID-preserving host self-reexec
        // (`resume_guest_from_capsule`): the surviving thread's kernel CPU
        // counter is cumulative across the exec, so its post-exec
        // `ThreadBudget` carries an installed baseline. Install one
        // comfortably above anything this era could plausibly consume before
        // the flush below, so the era's own `thread_cpu_ns` must saturate at
        // zero — proving the pre-exec CPU that era already flushed is
        // excluded here rather than double-counted.
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create translator"),
        );
        let mut thread = super::ThreadTranslator::for_process(process, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        thread
            .budget
            .install_thread_cpu_baseline_ns_for_test(1_000_000_000_000);

        let frames = thread.take_profile_frames().expect("post-exec-seeded era");

        assert_eq!(protocol_value(&frames, "thread_cpu_ns"), 0);
    }

    #[test]
    fn process_resolver_deltas_are_counted_exactly_once_across_threads() {
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create translator"),
        );
        let mut first = super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), 42);
        let mut second = super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), 43);
        first.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        second.budget = super::profile::ThreadBudget::enabled_for_test(41, 43);
        process
            .state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 7);
        {
            let mut state = process.state.write();
            state
                .stats
                .add(super::ResolverStat::SharedMetadataBytesRead, 11);
            state
                .stats
                .add(super::ResolverStat::SharedMetadataBytesMapped, 13);
            state
                .stats
                .add(super::ResolverStat::SharedMetadataValidationNs, 17);
            state
                .stats
                .add(super::ResolverStat::SharedMappedImmutableRecords, 19);
            state
                .stats
                .add(super::ResolverStat::SharedOwnedImmutableRecords, 23);
            state
                .stats
                .add(super::ResolverStat::SharedGuestRangeDerivations, 29);
            state
                .stats
                .add(super::ResolverStat::SharedDirectEdgeGroupBuilds, 31);
        }
        let first_frames = first.take_profile_frames().expect("first record");
        process
            .state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 5);
        let second_frames = second.take_profile_frames().expect("second record");

        assert_eq!(protocol_value(&first_frames, "translations"), 7);
        assert_eq!(protocol_value(&second_frames, "translations"), 5);
        for (field, expected) in [
            ("shared_metadata_bytes_read", 11),
            ("shared_metadata_bytes_mapped", 13),
            ("shared_metadata_validation_ns", 17),
            ("shared_mapped_immutable_records", 19),
            ("shared_owned_immutable_records", 23),
            ("shared_guest_range_derivations", 29),
            ("shared_direct_edge_group_builds", 31),
        ] {
            assert_eq!(protocol_value(&first_frames, field), expected, "{field}");
            assert_eq!(protocol_value(&second_frames, field), 0, "{field}");
        }
        assert_eq!(
            protocol_value(&first_frames, "translations")
                + protocol_value(&second_frames, "translations"),
            12
        );
    }

    #[test]
    fn take_profile_frames_emits_typed_attribution_frames() {
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create translator"),
        );
        let mut thread = super::ThreadTranslator::for_process(process, 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);

        let frames = thread.take_profile_frames().expect("attribution frames");

        // `resolver-metadata` keeps the low-frequency mechanism evidence in a
        // separate PIPE_BUF-bounded frame from the sharing counters, and the
        // live lane keeps its five (lane, bytes, three fallback-class frames).
        assert_eq!(frames.len(), 23);
        assert!(frames.iter().any(|frame| frame.contains("|frame=process|")));
        assert!(
            frames
                .iter()
                .any(|frame| frame.contains("|phase_blocked_cpu_ns="))
        );
        // Gauge fields must parse; the flush-time process CPU of the test
        // harness is always positive.
        let _ = protocol_value(&frames, "thread_cpu_ns");
        let _ = protocol_value(&frames, "startup_wall_ns");
        let _ = protocol_value(&frames, "startup_cpu_ns");
        assert!(protocol_value(&frames, "process_cpu_ns") > 0);
    }

    #[test]
    fn resolver_overflow_invalidates_and_finalization_is_idempotent() {
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create translator"),
        );
        let mut thread = super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), 42);
        thread.budget = super::profile::ThreadBudget::enabled_for_test(41, 42);
        process.state.write().stats.translations = u64::MAX;
        process
            .state
            .write()
            .stats
            .add(super::ResolverStat::Translations, 1);

        let frames = thread.take_profile_frames().expect("invalid record");
        assert_eq!(frames.len(), 1);
        assert!(frames[0].contains("|complete=0|"));
        assert!(frames[0].contains("|reason=counter-overflow"));
        assert!(thread.take_profile_frames().is_none());
    }

    /// The seam that owns the flush: `native_darwin::finalize_native_thread_exit`
    /// is the function the real `DispatchOutcome::ThreadExit` dispatch arm
    /// calls before a guest thread retires. Driving the actual dispatch loop
    /// end-to-end (a real forked guest binary hitting a real `exit(2)`) is
    /// outside what a pure unit test can reach here, so this test calls the
    /// exact production function directly with a synthetic sibling thread and
    /// proves the two properties the attribution defect depended on: (1) a
    /// thread that retires via this path emits its complete NATIVEPERF
    /// `core`/`thread_cpu_ns` record — not silently absorbed into another
    /// pid's helper residual — and (2) that flush is exactly-once, so the
    /// translator's later `Drop` cannot duplicate the `(pid, tid, era)`
    /// group the wire protocol (and the Python analyzer) rejects on replay.
    #[test]
    fn thread_exit_flushes_the_exiting_threads_profile_record() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            // Redirect the real fd 2 to a pipe for the duration of the call:
            // `finalize_profile_epoch` writes NATIVEPERF frames directly to
            // `libc::STDERR_FILENO`, exactly as the production dispatch loop
            // does, so this observes the identical wire the campaign harness
            // parses instead of a stand-in.
            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let (memory, _guest) = mapped_dsr_test_memory(&[]).expect("map test memory");
            let memory: super::super::SharedNativeMemory =
                std::sync::Arc::new(super::super::NativeMemoryHandle::new(memory));

            let runtime = super::super::NativeThreadRuntime::new_current();
            // clear_child_tid=0 so `finish_thread` never dereferences guest
            // memory: this test only exercises the profile-flush contract.
            let sib_tid = runtime.registry.register_child(0);
            let mut sibling = runtime.sibling(sib_tid);
            let dispatcher = super::super::SyscallDispatcher::new();

            let process = std::sync::Arc::new(
                super::test_process_translator(16 * 1024).expect("create process translator"),
            );
            let mut translator = super::ThreadTranslator::for_process(process, sib_tid.raw());
            translator.budget = super::profile::ThreadBudget::enabled_for_test(
                unsafe { libc::getpid() },
                sib_tid.raw(),
            );
            translator
                .budget
                .record_exit(super::profile::ExitClass::Syscall)
                .expect("record a balanced gateway entry/exit pair");

            let outcome = super::super::finalize_native_thread_exit(
                &mut translator,
                &mut sibling,
                &dispatcher,
                &memory,
                0,
            );

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }
            runtime.registry.exit(sib_tid);

            assert!(
                matches!(outcome, super::super::NativeThreadLoopOutcome::ThreadDone),
                "a sibling with a live process leader must retire as ThreadDone"
            );
            assert!(
                captured.contains("NATIVEPERF1|thread|"),
                "ThreadExit must flush a NATIVEPERF record before the thread retires; \
                 captured stderr: {captured:?}"
            );
            assert!(captured.contains(&format!("|tid={}|", sib_tid.raw())));
            assert!(captured.contains("|frame=core|"));
            assert!(
                translator.take_profile_frames().is_none(),
                "the flush must be exactly-once: a later drop/finalize must not re-emit \
                 the same (pid, tid, era) group"
            );
        });
    }

    /// Extracts every complete `NATIVEPERF1|thread|...` line naming `tid` from
    /// captured stderr text.
    fn frames_for_tid(captured: &str, tid: i32) -> Vec<String> {
        let needle = format!("|tid={tid}|");
        captured
            .lines()
            .filter(|line| line.starts_with("NATIVEPERF1|thread|") && line.contains(&needle))
            .map(str::to_owned)
            .collect()
    }

    /// How many complete `core` frames (i.e. how many EMITTED RECORDS -- one
    /// `core` frame per record) name `tid` in the captured wire.
    fn core_frames_for_tid(captured: &str, tid: i32) -> usize {
        frames_for_tid(captured, tid)
            .iter()
            .filter(|line| line.contains("|frame=core|"))
            .count()
    }

    /// EXACTLY-ONCE UNDER CONCURRENCY. The registry hands one thread's record
    /// to exactly one of two possible emitters -- the thread's own self-flush
    /// (individual `exit(2)` via `finalize_native_thread_exit`, an `Execve`
    /// self-reexec, `native_die_by_signal`, or a `RetireForExec` retirement)
    /// or a FOREIGN thread's `exit_group` drain -- and those two can genuinely
    /// run at the same instant on two cores, since `exit_group` fires while
    /// siblings are still executing. If both emit, the wire carries a
    /// duplicate `(pid, tid, era)` group, which `parse_nativeperf` hard-rejects
    /// ("duplicate frame ... for duplicate thread identity") -- an intermittent
    /// HARD FAILURE of a real profiled campaign run, not a degradation.
    ///
    /// Two REAL OS threads, synchronized only through the shared registry plus
    /// a per-iteration barrier that lines their two claims up as tightly as
    /// the scheduler allows: one repeatedly registers-then-self-flushes, the
    /// other repeatedly drains. Across every iteration each identity must
    /// appear EXACTLY once on the wire -- never twice (duplicate) and never
    /// zero times (lost).
    #[test]
    fn sibling_flush_is_exactly_once_when_a_drain_races_a_self_flush() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;
            use std::sync::{Arc, Barrier};

            const ITERATIONS: i32 = 256;
            const FIRST_TID: i32 = 20_000;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            // Drain the pipe CONCURRENTLY: 256 iterations x 10 frames x up to
            // two emitters is far past the 64 KiB pipe buffer, so a reader that
            // only ran after the join would wedge the writers.
            let read_fd = stderr_pipe[0];
            let reader = std::thread::spawn(move || {
                let mut text = String::new();
                let mut file = unsafe { std::fs::File::from_raw_fd(read_fd) };
                file.read_to_string(&mut text)
                    .expect("read captured stderr");
                text
            });

            let pid = unsafe { libc::getpid() };
            let process = std::sync::Arc::new(
                super::test_process_translator(16 * 1024).expect("create process translator"),
            );
            let barrier = Arc::new(Barrier::new(2));

            let self_flusher = {
                let process = std::sync::Arc::clone(&process);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    for index in 0..ITERATIONS {
                        let tid = FIRST_TID + index;
                        let mut translator = super::ThreadTranslator::for_process(
                            std::sync::Arc::clone(&process),
                            tid,
                        );
                        translator.budget =
                            super::profile::ThreadBudget::enabled_for_test(pid, tid);
                        // "At DSR loop entry" -- register the slot a foreign
                        // drain could take.
                        translator.publish_sibling_snapshot();
                        barrier.wait();
                        // Alternate which side is favoured so BOTH orderings
                        // are exercised: on even iterations yield so the drain
                        // most likely wins the claim, on odd ones go straight
                        // for it so this thread most likely wins. Either way
                        // the identity must land on the wire exactly once.
                        if index % 2 == 0 {
                            std::thread::yield_now();
                        }
                        // ...and race a drain with this thread's OWN
                        // retirement flush.
                        translator.finalize_profile_epoch();
                    }
                })
            };
            let drainer = {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut leader = super::ThreadTranslator::for_process(process, 42);
                    leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, 42);
                    for index in 0..ITERATIONS {
                        barrier.wait();
                        if index % 2 == 1 {
                            std::thread::yield_now();
                        }
                        leader.drain_sibling_profiles_before_process_exit();
                    }
                    leader.finalize_profile_epoch();
                })
            };
            self_flusher.join().expect("join self-flushing thread");
            drainer.join().expect("join draining thread");

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let captured = reader.join().expect("join stderr reader");

            assert!(
                !captured.contains("NATIVEPERF1|invalid|"),
                "the race must never produce an invalid record"
            );
            let mut duplicated = Vec::new();
            let mut lost = Vec::new();
            for index in 0..ITERATIONS {
                let tid = FIRST_TID + index;
                match core_frames_for_tid(&captured, tid) {
                    1 => {}
                    0 => lost.push(tid),
                    n => duplicated.push((tid, n)),
                }
            }
            assert!(
                duplicated.is_empty(),
                "a drain racing a self-flush DOUBLE-emitted {} of {ITERATIONS} identities \
                 (duplicate (pid, tid, era) groups the wire protocol rejects): {duplicated:?}",
                duplicated.len()
            );
            assert!(
                lost.is_empty(),
                "a drain racing a self-flush LOST {} of {ITERATIONS} identities entirely: {lost:?}",
                lost.len()
            );
        });
    }

    /// The process-wide resolver counters (translations, cache lookups/hits,
    /// invalidated blocks, translation_*_ns, duplicate publications) are
    /// SHARED by every thread of the process and are published as a delta
    /// against ONE `reported_stats` checkpoint. So the delta must be assigned
    /// to exactly one record per process epoch -- never split arbitrarily, and
    /// never double-counted.
    ///
    /// At an `exit_group` seam the owner is the DRAINING thread's own record:
    /// its `finalize_profile_epoch()` always runs immediately before the
    /// drain, and claims the outstanding delta. The siblings drained after it
    /// therefore report structurally ZERO process-wide deltas -- not "whatever
    /// happened to still be unclaimed when the loop reached them", which
    /// would hand the first sibling the residue and every later one ~0 purely
    /// as a function of loop order.
    ///
    /// This pins that ownership. It also pins what must NOT be zeroed: the
    /// siblings' own PER-THREAD resolver counters, and the cache
    /// point-in-time gauges (neither is a delta).
    #[test]
    fn a_drain_leaves_the_process_wide_resolver_delta_to_the_draining_threads_record() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let pid = unsafe { libc::getpid() };
            const LEADER_TID: i32 = 42;
            const SIBLING_TIDS: [i32; 2] = [9051, 9052];
            let process = std::sync::Arc::new(
                super::test_process_translator(16 * 1024).expect("create process translator"),
            );
            // The whole process epoch's shared, process-wide resolver work.
            process
                .state
                .write()
                .stats
                .add(super::ResolverStat::Translations, 11);
            process
                .state
                .write()
                .stats
                .add(super::ResolverStat::CacheLookups, 23);

            // Two siblings register, then die without ever running their own
            // flush (exit_group's hard kill) -- each with its OWN per-thread
            // resolver counters, which must survive the drain intact.
            let mut siblings = Vec::new();
            for (index, tid) in SIBLING_TIDS.into_iter().enumerate() {
                let mut sibling =
                    super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), tid);
                sibling.budget = super::profile::ThreadBudget::enabled_for_test(pid, tid);
                sibling
                    .stats
                    .add(super::ResolverStat::OneEntryHits, (index as u64) + 1);
                sibling.publish_sibling_snapshot();
                siblings.push(sibling);
            }

            let mut leader =
                super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), LEADER_TID);
            leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, LEADER_TID);
            // The real `exit_group` seam: claim own slot, drain the siblings,
            // then flush this thread's own record LAST so it claims the whole
            // outstanding process-wide delta.
            leader.finalize_profile_epoch_at_process_exit();

            // The siblings were killed by the `_exit()`: they never run again.
            for sibling in siblings {
                std::mem::forget(sibling);
            }

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }

            // The draining thread's own record owns the whole process delta.
            let leader_frames = frames_for_tid(&captured, LEADER_TID);
            assert_eq!(core_frames_for_tid(&captured, LEADER_TID), 1);
            assert_eq!(protocol_value(&leader_frames, "translations"), 11);
            assert_eq!(protocol_value(&leader_frames, "cache_lookups"), 23);

            for (index, tid) in SIBLING_TIDS.into_iter().enumerate() {
                let frames = frames_for_tid(&captured, tid);
                assert_eq!(
                    core_frames_for_tid(&captured, tid),
                    1,
                    "each drained sibling must be emitted exactly once"
                );
                // Process-wide deltas: structurally zero on EVERY drained
                // sibling -- not just the 2nd..Nth. Before this rule, the
                // first sibling in the drain loop swallowed the (arbitrary)
                // residue and the rest silently got 0.
                for field in [
                    "translations",
                    "optimistic_decode_discards",
                    "optimistic_decode_discard_ns",
                    "cache_lookups",
                    "cache_lookup_hits",
                    "invalidated_blocks",
                    "nested_translation_ns",
                    "nested_translation_decode_ns",
                    "nested_translation_plan_ns",
                    "nested_translation_emit_ns",
                    "nested_translation_publication_ns",
                ] {
                    assert_eq!(
                        protocol_value(&frames, field),
                        0,
                        "drained sibling tid={tid} must report a structurally zero \
                         process-wide delta for {field} (the draining thread's record owns it)"
                    );
                }
                // ...but its OWN per-thread counters are real, and the cache
                // point-in-time gauges are real live reads. Neither is a delta.
                assert_eq!(
                    protocol_value(&frames, "one_entry_hits"),
                    (index as u64) + 1,
                    "a drained sibling's per-thread resolver counters must survive intact"
                );
                assert_eq!(protocol_value(&frames, "cache_capacity_bytes"), 16 * 1024);
            }
        });
    }

    /// The root cause this task fixes: Linux `exit_group` kills every OTHER
    /// live guest OS thread of a process unconditionally, at the runtime's own
    /// `libc::_exit()`, with zero chance for any of them to run their own
    /// flush -- Drop included. A thread that registered a sibling slot (every
    /// DSR loop iteration republishes one, see `publish_sibling_snapshot`) but
    /// never got to self-flush must still have its complete NATIVEPERF record
    /// emitted by whichever thread drains the registry before calling
    /// `libc::_exit()`, carrying its own identity and a plausible
    /// `thread_cpu_ns` read LIVE, cross-thread, via the mach port it captured
    /// on itself at registration.
    #[test]
    fn exit_group_drain_emits_a_registered_but_unflushed_siblings_record() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let pid = unsafe { libc::getpid() };
            const SIBLING_TID: i32 = 9042;
            let process = std::sync::Arc::new(
                super::test_process_translator(16 * 1024).expect("create process translator"),
            );

            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(0);
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(0);
            let sibling_process = std::sync::Arc::clone(&process);
            let sibling_thread = std::thread::spawn(move || {
                let mut translator =
                    super::ThreadTranslator::for_process(sibling_process, SIBLING_TID);
                translator.budget =
                    super::profile::ThreadBudget::enabled_for_test(pid, SIBLING_TID);
                translator
                    .budget
                    .record_exit(super::profile::ExitClass::Syscall)
                    .expect("record a balanced gateway entry/exit pair");
                // "At DSR loop entry" -- the real call site is the top of
                // `run_native_dsr_thread_loop_profiled`; this registers the
                // same way.
                translator.publish_sibling_snapshot();
                // Burn real CPU (sleeping would advance wall time, not the
                // thread's own `thread_info` CPU counters this test proves a
                // FOREIGN thread can read).
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(20);
                let mut spin: u64 = 0;
                while std::time::Instant::now() < deadline {
                    spin = spin.wrapping_add(1);
                }
                std::hint::black_box(spin);
                ready_tx.send(()).expect("signal registered and warmed up");
                // Simulate `exit_group`'s kernel-level, unconditional kill:
                // this thread runs no more of its own code after the leader's
                // drain runs, Drop included, so it must never reach
                // `take_profile_frames` -- `mem::forget` instead of letting
                // the value drop naturally.
                release_rx.recv().expect("wait for the leader's drain");
                std::mem::forget(translator);
            });

            ready_rx.recv().expect("sibling registered its slot");

            let mut leader = super::ThreadTranslator::for_process(process, 42);
            leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, 42);
            leader.drain_sibling_profiles_before_process_exit();
            // Flush the leader's OWN (uninteresting, all-zero) record here,
            // still inside the redirected-stderr window, so its `Drop` does
            // not write directly to the real fd 2 after the restore below.
            leader.finalize_profile_epoch();

            release_tx.send(()).expect("release the sibling thread");
            sibling_thread.join().expect("join sibling thread");

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }

            let sibling_frames = frames_for_tid(&captured, SIBLING_TID);
            assert_eq!(
                sibling_frames.len(),
                23,
                "the drain must emit the sibling's complete 23-frame record exactly once; \
                 captured stderr: {captured:?}"
            );
            for frame in [
                "core",
                "exits",
                "sensitive",
                "fusion-exec-a",
                "fusion-exec-b",
                "fusion-sites-a",
                "fusion-sites-b",
                "phases-a",
                "phases-b",
                "resolver-thread",
                "resolver-process",
                "resolver-times",
                "resolver-shared",
                "resolver-metadata",
                "resolve-class",
                "direct-binding-gauge",
                "cache-gauge",
                "live-lane",
                "live-bytes",
                "live-fallback-a",
                "live-fallback-b",
                "live-fallback-c",
                "process",
            ] {
                let marker = format!("|frame={frame}|");
                assert_eq!(
                    sibling_frames
                        .iter()
                        .filter(|line| line.contains(&marker))
                        .count(),
                    1,
                    "frame {frame} must appear exactly once for the drained sibling"
                );
            }
            let thread_cpu_ns = protocol_value(&sibling_frames, "thread_cpu_ns");
            assert!(
                thread_cpu_ns > 0,
                "a sibling thread that spun for 20ms must report a plausibly nonzero \
                 thread_cpu_ns read live via its mach port, got {thread_cpu_ns}"
            );
        });
    }

    /// Exactly-once: a thread that runs its OWN flush (and so deregisters
    /// itself) must never ALSO be re-emitted by a later foreign
    /// `exit_group` drain -- a double emission is a duplicate `(pid, tid,
    /// era)` group, which the Python analyzer hard-rejects on replay.
    #[test]
    fn exit_group_drain_never_reemits_a_thread_that_already_self_flushed() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let pid = unsafe { libc::getpid() };
            const SELF_FLUSHED_TID: i32 = 9043;
            let process = std::sync::Arc::new(
                super::test_process_translator(16 * 1024).expect("create process translator"),
            );

            let mut already_flushed = super::ThreadTranslator::for_process(
                std::sync::Arc::clone(&process),
                SELF_FLUSHED_TID,
            );
            already_flushed.budget =
                super::profile::ThreadBudget::enabled_for_test(pid, SELF_FLUSHED_TID);
            already_flushed
                .budget
                .record_exit(super::profile::ExitClass::Syscall)
                .expect("record a balanced gateway entry/exit pair");
            // Register, exactly like a real DSR loop iteration would...
            already_flushed.publish_sibling_snapshot();
            // ...then flush and deregister itself, exactly like the normal
            // (non-`exit_group`) retirement paths do.
            already_flushed.finalize_profile_epoch();

            let mut leader = super::ThreadTranslator::for_process(process, 42);
            leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, 42);
            // The `exit_group` seam: the leader's own flush already ran
            // (mirrored here by `already_flushed.finalize_profile_epoch()`
            // above standing in for a DIFFERENT thread's self-flush); now
            // drain whatever siblings remain -- which must be none.
            leader.drain_sibling_profiles_before_process_exit();
            // Flush the leader's OWN (uninteresting, all-zero) record here,
            // still inside the redirected-stderr window, so its `Drop` does
            // not write directly to the real fd 2 after the restore below.
            leader.finalize_profile_epoch();

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }

            let frames = frames_for_tid(&captured, SELF_FLUSHED_TID);
            assert_eq!(
                frames.len(),
                23,
                "a self-flushed thread's record must appear exactly once (its own \
                 self-flush), never a second time from the leader's drain; captured: {captured:?}"
            );
        });
    }

    /// Zero cost / zero effect when profiling is off: a thread whose budget
    /// was never enabled must never register a sibling slot at all, so a
    /// foreign drain finds (and emits) nothing for it.
    #[test]
    fn disabled_profiling_thread_never_registers_a_sibling_slot() {
        fork_test(|| {
            use std::io::Read as _;
            use std::os::fd::FromRawFd as _;

            let mut stderr_pipe = [0i32; 2];
            assert_eq!(unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) }, 0);
            let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
            assert!(saved_stderr >= 0, "dup stderr");
            assert_eq!(
                unsafe { libc::dup2(stderr_pipe[1], libc::STDERR_FILENO) },
                libc::STDERR_FILENO,
                "redirect stderr"
            );
            assert_eq!(unsafe { libc::close(stderr_pipe[1]) }, 0);

            let pid = unsafe { libc::getpid() };
            const DISABLED_TID: i32 = 9044;
            let process = std::sync::Arc::new(
                super::test_process_translator(16 * 1024).expect("create process translator"),
            );

            let mut disabled =
                super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), DISABLED_TID);
            disabled.budget = super::profile::ThreadBudget::disabled_for_test(pid, DISABLED_TID);
            disabled.publish_sibling_snapshot();

            let mut leader = super::ThreadTranslator::for_process(process, 42);
            leader.budget = super::profile::ThreadBudget::enabled_for_test(pid, 42);
            leader.drain_sibling_profiles_before_process_exit();
            // Flush the leader's OWN (uninteresting, all-zero) record here,
            // still inside the redirected-stderr window, so its `Drop` does
            // not write directly to the real fd 2 after the restore below.
            leader.finalize_profile_epoch();

            unsafe {
                assert_eq!(
                    libc::dup2(saved_stderr, libc::STDERR_FILENO),
                    libc::STDERR_FILENO
                );
                libc::close(saved_stderr);
            }
            let mut captured = String::new();
            {
                let mut reader = unsafe { std::fs::File::from_raw_fd(stderr_pipe[0]) };
                reader
                    .read_to_string(&mut captured)
                    .expect("read captured stderr");
            }

            assert!(
                frames_for_tid(&captured, DISABLED_TID).is_empty(),
                "a profile-disabled thread must never publish a sibling slot; captured: {captured:?}"
            );
        });
    }

    #[test]
    fn dsr_fork_child_exec_reuses_and_clears_inherited_translator() {
        let process = std::sync::Arc::new(
            super::test_process_translator(16 * 1024).expect("create inherited translator"),
        );
        let key = (PC, super::types::CodeGeneration::INITIAL);
        let entry = super::types::CacheVa::published(carrick_guest_mem::HostVa(0x1000));
        process.state.write().blocks.insert(key, entry);
        let mut thread = super::ThreadTranslator::for_process(std::sync::Arc::clone(&process), 42);

        let mut reset_token = thread
            .prepare_direct_binding_exec_reset()
            .expect("mint exec reset authority");
        process
            .reset_after_fork_for_exec(&thread, &mut reset_token)
            .expect("consume surviving thread exec reset authority");
        thread
            .reset_for_exec(std::sync::Arc::clone(&process))
            .expect("reset translator for exec");

        let state = process.state.read();
        assert!(state.blocks.is_empty());
        assert!(state.published.is_empty());
    }

    #[test]
    fn classifies_copy_syscall_and_control_flow() {
        assert!(matches!(
            classify(0x9100_0400, PC),
            Ok(InstAction::Copy(0x9100_0400))
        ));
        assert!(matches!(
            classify(0xd503_251f, PC),
            Ok(InstAction::Copy(0xd503_251f))
        ));
        for word in [0xd53b_4416, 0xd51b_4416, 0xd53b_4436, 0xd51b_4436] {
            assert!(
                matches!(classify(word, PC), Ok(InstAction::Copy(observed)) if observed == word)
            );
        }
        assert!(matches!(
            classify(0xa900_4b82, PC),
            Ok(InstAction::Memory(memory))
                if memory.word == 0xa900_4b82
                    && memory.virtualization == MemoryVirtualization::X18X28ReadOnly
        ));
        assert!(matches!(
            classify(0xf900_0e5c, PC),
            Ok(InstAction::Memory(memory))
                if memory.word == 0xf900_0e5c
                    && memory.virtualization == MemoryVirtualization::X18X28ReadOnly
        ));
        assert!(matches!(
            classify(0x910a_6392, PC),
            Ok(InstAction::VirtualizedX18WriteX28Read {
                word: 0x910a_6392,
                ..
            })
        ));
        assert!(matches!(
            classify(0xcb16_0392, PC),
            Ok(InstAction::VirtualizedX18WriteX28Read {
                word: 0xcb16_0392,
                ..
            })
        ));
        assert!(matches!(
            classify(0xa94d_cb8f, PC),
            Ok(InstAction::Memory(memory))
                if memory.word == 0xa94d_cb8f
                    && memory.virtualization == MemoryVirtualization::X18WriteX28Read
        ));
        assert!(matches!(
            classify(0xd400_0001, PC),
            Ok(InstAction::Syscall { resume }) if resume == GuestVa(0x1004)
        ));
        assert!(matches!(
            classify(0x1400_0002, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Branch && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0x9400_0002, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Call && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd61f_0000, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Branch
        ));
        assert!(matches!(
            classify(0xd65f_03c0, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Return
        ));
    }

    #[test]
    fn copy_subset_rejects_virtualized_register_operands() {
        let word = 0xd280_0032;
        assert!(super::decode::decoded_operands_mention_x18(word, PC));
        assert!(matches!(
            classify(word, PC),
            Ok(InstAction::VirtualizedX18 { word: observed, .. }) if observed == word
        ));
        let word = 0xd280_003c;
        assert!(super::decode::decoded_operands_mention_x28(word, PC));
        assert!(matches!(
            classify(word, PC),
            Ok(InstAction::VirtualizedX28 { word: observed, .. }) if observed == word
        ));
        assert!(matches!(
            classify(0xf940_0240, PC),
            Ok(InstAction::Memory(memory)) if memory.base == MemoryBase::VirtualX18
        ));
        assert!(matches!(
            classify(0xf940_0380, PC),
            Ok(InstAction::Memory(memory)) if memory.base == MemoryBase::VirtualX28
        ));
    }

    proptest! {
        #[test]
        fn copy_subset_never_contains_virtualized_registers(word in any::<u32>()) {
            if matches!(classify(word, PC), Ok(InstAction::Copy(_))) {
                prop_assert!(!super::decode::decoded_operands_mention_x18(word, PC));
                prop_assert!(!super::decode::decoded_operands_mention_x28(word, PC));
            }
        }
    }

    #[test]
    #[ignore = "set CARRICK_DSR_SCAN_ELF to audit a built AArch64 ELF"]
    fn dsr_static_elf_reserved_register_decode_audit() {
        let path = std::env::var("CARRICK_DSR_SCAN_ELF").expect("CARRICK_DSR_SCAN_ELF");
        let bytes = std::fs::read(&path).expect("read scan ELF");
        let elf = goblin::elf::Elf::parse(&bytes).expect("parse scan ELF");
        let mut blind_spots = Vec::new();
        for header in elf.program_headers.iter().filter(|header| {
            header.p_type == goblin::elf::program_header::PT_LOAD
                && header.p_flags & goblin::elf::program_header::PF_X != 0
        }) {
            let start = usize::try_from(header.p_offset).expect("segment offset");
            let length = usize::try_from(header.p_filesz).expect("segment length");
            for (index, chunk) in bytes[start..start + length].chunks_exact(4).enumerate() {
                let word = u32::from_le_bytes(chunk.try_into().expect("instruction word"));
                let pc =
                    GuestVa(header.p_vaddr + u64::try_from(index * 4).expect("instruction PC"));
                let Ok(instruction) = bad64::decode(word, pc.raw()) else {
                    continue;
                };
                let text_mentions_reserved = instruction
                    .to_string()
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|token| matches!(token, "x18" | "w18" | "x28" | "w28"));
                let decoder_mentions_reserved =
                    super::decode::decoded_operands_mention_x18(word, pc)
                        || super::decode::decoded_operands_mention_x28(word, pc);
                if text_mentions_reserved && !decoder_mentions_reserved {
                    blind_spots.push(format!("0x{:x}: 0x{word:08x} {instruction}", pc.raw()));
                }
            }
        }
        assert!(
            blind_spots.is_empty(),
            "bad64 operand audit missed x18/x28 references:\n{}",
            blind_spots.join("\n")
        );
    }

    #[test]
    #[ignore = "set CARRICK_DSR_SCAN_CORPUS to audit a directory of AArch64 ELFs"]
    fn dsr_static_elf_instruction_contract_audit() {
        let root = std::path::PathBuf::from(
            std::env::var("CARRICK_DSR_SCAN_CORPUS").expect("CARRICK_DSR_SCAN_CORPUS"),
        );
        let mut paths = std::fs::read_dir(&root)
            .expect("read scan corpus")
            .map(|entry| entry.expect("read corpus entry").path())
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        paths.sort();

        let mut decoded_words = 0_u64;
        let mut contract_gaps = BTreeSet::new();
        for path in paths {
            let output = std::process::Command::new(
                std::env::var("CARRICK_DSR_OBJDUMP")
                    .unwrap_or_else(|_| "aarch64-linux-gnu-objdump".to_string()),
            )
            .arg("-d")
            .arg(&path)
            .output()
            .expect("run AArch64 objdump");
            if !output.status.success() {
                continue;
            }
            let disassembly = String::from_utf8(output.stdout).expect("objdump UTF-8");
            for line in disassembly.lines() {
                let mut fields = line.split_ascii_whitespace();
                let Some(pc_text) = fields.next().and_then(|field| field.strip_suffix(':')) else {
                    continue;
                };
                let Some(word_text) = fields.next() else {
                    continue;
                };
                let (Ok(pc_raw), Ok(word)) = (
                    u64::from_str_radix(pc_text, 16),
                    u32::from_str_radix(word_text, 16),
                ) else {
                    continue;
                };
                let pc = GuestVa(pc_raw);
                let Ok(instruction) = bad64::decode(word, pc.raw()) else {
                    continue;
                };
                decoded_words += 1;
                let text = instruction.to_string();
                let has_memory_operand = instruction.operands().iter().any(|operand| {
                    matches!(
                        operand,
                        bad64::Operand::MemReg(_)
                            | bad64::Operand::MemOffset { .. }
                            | bad64::Operand::MemPreIdx { .. }
                            | bad64::Operand::MemPostIdxReg(_)
                            | bad64::Operand::MemPostIdxImm { .. }
                            | bad64::Operand::MemExt { .. }
                    )
                });
                let expected_writeback = has_memory_operand
                    .then(|| text.rfind(']'))
                    .flatten()
                    .and_then(|close| {
                        let suffix = text[close + 1..].trim_start();
                        if suffix.starts_with('!') {
                            Some(MemoryWriteback::PreIndex)
                        } else if suffix.starts_with(',') {
                            Some(MemoryWriteback::PostIndex)
                        } else {
                            None
                        }
                    });
                let classified = classify(word, pc);
                if let Some(expected) = expected_writeback {
                    let actual = match &classified {
                        Ok(InstAction::Memory(memory)) => Some(memory.writeback),
                        _ => None,
                    };
                    if actual != Some(expected) {
                        contract_gaps.insert(format!(
                                "{}:0x{:x}: 0x{word:08x} writeback={actual:?}, expected={expected:?}: {text}",
                                path.display(),
                                pc.raw(),
                            ));
                    }
                }

                let mentions_reserved = super::decode::decoded_operands_mention_x18(word, pc)
                    || super::decode::decoded_operands_mention_x28(word, pc);
                if mentions_reserved
                    && matches!(
                        &classified,
                        Ok(InstAction::Unsupported { .. })
                            | Ok(InstAction::Memory(super::types::MemoryAccess {
                                virtualization: MemoryVirtualization::Unsupported,
                                ..
                            }))
                            | Err(_)
                    )
                {
                    contract_gaps.insert(format!(
                        "{}:0x{:x}: 0x{word:08x} reserved-register action={classified:?}: {text}",
                        path.display(),
                        pc.raw(),
                    ));
                }
            }
        }
        assert!(
            decoded_words > 0,
            "scan corpus contained no decoded AArch64 words"
        );
        assert!(
            contract_gaps.is_empty(),
            "AArch64 corpus contract gaps ({} across {decoded_words} decoded words):\n{}",
            contract_gaps.len(),
            contract_gaps.into_iter().collect::<Vec<_>>().join("\n")
        );
    }

    #[test]
    fn dsr_vdso_reserved_register_decode_audit() {
        let bytes = carrick_mem::vdso::vdso_image_bytes();
        let elf = goblin::elf::Elf::parse(&bytes).expect("parse vDSO ELF");
        let mut blind_spots = Vec::new();
        for header in elf.program_headers.iter().filter(|header| {
            header.p_type == goblin::elf::program_header::PT_LOAD
                && header.p_flags & goblin::elf::program_header::PF_X != 0
        }) {
            let start = usize::try_from(header.p_offset).expect("segment offset");
            let length = usize::try_from(header.p_filesz).expect("segment length");
            for (index, chunk) in bytes[start..start + length].chunks_exact(4).enumerate() {
                let word = u32::from_le_bytes(chunk.try_into().expect("instruction word"));
                let pc =
                    GuestVa(header.p_vaddr + u64::try_from(index * 4).expect("instruction PC"));
                let Ok(instruction) = bad64::decode(word, pc.raw()) else {
                    continue;
                };
                let text_mentions_reserved = instruction
                    .to_string()
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|token| matches!(token, "x18" | "w18" | "x28" | "w28"));
                let decoder_mentions_reserved =
                    super::decode::decoded_operands_mention_x18(word, pc)
                        || super::decode::decoded_operands_mention_x28(word, pc);
                if text_mentions_reserved && !decoder_mentions_reserved {
                    blind_spots.push(format!("0x{:x}: 0x{word:08x} {instruction}", pc.raw()));
                }
            }
        }
        assert!(
            blind_spots.is_empty(),
            "vDSO operand audit missed x18/x28 references:\n{}",
            blind_spots.join("\n")
        );
    }

    #[test]
    fn classifies_pc_relative_and_sensitive_operations() {
        assert!(matches!(
            classify(0x1000_0040, PC),
            Ok(InstAction::PcRelative(inst))
                if inst.kind == PcRelativeKind::Adr && inst.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xd53b_d040, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadTpidr
        ));
        assert!(matches!(
            classify(0xd51b_d040, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::WriteTpidr
        ));
        assert!(matches!(
            classify(0xd50b_7420, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::DcZva
        ));
        assert!(matches!(
            classify(0x9000_0000, PC),
            Ok(InstAction::PcRelative(inst)) if inst.kind == PcRelativeKind::Adrp
        ));
        assert!(matches!(
            classify(0x5800_0040, PC),
            Ok(InstAction::Memory(memory))
                if memory.class == MemoryClass::Literal
                    && memory.base == MemoryBase::Literal(GuestVa(0x1008))
        ));
        assert!(matches!(
            classify(0xd53b_0020, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadCtr
        ));
        assert!(matches!(
            classify(0xd53b_00e0, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::ReadDczid
        ));
        assert!(matches!(
            classify(0xd50b_7b20, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::DcCvau
        ));
        assert!(matches!(
            classify(0xd50b_7520, PC),
            Ok(InstAction::Sensitive(exit)) if exit.kind == SensitiveKind::IcIvau
        ));
    }

    #[test]
    fn dsr_counter_register_reads_execute_directly() {
        assert!(matches!(
            classify(0xd53b_e042, PC),
            Ok(InstAction::CounterRead(CounterRead {
                destination: CounterDestination::Gpr(2)
            }))
        ));
        assert!(matches!(
            classify(0xd53b_e05f, PC),
            Ok(InstAction::CounterRead(CounterRead {
                destination: CounterDestination::Discard
            }))
        ));
        assert!(matches!(classify(0xd53b_e002, PC), Ok(InstAction::Copy(_))));
        assert!(matches!(
            classify(0xd53b_e052, PC),
            Ok(InstAction::CounterRead(CounterRead {
                destination: CounterDestination::Gpr(18)
            }))
        ));
        assert!(matches!(
            classify(0xd53b_e05c, PC),
            Ok(InstAction::CounterRead(CounterRead {
                destination: CounterDestination::Gpr(28)
            }))
        ));
    }

    #[test]
    fn classifies_conditional_compare_test_and_indirect_calls() {
        assert!(matches!(
            classify(0x5400_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::Conditional && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xb400_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::CompareZero { nonzero: false }
                    && exit.target == GuestVa(0x1008)
        ));
        assert!(matches!(
            classify(0xb500_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::CompareZero { nonzero: true }
        ));
        assert!(matches!(
            classify(0x3600_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::TestBit { nonzero: false }
        ));
        assert!(matches!(
            classify(0x3700_0040, PC),
            Ok(InstAction::Direct(exit))
                if exit.kind == DirectKind::TestBit { nonzero: true }
        ));
        assert!(matches!(
            classify(0xd63f_0000, PC),
            Ok(InstAction::Indirect(exit)) if exit.kind == IndirectKind::Call
        ));
    }

    proptest! {
        #[test]
        fn direct_branch_targets_follow_signed_imm26(word_offset in -0x1ff_ffff_i32..=0x1ff_ffff_i32) {
            let pc = GuestVa(0x1_0000_0000);
            let immediate = (word_offset as u32) & 0x03ff_ffff;
            let word = 0x1400_0000 | immediate;
            let expected = GuestVa(pc.raw().wrapping_add_signed(i64::from(word_offset) * 4));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::Direct(exit))
                    if exit.kind == DirectKind::Branch && exit.target == expected
            ));
        }

        #[test]
        fn adr_targets_follow_signed_imm21(byte_offset in -0x10_0000_i32..=0x0f_ffff_i32) {
            let pc = GuestVa(0x1_0000_0000);
            let immediate = (byte_offset as u32) & 0x001f_ffff;
            let immlo = immediate & 0x3;
            let immhi = immediate >> 2;
            let word = 0x1000_0000 | (immlo << 29) | (immhi << 5);
            let expected = GuestVa(pc.raw().wrapping_add_signed(i64::from(byte_offset)));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::PcRelative(inst))
                    if inst.kind == PcRelativeKind::Adr && inst.target == expected
            ));
        }

        #[test]
        fn adrp_targets_follow_signed_page_imm21(page_offset in -0x10_0000_i32..=0x0f_ffff_i32) {
            let pc = GuestVa(0x1_0000_0abc);
            let immediate = (page_offset as u32) & 0x001f_ffff;
            let immlo = immediate & 0x3;
            let immhi = immediate >> 2;
            let word = 0x9000_0000 | (immlo << 29) | (immhi << 5);
            let expected = GuestVa((pc.raw() & !0xfff).wrapping_add_signed(i64::from(page_offset) * 4096));
            prop_assert!(matches!(
                classify(word, pc),
                Ok(InstAction::PcRelative(inst))
                    if inst.kind == PcRelativeKind::Adrp && inst.target == expected
            ));
        }
    }

    #[test]
    fn dsr_cache_publishes_executable_aarch64_code() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let result = super::cache::TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .map_err(super::types::DsrError::from)
            .and_then(|mut cache| {
                let mut writer = cache.begin_write(8)?;
                writer.write_words(&[0xd280_0540, 0xd65f_03c0])?; // mov x0,#42; ret
                let published = writer.publish()?;
                if published.len() != 8
                    || !cache.contains_host_pc(published.entry().host())
                    || cache.contains_host_pc(carrick_guest_mem::HostVa(1))
                {
                    return Err(super::types::DsrError::CachePolicy(
                        "published code metadata was inconsistent".to_string(),
                    ));
                }
                let function: extern "C" fn() -> u64 =
                    unsafe { std::mem::transmute(published.entry().host().raw()) };
                if function() != 42 {
                    return Err(super::types::DsrError::CachePolicy(
                        "published code returned the wrong value".to_string(),
                    ));
                }
                Ok(())
            });
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn dsr_cache_second_publication_executes_new_instructions() {
        let mut cache = super::cache::TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let mut first_writer = cache.begin_write(8).expect("begin first cache write");
        first_writer
            .write_words(&[0xd280_0540, 0xd65f_03c0])
            .expect("write first code");
        let first = first_writer.publish().expect("publish first code");
        let first_function: extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(first.entry().host().raw()) };
        assert_eq!(first_function(), 42);

        let mut second_writer = cache.begin_write(8).expect("begin second cache write");
        second_writer
            .write_words(&[0xd280_00e0, 0xd65f_03c0])
            .expect("write second code"); // mov x0,#7; ret
        let second = second_writer.publish().expect("publish second code");
        let second_function: extern "C" fn() -> u64 =
            unsafe { std::mem::transmute(second.entry().host().raw()) };
        assert_eq!(second_function(), 7);
        assert_ne!(first.entry(), second.entry());
    }

    fn assert_child_faults(action: impl FnOnce()) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            action();
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        let fatal_handler_exit = libc::WIFEXITED(status)
            && matches!(
                libc::WEXITSTATUS(status),
                value if value == 128 + libc::SIGBUS || value == 128 + libc::SIGSEGV
            );
        assert!(
            fatal_handler_exit
                || (libc::WIFSIGNALED(status)
                    && matches!(libc::WTERMSIG(status), libc::SIGBUS | libc::SIGSEGV)),
            "child unexpectedly survived W/X violation: status=0x{status:x}"
        );
    }

    #[test]
    fn dsr_cache_write_and_execute_phases_are_disjoint() {
        assert_child_faults(|| {
            let mut cache = super::cache::TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate translation cache");
            let mut writer = cache.begin_write(8).expect("begin cache write");
            writer
                .write_words(&[0xd280_0540, 0xd65f_03c0])
                .expect("write code");
            let function: extern "C" fn() -> u64 =
                unsafe { std::mem::transmute(writer.entry_for_test().host().raw()) };
            let _ = function();
        });

        assert_child_faults(|| {
            let mut cache = super::cache::TranslationCache::new(
                16 * 1024,
                crate::native_darwin::darwin_jit::active_host_jit(),
            )
            .expect("allocate translation cache");
            let mut writer = cache.begin_write(8).expect("begin cache write");
            writer
                .write_words(&[0xd280_0540, 0xd65f_03c0])
                .expect("write code");
            let published = writer.publish().expect("publish code");
            let ptr = published.entry().host().raw() as *mut u32;
            unsafe { std::ptr::write_volatile(ptr, 0xd280_00e0) };
        });
    }

    #[test]
    fn dsr_cache_published_code_is_fork_inherited() {
        let mut cache = super::cache::TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let mut writer = cache.begin_write(8).expect("begin cache write");
        writer
            .write_words(&[0xd280_0540, 0xd65f_03c0])
            .expect("write code");
        let published = writer.publish().expect("publish code");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // The per-thread MAP_JIT write-protect bit is NOT reliably
            // inherited executable-only across `fork(2)` on Apple Silicon: a
            // process that has toggled the bit (as the wider test suite does)
            // can hand the sole surviving child a WRITABLE (non-executable)
            // window, so executing the inherited cache faults with SIGBUS.
            // The production fork path never executes inherited translated code
            // without first repairing this via `TranslationCache::after_fork_child`
            // (see `carrick-dsr-aarch64` translator's `after_fork_child` →
            // `state.cache.after_fork_child()`); this test must honor the same
            // contract before it dereferences the inherited entry.
            cache.after_fork_child();
            let function: extern "C" fn() -> u64 =
                unsafe { std::mem::transmute(published.entry().host().raw()) };
            unsafe { libc::_exit(i32::from(function() != 42)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn dsr_cache_child_discards_inherited_unpublished_write() {
        let mut cache = super::cache::TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate translation cache");
        let writer = cache.begin_write(8).expect("begin inherited cache write");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            drop(writer);
            let result = cache
                .begin_write(8)
                .map_err(super::types::DsrError::from)
                .and_then(|mut clean_writer| {
                    clean_writer.write_words(&[0xd280_00e0, 0xd65f_03c0])?;
                    let published = clean_writer.publish()?;
                    let function: extern "C" fn() -> u64 =
                        unsafe { std::mem::transmute(published.entry().host().raw()) };
                    if function() != 7 {
                        return Err(super::types::DsrError::CachePolicy(
                            "child clean transaction returned the wrong value".to_string(),
                        ));
                    }
                    Ok(())
                });
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);

        drop(writer);
    }

    #[test]
    fn dsr_cache_exhaustion_is_a_typed_error() {
        let mut cache = super::cache::TranslationCache::new(
            1,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("allocate one-page translation cache");
        let error = match cache.begin_write(16 * 1024 + 4) {
            Ok(_) => panic!("oversized write should exhaust cache"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            super::cache::CacheError::Capacity {
                requested: 16_388,
                used: 0,
                capacity: 16_384,
            }
        ));
    }
}
