//! Shim: the per-block translation-artifact spike store moved verbatim to
//! `carrick_dsr_aarch64::artifact_spike` as part of the staged
//! native-backend extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `dsr::artifact_spike::*` call paths resolve
//! unchanged.
//!
//! The re-exec capsule schema (`NativeReexecArtifactSpikeV1`) is
//! macOS-gated runtime code and did NOT move; the arch crate speaks the
//! plain [`ArtifactSpikeReexecConfig`] carrier instead, and the wrappers
//! below (which SHADOW the glob re-exports of the same names) keep the V1
//! signatures for the runtime's capsule call sites. The V1 <-> carrier field
//! mapping lives in `native_exec_capsule.rs`.

pub(in crate::native_darwin) use carrick_dsr_aarch64::artifact_spike::*;

pub(crate) fn authority_snapshot_if_enabled()
-> anyhow::Result<Option<crate::native_exec_capsule::NativeReexecArtifactSpikeV1>> {
    Ok(
        carrick_dsr_aarch64::artifact_spike::authority_snapshot_if_enabled()?
            .map(crate::native_exec_capsule::NativeReexecArtifactSpikeV1::from),
    )
}

pub(crate) fn adopt_for_resume(
    snapshot: &crate::native_exec_capsule::NativeReexecArtifactSpikeV1,
) -> anyhow::Result<()> {
    carrick_dsr_aarch64::artifact_spike::adopt_for_resume(&ArtifactSpikeReexecConfig::from(
        snapshot,
    ))
}

// The two replay tests below publish into a live `TranslationCache` through
// the Darwin host JIT (`darwin_jit::active_host_jit`), which is still
// runtime-owned this slice, so they stay here; the rest of the artifact
// store's tests moved with it. `emit_artifact_fixture`/`mov_wide` are
// duplicated from the arch crate's test module.
#[cfg(test)]
mod tests {
    use super::super::block::{BlockPlan, PlannedExit, PlannedInst};
    use super::super::cache::TranslationCache;
    use super::super::emit::{
        BiasedBase, BiasedBaseCoordinate, BiasedMemoryRecovery, DirectLink, EmitAddressMode,
        GenerationGuard, PcMapEntry, RecoveryAction, RecoveryEntry,
    };
    use super::super::types::{
        CacheOffset, CodeGeneration, CounterDestination, CounterRead, InstAction,
    };
    use super::*;
    use crate::native_darwin::address::NativeHostBias;
    use carrick_guest_mem::GuestVa;
    use std::sync::atomic::AtomicU64;

    const IMM16_MASK: u32 = 0x001f_ffe0;

    fn mov_wide(register: u8, value: u64) -> [u32; 4] {
        std::array::from_fn(|halfword| {
            let base = if halfword == 0 {
                0xd280_0000
            } else {
                0xf280_0000
            };
            let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
            base | ((halfword as u32) << 21) | (immediate << 5) | u32::from(register)
        })
    }

    fn emit_artifact_fixture(
        generation_address: u64,
        host_bias: u64,
    ) -> (ArtifactTemplate, ArtifactBindings) {
        let mut words = mov_wide(16, generation_address).to_vec();
        words.extend([0xd280_0540, 0xd65f_03c0]); // mov x0, #42; ret
        let relocation = ArtifactRelocation {
            first_word: 0,
            register: 16,
            value: ProcessValue::GenerationAddress,
            expected_opcode_mask: std::array::from_fn(|index| words[index] & !IMM16_MASK),
        };
        let bindings = ArtifactBindings::from_values([
            (ProcessValue::GenerationAddress, generation_address),
            (ProcessValue::HostBias, host_bias),
        ])
        .expect("unique fixture bindings");
        let bias = NativeHostBias::new(host_bias, 16 * 1024).expect("aligned fixture bias");
        let recovery = vec![RecoveryEntry {
            cache: CacheOffset::published(0),
            action: RecoveryAction::RecoverBiasedMemory(BiasedMemoryRecovery {
                scratch_registers: [16, 17, 0, 0],
                scratch_count: 2,
                base_scratch: 16,
                base: BiasedBase::Register(0),
                base_coordinate: BiasedBaseCoordinate::Guest,
                commit_base: false,
                virtual_x18_scratch: None,
                virtual_x28_scratch: None,
                host_bias: bias,
                instruction_complete: false,
            }),
        }];
        let template = ArtifactTemplate::normalize(
            words,
            vec![PcMapEntry {
                guest: GuestVa(0x4000),
                cache: CacheOffset::published(0),
            }],
            recovery,
            vec![DirectLink {
                slot: CacheOffset::published(20),
                target: GuestVa(0x5000),
            }],
            vec![0xd280_0540, 0xd65f_03c0],
            vec![relocation],
            &bindings,
        )
        .expect("normalize fixture");
        (template, bindings)
    }

    #[test]
    fn replay_matches_fresh_metadata_and_guest_result() {
        let (template, bindings) = emit_artifact_fixture(0x1000_0000, 0x2000_0000);
        let mut fresh_cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("fresh cache");
        let fresh = replay_artifact(&mut fresh_cache, &template, &bindings).expect("fresh replay");
        let mut replay_cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("replay cache");
        let replay = replay_artifact(&mut replay_cache, &template, &bindings).expect("replay");

        assert_eq!(fresh.map().entries(), replay.map().entries());
        assert_eq!(fresh.recovery(), replay.recovery());
        assert_eq!(fresh.direct_links(), replay.direct_links());
        #[cfg(target_arch = "aarch64")]
        unsafe {
            let fresh_fn: unsafe extern "C" fn() -> u64 =
                std::mem::transmute(fresh.entry().host().raw());
            let replay_fn: unsafe extern "C" fn() -> u64 =
                std::mem::transmute(replay.entry().host().raw());
            assert_eq!(fresh_fn(), 42);
            assert_eq!(replay_fn(), 42);
        }
    }

    #[test]
    fn counter_artifact_replay_matches_fresh_metadata() {
        let guest = GuestVa(0x6000);
        let source_words = vec![0xd53b_e042, 0xd400_0001];
        let plan = BlockPlan {
            start: guest,
            end: GuestVa(guest.raw() + 8),
            generation: CodeGeneration::INITIAL,
            instructions: vec![PlannedInst {
                guest,
                action: InstAction::CounterRead(CounterRead {
                    destination: CounterDestination::Gpr(2),
                }),
            }],
            exit: PlannedExit::Syscall {
                guest: GuestVa(guest.raw() + 4),
                resume: GuestVa(guest.raw() + 8),
            },
        };
        let generation = AtomicU64::new(CodeGeneration::INITIAL.get());
        let guard = GenerationGuard::new(&generation, CodeGeneration::INITIAL);
        let mut fresh_cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("fresh counter cache");
        let (fresh, record) = super::super::emit::emit_block_recording_artifact(
            &mut fresh_cache,
            &plan,
            guard,
            EmitAddressMode::Direct,
            source_words,
        )
        .expect("record counter artifact");
        let mut replay_cache = TranslationCache::new(
            16 * 1024,
            crate::native_darwin::darwin_jit::active_host_jit(),
        )
        .expect("replay counter cache");
        let replay =
            replay_artifact_owned(&mut replay_cache, record.template.clone(), &record.bindings)
                .expect("replay counter artifact without cloning decoded buffers");

        assert_eq!(fresh.map().entries(), replay.map().entries());
        assert_eq!(fresh.recovery(), replay.recovery());
        assert_eq!(fresh.direct_links(), replay.direct_links());
        assert_eq!(fresh.len(), replay.len());
        for offset in (0..fresh.len()).step_by(std::mem::size_of::<u32>()) {
            // SAFETY: both published blocks contain `len` executable bytes,
            // and the loop visits aligned-width words wholly within them.
            let fresh_word = unsafe {
                std::ptr::read_unaligned((fresh.entry().host().raw() + offset) as *const u32)
            };
            // SAFETY: same published-block bounds argument as `fresh_word`.
            let replay_word = unsafe {
                std::ptr::read_unaligned((replay.entry().host().raw() + offset) as *const u32)
            };
            assert_eq!(fresh_word, replay_word, "counter replay word {offset}");
        }
    }
}
