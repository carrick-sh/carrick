//! Shim: the AArch64 DSR block planner moved verbatim to
//! `carrick_dsr_aarch64::block` as part of the staged native-backend
//! extraction (see
//! docs/superpowers/specs/2026-07-17-native-backend-portability-seams-design.md);
//! re-exported so existing `super::block::*` call paths resolve unchanged.
//!
//! `plan_block(memory: &NativeMappedMemory, ...)` moved with the memory
//! model in the extraction-completing slice (`NativeMappedMemory` now lives
//! in the arch crate) and is covered by the glob re-export above; the three
//! production-biased planner tests that construct a live
//! `NativeMappedMemory` stay here (they run through the Darwin host JIT).

// `allow(unused_imports)`: since the translator orchestration moved to the
// arch crate the runtime LIB no longer names `dsr::block::*`; the re-export
// stays for the still-runtime-resident planner tests and the oracle.
#[allow(unused_imports)]
pub(in crate::native_darwin) use carrick_dsr_aarch64::block::*;

#[cfg(test)]
use super::types::{CodeGeneration, DsrError};
#[cfg(test)]
use carrick_guest_mem::GuestVa;

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_dsr_aarch64::types::{
        ExclusiveFusionDisposition, ExclusiveFusionRejection, ExclusiveFusionSite,
    };

    // The encode helpers and canonical CAS shape below are duplicated from
    // the arch crate's `block::tests` (they are `#[cfg(test)]`-private
    // there); the production-biased tests need them against a live
    // `NativeMappedMemory` fixture, which cannot move until the runtime
    // memory model does.

    // ldaxr w0, [x1]
    const LDAXR_W0_X1: u32 = 0x885f_fc20;
    // cmp w0, w2
    const CMP_W0_W2: u32 = 0x6b02_001f;
    // stlxr w3, w4, [x1]
    const STLXR_W3_W4_X1: u32 = 0x8803_fc24;
    // svc #0
    const SVC0: u32 = 0xd400_0001;
    const COND_NE: u32 = 1;

    /// Encode `b.<cond> target` at `pc`.
    fn encode_b_cond(pc: GuestVa, target: GuestVa, cond: u32) -> u32 {
        let offset = (target.raw() as i64 - pc.raw() as i64) / 4;
        let imm19 = (offset as u32) & 0x7_ffff;
        0x5400_0000 | (imm19 << 5) | cond
    }

    /// Encode `cbnz w<rt>, target` at `pc`.
    fn encode_cbnz_w(pc: GuestVa, target: GuestVa, rt: u32) -> u32 {
        let offset = (target.raw() as i64 - pc.raw() as i64) / 4;
        let imm19 = (offset as u32) & 0x7_ffff;
        0x3500_0000 | (imm19 << 5) | rt
    }

    fn encode_cmp_w(left: u32, right: u32) -> u32 {
        0x6b00_001f | (right << 16) | (left << 5)
    }

    /// Replace the encoded base register (bits [9:5]) of an exclusive
    /// access word.
    fn with_base_register(word: u32, index: u32) -> u32 {
        (word & !(0x1f << 5)) | (index << 5)
    }

    fn canonical_cas(start: GuestVa) -> [u32; 6] {
        let branch_pc = GuestVa(start.raw() + 8);
        let retry_pc = GuestVa(start.raw() + 16);
        let out_pc = GuestVa(start.raw() + 20);
        [
            LDAXR_W0_X1,
            CMP_W0_W2,
            encode_b_cond(branch_pc, out_pc, COND_NE),
            STLXR_W3_W4_X1,
            encode_cbnz_w(retry_pc, start, 3),
            SVC0,
        ]
    }

    /// Plan the block via the moved production planner (`plan_with_reader`),
    /// the exact path `plan_block` drives.
    fn plan_via_production(
        words: &[u32],
        start: GuestVa,
        policy: ExclusiveFusionPolicy,
        page_size: u64,
    ) -> BlockPlan {
        plan_with_reader(
            start,
            CodeGeneration::INITIAL,
            256,
            page_size,
            policy,
            |pc| {
                let offset = usize::try_from((pc.raw() - start.raw()) / 4)
                    .map_err(|_| DsrError::BlockPolicy("test offset overflow".to_string()))?;
                words
                    .get(offset)
                    .copied()
                    .ok_or_else(|| DsrError::MemoryRead {
                        pc: pc.raw(),
                        detail: "test region exhausted".to_string(),
                    })
            },
        )
        .expect("plan production block")
    }

    fn plan_biased_memory_via_production(words: &[u32]) -> BlockPlan {
        static FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        const BIAS: u64 = 0x80_0000_0000;
        const PAGE_SIZE: u64 = 16 * 1024;
        const GUEST_CODE: GuestVa = GuestVa(0x21_0000_0000);
        let _fixture_guard = FIXTURE_LOCK.lock().expect("lock biased planner fixture");
        let host_bias = crate::native_darwin::address::NativeHostBias::new(BIAS, PAGE_SIZE)
            .expect("construct biased planner host bias");
        let mapping = crate::native_darwin::address::OwnedHostMapping::map_exact(
            carrick_guest_mem::HostVa((BIAS + GUEST_CODE.raw()) as usize),
            PAGE_SIZE as usize,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_PRIVATE,
        )
        .expect("map biased planner fixture");
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
        let memory = crate::native_darwin::NativeMappedMemory {
            address_mode: crate::native_darwin::address::NativeAddressMode::Biased { host_bias },
            owned_host_ranges: std::sync::Arc::new(vec![mapping.range()]),
            regions: vec![crate::native_darwin::NativeMappedRegion {
                start: GUEST_CODE.raw(),
                end: GUEST_CODE.raw() + PAGE_SIZE,
                host_protects: false,
                shared_futex: false,
                guest_writable: false,
                default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                shared_key_base: 0,
                shared_key_offset: 0,
            }],
            protections: crate::native_darwin::MemoryProtections::default(),
            native_page_protections: std::collections::BTreeMap::new(),
            native_write_exec_writable_pages: std::collections::BTreeSet::new(),
            linux4k_page_protections: std::collections::BTreeMap::new(),
            exclusive_sequences: parking_lot::Mutex::new(std::collections::BTreeMap::new()),
            host_page_size: PAGE_SIZE,
            linux_page_size: PAGE_SIZE,
            dsr_generations: super::super::cache::PageGenerationTable::new(PAGE_SIZE)
                .expect("construct planner generation table"),
            dsr_translator: None,
            host_access_lifts: parking_lot::Mutex::new(std::collections::HashMap::new()),
        };
        plan_block(
            &memory,
            GUEST_CODE,
            CodeGeneration::INITIAL,
            EXCLUSIVE_REGION_SCAN_LIMIT,
        )
        .expect("plan biased memory through production policy")
    }

    #[test]
    fn production_biased_exclusive_planner_records_only_safe_scratch_candidates() {
        let start = GuestVa(0x21_0000_0000);
        // Biased mode now FUSES (see `block::fusion_policy_for`), so the
        // canonical CAS leaves the planner as a lowered `ExclusiveRegion`
        // rather than the `Sensitive` trap fallback it used to. The property
        // this test exists for is unchanged: a safe scratch plan is recorded.
        let eligible = plan_biased_memory_via_production(&canonical_cas(start));
        assert!(matches!(
            eligible.exit,
            PlannedExit::ExclusiveRegion {
                fusion: ExclusiveFusionSite {
                    disposition: ExclusiveFusionDisposition::FusedBiased,
                    biased_scratch: Some(_),
                    ..
                },
                ..
            }
        ));

        let scratch_order = [
            17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 30, 29, 27,
        ];
        let mut saturated = vec![LDAXR_W0_X1];
        saturated.extend(
            scratch_order
                .chunks(2)
                .map(|pair| encode_cmp_w(pair[0], pair.get(1).copied().unwrap_or(pair[0]))),
        );
        saturated.push(STLXR_W3_W4_X1);
        let retry_pc = GuestVa(start.raw() + saturated.len() as u64 * 4);
        saturated.push(encode_cbnz_w(retry_pc, start, 3));

        let rejected = plan_biased_memory_via_production(&saturated);
        assert!(matches!(
            rejected.exit,
            PlannedExit::Sensitive {
                fusion: Some(ExclusiveFusionSite {
                    disposition: ExclusiveFusionDisposition::Rejected(
                        ExclusiveFusionRejection::BiasedNoSafeScratch
                    ),
                    biased_scratch: None,
                    ..
                }),
                ..
            }
        ));
    }

    #[test]
    fn production_biased_planner_records_audited_go_atomic_alu_bodies() {
        let start = GuestVa(0x21_0000_0000);
        let cases = [
            ("add", 0x8b01_0042), // add x2, x2, x1
            ("and", 0x8a01_0062), // and x2, x3, x1
            ("orr", 0xaa01_0062), // orr x2, x3, x1
        ];

        for (name, body) in cases {
            let words = [
                LDAXR_W0_X1,
                body,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(start.raw() + 12), start, 3),
            ];
            let plan = plan_biased_memory_via_production(&words);
            // Fused, not trapped: these are the real shapes Go's sync/atomic
            // emits, and they are the population that made `sensitive_exclusive`
            // 76% of all gateway exits before biased fusion was enabled.
            let PlannedExit::ExclusiveRegion {
                fusion:
                    ExclusiveFusionSite {
                        disposition: ExclusiveFusionDisposition::FusedBiased,
                        biased_scratch: Some(scratch),
                        ..
                    },
                ..
            } = plan.exit
            else {
                panic!("Go atomic {name} body did not fuse with a safe biased scratch plan");
            };
            for used in [0, 1, 2, 3, 4, 27] {
                assert_ne!(scratch.address.index(), used, "{name} address scratch");
                assert_ne!(scratch.bias.index(), used, "{name} bias scratch");
            }
        }
    }

    #[test]
    fn production_biased_planner_falls_back_for_sp_based_exclusive_region() {
        let start = GuestVa(0x21_0000_0000);
        let load_word = with_base_register(LDAXR_W0_X1, 31);
        let store_word = with_base_register(STLXR_W3_W4_X1, 31);
        let words = [
            load_word,
            CMP_W0_W2,
            store_word,
            encode_cbnz_w(GuestVa(start.raw() + 12), start, 3),
        ];
        let direct = plan_via_production(&words, start, ExclusiveFusionPolicy::Direct, 0x1000);
        assert!(matches!(
            direct.exit,
            PlannedExit::ExclusiveRegion {
                fusion: ExclusiveFusionSite {
                    disposition: ExclusiveFusionDisposition::FusedDirect,
                    ..
                },
                ..
            }
        ));

        let plan = plan_biased_memory_via_production(&words);
        assert!(matches!(
            plan.exit,
            PlannedExit::Sensitive {
                fusion: Some(ExclusiveFusionSite {
                    disposition: ExclusiveFusionDisposition::Rejected(
                        ExclusiveFusionRejection::BiasedAddressFormUnsupported
                    ),
                    biased_scratch: None,
                    ..
                }),
                ..
            }
        ));
    }
}
