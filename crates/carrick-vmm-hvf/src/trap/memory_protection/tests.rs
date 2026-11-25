//! Unit tests for memory protection and alias remapping.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod alias_remap_limiter_tests {
    use super::*;

    #[test]
    fn exact_replay_marker_turns_a_sibling_race_into_success() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let len = HVF_PAGE_SIZE as usize;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate live replay backing");
        let host_addr = host_mapping.as_ptr() as usize;
        let backing = AliasBacking {
            start: 0x1000,
            ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7f00_0000,
            host_addr,
            size: len,
            physical_ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7f00_0000,
            physical_host_addr: host_addr,
            physical_size: len,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let key = replay_mapping_key(backing);
        let custody = CarrierVmCustody::new_live_fixture();
        let g1 = custody.live_generation().expect("live fixture generation");

        // Orphan replay marker without live alias row must be ignored/refused.
        alias_registry()
            .lock()
            .insert_replay_in_scope(backing.ownership_scope, key);
        let orphan_result = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::Ipa { gpa: backing.ipa },
                &mut |_| true,
            )
        };
        assert_eq!(orphan_result, Ok(None));

        // Registered live alias + replay marker hits the cache without mapping backend.
        register_shared_alias(backing);
        let result = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::Ipa { gpa: backing.ipa },
                &mut |_| true,
            )
        };
        assert_eq!(
            result,
            Ok(Some((
                backing,
                carrick_aarch64::stage2::Stage2Status::SUCCESS
            )))
        );
        assert!(alias_registry().lock().contains_replay(&key));

        mutate_external_alias_state(|registry| {
            registry.retain(|alias| alias.physical_ipa != backing.ipa);
        });
        forget_replay_extent(backing.ipa, backing.size);
        assert!(!alias_registry().lock().contains_replay(&key));
        drop(host_mapping);
    }

    #[test]
    fn caps_repeated_faults_on_one_alias_backing() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let mut limiter = AliasRemapLimiter::default();
        let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000;

        for _ in 0..AliasRemapLimiter::MAX_ATTEMPTS_PER_IPA {
            assert!(limiter.allow(ipa));
        }
        assert!(!limiter.allow(ipa));
    }

    #[test]
    fn alias_replacement_keeps_one_replay_identity_per_ipa() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let original = AliasBacking {
            start: 0x1000,
            ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7e00_0000,
            host_addr: 0x1234_0000,
            size: HVF_PAGE_SIZE as usize,
            physical_ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7e00_0000,
            physical_host_addr: 0x1234_0000,
            physical_size: HVF_PAGE_SIZE as usize,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::Private(2),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let replacement = AliasBacking {
            host_addr: 0x5678_0000,
            physical_host_addr: 0x5678_0000,
            ..original
        };
        register_shared_alias(original);
        register_shared_alias(replacement);

        let registry = alias_registry().lock();
        assert!(!registry.contains_replay(&replay_mapping_key(original)));
        assert!(registry.contains_replay(&replay_mapping_key(replacement)));
        assert_eq!(
            registry
                .all_replay_mappings()
                .iter()
                .filter(|(ipa, _, _, _, _)| *ipa == original.ipa)
                .count(),
            1
        );
        drop(registry);
        forget_replay_extent(original.ipa, original.size);
        alias_registry()
            .lock()
            .retain(|alias| alias.ipa != original.ipa);
    }

    #[test]
    fn permits_many_distinct_alias_backings() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let mut limiter = AliasRemapLimiter::default();

        for i in 0..64 {
            let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + i * 0x20_0000;
            assert!(
                limiter.allow(ipa),
                "alias backing {i} should not hit a global cap"
            );
        }
    }

    #[test]
    fn exhausted_alias_does_not_block_a_different_alias() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let mut limiter = AliasRemapLimiter::default();
        let first = crate::memory::LINUX_ALIAS_IPA_BASE;
        let second = first + 0x20_0000;

        for _ in 0..AliasRemapLimiter::MAX_ATTEMPTS_PER_IPA {
            assert!(limiter.allow(first));
        }

        assert!(!limiter.allow(first));
        assert!(limiter.allow(second));
        assert!(!limiter.allow(first));
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod memory_protection_tests {
    use super::*;

    #[test]
    fn exec_level_classifies_el0_as_guest_el1_as_kernel() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        // PSTATE M[3:0]: EL0t=0b0000, EL1t=0b0100, EL1h=0b0101.
        assert_eq!(ExecLevel::from_pstate(0b0000), ExecLevel::Guest);
        assert!(ExecLevel::from_pstate(0b0000).is_guest());
        // EL0t with DAIF/nzcv bits set high is still EL0 (only M[3:2] matter).
        assert_eq!(ExecLevel::from_pstate(0x6000_0000), ExecLevel::Guest);
        assert_eq!(ExecLevel::from_pstate(0b0100), ExecLevel::Kernel); // EL1t
        assert_eq!(ExecLevel::from_pstate(0b0101), ExecLevel::Kernel); // EL1h
        assert!(!ExecLevel::from_pstate(0b0101).is_guest());
    }

    #[test]
    fn deferred_cow_block_authentication_visits_each_descriptor_once() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let base = 0x6000_0000_u64;
        let end = base + 4 * 1024 * 1024;
        let mut page = base;
        let mut visits = 0;
        // Authenticated L0/L1 tables and one L2 block. Adjacent 4 KiB
        // addresses in that block share the exact same terminal descriptor.
        let walk = [0x1003, 0x2003, 0x6000_0001, 0];
        while page < end {
            visits += 1;
            page = next_deferred_cow_authentication_page(walk, page, end, &[]);
        }
        assert_eq!(visits, 2, "one authenticated descriptor per 2 MiB block");
    }

    #[test]
    fn deferred_cow_authentication_stops_at_cow_and_leaf_boundaries() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        use carrick_aarch64::vmm::{CowGranule, ForkCowRange};
        let base = 0x6000_0000_u64;
        let end = base + 2 * 1024 * 1024;
        let block = [0x1003, 0x2003, base | 1, 0];
        let armed = [ForkCowRange {
            va: base + 4096,
            len: 4096,
            executable: false,
            kernel_only: false,
            granule: CowGranule::Page,
        }];
        assert_eq!(
            next_deferred_cow_authentication_page(block, base, end, &armed),
            base + 4096
        );
        assert_eq!(
            next_deferred_cow_authentication_page(block, base + 4096, end, &armed),
            base + 8192
        );
        assert_eq!(
            next_deferred_cow_authentication_page(block, base + 8192, end, &armed),
            end
        );
        // A split block can contain a corrupt interior leaf. Never skip any
        // L3 descriptor, including when its neighbors have identical outputs.
        let split = [0x1003, 0x2003, 0x3003, base | 3];
        assert_eq!(
            next_deferred_cow_authentication_page(split, base, end, &[]),
            base + 4096
        );
        let invalid = [0x1003, 0x2003, base, 0];
        assert_eq!(
            next_deferred_cow_authentication_page(invalid, base, end, &[]),
            base + 4096
        );
        assert_eq!(
            next_deferred_cow_authentication_page(block, base, base + 8192, &[]),
            base + 8192
        );
    }

    #[test]
    fn deferred_cow_block_step_preserves_overlapping_unaligned_arm_classification() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        use carrick_aarch64::vmm::{CowGranule, ForkCowRange};
        let base = 0x6000_0000_u64;
        let end = base + 65536;
        let walk = [0x1003, base | 1, 0, 0]; // genuine L1 terminal shape
        let mut arms = vec![
            ForkCowRange {
                va: base + 17,
                len: 9000,
                executable: false,
                kernel_only: false,
                granule: CowGranule::Page,
            },
            ForkCowRange {
                va: base + 5000,
                len: 13000,
                executable: false,
                kernel_only: false,
                granule: CowGranule::Page,
            },
        ];
        assert_eq!(
            next_deferred_cow_authentication_page(walk, base, end, &[]),
            end
        );
        for _ in 0..2 {
            let covers = |page| {
                arms.iter()
                    .any(|r| page >= r.va && page < r.va + r.len as u64)
            };
            let mut page = base;
            while page < end {
                let next = next_deferred_cow_authentication_page(walk, page, end, &arms);
                assert!(next > page && next <= end && next.is_multiple_of(4096));
                for skipped in (page..next).step_by(4096) {
                    assert_eq!(covers(skipped), covers(page));
                }
                page = next;
            }
            arms.reverse();
        }
    }

    #[test]
    fn deferred_cow_walk_detects_interior_live_leaf_corruption() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let base = crate::memory::LINUX_MMAP_BASE;
        let bad_va = base + 4096;
        let mut manager = carrick_mmu_core::aarch64::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            crate::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        manager.set_readonly(bad_va, 4096, false, None).unwrap();
        let shadow = manager.debug_walk(bad_va);
        assert_ne!(shadow[3], 0, "fixture must contain an L3 split");
        let table = shadow[2] & 0x0000_ffff_ffff_f000;
        let slot =
            ((table - manager.base()) / 8) as usize + carrick_mmu_core::aarch64::indices(bad_va)[3];
        let pristine: Vec<u64> = manager
            .as_bytes()
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect();
        for corruption in [1 << 12, 1 << 7, 1 << 54] {
            // IPA, AP, UXN
            let mut host = pristine.clone();
            host[slot] ^= corruption;
            let resolver = (manager.base(), host.as_ptr().cast::<u8>());
            let mut page = base;
            let mut mismatch = None;
            while page < base + 3 * 4096 {
                let live = unsafe { manager.debug_walk_host(resolver, page).unwrap() };
                if live != manager.debug_walk(page) {
                    mismatch = Some(page);
                    break;
                }
                page = next_deferred_cow_authentication_page(live, page, base + 3 * 4096, &[]);
            }
            assert_eq!(mismatch, Some(bad_va));
        }
    }

    #[test]
    fn deferred_prot_none_accepts_retained_rw_ap_on_invalid_leaf() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        const AP_USER_RO: u64 = 0b11 << 6;
        let va = crate::memory::LINUX_MMAP_BASE;
        let mut page_tables = carrick_mmu_core::aarch64::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            crate::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        page_tables
            .set_rw(va, 0x1000, false, None)
            .expect("publish writable leaf");
        page_tables
            .set_prot_none(va, 0x1000, None)
            .expect("invalidate leaf while retaining its output and attributes");

        let leaf = carrick_mmu_core::aarch64::terminal_descriptor(page_tables.debug_walk(va));
        let expected_ipa = page_tables
            .translate_retained_output(va)
            .expect("invalid leaf retains exact output");
        assert_eq!(leaf & 1, 0, "fixture leaf is invalid");
        assert_eq!(leaf & (0b11 << 6), 0b01 << 6, "fixture retains RW AP");
        assert!(
            deferred_cow_leaf_authenticates(
                leaf,
                Some(expected_ipa),
                expected_ipa,
                AP_USER_RO,
                false,
                false,
            ),
            "AP is non-semantic once the exact published leaf is invalid"
        );
    }

    #[test]
    fn deferred_executable_protection_rejects_valid_uxn_leaf() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        const AP_USER_RW: u64 = 0b01 << 6;
        const UXN: u64 = 1 << 54;
        let va = crate::memory::LINUX_MMAP_BASE;
        let mut page_tables = carrick_mmu_core::aarch64::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            crate::memory::LINUX_PAGE_TABLES_BASE,
            carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
        );
        page_tables
            .set_rw(va, 0x1000, false, None)
            .expect("publish writable non-executable leaf");

        let leaf = carrick_mmu_core::aarch64::terminal_descriptor(page_tables.debug_walk(va));
        let expected_ipa = page_tables.translate(va).expect("valid leaf translates");
        assert_ne!(leaf & 1, 0, "fixture leaf is valid");
        assert_ne!(leaf & UXN, 0, "fixture leaf is execute-never");
        assert!(
            !deferred_cow_leaf_authenticates(
                leaf,
                Some(expected_ipa),
                expected_ipa,
                AP_USER_RW,
                true,
                true,
            ),
            "an executable receipt must reject a UXN leaf"
        );
    }

    #[test]
    fn cloned_protection_metadata_shares_updates_across_thread_engines() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let protections = std::sync::Arc::new(MemoryProtections::default());
        let sibling = std::sync::Arc::clone(&protections);

        protections.set_no_access(0x4000, 0x2000, true);
        assert!(sibling.range_no_access(0x4fff, 1));

        sibling.set_no_access(0x5000, 0x1000, false);
        assert!(protections.range_no_access(0x4000, 1));
        assert!(protections.range_no_access(0x4fff, 1));
        assert!(!protections.range_no_access(0x5000, 1));
        assert!(!protections.range_no_access(0x6000 - 1, 1));
    }

    #[test]
    fn protection_ranges_are_sorted_coalesced_and_split_on_clear() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let protections = MemoryProtections::default();

        protections.set_no_access(0x3000, 0x1000, true);
        protections.set_no_access(0x1000, 0x1000, true);
        protections.set_no_access(0x2000, 0x1000, true);

        assert_eq!(protections.snapshot(), vec![(0x1000, 0x4000)]);
        assert!(protections.range_no_access(0x1800, 1));
        assert!(protections.range_no_access(0x3fff, 1));
        assert!(!protections.range_no_access(0x4000, 1));

        protections.set_no_access(0x2000, 0x800, false);

        assert_eq!(
            protections.snapshot(),
            vec![(0x1000, 0x2000), (0x2800, 0x4000)]
        );
        assert!(!protections.range_no_access(0x2000, 0x800));
        assert!(protections.range_no_access(0x2800, 1));
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod alias_registry_tests {
    use super::*;

    /// Test adapter preserving the retired linear signature over the index.
    fn mapping_is_current_for_process_fork_test(
        mapping: &HvfMappedRegion,
        aliases: &[AliasBacking],
        mm_root_slot: Option<(u64, u64)>,
    ) -> bool {
        mapping_is_current_for_process_fork_indexed(
            mapping,
            &process_alias_index(aliases, mm_root_slot, ContainerRootToken::ROOT),
        )
    }

    #[test]
    fn private_alias_scope_separates_root_and_child_mm_root_slots() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let container_a = ContainerRootToken::ROOT;
        let container_b = ContainerRootToken::from_raw(2);
        assert!(alias_matches_process_scope(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1
            },
            Some(root_slot),
            container_a,
        ));
        assert!(!alias_matches_process_scope(
            AliasOwnershipScope::ContainerRoot(container_a),
            Some(root_slot),
            container_a,
        ));
        assert!(alias_matches_process_scope(
            AliasOwnershipScope::ContainerRoot(container_a),
            None,
            container_a,
        ));
        assert!(!alias_matches_process_scope(
            AliasOwnershipScope::ContainerRoot(container_a),
            None,
            container_b,
        ));
        assert!(!alias_matches_process_scope(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1
            },
            None,
            container_a,
        ));
        assert!(!alias_matches_process_scope(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0 + root_slot.1,
                size: root_slot.1
            },
            Some(root_slot),
            container_a,
        ));
        assert!(alias_matches_process_scope(
            AliasOwnershipScope::Global,
            Some(root_slot),
            container_a,
        ));
        assert!(alias_matches_process_scope(
            AliasOwnershipScope::Global,
            Some(root_slot),
            container_b,
        ));
    }

    #[test]
    fn fork_shared_anonymous_alias_stays_process_scoped() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let parent_root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let foreign_root_slot = (parent_root_slot.0 + parent_root_slot.1, parent_root_slot.1);
        let requested = carrick_mem::memory::LINUX_ALIAS_IPA_BASE;
        let sharing = GuestMappingSharing::ForkSharedAnonymous;
        assert!(sharing.shares_across_fork());
        assert!(!sharing.uses_global_ipa());
        assert!(sharing.has_shared_futex_identity());

        // A MAP_SHARED anonymous alias needs a fork-shared backing, but that
        // does not make it a shared-file/futex identity. Its physical frame
        // still owns one stable global IPA; semantic visibility remains scoped
        // to the owning mm and explicitly inherited descendants.
        let ipa = requested;
        assert_eq!(ipa, requested);

        let alias = AliasBacking {
            start: 0x1400_0000_0000,
            ipa,
            host_addr: 0x1000,
            size: 0x4000,
            physical_ipa: ipa,
            physical_host_addr: 0x1000,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: parent_root_slot.0,
                size: parent_root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::SharedAnon(41),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        assert_eq!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[alias],
                Some(parent_root_slot),
                ContainerRootToken::ROOT,
            )
            .len(),
            1,
            "the owning mm must inventory its sibling-owned alias"
        );
        assert!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[alias],
                Some(foreign_root_slot),
                ContainerRootToken::ROOT,
            )
            .is_empty(),
            "an unrelated mm must not acquire anonymous backing through global alias scope"
        );
    }

    /// Retiring a scope drops its own indexes whole and edits only the
    /// carrier-wide ones per row, leaving exactly what rebuilding every index
    /// from the surviving buckets would give. Adversarial shape: many scopes
    /// whose rows share starts and physical extents (fork siblings mapping the
    /// same frames), so carrier-wide buckets hold rows of every scope.
    #[test]
    fn retiring_a_scope_leaves_the_indexes_a_rebuild_would() {
        let scope = |index: u64| AliasOwnershipScope::MmRootSlot {
            base: 0x9000_0000 + index * 0x20_0000,
            size: 0x20_0000,
        };
        let row = |owner: u64, page: u64, wide: bool| AliasBacking {
            start: 0x4000_0000 + page * 0x4000,
            ipa: crate::memory::LINUX_ALIAS_IPA_BASE + page * 0x4000,
            host_addr: 0x1000_0000 + (page as usize) * 0x4000,
            size: if wide { 0x8000 } else { HVF_PAGE_SIZE as usize },
            physical_ipa: crate::memory::LINUX_ALIAS_IPA_BASE + (page / 4) * 0x10000,
            physical_host_addr: 0x1000_0000 + (page as usize / 4) * 0x10000,
            physical_size: 0x10000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: scope(owner),
            inventory_backing: InventoryBackingIdentity::Private(owner),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let mut registry = AliasRegistry::default();
        for owner in 0..12 {
            for page in 0..64 {
                registry.push(row(owner, page, page % 3 == 0));
            }
        }
        let retired = registry.retire_scope(scope(5));
        assert_eq!(retired.len(), 64);
        assert_eq!(registry.rows, 11 * 64);
        let mut rebuilt = registry.clone();
        rebuilt.reindex();
        assert_eq!(registry.va_classes, rebuilt.va_classes);
        assert_eq!(registry.ipa_classes, rebuilt.ipa_classes);
        assert_eq!(registry.va_classes_by_scope, rebuilt.va_classes_by_scope);
        assert_eq!(
            registry.physical_classes_by_scope,
            rebuilt.physical_classes_by_scope
        );
        assert_eq!(registry.by_physical_start, rebuilt.by_physical_start);
        assert_eq!(
            registry.by_scope_physical_start,
            rebuilt.by_scope_physical_start
        );
        assert_eq!(
            registry.physical_size_counts_by_scope,
            rebuilt.physical_size_counts_by_scope
        );
        assert!(!registry.va_classes_by_scope.contains_key(&scope(5)));
    }

    #[test]
    fn address_space_replacement_drops_only_its_private_alias_scope() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let root_slot = (0x9000_0000, 0x20_0000);
        let container_a = ContainerRootToken::ROOT;
        let container_b = ContainerRootToken::from_raw(2);
        assert!(alias_is_owned_by_process(
            AliasOwnershipScope::ContainerRoot(container_a),
            None,
            container_a,
        ));
        assert!(!alias_is_owned_by_process(
            AliasOwnershipScope::ContainerRoot(container_a),
            None,
            container_b,
        ));
        assert!(!alias_is_owned_by_process(
            AliasOwnershipScope::ContainerRoot(container_a),
            Some(root_slot),
            container_a,
        ));
        assert!(alias_is_owned_by_process(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            Some(root_slot),
            container_a,
        ));
        assert!(!alias_is_owned_by_process(
            AliasOwnershipScope::MmRootSlot {
                base: root_slot.0 + root_slot.1,
                size: root_slot.1,
            },
            Some(root_slot),
            container_a,
        ));
        assert!(!alias_is_owned_by_process(
            AliasOwnershipScope::Global,
            Some(root_slot),
            container_a,
        ));
    }

    #[test]
    fn fork_shared_anonymous_alias_survives_a_second_fork_without_global_scope() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let parent_root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let child_root_slot = (parent_root_slot.0 + parent_root_slot.1, parent_root_slot.1);
        let grandchild_root_slot = (child_root_slot.0 + child_root_slot.1, child_root_slot.1);
        let unrelated_root_slot = (
            grandchild_root_slot.0 + grandchild_root_slot.1,
            grandchild_root_slot.1,
        );
        let frame_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        let alias = rebind_inherited_alias_to_process(
            AliasBacking {
                start: 0x1382_8ed0_0000,
                ipa: frame_ipa,
                host_addr: 0x1000,
                size: 0x4000,
                physical_ipa: frame_ipa,
                physical_host_addr: 0x1000,
                physical_size: 0x4000,
                perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
                guest_writable: true,
                sharing: GuestMappingSharing::ForkSharedAnonymous,
                ownership_scope: AliasOwnershipScope::MmRootSlot {
                    base: parent_root_slot.0,
                    size: parent_root_slot.1,
                },
                inventory_backing: InventoryBackingIdentity::SharedAnon(42),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            },
            child_root_slot,
        );

        assert_eq!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[alias],
                Some(child_root_slot),
                ContainerRootToken::ROOT,
            )
            .len(),
            1,
            "a child forking a grandchild must retain its inherited anonymous frame"
        );
        assert_eq!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[alias],
                Some(child_root_slot),
                ContainerRootToken::ROOT,
            )[0]
            .inventory_backing,
            InventoryBackingIdentity::SharedAnon(42),
            "scope rebinding must not mint a new backing identity",
        );
        let frame =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(9101).unwrap());
        let inventory = std::collections::BTreeMap::from([(
            (alias.physical_ipa, alias.physical_size as u64),
            super::InventoryExtent {
                frame,
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    std::num::NonZeroU64::new(9102).unwrap(),
                ),
                backing: alias.inventory_backing,
                stage2_base: alias.physical_ipa,
                stage2_length: alias.physical_size as u64,
                stage2_owner: super::InventoryStage2OwnerIdentity::TEST_UNOWNED,
            },
        )]);
        let child_source = super::ThreadMappingDesc::from_alias(alias).unwrap();
        let grandchild_extent = inherited_fork_inventory_extents(&child_source, &inventory)
            .pop()
            .expect("grandchild retains exact inherited mapping")
            .1;
        assert_eq!(grandchild_extent.frame, frame);
        assert_eq!(grandchild_extent.backing, alias.inventory_backing);

        let grandchild_alias = rebind_inherited_alias_to_process(alias, grandchild_root_slot);
        assert_eq!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[grandchild_alias],
                Some(grandchild_root_slot),
                ContainerRootToken::ROOT,
            )[0]
            .inventory_backing,
            alias.inventory_backing,
            "grandchild publication must retain the inherited frame identity",
        );
        assert!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &[grandchild_alias],
                Some(unrelated_root_slot),
                ContainerRootToken::ROOT,
            )
            .is_empty(),
            "an unrelated mm must not gain the inherited frame"
        );
    }

    #[test]
    fn alias_registry_partial_unmap_preserves_exact_live_fragments() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let va = 0x1383_0000_0000;
        let ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7d00_0000;
        let alias = AliasBacking {
            start: va,
            ipa,
            host_addr: 0x1234_0000,
            size: 0xc000,
            physical_ipa: ipa,
            physical_host_addr: 0x1234_0000,
            physical_size: 0xc000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            ownership_scope: AliasOwnershipScope::Global,
            inventory_backing: InventoryBackingIdentity::SharedFile {
                device: 1,
                inode: 2,
                offset: 0x8000,
                length: 0xc000,
            },
            shared_key_base: Some(carrick_guest_mem::SharedFutexFileIdentity {
                device: 0,
                inode: 7,
            }),
            shared_key_offset: 0x8000,
            owner_generation: 0,
        };
        let retained = std::collections::BTreeSet::new();
        assert!(
            retired_alias_disarm_spans(
                &[alias],
                va + 0x4000,
                0x4000,
                None,
                ContainerRootToken::ROOT,
                &retained
            )
            .is_empty(),
            "a semantic hole in a retained physical frame must keep its COW arm for same-VA reuse",
        );
        assert_eq!(
            retired_alias_disarm_spans(
                &[alias],
                va + 0x4000,
                0x4000,
                None,
                ContainerRootToken::ROOT,
                &std::collections::BTreeSet::from([(ipa, 0xc000)]),
            ),
            vec![CowArmedSpan {
                va: va + 0x4000,
                len: 0x4000,
                executable: false,
                kernel_only: false,
            }],
            "only retirement of the whole physical lease may disarm the semantic hole",
        );
        register_shared_alias(alias);

        let retired = unregister_alias(va + 0x4000, 0x4000, None, ContainerRootToken::ROOT);
        assert!(
            retired.is_empty(),
            "a partial semantic unmap must retain its containing stage-2 lease"
        );
        let mut fragments: Vec<AliasBacking> = alias_registry()
            .lock()
            .iter()
            .filter(|entry| entry.start >= va && entry.start < va + 0xc000)
            .copied()
            .collect();
        fragments.sort_by_key(|entry| entry.start);

        assert_eq!(fragments.len(), 2);
        assert_eq!(
            (fragments[0].start, fragments[0].ipa, fragments[0].size),
            (va, ipa, 0x4000)
        );
        assert_eq!(
            (fragments[1].start, fragments[1].ipa, fragments[1].size),
            (va + 0x8000, ipa + 0x8000, 0x4000),
        );
        assert_eq!(fragments[1].host_addr, alias.host_addr + 0x8000);
        assert_eq!(
            fragments[1].shared_key_offset,
            alias.shared_key_offset + 0x8000
        );

        let physical_extent = super::InventoryExtent {
            frame: carrick_hal::FrameId::from_kernel_allocation(
                std::num::NonZeroU64::new(9001).unwrap(),
            ),
            mapping: carrick_hal::MappingId::from_kernel_allocation(
                std::num::NonZeroU64::new(9002).unwrap(),
            ),
            backing: alias.inventory_backing,
            stage2_base: alias.physical_ipa,
            stage2_length: alias.physical_size as u64,
            stage2_owner: super::InventoryStage2OwnerIdentity::TEST_UNOWNED,
        };
        let inventory = std::collections::BTreeMap::from([(
            (alias.physical_ipa, alias.physical_size as u64),
            physical_extent,
        )]);
        for fragment in fragments {
            let desc = super::ThreadMappingDesc::from_alias(fragment).unwrap();
            assert_eq!(
                inherited_fork_inventory_extents(&desc, &inventory)
                    .pop()
                    .expect("fragment retains inherited mapping")
                    .1
                    .frame,
                physical_extent.frame,
                "each exact semantic fragment must remain forkable through the whole physical extent",
            );
        }

        assert_eq!(
            unregister_alias(va, 0xc000, None, ContainerRootToken::ROOT),
            std::collections::BTreeSet::from([(ipa, 0xc000)]),
            "the last semantic fragment retires the exact physical lease"
        );
    }

    #[test]
    fn retained_private_reuse_republishes_semantic_fragment_before_sibling_unmap() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let va = 0x1383_0800_0000;
        let physical_ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7c80_0000;
        let root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let scope = AliasOwnershipScope::MmRootSlot {
            base: root_slot.0,
            size: root_slot.1,
        };
        // A prior partial munmap carved the second Linux page out of this
        // still-live 16 KiB private frame. The first page is the remaining
        // semantic owner; the invalid second leaf retains its output IPA for
        // low-arena same-VA reuse.
        let prefix = AliasBacking {
            start: va,
            ipa: physical_ipa,
            host_addr: 0x4234_0000,
            size: 0x1000,
            physical_ipa,
            physical_host_addr: 0x4234_0000,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWriteExec),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: scope,
            inventory_backing: InventoryBackingIdentity::Private(46),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let mut registry = AliasRegistry::default();
        registry.extend([prefix]);

        let reused = retained_private_reuse_alias_fragment(
            &registry,
            va + 0x1000,
            physical_ipa + 0x1000,
            0x1000,
            Some(root_slot),
            ContainerRootToken::ROOT,
        )
        .expect("reused Linux page must regain semantic lifetime ownership");
        assert_eq!(reused.start, va + 0x1000);
        assert_eq!(reused.ipa, physical_ipa + 0x1000);
        assert_eq!(reused.host_addr, prefix.physical_host_addr + 0x1000);
        assert_eq!(reused.size, 0x1000);
        assert_eq!(reused.physical_ipa, physical_ipa);
        registry.push(reused);

        assert!(
            unregister_alias_entries(
                &mut registry,
                va,
                0x1000,
                Some(root_slot),
                ContainerRootToken::ROOT
            )
            .is_empty(),
            "unmapping the old sibling must retain the frame owned by the reused page",
        );
        assert_eq!(registry.ordered(), vec![reused]);
        assert_eq!(
            unregister_alias_entries(
                &mut registry,
                va + 0x1000,
                0x1000,
                Some(root_slot),
                ContainerRootToken::ROOT,
            ),
            std::collections::BTreeSet::from([(physical_ipa, 0x4000)]),
            "the physical lease retires only after the reused page is also unmapped",
        );
    }

    #[test]
    fn alias_registry_prefix_unmap_preserves_exact_suffix() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let va = 0x1383_1000_0000;
        let ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7c00_0000;
        let alias = AliasBacking {
            start: va,
            ipa,
            host_addr: 0x2234_0000,
            size: 0xc000,
            physical_ipa: ipa,
            physical_host_addr: 0x2234_0000,
            physical_size: 0xc000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::SharedAnon(44),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        register_shared_alias(alias);
        unregister_alias(va, 0x4000, None, ContainerRootToken::ROOT);
        let fragment = alias_registry()
            .lock()
            .iter()
            .find(|entry| entry.start == va + 0x4000)
            .copied()
            .expect("suffix fragment");
        assert_eq!(
            (fragment.ipa, fragment.host_addr, fragment.size),
            (ipa + 0x4000, alias.host_addr + 0x4000, 0x8000)
        );
        assert_eq!(
            (fragment.physical_ipa, fragment.physical_size),
            (ipa, 0xc000)
        );
        let frame =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(9011).unwrap());
        let inventory = std::collections::BTreeMap::from([(
            (alias.physical_ipa, alias.physical_size as u64),
            super::InventoryExtent {
                frame,
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    std::num::NonZeroU64::new(9012).unwrap(),
                ),
                backing: alias.inventory_backing,
                stage2_base: alias.physical_ipa,
                stage2_length: alias.physical_size as u64,
                stage2_owner: super::InventoryStage2OwnerIdentity::TEST_UNOWNED,
            },
        )]);
        assert_eq!(
            inherited_fork_inventory_extents(
                &super::ThreadMappingDesc::from_alias(fragment).unwrap(),
                &inventory,
            )
            .pop()
            .expect("suffix retains inherited mapping")
            .1
            .frame,
            frame,
            "the exact suffix must remain forkable through the retained physical extent",
        );
        unregister_alias(va, 0xc000, None, ContainerRootToken::ROOT);
    }

    #[test]
    fn alias_registry_suffix_unmap_preserves_exact_prefix() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let va = 0x1383_2000_0000;
        let ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7b00_0000;
        let alias = AliasBacking {
            start: va,
            ipa,
            host_addr: 0x3234_0000,
            size: 0xc000,
            physical_ipa: ipa,
            physical_host_addr: 0x3234_0000,
            physical_size: 0xc000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::SharedAnon(45),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        register_shared_alias(alias);
        unregister_alias(va + 0x8000, 0x4000, None, ContainerRootToken::ROOT);
        let fragment = alias_registry()
            .lock()
            .iter()
            .find(|entry| entry.start == va)
            .copied()
            .expect("prefix fragment");
        assert_eq!(
            (fragment.ipa, fragment.host_addr, fragment.size),
            (ipa, alias.host_addr, 0x8000)
        );
        assert_eq!(
            (fragment.physical_ipa, fragment.physical_size),
            (ipa, 0xc000)
        );
        let frame =
            carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(9021).unwrap());
        let inventory = std::collections::BTreeMap::from([(
            (alias.physical_ipa, alias.physical_size as u64),
            super::InventoryExtent {
                frame,
                mapping: carrick_hal::MappingId::from_kernel_allocation(
                    std::num::NonZeroU64::new(9022).unwrap(),
                ),
                backing: alias.inventory_backing,
                stage2_base: alias.physical_ipa,
                stage2_length: alias.physical_size as u64,
                stage2_owner: super::InventoryStage2OwnerIdentity::TEST_UNOWNED,
            },
        )]);
        assert_eq!(
            inherited_fork_inventory_extents(
                &super::ThreadMappingDesc::from_alias(fragment).unwrap(),
                &inventory,
            )
            .pop()
            .expect("prefix retains inherited mapping")
            .1
            .frame,
            frame,
            "the exact prefix must remain forkable through the retained physical extent",
        );
        unregister_alias(va, 0xc000, None, ContainerRootToken::ROOT);
    }

    #[test]
    fn alias_registry_full_semantic_unmap_rejects_hvf_padding() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let va = 0x1383_3000_0000;
        let ipa = carrick_mem::memory::LINUX_ALIAS_IPA_BASE + 0x7a00_0000;
        let guest_size = 0x1000;
        let physical_size = HVF_PAGE_SIZE as usize;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            physical_size,
            crate::host_mapping::HostMappingKind::SharedAnon,
        )
        .expect("16-KiB physical alias backing");
        let region = HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: va + guest_size as u64,
            host_addr: host_mapping.as_ptr(),
            size: host_mapping.len(),
            physical_size,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            stage2_generation: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let desc = ThreadMappingDesc::from_region(&region);
        assert_eq!(desc.size, guest_size, "thread/fork semantics stay exact");
        assert_eq!(
            desc.physical_size, physical_size,
            "the whole HVF granule remains the replay/lifetime extent"
        );
        let alias = AliasBacking {
            start: desc.start,
            ipa: desc.ipa,
            host_addr: desc.host_addr as usize,
            size: desc.size,
            physical_ipa: desc.physical_ipa,
            physical_host_addr: desc.physical_host_addr as usize,
            physical_size: desc.physical_size,
            perms: carrick_aarch64::stage2::stage2_perms_bits(desc.perms),
            guest_writable: desc.guest_writable,
            sharing: desc.sharing,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::SharedAnon(46),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        register_shared_alias(alias);

        unregister_alias(va, guest_size, None, ContainerRootToken::ROOT);
        let fragments: Vec<AliasBacking> = alias_registry()
            .lock()
            .iter()
            .filter(|entry| entry.physical_ipa == ipa)
            .copied()
            .collect();
        let padding_replay_candidate = lookup_shared_alias(ipa + guest_size as u64);
        let fork_candidates = missing_process_aliases(
            &std::collections::HashSet::new(),
            &fragments,
            None,
            ContainerRootToken::ROOT,
        );

        alias_registry()
            .lock()
            .retain(|entry| entry.physical_ipa != ipa);
        forget_replay_extent(ipa, physical_size);

        assert!(
            fragments.is_empty(),
            "fully unmapping the 4-KiB guest extent must not retain 12 KiB of HVF padding"
        );
        assert!(
            padding_replay_candidate.is_none(),
            "physical padding must not resolve into a lazy replay authority"
        );
        assert!(
            fork_candidates.is_empty(),
            "physical padding must not enter a descendant's semantic inventory"
        );
    }

    #[test]
    fn fork_source_uses_live_alias_inventory_not_retired_mapping_owners() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let va = 0x1382_8ed0_0000;
        let retired_ipa = root_slot.0 + 0x20_0000;
        let live_ipa = root_slot.0 + 0x40_0000;
        let mapping = |ipa, host_addr, is_dynamic_alias, owner_generation| HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: va + 0x4000,
            host_addr: host_addr as *mut u8,
            size: 0x4000,
            physical_size: 0x4000,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            stage2_generation: None,
            is_dynamic_alias,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation,
        };
        let live_alias = AliasBacking {
            start: va,
            ipa: live_ipa,
            host_addr: 0x3000,
            size: 0x4000,
            physical_ipa: live_ipa,
            physical_host_addr: 0x3000,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::SharedAnon(43),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 7,
        };

        assert!(
            !mapping_is_current_for_process_fork_test(
                &mapping(retired_ipa, 0x2000, true, 0),
                &[live_alias],
                Some(root_slot),
            ),
            "a retained stage-2 lifetime owner is not a live child mapping"
        );
        assert!(mapping_is_current_for_process_fork_test(
            &mapping(live_ipa, 0x3000, true, 7),
            &[live_alias],
            Some(root_slot),
        ));
        assert!(
            !mapping_is_current_for_process_fork_test(
                &mapping(live_ipa, 0x3000, true, 6),
                &[live_alias],
                Some(root_slot),
            ),
            "a recycled VA/IPA/host triple from an older owner generation must stay retired",
        );
        assert!(
            mapping_is_current_for_process_fork_test(
                &mapping(root_slot.0, 0x4000, false, 0),
                &[],
                Some(root_slot),
            ),
            "structural boot mappings do not depend on the dynamic alias registry"
        );
    }

    #[test]
    fn sparse_shared_aperture_owner_does_not_require_a_base_leaf() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        assert!(!super::fork_mapping_requires_base_translation(
            crate::memory::LINUX_SHARED_FILE_BASE,
            crate::memory::LINUX_SHARED_FILE_SIZE as usize,
            false,
        ));
        assert!(super::fork_mapping_requires_base_translation(
            crate::memory::LINUX_SHARED_FILE_BASE,
            0x4000,
            true,
        ));
        assert!(super::fork_mapping_requires_base_translation(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size() as usize,
            false,
        ));
    }

    #[test]
    fn next_generation_fork_deduplicates_exact_private_alias_but_keeps_overlay() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let root_slot = (0x9000_0000, 0x20_0000);
        let start = 0x0040_0000;
        let ipa = 0x0020_0000;
        let host = 0x3000usize;
        let generation = 17;
        let local = HvfMappedRegion {
            start,
            ipa,
            physical_ipa: ipa,
            end: start + 0x4000,
            host_addr: host as *mut u8,
            size: 0x4000,
            physical_size: 0x4000,
            perms: carrick_hal::MemPerms::ReadExec,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            stage2_generation: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: false,
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: generation,
        };
        let exact = AliasBacking {
            start,
            ipa,
            host_addr: host,
            size: 0x4000,
            physical_ipa: ipa,
            physical_host_addr: host,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadExec),
            guest_writable: false,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::Private(71),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: generation,
        };
        let overlay = AliasBacking {
            start: start + 0x1000,
            host_addr: host + 0x1000,
            size: 0x1000,
            ..exact
        };
        let aliases = [exact, overlay];
        let current = current_process_alias_keys(
            &[local],
            &aliases,
            Some(root_slot),
            ContainerRootToken::ROOT,
        );

        assert_eq!(
            missing_process_aliases(
                &current,
                &aliases,
                Some(root_slot),
                ContainerRootToken::ROOT,
            ),
            vec![overlay],
            "the exact child publication must not duplicate its local row, while a narrower same-IPA overlay remains a fork source",
        );
    }

    #[test]
    fn process_fork_includes_sibling_owned_private_aliases() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let local_ipa = root_slot.0 + 0x20_0000;
        let sibling_ipa = root_slot.0 + 0x40_0000;
        let foreign_ipa = root_slot.0 + root_slot.1 + 0x20_0000;
        let alias = |ipa, ownership_scope| AliasBacking {
            start: 0x1400_0000_0000 + ipa,
            ipa,
            host_addr: 0x1000,
            size: 0x4000,
            physical_ipa: ipa,
            physical_host_addr: 0x1000,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope,
            inventory_backing: InventoryBackingIdentity::Private(ipa),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let local_scope = AliasOwnershipScope::MmRootSlot {
            base: root_slot.0,
            size: root_slot.1,
        };
        let aliases = [
            alias(local_ipa, local_scope),
            alias(sibling_ipa, local_scope),
            alias(
                foreign_ipa,
                AliasOwnershipScope::MmRootSlot {
                    base: root_slot.0 + root_slot.1,
                    size: root_slot.1,
                },
            ),
        ];
        let local_aliases = std::collections::HashSet::from([process_alias_key(aliases[0])]);

        let missing = missing_process_aliases(
            &local_aliases,
            &aliases,
            Some(root_slot),
            ContainerRootToken::ROOT,
        );

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].ipa, sibling_ipa);
    }

    #[test]
    fn retired_local_alias_row_does_not_mask_live_fragment_at_same_ipa() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let root_slot = (0x9000_0000, 0x20_0000);
        let va = 0x0060_000a_8000;
        let ipa = 0x009b_0033_8000;
        let mapping = HvfMappedRegion {
            start: va,
            ipa,
            physical_ipa: ipa,
            end: va + 0x4000,
            host_addr: 0x2000 as *mut u8,
            size: 0x4000,
            physical_size: 0x4000,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            stage2_generation: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let live_fragment = AliasBacking {
            start: va + 0x2000,
            ipa: ipa + 0x2000,
            host_addr: 0x4000,
            size: 0x2000,
            physical_ipa: ipa,
            physical_host_addr: 0x2000,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::Private(44),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let aliases = [live_fragment];

        let current = current_process_alias_keys(
            &[mapping],
            &aliases,
            Some(root_slot),
            ContainerRootToken::ROOT,
        );
        assert!(current.is_empty(), "the unsplit local owner is retired");
        assert_eq!(
            missing_process_aliases(
                &current,
                &aliases,
                Some(root_slot),
                ContainerRootToken::ROOT
            ),
            vec![live_fragment],
            "the retired row must not suppress the live suffix from fork arming",
        );
    }

    #[test]
    fn container_root_isolation_prevents_cross_container_alias_visibility() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let container_1 = ContainerRootToken::ROOT;
        let container_2 = ContainerRootToken::from_raw(2);
        let root_slot_1 = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
            2 * 1024 * 1024,
        );
        let root_slot_2 = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE + 0x1000_0000,
            2 * 1024 * 1024,
        );

        let alias_c1_root = AliasBacking {
            start: 0x1000_0000,
            ipa: 0x2000_0000,
            host_addr: 0x3000_0000,
            size: 0x4000,
            physical_ipa: 0x2000_0000,
            physical_host_addr: 0x3000_0000,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::ContainerRoot(container_1),
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };

        let alias_c2_root = AliasBacking {
            start: 0x1000_0000,
            ipa: 0x2000_4000,
            host_addr: 0x3000_4000,
            size: 0x4000,
            physical_ipa: 0x2000_4000,
            physical_host_addr: 0x3000_4000,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::ContainerRoot(container_2),
            inventory_backing: InventoryBackingIdentity::Private(2),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };

        let aliases = [alias_c1_root, alias_c2_root];

        // Container 1 root process looking for aliases (None root_slot)
        let c1_root_missing = missing_process_aliases(
            &std::collections::HashSet::new(),
            &aliases,
            None,
            container_1,
        );
        assert_eq!(c1_root_missing.len(), 1);
        assert_eq!(c1_root_missing[0].ipa, alias_c1_root.ipa);

        // Container 2 root process looking for aliases (None root_slot)
        let c2_root_missing = missing_process_aliases(
            &std::collections::HashSet::new(),
            &aliases,
            None,
            container_2,
        );
        assert_eq!(c2_root_missing.len(), 1);
        assert_eq!(c2_root_missing[0].ipa, alias_c2_root.ipa);

        // Neither container sees the other's root alias when acting as child process
        assert!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &aliases,
                Some(root_slot_1),
                container_1,
            )
            .is_empty()
        );
        assert!(
            missing_process_aliases(
                &std::collections::HashSet::new(),
                &aliases,
                Some(root_slot_2),
                container_2,
            )
            .is_empty()
        );

        // Test unregister_alias_entries across containers
        let mut registry = AliasRegistry::default();
        registry.extend([alias_c1_root, alias_c2_root]);
        let retired =
            unregister_alias_entries(&mut registry, 0x1000_0000, 0x4000, None, container_1);
        assert_eq!(
            retired,
            std::collections::BTreeSet::from([(
                alias_c1_root.physical_ipa,
                alias_c1_root.physical_size as u64
            )])
        );
        assert_eq!(
            registry.ordered(),
            vec![alias_c2_root],
            "container 1 unregister must not touch container 2 alias"
        );
    }

    #[test]
    fn container_child_nonpersistent_cow_physical_source_lookup() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let container_1 = ContainerRootToken::from_raw(2);
        let child_root_slot = (
            carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE + 0x20_0000,
            2 * 1024 * 1024,
        );
        let mmap_va = 0x6000004000_u64;
        let mmap_ipa = 0x9b00204000_u64;
        let host_buf = vec![0u8; 0x4000];
        let host_ptr = host_buf.as_ptr() as usize;

        let alias = AliasBacking {
            start: mmap_va,
            ipa: mmap_ipa,
            host_addr: host_ptr,
            size: 0x4000,
            physical_ipa: mmap_ipa,
            physical_host_addr: host_ptr,
            physical_size: 0x4000,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: child_root_slot.0,
                size: child_root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };

        alias_registry().lock().push(alias);

        let mut child_task = super::HvfTaskState::neutral();
        child_task.container_root = container_1;
        child_task.mm_root_slot = Some(child_root_slot);
        // This test isolates container/mm alias visibility. Persistent HVPatch
        // sources additionally require an exact live owner pin; dedicated
        // custody tests above cover that production contract.
        child_task.persistent_vm_lifecycle = false;

        let source = child_task.physical_cow_source(mmap_va, mmap_ipa);
        assert!(
            source.is_some(),
            "child task must find physical COW source for rebound alias"
        );

        alias_registry().lock().retain(|a| a.start != mmap_va);
    }

    #[test]
    fn cow_physical_source_accepts_compound_prefix_before_an_offset_view() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let physical_ipa = 0x9b03_b60000_u64;
        let semantic_ipa = physical_ipa + 0x1000;
        let compound_va = 0x6001_17c000_u64;
        let semantic_va = compound_va + 0x1000;
        let physical = vec![0u8; 0x4000];
        let physical_host = physical.as_ptr() as *mut u8;
        let semantic_host = physical_host.wrapping_add(0x1000);
        let mut task = super::HvfTaskState::neutral();
        task.mappings.insert(HvfMappedRegion {
            start: semantic_va,
            ipa: semantic_ipa,
            physical_ipa,
            end: semantic_va + 0x1000,
            host_addr: semantic_host,
            size: 0x1000,
            physical_size: 0x4000,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            stage2_generation: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        });

        let source = task
            .physical_cow_source(compound_va, physical_ipa)
            .expect("resolve offset semantic COW source");
        assert_eq!(
            (source.host_addr(), source.physical_ipa()),
            (physical_host, physical_ipa),
            "a 16 KiB COW span may begin before its live semantic 4 KiB view"
        );
    }

    #[test]
    fn thread_mapping_desc_from_region_and_fork_inheritance_with_offset() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let physical_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
        let physical_len = 0x8000_usize;
        let semantic_offset = 0x4000_u64;
        let semantic_ipa = physical_ipa + semantic_offset;
        let semantic_va = 0x6000_004000_u64;
        let semantic_len = 0x4000_usize;

        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            physical_len,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("test host owner");
        let physical_host = host_mapping.as_ptr() as usize;
        let semantic_host = (physical_host + semantic_offset as usize) as *mut u8;

        let generation = super::next_global_frame_owner_generation();
        let owner = super::GlobalFrameHostOwner::new(
            super::GlobalFrameStage2Lease::fixed(physical_ipa, physical_len as u64),
            host_mapping,
            carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            generation,
            physical_ipa,
            physical_len as u64,
        );
        assert!(
            super::global_frame_host_owners()
                .lock()
                .insert(
                    (physical_ipa, physical_len as u64),
                    super::GlobalFrameOwnerEntry::Live(std::sync::Arc::new(owner)),
                )
                .is_none()
        );

        let region = HvfMappedRegion {
            start: semantic_va,
            ipa: semantic_ipa,
            physical_ipa,
            end: semantic_va + semantic_len as u64,
            host_addr: semantic_host,
            size: semantic_len,
            physical_size: physical_len,
            perms: carrick_hal::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            stage2_generation: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: generation,
        };

        let desc = ThreadMappingDesc::from_region(&region);
        assert_eq!(
            desc.physical_host_addr as usize, physical_host,
            "from_region must derive physical host base from semantic host and IPA offset"
        );
        assert_eq!(desc.host_addr as usize, semantic_host as usize);

        let id = |raw: u64| std::num::NonZeroU64::new(raw).unwrap();
        let inventory_extent = super::InventoryExtent {
            frame: carrick_hal::FrameId::from_kernel_allocation(id(9801)),
            mapping: carrick_hal::MappingId::from_kernel_allocation(id(9802)),
            backing: InventoryBackingIdentity::Private(9803),
            stage2_base: physical_ipa,
            stage2_length: physical_len as u64,
            stage2_owner: super::InventoryStage2OwnerIdentity {
                host_addr: physical_host,
                generation,
            },
        };
        let parent_inventory = std::collections::BTreeMap::from([(
            (physical_ipa, physical_len as u64),
            inventory_extent,
        )]);

        let inherited = inherited_fork_inventory_extents(&desc, &parent_inventory);
        assert_eq!(
            inherited.len(),
            1,
            "fork inventory inheritance must succeed for region with non-zero semantic offset"
        );
        assert_eq!(inherited[0].1.stage2_owner.host_addr, physical_host);
        assert_eq!(inherited[0].1.stage2_owner.generation, generation);

        super::global_frame_host_owners()
            .lock()
            .remove(&(physical_ipa, physical_len as u64));
    }

    #[test]
    fn scrub_run_remap_and_fallback() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        static ZERO_REMAP_ENV_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
        let _env_guard = ZERO_REMAP_ENV_LOCK.lock();

        const SIZE: usize = 64 * 1024;
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        let ptr = mapped as *mut u8;

        // 1. Eligible aligned run zeroes memory via kernel mmap replacement
        unsafe { core::ptr::write_bytes(ptr, 0x5a, SIZE) };
        assert_eq!(unsafe { *ptr }, 0x5a);
        let run = super::ScrubRun {
            host_start: ptr,
            len: SIZE,
            eligible: true,
        };
        run.flush();
        let bytes = unsafe { std::slice::from_raw_parts(ptr, SIZE) };
        assert!(
            bytes.iter().all(|&b| b == 0),
            "eligible aligned run must zero memory"
        );

        // 2. Ineligible run zeroes memory via write_bytes fallback
        unsafe { core::ptr::write_bytes(ptr, 0xa5, SIZE) };
        let run = super::ScrubRun {
            host_start: ptr,
            len: SIZE,
            eligible: false,
        };
        run.flush();
        let bytes = unsafe { std::slice::from_raw_parts(ptr, SIZE) };
        assert!(
            bytes.iter().all(|&b| b == 0),
            "ineligible run must zero memory via fallback"
        );

        // 3. Partial alignment (e.g. 20 KiB): 16 KiB remapped + 4 KiB memset
        unsafe { core::ptr::write_bytes(ptr, 0x33, SIZE) };
        let run = super::ScrubRun {
            host_start: ptr,
            len: 20480,
            eligible: true,
        };
        run.flush();
        let scrubbed = unsafe { std::slice::from_raw_parts(ptr, 20480) };
        assert!(
            scrubbed.iter().all(|&b| b == 0),
            "scrubbed portion must be zeroed"
        );
        let untouched = unsafe { std::slice::from_raw_parts(ptr.add(20480), SIZE - 20480) };
        assert!(
            untouched.iter().all(|&b| b == 0x33),
            "unscrubbed tail must remain untouched"
        );

        // 4. Escape hatch CARRICK_DSR_ZERO_REMAP=0 disables remap
        let prior = std::env::var_os("CARRICK_DSR_ZERO_REMAP");
        unsafe { std::env::set_var("CARRICK_DSR_ZERO_REMAP", "0") };
        assert!(!super::zero_anonymous_remap_enabled());
        match prior {
            Some(val) => unsafe { std::env::set_var("CARRICK_DSR_ZERO_REMAP", val) },
            None => unsafe { std::env::remove_var("CARRICK_DSR_ZERO_REMAP") },
        }
        assert!(super::zero_anonymous_remap_enabled());

        assert_eq!(unsafe { libc::munmap(mapped, SIZE) }, 0);
    }

    fn legacy_unregister_alias_entries(
        registry: &mut AliasRegistry,
        va: u64,
        len: usize,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> std::collections::BTreeSet<(u64, u64)> {
        let end = va.saturating_add(len as u64);
        let mut candidates = std::collections::BTreeSet::new();
        let scopes = AliasRegistry::process_visible_scopes(mm_root_slot, container_root);
        for scope in scopes {
            registry.rebuild_scope_rows(scope, |rows| {
                let mut replacement = Vec::with_capacity(rows.len().saturating_add(1));
                for (seq, entry) in rows {
                    let entry_end = entry.start.saturating_add(entry.size as u64);
                    if entry_end <= va || entry.start >= end {
                        replacement.push((seq, entry));
                        continue;
                    }
                    candidates.insert((entry.physical_ipa, entry.physical_size as u64));
                    if entry.start < va {
                        replacement.push((
                            seq,
                            AliasBacking {
                                size: usize::try_from(va - entry.start).unwrap_or_default(),
                                ..entry
                            },
                        ));
                    }
                    if entry_end > end {
                        let delta = end.saturating_sub(entry.start);
                        replacement.push((
                            seq,
                            AliasBacking {
                                start: end,
                                ipa: entry.ipa.saturating_add(delta),
                                host_addr: entry.host_addr.saturating_add(delta as usize),
                                size: usize::try_from(entry_end - end).unwrap_or_default(),
                                shared_key_offset: entry.shared_key_offset.saturating_add(delta),
                                ..entry
                            },
                        ));
                    }
                }
                replacement
            });
        }
        let mut retained_extents = std::collections::BTreeSet::new();
        for scope in scopes {
            let rows = registry.scope_rows(scope);
            for (_, entry) in rows {
                retained_extents.insert((entry.physical_ipa, entry.physical_size as u64));
            }
        }
        candidates.retain(|extent| !retained_extents.contains(extent));
        candidates
    }

    fn legacy_snapshot_plan_unmap(
        registry: &AliasRegistry,
        va: u64,
        len: usize,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> (std::collections::BTreeSet<(u64, u64)>, Vec<CowArmedSpan>) {
        let mut visible = AliasRegistry {
            next_seq: registry.next_seq,
            ..AliasRegistry::default()
        };
        for scope in AliasRegistry::process_visible_scopes(mm_root_slot, container_root) {
            if let Some(bucket) = registry.by_scope.get(&scope) {
                visible.rows = visible.rows.saturating_add(bucket.rows.len());
                visible.by_scope.insert(scope, bucket.clone());
            }
        }
        visible.reindex();
        let registry_before = visible.ordered();
        let mut planned = visible.clone();
        let planned_leases =
            legacy_unregister_alias_entries(&mut planned, va, len, mm_root_slot, container_root);
        let disarm_spans = retired_alias_disarm_spans(
            &registry_before,
            va,
            len,
            mm_root_slot,
            container_root,
            &planned_leases,
        );
        (planned_leases, disarm_spans)
    }

    fn make_test_alias(
        va: u64,
        size: usize,
        physical_ipa: u64,
        physical_size: usize,
        scope: AliasOwnershipScope,
    ) -> AliasBacking {
        AliasBacking {
            start: va,
            ipa: physical_ipa,
            host_addr: 0x4000_0000 + va as usize,
            size,
            physical_ipa,
            physical_host_addr: 0x4000_0000 + physical_ipa as usize,
            physical_size,
            perms: carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: scope,
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 1,
        }
    }

    /// The 2026-09-30 `hvpatch::host_alias` carrier fatal's transaction
    /// shape, VM-free. A munmap planned `{Y}`: its window also held a row of
    /// extent X, and a co-holder of X elsewhere in the scope kept X alive.
    /// Before the commit, ANOTHER MM retired that projection and -- holding
    /// only its own MM guard -- removed every scope's rows of it.
    /// Unregistering against the old plan then retired X too, a lease the plan
    /// never reserved. The commit must see the change before it mutates, and
    /// the restarted plan must be the live one and read strictly fewer rows.
    /// (The witnesses' co-holder was an OLDER incarnation, which no longer
    /// co-holds at all: see `stale_incarnation_row_does_not_hold_a_live_lease`.)
    #[test]
    fn retirement_commit_detects_an_out_of_guard_co_holder_removal() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT);
        let (va, len) = (0x1000_4000_u64, 0x8000_usize);
        let (x, y) = (0x9000_0000_u64, 0x9001_0000_u64);
        let planned_row = make_test_alias(0x1000_4000, 0x4000, y, 0x4000, scope);
        let mut live_row = make_test_alias(0x1000_8000, 0x4000, x, 0x4000, scope);
        live_row.owner_generation = 2125;
        let mut co_holder = make_test_alias(0x2000_0000, 0x2000, x, 0x4000, scope);
        co_holder.owner_generation = 2125;
        let mut registry = AliasRegistry::default();
        for alias in [planned_row, live_row, co_holder] {
            registry.push(alias);
        }

        let visible = AliasVisibleRevisions::capture(&registry, None, ContainerRootToken::ROOT);
        let (planned, window) =
            registry.plan_unregister_process_alias(va, len, None, ContainerRootToken::ROOT);
        assert_eq!(planned, [(y, 0x4000)].into());
        let footprint = alias_unmap_footprint(&registry, &window, None, ContainerRootToken::ROOT);
        assert_eq!(footprint.len(), 3);

        // Another MM retires X's projection, removing every scope's rows of
        // it; drop just the co-holder to model the window row surviving.
        assert_eq!(
            registry.remove_exact_values_in_batch(&[co_holder]),
            vec![co_holder]
        );
        let rows_before_commit: Vec<_> = registry.iter().copied().collect();

        let outcome = commit_planned_unregister_in(
            &mut registry,
            va,
            len,
            None,
            ContainerRootToken::ROOT,
            AliasUnmapPlanAuthority {
                planned_leases: &planned,
                visible_revisions: Some(visible),
            },
        );
        let live: std::collections::BTreeSet<_> = [(x, 0x4000), (y, 0x4000)].into();
        assert_eq!(
            outcome,
            AliasUnmapCommit::Stale {
                live_leases: live.clone()
            },
            "a plan the registry no longer supports must not commit"
        );
        assert_eq!(
            registry.iter().copied().collect::<Vec<_>>(),
            rows_before_commit,
            "a stale commit mutated the registry"
        );

        // The restart: a fresh plan under the same guard is the live one,
        // read strictly fewer rows, and commits exactly.
        let visible = AliasVisibleRevisions::capture(&registry, None, ContainerRootToken::ROOT);
        let (replanned, window) =
            registry.plan_unregister_process_alias(va, len, None, ContainerRootToken::ROOT);
        assert_eq!(replanned, live);
        assert!(
            alias_unmap_footprint(&registry, &window, None, ContainerRootToken::ROOT).len()
                < footprint.len()
        );
        assert_eq!(
            commit_planned_unregister_in(
                &mut registry,
                va,
                len,
                None,
                ContainerRootToken::ROOT,
                AliasUnmapPlanAuthority {
                    planned_leases: &replanned,
                    visible_revisions: Some(visible),
                },
            ),
            AliasUnmapCommit::Retired(live)
        );
        assert_eq!(registry.len(), 0);
    }

    /// A row naming an OLDER incarnation of a physical extent (a parent's COW
    /// shadow left behind when a child borrowed the old frame, outliving that
    /// lease) is not a co-holder of the live incarnation: it must not keep the
    /// live lease from retiring when its last live row is unmapped. Matching
    /// by extent alone leaked the live lease until the stale row happened to
    /// be removed, which is also what let another MM's cleanup change a plan.
    #[test]
    fn stale_incarnation_row_does_not_hold_a_live_lease() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT);
        let x = 0x9000_0000_u64;
        let mut live_row = make_test_alias(0x1000_8000, 0x4000, x, 0x4000, scope);
        live_row.owner_generation = 2125;
        let mut stale_row = make_test_alias(0x2000_0000, 0x2000, x, 0x4000, scope);
        stale_row.owner_generation = 1788;
        let mut same_incarnation = make_test_alias(0x3000_0000, 0x1000, x, 0x4000, scope);
        same_incarnation.owner_generation = 2125;
        let mut registry = AliasRegistry::default();
        registry.push(live_row);
        registry.push(stale_row);

        let (planned, _) = registry.plan_unregister_process_alias(
            0x1000_8000,
            0x4000,
            None,
            ContainerRootToken::ROOT,
        );
        assert_eq!(
            planned,
            [(x, 0x4000)].into(),
            "stale incarnation held the live lease"
        );
        let mut live = registry.clone();
        assert_eq!(
            unregister_alias_entries(
                &mut live,
                0x1000_8000,
                0x4000,
                None,
                ContainerRootToken::ROOT
            ),
            planned
        );

        // The same incarnation elsewhere still co-holds.
        registry.push(same_incarnation);
        let (planned, _) = registry.plan_unregister_process_alias(
            0x1000_8000,
            0x4000,
            None,
            ContainerRootToken::ROOT,
        );
        assert!(planned.is_empty(), "a live co-holder must keep the lease");
    }

    /// Where the stale incarnations came from (the witnesses showed ~10^4
    /// stale-incarnation co-holder encounters per mm-occupancy run). A parent
    /// COW-splits a page whose old frame a child still borrows: the parent's
    /// row for the old frame stays behind as a shadow. When the child -- the
    /// frame's last user -- EXITS, it retires that incarnation but removed
    /// only its own scope's rows, so the parent kept a row naming a retired,
    /// soon recycled IPA. Exit retirement must remove every scope's rows of
    /// exactly the incarnations it retired, and nothing else.
    #[test]
    fn exit_retirement_removes_other_scopes_rows_of_the_retired_incarnation() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let parent = AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT);
        let child_slot = (0x009a_0020_0000_u64, 0x20_0000_u64);
        let child = AliasOwnershipScope::MmRootSlot {
            base: child_slot.0,
            size: child_slot.1,
        };
        let x = 0x9000_0000_u64;
        let mut child_row = make_test_alias(0x6000_8000, 0x4000, x, 0x4000, child);
        child_row.owner_generation = 1788;
        let mut parent_shadow = make_test_alias(0x6000_8000, 0x2000, x, 0x4000, parent);
        parent_shadow.owner_generation = 1788;
        // The parent's live successor incarnation of the same IPA, and an
        // unrelated live row: neither may be touched.
        let mut parent_successor = make_test_alias(0x7000_0000, 0x4000, x, 0x4000, parent);
        parent_successor.owner_generation = 2125;
        let parent_other = make_test_alias(0x6000_c000, 0x4000, 0x9001_0000, 0x4000, parent);
        let mut registry = AliasRegistry::default();
        for alias in [child_row, parent_shadow, parent_successor, parent_other] {
            registry.push(alias);
        }

        let cleanup = crate::trap::retire_exited_process_rows_in(
            &mut registry,
            Some(child_slot),
            ContainerRootToken::ROOT,
            &[RetiredStage2Projection {
                physical_ipa: x,
                physical_length: 0x4000,
                owner: InventoryStage2OwnerIdentity {
                    host_addr: child_row.physical_host_addr,
                    generation: 1788,
                },
            }],
            |_| true,
        );
        let mut left: Vec<_> = registry.iter().copied().collect();
        left.sort_by_key(|alias| alias.start);
        assert_eq!(left, vec![parent_other, parent_successor]);
        assert_eq!(cleanup.removed_aliases, vec![parent_shadow]);
    }

    /// A visible-scope change that leaves this window's lease set alone (a
    /// row elsewhere in the scope) re-authenticates under the lock and
    /// commits; only a change to THIS window's leases restarts.
    #[test]
    fn retirement_commit_tolerates_unrelated_visible_scope_mutation() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT);
        let (va, len) = (0x1000_4000_u64, 0x4000_usize);
        let y = 0x9001_0000_u64;
        let mut registry = AliasRegistry::default();
        registry.push(make_test_alias(0x1000_4000, 0x4000, y, 0x4000, scope));
        let unrelated = make_test_alias(0x3000_0000, 0x4000, 0x9002_0000, 0x4000, scope);
        registry.push(unrelated);
        let visible = AliasVisibleRevisions::capture(&registry, None, ContainerRootToken::ROOT);
        let (planned, _) =
            registry.plan_unregister_process_alias(va, len, None, ContainerRootToken::ROOT);
        assert_eq!(
            registry.remove_exact_values_in_batch(&[unrelated]),
            vec![unrelated]
        );
        assert!(!visible.unchanged(&registry));
        assert_eq!(
            commit_planned_unregister_in(
                &mut registry,
                va,
                len,
                None,
                ContainerRootToken::ROOT,
                AliasUnmapPlanAuthority {
                    planned_leases: &planned,
                    visible_revisions: Some(visible),
                },
            ),
            AliasUnmapCommit::Retired(planned)
        );
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn forked_stack_grant_keeps_neighbor_and_child_leases_during_partial_discard() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let va = 0x0060_0269_0000_u64;
        let ipa = 0x009b_0443_4000_u64;
        let stack_len = 8 * 1024 * 1024;
        let parent_slot = (0x5000_0000, 0x4000);
        let child_slot = (0x6000_0000, 0x4000);
        let parent_scope = AliasOwnershipScope::MmRootSlot {
            base: parent_slot.0,
            size: parent_slot.1,
        };
        let child_scope = AliasOwnershipScope::MmRootSlot {
            base: child_slot.0,
            size: child_slot.1,
        };
        let mut registry = AliasRegistry::default();
        registry.push(make_test_alias(va, stack_len, ipa, stack_len, parent_scope));
        registry.push(make_test_alias(va, stack_len, ipa, stack_len, child_scope));
        for len in [0x10000, 0x7de000] {
            let (planned, _) = registry.plan_unregister_process_alias(
                va + 0x1000,
                len,
                Some(parent_slot),
                ContainerRootToken::ROOT,
            );
            let actual = unregister_alias_entries(
                &mut registry,
                va + 0x1000,
                len,
                Some(parent_slot),
                ContainerRootToken::ROOT,
            );
            assert_eq!(planned, actual);
            assert!(
                actual.is_empty(),
                "outside-range parent pages still hold the lease"
            );
            assert!(
                registry
                    .process_alias_containing_va_candidates(
                        va,
                        Some(parent_slot),
                        ContainerRootToken::ROOT,
                        |_| true
                    )
                    .iter()
                    .any(|alias| alias.physical_ipa == ipa)
            );
            assert!(
                registry
                    .process_alias_containing_va_candidates(
                        va + 0x1000,
                        Some(child_slot),
                        ContainerRootToken::ROOT,
                        |_| true
                    )
                    .iter()
                    .any(|alias| alias.physical_ipa == ipa)
            );
        }
    }

    #[test]
    fn planned_unmap_matches_legacy_snapshot_oracle() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let root_slot = Some((0x5000_0000, 0x4000));
        let owned_scope = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000,
            size: 0x4000,
        };
        let global_scope = AliasOwnershipScope::Global;
        let foreign_scope = AliasOwnershipScope::MmRootSlot {
            base: 0x6000_0000,
            size: 0x4000,
        };

        // Seed entries for various test patterns
        let seed = vec![
            // Discrete mappings
            make_test_alias(0x1000_0000, 0x1000, 0x8000_0000, 0x1000, owned_scope),
            make_test_alias(0x1000_4000, 0x4000, 0x8000_4000, 0x4000, owned_scope),
            make_test_alias(0x1000_a000, 0x8000, 0x8000_a000, 0x8000, owned_scope),
            // Contiguous mappings
            make_test_alias(0x1002_0000, 0x2000, 0x8002_0000, 0x2000, owned_scope),
            make_test_alias(0x1002_2000, 0x2000, 0x8002_2000, 0x2000, owned_scope),
            make_test_alias(0x1002_4000, 0x2000, 0x8002_4000, 0x2000, owned_scope),
            // Shared physical extent between two aliases
            make_test_alias(0x1003_0000, 0x2000, 0x8003_0000, 0x4000, owned_scope),
            make_test_alias(0x1003_4000, 0x2000, 0x8003_0000, 0x4000, owned_scope),
            // Global scope alias
            make_test_alias(0x1004_0000, 0x4000, 0x8004_0000, 0x4000, global_scope),
            // Foreign scope alias (should be untouched and invisible)
            make_test_alias(0x1005_0000, 0x4000, 0x8005_0000, 0x4000, foreign_scope),
        ];

        let base_registry = {
            let mut reg = AliasRegistry::default();
            for alias in &seed {
                reg.push(*alias);
            }
            reg
        };

        // Test vectors: (description, unmap_va, unmap_len)
        let test_cases = vec![
            ("empty len unmap", 0x1000_0000, 0),
            ("non-overlapping unmap", 0x1009_0000, 0x2000),
            ("exact match single alias", 0x1000_0000, 0x1000),
            ("prefix unmap", 0x1000_4000, 0x2000),
            ("suffix unmap", 0x1000_6000, 0x2000),
            ("middle unmap", 0x1000_b000, 0x2000),
            ("multi-row span (contiguous 3 rows)", 0x1002_1000, 0x4000),
            (
                "shared physical extent - first alias unmapped",
                0x1003_0000,
                0x2000,
            ),
            (
                "shared physical extent - second alias unmapped",
                0x1003_4000,
                0x2000,
            ),
            (
                "shared physical extent - both aliases unmapped",
                0x1003_0000,
                0x6000,
            ),
            ("global scope unmap", 0x1004_1000, 0x2000),
            ("foreign scope address unmap", 0x1005_0000, 0x4000),
        ];

        for (desc, va, len) in test_cases {
            let (oracle_leases, oracle_spans) = legacy_snapshot_plan_unmap(
                &base_registry,
                va,
                len,
                root_slot,
                ContainerRootToken::ROOT,
            );
            let (planned_leases, registry_before) = base_registry.plan_unregister_process_alias(
                va,
                len,
                root_slot,
                ContainerRootToken::ROOT,
            );
            let disarm_spans = retired_alias_disarm_spans(
                &registry_before,
                va,
                len,
                root_slot,
                ContainerRootToken::ROOT,
                &planned_leases,
            );

            assert_eq!(
                planned_leases, oracle_leases,
                "planned leases mismatch for case: {desc} (va={va:#x}, len={len:#x})"
            );
            assert_eq!(
                disarm_spans, oracle_spans,
                "disarm spans mismatch for case: {desc} (va={va:#x}, len={len:#x})"
            );

            // Now verify actual in-place removal against legacy removal
            let mut reg_new = base_registry.clone();
            let mut reg_oracle = base_registry.clone();
            let actual_new = unregister_alias_entries(
                &mut reg_new,
                va,
                len,
                root_slot,
                ContainerRootToken::ROOT,
            );
            let actual_oracle = legacy_unregister_alias_entries(
                &mut reg_oracle,
                va,
                len,
                root_slot,
                ContainerRootToken::ROOT,
            );

            assert_eq!(
                actual_new, actual_oracle,
                "actual removed leases mismatch for case: {desc}"
            );
            assert_eq!(
                actual_new, planned_leases,
                "actual removed leases must match planned leases for case: {desc}"
            );
            assert_eq!(
                reg_new.ordered(),
                reg_oracle.ordered(),
                "resulting registry ordered rows mismatch for case: {desc}"
            );
        }
    }

    /// A seeded generator. Shapes must be identical on every run and on every
    /// machine, so this is a fixed SplitMix64 rather than `rand`.
    struct ShapeRng(u64);

    impl ShapeRng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }

    type SelectedRows = Vec<(usize, u64, AliasBacking)>;

    /// The two ways of answering "which rows does this unmap split", per
    /// touched scope: `(scope, scan, window)`.
    ///
    /// `scan` is the full walk of the scope's row vector that
    /// `unregister_alias_entries` performs; `window` is the same question
    /// answered from the bounded `overlapping` window query, each row located
    /// in the bucket by binary search on its sequence. They must be equal in
    /// EVERY registry the routine runs over — the live one and the planner's
    /// staged one — or the frames a `munmap` retires stop matching the ones
    /// its caller planned.
    fn unmap_row_selections(
        registry: &AliasRegistry,
        va: u64,
        len: usize,
        mm_root_slot: Option<(u64, u64)>,
        container_root: ContainerRootToken,
    ) -> Vec<(AliasOwnershipScope, SelectedRows, SelectedRows)> {
        let Some(end) = va.checked_add(len as u64) else {
            return Vec::new();
        };
        if len == 0 || end <= va {
            return Vec::new();
        }
        let overlapping =
            registry.overlapping_process_aliases(va, len, mm_root_slot, container_root);
        let touched: std::collections::BTreeSet<AliasOwnershipScope> = overlapping
            .iter()
            .map(|(_, entry)| entry.ownership_scope)
            .collect();
        let mut out = Vec::new();
        for scope in touched {
            let Some(bucket) = registry.by_scope.get(&scope) else {
                continue;
            };
            let rows = &bucket.rows;
            let mut scan = Vec::new();
            for (pos, &(seq, alias)) in rows.iter().enumerate() {
                let entry_end = alias.start.saturating_add(alias.size as u64);
                if entry_end > va && alias.start < end {
                    scan.push((pos, seq, alias));
                }
            }
            let mut window = Vec::new();
            for &(seq, alias) in &overlapping {
                if alias.ownership_scope != scope {
                    continue;
                }
                if let Some(pos) = AliasRegistry::bucket_position_in(rows, seq, &alias, None) {
                    window.push((pos, seq, alias));
                }
            }
            window.sort_unstable_by_key(|&(pos, _, _)| pos);
            out.push((scope, scan, window));
        }
        out
    }

    fn describe_registry(registry: &AliasRegistry) -> String {
        let mut out = String::new();
        for (scope, bucket) in &registry.by_scope {
            out.push_str(&format!("  scope {scope:?}\n"));
            for (pos, (seq, alias)) in bucket.rows.iter().enumerate() {
                out.push_str(&format!(
                    "    [{pos}] seq={seq} va={:#x}..{:#x} phys={:#x}+{:#x}\n",
                    alias.start,
                    alias.start + alias.size as u64,
                    alias.physical_ipa,
                    alias.physical_size,
                ));
            }
        }
        out
    }

    /// Selecting an unmap's rows from the guest-VA window query must give the
    /// same rows as walking the scope, in the LIVE registry and in the
    /// planner's staged one alike.
    ///
    /// Red-first shape: this is the property `e123216a4` assumed and
    /// `da0270d43` reverted for lack of evidence. The staged registry replays
    /// existing rows out of sequence order — the overlapping rows sorted by
    /// sequence, then their physical co-holders in physical-index order — while
    /// `bucket_position_in` binary-searches the bucket BY sequence. On an
    /// unsorted bucket that search reports "not present", the planner splits
    /// fewer rows than the live unmap does, and
    /// `debug_assert_eq!(actual, planned_leases)` aborts the guest (it did, as
    /// "left: {8 entries} right: {6 entries}", under `sysvsem` and
    /// `rlimitnproc`).
    #[test]
    fn unmap_row_selection_agrees_between_the_scope_scan_and_the_window_query() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        const PAGE: u64 = 0x1000;
        let root_slot = Some((0x5000_0000, 0x4000));
        let owned = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000,
            size: 0x4000,
        };
        let global = AliasOwnershipScope::Global;
        let foreign = AliasOwnershipScope::MmRootSlot {
            base: 0x6000_0000,
            size: 0x4000,
        };
        // Weighted so most rows land in the process's own scope, with a
        // Global co-tenant and an invisible foreign owner in every shape.
        let scope_pool = [owned, owned, owned, global, foreign];

        let mut failures: Vec<(usize, String)> = Vec::new();
        let mut shapes = 0usize;
        let mut staged_shapes = 0usize;

        for seed in 0..768u64 {
            let mut rng = ShapeRng(seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ 0x00C0_FFEE);
            let mut registry = AliasRegistry::default();
            let row_count = 4 + rng.below(12) as usize;
            for _ in 0..row_count {
                let scope = scope_pool[rng.below(scope_pool.len() as u64) as usize];
                // Four VA size classes, so `va_window_rows` has to visit more
                // than one class bucket.
                let size = (1u64 << rng.below(4)) * PAGE;
                let start = 0x1000_0000 + rng.below(24) * PAGE;
                // A three-extent physical pool: rows at distant VAs co-hold one
                // extent, which is what puts co-holders in the staged registry.
                let physical_ipa = 0x8000_0000 + rng.below(3) * 0x1_0000;
                registry.push(make_test_alias(
                    start,
                    size as usize,
                    physical_ipa,
                    0x1_0000,
                    scope,
                ));
            }

            // Each step first CHECKS the property, then applies the unmap, so
            // later steps see rows already split into head+tail fragments that
            // share their parent's sequence.
            let steps = 1 + rng.below(4);
            for _ in 0..steps {
                let va = 0x1000_0000 + rng.below(24) * PAGE;
                let len = ((1 + rng.below(4)) * PAGE) as usize;
                shapes += 1;

                let overlapping = registry.overlapping_process_aliases(
                    va,
                    len,
                    root_slot,
                    ContainerRootToken::ROOT,
                );
                let staged = (!overlapping.is_empty()).then(|| {
                    staged_shapes += 1;
                    registry.staged_unmap_registry(
                        &overlapping,
                        root_slot,
                        ContainerRootToken::ROOT,
                    )
                });

                for (which, subject) in [
                    Some(("live", &registry)),
                    staged.as_ref().map(|s| ("staged", s)),
                ]
                .into_iter()
                .flatten()
                {
                    // The invariant the binary search rests on, named
                    // directly: an unsorted bucket does not make
                    // `bucket_position_in` slower, it makes it answer "absent"
                    // for a row that is present.
                    for (scope, bucket) in &subject.by_scope {
                        let rows = &bucket.rows;
                        if !rows.windows(2).all(|pair| pair[0].0 <= pair[1].0) {
                            failures.push((
                                rows.len(),
                                format!(
                                    "seed {seed}: {which} registry scope {scope:?} bucket is not \
                                     ordered by sequence: {:?}",
                                    rows.iter().map(|&(seq, _)| seq).collect::<Vec<_>>()
                                ),
                            ));
                        }
                    }
                    for (scope, scan, window) in
                        unmap_row_selections(subject, va, len, root_slot, ContainerRootToken::ROOT)
                    {
                        if scan != window {
                            failures.push((
                                subject.len(),
                                format!(
                                    "seed {seed}: {which} registry, unmap {va:#x}..{:#x}, \
                                     scope {scope:?}\n  scan   selected {} row(s): {scan:?}\n  \
                                     window selected {} row(s): {window:?}\nregistry:\n{}",
                                    va + len as u64,
                                    scan.len(),
                                    window.len(),
                                    describe_registry(subject),
                                ),
                            ));
                        }
                    }
                }

                // The end-to-end invariant the guest actually depends on.
                let (planned, _) = registry.plan_unregister_process_alias(
                    va,
                    len,
                    root_slot,
                    ContainerRootToken::ROOT,
                );
                let actual = unregister_alias_entries(
                    &mut registry,
                    va,
                    len,
                    root_slot,
                    ContainerRootToken::ROOT,
                );
                if planned != actual {
                    failures.push((
                        registry.len(),
                        format!(
                            "seed {seed}: planned leases {planned:?} != actual {actual:?} \
                             for unmap {va:#x}..{:#x}",
                            va + len as u64
                        ),
                    ));
                }
            }
        }

        assert!(
            shapes >= 700 && staged_shapes >= 100,
            "generator produced too few shapes: {shapes} unmaps, {staged_shapes} with a staged registry"
        );
        if !failures.is_empty() {
            failures.sort_by_key(|(rows, _)| *rows);
            let total = failures.len();
            panic!(
                "{total} diverging case(s) out of {shapes} unmaps; smallest ({} rows):\n{}",
                failures[0].0, failures[0].1
            );
        }
    }

    #[test]
    fn containing_physical_query_wider_than_any_recorded_row_does_not_panic() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        // The scope's widest recorded physical size bounds the range's lower
        // end; a query longer than every recorded row put the lower bound
        // ABOVE the query start and `BTreeMap::range` panicked on a reversed
        // range. Reported by the fork-table-copy worker while reading the
        // alias index; a guest-reachable abort.
        let root_slot = Some((0x5000_0000, 0x4000));
        let owned_scope = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000,
            size: 0x4000,
        };
        let mut registry = AliasRegistry::default();
        registry.push(make_test_alias(
            0x1000_0000,
            0x4000,
            0x8000_0000,
            0x4000,
            owned_scope,
        ));
        let candidates = registry.private_owned_containing_physical(
            root_slot,
            ContainerRootToken::ROOT,
            0x8000_0000,
            0x10000,
        );
        assert!(
            candidates.is_empty(),
            "a 16 KiB row cannot contain a 64 KiB extent"
        );
        let exact = registry.private_owned_containing_physical(
            root_slot,
            ContainerRootToken::ROOT,
            0x8000_0000,
            0x4000,
        );
        assert_eq!(exact.len(), 1);
    }

    #[test]
    fn planned_unmap_matches_actual_across_split_fragments() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        // `mincoreedge`: a three-page private mapping whose middle page is
        // unmapped first, then the head, then the tail. Both fragments of the
        // split keep the original row's sequence number, so a co-holder scan
        // that dedups on sequence alone drops the tail while planning the
        // head's unmap and plans a lease the live registry still holds.
        let root_slot = Some((0x5000_0000, 0x4000));
        let owned_scope = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000,
            size: 0x4000,
        };
        let mut registry = AliasRegistry::default();
        registry.push(make_test_alias(
            0x1000_0000,
            0x3000,
            0x8000_0000,
            0x8000,
            owned_scope,
        ));
        let released: std::collections::BTreeSet<(u64, u64)> =
            [(0x8000_0000u64, 0x8000u64)].into_iter().collect();
        let steps = [
            (
                "middle",
                0x1000_1000u64,
                0x1000usize,
                std::collections::BTreeSet::new(),
            ),
            (
                "head",
                0x1000_0000,
                0x1000,
                std::collections::BTreeSet::new(),
            ),
            ("tail", 0x1000_2000, 0x1000, released),
        ];
        for (desc, va, len, expected) in steps {
            let (planned, _) = registry.plan_unregister_process_alias(
                va,
                len,
                root_slot,
                ContainerRootToken::ROOT,
            );
            let actual = unregister_alias_entries(
                &mut registry,
                va,
                len,
                root_slot,
                ContainerRootToken::ROOT,
            );
            assert_eq!(planned, actual, "planned vs actual leases at {desc}");
            assert_eq!(actual, expected, "released leases at {desc}");
        }
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn unmap_single_row_in_5000_row_registry_is_fast() {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
            for population in [16_u64, 256, 5000] {
                let mut registry = AliasRegistry::default();
                let scope = AliasOwnershipScope::MmRootSlot {
                    base: 0x5000_0000,
                    size: 0x4000,
                };
                // Descending insertion puts the target near the tail of the scope
                // vector but at the front of the VA tree. A population scan cannot
                // accidentally find it early; unrelated rows share its scope.
                for i in (0..population).rev() {
                    let va = 0x1000_0000 + i * 0x8000;
                    let physical_ipa = 0x8000_0000 + i * 0x8000;
                    registry.push(make_test_alias(va, 0x1000, physical_ipa, 0x1000, scope));
                }
                assert_eq!(registry.len(), population as usize);

                let target_va = 0x1000_0000 + 0x8000;
                let before_scanned = alias_state_rows_scanned();
                let before_moved = alias_rows_moved();
                let (planned, registry_before) = registry.plan_unregister_process_alias(
                    target_va,
                    0x1000,
                    Some((0x5000_0000, 0x4000)),
                    ContainerRootToken::ROOT,
                );
                let after_plan = alias_state_rows_scanned();
                assert_eq!(
                    registry_before.len(),
                    1,
                    "planning must retain only the queried row"
                );
                let spans = retired_alias_disarm_spans(
                    &registry_before,
                    target_va,
                    0x1000,
                    Some((0x5000_0000, 0x4000)),
                    ContainerRootToken::ROOT,
                    &planned,
                );
                let after_disarm = alias_state_rows_scanned();
                let actual = unregister_alias_entries(
                    &mut registry,
                    target_va,
                    0x1000,
                    Some((0x5000_0000, 0x4000)),
                    ContainerRootToken::ROOT,
                );
                let after_remove = alias_state_rows_scanned();
                let height = u64::from(population.ilog2()) + 1;
                assert!(
                    after_plan - before_scanned <= height + 12,
                    "planning visited {} rows at population {population}",
                    after_plan - before_scanned
                );
                assert_eq!(
                    after_disarm - after_plan,
                    1,
                    "disarm must visit only the planned row"
                );
                assert!(
                    after_remove - after_disarm <= height + 8,
                    "removal visited {} rows at population {population}",
                    after_remove - after_disarm
                );
                let moved = alias_rows_moved().saturating_sub(before_moved);

                assert_eq!(planned, actual);
                assert_eq!(actual.len(), 1);
                assert_eq!(spans.len(), 1);
                assert_eq!(spans[0].va, target_va);
                assert_eq!(spans[0].len, 0x1000);
                assert_eq!(registry.len(), population as usize - 1);
                assert!(
                    moved <= population,
                    "unmapping 1 row at population {population} moved {moved} rows, expected <= {population}"
                );
            }
            drop(_global_state_guard);
            done_tx.send(()).unwrap();
        });
        match done_rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(()) => worker.join().unwrap(),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                worker.join().unwrap();
                panic!("unmap worker exited without completing fixture");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // A stuck worker may hold the global lock needed by other tests.
                // Fail the test process so it cannot strand the rest of the suite.
                eprintln!("FAIL: unmap fixture independent watchdog expired");
                std::process::exit(101);
            }
        }
    }

    #[test]
    #[ignore = "director perf benchmark: single-row unmap in 5000-row registry"]
    fn perf_unmap_single_row_in_5000_row_registry() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let mut registry = AliasRegistry::default();
        let scope = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000,
            size: 0x4000,
        };
        for i in 0..5000u64 {
            let va = 0x1000_0000 + i * 0x8000;
            let physical_ipa = 0x8000_0000 + i * 0x8000;
            registry.push(make_test_alias(va, 0x1000, physical_ipa, 0x1000, scope));
        }

        let target_va = 0x1000_0000 + 2500 * 0x8000;
        let start = std::time::Instant::now();
        let (planned, registry_before) = registry.plan_unregister_process_alias(
            target_va,
            0x1000,
            Some((0x5000_0000, 0x4000)),
            ContainerRootToken::ROOT,
        );
        let spans = retired_alias_disarm_spans(
            &registry_before,
            target_va,
            0x1000,
            Some((0x5000_0000, 0x4000)),
            ContainerRootToken::ROOT,
            &planned,
        );
        let actual = unregister_alias_entries(
            &mut registry,
            target_va,
            0x1000,
            Some((0x5000_0000, 0x4000)),
            ContainerRootToken::ROOT,
        );
        let elapsed = start.elapsed();

        assert_eq!(planned, actual);
        assert_eq!(actual.len(), 1);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].va, target_va);
        assert_eq!(spans[0].len, 0x1000);
        assert_eq!(registry.len(), 4999);
        assert!(
            elapsed < std::time::Duration::from_millis(10),
            "unmapping 1 row in 5000-row registry took {elapsed:?}, expected < 10ms"
        );
    }

    #[test]
    fn unregister_alias_entries_does_not_memmove_scope_bucket_per_row() {
        let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
        let mut registry = AliasRegistry::default();
        let scope = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000,
            size: 0x4000,
        };
        const TOTAL_ROWS: u64 = 20_000;
        for i in 0..TOTAL_ROWS {
            let va = 0x1000_0000 + i * 0x8000;
            let physical_ipa = 0x8000_0000 + i * 0x8000;
            registry.push(make_test_alias(va, 0x1000, physical_ipa, 0x1000, scope));
        }
        assert_eq!(registry.len(), TOTAL_ROWS as usize);

        // Unregister a window covering 8 rows near the FRONT (i = 0..8).
        const ROWS_TO_UNREGISTER: usize = 8;
        let target_va = 0x1000_0000;
        let target_len = ROWS_TO_UNREGISTER * 0x8000;

        let before_moved = alias_rows_moved();
        let retired = unregister_alias_entries(
            &mut registry,
            target_va,
            target_len,
            Some((0x5000_0000, 0x4000)),
            ContainerRootToken::ROOT,
        );
        let moved = alias_rows_moved().saturating_sub(before_moved);

        assert_eq!(retired.len(), ROWS_TO_UNREGISTER);
        assert_eq!(registry.len(), (TOTAL_ROWS as usize) - ROWS_TO_UNREGISTER);

        // One linear compaction pass is allowed, k * bucket is not:
        // rows moved <= 8 * log2(20,000) + 20,000
        let bound =
            (ROWS_TO_UNREGISTER as u64) * ((TOTAL_ROWS as f64).log2().ceil() as u64) + TOTAL_ROWS;
        assert!(
            moved <= bound,
            "unregistering {ROWS_TO_UNREGISTER} rows near front moved {moved} rows, expected <= {bound}"
        );
    }
}

#[test]
fn retained_fragment_query_wide_hit_avoids_unrelated_narrow_rows() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let template = AliasBacking {
        start: 0x1000_0000,
        ipa: 0x2000_0000,
        host_addr: 0x3000_0000,
        size: 0x1000,
        physical_ipa: 0x2000_0000,
        physical_host_addr: 0x3000_0000,
        physical_size: 0x1000,
        perms: 0,
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
        inventory_backing: InventoryBackingIdentity::Private(1),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    for scale in [1, 8, 32, 128] {
        let mut registry = AliasRegistry::default();
        for index in 0..scale {
            let mut unrelated = template;
            unrelated.size = 0x1000 << (index % 8);
            unrelated.ipa += 0x1000 * (index as u64 + 1);
            registry.push(unrelated);
        }
        let mut owner = template;
        owner.size = 0x100_0000;
        registry.push(owner);
        let mut examined = 0;
        assert!(registry.any_process_va_window_row(
            template.start,
            template.start + 1,
            None,
            ContainerRootToken::ROOT,
            |alias| {
                examined += 1;
                alias.ipa == owner.ipa && alias.size == owner.size
            }
        ));
        assert_eq!(
            examined, 1,
            "wide owner must not inspect {scale} unrelated narrow rows"
        );
        // Existence semantics remain identical to the original candidate query,
        // including rejected broad candidates, absent matches and empty windows.
        for offset in [0, 1, 0x1000, 0x10_0000, 0x100_0000] {
            for wanted in [template.ipa, template.ipa + 0x1000, u64::MAX] {
                let start = template.start + offset;
                let expected = registry
                    .va_window_rows(start, start + 1)
                    .any(|(_, a)| a.ipa == wanted && start < a.start.saturating_add(a.size as u64));
                assert_eq!(
                    registry.any_process_va_window_row(
                        start,
                        start + 1,
                        None,
                        ContainerRootToken::ROOT,
                        |a| a.ipa == wanted && start < a.start.saturating_add(a.size as u64)
                    ),
                    expected
                );
            }
        }
        assert!(
            !registry.any_process_va_window_row(0, 0, None, ContainerRootToken::ROOT, |_| true)
        );
    }
}

#[test]
#[allow(clippy::expect_used)]
fn stage2_map_replay_miss_and_cache_hit_never_scan_unrelated_registry() {
    use crate::trap::stage2_backend::{
        ReplayAliasLookup, ScopedStage2MapTestStub, stage2_map_replay,
    };
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();

    let target_len = 0x4000_usize;
    let target_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        target_len,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("target alias backing");
    let target_ipa = 0x7e00_1000_u64;
    let target_va = 0x6000_1000_u64;
    let scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken(10_000_000));
    let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
    let target_alias = AliasBacking {
        start: target_va,
        ipa: target_ipa,
        host_addr: target_backing.as_ptr() as usize,
        size: target_len,
        physical_ipa: target_ipa,
        physical_host_addr: target_backing.as_ptr() as usize,
        physical_size: target_len,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: scope,
        inventory_backing: InventoryBackingIdentity::Private(7001),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };

    let cold_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        target_len,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .expect("allocate cold alias backing");
    let cold_ipa = 0x7100_0000_u64;
    let cold_scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken(10_000_001));
    let cold_alias = AliasBacking {
        start: 0x5100_0000,
        ipa: cold_ipa,
        host_addr: cold_backing.as_ptr() as usize,
        size: target_len,
        physical_ipa: cold_ipa,
        physical_host_addr: cold_backing.as_ptr() as usize,
        physical_size: target_len,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: cold_scope,
        inventory_backing: InventoryBackingIdentity::Private(7002),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };

    for population in [16_u64, 256, 2000] {
        let _stub = ScopedStage2MapTestStub::enable();
        let custody = std::sync::Arc::new(CarrierVmCustody::new());
        let g1 = custody.begin_create().expect("begin G1");
        custody.commit_create(g1).expect("commit G1");

        mutate_external_alias_state(|registry| {
            *registry = AliasRegistry::default();
            for i in 1..=population {
                let va = 0x1000_0000 + i * 0x8000;
                let ipa = 0x8000_0000 + i * 0x8000;
                // Distinct scope per unrelated alias so any by_scope walk scales linearly.
                registry.push(AliasBacking {
                    start: va,
                    ipa,
                    host_addr: (0x2000_0000 + i * 0x8000) as usize,
                    size: 0x4000,
                    physical_ipa: ipa,
                    physical_host_addr: (0x2000_0000 + i * 0x8000) as usize,
                    physical_size: 0x4000,
                    perms,
                    guest_writable: true,
                    sharing: GuestMappingSharing::GlobalShared,
                    ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(
                        1000 + i,
                    )),
                    inventory_backing: InventoryBackingIdentity::Private(8000 + i),
                    shared_key_base: None,
                    shared_key_offset: 0,
                    owner_generation: 0,
                });
            }
            registry.push(target_alias);
            registry.push(cold_alias);
        });
        // Configure exhausted replay epoch & cold cache membership directly on the
        // registry AFTER `mutate_external_alias_state` finishes so delta-epoch
        // tracking bumps cleanly first and doesn't overflow `u64::MAX` in setup.
        {
            let mut registry = alias_registry().lock();
            registry.remove_replay_in_scope(cold_scope, &replay_mapping_key(cold_alias));
            registry
                .by_scope
                .entry(cold_scope)
                .or_default()
                .versions
                .replay_epochs
                .insert(cold_ipa, u64::MAX);
            assert_eq!(registry.recomputed_replay_counts(), registry.replay_counts);
        }

        let before_cold_rows = alias_state_rows_scanned();
        let before_cold_scopes = alias_replay_scopes_probed();
        // 1. Cold registered lookup with empty replay cache (contains_replay == false).
        let cold_exhausted = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::Ipa { gpa: cold_ipa },
                &mut |_| true,
            )
        };
        assert_eq!(
            cold_exhausted,
            Ok(Some((
                cold_alias,
                carrick_aarch64::stage2::Stage2Status::from_raw(0xfae9_4003)
            )))
        );
        assert_eq!(alias_state_rows_scanned() - before_cold_rows, 1);
        assert_eq!(alias_replay_scopes_probed() - before_cold_scopes, 0);

        // 2. Warm target replay entry into replay cache (placed in LAST scope).
        let mapped = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::Ipa { gpa: target_ipa },
                &mut |_| true,
            )
        };
        assert_eq!(
            mapped,
            Ok(Some((
                target_alias,
                carrick_aarch64::stage2::Stage2Status::SUCCESS
            )))
        );

        // 3. Miss, limiter refusal, and warm cache hit in last scope must NOT clone rows OR probe scopes.
        let before_miss_rows = alias_state_rows_scanned();
        let before_scopes = alias_replay_scopes_probed();
        let miss = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::Ipa { gpa: 0x7f00_0000 },
                &mut |_| true,
            )
        };
        assert_eq!(miss, Ok(None));
        assert_eq!(alias_state_rows_scanned() - before_miss_rows, 0);

        let before_hit_rows = alias_state_rows_scanned();
        let limited = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::Ipa { gpa: target_ipa },
                &mut |_| false,
            )
        };
        assert_eq!(limited, Ok(None));

        let hit = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::Ipa { gpa: target_ipa },
                &mut |_| true,
            )
        };
        assert_eq!(
            hit,
            Ok(Some((
                target_alias,
                carrick_aarch64::stage2::Stage2Status::SUCCESS
            )))
        );
        let scanned = alias_state_rows_scanned() - before_hit_rows;
        let scopes_probed = alias_replay_scopes_probed() - before_scopes;
        assert_eq!(
            scanned, 2,
            "stage2_map_replay limit+hit scanned {scanned} rows at population {population}"
        );
        assert_eq!(
            scopes_probed, 0,
            "stage2_map_replay probed {scopes_probed} unrelated scopes at population {population}"
        );
    }
    drop(cold_backing);
    mutate_external_alias_state(|registry| *registry = AliasRegistry::default());
    drop(target_backing);
}

#[test]
#[allow(clippy::expect_used)]
fn stage2_map_replay_resolves_live_row_past_dead_prefix_and_bounds_per_lock_slices() {
    use crate::trap::stage2_backend::{
        ReplayAliasLookup, ScopedStage2MapTestStub, stage2_map_replay,
    };
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let _stub = ScopedStage2MapTestStub::enable();
    let custody = std::sync::Arc::new(CarrierVmCustody::new());
    let g1 = custody.begin_create().expect("begin G1");
    custody.commit_create(g1).expect("commit G1");

    let len = 0x4000_usize;
    let live_backing = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        len,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate live backing");
    let live_host = live_backing.as_ptr() as usize;
    let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);

    // 1. Codex #13 P0: insert an early row, add 70 dead rows at the SAME IPA,
    //    then `upsert_by_key` the early row (keeping its low sequence number).
    let upsert_ipa = 0x7c00_0000_u64;
    let upsert_scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken(2100));
    let upsert_initial = AliasBacking {
        start: 0x3100_0000,
        ipa: upsert_ipa,
        host_addr: 0,
        size: len,
        physical_ipa: upsert_ipa,
        physical_host_addr: 0,
        physical_size: len,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: upsert_scope,
        inventory_backing: InventoryBackingIdentity::Private(9100),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let upsert_live = AliasBacking {
        host_addr: live_host,
        physical_host_addr: live_host,
        ..upsert_initial
    };

    // 2. Codex #13 P1-1: 200 dead overlapping rows across 200 DISTINCT start keys
    //    (worst-to-best sequence order) plus one live row at the end.
    let distinct_ipa = 0x7c20_0000_u64;
    let distinct_live = AliasBacking {
        start: 0x3300_0000,
        ipa: distinct_ipa,
        host_addr: live_host,
        size: len,
        physical_ipa: distinct_ipa,
        physical_host_addr: live_host,
        physical_size: len,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::Global,
        inventory_backing: InventoryBackingIdentity::Private(9102),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };

    // 3. Codex #13 P1-2: `VaProcess` with `mm_root_slot: Some(...)` sees BOTH
    //    `MmRootSlot` and `Global`. Populate BOTH visible scopes across 4 KiB
    //    and 16 KiB size classes with competing rows.
    let va_probe_a = 0x4400_0000_u64;
    let va_probe_b = 0x4600_0000_u64;
    let proc_slot = (0xa000_0000_u64, 0x20_0000_u64);
    let proc_container = ContainerRootToken(777);
    let mm_scope = AliasOwnershipScope::MmRootSlot {
        base: proc_slot.0,
        size: proc_slot.1,
    };
    let live_mm_alias = AliasBacking {
        start: va_probe_a,
        ipa: 0x7c10_0000,
        host_addr: live_host,
        size: len,
        physical_ipa: 0x7c10_0000,
        physical_host_addr: live_host,
        physical_size: len,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::ForkSharedAnonymous,
        ownership_scope: mm_scope,
        inventory_backing: InventoryBackingIdentity::Private(9101),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let older_global_fallback = AliasBacking {
        ipa: 0x7c11_0000,
        physical_ipa: 0x7c11_0000,
        size: 0x1000,
        physical_size: 0x1000,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::Global,
        inventory_backing: InventoryBackingIdentity::Private(9104),
        ..live_mm_alias
    };
    let live_global_alias = AliasBacking {
        start: va_probe_b,
        ipa: 0x7c14_0000,
        host_addr: live_host,
        size: len,
        physical_ipa: 0x7c14_0000,
        physical_host_addr: live_host,
        physical_size: len,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::Global,
        inventory_backing: InventoryBackingIdentity::Private(9103),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let older_mm_fallback = AliasBacking {
        ipa: 0x7c15_0000,
        physical_ipa: 0x7c15_0000,
        size: 0x1000,
        physical_size: 0x1000,
        sharing: GuestMappingSharing::ForkSharedAnonymous,
        ownership_scope: mm_scope,
        inventory_backing: InventoryBackingIdentity::Private(9105),
        ..live_global_alias
    };

    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        registry.push(upsert_initial);
        for i in 1..=70_u64 {
            registry.push(AliasBacking {
                start: upsert_initial.start,
                ipa: upsert_ipa,
                host_addr: 0,
                size: len,
                physical_ipa: upsert_ipa,
                physical_host_addr: 0,
                physical_size: len,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(2200 + i)),
                inventory_backing: InventoryBackingIdentity::Private(9200 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        assert_eq!(registry.upsert_by_key(upsert_live), Some(upsert_initial));
        assert!(!registry.contains_exact_physical_row(&upsert_initial));
        assert!(registry.contains_exact_physical_row(&upsert_live));
        let ipa_bucket = registry.ipa_classes.rows_at(upsert_ipa, len as u64);
        assert_eq!(ipa_bucket.len(), 71);
        assert!(
            ipa_bucket.windows(2).all(|w| w[0].0 < w[1].0),
            "AliasClassIndex IPA bucket must stay strictly seq-sorted after upsert_by_key"
        );
        assert_eq!(ipa_bucket[0].1, upsert_live);
        let va_bucket = registry
            .va_classes
            .rows_at(upsert_initial.start, len as u64);
        assert_eq!(va_bucket.len(), 71);
        assert!(
            va_bucket.windows(2).all(|w| w[0].0 < w[1].0),
            "AliasClassIndex VA bucket must stay strictly seq-sorted after upsert_by_key"
        );
        assert_eq!(va_bucket[0].1, upsert_live);

        // 200 distinct overlapping starts (`ipa = distinct_ipa - k * 0x1000`, wide enough
        // to cover `distinct_ipa`) plus live row `distinct_live`.
        registry.push(distinct_live);
        for i in 1..=200_u64 {
            let start_ipa = distinct_ipa - i * 0x1000;
            let row_len = ((i as usize) + 1) * 0x1000;
            registry.push(AliasBacking {
                start: 0x3400_0000 + i * 0x4000,
                ipa: start_ipa,
                host_addr: 0,
                size: row_len,
                physical_ipa: start_ipa,
                physical_host_addr: 0,
                physical_size: row_len,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(3000 + i)),
                inventory_backing: InventoryBackingIdentity::Private(9600 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }

        // VaProcess Subcase A: oldest live 4 KiB in Global, newer live 16 KiB in MmRootSlot,
        // plus 70 newest dead 4 KiB rows in Global.
        registry.push(older_global_fallback);
        registry.push(live_mm_alias);
        for i in 1..=70_u64 {
            registry.push(AliasBacking {
                start: va_probe_a,
                ipa: 0x7c18_0000 + i * 0x1000,
                host_addr: 0,
                size: 0x1000,
                physical_ipa: 0x7c18_0000 + i * 0x1000,
                physical_host_addr: 0,
                physical_size: 0x1000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::Global,
                inventory_backing: InventoryBackingIdentity::Private(9400 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }

        // VaProcess Subcase B: oldest live 4 KiB in MmRootSlot, newer live 16 KiB in Global,
        // plus 70 newest dead 4 KiB rows in MmRootSlot.
        registry.push(older_mm_fallback);
        registry.push(live_global_alias);
        for i in 1..=70_u64 {
            registry.push(AliasBacking {
                start: va_probe_b,
                ipa: 0x7c38_0000 + i * 0x1000,
                host_addr: 0,
                size: 0x1000,
                physical_ipa: 0x7c38_0000 + i * 0x1000,
                physical_host_addr: 0,
                physical_size: 0x1000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::ForkSharedAnonymous,
                ownership_scope: mm_scope,
                inventory_backing: InventoryBackingIdentity::Private(9500 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        // Clear pre-populated replay cache so every `stage2_map_replay` below
        // exercises Phase 2 exact-row checks and real `stage2_map` installation.
        registry.clear_replay_mappings_in();
    });

    // Verify P0 + full map path: `upsert_by_key` older-seq live row maps cleanly.
    assert!(!ScopedStage2MapTestStub::is_mapped(upsert_ipa, len));
    let res_upserted = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::Ipa { gpa: upsert_ipa },
            &mut |_| true,
        )
    };
    assert_eq!(
        res_upserted,
        Ok(Some((
            upsert_live,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(upsert_ipa, len));

    // Verify production lock release and per-slice row budget between slices inside
    // `stage2_map_replay` itself across 200 distinct overlapping starts + 1 live row.
    let slice_fires = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let last_scanned =
        std::sync::Arc::new(std::sync::atomic::AtomicU64::new(alias_state_rows_scanned()));
    let slice_fires_hook = std::sync::Arc::clone(&slice_fires);
    let last_scanned_hook = std::sync::Arc::clone(&last_scanned);
    custody
        .stage2
        .set_hook(Some(std::sync::Arc::new(move |point| {
            if let carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name) = point
                && name == crate::trap::carrier_custody::REPLAY_SLICE_BETWEEN_LOCKS
            {
                assert!(
                    alias_registry().try_lock().is_some(),
                    "production stage2_map_replay must release alias_registry lock between slices"
                );
                let now = alias_state_rows_scanned();
                let prev = last_scanned_hook.swap(now, std::sync::atomic::Ordering::SeqCst);
                let delta = now.saturating_sub(prev);
                assert!(
                    delta > 0 && delta <= crate::trap::LAZY_REPLAY_ROW_BUDGET as u64,
                    "production slice inspected {delta} rows (budget {})",
                    crate::trap::LAZY_REPLAY_ROW_BUDGET
                );
                slice_fires_hook.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        })));
    assert!(!ScopedStage2MapTestStub::is_mapped(distinct_ipa, len));
    let before_distinct = alias_state_rows_scanned();
    let res_distinct = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::Ipa { gpa: distinct_ipa },
            &mut |_| true,
        )
    };
    custody.stage2.set_hook(None);
    let tail_scanned =
        alias_state_rows_scanned() - last_scanned.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(slice_fires.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert!(
        tail_scanned > 0 && tail_scanned <= crate::trap::LAZY_REPLAY_ROW_BUDGET as u64,
        "final production slice tail inspected {tail_scanned} rows"
    );
    assert_eq!(
        alias_state_rows_scanned() - before_distinct,
        201,
        "200 distinct overlapping starts + 1 live row must be visited once without revisiting"
    );
    assert_eq!(
        res_distinct,
        Ok(Some((
            distinct_live,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(distinct_ipa, len));

    // Verify cross-scope + cross-class newest-first merging on real backend map.
    assert!(!ScopedStage2MapTestStub::is_mapped(0x7c10_0000, len));
    assert_eq!(
        unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::VaProcess {
                    va: va_probe_a,
                    mm_root_slot: Some(proc_slot),
                    container_root: proc_container,
                },
                &mut |_| true,
            )
        },
        Ok(Some((
            live_mm_alias,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(0x7c10_0000, len));

    assert!(!ScopedStage2MapTestStub::is_mapped(0x7c14_0000, len));
    assert_eq!(
        unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::VaProcess {
                    va: va_probe_b,
                    mm_root_slot: Some(proc_slot),
                    container_root: proc_container,
                },
                &mut |_| true,
            )
        },
        Ok(Some((
            live_global_alias,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(0x7c14_0000, len));

    // Verify duplicate insertion/removal and `retire_scope` keep `exact_row_counts` exact.
    mutate_external_alias_state(|registry| {
        let dup_scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken(8888));
        let dup_row = AliasBacking {
            ownership_scope: dup_scope,
            inventory_backing: InventoryBackingIdentity::Private(9988),
            ..upsert_live
        };
        registry.push(dup_row);
        registry.push(dup_row);
        assert!(registry.contains_exact_physical_row(&dup_row));
        let mut drop_once = false;
        let removed = registry.retain_in_scope(dup_scope, |_| {
            if !drop_once {
                drop_once = true;
                false
            } else {
                true
            }
        });
        assert_eq!(removed.len(), 1);
        assert!(
            registry.contains_exact_physical_row(&dup_row),
            "second duplicate row must preserve membership after removing first"
        );
        let _ = registry.retire_scope(dup_scope);
        assert!(!registry.contains_exact_physical_row(&dup_row));
        *registry = AliasRegistry::default();
    });
    drop(live_backing);
}

#[test]
#[allow(clippy::expect_used)]
fn stage2_map_replay_restarts_coherently_on_concurrent_class_upsert() {
    use crate::trap::stage2_backend::{
        ReplayAliasLookup, ScopedStage2MapTestStub, stage2_map_replay,
    };
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let _stub = ScopedStage2MapTestStub::enable();
    let custody = std::sync::Arc::new(CarrierVmCustody::new());
    let g1 = custody.begin_create().expect("begin G1");
    custody.commit_create(g1).expect("commit G1");

    let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
    let live_4k = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x1000,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate 4 KiB backing");
    let live_16k = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate 16 KiB backing");
    let host_4k = live_4k.as_ptr() as usize;
    let host_16k = live_16k.as_ptr() as usize;
    let upsert_scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken(4100));

    // Subcase 1 (Codex #14 P0): Slice 1 collects `old_4k`; before Slice 2, an in-place
    // `upsert_by_key` grows the same semantic row into `new_16k` (preserving `seq`) while
    // `live_4k` remains live. Replay must restart coherently and resolve `new_16k`.
    let ipa_grow = 0x7c40_0000_u64;
    let old_4k = AliasBacking {
        start: 0x3500_0000,
        ipa: ipa_grow,
        host_addr: host_4k,
        size: 0x1000,
        physical_ipa: ipa_grow,
        physical_host_addr: host_4k,
        physical_size: 0x1000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: upsert_scope,
        inventory_backing: InventoryBackingIdentity::Private(9700),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let new_16k = AliasBacking {
        host_addr: host_16k,
        size: 0x4000,
        physical_host_addr: host_16k,
        physical_size: 0x4000,
        inventory_backing: InventoryBackingIdentity::Private(9701),
        ..old_4k
    };
    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        registry.push(old_4k);
        for i in 1..=70_u64 {
            registry.push(AliasBacking {
                start: 0x3501_0000 + i * 0x1000,
                ipa: ipa_grow,
                host_addr: 0,
                size: 0x1000,
                physical_ipa: ipa_grow,
                physical_host_addr: 0,
                physical_size: 0x1000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(4200 + i)),
                inventory_backing: InventoryBackingIdentity::Private(9710 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        registry.clear_replay_mappings_in();
    });
    let did_grow = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let did_grow_hook = std::sync::Arc::clone(&did_grow);
    custody
        .stage2
        .set_hook(Some(std::sync::Arc::new(move |point| {
            if let carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name) = point
                && name == crate::trap::carrier_custody::REPLAY_SLICE_BETWEEN_LOCKS
                && !did_grow_hook.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                mutate_external_alias_state(|registry| {
                    assert_eq!(registry.upsert_by_key(new_16k), Some(old_4k));
                    registry.clear_replay_mappings_in();
                });
            }
        })));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_grow, 0x4000));
    let res_grow = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::Ipa { gpa: ipa_grow },
            &mut |_| true,
        )
    };
    custody.stage2.set_hook(None);
    assert!(did_grow.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        res_grow,
        Ok(Some((
            new_16k,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(ipa_grow, 0x4000));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_grow, 0x1000));

    // Subcase 2: `old_16k` (earliest seq) starts in the 16 KiB class behind 70 dead 4 KiB
    // rows; between Slice 1 (past row 64 of the 4 KiB bucket) and Slice 2, `upsert_by_key`
    // shrinks it into `new_4k` at index 0 of the already-traversed 4 KiB bucket.
    let ipa_shrink = 0x7c50_0000_u64;
    let old_16k = AliasBacking {
        start: 0x3600_0000,
        ipa: ipa_shrink,
        host_addr: host_16k,
        size: 0x4000,
        physical_ipa: ipa_shrink,
        physical_host_addr: host_16k,
        physical_size: 0x4000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: upsert_scope,
        inventory_backing: InventoryBackingIdentity::Private(9800),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let new_4k = AliasBacking {
        host_addr: host_4k,
        size: 0x1000,
        physical_host_addr: host_4k,
        physical_size: 0x1000,
        inventory_backing: InventoryBackingIdentity::Private(9801),
        ..old_16k
    };
    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        registry.push(old_16k);
        for i in 1..=70_u64 {
            registry.push(AliasBacking {
                start: 0x3601_0000 + i * 0x1000,
                ipa: ipa_shrink,
                host_addr: 0,
                size: 0x1000,
                physical_ipa: ipa_shrink,
                physical_host_addr: 0,
                physical_size: 0x1000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(4300 + i)),
                inventory_backing: InventoryBackingIdentity::Private(9810 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        registry.clear_replay_mappings_in();
    });
    let did_shrink = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let did_shrink_hook = std::sync::Arc::clone(&did_shrink);
    custody
        .stage2
        .set_hook(Some(std::sync::Arc::new(move |point| {
            if let carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name) = point
                && name == crate::trap::carrier_custody::REPLAY_SLICE_BETWEEN_LOCKS
                && !did_shrink_hook.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                mutate_external_alias_state(|registry| {
                    assert_eq!(registry.upsert_by_key(new_4k), Some(old_16k));
                    registry.clear_replay_mappings_in();
                });
            }
        })));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_shrink, 0x1000));
    let res_shrink = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::Ipa { gpa: ipa_shrink },
            &mut |_| true,
        )
    };
    custody.stage2.set_hook(None);
    assert!(did_shrink.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        res_shrink,
        Ok(Some((
            new_4k,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(ipa_shrink, 0x1000));

    // Subcase 3 (Codex #15 P0-2): Single-slice lookup (1 row, no slice yields)
    // followed by `upsert_by_key` during `REPLAY_REMAP_BEFORE_GUARD` keeping
    // `live_4k` live. Phase 2 retry must re-collect and map `new_16k_single`
    // while charging `allow_ipa` only once for `ipa_single`.
    let ipa_single = 0x7c70_0000_u64;
    let old_4k_single = AliasBacking {
        start: 0x3700_0000,
        ipa: ipa_single,
        host_addr: host_4k,
        size: 0x1000,
        physical_ipa: ipa_single,
        physical_host_addr: host_4k,
        physical_size: 0x1000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: upsert_scope,
        inventory_backing: InventoryBackingIdentity::Private(9900),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let new_16k_single = AliasBacking {
        host_addr: host_16k,
        size: 0x4000,
        physical_host_addr: host_16k,
        physical_size: 0x4000,
        inventory_backing: InventoryBackingIdentity::Private(9901),
        ..old_4k_single
    };
    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        registry.push(old_4k_single);
        registry.clear_replay_mappings_in();
    });
    let did_single_guard_upsert = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let did_single_hook = std::sync::Arc::clone(&did_single_guard_upsert);
    custody
        .stage2
        .set_hook(Some(std::sync::Arc::new(move |point| {
            if let carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name) = point
                && name == crate::trap::carrier_custody::REPLAY_REMAP_BEFORE_GUARD
                && !did_single_hook.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                mutate_external_alias_state(|registry| {
                    assert_eq!(registry.upsert_by_key(new_16k_single), Some(old_4k_single));
                    registry.clear_replay_mappings_in();
                });
            }
        })));
    let mut allow_calls = 0_usize;
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_single, 0x4000));
    let res_single = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::Ipa { gpa: ipa_single },
            &mut |_| {
                allow_calls += 1;
                true
            },
        )
    };
    custody.stage2.set_hook(None);
    assert!(did_single_guard_upsert.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        allow_calls, 1,
        "Phase-2 retry must not re-charge allow_ipa for the same IPA"
    );
    assert_eq!(
        res_single,
        Ok(Some((
            new_16k_single,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(ipa_single, 0x4000));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_single, 0x1000));

    // Subcase 4 (Codex #17 P0-1 & P0-2): Disjoint 48 KiB edits ending right at
    // the probe (inside the 64 KiB class AND inside a paused 64 KiB bucket),
    // 600 disjoint edits in ONE SINGLE inter-slice pause (> 512), and identical
    // sole-row `Global` upserts run on a dedicated helper thread so the replay
    // thread's `alias_state_rows_scanned()` reflects ONLY production replay scans.
    let live_128k = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x2_0000,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate 128 KiB backing");
    let host_128k = live_128k.as_ptr() as usize;
    let ipa_unrel = 0x7c80_0000_u64;
    let va_unrel = 0x4800_0000_u64;
    let unrel_mm_scope = AliasOwnershipScope::MmRootSlot {
        base: 0xb000_0000,
        size: 0x20_0000,
    };
    let unrel_container = ContainerRootToken(7788);
    let bucket64_start_ipa = ipa_unrel - 0xC000;
    let early_disjoint_48k_ipa = AliasBacking {
        start: 0x37f0_0000,
        ipa: bucket64_start_ipa,
        host_addr: 0,
        size: 0xC000,
        physical_ipa: bucket64_start_ipa,
        physical_host_addr: 0,
        physical_size: 0xC000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(4999)),
        inventory_backing: InventoryBackingIdentity::Private(9999),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let live_ipa_unrel = AliasBacking {
        start: 0x3800_0000,
        ipa: ipa_unrel,
        host_addr: host_128k,
        size: 0x2_0000,
        physical_ipa: ipa_unrel,
        physical_host_addr: host_128k,
        physical_size: 0x2_0000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(4998)),
        inventory_backing: InventoryBackingIdentity::Private(10_000),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let live_va_unrel = AliasBacking {
        start: va_unrel,
        ipa: 0x7c90_0000,
        host_addr: host_16k,
        size: 0x4000,
        physical_ipa: 0x7c90_0000,
        physical_host_addr: host_16k,
        physical_size: 0x4000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::ForkSharedAnonymous,
        ownership_scope: unrel_mm_scope,
        inventory_backing: InventoryBackingIdentity::Private(10_001),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let sole_global_row = AliasBacking {
        start: 0x9800_0000,
        ipa: 0x8800_0000,
        host_addr: 0,
        size: 0x4000,
        physical_ipa: 0x8800_0000,
        physical_host_addr: 0,
        physical_size: 0x4000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::Global,
        inventory_backing: InventoryBackingIdentity::Private(10_002),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        // Put early disjoint 48 KiB row at index 0 of class-16 bucket `(16, ipa_unrel - 0xC000)`,
        // followed by 70 dead 64 KiB rows at the SAME bucket start so slice 11 pauses at index 64.
        registry.push(early_disjoint_48k_ipa);
        for i in 1..=640_u64 {
            registry.push(AliasBacking {
                start: 0x3810_0000 + i * 0x4000,
                ipa: ipa_unrel,
                host_addr: 0,
                size: 0x4000,
                physical_ipa: ipa_unrel,
                physical_host_addr: 0,
                physical_size: 0x4000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(5000 + i)),
                inventory_backing: InventoryBackingIdentity::Private(10_100 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
            registry.push(AliasBacking {
                start: va_unrel,
                ipa: 0x7d00_0000 + i * 0x4000,
                host_addr: 0,
                size: 0x4000,
                physical_ipa: 0x7d00_0000 + i * 0x4000,
                physical_host_addr: 0,
                physical_size: 0x4000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::ForkSharedAnonymous,
                ownership_scope: unrel_mm_scope,
                inventory_backing: InventoryBackingIdentity::Private(11_100 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        for i in 1..=70_u64 {
            registry.push(AliasBacking {
                start: 0x37f1_0000 + i * 0x1_0000,
                ipa: bucket64_start_ipa,
                host_addr: 0,
                size: 0x1_0000,
                physical_ipa: bucket64_start_ipa,
                physical_host_addr: 0,
                physical_size: 0x1_0000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(6000 + i)),
                inventory_backing: InventoryBackingIdentity::Private(11_900 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        registry.push(live_ipa_unrel);
        registry.push(live_va_unrel);
        registry.push(sole_global_row);
        registry.clear_replay_mappings_in();
    });

    let (pause_tx, pause_rx) = std::sync::mpsc::channel::<Option<u64>>();
    let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();
    let mutator = std::thread::spawn(move || {
        while let Ok(Some(k)) = pause_rx.recv() {
            mutate_external_alias_state(|registry| {
                // Sole-row `Global` identical upsert empties + recreates `va_classes_by_scope[Global]`.
                assert_eq!(registry.scope_rows(AliasOwnershipScope::Global).len(), 1);
                assert_eq!(
                    registry.upsert_by_key(sole_global_row),
                    Some(sole_global_row)
                );
                // On pause 1 alone, push 600 disjoint rows (> 512 single-pause log cap!).
                let batch = if k == 1 { 600_u64 } else { 1_u64 };
                for j in 0..batch {
                    let id = k * 1000 + j;
                    registry.push(AliasBacking {
                        start: 0x9900_0000 + id * 0x1_0000,
                        ipa: 0x8900_0000 + id * 0x1_0000,
                        host_addr: 0,
                        size: 0x4000,
                        physical_ipa: 0x8900_0000 + id * 0x1_0000,
                        physical_host_addr: 0,
                        physical_size: 0x4000,
                        perms,
                        guest_writable: true,
                        sharing: GuestMappingSharing::ForkSharedAnonymous,
                        ownership_scope: AliasOwnershipScope::MmRootSlot {
                            base: 0xc000_0000 + id * 0x20_0000,
                            size: 0x20_0000,
                        },
                        inventory_backing: InventoryBackingIdentity::Private(12_000 + id),
                        shared_key_base: None,
                        shared_key_offset: 0,
                        owner_generation: 0,
                    });
                }
                // On every pause, insert a disjoint 48 KiB row ending at `ipa_unrel` and `va_unrel`
                // (inside the 64 KiB search window), and on pause 11 (paused inside bucket64)
                // remove `early_disjoint_48k_ipa` at index 0 < paused_next_pos = 64.
                registry.push(AliasBacking {
                    start: 0x3b00_0000 + k * 0x1_0000,
                    ipa: bucket64_start_ipa,
                    host_addr: 0,
                    size: 0xC000,
                    physical_ipa: bucket64_start_ipa,
                    physical_host_addr: 0,
                    physical_size: 0xC000,
                    perms,
                    guest_writable: true,
                    sharing: GuestMappingSharing::GlobalShared,
                    ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(
                        7000 + k,
                    )),
                    inventory_backing: InventoryBackingIdentity::Private(13_000 + k),
                    shared_key_base: None,
                    shared_key_offset: 0,
                    owner_generation: 0,
                });
                registry.push(AliasBacking {
                    start: va_unrel - 0xC000,
                    ipa: 0x8b00_0000 + k * 0x1_0000,
                    host_addr: 0,
                    size: 0xC000,
                    physical_ipa: 0x8b00_0000 + k * 0x1_0000,
                    physical_host_addr: 0,
                    physical_size: 0xC000,
                    perms,
                    guest_writable: true,
                    sharing: GuestMappingSharing::ForkSharedAnonymous,
                    ownership_scope: unrel_mm_scope,
                    inventory_backing: InventoryBackingIdentity::Private(13_500 + k),
                    shared_key_base: None,
                    shared_key_offset: 0,
                    owner_generation: 0,
                });
                if k == 11 {
                    let retired = registry
                        .retire_scope(AliasOwnershipScope::ContainerRoot(ContainerRootToken(4999)));
                    assert_eq!(retired.len(), 1);
                }
            });
            let _ = ack_tx.send(());
        }
    });

    let unrel_seq = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let unrel_seq_hook = std::sync::Arc::clone(&unrel_seq);
    let pause_tx_hook = std::sync::Arc::new(parking_lot::Mutex::new(pause_tx));
    let pause_tx_hook_clone = std::sync::Arc::clone(&pause_tx_hook);
    let ack_rx_hook = std::sync::Arc::new(parking_lot::Mutex::new(ack_rx));
    custody
        .stage2
        .set_hook(Some(std::sync::Arc::new(move |point| {
            if let carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name) = point
                && name == crate::trap::carrier_custody::REPLAY_SLICE_BETWEEN_LOCKS
            {
                let k = unrel_seq_hook.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                pause_tx_hook_clone
                    .lock()
                    .send(Some(k))
                    .expect("send pause");
                ack_rx_hook.lock().recv().expect("recv ack");
            }
        })));

    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_unrel, 0x2_0000));
    let before_unrel_ipa = alias_state_rows_scanned();
    let res_unrel_ipa = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::Ipa { gpa: ipa_unrel },
            &mut |_| true,
        )
    };
    let ipa_pauses = unrel_seq.swap(0, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(ipa_pauses, 11, "expected 11 inter-slice pauses (> 8 limit)");
    // 640 (class 14) + 64 (slice 11 before pause) + 7 (remaining class-16 64K) + 10 (k=1..10 48K pushed into class 16 after slice 10) + 1 (k=11 48K pushed in slice 12) + 1 (live class 17) = 723
    assert_eq!(
        alias_state_rows_scanned() - before_unrel_ipa,
        723,
        "disjoint 48K edits, index-0 paused-bucket removal, and 600 single-pause writes must cause ZERO restarts"
    );
    assert_eq!(
        res_unrel_ipa,
        Ok(Some((
            live_ipa_unrel,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(ipa_unrel, 0x2_0000));

    assert!(!ScopedStage2MapTestStub::is_mapped(0x7c90_0000, 0x4000));
    let before_unrel_va = alias_state_rows_scanned();
    let res_unrel_va = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::VaProcess {
                va: va_unrel,
                mm_root_slot: Some((0xb000_0000, 0x20_0000)),
                container_root: unrel_container,
            },
            &mut |_| true,
        )
    };
    custody.stage2.set_hook(None);
    let _ = pause_tx_hook.lock().send(None);
    mutator.join().expect("mutator joined");
    let va_pauses = unrel_seq.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        va_pauses, 10,
        "expected 10 inter-slice pauses for VaProcess"
    );
    // 640 (class 14 dead) + 1 (live_va_unrel) + 11 (48K rows from ipa_unrel pauses) + 10 (48K rows from va_unrel pauses) = 662
    assert_eq!(
        alias_state_rows_scanned() - before_unrel_va,
        662,
        "disjoint 48K VaProcess edits, sole-row Global upserts, and 600 single-pause writes must cause ZERO restarts"
    );
    assert_eq!(
        res_unrel_va,
        Ok(Some((
            live_va_unrel,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(0x7c90_0000, 0x4000));
    drop(live_128k);

    // Subcase 5a (Codex #16 P0-3 & P1): Single-slice replacement that ALSO drops
    // the old host backing before Phase 1's liveness probe retries via `registry.revision()`
    // while firing `REPLAY_REMAP_DURING_PHASE1_LOOKUP` strictly once.
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<usize>();
    let (start_drop_tx, start_drop_rx) = std::sync::mpsc::channel::<()>();
    let (did_drop_tx, did_drop_rx) = std::sync::mpsc::channel::<()>();
    let dropper = std::thread::spawn(move || {
        let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x1000,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate disposable 4 KiB backing");
        let addr = owned.as_ptr() as usize;
        addr_tx.send(addr).expect("send disposable addr");
        let _ = start_drop_rx.recv();
        drop(owned);
        let _ = did_drop_tx.send(());
    });
    let drop_4k_host = addr_rx.recv().expect("receive disposable addr");
    let ipa_drop = 0x7ca0_0000_u64;
    let old_drop_4k = AliasBacking {
        start: 0x3900_0000,
        ipa: ipa_drop,
        host_addr: drop_4k_host,
        size: 0x1000,
        physical_ipa: ipa_drop,
        physical_host_addr: drop_4k_host,
        physical_size: 0x1000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: upsert_scope,
        inventory_backing: InventoryBackingIdentity::Private(14_000),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let new_keep_16k = AliasBacking {
        host_addr: host_16k,
        size: 0x4000,
        physical_host_addr: host_16k,
        physical_size: 0x4000,
        inventory_backing: InventoryBackingIdentity::Private(14_001),
        ..old_drop_4k
    };
    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        registry.push(old_drop_4k);
        registry.clear_replay_mappings_in();
    });
    let phase1_hook_fires = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let phase1_hook_fires_clone = std::sync::Arc::clone(&phase1_hook_fires);
    let start_drop_tx = std::sync::Arc::new(parking_lot::Mutex::new(Some(start_drop_tx)));
    let did_drop_rx = std::sync::Arc::new(parking_lot::Mutex::new(did_drop_rx));
    custody
        .stage2
        .set_hook(Some(std::sync::Arc::new(move |point| {
            if let carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name) = point
                && name == crate::trap::carrier_custody::REPLAY_REMAP_DURING_PHASE1_LOOKUP
            {
                phase1_hook_fires_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(tx) = start_drop_tx.lock().take() {
                    mutate_external_alias_state(|registry| {
                        assert_eq!(registry.upsert_by_key(new_keep_16k), Some(old_drop_4k));
                        registry.clear_replay_mappings_in();
                    });
                    let _ = tx.send(());
                    let _ = did_drop_rx.lock().recv();
                }
            }
        })));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_drop, 0x4000));
    let res_drop = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::Ipa { gpa: ipa_drop },
            &mut |_| true,
        )
    };
    custody.stage2.set_hook(None);
    dropper.join().expect("dropper joined");
    assert_eq!(
        phase1_hook_fires.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "REPLAY_REMAP_DURING_PHASE1_LOOKUP must fire strictly once per replay call"
    );
    assert_eq!(
        res_drop,
        Ok(Some((
            new_keep_16k,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(ipa_drop, 0x4000));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_drop, 0x1000));

    // Subcase 5b (Codex #17 P0-3 & Codex #18 P1): Multi-slice lookup keeps its
    // watch armed AFTER the final slice (`Complete`) into
    // `REPLAY_PHASE1_BEFORE_LIVENESS_PROBE`. Performing BOTH `upsert_by_key` AND
    // backing disposal on the owner thread there dirties the live watch and
    // retries to map `new_multi_keep_16k`.
    let ipa_multi_drop = 0x7cb0_0000_u64;
    let (m_addr_tx, m_addr_rx) = std::sync::mpsc::channel::<usize>();
    let (m_start_drop_tx, m_start_drop_rx) = std::sync::mpsc::channel::<()>();
    let (m_did_drop_tx, m_did_drop_rx) = std::sync::mpsc::channel::<()>();
    let m_owner = std::thread::spawn(move || {
        let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x1000,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate disposable multi-slice 4 KiB backing");
        let addr = owned.as_ptr() as usize;
        let old_row = AliasBacking {
            start: 0x3910_0000,
            ipa: ipa_multi_drop,
            host_addr: addr,
            size: 0x1000,
            physical_ipa: ipa_multi_drop,
            physical_host_addr: addr,
            physical_size: 0x1000,
            perms,
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            ownership_scope: upsert_scope,
            inventory_backing: InventoryBackingIdentity::Private(15_000),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let new_row = AliasBacking {
            host_addr: host_16k,
            size: 0x4000,
            physical_host_addr: host_16k,
            physical_size: 0x4000,
            inventory_backing: InventoryBackingIdentity::Private(15_001),
            ..old_row
        };
        m_addr_tx.send(addr).expect("send disposable addr");
        if m_start_drop_rx.recv().is_ok() {
            mutate_external_alias_state(|registry| {
                assert!(
                    !registry.active_replay_watches.is_empty(),
                    "multi-slice watch must remain live into liveness probe"
                );
                assert_eq!(registry.upsert_by_key(new_row), Some(old_row));
                registry.clear_replay_mappings_in();
            });
            drop(owned);
            let _ = m_did_drop_tx.send(());
        }
    });
    let m_drop_4k_host = m_addr_rx.recv().expect("receive disposable addr");
    let old_multi_drop_4k = AliasBacking {
        start: 0x3910_0000,
        ipa: ipa_multi_drop,
        host_addr: m_drop_4k_host,
        size: 0x1000,
        physical_ipa: ipa_multi_drop,
        physical_host_addr: m_drop_4k_host,
        physical_size: 0x1000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: upsert_scope,
        inventory_backing: InventoryBackingIdentity::Private(15_000),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let new_multi_keep_16k = AliasBacking {
        host_addr: host_16k,
        size: 0x4000,
        physical_host_addr: host_16k,
        physical_size: 0x4000,
        inventory_backing: InventoryBackingIdentity::Private(15_001),
        ..old_multi_drop_4k
    };
    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        for i in 1..=70_u64 {
            registry.push(AliasBacking {
                start: 0x3920_0000 + i * 0x1000,
                ipa: ipa_multi_drop,
                host_addr: 0,
                size: 0x1000,
                physical_ipa: ipa_multi_drop,
                physical_host_addr: 0,
                physical_size: 0x1000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(8000 + i)),
                inventory_backing: InventoryBackingIdentity::Private(15_100 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        registry.push(old_multi_drop_4k);
        registry.clear_replay_mappings_in();
    });
    let before_liveness_fires = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let before_liveness_clone = std::sync::Arc::clone(&before_liveness_fires);
    let m_start_drop_tx = std::sync::Arc::new(parking_lot::Mutex::new(Some(m_start_drop_tx)));
    let m_did_drop_rx = std::sync::Arc::new(parking_lot::Mutex::new(m_did_drop_rx));
    custody
        .stage2
        .set_hook(Some(std::sync::Arc::new(move |point| {
            if let carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name) = point
                && name == crate::trap::carrier_custody::REPLAY_PHASE1_BEFORE_LIVENESS_PROBE
            {
                before_liveness_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if let Some(tx) = m_start_drop_tx.lock().take() {
                    let _ = tx.send(());
                    let _ = m_did_drop_rx.lock().recv();
                }
            }
        })));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_multi_drop, 0x4000));
    let res_multi_drop = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::Ipa {
                gpa: ipa_multi_drop,
            },
            &mut |_| true,
        )
    };
    custody.stage2.set_hook(None);
    m_owner.join().expect("multi-slice owner joined");
    assert_eq!(
        before_liveness_fires.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "REPLAY_PHASE1_BEFORE_LIVENESS_PROBE must fire strictly once per replay call"
    );
    assert_eq!(
        res_multi_drop,
        Ok(Some((
            new_multi_keep_16k,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(ScopedStage2MapTestStub::is_mapped(ipa_multi_drop, 0x4000));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_multi_drop, 0x1000));

    // Subcase 5c (Codex #18 P0-1): Even when an older live fallback VA alias
    // (`older_fallback_va`) survives in Phase 2, replacing and dropping the newer
    // preferred VA alias (`preferred_drop_4k` -> `replacement_va_16k`) on an owner
    // thread before `find` MUST NOT map `older_fallback_va`; dirty watch in Phase 2
    // forces retry and maps `replacement_va_16k`.
    let va_pref = 0x4a00_0000_u64;
    let ipa_old_fb = 0x7cc0_0000_u64;
    let ipa_new_pref = 0x7cd0_0000_u64;
    let (fb_addr_tx, fb_addr_rx) = std::sync::mpsc::channel::<usize>();
    let (fb_start_tx, fb_start_rx) = std::sync::mpsc::channel::<()>();
    let (fb_done_tx, fb_done_rx) = std::sync::mpsc::channel::<()>();
    let fb_owner = std::thread::spawn(move || {
        let owned = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            0x1000,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .expect("allocate disposable VA backing");
        let addr = owned.as_ptr() as usize;
        let old_pref = AliasBacking {
            start: va_pref,
            ipa: 0x7cc8_0000,
            host_addr: addr,
            size: 0x1000,
            physical_ipa: 0x7cc8_0000,
            physical_host_addr: addr,
            physical_size: 0x1000,
            perms,
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            ownership_scope: upsert_scope,
            inventory_backing: InventoryBackingIdentity::Private(16_001),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let replacement = AliasBacking {
            host_addr: host_16k,
            size: 0x4000,
            physical_ipa: ipa_new_pref,
            physical_host_addr: host_16k,
            physical_size: 0x4000,
            inventory_backing: InventoryBackingIdentity::Private(16_002),
            ..old_pref
        };
        fb_addr_tx.send(addr).expect("send VA disposable addr");
        if fb_start_rx.recv().is_ok() {
            mutate_external_alias_state(|registry| {
                assert!(!registry.active_replay_watches.is_empty());
                assert_eq!(registry.upsert_by_key(replacement), Some(old_pref));
                registry.clear_replay_mappings_in();
            });
            drop(owned);
            let _ = fb_done_tx.send(());
        }
    });
    let fb_drop_host = fb_addr_rx.recv().expect("recv VA disposable addr");
    let older_fallback_va = AliasBacking {
        start: va_pref,
        ipa: ipa_old_fb,
        host_addr: host_16k,
        size: 0x4000,
        physical_ipa: ipa_old_fb,
        physical_host_addr: host_16k,
        physical_size: 0x4000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(9000)),
        inventory_backing: InventoryBackingIdentity::Private(16_000),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let preferred_drop_4k = AliasBacking {
        start: va_pref,
        ipa: 0x7cc8_0000,
        host_addr: fb_drop_host,
        size: 0x1000,
        physical_ipa: 0x7cc8_0000,
        physical_host_addr: fb_drop_host,
        physical_size: 0x1000,
        perms,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: upsert_scope,
        inventory_backing: InventoryBackingIdentity::Private(16_001),
        shared_key_base: None,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    let replacement_va_16k = AliasBacking {
        host_addr: host_16k,
        size: 0x4000,
        physical_ipa: ipa_new_pref,
        physical_host_addr: host_16k,
        physical_size: 0x4000,
        inventory_backing: InventoryBackingIdentity::Private(16_002),
        ..preferred_drop_4k
    };
    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        registry.push(older_fallback_va);
        for i in 1..=70_u64 {
            registry.push(AliasBacking {
                start: va_pref,
                ipa: 0x7ce0_0000 + i * 0x1000,
                host_addr: 0,
                size: 0x1000,
                physical_ipa: 0x7ce0_0000 + i * 0x1000,
                physical_host_addr: 0,
                physical_size: 0x1000,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(9100 + i)),
                inventory_backing: InventoryBackingIdentity::Private(16_100 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        registry.push(preferred_drop_4k);
        registry.clear_replay_mappings_in();
    });
    let fb_start_tx = std::sync::Arc::new(parking_lot::Mutex::new(Some(fb_start_tx)));
    let fb_done_rx = std::sync::Arc::new(parking_lot::Mutex::new(fb_done_rx));
    custody
        .stage2
        .set_hook(Some(std::sync::Arc::new(move |point| {
            if let carrick_aarch64::stage2::custody::Stage2HookPoint::Client(name) = point
                && name == crate::trap::carrier_custody::REPLAY_PHASE1_BEFORE_LIVENESS_PROBE
                && let Some(tx) = fb_start_tx.lock().take()
            {
                let _ = tx.send(());
                let _ = fb_done_rx.lock().recv();
            }
        })));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_old_fb, 0x4000));
    assert!(!ScopedStage2MapTestStub::is_mapped(ipa_new_pref, 0x4000));
    let res_fb = unsafe {
        stage2_map_replay(
            &custody,
            g1,
            ReplayAliasLookup::VaAnyScope { va: va_pref },
            &mut |ipa| {
                // Codex #19 P0-2: stale fallback IPA may already be limiter-exhausted (false);
                // Phase 2 must detect the dirty watch and retry BEFORE querying allow_ipa.
                assert_ne!(
                    ipa, ipa_old_fb,
                    "allow_ipa must not be called for stale fallback IPA"
                );
                ipa == ipa_new_pref
            },
        )
    };
    custody.stage2.set_hook(None);
    fb_owner.join().expect("fallback owner joined");
    assert_eq!(
        res_fb,
        Ok(Some((
            replacement_va_16k,
            carrick_aarch64::stage2::Stage2Status::SUCCESS
        )))
    );
    assert!(
        !ScopedStage2MapTestStub::is_mapped(ipa_old_fb, 0x4000),
        "must not map older live fallback after preferred row was replaced"
    );
    assert!(ScopedStage2MapTestStub::is_mapped(ipa_new_pref, 0x4000));

    // Subcase 5d (Codex #19 P0-3): Single-slice fallback (`[older_single_fb, dead_preferred]`)
    // under continuous disjoint sibling writes must arm a live watch on retry and never hit
    // `MAX_REPLAY_PHASE2_RETRIES` exhaustion.
    let (disjoint_ready_tx, disjoint_ready_rx) = std::sync::mpsc::channel::<()>();
    let stop_disjoint = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_disjoint_clone = std::sync::Arc::clone(&stop_disjoint);
    let sibling = std::thread::spawn(move || {
        let base_row = AliasBacking {
            start: 0xa100_0000,
            ipa: 0x8f00_0000,
            host_addr: 0,
            size: 0x4000,
            physical_ipa: 0x8f00_0000,
            physical_host_addr: 0,
            physical_size: 0x4000,
            perms,
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(20_000)),
            inventory_backing: InventoryBackingIdentity::Private(20_000),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        {
            alias_registry().lock().push(base_row);
        }
        let _ = disjoint_ready_tx.send(());
        let mut iter_count = 0_u64;
        while !stop_disjoint_clone.load(std::sync::atomic::Ordering::Relaxed) {
            iter_count += 1;
            let toggled = AliasBacking {
                inventory_backing: InventoryBackingIdentity::Private(20_000 + (iter_count & 1)),
                ..base_row
            };
            {
                let mut registry = alias_registry().lock();
                let _ = registry.upsert_by_key(toggled);
            }
            if iter_count.is_multiple_of(8) {
                std::thread::yield_now();
            }
        }
    });
    disjoint_ready_rx.recv().expect("sibling started");
    for iter in 0..10_u64 {
        let va_single = 0x5200_0000 + iter * 0x10_0000;
        let ipa_single_fb = 0x7d40_0000 + iter * 0x10_0000;
        let single_fb = AliasBacking {
            start: va_single,
            ipa: ipa_single_fb,
            host_addr: host_16k,
            size: 0x4000,
            physical_ipa: ipa_single_fb,
            physical_host_addr: host_16k,
            physical_size: 0x4000,
            perms,
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(
                18_000 + iter * 2,
            )),
            inventory_backing: InventoryBackingIdentity::Private(18_000 + iter * 2),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let single_dead_pref = AliasBacking {
            start: va_single,
            ipa: ipa_single_fb + 0x1_0000,
            host_addr: 0,
            size: 0x4000,
            physical_ipa: ipa_single_fb + 0x1_0000,
            physical_host_addr: 0,
            physical_size: 0x4000,
            perms,
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken(
                18_001 + iter * 2,
            )),
            inventory_backing: InventoryBackingIdentity::Private(18_001 + iter * 2),
            shared_key_base: None,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        {
            let mut registry = alias_registry().lock();
            registry.push(single_fb);
            registry.push(single_dead_pref);
            registry.clear_replay_mappings_in();
        }
        assert!(!ScopedStage2MapTestStub::is_mapped(ipa_single_fb, 0x4000));
        let res_single_churn = unsafe {
            stage2_map_replay(
                &custody,
                g1,
                ReplayAliasLookup::VaAnyScope { va: va_single },
                &mut |_| true,
            )
        };
        assert_eq!(
            res_single_churn,
            Ok(Some((
                single_fb,
                carrick_aarch64::stage2::Stage2Status::SUCCESS
            )))
        );
        assert!(ScopedStage2MapTestStub::is_mapped(ipa_single_fb, 0x4000));
    }
    stop_disjoint.store(true, std::sync::atomic::Ordering::Release);
    sibling.join().expect("sibling joined");

    mutate_external_alias_state(|registry| {
        assert!(
            registry.active_replay_watches.is_empty(),
            "all replay watches must be removed cleanly: {:?}",
            registry.active_replay_watches
        );
        *registry = AliasRegistry::default();
    });
    drop(live_4k);
    drop(live_16k);
}

#[test]
#[allow(clippy::expect_used)]
fn forget_replay_extent_skips_unrelated_scopes() {
    use crate::trap::stage2_backend::{
        ScopedStage2MapTestStub, stage2_unmap_untracked_in, test_stage2_map_untracked,
    };
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let _stub = ScopedStage2MapTestStub::enable();
    let custody = std::sync::Arc::new(CarrierVmCustody::new());
    let g1 = custody.begin_create().expect("begin G1");
    custody.commit_create(g1).expect("commit G1");

    let perms = carrick_aarch64::stage2::stage2_perms_bits(carrick_hal::MemPerms::ReadWrite);
    let non_alias_ipa = 0xa082_0000_0000_u64;
    let non_alias_len = 0x4000_usize;
    let mut non_alias_backing = vec![0_u8; non_alias_len];
    test_stage2_map_untracked(
        &custody,
        non_alias_backing.as_mut_ptr().cast(),
        non_alias_ipa,
        non_alias_len,
        perms,
    );

    let orphan_ipa = 0x7d10_0000_u64;
    let orphan_scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken(5150));
    let orphan_key = (orphan_ipa, non_alias_len, 0xdead_beef, perms, 0);

    mutate_external_alias_state(|registry| {
        *registry = AliasRegistry::default();
        for i in 1..=200_u64 {
            let scope = AliasOwnershipScope::ContainerRoot(ContainerRootToken(5000 + i));
            let ipa = 0x7e00_0000 + i * 0x4000;
            registry.push(AliasBacking {
                start: 0x3500_0000 + i * 0x4000,
                ipa,
                host_addr: (0x4500_0000 + i * 0x4000) as usize,
                size: non_alias_len,
                physical_ipa: ipa,
                physical_host_addr: (0x4500_0000 + i * 0x4000) as usize,
                physical_size: non_alias_len,
                perms,
                guest_writable: true,
                sharing: GuestMappingSharing::GlobalShared,
                ownership_scope: scope,
                inventory_backing: InventoryBackingIdentity::Private(9800 + i),
                shared_key_base: None,
                shared_key_offset: 0,
                owner_generation: 0,
            });
        }
        registry.insert_replay_in_scope(orphan_scope, orphan_key);
        assert_eq!(registry.recomputed_replay_counts(), registry.replay_counts);
    });

    // 1. Unmapping a non-alias extent must touch 0 alias scopes even with 200 live scopes.
    let before_non_alias = alias_replay_scopes_probed();
    stage2_unmap_untracked_in(&custody, g1, None, non_alias_ipa, non_alias_len)
        .expect("unmap non-alias extent");
    assert_eq!(
        alias_replay_scopes_probed() - before_non_alias,
        0,
        "unmapping non-alias extent must never scan unrelated alias scopes"
    );

    // 2. Forgetting an orphan replay extent with no physical-start row must probe ONLY its scope.
    let before_orphan = alias_replay_scopes_probed();
    forget_replay_extent(orphan_ipa, non_alias_len);
    assert!(
        alias_replay_scopes_probed() - before_orphan <= 1,
        "forgetting orphan replay extent probed unrelated scopes"
    );
    {
        let registry = alias_registry().lock();
        assert!(!registry.contains_replay(&orphan_key));
        assert!(
            registry
                .replay_scopes_for_extent(orphan_ipa, non_alias_len)
                .is_none()
        );
        assert_eq!(registry.recomputed_replay_counts(), registry.replay_counts);
    }

    mutate_external_alias_state(|registry| *registry = AliasRegistry::default());
}

mod maintenance_lookup_budget;
