//! Unit tests for memory protection and alias remapping.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod alias_remap_limiter_tests {
    use super::*;

    #[test]
    fn exact_replay_marker_turns_a_sibling_race_into_success() {
        let backing = AliasBacking {
            start: 0x1000,
            ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7f00_0000,
            host_addr: 0x1234_0000,
            size: HVF_PAGE_SIZE as usize,
            physical_ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7f00_0000,
            physical_host_addr: 0x1234_0000,
            physical_size: HVF_PAGE_SIZE as usize,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 0,
        };
        let key = replay_mapping_key(backing);
        alias_registry()
            .lock()
            .by_scope
            .entry(backing.ownership_scope)
            .or_default()
            .replay
            .insert(key);

        // The exact installed marker returns before touching Hypervisor.framework.
        let result = unsafe { inventory_hv_vm_map_replay(backing) };
        assert_eq!(result, 0);
        assert!(alias_registry().lock().contains_replay(&key));

        forget_replay_extent(backing.ipa, backing.size);
        assert!(!alias_registry().lock().contains_replay(&key));
    }

    #[test]
    fn caps_repeated_faults_on_one_alias_backing() {
        let mut limiter = AliasRemapLimiter::default();
        let ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000;

        for _ in 0..AliasRemapLimiter::MAX_ATTEMPTS_PER_IPA {
            assert!(limiter.allow(ipa));
        }
        assert!(!limiter.allow(ipa));
    }

    #[test]
    fn alias_replacement_keeps_one_replay_identity_per_ipa() {
        let original = AliasBacking {
            start: 0x1000,
            ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7e00_0000,
            host_addr: 0x1234_0000,
            size: HVF_PAGE_SIZE as usize,
            physical_ipa: crate::memory::LINUX_ALIAS_IPA_BASE + 0x7e00_0000,
            physical_host_addr: 0x1234_0000,
            physical_size: HVF_PAGE_SIZE as usize,
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::Private(2),
            shared_key_base: 0,
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
        let base = crate::memory::LINUX_MMAP_BASE;
        let bad_va = base + 4096;
        let mut manager = carrick_mem::page_table::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            crate::memory::LINUX_PAGE_TABLES_BASE,
        );
        manager.set_readonly(bad_va, 4096, false, None).unwrap();
        let shadow = manager.debug_walk(bad_va);
        assert_ne!(shadow[3], 0, "fixture must contain an L3 split");
        let table = shadow[2] & 0x0000_ffff_ffff_f000;
        let slot =
            ((table - manager.base()) / 8) as usize + carrick_mem::page_table::indices(bad_va)[3];
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
        const AP_USER_RO: u64 = 0b11 << 6;
        let va = crate::memory::LINUX_MMAP_BASE;
        let mut page_tables = carrick_mem::page_table::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            crate::memory::LINUX_PAGE_TABLES_BASE,
        );
        page_tables
            .set_rw(va, 0x1000, false, None)
            .expect("publish writable leaf");
        page_tables
            .set_prot_none(va, 0x1000, None)
            .expect("invalidate leaf while retaining its output and attributes");

        let leaf = carrick_mem::page_table::terminal_descriptor(page_tables.debug_walk(va));
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
        const AP_USER_RW: u64 = 0b01 << 6;
        const UXN: u64 = 1 << 54;
        let va = crate::memory::LINUX_MMAP_BASE;
        let mut page_tables = carrick_mem::page_table::PageTableManager::new(
            carrick_mem::memory::stage1_hvpatch_page_tables(),
            crate::memory::LINUX_PAGE_TABLES_BASE,
        );
        page_tables
            .set_rw(va, 0x1000, false, None)
            .expect("publish writable non-executable leaf");

        let leaf = carrick_mem::page_table::terminal_descriptor(page_tables.debug_walk(va));
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: parent_root_slot.0,
                size: parent_root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::SharedAnon(41),
            shared_key_base: 0,
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

    #[test]
    fn address_space_replacement_drops_only_its_private_alias_scope() {
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
                perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
                guest_writable: true,
                sharing: GuestMappingSharing::ForkSharedAnonymous,
                ownership_scope: AliasOwnershipScope::MmRootSlot {
                    base: parent_root_slot.0,
                    size: parent_root_slot.1,
                },
                inventory_backing: InventoryBackingIdentity::SharedAnon(42),
                shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::GlobalShared,
            ownership_scope: AliasOwnershipScope::Global,
            inventory_backing: InventoryBackingIdentity::SharedFile {
                device: 1,
                inode: 2,
                offset: 0x8000,
                length: 0xc000,
            },
            shared_key_base: 7,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: scope,
            inventory_backing: InventoryBackingIdentity::Private(46),
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::SharedAnon(44),
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::SharedAnon(45),
            shared_key_base: 0,
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
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            guest_writable: true,
            shared_key_base: 0,
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
            perms: u64::from(desc.perms),
            guest_writable: desc.guest_writable,
            sharing: desc.sharing,
            ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
            inventory_backing: InventoryBackingIdentity::SharedAnon(46),
            shared_key_base: 0,
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
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::ForkSharedAnonymous,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::SharedAnon(43),
            shared_key_base: 0,
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
            perms: applevisor::memory::MemPerms::ReadExec,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: false,
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadExec),
            guest_writable: false,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::Private(71),
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope,
            inventory_backing: InventoryBackingIdentity::Private(ipa),
            shared_key_base: 0,
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
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: root_slot.0,
                size: root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::Private(44),
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::ContainerRoot(container_1),
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::ContainerRoot(container_2),
            inventory_backing: InventoryBackingIdentity::Private(2),
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: child_root_slot.0,
                size: child_root_slot.1,
            },
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: 0,
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
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
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
        static TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
        let _test_lock = TEST_LOCK.lock();
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
            u64::from(applevisor::memory::MemPerms::ReadWrite),
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
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: None,
            is_dynamic_alias: true,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
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
            perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
            guest_writable: true,
            sharing: GuestMappingSharing::Private,
            ownership_scope: scope,
            inventory_backing: InventoryBackingIdentity::Private(1),
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: 1,
        }
    }

    #[test]
    fn planned_unmap_matches_legacy_snapshot_oracle() {
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
        assert_eq!(registry.len(), 5000);

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
            elapsed < std::time::Duration::from_millis(50),
            "unmapping 1 row in 5000-row registry took {elapsed:?}, expected < 50ms"
        );
    }

    #[test]
    #[ignore = "director perf benchmark: single-row unmap in 5000-row registry"]
    fn perf_unmap_single_row_in_5000_row_registry() {
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
}
