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
        replay_mappings().lock().insert(key);

        // The exact installed marker returns before touching Hypervisor.framework.
        let result = unsafe { inventory_hv_vm_map_replay(backing) };
        assert_eq!(result, 0);
        assert!(replay_mappings().lock().contains(&key));

        forget_replay_extent(backing.ipa, backing.size);
        assert!(!replay_mappings().lock().contains(&key));
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

        let replay = replay_mappings().lock();
        assert!(!replay.contains(&replay_mapping_key(original)));
        assert!(replay.contains(&replay_mapping_key(replacement)));
        assert_eq!(
            replay
                .iter()
                .filter(|(ipa, _, _, _, _)| *ipa == original.ipa)
                .count(),
            1
        );
        drop(replay);
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
