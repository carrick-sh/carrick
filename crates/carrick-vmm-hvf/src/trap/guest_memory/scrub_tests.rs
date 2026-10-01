//! Real software stage-1 fixtures; no HVF VM or guest execution.
use super::budget_tests::{MmapBuffer, test_vm_state};
use super::*;
use crate::trap::thread_sibling_tests::mapped_region;

const VA: u64 = 0x1383_4800_0000;
const PAGE: usize = 0x1000;
const LEN: usize = 4 * PAGE;

fn tables() -> carrick_mmu_core::aarch64::PageTableManager {
    carrick_mmu_core::aarch64::PageTableManager::new(
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
        carrick_mem::memory::AARCH64_LINUX_PAGE_TABLE_LAYOUT,
    )
}

fn translation_after_hole(reusable: bool, retained: bool) {
    let backing = MmapBuffer::new(LEN);
    let translated = MmapBuffer::new(LEN);
    unsafe {
        std::ptr::write_bytes(backing.ptr, 0xa5, LEN);
        std::ptr::write_bytes(translated.ptr, 0xb6, LEN);
    }
    let mut task = HvfTaskState::neutral();
    let ipa = if reusable {
        carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x7840_0000
    } else {
        0x2000_0000
    };
    assert_eq!(is_reusable_global_frame_extent(ipa, 1), reusable);
    let mut row = mapped_region(VA, VA + LEN as u64, ipa);
    row.host_addr = backing.ptr;
    task.mappings.insert(row);
    let q = 0x3000_0000;
    let mut row = mapped_region(VA + PAGE as u64, VA + 2 * PAGE as u64, q);
    row.host_addr = translated.ptr;
    task.mappings.insert(row);
    let mut pt = tables();
    assert_eq!(pt.translate(VA), None);
    assert_eq!(pt.translate_retained_output(VA), None);
    pt.map_aliased(
        VA + PAGE as u64,
        q,
        PAGE as u64,
        carrick_mmu_core::aarch64::UserLeafAccess {
            writable: false,
            executable: true,
        },
        None,
    )
    .unwrap();
    if retained {
        pt.set_prot_none(VA + PAGE as u64, PAGE, None).unwrap();
    }
    task.page_tables_authority().set_manager(pt);
    let mut vm = test_vm_state(task);
    vm.zero_guest_backing(VA, 2 * PAGE).unwrap();
    assert_eq!(
        unsafe { *translated.ptr },
        0,
        "later translated backing must be scrubbed"
    );
    assert_eq!(
        unsafe { *backing.ptr.add(PAGE) },
        0xa5,
        "VA fallback must not overwrite the other backing's page"
    );
    assert_eq!(unsafe { *backing.ptr }, if reusable { 0xa5 } else { 0 });
}

#[test]
fn fallback_stops_before_live_translation() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    translation_after_hole(false, false);
}
#[test]
fn fallback_stops_before_retained_translation() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    translation_after_hole(false, true);
}
#[test]
fn reusable_skip_stops_before_live_translation() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    translation_after_hole(true, false);
}
#[test]
fn reusable_skip_stops_before_retained_translation() {
    translation_after_hole(true, true);
}

#[test]
fn retained_interior_pages_republish_lifetime_edges() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    let _restore = crate::trap::foreign_mm::tests::ExternalAliasStateRestore::capture();
    let backing = MmapBuffer::new(LEN);
    let ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x7880_0000;
    let root = (
        carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE,
        2 * 1024 * 1024,
    );
    let mut task = HvfTaskState::neutral();
    task.mm_root_slot = Some(root);
    let mut row = mapped_region(VA, VA + LEN as u64, ipa);
    row.host_addr = backing.ptr;
    task.mappings.insert(row);
    let prefix = AliasBacking {
        start: VA,
        ipa,
        host_addr: backing.ptr as usize,
        size: PAGE,
        physical_ipa: ipa,
        physical_host_addr: backing.ptr as usize,
        physical_size: LEN,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: root.0,
            size: root.1,
        },
        inventory_backing: InventoryBackingIdentity::Private(46),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    register_shared_alias(prefix);
    register_shared_alias(AliasBacking {
        start: VA + 3 * PAGE as u64,
        ipa: ipa + 3 * PAGE as u64,
        host_addr: backing.ptr as usize + 3 * PAGE,
        ..prefix
    });
    let mut pt = tables();
    pt.map_aliased(
        VA,
        ipa,
        LEN as u64,
        carrick_mmu_core::aarch64::UserLeafAccess {
            writable: false,
            executable: true,
        },
        None,
    )
    .unwrap();
    pt.set_prot_none(VA, LEN, None).unwrap();
    task.page_tables_authority().set_manager(pt);
    let mut vm = test_vm_state(task);
    let initial_registry = alias_registry().lock().clone();
    unsafe {
        std::ptr::write_bytes(backing.ptr, 0xa5, LEN);
    }
    vm.zero_guest_backing_reference(VA, 3 * PAGE).unwrap();
    let reference_entries = alias_registry().lock().ordered();
    let reference_bytes = unsafe { std::slice::from_raw_parts(backing.ptr, LEN).to_vec() };
    mutate_external_alias_state(|registry| *registry = initial_registry);
    unsafe {
        std::ptr::write_bytes(backing.ptr, 0xa5, LEN);
    }
    vm.zero_guest_backing(VA, 3 * PAGE).unwrap();
    let entries = alias_registry().lock().ordered();
    assert_eq!(
        entries, reference_entries,
        "retain every pre-batch lifetime edge"
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(backing.ptr, LEN) },
        reference_bytes
    );
    for page in 1..3 {
        assert!(
            entries
                .iter()
                .any(|entry| entry.start == VA + page * PAGE as u64 && entry.size == PAGE),
            "missing retained page {page} lifetime edge"
        );
    }
    assert!(unregister_alias(VA, PAGE, Some(root), ContainerRootToken::ROOT).is_empty());
    assert!(
        unregister_alias(
            VA + 3 * PAGE as u64,
            PAGE,
            Some(root),
            ContainerRootToken::ROOT
        )
        .is_empty()
    );
}

// Frozen reference from 88fd31403, intentionally independent of run construction.
impl HvfVmState {
    fn zero_guest_backing_reference(
        &mut self,
        address: u64,
        length: usize,
    ) -> Result<(), MemoryError> {
        let address = strip_pointer_tag(address);
        // Scrub debug: CARRICK_FORK_DEBUG_VA=<hex> logs any zeroing whose range
        // covers that VA, with the caller — the instrument that named the agent
        // zeroing a live dict granule during the forkserver corruption hunt.
        if let Some(debug_va) = fork_debug_va()
            && address <= debug_va
            && debug_va < address.saturating_add(length as u64)
        {
            eprintln!(
                "[FORKDBG pid={:?}] zero_guest_backing va={address:#x} len={length:#x}\n{}",
                self.cow_identity.map(|identity| identity.linux_pid),
                std::backtrace::Backtrace::force_capture(),
            );
        }
        let mut cleared = 0usize;
        let mut active_run: Option<ScrubRun> = None;
        while cleared < length {
            let (chunk_va, chunk_len) = Self::guest_copy_chunk(address, cleared, length)?;
            // munmap invalidates the leaf but intentionally preserves its PA.
            // Backing maintenance runs before the replacement VMA is made
            // guest-visible, so an ordinary hardware-valid translation cannot
            // identify a retained private-COW fragment here. Resolve that PA
            // through the typed invalid-leaf seam and scrub each page-bounded
            // physical fragment independently.
            let retained_ipa = self
                .page_tables_authority()
                .with_manager(|manager| manager.translate_retained_output(chunk_va))
                .flatten();
            // A partial munmap can carve this 4 KiB Linux page out of a live
            // 16 KiB private frame while preserving the invalid leaf's output
            // IPA. Reusing that page does not pass through `add_alias`, so
            // republish its semantic lifetime edge before a later sibling
            // munmap is allowed to retire the containing stage-2 lease.
            let retained_fragment = retained_ipa.and_then(|ipa| {
                retained_private_reuse_alias_fragment_in(
                    &self.carrier_foreign_mm_transport.custody,
                    &alias_registry().lock(),
                    chunk_va,
                    ipa,
                    chunk_len,
                    self.mm_root_slot,
                    self.container_root,
                )
            });
            // WRITE TARGETS ARE STAGE-1-AUTHENTICATED, PERIOD. This used to
            // fall back to `mapping_for_range_mut` — a VA-keyed search over
            // carrier-inherited rows with no scope filter — when the caller's
            // own translation had nothing. A fork child's engine inherits
            // Borrowed rows pointing at the ANCESTOR's host memory for
            // numerically identical VAs, and a reused range is scrubbed
            // exactly while its stage-1 is invalid, so that fallback resolved
            // another process's frame and zeroed it: one 16 KiB granule of the
            // forkserver server's live interned-strings dict, read back as
            // NULL me_keys by every worker (the CPython multiprocessing
            // SIGSEGV cluster).
            //
            // The scrub's purpose is to keep STALE BYTES from being observed
            // through THIS VA. If neither the live walk nor the retained
            // invalid-leaf output names an IPA, the guest has no translation
            // here and cannot observe anything — there is nothing to scrub,
            // and skipping is the correct amount of writing. With an IPA in
            // hand, `mapping_for_live_ipa_range` demands VA/IPA consistency
            // plus a live authenticated owner, so the write can only land in
            // this mm's own backing.
            let live_ipa = self.translate_va(chunk_va);
            let ipa = live_ipa.or(retained_ipa);
            let chunk_resolved = ipa
                .and_then(|ipa| {
                    self.mapping_for_live_ipa_range(chunk_va, ipa, chunk_len)
                        .and_then(|mapping| {
                            let offset = usize::try_from(ipa.checked_sub(mapping.ipa)?).ok()?;
                            let target = unsafe { mapping.host_addr.add(offset) };
                            let is_alias = is_reusable_global_frame_extent(mapping.ipa, 1);
                            let eligible_without_cow = mapping.sharing
                                == GuestMappingSharing::Private
                                && mapping.shared_key_base == 0
                                && !is_alias
                                && retained_fragment.is_none()
                                && zero_anonymous_remap_enabled();
                            let eligible = scrub_remap_eligible(eligible_without_cow, || {
                                self.physical_cow_source(chunk_va, ipa).is_some()
                            });
                            Some((target, eligible))
                        })
                })
                .or_else(|| {
                    // VA fallback, restricted to NON-reusable backing. Boot and
                    // identity regions (the brk heap above all) are per-mm by
                    // construction and sometimes reachable only by VA here;
                    // skipping them left stale bytes where `ltp-brk02` demands
                    // zeros. Reusable global-frame results stay excluded — a
                    // VA-only join over carrier-inherited rows is exactly the
                    // cross-process write this function must never make.
                    self.mapping_for_range_mut(chunk_va, chunk_len)
                        .and_then(|mapping| {
                            // The view carries only the semantic IPA; that is
                            // sufficient here — reusable-frame mappings' semantic
                            // IPAs live inside the global-frame arena, identity
                            // and boot mappings' do not.
                            if is_reusable_global_frame_extent(mapping.ipa, 1) {
                                return None;
                            }
                            let offset =
                                usize::try_from(chunk_va.checked_sub(mapping.start)?).ok()?;
                            let target = unsafe { mapping.host_addr.add(offset) };
                            let eligible_without_cow = mapping.sharing
                                == GuestMappingSharing::Private
                                && mapping.shared_key_base == 0
                                && retained_fragment.is_none()
                                && zero_anonymous_remap_enabled();
                            let eligible = scrub_remap_eligible(eligible_without_cow, || {
                                self.physical_cow_source(chunk_va, mapping.ipa).is_some()
                            });
                            Some((target, eligible))
                        })
                });
            if let Some(debug_va) = fork_debug_va()
                && chunk_va <= debug_va
                && debug_va < chunk_va.saturating_add(chunk_len as u64)
            {
                eprintln!(
                    "[SCRUBDBG pid={:?}] chunk va={chunk_va:#x}+{chunk_len:#x} live_ipa={live_ipa:x?} \
                     retained_ipa={retained_ipa:x?} target={:?}",
                    self.cow_identity.map(|identity| identity.linux_pid),
                    chunk_resolved.map(|(target, _)| target),
                );
            }
            if let Some(fragment) = retained_fragment {
                register_shared_alias(fragment);
            }
            match (active_run.as_mut(), chunk_resolved) {
                (Some(run), Some((target, eligible)))
                    if run.eligible == eligible
                        && unsafe { run.host_start.add(run.len) } == target =>
                {
                    run.len += chunk_len;
                }
                (Some(_), Some((target, eligible))) => {
                    if let Some(prev) = active_run.take() {
                        prev.flush();
                    }
                    active_run = Some(ScrubRun {
                        host_start: target,
                        len: chunk_len,
                        eligible,
                    });
                }
                (Some(_), None) => {
                    if let Some(prev) = active_run.take() {
                        prev.flush();
                    }
                }
                (None, Some((target, eligible))) => {
                    active_run = Some(ScrubRun {
                        host_start: target,
                        len: chunk_len,
                        eligible,
                    });
                }
                (None, None) => {}
            }
            cleared += chunk_len;
        }
        if let Some(run) = active_run {
            run.flush();
        }
        Ok(())
    }
}

#[test]
fn enumerated_layouts_match_pre_batch_page_reference() {
    let _global_state_guard = crate::trap::foreign_mm_tests::global_state_test_lock();
    // Four states per page: hole, first backing, second backing, retained
    // second backing. Enumerate all four-page layouts, including alternating
    // non-identity translations and a mapping-selection boundary at page 1.
    let first = MmapBuffer::new(LEN);
    let second = MmapBuffer::new(LEN);
    for layout in 0..256u32 {
        let mut task = HvfTaskState::neutral();
        let mut a = mapped_region(VA, VA + LEN as u64, 0x2000_0000);
        a.host_addr = first.ptr;
        task.mappings.insert(a);
        let mut b = mapped_region(VA + PAGE as u64, VA + LEN as u64, 0x3000_0000 + PAGE as u64);
        b.host_addr = unsafe { second.ptr.add(PAGE) };
        task.mappings.insert(b);
        let mut pt = tables();
        for page in 0..4 {
            let state = (layout >> (2 * page)) & 3;
            let va = VA + (page * PAGE) as u64;
            let ipa = if state == 1 { 0x2000_0000 } else { 0x3000_0000 } + (page * PAGE) as u64;
            if state != 0 {
                pt.map_aliased(
                    va,
                    ipa,
                    PAGE as u64,
                    carrick_mmu_core::aarch64::UserLeafAccess {
                        writable: false,
                        executable: true,
                    },
                    None,
                )
                .unwrap();
                if state == 3 {
                    pt.set_prot_none(va, PAGE, None).unwrap();
                }
            }
        }
        task.page_tables_authority().set_manager(pt);
        if layout & 1 != 0 {
            task.cow_armed
                .lock()
                .arm(&[carrick_aarch64::vmm::ForkCowRange {
                    va: VA + PAGE as u64,
                    len: PAGE,
                    granule: carrick_aarch64::vmm::CowGranule::Compound,
                    executable: false,
                    kernel_only: false,
                }]);
        }
        let mut vm = test_vm_state(task);
        for (head, tail) in [(0, 0), (0x123, 0x321), (PAGE - 1, PAGE - 3)] {
            let reset = || unsafe {
                std::ptr::write_bytes(first.ptr, 0xa5, LEN);
                std::ptr::write_bytes(second.ptr, 0xb6, LEN);
            };
            let bytes = || unsafe {
                (
                    std::slice::from_raw_parts(first.ptr, LEN).to_vec(),
                    std::slice::from_raw_parts(second.ptr, LEN).to_vec(),
                )
            };
            reset();
            vm.zero_guest_backing_reference(VA + head as u64, LEN - head - tail)
                .unwrap();
            let expected = bytes();
            reset();
            vm.zero_guest_backing(VA + head as u64, LEN - head - tail)
                .unwrap();
            let actual = bytes();
            assert!(
                actual == expected,
                "layout={layout:#x}, head={head:#x}, tail={tail:#x}"
            );
        }
    }
}
