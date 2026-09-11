#![cfg(all(test, target_os = "macos", target_arch = "aarch64"))]

use super::*;

// NOTE: the thread-sibling register SEEDING tests (child_resumes_at_post_
// syscall_pc_with_x0_zero / child_uses_clone_stack_and_tls /
// child_keeps_parent_tls_when_clone_tls_is_zero / child_copies_all_other_
// gprs_and_sysregs) moved with `seed_child_snapshot` into the shared engine:
// they live ONCE in `carrick_aarch64`'s `seed_applies_thread_entry_deltas`
// (over the neutral `Aarch64VcpuSnapshot`). HVF no longer owns the seeding, so
// it no longer owns those assertions.

#[test]
fn decodes_el0_counter_register_traps() {
    let cntfrq = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
        | AARCH64_SYS64_ISS_SYS_CNTFRQ
        | (1 << AARCH64_SYS64_ISS_RT_SHIFT);
    let cntvct = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
        | AARCH64_SYS64_ISS_SYS_CNTVCT
        | (2 << AARCH64_SYS64_ISS_RT_SHIFT);

    assert_eq!(
        decode_el0_sys64_read(cntfrq),
        Some((1, El0SysRegRead::CntfrqEl0))
    );
    assert_eq!(
        decode_el0_sys64_read(cntvct),
        Some((2, El0SysRegRead::CntvctEl0))
    );
    // CTR_EL0 / DCZID_EL0 — the cache-geometry reads glibc 2.41 does at
    // startup. The faulting `mrs x1, ctr_el0` observed from python:3.12-slim
    // was ESR_EL1=0x6232c021 (EC=0x18, Rt=1): decode it directly.
    assert_eq!(
        decode_el0_sys64_read(0x6232c021),
        Some((1, El0SysRegRead::CtrEl0))
    );
    let dczid = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
        | AARCH64_SYS64_ISS_SYS_DCZID
        | (3 << AARCH64_SYS64_ISS_RT_SHIFT);
    assert_eq!(
        decode_el0_sys64_read(dczid),
        Some((3, El0SysRegRead::DczidEl0))
    );
    assert_eq!(decode_el0_sys64_read(0), None);
}

#[test]
fn shared_mm_task_projection_preserves_structural_owner() {
    let size = 0x4000usize;
    let ipa = 0x8800_3100_0000u64;
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate shared-MM projection backing");
    let host = mapping.as_ptr();
    let epoch = next_structural_epoch().expect("shared-MM projection epoch");
    let owner = StructuralBackingOwner::new(
        mapping,
        GlobalFrameStage2Lease::fixed(ipa, size as u64),
        epoch,
        ipa,
        size,
    )
    .expect("publish shared-MM projection owner");
    let identity = *owner.retained.record_identity.lock();
    let desc = ThreadMappingDesc {
        start: 0x0040_0000,
        ipa,
        end: 0x0040_4000,
        host_addr: host,
        size,
        physical_ipa: ipa,
        physical_host_addr: host,
        physical_size: size,
        perms: applevisor::memory::MemPerms::ReadExec,
        is_dynamic_alias: false,
        sharing: GuestMappingSharing::Private,
        guest_writable: false,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: epoch.raw(),
        structural_owner: Some(std::sync::Arc::clone(&owner)),
    };

    let projected = desc.into_shared_mm_task_mapping();
    assert!(
        projected
            .structural_owner
            .as_ref()
            .is_some_and(|projected| std::sync::Arc::ptr_eq(projected, &owner)),
        "shared-process and sibling task projections must retain the exact structural owner",
    );

    drop(projected);
    drop(owner);
    retry_structural_backing_identities_in_using(
        legacy_test_carrier_vm_custody(),
        &[identity],
        &mut unmap_global_frame_stage2_record,
        &mut release_retired_stage2_ipa,
    )
    .expect("retire shared-MM projection fixture");
}

#[test]
fn thread_mapping_descriptor_preserves_shared_mapping_metadata() {
    // `into_unowned_region` (the surviving half of the old `ThreadMappingDesc`
    // round-trip; `from_region` moved to the engine's sibling-builder seam)
    // must re-materialise the syscall-path metadata UNOWNED (memory/host_mapping
    // = None) so a sibling never frees the main engine's buffers.
    let desc = ThreadMappingDesc {
        start: 0x1000,
        ipa: 0x1000,
        end: 0x5000,
        host_addr: 0x7000usize as *mut u8,
        size: 0x4000,
        physical_ipa: 0x1000,
        physical_host_addr: 0x7000usize as *mut u8,
        physical_size: 0x4000,
        perms: applevisor::memory::MemPerms::ReadWrite,
        is_dynamic_alias: true,
        sharing: GuestMappingSharing::GlobalShared,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 17,
        structural_owner: None,
    };

    let copied = desc.into_unowned_region();

    assert_eq!(copied.start, 0x1000);
    assert_eq!(copied.end, 0x5000);
    assert_eq!(copied.host_addr, 0x7000usize as *mut u8);
    assert_eq!(copied.size, 0x4000);
    assert_eq!(copied.perms, applevisor::memory::MemPerms::ReadWrite);
    assert!(copied.memory.is_none());
    assert!(copied.host_mapping.is_none());
    assert_eq!(copied.sharing, GuestMappingSharing::GlobalShared);
    assert_eq!(copied.owner_generation, 17);
}

#[test]
fn global_frame_futex_resolves_raw_backing_ipa_not_semantic_va() {
    // Global-frame HVPatch deliberately has start != ipa. The neutral
    // AArch64 engine passes the translated backing GPA to the VMM seam, so
    // subtracting the semantic VA selects no word (and routes a shared
    // anonymous futex through the process-private table after fork).
    let view = MappingView {
        start: 0x0090_0000_0000,
        end: 0x0090_0000_4000,
        ipa: 0x00a3_0010_0000,
        host_addr: 0x1000usize as *mut u8,
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        shared_key_base: 0,
        shared_key_offset: 0,
    };
    let location = view
        .shared_futex_location_for_ipa(view.ipa + 4)
        .expect("global shared frame must expose its translated host word");
    assert_eq!(location.wait_addr().raw(), 0x1004);
    assert_eq!(location.waiter_key(), 0x1004);
}

#[test]
fn shared_futex_route_skips_private_row_at_recycled_ipa() {
    let backing_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x80_0000;
    let mut shared = mapped_region(0x100_0080_0000, 0x100_0080_4000, backing_ipa);
    shared.host_addr = 0x1046_78000usize as *mut u8;
    shared.sharing = GuestMappingSharing::GlobalShared;
    // The ordered index walks rows newest-VA-first, so a private row ABOVE
    // the shared one is the first candidate an unfiltered raw-IPA lookup
    // would take. Its VA is incidental to what this test proves: only the
    // shared-futex identity filter may decide the route.
    let mut retired_private = mapped_region(0x100_0090_0000, 0x100_0094_0000, backing_ipa);
    retired_private.host_addr = 0x1177_d0000usize as *mut u8;
    let mappings = TaskMappingIndex::from_iter([shared, retired_private]);

    let location = HvfVmState::shared_futex_mapping_for_ipa(&mappings, backing_ipa + 4, false)
        .expect("the older exact shared owner must remain routable");

    assert_eq!(location.wait_addr().raw(), 0x1046_78004);
    assert_eq!(location.waiter_key(), 0x1046_78004);
}

pub(crate) fn mapped_region(start: u64, end: u64, ipa: u64) -> HvfMappedRegion {
    HvfMappedRegion {
        start,
        ipa,
        physical_ipa: ipa,
        end,
        host_addr: std::ptr::null_mut(),
        size: usize::try_from(end - start).unwrap(),
        physical_size: usize::try_from(end - start).unwrap(),
        perms: applevisor::memory::MemPerms::ReadWrite,
        memory: None,
        host_mapping: None,
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: false,
        sharing: GuestMappingSharing::Private,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
    }
}

#[derive(Debug, Clone, Copy)]
struct FakeStageSegment {
    va_start: u64,
    va_end: u64,
    ipa_start: u64,
}

impl FakeStageSegment {
    fn new(va_start: u64, va_end: u64, ipa_start: u64) -> Self {
        Self {
            va_start,
            va_end,
            ipa_start,
        }
    }

    fn translate(self, va: u64) -> Option<u64> {
        (va >= self.va_start && va < self.va_end).then_some(self.ipa_start + (va - self.va_start))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeCopyChunk {
    mapping_idx: usize,
    len: usize,
    mapping_offset: usize,
}

struct FakeStageCopyHarness {
    mappings: Vec<HvfMappedRegion>,
    backing: Vec<Vec<u8>>,
    stage: Vec<FakeStageSegment>,
}

impl FakeStageCopyHarness {
    fn new(mappings: Vec<HvfMappedRegion>, stage: Vec<FakeStageSegment>) -> Self {
        let backing = mappings
            .iter()
            .map(|mapping| vec![0; mapping.size])
            .collect();
        Self {
            mappings,
            backing,
            stage,
        }
    }

    fn read(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let plan = self.plan(address, length)?;
        let mut bytes = vec![0; length];
        let mut copied = 0usize;
        for chunk in plan {
            let src = &self.backing[chunk.mapping_idx]
                [chunk.mapping_offset..chunk.mapping_offset + chunk.len];
            bytes[copied..copied + chunk.len].copy_from_slice(src);
            copied += chunk.len;
        }
        Ok(bytes)
    }

    fn write(
        &mut self,
        address: u64,
        bytes: &[u8],
        require_guest_writable: bool,
    ) -> Result<(), MemoryError> {
        let plan = self.plan(address, bytes.len())?;
        if require_guest_writable
            && plan
                .iter()
                .any(|chunk| !self.mappings[chunk.mapping_idx].guest_writable)
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }

        let mut copied = 0usize;
        for chunk in plan {
            let dst = &mut self.backing[chunk.mapping_idx]
                [chunk.mapping_offset..chunk.mapping_offset + chunk.len];
            dst.copy_from_slice(&bytes[copied..copied + chunk.len]);
            copied += chunk.len;
        }
        Ok(())
    }

    fn mapping_bytes(&self, idx: usize) -> &[u8] {
        &self.backing[idx]
    }

    fn zero_copy_eligible(&self, address: u64, length: usize) -> bool {
        let Ok(plan) = self.plan(address, length) else {
            return false;
        };
        let Some(first) = plan.first() else {
            return false;
        };
        let first_mapping = &self.mappings[first.mapping_idx];
        let first_physical = first_mapping.ipa + first.mapping_offset as u64;
        let mut copied = 0usize;
        for chunk in &plan {
            let mapping = &self.mappings[chunk.mapping_idx];
            let physical = mapping.ipa + chunk.mapping_offset as u64;
            if chunk.mapping_idx != first.mapping_idx || physical != first_physical + copied as u64
            {
                return false;
            }
            copied += chunk.len;
        }
        true
    }

    fn plan(&self, address: u64, length: usize) -> Result<Vec<FakeCopyChunk>, MemoryError> {
        let mut copied = 0usize;
        let mut plan = Vec::new();
        while copied < length {
            let (chunk_address, chunk_len) = HvfVmState::guest_copy_chunk(address, copied, length)?;
            let stage1_ipa = crate::memory::is_high_va(chunk_address)
                .then(|| self.translate(chunk_address))
                .flatten();
            let mapping_idx = HvfVmState::mapping_index_for_range(
                &self.mappings,
                chunk_address,
                chunk_len,
                stage1_ipa,
            )
            .ok_or(MemoryError::OutOfBounds { address, length })?;
            let mapping_offset =
                usize::try_from(chunk_address - self.mappings[mapping_idx].start).unwrap();
            plan.push(FakeCopyChunk {
                mapping_idx,
                len: chunk_len,
                mapping_offset,
            });
            copied += chunk_len;
        }
        Ok(plan)
    }

    fn translate(&self, va: u64) -> Option<u64> {
        let va = strip_pointer_tag(va);
        self.stage.iter().find_map(|segment| segment.translate(va))
    }
}

#[test]
fn high_va_mapping_lookup_prefers_stage1_ipa_owner_over_newer_va_overlap() {
    let b_start = crate::memory::LINUX_HIGH_VA_THRESHOLD + 0x3000;
    let b_ipa = crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000;
    let mappings = vec![
        mapped_region(b_start, b_start + 0x4000, b_ipa),
        // Newer region A over-claims into B's VA range because the host
        // mapping size was rounded to 16 KiB. The guest stage-1 walk still
        // says B owns b_start+0x1000, so B must win.
        mapped_region(
            crate::memory::LINUX_HIGH_VA_THRESHOLD,
            crate::memory::LINUX_HIGH_VA_THRESHOLD + 0x4000,
            crate::memory::LINUX_ALIAS_IPA_BASE,
        ),
    ];

    let idx =
        HvfVmState::mapping_index_for_range(&mappings, b_start + 0x1000, 8, Some(b_ipa + 0x1000));

    assert_eq!(idx, Some(0));
}

#[test]
fn guest_copy_chunks_reselect_stage1_owner_across_alias_boundary() {
    let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
    let new_start = old_start + 0x3000;
    let new_ipa = old_ipa + 0x20_0000;
    let mappings = vec![
        mapped_region(old_start, old_start + 0x9000, old_ipa),
        mapped_region(new_start, new_start + 0x6000, new_ipa),
    ];
    let address = old_start + 0x2f50;
    let length = 0x5000usize;

    // The old single-region path would select the owner for the range's
    // start and use it for bytes after new_start, even though stage-1 has
    // already repointed that tail to the newer alias.
    assert_eq!(
        HvfVmState::mapping_index_for_range(
            &mappings,
            address,
            length,
            Some(old_ipa + (address - old_start)),
        ),
        Some(0),
    );

    let mut offset = 0usize;
    let mut owners = Vec::new();
    while offset < length {
        let (chunk_address, chunk_len) =
            HvfVmState::guest_copy_chunk(address, offset, length).unwrap();
        let stage1_ipa = if chunk_address < new_start {
            old_ipa + (chunk_address - old_start)
        } else {
            new_ipa + (chunk_address - new_start)
        };
        let idx = HvfVmState::mapping_index_for_range(
            &mappings,
            chunk_address,
            chunk_len,
            Some(stage1_ipa),
        )
        .unwrap();
        if owners.last() != Some(&idx) {
            owners.push(idx);
        }
        offset += chunk_len;
    }

    assert_eq!(owners, vec![0, 1]);
}

#[test]
fn fake_stage1_copy_writes_tail_to_live_owner_backing() {
    let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
    let new_start = old_start + 0x3000;
    let new_ipa = old_ipa + 0x20_0000;
    let mut harness = FakeStageCopyHarness::new(
        vec![
            mapped_region(old_start, old_start + 0x9000, old_ipa),
            mapped_region(new_start, new_start + 0x6000, new_ipa),
        ],
        vec![
            FakeStageSegment::new(old_start, new_start, old_ipa),
            FakeStageSegment::new(new_start, new_start + 0x6000, new_ipa),
        ],
    );
    let address = old_start + 0x2f50;
    let length = 0x2400usize;
    let boundary_prefix = usize::try_from(new_start - address).unwrap();
    let source: Vec<u8> = (0..length).map(|idx| (idx % 251) as u8).collect();

    harness.write(address, &source, false).unwrap();

    assert_eq!(harness.read(address, length).unwrap(), source);
    assert_eq!(
        &harness.mapping_bytes(0)[0x2f50..0x3000],
        &source[..boundary_prefix]
    );
    assert!(
        harness.mapping_bytes(0)[0x3000..0x5350]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        &harness.mapping_bytes(1)[..length - boundary_prefix],
        &source[boundary_prefix..]
    );
}

#[test]
fn zero_copy_declines_cross_fragment_stage1_range() {
    let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
    let new_start = old_start + 0x3000;
    let new_ipa = old_ipa + 0x20_0000;
    let harness = FakeStageCopyHarness::new(
        vec![
            mapped_region(old_start, old_start + 0x9000, old_ipa),
            mapped_region(new_start, new_start + 0x6000, new_ipa),
        ],
        vec![
            FakeStageSegment::new(old_start, new_start, old_ipa),
            FakeStageSegment::new(new_start, new_start + 0x6000, new_ipa),
        ],
    );

    assert!(harness.zero_copy_eligible(old_start + 0x1000, 0x1000));
    assert!(!harness.zero_copy_eligible(old_start + 0x2ff0, 0x1020));
}

#[test]
fn fake_stage1_checked_write_rejects_readonly_tail_without_partial_write() {
    let old_start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let old_ipa = crate::memory::LINUX_ALIAS_IPA_BASE;
    let new_start = old_start + 0x3000;
    let new_ipa = old_ipa + 0x20_0000;
    let mut new_region = mapped_region(new_start, new_start + 0x6000, new_ipa);
    new_region.guest_writable = false;
    let mut harness = FakeStageCopyHarness::new(
        vec![
            mapped_region(old_start, old_start + 0x9000, old_ipa),
            new_region,
        ],
        vec![
            FakeStageSegment::new(old_start, new_start, old_ipa),
            FakeStageSegment::new(new_start, new_start + 0x6000, new_ipa),
        ],
    );
    let address = old_start + 0x2f50;
    let source = vec![0xa5; 0x2400];

    assert!(harness.write(address, &source, true).is_err());
    assert!(harness.mapping_bytes(0).iter().all(|byte| *byte == 0));
    assert!(harness.mapping_bytes(1).iter().all(|byte| *byte == 0));
}

#[test]
fn mapping_lookup_falls_back_to_newest_overlap_without_stage1_ipa() {
    let start = crate::memory::LINUX_HIGH_VA_THRESHOLD;
    let old = mapped_region(start, start + 0x4000, crate::memory::LINUX_ALIAS_IPA_BASE);
    let new = mapped_region(
        start,
        start + 0x4000,
        crate::memory::LINUX_ALIAS_IPA_BASE + 0x20_0000,
    );
    let mappings = vec![old, new];

    let idx = HvfVmState::mapping_index_for_range(&mappings, start + 0x1000, 8, None);

    assert_eq!(idx, Some(1));
}

#[test]
fn raw_ipa_lookup_selects_rebased_mm_global_frame_backing() {
    let guest_va = crate::memory::LINUX_PAGE_TABLES_BASE;
    let root_slot_ipa = crate::memory::LINUX_HVPATCH_ROOT_SLOT_BASE;
    let mappings = TaskMappingIndex::from_region(mapped_region(
        guest_va,
        guest_va + crate::memory::LINUX_PAGE_TABLES_SIZE,
        root_slot_ipa,
    ));

    let mapping = HvfVmState::mapping_for_ipa_range(&mappings, root_slot_ipa + 0x4000, 8)
        .expect("rebased page-table IPA must resolve by IPA, not guest VA");

    assert_eq!(mapping.start, guest_va);
    assert_eq!(mapping.ipa, root_slot_ipa);
    assert!(
        HvfVmState::mapping_for_ipa_range(&mappings, guest_va + 0x4000, 8).is_none(),
        "raw GPA access must not silently select a VA-only match"
    );
}

#[test]
fn mailbox_route_rejects_unrelated_retired_row_at_recycled_ipa() {
    let mailbox_va = crate::memory::LINUX_SYSCALL_MAILBOX_BASE;
    let recycled_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x3c_000;
    let mut mailbox = mapped_region(mailbox_va, mailbox_va + 0x1_0000, recycled_ipa);
    mailbox.host_addr = 0x1177_bc000usize as *mut u8;
    // A retired row that kept the recycled IPA, placed ABOVE the mailbox in
    // VA order so it is the first row a raw-IPA search would reach. It
    // cannot represent the mailbox VA in the live stage-1 graph, so the
    // route must still authenticate the VA-to-IPA translation.
    let mut retired = mapped_region(mailbox_va + 0x10_0000, mailbox_va + 0x10_4000, recycled_ipa);
    retired.host_addr = 0x10e2_90000usize as *mut u8;
    let mappings = TaskMappingIndex::from_iter([mailbox, retired]);

    let selected = HvfVmState::mailbox_mapping_for_range(
        &mappings,
        mailbox_va + 0x400,
        recycled_ipa + 0x400,
        carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
    )
    .expect("live mailbox route");

    assert_eq!(
        selected.start, mailbox_va,
        "mailbox lookup must preserve semantic VA while authenticating the translated IPA",
    );
    assert_eq!(selected.host_addr as usize, 0x1177_bc000);
}

#[test]
fn neutral_persistent_worker_resolves_slot_zero_only_from_carrier_mappings() {
    let carrier_region = |start: u64, size: u64, host: usize| {
        let mut region = mapped_region(start, start + size, start);
        region.host_addr = host as *mut u8;
        region
    };
    let mappings = vec![
        carrier_region(
            crate::memory::LINUX_EL0_TRAMPOLINE_BASE,
            crate::memory::LINUX_EL0_TRAMPOLINE_SIZE,
            0x1100_0000,
        ),
        carrier_region(
            crate::memory::LINUX_EL1_VECTORS_BASE,
            crate::memory::LINUX_EL1_VECTORS_SIZE,
            0x1200_0000,
        ),
        carrier_region(
            crate::memory::LINUX_EL1_MAINT_BASE,
            crate::memory::LINUX_EL1_MAINT_SIZE,
            0x1300_0000,
        ),
        carrier_region(
            crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
            0x1400_0000,
        ),
        carrier_region(
            crate::memory::LINUX_CARRIER_MAINT_ROOT_BASE,
            crate::memory::LINUX_CARRIER_MAINT_ROOT_SIZE,
            0x1500_0000,
        ),
        mapped_region(0x0040_0000, 0x0040_4000, 0x0040_0000),
        mapped_region(
            crate::memory::LINUX_PAGE_TABLES_BASE,
            crate::memory::LINUX_PAGE_TABLES_BASE + crate::memory::LINUX_PAGE_TABLES_SIZE,
            crate::memory::LINUX_PAGE_TABLES_BASE,
        ),
    ];
    let carrier = persistent_executor_carrier_mappings(&mappings);
    assert_eq!(
        carrier.len(),
        5,
        "task image and stage-1 root stay task-owned"
    );

    let neutral = HvfTaskState::neutral();
    neutral
        .audit_neutral()
        .expect("idle worker stays task-neutral");
    assert!(
        persistent_carrier_host_pointer(
            &[],
            crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
        )
        .is_none(),
        "the signed startup failure had no carrier mapping projection"
    );
    let pointer = persistent_carrier_host_pointer(
        &carrier,
        crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
        carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
    )
    .expect("slot zero resolves from executor-local carrier metadata");
    assert_eq!(pointer.as_ptr() as usize, 0x1400_0000);
}

#[test]
fn persistent_carrier_authority_outlives_terminal_task_cleanup_and_drops_stage2_first() {
    let mut task_mappings =
        TaskMappingIndex::from_region(mapped_region(0x0040_0000, 0x0040_4000, 0x0040_0000));
    let mut drop_observations = Vec::new();
    for (start, size) in [
        (
            crate::memory::LINUX_EL0_TRAMPOLINE_BASE,
            crate::memory::LINUX_EL0_TRAMPOLINE_SIZE,
        ),
        (
            crate::memory::LINUX_EL1_VECTORS_BASE,
            crate::memory::LINUX_EL1_VECTORS_SIZE,
        ),
        (
            crate::memory::LINUX_EL1_MAINT_BASE,
            crate::memory::LINUX_EL1_MAINT_SIZE,
        ),
        (
            crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            crate::memory::LINUX_SYSCALL_MAILBOX_ARENA_SIZE,
        ),
        (
            crate::memory::LINUX_CARRIER_MAINT_ROOT_BASE,
            crate::memory::LINUX_CARRIER_MAINT_ROOT_SIZE,
        ),
    ] {
        let size = usize::try_from(size).unwrap();
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            size,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .unwrap();
        let host_addr = host.as_ptr();
        let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut lease = GlobalFrameStage2Lease::fixed(start, size as u64);
        lease.drop_backing_audit = Some((host_addr as usize, std::sync::Arc::clone(&observed)));
        let mut region = mapped_region(start, start + size as u64, start);
        region.host_addr = host_addr;
        region.host_mapping = Some(host);
        region.stage2_lease = Some(lease);
        task_mappings.insert(region);
        drop_observations.push((host_addr as usize, observed));
    }
    assert_eq!(
        task_mappings
            .iter()
            .filter(|mapping| mapping_belongs_to_task_inventory(true, mapping))
            .count(),
        1,
        "Kernel MM inventory must never acquire carrier control extents"
    );

    let authority = PersistentCarrierMappings::extract(
        &mut task_mappings,
        std::sync::Arc::new(CarrierVmCustody::new_live_fixture()),
    )
    .expect("extract exact carrier mapping authority");
    assert_eq!(
        task_mappings.len(),
        1,
        "task retains only its own image mapping"
    );
    let worker = std::sync::Arc::new(authority);
    let factory = std::sync::Arc::clone(&worker);
    drop(task_mappings);

    let mailbox = worker
        .host_pointer(
            crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            carrick_aarch64::mailbox::AARCH64_SYSCALL_MAILBOX_SIZE as usize,
        )
        .expect("terminal task cleanup cannot invalidate a live worker mailbox");
    // SAFETY: the carrier authority owns the complete mailbox mapping.
    unsafe { mailbox.as_ptr().write_volatile(0x5a) };
    drop(worker);
    assert!(
        drop_observations
            .iter()
            .all(|(host, _)| alias_backing_is_live(*host))
    );

    drop(factory);
    assert!(drop_observations.iter().all(|(host, observed)| {
        observed.load(std::sync::atomic::Ordering::SeqCst) && !alias_backing_is_live(*host)
    }));
}

#[test]
fn persistent_carrier_mapping_drop_after_exact_custody_destroy_skips_live_unmap() {
    let custody = std::sync::Arc::new(CarrierVmCustody::new_live_fixture());
    let start = crate::memory::LINUX_EL0_TRAMPOLINE_BASE;
    let mut mapping = mapped_region(
        start,
        start + crate::memory::LINUX_EL0_TRAMPOLINE_SIZE,
        start,
    );
    mapping.physical_ipa = start;
    mapping.physical_size = usize::try_from(crate::memory::LINUX_EL0_TRAMPOLINE_SIZE).unwrap();
    let authority = PersistentCarrierMappings {
        mappings: TaskMappingIndex::from_region(mapping),
        custody: std::sync::Arc::clone(&custody),
        vm_destroyed_after_custody_commit: std::sync::atomic::AtomicBool::new(false),
    };

    destroy_vm_with_custody_using(&custody, "terminal carrier mapping fixture", || 0, || {})
        .expect("exact custody destroy commits");
    authority
        .mark_vm_destroyed_after_custody_commit()
        .expect("only the exact terminal custody may disarm live unmap");

    // A raw no-lease mapping would call hv_vm_unmap here. The exact
    // destroy receipt must instead make Drop release only its host owner;
    // an unsigned host test has no VM, so a stray unmap aborts the test.
    drop(authority);
}

#[test]
fn persistent_worker_invariant_configuration_is_complete_and_audited() {
    let mailbox_sp = crate::memory::LINUX_SYSCALL_MAILBOX_BASE;
    let mut registers = std::collections::HashMap::new();
    configure_persistent_executor_invariant_registers(|register, value| {
        registers.insert(register, value);
        Ok(())
    })
    .expect("fake executor invariant configuration");
    registers.insert(PersistentExecutorInvariantRegister::SpEl1, mailbox_sp);

    audit_persistent_executor_invariant_registers(
        |register| Ok(*registers.get(&register).unwrap_or(&0)),
        mailbox_sp,
    )
    .expect("complete fake executor invariant image");

    for value in registers.values_mut() {
        *value ^= 0x55aa_0000;
    }
    restore_persistent_executor_invariant_registers(
        |register, value| {
            registers.insert(register, value);
            Ok(())
        },
        mailbox_sp,
    )
    .expect("detach restores every executor-local invariant");
    audit_persistent_executor_invariant_registers(
        |register| Ok(*registers.get(&register).unwrap_or(&0)),
        mailbox_sp,
    )
    .expect("restored fake executor invariant image");

    for missing in PERSISTENT_EXECUTOR_INVARIANT_REGISTERS {
        let mut partial = registers.clone();
        partial.remove(&missing);
        assert!(
            audit_persistent_executor_invariant_registers(
                |register| {
                    partial.get(&register).copied().ok_or_else(|| {
                        TrapError::Hypervisor(format!("fake executor omitted {register:?}"))
                    })
                },
                mailbox_sp,
            )
            .is_err(),
            "missing {missing:?} must fail closed",
        );
    }

    let factory = include_str!("../trap.rs")
        .split("pub(crate) fn from_persistent_executor_spec")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub(crate) fn audit_persistent_executor_idle")
                .next()
        })
        .expect("persistent factory body");
    let configure = factory
        .find("Self::configure_executor_invariants(&vcpu)")
        .expect("factory configures the fresh owner-thread vCPU");
    let allocate = factory
        .find("Self::allocate_persistent_mailbox_for_vcpu")
        .expect("factory binds executor-local SP_EL1");
    let audit = factory
        .find("Self::audit_executor_invariants(&vcpu, mailbox.slot().guest_address())")
        .expect("factory audits invariants and mailbox SP before publication");
    assert!(configure < allocate && allocate < audit);
}
