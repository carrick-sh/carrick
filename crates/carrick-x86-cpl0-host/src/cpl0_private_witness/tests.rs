use super::*;
#[test]
fn private_mm_cpu_evidence_uses_each_actual_settled_caller() {
    let mut witness = PrivateAnonymousWitness::default();
    witness
        .record(
            CpuId::new(0),
            (7, 0x1000, 1, 4),
            1,
            &[(0x8000, 0x20000, 19)],
            PeerActivity(false),
        )
        .unwrap();
    witness
        .record(
            CpuId::new(1),
            (8, 0x3000, 1, 4),
            2,
            &[(0x8000, 0x24000, 20)],
            PeerActivity(true),
        )
        .unwrap();
    assert_eq!(
        witness
            .rows()
            .iter()
            .map(|row| row.cpu_mask)
            .collect::<Vec<_>>(),
        [1, 2]
    );
}

#[test]
fn cpu_evidence_accumulates_real_migration_without_duplicating_pages() {
    let mut witness = PrivateAnonymousWitness::default();
    let key = (7, 0x1000, 1, 4);
    let leaves = [(0x8000, 0x20000, 19)];
    witness
        .record(CpuId::new(0), key, 1, &leaves, PeerActivity(false))
        .unwrap();
    witness
        .record(CpuId::new(1), key, 2, &leaves, PeerActivity(false))
        .unwrap();
    assert_eq!(witness.rows()[0].cpu_mask, 3);
    assert_eq!(witness.rows()[0].private_pages, 1);
    assert_eq!(witness.private_pages(), 1);
    assert_eq!(witness.peer_active_private_grants(), 0);
}

#[test]
fn an_unrepresentable_cpu_cannot_publish_partial_evidence() {
    let mut witness = PrivateAnonymousWitness::default();
    assert!(
        witness
            .record(
                CpuId::new(64),
                (7, 0x1000, 1, 4),
                1,
                &[(0x8000, 0x20000, 19)],
                PeerActivity(true)
            )
            .is_err()
    );
    assert!(witness.rows().is_empty());
    assert_eq!(witness.peer_active_private_grants(), 0);
}

#[test]
fn actual_peer_samples_and_repeated_settlement_count_one_grant() {
    let actual = AtomicU32::new(0);
    let selected = PeerActivity::observe(&actual);
    actual.store(1, Ordering::Release);
    let settled = PeerActivity::observe(&actual);
    let mut witness = PrivateAnonymousWitness::default();
    let key = (7, 0x1000, 1, 4);
    let leaves = [(0x8000, 0x20000, 19)];
    witness
        .record(CpuId::new(0), key, 1, &leaves, selected.combine(settled))
        .unwrap();
    witness
        .record(CpuId::new(0), key, 1, &leaves, settled)
        .unwrap();
    assert_eq!(witness.rows()[0].private_pages, 1);
    assert_eq!(witness.private_pages(), 1);
    assert_eq!(witness.peer_active_private_grants(), 1);
}

#[test]
fn two_mms_same_va_retain_distinct_private_physical_proof() {
    let mut witness = PrivateAnonymousWitness::default();
    witness
        .record(
            CpuId::new(0),
            (7, 0x1000, 1, 4),
            1,
            &[(0x8000, 0x20000, 19)],
            PeerActivity(false),
        )
        .unwrap();
    witness
        .record(
            CpuId::new(0),
            (8, 0x3000, 1, 4),
            2,
            &[(0x8000, 0x24000, 20)],
            PeerActivity(true),
        )
        .unwrap();
    assert_eq!(witness.rows().len(), 2);
    assert_eq!(
        witness.rows().iter().map(|r| r.private_pages).sum::<u64>(),
        2
    );
    assert_eq!(witness.cross_mm_private_aliases(), 0);
    assert_eq!(witness.peer_active_private_grants(), 1);
}
#[test]
fn duplicate_physical_frame_across_mms_is_rejected_without_partial_row() {
    let mut witness = PrivateAnonymousWitness::default();
    witness
        .record(
            CpuId::new(0),
            (7, 0x1000, 1, 4),
            1,
            &[(0x8000, 0x20000, 19)],
            PeerActivity(false),
        )
        .unwrap();
    assert!(
        witness
            .record(
                CpuId::new(0),
                (8, 0x3000, 1, 4),
                2,
                &[(0x9000, 0x24000, 20), (0x8000, 0x20000, 19)],
                PeerActivity(true)
            )
            .is_err()
    );
    assert_eq!(witness.rows().len(), 1);
    assert_eq!(witness.cross_mm_private_aliases(), 1);
    assert_eq!(witness.peer_active_private_grants(), 0);
}
#[test]
fn physical_address_reuse_with_new_frame_identity_is_not_aliasing() {
    let mut witness = PrivateAnonymousWitness::default();
    witness
        .record(
            CpuId::new(0),
            (7, 0x1000, 1, 4),
            1,
            &[(0x8000, 0x20000, 19)],
            PeerActivity(false),
        )
        .unwrap();
    witness
        .record(
            CpuId::new(0),
            (8, 0x3000, 1, 4),
            2,
            &[(0x8000, 0x20000, 21)],
            PeerActivity(false),
        )
        .unwrap();
    assert_eq!(witness.rows().len(), 2);
}

/// The physical inventory row of the one settled grant, as the
/// production inventory reports it to the witness.
struct SettledInventory(carrick_mmu_core::x86::descriptor_txn::BackingIdentity);
impl carrick_hal::PhysicalFrameInventory for SettledInventory {
    fn bind(
        &self,
        _owner: carrick_hal::GuestFrameOwner,
    ) -> std::sync::Arc<dyn carrick_hal::FrameCowAuthority> {
        std::sync::Arc::new(SettledRow(self.0))
    }
    fn allocate_backing_ids(
        &self,
    ) -> Result<
        (carrick_hal::FrameId, carrick_hal::MappingId),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Err("unused".into())
    }
    fn retire_mm(
        &self,
        _mm: carrick_guest_arch::MmGeneration,
    ) -> Result<usize, carrick_hal::MmRetireBroken> {
        Err(carrick_hal::MmRetireBroken::new("unused"))
    }
    fn frame_is_mapped(&self, _frame: carrick_hal::FrameId) -> bool {
        true
    }
}
struct SettledRow(carrick_mmu_core::x86::descriptor_txn::BackingIdentity);
impl carrick_hal::FrameCowAuthority for SettledRow {
    fn quiesce(
        &self,
    ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
    {
        Err("unused".into())
    }
    fn reserve(
        &self,
        _frames: usize,
        _mappings: usize,
        _events: usize,
    ) -> Result<carrick_hal::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>
    {
        Err("unused".into())
    }
    fn apply(
        &self,
        _commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err("unused".into())
    }
    fn mapping_is_live(
        &self,
        _mapping: carrick_hal::MappingId,
        _frame: carrick_hal::FrameId,
        _gpa: carrick_guest_mem::Gpa,
        _length: carrick_hal::FrameLength,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Err("unused".into())
    }
    fn frame_mapping_count(
        &self,
        _frame: carrick_hal::FrameId,
    ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
        Err("unused".into())
    }
    fn mapping_is_live_exact_generation(
        &self,
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        generation: carrick_hal::MappingGeneration,
        gpa: carrick_guest_mem::Gpa,
        length: carrick_hal::FrameLength,
    ) -> bool {
        mapping == carrick_hal::MappingId::from_kernel_allocation(self.0.mapping_id)
            && frame == carrick_hal::FrameId::from_kernel_allocation(self.0.frame_id)
            && generation
                == carrick_hal::MappingGeneration::from_backend_counter(self.0.owner_generation)
            && gpa == carrick_guest_mem::Gpa::new(0x800000)
            && length
                == carrick_hal::FrameLength::from_mapping_extent(
                    std::num::NonZeroU64::new(0x2000).unwrap(),
                )
    }
}

/// Run the production witness over an owner grant that settled after a
/// sibling's fork (`fork_arms`) or with no fork, as the owner-grant
/// settlement calls it.
fn witness_owner_grant(
    fork_arms: bool,
    custody: crate::carrier_memory::SettlementCustody,
) -> (Result<(), carrick_hal::TrapError>, PrivateAnonymousWitness) {
    use crate::carrier_memory::test_support;
    let settled = test_support::owner_grant_settled_after_a_fork(
        || test_support::MemoryTestIo::new(test_support::TestMemoryIo::default()),
        fork_arms,
    );
    let mm = settled.context.mm.raw();
    let window = carrick_el1_abi::PortalGrantWindow {
        operation: carrick_el1_abi::PortalOperation {
            carrier: settled.memory.identity().nonzero(),
            mm: carrick_el1_abi::ReservationMm::new(mm.get()).unwrap(),
            incarnation: settled.context.generation.raw(),
            sequence: std::num::NonZeroU64::MIN,
        },
        mapping_incarnation: carrick_el1_abi::ReservationIncarnation::new(1).unwrap(),
        range: carrick_el1_abi::ReservationRange::new(0x4000, 0x6000).unwrap(),
        protection: carrick_el1_abi::ReservationProtection::READ_WRITE,
        fault_page: 0x4000,
        host_backing: None,
        fork_sequence: None,
    };
    let inventory = SettledInventory(settled.backing);
    let mut witness = PrivateAnonymousWitness::default();
    let recorded = witness.record_settled(SettledPrivateGrant {
        cpu: CpuId::new(0),
        memory: &settled.memory,
        inventory: &inventory,
        binding: carrick_el1_abi::ExecutionBinding {
            task: carrick_el1_abi::EntryTaskKey::from_raw(41),
            generation: carrick_el1_abi::SnapshotGeneration::from_raw(11),
            mm: carrick_el1_abi::EntryMmKey::from_raw(mm.get()),
            thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(101),
        },
        context: settled.context,
        window,
        txn: &settled.wire,
        publication: settled.publication,
        custody,
        peer: PeerActivity(true),
    });
    (recorded, witness)
}

/// The witness's own control: with no fork, the owner grant's two
/// settled leaves are authenticated.
#[test]
fn an_owner_grant_settled_with_no_fork_is_witnessed() {
    let (recorded, witness) = witness_owner_grant(
        false,
        crate::carrier_memory::SettlementCustody::EditorReleased,
    );
    recorded.unwrap();
    assert_eq!(witness.private_pages(), 2);
}

/// #3153: a sibling thread's vfork (served as a copy-on-write fork) arms
/// a reader's freshly granted leaves after the ring released the editor
/// and before the host settles the grant. `CarrierMemory::publish`
/// accepts those leaves (#3151); the witness killed the carrier on them
/// ("private witness terminal/backing mismatch", exit 125, 3/40 under
/// load), though they keep the grant's frame and identity.
#[test]
fn an_owner_grant_a_fork_armed_before_settlement_is_witnessed() {
    let (recorded, witness) = witness_owner_grant(
        true,
        crate::carrier_memory::SettlementCustody::EditorReleased,
    );
    recorded.unwrap();
    assert_eq!(witness.private_pages(), 2);
    assert_eq!(witness.cross_mm_private_aliases(), 0);
}

/// With the editor held through settlement no fork could have armed the
/// leaves, so an armed leaf is still a broken guest.
#[test]
fn an_armed_leaf_under_a_held_editor_is_still_a_mismatch() {
    let (recorded, witness) =
        witness_owner_grant(true, crate::carrier_memory::SettlementCustody::EditorHeld);
    let error = recorded.unwrap_err();
    assert!(
        format!("{error:?}").contains("private witness terminal/backing mismatch"),
        "{error:?}"
    );
    assert_eq!(witness.private_pages(), 0);
}
