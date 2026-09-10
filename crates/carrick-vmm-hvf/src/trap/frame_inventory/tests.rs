//! # Frame Inventory Backend Tests

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use super::*;
use crate::trap::frame_inventory_backend_tests::*;

/// Two live containers in one carrier must never share private alias
/// ownership.
///
/// Before `ContainerRoot`, `alias_ownership_scope` fell back to a single
/// `Root` variant whenever `mm_root_slot` was `None`, and
/// `alias_matches_process_scope` matched it with `mm_root_slot.is_none()`.
/// `None` is the default in `HvfTaskState::neutral()`, and a later
/// container's root is built through the carrier REUSE lane which leaves it
/// `None` — so both containers matched every `Root`-scoped alias and each
/// treated the other's private aliases as its own. The guest symptom was a
/// deterministic SIGSEGV writing `LINUX_MMAP_BASE + 8`, a level-1
/// translation fault, on whichever container lost.
///
/// This binds the discriminator. Collapse `ContainerRoot` back to a single
/// variant, or compare without the token, and the cross-container
/// assertions below fail.
#[test]
fn private_alias_scopes_never_collide_across_carrier_containers() {
    let alpha = ContainerRootToken::next();
    let beta = ContainerRootToken::next();
    assert_ne!(alpha, beta, "each container root mints a distinct token");
    assert_ne!(
        alpha,
        ContainerRootToken::ROOT,
        "a minted token must never alias the ROOT sentinel"
    );

    let alpha_scope = alias_ownership_scope(GuestMappingSharing::Private, None, alpha);
    let beta_scope = alias_ownership_scope(GuestMappingSharing::Private, None, beta);
    assert_ne!(
        alpha_scope, beta_scope,
        "two containers on the carrier reuse lane (mm_root_slot = None) must \
             not share one private ownership scope"
    );

    // The cross-container half: alpha's alias must not be claimed by beta.
    assert!(
        alias_matches_process_scope(alpha_scope, None, alpha),
        "a container owns its own private aliases"
    );
    assert!(
        !alias_matches_process_scope(alpha_scope, None, beta),
        "a container must NOT own a sibling's private aliases"
    );
    assert!(
        !alias_matches_process_scope(beta_scope, None, alpha),
        "ownership is not symmetric-by-accident either"
    );

    // Shared-file aliases stay VM-global and are unaffected.
    let global = alias_ownership_scope(GuestMappingSharing::GlobalShared, None, alpha);
    assert_eq!(global, AliasOwnershipScope::Global);
    assert!(alias_matches_process_scope(global, None, beta));
}

fn predecessor_test_identity(task: &HvfTaskState) -> (carrick_hal::ExecPredecessorIdentity, u64) {
    let cow = task.cow_identity.expect("fixture COW identity");
    (
        carrick_hal::ExecPredecessorIdentity {
            task_serial: u64::try_from(cow.linux_pid).unwrap(),
            thread_serial: u64::try_from(cow.linux_tid).unwrap(),
            linux_pid: cow.linux_pid,
            linux_tid: cow.linux_tid,
            mm: cow.mm,
            asid: cow.asid,
        },
        cow.mm,
    )
}

#[test]
fn bootstrap_exec_predecessor_uses_bound_kernel_identity_without_registration() {
    let mut task = hvpatch_task_state_test_fixture(31, 0x4000, 31);
    let (identity, _) = predecessor_test_identity(&task);
    assert!(task.registration.is_none());
    bind_exec_predecessor_identity_slot(&mut task.pending_exec_predecessor_identity, identity)
        .expect("bind bootstrap predecessor identity");
    let mut duplicate = identity;
    duplicate.thread_serial += 1;
    assert!(
            bind_exec_predecessor_identity_slot(
                &mut task.pending_exec_predecessor_identity,
                duplicate,
            )
            .is_err()
        );
    assert_eq!(
        task.pending_exec_predecessor_identity,
        Some(identity),
        "duplicate bind must not replace the first exact identity",
    );

    let observed = task
        .take_exec_predecessor_identity(task.cow_identity.unwrap())
        .expect("bound bootstrap predecessor identity");
    assert_eq!(observed, identity);
    assert!(task.pending_exec_predecessor_identity.is_none());
}

#[test]
fn exec_predecessor_accepts_current_kernel_identity_over_stale_registration_birth_fields() {
    let (mut task, current_kernel, current_cow) = exec_predecessor_authority_test_fixture();
    assert_eq!(
        task.take_exec_predecessor_identity(current_cow)
            .expect("current Kernel/COW authority outranks stale registration birth fields"),
        current_kernel,
    );
}

#[test]
fn exec_predecessor_rejects_registration_cow_backend_identity_mismatch() {
    let (mut task, _, current_cow) = exec_predecessor_authority_test_fixture();
    task.registration
        .as_mut()
        .expect("fixture registration")
        .cow_identity
        .as_mut()
        .expect("fixture registered COW identity")
        .linux_tid += 1;

    let error = task
        .take_exec_predecessor_identity(current_cow)
        .expect_err("foreign backend COW identity must fail closed");
    assert!(matches!(
        error,
        TrapError::Hypervisor(message)
            if message == "HVPatch exec predecessor registration/COW identity mismatch"
    ));
}

#[test]
fn exec_predecessor_rejects_each_retained_authority_anchor_mismatch() {
    const KERNEL_REGISTRATION: &str =
        "HVPatch exec predecessor Kernel/registration identity mismatch";
    const REGISTRATION_COW: &str = "HVPatch exec predecessor registration/COW identity mismatch";
    const KERNEL_COW: &str = "HVPatch exec predecessor Kernel/COW identity mismatch";

    let (mut task, _, cow) = exec_predecessor_authority_test_fixture();
    task.registration
        .as_mut()
        .unwrap()
        .expected_identity
        .task_serial += 1;
    assert_exec_predecessor_mismatch(task, cow, KERNEL_REGISTRATION);

    let (mut task, _, cow) = exec_predecessor_authority_test_fixture();
    task.registration
        .as_mut()
        .unwrap()
        .expected_identity
        .linux_pid += 1;
    assert_exec_predecessor_mismatch(task, cow, KERNEL_REGISTRATION);

    let (mut task, _, cow) = exec_predecessor_authority_test_fixture();
    task.pending_exec_predecessor_identity
        .as_mut()
        .unwrap()
        .linux_pid += 1;
    task.registration
        .as_mut()
        .unwrap()
        .expected_identity
        .linux_pid += 1;
    assert_exec_predecessor_mismatch(task, cow, KERNEL_COW);

    let (mut task, _, cow) = exec_predecessor_authority_test_fixture();
    task.pending_exec_predecessor_identity.as_mut().unwrap().mm += 1;
    assert_exec_predecessor_mismatch(task, cow, KERNEL_COW);

    let (mut task, _, cow) = exec_predecessor_authority_test_fixture();
    task.pending_exec_predecessor_identity
        .as_mut()
        .unwrap()
        .asid += 1;
    assert_exec_predecessor_mismatch(task, cow, KERNEL_COW);

    for mutate in [
        |identity: &mut carrick_hal::FrameCowIdentity| identity.linux_pid += 1,
        |identity: &mut carrick_hal::FrameCowIdentity| identity.linux_tid += 1,
        |identity: &mut carrick_hal::FrameCowIdentity| identity.mm += 1,
        |identity: &mut carrick_hal::FrameCowIdentity| identity.asid += 1,
    ] {
        let (mut task, _, cow) = exec_predecessor_authority_test_fixture();
        mutate(
            task.registration
                .as_mut()
                .unwrap()
                .cow_identity
                .as_mut()
                .unwrap(),
        );
        assert_exec_predecessor_mismatch(task, cow, REGISTRATION_COW);
    }

    let (mut task, _, cow) = exec_predecessor_authority_test_fixture();
    task.registration.as_mut().unwrap().cow_identity = None;
    assert_exec_predecessor_mismatch(task, cow, REGISTRATION_COW);
}

fn assert_exec_predecessor_mismatch(
    mut task: HvfTaskState,
    current_cow: carrick_hal::FrameCowIdentity,
    expected: &str,
) {
    let error = task
        .take_exec_predecessor_identity(current_cow)
        .expect_err("foreign predecessor authority must fail closed");
    assert!(matches!(
        error,
        TrapError::Hypervisor(message) if message == expected
    ));
}

fn exec_predecessor_authority_test_fixture() -> (
    HvfTaskState,
    carrick_hal::ExecPredecessorIdentity,
    carrick_hal::FrameCowIdentity,
) {
    let mut task = hvpatch_task_state_test_fixture(200, 0x4000, 73);
    let current_cow = carrick_hal::FrameCowIdentity {
        linux_pid: 41,
        // This field is paired to the persistent backend/kicker ThreadId;
        // nonleader exec may promote the current Kernel Linux TID to 41
        // while this backend identity remains 73.
        linux_tid: 73,
        mm: 200,
        asid: 8,
    };
    task.cow_identity = Some(current_cow);
    let directory = std::sync::Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let (_, child_token_verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    task.registration = Some(HvpatchTaskRegistration {
        directory: std::sync::Arc::clone(&directory),
        key: HvpatchCarrierTaskStateKey {
            directory_instance: directory.instance,
            task_serial: 41,
            thread_serial: 73,
            execution_generation: 1,
            nonce: std::num::NonZeroU64::new(1).unwrap(),
        },
        expected_identity: HvpatchCarrierTaskIdentity {
            task_serial: 41,
            thread_serial: 73,
            execution_generation: 1,
            linux_pid: 41,
            linux_tid: 73,
            asid: 7,
        },
        foreign_mm_registration: None,
        task_mm: None,
        cow_authority: None,
        cow_identity: Some(current_cow),
        cow_authority_identity: None,
        child_token_verifier,
    });
    let current_kernel = carrick_hal::ExecPredecessorIdentity {
        task_serial: 41,
        thread_serial: 99,
        linux_pid: 41,
        linux_tid: 41,
        mm: 200,
        asid: 8,
    };
    bind_exec_predecessor_identity_slot(
        &mut task.pending_exec_predecessor_identity,
        current_kernel,
    )
    .expect("bind current Kernel predecessor identity");
    (task, current_kernel, current_cow)
}

// global_frame_allocator_test_lock rehomed to trap.rs stub

fn register_carrier_lease(mut lease: GlobalFrameStage2Lease, host_addr: usize) -> (u64, u64) {
    let key = lease.key();
    lease.mark_test_mapped_without_backend();
    let owners = std::collections::BTreeMap::from([(key, host_addr)]);
    let identities = register_carrier_stage2_leases(
        legacy_test_carrier_vm_custody_arc(),
        &mut vec![lease],
        &owners,
    )
    .unwrap();
    assert_eq!(identities.len(), 1);
    assert_eq!(
        legacy_test_carrier_vm_custody_arc()
            .stage2_record_snapshot(identities[0].record_id)
            .map(|snapshot| (snapshot.ipa, snapshot.len as u64)),
        Some(key)
    );
    key
}

enum TestFrameMappingCount {
    Exact(usize),
    ExactButMappingNotLive(usize),
    Error,
}

impl carrick_hal::FrameCowAuthority for TestFrameMappingCount {
    fn quiesce(
        &self,
    ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
    {
        Ok(Box::new(()))
    }

    fn reserve(
        &self,
        _frame_candidates: usize,
        _mapping_candidates: usize,
        _event_count: usize,
    ) -> Result<carrick_hal::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>
    {
        Err(Box::new(std::io::Error::other("unused test reserve")))
    }

    fn apply(
        &self,
        _commit: carrick_hal::FrameInventoryCommit<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Err(Box::new(std::io::Error::other("unused test apply")))
    }

    fn mapping_is_live(
        &self,
        _mapping: carrick_hal::MappingId,
        _frame: carrick_hal::FrameId,
        _gpa: carrick_guest_mem::Gpa,
        _length: carrick_hal::FrameLength,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(!matches!(self, Self::ExactButMappingNotLive(_)))
    }

    fn frame_mapping_count(
        &self,
        _frame: carrick_hal::FrameId,
    ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::Exact(count) | Self::ExactButMappingNotLive(count) => Ok(Some(*count)),
            Self::Error => Err(Box::new(std::io::Error::other(
                "injected mapping-count failure",
            ))),
        }
    }
}

fn exec_mapping_for_order(guest_start: u64, mapped_size: u64) -> GuestMapping {
    GuestMapping {
        guest_start,
        ipa_start: guest_start,
        mapped_size,
        offset_in_mapping: 0,
        payload_size: 0,
        perms: carrick_mem::elf::SegmentPerms::default(),
        shared: false,
        image: std::sync::Arc::new(Vec::new()),
        private_file_backing: None,
    }
}

fn id(raw: u64) -> std::num::NonZeroU64 {
    std::num::NonZeroU64::new(raw).unwrap()
}

fn empty_inventory_reservation(raw: u64) -> carrick_hal::FrameInventoryReservation {
    let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(id(raw));
    let capacity = carrick_hal::FrameEventCapacity::for_event_count(1).unwrap();
    carrick_hal::FrameInventoryReservation::from_kernel_candidates(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([raw as u8; 32]),
        carrick_hal::FrameInventoryBatch::prepare(transaction, capacity).unwrap(),
        Vec::new(),
        Vec::new(),
    )
}

fn inventory_pair(
    raw: u64,
) -> (
    carrick_hal::FrameInventoryReservation,
    carrick_hal::FrameInventoryReservation,
) {
    (
        empty_inventory_reservation(raw),
        empty_inventory_reservation(raw + 1),
    )
}

#[test]
fn cancelled_process_inventory_does_not_poison_the_next_fork() {
    let ledger = std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let state = HvpatchFrameInventoryState::new(std::sync::Arc::clone(&ledger));

    state
        .begin_process_inventory(empty_inventory_reservation(91))
        .expect("first reservation");
    assert!(state.cancel_process_inventory());
    state
        .begin_process_inventory(empty_inventory_reservation(92))
        .expect("retry after an EFAULT/build/spawn failure");
    assert!(state.cancel_process_inventory());
    assert!(ledger.lock().process_reservation.is_none());
}

/// A guest `mmap` whose alias install fails used to `abort()` the carrier —
/// killing every Linux process multiplexed into it — precisely because the
/// reservation `begin_alias_inventory` armed had nowhere to go: returning
/// ENOMEM instead would have left it armed and wedged the NEXT guest mmap
/// with "overlapping HVPatch alias inventory transaction". Prove the
/// rollback seam actually clears the staging, from BOTH states a failure can
/// leave: the untouched reservation (`add_alias_with_sharing` returned
/// early) and the staged commit (stage-1 `map_aliased` failed after stage-2
/// succeeded).
#[test]
fn abandoned_alias_inventory_does_not_poison_the_next_guest_mmap() {
    let ledger = std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let state = HvpatchFrameInventoryState::new(std::sync::Arc::clone(&ledger));

    // Failure BEFORE the backend consumed the reservation.
    state
        .begin_alias_inventory(empty_inventory_reservation(81))
        .expect("first alias reservation");
    // Red without the seam: a second arm is refused while staging is live.
    state
        .begin_alias_inventory(empty_inventory_reservation(82))
        .expect_err("overlapping alias inventory must be refused");
    assert!(state.cancel_alias_inventory());
    assert!(ledger.lock().alias_reservation.is_none());
    state
        .begin_alias_inventory(empty_inventory_reservation(83))
        .expect("the mmap after a failed alias install must still arm");

    // Failure AFTER the backend staged its commit (stage-1 unwind path).
    {
        let mut inventory = ledger.lock();
        let reservation = inventory
            .alias_reservation
            .take()
            .expect("armed reservation");
        inventory.alias_commit = Some(reservation.commit(()));
    }
    state
        .begin_alias_inventory(empty_inventory_reservation(84))
        .expect_err("a staged commit must also block a second arm");
    assert!(state.cancel_alias_inventory());
    assert!(ledger.lock().alias_commit.is_none());
    state
        .begin_alias_inventory(empty_inventory_reservation(85))
        .expect("the mmap after a failed stage-1 publication must still arm");
    assert!(state.cancel_alias_inventory());
    assert!(!state.cancel_alias_inventory());
}

#[test]
fn parent_arm_rollback_restores_preexisting_overlapping_ranges_exactly() {
    let broad = carrick_aarch64::vmm::ForkCowRange {
        va: 0x4000_0000,
        len: 0x20_000,
        executable: false,
        kernel_only: false,
        granule: carrick_aarch64::vmm::CowGranule::Compound,
    };
    let exact = carrick_aarch64::vmm::ForkCowRange {
        va: 0x4000_8000,
        len: 0x4000,
        executable: false,
        kernel_only: false,
        granule: carrick_aarch64::vmm::CowGranule::Compound,
    };
    let mut armed = CowArmedRanges::default();
    armed.arm(&[broad]);
    let before = armed.snapshot();

    armed.arm(&[exact]);
    armed.disarm_ranges(&[exact]);
    assert_ne!(
        armed.ranges, before,
        "the old range-subtraction rollback is lossy"
    );

    armed.restore(before.clone());
    assert_eq!(armed.ranges, before);
}

#[test]
fn global_frame_allocator_reuses_only_released_exact_extents() {
    let mut allocator = GlobalFrameIpaAllocator::new();
    let first = allocator.allocate(0x4000, 0x4000).unwrap();
    let second = allocator.allocate(0x4000, 0x4000).unwrap();
    assert_ne!(first, second, "live frame IPAs must remain globally unique");

    allocator.release(first, 0x4000).unwrap();
    assert_eq!(
        allocator.allocate(0x4000, 0x4000).unwrap(),
        first,
        "an IPA becomes reusable only after its exact frame extent retires"
    );
}

#[test]
fn global_frame_allocator_coalesces_adjacent_retired_extents() {
    let mut allocator = GlobalFrameIpaAllocator::new();
    let first = allocator.allocate(0x4000, 0x4000).unwrap();
    let second = allocator.allocate(0x4000, 0x4000).unwrap();
    allocator.release(second, 0x4000).unwrap();
    allocator.release(first, 0x4000).unwrap();

    assert_eq!(
        allocator.allocate(0x8000, 0x4000).unwrap(),
        first,
        "adjacent retired global IPA extents must form reusable capacity"
    );
}

#[test]
fn global_frame_allocator_rejects_duplicate_or_partial_release() {
    let mut allocator = GlobalFrameIpaAllocator::new();
    let frame = allocator.allocate(0x8000, 0x4000).unwrap();
    assert!(allocator.release(frame, 0).is_err());
    assert!(
        allocator
            .release(
                carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE - 0x4000,
                0x4000,
            )
            .is_err()
    );
    assert!(
        allocator
            .release(
                carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE
                    + carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE,
                0x4000,
            )
            .is_err()
    );
    assert!(allocator.release(frame, 0x4000).is_err());
    allocator.release(frame, 0x8000).unwrap();
    assert!(allocator.release(frame, 0x8000).is_err());
}

#[test]
fn global_frame_allocator_honors_large_frame_alignment() {
    const TWO_MIB: u64 = 2 * 1024 * 1024;
    let mut allocator = GlobalFrameIpaAllocator::new();
    let _prefix = allocator.allocate(0x4000, 0x4000).unwrap();
    let large = allocator.allocate(TWO_MIB, TWO_MIB).unwrap();
    assert_eq!(large % TWO_MIB, 0);
}

#[test]
fn global_frame_allocator_rejects_invalid_allocation_arithmetic() {
    let mut allocator = GlobalFrameIpaAllocator::new();
    assert!(allocator.allocate(0x4000, 0).is_err());
    assert!(allocator.allocate(u64::MAX, 0x4000).is_err());
    assert!(
        allocator
            .release(
                carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE,
                u64::MAX,
            )
            .is_err()
    );
}

#[test]
fn fixed_identity_stage2_retirement_does_not_release_global_allocator() {
    assert!(release_retired_stage2_ipa(0x1_0000_0000, 0x70_0000).is_ok());
}

#[test]
fn global_frame_allocator_preserves_large_hole_for_large_request() {
    const LARGE: u64 = 32 * 1024 * 1024 * 1024;
    const SMALL: u64 = 0x4000;
    let arena_base = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE;
    let mut allocator = GlobalFrameIpaAllocator::new();
    allocator.next = arena_base + carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_SIZE;
    allocator.free = vec![(arena_base, LARGE), (arena_base + LARGE + SMALL, SMALL)];

    assert_eq!(
        allocator.allocate(SMALL, SMALL).unwrap(),
        arena_base + LARGE + SMALL,
        "a tiny mapping must consume the smallest fitting hole"
    );
    assert_eq!(
        allocator.allocate(LARGE, 2 * 1024 * 1024).unwrap(),
        arena_base,
        "small mappings must not fragment the scarce 32 GiB exec-frame holes"
    );
}

#[test]
fn global_frame_exec_omits_sparse_mmap_arena_and_reserves_large_extents_first() {
    let mappings = vec![
        exec_mapping_for_order(0x10_0000, 0x4000),
        exec_mapping_for_order(crate::memory::LINUX_PAGE_TABLES_BASE, 0x20_0000),
        exec_mapping_for_order(
            crate::memory::LINUX_MMAP_BASE,
            crate::memory::mmap_arena_size(),
        ),
        exec_mapping_for_order(0x0090_0000_0000, 2 * 1024 * 1024 * 1024),
    ];

    assert_eq!(
        global_frame_exec_lease_order(&mappings, 1),
        vec![1, 3, 0],
        "the hidden semantic mmap arena must consume no exec frame; backed extents remain size-ordered"
    );
}

fn root_exec_test_plan() -> GuestMappingPlan {
    let mut data = exec_mapping_for_order(0x20_0000, 0x20_000);
    data.perms = carrick_mem::elf::SegmentPerms {
        read: true,
        write: true,
        execute: false,
    };
    let mut page_tables = exec_mapping_for_order(
        crate::memory::LINUX_PAGE_TABLES_BASE,
        crate::memory::LINUX_PAGE_TABLES_SIZE,
    );
    page_tables.image = std::sync::Arc::new(carrick_mem::memory::stage1_hvpatch_page_tables());
    page_tables.payload_size = page_tables.image.len() as u64;
    let sparse = exec_mapping_for_order(
        crate::memory::LINUX_MMAP_BASE,
        crate::memory::mmap_arena_size(),
    );
    GuestMappingPlan {
        mappings: vec![data, page_tables, sparse],
        entry: 0x20_0000,
        initial_stack_pointer: None,
        el0_trampoline_entry: None,
        el1_vectors_base: None,
        stage1_page_tables_base: Some(crate::memory::LINUX_PAGE_TABLES_BASE),
        ro_spans: vec![carrick_mem::elf::RoSpan {
            start: 0x20_4000,
            len: 0x4000,
            exec: false,
        }],
    }
}

#[test]
fn root_exec_plan_owns_every_materialized_stage2_extent() {
    let plan = root_exec_test_plan();
    let GlobalExecPlan {
        plan: rebuilt,
        mut stage2_leases,
    } = prepare_global_exec_plan(&plan, None).unwrap();
    for mapping in rebuilt
        .mappings
        .iter()
        .filter(|mapping| !is_sparse_hvpatch_mmap_mapping(mapping))
    {
        let key = (mapping.ipa_start, mapping.mapped_size);
        let lease = stage2_leases
            .remove(&key)
            .unwrap_or_else(|| panic!("root exec mapping {key:x?} lost its stage-2 lease"));
        assert_eq!(lease.key(), key);
        assert!(
            lease.release_ipa,
            "replacement root frames are allocator-owned"
        );
        assert_ne!(
            mapping.ipa_start, mapping.guest_start,
            "root exec must not collide with identity frames retained by a child"
        );
    }
    assert!(stage2_leases.is_empty());
}

#[test]
fn consecutive_root_exec_plans_reserve_disjoint_frame_generations() {
    let plan = root_exec_test_plan();
    let first = prepare_global_exec_plan(&plan, None).unwrap();
    let second = prepare_global_exec_plan(&plan, None).unwrap();
    let first_keys = first.stage2_leases.keys().copied().collect::<Vec<_>>();
    let second_keys = second.stage2_leases.keys().copied().collect::<Vec<_>>();

    assert!(
        first_keys
            .iter()
            .all(|first| second_keys.iter().all(|second| first != second)),
        "a successor root image must not reuse a frame still retained by a child or predecessor"
    );
}

/// The exec successor's task authority is preseeded with its new
/// `MmAccessState`, so executor activation does not run the lazy
/// task-only structural-owner installer. The exec publication itself must
/// therefore put the fixed root-slot backing under structural custody;
/// publishing it as an ordinary global frame leaves terminal retirement
/// with the right numeric slot but no exact root proof.
#[test]
fn exec_successor_root_publication_installs_exact_structural_authority() {
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let custody = std::sync::Arc::new(CarrierVmCustody::new_live_fixture());
    let root_slot = (0x7ee0_0000_0000_u64, 0x20_0000_u64);
    let mut mapping = exec_mapping_for_order(
        crate::memory::LINUX_PAGE_TABLES_BASE,
        crate::memory::LINUX_PAGE_TABLES_SIZE,
    );
    mapping.ipa_start = root_slot.0;
    let mut region =
        prepare_exec_region_raw_in(&custody, &mapping).expect("prepare fixed exec root backing");
    let mut lease = GlobalFrameStage2Lease::fixed(root_slot.0, mapping.mapped_size);
    lease.mark_mapped();

    publish_exec_region_host_owner_in(&custody, &mut region, lease, Some(root_slot))
        .expect("publish exec root under structural custody");

    let owner = region
        .structural_owner
        .as_ref()
        .cloned()
        .expect("exec root publication preserves its exact structural owner");
    assert_eq!(owner.physical_ipa, root_slot.0);
    assert_eq!(owner.physical_size as u64, mapping.mapped_size);
    assert!(
        global_frame_host_owner_identity_in(&custody, root_slot.0, mapping.mapped_size).is_none(),
        "fixed root-slot custody must not be hidden in the global-frame directory"
    );

    let access = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        std::sync::Arc::new(MemoryProtections::default()),
        std::sync::Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        std::sync::Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
        std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
    );
    access
        .install_structural_mapping_authority(Some(root_slot), owner)
        .expect("install exec successor's exact root authority");
    let proof = access
        .retire_mm_root_stage2_in(&custody, root_slot)
        .expect("retire exec successor root by exact authority")
        .proof;
    assert_eq!((proof.root_slot_base(), proof.root_slot_size()), root_slot);
}

#[test]
fn retire_initial_mmap_arena_is_idempotent_when_sparse_mapping_absent() {
    // The retirement flag is carrier-scoped, so it outlives any one test in
    // this process. Each of these tests owns it explicitly rather than
    // inheriting whatever a sibling left behind.
    carrier_initial_arena_retired().store(false, std::sync::atomic::Ordering::Release);
    let mut state = HvfTaskState::neutral();
    state.persistent_vm_lifecycle = true;
    // Under persistent VM lifecycle, if the initial eager mmap arena was not mapped
    // (as for subsequent containers in a persistent carrier), retirement is an idempotent Ok(()).
    assert!(state.retire_initial_mmap_arena().is_ok());
}

#[test]
fn second_container_never_unmaps_the_carrier_arena_again() {
    // The unmap inside retirement is VM-wide, but retirement runs during
    // each CONTAINER's root bring-up. A second container reaching it must
    // not unmap again: a sibling container may already have faulted sparse
    // pages into that same arena range, and tearing the range out from
    // under it makes its next access a level-1 translation fault on an
    // address it was legitimately handed.
    //
    // This binds the carrier once-guard. Delete the guard and the second
    // call below walks into the shape validation and unmap path instead of
    // returning early.
    carrier_initial_arena_retired().store(false, std::sync::atomic::Ordering::Release);

    let mut first = HvfTaskState::neutral();
    first.persistent_vm_lifecycle = true;
    assert!(
        first.retire_initial_mmap_arena().is_ok(),
        "first container retires the eager arena"
    );
    assert!(
        carrier_initial_arena_retired().load(std::sync::atomic::Ordering::Acquire),
        "retirement must be recorded at carrier scope, not per container"
    );

    // A second container whose mappings still describe an arena extent: if
    // the guard were absent this would be validated and unmapped a second
    // time. With the guard it returns before touching `mappings` at all.
    let mut second = HvfTaskState::neutral();
    second.persistent_vm_lifecycle = true;
    let mut region = thread_sibling_tests::mapped_region(
        crate::memory::LINUX_MMAP_BASE,
        crate::memory::LINUX_MMAP_BASE + 0x4000,
        crate::memory::LINUX_MMAP_BASE,
    );
    region.physical_size = 0x4000;
    second.mappings.insert(region);
    assert!(
        second.retire_initial_mmap_arena().is_ok(),
        "a later container must skip retirement entirely"
    );
    assert_eq!(
        second.mappings.len(),
        1,
        "the later container's arena mapping must be left untouched"
    );

    carrier_initial_arena_retired().store(false, std::sync::atomic::Ordering::Release);
}

#[test]
fn retire_initial_mmap_arena_rejects_corrupted_shape() {
    // Shape validation applies to the FIRST retirement only: it exists to
    // catch a carrier eager mapping that is present but malformed, and only
    // the first container ever sees that mapping. A later container's arena
    // entries are its own sparse ones and must not be judged against the
    // eager shape — which is why the carrier guard returns before this
    // check for them. Reset the carrier flag so this test is that first
    // caller regardless of sibling test order.
    carrier_initial_arena_retired().store(false, std::sync::atomic::Ordering::Release);
    let mut state = HvfTaskState::neutral();
    state.persistent_vm_lifecycle = true;
    let mut region = thread_sibling_tests::mapped_region(
        crate::memory::LINUX_MMAP_BASE,
        crate::memory::LINUX_MMAP_BASE + 0x4000,
        crate::memory::LINUX_MMAP_BASE,
    );
    region.physical_size = 0x4000;
    state.mappings.insert(region);
    assert!(state.retire_initial_mmap_arena().is_err());
}

#[test]
fn exec_replacement_preserves_canonical_scoped_asid_and_load_barrier_code() {
    let mut input = root_exec_test_plan();
    let mut maintenance = exec_mapping_for_order(
        carrick_mem::memory::LINUX_EL1_MAINT_BASE,
        carrick_mem::memory::LINUX_EL1_MAINT_SIZE,
    );
    maintenance.image = std::sync::Arc::new(carrick_mem::memory::el1_maintenance_bytes());
    maintenance.payload_size = maintenance.image.len() as u64;
    maintenance.perms = carrick_mem::elf::SegmentPerms {
        read: true,
        write: false,
        execute: true,
    };
    input.mappings.push(maintenance);

    let GlobalExecPlan { plan, .. } =
        prepare_global_exec_plan(&input, None).expect("global exec plan");
    let mapping = plan
        .mappings
        .iter()
        .find(|mapping| {
            mapping.guest_start <= carrick_mem::memory::LINUX_EL1_MAINT_BASE
                && mapping.guest_start + mapping.mapped_size
                    >= carrick_mem::memory::LINUX_EL1_MAINT_BASE
                        + carrick_mem::memory::LINUX_EL1_MAINT_SIZE
        })
        .expect("exec kernel mapping contains maintenance image");
    let bytes_at = |address: u64, expected: Vec<u8>| {
        let offset = usize::try_from(address - mapping.guest_start).unwrap();
        assert_eq!(
            &mapping.image[offset..offset + expected.len()],
            expected.as_slice()
        );
    };
    bytes_at(
        carrick_mem::memory::LINUX_EL1_ASID_MAINT_BASE,
        carrick_mem::memory::el1_asid_maintenance_bytes(),
    );
    bytes_at(
        carrick_mem::memory::LINUX_EL1_LOAD_BARRIER_BASE,
        carrick_mem::memory::el1_load_barrier_bytes(),
    );
}

#[test]
fn exec_reuses_carrier_control_stage2_without_allocating_task_leases() {
    let mut input = root_exec_test_plan();
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
        input.mappings.push(exec_mapping_for_order(start, size));
    }

    let GlobalExecPlan {
        plan,
        stage2_leases,
    } = prepare_global_exec_plan(&input, None).expect("global exec plan");
    for mapping in plan
        .mappings
        .iter()
        .filter(|mapping| is_persistent_executor_carrier_guest_mapping(mapping))
    {
        assert_eq!(mapping.ipa_start, mapping.guest_start);
        assert!(
            !stage2_leases.contains_key(&(mapping.ipa_start, mapping.mapped_size)),
            "exec must reuse carrier stage-2 rather than hand it to an MM retirement"
        );
    }
    assert_eq!(
        plan.mappings
            .iter()
            .filter(|mapping| is_persistent_executor_carrier_guest_mapping(mapping))
            .count(),
        5
    );
}

#[test]
fn exec_predecessor_backing_stays_live_until_detached_cleanup() {
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .unwrap();
    let host_addr = host.as_ptr();
    let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut lease = GlobalFrameStage2Lease::fixed(0x1234_0000, 0x4000);
    lease.drop_backing_audit = Some((host_addr as usize, std::sync::Arc::clone(&observed)));
    let mut mapping = thread_sibling_tests::mapped_region(0x1234_0000, 0x1234_4000, 0x1234_0000);
    mapping.host_addr = host_addr;
    mapping.host_mapping = Some(host);
    mapping.stage2_lease = Some(lease);
    let mut task = hvpatch_task_state_test_fixture(7, 0x4000, 7);
    let (predecessor_identity, predecessor_mm) = predecessor_test_identity(&task);
    task.pending_exec_stage2_cleanup = Some(PendingExecStage2Cleanup {
        mappings: TaskMappingIndex::from_region(mapping),
        extents: [(
            (0x1234_0000, 0x4000),
            InventoryStage2OwnerIdentity {
                host_addr: host_addr as usize,
                generation: 0,
            },
        )]
        .into_iter()
        .collect(),
        predecessor_aliases: Vec::new(),
        frames: std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default())),
        mm_root_slot: task.mm_root_slot,
        mm_access: None,
        predecessor_identity,
        predecessor_mm,
        shared_projection: false,
        armed: true,
    });

    assert!(alias_backing_is_live(host_addr as usize));
    HvfVmState::retire_task_state_exec_predecessor(&mut task).expect("post-TLBI detached cleanup");
    assert!(
        !observed.load(std::sync::atomic::Ordering::SeqCst),
        "lease Drop must not execute stage-2 retirement"
    );
    assert!(!alias_backing_is_live(host_addr as usize));
    assert!(task.pending_exec_stage2_cleanup.is_none());
}

#[test]
fn shared_exec_predecessor_cleanup_retains_and_emits_exact_classification() {
    let task = hvpatch_task_state_test_fixture(19, 0x4000, 23);
    let (predecessor_identity, predecessor_mm) = predecessor_test_identity(&task);
    let mut cleanup = PendingExecStage2Cleanup {
        mappings: TaskMappingIndex::new(),
        extents: std::collections::BTreeMap::new(),
        predecessor_aliases: Vec::new(),
        frames: std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default())),
        mm_root_slot: task.mm_root_slot,
        mm_access: None,
        predecessor_identity,
        predecessor_mm,
        shared_projection: true,
        armed: true,
    };
    let mut observed = Vec::new();

    cleanup
        .retire_with(&mut |event| observed.push(event))
        .expect("retire shared predecessor projection");

    assert_eq!(observed.len(), 1);
    let event = observed[0];
    assert_eq!(
        event.phase(),
        carrick_observability::probes::HvpatchExecPredecessorClassificationPhase::CleanupConsumed
    );
    assert_eq!(event.linux_pid(), predecessor_identity.linux_pid);
    assert_eq!(event.linux_tid(), predecessor_identity.linux_tid);
    assert_eq!(event.task_serial(), predecessor_identity.task_serial);
    assert_eq!(event.thread_serial(), predecessor_identity.thread_serial);
    assert_eq!(event.mm(), predecessor_mm);
    assert_eq!(event.asid(), u32::from(predecessor_identity.asid));
    assert!(event.shared());
    assert!(!cleanup.armed);
}

#[test]
fn exec_predecessor_cleanup_rechecks_a_republished_stage2_reference() {
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .unwrap();
    let host_addr = host.as_ptr();
    let lease_key = (0x1238_0000_u64, 0x4000_usize);
    let observed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut lease = GlobalFrameStage2Lease::fixed(lease_key.0, lease_key.1 as u64);
    lease.drop_backing_audit = Some((host_addr as usize, std::sync::Arc::clone(&observed)));
    let mut mapping = thread_sibling_tests::mapped_region(
        lease_key.0,
        lease_key.0 + lease_key.1 as u64,
        lease_key.0,
    );
    mapping.host_addr = host_addr;
    mapping.host_mapping = Some(host);
    mapping.stage2_lease = Some(lease);

    // Exec selected this extent while it was unreferenced. Before deferred
    // cleanup runs, another MM publishes a reference into the shared backend
    // registry. The stale selection must not drop that MM's physical lease.
    let frames = std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default()));
    frames
        .lock()
        .stage2_references
        .insert((lease_key.0, lease_key.1 as u64), 1);
    let mut task = hvpatch_task_state_test_fixture(17, 0x4000, 17);
    let (predecessor_identity, predecessor_mm) = predecessor_test_identity(&task);
    let predecessor_scope = task.mm_root_slot.expect("predecessor MM root slot");
    let sibling_scope = (
        predecessor_scope.0 + predecessor_scope.1,
        predecessor_scope.1,
    );
    let predecessor_ipa = 0x2238_0000_u64;
    let sibling_ipa = 0x3238_0000_u64;
    let alias = |ipa, ownership_scope| AliasBacking {
        start: ipa,
        ipa,
        host_addr: host_addr as usize,
        size: lease_key.1,
        physical_ipa: lease_key.0,
        physical_host_addr: host_addr as usize,
        physical_size: lease_key.1,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope,
        inventory_backing: InventoryBackingIdentity::Private(lease_key.0),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
    };
    register_shared_alias(alias(
        predecessor_ipa,
        AliasOwnershipScope::MmRootSlot {
            base: predecessor_scope.0,
            size: predecessor_scope.1,
        },
    ));
    register_shared_alias(alias(
        sibling_ipa,
        AliasOwnershipScope::MmRootSlot {
            base: sibling_scope.0,
            size: sibling_scope.1,
        },
    ));
    task.pending_exec_stage2_cleanup = Some(PendingExecStage2Cleanup {
        mappings: TaskMappingIndex::from_region(mapping),
        extents: [(
            lease_key,
            InventoryStage2OwnerIdentity {
                host_addr: host_addr as usize,
                generation: 0,
            },
        )]
        .into_iter()
        .collect(),
        predecessor_aliases: vec![alias(
            predecessor_ipa,
            AliasOwnershipScope::MmRootSlot {
                base: predecessor_scope.0,
                size: predecessor_scope.1,
            },
        )],
        frames,
        mm_root_slot: task.mm_root_slot,
        mm_access: None,
        predecessor_identity,
        predecessor_mm,
        shared_projection: false,
        armed: true,
    });

    HvfVmState::retire_task_state_exec_predecessor(&mut task)
        .expect("recheck deferred predecessor cleanup");
    assert!(
        !observed.load(std::sync::atomic::Ordering::SeqCst),
        "a republished stage-2 reference must keep its exact lease alive",
    );
    assert!(
        alias_backing_is_live(host_addr as usize),
        "a republished stage-2 reference must keep its host backing alive",
    );
    let aliases = alias_registry().lock();
    assert!(
        !aliases.iter().any(|alias| alias.ipa == predecessor_ipa),
        "exec must remove semantic aliases owned by the predecessor MM",
    );
    assert!(
        aliases.iter().any(|alias| alias.ipa == sibling_ipa),
        "exec must retain the sibling MM alias for the shared live extent",
    );
    drop(aliases);
    mutate_external_alias_state(|replay, registry| {
        registry.retain(|alias| alias.ipa != predecessor_ipa && alias.ipa != sibling_ipa);
        replay.retain(|(ipa, _, _, _, _)| *ipa != lease_key.0);
    });
}

#[test]
fn exec_predecessor_cleanup_rejects_a_recycled_owner_generation() {
    let lease_key = (0x123c_0000_u64, 0x4000_usize);
    let successor_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        lease_key.1,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .unwrap();
    let successor_host_addr = successor_host.as_ptr() as usize;
    let successor_gen = next_global_frame_owner_generation();
    let successor = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(lease_key.0, lease_key.1 as u64),
        successor_host,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        successor_gen,
        lease_key.0,
        lease_key.1 as u64,
    );
    let successor_generation = successor.generation();
    let stale_generation = successor_generation.wrapping_add(1);
    assert_ne!(stale_generation, successor_generation);
    assert!(
        global_frame_host_owners()
            .lock()
            .insert(
                (lease_key.0, lease_key.1 as u64),
                GlobalFrameOwnerEntry::Live(std::sync::Arc::new(successor)),
            )
            .is_none()
    );

    let mut task = hvpatch_task_state_test_fixture(18, 0x4000, 18);
    let (predecessor_identity, predecessor_mm) = predecessor_test_identity(&task);
    task.pending_exec_stage2_cleanup = Some(PendingExecStage2Cleanup {
        mappings: TaskMappingIndex::from_region(thread_sibling_tests::mapped_region(
            lease_key.0,
            lease_key.0 + lease_key.1 as u64,
            lease_key.0,
        )),
        extents: [((lease_key.0, lease_key.1), stale_generation)]
            .into_iter()
            .map(|(key, generation)| {
                (
                    key,
                    InventoryStage2OwnerIdentity {
                        host_addr: successor_host_addr,
                        generation,
                    },
                )
            })
            .collect(),
        predecessor_aliases: Vec::new(),
        frames: std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default())),
        mm_root_slot: task.mm_root_slot,
        mm_access: None,
        predecessor_identity,
        predecessor_mm,
        shared_projection: false,
        armed: true,
    });

    HvfVmState::retire_task_state_exec_predecessor(&mut task)
        .expect("reject recycled exec predecessor owner");
    assert_eq!(
        global_frame_host_owner_generation(lease_key.0, lease_key.1 as u64),
        successor_generation,
        "stale cleanup must not retire a newer owner of the recycled key",
    );
    let successor = global_frame_host_owners()
        .lock()
        .remove(&(lease_key.0, lease_key.1 as u64))
        .expect("remove successor owner after test");
    drop(successor);
}

#[test]
fn exec_cleanup_after_owner_release_keeps_same_scope_reused_successor() {
    let _guard = foreign_mm_tests::FOREIGN_MM_TEST_LOCK.lock();
    let _external_alias_restore = foreign_mm_tests::ExternalAliasStateRestore::capture();
    clear_alias_registry();
    clear_replay_mappings();

    let lease_key = (
        carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x2340_0000,
        CowArmedRanges::COMPOUND_SIZE as usize,
    );
    let old_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        lease_key.1,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .unwrap();
    let old_host_addr = old_host.as_ptr() as usize;
    let old_generation = next_global_frame_owner_generation();
    let old_owner = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(lease_key.0, lease_key.1 as u64),
        old_host,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        old_generation,
        lease_key.0,
        lease_key.1 as u64,
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .insert(
                (lease_key.0, lease_key.1 as u64),
                GlobalFrameOwnerEntry::Live(std::sync::Arc::new(old_owner)),
            )
            .is_none()
    );

    let task = hvpatch_task_state_test_fixture(222, 0x4000, 222);
    let (predecessor_identity, predecessor_mm) = predecessor_test_identity(&task);
    let scope = AliasOwnershipScope::MmRootSlot {
        base: task.mm_root_slot.unwrap().0,
        size: task.mm_root_slot.unwrap().1,
    };
    let old_alias = AliasBacking {
        start: 0x6002_3400_0000,
        ipa: lease_key.0,
        host_addr: old_host_addr,
        size: lease_key.1,
        physical_ipa: lease_key.0,
        physical_host_addr: old_host_addr,
        physical_size: lease_key.1,
        perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: scope,
        inventory_backing: InventoryBackingIdentity::Private(0x2340),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: old_generation,
    };
    register_shared_alias(old_alias);
    let mut old_mapping = thread_sibling_tests::mapped_region(
        old_alias.start,
        old_alias.start + old_alias.size as u64,
        old_alias.ipa,
    );
    old_mapping.physical_ipa = old_alias.physical_ipa;
    old_mapping.physical_size = old_alias.physical_size;
    old_mapping.host_addr = old_host_addr as *mut u8;
    old_mapping.size = old_alias.size;
    old_mapping.is_dynamic_alias = true;
    old_mapping.owner_generation = old_generation;
    let mut cleanup = PendingExecStage2Cleanup {
        mappings: TaskMappingIndex::from_region(old_mapping),
        extents: [(
            lease_key,
            InventoryStage2OwnerIdentity {
                host_addr: old_host_addr,
                generation: old_generation,
            },
        )]
        .into_iter()
        .collect(),
        predecessor_aliases: vec![old_alias],
        frames: std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default())),
        mm_root_slot: task.mm_root_slot,
        mm_access: None,
        predecessor_identity,
        predecessor_mm,
        shared_projection: false,
        armed: true,
    };

    let owner_released = std::sync::Arc::new(std::sync::Barrier::new(2));
    let successor_published = std::sync::Arc::new(std::sync::Barrier::new(2));
    let successor_alias = std::thread::scope(|scope_thread| {
        let publisher_released = std::sync::Arc::clone(&owner_released);
        let publisher_done = std::sync::Arc::clone(&successor_published);
        let publisher = scope_thread.spawn(move || {
            publisher_released.wait();
            let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                lease_key.1,
                crate::host_mapping::HostMappingKind::FrameCow,
            )
            .unwrap();
            let host_addr = host.as_ptr() as usize;
            let generation = next_global_frame_owner_generation();
            let owner = GlobalFrameHostOwner::new(
                GlobalFrameStage2Lease::fixed(lease_key.0, lease_key.1 as u64),
                host,
                u64::from(applevisor::memory::MemPerms::ReadWriteExec),
                generation,
                lease_key.0,
                lease_key.1 as u64,
            );
            assert!(
                global_frame_host_owners()
                    .lock()
                    .insert(
                        (lease_key.0, lease_key.1 as u64),
                        GlobalFrameOwnerEntry::Live(std::sync::Arc::new(owner)),
                    )
                    .is_none(),
                "old exec owner must be absent before the same IPA is reused",
            );
            let alias = AliasBacking {
                physical_host_addr: host_addr,
                host_addr,
                owner_generation: generation,
                ..old_alias
            };
            register_shared_alias(alias);
            publisher_done.wait();
            alias
        });
        cleanup
            .retire_with_cleanup_boundary(&mut |_| {}, &mut |retired| {
                assert_eq!(retired.physical_ipa, lease_key.0);
                assert_eq!(retired.owner.generation, old_generation);
                owner_released.wait();
                successor_published.wait();
            })
            .expect("retire old exec owner around deterministic IPA reuse");
        publisher.join().unwrap()
    });

    let aliases = alias_registry()
        .lock()
        .process_visible_ordered(task.mm_root_slot, task.container_root);
    assert!(aliases.contains(&successor_alias));
    assert!(
        replay_mappings()
            .lock()
            .contains(&replay_mapping_key(successor_alias)),
        "delayed exec cleanup must retain the successor replay identity",
    );
    assert_eq!(
        missing_process_aliases(
            &std::collections::HashSet::new(),
            &aliases,
            task.mm_root_slot,
            task.container_root,
        ),
        vec![successor_alias],
        "the reused exact alias must remain eligible for fork materialization",
    );
    assert!(
        retire_global_frame_host_owner_if_generation(
            lease_key.0,
            lease_key.1 as u64,
            successor_alias.owner_generation,
        )
        .is_retired()
    );
}

#[test]
fn shared_process_exec_splits_inventory_without_retiring_parent_ledger() {
    let mut task = hvpatch_task_state_test_fixture(8, 0x8000, 8);
    task.shared_process_mm = true;
    let parent_ledger = task.frame_inventory.shared_ledger();
    parent_ledger.lock().initialized = true;
    let (_unused, replacement) = inventory_pair(11);

    task.begin_exec_inventory(None, replacement)
        .expect("arm shared-process exec inventory");

    let replacement_ledger = task.frame_inventory.shared_ledger();
    assert!(!std::sync::Arc::ptr_eq(&parent_ledger, &replacement_ledger));
    assert!(parent_ledger.lock().initialized);
    assert!(parent_ledger.lock().retired_reservation.is_none());
    let replacement = replacement_ledger.lock();
    // The replacement ledger is fresh, so a retirement armed against it
    // could only ever stage zero events. It must not be armed at all.
    assert!(replacement.retired_reservation.is_none());
    assert!(replacement.replacement_reservation.is_some());
}

/// The seam this pins: the runtime sizes the retirement transaction from
/// the count the backend reports, then the backend rebases onto a fresh
/// ledger and stages nothing into it. Reporting the old ledger's extents
/// for a retained mm made those two disagree, and every vfork+execve died
/// past its point of no return on the resulting zero-event commit.
#[test]
fn retained_old_mm_reports_no_exec_retirement_extents() {
    let mut task = hvpatch_task_state_test_fixture(9, 0x9000, 9);
    {
        let mut ledger = task.frame_inventory.lock();
        ledger.initialized = true;
        ledger.extents.insert(
            (0x9000_0000, 0x4000),
            InventoryExtent {
                frame: carrick_hal::FrameId::from_kernel_allocation(id(41)),
                mapping: carrick_hal::MappingId::from_kernel_allocation(id(42)),
                backing: InventoryBackingIdentity::Private(9),
                stage2_base: 0x9000_0000,
                stage2_length: 0x4000,
                stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
            },
        );
    }

    assert!(task.exec_retires_old_mm());
    assert_eq!(task.exec_retired_extent_count(), 1);

    task.shared_process_mm = true;
    assert!(!task.exec_retires_old_mm());
    assert_eq!(task.exec_retired_extent_count(), 0);
}

#[test]
fn exec_replacement_keeps_every_representative_leaf_asid_scoped() {
    const NON_GLOBAL: u64 = 1 << 11;
    let GlobalExecPlan { plan, .. } =
        prepare_global_exec_plan(&root_exec_test_plan(), None).expect("global exec plan");
    let tables = plan
        .mappings
        .iter()
        .find(|mapping| mapping.guest_start == carrick_mem::memory::LINUX_PAGE_TABLES_BASE)
        .expect("exec stage-1 table mapping");
    // No `heap` row: since `59cfc210f` ("make HVPatch brk heap a real
    // VMA") the heap L1 entry is SPLIT INTO A TABLE and left
    // `set_prot_none` until `brk` grows it, so `terminal_descriptor`
    // returns a zero leaf — it is neither mapped nor nG-tagged, and both
    // assertions below are meaningless for it. `59cfc210f` dropped the
    // identical row from the `carrick-mem` `stage1_tests` twin and missed
    // this one, which is why `just test` was red on main. The heap's new
    // shape is asserted where it now lives: "L1A[..] (heap split) must be
    // a table" in `carrick_mem::memory` stage1_tests.
    for (name, va) in [
        ("user text", 0x0040_0000),
        ("mmap", carrick_mem::memory::LINUX_MMAP_BASE),
        (
            "shared aperture",
            carrick_mem::memory::LINUX_SHARED_FILE_BASE,
        ),
        ("stack", carrick_mem::memory::LINUX_STACK_TOP - 0x4000),
        ("EL1 maintenance", carrick_mem::memory::LINUX_EL1_MAINT_BASE),
        (
            "identity control",
            carrick_mem::memory::LINUX_IDENTITY_PAGE_BASE,
        ),
        (
            "syscall mailbox",
            carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE,
        ),
        ("Rosetta alias", carrick_mem::memory::LINUX_ROSETTA_VA_BASE),
    ] {
        let leaf = carrick_mem::page_table::terminal_descriptor(
            carrick_mem::page_table::walk_descriptors(tables.image.as_ref(), tables.ipa_start, va),
        );
        if name != "mmap" {
            assert_ne!(leaf & 0b11, 0, "{name} leaf at {va:#x} is not mapped");
        }
        assert_ne!(
            leaf & NON_GLOBAL,
            0,
            "post-exec {name} leaf at {va:#x} escaped ASID scope"
        );
    }
}

#[test]
fn root_exec_plan_does_not_collide_with_a_live_child_generation() {
    let plan = root_exec_test_plan();
    let child = prepare_global_exec_plan(
        &plan,
        Some((crate::memory::LINUX_HVPATCH_ROOT_SLOT_BASE, 2 * 1024 * 1024)),
    )
    .unwrap();
    let root = prepare_global_exec_plan(&plan, None).unwrap();

    assert!(root.stage2_leases.keys().all(|root_key| {
        child
            .stage2_leases
            .keys()
            .all(|child_key| root_key != child_key)
    }));
}

fn exec_authority_fingerprint_fixture() -> ExecAuthorityFingerprint {
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(201));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(202));
    let lease = ExecLeaseFingerprint {
        base: 0x9000,
        length: 0x1000,
        mapped: true,
        active: true,
        release_ipa: true,
    };
    ExecAuthorityFingerprint {
        owners: vec![ExecOwnerFingerprint {
            key: (0x9000, 0x1000),
            host: 0x100_0000,
            host_len: 0x1000,
            perms: 7,
            lease,
        }],
        inventory_initialized: true,
        backend_extents: vec![ExecBackendExtentFingerprint {
            key: (0x9000, 0x1000),
            frame,
            mapping,
            backing: InventoryBackingIdentity::Private(1),
            stage2_base: 0x9000,
            stage2_length: 0x1000,
        }],
        frame_references: vec![(frame, 1)],
        extent_references: vec![((frame, 0x9000, 0x1000), 1)],
        stage2_references: vec![((0x9000, 0x1000), 1)],
        authority_retained_stage2: Vec::new(),
        mappings: vec![ExecMappingFingerprint {
            start: 0x4000,
            ipa: 0x9000,
            physical_ipa: 0x9000,
            end: 0x5000,
            host: 0x100_0000,
            size: 0x1000,
            physical_size: 0x1000,
            perms: 7,
            has_memory: false,
            host_owner: None,
            stage2_lease: Some(lease),
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
        }],
        allocator: ExecAllocatorFingerprint {
            next: 0xa000,
            free: vec![(0xb000, 0x1000)],
            live: vec![(0x9000, 0x1000)],
        },
        replay_mappings: vec![(0x9000, 0x1000, 0x100_0000, 7, 0)],
    }
}

#[test]
fn exec_authority_rollback_rejects_drift_in_every_published_component() {
    let before = exec_authority_fingerprint_fixture();
    let assert_drift = |mut after: ExecAuthorityFingerprint,
                        mutate: fn(&mut ExecAuthorityFingerprint)| {
        mutate(&mut after);
        assert!(verify_exec_authority_rollback(&before, &after).is_err());
    };

    assert_drift(before.clone(), |after| after.owners[0].perms ^= 1);
    assert_drift(before.clone(), |after| after.inventory_initialized = false);
    assert_drift(before.clone(), |after| {
        after.backend_extents[0].stage2_base += 0x1000
    });
    assert_drift(before.clone(), |after| after.frame_references[0].1 += 1);
    assert_drift(before.clone(), |after| after.extent_references[0].1 += 1);
    assert_drift(before.clone(), |after| after.stage2_references[0].1 += 1);
    assert_drift(before.clone(), |after| {
        after.authority_retained_stage2.push((0xa000, 0x1000))
    });
    assert_drift(before.clone(), |after| {
        after.mappings[0].guest_writable = false
    });
    assert_drift(before.clone(), |after| after.allocator.next += 0x1000);
    assert_drift(before.clone(), |after| {
        after.allocator.free.push((0xc000, 0x1000))
    });
    assert_drift(before.clone(), |after| {
        after.allocator.live.push((0xd000, 0x1000))
    });
    assert_drift(before.clone(), |after| {
        after
            .replay_mappings
            .push((0xe000, 0x1000, 0x200_0000, 7, 0))
    });
}

fn assert_exec_stage2_injected_failure_restores_old(fail_after_maps: usize) {
    let old = [
        ExecStage2Install::for_test(0x1000, 0x1000),
        ExecStage2Install::for_test(0x3000, 0x1000),
    ];
    let new = [
        ExecStage2Install::for_test(0x9000, 0x1000),
        ExecStage2Install::for_test(0xb000, 0x1000),
    ];
    let installed = std::cell::RefCell::new(
        old.iter()
            .map(ExecStage2Install::key)
            .collect::<std::collections::BTreeSet<_>>(),
    );
    let actions = std::cell::RefCell::new(Vec::new());

    let error = switch_exec_stage2_transaction(
        &old,
        &new,
        Some(fail_after_maps),
        |extent| {
            actions.borrow_mut().push(("unmap", extent.key()));
            if installed.borrow_mut().remove(&extent.key()) {
                Ok(())
            } else {
                Err(TrapError::Hypervisor(format!(
                    "unmap absent {:?}",
                    extent.key()
                )))
            }
        },
        |extent| {
            actions.borrow_mut().push(("map", extent.key()));
            if installed.borrow_mut().insert(extent.key()) {
                Ok(())
            } else {
                Err(TrapError::Hypervisor(format!(
                    "map duplicate {:?}",
                    extent.key()
                )))
            }
        },
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected HVPatch exec stage-2 map failure")
    );
    assert_eq!(
        *installed.borrow(),
        old.iter().map(ExecStage2Install::key).collect(),
        "an injected replacement failure must restore the exact predecessor stage-2 set"
    );
    let mut expected = old
        .iter()
        .map(|extent| ("unmap", extent.key()))
        .collect::<Vec<_>>();
    expected.extend(
        new[..fail_after_maps]
            .iter()
            .map(|extent| ("map", extent.key())),
    );
    expected.extend(
        new[..fail_after_maps]
            .iter()
            .rev()
            .map(|extent| ("unmap", extent.key())),
    );
    expected.extend(old.iter().map(|extent| ("map", extent.key())));
    assert_eq!(
        *actions.borrow(),
        expected,
        "rollback must remove every published successor in reverse order before restoring every predecessor"
    );
}

#[test]
fn exec_stage2_failure_after_teardown_restores_predecessor_exactly() {
    assert_exec_stage2_injected_failure_restores_old(0);
}

#[test]
fn exec_stage2_failure_after_one_map_removes_successor_and_restores_predecessor() {
    assert_exec_stage2_injected_failure_restores_old(1);
}

#[test]
fn exec_stage2_rollback_restores_predecessor_replay_registration() {
    let mut predecessor = ExecStage2Install::for_test(0x1000, 0x1000);
    predecessor.replay_registered = true;
    let replacement = ExecStage2Install::for_test(0x9000, 0x1000);
    let installed = std::cell::RefCell::new(std::collections::BTreeSet::from([predecessor.key()]));
    let replay = std::cell::RefCell::new(std::collections::BTreeSet::from([predecessor
        .replay_key()
        .unwrap()]));

    let error = switch_exec_stage2_transaction(
        &[predecessor],
        &[replacement],
        Some(0),
        |extent| {
            installed.borrow_mut().remove(&extent.key());
            if let Some(key) = extent.replay_key() {
                replay.borrow_mut().remove(&key);
            }
            Ok(())
        },
        |extent| {
            installed.borrow_mut().insert(extent.key());
            if let Some(key) = extent.replay_key() {
                replay.borrow_mut().insert(key);
            }
            Ok(())
        },
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("injected HVPatch exec stage-2 map failure")
    );
    assert_eq!(
        *installed.borrow(),
        std::collections::BTreeSet::from([predecessor.key()])
    );
    assert_eq!(
        *replay.borrow(),
        std::collections::BTreeSet::from([predecessor.replay_key().unwrap()])
    );
}

#[test]
fn root_exec_rebuilds_tables_with_sparse_and_hvpatch_reservations() {
    let plan = root_exec_test_plan();

    let GlobalExecPlan {
        plan: rebuilt,
        stage2_leases,
    } = prepare_global_exec_plan(&plan, None).unwrap();
    assert_eq!(
        rebuilt.stage1_page_tables_base,
        rebuilt
            .mappings
            .iter()
            .find(|mapping| mapping.guest_start == crate::memory::LINUX_PAGE_TABLES_BASE)
            .map(|mapping| mapping.ipa_start)
    );
    assert_eq!(stage2_leases.len(), 2, "the sparse arena owns no frame");
    let table = rebuilt
        .mappings
        .iter()
        .find(|mapping| mapping.guest_start == crate::memory::LINUX_PAGE_TABLES_BASE)
        .unwrap();
    let mut manager = crate::page_table::PageTableManager::new(
        table.image.as_ref().clone(),
        rebuilt.stage1_page_tables_base.unwrap(),
    );
    assert_eq!(
        manager.translate(0x20_0000),
        rebuilt
            .mappings
            .iter()
            .find(|mapping| mapping.guest_start == 0x20_0000)
            .map(|mapping| mapping.ipa_start)
    );
    assert_eq!(manager.translate(crate::memory::LINUX_MMAP_BASE), None);
    assert_eq!(
        manager.translate(crate::memory::LINUX_HVPATCH_ROOT_SLOT_BASE),
        None
    );
    assert!(
        !manager
            .set_readonly(0x20_4000, 0x4000, false, None)
            .unwrap()
            .changed,
        "root exec must preserve the ELF read-only span"
    );
}

#[test]
fn sparse_exec_omission_requires_exact_private_hidden_arena() {
    let exact = exec_mapping_for_order(
        crate::memory::LINUX_MMAP_BASE,
        crate::memory::mmap_arena_size(),
    );
    assert!(is_sparse_hvpatch_mmap_mapping(&exact));

    let mut shared = exact.clone();
    shared.shared = true;
    assert!(!is_sparse_hvpatch_mmap_mapping(&shared));

    let shorter = exec_mapping_for_order(
        crate::memory::LINUX_MMAP_BASE,
        crate::memory::mmap_arena_size() - 0x4000,
    );
    assert!(!is_sparse_hvpatch_mmap_mapping(&shorter));

    let shifted = exec_mapping_for_order(
        crate::memory::LINUX_MMAP_BASE + 0x4000,
        crate::memory::mmap_arena_size(),
    );
    assert!(!is_sparse_hvpatch_mmap_mapping(&shifted));
}

#[test]
fn reserved_global_stage2_lease_rolls_back_before_map() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000).unwrap();
    let key = lease.key();
    assert_eq!(
        global_frame_ipa_allocator().lock().live.get(&key.0),
        Some(&key.1)
    );
    drop(lease);
    assert!(
        !global_frame_ipa_allocator()
            .lock()
            .live
            .contains_key(&key.0),
        "dropping a not-yet-mapped child/exec lease must return its IPA"
    );
}

#[test]
fn mapped_host_address_is_not_proof_of_a_retired_global_owner() {
    const RETIRED_IPA: u64 = 0x7e00_0000_0000;
    const LIVE_IPA: u64 = RETIRED_IPA + 0x4000;
    const LENGTH: u64 = 0x4000;

    let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        LENGTH as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .unwrap();
    let host_addr = host_mapping.as_ptr() as usize;
    let owner_gen = next_global_frame_owner_generation();
    let owner = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(LIVE_IPA, LENGTH),
        host_mapping,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        owner_gen,
        LIVE_IPA,
        LENGTH,
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .insert(
                (LIVE_IPA, LENGTH),
                GlobalFrameOwnerEntry::Live(std::sync::Arc::new(owner))
            )
            .is_none()
    );

    assert!(
        alias_backing_is_live(host_addr),
        "the superseded mapped-address predicate must admit this live host VA"
    );
    let generation = global_frame_host_owner_generation(LIVE_IPA, LENGTH);
    assert_ne!(generation, 0, "a registered owner carries an incarnation");
    assert!(global_frame_host_owner_matches(
        LIVE_IPA, LENGTH, host_addr, generation
    ));
    assert!(
        !global_frame_host_owner_matches(RETIRED_IPA, LENGTH, host_addr, generation),
        "a live host VA owned by another IPA must not resurrect a retired lease"
    );

    let owner = global_frame_host_owners()
        .lock()
        .remove(&(LIVE_IPA, LENGTH))
        .unwrap();
    drop(owner);
    assert!(!global_frame_host_owner_matches(
        LIVE_IPA, LENGTH, host_addr, generation
    ));

    // The point of the incarnation: re-registering the SAME (ipa, length)
    // on the SAME recycled host VA must NOT re-authenticate the stale row.
    // Darwin hands that VA straight back — measured 499/499 — so without
    // this the row silently passes and the reuse scrub zeroes a live
    // granule.
    let remap = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        LENGTH as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .unwrap();
    let reused_addr = remap.as_ptr() as usize;
    let succ_gen = next_global_frame_owner_generation();
    let successor = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(LIVE_IPA, LENGTH),
        remap,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        succ_gen,
        LIVE_IPA,
        LENGTH,
    );
    let successor_generation = successor.generation();
    global_frame_host_owners().lock().insert(
        (LIVE_IPA, LENGTH),
        GlobalFrameOwnerEntry::Live(std::sync::Arc::new(successor)),
    );
    assert_ne!(successor_generation, generation);
    assert!(
        !global_frame_host_owner_matches(LIVE_IPA, LENGTH, reused_addr, generation),
        "a stale row must not authenticate against a NEW incarnation of the \
             same (ipa, length, host VA)"
    );
    assert!(
        global_frame_host_owner_matches(LIVE_IPA, LENGTH, reused_addr, successor_generation),
        "the successor's own rows still authenticate"
    );
    global_frame_host_owners()
        .lock()
        .remove(&(LIVE_IPA, LENGTH));
}

#[test]
fn an_unowned_extent_authenticates_a_row_that_recorded_no_incarnation() {
    // A forked child inherits kernel regions — its identity page among them
    // — as non-owning rows over an extent that no global-frame owner was
    // ever registered for. Such a row stamps generation 0 by definition
    // (`global_frame_host_owner_generation` returns 0 when unowned), so this
    // predicate has no owner to authenticate it against and must not treat
    // that absence as a rejection: doing so made every child's identity
    // stamp fail `validate_guest_write_range` with a spurious out-of-bounds.
    const UNOWNED_IPA: u64 = 0x7e00_0001_0000;
    const LENGTH: u64 = 0x4000;
    let host_addr = 0x1_0000usize;

    assert_eq!(
        global_frame_host_owner_generation(UNOWNED_IPA, LENGTH),
        0,
        "precondition: no owner is registered for this extent"
    );
    assert!(
        global_frame_host_owner_matches(UNOWNED_IPA, LENGTH, host_addr, 0),
        "a row published against an unowned extent keeps the historical \
             pointer-only behaviour"
    );
    assert!(
        !global_frame_host_owner_matches(UNOWNED_IPA, LENGTH, host_addr, 7),
        "a row that DID record an incarnation must stay rejected once its \
             owner is gone — macOS may have recycled the host VA"
    );
}

#[test]
fn child_local_mapping_authenticates_through_its_own_raii_lease() {
    let ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x7f00_0000;
    let size = 0x4000usize;
    let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .unwrap();
    let host_addr = host_mapping.as_ptr();
    let mut lease = GlobalFrameStage2Lease::fixed(ipa, size as u64);
    lease.mark_mapped();
    let mut mapping = HvfMappedRegion {
        start: 0x002d_0000_0000,
        end: 0x002d_0000_4000,
        ipa,
        physical_ipa: ipa,
        host_addr,
        size,
        physical_size: size,
        perms: applevisor::memory::MemPerms::ReadWriteExec,
        memory: None,
        host_mapping: Some(host_mapping),
        structural_owner: None,
        stage2_lease: Some(lease),
        is_dynamic_alias: false,
        sharing: GuestMappingSharing::Private,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
    };

    assert!(global_frame_region_owner_matches(&mapping));

    // No stage-2 mapping was installed in this pure ownership test.
    mapping.stage2_lease.as_mut().unwrap().active = false;
}

#[test]
fn lease_retirement_waits_for_the_last_global_stage2_reference() {
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(31));
    let mut inventory = HvpatchFrameInventory::default();
    let lease = (0xa000_0000_0000, 0x8000);
    for (index, gpa) in [lease.0, lease.0 + 0x4000].into_iter().enumerate() {
        let mapping = carrick_hal::MappingId::from_kernel_allocation(id(32 + index as u64));
        inventory.extents.insert(
            (gpa, 0x4000),
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(9),
                stage2_base: lease.0,
                stage2_length: lease.1,
                stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
            },
        );
    }
    {
        let mut registry = inventory.frames.lock();
        registry.references.insert(frame, 3);
        registry
            .extent_references
            .insert((frame, lease.0, 0x4000), 1);
        registry
            .extent_references
            .insert((frame, lease.0 + 0x4000, 0x4000), 1);
        registry.stage2_references.insert(lease, 3);
    }
    let leases = std::collections::BTreeSet::from([lease]);
    let authority_agrees = |_frame| Ok(Some(2usize));
    let shared =
        HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &authority_agrees)
            .unwrap();
    assert!(shared.frames.is_empty());
    assert!(shared.stage2_leases.is_empty());

    {
        let mut registry = inventory.frames.lock();
        registry.references.insert(frame, 2);
        registry.stage2_references.insert(lease, 2);
    }
    let final_owner =
        HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &authority_agrees)
            .unwrap();
    assert_eq!(
        final_owner.frames,
        std::collections::BTreeSet::from([frame])
    );
    assert_eq!(final_owner.stage2_leases, leases);
}

// NEXT_TEST_PHYSICAL_IPA rehomed to trap.rs stub

fn next_test_physical_key(size: u64) -> (u64, u64) {
    let base = NEXT_TEST_PHYSICAL_IPA.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
    (base, size)
}

struct TestGlobalFrameOwnerGuard {
    key: (u64, u64),
    generation: u64,
}

impl Drop for TestGlobalFrameOwnerGuard {
    fn drop(&mut self) {
        retire_global_frame_host_owner_if_generation(self.key.0, self.key.1, self.generation);
    }
}

/// Pure ownership tests cannot install an HVF stage-2 mapping. They still
/// publish through the production helper with a mapped lease so the
/// production invariant is exercised, then disarm only that exact owner
/// generation before retirement. The reusable-IPA lease remains active and
/// therefore still proves allocator release/reuse on drop.
fn disarm_test_owner_stage2_unmap(key: (u64, u64), generation: u64) {
    let owners = global_frame_host_owners().lock();
    let entry = owners
        .get(&key)
        .expect("test owner must remain published before retirement");
    let owner = entry.owner();
    assert_eq!(
        owner.generation(),
        generation,
        "test seam must not disarm a recycled owner generation"
    );
    let snapshot = owner.snapshot().expect("test owner stage-2 record");
    assert!(
        snapshot.mapped,
        "production publication must retain a mapped stage-2 record"
    );
    owner
        .custody
        .upgrade()
        .expect("test owner custody")
        .disarm_stage2_backend_map_for_test(owner.record_identity);
}

fn process_retirement_task(
    authority: TestFrameMappingCount,
) -> (
    HvfTaskState,
    carrick_hal::FrameId,
    carrick_hal::MappingId,
    (u64, u64),
    TestGlobalFrameOwnerGuard,
) {
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(41));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(42));
    let key = next_test_physical_key(0x4000);
    let generation = next_global_frame_owner_generation();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        key.1 as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .unwrap();
    let host_addr = host.as_ptr();
    let mut task = hvpatch_task_state_test_fixture(12, key.0, 12);
    task.cow_authority = Some(std::sync::Arc::new(authority));
    task.mappings[0].start = key.0;
    task.mappings[0].end = key.0 + key.1;
    task.mappings[0].ipa = key.0;
    task.mappings[0].physical_ipa = key.0;
    task.mappings[0].host_addr = host_addr;
    task.mappings[0].size = key.1 as usize;
    task.mappings[0].physical_size = key.1 as usize;
    task.mappings[0].owner_generation = generation;
    task.mappings[0].stage2_lease = Some(GlobalFrameStage2Lease::fixed(key.0, key.1));
    {
        let mut inventory = task.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            key,
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(41),
                stage2_base: key.0,
                stage2_length: key.1,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: host_addr as usize,
                    generation,
                },
            },
        );
        {
            let mut frames = inventory.frames.lock();
            // This mm's backend ledger is the only one that still names the
            // frame, but the kernel authority reports a second live mapping
            // in another mm. The stage-2 reference remains shared as well,
            // so this pure inventory test performs no HVF unmap.
            frames.references.insert(frame, 1);
            frames.extent_references.insert((frame, key.0, key.1), 1);
            frames.stage2_references.insert(key, 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([93; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(93)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }
    let owner = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(key.0, key.1),
        host,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        generation,
        key.0,
        key.1,
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .insert(key, GlobalFrameOwnerEntry::Live(std::sync::Arc::new(owner)))
            .is_none(),
        "publication must displace no predecessor"
    );
    let guard = TestGlobalFrameOwnerGuard { key, generation };
    (task, frame, mapping, key, guard)
}

#[test]
fn process_retirement_does_not_retire_a_frame_still_mapped_by_another_mm() {
    let (mut task, frame, mapping, _key, _guard) =
        process_retirement_task(TestFrameMappingCount::Exact(2));

    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("stage process-terminal retirement");
    let commit = HvfVmState::take_task_state_retirement_inventory(&mut task)
        .expect("process-terminal retirement commit");
    assert!(commit.batch().events().iter().any(|event| {
        matches!(
            event,
            carrick_hal::FrameInventoryEvent::UnmapMapping {
                mapping: retired,
                ..
            } if *retired == mapping
        )
    }));
    assert!(
        commit.batch().events().iter().all(|event| !matches!(
            event,
            carrick_hal::FrameInventoryEvent::RetireFrame {
                frame: retired,
                ..
            } if *retired == frame
        )),
        "a process terminal must not retire a frame another mm still maps",
    );
}

#[test]
fn process_retirement_terminalizes_a_nonselected_structural_root_before_slot_reuse() {
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let custody = legacy_test_carrier_vm_custody_arc();
    let root_slot = (0x7d20_0000_0000_u64, 0x20_0000_u64);
    let root_len = 0x1c_0000_u64;
    let root_mapping = GuestMapping {
        guest_start: carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
        ipa_start: root_slot.0,
        mapped_size: root_len,
        offset_in_mapping: 0,
        payload_size: root_len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: true,
            execute: false,
        },
        shared: false,
        image: std::sync::Arc::new(vec![0; root_len as usize]),
        private_file_backing: None,
    };
    let root_region = map_region_raw_in(custody, &root_mapping, false, true)
        .expect("map exact structural root-slot fixture");
    let root_owner = root_region
        .structural_owner
        .as_ref()
        .cloned()
        .expect("root slot has structural custody");
    let root_identity = root_owner.record_identity();
    let stage2_owner = mapped_region_stage2_owner_identity(&root_region)
        .expect("structural root has exact owner identity");

    let frame = carrick_hal::FrameId::from_kernel_allocation(id(451));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(452));
    let mut task = hvpatch_task_state_test_fixture(12, root_slot.0, 12);
    task.mm_root_slot = Some(root_slot);
    task.cow_authority = Some(std::sync::Arc::new(TestFrameMappingCount::Exact(2)));
    task.mappings = TaskMappingIndex::from_region(root_region);
    task.mm_access
        .install_structural_mapping_authority(Some(root_slot), std::sync::Arc::clone(&root_owner))
        .expect("install exact root authority");
    {
        let mut inventory = task.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            (root_slot.0, root_len),
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(451),
                stage2_base: root_slot.0,
                stage2_length: root_len,
                stage2_owner,
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(frame, 1);
            frames
                .extent_references
                .insert((frame, root_slot.0, root_len), 1);
            frames.stage2_references.insert((root_slot.0, root_len), 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([95; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(95)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }

    let proof =
        HvfVmState::retire_task_state_process_mappings_with_root_proof(&mut task, root_slot)
            .expect("retire process whose structural root frame is not globally complete");
    assert_eq!(proof.root_slot_base(), root_slot.0);
    assert_eq!(proof.root_slot_size(), root_slot.1);

    let root_remained_live = custody
        .stage2_record_snapshot(root_identity.record_id)
        .is_some_and(|snapshot| snapshot.mapped);
    let replacement = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        root_len as usize,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate successor root backing");
    let replacement_map = unsafe {
        inventory_hv_vm_map(
            replacement.as_ptr().cast(),
            root_slot.0,
            root_len as usize,
            u64::from(applevisor::memory::MemPerms::ReadWrite),
        )
    };

    // Keep a RED run from contaminating later host tests with the leaked
    // pre-fix custody row. Production must make both observations false/0.
    if root_remained_live {
        root_owner
            .retained
            .owner_retired
            .store(true, std::sync::atomic::Ordering::Release);
        retry_structural_backing_identities_in_using(
            custody,
            &[root_identity],
            &mut unmap_global_frame_stage2_record,
            &mut release_retired_stage2_ipa,
        )
        .expect("clean leaked RED root fixture");
    } else if replacement_map == 0 {
        assert_eq!(
            unsafe { inventory_hv_vm_unmap(root_slot.0, root_len as usize) },
            0,
        );
    }
    drop(replacement);
    drop(root_owner);

    assert!(
        !root_remained_live,
        "MM retirement returned while its exact structural root remained mapped/current",
    );
    assert_eq!(
        replacement_map, 0,
        "the next MM must be able to map the returned numeric root slot",
    );
}

fn shared_inventory_root_fixture(
    root_slot: (u64, u64),
) -> (
    std::sync::Arc<CarrierVmCustody>,
    HvfTaskState,
    std::sync::Arc<StructuralBackingOwner>,
    CarrierStage2RecordIdentity,
) {
    let custody = legacy_test_carrier_vm_custody_arc();
    let root_len = 0x1c_0000_u64;
    let root_mapping = GuestMapping {
        guest_start: carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
        ipa_start: root_slot.0,
        mapped_size: root_len,
        offset_in_mapping: 0,
        payload_size: root_len,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: true,
            execute: false,
        },
        shared: false,
        image: std::sync::Arc::new(vec![0; root_len as usize]),
        private_file_backing: None,
    };
    let root_region = map_region_raw_in(custody, &root_mapping, false, true)
        .expect("map shared-inventory structural root fixture");
    let owner = root_region
        .structural_owner
        .as_ref()
        .cloned()
        .expect("shared-inventory root has structural custody");
    let identity = owner.record_identity();
    let mut task = hvpatch_task_state_test_fixture(12, root_slot.0, 12);
    task.mm_root_slot = Some(root_slot);
    task.shared_process_mm = true;
    task.mappings = TaskMappingIndex::from_region(root_region);
    task.mm_access
        .install_structural_mapping_authority(Some(root_slot), std::sync::Arc::clone(&owner))
        .expect("install shared-inventory exact root authority");
    (std::sync::Arc::clone(custody), task, owner, identity)
}

#[test]
fn shared_inventory_final_owner_retires_only_its_exact_structural_root() {
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let root_slot = (0x7d40_0000_0000_u64, 0x20_0000_u64);
    let (custody, mut task, owner, identity) = shared_inventory_root_fixture(root_slot);
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(461));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(462));
    let shared_key = (0x5500_0000_u64, 0x4000_u64);
    {
        let mut inventory = task.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            shared_key,
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::SharedAnon(461),
                stage2_base: shared_key.0,
                stage2_length: shared_key.1,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: 0x1234_0000,
                    generation: 7,
                },
            },
        );
    }

    let proof = HvfVmState::retire_task_state_mm_root_only(&mut task, root_slot)
        .expect("retire only final shared-inventory root");

    assert_eq!((proof.root_slot_base(), proof.root_slot_size()), root_slot);
    assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
    let inventory = task.frame_inventory.lock();
    assert_eq!(inventory.extents.len(), 1);
    assert_eq!(
        inventory.extents.get(&shared_key).map(|row| row.mapping),
        Some(mapping)
    );
    drop(inventory);
    drop(owner);
}

#[test]
fn root_retirement_refuses_mismatched_coordinates_and_active_pins() {
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let root_slot = (0x7d60_0000_0000_u64, 0x20_0000_u64);
    let (custody, mut task, owner, identity) = shared_inventory_root_fixture(root_slot);

    let mismatch = HvfVmState::retire_task_state_mm_root_only(
        &mut task,
        (root_slot.0 + root_slot.1, root_slot.1),
    )
    .expect_err("foreign root coordinates must not mint a proof");
    assert!(mismatch.to_string().contains("coordinates mismatch"));
    assert!(
        custody
            .stage2_record_snapshot(identity.record_id)
            .is_some_and(|snapshot| snapshot.mapped)
    );

    let pin = custody
        .pin_stage2_record(identity)
        .expect("pin exact structural root record");
    let pinned = HvfVmState::retire_task_state_mm_root_only(&mut task, root_slot)
        .expect_err("an active record pin must prevent a root proof");
    assert!(pinned.to_string().contains("remained nonterminal"));
    assert!(custody.stage2_record_snapshot(identity.record_id).is_some());

    drop(pin);
    let proof = HvfVmState::retire_task_state_mm_root_only(&mut task, root_slot)
        .expect("retry exact root retirement after pin release");
    assert_eq!((proof.root_slot_base(), proof.root_slot_size()), root_slot);
    assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
    drop(owner);
}

#[test]
fn exec_predecessor_returns_proof_for_a_root_omitted_from_retirement_candidates() {
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let root_slot = (0x7d80_0000_0000_u64, 0x20_0000_u64);
    let (custody, mut task, owner, identity) = shared_inventory_root_fixture(root_slot);
    task.shared_process_mm = false;
    let (predecessor_identity, predecessor_mm) = predecessor_test_identity(&task);
    task.pending_exec_stage2_cleanup = Some(PendingExecStage2Cleanup {
        mappings: std::mem::take(&mut task.mappings),
        extents: std::collections::BTreeMap::new(),
        predecessor_aliases: Vec::new(),
        frames: std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default())),
        mm_root_slot: Some(root_slot),
        mm_access: Some(std::sync::Arc::clone(&task.mm_access)),
        predecessor_identity,
        predecessor_mm,
        shared_projection: false,
        armed: true,
    });

    let proof =
        HvfVmState::retire_task_state_exec_predecessor_with_root_proof(&mut task, root_slot)
            .expect("exec predecessor exact root proof");

    assert_eq!((proof.root_slot_base(), proof.root_slot_size()), root_slot);
    assert!(custody.stage2_record_snapshot(identity.record_id).is_none());
    drop(owner);
}

#[test]
fn carrier_drop_preserves_a_zero_backend_ref_lease_retained_by_kernel_authority() {
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(41));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(42));
    let key = (0x7e00_0000_0000_u64, 0x4000_u64);
    let mut task = hvpatch_task_state_test_fixture(12, key.0, 12);
    task.cow_authority = Some(std::sync::Arc::new(TestFrameMappingCount::Exact(2)));
    task.mappings[0].start = key.0;
    task.mappings[0].end = key.0 + key.1;
    task.mappings[0].ipa = key.0;
    task.mappings[0].physical_ipa = key.0;
    task.mappings[0].host_addr = 0x1000usize as *mut u8;
    task.mappings[0].size = key.1 as usize;
    task.mappings[0].physical_size = key.1 as usize;
    task.mappings[0].owner_generation = 0;
    task.mappings[0].stage2_lease = None;
    {
        let mut inventory = task.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            key,
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(41),
                stage2_base: key.0,
                stage2_length: key.1,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr: 0x1000,
                    generation: 0,
                },
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(frame, 1);
            frames.extent_references.insert((frame, key.0, key.1), 1);
            frames.stage2_references.insert(key, 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([93; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(93)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }
    register_carrier_lease(GlobalFrameStage2Lease::fixed(key.0, key.1), 0x1000);
    let frames = std::sync::Arc::clone(&task.frame_inventory.lock().frames);

    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("retire the backend's final known row");

    {
        let frames = frames.lock();
        assert!(!frames.stage2_references.contains_key(&key));
        assert!(
            frames.authority_retained_stage2.contains(&key),
            "kernel/backend disagreement must survive a zero backend count",
        );
    }
    drop(HvpatchCarrierMmAuthority::LeaseTest {
        stage2_lease_keys: vec![key],
        frames: std::sync::Arc::clone(&frames),
    });
    assert!(
        carrier_stage2_leases().lock().contains_key(&key),
        "carrier teardown must not override authority-retained physical ownership",
    );
    assert!(
        !frames.lock().authority_retained_stage2.contains(&key),
        "carrier teardown consumes the one-shot authority-retained handoff",
    );
    assert!(
        HvfVmState::retire_stage2_candidate_if_unreferenced(&frames, key, || {
            HvfVmState::retire_stage2_extent_from_mappings(
                &mut TaskMappingIndex::new(),
                key.0,
                key.1,
            )
        })
        .unwrap(),
    );
    assert!(!carrier_stage2_leases().lock().contains_key(&key));
}

/// Terminal retirement must read the mapping rows a bounded number of
/// times, not once per inventory extent.
///
/// The direct per-extent scan is the 2026-09-08 exit residual: a CPython
/// `test_compile` guest retires 33,471 inventory extents against 33,478
/// mapping rows, so the executor that owns the container's `exit_group`
/// spends minutes inside `retire_task_state_process_mappings_inner`
/// between its `Saved` receipt and `settle_exited`. Nothing deadlocks —
/// the container job's result is simply never published while that sweep
/// runs, which the process-graph liveness sink reports as "1 container
/// job(s) unpublished with 0 live task(s), 1 live thread(s)" and turns
/// into `carrick run` rc 125.
///
/// Counting rows rather than seconds keeps the bar deterministic: the
/// pre-index code visits `EXTENTS * EXTENTS` rows here, the indexed code
/// one pass.
#[test]
fn process_retirement_reads_mapping_rows_once_not_once_per_inventory_extent() {
    const EXTENTS: usize = 600;
    const EXTENT_SIZE: u64 = 0x4000;

    let mut task = hvpatch_task_state_test_fixture(12, 0x1_0000_0000, 12);
    task.cow_authority = Some(std::sync::Arc::new(TestFrameMappingCount::Exact(2)));
    task.mappings.clear();

    let mut guards = Vec::with_capacity(EXTENTS);
    let mut hosts = Vec::with_capacity(EXTENTS);
    let mut rows = Vec::with_capacity(EXTENTS);
    let mut extents = Vec::with_capacity(EXTENTS);
    for index in 0..EXTENTS {
        let key = next_test_physical_key(EXTENT_SIZE);
        let generation = next_global_frame_owner_generation();
        let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            EXTENT_SIZE as usize,
            crate::host_mapping::HostMappingKind::FrameCow,
        )
        .unwrap();
        let host_addr = host.as_ptr();
        let start = 0x1_0000_0000 + index as u64 * EXTENT_SIZE;
        rows.push(HvfMappedRegion {
            start,
            end: start + EXTENT_SIZE,
            ipa: key.0,
            physical_ipa: key.0,
            host_addr,
            size: EXTENT_SIZE as usize,
            physical_size: EXTENT_SIZE as usize,
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            structural_owner: None,
            stage2_lease: Some(GlobalFrameStage2Lease::fixed(key.0, key.1)),
            is_dynamic_alias: false,
            sharing: GuestMappingSharing::Private,
            guest_writable: true,
            shared_key_base: 0,
            shared_key_offset: 0,
            owner_generation: generation,
        });
        extents.push((index, key, generation, host_addr as usize));
        let owner = GlobalFrameHostOwner::new(
            GlobalFrameStage2Lease::fixed(key.0, key.1),
            host,
            u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            generation,
            key.0,
            key.1,
        );
        assert!(
            global_frame_host_owners()
                .lock()
                .insert(key, GlobalFrameOwnerEntry::Live(std::sync::Arc::new(owner)))
                .is_none(),
            "publication must displace no predecessor"
        );
        guards.push(TestGlobalFrameOwnerGuard { key, generation });
        hosts.push(host_addr);
    }
    task.mappings.extend(rows);

    {
        let mut inventory = task.frame_inventory.lock();
        inventory.initialized = true;
        for &(index, key, generation, host_addr) in &extents {
            let frame = carrick_hal::FrameId::from_kernel_allocation(id(1 + index as u64));
            let mapping = carrick_hal::MappingId::from_kernel_allocation(id(1 + index as u64));
            inventory.extents.insert(
                key,
                InventoryExtent {
                    frame,
                    mapping,
                    backing: InventoryBackingIdentity::Private(1 + index as u64),
                    stage2_base: key.0,
                    stage2_length: key.1,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr,
                        generation,
                    },
                },
            );
            let mut frames = inventory.frames.lock();
            frames.references.insert(frame, 1);
            frames.extent_references.insert((frame, key.0, key.1), 1);
            frames.stage2_references.insert(key, 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(4 * EXTENTS).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([93; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(93)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }

    let before = hot_path_rows_scanned(HotPathScan::TaskMappings);
    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("stage terminal retirement over a many-extent inventory");
    let scanned = hot_path_rows_scanned(HotPathScan::TaskMappings) - before;

    let extents = EXTENTS as u64;
    assert!(
        scanned <= 8 * extents,
        "terminal retirement over {extents} inventory extents visited {scanned} \
             mapping rows; the containment question must be indexed once per \
             retirement, not re-asked against every row per extent (the rescan \
             shape visits {} rows and is the exit residual)",
        extents * extents
    );
    drop(guards);
}

#[test]
fn process_retirement_retires_the_exact_last_authoritative_mapping() {
    let (mut task, frame, _, _key, _guard) =
        process_retirement_task(TestFrameMappingCount::Exact(1));

    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("stage last-owner process-terminal retirement");
    let commit = HvfVmState::take_task_state_retirement_inventory(&mut task)
        .expect("last-owner process-terminal retirement commit");
    assert!(commit.batch().events().iter().any(|event| {
        matches!(
            event,
            carrick_hal::FrameInventoryEvent::RetireFrame {
                frame: retired,
                ..
            } if *retired == frame
        )
    }));
}

#[test]
fn process_retirement_fails_when_the_authoritative_mapping_count_is_unavailable() {
    let (mut task, _, _, _key, _guard) = process_retirement_task(TestFrameMappingCount::Error);

    let error = HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect_err("an unavailable VM-wide mapping count must fail retirement");
    assert!(
        error.to_string().contains("injected mapping-count failure"),
        "the authority-query cause must remain visible: {error}",
    );
    assert!(
        HvfVmState::take_task_state_retirement_inventory(&mut task).is_none(),
        "a failed authority query must not publish a retirement commit",
    );
}

#[test]
fn process_retirement_rejects_a_recycled_owner_generation() {
    let (mut task, _frame, _mapping, key, _guard) =
        process_retirement_task(TestFrameMappingCount::Exact(1));
    let stale_host = task.mappings[0].host_addr as usize;
    let stale_generation = task.mappings[0].owner_generation;

    let successor_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        key.1 as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .unwrap();
    let successor_host_addr = successor_host.as_ptr() as usize;
    let succ_gen = next_global_frame_owner_generation();
    let successor = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(key.0, key.1),
        successor_host,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        succ_gen,
        key.0,
        key.1,
    );
    let successor_generation = successor.generation();
    assert_ne!(stale_generation, successor_generation);
    global_frame_host_owners().lock().insert(
        key,
        GlobalFrameOwnerEntry::Live(std::sync::Arc::new(successor)),
    );

    let alias = |start, host_addr, owner_generation| AliasBacking {
        start,
        ipa: key.0,
        host_addr,
        size: key.1 as usize,
        physical_ipa: key.0,
        physical_host_addr: host_addr,
        physical_size: key.1 as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        guest_writable: true,
        sharing: GuestMappingSharing::GlobalShared,
        ownership_scope: AliasOwnershipScope::Global,
        inventory_backing: InventoryBackingIdentity::SharedAnon(owner_generation),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation,
    };
    let stale_alias = alias(key.0 + 0x1000_0000, stale_host, stale_generation);
    let successor_alias = alias(
        key.0 + 0x2000_0000,
        successor_host_addr,
        successor_generation,
    );
    alias_registry()
        .lock()
        .extend([stale_alias, successor_alias]);

    task.mappings[0].stage2_lease = None;

    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("process-terminal retirement should succeed");
    assert_eq!(
        global_frame_host_owner_generation(key.0, key.1),
        successor_generation,
        "stale process cleanup must not retire a newer owner of the recycled key",
    );
    {
        let registry = alias_registry().lock();
        assert!(
            !registry.contains(&stale_alias),
            "stale logical aliases must retire with the superseded inventory owner"
        );
        assert!(
            registry.contains(&successor_alias),
            "successor-generation aliases must remain live"
        );
    }
    alias_registry()
        .lock()
        .retain(|alias| *alias != successor_alias);
    let successor = global_frame_host_owners()
        .lock()
        .remove(&key)
        .expect("remove successor owner after test");
    drop(successor);
}

#[test]
fn process_retirement_uses_inventory_owner_identity_not_stale_mapping_rows() {
    let (mut task, _frame, _mapping, key, _guard) =
        process_retirement_task(TestFrameMappingCount::Exact(1));
    let live_generation = task.mappings[0].owner_generation;
    assert_ne!(live_generation, 0);

    for stale_generation in [
        live_generation.saturating_sub(1),
        live_generation.saturating_sub(2),
    ] {
        let mut stale = hvpatch_task_state_test_fixture(13, key.0, 13)
            .mappings
            .into_values()
            .next_back()
            .unwrap();
        stale.start = key.0;
        stale.end = key.0 + key.1;
        stale.ipa = key.0;
        stale.physical_ipa = key.0;
        stale.host_addr = 0x1_0000usize as *mut u8;
        stale.size = key.1 as usize;
        stale.physical_size = key.1 as usize;
        stale.owner_generation = stale_generation;
        stale.is_dynamic_alias = true;
        stale.stage2_lease = None;
        task.mappings.insert(stale);
    }

    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("the inventory's exact live owner must outrank stale descriptor rows");
    assert_eq!(
        global_frame_host_owner_generation(key.0, key.1),
        0,
        "terminal retirement must remove the exact owner named by inventory",
    );
}

#[test]
fn process_retirement_uses_inventory_owner_when_task_local_rows_are_absent() {
    let (mut task, frame, mapping, key, _guard) =
        process_retirement_task(TestFrameMappingCount::Exact(1));
    let live = global_frame_host_owner_identity(key.0, key.1)
        .expect("the inventory owner must remain globally authenticated");

    // A detached task-only backend is reconstructed from the MM authority's
    // publication snapshot. Runtime-created extents remain authoritative in
    // the inventory but need not have a duplicate row in that snapshot.
    // The carrier/global owner retains the physical lease in this state.
    task.mappings[0].stage2_lease = None;
    task.mappings.clear();

    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("the exact inventory/global owner pair is sufficient authority");
    let commit = HvfVmState::take_task_state_retirement_inventory(&mut task)
        .expect("rowless process-terminal retirement commit");
    assert!(commit.batch().events().iter().any(|event| {
        matches!(
            event,
            carrick_hal::FrameInventoryEvent::UnmapMapping {
                mapping: retired,
                ..
            } if *retired == mapping
        )
    }));
    assert!(commit.batch().events().iter().any(|event| {
        matches!(
            event,
            carrick_hal::FrameInventoryEvent::RetireFrame {
                frame: retired,
                ..
            } if *retired == frame
        )
    }));
    assert_eq!(
        global_frame_host_owner_identity(key.0, key.1),
        None,
        "retirement must consume the exact globally authenticated owner {live:?}",
    );
}

#[test]
fn process_retirement_rejects_rowless_inventory_not_owned_by_the_retiring_mm() {
    let (mut task, _frame, _mapping, key, _guard) =
        process_retirement_task(TestFrameMappingCount::ExactButMappingNotLive(1));
    let live =
        global_frame_host_owner_identity(key.0, key.1).expect("the physical owner starts live");
    task.mappings[0].stage2_lease = None;
    task.mappings.clear();

    let error = HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect_err("physical identity alone must not authorize another MM's mapping");
    assert!(
        error.to_string().contains("not exact-live for retiring mm"),
        "unexpected rowless MM-authentication error: {error}"
    );
    assert_eq!(
        global_frame_host_owner_identity(key.0, key.1),
        Some(live),
        "failed MM authentication must not consume the physical owner",
    );
}

#[test]
fn process_retirement_rejects_matching_generation_with_wrong_host_pointer() {
    let (mut task, _frame, _mapping, key, _guard) =
        process_retirement_task(TestFrameMappingCount::Exact(1));
    let live = global_frame_host_owner_identity(key.0, key.1).expect("test owner is published");
    let wrong_host = live.0 + key.1 as usize;
    task.mappings[0].host_addr = wrong_host as *mut u8;
    task.frame_inventory
        .lock()
        .extents
        .get_mut(&key)
        .expect("inventory extent")
        .stage2_owner
        .host_addr = wrong_host;

    let error = HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect_err("a generation match must not hide a host-pointer mismatch");
    assert!(
        error.to_string().contains("owner pointer drifted"),
        "the exact identity mismatch must remain visible: {error}"
    );
    assert_eq!(
        global_frame_host_owner_identity(key.0, key.1),
        Some(live),
        "failed authentication must leave the live owner untouched",
    );
}

#[test]
fn global_frame_host_owner_rejects_an_unmapped_lease() {
    let key = next_test_physical_key(0x4000);
    let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        key.1 as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate owner backing");
    let error = register_global_frame_host_owner(
        GlobalFrameStage2Lease::fixed(key.0, key.1),
        host_mapping,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
    )
    .expect_err("an unmapped lease must never become a global frame owner");
    assert!(
        error.to_string().contains("mapped=false"),
        "rejection must identify the missing stage-2 publication: {error}"
    );
    assert!(
        !global_frame_host_owners().lock().contains_key(&key),
        "rejected owner must not be published"
    );
}

#[test]
fn stage_mapping_owner_rejection_leaves_all_reference_maps_unchanged() {
    let key = next_test_physical_key(0x4000);
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        key.1 as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate live owner backing");
    let live_host_addr = host.as_ptr() as usize;
    let live_gen = next_global_frame_owner_generation();
    let live = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(key.0, key.1),
        host,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        live_gen,
        key.0,
        key.1,
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .insert(key, GlobalFrameOwnerEntry::Live(std::sync::Arc::new(live)))
            .is_none()
    );

    let frame = carrick_hal::FrameId::from_kernel_allocation(id(301));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(302));
    let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(id(303));
    let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
    let mut reservation = carrick_hal::FrameInventoryReservation::from_kernel_candidates(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([0x33; 32]),
        carrick_hal::FrameInventoryBatch::prepare(transaction, capacity).unwrap(),
        vec![frame],
        vec![mapping],
    );
    let mut inventory = HvpatchFrameInventory::default();
    let error = HvfVmState::stage_mapping(
        &mut inventory,
        &mut reservation,
        InventoryMappingStage {
            gpa: key.0,
            length: key.1,
            permissions: carrick_hal::MemPerms {
                read: true,
                write: true,
                exec: false,
            },
            backing: InventoryBackingIdentity::Private(301),
            inherited_frame: None,
            stage2_lease: Some(key),
            // A generation-zero publication must not borrow a live global
            // owner merely because its numeric lease key and host pointer
            // match.
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: live_host_addr,
                generation: 0,
            },
        },
    )
    .expect_err("owner mismatch must reject the inventory publication");
    assert!(error.to_string().contains("owner is not live"));
    assert!(inventory.extents.is_empty());
    let frames = inventory.frames.lock();
    assert!(frames.references.is_empty());
    assert!(frames.extent_references.is_empty());
    assert!(frames.stage2_references.is_empty());
    drop(frames);

    drop(global_frame_host_owners().lock().remove(&key));
}

#[test]
fn retained_private_reuse_requires_and_preserves_exact_owner_generation() {
    let key = next_test_physical_key(0x4000);
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        key.1 as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("allocate live owner backing");
    let host_addr = host.as_ptr() as usize;
    let generation = next_global_frame_owner_generation();
    let owner = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(key.0, key.1),
        host,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        generation,
        key.0,
        key.1,
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .insert(key, GlobalFrameOwnerEntry::Live(std::sync::Arc::new(owner)))
            .is_none()
    );

    let source = AliasBacking {
        start: 0x5000_0000,
        ipa: key.0,
        host_addr,
        size: 0x1000,
        physical_ipa: key.0,
        physical_host_addr: host_addr,
        physical_size: key.1 as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWriteExec),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::ContainerRoot(ContainerRootToken::ROOT),
        inventory_backing: InventoryBackingIdentity::Private(401),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: generation.saturating_sub(1),
    };
    let mut stale_registry = AliasRegistry::default();
    stale_registry.push(source);
    assert!(
        retained_private_reuse_alias_fragment(
            &stale_registry,
            source.start + 0x1000,
            key.0 + 0x1000,
            0x1000,
            None,
            ContainerRootToken::ROOT,
        )
        .is_none(),
        "a stale source must not launder itself through the live successor owner"
    );

    let exact = AliasBacking {
        owner_generation: generation,
        ..source
    };
    let mut exact_registry = AliasRegistry::default();
    exact_registry.push(exact);
    let reused = retained_private_reuse_alias_fragment(
        &exact_registry,
        exact.start + 0x1000,
        key.0 + 0x1000,
        0x1000,
        None,
        ContainerRootToken::ROOT,
    )
    .expect("the exact live source may republish its missing semantic fragment");
    assert_eq!(reused.owner_generation, generation);
    assert_eq!(reused.physical_host_addr, host_addr);

    drop(global_frame_host_owners().lock().remove(&key));
}

#[test]
fn partial_unmap_preserves_stale_generation_on_both_local_fragments() {
    let start = 0x6000_0000;
    let ipa = 0xa200_0000_0000;
    let mut mappings = vec![HvfMappedRegion {
        start,
        end: start + 0xc000,
        ipa,
        physical_ipa: ipa,
        host_addr: 0x4000_0000usize as *mut u8,
        size: 0xc000,
        physical_size: 0xc000,
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
        owner_generation: 77,
    }];

    split_local_mapping_rows_for_unmap(&mut mappings, start + 0x4000, 0x4000);
    mappings.sort_by_key(|mapping| mapping.start);
    assert_eq!(mappings.len(), 2);
    assert_eq!(mappings[0].owner_generation, 77);
    assert_eq!(mappings[1].owner_generation, 77);
    assert_eq!(
        (mappings[0].start, mappings[0].end),
        (start, start + 0x4000)
    );
    assert_eq!(
        (mappings[1].start, mappings[1].end),
        (start + 0x8000, start + 0xc000)
    );
}

#[test]
fn exec_replacement_terminal_retirement_releases_exact_owner_and_reuses_lease() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let mut lease =
        GlobalFrameStage2Lease::reserve(0x4000, 0x4000).expect("reserve global frame IPA");
    let key = lease.key();
    assert!(
        global_frame_ipa_allocator().lock().is_live(key.0, key.1),
        "allocator must report reserved IPA as live"
    );

    let guest_mapping = GuestMapping {
        guest_start: 0x40_0000,
        mapped_size: key.1,
        ipa_start: key.0,
        perms: carrick_mem::elf::SegmentPerms {
            read: true,
            write: true,
            execute: false,
        },
        shared: false,
        image: std::sync::Arc::new(vec![0u8; key.1 as usize]),
        payload_size: key.1,
        offset_in_mapping: 0,
        private_file_backing: None,
    };

    let mut region = prepare_exec_region_raw(&guest_mapping).expect("prepare exec region");
    lease.mark_mapped();
    // Call the real production publication helper which registers the global
    // frame host owner and stamps region.owner_generation.
    let owner_generation =
        publish_exec_region_host_owner(&mut region, lease).expect("publish exec region host owner");
    assert_eq!(
        region.owner_generation, owner_generation,
        "helper must stamp the registered owner generation on the region"
    );
    let stage2_owner = mapped_region_stage2_owner_identity(&region)
        .expect("published exec region has a physical owner identity");
    disarm_test_owner_stage2_unmap(key, owner_generation);

    let frame = carrick_hal::FrameId::from_kernel_allocation(id(41));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(42));
    let mut task = hvpatch_task_state_test_fixture(12, key.0, 12);
    task.cow_authority = Some(std::sync::Arc::new(TestFrameMappingCount::Exact(1)));
    task.mappings = TaskMappingIndex::from_region(region);
    {
        let mut inventory = task.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            key,
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(41),
                stage2_base: key.0,
                stage2_length: key.1,
                stage2_owner,
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(frame, 1);
            frames.extent_references.insert((frame, key.0, key.1), 1);
            frames.stage2_references.insert(key, 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([93; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(93)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }

    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("process-terminal retirement should succeed");

    assert_eq!(
        global_frame_host_owner_generation(key.0, key.1),
        0,
        "exact owner must be absent after terminal retirement"
    );
    assert!(
        !global_frame_host_owners().lock().contains_key(&key),
        "owner entry must be removed from global owners map"
    );
    assert!(
        !global_frame_ipa_allocator().lock().is_live(key.0, key.1),
        "allocator-reserved IPA must be freed after terminal retirement"
    );

    // Prove the allocator can re-allocate a fresh lease and register a successor owner
    let mut lease2 = GlobalFrameStage2Lease::reserve(0x4000, 0x4000)
        .expect("allocator must allow reserving fresh lease after retirement");
    let key2 = lease2.key();
    assert_eq!(
        key2, key,
        "terminal retirement must make the exact reusable IPA extent available again"
    );
    let mut guest_mapping2 = guest_mapping;
    guest_mapping2.ipa_start = key2.0;
    let mut region2 = prepare_exec_region_raw(&guest_mapping2).expect("prepare second region");
    lease2.mark_mapped();
    let gen2 = publish_exec_region_host_owner(&mut region2, lease2)
        .expect("must register successor owner without collision");
    assert_ne!(gen2, owner_generation);
    disarm_test_owner_stage2_unmap(key2, gen2);
    assert!(retire_global_frame_host_owner(key2.0, key2.1).is_retired());
}

#[test]
fn fork_independent_kernel_state_publication_registers_global_frame_owner_and_retires_cleanly() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let mut lease =
        GlobalFrameStage2Lease::reserve(0x4000, 0x4000).expect("reserve global frame IPA");
    let key = lease.key();
    assert!(
        global_frame_ipa_allocator().lock().is_live(key.0, key.1),
        "allocator must report reserved IPA as live"
    );
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate kernel state host mapping");
    let host_addr = host.as_ptr() as usize;

    // Register the reusable global frame lease as would happen during fork commit
    lease.mark_test_mapped_without_backend();
    let owner_generation = register_global_frame_host_owner(
        lease,
        host,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
    )
    .expect("register global frame host owner");
    assert!(owner_generation > 0);
    assert_eq!(
        global_frame_host_owner_generation(key.0, key.1),
        owner_generation
    );
    disarm_test_owner_stage2_unmap(key, owner_generation);

    // Build a task state with unowned runtime region holding the stamped owner_generation
    let mut task = hvpatch_task_state_test_fixture(21, key.0, 21);
    task.cow_authority = Some(std::sync::Arc::new(TestFrameMappingCount::Exact(1)));
    task.mappings = TaskMappingIndex::from_region(HvfMappedRegion {
        start: 0x7fff_0000,
        ipa: key.0,
        physical_ipa: key.0,
        end: 0x7fff_4000,
        host_addr: host_addr as *mut u8,
        size: 0x4000,
        physical_size: 0x4000,
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
        owner_generation,
    });

    let frame = carrick_hal::FrameId::from_kernel_allocation(id(201));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(202));
    {
        let mut inventory = task.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            key,
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(201),
                stage2_base: key.0,
                stage2_length: key.1,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr,
                    generation: owner_generation,
                },
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(frame, 1);
            frames.extent_references.insert((frame, key.0, key.1), 1);
            frames.stage2_references.insert(key, 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([94; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(94)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }

    HvfVmState::retire_task_state_process_mappings(&mut task)
        .expect("detached child retirement with registered global frame owner should succeed");

    assert_eq!(
        global_frame_host_owner_generation(key.0, key.1),
        0,
        "exact owner must be absent after terminal retirement"
    );
    assert!(
        !global_frame_host_owners().lock().contains_key(&key),
        "owner entry must be removed from global owners map"
    );
    assert!(
        !global_frame_ipa_allocator().lock().is_live(key.0, key.1),
        "allocator-reserved IPA must be freed after terminal retirement"
    );

    // Prove second container can reuse this exact lease without collision or error
    let mut lease2 = GlobalFrameStage2Lease::reserve(0x4000, 0x4000)
        .expect("reserve global frame IPA for second container");
    let key2 = lease2.key();
    assert_eq!(key2, key);
    let host2 = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate second container kernel state host mapping");
    lease2.mark_test_mapped_without_backend();
    let gen2 = register_global_frame_host_owner(
        lease2,
        host2,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
    )
    .expect("register second container global frame host owner");
    assert_ne!(gen2, owner_generation);
    disarm_test_owner_stage2_unmap(key2, gen2);
    assert!(retire_global_frame_host_owner(key2.0, key2.1).is_retired());
}

#[test]
fn unowned_global_frame_mapping_authenticates_and_retires_against_registered_owner_and_rejects_stale_generation()
 {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let mut lease =
        GlobalFrameStage2Lease::reserve(0x4000, 0x4000).expect("reserve global frame IPA");
    let key = lease.key();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate kernel state host mapping");
    let host_addr = host.as_ptr() as usize;

    lease.mark_test_mapped_without_backend();
    let owner_generation = register_global_frame_host_owner(
        lease,
        host,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
    )
    .expect("register global frame host owner");
    assert!(owner_generation > 0);

    // 1. Negative test: generation == 0 fails because reusable global frame extent requires owner
    let mut task_gen0 = hvpatch_task_state_test_fixture(22, key.0, 22);
    task_gen0.cow_authority = Some(std::sync::Arc::new(TestFrameMappingCount::Exact(1)));
    task_gen0.mappings = TaskMappingIndex::from_region(HvfMappedRegion {
        start: 0x7fff_0000,
        ipa: key.0,
        physical_ipa: key.0,
        end: 0x7fff_4000,
        host_addr: host_addr as *mut u8,
        size: 0x4000,
        physical_size: 0x4000,
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
    });
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(203));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(204));
    {
        let mut inventory = task_gen0.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            key,
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(203),
                stage2_base: key.0,
                stage2_length: key.1,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr,
                    generation: 0,
                },
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(frame, 1);
            frames.extent_references.insert((frame, key.0, key.1), 1);
            frames.stage2_references.insert(key, 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([95; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(95)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }
    let err = HvfVmState::retire_task_state_process_mappings(&mut task_gen0).unwrap_err();
    assert!(
        matches!(err, TrapError::Hypervisor(ref msg) if msg.contains("unexpectedly has live global owner")),
        "expected unowned retirement error for generation 0 with live owner, got: {err}"
    );

    // 2. Negative test: absent owner fails authentication
    let absent_key = (key.0 + 0x10_0000, key.1);
    let mut task_absent = hvpatch_task_state_test_fixture(23, absent_key.0, 23);
    task_absent.cow_authority = Some(std::sync::Arc::new(TestFrameMappingCount::Exact(1)));
    task_absent.mappings = TaskMappingIndex::from_region(HvfMappedRegion {
        start: 0x7fff_0000,
        ipa: absent_key.0,
        physical_ipa: absent_key.0,
        end: 0x7fff_4000,
        host_addr: host_addr as *mut u8,
        size: 0x4000,
        physical_size: 0x4000,
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
        owner_generation: 42,
    });
    {
        let mut inventory = task_absent.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            absent_key,
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(203),
                stage2_base: absent_key.0,
                stage2_length: absent_key.1,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr,
                    generation: 42,
                },
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(frame, 1);
            frames
                .extent_references
                .insert((frame, absent_key.0, absent_key.1), 1);
            frames.stage2_references.insert(absent_key, 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([96; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(96)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }
    let err = HvfVmState::retire_task_state_process_mappings(&mut task_absent).unwrap_err();
    assert!(
        matches!(err, TrapError::Hypervisor(ref msg) if msg.contains("the owner is absent")),
        "expected absent owner generation error, got: {err}"
    );

    // 3. Positive test: exact live owner generation authenticates and unmaps cleanly
    disarm_test_owner_stage2_unmap(key, owner_generation);
    let mut task_valid = hvpatch_task_state_test_fixture(24, key.0, 24);
    task_valid.cow_authority = Some(std::sync::Arc::new(TestFrameMappingCount::Exact(1)));
    task_valid.mappings = TaskMappingIndex::from_region(HvfMappedRegion {
        start: 0x7fff_0000,
        ipa: key.0,
        physical_ipa: key.0,
        end: 0x7fff_4000,
        host_addr: host_addr as *mut u8,
        size: 0x4000,
        physical_size: 0x4000,
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
        owner_generation,
    });
    {
        let mut inventory = task_valid.frame_inventory.lock();
        inventory.initialized = true;
        inventory.extents.insert(
            key,
            InventoryExtent {
                frame,
                mapping,
                backing: InventoryBackingIdentity::Private(203),
                stage2_base: key.0,
                stage2_length: key.1,
                stage2_owner: InventoryStage2OwnerIdentity {
                    host_addr,
                    generation: owner_generation,
                },
            },
        );
        {
            let mut frames = inventory.frames.lock();
            frames.references.insert(frame, 1);
            frames.extent_references.insert((frame, key.0, key.1), 1);
            frames.stage2_references.insert(key, 1);
        }
        let capacity = carrick_hal::FrameEventCapacity::for_event_count(2).unwrap();
        inventory.retirement_reservation = Some(
            carrick_hal::FrameInventoryReservation::from_kernel_candidates(
                carrick_hal::FrameInventoryProvenance::from_kernel_entropy([97; 32]),
                carrick_hal::FrameInventoryBatch::prepare(
                    carrick_hal::KernelTransactionId::from_kernel_allocation(id(97)),
                    capacity,
                )
                .unwrap(),
                Vec::new(),
                Vec::new(),
            ),
        );
    }
    HvfVmState::retire_task_state_process_mappings(&mut task_valid)
        .expect("exact live owner generation must authenticate and retire cleanly");
    assert_eq!(global_frame_host_owner_generation(key.0, key.1), 0);
}

#[test]
fn failed_stage2_unmap_preserves_custody_and_succeeds_on_retry() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let mut lease =
        GlobalFrameStage2Lease::reserve(0x4000, 0x4000).expect("reserve global frame IPA");
    let key = lease.key();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate kernel state host mapping");
    let host_addr = host.as_ptr() as usize;

    let rc = unsafe { inventory_hv_vm_map(host.as_ptr().cast(), key.0, key.1 as usize, 7) };
    assert_eq!(rc, 0);
    lease.mark_mapped();

    let owner_generation = register_global_frame_host_owner(
        lease,
        host,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
    )
    .expect("register global frame host owner");
    assert!(owner_generation > 0);
    assert!(ScopedStage2MapTestStub::is_mapped(key.0, key.1 as usize));
    assert!(alias_backing_is_live(host_addr));
    assert_eq!(
        global_frame_host_owner_identity(key.0, key.1),
        Some((host_addr, owner_generation)),
    );

    // Injected unmap failure during retirement
    _stage2_stub.set_fail_next_unmap(true);
    let outcome = retire_global_frame_host_owner_if_generation(key.0, key.1, owner_generation);
    assert!(
        matches!(outcome, GlobalFrameRetirementOutcome::RetryPending { ipa, length, generation, .. } if ipa == key.0 && length == key.1 && generation == owner_generation),
        "unmap failure must return RetryPending outcome"
    );
    {
        let entry = global_frame_host_owners()
            .lock()
            .get(&key)
            .cloned()
            .expect("pending entry must remain in authoritative directory");
        assert!(
            entry.is_pending(),
            "owner entry must be in RetirementPending state"
        );
        assert_eq!(entry.owner().generation(), owner_generation);
        assert_eq!(entry.owner().host_addr(), host_addr);
        assert!(matches!(
            entry,
            GlobalFrameOwnerEntry::RetirementPending {
                in_flight: false,
                ..
            }
        ));
    }
    assert_eq!(
        global_frame_host_owner_identity(key.0, key.1),
        None,
        "pending custody must not authenticate as a live owner identity",
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(key.0, key.1 as usize),
        "stage-2 mapping must remain installed after unmap failure"
    );
    assert!(
        alias_backing_is_live(host_addr),
        "host mapping must remain live after unmap failure"
    );

    // Duplicate / collision registration attempt must fail closed without replacing or dropping prior custody
    let collision_host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate collision host mapping");
    let mut collision_lease = GlobalFrameStage2Lease::fixed(key.0, key.1);
    collision_lease.mark_test_mapped_without_backend();
    let collision_res = register_global_frame_host_owner(
        collision_lease,
        collision_host,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
    );
    assert!(
        matches!(collision_res, Err(TrapError::Hypervisor(ref msg)) if msg.contains("collision")),
        "collision must fail closed: {collision_res:?}",
    );
    assert_eq!(
        global_frame_host_owner_identity(key.0, key.1),
        None,
        "collision must not republish pending custody as a live identity",
    );
    assert!(matches!(
        global_frame_host_owners().lock().get(&key),
        Some(GlobalFrameOwnerEntry::RetirementPending {
            owner,
            in_flight: false,
            ..
        }) if owner.host_addr() == host_addr && owner.generation() == owner_generation
    ));

    // Mismatched generation on retry fails with MismatchedGeneration and preserves custody
    let wrong_gen = owner_generation.wrapping_add(1);
    let mismatch = retire_global_frame_host_owner_if_generation(key.0, key.1, wrong_gen);
    assert!(
        matches!(mismatch, GlobalFrameRetirementOutcome::MismatchedGeneration { current_generation, expected_generation, .. } if current_generation == owner_generation && expected_generation == wrong_gen)
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .get(&key)
            .is_some_and(|e| e.is_pending()),
        "failed custody must remain intact on generation mismatch"
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(key.0, key.1 as usize),
        "stage-2 mapping must still remain installed"
    );
    assert!(
        alias_backing_is_live(host_addr),
        "host mapping must still remain live"
    );

    // Retry with correct generation succeeds when hypervisor unmap succeeds
    let retry_outcome =
        retire_global_frame_host_owner_if_generation(key.0, key.1, owner_generation);
    assert!(
        matches!(retry_outcome, GlobalFrameRetirementOutcome::RetiredUnmapped { ipa, length, generation } if ipa == key.0 && length == key.1 && generation == owner_generation),
        "retry with matching generation must succeed"
    );
    assert!(
        !global_frame_host_owners().lock().contains_key(&key),
        "directory must be cleared after successful retry"
    );
    assert_eq!(
        global_frame_host_owner_identity(key.0, key.1),
        None,
        "authoritative identity must be removed after successful retirement",
    );
    assert!(
        !ScopedStage2MapTestStub::is_mapped(key.0, key.1 as usize),
        "stage-2 mapping must be unmapped after successful retirement"
    );
    assert!(
        !alias_backing_is_live(host_addr),
        "host mapping must be unmapped after successful retirement"
    );
}

#[test]
fn shared_arc_global_frame_owner_transitions_to_pending_until_all_holders_drop() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let mut lease =
        GlobalFrameStage2Lease::reserve(0x4000, 0x4000).expect("reserve global frame IPA");
    let key = lease.key();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate kernel state host mapping");
    let host_addr = host.as_ptr() as usize;

    let rc = unsafe { inventory_hv_vm_map(host.as_ptr().cast(), key.0, key.1 as usize, 7) };
    assert_eq!(rc, 0);
    lease.mark_mapped();

    let owner_generation = register_global_frame_host_owner(
        lease,
        host,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
    )
    .expect("register global frame host owner");

    // Acquire an active typed reader pin.
    let reader_ref = global_frame_host_owners()
        .lock()
        .get(&key)
        .expect("owner entry")
        .owner()
        .pin()
        .expect("pin exact owner record");

    // Attempt retirement while reader holds Arc: must NOT report Retired!
    let outcome = retire_global_frame_host_owner_if_generation(key.0, key.1, owner_generation);
    assert!(
        matches!(
            outcome,
            GlobalFrameRetirementOutcome::DeferredActivePins { .. }
        ),
        "retirement while a typed pin is held must defer, never retire",
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .get(&key)
            .is_some_and(|e| e.is_pending()),
        "owner must be placed in RetirementPending",
    );
    assert!(
        ScopedStage2MapTestStub::is_mapped(key.0, key.1 as usize),
        "stage-2 mapping must remain installed while reader is active",
    );
    assert!(
        alias_backing_is_live(host_addr),
        "host backing must remain live while reader is active",
    );

    // Drop foreign reader reference
    drop(reader_ref);

    // Safe-point drain now successfully completes retirement
    drain_and_retry_pending_global_frame_retirements()
        .expect("drain must succeed after foreign reference drop");
    assert!(
        global_frame_host_owners().lock().is_empty(),
        "directory must be drained after retry",
    );
    assert!(
        !ScopedStage2MapTestStub::is_mapped(key.0, key.1 as usize),
        "stage-2 mapping must be unmapped after drain",
    );
    assert!(
        !alias_backing_is_live(host_addr),
        "host backing must be unmapped after drain",
    );
}

#[test]
fn explicit_live_vm_safe_point_retries_pending_retirements_or_reports_failure() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let _stage2_stub = ScopedStage2MapTestStub::enable();
    let mut lease =
        GlobalFrameStage2Lease::reserve(0x4000, 0x4000).expect("reserve global frame IPA");
    let key = lease.key();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate kernel state host mapping");

    let rc = unsafe { inventory_hv_vm_map(host.as_ptr().cast(), key.0, key.1 as usize, 7) };
    assert_eq!(rc, 0);
    lease.mark_mapped();

    let owner_generation = register_global_frame_host_owner(
        lease,
        host,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
    )
    .expect("register global frame host owner");

    // Injected unmap failure
    _stage2_stub.set_fail_next_unmap(true);
    let _ = retire_global_frame_host_owner_if_generation(key.0, key.1, owner_generation);
    assert!(
        global_frame_host_owners()
            .lock()
            .get(&key)
            .is_some_and(|e| e.is_pending()),
        "owner must be in RetirementPending",
    );

    // Persistent failure during an explicit live-VM retry remains pending.
    _stage2_stub.set_fail_next_unmap(true);
    let drain_err = drain_and_retry_pending_global_frame_retirements();
    assert!(
        drain_err.is_err(),
        "safe-point retry must report persistent unmap failure",
    );

    // Clearing unmap failure allows the explicit safe point to complete.
    let drain_ok = drain_and_retry_pending_global_frame_retirements();
    assert!(drain_ok.is_ok(), "drain must succeed when unmap succeeds");
    assert!(global_frame_host_owners().lock().is_empty());
}

#[test]
fn cow_split_keeps_stage2_when_the_authority_keeps_the_old_frame_live() {
    let old_frame = carrick_hal::FrameId::from_kernel_allocation(id(51));
    let old_mapping = carrick_hal::MappingId::from_kernel_allocation(id(52));
    let new_frame = carrick_hal::FrameId::from_kernel_allocation(id(53));
    let new_mapping = carrick_hal::MappingId::from_kernel_allocation(id(54));
    let old_key = (0xa090_0000_0000, 0x4000);
    let new_key = (0xa092_0000_0000, 0x4000);
    register_carrier_lease(GlobalFrameStage2Lease::fixed(old_key.0, old_key.1), 0x1000);
    let old = InventoryExtent {
        frame: old_frame,
        mapping: old_mapping,
        backing: InventoryBackingIdentity::Private(51),
        stage2_base: old_key.0,
        stage2_length: old_key.1,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    };
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(old_key, old);
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(old_frame, 1);
        frames
            .extent_references
            .insert((old_frame, old_key.0, old_key.1), 1);
        frames.stage2_references.insert(old_key, 1);
    }
    let shape =
        HvfVmState::cow_inventory_split_shape(&inventory, old_key.0, false, |_| Ok(Some(2)))
            .expect("plan COW with a sibling-mm authority mapping");
    assert!(
        !shape.retirement.backend_frame_references_complete,
        "the planner must carry the backend/authority mismatch into commit",
    );
    let split = CowInventorySplit {
        replacement_is_existing: false,
        old_key,
        old,
        fragments: Vec::new(),
        new_key,
        new_extent: InventoryExtent {
            frame: new_frame,
            mapping: new_mapping,
            backing: InventoryBackingIdentity::Private(53),
            stage2_base: new_key.0,
            stage2_length: new_key.1,
            stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
        },
        // The kernel authority reports another mm still maps old_frame.
        retirement: shape.retirement,
    };
    let stage2_retired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = std::sync::Arc::clone(&stage2_retired);

    let retired = HvfVmState::commit_cow_inventory_split(&mut inventory, &split, move || {
        observed.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    })
    .expect("commit authority-retained COW split");

    assert!(!retired, "the old stage-2 extent must remain installed");
    assert!(
        !stage2_retired.load(std::sync::atomic::Ordering::SeqCst),
        "physical stage-2 retirement must follow authoritative frame retirement",
    );
    let frames = std::sync::Arc::clone(&inventory.frames);
    assert!(
        !frames.lock().stage2_references.contains_key(&old_key),
        "the COW split must remove its last backend reference",
    );
    drop(HvpatchCarrierMmAuthority::LeaseTest {
        stage2_lease_keys: vec![old_key],
        frames: std::sync::Arc::clone(&frames),
    });
    assert!(
        carrier_stage2_leases().lock().contains_key(&old_key),
        "carrier teardown must preserve a COW lease retained by Kernel authority",
    );
    assert!(
        HvfVmState::retire_stage2_candidate_if_unreferenced(&frames, old_key, || {
            HvfVmState::retire_stage2_extent_from_mappings(
                &mut TaskMappingIndex::new(),
                old_key.0,
                old_key.1,
            )
        })
        .unwrap(),
    );
    assert!(!carrier_stage2_leases().lock().contains_key(&old_key));
}

#[test]
fn alias_retirement_keeps_carrier_lease_when_kernel_population_is_incomplete() {
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(55));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(56));
    let key = (0xa094_0000_0000, 0x4000);
    let extent = InventoryExtent {
        frame,
        mapping,
        backing: InventoryBackingIdentity::Private(55),
        stage2_base: key.0,
        stage2_length: key.1,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    };
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(key, extent);
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(frame, 1);
        frames.extent_references.insert((frame, key.0, key.1), 1);
        frames.stage2_references.insert(key, 1);
    }
    register_carrier_lease(GlobalFrameStage2Lease::fixed(key.0, key.1), 0x1000);
    let frames = std::sync::Arc::clone(&inventory.frames);
    let retirement = HvfVmState::inventory_lease_retirement_shape(
        &inventory,
        &std::collections::BTreeSet::from([key]),
        &|_| Ok(Some(2)),
    )
    .expect("plan alias retirement with an out-of-population Kernel mapping");
    assert!(retirement.stage2_leases.is_empty());

    HvfVmState::commit_inventory_lease_retirement(&mut inventory, &retirement)
        .expect("commit alias backend retirement");
    assert!(
        !frames.lock().stage2_references.contains_key(&key),
        "alias retirement must remove its last backend reference",
    );
    drop(HvpatchCarrierMmAuthority::LeaseTest {
        stage2_lease_keys: vec![key],
        frames: std::sync::Arc::clone(&frames),
    });
    assert!(
        carrier_stage2_leases().lock().contains_key(&key),
        "carrier teardown must preserve an alias lease retained by Kernel authority",
    );
    assert!(
        HvfVmState::retire_stage2_candidate_if_unreferenced(&frames, key, || {
            HvfVmState::retire_stage2_extent_from_mappings(
                &mut TaskMappingIndex::new(),
                key.0,
                key.1,
            )
        })
        .unwrap(),
    );
    assert!(!carrier_stage2_leases().lock().contains_key(&key));
}

#[test]
fn stale_stage2_retirement_candidate_rechecks_under_the_publication_lock() {
    let frames = std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default()));
    let candidate = (0xa100_0000_0000, CowArmedRanges::COMPOUND_SIZE);
    frames.lock().stage2_references.insert(candidate, 1);
    let retired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let retired_in_callback = std::sync::Arc::clone(&retired);

    assert!(
        !HvfVmState::retire_stage2_candidate_if_unreferenced(&frames, candidate, move || {
            retired_in_callback.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },)
        .unwrap(),
        "a sibling publication that wins after the candidate snapshot keeps the lease live",
    );
    assert!(!retired.load(std::sync::atomic::Ordering::SeqCst));

    frames.lock().stage2_references.remove(&candidate);
    let frames_in_callback = std::sync::Arc::clone(&frames);
    assert!(
        HvfVmState::retire_stage2_candidate_if_unreferenced(&frames, candidate, move || {
            assert!(
                frames_in_callback.try_lock().is_none(),
                "the shared publication registry must stay locked through IPA recycle",
            );
            Ok(())
        },)
        .unwrap(),
    );
}

#[test]
fn final_carrier_mm_drop_keeps_a_backend_referenced_stage2_lease_live() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let frames = std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default()));
    let lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000).unwrap();
    let key = lease.key();
    register_carrier_lease(lease, 0x1000);
    frames.lock().stage2_references.insert(key, 1);
    drop(HvpatchCarrierMmAuthority::LeaseTest {
        stage2_lease_keys: vec![key],
        frames: std::sync::Arc::clone(&frames),
    });

    assert!(
        global_frame_ipa_allocator().lock().is_live(key.0, key.1),
        "a final carrier-MM drop must not recycle an extent another MM still references",
    );
    assert!(
        carrier_stage2_leases().lock().contains_key(&key),
        "the retained lease must stay discoverable for later exact retirement",
    );

    frames.lock().stage2_references.remove(&key);
    assert!(
        HvfVmState::retire_stage2_candidate_if_unreferenced(&frames, key, || {
            HvfVmState::retire_stage2_extent_from_mappings(
                &mut TaskMappingIndex::new(),
                key.0,
                key.1,
            )
        })
        .unwrap(),
    );
    assert!(!global_frame_ipa_allocator().lock().is_live(key.0, key.1));
    assert!(!carrier_stage2_leases().lock().contains_key(&key));
}

#[test]
fn final_carrier_mm_drop_requests_then_safe_point_releases_stage2_once() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let frames = std::sync::Arc::new(parking_lot::Mutex::new(InventoryFrameRegistry::default()));
    let lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000).unwrap();
    let key = lease.key();
    register_carrier_lease(lease, 0x1000);

    drop(HvpatchCarrierMmAuthority::LeaseTest {
        stage2_lease_keys: vec![key],
        frames,
    });

    assert!(global_frame_ipa_allocator().lock().is_live(key.0, key.1));
    assert!(carrier_stage2_leases().lock().contains_key(&key));
    HvfVmState::retire_stage2_extent_from_mappings(&mut TaskMappingIndex::new(), key.0, key.1)
        .expect("explicit safe point performs requested carrier retirement");
    assert!(!global_frame_ipa_allocator().lock().is_live(key.0, key.1));
    assert!(!carrier_stage2_leases().lock().contains_key(&key));
}

#[test]
fn carrier_stage2_registration_rejects_unmapped_or_missing_host_owner() {
    let key = next_test_physical_key(0x4000);
    let mut unmapped = vec![GlobalFrameStage2Lease::fixed(key.0, key.1)];
    let owners = std::collections::BTreeMap::from([(key, 0x1000)]);
    let error = register_carrier_stage2_leases(
        legacy_test_carrier_vm_custody_arc(),
        &mut unmapped,
        &owners,
    )
    .expect_err("an unmapped carrier lease cannot authenticate retirement");
    assert!(error.to_string().contains("mapped=false"));
    assert!(
        unmapped.is_empty(),
        "rejection explicitly rolls back candidates"
    );
    assert!(!carrier_stage2_leases().lock().contains_key(&key));

    let mut unmapped = vec![GlobalFrameStage2Lease::fixed(key.0, key.1)];
    unmapped[0].mark_test_mapped_without_backend();
    unmapped[0].active = false;
    let error = register_carrier_stage2_leases(
        legacy_test_carrier_vm_custody_arc(),
        &mut unmapped,
        &owners,
    )
    .expect_err("an inactive mapped carrier lease cannot authenticate retirement");
    assert!(error.to_string().contains("active=false"));
    assert!(unmapped.is_empty());
    assert!(!carrier_stage2_leases().lock().contains_key(&key));

    let mut unmapped = vec![GlobalFrameStage2Lease::fixed(key.0, key.1)];
    unmapped[0].mark_test_mapped_without_backend();
    let error = register_carrier_stage2_leases(
        legacy_test_carrier_vm_custody_arc(),
        &mut unmapped,
        &std::collections::BTreeMap::new(),
    )
    .expect_err("a mapped key without its exact host owner is still insufficient");
    assert!(error.to_string().contains("host=0x0"));
    assert!(unmapped.is_empty());
    assert!(!carrier_stage2_leases().lock().contains_key(&key));
}

#[test]
fn mapped_setup_failure_explicitly_unmaps_before_backing_drop_without_drop_hv() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let _stage2 = ScopedStage2MapTestStub::enable();
    let custody = std::sync::Arc::new(CarrierVmCustody::new());
    let key = (0x7d00_1800_0000, 0x4000);
    let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        key.1 as usize,
        crate::host_mapping::HostMappingKind::PerMmKernelState,
    )
    .expect("allocate failed-setup backing");
    let host_addr = mapping.as_ptr() as usize;
    let mut lease = GlobalFrameStage2Lease::fixed(key.0, key.1);
    assert_eq!(
        unsafe {
            inventory_hv_vm_map(
                mapping.as_ptr().cast(),
                key.0,
                key.1 as usize,
                u64::from(applevisor::memory::MemPerms::ReadWriteExec),
            )
        },
        0
    );
    lease.mark_mapped();

    register_global_frame_host_owner_in(
        &custody,
        lease,
        mapping,
        u64::from(applevisor::memory::MemPerms::ReadWriteExec),
    )
    .expect_err("vacant custody rejects mapped publication after explicit rollback");
    assert!(!ScopedStage2MapTestStub::is_mapped(key.0, key.1 as usize));
    assert!(!alias_backing_is_live(host_addr));
}

#[test]
fn unowned_retirement_rejects_an_unmapped_local_lease() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000).unwrap();
    let key = lease.key();
    let mut mappings = TaskMappingIndex::from_region(HvfMappedRegion {
        start: 0x7000_0000,
        end: 0x7000_4000,
        ipa: key.0,
        physical_ipa: key.0,
        host_addr: 0x5000_0000usize as *mut u8,
        size: key.1 as usize,
        physical_size: key.1 as usize,
        perms: applevisor::memory::MemPerms::ReadWriteExec,
        memory: None,
        host_mapping: None,
        structural_owner: None,
        stage2_lease: Some(lease),
        is_dynamic_alias: false,
        sharing: GuestMappingSharing::Private,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
    });
    let error = HvfVmState::retire_unowned_stage2_extent_from_mappings(
        &mut mappings,
        key.0,
        key.1,
        0x5000_0000,
    )
    .expect_err("a numeric local key without a mapped lease is not ownership");
    assert!(
        error
            .to_string()
            .contains("lost exact mapped local/carrier owner")
    );
    assert!(mappings[0].stage2_lease.is_some());
}

#[test]
fn carrier_lease_batch_collision_publishes_nothing_and_retains_every_candidate() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let existing_key = (0x7e10_0000_0000, 0x4000);
    register_carrier_lease(
        GlobalFrameStage2Lease::fixed(existing_key.0, existing_key.1),
        0x1000,
    );
    let reserved = GlobalFrameStage2Lease::reserve(0x4000, 0x4000).unwrap();
    let reserved_key = reserved.key();
    let mut candidates = vec![
        reserved,
        GlobalFrameStage2Lease::fixed(existing_key.0, existing_key.1),
    ];
    for candidate in &mut candidates {
        candidate.mark_test_mapped_without_backend();
    }

    let owners = std::collections::BTreeMap::from([(reserved_key, 0x2000), (existing_key, 0x1000)]);
    let error = register_carrier_stage2_leases(
        legacy_test_carrier_vm_custody_arc(),
        &mut candidates,
        &owners,
    )
    .expect_err("an existing carrier key must reject the complete batch");

    assert!(error.to_string().contains("collision"));
    assert!(
        candidates.is_empty(),
        "registration failure explicitly rolls back every rejected candidate"
    );
    assert!(
        !carrier_stage2_leases().lock().contains_key(&reserved_key),
        "no prefix of a rejected lease batch may become visible",
    );
    assert!(
        !global_frame_ipa_allocator()
            .lock()
            .is_live(reserved_key.0, reserved_key.1),
        "the rejected reservation must be explicitly released before returning",
    );
    let _ = carrier_stage2_leases()
        .lock()
        .remove(&existing_key)
        .expect("remove collision fixture");
}

#[test]
fn directory_failpoint_rolls_back_inventory_before_final_carrier_drop() {
    let _allocator_test_guard = global_frame_allocator_test_lock().lock();
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(301));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(302));
    let lease = GlobalFrameStage2Lease::reserve(0x4000, 0x4000).unwrap();
    let key = lease.key();
    register_carrier_lease(lease, 0x1000);
    let mut inventory = HvpatchFrameInventory::default();
    let extent = InventoryExtent {
        frame,
        mapping,
        backing: InventoryBackingIdentity::Private(301),
        stage2_base: key.0,
        stage2_length: key.1,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    };
    inventory.extents.insert(key, extent);
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(frame, 1);
        frames.extent_references.insert((frame, key.0, key.1), 1);
        frames.stage2_references.insert(key, 1);
    }
    let frames = std::sync::Arc::clone(&inventory.frames);
    let ledger = std::sync::Arc::new(parking_lot::Mutex::new(inventory));
    let task_mm = std::sync::Arc::new(HvpatchTaskMmAuthority {
        mappings: Vec::new(),
        foreign_mm_transport: None,
        mm_root_slot: Some((0x7e20_0000_0000, 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        container_root: ContainerRootToken::ROOT,
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::ProcessPrepared {
            ledger: std::sync::Arc::clone(&ledger),
            staged: vec![(key, extent)],
            commit: None,
            challenge: None,
        }),
        kernel_mm: parking_lot::Mutex::new(None),
        cow_armed: None,
        cow_deferred_publications: None,
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::FailpointRollback),
        drop_order: None,
    });
    let carrier = std::sync::Arc::new(HvpatchCarrierMmAuthority::LeaseTest {
        stage2_lease_keys: vec![key],
        frames,
    });
    let row = HvpatchCarrierTaskRow {
        _mm: Some(carrier),
        rollbacks: None,
    };

    let (row, carrier_mm) = rollback_failed_directory_publication(&task_mm, row, None).unwrap();
    drop(row);
    drop(carrier_mm);

    let ledger = ledger.lock();
    assert!(ledger.extents.is_empty());
    assert!(ledger.frames.lock().stage2_references.is_empty());
    drop(ledger);
    HvfVmState::retire_stage2_extent_from_mappings(&mut TaskMappingIndex::new(), key.0, key.1)
        .expect("directory rollback safe point performs requested carrier retirement");
    assert!(
        !carrier_stage2_leases().lock().contains_key(&key),
        "rollback must expose zero refs before the final carrier drain",
    );
    assert!(
        !global_frame_ipa_allocator().lock().is_live(key.0, key.1),
        "a failed directory publication must return its reserved IPA",
    );
}

#[test]
fn cow_collision_is_rejected_before_backend_inventory_mutation() {
    let old_frame = carrick_hal::FrameId::from_kernel_allocation(id(81));
    let old_mapping = carrick_hal::MappingId::from_kernel_allocation(id(82));
    let existing_frame = carrick_hal::FrameId::from_kernel_allocation(id(83));
    let existing_mapping = carrick_hal::MappingId::from_kernel_allocation(id(84));
    let new_frame = carrick_hal::FrameId::from_kernel_allocation(id(85));
    let new_mapping = carrick_hal::MappingId::from_kernel_allocation(id(86));
    let old_key = (0xa200_0000_0000, CowArmedRanges::COMPOUND_SIZE);
    let new_key = (old_key.0 + CowArmedRanges::COMPOUND_SIZE, old_key.1);
    let old = InventoryExtent {
        frame: old_frame,
        mapping: old_mapping,
        backing: InventoryBackingIdentity::Private(81),
        stage2_base: old_key.0,
        stage2_length: old_key.1,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    };
    let existing = InventoryExtent {
        frame: existing_frame,
        mapping: existing_mapping,
        backing: InventoryBackingIdentity::Private(83),
        stage2_base: new_key.0,
        stage2_length: new_key.1,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    };
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(old_key, old);
    inventory.extents.insert(new_key, existing);
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(old_frame, 1);
        frames.references.insert(existing_frame, 1);
        frames
            .extent_references
            .insert((old_frame, old_key.0, old_key.1), 1);
        frames
            .extent_references
            .insert((existing_frame, new_key.0, new_key.1), 1);
        frames.stage2_references.insert(old_key, 1);
        frames.stage2_references.insert(new_key, 1);
    }
    let split = CowInventorySplit {
        replacement_is_existing: false,
        old_key,
        old,
        fragments: Vec::new(),
        new_key,
        new_extent: InventoryExtent {
            frame: new_frame,
            mapping: new_mapping,
            backing: InventoryBackingIdentity::Private(85),
            stage2_base: new_key.0,
            stage2_length: new_key.1,
            stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
        },
        retirement: CowInventoryRetirementDecision {
            retire_old_frame: false,
            backend_frame_references_complete: true,
        },
    };

    let error = HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || Ok(()))
        .expect_err("colliding COW extent must fail closed");
    assert!(error.to_string().contains("before backend mutation"));
    assert_eq!(
        inventory.extents.get(&old_key).unwrap().mapping,
        old_mapping
    );
    assert_eq!(
        inventory.extents.get(&new_key).unwrap().mapping,
        existing_mapping
    );
    let frames = inventory.frames.lock();
    assert_eq!(frames.references.get(&old_frame), Some(&1));
    assert_eq!(frames.references.get(&existing_frame), Some(&1));
    assert_eq!(frames.stage2_references.get(&old_key), Some(&1));
    assert_eq!(frames.stage2_references.get(&new_key), Some(&1));
}

#[test]
fn cow_split_commit_preserves_old_owner_and_publishes_replacement_owner() {
    let compound = CowArmedRanges::COMPOUND_SIZE;
    let old_key = (0x7000_0000, compound * 3);
    let old_stage2 = (0xa280_0000_0000, compound * 3);
    let new_key = (old_key.0 + compound, compound);
    let new_stage2 = (0xa290_0000_0000, compound);
    let old_owner = InventoryStage2OwnerIdentity {
        host_addr: 0x5100_0000,
        generation: 41,
    };
    let new_owner = InventoryStage2OwnerIdentity {
        host_addr: 0x5200_0000,
        generation: 42,
    };
    let old_frame = carrick_hal::FrameId::from_kernel_allocation(id(87));
    let old_mapping = carrick_hal::MappingId::from_kernel_allocation(id(88));
    let new_frame = carrick_hal::FrameId::from_kernel_allocation(id(89));
    let new_mapping = carrick_hal::MappingId::from_kernel_allocation(id(90));
    let old = InventoryExtent {
        frame: old_frame,
        mapping: old_mapping,
        backing: InventoryBackingIdentity::Private(87),
        stage2_base: old_stage2.0,
        stage2_length: old_stage2.1,
        stage2_owner: old_owner,
    };
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(old_key, old);
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(old_frame, 1);
        frames
            .extent_references
            .insert((old_frame, old_key.0, old_key.1), 1);
        frames.stage2_references.insert(old_stage2, 1);
    }
    let fragments = vec![
        CowInventoryFragment {
            gpa: old_key.0,
            length: compound,
            mapping: carrick_hal::MappingId::from_kernel_allocation(id(91)),
        },
        CowInventoryFragment {
            gpa: old_key.0 + compound * 2,
            length: compound,
            mapping: carrick_hal::MappingId::from_kernel_allocation(id(92)),
        },
    ];
    let split = CowInventorySplit {
        replacement_is_existing: false,
        old_key,
        old,
        fragments,
        new_key,
        new_extent: InventoryExtent {
            frame: new_frame,
            mapping: new_mapping,
            backing: InventoryBackingIdentity::Private(89),
            stage2_base: new_stage2.0,
            stage2_length: new_stage2.1,
            stage2_owner: new_owner,
        },
        retirement: CowInventoryRetirementDecision {
            retire_old_frame: false,
            backend_frame_references_complete: true,
        },
    };

    assert!(!HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || Ok(())).unwrap());
    assert_eq!(
        inventory
            .extents
            .get(&(old_key.0, compound))
            .unwrap()
            .stage2_owner,
        old_owner
    );
    assert_eq!(
        inventory
            .extents
            .get(&(old_key.0 + compound * 2, compound))
            .unwrap()
            .stage2_owner,
        old_owner
    );
    assert_eq!(
        inventory.extents.get(&new_key).unwrap().stage2_owner,
        new_owner
    );
}

#[test]
fn cow_stage2_recycle_holds_the_publication_lock() {
    let old_frame = carrick_hal::FrameId::from_kernel_allocation(id(91));
    let old_mapping = carrick_hal::MappingId::from_kernel_allocation(id(92));
    let new_frame = carrick_hal::FrameId::from_kernel_allocation(id(93));
    let new_mapping = carrick_hal::MappingId::from_kernel_allocation(id(94));
    let old_key = (0xa300_0000_0000, CowArmedRanges::COMPOUND_SIZE);
    let new_key = (old_key.0 + CowArmedRanges::COMPOUND_SIZE, old_key.1);
    let old = InventoryExtent {
        frame: old_frame,
        mapping: old_mapping,
        backing: InventoryBackingIdentity::Private(91),
        stage2_base: old_key.0,
        stage2_length: old_key.1,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    };
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(old_key, old);
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(old_frame, 1);
        frames
            .extent_references
            .insert((old_frame, old_key.0, old_key.1), 1);
        frames.stage2_references.insert(old_key, 1);
    }
    let split = CowInventorySplit {
        replacement_is_existing: false,
        old_key,
        old,
        fragments: Vec::new(),
        new_key,
        new_extent: InventoryExtent {
            frame: new_frame,
            mapping: new_mapping,
            backing: InventoryBackingIdentity::Private(93),
            stage2_base: new_key.0,
            stage2_length: new_key.1,
            stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
        },
        retirement: CowInventoryRetirementDecision {
            retire_old_frame: true,
            backend_frame_references_complete: true,
        },
    };
    let frames = std::sync::Arc::clone(&inventory.frames);

    assert!(
        HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || {
            assert!(
                frames.try_lock().is_none(),
                "COW must retain the shared registry lock through old-IPA recycle",
            );
            Ok(())
        })
        .unwrap(),
    );
    assert!(!inventory.extents.contains_key(&old_key));
    assert_eq!(inventory.extents.get(&new_key).unwrap().frame, new_frame);
}

/// A frame this mm has finished with, which a SIBLING mm still maps.
///
/// The per-mm populations say retire: this inventory holds the only extent
/// naming the frame and the backend reference count it tracks falls to
/// zero. The authority disagrees, because a forked sibling still has the
/// frame mapped, and `RetireFrame` rejects any frame whose VM-wide mapping
/// count is non-zero — which aborted the carrier
/// (`FATAL: apply HVPatch alias retirement inventory: frame ... still has
/// live mappings`, seen on `arm64:musl:recursionguard` under gate load).
/// Retirement must defer to the authority's count.
#[test]
fn lease_retirement_defers_to_a_sibling_mm_still_mapping_the_frame() {
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(71));
    let mapping = carrick_hal::MappingId::from_kernel_allocation(id(72));
    let lease = (0xb000_0000_0000, 0x4000);
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(
        (lease.0, 0x4000),
        InventoryExtent {
            frame,
            mapping,
            backing: InventoryBackingIdentity::Private(11),
            stage2_base: lease.0,
            stage2_length: lease.1,
            stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
        },
    );
    {
        let mut registry = inventory.frames.lock();
        registry.references.insert(frame, 1);
        registry
            .extent_references
            .insert((frame, lease.0, 0x4000), 1);
        registry.stage2_references.insert(lease, 1);
    }
    let leases = std::collections::BTreeSet::from([lease]);

    // Two mms map the frame; this transaction unmaps one of them.
    let sibling_still_maps = |_frame| Ok(Some(2usize));
    let shape =
        HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &sibling_still_maps)
            .unwrap();
    assert_eq!(shape.mappings.len(), 1, "the mapping is still unmapped");
    assert!(
        shape.frames.is_empty(),
        "a frame a sibling mm still maps must not be retired: {:?}",
        shape.frames
    );
    assert!(
        shape.stage2_leases.is_empty(),
        "a stage-2 lease whose backend frame population is incomplete must stay mapped",
    );

    // Last mm out does retire it.
    let unavailable = |_frame| {
        Err(TrapError::Hypervisor(
            "injected alias mapping-count failure".to_owned(),
        ))
    };
    let error = HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &unavailable)
        .expect_err("alias retirement must fail when authority is unavailable");
    assert!(
        error
            .to_string()
            .contains("injected alias mapping-count failure")
    );

    let last_owner = |_frame| Ok(Some(1usize));
    let shape =
        HvfVmState::inventory_lease_retirement_shape(&inventory, &leases, &last_owner).unwrap();
    assert_eq!(shape.frames, std::collections::BTreeSet::from([frame]));
}

#[test]
fn cow_reuse_commit_keeps_destination_mapping_and_reference_counts() {
    let old_key = (0x9b00_000000, 0x4000);
    let new_key = (old_key.0 + 0x4000, 0x4000);
    let old = InventoryExtent {
        frame: carrick_hal::FrameId::from_kernel_allocation(id(91)),
        mapping: carrick_hal::MappingId::from_kernel_allocation(id(92)),
        backing: InventoryBackingIdentity::Private(93),
        stage2_base: old_key.0,
        stage2_length: old_key.1,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    };
    let new = InventoryExtent {
        frame: carrick_hal::FrameId::from_kernel_allocation(id(94)),
        mapping: carrick_hal::MappingId::from_kernel_allocation(id(95)),
        stage2_base: new_key.0,
        ..old
    };
    let mut inventory = HvpatchFrameInventory::default();
    for (key, extent) in [(old_key, old), (new_key, new)] {
        inventory.extents.insert(key, extent);
        let mut frames = inventory.frames.lock();
        frames.references.insert(extent.frame, 1);
        frames
            .extent_references
            .insert((extent.frame, key.0, key.1), 1);
        frames.stage2_references.insert(key, 1);
    }
    let mut reservation = carrick_hal::FrameInventoryReservation::from_kernel_candidates(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([96; 32]),
        carrick_hal::FrameInventoryBatch::prepare(
            carrick_hal::KernelTransactionId::from_kernel_allocation(id(96)),
            carrick_hal::FrameEventCapacity::for_event_count(2).unwrap(),
        )
        .unwrap(),
        Vec::new(),
        Vec::new(),
    );
    let mut split = HvfVmState::stage_cow_inventory_split(
        &mut reservation,
        old_key,
        old,
        &[],
        CowInventoryRetirementDecision {
            retire_old_frame: true,
            backend_frame_references_complete: true,
        },
        CowInventoryReplacementStage {
            gpa: new_key.0,
            backing: new.backing,
            stage2_owner: new.stage2_owner,
            existing: Some(new),
        },
    )
    .unwrap();
    assert_eq!(reservation.commit(()).batch().events().len(), 2);
    split.new_extent.stage2_owner.generation += 1;
    assert!(
        HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || panic!(
            "stale destination must fail before retirement"
        ))
        .is_err()
    );
    assert_eq!(inventory.extents[&old_key], old);
    assert_eq!(inventory.extents[&new_key], new);
    split.new_extent = new;
    assert!(HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || Ok(())).unwrap());
    assert_eq!(inventory.extents.len(), 1);
    assert_eq!(inventory.extents[&new_key].mapping, new.mapping);
    let frames = inventory.frames.lock();
    assert_eq!(frames.references[&new.frame], 1);
    assert_eq!(
        frames.extent_references[&(new.frame, new_key.0, new_key.1)],
        1
    );
    assert_eq!(frames.stage2_references[&new_key], 1);
    assert!(!frames.references.contains_key(&old.frame));
}

#[test]
fn cow_lane_reuse_requires_an_unpublished_exact_owner_lane() {
    let key = (0x9b00_000000, 0x4000);
    let scope = AliasOwnershipScope::MmRootSlot {
        base: 0x3100_0000,
        size: 0x4000,
    };
    let extent = InventoryExtent {
        frame: carrick_hal::FrameId::from_kernel_allocation(id(81)),
        mapping: carrick_hal::MappingId::from_kernel_allocation(id(82)),
        backing: InventoryBackingIdentity::Private(83),
        stage2_base: key.0,
        stage2_length: key.1,
        stage2_owner: InventoryStage2OwnerIdentity {
            host_addr: 0x7200_0000,
            generation: 9,
        },
    };
    let alias = AliasBacking {
        start: 0x6000_040000,
        ipa: key.0,
        host_addr: extent.stage2_owner.host_addr,
        size: 0x1000,
        physical_ipa: key.0,
        physical_host_addr: extent.stage2_owner.host_addr,
        physical_size: key.1 as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: scope,
        inventory_backing: extent.backing,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: extent.stage2_owner.generation,
    };
    assert!(cow_lane_is_unpublished(
        key,
        extent,
        scope,
        0x1000,
        &[alias]
    ));
    assert!(
        !cow_lane_is_unpublished(key, extent, scope, 0, &[alias]),
        "published lane"
    );
    assert!(
        !cow_lane_is_unpublished(key, extent, scope, 0x4000, &[alias]),
        "outside owner"
    );
    assert!(
        !cow_lane_is_unpublished(key, extent, scope, 1, &[alias]),
        "partial page"
    );
    assert!(
        !cow_lane_is_unpublished(key, extent, scope, 0x1000, &[]),
        "missing alias census"
    );
    for changed in [
        AliasBacking {
            owner_generation: 8,
            ..alias
        },
        AliasBacking {
            ownership_scope: AliasOwnershipScope::MmRootSlot {
                base: 0x3200_0000,
                size: 0x4000,
            },
            ..alias
        },
        AliasBacking {
            size: 0x2000,
            ..alias
        },
        AliasBacking {
            host_addr: alias.host_addr + 0x1000,
            ..alias
        },
        AliasBacking {
            physical_size: 0x8000,
            ..alias
        },
        AliasBacking {
            ipa: u64::MAX - 0x100,
            ..alias
        },
    ] {
        assert!(
            !cow_lane_is_unpublished(key, extent, scope, 0x1000, &[alias, changed]),
            "every registered alias participates, including foreign/stale/malformed rows"
        );
    }
    let second = AliasBacking {
        start: alias.start + 0x2000,
        ipa: key.0 + 0x2000,
        host_addr: alias.host_addr + 0x2000,
        ..alias
    };
    assert!(cow_lane_is_unpublished(
        key,
        extent,
        scope,
        0x1000,
        &[alias, second]
    ));
    assert!(!cow_lane_is_unpublished(
        key,
        extent,
        scope,
        0x2000,
        &[alias, second]
    ));
}

#[test]
fn partial_semantic_cow_retains_the_old_physical_compound() {
    let old_frame = carrick_hal::FrameId::from_kernel_allocation(id(41));
    let old_mapping = carrick_hal::MappingId::from_kernel_allocation(id(42));
    let physical_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x20_0000;
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(
        (physical_ipa, CowArmedRanges::COMPOUND_SIZE),
        InventoryExtent {
            frame: old_frame,
            mapping: old_mapping,
            backing: InventoryBackingIdentity::Private(1),
            stage2_base: physical_ipa,
            stage2_length: CowArmedRanges::COMPOUND_SIZE,
            stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
        },
    );
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(old_frame, 1);
        frames
            .extent_references
            .insert((old_frame, physical_ipa, CowArmedRanges::COMPOUND_SIZE), 1);
        frames
            .stage2_references
            .insert((physical_ipa, CowArmedRanges::COMPOUND_SIZE), 1);
    }

    let shape =
        HvfVmState::cow_inventory_split_shape(&inventory, physical_ipa, true, |_| Ok(Some(1)))
            .expect("partial semantic COW split shape");

    assert_eq!(
        shape.fragments,
        vec![(physical_ipa, CowArmedRanges::COMPOUND_SIZE)],
        "a sibling leaf still naming the source frame keeps its exact physical compound live",
    );
    assert!(
        !shape.retirement.retire_old_frame,
        "the source frame cannot retire while this mm retains one of its sibling leaves",
    );
}

#[test]
fn retained_sibling_detection_reads_exact_old_frame_leaves() {
    let va = 0x6000_004000;
    let physical_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x24_0000;
    let one_page = CowArmedSpan {
        va: va + 0x1000,
        len: 0x1000,
        executable: false,
        kernel_only: false,
    };
    let old_ipa = physical_ipa + 0x1000;

    assert!(cow_source_has_retained_sibling(
        one_page,
        old_ipa,
        physical_ipa,
        |page_va| (page_va == va).then_some(physical_ipa),
    ));
    assert!(
        !cow_source_has_retained_sibling(one_page, old_ipa, physical_ipa, |page_va| (page_va
            == va + 0x1000)
            .then_some(old_ipa),),
        "the semantic pages repointed by this transaction are not retained siblings",
    );
    assert!(
        !cow_source_has_retained_sibling(one_page, old_ipa, physical_ipa, |page_va| (page_va
            == va)
            .then_some(physical_ipa + 0x8000),),
        "a sibling VA naming another physical frame cannot retain this source",
    );
}

#[test]
fn distant_live_alias_retains_the_shared_physical_cow_inventory() {
    let source_va = 0x6000_040000;
    let distant_va = source_va + 0x10_0000;
    let physical_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x28_0000;
    let span = CowArmedSpan {
        va: source_va,
        len: CowArmedRanges::COMPOUND_SIZE as usize,
        executable: false,
        kernel_only: false,
    };

    let distant_alias = AliasBacking {
        start: distant_va,
        ipa: physical_ipa,
        host_addr: 0x7200_0000,
        size: CowArmedRanges::COMPOUND_SIZE as usize,
        physical_ipa,
        physical_host_addr: 0x7200_0000,
        physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: 0x3100_0000,
            size: 0x4000,
        },
        inventory_backing: InventoryBackingIdentity::Private(0x71),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 9,
    };

    let retain = cow_source_has_retained_projection(
        span,
        physical_ipa,
        physical_ipa,
        &[distant_alias],
        |page_va| {
            if (source_va..source_va + CowArmedRanges::COMPOUND_SIZE).contains(&page_va) {
                Some(physical_ipa + (page_va - source_va))
            } else if (distant_va..distant_va + CowArmedRanges::COMPOUND_SIZE).contains(&page_va) {
                Some(physical_ipa + (page_va - distant_va))
            } else {
                None
            }
        },
    );

    assert!(
        retain,
        "a distant live VA aliasing the same physical compound must retain this mm's one physical inventory row",
    );
}

#[test]
fn cow_then_fork_distant_alias_keeps_inventory_for_live_owner() {
    let source_va = 0x6000_080000;
    let distant_va = source_va + 0x20_0000;
    let physical_ipa = carrick_mem::memory::LINUX_HVPATCH_GLOBAL_FRAME_BASE + 0x2c_0000;
    let span = CowArmedSpan {
        va: source_va,
        len: CowArmedRanges::COMPOUND_SIZE as usize,
        executable: false,
        kernel_only: false,
    };
    let alias = AliasBacking {
        start: distant_va,
        ipa: physical_ipa,
        host_addr: 0x7300_0000,
        size: CowArmedRanges::COMPOUND_SIZE as usize,
        physical_ipa,
        physical_host_addr: 0x7300_0000,
        physical_size: CowArmedRanges::COMPOUND_SIZE as usize,
        perms: u64::from(applevisor::memory::MemPerms::ReadWrite),
        guest_writable: true,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: 0x3200_0000,
            size: 0x4000,
        },
        inventory_backing: InventoryBackingIdentity::Private(0x72),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 19,
    };
    let mut stale_alias = alias;
    stale_alias.start += 0x20_0000;
    stale_alias.owner_generation -= 1;
    let root_slot = Some((0x3200_0000, 0x4000));
    let mut registry = AliasRegistry::default();
    registry.extend([alias, stale_alias]);
    let candidates = registry.private_owned_containing_physical(
        root_slot,
        ContainerRootToken::ROOT,
        physical_ipa,
        CowArmedRanges::COMPOUND_SIZE,
    );
    let current_owner = (alias.physical_host_addr, alias.owner_generation);
    let authenticated = authenticate_cow_retention_aliases(candidates, |candidate| {
        (candidate.physical_host_addr, candidate.owner_generation) == current_owner
    });
    assert_eq!(
        authenticated,
        vec![alias],
        "only the exact current owner generation may supply retention authority"
    );
    let live_translation = |va: u64| {
        if (source_va..source_va + CowArmedRanges::COMPOUND_SIZE).contains(&va) {
            Some(physical_ipa + (va - source_va))
        } else if (distant_va..distant_va + CowArmedRanges::COMPOUND_SIZE).contains(&va) {
            Some(physical_ipa + (va - distant_va))
        } else {
            None
        }
    };
    let retain = cow_source_has_retained_projection(
        span,
        physical_ipa,
        physical_ipa,
        &authenticated,
        live_translation,
    );
    assert!(retain, "the distant stage-1 projection remains live");

    let old_frame = carrick_hal::FrameId::from_kernel_allocation(id(111));
    let old_mapping = carrick_hal::MappingId::from_kernel_allocation(id(112));
    let new_frame = carrick_hal::FrameId::from_kernel_allocation(id(113));
    let new_mapping = carrick_hal::MappingId::from_kernel_allocation(id(114));
    let old_key = (physical_ipa, CowArmedRanges::COMPOUND_SIZE);
    let new_key = (physical_ipa + 0x40_0000, CowArmedRanges::COMPOUND_SIZE);
    let owner = InventoryStage2OwnerIdentity {
        host_addr: alias.physical_host_addr,
        generation: alias.owner_generation,
    };
    let old = InventoryExtent {
        frame: old_frame,
        mapping: old_mapping,
        backing: alias.inventory_backing,
        stage2_base: old_key.0,
        stage2_length: old_key.1,
        stage2_owner: owner,
    };
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(old_key, old);
    {
        let mut frames = inventory.frames.lock();
        // The fork sibling and this mm each retain the same frame/stage-2
        // owner, while this inventory contains this mm's sole row.
        frames.references.insert(old_frame, 2);
        frames
            .extent_references
            .insert((old_frame, old_key.0, old_key.1), 2);
        frames.stage2_references.insert(old_key, 2);
    }
    let shape =
        HvfVmState::cow_inventory_split_shape(&inventory, physical_ipa, retain, |_| Ok(Some(2)))
            .expect("plan COW with distant live projection");
    assert_eq!(shape.fragments, vec![old_key]);
    let split = CowInventorySplit {
        replacement_is_existing: false,
        old_key: shape.old_key,
        old: shape.old,
        fragments: vec![CowInventoryFragment {
            gpa: old_key.0,
            length: old_key.1,
            mapping: carrick_hal::MappingId::from_kernel_allocation(id(115)),
        }],
        new_key,
        new_extent: InventoryExtent {
            frame: new_frame,
            mapping: new_mapping,
            backing: InventoryBackingIdentity::Private(0x73),
            stage2_base: new_key.0,
            stage2_length: new_key.1,
            stage2_owner: InventoryStage2OwnerIdentity {
                host_addr: 0x7400_0000,
                generation: 20,
            },
        },
        retirement: shape.retirement,
    };
    let retired = HvfVmState::commit_cow_inventory_split(&mut inventory, &split, || {
        panic!("a live distant projection must prevent physical retirement")
    })
    .expect("commit COW while preserving old inventory authority");

    assert!(!retired);
    assert_eq!(inventory.extents.get(&old_key).unwrap().stage2_owner, owner);
    assert_eq!(
        inventory.frames.lock().stage2_references.get(&old_key),
        Some(&2)
    );
    assert_eq!(
        live_translation(distant_va),
        Some(physical_ipa),
        "the live stage-1 projection and its current owner remain paired with inventory"
    );
}

#[test]
fn foreign_mm_binding_stage1_tables_preserves_the_exact_shared_mm_access_arc() {
    let owner = HvfTaskState::neutral();
    let sibling_mm_access = std::sync::Arc::clone(&owner.mm_access);
    let before = std::sync::Arc::as_ptr(&owner.mm_access);
    let page_tables = carrick_aarch64::Stage1Authority::new();

    owner
        .mm_access
        .bind_page_tables_authority(page_tables.clone());

    assert_eq!(std::sync::Arc::as_ptr(&owner.mm_access), before);
    assert!(std::sync::Arc::ptr_eq(&owner.mm_access, &sibling_mm_access));
    assert!(
        owner
            .page_tables_authority()
            .shares_exact_authority(&page_tables)
    );
    assert!(
        sibling_mm_access
            .page_tables_authority()
            .shares_exact_authority(&page_tables)
    );
    assert!(owner.runtime_authorities_match(&sibling_mm_access, &page_tables, &owner.protections,));

    let distinct_state = MmAccessState::new(
        page_tables.clone(),
        std::sync::Arc::clone(&owner.protections),
        owner.frame_inventory.shared_ledger(),
        std::sync::Arc::clone(&owner.cow_armed),
        std::sync::Arc::clone(&owner.cow_deferred_publications),
    );
    assert!(
        !owner.runtime_authorities_match(&distinct_state, &page_tables, &owner.protections,),
        "matching component Arcs must not authenticate a distinct MM access state",
    );
}

#[test]
fn bind_page_tables_authority_migrates_live_manager_when_new_authority_empty() {
    let owner = HvfTaskState::neutral();
    let bytes = carrick_mem::memory::stage1_identity_page_tables();
    let manager = crate::page_table::PageTableManager::new(
        bytes,
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
    );
    let old_authority = carrick_aarch64::Stage1Authority::new_with_manager(Some(manager));
    owner
        .mm_access
        .bind_page_tables_authority(old_authority.clone());
    drop(old_authority);

    let new_authority = carrick_aarch64::Stage1Authority::new();
    owner
        .mm_access
        .bind_page_tables_authority(new_authority.clone());

    assert!(
        new_authority.is_present(),
        "live manager must be migrated into empty new authority"
    );
}
#[derive(Debug)]
struct BindTestArenaSource(carrick_mem::page_table::TableArenaSourceId);

impl carrick_mem::page_table::TableArenaSource for BindTestArenaSource {
    fn id(&self) -> carrick_mem::page_table::TableArenaSourceId {
        self.0
    }
    fn take_arena(&mut self) -> Option<carrick_guest_mem::Gpa> {
        None
    }
    fn return_arena(&mut self, _base: carrick_guest_mem::Gpa) {}
}

#[test]
fn bind_page_tables_authority_adopts_extension_state_when_both_present() {
    let owner = HvfTaskState::neutral();
    let bytes = carrick_mem::memory::stage1_identity_page_tables();
    let old_mgr = crate::page_table::PageTableManager::new(
        bytes.clone(),
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
    );
    let stage1_root = carrick_guest_mem::Gpa(carrick_mem::memory::LINUX_PAGE_TABLES_BASE);
    let source = BindTestArenaSource(carrick_mem::page_table::TableArenaSourceId(stage1_root));
    let old_authority = carrick_aarch64::Stage1Authority::new_with_manager(Some(old_mgr));
    old_authority.install_source(Box::new(source)).unwrap();
    assert!(old_authority.has_source());

    owner
        .mm_access
        .bind_page_tables_authority(old_authority.clone());
    drop(old_authority);

    let new_mgr = crate::page_table::PageTableManager::new(
        bytes,
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
    );
    let new_authority = carrick_aarch64::Stage1Authority::new_with_manager(Some(new_mgr));
    assert!(!new_authority.has_source());

    owner
        .mm_access
        .bind_page_tables_authority(new_authority.clone());

    assert!(
        new_authority.has_source(),
        "new manager must have adopted the arena source"
    );
}

#[test]
fn bind_page_tables_authority_preserves_shared_previous_authority() {
    let owner = HvfTaskState::neutral();
    let bytes = carrick_mem::memory::stage1_identity_page_tables();
    let old_mgr = crate::page_table::PageTableManager::new(
        bytes.clone(),
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
    );
    let stage1_root = carrick_guest_mem::Gpa(carrick_mem::memory::LINUX_PAGE_TABLES_BASE);
    let source = BindTestArenaSource(carrick_mem::page_table::TableArenaSourceId(stage1_root));
    let shared_authority = carrick_aarch64::Stage1Authority::new_with_manager(Some(old_mgr));
    shared_authority.install_source(Box::new(source)).unwrap();
    shared_authority.share_with_vfork_child();

    let parent_clone = shared_authority.clone();

    owner
        .mm_access
        .bind_page_tables_authority(shared_authority.clone());

    let new_authority = carrick_aarch64::Stage1Authority::new();
    owner
        .mm_access
        .bind_page_tables_authority(new_authority.clone());

    assert!(
        parent_clone.has_source(),
        "parent manager must retain its arena source"
    );
    assert!(
        parent_clone.is_present(),
        "parent manager must not be stolen"
    );
    assert!(
        !new_authority.has_source(),
        "new authority must not adopt arena source from shared predecessor"
    );
    assert!(
        new_authority.is_none(),
        "new authority must not adopt manager from shared predecessor"
    );
}

#[test]
fn foreign_mm_shared_state_keeps_exec_injection_executor_local() {
    let mut engine_a = HvfTaskState::neutral();
    let mut engine_b = HvfTaskState::neutral();
    engine_b.mm_access = std::sync::Arc::clone(&engine_a.mm_access);
    let ledger = engine_a.frame_inventory.shared_ledger();

    engine_a.fail_next_begin_exec_inventory = true;

    let (b_retired, b_replacement) = inventory_pair(1);
    engine_b
        .begin_exec_inventory(Some(b_retired), b_replacement)
        .expect("unarmed engine B must not consume engine A's injection");
    {
        let mut ledger = ledger.lock();
        drop(ledger.retired_reservation.take());
        drop(ledger.replacement_reservation.take());
    }

    let (a_retired, a_replacement) = inventory_pair(3);
    let error = engine_a
        .begin_exec_inventory(Some(a_retired), a_replacement)
        .expect_err("armed engine A must receive its own injected error");
    assert!(
        error
            .to_string()
            .contains("injected HVPatch begin_exec_inventory failure")
    );

    let (retry_retired, retry_replacement) = inventory_pair(5);
    engine_a
        .begin_exec_inventory(Some(retry_retired), retry_replacement)
        .expect("engine A injection must be consumed exactly once");
}

#[test]
fn exec_keeps_a_physical_extent_owned_by_another_mm() {
    let shared = carrick_hal::FrameId::from_kernel_allocation(id(1));
    let private = carrick_hal::FrameId::from_kernel_allocation(id(2));
    let mut inventory = HvpatchFrameInventory::default();
    inventory.extents.insert(
        (0x4000, 0x4000),
        InventoryExtent {
            frame: shared,
            mapping: carrick_hal::MappingId::from_kernel_allocation(id(3)),
            backing: InventoryBackingIdentity::SharedFile {
                device: 1,
                inode: 2,
                offset: 0,
                length: 0x4000,
            },
            stage2_base: 0x4000,
            stage2_length: 0x4000,
            stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
        },
    );
    inventory.extents.insert(
        (0x8000, 0x4000),
        InventoryExtent {
            frame: private,
            mapping: carrick_hal::MappingId::from_kernel_allocation(id(4)),
            backing: InventoryBackingIdentity::Private(1),
            stage2_base: 0x8000,
            stage2_length: 0x4000,
            stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
        },
    );
    {
        let mut frames = inventory.frames.lock();
        frames.references.insert(shared, 2);
        frames.references.insert(private, 1);
        frames.extent_references.insert((shared, 0x4000, 0x4000), 2);
        frames
            .extent_references
            .insert((private, 0x8000, 0x4000), 1);
        frames.stage2_references.insert((0x4000, 0x4000), 2);
        frames.stage2_references.insert((0x8000, 0x4000), 1);
    }

    struct TestFnAuthority<F>(F);
    impl<F: Fn(carrick_hal::FrameId) -> Option<usize> + Send + Sync> carrick_hal::FrameCowAuthority
        for TestFnAuthority<F>
    {
        fn quiesce(
            &self,
        ) -> Result<Box<dyn carrick_hal::FrameCowQuiesce>, Box<dyn std::error::Error + Send + Sync>>
        {
            Ok(Box::new(()))
        }
        fn reserve(
            &self,
            _: usize,
            _: usize,
            _: usize,
        ) -> Result<carrick_hal::FrameInventoryReservation, Box<dyn std::error::Error + Send + Sync>>
        {
            Err(Box::new(std::io::Error::other("unused")))
        }
        fn apply(
            &self,
            _: carrick_hal::FrameInventoryCommit<()>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err(Box::new(std::io::Error::other("unused")))
        }
        fn mapping_is_live(
            &self,
            _: carrick_hal::MappingId,
            _: carrick_hal::FrameId,
            _: carrick_guest_mem::Gpa,
            _: carrick_hal::FrameLength,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
            Ok(true)
        }
        fn frame_mapping_count(
            &self,
            frame: carrick_hal::FrameId,
        ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
            Ok((self.0)(frame))
        }
    }

    let authoritative = TestFnAuthority(|frame| Some(if frame == shared { 2 } else { 1 }));
    let extents = final_exec_physical_extents(&inventory, &authoritative).unwrap();
    assert_eq!(
        extents,
        std::collections::BTreeSet::from([(0x8000, 0x4000)])
    );

    // The same shared frame may also be mapped at another IPA. Once this
    // exact IPA has no other owner it is independently removable even while
    // the frame itself remains live.
    inventory
        .frames
        .lock()
        .stage2_references
        .insert((0x4000, 0x4000), 1);
    let incomplete_authority = TestFnAuthority(|frame| Some(if frame == shared { 3 } else { 1 }));
    let extents = final_exec_physical_extents(&inventory, &incomplete_authority).unwrap();
    assert_eq!(
        extents,
        std::collections::BTreeSet::from([(0x8000, 0x4000)]),
        "exec must retain a lease when authoritative frame mappings exceed backend references",
    );

    let extents = final_exec_physical_extents(&inventory, &authoritative).unwrap();
    assert_eq!(
        extents,
        std::collections::BTreeSet::from([(0x4000, 0x4000), (0x8000, 0x4000)])
    );
}

#[test]
fn fork_inherits_private_and_shared_frames_before_any_write() {
    let ipa = carrick_mem::memory::LINUX_HVPATCH_ROOT_SLOT_BASE + 0x20_0000;
    let size = 0x4000;
    let frame = carrick_hal::FrameId::from_kernel_allocation(id(11));
    let backing = InventoryBackingIdentity::SharedAnon(17);
    let extent = InventoryExtent {
        frame,
        mapping: carrick_hal::MappingId::from_kernel_allocation(id(12)),
        backing,
        stage2_base: ipa,
        stage2_length: size,
        stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
    };
    let parent_inventory = std::collections::BTreeMap::from([((ipa, size), extent)]);
    let mapping = |sharing| ThreadMappingDesc {
        start: 0x1382_8ed0_0000,
        ipa,
        end: 0x1382_8ed0_0000 + size,
        host_addr: 0x1000usize as *mut u8,
        size: size as usize,
        physical_ipa: ipa,
        physical_host_addr: 0x1000usize as *mut u8,
        physical_size: size as usize,
        perms: applevisor::memory::MemPerms::ReadWrite,
        is_dynamic_alias: true,
        sharing,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 0,
        structural_owner: None,
    };

    let inherited = inherited_fork_inventory_extents(
        &mapping(GuestMappingSharing::ForkSharedAnonymous),
        &parent_inventory,
    )
    .pop()
    .expect("shared-anonymous mapping reuses the parent extent")
    .1;
    assert_eq!(inherited.frame, frame);
    assert_eq!(inherited.backing, backing);

    assert_eq!(
        fork_mapping_disposition(&mapping(GuestMappingSharing::Private), false),
        ForkMappingDisposition::SharedFrameReadOnly,
        "private fork mappings must not take an eager writable snapshot",
    );
    assert_eq!(
        fork_mapping_disposition(&mapping(GuestMappingSharing::Private), true),
        ForkMappingDisposition::SharedFrameWritable,
        "CLONE_VM must preserve the parent's writable user-frame identity",
    );
    let mut kernel_state = mapping(GuestMappingSharing::Private);
    kernel_state.start = crate::memory::LINUX_SYSCALL_MAILBOX_BASE;
    kernel_state.end = kernel_state.start + size;
    assert_ne!(
        fork_mapping_disposition(&kernel_state, true),
        ForkMappingDisposition::SharedFrameWritable,
        "CLONE_VM must still isolate per-process EL1 control state",
    );
    assert_ne!(
        fork_mapping_disposition(&kernel_state, false),
        ForkMappingDisposition::SharedFrameReadOnly,
        "EL1-only per-mm control state must not enter fault-driven guest COW",
    );

    // The fork projection is what carries `MADV_DONTFORK`/`MADV_WIPEONFORK`
    // into the child. Before this was consumed the VMM derived every
    // disposition from the mapping alone, so both advices changed only
    // carrick's metadata while the child still inherited the pages.
    let guest = mapping(GuestMappingSharing::Private);
    let span = |disposition| {
        [carrick_hal::ForkProjectionRange {
            va: guest.start,
            len: guest.end - guest.start,
            disposition,
        }]
    };
    assert_eq!(
        projected_fork_mapping_disposition(&guest, false, &[]),
        ForkMappingPlan::preserved(ForkMappingDisposition::SharedFrameReadOnly),
        "an empty projection must leave the mapping's own disposition alone",
    );
    assert_eq!(
        projected_fork_mapping_disposition(
            &guest,
            false,
            &span(carrick_hal::ForkLeafDisposition::Omit)
        ),
        ForkMappingPlan::Omit,
        "MADV_DONTFORK must drop the mapping from the child entirely",
    );
    assert_eq!(
        projected_fork_mapping_disposition(
            &guest,
            false,
            &span(carrick_hal::ForkLeafDisposition::Zero)
        ),
        ForkMappingPlan::Map {
            disposition: ForkMappingDisposition::IndependentGuestZeroed,
            wiped: vec![(0, guest.end - guest.start)],
        },
        "MADV_WIPEONFORK must give the child its own frame, not a shared one",
    );

    // Carrick's own per-mm state has no semantic VMA, so a projection can
    // never redirect it -- a child without page tables cannot run.
    let mut tables = mapping(GuestMappingSharing::Private);
    tables.start = crate::memory::LINUX_PAGE_TABLES_BASE;
    tables.end = tables.start + size;
    assert_eq!(
        projected_fork_mapping_disposition(
            &tables,
            false,
            &[carrick_hal::ForkProjectionRange {
                va: tables.start,
                len: tables.end - tables.start,
                disposition: carrick_hal::ForkLeafDisposition::Omit,
            }]
        ),
        ForkMappingPlan::preserved(ForkMappingDisposition::IndependentPageTables),
    );

    // A partial MADV_DONTFORK cannot be a hole inside one descriptor, and
    // inheriting it anyway would hand the child excluded memory.
    assert_eq!(
        projected_fork_mapping_disposition(
            &guest,
            false,
            &[carrick_hal::ForkProjectionRange {
                va: guest.start,
                len: (guest.end - guest.start) / 2,
                disposition: carrick_hal::ForkLeafDisposition::Omit,
            }]
        ),
        ForkMappingPlan::PartialOmit,
    );

    // A partial WIPEONFORK IS representable: the child's own frame is
    // seeded from the parent and zeroed across exactly the advised bytes.
    let half = (guest.end - guest.start) / 2;
    assert_eq!(
        projected_fork_mapping_disposition(
            &guest,
            false,
            &[carrick_hal::ForkProjectionRange {
                va: guest.start + half,
                len: half,
                disposition: carrick_hal::ForkLeafDisposition::Zero,
            }]
        ),
        ForkMappingPlan::Map {
            disposition: ForkMappingDisposition::IndependentGuestZeroed,
            wiped: vec![(half, half)],
        },
    );

    // A projection range that does not reach this mapping changes nothing.
    assert_eq!(
        projected_fork_span(
            &[carrick_hal::ForkProjectionRange {
                va: guest.end,
                len: size,
                disposition: carrick_hal::ForkLeafDisposition::Omit,
            }],
            guest.start,
            guest.end,
        ),
        ProjectedForkSpan::Preserve,
    );
    let inherited_private =
        inherited_fork_inventory_extents(&mapping(GuestMappingSharing::Private), &parent_inventory)
            .pop()
            .expect("private fork mapping must initially reuse the parent frame read-only")
            .1;
    assert_eq!(inherited_private.frame, frame);
    assert_eq!(inherited_private.backing, backing);
    assert_ne!(
        HvfVmState::shared_anon_backing_identity(),
        HvfVmState::shared_anon_backing_identity(),
        "independent shared-anonymous mappings must never deduplicate globally"
    );
}

#[test]
fn fork_inventory_inheritance_rejects_a_stale_owner_generation() {
    let lease_ipa = next_test_physical_key(0x8000).0;
    let lease_length = 0x8000;
    let stale_generation = next_global_frame_owner_generation();
    let current_generation = next_global_frame_owner_generation();
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        lease_length as usize,
        crate::host_mapping::HostMappingKind::FrameCow,
    )
    .expect("test host owner");
    let current_host = host.as_ptr() as usize;
    let owner = GlobalFrameHostOwner::new(
        GlobalFrameStage2Lease::fixed(lease_ipa, lease_length),
        host,
        u64::from(applevisor::memory::MemPerms::ReadWrite),
        current_generation,
        lease_ipa,
        lease_length,
    );
    assert!(
        global_frame_host_owners()
            .lock()
            .insert(
                (lease_ipa, lease_length),
                GlobalFrameOwnerEntry::Live(std::sync::Arc::new(owner))
            )
            .is_none()
    );
    let _guard = TestGlobalFrameOwnerGuard {
        key: (lease_ipa, lease_length),
        generation: current_generation,
    };
    let mut mapping = ThreadMappingDesc {
        start: 0x1382_9000_0000,
        ipa: lease_ipa,
        end: 0x1382_9000_4000,
        host_addr: current_host as *mut u8,
        size: 0x4000,
        physical_ipa: lease_ipa,
        physical_host_addr: current_host as *mut u8,
        physical_size: lease_length as usize,
        perms: applevisor::memory::MemPerms::ReadWrite,
        is_dynamic_alias: true,
        sharing: GuestMappingSharing::Private,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: current_generation,
        structural_owner: None,
    };
    let extent = |mapping_id, generation| super::InventoryExtent {
        frame: carrick_hal::FrameId::from_kernel_allocation(id(mapping_id + 100)),
        mapping: carrick_hal::MappingId::from_kernel_allocation(id(mapping_id)),
        backing: InventoryBackingIdentity::Private(mapping_id),
        stage2_base: lease_ipa,
        stage2_length: lease_length,
        stage2_owner: super::InventoryStage2OwnerIdentity {
            host_addr: current_host,
            generation,
        },
    };
    let stale = extent(9201, stale_generation);
    let current = extent(9202, current_generation);
    let inventory = std::collections::BTreeMap::from([
        ((lease_ipa, 0x4000), stale),
        ((lease_ipa + 0x4000, 0x4000), current),
    ]);

    let inherited = inherited_fork_inventory_extents(&mapping, &inventory);
    assert_eq!(
        inherited
            .iter()
            .map(|(key, extent)| (*key, extent.mapping))
            .collect::<Vec<_>>(),
        vec![((lease_ipa + 0x4000, 0x4000), current.mapping)],
        "fork must not launder a superseded inventory owner through a recycled physical lease",
    );

    mapping.owner_generation = stale_generation;
    let mutually_stale =
        std::collections::BTreeMap::from([((lease_ipa, 0x4000), extent(9203, stale_generation))]);
    assert!(
        inherited_fork_inventory_extents(&mapping, &mutually_stale).is_empty(),
        "matching stale metadata must not survive a newer live owner incarnation",
    );
}

#[test]
fn fork_receipts_cover_read_only_user_cow_but_not_independent_kernel_frames() {
    use carrick_observability::probes::HvpatchForkFrameKind;

    assert_eq!(
        fork_frame_receipt_kind(
            ForkMappingDisposition::SharedFrameReadOnly,
            crate::vdso::LINUX_VVAR_BASE,
            HVF_PAGE_SIZE as usize,
        ),
        Some(HvpatchForkFrameKind::PrivateCow),
        "the inherited read-only vvar frame is internally COWed for the child RNG stamp",
    );
    assert_eq!(
        fork_frame_receipt_kind(
            ForkMappingDisposition::SharedFrameWritable,
            0x1382_8ed0_0000,
            HVF_PAGE_SIZE as usize,
        ),
        Some(HvpatchForkFrameKind::Shared),
    );
    assert_eq!(
        fork_frame_receipt_kind(
            ForkMappingDisposition::SharedFrameReadOnly,
            crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            HVF_PAGE_SIZE as usize,
        ),
        None,
        "EL1-only read-only frames never enter the user COW authority",
    );
    assert_eq!(
        fork_frame_receipt_kind(
            ForkMappingDisposition::IndependentKernelState,
            crate::memory::LINUX_SYSCALL_MAILBOX_BASE,
            HVF_PAGE_SIZE as usize,
        ),
        None,
    );
}

#[test]
fn cow_fault_classifier_accepts_only_el0_write_permission_aborts() {
    const DATA_ABORT_LOWER_EL: u64 = 0x24 << 26;
    const WRITE: u64 = 1 << 6;
    for permission_level in [0x0d_u64, 0x0e, 0x0f] {
        assert!(is_stage1_cow_write_fault(
            DATA_ABORT_LOWER_EL | WRITE | permission_level
        ));
    }
    assert!(!is_stage1_cow_write_fault(DATA_ABORT_LOWER_EL | 0x0f));
    assert!(!is_stage1_cow_write_fault(
        DATA_ABORT_LOWER_EL | WRITE | 0x07
    ));
    assert!(is_stage1_cow_write_fault((0x25 << 26) | WRITE | 0x0f));
    assert!(!is_stage1_cow_write_fault((0x21 << 26) | WRITE | 0x0f));
}

#[test]
fn cow_intents_preserve_guest_write_authority_while_internal_writes_bypass_it() {
    use carrick_aarch64::vmm::FrameCowWriteIntent;

    assert!(frame_cow_write_is_denied(
        true,
        true,
        FrameCowWriteIntent::GuestVisible,
    ));
    assert!(frame_cow_write_is_denied(
        false,
        false,
        FrameCowWriteIntent::GuestVisible,
    ));
    assert!(!frame_cow_write_is_denied(
        false,
        true,
        FrameCowWriteIntent::GuestVisible,
    ));
    assert!(
        !frame_cow_write_is_denied(true, false, FrameCowWriteIntent::BackingMaintenance),
        "an internal zero scrub must split the frame before mmap publishes the new VMA permission",
    );
    assert!(
        !frame_cow_write_is_denied(true, false, FrameCowWriteIntent::PrivilegedInternal),
        "a Carrick-owned unchecked write must split without changing guest permissions",
    );
    assert!(!frame_cow_preserves_guest_protection(
        FrameCowWriteIntent::GuestVisible,
    ));
    assert!(frame_cow_preserves_guest_protection(
        FrameCowWriteIntent::BackingMaintenance,
    ));
    assert!(frame_cow_preserves_guest_protection(
        FrameCowWriteIntent::PrivilegedInternal,
    ));
}

#[test]
fn concurrent_cow_loser_retries_only_an_exact_live_writable_winner() {
    assert_eq!(
        unarmed_permission_fault_route(true, false, true, true),
        UnarmedPermissionFaultRoute::RetryCommittedWinner,
        "a sibling winner removes the arm before the losing vCPU resumes"
    );
    assert_eq!(
        unarmed_permission_fault_route(true, false, false, true),
        UnarmedPermissionFaultRoute::RetryCommittedWinner,
        "the last armed page may be removed by the winner before the loser resumes"
    );
    assert_eq!(
        unarmed_permission_fault_route(true, false, true, false),
        UnarmedPermissionFaultRoute::MissingArm,
        "a still-read-only private leaf without its arm is structural corruption"
    );
    assert_eq!(
        unarmed_permission_fault_route(true, true, true, false),
        UnarmedPermissionFaultRoute::NotCow,
        "mprotect-denied writes remain ordinary guest faults"
    );
    assert_eq!(
        unarmed_permission_fault_route(true, false, false, false),
        UnarmedPermissionFaultRoute::NotCow,
        "an address space with no fork arms is not routed into COW"
    );
}

#[test]
fn retired_invalid_output_materializes_before_a_stale_cow_arm() {
    use carrick_aarch64::vmm::FrameCowWriteIntent;

    assert_eq!(
        frame_cow_write_route(FrameCowWriteIntent::BackingMaintenance, true, true, false),
        FrameCowWriteRoute::MaterializeRetired,
        "same-VA reuse must not COW an IPA after its exact stage-2 lease retired",
    );
    assert_eq!(
        frame_cow_write_route(FrameCowWriteIntent::BackingMaintenance, true, false, false),
        FrameCowWriteRoute::CopyOnWrite,
        "a still-live fork-shared physical source remains an ordinary COW",
    );
    assert_eq!(
        frame_cow_write_route(FrameCowWriteIntent::GuestVisible, true, true, false),
        FrameCowWriteRoute::CopyOnWrite,
        "guest faults never use the pre-publication backing-maintenance route",
    );
    // The corruption shape: an UNARMED maintenance write whose retained
    // output names a frame other mms still reference must materialize a
    // private replacement — never write Direct through the shared frame
    // (the CPython forkserver interned-dict zeroing).
    assert_eq!(
        frame_cow_write_route(FrameCowWriteIntent::BackingMaintenance, false, false, true),
        FrameCowWriteRoute::MaterializeRetired,
        "an unarmed maintenance write must not go direct through a shared frame",
    );
    assert_eq!(
        frame_cow_write_route(FrameCowWriteIntent::BackingMaintenance, false, false, false),
        FrameCowWriteRoute::Direct,
        "an unshared retained frame is this mm's own; direct scrub is correct",
    );

    // Linux can reuse a 4 KiB hole inside one 16 KiB HVF compound while
    // adjacent pages still name different live or retired owners. A
    // backing-maintenance scrub must therefore classify every Linux page;
    // jumping to the next compound after a Direct first page skipped a
    // later retired output, and mmap subsequently made that dead IPA valid
    // (`mtforkcorrupt`: VA 0x60000aa000, ESR 0x93cb8047).
    let compound = 0x0600_000a_8000;
    assert_eq!(
        next_frame_cow_write_probe(
            FrameCowWriteIntent::BackingMaintenance,
            compound,
            compound + CowArmedRanges::COMPOUND_SIZE,
            Some(compound + CowArmedRanges::COMPOUND_SIZE),
            None,
        ),
        compound + 0x1000,
        "backing maintenance must inspect every 4 KiB Linux page in a mixed HVF compound",
    );
    assert_eq!(
        next_frame_cow_write_probe(
            FrameCowWriteIntent::GuestVisible,
            compound,
            compound + CowArmedRanges::COMPOUND_SIZE,
            Some(compound + CowArmedRanges::COMPOUND_SIZE),
            None,
        ),
        compound + CowArmedRanges::COMPOUND_SIZE,
        "a fork-armed guest-visible write retains compound-granular progress",
    );
    assert_eq!(
        next_frame_cow_write_probe(
            FrameCowWriteIntent::GuestVisible,
            compound,
            compound + CowArmedRanges::COMPOUND_SIZE,
            Some(compound + 0x1000),
            None,
        ),
        compound + 0x1000,
        "a page-granular (private file view) span advances one Linux page",
    );
    assert_eq!(
        next_frame_cow_write_probe(
            FrameCowWriteIntent::GuestVisible,
            compound,
            compound + CowArmedRanges::COMPOUND_SIZE,
            None,
            Some(compound + 0x2000),
        ),
        compound + 0x2000,
        "an unarmed page must stop at the next armed sibling inside its compound",
    );
    assert_eq!(
        next_frame_cow_write_probe(
            FrameCowWriteIntent::GuestVisible,
            compound + 0x1000,
            compound + CowArmedRanges::COMPOUND_SIZE,
            None,
            Some(compound + 0x8000),
        ),
        compound + CowArmedRanges::COMPOUND_SIZE,
        "an unarmed page with no armed sibling in its compound advances to the compound end",
    );

    let va = 0x0600_000a_9000;
    let mut armed = CowArmedRanges::default();
    armed.arm(&[carrick_aarch64::vmm::ForkCowRange {
        va,
        len: 0x5000,
        executable: true,
        kernel_only: false,
        granule: carrick_aarch64::vmm::CowGranule::Compound,
    }]);
    armed.disarm(CowArmedSpan {
        va,
        len: 0x3000,
        executable: false,
        kernel_only: false,
    });
    assert!(
        armed.span_for(va).is_none(),
        "fresh private leaves must not be forced back to RO by the retired frame's arm",
    );
    assert!(
        armed.span_for(va + 0x3000).is_some(),
        "materializing one compound fragment must preserve adjacent arms",
    );
}

#[test]
fn cow_armed_ranges_split_one_compound_and_leave_peers_armed() {
    let base = 0x4000_0000;
    let mut armed = CowArmedRanges::default();
    armed.arm(&[carrick_aarch64::vmm::ForkCowRange {
        va: base,
        len: 4 * CowArmedRanges::COMPOUND_SIZE as usize,
        executable: false,
        kernel_only: false,
        granule: carrick_aarch64::vmm::CowGranule::Compound,
    }]);
    let writer = armed
        .span_for(base + CowArmedRanges::COMPOUND_SIZE + 8)
        .expect("second compound is armed");
    assert_eq!(writer.va, base + CowArmedRanges::COMPOUND_SIZE);
    assert_eq!(writer.len, CowArmedRanges::COMPOUND_SIZE as usize);
    armed.disarm(writer);
    assert!(armed.span_for(writer.va).is_none());
    assert!(armed.span_for(base).is_some());
    assert!(
        armed
            .span_for(base + 2 * CowArmedRanges::COMPOUND_SIZE)
            .is_some()
    );
}

#[test]
fn cow_armed_ranges_disjoint_overlap_query_is_empty() {
    let base = 0x4000_0000;
    let mut armed = CowArmedRanges::default();
    armed.arm(&[carrick_aarch64::vmm::ForkCowRange {
        va: base,
        len: CowArmedRanges::COMPOUND_SIZE as usize,
        executable: false,
        kernel_only: false,
        granule: carrick_aarch64::vmm::CowGranule::Compound,
    }]);

    assert!(
        armed
            .overlapping(base + 2 * CowArmedRanges::COMPOUND_SIZE, 0x1000)
            .is_empty()
    );
}

#[test]
fn cow_armed_ranges_prefer_exact_alias_fragment_over_broad_arena() {
    let arena = 0x0060_0000_0000;
    let alias = arena + 0xa8_000;
    let mut armed = CowArmedRanges::default();
    armed.arm(&[
        carrick_aarch64::vmm::ForkCowRange {
            va: arena,
            len: 0x8000_0000,
            executable: false,
            kernel_only: false,
            granule: carrick_aarch64::vmm::CowGranule::Compound,
        },
        carrick_aarch64::vmm::ForkCowRange {
            va: alias,
            len: 0x2000,
            executable: false,
            kernel_only: false,
            granule: carrick_aarch64::vmm::CowGranule::Compound,
        },
        carrick_aarch64::vmm::ForkCowRange {
            va: alias + 0x2000,
            len: 0x2000,
            executable: false,
            kernel_only: false,
            granule: carrick_aarch64::vmm::CowGranule::Compound,
        },
    ]);

    let span = armed
        .span_for(alias + 0x1000)
        .expect("exact alias fragment is armed");
    assert_eq!(
        span,
        CowArmedSpan {
            va: alias,
            len: 0x2000,
            executable: false,
            kernel_only: false,
        },
        "an adjacent frame at aa must not be repointed by the a8-aa COW"
    );
}

#[test]
fn inherited_private_frame_skips_duplicate_stage2_install() {
    let inherited = carrick_hal::FrameId::from_kernel_allocation(id(99));
    assert!(!process_mapping_needs_stage2_install(Some(inherited)));
    assert!(process_mapping_needs_stage2_install(None));
}

#[test]
fn fork_translation_accepts_winning_overlay_independent_of_descriptor_order() {
    let mapping = |ipa, host| ProcessMappingDesc {
        start: 0x4000_0000,
        ipa,
        end: 0x4000_4000,
        host: ProcessMappingHost::Borrowed {
            pointer: host as *mut u8,
            structural_owner: None,
        },
        size: 0x4000,
        physical_ipa: ipa,
        physical_host_addr: host as *mut u8,
        physical_size: 0x4000,
        inventory_backing: InventoryBackingIdentity::Private(ipa),
        perms: applevisor::memory::MemPerms::ReadWrite,
        is_dynamic_alias: true,
        sharing: GuestMappingSharing::Private,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        inherited_frame: None,
        stage2_lease: None,
        owner_generation: 0,
    };
    let winning_ipa = 0x9b00_028000;
    let stale_ipa = 0x9b00_008000;
    let mappings = vec![
        mapping(winning_ipa, 0x2000_0000),
        mapping(stale_ipa, 0x3000_0000),
    ];

    let overlay_index =
        ForkTranslationOverlayIndex::build(&mappings, None, ContainerRootToken::ROOT);
    assert!(fork_translation_has_overlay_owner(
        &overlay_index,
        &mappings,
        1,
        0x4000_0000,
        winning_ipa,
    ));
}
