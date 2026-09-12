#![cfg(all(test, target_os = "macos", target_arch = "aarch64"))]

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) struct TestCowAuthority;

impl carrick_hal::FrameCowAuthority for TestCowAuthority {
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
        Ok(false)
    }

    fn frame_mapping_count(
        &self,
        _frame: carrick_hal::FrameId,
    ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }
}

struct LiveForkReceiptAuthority {
    calls: Arc<AtomicUsize>,
    mapping: carrick_hal::MappingId,
    frame: carrick_hal::FrameId,
    ipa: u64,
    length: u64,
}

impl carrick_hal::FrameCowAuthority for LiveForkReceiptAuthority {
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
        mapping: carrick_hal::MappingId,
        frame: carrick_hal::FrameId,
        gpa: carrick_guest_mem::Gpa,
        length: carrick_hal::FrameLength,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        assert_eq!(mapping, self.mapping);
        assert_eq!(frame, self.frame);
        assert_eq!(gpa, carrick_guest_mem::Gpa(self.ipa));
        assert_eq!(length.raw(), self.length);
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }

    fn frame_mapping_count(
        &self,
        _frame: carrick_hal::FrameId,
    ) -> Result<Option<usize>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }
}

#[test]
fn pending_fork_frame_publication_authenticates_and_drains_exactly_once() {
    let mapping =
        carrick_hal::MappingId::from_kernel_allocation(std::num::NonZeroU64::new(42).unwrap());
    let parent_mapping =
        carrick_hal::MappingId::from_kernel_allocation(std::num::NonZeroU64::new(41).unwrap());
    let frame =
        carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(17).unwrap());
    let ipa = 0xa0_0000_0000;
    let length = 0x4000;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut task = HvfTaskState::neutral();
    task.cow_authority = Some(Arc::new(LiveForkReceiptAuthority {
        calls: Arc::clone(&calls),
        mapping,
        frame,
        ipa,
        length,
    }));
    task.cow_identity = Some(carrick_hal::FrameCowIdentity {
        linux_pid: 123,
        linux_tid: 124,
        mm: 9,
        asid: 7,
    });
    task.pending_fork_frame_receipts
        .push(PendingForkFrameReceipt {
            transaction: carrick_hal::KernelTransactionId::from_kernel_allocation(
                std::num::NonZeroU64::new(101).unwrap(),
            ),
            kind: carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
            parent_mapping,
            child_mapping: mapping,
            frame,
            ipa,
            length,
        });

    let mut events = Vec::new();
    task.publish_pending_fork_frame_receipts_with(&mut |event| events.push(event));
    task.publish_pending_fork_frame_receipts_with(&mut |event| events.push(event));

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(task.pending_fork_frame_receipts.is_empty());
    assert_eq!(
        events,
        vec![
            carrick_observability::probes::HvpatchForkFrameShare::new(
                123,
                124,
                9,
                7,
                carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
                parent_mapping.raw(),
                mapping.raw(),
                frame.raw(),
                ipa,
                length,
            )
            .unwrap()
        ]
    );
}

#[test]
fn empty_pending_fork_frame_publication_needs_no_authority_and_emits_nothing() {
    let mut task = HvfTaskState::neutral();
    let mut events = Vec::new();

    task.publish_pending_fork_frame_receipts_with(&mut |event| events.push(event));

    assert!(events.is_empty());
    assert!(task.cow_authority.is_none());
    assert!(task.cow_identity.is_none());
}

#[test]
fn runtime_task_receipt_copy_drains_without_discharging_mm_authority() {
    let mapping =
        carrick_hal::MappingId::from_kernel_allocation(std::num::NonZeroU64::new(52).unwrap());
    let parent_mapping =
        carrick_hal::MappingId::from_kernel_allocation(std::num::NonZeroU64::new(51).unwrap());
    let frame =
        carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(27).unwrap());
    let ipa = 0xb0_0000_0000;
    let length = 0x4000;
    let receipt = PendingForkFrameReceipt {
        transaction: carrick_hal::KernelTransactionId::from_kernel_allocation(
            std::num::NonZeroU64::new(102).unwrap(),
        ),
        kind: carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
        parent_mapping,
        child_mapping: mapping,
        frame,
        ipa,
        length,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let cow_authority: Arc<dyn carrick_hal::FrameCowAuthority> =
        Arc::new(LiveForkReceiptAuthority {
            calls: Arc::clone(&calls),
            mapping,
            frame,
            ipa,
            length,
        });
    let cow_identity = carrick_hal::FrameCowIdentity {
        linux_pid: 223,
        linux_tid: 224,
        mm: 19,
        asid: 17,
    };
    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let task_mm = Arc::new(HvpatchTaskMmAuthority {
        container_root: ContainerRootToken::ROOT,
        mappings: Vec::new(),
        foreign_mm_transport: None,
        mm_root_slot: Some((0xb1_0000_0000, 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::SiblingShared { ledger }),
        kernel_mm: parking_lot::Mutex::new(None),
        cow_armed: Some(Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()))),
        cow_deferred_publications: Some(Arc::new(parking_lot::Mutex::new(Vec::new()))),
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(vec![receipt]),
        pending_receipts: parking_lot::Mutex::new(vec![receipt]),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Test),
        drop_order: None,
    });
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let (_, child_token_verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let registration = HvpatchTaskRegistration {
        directory: Arc::clone(&directory),
        key: HvpatchCarrierTaskStateKey {
            directory_instance: directory.instance,
            task_serial: 223,
            thread_serial: 224,
            execution_generation: 1,
            nonce: std::num::NonZeroU64::new(1).unwrap(),
        },
        expected_identity: HvpatchCarrierTaskIdentity {
            task_serial: 223,
            thread_serial: 224,
            execution_generation: 1,
            linux_pid: 223,
            linux_tid: 224,
            asid: 17,
        },
        foreign_mm_registration: None,
        task_mm: Some(Arc::clone(&task_mm)),
        cow_authority: Some(cow_authority),
        cow_identity: Some(cow_identity),
        cow_authority_identity: None,
        child_token_verifier,
    };
    let mut runtime = registration
        .runtime_task_state(
            carrick_aarch64::Stage1Authority::new(),
            Arc::new(MemoryProtections::default()),
        )
        .unwrap();

    assert_eq!(runtime.pending_fork_frame_receipts.len(), 1);
    assert_eq!(task_mm.pending_receipts.lock().len(), 1);
    let mut events = Vec::new();
    runtime.publish_pending_fork_frame_receipts_with(&mut |event| events.push(event));

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(events.len(), 1);
    assert!(runtime.pending_fork_frame_receipts.is_empty());
    assert_eq!(
        task_mm.pending_receipts.lock().len(),
        1,
        "publication must not consume the authoritative retirement receipts"
    );
    assert_eq!(task_mm.pending_receipts.lock()[0].child_mapping, mapping);
    assert_eq!(task_mm.pending_receipts.lock()[0].frame, frame);

    let reloaded = registration
        .runtime_task_state(
            carrick_aarch64::Stage1Authority::new(),
            Arc::new(MemoryProtections::default()),
        )
        .unwrap();
    assert!(
        reloaded.pending_fork_frame_receipts.is_empty(),
        "an executor reload must not republish a fork receipt whose mapping may have been superseded by COW",
    );
    assert_eq!(
        task_mm.pending_receipts.lock().len(),
        1,
        "one-shot publication must not consume retirement authentication",
    );
}

#[test]
fn bind_frame_cow_authenticates_and_drains_pending_receipts() {
    let mapping =
        carrick_hal::MappingId::from_kernel_allocation(std::num::NonZeroU64::new(62).unwrap());
    let parent_mapping =
        carrick_hal::MappingId::from_kernel_allocation(std::num::NonZeroU64::new(61).unwrap());
    let frame =
        carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(37).unwrap());
    let ipa = 0xc0_0000_0000;
    let length = 0x4000;
    let calls = Arc::new(AtomicUsize::new(0));
    let authority: Arc<dyn carrick_hal::FrameCowAuthority> = Arc::new(LiveForkReceiptAuthority {
        calls: Arc::clone(&calls),
        mapping,
        frame,
        ipa,
        length,
    });
    let identity = carrick_hal::FrameCowIdentity {
        linux_pid: 323,
        linux_tid: 324,
        mm: 29,
        asid: 27,
    };
    let mut task = HvfTaskState::neutral();
    task.pending_fork_frame_receipts
        .push(PendingForkFrameReceipt {
            transaction: carrick_hal::KernelTransactionId::from_kernel_allocation(
                std::num::NonZeroU64::new(103).unwrap(),
            ),
            kind: carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
            parent_mapping,
            child_mapping: mapping,
            frame,
            ipa,
            length,
        });

    task.bind_frame_cow(Arc::clone(&authority), identity);

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(task.pending_fork_frame_receipts.is_empty());
    assert!(Arc::ptr_eq(
        task.cow_authority.as_ref().unwrap(),
        &authority
    ));
    assert_eq!(task.cow_identity, Some(identity));
}

/// An unmap must void the deferred-COW promises naming the range it tears
/// down, before it tears anything down.
///
/// `supersede_cow_receipts`' own contract is that "every stage-1 repointer
/// calls this before publishing its own receipt". An unmap repoints leaves
/// and publishes nothing, so it was the one repointer that never called it,
/// and a receipt could outlive the leaves it describes. The next mapping
/// over that VA then authenticated the stale promise against an absent
/// translation and failed — `deferred COW protection authentication failed
/// at VA 0x6047c96000: leaf=0x0 translated=None` — which the dispatcher can
/// only lower to a guest `ENOMEM`. `go-net` died on it with "fatal error:
/// runtime: cannot allocate memory" while mapping a 256 KiB arena whose
/// fifth page still held a one-page receipt from a freed mapping.
///
/// Red-first shape: this fails on the revision that introduced the report,
/// where `unregister_process_alias` contains no `supersede_cow_receipts`
/// call at all. Asserted on the source because the entry point needs a live
/// carrier VM, the same reason
/// `pending_fork_frame_authentication_false_and_error_paths_fail_closed`
/// below reads the source rather than building one.
#[test]
fn an_unmap_supersedes_the_cow_receipts_naming_its_range_first() {
    let source = concat!(include_str!("../trap.rs"), include_str!("cow_engine.rs"));
    // `rsplit_once`, not `split_once`: this test's own string literal is
    // the FIRST occurrence in the file, and matching it makes the test
    // inspect itself and pass unconditionally.
    let tail = source
        .rsplit_once("pub(crate) fn unregister_process_alias(")
        .expect("process alias retirement entry point")
        .1;
    // Bound the search to THIS function: the file has other callers of
    // `supersede_cow_receipts`, and an unbounded search finds one of them
    // and passes on the very revision this test exists to fail.
    let body = &tail[..tail
        .find("\n    fn ")
        .into_iter()
        .chain(tail.find("\n    pub(crate) fn "))
        .min()
        .expect("end of unregister_process_alias")];
    let supersede = body
        .find("self.supersede_cow_receipts(")
        .expect("an unmap must void the deferred-COW receipts naming its range");
    for teardown in [
        "self.cow_armed.lock().disarm(",
        "unregister_alias(",
        "self.split_local_rows_for_unmap(",
    ] {
        let at = body.find(teardown).unwrap_or_else(|| {
            panic!("teardown step {teardown} not found in unregister_process_alias")
        });
        assert!(
            supersede < at,
            "receipts must be superseded BEFORE {teardown}: a promise voided after its \
             leaves are gone has already been authenticated against nothing"
        );
    }
}

#[test]
fn pending_fork_frame_authentication_false_and_error_paths_fail_closed() {
    let source = include_str!("../trap.rs");
    let helper = source
        .rsplit_once("fn publish_pending_fork_frame_receipts_with(")
        .expect("fork-frame publication helper")
        .1
        .split_once("pub(crate) fn publish_pending_fork_frame_receipts")
        .expect("end of fork-frame publication helper")
        .0;
    let false_branch = helper
        .split_once("Ok(false) => {")
        .expect("false live-mapping result")
        .1
        .split_once("Err(error) => {")
        .expect("end of false live-mapping result")
        .0;
    let error_branch = helper
        .split_once("Err(error) => {")
        .expect("mapping authority error")
        .1
        .split_once("\n            }\n            let event")
        .expect("end of mapping authority error")
        .0;

    assert!(false_branch.contains("carrick_fatal!"));
    assert!(error_branch.contains("carrick_fatal!"));
}

fn identity(generation: u64) -> HvpatchCarrierTaskIdentity {
    HvpatchCarrierTaskIdentity {
        task_serial: 41,
        thread_serial: 73,
        execution_generation: generation,
        linux_pid: 41,
        linux_tid: 73,
        asid: 9,
    }
}

fn test_state(rollbacks: &Arc<AtomicUsize>) -> HvpatchCarrierTaskState {
    HvpatchCarrierTaskState::Test {
        rollbacks: Arc::clone(rollbacks),
        order: None,
    }
}

#[test]
fn prepared_abort_rolls_back_inventory_before_dropping_carrier_leases() {
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let order = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let state = HvpatchCarrierTaskState::Test {
        rollbacks,
        order: Some(Arc::clone(&order)),
    };
    // Deliberately NOT `prepared_task()`: this asserts only the order in
    // which abort tears the two authorities down, and the fixture custody
    // is a LIVE one, so handing it here drives the abort into real
    // structural-backing retirement -- an `hv_*` call an unentitled unit
    // test cannot make.
    let task = HvpatchPreparedTaskAuthority {
        abort_order: Some(Arc::clone(&order)),
        ..HvpatchPreparedTaskAuthority::default()
    };

    abort_prepared_task_and_carrier(task, state).unwrap();

    assert_eq!(&*order.lock(), &["inventory", "carrier"]);
}

/// A prepared task shaped the way production always builds one.
///
/// Every production construction of `HvpatchPreparedTaskAuthority` --
/// `from_process_spec`, the sibling/shared-process paths -- sets `custody`
/// explicitly and uses `..default()` only for the remaining fields, so
/// `custody: None` is a state the runtime cannot reach. `publish_inner`
/// enforces that, which is why a fixture built from a bare `default()`
/// fails at "prepared HVPatch task has no carrier custody" before reaching
/// the behaviour under test. Take the carrier custody from the same live
/// fixture the rest of this module's carrier state comes from.
fn prepared_task() -> HvpatchPreparedTaskAuthority {
    HvpatchPreparedTaskAuthority {
        custody: Some(Arc::clone(legacy_test_carrier_vm_custody_arc())),
        ..HvpatchPreparedTaskAuthority::default()
    }
}

fn owner_key(
    directory: &HvpatchCarrierTaskStateDirectory,
    generation: u64,
    nonce: u64,
) -> HvpatchCarrierTaskStateKey {
    HvpatchCarrierTaskStateKey {
        directory_instance: directory.instance,
        task_serial: 41,
        thread_serial: 73,
        execution_generation: generation,
        nonce: std::num::NonZeroU64::new(nonce).unwrap(),
    }
}

#[test]
fn carrier_keys_are_exact_nonreused_and_terminal_retirement_rolls_back() {
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let first = directory
        .publish(identity(1), test_state(&rollbacks), prepared_task())
        .unwrap();
    assert!(
        directory
            .publish(identity(1), test_state(&rollbacks), prepared_task(),)
            .is_err()
    );
    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    let first_key = first.registration.as_ref().unwrap().key;
    drop(first);
    assert_eq!(rollbacks.load(Ordering::SeqCst), 2);
    let successor = directory
        .publish(identity(2), test_state(&rollbacks), prepared_task())
        .unwrap();
    assert_ne!(first_key, successor.registration.as_ref().unwrap().key);
    drop(successor);
    assert_eq!(rollbacks.load(Ordering::SeqCst), 3);
}

static ALIAS_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[test]
fn injected_alias_and_directory_failures_rollback_before_visibility() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    for failpoint in [1, 2] {
        let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
        let rollbacks = Arc::new(AtomicUsize::new(0));
        let preimage = alias(0x3333_0000 + usize::from(failpoint), 1);
        let replacement = alias(0x4444_0000 + usize::from(failpoint), 3);
        register_shared_alias(preimage);
        assert!(
            directory
                .publish_inner(
                    identity(u64::from(failpoint)),
                    test_state(&rollbacks),
                    HvpatchPreparedTaskAuthority {
                        pending_aliases: vec![replacement],
                        ..prepared_task()
                    },
                    failpoint
                )
                .is_err()
        );
        assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
        assert!(directory.inner.lock().states.is_empty());
        assert!(alias_registry().lock().contains(&preimage));
        assert!(!alias_registry().lock().contains(&replacement));
        assert!(
            replay_mappings()
                .lock()
                .contains(&replay_mapping_key(preimage))
        );
        alias_registry().lock().retain(|entry| {
            !(entry.ipa == preimage.ipa && entry.ownership_scope == preimage.ownership_scope)
        });
        replay_mappings()
            .lock()
            .retain(|(ipa, _, _, _, _)| *ipa != preimage.physical_ipa);
    }
}

fn alias(host: usize, perms: u64) -> AliasBacking {
    AliasBacking {
        start: 0x7fff_1000_0000,
        ipa: 0x6fff_1000_0000,
        host_addr: host,
        size: 0x1000,
        physical_ipa: 0x5fff_1000_0000,
        physical_host_addr: host,
        physical_size: 0x4000,
        perms,
        guest_writable: perms & 2 != 0,
        sharing: GuestMappingSharing::Private,
        ownership_scope: AliasOwnershipScope::MmRootSlot {
            base: 0x4fff_1000_0000,
            size: 0x4000,
        },
        inventory_backing: InventoryBackingIdentity::Private(0x41),
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation: 7,
    }
}

/// A first-touch fault must not pay for every extent the process already
/// materialized.
///
/// The complexity contract for the VA-window queries, asserted on visited
/// rows so it is deterministic under load. The shape it pins is the one
/// `docs/perf-results/2026-09-08-mapping-index-census.md` measured on the
/// cpython-compile reducer: six sites asked "which alias VA windows
/// overlap this range" as `by_va_start.range(va - widest_va ..= va)`, and
/// `widest_va` is a MONOTONE GLOBAL MAXIMUM, so one live large mapping
/// widened the walk for every later query while every materialized extent
/// added a row inside it. That walk visited 341 rows per fault at reducer
/// depth 100,000 and 847 at depth 800,000 -- 111 million rows in one run,
/// 532x what the ordered mapping index visited.
///
/// The fixture is that shape in miniature: one wide row sets the bound,
/// and `DENSE_ROWS` page-sized rows pack the window below the probe. Only
/// two rows can possibly contain the probe VA, so a bound that is a
/// function of the ANSWER visits a handful; a bound that is a function of
/// the POPULATION visits `DENSE_ROWS`.
#[test]
fn a_va_window_query_does_not_pay_for_every_materialized_extent() {
    const DENSE_ROWS: u64 = 2048;
    const PAGE: u64 = 0x1000;
    const BASE: u64 = 0x7000_0000_0000;
    let scope = AliasOwnershipScope::MmRootSlot {
        base: 0x4fff_1000_0000,
        size: 0x4000,
    };

    let mut registry = AliasRegistry::default();
    // One wide live row well below the dense run. It legitimately exists
    // (a large file mapping, an arena reservation) and must stay findable.
    let mut wide = alias(0x1000, 3);
    wide.start = BASE;
    wide.size = (DENSE_ROWS * PAGE) as usize;
    wide.ipa = 0x6000_0000_0000;
    wide.physical_ipa = 0x5000_0000_0000;
    wide.ownership_scope = scope;
    registry.push(wide);

    let dense_base = BASE + DENSE_ROWS * PAGE;
    for index in 0..DENSE_ROWS {
        let mut row = alias(0x2000 + index as usize, 3);
        row.start = dense_base + index * PAGE;
        row.size = PAGE as usize;
        row.ipa = 0x6100_0000_0000 + index * PAGE;
        row.physical_ipa = 0x5100_0000_0000 + index * PAGE;
        row.ownership_scope = scope;
        registry.push(row);
    }

    let probe = dense_base + (DENSE_ROWS - 1) * PAGE;
    let before = alias_state_rows_scanned();
    let found = registry.newest_process_alias_containing_va(
        probe,
        Some((0x4fff_1000_0000, 0x4000)),
        ContainerRootToken::ROOT,
        |_| true,
    );
    let scanned = alias_state_rows_scanned() - before;

    assert_eq!(
        found.map(|row| row.start),
        Some(probe),
        "the containment query must still find the exact covering row"
    );
    // The wide row must stay reachable through the same query: a bound
    // that only looks near the probe would silently lose it.
    let wide_probe = BASE + PAGE;
    assert_eq!(
        registry
            .newest_process_alias_containing_va(
                wide_probe,
                Some((0x4fff_1000_0000, 0x4000)),
                ContainerRootToken::ROOT,
                |_| true,
            )
            .map(|row| row.start),
        Some(BASE),
        "a wide row must still answer a containment query inside it"
    );
    assert!(
        scanned <= 64,
        "a containment query visited {scanned} alias rows with {DENSE_ROWS} \
         extents materialized below it; the bound must be a function of the \
         answer, not of the population"
    );
}

/// One retiring guest process must not pay for the alias rows of every
/// OTHER live guest process.
///
/// This is a complexity contract, asserted on visited rows rather than
/// wall time so it is deterministic under load. The shape it pins is the
/// one measured on 2026-08-30: with 1,000 guest children live,
/// `futexforkrequeue` spent 44.5 s of carrier-global topology-lock hold in
/// process retirement, and the per-retirement hold decayed monotonically
/// from 38.7 ms to 5.3 ms as the children drained — retirement cost was
/// linear in the live-process count, so total exit cost was O(N^2) and the
/// probe could not reap its children inside its 40 s bound.
///
/// The bound below is deliberately generous: it only has to separate
/// "proportional to this process" from "proportional to the carrier".
/// `AliasRegistry::len` reads a maintained total instead of summing every
/// bucket, because summing is O(live processes) and it is read on the
/// generic mutation path. This is what keeps the total honest — a
/// `debug_assert` inside `len` cannot, because it would reintroduce the
/// very sum it replaces in the debug builds the conformance lane runs.
/// The window indexes must answer exactly what a full scan answers, after
/// every kind of mutation.
///
/// `lookup_live_alias_by_va_any_scope`, the IPA mapping lookup and the
/// shared-futex location lookup take the FIRST or LAST match across all
/// scopes, on paths a guest hits per fault and per futex operation. They
/// used to walk every live process's rows; they now range-query an index
/// keyed by window start. An index that drifts from its buckets is silent,
/// so the unindexed scans are kept as the oracle here.
#[test]
fn window_indexed_lookups_match_a_full_scan() {
    let scope_a = AliasOwnershipScope::MmRootSlot {
        base: 0x1000_0000,
        size: 0x4000,
    };
    let scope_b = AliasOwnershipScope::MmRootSlot {
        base: 0x2000_0000,
        size: 0x4000,
    };
    let row = |scope, start: u64, ipa: u64, size: usize| {
        let mut entry = alias(0x7000_0000, 1);
        entry.ownership_scope = scope;
        entry.start = start;
        entry.ipa = ipa;
        entry.size = size;
        entry
    };
    // Deliberately overlapping windows, repeated starts and differing
    // widths, so "first" and "last" are distinguishable and the
    // widest-window bound actually has to reach back.
    let seed = vec![
        row(scope_a, 0x10_0000, 0x90_0000, 0x4000),
        row(scope_a, 0x10_0000, 0x90_4000, 0x8000),
        row(scope_b, 0x10_2000, 0x90_2000, 0x2000),
        row(scope_a, 0x0f_0000, 0x8f_0000, 0x40000),
        row(AliasOwnershipScope::Global, 0x11_0000, 0x91_0000, 0x1000),
        row(scope_b, 0x12_0000, 0x92_0000, 0x10000),
    ];
    let mut registry = AliasRegistry::default();
    for entry in &seed {
        registry.push(*entry);
    }

    let probes: Vec<u64> = (0x0e_0000_u64..0x14_0000).step_by(0x800).collect();
    let ipa_probes: Vec<u64> = (0x8e_0000_u64..0x94_0000).step_by(0x800).collect();
    let check = |registry: &AliasRegistry, stage: &str| {
        for &va in &probes {
            let contains_va = |entry: &AliasBacking| {
                va >= entry.start && va < entry.start.saturating_add(entry.size as u64)
            };
            assert_eq!(
                registry.newest_containing_va(va, contains_va),
                registry.newest_matching(contains_va),
                "VA index disagreed with a full scan at 0x{va:x} after {stage}"
            );
        }
        for &ipa in &ipa_probes {
            let contains_ipa = |entry: &AliasBacking| {
                ipa >= entry.ipa && ipa < entry.ipa.saturating_add(entry.size as u64)
            };
            assert_eq!(
                registry.newest_containing_ipa(ipa, contains_ipa),
                registry.newest_matching(contains_ipa),
                "IPA index disagreed with a full scan (newest) at 0x{ipa:x} after {stage}"
            );
            assert_eq!(
                registry.oldest_containing_ipa(ipa, contains_ipa),
                registry.oldest_matching(contains_ipa),
                "IPA index disagreed with a full scan (oldest) at 0x{ipa:x} after {stage}"
            );
        }
    };

    check(&registry, "push");
    let _ = registry.upsert_by_key(row(scope_a, 0x10_0000, 0x90_0000, 0x2000));
    check(&registry, "upsert replacing an existing key");
    let _ = registry.upsert_by_key(row(scope_a, 0x13_8000, 0x93_8000, 0x2000));
    check(&registry, "upsert of a new key");
    registry.retain_in_scope(scope_b, |entry| entry.start != 0x12_0000);
    check(&registry, "retain_in_scope");
    registry.rebuild_scope_rows(scope_a, |rows| {
        rows.into_iter()
            .flat_map(|(seq, entry)| {
                let mut half = entry;
                half.size = entry.size / 2;
                let mut tail = entry;
                tail.start = entry.start + (entry.size as u64) / 2;
                tail.ipa = entry.ipa + (entry.size as u64) / 2;
                tail.size = entry.size / 2;
                [(seq, half), (seq, tail)]
            })
            .collect()
    });
    check(&registry, "rebuild_scope_rows splitting every row");
    registry.remove_scope(scope_a);
    check(&registry, "remove_scope");
    registry.retain(|entry| entry.ownership_scope == AliasOwnershipScope::Global);
    check(&registry, "retain");

    registry.reindex();
    check(&registry, "reindex");
    registry.clear();
    check(&registry, "clear");
}

#[test]
fn alias_registry_row_total_tracks_its_buckets() {
    let mut registry = AliasRegistry::default();
    let scope_a = AliasOwnershipScope::MmRootSlot {
        base: 0x1000_0000,
        size: 0x4000,
    };
    let scope_b = AliasOwnershipScope::MmRootSlot {
        base: 0x2000_0000,
        size: 0x4000,
    };
    let row = |scope, ipa: u64, start: u64| {
        let mut entry = alias(0x7000_0000, 1);
        entry.ownership_scope = scope;
        entry.ipa = ipa;
        entry.start = start;
        entry
    };
    let check = |registry: &AliasRegistry, stage: &str| {
        assert_eq!(
            registry.len(),
            registry.recomputed_len(),
            "row total diverged from the buckets after {stage}"
        );
    };

    check(&registry, "construction");
    registry.push(row(scope_a, 0x10_0000, 0x20_0000));
    registry.push(row(scope_a, 0x11_0000, 0x21_0000));
    registry.push(row(scope_b, 0x12_0000, 0x22_0000));
    registry.push(row(AliasOwnershipScope::Global, 0x13_0000, 0x23_0000));
    check(&registry, "push");
    assert_eq!(registry.len(), 4);

    // Replacing an existing key must not change the total; a new key must.
    let mut replacement = row(scope_a, 0x10_0000, 0x20_0000);
    replacement.host_addr = replacement.host_addr.saturating_add(0x4000);
    let _ = registry.upsert_by_key(replacement);
    check(&registry, "upsert replacing an existing key");
    assert_eq!(registry.len(), 4);
    let _ = registry.upsert_by_key(row(scope_a, 0x14_0000, 0x24_0000));
    check(&registry, "upsert of a new key");
    assert_eq!(registry.len(), 5);

    assert_eq!(
        registry
            .retain_in_scope(scope_a, |entry| entry.ipa != 0x11_0000)
            .len(),
        1
    );
    check(&registry, "retain_in_scope");
    assert_eq!(registry.remove_scope(scope_b).len(), 1);
    check(&registry, "remove_scope");
    assert!(registry.remove_scope(scope_b).is_empty());
    check(&registry, "remove_scope on an absent scope");

    registry.rebuild_scope_rows(scope_a, |rows| {
        // Split every row in two, exactly as a partial unmap does.
        rows.into_iter()
            .flat_map(|(seq, entry)| [(seq, entry), (seq, entry)])
            .collect()
    });
    check(&registry, "rebuild_scope_rows growing a bucket");
    registry.rebuild_scope_rows(scope_a, |_| Vec::new());
    check(&registry, "rebuild_scope_rows emptying a bucket");

    registry.retain(|_| false);
    check(&registry, "retain removing everything");
    assert_eq!(registry.len(), 0);
    registry.clear();
    check(&registry, "clear");
}

#[test]
fn alias_registry_keeps_distant_same_ipa_rows_in_one_mm() {
    let scope = AliasOwnershipScope::MmRootSlot {
        base: 0x3100_0000,
        size: 0x4000,
    };
    let mut first = alias(0x7100_0000, 1);
    first.ownership_scope = scope;
    first.start = 0x4000_1000;
    first.ipa = 0x9b00_4000;
    let mut distant = first;
    distant.start += 0x10_0000;

    let mut registry = AliasRegistry::default();
    assert!(registry.upsert_by_key(first).is_none());
    assert!(registry.upsert_by_key(distant).is_none());

    assert_eq!(registry.len(), 2);
    assert!(registry.contains(&first));
    assert!(registry.contains(&distant));
    assert_eq!(
        registry.private_owned_containing_physical(
            Some((0x3100_0000, 0x4000)),
            ContainerRootToken::ROOT,
            first.physical_ipa,
            first.physical_size as u64,
        ),
        vec![first, distant],
        "the physical index must preserve both semantic projections of one frame",
    );
}

#[test]
fn alias_registry_replace_all_discards_stale_rows_from_every_index() {
    let scope = AliasOwnershipScope::MmRootSlot {
        base: 0x3150_0000,
        size: 0x4000,
    };
    let mut stale = alias(0x7150_0000, 1);
    stale.start = 0x4150_0000;
    stale.ipa = 0x9b15_0000;
    stale.physical_ipa = 0x5f15_0000_0000;
    stale.ownership_scope = scope;
    let mut restored = alias(0x7250_0000, 1);
    restored.start = 0x4250_0000;
    restored.ipa = 0x9b25_0000;
    restored.physical_ipa = 0x5f25_0000_0000;
    restored.ownership_scope = scope;

    let mut registry = AliasRegistry::default();
    registry.push(stale);
    registry.replace_all([restored]);

    assert_eq!(registry.len(), 1, "replacement must reset the row count");
    assert_eq!(registry.ordered(), vec![restored]);
    assert_eq!(
        registry.newest_containing_va(stale.start, |_| true),
        None,
        "the VA index retained a row from the state being replaced"
    );
    assert_eq!(
        registry.newest_containing_ipa(stale.ipa, |_| true),
        None,
        "the IPA index retained a row from the state being replaced"
    );
    assert!(
        registry
            .private_owned_containing_physical(
                Some((0x3150_0000, 0x4000)),
                ContainerRootToken::ROOT,
                stale.physical_ipa,
                stale.physical_size as u64,
            )
            .is_empty(),
        "the physical index retained a row from the state being replaced"
    );
    assert_eq!(
        registry.newest_containing_va(restored.start, |_| true),
        Some(restored)
    );
    assert_eq!(
        registry.newest_containing_ipa(restored.ipa, |_| true),
        Some(restored)
    );
    assert_eq!(
        registry.private_owned_containing_physical(
            Some((0x3150_0000, 0x4000)),
            ContainerRootToken::ROOT,
            restored.physical_ipa,
            restored.physical_size as u64,
        ),
        vec![restored]
    );
}

#[test]
fn alias_registry_batch_removal_matches_rebuilt_state() {
    let scope_a = AliasOwnershipScope::MmRootSlot {
        base: 0x3500_0000,
        size: 0x4000,
    };
    let scope_b = AliasOwnershipScope::MmRootSlot {
        base: 0x3600_0000,
        size: 0x4000,
    };
    let mut registry = AliasRegistry::default();

    let row = |scope, start: u64, ipa: u64, phys: u64, host: usize, phys_size: usize| {
        let mut entry = alias(host, 1);
        entry.ownership_scope = scope;
        entry.start = start;
        entry.ipa = ipa;
        entry.physical_ipa = phys;
        entry.physical_host_addr = host;
        entry.physical_size = phys_size;
        entry
    };

    // Populate scope_a with many rows, including duplicate (start, ipa) keys.
    let r0 = row(scope_a, 0x1000, 0x5000, 0x9000, 0x10, 0x4000); // first occurrence of (0x1000, 0x5000)
    let r1 = row(scope_a, 0x2000, 0x6000, 0x9000, 0x20, 0x4000);
    let r2 = row(scope_a, 0x3000, 0x7000, 0xa000, 0x30, 0x8000);
    let r3 = row(scope_a, 0x1000, 0x5000, 0xb000, 0x40, 0x4000); // duplicate of r0
    let r4 = row(scope_a, 0x4000, 0x8000, 0xc000, 0x50, 0x4000);
    let r5 = row(scope_a, 0x2000, 0x6000, 0xd000, 0x60, 0x4000); // duplicate of r1
    let r6 = row(scope_a, 0x5000, 0x9000, 0xe000, 0x70, 0x10000);
    let r7 = row(scope_a, 0x1000, 0x5000, 0xf000, 0x80, 0x4000); // 2nd duplicate of r0
    let r8 = row(scope_a, 0x6000, 0xa000, 0x10000, 0x90, 0x4000);

    // Populate scope_b to ensure foreign scopes remain completely intact.
    let foreign = row(scope_b, 0x7000, 0xb000, 0x20000, 0xa0, 0x4000);

    let initial_rows = [r0, r1, r2, r3, r4, r5, r6, r7, r8];
    for r in initial_rows {
        registry.push(r);
    }
    registry.push(foreign);

    let rev_before = registry.revision();

    // Remove a batch that includes a first-occurrence row (r0) and middle rows (r4, r5 which is duplicate of r1).
    let to_remove = vec![r0, r4, r5];
    let removed = registry.remove_exact_values_in_batch(&to_remove);
    assert_eq!(removed.len(), 3);
    assert_eq!(removed, to_remove);

    // Expected remaining rows in scope_a in insertion order:
    // [r1, r2, r3 (now first occurrence of (0x1000, 0x5000)!), r6, r7, r8]
    let remaining_scope_a = vec![r1, r2, r3, r6, r7, r8];

    // Build a fresh reference registry from scratch with the expected surviving rows:
    let mut reference = AliasRegistry::default();
    for r in remaining_scope_a {
        reference.push(r);
    }
    reference.push(foreign);

    // Verify by_scope order
    let scope_a_actual: Vec<AliasBacking> = registry
        .scope_rows(scope_a)
        .iter()
        .map(|(_, a)| *a)
        .collect();
    let scope_a_expected: Vec<AliasBacking> = reference
        .scope_rows(scope_a)
        .iter()
        .map(|(_, a)| *a)
        .collect();
    assert_eq!(scope_a_actual, scope_a_expected);

    // Verify exact_first_by_scope sequences and entries against a from-scratch reindex
    let mut from_scratch = registry.clone();
    from_scratch.reindex();
    assert_eq!(
        registry.exact_first_by_scope,
        from_scratch.exact_first_by_scope
    );

    // Verify secondary indexes
    assert_eq!(registry.va_classes, from_scratch.va_classes);
    assert_eq!(registry.ipa_classes, from_scratch.ipa_classes);
    assert_eq!(registry.by_physical_start, from_scratch.by_physical_start);
    assert_eq!(
        registry.by_scope_physical_start,
        from_scratch.by_scope_physical_start
    );
    assert_eq!(
        registry.physical_size_counts_by_scope,
        from_scratch.physical_size_counts_by_scope
    );

    // Verify row count and revision
    assert_eq!(registry.len(), from_scratch.len());
    assert_eq!(registry.rows, 7);
    assert_eq!(registry.revision(), rev_before + 1);

    // Also verify removing an absent row does not bump revision or alter state
    let rev_after = registry.revision();
    let absent = row(scope_a, 0x9999, 0x9999, 0x9999, 0x99, 0x4000);
    let removed_absent = registry.remove_exact_values_in_batch(&[absent]);
    assert!(removed_absent.is_empty());
    assert_eq!(registry.revision(), rev_after);
}

#[test]
fn alias_registry_batch_removal_does_not_scan_scope_rows() {
    const TOTAL_ROWS: usize = 10_000;
    let scope = AliasOwnershipScope::MmRootSlot {
        base: 0x3400_0000,
        size: 0x4000,
    };
    let mut registry = AliasRegistry::default();
    let mut target = alias(0x7500_0000 + 5000, 1);
    target.ownership_scope = scope;
    target.start = 0x4000_0000 + 5000 * 0x4000;
    target.ipa = 0x6000_0000 + 5000 * 0x4000;
    target.physical_ipa = 0x8000_0000 + 5000 * 0x4000;

    for i in 0..TOTAL_ROWS {
        let mut row = alias(0x7500_0000 + i, 1);
        row.ownership_scope = scope;
        row.start = 0x4000_0000 + i as u64 * 0x4000;
        row.ipa = 0x6000_0000 + i as u64 * 0x4000;
        row.physical_ipa = 0x8000_0000 + i as u64 * 0x4000;
        registry.push(row);
    }

    let before = alias_state_rows_scanned();
    let removed = registry.remove_exact_values_in_batch(&[target]);
    let scanned = alias_state_rows_scanned() - before;

    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0], target);
    let k = 1;
    let log2_n = (TOTAL_ROWS as f64).log2().ceil() as u64;
    let bound = 16 * k + 4 * log2_n;
    assert!(
        scanned <= bound,
        "k={k} removal visited {scanned} rows in a {TOTAL_ROWS}-row scope (bound {bound}); must be O(k log N), not O(N)"
    );
}

#[test]
fn cow_retention_physical_index_does_not_scan_foreign_alias_rows() {
    const FOREIGN_OWNERS: usize = 512;
    let root_slot = (0x3300_0000_u64, 0x4000_u64);
    let scope = AliasOwnershipScope::MmRootSlot {
        base: root_slot.0,
        size: root_slot.1,
    };
    let physical_ipa = 0x5fff_2000_0000;
    let mut registry = AliasRegistry::default();
    for index in 0..FOREIGN_OWNERS {
        let mut foreign = alias(0x7000_0000 + index, 1);
        foreign.start = 0x4000_0000 + index as u64 * 0x10_0000;
        foreign.ipa = physical_ipa;
        foreign.physical_ipa = physical_ipa;
        foreign.ownership_scope = AliasOwnershipScope::MmRootSlot {
            base: 0x5000_0000 + index as u64 * 0x4000,
            size: 0x4000,
        };
        registry.push(foreign);
    }
    for offset in [0_u64, 0x20_0000] {
        let mut mine = alias(0x7100_0000, 3);
        mine.start = 0x6000_0000 + offset;
        mine.ipa = physical_ipa;
        mine.physical_ipa = physical_ipa;
        mine.ownership_scope = scope;
        registry.push(mine);
    }
    let mut global = alias(0x7200_0000, 1);
    global.start = 0x7000_0000;
    global.ipa = physical_ipa;
    global.physical_ipa = physical_ipa;
    global.sharing = GuestMappingSharing::GlobalShared;
    global.ownership_scope = AliasOwnershipScope::Global;
    registry.push(global);

    let before = alias_state_rows_scanned();
    let candidates = registry.private_owned_containing_physical(
        Some(root_slot),
        ContainerRootToken::ROOT,
        physical_ipa,
        CowArmedRanges::COMPOUND_SIZE,
    );
    let scanned = alias_state_rows_scanned() - before;

    assert_eq!(
        candidates.len(),
        2,
        "private COW retention must not consider GlobalShared rows"
    );
    assert_eq!(
        scanned, 2,
        "physical retention lookup visited foreign process rows; expected O(log n + scoped matches), foreign={FOREIGN_OWNERS}"
    );
}

#[test]
fn private_cow_retention_query_ignores_global_and_removed_wide_rows() {
    const DISTRACTORS: usize = 512;
    let root_slot = (0x3350_0000_u64, 0x4000_u64);
    let owned_scope = AliasOwnershipScope::MmRootSlot {
        base: root_slot.0,
        size: root_slot.1,
    };
    let target = 0x5fff_6000_0000_u64;
    let mut registry = AliasRegistry::default();

    let mut removed_wide = alias(0x7300_0000, 1);
    removed_wide.start = 0x4300_0000;
    removed_wide.ipa = target - 0x2000_0000;
    removed_wide.physical_ipa = target - 0x2000_0000;
    removed_wide.physical_size = 0x4000_0000;
    removed_wide.size = removed_wide.physical_size;
    removed_wide.ownership_scope = owned_scope;
    registry.push(removed_wide);
    assert_eq!(
        registry.retain_in_scope(owned_scope, |row| row != &removed_wide),
        vec![removed_wide]
    );

    for index in 0..DISTRACTORS {
        let mut nonmatch = alias(0x7400_0000 + index, 1);
        nonmatch.start = 0x5000_0000 + index as u64 * 0x8000;
        nonmatch.ipa = target - (index as u64 + 1) * 0x4000;
        nonmatch.physical_ipa = nonmatch.ipa;
        nonmatch.physical_size = 0x4000;
        nonmatch.size = 0x4000;
        nonmatch.ownership_scope = owned_scope;
        registry.push(nonmatch);

        let mut global = nonmatch;
        global.start += 0x1000_0000;
        global.ipa = target;
        global.physical_ipa = target;
        global.sharing = GuestMappingSharing::GlobalShared;
        global.ownership_scope = AliasOwnershipScope::Global;
        registry.push(global);
    }
    for offset in [0_u64, 0x20_0000] {
        let mut live = alias(0x7500_0000 + offset as usize, 1);
        live.start = 0x7000_0000 + offset;
        live.ipa = target;
        live.physical_ipa = target;
        live.physical_size = CowArmedRanges::COMPOUND_SIZE as usize;
        live.size = live.physical_size;
        live.ownership_scope = owned_scope;
        registry.push(live);
    }

    let before = alias_state_rows_scanned();
    let candidates = registry.private_owned_containing_physical(
        Some(root_slot),
        ContainerRootToken::ROOT,
        target,
        CowArmedRanges::COMPOUND_SIZE,
    );
    let scanned = alias_state_rows_scanned() - before;

    assert_eq!(
        candidates.len(),
        2,
        "only private rows owned by this mm qualify"
    );
    assert_eq!(
        scanned, 2,
        "private COW lookup visited global, removed-wide, or nonmatching rows"
    );
}

#[test]
fn delayed_old_cow_alias_cleanup_cannot_remove_reused_generation() {
    let physical = (0x5fff_2200_0000_u64, 0x4000_u64);
    let registry = std::sync::Arc::new(parking_lot::Mutex::new(AliasRegistry::default()));
    let replay = std::sync::Arc::new(parking_lot::Mutex::new(std::collections::BTreeSet::new()));
    let mut retired = alias(0x7800_0000, 3);
    retired.start = 0x7000_0000;
    retired.ipa = physical.0;
    retired.physical_ipa = physical.0;
    retired.physical_size = physical.1 as usize;
    retired.owner_generation = 41;
    let mut successor = retired;
    successor.start += 0x8000;
    successor.ipa = physical.0;
    successor.host_addr = 0x7900_0000;
    successor.physical_host_addr = successor.host_addr;
    successor.owner_generation = 42;
    registry.lock().push(retired);
    replay.lock().insert(replay_mapping_key(retired));
    let old_extent = InventoryExtent {
        frame: carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(91).unwrap()),
        mapping: carrick_hal::MappingId::from_kernel_allocation(
            std::num::NonZeroU64::new(92).unwrap(),
        ),
        backing: InventoryBackingIdentity::Private(91),
        stage2_base: physical.0,
        stage2_length: physical.1,
        stage2_owner: InventoryStage2OwnerIdentity {
            host_addr: retired.physical_host_addr,
            generation: retired.owner_generation,
        },
    };

    let after_old_ipa_release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let allow_delayed_cleanup = std::sync::Arc::new(std::sync::Barrier::new(2));
    let removed = std::thread::scope(|scope| {
        let cleanup_registry = std::sync::Arc::clone(&registry);
        let cleanup_replay = std::sync::Arc::clone(&replay);
        let cleanup_after_release = std::sync::Arc::clone(&after_old_ipa_release);
        let cleanup_allowed = std::sync::Arc::clone(&allow_delayed_cleanup);
        let cleanup = scope.spawn(move || {
            // This is the production gap: the old owner has been retired
            // and its IPA released, but alias cleanup has not run yet.
            cleanup_after_release.wait();
            cleanup_allowed.wait();
            remove_rows_for_retired_stage2_projection(
                &mut cleanup_replay.lock(),
                &mut cleanup_registry.lock(),
                old_extent.into(),
            )
        });

        after_old_ipa_release.wait();
        registry.lock().push(successor);
        replay.lock().insert(replay_mapping_key(successor));
        allow_delayed_cleanup.wait();
        cleanup.join().unwrap()
    });
    let registry = registry.lock();

    assert_eq!(removed.removed_aliases, vec![retired]);
    assert_eq!(removed.preserved_reused_aliases, vec![successor]);
    assert_eq!(removed.removed_replay, vec![replay_mapping_key(retired)]);
    assert_eq!(
        removed.preserved_reused_replay,
        vec![replay_mapping_key(successor)]
    );
    assert!(!replay.lock().contains(&replay_mapping_key(retired)));
    assert!(replay.lock().contains(&replay_mapping_key(successor)));
    assert!(!registry.contains(&retired));
    assert!(
        registry.contains(&successor),
        "a delayed old-generation cleanup must not delete an ABA-reused successor"
    );

    let region = |host_addr: usize, owner_generation: u64| HvfMappedRegion {
        start: retired.start,
        end: retired.start + retired.size as u64,
        ipa: retired.ipa,
        physical_ipa: retired.physical_ipa,
        host_addr: host_addr as *mut u8,
        size: retired.size,
        physical_size: retired.physical_size,
        perms: applevisor::memory::MemPerms::ReadWrite,
        memory: None,
        host_mapping: None,
        structural_owner: None,
        stage2_lease: None,
        is_dynamic_alias: true,
        sharing: retired.sharing,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        owner_generation,
    };
    let mut mappings = vec![
        region(retired.physical_host_addr, retired.owner_generation),
        region(successor.physical_host_addr, successor.owner_generation),
    ];
    mappings.retain(|mapping| {
        !mapped_region_matches_retired_inventory_extent(mapping, old_extent.into())
    });
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].owner_generation, successor.owner_generation);
}

#[test]
fn exact_owner_cleanup_does_not_scan_foreign_physical_extents() {
    const FOREIGN_OWNERS: usize = 512;
    let physical = (0x5fff_2600_0000_u64, 0x4000_u64);
    let mut registry = AliasRegistry::default();
    let mut replay = std::collections::BTreeSet::new();
    for index in 0..FOREIGN_OWNERS {
        let mut foreign = alias(0x7a00_0000 + index, 1);
        foreign.start = 0x7100_0000 + index as u64 * 0x8000;
        foreign.ipa = 0x5eee_0000_0000 + index as u64 * 0x4000;
        foreign.physical_ipa = foreign.ipa;
        foreign.physical_size = physical.1 as usize;
        foreign.size = foreign.physical_size;
        foreign.ownership_scope = AliasOwnershipScope::MmRootSlot {
            base: 0x4eee_0000_0000 + index as u64 * 0x4000,
            size: 0x4000,
        };
        registry.push(foreign);
    }
    let mut retired_alias = alias(0x7b00_0000, 3);
    retired_alias.ipa = physical.0;
    retired_alias.physical_ipa = physical.0;
    retired_alias.physical_size = physical.1 as usize;
    retired_alias.size = retired_alias.physical_size;
    retired_alias.owner_generation = 73;
    registry.push(retired_alias);
    replay.insert(replay_mapping_key(retired_alias));
    let retired = RetiredStage2Projection {
        physical_ipa: physical.0,
        physical_length: physical.1,
        owner: InventoryStage2OwnerIdentity {
            host_addr: retired_alias.physical_host_addr,
            generation: retired_alias.owner_generation,
        },
    };

    let before = alias_state_rows_scanned();
    let cleanup = remove_rows_for_retired_stage2_projection(&mut replay, &mut registry, retired);
    let scanned = alias_state_rows_scanned() - before;

    assert_eq!(cleanup.removed_aliases, vec![retired_alias]);
    assert!(
        scanned <= 4,
        "exact owner cleanup visited {scanned} aliases with {FOREIGN_OWNERS} foreign physical extents; expected O(log n + exact matches)"
    );
}

#[test]
fn alias_receipts_retire_distant_same_ipa_rows_independently() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    let directory = HvpatchCarrierTaskStateDirectory::default();
    let first = alias(0x7100_0000, 3);
    let mut distant = first;
    distant.start += 0x10_0000;

    let first_receipt =
        AliasPublicationReceipt::commit(owner_key(&directory, 31, 1), &[first]).unwrap();
    let distant_receipt =
        AliasPublicationReceipt::commit(owner_key(&directory, 32, 2), &[distant]).unwrap();
    assert!(alias_registry().lock().contains(&first));
    assert!(alias_registry().lock().contains(&distant));

    first_receipt.retire_exact();
    assert!(!alias_registry().lock().contains(&first));
    assert!(
        alias_registry().lock().contains(&distant),
        "retiring one semantic projection must not remove the distant projection"
    );

    distant_receipt.retire_exact();
    assert!(!alias_registry().lock().contains(&distant));
    replay_mappings()
        .lock()
        .retain(|(ipa, _, _, _, _)| *ipa != first.physical_ipa);
}

#[test]
fn alias_receipt_batch_cost_scales_with_rows_plus_changes() {
    const EXISTING: usize = 512;
    const CHANGES: usize = 64;
    let _test_lock = ALIAS_TEST_LOCK.lock();
    let _restore = foreign_mm_tests::ExternalAliasStateRestore::capture();
    clear_alias_registry();
    clear_replay_mappings();
    let scope = AliasOwnershipScope::MmRootSlot {
        base: 0x4fff_8100_0000,
        size: 0x4000,
    };
    for index in 0..EXISTING {
        let mut row = alias(0x7600_0000 + index, 1);
        row.start = 0x6000_0000 + index as u64 * 0x8000;
        row.ipa = 0x6f00_0000_0000 + index as u64 * 0x4000;
        row.physical_ipa = 0x5f00_0000_0000 + index as u64 * 0x4000;
        row.ownership_scope = scope;
        register_shared_alias(row);
    }
    let changes = (0..CHANGES)
        .map(|index| {
            let mut row = alias(0x7700_0000 + index, 3);
            row.start = 0x7000_0000 + index as u64 * 0x8000;
            row.ipa = 0x6f80_0000_0000 + index as u64 * 0x4000;
            row.physical_ipa = 0x5f80_0000_0000 + index as u64 * 0x4000;
            row.ownership_scope = scope;
            row
        })
        .collect::<Vec<_>>();
    let directory = HvpatchCarrierTaskStateDirectory::default();

    let before_commit = alias_state_rows_scanned();
    let receipt = AliasPublicationReceipt::commit(owner_key(&directory, 81, 1), &changes).unwrap();
    let commit_scanned = alias_state_rows_scanned() - before_commit;
    let before_retire = alias_state_rows_scanned();
    receipt.retire_exact();
    let retire_scanned = alias_state_rows_scanned() - before_retire;

    let linear_bound = (EXISTING + CHANGES * 16) as u64;
    assert!(
        commit_scanned <= linear_bound,
        "publishing {CHANGES} exact aliases visited {commit_scanned} rows with {EXISTING} existing rows; expected O(existing + changes)"
    );
    assert!(
        retire_scanned <= linear_bound,
        "retiring {CHANGES} exact aliases visited {retire_scanned} rows with {EXISTING} existing rows; expected O(existing + changes)"
    );
    let registry = alias_registry().lock();
    assert_eq!(registry.len(), EXISTING);
    assert!(changes.iter().all(|alias| !registry.contains(alias)));
}

#[test]
fn retiring_one_owner_does_not_scan_foreign_alias_rows() {
    const FOREIGN_OWNERS: usize = 512;
    let retiring_root_slot = (0x4fff_1000_0000_u64, 0x4000_u64);
    let retiring_scope = AliasOwnershipScope::MmRootSlot {
        base: retiring_root_slot.0,
        size: retiring_root_slot.1,
    };

    // Driven against local authorities, NOT the process-global registry:
    // measuring visited rows against carrier-global state made this
    // assertion depend on whatever other tests were running concurrently.
    let mut registry = AliasRegistry::default();
    let mut replay = std::collections::BTreeSet::new();
    let mut versions = AliasVersionRegistry::default();
    for index in 0..FOREIGN_OWNERS {
        let mut foreign = alias(0x3000_0000 + index, 1);
        foreign.ipa = 0x6000_0000_0000 + (index as u64) * 0x4000;
        foreign.physical_ipa = 0x5000_0000_0000 + (index as u64) * 0x4000;
        foreign.ownership_scope = AliasOwnershipScope::MmRootSlot {
            base: 0x1000_0000_0000 + (index as u64) * 0x4000,
            size: 0x4000,
        };
        replay.insert(replay_mapping_key(foreign));
        registry.push(foreign);
    }
    let mut mine = alias(0x9999_0000, 1);
    mine.ownership_scope = retiring_scope;
    replay.insert(replay_mapping_key(mine));
    registry.push(mine);

    let before = alias_state_rows_scanned();
    retire_process_aliases_in(
        &mut registry,
        &replay,
        &mut versions,
        Some(retiring_root_slot),
        ContainerRootToken::ROOT,
        |_| true,
    );
    let scanned = alias_state_rows_scanned() - before;

    assert_eq!(
        registry.len(),
        FOREIGN_OWNERS,
        "retirement must drop exactly the retiring owner's row"
    );
    assert!(
        !registry
            .iter()
            .any(|entry| entry.ownership_scope == retiring_scope),
        "the retiring owner's alias row must be gone"
    );
    // The contract: cost is a function of the RETIRING process, not of the
    // carrier. This process owns one row and there are no `Global` rows, so
    // the bound is a small constant however many other owners are live. On
    // this fixture the clone-and-diff mutator visited 3,076 rows, a single
    // flat-`Vec` retain visited 513, and the scope-partitioned registry
    // visits ~1.
    assert!(
        scanned <= 16,
        "retiring one owner visited {scanned} alias rows with {FOREIGN_OWNERS} \
         foreign owners live; retirement cost must be a function of the \
         retiring process, not of the carrier"
    );
}

#[test]
fn alias_receipt_restores_exact_registry_and_replay_preimages() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    let preimage = alias(0x1111_0000, 1);
    let replacement = alias(0x2222_0000, 3);
    register_shared_alias(preimage);

    let directory = HvpatchCarrierTaskStateDirectory::default();
    let receipt =
        AliasPublicationReceipt::commit(owner_key(&directory, 1, 1), &[replacement]).unwrap();
    assert!(alias_registry().lock().contains(&replacement));
    assert!(
        replay_mappings()
            .lock()
            .contains(&replay_mapping_key(replacement))
    );

    receipt.retire_exact();
    assert!(alias_registry().lock().contains(&preimage));
    assert!(!alias_registry().lock().contains(&replacement));
    assert!(
        replay_mappings()
            .lock()
            .contains(&replay_mapping_key(preimage))
    );
    assert!(
        !replay_mappings()
            .lock()
            .contains(&replay_mapping_key(replacement))
    );

    alias_registry().lock().retain(|entry| {
        !(entry.ipa == preimage.ipa && entry.ownership_scope == preimage.ownership_scope)
    });
    replay_mappings()
        .lock()
        .retain(|(ipa, _, _, _, _)| *ipa != preimage.physical_ipa);
}

#[test]
fn alias_retirement_never_restores_over_a_later_writer() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    let preimage = alias(0x5555_0000, 1);
    let owned = alias(0x6666_0000, 3);
    let later = alias(0x7777_0000, 5);
    register_shared_alias(preimage);
    let directory = HvpatchCarrierTaskStateDirectory::default();
    let receipt = AliasPublicationReceipt::commit(owner_key(&directory, 2, 1), &[owned]).unwrap();
    register_shared_alias(later);
    receipt.retire_exact();
    assert!(alias_registry().lock().contains(&later));
    assert!(!alias_registry().lock().contains(&preimage));
    alias_registry().lock().retain(|entry| {
        !(entry.ipa == later.ipa && entry.ownership_scope == later.ownership_scope)
    });
    replay_mappings()
        .lock()
        .retain(|(ipa, _, _, _, _)| *ipa != later.physical_ipa);
}

#[test]
fn buried_alias_owner_retires_without_clobbering_successor() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    let preimage = alias(0x8888_0000, 1);
    let first_value = alias(0x9999_0000, 3);
    let second_value = alias(0xaaaa_0000, 5);
    register_shared_alias(preimage);
    let directory = HvpatchCarrierTaskStateDirectory::default();
    let first =
        AliasPublicationReceipt::commit(owner_key(&directory, 3, 1), &[first_value]).unwrap();
    let second =
        AliasPublicationReceipt::commit(owner_key(&directory, 4, 2), &[second_value]).unwrap();
    first.retire_exact();
    assert!(alias_registry().lock().contains(&second_value));
    second.retire_exact();
    assert!(alias_registry().lock().contains(&preimage));
    assert!(!alias_registry().lock().contains(&first_value));
    alias_registry().lock().retain(|entry| {
        !(entry.ipa == preimage.ipa && entry.ownership_scope == preimage.ownership_scope)
    });
    replay_mappings()
        .lock()
        .retain(|(ipa, _, _, _, _)| *ipa != preimage.physical_ipa);
}

#[test]
fn external_writer_between_owned_versions_becomes_effective_base() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    let preimage = alias(0xbbbb_0000, 1);
    let first_value = alias(0xcccc_0000, 3);
    let external = alias(0xdddd_0000, 5);
    let second_value = alias(0xeeee_0000, 7);
    register_shared_alias(preimage);
    let directory = HvpatchCarrierTaskStateDirectory::default();
    let first =
        AliasPublicationReceipt::commit(owner_key(&directory, 5, 1), &[first_value]).unwrap();
    register_shared_alias(external);
    let second =
        AliasPublicationReceipt::commit(owner_key(&directory, 6, 2), &[second_value]).unwrap();
    first.retire_exact();
    assert!(alias_registry().lock().contains(&second_value));
    second.retire_exact();
    assert!(alias_registry().lock().contains(&external));
    alias_registry().lock().retain(|entry| {
        !(entry.ipa == external.ipa && entry.ownership_scope == external.ownership_scope)
    });
    replay_mappings()
        .lock()
        .retain(|(ipa, _, _, _, _)| *ipa != external.physical_ipa);
}

#[test]
fn repeated_alias_key_exhaustion_is_preflighted_without_partial_publication() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    let preimage = alias(0xf111_0000, 1);
    let first_value = alias(0xf222_0000, 3);
    let second_value = alias(0xf333_0000, 5);
    register_shared_alias(preimage);
    {
        let mut versions = alias_version_registry().lock();
        let key = alias_version_key(&preimage);
        *versions.alias_epochs.get_mut(&key).unwrap() = u64::MAX - 1;
    }
    let directory = HvpatchCarrierTaskStateDirectory::default();
    assert!(
        AliasPublicationReceipt::commit(owner_key(&directory, 7, 1), &[first_value, second_value])
            .is_err()
    );
    assert!(alias_registry().lock().contains(&preimage));
    assert!(!alias_registry().lock().contains(&first_value));
    {
        let mut versions = alias_version_registry().lock();
        let key = alias_version_key(&preimage);
        *versions.alias_epochs.get_mut(&key).unwrap() = 1;
    }
    alias_registry().lock().retain(|entry| {
        !(entry.ipa == preimage.ipa && entry.ownership_scope == preimage.ownership_scope)
    });
    replay_mappings()
        .lock()
        .retain(|(ipa, _, _, _, _)| *ipa != preimage.physical_ipa);
}

#[test]
fn unregister_alias_does_not_scan_foreign_owners() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    clear_alias_registry();
    clear_replay_mappings();
    const FOREIGN: usize = 512;
    let mine = alias(0x9999_0000, 1);
    let scope = match mine.ownership_scope {
        AliasOwnershipScope::MmRootSlot { base, size } => Some((base, size)),
        _ => None,
    };
    let mut foreign_rows = Vec::new();
    {
        let mut registry = alias_registry().lock();
        for index in 0..FOREIGN {
            let mut row = alias(0x3000_0000 + index, 1);
            row.start = 0x1000_0000 + index as u64 * 0x4000;
            row.ipa += index as u64 * 0x4000;
            row.physical_ipa += (index as u64 + 1) * 0x4000;
            row.ownership_scope = AliasOwnershipScope::MmRootSlot {
                base: 0x1000_0000_0000 + index as u64 * 0x4000,
                size: 0x4000,
            };
            foreign_rows.push(row);
            registry.push(row);
        }
        registry.push(mine);
    }
    let before = alias_state_rows_scanned();
    let retired = unregister_alias(mine.start, mine.size, scope, ContainerRootToken::ROOT);
    let scanned = alias_state_rows_scanned() - before;
    assert!(retired.contains(&(mine.physical_ipa, mine.physical_size as u64)));
    assert_eq!(alias_registry().lock().len(), FOREIGN);
    for row in foreign_rows {
        assert!(alias_registry().lock().contains(&row));
    }
    clear_alias_registry();
    clear_replay_mappings();
    assert!(
        scanned <= 16,
        "unregister of one alias visited {scanned} rows with {FOREIGN} foreign owners"
    );
}

#[test]
fn unregister_last_alias_does_not_rebuild_earlier_exact_rows() {
    const PREFIX: usize = 512;
    let mut registry = AliasRegistry::default();
    let mut mine = alias(0x9000_0000, 3);
    for index in 0..PREFIX {
        let mut row = mine;
        row.start -= (index as u64 + 1) * 0x4000;
        row.ipa -= (index as u64 + 1) * 0x4000;
        row.physical_ipa -= (index as u64 + 1) * 0x4000;
        registry.push(row);
    }
    mine.start += 0x100000;
    registry.push(mine);
    let scope = match mine.ownership_scope {
        AliasOwnershipScope::MmRootSlot { base, size } => Some((base, size)),
        _ => None,
    };
    let before = alias_state_rows_scanned();
    unregister_alias_entries(
        &mut registry,
        mine.start,
        mine.size,
        scope,
        ContainerRootToken::ROOT,
    );
    let scanned = alias_state_rows_scanned() - before;
    let mut expected = registry.clone();
    expected.rebuild_exact_scope(mine.ownership_scope);
    assert_eq!(registry.exact_first_by_scope, expected.exact_first_by_scope);
    assert!(
        scanned <= PREFIX as u64 + 16,
        "last-row unmap visited {scanned} rows; prefix scan may remain, full index rebuild must not"
    );
}

/// Unmapping ONE row must cost the same whatever else the mm holds.
///
/// Red-first shape: this fails on the representation this replaced. That
/// one scanned the scope's whole row vector to locate the overlap, then
/// collected `rows[first_changed..]` into a fresh `Vec` and re-indexed the
/// whole suffix through `refresh_exact_scope_suffix`, because
/// `exact_first_by_scope` was a first-occurrence index over positions. A
/// mid-scope unmap therefore visited ~1.5x the population; with 4,096
/// neighbours that is >6,000 rows against the 64 asserted here. Measured
/// on `cpython-compile`, `unregister_process_alias` held 60% of the
/// carrier's user CPU and its `Vec::from_iter` alone held 36%
/// (`docs/perf-results/2026-09-08-cpython-compile-per-fault-cost.md`).
///
/// The exactness half is asserted too: the incrementally promoted index
/// must equal a from-scratch rebuild, which is what makes dropping the
/// suffix pass legitimate rather than merely cheaper.
#[test]
fn unregister_one_alias_costs_the_same_at_any_mm_size() {
    const NEIGHBOURS: usize = 4096;
    // Room for the binary search's comparisons (log2 4097 ~ 12) and the
    // per-key promotion, and nothing that scales with NEIGHBOURS.
    const BUDGET: u64 = 64;
    let mut registry = AliasRegistry::default();
    let template = alias(0x9000_0000, 3);
    // A scope's rows are in INSERTION order, not address order, so the
    // victim is registered FIRST: every later row is then part of the
    // suffix the retired representation had to re-index.
    let victim = template;
    registry.push(victim);
    for index in 0..NEIGHBOURS {
        let mut row = template;
        let offset = (index as u64 + 1) * 0x4000;
        row.start += offset;
        row.ipa += offset;
        row.physical_ipa += offset;
        registry.push(row);
    }
    let scope = match victim.ownership_scope {
        AliasOwnershipScope::MmRootSlot { base, size } => Some((base, size)),
        _ => None,
    };

    let before = alias_state_rows_scanned();
    unregister_alias_entries(
        &mut registry,
        victim.start,
        victim.size,
        scope,
        ContainerRootToken::ROOT,
    );
    let scanned = alias_state_rows_scanned() - before;

    let mut expected = registry.clone();
    expected.rebuild_exact_scope(victim.ownership_scope);
    assert_eq!(
        registry.exact_first_by_scope, expected.exact_first_by_scope,
        "incrementally promoted exact-first index must equal a from-scratch rebuild"
    );
    assert!(
        scanned <= BUDGET,
        "unmapping the FIRST-registered row of a {NEIGHBOURS}-row mm visited \
         {scanned} rows; the cost must not scale with the mm's population"
    );
}

/// A row that begins exactly where the unmap ends is NOT part of it.
///
/// Red-first shape: selecting overlap from the guest-VA window query alone
/// (which pre-filters on `start + size > va` only) admits this row. Its
/// head test fails and its tail test succeeds, so it is rewritten to begin
/// at `end` — the unmapped range's own end — and its frame is reported as
/// retired. The caller checks that against the leases it planned
/// (`debug_assert_eq!(actual, planned_leases)`); the mismatch aborted the
/// guest under `sysvsem` and `rlimitnproc` with "assertion `left == right`
/// failed". The neighbour must survive untouched and must not be retired.
#[test]
fn unregister_leaves_a_row_that_begins_at_the_unmap_end_untouched() {
    let mut registry = AliasRegistry::default();
    let victim = alias(0x9000_0000, 3);
    let mut neighbour = victim;
    neighbour.start = victim.start + victim.size as u64;
    neighbour.ipa += victim.size as u64;
    neighbour.physical_ipa += victim.size as u64;
    registry.push(victim);
    registry.push(neighbour);
    let scope = match victim.ownership_scope {
        AliasOwnershipScope::MmRootSlot { base, size } => Some((base, size)),
        _ => None,
    };

    let retired = unregister_alias_entries(
        &mut registry,
        victim.start,
        victim.size,
        scope,
        ContainerRootToken::ROOT,
    );

    let surviving = registry
        .by_scope
        .get(&neighbour.ownership_scope)
        .map(|rows| rows.iter().map(|&(_, row)| row).collect::<Vec<_>>())
        .unwrap_or_default();
    assert_eq!(
        surviving,
        vec![neighbour],
        "the row beginning at the unmap end must survive unchanged"
    );
    assert!(
        !retired.contains(&(neighbour.physical_ipa, neighbour.physical_size as u64)),
        "the neighbour's frame must not be reported as retired: {retired:?}"
    );
}

#[test]
fn unregister_alias_matches_full_snapshot_invalidation() {
    let directory = HvpatchCarrierTaskStateDirectory::default();
    let owner = owner_key(&directory, 88, 1);
    let mut root = alias(0x9000_0000, 3);
    root.size = 0x4000;
    let scope = match root.ownership_scope {
        AliasOwnershipScope::MmRootSlot { base, size } => Some((base, size)),
        _ => None,
    };
    let mut foreign = root;
    foreign.start -= 0x100000;
    foreign.ipa -= 0x100000;
    foreign.physical_ipa -= 0x100000;
    foreign.ownership_scope = AliasOwnershipScope::MmRootSlot {
        base: 0x1234_0000,
        size: 0x4000,
    };
    let ranges = [
        (0, 0x4000),
        (0, 0x1000),
        (0x3000, 0x1000),
        (0x1000, 0x1000),
        (0, 0),
        (0x5000, 0x1000),
    ];
    for variant in 0..5 {
        for (offset, len) in ranges {
            let va = root.start + offset;
            let mut rows = vec![root, foreign];
            if variant == 1 || variant == 2 {
                let mut duplicate = root;
                duplicate.size = if variant == 1 { 0x1000 } else { 0x8000 };
                duplicate.physical_ipa += 0x100000;
                rows.push(duplicate);
            }
            if variant == 3 || variant == 4 {
                let mut collision = root;
                collision.start = va + len as u64;
                collision.ipa += offset + len as u64;
                collision.physical_ipa += 0x200000;
                if variant == 3 {
                    rows.insert(0, collision);
                } else {
                    rows.push(collision);
                }
            }
            let mut registry = AliasRegistry::default();
            let mut replay = std::collections::BTreeSet::new();
            let mut versions = AliasVersionRegistry::default();
            for (index, row) in rows.into_iter().enumerate() {
                registry.push(row);
                replay.insert(replay_mapping_key(row));
                let key = alias_version_key(&row);
                let id = AliasPublicationVersionId {
                    owner,
                    ordinal: index as u32,
                };
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    versions.aliases.entry(key)
                {
                    let mut preimage = row;
                    preimage.host_addr += 0x4000;
                    entry.insert(AliasVersionChain {
                        base: Some(preimage),
                        versions: vec![OwnedAliasVersion {
                            id,
                            value: row,
                            epoch: 7,
                        }],
                    });
                    versions.alias_epochs.insert(key, 7);
                    versions.alias_version_owner.insert(id, key);
                }
                let id = AliasPublicationVersionId {
                    owner,
                    ordinal: index as u32 + 100,
                };
                if let std::collections::btree_map::Entry::Vacant(entry) =
                    versions.replays.entry(row.physical_ipa)
                {
                    entry.insert(ReplayVersionChain {
                        base: vec![],
                        versions: vec![OwnedReplayVersion {
                            id,
                            value: replay_mapping_key(row),
                            epoch: 9,
                        }],
                    });
                    versions.replay_epochs.insert(row.physical_ipa, 9);
                    versions.replay_version_owner.insert(id, row.physical_ipa);
                }
            }
            let mut reference_registry = registry.clone();
            let mut reference_replay = replay.clone();
            let mut reference_versions = versions.clone();
            let expected = mutate_external_alias_state_in(
                &mut reference_replay,
                &mut reference_registry,
                &mut reference_versions,
                |_, registry| {
                    unregister_alias_entries(registry, va, len, scope, ContainerRootToken::ROOT)
                },
            );
            let actual = unregister_alias_in(
                &mut registry,
                &replay,
                &mut versions,
                va,
                len,
                scope,
                ContainerRootToken::ROOT,
            );
            assert_eq!(
                actual, expected,
                "retired extents variant={variant} offset={offset}"
            );
            assert_eq!(
                registry.iter().copied().collect::<Vec<_>>(),
                reference_registry.iter().copied().collect::<Vec<_>>()
            );
            assert_eq!(replay, reference_replay);
            let mut reindexed = registry.clone();
            for scope in registry.by_scope.keys() {
                reindexed.rebuild_exact_scope(*scope);
            }
            assert_eq!(
                registry.exact_first_by_scope,
                reindexed.exact_first_by_scope
            );
            assert_eq!(
                versions, reference_versions,
                "version invalidation variant={variant} offset={offset}"
            );
            // A checked-add overflow must leave even live receipts untouched.
            let before = versions.clone();
            assert!(
                unregister_alias_in(
                    &mut registry,
                    &replay,
                    &mut versions,
                    u64::MAX - 1,
                    4,
                    scope,
                    ContainerRootToken::ROOT
                )
                .is_empty()
            );
            assert_eq!(versions, before);
        }
    }
}

#[test]
fn external_unregister_and_clear_invalidate_owned_versions() {
    let _test_lock = ALIAS_TEST_LOCK.lock();
    let preimage = alias(0xf666_0000, 1);
    let owned = alias(0xf777_0000, 3);
    register_shared_alias(preimage);
    let directory = HvpatchCarrierTaskStateDirectory::default();
    let receipt = AliasPublicationReceipt::commit(owner_key(&directory, 8, 1), &[owned]).unwrap();
    let scope = match owned.ownership_scope {
        AliasOwnershipScope::MmRootSlot { base, size } => Some((base, size)),
        _ => None,
    };
    unregister_alias(owned.start, owned.size, scope, ContainerRootToken::ROOT);
    receipt.retire_exact();
    assert!(!alias_registry().lock().contains(&preimage));
    assert!(!alias_registry().lock().contains(&owned));

    register_shared_alias(preimage);
    let receipt = AliasPublicationReceipt::commit(owner_key(&directory, 9, 2), &[owned]).unwrap();
    clear_alias_registry();
    clear_replay_mappings();
    receipt.retire_exact();
    assert!(alias_registry().lock().is_empty());
    assert!(
        replay_mappings()
            .lock()
            .iter()
            .all(|(ipa, _, _, _, _)| *ipa != owned.physical_ipa)
    );
}

fn empty_inventory_commit(raw: u64) -> carrick_hal::FrameInventoryCommit<()> {
    let id = std::num::NonZeroU64::new(raw).unwrap();
    let capacity = carrick_hal::FrameEventCapacity::for_event_count(1).unwrap();
    carrick_hal::FrameInventoryReservation::from_kernel_candidates(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([raw as u8; 32]),
        carrick_hal::FrameInventoryBatch::prepare(
            carrick_hal::KernelTransactionId::from_kernel_allocation(id),
            capacity,
        )
        .unwrap(),
        Vec::new(),
        Vec::new(),
    )
    .commit(())
}

pub(crate) fn retirement_inventory_commit(
    raw: u64,
    mappings: &[carrick_hal::MappingId],
) -> carrick_hal::FrameInventoryCommit<()> {
    let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(
        std::num::NonZeroU64::new(raw).unwrap(),
    );
    let capacity = carrick_hal::FrameEventCapacity::for_event_count(mappings.len()).unwrap();
    let mut reservation = carrick_hal::FrameInventoryReservation::from_kernel_candidates(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([raw as u8; 32]),
        carrick_hal::FrameInventoryBatch::prepare(transaction, capacity).unwrap(),
        Vec::new(),
        Vec::new(),
    );
    for &mapping in mappings {
        reservation
            .push(carrick_hal::FrameInventoryEvent::UnmapMapping {
                transaction,
                mapping,
                generation: carrick_hal::MappingGeneration::from_backend_counter(
                    std::num::NonZeroU64::new(2).unwrap(),
                ),
            })
            .unwrap();
    }
    reservation.commit(())
}

pub(crate) fn test_kernel_apply(
    commit: carrick_hal::FrameInventoryCommit<()>,
    raw: u64,
    mm: std::num::NonZeroU64,
    revision: u64,
    mappings: Vec<(carrick_hal::MappingId, carrick_hal::FrameId)>,
) -> carrick_hal::FrameInventoryApplyReceipt {
    carrick_hal::FrameInventoryApplyReceipt::from_kernel_authority(
        carrick_hal::FrameInventoryProvenance::from_kernel_entropy([raw as u8; 32]),
        commit.batch().transaction(),
        mm,
        revision,
        mappings,
    )
}

#[test]
fn a_superseded_fork_inheritance_no_longer_blocks_retirement() {
    let id = |raw| {
        std::num::NonZeroU64::new(raw)
            .map(carrick_hal::MappingId::from_kernel_allocation)
            .unwrap()
    };
    let frame =
        |raw| carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(raw).unwrap());
    let mm = std::num::NonZeroU64::new(503).unwrap();

    // The live set at retirement: one mapping, unmapped by the commit.
    let live = vec![(id(71), frame(11))];
    let retired = carrick_hal::FrameInventoryRetirementReceipt::from_kernel_authority(
        test_kernel_apply(
            retirement_inventory_commit(96, &[id(71)]),
            96,
            mm,
            12,
            live.clone(),
        ),
        true,
    );
    let transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(
        std::num::NonZeroU64::new(96).unwrap(),
    );

    // A fork inheritance the child has since COW'd. `stage_cow_inventory_split`
    // already pushed `UnmapMapping` for `child_mapping` and retired its frame
    // reference in that transaction, and `commit_cow_inventory_split` dropped
    // the extent — so the obligation is discharged and the mapping is gone
    // from the live set. Retirement must not be asked to account for it a
    // second time; demanding that failed every forked child that wrote to an
    // inherited page.
    let superseded = PendingForkFrameReceipt {
        transaction,
        kind: carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
        parent_mapping: id(22),
        child_mapping: id(70),
        frame: frame(9),
        ipa: 0x0020_0000,
        length: 0x0009_4000,
    };
    assert!(
        authenticate_pending_retirement(&live, &[superseded], &retired).ok(),
        "a fork inheritance whose mapping was superseded before retirement is \
         already accounted for"
    );

    // A STILL-LIVE inherited mapping whose frame drifted is a real defect and
    // must stay rejected: the retirement would be unmapping a frame the child
    // never inherited.
    let drifted = PendingForkFrameReceipt {
        transaction,
        kind: carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
        parent_mapping: id(22),
        child_mapping: id(71),
        frame: frame(9),
        ipa: 0x0020_0000,
        length: 0x0009_4000,
    };
    assert!(
        !authenticate_pending_retirement(&live, &[drifted], &retired).ok(),
        "a live inherited mapping retiring under a different frame is still a \
         failure"
    );
}

#[test]
fn inventory_phase_is_process_owned_and_exactly_ordered() {
    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let mut sibling = HvpatchTaskInventoryAuthority::SiblingShared {
        ledger: Arc::clone(&ledger),
    };
    let mm = std::num::NonZeroU64::new(501).unwrap();
    assert!(
        sibling
            .apply_process_inventory(|_| unreachable!(), mm)
            .is_err()
    );
    assert_eq!(sibling.phase_name(), "sibling_shared");

    let commit = empty_inventory_commit(91);
    let challenge = commit.receipt_challenge();
    let mut process = HvpatchTaskInventoryAuthority::ProcessPrepared {
        ledger: Arc::clone(&ledger),
        staged: Vec::new(),
        commit: Some(commit),
        challenge: Some(challenge),
    };
    let id = |raw| {
        std::num::NonZeroU64::new(raw)
            .map(carrick_hal::MappingId::from_kernel_allocation)
            .unwrap()
    };
    let frame = carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(3).unwrap());
    process
        .apply_process_inventory(
            |commit| Ok(test_kernel_apply(commit, 91, mm, 10, vec![(id(2), frame)])),
            mm,
        )
        .unwrap();
    assert_eq!(process.phase_name(), "inventory_published");
    let expected_transaction = carrick_hal::KernelTransactionId::from_kernel_allocation(
        std::num::NonZeroU64::new(91).unwrap(),
    );
    let mut pending = PendingForkFrameReceipt {
        transaction: carrick_hal::KernelTransactionId::from_kernel_allocation(
            std::num::NonZeroU64::new(92).unwrap(),
        ),
        kind: carrick_observability::probes::HvpatchForkFrameKind::PrivateCow,
        parent_mapping: id(1),
        child_mapping: id(2),
        frame,
        ipa: 0x4000,
        length: 0x4000,
    };
    assert!(process.activate(&[pending]).is_err());
    assert_eq!(process.phase_name(), "inventory_published");
    pending.transaction = expected_transaction;
    process.activate(&[pending]).unwrap();
    assert_eq!(process.phase_name(), "active");
    let frame5 =
        carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(5).unwrap());
    let frame7 =
        carrick_hal::FrameId::from_kernel_allocation(std::num::NonZeroU64::new(7).unwrap());
    let mapping_pairs = [(id(2), frame), (id(4), frame5), (id(6), frame7)];
    {
        let mut current = ledger.lock();
        for (index, &(mapping, frame)) in mapping_pairs.iter().enumerate() {
            current.extents.insert(
                (0x4000 + index as u64 * 0x4000, 0x4000),
                InventoryExtent {
                    frame,
                    mapping,
                    backing: InventoryBackingIdentity::Private(index as u64 + 1),
                    stage2_base: 0x1000_0000 + index as u64 * 0x4000,
                    stage2_length: 0x4000,
                    stage2_owner: InventoryStage2OwnerIdentity::TEST_UNOWNED,
                },
            );
        }
    }
    assert!(
        process
            .prepare_retirement(retirement_inventory_commit(95, &[id(2)]))
            .is_err()
    );
    // A post-activation munmap/COW retirement changed the exact live set.
    ledger.lock().extents.remove(&(0x8000, 0x4000));
    let expected_after_unmap = vec![mapping_pairs[0], mapping_pairs[2]];
    let unrelated_commit = empty_inventory_commit(92);
    let unrelated = carrick_hal::FrameInventoryRetirementReceipt::from_kernel_authority(
        test_kernel_apply(unrelated_commit, 92, mm, 11, Vec::new()),
        false,
    );
    assert!(!authenticate_pending_retirement(&expected_after_unmap, &[pending], &unrelated).ok());
    let retirement_commit = retirement_inventory_commit(93, &[id(2), id(6)]);
    process.prepare_retirement(retirement_commit).unwrap();
    process
        .apply_retirement(mm, &[pending], |retirement_commit| {
            Ok(
                carrick_hal::FrameInventoryRetirementReceipt::from_kernel_authority(
                    test_kernel_apply(retirement_commit, 93, mm, 11, expected_after_unmap.clone()),
                    true,
                ),
            )
        })
        .unwrap();
    assert_eq!(process.phase_name(), "retired");

    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let rejected_commit = empty_inventory_commit(94);
    let rejected_challenge = rejected_commit.receipt_challenge();
    let mut rejected = HvpatchTaskInventoryAuthority::ProcessPrepared {
        ledger,
        staged: Vec::new(),
        commit: Some(rejected_commit),
        challenge: Some(rejected_challenge),
    };
    assert!(
        rejected
            .apply_process_inventory(
                |_| {
                    Err(TrapError::Hypervisor(
                        "injected kernel apply reject".to_owned(),
                    ))
                },
                mm
            )
            .is_err()
    );
    assert_eq!(rejected.phase_name(), "retired");
    assert!(rejected.activate(&[]).is_err());
}

#[test]
fn only_a_non_owning_authority_reports_a_shared_process_inventory() {
    let ledger = || Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    // vfork / CLONE_VM: the ledger belongs to the process whose kernel mm
    // this task shares. Retirement is the owner's job.
    for shared in [
        HvpatchTaskInventoryAuthority::SharedProcess { ledger: ledger() },
        HvpatchTaskInventoryAuthority::SiblingShared { ledger: ledger() },
    ] {
        assert!(
            shared.shares_another_process_inventory(),
            "{}",
            shared.phase_name()
        );
    }
    // Owning phases retire their own ledger, and `Retired`/`Absent` must NOT
    // report as shared — a second retirement of an owned ledger has to keep
    // failing in `prepare_retirement` rather than being skipped here.
    for owning in [
        HvpatchTaskInventoryAuthority::Absent,
        HvpatchTaskInventoryAuthority::Retired,
        HvpatchTaskInventoryAuthority::ProcessPrepared {
            ledger: ledger(),
            staged: Vec::new(),
            commit: None,
            challenge: None,
        },
    ] {
        assert!(
            !owning.shares_another_process_inventory(),
            "{}",
            owning.phase_name()
        );
    }
}

#[test]
fn shared_process_activation_has_no_process_inventory_transaction() {
    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let mut shared = HvpatchTaskInventoryAuthority::SharedProcess {
        ledger: Arc::clone(&ledger),
    };
    let mm = std::num::NonZeroU64::new(777).unwrap();
    assert!(
        shared
            .apply_process_inventory(|_| unreachable!(), mm)
            .is_err()
    );
    assert_eq!(shared.phase_name(), "shared_process");
    shared.activate(&[]).unwrap();
    assert_eq!(shared.phase_name(), "shared_process");

    let commit = empty_inventory_commit(778);
    let challenge = commit.receipt_challenge();
    let mut copied = HvpatchTaskInventoryAuthority::ProcessPrepared {
        ledger,
        staged: Vec::new(),
        commit: Some(commit),
        challenge: Some(challenge),
    };
    assert!(copied.activate(&[]).is_err());
    assert_eq!(copied.phase_name(), "prepared");
}

#[test]
fn active_inventory_activation_is_idempotent_for_thread_siblings() {
    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let receipt = test_kernel_apply(
        empty_inventory_commit(101),
        101,
        std::num::NonZeroU64::new(101).unwrap(),
        1,
        Vec::new(),
    );
    let mut active = HvpatchTaskInventoryAuthority::Active {
        ledger,
        receipt,
        retirement: None,
    };
    assert_eq!(active.phase_name(), "active");
    active.activate(&[]).unwrap();
    assert_eq!(active.phase_name(), "active");
}

#[test]
fn exec_predecessor_authority_retires_without_aborting_active_drop() {
    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let receipt = test_kernel_apply(
        empty_inventory_commit(102),
        102,
        std::num::NonZeroU64::new(102).unwrap(),
        1,
        Vec::new(),
    );
    let authority = HvpatchTaskMmAuthority {
        container_root: ContainerRootToken::ROOT,
        mappings: Vec::new(),
        foreign_mm_transport: None,
        mm_root_slot: Some((0x1000_0000, 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::Active {
            ledger,
            receipt,
            retirement: None,
        }),
        kernel_mm: parking_lot::Mutex::new(std::num::NonZeroU64::new(102)),
        cow_armed: None,
        cow_deferred_publications: None,
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Test),
        drop_order: None,
    };
    authority.retire_exec_predecessor();
    assert_eq!(authority.inventory.lock().phase_name(), "retired");
    drop(authority);
}

#[test]
fn exclusive_rebind_retires_predecessor_authority() {
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let receipt = test_kernel_apply(
        empty_inventory_commit(103),
        103,
        std::num::NonZeroU64::new(103).unwrap(),
        1,
        Vec::new(),
    );
    let mut state = directory
        .publish(
            identity(103),
            test_state(&rollbacks),
            HvpatchPreparedTaskAuthority {
                mm_root_slot: Some((0x1100_0000, 0x20_0000)),
                inventory: HvpatchTaskInventoryAuthority::Active {
                    ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
                    receipt,
                    retirement: None,
                },
                ..prepared_task()
            },
        )
        .unwrap();
    let old_task_mm = Arc::clone(
        state
            .registration
            .as_ref()
            .unwrap()
            .task_mm
            .as_ref()
            .unwrap(),
    );
    let replacement = Arc::new(HvpatchTaskMmAuthority {
        container_root: ContainerRootToken::ROOT,
        mappings: Vec::new(),
        foreign_mm_transport: None,
        mm_root_slot: Some((0x1200_0000, 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::SharedProcess {
            ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        }),
        kernel_mm: parking_lot::Mutex::new(None),
        cow_armed: None,
        cow_deferred_publications: None,
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Test),
        drop_order: None,
    });
    state
        .registration
        .as_mut()
        .unwrap()
        .rebind_exec_authority(
            replacement,
            (0x1200_0000, 0x20_0000),
            Vec::new(),
            legacy_test_carrier_vm_custody_arc(),
            false,
        )
        .unwrap();

    assert_eq!(old_task_mm.inventory.lock().phase_name(), "retired");
    drop(state);
    drop(old_task_mm);
    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
}

/// `vforkexecthread`: thread T0 vforks child C (`CLONE_VM|CLONE_VFORK`),
/// then sibling thread T1 execs while C is still alive. The Kernel keeps
/// mm A for C (`RetainOldMm`), so T1's rebind must hand the `Active`
/// inventory authority -- receipt and outstanding fork receipts -- to C's
/// `SharedProcess` authority, deterministically, whether or not T0's
/// registration still holds the predecessor Arc. Before this, the outcome
/// depended on drop order: T1 sole holder -> the receipt was silently
/// discarded and C's exit skipped mm A's retirement; T0 still holding ->
/// T0's cleanup dropped an `Active` authority and aborted the carrier
/// (`holder=registration-cleanup`).
#[test]
fn owner_exec_hands_active_inventory_to_live_clone_vm_sharer() {
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let slot_a = (0x1300_0000, 0x20_0000);
    let mm_a = std::num::NonZeroU64::new(303).unwrap();
    let receipt = test_kernel_apply(empty_inventory_commit(303), 303, mm_a, 1, Vec::new());
    let publish = |task_serial, thread_serial, task: HvpatchPreparedTaskAuthority| {
        directory
            .publish(
                HvpatchCarrierTaskIdentity {
                    task_serial,
                    thread_serial,
                    execution_generation: 1,
                    linux_pid: task_serial as i32,
                    linux_tid: thread_serial as i32,
                    asid: 9,
                },
                test_state(&rollbacks),
                task,
            )
            .unwrap()
    };
    let mut owner = publish(
        301,
        301,
        HvpatchPreparedTaskAuthority {
            mm_root_slot: Some(slot_a),
            inventory: HvpatchTaskInventoryAuthority::Active {
                ledger: Arc::clone(&ledger),
                receipt,
                retirement: None,
            },
            ..prepared_task()
        },
    );
    owner
        .registration
        .as_mut()
        .unwrap()
        .bind_kernel_mm(mm_a)
        .unwrap();
    let mut exec_thread = publish(
        301,
        302,
        HvpatchPreparedTaskAuthority {
            mm_root_slot: Some(slot_a),
            inventory: HvpatchTaskInventoryAuthority::SiblingShared {
                ledger: Arc::clone(&ledger),
            },
            ..prepared_task()
        },
    );
    exec_thread
        .registration
        .as_mut()
        .unwrap()
        .bind_kernel_mm(mm_a)
        .unwrap();
    let mut vfork_child = publish(
        303,
        303,
        HvpatchPreparedTaskAuthority {
            mm_root_slot: Some(slot_a),
            shared_kernel_mm: Some(mm_a.get()),
            inventory: HvpatchTaskInventoryAuthority::SharedProcess {
                ledger: Arc::clone(&ledger),
            },
            ..prepared_task()
        },
    );
    vfork_child
        .registration
        .as_mut()
        .unwrap()
        .bind_kernel_mm(mm_a)
        .unwrap();
    let task_mm = |state: &HvpatchTaskOnlyBackendState| {
        Arc::clone(
            state
                .registration
                .as_ref()
                .unwrap()
                .task_mm
                .as_ref()
                .unwrap(),
        )
    };
    let predecessor = task_mm(&owner);
    assert!(Arc::ptr_eq(&predecessor, &task_mm(&exec_thread)));
    let sharer = task_mm(&vfork_child);
    assert!(!Arc::ptr_eq(&predecessor, &sharer));
    assert_eq!(sharer.inventory.lock().phase_name(), "shared_process");

    let replacement = Arc::new(HvpatchTaskMmAuthority {
        container_root: ContainerRootToken::ROOT,
        mappings: Vec::new(),
        foreign_mm_transport: None,
        mm_root_slot: Some((0x1400_0000, 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::SharedProcess {
            ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        }),
        kernel_mm: parking_lot::Mutex::new(None),
        cow_armed: None,
        cow_deferred_publications: None,
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Test),
        drop_order: None,
    });
    // T0 (`owner`) still holds the predecessor Arc while T1 execs: the
    // drop-order case that used to abort.
    exec_thread
        .registration
        .as_mut()
        .unwrap()
        .rebind_exec_authority(
            replacement,
            (0x1400_0000, 0x20_0000),
            Vec::new(),
            legacy_test_carrier_vm_custody_arc(),
            true,
        )
        .unwrap();

    assert_eq!(predecessor.inventory.lock().phase_name(), "retired");
    let inventory = sharer.inventory.lock();
    assert_eq!(inventory.phase_name(), "active");
    assert!(
        inventory
            .shared_runtime_ledger()
            .is_some_and(|handed| Arc::ptr_eq(&handed, &ledger))
    );
    assert!(!inventory.shares_another_process_inventory());
    drop(inventory);

    // Every registration drop must now be abort-free regardless of order.
    drop(owner);
    drop(exec_thread);
    drop(predecessor);
    assert_eq!(sharer.inventory.lock().phase_name(), "active");
    sharer.retire_exec_predecessor();
    drop(vfork_child);
    drop(sharer);
    assert_eq!(rollbacks.load(Ordering::SeqCst), 3);
}

/// A CLONE_VM process is a distinct task/inventory projection, but it is
/// not a distinct MM. Reconstructing `MmAccessState` from the shared
/// ledger/COW fields loses the exact structural root owner kept inside the
/// original Arc. If exec later hands the active inventory to this sharer,
/// its terminal root retirement then fails even though it owns the right
/// numeric slot.
#[test]
fn shared_process_authority_preserves_the_exact_mm_access_arc() {
    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let cow_armed = Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()));
    let cow_deferred_publications = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let inherited = MmAccessState::new(
        carrick_aarch64::Stage1Authority::new(),
        Arc::new(MemoryProtections::default()),
        Arc::clone(&ledger),
        Arc::clone(&cow_armed),
        Arc::clone(&cow_deferred_publications),
    );
    let authority = HvpatchTaskMmAuthority::from_prepared(
        HvpatchPreparedTaskAuthority {
            mm_root_slot: Some((0x13a0_0000, 0x20_0000)),
            shared_kernel_mm: Some(303),
            inventory: HvpatchTaskInventoryAuthority::SharedProcess { ledger },
            cow_armed: Some(cow_armed),
            cow_deferred_publications: Some(cow_deferred_publications),
            inherited_mm_access: Some(Arc::clone(&inherited)),
            ..prepared_task()
        },
        AliasPublicationReceipt::default(),
    );
    let retained = authority
        .mm_access
        .lock()
        .as_ref()
        .cloned()
        .expect("shared process retains inherited MM authority");

    assert!(Arc::ptr_eq(&retained, &inherited));
}

#[test]
fn root_parent_shared_process_interns_by_exact_kernel_mm_without_parent_row() {
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let ledger = Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default()));
    let publish = |task_serial, thread_serial, generation| {
        directory
            .publish(
                HvpatchCarrierTaskIdentity {
                    task_serial,
                    thread_serial,
                    execution_generation: generation,
                    linux_pid: task_serial as i32,
                    linux_tid: thread_serial as i32,
                    asid: 9,
                },
                test_state(&rollbacks),
                HvpatchPreparedTaskAuthority {
                    shared_kernel_mm: Some(0xfeed),
                    inventory: HvpatchTaskInventoryAuthority::SharedProcess {
                        ledger: Arc::clone(&ledger),
                    },
                    ..prepared_task()
                },
            )
            .unwrap()
    };
    let mut root_vfork_child = publish(101, 101, 1);
    let nested_vfork_child = publish(202, 202, 1);
    let first_mm = Arc::clone(
        root_vfork_child
            .registration
            .as_ref()
            .unwrap()
            .task_mm
            .as_ref()
            .unwrap(),
    );
    let second_mm = Arc::clone(
        nested_vfork_child
            .registration
            .as_ref()
            .unwrap()
            .task_mm
            .as_ref()
            .unwrap(),
    );
    assert!(Arc::ptr_eq(&first_mm, &second_mm));

    let replacement = Arc::new(HvpatchTaskMmAuthority {
        container_root: ContainerRootToken::ROOT,
        mappings: Vec::new(),
        foreign_mm_transport: None,
        mm_root_slot: Some((0x1000_0000, 0x20_0000)),
        mm_root_stage2: parking_lot::Mutex::new(None),
        inventory: parking_lot::Mutex::new(HvpatchTaskInventoryAuthority::SharedProcess {
            ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
        }),
        kernel_mm: parking_lot::Mutex::new(None),
        cow_armed: None,
        cow_deferred_publications: None,
        mm_access: parking_lot::Mutex::new(None),
        pending_publication_receipts: parking_lot::Mutex::new(Vec::new()),
        pending_receipts: parking_lot::Mutex::new(Vec::new()),
        alias_receipts: parking_lot::Mutex::new(Vec::new()),
        last_holder: parking_lot::Mutex::new(HvpatchTaskMmHolder::Test),
        drop_order: None,
    });
    root_vfork_child
        .registration
        .as_mut()
        .unwrap()
        .rebind_exec_authority(
            replacement,
            (0x1000_0000, 0x20_0000),
            Vec::new(),
            legacy_test_carrier_vm_custody_arc(),
            true,
        )
        .unwrap();
    let inventory = second_mm.inventory.lock();
    assert_eq!(inventory.phase_name(), "shared_process");
    assert!(inventory.shared_runtime_ledger().is_some());
    drop(inventory);

    drop(root_vfork_child);
    drop(nested_vfork_child);
    assert_eq!(rollbacks.load(Ordering::SeqCst), 2);
}

#[test]
fn shared_mm_retires_carrier_before_final_task_authority() {
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let order = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let alias_preimage = alias(0xf444_0000, 1);
    let alias_owned = alias(0xf555_0000, 3);
    register_shared_alias(alias_preimage);
    let publish = |generation| {
        directory
            .publish(
                identity(generation),
                HvpatchCarrierTaskState::Test {
                    rollbacks: Arc::clone(&rollbacks),
                    order: Some(Arc::clone(&order)),
                },
                HvpatchPreparedTaskAuthority {
                    pending_aliases: (generation == 21)
                        .then_some(alias_owned)
                        .into_iter()
                        .collect(),
                    drop_order: Some(Arc::clone(&order)),
                    ..prepared_task()
                },
            )
            .unwrap()
    };
    let first = publish(21);
    let second = publish(22);
    let first_mm = first
        .registration
        .as_ref()
        .unwrap()
        .task_mm
        .as_ref()
        .unwrap();
    let second_mm = second
        .registration
        .as_ref()
        .unwrap()
        .task_mm
        .as_ref()
        .unwrap();
    assert!(Arc::ptr_eq(first_mm, second_mm));
    drop(first);
    assert!(order.lock().is_empty());
    assert!(alias_registry().lock().contains(&alias_owned));
    drop(second);
    assert_eq!(&*order.lock(), &["carrier", "task"]);
    assert!(alias_registry().lock().contains(&alias_preimage));
    assert_eq!(rollbacks.load(Ordering::SeqCst), 2);
    alias_registry().lock().retain(|entry| {
        !(entry.ipa == alias_preimage.ipa
            && entry.ownership_scope == alias_preimage.ownership_scope)
    });
    replay_mappings()
        .lock()
        .retain(|(ipa, _, _, _, _)| *ipa != alias_preimage.physical_ipa);
}

#[test]
fn process_descriptor_lease_retires_while_host_backing_is_live() {
    let host = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        0x4000,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .unwrap();
    let host_addr = host.as_ptr();
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut lease = GlobalFrameStage2Lease::fixed(0x1234_0000, 0x4000);
    lease.drop_backing_audit = Some((host_addr as usize, Arc::clone(&observed)));
    let mut descriptor = ProcessMappingDesc {
        start: 0x1000,
        ipa: 0x1234_0000,
        end: 0x5000,
        stage2_lease: Some(lease),
        host: ProcessMappingHost::Owned(host),
        size: 0x4000,
        physical_ipa: 0x1234_0000,
        physical_host_addr: host_addr,
        physical_size: 0x4000,
        inventory_backing: InventoryBackingIdentity::Private(1),
        perms: applevisor::memory::MemPerms::ReadWrite,
        is_dynamic_alias: false,
        sharing: GuestMappingSharing::Private,
        guest_writable: true,
        shared_key_base: 0,
        shared_key_offset: 0,
        inherited_frame: None,
        owner_generation: 0,
    };
    // Retirement is EXPLICIT. Dropping a lease has not unmapped stage-2
    // since `901945f82` made carrier custody generation-safe -- an implicit
    // unmap during teardown can outlive the VM it would unmap into, so
    // `Drop` now only releases the IPA reservation. The invariant this
    // guards is unchanged and is what the retirement point must honour:
    // stage-2 goes away while the host backing is still live, never after
    // `ProcessMappingHost::Owned` has released it.
    descriptor
        .stage2_lease
        .as_mut()
        .expect("descriptor owns its stage-2 lease")
        .try_retire()
        .expect("retire the descriptor's stage-2 lease");
    assert!(
        observed.load(Ordering::SeqCst),
        "stage-2 must retire while the host backing is still live"
    );
    drop(descriptor);
    assert!(!alias_backing_is_live(host_addr as usize));
}

#[test]
fn exhausted_nonce_aborts_prepared_authority_before_visibility() {
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    directory.next.store(u64::MAX, Ordering::SeqCst);
    let rollbacks = Arc::new(AtomicUsize::new(0));
    assert!(
        directory
            .publish(identity(9), test_state(&rollbacks), prepared_task(),)
            .is_err()
    );
    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    assert!(directory.inner.lock().states.is_empty());
}

#[test]
fn carrier_token_is_rejected_by_a_different_directory_instance() {
    let first = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let second = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let binding = first
        .publish(identity(11), test_state(&rollbacks), prepared_task())
        .unwrap();
    let key = binding.registration.as_ref().unwrap().key;
    assert!(second.retire(key).is_err());
    assert!(first.inner.lock().states.contains_key(&key));
    drop(binding);
    assert!(first.inner.lock().states.is_empty());
}

#[test]
fn duplicate_core_key_rejects_different_linux_metadata() {
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::default());
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let binding = directory
        .publish(identity(12), test_state(&rollbacks), prepared_task())
        .unwrap();
    let mut mismatched = identity(12);
    mismatched.linux_tid += 1;
    mismatched.asid += 1;
    assert!(
        directory
            .publish(mismatched, test_state(&rollbacks), prepared_task(),)
            .is_err()
    );
    assert_eq!(directory.inner.lock().states.len(), 1);
    drop(binding);
}

/// COW arming and COW deferred publication are ONE authority. A task that
/// can arm a COW range must also own the slot its deferred publications
/// land in. Half the pair is exactly how every forked PROCESS reached a
/// worker with `cow_armed` set and no publication slot: the omission was
/// swallowed by `..Default::default()` and surfaced only at child
/// activation, after the child had already been published.
#[test]
fn prepared_task_authority_rejects_half_a_cow_authority() {
    let armed = || Arc::new(parking_lot::Mutex::new(CowArmedRanges::default()));
    let publications = || Arc::new(parking_lot::Mutex::new(Vec::new()));

    prepared_task()
        .validate_cow_authority_pairing()
        .expect("neither half present is a complete, COW-less authority");

    HvpatchPreparedTaskAuthority {
        cow_armed: Some(armed()),
        cow_deferred_publications: Some(publications()),
        ..prepared_task()
    }
    .validate_cow_authority_pairing()
    .expect("both halves present is a complete COW authority");

    let error = HvpatchPreparedTaskAuthority {
        cow_armed: Some(armed()),
        ..prepared_task()
    }
    .validate_cow_authority_pairing()
    .expect_err("arming without a publication slot must fail closed");
    assert!(
        error
            .to_string()
            .contains("armed COW without publication state"),
        "unexpected error: {error}"
    );

    let error = HvpatchPreparedTaskAuthority {
        cow_deferred_publications: Some(publications()),
        ..prepared_task()
    }
    .validate_cow_authority_pairing()
    .expect_err("a publication slot without arming must fail closed");
    assert!(
        error
            .to_string()
            .contains("COW publication state without arming"),
        "unexpected error: {error}"
    );
}

#[test]
fn committed_child_requires_fresh_exact_kernel_cow_binding() {
    let (issuer, verifier) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let directory = Arc::new(HvpatchCarrierTaskStateDirectory::new(
        std::num::NonZeroU64::new(0x881).unwrap(),
        verifier,
    ));
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let mut binding = directory
        .publish(
            identity(31),
            test_state(&rollbacks),
            HvpatchPreparedTaskAuthority {
                inventory: HvpatchTaskInventoryAuthority::SiblingShared {
                    ledger: Arc::new(parking_lot::Mutex::new(HvpatchFrameInventory::default())),
                },
                ..prepared_task()
            },
        )
        .unwrap();
    assert!(binding.activate().is_err());
    let mm = std::num::NonZeroU64::new(0x1234).unwrap();
    let authority: Arc<dyn carrick_hal::FrameCowAuthority> = Arc::new(TestCowAuthority);
    let cow_identity = carrick_hal::FrameCowIdentity {
        linux_pid: 41,
        linux_tid: 73,
        mm: mm.get(),
        asid: 9,
    };
    let token = |generation, cow_identity, authority_identity| {
        issuer.issue(
            41,
            73,
            generation,
            cow_identity,
            std::num::NonZeroU64::new(authority_identity).unwrap(),
            Arc::clone(&authority),
        )
    };
    let (foreign_issuer, _) = carrick_hal::HvpatchChildTokenIssuer::new_pair();
    let foreign = foreign_issuer.issue(
        41,
        73,
        31,
        cow_identity,
        std::num::NonZeroU64::new(9).unwrap(),
        Arc::clone(&authority),
    );
    assert!(binding.bind_child_kernel(foreign).is_err());
    let wrong = token(32, cow_identity, 1);
    assert!(binding.bind_child_kernel(wrong).is_err());
    let parent_tid = token(
        31,
        carrick_hal::FrameCowIdentity {
            linux_tid: 72,
            ..cow_identity
        },
        2,
    );
    assert!(binding.bind_child_kernel(parent_tid).is_err());
    let stale_asid = token(
        31,
        carrick_hal::FrameCowIdentity {
            asid: 8,
            ..cow_identity
        },
        3,
    );
    assert!(binding.bind_child_kernel(stale_asid).is_err());
    let exact = token(31, cow_identity, 4);
    binding.bind_child_kernel(exact).unwrap();
    binding.activate().unwrap();
    assert_eq!(
        *binding
            .registration
            .as_ref()
            .unwrap()
            .task_mm
            .as_ref()
            .unwrap()
            .kernel_mm
            .lock(),
        Some(mm)
    );
    let duplicate = token(31, cow_identity, 5);
    assert!(binding.bind_child_kernel(duplicate).is_err());
}
